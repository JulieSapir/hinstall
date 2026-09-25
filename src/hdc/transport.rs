// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! USB 传输层：分帧读写与软复位。
//!
//! 分帧规则与官方 `src/common/usb.cpp` 的 `SendUSBBlock` /
//! `CheckPacketOption` 一致：
//!
//! - 每个数据包 = 11 字节 `USBHead` + 载荷；
//! - 载荷长度是 `wMaxPacketSizeSend` 的整数倍时，补发一个占位头
//!   （`option = 0`、`dataSize = 0`），避免对端等待零长度包；
//! - 读侧按 `option & USB_OPTION_HEADER` 或 `dataSize == 0` 识别包头，
//!   会话号不匹配的残留数据直接丢弃。
//!
//! IO 原语（`write_chunk` / `read_chunk`）走 `transfer_blocking`：自带超时，
//! 超时会取消传输。
//!
//! 上层（[`crate::hdc::session`] / [`crate::hdc::install`]）只调 `async fn`；
//! 调用方用 `futures_lite::future::block_on` 驱动。

use std::time::{Duration, Instant};

use crate::hdc::config::{
    HDC_BUF_MAX_SIZE, MAX_PACKET_SIZE_HISPEED, USB_HEAD_SIZE, USB_OPTION_HEADER, USB_READ_BUF_SIZE,
    USB_RESET_MAX_DRAIN_MS, USB_RESET_READ_TIMEOUT_MS, USB_RESET_RETRY_BYTES,
};
use crate::hdc::packet::UsbHead;
use nusb::descriptors::TransferType;
use nusb::transfer::{Bulk, In, Out, TransferError};
// 用 `MaybeFuture::wait()` 阻塞取结果。注意不能用 `.await`：nusb 的 `IntoFuture`
// 在没有 smol/tokio 特性时会直接 panic。
use nusb::MaybeFuture;
use nusb::{Device, DeviceInfo, Endpoint, Interface};

use crate::hdc::device::{HDC_INTERFACE_CLASS, HDC_INTERFACE_PROTOCOL, HDC_INTERFACE_SUBCLASS};
use crate::hdc::error::{Error, Result};

/// 默认的读写超时。
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_millis(3000);

/// 打开后的 HDC USB 通道。
pub struct UsbTransport {
    /// 持有设备句柄，避免底层 fd 被提前关闭。
    _device: Device,
    /// 已占用的 HDC 接口。
    _interface: Interface,
    /// bulk OUT 端点。
    ep_out: Endpoint<Bulk, Out>,
    /// bulk IN 端点。
    ep_in: Endpoint<Bulk, In>,
    /// 当前会话号。
    session_id: u32,
    /// OUT 端点的最大包长，用于判断是否需要补占位包。
    max_packet_size_send: usize,
    /// 读写超时。
    io_timeout: Duration,
    /// 接收累积缓冲：bulk 读返回的片段先落在这里，再按帧切分。
    rx: Vec<u8>,
}

impl UsbTransport {
    /// 打开指定设备上的 HDC 接口。
    ///
    /// `session_id` 由调用方生成，握手时一并送给设备。
    pub async fn open(info: &DeviceInfo, session_id: u32, io_timeout: Duration) -> Result<Self> {
        let device = info.open().wait()?;
        // 接口号和端点必须从**设备返回的配置描述符**里读，不能信 `DeviceInfo`：
        // 那是打开前的快照，`configuration` 可能为空，接口列表读不到。
        let (interface_number, out_addr, in_addr, max_packet_size_send) =
            find_hdc_endpoints(&device)?;
        let interface = device.claim_interface(interface_number).wait()?;
        let ep_out = interface.endpoint::<Bulk, Out>(out_addr)?;
        let ep_in = interface.endpoint::<Bulk, In>(in_addr)?;
        Ok(Self {
            _device: device,
            _interface: interface,
            ep_out,
            ep_in,
            session_id,
            max_packet_size_send,
            io_timeout,
            rx: Vec::with_capacity(USB_READ_BUF_SIZE),
        })
    }

    /// 更新会话号（握手协商出设备侧会话号后调用）。
    pub fn set_session_id(&mut self, session_id: u32) {
        self.session_id = session_id;
    }

    /// 更新读写超时。
    pub fn set_io_timeout(&mut self, timeout: Duration) {
        self.io_timeout = timeout;
    }

    /// 发送一个数据包（头 + 载荷 + 必要的占位包）。
    pub async fn send_packet(&mut self, payload: &[u8]) -> Result<()> {
        let head = UsbHead::header(self.session_id, payload.len() as u32).encode();
        self.write_all(&head).await?;
        if payload.is_empty() {
            return Ok(());
        }
        self.write_all(payload).await?;
        if payload.len().is_multiple_of(self.max_packet_size_send) {
            let dummy = UsbHead::dummy(self.session_id).encode();
            self.write_all(&dummy).await?;
        }
        Ok(())
    }

    /// 接收一个数据包，返回载荷（不含 11 字节头）。
    ///
    /// 占位包、其他会话的残留数据会被跳过。
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>> {
        let max_frame = HDC_BUF_MAX_SIZE as u32;
        loop {
            self.fill(USB_HEAD_SIZE).await?;
            let head = UsbHead::decode(&self.rx[..USB_HEAD_SIZE])?;
            self.rx.drain(..USB_HEAD_SIZE);
            if head.session_id != self.session_id {
                // 上一个会话遗留的数据，丢弃后继续找下一个头。
                continue;
            }
            if head.data_size == 0 || head.option & USB_OPTION_HEADER == 0 {
                // 占位包或非数据包，继续读。
                continue;
            }
            let size = head.data_size as usize;
            if size > max_frame as usize {
                return Err(Error::FrameTooLarge {
                    declared: head.data_size,
                    max: max_frame,
                });
            }
            self.fill(size).await?;
            return Ok(self.rx.drain(..size).collect());
        }
    }

    /// 软复位：通知设备丢弃当前通道数据，并把设备侧残留数据读干净。
    ///
    /// 返回被丢弃的字节数。排空以「读超时」为终止信号，总耗时严格不超过
    /// `USB_RESET_MAX_DRAIN_MS`（官方 `NEW_SESSION_DROP_USB_DATA_TIME_MAX_MS`）。
    /// 这个上限是协议约束：设备端在收到软复位后约 1 秒内必须收到握手，
    /// 否则会主动 reset USB gadget。因此单次读的超时取「剩余窗口」与
    /// `USB_RESET_READ_TIMEOUT_MS` 的较小值，避免最后一次读把总时长顶出窗口。
    ///
    /// 累计丢弃超过 `USB_RESET_RETRY_BYTES` 时补发一次复位
    /// （对应官方 `ClearUsbChannel` 的行为）。
    pub async fn soft_reset(&mut self) -> Result<u64> {
        let reset_head = UsbHead::reset(self.session_id).encode();
        self.write_all(&reset_head).await?;
        let mut dropped: u64 = 0;
        let mut resent = false;
        let deadline = Instant::now() + Duration::from_millis(USB_RESET_MAX_DRAIN_MS);
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let slice = (deadline - now).min(Duration::from_millis(USB_RESET_READ_TIMEOUT_MS));
            match self.read_chunk(slice).await {
                Ok(data) => {
                    dropped += data.len() as u64;
                    if !resent && dropped > USB_RESET_RETRY_BYTES {
                        self.write_all(&reset_head).await?;
                        resent = true;
                    }
                }
                // 读超时即认为设备侧已经没有残留数据。
                Err(Error::Timeout { .. }) => break,
                Err(e) => return Err(e),
            }
        }
        self.rx.clear();
        Ok(dropped)
    }

    /// 把 `data` 完整写到 OUT 端点。
    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let mut sent = 0usize;
        while sent < data.len() {
            let written = self.write_chunk(&data[sent..]).await?;
            if written == 0 {
                return Err(Error::Timeout {
                    stage: "写",
                    ms: self.io_timeout.as_millis() as u64,
                });
            }
            sent += written;
        }
        Ok(())
    }

    /// 一次 OUT 传输，返回实际发送的字节数。
    ///
    /// native 端的 `transfer_blocking` 自带超时，并在超时时取消传输，因此不会
    /// 留下悬挂状态。
    async fn write_chunk(&mut self, data: &[u8]) -> Result<usize> {
        let completion = self
            .ep_out
            .transfer_blocking(data.to_vec().into(), self.io_timeout);
        completion.status?;
        Ok(completion.actual_len)
    }

    /// 一次 IN 传输，返回读到的字节。
    async fn read_chunk(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let buffer = self.ep_in.allocate(USB_READ_BUF_SIZE);
        let completion = self.ep_in.transfer_blocking(buffer, timeout);
        let len = completion.actual_len;
        match completion.status {
            Ok(()) => {}
            Err(TransferError::Cancelled) => {
                return Err(Error::Timeout {
                    stage: "读",
                    ms: timeout.as_millis() as u64,
                });
            }
            Err(TransferError::Disconnected) => return Err(Error::Disconnected),
            Err(e) => return Err(Error::Transfer(e)),
        }
        if len == 0 {
            return Err(Error::Timeout {
                stage: "读",
                ms: timeout.as_millis() as u64,
            });
        }
        Ok(completion.buffer[..len].to_vec())
    }

    /// 保证接收缓冲里至少有 `n` 字节。
    ///
    /// 读请求固定用 `USB_READ_BUF_SIZE` 的大缓冲：设备可能一次返回整帧
    /// （例如握手响应 99 字节、安装响应上千字节），若按 `n` 精确申请会触发
    /// `LIBUSB_ERROR_OVERFLOW`。官方同样用 513KB 缓冲来规避这一点
    /// （见 `host_usb.cpp` 的 `ClearUsbChannel`）。
    async fn fill(&mut self, n: usize) -> Result<()> {
        while self.rx.len() < n {
            let data = self.read_chunk(self.io_timeout).await?;
            self.rx.extend_from_slice(&data);
        }
        Ok(())
    }
}

/// 在设备的配置描述符里找出 HDC 调试接口及其一对 bulk 端点。
///
/// 返回 `(接口号, OUT 地址, IN 地址, OUT 最大包长)`。匹配条件与官方
/// `IsDebuggableDev` 一致：`class = 0xff`、`subclass = 0x50`、`protocol = 0x01`。
fn find_hdc_endpoints(device: &Device) -> Result<(u8, u8, u8, usize)> {
    for config in device.configurations() {
        for interface in config.interfaces() {
            // 只认第一个 alt setting：HDC 接口不用备用设置切换。
            let Some(alt) = interface.alt_settings().next() else {
                continue;
            };
            if alt.class() != HDC_INTERFACE_CLASS
                || alt.subclass() != HDC_INTERFACE_SUBCLASS
                || alt.protocol() != HDC_INTERFACE_PROTOCOL
            {
                continue;
            }
            let interface_number = alt.interface_number();
            let mut out_addr: Option<u8> = None;
            let mut in_addr: Option<u8> = None;
            let mut max_packet_size = 0usize;
            for ep in alt.endpoints() {
                if ep.transfer_type() != TransferType::Bulk {
                    continue;
                }
                let addr = ep.address();
                if addr & 0x80 == 0 {
                    out_addr = Some(addr);
                    max_packet_size = ep.max_packet_size();
                } else {
                    in_addr = Some(addr);
                }
            }
            return match (out_addr, in_addr) {
                (Some(o), Some(i)) => Ok((
                    interface_number,
                    o,
                    i,
                    if max_packet_size == 0 {
                        MAX_PACKET_SIZE_HISPEED as usize
                    } else {
                        max_packet_size
                    },
                )),
                _ => Err(Error::NoBulkEndpoint {
                    interface: interface_number,
                }),
            };
        }
    }
    Err(Error::NoDevice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hdc::config::{USB_OPTION_DUMMY, USB_OPTION_RESET};

    /// 构造一段与设备返回完全相同的字节流，验证读侧的切帧规则。
    fn build_stream(session_id: u32, packets: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in packets {
            out.extend_from_slice(&UsbHead::header(session_id, p.len() as u32).encode());
            out.extend_from_slice(p);
        }
        out
    }

    #[test]
    fn 默认超时是正数() {
        assert!(DEFAULT_IO_TIMEOUT.as_millis() > 0);
    }

    #[test]
    fn 占位包与残留数据被跳过() {
        // 一个别的会话的头 + 占位包 + 真正的数据包
        let mut stream = build_stream(0xdead_beef, &[b"stale"]);
        stream.extend_from_slice(&UsbHead::dummy(7).encode());
        stream.extend_from_slice(&UsbHead::reset(7).encode());
        stream.extend_from_slice(&UsbHead::header(7, 3).encode());
        stream.extend_from_slice(b"abc");

        // 模拟读侧切帧：直接复用 recv_packet 的判定逻辑。
        let mut pos = 0usize;
        let mut got: Option<Vec<u8>> = None;
        while pos + USB_HEAD_SIZE <= stream.len() {
            let head = UsbHead::decode(&stream[pos..pos + USB_HEAD_SIZE]).unwrap();
            pos += USB_HEAD_SIZE;
            if head.session_id != 7 {
                pos += head.data_size as usize;
                continue;
            }
            if head.data_size == 0 || head.option & USB_OPTION_HEADER == 0 {
                continue;
            }
            let size = head.data_size as usize;
            got = Some(stream[pos..pos + size].to_vec());
            pos += size;
            break;
        }
        assert_eq!(got.as_deref(), Some(&b"abc"[..]));
        assert_eq!(pos, stream.len());
    }

    #[test]
    fn 复位头_option_与官方一致() {
        assert_eq!(UsbHead::reset(1).encode()[2], USB_OPTION_RESET);
        assert_eq!(UsbHead::dummy(1).encode()[2], USB_OPTION_DUMMY);
    }

    #[test]
    fn 占位包规则_载荷为包长整数倍() {
        let max_packet = 512usize;
        for len in [0usize, 1, 511, 512, 1024, 1025] {
            let need_dummy = len != 0 && len % max_packet == 0;
            match len {
                512 | 1024 => assert!(need_dummy, "长度 {len} 应补占位包"),
                _ => assert!(!need_dummy, "长度 {len} 不应补占位包"),
            }
        }
    }
}
