// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 应用安装（对应官方 `hdc install`）的协议编排。
//!
//! 命令序列由官方 C++ 实现与真机 USB 抓包双向确认：
//!
//! ```text
//! host   -> daemon   CMD_APP_CHECK  (3501)  载荷 = TransferConfig
//! daemon -> host     CMD_APP_BEGIN  (3502)  载荷 = 8 字节 FeatureFlags
//! host   -> daemon   CMD_APP_DATA   (3503)  载荷 = 64 字节 TransferPayload 前缀 + 分片
//! daemon -> host     CMD_APP_FINISH (3504)  载荷 = [mode, exitStatus, 消息...]
//! ```
//!
//! 两个容易踩的点：
//!
//! 1. 本端**不主动发** `CMD_APP_INIT` / `CMD_APP_BEGIN` / `CMD_APP_FINISH`。
//!    设备端 `HdcTransferBase::ProcressFileIOWrite` 在累计写入量达到
//!    `TransferConfig.fileSize` 后自行关文件、跑 `bm install`，再把
//!    `CMD_APP_FINISH` 回给本端。官方 host 侧那三个分支是 client/server
//!    分离部署时才走的路径，USB 直连不会用到。
//! 2. 分片大小由设备在 `CMD_APP_BEGIN` 里回的特性位决定，不是固定值：
//!    `hugeBuf == 1` 走 `MAX_SIZE_IOBUF * 0.8`，否则走
//!    `MAX_SIZE_IOBUF_STABLE * 0.8`。官方常量 `maxTransferBufFactor = 0.8`。

use std::time::Duration;

use crate::hdc::command::Command;
use crate::hdc::config::{MAX_SIZE_IOBUF, MAX_SIZE_IOBUF_STABLE};
use crate::hdc::packet::Frame;
use crate::hdc::transfer::{TransferConfig, TransferPayload};

use crate::hdc::error::{Error, Result};
use crate::hdc::transport::UsbTransport;

/// 官方 `HdcTransferBase::maxTransferBufFactor`：每个 IO 分片占缓冲区容量的比例。
const TRANSFER_BUF_FACTOR_NUM: usize = 8;
/// 见 [`TRANSFER_BUF_FACTOR_NUM`]。
const TRANSFER_BUF_FACTOR_DEN: usize = 10;

/// 官方 `transfer.h` 的 `payloadPrefixReserve`：分片前的定长前缀。
pub const PAYLOAD_PREFIX_RESERVE: usize = 64;

/// 官方 `define.h` 的 `EXPECTED_LEN`：随机文件名的字符数。
const EXPECTED_LEN: usize = 9;

/// 安装命令等待设备返回的超时。
///
/// `bm install` 在设备侧要校验签名、解包、写盘，几十 MB 的包耗时可达分钟级，
/// 因此这里远大于普通命令的 3 秒。
const INSTALL_TIMEOUT: Duration = Duration::from_secs(300);

/// 设备在 `CMD_APP_BEGIN` 里回传的特性位（官方 `FeatureFlagsUnion`，8 字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    /// bit0：对端支持 512K 大缓冲。
    pub huge_buf: bool,
    /// bit1：对端支持 lz4 压缩。
    pub compress_lz4: bool,
    /// 是否按「稳定缓冲区」尺寸分片。
    ///
    /// 对齐官方 `CheckFeatures`：`isStableBufSize = isStableBuf ? true : !hugeBuf`。
    /// 本端 `isStableBuf` 恒为 false（USB 直连不用 ffs 稳定模式），故取 `!hugeBuf`。
    pub stable_buf: bool,
    /// 对端是否支持沙箱路径（官方 `isOtherSideSandboxSupported`）。
    pub sandbox_supported: bool,
}

/// 一次安装的最终结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    /// 官方 `AppModType`：1=安装，2=卸载，3=更新。
    pub mode: u8,
    /// 设备返回的退出状态字节。
    pub exit_status: u8,
    /// 设备返回的说明文本（失败时为错误原因）。
    pub message: String,
}

/// 按设备特性位算出本次传输的分片大小（字节）。
///
/// 官方在 `CommandDispatch` 的 `commandBegin` 分支用
/// `GetMaxBufSize() * maxTransferBufFactor` 作为单次 IO 长度，浮点乘积截断为
/// `int`；这里用整数乘除复现同一结果。
pub fn chunk_size(features: Features) -> usize {
    let buf = if features.stable_buf {
        MAX_SIZE_IOBUF_STABLE
    } else {
        MAX_SIZE_IOBUF
    };
    buf * TRANSFER_BUF_FACTOR_NUM / TRANSFER_BUF_FACTOR_DEN
}

/// 解析 `CMD_APP_BEGIN` 的载荷。
///
/// 官方 `CheckFeatures` 只接受 0 字节（用默认值）或 8 字节；真机上设备回的
/// `PayloadProtect` 比本端多一个字段，但 `dataSize` 仍按 8 计算，因此这里只
/// 取前 8 字节，多余的按未知字段忽略。
pub fn parse_features(data: &[u8]) -> Result<Features> {
    if data.is_empty() {
        // 官方语义：空载荷表示「用默认特性」，即稳定缓冲、不支持沙箱。
        return Ok(Features {
            huge_buf: false,
            compress_lz4: false,
            stable_buf: true,
            sandbox_supported: false,
        });
    }
    if data.len() < 8 {
        return Err(Error::BadHandshake {
            reason: "CMD_APP_BEGIN 载荷不足 8 字节特性位",
        });
    }
    let raw = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let huge_buf = raw & 1 != 0;
    Ok(Features {
        huge_buf,
        compress_lz4: raw & 2 != 0,
        stable_buf: !huge_buf,
        sandbox_supported: raw & 0b100 != 0,
    })
}

/// 解析 `CMD_APP_FINISH` 的载荷。
///
/// 真机字节布局：`[mode(1B)] [exitStatus(1B)] [消息...]`。
pub fn parse_install_reply(data: &[u8]) -> Result<InstallResult> {
    if data.len() < 2 {
        return Err(Error::BadHandshake {
            reason: "CMD_APP_FINISH 载荷不足 2 字节",
        });
    }
    Ok(InstallResult {
        mode: data[0],
        exit_status: data[1],
        message: String::from_utf8_lossy(&data[2..]).trim().to_string(),
    })
}

/// 构造一个 `CMD_APP_DATA` 的载荷：64 字节定长前缀 + 分片数据。
///
/// 官方把 `TransferPayload` 序列化结果直接铺在 `payloadPrefixReserve` 字节里，
/// 尾部补 0，因此本函数先序列化再补齐到 64 字节。
pub fn build_data_payload(index: u64, chunk: &[u8]) -> Vec<u8> {
    let header = TransferPayload {
        index,
        compress_type: 0,
        compress_size: chunk.len() as u32,
        uncompress_size: chunk.len() as u32,
    }
    .encode();
    let mut out = vec![0u8; PAYLOAD_PREFIX_RESERVE];
    out[..header.len()].copy_from_slice(&header);
    out.extend_from_slice(chunk);
    out
}

/// 生成设备侧的临时文件名。
///
/// 官方 `HdcHostApp::CheckMaster` 用 9 个随机十六进制字符拼上源文件的扩展名，
/// 目的是让 `pm` 不去解析原始（可能非法的）文件名。
pub fn optional_name(file_name_hint: &str) -> Result<String> {
    let mut buf = [0u8; EXPECTED_LEN];
    getrandom::fill(&mut buf).map_err(|_| Error::NoRandom)?;
    let mut name = String::with_capacity(EXPECTED_LEN + 8);
    for b in buf {
        name.push(char::from_digit((b & 0x0f) as u32, 16).ok_or(Error::NoRandom)?);
    }
    let ext = if file_name_hint.contains(".hsp") {
        ".hsp"
    } else if file_name_hint.contains(".tar") {
        ".tar"
    } else if file_name_hint.contains(".app") {
        ".app"
    } else if file_name_hint.contains(".hap") {
        ".hap"
    } else {
        ".bundle"
    };
    name.push_str(ext);
    Ok(name)
}

/// 生成一个非 0 的通道号。
///
/// 对齐官方 `HdcSessionBase::GetChannelPseudoUid()`：设备端 `MallocChannel` 会用
/// 请求里的通道号建任务，后续 `CMD_APP_DATA` 必须复用同一个值，否则
/// `HdcDaemonApp` 找不到上下文。
fn random_channel_id() -> Result<u32> {
    loop {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).map_err(|_| Error::NoRandom)?;
        let id = u32::from_be_bytes(buf);
        if id != 0 {
            return Ok(id);
        }
    }
}

/// 构造 `CMD_APP_CHECK` 的载荷。
///
/// `options` 恒为 `-r`：`tool.py` 的安装路径固定用 `hdc install -r`，设备端
/// `HdcDaemonApp::do_app_install` 会把它拼成 `bm install -r -p <path>`，
/// 即「覆盖安装」。空 options 会退化成不带 `-r` 的 `bm install -p`，重复安装
/// 同一 bundle 时会直接报错。
pub fn build_check_config(file_size: u64, file_name_hint: &str) -> Result<TransferConfig> {
    Ok(TransferConfig {
        file_size,
        optional_name: optional_name(file_name_hint)?,
        options: "-r".to_string(),
        function_name: "install".to_string(),
        ..Default::default()
    })
}

/// 在已建立的会话上安装一个应用包。
///
/// `hap` 为完整安装包字节（本端已在内存里签好名），`file_name_hint` 只用于
/// 推断扩展名。
///
/// 设备侧失败会以 [`InstallResult`] 返回而不是 `Err`：`bm install` 失败属于
/// 业务结果，只有链路/协议异常才报错。
pub async fn install_app(
    transport: &mut UsbTransport,
    hap: &[u8],
    file_name_hint: &str,
) -> Result<InstallResult> {
    if hap.is_empty() {
        return Err(Error::BadHandshake {
            reason: "待安装的包为空",
        });
    }

    let channel_id = random_channel_id()?;

    // 先唤醒从任务：设备端 `HdcSessionBase::NeedNewTaskInfo` 只对
    // `CMD_KERNEL_WAKEUP_SLAVETASK` / `CMD_APP_INIT` 这类命令建 task，
    // `CMD_APP_CHECK` 单独发会被 `AdminTask(OP_QUERY)` 查不到 task 后静默丢弃。
    // 官方 `HdcTaskBase` 构造函数在建 master task 时正是先发这一帧。
    let wake = Frame::new(channel_id, Command::KernelWakeupSlaveTask, Vec::new());
    transport.send_packet(&wake.encode()).await?;

    let config = build_check_config(hap.len() as u64, file_name_hint)?;
    let check = Frame::new(channel_id, Command::AppCheck, config.encode());
    transport.send_packet(&check.encode()).await?;

    // 设备先回 APP_BEGIN 才允许灌数据；若包本身就不合法，这里会直接回 APP_FINISH。
    let features = loop {
        let raw = transport.recv_packet().await?;
        let frame = Frame::decode(&raw)?;
        match frame.command {
            Command::AppBegin => break parse_features(&frame.data)?,
            Command::AppFinish => return parse_install_reply(&frame.data),
            // 通道号不匹配或中间态噪声，继续等目标帧。
            _ => continue,
        }
    };

    let chunk = chunk_size(features);
    if chunk == 0 {
        return Err(Error::BadHandshake {
            reason: "分片大小算成了 0",
        });
    }

    // `TransferPayload.index` 是分片在文件中的**字节偏移**，不是分片序号：
    // 设备端 `HdcTransferBase::RecvIOPayload` 把它直接当作 `uv_fs_write` 的
    // offset 使用，按序号递增会让每片都写到文件开头附近，落盘内容全错。
    let mut offset = 0usize;
    while offset < hap.len() {
        let end = (offset + chunk).min(hap.len());
        let payload = build_data_payload(offset as u64, &hap[offset..end]);
        let frame = Frame::new(channel_id, Command::AppData, payload);
        transport.send_packet(&frame.encode()).await?;
        offset = end;
    }

    // 设备此时开始跑 bm install，耗时不可控，放宽读超时。
    transport.set_io_timeout(INSTALL_TIMEOUT);
    let result = loop {
        let raw = transport.recv_packet().await?;
        let frame = Frame::decode(&raw)?;
        if frame.command == Command::AppFinish {
            break parse_install_reply(&frame.data)?;
        }
    };
    Ok(result)
}
/// 卸载设备上的一个应用（对应官方 `hdc uninstall <bundle>`）。
///
/// 与安装的两点不同：
///
/// 1. **不需要先发 `CMD_KERNEL_WAKEUP_SLAVETASK`**。`CMD_APP_UNINSTALL` 本身就在
///    官方 `HdcSessionBase::NeedNewTaskInfo` 的 `taskMasterInit` 名单里，设备端
///    收到它就会建 task；而 `CMD_APP_CHECK` 不在名单里，所以安装必须先唤醒。
/// 2. **不传文件**。载荷是空格分隔的命令行串，设备端 `SplitCommand` 把 `-` 开头的
///    当选项、其余当包名，拼成 `bm uninstall <options> <packages>` 交给 shell。
///
/// 结果仍由 `CMD_APP_FINISH` 带回，格式与安装一致。
pub async fn uninstall_app(transport: &mut UsbTransport, bundle: &str) -> Result<InstallResult> {
    if bundle.trim().is_empty() {
        return Err(Error::BadHandshake {
            reason: "待卸载的包名为空",
        });
    }

    let channel_id = random_channel_id()?;
    let frame = Frame::new(
        channel_id,
        Command::AppUninstall,
        bundle.as_bytes().to_vec(),
    );
    transport.send_packet(&frame.encode()).await?;

    // 设备侧要跑 `bm uninstall`，耗时同样不可控。
    transport.set_io_timeout(INSTALL_TIMEOUT);
    let result = loop {
        let raw = transport.recv_packet().await?;
        let frame = Frame::decode(&raw)?;
        if frame.command == Command::AppFinish {
            break parse_install_reply(&frame.data)?;
        }
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 大缓冲分片是缓冲容量的八成() {
        let features = Features {
            huge_buf: true,
            compress_lz4: false,
            stable_buf: false,
            sandbox_supported: true,
        };
        assert_eq!(chunk_size(features), MAX_SIZE_IOBUF * 8 / 10);
    }

    #[test]
    fn 稳定分片是稳定缓冲容量的八成() {
        let features = Features {
            huge_buf: false,
            compress_lz4: false,
            stable_buf: true,
            sandbox_supported: false,
        };
        assert_eq!(chunk_size(features), MAX_SIZE_IOBUF_STABLE * 8 / 10);
    }

    #[test]
    fn 空特性载荷走稳定缓冲() {
        let features = parse_features(&[]).unwrap();
        assert!(features.stable_buf);
        assert!(!features.huge_buf);
    }

    #[test]
    fn 真机特性字节解析正确() {
        // 真机抓包：CMD_APP_BEGIN 载荷首字节 0x05。
        let features = parse_features(&[0x05, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(features.huge_buf);
        assert!(!features.stable_buf);
        assert!(features.sandbox_supported);
    }

    #[test]
    fn 分片载荷前缀定长且字段正确() {
        let chunk = vec![0xabu8; 10];
        let payload = build_data_payload(7, &chunk);
        assert_eq!(payload.len(), PAYLOAD_PREFIX_RESERVE + 10);
        // 分片头四个字段的 protobuf 编码：index=7, compressType=0,
        // compressSize=10, uncompressSize=10。
        assert_eq!(
            &payload[..8],
            &[0x08, 0x07, 0x10, 0x00, 0x18, 0x0a, 0x20, 0x0a]
        );
        // 剩余前缀补 0。
        assert!(payload[8..PAYLOAD_PREFIX_RESERVE].iter().all(|b| *b == 0));
        assert_eq!(&payload[PAYLOAD_PREFIX_RESERVE..], &chunk[..]);
    }

    #[test]
    fn 安装失败结果按错误消息判定() {
        let mut data = vec![1u8, 0];
        data.extend_from_slice(
            b"error: failed to install bundle. code:9568320 error: no signature file. ",
        );
        let result = parse_install_reply(&data).unwrap();
        assert_eq!(result.mode, 1);
        assert_eq!(result.exit_status, 0);
        assert!(result.message.to_ascii_lowercase().contains("error"));
    }

    #[test]
    fn 安装成功结果判定() {
        // 真机成功回包：exitStatus 字节同为 0，只能靠消息区分。
        let mut data = vec![1u8, 0];
        data.extend_from_slice(b"install bundle successfully. ");
        let result = parse_install_reply(&data).unwrap();
        assert_eq!(result.exit_status, 0);
        assert!(result.message.contains("successfully"));

        // 空消息不带成功字样。
        assert!(
            !parse_install_reply(&[1u8, 0])
                .unwrap()
                .message
                .contains("successfully")
        );
    }

    #[test]
    fn 随机文件名带正确扩展名() {
        let name = optional_name("/opt/x/entry-default-signed.hap").unwrap();
        assert_eq!(name.len(), EXPECTED_LEN + 4);
        assert!(name.ends_with(".hap"));
        assert!(name[..EXPECTED_LEN].chars().all(|c| c.is_ascii_hexdigit()));

        let hsp = optional_name("mod.hsp").unwrap();
        assert!(hsp.ends_with(".hsp"));

        let other = optional_name("weird.bin").unwrap();
        assert!(other.ends_with(".bundle"));
    }
}
