// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 会话层：握手、认证与命令收发。
//!
//! 连接顺序与官方 host 侧一致：打开设备 → 软复位清通道 →
//! 发 `KERNEL_HANDSHAKE` 帧 → 校验设备返回的握手 → 若设备要求公钥认证则走完
//! 认证往返 → 采用设备侧会话号。

use std::time::Duration;

use crate::hdc::command::Command;
use crate::hdc::config::HDC_VERSION;
use crate::hdc::handshake::{AuthType, SessionHandShake};
use crate::hdc::packet::Frame;
use nusb::DeviceInfo;

use crate::hdc::auth::AuthKey;
use crate::hdc::error::{Error, Result};
use crate::hdc::transport::{DEFAULT_IO_TIMEOUT, UsbTransport};

/// 公钥认证阶段的读超时。
///
/// 设备首次见到一把公钥时会弹信任窗口等用户点确认，耗时不可控，因此这里远
/// 大于普通命令的 3 秒。
const AUTH_TIMEOUT: Duration = Duration::from_secs(120);

/// 生成一个非 0 的随机会话号。
///
/// 对齐官方 `HdcSessionBase::GetSessionPseudoUid()`：取 32 位安全随机数并排除 0
/// （0 在协议里表示「沿用上一个会话」）。
fn random_session_id() -> Result<u32> {
    loop {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).map_err(|_| Error::NoRandom)?;
        let id = u32::from_be_bytes(buf);
        if id != 0 {
            return Ok(id);
        }
    }
}

/// 读一帧认证响应，把读超时翻译成 [`Error::AuthTimeout`]。
///
/// 这个区分很关键：认证阶段超时说明设备正在等用户点确认，调用方**不能**重试
/// （重试会重发公钥，设备就再弹一个窗口），只能停下来提示用户。
async fn read_auth_reply(transport: &mut UsbTransport) -> Result<Vec<u8>> {
    transport.recv_packet().await.map_err(|e| match e {
        Error::Timeout { .. } => Error::AuthTimeout {
            secs: AUTH_TIMEOUT.as_secs(),
        },
        other => other,
    })
}

/// 走完设备要求的公钥认证往返，返回设备版本串。
///
/// 四帧全部用 `CMD_KERNEL_HANDSHAKE`（channel 0），流程见 [`crate::hdc::auth`] 的
/// 模块说明。`handshake` 在过程中被就地改写，因为四帧只差 `auth_type` 与 `buf`。
async fn authenticate(
    transport: &mut UsbTransport,
    handshake: &mut SessionHandShake,
    key: Option<&AuthKey>,
) -> Result<String> {
    let key = key.ok_or(Error::AuthRequired)?;

    // 设备首次见到这把公钥会弹信任窗口，等用户点确认的时间不可控，必须把读
    // 超时放大。
    transport.set_io_timeout(AUTH_TIMEOUT);

    // 第二步：把公钥交给设备。
    handshake.auth_type = AuthType::PublicKey.as_u8();
    handshake.buf = key.public_key_info();
    transport
        .send_packet(&Frame::new(0, Command::KernelHandshake, handshake.encode()).encode())
        .await?;

    let raw = read_auth_reply(transport).await?;
    let reply = Frame::decode(&raw)?;
    let challenge = SessionHandShake::decode(&reply.data)?;
    if challenge.auth_type != AuthType::Signature.as_u8() {
        return Err(Error::UnexpectedAuthType {
            expected: AuthType::Signature.as_u8(),
            got: challenge.auth_type,
        });
    }

    // 第三步：对设备下发的 token 签名回送。
    handshake.auth_type = AuthType::Signature.as_u8();
    handshake.buf = key.sign(challenge.buf.as_bytes())?;
    transport
        .send_packet(&Frame::new(0, Command::KernelHandshake, handshake.encode()).encode())
        .await?;

    let raw = read_auth_reply(transport).await?;
    let reply = Frame::decode(&raw)?;
    let ok = SessionHandShake::decode(&reply.data)?;
    if ok.auth_type != AuthType::Ok.as_u8() {
        return Err(Error::AuthFailed);
    }

    // 设备在 AUTH_OK 之后固定再补一帧 CMD_KERNEL_CHANNEL_CLOSE（官方
    // `HdcDaemon::SendAuthOkMsg` 的收尾），必须读掉，否则它会留在接收流里，
    // 被后续第一个业务命令当成响应。
    let raw = read_auth_reply(transport).await?;
    let tail = Frame::decode(&raw)?;
    if tail.command != Command::KernelChannelClose {
        return Err(Error::UnexpectedCommand {
            expected: Command::KernelChannelClose.as_u16(),
            got: tail.command.as_u16(),
        });
    }

    // 认证期间放大的超时到此为止，业务命令恢复默认值。
    transport.set_io_timeout(DEFAULT_IO_TIMEOUT);
    Ok(ok.version)
}

/// 一条已建立的 HDC 会话。
pub struct HdcSession {
    /// 底层 USB 通道。
    transport: UsbTransport,
}

impl HdcSession {
    /// 打开设备并完成握手（含设备要求的公钥认证）。
    ///
    /// `session_id` 传 0 表示让本端自动生成随机会话号（推荐）。首包必须携带
    /// **非 0** 会话号：设备端 `HdcDaemonUSB::DispatchToWorkThread` 会把
    /// `sessionId == 0` 替换成上一个会话号，随后 `HdcUSBBase::CheckPacketOption`
    /// 判定会话号不匹配，把整包当残留数据丢弃 —— 表现就是握手包发出去后设备
    /// 永不回应。官方 `HdcSessionBase::MallocSession` 用 `GetSessionPseudoUid()`
    /// 取 32 位安全随机数，这里对齐该行为。
    ///
    /// `connectKey` 取设备序列号（官方 `HdcUSBBase` 同样用 iSerialNumber），
    /// 缺失时退化为空串。
    ///
    /// `key` 为认证密钥：设备端 `authEnable` 打开时会回 `AUTH_PUBLICKEY` 要求
    /// 认证，此时必须提供，否则返回 [`Error::AuthRequired`]。
    pub async fn connect(
        info: &DeviceInfo,
        session_id: u32,
        key: Option<&AuthKey>,
    ) -> Result<Self> {
        let session_id = if session_id == 0 {
            random_session_id()?
        } else {
            session_id
        };
        let connect_key = info.serial_number().unwrap_or_default().to_string();
        let mut transport = UsbTransport::open(info, session_id, DEFAULT_IO_TIMEOUT).await?;
        transport.soft_reset().await?;

        let mut handshake = SessionHandShake::new_usb(session_id, &connect_key, HDC_VERSION);
        transport
            .send_packet(&Frame::new(0, Command::KernelHandshake, handshake.encode()).encode())
            .await?;

        let raw = transport.recv_packet().await?;
        let reply = Frame::decode(&raw)?;
        if reply.command != Command::KernelHandshake {
            return Err(Error::UnexpectedCommand {
                expected: Command::KernelHandshake.as_u16(),
                got: reply.command.as_u16(),
            });
        }
        let peer = SessionHandShake::decode(&reply.data)?;
        if peer.banner != handshake.banner {
            return Err(Error::BadHandshake {
                reason: "设备返回的 banner 与本端不一致",
            });
        }
        let negotiated_session_id = if peer.session_id == 0 {
            session_id
        } else {
            peer.session_id
        };
        transport.set_session_id(negotiated_session_id);

        // 设备要求公钥认证时，先把它要求的公钥送过去，再用私钥对 token 签名。
        if peer.auth_type == AuthType::PublicKey.as_u8() {
            authenticate(&mut transport, &mut handshake, key).await?;
        }

        Ok(Self { transport })
    }

    /// 底层通道的可变引用。
    pub fn transport_mut(&mut self) -> &mut UsbTransport {
        &mut self.transport
    }
}

#[cfg(test)]
mod tests {
    use crate::hdc::config::HDC_VERSION;

    #[test]
    fn 版本串格式() {
        assert!(
            HDC_VERSION.starts_with("Ver: "),
            "版本串应与官方 GetVersion 格式一致"
        );
    }
}
