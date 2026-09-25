// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! USB 传输层错误类型。

use std::fmt;

/// USB 传输层错误。
#[derive(Debug)]
pub enum Error {
    /// nusb 底层错误。
    Usb(nusb::Error),
    /// 传输本身失败（STALL、超时、断开等）。
    Transfer(nusb::transfer::TransferError),
    /// 协议层错误。
    Proto(crate::hdc::proto_error::Error),
    /// 没有找到符合 HDC 特征（class 0xff / subclass 0x50 / proto 0x01）的设备。
    NoDevice,
    /// 目标接口缺少成对的 bulk 端点。
    NoBulkEndpoint {
        /// 接口号。
        interface: u8,
    },
    /// 等待数据超时。
    Timeout {
        /// 所处阶段（读头 / 读体 / 写）。
        stage: &'static str,
        /// 等待的毫秒数。
        ms: u64,
    },
    /// 设备在传输过程中断开。
    Disconnected,
    /// 收到的帧长度超过协议上限。
    FrameTooLarge {
        /// 声明的长度。
        declared: u32,
        /// 允许上限。
        max: u32,
    },
    /// 设备返回的命令字与请求不符。
    UnexpectedCommand {
        /// 请求的命令字。
        expected: u16,
        /// 实际收到的命令字。
        got: u16,
    },
    /// 握手响应内容不符合协议。
    BadHandshake {
        /// 具体原因。
        reason: &'static str,
    },
    /// 系统随机数不可用，无法生成会话号。
    NoRandom,
    /// 设备要求认证，但调用方没有提供密钥。
    AuthRequired,
    /// 等待用户在设备上确认信任窗口超时。
    ///
    /// 与普通 [`Error::Timeout`] 分开，因为它的处置方式完全不同：设备正等着
    /// 用户点确认，本端一旦重试就会重发公钥，设备会跟着再弹一个窗口。
    AuthTimeout {
        /// 等待的秒数。
        secs: u64,
    },
    /// 读取本机 hdc 密钥失败（`~/.harmony/hdckey` 或 `hdckey.pub` 不可用）。
    NoAuthKey,
    /// 密钥内容无法解析。
    BadAuthKey,
    /// 设备判定认证失败。
    AuthFailed,
    /// 设备在认证流程里返回了预期之外的状态。
    UnexpectedAuthType {
        /// 期望的认证类型值。
        expected: u8,
        /// 实际收到的认证类型值。
        got: u8,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usb(e) => write!(f, "USB 错误: {e}"),
            Error::Transfer(e) => write!(f, "USB 传输失败: {e:?}"),
            Error::Proto(e) => write!(f, "协议错误: {e}"),
            Error::NoDevice => write!(
                f,
                "未发现 HDC 设备（class 0xff / subclass 0x50 / protocol 0x01）"
            ),
            Error::NoBulkEndpoint { interface } => {
                write!(f, "接口 {interface} 上没有找到成对的 bulk 端点")
            }
            Error::Timeout { stage, ms } => write!(f, "{stage} 等待超时（{ms} ms）"),
            Error::Disconnected => write!(f, "设备已断开"),
            Error::FrameTooLarge { declared, max } => {
                write!(f, "帧长度 {declared} 超过上限 {max}")
            }
            Error::UnexpectedCommand { expected, got } => {
                write!(f, "命令字不符：期望 {expected}，实际 {got}")
            }
            Error::BadHandshake { reason } => write!(f, "握手失败：{reason}"),
            Error::NoRandom => write!(f, "系统随机数不可用，无法生成会话号"),
            Error::AuthRequired => write!(f, "设备要求认证，但没有提供本机密钥"),
            Error::AuthTimeout { secs } => write!(
                f,
                "等待设备确认信任窗口超时（{secs} 秒）：请在设备上点「允许」后重试"
            ),
            Error::NoAuthKey => {
                write!(
                    f,
                    "读不到本机 hdc 密钥（需要 ~/.harmony/hdckey 与 hdckey.pub）"
                )
            }
            Error::BadAuthKey => write!(f, "密钥内容无法解析"),
            Error::AuthFailed => write!(f, "设备判定认证失败"),
            Error::UnexpectedAuthType { expected, got } => {
                write!(f, "认证状态不符：期望 {expected}，实际 {got}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<nusb::Error> for Error {
    fn from(e: nusb::Error) -> Self {
        Error::Usb(e)
    }
}

impl From<nusb::transfer::TransferError> for Error {
    fn from(e: nusb::transfer::TransferError) -> Self {
        Error::Transfer(e)
    }
}

impl From<crate::hdc::proto_error::Error> for Error {
    fn from(e: crate::hdc::proto_error::Error) -> Self {
        Error::Proto(e)
    }
}

/// USB 传输层结果类型。
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 认证超时提示带秒数且指向信任窗口() {
        let text = Error::AuthTimeout { secs: 120 }.to_string();
        assert!(text.contains("120"), "实际: {text}");
        assert!(text.contains("信任窗口"), "实际: {text}");
    }
}
