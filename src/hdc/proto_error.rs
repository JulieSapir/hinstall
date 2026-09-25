// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 协议层错误类型。不吞错误：所有异常输入都显式返回 Err。

use std::fmt;

/// 协议编解码错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 数据不足，需要更多字节。
    UnexpectedEof {
        /// 需要的字节数。
        need: usize,
        /// 实际拥有的字节数。
        got: usize,
    },
    /// 帧头魔数不匹配。
    BadFlag {
        /// 期望的魔数。
        expected: [u8; 2],
        /// 实际读到的魔数。
        got: [u8; 2],
    },
    /// 长度字段超出允许上限。
    LengthTooLarge {
        /// 字段名。
        field: &'static str,
        /// 实际长度。
        value: u64,
        /// 允许上限。
        max: u64,
    },
    /// varint 编码超过 10 字节仍未结束。
    VarintOverflow,
    /// 字段 tag 的 wire type 不受支持。
    UnsupportedWireType(u8),
    /// 字符串字段不是合法 UTF-8。
    InvalidUtf8 {
        /// 字段名。
        field: &'static str,
    },
    /// 字段 tag 与结构定义不符。
    UnknownField {
        /// 结构名。
        message: &'static str,
        /// 出问题的 tag。
        tag: u32,
    },
    /// 命令字不在已知集合内。
    UnknownCommand(u16),
    /// 固定长度的字段实际长度不对。
    BadFieldLength {
        /// 字段名。
        field: &'static str,
        /// 期望长度。
        expected: usize,
        /// 实际长度。
        got: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof { need, got } => {
                write!(f, "数据不足：需要 {need} 字节，只有 {got} 字节")
            }
            Error::BadFlag { expected, got } => write!(
                f,
                "帧头魔数不匹配：期望 {:?}，实际 {:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(got)
            ),
            Error::LengthTooLarge { field, value, max } => {
                write!(f, "字段 {field} 长度 {value} 超过上限 {max}")
            }
            Error::VarintOverflow => write!(f, "varint 超过 10 字节仍未终止"),
            Error::UnsupportedWireType(w) => write!(f, "不支持的 wire type: {w}"),
            Error::InvalidUtf8 { field } => write!(f, "字段 {field} 不是合法 UTF-8"),
            Error::UnknownField { message, tag } => {
                write!(f, "结构 {message} 中不存在 tag={tag} 的字段")
            }
            Error::UnknownCommand(v) => write!(f, "未知命令字: {v}"),
            Error::BadFieldLength {
                field,
                expected,
                got,
            } => {
                write!(f, "字段 {field} 长度应为 {expected}，实际 {got}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// 协议层结果类型。
pub type Result<T> = std::result::Result<T, Error>;
