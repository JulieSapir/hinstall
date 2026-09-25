//! 工具级错误与结果类型。
//!
//! `tool.py` 用 `die()` 直接退出；移植后统一为 `Err`，由 `main` 打印
//! `错误: <消息>` 并以退出码 1 结束，对外行为完全一致。

use std::fmt;

/// 带一句中文说明的失败。
#[derive(Debug)]
pub struct Fail(pub String);

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fail {}

/// 本工具的结果类型。
pub type R<T> = std::result::Result<T, Fail>;

impl From<crate::hap_sign::error::Error> for Fail {
    fn from(e: crate::hap_sign::error::Error) -> Self {
        Fail(e.to_string())
    }
}

impl From<crate::hdc::Error> for Fail {
    fn from(e: crate::hdc::Error) -> Self {
        Fail(format!("设备通信失败: {e}"))
    }
}

impl From<crate::hdc::proto_error::Error> for Fail {
    fn from(e: crate::hdc::proto_error::Error) -> Self {
        Fail(format!("设备通信协议错误: {e}"))
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        Fail(format!("文件操作失败: {e}"))
    }
}

impl From<std::num::ParseIntError> for Fail {
    fn from(e: std::num::ParseIntError) -> Self {
        Fail(format!("数字解析失败: {e}"))
    }
}

impl From<std::string::FromUtf8Error> for Fail {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Fail(format!("文本解码失败: {e}"))
    }
}
