//! 错误类型。
//!
//! 全部错误显式向上传播，不做静默回退：签名产物一旦出错必须立刻暴露，
//! 不能产出「看起来成功了」的坏签名。

use std::fmt;

/// 签名库统一错误类型。
#[derive(Debug)]
pub enum Error {
    /// DER/ASN.1 结构非法。
    Der(&'static str),
    /// X.509 证书结构非法。
    X509(&'static str),
    /// CMS/PKCS#7 结构非法。
    Cms(&'static str),
    /// ZIP 结构非法。
    Zip(String),
    /// 密码学运算失败（密钥非法、签名失败等）。
    Crypto(String),
    /// 调用方传入的输入非法。
    Invalid(String),
    /// 底层 IO 失败。
    Io(std::io::Error),
}

/// 本库统一结果类型。
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Der(m) => write!(f, "DER 解析失败: {m}"),
            Error::X509(m) => write!(f, "证书解析失败: {m}"),
            Error::Cms(m) => write!(f, "CMS 结构非法: {m}"),
            Error::Zip(m) => write!(f, "ZIP 结构非法: {m}"),
            Error::Crypto(m) => write!(f, "密码学运算失败: {m}"),
            Error::Invalid(m) => write!(f, "输入非法: {m}"),
            Error::Io(e) => write!(f, "IO 失败: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// 构造 [`Error::Crypto`] 的快捷方式。
pub fn crypto(msg: impl Into<String>) -> Error {
    Error::Crypto(msg.into())
}
