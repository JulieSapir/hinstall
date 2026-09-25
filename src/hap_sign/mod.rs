//! HarmonyOS HAP 签名方案 v3 的纯 Rust 实现。
//!
//! 移植自 `deprecated/crates/hap-sign`，按 `tool.py` 的实际使用面裁剪。

pub mod cms;
pub mod codesign;
pub mod crypto;
pub mod der;
pub mod error;
pub mod hap;
pub mod json;
pub mod sign;
pub mod time;
pub mod x509;
pub mod zip;
