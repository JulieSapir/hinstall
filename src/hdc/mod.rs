//! HDC 协议与 USB 传输的纯 Rust 实现。
//!
//! 移植自 `deprecated/crates/hdc-proto` 与 `deprecated/crates/hdc-usb`，
//! 按 `tool.py` 的实际使用面裁剪，只保留 native 分支。

pub mod auth;
pub mod command;
pub mod config;
pub mod device;
pub mod error;
pub mod handshake;
pub mod install;
pub mod packet;
pub mod proto_error;
pub mod ser;
pub mod session;
pub mod tlv;
pub mod transfer;
pub mod transport;

pub use command::Command;
pub use error::Error;
pub use packet::Frame;

pub use auth::AuthKey;
pub use session::HdcSession;
