// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! HDC 协议常量。
//!
//! 数值取自官方 `developtools_hdc` 的 `src/common/define_plus.h`、
//! `src/common/session.h` 与 `hdc_rust/src/config.rs`，
//! 均为协议事实（非可版权表达的代码），此处按事实重写。

/// 通用 payload 帧头魔数（`PayloadHead.flag`）。
pub const PACKET_FLAG: [u8; 2] = *b"HW";

/// USB 传输帧头魔数（`USBHead.flag`）。
pub const USB_PACKET_FLAG: [u8; 2] = *b"UB";

/// 协议版本，写入 `PayloadHead.protocolVer`。
pub const VER_PROTOCOL: u8 = 1;

/// `PayloadProtect.vCode` 固定值，收发双方都要校验。
pub const PAYLOAD_VCODE: u8 = 0x09;

/// USB 传输头长度：`flag[2] + option[1] + sessionId[4] + dataSize[4]`（packed）。
pub const USB_HEAD_SIZE: usize = 11;

/// 通用 payload 头长度：`flag[2] + reserve[2] + protocolVer[1] + headSize[2] + dataSize[4]`（packed）。
pub const PAYLOAD_HEAD_SIZE: usize = 11;

/// 握手 banner 固定文本。
pub const HANDSHAKE_BANNER: &str = "OHOS HDC";

/// 版本串。官方 `Base::GetVersion()` 返回 `Ver: 3.1.0e`，再拼上编译期生成的
/// 源码指纹 `HDC_MSG_HASH`（`scripts/hdc_hash_gen.py`：对源文件清单做 SHA-256，
/// 取前 16 位十六进制）。完整串见 `src/common/base.cpp` 的 `HDC_MSG_HASH` 宏。
///
/// 该值来自对官方 hdc 3.1.0e 的 usbmon 抓包（`SessionHandShake.version` 字段），
/// 与设备回包中的 version 逐字节一致。
pub const HDC_VERSION: &str = "Ver: 3.1.0e7bca7aebfc4e7048";

/// banner 字段长度上限（官方 `BANNER_SIZE`）。
pub const BANNER_SIZE: usize = 12;

/// connectKey 字段长度上限（官方 `KEY_MAX_SIZE`）。
pub const KEY_MAX_SIZE: usize = 32;

/// 单个 payload 的 data 上限。
pub const HDC_BUF_MAX_SIZE: usize = 0x7fff_ffff;

/// USB 端点单包大小（高速）。
pub const MAX_PACKET_SIZE_HISPEED: u16 = 512;

/// 大缓冲模式下单次 IO 的长度上限（官方 `MAX_SIZE_IOBUF`）。
pub const MAX_SIZE_IOBUF: usize = 511 * 1024;

/// 稳定缓冲模式下单次 IO 的长度上限（官方 `MAX_SIZE_IOBUF_STABLE`）。
pub const MAX_SIZE_IOBUF_STABLE: usize = 60 * 1024;

/// 本端 USB bulk 读请求的缓冲大小。
///
/// 官方这里用 `GetUsbffsBulkSize()`（512KB），但 `nusb` 的
/// `Endpoint::allocate` 每次调用都要重新申请一块缓冲，512KB 在「一帧一发」的
/// 命令交互里开销明显。设备单次回包不会超过 64KB，实测 61440 足够，同时还能
/// 避开 `LIBUSB_ERROR_OVERFLOW`。
pub const USB_READ_BUF_SIZE: usize = 61440;

/// USB 头 option：普通数据包。
pub const USB_OPTION_HEADER: u8 = 1;

/// USB 头 option：软复位（清空通道）。
pub const USB_OPTION_RESET: u8 = 2;

/// USB 头 option：占位包（防止 0 长度包）。
pub const USB_OPTION_DUMMY: u8 = 0;

/// 软复位后读取排空时，单次 bulk 读的超时（毫秒）。
pub const USB_RESET_READ_TIMEOUT_MS: u64 = 160;

/// 软复位后最多排空多久（毫秒）。
///
/// 官方 `src/common/define.h` 的 `NEW_SESSION_DROP_USB_DATA_TIME_MAX_MS = 1000`。
/// 这个上限不是性能调优值而是协议约束：设备端在收到软复位后约 1 秒内必须收到握手，
/// 超时它会主动 reset USB gadget（表现为设备重新枚举、传输报 Disconnected）。
pub const USB_RESET_MAX_DRAIN_MS: u64 = 1000;

/// 排空过程中累计丢弃超过该字节数时补发一次软复位。
pub const USB_RESET_RETRY_BYTES: u64 = 1024 * 1024;
