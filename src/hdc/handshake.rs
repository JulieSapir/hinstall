// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 会话握手结构。
//!
//! 对应官方 `src/common/session.h` 的 `SessionHandShake`，
//! 字段 tag 与 `serial_struct_define.h` 中的 `Field<...>` 声明一致。

use crate::hdc::config::{BANNER_SIZE, HANDSHAKE_BANNER, KEY_MAX_SIZE};
use crate::hdc::proto_error::{Error, Result};
use crate::hdc::ser;
use crate::hdc::tlv::{AuthVerifyType, TAG_AUTH_TYPE, tlv_new};

/// 握手认证类型（官方 `HdcSessionBase::AuthType`）。
///
/// 只保留本端会用到的取值：USB 直连时不发认证（`None`），设备要求公钥认证时
/// 回 `PublicKey`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthType {
    /// 无需认证（USB 直连时使用）。
    None = 0,
    /// 签名认证。
    Signature = 2,
    /// 公钥认证。
    PublicKey = 3,
    /// 认证通过。
    Ok = 4,
}

impl AuthType {
    /// 取数值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// 握手报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHandShake {
    /// 固定为 `OHOS HDC`。
    pub banner: String,
    /// 认证类型。
    pub auth_type: u8,
    /// 会话号。
    pub session_id: u32,
    /// 连接密钥。USB 直连时官方填**设备序列号**（`hSession->connectKey`
    /// 由 `HdcUSBBase` 从设备描述符的 iSerialNumber 读取），
    /// 见官方 usbmon 抓包中该字段为 16 字节的 `3QC0225930000504`。
    pub connect_key: String,
    /// 能力协商串（TLV 拼接）。官方至少写入一条 `authtype` TLV，
    /// 声明本端支持 RSA-3072/SHA-512。
    pub buf: String,
    /// 版本串，设备侧只做日志记录，不参与校验。
    pub version: String,
}

impl SessionHandShake {
    /// 构造 USB 直连握手：`authType = AUTH_NONE`，`connectKey` 为设备序列号，
    /// `buf` 携带 `authtype` 能力协商 TLV。
    ///
    /// 与官方 `HdcSessionBase::WorkThreadInitSession` 的行为一致：
    /// 该函数在 `handshake.authType = AUTH_NONE` 之后调用
    /// `Base::TlvAppend(handshake.buf, TAG_AUTH_TYPE, "1")`，
    /// 其中 `1` 即 `AuthVerifyType::RSA_3072_SHA512`。
    ///
    /// `connect_key` 传设备序列号。
    pub fn new_usb(
        session_id: u32,
        connect_key: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            banner: HANDSHAKE_BANNER.to_string(),
            auth_type: AuthType::None.as_u8(),
            session_id,
            connect_key: connect_key.into(),
            buf: tlv_new(
                TAG_AUTH_TYPE,
                &AuthVerifyType::Rsa3072Sha512.as_u8().to_string(),
            ),
            version: version.into(),
        }
    }

    /// 序列化。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        ser::write_string_field(1, &self.banner, &mut out);
        ser::write_u8_field(2, self.auth_type, &mut out);
        ser::write_u32_field(3, self.session_id, &mut out);
        ser::write_string_field(4, &self.connect_key, &mut out);
        ser::write_string_field(5, &self.buf, &mut out);
        ser::write_string_field(6, &self.version, &mut out);
        out
    }

    /// 反序列化。
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut banner = String::new();
        let mut auth_type = 0u8;
        let mut session_id = 0u32;
        let mut connect_key = String::new();
        let mut buf = String::new();
        let mut version = String::new();
        let mut pos = 0usize;
        while pos < raw.len() {
            let (field, wire) = ser::read_tag(raw, &mut pos)?;
            match (field, wire) {
                (1, ser::WireType::LengthDelimited) => {
                    banner =
                        ser::read_string_field(raw, &mut pos, "banner", BANNER_SIZE)?.to_string();
                }
                (2, ser::WireType::Varint) => {
                    auth_type = ser::read_varint(raw, &mut pos)? as u8;
                }
                (3, ser::WireType::Varint) => {
                    let v = ser::read_varint(raw, &mut pos)?;
                    session_id = u32::try_from(v).map_err(|_| Error::VarintOverflow)?;
                }
                (4, ser::WireType::LengthDelimited) => {
                    connect_key =
                        ser::read_string_field(raw, &mut pos, "connectKey", KEY_MAX_SIZE)?
                            .to_string();
                }
                (5, ser::WireType::LengthDelimited) => {
                    buf = ser::read_string_field(raw, &mut pos, "buf", 64 * 1024)?.to_string();
                }
                (6, ser::WireType::LengthDelimited) => {
                    version = ser::read_string_field(raw, &mut pos, "version", 256)?.to_string();
                }
                _ => ser::skip_field(raw, &mut pos, wire)?,
            }
        }
        if banner != HANDSHAKE_BANNER {
            return Err(Error::BadFlag {
                expected: {
                    let mut e = [0u8; 2];
                    e.copy_from_slice(&HANDSHAKE_BANNER.as_bytes()[..2]);
                    e
                },
                got: {
                    let b = banner.as_bytes();
                    let mut g = [0u8; 2];
                    let n = b.len().min(2);
                    g[..n].copy_from_slice(&b[..n]);
                    g
                },
            });
        }
        Ok(Self {
            banner,
            auth_type,
            session_id,
            connect_key,
            buf,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 认证类型数值与官方一致() {
        assert_eq!(AuthType::None.as_u8(), 0);
        assert_eq!(AuthType::Signature.as_u8(), 2);
        assert_eq!(AuthType::PublicKey.as_u8(), 3);
        assert_eq!(AuthType::Ok.as_u8(), 4);
    }

    #[test]
    fn usb_握手_序列化字节逐字节核对() {
        let hs = SessionHandShake::new_usb(0, "", "");
        // banner    : 0a 08 "OHOS HDC"
        // authType  : 10 00
        // sessionId : 18 00
        // connectKey: 22 00
        // buf       : 2a 21 <33 字节 authtype TLV>
        // version   : 32 00
        let mut expect = vec![
            0x0a, 0x08, b'O', b'H', b'O', b'S', b' ', b'H', b'D', b'C', 0x10, 0x00, 0x18, 0x00,
            0x22, 0x00, 0x2a, 0x21,
        ];
        expect.extend_from_slice(b"authtype        ");
        expect.extend_from_slice(b"1               ");
        expect.push(b'1');
        expect.push(0x32);
        expect.push(0x00);
        assert_eq!(hs.encode(), expect);
    }

    #[test]
    fn usb_握手_与官方_usbmon_抓包逐字节一致() {
        // 来源：官方 hdc 3.1.0e 直连设备时 usbmon 抓到的 SessionHandShake 99 字节原文。
        // 会话号 114545449 (0x06d3d329)，connectKey 为设备序列号。
        let hs = SessionHandShake::new_usb(
            114_545_449,
            "3QC0225930000504",
            crate::hdc::config::HDC_VERSION,
        );
        let expect: Vec<u8> = [
            &[0x0a, 0x08][..],
            b"OHOS HDC",
            &[0x10, 0x00, 0x18, 0xa9, 0xa6, 0xcf, 0x36, 0x22, 0x10],
            b"3QC0225930000504",
            &[0x2a, 0x21],
            b"authtype        ",
            b"1               ",
            b"1",
            &[0x32, 0x1b],
            b"Ver: 3.1.0e7bca7aebfc4e7048",
        ]
        .concat();
        assert_eq!(expect.len(), 99, "官方握手 data 长度为 99 字节");
        assert_eq!(hs.encode(), expect);
    }

    #[test]
    fn usb_握手_带会话号与版本() {
        let hs = SessionHandShake::new_usb(0x0102_0304, "3QC0225930000504", "3.1.0e");
        let raw = hs.encode();
        // sessionId 走 varint: 0x01020304 = 16909060 -> 84 86 88 08
        assert!(
            raw.windows(4).any(|w| w == [0x84, 0x86, 0x88, 0x08]),
            "sessionId 应以 4 字节 varint 编码"
        );
        let back = SessionHandShake::decode(&raw).unwrap();
        assert_eq!(back, hs);
    }

    #[test]
    fn 握手_往返() {
        let mut hs = SessionHandShake::new_usb(42, "3QC0225930000504", "Ver: 3.1.0e");
        hs.buf = "k1=v1;k2=v2".to_string();
        let raw = hs.encode();
        assert_eq!(SessionHandShake::decode(&raw).unwrap(), hs);
    }

    #[test]
    fn 握手_banner_不符报错() {
        let mut hs = SessionHandShake::new_usb(0, "", "");
        hs.banner = "XX HDC".to_string();
        let raw = hs.encode();
        assert!(matches!(
            SessionHandShake::decode(&raw),
            Err(Error::BadFlag { .. })
        ));
    }

    #[test]
    fn 握手_缺字段用默认值() {
        let mut raw = Vec::new();
        crate::hdc::ser::write_string_field(1, "OHOS HDC", &mut raw);
        let hs = SessionHandShake::decode(&raw).unwrap();
        assert_eq!(hs.session_id, 0);
        assert_eq!(hs.auth_type, 0);
        assert_eq!(hs.connect_key, "");
        assert_eq!(hs.version, "");
    }

    #[test]
    fn 握手_未知字段被跳过() {
        let mut raw = SessionHandShake::new_usb(7, "", "").encode();
        crate::hdc::ser::write_string_field(99, "future", &mut raw);
        let hs = SessionHandShake::decode(&raw).unwrap();
        assert_eq!(hs.session_id, 7);
    }

    #[test]
    fn 握手_超长_banner_报错() {
        let mut hs = SessionHandShake::new_usb(0, "", "");
        hs.banner = "OHOS HDC".repeat(4);
        let raw = hs.encode();
        assert!(matches!(
            SessionHandShake::decode(&raw),
            Err(Error::LengthTooLarge { .. })
        ));
    }
}
