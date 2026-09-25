// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 帧结构：USB 传输头、通用 payload 头与完整帧编解码。
//!
//! 两个头在官方 C++ 里都是 1 字节对齐（`#pragma pack(1)` /
//! `__attribute__((packed))`），因此各占 11 字节，整数一律大端。

use crate::hdc::command::Command;
use crate::hdc::config::{
    PACKET_FLAG, PAYLOAD_HEAD_SIZE, PAYLOAD_VCODE, USB_HEAD_SIZE, USB_PACKET_FLAG,
};
use crate::hdc::proto_error::{Error, Result};
use crate::hdc::ser;

/// USB 传输头（11 字节，packed）。
///
/// ```text
/// offset  size  field
/// 0       2     flag      "UB"
/// 2       1     option    1=数据 2=软复位 0=占位
/// 3       4     sessionId 大端
/// 7       4     dataSize  大端
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbHead {
    /// 包类型。
    pub option: u8,
    /// 会话号。
    pub session_id: u32,
    /// 紧随其后的数据长度。
    pub data_size: u32,
}

impl UsbHead {
    /// 构造一个普通数据包的头。
    pub const fn header(session_id: u32, data_size: u32) -> Self {
        Self {
            option: crate::hdc::config::USB_OPTION_HEADER,
            session_id,
            data_size,
        }
    }

    /// 构造软复位包的头。
    pub const fn reset(session_id: u32) -> Self {
        Self {
            option: crate::hdc::config::USB_OPTION_RESET,
            session_id,
            data_size: 0,
        }
    }

    /// 构造占位包的头（长度为 0，用于对齐 wMaxPacketSize）。
    pub const fn dummy(session_id: u32) -> Self {
        Self {
            option: crate::hdc::config::USB_OPTION_DUMMY,
            session_id,
            data_size: 0,
        }
    }

    /// 编码为 11 字节。
    pub fn encode(&self) -> [u8; USB_HEAD_SIZE] {
        let mut buf = [0u8; USB_HEAD_SIZE];
        buf[0..2].copy_from_slice(&USB_PACKET_FLAG);
        buf[2] = self.option;
        buf[3..7].copy_from_slice(&self.session_id.to_be_bytes());
        buf[7..11].copy_from_slice(&self.data_size.to_be_bytes());
        buf
    }

    /// 从 11 字节解码。
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < USB_HEAD_SIZE {
            return Err(Error::UnexpectedEof {
                need: USB_HEAD_SIZE,
                got: raw.len(),
            });
        }
        let flag = [raw[0], raw[1]];
        if flag != USB_PACKET_FLAG {
            return Err(Error::BadFlag {
                expected: USB_PACKET_FLAG,
                got: flag,
            });
        }
        Ok(Self {
            option: raw[2],
            session_id: u32::from_be_bytes([raw[3], raw[4], raw[5], raw[6]]),
            data_size: u32::from_be_bytes([raw[7], raw[8], raw[9], raw[10]]),
        })
    }
}

/// 通用 payload 头（11 字节，packed）。
///
/// ```text
/// offset  size  field
/// 0       2     flag        "HW"
/// 2       2     reserve     预留（加密标志等）
/// 4       1     protocolVer 协议版本
/// 5       2     headSize    PayloadProtect 的序列化长度，大端
/// 7       4     dataSize    数据长度，大端
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHead {
    /// 预留字段。
    pub reserve: u16,
    /// 协议版本。
    pub protocol_ver: u8,
    /// 保护头长度。
    pub head_size: u16,
    /// 数据长度。
    pub data_size: u32,
}

impl PayloadHead {
    /// 按协议版本构造。
    pub const fn new(head_size: u16, data_size: u32) -> Self {
        Self {
            reserve: 0,
            protocol_ver: crate::hdc::config::VER_PROTOCOL,
            head_size,
            data_size,
        }
    }

    /// 编码为 11 字节。
    pub fn encode(&self) -> [u8; PAYLOAD_HEAD_SIZE] {
        let mut buf = [0u8; PAYLOAD_HEAD_SIZE];
        buf[0..2].copy_from_slice(&PACKET_FLAG);
        buf[2..4].copy_from_slice(&self.reserve.to_be_bytes());
        buf[4] = self.protocol_ver;
        buf[5..7].copy_from_slice(&self.head_size.to_be_bytes());
        buf[7..11].copy_from_slice(&self.data_size.to_be_bytes());
        buf
    }

    /// 从 11 字节解码。
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < PAYLOAD_HEAD_SIZE {
            return Err(Error::UnexpectedEof {
                need: PAYLOAD_HEAD_SIZE,
                got: raw.len(),
            });
        }
        let flag = [raw[0], raw[1]];
        if flag != PACKET_FLAG {
            return Err(Error::BadFlag {
                expected: PACKET_FLAG,
                got: flag,
            });
        }
        Ok(Self {
            reserve: u16::from_be_bytes([raw[2], raw[3]]),
            protocol_ver: raw[4],
            head_size: u16::from_be_bytes([raw[5], raw[6]]),
            data_size: u32::from_be_bytes([raw[7], raw[8], raw[9], raw[10]]),
        })
    }
}

/// 保护头（官方 `PayloadProtect`），protobuf 风格序列化。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadProtect {
    /// 通道号（会话建立后由握手分配）。
    pub channel_id: u32,
    /// 命令字。
    pub command: Command,
    /// 校验和。
    pub check_sum: u8,
    /// 固定校验值。
    pub v_code: u8,
}

impl PayloadProtect {
    /// 序列化。整数一律写出（含 0），与官方 `SerialStruct` 一致。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        ser::write_u32_field(1, self.channel_id, &mut out);
        ser::write_u32_field(2, self.command.as_u32(), &mut out);
        ser::write_u8_field(3, self.check_sum, &mut out);
        ser::write_u8_field(4, self.v_code, &mut out);
        out
    }

    /// 反序列化。未知字段按 wire type 跳过。
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut protect = Self {
            channel_id: 0,
            command: Command::KernelHelp,
            check_sum: 0,
            v_code: PAYLOAD_VCODE,
        };
        let mut saw_command = false;
        let mut pos = 0usize;
        while pos < raw.len() {
            let (field, wire) = ser::read_tag(raw, &mut pos)?;
            match (field, wire) {
                (1, ser::WireType::Varint) => {
                    protect.channel_id = ser::read_varint(raw, &mut pos)? as u32;
                }
                (2, ser::WireType::Varint) => {
                    let v = ser::read_varint(raw, &mut pos)?;
                    let v = u32::try_from(v).map_err(|_| Error::VarintOverflow)?;
                    protect.command = Command::from_u32(v)?;
                    saw_command = true;
                }
                (3, ser::WireType::Varint) => {
                    protect.check_sum = ser::read_varint(raw, &mut pos)? as u8;
                }
                (4, ser::WireType::Varint) => {
                    protect.v_code = ser::read_varint(raw, &mut pos)? as u8;
                }
                _ => ser::skip_field(raw, &mut pos, wire)?,
            }
        }
        if !saw_command {
            return Err(Error::UnknownField {
                message: "PayloadProtect",
                tag: 2,
            });
        }
        Ok(protect)
    }
}

/// 一条完整的通用帧：`PayloadHead + PayloadProtect + data`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// 通道号。
    pub channel_id: u32,
    /// 命令字。
    pub command: Command,
    /// 校验和。
    pub check_sum: u8,
    /// 固定校验值。
    pub v_code: u8,
    /// 载荷。
    pub data: Vec<u8>,
}

impl Frame {
    /// 构造一条数据帧。
    pub fn new(channel_id: u32, command: Command, data: Vec<u8>) -> Self {
        Self {
            channel_id,
            command,
            check_sum: 0,
            v_code: PAYLOAD_VCODE,
            data,
        }
    }

    /// 编码为完整字节流。
    pub fn encode(&self) -> Vec<u8> {
        let protect = PayloadProtect {
            channel_id: self.channel_id,
            command: self.command,
            check_sum: self.check_sum,
            v_code: self.v_code,
        }
        .encode();
        let head = PayloadHead::new(protect.len() as u16, self.data.len() as u32);
        let mut out = Vec::with_capacity(PAYLOAD_HEAD_SIZE + protect.len() + self.data.len());
        out.extend_from_slice(&head.encode());
        out.extend_from_slice(&protect);
        out.extend_from_slice(&self.data);
        out
    }

    /// 从完整字节流解码，要求恰好消费全部字节。
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let head = PayloadHead::decode(raw)?;
        let protect_len = head.head_size as usize;
        let data_len = head.data_size as usize;
        let total = PAYLOAD_HEAD_SIZE
            .checked_add(protect_len)
            .and_then(|v| v.checked_add(data_len))
            .ok_or(Error::VarintOverflow)?;
        if raw.len() < total {
            return Err(Error::UnexpectedEof {
                need: total,
                got: raw.len(),
            });
        }
        if raw.len() > total {
            return Err(Error::BadFieldLength {
                field: "frame",
                expected: total,
                got: raw.len(),
            });
        }
        let protect =
            PayloadProtect::decode(&raw[PAYLOAD_HEAD_SIZE..PAYLOAD_HEAD_SIZE + protect_len])?;
        let data = raw[PAYLOAD_HEAD_SIZE + protect_len..total].to_vec();
        Ok(Self {
            channel_id: protect.channel_id,
            command: protect.command,
            check_sum: protect.check_sum,
            v_code: protect.v_code,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hdc::config::{USB_OPTION_HEADER, USB_OPTION_RESET, VER_PROTOCOL};

    #[test]
    fn usb_头长度与字节序() {
        let head = UsbHead::header(0x0102_0304, 0x0a0b_0c0d);
        let raw = head.encode();
        assert_eq!(raw.len(), USB_HEAD_SIZE);
        assert_eq!(&raw[0..2], b"UB");
        assert_eq!(raw[2], USB_OPTION_HEADER);
        assert_eq!(&raw[3..7], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&raw[7..11], &[0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(UsbHead::decode(&raw).unwrap(), head);
    }

    #[test]
    fn usb_软复位头() {
        let head = UsbHead::reset(7);
        let raw = head.encode();
        assert_eq!(raw[2], USB_OPTION_RESET);
        assert_eq!(&raw[7..11], &[0, 0, 0, 0]);
        assert_eq!(UsbHead::decode(&raw).unwrap(), head);
    }

    #[test]
    fn usb_魔数不符报错() {
        let mut raw = UsbHead::header(1, 0).encode();
        raw[0] = b'X';
        assert!(matches!(UsbHead::decode(&raw), Err(Error::BadFlag { .. })));
    }

    #[test]
    fn usb_截断报错() {
        let raw = UsbHead::header(1, 0).encode();
        assert!(matches!(
            UsbHead::decode(&raw[..10]),
            Err(Error::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn payload_头长度与字节序() {
        let head = PayloadHead::new(8, 0x0a0b_0c0d);
        let raw = head.encode();
        assert_eq!(raw.len(), PAYLOAD_HEAD_SIZE);
        assert_eq!(&raw[0..2], b"HW");
        assert_eq!(&raw[2..4], &[0, 0]);
        assert_eq!(raw[4], VER_PROTOCOL);
        assert_eq!(&raw[5..7], &[0, 8]);
        assert_eq!(&raw[7..11], &[0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(PayloadHead::decode(&raw).unwrap(), head);
    }

    #[test]
    fn 保护头_序列化字节() {
        let protect = PayloadProtect {
            channel_id: 0,
            command: Command::KernelHandshake,
            check_sum: 0,
            v_code: PAYLOAD_VCODE,
        };
        let raw = protect.encode();
        // field1 channelId=0 -> tag 0x08 value 0
        // field2 commandFlag=1 -> tag 0x10 value 1
        // field3 checkSum=0 -> tag 0x18 value 0
        // field4 vCode=9 -> tag 0x20 value 9
        assert_eq!(raw, vec![0x08, 0x00, 0x10, 0x01, 0x18, 0x00, 0x20, 0x09]);
    }

    #[test]
    fn 保护头_往返() {
        let protect = PayloadProtect {
            channel_id: 0x1234_5678,
            command: Command::FileBegin,
            check_sum: 0,
            v_code: PAYLOAD_VCODE,
        };
        let raw = protect.encode();
        assert_eq!(PayloadProtect::decode(&raw).unwrap(), protect);
    }

    #[test]
    fn 保护头_大命令字用_varint() {
        let protect = PayloadProtect {
            channel_id: 0,
            command: Command::AppFinish,
            check_sum: 0,
            v_code: PAYLOAD_VCODE,
        };
        let raw = protect.encode();
        // 3504 = 0xDB0 -> varint 0xb0 0x1b
        assert!(
            raw.windows(2).any(|w| w == [0xb0, 0x1b]),
            "3504 应以两字节 varint 编码"
        );
        assert_eq!(PayloadProtect::decode(&raw).unwrap(), protect);
    }

    #[test]
    fn 帧_往返() {
        let frame = Frame::new(3, Command::ShellData, b"echo hi\n".to_vec());
        let raw = frame.encode();
        assert_eq!(&raw[0..2], b"HW");
        // protect 9 字节（channelId 2 + command 3 + checkSum 2 + vCode 2）+ 数据 8 字节
        assert_eq!(raw.len(), PAYLOAD_HEAD_SIZE + 9 + 8);
        assert_eq!(Frame::decode(&raw).unwrap(), frame);
    }

    #[test]
    fn 帧_空载荷() {
        let frame = Frame::new(1, Command::KernelEcho, Vec::new());
        let raw = frame.encode();
        assert_eq!(raw.len(), PAYLOAD_HEAD_SIZE + 8);
        assert_eq!(Frame::decode(&raw).unwrap(), frame);
    }

    #[test]
    fn 帧_多字节命令字() {
        let frame = Frame::new(0, Command::UnityExecute, b"ls".to_vec());
        let raw = frame.encode();
        assert_eq!(Frame::decode(&raw).unwrap(), frame);
    }

    #[test]
    fn 帧_多余字节报错() {
        let mut raw = Frame::new(1, Command::KernelEcho, Vec::new()).encode();
        raw.push(0xff);
        assert!(matches!(
            Frame::decode(&raw),
            Err(Error::BadFieldLength { .. })
        ));
    }

    #[test]
    fn 帧_截断报错() {
        let raw = Frame::new(1, Command::ShellData, vec![1, 2, 3, 4]).encode();
        assert!(matches!(
            Frame::decode(&raw[..raw.len() - 2]),
            Err(Error::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn 保护头_缺少命令字报错() {
        let mut raw = Vec::new();
        crate::hdc::ser::write_u32_field(1, 5, &mut raw);
        assert!(matches!(
            PayloadProtect::decode(&raw),
            Err(Error::UnknownField { .. })
        ));
    }
}
