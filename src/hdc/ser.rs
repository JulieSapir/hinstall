// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 与官方 `SerialStruct` 对齐的线格式原语。
//!
//! 官方 `hdc_rust/src/serializer/` 在设备侧通过 cffi 调用 C++ 的
//! `SerialStruct::SerializeToString`，线格式等价于 protobuf：
//!
//! - tag = `(field << 3) | wireType`，以 varint 编码；
//! - 整数默认走 VARINT，**即使值为 0 也会写出**（除非该字段声明了 `flags::f`）；
//! - 字符串走 LENGTH_DELIMITED：`varint(len) + 原始字节`（不带 NUL）；
//! - 嵌套 Message 走 LENGTH_DELIMITED，长度为 0 且未强制时整体跳过。
//!
//! 解析侧按 protobuf 语义容忍未知字段（按 wire type 跳过）。

use crate::hdc::proto_error::{Error, Result};

/// protobuf wire type。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType {
    /// varint（u32/u64/bool/enum）。
    Varint = 0,
    /// 固定 8 字节小端（double / fixed64）。
    Fixed64 = 1,
    /// 长度前缀（string / bytes / 嵌套 Message）。
    LengthDelimited = 2,
    /// 固定 4 字节小端（float / fixed32）。
    Fixed32 = 5,
}

impl WireType {
    /// 由数值还原 wire type。
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(WireType::Varint),
            1 => Ok(WireType::Fixed64),
            2 => Ok(WireType::LengthDelimited),
            5 => Ok(WireType::Fixed32),
            other => Err(Error::UnsupportedWireType(other)),
        }
    }
}

/// 写入 varint。
pub fn write_varint(value: u64, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// 读取 varint，`pos` 前移。
pub fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos).ok_or(Error::UnexpectedEof {
            need: *pos + 1,
            got: data.len(),
        })?;
        *pos += 1;
        if shift >= 64 {
            return Err(Error::VarintOverflow);
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

/// 写入字段 tag。
pub fn write_tag(field: u32, wire: WireType, out: &mut Vec<u8>) {
    write_varint((u64::from(field) << 3) | u64::from(wire as u8), out);
}

/// 读取字段 tag，返回 (field, wire)。
pub fn read_tag(data: &[u8], pos: &mut usize) -> Result<(u32, WireType)> {
    let key = read_varint(data, pos)?;
    let field = u32::try_from(key >> 3).map_err(|_| Error::VarintOverflow)?;
    if field == 0 {
        return Err(Error::UnknownField {
            message: "帧",
            tag: 0,
        });
    }
    let wire = WireType::from_u8((key & 0x07) as u8)?;
    Ok((field, wire))
}

/// 写一个 u64 字段（VARINT，值为 0 也写出）。
pub fn write_u64_field(field: u32, value: u64, out: &mut Vec<u8>) {
    write_tag(field, WireType::Varint, out);
    write_varint(value, out);
}

/// 写一个 u32 字段。
pub fn write_u32_field(field: u32, value: u32, out: &mut Vec<u8>) {
    write_u64_field(field, u64::from(value), out);
}

/// 写一个 u8 字段（协议里小整数同样走 varint）。
pub fn write_u8_field(field: u32, value: u8, out: &mut Vec<u8>) {
    write_u64_field(field, u64::from(value), out);
}

/// 写一个 bool 字段（协议里按 uint32 处理）。
pub fn write_bool_field(field: u32, value: bool, out: &mut Vec<u8>) {
    write_u8_field(field, u8::from(value), out);
}

/// 写一个字符串字段（LENGTH_DELIMITED）。
pub fn write_string_field(field: u32, value: &str, out: &mut Vec<u8>) {
    write_tag(field, WireType::LengthDelimited, out);
    write_varint(value.len() as u64, out);
    out.extend_from_slice(value.as_bytes());
}

/// 读取一个 LENGTH_DELIMITED 字段的原始字节。
pub fn read_bytes_field<'a>(data: &'a [u8], pos: &mut usize, max: usize) -> Result<&'a [u8]> {
    let len = read_varint(data, pos)?;
    if len > max as u64 {
        return Err(Error::LengthTooLarge {
            field: "bytes",
            value: len,
            max: max as u64,
        });
    }
    let len = len as usize;
    let end = pos.checked_add(len).ok_or(Error::VarintOverflow)?;
    if end > data.len() {
        return Err(Error::UnexpectedEof {
            need: end,
            got: data.len(),
        });
    }
    let slice = &data[*pos..end];
    *pos = end;
    Ok(slice)
}

/// 读取一个字符串字段。
pub fn read_string_field<'a>(
    data: &'a [u8],
    pos: &mut usize,
    field: &'static str,
    max: usize,
) -> Result<&'a str> {
    let raw = read_bytes_field(data, pos, max)?;
    std::str::from_utf8(raw).map_err(|_| Error::InvalidUtf8 { field })
}

/// 按 wire type 跳过当前字段（用于未知字段的向前兼容）。
pub fn skip_field(data: &[u8], pos: &mut usize, wire: WireType) -> Result<()> {
    match wire {
        WireType::Varint => {
            read_varint(data, pos)?;
        }
        WireType::Fixed64 => {
            advance(data, pos, 8)?;
        }
        WireType::Fixed32 => {
            advance(data, pos, 4)?;
        }
        WireType::LengthDelimited => {
            let len = read_varint(data, pos)?;
            let len = usize::try_from(len).map_err(|_| Error::VarintOverflow)?;
            advance(data, pos, len)?;
        }
    }
    Ok(())
}

/// 前移 `n` 字节，越界报错。
pub fn advance(data: &[u8], pos: &mut usize, n: usize) -> Result<()> {
    let end = pos.checked_add(n).ok_or(Error::VarintOverflow)?;
    if end > data.len() {
        return Err(Error::UnexpectedEof {
            need: end,
            got: data.len(),
        });
    }
    *pos = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_往返() {
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(v, &mut buf);
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos).unwrap(), v);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn varint_已知字节序列() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
            (1001, &[0xe9, 0x07]),
        ];
        for (value, expect) in cases {
            let mut buf = Vec::new();
            write_varint(*value, &mut buf);
            assert_eq!(buf, *expect, "varint({value}) 编码不符");
        }
    }

    #[test]
    fn varint_截断报错() {
        let mut pos = 0;
        assert!(matches!(
            read_varint(&[0x80], &mut pos),
            Err(Error::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn varint_超长报错() {
        let data = [0x80u8; 12];
        let mut pos = 0;
        assert_eq!(read_varint(&data, &mut pos), Err(Error::VarintOverflow));
    }

    #[test]
    fn tag_编解码() {
        let mut buf = Vec::new();
        write_tag(6, WireType::LengthDelimited, &mut buf);
        assert_eq!(buf, vec![0x32]);
        let mut pos = 0;
        assert_eq!(
            read_tag(&buf, &mut pos).unwrap(),
            (6, WireType::LengthDelimited)
        );
    }

    #[test]
    fn 字符串字段_已知字节序列() {
        let mut buf = Vec::new();
        write_string_field(1, "OHOS HDC", &mut buf);
        assert_eq!(
            buf,
            vec![0x0a, 0x08, b'O', b'H', b'O', b'S', b' ', b'H', b'D', b'C']
        );
    }

    #[test]
    fn 字符串字段_空串也写出长度() {
        let mut buf = Vec::new();
        write_string_field(5, "", &mut buf);
        assert_eq!(buf, vec![0x2a, 0x00]);
    }

    #[test]
    fn 未知字段按_wire_type_跳过() {
        let mut buf = Vec::new();
        write_string_field(1, "abc", &mut buf);
        write_u32_field(2, 7, &mut buf);
        let mut pos = 0;
        let (f1, w1) = read_tag(&buf, &mut pos).unwrap();
        assert_eq!((f1, w1), (1, WireType::LengthDelimited));
        skip_field(&buf, &mut pos, w1).unwrap();
        let (f2, w2) = read_tag(&buf, &mut pos).unwrap();
        assert_eq!((f2, w2), (2, WireType::Varint));
        skip_field(&buf, &mut pos, w2).unwrap();
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn 长度超限报错() {
        let mut buf = Vec::new();
        write_tag(1, WireType::LengthDelimited, &mut buf);
        write_varint(4096, &mut buf);
        buf.extend_from_slice(&[0u8; 4096]);
        let mut pos = 0;
        let (_, wire) = read_tag(&buf, &mut pos).unwrap();
        assert_eq!(wire, WireType::LengthDelimited);
        assert!(matches!(
            read_bytes_field(&buf, &mut pos, 64),
            Err(Error::LengthTooLarge { .. })
        ));
    }
}
