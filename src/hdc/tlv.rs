// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 握手能力协商 TLV。
//!
//! 对应官方 `src/common/base.h` 的 `TAG_*` 常量与 `src/common/base.cpp`
//! 的 `TlvAppend` / `TlvToStringMap`（`Base` 命名空间，行号见仓库 NOTICE）。
//!
//! 线格式（无分隔符，靠固定宽度切分）：
//!
//! ```text
//! tag   : 原始字节，右侧补空格到 16 字节
//! vallen: 十进制长度字符串，右侧补空格到 16 字节
//! value : 原始字节，长度即 vallen
//! ```
//!
//! 例：`TlvAppend(buf, "authtype", "1")` 产出 33 字节
//! `"authtype" + 8×空格 + "1" + 15×空格 + "1"`。
//! 该串整体作为 `SessionHandShake.buf` 的内容。

/// TLV tag 字段宽度。
pub const TLV_TAG_LEN: usize = 16;

/// TLV 长度字段宽度。
pub const TLV_VAL_LEN: usize = 16;

/// tag：认证方式（值见 [`AuthVerifyType`]）。
pub const TAG_AUTH_TYPE: &str = "authtype";

/// 设备侧认证方式（官方 `src/common/define_enum.h` 的 `AuthVerifyType`）。
///
/// 只保留当前设备默认的 RSA-3072 + SHA-512。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthVerifyType {
    /// RSA-3072 + SHA-512，当前设备默认。
    Rsa3072Sha512 = 1,
}

impl AuthVerifyType {
    /// 取数值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// 追加一条 TLV 到 `out`。`tag` 为空时不做任何事（与官方一致）。
pub fn tlv_append(out: &mut String, tag: &str, val: &str) {
    if tag.is_empty() {
        return;
    }
    out.push_str(tag);
    for _ in tag.len()..TLV_TAG_LEN {
        out.push(' ');
    }
    let vallen = val.len().to_string();
    out.push_str(&vallen);
    for _ in vallen.len()..TLV_VAL_LEN {
        out.push(' ');
    }
    out.push_str(val);
}

/// 构造只含一条 TLV 的串。
pub fn tlv_new(tag: &str, val: &str) -> String {
    let mut out = String::new();
    tlv_append(&mut out, tag, val);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_字节布局与官方抓包一致() {
        // 官方 usbmon 抓包中 buf 字段的 33 字节原文。
        let expect: Vec<u8> = [
            "authtype        ".as_bytes(),
            "1               ".as_bytes(),
            "1".as_bytes(),
        ]
        .concat();
        assert_eq!(expect.len(), 33);
        assert_eq!(tlv_new(TAG_AUTH_TYPE, "1").as_bytes(), expect.as_slice());
    }

    #[test]
    fn tlv_长度字段按十进制字符宽度补齐() {
        // 值长 21 → 长度字段写 "21"，再补 14 个空格。
        let s = tlv_new(TAG_AUTH_TYPE, "012345678901234567890");
        assert_eq!(&s[16..32], "21              ");
        assert_eq!(&s[32..], "012345678901234567890");
        assert_eq!(s.len(), 32 + 21);
    }

    #[test]
    fn 空_tag_不写入() {
        let mut s = String::new();
        tlv_append(&mut s, "", "1");
        assert!(s.is_empty());
    }

    #[test]
    fn 认证方式数值与官方一致() {
        assert_eq!(AuthVerifyType::Rsa3072Sha512.as_u8(), 1);
    }
}
