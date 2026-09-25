// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 文件传输相关结构。
//!
//! 对应官方 `src/common/transfer.h` 的 `TransferConfig` /
//! `TransferPayload`，字段 tag 与 `serial_struct_define.h` 一致。

use crate::hdc::ser;

/// 文件传输配置。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransferConfig {
    /// 文件大小。
    pub file_size: u64,
    /// 访问时间。
    pub atime: u64,
    /// 修改时间。
    pub mtime: u64,
    /// 选项串（如 `sync`、`tar` 等）。
    pub options: String,
    /// 目标路径。
    pub path: String,
    /// 可选名称。
    pub optional_name: String,
    /// 仅当目标较旧时才覆盖。
    pub update_if_new: bool,
    /// 压缩类型。
    pub compress_type: u8,
    /// 是否保持时间戳。
    pub hold_timestamp: bool,
    /// 功能名。
    pub function_name: String,
    /// 客户端工作目录。
    pub client_cwd: String,
    /// 预留字段 1。
    pub reserve1: String,
    /// 预留字段 2。
    pub reserve2: String,
}

impl TransferConfig {
    /// 序列化。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        ser::write_u64_field(1, self.file_size, &mut out);
        ser::write_u64_field(2, self.atime, &mut out);
        ser::write_u64_field(3, self.mtime, &mut out);
        ser::write_string_field(4, &self.options, &mut out);
        ser::write_string_field(5, &self.path, &mut out);
        ser::write_string_field(6, &self.optional_name, &mut out);
        ser::write_bool_field(7, self.update_if_new, &mut out);
        ser::write_u8_field(8, self.compress_type, &mut out);
        ser::write_bool_field(9, self.hold_timestamp, &mut out);
        ser::write_string_field(10, &self.function_name, &mut out);
        ser::write_string_field(11, &self.client_cwd, &mut out);
        ser::write_string_field(12, &self.reserve1, &mut out);
        ser::write_string_field(13, &self.reserve2, &mut out);
        out
    }
}

/// 文件分片头。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransferPayload {
    /// 分片序号。
    pub index: u64,
    /// 压缩类型。
    pub compress_type: u8,
    /// 压缩后长度。
    pub compress_size: u32,
    /// 解压后长度。
    pub uncompress_size: u32,
}

impl TransferPayload {
    /// 序列化。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        ser::write_u64_field(1, self.index, &mut out);
        ser::write_u8_field(2, self.compress_type, &mut out);
        ser::write_u32_field(3, self.compress_size, &mut out);
        ser::write_u32_field(4, self.uncompress_size, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 传输配置_零值字段也写出() {
        let cfg = TransferConfig::default();
        let raw = cfg.encode();
        // 3 个 u64 零值：08 00 10 00 18 00
        assert_eq!(&raw[0..6], &[0x08, 0x00, 0x10, 0x00, 0x18, 0x00]);
    }
}
