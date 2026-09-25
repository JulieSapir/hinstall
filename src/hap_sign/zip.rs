//! HAP / HSP 使用的 ZIP 容器：解析、对齐、重写。
//!
//! 与官方 Java 实现（`ZipUtils` / `ZipEntryData`）行为对齐，包括两个看起来奇怪但必须保留的点：
//!
//! 1. **对齐 padding 用 extra 字段承载**：本地头与中央目录项的 extra 长度必须一致，
//!    差多少就补多少 `0x00`，因此 `_cal_zero_padding` 会往短的那边补齐。
//! 2. **中央目录项的 `toBytes` 在存在 comment 时会把 extra 再写一遍**——这是官方实现的
//!    既有行为（实际写出的条目没有 comment），为保持字节一致照搬。
//!
//! 支持纯内存操作（`from_bytes` / `to_bytes`），web 端不做文件落盘。

use crate::hap_sign::error::{Error, Result};

// ------------------------------------------------------------ 常量

/// EOCD 签名
pub const ZIP_EOCD_SIG: u32 = 0x0605_4B50;
/// 中央目录项签名
pub const ZIP_CD_SIG: u32 = 0x0201_4B50;
/// 本地文件头签名
pub const ZIP_LOCAL_SIG: u32 = 0x0403_4B50;
/// 数据描述符签名
pub const ZIP_DD_SIG: u32 = 0x0807_4B50;
/// EOCD 固定长度
pub const ZIP_EOCD_LENGTH: usize = 22;
/// 中央目录项固定长度
pub const ZIP_CD_LENGTH: usize = 46;
/// 本地文件头固定长度
pub const ZIP_LOCAL_LENGTH: usize = 30;
/// 数据描述符长度
pub const ZIP_DD_LENGTH: usize = 16;

/// 条目分类：可执行文件
pub const TYPE_RUNNABLE_FILE: u8 = 0;
/// 条目分类：页面信息 bitmap
pub const TYPE_BIT_MAP: u8 = 1;
/// 条目分类：资源文件
pub const TYPE_RESOURCE_FILE: u8 = 2;

/// 页面信息 bitmap 的文件名
pub const BIT_MAP_FILENAME: &str = ".pages.info";
/// 原生库目录前缀
pub const LIBS_PATH_PREFIX: &str = "libs/";
/// Ark 字节码后缀
pub const ABC_FILE_SUFFIX: &str = ".abc";
/// 原生库后缀
pub const NATIVE_LIB_AN_SUFFIX: &str = ".an";
/// 资源文件目录前缀
pub const RESFILE_PATH_PREFIX: &str = "resources/resfile/";

// ------------------------------------------------------------ 小端读写

fn rd_u16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([d[off], d[off + 1]])
}

fn rd_u32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

// ------------------------------------------------------------ 条目分类

/// 是否为可执行文件（与 `FileUtils.isRunnableFile` 一致）。
pub fn is_runnable_file(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.ends_with(NATIVE_LIB_AN_SUFFIX)
        || name.ends_with(ABC_FILE_SUFFIX)
        || name.starts_with(LIBS_PATH_PREFIX)
}

/// 条目分类。
pub fn entry_type_of(name: &str) -> u8 {
    if is_runnable_file(name) {
        return TYPE_RUNNABLE_FILE;
    }
    if name == BIT_MAP_FILENAME {
        return TYPE_BIT_MAP;
    }
    TYPE_RESOURCE_FILE
}

// ------------------------------------------------------------ 本地文件头

/// ZIP 本地文件头（30 字节 + 文件名 + extra）。
#[derive(Clone, Debug, Default)]
pub struct ZipEntryHeader {
    /// 解压所需版本
    pub version: u16,
    /// 通用标志位
    pub flag: u16,
    /// 压缩方法
    pub method: u16,
    /// 最后修改时间
    pub last_time: u16,
    /// 最后修改日期
    pub last_date: u16,
    /// CRC32
    pub crc32: u32,
    /// 压缩后大小
    pub compressed_size: u32,
    /// 压缩前大小
    pub uncompressed_size: u32,
    /// 文件名
    pub file_name: Vec<u8>,
    /// extra 字段
    pub extra_data: Vec<u8>,
}

impl ZipEntryHeader {
    /// 从 `data[off..]` 解析。
    pub fn parse(data: &[u8], off: usize) -> Result<Self> {
        if off + ZIP_LOCAL_LENGTH > data.len() {
            return Err(Error::Zip("本地文件头越界".into()));
        }
        let sig = rd_u32(data, off);
        if sig != ZIP_LOCAL_SIG {
            return Err(Error::Zip(format!(
                "本地文件头签名错误: 0x{sig:08x} @ {off}"
            )));
        }
        let name_len = rd_u16(data, off + 26) as usize;
        let extra_len = rd_u16(data, off + 28) as usize;
        let p = off + ZIP_LOCAL_LENGTH;
        if p + name_len + extra_len > data.len() {
            return Err(Error::Zip("本地文件头字段越界".into()));
        }
        Ok(Self {
            version: rd_u16(data, off + 4),
            flag: rd_u16(data, off + 6),
            method: rd_u16(data, off + 8),
            last_time: rd_u16(data, off + 10),
            last_date: rd_u16(data, off + 12),
            crc32: rd_u32(data, off + 14),
            compressed_size: rd_u32(data, off + 18),
            uncompressed_size: rd_u32(data, off + 22),
            file_name: data[p..p + name_len].to_vec(),
            extra_data: data[p + name_len..p + name_len + extra_len].to_vec(),
        })
    }

    /// 头长度（含文件名与 extra）。
    pub fn length(&self) -> usize {
        ZIP_LOCAL_LENGTH + self.file_name.len() + self.extra_data.len()
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.length());
        out.extend_from_slice(&ZIP_LOCAL_SIG.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.flag.to_le_bytes());
        out.extend_from_slice(&self.method.to_le_bytes());
        out.extend_from_slice(&self.last_time.to_le_bytes());
        out.extend_from_slice(&self.last_date.to_le_bytes());
        out.extend_from_slice(&self.crc32.to_le_bytes());
        out.extend_from_slice(&self.compressed_size.to_le_bytes());
        out.extend_from_slice(&self.uncompressed_size.to_le_bytes());
        out.extend_from_slice(&(self.file_name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(self.extra_data.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.file_name);
        out.extend_from_slice(&self.extra_data);
        out
    }
}

// ------------------------------------------------------------ 中央目录项

/// ZIP 中央目录项（46 字节 + 文件名 + extra + comment）。
#[derive(Clone, Debug, Default)]
pub struct CentralDirectory {
    /// 创建版本
    pub version: u16,
    /// 解压所需版本
    pub version_extra: u16,
    /// 通用标志位
    pub flag: u16,
    /// 压缩方法
    pub method: u16,
    /// 最后修改时间
    pub last_time: u16,
    /// 最后修改日期
    pub last_date: u16,
    /// CRC32
    pub crc32: u32,
    /// 压缩后大小
    pub compressed_size: u32,
    /// 压缩前大小
    pub uncompressed_size: u32,
    /// 起始磁盘号
    pub disk_num_start: u16,
    /// 内部属性
    pub internal_file: u16,
    /// 外部属性
    pub external_file: u32,
    /// 本地头偏移
    pub offset: u32,
    /// 文件名
    pub file_name: Vec<u8>,
    /// extra 字段
    pub extra_data: Vec<u8>,
    /// 注释
    pub comment: Vec<u8>,
}

impl CentralDirectory {
    /// 从 `data[off..]` 解析，返回 `(条目, 下一个偏移)`。
    pub fn parse(data: &[u8], off: usize) -> Result<(Self, usize)> {
        if off + ZIP_CD_LENGTH > data.len() {
            return Err(Error::Zip("中央目录项越界".into()));
        }
        let sig = rd_u32(data, off);
        if sig != ZIP_CD_SIG {
            return Err(Error::Zip(format!("中央目录签名错误: 0x{sig:08x} @ {off}")));
        }
        let name_len = rd_u16(data, off + 28) as usize;
        let extra_len = rd_u16(data, off + 30) as usize;
        let comment_len = rd_u16(data, off + 32) as usize;
        let p = off + ZIP_CD_LENGTH;
        let end = p + name_len + extra_len + comment_len;
        if end > data.len() {
            return Err(Error::Zip("中央目录项字段越界".into()));
        }
        let cd = Self {
            version: rd_u16(data, off + 4),
            version_extra: rd_u16(data, off + 6),
            flag: rd_u16(data, off + 8),
            method: rd_u16(data, off + 10),
            last_time: rd_u16(data, off + 12),
            last_date: rd_u16(data, off + 14),
            crc32: rd_u32(data, off + 16),
            compressed_size: rd_u32(data, off + 20),
            uncompressed_size: rd_u32(data, off + 24),
            disk_num_start: rd_u16(data, off + 34),
            internal_file: rd_u16(data, off + 36),
            external_file: rd_u32(data, off + 38),
            offset: rd_u32(data, off + 42),
            file_name: data[p..p + name_len].to_vec(),
            extra_data: data[p + name_len..p + name_len + extra_len].to_vec(),
            comment: data[p + name_len + extra_len..end].to_vec(),
        };
        Ok((cd, end))
    }

    /// 编码长度。
    pub fn length(&self) -> usize {
        ZIP_CD_LENGTH + self.file_name.len() + self.extra_data.len() + self.comment.len()
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.length());
        out.extend_from_slice(&ZIP_CD_SIG.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.version_extra.to_le_bytes());
        out.extend_from_slice(&self.flag.to_le_bytes());
        out.extend_from_slice(&self.method.to_le_bytes());
        out.extend_from_slice(&self.last_time.to_le_bytes());
        out.extend_from_slice(&self.last_date.to_le_bytes());
        out.extend_from_slice(&self.crc32.to_le_bytes());
        out.extend_from_slice(&self.compressed_size.to_le_bytes());
        out.extend_from_slice(&self.uncompressed_size.to_le_bytes());
        out.extend_from_slice(&(self.file_name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(self.extra_data.len() as u16).to_le_bytes());
        out.extend_from_slice(&(self.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.disk_num_start.to_le_bytes());
        out.extend_from_slice(&self.internal_file.to_le_bytes());
        out.extend_from_slice(&self.external_file.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        // 与官方实现一致：存在 comment 时额外再写一遍 extraData
        out.extend_from_slice(&self.file_name);
        out.extend_from_slice(&self.extra_data);
        if !self.comment.is_empty() {
            out.extend_from_slice(&self.extra_data);
        }
        out
    }
}

// ------------------------------------------------------------ EOCD

/// 中央目录结束记录（22 字节 + 注释）。
#[derive(Clone, Debug, Default)]
pub struct EndOfCentralDirectory {
    /// 本磁盘号
    pub disk_num: u16,
    /// 中央目录起始磁盘号
    pub cd_start_disk_num: u16,
    /// 本磁盘中央目录项数
    pub this_disk_cd_num: u16,
    /// 中央目录项总数
    pub cd_total: u16,
    /// 中央目录大小
    pub cd_size: u32,
    /// 中央目录偏移
    pub offset: u32,
    /// 注释（HAP 签名块所在位置）
    pub comment: Vec<u8>,
}

impl EndOfCentralDirectory {
    /// 从 `data[off..]` 解析。
    pub fn parse(data: &[u8], off: usize) -> Result<Self> {
        if off + ZIP_EOCD_LENGTH > data.len() {
            return Err(Error::Zip("EOCD 越界".into()));
        }
        let sig = rd_u32(data, off);
        if sig != ZIP_EOCD_SIG {
            return Err(Error::Zip(format!("EOCD 签名错误: 0x{sig:08x}")));
        }
        let comment_len = rd_u16(data, off + 20) as usize;
        let start = off + ZIP_EOCD_LENGTH;
        let end = (start + comment_len).min(data.len());
        Ok(Self {
            disk_num: rd_u16(data, off + 4),
            cd_start_disk_num: rd_u16(data, off + 6),
            this_disk_cd_num: rd_u16(data, off + 8),
            cd_total: rd_u16(data, off + 10),
            cd_size: rd_u32(data, off + 12),
            offset: rd_u32(data, off + 16),
            comment: data[start..end].to_vec(),
        })
    }

    /// 编码长度。
    pub fn length(&self) -> usize {
        ZIP_EOCD_LENGTH + self.comment.len()
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.length());
        out.extend_from_slice(&ZIP_EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&self.disk_num.to_le_bytes());
        out.extend_from_slice(&self.cd_start_disk_num.to_le_bytes());
        out.extend_from_slice(&self.this_disk_cd_num.to_le_bytes());
        out.extend_from_slice(&self.cd_total.to_le_bytes());
        out.extend_from_slice(&self.cd_size.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&(self.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.comment);
        out
    }
}

// ------------------------------------------------------------ 数据描述符

/// 数据描述符（16 字节）。
#[derive(Clone, Debug, Default)]
pub struct DataDescriptor {
    /// CRC32
    pub crc32: u32,
    /// 压缩后大小
    pub compressed_size: u32,
    /// 压缩前大小
    pub uncompressed_size: u32,
}

impl DataDescriptor {
    /// 从 `data[off..]` 解析。
    pub fn parse(data: &[u8], off: usize) -> Result<Self> {
        if off + ZIP_DD_LENGTH > data.len() {
            return Err(Error::Zip("数据描述符越界".into()));
        }
        let sig = rd_u32(data, off);
        if sig != ZIP_DD_SIG {
            return Err(Error::Zip(format!("数据描述符签名错误: 0x{sig:08x}")));
        }
        Ok(Self {
            crc32: rd_u32(data, off + 4),
            compressed_size: rd_u32(data, off + 8),
            uncompressed_size: rd_u32(data, off + 12),
        })
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ZIP_DD_LENGTH);
        out.extend_from_slice(&ZIP_DD_SIG.to_le_bytes());
        out.extend_from_slice(&self.crc32.to_le_bytes());
        out.extend_from_slice(&self.compressed_size.to_le_bytes());
        out.extend_from_slice(&self.uncompressed_size.to_le_bytes());
        out
    }
}

// ------------------------------------------------------------ 条目

/// 一个 ZIP 条目：本地头 + 数据 +（可选）描述符 + 中央目录项。
#[derive(Clone, Debug)]
pub struct ZipEntry {
    /// 本地文件头
    pub header: ZipEntryHeader,
    /// 中央目录项
    pub cd: CentralDirectory,
    /// 新增条目时携带数据；从文件解析来的条目为 `None`
    pub data: Option<Vec<u8>>,
    /// 数据在原始文件中的偏移
    pub file_offset: usize,
    /// 数据长度
    pub file_size: usize,
    /// 数据描述符
    pub descriptor: Option<DataDescriptor>,
    /// 条目总长度
    pub length: usize,
    /// 条目分类
    pub entry_type: u8,
}

impl Default for ZipEntry {
    fn default() -> Self {
        Self {
            header: ZipEntryHeader::default(),
            cd: CentralDirectory::default(),
            data: None,
            file_offset: 0,
            file_size: 0,
            descriptor: None,
            length: 0,
            entry_type: TYPE_RESOURCE_FILE,
        }
    }
}

impl ZipEntry {
    /// 条目名（UTF-8，非法字节用替换字符）。
    pub fn name(&self) -> String {
        String::from_utf8_lossy(&self.header.file_name).into_owned()
    }

    /// 重新计算条目总长度。
    pub fn update_length(&mut self) {
        let body = match &self.data {
            Some(d) => d.len(),
            None => self.file_size,
        };
        self.length = self.header.length()
            + body
            + if self.descriptor.is_some() {
                ZIP_DD_LENGTH
            } else {
                0
            };
    }

    /// 对齐本条目的数据区，返回新增字节数（0 表示无需对齐）。
    pub fn alignment(&mut self, align_num: u32) -> Result<usize> {
        let padding = self.cal_zero_padding()?;
        let remainder = (self.header.length() + self.cd.offset as usize) % align_num as usize;
        if remainder == 0 {
            return Ok(padding);
        }
        let add = align_num as usize - remainder;
        let new_extra_len = self.header.extra_data.len() + add;
        if new_extra_len > 0xFFFF {
            return Err(Error::Zip(format!(
                "条目 {} 无法对齐：extra 字段超长",
                self.name()
            )));
        }
        self.set_new_extra_length(new_extra_len)?;
        Ok(add)
    }

    /// 本地头与中央目录项的 extra 长度取齐。
    fn cal_zero_padding(&mut self) -> Result<usize> {
        let entry_extra = self.header.extra_data.len();
        let cd_extra = self.cd.extra_data.len();
        if cd_extra > entry_extra {
            self.header.extra_data.resize(cd_extra, 0);
            return Ok(cd_extra - entry_extra);
        }
        if cd_extra < entry_extra {
            self.cd.extra_data.resize(entry_extra, 0);
            return Ok(entry_extra - cd_extra);
        }
        Ok(0)
    }

    fn set_new_extra_length(&mut self, new_len: usize) -> Result<()> {
        if new_len < self.header.extra_data.len() {
            return Err(Error::Zip(format!(
                "条目 {} 无法对齐：extra 长度回退",
                self.name()
            )));
        }
        self.header.extra_data.resize(new_len, 0);
        self.cd.extra_data.resize(new_len, 0);
        self.update_length();
        Ok(())
    }
}

// ------------------------------------------------------------ 容器

/// HAP / HSP 的 ZIP 容器。
pub struct Zip {
    /// 原始字节
    pub raw: Vec<u8>,
    /// 条目列表
    pub entries: Vec<ZipEntry>,
    /// EOCD
    pub eocd: EndOfCentralDirectory,
    /// 签名块（位于最后一个条目数据与中央目录之间）
    pub signing_block: Vec<u8>,
    /// 中央目录偏移
    pub cd_offset: usize,
    /// 签名块偏移
    pub signing_offset: usize,
    /// EOCD 偏移
    pub eocd_offset: usize,
}

impl Zip {
    /// 从内存打开（web 端路径）。
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self> {
        let mut zip = Self {
            raw,
            entries: Vec::new(),
            eocd: EndOfCentralDirectory::default(),
            signing_block: Vec::new(),
            cd_offset: 0,
            signing_offset: 0,
            eocd_offset: 0,
        };
        zip.parse()?;
        Ok(zip)
    }

    // ---- 解析 ----

    /// 定位 EOCD（从尾部向前找签名）。
    fn find_eocd(&self) -> Result<usize> {
        let size = self.raw.len();
        if size < ZIP_EOCD_LENGTH {
            return Err(Error::Zip("文件过小，找不到 EOCD".into()));
        }
        let off = size - ZIP_EOCD_LENGTH;
        if rd_u32(&self.raw, off) == ZIP_EOCD_SIG {
            return Ok(off);
        }
        let max_len = (ZIP_EOCD_LENGTH + 0xFFFF).min(size);
        let start = size - max_len;
        for p in start..=size - ZIP_EOCD_LENGTH {
            if rd_u32(&self.raw, p) == ZIP_EOCD_SIG {
                return Ok(p);
            }
        }
        Err(Error::Zip("未找到 EOCD".into()))
    }

    fn parse(&mut self) -> Result<()> {
        self.eocd_offset = self.find_eocd()?;
        self.eocd = EndOfCentralDirectory::parse(&self.raw, self.eocd_offset)?;
        self.cd_offset = self.eocd.offset as usize;
        let mut pos = self.cd_offset;
        for _ in 0..self.eocd.cd_total {
            let (cd, next) = CentralDirectory::parse(&self.raw, pos)?;
            pos = next;
            self.entries.push(ZipEntry {
                cd,
                ..ZipEntry::default()
            });
        }
        for i in 0..self.entries.len() {
            self.load_entry_data(i)?;
        }
        self.signing_offset = match self.entries.last() {
            Some(last) => last.cd.offset as usize + last.length,
            None => 0,
        };
        if self.cd_offset < self.signing_offset {
            return Err(Error::Zip("签名块偏移位于条目数据之前".into()));
        }
        self.signing_block = self.raw[self.signing_offset..self.cd_offset].to_vec();
        Ok(())
    }

    fn load_entry_data(&mut self, idx: usize) -> Result<()> {
        let off = self.entries[idx].cd.offset as usize;
        let header = ZipEntryHeader::parse(&self.raw, off)?;
        let p = off + header.length();
        let e = &mut self.entries[idx];
        e.file_size = if e.cd.method == 0 {
            e.cd.uncompressed_size as usize
        } else {
            e.cd.compressed_size as usize
        };
        e.file_offset = p;
        e.entry_type = entry_type_of(&String::from_utf8_lossy(&header.file_name));
        e.header = header;
        if e.header.flag & 0x08 != 0 {
            e.descriptor = Some(DataDescriptor::parse(&self.raw, p + e.file_size)?);
        }
        e.update_length();
        if self.cd_offset - off < e.length {
            return Err(Error::Zip(format!("条目 {} 越界", e.name())));
        }
        Ok(())
    }

    // ---- 变更 ----

    /// 清空签名块并重排偏移。
    pub fn remove_sign_block(&mut self) {
        self.signing_block.clear();
        self.reset_offset();
    }

    /// 写入页面信息 bitmap 条目（覆盖已有同名条目）。
    pub fn add_bitmap(&mut self, data: Vec<u8>) {
        self.entries.retain(|e| e.entry_type != TYPE_BIT_MAP);
        let name = BIT_MAP_FILENAME.as_bytes().to_vec();
        let len = data.len() as u32;
        let mut e = ZipEntry {
            data: Some(data),
            entry_type: TYPE_BIT_MAP,
            ..ZipEntry::default()
        };
        e.header.method = 0;
        e.header.uncompressed_size = len;
        e.header.compressed_size = len;
        e.header.crc32 = 0;
        e.header.file_name = name.clone();
        e.cd.method = 0;
        e.cd.uncompressed_size = len;
        e.cd.compressed_size = len;
        e.cd.file_name = name;
        e.update_length();
        self.entries.push(e);
    }

    /// 排序：未压缩条目在前（可执行 → bitmap → 其他），同组按文件名。
    pub fn sort(&mut self) {
        self.entries.sort_by(|a, b| {
            let ka = if a.header.method == 0 {
                (0u8, a.entry_type, a.name())
            } else {
                (1u8, 0u8, a.name())
            };
            let kb = if b.header.method == 0 {
                (0u8, b.entry_type, b.name())
            } else {
                (1u8, 0u8, b.name())
            };
            ka.cmp(&kb)
        });
        self.reset_offset();
    }

    /// 重算所有偏移与中央目录长度。
    pub fn reset_offset(&mut self) {
        let mut off = 0usize;
        let mut cd_len = 0usize;
        for e in &mut self.entries {
            e.update_length();
            e.cd.offset = off as u32;
            off += e.length;
            cd_len += e.cd.length();
        }
        if !self.signing_block.is_empty() {
            off += self.signing_block.len();
        }
        self.cd_offset = off;
        self.eocd.offset = off as u32;
        self.eocd.cd_size = cd_len as u32;
        off += cd_len;
        self.eocd_offset = off;
        self.eocd.cd_total = self.entries.len() as u16;
        self.eocd.this_disk_cd_num = self.entries.len() as u16;
    }

    /// 对齐：未压缩条目与首个非可执行条目按 4096 对齐，其余按 `align_num`。
    pub fn alignment(&mut self, align_num: u32) -> Result<()> {
        self.sort();
        let mut is_first_un_runnable = true;
        for i in 0..self.entries.len() {
            let method = self.entries[i].header.method;
            if method != 0 && !is_first_un_runnable {
                break;
            }
            let e = &self.entries[i];
            let align_bytes = if (e.entry_type == TYPE_RUNNABLE_FILE && method == 0)
                || e.entry_type == TYPE_BIT_MAP
            {
                4096
            } else if is_first_un_runnable {
                is_first_un_runnable = false;
                4096
            } else if e.name().starts_with(RESFILE_PATH_PREFIX) && e.file_size >= 1024 * 1024 {
                4096
            } else {
                align_num
            };
            let add = self.entries[i].alignment(align_bytes)?;
            if add > 0 {
                self.reset_offset();
            }
        }
        Ok(())
    }

    // ---- 写出 ----

    /// 按当前状态序列化为完整 ZIP 字节流。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.raw.len() + 4096);
        for e in &self.entries {
            out.extend_from_slice(&e.header.to_bytes());
            match &e.data {
                Some(d) => out.extend_from_slice(d),
                None => {
                    out.extend_from_slice(&self.raw[e.file_offset..e.file_offset + e.file_size])
                }
            }
            if let Some(dd) = &e.descriptor {
                out.extend_from_slice(&dd.to_bytes());
            }
        }
        out.extend_from_slice(&self.signing_block);
        for e in &self.entries {
            out.extend_from_slice(&e.cd.to_bytes());
        }
        out.extend_from_slice(&self.eocd.to_bytes());
        out
    }

    // ---- 查询 ----

    /// 按名字查找条目。
    pub fn find_entry(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name() == name)
    }

    /// 取条目内容（`method 0` 直读，`method 8` 用 inflate 解压）。
    pub fn entry_content(&self, name: &str) -> Result<Vec<u8>> {
        match self.find_entry(name) {
            Some(e) => e.content(&self.raw),
            None => Err(Error::Zip(format!("条目不存在: {name}"))),
        }
    }
}

impl ZipEntry {
    /// 取条目原始字节（未解压）。
    pub fn body<'a>(&'a self, raw: &'a [u8]) -> &'a [u8] {
        match &self.data {
            Some(d) => d,
            None => &raw[self.file_offset..self.file_offset + self.file_size],
        }
    }

    /// 解出条目内容。
    pub fn content(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let body = self.body(raw);
        match self.header.method {
            0 => Ok(body.to_vec()),
            8 => miniz_oxide::inflate::decompress_to_vec(body)
                .map_err(|e| Error::Zip(format!("条目 {} 解压失败: {e:?}", self.name()))),
            m => Err(Error::Zip(format!(
                "条目 {} 的压缩方法 {m} 不支持",
                self.name()
            ))),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// 手工拼一个最小的单条目 ZIP（stored，无 extra）。
    pub fn tiny_zip() -> Vec<u8> {
        let name = b"module.json";
        let data = b"{}";
        let mut out = Vec::new();
        // 本地头
        out.extend_from_slice(&ZIP_LOCAL_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(data);
        let cd_off = out.len();
        // 中央目录
        out.extend_from_slice(&ZIP_CD_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // external
        out.extend_from_slice(&0u32.to_le_bytes()); // 本地头偏移（本测试里本地头在 0）
        out.extend_from_slice(name);
        let cd_len = out.len() - cd_off;
        // EOCD
        out.extend_from_slice(&ZIP_EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(cd_len as u32).to_le_bytes());
        out.extend_from_slice(&(cd_off as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn parse_and_roundtrip() {
        let raw = tiny_zip();
        let zip = Zip::from_bytes(raw.clone()).unwrap();
        assert_eq!(zip.entries.len(), 1);
        assert_eq!(zip.entries[0].name(), "module.json");
        assert_eq!(zip.entry_content("module.json").unwrap(), b"{}");
        assert_eq!(zip.signing_block.len(), 0);
        assert_eq!(zip.to_bytes(), raw);
    }

    #[test]
    fn entry_type_classification() {
        assert!(is_runnable_file("libs/arm64/liba.so"));
        assert!(is_runnable_file("modules/entry.abc"));
        assert!(is_runnable_file("libs/x.an"));
        assert!(!is_runnable_file("module.json"));
        assert_eq!(entry_type_of(".pages.info"), TYPE_BIT_MAP);
        assert_eq!(entry_type_of("resources/index.js"), TYPE_RESOURCE_FILE);
    }

    /// 签名块被写入后必须位于最后一个条目数据与中央目录之间，并可原样读回。
    #[test]
    fn signing_block_roundtrip() {
        let mut zip = Zip::from_bytes(tiny_zip()).unwrap();
        zip.signing_block = b"FAKE-SIGN-BLOCK".to_vec();
        zip.reset_offset();
        let bytes = zip.to_bytes();
        let re = Zip::from_bytes(bytes).unwrap();
        assert_eq!(re.signing_block, b"FAKE-SIGN-BLOCK");
        assert_eq!(re.entries.len(), 1);
        assert_eq!(re.entry_content("module.json").unwrap(), b"{}");
        // 签名块紧跟在条目数据之后
        assert_eq!(
            re.signing_offset,
            re.entries[0].file_offset + re.entries[0].file_size
        );
    }

    /// 对齐后本地头与中央目录项的 extra 长度必须一致，且数据区按 4096 对齐。
    #[test]
    fn alignment_pads_extra() {
        let mut zip = Zip::from_bytes(tiny_zip()).unwrap();
        zip.add_bitmap(vec![0u8; 8]);
        zip.alignment(crate::hap_sign::hap::DEFAULT_ALIGNMENT)
            .unwrap();
        for e in &zip.entries {
            assert_eq!(e.header.extra_data.len(), e.cd.extra_data.len());
        }
        let bitmap = zip.find_entry(BIT_MAP_FILENAME).unwrap();
        let abs = bitmap.cd.offset as usize + bitmap.header.length();
        assert_eq!(abs % 4096, 0);
        // 重排后仍能正确序列化与再解析
        let re = Zip::from_bytes(zip.to_bytes()).unwrap();
        assert_eq!(re.entries.len(), zip.entries.len());
    }

    /// deflate 条目必须能解回原文（HAP 里的 module.json 通常是压缩的）。
    #[test]
    fn deflate_entry_decompresses() {
        let payload = b"{\"module\":{\"name\":\"entry\"}}".repeat(8);
        let deflated = miniz_oxide::deflate::compress_to_vec(&payload, 6);

        let name = b"module.json";
        let mut out = Vec::new();
        out.extend_from_slice(&ZIP_LOCAL_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes()); // method = deflate
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&deflated);
        let cd_off = out.len();
        out.extend_from_slice(&ZIP_CD_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name);
        let cd_len = out.len() - cd_off;
        out.extend_from_slice(&ZIP_EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(cd_len as u32).to_le_bytes());
        out.extend_from_slice(&(cd_off as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());

        let zip = Zip::from_bytes(out).unwrap();
        assert_eq!(zip.entry_content("module.json").unwrap(), payload);
    }
}
