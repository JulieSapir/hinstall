//! 代码签名：fs-verity Merkle 树、ELF 段解析、页面信息 bitmap、code sign block。
//!
//! 与官方 `CodeSignBlock` / `FsVerityUtils` / `ElfUtils` 结构对齐。字节布局全部小端。
//!
//! 层次关系：
//!
//! ```text
//! CodeSignBlock
//! ├─ header（32B：magic + version + blockSize + segmentNum + flags + 8B 保留）
//! ├─ segment headers（3 × 12B）
//! ├─ zero padding（把 merkle tree 起点对齐到 4K）
//! ├─ hap merkle tree
//! ├─ FsVerityInfoSegment（64B）
//! ├─ HapInfoSegment（4B magic + SignInfo）
//! └─ NativeLibInfoSegment
//! ```

use sha2::{Digest, Sha256};

use crate::hap_sign::cms::{self, Attr, SignedDataInput};
use crate::hap_sign::crypto::{PrivateKey, SignAlg};
use crate::hap_sign::der::Der;
use crate::hap_sign::error::{Error, Result};
use crate::hap_sign::json::Json;
use crate::hap_sign::x509::Certificate;
use crate::hap_sign::zip::{
    ABC_FILE_SUFFIX, LIBS_PATH_PREFIX, NATIVE_LIB_AN_SUFFIX, TYPE_BIT_MAP, TYPE_RUNNABLE_FILE,
    ZIP_LOCAL_LENGTH, Zip,
};

// ------------------------------------------------------------ 常量

/// code sign block magic
pub const CODE_SIGN_MAGIC: u64 = 0xE046_C8C6_5389_FCCD;
/// fs-verity info 段 magic
pub const FSVERITY_INFO_MAGIC: u32 = 0x1E38_31AB;
/// HAP info 段 magic
pub const HAP_INFO_MAGIC: u32 = 0xC1B5_CC66;
/// 原生库 info 段 magic
pub const NATIVE_LIB_INFO_MAGIC: u32 = 0x0ED2_E720;

/// fs-verity info 段
pub const CSB_FSVERITY_INFO_SEG: u32 = 0x1;
/// HAP 元信息段
pub const CSB_HAP_META_SEG: u32 = 0x2;
/// 原生库信息段
pub const CSB_NATIVE_LIB_INFO_SEG: u32 = 0x3;

/// SignInfo 标志：内联 Merkle 树
pub const FLAG_MERKLE_TREE_INLINED: u32 = 0x1;
/// SignInfo 标志：包含原生库
pub const FLAG_NATIVE_LIB_INCLUDED: u32 = 0x2;

/// 扩展类型：内联 Merkle 树
pub const FSV_MERKLE_TREE_INLINED: u32 = 0x1;
/// 扩展类型：内联页面信息
pub const FSV_PAGE_INFO_INLINED: u32 = 0x2;

/// 哈希算法：SHA-256
pub const FS_VERITY_HASH_ALG_SHA256: u8 = 1;
/// log2(block size) = 12 → 4096
pub const FS_VERITY_LOG_BLOCK_SIZE: u8 = 12;
/// fs-verity 描述符长度
pub const FS_VERITY_DESCRIPTOR_SIZE: usize = 256;
/// fs-verity 版本
pub const FS_VERITY_VERSION: u8 = 1;
/// 描述符版本（csv2）
pub const CODE_SIGN_VERSION: u8 = 1;
/// 描述符版本（csv2）
pub const CODE_SIGN_VERSION_V2: u8 = 2;
/// bitmap 单位大小（字节）
pub const DEFAULT_UNIT_SIZE: usize = 4;
/// 页大小
pub const PAGE_SIZE_4K: usize = 4096;

/// profile 为 debug 时的 ownerID
pub const DEBUG_LIB_ID: &str = "DEBUG_LIB_ID";

/// bitmap 段类型：ELF 代码段
const ELF_M_CODE: u32 = 1;
/// bitmap 段类型：Ark 字节码
const ABC_M_CODE: u32 = 2;

// ------------------------------------------------------------ 小工具

fn ceil_div(a: usize, b: usize) -> usize {
    a.div_ceil(b)
}

fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn u64le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

// ------------------------------------------------------------ fs-verity

/// 按 4096 分块做 SHA-256；最后一块不足 4096 时先补零再哈希。
///
/// 官方 `MerkleTreeBuilder` 把读入的数据装进 `ceil(size/4096)*4096` 的缓冲区再逐块哈希，
/// 因此尾部不满一块时必须补零——数据区是 4K 对齐时两者结果相同，非对齐（原生库）就会分叉。
fn hash_blocks(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(PAGE_SIZE_4K) * 32);
    let mut padded = vec![0u8; PAGE_SIZE_4K];
    for chunk in data.chunks(PAGE_SIZE_4K) {
        if chunk.len() == PAGE_SIZE_4K {
            out.extend_from_slice(&Sha256::digest(chunk));
        } else {
            padded[..chunk.len()].copy_from_slice(chunk);
            for b in &mut padded[chunk.len()..] {
                *b = 0;
            }
            out.extend_from_slice(&Sha256::digest(&padded));
        }
    }
    out
}

/// 构建 fs-verity Merkle 树，返回 `(树字节或 None, root hash)`。
///
/// 叶子层：数据按 4096 分块取 SHA-256，末尾按 4096 对齐补零；
/// 上层：子层按 4096 分块取 SHA-256，同样对齐补零；
/// 数据 ≤ 4096 时无树，rootHash 取缓冲区前 32 字节。
pub fn fsverity_build_tree(data: &[u8]) -> (Option<Vec<u8>>, Vec<u8>) {
    let data_size = data.len();
    let digest_size = 32usize;
    if data_size == 0 {
        return (None, Vec::new());
    }

    let mut level_size: Vec<usize> = Vec::new();
    let mut original = data_size;
    loop {
        let full_chunk = ceil_div(original, PAGE_SIZE_4K) * digest_size;
        level_size.push(ceil_div(full_chunk, PAGE_SIZE_4K) * PAGE_SIZE_4K);
        original = full_chunk;
        if full_chunk <= PAGE_SIZE_4K {
            break;
        }
    }

    let mut offsets = vec![0usize];
    for i in 0..level_size.len() {
        offsets.push(offsets[i] + level_size[level_size.len() - 1 - i]);
    }
    let mut buf = vec![0u8; offsets[offsets.len() - 1]];

    // 叶子层
    let hashes = hash_blocks(data);
    let leaf_begin = offsets[offsets.len() - 2];
    buf[leaf_begin..leaf_begin + hashes.len()].copy_from_slice(&hashes);
    fsverity_pad(&mut buf, leaf_begin, hashes.len(), data_size);

    // 上层
    for i in (0..offsets.len().saturating_sub(2)).rev() {
        let src = buf[offsets[i + 1]..offsets[i + 2]].to_vec();
        let upper = hash_blocks(&src);
        let dst = offsets[i];
        buf[dst..dst + upper.len()].copy_from_slice(&upper);
        fsverity_pad(&mut buf, dst, upper.len(), src.len());
    }

    if data_size <= PAGE_SIZE_4K {
        return (None, buf[..digest_size].to_vec());
    }
    let root = Sha256::digest(&buf[..PAGE_SIZE_4K]).to_vec();
    (Some(buf), root)
}

/// 把层级缓冲区按 4096 对齐补零。
fn fsverity_pad(buf: &mut [u8], dst: usize, written: usize, original_size: usize) {
    let full_chunk = ceil_div(original_size, PAGE_SIZE_4K) * 32;
    let diff = full_chunk % PAGE_SIZE_4K;
    if diff > 0 {
        let pad = PAGE_SIZE_4K - diff;
        for b in &mut buf[dst + written..dst + written + pad] {
            *b = 0;
        }
    }
}

/// `getDiscByte`：生成摘要用的描述符（首字节 `CODE_SIGN_VERSION`，尾部全零）。
pub fn fsverity_disc_byte(
    file_size: u64,
    root_hash: &[u8],
    flags: u32,
    merkle_tree_offset: u64,
) -> Vec<u8> {
    let mut buf = vec![0u8; FS_VERITY_DESCRIPTOR_SIZE];
    buf[0] = CODE_SIGN_VERSION;
    buf[1] = FS_VERITY_HASH_ALG_SHA256;
    buf[2] = FS_VERITY_LOG_BLOCK_SIZE;
    buf[3] = 0; // saltSize
    buf[4..8].copy_from_slice(&u32le(0)); // signSize
    buf[8..16].copy_from_slice(&u64le(file_size));
    let n = root_hash.len().min(64);
    buf[16..16 + n].copy_from_slice(&root_hash[..n]);
    buf[112..116].copy_from_slice(&u32le(flags));
    buf[116..120].copy_from_slice(&u32le(0));
    buf[120..128].copy_from_slice(&u64le(merkle_tree_offset));
    buf
}

/// `getDiscByteCsv2`：带 bitmap 描述的描述符（末字节 `CODE_SIGN_VERSION_V2`）。
pub fn fsverity_disc_byte_csv2(
    file_size: u64,
    root_hash: &[u8],
    flags: u32,
    merkle_tree_offset: u64,
    map_offset: u64,
    map_size: u64,
    unit_size: u8,
) -> Vec<u8> {
    let mut buf = vec![0u8; FS_VERITY_DESCRIPTOR_SIZE];
    buf[0] = FS_VERITY_VERSION;
    buf[1] = FS_VERITY_HASH_ALG_SHA256;
    buf[2] = FS_VERITY_LOG_BLOCK_SIZE;
    buf[3] = 0;
    buf[4..8].copy_from_slice(&u32le(0));
    buf[8..16].copy_from_slice(&u64le(file_size));
    let n = root_hash.len().min(64);
    buf[16..16 + n].copy_from_slice(&root_hash[..n]);
    buf[112..116].copy_from_slice(&u32le(((unit_size as u32) << 1) | flags));
    buf[116..120].copy_from_slice(&u32le(map_size as u32));
    buf[120..128].copy_from_slice(&u64le(merkle_tree_offset));
    buf[128..136].copy_from_slice(&u64le(map_offset));
    buf[255] = CODE_SIGN_VERSION_V2;
    buf
}

/// fs-verity 摘要封装：`"FSVerity" || u16 algo || u16 len || digest`。
pub fn fsverity_digest(algo_id: u16, digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + digest.len() + 4);
    out.extend_from_slice(b"FSVerity");
    out.extend_from_slice(&algo_id.to_le_bytes());
    out.extend_from_slice(&(digest.len() as u16).to_le_bytes());
    out.extend_from_slice(digest);
    out
}

// ------------------------------------------------------------ ELF

/// 返回 ELF 中可执行程序段的 `[(p_offset, p_filesz)]`；非 ELF 返回空列表。
pub fn elf_exec_segments(data: &[u8]) -> Result<Vec<(u64, u64)>> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Ok(Vec::new());
    }
    let ei_class = data[4];
    let ei_data = data[5];
    let little = ei_data == 1;

    let (phoff, phentsize, phnum): (u64, u16, u16) = match ei_class {
        2 => (
            rd_u64(data, 32, little),
            rd_u16(data, 54, little),
            rd_u16(data, 56, little),
        ),
        1 => (
            rd_u32(data, 28, little) as u64,
            rd_u16(data, 42, little),
            rd_u16(data, 44, little),
        ),
        _ => return Ok(Vec::new()),
    };

    let mut result = Vec::new();
    for i in 0..phnum as u64 {
        let off = phoff + i * phentsize as u64;
        let off = off as usize;
        if off + phentsize as usize > data.len() {
            break;
        }
        // p_flags / p_offset / p_filesz 在 32/64 位下的字段顺序不同
        let (p_flags, p_offset, p_filesz): (u32, u64, u64) = match ei_class {
            2 => (
                rd_u32(data, off + 4, little),
                rd_u64(data, off + 8, little),
                rd_u64(data, off + 32, little),
            ),
            _ => (
                rd_u32(data, off + 24, little),
                rd_u32(data, off + 4, little) as u64,
                rd_u32(data, off + 16, little) as u64,
            ),
        };
        if p_flags & 1 != 0 {
            result.push((p_offset, p_filesz));
        }
    }
    Ok(result)
}

fn rd_u16(d: &[u8], off: usize, little: bool) -> u16 {
    let b = [d[off], d[off + 1]];
    if little {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    }
}

fn rd_u32(d: &[u8], off: usize, little: bool) -> u32 {
    let b = [d[off], d[off + 1], d[off + 2], d[off + 3]];
    if little {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

fn rd_u64(d: &[u8], off: usize, little: bool) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[off..off + 8]);
    if little {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    }
}

// ------------------------------------------------------------ 页面信息 bitmap

/// 生成 pages 信息 bitmap；`segments` 为 `[(类型, 起始, 结束)]`。
///
/// ELF 段置位 `i`，ABC 段置位 `i + 1`，单位 4 字节，返回小端 u64 序列。
pub fn generate_bitmap(segments: &[(u32, usize, usize)], max_entry_data_offset: usize) -> Vec<u8> {
    if segments.is_empty() {
        return Vec::new();
    }
    let capacity_bits = max_entry_data_offset / PAGE_SIZE_4K * DEFAULT_UNIT_SIZE;
    let mut words = vec![0u64; capacity_bits.div_ceil(64)];

    for (seg_type, start, end) in segments {
        let begin = (start >> 12) * DEFAULT_UNIT_SIZE;
        let finish = if end % PAGE_SIZE_4K == 0 {
            (end >> 12) * DEFAULT_UNIT_SIZE
        } else {
            ((end >> 12) + 1) * DEFAULT_UNIT_SIZE
        };
        let mut i = begin;
        while i < finish {
            let index = if *seg_type == ELF_M_CODE { i } else { i + 1 };
            let word = index / 64;
            if word >= words.len() {
                words.resize(word + 1, 0);
            }
            words[word] |= 1u64 << (index % 64);
            i += DEFAULT_UNIT_SIZE;
        }
    }

    let mut out = Vec::with_capacity(words.len() * 8);
    for w in words {
        out.extend_from_slice(&u64le(w));
    }
    out
}

// ------------------------------------------------------------ SignInfo 扩展

/// Merkle 树扩展。
#[derive(Clone, Debug)]
pub struct MerkleTreeExtension {
    /// 树字节数
    pub merkle_tree_size: u64,
    /// 树偏移
    pub merkle_tree_offset: u64,
    /// root hash（右侧补零到 64 字节）
    pub root_hash: Vec<u8>,
}

impl MerkleTreeExtension {
    /// 数据区大小（不含 8 字节头）
    pub const DATA_SIZE: u32 = 80;

    /// 新建。
    pub fn new(merkle_tree_size: u64, merkle_tree_offset: u64, root_hash: &[u8]) -> Self {
        let mut rh = root_hash.to_vec();
        rh.resize(64, 0);
        rh.truncate(64);
        Self {
            merkle_tree_size,
            merkle_tree_offset,
            root_hash: rh,
        }
    }

    /// 编码长度。
    pub fn size(&self) -> usize {
        8 + Self::DATA_SIZE as usize
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&u32le(FSV_MERKLE_TREE_INLINED));
        out.extend_from_slice(&u32le(Self::DATA_SIZE));
        out.extend_from_slice(&u64le(self.merkle_tree_size));
        out.extend_from_slice(&u64le(self.merkle_tree_offset));
        out.extend_from_slice(&self.root_hash);
        out
    }
}

/// 页面信息扩展。
#[derive(Clone, Debug)]
pub struct PageInfoExtension {
    /// bitmap 偏移
    pub map_offset: u64,
    /// bitmap 大小
    pub map_size: u64,
    /// 单位大小
    pub unit_size: u8,
    /// 二次签名
    pub signature: Vec<u8>,
    /// 签名后的零填充
    pub zero_padding: Vec<u8>,
}

impl PageInfoExtension {
    /// 数据区大小（不含签名）
    pub const DATA_SIZE_WITHOUT_SIGN: u32 = 24;

    /// 新建。
    pub fn new(map_offset: u64, map_size: u64) -> Self {
        Self {
            map_offset,
            map_size,
            unit_size: DEFAULT_UNIT_SIZE as u8,
            signature: Vec::new(),
            zero_padding: Vec::new(),
        }
    }

    /// 设置二次签名并补零到 4 字节对齐。
    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.zero_padding = vec![0u8; (4 - signature.len() % 4) % 4];
        self.signature = signature;
    }

    /// 编码长度。
    pub fn size(&self) -> usize {
        8 + Self::DATA_SIZE_WITHOUT_SIGN as usize + self.signature.len() + self.zero_padding.len()
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let data_size =
            Self::DATA_SIZE_WITHOUT_SIGN as usize + self.signature.len() + self.zero_padding.len();
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&u32le(FSV_PAGE_INFO_INLINED));
        out.extend_from_slice(&u32le(data_size as u32));
        out.extend_from_slice(&u64le(self.map_offset));
        out.extend_from_slice(&u64le(self.map_size));
        out.push(self.unit_size);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&u32le(self.signature.len() as u32));
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.zero_padding);
        out
    }
}

/// SignInfo 扩展。
#[derive(Clone, Debug)]
pub enum Extension {
    /// 内联 Merkle 树
    Merkle(MerkleTreeExtension),
    /// 内联页面信息
    PageInfo(PageInfoExtension),
}

impl Extension {
    /// 编码长度。
    pub fn size(&self) -> usize {
        match self {
            Extension::Merkle(e) => e.size(),
            Extension::PageInfo(e) => e.size(),
        }
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Extension::Merkle(e) => e.to_bytes(),
            Extension::PageInfo(e) => e.to_bytes(),
        }
    }
}

// ------------------------------------------------------------ SignInfo

/// 代码签名信息块（60 字节固定区 + 签名 + 扩展）。
#[derive(Clone, Debug)]
pub struct SignInfo {
    /// salt 长度
    pub salt_size: u32,
    /// 标志位
    pub flags: u32,
    /// 被签数据大小
    pub data_size: u64,
    /// salt（32 字节）
    pub salt: Vec<u8>,
    /// 签名
    pub signature: Vec<u8>,
    /// 签名后的零填充
    pub zero_padding: Vec<u8>,
    /// 扩展
    pub extensions: Vec<Extension>,
}

impl SignInfo {
    /// 固定区长度
    pub const SIZE_WITHOUT_SIGNATURE: usize = 60;
    /// salt 缓冲区长度
    pub const SALT_BUFFER_LENGTH: usize = 32;

    /// 新建。
    pub fn new(
        salt_size: u32,
        flags: u32,
        data_size: u64,
        salt: Option<Vec<u8>>,
        signature: Vec<u8>,
    ) -> Self {
        let zero_padding = vec![0u8; (4 - signature.len() % 4) % 4];
        Self {
            salt_size,
            flags,
            data_size,
            salt: salt.unwrap_or_else(|| vec![0u8; Self::SALT_BUFFER_LENGTH]),
            signature,
            zero_padding,
            extensions: Vec::new(),
        }
    }

    /// 追加扩展。
    pub fn add_extension(&mut self, ext: Extension) {
        self.extensions.push(ext);
    }

    /// 是否存在 Merkle 树扩展。
    pub fn has_merkle_tree(&self) -> bool {
        self.extensions
            .iter()
            .any(|e| matches!(e, Extension::Merkle(_)))
    }

    /// 编码长度。
    pub fn size(&self) -> usize {
        Self::SIZE_WITHOUT_SIGNATURE
            + self.signature.len()
            + self.zero_padding.len()
            + self.extensions.iter().map(|e| e.size()).sum::<usize>()
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let extension_offset =
            Self::SIZE_WITHOUT_SIGNATURE + self.signature.len() + self.zero_padding.len();
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&u32le(self.salt_size));
        out.extend_from_slice(&u32le(self.signature.len() as u32));
        out.extend_from_slice(&u32le(self.flags));
        out.extend_from_slice(&u64le(self.data_size));
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&u32le(self.extensions.len() as u32));
        out.extend_from_slice(&u32le(extension_offset as u32));
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.zero_padding);
        for ext in &self.extensions {
            out.extend_from_slice(&ext.to_bytes());
        }
        out
    }
}

// ------------------------------------------------------------ 段

/// fs-verity 信息段（64 字节）。
#[derive(Clone, Debug)]
pub struct FsVerityInfoSegment {
    /// 版本
    pub version: u8,
    /// 哈希算法
    pub hash_algorithm: u8,
    /// log2(block size)
    pub log2_block_size: u8,
}

impl FsVerityInfoSegment {
    /// 段长度
    pub const SIZE: usize = 64;

    /// 编码长度。
    pub fn size(&self) -> usize {
        Self::SIZE
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; Self::SIZE];
        out[0..4].copy_from_slice(&u32le(FSVERITY_INFO_MAGIC));
        out[4] = self.version;
        out[5] = self.hash_algorithm;
        out[6] = self.log2_block_size;
        out
    }
}

/// HAP 元信息段。
#[derive(Clone, Debug)]
pub struct HapInfoSegment {
    /// HAP 自身的签名信息
    pub sign_info: SignInfo,
}

impl HapInfoSegment {
    /// 编码长度。
    pub fn size(&self) -> usize {
        4 + self.sign_info.size()
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&u32le(HAP_INFO_MAGIC));
        out.extend_from_slice(&self.sign_info.to_bytes());
        out
    }
}

/// 原生库信息段。
#[derive(Clone, Debug, Default)]
pub struct NativeLibInfoSegment {
    /// 文件名列表
    pub file_names: Vec<String>,
    /// 对应的签名信息
    pub sign_infos: Vec<SignInfo>,
    /// 文件名块后的零填充
    pub zero_padding: Vec<u8>,
}

impl NativeLibInfoSegment {
    /// 单个「文件名 + SignInfo」定位项长度
    pub const SIGNED_FILE_POS_SIZE: usize = 16;

    /// 设置列表（顺序即插入顺序）。
    pub fn set_list(&mut self, pairs: Vec<(String, SignInfo)>) {
        self.file_names = pairs.iter().map(|(n, _)| n.clone()).collect();
        self.sign_infos = pairs.into_iter().map(|(_, s)| s).collect();
        let name_len: usize = self.file_names.iter().map(|n| n.len()).sum();
        self.zero_padding = vec![0u8; (4 - name_len % 4) % 4];
    }

    /// 段数。
    pub fn section_num(&self) -> usize {
        self.sign_infos.len()
    }

    /// 编码长度。
    pub fn size(&self) -> usize {
        let name_len: usize = self.file_names.iter().map(|n| n.len()).sum();
        12 + self.sign_infos.len() * Self::SIGNED_FILE_POS_SIZE
            + name_len
            + self.zero_padding.len()
            + self.sign_infos.iter().map(|s| s.size()).sum::<usize>()
    }

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let base = 12 + self.sign_infos.len() * Self::SIGNED_FILE_POS_SIZE;
        let name_len: usize = self.file_names.iter().map(|n| n.len()).sum();
        let sign_base = base + name_len + self.zero_padding.len();

        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&u32le(NATIVE_LIB_INFO_MAGIC));
        out.extend_from_slice(&u32le(self.size() as u32));
        out.extend_from_slice(&u32le(self.sign_infos.len() as u32));

        let mut name_offset = 0usize;
        let mut sign_offset = 0usize;
        for (name, sign_info) in self.file_names.iter().zip(self.sign_infos.iter()) {
            out.extend_from_slice(&u32le((base + name_offset) as u32));
            out.extend_from_slice(&u32le(name.len() as u32));
            out.extend_from_slice(&u32le((sign_base + sign_offset) as u32));
            out.extend_from_slice(&u32le(sign_info.size() as u32));
            name_offset += name.len();
            sign_offset += sign_info.size();
        }
        for name in &self.file_names {
            out.extend_from_slice(name.as_bytes());
        }
        out.extend_from_slice(&self.zero_padding);
        for sign_info in &self.sign_infos {
            out.extend_from_slice(&sign_info.to_bytes());
        }
        out
    }
}

/// code sign block 头（32 字节）。
#[derive(Clone, Debug)]
pub struct CodeSignBlockHeader {
    /// 块总长
    pub block_size: u32,
    /// 段数
    pub segment_num: u32,
    /// 标志位
    pub flags: u32,
}

impl CodeSignBlockHeader {
    /// 头长度
    pub const SIZE: usize = 32;

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; Self::SIZE];
        out[0..8].copy_from_slice(&u64le(CODE_SIGN_MAGIC));
        out[8..12].copy_from_slice(&u32le(1)); // version
        out[12..16].copy_from_slice(&u32le(self.block_size));
        out[16..20].copy_from_slice(&u32le(self.segment_num));
        out[20..24].copy_from_slice(&u32le(self.flags));
        out
    }
}

/// 段头（12 字节）。
#[derive(Clone, Debug)]
pub struct SegmentHeader {
    /// 段类型
    pub seg_type: u32,
    /// 段偏移
    pub segment_offset: u32,
    /// 段长度
    pub segment_size: u32,
}

impl SegmentHeader {
    /// 头长度
    pub const SIZE: usize = 12;

    /// 编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.extend_from_slice(&u32le(self.seg_type));
        out.extend_from_slice(&u32le(self.segment_offset));
        out.extend_from_slice(&u32le(self.segment_size));
        out
    }
}

// ------------------------------------------------------------ CodeSignBlock

/// 代码签名块。
#[derive(Clone, Debug)]
pub struct CodeSignBlock {
    /// 头
    pub header: CodeSignBlockHeader,
    /// 段头
    pub segment_headers: Vec<SegmentHeader>,
    /// fs-verity 信息段
    pub fs_verity_info_segment: FsVerityInfoSegment,
    /// HAP 元信息段
    pub hap_info_segment: HapInfoSegment,
    /// 原生库信息段
    pub native_lib_info_segment: NativeLibInfoSegment,
    /// 对齐用零填充
    pub zero_padding: Vec<u8>,
    /// HAP 的 Merkle 树
    pub hap_merkle_tree: Vec<u8>,
}

impl CodeSignBlock {
    /// 段头数量
    pub const SEGMENT_HEADER_COUNT: usize = 3;

    /// 新建。
    pub fn new(hap_sign_info: SignInfo, hap_merkle_tree: Vec<u8>) -> Self {
        Self {
            header: CodeSignBlockHeader {
                block_size: 0,
                segment_num: 0,
                flags: 0,
            },
            segment_headers: Vec::new(),
            fs_verity_info_segment: FsVerityInfoSegment {
                version: FS_VERITY_VERSION,
                hash_algorithm: FS_VERITY_HASH_ALG_SHA256,
                log2_block_size: FS_VERITY_LOG_BLOCK_SIZE,
            },
            hap_info_segment: HapInfoSegment {
                sign_info: hap_sign_info,
            },
            native_lib_info_segment: NativeLibInfoSegment::default(),
            zero_padding: Vec::new(),
            hap_merkle_tree,
        }
    }

    /// 设置标志位。
    pub fn set_code_sign_block_flag(&mut self) {
        let mut flags = FLAG_MERKLE_TREE_INLINED;
        if self.native_lib_info_segment.section_num() != 0 {
            flags += FLAG_NATIVE_LIB_INCLUDED;
        }
        self.header.flags = flags;
    }

    /// 设置段头。
    pub fn set_segment_headers(&mut self) {
        self.segment_headers = vec![
            SegmentHeader {
                seg_type: CSB_FSVERITY_INFO_SEG,
                segment_offset: 0,
                segment_size: self.fs_verity_info_segment.size() as u32,
            },
            SegmentHeader {
                seg_type: CSB_HAP_META_SEG,
                segment_offset: 0,
                segment_size: self.hap_info_segment.size() as u32,
            },
            SegmentHeader {
                seg_type: CSB_NATIVE_LIB_INFO_SEG,
                segment_offset: 0,
                segment_size: self.native_lib_info_segment.size() as u32,
            },
        ];
    }

    /// 计算各段偏移。
    pub fn compute_segment_offset(&mut self) {
        let mut offset = CodeSignBlockHeader::SIZE
            + self.segment_headers.len() * SegmentHeader::SIZE
            + self.zero_padding.len()
            + self.hap_merkle_tree.len();
        for sh in &mut self.segment_headers {
            sh.segment_offset = offset as u32;
            offset += sh.segment_size as usize;
        }
    }

    /// 计算 Merkle 树偏移，并把 block 起点对齐到 4K。
    pub fn compute_merkle_tree_offset(&mut self, code_sign_block_offset: usize) -> u64 {
        let size_without_tree =
            CodeSignBlockHeader::SIZE + Self::SEGMENT_HEADER_COUNT * SegmentHeader::SIZE;
        let residual = (code_sign_block_offset + size_without_tree) % PAGE_SIZE_4K;
        self.zero_padding = if residual == 0 {
            Vec::new()
        } else {
            vec![0u8; PAGE_SIZE_4K - residual]
        };
        (code_sign_block_offset + size_without_tree + self.zero_padding.len()) as u64
    }

    /// 生成字节流（会写入 `block_size` 并更新 Merkle 树偏移）。
    pub fn generate_bytes(&mut self, fsv_tree_offset: u64) -> Vec<u8> {
        let size = CodeSignBlockHeader::SIZE
            + self.segment_headers.len() * SegmentHeader::SIZE
            + self.zero_padding.len()
            + self.hap_merkle_tree.len()
            + self.fs_verity_info_segment.size()
            + self.hap_info_segment.size()
            + self.native_lib_info_segment.size();
        for ext in &mut self.hap_info_segment.sign_info.extensions {
            if let Extension::Merkle(m) = ext {
                m.merkle_tree_offset = fsv_tree_offset;
            }
        }
        self.header.block_size = size as u32;

        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&self.header.to_bytes());
        for sh in &self.segment_headers {
            out.extend_from_slice(&sh.to_bytes());
        }
        out.extend_from_slice(&self.zero_padding);
        if self.hap_info_segment.sign_info.has_merkle_tree() {
            out.extend_from_slice(&self.hap_merkle_tree);
        }
        out.extend_from_slice(&self.fs_verity_info_segment.to_bytes());
        out.extend_from_slice(&self.hap_info_segment.to_bytes());
        out.extend_from_slice(&self.native_lib_info_segment.to_bytes());
        out
    }
}

// ------------------------------------------------------------ 代码签名流程

/// `module.json` 内容（去掉所有换行，与官方实现一致）。
fn module_content_without_newlines(zip: &Zip) -> Result<String> {
    if zip.find_entry("module.json").is_none() {
        return Ok(String::new());
    }
    let content = zip.entry_content("module.json")?;
    let text = String::from_utf8(content)
        .map_err(|e| Error::Invalid(format!("module.json 不是 UTF-8: {e}")))?;
    Ok(text.lines().collect::<Vec<_>>().join(""))
}

/// `app.bundleType`。
fn bundle_type(module_content: &str) -> Result<String> {
    if module_content.is_empty() {
        return Ok(String::new());
    }
    let obj = Json::parse(module_content)
        .map_err(|e| Error::Invalid(format!("module.json 不是合法 JSON: {e}")))?;
    Ok(obj
        .get("app")
        .and_then(|a| a.get("bundleType"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string())
}

/// profile 中的 pluginId（`app-services-capabilities` 下）。
fn parse_plugin_id(profile_content: &str) -> Result<String> {
    let obj = Json::parse(profile_content)
        .map_err(|e| Error::Invalid(format!("profile 不是合法 JSON: {e}")))?;
    let caps = obj.get("app-services-capabilities").ok_or_else(|| {
        Error::Invalid("profile 缺少 app-services-capabilities，无法取得 pluginId".into())
    })?;
    let perm = caps
        .get("ohos.permission.kernel.SUPPORT_PLUGIN")
        .ok_or_else(|| {
            Error::Invalid("profile 缺少 ohos.permission.kernel.SUPPORT_PLUGIN".into())
        })?;
    let value = perm
        .get("pluginDistributionIDs")
        .ok_or_else(|| Error::Invalid("profile 缺少 pluginDistributionIDs".into()))?;
    value
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Invalid("pluginDistributionIDs 不是字符串".into()))
}

/// 按 profile 类型返回 ownerID：debug → `DEBUG_LIB_ID`，release → `app-identifier`。
fn app_identifier(profile_content: &str) -> Result<String> {
    let obj = Json::parse(profile_content)
        .map_err(|e| Error::Invalid(format!("profile 不是合法 JSON: {e}")))?;
    match obj.get("type").and_then(|t| t.as_str()) {
        Some("debug") => Ok(DEBUG_LIB_ID.to_string()),
        Some("release") => obj
            .get("bundle-info")
            .and_then(|b| b.get("app-identifier"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Invalid("profile 缺少 bundle-info.app-identifier".into())),
        other => Err(Error::Invalid(format!(
            "不支持的 profile type: {}",
            other.unwrap_or("<缺失>")
        ))),
    }
}

/// 代码签名用 CMS：detached + ownerID（可选 pluginId）属性。
fn cms_sign_code(
    data: &[u8],
    owner_id: &str,
    plugin_id: Option<&str>,
    certs: &[Certificate],
    key: &PrivateKey,
    alg: SignAlg,
    sign_time: Option<i64>,
) -> Result<Vec<u8>> {
    let mut extra = vec![Attr::new(
        cms::OID_OWNER_ID,
        Der::new().utf8(owner_id).bytes(),
    )];
    if let Some(pid) = plugin_id {
        extra.push(Attr::new(cms::OID_PLUGIN_ID, Der::new().utf8(pid).bytes()));
    }
    cms::signed_data(SignedDataInput {
        content: data,
        certs,
        key,
        alg,
        detached: true,
        extra_attrs: extra,
        sign_time,
    })
}

/// 对一段内容做 fs-verity 签名，返回 `(SignInfo, 树字节)`。
#[allow(clippy::too_many_arguments)]
pub fn sign_file_content(
    data: &[u8],
    store_tree: bool,
    fsv_tree_offset: u64,
    owner_id: &str,
    plugin_id: Option<&str>,
    page_info_ext: Option<PageInfoExtension>,
    certs: &[Certificate],
    key: &PrivateKey,
    alg: SignAlg,
    sign_time: Option<i64>,
) -> Result<(SignInfo, Option<Vec<u8>>)> {
    let file_size = data.len();
    let (tree_bytes, root_hash) = fsverity_build_tree(data);
    let flags = if fsv_tree_offset == 0 { 0 } else { 1 };
    let disc = fsverity_disc_byte(file_size as u64, &root_hash, flags, fsv_tree_offset);
    let signature = cms_sign_code(
        &fsverity_digest(FS_VERITY_HASH_ALG_SHA256 as u16, &Sha256::digest(&disc)),
        owner_id,
        plugin_id,
        certs,
        key,
        alg,
        sign_time,
    )?;

    let sign_flags = if store_tree {
        FLAG_MERKLE_TREE_INLINED
    } else {
        0
    };
    let mut sign_info = SignInfo::new(0, sign_flags, file_size as u64, None, signature);
    if store_tree {
        let tree_len = tree_bytes.as_ref().map(|t| t.len()).unwrap_or(0);
        sign_info.add_extension(Extension::Merkle(MerkleTreeExtension::new(
            tree_len as u64,
            fsv_tree_offset,
            &root_hash,
        )));
        if let Some(mut page_info) = page_info_ext
            && flags != 0
        {
            let disc2 = fsverity_disc_byte_csv2(
                file_size as u64,
                &root_hash,
                flags,
                fsv_tree_offset,
                page_info.map_offset,
                page_info.map_size,
                page_info.unit_size,
            );
            let signature2 = cms_sign_code(
                &fsverity_digest(FS_VERITY_HASH_ALG_SHA256 as u16, &Sha256::digest(&disc2)),
                owner_id,
                plugin_id,
                certs,
                key,
                alg,
                sign_time,
            )?;
            page_info.set_signature(signature2);
            sign_info.add_extension(Extension::PageInfo(page_info));
        }
    }
    Ok((sign_info, tree_bytes))
}

/// 代码签名覆盖的数据区大小与 bitmap 扩展（与 `computeDataSize` 一致）。
pub fn compute_data_size_and_page_info(zip: &Zip) -> Result<(usize, Option<PageInfoExtension>)> {
    let mut data_size = 0usize;
    let mut page_info = None;
    for e in &zip.entries {
        let method = e.header.method;
        if e.entry_type == TYPE_RUNNABLE_FILE && method == 0 {
            continue;
        }
        let data_offset = e.cd.offset as usize
            + ZIP_LOCAL_LENGTH
            + e.header.file_name.len()
            + e.header.extra_data.len();
        if e.entry_type == TYPE_BIT_MAP {
            page_info = Some(PageInfoExtension::new(
                data_offset as u64,
                (data_offset / PAGE_SIZE_4K * DEFAULT_UNIT_SIZE) as u64,
            ));
            continue;
        }
        if e.cd.offset == 0 {
            break;
        }
        data_size = data_offset;
        break;
    }
    if !data_size.is_multiple_of(PAGE_SIZE_4K) {
        return Err(Error::Invalid(format!(
            "HAP 数据区未按 4K 对齐: {data_size}"
        )));
    }
    Ok((data_size, page_info))
}

/// 构造 pages 信息 bitmap：可执行条目（`.abc` / `.so` / `.an`）的段范围。
pub fn build_page_bitmap(zip: &Zip) -> Result<Vec<u8>> {
    let mut runnable: Vec<(String, usize)> = Vec::new();
    let mut max_offset = 0usize;
    for e in &zip.entries {
        let data_offset = e.cd.offset as usize
            + ZIP_LOCAL_LENGTH
            + e.header.file_name.len()
            + e.header.extra_data.len();
        if !data_offset.is_multiple_of(PAGE_SIZE_4K) {
            return Err(Error::Invalid(format!(
                "条目 {} 数据区未按 4K 对齐: {data_offset}",
                e.name()
            )));
        }
        if e.entry_type == TYPE_RUNNABLE_FILE && e.header.method == 0 {
            runnable.push((e.name(), data_offset));
            continue;
        }
        max_offset = data_offset;
        break;
    }
    if runnable.is_empty() {
        return Ok(Vec::new());
    }

    let mut segments = Vec::new();
    for (name, data_offset) in runnable {
        if name.ends_with(ABC_FILE_SUFFIX) {
            let size = zip.entry_content(&name)?.len();
            segments.push((ABC_M_CODE, data_offset, data_offset + size));
            continue;
        }
        let content = zip.entry_content(&name)?;
        for (p_offset, p_filesz) in elf_exec_segments(&content)? {
            let begin = data_offset + p_offset as usize;
            segments.push((ELF_M_CODE, begin, begin + p_filesz as usize));
        }
    }
    Ok(generate_bitmap(&segments, max_offset))
}

/// 对 HAP 内的原生库（`libs/` 前缀或 `.an` 后缀）逐个签名。
pub fn sign_native_libs(
    zip: &Zip,
    owner_id: &str,
    plugin_id: Option<&str>,
    certs: &[Certificate],
    key: &PrivateKey,
    alg: SignAlg,
    sign_time: Option<i64>,
) -> Result<Vec<(String, SignInfo)>> {
    let names: Vec<String> = zip
        .entries
        .iter()
        .map(|e| e.name())
        .filter(|n| {
            !n.ends_with('/')
                && (n.ends_with(NATIVE_LIB_AN_SUFFIX) || n.starts_with(LIBS_PATH_PREFIX))
        })
        .collect();

    let mut result = Vec::new();
    for name in names {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("hnp/") && lower.ends_with(".hnp") {
            return Err(Error::Invalid(format!(
                "暂不支持含 hnp 的 HAP 代码签名: {name}"
            )));
        }
        let data = zip.entry_content(&name)?;
        let (sign_info, _) = sign_file_content(
            &data, false, 0, owner_id, plugin_id, None, certs, key, alg, sign_time,
        )?;
        result.push((name, sign_info));
    }
    Ok(result)
}

/// 组装 code sign block 字节。
#[allow(clippy::too_many_arguments)]
pub fn build_code_sign_block(
    zip: &Zip,
    code_sign_offset: usize,
    profile_content: &str,
    certs: &[Certificate],
    key: &PrivateKey,
    alg: SignAlg,
    sign_time: Option<i64>,
) -> Result<Vec<u8>> {
    let (data_size, page_info_ext) = compute_data_size_and_page_info(zip)?;
    let module_content = module_content_without_newlines(zip)?;
    let bundle_type = bundle_type(&module_content)?;
    let plugin_id = if bundle_type == "appPlugin" {
        Some(parse_plugin_id(profile_content)?)
    } else {
        None
    };
    let owner_id = app_identifier(profile_content)?;

    // 先算 Merkle 树偏移（决定 zero padding），再对数据区做 fs-verity 签名
    let mut csb = CodeSignBlock::new(SignInfo::new(0, 0, 0, None, Vec::new()), Vec::new());
    let fsv_tree_offset = csb.compute_merkle_tree_offset(code_sign_offset);

    if data_size > zip.raw.len() {
        return Err(Error::Invalid(format!(
            "数据区大小 {data_size} 超过文件长度 {}",
            zip.raw.len()
        )));
    }
    let hap_data = &zip.raw[..data_size];
    let (sign_info, tree_bytes) = sign_file_content(
        hap_data,
        true,
        fsv_tree_offset,
        &owner_id,
        plugin_id.as_deref(),
        page_info_ext,
        certs,
        key,
        alg,
        sign_time,
    )?;

    let native_libs = sign_native_libs(
        zip,
        &owner_id,
        plugin_id.as_deref(),
        certs,
        key,
        alg,
        sign_time,
    )?;

    csb.hap_info_segment.sign_info = sign_info;
    csb.hap_merkle_tree = tree_bytes.unwrap_or_default();
    csb.native_lib_info_segment.set_list(native_libs);
    csb.set_segment_headers();
    csb.header.segment_num = csb.segment_headers.len() as u32;
    csb.set_code_sign_block_flag();
    csb.compute_segment_offset();
    Ok(csb.generate_bytes(fsv_tree_offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hap_sign::crypto::EcKey;
    use crate::hap_sign::x509::tests::self_signed_cert;
    use p256::elliptic_curve::Generate;

    #[test]
    fn fsverity_small_file_has_no_tree() {
        // 单块：补零到 4096 再哈希
        let data = vec![7u8; 100];
        let (tree, root) = fsverity_build_tree(&data);
        assert!(tree.is_none());
        let mut padded = vec![0u8; PAGE_SIZE_4K];
        padded[..100].copy_from_slice(&data);
        assert_eq!(root, Sha256::digest(&padded).to_vec());
    }

    #[test]
    fn fsverity_last_block_is_zero_padded() {
        // 4096 + 1 字节：第二块补零到 4096 再哈希，顶层块也要补零到 4096
        let data = vec![3u8; PAGE_SIZE_4K + 1];
        let (tree, root) = fsverity_build_tree(&data);
        assert!(tree.is_some());
        let mut second = vec![0u8; PAGE_SIZE_4K];
        second[0] = 3;
        let mut top = vec![0u8; PAGE_SIZE_4K];
        top[..32].copy_from_slice(&Sha256::digest(&data[..PAGE_SIZE_4K]));
        top[32..64].copy_from_slice(&Sha256::digest(&second));
        assert_eq!(root, Sha256::digest(&top).to_vec());
        // 不补零的算法会得到不同的 root
        let wrong = Sha256::digest(Sha256::digest(&data[PAGE_SIZE_4K..])).to_vec();
        assert_ne!(root, wrong);
    }

    #[test]
    fn fsverity_tree_levels() {
        // 3 个 4K 页 → 叶子层 3 个摘要，上层 1 个摘要
        let data = vec![1u8; PAGE_SIZE_4K * 3];
        let (tree, root) = fsverity_build_tree(&data);
        let tree = tree.expect("应生成 Merkle 树");
        assert_eq!(tree.len(), PAGE_SIZE_4K);
        let leaf: Vec<u8> = data
            .chunks(PAGE_SIZE_4K)
            .flat_map(|c| Sha256::digest(c).to_vec())
            .collect();
        assert_eq!(&tree[..leaf.len()], leaf.as_slice());
        assert_eq!(root, Sha256::digest(&tree[..PAGE_SIZE_4K]).to_vec());
    }

    #[test]
    fn elf_segments_parse() {
        // 最小 64 位 ELF 头 + 1 个可执行程序段
        let mut elf = vec![0u8; 64 + 56];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // 64 位
        elf[5] = 1; // 小端
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
        elf[ph + 8..ph + 16].copy_from_slice(&0x100u64.to_le_bytes()); // p_offset
        elf[ph + 32..ph + 40].copy_from_slice(&0x200u64.to_le_bytes()); // p_filesz
        assert_eq!(elf_exec_segments(&elf).unwrap(), [(0x100, 0x200)]);

        // 非 ELF
        assert!(elf_exec_segments(b"not an elf").unwrap().is_empty());
    }

    #[test]
    fn bitmap_bits() {
        // ELF 段 [0x1000, 0x2000) → 置位 i；ABC 段 [0x2000, 0x3000) → 置位 i+1
        let segments = [(ELF_M_CODE, 0x1000, 0x2000), (ABC_M_CODE, 0x2000, 0x3000)];
        let out = generate_bitmap(&segments, 0x4000);
        // 容量 = 4 个 4K 页 × 4 字节 = 16 位 → 1 个 u64
        assert_eq!(out.len(), 8);
        let w0 = u64::from_le_bytes(out[0..8].try_into().unwrap());
        assert_eq!(w0, (1u64 << 4) | (1u64 << 9));
    }

    #[test]
    fn sign_info_layout() {
        let mut si = SignInfo::new(0, FLAG_MERKLE_TREE_INLINED, 4096, None, vec![1, 2, 3]);
        si.add_extension(Extension::Merkle(MerkleTreeExtension::new(
            4096, 0x2000, &[9u8; 32],
        )));
        let bytes = si.to_bytes();
        assert_eq!(bytes.len(), si.size());
        assert_eq!(&bytes[0..4], &0u32.to_le_bytes()); // saltSize
        assert_eq!(&bytes[4..8], &3u32.to_le_bytes()); // sigSize
        assert_eq!(&bytes[8..12], &FLAG_MERKLE_TREE_INLINED.to_le_bytes());
        assert_eq!(&bytes[12..20], &4096u64.to_le_bytes()); // dataSize
        assert_eq!(&bytes[52..56], &1u32.to_le_bytes()); // extensionNum
        // 扩展偏移 = 60 + 3 + 1（补零）
        assert_eq!(&bytes[56..60], &64u32.to_le_bytes());
        assert_eq!(&bytes[60..63], &[1, 2, 3]);
        assert_eq!(bytes[63], 0);
        assert_eq!(&bytes[64..68], &u32le(FSV_MERKLE_TREE_INLINED));
    }

    /// 端到端：对一个最小 HAP 做代码签名，检查块头与段头自洽。
    #[test]
    fn code_sign_block_layout() {
        let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut crate::util::os_rng());
        let cert = self_signed_cert(&sk, "test");
        let key = PrivateKey::Ec(EcKey::P256(Box::new(sk)));
        let profile = r#"{"type":"debug","bundle-info":{"app-identifier":"x"}}"#;

        // 构造一个 4K 对齐的单条目 HAP
        let mut zip = Zip::from_bytes(crate::hap_sign::zip::tests::tiny_zip()).unwrap();
        zip.alignment(crate::hap_sign::hap::DEFAULT_ALIGNMENT)
            .unwrap();
        let hap_bytes = zip.to_bytes();
        let zip = Zip::from_bytes(hap_bytes).unwrap();

        let block = build_code_sign_block(
            &zip,
            zip.cd_offset,
            profile,
            std::slice::from_ref(&cert),
            &key,
            SignAlg::EcdsaSha256,
            Some(1_700_000_000),
        )
        .unwrap();

        // 头部自洽：magic / version / blockSize / segmentNum
        assert_eq!(&block[0..8], &u64le(CODE_SIGN_MAGIC));
        assert_eq!(&block[8..12], &u32le(1));
        let block_size = u32::from_le_bytes(block[12..16].try_into().unwrap()) as usize;
        assert_eq!(block_size, block.len());
        assert_eq!(&block[16..20], &u32le(3));
        // 三个段头类型
        let types: Vec<u32> = (0..3)
            .map(|i| {
                let off = CodeSignBlockHeader::SIZE + i * SegmentHeader::SIZE;
                u32::from_le_bytes(block[off..off + 4].try_into().unwrap())
            })
            .collect();
        assert_eq!(
            types,
            [
                CSB_FSVERITY_INFO_SEG,
                CSB_HAP_META_SEG,
                CSB_NATIVE_LIB_INFO_SEG
            ]
        );
        // 段偏移必须依次递增且落在块内
        let mut last = 0u32;
        for i in 0..3 {
            let off = CodeSignBlockHeader::SIZE + i * SegmentHeader::SIZE;
            let seg_off = u32::from_le_bytes(block[off + 4..off + 8].try_into().unwrap());
            let seg_size = u32::from_le_bytes(block[off + 8..off + 12].try_into().unwrap());
            assert!(seg_off as usize + seg_size as usize <= block.len());
            assert!(seg_off >= last);
            last = seg_off;
        }
    }
}
