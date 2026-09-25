//! HAP 摘要与签名块组装。
//!
//! 与官方 `SignHap` / `ParamConstants` 对齐：
//!
//! - 内容摘要是**分块二级摘要**：一级把每个 1MB 块的二级摘要串起来，最后再拼上可选块内容。
//! - 签名块 = 头部区（每块 12 字节）+ 值区 + 尾部（块数 / 总长 / magic / 版本）。
//! - `magic` 与版本由 `compatibleVersion` 决定：≥8 用 V3，否则 V2。

use crate::hap_sign::cms::{self, SignedDataInput};
use crate::hap_sign::crypto::{DigestAlg, PrivateKey, SignAlg};
use crate::hap_sign::error::{Error, Result};
use crate::hap_sign::json::Json;
use crate::hap_sign::x509::Certificate;
use crate::hap_sign::zip::Zip;

// ------------------------------------------------------------ 常量

/// 签名方案块 ID
pub const HAP_SIGNATURE_SCHEME_V1_BLOCK_ID: u32 = 0x2000_0000;
/// profile 块 ID
pub const HAP_PROFILE_BLOCK_ID: u32 = 0x2000_0002;
/// 属性块 ID（承载代码签名与权限签名）
pub const HAP_PROPERTY_BLOCK_ID: u32 = 0x2000_0003;
/// 代码签名块 ID
pub const HAP_CODE_SIGN_BLOCK_ID: u32 = 0x3000_0001;
/// 权限签名块 ID
pub const HAP_PERMISSION_SIGN_BLOCK_ID: u32 = 0x3000_0002;

/// 签名块 magic（compatibleVersion < 8）
pub const HAP_SIGN_BLOCK_MAGIC_V2: &[u8; 16] = b"HAP Sig Block 42";
/// 签名块 magic（compatibleVersion >= 8）
pub const HAP_SIGN_BLOCK_MAGIC_V3: &[u8; 16] = b"<hap sign block>";

/// 内容摘要分块大小
pub const CONTENT_DIGESTED_CHUNK_MAX_SIZE: usize = 1024 * 1024;
/// 摘要对列表版本
pub const CONTENT_VERSION: u32 = 2;
/// 摘要对列表块号
pub const BLOCK_NUMBER: u32 = 1;
/// 默认对齐字节数
pub const DEFAULT_ALIGNMENT: u32 = 4;

/// 权限签名块 magic
pub const PERMISSION_BLOCK_MAGIC: u64 = 0x28E2_450F_9303_6A7D;
/// 权限签名内容类型：profile
pub const PERMISSION_TYPE_PROFILE: u32 = 0x01;
/// 权限签名内容类型：module.json
pub const PERMISSION_TYPE_MODULE_JSON: u32 = 0x02;
/// 权限签名内容类型：代码签名
pub const PERMISSION_TYPE_CODE_SIGN: u32 = 0x03;
/// 权限签名内容类型：shareFiles
pub const PERMISSION_TYPE_SHARE_FILES: u32 = 0x04;

/// 支持的 HAP 形态后缀
pub const SUPPORTED_FORMS: [&str; 3] = ["hap", "hsp", "hqf"];

// ------------------------------------------------------------ 内容摘要

/// HAP 内容摘要：分块二级摘要，末尾拼接可选块内容。
///
/// - 一级：`0x5A || u32(总块数) || 各块摘要`
/// - 每块：`sha(0xA5 || u32(块长) || 块数据)`
/// - 最终：`sha(一级内容 || 各可选块 value)`
pub fn content_digest(
    contents: &[Vec<u8>],
    optional_values: &[Vec<u8>],
    alg: DigestAlg,
) -> Vec<u8> {
    let chunk_count: usize = contents
        .iter()
        .map(|c| c.len().div_ceil(CONTENT_DIGESTED_CHUNK_MAX_SIZE))
        .sum();

    let mut top = alg.hasher();
    top.update(&[0x5A]);
    top.update(&(chunk_count as u32).to_le_bytes());
    for c in contents {
        for chunk in c.chunks(CONTENT_DIGESTED_CHUNK_MAX_SIZE) {
            let mut ch = alg.hasher();
            ch.update(&[0xA5]);
            ch.update(&(chunk.len() as u32).to_le_bytes());
            ch.update(chunk);
            top.update(&ch.finish());
        }
    }
    for v in optional_values {
        top.update(v);
    }
    top.finish()
}

/// 摘要对列表编码：`u32 版本 + u32 块号 + 各对 (u32 长度, u32 算法, u32 摘要长度, 摘要)`。
pub fn encode_list_of_pairs(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&CONTENT_VERSION.to_le_bytes());
    out.extend_from_slice(&BLOCK_NUMBER.to_le_bytes());
    for (alg_id, digest) in pairs {
        out.extend_from_slice(&((8 + digest.len()) as u32).to_le_bytes());
        out.extend_from_slice(&alg_id.to_le_bytes());
        out.extend_from_slice(&(digest.len() as u32).to_le_bytes());
        out.extend_from_slice(digest);
    }
    out
}

/// 生成 HAP 签名方案块（内容为摘要对编码的 CMS `SignedData`）。
pub fn signature_scheme_block(
    content_digests: &[Vec<u8>],
    certs: &[Certificate],
    key: &PrivateKey,
    alg: SignAlg,
    sign_time: Option<i64>,
) -> Result<Vec<u8>> {
    let pairs: Vec<(u32, Vec<u8>)> = content_digests
        .iter()
        .map(|d| (alg.block_id(), d.clone()))
        .collect();
    let unsigned = encode_list_of_pairs(&pairs);
    cms::signed_data(SignedDataInput {
        content: &unsigned,
        certs,
        key,
        alg,
        detached: false,
        extra_attrs: Vec::new(),
        sign_time,
    })
}

// ------------------------------------------------------------ 签名块

/// 组装完整 HAP 签名块：头部区 + 值区 + 尾部。
///
/// 头部每块 `[u32 type][u32 length][u32 offset]`，`offset` 相对值区起点；
/// 尾部 `[u32 块数][u64 总长][16B magic][u32 版本]`。
pub fn signing_block(
    optional_blocks: &[(u32, Vec<u8>)],
    signer_block: Vec<u8>,
    compatible_version: u32,
) -> Vec<u8> {
    let mut blocks: Vec<(u32, Vec<u8>)> = optional_blocks.to_vec();
    blocks.push((HAP_SIGNATURE_SCHEME_V1_BLOCK_ID, signer_block));

    let count = blocks.len();
    let block_size: usize = blocks.iter().map(|(_, v)| v.len()).sum();
    let result_size = 12 * count + block_size + 4 + 8 + 16 + 4;

    let mut headers = Vec::with_capacity(12 * count);
    let mut values = Vec::with_capacity(block_size);
    let mut offset = 12 * count;
    for (block_type, value) in &blocks {
        headers.extend_from_slice(&block_type.to_le_bytes());
        headers.extend_from_slice(&(value.len() as u32).to_le_bytes());
        headers.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += value.len();
        values.extend_from_slice(value);
    }

    let (magic, version): (&[u8; 16], u32) = if compatible_version >= 8 {
        (HAP_SIGN_BLOCK_MAGIC_V3, 3)
    } else {
        (HAP_SIGN_BLOCK_MAGIC_V2, 2)
    };

    let mut out = Vec::with_capacity(result_size);
    out.extend_from_slice(&headers);
    out.extend_from_slice(&values);
    out.extend_from_slice(&(count as u32).to_le_bytes());
    out.extend_from_slice(&(result_size as u64).to_le_bytes());
    out.extend_from_slice(magic);
    out.extend_from_slice(&version.to_le_bytes());
    out
}

// ------------------------------------------------------------ 权限签名块

/// 权限签名块：对非空内容分别摘要后整体做**原始签名**（非 CMS）。
pub fn permission_signing_block(
    alg: SignAlg,
    key: &PrivateKey,
    profile_content: &[u8],
    code_sign_bytes: &[u8],
    module_content: &[u8],
    share_files_content: &[u8],
) -> Result<Vec<u8>> {
    let digest_alg = alg.digest_alg();
    let items: Vec<(u32, Vec<u8>)> = [
        (PERMISSION_TYPE_PROFILE, profile_content),
        (PERMISSION_TYPE_MODULE_JSON, module_content),
        (PERMISSION_TYPE_CODE_SIGN, code_sign_bytes),
        (PERMISSION_TYPE_SHARE_FILES, share_files_content),
    ]
    .into_iter()
    .filter(|(_, c)| !c.is_empty())
    .map(|(t, c)| (t, digest_alg.digest(c)))
    .collect();

    let mut body = Vec::new();
    for (t, d) in &items {
        body.extend_from_slice(&t.to_le_bytes());
        body.extend_from_slice(d);
    }

    let mut unsign = Vec::new();
    unsign.extend_from_slice(&PERMISSION_BLOCK_MAGIC.to_le_bytes());
    unsign.extend_from_slice(&alg.block_id().to_le_bytes());
    unsign.extend_from_slice(&(body.len() as u32).to_le_bytes());
    unsign.extend_from_slice(&(items.len() as u16).to_le_bytes());
    unsign.extend_from_slice(&body);

    let signature = key.sign(&unsign, alg)?;
    unsign.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    unsign.extend_from_slice(&signature);
    Ok(unsign)
}

// ------------------------------------------------------------ HAP 内部查询

/// HAP 内部与签名相关的内容。
#[derive(Clone, Debug)]
pub struct ModuleFiles {
    /// `module.json` 内容
    pub module_json: Vec<u8>,
    /// shareFiles 指向的 profile 内容（无则为 `None`，有引用但文件缺失为空 `Vec`）
    pub share_files: Option<Vec<u8>>,
}

/// 定位 `module.json` 与 shareFiles 内容（与 `HapUtils` 一致）。
///
/// 没有 `module.json` 时返回 `None`。
pub fn find_module_and_share_file(zip: &Zip) -> Result<Option<ModuleFiles>> {
    if zip.find_entry("module.json").is_none() {
        return Ok(None);
    }
    let module_content = zip.entry_content("module.json")?;
    if module_content.is_empty() {
        return Err(Error::Zip("module.json 内容为空".into()));
    }
    let text = std::str::from_utf8(&module_content)
        .map_err(|e| Error::Invalid(format!("module.json 不是 UTF-8: {e}")))?;
    let obj =
        Json::parse(text).map_err(|e| Error::Invalid(format!("module.json 不是合法 JSON: {e}")))?;
    let Some(module) = obj.get("module") else {
        return Ok(Some(ModuleFiles {
            module_json: module_content,
            share_files: None,
        }));
    };
    if module.as_obj().is_none() {
        return Ok(Some(ModuleFiles {
            module_json: module_content,
            share_files: None,
        }));
    }
    let Some(share_files) = module.get("shareFiles") else {
        return Ok(Some(ModuleFiles {
            module_json: module_content,
            share_files: None,
        }));
    };
    let Some(name) = share_files.as_str() else {
        return Ok(Some(ModuleFiles {
            module_json: module_content,
            share_files: None,
        }));
    };
    let Some(profile_name) = name.strip_prefix("$profile:") else {
        return Ok(Some(ModuleFiles {
            module_json: module_content,
            share_files: Some(Vec::new()),
        }));
    };

    let full_name = format!("resources/base/profile/{profile_name}");
    let prefix = format!("{full_name}.");
    let target = zip
        .entries
        .iter()
        .map(|e| e.name())
        .find(|n| *n == full_name || n.starts_with(&prefix));
    let share_files = match target {
        Some(t) => Some(zip.entry_content(&t)?),
        None => Some(Vec::new()),
    };
    Ok(Some(ModuleFiles {
        module_json: module_content,
        share_files,
    }))
}

/// 校验 profile 与签名证书的匹配关系（与 `checkProfileInfo` 一致）。
pub fn check_profile(profile_content: &str, certs: &[Certificate]) -> Result<()> {
    let obj = Json::parse(profile_content)
        .map_err(|e| Error::Invalid(format!("profile 不是合法 JSON: {e}")))?;
    let profile_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| Error::Invalid("profile 缺少 type".into()))?;
    let cert_key = match profile_type {
        "release" => "distribution-certificate",
        "debug" => "development-certificate",
        other => {
            return Err(Error::Invalid(format!("不支持的 profile type: {other}")));
        }
    };
    let pem = obj
        .get("bundle-info")
        .and_then(|b| b.get(cert_key))
        .and_then(|c| c.as_str())
        .ok_or_else(|| Error::Invalid(format!("profile 缺少 bundle-info.{cert_key}")))?;

    let profile_certs = crate::hap_sign::x509::parse_certificates(pem.as_bytes())?;
    let profile_cert = profile_certs
        .first()
        .ok_or_else(|| Error::Invalid("profile 中的证书为空".into()))?;
    if profile_cert.subject_cn.is_empty() {
        return Err(Error::Invalid("profile 中的证书缺少 CN".into()));
    }
    let sign_cn = certs
        .first()
        .map(|c| c.subject_cn.as_str())
        .unwrap_or_default();
    if profile_cert.subject_cn != sign_cn {
        return Err(Error::Invalid(format!(
            "profile 证书与签名证书不匹配: profile CN={} 签名 CN={sign_cn}",
            profile_cert.subject_cn
        )));
    }
    Ok(())
}

/// 取出 profile 的 JSON 内容（从 p7b 中解出）。
pub fn profile_content(profile_der: &[u8]) -> Result<String> {
    let bytes = cms::extract_signed_content(profile_der)?;
    String::from_utf8(bytes).map_err(|e| Error::Invalid(format!("profile 不是 UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_chunking() {
        // 空内容：块数 0
        let d = content_digest(&[Vec::new()], &[], DigestAlg::Sha256);
        let mut h = DigestAlg::Sha256.hasher();
        h.update(&[0x5A]);
        h.update(&0u32.to_le_bytes());
        assert_eq!(d, h.finish());

        // 跨块：2MB + 1 字节 → 3 块
        let big = vec![0u8; 2 * 1024 * 1024 + 1];
        let d = content_digest(&[big], &[], DigestAlg::Sha256);
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn list_of_pairs_layout() {
        let pairs = vec![(0x201u32, vec![0xAAu8; 32])];
        let out = encode_list_of_pairs(&pairs);
        assert_eq!(&out[0..4], &2u32.to_le_bytes());
        assert_eq!(&out[4..8], &1u32.to_le_bytes());
        assert_eq!(&out[8..12], &40u32.to_le_bytes()); // 8 + 32
        assert_eq!(&out[12..16], &0x201u32.to_le_bytes());
        assert_eq!(&out[16..20], &32u32.to_le_bytes());
        assert_eq!(out.len(), 20 + 32);
    }

    #[test]
    fn signing_block_layout() {
        let optional = vec![(HAP_PROFILE_BLOCK_ID, vec![1u8, 2, 3])];
        let out = signing_block(&optional, vec![9u8; 5], 9);
        // 头部：2 块 × 12 字节
        assert_eq!(&out[0..4], &HAP_PROFILE_BLOCK_ID.to_le_bytes());
        assert_eq!(&out[4..8], &3u32.to_le_bytes());
        assert_eq!(&out[8..12], &24u32.to_le_bytes()); // 值区起点
        assert_eq!(
            &out[12..16],
            &HAP_SIGNATURE_SCHEME_V1_BLOCK_ID.to_le_bytes()
        );
        assert_eq!(&out[16..20], &5u32.to_le_bytes());
        assert_eq!(&out[20..24], &27u32.to_le_bytes());
        // 值区
        assert_eq!(&out[24..27], &[1, 2, 3]);
        assert_eq!(&out[27..32], &[9u8; 5]);
        // 尾部
        let tail = &out[32..];
        assert_eq!(&tail[0..4], &2u32.to_le_bytes());
        assert_eq!(&tail[4..12], &(out.len() as u64).to_le_bytes());
        assert_eq!(&tail[12..28], HAP_SIGN_BLOCK_MAGIC_V3);
        assert_eq!(&tail[28..32], &3u32.to_le_bytes());
        assert_eq!(out.len(), 12 * 2 + 8 + 4 + 8 + 16 + 4);
    }
}
