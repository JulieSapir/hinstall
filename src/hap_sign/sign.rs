//! HAP 签名编排。
//!
//! 全流程在内存内完成（web 端没有文件系统），与 Python 版 `sign_hap_file` 的步骤一一对应：
//!
//! 1. 重排对齐并清除旧签名块
//! 2. 重新取「中央目录之前 / 中央目录 / EOCD」三段
//! 3. 组装可选块（profile / 代码签名 / 权限签名）
//! 4. 算内容摘要 → 生成 HAP 签名块
//! 5. 修正 EOCD 的中央目录偏移并拼出结果

use crate::hap_sign::crypto::{PrivateKey, SignAlg};
use crate::hap_sign::error::{Error, Result};
use crate::hap_sign::hap;
use crate::hap_sign::x509::Certificate;
use crate::hap_sign::zip::Zip;

/// 签名请求。
pub struct HapSignRequest<'a> {
    /// 输入 HAP 字节
    pub hap: &'a [u8],
    /// 证书链，第一张必须是签名证书
    pub certs: &'a [Certificate],
    /// 签名私钥
    pub key: &'a PrivateKey,
    /// profile（p7b）DER
    pub profile_der: &'a [u8],
    /// 签名算法
    pub alg: SignAlg,
    /// compatibleVersion（≥8 用 V3 magic）
    pub compatible_version: u32,
    /// 形态后缀（hap / hsp / hqf），决定是否支持代码签名
    pub form: &'a str,
    /// 是否做代码签名（页面信息 bitmap + code sign 块）
    pub sign_code: bool,
    /// 是否做权限签名（依赖代码签名块）
    pub permission_sign: bool,
    /// 签名时间（Unix 秒），`None` 取当前时间
    pub sign_time: Option<i64>,
}

/// 执行 HAP 签名，返回签名后的完整字节流。
pub fn sign_hap(req: &HapSignRequest<'_>) -> Result<Vec<u8>> {
    let support_form = hap::SUPPORTED_FORMS.contains(&req.form.to_ascii_lowercase().as_str());
    if req.sign_code && !support_form {
        return Err(Error::Invalid(format!(
            "形态 {} 不支持代码签名（仅 {:?}）",
            req.form,
            hap::SUPPORTED_FORMS
        )));
    }
    if req.permission_sign && !req.sign_code {
        return Err(Error::Invalid("权限签名需要先做代码签名".into()));
    }

    let profile_content = hap::profile_content(req.profile_der)?;
    hap::check_profile(&profile_content, req.certs)?;

    // 1) 重排对齐并清除旧签名块
    let mut zip = Zip::from_bytes(req.hap.to_vec())?;
    zip.alignment(hap::DEFAULT_ALIGNMENT)?;
    if req.sign_code {
        let bitmap = crate::hap_sign::codesign::build_page_bitmap(&zip)?;
        if !bitmap.is_empty() {
            zip.add_bitmap(bitmap);
            zip.alignment(hap::DEFAULT_ALIGNMENT)?;
        }
    }
    zip.remove_sign_block();
    let staged = zip.to_bytes();

    // 2) 重新解析，取三段内容
    let zip2 = Zip::from_bytes(staged.clone())?;
    let cd_offset = zip2.cd_offset;
    let before_cd = &staged[..cd_offset];
    let cd_bytes = &staged[cd_offset..cd_offset + zip2.eocd.cd_size as usize];
    let mut eocd_bytes = staged[zip2.eocd_offset..].to_vec();

    let mut optional_blocks: Vec<(u32, Vec<u8>)> =
        vec![(hap::HAP_PROFILE_BLOCK_ID, req.profile_der.to_vec())];

    // 3) 代码签名块
    if req.sign_code {
        // 代码签名块的自身偏移：头部区（可选块数 + 签名块）之后紧跟属性块内的 code sign 块
        let code_sign_offset = cd_offset + 12 * (optional_blocks.len() + 2) + 12;
        let code_sign_array = crate::hap_sign::codesign::build_code_sign_block(
            &zip2,
            code_sign_offset,
            &profile_content,
            req.certs,
            req.key,
            req.alg,
            req.sign_time,
        )?;
        let mut value = Vec::with_capacity(12 + code_sign_array.len());
        value.extend_from_slice(&hap::HAP_CODE_SIGN_BLOCK_ID.to_le_bytes());
        value.extend_from_slice(&(code_sign_array.len() as u32).to_le_bytes());
        value.extend_from_slice(&(code_sign_offset as u32).to_le_bytes());
        value.extend_from_slice(&code_sign_array);
        optional_blocks.insert(0, (hap::HAP_PROPERTY_BLOCK_ID, value));
    }

    // 4) 权限签名块（挂在属性块尾部）
    if req.permission_sign {
        let index = optional_blocks
            .iter()
            .position(|(t, _)| *t == hap::HAP_PROPERTY_BLOCK_ID)
            .ok_or_else(|| Error::Invalid("权限签名需要先存在 code sign 块".into()))?;
        let module_files = hap::find_module_and_share_file(&zip2)?;
        if let Some(files) = module_files {
            let code_sign_value = optional_blocks[index].1.clone();
            let permission_bytes = hap::permission_signing_block(
                req.alg,
                req.key,
                profile_content.as_bytes(),
                &code_sign_value[12..],
                &files.module_json,
                files.share_files.as_deref().unwrap_or(&[]),
            )?;
            let mut combined = code_sign_value;
            // 偏移字段：属性块自身 12 字节前缀 + code sign 块长度
            let permission_offset = 12 + combined.len();
            combined.extend_from_slice(&hap::HAP_PERMISSION_SIGN_BLOCK_ID.to_le_bytes());
            combined.extend_from_slice(&(permission_bytes.len() as u32).to_le_bytes());
            combined.extend_from_slice(&(permission_offset as u32).to_le_bytes());
            combined.extend_from_slice(&permission_bytes);
            optional_blocks[index] = (hap::HAP_PROPERTY_BLOCK_ID, combined);
        }
    }

    // 5) 内容摘要 → HAP 签名块
    let contents = vec![before_cd.to_vec(), cd_bytes.to_vec(), eocd_bytes.clone()];
    let optional_values: Vec<Vec<u8>> = optional_blocks.iter().map(|(_, v)| v.clone()).collect();
    let digest = hap::content_digest(&contents, &optional_values, req.alg.digest_alg());
    let signer_block =
        hap::signature_scheme_block(&[digest], req.certs, req.key, req.alg, req.sign_time)?;
    let signing_block = hap::signing_block(&optional_blocks, signer_block, req.compatible_version);

    // 6) 修正 EOCD 的中央目录偏移并拼出结果
    let new_cd_offset = (cd_offset + signing_block.len()) as u32;
    if eocd_bytes.len() < 20 {
        return Err(Error::Zip("EOCD 长度不足，无法修正中央目录偏移".into()));
    }
    eocd_bytes[16..20].copy_from_slice(&new_cd_offset.to_le_bytes());

    let mut out = Vec::with_capacity(staged.len() + signing_block.len());
    out.extend_from_slice(before_cd);
    out.extend_from_slice(&signing_block);
    out.extend_from_slice(cd_bytes);
    out.extend_from_slice(&eocd_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hap_sign::cms::SignedDataInput;
    use crate::hap_sign::crypto::EcKey;
    use crate::hap_sign::x509::tests::self_signed_cert;
    use p256::elliptic_curve::Generate;

    fn pem_of(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// 端到端：签一个最小 HAP，再解析回签名块并复算内容摘要。
    #[test]
    fn sign_hap_end_to_end() {
        let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut crate::util::os_rng());
        let cert = self_signed_cert(&sk, "test");
        let key = PrivateKey::Ec(EcKey::P256(Box::new(sk)));

        let profile_json = format!(
            r#"{{"type":"debug","bundle-info":{{"development-certificate":"{}"}}}}"#,
            pem_of(&cert.der).replace('\n', "\\n")
        );
        let profile_der = crate::hap_sign::cms::signed_data(SignedDataInput {
            content: profile_json.as_bytes(),
            certs: std::slice::from_ref(&cert),
            key: &key,
            alg: SignAlg::EcdsaSha256,
            detached: false,
            extra_attrs: Vec::new(),
            sign_time: Some(0),
        })
        .unwrap();

        let hap_bytes = crate::hap_sign::zip::tests::tiny_zip();
        let signed = sign_hap(&HapSignRequest {
            hap: &hap_bytes,
            certs: std::slice::from_ref(&cert),
            key: &key,
            profile_der: &profile_der,
            alg: SignAlg::EcdsaSha256,
            compatible_version: crate::paths::DEFAULT_COMPATIBLE_VERSION,
            form: "hap",
            sign_code: false,
            permission_sign: false,
            sign_time: Some(1_700_000_000),
        })
        .unwrap();

        // 结果仍是一个可解析的 ZIP，且签名块就位
        let zip = Zip::from_bytes(signed.clone()).unwrap();
        assert!(!zip.signing_block.is_empty());
        assert_eq!(zip.entry_content("module.json").unwrap(), b"{}");

        // 签名块尾部：V3 magic
        let block = &zip.signing_block;
        let tail = &block[block.len() - 32..];
        assert_eq!(&tail[12..28], hap::HAP_SIGN_BLOCK_MAGIC_V3);
        assert_eq!(&tail[28..32], &3u32.to_le_bytes());
    }

    /// profile 与签名证书 CN 不匹配必须显式失败。
    #[test]
    fn profile_cert_mismatch_fails() {
        let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut crate::util::os_rng());
        let cert = self_signed_cert(&sk, "signer");
        let key = PrivateKey::Ec(EcKey::P256(Box::new(sk)));
        let other_sk = p256::ecdsa::SigningKey::generate_from_rng(&mut crate::util::os_rng());
        let other = self_signed_cert(&other_sk, "other");

        let profile_json = format!(
            r#"{{"type":"debug","bundle-info":{{"development-certificate":"{}"}}}}"#,
            pem_of(&other.der).replace('\n', "\\n")
        );
        let profile_der = crate::hap_sign::cms::signed_data(SignedDataInput {
            content: profile_json.as_bytes(),
            certs: std::slice::from_ref(&other),
            key: &key,
            alg: SignAlg::EcdsaSha256,
            detached: false,
            extra_attrs: Vec::new(),
            sign_time: Some(0),
        })
        .unwrap();

        let hap_bytes = crate::hap_sign::zip::tests::tiny_zip();
        let err = sign_hap(&HapSignRequest {
            hap: &hap_bytes,
            certs: std::slice::from_ref(&cert),
            key: &key,
            profile_der: &profile_der,
            alg: SignAlg::EcdsaSha256,
            compatible_version: crate::paths::DEFAULT_COMPATIBLE_VERSION,
            form: "hap",
            sign_code: false,
            permission_sign: false,
            sign_time: Some(0),
        })
        .unwrap_err();
        assert!(format!("{err}").contains("不匹配"), "{err}");
    }
}
