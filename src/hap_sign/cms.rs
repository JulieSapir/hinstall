//! PKCS#7 / CMS `SignedData` 生成。
//!
//! 目标是与 Java BouncyCastle `CMSSignedDataGenerator` 产物**字节等价**。两个容易踩的细节：
//!
//! 1. **签名对象是 `signedAttrs` 的 SET OF（`0x31`）编码**，而文件里存的是 `[0]` IMPLICIT
//!    （`0xA0`）。校验方会把 `signedAttrs` 按 SET 重新编码后再验签，两者必须一致，
//!    否则签名永远验不过。
//! 2. `AlgorithmIdentifier` **不带 NULL 参数**（`digestAlgorithm` / `signatureAlgorithm`
//!    都不带），与部分实现默认加 NULL 的习惯不同。

use crate::hap_sign::crypto::{PrivateKey, SignAlg};
use crate::hap_sign::der::{self, Der, sort_set, tlv};
use crate::hap_sign::error::{Error, Result};
use crate::hap_sign::time;
use crate::hap_sign::x509::Certificate;

// ------------------------------------------------------------ OID

/// PKCS#7 `data`
pub const OID_DATA: &str = "1.2.840.113549.1.7.1";
/// PKCS#7 `signedData`
pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// 属性 `contentType`
pub const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
/// 属性 `messageDigest`
pub const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
/// 属性 `signingTime`
pub const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
/// 代码签名属性 ownerID
pub const OID_OWNER_ID: &str = "1.3.6.1.4.1.2011.2.376.1.4.1";
/// 代码签名属性 pluginID
pub const OID_PLUGIN_ID: &str = "1.3.6.1.4.1.2011.2.376.1.4.2";

// ------------------------------------------------------------ 参数

/// 一条签名属性。
#[derive(Clone, Debug)]
pub struct Attr {
    /// 属性 OID
    pub oid: String,
    /// 属性值的 DER 编码
    pub value: Vec<u8>,
}

impl Attr {
    /// 新建属性。
    pub fn new(oid: &str, value: Vec<u8>) -> Self {
        Self {
            oid: oid.to_string(),
            value,
        }
    }
}

/// `SignedData` 生成参数。
pub struct SignedDataInput<'a> {
    /// 被签名的内容
    pub content: &'a [u8],
    /// 证书链，**第一张必须是签名证书**（叶子）
    pub certs: &'a [Certificate],
    /// 签名私钥
    pub key: &'a PrivateKey,
    /// 签名算法
    pub alg: SignAlg,
    /// `true`：内容不嵌入（代码签名）；`false`：内容嵌入（HAP 签名）
    pub detached: bool,
    /// 附加签名属性
    pub extra_attrs: Vec<Attr>,
    /// 签名时间（Unix 秒）；`None` 取当前时间
    pub sign_time: Option<i64>,
}

// ------------------------------------------------------------ 生成

/// 生成 `ContentInfo { contentType=signedData, [0] SignedData }`。
pub fn signed_data(input: SignedDataInput<'_>) -> Result<Vec<u8>> {
    let leaf = input
        .certs
        .first()
        .ok_or(Error::Cms("签名需要至少一张证书"))?;

    let digest_alg = input.alg.digest_alg();
    let sign_time = match input.sign_time {
        Some(t) => t,
        None => time::now_unix(),
    };

    // ---- 签名属性：contentType / messageDigest / signingTime / 附加属性
    let msg_digest = digest_alg.digest(input.content);
    let mut attrs = vec![
        attr(OID_CONTENT_TYPE, &der::oid(OID_DATA)?),
        attr(OID_MESSAGE_DIGEST, &Der::new().octet(&msg_digest).bytes()),
        attr(
            OID_SIGNING_TIME,
            &Der::new()
                .utc_time(&time::utc_time_content(sign_time))
                .bytes(),
        ),
    ];
    for extra in &input.extra_attrs {
        attrs.push(attr(&extra.oid, &extra.value));
    }
    let attrs_body = sort_set(attrs);

    // 签名对象是 SET OF 的 DER 编码，文件里存的是 [0] IMPLICIT
    let to_sign = tlv(0x31, &attrs_body);
    let signature = input
        .key
        .sign_digest(&digest_alg.digest(&to_sign), input.alg)?;

    // ---- SignerInfo
    let digest_alg_id = Der::new().alg_id(digest_alg.oid(), false)?;
    let sign_alg_id = Der::new().alg_id(input.alg.oid(), false)?;
    let signer_info = Der::new()
        .seq(|d| {
            d.int_u64(1)
                .push(leaf.issuer_and_serial())
                .push(digest_alg_id.clone())
                .tagged(0xA0, &attrs_body)
                .push(sign_alg_id)
                .octet(&signature)
        })
        .bytes();

    // ---- EncapsulatedContentInfo
    let data_oid = der::oid(OID_DATA)?;
    let eci = if input.detached {
        Der::new().seq(|d| d.raw(&data_oid)).bytes()
    } else {
        let octet = Der::new().octet(input.content).bytes();
        Der::new().seq(|d| d.raw(&data_oid).ctx(0, &octet)).bytes()
    };

    // ---- 证书集合：[0] IMPLICIT SET OF Certificate，按 DER 编码排序
    let cert_set = sort_set(input.certs.iter().map(|c| c.der.clone()).collect());

    // ---- SignedData
    let signed_data = Der::new()
        .seq(|d| {
            d.int_u64(1)
                .set(|s| s.push(digest_alg_id))
                .raw(&eci)
                .ctx(0, &cert_set)
                .set(|s| s.raw(&signer_info))
        })
        .bytes();

    // ---- ContentInfo
    let signed_data_oid = der::oid(OID_SIGNED_DATA)?;
    Ok(Der::new()
        .seq(|d| d.raw(&signed_data_oid).ctx(0, &signed_data))
        .bytes())
}

/// 组装一条签名属性 `SEQUENCE { OID, SET { value } }`。
fn attr(oid: &str, value: &[u8]) -> Vec<u8> {
    let mut out = der::oid(oid).expect("OID 为编译期常量，不会非法");
    out.extend_from_slice(&Der::new().set(|s| s.raw(value)).bytes());
    tlv(0x30, &out)
}

/// 从 PKCS#7 `SignedData` 中取出 `encapContentInfo` 的内容（profile 的 JSON）。
pub fn extract_signed_content(der: &[u8]) -> Result<Vec<u8>> {
    let (ci, _) = der::read_expect(der, 0, 0x30).map_err(|_| Error::Cms("PKCS#7 不是 SEQUENCE"))?;
    let (_, p) = der::read(ci.content, 0)?;
    let (exp, _) = der::read_expect(ci.content, p, 0xA0)
        .map_err(|_| Error::Cms("ContentInfo 缺少 [0] EXPLICIT content"))?;
    let (sd, _) = der::read(exp.content, 0)?;
    let (_, q) = der::read(sd.content, 0)?; // version
    let (_, q) = der::read(sd.content, q)?; // digestAlgorithms
    let (eci, _) = der::read(sd.content, q)?; // encapContentInfo
    let (_, r) = der::read(eci.content, 0)?; // contentType
    let (exp2, _) = der::read(eci.content, r)?; // [0] EXPLICIT
    let (content, _) = der::read(exp2.content, 0)?;
    Ok(content.content.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hap_sign::crypto::{EcKey, PrivateKey};
    use crate::hap_sign::x509::tests::self_signed_cert;
    use p256::elliptic_curve::Generate;

    /// 用 P-256 密钥自签一张证书，跑完整 CMS 生成，并把关键结构解析回来校验。
    #[test]
    fn signed_data_structure() {
        let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut crate::util::os_rng());
        let cert = self_signed_cert(&sk, "CN=test");
        let key = PrivateKey::Ec(EcKey::P256(Box::new(sk)));

        let out = signed_data(SignedDataInput {
            content: b"hello hap",
            certs: std::slice::from_ref(&cert),
            key: &key,
            alg: SignAlg::EcdsaSha256,
            detached: false,
            extra_attrs: Vec::new(),
            sign_time: Some(0),
        })
        .unwrap();

        // ContentInfo
        let (ci, end) = der::read_expect(&out, 0, 0x30).unwrap();
        assert_eq!(end, out.len());
        let (oid, next) = der::read_expect(ci.content, 0, 0x06).unwrap();
        assert_eq!(
            crate::hap_sign::x509::decode_oid(oid.content).unwrap(),
            OID_SIGNED_DATA
        );
        let (explicit, _) = der::read_expect(ci.content, next, 0xA0).unwrap();
        let (sd, _) = der::read_expect(explicit.content, 0, 0x30).unwrap();

        // version / digestAlgorithms / encapContentInfo / certificates / signerInfos
        let (ver, p) = der::read_expect(sd.content, 0, 0x02).unwrap();
        assert_eq!(ver.content, [1]);
        let (digest_algs, p) = der::read_expect(sd.content, p, 0x31).unwrap();
        assert!(digest_algs.content.starts_with(&[0x30])); // SET OF AlgorithmIdentifier
        let (eci, p) = der::read_expect(sd.content, p, 0x30).unwrap();
        assert!(eci.content.starts_with(&der::oid(OID_DATA).unwrap()));
        let (certs, p) = der::read_expect(sd.content, p, 0xA0).unwrap();
        assert_eq!(certs.content, cert.der.as_slice());
        let (signer_infos, p) = der::read_expect(sd.content, p, 0x31).unwrap();
        assert_eq!(p, sd.content.len());

        // SignerInfo 里的 signedAttrs 必须是 [0] IMPLICIT 且含三条标准属性
        let (si, _) = der::read_expect(signer_infos.content, 0, 0x30).unwrap();
        let mut q = 0;
        let (_, n) = der::read_expect(si.content, q, 0x02).unwrap(); // version
        q = n;
        let (_, n) = der::read_expect(si.content, q, 0x30).unwrap(); // issuerAndSerial
        q = n;
        let (_, n) = der::read_expect(si.content, q, 0x30).unwrap(); // digestAlgorithm
        q = n;
        let (attrs, n) = der::read_expect(si.content, q, 0xA0).unwrap();
        q = n;
        let (_, n) = der::read_expect(si.content, q, 0x30).unwrap(); // signatureAlgorithm
        q = n;
        let (sig, n) = der::read_expect(si.content, q, 0x04).unwrap(); // signature
        assert_eq!(n, si.content.len());
        assert!(!sig.content.is_empty());

        let mut seen = Vec::new();
        let mut ap = 0;
        while ap < attrs.content.len() {
            let (a, n) = der::read_expect(attrs.content, ap, 0x30).unwrap();
            let (oid, _) = der::read_expect(a.content, 0, 0x06).unwrap();
            seen.push(crate::hap_sign::x509::decode_oid(oid.content).unwrap());
            ap = n;
        }
        // SET OF 按元素编码字节序排列，因此顺序是 1.9.3 / 1.9.5 / 1.9.4
        assert_eq!(
            seen,
            [OID_CONTENT_TYPE, OID_SIGNING_TIME, OID_MESSAGE_DIGEST]
        );
    }

    /// 签名必须能自验：对 `signedAttrs` 的 SET 编码做验签。
    #[test]
    fn signature_verifies_over_set_encoding() {
        let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut crate::util::os_rng());
        let cert = self_signed_cert(&sk, "CN=test");
        let key = PrivateKey::Ec(EcKey::P256(Box::new(sk.clone())));
        let content = b"payload";

        let out = signed_data(SignedDataInput {
            content,
            certs: std::slice::from_ref(&cert),
            key: &key,
            alg: SignAlg::EcdsaSha256,
            detached: true,
            extra_attrs: Vec::new(),
            sign_time: Some(1_700_000_000),
        })
        .unwrap();

        // 取出 signedAttrs 与签名，按 SET（0x31）重编码后验签
        let (ci, _) = der::read_expect(&out, 0, 0x30).unwrap();
        let (_, next) = der::read_expect(ci.content, 0, 0x06).unwrap();
        let (explicit, _) = der::read_expect(ci.content, next, 0xA0).unwrap();
        let (sd, _) = der::read_expect(explicit.content, 0, 0x30).unwrap();
        let (_, p) = der::read_expect(sd.content, 0, 0x02).unwrap();
        let (_, p) = der::read_expect(sd.content, p, 0x31).unwrap();
        let (_, p) = der::read_expect(sd.content, p, 0x30).unwrap();
        let (_, p) = der::read_expect(sd.content, p, 0xA0).unwrap();
        let (sis, _) = der::read_expect(sd.content, p, 0x31).unwrap();
        let (si, _) = der::read_expect(sis.content, 0, 0x30).unwrap();
        let mut q = 0;
        for tag in [0x02, 0x30, 0x30] {
            let (_, n) = der::read_expect(si.content, q, tag).unwrap();
            q = n;
        }
        let (attrs, n) = der::read_expect(si.content, q, 0xA0).unwrap();
        q = n;
        let (_, n) = der::read_expect(si.content, q, 0x30).unwrap();
        q = n;
        let (sig, _) = der::read_expect(si.content, q, 0x04).unwrap();

        // 用签名私钥对应的公钥复验：签名对象是 signedAttrs 的 SET 编码。
        use ecdsa::signature::hazmat::PrehashVerifier;
        let digest = SignAlg::EcdsaSha256
            .digest_alg()
            .digest(&tlv(0x31, attrs.content));
        let sig_der = ecdsa::Signature::<p256::NistP256>::from_der(sig.content).unwrap();
        sk.verifying_key()
            .verify_prehash(&digest, &sig_der)
            .unwrap();

        // messageDigest 属性必须等于内容摘要
        let expected = SignAlg::EcdsaSha256.digest_alg().digest(content);
        assert!(attrs.content.windows(expected.len()).any(|w| w == expected));
    }
}
