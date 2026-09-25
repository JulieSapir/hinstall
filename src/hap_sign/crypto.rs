//! 密码学层：私钥加载、签名、验签。
//!
//! 纯 Rust 实现，不调用 `openssl` 等外部进程——这样目标机上不需要额外装 openssl。

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::hap_sign::der::{self, Der};
use crate::hap_sign::error::{Error, Result, crypto};
use crate::hap_sign::x509::{
    OID_CURVE_P256, OID_CURVE_P384, OID_CURVE_P521, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION,
    pem_blocks,
};

// ============================================================ 摘要算法

/// 内容摘要算法。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestAlg {
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl DigestAlg {
    /// 摘要算法 OID。
    pub fn oid(self) -> &'static str {
        match self {
            DigestAlg::Sha256 => "2.16.840.1.101.3.4.2.1",
            DigestAlg::Sha384 => "2.16.840.1.101.3.4.2.2",
            DigestAlg::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    /// 摘要输出长度（字节）。
    pub fn output_len(self) -> usize {
        match self {
            DigestAlg::Sha256 => 32,
            DigestAlg::Sha384 => 48,
            DigestAlg::Sha512 => 64,
        }
    }

    /// 一次性摘要。
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlg::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlg::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlg::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// 创建增量摘要器。
    pub fn hasher(self) -> Hasher {
        match self {
            DigestAlg::Sha256 => Hasher::S256(Sha256::new()),
            DigestAlg::Sha384 => Hasher::S384(Sha384::new()),
            DigestAlg::Sha512 => Hasher::S512(Sha512::new()),
        }
    }
}

/// 增量摘要器。
#[derive(Clone)]
pub enum Hasher {
    /// SHA-256
    S256(Sha256),
    /// SHA-384
    S384(Sha384),
    /// SHA-512
    S512(Sha512),
}

impl Hasher {
    /// 追加数据。
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::S256(h) => h.update(data),
            Hasher::S384(h) => h.update(data),
            Hasher::S512(h) => h.update(data),
        }
    }

    /// 结束并取出摘要。
    pub fn finish(self) -> Vec<u8> {
        match self {
            Hasher::S256(h) => h.finalize().to_vec(),
            Hasher::S384(h) => h.finalize().to_vec(),
            Hasher::S512(h) => h.finalize().to_vec(),
        }
    }
}

// ============================================================ 签名算法

/// HAP 支持的签名算法（对应 `SIGN_ALG_TABLE`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignAlg {
    /// SHA256withECDSA
    EcdsaSha256,
    /// SHA384withECDSA
    EcdsaSha384,
    /// SHA512withECDSA
    EcdsaSha512,
    /// SHA256withRSA
    RsaSha256,
}

impl SignAlg {
    /// 全部支持的算法。
    pub const ALL: [SignAlg; 4] = [
        SignAlg::EcdsaSha256,
        SignAlg::EcdsaSha384,
        SignAlg::EcdsaSha512,
        SignAlg::RsaSha256,
    ];

    /// 按 JCA 名称解析。
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "SHA256withECDSA" => Ok(SignAlg::EcdsaSha256),
            "SHA384withECDSA" => Ok(SignAlg::EcdsaSha384),
            "SHA512withECDSA" => Ok(SignAlg::EcdsaSha512),
            "SHA256withRSA" => Ok(SignAlg::RsaSha256),
            _ => Err(Error::Invalid(format!(
                "不支持的签名算法: {name}（支持 {}）",
                SignAlg::ALL
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// JCA 名称。
    pub fn name(self) -> &'static str {
        match self {
            SignAlg::EcdsaSha256 => "SHA256withECDSA",
            SignAlg::EcdsaSha384 => "SHA384withECDSA",
            SignAlg::EcdsaSha512 => "SHA512withECDSA",
            SignAlg::RsaSha256 => "SHA256withRSA",
        }
    }

    /// 使用的摘要算法。
    pub fn digest_alg(self) -> DigestAlg {
        match self {
            SignAlg::EcdsaSha256 | SignAlg::RsaSha256 => DigestAlg::Sha256,
            SignAlg::EcdsaSha384 => DigestAlg::Sha384,
            SignAlg::EcdsaSha512 => DigestAlg::Sha512,
        }
    }

    /// 签名算法 OID。
    pub fn oid(self) -> &'static str {
        match self {
            SignAlg::EcdsaSha256 => "1.2.840.10045.4.3.2",
            SignAlg::EcdsaSha384 => "1.2.840.10045.4.3.3",
            SignAlg::EcdsaSha512 => "1.2.840.10045.4.3.4",
            SignAlg::RsaSha256 => "1.2.840.113549.1.1.11",
        }
    }

    /// 签名算法块 ID（写入 SignInfo）。
    pub fn block_id(self) -> u32 {
        match self {
            SignAlg::EcdsaSha256 => 0x201,
            SignAlg::EcdsaSha384 => 0x202,
            SignAlg::EcdsaSha512 => 0x203,
            SignAlg::RsaSha256 => 0x104,
        }
    }

    /// 是否为 ECDSA 族。
    pub fn is_ecdsa(self) -> bool {
        !matches!(self, SignAlg::RsaSha256)
    }
}

// ============================================================ 私钥

/// 椭圆曲线私钥。
///
/// 只支持 P-256 / P-384：`p521` 0.13 没有实现 `PrehashSigner`，无法做确定性（RFC6979）
/// 摘要签名，而 HAP 签名实际只用 P-256，所以不支持 P-521 并显式报错。
#[derive(Clone)]
pub enum EcKey {
    /// NIST P-256
    P256(Box<p256::ecdsa::SigningKey>),
    /// NIST P-384
    P384(Box<p384::ecdsa::SigningKey>),
}

impl EcKey {
    /// 对已算好的摘要签名，输出 DER 编码的 `SEQUENCE { r, s }`。
    pub fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        match self {
            EcKey::P256(k) => p256_sign(k, digest),
            EcKey::P384(k) => p384_sign(k, digest),
        }
    }
}

/// 为三条曲线展开签名 / 验签实现。
///
/// 用宏而不是泛型：ecdsa 0.16 的 trait 约束组合繁琐且容易写错，展开后每条曲线都是具体类型。
macro_rules! ec_impl {
    ($sign_fn:ident, $curve:ty, $field:expr) => {
        /// 对显式摘要做 ECDSA 签名（RFC6979 确定性随机数，无需 RNG）。
        fn $sign_fn(key: &ecdsa::SigningKey<$curve>, digest: &[u8]) -> Result<Vec<u8>> {
            use ecdsa::signature::hazmat::PrehashSigner;
            let sig: ecdsa::Signature<$curve> = key
                .sign_prehash(digest)
                .map_err(|e| crypto(format!("ECDSA 签名失败: {e}")))?;
            let bytes = sig.to_bytes();
            Ok(Der::new()
                .seq(|d| d.int_be(&bytes[..$field]).int_be(&bytes[$field..]))
                .bytes())
        }
    };
}

ec_impl!(p256_sign, p256::NistP256, 32);
ec_impl!(p384_sign, p384::NistP384, 48);

/// 私钥。
#[derive(Clone)]
pub enum PrivateKey {
    /// 椭圆曲线私钥。
    Ec(EcKey),
    /// RSA 私钥。
    Rsa(Box<rsa::RsaPrivateKey>),
}

impl PrivateKey {
    /// 从 PEM 文本加载私钥。
    ///
    /// 支持 PKCS#8（`PRIVATE KEY`）、SEC1（`EC PRIVATE KEY`）、PKCS#1（`RSA PRIVATE KEY`）。
    pub fn from_pem(data: &[u8]) -> Result<Self> {
        let blocks = pem_blocks(data)?;
        for (label, der) in &blocks {
            match label.as_str() {
                "PRIVATE KEY" => return Self::from_pkcs8(der),
                "EC PRIVATE KEY" => return Self::from_sec1(der),
                "RSA PRIVATE KEY" => return Self::from_pkcs1(der),
                _ => continue,
            }
        }
        Err(Error::Invalid(
            "PEM 中找不到私钥块（PRIVATE KEY / EC PRIVATE KEY / RSA PRIVATE KEY）".into(),
        ))
    }

    /// 解析 PKCS#8 `PrivateKeyInfo`。
    fn from_pkcs8(der: &[u8]) -> Result<Self> {
        let (info, _) = der::read_expect(der, 0, 0x30)?;
        let mut p = 0;
        let (_, next) = der::read(info.content, p)?; // version
        p = next;
        let (alg, next) = der::read_expect(info.content, p, 0x30)?;
        p = next;
        let (key_octets, _) = der::read_expect(info.content, p, 0x04)?;

        let (alg_oid_tlv, rest) = der::read_expect(alg.content, 0, 0x06)?;
        let alg_oid = crate::hap_sign::x509::decode_oid(alg_oid_tlv.content)?;
        let params = if rest < alg.content.len() {
            let (t, _) = der::read(alg.content, rest)?;
            Some(t)
        } else {
            None
        };

        match alg_oid.as_str() {
            OID_EC_PUBLIC_KEY => {
                let curve = params
                    .and_then(|t| {
                        (t.tag == 0x06).then(|| crate::hap_sign::x509::decode_oid(t.content))
                    })
                    .transpose()?
                    .ok_or_else(|| Error::Invalid("PKCS#8 EC 私钥缺少曲线参数".into()))?;
                Self::from_sec1_with_curve(key_octets.content, &curve)
            }
            OID_RSA_ENCRYPTION => Self::from_pkcs1(key_octets.content),
            other => Err(Error::Invalid(format!("不支持的私钥算法 OID: {other}"))),
        }
    }

    /// 解析 SEC1 `ECPrivateKey`（曲线参数从内部 `[0]` 取）。
    fn from_sec1(der: &[u8]) -> Result<Self> {
        Self::from_sec1_with_curve(der, "")
    }

    fn from_sec1_with_curve(der: &[u8], curve_hint: &str) -> Result<Self> {
        let (seq, _) = der::read_expect(der, 0, 0x30)?;
        let mut p = 0;
        let (_, next) = der::read(seq.content, p)?; // version
        p = next;
        let (scalar, next) = der::read_expect(seq.content, p, 0x04)?;
        p = next;
        // 可选 [0] parameters（后面的 [1] publicKey 用不上，不解析）
        let mut curve = curve_hint.to_string();
        if p < seq.content.len() {
            let (t, _) = der::read(seq.content, p)?;
            if t.tag == 0xA0 {
                let (inner, _) = der::read(t.content, 0)?;
                if inner.tag == 0x06 {
                    curve = crate::hap_sign::x509::decode_oid(inner.content)?;
                }
            }
        }
        if curve.is_empty() {
            return Err(Error::Invalid("EC 私钥缺少曲线信息".into()));
        }
        match curve.as_str() {
            OID_CURVE_P256 => Ok(PrivateKey::Ec(EcKey::P256(Box::new(
                p256::ecdsa::SigningKey::from_slice(scalar.content)
                    .map_err(|e| crypto(format!("P-256 私钥非法: {e}")))?,
            )))),
            OID_CURVE_P384 => Ok(PrivateKey::Ec(EcKey::P384(Box::new(
                p384::ecdsa::SigningKey::from_slice(scalar.content)
                    .map_err(|e| crypto(format!("P-384 私钥非法: {e}")))?,
            )))),
            OID_CURVE_P521 => Err(Error::Invalid(
                "不支持 P-521 曲线：请改用 P-256 / P-384 或 RSA 密钥".into(),
            )),
            other => Err(Error::Invalid(format!("不支持的椭圆曲线: {other}"))),
        }
    }

    /// 解析 PKCS#1 `RSAPrivateKey`。
    fn from_pkcs1(der: &[u8]) -> Result<Self> {
        let (seq, _) = der::read_expect(der, 0, 0x30)?;
        let mut ints = Vec::new();
        for item in der::iter(seq.content) {
            let t = item?;
            if t.tag != 0x02 {
                break;
            }
            ints.push(t.content.to_vec());
        }
        if ints.len() < 9 {
            return Err(Error::Invalid(format!(
                "RSA 私钥字段不足: {} 个（需要 9 个）",
                ints.len()
            )));
        }
        let big = |i: usize| rsa::BigUint::from_bytes_be(&ints[i]);
        let key = rsa::RsaPrivateKey::from_components(big(1), big(2), big(3), vec![big(4), big(5)])
            .map_err(|e| crypto(format!("RSA 私钥非法: {e}")))?;
        Ok(PrivateKey::Rsa(Box::new(key)))
    }

    /// 对数据签名（内部按算法选摘要）。
    pub fn sign(&self, data: &[u8], alg: SignAlg) -> Result<Vec<u8>> {
        let digest = alg.digest_alg().digest(data);
        self.sign_digest(&digest, alg)
    }

    /// 对已算好的摘要签名。
    pub fn sign_digest(&self, digest: &[u8], alg: SignAlg) -> Result<Vec<u8>> {
        if digest.len() != alg.digest_alg().output_len() {
            return Err(crypto(format!(
                "摘要长度 {} 与算法 {} 不符（期望 {}）",
                digest.len(),
                alg.name(),
                alg.digest_alg().output_len()
            )));
        }
        match (self, alg) {
            (PrivateKey::Ec(k), a) if a.is_ecdsa() => k.sign_digest(digest),
            (PrivateKey::Rsa(k), SignAlg::RsaSha256) => k
                .sign(rsa::Pkcs1v15Sign::new::<sha2_10::Sha256>(), digest)
                .map_err(|e| crypto(format!("RSA 签名失败: {e}"))),
            (PrivateKey::Ec(_), a) => Err(Error::Invalid(format!(
                "算法 {} 需要 RSA 私钥，当前为 EC",
                a.name()
            ))),
            (PrivateKey::Rsa(_), a) => Err(Error::Invalid(format!(
                "算法 {} 需要 EC 私钥，当前为 RSA",
                a.name()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_lengths() {
        assert_eq!(DigestAlg::Sha256.digest(b"abc").len(), 32);
        assert_eq!(DigestAlg::Sha384.digest(b"abc").len(), 48);
        assert_eq!(DigestAlg::Sha512.digest(b"abc").len(), 64);
    }

    #[test]
    fn sha256_known_vector() {
        // NIST 向量：SHA-256("abc")
        assert_eq!(
            DigestAlg::Sha256.digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn sign_alg_table() {
        assert_eq!(
            SignAlg::from_name("SHA256withECDSA").unwrap().block_id(),
            0x201
        );
        assert_eq!(
            SignAlg::from_name("SHA384withECDSA").unwrap().block_id(),
            0x202
        );
        assert_eq!(
            SignAlg::from_name("SHA512withECDSA").unwrap().block_id(),
            0x203
        );
        assert_eq!(
            SignAlg::from_name("SHA256withRSA").unwrap().block_id(),
            0x104
        );
        assert!(SignAlg::from_name("MD5withRSA").is_err());
    }

    /// 曲线不匹配的算法必须显式报错，不能静默产出坏签名。
    #[test]
    fn alg_key_mismatch() {
        use p256::elliptic_curve::Generate;
        let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut crate::util::os_rng());
        let key = PrivateKey::Ec(EcKey::P256(Box::new(sk)));
        assert!(key.sign(b"x", SignAlg::RsaSha256).is_err());
    }

    /// RSA 私钥 PEM 解析 + 签名。
    #[test]
    fn rsa_sign_from_pkcs1() {
        use rand_core06::OsRng;
        // 1024 位仅用于单测，不用于生产
        let sk = rsa::RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let pkcs1 = rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&sk).unwrap();
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            base64_encode(pkcs1.as_bytes())
        );
        let key = PrivateKey::from_pem(pem.as_bytes()).unwrap();
        let sig = key.sign(b"rsa roundtrip", SignAlg::RsaSha256).unwrap();
        assert!(!sig.is_empty());
    }

    fn base64_encode(data: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(data)
    }
}
