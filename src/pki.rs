//! 本地生成 EC 密钥与 CSR。
//!
//! `tool.py` 这一段是 fork 出 `openssl ecparam` / `openssl req` 完成的；移植后
//! 改为纯 Rust 实现，产物 DER 结构与 `openssl` 一致（私钥不出本机）。
//!
//! 生成的 PEM 分别等价于：
//!
//! ```text
//! openssl ecparam -name prime256v1 -genkey -noout -out data/hinstall.key
//! openssl req -new -key data/hinstall.key \
//!     -subj "/C=CN/O=Personal/OU=Individual Developer/CN=quantum-debug" \
//!     -out data/hinstall.csr
//! ```

use std::path::Path;

use base64::Engine as _;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::Generate;

use crate::fail::R;
use crate::hap_sign::der;
use crate::paths;
use crate::util;

/// 曲线 OID：prime256v1（= secp256r1 = P-256）。
const OID_CURVE_P256: &str = "1.2.840.10045.3.1.7";
/// 公钥算法 OID：id-ecPublicKey。
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// 签名算法 OID：ecdsa-with-SHA256。
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// 证书主体 CN，与 `tool.py` 的 `-subj` 保持一致。
const SUBJECT_CN: &str = "quantum-debug";

/// 首次运行时本地生成 EC 密钥与 CSR（私钥不出本机）。
pub fn ensure_materials() -> R<()> {
    if paths::key_file().exists() && paths::csr_file().exists() {
        return Ok(());
    }
    let key = SigningKey::generate_from_rng(&mut util::os_rng());
    write_private_key(&key, &paths::key_file())?;
    write_csr(&key, &paths::csr_file())?;
    println!("已本地生成密钥与 CSR（私钥不出本机）");
    Ok(())
}

/// 写出 SEC1 `ECPrivateKey`（`EC PRIVATE KEY` PEM，权限 0600）。
fn write_private_key(key: &SigningKey, path: &Path) -> R<()> {
    let secret = key.to_bytes();
    let public = key.verifying_key().to_sec1_point(false);
    let curve = der::oid(OID_CURVE_P256)?;
    let der_bytes = der::Der::new()
        .seq(|d| {
            d.int_u64(1)
                .octet(&secret[..])
                .tagged(0xa0, &curve)
                // SEC1 `publicKey [1] BIT STRING`：模块是 EXPLICIT TAGS，
                // [1] 内必须再套一层 BIT STRING，openssl 才认（`a1 44 03 42 00 04 …`）。
                .tagged(0xa1, &der::tlv(0x03, &bit_string(public.as_bytes())))
        })
        .bytes();
    write_pem(path, "EC PRIVATE KEY", &der_bytes)?;
    util::set_mode_600(path)
}

/// 写出 PKCS#10 `CertificationRequest`（`CERTIFICATE REQUEST` PEM）。
fn write_csr(key: &SigningKey, path: &Path) -> R<()> {
    let cri = certification_request_info(key)?;
    let signature: p256::ecdsa::Signature = key.sign(&cri);
    let sig_oid = der::oid(OID_ECDSA_SHA256)?;
    let alg = der::Der::new().seq(|d| d.raw(&sig_oid)).bytes();
    let csr = der::Der::new()
        .seq(|d| {
            d.raw(&cri)
                .raw(&alg)
                .raw(&der::tlv(0x03, &bit_string(signature.to_der().as_bytes())))
        })
        .bytes();
    write_pem(path, "CERTIFICATE REQUEST", &csr)
}

/// 构造 `CertificationRequestInfo`，其 DER 编码就是被签名的内容。
fn certification_request_info(key: &SigningKey) -> R<Vec<u8>> {
    let oid_c = der::oid("2.5.4.6")?;
    let oid_o = der::oid("2.5.4.10")?;
    let oid_ou = der::oid("2.5.4.11")?;
    let oid_cn = der::oid("2.5.4.3")?;
    let curve = der::oid(OID_CURVE_P256)?;
    let ec_public_key = der::oid(OID_EC_PUBLIC_KEY)?;

    // 主体：/C=CN/O=Personal/OU=Individual Developer/CN=quantum-debug
    // openssl 对纯 ASCII 值一律用 PrintableString(0x13)，这里对齐。
    let subject = der::Der::new()
        .seq(|d| {
            d.set(|d| d.seq(|d| d.raw(&oid_c).tagged(0x13, b"CN")))
                .set(|d| d.seq(|d| d.raw(&oid_o).tagged(0x13, b"Personal")))
                .set(|d| d.seq(|d| d.raw(&oid_ou).tagged(0x13, b"Individual Developer")))
                .set(|d| d.seq(|d| d.raw(&oid_cn).tagged(0x13, SUBJECT_CN.as_bytes())))
        })
        .bytes();

    let public = key.verifying_key().to_sec1_point(false);
    let spki = der::Der::new()
        .seq(|d| {
            d.seq(|d| d.raw(&ec_public_key).raw(&curve))
                .raw(&der::tlv(0x03, &bit_string(public.as_bytes())))
        })
        .bytes();

    // attributes 为空，显式标签 [0] 长度 0（openssl 同样输出 `a0 00`）。
    Ok(der::Der::new()
        .seq(|d| d.int_u64(0).raw(&subject).raw(&spki).tagged(0xa0, &[]))
        .bytes())
}

/// 给 BIT STRING 内容补上「未使用位数」字节（恒为 0）。
fn bit_string(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.push(0u8);
    out.extend_from_slice(payload);
    out
}

/// 写 PEM：Base64 每行 64 字符，行尾 LF。
fn write_pem(path: &Path, label: &str, der_bytes: &[u8]) -> R<()> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der_bytes);
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 64);
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("Base64 一定是 ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    util::write(path, out.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use p256::elliptic_curve::Generate;
    use sha2::{Digest, Sha256};

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hinstall-pki-{}-{name}", std::process::id()))
    }

    /// 取出 PEM 的 Base64 正文并解码。
    fn pem_body(pem: &str) -> Vec<u8> {
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("PEM 正文是 Base64")
    }

    /// 新随机源生成的密钥：SEC1 私钥必须能解回同一标量，公钥必须是未压缩 SEC1 点。
    #[test]
    fn sec1_私钥与公钥编码() {
        let key = SigningKey::generate_from_rng(&mut util::os_rng());
        let path = tmp("key.pem");
        write_private_key(&key, &path).unwrap();
        let pem = std::fs::read_to_string(&path).unwrap();
        assert!(pem.starts_with("-----BEGIN EC PRIVATE KEY-----\n"), "{pem}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "私钥必须是 0600");
        }

        let der_bytes = pem_body(&pem);
        let (outer, _) = der::read_expect(&der_bytes, 0, 0x30).unwrap();
        let (ver, p) = der::read_expect(outer.content, 0, 0x02).unwrap();
        assert_eq!(ver.content, &[1], "SEC1 version");
        let (scalar, p) = der::read_expect(outer.content, p, 0x04).unwrap();
        assert_eq!(scalar.content, &key.to_bytes()[..], "私钥标量");
        let (curve, p) = der::read_expect(outer.content, p, 0xa0).unwrap();
        assert_eq!(curve.content, der::oid(OID_CURVE_P256).unwrap().as_slice());
        let (tagged, _) = der::read_expect(outer.content, p, 0xa1).unwrap();
        // EXPLICIT TAGS：[1] 内必须再套一层 BIT STRING（openssl 同样输出）
        let (bits, _) = der::read_expect(tagged.content, 0, 0x03).unwrap();
        assert_eq!(bits.content[0], 0, "BIT STRING 未使用位数为 0");
        let point = &bits.content[1..];
        assert_eq!(point.len(), 65, "未压缩 P-256 点 1+32+32");
        assert_eq!(point[0], 0x04, "未压缩点前缀");
        assert_eq!(point, key.verifying_key().to_sec1_point(false).as_bytes());
        let _ = std::fs::remove_file(&path);
    }

    /// CSR：被签名的内容就是 CRI 的完整 DER，签名必须能被自己的公钥验过。
    #[test]
    fn csr_结构与签名自验() {
        let key = SigningKey::generate_from_rng(&mut util::os_rng());
        let path = tmp("csr.pem");
        write_csr(&key, &path).unwrap();
        let pem = std::fs::read_to_string(&path).unwrap();
        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"),
            "{pem}"
        );

        let der_bytes = pem_body(&pem);
        let (outer, _) = der::read_expect(&der_bytes, 0, 0x30).unwrap();
        let (cri, p) = der::read_expect(outer.content, 0, 0x30).unwrap();
        let (alg, p) = der::read_expect(outer.content, p, 0x30).unwrap();
        assert_eq!(
            alg.content,
            der::oid(OID_ECDSA_SHA256).unwrap().as_slice(),
            "签名算法必须是 ecdsa-with-SHA256"
        );
        let (bits, _) = der::read_expect(outer.content, p, 0x03).unwrap();
        assert_eq!(bits.content[0], 0);

        let sig = p256::ecdsa::Signature::from_der(&bits.content[1..]).unwrap();
        let digest = Sha256::digest(cri.raw);
        key.verifying_key().verify_prehash(&digest, &sig).unwrap();

        // CRI 里必须有 CN=quantum-debug 与 P-256 的 SPKI
        assert!(
            cri.content
                .windows(SUBJECT_CN.len())
                .any(|w| w == SUBJECT_CN.as_bytes()),
            "CRI 缺 CN"
        );
        let _ = std::fs::remove_file(&path);
    }
}
