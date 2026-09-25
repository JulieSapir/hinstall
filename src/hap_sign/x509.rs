//! X.509 证书最小解析。
//!
//! 只解析签名流程真正需要的字段：序列号、issuer、subject、公钥。
//! 不做完整合规校验——链的信任判定由设备侧完成，本库只负责把正确的字节放进
//! CMS 的 `IssuerAndSerialNumber` 与证书集合。

use crate::hap_sign::der::{self, Der};
use crate::hap_sign::error::{Error, Result};

/// PEM 标签为 `CERTIFICATE` 的块。
const PEM_CERT: &str = "CERTIFICATE";

/// OID：id-ecPublicKey。
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// OID：rsaEncryption。
pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// OID：prime256v1 (P-256)。
pub const OID_CURVE_P256: &str = "1.2.840.10045.3.1.7";
/// OID：secp384r1 (P-384)。
pub const OID_CURVE_P384: &str = "1.3.132.0.34";
/// OID：secp521r1 (P-521)。
pub const OID_CURVE_P521: &str = "1.3.132.0.35";

/// 最小 X.509 证书视图。
#[derive(Debug, Clone)]
pub struct Certificate {
    /// 证书完整 DER。
    pub der: Vec<u8>,
    /// issuer 的原始 DER 编码（含 tag/length）。
    pub issuer_raw: Vec<u8>,
    /// subject 的原始 DER 编码（含 tag/length）。
    pub subject_raw: Vec<u8>,
    /// serialNumber 的 DER 内容（大端无符号，已是最小编码）。
    pub serial: Vec<u8>,
    /// subject 中的 CN（找不到则为空串）。
    pub subject_cn: String,
}

impl Certificate {
    /// 解析单张 DER 证书。
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (cert, _) =
            der::read_expect(der, 0, 0x30).map_err(|_| Error::X509("证书不是 SEQUENCE"))?;
        let (tbs, _) = der::read_expect(cert.content, 0, 0x30)
            .map_err(|_| Error::X509("tbsCertificate 不是 SEQUENCE"))?;
        let tbs_bytes = tbs.content;

        let mut p = 0;
        let (first, next) = der::read(tbs_bytes, p)?;
        p = next;
        if first.tag == 0xA0 {
            // 显式 [0] version，跳过
            let (serial, next) = der::read(tbs_bytes, p)?;
            p = next;
            if serial.tag != 0x02 {
                return Err(Error::X509("证书缺少 serialNumber"));
            }
            return Self::finish(der, tbs_bytes, p, serial.content);
        }
        if first.tag != 0x02 {
            return Err(Error::X509("证书缺少 serialNumber"));
        }
        Self::finish(der, tbs_bytes, p, first.content)
    }

    fn finish(der: &[u8], tbs: &[u8], mut p: usize, serial: &[u8]) -> Result<Self> {
        // signature AlgorithmIdentifier
        let (_, next) = der::read(tbs, p)?;
        p = next;
        // issuer（保留原始编码）
        let (issuer, next) = der::read(tbs, p)?;
        p = next;
        // validity
        let (_, next) = der::read(tbs, p)?;
        p = next;
        // subject（保留原始编码）
        let (subject, _) = der::read(tbs, p)?;

        Ok(Certificate {
            der: der.to_vec(),
            issuer_raw: issuer.raw.to_vec(),
            subject_raw: subject.raw.to_vec(),
            serial: serial.to_vec(),
            subject_cn: find_cn(subject.raw),
        })
    }

    /// 重新编码 `IssuerAndSerialNumber`（SignerInfo 使用）。
    pub fn issuer_and_serial(&self) -> Der {
        Der::new().seq(|d| d.raw(&self.issuer_raw).int_be(&self.serial))
    }
}

/// 在 Name（RDNSequence）中查 OID 2.5.4.3（CN）的字符串值。
///
/// 用字节搜索而非完整 RDN 解析：与 Java 侧行为一致，且证书结构固定。
fn find_cn(name_der: &[u8]) -> String {
    const CN_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03]; // 2.5.4.3
    let Some(idx) = name_der.windows(CN_OID.len()).position(|w| w == CN_OID) else {
        return String::new();
    };
    let p = idx + CN_OID.len();
    let Ok((value, _)) = der::read(name_der, p) else {
        return String::new();
    };
    match std::str::from_utf8(value.content) {
        Ok(s) => s.to_string(),
        Err(_) => value.content.iter().map(|&b| b as char).collect(),
    }
}

/// 解码 OID 内容为点分十进制字符串。
pub fn decode_oid(content: &[u8]) -> Result<String> {
    if content.is_empty() {
        return Err(Error::Der("OID 内容为空"));
    }
    let mut out = Vec::new();
    // 首字节承载前两段：x*40 + y，且可能是变长编码
    let mut idx = 0;
    let (first, consumed) = read_base128(content, 0)?;
    idx += consumed;
    let (a, b) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    out.push(a.to_string());
    out.push(b.to_string());
    while idx < content.len() {
        let (v, consumed) = read_base128(content, idx)?;
        idx += consumed;
        out.push(v.to_string());
    }
    Ok(out.join("."))
}

/// 读取一个 base-128 变长整数，返回 `(值, 消耗字节数)`。
fn read_base128(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let start = pos;
    let mut v: u64 = 0;
    loop {
        let byte = *data.get(pos).ok_or(Error::Der("OID 截断"))?;
        pos += 1;
        v = v
            .checked_mul(128)
            .and_then(|x| x.checked_add((byte & 0x7F) as u64))
            .ok_or(Error::Der("OID 数值溢出"))?;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((v, pos - start))
}

/// 解析 PEM 文本中的全部块，返回 `(标签, DER)`。
pub fn pem_blocks(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let text = String::from_utf8_lossy(data).into_owned();
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(begin) = rest.find("-----BEGIN ") {
        let after_begin = &rest[begin + "-----BEGIN ".len()..];
        let Some(label_end) = after_begin.find("-----") else {
            return Err(Error::Invalid("PEM 头缺少结束标记".into()));
        };
        let label = after_begin[..label_end].to_string();
        let body_start = label_end + "-----".len();
        let end_marker = format!("-----END {label}-----");
        let Some(end) = after_begin[body_start..].find(&end_marker) else {
            return Err(Error::Invalid(format!("PEM 缺少 {end_marker}")));
        };
        let body = &after_begin[body_start..body_start + end];
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let der = base64_decode(&compact)?;
        out.push((label, der));
        rest = &after_begin[body_start + end + end_marker.len()..];
    }
    Ok(out)
}

/// base64 解码（标准字母表；允许省略尾部填充）。
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let mut compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    // PEM 体允许省略填充，补齐到 4 的倍数再解码
    while !compact.len().is_multiple_of(4) {
        compact.push('=');
    }
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| Error::Invalid(format!("base64 解码失败: {e}")))
}

/// 解析证书链文件：PEM（可含多张）或裸 DER。
pub fn parse_certificates(data: &[u8]) -> Result<Vec<Certificate>> {
    let blocks = pem_blocks(data)?;
    let certs: Vec<&(String, Vec<u8>)> = blocks
        .iter()
        .filter(|(label, _)| label == PEM_CERT)
        .collect();
    if certs.is_empty() {
        // 无 PEM 块：按裸 DER 处理
        return Ok(vec![Certificate::from_der(data)?]);
    }
    certs
        .into_iter()
        .map(|(_, der)| Certificate::from_der(der))
        .collect()
}

/// 读取证书链并按 issuer/subject 关系排序（叶子在前、根在最后）。
pub fn load_cert_chain(data: &[u8]) -> Result<Vec<Certificate>> {
    let certs = parse_certificates(data)?;
    if certs.is_empty() {
        return Err(Error::Invalid("证书文件为空".into()));
    }
    Ok(sort_cert_chain(certs))
}

/// 按 issuer→subject 关系重建链序：叶子在前、根在最后。
///
/// 叶子判定：其 subject 没有被链中任何证书的 issuer 引用。
/// 信任锚判定交由设备侧完成，此处只做排序。
pub fn sort_cert_chain(certs: Vec<Certificate>) -> Vec<Certificate> {
    if certs.len() == 1 {
        return certs;
    }
    let issuers: Vec<&Vec<u8>> = certs.iter().map(|c| &c.issuer_raw).collect();
    let leaf = certs
        .iter()
        .position(|c| !issuers.iter().any(|i| **i == c.subject_raw))
        .unwrap_or(0);

    let mut order = vec![leaf];
    let mut used = vec![false; certs.len()];
    used[leaf] = true;
    loop {
        let cur = &certs[*order.last().expect("order 非空")];
        let next = certs
            .iter()
            .enumerate()
            .position(|(i, c)| !used[i] && c.subject_raw == cur.issuer_raw);
        match next {
            Some(i) => {
                used[i] = true;
                order.push(i);
            }
            None => break,
        }
    }
    // 未参与成链的证书按原顺序追加在尾部
    for (i, _) in certs.iter().enumerate() {
        if !used[i] {
            order.push(i);
        }
    }

    let mut slots: Vec<Option<Certificate>> = certs.into_iter().map(Some).collect();
    order
        .into_iter()
        .map(|i| slots[i].take().expect("索引唯一，不会重复取出"))
        .collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::hap_sign::der::{cat, tlv};

    /// 构造一张结构合法（不校验外层签名）的 v3 证书，公钥取自给定 P-256 私钥。
    ///
    /// 单测只需要「结构正确、公钥真实」的证书字节，签名值填占位符。
    pub fn self_signed_cert(key: &p256::ecdsa::SigningKey, cn: &str) -> Certificate {
        let point = key.verifying_key().to_sec1_point(false);
        let alg = cat(&[
            &der::oid(OID_EC_PUBLIC_KEY).unwrap(),
            &der::oid(OID_CURVE_P256).unwrap(),
        ]);
        let spki = Der::new()
            .seq(|d| {
                d.raw(&tlv(0x30, &alg))
                    .tagged(0x03, &cat(&[&[0x00], point.as_bytes()]))
            })
            .bytes();
        let sig_alg = Der::new()
            .alg_id("1.2.840.10045.4.3.2", false)
            .unwrap()
            .bytes();
        let atv = Der::new()
            .seq(|d| d.raw(&der::oid("2.5.4.3").unwrap()).utf8(cn))
            .bytes();
        let name = Der::new().seq(|d| d.set(|s| s.raw(&atv))).bytes();
        let serial = vec![0x01u8];

        let tbs = Der::new()
            .seq(|d| {
                d.tagged(0xA0, &Der::new().int_u64(2).bytes())
                    .int_be(&serial)
                    .raw(&sig_alg)
                    .raw(&name)
                    .seq(|v| v.utc_time("240101000000Z").utc_time("340101000000Z"))
                    .raw(&name)
                    .raw(&spki)
            })
            .bytes();
        let cert = Der::new()
            .seq(|d| {
                d.raw(&tbs)
                    .raw(&sig_alg)
                    .tagged(0x03, &cat(&[&[0x00], &[0x00]]))
            })
            .bytes();
        Certificate::from_der(&cert).unwrap()
    }

    #[test]
    fn oid_roundtrip() {
        for s in [
            "1.2.840.113549.1.7.2",
            "2.16.840.1.101.3.4.2.1",
            "1.2.840.10045.4.3.2",
            "1.3.6.1.4.1.2011.2.376.1.4.1",
        ] {
            let encoded = der::oid(s).unwrap();
            let content = &encoded[2..];
            assert_eq!(decode_oid(content).unwrap(), s);
        }
    }

    #[test]
    fn pem_base64() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAAEC\nAwQF\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, "CERTIFICATE");
        assert_eq!(blocks[0].1, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    }
}
