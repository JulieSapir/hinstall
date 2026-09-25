//! DER / ASN.1 编解码。
//!
//! 手写实现而非引入 asn1 库，原因有二：
//! 1. 需要与 Java BouncyCastle 产物**字节等价**，编码细节必须完全可控；
//! 2. 保持依赖最小。

use crate::hap_sign::error::{Error, Result};

// ============================================================ 编码

/// 编码 DER 长度域。
pub fn der_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut body = Vec::new();
    let mut v = n;
    while v > 0 {
        body.insert(0, (v & 0xFF) as u8);
        v >>= 8;
    }
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(0x80 | body.len() as u8);
    out.extend_from_slice(&body);
    out
}

/// 编码一个 TLV。
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 5);
    out.push(tag);
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// 把多个片段拼成一个字节串。
pub fn cat(items: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(items.iter().map(|i| i.len()).sum());
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

/// 编码 OID 内容（不含 tag/length）。
fn oid_content(oid: &str) -> Result<Vec<u8>> {
    let parts: Vec<u64> = oid
        .split('.')
        .map(|p| p.parse::<u64>().map_err(|_| Error::Der("OID 段非数字")))
        .collect::<Result<_>>()?;
    if parts.len() < 2 {
        return Err(Error::Der("OID 至少需要两段"));
    }
    if parts[0] > 2 || (parts[0] < 2 && parts[1] >= 40) {
        return Err(Error::Der("OID 首段非法"));
    }
    let mut body = Vec::new();
    push_base128(&mut body, parts[0] * 40 + parts[1]);
    for p in &parts[2..] {
        push_base128(&mut body, *p);
    }
    Ok(body)
}

/// 追加 base-128 变长编码（首字节高位为续位标志，末字节清零）。
fn push_base128(out: &mut Vec<u8>, v: u64) {
    let mut chunk = Vec::new();
    let mut v = v;
    while v > 0 {
        chunk.insert(0, ((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    if chunk.is_empty() {
        chunk.push(0x80);
    }
    let last = chunk.len() - 1;
    chunk[last] &= 0x7F;
    out.extend_from_slice(&chunk);
}

/// 编码 OID（完整 TLV）。
pub fn oid(oid: &str) -> Result<Vec<u8>> {
    Ok(tlv(0x06, &oid_content(oid)?))
}

/// 编码非负 INTEGER 内容。
///
/// 入参是大端无符号字节；最高位为 1 时补前导 0x00，避免被解析成负数。
pub fn int_content_be(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    let mut out = Vec::with_capacity(v.len() + 1);
    if v.is_empty() {
        return vec![0x00];
    }
    if v[0] & 0x80 != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(v);
    out
}

/// DER SET OF 排序：按元素完整编码的字节序升序拼接。
pub fn sort_set(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut items = items;
    items.sort();
    cat(&items.iter().map(|v| v.as_slice()).collect::<Vec<_>>())
}

// ============================================================ 流式构造器

/// DER 追加式构造器（链式调用）。
///
/// 使用移动语义的链式 API，避免手工拼接时把长度算错。
#[derive(Debug, Default, Clone)]
pub struct Der {
    buf: Vec<u8>,
}

impl Der {
    /// 新建空构造器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 直接追加已编码好的字节。
    pub fn raw(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// 追加另一个构造器的内容。
    pub fn push(self, other: Der) -> Self {
        self.raw(&other.buf)
    }

    /// 追加一个自定义标签的 TLV。
    pub fn tagged(mut self, tag: u8, content: &[u8]) -> Self {
        self.buf.push(tag);
        self.buf.extend_from_slice(&der_length(content.len()));
        self.buf.extend_from_slice(content);
        self
    }

    /// 追加 SEQUENCE。
    pub fn seq(self, f: impl FnOnce(Der) -> Der) -> Self {
        let inner = f(Der::new()).buf;
        self.tagged(0x30, &inner)
    }

    /// 追加 SET。
    pub fn set(self, f: impl FnOnce(Der) -> Der) -> Self {
        let inner = f(Der::new()).buf;
        self.tagged(0x31, &inner)
    }

    /// 追加 OCTET STRING。
    pub fn octet(self, data: &[u8]) -> Self {
        self.tagged(0x04, data)
    }

    /// 追加 NULL。
    pub fn null(self) -> Self {
        self.tagged(0x05, &[])
    }

    /// 追加 INTEGER（内容为原始大端字节）。
    pub fn int_be(self, bytes: &[u8]) -> Self {
        let c = int_content_be(bytes);
        self.tagged(0x02, &c)
    }

    /// 追加 INTEGER（u64）。
    pub fn int_u64(self, v: u64) -> Self {
        let c = int_content_be(&v.to_be_bytes());
        self.tagged(0x02, &c)
    }

    /// 追加 UTF8String。
    pub fn utf8(self, s: &str) -> Self {
        self.tagged(0x0C, s.as_bytes())
    }

    /// 追加 UTCTime（内容须为 `YYMMDDHHMMSSZ`）。
    pub fn utc_time(self, content: &str) -> Self {
        self.tagged(0x17, content.as_bytes())
    }

    /// 追加 `[n]` 上下文标签（默认 constructed）。
    pub fn ctx(self, number: u8, content: &[u8]) -> Self {
        self.tagged(0xA0 | number, content)
    }

    /// 追加 AlgorithmIdentifier。
    ///
    /// `with_null` 为 false 时省略参数——与 BouncyCastle 的
    /// `AlgorithmIdentifier(oid, DERNull.INSTANCE)` 行为区分开，签名路径必须为 false。
    pub fn alg_id(self, oid_str: &str, with_null: bool) -> Result<Self> {
        let oid_der = oid(oid_str)?;
        Ok(self.seq(move |d| {
            let d = d.raw(&oid_der);
            if with_null { d.null() } else { d }
        }))
    }

    /// 取出最终字节。
    pub fn bytes(self) -> Vec<u8> {
        self.buf
    }
}

// ============================================================ 解析

/// 一个已解析的 TLV。
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    /// 标签字节（含 class / constructed 位）。
    pub tag: u8,
    /// 内容（不含标签与长度域）。
    pub content: &'a [u8],
    /// 完整原始编码（含标签与长度域）。
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {}

/// 从 `pos` 处读取一个 TLV，返回 `(Tlv, 下一个位置)`。
pub fn read(data: &[u8], pos: usize) -> Result<(Tlv<'_>, usize)> {
    if pos >= data.len() {
        return Err(Error::Der("TLV 越界"));
    }
    let start = pos;
    let tag = data[pos];
    let mut p = pos + 1;
    let first = *data.get(p).ok_or(Error::Der("长度域缺失"))?;
    p += 1;
    let len = if first & 0x80 != 0 {
        let n = (first & 0x7F) as usize;
        if n == 0 {
            return Err(Error::Der("不支持不定长 BER 编码"));
        }
        if p + n > data.len() {
            return Err(Error::Der("长度域截断"));
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | data[p + i] as usize;
        }
        p += n;
        v
    } else {
        first as usize
    };
    let end = p.checked_add(len).ok_or(Error::Der("长度溢出"))?;
    if end > data.len() {
        return Err(Error::Der("DER 数据截断"));
    }
    Ok((
        Tlv {
            tag,
            content: &data[p..end],
            raw: &data[start..end],
        },
        end,
    ))
}

/// 读取一个 TLV 并断言其标签。
pub fn read_expect(data: &[u8], pos: usize, tag: u8) -> Result<(Tlv<'_>, usize)> {
    let (t, next) = read(data, pos)?;
    if t.tag != tag {
        return Err(Error::Der("标签不匹配"));
    }
    Ok((t, next))
}

/// 顺序遍历全部 TLV。
pub fn iter(data: &[u8]) -> TlvIter<'_> {
    TlvIter { data, pos: 0 }
}

/// [`iter`] 返回的迭代器。
pub struct TlvIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<Tlv<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        match read(self.data, self.pos) {
            Ok((t, next)) => {
                self.pos = next;
                Some(Ok(t))
            }
            Err(e) => {
                self.pos = self.data.len();
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_encoding() {
        assert_eq!(der_length(0x7F), vec![0x7F]);
        assert_eq!(der_length(0x80), vec![0x81, 0x80]);
        assert_eq!(der_length(0x1234), vec![0x82, 0x12, 0x34]);
    }

    #[test]
    fn oid_encoding() {
        // 1.2.840.113549.1.7.2 → 06 09 2A 86 48 86 F7 0D 01 07 02
        assert_eq!(
            oid("1.2.840.113549.1.7.2").unwrap(),
            vec![
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
            ]
        );
        // 2.16.840.1.101.3.4.2.1 → 06 09 60 86 48 01 65 03 04 02 01
        assert_eq!(
            oid("2.16.840.1.101.3.4.2.1").unwrap(),
            vec![
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
            ]
        );
        // 1.2.840.10045.4.3.2 → 06 08 2A 86 48 CE 3D 04 03 02
        assert_eq!(
            oid("1.2.840.10045.4.3.2").unwrap(),
            vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
        );
    }

    #[test]
    fn integer_padding() {
        assert_eq!(int_content_be(&[0x7F]), vec![0x7F]);
        assert_eq!(int_content_be(&[0x80]), vec![0x00, 0x80]);
        assert_eq!(int_content_be(&[0x00, 0x00, 0x01]), vec![0x01]);
    }

    #[test]
    fn set_sorting() {
        // 排序按完整编码字节序，长度域参与比较
        let a = tlv(0x30, &[0x01]); // 30 01 01
        let b = tlv(0x30, &[0x01, 0x02, 0x03]); // 30 03 01 02 03
        let sorted = sort_set(vec![b.clone(), a.clone()]);
        assert_eq!(sorted, cat(&[&a, &b]));
    }

    #[test]
    fn roundtrip_read() {
        let inner = Der::new().int_u64(1).octet(b"abc").bytes();
        let outer = tlv(0x30, &inner);
        let (t, next) = read(&outer, 0).unwrap();
        assert_eq!(t.tag, 0x30);
        assert_eq!(next, outer.len());
        assert_eq!(t.raw, outer.as_slice());
        let items: Vec<_> = iter(t.content).map(|r| r.unwrap().tag).collect();
        assert_eq!(items, vec![0x02, 0x04]);
    }
}
