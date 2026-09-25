//! 极简 JSON 解析。
//!
//! 不引入 `serde_json`：整个工程只需要「读 `module.json` 里的一个字段」和
//! 「读 auth.json / config.json」，为此拖进一整棵依赖树不划算（web 端还要计体积）。
//! 只实现 RFC 8259 的读取部分，不做序列化。

use crate::hap_sign::error::{Error, Result};

/// JSON 值。
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    /// null
    Null,
    /// true / false
    Bool(bool),
    /// 数字（统一按 f64 存）
    Num(f64),
    /// 字符串
    Str(String),
    /// 数组
    Arr(Vec<Json>),
    /// 对象（保持出现顺序）
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// 解析一段 JSON 文本（要求整段被消费）。
    pub fn parse(text: &str) -> Result<Self> {
        let mut p = Parser {
            bytes: text.as_bytes(),
            pos: 0,
        };
        p.skip_ws();
        let v = p.value()?;
        p.skip_ws();
        if p.pos != p.bytes.len() {
            return Err(Error::Invalid(format!("JSON 尾部有多余内容 @ {}", p.pos)));
        }
        Ok(v)
    }

    /// 按 key 取对象成员。
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// 取字符串值。
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// 取对象成员。
    pub fn as_obj(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(items) => Some(items),
            _ => None,
        }
    }

    /// 取数组元素。
    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items),
            _ => None,
        }
    }

    /// 取数字。
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<()> {
        if self.peek() != Some(b) {
            return Err(Error::Invalid(format!(
                "JSON 期望 '{}' @ {}",
                b as char, self.pos
            )));
        }
        self.pos += 1;
        Ok(())
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            return Ok(value);
        }
        Err(Error::Invalid(format!("JSON 非法字面量 @ {}", self.pos)))
    }

    fn value(&mut self) -> Result<Json> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(Error::Invalid(format!("JSON 非法值 @ {}", self.pos))),
        }
    }

    fn object(&mut self) -> Result<Json> {
        self.expect(b'{')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(items));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value()?;
            items.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(items));
                }
                _ => return Err(Error::Invalid(format!("JSON 对象未闭合 @ {}", self.pos))),
            }
        }
    }

    fn array(&mut self) -> Result<Json> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(Error::Invalid(format!("JSON 数组未闭合 @ {}", self.pos))),
            }
        }
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit() || c == b'.' || c == b'e' || c == b'E' || c == b'+' || c == b'-')
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| Error::Invalid("JSON 数字非 UTF-8".into()))?;
        let n = text
            .parse::<f64>()
            .map_err(|e| Error::Invalid(format!("JSON 数字非法: {text} ({e})")))?;
        Ok(Json::Num(n))
    }

    fn string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self
                .peek()
                .ok_or_else(|| Error::Invalid("JSON 字符串未闭合".into()))?;
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self
                        .peek()
                        .ok_or_else(|| Error::Invalid("JSON 转义未闭合".into()))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => {
                            return Err(Error::Invalid(format!(
                                "JSON 非法转义: \\{}",
                                other as char
                            )));
                        }
                    }
                }
                _ => {
                    // 按 UTF-8 字符推进
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| Error::Invalid("JSON 字符串非 UTF-8".into()))?;
                    let ch = rest
                        .chars()
                        .next()
                        .ok_or_else(|| Error::Invalid("JSON 字符串未闭合".into()))?;
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        if self.pos + 4 > self.bytes.len() {
            return Err(Error::Invalid("JSON \\u 转义越界".into()));
        }
        let text = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| Error::Invalid("JSON \\u 转义非 UTF-8".into()))?;
        let v = u32::from_str_radix(text, 16)
            .map_err(|_| Error::Invalid(format!("JSON \\u 转义非法: {text}")))?;
        self.pos += 4;
        Ok(v)
    }

    fn unicode_escape(&mut self) -> Result<char> {
        let hi = self.hex4()?;
        // 代理对：高代理后必须跟 \uDC00-\uDFFF
        if (0xD800..0xDC00).contains(&hi) {
            if self.peek() != Some(b'\\') {
                return Err(Error::Invalid("JSON 高代理后缺少 \\u".into()));
            }
            self.pos += 1;
            if self.peek() != Some(b'u') {
                return Err(Error::Invalid("JSON 高代理后缺少 \\u".into()));
            }
            self.pos += 1;
            let lo = self.hex4()?;
            if !(0xDC00..0xE000).contains(&lo) {
                return Err(Error::Invalid("JSON 低代理非法".into()));
            }
            let code = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
            return char::from_u32(code).ok_or_else(|| Error::Invalid("JSON 代理对非法".into()));
        }
        char::from_u32(hi).ok_or_else(|| Error::Invalid("JSON \\u 码点非法".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_module_json() {
        let text = r#"{
          "app": {"bundleName": "com.example.demo"},
          "module": {
            "name": "entry",
            "shareFiles": "$profile:share",
            "abilities": [{"name": "EntryAbility"}]
          }
        }"#;
        let v = Json::parse(text).unwrap();
        let module = v.get("module").unwrap();
        assert_eq!(module.get("name").unwrap().as_str(), Some("entry"));
        assert_eq!(
            module.get("shareFiles").unwrap().as_str(),
            Some("$profile:share")
        );
        let abilities = module.get("abilities").unwrap().as_arr().unwrap();
        assert_eq!(
            abilities[0].get("name").unwrap().as_str(),
            Some("EntryAbility")
        );
    }

    #[test]
    fn escapes_and_numbers() {
        let v = Json::parse(r#"{"s":"a\"b\n\u0041\uD83D\uDE00","n":-1.5e3,"b":true,"z":null}"#)
            .unwrap();
        assert_eq!(v.get("s").unwrap().as_str(), Some("a\"b\nA\u{1F600}"));
        assert_eq!(v.get("n").unwrap().as_f64(), Some(-1500.0));
        assert_eq!(v.get("z").unwrap(), &Json::Null);
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(Json::parse("{} x").is_err());
        assert!(Json::parse("{\"a\":}").is_err());
        assert!(Json::parse("").is_err());
    }
}
