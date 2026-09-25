//! 最小 JSON 写出（对应 `tool.py` 里的 `json.dumps`）。
//!
//! 解析侧复用 `hap_sign::json::Json`，这里只补写出能力。格式对齐 Python：
//! 非缩进时分隔符为 `", "` / `": "`，[`JVal::to_indent1`] 对齐
//! `json.dumps(obj, ensure_ascii=False, indent=1)`。

use crate::hap_sign::json::Json;

/// 一个可写出的 JSON 值。
#[derive(Debug, Clone, PartialEq)]
pub enum JVal {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// 整数
    Int(i64),
    /// 字符串
    Str(String),
    /// 数组
    Arr(Vec<JVal>),
    /// 对象（保持插入顺序）
    Obj(Vec<(String, JVal)>),
}

impl JVal {
    /// 紧凑形式，对齐 `json.dumps(obj)`。
    pub fn to_compact(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, None, 0);
        out
    }

    /// 缩进 1 空格，对齐 `json.dumps(obj, indent=1)`。
    pub fn to_indent1(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, Some(1), 0);
        out
    }

    fn write(&self, out: &mut String, indent: Option<usize>, depth: usize) {
        match self {
            JVal::Null => out.push_str("null"),
            JVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JVal::Int(v) => out.push_str(&v.to_string()),
            JVal::Str(s) => write_str(out, s),
            JVal::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(if indent.is_some() { "," } else { ", " });
                    }
                    newline_indent(out, indent, depth + 1);
                    item.write(out, indent, depth + 1);
                }
                newline_indent(out, indent, depth);
                out.push(']');
            }
            JVal::Obj(pairs) => {
                if pairs.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push_str(if indent.is_some() { "," } else { ", " });
                    }
                    newline_indent(out, indent, depth + 1);
                    write_str(out, k);
                    out.push_str(": ");
                    v.write(out, indent, depth + 1);
                }
                newline_indent(out, indent, depth);
                out.push('}');
            }
        }
    }
}

/// 按 `indent` 输出换行与缩进；非缩进模式什么都不做。
fn newline_indent(out: &mut String, indent: Option<usize>, depth: usize) {
    if let Some(step) = indent {
        out.push('\n');
        for _ in 0..step * depth {
            out.push(' ');
        }
    }
}

/// 写一个 JSON 字符串字面量，转义规则与 Python 一致。
fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// 把解析得到的 [`Json`] 转成可写出的 [`JVal`]。
pub fn to_jval(v: &Json) -> JVal {
    match v {
        Json::Null => JVal::Null,
        Json::Bool(b) => JVal::Bool(*b),
        Json::Num(n) => {
            // Python 侧 JSON 数字可能是 int 或 float；云端字段都是整数，
            // 这里统一按 i64 还原，避免出现 `4.0` 这种字面量。
            if n.fract() == 0.0 && n.abs() < 9.2e18 {
                JVal::Int(*n as i64)
            } else {
                JVal::Str(n.to_string())
            }
        }
        Json::Str(s) => JVal::Str(s.clone()),
        Json::Arr(items) => JVal::Arr(items.iter().map(to_jval).collect()),
        Json::Obj(pairs) => JVal::Obj(pairs.iter().map(|(k, v)| (k.clone(), to_jval(v))).collect()),
    }
}

/// 对齐 Python 的 `json.dumps(obj, ensure_ascii=False, indent=1)`。
pub fn pretty(v: &Json) -> String {
    to_jval(v).to_indent1()
}

/// 打印用文本（对应 Python f-string 里直接插值）。
pub fn display(v: &Json) -> String {
    match v {
        Json::Str(s) => s.clone(),
        other => to_jval(other).to_compact(),
    }
}

/// 请求头文本（对应 Python 的 `str(v)`）。
pub fn header_value(v: &Json) -> String {
    match v {
        Json::Str(s) => s.clone(),
        Json::Num(n) if n.fract() == 0.0 => (*n as i64).to_string(),
        other => to_jval(other).to_compact(),
    }
}

/// 对齐 Python 的真值判断（`or` 链用）。
pub fn truthy(v: &Json) -> bool {
    match v {
        Json::Null => false,
        Json::Bool(b) => *b,
        Json::Num(n) => *n != 0.0,
        Json::Str(s) => !s.is_empty(),
        Json::Arr(a) => !a.is_empty(),
        Json::Obj(o) => !o.is_empty(),
    }
}

/// 取字符串字段。
pub fn str_field(v: &Json, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_string)
}

/// 取整数字段。
pub fn int_field(v: &Json, key: &str) -> Option<i64> {
    v.get(key).and_then(|x| x.as_f64()).map(|f| f as i64)
}

/// 取数组字段；键缺失时返回空数组，键存在但不是数组时显式报错。
pub fn arr_field(v: &Json, key: &str, ctx: &str) -> crate::fail::R<Vec<Json>> {
    match v.get(key) {
        None => Ok(Vec::new()),
        Some(x) => x.as_arr().map(|a| a.to_vec()).ok_or_else(|| {
            crate::fail::Fail(format!(
                "响应字段 {key} 不是数组 {ctx}:\n{}",
                crate::util::truncate(&pretty(v), 2000)
            ))
        }),
    }
}
