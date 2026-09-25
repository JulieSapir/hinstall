//! HTTP 客户端（对应 `tool.py` 的 `http_text` / `http_json` / `download`）。

use std::path::Path;
use std::time::Duration;

use crate::fail::{Fail, R};
use crate::hap_sign::json::Json;
use crate::jsonw::{JVal, pretty};
use crate::util::truncate;

/// 与官方 IDE 一致的请求头。
const UA: &str = "Dart/3.6 (dart:io)";
/// 单次请求超时。
const TIMEOUT: Duration = Duration::from_secs(30);
/// 下载超时。
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// 报错时最多回显的响应体字符数。
const ERR_BODY_LIMIT: usize = 2000;

/// 一次请求的响应。
pub struct HttpReply {
    /// HTTP 状态码。
    pub status: u16,
    /// 响应文本（已按 `Content-Encoding` 解压，非 UTF-8 字节按替换字符处理）。
    pub text: String,
}

/// 发起请求并返回状态码与文本，**不把非 2xx 当错误**。
///
/// `raw_dump` 非空时把响应文本写入该路径，用于协议校准。
pub fn http_raw(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&JVal>,
    raw_dump: Option<&Path>,
) -> R<HttpReply> {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            // ureq 3 默认把 4xx/5xx 转成 Err(Error::StatusCode)，会丢掉响应体；
            // tool.py 的 HTTPError 分支要回显错误体，所以必须关掉。
            .http_status_as_error(false)
            .build(),
    );
    let mut req = ureq::http::Request::builder()
        .method(method)
        .uri(url)
        .header("User-Agent", UA)
        .header("Accept-Encoding", "gzip")
        .header("Content-Type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    // ureq 3 没有 request(method, url) 泛接口，只能自己拼 http::Request 再交给 Agent::run。
    let mut resp = match body {
        Some(b) => agent.run(
            req.body(b.to_compact())
                .map_err(|e| Fail(format!("构造请求失败 {url}: {e}")))?,
        ),
        None => agent.run(
            req.body(())
                .map_err(|e| Fail(format!("构造请求失败 {url}: {e}")))?,
        ),
    }
    .map_err(|e| Fail(format!("网络失败 {url}: {e}")))?;
    let status = resp.status().as_u16();
    let text = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| Fail(format!("网络失败 {url}: {e}")))?;
    if let Some(path) = raw_dump {
        crate::util::write(path, text.as_bytes())?;
    }
    Ok(HttpReply { status, text })
}

/// 发起请求并返回响应文本；非 2xx 直接失败。
pub fn http_text(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&JVal>,
    raw_dump: Option<&Path>,
) -> R<String> {
    let reply = http_raw(method, url, headers, body, raw_dump)?;
    if !(200..300).contains(&reply.status) {
        return Err(Fail(format!(
            "HTTP {} {url}\n{}",
            reply.status,
            truncate(&reply.text, ERR_BODY_LIMIT)
        )));
    }
    Ok(reply.text)
}

/// 发起请求并把响应体解析为 JSON。
pub fn http_json(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&JVal>,
    raw_dump: Option<&Path>,
) -> R<Json> {
    let text = http_text(method, url, headers, body, raw_dump)?;
    Json::parse(&text).map_err(|_| {
        Fail(format!(
            "响应非 JSON: {url}\n{}",
            truncate(&text, ERR_BODY_LIMIT)
        ))
    })
}

/// 严格取字段，缺失时打印整个对象——不猜结构。
pub fn require<'a>(obj: &'a Json, key: &str, ctx: &str) -> R<&'a Json> {
    obj.get(key).ok_or_else(|| {
        Fail(format!(
            "响应缺少字段 {key} {ctx}:\n{}",
            truncate(&pretty(obj), 3000)
        ))
    })
}

/// 下载一个 URL 到文件。
pub fn download(url: &str, dest: &Path) -> R<()> {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(DOWNLOAD_TIMEOUT))
            .build(),
    );
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| Fail(format!("下载失败 {url}: {e}")))?;
    let mut reader = resp.into_body().into_reader();
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Fail(format!("创建目录 {} 失败: {e}", dir.display())))?;
    }
    let mut file = std::fs::File::create(dest)
        .map_err(|e| Fail(format!("创建 {} 失败: {e}", dest.display())))?;
    std::io::copy(&mut reader, &mut file).map_err(|e| Fail(format!("下载失败 {url}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    /// 起一个只服务一次的 HTTP/1.1 服务，返回 (端口, 取回原始请求文本的句柄)。
    fn serve_once(reply: &'static [u8]) -> (u16, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
        let port = listener.local_addr().expect("取端口").port();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("接受连接");
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            // 读到头部结束，再按 Content-Length 补齐请求体
            loop {
                let n = sock.read(&mut chunk).expect("读取请求");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf);
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let len = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= head_end + 4 + len {
                        break;
                    }
                }
            }
            sock.write_all(reply).expect("写响应");
            sock.flush().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        });
        (port, handle)
    }

    fn reply(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn reply_with(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// 把响应字节泄漏成 'static（测试内只调用几次，不关心泄漏）。
    fn leak(bytes: Vec<u8>) -> &'static [u8] {
        Box::leak(bytes.into_boxed_slice())
    }

    #[test]
    fn get_请求头与响应体() {
        let (port, handle) = serve_once(leak(reply(r#"{"ok":true}"#)));
        let url = format!("http://127.0.0.1:{port}/api/x");
        let r = http_raw("GET", &url, &[("X-Token", "abc")], None, None).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.text, r#"{"ok":true}"#);
        let req = handle.join().unwrap();
        assert!(req.starts_with("GET /api/x HTTP/1.1\r\n"), "{req}");
        assert!(req.contains("user-agent: Dart/3.6 (dart:io)"), "{req}");
        assert!(req.contains("accept-encoding: gzip"), "{req}");
        assert!(req.contains("content-type: application/json"), "{req}");
        assert!(req.contains("x-token: abc"), "{req}");
    }

    #[test]
    fn post_json_请求体与自定义方法() {
        let (port, handle) = serve_once(leak(reply("{}")));
        let url = format!("http://127.0.0.1:{port}/api/y");
        let body = JVal::Obj(vec![
            ("a".to_string(), JVal::Int(1)),
            ("b".to_string(), JVal::Str("中文".to_string())),
        ]);
        let r = http_raw("POST", &url, &[], Some(&body), None).unwrap();
        assert_eq!(r.status, 200);
        let req = handle.join().unwrap();
        assert!(req.starts_with("POST /api/y HTTP/1.1\r\n"), "{req}");
        assert!(req.ends_with(r#"{"a": 1, "b": "中文"}"#), "{req}");
    }

    #[test]
    fn 非2xx_保留响应体() {
        let (port, _h) = serve_once(leak(reply_with("404 Not Found", "missing")));
        let url = format!("http://127.0.0.1:{port}/nope");
        let r = http_raw("GET", &url, &[], None, None).unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.text, "missing");
    }

    #[test]
    fn http_text_非2xx_报错含响应体() {
        let (port, _h) = serve_once(leak(reply_with("500 Server Error", "boom")));
        let url = format!("http://127.0.0.1:{port}/nope");
        let e = http_text("GET", &url, &[], None, None).unwrap_err();
        assert!(e.0.contains("HTTP 500"), "{e:?}");
        assert!(e.0.contains("boom"), "{e:?}");
    }

    #[test]
    fn download_建目录并写文件() {
        let (port, _h) = serve_once(leak(reply("file-body")));
        let url = format!("http://127.0.0.1:{port}/f.bin");
        let dir = std::env::temp_dir().join(format!("hinstall-net-{}", std::process::id()));
        let dest = dir.join("sub/f.bin");
        let _ = std::fs::remove_dir_all(&dir);
        download(&url, &dest).unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "file-body");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
