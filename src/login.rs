//! 华为账号 OAuth 登录与凭证加载（对应 `tool.py` 的 `login` 一段）。
//!
//! 流程：本地 `127.0.0.1:8888` 收授权回调 → tempToken → jwtToken →
//! accessToken → 落盘 `data/auth.json`。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command as ProcCommand, Stdio};
use std::time::{Duration, Instant};

use crate::fail::{Fail, R};
use crate::hap_sign::json::Json;
use crate::jsonw::{display, header_value, to_jval, truthy};
use crate::net;
use crate::paths;
use crate::util;

/// 回调轮询间隔（对齐 `tool.py` 的 `time.sleep(0.3)`）。
const POLL_INTERVAL: Duration = Duration::from_millis(300);

/// 登录成功后得到的凭证。
pub struct Auth {
    /// 访问令牌，作为 `oauth2Token` 头。
    pub access_token: String,
    /// 用户 ID，作为 `uid` 头。
    pub user_id: String,
    /// 团队 ID，作为 `teamId` 头。
    pub team_id: String,
}

/// 组装云侧 API 的鉴权头。
pub fn api_headers(auth: &Auth) -> Vec<(String, String)> {
    vec![
        ("oauth2Token".to_string(), auth.access_token.clone()),
        ("teamId".to_string(), auth.team_id.clone()),
        ("uid".to_string(), auth.user_id.clone()),
    ]
}

/// 把拥有的头部列表转成请求头借用视图。
pub fn header_refs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// 执行 `login` 子命令。
pub fn cmd_login(args: &crate::cli::Args) -> R<()> {
    std::fs::create_dir_all(paths::data_dir())?;
    let temp_token = wait_temp_token(args.timeout)?;
    let url = format!(
        "{}/temptoken/check?site=CN&tempToken={}&appid=1007&version=0.0.0",
        paths::AUTH_ROUTER,
        percent_encode(&temp_token)
    );
    let text = net::http_text(
        "GET",
        &url,
        &[],
        None,
        Some(&paths::data_dir().join("raw_temptoken.txt")),
    )?
    .trim()
    .to_string();

    // 两种可能：直接回 JWT，或回 `{"ret":{"msg":"<jwt>"}}`。
    let jwt_token = if text.starts_with("eyJ") {
        text
    } else {
        let parsed = Json::parse(&text).map_err(|_| {
            Fail(format!(
                "响应非 JSON: {url}\n{}",
                util::truncate(&text, 2000)
            ))
        })?;
        let ret = net::require(&parsed, "ret", "temptoken/check")?;
        let msg = net::require(ret, "msg", "temptoken/check")?;
        msg.as_str()
            .ok_or_else(|| Fail("temptoken/check 的 ret.msg 不是字符串".into()))?
            .to_string()
    };

    let resp = net::http_json(
        "GET",
        &format!("{}/jwToken/check", paths::AUTH_ROUTER),
        &[("refresh", "false"), ("jwtToken", &jwt_token)],
        None,
        Some(&paths::data_dir().join("raw_jwtoken.json")),
    )?;
    let user_info = resp
        .get("userInfo")
        .filter(|v| truthy(v))
        .or_else(|| {
            resp.get("body")
                .and_then(|b| b.get("userInfo"))
                .filter(|v| truthy(v))
        })
        .ok_or_else(|| {
            Fail(format!(
                "jwToken/check 缺 userInfo: {}",
                util::truncate(&to_jval(&resp).to_compact(), 600)
            ))
        })?;
    let access_token = net::require(user_info, "accessToken", "userInfo")?
        .as_str()
        .ok_or_else(|| Fail("userInfo.accessToken 不是字符串".into()))?
        .to_string();
    let user_id = user_info
        .get("userId")
        .filter(|v| truthy(v))
        .or_else(|| user_info.get("userID").filter(|v| truthy(v)))
        .ok_or_else(|| {
            Fail(format!(
                "userInfo 缺 userId: {}",
                util::truncate(&to_jval(user_info).to_compact(), 600)
            ))
        })?;
    let nick_name = user_info
        .get("nickName")
        .cloned()
        .unwrap_or(Json::Str(String::new()));

    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Fail(format!("系统时间异常: {e}")))?
        .as_secs() as i64;
    let auth = Json::Obj(vec![
        ("fetched_at".to_string(), Json::Num(fetched_at as f64)),
        ("accessToken".to_string(), Json::Str(access_token)),
        ("userId".to_string(), user_id.clone()),
        ("teamId".to_string(), user_id.clone()),
        ("nickName".to_string(), nick_name.clone()),
        ("jwtToken".to_string(), Json::Str(jwt_token)),
    ]);
    let auth_file = paths::auth_file();
    util::write(&auth_file, to_jval(&auth).to_indent1().as_bytes())?;
    util::set_mode_600(&auth_file)?;
    println!(
        "登录成功: {} (uid={}) → {}",
        display(&nick_name),
        header_value(user_id),
        auth_file.display()
    );
    Ok(())
}

/// 校验本地凭证仍然有效，并返回它。
pub fn load_auth() -> R<Auth> {
    let auth_file = paths::auth_file();
    if !auth_file.exists() {
        return Err(Fail(format!(
            "缺少登录凭证，请先执行: {}",
            paths::LOGIN_HINT
        )));
    }
    let text = util::read_to_string(&auth_file)?;
    let obj =
        Json::parse(&text).map_err(|_| Fail(format!("{} 不是合法 JSON", auth_file.display())))?;
    let auth = Auth {
        access_token: net::require(&obj, "accessToken", "auth.json")?
            .as_str()
            .ok_or_else(|| Fail("auth.json 的 accessToken 不是字符串".into()))?
            .to_string(),
        user_id: header_value(net::require(&obj, "userId", "auth.json")?),
        team_id: header_value(net::require(&obj, "teamId", "auth.json")?),
    };

    let expired = || {
        Fail(format!(
            "登录 token 已过期，请重新执行: {}",
            paths::LOGIN_HINT
        ))
    };
    let url = format!(
        "{}/ups/user-permission-service/v1/user-team-list",
        paths::CONNECT_API
    );
    let headers = api_headers(&auth);
    let reply = net::http_raw("GET", &url, &header_refs(&headers), None, None)?;
    if reply.status == 401 {
        return Err(expired());
    }
    if !(200..300).contains(&reply.status) {
        return Err(Fail(format!(
            "token 校验失败 HTTP {}: {}",
            reply.status,
            util::truncate(&reply.text, 300)
        )));
    }
    if let Ok(result) = Json::parse(&reply.text)
        && let Some(code) = result.get("ret").and_then(|r| r.get("code"))
        && (code.as_f64() == Some(401.0) || code.as_str() == Some("401"))
    {
        return Err(expired());
    }
    Ok(auth)
}

/// 起本地回调服务，等浏览器把 tempToken 送回来。
pub fn wait_temp_token(timeout_s: u64) -> R<String> {
    let listener = TcpListener::bind(("127.0.0.1", paths::CALLBACK_PORT)).map_err(|e| {
        Fail(format!(
            "监听 127.0.0.1:{} 失败(端口占用?): {e}",
            paths::CALLBACK_PORT
        ))
    })?;
    listener.set_nonblocking(true)?;
    println!(
        "等待浏览器授权回调(最长 {timeout_s}s)...\n授权页: {}",
        paths::APPLY_URL
    );
    open_in_browser(paths::APPLY_URL);
    println!("如未自动打开，请手动访问上方链接并用华为开发者账号登录。");
    println!("正在等待登陆成功回调...");

    let deadline = Instant::now() + Duration::from_secs(timeout_s);
    let mut collected: Option<Vec<(String, String)>> = None;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if let Some(params) = handle_connection(&mut stream) {
                    collected = Some(params);
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => return Err(Fail(format!("回调监听失败: {e}"))),
        }
    }
    // 先释放端口再继续，避免后续步骤占着 8888。
    drop(listener);

    let params = collected
        .ok_or_else(|| Fail("超时未收到回调。请确认浏览器完成授权且账号具备开发者权限。".into()))?;
    let keys: Vec<&str> = params.iter().map(|(k, _)| k.as_str()).collect();
    println!("回调参数: {keys:?}");
    params
        .iter()
        .find(|(k, _)| k == "tempToken")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| {
            let dump: Vec<String> = params.iter().map(|(k, v)| format!("  {k} = {v}")).collect();
            Fail(format!(
                "响应缺少字段 tempToken (回调参数以实际为准，上方已打印 keys):\n{}",
                dump.join("\n")
            ))
        })
}

/// 处理一次回调连接；没有拿到参数时返回 `None`。
fn handle_connection(stream: &mut TcpStream) -> Option<Vec<(String, String)>> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let body = if method == "POST" && content_length > 0 {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf).ok()?;
        buf
    } else {
        Vec::new()
    };

    let params = collect_params(&target, &body);
    let page = if params.is_empty() {
        "缺少回调参数"
    } else {
        "登录成功！请返回。"
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        page.len(),
        page
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    if params.is_empty() {
        None
    } else {
        Some(params)
    }
}

/// 收集回调参数，等价于 `tool.py` 的 `_CallbackHandler._accept`。
fn collect_params(target: &str, body: &[u8]) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some((_, query)) = target.split_once('?') {
        for (k, v) in parse_qs(query) {
            set(&mut params, k, v);
        }
    }
    let text = String::from_utf8_lossy(body).into_owned();
    if !text.trim().is_empty() {
        match Json::parse(&text) {
            Ok(Json::Obj(pairs)) => {
                for (k, v) in pairs {
                    let value = match v {
                        Json::Str(s) => s,
                        other => to_jval(&other).to_compact(),
                    };
                    set(&mut params, k, value);
                }
            }
            // 合法 JSON 但不是对象：Python 侧同样什么都不加。
            Ok(_) => {}
            Err(_) => {
                for (k, v) in parse_qs(&text) {
                    insert_if_absent(&mut params, k, v);
                }
            }
        }
    }
    if params.is_empty() && !text.trim().is_empty() {
        // 回调 body 可能是裸 tempToken（没有 key=value 结构）。
        params.push(("tempToken".to_string(), text.trim().to_string()));
    }
    params
}

/// 覆盖写入。
fn set(params: &mut Vec<(String, String)>, key: String, value: String) {
    match params.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => params.push((key, value)),
    }
}

/// 仅在缺失时写入（对应 Python 的 `setdefault`）。
fn insert_if_absent(params: &mut Vec<(String, String)>, key: String, value: String) {
    if !params.iter().any(|(k, _)| *k == key) {
        params.push((key, value));
    }
}

/// 解析 `k=v&k2=v2`，忽略空值，`+` 视为空格。
fn parse_qs(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if v.is_empty() {
            continue;
        }
        out.push((percent_decode(k), percent_decode(v)));
    }
    out
}

/// 百分号解码（对应 `urllib.parse.unquote_plus`）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 百分号编码（对应 `urllib.parse.quote`，保留 `-_.~/`）。
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/');
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// 尽力打开浏览器；失败不影响流程，链接已经打印出来了。
fn open_in_browser(url: &str) {
    let _ = ProcCommand::new("xdg-open")
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}
