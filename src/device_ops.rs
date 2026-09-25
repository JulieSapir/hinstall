//! 设备侧操作：取 UDID、安装、卸载。
//!
//! `tool.py` 这三件事都是 fork `res/hdc` 完成的。移植后改为纯 Rust 的 HDC over
//! USB 实现——aarch64 产物执行不了 x86_64 的 `res/hdc`（`Exec format error`），
//! 所以这里必须自己走协议。

use std::path::PathBuf;
use std::time::Duration;

use futures_lite::future::block_on;

use crate::fail::{Fail, R};
use crate::hdc::{AuthKey, Command, Frame, HdcSession, device, install};

/// 连接建立后的读超时。
///
/// `bm get --udid` 本身很快，但设备刚被唤醒时首包可能拖到数秒；安装路径
/// 由 `install::install_app` 自己放大到 300s，这里给的是握手后的通用值。
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// 官方 hdc 首次使用时生成的认证密钥位数。
const AUTH_KEY_BITS: usize = 3072;

/// 打开一条到目标设备的会话。
///
/// `device` 对应 `hdc -t <connectkey>`；USB 直连时 connectkey 就是设备序列号。
pub fn open_session(device: Option<&str>) -> R<HdcSession> {
    let infos = block_on(device::list_hdc_devices())?;
    if infos.is_empty() {
        return Err(Fail(
            "未发现 HDC 设备。请确认设备已通过 USB 连接，并已打开开发者模式与 USB 调试。".into(),
        ));
    }
    let info = match device {
        Some(key) => infos
            .iter()
            .find(|i| i.serial_number() == Some(key))
            .ok_or_else(|| {
                let online: Vec<String> = infos
                    .iter()
                    .map(|i| i.serial_number().unwrap_or("<无序列号>").to_string())
                    .collect();
                Fail(format!(
                    "未找到 connectkey={key} 的设备，当前在线: {}",
                    online.join(", ")
                ))
            })?,
        None => &infos[0],
    };
    let key = auth_key()?;
    let mut session = block_on(HdcSession::connect(info, 0, Some(&key)))?;
    session.transport_mut().set_io_timeout(IO_TIMEOUT);
    Ok(session)
}

/// 取 HDC 认证密钥；本地没有时按官方 hdc 的行为在 `$HOME/.harmony` 下生成。
///
/// 设备端 `authEnable` 打开时握手会要求公钥认证，没有密钥就无法完成握手。
fn auth_key() -> R<AuthKey> {
    if let Ok(key) = AuthKey::load_default() {
        return Ok(key);
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Fail("环境变量 HOME 未设置，无法定位 ~/.harmony/hdckey".into()))?;
    let dir = PathBuf::from(home).join(".harmony");
    std::fs::create_dir_all(&dir)?;
    let key = AuthKey::generate(AUTH_KEY_BITS, crate::hdc::auth::hostname()?)?;
    let private = dir.join("hdckey");
    std::fs::write(&private, key.private_pem())?;
    std::fs::write(dir.join("hdckey.pub"), key.public_pem())?;
    crate::util::set_mode_600(&private)?;
    println!(
        "已生成 HDC 认证密钥 {}（设备会弹出授权提示）",
        private.display()
    );
    Ok(key)
}

/// 生成一个非 0 通道号（对齐官方 `GetChannelPseudoUid`）。
fn random_channel_id() -> R<u32> {
    loop {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).map_err(|_| Fail("系统随机数不可用".into()))?;
        let id = u32::from_be_bytes(buf);
        if id != 0 {
            return Ok(id);
        }
    }
}

/// 在设备上跑一条 shell 命令，返回合并后的 stdout/stderr。
///
/// 对应官方 `hdc shell <cmd>`：请求以 `UnityExecute` 发到一条新通道，设备把
/// 输出用 `KernelEchoRaw` 帧流回来，最后以 `KernelChannelClose` 收尾。
fn shell(session: &mut HdcSession, cmd: &str) -> R<String> {
    let channel = random_channel_id()?;
    let transport = session.transport_mut();
    block_on(transport.send_packet(
        &Frame::new(channel, Command::UnityExecute, cmd.as_bytes().to_vec()).encode(),
    ))?;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let raw = block_on(transport.recv_packet())?;
        let frame = Frame::decode(&raw)?;
        if frame.channel_id != channel {
            continue;
        }
        match frame.command {
            Command::KernelEchoRaw => out.extend_from_slice(&frame.data),
            // 官方 KernelEcho 的载荷首字节是流标识，正文从第 2 字节起。
            Command::KernelEcho => {
                if frame.data.len() > 1 {
                    out.extend_from_slice(&frame.data[1..]);
                }
            }
            Command::KernelChannelClose => break,
            _ => continue,
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// 取设备 UDID（对应 `hdc shell bm get --udid`）。
pub fn get_udid(udid_arg: Option<&str>, device: Option<&str>) -> R<String> {
    if let Some(u) = udid_arg
        && !u.is_empty()
    {
        return Ok(u.to_string());
    }
    let mut session = open_session(device)?;
    let out = shell(&mut session, "bm get --udid")?;
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.to_lowercase().contains("error") {
            continue;
        }
        let token = line.rsplit(':').next().unwrap_or("").trim();
        if token.len() >= 32 {
            return Ok(token.to_string());
        }
    }
    Err(Fail(
        "取 UDID 失败。连接设备后重试，或用 --udid 手动指定。".into(),
    ))
}

/// 安装若干包（对应 `hdc install -r <files...>`），返回设备侧输出。
pub fn install(device: Option<&str>, sources: &[PathBuf]) -> R<String> {
    let mut session = open_session(device)?;
    let mut output = String::new();
    for src in sources {
        let data = crate::util::read(src)?;
        let hint = src.to_string_lossy().to_string();
        let result = block_on(install::install_app(session.transport_mut(), &data, &hint))?;
        output.push_str(&result.message);
        output.push('\n');
    }
    Ok(output.trim().to_string())
}

/// 卸载一个包（对应 `hdc uninstall <bundle>`），返回设备侧输出。
pub fn uninstall(device: Option<&str>, bundle: &str) -> R<String> {
    let mut session = open_session(device)?;
    let result = block_on(install::uninstall_app(session.transport_mut(), bundle))?;
    Ok(result.message.trim().to_string())
}
