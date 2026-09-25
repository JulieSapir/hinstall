//! `install` 与 `status` 子命令（对应 `tool.py` 的 `cmd_install` / `cmd_status`）。

use std::path::PathBuf;

use crate::cli::Args;
use crate::fail::{Fail, R};
use crate::hap_sign::json::Json;
use crate::jsonw::{display, int_field, str_field};
use crate::paths;
use crate::util;

/// 收集待安装的包。
///
/// 显式给了 hap 就只装它；否则取上层工程 `build/ohos/hap` 下的
/// `*-signed.hap` 与 `*-signed.hsp`。
pub fn collect_sources(hap: Option<&str>) -> R<Vec<PathBuf>> {
    if let Some(h) = hap {
        return Ok(vec![PathBuf::from(h)]);
    }
    let directory = paths::root()
        .parent()
        .ok_or_else(|| Fail("无法定位工程根目录".into()))?
        .join("build/ohos/hap");
    let mut sources: Vec<PathBuf> = std::fs::read_dir(&directory)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    name.ends_with("-signed.hap") || name.ends_with("-signed.hsp")
                })
                .collect()
        })
        .unwrap_or_default();
    sources.sort();
    if sources.is_empty() {
        return Err(Fail(format!(
            "{} 下没有 *-signed.hap/.hsp，先执行 sign",
            directory.display()
        )));
    }
    Ok(sources)
}

/// 安装给定包：可选前置卸载，然后覆盖安装并判定结果。
pub fn install_files(args: &Args, sources: &[PathBuf]) -> R<()> {
    for src in sources {
        if !src.exists() {
            return Err(Fail(format!("文件不存在: {}", src.display())));
        }
    }
    let device = args.device.as_deref();

    if args.uninstall {
        let bundle = match &args.bundle {
            Some(b) => b.clone(),
            None => paths::bundle_name()?,
        };
        // tool.py 不看卸载的返回码：包本来就不在时卸载会失败，继续装即可。
        match crate::device_ops::uninstall(device, &bundle) {
            Ok(out) => println!("{out}"),
            Err(e) => println!("卸载失败(继续安装): {e}"),
        }
    }

    let output = crate::device_ops::install(device, sources)?;
    println!("{output}");
    let lower = output.to_lowercase();
    let ok = !output.is_empty() && lower.contains("successfully") && !lower.contains("[fail");
    if !ok {
        let hint = if output.contains("9568322") || lower.contains("not trusted") {
            "\n提示: 证书不受设备信任——必须用本机 init 签发的调试证书（同一华为账号），第三方/官方测试证书无法安装到零售设备"
        } else if ["9568268", "9568289", "9568226", "9568321"]
            .iter()
            .any(|code| output.contains(code))
            || lower.contains("signature")
            || lower.contains("profile")
        {
            "\n提示: 签名或 Profile 设备不匹配——先 `signinstall --uninstall` 卸旧包重装；新设备需先跑 init 把 UDID 加进云端设备清单并刷新 Profile"
        } else {
            ""
        };
        return Err(Fail(format!("安装失败{hint}")));
    }
    let names: Vec<String> = sources.iter().map(|s| file_name(s)).collect();
    println!("安装成功: {}", names.join(", "));
    Ok(())
}

/// `install` 子命令。
pub fn cmd_install(args: &Args) -> R<()> {
    let sources = collect_sources(args.hap.as_deref())?;
    install_files(args, &sources)
}

/// `status` 子命令。
pub fn cmd_status(_args: &Args) -> R<()> {
    println!("资源目录: {}", paths::res_dir().display());
    println!("数据目录: {}", paths::data_dir().display());
    // tool.py 这里检查的是 res/hdc 与 res/libusb_shared.so；移植后设备访问走内置
    // USB 协议栈，等价的可观测项变成「能否枚举到 HDC 设备」。
    match futures_lite::future::block_on(crate::hdc::device::list_hdc_devices()) {
        Ok(devices) => println!("  USB: 枚举到 {} 台 HDC 设备", devices.len()),
        Err(e) => println!("  USB: 枚举失败 {e}"),
    }

    let auth_file = paths::auth_file();
    if auth_file.exists() {
        match Json::parse(&util::read_to_string(&auth_file)?) {
            Ok(auth) => println!(
                "登录: {} teamId={} 获取于 {}",
                str_field(&auth, "nickName").unwrap_or_else(|| "?".to_string()),
                display(auth.get("teamId").unwrap_or(&Json::Null)),
                format_local_time(int_field(&auth, "fetched_at").unwrap_or(0))?
            ),
            Err(_) => println!("登录: {} 不是合法 JSON", auth_file.display()),
        }
    } else {
        println!("登录: 未执行");
    }

    for path in [
        paths::key_file(),
        paths::csr_file(),
        paths::cer_file(),
        paths::p7b_file(),
    ] {
        let mark = if path.exists() { '✓' } else { '✗' };
        println!("  data/{}: {mark}", file_name(&path));
    }
    Ok(())
}

/// 本地时间 `%F %T`，对齐 Python 的 `time.strftime('%F %T', time.localtime(t))`。
fn format_local_time(unix: i64) -> R<String> {
    let seconds: libc::time_t = unix as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `localtime_r` 只往 `tm` 里写，指针在本函数栈上有效。
    if unsafe { libc::localtime_r(&seconds, &mut tm) }.is_null() {
        return Err(Fail(format!("本地时间换算失败: {unix}")));
    }
    Ok(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}

/// 取文件名用于展示。
fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}
