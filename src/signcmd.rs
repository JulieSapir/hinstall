//! `sign` / `signinstall` 子命令（对应 `tool.py` 的 `_do_sign` / `cmd_sign` /
//! `cmd_signinstall`）。

use std::path::{Path, PathBuf};

use crate::cli::Args;
use crate::fail::{Fail, R};
use crate::hap_sign::crypto::{PrivateKey, SignAlg};
use crate::hap_sign::hap;
use crate::hap_sign::sign::{HapSignRequest, sign_hap};
use crate::hap_sign::x509::load_cert_chain;
use crate::paths;
use crate::util;

/// 执行签名；`out` 为 `None` 时输出 `<hap 同目录>/<name>-signed.hap`。
pub fn do_sign(args: &Args, out: Option<&Path>) -> R<PathBuf> {
    let hap_arg = args
        .hap
        .as_ref()
        .ok_or_else(|| Fail("缺少 hap 参数".into()))?;
    let hap = PathBuf::from(hap_arg);
    if !hap.exists() {
        return Err(Fail(format!("hap 文件不存在: {}", hap.display())));
    }

    let cert_file = args
        .cert
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(paths::cer_file);
    let profile_file = args
        .profile
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(paths::p7b_file);
    let key_file = args
        .key
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(paths::key_file);
    for (path, hint) in [
        (&cert_file, "证书"),
        (&profile_file, "Profile"),
        (&key_file, "私钥"),
    ] {
        if !path.exists() {
            return Err(Fail(format!(
                "缺少{hint}材料 {}，请先执行 init",
                path.display()
            )));
        }
    }

    let alg = SignAlg::from_name(&args.sign_alg).map_err(|_| {
        Fail(format!(
            "不支持的签名算法: {}（支持 {}）",
            args.sign_alg,
            paths::SIGN_ALGS.join(", ")
        ))
    })?;
    let certs = load_cert_chain(&util::read(&cert_file)?)?;
    let profile_der = util::read(&profile_file)?;
    let key = PrivateKey::from_pem(&util::read(&key_file)?)?;
    let hap_bytes = util::read(&hap)?;

    let form = hap
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // tool.py 对不支持的形态是「静默跳过」代码签名，而 `sign_hap` 会直接报错，
    // 所以先把开关收窄，保持对外行为一致。
    let support_form = hap::SUPPORTED_FORMS.contains(&form.as_str());
    let sign_code = args.sign_code && support_form;
    let permission_sign = args.permission_sign && sign_code;

    let out = match out {
        Some(p) => p.to_path_buf(),
        None => {
            let stem = hap
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Fail(format!("无法从 {} 取出文件名", hap.display())))?;
            hap.with_file_name(format!("{stem}-signed.hap"))
        }
    };

    let signed = sign_hap(&HapSignRequest {
        hap: &hap_bytes,
        certs: &certs,
        key: &key,
        profile_der: &profile_der,
        alg,
        compatible_version: args.compatible_version,
        form: &form,
        sign_code,
        permission_sign,
        sign_time: Some(signing_time()?),
    })?;
    util::write(&out, &signed)?;
    Ok(out)
}

/// `sign` 子命令。
pub fn cmd_sign(args: &Args) -> R<()> {
    let signed = do_sign(args, args.out.as_deref().map(Path::new))?;
    report(&signed)
}

/// `signinstall` 子命令：产物固定 `data/signed.hap`，重复执行直接覆盖。
pub fn cmd_signinstall(args: &Args) -> R<()> {
    std::fs::create_dir_all(paths::data_dir())?;
    let out = paths::data_dir().join("signed.hap");
    let signed = do_sign(args, Some(&out))?;
    report(&signed)?;
    crate::installcmd::install_files(args, std::slice::from_ref(&signed))
}

/// 打印签名产物信息。
fn report(signed: &Path) -> R<()> {
    let size = std::fs::metadata(signed)
        .map_err(|e| Fail(format!("读取 {} 元信息失败: {e}", signed.display())))?
        .len();
    println!("签名产物: {} ({size} bytes)", signed.display());
    Ok(())
}

/// 签名时间：默认当前 UTC 时间，可用 `HAP_SIGN_TIME` 固定以便复现。
fn signing_time() -> R<i64> {
    if let Some(fixed) = std::env::var_os("HAP_SIGN_TIME") {
        return parse_fixed_time(&fixed.to_string_lossy());
    }
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Fail(format!("系统时间异常: {e}")))?
        .as_secs() as i64)
}

/// 解析 `HAP_SIGN_TIME`（`%y%m%d%H%M%S`，UTC），返回 Unix 秒。
fn parse_fixed_time(text: &str) -> R<i64> {
    if text.len() != 12 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Fail(format!(
            "HAP_SIGN_TIME 应为 %y%m%d%H%M%S 形式的 12 位数字，收到: {text}"
        )));
    }
    let field = |range: std::ops::Range<usize>| -> R<i64> { Ok(text[range].parse::<i64>()?) };
    let yy = field(0..2)?;
    let month = field(2..4)?;
    let day = field(4..6)?;
    let hour = field(6..8)?;
    let minute = field(8..10)?;
    let second = field(10..12)?;
    // 与 Python 的 %y 一致：00-68 → 2000-2068，69-99 → 1969-1999。
    let year = if yy <= 68 { 2000 + yy } else { 1900 + yy };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(Fail(format!("HAP_SIGN_TIME 取值非法: {text}")));
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// 公历日期 → 距 1970-01-01 的天数（Howard Hinnant 的 days_from_civil）。
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
