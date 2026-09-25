//! 命令行解析（对齐 `tool.py` 里 argparse 的定义）。
//!
//! 支持 `--opt value` 与 `--opt=value` 两种写法，以及
//! `--sign-code` / `--no-sign-code`、`--permission-sign` / `--no-permission-sign`
//! 这类布尔开关。用法错误按 argparse 的习惯以退出码 2 结束。

use crate::paths;

/// 解析后的全部参数。
#[derive(Debug)]
pub struct Args {
    /// 子命令名。
    pub cmd: String,
    /// `login --timeout`。
    pub timeout: u64,
    /// `init --udid`。
    pub udid: Option<String>,
    /// `init --device-name`。
    pub device_name: Option<String>,
    /// `init/install/signinstall --bundle`。
    pub bundle: Option<String>,
    /// 位置参数 hap 路径（`sign` / `install` / `signinstall`）。
    pub hap: Option<String>,
    /// `sign --cert`。
    pub cert: Option<String>,
    /// `sign --profile`。
    pub profile: Option<String>,
    /// `sign --key`。
    pub key: Option<String>,
    /// `sign --sign-alg`。
    pub sign_alg: String,
    /// `sign --compatible-version`。
    pub compatible_version: u32,
    /// `sign --sign-code` / `--no-sign-code`。
    pub sign_code: bool,
    /// `sign --permission-sign` / `--no-permission-sign`。
    pub permission_sign: bool,
    /// `sign --out`。
    pub out: Option<String>,
    /// `install --device`。
    pub device: Option<String>,
    /// `install --uninstall`。
    pub uninstall: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            cmd: String::new(),
            timeout: 300,
            udid: None,
            device_name: None,
            bundle: None,
            hap: None,
            cert: None,
            profile: None,
            key: None,
            sign_alg: paths::SIGN_ALG.to_string(),
            compatible_version: paths::DEFAULT_COMPATIBLE_VERSION,
            sign_code: true,
            permission_sign: true,
            out: None,
            device: None,
            uninstall: false,
        }
    }
}

/// 解析结果。
pub enum Parsed {
    /// 参数可用。
    Run(Args),
    /// 已经输出过帮助或用法错误，按给定退出码结束。
    Exit(i32),
}

/// 子命令列表。
const COMMANDS: [&str; 6] = ["login", "init", "sign", "install", "signinstall", "status"];

/// 解析命令行。
pub fn parse(argv: &[String]) -> Parsed {
    let Some(cmd) = argv.first() else {
        return usage_error("缺少子命令".to_string());
    };
    if cmd == "-h" || cmd == "--help" {
        print_help();
        return Parsed::Exit(0);
    }
    if !COMMANDS.contains(&cmd.as_str()) {
        return usage_error(format!("未知子命令: {cmd}（可选: {}）", COMMANDS.join(" ")));
    }

    let mut args = Args {
        cmd: cmd.clone(),
        ..Default::default()
    };
    let rest = &argv[1..];
    let mut i = 0usize;
    while i < rest.len() {
        let token = rest[i].as_str();
        if token == "-h" || token == "--help" {
            print_help();
            return Parsed::Exit(0);
        }
        let (opt, inline) = match token.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v)),
            _ => (token, None),
        };
        if opt.starts_with("--") {
            if !allowed(&args.cmd, opt) {
                return usage_error(format!("{} 不支持选项 {opt}", args.cmd));
            }
            let value = match inline {
                Some(v) => Some(v),
                None => {
                    if is_flag(opt) {
                        None
                    } else {
                        i += 1;
                        match rest.get(i) {
                            Some(v) => Some(v.as_str()),
                            None => return usage_error(format!("选项 {opt} 需要一个值")),
                        }
                    }
                }
            };
            if let Err(msg) = apply(&mut args, opt, value) {
                return usage_error(msg);
            }
        } else if token.starts_with('-') && token.len() > 1 {
            return usage_error(format!("未知选项: {token}"));
        } else if args.hap.is_none() {
            args.hap = Some(token.to_string());
        } else {
            return usage_error(format!("多余的位置参数: {token}"));
        }
        i += 1;
    }

    if matches!(args.cmd.as_str(), "sign" | "signinstall") && args.hap.is_none() {
        return usage_error(format!("{} 缺少参数 hap", args.cmd));
    }
    Parsed::Run(args)
}

/// 该选项是否属于该子命令。
fn allowed(cmd: &str, opt: &str) -> bool {
    const SIGN: [&str; 10] = [
        "--cert",
        "--profile",
        "--key",
        "--sign-alg",
        "--compatible-version",
        "--sign-code",
        "--no-sign-code",
        "--permission-sign",
        "--no-permission-sign",
        "--out",
    ];
    const INSTALL: [&str; 3] = ["--device", "--uninstall", "--bundle"];
    match cmd {
        "login" => opt == "--timeout",
        "init" => matches!(opt, "--udid" | "--device-name" | "--bundle"),
        "sign" => SIGN.contains(&opt),
        "install" => INSTALL.contains(&opt),
        "signinstall" => SIGN.contains(&opt) || INSTALL.contains(&opt),
        _ => false,
    }
}

/// 是否是无需取值的开关型选项。
fn is_flag(opt: &str) -> bool {
    matches!(
        opt,
        "--sign-code"
            | "--no-sign-code"
            | "--permission-sign"
            | "--no-permission-sign"
            | "--uninstall"
    )
}

/// 把一个选项写进参数结构。
fn apply(args: &mut Args, opt: &str, value: Option<&str>) -> Result<(), String> {
    let text = |value: Option<&str>| -> Result<String, String> {
        value
            .map(str::to_string)
            .ok_or_else(|| format!("选项 {opt} 需要一个值"))
    };
    match opt {
        "--timeout" => {
            args.timeout = text(value)?
                .parse()
                .map_err(|_| "--timeout 需要整数".to_string())?
        }
        "--udid" => args.udid = Some(text(value)?),
        "--device-name" => args.device_name = Some(text(value)?),
        "--bundle" => args.bundle = Some(text(value)?),
        "--cert" => args.cert = Some(text(value)?),
        "--profile" => args.profile = Some(text(value)?),
        "--key" => args.key = Some(text(value)?),
        // tool.py 用 argparse 的 choices 拦非法算法（退出码 2），这里保持同一层拦截
        "--sign-alg" => {
            let alg = text(value)?;
            if !paths::SIGN_ALGS.contains(&alg.as_str()) {
                return Err(format!(
                    "--sign-alg 取值非法: {alg}（可选: {}）",
                    paths::SIGN_ALGS.join(", ")
                ));
            }
            args.sign_alg = alg;
        }
        "--compatible-version" => {
            args.compatible_version = text(value)?
                .parse()
                .map_err(|_| "--compatible-version 需要整数".to_string())?
        }
        "--sign-code" => args.sign_code = true,
        "--no-sign-code" => args.sign_code = false,
        "--permission-sign" => args.permission_sign = true,
        "--no-permission-sign" => args.permission_sign = false,
        "--out" => args.out = Some(text(value)?),
        "--device" => args.device = Some(text(value)?),
        "--uninstall" => args.uninstall = true,
        other => return Err(format!("未知选项: {other}")),
    }
    Ok(())
}

/// 打印用法错误并按退出码 2 结束。
fn usage_error(msg: String) -> Parsed {
    eprintln!("用法: hinstall <{}> [选项]", COMMANDS.join("|"));
    eprintln!("错误: {msg}");
    Parsed::Exit(2)
}

/// 打印帮助。
fn print_help() {
    println!(
        "hinstall —— 华为 HAP 调试签名与安装工具\n\
         \n\
         用法: hinstall <命令> [选项]\n\
         \n\
         命令:\n\
         \x20 login        华为账号 OAuth 登录\n\
         \x20 init         注册设备/证书/Profile\n\
         \x20 sign         对 hap 签名（纯本地算法）\n\
         \x20 install      安装签名产物到设备\n\
         \x20 signinstall  签名后直接安装（产物固定 data/signed.hap）\n\
         \x20 status       查看状态\n\
         \n\
         通用选项:\n\
         \x20 -h, --help   显示本帮助\n\
         \n\
         login 选项:\n\
         \x20 --timeout <秒>              等待回调的超时，默认 300\n\
         \n\
         init 选项:\n\
         \x20 --udid <UDID>               手动指定设备 UDID\n\
         \x20 --device-name <名称>        云端设备名，默认 quantum-dev-<udid 前 10 位>\n\
         \x20 --bundle <包名>             默认读 ohos/AppScope/app.json5\n\
         \n\
         sign / signinstall 选项:\n\
         \x20 --cert <路径>               证书链，缺省 data/hinstall-debug.cer\n\
         \x20 --profile <路径>            Profile，缺省 data/debug-profile.p7b\n\
         \x20 --key <路径>                私钥 PEM，缺省 data/hinstall.key\n\
         \x20 --sign-alg <算法>           默认 {}，可选 {}\n\
         \x20 --compatible-version <n>   默认 {}\n\
         \x20 --sign-code / --no-sign-code\n\
         \x20 --permission-sign / --no-permission-sign\n\
         \x20 --out <路径>                仅 sign：输出路径\n\
         \n\
         install / signinstall 选项:\n\
         \x20 --device <connectkey>      多设备时指定目标\n\
         \x20 --uninstall                 先卸载旧包再安装\n\
         \x20 --bundle <包名>            卸载用包名，缺省读 ohos/AppScope/app.json5\n",
        paths::SIGN_ALG,
        paths::SIGN_ALGS.join(", "),
        paths::DEFAULT_COMPATIBLE_VERSION
    );
}

/// 供 `main` 使用的便捷包装：拿不到参数就直接退出。
pub fn args_or_exit(argv: &[String]) -> Args {
    match parse(argv) {
        Parsed::Run(args) => args,
        Parsed::Exit(code) => std::process::exit(code),
    }
}
