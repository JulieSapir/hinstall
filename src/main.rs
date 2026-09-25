//! hinstall —— 华为 HAP 调试签名与安装工具。
//!
//! 这是 `tool.py` 的纯 Rust 重写，子命令一一对应：
//! `login` / `init` / `sign` / `install` / `signinstall` / `status`。
//!
//! 与 Python 版的唯一结构性差异：设备访问不再 fork 外部的 `hdc` 可执行文件，
//! 而是走内置的 HDC over USB 协议栈（`src/hdc/`），因此产物可以直接在
//! aarch64 上跑。

mod cli;
mod device_ops;
mod fail;
mod hap_sign;
mod hdc;
mod initcmd;
mod installcmd;
mod jsonw;
mod login;
mod net;
mod paths;
mod pki;
mod signcmd;
mod util;

use fail::R;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = cli::args_or_exit(&argv);
    let result: R<()> = match args.cmd.as_str() {
        "login" => login::cmd_login(&args),
        "init" => initcmd::cmd_init(&args),
        "sign" => signcmd::cmd_sign(&args),
        "install" => installcmd::cmd_install(&args),
        "signinstall" => signcmd::cmd_signinstall(&args),
        "status" => installcmd::cmd_status(&args),
        other => Err(fail::Fail(format!("未知子命令: {other}"))),
    };
    if let Err(e) = result {
        eprintln!("错误: {e}");
        std::process::exit(1);
    }
}
