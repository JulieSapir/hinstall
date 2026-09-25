//! 路径与常量（对应 `tool.py` 的「路径与常量」章节）。

use std::path::PathBuf;

use crate::fail::{Fail, R};
use crate::util;

/// 鉴权路由基址。
pub const AUTH_ROUTER: &str = "https://cn.devecostudio.huawei.com/authrouter/auth/api";

/// 浏览器授权页。
pub const APPLY_URL: &str = "https://cn.devecostudio.huawei.com/console/DevEcoIDE/apply?port=8888&appid=1007&code=20698961dd4f420c8b44f49010c6f0cc";

/// 云侧业务 API 基址。
pub const CONNECT_API: &str = "https://connect-api.cloud.huawei.com/api";

/// 本地回调监听端口。
pub const CALLBACK_PORT: u16 = 8888;

/// 申请调试证书时使用的名称。
pub const CERT_NAME: &str = "quantum-debug";

/// 默认签名算法。
pub const SIGN_ALG: &str = "SHA256withECDSA";

/// 默认 compatibleVersion。
pub const DEFAULT_COMPATIBLE_VERSION: u32 = 9;

/// 支持的签名算法名（对应 `sorted(SIGN_ALG_TABLE)`）。
pub const SIGN_ALGS: [&str; 4] = [
    "SHA256withECDSA",
    "SHA256withRSA",
    "SHA384withECDSA",
    "SHA512withECDSA",
];

/// 登录命令提示串（替换掉 `tool.py` 里写死的 `hap_sign.py login`）。
pub const LOGIN_HINT: &str = "hinstall login";

/// 工具根目录：可执行文件所在目录。
///
/// 对应 `tool.py` 的 `ROOT = Path(__file__).resolve().parent`——`res/` 与
/// `data/` 都相对它解析，因此产物要和 `res/`、`data/` 放在同一层。
pub fn root() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("无法确定可执行文件路径: {e}"));
    exe.parent()
        .unwrap_or_else(|| panic!("可执行文件路径 {} 没有父目录", exe.display()))
        .to_path_buf()
}

/// 预置资源目录。
pub fn res_dir() -> PathBuf {
    root().join("res")
}

/// 运行期数据目录，可用环境变量 `HAP_SIGN_DATA` 覆盖。
pub fn data_dir() -> PathBuf {
    match std::env::var_os("HAP_SIGN_DATA") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => root().join("data"),
    }
}

/// 登录凭证文件。
pub fn auth_file() -> PathBuf {
    data_dir().join("auth.json")
}

/// 本地 EC 私钥。
pub fn key_file() -> PathBuf {
    data_dir().join("hinstall.key")
}

/// 本地 CSR。
pub fn csr_file() -> PathBuf {
    data_dir().join("hinstall.csr")
}

/// 云端签发的调试证书链。
pub fn cer_file() -> PathBuf {
    data_dir().join("hinstall-debug.cer")
}

/// 云端签发的调试 Profile。
pub fn p7b_file() -> PathBuf {
    data_dir().join("debug-profile.p7b")
}

/// 从上层工程的 `ohos/AppScope/app.json5` 读取 `bundleName`。
pub fn bundle_name() -> R<String> {
    let aj = root()
        .parent()
        .ok_or_else(|| Fail("无法定位工程根目录".into()))?
        .join("ohos/AppScope/app.json5");
    if !aj.exists() {
        return Err(Fail(format!(
            "找不到 {}，无法读取 bundleName（可用 --bundle 指定）",
            aj.display()
        )));
    }
    let text = util::read_to_string(&aj)?;
    extract_bundle_name(&text).ok_or_else(|| Fail(format!("{} 中无 bundleName", aj.display())))
}

/// 等价于 `re.search(r'"bundleName"\s*:\s*"([^"]+)"', text)`。
fn extract_bundle_name(text: &str) -> Option<String> {
    const KEY: &str = "\"bundleName\"";
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(KEY) {
        let after_key = from + rel + KEY.len();
        let mut i = after_key;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b':' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'"' {
                i += 1;
                let value_start = i;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
                if i < bytes.len() {
                    return Some(text[value_start..i].to_string());
                }
            }
        }
        // 这一处不是我们要的形状，从 key 之后继续找下一个。
        from = after_key;
    }
    None
}
