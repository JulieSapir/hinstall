//! 文件读写、权限与文本处理的公共小工具。

use std::path::Path;

use crate::fail::{Fail, R};

/// 系统随机源（rand_core 0.10）。
///
/// rand_core 0.10 是纯 trait crate，不再提供 `OsRng`；getrandom 0.4 开了 `sys_rng`
/// 后提供的 `SysRng` 是失败可能型，用 `UnwrapErr` 包一层得到 `CryptoRng`。
pub fn os_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

/// 按字符截断，避免切断多字节字符（对齐 Python 的 `s[:n]`）。
pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    s.chars().take(n).collect()
}

/// 读整个文件。
pub fn read(path: &Path) -> R<Vec<u8>> {
    std::fs::read(path).map_err(|e| Fail(format!("读取 {} 失败: {e}", path.display())))
}

/// 读整个文件为文本（严格 UTF-8，不做替换解码）。
pub fn read_to_string(path: &Path) -> R<String> {
    std::fs::read_to_string(path).map_err(|e| Fail(format!("读取 {} 失败: {e}", path.display())))
}

/// 写整个文件，必要时创建父目录。
pub fn write(path: &Path, data: &[u8]) -> R<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Fail(format!("创建目录 {} 失败: {e}", dir.display())))?;
    }
    std::fs::write(path, data).map_err(|e| Fail(format!("写入 {} 失败: {e}", path.display())))
}

/// 把文件权限设为仅属主可读写（对应 `os.chmod(path, 0o600)`）。
pub fn set_mode_600(path: &Path) -> R<()> {
    set_mode(path, 0o600)
}

/// 设置文件权限。
pub fn set_mode(path: &Path, mode: u32) -> R<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| Fail(format!("设置 {} 权限失败: {e}", path.display())))
}
