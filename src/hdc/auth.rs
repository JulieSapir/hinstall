// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! 设备认证（官方 `HdcDaemon::HandDaemonAuth*` 的 host 侧对应实现）。
//!
//! 真机实测：设备端 `authEnable` 为真，握手时回 `authType = AUTH_PUBLICKEY`。
//! 此时**任何**业务命令都会被 `HdcDaemon::CheckAuthStatus` 拒绝 —— 表现为设备
//! 回一帧 `CMD_KERNEL_CHANNEL_CLOSE`（载荷 `01`），之后不再响应。所以认证不是
//! 可选项，而是安装等一切业务命令的前置条件。
//!
//! 完整往返共四帧，全部走 `CMD_KERNEL_HANDSHAKE`（channel 0）：
//!
//! ```text
//! host -> dev    authType=AUTH_NONE       buf=authtype TLV
//! dev  -> host   authType=AUTH_PUBLICKEY  buf=authtype TLV
//! host -> dev    authType=AUTH_PUBLICKEY  buf="<hostname>\x0C<公钥 PEM>"
//! dev  -> host   authType=AUTH_SIGNATURE  buf=<token>
//! host -> dev    authType=AUTH_SIGNATURE  buf=base64(RSA-PSS-SHA512(token))
//! dev  -> host   authType=AUTH_OK
//! ```
//!
//! 设备第一次见到某个公钥时会弹系统对话框要求用户确认（官方
//! `HdcDaemon::ShowPermitDialog` 拉起 `/system/bin/hdcd_user_permit`）。确认后
//! 公钥写进设备本地 known hosts，后续连接直接进入签名环节。

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::pss::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha2_10::Sha512;
use std::path::{Path, PathBuf};

use crate::hdc::error::{Error, Result};

/// 官方 `HDC_HOST_DAEMON_BUF_SEPARATOR`：主机名与公钥之间的分隔符。
const HOST_DAEMON_SEPARATOR: char = '\x0C';

/// 本机 hdc 密钥对。
///
/// 路径与官方一致（官方 `GetUserKeyPath` 取 `$HOME/.harmony/hdckey`），这样能直接
/// 复用官方 hdc 已经与设备建立信任的那对密钥，免去设备端重新确认。
#[derive(Debug, Clone)]
pub struct AuthKey {
    /// 私钥（PKCS#8 PEM）。
    private_pem: String,
    /// 公钥（SubjectPublicKeyInfo PEM）。
    public_pem: String,
    /// 本机主机名，设备侧仅记录不校验。
    hostname: String,
}

impl AuthKey {
    /// 用现成的 PEM 文本构造。
    pub fn new(
        private_pem: impl Into<String>,
        public_pem: impl Into<String>,
        hostname: impl Into<String>,
    ) -> Self {
        Self {
            private_pem: private_pem.into(),
            public_pem: public_pem.into(),
            hostname: hostname.into(),
        }
    }

    /// 生成一对新的 RSA 密钥。
    ///
    /// 本机没有 `$HOME/.harmony/hdckey` 可读时走这条路，密钥现场生成后落盘。
    /// 官方 hdc 用 3072 位；生成是秒级开销。
    pub fn generate(bits: usize, hostname: impl Into<String>) -> Result<Self> {
        let private =
            RsaPrivateKey::new(&mut rand_core06::OsRng, bits).map_err(|_| Error::BadAuthKey)?;
        let public = private.to_public_key();
        let private_pem = private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| Error::BadAuthKey)?
            .to_string();
        let public_pem = public
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| Error::BadAuthKey)?;
        Ok(Self::new(private_pem, public_pem, hostname))
    }

    /// 读取官方 hdc 的密钥对（`$HOME/.harmony/hdckey`）。
    ///
    /// 不存在时由 [`crate::device_ops`] 调用 [`AuthKey::generate`] 现场生成并落盘。
    pub fn load_default() -> Result<Self> {
        let home = std::env::var_os("HOME").ok_or(Error::NoAuthKey)?;
        Self::load_from_dir(&PathBuf::from(home).join(".harmony"))
    }

    /// 从指定目录读取 `hdckey` 与 `hdckey.pub`。
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let private_pem =
            std::fs::read_to_string(dir.join("hdckey")).map_err(|_| Error::NoAuthKey)?;
        let public_pem =
            std::fs::read_to_string(dir.join("hdckey.pub")).map_err(|_| Error::NoAuthKey)?;
        Ok(Self {
            private_pem,
            public_pem,
            hostname: hostname()?,
        })
    }

    /// 公钥信息串：`"<hostname>\x0C<公钥 PEM>"`。
    ///
    /// 设备端 `HdcDaemon::GetHostPubkeyInfo` 按 `\x0C` 切分，两段都必须非空。
    pub fn public_key_info(&self) -> String {
        let mut out = String::with_capacity(self.hostname.len() + 1 + self.public_pem.len());
        out.push_str(&self.hostname);
        out.push(HOST_DAEMON_SEPARATOR);
        out.push_str(&self.public_pem);
        out
    }

    /// 私钥 PEM。
    ///
    /// 首次生成密钥时由 [`crate::device_ops`] 写到 `$HOME/.harmony/hdckey`。
    pub fn private_pem(&self) -> &str {
        &self.private_pem
    }

    /// 公钥 PEM。
    pub fn public_pem(&self) -> &str {
        &self.public_pem
    }

    /// 对设备下发的 token 签名，返回 base64 文本。
    ///
    /// 官方 `HdcAuth::RsaSign` 用 `RSA_PKCS1_PSS_PADDING` +
    /// `RSA_PSS_SALTLEN_DIGEST` + SHA512，`MakeRsaSign` 再 `EVP_EncodeBlock` 做
    /// base64。`rsa::pss::SigningKey` 的默认盐长就是摘要长度，与之等价。
    pub fn sign(&self, token: &[u8]) -> Result<String> {
        let private =
            RsaPrivateKey::from_pkcs8_pem(&self.private_pem).map_err(|_| Error::BadAuthKey)?;
        let signing_key = SigningKey::<Sha512>::new(private);
        let mut rng = rand_core06::OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, token);
        Ok(BASE64.encode(signature.to_bytes()))
    }
}

/// 取本机主机名。
///
/// 设备侧只把它记进日志与 known hosts 条目，不参与校验，但官方要求非空
/// （`GetHostPubkeyInfo` 会检查两段都非空）。
/// 本机主机名：先取 `HOSTNAME`，再回落到 `/etc/hostname`。
pub fn hostname() -> Result<String> {
    if let Ok(name) = std::env::var("HOSTNAME")
        && !name.is_empty()
    {
        return Ok(name);
    }
    let raw = std::fs::read_to_string("/etc/hostname").map_err(|_| Error::NoAuthKey)?;
    let name = raw.trim();
    if name.is_empty() {
        return Err(Error::NoAuthKey);
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 公钥信息串用_0x0c_分隔() {
        let key = AuthKey::new("PRIV", "PUB", "myhost");
        let info = key.public_key_info();
        let (host, pubkey) = info.split_once('\x0C').expect("应当含分隔符");
        assert_eq!(host, "myhost");
        assert_eq!(pubkey, "PUB");
    }

    #[test]
    fn 坏私钥显式报错() {
        let key = AuthKey::new("not a pem", "PUB", "h");
        assert!(matches!(key.sign(b"token"), Err(Error::BadAuthKey)));
    }

    #[test]
    fn 官方密钥可签名且是_base64() {
        // 本机若没有官方密钥就跳过：该用例只在开发机上验证真实密钥路径。
        let Ok(key) = AuthKey::load_default() else {
            return;
        };
        let sig = key.sign(b"hello token").expect("签名应当成功");
        let raw = BASE64.decode(sig.as_bytes()).expect("应当是合法 base64");
        // RSA-3072 的 PSS 签名固定 384 字节。
        assert_eq!(raw.len(), 384);
        assert!(!key.public_key_info().is_empty());
    }
}
