//! `init` 子命令（对应 `tool.py` 的 `cmd_init`）：注册设备 / 申请调试证书 /
//! 申请调试 Profile。

use std::path::Path;

use crate::cli::Args;
use crate::fail::{Fail, R};
use crate::hap_sign::json::Json;
use crate::jsonw::{JVal, arr_field, display, int_field, pretty, str_field, to_jval};
use crate::login;
use crate::net::{download, http_json, require};
use crate::paths::{self, CERT_NAME, CONNECT_API};
use crate::util;

/// AGC 调试证书配额。
const MAX_DEBUG_CERTS: usize = 3;

/// 执行 `init`。
pub fn cmd_init(args: &Args) -> R<()> {
    let auth = login::load_auth()?;
    crate::pki::ensure_materials()?;
    let headers_owned = login::api_headers(&auth);
    let headers = login::header_refs(&headers_owned);
    let udid = crate::device_ops::get_udid(args.udid.as_deref(), args.device.as_deref())?;
    let bundle = match &args.bundle {
        Some(b) => b.clone(),
        None => paths::bundle_name()?,
    };
    let data = paths::data_dir();

    // 1) 设备：不存在则注册（deviceType=4）
    let list_url =
        format!("{CONNECT_API}/cps/device-manage/v1/device/list?start=1&pageSize=100&encodeFlag=0");
    let mut devices = device_list(
        &list_url,
        &headers,
        Some(&data.join("raw_device_list.json")),
    )?;
    if !has_udid(&devices, &udid) {
        let device_name = args
            .device_name
            .clone()
            .unwrap_or_else(|| format!("quantum-dev-{}", util::truncate(&udid, 10)));
        http_json(
            "POST",
            &format!("{CONNECT_API}/cps/device-manage/v1/device/add"),
            &headers,
            Some(&JVal::Obj(vec![
                ("deviceName".to_string(), JVal::Str(device_name)),
                ("udid".to_string(), JVal::Str(udid.clone())),
                ("deviceType".to_string(), JVal::Int(4)),
            ])),
            Some(&data.join("raw_device_add.json")),
        )?;
        devices = device_list(&list_url, &headers, None)?;
    }
    if !has_udid(&devices, &udid) {
        return Err(Fail(format!(
            "设备注册后仍查不到 udid={udid}，请检查账号设备配额"
        )));
    }
    let mut device_ids: Vec<JVal> = Vec::with_capacity(devices.len());
    for device in &devices {
        device_ids.push(to_jval(require(device, "id", "device/list")?));
    }
    println!("设备清单: {} 台", device_ids.len());

    // 2) 调试证书（certType=1）
    let cert_resp = http_json(
        "GET",
        &format!("{CONNECT_API}/cps/harmony-cert-manage/v1/cert/list"),
        &headers,
        None,
        Some(&data.join("raw_cert_list.json")),
    )?;
    let mut debug_certs: Vec<Json> = arr_field(&cert_resp, "certList", "cert/list")?
        .into_iter()
        .filter(|c| int_field(c, "certType") == Some(1))
        .collect();
    let mut existing = debug_certs
        .iter()
        .find(|c| str_field(c, "certName").as_deref() == Some(CERT_NAME))
        .cloned();

    if existing.is_some() && !paths::cer_file().exists() {
        println!("本地证书缺失(密钥不匹配)，删除云端旧证书重建...");
        let id = require(
            existing.as_ref().expect("刚刚判过是 Some"),
            "id",
            "cert/list",
        )?;
        delete_cert(&headers, id)?;
        existing = None;
    }

    let cert_id = match existing {
        Some(cert) => {
            let id = require(&cert, "id", "cert/list")?.clone();
            println!("复用云端证书 {CERT_NAME} (id={})", display(&id));
            id
        }
        None => {
            if debug_certs.len() >= MAX_DEBUG_CERTS {
                // 配额满时删最旧的一张（按 expireTime 升序取第一个）。
                debug_certs.sort_by_key(|c| int_field(c, "expireTime").unwrap_or(0));
                delete_cert(&headers, require(&debug_certs[0], "id", "cert/list")?)?;
            }
            let csr = util::read_to_string(&paths::csr_file())?;
            let resp = http_json(
                "POST",
                &format!("{CONNECT_API}/cps/harmony-cert-manage/v1/cert/add"),
                &headers,
                Some(&JVal::Obj(vec![
                    ("csr".to_string(), JVal::Str(csr)),
                    ("certName".to_string(), JVal::Str(CERT_NAME.to_string())),
                    ("certType".to_string(), JVal::Int(1)),
                ])),
                Some(&data.join("raw_cert_add.json")),
            )?;
            let harmony_cert = require(&resp, "harmonyCert", "cert/add")?;
            let cert_id = require(harmony_cert, "id", "harmonyCert")?.clone();
            let object_id = require(harmony_cert, "certObjectId", "harmonyCert")?;

            let urls = http_json(
                "POST",
                &format!("{CONNECT_API}/amis/app-manage/v1/objects/url/reapply"),
                &headers,
                Some(&JVal::Obj(vec![(
                    "sourceUrls".to_string(),
                    to_jval(object_id),
                )])),
                Some(&data.join("raw_reapply.json")),
            )?;
            let urls_info = require(&urls, "urlsInfo", "reapply")?;
            let first = urls_info.as_arr().and_then(|a| a.first()).ok_or_else(|| {
                Fail(format!(
                    "reapply 的 urlsInfo 不是非空数组:\n{}",
                    util::truncate(&pretty(&urls), 2000)
                ))
            })?;
            let new_url = require(first, "newUrl", "urlsInfo[0]")?
                .as_str()
                .ok_or_else(|| Fail("urlsInfo[0].newUrl 不是字符串".into()))?;
            download(new_url, &paths::cer_file())?;
            println!(
                "证书: {} (id={})",
                file_name(&paths::cer_file()),
                display(&cert_id)
            );
            cert_id
        }
    };

    // 3) 调试 Profile（全部设备 + 本证书 + 包名）
    let resp = http_json(
        "POST",
        &format!("{CONNECT_API}/cps/provision-manage/v1/ide/test/provision/add"),
        &headers,
        Some(&JVal::Obj(vec![
            (
                "provisionName".to_string(),
                JVal::Str(format!("quantum-debug-{bundle}")),
            ),
            ("aclPermissionList".to_string(), JVal::Arr(Vec::new())),
            ("deviceList".to_string(), JVal::Arr(device_ids)),
            ("certList".to_string(), JVal::Arr(vec![to_jval(&cert_id)])),
            ("packageName".to_string(), JVal::Str(bundle.clone())),
        ])),
        Some(&data.join("raw_provision_add.json")),
    )?;
    let url = require(&resp, "provisionFileUrl", "provision/add")?
        .as_str()
        .ok_or_else(|| Fail("provision/add 的 provisionFileUrl 不是字符串".into()))?;
    download(url, &paths::p7b_file())?;
    println!(
        "Profile: {} (bundle={bundle})",
        file_name(&paths::p7b_file())
    );
    println!("init 完成，可执行 sign。");
    Ok(())
}

/// 拉取云端设备清单。
fn device_list(url: &str, headers: &[(&str, &str)], raw_dump: Option<&Path>) -> R<Vec<Json>> {
    let resp = http_json("GET", url, headers, None, raw_dump)?;
    arr_field(&resp, "list", "device/list")
}

/// 清单里是否已有该 UDID。
fn has_udid(devices: &[Json], udid: &str) -> bool {
    devices
        .iter()
        .any(|d| str_field(d, "udid").as_deref() == Some(udid))
}

/// 删除一张云端证书。
fn delete_cert(headers: &[(&str, &str)], cert_id: &Json) -> R<()> {
    http_json(
        "DELETE",
        &format!("{CONNECT_API}/cps/harmony-cert-manage/v1/cert/delete"),
        headers,
        Some(&JVal::Obj(vec![(
            "certIds".to_string(),
            JVal::Arr(vec![to_jval(cert_id)]),
        )])),
        None,
    )?;
    Ok(())
}

/// 取文件名用于展示。
fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}
