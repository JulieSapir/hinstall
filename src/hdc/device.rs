// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! HDC 设备发现与接口匹配。
//!
//! 匹配条件与官方 `src/host/host_usb.cpp` 的 `IsDebuggableDev` 一致：
//! `bInterfaceClass = 0xff`、`bInterfaceSubClass = 0x50`、
//! `bInterfaceProtocol = 0x01`，且接口上提供一对 bulk 端点。
//!
//! 接口匹配只对 **native 的 `DeviceInfo`** 生效：设备打开前 `interfaces`
//! 可能为空，真正的接口列表要从设备返回的配置描述符里读（见 `transport`）。

use nusb::MaybeFuture;
use nusb::{DeviceInfo, InterfaceInfo};

use crate::hdc::error::Result;

/// HDC 接口的 class 值。
pub const HDC_INTERFACE_CLASS: u8 = 0xff;
/// HDC 接口的 subclass 值。
pub const HDC_INTERFACE_SUBCLASS: u8 = 0x50;
/// HDC 接口的 protocol 值。
pub const HDC_INTERFACE_PROTOCOL: u8 = 0x01;

/// 判断某个接口是否为 HDC 调试接口。
pub fn is_hdc_interface(info: &InterfaceInfo) -> bool {
    info.class() == HDC_INTERFACE_CLASS
        && info.subclass() == HDC_INTERFACE_SUBCLASS
        && info.protocol() == HDC_INTERFACE_PROTOCOL
}

/// 判断设备上是否存在 HDC 调试接口。
pub fn is_hdc_device(info: &DeviceInfo) -> bool {
    info.interfaces().any(is_hdc_interface)
}

/// 列出当前连接的所有 HDC 设备。
pub async fn list_hdc_devices() -> Result<Vec<DeviceInfo>> {
    let devices = nusb::list_devices().wait()?;
    Ok(devices.filter(is_hdc_device).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 接口匹配条件正确() {
        // 匹配条件本身是常量比较，这里锁定数值防止误改。
        assert_eq!(HDC_INTERFACE_CLASS, 0xff);
        assert_eq!(HDC_INTERFACE_SUBCLASS, 0x50);
        assert_eq!(HDC_INTERFACE_PROTOCOL, 0x01);
    }
}
