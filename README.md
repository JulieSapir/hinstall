# hinstall 鸿蒙hap安装工具

高纯度rust，理论上所有操作系统都能用

> 为什么不支持浏览器？
>
> 因为回调必须是localhost
> 除非直接去请求接口

## 特性

极致轻量化

- 不需要安装jdk
- 不需要安装openssl
- 不需要安装libusb
- 不需要安装hdc

## 从源代码运行

1. 安装rust工具链
2. 执行`cargo run -- -h`

## 使用方法

```text
hinstall —— 华为 HAP 调试签名与安装工具

用法: hinstall <命令> [选项]

命令:
  login        华为账号 OAuth 登录
  init         注册设备/证书/Profile
  sign         对 hap 签名（纯本地算法）
  install      安装签名产物到设备
  signinstall  签名后直接安装（产物固定 data/signed.hap）
  status       查看状态

通用选项:
  -h, --help   显示本帮助

login 选项:
  --timeout <秒>              等待回调的超时，默认 300

init 选项:
  --udid <UDID>               手动指定设备 UDID
  --device-name <名称>        云端设备名，默认 quantum-dev-<udid 前 10 位>
  --bundle <包名>             默认读 ohos/AppScope/app.json5

sign / signinstall 选项:
  --cert <路径>               证书链，缺省 data/hinstall-debug.cer
  --profile <路径>            Profile，缺省 data/debug-profile.p7b
  --key <路径>                私钥 PEM，缺省 data/hinstall.key
  --sign-alg <算法>           默认 SHA256withECDSA，可选 SHA256withECDSA, SHA256withRSA, SHA384withECDSA, SHA512withECDSA
  --compatible-version <n>   默认 9
  --sign-code / --no-sign-code
  --permission-sign / --no-permission-sign
  --out <路径>                仅 sign：输出路径

install / signinstall 选项:
  --device <connectkey>      多设备时指定目标
  --uninstall                 先卸载旧包再安装
  --bundle <包名>            卸载用包名，缺省读 ohos/AppScope/app.json5
```

## Plan

添加UI

## License

MIT
