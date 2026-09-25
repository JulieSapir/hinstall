// 移植自 openharmony/developtools_hdc（Apache-2.0）：
//   Copyright (C) 2021 Huawei Device Co., Ltd.
//   Licensed under the Apache License, Version 2.0
// 本项目将其改写为 Rust 实现。

//! HDC 命令字。
//!
//! 数值与官方 `src/common/define_enum.h` 的 `HdcCommand` 枚举逐项对齐。
//! 写入 `PayloadProtect.commandFlag`（u32，按 varint 编码）。

use crate::hdc::proto_error::{Error, Result};

/// HDC 命令字。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Command {
    /// 帮助信息。
    KernelHelp = 0,
    /// 会话握手。
    KernelHandshake = 1,
    /// 关闭通道。
    KernelChannelClose = 2,
    /// 发现设备（server 广播）。
    KernelTargetDiscover = 4,
    /// 列出设备。
    KernelTargetList = 5,
    /// 任意设备。
    KernelTargetAny = 6,
    /// 连接指定设备。
    KernelTargetConnect = 7,
    /// 断开指定设备。
    KernelTargetDisconnect = 8,
    /// echo。
    KernelEcho = 9,
    /// 原始 echo。
    KernelEchoRaw = 10,
    /// 开启保活。
    KernelEnableKeepalive = 11,
    /// 唤醒从任务。
    ///
    /// 设备端 `HdcSessionBase::NeedNewTaskInfo` 只对少数命令建 task，本命令是
    /// 其中之一：官方 `HdcTaskBase` 构造函数在建 master task 时会先发它，
    /// 使对端先建好同名 channel。直接发 `AppCheck` 而不先唤醒会被静默丢弃
    /// （`AdminTask(OP_QUERY)` 查不到 task 就 break，不回任何东西）。
    KernelWakeupSlaveTask = 12,
    /// 检查 server 是否在跑。
    CheckServer = 13,
    /// 检查设备。
    CheckDevice = 14,
    /// 等待设备。
    WaitFor = 15,
    /// 重连设备。
    KernelTargetReconnect = 18,
    /// TLS 握手。
    SslHandshake = 20,

    /// 执行 shell 命令。
    UnityExecute = 1001,
    /// 重新挂载。
    UnityRemount = 1002,
    /// 重启。
    UnityReboot = 1003,
    /// 设置运行模式。
    UnityRunmode = 1004,
    /// 拉取 hilog。
    UnityHilog = 1005,
    /// 带额外参数执行。
    UnityExecuteEx = 1200,

    /// shell 会话初始化。
    ShellInit = 2000,
    /// shell 数据。
    ShellData = 2001,

    /// 端口转发初始化。
    ForwardInit = 2500,
    /// 端口转发检查。
    ForwardCheck = 2501,
    /// 端口转发开始。
    ForwardActive = 2502,
    /// 端口转发数据。
    ForwardData = 2503,
    /// 端口转发结束。
    ForwardFinish = 2504,
    /// 反向端口转发初始化。
    ForwardInitReverse = 2505,
    /// 反向端口转发检查。
    ForwardCheckReverse = 2506,
    /// 反向端口转发开始。
    ForwardActiveReverse = 2507,
    /// 反向端口转发数据。
    ForwardDataReverse = 2508,
    /// 反向端口转发结束。
    ForwardFinishReverse = 2509,
    /// 移除转发规则。
    ForwardRemove = 2510,

    /// 文件传输初始化。
    FileInit = 3000,
    /// 文件传输检查。
    FileCheck = 3001,
    /// 文件传输开始。
    FileBegin = 3002,
    /// 文件传输数据。
    FileData = 3003,
    /// 文件传输结束。
    FileFinish = 3004,
    /// 应用安装包传输。
    AppSideload = 3005,
    /// 查询文件模式。
    FileMode = 3006,
    /// 查询目录模式。
    DirMode = 3007,

    /// 应用安装初始化。
    AppInit = 3500,
    /// 应用安装检查。
    AppCheck = 3501,
    /// 应用安装开始。
    AppBegin = 3502,
    /// 应用安装数据。
    AppData = 3503,
    /// 应用安装结束。
    AppFinish = 3504,
    /// 卸载应用。
    AppUninstall = 3505,

    /// 刷机初始化。
    FlashdInit = 4000,
    /// 刷机检查。
    FlashdCheck = 4001,
    /// 刷机开始。
    FlashdBegin = 4002,
    /// 刷机数据。
    FlashdData = 4003,
    /// 刷机结束。
    FlashdFinish = 4004,
    /// 刷机擦除。
    FlashdErase = 4005,
    /// 刷机进度。
    FlashdProgress = 4006,
    /// 刷机格式化。
    FlashdFormat = 4007,
    /// 刷机更新包。
    FlashdUpdate = 4008,

    /// 心跳。
    HeartbeatMsg = 5000,

    /// 派生进程。
    SpawnSub = 6000,
}

impl Command {
    /// 取命令字数值。
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// 取命令字数值（协议字段为 u32）。
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// 由数值还原命令字。
    pub fn from_u16(value: u16) -> Result<Self> {
        let cmd = match value {
            0 => Command::KernelHelp,
            1 => Command::KernelHandshake,
            2 => Command::KernelChannelClose,
            4 => Command::KernelTargetDiscover,
            5 => Command::KernelTargetList,
            6 => Command::KernelTargetAny,
            7 => Command::KernelTargetConnect,
            8 => Command::KernelTargetDisconnect,
            9 => Command::KernelEcho,
            10 => Command::KernelEchoRaw,
            11 => Command::KernelEnableKeepalive,
            12 => Command::KernelWakeupSlaveTask,
            13 => Command::CheckServer,
            14 => Command::CheckDevice,
            15 => Command::WaitFor,
            18 => Command::KernelTargetReconnect,
            20 => Command::SslHandshake,
            1001 => Command::UnityExecute,
            1002 => Command::UnityRemount,
            1003 => Command::UnityReboot,
            1004 => Command::UnityRunmode,
            1005 => Command::UnityHilog,
            1200 => Command::UnityExecuteEx,
            2000 => Command::ShellInit,
            2001 => Command::ShellData,
            2500 => Command::ForwardInit,
            2501 => Command::ForwardCheck,
            2502 => Command::ForwardActive,
            2503 => Command::ForwardData,
            2504 => Command::ForwardFinish,
            2505 => Command::ForwardInitReverse,
            2506 => Command::ForwardCheckReverse,
            2507 => Command::ForwardActiveReverse,
            2508 => Command::ForwardDataReverse,
            2509 => Command::ForwardFinishReverse,
            2510 => Command::ForwardRemove,
            3000 => Command::FileInit,
            3001 => Command::FileCheck,
            3002 => Command::FileBegin,
            3003 => Command::FileData,
            3004 => Command::FileFinish,
            3005 => Command::AppSideload,
            3006 => Command::FileMode,
            3007 => Command::DirMode,
            3500 => Command::AppInit,
            3501 => Command::AppCheck,
            3502 => Command::AppBegin,
            3503 => Command::AppData,
            3504 => Command::AppFinish,
            3505 => Command::AppUninstall,
            4000 => Command::FlashdInit,
            4001 => Command::FlashdCheck,
            4002 => Command::FlashdBegin,
            4003 => Command::FlashdData,
            4004 => Command::FlashdFinish,
            4005 => Command::FlashdErase,
            4006 => Command::FlashdProgress,
            4007 => Command::FlashdFormat,
            4008 => Command::FlashdUpdate,
            5000 => Command::HeartbeatMsg,
            6000 => Command::SpawnSub,
            other => return Err(Error::UnknownCommand(other)),
        };
        Ok(cmd)
    }

    /// 由 u32 还原命令字，超出 u16 范围直接报错。
    pub fn from_u32(value: u32) -> Result<Self> {
        let narrowed = u16::try_from(value).map_err(|_| Error::UnknownCommand(0))?;
        Self::from_u16(narrowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 命令字往返一致() {
        let all = [
            Command::KernelHelp,
            Command::KernelHandshake,
            Command::KernelChannelClose,
            Command::KernelTargetDiscover,
            Command::KernelTargetList,
            Command::KernelTargetAny,
            Command::KernelTargetConnect,
            Command::KernelTargetDisconnect,
            Command::KernelEcho,
            Command::KernelEchoRaw,
            Command::CheckServer,
            Command::CheckDevice,
            Command::WaitFor,
            Command::KernelTargetReconnect,
            Command::SslHandshake,
            Command::UnityExecute,
            Command::UnityRemount,
            Command::UnityReboot,
            Command::UnityRunmode,
            Command::UnityHilog,
            Command::UnityExecuteEx,
            Command::ShellInit,
            Command::ShellData,
            Command::ForwardInit,
            Command::ForwardCheck,
            Command::ForwardActive,
            Command::ForwardData,
            Command::ForwardFinish,
            Command::ForwardInitReverse,
            Command::ForwardCheckReverse,
            Command::ForwardActiveReverse,
            Command::ForwardDataReverse,
            Command::ForwardFinishReverse,
            Command::ForwardRemove,
            Command::FileInit,
            Command::FileCheck,
            Command::FileBegin,
            Command::FileData,
            Command::FileFinish,
            Command::AppSideload,
            Command::FileMode,
            Command::DirMode,
            Command::AppInit,
            Command::AppCheck,
            Command::AppBegin,
            Command::AppData,
            Command::AppFinish,
            Command::AppUninstall,
            Command::FlashdInit,
            Command::FlashdCheck,
            Command::FlashdBegin,
            Command::FlashdData,
            Command::FlashdFinish,
            Command::FlashdErase,
            Command::FlashdProgress,
            Command::FlashdFormat,
            Command::FlashdUpdate,
            Command::HeartbeatMsg,
            Command::SpawnSub,
        ];
        for c in all {
            assert_eq!(
                Command::from_u16(c.as_u16()).unwrap(),
                c,
                "命令 {:?} 往返失败",
                c
            );
        }
    }

    #[test]
    fn 未知命令字报错() {
        assert!(matches!(
            Command::from_u16(3),
            Err(Error::UnknownCommand(3))
        ));
        assert!(matches!(
            Command::from_u16(65000),
            Err(Error::UnknownCommand(65000))
        ));
    }

    #[test]
    fn 关键命令字数值与官方一致() {
        assert_eq!(Command::KernelHandshake.as_u16(), 1);
        assert_eq!(Command::UnityExecute.as_u16(), 1001);
        assert_eq!(Command::ShellInit.as_u16(), 2000);
        assert_eq!(Command::FileBegin.as_u16(), 3002);
        assert_eq!(Command::AppFinish.as_u16(), 3504);
        assert_eq!(Command::HeartbeatMsg.as_u16(), 5000);
    }
}
