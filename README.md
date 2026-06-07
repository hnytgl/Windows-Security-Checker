# Windows Security Checker

一个 Windows 主机安全基线、应急排查和受控修复工具，兼容 Windows PowerShell 5.1+。支持控制台、JSON、HTML 报告，以及带备份、预演和复检的一键修复。

## 检查项目

- 本地管理员账号
- 内置 Guest 账号状态
- 远程桌面与 NLA 状态
- Windows 防火墙状态
- SMBv1 状态
- SMB 共享目录
- 开机启动项
- 非 Microsoft 计划任务
- 启发式可疑进程
- 用户和 WinHTTP 代理配置
- hosts 文件非默认记录
- IPv4 DNS 配置
- 高关注端口监听
- 最近 Windows 登录失败事件（4625）

## 快速检查

请使用 **64 位管理员 PowerShell** 运行，以便读取完整配置和 Security 事件日志。

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-WindowsSecurityCheck.ps1
```

生成 JSON 和 HTML 报告：

```powershell
.\Invoke-WindowsSecurityCheck.ps1 -Format All -OutputDirectory .\reports
```

## 一键修复

先预演，不修改系统：

```powershell
.\Invoke-WindowsSecurityCheck.ps1 -Repair -RepairProfile Safe -WhatIf
```

执行安全修复，自动确认并在完成后复检：

```powershell
.\Invoke-WindowsSecurityCheck.ps1 -Repair -RepairProfile Safe -Force -Format All
```

更严格的加固：

```powershell
.\Invoke-WindowsSecurityCheck.ps1 -Repair -RepairProfile Harden -Force -Format All
```

### 修复档位

| 档位 | 自动操作 |
| --- | --- |
| `Safe` | 禁用 Guest、启用域/专用/公用防火墙、禁用 SMBv1 |
| `Harden` | 包含 `Safe`，并关闭远程桌面、清除当前用户和 WinHTTP 代理 |

`Harden` 可能中断远程桌面和依赖代理的网络访问。远程管理主机应先使用 `-WhatIf`，并确保有控制台或其他恢复通道。

默认情况下，修复前会创建 `security-backup-时间戳` 目录，包含：

- 远程桌面、SMB 和用户代理注册表导出
- Windows 防火墙策略
- WinHTTP 代理状态
- hosts 文件副本
- 备份元数据
- 修复完成后的 `repair-result.json`

指定备份路径：

```powershell
.\Invoke-WindowsSecurityCheck.ps1 -Repair -Force -BackupDirectory C:\SecurityBackup
```

跳过修复后复检：

```powershell
.\Invoke-WindowsSecurityCheck.ps1 -Repair -Force -NoRecheck
```

## 不自动处理的项目

以下项目依赖业务用途或调查结论，不会被工具直接删除或终止：

- 管理员组成员
- 共享目录
- 启动项和计划任务
- 可疑进程
- DNS 和 hosts 映射
- 监听端口及其服务
- 登录失败记录

这些项目会继续出现在报告中，并给出人工处置建议。

## 模块调用

```powershell
Import-Module .\WindowsSecurityChecker.psm1
$report = Invoke-WindowsSecurityCheck -Format Json
$repair = Invoke-WindowsSecurityRepair -Profile Safe -WhatIf
```

## 状态说明

检查状态包括 `Critical`、`Warning`、`Pass`、`Info` 和 `Error`。

修复状态包括：

| 状态 | 含义 |
| --- | --- |
| `Fixed` | 已完成修改 |
| `NoChange` | 当前配置已符合目标 |
| `Planned` | `-WhatIf` 预演中计划执行 |
| `Skipped` | 未找到目标或不适用 |
| `Failed` | 单项修复失败，其他项目继续执行 |

## 注意事项

- 修复模式必须使用管理员 PowerShell，`-WhatIf` 预演除外。
- SMBv1 组件变更可能需要重启。
- 工具不会保证符合某个特定行业合规标准。
- 在域环境中，本地设置可能被组策略再次覆盖。
- 报告和备份可能包含账号、路径、IP、命令行和网络配置等敏感信息。

## 测试

```powershell
Invoke-Pester .\tests
```

## License

[MIT](LICENSE)
