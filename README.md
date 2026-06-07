# Windows Security Checker

一个只读的 Windows 主机安全基线与应急排查工具，兼容 Windows PowerShell 5.1+。它会汇总关键安全配置和可疑迹象，并输出控制台、JSON 或 HTML 报告。

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

## 快速开始

请使用 **64 位管理员 PowerShell** 运行，以便读取完整的系统配置和 Security 事件日志。

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-WindowsSecurityCheck.ps1
```

同时生成 JSON 和 HTML 报告：

```powershell
.\Invoke-WindowsSecurityCheck.ps1 -Format All -OutputDirectory .\reports
```

检查最近 72 小时的登录失败：

```powershell
.\Invoke-WindowsSecurityCheck.ps1 -FailedLogonHours 72 -Format Html
```

也可以作为模块使用：

```powershell
Import-Module .\WindowsSecurityChecker.psm1
$report = Invoke-WindowsSecurityCheck -Format Json
$report.Findings | Where-Object Status -in 'Critical', 'Warning'
```

## 状态说明

| 状态 | 含义 |
| --- | --- |
| `Critical` | 明显扩大攻击面或达到高风险阈值，应优先复核 |
| `Warning` | 存在配置、暴露面或启发式命中，需要人工确认 |
| `Pass` | 未发现该项风险 |
| `Info` | 资产清单类信息，或风险依赖具体业务环境 |
| `Error` | 权限不足、组件不可用或检查执行失败 |

## 注意事项

- 工具只读取配置，不会自动修改系统。
- “可疑进程”和部分启动项判断基于命令行及路径启发式，可能产生误报。
- 端口处于监听状态不等于可从外网访问，还需结合 Windows 防火墙和边界网络策略判断。
- 在域环境中，本地策略可能被组策略覆盖。
- JSON 报告可能包含账号、路径、IP 和命令行等敏感信息，请妥善保存。

## 测试

```powershell
Invoke-Pester .\tests
```

## License

[MIT](LICENSE)
