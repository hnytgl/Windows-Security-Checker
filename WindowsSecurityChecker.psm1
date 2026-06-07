Set-StrictMode -Version 2.0

$script:ToolVersion = '1.0.0'

function New-SecurityFinding {
    param(
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][ValidateSet('Pass', 'Info', 'Warning', 'Critical', 'Error')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Summary,
        [object[]]$Details = @(),
        [string]$Recommendation = ''
    )

    [pscustomobject]@{
        Check          = $Check
        Status         = $Status
        Summary        = $Summary
        Details        = @($Details)
        Recommendation = $Recommendation
    }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-CommandLineRisk {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $null
    }

    $patterns = @(
        @{ Pattern = '(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}'; Reason = '包含 PowerShell 编码命令' },
        @{ Pattern = '(?i)\bfrombase64string\b|\biex\s*\('; Reason = '包含常见内存执行语句' },
        @{ Pattern = '(?i)\\(temp|public)\\.*\.(exe|dll|ps1|bat|cmd|vbs|js)\b|\\appdata\\.*\.(ps1|bat|cmd|vbs|js)\b'; Reason = '从高风险用户可写目录执行脚本或程序' },
        @{ Pattern = '(?i)\b(mshta|regsvr32|rundll32|certutil|bitsadmin)\.exe\b.*(https?://|javascript:|scrobj|urlcache)'; Reason = '系统工具存在可疑网络或脚本参数' },
        @{ Pattern = '(?i)\b(downloadstring|downloadfile|invoke-webrequest|curl\.exe|wget\.exe)\b'; Reason = '命令行包含下载行为' }
    )

    foreach ($item in $patterns) {
        if ($CommandLine -match $item.Pattern) {
            return $item.Reason
        }
    }
    return $null
}

function Get-LocalAdministratorFinding {
    try {
        $accounts = @()
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $accounts = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
                Select-Object Name, ObjectClass, PrincipalSource)
        }
        else {
            $group = [ADSI]'WinNT://./Administrators,group'
            $accounts = @($group.psbase.Invoke('Members') | ForEach-Object {
                $path = $_.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $_, $null)
                [pscustomobject]@{
                    Name            = $path -replace '^WinNT://', ''
                    ObjectClass     = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
                    PrincipalSource = 'WinNT'
                }
            })
        }

        $status = if ($accounts.Count -gt 2) { 'Warning' } else { 'Info' }
        New-SecurityFinding -Check '本地管理员账号' -Status $status `
            -Summary "发现 $($accounts.Count) 个本地 Administrators 组成员。" `
            -Details $accounts `
            -Recommendation '核实每个管理员成员的业务必要性，移除闲置账号并为管理员启用强密码和多因素认证。'
    }
    catch {
        New-SecurityFinding -Check '本地管理员账号' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-GuestAccountFinding {
    try {
        $guest = $null
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $guest = Get-LocalUser -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.SID -like '*-501' } |
                Select-Object -First 1
            if (-not $guest) {
                $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
            }
        }
        if (-not $guest) {
            $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'" -ErrorAction Stop |
                Select-Object -First 1 Name, Disabled, SID
        }

        if (-not $guest) {
            return New-SecurityFinding -Check 'Guest 账号' -Status 'Info' -Summary '未找到内置 Guest 账号。'
        }

        $enabled = if ($null -ne $guest.Enabled) { [bool]$guest.Enabled } else { -not [bool]$guest.Disabled }
        $status = if ($enabled) { 'Critical' } else { 'Pass' }
        $summary = if ($enabled) { '内置 Guest 账号已启用。' } else { '内置 Guest 账号已禁用。' }
        New-SecurityFinding -Check 'Guest 账号' -Status $status -Summary $summary `
            -Details @([pscustomobject]@{ Name = $guest.Name; Enabled = $enabled; SID = $guest.SID }) `
            -Recommendation '除非有明确且受控的业务需要，否则保持 Guest 账号禁用。'
    }
    catch {
        New-SecurityFinding -Check 'Guest 账号' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-RemoteDesktopFinding {
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $deny = (Get-ItemProperty -Path $path -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
        $nlaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $nla = (Get-ItemProperty -Path $nlaPath -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
        $enabled = ($deny -eq 0)
        $status = if (-not $enabled) { 'Pass' } elseif ($nla -eq 1) { 'Warning' } else { 'Critical' }
        $summary = if (-not $enabled) { '远程桌面已关闭。' } elseif ($nla -eq 1) {
            '远程桌面已开启，并启用了网络级别身份验证（NLA）。'
        } else {
            '远程桌面已开启，但未确认启用 NLA。'
        }
        New-SecurityFinding -Check '远程桌面' -Status $status -Summary $summary `
            -Details @([pscustomobject]@{ Enabled = $enabled; NLAEnabled = ($nla -eq 1) }) `
            -Recommendation '不需要时关闭远程桌面；需要时限制来源 IP、启用 NLA、强认证和账户锁定策略。'
    }
    catch {
        New-SecurityFinding -Check '远程桌面' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-FirewallFinding {
    try {
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            $profiles = @(Get-NetFirewallProfile -ErrorAction Stop |
                Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
        }
        else {
            $profiles = @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetFirewallProfile -ErrorAction Stop |
                Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
        }
        $disabled = @($profiles | Where-Object { -not $_.Enabled })
        $status = if ($disabled.Count -gt 0) { 'Critical' } else { 'Pass' }
        $summary = if ($disabled.Count -gt 0) {
            "有 $($disabled.Count) 个防火墙配置文件处于关闭状态。"
        } else {
            '所有 Windows 防火墙配置文件均已启用。'
        }
        New-SecurityFinding -Check 'Windows 防火墙' -Status $status -Summary $summary -Details $profiles `
            -Recommendation '启用域、专用和公用网络配置文件，并遵循最小开放原则配置入站规则。'
    }
    catch {
        New-SecurityFinding -Check 'Windows 防火墙' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-SmbV1Finding {
    try {
        $states = @()
        if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            try {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
                if ($feature) {
                    $states += [pscustomobject]@{ Component = 'SMB1Protocol feature'; State = [string]$feature.State }
                }
            }
            catch {
                $states += [pscustomobject]@{ Component = 'SMB1Protocol feature'; State = 'Unavailable without elevation' }
            }
        }
        if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            $server = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($server) {
                $states += [pscustomobject]@{ Component = 'SMB server'; State = [string]$server.EnableSMB1Protocol }
            }
        }
        $reg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -ErrorAction SilentlyContinue
        if ($reg) {
            $states += [pscustomobject]@{ Component = 'Registry SMB1'; State = [string]$reg.SMB1 }
        }

        $enabled = @($states | Where-Object { $_.State -match 'Enabled|^True$|^1$' }).Count -gt 0
        $unknown = ($states.Count -eq 0)
        $status = if ($enabled) { 'Critical' } elseif ($unknown) { 'Info' } else { 'Pass' }
        $summary = if ($enabled) { '检测到 SMBv1 已启用。' } elseif ($unknown) {
            '无法确认 SMBv1 状态。'
        } else {
            '未检测到启用的 SMBv1 组件。'
        }
        New-SecurityFinding -Check 'SMBv1' -Status $status -Summary $summary -Details $states `
            -Recommendation '禁用 SMBv1，使用 SMBv2/SMBv3，并确认旧设备兼容性。'
    }
    catch {
        New-SecurityFinding -Check 'SMBv1' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-ShareFinding {
    try {
        if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
            $shares = @(Get-SmbShare -ErrorAction Stop |
                Select-Object Name, Path, Description, Special, EncryptData, FolderEnumerationMode)
        }
        else {
            $shares = @(Get-CimInstance Win32_Share -ErrorAction Stop |
                Select-Object Name, Path, Description, Type)
        }
        $nonAdministrative = @($shares | Where-Object {
            $_.Name -notmatch '^(ADMIN|IPC|[A-Z])\$$' -and -not $_.Special
        })
        $status = if ($nonAdministrative.Count -gt 0) { 'Warning' } else { 'Info' }
        New-SecurityFinding -Check '共享目录' -Status $status `
            -Summary "共发现 $($shares.Count) 个共享，其中 $($nonAdministrative.Count) 个为非默认共享。" `
            -Details $shares `
            -Recommendation '逐项核实共享用途和 ACL，避免 Everyone/Guest 写权限，敏感共享应启用 SMB 加密。'
    }
    catch {
        New-SecurityFinding -Check '共享目录' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-StartupFinding {
    try {
        $items = @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop |
            Select-Object Name, Command, Location, User)
        $risky = @($items | Where-Object { Get-CommandLineRisk -CommandLine $_.Command })
        $details = @($items | ForEach-Object {
            [pscustomobject]@{
                Name     = $_.Name
                Command  = $_.Command
                Location = $_.Location
                User     = $_.User
                Risk     = Get-CommandLineRisk -CommandLine $_.Command
            }
        })
        $status = if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }
        New-SecurityFinding -Check '开机启动项' -Status $status `
            -Summary "发现 $($items.Count) 个启动项，其中 $($risky.Count) 个命中可疑规则。" `
            -Details $details `
            -Recommendation '核实未知启动项的发布者、文件路径和签名，重点检查用户可写目录中的程序。'
    }
    catch {
        New-SecurityFinding -Check '开机启动项' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-ScheduledTaskFinding {
    try {
        if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            return New-SecurityFinding -Check '计划任务' -Status 'Error' -Summary '当前系统不支持 Get-ScheduledTask。'
        }
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled'
        })
        $details = @($tasks | ForEach-Object {
            $commands = @($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; '
            $risk = Get-CommandLineRisk -CommandLine $commands
            if (-not $risk -and $commands -match '(?i)\\(temp|appdata|public)\\') {
                $risk = '任务从用户可写目录执行'
            }
            [pscustomobject]@{
                TaskPath = "$($_.TaskPath)$($_.TaskName)"
                State    = $_.State
                User     = $_.Principal.UserId
                Hidden   = $_.Settings.Hidden
                Command  = $commands
                Risk     = $risk
            }
        })
        $risky = @($details | Where-Object { $_.Risk -or $_.Hidden })
        $status = if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }
        New-SecurityFinding -Check '计划任务' -Status $status `
            -Summary "发现 $($tasks.Count) 个第三方启用任务，其中 $($risky.Count) 个需重点核实。" `
            -Details $details `
            -Recommendation '检查隐藏任务、编码命令、用户可写目录以及未知账户创建的任务。'
    }
    catch {
        New-SecurityFinding -Check '计划任务' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-SuspiciousProcessFinding {
    try {
        $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $details = @()
        foreach ($process in $processes) {
            $risk = Get-CommandLineRisk -CommandLine $process.CommandLine
            if (-not $risk -and $process.ExecutablePath -match '(?i)\\(temp|public)\\') {
                $risk = '进程从高风险用户可写目录运行'
            }
            if ($risk) {
                $details += [pscustomobject]@{
                    Name           = $process.Name
                    ProcessId      = $process.ProcessId
                    ExecutablePath = $process.ExecutablePath
                    CommandLine    = $process.CommandLine
                    Risk           = $risk
                }
            }
        }
        $status = if ($details.Count -gt 0) { 'Warning' } else { 'Pass' }
        $summary = if ($details.Count -gt 0) {
            "有 $($details.Count) 个进程命中启发式可疑规则。"
        } else {
            '未发现命中内置启发式规则的进程。'
        }
        New-SecurityFinding -Check '可疑进程' -Status $status -Summary $summary -Details $details `
            -Recommendation '启发式结果可能误报；请结合数字签名、父进程、网络连接和终端防护告警复核。'
    }
    catch {
        New-SecurityFinding -Check '可疑进程' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-ProxyFinding {
    try {
        $userProxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $proxyServer = if ($userProxy.PSObject.Properties['ProxyServer']) { $userProxy.ProxyServer } else { $null }
        $autoConfig = if ($userProxy.PSObject.Properties['AutoConfigURL']) { $userProxy.AutoConfigURL } else { $null }
        $proxyEnabled = if ($userProxy.PSObject.Properties['ProxyEnable']) { [bool]$userProxy.ProxyEnable } else { $false }
        $winHttpRaw = (& netsh winhttp show proxy 2>&1 | Out-String).Trim()
        $details = @(
            [pscustomobject]@{
                Scope       = 'Current user'
                ProxyEnable = $proxyEnabled
                ProxyServer = $proxyServer
                AutoConfig  = $autoConfig
            },
            [pscustomobject]@{
                Scope       = 'WinHTTP'
                ProxyEnable = $winHttpRaw -notmatch '(?i)direct access|直接访问'
                ProxyServer = $winHttpRaw
                AutoConfig  = $null
            }
        )
        $configured = $proxyEnabled -or -not [string]::IsNullOrWhiteSpace($autoConfig) -or
            $details[1].ProxyEnable
        $status = if ($configured) { 'Warning' } else { 'Pass' }
        $summary = if ($configured) { '检测到代理或自动代理脚本配置。' } else { '未检测到显式代理配置。' }
        New-SecurityFinding -Check '代理配置' -Status $status -Summary $summary -Details $details `
            -Recommendation '确认代理服务器或 PAC 地址可信，排查恶意流量劫持和遗留调试代理。'
    }
    catch {
        New-SecurityFinding -Check '代理配置' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-HostsFinding {
    try {
        $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        $entries = @(Get-Content -LiteralPath $path -ErrorAction Stop | ForEach-Object {
            $line = ($_ -replace '#.*$', '').Trim()
            if ($line) {
                $parts = $line -split '\s+'
                if ($parts.Count -ge 2) {
                    [pscustomobject]@{ Address = $parts[0]; Hostname = ($parts[1..($parts.Count - 1)] -join ', ') }
                }
            }
        })
        $nonDefault = @($entries | Where-Object {
            -not (($_.Address -in @('127.0.0.1', '::1')) -and $_.Hostname -match '^(localhost|ip6-)')
        })
        $status = if ($nonDefault.Count -gt 0) { 'Warning' } else { 'Pass' }
        New-SecurityFinding -Check 'hosts 文件' -Status $status `
            -Summary "hosts 文件包含 $($entries.Count) 条有效记录，其中 $($nonDefault.Count) 条为非默认映射。" `
            -Details $entries `
            -Recommendation '核实非默认域名映射，特别关注安全软件、更新服务、银行和常用网站域名。'
    }
    catch {
        New-SecurityFinding -Check 'hosts 文件' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-DnsFinding {
    try {
        if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
            $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.ServerAddresses.Count -gt 0 } |
                ForEach-Object {
                    [pscustomobject]@{
                        Interface = $_.InterfaceAlias
                        Index     = $_.InterfaceIndex
                        Servers   = $_.ServerAddresses -join ', '
                    }
                })
        }
        else {
            $dns = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
                ForEach-Object {
                    [pscustomobject]@{
                        Interface = $_.Description
                        Index     = $_.InterfaceIndex
                        Servers   = $_.DNSServerSearchOrder -join ', '
                    }
                })
        }
        New-SecurityFinding -Check 'DNS 配置' -Status 'Info' `
            -Summary "发现 $($dns.Count) 个配置了 IPv4 DNS 的网络接口。" `
            -Details $dns `
            -Recommendation '确认 DNS 服务器属于可信的企业、运营商或明确配置的公共解析服务。'
    }
    catch {
        New-SecurityFinding -Check 'DNS 配置' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-HighRiskPortFinding {
    $riskPorts = @{
        21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 69 = 'TFTP'; 135 = 'RPC'; 137 = 'NetBIOS'
        138 = 'NetBIOS'; 139 = 'NetBIOS'; 445 = 'SMB'; 1433 = 'MSSQL'; 1521 = 'Oracle'
        3306 = 'MySQL'; 3389 = 'RDP'; 5432 = 'PostgreSQL'; 5900 = 'VNC'; 5985 = 'WinRM HTTP'
        5986 = 'WinRM HTTPS'; 6379 = 'Redis'; 9200 = 'Elasticsearch'; 11211 = 'Memcached'
        27017 = 'MongoDB'
    }
    try {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
            $details = @($listeners | Where-Object { $riskPorts.ContainsKey([int]$_.LocalPort) } | ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    Protocol = 'TCP'
                    Address  = $_.LocalAddress
                    Port     = $_.LocalPort
                    Service  = $riskPorts[[int]$_.LocalPort]
                    PID      = $_.OwningProcess
                    Process  = $process.ProcessName
                    Exposure = if ($_.LocalAddress -in @('0.0.0.0', '::')) { 'All interfaces' } else { 'Restricted' }
                }
            })
        }
        else {
            $details = @()
        }
        $public = @($details | Where-Object { $_.Exposure -eq 'All interfaces' })
        $status = if ($public.Count -gt 0) { 'Critical' } elseif ($details.Count -gt 0) { 'Warning' } else { 'Pass' }
        New-SecurityFinding -Check '高危端口监听' -Status $status `
            -Summary "发现 $($details.Count) 个高关注端口监听，其中 $($public.Count) 个监听所有接口。" `
            -Details $details `
            -Recommendation '关闭不必要服务；必要服务应限制监听地址和防火墙来源，并启用加密及强认证。'
    }
    catch {
        New-SecurityFinding -Check '高危端口监听' -Status 'Error' -Summary $_.Exception.Message
    }
}

function Get-FailedLogonFinding {
    param([ValidateRange(1, 168)][int]$Hours = 24)

    try {
        $start = (Get-Date).AddHours(-$Hours)
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -ErrorAction Stop)
        $details = @($events | Select-Object -First 100 | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            foreach ($node in $xml.Event.EventData.Data) {
                $data[[string]$node.Name] = [string]$node.'#text'
            }
            [pscustomobject]@{
                TimeCreated = $_.TimeCreated
                Account     = "$($data.TargetDomainName)\$($data.TargetUserName)".Trim('\')
                SourceIP    = $data.IpAddress
                Workstation = $data.WorkstationName
                LogonType   = $data.LogonType
                Status      = $data.Status
                SubStatus   = $data.SubStatus
            }
        })
        $status = if ($events.Count -ge 20) { 'Critical' } elseif ($events.Count -gt 0) { 'Warning' } else { 'Pass' }
        New-SecurityFinding -Check '最近登录失败' -Status $status `
            -Summary "最近 $Hours 小时发现 $($events.Count) 次登录失败（报告最多列出 100 条）。" `
            -Details $details `
            -Recommendation '按来源 IP、目标账号和时间聚合分析；大量失败可能表示密码喷洒、暴力破解或失效服务凭据。'
    }
    catch {
        New-SecurityFinding -Check '最近登录失败' -Status 'Error' `
            -Summary "无法读取安全日志：$($_.Exception.Message)" `
            -Recommendation '请以管理员身份运行，并确认当前账户具有读取 Security 日志的权限。'
    }
}

function ConvertTo-HtmlReport {
    param([Parameter(Mandatory = $true)]$Report)

    $encode = [System.Net.WebUtility]
    $cards = foreach ($finding in $Report.Findings) {
        $detailHtml = if ($finding.Details.Count -gt 0) {
            $finding.Details | ConvertTo-Html -Fragment | Out-String
        } else {
            '<p class="muted">无明细</p>'
        }
        @"
<section class="finding $($finding.Status.ToLowerInvariant())">
  <h2>$($encode::HtmlEncode($finding.Check)) <span>$($finding.Status)</span></h2>
  <p>$($encode::HtmlEncode($finding.Summary))</p>
  <details><summary>查看证据</summary>$detailHtml</details>
  <p class="recommendation"><strong>建议：</strong>$($encode::HtmlEncode($finding.Recommendation))</p>
</section>
"@
    }

    @"
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Security Checker Report</title>
<style>
body{font-family:"Segoe UI","Microsoft YaHei",sans-serif;margin:0;background:#f4f6f8;color:#1f2937}
main{max-width:1180px;margin:28px auto;padding:0 20px}.hero,.finding{background:#fff;border-radius:10px;padding:20px;margin-bottom:16px;box-shadow:0 2px 10px #00000012}
h1{margin:0 0 8px}.meta,.muted{color:#667085}.finding{border-left:6px solid #98a2b3}.finding.pass{border-color:#12b76a}.finding.info{border-color:#2e90fa}.finding.warning{border-color:#f79009}.finding.critical,.finding.error{border-color:#f04438}
h2{display:flex;justify-content:space-between;font-size:19px}h2 span{font-size:13px;padding:4px 9px;border-radius:12px;background:#eef2f6}
table{border-collapse:collapse;width:100%;font-size:13px;display:block;overflow:auto}th,td{border:1px solid #d0d5dd;padding:7px;text-align:left;white-space:nowrap}
.recommendation{background:#f8fafc;padding:10px;border-radius:6px}summary{cursor:pointer;font-weight:600;margin:8px 0}
</style>
</head>
<body><main>
<section class="hero">
  <h1>Windows Security Checker</h1>
  <p class="meta">主机：$($encode::HtmlEncode($Report.ComputerName)) | 时间：$($Report.GeneratedAt) | 管理员：$($Report.IsAdministrator)</p>
  <p>Critical: $($Report.Summary.Critical) | Warning: $($Report.Summary.Warning) | Pass: $($Report.Summary.Pass) | Info: $($Report.Summary.Info) | Error: $($Report.Summary.Error)</p>
</section>
$($cards -join "`n")
</main></body></html>
"@
}

function Invoke-WindowsSecurityCheck {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 168)][int]$FailedLogonHours = 24,
        [ValidateSet('Console', 'Json', 'Html', 'All')][string]$Format = 'Console',
        [string]$OutputDirectory = (Join-Path (Get-Location) 'reports')
    )

    $findings = @(
        Get-LocalAdministratorFinding
        Get-GuestAccountFinding
        Get-RemoteDesktopFinding
        Get-FirewallFinding
        Get-SmbV1Finding
        Get-ShareFinding
        Get-StartupFinding
        Get-ScheduledTaskFinding
        Get-SuspiciousProcessFinding
        Get-ProxyFinding
        Get-HostsFinding
        Get-DnsFinding
        Get-HighRiskPortFinding
        Get-FailedLogonFinding -Hours $FailedLogonHours
    )

    $summary = [ordered]@{}
    foreach ($status in @('Critical', 'Warning', 'Pass', 'Info', 'Error')) {
        $summary[$status] = @($findings | Where-Object { $_.Status -eq $status }).Count
    }
    $report = [pscustomobject]@{
        ToolVersion     = $script:ToolVersion
        ComputerName    = $env:COMPUTERNAME
        GeneratedAt     = (Get-Date).ToString('o')
        IsAdministrator = Test-IsAdministrator
        Summary         = [pscustomobject]$summary
        Findings        = $findings
    }

    if ($Format -in @('Json', 'Html', 'All')) {
        if (-not (Test-Path -LiteralPath $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        if ($Format -in @('Json', 'All')) {
            $jsonPath = Join-Path $OutputDirectory "windows-security-$stamp.json"
            $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            Write-Host "JSON 报告：$jsonPath" -ForegroundColor Cyan
        }
        if ($Format -in @('Html', 'All')) {
            $htmlPath = Join-Path $OutputDirectory "windows-security-$stamp.html"
            ConvertTo-HtmlReport -Report $report | Set-Content -LiteralPath $htmlPath -Encoding UTF8
            Write-Host "HTML 报告：$htmlPath" -ForegroundColor Cyan
        }
    }

    if ($Format -in @('Console', 'All')) {
        Write-Host "`nWindows Security Checker $script:ToolVersion" -ForegroundColor Cyan
        Write-Host "主机: $($report.ComputerName)  管理员: $($report.IsAdministrator)`n"
        foreach ($finding in $findings) {
            $color = switch ($finding.Status) {
                'Pass' { 'Green' }
                'Info' { 'Cyan' }
                'Warning' { 'Yellow' }
                default { 'Red' }
            }
            Write-Host ("[{0,-8}] {1}: {2}" -f $finding.Status, $finding.Check, $finding.Summary) -ForegroundColor $color
        }
        Write-Host ("`n汇总: Critical={0}, Warning={1}, Pass={2}, Info={3}, Error={4}" -f
            $summary.Critical, $summary.Warning, $summary.Pass, $summary.Info, $summary.Error)
    }

    return $report
}

Export-ModuleMember -Function Invoke-WindowsSecurityCheck
