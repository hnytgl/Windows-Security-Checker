[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(1, 168)]
    [int]$FailedLogonHours = 24,

    [ValidateSet('Console', 'Json', 'Html', 'All')]
    [string]$Format = 'Console',

    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'reports'),

    [switch]$Repair,

    [ValidateSet('Safe', 'Harden')]
    [string]$RepairProfile = 'Safe',

    [string]$BackupDirectory,

    [switch]$Force,

    [switch]$NoRecheck
)

$modulePath = Join-Path $PSScriptRoot 'WindowsSecurityChecker.psm1'
Import-Module $modulePath -Force

if ($Repair) {
    $repairParameters = @{
        Profile = $RepairProfile
        Force   = $Force
        WhatIf  = [bool]$WhatIfPreference
    }
    if ($BackupDirectory) {
        $repairParameters.BackupDirectory = $BackupDirectory
    }
    $repairReport = Invoke-WindowsSecurityRepair @repairParameters

    if (-not $NoRecheck -and -not $WhatIfPreference) {
        Write-Host "`n开始修复后复检..." -ForegroundColor Cyan
        $checkReport = Invoke-WindowsSecurityCheck -FailedLogonHours $FailedLogonHours `
            -Format $Format -OutputDirectory $OutputDirectory
        [pscustomobject]@{
            Repair  = $repairReport
            Recheck = $checkReport
        }
    }
    else {
        $repairReport
    }
}
else {
    Invoke-WindowsSecurityCheck -FailedLogonHours $FailedLogonHours -Format $Format -OutputDirectory $OutputDirectory
}
