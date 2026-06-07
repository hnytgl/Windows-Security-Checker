[CmdletBinding()]
param(
    [ValidateRange(1, 168)]
    [int]$FailedLogonHours = 24,

    [ValidateSet('Console', 'Json', 'Html', 'All')]
    [string]$Format = 'Console',

    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'reports')
)

$modulePath = Join-Path $PSScriptRoot 'WindowsSecurityChecker.psm1'
Import-Module $modulePath -Force

Invoke-WindowsSecurityCheck -FailedLogonHours $FailedLogonHours -Format $Format -OutputDirectory $OutputDirectory
