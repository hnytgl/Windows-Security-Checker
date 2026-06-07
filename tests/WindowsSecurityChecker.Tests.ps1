$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'WindowsSecurityChecker.psm1'
Import-Module $modulePath -Force

Describe 'WindowsSecurityChecker module' {
    It 'exports the main command' {
        Get-Command Invoke-WindowsSecurityCheck -ErrorAction Stop | Should Not BeNullOrEmpty
        Get-Command Invoke-WindowsSecurityRepair -ErrorAction Stop | Should Not BeNullOrEmpty
    }

    It 'supports safe and harden repair profiles' {
        $command = Get-Command Invoke-WindowsSecurityRepair
        $validateSet = $command.Parameters.Profile.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        ($validateSet.ValidValues -contains 'Safe') | Should Be $true
        ($validateSet.ValidValues -contains 'Harden') | Should Be $true
        $command.Parameters.ContainsKey('WhatIf') | Should Be $true
    }

    It 'accepts the documented output formats' {
        $command = Get-Command Invoke-WindowsSecurityCheck
        $validateSet = $command.Parameters.Format.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        $formats = $validateSet.ValidValues
        ($formats -contains 'Console') | Should Be $true
        ($formats -contains 'Json') | Should Be $true
        ($formats -contains 'Html') | Should Be $true
        ($formats -contains 'All') | Should Be $true
    }

    It 'parses on Windows PowerShell' {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$errors)
        $errors.Count | Should Be 0
    }
}
