$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'WindowsSecurityChecker.psm1'
Import-Module $modulePath -Force

Describe 'WindowsSecurityChecker module' {
    It 'exports the main command' {
        Get-Command Invoke-WindowsSecurityCheck -ErrorAction Stop | Should Not BeNullOrEmpty
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
