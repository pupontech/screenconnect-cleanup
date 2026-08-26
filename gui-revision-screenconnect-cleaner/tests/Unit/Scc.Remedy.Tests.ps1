# =====================================================================
# Scc.Remedy.Tests.ps1  -  Pester unit tests for Scc.Remedy
#
# Runs on Linux pwsh. Windows-only behavior is mocked so the safety
# logic (plan gating, re-verification, ordering, quarantine manifest,
# restore, clear) is exercised without a live Windows box.
#
# PowerShell 5.1 compatible syntax. Pure ASCII, no BOM.
# =====================================================================

$moduleDir = Join-Path $PSScriptRoot '..' '..' 'src' 'Scc.Remedy'
$modulePath = Join-Path $moduleDir 'Scc.Remedy.psd1'

Import-Module $modulePath -Force -ErrorAction Stop

# ---------------------------------------------------------------------
Describe 'Scc.Remedy Plan Creation (New-SccPlan)' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    Context 'Default KEEP and explicit REMOVE' {
        It 'defaults every finding to KEEP when no decisions given' {
            $f = @(
                (New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service')
                (New-Finding -Id 'sc2' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service')
            )
            $plan = New-SccPlan -Run (New-TestRun) -Findings $f
            @($plan.Items).Count | Should -Be 2
            foreach ($it in $plan.Items) { $it.Action | Should -Be 'KEEP' }
        }

        It 'respects an explicit REMOVE decision for a ScreenConnect finding' {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service'))
            $plan = New-SccPlan -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }
            $plan.Items[0].Action | Should -Be 'REMOVE'
        }

        It 'writes a plan.json when a Run is supplied' {
            $run = New-TestRun
            try {
                $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service'))
                $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }
                $pp = Join-Path $run.RunDir 'plan.json'
                Test-Path -LiteralPath $pp | Should -Be $true
                $reread = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($pp))
                $reread.PlanVersion | Should -Be '1.0'
                $reread.Items[0].Action | Should -Be 'REMOVE'
            } finally { Remove-TestRun $run }
        }
    }

    Context 'Owner policy: only ScreenConnect may be REMOVE' {
        It 'throws and lists refused items when an AnyDesk finding is marked REMOVE' {
            $f = @(
                (New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service')
                (New-Finding -Id 'ad1' -Product 'anydesk' -ServiceName 'AnyDesk Service')
            )
            { New-SccPlan -Findings $f -Decisions @{ 'ad1' = 'REMOVE' } } | Should -Throw -Because 'non-ScreenConnect REMOVE must be refused'
            try {
                New-SccPlan -Findings $f -Decisions @{ 'ad1' = 'REMOVE' }
            } catch {
                $_.Exception.Message | Should -BeLike '*ad1*'
            }
        }

        It 'ignores malformed decision values (stays KEEP, no throw)' {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service'))
            $plan = New-SccPlan -Findings $f -Decisions @{ 'sc1' = 'maybe-remove' }
            $plan.Items[0].Action | Should -Be 'KEEP'
        }

        It 'keeps a malformed AnyDesk decision as KEEP without refusal' {
            $f = @((New-Finding -Id 'ad1' -Product 'anydesk' -ServiceName 'AnyDesk Service'))
            { New-SccPlan -Findings $f -Decisions @{ 'ad1' = 'garbage' } } | Should -Not -Throw
        }
    }
}

# ---------------------------------------------------------------------
Describe 'Scc.Remedy Smuggling and Dry-Run Guards' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
        $global:sccMod = 'Scc.Remedy'
    }

    It 'poisoned plan with an AnyDesk REMOVE item performs ZERO destructive actions' {
        $run = New-TestRun
        try {
            $poisonPath = Join-Path $run.RunDir 'poison-plan.json'
            $poison = [PSCustomObject]@{
                PlanVersion = '1.0'
                CreatedUtc  = '2026-08-26 00:00:00'
                CreatedBy   = 'attacker'
                Items = @(
                    [PSCustomObject]@{
                        FindingId  = 'ad1'
                        Product    = 'anydesk'
                        TargetType = 'Uninstall'
                        Action     = 'REMOVE'
                        Detail     = ''
                        DisplayText = 'ad1 [anydesk]'
                        ServiceName = 'AnyDesk Service'
                        InstallDir  = 'C:\Program Files (x86)\AnyDesk'
                    }
                )
            }
            [System.IO.File]::WriteAllText($poisonPath, (ConvertTo-Json -InputObject $poison -Depth 10 -Compress), [System.Text.Encoding]::ASCII)

            Mock Stop-SccTargetService -ModuleName $global:sccMod { return $true }
            Mock Stop-SccTargetProcesses -ModuleName $global:sccMod { return $true }
            Mock Uninstall-SccTarget -ModuleName $global:sccMod { return $true }
            Mock Test-SccTargetRemoved -ModuleName $global:sccMod { return $true }
            Mock Remove-SccTargetService -ModuleName $global:sccMod { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName $global:sccMod { return $true }
            Mock Remove-SccTargetRunKey -ModuleName $global:sccMod { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName $global:sccMod { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName $global:sccMod { return $true }

            { Invoke-SccRemediation -Run $run -Plan $poisonPath -Execute } | Should -Not -Throw

            Should -Invoke Stop-SccTargetService -ModuleName $global:sccMod -Exactly 0
            Should -Invoke Stop-SccTargetProcesses -ModuleName $global:sccMod -Exactly 0
            Should -Invoke Uninstall-SccTarget -ModuleName $global:sccMod -Exactly 0
            Should -Invoke Move-SccTargetToQuarantine -ModuleName $global:sccMod -Exactly 0

            $rem = Read-Remediation -Run $run
            @($rem | Where-Object { $_.Action -ne 'SkipItem' }).Count | Should -Be 0
        } finally { Remove-TestRun $run }
    }

    It 'dry-run by default (no -Execute) calls no destructive primitive' {
        $run = New-TestRun
        try {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Stop-SccTargetService -ModuleName $global:sccMod { return $true }
            Mock Stop-SccTargetProcesses -ModuleName $global:sccMod { return $true }
            Mock Uninstall-SccTarget -ModuleName $global:sccMod { return $true }
            Mock Test-SccTargetRemoved -ModuleName $global:sccMod { return $true }
            Mock Remove-SccTargetService -ModuleName $global:sccMod { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName $global:sccMod { return $true }
            Mock Remove-SccTargetRunKey -ModuleName $global:sccMod { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName $global:sccMod { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName $global:sccMod { return $true }

            $preview = Invoke-SccRemediation -Run $run -Plan $plan
            $preview | Should -Not -BeNullOrEmpty
            Should -Invoke Stop-SccTargetService -ModuleName $global:sccMod -Exactly 0
            Should -Invoke Uninstall-SccTarget -ModuleName $global:sccMod -Exactly 0
            Should -Invoke Move-SccTargetToQuarantine -ModuleName $global:sccMod -Exactly 0
        } finally { Remove-TestRun $run }
    }

    It 'malformed plan JSON yields a clean error and performs no destructive actions' {
        $run = New-TestRun
        try {
            $badPath = Join-Path $run.RunDir 'bad.json'
            [System.IO.File]::WriteAllText($badPath, '{ this is not valid json ', [System.Text.Encoding]::ASCII)

            Mock Stop-SccTargetService -ModuleName $global:sccMod { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName $global:sccMod { return $true }

            { Invoke-SccRemediation -Run $run -Plan $badPath -Execute } | Should -Throw

            Should -Invoke Stop-SccTargetService -ModuleName $global:sccMod -Exactly 0
            Should -Invoke Move-SccTargetToQuarantine -ModuleName $global:sccMod -Exactly 0
        } finally { Remove-TestRun $run }
    }
}

# ---------------------------------------------------------------------
Describe 'Scc.Remedy Remediation Ordering' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'runs destructive primitives in the required order (stop -> kill -> uninstall -> validate -> cleanup -> quarantine)' {
        $run = New-TestRun
        try {
            $global:callOrder = New-Object System.Collections.ArrayList
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $f[0] | Add-Member -MemberType NoteProperty -Name 'QuarantinePaths' -Value @('C:\SC\sc1') -Force
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('StopService'); return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('KillProcesses'); return $true }
            Mock Uninstall-SccTarget -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('Uninstall'); return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('Validate'); return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('DeleteService'); return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('DeleteTask'); return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('DeleteRunKey'); return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('DeleteFirewall'); return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { [void]$global:callOrder.Add('Quarantine'); return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute

            $expected = @('StopService','KillProcesses','Uninstall','Validate','DeleteService','DeleteTask','DeleteRunKey','DeleteFirewall','Quarantine')
            @($global:callOrder) -join ',' | Should -Be ($expected -join ',')
        } finally {
            Remove-TestRun $run
            Remove-Variable -Name callOrder -Scope Global -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------
Describe 'Scc.Remedy Re-Verification Gate' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'skips an item whose re-verification fails while processing the others' {
        $run = New-TestRun
        try {
            $f = @(
                (New-Finding -Id 'sc-good' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\good')
                (New-Finding -Id 'sc-bad'  -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\bad')
            )
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc-good' = 'REMOVE'; 'sc-bad' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' {
                param($PlanItem)
                if ([string]$PlanItem.FindingId -eq 'sc-bad') { return $false }
                return $true
            }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Uninstall-SccTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute

            $rem = Read-Remediation -Run $run
            $bad = @($rem | Where-Object { $_.Target -eq 'sc-bad' -and $_.Action -eq 'ReVerify' })[0]
            $bad | Should -Not -BeNullOrEmpty
            $bad.Result | Should -Be 'Skipped'

            $good = @($rem | Where-Object { $_.Target -eq 'sc-good' -and $_.Action -eq 'ReVerify' })[0]
            $good | Should -Not -BeNullOrEmpty
            $good.Result | Should -Be 'Succeeded'

            # sc-good must have progressed past re-verification (StopService invoked);
            # sc-bad must NOT have reached StopService (re-verification skipped it).
            Should -Invoke Stop-SccTargetService -ModuleName 'Scc.Remedy' -ParameterFilter { $true } -Exactly 1
            $goodStopped = [bool](@($rem | Where-Object { $_.Target -eq 'sc-good' -and $_.Action -eq 'ReVerify' -and $_.Result -eq 'Succeeded' }).Count -gt 0)
            $goodStopped | Should -Be $true
        } finally { Remove-TestRun $run }
    }
}

# ---------------------------------------------------------------------
Describe 'Scc.Remedy Uninstaller Discovery' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'uses the registry UninstallString verbatim when present' {
        $run = New-TestRun
        try {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Get-SccTargetUninstallData -ModuleName 'Scc.Remedy' {
                return [PSCustomObject]@{
                    UninstallString      = 'C:\SC\sc1\uninstall.exe /quiet'
                    QuietUninstallString = ''
                    ProductCode          = ''
                    DisplayName          = 'ScreenConnect Client (abc123)'
                    PSPath               = 'Registry::HKLM:\x'
                }
            }
            Mock Test-SccUninstallExeValid -ModuleName 'Scc.Remedy' { return $true }
            Mock Invoke-SccUninstallCommand -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute
            $rem = Read-Remediation -Run $run
            $un = @($rem | Where-Object { $_.Action -eq 'Uninstall' })[0]
            $un.Command | Should -Be 'C:\SC\sc1\uninstall.exe /quiet'
        } finally { Remove-TestRun $run }
    }

    It 'falls back to msiexec when only a ProductCode is present' {
        $run = New-TestRun
        try {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }
            $code = '{A1B2C3D4-0000-0000-0000-000000000001}'

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Get-SccTargetUninstallData -ModuleName 'Scc.Remedy' {
                return [PSCustomObject]@{
                    UninstallString      = ''
                    QuietUninstallString = ''
                    ProductCode          = '{A1B2C3D4-0000-0000-0000-000000000001}'
                    DisplayName          = 'ScreenConnect Client (abc123)'
                    PSPath               = 'Registry::HKLM:\x'
                }
            }
            Mock Invoke-SccUninstallCommand -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute
            $rem = Read-Remediation -Run $run
            $un = @($rem | Where-Object { $_.Action -eq 'Uninstall' })[0]
            $un.Command | Should -BeLike '*msiexec*'
            $un.Command | Should -BeLike "*$code*"
        } finally { Remove-TestRun $run }
    }

    It 'records manual-cleanup-only + Failed-with-reason when no uninstaller is discoverable' {
        $run = New-TestRun
        try {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Get-SccTargetUninstallData -ModuleName 'Scc.Remedy' { return $null }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute
            $rem = Read-Remediation -Run $run
            $un = @($rem | Where-Object { $_.Action -eq 'Uninstall' })[0]
            $un.Result | Should -Be 'Failed'
            $un.Error | Should -BeLike '*manual-cleanup-only*'
        } finally { Remove-TestRun $run }
    }
}

# ---------------------------------------------------------------------
Describe 'Scc.Remedy Quarantine Manifest' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'moves a real file, records correct manifest fields, and removes the original' {
        $run = New-TestRun
        try {
            $srcDir = Join-Path ([System.IO.Path]::GetTempPath()) ('scc_qsrc_' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
            $srcFile = Join-Path $srcDir 'artifact.dll'
            [System.IO.File]::WriteAllText($srcFile, 'SC-payload-bytes', [System.Text.Encoding]::ASCII)
            $expectedSize = (Get-Item -LiteralPath $srcFile).Length
            $expectedHash = (Get-FileHash -LiteralPath $srcFile -Algorithm SHA256).Hash

            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            # Inject the real temp file as a quarantine path on the plan item.
            $f[0] | Add-Member -MemberType NoteProperty -Name 'QuarantinePaths' -Value @($srcFile) -Force
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Uninstall-SccTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute

            $qManifestPath = Join-Path (Join-Path $run.RunDir 'Quarantine') 'quarantine-manifest.json'
            Test-Path -LiteralPath $qManifestPath | Should -Be $true
            $man = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($qManifestPath))
            $entry = $man[0]
            $entry | Should -Not -BeNullOrEmpty
            $entry.OriginalPath | Should -Be $srcFile
            $entry.SHA256 | Should -Be $expectedHash
            $entry.SizeBytes | Should -Be $expectedSize
            Test-Path -LiteralPath $entry.QuarantinePath | Should -Be $true
            Test-Path -LiteralPath $srcFile | Should -Be $false
        } finally {
            if (Test-Path -LiteralPath $srcDir) { Remove-Item -LiteralPath $srcDir -Recurse -Force -ErrorAction SilentlyContinue }
            Remove-TestRun $run
        }
    }
}

# ---------------------------------------------------------------------
Describe 'Scc.Remedy Restore and Clear Quarantine' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'restores a quarantined item and refuses when the destination already exists' {
        $run = New-TestRun
        try {
            $srcDir = Join-Path ([System.IO.Path]::GetTempPath()) ('scc_r_' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
            $srcFile = Join-Path $srcDir 'artifact.dll'
            [System.IO.File]::WriteAllText($srcFile, 'SC-payload', [System.Text.Encoding]::ASCII)

            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $f[0] | Add-Member -MemberType NoteProperty -Name 'QuarantinePaths' -Value @($srcFile) -Force
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Uninstall-SccTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute

            $man = Read-QuarantineManifest -Run $run
            $itemId = $man[0].ItemId
            $original = $man[0].OriginalPath

            # Restore normally.
            Restore-SccQuarantineItem -Run $run -ItemId $itemId
            Test-Path -LiteralPath $original | Should -Be $true
            $manAfter = Read-QuarantineManifest -Run $run
            @($manAfter | Where-Object { $_.ItemId -eq $itemId }).Count | Should -Be 0

            # Re-quarantine, then block restore by pre-creating the destination.
            $srcFile2 = Join-Path $srcDir 'artifact2.dll'
            [System.IO.File]::WriteAllText($srcFile2, 'SC-payload-2', [System.Text.Encoding]::ASCII)
            $f2 = @((New-Finding -Id 'sc2' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc2'))
            $f2[0] | Add-Member -MemberType NoteProperty -Name 'QuarantinePaths' -Value @($srcFile2) -Force
            $plan2 = New-SccPlan -Run $run -Findings $f2 -Decisions @{ 'sc2' = 'REMOVE' }
            Invoke-SccRemediation -Run $run -Plan $plan2 -Execute
            $man2 = Read-QuarantineManifest -Run $run
            $id2 = @($man2 | Where-Object { $_.OriginalPath -eq $srcFile2 })[0].ItemId

            # Pre-create the destination so restore must refuse.
            [System.IO.File]::WriteAllText($srcFile2, 'blocker', [System.Text.Encoding]::ASCII)
            { Restore-SccQuarantineItem -Run $run -ItemId $id2 } | Should -Throw -Because 'destination already exists must refuse'

            Remove-Item -LiteralPath $original -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $srcFile2 -Force -ErrorAction SilentlyContinue
        } finally {
            if (Test-Path -LiteralPath $srcDir) { Remove-Item -LiteralPath $srcDir -Recurse -Force -ErrorAction SilentlyContinue }
            Remove-TestRun $run
        }
    }

    It 'Clear-SccQuarantine refuses without -Approved and wrong -ConfirmText, and works with both' {
        $run = New-TestRun
        try {
            # Seed a quarantine directory + manifest.
            $qDir = Join-Path (Join-Path $run.RunDir 'Quarantine') 'q'
            New-Item -ItemType Directory -Path $qDir -Force | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $qDir 'junk.bin'), 'x', [System.Text.Encoding]::ASCII)

            { Clear-SccQuarantine -Run $run } | Should -Throw -Because 'requires -Approved'
            { Clear-SccQuarantine -Run $run -Approved } | Should -Throw -Because 'requires exact -ConfirmText'
            { Clear-SccQuarantine -Run $run -Approved -ConfirmText 'WRONG' } | Should -Throw -Because 'requires exact -ConfirmText'

            { Clear-SccQuarantine -Run $run -Approved -ConfirmText 'PERMANENTLY DELETE' } | Should -Not -Throw
            Test-Path -LiteralPath $qDir | Should -Be $false
        } finally { Remove-TestRun $run }
    }
}

# ---------------------------------------------------------------------
Describe 'Scc.Remedy Plan Preview (Test-SccPlan)' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'returns a human-readable action list covering KEEP and REMOVE items' {
        $f = @(
            (New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1')
            (New-Finding -Id 'sc2' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc2')
        )
        $plan = New-SccPlan -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }
        # A smuggled raw plan object (bypassing owner-policy) to exercise the
        # non-ScreenConnect refusal branch in the preview path.
        $smuggled = [PSCustomObject]@{
            PlanVersion = '1.0'
            CreatedUtc  = '2026-08-26 00:00:00'
            CreatedBy   = 'tester'
            Items = @(
                [PSCustomObject]@{ FindingId='ad1'; Product='anydesk'; TargetType='Uninstall'; Action='REMOVE'; Detail=''; DisplayText='ad1'; ServiceName='AnyDesk Service'; InstallDir='C:\AnyDesk' }
            )
        }
        $preview = Test-SccPlan -Plan $plan
        $preview | Should -Not -BeNullOrEmpty
        $joined = @($preview) -join "`n"
        $joined | Should -BeLike '*stop service*'
        $joined | Should -BeLike '*quarantine*'
        $joined | Should -BeLike '*KEEP*'
        $smuggledPreview = Test-SccPlan -Plan $smuggled
        (@($smuggledPreview) -join "`n") | Should -BeLike '*not ScreenConnect*'
    }
}

# =====================================================================
# Security hardening regression tests (F1-F7)
# =====================================================================

Describe 'F1: AND-of-gates re-verification (poisoned-plan test)' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'poisoned plan with Product=screenconnect but arbitrary ServiceName performs ZERO destructive calls' {
        $run = New-TestRun
        try {
            $poison = [PSCustomObject]@{
                PlanVersion = '1.0'
                CreatedUtc  = '2026-08-26 00:00:00'
                CreatedBy   = 'attacker'
                Items = @(
                    [PSCustomObject]@{
                        FindingId   = 'sc-poison'
                        Product     = 'screenconnect'
                        TargetType  = 'Service'
                        Action      = 'REMOVE'
                        Detail      = ''
                        DisplayText = 'sc-poison [screenconnect]'
                        ServiceName = 'Defragsvc'
                        InstallDir  = 'C:\Windows\System32'
                        MainExe     = 'Defragsvc.exe'
                    }
                )
            }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Uninstall-SccTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $poison -Execute

            Should -Invoke Stop-SccTargetService -ModuleName 'Scc.Remedy' -Exactly 0
            Should -Invoke Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' -Exactly 0
            Should -Invoke Uninstall-SccTarget -ModuleName 'Scc.Remedy' -Exactly 0
            Should -Invoke Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' -Exactly 0
        } finally { Remove-TestRun $run }
    }

    It 'plan item with only InstallDir hint and no service match is rejected' {
        $run = New-TestRun
        try {
            $poison = [PSCustomObject]@{
                PlanVersion = '1.0'
                CreatedUtc  = '2026-08-26 00:00:00'
                CreatedBy   = 'tester'
                Items = @(
                    [PSCustomObject]@{
                        FindingId   = 'sc-dir-only'
                        Product     = 'screenconnect'
                        TargetType  = 'Service'
                        Action      = 'REMOVE'
                        Detail      = ''
                        DisplayText = 'sc-dir-only [screenconnect]'
                        ServiceName = ''
                        InstallDir  = 'C:\Fake\ScreenConnect\Path'
                        MainExe     = ''
                    }
                )
            }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Uninstall-SccTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $poison -Execute

            Should -Invoke Stop-SccTargetService -ModuleName 'Scc.Remedy' -Exactly 0
            Should -Invoke Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' -Exactly 0
        } finally { Remove-TestRun $run }
    }
}

Describe 'F2: Uninstaller validation (calc.exe rejection)' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'rejects a mocked UninstallString pointing at C:\Windows\System32\calc.exe' {
        $run = New-TestRun
        try {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Get-SccTargetUninstallData -ModuleName 'Scc.Remedy' {
                return [PSCustomObject]@{
                    UninstallString      = 'C:\Windows\System32\calc.exe /uninstall'
                    QuietUninstallString = ''
                    ProductCode          = ''
                    DisplayName          = 'ScreenConnect Client'
                    PSPath               = 'Registry::HKLM:\x'
                }
            }
            Mock Invoke-SccUninstallCommand -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute

            Should -Invoke Invoke-SccUninstallCommand -ModuleName 'Scc.Remedy' -Exactly 0

            $rem = Read-Remediation -Run $run
            $un = @($rem | Where-Object { $_.Action -eq 'Uninstall' })[0]
            $un.Result | Should -Be 'Failed'
            $un.Error | Should -BeLike '*uninstaller-validation-failed*'
        } finally { Remove-TestRun $run }
    }

    It 'allows a legitimate uninstaller under the verified install dir' {
        $run = New-TestRun
        try {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Get-SccTargetUninstallData -ModuleName 'Scc.Remedy' {
                return [PSCustomObject]@{
                    UninstallString      = 'C:\SC\sc1\ScreenConnect.Uninstall.exe'
                    QuietUninstallString = ''
                    ProductCode          = ''
                    DisplayName          = 'ScreenConnect Client'
                    PSPath               = 'Registry::HKLM:\x'
                }
            }
            Mock Test-SccUninstallExeValid -ModuleName 'Scc.Remedy' { return $true }
            Mock Invoke-SccUninstallCommand -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }
            Mock Move-SccTargetToQuarantine -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute

            $rem = Read-Remediation -Run $run
            $un = @($rem | Where-Object { $_.Action -eq 'Uninstall' })[0]
            $un.Result | Should -Be 'Succeeded'
        } finally { Remove-TestRun $run }
    }
}

Describe 'F3: Path traversal guard on restore' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'rejects restoring to a path containing double-dots (traversal)' {
        $run = New-TestRun
        try {
            $srcDir = Join-Path ([System.IO.Path]::GetTempPath()) ('scc_f3_' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
            $srcFile = Join-Path $srcDir 'evil.dll'
            [System.IO.File]::WriteAllText($srcFile, 'payload', [System.Text.Encoding]::ASCII)

            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $f[0] | Add-Member -MemberType NoteProperty -Name 'QuarantinePaths' -Value @($srcFile) -Force
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Uninstall-SccTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute

            $man = Read-QuarantineManifest -Run $run
            @($man).Count | Should -Be 1
            $itemId = $man[0].ItemId

            # Tamper the manifest to inject a traversal path
            $qBase = Join-Path $run.RunDir 'Quarantine'
            $mp = Join-Path $qBase 'quarantine-manifest.json'
            $man[0].OriginalPath = $srcDir + '\..\..\..\Windows\System32\evil.dll'
            [System.IO.File]::WriteAllText($mp, (ConvertTo-Json -InputObject $man -Depth 10), [System.Text.Encoding]::ASCII)

            { Restore-SccQuarantineItem -Run $run -ItemId $itemId } | Should -Throw -Because 'traversal path must be rejected'
        } finally {
            if (Test-Path -LiteralPath $srcDir) { Remove-Item -LiteralPath $srcDir -Recurse -Force -ErrorAction SilentlyContinue }
            Remove-TestRun $run
        }
    }
}

Describe 'F5: Process-kill self-protection (ancestor-PID chain)' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'Stop-SccTargetProcesses handles missing Get-CimInstance gracefully on Linux' {
        $run = New-TestRun
        try {
            InModuleScope -ModuleName 'Scc.Remedy' -Parameters @{ RunObj = $run } {
                param($RunObj)
                $script:remediationPath = Join-Path $RunObj.RunDir 'remediation.json'
                $script:remediationActions = @()
                Stop-SccTargetProcesses -InstallDir 'C:\Fake' -ServiceName '' -PlanItem ([PSCustomObject]@{ FindingId = 'test' }) -Run $RunObj
            }
            $rem = Read-Remediation -Run $run
            @($rem).Count | Should -BeGreaterOrEqual 1
            $skipped = @($rem | Where-Object { $_.Action -eq 'KillProcesses' -and $_.Result -eq 'Skipped' })
            @($skipped).Count | Should -BeGreaterOrEqual 1
        } finally { Remove-TestRun $run }
    }
}

Describe 'F6: Admin gate before -Execute' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'refuses -Execute when Test-SccIsAdmin returns false (mocked Windows)' {
        $run = New-TestRun
        try {
            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccIsAdmin -ModuleName 'Scc.Remedy' { return $false }

            { Invoke-SccRemediation -Run $run -Plan $plan -Execute } | Should -Throw -Because 'non-admin must be refused'
        } finally { Remove-TestRun $run }
    }
}

Describe 'F7: Quarantine reboot-resume on in-use file' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
        . $helperPath
    }

    It 'records a resume marker when Move-Item fails (in-use file simulation)' {
        $run = New-TestRun
        try {
            $srcDir = Join-Path ([System.IO.Path]::GetTempPath()) ('scc_f7_' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
            $srcFile = Join-Path $srcDir 'locked.dll'
            [System.IO.File]::WriteAllText($srcFile, 'locked-by-process', [System.Text.Encoding]::ASCII)

            $f = @((New-Finding -Id 'sc1' -Product 'screenconnect' -ServiceName 'ScreenConnect Client Service' -InstallDir 'C:\SC\sc1'))
            $f[0] | Add-Member -MemberType NoteProperty -Name 'QuarantinePaths' -Value @($srcFile) -Force
            $plan = New-SccPlan -Run $run -Findings $f -Decisions @{ 'sc1' = 'REMOVE' }

            Mock Test-SccScreenConnectTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Stop-SccTargetProcesses -ModuleName 'Scc.Remedy' { return $true }
            Mock Uninstall-SccTarget -ModuleName 'Scc.Remedy' { return $true }
            Mock Test-SccTargetRemoved -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetService -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetScheduledTask -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetRunKey -ModuleName 'Scc.Remedy' { return $true }
            Mock Remove-SccTargetFirewallRule -ModuleName 'Scc.Remedy' { return $true }
            # Override Move-Item to simulate failure
            Mock Move-Item -ModuleName 'Scc.Remedy' { throw 'The process cannot access the file' }

            Invoke-SccRemediation -Run $run -Plan $plan -Execute

            $rem = Read-Remediation -Run $run
            $quar = @($rem | Where-Object { $_.Action -eq 'Quarantine' })[0]
            $quar.Result | Should -Be 'PendingReboot'

            $resumePath = Join-Path $run.RunDir 'resume-marker.json'
            Test-Path -LiteralPath $resumePath | Should -Be $true
            $marker = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($resumePath))
            $marker.Phase | Should -Be 'quarantine-pending'
        } finally {
            if (Test-Path -LiteralPath $srcDir) { Remove-Item -LiteralPath $srcDir -Recurse -Force -ErrorAction SilentlyContinue }
            Remove-TestRun $run
        }
    }
}
