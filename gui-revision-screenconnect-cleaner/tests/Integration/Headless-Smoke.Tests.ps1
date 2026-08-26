# Headless-Smoke.Tests.ps1 - Integration wiring validator (Pester 6)
# Runs on Linux pwsh 7.6.5 (no Windows APIs required).
# Pure ASCII, no BOM. PowerShell 5.1 compatible.

BeforeAll {
    $ErrorActionPreference = 'Stop'
    if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }

    # Isolate config so we do not pollute the user's real config.
    $script:origLocalAppData = $env:LocalAppData
    $script:origProgramData = $env:ProgramData
    $env:LocalAppData = Join-Path $env:TEMP ('scc-smoke-la-' + [guid]::NewGuid().ToString('N'))
    $env:ProgramData = Join-Path $env:TEMP ('scc-smoke-pd-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $env:LocalAppData -Force
    $null = New-Item -ItemType Directory -Path $env:ProgramData -Force

    $script:srcRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../src'))
    $script:newRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $sep = [System.IO.Path]::PathSeparator
    $env:PSModulePath = $script:srcRoot + $sep + $env:PSModulePath

    # Discover expected modules from src/ at runtime
    $script:expectedModules = @(
        'Scc.Core','Scc.Detection','Scc.Evidence','Scc.Snapshots',
        'Scc.Tools','Scc.Scanners','Scc.Remedy','Scc.Report','Scc.UI'
    )
    $script:discoveredModules = @(
        Get-ChildItem -Path $script:srcRoot -Directory -ErrorAction Stop |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName ($_.Name + '.psd1')) } |
            Select-Object -ExpandProperty Name
    )

    # Import all that exist (wiring validator)
    $script:importErrors = @()
    foreach ($m in $script:expectedModules) {
        $manifest = Join-Path $script:srcRoot $m "$m.psd1"
        if (-not (Test-Path -LiteralPath $manifest)) {
            $script:importErrors += ("MISSING: {0} ({1})" -f $m, $manifest)
            continue
        }
        try {
            Import-Module -Name $manifest -Force -ErrorAction Stop
        } catch {
            $script:importErrors += ("IMPORT-FAIL: {0} ({1})" -f $m, $_.Exception.Message)
        }
    }

    # Temp report root for the headless run
    $script:smokeReportRoot = Join-Path $env:TEMP ('scc-smoke-reports-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $script:smokeReportRoot -Force

    # Plan file with 0 REMOVE items (KEEP only, so remediation is dry-run safe)
    $script:planFile = Join-Path $env:TEMP ('scc-smoke-plan-' + [guid]::NewGuid().ToString('N') + '.json')
    $planObj = [ordered]@{
        PlanVersion = 1
        CreatedUtc = '2026-01-01T00:00:00Z'
        CreatedBy = 'smoke-test'
        Items = @(
            [ordered]@{
                FindingId = 'SC-KEEP-001'
                Product = 'ScreenConnect'
                TargetType = 'Service'
                Action = 'KEEP'
                Detail = 'smoke test KEEP'
                DisplayText = 'Keep example'
                ServiceName = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                InstallDir = 'C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                MainExe = 'ScreenConnect.ClientService.exe'
                UninstallRegistryKey = ''
                RelayHost = 'support.example.com'
            }
        )
    }
    $planJson = $planObj | ConvertTo-Json -Depth 8
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($script:planFile, $planJson, $utf8NoBom)
}

AfterAll {
    try { Remove-Item -LiteralPath $script:smokeReportRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    try { Remove-Item -LiteralPath $script:planFile -Force -ErrorAction SilentlyContinue } catch { }
    if ($null -ne $script:origLocalAppData) { $env:LocalAppData = $script:origLocalAppData } else { Remove-Item Env:LocalAppData -ErrorAction SilentlyContinue }
    if ($null -ne $script:origProgramData) { $env:ProgramData = $script:origProgramData } else { Remove-Item Env:ProgramData -ErrorAction SilentlyContinue }
}

Describe 'Headless Smoke - Wiring validator' {

    It 'discovers all expected modules from src/ (FAIL if any missing)' {
        # This is the wiring gate: if a builder has not landed their module, the smoke fails.
        foreach ($m in $script:expectedModules) {
            $script:discoveredModules | Should -Contain $m -Because ("module {0} must exist under src/" -f $m)
        }
        @($script:discoveredModules).Count | Should -BeGreaterOrEqual @($script:expectedModules).Count
    }

    It 'imports all expected modules cleanly (FAIL on missing dependency)' {
        if (@($script:importErrors).Count -gt 0) {
            $msg = ($script:importErrors -join "`n")
            Throw ("Module import failures:`n" + $msg)
        }
        foreach ($m in $script:expectedModules) {
            Get-Module -Name $m | Should -Not -BeNullOrEmpty -Because ("{0} must be importable" -f $m)
        }
    }

    It 'exposes exactly the public functions per contract (minimal exports)' {
        # Spot-check a few key exports to ensure contract is respected
        (Get-Command -Module Scc.Core -ErrorAction Stop).Name | Should -Contain 'New-SccRun'
        (Get-Command -Module Scc.Core -ErrorAction Stop).Name | Should -Contain 'Get-SccConfig'
        (Get-Command -Module Scc.Detection -ErrorAction Stop).Name | Should -Contain 'Invoke-SccDetection'
        (Get-Command -Module Scc.Detection -ErrorAction Stop).Name | Should -Contain 'Invoke-SccDetectionSelfTest'
        (Get-Command -Module Scc.Evidence -ErrorAction Stop).Name | Should -Contain 'New-SccSnapshot'
        (Get-Command -Module Scc.Snapshots -ErrorAction Stop).Name | Should -Contain 'Compare-SccSnapshots'
        (Get-Command -Module Scc.Report -ErrorAction Stop).Name | Should -Contain 'New-SccReport'
        (Get-Command -Module Scc.UI -ErrorAction Stop).Name | Should -Contain 'New-SccWorkflow'
        (Get-Command -Module Scc.UI -ErrorAction Stop).Name | Should -Contain 'Start-SccWorkflow'
    }
}

Describe 'Headless Smoke - Full pipeline (SkipScanners, mocked detection)' {

    BeforeAll {
        # Mock detection inventories inside Scc.Detection to return synthetic
        # ScreenConnect service+process+uninstall -> 1 instance
        Mock -ModuleName Scc.Detection Get-SccServiceInventory {
            return @(
                [PSCustomObject]@{
                    Name = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    DisplayName = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    PathName = '"C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=support.example.com&p=8041&s=11111111-2222-3333-4444-555555555555&k=BgIAAACkAABSU0ExAAIAAAEAAQ==&c1=Test"'
                    State = 'Running'
                    StartMode = 'Auto'
                    StartName = 'LocalSystem'
                    ProcessId = 1234
                    Description = ''
                }
            )
        }

        Mock -ModuleName Scc.Detection Get-SccProcessInventory {
            return @(
                [PSCustomObject]@{
                    ProcessId = 1234
                    ParentProcessId = 4
                    Name = 'ScreenConnect.ClientService.exe'
                    ExecutablePath = 'C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\ScreenConnect.ClientService.exe'
                    CommandLine = '"C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=support.example.com&p=8041&s=11111111-2222-3333-4444-555555555555&k=BgIAAACkAABSU0ExAAIAAAEAAQ==&c1=Test"'
                    CreationDate = (Get-Date)
                }
            )
        }

        Mock -ModuleName Scc.Detection Get-SccUninstallInventory {
            return @(
                [PSCustomObject]@{
                    RegistryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4}'
                    KeyName = '{A1B2C3D4}'
                    DisplayName = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    DisplayVersion = '24.1'
                    Publisher = 'ConnectWise'
                    InstallDate = '20260826'
                    InstallLocation = 'C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    UninstallString = '"C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\Uninstall.exe"'
                    QuietUninstallString = ''
                }
            )
        }

        Mock -ModuleName Scc.Detection Get-SccServiceInstallEvents { return @() }
        Mock -ModuleName Scc.Detection Get-SccConnectionsForPids { return @() }
        Mock -ModuleName Scc.Detection Get-SccScDirs { return @() }

        # Create run under the temp report root
        $script:smokeRun = New-SccRun -ReportRoot $script:smokeReportRoot -Technician 'Smoke' -Client 'SmokeClient'
        $script:smokeRunDir = $script:smokeRun.RunDir

        # Build workflow Full + SkipScanners, inject plan via -PlanPath (0 REMOVE)
        $script:smokeWorkflow = New-SccWorkflow -Run $script:smokeRun -Mode Full -SkipScanners
        $script:smokeWorkflow.PlanPath = $script:planFile
        # Also copy to RunDir so Review finds it via file path
        Copy-Item -LiteralPath $script:planFile -Destination (Join-Path $script:smokeRunDir 'plan.json') -Force

        # Run the pipeline (state machine)
        $null = Start-SccWorkflow -Workflow $script:smokeWorkflow -Mode Full -SkipScanners -PlanPath $script:planFile
    }

    It 'creates findings with exactly 1 ScreenConnect instance (mocked inventories collapsed)' {
        $findingsPath = Join-Path $script:smokeRunDir 'findings.json'
        Test-Path -LiteralPath $findingsPath | Should -Be $true
        $findings = Get-Content -LiteralPath $findingsPath -Raw | ConvertFrom-Json
        $sc = @($findings.ScreenConnect)
        @($sc).Count | Should -Be 1 -Because 'service+process+uninstall with same identifier must deduplicate to 1 instance'
        $sc[0].RelayHost | Should -Be 'support.example.com'
    }

    It 'completes all stages (Preflight may be Skipped on Linux)' {
        $statePath = Join-Path $script:smokeRunDir 'runstate.json'
        Test-Path -LiteralPath $statePath | Should -Be $true
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        @($state.Stages).Count | Should -Be 9
        # Stage 0 Preflight: accept Completed or Skipped on non-Windows
        $pre = $state.Stages | Where-Object { $_.Index -eq 0 }
        $pre.Status | Should -Match '^(Completed|Skipped)$'
        # SnapshotBefore, Detection, Review, Compare, Report must be Completed
        foreach ($idx in @(1,2,3,7,8)) {
            $st = $state.Stages | Where-Object { $_.Index -eq $idx }
            $st.Status | Should -Be 'Completed' -Because ("stage {0} {1} must be Completed" -f $idx, $st.Name)
        }
        # Scanners must be Skipped
        ($state.Stages | Where-Object { $_.Index -eq 5 }).Status | Should -Be 'Skipped'
        # Remediate: with 0 REMOVE items it completes (dry-run)
        ($state.Stages | Where-Object { $_.Index -eq 4 }).Status | Should -Be 'Completed'
        # SnapshotAfter must be Completed
        ($state.Stages | Where-Object { $_.Index -eq 6 }).Status | Should -Be 'Completed'
    }

    It 'produces snapshots before.json, after.json and diff.json' {
        Test-Path -LiteralPath (Join-Path $script:smokeRunDir 'snapshots/before.json') | Should -Be $true
        Test-Path -LiteralPath (Join-Path $script:smokeRunDir 'snapshots/after.json') | Should -Be $true
        $diffPath = Join-Path $script:smokeRunDir 'snapshots/diff.json'
        Test-Path -LiteralPath $diffPath | Should -Be $true
        $diff = Get-Content -LiteralPath $diffPath -Raw | ConvertFrom-Json
        $diff.Summary | Should -Not -BeNullOrEmpty
    }

    It 'produces report.html, report.json, technician-summary.txt (all three)' {
        $html = Join-Path $script:smokeRunDir 'report.html'
        $json = Join-Path $script:smokeRunDir 'report.json'
        $txt = Join-Path $script:smokeRunDir 'technician-summary.txt'
        Test-Path -LiteralPath $html | Should -Be $true
        Test-Path -LiteralPath $json | Should -Be $true
        Test-Path -LiteralPath $txt | Should -Be $true
        # report.json must parse and contain summary counts
        { Get-Content -LiteralPath $json -Raw | ConvertFrom-Json } | Should -Not -Throw
        $parsed = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
        $parsed.Summary | Should -Not -BeNullOrEmpty
        # report.html must be self-contained single file with sections
        $htmlRaw = Get-Content -LiteralPath $html -Raw
        $htmlRaw | Should -Match 'Executive Summary'
        $htmlRaw | Should -Match 'ScreenConnect Findings'
    }

    It 'leaves quarantine empty (no destructive function invoked)' {
        # Remedy quarantine dir on Linux falls back to RunDir/Quarantine/q
        $qDir = Join-Path $script:smokeRunDir 'Quarantine/q'
        $qDir2 = (Get-SccPaths -Run $script:smokeRun).QuarantineRoot
        $foundFiles = @()
        if (Test-Path -LiteralPath $qDir) {
            $foundFiles += @(Get-ChildItem -LiteralPath $qDir -File -Recurse -ErrorAction SilentlyContinue)
        }
        # Also check ProgramData fallback path if different
        if ($qDir2 -ne $qDir -and (Test-Path -LiteralPath $qDir2)) {
            $foundFiles += @(Get-ChildItem -LiteralPath $qDir2 -File -Recurse -ErrorAction SilentlyContinue)
        }
        # Check manifest too - should be absent or empty
        $manifest = Join-Path $script:smokeRunDir 'Quarantine/quarantine-manifest.json'
        if (Test-Path -LiteralPath $manifest) {
            $m = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            @($m).Count | Should -Be 0 -Because 'quarantine manifest must be empty when plan has 0 REMOVE items'
        }
        @($foundFiles).Count | Should -Be 0 -Because 'no artifacts should be quarantined in dry-run / KEEP-only plan'
    }

    It 'never auto-approves: without PlanPath the workflow stops at AwaitingReview' {
        # Verify the guard by running a second workflow without a plan
        $run2 = New-SccRun -ReportRoot $script:smokeReportRoot -Technician 'Smoke2' -Client 'SmokeClient2'
        $wf2 = New-SccWorkflow -Run $run2 -Mode Full -SkipScanners
        # Re-mock inside this It? Mocks from BeforeAll are still active for Scc.Detection
        $null = Start-SccWorkflow -Workflow $wf2 -Mode Full -SkipScanners
        $wf2.Status | Should -Be 'AwaitingReview'
        ($wf2.Stages | Where-Object { $_.Index -eq 3 }).Status | Should -Be 'AwaitingReview'
    }
}
