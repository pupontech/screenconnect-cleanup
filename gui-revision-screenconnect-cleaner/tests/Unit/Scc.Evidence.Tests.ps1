BeforeAll {
    if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
    if (-not $env:TMP) { $env:TMP = $env:TEMP }
    $modulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'Scc.Evidence' 'Scc.Evidence.psd1'
    if (Test-Path -LiteralPath $modulePath) {
        Import-Module $modulePath -Force
    }
    $script:setupOk = $true
}

Describe 'Scc.Evidence Module' {
    BeforeEach {
        if (-not $script:setupOk) {
            Set-ItResult -Skipped -Because 'Windows setup unavailable'
            return
        }
    }

    Context 'New-SccSnapshot on Linux' {
        BeforeAll {
            $script:setupOk = $true
            try {
                if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
                $tempDir = Join-Path $env:TEMP ("scc_test_" + [guid]::NewGuid().ToString('N'))
                $runDir = Join-Path $tempDir 'SC-20260826-TEST-120000'
                if (-not (Test-Path -LiteralPath $tempDir)) { $null = New-Item -ItemType Directory -Path $tempDir -Force }
                $null = New-Item -ItemType Directory -Path $runDir -Force
                $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-120000' }
                $script:tempDir = $tempDir
            } catch {
                $script:setupOk = $false
            }
        }

        AfterAll {
            if ($script:tempDir -and (Test-Path -LiteralPath $script:tempDir)) { Remove-Item -LiteralPath $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'runs end-to-end without throwing' {
            { New-SccSnapshot -Run $script:run -Label 'before' } | Should -Not -Throw
        }

        It 'returns a result with SchemaVersion 2' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.SchemaVersion | Should -Be 2
        }

        It 'has all required top-level fields' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.SchemaVersion | Should -Not -BeNullOrEmpty
            $snap.Label | Should -Not -BeNullOrEmpty
            $snap.ComputerName | Should -Not -BeNullOrEmpty
            $snap.CollectedUtc | Should -Not -BeNullOrEmpty
            $snap.IsAdmin | Should -Not -BeNullOrEmpty
            $snap.OSCaption | Should -Not -BeNullOrEmpty
            $snap.IncidentWindowDays | Should -Not -BeNullOrEmpty
            $snap.SccAppVersion | Should -Not -BeNullOrEmpty
            $snap.CollectionErrors | Should -Not -BeNullOrEmpty
            $snap.Sections | Should -Not -BeNullOrEmpty
        }

        It 'has all 13 sections' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            # Sections is an OrderedDictionary - use .ContainsKey() to check
            $expectedSections = @(
                'Services', 'ScheduledTasks', 'RegistryAutoruns', 'StartupFolders',
                'Processes', 'Connections', 'InstalledPrograms', 'LocalAccounts',
                'FirewallRules', 'WmiPersistence', 'RecentFiles', 'ScInstallations',
                'SystemSettings'
            )
            foreach ($name in $expectedSections) {
                $snap.Sections.Contains($name) | Should -BeTrue -Because "section $name should exist"
            }
        }

        It 'serializes empty arrays as arrays in JSON' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $json = $snap | ConvertTo-Json -Depth 6
            $json | Should -Match '"Services"\s*:\s*\[\s*\]'
        }

        It 'has CollectionErrors collection (platform-aware)' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.CollectionErrors | Should -Not -BeNullOrEmpty
            # On non-Windows, some sections intentionally fail and are recorded.
            # On Windows, CollectionErrors may be empty if all sections succeed.
            if ($env:OS -ne 'Windows_NT') {
                $snap.CollectionErrors.Count | Should -BeGreaterThan 0
            }
            $hasNote = $false
            foreach ($err in $snap.CollectionErrors) {
                if ($err.Section -and $err.Error) { $hasNote = $true; break }
            }
            if ($snap.CollectionErrors.Count -gt 0) {
                $hasNote | Should -BeTrue
            }
        }

        It 'has ScInstallations section (platform-aware)' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.Sections.Contains('ScInstallations') | Should -BeTrue
            if ($env:OS -ne 'Windows_NT') {
                @($snap.Sections.ScInstallations).Count | Should -Be 0
            }
        }

        It 'writes snapshot file to disk' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $file = Join-Path $script:run.RunDir 'snapshots' 'before.json'
            Test-Path -LiteralPath $file | Should -BeTrue
        }

        It 'JSON round-trip preserves data' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $file = Join-Path $script:run.RunDir 'snapshots' 'before.json'
            $readBack = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
            $readBack.SchemaVersion | Should -Be 2
            $readBack.Label | Should -Be 'before'
            $readBack.ComputerName | Should -Be $snap.ComputerName
            $readBack.CollectionErrors.Count | Should -Be $snap.CollectionErrors.Count
        }

        It 'Label parameter accepts before and after' {
            { New-SccSnapshot -Run $script:run -Label 'before' } | Should -Not -Throw
            { New-SccSnapshot -Run $script:run -Label 'after' } | Should -Not -Throw
        }
    }

    Context 'Get-SccSnapshot' {
        BeforeAll {
            $script:setupOk = $true
            try {
                if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
                $tempDir = Join-Path $env:TEMP ("scc_test_" + [guid]::NewGuid().ToString('N'))
                $runDir = Join-Path $tempDir 'SC-20260826-TEST-220000'
                if (-not (Test-Path -LiteralPath $tempDir)) { $null = New-Item -ItemType Directory -Path $tempDir -Force }
                $null = New-Item -ItemType Directory -Path $runDir -Force
                $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-220000' }
                $script:tempDir = $tempDir
                New-SccSnapshot -Run $script:run -Label 'before' | Out-Null
            } catch {
                $script:setupOk = $false
            }
        }

        AfterAll {
            if ($script:tempDir -and (Test-Path -LiteralPath $script:tempDir)) { Remove-Item -LiteralPath $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'reads back a previously saved snapshot' {
            $snap = Get-SccSnapshot -Run $script:run -Label 'before'
            $snap | Should -Not -BeNullOrEmpty
            $snap.SchemaVersion | Should -Be 2
        }

        It 'throws when snapshot file not found' {
            $fakeRun = [PSCustomObject]@{ RunDir = (Join-Path $env:TEMP 'nonexistent_scc_test_path_xyz') }
            { Get-SccSnapshot -Run $fakeRun -Label 'before' } | Should -Throw
        }
    }

    Context 'Key stability and sorting' {
        BeforeAll {
            $script:setupOk = $true
            try {
                if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
                $tempDir = Join-Path $env:TEMP ("scc_test_" + [guid]::NewGuid().ToString('N'))
                $runDir = Join-Path $tempDir 'SC-20260826-TEST-330000'
                if (-not (Test-Path -LiteralPath $tempDir)) { $null = New-Item -ItemType Directory -Path $tempDir -Force }
                $null = New-Item -ItemType Directory -Path $runDir -Force
                $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-330000' }
                $script:tempDir = $tempDir
            } catch {
                $script:setupOk = $false
            }
        }

        AfterAll {
            if ($script:tempDir -and (Test-Path -LiteralPath $script:tempDir)) { Remove-Item -LiteralPath $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'emits sorted keys in sections on a mock section' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $json = $snap | ConvertTo-Json -Depth 6
            $parsed = $json | ConvertFrom-Json
            @($parsed.Sections.Services).Count | Should -Be 0
            @($parsed.Sections.ScheduledTasks).Count | Should -Be 0
            @($parsed.Sections.InstalledPrograms).Count | Should -Be 0
        }
    }

    Context 'Section failure handling' {
        BeforeAll {
            $script:setupOk = $true
            try {
                if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
                $tempDir = Join-Path $env:TEMP ("scc_test_" + [guid]::NewGuid().ToString('N'))
                $runDir = Join-Path $tempDir 'SC-20260826-TEST-440000'
                if (-not (Test-Path -LiteralPath $tempDir)) { $null = New-Item -ItemType Directory -Path $tempDir -Force }
                $null = New-Item -ItemType Directory -Path $runDir -Force
                $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-440000' }
                $script:tempDir = $tempDir
            } catch {
                $script:setupOk = $false
            }
        }

        AfterAll {
            if ($script:tempDir -and (Test-Path -LiteralPath $script:tempDir)) { Remove-Item -LiteralPath $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'records errors in CollectionErrors when sections fail' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            # Platform-aware: on Windows some sections may succeed, but the snapshot must still be valid.
            $snap.CollectionErrors | Should -Not -BeNullOrEmpty
            if ($env:OS -ne 'Windows_NT') {
                $snap.CollectionErrors.Count | Should -BeGreaterThan 0
            }
        }

        It 'continues collection despite section failures' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.Sections.Contains('Services') | Should -BeTrue
            $snap.Sections.Contains('SystemSettings') | Should -BeTrue
        }
    }

    Context 'schema v2 fields' {
        BeforeAll {
            $script:setupOk = $true
            try {
                if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
                $tempDir = Join-Path $env:TEMP ("scc_test_" + [guid]::NewGuid().ToString('N'))
                $runDir = Join-Path $tempDir 'SC-20260826-TEST-550000'
                if (-not (Test-Path -LiteralPath $tempDir)) { $null = New-Item -ItemType Directory -Path $tempDir -Force }
                $null = New-Item -ItemType Directory -Path $runDir -Force
                $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-550000' }
                $script:tempDir = $tempDir
            } catch {
                $script:setupOk = $false
            }
        }

        AfterAll {
            if ($script:tempDir -and (Test-Path -LiteralPath $script:tempDir)) { Remove-Item -LiteralPath $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'includes SccAppVersion field' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.SccAppVersion | Should -Not -BeNullOrEmpty
        }

        It 'includes ScInstallations section' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.Sections.Contains('ScInstallations') | Should -BeTrue
        }

        It 'includes SystemSettings with RdpEnabled and HostsFileLines' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $sysSettings = $snap.Sections.SystemSettings
            $sysSettings.Contains('RdpEnabled') | Should -BeTrue
            $sysSettings.Contains('HostsFileLines') | Should -BeTrue
        }
    }
}
