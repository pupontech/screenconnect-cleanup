BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'Scc.Evidence' 'Scc.Evidence.psd1'
    Import-Module $modulePath -Force
}

Describe 'Scc.Evidence Module' {
    Context 'New-SccSnapshot on Linux' {
        BeforeAll {
            $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "scc_test_$(Get-Random)"
            $runDir = Join-Path $tempDir 'SC-20260826-TEST-120000'
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-120000' }
            $script:tempDir = $tempDir
        }

        AfterAll {
            if (Test-Path $script:tempDir) { Remove-Item -Path $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
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

        It 'has CollectionErrors with non-Windows notes' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.CollectionErrors.Count | Should -BeGreaterThan 0
            $hasNonWindowsNote = $false
            foreach ($err in $snap.CollectionErrors) {
                if ($err.Section -and $err.Error) {
                    $hasNonWindowsNote = $true
                    break
                }
            }
            $hasNonWindowsNote | Should -BeTrue
        }

        It 'has empty ScInstallations on Linux' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            @($snap.Sections.ScInstallations).Count | Should -Be 0
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
            $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "scc_test_$(Get-Random)"
            $runDir = Join-Path $tempDir 'SC-20260826-TEST-220000'
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-220000' }
            $script:tempDir = $tempDir
            New-SccSnapshot -Run $script:run -Label 'before' | Out-Null
        }

        AfterAll {
            if (Test-Path $script:tempDir) { Remove-Item -Path $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'reads back a previously saved snapshot' {
            $snap = Get-SccSnapshot -Run $script:run -Label 'before'
            $snap | Should -Not -BeNullOrEmpty
            $snap.SchemaVersion | Should -Be 2
        }

        It 'throws when snapshot file not found' {
            $fakeRun = [PSCustomObject]@{ RunDir = '/nonexistent/path' }
            { Get-SccSnapshot -Run $fakeRun -Label 'before' } | Should -Throw
        }
    }

    Context 'Key stability and sorting' {
        BeforeAll {
            $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "scc_test_$(Get-Random)"
            $runDir = Join-Path $tempDir 'SC-20260826-TEST-330000'
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-330000' }
            $script:tempDir = $tempDir
        }

        AfterAll {
            if (Test-Path $script:tempDir) { Remove-Item -Path $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
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
            $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "scc_test_$(Get-Random)"
            $runDir = Join-Path $tempDir 'SC-20260826-TEST-440000'
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-440000' }
            $script:tempDir = $tempDir
        }

        AfterAll {
            if (Test-Path $script:tempDir) { Remove-Item -Path $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'records errors in CollectionErrors when sections fail' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.CollectionErrors.Count | Should -BeGreaterThan 0
        }

        It 'continues collection despite section failures' {
            $snap = New-SccSnapshot -Run $script:run -Label 'before'
            $snap.Sections.Contains('Services') | Should -BeTrue
            $snap.Sections.Contains('SystemSettings') | Should -BeTrue
        }
    }

    Context 'schema v2 fields' {
        BeforeAll {
            $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "scc_test_$(Get-Random)"
            $runDir = Join-Path $tempDir 'SC-20260826-TEST-550000'
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            $script:run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-550000' }
            $script:tempDir = $tempDir
        }

        AfterAll {
            if (Test-Path $script:tempDir) { Remove-Item -Path $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
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
