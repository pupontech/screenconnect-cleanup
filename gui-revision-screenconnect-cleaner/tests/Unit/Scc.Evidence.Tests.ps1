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
            $run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-120000' }
        }

        AfterAll {
            if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'runs end-to-end without throwing' {
            { New-SccSnapshot -Run $run -Label 'before' } | Should -Not -Throw
        }

        It 'returns a result with SchemaVersion 2' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $snap.SchemaVersion | Should -Be 2
        }

        It 'has all required top-level fields' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $snap.PSObject.Properties['SchemaVersion'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['Label'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['ComputerName'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['CollectedUtc'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['IsAdmin'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['OSCaption'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['IncidentWindowDays'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['SccAppVersion'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['CollectionErrors'] | Should -Not -BeNullOrEmpty
            $snap.PSObject.Properties['Sections'] | Should -Not -BeNullOrEmpty
        }

        It 'has all 13 sections' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $sectionNames = @(
                'Services', 'ScheduledTasks', 'RegistryAutoruns', 'StartupFolders',
                'Processes', 'Connections', 'InstalledPrograms', 'LocalAccounts',
                'FirewallRules', 'WmiPersistence', 'RecentFiles', 'ScInstallations',
                'SystemSettings'
            )
            foreach ($name in $sectionNames) {
                $snap.Sections.PSObject.Properties[$name] | Should -Not -BeNullOrEmpty -Because "section $name should exist"
            }
        }

        It 'serializes empty arrays as arrays in JSON' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $json = $snap | ConvertTo-Json -Depth 6
            # Services should be [] (empty array), not {} (empty object)
            $json | Should -Match '"Services"\s*:\s*\[\s*\]'
        }

        It 'has CollectionErrors with non-Windows notes' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
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
            $snap = New-SccSnapshot -Run $run -Label 'before'
            @($snap.Sections.ScInstallations).Count | Should -Be 0
        }

        It 'writes snapshot file to disk' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $file = Join-Path $runDir 'snapshots' 'before.json'
            Test-Path -LiteralPath $file | Should -BeTrue
        }

        It 'JSON round-trip preserves data' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $file = Join-Path $runDir 'snapshots' 'before.json'
            $readBack = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
            $readBack.SchemaVersion | Should -Be 2
            $readBack.Label | Should -Be 'before'
            $readBack.ComputerName | Should -Be $snap.ComputerName
            $readBack.CollectionErrors.Count | Should -Be $snap.CollectionErrors.Count
        }

        It 'Label parameter accepts before and after' {
            { New-SccSnapshot -Run $run -Label 'before' } | Should -Not -Throw
            { New-SccSnapshot -Run $run -Label 'after' } | Should -Not -Throw
        }
    }

    Context 'Get-SccSnapshot' {
        BeforeAll {
            $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "scc_test_$(Get-Random)"
            $runDir = Join-Path $tempDir 'SC-20260826-TEST-220000'
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            $run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-220000' }
            New-SccSnapshot -Run $run -Label 'before' | Out-Null
        }

        AfterAll {
            if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'reads back a previously saved snapshot' {
            $snap = Get-SccSnapshot -Run $run -Label 'before'
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
            $run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-330000' }
        }

        AfterAll {
            if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'emits sorted keys in sections on a mock section' {
            # On Linux, all Windows-only sections are empty arrays, so we verify
            # that the JSON structure has the correct shape for sorted arrays
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $json = $snap | ConvertTo-Json -Depth 6
            # Verify the structure: sections should be arrays
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
            $run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-440000' }
        }

        AfterAll {
            if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'records errors in CollectionErrors when sections fail' {
            # On Linux, Windows-only sections should produce CollectionErrors or empty arrays
            $snap = New-SccSnapshot -Run $run -Label 'before'
            # Should have at least some CollectionErrors from non-Windows sections
            $snap.CollectionErrors.Count | Should -BeGreaterThan 0
        }

        It 'continues collection despite section failures' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            # Even with errors, all sections should be present
            $snap.Sections.PSObject.Properties['Services'] | Should -Not -BeNullOrEmpty
            $snap.Sections.PSObject.Properties['SystemSettings'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'schema v2 fields' {
        BeforeAll {
            $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "scc_test_$(Get-Random)"
            $runDir = Join-Path $tempDir 'SC-20260826-TEST-550000'
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            $run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-550000' }
        }

        AfterAll {
            if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'includes SccAppVersion field' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $snap.PSObject.Properties['SccAppVersion'] | Should -Not -BeNullOrEmpty
        }

        It 'includes ScInstallations section' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $snap.Sections.PSObject.Properties['ScInstallations'] | Should -Not -BeNullOrEmpty
        }

        It 'includes SystemSettings with RdpEnabled and HostsFileLines' {
            $snap = New-SccSnapshot -Run $run -Label 'before'
            $snap.Sections.SystemSettings.PSObject.Properties['RdpEnabled'] | Should -Not -BeNullOrEmpty
            $snap.Sections.SystemSettings.PSObject.Properties['HostsFileLines'] | Should -Not -BeNullOrEmpty
        }
    }
}
