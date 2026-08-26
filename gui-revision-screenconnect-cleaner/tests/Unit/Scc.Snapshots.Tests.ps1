BeforeAll {
    $snapshotsModulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'Scc.Snapshots' 'Scc.Snapshots.psd1'
    Import-Module $snapshotsModulePath -Force
    $evidenceModulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'Scc.Evidence' 'Scc.Evidence.psd1'
    Import-Module $evidenceModulePath -Force
}

Describe 'Scc.Snapshots Module' {
    Context 'Compare-SccSnapshots with synthetic snapshots' {
        BeforeAll {
            $beforeSnap = [PSCustomObject]@{
                SchemaVersion      = 2
                Label              = 'before'
                ComputerName       = 'TEST-PC'
                CollectedUtc       = '2026-08-26 10:00:00'
                IsAdmin            = $true
                OSCaption          = 'Windows 10'
                IncidentWindowDays = 0
                SccAppVersion      = '0.1.0'
                CollectionErrors   = @()
                Sections           = [ordered]@{
                    Services = @(
                        [PSCustomObject]@{ Key = 'WinSvc1'; Name = 'WinSvc1'; State = 'Running' }
                        [PSCustomObject]@{ Key = 'ScreenConnect Client'; Name = 'ScreenConnect Client'; State = 'Running' }
                        [PSCustomObject]@{ Key = 'BenignSvc'; Name = 'BenignSvc'; State = 'Stopped' }
                    )
                    ScheduledTasks   = @(
                        [PSCustomObject]@{ Key = '\Task1|DoStuff'; TaskName = 'DoStuff'; TaskPath = '\'; State = 'Ready' }
                    )
                    RegistryAutoruns = @()
                    StartupFolders   = @()
                    Processes        = @()
                    Connections      = @()
                    InstalledPrograms = @()
                    LocalAccounts    = @()
                    FirewallRules    = @()
                    WmiPersistence   = @()
                    RecentFiles      = @()
                    ScInstallations  = @()
                    SystemSettings   = [ordered]@{ RdpEnabled = $true; HostsFileLines = @() }
                }
            }

            $afterSnap = [PSCustomObject]@{
                SchemaVersion      = 2
                Label              = 'after'
                ComputerName       = 'TEST-PC'
                CollectedUtc       = '2026-08-26 12:00:00'
                IsAdmin            = $true
                OSCaption          = 'Windows 10'
                IncidentWindowDays = 0
                SccAppVersion      = '0.1.0'
                CollectionErrors   = @()
                Sections           = [ordered]@{
                    Services = @(
                        [PSCustomObject]@{ Key = 'WinSvc1'; Name = 'WinSvc1'; State = 'Stopped' }
                        # ScreenConnect Client removed
                        [PSCustomObject]@{ Key = 'BenignSvc'; Name = 'BenignSvc'; State = 'Running' }
                        [PSCustomObject]@{ Key = 'NewRatSvc'; Name = 'NewRatSvc'; State = 'Running' }
                    )
                    ScheduledTasks   = @(
                        [PSCustomObject]@{ Key = '\Task1|DoStuff'; TaskName = 'DoStuff'; TaskPath = '\'; State = 'Running' }
                    )
                    RegistryAutoruns = @()
                    StartupFolders   = @()
                    Processes        = @()
                    Connections      = @()
                    InstalledPrograms = @()
                    LocalAccounts    = @()
                    FirewallRules    = @()
                    WmiPersistence   = @()
                    RecentFiles      = @()
                    ScInstallations  = @()
                    SystemSettings   = [ordered]@{ RdpEnabled = $false; HostsFileLines = @() }
                }
            }
        }

        It 'returns correct summary counts' {
            $diff = Compare-SccSnapshots -Before $beforeSnap -After $afterSnap
            # Services: WinSvc1 still present (changed State), ScreenConnect Client removed, BenignSvc still present, NewRatSvc new
            $diff.Summary.RemovedCount | Should -Be 1  # ScreenConnect Client
            $diff.Summary.NewCount | Should -Be 1      # NewRatSvc
            $diff.Summary.ChangedCount | Should -BeGreaterThan 0  # WinSvc1 state, SystemSettings RdpEnabled
        }

        It 'identifies removed items' {
            $diff = Compare-SccSnapshots -Before $beforeSnap -After $afterSnap
            $svcDiff = $null
            foreach ($sd in $diff.Sections) {
                if ($sd.Section -eq 'Services') {
                    $svcDiff = $sd
                    break
                }
            }
            $svcDiff | Should -Not -BeNullOrEmpty
            $svcDiff.Removed | Should -Contain 'ScreenConnect Client'
        }

        It 'identifies new items' {
            $diff = Compare-SccSnapshots -Before $beforeSnap -After $afterSnap
            $svcDiff = $null
            foreach ($sd in $diff.Sections) {
                if ($sd.Section -eq 'Services') {
                    $svcDiff = $sd
                    break
                }
            }
            $svcDiff | Should -Not -BeNullOrEmpty
            $svcDiff.New | Should -Contain 'NewRatSvc'
        }

        It 'identifies changed items with field details' {
            $diff = Compare-SccSnapshots -Before $beforeSnap -After $afterSnap
            $svcDiff = $null
            foreach ($sd in $diff.Sections) {
                if ($sd.Section -eq 'Services') {
                    $svcDiff = $sd
                    break
                }
            }
            $svcDiff | Should -Not -BeNullOrEmpty
            $changedKeys = @($svcDiff.Changed | ForEach-Object { $_.Key })
            $changedKeys | Should -Contain 'WinSvc1'
            $winSvc1Change = $svcDiff.Changed | Where-Object { $_.Key -eq 'WinSvc1' }
            $winSvc1Change.Fields | Should -Contain 'State'
        }

        It 'identifies still-present items' {
            $diff = Compare-SccSnapshots -Before $beforeSnap -After $afterSnap
            $svcDiff = $null
            foreach ($sd in $diff.Sections) {
                if ($sd.Section -eq 'Services') {
                    $svcDiff = $sd
                    break
                }
            }
            $svcDiff | Should -Not -BeNullOrEmpty
            $svcDiff.StillPresent | Should -Contain 'BenignSvc'
        }

        It 'reports object section changes' {
            $diff = Compare-SccSnapshots -Before $beforeSnap -After $afterSnap
            $sysDiff = $null
            foreach ($sd in $diff.Sections) {
                if ($sd.Section -eq 'SystemSettings') {
                    $sysDiff = $sd
                    break
                }
            }
            $sysDiff | Should -Not -BeNullOrEmpty
            @($sysDiff.Changed).Count | Should -BeGreaterThan 0
        }

        It 'produces identical result on identical snapshots' {
            $diff = Compare-SccSnapshots -Before $beforeSnap -After $beforeSnap
            $diff.Summary.RemovedCount | Should -Be 0
            $diff.Summary.NewCount | Should -Be 0
            $diff.Summary.ChangedCount | Should -Be 0
        }

        It 'handles missing sections as empty' {
            $emptySnap = [PSCustomObject]@{
                SchemaVersion = 2
                Label = 'empty'
                ComputerName = 'EMPTY'
                CollectedUtc = '2026-08-26 00:00:00'
                Sections = [ordered]@{}
            }
            $diff = Compare-SccSnapshots -Before $emptySnap -After $emptySnap
            $diff | Should -Not -BeNullOrEmpty
            $diff.Summary.RemovedCount | Should -Be 0
        }
    }

    Context 'Test-SccResurrection' {
        BeforeAll {
            $diffWithResurrection = [PSCustomObject]@{
                SchemaVersion = 1
                Summary = [ordered]@{ RemovedCount = 0; StillPresentCount = 0; NewCount = 1; ChangedCount = 0 }
                Sections = @(
                    [PSCustomObject]@{
                        Section      = 'Services'
                        Removed      = @()
                        StillPresent = @()
                        New          = @('ScreenConnect Client')
                        Changed      = @()
                    }
                    [PSCustomObject]@{
                        Section      = 'ScInstallations'
                        Removed      = @()
                        StillPresent = @()
                        New          = @()
                        Changed      = @()
                    }
                )
            }

            $diffNoResurrection = [PSCustomObject]@{
                SchemaVersion = 1
                Summary = [ordered]@{ RemovedCount = 0; StillPresentCount = 1; NewCount = 0; ChangedCount = 0 }
                Sections = @(
                    [PSCustomObject]@{
                        Section      = 'Services'
                        Removed      = @()
                        StillPresent = @('BenignWindowsSvc')
                        New          = @()
                        Changed      = @()
                    }
                    [PSCustomObject]@{
                        Section      = 'ScInstallations'
                        Removed      = @()
                        StillPresent = @()
                        New          = @()
                        Changed      = @()
                    }
                )
            }
        }

        It 'flags new ScreenConnect service as resurrection' {
            $flagged = Test-SccResurrection -Diff $diffWithResurrection
            $flagged.Count | Should -BeGreaterThan 0
            $svcFlag = $flagged | Where-Object { $_.Section -eq 'Services' -and $_.Key -eq 'ScreenConnect Client' }
            $svcFlag | Should -Not -BeNullOrEmpty
        }

        It 'does not flag benign services' {
            $flagged = Test-SccResurrection -Diff $diffNoResurrection
            $flagged.Count | Should -Be 0
        }

        It 'flags new AnyDesk service' {
            $diff = [PSCustomObject]@{
                Sections = @(
                    [PSCustomObject]@{
                        Section = 'Services'
                        Removed = @()
                        StillPresent = @()
                        New = @('AnyDesk')
                        Changed = @()
                    }
                )
            }
            $flagged = Test-SccResurrection -Diff $diff
            $flagged.Count | Should -BeGreaterThan 0
        }

        It 'does not flag changed non-remote-access service' {
            $diff = [PSCustomObject]@{
                Sections = @(
                    [PSCustomObject]@{
                        Section = 'Services'
                        Removed = @()
                        StillPresent = @()
                        New = @()
                        Changed = @(
                            [PSCustomObject]@{ Key = 'BenignSvc'; Fields = @('State') }
                        )
                    }
                )
            }
            $flagged = Test-SccResurrection -Diff $diff
            $flagged.Count | Should -Be 0
        }
    }

    Context 'empty snapshots' {
        It 'diffs two empty snapshots without exceptions' {
            $empty1 = [PSCustomObject]@{
                SchemaVersion = 2
                Label = 'before'
                ComputerName = 'EMPTY'
                CollectedUtc = '2026-08-26 00:00:00'
                Sections = [ordered]@{}
            }
            $empty2 = [PSCustomObject]@{
                SchemaVersion = 2
                Label = 'after'
                ComputerName = 'EMPTY'
                CollectedUtc = '2026-08-26 00:00:00'
                Sections = [ordered]@{}
            }
            { Compare-SccSnapshots -Before $empty1 -After $empty2 } | Should -Not -Throw
        }
    }

    Context 'diff ordering noise' {
        It 'produces sorted output regardless of input order' {
            $beforeSnap = [PSCustomObject]@{
                SchemaVersion = 2
                Label = 'before'
                ComputerName = 'TEST'
                CollectedUtc = '2026-08-26 00:00:00'
                Sections = [ordered]@{
                    Services = @(
                        [PSCustomObject]@{ Key = 'ZebraSvc'; Name = 'ZebraSvc' }
                        [PSCustomObject]@{ Key = 'AlphaSvc'; Name = 'AlphaSvc' }
                        [PSCustomObject]@{ Key = 'MiddleSvc'; Name = 'MiddleSvc' }
                    )
                    ScheduledTasks = @()
                    RegistryAutoruns = @()
                    StartupFolders = @()
                    Processes = @()
                    Connections = @()
                    InstalledPrograms = @()
                    LocalAccounts = @()
                    FirewallRules = @()
                    WmiPersistence = @()
                    RecentFiles = @()
                    ScInstallations = @()
                    SystemSettings = [ordered]@{ RdpEnabled = $null; HostsFileLines = @() }
                }
            }
            $afterSnap = [PSCustomObject]@{
                SchemaVersion = 2
                Label = 'after'
                ComputerName = 'TEST'
                CollectedUtc = '2026-08-26 00:00:00'
                Sections = [ordered]@{
                    Services = @(
                        [PSCustomObject]@{ Key = 'MiddleSvc'; Name = 'MiddleSvc' }
                        [PSCustomObject]@{ Key = 'AlphaSvc'; Name = 'AlphaSvc' }
                        [PSCustomObject]@{ Key = 'ZebraSvc'; Name = 'ZebraSvc' }
                    )
                    ScheduledTasks = @()
                    RegistryAutoruns = @()
                    StartupFolders = @()
                    Processes = @()
                    Connections = @()
                    InstalledPrograms = @()
                    LocalAccounts = @()
                    FirewallRules = @()
                    WmiPersistence = @()
                    RecentFiles = @()
                    ScInstallations = @()
                    SystemSettings = [ordered]@{ RdpEnabled = $null; HostsFileLines = @() }
                }
            }
            $diff = Compare-SccSnapshots -Before $beforeSnap -After $afterSnap
            $svcDiff = $null
            foreach ($sd in $diff.Sections) {
                if ($sd.Section -eq 'Services') {
                    $svcDiff = $sd
                    break
                }
            }
            # StillPresent should be sorted
            @($svcDiff.StillPresent) | Should -Be @(Sort-Object @($svcDiff.StillPresent))
        }
    }

    Context 'JSON export of snapshots' {
        BeforeAll {
            $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "scc_snap_test_$(Get-Random)"
            $runDir = Join-Path $tempDir 'SC-20260826-TEST-660000'
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            $run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-660000' }
            New-SccSnapshot -Run $run -Label 'before' | Out-Null
            # Create a modified 'after' snapshot
            $afterDir = Join-Path $tempDir 'SC-20260826-TEST-660001'
            New-Item -ItemType Directory -Path $afterDir -Force | Out-Null
            $afterRun = [PSCustomObject]@{ RunDir = $afterDir; RunId = 'SC-20260826-TEST-660001' }
            New-SccSnapshot -Run $afterRun -Label 'after' | Out-Null
        }

        AfterAll {
            if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'compares snapshots from files' {
            $beforeFile = Join-Path $runDir 'snapshots' 'before.json'
            $afterFile = Join-Path $afterDir 'snapshots' 'after.json'
            { Compare-SccSnapshots -Before $beforeFile -After $afterFile } | Should -Not -Throw
        }

        It 'returns correct structure from file comparison' {
            $beforeFile = Join-Path $runDir 'snapshots' 'before.json'
            $afterFile = Join-Path $afterDir 'snapshots' 'after.json'
            $diff = Compare-SccSnapshots -Before $beforeFile -After $afterFile
            $diff.PSObject.Properties['SchemaVersion'] | Should -Not -BeNullOrEmpty
            $diff.PSObject.Properties['Summary'] | Should -Not -BeNullOrEmpty
            $diff.PSObject.Properties['Sections'] | Should -Not -BeNullOrEmpty
        }
    }
}
