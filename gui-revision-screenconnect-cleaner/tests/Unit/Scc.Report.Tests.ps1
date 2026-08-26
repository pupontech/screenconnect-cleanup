Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:modulePath = Join-Path $PSScriptRoot '../../src/Scc.Report/Scc.Report.psd1'
Import-Module $script:modulePath -Force

Describe 'Scc.Report module' {

    BeforeAll {
        $script:TempRoots = New-Object System.Collections.ArrayList
        function New-TempRunDir {
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ('SccReportTest_' + [Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $root -Force | Out-Null
            [void]$script:TempRoots.Add($root)
            return $root
        }
        function Write-JsonFile {
            param([string]$Path, $Object)
            $dir = Split-Path -Parent $Path
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $json = $Object | ConvertTo-Json -Depth 12
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($Path, $json, $utf8)
        }
    }

    AfterAll {
        foreach ($r in $script:TempRoots) {
            try { Remove-Item -LiteralPath $r -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        }
    }

    Context 'Module exports' {
        It 'exports exactly two functions' {
            $cmds = @(Get-Command -Module Scc.Report | Select-Object -ExpandProperty Name | Sort-Object)
            $cmds.Count | Should -Be 2
            $cmds -contains 'New-SccReport' | Should -Be $true
            $cmds -contains 'ConvertTo-SccHtml' | Should -Be $true
        }

        It 'imports cleanly' {
            { Import-Module $modulePath -Force } | Should -Not -Throw
        }
    }

    Context 'ConvertTo-SccHtml escapes' {
        It 'escapes ampersand, angle brackets, and quotes' {
            $r1 = ConvertTo-SccHtml -Text '&'
            $r2 = ConvertTo-SccHtml -Text '<'
            $r3 = ConvertTo-SccHtml -Text '>'
            $r4 = ConvertTo-SccHtml -Text '"'
            $r5 = ConvertTo-SccHtml -Text ([char]39)
            $r1 | Should -Be '&amp;'
            $r2 | Should -Be '&lt;'
            $r3 | Should -Be '&gt;'
            $r4 | Should -Be '&quot;'
            $r5 | Should -Be '&#39;'
        }

        It 'escapes combined string' {
            $in = '<script>alert("x&y")</script>'
            $out = ConvertTo-SccHtml -Text $in
            $out | Should -Be '&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;'
        }

        It 'returns empty for null' {
            ConvertTo-SccHtml -Text $null | Should -Be ''
        }
    }

    Context 'Empty run dir (only runstate)' {
        It 'generates all three outputs with Not collected markers and no exception' {
            $runDir = New-TempRunDir
            $runState = [ordered]@{
                RunId = 'SC-20260826-HOST-120000'
                ComputerName = 'HOST'
                Stages = [ordered]@{ Preflight = 'Completed' }
            }
            Write-JsonFile (Join-Path $runDir 'runstate.json') $runState

            { New-SccReport -Run $runDir } | Should -Not -Throw

            (Test-Path (Join-Path $runDir 'report.html')) | Should -Be $true
            (Test-Path (Join-Path $runDir 'report.json')) | Should -Be $true
            (Test-Path (Join-Path $runDir 'technician-summary.txt')) | Should -Be $true

            $html = Get-Content -LiteralPath (Join-Path $runDir 'report.html') -Raw
            $html | Should -Match 'Not collected'
            $html | Should -Match 'Executive Summary'
            $html | Should -Match 'System Information'
            $html | Should -Match 'Incident Timeline'
            $html | Should -Match 'ScreenConnect Findings'
            $html | Should -Match 'Credential / Incident Follow-up Checklist'
        }
    }

    Context 'XSS protection' {
        It 'escapes RelayHost containing script tag and quotes' {
            $runDir = New-TempRunDir
            $findings = [ordered]@{
                ComputerName = 'HOST'
                GeneratedUtc = '2026-08-26 12:00:00'
                ScreenConnect = [ordered]@{
                    Instances = @(
                        [ordered]@{
                            RelayHost = '<script>alert(1)</script>'
                            InstanceId = 'bad''"&test'
                            ServerKeyFingerprint = 'abc123'
                            SessionType = 'Access'
                            InstallPath = 'C:\Program Files (x86)\ScreenConnect Client (abc)'
                            Service = 'ScreenConnect Client (abc)'
                            InstallTimestampUtc = '2026-08-25 10:00:00'
                            Publisher = 'TestPublisher'
                            Signature = 'Valid'
                            Version = '1.0'
                            Confidence = 'High'
                            TrustMatch = 'Unknown'
                            Persistence = @()
                            Processes = @()
                            Connections = @()
                            RawLaunchParameters = '?h=<script>&e=Access'
                            ParserWarnings = @()
                            UnknownParameters = @()
                        }
                    )
                }
                OtherTargets = @()
            }
            Write-JsonFile (Join-Path $runDir 'findings.json') $findings
            $rs = [ordered]@{ RunId = 'SC-20260826-HOST-120000' }
            Write-JsonFile (Join-Path $runDir 'runstate.json') $rs

            { New-SccReport -Run $runDir } | Should -Not -Throw

            $html = Get-Content -LiteralPath (Join-Path $runDir 'report.html') -Raw
            $html | Should -Not -Match '<script>alert\(1\)</script>'
            $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
            # raw on* attribute should not appear unescaped as executable
            $html | Should -Not -Match 'javascript:'
            $txt = Get-Content -LiteralPath (Join-Path $runDir 'technician-summary.txt') -Raw
            $txt.Length | Should -BeGreaterThan 0
        }
    }

    Context 'Missing inputs handling' {
        It 'reports ScreenConnect not collected when findings.json missing' {
            $runDir = New-TempRunDir
            $rs = [ordered]@{ RunId = 'SC-20260826-HOST-120000' }
            Write-JsonFile (Join-Path $runDir 'runstate.json') $rs

            { New-SccReport -Run $runDir } | Should -Not -Throw

            $html = Get-Content -LiteralPath (Join-Path $runDir 'report.html') -Raw
            $html | Should -Match 'ScreenConnect Findings'
            $html | Should -Match 'Not collected'
            $html | Should -Match '<html'
        }
    }

    Context 'Follow-up checklist always present' {
        It 'contains credential checklist section' {
            $runDir = New-TempRunDir
            $rs = [ordered]@{ RunId = 'SC-20260826-HOST-120000' }
            Write-JsonFile (Join-Path $runDir 'runstate.json') $rs
            { New-SccReport -Run $runDir } | Should -Not -Throw
            $html = Get-Content -LiteralPath (Join-Path $runDir 'report.html') -Raw
            $html | Should -Match 'Credential / Incident Follow-up Checklist'
            $html | Should -Match 'Reset ScreenConnect'
        }
    }

    Context 'Full synthetic run' {
        It 'renders all sections, correct executive summary counts, valid json, summary <=60 lines' {
            $runDir = New-TempRunDir

            $findings = [ordered]@{
                ComputerName = 'WORKSTATION1'
                GeneratedUtc = '2026-08-26 12:00:00'
                DetectedUtc = '2026-08-26 12:00:00'
                ScreenConnect = @(
                    [ordered]@{
                        RelayHost = 'good.example.com'
                        InstanceId = 'aaaa1111'
                        ServerKeyFingerprint = 'fingerprint-good'
                        SessionType = 'Access'
                        InstallPath = 'C:\Program Files (x86)\ScreenConnect Client (aaaa1111)\ScreenConnect.ClientService.exe'
                        Service = 'ScreenConnect Client (aaaa1111)'
                        InstallTimestampUtc = '2026-08-25 09:00:00'
                        Publisher = 'ConnectWise'
                        Signature = 'Valid'
                        Version = '24.1'
                        Confidence = 'High'
                        TrustMatch = 'Known'
                        Persistence = @([ordered]@{ Type = 'Service'; Location = 'ScreenConnect Client (aaaa1111)'; Details = 'Auto' })
                        Processes = @([ordered]@{ ProcessId = 1234; Name = 'ScreenConnect.ClientService.exe'; ExecutablePath = 'C:\Program Files (x86)\ScreenConnect Client (aaaa1111)\ScreenConnect.ClientService.exe' })
                        Connections = @([ordered]@{ LocalAddress = '192.168.1.10'; LocalPort = 50000; RemoteAddress = '10.0.0.1'; RemotePort = 8041; State = 'Established' })
                        RawLaunchParameters = '?h=good.example.com&e=Access&s=aaaa1111'
                        ParserWarnings = @()
                        UnknownParameters = @()
                    },
                    [ordered]@{
                        RelayHost = 'evil.badguy.example'
                        InstanceId = 'bbbb2222'
                        ServerKeyFingerprint = 'fingerprint-evil'
                        SessionType = 'Support'
                        InstallPath = 'C:\Program Files (x86)\ScreenConnect Client (bbbb2222)\ScreenConnect.ClientService.exe'
                        Service = 'ScreenConnect Client (bbbb2222)'
                        InstallTimestampUtc = '2026-08-25 11:00:00'
                        Publisher = 'ConnectWise'
                        Signature = 'Valid'
                        Version = '24.1'
                        Confidence = 'High'
                        TrustMatch = 'Unknown'
                        Persistence = @()
                        Processes = @()
                        Connections = @()
                        RawLaunchParameters = '?h=evil.badguy.example&e=Support'
                        ParserWarnings = @('missing params')
                        UnknownParameters = @([ordered]@{ Name = 'zz'; Value = '1' })
                    }
                )
                RemoteAccess = @(
                    [ordered]@{
                        Product = 'AnyDesk'
                        DisplayName = 'AnyDesk'
                        DetectionType = 'service'
                        Evidence = 'AnyDesk service found'
                        Version = '8.0'
                        Publisher = 'AnyDesk Software'
                        Confidence = 'High'
                    }
                )
            }
            Write-JsonFile (Join-Path $runDir 'findings.json') $findings

            $plan = [ordered]@{
                PlanVersion = 1
                CreatedUtc = '2026-08-26 12:05:00'
                CreatedBy = 'tech'
                Items = @(
                    [ordered]@{ FindingId = 'bbbb2222'; Product = 'ScreenConnect'; TargetType = 'Service'; Action = 'REMOVE'; Detail = 'evil instance'; DisplayText = 'Remove evil' }
                )
            }
            Write-JsonFile (Join-Path $runDir 'plan.json') $plan

            $remed = [ordered]@{
                Actions = @(
                    [ordered]@{ FindingId = 'bbbb2222'; Action = 'StopService'; Target = 'ScreenConnect Client (bbbb2222)'; Result = 'Success'; TimestampUtc = '2026-08-26 12:10:00' },
                    [ordered]@{ FindingId = 'bbbb2222'; Action = 'Quarantine'; Target = 'C:\Program Files (x86)\ScreenConnect Client (bbbb2222)'; Result = 'Success'; TimestampUtc = '2026-08-26 12:11:00' }
                )
            }
            Write-JsonFile (Join-Path $runDir 'remediation.json') $remed

            # scanner results
            New-Item -ItemType Directory -Path (Join-Path $runDir 'scanner-results') -Force | Out-Null
            $scan1 = [ordered]@{ ScannerName = 'Defender'; Status = 'Completed'; ExitCode = 0; DetectionCount = 0; StartTimeUtc = '2026-08-26 12:15:00'; EndTimeUtc = '2026-08-26 12:20:00' }
            $scan2 = [ordered]@{ ScannerName = 'KVRT'; Status = 'Failed'; ExitCode = 1; DetectionCount = 0; StartTimeUtc = '2026-08-26 12:20:00'; EndTimeUtc = '2026-08-26 12:25:00' }
            Write-JsonFile (Join-Path $runDir 'scanner-results/defender.json') $scan1
            Write-JsonFile (Join-Path $runDir 'scanner-results/kvrt.json') $scan2

            # snapshots
            $before = [ordered]@{
                Label = 'before'
                ComputerName = 'WORKSTATION1'
                CollectedUtc = '2026-08-26 11:00:00'
                SchemaVersion = 2
                Sections = [ordered]@{
                    Services = @([ordered]@{ Key = 'SvcA'; Name = 'SvcA' }, [ordered]@{ Key = 'SvcToRemove'; Name = 'SvcToRemove' })
                    Connections = @()
                }
                CollectionErrors = @()
            }
            $after = [ordered]@{
                Label = 'after'
                ComputerName = 'WORKSTATION1'
                CollectedUtc = '2026-08-26 12:30:00'
                SchemaVersion = 2
                Sections = [ordered]@{
                    Services = @([ordered]@{ Key = 'SvcA'; Name = 'SvcA'; State = 'ChangedState' }, [ordered]@{ Key = 'SvcNew'; Name = 'SvcNew' })
                    Connections = @()
                }
                CollectionErrors = @()
            }
            Write-JsonFile (Join-Path $runDir 'snapshots/before.json') $before
            Write-JsonFile (Join-Path $runDir 'snapshots/after.json') $after

            $diff = [ordered]@{
                SchemaVersion = 1
                DiffUtc = '2026-08-26 12:31:00'
                BeforeFile = 'before.json'
                AfterFile = 'after.json'
                SameComputerName = $true
                ResurrectionsAdded = 1
                Verdict = 'RESURRECTION'
                Summary = [ordered]@{ RemovedCount = 1; NewCount = 1; ChangedCount = 1; StillPresentCount = 1 }
                Sections = @(
                    [ordered]@{ Section = 'Services'; Kind = 'stable'; BeforeCount = 2; AfterCount = 2; Removed = @('SvcToRemove'); Added = @('SvcNew'); Changed = @([ordered]@{ Key = 'SvcA'; Fields = @('State') }) },
                    [ordered]@{ Section = 'Processes'; Kind = 'volatile'; BeforeCount = 0; AfterCount = 0; Removed = @(); Added = @(); Changed = @() }
                )
            }
            Write-JsonFile (Join-Path $runDir 'snapshots/diff.json') $diff

            $prov = @(
                [ordered]@{ Name = 'KVRT'; Version = '20.0.14.0'; SHA256 = 'ABC123'; Source = 'Official' }
            )
            Write-JsonFile (Join-Path $runDir 'tool-provenance.json') $prov

            # master.log
            New-Item -ItemType Directory -Path (Join-Path $runDir 'logs') -Force | Out-Null
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText((Join-Path $runDir 'logs/master.log'), "2026-08-26 INFO Test log`n", $utf8)

            $runState = [ordered]@{ RunId = 'SC-20260826-WORKSTATION1-120000'; ComputerName = 'WORKSTATION1' }
            Write-JsonFile (Join-Path $runDir 'runstate.json') $runState

            { New-SccReport -Run $runDir } | Should -Not -Throw

            $html = Get-Content -LiteralPath (Join-Path $runDir 'report.html') -Raw
            $html | Should -Match 'Executive Summary'
            $html | Should -Match 'System Information'
            $html | Should -Match 'Incident Timeline'
            $html | Should -Match 'ScreenConnect Findings'
            $html | Should -Match 'Other Remote Access Findings'
            $html | Should -Match 'Persistence'
            $html | Should -Match 'Network Findings'
            $html | Should -Match 'Scanner Results'
            $html | Should -Match 'Remediation Actions'
            $html | Should -Match 'Quarantine'
            $html | Should -Match 'Before/After Comparison'
            $html | Should -Match 'Outstanding Concerns'
            $html | Should -Match 'Errors / Warnings'
            $html | Should -Match 'Tool Provenance'
            $html | Should -Match 'Credential / Incident Follow-up Checklist'
            $html | Should -Match 'Raw Evidence Index'

            # Executive summary counts
            $html | Should -Match 'ScreenConnect'
            # Check trust badge
            $html | Should -Match 'Known'
            $html | Should -Match 'Unknown'

            $jsonRaw = Get-Content -LiteralPath (Join-Path $runDir 'report.json') -Raw
            { $jsonRaw | ConvertFrom-Json } | Should -Not -Throw
            $j = $jsonRaw | ConvertFrom-Json
            $j.Summary.Counts.ScreenConnectInstances | Should -Be 2
            $j.Summary.Counts.OtherRemoteAccessFindings | Should -Be 1

            $txt = Get-Content -LiteralPath (Join-Path $runDir 'technician-summary.txt')
            $txt.Count | Should -BeLessOrEqual 60
            ($txt -join "`n") | Should -Match 'Credential'
        }
    }

    Context 'Determinism' {
        It 'generates byte-identical outputs when run twice' {
            $runDir = New-TempRunDir
            $findings = [ordered]@{
                ComputerName = 'HOST'
                GeneratedUtc = '2026-08-26 12:00:00'
                ScreenConnect = @(
                    [ordered]@{ RelayHost = 'host.example.com'; InstanceId = 'id1'; TrustMatch = 'Known'; InstallPath = 'C:\path'; Service = 'svc'; Signature = 'Valid'; Version = '1.0'; Confidence = 'High' }
                )
            }
            Write-JsonFile (Join-Path $runDir 'findings.json') $findings
            $rs = [ordered]@{ RunId = 'SC-20260826-HOST-120000' }
            Write-JsonFile (Join-Path $runDir 'runstate.json') $rs

            New-SccReport -Run $runDir | Out-Null
            $html1 = [System.IO.File]::ReadAllBytes((Join-Path $runDir 'report.html'))
            $json1 = [System.IO.File]::ReadAllBytes((Join-Path $runDir 'report.json'))
            $txt1  = [System.IO.File]::ReadAllBytes((Join-Path $runDir 'technician-summary.txt'))

            Start-Sleep -Milliseconds 200
            New-SccReport -Run $runDir | Out-Null
            $html2 = [System.IO.File]::ReadAllBytes((Join-Path $runDir 'report.html'))
            $json2 = [System.IO.File]::ReadAllBytes((Join-Path $runDir 'report.json'))
            $txt2  = [System.IO.File]::ReadAllBytes((Join-Path $runDir 'technician-summary.txt'))

            (Compare-Object $html1 $html2).Count | Should -Be 0
            (Compare-Object $json1 $json2).Count | Should -Be 0
            (Compare-Object $txt1 $txt2).Count | Should -Be 0
        }
    }

}
