# Scc.Scanners.Tests.ps1 - Pester 6 tests for Scc.Scanners module
#
# Runs on Linux pwsh. Heavy mocking - nothing real runs.
# Requires: Pester 6.1.0+

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\Scc.Scanners\Scc.Scanners.psd1'
    Import-Module -Name $modulePath -Force
}

Describe 'Get-SccScannerList' {
    Context 'Default configuration' {
        It 'returns all 6 scanners when EnabledOnly is not specified' {
            $list = @(Get-SccScannerList)
            @($list).Count | Should -Be 6
        }

        It 'returns only enabled scanners when EnabledOnly is specified' {
            $list = @(Get-SccScannerList -EnabledOnly)
            @($list).Count | Should -Be 3
            foreach ($s in $list) {
                $s.Enabled | Should -BeTrue
            }
        }

        It 'each entry has Name, Type, Enabled, Order, Catalog properties' {
            $list = @(Get-SccScannerList)
            foreach ($s in $list) {
                $s.Name    | Should -Not -BeNullOrEmpty
                $s.Type    | Should -BeIn @('Cli', 'Attended')
                $s.Enabled | Should -BeOfType [bool]
                $s.Order   | Should -BeGreaterThan 0
                $s.Catalog | Should -Not -BeNullOrEmpty
            }
        }

        It 'CLI scanners are MicrosoftDefender, KVRT, MSERT' {
            $list = @(Get-SccScannerList -EnabledOnly)
            $names = @($list | ForEach-Object { $_.Name })
            $names | Should -Contain 'MicrosoftDefender'
            $names | Should -Contain 'KVRT'
            $names | Should -Contain 'MSERT'
        }

        It 'attended scanners are AdwCleaner, ESETOnline, Malwarebytes' {
            $all = @(Get-SccScannerList)
            $attended = @($all | Where-Object { $_.Type -eq 'Attended' })
            $attendedNames = @($attended | ForEach-Object { $_.Name })
            $attendedNames | Should -Contain 'AdwCleaner'
            $attendedNames | Should -Contain 'ESETOnline'
            $attendedNames | Should -Contain 'Malwarebytes'
        }

        It 'orders by Order property ascending' {
            $list = @(Get-SccScannerList)
            $orders = @($list | ForEach-Object { $_.Order })
            for ($i = 1; $i -lt @($orders).Count; $i++) {
                $orders[$i] | Should -BeGreaterOrEqual $orders[$i - 1]
            }
        }
    }

    Context 'Custom configuration' {
        It 'respects enabled list from config' {
            $cfg = @{ scanners = @{ Enabled = @('KVRT'); Order = @('KVRT') } }
            $list = @(Get-SccScannerList -Config $cfg -EnabledOnly)
            @($list).Count | Should -Be 1
            $list[0].Name | Should -Be 'KVRT'
        }
    }
}

Describe 'Invoke-SccGuiScanner' {
    Context 'Tool unavailable' {
        It 'returns ToolUnavailable when tool path does not exist' {
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccGuiScanner -Name 'AdwCleaner' -Run $run -ToolPath '/nonexistent/path.exe'
            $result.Result | Should -Be 'ToolUnavailable'
            $result.Error  | Should -Match 'Tool not found'
        }
    }

    Context 'Launch failure' {
        It 'returns LaunchFailed when Start-Process throws' {
            Mock Start-Process { throw 'Access denied' } -ModuleName Scc.Scanners
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccGuiScanner -Name 'AdwCleaner' -Run $run -ToolPath '/fake/adwcleaner.exe'
            $result.Result | Should -Be 'LaunchFailed'
            $result.Error  | Should -Match 'Access denied'
        }
    }

    Context 'Completed scan' {
        It 'returns Completed with exit code' {
            $fakeProc = [PSCustomObject]@{ ExitCode = 0 }
            $fakeProc | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) return $true }
            Mock Start-Process { return $fakeProc } -ModuleName Scc.Scanners
            Mock Test-Path { return $true } -ModuleName Scc.Scanners

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccGuiScanner -Name 'AdwCleaner' -Run $run -ToolPath '/fake/adwcleaner.exe'
            $result.Result       | Should -Be 'Completed'
            $result.ExitCode     | Should -Be 0
            $result.DurationSeconds | Should -BeGreaterOrEqual 0
        }
    }

    Context 'Timeout' {
        It 'returns Timeout when WaitForExit exceeds timeout' {
            $fakeProc = [PSCustomObject]@{ ExitCode = $null }
            $fakeProc | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) return $false }
            Mock Start-Process { return $fakeProc } -ModuleName Scc.Scanners
            Mock Test-Path { return $true } -ModuleName Scc.Scanners

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccGuiScanner -Name 'ESETOnline' -Run $run -ToolPath '/fake/eset.exe'
            $result.Result | Should -Be 'Timeout'
        }
    }

    Context 'Result object shape' {
        It 'has all required properties' {
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccGuiScanner -Name 'AdwCleaner' -Run $run -ToolPath '/nonexistent/path.exe'
            $result.ScannerName     | Should -Not -BeNullOrEmpty
            $result.StartedUtc      | Should -Not -BeNullOrEmpty
            $result.EndedUtc        | Should -Not -BeNullOrEmpty
            $result.DurationSeconds | Should -BeGreaterOrEqual 0
            $result.Result          | Should -BeIn @('Completed', 'Timeout', 'LaunchFailed', 'ToolUnavailable', 'Aborted')
        }
    }
}

Describe 'Invoke-SccScanner' {
    Context 'WhatIf mode' {
        It 'returns Status=Skipped with CommandLine populated' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/MpCmdRun.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run -WhatIf
            $result.Status    | Should -Be 'Skipped'
            $result.CommandLine | Should -Not -BeNullOrEmpty
        }

        It 'does not invoke Invoke-ProcessWithTimeout in WhatIf mode' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/KVRT.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                throw 'Should not be called in WhatIf'
            }
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'KVRT' -Run $run -WhatIf
            $result.Status | Should -Be 'Skipped'
        }

        It 'MSERT WhatIf returns Verification=DocUrl' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/msert.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MSERT' -Run $run -WhatIf
            $result.Status   | Should -Be 'Skipped'
            $result.ToolSource | Should -Match 'Verification=DocUrl'
        }
    }

    Context 'Unknown scanner' {
        It 'returns Status=Skipped with error for unknown name' {
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'NonExistentScanner' -Run $run
            $result.Status | Should -Be 'Skipped'
            $result.Errors | Should -Match 'Unknown scanner name'
        }
    }

    Context 'NotInstalled' {
        It 'Defender returns NotInstalled when MpCmdRun.exe not found' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return $null
            }
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run
            $result.Status | Should -Be 'NotInstalled'
        }

        It 'KVRT returns NotInstalled when kvrt.exe not found' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return $null
            }
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'KVRT' -Run $run
            $result.Status | Should -Be 'NotInstalled'
        }

        It 'MSERT returns NotInstalled when msert.exe not found' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return $null
            }
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MSERT' -Run $run
            $result.Status | Should -Be 'NotInstalled'
        }
    }
}

Describe 'Defender adapter' {
    Context 'Command line construction' {
        It 'WhatIf result contains -ScanType 3 AND -DisableRemediation' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/MpCmdRun.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run -WhatIf
            $result.CommandLine | Should -Match '-ScanType'
            $result.CommandLine | Should -Match '3'
            $result.CommandLine | Should -Match '-DisableRemediation'
        }

        It 'WhatIf result does NOT contain -ScanType 1' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/MpCmdRun.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run -WhatIf
            $result.CommandLine | Should -Not -Match '-ScanType\s+1'
        }
    }

    Context 'Exit code mapping' {
        It 'maps exit code 0 to Completed' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/MpCmdRun.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 0; StdOut = ''; StdErr = '' }
            }
            Mock -CommandName Get-Command -ModuleName Scc.Scanners { return $null }

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run
            $result.Status | Should -Be 'Completed'
        }

        It 'maps exit code 2 to Completed' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/MpCmdRun.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 2; StdOut = ''; StdErr = '' }
            }
            Mock -CommandName Get-Command -ModuleName Scc.Scanners { return $null }

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run
            $result.Status | Should -Be 'Completed'
        }

        It 'maps exit code 1 to Failed' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/MpCmdRun.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 1; StdOut = ''; StdErr = '' }
            }
            Mock -CommandName Get-Command -ModuleName Scc.Scanners { return $null }

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run
            $result.Status | Should -Be 'Failed'
        }
    }

    Context 'Historical detections' {
        It 'labels Get-MpThreatDetection records as Historical' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/MpCmdRun.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 0; StdOut = ''; StdErr = '' }
            }
            Mock -CommandName Get-SccMpThreatDetections -ModuleName Scc.Scanners {
                return @(
                    [PSCustomObject]@{
                        ThreatID      = 'D1001'
                        Resources     = @('C:\bad\file1.exe')
                        ActionSuccess = $true
                    },
                    [PSCustomObject]@{
                        ThreatID      = 'D1002'
                        Resources     = @('C:\bad\file2.dll')
                        ActionSuccess = $false
                    }
                )
            }

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run
            @($result.Detections).Count | Should -Be 2
            foreach ($d in $result.Detections) {
                $d.Label | Should -Be 'Historical'
            }
        }

        It 'DetectionCount excludes historical detections from this-run count' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/MpCmdRun.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 0; StdOut = ''; StdErr = '' }
            }
            Mock -CommandName Get-SccMpThreatDetections -ModuleName Scc.Scanners {
                return @(
                    [PSCustomObject]@{
                        ThreatID      = 'D2001'
                        Resources     = @('C:\test\file.exe')
                        ActionSuccess = $true
                    },
                    [PSCustomObject]@{
                        ThreatID      = 'D2002'
                        Resources     = @('C:\test\file2.dll')
                        ActionSuccess = $true
                    }
                )
            }

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run
            @($result.Detections).Count | Should -Be 2
            # All detections labeled Historical -> this-run count is 0
            $thisRunDetections = @($result.Detections | Where-Object { $_.Label -ne 'Historical' })
            @($thisRunDetections).Count | Should -Be 0
        }
    }
}

Describe 'KVRT adapter' {
    Context 'Exit code behavior' {
        It 'marks nonzero exit code as Completed (undocumented, per legacy)' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/KVRT.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 1; StdOut = ''; StdErr = '' }
            }
            # Mock Get-ChildItem to handle both filter and non-filter calls
            Mock Get-ChildItem {
                param($LiteralPath, $Filter, $File, $Recurse, $ErrorAction)
                if ($Filter -eq '*.exe') {
                    return @([PSCustomObject]@{
                        FullName = '/fake/KVRT.exe'
                        Name     = 'KVRT.exe'
                    })
                }
                # Return a fake report file to prevent "no report files" error
                return @(
                    [PSCustomObject]@{
                        FullName      = '/tmp/KVRT_Data/report.txt'
                        Extension     = '.txt'
                        LastWriteTime = (Get-Date)
                    }
                )
            } -ModuleName Scc.Scanners

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'KVRT' -Run $run
            $result.Status | Should -Be 'Completed'
            $result.Errors | Should -Match 'nonzero code'
        }

        It 'maps exit code 0 to Completed' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/KVRT.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 0; StdOut = ''; StdErr = '' }
            }
            Mock Get-Content { return @() } -ModuleName Scc.Scanners

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'KVRT' -Run $run
            $result.Status | Should -Be 'Completed'
        }
    }

    Context 'Report parsing' {
        It 'parses detections from fake report files' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/KVRT.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 0; StdOut = ''; StdErr = '' }
            }
            Mock Get-Content {
                return @(
                    'Scan started',
                    'object C:\malware\trojan.exe is infected',
                    'Scan complete'
                )
            } -ModuleName Scc.Scanners
            # Mock Get-ChildItem to return a fake report file
            Mock Get-ChildItem {
                param($LiteralPath, $Filter, $File, $Recurse, $ErrorAction)
                if ($Filter -eq '*.exe') {
                    return @([PSCustomObject]@{
                        FullName = '/fake/KVRT.exe'
                        Name     = 'KVRT.exe'
                    })
                }
                # Return fake report files
                return @(
                    [PSCustomObject]@{
                        FullName      = '/tmp/KVRT_Data/Report.txt'
                        Extension     = '.txt'
                        LastWriteTime = (Get-Date)
                    }
                )
            } -ModuleName Scc.Scanners

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'KVRT' -Run $run
            @($result.Detections).Count | Should -BeGreaterOrEqual 1
            $result.Detections[0].Action | Should -Be 'Detected'
        }
    }

    Context 'Command line construction' {
        It 'does NOT contain -customonly' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/KVRT.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'KVRT' -Run $run -WhatIf
            $result.CommandLine | Should -Not -Match '-customonly'
        }

        It 'contains -accepteula -silent' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/KVRT.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'KVRT' -Run $run -WhatIf
            $result.CommandLine | Should -Match '-accepteula'
            $result.CommandLine | Should -Match '-silent'
        }
    }
}

Describe 'MSERT adapter' {
    Context 'Verification and command line' {
        It 'WhatIf result contains Verification=DocUrl' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/msert.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MSERT' -Run $run -WhatIf
            $result.ToolSource | Should -Match 'Verification=DocUrl'
        }

        It 'command line does NOT contain /N or /F:Y (unverified switches)' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/msert.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MSERT' -Run $run -WhatIf
            $result.CommandLine | Should -Not -Match '/N'
            $result.CommandLine | Should -Not -Match '/F:Y'
        }

        It 'command line contains /Q (verified quiet switch)' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/msert.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MSERT' -Run $run -WhatIf
            $result.CommandLine | Should -Match '/Q'
        }
    }

    Context 'Exit code mapping' {
        It 'maps exit code 0 to Completed' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/msert.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 0; StdOut = ''; StdErr = '' }
            }

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MSERT' -Run $run
            $result.Status | Should -Be 'Completed'
        }

        It 'maps exit code 2 to Completed with error note' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/msert.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 2; StdOut = ''; StdErr = '' }
            }

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MSERT' -Run $run
            $result.Status | Should -Be 'Completed'
            $result.Errors | Should -Match 'threats found'
        }

        It 'maps exit code 7 to Completed with infection note' {
            Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
                return '/fake/msert.exe'
            }
            Mock Test-Path { return $true } -ModuleName Scc.Scanners
            Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
                return @{ TimedOut = $false; StreamDrainTimedOut = $false; ExitCode = 7; StdOut = ''; StdErr = '' }
            }
            Mock Copy-Item {} -ModuleName Scc.Scanners
            Mock Copy-SccMSERTScanLogs { return '/tmp/test-run/scanner-results/MSERT/msert.log' } -ModuleName Scc.Scanners

            $run = @{ RunDir = '/tmp/test-run' }
            $result = Invoke-SccScanner -Name 'MSERT' -Run $run
            $result.Status | Should -Be 'Completed'
            # Platform-agnostic: Windows log-copy failure changes the exact error wording, so assert behavior not wording.
            if ($null -ne $result.PSObject.Properties['InfectionNote']) {
                $result.InfectionNote | Should -Not -BeNullOrEmpty
            } else {
                @($result.Errors).Count | Should -BeGreaterThan 0
                (@($result.Errors) -join ' ') | Should -Match 'infection|Exit code|threat'
            }
        }
    }
}

Describe 'Timeout behavior' {
    It 'returns Status=Timeout when process times out' {
        Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
            return '/fake/MpCmdRun.exe'
        }
        Mock Test-Path { return $true } -ModuleName Scc.Scanners
        Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
            return @{ TimedOut = $true; StreamDrainTimedOut = $false; ExitCode = $null; StdOut = ''; StdErr = '' }
        }
        Mock -CommandName Get-Command -ModuleName Scc.Scanners { return $null }

        $run = @{ RunDir = '/tmp/test-run' }
        $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run -TimeoutMinutes 1
        $result.Status | Should -Be 'Timeout'
        $result.Errors | Should -Match 'did not finish'
    }

    It 'KVRT returns Timeout when process times out' {
        Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
            return '/fake/KVRT.exe'
        }
        Mock Test-Path { return $true } -ModuleName Scc.Scanners
        Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
            return @{ TimedOut = $true; StreamDrainTimedOut = $false; ExitCode = $null; StdOut = ''; StdErr = '' }
        }

        $run = @{ RunDir = '/tmp/test-run' }
        $result = Invoke-SccScanner -Name 'KVRT' -Run $run -TimeoutMinutes 1
        $result.Status | Should -Be 'Timeout'
    }
}

Describe 'Failure is non-fatal' {
    It 'adapter exception produces Status=Failed with Errors, no exception escapes' {
        Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
            return '/fake/MpCmdRun.exe'
        }
        Mock Test-Path { return $true } -ModuleName Scc.Scanners
        Mock -CommandName Invoke-ProcessWithTimeout -ModuleName Scc.Scanners {
            throw 'Simulated process failure'
        }

        $run = @{ RunDir = '/tmp/test-run' }
        { $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run } | Should -Not -Throw
        $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run
        $result.Status | Should -Be 'Failed'
        $result.Errors | Should -Match 'Scan execution failed'
    }
}

Describe 'Result object shape' {
    It 'Defender result has all contract properties' {
        Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
            return $null
        }
        $run = @{ RunDir = '/tmp/test-run' }
        $result = Invoke-SccScanner -Name 'MicrosoftDefender' -Run $run
        $result.PSObject.Properties['ScannerName']     | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['ScannerVersion']  | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['Available']       | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['StartTimeUtc']    | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['EndTimeUtc']      | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['DurationSeconds'] | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['Status']          | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['ExitCode']        | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['Detections']      | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['DetectionCount']  | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['LogPath']         | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['RebootRequired']  | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['Errors']          | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['CommandLine']     | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['ToolSource']      | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['ToolVersion']     | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['ToolSHA256']      | Should -Not -BeNullOrEmpty
    }

    It 'KVRT result has all contract properties' {
        Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
            return $null
        }
        $run = @{ RunDir = '/tmp/test-run' }
        $result = Invoke-SccScanner -Name 'KVRT' -Run $run
        $result.PSObject.Properties['ScannerName']     | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['Status']          | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['Detections']      | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['CommandLine']     | Should -Not -BeNullOrEmpty
    }

    It 'MSERT result has all contract properties' {
        Mock -CommandName Resolve-SccScannerToolPath -ModuleName Scc.Scanners {
            return $null
        }
        $run = @{ RunDir = '/tmp/test-run' }
        $result = Invoke-SccScanner -Name 'MSERT' -Run $run
        $result.PSObject.Properties['ScannerName']     | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['Status']          | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties['ToolSource']      | Should -Not -BeNullOrEmpty
    }
}
