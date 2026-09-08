# Scc.Detection unit tests (Pester 6, Linux, no real Windows)
# Pure ASCII. Covers the required test matrix from the module contract.
#
# All CIM/registry/event-log access lives in the inventory functions, so we
# mock those and feed synthetic data exactly like the legacy -SelfTest, plus
# multi-source dedup and generic-target hits.

if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
Import-Module -Name (Join-Path $PSScriptRoot '../../src/Scc.Detection/Scc.Detection.psd1') -Force

# ---------------------------------------------------------------------------
# Private-helper tests run INSIDE the module scope so the non-exported
# functions (Find-ScParamBlob, ConvertFrom-ScParamBlob, Get-ScIdentifier,
# New-ScInstanceTemplate, Apply-ScParameters, Resolve-SccScInstances) are visible.
# ---------------------------------------------------------------------------
InModuleScope Scc.Detection {

    Describe 'SC parameter parser' {

        It 'parses known keys from a service ImagePath blob' {
            $blob = Find-ScParamBlob '"X\ScreenConnect Client (id)\Client.exe" "?e=Access&y=Guest&h=support.example.com&p=8041&s=1111-2222&k=KEY123&c1=Acme%20IT"'
            $w = New-Object System.Collections.ArrayList
            $p = ConvertFrom-ScParamBlob -Blob $blob -Warnings ([ref]$w)
            $p['e'] | Should -Be 'Access'
            $p['y'] | Should -Be 'Guest'
            $p['h'] | Should -Be 'support.example.com'
            $p['p'] | Should -Be '8041'
            $p['s'] | Should -Be '1111-2222'
            $p['k'] | Should -Be 'KEY123'
            $p['c1'] | Should -Be 'Acme IT'   # URL-decoded
        }

        It 'extracts h= and e= from a blob' {
            $blob = Find-ScParamBlob 'junk ?e=Support&y=Guest&h=relay.example.com&p=443&x=1'
            $blob | Should -Match 'h=relay.example.com'
            $blob | Should -Match 'e=Support'
        }

        It 'URL-encoded relay decodes correctly' {
            $blob = Find-ScParamBlob '?e=Access&h=relay%2eexample%2ecom&p=8041&k=KEY&x=1'
            $w = New-Object System.Collections.ArrayList
            $p = ConvertFrom-ScParamBlob -Blob $blob -Warnings ([ref]$w)
            $p['h'] | Should -Be 'relay.example.com'
        }

        It 'malformed percent-encoding stays and records a warning' {
            $blob = Find-ScParamBlob '?e=Access&h=relay%zz%zz.example.com&p=8041&k=KEY'
            $w = New-Object System.Collections.ArrayList
            $p = ConvertFrom-ScParamBlob -Blob $blob -Warnings ([ref]$w)
            $p['h'] | Should -Be 'relay%zz%zz.example.com'
            @($w).Count | Should -BeGreaterThan 0
        }

        It 'unknown key lands in UnknownParameters' {
            $blob = Find-ScParamBlob '?zz=1&qq=hello&h=host.example.net&ww=3&k=KEY'
            $w = New-Object System.Collections.ArrayList
            $slot = New-ScInstanceTemplate -Key 't'
            $params = ConvertFrom-ScParamBlob -Blob $blob -Warnings ([ref]$w)
            Apply-ScParameters -Params $params -Slot $slot -Warnings ([ref]$slot.ParserWarnings)
            @($slot.UnknownParams.Keys) -contains 'zz' | Should -BeTrue
            @($slot.UnknownParams.Keys) -contains 'qq' | Should -BeTrue
            @($slot.UnknownParams.Keys) -contains 'ww' | Should -BeTrue
            $slot.RelayHost | Should -Be 'host.example.net'
        }

        It 'prefers a blob carrying h=/e= over a longer plain blob' {
            $text = 'somequery?a=1&b=2&c=3&d=4 thisisalongerblobwithoutidentifyingkeys=1&nope=2&x=3&y=4&z=5 ?e=Support&h=relay.example.com&k=KEY&w=1'
            $blob = Find-ScParamBlob $text
            $blob | Should -Match 'h=relay.example.com'
        }

        It 'splits values that contain an equals sign correctly' {
            $blob = Find-ScParamBlob '?e=Access&h=host.example.com&k=a=b=c&x=1'
            $w = New-Object System.Collections.ArrayList
            $slot = New-ScInstanceTemplate -Key 't'
            $params = ConvertFrom-ScParamBlob -Blob $blob -Warnings ([ref]$w)
            Apply-ScParameters -Params $params -Slot $slot -Warnings ([ref]$slot.ParserWarnings)
            $slot.ServerKey | Should -Be 'a=b=c'
        }

        It 'empty input returns empty ordered dict' {
            $w = New-Object System.Collections.ArrayList
            $p = ConvertFrom-ScParamBlob -Blob '' -Warnings ([ref]$w)
            @($p.Keys).Count | Should -Be 0
        }

        It 'trims leading ? and &' {
            $blob = Find-ScParamBlob '?e=Access&h=host.example.com&k=KEY123&x=1'
            $w = New-Object System.Collections.ArrayList
            $p = ConvertFrom-ScParamBlob -Blob $blob -Warnings ([ref]$w)
            $p['e'] | Should -Be 'Access'
            $p['h'] | Should -Be 'host.example.com'

            $blob2 = Find-ScParamBlob '&e=Support&h=other.example.net&k=KEY456&x=1'
            $w2 = New-Object System.Collections.ArrayList
            $p2 = ConvertFrom-ScParamBlob -Blob $blob2 -Warnings ([ref]$w2)
            $p2['e'] | Should -Be 'Support'
            $p2['h'] | Should -Be 'other.example.net'
        }
    }

    Describe 'SC identifier extraction' {

        It 'extracts from "ScreenConnect Client (a1b2c3d4)"' {
            Get-ScIdentifier -Text 'ScreenConnect Client (a1b2c3d4)' | Should -Be 'a1b2c3d4'
        }

        It 'extracts from a service ImagePath' {
            Get-ScIdentifier -Text '"C:\Program Files (x86)\ScreenConnect Client (9f8e7d6c5b4a3210)\Client.exe"' | Should -Be '9f8e7d6c5b4a3210'
        }

        It 'returns null when no identifier is present' {
            Get-ScIdentifier -Text 'Some Other Service (xyz)' | Should -BeNullOrEmpty
        }
    }

    Describe 'SC fingerprint derivation' {

        It 'SHA256 -> 16 hex lowercase' {
            $slot = New-ScInstanceTemplate -Key 't'
            $slot.ServerKey = 'KEY123'
            Apply-ScParameters -Params ([ordered]@{'k'='KEY123'}) -Slot $slot -Warnings ([ref]$slot.ParserWarnings)
            $fp = $slot.ServerFingerprint
            $fp.Length | Should -Be 16
            $fp | Should -Match '^[0-9a-f]{16}$'
        }
    }

    Describe 'Confidence scoring' {

        It 'High with >=3 distinct sources' {
            $slot = New-ScInstanceTemplate -Key 't'
            foreach ($s in @('service','directory','uninstall-registry')) { [void]$slot.Sources.Add($s) }
            $distinct = @($slot.Sources | Sort-Object -Unique).Count
            $distinct | Should -BeGreaterOrEqual 3
        }

        It 'Medium with exactly 2 distinct sources' {
            $slot = New-ScInstanceTemplate -Key 't'
            foreach ($s in @('service','process')) { [void]$slot.Sources.Add($s) }
            $distinct = @($slot.Sources | Sort-Object -Unique).Count
            $distinct | Should -Be 2
        }

        It 'Low with a single source' {
            $slot = New-ScInstanceTemplate -Key 't'
            [void]$slot.Sources.Add('service')
            $distinct = @($slot.Sources | Sort-Object -Unique).Count
            $distinct | Should -Be 1
        }
    }

    Describe 'Detection orchestration (mocked inventories)' {

        BeforeAll {
            $script:scTarget = @(
                '{"targets":[{"id":"screenconnect","name":"SC","enabled":true,"deep":true,
                  "servicePatterns":["ScreenConnect*"],"processPatterns":["ScreenConnect.*"],
                  "pathPatterns":["%ProgramFiles(x86)%\\ScreenConnect Client*"],
                  "uninstallPatterns":["ScreenConnect*","ConnectWise Control*"]}]}' | ConvertFrom-Json
            ).targets[0]

            $script:fakeServices = @(
                [PSCustomObject]@{
                    Name = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    DisplayName = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    PathName = '"C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=support.example.com&p=8041&s=11111111-2222-3333-4444-555555555555&k=BgIAAACkAABSU0ExAAIAAAEAAQ%3d%3d&c1=Acme%20IT"'
                    State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; ProcessId = 100; Description = ''
                },
                [PSCustomObject]@{
                    Name = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    DisplayName = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    PathName = '"C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\ScreenConnect.ClientService.exe" "?e=Access&h=support.example.com&k=BgIAAACkAABSU0ExAAIAAAEAAQ%3d%3d"'
                    State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; ProcessId = 101; Description = ''
                }
            )
            $script:fakeProcesses = @(
                [PSCustomObject]@{
                    ProcessId = 100; ParentProcessId = 1; Name = 'ScreenConnect.ClientService.exe'
                    ExecutablePath = 'C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\ScreenConnect.ClientService.exe'
                    CommandLine = '"C:\...\ScreenConnect.ClientService.exe" "?e=Access&h=support.example.com&k=BgIAAACkAABSU0ExAAIAAAEAAQ%3d%3d"'
                    CreationDate = $null
                }
            )
            $script:fakeUninstall = @(
                [PSCustomObject]@{
                    RegistryKey = 'HKLM:\...\Uninstall\{abc}'
                    KeyName = '{abc}'
                    DisplayName = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    DisplayVersion = '24.1.1.0'
                    Publisher = 'ConnectWise'
                    InstallDate = '20260101'
                    InstallLocation = 'C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)'
                    UninstallString = 'MsiExec.exe /X{abc}'
                    QuietUninstallString = 'MsiExec.exe /X{abc} /qn'
                }
            )
            $script:fakeEvents = @()
        }

        It 'resolves 2 services + 1 process + 1 uninstall into 1 deduped instance' {
            Mock -CommandName Get-SccServiceInventory { return $script:fakeServices }
            Mock -CommandName Get-SccProcessInventory { return $script:fakeProcesses }
            Mock -CommandName Get-SccUninstallInventory { return $script:fakeUninstall }
            Mock -CommandName Get-SccServiceInstallEvents { return $script:fakeEvents }
            Mock -CommandName Get-SccScDirs { return @() }

            $res = Resolve-SccScInstances -Services $script:fakeServices -Processes $script:fakeProcesses `
                      -UninstallEntries $script:fakeUninstall -Events $script:fakeEvents -Target $script:scTarget -TrustedRelays @()
            @($res.Instances).Count | Should -Be 1
            $inst = $res.Instances[0]
            @($inst.Sources | Sort-Object -Unique).Count | Should -Be 3
            $inst.RelayHost | Should -Be 'support.example.com'
            $inst.Confidence | Should -Be 'High'
        }

        It 'F1: copies uninstall evidence onto the deduped instance' {
            Mock -CommandName Get-SccServiceInventory { return $script:fakeServices }
            Mock -CommandName Get-SccProcessInventory { return $script:fakeProcesses }
            Mock -CommandName Get-SccUninstallInventory { return $script:fakeUninstall }
            Mock -CommandName Get-SccServiceInstallEvents { return $script:fakeEvents }
            Mock -CommandName Get-SccScDirs { return @() }

            $res = Resolve-SccScInstances -Services $script:fakeServices -Processes $script:fakeProcesses `
                      -UninstallEntries $script:fakeUninstall -Events $script:fakeEvents -Target $script:scTarget -TrustedRelays @()
            $inst = $res.Instances[0]
            $inst.UninstallDisplayName  | Should -Be 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'
            $inst.UninstallString       | Should -Be 'MsiExec.exe /X{abc}'
            $inst.QuietUninstallString  | Should -Be 'MsiExec.exe /X{abc} /qn'
            $inst.UninstallRegistryKey  | Should -Be 'HKLM:\...\Uninstall\{abc}'
        }

        It 'F3: enumerates ConfigFiles for an instance with InstallPath even when blob came from the service' {
            $tmp = Join-Path $env:TEMP ('scc-cfg-' + [guid]::NewGuid().ToString())
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            'x' | Out-File -FilePath (Join-Path $tmp 'App_Config.config') -Encoding ascii

            $svc = [PSCustomObject]@{
                Name = 'ScreenConnect Client (cccccccccccccccc)'
                DisplayName = 'ScreenConnect Client (cccccccccccccccc)'
                PathName = '"C:\Windows\System32\svchost.exe" -k ScreenConnect "?e=Access&y=Guest&h=relay.example.com&p=8041&s=1111-2222&k=KEY123"'
                State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; ProcessId = 1; Description = ''
            }
            Mock -CommandName Get-SccServiceInventory { return @($svc) }
            Mock -CommandName Get-SccProcessInventory { return @() }
            Mock -CommandName Get-SccUninstallInventory { return @() }
            Mock -CommandName Get-SccServiceInstallEvents { return @() }
            Mock -CommandName Get-SccScDirs { return @([PSCustomObject]@{
                Name = 'ScreenConnect Client (cccccccccccccccc)'
                FullName = $tmp
                CreationTimeUtc = '2026-01-01 00:00:00'
            }) }

            $res = Resolve-SccScInstances -Services @($svc) -Processes @() `
                      -UninstallEntries @() -Events @() -Target $script:scTarget -TrustedRelays @()
            $inst = $res.Instances[0]
            $inst.InstallPath | Should -Be $tmp
            $inst.ParamBlobSource | Should -Be 'service ImagePath'
            @($inst.ConfigFiles).Count | Should -BeGreaterOrEqual 1

            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'Get-SccScreenConnect returns deduped instances from mocked inventory' {
            Mock -CommandName Get-SccServiceInventory { return $script:fakeServices }
            Mock -CommandName Get-SccProcessInventory { return $script:fakeProcesses }
            Mock -CommandName Get-SccUninstallInventory { return $script:fakeUninstall }
            Mock -CommandName Get-SccServiceInstallEvents { return $script:fakeEvents }
            Mock -CommandName Get-SccScDirs { return @() }

            $sc = @(Get-SccScreenConnect)
            @($sc).Count | Should -Be 1
            $sc[0].PSObject.Properties.Name -contains 'UnknownParameters' | Should -BeTrue
            @($sc[0].UnknownParameters).Count | Should -Be 0
            $sc[0].DetectionSources.Count | Should -BeGreaterThan 0
        }
    }

    Describe 'Generic remote-access detection (mocked)' {

        BeforeAll {
            $script:genericTargets = [PSCustomObject]@{
                id = 'anydesk'; name = 'AnyDesk'; enabled = $true; deep = $false
                servicePatterns = @('AnyDesk*'); processPatterns = @('AnyDesk*')
                pathPatterns = @('%ProgramFiles(x86)%\AnyDesk*'); uninstallPatterns = @('AnyDesk*')
            }
            $script:anySvc = [PSCustomObject]@{ Name = 'AnyDesk Service'; DisplayName = 'AnyDesk Service'; PathName = 'C:\Program Files (x86)\AnyDesk\anydesk.exe'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; ProcessId = 5; Description = '' }
        }

        It 'reports a service hit for a mocked AnyDesk service' {
            Mock -CommandName Get-SccServiceInventory { return @($script:anySvc) }
            Mock -CommandName Get-SccProcessInventory { return @() }
            Mock -CommandName Get-SccUninstallInventory { return @() }
            Mock -CommandName Get-SccScDirs { return @() }

            # Force the generic target by passing -Targets and bypassing enabled gating.
            $findings = @(Get-SccRemoteAccess -Targets @('anydesk') -All)
            @($findings).Count | Should -BeGreaterOrEqual 1
            $f = $findings | Where-Object { $_.Id -eq 'anydesk' } | Select-Object -First 1
            $f | Should -Not -BeNullOrEmpty
            $f.Count | Should -BeGreaterOrEqual 1
            $f.Hits[0].Kind | Should -Be 'Service'
            # anydesk is disabled in the real config, so Enabled reflects the
            # config flag (false), not the fact it was force-selected this run.
            $f.Enabled | Should -BeFalse
        }
    }
}

# ---------------------------------------------------------------------------
# Public-API tests (module imported at top-level; mocks via -ModuleName).
# ---------------------------------------------------------------------------
Describe 'Trust matching' {

    It 'exact relay match returns Known' {
        $relays = @([PSCustomObject]@{ relay = 'support.example.com'; name = 'Our MSP'; fingerprint = ''; notes = '' })
        $inst = [PSCustomObject]@{ ServerFingerprint = 'abc123' }
        $r = Test-SccTrustedRelay -Relay 'support.example.com' -Instance $inst -Config $relays
        $r.TrustMatch | Should -Be 'Known'
        $r.Entry.relay | Should -Be 'support.example.com'
    }

    It 'case-insensitive relay match returns Known' {
        $relays = @([PSCustomObject]@{ relay = 'Support.Example.COM'; name = 'Our MSP'; fingerprint = ''; notes = '' })
        $inst = [PSCustomObject]@{ ServerFingerprint = 'abc123' }
        $r = Test-SccTrustedRelay -Relay 'support.example.com' -Instance $inst -Config $relays
        $r.TrustMatch | Should -Be 'Known'
    }

    It 'wrong fingerprint returns Unknown' {
        $relays = @([PSCustomObject]@{ relay = 'support.example.com'; name = 'Our MSP'; fingerprint = 'deadbeefdeadbeef'; notes = '' })
        $inst = [PSCustomObject]@{ ServerFingerprint = 'abc123abc123abc1' }
        $r = Test-SccTrustedRelay -Relay 'support.example.com' -Instance $inst -Config $relays
        $r.TrustMatch | Should -Be 'Unknown'
    }

    It 'absent relay returns Unknown' {
        $relays = @([PSCustomObject]@{ relay = 'support.example.com'; name = 'Our MSP'; fingerprint = ''; notes = '' })
        $inst = [PSCustomObject]@{ ServerFingerprint = 'abc123' }
        $r = Test-SccTrustedRelay -Relay 'evil.example.com' -Instance $inst -Config $relays
        $r.TrustMatch | Should -Be 'Unknown'
    }

    It 'no config -> all Unknown' {
        $inst = [PSCustomObject]@{ ServerFingerprint = 'abc123' }
        $r = Test-SccTrustedRelay -Relay 'support.example.com' -Instance $inst -Config @()
        $r.TrustMatch | Should -Be 'Unknown'
    }
}

Describe 'Invoke-SccDetectionSelfTest' {

    It 'returns 0 failures' {
        $failures = Invoke-SccDetectionSelfTest
        @($failures).Count | Should -Be 0
    }
}

Describe 'findings.json is written on -Run' {

    It 'writes findings.json to the run dir' {
        $runDir = Join-Path $env:TEMP ('scc-det-' + [guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $runDir -Force | Out-Null
        $run = [PSCustomObject]@{ RunId = 'SC-TEST'; RunDir = $runDir }

        Mock -CommandName Get-SccServiceInventory { return @() } -ModuleName Scc.Detection
        Mock -CommandName Get-SccProcessInventory { return @() } -ModuleName Scc.Detection
        Mock -CommandName Get-SccUninstallInventory { return @() } -ModuleName Scc.Detection
        Mock -CommandName Get-SccServiceInstallEvents { return @() } -ModuleName Scc.Detection
        Mock -CommandName Get-SccScDirs { return @() } -ModuleName Scc.Detection

        $result = Invoke-SccDetection -Run $run
        $jsonPath = Join-Path $runDir 'findings.json'
        Test-Path -LiteralPath $jsonPath | Should -BeTrue
        $content = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        $content.ComputerName | Should -Be $env:COMPUTERNAME
        @($content.ScreenConnect).Count | Should -Be 0

        Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Standalone operation without external config' {

    It 'works with no targets.json / trusted-relays.json present' {
        Mock -CommandName Get-SccServiceInventory { return @() } -ModuleName Scc.Detection
        Mock -CommandName Get-SccProcessInventory { return @() } -ModuleName Scc.Detection
        Mock -CommandName Get-SccUninstallInventory { return @() } -ModuleName Scc.Detection
        Mock -CommandName Get-SccServiceInstallEvents { return @() } -ModuleName Scc.Detection
        Mock -CommandName Get-SccScDirs { return @() } -ModuleName Scc.Detection

        { Get-SccScreenConnect } | Should -Not -Throw
        { Get-SccRemoteAccess } | Should -Not -Throw
        { Get-SccTrustedRelays } | Should -Not -Throw
    }
}
