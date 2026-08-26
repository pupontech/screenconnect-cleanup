# Scc.Tools unit tests (Pester 6, Linux, NO network).
# Pure ASCII. Covers the required test matrix from the module contract.
# All acquisition/integrity/status/provenance behavior is exercised through
# InModuleScope so private helpers (Get-SccWebDownload, Find-SccNasFile) can be
# Mocked and the runtime config can point at throwaway temp dirs.

$modulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'Scc.Tools' 'Scc.Tools.psd1'

# Import at file top-level so the InModuleScope blocks below resolve the module
# during Pester discovery (BeforeAll runs too late for top-level InModuleScope).
Import-Module $modulePath -Force

Describe 'Scc.Tools module surface' {
    It 'exports exactly the public contract functions' {
        $actual   = @(Get-Command -Module Scc.Tools | Where-Object { $_.CommandType -eq 'Function' } | ForEach-Object { $_.Name } | Sort-Object)
        $expected = @(
            'Get-SccToolCatalog',
            'Get-SccToolStatus',
            'Resolve-SccTool',
            'Save-SccToolToCache',
            'Test-SccToolIntegrity',
            'Write-SccToolProvenance'
        ) | Sort-Object
        $actual | Should -Be $expected
    }
}

# ---------------------------------------------------------------------------
# Catalog + acquisition + integrity + status + provenance, all in module scope
# so private helpers are mockable and temp dirs are used for the cache/NAS.
# ---------------------------------------------------------------------------
InModuleScope Scc.Tools {

    Describe 'Scc.Tools catalog' {
        It 'exposes all 9 catalog tools' {
            $names = @(Get-SccToolCatalog | ForEach-Object { $_.Name })
            $names.Count | Should -Be 9
            $names | Should -Contain 'KVRT'
            $names | Should -Contain 'MSERT'
            $names | Should -Contain 'AdwCleaner'
            $names | Should -Contain 'ESETOnline'
            $names | Should -Contain 'Malwarebytes'
            $names | Should -Contain 'autorunsc64'
            $names | Should -Contain 'sigcheck64'
            $names | Should -Contain 'procmon'
            $names | Should -Contain 'tcpview'
        }

        It 'uses only https official URLs' {
            foreach ($t in @(Get-SccToolCatalog)) {
                [string]$t.OfficialUrl | Should -Match '^https://'
            }
        }

        It 'KVRT URL matches the legacy Get-AVTools.ps1 value exactly' {
            $kvrt = @(Get-SccToolCatalog | Where-Object { $_.Name -eq 'KVRT' })[0]
            $kvrt.OfficialUrl | Should -Be 'https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe'
        }

        It 'Malwarebytes URL matches the legacy Get-AVTools.ps1 value exactly' {
            $mb = @(Get-SccToolCatalog | Where-Object { $_.Name -eq 'Malwarebytes' })[0]
            $mb.OfficialUrl | Should -Be 'https://downloads.malwarebytes.com/file/mb-windows/'
        }

        It 'Sysinternals URLs follow download.sysinternals.com/files/<Zip>.zip' {
            foreach ($t in @(Get-SccToolCatalog | Where-Object { $_.Name -in @('autorunsc64','sigcheck64','procmon','tcpview') })) {
                [string]$t.OfficialUrl | Should -Match '^https://download\.sysinternals\.com/files/.*\.zip$'
                $t.ExpectedSha256 | Should -Not -BeNullOrEmpty
            }
        }
    }

    Describe 'Scc.Tools acquisition and validation' {
        BeforeAll {
            $script:scratchRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc_tools_' + [guid]::NewGuid().ToString('N'))
            $script:userData    = Join-Path $script:scratchRoot 'userdata'
            $script:cache       = Join-Path $script:userData 'tools'
            $script:nas         = Join-Path $script:scratchRoot 'nas'
            $null = New-Item -ItemType Directory -Path $script:cache -Force
            $null = New-Item -ItemType Directory -Path $script:nas -Force
            $script:config = @{
                ToolCacheDir    = $script:cache
                NasEnabled      = $true
                NasPath         = $script:nas
                PriorityOrder   = @('local', 'nas', 'official')
                DownloadAllowed = $true
            }
        }

        BeforeEach {
            Set-SccToolRuntimeConfig -Config $script:config
            # Reset cache + NAS to a clean state per test.
            Get-ChildItem -LiteralPath $script:cache -Recurse -File -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            Get-ChildItem -LiteralPath $script:nas -Recurse -File -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            $manifestFile = Join-Path $script:cache 'tool-cache-manifest.json'
            if (Test-Path -LiteralPath $manifestFile) {
                Remove-Item -LiteralPath $manifestFile -Force -ErrorAction SilentlyContinue
            }
        }

        AfterAll {
            if (Test-Path -LiteralPath $script:scratchRoot) {
                Remove-Item -LiteralPath $script:scratchRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'uses a valid local cache file with no NAS or web access' {
            Mock Find-SccNasFile { throw 'Find-SccNasFile should not be called' }
            Mock Get-SccWebDownload { throw 'Get-SccWebDownload should not be called' }
            $cached = Join-Path $script:cache 'KVRT\KVRT.exe'
            $null = New-Item -ItemType Directory -Path (Split-Path $cached) -Force
            Set-Content -LiteralPath $cached -Value 'LOCAL-VALID-KVRT' -Encoding ASCII

            $r = Resolve-SccTool -Tool 'KVRT'
            $r.Source | Should -Be 'LocalCache'
            Test-Path -LiteralPath $r.ResolvedPath | Should -BeTrue
            Should -Invoke Find-SccNasFile -Times 0
            Should -Invoke Get-SccWebDownload -Times 0
        }

        It 'falls through to NAS when the local cache file is corrupt' {
            Mock Get-SccWebDownload { throw 'official should not be reached' }
            # Establish a known-good KVRT baseline in the cache/manifest.
            $seed = Join-Path $script:nas 'KVRT.exe'
            Set-Content -LiteralPath $seed -Value 'REAL-KVRT-CONTENT' -Encoding ASCII
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' | Should -BeTrue
            # Corrupt the cached copy (now differs from the manifest hash).
            $cached = Join-Path $script:cache 'KVRT\KVRT.exe'
            Set-Content -LiteralPath $cached -Value 'CORRUPTED-CACHE-COPIES' -Encoding ASCII

            $r = Resolve-SccTool -Tool 'KVRT'
            $r.Source | Should -Be 'Nas'
            Should -Invoke Get-SccWebDownload -Times 0
        }

        It 'resolves from NAS and copies the valid file into the local cache' {
            Mock Get-SccWebDownload { throw 'official should not be reached' }
            Set-Content -LiteralPath (Join-Path $script:nas 'KVRT.exe') -Value 'NAS-KVRT-CONTENT' -Encoding ASCII

            $r = Resolve-SccTool -Tool 'KVRT'
            $r.Source | Should -Be 'Nas'
            Test-Path -LiteralPath (Join-Path $script:cache 'KVRT\KVRT.exe') | Should -BeTrue
            Should -Invoke Get-SccWebDownload -Times 0
            (@($r.Provenance.Warnings) -join ';') | Should -Not -Match 'NAS unreachable'
        }

        It 'warns on unreachable NAS but is not fatal and falls back to a mocked official download' {
            $badConfig = @{
                ToolCacheDir    = $script:cache
                NasEnabled      = $true
                NasPath         = Join-Path $script:scratchRoot 'does-not-exist'
                PriorityOrder   = @('local', 'nas', 'official')
                DownloadAllowed = $true
            }
            Set-SccToolRuntimeConfig -Config $badConfig
            Mock Get-SccWebDownload {
                param([string]$Url, [string]$Dest)
                Set-Content -LiteralPath $Dest -Value 'OFFICIAL-KVRT-CONTENT' -Encoding ASCII
                return @{
                    Success   = $true
                    LocalPath = $Dest
                    FinalUrl  = $Url
                    Redirects = @()
                    Error     = ''
                }
            }

            $r = Resolve-SccTool -Tool 'KVRT'
            $r.Source | Should -Be 'Official'
            [string]$r.Provenance.DownloadUrl | Should -Match 'kaspersky-labs.com/kvrt/latest/full/KVRT.exe'
            (@($r.Provenance.Warnings) -join ';') | Should -Match 'NAS unreachable'
            Should -Invoke Get-SccWebDownload -Times 1
        }

        It 'rejects a NAS file whose hash does not match, then falls back to a mocked official download' {
            Mock Get-SccWebDownload {
                param([string]$Url, [string]$Dest)
                Set-Content -LiteralPath $Dest -Value 'REAL-KVRT-CONTENT' -Encoding ASCII
                return @{
                    Success   = $true
                    LocalPath = $Dest
                    FinalUrl  = $Url
                    Redirects = @()
                    Error     = ''
                }
            }
            # Record a known-good KVRT baseline in the manifest.
            $seed = Join-Path $script:nas 'KVRT.exe'
            Set-Content -LiteralPath $seed -Value 'REAL-KVRT-CONTENT' -Encoding ASCII
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' | Should -BeTrue
            # NAS now holds a WRONG-hash binary (differs from the baseline).
            Set-Content -LiteralPath $seed -Value 'TAMPERED-NAS-BINARY' -Encoding ASCII
            # -ForceRefresh bypasses local, forcing the NAS validation to run and fail.
            $r = Resolve-SccTool -Tool 'KVRT' -ForceRefresh
            $r.Source | Should -Be 'Official'
            (@($r.Provenance.Warnings) -join ';') | Should -Match 'cache manifest'
            Should -Invoke Get-SccWebDownload -Times 1
        }

        It 'caches a successful mocked official download and records provenance' {
            Mock Get-SccWebDownload {
                param([string]$Url, [string]$Dest)
                Set-Content -LiteralPath $Dest -Value 'OFFICIAL-KVRT-CONTENT' -Encoding ASCII
                return @{
                    Success   = $true
                    LocalPath = $Dest
                    FinalUrl  = 'https://cdn.example.com/redirected/KVRT.exe'
                    Redirects = @('https://cdn.example.com/redirected/KVRT.exe')
                    Error     = ''
                }
            }

            $r = Resolve-SccTool -Tool 'KVRT'
            $r.Source | Should -Be 'Official'
            Test-Path -LiteralPath (Join-Path $script:cache 'KVRT\KVRT.exe') | Should -BeTrue
            [string]$r.Provenance.DownloadUrl | Should -Match 'kaspersky-labs.com/kvrt/latest/full/KVRT.exe'
            [string]$r.Provenance.FinalUrl | Should -Match 'cdn.example.com'
            @($r.Provenance.Redirects).Count | Should -BeGreaterThan 0
            Should -Invoke Get-SccWebDownload -Times 1

            # Manifest entry carries the download provenance + SHA256.
            $entry = @(Get-SccCacheManifest | Where-Object { $_.Name -eq 'KVRT' })[0]
            $entry.DownloadUrl | Should -Match 'kaspersky-labs.com/kvrt/latest/full/KVRT.exe'
            $entry.SHA256 | Should -Not -BeNullOrEmpty
        }

        It 'records a failure and returns Source=None on an official HTTP error (non-fatal)' {
            Mock Get-SccWebDownload {
                param([string]$Url, [string]$Dest)
                return @{
                    Success   = $false
                    LocalPath = $Dest
                    FinalUrl  = $Url
                    Redirects = @()
                    Error     = 'HTTP 404 Not Found'
                }
            }

            $r = Resolve-SccTool -Tool 'KVRT'
            $r.Source | Should -Be 'None'
            [string]$r.ResolvedPath | Should -Be ''
            (@($r.Provenance.Warnings) -join ';') | Should -Match 'official download failed'
            { Resolve-SccTool -Tool 'KVRT' } | Should -Not -Throw
        }

        It 'Test-SccToolIntegrity accepts a valid unbaselined file with a NotChecked signature note' {
            $f = Join-Path $script:nas 'valid.tmp'
            Set-Content -LiteralPath $f -Value 'SOME-VALID-BINARY' -Encoding ASCII
            $c = Test-SccToolIntegrity -Path $f -Tool 'KVRT'
            $c.Passed | Should -BeTrue
            (@($c.Reasons) -join ';') | Should -Match 'not checked'
        }

        It 'Test-SccToolIntegrity fails a tampered file against a catalog baseline' {
            $f = Join-Path $script:nas 'sig.tmp'
            Set-Content -LiteralPath $f -Value 'THIS-IS-NOT-SIGCHECK64' -Encoding ASCII
            $c = Test-SccToolIntegrity -Path $f -Tool 'sigcheck64'
            $c.Passed | Should -BeFalse
            (@($c.Reasons) -join ';') | Should -Match 'SHA256 mismatch vs catalog baseline'
        }

        It 'Test-SccToolIntegrity fails an empty file (size zero)' {
            $f = Join-Path $script:nas 'empty.tmp'
            $null = New-Item -ItemType File -Path $f -Force   # true 0-byte file
            $c = Test-SccToolIntegrity -Path $f -Tool 'KVRT'
            $c.Passed | Should -BeFalse
        }

        It 'Save-SccToolToCache refuses an invalid file and caches nothing' {
            $bad = Join-Path $script:nas 'bad.tmp'
            Set-Content -LiteralPath $bad -Value 'NOT-A-VALID-SIGCHECK' -Encoding ASCII
            Save-SccToolToCache -Path $bad -Tool 'sigcheck64' | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $script:cache 'sigcheck64\sigcheck64.exe') | Should -BeFalse
        }

        It 'manifest round-trip: save, re-read, entry present with SHA256' {
            $seed = Join-Path $script:nas 'KVRT.exe'
            Set-Content -LiteralPath $seed -Value 'MANIFEST-ROUNDTRIP-DATA' -Encoding ASCII
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' | Should -BeTrue

            $manifestFile = Join-Path $script:cache 'tool-cache-manifest.json'
            Test-Path -LiteralPath $manifestFile | Should -BeTrue
            $entries = @(Get-SccCacheManifest)
            $e = @($entries | Where-Object { $_.Name -eq 'KVRT' })[0]
            $e.Name   | Should -Be 'KVRT'
            $e.SHA256 | Should -Not -BeNullOrEmpty
            $e.Size   | Should -BeGreaterThan 0
        }

        It 'Get-SccToolStatus reports cached, verified and NAS state without network calls' {
            $seed = Join-Path $script:nas 'KVRT.exe'
            Set-Content -LiteralPath $seed -Value 'STATUS-DATA' -Encoding ASCII
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' | Should -BeTrue

            $rows = @(Get-SccToolStatus)
            $rows.Count | Should -Be 9
            $kv = @($rows | Where-Object { $_.Name -eq 'KVRT' })[0]
            $kv.Cached        | Should -BeTrue
            $kv.CacheVerified | Should -BeTrue
            $kv.NasReachable  | Should -BeTrue
            $kv.NasPathFound  | Should -BeTrue
            $kv.OfficialAvailable | Should -BeTrue
            $kv.PSObject.Properties['CachedVersion'] | Should -Not -BeNullOrEmpty   # property present; plain data has no file version
            $kv.Source        | Should -Be 'LocalCache'       # cached + verified wins over NAS/official
        }

        It 'Get-SccToolStatus marks OfficialAvailable=false when download is disabled' {
            $noDownload = @{
                ToolCacheDir    = $script:cache
                NasEnabled      = $false
                NasPath         = ''
                PriorityOrder   = @('local', 'nas', 'official')
                DownloadAllowed = $false
            }
            Set-SccToolRuntimeConfig -Config $noDownload
            $rows = @(Get-SccToolStatus)
            foreach ($row in $rows) {
                $row.OfficialAvailable | Should -BeFalse
            }
            $none = @($rows)[0]
            $none.Source | Should -Be 'None'
        }

        It 'Write-SccToolProvenance writes tool provenance JSON into a run dir from -Run' {
            $runDir = Join-Path $script:scratchRoot 'run1'
            $null = New-Item -ItemType Directory -Path $runDir -Force
            $run = [PSCustomObject]@{ RunDir = $runDir; RunId = 'SC-20260826-TEST-130000' }
            $toolObj = [PSCustomObject]@{
                Name         = 'KVRT'
                ResolvedPath = 'C:\cache\KVRT\KVRT.exe'
                Source       = 'Official'
                SHA256       = 'ABCDEF'
                Provenance   = @{ DownloadUrl = 'https://example.com/kvrt.exe' }
            }

            $out = Write-SccToolProvenance -Run $run -Tools @($toolObj)
            $expected = Join-Path $runDir 'tool-provenance.json'
            $out | Should -Be $expected
            Test-Path -LiteralPath $expected | Should -BeTrue
            $parsed = Get-Content -LiteralPath $expected -Raw | ConvertFrom-Json
            @($parsed).Count | Should -BeGreaterThan 0
            $parsed[0].Name | Should -Be 'KVRT'
        }

        It 'Write-SccToolProvenance accepts -OutputPath when no run dir is available' {
            $out = Join-Path $script:scratchRoot 'provenance-direct.json'
            $toolObj = [PSCustomObject]@{ Name = 'MSERT'; Source = 'None' }
            $result = Write-SccToolProvenance -Tools @($toolObj) -OutputPath $out
            $result | Should -Be $out
            Test-Path -LiteralPath $out | Should -BeTrue
        }
    }
}