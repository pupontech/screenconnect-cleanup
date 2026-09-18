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
            # Platform guard: on Windows, Get-AuthenticodeSignature returns UnknownError for
            # fake test binaries, which would incorrectly block cache/NAS/official tests.
            # Mock Get-SccToolFacts to return NotChecked with the real hash so the
            # B1 signature-rejection logic is not exercised in this Describe (the
            # dedicated hardening Describe covers it explicitly). This keeps the
            # acquisition tests platform-agnostic without weakening product code.
            Mock Get-SccToolFacts {
                param([string]$Path)
                $exists = Test-Path -LiteralPath $Path
                if (-not $exists) {
                    return [PSCustomObject]@{ Path = $Path; Exists = $false; SizeBytes = $null; SHA256 = $null; FileVersion = ''; Publisher = ''; SignatureStatus = 'NotChecked'; LastWriteUtc = $null }
                }
                $sz = $null; $h = $null; $ver = ''
                try { $sz = (Get-Item -LiteralPath $Path -ErrorAction Stop).Length } catch {}
                try { $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
                try {
                    $it = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
                    if ($it -and $it.VersionInfo.FileVersion) { $ver = $it.VersionInfo.FileVersion }
                } catch {}
                return [PSCustomObject]@{ Path = $Path; Exists = $true; SizeBytes = $sz; SHA256 = $h; FileVersion = $ver; Publisher = ''; SignatureStatus = 'NotChecked'; LastWriteUtc = (Get-Date).ToUniversalTime() }
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
            $hash = (Get-FileHash -LiteralPath $seed -Algorithm SHA256).Hash
            $size = (Get-Item -LiteralPath $seed).Length
            $check = [PSCustomObject]@{ Passed = $true; Reasons = @('signature not checked on this platform, accepted'); Facts = [PSCustomObject]@{ Path = $seed; Exists = $true; SizeBytes = $size; SHA256 = $hash; FileVersion = '1.0'; Publisher = ''; SignatureStatus = 'NotChecked'; LastWriteUtc = (Get-Date).ToUniversalTime() } }
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' -Integrity $check | Should -BeTrue
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
            $hash = (Get-FileHash -LiteralPath $seed -Algorithm SHA256).Hash
            $size = (Get-Item -LiteralPath $seed).Length
            $check = [PSCustomObject]@{ Passed = $true; Reasons = @('signature not checked on this platform, accepted'); Facts = [PSCustomObject]@{ Path = $seed; Exists = $true; SizeBytes = $size; SHA256 = $hash; FileVersion = '1.0'; Publisher = ''; SignatureStatus = 'NotChecked'; LastWriteUtc = (Get-Date).ToUniversalTime() } }
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' -Integrity $check | Should -BeTrue
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
            $hash = (Get-FileHash -LiteralPath $seed -Algorithm SHA256).Hash
            $size = (Get-Item -LiteralPath $seed).Length
            $check = [PSCustomObject]@{ Passed = $true; Reasons = @('signature not checked on this platform, accepted'); Facts = [PSCustomObject]@{ Path = $seed; Exists = $true; SizeBytes = $size; SHA256 = $hash; FileVersion = '1.0'; Publisher = ''; SignatureStatus = 'NotChecked'; LastWriteUtc = (Get-Date).ToUniversalTime() } }
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' -Integrity $check | Should -BeTrue

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
            $hash = (Get-FileHash -LiteralPath $seed -Algorithm SHA256).Hash
            $size = (Get-Item -LiteralPath $seed).Length
            $check = [PSCustomObject]@{ Passed = $true; Reasons = @('signature not checked on this platform, accepted'); Facts = [PSCustomObject]@{ Path = $seed; Exists = $true; SizeBytes = $size; SHA256 = $hash; FileVersion = '1.0'; Publisher = ''; SignatureStatus = 'NotChecked'; LastWriteUtc = (Get-Date).ToUniversalTime() } }
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' -Integrity $check | Should -BeTrue
            # Mock Get-SccToolFacts for the status check so the cached file is verified on Windows (which would otherwise return UnknownError for the fake binary).
            Mock Get-SccToolFacts {
                param([string]$Path)
                $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                if (-not $h) { $h = 'FAKE' }
                $sz = $null; try { $sz = (Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).Length } catch { $sz = 1 }
                return [PSCustomObject]@{ Path = $Path; Exists = $true; SizeBytes = $sz; SHA256 = $h; FileVersion = '1.0'; Publisher = ''; SignatureStatus = 'NotChecked'; LastWriteUtc = (Get-Date).ToUniversalTime() }
            } -ParameterFilter { $Path -like '*KVRT*' }

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

    Describe 'Scc.Tools signature trust and MinVersion rejection (hardening B1/B2/B3)' {
        BeforeAll {
            $script:scratchRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc_tools_hard_' + [guid]::NewGuid().ToString('N'))
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


        foreach ($badStatus in @('NotTrusted', 'NotSigned', 'UnknownError', 'NotSupported', 'Error')) {
            It ('Test-SccToolIntegrity fails a binary whose signature status is ' + $badStatus) {
                Mock Get-SccToolFacts {
                    return [PSCustomObject]@{
                        Path='fake'; Exists=$true; SizeBytes=123
                        SHA256='FAKEHASH00000000000000000000000000000000000000000000000000000000000000'
                        FileVersion=''; Publisher=''; SignatureStatus=$badStatus
                        LastWriteUtc=(Get-Date).ToUniversalTime()
                    }
                }
                $c = Test-SccToolIntegrity -Path 'anything.exe' -Tool 'KVRT'
                $c.Passed | Should -BeFalse
                (@($c.Reasons) -join ';') | Should -Match 'signature'
            }

            It ('Resolve-SccTool refuses (Source=None + warning) a binary whose signature status is ' + $badStatus) {
                Mock Get-SccToolFacts {
                    return [PSCustomObject]@{
                        Path='fake'; Exists=$true; SizeBytes=123
                        SHA256='FAKEHASH00000000000000000000000000000000000000000000000000000000000000'
                        FileVersion=''; Publisher=''; SignatureStatus=$badStatus
                        LastWriteUtc=(Get-Date).ToUniversalTime()
                    }
                }
                Mock Find-SccNasFile { return $null }
                Mock Get-SccWebDownload {
                    param([string]$Url, [string]$Dest)
                    Set-Content -LiteralPath $Dest -Value 'X' -Encoding ASCII
                    return @{ Success = $true; LocalPath = $Dest; FinalUrl = $Url; Redirects = @(); Error = '' }
                }
                $r = Resolve-SccTool -Tool 'KVRT'
                $r.Source | Should -Be 'None'
                (@($r.Provenance.Warnings) -join ';') | Should -Match 'signature'
            }
        }

        It 'Test-SccToolIntegrity still accepts NotChecked on a non-Windows host (platform limitation)' {
            Mock Get-SccToolFacts {
                return [PSCustomObject]@{
                    Path='fake'; Exists=$true; SizeBytes=123
                    SHA256='FAKEHASH00000000000000000000000000000000000000000000000000000000000000'
                    FileVersion=''; Publisher=''; SignatureStatus='NotChecked'
                    LastWriteUtc=(Get-Date).ToUniversalTime()
                }
            }
            $c = Test-SccToolIntegrity -Path 'anything.exe' -Tool 'KVRT'
            $c.Passed | Should -BeTrue
            (@($c.Reasons) -join ';') | Should -Match 'not checked'
        }

        It 'Test-SccToolIntegrity refuses an unversioned binary when MinVersion is set (B2)' {
            Mock Get-SccToolFacts {
                return [PSCustomObject]@{
                    Path='fake'; Exists=$true; SizeBytes=123
                    SHA256='FAKEHASH00000000000000000000000000000000000000000000000000000000000000'
                    FileVersion=''; Publisher=''; SignatureStatus='NotChecked'
                    LastWriteUtc=(Get-Date).ToUniversalTime()
                }
            }
            $c = Test-SccToolIntegrity -Path 'mb.exe' -Tool 'Malwarebytes'
            $c.Passed | Should -BeFalse
            (@($c.Reasons) -join ';') | Should -Match 'MinVersion'
        }

        It 'Test-SccToolIntegrity accepts an unversioned binary when a catalog SHA256 baseline exists (B2 escape)' {
            Mock Get-SccToolFacts {
                return [PSCustomObject]@{
                    Path = 'x'; Exists = $true; SizeBytes = 9
                    SHA256 = 'A2EFFF8D5BCE9DB4B899D38AFAA706BDFD822711F929616A51B0DBC9F76C6281'
                    FileVersion = ''; Publisher = ''; SignatureStatus = 'NotChecked'; LastWriteUtc = (Get-Date).ToUniversalTime()
                }
            }
            $c = Test-SccToolIntegrity -Path 'sig.exe' -Tool 'sigcheck64'
            $c.Passed | Should -BeTrue
        }

        It 'Resolve-SccTool refuses an unversioned binary when MinVersion is set (B2)' {
            Mock Get-SccToolFacts {
                return [PSCustomObject]@{
                    Path='fake'; Exists=$true; SizeBytes=123
                    SHA256='FAKEHASH00000000000000000000000000000000000000000000000000000000000000'
                    FileVersion=''; Publisher=''; SignatureStatus='NotChecked'
                    LastWriteUtc=(Get-Date).ToUniversalTime()
                }
            }
            Mock Find-SccNasFile { return $null }
            Mock Get-SccWebDownload {
                param([string]$Url, [string]$Dest)
                Set-Content -LiteralPath $Dest -Value 'X' -Encoding ASCII
                return @{ Success = $true; LocalPath = $Dest; FinalUrl = $Url; Redirects = @(); Error = '' }
            }
            $r = Resolve-SccTool -Tool 'Malwarebytes'
            $r.Source | Should -Be 'None'
            (@($r.Provenance.Warnings) -join ';') | Should -Match 'MinVersion'
        }

        It 'Save-SccToolToCache does not re-hash when a pre-computed integrity result is supplied (B3)' {
            Mock Get-SccToolFacts { throw 'Get-SccToolFacts must not be called when -Integrity is supplied' }
            $check = [PSCustomObject]@{
                Passed  = $true
                Reasons = @('signature not checked on this platform, accepted')
                Facts   = [PSCustomObject]@{
                    Path='fake'; Exists=$true; SizeBytes=123
                    SHA256='FAKEHASH00000000000000000000000000000000000000000000000000000000000000'
                    FileVersion=''; Publisher=''; SignatureStatus='NotChecked'
                    LastWriteUtc=(Get-Date).ToUniversalTime()
                }
            }
            $seed = Join-Path $script:nas 'KVRT.exe'
            Set-Content -LiteralPath $seed -Value 'B3-DATA' -Encoding ASCII
            Save-SccToolToCache -Path $seed -Tool 'KVRT' -Source 'Nas' -Integrity $check | Should -BeTrue
            Should -Invoke Get-SccToolFacts -Times 0
            # The supplied facts were used (manifest carries the faked SHA256).
            $entry = @(Get-SccCacheManifest | Where-Object { $_.Name -eq 'KVRT' })[0]
            $entry.SHA256 | Should -Be 'FAKEHASH00000000000000000000000000000000000000000000000000000000000000'
        }
    }
}