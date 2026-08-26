# Scc.Core unit tests (Pester 6, Linux, no network)
# Pure ASCII. Covers the required test matrix from the module contract.

Describe 'Scc.Core configuration' {

    It 'returns embedded defaults when no file present' {
        InModuleScope Scc.Core { $script:SccConfig = $null }
        $cfg = Get-SccConfig
        $cfg.logging.level | Should -Be 'INFO'
        $cfg.safety.serverOsRefusal | Should -BeTrue
        $cfg.safety.removableProducts | Should -Contain 'screenconnect'
        $cfg.paths.reportRoot | Should -Be '%USERPROFILE%\Documents\ScreenConnect Cleanup\Reports'
        @($cfg.trustedRelays).Count | Should -BeGreaterThan 0
    }

    It 'merges a user file override via -Path' {
        $tmp = New-TemporaryFile | Rename-Item -NewName { $_ -replace '\.tmp$', '.json' } -PassThru
        $tmp.FullName
        Set-Content -Path $tmp.FullName -Value '{"logging":{"level":"DEBUG"},"safety":{"serverOsRefusal":false}}' -Encoding ASCII
        $cfg = Get-SccConfig -Path $tmp.FullName
        $cfg.logging.level | Should -Be 'DEBUG'
        $cfg.safety.serverOsRefusal | Should -BeFalse
        # untouched sections keep defaults
        $cfg.safety.dryRunDefault | Should -BeTrue
        Remove-Item -LiteralPath $tmp.FullName -Force
    }

    It 'falls back to defaults + warning on malformed JSON' {
        Mock -ModuleName Scc.Core Write-SccLog {} -ParameterFilter { $Level -eq 'WARNING' }
        $tmp = New-TemporaryFile | Rename-Item -NewName { $_ -replace '\.tmp$', '.json' } -PassThru
        Set-Content -Path $tmp.FullName -Value '{ this is not valid json ,,,' -Encoding ASCII
        $cfg = Get-SccConfig -Path $tmp.FullName
        $cfg.logging.level | Should -Be 'INFO'
        $cfg.safety.serverOsRefusal | Should -BeTrue
        Should -Invoke -ModuleName Scc.Core Write-SccLog -ParameterFilter { $Level -eq 'WARNING' } -Times 1
        Remove-Item -LiteralPath $tmp.FullName -Force
    }
}

Describe 'Resolve-SccEnv' {

    It 'expands known %VAR% placeholders' {
        $env:SCC_TEST_TEMP = '/tmp/sccroottemp'
        $env:SCC_TEST_PROG = '/progdata'
        Resolve-SccEnv -Text '%SCC_TEST_TEMP%\sub' | Should -Be '/tmp/sccroottemp\sub'
        Resolve-SccEnv -Text '%SCC_TEST_PROG%\x' | Should -Be '/progdata\x'
        Remove-Item Env:SCC_TEST_TEMP, Env:SCC_TEST_PROG
    }

    It 'leaves unknown %VAR% literal' {
        Resolve-SccEnv -Text '%SCC_DOES_NOT_EXIST_XYZ%' | Should -Be '%SCC_DOES_NOT_EXIST_XYZ%'
    }
}

Describe 'Get-SccPaths env-var expansion' {
    BeforeAll {
        $env:SCC_TMP = '/tmp/sccenv'
        $env:SCC_PDATA = '/progdata'
        $env:SCC_LDATA = '/localdata'
    }
    AfterAll {
        Remove-Item Env:SCC_TMP, Env:SCC_PDATA, Env:SCC_LDATA -ErrorAction SilentlyContinue
    }

    It 'expands config paths and derivces subdirs' {
        InModuleScope Scc.Core { $script:SccConfig = $null }
        $p = Get-SccPaths
        $p.ProgramDataDir | Should -Match 'ScreenConnectCleaner'
        $p.ToolCacheDir | Should -Match 'tools$'
        $p.ReportRoot | Should -Be '%USERPROFILE%\Documents\ScreenConnect Cleanup\Reports'
    }

    It 'includes run id in TempDir and QuarantineRoot when -Run given' {
        $run = [PSCustomObject]@{ RunId = 'SC-20260101-HOST-120000'; RunDir = '/x' }
        $p = Get-SccPaths -Run $run
        $p.TempDir | Should -Match 'SC-20260101-HOST-120000$'
        $p.QuarantineRoot | Should -Match 'SC-20260101-HOST-120000$'
    }
}

Describe 'New-SccRun and run state' {
    BeforeAll {
        $script:reportRoot = Join-Path (New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('scc-test-' + [guid]::NewGuid())) -Force).FullName 'reports'
        $env:COMPUTERNAME = 'TESTHOST'
    }
    AfterAll {
        Remove-Item -LiteralPath (Split-Path $script:reportRoot) -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'creates correct dir tree with 9 Pending stages and valid RunId' {
        $run = New-SccRun -ReportRoot $script:reportRoot -Technician 'T1' -Client 'C1'
        $run.RunId | Should -Match '^SC-\d{8}-[A-Z0-9_]{1,20}-\d{6}$'
        Test-Path -LiteralPath $run.RunDir | Should -BeTrue
        foreach ($s in @('evidence','snapshots','scanner-results','logs','quarantine-meta')) {
            Test-Path -LiteralPath (Join-Path $run.RunDir $s) | Should -BeTrue
        }
        $state = Get-SccRunState -RunId $run.RunId
        @($state.Stages).Count | Should -Be 9
        foreach ($st in $state.Stages) { $st.Status | Should -Be 'Pending' }
        $script:runId = $run.RunId
    }

    It 'Find-SccRecentRuns finds the created run, newest first' {
        Start-Sleep -Milliseconds 50
        $runs = Find-SccRecentRuns -MaxAgeDays 7
        @($runs | Where-Object { $_.RunId -eq $script:runId }).Count | Should -Be 1
    }

    It 'Save-SccRunState updates a stage status' {
        $run = [PSCustomObject]@{ RunId = $script:runId; RunDir = (Join-Path $script:reportRoot $script:runId) }
        Save-SccRunState -Run $run -Stage 'Detection' -Status Completed -Detail 'ok'
        $state = Get-SccRunState -RunId $script:runId
        ($state.Stages | Where-Object { $_.Name -eq 'Detection' }).Status | Should -Be 'Completed'
    }
}

Describe 'Write-SccLog' {
    BeforeAll {
        $script:logRoot = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('scc-log-' + [guid]::NewGuid())) -Force
        $script:run = [PSCustomObject]@{ RunId = 'SC-20260101-HOST-120000'; RunDir = $script:logRoot.FullName }
        InModuleScope Scc.Core { $script:SccConfig = [PSCustomObject]@{ logging = [PSCustomObject]@{ level = 'DEBUG' } } }
    }
    AfterAll {
        Remove-Item -LiteralPath $script:logRoot.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'applies level threshold (TRACE filtered out at DEBUG)' {
        Write-SccLog -Run $script:run -Level TRACE -Stage 'Detect' -Component 'X' -Operation 'Y' -Message 'should-be-filtered'
        Write-SccLog -Run $script:run -Level INFO -Stage 'Detect' -Component 'X' -Operation 'Y' -Message 'keep-me' -Data ([PSCustomObject]@{ n = 1 })
        $jsonl = Join-Path $script:run.RunDir 'logs\Detect.jsonl'
        $lines = Get-Content -LiteralPath $jsonl
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match 'keep-me'
        $parsed = $lines[0] | ConvertFrom-Json
        $parsed.level | Should -Be 'INFO'
        $parsed.data.n | Should -Be 1
    }

    It 'writes a plain line to master.log' {
        $master = Join-Path $script:run.RunDir 'logs\master.log'
        Test-Path -LiteralPath $master | Should -BeTrue
        Get-Content -LiteralPath $master | Should -Match '\[INFO\]'
    }
}

Describe 'Get-SccFileFacts' {
    BeforeAll {
        $script:f = New-TemporaryFile
        Set-Content -Path $script:f.FullName -Value 'hello scc' -Encoding ASCII
        $script:expectedSha = (Get-FileHash -LiteralPath $script:f.FullName -Algorithm SHA256).Hash
    }
    AfterAll {
        Remove-Item -LiteralPath $script:f.FullName -Force -ErrorAction SilentlyContinue
    }

    It 'returns size, sha256, and NotChecked signature on Linux' {
        InModuleScope Scc.Core { $script:SccConfig = $null; $script:SccCache = @{} }
        $facts = Get-SccFileFacts -Path $script:f.FullName
        $facts.Exists | Should -BeTrue
        $facts.Size | Should -Be (('hello scc').Length)
        $facts.SHA256 | Should -Be $script:expectedSha
        $facts.SignatureStatus | Should -Be 'NotChecked'
    }

    It 'returns identical SHA256 on second (cached) call' {
        $facts1 = Get-SccFileFacts -Path $script:f.FullName -TtlSeconds 3600
        $facts2 = Get-SccFileFacts -Path $script:f.FullName -TtlSeconds 3600
        $facts1.SHA256 | Should -Be $facts2.SHA256
    }
}

Describe 'ConvertTo-SccJson single-element array' {
    It 'serializes a one-element array as an array (not an object)' {
        $json = ConvertTo-SccJson -InputObject @(42)
        $json | Should -Match '^\[42\]$'
        $back = ConvertFrom-Json -InputObject $json
        $back -is [System.Array] | Should -BeTrue
        @($back).Count | Should -Be 1
    }

    It 'serializes an empty array as an array' {
        $json = ConvertTo-SccJson -InputObject @()
        $json | Should -Match '^\[\]$'
    }
}

Describe 'Test-SccNas' {
    BeforeAll {
        $script:real = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('scc-nas-' + [guid]::NewGuid())) -Force
        $script:missing = Join-Path $env:TEMP ('scc-nas-missing-' + [guid]::NewGuid())
    }
    AfterAll {
        Remove-Item -LiteralPath $script:real.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'returns Reachable true for a real directory' {
        $r = Test-SccNas -NasPath $script:real.FullName
        $r.Reachable | Should -BeTrue
    }

    It 'returns Reachable false for a nonexistent path' {
        $r = Test-SccNas -NasPath $script:missing
        $r.Reachable | Should -BeFalse
    }
}
