# Scc.Core unit tests (Pester 6, Linux, no network)
# Pure ASCII. Covers the required test matrix from the module contract.

BeforeAll {
    if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
    if (-not $env:TMP) { $env:TMP = $env:TEMP }
    # Save original env so we can restore in AfterAll and not pollute other containers.
    $script:origLocalAppData = $env:LocalAppData
    $script:origProgramData = $env:ProgramData
    $script:origTemp = $env:TEMP
    # Control user/machine config discovery so no stray config pollutes defaults.
    $env:LocalAppData = Join-Path $env:TEMP ('scc-la-' + [guid]::NewGuid().ToString())
    $env:ProgramData = Join-Path $env:TEMP ('scc-pd-' + [guid]::NewGuid().ToString())
    if (-not (Test-Path -LiteralPath $env:LocalAppData)) { $null = New-Item -ItemType Directory -Path $env:LocalAppData -Force }
    if (-not (Test-Path -LiteralPath $env:ProgramData)) { $null = New-Item -ItemType Directory -Path $env:ProgramData -Force }
    $modulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'Scc.Core' 'Scc.Core.psd1'
    if (-not (Test-Path -LiteralPath $modulePath)) {
        throw "Scc.Core module not found at $modulePath"
    }
    Import-Module -Name $modulePath -Force
}

AfterAll {
    if ($null -ne $script:origLocalAppData) { $env:LocalAppData = $script:origLocalAppData } else { Remove-Item Env:LocalAppData -ErrorAction SilentlyContinue }
    if ($null -ne $script:origProgramData) { $env:ProgramData = $script:origProgramData } else { Remove-Item Env:ProgramData -ErrorAction SilentlyContinue }
    if ($script:origTemp -and $env:TEMP -ne $script:origTemp) { $env:TEMP = $script:origTemp }
    # Clean up temp dirs created in BeforeAll if they still exist.
    foreach ($p in @($env:LocalAppData, $env:ProgramData)) {
        if ($p -and $p -match 'scc-la-|scc-pd-' -and (Test-Path -LiteralPath $p)) {
            Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

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
        $tmp = Join-Path $env:TEMP ('scc-cfg-' + [guid]::NewGuid().ToString() + '.json')
        Set-Content -Path $tmp -Value '{"logging":{"level":"DEBUG"},"safety":{"serverOsRefusal":false}}' -Encoding ASCII
        $cfg = Get-SccConfig -Path $tmp
        $cfg.logging.level | Should -Be 'DEBUG'
        $cfg.safety.serverOsRefusal | Should -BeFalse
        # untouched sections keep defaults
        $cfg.safety.dryRunDefault | Should -BeTrue
        Remove-Item -LiteralPath $tmp -Force
    }

    It 'falls back to defaults + warning on malformed JSON' {
        Mock -ModuleName Scc.Core Write-SccLog {} -ParameterFilter { $Level -eq 'WARNING' }
        $tmp = Join-Path $env:TEMP ('scc-cfg-' + [guid]::NewGuid().ToString() + '.json')
        Set-Content -Path $tmp -Value '{ this is not valid json ,,,' -Encoding ASCII
        $cfg = Get-SccConfig -Path $tmp
        $cfg.logging.level | Should -Be 'INFO'
        $cfg.safety.serverOsRefusal | Should -BeTrue
        Should -Invoke -ModuleName Scc.Core Write-SccLog -ParameterFilter { $Level -eq 'WARNING' } -Times 1
        Remove-Item -LiteralPath $tmp -Force
    }
}

Describe 'Resolve-SccEnv' {

    It 'expands known %VAR% placeholders' {
        $tmpBase = Join-Path $env:TEMP ('sccroottemp-' + [guid]::NewGuid().ToString('N'))
        $progBase = Join-Path $env:TEMP ('progdata-' + [guid]::NewGuid().ToString('N'))
        $env:SCC_TEST_TEMP = $tmpBase
        $env:SCC_TEST_PROG = $progBase
        Resolve-SccEnv -Text '%SCC_TEST_TEMP%\sub' | Should -Be ($tmpBase + '\sub')
        Resolve-SccEnv -Text '%SCC_TEST_PROG%\x' | Should -Be ($progBase + '\x')
        Remove-Item Env:SCC_TEST_TEMP, Env:SCC_TEST_PROG -ErrorAction SilentlyContinue
    }

    It 'leaves unknown %VAR% literal' {
        Resolve-SccEnv -Text '%SCC_DOES_NOT_EXIST_XYZ%' | Should -Be '%SCC_DOES_NOT_EXIST_XYZ%'
    }
}

Describe 'Get-SccPaths env-var expansion' {
    BeforeAll {
        $env:SCC_TMP = Join-Path $env:TEMP ('sccenv-' + [guid]::NewGuid().ToString('N'))
        $env:SCC_PDATA = Join-Path $env:TEMP ('progdata-' + [guid]::NewGuid().ToString('N'))
        $env:SCC_LDATA = Join-Path $env:TEMP ('localdata-' + [guid]::NewGuid().ToString('N'))
    }
    AfterAll {
        Remove-Item Env:SCC_TMP, Env:SCC_PDATA, Env:SCC_LDATA -ErrorAction SilentlyContinue
    }

    It 'expands config paths and derivces subdirs' {
        InModuleScope Scc.Core { $script:SccConfig = $null }
        $p = Get-SccPaths
        $p.ProgramDataDir | Should -Match 'ScreenConnectCleaner'
        $p.ToolCacheDir | Should -Match 'tools$'
        $p.ReportRoot | Should -Match 'Documents\\ScreenConnect Cleanup\\Reports$'
        $p.ReportRoot | Should -Not -Match '%'
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
        $state = Get-SccRunState -RunId $run.RunId -ReportRoot $script:reportRoot
        @($state.Stages).Count | Should -Be 9
        foreach ($st in $state.Stages) { $st.Status | Should -Be 'Pending' }
        $script:runId = $run.RunId
    }

    It 'Find-SccRecentRuns finds the created run, newest first' {
        Start-Sleep -Milliseconds 50
        $runs = Find-SccRecentRuns -MaxAgeDays 7 -ReportRoot $script:reportRoot
        @($runs | Where-Object { $_.RunId -eq $script:runId }).Count | Should -Be 1
    }

    It 'Save-SccRunState updates a stage status' {
        $run = [PSCustomObject]@{ RunId = $script:runId; RunDir = (Join-Path $script:reportRoot $script:runId) }
        Save-SccRunState -Run $run -Stage 'Detection' -Status Completed -Detail 'ok'
        $state = Get-SccRunState -RunId $script:runId -ReportRoot $script:reportRoot
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
        $jsonl = Join-Path (Join-Path $script:run.RunDir 'logs') 'Detect.jsonl'
        $lines = @(Get-Content -LiteralPath $jsonl)
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match 'keep-me'
        $parsed = $lines[0] | ConvertFrom-Json
        $parsed.level | Should -Be 'INFO'
        $parsed.data.n | Should -Be 1
    }

    It 'writes a plain line to master.log' {
        $master = Join-Path (Join-Path $script:run.RunDir 'logs') 'master.log'
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

    It 'returns size, sha256, and platform-appropriate signature status' {
        InModuleScope Scc.Core { $script:SccConfig = $null; $script:SccCache = @{} }
        $facts = Get-SccFileFacts -Path $script:f.FullName
        $facts.Exists | Should -BeTrue
        $facts.SizeBytes | Should -Be (Get-Item -LiteralPath $script:f.FullName).Length
        $facts.SHA256 | Should -Be $script:expectedSha
        if ($env:OS -eq 'Windows_NT') {
            $facts.SignatureStatus | Should -Not -BeNullOrEmpty
            @('Valid','Invalid','NotSigned','UnknownError','NotTrusted','Error','NotSupported','NotChecked') | Should -Contain $facts.SignatureStatus
        } else {
            $facts.SignatureStatus | Should -Be 'NotChecked'
        }
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
        # pwsh may unroll on read; assert the serialized form is an array.
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

Describe 'runstate shape (resume contract)' {
    BeforeAll {
        if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
        $script:rtRoot = Join-Path $env:TEMP ('SccRt_' + [Guid]::NewGuid().ToString('N'))
        if (-not (Test-Path -LiteralPath $script:rtRoot)) { New-Item -ItemType Directory -Path $script:rtRoot -Force | Out-Null }
        # Save/restore the user config file so this Describe does not leak
        # its reportRoot override into other tests.
        $script:rtCfgDir = (Get-SccPaths).ConfigUserDir
        $script:rtCfgFile = Join-Path $script:rtCfgDir 'scc-config.json'
        $script:rtCfgBackup = $null
        if (Test-Path -LiteralPath $script:rtCfgFile) {
            try { $script:rtCfgBackup = [System.IO.File]::ReadAllText($script:rtCfgFile) } catch { $script:rtCfgBackup = $null }
        }
        Set-SccConfigValue -Name 'paths.reportRoot' -Value $script:rtRoot -UserScope
        $script:rtRun = New-SccRun -Technician 'rt' -Client 'c'
    }
    AfterAll {
        if ($null -ne $script:rtCfgBackup) {
            try { [System.IO.File]::WriteAllText($script:rtCfgFile, $script:rtCfgBackup, [System.Text.Encoding]::ASCII) } catch { }
        } elseif (Test-Path -LiteralPath $script:rtCfgFile) {
            Remove-Item -LiteralPath $script:rtCfgFile -Force -ErrorAction SilentlyContinue
        }
        if ($script:rtRoot -and (Test-Path -LiteralPath $script:rtRoot)) {
            Remove-Item -LiteralPath $script:rtRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    It 'runstate stages carry Index, Name, Status' {
        $state = Get-SccRunState -RunId $script:rtRun.RunId
        $state | Should -Not -BeNullOrEmpty
        @($state.Stages).Count | Should -Be 9
        $state.Stages[0].Index | Should -Be 0
        $state.Stages[0].Name | Should -Be 'Preflight'
        $state.Stages[8].Index | Should -Be 8
        $state.Stages[8].Name | Should -Be 'Report'
        $state.Stages[2].Status | Should -Be 'Pending'
    }
    It 'Save-SccRunState updates the named stage and Get-SccRunState reads it back' {
        Save-SccRunState -Run $script:rtRun -Stage 'Detection' -Status 'Completed' -Detail 'done'
        $state = Get-SccRunState -RunId $script:rtRun.RunId
        $det = $state.Stages | Where-Object { $_.Index -eq 2 }
        $det.Status | Should -Be 'Completed'
        $det.Detail | Should -Be 'done'
        $det.StartedUtc | Should -Not -BeNullOrEmpty
        $det.EndedUtc | Should -Not -BeNullOrEmpty
    }
}
