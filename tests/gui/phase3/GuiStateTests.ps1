Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$scriptPath = Join-Path $repoRoot 'gui-bridge/GuiState.ps1'
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { throw "Missing library: $scriptPath" }

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Library parse failed: $($parseErrors[0].Message)" }
. $scriptPath

$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "FAIL: $Message" }
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $script:Assertions++
    $thrown = $false
    try { & $Action } catch { $thrown = $true }
    if (-not $thrown) { throw "FAIL: expected rejection: $Message" }
}
function Assert-BytesEqual {
    param([byte[]]$Expected, [byte[]]$Actual, [string]$Message)
    $equal = $Expected.Length -eq $Actual.Length
    if ($equal) {
        for ($i = 0; $i -lt $Expected.Length; $i++) {
            if ($Expected[$i] -ne $Actual[$i]) { $equal = $false; break }
        }
    }
    Assert-True $equal $Message
}
function Get-CurrentRaw {
    param([string]$Path)
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
}
function Set-TestArtifact {
    param($State, [string]$Role, [string]$Path)
    $property = $State.artifacts.PSObject.Properties[$Role]
    if ($null -eq $property) {
        Add-Member -InputObject $State.artifacts -MemberType NoteProperty -Name $Role -Value $Path
    } else {
        $property.Value = $Path
    }
}

$testRoot = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('gui-state-tests-' + [Guid]::NewGuid().ToString('N')))
$runId = 'HOST-20260923_120000'
$runRoot = Join-Path $testRoot $runId
$outsideRoot = Join-Path $testRoot 'outside'
[void][System.IO.Directory]::CreateDirectory($runRoot)
[void][System.IO.Directory]::CreateDirectory($outsideRoot)

try {
    $state = New-GuiState -RunId $runId -ComputerName 'HOST'
    Assert-True ($state.stages.Count -eq 10) 'initializer creates exactly ten stages'
    $expectedNames = @('Preflight', 'Snapshot (Before)', 'Detect', 'Review Gate', 'Contain + Remove', 'Scanners', 'Uninstall installed AV', 'Procmon', 'Snapshot (After)+Diff', 'Report')
    for ($i = 0; $i -lt 10; $i++) {
        Assert-True ($state.stages[$i].id -eq $i) "stage $i has the exact engine ID"
        Assert-True ($state.stages[$i].name -ceq $expectedNames[$i]) "stage $i has the exact engine name"
        Assert-True ($state.stages[$i].status -ceq 'Pending') "stage $i starts Pending"
    }

    $target = Write-GuiState -RunRoot $runRoot -State $state
    Assert-True ([System.IO.File]::Exists($target)) 'initial state is published'
    $initialBytes = [System.IO.File]::ReadAllBytes($target)
    $hasBom = $initialBytes.Length -ge 3 -and $initialBytes[0] -eq 239 -and $initialBytes[1] -eq 187 -and $initialBytes[2] -eq 191
    Assert-True (-not $hasBom) 'state file is UTF-8 without BOM'
    $saved = ConvertFrom-Json -InputObject (Get-CurrentRaw $target)
    Assert-True ($saved.stages.Count -eq 10 -and $saved.schemaVersion -eq 1) 'published JSON parses with schema version 1'

    $state.stages[0].status = 'Running'
    $state.stages[0].startedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $state.currentStage = 0
    $state.updatedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    [void](Write-GuiState -RunRoot $runRoot -State $state)
    $runningRaw = Get-CurrentRaw $target
    $running = ConvertFrom-Json -InputObject $runningRaw
    Assert-True ($running.stages[0].status -ceq 'Running') 'valid Pending to Running transition is written'
    $sidecars = @(Get-ChildItem -LiteralPath $runRoot -Force | Where-Object { $_.Name -match '^\.gui-state\.json\..+\.(tmp|bak)$' })
    Assert-True ($sidecars.Count -eq 0) 'atomic replacement removes temporary and backup files'

    $state.stages[0].status = 'Pending'
    $beforeRejectedUpdate = Get-CurrentRaw $target
    Assert-Throws { Write-GuiState -RunRoot $runRoot -State $state } 'invalid Running to Pending transition'
    Assert-True ((Get-CurrentRaw $target) -ceq $beforeRejectedUpdate) 'invalid transition leaves the target byte-for-byte unchanged'

    $state = ConvertFrom-Json -InputObject $beforeRejectedUpdate
    $state.stages[0].status = 'RebootPending'
    [void](Write-GuiState -RunRoot $runRoot -State $state)
    $rebootPendingRaw = Get-CurrentRaw $target
    $state.stages[0].status = 'Running'
    Assert-Throws { Write-GuiState -RunRoot $runRoot -State $state } 'RebootPending cannot resume without trusted proof'
    Assert-True ((Get-CurrentRaw $target) -ceq $rebootPendingRaw) 'unproven reboot resume leaves the target unchanged'

    $state.stages[0].status = 'Incomplete'
    $state.stages[0].operation = 'Producer interrupted'
    [void](Write-GuiState -RunRoot $runRoot -State $state)
    $beforeRejectedUpdate = Get-CurrentRaw $target
    Assert-True ((ConvertFrom-Json -InputObject $beforeRejectedUpdate).stages[0].status -ceq 'Incomplete') 'interrupted stage can recover to Incomplete'

    $state = ConvertFrom-Json -InputObject $beforeRejectedUpdate
    Set-TestArtifact $state 'findings' '../outside/findings.json'
    Assert-Throws { Write-GuiState -RunRoot $runRoot -State $state } 'relative traversal artifact path'
    Assert-True ((Get-CurrentRaw $target) -ceq $beforeRejectedUpdate) 'traversal rejection leaves the target unchanged'

    $state = ConvertFrom-Json -InputObject $beforeRejectedUpdate
    Set-TestArtifact $state 'findings' 'detect/HOST_2026-09-23_120000/findings.json'
    [void](Write-GuiState -RunRoot $runRoot -State $state)
    $withArtifactRaw = Get-CurrentRaw $target
    Assert-True ((ConvertFrom-Json -InputObject $withArtifactRaw).artifacts.findings -ceq 'detect/HOST_2026-09-23_120000/findings.json') 'valid run-root-relative artifact is accepted'

    $linkPath = Join-Path $runRoot 'escape'
    try {
        New-Item -ItemType SymbolicLink -Path $linkPath -Target $outsideRoot -ErrorAction Stop | Out-Null
        $state = ConvertFrom-Json -InputObject $withArtifactRaw
        Set-TestArtifact $state 'findings' 'escape/findings.json'
        Assert-Throws { Write-GuiState -RunRoot $runRoot -State $state } 'symlink artifact escape'
        Assert-True ((Get-CurrentRaw $target) -ceq $withArtifactRaw) 'symlink escape rejection leaves the target unchanged'
    } catch {
        if ($_.Exception.Message -like 'FAIL:*') { throw }
        throw "Symlink regression could not be exercised: $($_.Exception.Message)"
    }

    $state = ConvertFrom-Json -InputObject $withArtifactRaw
    Set-TestArtifact $state 'findings' 'detect/../outside/findings.json'
    Assert-Throws { Write-GuiState -RunRoot $runRoot -State $state } 'nested traversal artifact path'
    $state = ConvertFrom-Json -InputObject $withArtifactRaw
    Set-TestArtifact $state 'findings' 'C:/outside/findings.json'
    Assert-Throws { Write-GuiState -RunRoot $runRoot -State $state } 'drive-root artifact path'

    $malformed = '{"schemaVersion":1,"runId":'
    [System.IO.File]::WriteAllText($target, $malformed, (New-Object System.Text.UTF8Encoding($false)))
    $state = ConvertFrom-Json -InputObject $withArtifactRaw
    Assert-Throws { Write-GuiState -RunRoot $runRoot -State $state } 'truncated prior state'
    Assert-True ((Get-CurrentRaw $target) -ceq $malformed) 'truncated prior file is not replaced by a candidate update'

    $duplicateCases = @(
        @{ Label = 'root member'; Search = '"runId": "' + $runId + '"'; Insert = ', "run\u0049d": "' + $runId + '"' },
        @{ Label = 'nested stage member'; Search = '"operation": "Producer interrupted"'; Insert = ', "oper\u0061tion": "ambiguous"' },
        @{ Label = 'nested artifacts member'; Search = '"findings": "detect/HOST_2026-09-23_120000/findings.json"'; Insert = ', "find\u0069ngs": "ambiguous.json"' }
    )
    foreach ($duplicateCase in $duplicateCases) {
        $duplicateRaw = $withArtifactRaw.Replace($duplicateCase.Search, $duplicateCase.Search + $duplicateCase.Insert)
        Assert-True ($duplicateRaw -cne $withArtifactRaw) "duplicate fixture inserts escaped key at $($duplicateCase.Label)"
        $duplicateBytes = [System.Text.Encoding]::UTF8.GetBytes($duplicateRaw)
        [System.IO.File]::WriteAllBytes($target, $duplicateBytes)
        Assert-Throws { Write-GuiState -RunRoot $runRoot -State $state } "decoded duplicate $($duplicateCase.Label)"
        Assert-BytesEqual $duplicateBytes ([System.IO.File]::ReadAllBytes($target)) "decoded duplicate $($duplicateCase.Label) rejection leaves prior bytes unchanged"
    }

    $firstWriteRoot = Join-Path $testRoot 'FIRST-WRITE'
    [void][System.IO.Directory]::CreateDirectory($firstWriteRoot)
    $unsafeFirst = New-GuiState -RunId 'FIRST-WRITE' -ComputerName 'HOST'
    $unsafeFirst.stages[0].status = 'Completed'
    Assert-Throws { Write-GuiState -RunRoot $firstWriteRoot -State $unsafeFirst } 'first publication cannot imply Completed'
    Assert-True (-not [System.IO.File]::Exists((Join-Path $firstWriteRoot 'gui-state.json'))) 'failed first publication leaves no partial final JSON'

    $blockerRoot = Join-Path $testRoot 'BLOCKED-WRITE'
    [void][System.IO.Directory]::CreateDirectory($blockerRoot)
    [void][System.IO.Directory]::CreateDirectory((Join-Path $blockerRoot 'gui-state.json'))
    $blockedState = New-GuiState -RunId 'BLOCKED-WRITE' -ComputerName 'HOST'
    Assert-Throws { Write-GuiState -RunRoot $blockerRoot -State $blockedState } 'directory cannot be replaced as state file'
    Assert-True ([System.IO.Directory]::Exists((Join-Path $blockerRoot 'gui-state.json'))) 'failed publication preserves existing non-file target'

    Write-Output "PASS: $script:Assertions assertions; atomic writer, schema, transitions, traversal, symlink, truncation, decoded duplicate members, and no-partial-file regressions."
} finally {
    if ([System.IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
