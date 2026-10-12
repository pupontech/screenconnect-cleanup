Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$adapterPath = Join-Path $repoRoot 'gui-bridge/Invoke-GuiStage.ps1'
$runnerPath = Join-Path $repoRoot 'sc-cleanup.ps1'
$stateLibraryPath = Join-Path $repoRoot 'gui-bridge/GuiState.ps1'
foreach ($path in @($adapterPath, $runnerPath, $stateLibraryPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing required file: $path" }
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "Parse failed for $path : $($parseErrors[0].Message)" }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) { throw "BOM is not allowed: $path" }
    foreach ($byte in $bytes) { if ($byte -gt 127) { throw "Non-ASCII byte found in $path" } }
}
. $adapterPath

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
function New-TestRequest {
    param([string]$Operation, [string]$RunId)
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        operation = $Operation
        runId = $RunId
        computerName = (Get-GuiLocalComputerName)
    }
}
function Read-TestState {
    param([string]$RunRoot)
    return ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $RunRoot 'gui-state.json'), [System.Text.Encoding]::UTF8))
}
function New-SyntheticExecutor {
    param([switch]$FailDetector, [switch]$IncompleteFindings)
    $failDetectorValue = [bool]$FailDetector
    $incompleteFindingsValue = [bool]$IncompleteFindings
    $computerName = Get-GuiLocalComputerName
    return {
        param($Stage, $RunRoot, $ScriptRoot)
        if ($Stage -eq 'SnapshotBefore') {
            [System.IO.File]::WriteAllText((Join-Path $RunRoot 'snapshot_before.json'), '{}', (New-Object System.Text.UTF8Encoding($false)))
            return 0
        }
        if ($Stage -eq 'Detect') {
            if ($failDetectorValue) { return 7 }
            $detectorRunId = $computerName + '_2026-09-23_120000'
            $detectRun = Join-Path (Join-Path $RunRoot 'detect') $detectorRunId
            [void][System.IO.Directory]::CreateDirectory($detectRun)
            $findings = [ordered]@{
                RunId = $detectorRunId
                ComputerName = $computerName
                CollectionComplete = (-not $incompleteFindingsValue)
                CollectionErrors = @()
                EventLogError = $null
                ScreenConnect = [ordered]@{ Instances = @(); ParseIssues = @() }
            }
            $findingsJson = ConvertTo-Json -InputObject $findings -Depth 5
            [System.IO.File]::WriteAllText((Join-Path $detectRun 'findings.json'), $findingsJson, (New-Object System.Text.UTF8Encoding($false)))
            return 0
        }
        throw 'Unexpected synthetic stage.'
    }.GetNewClosure()
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('gui-stage-tests-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($testRoot)
$parallelJobs = @()
try {
    $validRequest = New-TestRequest -Operation 'DetectOnly' -RunId 'GUI-TEST-DETECT'
    Assert-True ((Get-GuiRequestExpectedFields -Operation 'DetectOnly').Count -eq 4) 'DetectOnly requires only the four base request fields'
    Assert-Throws { Assert-GuiRequestFieldTypes -Request ([pscustomobject]@{ schemaVersion = 1; operation = 'RunAnything'; runId = 'RUN-1'; computerName = 'HOST' }) } 'unknown operation'

    $malformedPath = Join-Path $testRoot 'malformed.json'
    [System.IO.File]::WriteAllText($malformedPath, '{"schemaVersion":1,"operation":"RunAnything","runId":"BAD-1","computerName":"HOST"}', (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws { Read-GuiOperationRequest -Path $malformedPath } 'malformed operation value'
    [System.IO.File]::WriteAllText($malformedPath, '{"schemaVersion":1,"schemaVersion":1,"operation":"DetectOnly","runId":"BAD-2","computerName":"HOST"}', (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws { Read-GuiOperationRequest -Path $malformedPath } 'duplicate request property'
    [System.IO.File]::WriteAllText($malformedPath, '{"schemaVersion":1,"operation":"DetectOnly","oper\u0061tion":"FullInvestigation","runId":"BAD-ESCAPED-1","computerName":"HOST"}', (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws { Read-GuiOperationRequest -Path $malformedPath } 'escaped duplicate request property after literal spelling'
    [System.IO.File]::WriteAllText($malformedPath, '{"schemaVersion":1,"oper\u0061tion":"DetectOnly","operation":"FullInvestigation","runId":"BAD-ESCAPED-2","computerName":"HOST"}', (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws { Read-GuiOperationRequest -Path $malformedPath } 'escaped duplicate request property before literal spelling'
    [System.IO.File]::WriteAllText($malformedPath, '{"schemaVersion":1,"operation":"DetectOnly","runId":"BAD-3","computerName":"HOST","scriptPath":"remove.ps1"}', (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws { Read-GuiOperationRequest -Path $malformedPath } 'arbitrary script field'

    $approvalRequest = New-TestRequest -Operation 'FullInvestigation' -RunId 'GUI-TEST-APPROVAL'
    Add-Member -InputObject $approvalRequest -MemberType NoteProperty -Name decision -Value 'ApproveRemoval'
    Assert-Throws { Assert-GuiRequestFieldTypes -Request $approvalRequest } 'GUI request cannot carry removal approval'

    $runnerSource = [System.IO.File]::ReadAllText($runnerPath)
    Assert-True ($runnerSource.Contains("if (`$PSBoundParameters.ContainsKey('GuiRequestPath'))")) 'legacy runner enters GUI mode only when the new parameter is explicitly supplied'
    foreach ($legacyParameter in @('sa', 'sr', 'avu', 'np', 'offline', 'WhatIf', 'OutRoot', 'MinFreeGB')) {
        Assert-True ($runnerSource -match ('(?m)^\s*\$?' + [regex]::Escape($legacyParameter) + '\b|(?m)^\s*\[\w+\]\$' + [regex]::Escape($legacyParameter) + '\b')) "legacy CLI parameter $legacyParameter remains declared"
    }

    $detectRoot = Join-Path $testRoot 'detect-output'
    $detectRequest = New-TestRequest -Operation 'DetectOnly' -RunId 'GUI-TEST-DETECT'
    $detectRc = Invoke-GuiOperationRequest -Request $detectRequest -ConfiguredOutRoot $detectRoot -StageExecutor (New-SyntheticExecutor)
    $detectState = Read-TestState -RunRoot (Join-Path $detectRoot 'GUI-TEST-DETECT')
    Assert-True ($detectRc -eq 0) 'synthetic DetectOnly completes successfully'
    Assert-True (-not [System.IO.File]::Exists((Join-Path (Join-Path $detectRoot 'GUI-TEST-DETECT') 'snapshot_before.json'))) 'DetectOnly skips snapshot collection'
    Assert-True ($detectState.overallStatus -ceq 'Completed' -and $detectState.stages[2].status -ceq 'Completed') 'DetectOnly publishes completed detector state'
    Assert-True ($detectState.stages[4].status -ceq 'Skipped') 'DetectOnly cannot invoke the removal stage'
    Assert-True ($detectState.artifacts.findings -match '^detect/') 'DetectOnly publishes the run-relative findings artifact'

    $incompleteRoot = Join-Path $testRoot 'incomplete-output'
    $incompleteRequest = New-TestRequest -Operation 'DetectOnly' -RunId 'GUI-TEST-INCOMPLETE'
    $incompleteRc = Invoke-GuiOperationRequest -Request $incompleteRequest -ConfiguredOutRoot $incompleteRoot -StageExecutor (New-SyntheticExecutor -IncompleteFindings)
    $incompleteState = Read-TestState -RunRoot (Join-Path $incompleteRoot 'GUI-TEST-INCOMPLETE')
    Assert-True ($incompleteRc -eq 1) 'incomplete detector evidence returns nonzero'
    Assert-True ($incompleteState.overallStatus -ceq 'Incomplete' -and $incompleteState.stages[2].status -ceq 'Incomplete') 'missing collection proof cannot be shown as a completed clean run'

    $fullRoot = Join-Path $testRoot 'full-output'
    $fullRequest = New-TestRequest -Operation 'FullInvestigation' -RunId 'GUI-TEST-FULL'
    $fullRc = Invoke-GuiOperationRequest -Request $fullRequest -ConfiguredOutRoot $fullRoot -StageExecutor (New-SyntheticExecutor)
    $fullState = Read-TestState -RunRoot (Join-Path $fullRoot 'GUI-TEST-FULL')
    Assert-True ($fullRc -eq 10) 'FullInvestigation stops at the protected review boundary'
    Assert-True ([System.IO.File]::Exists((Join-Path (Join-Path $fullRoot 'GUI-TEST-FULL') 'snapshot_before.json'))) 'FullInvestigation executes the fixed read-only before snapshot'
    Assert-True ($fullState.overallStatus -ceq 'NeedsAction' -and $fullState.stages[3].status -ceq 'NeedsAction') 'FullInvestigation requires an explicit protected human review action'
    Assert-True ($fullState.stages[4].status -ceq 'Pending') 'FullInvestigation never enters removal without the protected gate'

    $failRoot = Join-Path $testRoot 'failure-output'
    $failRequest = New-TestRequest -Operation 'FullInvestigation' -RunId 'GUI-TEST-FAIL'
    $failRc = Invoke-GuiOperationRequest -Request $failRequest -ConfiguredOutRoot $failRoot -StageExecutor (New-SyntheticExecutor -FailDetector)
    $failState = Read-TestState -RunRoot (Join-Path $failRoot 'GUI-TEST-FAIL')
    Assert-True ($failRc -eq 1) 'synthetic detector failure returns nonzero'
    Assert-True ($failState.overallStatus -ceq 'Failed' -and $failState.stages[2].status -ceq 'Failed') 'stage failure is published as Failed, never Completed'
    Assert-True ($failState.stages[4].status -ceq 'Pending') 'stage failure does not continue to removal'

    $parallelRoot = Join-Path $testRoot 'parallel-output'
    $parallelReadyRoot = Join-Path $testRoot 'parallel-ready'
    $parallelStartedRoot = Join-Path $testRoot 'parallel-started'
    $parallelGate = Join-Path $testRoot 'parallel-start.gate'
    [void][System.IO.Directory]::CreateDirectory($parallelReadyRoot)
    [void][System.IO.Directory]::CreateDirectory($parallelStartedRoot)
    $parallelScript = {
        param($AdapterPath, $SyntheticOutputRoot, $RunId, $ComputerName, $Token, $ReadyRoot, $GatePath, $StartedRoot)
        . $AdapterPath
        [System.IO.File]::WriteAllText((Join-Path $ReadyRoot ($Token + '.ready')), 'ready', (New-Object System.Text.UTF8Encoding($false)))
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        while (-not [System.IO.File]::Exists($GatePath) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 20 }
        if (-not [System.IO.File]::Exists($GatePath)) { throw 'Parallel test start gate timed out.' }
        $request = [pscustomobject][ordered]@{ schemaVersion = 1; operation = 'DetectOnly'; runId = $RunId; computerName = $ComputerName }
        $executor = {
            param($Stage, $RunRoot, $ScriptRoot)
            [System.IO.File]::WriteAllText((Join-Path $StartedRoot ($Token + '.started')), 'started', (New-Object System.Text.UTF8Encoding($false)))
            Start-Sleep -Milliseconds 1000
            $detectorRunId = $ComputerName + '_2026-09-23_120000'
            $detectRun = Join-Path (Join-Path $RunRoot 'detect') $detectorRunId
            [void][System.IO.Directory]::CreateDirectory($detectRun)
            $findings = [ordered]@{
                RunId = $detectorRunId
                ComputerName = $ComputerName
                CollectionComplete = $true
                CollectionErrors = @()
                EventLogError = $null
                ScreenConnect = [ordered]@{ Instances = @(); ParseIssues = @() }
            }
            $findingsJson = ConvertTo-Json -InputObject $findings -Depth 5
            [System.IO.File]::WriteAllText((Join-Path $detectRun 'findings.json'), $findingsJson, (New-Object System.Text.UTF8Encoding($false)))
            return 0
        }.GetNewClosure()
        try {
            $result = Invoke-GuiOperationRequest -Request $request -ConfiguredOutRoot $SyntheticOutputRoot -StageExecutor $executor
            Write-Output ('completed:' + [int]$result)
        } catch {
            Write-Output 'rejected'
        }
    }
    for ($index = 1; $index -le 2; $index++) {
        $token = 'writer-' + $index
        $parallelJobs += Start-Job -ScriptBlock $parallelScript -ArgumentList @($adapterPath, $parallelRoot, 'GUI-TEST-PARALLEL', (Get-GuiLocalComputerName), $token, $parallelReadyRoot, $parallelGate, $parallelStartedRoot)
    }
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(20)
    while (@(Get-ChildItem -LiteralPath $parallelReadyRoot -Filter '*.ready' -File).Count -lt 2 -and [DateTime]::UtcNow -lt $readyDeadline) { Start-Sleep -Milliseconds 20 }
    if (@(Get-ChildItem -LiteralPath $parallelReadyRoot -Filter '*.ready' -File).Count -ne 2) { throw 'Parallel adapter workers did not reach the start barrier.' }
    [System.IO.File]::WriteAllText($parallelGate, 'start', (New-Object System.Text.UTF8Encoding($false)))
    [void](Wait-Job -Job $parallelJobs -Timeout 30)
    foreach ($parallelJob in $parallelJobs) {
        if ($parallelJob.State -notin @('Completed', 'Failed', 'Stopped')) { throw 'Parallel adapter worker did not complete.' }
    }
    $parallelResults = @()
    foreach ($parallelJob in $parallelJobs) { $parallelResults += @(Receive-Job -Job $parallelJob -ErrorAction SilentlyContinue) }
    $parallelSuccesses = @($parallelResults | Where-Object { [string]$_ -ceq 'completed:0' }).Count
    $parallelRejections = @($parallelResults | Where-Object { [string]$_ -ceq 'rejected' -or [string]$_ -ceq 'completed:1' }).Count
    $parallelStageStarts = @(Get-ChildItem -LiteralPath $parallelStartedRoot -Filter '*.started' -File).Count
    Assert-True ($parallelSuccesses -eq 1 -and $parallelRejections -eq 1) 'same-run parallel adapter invocation admits one owner and rejects the other'
    Assert-True ($parallelStageStarts -eq 1) 'same-run parallel invocation starts exactly one stage executor'
    $parallelState = Read-TestState -RunRoot (Join-Path $parallelRoot 'GUI-TEST-PARALLEL')
    Assert-True ($parallelState.overallStatus -ceq 'Completed') 'exclusive parallel owner publishes a complete run state'

    Write-Output "PASS: $script:Assertions assertions; strict request validation, safe stage boundary, atomic state integration, bounded failure, and legacy CLI parameter compatibility."
} finally {
    if ($parallelJobs.Count -gt 0) {
        $parallelJobs | Stop-Job -ErrorAction SilentlyContinue
        $parallelJobs | Remove-Job -Force -ErrorAction SilentlyContinue
    }
    if ([System.IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
