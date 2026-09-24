<#
  Bounded GUI adapter for the existing read-only investigation stages.
  Request data selects only a fixed operation; it cannot name scripts, arguments,
  paths, stdin answers, or destructive authorization.
  PowerShell 5.1 compatible. Pure ASCII, no BOM.
#>
[CmdletBinding()]
param(
    [string]$RequestPath,
    [string]$OutRoot,
    [switch]$ReturnExitCode
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$guiStateLibrary = Join-Path $PSScriptRoot 'GuiState.ps1'
if (-not (Test-Path -LiteralPath $guiStateLibrary -PathType Leaf)) { throw 'GUI state library is missing.' }
. $guiStateLibrary

$script:GuiRequestOperations = @(
    'DetectOnly', 'FullInvestigation', 'ContinueLowDisk', 'ContinueUacDisabled',
    'ReviewAllScreenConnect', 'DeclineRemoval', 'LaunchScanner', 'SkipScanner',
    'ApproveAvUninstall', 'SkipAvUninstall', 'AcknowledgeRestart', 'OpenExistingRun'
)
$script:GuiRequestMaxBytes = 65536
$script:GuiStageTimeoutMilliseconds = 900000

function Get-GuiRequestExpectedFields {
    param([Parameter(Mandatory = $true)][string]$Operation)

    $fields = @('schemaVersion', 'operation', 'runId', 'computerName')
    switch -CaseSensitive ($Operation) {
        'DetectOnly' { return ,$fields }
        'FullInvestigation' { return ,$fields }
        'ContinueLowDisk' { return ,($fields + 'decision') }
        'ContinueUacDisabled' { return ,($fields + 'decision') }
        'ReviewAllScreenConnect' { return ,($fields + 'findingsSha256') }
        'DeclineRemoval' { return ,($fields + @('findingsSha256', 'decision')) }
        'LaunchScanner' { return ,($fields + 'decision') }
        'SkipScanner' { return ,($fields + 'decision') }
        'ApproveAvUninstall' { return ,$fields }
        'SkipAvUninstall' { return ,$fields }
        'AcknowledgeRestart' { return ,$fields }
        'OpenExistingRun' { return ,$fields }
        default { throw 'Unsupported GUI operation.' }
    }
}

function Assert-GuiRequestFieldTypes {
    param([Parameter(Mandatory = $true)]$Request)

    $schemaVersion = Get-GuiStateField $Request 'schemaVersion'
    if (-not (Test-GuiStateInteger $schemaVersion) -or $schemaVersion -ne 1) { throw 'schemaVersion must be integer 1.' }

    $operation = Get-GuiStateField $Request 'operation'
    if ($operation -isnot [string] -or $script:GuiRequestOperations -cnotcontains $operation) { throw 'operation is not a recognized GUI operation.' }

    $runId = Get-GuiStateField $Request 'runId'
    if ($runId -isnot [string] -or $runId.Length -lt 1 -or $runId.Length -gt 128 -or $runId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $runId -ceq '.' -or $runId -ceq '..') {
        throw 'runId is invalid.'
    }

    $computerName = Get-GuiStateField $Request 'computerName'
    if ($computerName -isnot [string] -or $computerName.Length -lt 1 -or $computerName.Length -gt 63 -or $computerName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'computerName is invalid.'
    }

    $fieldNames = Get-GuiStateFieldNames $Request
    $expectedFields = Get-GuiRequestExpectedFields -Operation $operation
    Assert-GuiStateFields -InputObject $Request -Expected $expectedFields -Label 'GUI request'

    if ($fieldNames -ccontains 'findingsSha256') {
        $digest = Get-GuiStateField $Request 'findingsSha256'
        if ($digest -isnot [string] -or $digest -cnotmatch '^[A-Fa-f0-9]{64}$') { throw 'findingsSha256 must be a 64-character SHA-256 hex digest.' }
    }
    if ($fieldNames -ccontains 'decision') {
        $decision = Get-GuiStateField $Request 'decision'
        if ($decision -isnot [string]) { throw 'decision must be a string.' }
        $validDecisions = switch -CaseSensitive ($operation) {
            'ContinueLowDisk' { @('ContinueLowDisk') }
            'ContinueUacDisabled' { @('ContinueUacDisabled') }
            'DeclineRemoval' { @('DeclineRemoval') }
            'LaunchScanner' { @('KVRT', 'ESET', 'Malwarebytes') }
            'SkipScanner' { @('KVRT', 'ESET', 'Malwarebytes') }
            default { @() }
        }
        if ($validDecisions -cnotcontains $decision) { throw 'decision is not valid for this GUI operation.' }
    }
    return $Request
}

function Read-GuiOperationRequest {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    [void](Assert-GuiStateNoReparsePath -Path $fullPath)
    $attributes = Get-GuiStatePathAttributes -Path $fullPath
    if ($null -eq $attributes -or ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) { throw 'GUI request file does not exist or is not a regular file.' }
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'GUI request file cannot be a reparse point.' }
    if ((New-Object System.IO.FileInfo($fullPath)).Length -gt $script:GuiRequestMaxBytes) { throw 'GUI request exceeds the size limit.' }

    $bytes = [System.IO.File]::ReadAllBytes($fullPath)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) { throw 'GUI request must be UTF-8 without a BOM.' }
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $rawJson = $encoding.GetString($bytes)
    } catch {
        throw 'GUI request is not valid UTF-8.'
    }
    if ([string]::IsNullOrWhiteSpace($rawJson)) { throw 'GUI request is empty.' }
    Assert-GuiJsonNoDuplicateMembers -Json $rawJson
    try {
        $request = ConvertFrom-Json -InputObject $rawJson -ErrorAction Stop
    } catch {
        throw 'GUI request is malformed JSON.'
    }
    if ($null -eq $request -or $request -is [System.Array] -or $request -is [string]) { throw 'GUI request root must be an object.' }

    return Assert-GuiRequestFieldTypes -Request $request
}

function Get-GuiLocalComputerName {
    $name = $env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $env:HOSTNAME }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = [System.Net.Dns]::GetHostName() }
    return [string]$name
}

function Test-GuiProcessElevated {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-GuiPowerShellHost {
    if ($env:OS -eq 'Windows_NT' -or $PSVersionTable.PSEdition -eq 'Desktop') {
        $hostCommand = Get-Command powershell.exe -ErrorAction SilentlyContinue
        if ($null -eq $hostCommand) { throw 'Windows PowerShell 5.1 is required for GUI stage execution.' }
        return [string]$hostCommand.Source
    }
    throw 'GUI stage execution is supported only on Windows PowerShell 5.1.'
}

function ConvertTo-GuiWindowsArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    for ($index = 0; $index -lt $Value.Length; $index++) {
        $character = $Value[$index]
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            if ($slashes -gt 0) { [void]$builder.Append(('\' * (2 * $slashes + 1))) }
            else { [void]$builder.Append('\') }
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)) }
        [void]$builder.Append($character)
        $slashes = 0
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * (2 * $slashes))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-GuiStageProcess {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('SnapshotBefore', 'Detect')][string]$Stage,
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$ScriptRoot
    )

    if ($Stage -eq 'Detect' -and (Test-GuiProcessElevated)) { throw 'DetectOnly must run from a non-elevated process.' }
    $hostPath = Get-GuiPowerShellHost
    $scriptPath = if ($Stage -eq 'SnapshotBefore') { Join-Path $ScriptRoot 'collect-snapshot.ps1' } else { Join-Path $ScriptRoot 'detect-remote-access.ps1' }
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { throw 'Fixed investigation stage script is missing.' }

    if ($Stage -eq 'SnapshotBefore') {
        $snapshotPath = Join-Path $RunRoot 'snapshot_before.json'
        $childArguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath,
            '-Label', 'before', '-IncidentWindowDays', '0', '-OutFile', $snapshotPath, '-Quiet', '-NoParallel')
    } else {
        $detectRoot = Join-Path $RunRoot 'detect'
        $childArguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath,
            '-OutRoot', $detectRoot, '-NoPause', '-NoZip', '-NoReportShare', '-TranscriptCopyDir', $RunRoot)
    }

    $quotedArguments = @()
    foreach ($argument in $childArguments) { $quotedArguments += (ConvertTo-GuiWindowsArgument -Value ([string]$argument)) }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $hostPath
    $startInfo.Arguments = $quotedArguments -join ' '
    $startInfo.WorkingDirectory = $ScriptRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $false

    $process = $null
    try {
        $process = [System.Diagnostics.Process]::Start($startInfo)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($script:GuiStageTimeoutMilliseconds)) {
            try { $process.Kill() } catch { }
            $process.WaitForExit()
            return 124
        }
        [void]$stdoutTask.Result
        [void]$stderrTask.Result
        return [int]$process.ExitCode
    } catch {
        throw 'Fixed investigation stage process could not complete.'
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Get-GuiRelativeArtifactPath {
    param(
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$FullPath
    )

    $rootFull = [System.IO.Path]::GetFullPath($RunRoot).TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
    $fileFull = [System.IO.Path]::GetFullPath($FullPath)
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    $comparison = if ($env:OS -eq 'Windows_NT') { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not $fileFull.StartsWith($prefix, $comparison)) { throw 'Stage artifact escaped the run directory.' }
    [void](Assert-GuiStateNoReparsePath -Path $fileFull)
    return $fileFull.Substring($prefix.Length).Replace([System.IO.Path]::DirectorySeparatorChar, '/')
}

function Find-GuiFindingsArtifact {
    param([Parameter(Mandatory = $true)][string]$RunRoot)

    $detectRoot = Join-Path $RunRoot 'detect'
    if (-not [System.IO.Directory]::Exists($detectRoot)) { throw 'Detector did not create its output directory.' }
    $findings = @(Get-ChildItem -LiteralPath $detectRoot -Filter 'findings.json' -File -Recurse -ErrorAction Stop)
    if ($findings.Count -ne 1) { throw 'Detector did not produce exactly one findings.json artifact.' }
    return Get-GuiRelativeArtifactPath -RunRoot $RunRoot -FullPath $findings[0].FullName
}

function Get-GuiFindingsAssessment {
    param(
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$ComputerName
    )

    $separator = [System.IO.Path]::DirectorySeparatorChar
    $platformPath = $RelativePath.Replace('/', $separator)
    $findingsPath = [System.IO.Path]::Combine($RunRoot, $platformPath)
    $detectorRunId = [System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName($findingsPath))
    try {
        $findings = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($findingsPath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
        $runIdProperty = $findings.PSObject.Properties['RunId']
        $computerProperty = $findings.PSObject.Properties['ComputerName']
        $completeProperty = $findings.PSObject.Properties['CollectionComplete']
        $collectionErrorsProperty = $findings.PSObject.Properties['CollectionErrors']
        $eventErrorProperty = $findings.PSObject.Properties['EventLogError']
        $screenConnectProperty = $findings.PSObject.Properties['ScreenConnect']
        if (-not $runIdProperty -or $runIdProperty.Value -isnot [string] -or $runIdProperty.Value -cne $detectorRunId) {
            return [pscustomobject]@{ IsComplete = $false; Reason = 'Findings run identity does not match its detector directory.' }
        }
        if (-not $computerProperty -or $computerProperty.Value -isnot [string] -or -not [string]::Equals($computerProperty.Value, $ComputerName, [StringComparison]::OrdinalIgnoreCase)) {
            return [pscustomobject]@{ IsComplete = $false; Reason = 'Findings computer identity does not match the current run.' }
        }
        if (-not $completeProperty -or $completeProperty.Value -isnot [bool] -or -not $completeProperty.Value) {
            return [pscustomobject]@{ IsComplete = $false; Reason = 'Detector collection is not confirmed complete.' }
        }
        if (-not $collectionErrorsProperty -or $collectionErrorsProperty.Value -isnot [System.Array] -or $collectionErrorsProperty.Value.Count -gt 0) {
            return [pscustomobject]@{ IsComplete = $false; Reason = 'Detector reported collection errors or omitted the error list.' }
        }
        if ($eventErrorProperty -and -not [string]::IsNullOrWhiteSpace([string]$eventErrorProperty.Value)) {
            return [pscustomobject]@{ IsComplete = $false; Reason = 'Detector event-log collection is incomplete.' }
        }
        if (-not $screenConnectProperty -or $null -eq $screenConnectProperty.Value) {
            return [pscustomobject]@{ IsComplete = $false; Reason = 'Detector omitted the ScreenConnect result.' }
        }
        $instancesProperty = $screenConnectProperty.Value.PSObject.Properties['Instances']
        $parseIssuesProperty = $screenConnectProperty.Value.PSObject.Properties['ParseIssues']
        if (-not $instancesProperty -or $instancesProperty.Value -isnot [System.Array]) {
            return [pscustomobject]@{ IsComplete = $false; Reason = 'ScreenConnect instances are missing or malformed.' }
        }
        if (-not $parseIssuesProperty -or $parseIssuesProperty.Value -isnot [System.Array] -or $parseIssuesProperty.Value.Count -gt 0) {
            return [pscustomobject]@{ IsComplete = $false; Reason = 'ScreenConnect parsing is incomplete or reported issues.' }
        }
        return [pscustomobject]@{ IsComplete = $true; Reason = '' }
    } catch {
        return [pscustomobject]@{ IsComplete = $false; Reason = 'Findings JSON is malformed or could not be read.' }
    }
}

function Set-GuiStageState {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][ValidateRange(0, 9)][int]$StageId,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Operation
    )

    $stage = $State.stages[$StageId]
    $now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    if ($Status -ceq 'Running') {
        $stage.startedUtc = $now
        $stage.endedUtc = $null
        $State.currentStage = $StageId
    } elseif ($Status -in @('Completed', 'Warning', 'Failed', 'NeedsAction', 'Incomplete')) {
        if ($null -eq $stage.startedUtc) { $stage.startedUtc = $now }
        $stage.endedUtc = $now
        $State.currentStage = $StageId
    }
    $stage.status = $Status
    $stage.operation = $Operation
    $State.updatedUtc = $now
}

function Set-GuiOverallStatus {
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$Status)
    $State.overallStatus = $Status
    $State.updatedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Set-GuiUnvisitedStagesSkipped {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][int]$FirstStage,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    for ($index = $FirstStage; $index -lt 10; $index++) {
        if ($State.stages[$index].status -ceq 'Pending') {
            Set-GuiStageState -State $State -StageId $index -Status 'Skipped' -Operation $Reason
        }
    }
}

function Publish-GuiStateUpdate {
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$RunRoot)
    $State.updatedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    [void](Write-GuiState -RunRoot $RunRoot -State $State)
}

function Invoke-GuiOperationRequest {
    param(
        [Parameter(Mandatory = $true)]$Request,
        [Parameter(Mandatory = $true)][string]$ConfiguredOutRoot,
        [scriptblock]$StageExecutor
    )

    $validated = Assert-GuiRequestFieldTypes -Request $Request
    $operation = [string](Get-GuiStateField $validated 'operation')
    if ($operation -cnotin @('DetectOnly', 'FullInvestigation')) { throw 'This GUI operation is validated but not implemented by the bounded adapter.' }
    if ($null -eq $StageExecutor) {
        if ($env:OS -ne 'Windows_NT' -and $PSVersionTable.PSEdition -ne 'Desktop') { throw 'GUI stage execution is supported only on Windows PowerShell 5.1.' }
        if (Test-GuiProcessElevated) { throw 'GUI investigation must run from a non-elevated process.' }
    }

    $localComputer = Get-GuiLocalComputerName
    $requestedComputer = [string](Get-GuiStateField $validated 'computerName')
    if (-not [string]::Equals($localComputer, $requestedComputer, [StringComparison]::OrdinalIgnoreCase)) { throw 'Request computerName does not match this computer.' }

    $outRoot = if ([string]::IsNullOrWhiteSpace($ConfiguredOutRoot)) { 'C:\RIT-SCC' } else { $ConfiguredOutRoot }
    $fullOutRoot = [System.IO.Path]::GetFullPath($outRoot)
    [void](Assert-GuiStateNoReparsePath -Path $fullOutRoot)
    if (-not [System.IO.Directory]::Exists($fullOutRoot)) { [void][System.IO.Directory]::CreateDirectory($fullOutRoot) }
    [void](Assert-GuiStateNoReparsePath -Path $fullOutRoot -RequireDirectory)

    $runId = [string](Get-GuiStateField $validated 'runId')
    $runRoot = [System.IO.Path]::Combine($fullOutRoot, $runId)
    if ([System.IO.Directory]::Exists($runRoot) -or [System.IO.File]::Exists($runRoot)) { throw 'runId already exists under the configured output root.' }

    $runClaim = $null
    try {
        $claimPath = Join-Path $fullOutRoot ('.gui-run-' + $runId + '.claim')
        try {
            # CreateNew is the cross-process exclusive claim. Keep the marker permanently:
            # it reserves this runId even after a crash, so no later writer can take it over.
            $runClaim = [System.IO.File]::Open($claimPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        } catch {
            throw 'runId is already claimed or reserved under the configured output root.'
        }
        if ([System.IO.Directory]::Exists($runRoot) -or [System.IO.File]::Exists($runRoot)) { throw 'runId already exists under the configured output root.' }
        [void][System.IO.Directory]::CreateDirectory($runRoot)
        [void](Assert-GuiStateNoReparsePath -Path $runRoot -RequireDirectory)
        if ((Get-GuiStateRootLeaf $runRoot) -cne $runId) { throw 'Created run directory does not match runId.' }

        $state = New-GuiState -RunId $runId -ComputerName $requestedComputer
        [void](Write-GuiState -RunRoot $runRoot -State $state)
        $scriptRoot = Split-Path -Parent $PSScriptRoot
        $currentStage = $null

        try {
        Set-GuiOverallStatus -State $state -Status 'Running'
        Set-GuiStageState -State $state -StageId 0 -Status 'Skipped' -Operation 'Interactive preflight is outside the bounded GUI adapter.'
        if ($operation -ceq 'DetectOnly') {
            Set-GuiStageState -State $state -StageId 1 -Status 'Skipped' -Operation 'DetectOnly does not collect investigation snapshots.'
            Set-GuiStageState -State $state -StageId 2 -Status 'Running' -Operation 'Running the fixed read-only detector.'
            Set-GuiUnvisitedStagesSkipped -State $state -FirstStage 3 -Reason 'Not run by DetectOnly.'
            $currentStage = 2
        } else {
            Set-GuiStageState -State $state -StageId 1 -Status 'Running' -Operation 'Collecting the fixed read-only before snapshot.'
            $currentStage = 1
        }
        Publish-GuiStateUpdate -State $state -RunRoot $runRoot

        if ($operation -ceq 'FullInvestigation') {
            $snapshotExit = if ($null -ne $StageExecutor) { & $StageExecutor 'SnapshotBefore' $runRoot $scriptRoot } else { Invoke-GuiStageProcess -Stage SnapshotBefore -RunRoot $runRoot -ScriptRoot $scriptRoot }
            if ([int]$snapshotExit -ne 0) {
                Set-GuiStageState -State $state -StageId 1 -Status 'Failed' -Operation 'Before snapshot failed; no later stage was started.'
                Set-GuiUnvisitedStagesSkipped -State $state -FirstStage 2 -Reason 'Skipped after before-snapshot failure.'
                $state.errors = @('Before snapshot stage failed or timed out.')
                Set-GuiOverallStatus -State $state -Status 'Failed'
                $state.currentStage = $null
                Publish-GuiStateUpdate -State $state -RunRoot $runRoot
                return 1
            }
            $snapshotPath = Join-Path $runRoot 'snapshot_before.json'
            if (-not [System.IO.File]::Exists($snapshotPath)) { throw 'Before snapshot process succeeded without its required artifact.' }
            $state.artifacts['beforeSnapshot'] = Get-GuiRelativeArtifactPath -RunRoot $runRoot -FullPath $snapshotPath
            Set-GuiStageState -State $state -StageId 1 -Status 'Completed' -Operation 'Before snapshot completed.'
            Set-GuiStageState -State $state -StageId 2 -Status 'Running' -Operation 'Running the fixed read-only detector.'
            $currentStage = 2
            Publish-GuiStateUpdate -State $state -RunRoot $runRoot
        }

        $detectExit = if ($null -ne $StageExecutor) { & $StageExecutor 'Detect' $runRoot $scriptRoot } else { Invoke-GuiStageProcess -Stage Detect -RunRoot $runRoot -ScriptRoot $scriptRoot }
        if ([int]$detectExit -ne 0) {
            Set-GuiStageState -State $state -StageId 2 -Status 'Failed' -Operation 'Detector failed or timed out.'
            $state.errors = @('Detector stage failed or timed out.')
            Set-GuiOverallStatus -State $state -Status 'Failed'
            $state.currentStage = $null
            Publish-GuiStateUpdate -State $state -RunRoot $runRoot
            return 1
        }
        $findingsPath = Find-GuiFindingsArtifact -RunRoot $runRoot
        $state.artifacts['findings'] = $findingsPath
        $findingsAssessment = Get-GuiFindingsAssessment -RunRoot $runRoot -RelativePath $findingsPath -ComputerName $requestedComputer
        if (-not $findingsAssessment.IsComplete) {
            Set-GuiStageState -State $state -StageId 2 -Status 'Incomplete' -Operation $findingsAssessment.Reason
            $state.errors = @($findingsAssessment.Reason)
            Set-GuiOverallStatus -State $state -Status 'Incomplete'
            $state.currentStage = $null
            Publish-GuiStateUpdate -State $state -RunRoot $runRoot
            return 1
        }
        Set-GuiStageState -State $state -StageId 2 -Status 'Completed' -Operation 'Read-only detector completed.'
        if ($operation -ceq 'DetectOnly') {
            Set-GuiOverallStatus -State $state -Status 'Completed'
            $state.currentStage = $null
            Publish-GuiStateUpdate -State $state -RunRoot $runRoot
            return 0
        }

        Set-GuiStageState -State $state -StageId 3 -Status 'Running' -Operation 'Full investigation paused at the technician review gate.'
        $currentStage = 3
        Publish-GuiStateUpdate -State $state -RunRoot $runRoot
        Set-GuiStageState -State $state -StageId 3 -Status 'NeedsAction' -Operation 'Protected review and removal authorization are not implemented by this adapter.'
        $state.warnings = @('No GUI request authorizes removal. Continue only through a protected human review endpoint.')
        Set-GuiOverallStatus -State $state -Status 'NeedsAction'
        $state.currentStage = 3
        Publish-GuiStateUpdate -State $state -RunRoot $runRoot
        return 10
        } catch {
            if ($null -ne $state) {
                try {
                    if ($null -ne $currentStage -and $state.stages[$currentStage].status -ceq 'Running') {
                        Set-GuiStageState -State $state -StageId $currentStage -Status 'Failed' -Operation 'Stage failed with a contained adapter error.'
                    }
                    $state.errors = @('GUI adapter failed; run state is incomplete.')
                    Set-GuiOverallStatus -State $state -Status 'Failed'
                    $state.currentStage = $null
                    Publish-GuiStateUpdate -State $state -RunRoot $runRoot
                } catch { }
            }
            return 1
        }
    } finally {
        if ($null -ne $runClaim) { $runClaim.Dispose() }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = 2
    try {
        if ([string]::IsNullOrWhiteSpace($RequestPath)) { throw 'RequestPath is required.' }
        $request = Read-GuiOperationRequest -Path $RequestPath
        $configuredOutRoot = if ([string]::IsNullOrWhiteSpace($OutRoot)) { 'C:\RIT-SCC' } else { $OutRoot }
        $exitCode = Invoke-GuiOperationRequest -Request $request -ConfiguredOutRoot $configuredOutRoot
    } catch {
        [Console]::Error.WriteLine('GUI adapter rejected the request or could not start safely.')
    }
    if ($ReturnExitCode) { return [int]$exitCode }
    exit [int]$exitCode
}
