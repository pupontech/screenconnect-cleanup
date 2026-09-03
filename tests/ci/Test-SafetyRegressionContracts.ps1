# Test-SafetyRegressionContracts.ps1 - regression contracts for the safety audit.
# Source/behavior checks are intentionally non-destructive and PS 5.1 compatible.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$failures = @()

function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host ("PASS: " + $Name) }
    else {
        $script:failures += ("FAIL: " + $Name + $(if ($Detail) { " - " + $Detail } else { '' }))
        Write-Host $script:failures[-1] -ForegroundColor Red
    }
}

function Read-Source {
    param([string]$Name)
    return [System.IO.File]::ReadAllText((Join-Path $repoRoot $Name))
}

$start = Read-Source 'START-HERE.bat'
$lab = Read-Source 'RUN-REMOVAL-TEST.bat'
$cleanup = Read-Source 'sc-cleanup.ps1'
$preflight = Read-Source 'preflight.ps1'
$remover = Read-Source 'remove-screenconnect.ps1'
$review = Read-Source 'Invoke-ReviewAndRemove.ps1'
$av = Read-Source 'Invoke-AVUninstaller.ps1'
$scanner = Read-Source 'Invoke-GUIScanner.ps1'
$toolPack = Read-Source 'tools/Get-ToolPack.ps1'
$diff = Read-Source 'diff-snapshots.ps1'
$detector = Read-Source 'detect-remote-access.ps1'
$collect = Read-Source 'collect-snapshot.ps1'
$report = Read-Source 'New-InvestigationReport.ps1'

Check 'guided launcher gates baseline snapshot failure before removal' (($start -match 'before_snapshot_failed') -and ($start -match 'if errorlevel 1 goto :before_snapshot_failed'))
Check 'guided launcher gates preflight failure before removal' (($start -match '(?i)if errorlevel 1 .*preflight') -and ($start -match '(?i)preflight_failed'))
Check 'guided launcher does not search historical findings for automatic removal' ($start -notmatch '(?i)dir /b /ad /o-d.*RemoteAccessScan')
Check 'guided launcher disables automatic approval' (($start -notmatch '(?i)Invoke-ReviewAndRemove\.ps1[^\r\n]*-Yes') -and ($review -match 'automatic approval is disabled'))
Check 'guided launcher binds removal to a current-run findings path' (($start -match 'SCC_RUN') -and ($start -match 'findings\.json'))
Check 'guided launcher forwards current run root to review/removal' ($start -match '(?i)Invoke-ReviewAndRemove\.ps1[^\r\n]*-WorkDir[^\r\n]*SCC_RUN_ROOT')
Check 'guided preflight receives current run root' ($start -match '(?i)preflight\.ps1[^\r\n]*-WorkingRoot[^\r\n]*SCC_RUN_ROOT')
Check 'preflight checks the WorkingRoot volume' ($preflight -match '(?i)GetPathRoot')
$guidedReviewBlock = [regex]::Match($start, '(?is)if defined FINDINGS_JSON.*?\) else \(').Value
Check 'guided launcher preserves after-evidence after removal failure' (($guidedReviewBlock -match '(?i)REMOVE_RC') -and ($guidedReviewBlock -notmatch '(?i)goto :removal_failed'))
Check 'lab removal launcher returns pipeline exit code' (($lab -match '(?i)set "PIPE_RC=%ERRORLEVEL%"') -and ($lab -match '(?i)exit /b %PIPE_RC%'))
$blankUacToY = 'IsNullOrWhiteSpace\(\$uacInput\)\s*\}\s*\$uacInput\s*=\s*[''\"]Y'
Check 'disabled-UAC blank input is not treated as affirmative' (($cleanup -notmatch $blankUacToY) -and ($preflight -notmatch $blankUacToY) -and ($cleanup -match '(?i)UAC confirmation') -and ($preflight -match '(?i)UAC confirmation'))
Check 'low-space gates default to 10 GB' (($cleanup -match '(?m)\[int\]\$MinFreeGB\s*=\s*10') -and ($preflight -match '(?m)\[int\]\$MinFreeGB\s*=\s*10') -and ($review -match '(?m)\[int\]\$MinFreeGB\s*=\s*10'))
Check 'preflight treats registry export failure as failure' (($preflight -match 'Export-RegistryHives') -and ($preflight -match 'Write-StageFail.*export'))
Check 'direct destructive pipeline fails closed when not elevated' (($cleanup -match '(?s)if \(-not \$isAdmin\).*?ExecuteRemoval') -or ($cleanup -match '(?s)if \(-not \$isAdmin\).*?exit 1'))
Check 'remover requires approved plan confirmation/provenance' (($remover -match 'RemovalConfirmed') -and ($remover -match 'SourceFindings') -and ($remover -match '(?i)provenance') -and ($remover -match 'SourceFindingsSha256') -and ($remover -match 'current computer'))
Check 'detector emits a run binding' (($detector -match 'RunId') -and ($detector -match 'detect-remote-access\.ps1'))
Check 'remover validates quarantine containment' (($remover -match 'Test-PathContained') -or ($remover -match 'canonical.*quarantine') -or ($remover -match 'GetFullPath'))
$rawAuxiliaryInstancePaths = ($remover.Contains("quarantine-hashes-' + `$InstanceId") -or $remover.Contains("uninstall-key-' + `$instanceId"))
Check 'instance IDs are sanitized before auxiliary filenames' ((-not $rawAuxiliaryInstancePaths) -and ($remover -match 'Get-SafeInstanceFileStem'))
Check 'preflight native registry exports do not merge stderr under Stop' ($cleanup -notmatch '(?m)reg\.exe\s+export[^\r\n]*2>&1')
Check 'no-restore-point flag does not waive registry export failure' (($cleanup -match '\$script:RegistryExportFailed') -and ($cleanup -match '\$script:RegistryExportFailed\s*-or') -and ($cleanup -match '\(\$script:RestorePointFailed\s*-and\s*-not\s*\$np\)'))
Check 'quarantine failure gates service and registry surgery' ($remover -match 'quarantineSucceeded')
Check 'quarantine applies restrictive ACLs' ($remover -match 'Set-Acl')
Check 'deferred quarantine is RebootPending' (($remover -match 'DeferredQuarantineInstanceIds') -and ($remover -match 'RebootPending') -and ($remover -match "Result 'Deferred'"))
$rebootResumeGateIndex = $remover.IndexOf('$isRebootPendingResume')
$priorIdentityIndex = $remover.IndexOf('PriorVerifiedInstanceIds')
$liveIdentityCheckIndex = $remover.IndexOf('$verification = Test-ScreenConnectInstance')
$rebootResumeBranchIndex = $remover.IndexOf('if ($isRebootPendingResume) {', $liveIdentityCheckIndex)
Check 'reboot-pending action branch uses the guarded resume proof' (($rebootResumeBranchIndex -ge 0) -and ($rebootResumeBranchIndex -gt $liveIdentityCheckIndex))
Check 'RunOnce registration failure is returned to caller' (($remover -match 'Set-RunOnceResume.*\$false') -or ($remover -match 'return \$false'))
Check 'AV uninstaller does not execute raw registry strings through cmd shell' ($av -notmatch "FileName\s*=\s*'cmd\.exe'")
Check 'AV leftovers validate InstallLocation containment' (($av -match 'Test-PathContained') -or ($av -match 'canonical.*ProgramFiles'))
Check 'scanner launch failure is not Completed' (($scanner -match "LaunchFailed") -and ($scanner -match 'mbam\.exe'))
Check 'tool pack enforces each declared expected executable' (($toolPack -match 'ExesToCheck') -and ($toolPack -match 'expected.*exe|Expected.*file|Missing.*ExesToCheck'))
Check 'diff does not treat forensic history additions as resurrection' (($diff -notmatch "'Prefetch'.*'ShimCache'.*'BamDam'.*'UserAssist'.*'Amcache'") -or ($diff -match 'informational|forensic'))
Check 'diff compares changed fields without pipeline array flattening' (($diff -match 'ConvertTo-Json') -and ($diff -match 'InputObject'))
Check 'diff fails closed on incomplete collections' (($diff -match 'CollectionComplete') -and ($diff -match "Verdict.*INCOMPLETE") -and ($diff -match 'BeforeCollectionErrors') -and ($diff -match 'AfterCollectionErrors'))
Check 'Srum diff ignores timestamped offline-copy path' (($diff -match 'Get-ObjectCompareValue') -and ($diff -match 'DatabaseSha256') -and ($diff -notmatch 'OfflineCopyPath.*Get-ComparableJson'))
Check 'report accepts and renders the snapshot diff' (($report -match '\[string\]\$DiffPath') -and ($report -match 'snapshot-diff') -and ($report -match 'DiffPath'))
Check 'stage 9 passes the stage 8 diff to the report' (($cleanup -match "-DiffPath") -and ($cleanup -match 'reportDiffPath'))
Check 'incomplete diff propagates to pipeline outcome' (($cleanup -match 'DiffIncomplete') -and ($cleanup -match 'diffIncomplete') -and ($cleanup -match 'pipelineIncomplete'))
Check 'report receives the removal manifest when it exists' ($cleanup -match 'RemovalManifest')
Check 'summary counts normalize singleton and empty JSON values' (($cleanup -match 'screenInstances = Get-JsonItems') -and ($cleanup -match 'Get-PropertyValue.*Hits') -and ($cleanup -match 'SCInstanceCount') -and ($cleanup -match 'OtherHitTotal'))
Check 'Windows child stages use Windows PowerShell 5.1 on Windows' (($cleanup -match 'PSEdition') -and ($cleanup -match 'powershell.exe'))
$psiInitIndex = $cleanup.IndexOf('$psi = New-Object System.Diagnostics.ProcessStartInfo')
$psiUseIndex = $cleanup.IndexOf('$psi.FileName =')
Check 'child process runner constructs ProcessStartInfo before use' ($psiInitIndex -ge 0 -and $psiInitIndex -lt $psiUseIndex)
Check 'tool staging helpers run in isolated child processes' (($cleanup -match 'Invoke-ChildScript -ScriptPath \$getToolPack') -and ($cleanup -match 'Invoke-ChildScript -ScriptPath \$getAvTools') -and ($cleanup -notmatch '(?m)^\s*& \$getToolPack') -and ($cleanup -notmatch '(?m)^\s*& \$getAvTools'))
Check 'guided wrapper runs remover out of process' (($review -match '(?i)powershell\.exe') -and ($review -match '(?i)-File') -and ($review -notmatch '(?m)^\s*& \$remover'))
$executePathFields = "foreach (`$pn in @('ImagePath', 'ServiceImagePath', 'InstallDir', 'MainExe', 'File'))"
Check 'execute signature gate includes detector MainExe evidence' ($remover.Contains($executePathFields) -and ($remover -match 'Get-PathBinaryPath'))
Check 'resume task names use collision-safe instance stems' (($remover.Contains('$safeTaskId = Get-SafeInstanceFileStem -InstanceId $InstanceId')) -and ($remover.Contains('Get-SafeInstanceFileStem -InstanceId $InstanceId')))
Check 'plan uninstall keys are constrained to uninstall roots' (($remover -match 'Test-AllowedUninstallRegistryPath') -and ($remover -match 'WOW6432Node.*CurrentVersion.*Uninstall') -and ($remover -match 'HKCU.*CurrentVersion.*Uninstall'))
Check 'uninstaller executable uses canonical install containment' (($remover -match 'Test-PathContained -Root \$installDir') -and (-not $remover.Contains('$bareExe.StartsWith($installDir')))
Check 'process targeting uses literal canonical install containment' (($remover -match 'Test-PathContained -Root \$expandedInstallDir') -and ($remover -notmatch '(?m)ExecutablePath[^\r\n]*-like'))
Check 'all persistence cleanup path references are literal' (($remover -match 'Test-LiteralPathReference') -and ($remover -notmatch '\$InstallDir\\\*') -and ($remover -notmatch '\*\$InstallDir\*'))
Check 'path containment rejects reparse points' (($remover -match 'FileAttributes\]::ReparsePoint') -and ($remover -match 'Test-PathContained') -and ($remover -match 'Refusing to quarantine tree containing'))
Check 'moved quarantine payload ACLs are recursively verified' (($remover -match 'Protect-QuarantinePathAcl -Path \$destPath') -and ($remover -match 'Get-ChildItem -LiteralPath \$Path -Recurse') -and ($remover -match 'AreAccessRulesProtected'))
Check 'deferred quarantine records structured identity fields' (($remover -match 'SourceIdentity') -and ($remover -match 'Get-PathIdentityHash -Path \$resumeDest') -and ($remover -match 'identity mismatch'))
Check 'quarantine verifies identity after move' (($remover -match 'destinationIdentity') -and ($remover -match 'Post-move identity mismatch') -and ($remover -match 'Get-PathIdentityHash -Path \$destPath'))
Check 'failed resume registration cancels delayed move' (($remover -match 'pending move cancelled') -and ($remover -match 'MoveFileEx\(\$SourcePath, \$null'))
Check 'successful vendor uninstall requires postconditions' (($remover -match 'UninstallPostcondition') -and ($remover -match 'install directory remains') -and ($remover -match 'service.*remains'))
Check 'resume requires script and plan hash identity' (($remover -match 'ScriptHash') -and ($remover -match 'PlanHash') -and ($remover -match 'ResumeMarkerIdentityFailed'))
Check 'BAM/DAM uses a native full registry key path for timestamps' (($collect -match 'nativeKeyPath') -and ($collect -match 'GetLastWriteUtc'))
Check 'BAM/DAM uses value names for paths and decodes binary FILETIME' (($collect -match 'ProgramPath\s*=\s*\$progPath') -and ($collect -match 'Convert-BamFileTime') -and ($collect -match 'LastExecutionUtc') -and ($collect -match 'ValueDataHex'))
Check 'UserAssist exposes last-run FILETIME and incident-window flag' (($collect -match 'Convert-UserAssistFileTime') -and ($collect -match 'ToInt64\(\$Value, 60\)') -and ($collect -match 'LastExecutionUtc') -and ($collect -match 'InIncidentWindow'))
Check 'collection errors mark snapshots incomplete' (($collect -match 'CollectionIncomplete') -and ($collect -match 'CollectionComplete\s*=\s*\(-not \$script:CollectionIncomplete\)'))
Check 'targeted serial snapshot sections are supported' (($collect -match "'Srum'\s+\{.*Get-SrumSection") -and ($collect -match "'Amcache'\s+\{.*Get-AmcacheSection"))
Check 'parallel snapshot groups have a hard timeout' (($collect -match 'ParallelTimeoutSeconds') -and ($collect -match 'deadline') -and ($collect -match 'Stop-Job'))
Check 'ShimCache stays raw-only until decoder fixtures are validated' (($collect -match "DecoderStatus\s*=\s*'RawOnly'") -and ($collect -match 'RawSha256') -and ($collect -match 'path decoding disabled'))
Check 'resume marker write failures remain incomplete' (($remover -match 'ResumeMarkerWriteFailed') -and ($remover -match 'Cannot establish resume marker') -and ($remover -match 'markerOk') -and ($remover -match 'overallSuccess\s*=\s*\$false'))
Check 'resume marker read/missing failures are fail-closed' (($remover -match 'Could not read resume marker.*Error') -and ($remover -match 'No resume marker found.*Error') -and ($remover -match 'ResumeMarkerIdentityFailed'))
Check 'dry-run quarantine preparation is side-effect free' (($remover -match 'function Get-QuarantineDir') -and ($remover -match '\[switch\]\$Prepare') -and ($remover -match 'Get-QuarantineDir -WorkDir \$WorkDir -Prepare:\$Execute') -and ($remover -match 'if \(\$Prepare\s*-and') -and ($remover -match '(?s)function Get-QuarantineDir.*?if \(\$Prepare\s*-and.*?Protect-QuarantinePathAcl'))
Check 'AV uninstall executable is constrained to approved roots' (($av -match 'Resolve-UninstallCommand') -and ($av -match 'Test-AllowedAvPath') -and ($av -match 'resolved'))

if ($failures.Count -gt 0) { exit 1 }
Write-Host 'Safety regression contracts passed.' -ForegroundColor Green
exit 0
