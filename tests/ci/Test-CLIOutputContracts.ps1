# Test-CLIOutputContracts.ps1 - compact command-prompt output contracts.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$failures = 0

function Check {
    param([string]$Name, [bool]$Ok)
    if ($Ok) { Write-Host ("PASS  " + $Name) }
    else { Write-Host ("FAIL  " + $Name); $script:failures++ }
}

$startHere = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'START-HERE.bat'))
$cleanup = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'sc-cleanup.ps1'))
$scanner = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Invoke-GUIScanner.ps1'))
$toolPack = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'tools/Get-ToolPack.ps1'))
$avTools = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'tools/Get-AVTools.ps1'))
$snapshot = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'collect-snapshot.ps1'))
$removalTest = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'RUN-REMOVAL-TEST.bat'))
$bundleBuilder = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'make-deploy-bundle.sh'))

# --- START-HERE.bat guided runner ---
Check 'compact guided title exists' ($startHere.Contains('SCREENCONNECT CLEANUP - guided run'))
Check 'compact stage map exists' ($startHere.Contains('1 toolpack  2 preflight  3 snapshot  4 detect  5 remove'))
Check 'compact second stage map excludes Tikun' ($startHere.Contains('6 scanners  7 AV uninstall  8 diff  9 report') -and -not $startHere.Contains('Tikun'))
Check 'stage labels use compact slash form' ($startHere.Contains('STEP 1/9: Tool pack + scanner staging') -and $startHere.Contains('STEP 9/9: Report') -and -not $startHere.Contains('/10:'))
Check 'destructive removal warning remains' ($startHere.Contains('quarantined, never deleted'))
Check 'AV never-silent promise remains' ($startHere.Contains('Never silent-uninstalls - uninstallers open for you to drive.'))
Check 'decision prompts remain' ($startHere.Contains('Run now? [Y/n]') -and $startHere.Contains('Launch KVRT? [Y/n]') -and -not $startHere.Contains('Run Tikun now? [y/N]'))
Check 'Tikun is removed from the guided runner' (-not $startHere.Contains('Tikun') -and -not $startHere.Contains('GeneralFix'))
Check 'filter-block diagnostic path remains' ($startHere.Contains('DiagnosticsOnly') -and $startHere.Contains('scanner-Malwarebytes-result.json'))
Check 'run artifact location remains visible' ($startHere.Contains('Run artifacts: !SCC_RUN_ROOT!'))
Check 'done banner names explicit artifacts' ($startHere.Contains('plan.json, removal-manifest.json, quarantine\'))
Check 'toolpack pass 1 runs quiet, verify pass stays loud' ($startHere.Contains('Get-ToolPack.ps1" -Quiet') -and $startHere.Contains('Get-ToolPack.ps1" -Verify'))
Check 'old explanatory header is removed' (-not $startHere.Contains('You are prompted before each step that needs a decision. Ctrl+C to abort.'))
Check 'old long antivirus explanation is removed' (-not $startHere.Contains('Every other detected AV product opens its'))
Check 'pause remains at completion/failure paths' ($startHere.Contains('pause'))

# --- sc-cleanup.ps1 pipeline ---
Check 'single-line stage banner' ($cleanup.Contains('Write-Host ("== " + $Title + " ==")'))
Check 'Starting Stage is debug-only' ($cleanup.Contains('Write-Dbg ("Starting Stage ') -and -not $cleanup.Contains('Write-StageLog ("Starting Stage '))
Check 'host line is compact' ($cleanup.Contains('Write-Host "Host: $hostName  |  OS: $osCaption"'))
Check 'no stage-0 workdir/masterlog console repeats' (-not $cleanup.Contains('Write-StageLog "Master log opened'))
Check 'snapshot children run quiet' (([regex]::Matches($cleanup, "'-Quiet'")).Count -ge 4)
Check 'removal warning is compact' ($cleanup.Contains('Removal exited ') -and $cleanup.Contains('continuing to produce manifest/diff/report.'))
Check 'diff warnings are compact' ($cleanup.Contains('Diff: INCOMPLETE collection evidence') -and $cleanup.Contains('Diff: RESURRECTION detected'))
Check 'no per-scanner session chatter' (-not $cleanup.Contains('session recorded: Status='))
Check 'no duplicate final workdir/masterlog pair' (-not $cleanup.Contains('Write-StageLog ("Working directory: " + $WorkDir)'))
Check 'error marker and exit contract preserved' ($cleanup.Contains('PIPELINE COMPLETED WITH ERRORS') -and $cleanup.Contains('exit 1'))
Check 'pipelines UAC block kept' ($cleanup.Contains('UAC (User Account Control) is DISABLED'))

# --- child scripts ---
Check 'snapshot collection errors always visible' ($snapshot.Contains('[WARN] Snapshot contains ') -and $snapshot.Contains('collection error(s)'))
Check 'scanner diagnostics tails compact' ($scanner.Contains('Evidence, not proof - ask the filter admin') -and -not $scanner.Contains('This is evidence, not proof of causation.'))
Check 'no redundant install-failed tail' (-not $scanner.Contains('Malwarebytes installation failed; no attended scan was completed.'))
Check 'early-exit alarm compact' ($scanner.Contains('with no GUI - NOT a completed scan.'))
Check 'toolpack cached line compact' ($toolPack.Contains('OK (cached; -Force re-downloads)'))
Check 'toolpack quiet suppresses summary table' ($toolPack.Contains('if (-not $Quiet) {'))
Check 'avtools closing is compact' ($avTools.Contains('Done. GUI scanners staged in ') -and -not $avTools.Contains('Run the staged scanners attended:'))
Check 'avtools uses a visible BITS progress bar' ($avTools.Contains('Write-Progress') -and $avTools.Contains('-PercentComplete') -and $avTools.Contains('-Completed'))
Check 'guided AV staging keeps BITS progress visible' ($startHere.Contains('Get-AVTools.ps1" -ToolDir') -and $startHere -notmatch 'Get-AVTools\.ps1" -ToolDir[^\r\n]*-Quiet')
Check 'removal-test done block is conditional' ($removalTest.Contains('if "%PIPE_RC%"=="0" (') -and $removalTest.Contains('[WARN] Pipeline exited %PIPE_RC%'))
Check 'Tikun is removed from the bundle builder' (-not $bundleBuilder.Contains('Tikun') -and -not $bundleBuilder.Contains('GeneralFix'))
Check 'Tikun source directory is removed' (-not (Test-Path (Join-Path $repoRoot 'tools/GeneralFix')))

if ($script:failures -gt 0) {
    Write-Host ("$script:failures CLI output contract(s) failed")
    exit 1
}
Write-Host 'ALL CLI OUTPUT CONTRACTS PASSED'
exit 0
