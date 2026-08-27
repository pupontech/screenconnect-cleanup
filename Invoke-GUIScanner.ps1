<#
  Invoke-GUIScanner.ps1 - Launch a GUI-only AV scanner and WAIT for the
  technician to finish with it.

  WHY THIS EXISTS
    Malwarebytes (consumer MBAM) has no documented unattended/silent scan
    switches (verified 2026-08-26 against vendor docs; see docs/05-tools-scanners-tron.md).
    The pipeline therefore cannot drive it - but the technician can. This script
    does only three things:

      1. find or take an explicit path to the scanner EXE,
      2. launch it as a NORMAL VISIBLE GUI process,
      3. block until that process exits, then report elapsed time + exit code.

  It never passes scan/clean switches, never parses the scanner's output, and
  never fabricates a result: the technician drives the GUI; this script just
  keeps the pipeline paused while they do, so Stage 7/8 snapshots and the
  report are taken AFTER any GUI-driven cleaning has actually finished.

  USAGE
    .\Invoke-GUIScanner.ps1 -Scanner Malwarebytes    # MBSetup.exe
    .\Invoke-GUIScanner.ps1 -ToolPath C:\path\tool.exe   # any explicit EXE

  Search order when -ToolPath is not given:
    tools\AV\<name>.exe next to this script, then the user's Downloads
    folder, then TEMP.
    If not found: exits 3 with a clear message; nothing is downloaded here -
    staging is tools\Get-AVTools.ps1's job.

  NOTES
    - Use inside sc-cleanup.ps1 runs: run it between stages from another
      console, or via RUN-REMOVAL-TEST.bat-style wrappers; it writes a small
      JSON result to stdout for the master log.
    - -TimeoutMinutes caps a forgotten/abandoned GUI (default 240 = 4 h).
      On timeout the process is LEFT RUNNING (killing it mid-scan could
      abort a cleanup mid-write); the script reports Timeout and exits 4.
    - Exit codes: 0 technician closed the tool; 2 tool failed to start;
      3 tool not found; 4 timeout reached (process still running).

  House rules: PS 5.1 compatible, pure ASCII, no BOM.
#>

[CmdletBinding()]
param(
    [ValidateSet('Malwarebytes')]
    [string]$Scanner,
    [string]$ToolPath,              # explicit path wins over -Scanner lookup
    [int]$TimeoutMinutes = 240      # cap for an abandoned GUI window
)

Set-StrictMode -Version 2.0

$start = Get-Date

function Get-TempRoot {
    if ($env:TEMP) { return $env:TEMP }
    if ($env:TMP) { return $env:TMP }
    return (Get-Location).Path
}

function Get-HomeDir {
    if ($env:USERPROFILE) { return $env:USERPROFILE }
    if ($env:HOME) { return $env:HOME }
    return ''
}

$knownTools = @{
    'Malwarebytes' = 'MBSetup.exe'
}

# ---------------------------------------------------------------------------
# Resolve which EXE to launch
# ---------------------------------------------------------------------------
$target = $null

if ($ToolPath) {
    if (-not (Test-Path -LiteralPath $ToolPath)) {
        Write-Error ("ToolPath not found: " + $ToolPath)
        exit 3
    }
    $target = $ToolPath
} elseif ($Scanner) {
    $name = $knownTools[$Scanner]
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidates = @(
        (Join-Path $scriptRoot ('AV\' + $name)),
        (Join-Path $scriptRoot $name),
        (Join-Path $scriptRoot ('..\tools\AV\' + $name))
    )
    $homeDir = Get-HomeDir
    if ($homeDir) { $candidates += (Join-Path $homeDir ('Downloads\' + $name)) }
    $candidates += @(
        (Join-Path (Get-TempRoot) $name)
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { $target = $c; break }
    }
    if (-not $target) {
        Write-Host ("Scanner not found: " + $name) -ForegroundColor Red
        Write-Host "Stage it first with tools\Get-AVTools.ps1, or pass -ToolPath explicitly." -ForegroundColor Yellow
        exit 3
    }
} else {
    Write-Error "Specify -Scanner Malwarebytes or -ToolPath <exe>."
    exit 3
}

Write-Host ("Launching GUI scanner: " + $target) -ForegroundColor Cyan
Write-Host "Drive the scanner UI now. This script waits until you close it." -ForegroundColor Cyan
Write-Host ("Hard cap: " + $TimeoutMinutes + " min (on timeout the process is LEFT running).") -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Launch VISIBLE (no CreateNoWindow, no redirects - it is a GUI app) and wait
# ---------------------------------------------------------------------------
try {
    $proc = Start-Process -FilePath $target -PassThru -ErrorAction Stop
} catch {
    Write-Host ("Failed to launch: " + $_.Exception.Message) -ForegroundColor Red
    $result = @{
        Tool       = (Split-Path -Leaf $target)
        Status     = 'LaunchFailed'
        StartedUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Error      = $_.Exception.Message
    }
    $result | ConvertTo-Json -Compress | Write-Output
    exit 2
}

$timedOut = $false
if (-not $proc.WaitForExit($TimeoutMinutes * 60 * 1000)) {
    $timedOut = $true   # deliberately NOT killed: mid-scan kill could corrupt a cleanup
}

$end = Get-Date
$duration = [int]($end - $start).TotalSeconds
$exitCode = $null
if (-not $timedOut) {
    try { $exitCode = $proc.ExitCode } catch { }
}

$status = 'Completed'
if ($timedOut) { $status = 'Timeout' }

$result = @{
    Tool            = (Split-Path -Leaf $target)
    Status          = $status
    StartTimeUtc    = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    EndTimeUtc      = $end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    DurationSeconds = $duration
    ProcessExitCode = $exitCode
}
$result | ConvertTo-Json -Compress | Write-Output

if ($timedOut) {
    Write-Host ("TIMEOUT after " + $TimeoutMinutes + " min - scanner still running; pipeline result marked Timeout.") -ForegroundColor Yellow
    exit 4
}

Write-Host ("Technician closed the scanner after " + $duration + "s (exit code " + $exitCode + ").") -ForegroundColor Green
exit 0
