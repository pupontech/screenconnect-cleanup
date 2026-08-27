<#
  Invoke-GUIScanner.ps1 - Launch a GUI-only AV scanner and WAIT for the
  technician to finish with it.

  WHY THIS EXISTS
    KVRT and ESET Online Scanner are used here as attended GUI technician
    tools; Malwarebytes is INSTALLED here via winget (owner directive
    2026-08-27 - no more MBSetup.exe staging). This script does only three
    things:

      1. resolve what to run - the scanner EXE (KVRT/ESET, found or explicit)
         or the winget install command (Malwarebytes),
      2. launch it as a NORMAL VISIBLE process (GUI for the scanners; a
         console window for winget so the technician sees the install),
      3. block until that process exits, then report elapsed time + exit code.
         For Malwarebytes the script then also launches the freshly installed
         Malwarebytes GUI (mbam.exe) and waits on it like any scanner, so the
         pipeline stays paused while the technician runs the scan.

  It never passes scan/clean switches, never parses the scanner's output, and
  never fabricates a result: the technician drives the UI; this script just
  keeps the pipeline paused while they do, so later snapshots and the report are
  taken AFTER any GUI-driven cleaning has actually finished.

  USAGE
    .\Invoke-GUIScanner.ps1 -Scanner KVRT            # KVRT.exe
    .\Invoke-GUIScanner.ps1 -Scanner ESET            # esetonlinescanner.exe
    .\Invoke-GUIScanner.ps1 -Scanner Malwarebytes    # winget install -e --id Malwarebytes.Malwarebytes; then launches the GUI
    .\Invoke-GUIScanner.ps1 -ToolPath C:\path\tool.exe   # any explicit EXE

  Search order when -ToolPath is not given (KVRT/ESET):
    tools\AV\<name>.exe next to this script, then legacy AV\ and the bare
    script root, then ..\tools\AV, then the user's Downloads folder, then TEMP.
    If not found: exits 3 with a clear message; nothing is downloaded here -
    staging is tools\Get-AVTools.ps1's job.
    Malwarebytes does not use the file search: it requires winget and runs
    `winget install -e --id Malwarebytes.Malwarebytes` (exits 3 if winget is
    missing). After a successful install it locates mbam.exe under Program
    Files / Program Files (x86) and launches the Malwarebytes GUI, waiting
    for the technician to close it (same timeout cap as the scanners).

  NOTES
    - Use inside sc-cleanup.ps1 runs: the runner launches each scanner and waits.
    - -TimeoutMinutes caps a forgotten/abandoned GUI (default 240 = 4 h).
      On timeout the process is LEFT RUNNING (killing it mid-scan could abort a
      cleanup mid-write); the script reports Timeout and exits 4.
    - Exit codes: 0 technician closed the tool; 2 tool failed to start;
      3 tool not found; 4 timeout reached (process still running).

  House rules: PS 5.1 compatible, pure ASCII, no BOM.
#>

[CmdletBinding()]
param(
    [ValidateSet('KVRT', 'ESET', 'Malwarebytes')]
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
    'KVRT' = 'KVRT.exe'
    'ESET' = 'esetonlinescanner.exe'
}
# Scanners that are INSTALLED via winget instead of being staged as EXEs
# (owner directive 2026-08-27: Malwarebytes install/uninstall via winget).
$wingetScanners = @{
    'Malwarebytes' = 'Malwarebytes.Malwarebytes'
}

# ---------------------------------------------------------------------------
# Resolve what to run
# ---------------------------------------------------------------------------
$target = $null
$toolArgs = @()
$toolLabel = $null
$wingetViaCmd = $false

if ($ToolPath) {
    if (-not (Test-Path -LiteralPath $ToolPath)) {
        Write-Error ("ToolPath not found: " + $ToolPath)
        exit 3
    }
    $target = $ToolPath
    $toolLabel = Split-Path -Leaf $ToolPath
} elseif ($Scanner) {
    if ($knownTools.ContainsKey($Scanner)) {
        $name = $knownTools[$Scanner]
        $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
        # Search order: Get-AVTools.ps1's canonical staging sibling (tools\AV\) first
        # (its default $ToolDir is <Get-AVTools script dir>\AV), then legacy AV\ and
        # the bare script root, then ..\tools\AV (covers invoking this script from
        # inside tools\), then the user's Downloads and %TEMP% as fallbacks.
        $candidates = @(
            (Join-Path $scriptRoot ('tools\AV\' + $name)),
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
        $toolLabel = Split-Path -Leaf $target
    } elseif ($wingetScanners.ContainsKey($Scanner)) {
        # Malwarebytes: winget install (attended - visible console).
        $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $wingetCmd) {
            Write-Host ("winget not found - cannot install " + $Scanner + " (" + $wingetScanners[$Scanner] + ").") -ForegroundColor Red
            Write-Host "Install winget (App Installer) first, or pass -ToolPath <MBSetup.exe> explicitly." -ForegroundColor Yellow
            exit 3
        }
        $target   = $wingetCmd.Source
        $toolArgs = @('install', '-e', '--id', $wingetScanners[$Scanner])
        $toolLabel = $wingetScanners[$Scanner] + ' (winget install)'
        # winget on Windows 10/11 is an App Execution Alias: a 0-byte reparse
        # stub under WindowsApps. Start-Process -FilePath on the stub is
        # unreliable in PS 5.1 (silent $null process handle, or 'not a valid
        # Win32 application'), which used to crash the launcher right after
        # "launching Malwarebytes". Launch it through cmd.exe instead - the OS
        # resolves the alias and the console stays visible for the technician.
        $wingetViaCmd = $true
    }
} else {
    Write-Error "Specify -Scanner KVRT|ESET|Malwarebytes or -ToolPath <exe>."
    exit 3
}

if (-not $target) {
    Write-Host ("Scanner not found: " + $Scanner) -ForegroundColor Red
    exit 3
}

if ($toolArgs.Count -gt 0) {
    Write-Host ("Installing via winget: winget " + ($toolArgs -join ' ')) -ForegroundColor Cyan
    Write-Host "A console window opens for winget - wait until the install finishes." -ForegroundColor Cyan
} else {
    Write-Host ("Launching GUI scanner: " + $target) -ForegroundColor Cyan
    Write-Host "Drive the scanner UI now. This script waits until you close it." -ForegroundColor Cyan
}
Write-Host ("Hard cap: " + $TimeoutMinutes + " min (on timeout the process is LEFT running).") -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Launch VISIBLE (no CreateNoWindow, no redirects) and wait
# ---------------------------------------------------------------------------
try {
    if ($toolArgs.Count -gt 0) {
        if ($wingetViaCmd) {
            # cmd.exe resolves the WindowsApps alias stub; a fresh console
            # window opens for winget (visible, attended).
            $comSpec = $env:ComSpec
            if (-not $comSpec) { $comSpec = 'cmd.exe' }
            $cmdArgs = @('/c', 'winget')
            $cmdArgs += $toolArgs
            $proc = Start-Process -FilePath $comSpec -ArgumentList $cmdArgs -PassThru -ErrorAction Stop
        } else {
            $proc = Start-Process -FilePath $target -ArgumentList $toolArgs -PassThru -ErrorAction Stop
        }
    } else {
        $proc = Start-Process -FilePath $target -PassThru -ErrorAction Stop
    }
} catch {
    Write-Host ("Failed to launch: " + $_.Exception.Message) -ForegroundColor Red
    $result = @{
        Tool       = $toolLabel
        Status     = 'LaunchFailed'
        StartedUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Error      = $_.Exception.Message
    }
    $result | ConvertTo-Json -Compress | Write-Output
    exit 2
}

# Guard: Start-Process can return $null on some alias/handle paths - a null
# method call below would crash the launcher instead of failing cleanly.
if ($null -eq $proc) {
    Write-Host "Failed to launch: Start-Process returned no process handle." -ForegroundColor Red
    $result = @{
        Tool       = $toolLabel
        Status     = 'LaunchFailed'
        StartedUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Error      = 'Start-Process returned no process handle'
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

# Malwarebytes: winget just installed it - launch the GUI so the technician
# can scan with it, the same attended model as KVRT/ESET (waits for the UI
# to close; the scan happens inside it).
if ($wingetViaCmd -and -not $timedOut -and $exitCode -eq 0) {
    $mbam = $null
    $candidates = @((Join-Path $env:ProgramFiles 'Malwarebytes\Anti-Malware\mbam.exe'))
    if (${env:ProgramFiles(x86)}) {
        $candidates += (Join-Path ${env:ProgramFiles(x86)} 'Malwarebytes\Anti-Malware\mbam.exe')
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { $mbam = $candidate; break }
    }
    if ($mbam) {
        Write-Host ("Launching Malwarebytes GUI: " + $mbam) -ForegroundColor Cyan
        Write-Host "Drive a scan in the Malwarebytes UI - this script waits until you close it." -ForegroundColor Cyan
        $mbamProc = $null
        try {
            $mbamProc = Start-Process -FilePath $mbam -PassThru -ErrorAction Stop
        } catch {
            Write-Host ("  [WARN] Could not launch Malwarebytes GUI: " + $_.Exception.Message) -ForegroundColor Yellow
        }
        if ($null -ne $mbamProc) {
            if (-not $mbamProc.WaitForExit($TimeoutMinutes * 60 * 1000)) {
                $timedOut = $true   # deliberately NOT killed, same rule as the scanners
            }
        }
        $end = Get-Date
        $duration = [int]($end - $start).TotalSeconds
    } else {
        Write-Host "  [WARN] Malwarebytes installed but mbam.exe not found at standard paths - launch it from the Start Menu." -ForegroundColor Yellow
    }
}

$status = 'Completed'
if ($timedOut) { $status = 'Timeout' }

$result = @{
    Tool            = $toolLabel
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
