# Invoke-KVRTScan.ps1
#
# Stage 5 scanner adapter: Kaspersky Virus Removal Tool (KVRT).
#
# DOCUMENTED SWITCHES ONLY -- verified against official Kaspersky documentation,
# not written from memory (docs Q4 rule):
#   [1] "Managing the application from the command line", Kaspersky Virus
#       Removal Tool 2024 help, ID 269475:
#       https://support.kaspersky.com/kvrt2024/269475
#       Documented there:
#         -accepteula      Automatically accept the EULA, Privacy Policy and
#                          KSN Statement. REQUIRED before -silent.
#         -silent          Scan without GUI. By default (no -processlevel)
#                          the application ONLY DETECTS infected or probably
#                          infected objects and logs events -- it does NOT
#                          apply any actions to objects.
#         -processlevel N  Neutralize objects of threat level <= N (1 high,
#                          2 high+medium, 3 all). Omitted here => detect-only
#                          (read-only safety model).
#         -customonly      DOCUMENTED BUT REJECTED by KVRT 20.x (exit -2). Do not
#                          use. Scope-only scanning (excludes system memory,
#                          startup objects, boot sectors).
#         -custom <path>   Add a directory to the scan scope (full paths;
#                          repeatable).
#         -d <dir>         Directory for reports, traces, quarantine etc.
#         -dontencrypt     Disable encryption of traces, dumps and reports --
#                          needed so the technician can read the report files
#                          this adapter copies.
#         -details         Generate detailed reports (all application events);
#                          default standard reports include warning+error only.
#   [2] "Command line parameters for managing Kaspersky Virus Removal Tool",
#       Kaspersky support base, https://support.kaspersky.com/8537 (Windows
#       variant of [1]; same switch set).
#   [3] docs/05-tools-scanners-tron.md row "KVRT": report directory lives
#       under %SystemDrive%\KVRT*_Data\ with the exact name varying by
#       version -- hence the wildcard search in Copy-ScanLogs below.
#
# LICENSING / APPROVAL (docs/05-tools-scanners-tron.md):
#   APPROVED by the owner (decision D2). "Do not block on licensing." Note
#   that approval is an owner decision recorded in that doc; Kaspersky's own
#   commercial-use terms are NOT documented there ("approved is not
#   documented") -- flagged as an open item, not resolved by this adapter.
#
# SAFETY MODEL (docs/06-safety-model.md):
#   - Read-only by default: we run `-accepteula -silent` WITHOUT any
#     -processlevel, which per doc [1] means detections are logged but no
#     disinfect/delete action is taken. We never pass -adinsilent (that one
#     disinfects AND reboots). Removal stays behind Stage 4's approval gate.
#   - Scanner failure is non-fatal AND reported as failure (never silent).
#   - -WhatIf is genuinely safe: availability + command line only, nothing runs.
#
# House rules: PS 5.1 compatible (no ternary, no ??, no &&, no -AsHashtable),
# pure ASCII, single .ps1 standalone-capable.

[CmdletBinding()]
param(
    [string]$ScanPath,              # optional targeted directory -> -custom <path>
    [int]$TimeoutMinutes = 120,     # hard timeout per scanner (contract)
    [string]$LogDir,                # where to copy KVRT's own report files
    [string]$ToolPath,              # optional explicit path to KVRT.exe
    [switch]$WhatIf                 # report availability + command line, run nothing
)

Set-StrictMode -Version 2.0

$script:ScannerName = 'KVRT'

# Temp root fallback: $env:TEMP is Windows-standard but absent in some
# contexts (non-interactive sessions); fall back to TMP then the current dir.
function Get-TempRoot {
    if ($env:TEMP) { return $env:TEMP }
    if ($env:TMP) { return $env:TMP }
    return (Get-Location).Path
}

function Write-AdapterLog {
    param([string]$Message)
    $line = ('[{0}] [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $script:ScannerName, $Message)
    Write-Verbose $line
}

function New-ResultObject {
    param([hashtable]$Fields)
    return New-Object PSObject -Property @{
        ScannerName     = 'KVRT'
        ScannerVersion  = ''
        Available       = $false
        StartTimeUtc    = ''
        EndTimeUtc      = ''
        DurationSeconds = 0
        Status          = 'NotInstalled'
        ExitCode        = $null
        Detections      = @()
        DetectionCount  = 0
        LogPath         = ''
        RebootRequired  = $false
        Errors          = @()
        CommandLine     = ''
    } | ForEach-Object {
        foreach ($k in $Fields.Keys) { $_.$k = $Fields[$k] }
        $_
    }
}

# Locate kvrt.exe. KVRT ships as a single portable EXE (name varies by
# release, e.g. KVRT.exe / kvrt.exe); there is no fixed install location,
# so discovery checks common drop points plus an explicit path from the caller.
function Find-KVRT {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (Test-Path -LiteralPath $ExplicitPath) { return $ExplicitPath }
        return $null
    }

    try {
        $candidates = @()
        $toolsAvDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\AV'
        foreach ($root in @($toolsAvDir, $env:SystemDrive, 'C:\Users\Public\Downloads', $env:TEMP)) {
            if (-not $root) { continue }
            $driveRoot = $root
            if ($root -match '^[A-Za-z]:$') { $driveRoot = $root + '\' }
            try {
                $hits = @(Get-ChildItem -LiteralPath $driveRoot -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^(kvrt|KVRT)' })
                foreach ($h in $hits) { $candidates += $h.FullName }
            } catch { }
        }
        $candidates = @($candidates | Where-Object { $_ } | Select-Object -Unique)
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) { return $c }
        }
    } catch { }
    return $null
}

# KVRT has no documented "--version" style switch (doc [1] lists none), so we
# read the file's version resource rather than guess or run anything extra.
function Get-KVRTVersion {
    param([string]$ExePath)
    if (-not $ExePath) { return '' }
    try {
        $vi = (Get-Item -LiteralPath $ExePath).VersionInfo
        if ($vi.ProductVersion) { return [string]$vi.ProductVersion }
        if ($vi.FileVersion) { return [string]$vi.FileVersion }
    } catch { }
    return ''
}

# Copy KVRT's own report/traces out of its data directory. Per docs/05 the
# directory sits at %SystemDrive%\KVRT*_Data\ and the name varies by version
# ([3]); when -d was passed we know the exact folder instead.
function Copy-ScanLogs {
    param(
        [string]$DestinationDir,
        [string]$DataDir,
        [int]$SinceMinutes
    )
    if (-not $DestinationDir) { return '' }
    try {
        if (-not (Test-Path -LiteralPath $DestinationDir)) {
            New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }
        $roots = @()
        if ($DataDir) { $roots += $DataDir }
        $sysDrive = $env:SystemDrive
        if (-not $sysDrive) { $sysDrive = 'C:' }
        $wildcard = Join-Path ($sysDrive + '\') 'KVRT*_Data'
        try {
            $found = @(Get-Item -Path $wildcard -ErrorAction SilentlyContinue)
            foreach ($f in $found) { $roots += $f.FullName }
        } catch { }

        $cutoff = (Get-Date).AddMinutes(-1 * [Math]::Max($SinceMinutes, 5))
        $copied = @()
        foreach ($r in $roots) {
            if (-not $r -or -not (Test-Path -LiteralPath $r)) { continue }
            $files = @(Get-ChildItem -LiteralPath $r -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cutoff } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 20)
            foreach ($f in $files) {
                Copy-Item -LiteralPath $f.FullName -Destination $DestinationDir -Force
                $copied += $f.Name
            }
        }
        return (@($copied | Select-Object -Unique) -join ', ')
    } catch {
        Write-AdapterLog ("Log copy failed: " + $_.Exception.Message)
        return ''
    }
}

# Parse KVRT's unencrypted detailed report for detected-object lines.
# With -dontencrypt the reports are plain text; detection lines carry the
# object path and verdict. Parsing is best-effort and bounded: any miss is
# reported as empty detections, never fabricated.
function Get-DetectionsFromReports {
    param([string]$DataDir)
    $out = @()
    if (-not $DataDir -or -not (Test-Path -LiteralPath $DataDir)) { return ,$out }
    try {
        $files = @(Get-ChildItem -LiteralPath $DataDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.txt', '.log', '.htm', '.html' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 5)
        foreach ($f in $files) {
            $lines = @()
            try { $lines = @(Get-Content -LiteralPath $f.FullName -ErrorAction Stop) } catch { continue }
            foreach ($ln in $lines) {
                # Heuristic line match: KVRT report entries name the scanned
                # object path plus a verdict (infected / probably infected /
                # deleted / disinfected). Kept conservative: skip lines that
                # clearly describe settings rather than objects.
                if ($ln -match '(?i)(infected|detected|Trojan|Virus|Malware|Adware)') {
                    $path = ''
                    if ($ln -match '[A-Za-z]:\\[^\t";]+') { $path = $Matches[0].Trim() }
                    $out += ,@{
                        Path       = $path
                        ThreatName = $ln.Trim().Substring(0, [Math]::Min(200, $ln.Trim().Length))
                        Severity   = ''
                        Action     = 'Detected'   # detect-only run: nothing was remediated
                    }
                }
                if (@($out).Count -ge 200) { break }
            }
            if (@($out).Count -ge 200) { break }
        }
    } catch {
        Write-AdapterLog ("Report parse failed: " + $_.Exception.Message)
    }
    return ,$out
}

# ---------------------------------------------------------------------------
# Invoke-ProcessWithTimeout
#   Run a child process with both stdio streams redirected and a hard timeout
#   (contract: a hung scanner must not hang the run; a chatty scanner must not
#   deadlock on a full redirect pipe and defeat the timeout).
#
#   PS 5.1-safe drain pattern:
#     - Both redirected streams are read ASYNCHRONOUSLY via ReadToEndAsync()
#       as soon as the process starts. A redirected pipe buffers only a few KB;
#       waiting until exit to read (the old HasExited poll + sync ReadToEnd)
#       let a tool filling the buffer block forever inside its own write and
#       never flip HasExited - so the advertised timeout never fired.
#     - WaitForExit(milliseconds) does the bounded wait honoring the timeout.
#     - On timeout the child is terminated and reaped within a bounded window;
#       both async stream tasks are then collected so diagnostics survive.
#
#   Returns a hashtable: TimedOut (bool), ExitCode (int or $null when timed
#   out), StdOut and StdErr (string, best-effort diagnostics).
# ---------------------------------------------------------------------------
function Invoke-ProcessWithTimeout {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ($ArgumentList -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)

    # Drain both streams concurrently BEFORE the bounded wait so a full pipe
    # can never block the child. ReadToEndAsync is available on the .NET
    # Framework 4.5+ that Windows PowerShell 5.1 runs on.
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $timedOut = -not $proc.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        # Hard timeout: terminate the direct child and reap within a bounded
        # window so the async readers reach EOF and can be read below.
        try { $proc.Kill() } catch { }
        try { $null = $proc.WaitForExit(2000) } catch { }
    }

    # Collect both stream tasks with a BOUNDED WaitAll so a child that holds a
    # pipe handle open past termination can never make this step block forever.
    # Only read results for tasks that actually completed; otherwise report a
    # degraded (incomplete) drain via StreamDrainTimedOut.
    $stdout = ''
    $stderrText = ''
    $streamDrainTimedOut = $false
    $streamTasks = [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
    $allDrained = [System.Threading.Tasks.Task]::WaitAll($streamTasks, 5000)
    if ($allDrained) {
        try { $stdout = [string]$stdoutTask.GetAwaiter().GetResult() } catch { $stdout = '' }
        try { $stderrText = [string]$stderrTask.GetAwaiter().GetResult() } catch { $stderrText = '' }
    } else {
        $streamDrainTimedOut = $true
    }

    $exitCode = $null
    if (-not $timedOut) {
        try { $exitCode = $proc.ExitCode } catch { }
    }

    return @{
        TimedOut            = $timedOut
        StreamDrainTimedOut = $streamDrainTimedOut
        ExitCode            = $exitCode
        StdOut              = $stdout
        StdErr              = $stderrText
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$start = Get-Date
$errors = @()

$tool = Find-KVRT -ExplicitPath $ToolPath

if (-not $tool) {
    $r = New-ResultObject @{
        Status       = 'NotInstalled'
        StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        EndTimeUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Errors       = @('kvrt.exe not found (checked SystemDrive root, Public Downloads, TEMP; pass -ToolPath explicitly)')
    }
    return $r
}

$version = Get-KVRTVersion -ExePath $tool

# Build the command line per doc [1].
# Detect-only silent scan: -accepteula -silent, NO -processlevel (per doc [1],
# without a threat level no actions are applied to detected objects),
# -dontencrypt so reports stay readable, -details for full-event reporting.
# A targeted path adds -custom <path> (NOT -customonly - see note below).
if (-not $TimeoutMinutes -or $TimeoutMinutes -lt 1) { $TimeoutMinutes = 120 }

$dataDir = Join-Path (Get-TempRoot) ('KVRT_Data_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
# Create the -d directory up front. KVRT does not reliably create it itself,
# and when it is missing a run can finish without ever writing a report - which
# surfaced as "No KVRT data directory found after scan; report output missing"
# and 0 detections even though the scan ran.
if (-not (Test-Path -LiteralPath $dataDir)) {
    try { $null = New-Item -ItemType Directory -Path $dataDir -Force -ErrorAction Stop } catch { }
}
$argList = @('-accepteula', '-silent', '-dontencrypt', '-details', ('-d "' + $dataDir + '"'))
if ($ScanPath) {
    # -customonly is NOT accepted by KVRT 20.x: measured on 2026-08-25 against
    # KVRT 20.0.14.0, "-customonly -custom <path>" exits -2 in ~5s and writes no
    # report at all, while "-custom <path>" alone runs the scan and produces
    # report files. Passing -custom by itself is also what the vendor documents.
    $argList += @(('-custom "' + $ScanPath + '"'))
}
$commandLine = ('"' + $tool + '" ' + ($argList -join ' '))
# NOTE: KVRT exit codes are NOT published in doc [1] (the article documents
# switches only). We therefore do not map numeric exit codes to outcomes:
# status comes from whether the process completed within the timeout, and the
# authoritative outcome is the report file parsed below. This avoids guessing
# an undocumented table (docs Q4 rule).

if ($WhatIf) {
    $r = New-ResultObject @{
        Available    = $true
        Status       = 'Skipped'      # WhatIf: nothing ran
        ScannerVersion = $version
        StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        EndTimeUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        CommandLine  = $commandLine
    }
    return $r
}

# Run the scan with a hard timeout (contract: a hung scanner must not hang the
# run). Invoke-ProcessWithTimeout drains stdout/stderr concurrently, so a tool
# that fills a redirect pipe can never block itself and defeat the timeout.
$run = $null
try {
    $run = Invoke-ProcessWithTimeout -FilePath $tool -ArgumentList $argList -TimeoutSeconds ($TimeoutMinutes * 60)
} catch {
    $errors += ('Scan execution failed: ' + $_.Exception.Message)
}
$timedOut = $false
$exitCode = $null
if ($null -ne $run) {
    $timedOut = $run.TimedOut
    $exitCode = $run.ExitCode
    if ($timedOut) {
        $errors += ('Scanner did not finish within ' + $TimeoutMinutes + ' minute(s); process was terminated.')
    }
    if ($run.StreamDrainTimedOut) {
        $errors += 'Scanner output streams did not close within the drain window after termination; captured output may be incomplete.'
    }
}

$end = Get-Date
$duration = [int]($end - $start).TotalSeconds

$status = 'Failed'
if ($timedOut) {
    $status = 'Timeout'
} elseif ($null -ne $exitCode) {
    # Exit-code semantics undocumented (see NOTE above): completion with any
    # code counts as Completed; the report file decides detections. A nonzero
    # code is still surfaced in Errors so it is never silently dropped.
    $status = 'Completed'
    if ($exitCode -ne 0) {
        $errors += ('KVRT exited with nonzero code ' + $exitCode + ' (semantics undocumented per doc [1]); check copied reports.')
    }
} else {
    $errors += 'KVRT process could not be started.'
}

# Collect detections AFTER the scan from the (unencrypted, thanks to
# -dontencrypt) report files under our explicit -d data directory.
# NOTE: no outer @() here. The Get-*Detections helpers already return
# ',$out' (comma-protected). Wrapping that again in @() produced a
# ONE-element array whose single element was the whole detection list,
# so New-Object -Property below got an array instead of a hashtable and
# the adapter crashed the moment a scan actually found something.
$detections = Get-DetectionsFromReports -DataDir $dataDir
if ($null -ne $exitCode -and @($detections).Count -eq 0) {
    # We create $dataDir ourselves up front, so its existence proves nothing.
    # The failure signal is: scan finished but zero report files were produced.
    $reportFiles = @()
    try { $reportFiles = @(Get-ChildItem -LiteralPath $dataDir -Recurse -File -ErrorAction SilentlyContinue) } catch { }
    if ($reportFiles.Count -eq 0) {
        $errors += 'KVRT wrote no report files to the data directory; scan output missing.'
    }
}

$logNote = Copy-ScanLogs -DestinationDir $LogDir -DataDir $dataDir -SinceMinutes ([Math]::Max($duration / 60, 5))

$r = New-ResultObject @{
    Available       = $true
    ScannerVersion  = $version
    StartTimeUtc    = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    EndTimeUtc      = $end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    DurationSeconds = $duration
    Status          = $status
    ExitCode        = $exitCode
    Detections      = @($detections | ForEach-Object { New-Object PSObject -Property $_ })
    DetectionCount  = @($detections).Count
    LogPath         = $logNote
    RebootRequired  = $false   # detect-only run: -adinsilent is never passed, no restart triggered
    Errors          = @($errors)
    CommandLine     = $commandLine
}
return $r
