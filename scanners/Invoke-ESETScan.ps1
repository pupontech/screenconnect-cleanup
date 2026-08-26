# Invoke-ESETScan.ps1
#
# Stage 5 scanner adapter: ESET command-line scanner (ecls.exe).
#
# DOCUMENTED SWITCHES ONLY -- verified against official ESET documentation,
# not written from memory (docs Q4 rule):
#   [1] "Command line scanner", ESET Endpoint Security 12 Online Help:
#       https://help.eset.com/ees/12/en-US/advanced_cmd.html
#       Documented there:
#         ecls [OPTIONS...] FILES...
#         /base-dir=FOLDER   load modules from FOLDER
#         /log-file=FILE     log output to FILE (append by default;
#                            /log-rewrite overwrites)
#         /no-log-console    do not log output to console
#         /subdir            scan subfolders (default)
#         Exit codes: 0 = no threat found; 1 = threat found and cleaned;
#                     10 = some files could not be scanned (can be threats);
#                     50 = threat found; 100 = error. Codes > 100 mean the
#                     file was not scanned and thus can be infected.
#         /clean-mode=MODE   none (default) | standard | strict | rigorous |
#                            delete. Default "none" performs NO automatic
#                            cleaning -- detect-only.
#   [2] "[KB3417] ESET Command Line Scanner Parameters (ecls.exe)",
#       https://support.eset.com/en/kb3417-eset-command-line-scanner-parameters-eclsexe-5x-and-later
#       Scanner location: C:\Program Files\ESET\ESET Security\ecls.exe.
#       Example line: "...ecls.exe" /base-dir="C:\Program Files\ESET\ESET
#       Security\Modules" /auto /log-file=c:\ecls.txt /aind
#       (/auto scans AND automatically cleans -- deliberately NOT used here.)
#
# LICENSING / APPROVAL (docs/05-tools-scanners-tron.md):
#   APPROVED (decision D3) -- the MSP's ESET license covers technician scans.
#   Note ecls.exe ships WITH licensed endpoint products; standalone use of the
#   scanner binary is listed in that doc as a "verify" item ("approved is not
#   documented" at vendor level). If ecls.exe is absent, the adapter reports
#   NotInstalled and never fabricates a result. A machine with an unlicensed/
#   expired ESET install may fail activation inside ecls -- surfaced as
#   Status=Unlicensed when the log indicates it, else Failed.
#
# SAFETY MODEL (docs/06-safety-model.md):
#   - Read-only by default: we never pass /auto or any non-default
#     /clean-mode. Per doc [1] the default clean-mode is "none", so detected
#     objects are reported but NOT cleaned, deleted or quarantined. Removal
#     stays behind Stage 4's approval gate.
#   - Per docs/02-architecture.md: read the scanner's LOG FILE, never parse
#     stdout. We pass /log-file and /no-log-console and parse the file.
#   - Scanner failure is non-fatal AND reported as failure (never silent).
#   - -WhatIf is genuinely safe: availability + command line only.
#
# House rules: PS 5.1 compatible (no ternary, no ??, no &&, no -AsHashtable),
# pure ASCII, single .ps1 standalone-capable.

[CmdletBinding()]
param(
    [string]$ScanPath,              # optional targeted path -> scan that path; omit for local disks via default scope
    [int]$TimeoutMinutes = 120,     # hard timeout per scanner (contract)
    [string]$LogDir,                # where to copy ecls's own log file
    [string]$ToolPath,              # optional explicit path to ecls.exe
    [switch]$WhatIf                 # report availability + command line, run nothing
)

Set-StrictMode -Version 2.0

$script:ScannerName = 'ESET'

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
        ScannerName     = 'ESET'
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

# Locate ecls.exe per doc [2]: C:\Program Files\ESET\ESET Security\ecls.exe.
# Newer builds may live under versioned product folders, so also check the
# ESET program folder tree before giving up.
function Find-ECLS {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (Test-Path -LiteralPath $ExplicitPath) { return $ExplicitPath }
        return $null
    }

    try {
        $programFiles = $env:ProgramFiles
        if (-not $programFiles) { $programFiles = 'C:\Program Files' }
        $candidates = @()
        $candidates += (Join-Path $programFiles 'ESET\ESET Security\ecls.exe' -ErrorAction SilentlyContinue)
        $esetRoot = Join-Path $programFiles 'ESET' -ErrorAction SilentlyContinue
        if ($esetRoot -and (Test-Path -LiteralPath $esetRoot)) {
            $hits = @(Get-ChildItem -LiteralPath $esetRoot -Recurse -Filter 'ecls.exe' -File -ErrorAction SilentlyContinue |
                Select-Object -First 5)
            foreach ($h in $hits) { $candidates += $h.FullName }
        }
        foreach ($c in $candidates) {
            if ($c -and (Test-Path -LiteralPath $c)) { return $c }
        }
    } catch { }
    return $null
}

# Version string: /version is documented ([1], General options: "show version
# information and quit") but running it spawns a process even in WhatIf-ish
# paths; prefer the file's version resource instead, which is factual metadata.
function Get-ESETVersion {
    param([string]$ExePath)
    if (-not $ExePath) { return '' }
    try {
        $vi = (Get-Item -LiteralPath $ExePath).VersionInfo
        if ($vi.ProductVersion) { return [string]$vi.ProductVersion }
        if ($vi.FileVersion) { return [string]$vi.FileVersion }
    } catch { }
    return ''
}

# Parse the ecls log file (contract rule: parse the LOG, not stdout).
# Documented log lines mark threats as "threat" entries with the object path
# and detection name; parsing is best-effort, bounded, and never fabricated.
function Get-DetectionsFromLog {
    param([string]$LogFile)
    $out = @()
    if (-not $LogFile -or -not (Test-Path -LiteralPath $LogFile)) { return ,$out }
    try {
        $lines = @(Get-Content -LiteralPath $LogFile -ErrorAction Stop)
        foreach ($ln in $lines) {
            # ecls logs detections like:
            #   "path","detection name","action taken"  (quoted CSV-ish)
            # or text lines containing the word "threat". Keep both handlers
            # conservative: a line must mention threat/detection vocabulary.
            if ($ln -match '(?i)(threat|infected|virus|trojan|malware)') {
                $path = ''
                $name = ''
                if ($ln -match '"([^"]+)"\s*,\s*"([^"]+)"') {
                    $path = $Matches[1]
                    $name = $Matches[2]
                } elseif ($ln -match '[A-Za-z]:\\[^\t",]+') {
                    $path = $Matches[0].Trim()
                    $name = $ln.Trim().Substring(0, [Math]::Min(200, $ln.Trim().Length))
                }
                $out += ,@{
                    Path       = $path
                    ThreatName = $name
                    Severity   = ''
                    Action     = 'Detected'   # default clean-mode=none: nothing was remediated
                }
            }
            if (@($out).Count -ge 200) { break }
        }
    } catch {
        Write-AdapterLog ("Log parse failed: " + $_.Exception.Message)
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

$tool = Find-ECLS -ExplicitPath $ToolPath

if (-not $tool) {
    $r = New-ResultObject @{
        Status       = 'NotInstalled'
        StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        EndTimeUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Errors       = @('ecls.exe not found under Program Files\ESET (doc [2]); pass -ToolPath explicitly')
    }
    return $r
}

$version = Get-ESETVersion -ExePath $tool

# Build the command line per docs [1]/[2].
# Detect-only: NO /auto, NO /clean-mode override (default "none" = no
# cleaning). Log to our own temp file with /log-file + /no-log-console so the
# contract's "read the log file, never stdout" rule holds.
if (-not $TimeoutMinutes -or $TimeoutMinutes -lt 1) { $TimeoutMinutes = 120 }

$logFile = Join-Path (Get-TempRoot) ('ecls_scan_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
$baseDir = Join-Path (Split-Path -Parent $tool) 'Modules'

$argList = @('/subdir', '/no-log-console', ('/log-file="' + $logFile + '"'))
if (Test-Path -LiteralPath $baseDir) {
    $argList = @('/base-dir="' + $baseDir + '"') + $argList
}
$targets = @()
if ($ScanPath) {
    $targets += ('"' + $ScanPath + '"')
} else {
    # No targeted path: scan the fixed drives by passing each drive root as a
    # FILES... argument (doc [1] usage form: ecls [OPTIONS...] FILES...).
    try {
        $drives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Free -ne $null })
        foreach ($d in $drives) {
            if ($d.Name.Length -eq 1) { $targets += ('"' + $d.Name + ':\\"') }
        }
    } catch { }
    if (@($targets).Count -eq 0) { $targets = @('"C:\\"') }
}
$commandLine = ('"' + $tool + '" ' + (($argList + $targets) -join ' '))
# Exit-code mapping per doc [1]: 0 clean; 50 threat found; 10 partial scan
# failures (may be threats); 100 error; >100 file(s) not scanned. Codes 1/50
# would normally mean cleaning happened, but we never enable cleaning, so 1 is
# treated as unexpected and flagged.

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
    $run = Invoke-ProcessWithTimeout -FilePath $tool -ArgumentList ($argList + $targets) -TimeoutSeconds ($TimeoutMinutes * 60)
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
    switch ($exitCode) {
        0   { $status = 'Completed' }
        50  { $status = 'Completed'; $errors += 'Exit code 50: threat found (detect-only run, nothing cleaned).' }
        10  { $status = 'Completed'; $errors += 'Exit code 10: some files could not be scanned (may include threats).' }
        100 { $status = 'Failed'; $errors += 'Exit code 100: error during scan.' }
        default {
            if ($exitCode -gt 100) {
                $status = 'Completed'
                $errors += ('Exit code ' + $exitCode + ': file(s) were NOT scanned and can be infected (doc [1]).')
            } else {
                $status = 'Failed'
                $errors += ('Unexpected exit code ' + $exitCode + ' from ecls.exe.')
            }
        }
    }
}

# NOTE: no outer @() here. The Get-*Detections helpers already return
# ',$out' (comma-protected). Wrapping that again in @() produced a
# ONE-element array whose single element was the whole detection list,
# so New-Object -Property below got an array instead of a hashtable and
# the adapter crashed the moment a scan actually found something.
$detections = Get-DetectionsFromLog -LogFile $logFile

# Copy the scanner's own log into LogDir (contract: LogPath points at what we kept).
$logNote = ''
if ($LogDir) {
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        if (Test-Path -LiteralPath $logFile) {
            Copy-Item -LiteralPath $logFile -Destination $LogDir -Force
            $logNote = (Join-Path $LogDir (Split-Path -Leaf $logFile))
        }
    } catch {
        Write-AdapterLog ("Log copy failed: " + $_.Exception.Message)
    }
}
if ($null -ne $exitCode -and -not (Test-Path -LiteralPath $logFile)) {
    $errors += 'ecls log file was not created; outcome rests on exit code alone.'
}
# Unlicensed hint: an expired/unactivated ESET install typically errors out;
# surface it distinctly when the log says so rather than guessing up front.
if ($status -eq 'Failed' -and (Test-Path -LiteralPath $logFile)) {
    try {
        $content = (Get-Content -LiteralPath $logFile -ErrorAction SilentlyContinue) -join ' '
        if ($content -match '(?i)(licen[sc]e|activat)') {
            $status = 'Unlicensed'
            $errors += 'Log mentions license/activation; ESET install may be unlicensed (see docs/05 row ESET).'
        }
    } catch { }
}

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
    RebootRequired  = $false   # detect-only run: no cleaning actions, no reboot triggers
    Errors          = @($errors)
    CommandLine     = $commandLine
}
return $r
