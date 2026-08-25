# Invoke-DefenderScan.ps1
#
# Stage 5 scanner adapter: Microsoft Defender Antivirus via MpCmdRun.exe.
#
# DOCUMENTED SWITCHES ONLY -- verified against official Microsoft documentation,
# not written from memory (docs Q4 rule):
#   [1] "Configure and manage Microsoft Defender Antivirus with the MpCmdRun
#        command-line tool", Microsoft Learn:
#        https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
#        Documented there:
#          -Scan [-ScanType <0|1|2|3>] [-File <path>] [-DisableRemediation]
#                [-Timeout <days>] [-CpuThrottling] ...
#          Exit codes: 0 = no malware found OR found and successfully
#          remediated; 2 = malware found and not remediated / user action
#          required / scanning errors.
#          -DisableRemediation is valid only with custom scans (-ScanType 3):
#          actions are not applied after detection, detections are shown in
#          the command output instead of the UI.
#          MpCmdRun.exe locations on x64:
#            C:\Program Files\Windows Defender
#            C:\ProgramData\Microsoft\Windows Defender\Platform\<version>
#          (the Platform folder holds the newest version when present).
#   [2] "Get-MpThreatDetection", Microsoft Learn PowerShell reference:
#        https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection
#        Returns active and past threat detections. Backing WMI class
#        MSFT_MpThreatDetection exposes InitialDetectionTime, ThreatID,
#        Resources, ActionSuccess, RemediationTime (see also
#        https://powershell.one/wmi/root/microsoft/windows/defender/msft_mpthreatdetection).
#
# SAFETY MODEL (docs/06-safety-model.md):
#   - Read-only by default. The scan ALWAYS runs as a CUSTOM scan (-ScanType 3)
#     with -DisableRemediation, so Defender DETECTS but does NOT remove or
#     quarantine anything. Removal is Stage 4's job behind the approval gate.
#   - This is WHY the default (no -ScanPath) is a custom scan of the system
#     drive rather than a quick scan (-ScanType 1): -DisableRemediation is only
#     valid with custom scans per doc [1]. A quick scan cannot be made
#     detect-only, so using one would let Defender silently remediate -- a
#     direct violation of the safety model. We do not use quick scans.
#   - Scanner failure is non-fatal AND reported as failure (never a silent
#     "clean"). This script never throws to its caller.
#   - -WhatIf is genuinely safe: it reports availability + command line and
#     runs NOTHING.
#
# House rules: PS 5.1 compatible (no ternary, no ??, no &&, no -AsHashtable),
# pure ASCII, single .ps1 standalone-capable.

[CmdletBinding()]
param(
    [string]$ScanPath,              # optional targeted path -> custom scan; omit for quick scan
    [int]$TimeoutMinutes = 120,     # hard timeout per scanner (contract)
    [string]$LogDir,                # where to copy the scanner's own log output
    [string]$ToolPath,              # optional explicit path to MpCmdRun.exe
    [switch]$WhatIf                 # report availability + command line, run nothing
)

Set-StrictMode -Version 2.0

$script:ScannerName = 'MicrosoftDefender'

function Write-AdapterLog {
    param([string]$Message)
    $line = ('[{0}] [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $script:ScannerName, $Message)
    Write-Verbose $line
}

function New-ResultObject {
    param([hashtable]$Fields)
    return New-Object PSObject -Property @{
        ScannerName     = 'MicrosoftDefender'
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

# Locate MpCmdRun.exe. Prefer the newest platform version under
# ProgramData (per doc [1]), fall back to Program Files.
function Find-MpCmdRun {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (Test-Path -LiteralPath $ExplicitPath) { return $ExplicitPath }
        return $null
    }

    try {
    $candidates = @()
    $programData = $env:ProgramData
    if (-not $programData) { $programData = 'C:\ProgramData' }
    $programFiles = $env:ProgramFiles
    if (-not $programFiles) { $programFiles = 'C:\Program Files' }
    $platformRoot = Join-Path $programData 'Microsoft\Windows Defender\Platform' -ErrorAction SilentlyContinue
    if ($platformRoot -and (Test-Path -LiteralPath $platformRoot)) {
        $versions = @(Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending)
        foreach ($v in $versions) {
            $candidates += (Join-Path $v.FullName 'MpCmdRun.exe')
        }
    }
    $candidates += (Join-Path $programFiles 'Windows Defender\MpCmdRun.exe' -ErrorAction SilentlyContinue)
    $candidates = @($candidates | Where-Object { $_ })

    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    } catch { }
    return $null
}

# Version string for reporting: use Get-MpComputerStatus (doc-set [2]) when the
# Defender module is present; otherwise leave empty rather than guess.
function Get-DefenderVersion {
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $s = Get-MpComputerStatus -ErrorAction Stop
            if ($s.AMServiceVersion) { return [string]$s.AMServiceVersion }
        }
    } catch { }
    return ''
}

function Copy-ScanLogs {
    param(
        [string]$DestinationDir,
        [int]$SinceMinutes
    )
    if (-not $DestinationDir) { return '' }
    try {
        if (-not (Test-Path -LiteralPath $DestinationDir)) {
            New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }
        $supportRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Support'
        $cutoff = (Get-Date).AddMinutes(-1 * [Math]::Max($SinceMinutes, 5))
        $copied = @()
        if (Test-Path -LiteralPath $supportRoot) {
            $files = @(Get-ChildItem -LiteralPath $supportRoot -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cutoff } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 10)
            foreach ($f in $files) {
                Copy-Item -LiteralPath $f.FullName -Destination $DestinationDir -Force
                $copied += $f.Name
            }
        }
        return (@($copied) -join ', ')
    } catch {
        Write-AdapterLog ("Log copy failed: " + $_.Exception.Message)
        return ''
    }
}

# Map MpThreatDetection records into the contract's detection shape.
function Get-ThreatDetections {
    $out = @()
    try {
        if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
            $dets = @(Get-MpThreatDetection -ErrorAction Stop)
            foreach ($d in $dets) {
                $res = ''
                if ($null -ne $d.Resources) { $res = (@($d.Resources) -join '; ') }
                $action = ''
                if ($null -ne $d.ActionSuccess) {
                    if ($d.ActionSuccess) { $action = 'Succeeded' } else { $action = 'Failed' }
                }
                $sev = ''
                try {
                    if ($null -ne $d.ThreatID -and (Get-Command Get-MpThreatCatalog -ErrorAction SilentlyContinue)) {
                        $cat = Get-MpThreatCatalog -ThreatID $d.ThreatID -ErrorAction SilentlyContinue
                        if ($cat -and $cat.SeverityName) { $sev = [string]$cat.SeverityName }
                    }
                } catch { }
                $out += ,@{
                    Path       = $res
                    ThreatName = [string]$d.ThreatID
                    Severity   = $sev
                    Action     = $action
                }
            }
        }
    } catch {
        Write-AdapterLog ("Get-MpThreatDetection failed: " + $_.Exception.Message)
    }
    return ,$out
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$start = Get-Date
$errors = @()

$tool = Find-MpCmdRun -ExplicitPath $ToolPath

if (-not $tool) {
    $r = New-ResultObject @{
        Status       = 'NotInstalled'
        StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        EndTimeUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Errors       = @('MpCmdRun.exe not found (checked Platform versions and Program Files)')
    }
    return $r
}

$version = Get-DefenderVersion

# Build the command line per doc [1].
#   A targeted -ScanPath is given  -> custom scan (-ScanType 3) of that path.
#   No -ScanPath (default)         -> custom scan (-ScanType 3) of the system
#                                     drive (resolved below) with -DisableRemediation.
# In BOTH cases -DisableRemediation is passed, so the scan is detect-only.
# We deliberately NEVER use -ScanType 1 (quick scan): per doc [1]
# -DisableRemediation is valid only for custom scans, so a quick scan cannot be
# made read-only -- it would let Defender silently remediate and violate the
# safety model (docs/06).
if (-not $TimeoutMinutes -or $TimeoutMinutes -lt 1) { $TimeoutMinutes = 120 }

$scanType = '3'
if ($ScanPath) {
    $argList = @('-Scan', '-ScanType', $scanType, '-File', "`"$ScanPath`"", '-DisableRemediation')
} else {
    # Default: a custom scan needs an explicit target. Use the system drive
    # root (C:\ on Windows). On a non-Windows host this resolves harmlessly and
    # is only ever passed to MpCmdRun on a real Defender install anyway.
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }
    $argList = @('-Scan', '-ScanType', $scanType, '-File', "`"$systemDrive\`"", '-DisableRemediation')
}
$commandLine = ('"' + $tool + '" ' + ($argList -join ' '))

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

# Run the scan with a hard timeout (contract: a hung scanner must not hang the run).
$proc = $null
$timedOut = $false
try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $tool
    $psi.Arguments = ($argList -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
    }
    if (-not $proc.HasExited) {
        $timedOut = $true
        try { $proc.Kill() } catch { }
        $proc.WaitForExit(10000) | Out-Null
    }
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderrText = $proc.StandardError.ReadToEnd()
    $exitCode = $proc.ExitCode
} catch {
    $errors += ('Scan execution failed: ' + $_.Exception.Message)
    $exitCode = $null
}

$end = Get-Date
$duration = [int]($end - $start).TotalSeconds

$status = 'Failed'
if ($timedOut) {
    $status = 'Timeout'
} elseif ($null -ne $exitCode) {
    # Exit codes per doc [1]: 0 = clean/remediated; 2 = threats not remediated
    # or scanning errors. Anything else is an unexpected failure.
    if ($exitCode -eq 0 -or $exitCode -eq 2) { $status = 'Completed' }
    else {
        $status = 'Failed'
        $errors += ('Unexpected exit code ' + $exitCode + ' from MpCmdRun')
    }
}

# Collect detections AFTER the scan. With -DisableRemediation the custom-scan
# output lists detections; the durable record lives in threat history (doc [2]).
# NOTE: no outer @() here. The Get-*Detections helpers already return
# ',$out' (comma-protected). Wrapping that again in @() produced a
# ONE-element array whose single element was the whole detection list,
# so New-Object -Property below got an array instead of a hashtable and
# the adapter crashed the moment a scan actually found something.
$detections = Get-ThreatDetections
if ($exitCode -eq 2 -and @($detections).Count -eq 0) {
    $errors += 'Exit code 2 (threats found / errors) but no threat-detection records could be read.'
}

$logNote = ''
if ($status -ne 'NotInstalled') {
    $logNote = Copy-ScanLogs -DestinationDir $LogDir -SinceMinutes ([Math]::Max($duration / 60, 5))
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
    RebootRequired  = $false
    Errors          = @($errors)
    CommandLine     = $commandLine
}
return $r
