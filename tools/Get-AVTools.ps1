<#
  Get-AVTools.ps1  -  Stage third-party AV scanners for the Stage 5 pass.

  Distinct from Get-ToolPack.ps1 (which stages Sysinternals diagnostic
  utilities as zips from download.sysinternals.com). This script stages the
  antivirus scanners the technician can run during Stage 5:

    KVRT.exe               Kaspersky Virus Removal Tool - downloaded from
                           Kaspersky's official distribution URL when missing
                           or corrupt (KVRT is meant to be used current; it is
                           not versioned/pinned upstream). An already-staged
                           valid copy is skipped. Staged for attended
                           technician use; no silent flags are invented here.

    esetonlinescanner.exe  ESET Online Scanner (consumer, GUI-only). No
                           officially documented unattended/silent scan
                           switches exist for this standalone consumer tool.
                           Downloaded when missing or corrupt; an already
                           staged valid copy is skipped. Staged for attended
                           technician use.

    (Malwarebytes is no longer staged here: since v1.7.3 it is installed and
    uninstalled via winget - `winget install -e --id Malwarebytes.Malwarebytes
    --accept-package-agreements --accept-source-agreements` / `winget uninstall
    -e --id Malwarebytes.Malwarebytes --accept-package-agreements
    --accept-source-agreements` (owner directive 2026-08-27; agreements are
    accepted by default since v1.7.24). No MBSetup.exe download happens
    anymore.)

    (AdwCleaner remains removed from staging by owner decision.)

  Usage:
    Get-AVTools.ps1 -ToolDir .\tools\AV
    Get-AVTools.ps1 -ToolDir .\tools\AV -Verify
    Get-AVTools.ps1 -ToolDir .\tools\AV -Force     # re-download even if present

  Download policy: a tool already staged as a valid copy (at least 1 MB - the
  v1.7.8 sanity threshold that rejects HTML error pages / partial downloads,
  plus the v1.7.17 PE-header check) is KEPT and skipped; only missing or
  corrupt/partial copies are downloaded. -Force bypasses the skip. This stops
  Step 1 from re-fetching ~150 MB of scanners every run when they are already
  on disk. There is NO internal-share/NAS fallback (removed v1.7.22): every
  download comes fresh from the official vendor URLs above.

  PS 5.1 compatible. Pure ASCII, no BOM.
#>

param(
    [string]$ToolDir,
    [switch]$Verify,
    [switch]$Force,
    [switch]$Quiet
)

# The rendered progress bar is THE classic PowerShell large-download
# slowdown: Invoke-WebRequest redraws it per buffer and can halve or worse
# the throughput of a 100MB+ file on PS 5.1. Kill it script-wide; BITS and
# the fallback both report nothing either way (v1.7.25).
$ProgressPreference = 'SilentlyContinue'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $ToolDir) {
    $ToolDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'AV'
}
if (-not (Test-Path -LiteralPath $ToolDir)) {
    $null = New-Item -ItemType Directory -Path $ToolDir -Force
}

function Say {
    param([string]$Message, [string]$Color = 'Gray')
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}

# v1.7.8 sanity threshold: a real scanner download is tens of MB. Anything
# under 1 MB is an HTML error page or a partial/interrupted download - the
# "KVRT downloaded but does not launch" failure mode. A copy is only
# considered usable (and therefore skippable) when it is at least this big.
$script:minToolBytes = 1048576

function Test-PeExecutable {
    # Cheap structural validity check: a real Windows PE starts with 'MZ' and
    # carries the 'PE\0\0' signature at the offset stored in e_lfanew (0x3C).
    # A partial/interrupted download can pass a SIZE check while still being
    # broken ("KVRT downloaded but does not launch" - the observed failure);
    # only a structurally valid PE is treated as a usable, skippable copy.
    param([string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $buf = New-Object byte[] 4096
            $n = $fs.Read($buf, 0, 4096)
            if ($n -lt 64) { return $false }
            if ($buf[0] -ne 0x4D -or $buf[1] -ne 0x5A) { return $false }   # 'MZ'
            $peOff = [BitConverter]::ToInt32($buf, 0x3C)
            if ($peOff -lt 0 -or ($peOff + 4) -gt $n) { return $false }
            return ($buf[$peOff] -eq 0x50 -and $buf[$peOff + 1] -eq 0x45 -and
                    $buf[$peOff + 2] -eq 0 -and $buf[$peOff + 3] -eq 0)    # 'PE\0\0'
        } finally {
            $fs.Dispose()
        }
    } catch {
        return $false
    }
}

function Test-ToolUsable {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.Length -lt $script:minToolBytes) { return $false }
        return (Test-PeExecutable -Path $Path)
    } catch {
        return $false
    }
}

$kvrtPath = Join-Path $ToolDir 'KVRT.exe'
$eosPath  = Join-Path $ToolDir 'esetonlinescanner.exe'

if ($Verify) {
    $ok = $true
    foreach ($p in @($kvrtPath, $eosPath)) {
        if (Test-ToolUsable $p) {
            Say ("  present: " + $p) 'Green'
        } elseif (Test-Path -LiteralPath $p) {
            Say ("  CORRUPT (under 1 MB or not a valid executable - re-run staging to fetch a fresh copy): " + $p) 'Red'
            $ok = $false
        } else {
            Say ("  MISSING: " + $p) 'Red'
            $ok = $false
        }
    }
    if (-not $ok) { exit 1 }
    exit 0
}

function Start-DownloadFast {
    # Download helper for the big scanner files (KVRT is ~114 MB):
    # 1. BITS (Start-BitsTransfer, every Windows 10/11) - the OS transfer
    #    engine. Far faster than Invoke-WebRequest for 100MB+ files and
    #    network-aware. Run ASYNCHRONOUSLY and poll for a live progress line
    #    (the synchronous form shows nothing for the whole transfer).
    #    If it fails (403/UA rejection, BITS disabled by policy, service
    #    stopped) fall through to Invoke-WebRequest.
    # 2. Invoke-WebRequest with the browser-like UA and the progress bar
    #    suppressed (see $ProgressPreference above). Also the path used by
    #    pwsh on Linux, which keeps CI functional tests meaningful.
    param([string]$Url, [string]$OutFile, [string]$Label)
    $bits = Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue
    if ($bits -and $env:OS -eq 'Windows_NT') {
        try {
            Say ("  (BITS) " + $Label) 'DarkGray'
            $job = Start-BitsTransfer -Source $Url -Destination $OutFile -DisplayName ('ScreenConnect-Cleanup: ' + $Label) -Asynchronous -ErrorAction Stop
            $deadline = (Get-Date).AddMinutes(20)
            $lastPct = -1
            $nextReport = 25
            $sizeUnknown = $true
            do {
                Start-Sleep -Seconds 1
                $job = Get-BitsTransfer -JobId $job.JobId -ErrorAction SilentlyContinue
                if (-not $job) { break }
                $pct = 0
                if ($job.TotalBytes -gt 0) {
                    $pct = [math]::Round(($job.BytesTransferred / $job.TotalBytes) * 100)
                    # Throttle progress to 25/50/75/100% (and only when visible).
                    if (-not $Quiet -and $pct -ne $lastPct -and $pct -ge $nextReport) {
                        $lastPct = $pct
                        $mb = [math]::Round($job.BytesTransferred / 1MB, 1)
                        $tmb = [math]::Round($job.TotalBytes / 1MB, 1)
                        Write-Host ("`r  " + $Label + ": " + $pct + "% (" + $mb + " / " + $tmb + " MB)   ") -NoNewline
                        $nextReport = (([math]::Floor($pct / 25)) + 1) * 25
                    }
                    $sizeUnknown = $false
                } elseif ($sizeUnknown -and -not $Quiet) {
                    Write-Host ("`r  " + $Label + ": waiting for BITS size info...   ") -NoNewline
                }
            } while ($job -and $job.JobState -in @('Queued', 'Connecting', 'Transferring', 'TransientError') -and (Get-Date) -lt $deadline)
            if (-not $Quiet) { Write-Host "" }
            if (-not $job) { throw 'BITS job disappeared' }
            if ($job.JobState -eq 'Transferred') {
                Complete-BitsTransfer -BitsJob $job -ErrorAction Stop
            } elseif ($job.JobState -eq 'Error') {
                throw ('BITS error: ' + $job.ErrorDescription)
            } else {
                throw ('BITS did not finish: state=' + $job.JobState)
            }
            return
        } catch {
            Say ("  BITS failed (" + $_.Exception.Message + ") - falling back to Invoke-WebRequest.") 'Yellow'
            # Remove only the partial transfer target (the .part staging file),
            # never the final staged tool - the anti-clobber contract stands.
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        }
    }
    $headers = @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36' }
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers $headers -TimeoutSec 900 -ErrorAction Stop
}

function Get-DownloadFile {
    # Download to <name>.part and swap it into place ONLY after the size
    # sanity check passes. An interrupted/partial download can therefore
    # never leave a broken KVRT.exe / esetonlinescanner.exe at the final
    # path - the previous copy (or its absence) stays untouched until a
    # verified replacement exists. Before this, a partial file AT the real
    # path made the skip check fail forever: every Step 1 run saw a
    # sub-1-MB file, deleted it and re-downloaded (the "still redownloading
    # the AVs" loop). A leftover .part from a killed run is simply
    # overwritten on the next attempt.
    param([string]$Url, [string]$Dest, [string]$Label)
    $part = $Dest + '.part'
    Say ("Downloading " + $Label + "...")
    try {
        Start-DownloadFast -Url $Url -OutFile $part -Label $Label
        try {
            $item = Get-Item -LiteralPath $part -ErrorAction Stop
            $ver = $item.VersionInfo.FileVersion
            if ($ver) { Say ("       version: " + $ver + "  size: " + $item.Length) 'DarkGray' }
            # A real KVRT/EOS download is tens of MB. A tiny file means an HTML
            # error page or a partial/interrupted download; a larger file can
            # still be a truncated download. Validate the PE header too, so a
            # corrupt exe can never be swapped in (it would 'launch' silently
            # and fail - the "KVRT no longer launches" failure mode).
            if ($item.Length -lt 1048576 -or -not (Test-PeExecutable -Path $part)) {
                Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
                Say ("  FAILED: " + $Label + " looks incomplete or corrupt (" + $item.Length + " bytes, not a valid executable) - removed, re-run staging.") 'Yellow'
                return $false
            }
        } catch { }
        # Swap into place only after the sanity check passed. -Force also
        # replaces a corrupt copy from an older run.
        Move-Item -LiteralPath $part -Destination $Dest -Force -ErrorAction Stop
        Say ("  OK: " + $Dest) 'Green'
        return $true
    } catch {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        Say ("  FAILED: " + $_.Exception.Message) 'Yellow'
        return $false
    }
}

# Ensure-Tool: download only when needed. A valid existing copy (>= 1 MB) is
# kept and skipped - Step 1 runs every session, and re-fetching ~150 MB of
# scanners each time is pointless. A corrupt/partial copy is NOT deleted up
# front: Get-DownloadFile swaps atomically, so a failed fetch keeps whatever
# was already there instead of leaving nothing. -Force bypasses the skip.
function Ensure-Tool {
    param([string]$Url, [string]$Dest, [string]$Label)
    if (-not $Force) {
        if (Test-ToolUsable $Dest) {
            $sizeMb = [math]::Round((Get-Item -LiteralPath $Dest).Length / 1MB, 1)
            Say ("  already present (" + $sizeMb + " MB) - skipping download (use -Force to refresh)") 'Green'
            return $true
        }
        if (Test-Path -LiteralPath $Dest) {
            Say ("  existing copy is corrupt/partial (under 1 MB or not a valid executable) - fetching a fresh copy") 'Yellow'
        } else {
            Say ("  not staged in " + $ToolDir + " yet - downloading") 'DarkGray'
        }
    }
    return (Get-DownloadFile -Url $Url -Dest $Dest -Label $Label)
}

# --- KVRT: fetch from Kaspersky's official URL when missing/corrupt --------
# Endpoint previously verified live as the official current KVRT distribution.
$failures = @()
if (-not (Ensure-Tool -Url 'https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe' -Dest $kvrtPath -Label 'KVRT.exe (Kaspersky Virus Removal Tool)')) {
    $failures += 'KVRT.exe'
}

# --- ESET Online Scanner: fetch from ESET's official download host ---------
# The bootstrapper downloads current detection-engine modules on first run.
# GUI-only tool staged for attended technician use.
if (-not (Ensure-Tool -Url 'https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe' -Dest $eosPath -Label 'esetonlinescanner.exe (ESET Online Scanner, GUI-only)')) {
    $failures += 'esetonlinescanner.exe'
}

# --- Malwarebytes: NOT staged here (v1.7.3+). Installed/uninstalled via winget:
#   winget install -e --id Malwarebytes.Malwarebytes --accept-package-agreements --accept-source-agreements
#   winget uninstall -e --id Malwarebytes.Malwarebytes --accept-package-agreements --accept-source-agreements
# Owner directive 2026-08-27: replace the MBSetup.exe download + GUI launch
# with winget for both install and uninstall. Agreements accepted by default
# (owner directive 2026-08-28).

# NOTE (v1.7.22): there is NO internal-share/NAS fallback. Tools are staged
# exclusively from the official vendor URLs above; a failed download is a
# loud FAILED and the next run fetches fresh. The old internal-share copy
# path was removed - it staged stale/corrupt copies and caused field issues.

Say ''
Say ('Done. GUI scanners staged in ' + $ToolDir + ': KVRT.exe, esetonlinescanner.exe') 'Cyan'
Say 'Malwarebytes installs via winget: winget install -e --id Malwarebytes.Malwarebytes --accept-package-agreements --accept-source-agreements' 'Cyan'
if ($failures.Count -gt 0) {
    Say ("FAILED to stage: " + ($failures -join ', ') + " - re-run Step 1 to retry. A failed download is never reported as success (v1.7.23).") 'Yellow'
    exit 1
}
exit 0
