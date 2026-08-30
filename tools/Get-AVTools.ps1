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
    uninstalled via winget - `winget install -e --id Malwarebytes.Malwarebytes`
    / `winget uninstall -e --id Malwarebytes.Malwarebytes` (owner directive
    2026-08-27). No MBSetup.exe download happens anymore.)

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
        Invoke-WebRequest -Uri $Url -OutFile $part -UseBasicParsing -ErrorAction Stop
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
$null = Ensure-Tool -Url 'https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe' -Dest $kvrtPath -Label 'KVRT.exe (Kaspersky Virus Removal Tool)'

# --- ESET Online Scanner: fetch from ESET's official download host ---------
# The bootstrapper downloads current detection-engine modules on first run.
# GUI-only tool staged for attended technician use.
$null = Ensure-Tool -Url 'https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe' -Dest $eosPath -Label 'esetonlinescanner.exe (ESET Online Scanner, GUI-only)'

# --- Malwarebytes: NOT staged here (v1.7.3+). Installed/uninstalled via winget:
#   winget install -e --id Malwarebytes.Malwarebytes
#   winget uninstall -e --id Malwarebytes.Malwarebytes
# Owner directive 2026-08-27: replace the MBSetup.exe download + GUI launch
# with winget for both install and uninstall.

# NOTE (v1.7.22): there is NO internal-share/NAS fallback. Tools are staged
# exclusively from the official vendor URLs above; a failed download is a
# loud FAILED and the next run fetches fresh. The old internal-share copy
# path was removed - it staged stale/corrupt copies and caused field issues.

Say ''
Say ('Done. GUI scanners staged in ' + $ToolDir + ':') 'Cyan'
Say '  KVRT.exe, esetonlinescanner.exe' 'Cyan'
Say 'Malwarebytes is NOT staged here - install via winget:' 'Cyan'
Say '  winget install -e --id Malwarebytes.Malwarebytes' 'Cyan'
Say 'Run the staged scanners attended:' 'Cyan'
Say '  .\Invoke-GUIScanner.ps1 -Scanner KVRT' 'Cyan'
Say '  .\Invoke-GUIScanner.ps1 -Scanner ESET' 'Cyan'
Say 'The pipeline never invents silent-scan flags (owner decision 2026-08-26).' 'Cyan'
exit 0
