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
  v1.7.8 sanity threshold that rejects HTML error pages / partial downloads)
  is KEPT and skipped; only missing or corrupt/partial copies are downloaded.
  -Force bypasses the skip. This stops Step 1 from re-fetching ~150 MB of
  scanners every run when they are already on disk.

  PS 5.1 compatible. Pure ASCII, no BOM.
#>

param(
    [string]$ToolDir,
    [string]$InternalShare = '\\10.0.0.5\Public\Tools',
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

function Test-ToolUsable {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        return ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -ge $script:minToolBytes)
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
            Say ("  CORRUPT (under 1 MB - re-run staging to fetch a fresh copy): " + $p) 'Red'
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
    param([string]$Url, [string]$Dest, [string]$Label)
    Say ("Downloading " + $Label + "...")
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -ErrorAction Stop
        try {
            $item = Get-Item -LiteralPath $Dest
            $ver = $item.VersionInfo.FileVersion
            if ($ver) { Say ("       version: " + $ver + "  size: " + $item.Length) 'DarkGray' }
            # A real KVRT/EOS download is tens of MB. A tiny file means an HTML
            # error page or a partial/interrupted download; a corrupt exe would
            # then 'launch' silently and fail. Reject it so staging fails loudly
            # (observed: "KVRT no longer launches" = 0-byte/partial KVRT.exe).
            if ($item.Length -lt 1048576) {
                Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
                Say ("  FAILED: " + $Label + " looks incomplete (" + $item.Length + " bytes < 1 MB) - removed, re-run staging.") 'Yellow'
                return $false
            }
        } catch { }
        Say ("  OK: " + $Dest) 'Green'
        return $true
    } catch {
        Say ("  FAILED: " + $_.Exception.Message) 'Yellow'
        return $false
    }
}

# Ensure-Tool: download only when needed. A valid existing copy (>= 1 MB) is
# kept and skipped - Step 1 runs every session, and re-fetching ~150 MB of
# scanners each time is pointless. A corrupt/partial copy is removed and
# re-downloaded (heals the v1.7.8 "0-byte KVRT.exe" failure by itself).
# -Force bypasses the skip entirely.
function Ensure-Tool {
    param([string]$Url, [string]$Dest, [string]$Label)
    if (-not $Force) {
        if (Test-ToolUsable $Dest) {
            $sizeMb = [math]::Round((Get-Item -LiteralPath $Dest).Length / 1MB, 1)
            Say ("  already present (" + $sizeMb + " MB) - skipping download (use -Force to refresh)") 'Green'
            return $true
        }
        if (Test-Path -LiteralPath $Dest) {
            Say ("  existing copy is corrupt/partial (under 1 MB) - re-downloading") 'Yellow'
            Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
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

# --- Optional offline fallback: copy from an internal share if reachable --
# Never overwrites a file that was just downloaded from the official URL.
if ($InternalShare -and (Test-Path -LiteralPath $InternalShare)) {
    foreach ($pair in @(
        @('AV\KVRT.exe', $kvrtPath, 'KVRT'),
        @('AV\esetonlinescanner.exe', $eosPath, 'ESET Online Scanner')
    )) {
        $src = Join-Path $InternalShare $pair[0]
        if (-not (Test-Path -LiteralPath $src)) { continue }
        if (Test-Path -LiteralPath $pair[1]) {
            Say ("  (share) skipping " + $pair[2] + " - official download already staged.") 'DarkGray'
            continue
        }
        try {
            Copy-Item -LiteralPath $src -Destination $pair[1] -Force -ErrorAction Stop
            Say ("  OK (share): " + $pair[1]) 'Green'
        } catch {
            Say ("  FAILED to copy " + $pair[2] + ": " + $_.Exception.Message) 'Yellow'
        }
    }
}

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
