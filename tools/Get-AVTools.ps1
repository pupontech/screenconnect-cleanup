<#
  Get-AVTools.ps1  -  Stage third-party AV scanners for the Stage 5 pass.

  Distinct from Get-ToolPack.ps1 (which stages Sysinternals diagnostic
  utilities as zips from download.sysinternals.com). This script stages the
  antivirus scanners the technician can run during Stage 5:

    KVRT.exe               Kaspersky Virus Removal Tool - downloaded fresh
                           from Kaspersky's official distribution URL every
                           run (KVRT is meant to be used current; it is not
                           versioned/pinned upstream). Staged for attended
                           technician use; no silent flags are invented here.

    esetonlinescanner.exe  ESET Online Scanner (consumer, GUI-only). No
                           officially documented unattended/silent scan
                           switches exist for this standalone consumer tool.
                           Downloaded fresh from ESET's official download host
                           for attended technician use.

    MBSetup.exe            Malwarebytes 5 consumer installer (GUI). No CLI;
                           staged for attended technician use.

    (AdwCleaner remains removed from staging by owner decision.)

  Usage:
    Get-AVTools.ps1 -ToolDir .\tools\AV
    Get-AVTools.ps1 -ToolDir .\tools\AV -Verify

  PS 5.1 compatible. Pure ASCII, no BOM.
#>

param(
    [string]$ToolDir,
    [string]$InternalShare = '\\10.0.0.5\Public\Tools',
    [switch]$Verify,
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

$kvrtPath = Join-Path $ToolDir 'KVRT.exe'
$eosPath  = Join-Path $ToolDir 'esetonlinescanner.exe'
$mbPath   = Join-Path $ToolDir 'MBSetup.exe'

if ($Verify) {
    $ok = $true
    foreach ($p in @($kvrtPath, $eosPath, $mbPath)) {
        if (Test-Path -LiteralPath $p) {
            Say ("  present: " + $p) 'Green'
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
        Say ("  OK: " + $Dest) 'Green'
        try {
            $item = Get-Item -LiteralPath $Dest
            $ver = $item.VersionInfo.FileVersion
            if ($ver) { Say ("       version: " + $ver + "  size: " + $item.Length) 'DarkGray' }
        } catch { }
        return $true
    } catch {
        Say ("  FAILED: " + $_.Exception.Message) 'Yellow'
        return $false
    }
}

# --- KVRT: always fetch fresh from Kaspersky's official URL ---------------
# Endpoint previously verified live as the official current KVRT distribution.
$null = Get-DownloadFile -Url 'https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe' -Dest $kvrtPath -Label 'KVRT.exe (Kaspersky Virus Removal Tool)'

# --- ESET Online Scanner: fetch fresh from ESET's official download host --
# The bootstrapper downloads current detection-engine modules on first run.
# GUI-only tool staged for attended technician use.
$null = Get-DownloadFile -Url 'https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe' -Dest $eosPath -Label 'esetonlinescanner.exe (ESET Online Scanner, GUI-only)'

# --- Malwarebytes: fetch fresh from Malwarebytes' official URL ------------
# downloads.malwarebytes.com/file/mb-windows/ redirects to the current MB5
# consumer installer. GUI installer staged for attended use.
$null = Get-DownloadFile -Url 'https://downloads.malwarebytes.com/file/mb-windows/' -Dest $mbPath -Label 'MBSetup.exe (Malwarebytes 5 consumer installer)'

# --- Optional offline fallback: copy from an internal share if reachable --
# Never overwrites a file that was just downloaded from the official URL.
if ($InternalShare -and (Test-Path -LiteralPath $InternalShare)) {
    foreach ($pair in @(
        @('AV\KVRT.exe', $kvrtPath, 'KVRT'),
        @('AV\esetonlinescanner.exe', $eosPath, 'ESET Online Scanner'),
        @('MBSetup.exe', $mbPath, 'Malwarebytes')
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
Say '  KVRT.exe, esetonlinescanner.exe, MBSetup.exe' 'Cyan'
Say 'Run each one attended:' 'Cyan'
Say '  .\Invoke-GUIScanner.ps1 -Scanner KVRT' 'Cyan'
Say '  .\Invoke-GUIScanner.ps1 -Scanner ESET' 'Cyan'
Say '  .\Invoke-GUIScanner.ps1 -Scanner Malwarebytes' 'Cyan'
Say 'The pipeline never invents silent-scan flags (owner decision 2026-08-26).' 'Cyan'
exit 0
