<#
  Get-AVTools.ps1  -  Stage third-party AV scanners for the Stage 5 pass.

  Distinct from Get-ToolPack.ps1 (which stages Sysinternals diagnostic
  utilities as zips from download.sysinternals.com). This script stages
  the actual antivirus SCANNERS Stage 5 can use:

    KVRT.exe               Kaspersky Virus Removal Tool - downloaded fresh
                           from Kaspersky's official distribution URL every
                           run (KVRT is meant to be used current; it is not
                           versioned/pinned upstream). Has a documented
                           silent CLI (-accepteula -silent), which
                           scanners\Invoke-KVRTScan.ps1 already drives.

    adwcleaner.exe         Malwarebytes AdwCleaner (free) - downloaded fresh
                           from Malwarebytes' official distribution URL every
                           run. Documented CLI (/eula /scan, see scanners\
                           Invoke-AdwCleanerScan.ps1) makes it drivable
                           unattended in detect-only mode.

    esetonlinescanner.exe  ESET Online Scanner (consumer, GUI-only). No
                           officially documented unattended/silent scan
                           switches exist (verified 2026-08-26 against
                           help.eset.com + ESET forums; ecls.exe from a
                           licensed endpoint install remains the only CLI
                           path). Downloaded fresh from ESET's official
                           download host for a technician to run by
                           double-click during Stage 5 - the automated
                           pipeline never launches it.

  Usage:
    Get-AVTools.ps1 -ToolDir .\tools\AV
    Get-AVTools.ps1 -ToolDir .\tools\AV -InternalShare '\\10.0.0.5\Public\Tools'
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

$kvrtPath   = Join-Path $ToolDir 'KVRT.exe'
$adwPath    = Join-Path $ToolDir 'adwcleaner.exe'
$eosPath    = Join-Path $ToolDir 'esetonlinescanner.exe'

if ($Verify) {
    $ok = $true
    foreach ($p in @($kvrtPath, $adwPath, $eosPath)) {
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
        return $true
    } catch {
        Say ("  FAILED: " + $_.Exception.Message) 'Yellow'
        return $false
    }
}

# --- KVRT: always fetch fresh from Kaspersky's official URL ---------------
# Endpoint verified live 2026-08-26 (HTTP 200, application/octet-stream).
$null = Get-DownloadFile -Url 'https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe' -Dest $kvrtPath -Label 'KVRT.exe (Kaspersky Virus Removal Tool)'

# --- AdwCleaner: always fetch fresh from Malwarebytes' official URL -------
# downloads.malwarebytes.com/file/adwcleaner/ 302-redirects to
# adwcleaner.malwarebytes.com (channel=release). Endpoint verified live
# 2026-08-26 (final HTTP 200, application/octet-stream, ~9.6 MB).
# Invoke-WebRequest follows redirects by default.
$null = Get-DownloadFile -Url 'https://downloads.malwarebytes.com/file/adwcleaner/' -Dest $adwPath -Label 'adwcleaner.exe (Malwarebytes AdwCleaner)'

# --- ESET Online Scanner: fetch fresh from ESET's official download host --
# GUI-only tool staged for attended technician use - not launched by the
# pipeline. Endpoint verified live 2026-08-26 (HTTP 200, ~8.4 MB).
$null = Get-DownloadFile -Url 'https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe' -Dest $eosPath -Label 'esetonlinescanner.exe (ESET Online Scanner, GUI-only)'

# --- Optional offline fallback: copy from an internal share if reachable --
if ($InternalShare -and (Test-Path -LiteralPath $InternalShare)) {
    foreach ($pair in @(@('AV\esetonlinescanner.exe', $eosPath, 'ESET Online Scanner'), @('MBSetup.exe', (Join-Path $ToolDir 'MBSetup.exe'), 'Malwarebytes'))) {
        $src = Join-Path $InternalShare $pair[0]
        if (Test-Path -LiteralPath $src) {
            try {
                Copy-Item -LiteralPath $src -Destination $pair[1] -Force -ErrorAction Stop
                Say ("  OK (share): " + $pair[1]) 'Green'
            } catch {
                Say ("  FAILED to copy " + $pair[2] + ": " + $_.Exception.Message) 'Yellow'
            }
        }
    }
}

Say ''
Say 'Done. Unattended-capable (driven by Stage 5 adapters):' 'Cyan'
Say '  KVRT.exe       -> scanners\Invoke-KVRTScan.ps1  (-accepteula -silent)' 'Cyan'
Say '  adwcleaner.exe -> scanners\Invoke-AdwCleanerScan.ps1  (/eula /scan)' 'Cyan'
Say 'Attended only (GUI, no documented CLI):' 'Cyan'
Say '  esetonlinescanner.exe -> technician double-click during Stage 5;' 'Cyan'
Say '  the automated pipeline does not launch it.' 'Cyan'
exit 0
