<# 
  Get-AVTools.ps1  -  Stage the Malwarebytes scanner for the Stage 5 pass.

  Distinct from Get-ToolPack.ps1 (which stages Sysinternals diagnostic
  utilities as zips from download.sysinternals.com). This script stages
  the single antivirus scanner the tool uses (owner decision 2026-08-26:
  Malwarebytes only; KVRT, ESET, AdwCleaner, and Defender were all
  removed from scope):

    MBSetup.exe            Malwarebytes 5 consumer installer (GUI). No CLI;
                           staged for attended use via Invoke-GUIScanner.

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

$mbPath     = Join-Path $ToolDir 'MBSetup.exe'

if ($Verify) {
    if (Test-Path -LiteralPath $mbPath) {
        Say ("  present: " + $mbPath) 'Green'
        exit 0
    } else {
        Say ("  MISSING: " + $mbPath) 'Red'
        exit 1
    }
}

function Get-DownloadFile {
    param([string]$Url, [string]$Dest, [string]$Label)
    Say ("Downloading " + $Label + "...")
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -ErrorAction Stop
        Say ("  OK: " + $Dest) 'Green'
        try {
            $ver = (Get-Item -LiteralPath $Dest).VersionInfo.FileVersion
            if ($ver) { Say ("       version: " + $ver + "  size: " + (Get-Item -LiteralPath $Dest).Length) 'DarkGray' }
        } catch { }
        return $true
    } catch {
        Say ("  FAILED: " + $_.Exception.Message) 'Yellow'
        return $false
    }
}

# --- Malwarebytes: fetch fresh from Malwarebytes' official URL ------------
# downloads.malwarebytes.com/file/mb-windows/ 302-redirects to
# data-cdn.mbamupdates.com/web/mb5-setup-consumer/MBSetup.exe (the current
# MB5 consumer installer). Endpoint verified live 2026-08-26 (HTTP 200,
# FileVersion 5.6.x). GUI installer staged for attended use.
$null = Get-DownloadFile -Url 'https://downloads.malwarebytes.com/file/mb-windows/' -Dest $mbPath -Label 'MBSetup.exe (Malwarebytes 5 consumer installer)'

Say ''
Say ('Done. Scanner staged in ' + $ToolDir + ':') 'Cyan'
Say '  MBSetup.exe (Malwarebytes 5)' 'Cyan'
Say 'Run it attended:' 'Cyan'
Say '  .\Invoke-GUIScanner.ps1 -Scanner Malwarebytes' 'Cyan'
Say 'The pipeline never invents silent-scan flags (owner decision 2026-08-26).' 'Cyan'
exit 0
