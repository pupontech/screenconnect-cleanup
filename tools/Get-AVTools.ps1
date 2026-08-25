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

    esetonlinescanner.exe   ESET Online Scanner (consumer, GUI-only). No
    MBSetup.exe             officially documented unattended/silent scan
                            switches for either of these, so this script
                            only STAGES them for a technician to run by
                            double-click during Stage 5 - it does not
                            invent CLI flags to drive them unattended.
                            Copied from the internal tools share when
                            available (-InternalShare), else left for the
                            technician to supply manually.

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

# --- KVRT: always fetch fresh from Kaspersky's official URL --------------
Say 'Downloading KVRT.exe (Kaspersky Virus Removal Tool)...'
try {
    Invoke-WebRequest -Uri 'https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe' -OutFile $kvrtPath -ErrorAction Stop
    Say ("  OK: " + $kvrtPath) 'Green'
} catch {
    Say ("  FAILED: " + $_.Exception.Message) 'Yellow'
}

# --- ESET Online Scanner + Malwarebytes: copy from the internal share ----
# if reachable. GUI-only tools, staged for attended use - not invoked by
# the automated pipeline.
if ($InternalShare -and (Test-Path -LiteralPath $InternalShare)) {
    $srcAv = Join-Path $InternalShare 'AV\esetonlinescanner.exe'
    if (Test-Path -LiteralPath $srcAv) {
        try {
            Copy-Item -LiteralPath $srcAv -Destination $eosPath -Force -ErrorAction Stop
            Say ("  OK: " + $eosPath + " (from " + $srcAv + ")") 'Green'
        } catch {
            Say ("  FAILED to copy ESET Online Scanner: " + $_.Exception.Message) 'Yellow'
        }
    } else {
        Say ("  ESET Online Scanner not found at " + $srcAv + " - skipping.") 'Yellow'
    }

    $srcMb = Join-Path $InternalShare 'MBSetup.exe'
    if (Test-Path -LiteralPath $srcMb) {
        try {
            Copy-Item -LiteralPath $srcMb -Destination $mbPath -Force -ErrorAction Stop
            Say ("  OK: " + $mbPath + " (from " + $srcMb + ")") 'Green'
        } catch {
            Say ("  FAILED to copy Malwarebytes: " + $_.Exception.Message) 'Yellow'
        }
    } else {
        Say ("  Malwarebytes installer not found at " + $srcMb + " - skipping.") 'Yellow'
    }
} else {
    Say ("Internal share not reachable (" + $InternalShare + ") - ESET Online Scanner and Malwarebytes must be staged manually into " + $ToolDir) 'Yellow'
}

Say ''
Say 'Done. KVRT.exe runs unattended via scanners\Invoke-KVRTScan.ps1 (Stage 5).' 'Cyan'
Say 'esetonlinescanner.exe and MBSetup.exe are GUI tools - no verified silent-scan' 'Cyan'
Say 'switches exist for either, so run them by hand from tools\AV\ if you want' 'Cyan'
Say 'that extra coverage; the automated pipeline does not launch them.' 'Cyan'
exit 0
