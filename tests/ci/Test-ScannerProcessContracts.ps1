<# 
  Test-ScannerProcessContracts.ps1 - CI contract for the Malwarebytes-only
  scanner line-up (owner decision 2026-08-26: drop KVRT, ESET, AdwCleaner,
  Defender). Replaces the old adapter-process test, which verified the
  now-deleted KVRT/ESET adapters.

  Contracts checked:
    1. Get-AVTools.ps1 stages exactly MBSetup.exe (no KVRT/ESET/AdwCleaner).
    2. Invoke-GUIScanner.ps1 accepts only -Scanner Malwarebytes.
    3. Invoke-GUIScanner.ps1 rejects -Scanner ESET/KVRT/AdwCleaner.

  PS 5.1 compatible. Pure ASCII, no BOM.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$avTools   = Join-Path $repoRoot 'tools\Get-AVTools.ps1'
$guiScanner = Join-Path $repoRoot 'Invoke-GUIScanner.ps1'

$script:failures = @()
function Add-Failure { param([string]$Message) $script:failures += $Message }

# --- Contract 1: stager stages only Malwarebytes -------------------------
Write-Host 'Section 1: Get-AVTools.ps1 stages Malwarebytes only'
if (-not (Test-Path -LiteralPath $avTools)) { Add-Failure 'Get-AVTools.ps1 missing.' }
else {
    $text = [System.IO.File]::ReadAllText($avTools)
    if ($text -match 'KVRT\.exe')            { Add-Failure 'Get-AVTools.ps1 still references KVRT.exe.' }
    if ($text -match 'esetonlinescanner\.exe'){ Add-Failure 'Get-AVTools.ps1 still references esetonlinescanner.exe.' }
    if ($text -match 'adwcleaner\.exe')      { Add-Failure 'Get-AVTools.ps1 still references adwcleaner.exe.' }
    if ($text -notmatch 'MBSetup\.exe')       { Add-Failure 'Get-AVTools.ps1 does not stage MBSetup.exe.' }
    if ($text -notmatch 'downloads\.malwarebytes\.com/file/mb-windows') {
        Add-Failure 'Get-AVTools.ps1 missing the Malwarebytes download URL.'
    }
    if ($failures.Count -eq 0) { Write-Host '  OK Get-AVTools.ps1: Malwarebytes only.' }
}

# --- Contracts 2/3: GUI scanner accepts only Malwarebytes ---------------
Write-Host 'Section 2: Invoke-GUIScanner.ps1 scanner set'
if (-not (Test-Path -LiteralPath $guiScanner)) { Add-Failure 'Invoke-GUIScanner.ps1 missing.' }
else {
    $text = [System.IO.File]::ReadAllText($guiScanner)
    if ($text -notmatch "ValidateSet\('Malwarebytes'\)") {
        Add-Failure 'Invoke-GUIScanner.ps1 ValidateSet does not restrict to Malwarebytes only.'
    } else { Write-Host '  OK Invoke-GUIScanner.ps1: ValidateSet = Malwarebytes only.' }
}

# --- Fail/exit ----------------------------------------------------------
if ($script:failures.Count -gt 0) {
    foreach ($f in $script:failures) { Write-Host ("FAIL: " + $f) -ForegroundColor Red }
    exit 1
}
Write-Host 'Scanner contracts OK: Malwarebytes-only line-up verified.' -ForegroundColor Green
exit 0
