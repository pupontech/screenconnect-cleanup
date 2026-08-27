<#
  Test-ScannerProcessContracts.ps1 - CI contract for the attended GUI scanner
  line-up (owner update 2026-08-27: restore KVRT and ESET as official downloads;
  keep Malwarebytes; AdwCleaner and Defender remain removed).

  Contracts checked:
    1. Get-AVTools.ps1 stages KVRT.exe, esetonlinescanner.exe and MBSetup.exe.
    2. Get-AVTools.ps1 uses official vendor download URLs, not stale shares as
       the primary source.
    3. Invoke-GUIScanner.ps1 accepts KVRT, ESET and Malwarebytes, and still
       excludes AdwCleaner/Defender.

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

# --- Contract 1: stager stages KVRT / ESET / Malwarebytes -----------------
Write-Host 'Section 1: Get-AVTools.ps1 stages KVRT / ESET / Malwarebytes'
if (-not (Test-Path -LiteralPath $avTools)) { Add-Failure 'Get-AVTools.ps1 missing.' }
else {
    $text = [System.IO.File]::ReadAllText($avTools)
    if ($text -notmatch 'KVRT\.exe') { Add-Failure 'Get-AVTools.ps1 does not stage KVRT.exe.' }
    if ($text -notmatch 'esetonlinescanner\.exe') { Add-Failure 'Get-AVTools.ps1 does not stage esetonlinescanner.exe.' }
    if ($text -notmatch 'MBSetup\.exe') { Add-Failure 'Get-AVTools.ps1 does not stage MBSetup.exe.' }
    if ($text -match 'adwcleaner\.exe') { Add-Failure 'Get-AVTools.ps1 still references adwcleaner.exe.' }
    if ($text -notmatch 'devbuilds\.s\.kaspersky-labs\.com/kvrt/latest/full/KVRT\.exe') {
        Add-Failure 'Get-AVTools.ps1 missing the official KVRT download URL.'
    }
    if ($text -notmatch 'download\.eset\.com/com/eset/tools/online_scanner/latest/esetonlinescanner\.exe') {
        Add-Failure 'Get-AVTools.ps1 missing the official ESET Online Scanner download URL.'
    }
    if ($text -notmatch 'downloads\.malwarebytes\.com/file/mb-windows') {
        Add-Failure 'Get-AVTools.ps1 missing the Malwarebytes download URL.'
    }
    if ($script:failures.Count -eq 0) { Write-Host '  OK Get-AVTools.ps1: KVRT/ESET/Malwarebytes official downloads.' }
}

# --- Contract 2: GUI scanner accepts exactly the attended scanner set -------
Write-Host 'Section 2: Invoke-GUIScanner.ps1 scanner set'
if (-not (Test-Path -LiteralPath $guiScanner)) { Add-Failure 'Invoke-GUIScanner.ps1 missing.' }
else {
    $text = [System.IO.File]::ReadAllText($guiScanner)
    if ($text -notmatch "ValidateSet\('KVRT', 'ESET', 'Malwarebytes'\)") {
        Add-Failure 'Invoke-GUIScanner.ps1 ValidateSet is not KVRT/ESET/Malwarebytes.'
    }
    if ($text -match "'AdwCleaner'|adwcleaner\.exe") {
        Add-Failure 'Invoke-GUIScanner.ps1 still references AdwCleaner.'
    }
    if ($text -notmatch "'KVRT'\s*=\s*'KVRT\.exe'") { Add-Failure 'Invoke-GUIScanner.ps1 missing KVRT tool mapping.' }
    if ($text -notmatch "'ESET'\s*=\s*'esetonlinescanner\.exe'") { Add-Failure 'Invoke-GUIScanner.ps1 missing ESET tool mapping.' }
    if ($text -notmatch "'Malwarebytes'\s*=\s*'MBSetup\.exe'") { Add-Failure 'Invoke-GUIScanner.ps1 missing Malwarebytes tool mapping.' }
    if ($script:failures.Count -eq 0) { Write-Host '  OK Invoke-GUIScanner.ps1: ValidateSet = KVRT/ESET/Malwarebytes.' }
}

# --- Contract 3: AV-uninstaller is attended-only (never silent) ----------
Write-Host 'Section 3: Invoke-AVUninstaller.ps1 (attended AV removal)'
$avUninstaller = Join-Path $repoRoot 'Invoke-AVUninstaller.ps1'
if (-not (Test-Path -LiteralPath $avUninstaller)) { Add-Failure 'Invoke-AVUninstaller.ps1 missing.' }
else {
    $text = [System.IO.File]::ReadAllText($avUninstaller)
    if ($text -notmatch 'function Get-InstalledAv') { Add-Failure 'Invoke-AVUninstaller.ps1 missing Get-InstalledAv discovery.' }
    if ($text -notmatch 'function Open-Uninstaller') { Add-Failure 'Invoke-AVUninstaller.ps1 missing Open-Uninstaller launch+wait.' }
    $codeOnly = $text -replace '(?s)<#.*?#>', '' -replace '(?m)^\s*#.*$', ''
    if ($codeOnly -match '/quiet|/silent|/passive|/S\s|/S"') { Add-Failure 'Invoke-AVUninstaller.ps1 appears to pass silent uninstall flags - must be attended only.' }
    if ($text -match 'Windows Defender' -and $text -notmatch 'osExclude') { Add-Failure 'Invoke-AVUninstaller.ps1 does not exclude Windows Defender from removal.' }
    if ($script:failures.Count -eq 0) { Write-Host '  OK Invoke-AVUninstaller.ps1: attended-only, Defender excluded.' }
}

# --- Fail/exit ----------------------------------------------------------
if ($script:failures.Count -gt 0) {
    foreach ($f in $script:failures) { Write-Host ("FAIL: " + $f) -ForegroundColor Red }
    exit 1
}
Write-Host 'Scanner contracts OK: KVRT/ESET/Malwarebytes attended line-up verified.' -ForegroundColor Green
exit 0
