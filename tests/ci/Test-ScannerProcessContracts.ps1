<#
  Test-ScannerProcessContracts.ps1 - CI contract for the attended scanner
  line-up (owner update 2026-08-27: restore KVRT and ESET as official
  downloads; Malwarebytes install/uninstall via winget - no MBSetup.exe
  staging anymore; AdwCleaner and Defender remain removed).

  Contracts checked:
    1. Get-AVTools.ps1 stages KVRT.exe + esetonlinescanner.exe and does NOT
       stage MBSetup.exe; Malwarebytes is documented as winget-installed.
    2. Get-AVTools.ps1 uses official vendor download URLs, not stale shares as
       the primary source.
    3. Invoke-GUIScanner.ps1 accepts KVRT, ESET and Malwarebytes; KVRT/ESET
       are staged EXEs, Malwarebytes runs winget install (no MBSetup mapping)
       and then launches the installed Malwarebytes GUI (mbam.exe).
    4. Invoke-AVUninstaller.ps1 uninstalls Malwarebytes via winget.
    5. START-HERE.bat Step 6c installs Malwarebytes via winget and launches
       the Malwarebytes GUI (mbam.exe) after a successful install.

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

# --- Contract 1: stager stages KVRT / ESET (not MBSetup) ------------------
Write-Host 'Section 1: Get-AVTools.ps1 stages KVRT / ESET (Malwarebytes via winget)'
if (-not (Test-Path -LiteralPath $avTools)) { Add-Failure 'Get-AVTools.ps1 missing.' }
else {
    $text = [System.IO.File]::ReadAllText($avTools)
    if ($text -notmatch 'KVRT\.exe') { Add-Failure 'Get-AVTools.ps1 does not stage KVRT.exe.' }
    if ($text -notmatch 'esetonlinescanner\.exe') { Add-Failure 'Get-AVTools.ps1 does not stage esetonlinescanner.exe.' }
    if ($text -match '\$mbPath') { Add-Failure 'Get-AVTools.ps1 still defines the MBSetup staging target - Malwarebytes must be winget-only since v1.7.3.' }
    if ($text -match 'downloads\.malwarebytes\.com') { Add-Failure 'Get-AVTools.ps1 still downloads Malwarebytes - winget-only since v1.7.3.' }
    if ($text -notmatch 'winget install -e --id Malwarebytes\.Malwarebytes') { Add-Failure 'Get-AVTools.ps1 does not document the winget install for Malwarebytes.' }
    if ($text -match 'adwcleaner\.exe') { Add-Failure 'Get-AVTools.ps1 still references adwcleaner.exe.' }
    if ($text -notmatch 'devbuilds\.s\.kaspersky-labs\.com/kvrt/latest/full/KVRT\.exe') {
        Add-Failure 'Get-AVTools.ps1 missing the official KVRT download URL.'
    }
    if ($text -notmatch 'download\.eset\.com/com/eset/tools/online_scanner/latest/esetonlinescanner\.exe') {
        Add-Failure 'Get-AVTools.ps1 missing the official ESET Online Scanner download URL.'
    }
    if ($text -notmatch '\[switch\]\$Force') { Add-Failure 'Get-AVTools.ps1 missing the -Force re-download switch (skip-existing needs an explicit override).' }
    if ($text -notmatch 'skipping download') { Add-Failure 'Get-AVTools.ps1 does not skip an already-present valid tool copy.' }
    if ($text -notmatch 'corrupt/partial') { Add-Failure 'Get-AVTools.ps1 does not re-download corrupt/partial (under 1 MB) copies.' }
    if ($text -notmatch '1048576') { Add-Failure 'Get-AVTools.ps1 missing the 1 MB sanity threshold constant.' }
    if ($text -notmatch 'CORRUPT \(under 1 MB') { Add-Failure 'Get-AVTools.ps1 -Verify does not flag under-1-MB copies as corrupt.' }
    if ($text -notmatch 'function Test-PeExecutable') { Add-Failure 'Get-AVTools.ps1 missing the PE-header validity check (Test-PeExecutable) - a broken-but-big download would be skipped as "already present".' }
    if ($text -notmatch 'not a valid executable') { Add-Failure 'Get-AVTools.ps1 does not report corrupt PE files as such (not a valid executable).' }
    if ($text -notmatch '\$part = \$Dest \+ ''\.part''') { Add-Failure 'Get-AVTools.ps1 does not download to a .part staging file (atomic swap needed so a partial download cannot poison the staged exe).' }
    if ($text -notmatch 'Move-Item -LiteralPath \$part -Destination \$Dest') { Add-Failure 'Get-AVTools.ps1 does not atomically swap the .part file into place after the size check.' }
    if ($text -match 'Remove-Item -LiteralPath \$Dest') { Add-Failure 'Get-AVTools.ps1 deletes the destination BEFORE the download - a failed fetch leaves nothing staged (must keep the old file until a verified replacement exists).' }
    if ($script:failures.Count -eq 0) { Write-Host '  OK Get-AVTools.ps1: KVRT/ESET official downloads, Malwarebytes winget-only, skip-existing staging.' }
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
    if ($text -match "'Malwarebytes'\s*=\s*'MBSetup\.exe'") { Add-Failure 'Invoke-GUIScanner.ps1 still maps Malwarebytes to MBSetup.exe - winget-only since v1.7.3.' }
    if ($text -notmatch "'Malwarebytes'\s*=\s*'Malwarebytes\.Malwarebytes'") { Add-Failure 'Invoke-GUIScanner.ps1 missing Malwarebytes winget package id.' }
    if ($text -notmatch "'install', '-e', '--id'") { Add-Failure 'Invoke-GUIScanner.ps1 does not run winget install -e --id for Malwarebytes.' }
    if ($text -notmatch 'wingetViaCmd') { Add-Failure 'Invoke-GUIScanner.ps1 missing the winget alias-via-cmd launch (WindowsApps stub crashes Start-Process).' }
    if ($text -notmatch 'Start-Process returned no process handle') { Add-Failure 'Invoke-GUIScanner.ps1 missing the null-process guard after Start-Process.' }
    if ($text -notmatch "'Malwarebytes\\Anti-Malware\\mbam\.exe'") { Add-Failure 'Invoke-GUIScanner.ps1 does not launch the Malwarebytes GUI (mbam.exe) after a successful winget install.' }
    if ($text -notmatch '\$\{env:ProgramFiles\(x86\)\}') { Add-Failure 'Invoke-GUIScanner.ps1 missing the braced ${env:ProgramFiles(x86)} mbam.exe lookup (PS 5.1-safe).' }
    if ($text -notmatch 'Drive a scan in the Malwarebytes UI') { Add-Failure 'Invoke-GUIScanner.ps1 missing the Malwarebytes GUI attended-scan prompt.' }
    if ($text -notmatch 'Test-PeExecutable') { Add-Failure 'Invoke-GUIScanner.ps1 missing the launch-time PE-header guard - a corrupt staged exe would launch to nothing silently.' }
    if ($text -notmatch 'Scanner file is corrupt/truncated') { Add-Failure 'Invoke-GUIScanner.ps1 missing the corrupt-scanner error message.' }
    if ($text -notmatch '\$graceMs = 60000') { Add-Failure 'Invoke-GUIScanner.ps1 missing the 60s launch-grace probe - an instantly-exiting scanner would be reported as Completed.' }
    if ($text -notmatch 'ExitedEarly') { Add-Failure 'Invoke-GUIScanner.ps1 missing the ExitedEarly status - an early-exiting scanner must never count as a completed scan.' }
    if ($text -notmatch "Join-Path \`$scriptRoot \('tools\\AV\\' \+ \`$name\)") {
        Add-Failure 'Invoke-GUIScanner.ps1 does not search tools\\AV\\ (Get-AVTools.ps1 default staging sibling).'
    }
    if ($script:failures.Count -eq 0) { Write-Host '  OK Invoke-GUIScanner.ps1: ValidateSet = KVRT/ESET/Malwarebytes; Malwarebytes via winget + GUI launch.' }
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
    if ($text -notmatch 'winget uninstall -e --id ') { Add-Failure 'Invoke-AVUninstaller.ps1 does not run winget uninstall -e --id for winget-managed products.' }
    if ($text -notmatch "'Malwarebytes'\s*=\s*'Malwarebytes\.Malwarebytes'") { Add-Failure 'Invoke-AVUninstaller.ps1 missing the Malwarebytes winget package id.' }
    if ($text -notmatch 'function Clear-ProductLeftovers') { Add-Failure 'Invoke-AVUninstaller.ps1 missing the leftover sweep (Clear-ProductLeftovers).' }
    if ($text -notmatch 'av-uninstall-quarantine') { Add-Failure 'Invoke-AVUninstaller.ps1 missing the av-uninstall-quarantine destination.' }
    if ($text -notmatch 'NoLeftoverSweep') { Add-Failure 'Invoke-AVUninstaller.ps1 missing the -NoLeftoverSweep opt-out.' }
    if ($codeOnly -match 'Remove-Item') { Add-Failure 'Invoke-AVUninstaller.ps1 deletes instead of quarantining - the sweep must Move-Item only.' }
    if ($script:failures.Count -eq 0) { Write-Host '  OK Invoke-AVUninstaller.ps1: attended-only, Defender excluded, Malwarebytes via winget, quarantine sweep.' }
}

# --- Contract 4: START-HERE.bat Step 6c launches Malwarebytes after install --
Write-Host 'Section 4: START-HERE.bat Step 6c installs then launches Malwarebytes'
$startHere = Join-Path $repoRoot 'START-HERE.bat'
if (-not (Test-Path -LiteralPath $startHere)) { Add-Failure 'START-HERE.bat missing.' }
else {
    $text = [System.IO.File]::ReadAllText($startHere)
    if ($text -notmatch 'winget install -e --id Malwarebytes\.Malwarebytes') { Add-Failure 'START-HERE.bat Step 6c does not run winget install for Malwarebytes.' }
    if ($text -notmatch 'start "" "%MBAMEXE%"') { Add-Failure 'START-HERE.bat Step 6c does not launch Malwarebytes (start "" "%MBAMEXE%") after install.' }
    if ($text -notmatch ':mbam_found') { Add-Failure 'START-HERE.bat Step 6c missing the :mbam_found launch label.' }
    if ($text -notmatch '%ProgramFiles\(x86\)%\\Malwarebytes') { Add-Failure 'START-HERE.bat Step 6c missing the Program Files (x86) mbam.exe fallback path.' }
    if ($script:failures.Count -eq 0) { Write-Host '  OK START-HERE.bat: Step 6c installs Malwarebytes via winget, then launches the GUI.' }
}

# --- Fail/exit ----------------------------------------------------------
if ($script:failures.Count -gt 0) {
    foreach ($f in $script:failures) { Write-Host ("FAIL: " + $f) -ForegroundColor Red }
    exit 1
}
Write-Host 'Scanner contracts OK: KVRT/ESET/Malwarebytes attended line-up verified.' -ForegroundColor Green
exit 0
