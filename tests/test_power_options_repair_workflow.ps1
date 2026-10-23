# test_power_options_repair_workflow.ps1 - CLI-only flow and reboot-order contracts.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$startHere = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'START-HERE.bat'))
$cleanup = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'sc-cleanup.ps1'))
$report = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'New-InvestigationReport.ps1'))
$failures = 0
function Check {
    param([string]$Name, [bool]$Condition)
    if ($Condition) { Write-Host ("PASS  " + $Name) }
    else { Write-Host ("FAIL  " + $Name); $script:failures++ }
}

$startRepair = $startHere.IndexOf('Repair missing power options now? [y/N]')
$startAfterSnapshot = $startHere.IndexOf('-Label after')
$startReportOpen = $startHere.IndexOf('start "" "!SCC_RUN_ROOT!/report.html"')
$startRebootPrompt = $startHere.IndexOf('Restart now through CMD? [y/N]')
$startRebootCommand = $startHere.IndexOf('cmd.exe /d /c "shutdown /r /t 0 /f"')
Check 'guided runner repairs before its after snapshot' ($startRepair -ge 0 -and $startAfterSnapshot -gt $startRepair)
Check 'guided repair is opt-in with default No and prompt variable is cleared' ($startHere.Contains('set "GO="' + "`r`n" + 'set /p GO="    Repair missing power options now? [y/N] "') -and $startHere.Contains('if /i not "!GO!"=="y" goto :skip_power_repair'))
Check 'local GPO reset has a separate default-No prompt and explicit switch' ($startHere.Contains('set "RESET_GPO="' + "`r`n" + 'set /p RESET_GPO="    Back up, then reset local Group Policy folders? [y/N] "') -and $startHere.Contains('-ResetLocalGpo'))
Check 'guided reboot is gated by repair, report generation, and successful launch' ($startHere.Contains('if not "!POWER_REPAIR_RAN!"=="1" goto :skip_optional_reboot') -and $startHere.Contains('if not "!REPORT_RC!"=="0" goto :skip_optional_reboot') -and $startHere.Contains('if not "!REPORT_OPENED!"=="1" goto :skip_optional_reboot'))
Check 'guided repair evidence is required, not just a launch attempt' ($startHere -notmatch '(?m)^set "POWER_REPAIR_RAN=1"\r?$' -and $startHere.Contains('if exist "!SCC_RUN_ROOT!\power-options-repair.json" set "POWER_REPAIR_RAN=1"'))
Check 'guided forced reboot command follows default-No choice and warns of unsaved work' ($startRebootCommand -gt $startRebootPrompt -and $startHere.Contains('may lose unsaved work'))

$cleanupRepair = $cleanup.IndexOf("Running the consented power-options repair")
$cleanupAfterSnapshot = $cleanup.IndexOf("Running collect-snapshot.ps1 -Label after")
$cleanupReportOpen = $cleanup.IndexOf('Start-Process -FilePath $reportHtml')
$cleanupRebootPrompt = $cleanup.IndexOf('Restart now from CMD? [y/N]')
$cleanupRebootCommand = $cleanup.IndexOf("shutdown /r /t 0 /f'")
Check 'CLI runner exposes the opt-in repair and managed-device guard' ($cleanup.Contains('$RepairPowerOptions') -and $cleanup.Contains('$AllowManagedDevice'))
Check 'CLI repair runs before the after snapshot' ($cleanupRepair -ge 0 -and $cleanupAfterSnapshot -gt $cleanupRepair)
Check 'CLI reboot choice follows successful report launch' ($cleanupReportOpen -ge 0 -and $cleanupRebootPrompt -gt $cleanupReportOpen)
Check 'CLI invokes CMD reboot only after an affirmative choice' ($cleanupRebootCommand -gt $cleanupRebootPrompt -and $cleanup.Contains("if (`$rebootChoice -match '^(?i:y|yes)$')") -and $cleanup.Contains('& $env:ComSpec /d /c'))
Check 'report generator accepts the repair result as an optional section' ($report.Contains('$PowerOptionsRepair') -and $report.Contains('power-options-repair'))

if ($script:failures -gt 0) {
    Write-Host ("$script:failures power-options workflow contract(s) failed")
    exit 1
}
Write-Host 'ALL POWER-OPTIONS WORKFLOW CONTRACTS PASSED'
exit 0
