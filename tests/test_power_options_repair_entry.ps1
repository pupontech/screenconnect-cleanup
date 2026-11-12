# test_power_options_repair_entry.ps1 - consent and host-gate contracts.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$repairScript = Join-Path $repoRoot 'Repair-PowerOptions.ps1'
if (-not (Test-Path -LiteralPath $repairScript)) { throw 'Repair-PowerOptions.ps1 is required.' }
$source = [System.IO.File]::ReadAllText($repairScript)
$windowsSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'PowerOptionsRepair.Windows.psm1'))
$coreSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'PowerOptionsRepair.Core.psm1'))
$script:failures = @()
function Check {
    param([string]$Name, [bool]$Condition, [string]$Details = '')
    if ($Condition) { Write-Host ("PASS  " + $Name) }
    else {
        $message = "FAIL  " + $Name
        if ($Details) { $message += " - " + $Details }
        Write-Host $message
        $script:failures += $message
    }
}

Check 'repair requires an explicit Apply switch' ($source -match '\[switch\]\$Apply' -and $source -match 'if \(-not \$Apply\)')
Check 'managed devices require a separate explicit override' ($source -match '\[switch\]\$AllowManagedDevice' -and $source -match 'AllowManagedDevice')
Check 'server OS is refused' ($source -match 'ProductType' -and $source -match 'ProductType\s*-ne\s*1')
Check 'backup and result paths are explicit in the result' ($source -match 'BackupRoot' -and $source -match 'ResultPath')
Check 'repair helper never issues reboot/shutdown commands' ($source -notmatch '(?im)\b(shutdown\.exe|Restart-Computer)\b')
Check 'LSA grants the shutdown right additively' ($windowsSource -match 'LsaAddAccountRights' -and $windowsSource -notmatch 'LsaRemoveAccountRights')
Check 'local Group Policy backup must precede folder reset' ($coreSource.IndexOf("-Name 'BackupLocalGpo'") -ge 0 -and $coreSource.IndexOf("-Name 'ResetLocalGpo'") -gt $coreSource.IndexOf("-Name 'BackupLocalGpo'"))

$psHost = if ($PSVersionTable.PSEdition -eq 'Desktop') { Join-Path $PSHOME 'powershell.exe' } else { (Get-Command pwsh -ErrorAction Stop).Source }
$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-power-repair-entry-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force
Import-Module (Join-Path $repoRoot 'PowerOptionsRepair.Windows.psm1') -Force
$adapter = New-WindowsPowerOptionsRepairAdapter
Check 'Windows adapter exposes every required operation' (@($adapter.Keys).Count -ge 16 -and $adapter.Contains('BackupLocalGpo') -and $adapter.Contains('GrantShutdownRight'))
$adapterPathProbe = & $adapter.TestRegistryKey $probeRoot
Check 'adapter scriptblocks resolve their module helpers' ([bool]$adapterPathProbe)
try {
    $noConsent = & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $repairScript -WorkDir $probeRoot 2>&1
    $noConsentCode = $LASTEXITCODE
    Check 'without Apply the helper refuses and writes no result' ($noConsentCode -eq 2 -and -not (Test-Path (Join-Path $probeRoot 'power-options-repair.json'))) (($noConsent -join "`n"))

    $dryRun = & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $repairScript -Apply -WhatIf -WorkDir $probeRoot -ResultPath (Join-Path $probeRoot 'whatif.json') 2>&1
    $dryRunCode = $LASTEXITCODE
    Check 'WhatIf exits before Windows/system prerequisites and writes nothing' ($dryRunCode -eq 0 -and -not (Test-Path (Join-Path $probeRoot 'whatif.json'))) (($dryRun -join "`n"))
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if (@($script:failures).Count -gt 0) {
    Write-Host ("$(@($script:failures).Count) power-options entry test(s) failed")
    exit 1
}
Write-Host 'ALL POWER-OPTIONS ENTRY TESTS PASSED'
exit 0
