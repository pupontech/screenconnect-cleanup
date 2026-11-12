# test_power_options_repair_core.ps1 - deterministic fake-adapter tests.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$corePath = Join-Path $repoRoot 'PowerOptionsRepair.Core.psm1'
if (-not (Test-Path -LiteralPath $corePath)) {
    throw 'PowerOptionsRepair.Core.psm1 is required.'
}
Import-Module $corePath -Force

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
function Same-Items {
    param([object[]]$Actual, [object[]]$Expected)
    if (@($Actual).Count -ne @($Expected).Count) { return $false }
    for ($i = 0; $i -lt @($Expected).Count; $i++) {
        if ([string]$Actual[$i] -cne [string]$Expected[$i]) { return $false }
    }
    return $true
}

$loadedSids = @(
    'S-1-5-21-111-222-333-1001',
    'S-1-12-1-111-222-333-444',
    'S-1-5-21-111-222-333-1001',
    'S-1-5-18',
    'not-a-sid'
)
$plan = Get-PowerOptionsRepairPlan -LoadedUserSids $loadedSids
$userExplorer = @($plan.RegistryTargets | Where-Object { $_.Path -like 'Registry::HKEY_USERS*' -and $_.Path -like '*Policies\Explorer' })
$userSystem = @($plan.RegistryTargets | Where-Object { $_.Path -like 'Registry::HKEY_USERS*' -and $_.Path -like '*Policies\System' })
Check 'plan includes every unique valid loaded user hive' (@($userExplorer).Count -eq 2 -and @($userSystem).Count -eq 2)
Check 'plan never targets service/default or malformed SIDs' ((@($plan.RegistryTargets.Path) -join '|') -notmatch 'S-1-5-18|not-a-sid')
Check 'plan removes only the named Explorer restrictions' (Same-Items -Actual $plan.ExplorerValuesToRemove -Expected @('NoClose','NoLogoff','HidePowerOptions','NoShutdown','NoLock'))
$powerPolicyTarget = @($plan.RegistryTargets | Where-Object { $_.Path -eq $plan.PowerPolicyPath })
Check 'power policy subtree is an explicit backed-up delete target' (@($powerPolicyTarget).Count -eq 1 -and [bool]$powerPolicyTarget[0].DeleteKey)
Check 'shutdownwithoutlogon is explicitly enabled' ($plan.ShutdownWithoutLogonValue -eq 1)
Check 'PolicyManager flags restore visibility without adding unrelated settings' (Same-Items -Actual $plan.PolicyManagerValues -Expected @('HideShutDown','HideRestart','HideSleep','HideHibernate','HideLock','HidePowerButton'))
Check 'power button, sleep button, and lid return to documented sleep defaults for AC/DC' ($plan.ButtonActionValues.AC.PBUTTONACTION -eq 1 -and $plan.ButtonActionValues.AC.SBUTTONACTION -eq 1 -and $plan.ButtonActionValues.AC.LIDACTION -eq 1 -and $plan.ButtonActionValues.DC.PBUTTONACTION -eq 1 -and $plan.ButtonActionValues.DC.SBUTTONACTION -eq 1 -and $plan.ButtonActionValues.DC.LIDACTION -eq 1)
Check 'shutdown right is additive for the three built-in groups' (Same-Items -Actual $plan.ShutdownRightGroupSids -Expected @('S-1-5-32-544','S-1-5-32-551','S-1-5-32-545'))
Check 'local GPO reset is off by default' (-not $plan.ResetLocalGpo)
Check 'reboot is not part of the repair plan' (-not ($plan.PSObject.Properties.Name -contains 'Reboot'))

$gpoPlan = Get-PowerOptionsRepairPlan -LoadedUserSids @() -ResetLocalGpo
Check 'local GPO reset requires explicit opt-in' ($gpoPlan.ResetLocalGpo -eq $true)

$script:events = New-Object System.Collections.ArrayList
$script:registryKeys = @{}
$script:registryValues = @{}
$script:failBackupPath = $null
$script:failPowerBackup = $false
$script:failGpoBackup = $false
$script:powerRestoreOk = $true
$script:shutdownRightsBackupOk = $true
$script:mutations = 0

$adapter = @{
    TestRegistryKey = {
        param($path)
        return $true
    }
    BackupRegistryKey = {
        param($path)
        [void]$script:events.Add('backup-reg:' + $path)
        return ($path -ne $script:failBackupPath)
    }
    GetRegistryValue = {
        param($path, $name)
        if ($path -like '*PolicyManager*') {
            return [pscustomobject]@{ Exists = ($name -ne 'HidePowerButton'); Type = 'DWord'; Value = 1 }
        }
        return [pscustomobject]@{ Exists = $false; Type = $null; Value = $null }
    }
    RemoveRegistryValue = {
        param($path, $name)
        [void]$script:events.Add('remove:' + $path + ':' + $name)
        $script:mutations++
        return $true
    }
    RemoveRegistryTree = {
        param($path)
        [void]$script:events.Add('remove-tree:' + $path)
        $script:mutations++
        return $true
    }
    SetRegistryDword = {
        param($path, $name, $value)
        [void]$script:events.Add('set:' + $path + ':' + $name + ':' + $value)
        $script:mutations++
        return $true
    }
    BackupPowerSchemes = {
        param($backupRoot)
        [void]$script:events.Add('backup-power')
        return (-not $script:failPowerBackup)
    }
    RestoreDefaultPowerSchemes = {
        [void]$script:events.Add('restore-power')
        return $script:powerRestoreOk
    }
    EnableHibernate = {
        [void]$script:events.Add('hibernate-on')
        return $true
    }
    SetDefaultButtonActions = {
        param($values)
        [void]$script:events.Add('button-actions')
        return $true
    }
    BackupShutdownRights = {
        param($backupRoot)
        [void]$script:events.Add('backup-rights')
        return $script:shutdownRightsBackupOk
    }
    GrantShutdownRight = {
        param($groupSid, $rightName)
        [void]$script:events.Add('grant-right:' + $groupSid + ':' + $rightName)
        return $true
    }
    BackupLocalGpo = {
        param($backupRoot)
        [void]$script:events.Add('backup-gpo')
        return (-not $script:failGpoBackup)
    }
    ResetLocalGpo = {
        [void]$script:events.Add('reset-gpo')
        return $true
    }
    RunGpUpdate = {
        [void]$script:events.Add('gpupdate')
        return $true
    }
    RestartExplorer = {
        [void]$script:events.Add('restart-explorer')
        return $true
    }
}

$executionPlan = Get-PowerOptionsRepairPlan -LoadedUserSids @('S-1-5-21-111-222-333-1001') -ResetLocalGpo
$result = Invoke-PowerOptionsRepairPlan -Plan $executionPlan -Adapter $adapter -BackupRoot 'fixture-backup'
$removeIndex = [array]::IndexOf([object[]]$script:events, 'remove:HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoClose')
$backupIndex = [array]::IndexOf([object[]]$script:events, 'backup-reg:HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')
$powerBackupIndex = [array]::IndexOf([object[]]$script:events, 'backup-power')
$powerRestoreIndex = [array]::IndexOf([object[]]$script:events, 'restore-power')
$gpoBackupIndex = [array]::IndexOf([object[]]$script:events, 'backup-gpo')
$gpoResetIndex = [array]::IndexOf([object[]]$script:events, 'reset-gpo')
$powerPolicyBackupIndex = [array]::IndexOf([object[]]$script:events, ('backup-reg:' + $executionPlan.PowerPolicyPath))
$powerPolicyDeleteIndex = [array]::IndexOf([object[]]$script:events, ('remove-tree:' + $executionPlan.PowerPolicyPath))
Check 'registry key backup precedes its first edit' ($backupIndex -ge 0 -and $removeIndex -gt $backupIndex)
Check 'power policy subtree backup precedes deletion' ($powerPolicyBackupIndex -ge 0 -and $powerPolicyDeleteIndex -gt $powerPolicyBackupIndex)
Check 'power schemes are backed up before defaults are restored' ($powerBackupIndex -ge 0 -and $powerRestoreIndex -gt $powerBackupIndex)
Check 'local GPO backup precedes reset' ($gpoBackupIndex -ge 0 -and $gpoResetIndex -gt $gpoBackupIndex)
Check 'missing PolicyManager values are not created' ($script:events -notcontains 'set:HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start:HidePowerButton:0')
Check 'gpupdate precedes Explorer restart' ([array]::IndexOf([object[]]$script:events, 'gpupdate') -lt [array]::IndexOf([object[]]$script:events, 'restart-explorer'))
Check 'successful fake run is complete' ($result.Status -eq 'Completed')

$script:events.Clear()
$script:mutations = 0
$script:failBackupPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$resultNoBackup = Invoke-PowerOptionsRepairPlan -Plan $executionPlan -Adapter $adapter -BackupRoot 'fixture-backup'
Check 'failed registry backup blocks edits to that key' (@($script:events | Where-Object { $_ -like 'remove:HKLM:*Policies*Explorer:NoClose' -or $_ -like 'set:HKLM:*Policies*Explorer:*' }).Count -eq 0)
Check 'failed registry backup is reported as partial' ($resultNoBackup.Status -eq 'Partial')

$script:events.Clear()
$script:failBackupPath = $null
$script:failGpoBackup = $true
$resultNoGpoBackup = Invoke-PowerOptionsRepairPlan -Plan $executionPlan -Adapter $adapter -BackupRoot 'fixture-backup'
Check 'failed GPO backup blocks policy-folder reset' ($script:events -contains 'backup-gpo' -and $script:events -notcontains 'reset-gpo')
Check 'failed GPO backup leaves other independent repairs reportable' ($resultNoGpoBackup.Status -eq 'Partial')

$script:events.Clear()
$script:failGpoBackup = $false
$multiOutputAdapter = $adapter.Clone()
$multiOutputAdapter.BackupPowerSchemes = { param($backupRoot) 'diagnostic text'; return $false }
$resultNoPowerBackup = Invoke-PowerOptionsRepairPlan -Plan (Get-PowerOptionsRepairPlan -LoadedUserSids @()) -Adapter $multiOutputAdapter -BackupRoot 'fixture-backup'
Check 'adapter diagnostics cannot turn a failed power backup into success' ($script:events -notcontains 'restore-power' -and $resultNoPowerBackup.Status -eq 'Partial')

if (@($script:failures).Count -gt 0) {
    Write-Host ("$(@($script:failures).Count) power-options repair core test(s) failed")
    exit 1
}
Write-Host 'ALL POWER-OPTIONS REPAIR CORE TESTS PASSED'
exit 0
