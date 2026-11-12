<#
  Repair-PowerOptions.ps1 - consent-gated restoration of Windows power options.
  Requires -Apply. Local Group Policy reset and managed-device overrides are
  separate opt-ins. This script never reboots the computer.
  PowerShell 5.1 compatible. Pure ASCII, no BOM.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Apply,
    [switch]$ResetLocalGpo,
    [switch]$AllowManagedDevice,
    [string]$WorkDir,
    [string]$ResultPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$coreModule = Join-Path $scriptRoot 'PowerOptionsRepair.Core.psm1'
$windowsModule = Join-Path $scriptRoot 'PowerOptionsRepair.Windows.psm1'
if (-not (Test-Path -LiteralPath $coreModule -PathType Leaf) -or -not (Test-Path -LiteralPath $windowsModule -PathType Leaf)) {
    Write-Error 'Power-options repair modules are missing.'
    exit 4
}
Import-Module -Name $coreModule -Force -ErrorAction Stop
Import-Module -Name $windowsModule -Force -ErrorAction Stop

if (-not $Apply) {
    Write-Host 'Refused: no system changes were made. Review the repair, then rerun with -Apply.'
    exit 2
}
if ($WhatIfPreference) {
    Write-Host 'WhatIf: no Windows settings, power plans, user rights, or Group Policy folders will be changed.'
    exit 0
}
if (-not $PSCmdlet.ShouldProcess('local Windows power, policy, and shutdown-right settings', 'restore power options')) {
    Write-Host 'Skipped: no system changes were made.'
    exit 0
}
if ($env:OS -ne 'Windows_NT') {
    Write-Error 'This repair runs only on Windows.'
    exit 4
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Error 'Run this repair from 64-bit PowerShell.'
    exit 4
}

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}
if (-not $isAdmin) {
    Write-Error 'Administrator rights are required. No changes were made.'
    exit 4
}

try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ([int]$osInfo.ProductType -ne 1) {
        Write-Error 'This repair is limited to Windows client editions; server operating systems are refused.'
        exit 4
    }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $domainJoined = [bool]$computerSystem.PartOfDomain
} catch {
    Write-Error ('Could not establish the Windows client/management state; refusing the repair: ' + $_.Exception.Message)
    exit 4
}

$mdmEnrolled = $false
$mdmStateKnown = $true
$enrollmentRoot = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments'
try {
    if (Test-Path -LiteralPath $enrollmentRoot) {
        foreach ($enrollmentKey in (Get-ChildItem -LiteralPath $enrollmentRoot -ErrorAction Stop)) {
            $enrollment = Get-ItemProperty -LiteralPath $enrollmentKey.PSPath -ErrorAction SilentlyContinue
            if ($enrollment -and $enrollment.PSObject.Properties['EnrollmentState'] -and [int]$enrollment.EnrollmentState -eq 1 -and $enrollment.PSObject.Properties['ProviderID'] -and -not [string]::IsNullOrWhiteSpace([string]$enrollment.ProviderID)) {
                $mdmEnrolled = $true
                break
            }
        }
    }
} catch {
    $mdmStateKnown = $false
}

$managedDevice = ($domainJoined -or $mdmEnrolled -or -not $mdmStateKnown)
if ($managedDevice -and -not $AllowManagedDevice) {
    Write-Host 'Refused: this device is domain/MDM managed or its management state is unknown.' -ForegroundColor Yellow
    Write-Host 'Have the domain/MDM administrator remove the enforcing policy, or rerun only with explicit authorization and -AllowManagedDevice.'
    exit 3
}
if ($managedDevice) {
    Write-Host 'WARNING: local changes may be reapplied by domain or MDM policy. Continue only with authorization.' -ForegroundColor Yellow
}

if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $programData = $env:ProgramData
    if ([string]::IsNullOrWhiteSpace($programData)) { $programData = Join-Path $env:SystemDrive 'ProgramData' }
    $WorkDir = Join-Path $programData ('ScreenConnectCleanup\PowerRepair-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
}
try {
    if (-not [System.IO.Path]::IsPathRooted($WorkDir)) { throw 'WorkDir must be an absolute local path.' }
    $fullWorkDir = [System.IO.Path]::GetFullPath($WorkDir)
    $windowsRoot = [System.IO.Path]::GetFullPath($env:SystemRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $windowsPrefix = $windowsRoot + [System.IO.Path]::DirectorySeparatorChar
    if ($fullWorkDir.StartsWith($windowsPrefix, [StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($fullWorkDir, $windowsRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'WorkDir must not be inside the Windows directory.'
    }
    if ($fullWorkDir.StartsWith('\\', [StringComparison]::Ordinal) -or $fullWorkDir.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'WorkDir must be local, not a UNC path.'
    }
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullWorkDir)
    $drive = [System.IO.DriveInfo]::new($volumeRoot)
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) { throw 'WorkDir must be on a fixed local drive.' }
    Assert-PowerRepairSafePath -Path $fullWorkDir
    $null = [System.IO.Directory]::CreateDirectory($fullWorkDir)
    Assert-PowerRepairSafePath -Path $fullWorkDir
    if ([string]::IsNullOrWhiteSpace($ResultPath)) { $ResultPath = Join-Path $fullWorkDir 'power-options-repair.json' }
    if (-not [System.IO.Path]::IsPathRooted($ResultPath)) { throw 'ResultPath must be an absolute path.' }
    $fullResultPath = [System.IO.Path]::GetFullPath($ResultPath)
    $workPrefix = $fullWorkDir.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullResultPath.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'ResultPath must stay inside WorkDir.' }
    Assert-PowerRepairSafePath -Path $fullResultPath -Root $fullWorkDir
    $freeBytes = $drive.AvailableFreeSpace
    if ($freeBytes -lt 1GB) { throw 'At least 1 GB of free space is required for verified backups.' }
} catch {
    Write-Error ('Unsafe or unavailable backup/result path: ' + $_.Exception.Message)
    exit 4
}

$backupRoot = Join-Path $fullWorkDir ('power-options-repair-backup-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
try {
    Assert-PowerRepairSafePath -Path $backupRoot -Root $fullWorkDir
    $null = [System.IO.Directory]::CreateDirectory($backupRoot)
    Assert-PowerRepairSafePath -Path $backupRoot -Root $fullWorkDir
} catch {
    Write-Error ('Could not create the backup directory: ' + $_.Exception.Message)
    exit 4
}

$currentSid = $identity.User.Value
$loadedSids = @()
try {
    $loadedProfiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { $_.Loaded -and $_.SID }
    foreach ($profile in $loadedProfiles) { $loadedSids += [string]$profile.SID }
} catch {
    Write-Error ('Could not enumerate loaded user profiles; refusing a partial per-user repair: ' + $_.Exception.Message)
    exit 4
}
if ($loadedSids -notcontains $currentSid) { $loadedSids += $currentSid }

Write-Host 'Repair scope: Explorer policies, Start visibility flags, local power policy, built-in power schemes, hibernate, shutdown right, and refresh.'
Write-Host 'Backups: registry exports, every power scheme, and the user-rights template are written before their changes.'
Write-Host 'Hibernate can allocate disk space. Power/sleep button and lid actions are reset to Windows sleep defaults.'
Write-Host 'Local Group Policy reset is OFF unless -ResetLocalGpo is explicitly supplied.'
Write-Host 'The script never reboots. A separate reboot choice belongs after the investigation report opens.'

$plan = Get-PowerOptionsRepairPlan -LoadedUserSids $loadedSids -CurrentUserSid $currentSid -WindowsDirectory $env:SystemRoot -ResetLocalGpo:$ResetLocalGpo
$adapter = New-WindowsPowerOptionsRepairAdapter
try {
    $repairResult = Invoke-PowerOptionsRepairPlan -Plan $plan -Adapter $adapter -BackupRoot $backupRoot
    $repairResult | Add-Member -NotePropertyName GeneratedUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    $repairResult | Add-Member -NotePropertyName ComputerName -NotePropertyValue $env:COMPUTERNAME -Force
    $repairResult | Add-Member -NotePropertyName ManagementState -NotePropertyValue ([pscustomobject]@{ DomainJoined = $domainJoined; MdmEnrolled = $mdmEnrolled; StateKnown = $mdmStateKnown; ExplicitOverride = [bool]$AllowManagedDevice }) -Force
    $repairResult | Add-Member -NotePropertyName ResultPath -NotePropertyValue $fullResultPath -Force
    Assert-PowerRepairSafePath -Path $backupRoot -Root $fullWorkDir
    Assert-PowerRepairSafePath -Path $fullResultPath -Root $fullWorkDir
    $repairResult | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fullResultPath -Encoding UTF8 -NoNewline
} catch {
    Write-Error ('Repair failed before a complete result could be written. Review backups in ' + $backupRoot + ': ' + $_.Exception.Message)
    exit 1
}

Write-Host ('Repair status: ' + $repairResult.Status)
Write-Host ('Repair result: ' + $fullResultPath)
Write-Host ('Verified backups: ' + $backupRoot)
Write-Host 'If restrictions return after refresh, inspect enforced GPO/MDM policy and persistence (for example scheduled tasks); this repair does not remove those sources.'
if ($managedDevice) { Write-Host 'Managed-device override was used; coordinate with the policy administrator.' -ForegroundColor Yellow }
if ($repairResult.Status -eq 'Completed') { exit 0 }
exit 1
