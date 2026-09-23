# Exercises detector inventory completeness using mocked system providers.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = if ($PSScriptRoot) {
    Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
} else {
    (Get-Location).Path
}
$detectorPath = Join-Path $repoRoot 'detect-remote-access.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($detectorPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Detector parse failed: $($parseErrors[0].Message)" }

$functionNames = @(
    'Expand-Env', 'Add-CollectionError', 'Get-DirsMatching', 'Get-AllServices', 'Get-AllProcesses',
    'Get-AllUninstallEntries', 'Test-AnyLike', 'Get-ScIdentifier',
    'Find-ScParamBlob', 'Get-ConnectionsForPids', 'Invoke-ScreenConnectModule'
)
foreach ($name in $functionNames) {
    $functionAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if ($null -eq $functionAst) { throw "Required detector function not found: $name" }
    . ([scriptblock]::Create($functionAst.Extent.Text))
}

$resultAssignment = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$result'
}, $true)
if ($null -eq $resultAssignment) { throw 'Could not locate detector findings object assignment.' }

$script:failures = 0
function Check {
    param([string]$Name, [bool]$Ok)
    if ($Ok) { Write-Host "PASS: $Name" }
    else { Write-Host "FAIL: $Name"; $script:failures++ }
}
function Reset-CollectionErrors {
    $script:CollectionErrors = New-Object System.Collections.ArrayList
}
function Write-Log { param([string]$Message, [string]$Color = 'Gray') }

$script:cimFailures = @{}
$script:cimRows = @{
    Win32_Service = @()
    Win32_Process = @()
}
function Get-CimInstance {
    [CmdletBinding()]
    param([string]$ClassName)
    if ($ClassName -and $script:cimFailures.ContainsKey($ClassName)) {
        throw $script:cimFailures[$ClassName]
    }
    if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{ Caption = 'Test OS' } }
    return @($script:cimRows[$ClassName])
}

$script:registryRoots = @()
$script:registryFailRoot = $null
$script:registryKeys = @{}
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath)
    return (($script:registryRoots -contains $LiteralPath) -or ($script:directoryPresentParents -contains $LiteralPath))
}
function Get-ChildItem {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Directory, [string]$Filter)
    if ($script:registryFailRoot -eq $LiteralPath) { throw 'mock registry enumeration denied' }
    if ($script:registryKeys.ContainsKey($LiteralPath)) { return @($script:registryKeys[$LiteralPath]) }
    if ($script:directoryFailEnumeration.ContainsKey($LiteralPath)) { throw $script:directoryFailEnumeration[$LiteralPath] }
    if ($script:directoryChildren.ContainsKey($LiteralPath)) { return @($script:directoryChildren[$LiteralPath]) }
    return @()
}
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath)
    if ($script:directoryFailParents.ContainsKey($LiteralPath)) { throw $script:directoryFailParents[$LiteralPath] }
    if ($script:directoryMissingParents -contains $LiteralPath) {
        throw [System.IO.DirectoryNotFoundException]::new("mock optional directory is absent: $LiteralPath")
    }
    return [pscustomobject]@{ FullName = $LiteralPath; PSIsContainer = $true }
}
function Get-ItemProperty {
    [CmdletBinding()]
    param([string]$LiteralPath)
    return [pscustomobject]@{
        DisplayName = 'ScreenConnect Client (registry-instance)'
        DisplayVersion = '1.0'
        Publisher = 'Test'
        InstallDate = $null
        InstallLocation = $null
        UninstallString = $null
        QuietUninstallString = $null
    }
}
function Get-NetTCPConnection {
    [CmdletBinding()]
    param()
    # TCP data enriches already-detected process instances; it is not an
    # independent presence source, so TCP provider errors are out of scope for
    # CollectionComplete and must not erase service/process/directory findings.
    return @()
}

function New-TestFindingsResult {
    param($ScreenConnect, $Targets = @())
    $script:EventLogError = 'mock event log unavailable'
    $ScriptVersion = 'test-version'
    $outDir = 'test-host_2026-09-23_120000'
    $isAdmin = $false
    $targetsSrc = 'test'
    $selected = @([pscustomobject]@{ id = 'screenconnect' })
    $scResult = $ScreenConnect
    $genericResult = New-Object System.Collections.ArrayList
    foreach ($target in $Targets) { [void]$genericResult.Add($target) }
    Invoke-Expression $resultAssignment.Extent.Text
    return $result
}

$script:CollectionErrors = $null
Reset-CollectionErrors
$script:cimFailures = @{}
$script:cimRows = @{ Win32_Service = @(); Win32_Process = @() }
$script:registryRoots = @()
$script:registryFailRoot = $null
$script:registryKeys = @{}
$script:directoryPresentParents = @()
$script:directoryMissingParents = @()
$script:directoryFailParents = @{}
$script:directoryFailEnumeration = @{}
$script:directoryChildren = @{}
$services = @(Get-AllServices)
$processes = @(Get-AllProcesses)
$uninstall = @(Get-AllUninstallEntries)
Check 'clean provider success returns empty inventories without errors' (
    $services.Count -eq 0 -and $processes.Count -eq 0 -and $uninstall.Count -eq 0 -and $script:CollectionErrors.Count -eq 0
)
$cleanResult = New-TestFindingsResult -ScreenConnect ([pscustomobject]@{ Instances = @(); ParseIssues = @(); Historical = @(); RawFilesSaved = @() })
$legacyProperties = @(
    'Tool', 'Version', 'RunId', 'GeneratedUtc', 'ComputerName', 'RunAsUser', 'IsAdmin',
    'OSCaption', 'PSVersion', 'TargetsSource', 'TargetsSelected', 'EventLogError',
    'ScreenConnect', 'OtherTargets'
)
Check 'successful findings add completeness metadata and retain the legacy top-level shape' (
    $cleanResult.CollectionComplete -eq $true -and @($cleanResult.CollectionErrors).Count -eq 0 -and
        @($legacyProperties | Where-Object { $null -eq $cleanResult.PSObject.Properties[$_] }).Count -eq 0
)
$cleanJson = ConvertTo-Json -InputObject $cleanResult -Depth 12 -Compress
Check 'clean findings serialize CollectionComplete as a boolean and CollectionErrors as an empty array' (
    $cleanJson -match '"CollectionComplete":true' -and $cleanJson -match '"CollectionErrors":\[\]'
)
Check 'legacy EventLogError remains separate from collection-provider completeness' (
    $cleanResult.EventLogError -eq 'mock event log unavailable' -and $cleanResult.CollectionComplete -eq $true
)

$optionalParent = Join-Path ([System.IO.Path]::GetTempPath()) 'missing-optional-install-parent'
$optionalPattern = Join-Path $optionalParent 'ScreenConnect*'
Reset-CollectionErrors
$script:directoryPresentParents = @()
$script:directoryMissingParents = @($optionalParent)
$script:directoryFailParents = @{}
$script:directoryFailEnumeration = @{}
$script:directoryChildren = @{}
$optionalDirs = @(Get-DirsMatching $optionalPattern)
Check 'an absent optional install-directory parent does not make collection incomplete' (
    $optionalDirs.Count -eq 0 -and $script:CollectionErrors.Count -eq 0
)

$deniedParent = Join-Path ([System.IO.Path]::GetTempPath()) 'denied-install-parent'
$deniedPattern = Join-Path $deniedParent 'ScreenConnect*'
Reset-CollectionErrors
$script:directoryMissingParents = @()
$script:directoryFailParents = @{ $deniedParent = 'mock install-directory access denied' }
$deniedDirs = @(Get-DirsMatching $deniedPattern)
$deniedResult = New-TestFindingsResult -ScreenConnect ([pscustomobject]@{ Instances = @(); ParseIssues = @(); Historical = @(); RawFilesSaved = @() })
Check 'an inaccessible install-directory parent records an error and prevents a clean result' (
    $deniedDirs.Count -eq 0 -and $deniedResult.CollectionComplete -eq $false -and
        @($deniedResult.CollectionErrors).Count -eq 1 -and
        $deniedResult.CollectionErrors[0].Source -eq 'InstallDirectories' -and
        $deniedResult.CollectionErrors[0].Error -match 'mock install-directory access denied'
)

$enumerationParent = Join-Path ([System.IO.Path]::GetTempPath()) 'enumeration-failed-install-parent'
$enumerationPattern = Join-Path $enumerationParent 'ScreenConnect*'
Reset-CollectionErrors
$script:directoryPresentParents = @($enumerationParent)
$script:directoryMissingParents = @()
$script:directoryFailParents = @{}
$script:directoryFailEnumeration = @{ $enumerationParent = 'mock install-directory enumeration denied' }
$script:directoryChildren = @{}
$script:cimFailures = @{}
$script:cimRows = @{
    Win32_Service = @()
    Win32_Process = @([pscustomobject]@{
        ProcessId = 432; ParentProcessId = 1; Name = 'ScreenConnect.ClientService.exe'
        ExecutablePath = 'C:\ScreenConnect Client (directory-error-positive)\client.exe'
        CommandLine = ''; CreationDate = $null
    })
}
$enumerationProcesses = @(Get-AllProcesses)
$enumerationResult = Invoke-ScreenConnectModule -Services @() -Processes $enumerationProcesses -UninstallEntries @() -Events @() `
    -Target @{ servicePatterns = @(); pathPatterns = @($enumerationPattern); uninstallPatterns = @(); processPatterns = @('ScreenConnect*') } -RawDir ''
$enumerationFindings = New-TestFindingsResult -ScreenConnect $enumerationResult
Check 'install-directory enumeration failure records incompleteness while preserving positive process findings' (
    @($enumerationFindings.ScreenConnect.Instances).Count -eq 1 -and
        $enumerationFindings.ScreenConnect.Instances[0].Identifier -eq 'directory-error-positive' -and
        $enumerationFindings.CollectionComplete -eq $false -and
        @($enumerationFindings.CollectionErrors).Count -eq 1 -and
        $enumerationFindings.CollectionErrors[0].Source -eq 'InstallDirectories' -and
        $enumerationFindings.CollectionErrors[0].Error -match 'mock install-directory enumeration denied'
)

foreach ($provider in @(
    @{ ClassName = 'Win32_Service'; Source = 'Services' },
    @{ ClassName = 'Win32_Process'; Source = 'Processes' }
)) {
    Reset-CollectionErrors
    $script:cimFailures = @{ $provider.ClassName = 'mock CIM enumeration denied' }
    if ($provider.ClassName -eq 'Win32_Service') { $null = @(Get-AllServices) }
    else { $null = @(Get-AllProcesses) }
    Check "$($provider.Source) provider failure is recorded" (
        $script:CollectionErrors.Count -eq 1 -and
            $script:CollectionErrors[0].Source -eq $provider.Source -and
            $script:CollectionErrors[0].Error -match 'mock CIM enumeration denied'
    )
}

$registryRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$registryOtherRoot = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
Reset-CollectionErrors
$script:registryRoots = @($registryRoot, $registryOtherRoot)
$script:registryFailRoot = $registryRoot
$key = [pscustomobject]@{ PSPath = 'Registry::HKEY_LOCAL_MACHINE\Software\Test'; PSChildName = 'test-key' }
$script:registryKeys = @{ $registryOtherRoot = @($key) }
$partialUninstall = @(Get-AllUninstallEntries)
$registryResult = New-TestFindingsResult -ScreenConnect ([pscustomobject]@{ Instances = @(); ParseIssues = @(); Historical = @(); RawFilesSaved = @() })
Check 'registry enumeration failure is recorded while later roots retain positive entries' (
    $partialUninstall.Count -eq 1 -and $partialUninstall[0].DisplayName -eq 'ScreenConnect Client (registry-instance)' -and
        $script:CollectionErrors.Count -eq 1 -and $script:CollectionErrors[0].Source -eq 'UninstallRegistry' -and
        $registryResult.CollectionComplete -eq $false -and @($registryResult.CollectionErrors).Count -eq 1
)

Reset-CollectionErrors
$script:cimFailures = @{ Win32_Service = 'mock services unavailable' }
$script:cimRows = @{
    Win32_Service = @()
    Win32_Process = @([pscustomobject]@{
        ProcessId = 431; ParentProcessId = 1; Name = 'ScreenConnect.ClientService.exe'
        ExecutablePath = 'C:\ScreenConnect Client (positive-instance)\client.exe'
        CommandLine = ''; CreationDate = $null
    })
}
$services = @(Get-AllServices)
$processes = @(Get-AllProcesses)
$script:registryRoots = @()
$script:registryFailRoot = $null
$script:registryKeys = @{}
$uninstall = @(Get-AllUninstallEntries)
$target = @{ servicePatterns = @(); pathPatterns = @(); uninstallPatterns = @(); processPatterns = @('ScreenConnect*') }
$script:tcpCalls = 0
$screenConnect = Invoke-ScreenConnectModule -Services $services -Processes $processes -UninstallEntries $uninstall -Events @() -Target $target -RawDir ''
$partialResult = New-TestFindingsResult -ScreenConnect $screenConnect
Check 'partial provider failure preserves positive process findings and marks the result incomplete' (
    @($partialResult.ScreenConnect.Instances).Count -eq 1 -and
        $partialResult.ScreenConnect.Instances[0].Identifier -eq 'positive-instance' -and
        $partialResult.CollectionComplete -eq $false -and
        @($partialResult.CollectionErrors).Count -eq 1 -and
        $partialResult.CollectionErrors[0].Source -eq 'Services' -and
        $partialResult.EventLogError -eq 'mock event log unavailable'
)
$partialJson = ConvertTo-Json -InputObject $partialResult -Depth 12 -Compress
Check 'partial findings serialize the collection error as an array of source/error objects' (
    $partialJson -match '"CollectionComplete":false' -and
        $partialJson -match '"CollectionErrors":\[\{"Source":"Services","Error":"'
)

if ($script:failures) {
    Write-Error "$script:failures detector collection regression(s) failed"
    exit 1
}
Write-Host 'PASS: detector collection completeness regressions'
exit 0
