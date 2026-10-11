# Replay the real removal loop with only disposable files and mocked OS seams.
# No registry, service, scheduled task, vendor process or native MoveFileEx runs.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = Split-Path -Parent $PSScriptRoot
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'remove-screenconnect.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Remover did not parse.' }
foreach ($name in @('Get-EntryPropertySafe','Move-ToQuarantine','Remove-ContainedInstanceMetadata')) {
    $fn = $ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}.GetNewClosure(), $true)
    if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)) }
}
$loop = $ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.ForEachStatementAst] -and $_.Variable.VariablePath.UserPath -eq 'inst' } | Select-Object -First 1
if (-not $loop) { throw 'Real instance loop not found.' }
if ('Win32.Kernel32' -as [type]) { throw 'Fixture refuses a preloaded native Kernel32 type.' }
Add-Type -TypeDefinition 'namespace Win32 { public static class Kernel32 { public static bool MoveFileEx(string source, string dest, int flags) { return true; } } }'
$root = Join-Path ([IO.Path]::GetTempPath()) ('scc-outcome-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
function Write-Log { param($Message,$Level) }
function Write-Section { param($Message) }
function Get-PlanInstanceId { param($Instance) 'fixture' }
function Expand-Env { param($Path) $Path }
function Test-ScreenConnectInstance { param($Instance) [pscustomobject]@{Verified=$true;Reasons=@()} }
function Get-VerifiedUninstallEntry { param($RegistryKeyPath,$VerifiedInstallDir,$InstanceId) $script:Entry }
function Get-UninstallEntriesForInstance { param($InstanceIdentifier) $script:Entry }
function Run-VendorUninstaller { param($UninstallEntry,$InstanceId,$InstallDir) $null }
function Stop-ServiceSafe { param($ServiceName,$InstanceId) $true }
function Kill-ProcessesForInstance { param($InstallDir,$ServiceName,$InstanceId) $true }
function Delete-ServiceRegistration { param($ServiceName,$InstanceId) [void]$script:Calls.Add('DeleteService'); $true }
function Clean-Persistence { param($InstallDir,$InstanceId) [void]$script:Calls.Add('CleanPersistence'); $true }
function Remove-ResumeTask { param($InstanceId) [void]$script:Calls.Add('RemoveResumeTask') }
function Get-Service { param($Name,$ErrorAction) }
function Set-RunOnceResume { param($InstanceId,$WorkDir) $script:ResumeRegistrationOk }
function Test-PathContained { param($Root,$Candidate) $true }
function Get-SafeInstanceFileStem { param($InstanceId) 'fixture' }
function Get-SafeInstanceDirectoryName { param($InstanceId) 'fixture' }
function Get-Sha256Hex { param($Text) '0123456789abcdef' }
function Get-Sha256File { param($Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function Get-PathIdentityHash { param($Path) if ($script:BadIdentity -and $Path -like '*quarantine*') { 'BAD' } else { 'FIXTURE_IDENTITY' } }
function Protect-QuarantinePathAcl { param($Path) if ($script:BadAcl) { throw 'mock ACL failure' }; [void]$script:Calls.Add('ProtectAcl') }
function Move-Item {
    param($LiteralPath,$Destination,[switch]$Force,$ErrorAction)
    if (-not $LiteralPath.StartsWith($root) -or -not $Destination.StartsWith($root)) { throw 'Outside fixture.' }
    if ($script:Locked) { throw 'mock locked file' }
    [IO.File]::Move($LiteralPath,$Destination)
}
function reg.exe {
    param($Verb,$RegistryPath,$Third,$Fourth)
    if ($Verb -eq 'export') {
        if (-not $Third.StartsWith($root)) { throw 'Outside fixture export.' }
        if ($script:BackupFails) { $global:LASTEXITCODE=1; return }
        [IO.File]::WriteAllText($Third,'fixture backup'); [void]$script:Calls.Add('ExportRegistry')
    } elseif ($Verb -eq 'delete') { [void]$script:Calls.Add('DeleteRegistry') } else { throw 'Unexpected mock reg verb.' }
    $global:LASTEXITCODE=0
}
function Add-ManifestEntry {
    param($InstanceId,$Action,$Target,$Result,$Details,$SourcePath,$DestinationPath,$SourceIdentity)
    [void]$script:Manifest.Add([pscustomobject]@{InstanceId=$InstanceId;Action=$Action;Target=$Target;Result=$Result;Details=$Details;SourcePath=$SourcePath;DestinationPath=$DestinationPath;SourceIdentity=$SourceIdentity})
}
function Update-ResumeStatus { param($InstanceId,$Status) $script:FinalStatus=$Status }
function Reset-Fixture {
    param([string]$Name)
    $script:WorkDir=Join-Path $root $Name
    $null=New-Item -ItemType Directory -Path $script:WorkDir
    $script:quarantineDir=Join-Path $script:WorkDir 'quarantine'
    $null=New-Item -ItemType Directory -Path $script:quarantineDir
    $script:Source=Join-Path $script:WorkDir 'ScreenConnect.fixture'
    [IO.File]::WriteAllText($script:Source,'harmless payload')
    $script:Calls=New-Object Collections.ArrayList
    $script:Manifest=New-Object Collections.ArrayList
    foreach ($n in @('CompletedInstanceIds','RebootPendingInstanceIds','PriorVerifiedInstanceIds','DeferredQuarantineInstanceIds','DeferredQuarantineRecords')) { Set-Variable -Scope Script -Name $n -Value (New-Object Collections.ArrayList) }
    $script:Entry=[pscustomobject]@{DisplayName='ScreenConnect fixture';PSPath='Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Fixture'}
    $script:scInstancesArray=@([pscustomobject]@{ServiceName='Fixture';InstallDir=$script:Source;MainExe='';ServiceImagePath='';UninstallRegistryKey='fixture'})
    $script:Execute=$true; $script:Resume=$false; $script:Locked=$false; $script:ResumeRegistrationOk=$true
    $script:BadIdentity=$false; $script:BadAcl=$false; $script:BackupFails=$false; $script:overallSuccess=$true; $script:FinalStatus=''
}
function Replay-Loop { . ([scriptblock]::Create($loop.Extent.Text)) }
try {
    Reset-Fixture 'deferred'; $script:Locked=$true
    Replay-Loop
    if (@($script:Calls | Where-Object {$_ -in @('DeleteService','ExportRegistry','DeleteRegistry','CleanPersistence')}).Count -ne 0) { throw 'Deferred payload authorized metadata or persistence surgery before quarantine.' }
    if ($script:FinalStatus -ne 'RebootPending' -or -not (Test-Path -LiteralPath $script:Source)) { throw 'Deferred outcome was not pending with source preserved.' }
    $deferred=@($script:Manifest | Where-Object {$_.Action -eq 'Quarantine' -and $_.Result -eq 'Deferred'})
    if ($deferred.Count -ne 1) { throw 'Structured deferred evidence missing.' }
    $script:Resume=$true
    [void]$script:RebootPendingInstanceIds.Add('fixture'); [void]$script:PriorVerifiedInstanceIds.Add('fixture')
    [void]$script:DeferredQuarantineRecords.Add($deferred[0])
    # Source still present: real resume verifier must forbid every cleanup call.
    $script:Calls.Clear(); Replay-Loop
    if ($script:Calls.Count -ne 0 -or $script:FinalStatus -ne 'Failed') { throw 'Failed resume verification authorized cleanup.' }
    [IO.File]::Move($script:Source,$deferred[0].DestinationPath)
    foreach ($bad in @('BadIdentity','BadAcl')) {
        Set-Variable -Scope Script -Name $bad -Value $true
        $script:Calls.Clear(); Replay-Loop
        if (@($script:Calls | Where-Object {$_ -in @('DeleteService','DeleteRegistry','CleanPersistence')}).Count -ne 0 -or $script:FinalStatus -ne 'Failed') { throw ('Failed '+$bad+' authorized cleanup.') }
        Set-Variable -Scope Script -Name $bad -Value $false
    }
    $script:Calls.Clear(); Replay-Loop
    foreach ($required in @('ProtectAcl','DeleteService','ExportRegistry','DeleteRegistry','CleanPersistence','RemoveResumeTask')) { if ($script:Calls -notcontains $required) { throw ('Verified deferred resume omitted '+$required) } }
    if ($script:FinalStatus -ne 'Completed') { throw 'Verified deferred resume did not complete.' }
    Reset-Fixture 'immediate'; Replay-Loop
    if ($script:FinalStatus -ne 'Completed' -or $script:Calls -notcontains 'DeleteRegistry' -or (Test-Path -LiteralPath $script:Source)) { throw 'Immediate verified quarantine did not complete metadata cleanup.' }
    Reset-Fixture 'registration-failure'; $script:Locked=$true; $script:ResumeRegistrationOk=$false; Replay-Loop
    if ($script:FinalStatus -ne 'Failed' -or @($script:Calls | Where-Object {$_ -in @('DeleteService','DeleteRegistry','CleanPersistence')}).Count) { throw 'Failed quarantine authorized cleanup.' }
    Reset-Fixture 'backup-failure'; $script:BackupFails=$true; Replay-Loop
    if ($script:FinalStatus -ne 'Failed' -or $script:Calls -contains 'DeleteRegistry') { throw 'Failed registry export authorized key deletion.' }
    Write-Host 'PASS: real loop gates deferred/failed quarantine and cleans only after verified containment; registry backup failure remains closed.'
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
