$ErrorActionPreference = "Stop"
Import-Module "/root/screenconnect-cleanup/gui-revision-screenconnect-cleaner/src/Scc.Remedy/Scc.Remedy.psd1" -Force -ErrorAction Stop
$run = [PSCustomObject]@{ RunId='TESTRUN'; RunDir=(Join-Path ([System.IO.Path]::GetTempPath()) ('dbg_'+[guid]::NewGuid().ToString('N'))) }
New-Item -ItemType Directory -Path $run.RunDir -Force | Out-Null
$srcDir = Join-Path ([System.IO.Path]::GetTempPath()) ('dbgsrc_'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
$srcFile = Join-Path $srcDir 'artifact.dll'
[System.IO.File]::WriteAllText($srcFile, 'SC-payload', [System.Text.Encoding]::ASCII)
$f = [PSCustomObject]@{ FindingId='sc1'; Product='screenconnect'; TargetType='Uninstall'; Detail=''; DisplayText='sc1'; ServiceName='ScreenConnect Client Service'; InstallDir='C:\SC\sc1'; MainExe=''; ServiceImagePath=''; UninstallRegistryKey=''; RelayHost='' }
$f | Add-Member -MemberType NoteProperty -Name 'QuarantinePaths' -Value @($srcFile) -Force
$plan = New-SccPlan -Run $run -Findings @($f) -Decisions @{ 'sc1'='REMOVE' }
Invoke-SccRemediation -Run $run -Plan $plan -Execute
$qroot = Join-Path $run.RunDir 'Quarantine'
Write-Host "Quarantine dir: $qroot exists=$(Test-Path $qroot)"
$mp = Join-Path $qroot 'quarantine-manifest.json'
Write-Host "manifest exists=$(Test-Path $mp)"
if (Test-Path $mp) { Write-Host "manifest: $([System.IO.File]::ReadAllText($mp))" }
# Use module private func to read
$man = Get-SccQuarantineManifest -Run $run
Write-Host "Get-SccQuarantineManifest count=$($man.Count)"
if ($man.Count -gt 0) {
    $itemId = $man[0].ItemId
    $original = $man[0].OriginalPath
    Write-Host "itemId=$itemId original=$original"
    Restore-SccQuarantineItem -Run $run -ItemId $itemId
    Write-Host "after restore, original exists=$(Test-Path $original)"
    $man2 = Get-SccQuarantineManifest -Run $run
    Write-Host "after restore manifest count=$($man2.Count)"
}
Remove-Item -Path $run.RunDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $srcDir -Recurse -Force -ErrorAction SilentlyContinue
