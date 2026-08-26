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
$mp = Join-Path $run.RunDir 'Quarantine' 'quarantine-manifest.json'
$before = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($mp))
$itemId = $before[0].ItemId
Write-Host "before count=$($before.Count) itemId=$itemId"
Restore-SccQuarantineItem -Run $run -ItemId $itemId
Write-Host "after restore, original exists=$(Test-Path $before[0].OriginalPath)"
if (Test-Path $mp) {
    $after = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($mp))
    Write-Host "after count=$($after.Count)"
} else {
    Write-Host "manifest file deleted"
}
Remove-Item -Path $run.RunDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $srcDir -Recurse -Force -ErrorAction SilentlyContinue
