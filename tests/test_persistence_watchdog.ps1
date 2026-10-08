# Exercise the real wrapper with only harmless provider fixtures; no live collection.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc watchdog fixture '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$hostExe=(Get-Process -Id $PID).Path
try {
    Copy-Item -LiteralPath (Join-Path $repo 'Invoke-PersistenceScan.ps1') -Destination $temp
    $worker=Join-Path $repo 'Invoke-PersistenceInventoryWorker.ps1'
    if(Test-Path -LiteralPath $worker){Copy-Item -LiteralPath $worker -Destination $temp}
    $mock=@'
function Get-SccPersistenceInventory {
 param([string]$OutDir)
 $null=New-Item -ItemType Directory -Path $OutDir -Force
 [IO.File]::WriteAllText((Join-Path $OutDir 'fixture-PID.txt'),[string]$PID)
 Write-Host 'SCC_PERSISTENCE_SECTION|FixtureBlocked'
 Start-Sleep -Seconds 30
}
Export-ModuleMember -Function Get-SccPersistenceInventory
'@
    [IO.File]::WriteAllText((Join-Path $temp 'Persistence.Inventory.psm1'),$mock,[Text.Encoding]::ASCII)
    # If an interrupted collector accidentally reaches removal, this sentinel exposes it.
    $remove="[IO.File]::WriteAllText((Join-Path `$PSScriptRoot 'UNSAFE-REMOVAL.txt'),'unexpected');throw 'removal must not be imported'"
    [IO.File]::WriteAllText((Join-Path $temp 'Persistence.Removal.psm1'),$remove,[Text.Encoding]::ASCII)
    $run=Join-Path $temp 'run'
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=$hostExe
    $psi.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $temp 'Invoke-PersistenceScan.ps1')+'" -WorkDir "'+$run+'" -NoPrompt'
    $wrapper=[IO.File]::ReadAllText((Join-Path $temp 'Invoke-PersistenceScan.ps1'))
    if($wrapper -match 'InventorySectionTimeoutSeconds'){$psi.Arguments+=' -InventorySectionTimeoutSeconds 2 -InventoryTotalTimeoutSeconds 10'}
    $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
    $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($psi)
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    try {
        if(-not $process.WaitForExit(12000)) {
            $process.Kill()
            throw 'RED: blocked inventory left the wrapper waiting silently beyond the fixture deadline.'
        }
        $output=$stdout.Result+' '+$stderr.Result
        if($process.ExitCode -eq 0){throw 'Timed-out collection was incorrectly successful.'}
        $persist=Join-Path $run 'persistence'
        $result=[IO.File]::ReadAllText((Join-Path $persist 'result.json')) | ConvertFrom-Json
        $inventory=[IO.File]::ReadAllText((Join-Path $persist 'inventory.json')) | ConvertFrom-Json
        $removal=[IO.File]::ReadAllText((Join-Path $persist 'removal.json')) | ConvertFrom-Json
        if($result.Status -ne 'Incomplete' -or $inventory.Status -ne 'Incomplete' -or $removal.Status -ne 'Skipped'){throw 'Interrupted inventory did not preserve fail-closed report artifacts.'}
        if(($result.Errors -join ' ') -notmatch 'FixtureBlocked' -or ($result.Errors -join ' ') -notmatch 'timed out'){throw ('Timeout lost the stalled section: '+($result.Errors -join ' '))}
        if($output -notmatch 'FixtureBlocked' -or $output -notmatch 'still collecting'){throw ('Console progress/heartbeat was not streamed: '+$output)}
        if(Test-Path -LiteralPath (Join-Path $temp 'UNSAFE-REMOVAL.txt')){throw 'Removal was reached after inventory timeout.'}
        $workerPid=[int][IO.File]::ReadAllText((Join-Path $persist 'fixture-PID.txt'))
        $alive=Get-Process -Id $workerPid -ErrorAction SilentlyContinue
        if($alive -and -not $alive.HasExited){throw 'Timed-out inventory worker was left alive.'}
        $log=[IO.File]::ReadAllText((Join-Path $persist 'collection-progress.log'))
        if($log -notmatch 'FixtureBlocked' -or $log -notmatch 'timed out'){throw 'Durable progress log lost the stall diagnosis.'}
        Write-Host 'PASS: stalled provider timed out; section/heartbeat visible; worker ended; incomplete artifacts preserved; removal never reached.'
    } finally {$process.Dispose()}
    foreach($mode in @('Complete','ProviderFailure','TotalBudget')) {
        if($mode -eq 'Complete'){
            $fixture=@'
function Get-SccPersistenceInventory {
 param([string]$OutDir)
 Write-Host 'SCC_PERSISTENCE_SECTION|FixtureComplete'
 @{SchemaVersion=1;Status='Complete';Findings=@();Sections=@{};Errors=@()} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutDir 'inventory.json') -Encoding UTF8
 Write-Host 'SCC_PERSISTENCE_DONE|FixtureComplete'
}
Export-ModuleMember -Function Get-SccPersistenceInventory
'@
        } elseif($mode -eq 'ProviderFailure'){
            $fixture=@'
function Get-SccPersistenceInventory {
 param([string]$OutDir)
 Write-Host 'SCC_PERSISTENCE_SECTION|FixtureFailure'
 throw 'fixture provider failure'
}
Export-ModuleMember -Function Get-SccPersistenceInventory
'@
        } else {
            $fixture=@'
function Get-SccPersistenceInventory {
 param([string]$OutDir)
 [IO.File]::WriteAllText((Join-Path $OutDir 'fixture-PID.txt'),[string]$PID)
 for($i=0;$i -lt 100;$i++){Write-Host 'SCC_PERSISTENCE_SECTION|FixtureBusy';Start-Sleep -Milliseconds 200}
}
Export-ModuleMember -Function Get-SccPersistenceInventory
'@
        }
        [IO.File]::WriteAllText((Join-Path $temp 'Persistence.Inventory.psm1'),$fixture,[Text.Encoding]::ASCII)
        $caseRun=Join-Path $temp $mode
        $psi.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $temp 'Invoke-PersistenceScan.ps1')+'" -WorkDir "'+$caseRun+'" -NoPrompt -InventorySectionTimeoutSeconds 4 -InventoryTotalTimeoutSeconds '+$(if($mode -eq 'TotalBudget'){'2'}else{'10'})
        $case=[Diagnostics.Process]::Start($psi)
        $caseOut=$case.StandardOutput.ReadToEndAsync();$caseErr=$case.StandardError.ReadToEndAsync()
        try {
            if(-not $case.WaitForExit(15000)){$case.Kill();throw ($mode+' fixture exceeded bounded wait')}
            $data=[IO.File]::ReadAllText((Join-Path (Join-Path $caseRun 'persistence') 'result.json'))|ConvertFrom-Json
            if($mode -eq 'Complete'){
                if($case.ExitCode -ne 0 -or $data.Status -ne 'Complete' -or $data.RemovalStatus -ne 'NoCandidates'){throw 'Successful worker outcome was lost'}
            } else {
                if($case.ExitCode -eq 0 -or $data.Status -ne 'Incomplete' -or $data.RemovalStatus -ne 'Skipped'){throw ($mode+' did not disable removal')}
                if($mode -eq 'TotalBudget' -and ($data.Errors -join ' ') -notmatch 'timed out'){throw 'Repeated progress markers bypassed total deadline'}
                if($mode -eq 'ProviderFailure' -and ($data.Errors -join ' ') -notmatch 'worker exited 1'){throw ('Native worker exit code was lost: '+($data.Errors -join ' '))}
            }
            if(Test-Path -LiteralPath (Join-Path $temp 'UNSAFE-REMOVAL.txt')){throw 'Unexpected removal import'}
            Write-Host ('PASS: '+$mode+' actual worker/wrapper result and removal gate')
        } finally {$case.Dispose()}
    }
} finally {
    # Only dispose the unique fixture provider PID, never user processes.
    $pidPath=Join-Path (Join-Path (Join-Path $temp 'run') 'persistence') 'fixture-PID.txt'
    if(Test-Path -LiteralPath $pidPath){$fixturePid=[int][IO.File]::ReadAllText($pidPath);$p=Get-Process -Id $fixturePid -ErrorAction SilentlyContinue;if($p){try{$p.Kill();$null=$p.WaitForExit(5000)}catch{}}}
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
