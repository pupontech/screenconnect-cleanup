# Exercise the real wrapper with only harmless provider fixtures; no live collection.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc watchdog fixture '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$hostExe=(Get-Process -Id $PID).Path
$testStarted=(Get-Date)
$script:FixturePidFiles=New-Object System.Collections.ArrayList
function Test-SccOwnedFixtureProcess {
    # Never kill a PID we cannot tie to this test's own fixture worker.
    param([int]$Id)
    $p=Get-Process -Id $Id -ErrorAction SilentlyContinue
    if(-not $p){return $null}
    try {
        $path=$p.Path
        $started=$p.StartTime
    } catch { return $null }
    if($path -cne $hostExe -or $started -lt $testStarted.AddSeconds(-2)){ return $null }
    return $p
}
function Read-SccSharedText {
    # The wrapper keeps the progress log open for writing; a plain
    # [IO.File]::ReadAllText takes only FileShare.Read and is refused on Windows.
    param([string]$Path)
    if(-not (Test-Path -LiteralPath $Path)){return ''}
    $stream=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $reader=New-Object IO.StreamReader($stream)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}
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
    # 8s leaves room for cold powershell.exe startup + module import while still
    # tripping on the fixture's 30s sleep; production defaults are 60s/300s.
    if($wrapper -match 'InventorySectionTimeoutSeconds'){$psi.Arguments+=' -InventorySectionTimeoutSeconds 8 -InventoryTotalTimeoutSeconds 20'}
    $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
    $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($psi)
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    # Liveness proof: observe the progress log WHILE the run is still executing.
    $observedBeforeExit=$false
    $observe=New-Object Diagnostics.Stopwatch
    $observe.Start()
    try {
        $progressLog=Join-Path (Join-Path $run 'persistence') 'collection-progress.log'
        while(-not $process.HasExited -and $observe.Elapsed.TotalSeconds -lt 100) {
            if((Test-Path -LiteralPath $progressLog) -and ((Read-SccSharedText $progressLog) -match 'FixtureBlocked')){ $observedBeforeExit=$true; break }
            Start-Sleep -Milliseconds 100
        }
        if(-not $process.WaitForExit(25000)) {
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
        $errorText=$result.Errors -join ' '
        if($errorText -notmatch 'timed out'){throw ('Timeout was not recorded: '+$errorText)}
        $sawMarker=($errorText -match 'FixtureBlocked')
        if(-not $sawMarker -and $errorText -notmatch 'WorkerStartup'){throw ('Stall was recorded against an unexpected section: '+$errorText)}
        if($output -notmatch 'still collecting'){throw ('Heartbeat was not streamed to the console: '+$output)}
        if($sawMarker) {
            if($output -notmatch 'FixtureBlocked'){throw ('Stalled section name was not streamed: '+$output)}
            if(-not $observedBeforeExit){throw 'Progress was only visible after the run ended, so live streaming is not proven.'}
        } else {
            Write-Host 'NOTE: host startup exceeded the fixture deadline, so the stall was reported against WorkerStartup.'
        }
        if(Test-Path -LiteralPath (Join-Path $temp 'UNSAFE-REMOVAL.txt')){throw 'Removal was reached after inventory timeout.'}
        $workerPid=[int][IO.File]::ReadAllText((Join-Path $persist 'fixture-PID.txt'))
        [void]$script:FixturePidFiles.Add((Join-Path $persist 'fixture-PID.txt'))
        $alive=Get-Process -Id $workerPid -ErrorAction SilentlyContinue
        if($alive -and -not $alive.HasExited){throw 'Timed-out inventory worker was left alive.'}
        $log=Read-SccSharedText (Join-Path $persist 'collection-progress.log')
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
            if(-not $case.WaitForExit(25000)){$case.Kill();throw ($mode+' fixture exceeded bounded wait')}
            $data=[IO.File]::ReadAllText((Join-Path (Join-Path $caseRun 'persistence') 'result.json'))|ConvertFrom-Json
            $casePidFile=Join-Path (Join-Path $caseRun 'persistence') 'fixture-PID.txt'
            if(Test-Path -LiteralPath $casePidFile){
                [void]$script:FixturePidFiles.Add($casePidFile)
                $caseWorkerPid=[int][IO.File]::ReadAllText($casePidFile)
                $caseAlive=Get-Process -Id $caseWorkerPid -ErrorAction SilentlyContinue
                if($caseAlive -and -not $caseAlive.HasExited){throw ($mode+' left its inventory worker alive.')}
            }
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
    # A crashed previous attempt must produce the fresh-run message, not a raw
    # exclusive-create failure from the worker progress log.
    $staleRun=Join-Path $temp 'StaleRun'
    $stalePersist=Join-Path $staleRun 'persistence'
    $null=New-Item -ItemType Directory -Path $stalePersist -Force
    [IO.File]::WriteAllText((Join-Path $stalePersist 'collection-progress.log'),'leftover from an interrupted run')
    $staleOut=Join-Path $temp 'StaleOut.txt'
    $staleErr=Join-Path $temp 'StaleErr.txt'
    $stale=Start-Process -FilePath $hostExe -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $temp 'Invoke-PersistenceScan.ps1')+'" -WorkDir "'+$staleRun+'" -NoPrompt') -NoNewWindow -Wait -PassThru -RedirectStandardOutput $staleOut -RedirectStandardError $staleErr
    $staleText=[IO.File]::ReadAllText($staleOut)+' '+[IO.File]::ReadAllText($staleErr)
    if($stale.ExitCode -eq 0){throw 'A reused run directory was incorrectly accepted.'}
    # PowerShell wraps the formatted error at the host width, so assert the
    # distinguishing words rather than one contiguous sentence.
    if($staleText -notmatch '(?i)fresh' -or $staleText -notmatch '(?i)run' -or $staleText -notmatch '(?i)directory'){throw ('Reused run directory did not report the fresh-run requirement: '+$staleText)}
    if(Test-Path -LiteralPath (Join-Path $stalePersist 'inventory.json')){throw 'A refused reused run directory still wrote inventory evidence.'}
    if(Test-Path -LiteralPath (Join-Path $temp 'UNSAFE-REMOVAL.txt')){throw 'Removal was reached for a reused run directory.'}
    Write-Host 'PASS: leftover progress log is refused with the fresh-run requirement'
    # An unresolvable worker must not be reported as a successful launch.
    $noWorkerRoot=Join-Path $temp 'NoWorker'
    $null=New-Item -ItemType Directory -Path $noWorkerRoot -Force
    Copy-Item -LiteralPath (Join-Path $temp 'Invoke-PersistenceScan.ps1') -Destination $noWorkerRoot
    if(Test-Path -LiteralPath (Join-Path $noWorkerRoot 'Invoke-PersistenceInventoryWorker.ps1')){Remove-Item -LiteralPath (Join-Path $noWorkerRoot 'Invoke-PersistenceInventoryWorker.ps1') -Force}
    $noWorkerRun=Join-Path $temp 'NoWorkerRun'
    $noWorkerOut=Join-Path $temp 'NoWorkerOut.txt'
    $noWorkerErr=Join-Path $temp 'NoWorkerErr.txt'
    $noWorker=Start-Process -FilePath $hostExe -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $noWorkerRoot 'Invoke-PersistenceScan.ps1')+'" -WorkDir "'+$noWorkerRun+'" -NoPrompt') -NoNewWindow -Wait -PassThru -RedirectStandardOutput $noWorkerOut -RedirectStandardError $noWorkerErr
    if($noWorker.ExitCode -eq 0){throw 'A missing inventory worker was reported as success.'}
    $noWorkerData=[IO.File]::ReadAllText((Join-Path (Join-Path $noWorkerRun 'persistence') 'result.json'))|ConvertFrom-Json
    if($noWorkerData.Status -ne 'Incomplete' -or $noWorkerData.RemovalStatus -ne 'Skipped'){throw 'Missing worker did not fail closed.'}
    if(($noWorkerData.Errors -join ' ') -notmatch 'worker script is missing'){throw ('Missing worker was not identified: '+($noWorkerData.Errors -join ' '))}
    if(Test-Path -LiteralPath (Join-Path $temp 'UNSAFE-REMOVAL.txt')){throw 'Removal was reached with a missing worker.'}
    Write-Host 'PASS: missing inventory worker fails closed and never reports success'
} finally {
    # Terminate only fixture workers this test started and could identify as its
    # own PowerShell host process; never an unrelated user process.
    foreach($pidPath in @($script:FixturePidFiles)) {
        if(-not (Test-Path -LiteralPath $pidPath)){continue}
        $fixturePid=0
        if(-not [int]::TryParse(([IO.File]::ReadAllText($pidPath)).Trim(),[ref]$fixturePid)){continue}
        $owned=Test-SccOwnedFixtureProcess -Id $fixturePid
        if($owned){try{$owned.Kill();$null=$owned.WaitForExit(5000)}catch{}}
    }
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
