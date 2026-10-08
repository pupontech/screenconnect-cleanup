[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$WorkDir,
    [switch]$SkipRemoval,
    [switch]$RollbackReady,
    [switch]$NoPrompt,
    [switch]$WhatIf,
    [switch]$OpenReview,
    [string]$PreflightRoot,
    [ValidateRange(1,300)][int]$InventorySectionTimeoutSeconds=60,
    [ValidateRange(1,600)][int]$InventoryTotalTimeoutSeconds=300
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ErrorList = New-Object System.Collections.ArrayList
$persistDir = Join-Path $WorkDir 'persistence'
$inventoryPath = Join-Path $persistDir 'inventory.json'
$removalPath = Join-Path $persistDir 'removal.json'
$resultPath = Join-Path $persistDir 'result.json'
$inventoryStatus = 'Incomplete'
$removalStatus = 'Skipped'
$overallStatus = 'Complete'
$rollbackOk = [bool]$RollbackReady
function Assert-ArtifactPath {
    param([string]$Path)
    $current=[IO.Path]::GetFullPath($Path)
    while($current) {
        if(Test-Path -LiteralPath $current -ErrorAction Stop) {
            $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Redirected persistence artifact paths are refused.'}
        }
        $parent=Split-Path -Parent $current
        if(-not $parent -or $parent -eq $current){break}
        $current=$parent
    }
}
try {
    Assert-ArtifactPath $persistDir
    # collection-progress.log is included so a rerun into a directory from a
    # crashed attempt reports the fresh-run requirement instead of a raw
    # exclusive-create failure from the worker log.
    foreach($file in @($inventoryPath,$removalPath,$resultPath,(Join-Path $persistDir 'collection-progress.log'))) {
        Assert-ArtifactPath $file
        if(Test-Path -LiteralPath $file){throw 'Existing persistence artifacts are not overwritten; use a fresh run directory.'}
    }
} catch {Write-Error $_.Exception.Message;exit 1}
function Write-JsonArtifact {
    param([string]$Path, $Object)
    Assert-ArtifactPath $Path
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force -ErrorAction Stop
    Assert-ArtifactPath $Path
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $Object -Depth 16))
    $stream=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
function Write-RemovalRecord {
    param([string]$Status,[string[]]$Errors=@())
    $record=[pscustomobject]@{SchemaVersion=1;Status=$Status;Actions=@();Errors=@($Errors)}
    try { Write-JsonArtifact -Path $removalPath -Object $record } catch { [void]$ErrorList.Add(('Could not write removal.json: '+$_.Exception.Message)) }
}
function Invoke-SccInventoryWorker {
    param([string]$OutDir,[int]$SectionTimeoutSeconds,[int]$TotalTimeoutSeconds)
    $worker=Join-Path $PSScriptRoot 'Invoke-PersistenceInventoryWorker.ps1'
    if(-not(Test-Path -LiteralPath $worker -PathType Leaf)){throw 'Inventory worker script is missing.'}
    Assert-ArtifactPath $OutDir
    $null=New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction Stop
    $logPath=Join-Path $OutDir 'collection-progress.log'
    Assert-ArtifactPath $logPath
    # Share read AND write so a technician (or this process's own test) can tail
    # the log while the run is still writing to it on Windows.
    $logStream=New-Object IO.FileStream($logPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    $log=New-Object IO.StreamWriter($logStream,(New-Object Text.UTF8Encoding($false)))
    $log.AutoFlush=$true
    $process=$null
    try {
        $hostExe=(Get-Process -Id $PID -ErrorAction Stop).Path
        $psi=New-Object Diagnostics.ProcessStartInfo
        $psi.FileName=$hostExe
        # Paths travel through the inherited environment, not interpolated PS source.
        # A worker whose script cannot be resolved at all never runs a native
        # command, so $LASTEXITCODE stays null and a bare "exit $LASTEXITCODE"
        # would report success. Refuse explicitly instead.
        $psi.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& $env:SCC_INVENTORY_WORKER -OutDir $env:SCC_INVENTORY_OUTDIR; if ($null -eq $LASTEXITCODE) { exit 1 } else { exit $LASTEXITCODE }"'
        $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
        $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
        $psi.EnvironmentVariables['SCC_INVENTORY_WORKER']=$worker
        $psi.EnvironmentVariables['SCC_INVENTORY_OUTDIR']=$OutDir
        $process=[Diagnostics.Process]::Start($psi)
        if(-not $process){throw 'Inventory worker did not start.'}
        $stdout=$process.StandardOutput.ReadLineAsync();$stderr=$process.StandardError.ReadLineAsync()
        $outEnded=$false;$errEnded=$false;$section='WorkerStartup'
        $clock=[Diagnostics.Stopwatch]::StartNew();$sectionClock=[Diagnostics.Stopwatch]::StartNew()
        $lastHeartbeat=0.0;$heartbeat=[Math]::Min(5,[Math]::Max(1,$SectionTimeoutSeconds/2))
        $logChars=0;$logLimit=1MB;$logCapped=$false
        Write-Host ('[Persistence] Starting collection. Section limit: '+$SectionTimeoutSeconds+'s; total limit: '+$TotalTimeoutSeconds+'s.')
        while(-not $process.HasExited -or -not $outEnded -or -not $errEnded) {
            foreach($stream in @('out','err')) {
                $task=if($stream -eq 'out'){$stdout}else{$stderr}
                $ended=if($stream -eq 'out'){$outEnded}else{$errEnded}
                if(-not $ended -and $task.IsCompleted) {
                    $line=$task.GetAwaiter().GetResult()
                    if($null -eq $line){if($stream -eq 'out'){$outEnded=$true}else{$errEnded=$true};continue}
                    if($line.Length -gt 4096){$line=$line.Substring(0,4096)+' [truncated]'}
                    if($logChars -lt $logLimit){$log.WriteLine($line);$logChars+=$line.Length}
                    elseif(-not $logCapped){$log.WriteLine('[Persistence] Progress log truncated at the 1 MB limit.');$logCapped=$true}
                    if($stream -eq 'out' -and $line -match '^SCC_PERSISTENCE_SECTION\|([A-Za-z0-9]+)$') {
                        $section=$Matches[1];$sectionClock.Restart();$lastHeartbeat=$clock.Elapsed.TotalSeconds
                        Write-Host ('[Persistence] Collecting '+$section+' ...')
                    } elseif($line -match '^SCC_PERSISTENCE_DONE\|([A-Za-z0-9]+)$') {
                        Write-Host ('[Persistence] Finished '+$Matches[1]+'.')
                    } elseif($stream -eq 'err') { Write-Host ('[Persistence] Worker: '+$line) }
                    if($stream -eq 'out'){$stdout=$process.StandardOutput.ReadLineAsync()}else{$stderr=$process.StandardError.ReadLineAsync()}
                }
            }
            if($clock.Elapsed.TotalSeconds -ge $TotalTimeoutSeconds -or $sectionClock.Elapsed.TotalSeconds -ge $SectionTimeoutSeconds) {
                $message='Inventory timed out while collecting '+$section+'; collection is incomplete, removal disabled. Progress log: '+$logPath
                $log.WriteLine($message);Write-Host ('[Persistence] '+$message)
                if(-not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(5000)){throw 'Inventory worker did not terminate; removal is disabled.'}}
                throw $message
            }
            if(-not $process.HasExited -and ($clock.Elapsed.TotalSeconds-$lastHeartbeat) -ge $heartbeat) {
                $message='[Persistence] '+$section+' still collecting ('+[int]$sectionClock.Elapsed.TotalSeconds+'s).'
                Write-Host $message
                if($logChars -lt $logLimit){$log.WriteLine($message);$logChars+=$message.Length}
                $lastHeartbeat=$clock.Elapsed.TotalSeconds
            }
            Start-Sleep -Milliseconds 50
        }
        $process.WaitForExit()
        if($process.ExitCode -ne 0){throw ('Inventory worker exited '+$process.ExitCode+' while collecting '+$section+'. Progress log: '+$logPath)}
    } finally {
        if($process){if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(5000)};$process.Dispose()}
        $log.Dispose()
    }
}
function Test-GuidedRollbackReadiness {
    param([string]$Root)
    if (-not $Root -or -not (Test-Path -LiteralPath $Root -PathType Container)) { return $false }
    $required=@('HKLM-SOFTWARE.hiv','HKLM-SYSTEM.hiv','HKCU.hiv')
    foreach ($dir in @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue)) {
        $log=Join-Path $dir.FullName 'master.log'; $hiveDir=Join-Path $dir.FullName 'registry'
        if (-not (Test-Path -LiteralPath $log -PathType Leaf)) { continue }
        $text=Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue
        if ($text -notmatch '(?m)^PREFLIGHT COMPLETE ' -or $text -notmatch '(?m)^\[OK\] restore point \+ hive export\r?$') { continue }
        $all=$true
        foreach($name in $required){$p=Join-Path $hiveDir $name;if(-not(Test-Path -LiteralPath $p -PathType Leaf)-or(Get-Item -LiteralPath $p).Length -le 0){$all=$false}}
        if($all){return $true}
    }
    return $false
}
if($RollbackReady) {
    $rollbackOk=$false
    $master=Join-Path $WorkDir 'master.log'
    if(Test-Path -LiteralPath $master -PathType Leaf) {
        $masterText=Get-Content -LiteralPath $master -Raw -ErrorAction Stop
        if($masterText -match '(?m)^Restore point: Created\r?$') {
            $rollbackOk=$true
            foreach($name in @('HKLM_SOFTWARE.reg','HKLM_SYSTEM.reg','HKCU_SOFTWARE.reg')) {
                $hive=Join-Path (Join-Path $WorkDir 'registry_hives') $name
                if(-not(Test-Path -LiteralPath $hive -PathType Leaf)-or(Get-Item -LiteralPath $hive).Length -le 0){$rollbackOk=$false}
            }
        }
    }
}
if ($PreflightRoot -and -not $rollbackOk) { $rollbackOk=Test-GuidedRollbackReadiness -Root $PreflightRoot }
if ($WhatIf) {
    $inventoryStatus='Planned'; $removalStatus='Planned'
    [void]$ErrorList.Add('WhatIf: inventory collection and removal were not executed.')
    Write-RemovalRecord -Status 'Planned' -Errors @('WhatIf: no removal review was run.')
} else {
    $inventoryObject=$null
    try {
        Invoke-SccInventoryWorker -OutDir $persistDir -SectionTimeoutSeconds $InventorySectionTimeoutSeconds -TotalTimeoutSeconds $InventoryTotalTimeoutSeconds
        if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) { throw 'Inventory module did not write inventory.json.' }
        $inventoryObject=Get-Content -LiteralPath $inventoryPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $inventoryStatus=[string]$inventoryObject.Status
        if ($inventoryStatus -notin @('Complete','Incomplete','Unsupported')) { throw 'Inventory status is invalid.' }
        if ($inventoryStatus -ne 'Complete') {
            [void]$ErrorList.Add('Inventory collection status: '+$inventoryStatus)
            [void]$ErrorList.AddRange([object[]]@($inventoryObject.Errors))
            # Surface the reason on the console: a silent "incomplete" is what made
            # the previous live failure hard to diagnose.
            $shown=0
            foreach($entry in @($inventoryObject.Errors)) {
                if($shown -ge 12){Write-Host ('[Persistence] ... further collection notes are in inventory.json and collection-progress.log');break}
                Write-Host ('[Persistence] '+[string]$entry);$shown++
            }
            foreach($sectionName in @($inventoryObject.Sections.PSObject.Properties.Name)) {
                $sectionState=[string]$inventoryObject.Sections.$sectionName.Status
                if($sectionState -and $sectionState -ne 'Complete'){Write-Host ('[Persistence] Section '+$sectionName+': '+$sectionState)}
            }
        }
    } catch {
        $inventoryStatus='Incomplete'; $overallStatus='Incomplete'
        [void]$ErrorList.Add('Inventory collection failed: '+$_.Exception.Message)
        Write-Host ('[Persistence] Collection failed: '+$_.Exception.Message)
        try { Write-JsonArtifact -Path $inventoryPath -Object ([pscustomobject]@{SchemaVersion=1;Status='Incomplete';Errors=@($ErrorList);Findings=@();Sections=[pscustomobject]@{}}) }
        catch { [void]$ErrorList.Add('Could not persist inventory failure record: '+$_.Exception.Message) }
    }
    if ($SkipRemoval) {
        $removalStatus='Skipped'; Write-RemovalRecord -Status 'Skipped'
    } elseif ($inventoryObject -and $inventoryObject.Findings) {
        try {
            Import-Module (Join-Path $PSScriptRoot 'Persistence.Removal.psm1') -Force -ErrorAction Stop
            $rem=Invoke-SccPersistenceReview -Inventory $inventoryObject -OutDir $persistDir -AllowRemoval:([bool]$rollbackOk) -NoPrompt:$NoPrompt
            $removalStatus=[string]$rem.Status
            if ($removalStatus -eq 'Incomplete') { $overallStatus='Incomplete'; [void]$ErrorList.AddRange([object[]]@($rem.Errors)) }
            if (-not $rollbackOk -and @($inventoryObject.Findings).Count -gt 0) { [void]$ErrorList.Add('Removal disabled: verified rollback artifacts were not ready.') }
        } catch {
            $removalStatus='Incomplete'; $overallStatus='Incomplete'; $message='Removal review failed: '+$_.Exception.Message
            [void]$ErrorList.Add($message); Write-RemovalRecord -Status 'Incomplete' -Errors @($message)
        }
    } else {
        $removalStatus=if($inventoryStatus -eq 'Complete'){'NoCandidates'}else{'Skipped'}
        $noCandidateReason='No inventory findings were available for review.'
        if ($inventoryStatus -eq 'Unsupported') { $noCandidateReason='Inventory collection is unsupported on this platform; removal was not attempted.' }
        Write-RemovalRecord -Status $removalStatus
    }
    if ($inventoryStatus -ne 'Complete') { $overallStatus='Incomplete' }
}
$result=[pscustomobject]@{SchemaVersion=1;Status=$overallStatus;InventoryPath=$inventoryPath;RemovalPath=$removalPath;InventoryStatus=$inventoryStatus;RemovalStatus=$removalStatus;RollbackReady=$rollbackOk;Errors=@($ErrorList.ToArray())}
try { Write-JsonArtifact -Path $resultPath -Object $result }
catch { Write-Error ('Could not write persistence result: '+$_.Exception.Message); exit 1 }
if ($OpenReview -and -not $WhatIf) {
    # Attended, read-only: opens the folders, Services and Task Scheduler for the
    # technician. Never approves or performs cleanup.
    $reviewScript=Join-Path $PSScriptRoot 'Show-PersistenceReview.ps1'
    if (Test-Path -LiteralPath $reviewScript -PathType Leaf) {
        try { & $reviewScript -WorkDir $WorkDir } catch { Write-Host ('[Persistence] Review windows failed: '+$_.Exception.Message) }
    } else {
        # Console warning only: result.json is already written, so appending here
        # would be recorded nowhere and make the artifact disagree with the run.
        Write-Host '[Persistence] Show-PersistenceReview.ps1 is missing; review windows were not opened.'
    }
}
if ($overallStatus -ne 'Complete') { exit 1 }
exit 0
