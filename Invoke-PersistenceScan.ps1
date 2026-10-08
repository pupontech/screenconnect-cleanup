[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$WorkDir,
    [switch]$SkipRemoval,
    [switch]$RollbackReady,
    [switch]$NoPrompt,
    [switch]$WhatIf,
    [string]$PreflightRoot
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
    foreach($file in @($inventoryPath,$removalPath,$resultPath)) {
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
        Import-Module (Join-Path $PSScriptRoot 'Persistence.Inventory.psm1') -Force -ErrorAction Stop
        $null=Get-SccPersistenceInventory -OutDir $persistDir
        if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) { throw 'Inventory module did not write inventory.json.' }
        $inventoryObject=Get-Content -LiteralPath $inventoryPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $inventoryStatus=[string]$inventoryObject.Status
        if ($inventoryStatus -notin @('Complete','Incomplete','Unsupported')) { throw 'Inventory status is invalid.' }
        if ($inventoryStatus -ne 'Complete') { [void]$ErrorList.Add('Inventory collection status: '+$inventoryStatus); [void]$ErrorList.AddRange([object[]]@($inventoryObject.Errors)) }
    } catch {
        $inventoryStatus='Incomplete'; $overallStatus='Incomplete'
        [void]$ErrorList.Add('Inventory collection failed: '+$_.Exception.Message)
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
if ($overallStatus -ne 'Complete') { exit 1 }
exit 0
