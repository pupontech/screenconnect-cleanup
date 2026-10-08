# =====================================================================
# Show-PersistenceReview.ps1 -- open the attended review windows.
#
# Read-only. Opens Explorer at the evidence/startup/task folders and launches
# services.msc + taskschd.msc so the technician can inspect by hand what the
# persistence scan reported. It changes NOTHING: no service, task, registry or
# file is modified, and it never approves or performs removal.
#
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$WorkDir,
    # Test seam: receives ($FilePath, $ArgumentList) instead of Start-Process.
    [scriptblock]$Launcher = $null,
    [switch]$WhatIf
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-Value {
    param($InputObject,[string]$Name)
    if($null -eq $InputObject -or -not $Name){return $null}
    $property=$InputObject.PSObject.Properties[$Name]
    if($property){return $property.Value}
    return $null
}
function Get-List {
    param($InputObject,[string]$Name)
    $value=Get-Value $InputObject $Name
    if($null -eq $value){return @()}
    return @($value)
}

$persistDir=Join-Path $WorkDir 'persistence'
$inventoryPath=Join-Path $persistDir 'inventory.json'
if(-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) {
    Write-Host ('[Review] No persistence inventory at ' + $inventoryPath)
    Write-Host '[Review] Run the persistence scan (guided Step 6d) first.'
    exit 2
}
try { $inventory=Get-Content -LiteralPath $inventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop }
catch { Write-Host ('[Review] Could not read the inventory: ' + $_.Exception.Message); exit 1 }

$sections=Get-Value $inventory 'Sections'
$findings=Get-List $inventory 'Findings'

# ---- Build the review targets (folders + consoles) ------------------------
$folders=New-Object System.Collections.ArrayList
function Add-Folder {
    param([string]$Path,[string]$Label)
    if(-not $Path){return}
    if($script:seenFolders.Contains($Path)){return}
    [void]$script:seenFolders.Add($Path)
    [void]$script:folders.Add([pscustomobject]@{Kind='Folder';Label=$Label;Path=$Path;Exists=[bool](Test-Path -LiteralPath $Path -PathType Container)})
}
$script:seenFolders=New-Object System.Collections.ArrayList

Add-Folder -Path $persistDir -Label 'Persistence evidence (inventory + progress log)'
Add-Folder -Path (Join-Path $persistDir 'task_xml') -Label 'Exported task XML evidence'
Add-Folder -Path (Join-Path $persistDir 'quarantine') -Label 'Quarantine (files moved aside, never deleted)'
if($env:SystemRoot){Add-Folder -Path (Join-Path $env:SystemRoot 'System32\Tasks') -Label 'Scheduled task definition files on disk'}
try { $common=[Environment]::GetFolderPath('CommonStartup'); if($common){Add-Folder -Path $common -Label 'All-users startup folder'} } catch { }

# Startup folders actually observed by the scan (covers loaded user profiles).
foreach($item in (Get-List (Get-Value $sections 'StartupFiles') 'Items')) {
    $filePath=[string](Get-Value $item 'FilePath')
    if($filePath){ Add-Folder -Path (Split-Path -Parent $filePath) -Label ('Startup folder (' + [string](Get-Value $item 'UserName') + ')') }
}

$consoles=@(
    [pscustomobject]@{Kind='Console';Label='Services (check startup type + running state)';File='services.msc';Arguments=''},
    [pscustomobject]@{Kind='Console';Label='Task Scheduler (check the flagged tasks)';File='taskschd.msc';Arguments=''}
)

# ---- Checklist of what to look at ----------------------------------------
$checklist=New-Object System.Collections.ArrayList
foreach($finding in $findings) {
    $kind=[string](Get-Value $finding 'Kind')
    $reviewOnly=[bool](Get-Value $finding 'ReviewOnly')
    if($kind -notin @('ScheduledTask','RunKey','StartupFile','HiddenTask')){continue}
    [void]$checklist.Add([pscustomobject]@{
        Kind=$kind
        Target=[string](Get-Value $finding 'Target')
        Command=[string](Get-Value $finding 'Command')
        Reason=[string](Get-Value $finding 'Reason')
        ReviewOnly=$reviewOnly
        Where=$(switch($kind){
            'ScheduledTask' {'Task Scheduler (taskschd.msc) - find this exact task path/name'}
            'RunKey'        {'Registry Run/RunOnce value - review in regedit at the printed path'}
            'StartupFile'   {'Startup folder (opened) - inspect the exact file listed'}
            'HiddenTask'    {'Task Scheduler - compare with the on-disk task files folder'}
        })
    })
}
$remoteServices=@()
foreach($service in (Get-List (Get-Value $sections 'RemoteToolServices') 'Items')) {
    $remoteServices += [pscustomobject]@{
        Name=[string](Get-Value $service 'Name')
        DisplayName=[string](Get-Value $service 'DisplayName')
        Status=[string](Get-Value $service 'Status')
        StartType=[string](Get-Value $service 'StartType')
    }
}

# ---- Present the plan -----------------------------------------------------
Write-Host ''
Write-Host ' ============================================================'
Write-Host '  PERSISTENCE REVIEW - window to open for the technician'
Write-Host '  This step only opens windows. Nothing is changed, stopped or removed.'
Write-Host ' ============================================================'
$index=0
Write-Host ''
Write-Host ' Folders:'
foreach($folder in $folders) {
    $index++
    $state=if($folder.Exists){'open'}else{'not present'}
    Write-Host ('   {0}. [{1}] {2}  ->  {3}' -f $index,$state,$folder.Label,$folder.Path)
}
Write-Host ''
Write-Host ' Consoles:'
foreach($console in $consoles) {
    $index++
    Write-Host ('   {0}. [open] {1}' -f $index,$console.Label)
}
if($checklist.Count) {
    Write-Host ''
    Write-Host (' What the scan flagged (' + $checklist.Count + '):')
    $n=0
    foreach($entry in $checklist) {
        $n++
        $flag=if($entry.ReviewOnly){'REVIEW-ONLY (never auto-removed)'}else{'candidate - explicit selection required'}
        Write-Host ('   {0}) {1}  [{2}]' -f $n,$entry.Kind,$flag)
        Write-Host ('      target : ' + $entry.Target)
        if($entry.Command){Write-Host ('      command: ' + $entry.Command)}
        if($entry.Reason){Write-Host ('      reason : ' + $entry.Reason)}
        Write-Host ('      where  : ' + $entry.Where)
    }
} else {
    Write-Host ''
    Write-Host ' The scan flagged no persistence candidates in this run.'
}
if($remoteServices.Count) {
    Write-Host ''
    Write-Host ' Remote-access services seen (services.msc):'
    foreach($service in $remoteServices) {
        Write-Host ('   - {0}  [{1} / {2}]  {3}' -f $service.Name,$service.Status,$service.StartType,$service.DisplayName)
    }
}

# ---- Open them ------------------------------------------------------------
$opened=New-Object System.Collections.ArrayList
$failures=New-Object System.Collections.ArrayList
function Invoke-Open {
    param([string]$File,[string]$Arguments,[string]$Label)
    if($WhatIf) { Write-Host ('[Review] plan only: would open ' + $Label); return }
    try {
        if($Launcher) { $null=& $Launcher $File $Arguments }
        elseif($Arguments) { $null=Start-Process -FilePath $File -ArgumentList $Arguments -ErrorAction Stop }
        else { $null=Start-Process -FilePath $File -ErrorAction Stop }
        [void]$opened.Add([pscustomobject]@{Label=$Label;File=$File;Arguments=$Arguments;Status='Opened'})
    } catch {
        [void]$opened.Add([pscustomobject]@{Label=$Label;File=$File;Arguments=$Arguments;Status='Failed';Error=$_.Exception.Message})
        [void]$failures.Add($Label)
        Write-Host ('[Review] Could not open ' + $Label + ': ' + $_.Exception.Message)
    }
}
if(-not $WhatIf) { Write-Host ''; Write-Host ' Opening review windows...' }
foreach($folder in $folders) {
    if(-not $folder.Exists){continue}
    Invoke-Open -File 'explorer.exe' -Arguments $folder.Path -Label ('Folder: ' + $folder.Label)
}
foreach($console in $consoles) {
    Invoke-Open -File $console.File -Arguments $console.Arguments -Label ('Console: ' + $console.Label)
}

# ---- Audit trail in the run folder ---------------------------------------
$record=[pscustomobject]@{
    SchemaVersion = 1
    GeneratedUtc  = [DateTime]::UtcNow.ToString('o')
    ComputerName  = $env:COMPUTERNAME
    RunId         = [string](Get-Value $inventory 'RunId')
    WhatIf        = [bool]$WhatIf
    Opened        = @($opened.ToArray())
    Folders       = @($folders.ToArray())
    Consoles      = @(@($consoles | ForEach-Object {[pscustomobject]@{Label=$_.Label;File=$_.File}}))
    Checklist     = @($checklist.ToArray())
    RemoteServices= @($remoteServices)
    Failures      = @($failures.ToArray())
}
try {
    $target=Join-Path $persistDir 'review-opened.json'
    if(-not $WhatIf) {
        $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $record -Depth 8))
        $stream=New-Object IO.FileStream($target,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
        Write-Host ('[Review] Wrote ' + $target)
    } else { Write-Host ('[Review] plan only: would write ' + $target) }
} catch { Write-Host ('[Review] Could not write the review record: ' + $_.Exception.Message) }

Write-Host ''
Write-Host ' Review only. Nothing was changed, stopped or removed by this step.'
Write-Host ' Automated cleanup still requires explicit selection plus a typed REMOVE.'
if($WhatIf){ exit 0 }
if($failures.Count){ exit 1 }
exit 0
