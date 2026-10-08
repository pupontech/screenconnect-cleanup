# Attended review-window fixture. Injects a recorder launcher so NO real window,
# service console or task scheduler is ever started.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$scriptPath=Join-Path $repo 'Show-PersistenceReview.ps1'
if(-not (Test-Path -LiteralPath $scriptPath)){throw 'Show-PersistenceReview.ps1 is missing.'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc review fixture '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    # A run folder with a realistic inventory: candidates, review-only rows and a
    # startup file, plus the folders a technician is meant to inspect.
    $run=Join-Path $temp 'HOST-20261008'
    $persist=Join-Path $run 'persistence'
    $taskXml=Join-Path $persist 'task_xml'
    $quarantine=Join-Path $persist 'quarantine'
    $startup=Join-Path $temp 'user-startup'
    foreach($dir in @($persist,$taskXml,$quarantine,$startup)){ $null=New-Item -ItemType Directory -Path $dir -Force }
    [IO.File]::WriteAllText((Join-Path $startup 'suspect.vbs'),'x')
    $inventory=[pscustomobject]@{
        SchemaVersion=1; RunId='HOST-20261008'; ComputerName='HOST'; Status='Incomplete'
        Errors=@('Demo: coverage gap')
        Sections=[pscustomobject]@{
            StartupFiles=[pscustomobject]@{Status='Complete';Errors=@();Items=@([pscustomobject]@{FilePath=(Join-Path $startup 'suspect.vbs');UserName='Admin';SID='S-1-5-21-1-2-3-1001'})}
            RemoteToolServices=[pscustomobject]@{Status='Complete';Errors=@();Items=@([pscustomobject]@{Name='AnyDesk';DisplayName='AnyDesk Service';Status='Running';StartType='Automatic'})}
            TaskXml=[pscustomobject]@{Status='Complete';Errors=@();Items=@()}
        }
        Findings=@(
            [pscustomobject]@{Id=('a'*24);Kind='ScheduledTask';Target='\Evil\Run';Command='powershell -w hidden';Reason='script host';ReviewOnly=$false;Details=[pscustomobject]@{TaskName='Run';TaskPath='\Evil\'}}
            [pscustomobject]@{Id=('b'*24);Kind='HiddenTask';Target='HiddenTask|OrphanTaskFile|x';Command='visibility';Reason='not registered';ReviewOnly=$true;Details=[pscustomobject]@{}}
            [pscustomobject]@{Id=('c'*24);Kind='StartupFile';Target=(Join-Path $startup 'suspect.vbs');Command='wscript suspect.vbs';Reason='script host';ReviewOnly=$false;Details=[pscustomobject]@{}})
    }
    [IO.File]::WriteAllText((Join-Path $persist 'inventory.json'),($inventory | ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($false)))

    # Recorder seam: capture launches instead of opening windows.
    $global:ReviewLaunches=New-Object System.Collections.ArrayList
    # NOTE: never name a scriptblock parameter $args - the automatic variable
    # shadows it and the recorded arguments come back empty.
    $recorder=[scriptblock]{ param($file,$argumentList) [void]$global:ReviewLaunches.Add([pscustomobject]@{File=$file;Arguments=$argumentList}) }
    # Write-Host goes to the information stream, so merge ALL streams to assert on it.
    $output=& $scriptPath -WorkDir $run -Launcher $recorder *>&1
    $text=$output -join "`n"
    $files=@($global:ReviewLaunches | ForEach-Object {$_.File})
    $argsList=@($global:ReviewLaunches | ForEach-Object {$_.Arguments})

    if($LASTEXITCODE -ne 0){throw ('Review run failed: '+$text)}
    if($files -notcontains 'services.msc'){throw 'services.msc was not offered to the technician.'}
    if($files -notcontains 'taskschd.msc'){throw 'taskschd.msc was not offered to the technician.'}
    if($files -notcontains 'explorer.exe'){throw 'No folder was opened for the technician.'}
    foreach($expected in @($persist,$taskXml,$quarantine,$startup)) {
        if($argsList -notcontains $expected){throw ('Expected folder was not opened: '+$expected)}
    }
    if($env:SystemRoot) {
        if(-not ($argsList | Where-Object { $_ -like '*System32\Tasks' })){throw 'The on-disk scheduled-task folder was not opened.'}
    }
    if($text -notmatch 'REVIEW-ONLY'){throw 'Review-only findings were not labelled as such.'}
    if($text -notmatch 'explicit selection required'){throw 'Removable candidates were not labelled.'}
    if($text -notmatch 'AnyDesk'){throw 'Remote-access services were not listed for services.msc review.'}
    if($text -notmatch 'Nothing is changed'){throw 'The review step did not state that it changes nothing.'}

    $record=Get-Content -LiteralPath (Join-Path $persist 'review-opened.json') -Raw | ConvertFrom-Json
    if([int]$record.SchemaVersion -ne 1 -or $record.RunId -ne 'HOST-20261008'){throw 'Review record lost schema or run identity.'}
    if(@($record.Opened).Count -lt 3){throw 'Review record did not capture the opened windows.'}
    if(@($record.Checklist | Where-Object { $_.Kind -eq 'ScheduledTask' }).Count -ne 1){throw 'Review record lost the flagged task.'}

    # WhatIf must never launch anything and must not write the record.
    Remove-Item -LiteralPath (Join-Path $persist 'review-opened.json') -Force
    $global:ReviewLaunches.Clear()
    $planOut=& $scriptPath -WorkDir $run -Launcher $recorder -WhatIf *>&1
    if($global:ReviewLaunches.Count -ne 0){throw 'WhatIf opened a window.'}
    if(Test-Path -LiteralPath (Join-Path $persist 'review-opened.json')){throw 'WhatIf wrote the review record.'}
    if(($planOut -join "`n") -notmatch 'plan only'){throw 'WhatIf did not explain that it is a plan.'}

    # No inventory: explicit refusal, nothing opened.
    $global:ReviewLaunches.Clear()
    $blank=Join-Path $temp 'blank'; $null=New-Item -ItemType Directory -Path $blank
    $missing=& $scriptPath -WorkDir $blank -Launcher $recorder *>&1
    if($LASTEXITCODE -eq 0){throw 'Review without an inventory was reported successful.'}
    if($global:ReviewLaunches.Count -ne 0){throw 'Review opened windows without an inventory.'}
    if(($missing -join "`n") -notmatch 'Run the persistence scan'){throw 'Review did not point at the missing scan.'}

    # The direct runner's opt-in switch must respect WhatIf: a plan run must not
    # open anything, and must not claim the review ran.
    $hostExe=(Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
    if(-not $hostExe){$hostExe=(Get-Command pwsh -ErrorAction SilentlyContinue).Source}
    if(-not $hostExe){$hostExe='pwsh'}
    $planWork=Join-Path $temp 'direct plan run'
    $planRun=& $hostExe -NoProfile -File (Join-Path $repo 'Invoke-PersistenceScan.ps1') -WorkDir $planWork -OpenReview -WhatIf *>&1
    if($LASTEXITCODE -ne 0){throw ('Direct OpenReview plan run failed: '+($planRun -join ' '))}
    if(Test-Path -LiteralPath (Join-Path $planWork 'persistence/review-opened.json')){throw 'WhatIf with -OpenReview opened the review.'}

    # The review step must not be able to change the system.
    $source=[IO.File]::ReadAllText($scriptPath)
    foreach($forbidden in @('Unregister-ScheduledTask','Remove-Item','Stop-Service','Set-Service','Remove-ItemProperty','New-ItemProperty','reg.exe','schtasks','net stop','sc.exe')) {
        if($source -match [regex]::Escape($forbidden)){throw ('Review script contains a mutating command: '+$forbidden)}
    }
    Write-Host 'PASS: attended review opens the right folders and consoles, is read-only, and refuses without an inventory.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
