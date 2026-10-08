$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Persistence.Inventory.psm1') -Force
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('scc-inventory-fixture-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmp
try {
    $module = Get-Module Persistence.Inventory
    & $module {
        param($fixtureDir)
        $script:FixtureDir=$fixtureDir
        $script:FixtureTaskCount=3
        $script:FixtureComHandler=$false
        function Get-ScheduledTask {
            if($script:FixtureComHandler){[pscustomobject]@{TaskName='ComFixture';TaskPath='\Microsoft\Fixture\';State='Ready';Principal=[pscustomobject]@{UserId='SYSTEM'};Actions=@([pscustomobject]@{ClassId='{11111111-1111-1111-1111-111111111111}'})};return}
            for ($i=0; $i -lt $script:FixtureTaskCount; $i++) {
                [pscustomobject]@{TaskName="Fixture$i";TaskPath='\';State='Ready';Principal=[pscustomobject]@{UserId='SYSTEM'};Actions=@([pscustomobject]@{Execute='powershell.exe';Arguments="-File C:\Users\Public\x$i.ps1"})}
            }
        }
        function Export-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) "<Task Name='$TaskName'><Exec>powershell.exe</Exec></Task>" }
        $xmlDir=Join-Path $fixtureDir 'task_xml';$null=New-Item -ItemType Directory -Path $xmlDir
        $task=Get-SccTaskEvidence -XmlDirectory $xmlDir
        if($task.Items.Count -ne 3 -or $task.Findings.Count -ne 3){throw 'many-task fixture did not produce task rows and candidates'}
        if([IO.Directory]::GetFiles($xmlDir,'*.xml').Count -ne 3){throw 'flagged task XML was not written'}
        $script:FixtureTaskCount=1;$one=Get-SccTaskEvidence -XmlDirectory $xmlDir
        if($one.Items.Count -ne 1 -or $one.Findings.Count -ne 1){throw 'one-task fixture failed'}
        $script:FixtureTaskCount=0;$zero=Get-SccTaskEvidence -XmlDirectory $xmlDir
        if($zero.Items.Count -ne 0 -or $zero.Findings.Count -ne 0){throw 'zero-task fixture failed'}
        $script:FixtureComHandler=$true
        $com=Get-SccTaskEvidence -XmlDirectory $xmlDir
        if($com.Items.Count -ne 1 -or $com.Findings.Count -ne 0 -or $com.Items[0].Command -notmatch 'COM handler'){throw 'non-Exec task action was not collected safely'}
        $script:FixtureComHandler=$false

        function Get-SccProfileRoots { [pscustomobject]@{Profiles=@([pscustomobject]@{Sid='S-1-5-21-111-222-333-1001';Name='fixture';Root='Registry::HKEY_USERS\S-1-5-21-111-222-333-1001';Loaded=$true;ProfilePath=(Join-Path $script:FixtureDir 'profile')});Errors=@('S-1-5-21-111-222-333-1002 unloaded profile fixture')} }
        $profile=Get-SccProfileRoots
        if($profile.Profiles.Count -ne 1 -or $profile.Errors.Count -ne 1){throw 'loaded/unloaded profile coverage fixture failed'}
        $reg=Get-SccRegistryEvidence -ValueReader { param($path,$profile) if($path -like '*CurrentVersion*Run*' -or $path -like '*HKEY_USERS*Run*'){[pscustomobject]@{Name='Updater';Kind='String';Value='powershell.exe -File C:\Users\Public\a.ps1'}} }
        if(@($reg.Findings|Where-Object Kind -eq 'RunKey').Count -lt 1){throw 'registry fixture did not produce a candidate'}
        if(@($reg.Items|Where-Object {$_.ValueKind -eq 'Unknown'}).Count){throw 'registry value kind is unknown'}
        if(@($reg.Items|Where-Object {$_.RegistryPath -like 'Registry::HKEY_USERS\*'}).Count -lt 1){throw 'loaded user hive registry values absent'}

        $startupDir=Join-Path $script:FixtureDir 'profile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        $null=New-Item -ItemType Directory -Force -Path $startupDir
        $shortcut=Join-Path $startupDir 'fixture.lnk';[IO.File]::WriteAllText($shortcut,'fixture')
        $startup=Get-SccStartupEvidence -Profiles $profile.Profiles -CommonDirectory (Join-Path $fixtureDir 'missing-common-startup') -ShortcutResolver { param($path) 'powershell.exe -File C:\Users\Public\fixture.ps1' }
        if($startup.Items.Count -ne 1 -or $startup.Findings.Count -ne 1 -or -not $startup.Items[0].SHA256){throw 'startup shortcut fixture failed'}

        $taskRoot=Join-Path $script:FixtureDir 'Tasks';$null=New-Item -ItemType Directory -Path $taskRoot
        [IO.File]::WriteAllText((Join-Path $taskRoot 'OrphanTask'),'fixture')
        $hidden=Get-SccHiddenTaskEvidence -Tasks @() -TaskRoot $taskRoot -CacheRoot (Join-Path $fixtureDir 'missing-cache')
        if(@($hidden.Items|Where-Object Kind -eq 'OrphanTaskFile').Count -ne 1){throw 'hidden task discrepancy missing'}

        $denied=Get-SccBoundedScriptFiles -Roots @('mock-root') -MaxFiles 2 -MaxSeconds 5 -DirectoryReader { param($path) throw 'access denied fixture' }
        if($denied.Errors.Count -lt 1){throw 'directory access error was not recorded'}
        $capped=Get-SccBoundedScriptFiles -Roots @('mock-root') -MaxFiles 0 -MaxSeconds 5 -DirectoryReader { param($path) @() }
        if(-not $capped.Truncated){throw 'file cap did not report truncation'}
        $projection=Get-SccGenericEvidence -Name 'ProjectionFixture' -Collector {
            [pscustomobject]@{Time=[datetime]::SpecifyKind([datetime]'2020-01-01 01:00:00',[DateTimeKind]::Utc);Reference=[version]'1.2';Values=@('a','b')}
        }
        if($projection.Items[0].Reference -isnot [string] -or $projection.Items[0].Reference -ne '1.2' -or $projection.Items[0].Time -ne '2020-01-01T01:00:00.0000000Z'){throw 'generic evidence retained a native object graph or non-ISO timestamp'}
        function Get-WinEvent {
            [CmdletBinding()]param([hashtable]$FilterHashtable,[int]$MaxEvents)
            if($FilterHashtable.LogName -eq 'fixture-records'){[pscustomobject]@{TimeCreated=[datetime]'2020-01-01';Id=1;Message='fixture event'};return}
            if($FilterHashtable.LogName -eq 'fixture-denied'){throw 'access denied fixture'}
            Write-Error -Message 'No matching fixture events' -ErrorId 'NoMatchingEventsFound' -ErrorAction Stop
        }
        $events=Get-SccGenericEvidence -Name 'EventFixture' -Collector {Get-SccEventRecords -Filter @{LogName='fixture-records'} -Maximum 400;Get-SccEventRecords -Filter @{LogName='fixture-empty'} -Maximum 400}
        if($events.Items.Count -ne 1 -or $events.Errors.Count -ne 0){throw 'empty second event query erased prior event evidence'}
        $deniedEvents=Get-SccGenericEvidence -Name 'EventDeniedFixture' -Collector {Get-SccEventRecords -Filter @{LogName='fixture-denied'} -Maximum 400}
        if($deniedEvents.Errors.Count -ne 1){throw 'event access denial was falsely converted to empty successful collection'}
        # Public collector proof: use the real task helper and fully injected
        # remaining providers. No live Windows inventory source is consulted.
        $script:FixtureTaskCount=1
        $script:FixtureRegistry=$reg;$script:FixtureStartup=$startup;$script:FixtureHidden=$hidden
        function Get-SccRegistryEvidence {$script:FixtureRegistry}
        function Get-SccStartupEvidence {$script:FixtureStartup}
        function Get-SccHiddenTaskEvidence {$script:FixtureHidden}
        function Get-SccGenericEvidence {[pscustomobject]@{Items=@();Errors=@()}}
        function Get-SccBoundedScriptFiles {[pscustomobject]@{Items=@();Errors=@();Truncated=$true;Limits=[pscustomobject]@{MaxFiles=2500;MaxSeconds=30}}}
        $out=Join-Path (Join-Path $fixtureDir 'public-run') 'persistence'
        $public=Get-SccPersistenceInventory -OutDir $out
        if($public.Status -ne 'Incomplete' -or $public.RunId -ne 'public-run'){throw 'public inventory lost incomplete coverage or run identity'}
        $saved=[IO.File]::ReadAllText((Join-Path $out 'inventory.json')) | ConvertFrom-Json
        if($saved.SchemaVersion -ne 1 -or $saved.Findings -isnot [array] -or $saved.Errors -isnot [array]){throw 'public inventory JSON did not preserve array/schema shapes'}
        if(@($saved.Findings | Where-Object Kind -eq 'HiddenTask').Count -ne 1){throw 'hidden task review-only finding did not reach public inventory'}
        if(@($saved.Findings | Where-Object Kind -eq 'ScheduledTask').Count -ne 1){throw 'task helper findings did not reach public inventory'}
        if(@($saved.Findings | Where-Object Kind -eq 'StartupFile').Count -ne 1){throw 'startup helper findings did not reach public inventory'}
    } $tmp
    Write-Host 'PASS: production persistence section helper fixtures'
} finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
