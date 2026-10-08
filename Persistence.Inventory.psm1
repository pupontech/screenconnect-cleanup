Set-StrictMode -Version 2
$script:InventoryMaxFiles = 2500
$script:InventoryMaxSeconds = 30
$script:InventoryMaxHashBytes = 20MB
$script:RegistryRoots = @(
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows'
)

function Assert-SccInventoryPath {
    param([string]$Path)
    $current=[IO.Path]::GetFullPath($Path)
    while($current) {
        if(Test-Path -LiteralPath $current -ErrorAction Stop) {
            $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Redirected persistence evidence paths are refused.'}
        }
        $parent=Split-Path -Parent $current
        if(-not $parent -or $parent -eq $current){break}
        $current=$parent
    }
}
function Write-SccInventoryFile {
    param([string]$Path,[string]$Text,[switch]$AllowIdentical)
    Assert-SccInventoryPath $Path
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    if(Test-Path -LiteralPath $Path) {
        if($AllowIdentical -and [IO.File]::ReadAllText($Path) -ceq $Text){return}
        throw 'Persistence evidence already exists; a fresh run directory is required.'
    }
    $stream=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
function New-SccSection {
    param([string]$Status='Complete', [object[]]$Items=@(), [string[]]$Errors=@(), $Limits=$null)
    if(@($Errors).Count -gt 0 -and $Status -eq 'Complete'){$Status='Incomplete'}
    [pscustomobject]@{ Status=$Status; Items=@($Items); Errors=@($Errors); Limits=$Limits }
}
function Get-SccTaskCommand {
    param($Task)
    $commands=foreach($action in $Task.Actions) {
        $execute=$action.PSObject.Properties['Execute']
        $arguments=$action.PSObject.Properties['Arguments']
        $classId=$action.PSObject.Properties['ClassId']
        if($execute){(([string]$execute.Value+' '+$(if($arguments){[string]$arguments.Value}else{''})).Trim())}
        elseif($classId){'COM handler '+[string]$classId.Value}
        else{'Non-Exec task action (no executable command exposed)'}
    }
    @($commands) -join ' | '
}
function Get-SccStableId {
    param([string]$Kind,[string]$Identity)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Kind+'|'+$Identity))) -replace '-','').Substring(0,24) }
    finally { $sha.Dispose() }
}
function Test-SccSuspiciousCommand {
    param([string]$Command)
    return $Command -match '(?i)(wscript|cscript|mshta|powershell|pwsh|\.vbs\b|\.vbe\b|\.ps1\b|\.js\b|\.jse\b|\.wsf\b|\.hta\b|\\Users\\Public\\|\\AppData\\|\\Temp\\|\\ProgramData\\[^\\]+\.(vbs|vbe|ps1|js))'
}
function Get-SccTaskEvidence {
    param([string]$XmlDirectory)
    $items=New-Object System.Collections.ArrayList
    $findings=New-Object System.Collections.ArrayList
    $errors=New-Object System.Collections.ArrayList
    try { $tasks=@(Get-ScheduledTask -ErrorAction Stop) } catch { return [pscustomobject]@{Items=@();Findings=@();Errors=@('Get-ScheduledTask: '+$_.Exception.Message)} }
    foreach($task in $tasks) {
        $command=Get-SccTaskCommand $task
        [void]$items.Add([pscustomobject]@{TaskName=[string]$task.TaskName;TaskPath=[string]$task.TaskPath;State=[string]$task.State;RunAs=[string]$task.Principal.UserId;Command=$command})
        $microsoft=([string]$task.TaskPath).StartsWith('\Microsoft\',[StringComparison]::OrdinalIgnoreCase)
        $pattern='(?i)(wscript|cscript|mshta|powershell|pwsh|rundll32|regsvr32|bitsadmin|certutil|\.vbs\b|\.vbe\b|\.ps1\b|\.js\b|\.jse\b|\.wsf\b|\.hta\b|\\AppData\\|\\Temp\\|\\Users\\Public\\|ProgramData)'
        $candidate=if($microsoft){$command -match '(?i)(wscript|cscript|mshta|powershell|pwsh|\.vbs\b|\.vbe\b|\.ps1\b|\.js\b|\.jse\b|\.wsf\b|\.hta\b|\\AppData\\|\\Temp\\|\\Users\\Public\\)'}else{$command -match $pattern}
        if(-not $candidate){continue}
        try {
            $xml=[string](Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop)
            $sha=[Security.Cryptography.SHA256]::Create()
            try {$hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($xml))) -replace '-','')} finally {$sha.Dispose()}
            $path=Join-Path $XmlDirectory ($hash+'.xml')
            Write-SccInventoryFile -Path $path -Text $xml -AllowIdentical
            $details=[pscustomobject]@{TaskName=[string]$task.TaskName;TaskPath=[string]$task.TaskPath;XmlSha256=$hash}
            [void]$findings.Add([pscustomobject]@{Id=(Get-SccStableId 'ScheduledTask' ([string]$task.TaskPath+[string]$task.TaskName));Kind='ScheduledTask';Target=([string]$task.TaskPath+[string]$task.TaskName);Command=$command;Reason='Script-host or unusual task action heuristic; review evidence only';ReviewOnly=[bool]$microsoft;Details=$details})
        } catch {[void]$errors.Add(('Task XML {0}{1}: {2}' -f $task.TaskPath,$task.TaskName,$_.Exception.Message))}
    }
    [pscustomobject]@{Items=@($items.ToArray());Findings=@($findings.ToArray());Errors=@($errors.ToArray())}
}
function Get-SccProfileRoots {
    $roots=New-Object System.Collections.ArrayList
    $gaps=New-Object System.Collections.ArrayList
    $profileList='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    try {
        if(Test-Path -LiteralPath $profileList) {
            foreach($key in @(Get-ChildItem -LiteralPath $profileList -ErrorAction Stop)) {
                if($key.PSChildName -notmatch '^S-1-5-21-'){continue}
                $profilePath=[Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $key.PSPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath)
                if(-not $profilePath){[void]$gaps.Add("Profile $($key.PSChildName): missing ProfileImagePath");continue}
                $sid=[string]$key.PSChildName
                $loadedPath='Registry::HKEY_USERS\'+$sid
                $loaded=Test-Path -LiteralPath $loadedPath
                [void]$roots.Add([pscustomobject]@{Sid=$sid;Name=(Split-Path $profilePath -Leaf);Root=$loadedPath;Loaded=[bool]$loaded;ProfilePath=$profilePath})
                if(-not $loaded){[void]$gaps.Add("Profile $($key.PSChildName) ($profilePath): user hive is not loaded; offline hive was not mounted")}
            }
        }
    } catch {[void]$gaps.Add('ProfileList enumeration: '+$_.Exception.Message)}
    [pscustomobject]@{Profiles=@($roots.ToArray());Errors=@($gaps.ToArray())}
}
function Get-SccRegistryEvidence {
    param([scriptblock]$ValueReader=$null)
    $rows=New-Object System.Collections.ArrayList; $findings=New-Object System.Collections.ArrayList; $errors=New-Object System.Collections.ArrayList
    $keys=New-Object System.Collections.ArrayList
    foreach($p in $script:RegistryRoots){[void]$keys.Add([pscustomobject]@{Path=$p;Profile=$null;UserKey=$false})}
    $profileResult=Get-SccProfileRoots
    $currentSid=$null
    if($env:OS -eq 'Windows_NT'){try{$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}catch{}}
    $currentCovered=($currentSid -and @($profileResult.Profiles | Where-Object {$_.Loaded -and $_.Sid -eq $currentSid}).Count -gt 0)
    if(-not $currentCovered) {
        foreach($sub in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\Microsoft\Windows\CurrentVersion\RunServices','Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','Software\Microsoft\Windows NT\CurrentVersion\Windows','Software\Microsoft\Windows NT\CurrentVersion\Winlogon','Environment')) {
            [void]$keys.Add([pscustomobject]@{Path=('Registry::HKEY_CURRENT_USER\'+$sub);Profile=$null;UserKey=$true})
        }
    }
    foreach($profile in $profileResult.Profiles) {
        if(-not $profile.Loaded){continue}
        foreach($sub in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\Microsoft\Windows\CurrentVersion\RunServices','Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','Software\Microsoft\Windows NT\CurrentVersion\Windows','Software\Microsoft\Windows NT\CurrentVersion\Winlogon','Environment')) {
            [void]$keys.Add([pscustomobject]@{Path=($profile.Root+'\'+$sub);Profile=$profile;UserKey=$true})
        }
    }
    foreach($entry in $keys) {
        $keyPath=[string]$entry.Path
        try {
                if(-not $ValueReader -and -not (Test-Path -LiteralPath $keyPath)){continue}
                if($ValueReader) {
                $values=@(& $ValueReader $keyPath $entry.Profile)
                foreach($valueRow in $values) {
                    $name=[string]$valueRow.Name; $kind=[string]$valueRow.Kind; $value=[string]$valueRow.Value
                    if($name -match '^PS'){continue}
                    $removalPath=$keyPath
                    $identity=$removalPath+'|'+$name
                    $row=[pscustomobject]@{RegistryPath=$removalPath;ValueName=$name;OriginalValue=$value;ValueKind=$kind;UserName=$(if($entry.Profile){$entry.Profile.Name}else{$null});SID=$(if($entry.Profile){$entry.Profile.Sid}else{$null});HivePath=$keyPath}
                    [void]$rows.Add($row)
                    $special=($keyPath -match '(?i)Winlogon|\\Windows$|\\Environment$')
                    if(Test-SccSuspiciousCommand $value){[void]$findings.Add([pscustomobject]@{Id=(Get-SccStableId 'RunKey' $identity);Kind='RunKey';Target=$identity;Command=$value;Reason='Suspicious autorun command/path heuristic; review evidence only';ReviewOnly=[bool]$special;Details=[pscustomobject]@{RegistryPath=$removalPath;ValueName=$name;OriginalValue=$value;ValueKind=$kind;UserName=$row.UserName;SID=$row.SID}})}
                }
            } else {
                if(-not (Test-Path -LiteralPath $keyPath)){continue}
                $key=Get-Item -LiteralPath $keyPath -ErrorAction Stop
                foreach($name in @($key.GetValueNames())) {
                    $kind=[string]$key.GetValueKind($name)
                    $value=[string]$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if($name -match '^PS'){continue}
                    $removalPath=$keyPath
                    $identity=$removalPath+'|'+$name
                    $row=[pscustomobject]@{RegistryPath=$removalPath;ValueName=[string]$name;OriginalValue=$value;ValueKind=$kind;UserName=$(if($entry.Profile){$entry.Profile.Name}else{$null});SID=$(if($entry.Profile){$entry.Profile.Sid}else{$null});HivePath=$keyPath}
                    [void]$rows.Add($row)
                    $special=($keyPath -match '(?i)Winlogon|\\Windows$|\\Environment$')
                    if(Test-SccSuspiciousCommand $value){[void]$findings.Add([pscustomobject]@{Id=(Get-SccStableId 'RunKey' $identity);Kind='RunKey';Target=$identity;Command=$value;Reason='Suspicious autorun command/path heuristic; review evidence only';ReviewOnly=[bool]$special;Details=[pscustomobject]@{RegistryPath=$removalPath;ValueName=[string]$name;OriginalValue=$value;ValueKind=$kind;UserName=$row.UserName;SID=$row.SID}})}
                }
            }
        } catch {[void]$errors.Add(('Registry {0}: {1}' -f $keyPath,$_.Exception.Message))}
    }
    [pscustomobject]@{Items=@($rows.ToArray());Findings=@($findings.ToArray());Errors=@($errors.ToArray());ProfileErrors=@($profileResult.Errors)}
}
function Resolve-SccStartupTarget {
    param([string]$Path)
    $target=$Path
    if([IO.Path]::GetExtension($Path) -ieq '.lnk' -and $env:OS -eq 'Windows_NT') {
        $shell=$null; $shortcut=$null
        try {$shell=New-Object -ComObject WScript.Shell; $shortcut=$shell.CreateShortcut($Path); $target=[string]$shortcut.TargetPath; if($shortcut.Arguments){$target+=' '+$shortcut.Arguments}}
        finally {if($shortcut){[void][Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)};if($shell){[void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)}}
    }
    $target
}
function Get-SccStartupEvidence {
    param([object[]]$Profiles,[scriptblock]$ShortcutResolver=$null,[string]$CommonDirectory='')
    $rows=New-Object System.Collections.ArrayList; $findings=New-Object System.Collections.ArrayList; $errors=New-Object System.Collections.ArrayList
    $dirs=New-Object System.Collections.ArrayList
    $common=if($CommonDirectory){$CommonDirectory}else{[Environment]::GetFolderPath('CommonStartup')}; if($common){[void]$dirs.Add([pscustomobject]@{Path=$common;User=$null;SID=$null})}
    foreach($profile in $Profiles){$dir=Join-Path $profile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup';[void]$dirs.Add([pscustomobject]@{Path=$dir;User=$profile.Name;SID=$profile.Sid})}
    foreach($dir in $dirs) {
        try {
            if(-not (Test-Path -LiteralPath $dir.Path)){continue}
            foreach($file in @(Get-ChildItem -LiteralPath $dir.Path -Force -ErrorAction Stop)) {
                if($file.PSIsContainer -or $file.Name -ieq 'desktop.ini'){continue}
                $hash=$null; try{$hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash}catch{[void]$errors.Add(('Startup hash {0}: {1}' -f $file.FullName,$_.Exception.Message))}
                $target=if($ShortcutResolver){[string](& $ShortcutResolver ([string]$file.FullName))}else{Resolve-SccStartupTarget ([string]$file.FullName)}
                $row=[pscustomobject]@{FilePath=[string]$file.FullName;Length=$file.Length;CreatedUtc=$file.CreationTimeUtc;ModifiedUtc=$file.LastWriteTimeUtc;SHA256=$hash;ResolvedTarget=$target;User=$dir.User;SID=$dir.SID}
                [void]$rows.Add($row)
                $suspicious=($target -match '(?i)(wscript|cscript|mshta|powershell|pwsh|\.vbs\b|\.vbe\b|\.ps1\b|\.js\b|\.jse\b|\.wsf\b|\.hta\b|\\AppData\\|\\Temp\\|\\Users\\Public\\)')
                if($suspicious){[void]$findings.Add([pscustomobject]@{Id=(Get-SccStableId 'StartupFile' $file.FullName);Kind='StartupFile';Target=[string]$file.FullName;Command=$target;Reason='Startup shortcut/file resolves to script host or user-writable path heuristic; review only';ReviewOnly=[bool]($file.PSIsContainer -or -not $hash);Details=[pscustomobject]@{FilePath=[string]$file.FullName;SHA256=$hash;ResolvedTarget=$target}})}
            }
        } catch {[void]$errors.Add(('Startup folder {0}: {1}' -f $dir.Path,$_.Exception.Message))}
    }
    [pscustomobject]@{Items=@($rows.ToArray());Findings=@($findings.ToArray());Errors=@($errors.ToArray())}
}
function Get-SccHiddenTaskEvidence {
    param([object[]]$Tasks,[string]$TaskRoot='',[string]$CacheRoot='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree')
    $items=New-Object System.Collections.ArrayList; $errors=New-Object System.Collections.ArrayList
    if(-not $TaskRoot){$TaskRoot=Join-Path $env:SystemRoot 'System32\Tasks'}
    $known=@{};foreach($task in $Tasks){$known[(($task.TaskPath+$task.TaskName)-replace '^\\','').ToLowerInvariant()]=$true}
    try {
        if(Test-Path -LiteralPath $TaskRoot){foreach($file in @(Get-ChildItem -LiteralPath $TaskRoot -Recurse -Force -File -ErrorAction Stop)){$relative=$file.FullName.Substring($TaskRoot.Length).TrimStart('\');if(-not $known.ContainsKey($relative.ToLowerInvariant())){[void]$items.Add([pscustomobject]@{Kind='OrphanTaskFile';TaskPath=$relative;FilePath=$file.FullName;ModifiedUtc=$file.LastWriteTimeUtc;ReviewOnly=$true})}}}
    } catch {[void]$errors.Add(('Task files: '+$_.Exception.Message))}
    $tree=$CacheRoot
    try {
        if(Test-Path -LiteralPath $tree) {
            $stack=New-Object System.Collections.Stack
            $stack.Push($tree)
            while($stack.Count) {
                $path=[string]$stack.Pop()
                foreach($child in @(Get-ChildItem -LiteralPath $path -ErrorAction Stop)) {
                    $stack.Push($child.PSPath)
                    $key=Get-Item -LiteralPath $child.PSPath -ErrorAction Stop
                    $names=@($key.GetValueNames())
                    if($names -contains 'Id' -and $names -notcontains 'SD') {
                        [void]$items.Add([pscustomobject]@{Kind='TaskCacheMissingSD';TaskPath=($child.Name -replace '^.*Schedule\\TaskCache\\Tree\\','');RegistryPath=$child.PSPath;ReviewOnly=$true})
                    }
                }
            }
        }
    } catch {[void]$errors.Add(('TaskCache: '+$_.Exception.Message))}
    [pscustomobject]@{Items=@($items.ToArray());Errors=@($errors.ToArray())}
}
function Get-SccBoundedScriptFiles {
    param([string[]]$Roots,[int]$MaxFiles=2500,[int]$MaxSeconds=30,[scriptblock]$DirectoryReader=$null)
    $clock=[Diagnostics.Stopwatch]::StartNew();$items=New-Object System.Collections.ArrayList;$errors=New-Object System.Collections.ArrayList;$truncated=$false
    $extensions=@('.vbs','.vbe','.vb','.ps1','.js','.jse','.wsf','.hta','.bat','.cmd')
    $noise='(?i)\\(node_modules|\.git|Python\d+|site-packages|WindowsApps|Packages|npm-cache|chocolatey|Package Cache|Extensions|Edge\\User Data|Chrome\\Application|Windows Defender|Microsoft Office|dotnet|Windows Kits|Malwarebytes|Splashtop|Adobe|Intel|Realtek)($|\\)'
    foreach($root in $Roots) {
        if($clock.Elapsed.TotalSeconds -ge $MaxSeconds -or $items.Count -ge $MaxFiles){$truncated=$true;break}
        $stack=New-Object System.Collections.Stack;$stack.Push($root)
        while($stack.Count -gt 0) {
            if($clock.Elapsed.TotalSeconds -ge $MaxSeconds -or $items.Count -ge $MaxFiles){$truncated=$true;break}
            $directory=[string]$stack.Pop()
            try {$children=if($DirectoryReader){@(& $DirectoryReader $directory)}else{@(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)}} catch {[void]$errors.Add(('Directory access {0}: {1}' -f $directory,$_.Exception.Message));continue}
            foreach($entry in $children) {
                if($clock.Elapsed.TotalSeconds -ge $MaxSeconds -or $items.Count -ge $MaxFiles){$truncated=$true;break}
                if($entry.PSIsContainer) {
                    if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $entry.FullName -match $noise){continue}
                    $stack.Push($entry.FullName);continue
                }
                if($extensions -notcontains $entry.Extension.ToLowerInvariant() -or $entry.FullName -match $noise){continue}
                $hash=$null
                if($entry.Length -le $script:InventoryMaxHashBytes){try{$hash=(Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256 -ErrorAction Stop).Hash}catch{[void]$errors.Add(('File hash {0}: {1}' -f $entry.FullName,$_.Exception.Message))}}
                [void]$items.Add([pscustomobject]@{Path=$entry.FullName;Length=$entry.Length;CreatedUtc=$entry.CreationTimeUtc;ModifiedUtc=$entry.LastWriteTimeUtc;SHA256=$hash})
            }
            if($truncated){break}
        }
        if($truncated){break}
    }
    [pscustomobject]@{Items=@($items.ToArray());Errors=@($errors.ToArray());Truncated=$truncated;Limits=[pscustomobject]@{MaxFiles=$MaxFiles;MaxSeconds=$MaxSeconds;MaxHashBytes=$script:InventoryMaxHashBytes}}
}
function ConvertTo-SccEvidenceScalar {
    param($Value)
    if($null -eq $Value){return $null}
    if($Value -is [datetime]){return $Value.ToUniversalTime().ToString('o')}
    if($Value -is [DateTimeOffset]){return $Value.ToUniversalTime().ToString('o')}
    if($Value -is [string] -or $Value -is [bool] -or $Value.GetType().IsPrimitive -or $Value -is [decimal]){return $Value}
    if($Value -is [array]){return ,@($Value | ForEach-Object {ConvertTo-SccEvidenceScalar $_})}
    # CIM references, enum wrappers and other native objects are evidence
    # labels, not permission to serialize their provider/reflection graphs.
    return [string]$Value
}
function Get-SccGenericEvidence {
    param([string]$Name,[scriptblock]$Collector)
    try {
        $rows=foreach($item in @(& $Collector)) {
            if($item -is [string]){$item;continue}
            $record=[ordered]@{}
            foreach($property in $item.PSObject.Properties){$record[$property.Name]=ConvertTo-SccEvidenceScalar $property.Value}
            [pscustomobject]$record
        }
        [pscustomobject]@{Items=@($rows);Errors=@()}
    } catch {
        [pscustomobject]@{Items=@();Errors=@($Name+': '+$_.Exception.Message)}
    }
}
function Get-SccEventRecords {
    param([hashtable]$Filter,[int]$Maximum)
    try {Get-WinEvent -FilterHashtable $Filter -MaxEvents $Maximum -ErrorAction Stop}
    catch {if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
}
function Get-SccPersistenceInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$OutDir)
    Assert-SccInventoryPath $OutDir
    $inventoryFile=Join-Path $OutDir 'inventory.json'
    if(Test-Path -LiteralPath $inventoryFile){throw 'Existing persistence inventory is not overwritten; use a fresh run.'}
    $null=New-Item -ItemType Directory -Force -Path $OutDir
    $started=[Diagnostics.Stopwatch]::StartNew();$errors=New-Object System.Collections.ArrayList;$sections=[ordered]@{};$findings=New-Object System.Collections.ArrayList
    $xmlDir=Join-Path $OutDir 'task_xml';Assert-SccInventoryPath $xmlDir;$null=New-Item -ItemType Directory -Force -Path $xmlDir
    $task=Get-SccTaskEvidence -XmlDirectory $xmlDir
    $sections.ScheduledTasks=New-SccSection -Items $task.Items -Errors $task.Errors
    $sections.TaskXml=New-SccSection -Items @($task.Findings | ForEach-Object {$_.Details}) -Errors $task.Errors
    foreach($f in $task.Findings){[void]$findings.Add($f)};foreach($e in $task.Errors){[void]$errors.Add($e)}
    $registry=Get-SccRegistryEvidence
    $sections.RunKeys=New-SccSection -Items $registry.Items -Errors $registry.Errors
    $sections.ProfileCoverage=New-SccSection -Status $(if($registry.ProfileErrors.Count){'Incomplete'}else{'Complete'}) -Items @($registry.Items | Where-Object SID | Select-Object -ExpandProperty SID -Unique) -Errors $registry.ProfileErrors
    foreach($f in $registry.Findings){[void]$findings.Add($f)};foreach($e in $registry.Errors){[void]$errors.Add($e)};foreach($e in $registry.ProfileErrors){[void]$errors.Add($e)}
    $startup=Get-SccStartupEvidence -Profiles $((Get-SccProfileRoots).Profiles)
    $sections.StartupFiles=New-SccSection -Items $startup.Items -Errors $startup.Errors
    foreach($f in $startup.Findings){[void]$findings.Add($f)};foreach($e in $startup.Errors){[void]$errors.Add($e)}
    $hidden=Get-SccHiddenTaskEvidence -Tasks $task.Items
    $sections.HiddenTasks=New-SccSection -Items $hidden.Items -Errors $hidden.Errors
    foreach($e in $hidden.Errors){[void]$errors.Add($e)}
    foreach($item in $hidden.Items) {
        $target=[string]$item.TaskPath
        $identity=[string]$item.Kind+'|'+$target
        [void]$findings.Add([pscustomobject]@{Id=(Get-SccStableId 'HiddenTask' $identity);Kind='HiddenTask';Target=$identity;Command='Task Scheduler visibility discrepancy';Reason='Hidden/unregistered-task indicator requires investigation; not proof of malware';ReviewOnly=$true;Details=$item})
    }
    $collectors=[ordered]@{
      TaskRegistrationEvents={Get-SccEventRecords -Filter @{LogName='Microsoft-Windows-TaskScheduler/Operational';Id=106,140,141} -Maximum 400 | Select-Object TimeCreated,Id,Message}
      Services={Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,StartName,PathName}
      WmiSubscriptions={foreach($class in @('__EventConsumer','__EventFilter','__FilterToConsumerBinding')){Get-CimInstance -Namespace root\subscription -ClassName $class -ErrorAction Stop | Select-Object __CLASS,Name,Filter,Consumer,Query,CommandLineTemplate}}
      Processes={Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object Name -match '(?i)wscript|cscript|mshta|powershell|pwsh|rundll32|regsvr32|bitsadmin|certutil|msbuild|installutil|regasm|msiexec' | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine}
      Connections={Get-NetTCPConnection -ErrorAction Stop | Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State}
      Defender={ $threats=@{};foreach($threat in @(Get-MpThreat -ErrorAction Stop)){$threats[[string]$threat.ThreatID]=$threat.ThreatName};Get-MpThreatDetection -ErrorAction Stop | ForEach-Object {$d=$_;[pscustomobject]@{InitialDetectionTime=$d.InitialDetectionTime;ThreatID=$d.ThreatID;ThreatName=$threats[[string]$d.ThreatID];ProcessName=$d.ProcessName;Resources=$d.Resources;ActionSuccess=$d.ActionSuccess;DomainUser=$d.DomainUser}} }
      DefenderConfig={Get-MpPreference -ErrorAction Stop | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,DisableRealtimeMonitoring}
      AntivirusProducts={Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,productState}
      Logons={Get-SccEventRecords -Filter @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-14)} -Maximum 500 | ForEach-Object {$event=$_;$data=@{};try{$xml=[xml]$event.ToXml();foreach($d in $xml.Event.EventData.Data){$data[$d.Name]=$d.'#text'}}catch{};if(@('2','7','10','11') -contains [string]$data.LogonType){[pscustomobject]@{Time=$event.TimeCreated;LogonType=$data.LogonType;User=$data.TargetUserName;IP=$data.IpAddress;Process=$data.ProcessName}}}}
      RdpEvents={foreach($spec in @(@('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',1149),@('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',21,22,24,25))){Get-SccEventRecords -Filter @{LogName=$spec[0];Id=@($spec|Select-Object -Skip 1);StartTime=(Get-Date).AddDays(-14)} -Maximum 400 | Select-Object TimeCreated,Id,Message}}
      Accounts={Get-LocalUser -ErrorAction Stop | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description}
      LocalAdministrators={Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name,ObjectClass,PrincipalSource}
      RemoteTools={Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Stop | Where-Object DisplayName -match '(?i)AnyDesk|TeamViewer|Splashtop|ScreenConnect|ConnectWise|RustDesk|UltraVNC|TightVNC|RealVNC|LogMeIn|Ammyy|Supremo|Chrome Remote|Atera|NetSupport|RemotePC|Radmin|DWService|MeshAgent|Zoho.?Assist|Action1|Level\.io|Datto|Kaseya|N-able|Syncro|Pulseway' | Select-Object DisplayName,DisplayVersion,InstallDate,Publisher}
      RemoteToolServices={Get-Service -ErrorAction Stop | Where-Object {$_.Name -match '(?i)AnyDesk|TeamViewer|ScreenConnect|ConnectWise|RustDesk|VNC|Splashtop|Atera|Kaseya|MeshAgent' -or $_.DisplayName -match '(?i)AnyDesk|TeamViewer|ScreenConnect|ConnectWise|RustDesk|VNC|Splashtop|Atera|Kaseya|MeshAgent'} | Select-Object Name,DisplayName,Status,StartType}
      Hosts={Get-Content (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction Stop | Where-Object {$_ -and $_ -notmatch '^\s*#'}}
    }
    foreach($name in $collectors.Keys){$evidence=Get-SccGenericEvidence -Name $name -Collector $collectors[$name];$sections[$name]=New-SccSection -Items $evidence.Items -Errors $evidence.Errors;foreach($e in $evidence.Errors){[void]$errors.Add($e)}}
    $roots=@($env:ProgramData,$env:ProgramFiles,${env:ProgramFiles(x86)})
    if($env:SystemDrive){$roots+=(Join-Path $env:SystemDrive 'Users')}
    if($env:SystemRoot){$roots+=(Join-Path $env:SystemRoot 'Temp')}
    $roots=@($roots | Where-Object {$_ -and (Test-Path -LiteralPath $_)})
    $scripts=Get-SccBoundedScriptFiles -Roots $roots -MaxFiles $script:InventoryMaxFiles -MaxSeconds $script:InventoryMaxSeconds
    $sections.ScriptFiles=New-SccSection -Status $(if($scripts.Truncated -or $scripts.Errors.Count){'Incomplete'}else{'Complete'}) -Items $scripts.Items -Errors $scripts.Errors -Limits $scripts.Limits
    foreach($e in $scripts.Errors){[void]$errors.Add($e)};if($scripts.Truncated){[void]$errors.Add('ScriptFiles: bounded file/time cap reached; scan truncated')}
    $sections.PrivacyOmissions=New-SccSection -Items @('No raw script samples collected.','PowerShell shell/history content omitted for privacy.','Offline user registry hives are not mounted; unloaded profiles are explicit coverage gaps.')
    if($started.Elapsed.TotalSeconds -ge $script:InventoryMaxSeconds){[void]$errors.Add('Overall collection exceeded configured time budget; later sections may be partial')}
    $status=if($errors.Count){'Incomplete'}else{'Complete'}
    $runId=Split-Path (Split-Path $OutDir -Parent) -Leaf
    $result=[pscustomobject]@{SchemaVersion=1;RunId=$runId;ComputerName=$env:COMPUTERNAME;GeneratedUtc=[DateTime]::UtcNow.ToString('o');Status=$status;Errors=@($errors.ToArray());Sections=[pscustomobject]$sections;Findings=@($findings.ToArray());Counts=[pscustomobject]@{Findings=$findings.Count;ScriptFiles=$scripts.Items.Count}}
    $json=ConvertTo-Json -InputObject $result -Depth 12
    Write-SccInventoryFile -Path $inventoryFile -Text $json
    return $result
}
Export-ModuleMember -Function Get-SccPersistenceInventory
