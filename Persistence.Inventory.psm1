Set-StrictMode -Version 2
$script:InventoryMaxFiles = 2500
$script:InventoryMaxSeconds = 30
$script:InventoryMaxHashBytes = 20MB
# Tampering indicators (AutoHotkey, UAC). Detect-and-report only: every finding
# from these collectors is ReviewOnly and none is a removable kind.
$script:IndicatorMaxFiles = 3000
$script:IndicatorMaxSeconds = 20
$script:IndicatorMaxScanBytes = 2MB
$script:UacPolicyPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
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
function Get-SccPropertyValue {
    # Property-safe read. The simplified Where-Object form (Where-Object Name -match)
    # raises PSArgumentException "The input name cannot be resolved to a property"
    # as soon as ONE object in the pipeline lacks that value, and under the worker's
    # $ErrorActionPreference='Stop' that aborts collection. Registry Uninstall keys
    # with no DisplayName are the common real-world case.
    param($InputObject,[string]$Name)
    if($null -eq $InputObject -or -not $Name){return $null}
    $property=$InputObject.PSObject.Properties[$Name]
    if($property){return $property.Value}
    return $null
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
    $pathComparer=if($env:OS -eq 'Windows_NT'){[StringComparer]::OrdinalIgnoreCase}else{[StringComparer]::Ordinal}
    $visited=New-Object 'System.Collections.Generic.HashSet[string]' ($pathComparer)
    $extensions=@('.vbs','.vbe','.vb','.ps1','.js','.jse','.wsf','.hta','.bat','.cmd')
    $noise='(?i)\\(node_modules|\.git|Python\d+|site-packages|WindowsApps|Packages|npm-cache|chocolatey|Package Cache|Extensions|Edge\\User Data|Chrome\\Application|Windows Defender|Microsoft Office|dotnet|Windows Kits|Malwarebytes|Splashtop|Adobe|Intel|Realtek)($|\\)'
    foreach($root in $Roots) {
        $rootKey=[IO.Path]::GetFullPath($root).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
        if($visited.Contains($rootKey)){continue}
        if($clock.Elapsed.TotalSeconds -ge $MaxSeconds -or $items.Count -ge $MaxFiles){$truncated=$true;break}
        $stack=New-Object System.Collections.Stack;$stack.Push($root)
        while($stack.Count -gt 0) {
            if($clock.Elapsed.TotalSeconds -ge $MaxSeconds -or $items.Count -ge $MaxFiles){$truncated=$true;break}
            $directory=[string]$stack.Pop()
            $directoryKey=[IO.Path]::GetFullPath($directory).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
            # Root lists can overlap (including ProgramFiles(x86) on 32-bit
            # hosts). Enumerate/hash each lexical directory only once, keeping
            # output order and existing file/time/reparse limits unchanged.
            if(-not $visited.Add($directoryKey)){continue}
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
function New-SccIndicatorFinding {
    param([string]$Kind,[string]$Target,[string]$Command,[string]$Reason,$Details)
    # Always review-only. Persistence.Removal only accepts ScheduledTask, RunKey and
    # StartupFile, so these kinds can never become removal candidates.
    [pscustomobject]@{Id=(Get-SccStableId $Kind $Target);Kind=$Kind;Target=$Target;Command=$Command;Reason=$Reason;ReviewOnly=$true;Details=$Details}
}
function Get-SccUacPolicyEvidence {
    # Read-only. Records each UAC policy value (null = not set = Windows default) and
    # flags only the weakened states. Never tests or triggers a bypass.
    param([scriptblock]$ValueReader=$null)
    $items=New-Object System.Collections.ArrayList; $findings=New-Object System.Collections.ArrayList; $errors=New-Object System.Collections.ArrayList
    $rules=@(
        @{Name='EnableLUA';Default=1;Weak=0;Reason='UAC is turned off (EnableLUA=0): every admin process runs fully elevated with no prompt.'}
        @{Name='ConsentPromptBehaviorAdmin';Default=5;Weak=0;Reason='Administrators elevate with no prompt at all (ConsentPromptBehaviorAdmin=0).'}
        @{Name='PromptOnSecureDesktop';Default=1;Weak=0;Reason='UAC prompt is not shown on the secure desktop (PromptOnSecureDesktop=0); other programs can interact with it.'}
        @{Name='LocalAccountTokenFilterPolicy';Default=0;Weak=1;Reason='Remote logons by local admins get a full admin token (LocalAccountTokenFilterPolicy=1); remote UAC restrictions are off.'}
        @{Name='ConsentPromptBehaviorUser';Default=3;Weak=$null;Reason=''}
        @{Name='FilterAdministratorToken';Default=0;Weak=$null;Reason=''}
    )
    $values=$null
    try {
        if($ValueReader){$values=& $ValueReader $script:UacPolicyPath}
        elseif(Test-Path -LiteralPath $script:UacPolicyPath){
            $key=Get-Item -LiteralPath $script:UacPolicyPath -ErrorAction Stop
            $values=@{};foreach($n in @($key.GetValueNames())){$values[[string]$n]=$key.GetValue($n)}
        }
    } catch {[void]$errors.Add('UAC policy key: '+$_.Exception.Message)}
    if($null -eq $values){$values=@{}}
    foreach($rule in $rules) {
        $raw=$null; if($values.ContainsKey($rule.Name)){$raw=$values[$rule.Name]}
        $number=$null; if($null -ne $raw){$parsed=0;if([int]::TryParse([string]$raw,[ref]$parsed)){$number=$parsed}}
        $effective=if($null -ne $number){$number}else{$rule.Default}
        $weak=($null -ne $rule.Weak -and $effective -eq $rule.Weak)
        [void]$items.Add([pscustomobject]@{Name=$rule.Name;Value=$(if($null -ne $raw){[string]$raw}else{$null});WindowsDefault=$rule.Default;Effective=$effective;Weakened=[bool]$weak})
        if($weak) {
            $target='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|'+$rule.Name
            [void]$findings.Add((New-SccIndicatorFinding -Kind 'UacPolicy' -Target $target -Command ($rule.Name+'='+$effective) -Reason ($rule.Reason+' May be set on purpose by Group Policy or an RMM tool; confirm before changing. Review only.') -Details ([pscustomobject]@{ValueName=$rule.Name;Value=$effective;WindowsDefault=$rule.Default})))
        }
    }
    [pscustomobject]@{Items=@($items.ToArray());Findings=@($findings.ToArray());Errors=@($errors.ToArray())}
}
function Get-SccUacBypassEvidence {
    # Per loaded user hive: keys and values abused by well-known auto-elevate UAC
    # bypasses (fodhelper/computerdefaults, eventvwr, sdclt, SilentCleanup). None of
    # them exists in normal use. Read-only; unloaded profiles are coverage gaps.
    param([object[]]$Profiles,[scriptblock]$KeyReader=$null)
    $items=New-Object System.Collections.ArrayList; $findings=New-Object System.Collections.ArrayList; $errors=New-Object System.Collections.ArrayList
    $hijackKeys=@(
        @{Sub='Software\Classes\ms-settings\shell\open\command';Why='fodhelper.exe / computerdefaults.exe auto-elevate bypass'}
        @{Sub='Software\Classes\ms-settings\CurVer';Why='ms-settings redirection used by the fodhelper bypass'}
        @{Sub='Software\Classes\mscfile\shell\open\command';Why='eventvwr.exe auto-elevate bypass'}
        @{Sub='Software\Classes\exefile\shell\open\command';Why='per-user override of how every .exe is opened'}
        @{Sub='Software\Classes\Folder\shell\open\command';Why='sdclt.exe auto-elevate bypass'}
        @{Sub='Software\Classes\Launcher.SystemSettings\shell\open\command';Why='Settings-app launcher hijack used by UAC bypasses'}
    )
    $envNames=@('windir','systemroot')
    $roots=New-Object System.Collections.ArrayList
    foreach($p in @($Profiles)){if($p -and $p.Loaded){[void]$roots.Add([pscustomobject]@{Root=[string]$p.Root;User=[string]$p.Name;SID=[string]$p.Sid})}}
    if($roots.Count -eq 0){[void]$roots.Add([pscustomobject]@{Root='Registry::HKEY_CURRENT_USER';User=$env:USERNAME;SID=$null})}
    foreach($r in $roots) {
        foreach($h in $hijackKeys) {
            $path=$r.Root+'\'+$h.Sub
            try {
                $values=if($KeyReader){& $KeyReader $path}elseif(Test-Path -LiteralPath $path){$k=Get-Item -LiteralPath $path -ErrorAction Stop;$v=@{};foreach($n in @($k.GetValueNames())){$v[[string]$n]=[string]$k.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)};$v}else{$null}
                if($null -eq $values){continue}
                $default=if($values.ContainsKey('')){[string]$values['']}else{''}
                $delegate=$values.ContainsKey('DelegateExecute')
                $command=if($default){$default}else{'(key present, no default command)'}
                if($delegate){$command+=' [DelegateExecute set]'}
                [void]$items.Add([pscustomobject]@{RegistryPath=$path;ValueName='';Value=$command;User=$r.User;SID=$r.SID})
                [void]$findings.Add((New-SccIndicatorFinding -Kind 'UacBypassHijack' -Target $path -Command $command -Reason ('Known UAC-bypass hijack key exists ('+$h.Why+'). Not present in normal use. Review only; nothing is removed.') -Details ([pscustomobject]@{RegistryPath=$path;User=$r.User;SID=$r.SID;DefaultValue=$default;DelegateExecute=[bool]$delegate})))
            } catch {[void]$errors.Add(('UAC bypass key {0}: {1}' -f $path,$_.Exception.Message))}
        }
        $envPath=$r.Root+'\Environment'
        try {
            $values=if($KeyReader){& $KeyReader $envPath}elseif(Test-Path -LiteralPath $envPath){$k=Get-Item -LiteralPath $envPath -ErrorAction Stop;$v=@{};foreach($n in @($k.GetValueNames())){$v[[string]$n]=[string]$k.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)};$v}else{$null}
            if($null -ne $values) {
                foreach($name in @($values.Keys)) {
                    if($envNames -notcontains ([string]$name).ToLowerInvariant()){continue}
                    $target=$envPath+'|'+$name
                    [void]$items.Add([pscustomobject]@{RegistryPath=$envPath;ValueName=[string]$name;Value=[string]$values[$name];User=$r.User;SID=$r.SID})
                    [void]$findings.Add((New-SccIndicatorFinding -Kind 'UacBypassHijack' -Target $target -Command ([string]$name+'='+[string]$values[$name]) -Reason 'Per-user override of a system path variable (SilentCleanup scheduled-task UAC bypass). Not present in normal use. Review only.' -Details ([pscustomobject]@{RegistryPath=$envPath;ValueName=[string]$name;Value=[string]$values[$name];User=$r.User;SID=$r.SID})))
                }
            }
        } catch {[void]$errors.Add(('UAC bypass environment {0}: {1}' -f $envPath,$_.Exception.Message))}
    }
    [pscustomobject]@{Items=@($items.ToArray());Findings=@($findings.ToArray());Errors=@($errors.ToArray())}
}
function Get-SccUserWritableRoots {
    param([object[]]$Profiles)
    $roots=New-Object System.Collections.ArrayList
    foreach($p in @($Profiles)) {
        if(-not $p -or -not $p.ProfilePath){continue}
        # Targeted, shallow roots: where droppers and portable tools land. A full
        # AppData\Local walk measured ~55k folders / 73 s on a live PC, so only its
        # top level, Temp and Programs are walked. Deeper trees are a known gap.
        foreach($spec in @(@('Downloads',2,1),@('Desktop',2,1),@('AppData\Local\Temp',3,1),@('AppData\Roaming',3,2),@('AppData\Local\Programs',2,3),@('AppData\Local',1,4))){[void]$roots.Add([pscustomobject]@{Path=(Join-Path $p.ProfilePath $spec[0]);MaxDepth=$spec[1];Priority=$spec[2]})}
    }
    if($env:PUBLIC){[void]$roots.Add([pscustomobject]@{Path=$env:PUBLIC;MaxDepth=3;Priority=1})}
    if($env:SystemRoot){[void]$roots.Add([pscustomobject]@{Path=(Join-Path $env:SystemRoot 'Temp');MaxDepth=2;Priority=1})}
    if($env:ProgramData){[void]$roots.Add([pscustomobject]@{Path=$env:ProgramData;MaxDepth=2;Priority=2})}
    # Highest-value roots first; the broad AppData\Local top level goes last so a
    # very large profile cannot starve Downloads/Desktop/Temp of the time budget.
    @($roots | Where-Object {$_.Path -and (Test-Path -LiteralPath $_.Path)} | Sort-Object -Property Priority)
}
function Test-SccBytesContain {
    param([string]$Latin1Text,[string]$Marker)
    if($Latin1Text.IndexOf($Marker,[StringComparison]::Ordinal) -ge 0){return $true}
    $wide=[Text.Encoding]::GetEncoding(28591).GetString([Text.Encoding]::Unicode.GetBytes($Marker))
    return ($Latin1Text.IndexOf($wide,[StringComparison]::Ordinal) -ge 0)
}
function Get-SccUserWritableBinaryEvidence {
    # One bounded walk of user-writable folders. Flags AutoHotkey interpreters,
    # .ahk/.ah2 scripts and compiled AutoHotkey executables, plus ScreenConnect
    # binaries living outside an install folder. Only hits are kept, so the
    # inventory JSON stays small. Reads files; never opens or runs them.
    param([object[]]$Roots,[int]$MaxFiles=$script:IndicatorMaxFiles,[int]$MaxSeconds=$script:IndicatorMaxSeconds,[scriptblock]$DirectoryReader=$null,[scriptblock]$VersionReader=$null,[scriptblock]$ContentReader=$null)
    $clock=[Diagnostics.Stopwatch]::StartNew();$items=New-Object System.Collections.ArrayList;$findings=New-Object System.Collections.ArrayList;$errors=New-Object System.Collections.ArrayList
    $truncated=$false;$examined=0
    $pathComparer=if($env:OS -eq 'Windows_NT'){[StringComparer]::OrdinalIgnoreCase}else{[StringComparer]::Ordinal}
    $visited=New-Object 'System.Collections.Generic.HashSet[string]' ($pathComparer)
    $noise='(?i)\\(node_modules|\.git|Python\d+|site-packages|WindowsApps|Packages|npm-cache|pip|chocolatey|Package Cache|Edge\\User Data|Chrome\\User Data|Mozilla\\Firefox|Windows Defender|Microsoft\\Teams|Microsoft\\OneDrive|Microsoft\\Edge|Google\\Chrome|CrashDumps|D3DSCache|NVIDIA|Steam|JetBrains|Windows Kits|Malwarebytes)($|\\)'
    $scLocation='(?i)\\Program Files( \(x86\))?\\ScreenConnect Client'
    $rootList=@($Roots);$truncatedRoots=New-Object System.Collections.ArrayList
    for($ri=0;$ri -lt $rootList.Count;$ri++) {
        $root=$rootList[$ri]
        $remaining=$MaxSeconds-$clock.Elapsed.TotalSeconds
        if($remaining -le 0 -or $examined -ge $MaxFiles){$truncated=$true;for($rj=$ri;$rj -lt $rootList.Count;$rj++){[void]$truncatedRoots.Add([string]$rootList[$rj].Path)};break}
        # Fair share: each root gets the remaining budget divided by the roots
        # still to walk, so one huge folder is cut and named, not the whole scan.
        $rootDeadline=$clock.Elapsed.TotalSeconds+[Math]::Max(1.0,$remaining/($rootList.Count-$ri))
        $rootCut=$false;$capHit=$false
        $stack=New-Object System.Collections.Stack;$stack.Push([pscustomobject]@{Path=[string]$root.Path;Depth=0})
        while($stack.Count -gt 0) {
            if($examined -ge $MaxFiles){$capHit=$true;break}
            if($clock.Elapsed.TotalSeconds -ge $rootDeadline){$rootCut=$true;break}
            $frame=$stack.Pop();$directory=[string]$frame.Path
            $directoryKey=[IO.Path]::GetFullPath($directory).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
            if(-not $visited.Add($directoryKey)){continue}
            # Native enumeration, filtered by the OS: Get-ChildItem over deep AppData
            # trees spent the whole time budget on folder listing in a live probe.
            try {
                if($DirectoryReader){$children=@(& $DirectoryReader $directory)}
                else {
                    $info=New-Object IO.DirectoryInfo($directory)
                    $children=@($info.GetDirectories())+@($info.GetFiles('*.exe'))+@($info.GetFiles('*.ahk'))+@($info.GetFiles('*.ah2'))
                }
            } catch {[void]$errors.Add(('Directory access {0}: {1}' -f $directory,$_.Exception.Message));continue}
            foreach($entry in $children) {
                if($examined -ge $MaxFiles){$capHit=$true;break}
                if($clock.Elapsed.TotalSeconds -ge $rootDeadline){$rootCut=$true;break}
                if($entry -is [IO.DirectoryInfo]) {
                    if($frame.Depth -ge [int]$root.MaxDepth -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $entry.FullName -match $noise){continue}
                    $stack.Push([pscustomobject]@{Path=$entry.FullName;Depth=($frame.Depth+1)});continue
                }
                $ext=([string]$entry.Extension).ToLowerInvariant()
                if($ext -notin @('.exe','.ahk','.ah2')){continue}
                if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}
                $examined++
                $path=[string]$entry.FullName
                $evidence=New-Object System.Collections.ArrayList
                $kind=$null;$product=$null;$company=$null
                if($ext -ne '.exe') {
                    $kind='AutoHotkey';[void]$evidence.Add('AutoHotkey script file ('+$ext+')')
                } else {
                    try {
                        $vi=if($VersionReader){& $VersionReader $path}else{[Diagnostics.FileVersionInfo]::GetVersionInfo($path)}
                        if($vi){$product=[string](Get-SccPropertyValue $vi 'ProductName');$company=[string](Get-SccPropertyValue $vi 'CompanyName');$description=[string](Get-SccPropertyValue $vi 'FileDescription')}else{$description=''}
                    } catch {$description='';[void]$errors.Add(('Version info {0}: {1}' -f $path,$_.Exception.Message))}
                    if($entry.Name -match '(?i)^AutoHotkey'){[void]$evidence.Add('AutoHotkey interpreter file name')}
                    if(($product+' '+$description) -match '(?i)AutoHotkey'){[void]$evidence.Add('Version info names AutoHotkey')}
                    if($entry.Length -le $script:IndicatorMaxScanBytes) {
                        try {
                            $bytes=if($ContentReader){& $ContentReader $path}else{[IO.File]::ReadAllBytes($path)}
                            $text=[Text.Encoding]::GetEncoding(28591).GetString([byte[]]$bytes)
                            if(Test-SccBytesContain $text '>AUTOHOTKEY SCRIPT<'){[void]$evidence.Add('Compiled AutoHotkey script resource (>AUTOHOTKEY SCRIPT<)')}
                            elseif($evidence.Count -eq 0 -and (Test-SccBytesContain $text 'AutoHotkeyGUI')){[void]$evidence.Add('AutoHotkey runtime window class string (possible compiled script; weaker signal)')}
                        } catch {[void]$errors.Add(('File read {0}: {1}' -f $path,$_.Exception.Message))}
                    }
                    if($evidence.Count){$kind='AutoHotkey'}
                    elseif((($product+' '+$company+' '+$description) -match '(?i)ScreenConnect|ConnectWise Control') -and $path -notmatch $scLocation) {
                        $kind='ScreenConnectOutsideInstall';[void]$evidence.Add('ScreenConnect binary outside a Program Files install folder')
                    }
                }
                if(-not $kind){continue}
                $hash=$null
                if($entry.Length -le $script:InventoryMaxHashBytes){try{$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash}catch{[void]$errors.Add(('File hash {0}: {1}' -f $path,$_.Exception.Message))}}
                $evidenceText=@($evidence.ToArray()) -join '; '
                $row=[pscustomobject]@{Kind=$kind;Path=$path;Length=$entry.Length;CreatedUtc=$entry.CreationTimeUtc;ModifiedUtc=$entry.LastWriteTimeUtc;SHA256=$hash;ProductName=$product;CompanyName=$company;Evidence=$evidenceText}
                [void]$items.Add($row)
                $reason=if($kind -eq 'AutoHotkey'){'AutoHotkey is often used to drop or relaunch remote-access tools, but it is also a legitimate tool. Review only; nothing is removed.'}else{'Portable, renamed or leftover ScreenConnect binary in a user-writable folder. Review only; nothing is removed.'}
                [void]$findings.Add((New-SccIndicatorFinding -Kind $kind -Target $path -Command $evidenceText -Reason $reason -Details $row))
            }
            if($capHit -or $rootCut){break}
        }
        if($rootCut -or ($capHit -and $stack.Count -gt 0)){[void]$truncatedRoots.Add([string]$root.Path);$truncated=$true}
        if($examined -ge $MaxFiles){$truncated=$true;for($rj=$ri+1;$rj -lt $rootList.Count;$rj++){[void]$truncatedRoots.Add([string]$rootList[$rj].Path)};break}
    }
    [pscustomobject]@{Items=@($items.ToArray());Findings=@($findings.ToArray());Errors=@($errors.ToArray());Truncated=$truncated;Limits=[pscustomobject]@{MaxFiles=$MaxFiles;MaxSeconds=$MaxSeconds;MaxScanBytes=$script:IndicatorMaxScanBytes;Examined=$examined;TruncatedRoots=@($truncatedRoots.ToArray())}}
}
function Get-SccAutoHotkeyAutostartEvidence {
    # Cross-references rows the inventory already collected. No second registry or
    # task pass. A hit means AutoHotkey (or a compiled AutoHotkey file found by the
    # walk) starts automatically.
    param([object[]]$RunKeys=@(),[object[]]$StartupFiles=@(),[object[]]$Tasks=@(),[object[]]$Services=@(),[string[]]$KnownPaths=@())
    $items=New-Object System.Collections.ArrayList; $findings=New-Object System.Collections.ArrayList
    $pattern='(?i)autohotkey|\.ahk\b|\.ah2\b'
    $known=@($KnownPaths | Where-Object {$_})
    $candidates=New-Object System.Collections.ArrayList
    foreach($r in @($RunKeys)){[void]$candidates.Add(@('RunKey',([string](Get-SccPropertyValue $r 'RegistryPath')+'|'+[string](Get-SccPropertyValue $r 'ValueName')),[string](Get-SccPropertyValue $r 'OriginalValue')))}
    foreach($s in @($StartupFiles)){[void]$candidates.Add(@('StartupFile',[string](Get-SccPropertyValue $s 'FilePath'),([string](Get-SccPropertyValue $s 'FilePath')+' -> '+[string](Get-SccPropertyValue $s 'ResolvedTarget'))))}
    foreach($t in @($Tasks)){[void]$candidates.Add(@('ScheduledTask',([string](Get-SccPropertyValue $t 'TaskPath')+[string](Get-SccPropertyValue $t 'TaskName')),[string](Get-SccPropertyValue $t 'Command')))}
    foreach($v in @($Services)){[void]$candidates.Add(@('Service',[string](Get-SccPropertyValue $v 'Name'),[string](Get-SccPropertyValue $v 'PathName')))}
    foreach($c in $candidates) {
        $source=$c[0];$identity=$c[1];$command=$c[2]
        if(-not $command){continue}
        $hit=($command -match $pattern)
        if(-not $hit){foreach($k in $known){if($command.IndexOf($k,[StringComparison]::OrdinalIgnoreCase) -ge 0){$hit=$true;break}}}
        if(-not $hit){continue}
        $target=$source+'|'+$identity
        [void]$items.Add([pscustomobject]@{Source=$source;Identity=$identity;Command=$command})
        [void]$findings.Add((New-SccIndicatorFinding -Kind 'AutoHotkeyAutostart' -Target $target -Command $command -Reason ('AutoHotkey starts automatically from a '+$source+'. Legitimate for some users; review who set it up. Review only.') -Details ([pscustomobject]@{Source=$source;Identity=$identity;Command=$command})))
    }
    [pscustomobject]@{Items=@($items.ToArray());Findings=@($findings.ToArray());Errors=@()}
}
function Get-SccPersistenceInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$OutDir)
    Assert-SccInventoryPath $OutDir
    $inventoryFile=Join-Path $OutDir 'inventory.json'
    if(Test-Path -LiteralPath $inventoryFile){throw 'Existing persistence inventory is not overwritten; use a fresh run.'}
    $null=New-Item -ItemType Directory -Force -Path $OutDir
    $started=[Diagnostics.Stopwatch]::StartNew();$errors=New-Object System.Collections.ArrayList;$warnings=New-Object System.Collections.ArrayList;$sections=[ordered]@{};$findings=New-Object System.Collections.ArrayList
    $xmlDir=Join-Path $OutDir 'task_xml';Assert-SccInventoryPath $xmlDir;$null=New-Item -ItemType Directory -Force -Path $xmlDir
    Write-Host 'SCC_PERSISTENCE_SECTION|ScheduledTasks'
    $task=Get-SccTaskEvidence -XmlDirectory $xmlDir
    Write-Host 'SCC_PERSISTENCE_DONE|ScheduledTasks'
    $sections.ScheduledTasks=New-SccSection -Items $task.Items -Errors $task.Errors
    $sections.TaskXml=New-SccSection -Items @($task.Findings | ForEach-Object {$_.Details}) -Errors $task.Errors
    foreach($f in $task.Findings){[void]$findings.Add($f)};foreach($e in $task.Errors){[void]$errors.Add($e)}
    Write-Host 'SCC_PERSISTENCE_SECTION|RunKeys'
    $registry=Get-SccRegistryEvidence
    Write-Host 'SCC_PERSISTENCE_DONE|RunKeys'
    $sections.RunKeys=New-SccSection -Items $registry.Items -Errors $registry.Errors
    # Build the SID list explicitly: a pipeline property read here sits outside any
    # section try/catch and would abort the whole inventory collection.
    $coveredSids=New-Object System.Collections.ArrayList
    foreach($row in @($registry.Items)) {
        $sid=[string](Get-SccPropertyValue $row 'SID')
        if($sid -and -not $coveredSids.Contains($sid)){[void]$coveredSids.Add($sid)}
    }
    $sections.ProfileCoverage=New-SccSection -Status $(if($registry.ProfileErrors.Count){'Incomplete'}else{'Complete'}) -Items @($coveredSids.ToArray()) -Errors $registry.ProfileErrors
    foreach($f in $registry.Findings){[void]$findings.Add($f)};foreach($e in $registry.Errors){[void]$errors.Add($e)};foreach($e in $registry.ProfileErrors){[void]$errors.Add($e)}
    Write-Host 'SCC_PERSISTENCE_SECTION|StartupFiles'
    $startup=Get-SccStartupEvidence -Profiles $((Get-SccProfileRoots).Profiles)
    Write-Host 'SCC_PERSISTENCE_DONE|StartupFiles'
    $sections.StartupFiles=New-SccSection -Items $startup.Items -Errors $startup.Errors
    foreach($f in $startup.Findings){[void]$findings.Add($f)};foreach($e in $startup.Errors){[void]$errors.Add($e)}
    Write-Host 'SCC_PERSISTENCE_SECTION|HiddenTasks'
    $hidden=Get-SccHiddenTaskEvidence -Tasks $task.Items
    Write-Host 'SCC_PERSISTENCE_DONE|HiddenTasks'
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
      Processes={Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {(Get-SccPropertyValue $_ 'Name') -match '(?i)wscript|cscript|mshta|powershell|pwsh|rundll32|regsvr32|bitsadmin|certutil|msbuild|installutil|regasm|msiexec'} | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine}
      Connections={Get-NetTCPConnection -ErrorAction Stop | Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State}
      Defender={ $threats=@{};foreach($threat in @(Get-MpThreat -ErrorAction Stop)){$threats[[string]$threat.ThreatID]=$threat.ThreatName};Get-MpThreatDetection -ErrorAction Stop | ForEach-Object {$d=$_;[pscustomobject]@{InitialDetectionTime=$d.InitialDetectionTime;ThreatID=$d.ThreatID;ThreatName=$threats[[string]$d.ThreatID];ProcessName=$d.ProcessName;Resources=$d.Resources;ActionSuccess=$d.ActionSuccess;DomainUser=$d.DomainUser}} }
      DefenderConfig={Get-MpPreference -ErrorAction Stop | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,DisableRealtimeMonitoring}
      AntivirusProducts={Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,productState}
      Logons={Get-SccEventRecords -Filter @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-14)} -Maximum 500 | ForEach-Object {$event=$_;$data=@{};try{$xml=[xml]$event.ToXml();foreach($d in $xml.Event.EventData.Data){$data[$d.Name]=$d.'#text'}}catch{};if(@('2','7','10','11') -contains [string]$data.LogonType){[pscustomobject]@{Time=$event.TimeCreated;LogonType=$data.LogonType;User=$data.TargetUserName;IP=$data.IpAddress;Process=$data.ProcessName}}}}
      RdpEvents={foreach($spec in @(@('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',1149),@('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',21,22,24,25))){Get-SccEventRecords -Filter @{LogName=$spec[0];Id=@($spec|Select-Object -Skip 1);StartTime=(Get-Date).AddDays(-14)} -Maximum 400 | Select-Object TimeCreated,Id,Message}}
      Accounts={Get-LocalUser -ErrorAction Stop | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description}
      LocalAdministrators={Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name,ObjectClass,PrincipalSource}
      RemoteTools={Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Stop | Where-Object {(Get-SccPropertyValue $_ 'DisplayName') -match '(?i)AnyDesk|TeamViewer|Splashtop|ScreenConnect|ConnectWise|RustDesk|UltraVNC|TightVNC|RealVNC|LogMeIn|Ammyy|Supremo|Chrome Remote|Atera|NetSupport|RemotePC|Radmin|DWService|MeshAgent|Zoho.?Assist|Action1|Level\.io|Datto|Kaseya|N-able|Syncro|Pulseway'} | Select-Object DisplayName,DisplayVersion,InstallDate,Publisher}
      RemoteToolServices={Get-Service -ErrorAction Stop | Where-Object { $serviceName=(Get-SccPropertyValue $_ 'Name'); $serviceDisplay=(Get-SccPropertyValue $_ 'DisplayName'); $remotePattern='(?i)AnyDesk|TeamViewer|ScreenConnect|ConnectWise|RustDesk|VNC|Splashtop|Atera|Kaseya|MeshAgent'; ([string]$serviceName -match $remotePattern) -or ([string]$serviceDisplay -match $remotePattern) } | Select-Object Name,DisplayName,Status,StartType}
      Hosts={Get-Content (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction Stop | Where-Object {$_ -and $_ -notmatch '^\s*#'}}
    }
    foreach($name in $collectors.Keys){
        Write-Host ('SCC_PERSISTENCE_SECTION|'+$name)
        $evidence=Get-SccGenericEvidence -Name $name -Collector $collectors[$name]
        $sections[$name]=New-SccSection -Items $evidence.Items -Errors $evidence.Errors
        foreach($e in $evidence.Errors){[void]$errors.Add($e)}
        Write-Host ('SCC_PERSISTENCE_DONE|'+$name)
    }
    # ---- Tampering indicators (schema 2). Review-only findings. Coverage gaps here
    # (cap reached, access denied) mark the SECTION incomplete and are recorded in
    # Warnings, not Errors: a lighter lead scan must never flip the whole
    # persistence stage to Incomplete. The section's own Status still says so.
    $indicatorProfiles=@((Get-SccProfileRoots).Profiles)
    Write-Host 'SCC_PERSISTENCE_SECTION|UacPolicy'
    $uac=Get-SccUacPolicyEvidence
    Write-Host 'SCC_PERSISTENCE_DONE|UacPolicy'
    $sections.UacPolicy=New-SccSection -Items $uac.Items -Errors $uac.Errors
    foreach($f in $uac.Findings){[void]$findings.Add($f)};foreach($e in $uac.Errors){[void]$warnings.Add($e)}
    Write-Host 'SCC_PERSISTENCE_SECTION|UacBypassKeys'
    $bypass=Get-SccUacBypassEvidence -Profiles $indicatorProfiles
    Write-Host 'SCC_PERSISTENCE_DONE|UacBypassKeys'
    $sections.UacBypassKeys=New-SccSection -Items $bypass.Items -Errors $bypass.Errors
    foreach($f in $bypass.Findings){[void]$findings.Add($f)};foreach($e in $bypass.Errors){[void]$warnings.Add($e)}
    Write-Host 'SCC_PERSISTENCE_SECTION|UserWritableBinaries'
    $binaries=Get-SccUserWritableBinaryEvidence -Roots (Get-SccUserWritableRoots -Profiles $indicatorProfiles)
    Write-Host 'SCC_PERSISTENCE_DONE|UserWritableBinaries'
    $sections.UserWritableBinaries=New-SccSection -Status $(if($binaries.Truncated -or $binaries.Errors.Count){'Incomplete'}else{'Complete'}) -Items $binaries.Items -Errors $binaries.Errors -Limits $binaries.Limits
    foreach($f in $binaries.Findings){[void]$findings.Add($f)};foreach($e in $binaries.Errors){[void]$warnings.Add($e)}
    if($binaries.Truncated){
        $cutRoots=@();$limitsObject=$binaries.Limits;if($limitsObject){$cutProperty=$limitsObject.PSObject.Properties['TruncatedRoots'];if($cutProperty){$cutRoots=@($cutProperty.Value)}}
        [void]$warnings.Add('UserWritableBinaries: bounded file/time cap reached; AutoHotkey scan truncated'+$(if($cutRoots.Count){' (not fully walked: '+(@($cutRoots) -join '; ')+')'}else{''}))
    }
    Write-Host 'SCC_PERSISTENCE_SECTION|AutoHotkeyAutostart'
    $serviceRows=@();$serviceProperty=$sections['Services'];if($serviceProperty){$serviceRows=@($serviceProperty.Items)}
    $ahkPaths=@($binaries.Items | Where-Object {[string](Get-SccPropertyValue $_ 'Kind') -eq 'AutoHotkey' -and [string](Get-SccPropertyValue $_ 'Path') -match '(?i)\.exe$'} | ForEach-Object {[string](Get-SccPropertyValue $_ 'Path')})
    $autostart=Get-SccAutoHotkeyAutostartEvidence -RunKeys $registry.Items -StartupFiles $startup.Items -Tasks $task.Items -Services $serviceRows -KnownPaths $ahkPaths
    Write-Host 'SCC_PERSISTENCE_DONE|AutoHotkeyAutostart'
    $sections.AutoHotkeyAutostart=New-SccSection -Items $autostart.Items -Errors $autostart.Errors
    foreach($f in $autostart.Findings){[void]$findings.Add($f)}
    $roots=@($env:ProgramData,$env:ProgramFiles,${env:ProgramFiles(x86)})
    if($env:SystemDrive){$roots+=(Join-Path $env:SystemDrive 'Users')}
    if($env:SystemRoot){$roots+=(Join-Path $env:SystemRoot 'Temp')}
    $roots=@($roots | Where-Object {$_ -and (Test-Path -LiteralPath $_)})
    Write-Host 'SCC_PERSISTENCE_SECTION|ScriptFiles'
    $scripts=Get-SccBoundedScriptFiles -Roots $roots -MaxFiles $script:InventoryMaxFiles -MaxSeconds $script:InventoryMaxSeconds
    Write-Host 'SCC_PERSISTENCE_DONE|ScriptFiles'
    $sections.ScriptFiles=New-SccSection -Status $(if($scripts.Truncated -or $scripts.Errors.Count){'Incomplete'}else{'Complete'}) -Items $scripts.Items -Errors $scripts.Errors -Limits $scripts.Limits
    foreach($e in $scripts.Errors){[void]$errors.Add($e)};if($scripts.Truncated){[void]$errors.Add('ScriptFiles: bounded file/time cap reached; scan truncated')}
    $sections.PrivacyOmissions=New-SccSection -Items @('No raw script samples collected.','PowerShell shell/history content omitted for privacy.','Offline user registry hives are not mounted; unloaded profiles are explicit coverage gaps.')
    if($started.Elapsed.TotalSeconds -ge $script:InventoryMaxSeconds){[void]$errors.Add('Overall collection exceeded configured time budget; later sections may be partial')}
    $status=if($errors.Count){'Incomplete'}else{'Complete'}
    $runId=Split-Path (Split-Path $OutDir -Parent) -Leaf
    $result=[pscustomobject]@{SchemaVersion=2;RunId=$runId;ComputerName=$env:COMPUTERNAME;GeneratedUtc=[DateTime]::UtcNow.ToString('o');Status=$status;Errors=@($errors.ToArray());Warnings=@($warnings.ToArray());Sections=[pscustomobject]$sections;Findings=@($findings.ToArray());Counts=[pscustomobject]@{Findings=$findings.Count;ScriptFiles=$scripts.Items.Count}}
    Write-Host 'SCC_PERSISTENCE_SECTION|WriteInventory'
    $json=ConvertTo-Json -InputObject $result -Depth 12
    Write-SccInventoryFile -Path $inventoryFile -Text $json
    Write-Host 'SCC_PERSISTENCE_DONE|WriteInventory'
    return $result
}
Export-ModuleMember -Function Get-SccPersistenceInventory
