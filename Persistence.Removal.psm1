# Attended persistence review. Test hooks are private to this module and are never exported.
$script:TestHooks = $null
$script:StartupRootOverride = $null

function Get-SccHashBytes { param([byte[]]$Bytes) $sha=[Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','') } finally { $sha.Dispose() } }
function Get-SccFileHash { param([string]$Path) return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant() }
function Test-SccReparseChain {
    param([string]$Path,[switch]$AllowMissingLeaf)
    $full=[IO.Path]::GetFullPath($Path); $cur=$full
    while ($cur) {
        if (Test-Path -LiteralPath $cur) {
            $item=Get-Item -LiteralPath $cur -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point in protected path: $cur" }
        } elseif (-not $AllowMissingLeaf) { throw "Protected path component is missing: $cur" }
        $parent=Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur=$parent
    }
}
function Write-SccExclusiveBackup {
    param([string]$Path,[byte[]]$Bytes)
    Test-SccReparseChain -Path (Split-Path -Parent $Path)
    $stream=$null
    try { $stream=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush(); $stream.Dispose(); $stream=$null }
    finally { if ($stream) { $stream.Dispose() } }
    $read=[IO.File]::ReadAllBytes($Path)
    if ((Get-SccHashBytes $read) -cne (Get-SccHashBytes $Bytes)) { throw 'Backup readback hash mismatch.' }
}
function Get-SccStartupRoots {
    if ($script:StartupRootOverride) { return @($script:StartupRootOverride) }
    $roots=New-Object System.Collections.ArrayList
    $programData=[Environment]::GetEnvironmentVariable('ProgramData')
    if ($programData) { [void]$roots.Add((Join-Path $programData 'Microsoft\Windows\Start Menu\Programs\Startup')) }
    try {
        $profiles=Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop
        foreach ($sid in (Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop)) {
            if ($sid.PSChildName -notmatch '^S-1-5-21-(?:\d+-){3}\d+$') { continue }
            $profile=[string](Get-ItemProperty -LiteralPath $sid.PSPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
            if (-not $profile) { continue }
            $profile=[Environment]::ExpandEnvironmentVariables($profile)
            [void]$roots.Add((Join-Path $profile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
        }
    } catch { throw "Cannot enumerate profile startup roots: $($_.Exception.Message)" }
    return @($roots.ToArray())
}
function Test-SccRegistryPath {
    param([string]$Path)
    $p=$Path -replace '^HKLM:','Registry::HKEY_LOCAL_MACHINE' -replace '^HKCU:','Registry::HKEY_CURRENT_USER'
    $base='Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunServices|Policies\\Explorer\\Run)'
    $wow='Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunServices)'
    if ($p -match ('^Registry::HKEY_LOCAL_MACHINE\\'+$base+'$') -or $p -match ('^Registry::HKEY_LOCAL_MACHINE\\'+$wow+'$') -or $p -match ('^Registry::HKEY_CURRENT_USER\\'+$base+'$') -or $p -match ('^Registry::HKEY_USERS\\S-1-5-21-(?:\d+-){3}\d+\\'+$base+'$')) { return $p }
    throw 'Registry path is not an explicitly approved Run/RunOnce/RunServices/Explorer Run key.'
}
function Get-SccRegistryValue {
    param([string]$Path,[string]$Name)
    if ($script:TestHooks -and $script:TestHooks.GetRegistry) { return & $script:TestHooks.GetRegistry $Path $Name }
    $key=Get-Item -LiteralPath $Path -ErrorAction Stop
    $names=@($key.GetValueNames())
    if ($names -cnotcontains $Name) { throw 'Registry value is absent.' }
    $kind=$key.GetValueKind($Name).ToString()
    if ($kind -notin @('String','ExpandString')) { throw 'Registry value type is not String or ExpandString.' }
    $value=$key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    return [pscustomobject]@{Value=[string]$value;Kind=$kind;Names=$names}
}
function Get-SccTaskList {
    if ($script:TestHooks -and $script:TestHooks.GetTasks) { return @(& $script:TestHooks.GetTasks) }
    return @(Get-ScheduledTask -ErrorAction Stop)
}
function Get-SccTaskXml { param([string]$Name,[string]$Path) if ($script:TestHooks -and $script:TestHooks.ExportTask) { return [string](& $script:TestHooks.ExportTask $Name $Path) }; return [string](Export-ScheduledTask -TaskName $Name -TaskPath $Path -ErrorAction Stop) }
function Get-SccTaskIdentity { param($Task) return ([string]$Task.TaskPath + [string]$Task.TaskName) }
function Get-SccStartupLinkCount {
    param([string]$Path)
    if ($script:TestHooks -and $script:TestHooks.LinkCount) { return [int](& $script:TestHooks.LinkCount $Path) }
    if ($env:OS -ne 'Windows_NT') { return 1 }
    if (-not ('SccPersistenceFileInfo' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class SccPersistenceFileInfo {
 [StructLayout(LayoutKind.Sequential)] public struct Info { public uint A; public System.Runtime.InteropServices.ComTypes.FILETIME C,D,E; public uint V,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sec,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 public static uint Links(string p) { using(var h=CreateFile(p,0,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)){ if(h.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); Info i; if(!GetFileInformationByHandle(h,out i)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); return i.Links; } }
}
'@ -ErrorAction Stop
    }
    return [int][SccPersistenceFileInfo]::Links($Path)
}
function ConvertTo-SccDisplayText {
    param($Value)
    $text=[string]$Value
    $escape=[string][char]27
    $text=[regex]::Replace($text,($escape+'\[[0-?]*[ -/]*[@-~]'),'')
    return [regex]::Replace($text,'[\x00-\x1f\x7f]+',' ')
}
function Test-SccRemovalResultLeaf {
    param([string]$OutDir)
    $path=Join-Path $OutDir 'removal.json'
    if (-not (Test-Path -LiteralPath $path)) { return }
    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer) { throw 'Existing removal.json is not a plain file.' }
    if ((Get-SccStartupLinkCount $path) -ne 1) { throw 'Existing removal.json has multiple hard links.' }
}
function Write-SccRemovalResult {
    param([string]$OutDir,$Result)
    $path=Join-Path $OutDir 'removal.json'
    Test-SccReparseChain -Path $OutDir
    $temp=Join-Path $OutDir ('.removal.'+[guid]::NewGuid().ToString('N')+'.tmp')
    $json=ConvertTo-Json -InputObject $Result -Depth 12
    Write-SccExclusiveBackup $temp ([Text.Encoding]::UTF8.GetBytes($json))
    try {
        if (Test-Path -LiteralPath $path) {
            Test-SccRemovalResultLeaf -OutDir $OutDir
            $archive=Join-Path $OutDir ('removal.previous.'+[guid]::NewGuid().ToString('N')+'.json')
            [IO.File]::Replace($temp,$path,$archive)
        } else { [IO.File]::Move($temp,$path) }
        Test-SccReparseChain -Path $path
        if ((Get-SccFileHash $path) -cne (Get-SccHashBytes ([Text.Encoding]::UTF8.GetBytes($json))) ) { throw 'removal.json readback hash mismatch.' }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction Stop } }
}
function Invoke-SccPersistenceReview {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Inventory,[Parameter(Mandatory=$true)][string]$OutDir,[Parameter(Mandatory=$true)]$AllowRemoval,[switch]$NoPrompt)
    $errors=New-Object System.Collections.ArrayList; $actions=New-Object System.Collections.ArrayList; $candidates=New-Object System.Collections.ArrayList; $selected=@(); $status='NoCandidates'; $fatal=$false
    try {
        $OutDir=[IO.Path]::GetFullPath($OutDir)
        if ((Split-Path -Leaf $OutDir) -ine 'persistence') { throw 'OutDir must be the current run persistence directory.' }
        Test-SccReparseChain -Path $OutDir -AllowMissingLeaf
        if (-not (Test-Path -LiteralPath $OutDir -PathType Container)) { $null=New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction Stop }
        Test-SccReparseChain -Path $OutDir
        Test-SccRemovalResultLeaf -OutDir $OutDir
    } catch { throw "Invalid evidence output directory: $($_.Exception.Message)" }
    if ($AllowRemoval -isnot [bool]) { $fatal=$true; [void]$errors.Add('AllowRemoval must be a literal Boolean.') }
    if ($null -eq $Inventory -or $null -eq $Inventory.PSObject.Properties['Findings']) { $fatal=$true; [void]$errors.Add('Inventory has no Findings evidence collection.'); $findings=@() }
    else {
        $findings=@($Inventory.Findings)
        $expectedRunId=Split-Path -Leaf (Split-Path -Parent $OutDir)
        if ([int]$Inventory.SchemaVersion -ne 1 -or -not [string]::Equals([string]$Inventory.RunId,$expectedRunId,[StringComparison]::OrdinalIgnoreCase)) { $fatal=$true; [void]$errors.Add('Inventory run identity does not match the current persistence output directory.') }
        if([string]$Inventory.Status -cnotin @('Complete','Incomplete')){$fatal=$true;[void]$errors.Add('Unsupported or malformed inventory cannot authorize cleanup.')}
    }
    $ids=@{}
    foreach ($row in $findings) {
        if ($null -eq $row) { continue }
        $kind=[string]$row.Kind; $id=[string]$row.Id; $target=[string]$row.Target
        if ($kind -notin @('ScheduledTask','RunKey','StartupFile')) { continue }
        $valid=$true
        if ($row.ReviewOnly -isnot [bool]) { $valid=$false }
        if ($id -notmatch '^[A-Fa-f0-9]{24}$' -or $ids.ContainsKey($id)) { $valid=$false }
        if ($ids.ContainsKey($id)) { [void]$errors.Add("Duplicate finding ID refused: $id"); $fatal=$true }
        if ($id -match '^[A-Fa-f0-9]{24}$') { $ids[$id]=$true }
        if ($row.ReviewOnly -is [bool] -and $row.ReviewOnly) {
            if (-not $target -or $target -match '[\x00-\x1f]' -or -not [string]$row.Command -or -not [string]$row.Reason) { $valid=$false }
            if ($valid) { $expectedReviewId=(Get-SccHashBytes ([Text.Encoding]::UTF8.GetBytes($kind+'|'+$target))).Substring(0,24); if ($id -ine $expectedReviewId) { $valid=$false } }
            if (-not $valid) { [void]$errors.Add("Malformed review-only finding refused: $id"); $fatal=$true }
            continue
        }
        # Only the target's complete source category can support approval.
        # Unrelated context gaps never turn into a malware-clean verdict.
        $requiredSections=switch($kind){
            'ScheduledTask' {@('ScheduledTasks','TaskXml')}
            'RunKey' {@('RunKeys')}
            'StartupFile' {@('StartupFiles')}
        }
        foreach($sectionName in $requiredSections) {
            $section=$null
            if($Inventory.Sections){$property=$Inventory.Sections.PSObject.Properties[$sectionName];if($property){$section=$property.Value}}
            if(-not $section -or [string]$section.Status -cne 'Complete' -or @($section.Errors).Count -gt 0){
                $fatal=$true;$valid=$false
                [void]$errors.Add("Incomplete $sectionName evidence cannot authorize cleanup: $id")
            }
        }
        if (-not $target -or $target -match '[\x00-\x1f]') { $valid=$false }
        if (-not [string]$row.Command -or -not [string]$row.Reason) { $valid=$false }
        $details=$row.Details
        if ($kind -eq 'ScheduledTask') {
            $n=[string]$details.TaskName; $p=[string]$details.TaskPath
            if (-not $n -or $n -match '[*?\[\]]|[\\/]' -or $n -match '[\x00-\x1f]' -or -not $p -or $p -notmatch '^\\(?:[^\\:*?\[\]]+\\)*$' -or $p -match '^\\Microsoft\\') { $valid=$false }
            if ($target -cne ($p+$n) -or [string]$details.XmlSha256 -notmatch '^[A-Fa-f0-9]{64}$') { $valid=$false }
            $identity=$kind+'|'+$target
        } elseif ($kind -eq 'RunKey') {
            try { $allowed=Test-SccRegistryPath ([string]$details.RegistryPath) } catch { $allowed=$null }
            if (-not $allowed -or -not [string]$details.ValueName -or [string]$details.ValueName -match '[*?\[\]\x00-\x1f]' -or [string]$details.ValueKind -notin @('String','ExpandString') -or $null -eq $details.PSObject.Properties['OriginalValue']) { $valid=$false }
            if ($target -cne ([string]$details.RegistryPath+'|'+[string]$details.ValueName)) { $valid=$false }
            $identity=$kind+'|'+$target
        } else {
            try { $full=[IO.Path]::GetFullPath([string]$details.FilePath) } catch { $full='' }
            if (-not $full -or $target -cne $full -or [string]$details.SHA256 -notmatch '^[A-Fa-f0-9]{64}$') { $valid=$false }
            $identity=$kind+'|'+$target
        }
        if ($valid) {
            $expected=(Get-SccHashBytes ([Text.Encoding]::UTF8.GetBytes($identity))).Substring(0,24)
            if ($id -ine $expected) { $valid=$false }
        }
        if (-not $valid) { [void]$errors.Add("Malformed or untrusted removable finding refused: $id"); $fatal=$true; continue }
        [void]$candidates.Add($row)
    }
    if ($fatal) { $status='Incomplete' }
    elseif ($candidates.Count -eq 0) { $status='NoCandidates' }
    elseif (-not $AllowRemoval) { $status='Skipped' }
    elseif ($NoPrompt) { $status='Declined' }
    else {
        try {
            for ($i=0; $i -lt $candidates.Count; $i++) {
                $r=$candidates[$i]
                Write-Host ("[{0}] {1}`n    Target: {2}`n    Command: {3}`n    Reason: {4}" -f ($i+1),(ConvertTo-SccDisplayText $r.Kind),(ConvertTo-SccDisplayText $r.Target),(ConvertTo-SccDisplayText $r.Command),(ConvertTo-SccDisplayText $r.Reason))
            }
            $answer=Read-Host 'Enter comma-separated candidate indices'
            if ($null -eq $answer -or [string]$answer -notmatch '^\s*[1-9][0-9]*(?:\s*,\s*[1-9][0-9]*)*\s*$') { throw 'Invalid selection.' }
            $nums=New-Object System.Collections.ArrayList
            foreach ($piece in ([string]$answer -split ',')) {
                $num=0; if (-not [int]::TryParse($piece.Trim(),[ref]$num) -or $num -lt 1 -or $num -gt $candidates.Count -or $nums.Contains($num)) { throw 'Selection index invalid, duplicate, or out of range.' }
                [void]$nums.Add($num)
            }
            $selected=@($nums | ForEach-Object { $candidates[$_-1] })
            Write-Host 'Exact selected targets:'
            foreach ($r in $selected) { Write-Host ("  {0} | {1}`n      Command: {2}`n      Reason: {3}" -f (ConvertTo-SccDisplayText $r.Kind),(ConvertTo-SccDisplayText $r.Target),(ConvertTo-SccDisplayText $r.Command),(ConvertTo-SccDisplayText $r.Reason)) }
            $confirm=Read-Host 'Type REMOVE to confirm these exact targets'
            if ($confirm -cne 'REMOVE') { $selected=@(); $status='Declined' } else { $status='Completed' }
        } catch { $selected=@(); $status='Declined'; [void]$errors.Add("Selection declined: $($_.Exception.Message)") }
    }
    foreach ($row in $selected) {
        $act=[ordered]@{Id=[string]$row.Id;Kind=[string]$row.Kind;Target=[string]$row.Target;Status='Failed';BackupPath=$null;Error=$null}
        try {
            $backup=Join-Path $OutDir ([string]$row.Id+'.backup')
            if ($row.Kind -eq 'ScheduledTask') {
                $name=[string]$row.Details.TaskName; $path=[string]$row.Details.TaskPath
                $all=Get-SccTaskList; $matches=@($all | Where-Object { $_.TaskName -ceq $name -and $_.TaskPath -ceq $path })
                if ($matches.Count -ne 1 -or (Get-SccTaskIdentity $matches[0]) -cne [string]$row.Target) { throw 'Exact current task identity validation failed.' }
                $xml=Get-SccTaskXml $name $path; $hash=Get-SccHashBytes ([Text.Encoding]::UTF8.GetBytes($xml))
                if ($hash -cne ([string]$row.Details.XmlSha256).ToUpperInvariant()) { throw 'Current task XML hash mismatch.' }
                $bytes=[Text.Encoding]::UTF8.GetBytes($xml); Write-SccExclusiveBackup $backup $bytes; $act.BackupPath=$backup
                $fresh=Get-SccTaskList; $freshMatches=@($fresh | Where-Object { $_.TaskName -ceq $name -and $_.TaskPath -ceq $path })
                if ($freshMatches.Count -ne 1 -or (Get-SccHashBytes ([Text.Encoding]::UTF8.GetBytes((Get-SccTaskXml $name $path)))) -cne ([string]$row.Details.XmlSha256).ToUpperInvariant()) { throw 'Task identity/XML changed after backup; refusing removal.' }
                if ($script:TestHooks -and $script:TestHooks.RemoveTask) { & $script:TestHooks.RemoveTask $name $path } else { Unregister-ScheduledTask -TaskName $name -TaskPath $path -Confirm:$false -ErrorAction Stop }
                $after=Get-SccTaskList
                $still=@($after | Where-Object { $_.TaskName -ceq $name -and $_.TaskPath -ceq $path })
                if ($still.Count -ne 0) { throw 'Exact task remains after removal.' }
            } elseif ($row.Kind -eq 'RunKey') {
                $regPath=Test-SccRegistryPath ([string]$row.Details.RegistryPath); $valueName=[string]$row.Details.ValueName
                $current=Get-SccRegistryValue $regPath $valueName
                if ($current.Kind -notin @('String','ExpandString') -or $current.Kind -cne [string]$row.Details.ValueKind -or $current.Value -cne [string]$row.Details.OriginalValue) { throw 'Current registry value/type mismatch.' }
                $json=ConvertTo-Json -InputObject @{RegistryPath=$regPath;ValueName=$valueName;OriginalValue=$current.Value;ValueKind=$current.Kind} -Compress
                Write-SccExclusiveBackup $backup ([Text.Encoding]::UTF8.GetBytes($json)); $act.BackupPath=$backup
                $freshValue=Get-SccRegistryValue $regPath $valueName
                if ($freshValue.Kind -cne $current.Kind -or $freshValue.Value -cne $current.Value) { throw 'Registry value changed after backup; refusing removal.' }
                if ($script:TestHooks -and $script:TestHooks.RemoveRegistry) { & $script:TestHooks.RemoveRegistry $regPath $valueName } else { Remove-ItemProperty -LiteralPath $regPath -Name $valueName -ErrorAction Stop }
                if ($script:TestHooks -and $script:TestHooks.CheckRegistry) { $present=& $script:TestHooks.CheckRegistry $regPath $valueName } else { $key=Get-Item -LiteralPath $regPath -ErrorAction Stop; $names=@($key.GetValueNames()); $present=($names -ccontains $valueName) }
                if ($present) { throw 'Registry value remains after removal.' }
            } else {
                $file=[IO.Path]::GetFullPath([string]$row.Details.FilePath); $roots=Get-SccStartupRoots; $root=$null
                foreach ($candidateRoot in $roots) { $r=[IO.Path]::GetFullPath([string]$candidateRoot).TrimEnd('\'); if ([string]::Equals((Split-Path -Parent $file),$r,[StringComparison]::OrdinalIgnoreCase)) { $root=$r; break } }
                if (-not $root -or -not [string]::Equals((Split-Path -Parent $file),$root,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Startup target must be a direct child of an enumerated startup folder.' }
                Test-SccReparseChain -Path $root; Test-SccReparseChain -Path $file
                if ((Get-SccStartupLinkCount $file) -ne 1) { throw 'Hard-linked startup files are refused.' }
                if ((Get-SccFileHash $file) -cne ([string]$row.Details.SHA256).ToUpperInvariant()) { throw 'Startup file hash mismatch.' }
                $qdir=Join-Path $OutDir 'quarantine'; if (-not (Test-Path -LiteralPath $qdir)) { $null=New-Item -ItemType Directory -Path $qdir -ErrorAction Stop }
                Test-SccReparseChain -Path $qdir
                $backup=Join-Path $qdir ([string]$row.Id+'.backup'); $dest=Join-Path $qdir ([string]$row.Id+'-'+[IO.Path]::GetFileName($file))
                if ((Test-Path -LiteralPath $backup) -or (Test-Path -LiteralPath $dest)) { throw 'Quarantine destination collision; refusing overwrite.' }
                if ($script:TestHooks -and $script:TestHooks.CopyFile) { & $script:TestHooks.CopyFile $file $backup } else { [IO.File]::Copy($file,$backup,$false) }
                if ((Get-SccFileHash $backup) -cne ([string]$row.Details.SHA256).ToUpperInvariant()) { throw 'Startup backup verification failed.' }
                $act.BackupPath=$backup
                Test-SccReparseChain -Path $root; Test-SccReparseChain -Path $file
                if ((Get-SccStartupLinkCount $file) -ne 1 -or (Get-SccFileHash $file) -cne ([string]$row.Details.SHA256).ToUpperInvariant()) { throw 'Startup source changed after backup; refusing move.' }
                if (Test-Path -LiteralPath $dest) { throw 'Quarantine destination appeared; refusing overwrite.' }
                if ($script:TestHooks -and $script:TestHooks.MoveFile) { & $script:TestHooks.MoveFile $file $dest } else { [IO.File]::Move($file,$dest) }
                if ((Test-Path -LiteralPath $file) -or -not (Test-Path -LiteralPath $dest) -or (Get-SccFileHash $dest) -cne ([string]$row.Details.SHA256).ToUpperInvariant()) { throw 'Startup quarantine move/readback verification failed.' }
            }
            $act.Status='Removed'
        } catch { $act.Error=$_.Exception.Message; [void]$errors.Add($act.Error) }
        [void]$actions.Add([pscustomobject]$act)
    }
    if ($errors.Count -gt 0 -and $actions.Count -gt 0) { $status='Incomplete' }
    elseif ($actions.Count -gt 0) { $status='Completed' }
    $result=[pscustomobject]@{SchemaVersion=1;Status=$status;Actions=@($actions.ToArray());Errors=@($errors.ToArray())}
    try { Write-SccRemovalResult -OutDir $OutDir -Result $result } catch { throw "Could not write removal result: $($_.Exception.Message)" }
    return $result
}
Export-ModuleMember -Function Invoke-SccPersistenceReview
