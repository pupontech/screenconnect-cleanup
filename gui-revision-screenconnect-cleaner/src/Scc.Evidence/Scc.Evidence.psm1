
# Ensure Microsoft.PowerShell.Utility cmdlets ([datetime]::UtcNow, New-Object, ConvertTo-Json,
# Out-Null, Add-Member, etc.) are visible inside this module's session state on every
# host. Without this, module functions fail with CommandNotFoundException on Windows
# when the module is loaded through Pester or a nested session state.
$null = Import-Module -Name 'Microsoft.PowerShell.Utility' -ErrorAction SilentlyContinue
$null = Import-Module -Name 'Microsoft.PowerShell.Management' -ErrorAction SilentlyContinue

<#
  Scc.Evidence.psm1 - Snapshot collection for ScreenConnect Cleaner

  Captures the machine's persistence and execution surface in a stable,
  diffable JSON form. Read-only: never modifies system state.

  Schema v2: { SchemaVersion:2, Label, ComputerName, CollectedUtc, IsAdmin,
    OsCaption, IncidentWindowDays, SccAppVersion, CollectionErrors:[{Section,Error}],
    Sections: { Services, ScheduledTasks, RegistryAutoruns, StartupFolders,
    Processes, Connections, InstalledPrograms, LocalAccounts, FirewallRules,
    WmiPersistence, RecentFiles, ScInstallations, SystemSettings } }
#>

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

function Add-CollectionError {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]]$ErrorList,
        [string]$Section,
        [string]$ErrorText
    )
    # Thread-safe: List[T] is not safe for concurrent Add across runspaces.
    # Lock on the list instance to serialize writes.
    [System.Threading.Monitor]::Enter($ErrorList)
    try {
        $ErrorList.Add([PSCustomObject]@{
            Section = $Section
            Error   = $ErrorText
        })
    }
    finally {
        [System.Threading.Monitor]::Exit($ErrorList)
    }
}

function Invoke-Section {
    [CmdletBinding()]
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock,
        [System.Collections.Generic.List[object]]$ErrorList
    )
    try {
        $out = & $ScriptBlock
        if ($null -eq $out) { return , @() }
        return @($out)
    }
    catch {
        Add-CollectionError -ErrorList $ErrorList -Section $Name -ErrorText $_.Exception.Message
        return , @()
    }
}

function Sort-ByKey {
    param($Items)
    if ($null -eq $Items) { return , @() }
    if ($Items.Count -eq 0) { return , @() }
    return @($Items | Sort-Object -Property Key)
}

function ConvertTo-NullSafeString {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [string]$Value
}

function Get-RegValueSafe {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Test-IsWindows {
    # PS7 sets $IsWindows; PS 5.1 has no $IsWindows - check env:OS
    if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
        return $IsWindows
    }
    return ($env:OS -eq 'Windows_NT')
}

function Get-HostNameSafe {
    $h = $env:COMPUTERNAME
    if (-not [string]::IsNullOrWhiteSpace($h)) { return $h }
    $h = $env:HOSTNAME
    if (-not [string]::IsNullOrWhiteSpace($h)) { return $h }
    try {
        $h = [System.Net.Dns]::GetHostName()
        if (-not [string]::IsNullOrWhiteSpace($h)) { return $h }
    }
    catch { }
    return 'unknown'
}

function Test-IsAdmin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = [System.Security.Principal.WindowsPrincipal]::new($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-Win32OsCaption {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return ConvertTo-NullSafeString $os.Caption
    }
    catch {
        return ''
    }
}

# ---------------------------------------------------------------------------
# Section collectors (private)
# ---------------------------------------------------------------------------

function Get-ServicesSection {
    $wmiSvcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    $rows = @($wmiSvcs | ForEach-Object {
        [PSCustomObject]@{
            Key         = $_.Name
            Name        = $_.Name
            DisplayName = $_.DisplayName
            PathName    = $_.PathName
            State       = $_.State
            StartMode   = $_.StartMode
            StartName   = $_.StartName
        }
    })
    return $rows
}

function Get-ScheduledTasksSection {
    $tasks = Get-ScheduledTask -ErrorAction Stop
    $rows = @($tasks | ForEach-Object {
        $actions = @($_.Actions | ForEach-Object {
            [PSCustomObject]@{
                Execute   = ConvertTo-NullSafeString $_.Execute
                Arguments = ConvertTo-NullSafeString $_.Arguments
            }
        })
        $author = ''
        try { $author = ConvertTo-NullSafeString $_.Author } catch { $author = '' }
        [PSCustomObject]@{
            Key      = "$($_.TaskPath)|$($_.TaskName)"
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            State    = [string]$_.State
            Author   = $author
            Actions  = @($actions)
        }
    })
    return $rows
}

function Get-RegistryAutorunsSection {
    $rows = [System.Collections.Generic.List[object]]::new()

    $runKeySpecs = @(
        @{ Hive = 'HKLM'; View = '64'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' }
        @{ Hive = 'HKLM'; View = '64'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
        @{ Hive = 'HKLM'; View = '32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' }
        @{ Hive = 'HKLM'; View = '32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' }
        @{ Hive = 'HKCU'; View = '64'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' }
        @{ Hive = 'HKCU'; View = '64'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
    )

    foreach ($spec in $runKeySpecs) {
        try {
            if (Test-Path -LiteralPath $spec.Path) {
                $item = Get-Item -LiteralPath $spec.Path -ErrorAction Stop
                foreach ($valueName in $item.Property) {
                    $val = (Get-ItemProperty -LiteralPath $spec.Path -Name $valueName -ErrorAction Stop).$valueName
                    $rows.Add([PSCustomObject]@{
                        Key       = "$($spec.Hive)|$($spec.Path)|$valueName"
                        Hive      = $spec.Hive
                        View      = $spec.View
                        KeyPath   = $spec.Path
                        ValueName = $valueName
                        Value     = ConvertTo-NullSafeString $val
                        Kind      = 'RunKey'
                    })
                }
            }
        }
        catch {
            # Silently continue - error recorded by caller
            throw
        }
    }

    $winlogonSpecs = @(
        @{ Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' }
        @{ Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' }
    )
    foreach ($spec in $winlogonSpecs) {
        try {
            if (Test-Path -LiteralPath $spec.Path) {
                foreach ($valueName in @('Shell', 'Userinit')) {
                    $val = Get-RegValueSafe -Path $spec.Path -Name $valueName
                    if ($null -ne $val) {
                        $rows.Add([PSCustomObject]@{
                            Key       = "$($spec.Hive)|$($spec.Path)|$valueName"
                            Hive      = $spec.Hive
                            View      = '64'
                            KeyPath   = $spec.Path
                            ValueName = $valueName
                            Value     = ConvertTo-NullSafeString $val
                            Kind      = 'Winlogon'
                        })
                    }
                }
            }
        }
        catch {
            throw
        }
    }

    return $rows.ToArray()
}

function Get-StartupFoldersSection {
    $rows = [System.Collections.Generic.List[object]]::new()

    $allUsersStartup = ''
    $currentUserStartup = ''
    if ($env:ProgramData) {
        $allUsersStartup = [System.IO.Path]::Combine($env:ProgramData, 'Microsoft\Windows\Start Menu\Programs\StartUp')
    }
    if ($env:APPDATA) {
        $currentUserStartup = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Start Menu\Programs\Startup')
    }

    $folderSpecs = @(
        @{ Scope = 'AllUsers'; Path = $allUsersStartup }
        @{ Scope = 'CurrentUser'; Path = $currentUserStartup }
    )

    foreach ($spec in $folderSpecs) {
        try {
            if ($spec.Path -and (Test-Path -LiteralPath $spec.Path)) {
                $files = Get-ChildItem -LiteralPath $spec.Path -File -ErrorAction Stop
                foreach ($f in $files) {
                    $rows.Add([PSCustomObject]@{
                        Key          = "$($spec.Scope)|$($f.Name)"
                        Scope        = $spec.Scope
                        FileName     = $f.Name
                        FullPath     = $f.FullName
                        LastWriteUtc = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        LengthBytes  = $f.Length
                    })
                }
            }
        }
        catch {
            throw
        }
    }

    return $rows.ToArray()
}

function Get-ProcessesSection {
    $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    $rows = @($procs | ForEach-Object {
        $owner = ''
        try {
            $ownerInfo = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
            if ($ownerInfo -and $ownerInfo.ReturnValue -eq 0) {
                if ($ownerInfo.Domain) {
                    $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                }
                else {
                    $owner = ConvertTo-NullSafeString $ownerInfo.User
                }
            }
        }
        catch {
            $owner = ''
        }

        $created = ''
        try {
            if ($_.CreationDate) {
                $created = $_.CreationDate.ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
        catch { $created = '' }

        [PSCustomObject]@{
            Key             = "$($_.ExecutablePath)|$($_.ProcessId)"
            ProcessId       = $_.ProcessId
            ParentProcessId = $_.ParentProcessId
            Name            = $_.Name
            ExecutablePath  = ConvertTo-NullSafeString $_.ExecutablePath
            CommandLine     = ConvertTo-NullSafeString $_.CommandLine
            CreationDate    = $created
            Owner           = $owner
        }
    })
    return $rows
}

function Get-ConnectionsSection {
    $conns = Get-NetTCPConnection -ErrorAction Stop
    $rows = @($conns | ForEach-Object {
        $procName = ''
        try {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction Stop
            $procName = $proc.ProcessName
        }
        catch {
            $procName = ''
        }
        $localAddr = ConvertTo-NullSafeString $_.LocalAddress
        $remoteAddr = ConvertTo-NullSafeString $_.RemoteAddress
        [PSCustomObject]@{
            Key               = "$localAddr`:$($_.LocalPort)|$remoteAddr`:$($_.RemotePort)|$($_.State)|$($_.OwningProcess)"
            LocalAddress      = $localAddr
            LocalPort         = $_.LocalPort
            RemoteAddress     = $remoteAddr
            RemotePort        = $_.RemotePort
            State             = [string]$_.State
            OwningProcessId   = $_.OwningProcess
            OwningProcessName = $procName
            IsListening       = ($_.State -eq 'Listen')
        }
    })
    return $rows
}

function Get-InstalledProgramsSection {
    $rows = [System.Collections.Generic.List[object]]::new()

    $roots = @(
        @{ Hint = 'HKLM64'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
        @{ Hint = 'HKLM32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
        @{ Hint = 'HKCU';   Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
    )

    foreach ($root in $roots) {
        try {
            if (-not (Test-Path -LiteralPath $root.Path)) { continue }
            $subKeys = Get-ChildItem -LiteralPath $root.Path -ErrorAction Stop
            foreach ($sk in $subKeys) {
                try {
                    $props = Get-ItemProperty -LiteralPath $sk.PSPath -ErrorAction Stop
                    $displayName = ConvertTo-NullSafeString $props.DisplayName
                    if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
                    $subKeyName = Split-Path -Leaf $sk.PSPath
                    $rows.Add([PSCustomObject]@{
                        Key             = "$($root.Hint)|$subKeyName"
                        Root            = $root.Hint
                        SubKeyName      = $subKeyName
                        DisplayName     = $displayName
                        DisplayVersion  = ConvertTo-NullSafeString $props.DisplayVersion
                        Publisher       = ConvertTo-NullSafeString $props.Publisher
                        InstallDate     = ConvertTo-NullSafeString $props.InstallDate
                        InstallLocation = ConvertTo-NullSafeString $props.InstallLocation
                        UninstallString = ConvertTo-NullSafeString $props.UninstallString
                    })
                }
                catch {
                    throw
                }
            }
        }
        catch {
            throw
        }
    }

    return $rows.ToArray()
}

function Get-LocalAccountsSection {
    $rows = [System.Collections.Generic.List[object]]::new()

    $adminMembers = @{}
    try {
        $members = Get-CimInstance -ClassName Win32_GroupUser -ErrorAction Stop | Where-Object {
            $_.GroupComponent -match 'Name="Administrators"'
        }
        foreach ($m in $members) {
            if ($m.PartComponent -match 'Name="([^"]+)"') {
                $adminMembers[$Matches[1]] = $true
            }
        }
    }
    catch {
        try {
            $netOut = & net localgroup Administrators 2>$null
            $inList = $false
            foreach ($line in $netOut) {
                if ($line -match '^-+$') { $inList = $true; continue }
                if ($inList) {
                    $t = $line.Trim()
                    if ([string]::IsNullOrWhiteSpace($t)) { continue }
                    if ($t -match '^The command completed') { continue }
                    $adminMembers[$t] = $true
                }
            }
        }
        catch {
            Add-CollectionError -ErrorList $script:CollectionErrors -Section 'LocalAccounts' -ErrorText "Administrators group lookup: $($_.Exception.Message)"
        }
    }

    $accounts = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop
    foreach ($a in $accounts) {
        $isAdmin = $false
        if ($adminMembers.ContainsKey($a.Name)) { $isAdmin = $true }
        if ($adminMembers.ContainsKey("$($a.Domain)\$($a.Name)")) { $isAdmin = $true }
        $rows.Add([PSCustomObject]@{
            Key              = $a.SID
            SID              = $a.SID
            Name             = $a.Name
            FullName         = ConvertTo-NullSafeString $a.FullName
            Disabled         = $a.Disabled
            Lockout          = $a.Lockout
            PasswordRequired = $a.PasswordRequired
            IsLocalAdmin     = $isAdmin
        })
    }

    return $rows.ToArray()
}

function Get-FirewallRulesSection {
    $rules = Get-NetFirewallRule -ErrorAction Stop | Where-Object {
        $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq $true
    }

    $appByInstance = @{}
    $portByInstance = @{}
    try {
        foreach ($f in @(Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) {
            if ($f.InstanceID) { $appByInstance[[string]$f.InstanceID] = $f }
        }
    }
    catch { }
    try {
        foreach ($f in @(Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) {
            if ($f.InstanceID) { $portByInstance[[string]$f.InstanceID] = $f }
        }
    }
    catch { }

    $rows = @($rules | ForEach-Object {
        $appPath = ''
        $ports = ''
        $key = [string]$_.Name
        if ($appByInstance.ContainsKey($key)) {
            $appPath = ConvertTo-NullSafeString $appByInstance[$key].Program
        }
        if ($portByInstance.ContainsKey($key)) {
            $pf = $portByInstance[$key]
            $ports = "$($pf.Protocol):$($pf.LocalPort)"
        }
        [PSCustomObject]@{
            Key         = $_.Name
            Name        = $_.Name
            DisplayName = $_.DisplayName
            Profile     = [string]$_.Profile
            Program     = $appPath
            Ports       = $ports
        }
    })
    return $rows
}

function Get-WmiPersistenceSection {
    $rows = [System.Collections.Generic.List[object]]::new()

    try {
        $filters = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop
        foreach ($f in $filters) {
            $rows.Add([PSCustomObject]@{
                Key            = "root\subscription|__EventFilter|$($f.Name)"
                ClassType      = '__EventFilter'
                Namespace      = 'root\subscription'
                Name           = $f.Name
                Query          = ConvertTo-NullSafeString $f.Query
                QueryLanguage  = ConvertTo-NullSafeString $f.QueryLanguage
            })
        }
    }
    catch {
        throw
    }

    try {
        $consumers = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop
        foreach ($c in $consumers) {
            $className = $c.CimClass.CimClassName
            $detail = ''
            try {
                if ($c.PSObject.Properties.Match('CommandLineTemplate').Count -gt 0) {
                    $detail = ConvertTo-NullSafeString $c.CommandLineTemplate
                }
                elseif ($c.PSObject.Properties.Match('ScriptText').Count -gt 0) {
                    $detail = ConvertTo-NullSafeString $c.ScriptText
                }
                elseif ($c.PSObject.Properties.Match('Destination').Count -gt 0) {
                    $detail = ConvertTo-NullSafeString $c.Destination
                }
            }
            catch { }
            $rows.Add([PSCustomObject]@{
                Key       = "root\subscription|$className|$($c.Name)"
                ClassType = $className
                Namespace = 'root\subscription'
                Name      = $c.Name
                Detail    = $detail
            })
        }
    }
    catch {
        throw
    }

    try {
        $bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop
        foreach ($b in $bindings) {
            $filterRef = ConvertTo-NullSafeString $b.Filter
            $consumerRef = ConvertTo-NullSafeString $b.Consumer
            $rows.Add([PSCustomObject]@{
                Key       = "root\subscription|Binding|$filterRef->$consumerRef"
                ClassType = '__FilterToConsumerBinding'
                Namespace = 'root\subscription'
                Filter    = $filterRef
                Consumer  = $consumerRef
            })
        }
    }
    catch {
        throw
    }

    return $rows.ToArray()
}

function Get-RecentFilesSection {
    param([int]$WindowDays, [int]$CapCount = 500,
          [int]$MaxDirs = 40000, [int]$TimeBudgetSeconds = 120)

    $rows = [System.Collections.Generic.List[object]]::new()
    if ($WindowDays -le 0) {
        return [PSCustomObject]@{ Items = [object[]]$rows.ToArray(); CapHit = $false }
    }

    $cutoffUtc = ([datetime]::UtcNow).ToUniversalTime().AddDays(-1 * $WindowDays)
    $extensions = @('.exe', '.dll', '.msi', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.scr', '.lnk')

    $roots = [System.Collections.Generic.List[string]]::new()
    if ($env:TEMP) { $roots.Add($env:TEMP) }
    if ($env:WINDIR) { $roots.Add(([System.IO.Path]::Combine($env:WINDIR, 'Temp'))) }
    if ($env:APPDATA) { $roots.Add($env:APPDATA) }
    if ($env:LOCALAPPDATA) { $roots.Add($env:LOCALAPPDATA) }
    if ($env:USERPROFILE) { $roots.Add(([System.IO.Path]::Combine($env:USERPROFILE, 'Downloads'))) }
    if ($env:PUBLIC) { $roots.Add($env:PUBLIC) }
    if ($env:ProgramData) { $roots.Add($env:ProgramData) }

    $maxDepth = 6
    $capHit = $false

    $skipDirNames = @(
        'node_modules', '.git', '.svn', '.hg', '__pycache__', '.venv', 'venv',
        'winsxs', 'servicing', 'installer', 'assembly', 'driverstore',
        'packages', 'package_cache', 'nuget', 'npm-cache', '_npx', 'yarn',
        'pip', 'cache', 'cache2', 'caches', 'code cache', 'gpucache',
        'service worker', 'crashpad', 'cypress', 'chocolatey'
    )

    $dirsVisited = 0
    $walkWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $budgetHit = $false

    foreach ($root in $roots) {
        if ($rows.Count -ge $CapCount) { $capHit = $true; break }
        if ($budgetHit) { break }
        if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }

        try {
            $rootDepth = ($root.TrimEnd('\') -split '\\').Count
            $stack = [System.Collections.Generic.Stack[string]]::new()
            $stack.Push($root)

            while ($stack.Count -gt 0) {
                if ($rows.Count -ge $CapCount) { $capHit = $true; break }
                if ($dirsVisited -ge $MaxDirs -or $walkWatch.Elapsed.TotalSeconds -ge $TimeBudgetSeconds) {
                    $budgetHit = $true
                    $capHit = $true
                    break
                }
                $dir = $stack.Pop()
                $dirsVisited++

                $dirDepth = ($dir.TrimEnd('\') -split '\\').Count
                if (($dirDepth - $rootDepth) -ge $maxDepth) { continue }

                $children = $null
                try {
                    $children = Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop
                }
                catch {
                    continue
                }

                foreach ($child in $children) {
                    if ($rows.Count -ge $CapCount) { $capHit = $true; break }
                    if ($child.PSIsContainer) {
                        if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                        if ($skipDirNames -contains $child.Name.ToLowerInvariant()) { continue }
                        $stack.Push($child.FullName)
                        continue
                    }
                    $ext = [System.IO.Path]::GetExtension($child.Name).ToLowerInvariant()
                    if (-not ($extensions -contains $ext)) { continue }
                    try {
                        if ($child.CreationTimeUtc -ge $cutoffUtc) {
                            $rows.Add([PSCustomObject]@{
                                Key            = $child.FullName
                                Path           = $child.FullName
                                Extension      = $ext
                                CreatedUtc     = $child.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                                LastWriteUtc   = $child.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                                LengthBytes    = $child.Length
                            })
                        }
                    }
                    catch { }
                }
                if ($capHit) { break }
            }
        }
        catch {
            Add-CollectionError -ErrorList $script:CollectionErrors -Section 'RecentFiles' -ErrorText "Walking $root : $($_.Exception.Message)"
        }
        if ($capHit) { break }
    }

    $walkWatch.Stop()
    if ($budgetHit) {
        $walkSecs = [int]$walkWatch.Elapsed.TotalSeconds
        Add-CollectionError -ErrorList $script:CollectionErrors -Section 'RecentFiles' -ErrorText "Walk budget exhausted after $dirsVisited directories / ${walkSecs}s; results are partial."
    }

    return [PSCustomObject]@{
        Items          = [object[]]$rows.ToArray()
        CapHit         = $capHit
        DirsVisited    = $dirsVisited
        WalkSeconds    = [math]::Round($walkWatch.Elapsed.TotalSeconds, 1)
        BudgetExhausted = $budgetHit
    }
}

function Get-RdpEnabled {
    $val = Get-RegValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($null -eq $val) { return $null }
    return ($val -eq 0)
}

function Get-HostsFileLines {
    $hostsPath = ''
    if ($env:WINDIR) {
        $hostsPath = [System.IO.Path]::Combine($env:WINDIR, 'System32\drivers\etc\hosts')
    }
    elseif ($env:SystemRoot) {
        $hostsPath = [System.IO.Path]::Combine($env:SystemRoot, 'System32\drivers\etc\hosts')
    }
    if (-not $hostsPath -or -not (Test-Path -LiteralPath $hostsPath)) { return @() }
    $lines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop
    return @($lines | ForEach-Object { [string]$_ })
}

function Get-SystemSettingsSection {
    $rdpEnabled = $null
    try {
        $rdpEnabled = Get-RdpEnabled
    }
    catch {
        Add-CollectionError -ErrorList $script:CollectionErrors -Section 'SystemSettings' -ErrorText "RDP state: $($_.Exception.Message)"
    }

    $hostsLines = @()
    try {
        $hostsLines = Get-HostsFileLines
    }
    catch {
        Add-CollectionError -ErrorList $script:CollectionErrors -Section 'SystemSettings' -ErrorText "Hosts file: $($_.Exception.Message)"
    }

    return [ordered]@{
        RdpEnabled     = $rdpEnabled
        HostsFileLines = @($hostsLines)
    }
}

function Get-ScInstallationsSection {
    # Try to import Scc.Detection to get compact ScreenConnect installation list
    try {
        $det = Import-Module -Name 'Scc.Detection' -ErrorAction Stop -PassThru
        if ($det) {
            $instances = & Scc\Get-SccScreenConnect -ErrorAction Stop
            $compact = @($instances | ForEach-Object {
                [PSCustomObject]@{
                    Key          = $_.ServiceName
                    ServiceName  = $_.ServiceName
                    RelayHost    = $_.RelayHost
                    SessionType  = $_.SessionType
                    InstallPath  = $_.InstallPath
                    ServiceState = $_.ServiceState
                    Confidence   = $_.Confidence
                    TrustMatch   = $_.TrustMatch
                }
            })
            return $compact
        }
    }
    catch {
        # Scc.Detection not importable - skip section
    }
    return @()
}

# ---------------------------------------------------------------------------
# Private: Runspace pool for concurrent section collection (Windows only)
# ---------------------------------------------------------------------------

$script:MaxRunspaces = 4

function Invoke-SectionParallel {
    [CmdletBinding()]
    param(
        [hashtable]$SectionMap,
        [System.Collections.Generic.List[object]]$ErrorList
    )

    if (-not ($env:OS -eq 'Windows_NT')) {
        # On Linux, run inline
        $results = @{}
        foreach ($name in $SectionMap.Keys) {
            $results[$name] = Invoke-Section -Name $name -ScriptBlock $SectionMap[$name] -ErrorList $ErrorList
        }
        return $results
    }

    # Windows: run via runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $script:MaxRunspaces)
    $runspacePool.Open()

    $jobs = @{}
    foreach ($name in $SectionMap.Keys) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $runspacePool
        [void]$ps.AddScript({
            param($sb)
            & $sb
        })
        [void]$ps.AddArgument($SectionMap[$name])
        $jobs[$name] = $ps.BeginInvoke()
    }

    $results = @{}
    foreach ($name in $SectionMap.Keys) {
        try {
            $result = $jobs[$name].EndInvoke()
            if ($null -eq $result) { $result = @() }
            $results[$name] = @($result)
        }
        catch {
            Add-CollectionError -ErrorList $ErrorList -Section $name -ErrorText $_.Exception.Message
            $results[$name] = @()
        }
        finally {
            $jobs[$name].Dispose()
        }
    }

    $runspacePool.Close()
    $runspacePool.Dispose()

    return $results
}

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function New-SccSnapshot {
    <#
    .SYNOPSIS
        Collects a read-only machine snapshot for the investigation run.
    .DESCRIPTION
        Captures persistence and execution surface in a diffable JSON form.
        Read-only: never modifies system state. Schema v2.
    .PARAMETER Run
        Run object (must have RunDir property) or path string.
    .PARAMETER Label
        Snapshot label: 'before' or 'after'.
    .PARAMETER IncidentWindowDays
        Incident window for recent-files sweep (0 = skip).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Run,
        [Parameter(Mandatory = $true)]
        [ValidateSet('before', 'after')]
        [string]$Label,
        [int]$IncidentWindowDays = 0
    )

    $ErrorActionPreference = 'Stop'
    $script:CollectionErrors = [System.Collections.Generic.List[object]]::new()

    $startTime = [datetime]::UtcNow
    $isWindows = ($env:OS -eq 'Windows_NT')
    $isAdmin = $false
    $osCaption = ''

    # Resolve run directory
    $runDir = $null
    if ($Run -is [string]) {
        $runDir = $Run
    }
    elseif ($Run.PSObject.Properties['RunDir']) {
        $runDir = $Run.RunDir
    }
    else {
        throw 'Run object must have a RunDir property or be a string path.'
    }

    $snapshotsDir = [System.IO.Path]::Combine($runDir, 'snapshots')
    if (-not (Test-Path -LiteralPath $snapshotsDir)) {
        New-Item -ItemType Directory -Path $snapshotsDir -Force | Out-Null
    }

    # System info
    if ($isWindows) {
        $isAdmin = Test-IsAdmin
        $osCaption = Get-Win32OsCaption
    }
    else {
        $osCaption = 'non-Windows'
    }

    # Collect sections - independent sections may run in parallel on Windows
    $sectionCollectors = [ordered]@{
        Services         = { Get-ServicesSection }
        ScheduledTasks   = { Get-ScheduledTasksSection }
        RegistryAutoruns = { Get-RegistryAutorunsSection }
        StartupFolders   = { Get-StartupFoldersSection }
        Processes        = { Get-ProcessesSection }
        Connections      = { Get-ConnectionsSection }
        InstalledPrograms = { Get-InstalledProgramsSection }
        LocalAccounts    = { Get-LocalAccountsSection }
        FirewallRules    = { Get-FirewallRulesSection }
        WmiPersistence   = { Get-WmiPersistenceSection }
    }

    $sectionResults = Invoke-SectionParallel -SectionMap $sectionCollectors -ErrorList $script:CollectionErrors

    # Sort each collected section by Key
    $services         = Sort-ByKey $sectionResults['Services']
    $scheduledTasks   = Sort-ByKey $sectionResults['ScheduledTasks']
    $registryAutoruns = Sort-ByKey $sectionResults['RegistryAutoruns']
    $startupFolders   = Sort-ByKey $sectionResults['StartupFolders']
    $processes        = Sort-ByKey $sectionResults['Processes']
    $connections      = Sort-ByKey $sectionResults['Connections']
    $installedPrograms = Sort-ByKey $sectionResults['InstalledPrograms']
    $localAccounts    = Sort-ByKey $sectionResults['LocalAccounts']
    $firewallRules    = Sort-ByKey $sectionResults['FirewallRules']
    $wmiPersistence   = Sort-ByKey $sectionResults['WmiPersistence']

    # RecentFiles (incident window sweep)
    $recentFiles = @()
    $recentFilesCapHit = $false
    if ($IncidentWindowDays -gt 0) {
        try {
            $rf = Get-RecentFilesSection -WindowDays $IncidentWindowDays -CapCount 500
            $recentFiles = Sort-ByKey $rf.Items
            $recentFilesCapHit = $rf.CapHit
        }
        catch {
            $errLoc = ''
            if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) {
                $errLoc = ' @ line ' + $_.InvocationInfo.ScriptLineNumber
            }
            Add-CollectionError -ErrorList $script:CollectionErrors -Section 'RecentFiles' -ErrorText ($_.Exception.Message + $errLoc)
        }
    }

    # SystemSettings
    $systemSettings = Get-SystemSettingsSection

    # ScInstallations (best-effort from Scc.Detection)
    $scInstallations = @()
    try {
        $scInstallations = Get-ScInstallationsSection
    }
    catch {
        Add-CollectionError -ErrorList $script:CollectionErrors -Section 'ScInstallations' -ErrorText $_.Exception.Message
    }

    # Determine SccAppVersion
    $sccAppVersion = ''
    try {
        $mod = Get-Module -Name 'Scc.Evidence' -ErrorAction SilentlyContinue
        if ($mod -and $mod.Version) {
            $sccAppVersion = $mod.Version.ToString()
        }
    }
    catch { }

    # Build result (schema v2)
    $result = [ordered]@{
        SchemaVersion      = 2
        Label              = $Label
        ComputerName       = Get-HostNameSafe
        CollectedUtc       = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        IsAdmin            = $isAdmin
        OSCaption          = $osCaption
        IncidentWindowDays = $IncidentWindowDays
        SccAppVersion      = $sccAppVersion
        CollectionErrors   = @($script:CollectionErrors.ToArray())
        Sections           = [ordered]@{
            Services         = @($services)
            ScheduledTasks   = @($scheduledTasks)
            RegistryAutoruns = @($registryAutoruns)
            StartupFolders   = @($startupFolders)
            Processes        = @($processes)
            Connections      = @($connections)
            InstalledPrograms = @($installedPrograms)
            LocalAccounts    = @($localAccounts)
            FirewallRules    = @($firewallRules)
            WmiPersistence   = @($wmiPersistence)
            RecentFiles      = @($recentFiles)
            RecentFilesCapHit = $recentFilesCapHit
            ScInstallations  = @($scInstallations)
            SystemSettings   = $systemSettings
        }
    }

    # Serialize
    $outFile = [System.IO.Path]::Combine($snapshotsDir, "$Label.json")
    $json = $result | ConvertTo-Json -Depth 6
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($outFile, $json, $utf8NoBom)

    $elapsed = ([datetime]::UtcNow) - $startTime
    Write-Verbose ("Snapshot collected in {0:N1}s (Label={1}, CollectionErrors={2})" -f $elapsed.TotalSeconds, $Label, $script:CollectionErrors.Count)

    return $result
}

function Get-SccSnapshot {
    <#
    .SYNOPSIS
        Reads a previously collected snapshot from disk.
    .PARAMETER Run
        Run object (must have RunDir property) or path string.
    .PARAMETER Label
        Snapshot label: 'before' or 'after'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Run,
        [Parameter(Mandatory = $true)]
        [ValidateSet('before', 'after')]
        [string]$Label
    )

    $runDir = $null
    if ($Run -is [string]) {
        $runDir = $Run
    }
    elseif ($Run.PSObject.Properties['RunDir']) {
        $runDir = $Run.RunDir
    }
    else {
        throw 'Run object must have a RunDir property or be a string path.'
    }

    $snapshotsDir = [System.IO.Path]::Combine($runDir, 'snapshots')
    $outFile = [System.IO.Path]::Combine($snapshotsDir, "$Label.json")

    if (-not (Test-Path -LiteralPath $outFile)) {
        throw "Snapshot not found: $outFile"
    }

    $json = Get-Content -LiteralPath $outFile -Raw
    return ($json | ConvertFrom-Json)
}
