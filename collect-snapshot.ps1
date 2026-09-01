<#
  collect-snapshot.ps1  -  Stage 1 of the ScreenConnect Cleanup Tool pipeline

  READ-ONLY system snapshot collector. Captures the machine's persistence and
  execution surface in a stable, diffable JSON form. Run it once BEFORE any
  removal work and once AFTER, then diff the two files to prove what actually
  changed (and to catch anything that re-installs itself).

  This script writes its own output file and, for the Amcache section only, may
  temporarily mount the Windows Amcache hive under HKLM:\Amcache when running
  elevated. The mount is always attempted in a finally block and unload failure
  is recorded. All other collection paths are read-only and no Set-, Stop-,
  Remove-, Start-, or New- (system state) cmdlets are used against the machine.

  Requires Windows PowerShell 5.1+. Admin is NOT required - every section is
  individually wrapped so a failure there is recorded in CollectionErrors and
  the rest of the run continues; intentional limitations/absent optional artifacts
  are recorded in CollectionWarnings. Some sections (notably per-process owner,
  some registry hives, some services) return less detail without admin.

  --------------------------------------------------------------------------
  KEY SCHEME (how each section's "Key" is chosen - must be stable across a
  before/after run so a diff tool can match items by Key alone; volatile
  data like PID, timestamps, current state live in the fields, NOT the key):

    Services         : service Name (unique on a machine, survives restarts)
    ScheduledTasks   : TaskPath + "|" + TaskName (the pair Task Scheduler
                       itself treats as the unique identity)
    RegistryAutoruns : Hive + "|" + KeyPath + "|" + ValueName (identifies one
                       named value in one key; the run-key mechanism itself)
    StartupFolders   : the folder Scope ("AllUsers"/"CurrentUser") + "|" +
                       the file name (path itself is stable per machine/user,
                       but we key on scope+name so a rename shows as a real
                       diff instead of silently vanishing/appearing)
    Processes        : NOT diffable by identity across runs (PIDs are
                       reissued) - keyed on ExecutablePath + "|" + PID so the
                       item is still unique WITHIN one snapshot; a diff tool
                       should treat this whole section as a point-in-time
                       list, not an identity-matched one
    Connections      : LocalAddress+Port + "|" + RemoteAddress+Port + "|" +
                       State + "|" + PID - same caveat as Processes, this
                       section is inherently volatile and point-in-time
    InstalledPrograms: registry root hint + "|" + the uninstall subkey name
                       (that subkey name is usually the product/upgrade code
                       or a stable slug - it is the identity Windows itself
                       uses for the entry)
    LocalAccounts    : SID (survives rename; a rename is then a visible diff
                       on the Name field under a stable Key)
    FirewallRules    : rule Name (firewall rule names are the identity
                       Windows Firewall itself keys on; not guaranteed
                       unique in theory but is in practice for allow rules)
    WmiPersistence   : Namespace + "|" + object class + "|" + object Name
                       (FilterToConsumerBinding has no single Name, so it is
                       keyed on Namespace + "|Binding|" + Filter + "->" +
                       Consumer)
    RecentFiles      : full file Path (the artifact's identity is where it
                       sits; if it's deleted and a same-named one reappears
                       elsewhere that is legitimately a different item)
    Prefetch         : the .pf file name (includes Windows' own trace hash;
                       a same-binary different-arguments run is a distinct
                       artifact by Windows' own bookkeeping)
    ShimCache        : lower-cased cached path (the identity ShimCache
                       itself stores; case-folded so a diff is not fooled
                       by casing noise from our own decoder)
    BamDam           : service ("bam"/"dam") + "|" + SID + "|" + value name
    UserAssist       : GUID + "|" + ROT13-decoded program/shortcut name
    Srum             : NOT an identity-diffed array - a single object with
                       DB inventory + SHA-256 + offline-copy status. Diff on
                       DatabaseSha256 (changed = new activity was recorded).

  Output schema is documented in the project brief; see $result below for the
  authoritative shape actually emitted.
#>

param(
    [string]$OutFile,
    [string]$Label = 'before',
    [int]$IncidentWindowDays = 0,
    [string]$Section = '',      # internal: collect ONE section and exit (manual / single-section jobs)
    [string]$Sections = '',     # internal: collect a comma-separated GROUP of sections and exit (v1.7.16 group jobs)
    [switch]$NoParallel,        # collect everything sequentially (no background jobs)
    [int]$ParallelTimeoutSeconds = 300,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
# SchemaVersion 2: added Sections Prefetch, ShimCache, BamDam, UserAssist, Srum
# and Amcache (retrospective execution artifacts). Consumers diffing v1 files
# against v2 should treat missing sections in a v1 file as empty.
$SchemaVersion = 2

# Resolve hostname in a cross-platform-safe way: Windows sets COMPUTERNAME;
# on Linux/other hosts fall back to the system hostname (PowerShell 7+).
function Get-HostNameSafe {
    $h = $env:COMPUTERNAME
    if (-not [string]::IsNullOrWhiteSpace($h)) { return $h }
    $h = $env:HOSTNAME
    if (-not [string]::IsNullOrWhiteSpace($h)) { return $h }
    try {
        $h = [System.Net.Dns]::GetHostName()
        if (-not [string]::IsNullOrWhiteSpace($h)) { return $h }
    } catch { }
    return 'unknown'
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

$script:CollectionErrors = New-Object System.Collections.Generic.List[object]
$script:CollectionWarnings = New-Object System.Collections.Generic.List[object]
$script:CollectionIncomplete = $false

function Get-CollectionErrorsArray {
    $arr = New-Object object[] $script:CollectionErrors.Count
    $script:CollectionErrors.CopyTo($arr, 0)
    return $arr
}

function Get-CollectionWarningsArray {
    $arr = New-Object object[] $script:CollectionWarnings.Count
    $script:CollectionWarnings.CopyTo($arr, 0)
    return $arr
}

function Write-Info {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Host $Message
    }
}

function Add-CollectionError {
    param([string]$Section, [string]$ErrorText)
    $script:CollectionIncomplete = $true
    $script:CollectionErrors.Add([PSCustomObject]@{
        Section = $Section
        Error   = $ErrorText
    })
}

function Add-CollectionWarning {
    param([string]$Section, [string]$WarningText)
    $script:CollectionWarnings.Add([PSCustomObject]@{
        Section = $Section
        Warning = $WarningText
    })
}

function Invoke-Section {
    # Runs $ScriptBlock, catches any failure, records it under $Name, and
    # always returns an array (never $null) so ConvertTo-Json emits [].
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock
    )
    try {
        $out = & $ScriptBlock
        if ($null -eq $out) { return , @() }
        return @($out)
    } catch {
        Add-CollectionError -Section $Name -ErrorText $_.Exception.Message
        return , @()
    }
}

function Sort-ByKey {
    # Deliberately untyped: binding an EMPTY generic List to an [object[]]
    # parameter throws "Argument types do not match" in Windows PowerShell 5.1.
    param($Items)
    if (-not $Items -or $Items.Count -eq 0) { return , @() }
    return @($Items | Sort-Object -Property Key)
}

function Test-IsAdmin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
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
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------
function Get-ServicesSection {
    $wmiSvcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    $rows = foreach ($s in $wmiSvcs) {
        [PSCustomObject]@{
            Key         = $s.Name
            Name        = $s.Name
            DisplayName = $s.DisplayName
            PathName    = $s.PathName
            State       = $s.State
            StartMode   = $s.StartMode
            StartName   = $s.StartName
        }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------
function Get-ScheduledTasksSection {
    $tasks = Get-ScheduledTask -ErrorAction Stop
    $rows = foreach ($t in $tasks) {
        $actions = @()
        foreach ($a in $t.Actions) {
            $exec = ConvertTo-NullSafeString $a.Execute
            $args = ConvertTo-NullSafeString $a.Arguments
            $actions += [PSCustomObject]@{
                Execute   = $exec
                Arguments = $args
            }
        }
        $author = ''
        try { $author = ConvertTo-NullSafeString $t.Author } catch { $author = '' }
        [PSCustomObject]@{
            Key      = "$($t.TaskPath)|$($t.TaskName)"
            TaskName = $t.TaskName
            TaskPath = $t.TaskPath
            State    = [string]$t.State
            Author   = $author
            Actions  = @($actions)
        }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# Registry autoruns (Run/RunOnce, Winlogon Shell/Userinit)
# ---------------------------------------------------------------------------
function Get-RegistryAutorunsSection {
    $rows = New-Object System.Collections.Generic.List[object]

    # Run/RunOnce keys across hive x view(32/64) combinations.
    # PowerShell registry provider paths for the two views: the 64-bit view
    # is the normal path; the 32-bit (WOW6432Node) view is reached under
    # HKLM:\SOFTWARE\WOW6432Node for HKLM. HKCU has no separate WOW6432Node
    # on-disk split the way HKLM does, but we still enumerate the standard
    # HKCU Run/RunOnce paths.
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
        } catch {
            Add-CollectionError -Section 'RegistryAutoruns' -ErrorText "Reading $($spec.Path): $($_.Exception.Message)"
        }
    }

    # Winlogon Shell / Userinit - both on HKLM (the 64-bit view; Winlogon is
    # not typically redirected to WOW6432Node in a meaningful way for this
    # purpose) and check for a per-user override under HKCU as well since
    # some tooling/malware sets one there.
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
        } catch {
            Add-CollectionError -Section 'RegistryAutoruns' -ErrorText "Reading $($spec.Path): $($_.Exception.Message)"
        }
    }

    return $rows
}

# ---------------------------------------------------------------------------
# Startup folders (per-user and all-users)
# ---------------------------------------------------------------------------
function Get-StartupFoldersSection {
    $rows = New-Object System.Collections.Generic.List[object]

    $allUsersStartup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
    $currentUserStartup = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'

    $folderSpecs = @(
        @{ Scope = 'AllUsers'; Path = $allUsersStartup }
        @{ Scope = 'CurrentUser'; Path = $currentUserStartup }
    )

    foreach ($spec in $folderSpecs) {
        try {
            if (Test-Path -LiteralPath $spec.Path) {
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
        } catch {
            Add-CollectionError -Section 'StartupFolders' -ErrorText "Reading $($spec.Path): $($_.Exception.Message)"
        }
    }

    return $rows
}

# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------
function Get-ProcessesSection {
    $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    $rows = foreach ($p in $procs) {
        $owner = ''
        try {
            $ownerInfo = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($ownerInfo -and $ownerInfo.ReturnValue -eq 0) {
                if ($ownerInfo.Domain) {
                    $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                } else {
                    $owner = ConvertTo-NullSafeString $ownerInfo.User
                }
            }
        } catch {
            $owner = ''
        }

        $created = ''
        try {
            if ($p.CreationDate) {
                $created = $p.CreationDate.ToString('yyyy-MM-dd HH:mm:ss')
            }
        } catch { $created = '' }

        [PSCustomObject]@{
            Key             = "$($p.ExecutablePath)|$($p.ProcessId)"
            ProcessId       = $p.ProcessId
            ParentProcessId = $p.ParentProcessId
            Name            = $p.Name
            ExecutablePath  = ConvertTo-NullSafeString $p.ExecutablePath
            CommandLine     = ConvertTo-NullSafeString $p.CommandLine
            CreationDate    = $created
            Owner           = $owner
        }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# Network - active TCP connections + listening ports
# ---------------------------------------------------------------------------
function Get-ConnectionsSection {
    $conns = Get-NetTCPConnection -ErrorAction Stop
    $rows = foreach ($c in $conns) {
        $procName = ''
        try {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction Stop
            $procName = $proc.ProcessName
        } catch {
            $procName = ''
        }
        $localAddr = ConvertTo-NullSafeString $c.LocalAddress
        $remoteAddr = ConvertTo-NullSafeString $c.RemoteAddress
        [PSCustomObject]@{
            Key             = "$localAddr`:$($c.LocalPort)|$remoteAddr`:$($c.RemotePort)|$($c.State)|$($c.OwningProcess)"
            LocalAddress    = $localAddr
            LocalPort       = $c.LocalPort
            RemoteAddress   = $remoteAddr
            RemotePort      = $c.RemotePort
            State           = [string]$c.State
            OwningProcessId = $c.OwningProcess
            OwningProcessName = $procName
            IsListening     = ($c.State -eq 'Listen')
        }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# Installed programs - all three Uninstall roots
# ---------------------------------------------------------------------------
function Get-InstalledProgramsSection {
    $rows = New-Object System.Collections.Generic.List[object]

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
                } catch {
                    Add-CollectionError -Section 'InstalledPrograms' -ErrorText "Reading $($sk.PSPath): $($_.Exception.Message)"
                }
            }
        } catch {
            Add-CollectionError -Section 'InstalledPrograms' -ErrorText "Reading $($root.Path): $($_.Exception.Message)"
        }
    }

    return $rows
}

# ---------------------------------------------------------------------------
# Local accounts + local Administrators group membership
# ---------------------------------------------------------------------------
function Get-LocalAccountsSection {
    $rows = New-Object System.Collections.Generic.List[object]

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
    } catch {
        # Fall back to net localgroup parsing if the CIM association query
        # is unavailable (some builds require different WMI plumbing).
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
        } catch {
            Add-CollectionError -Section 'LocalAccounts' -ErrorText "Administrators group lookup: $($_.Exception.Message)"
        }
    }

    $accounts = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop
    foreach ($a in $accounts) {
        $isAdmin = $false
        if ($adminMembers.ContainsKey($a.Name)) { $isAdmin = $true }
        if ($adminMembers.ContainsKey("$($a.Domain)\$($a.Name)")) { $isAdmin = $true }
        $rows.Add([PSCustomObject]@{
            Key         = $a.SID
            SID         = $a.SID
            Name        = $a.Name
            FullName    = ConvertTo-NullSafeString $a.FullName
            Disabled    = $a.Disabled
            Lockout     = $a.Lockout
            PasswordRequired = $a.PasswordRequired
            IsLocalAdmin = $isAdmin
        })
    }

    return $rows
}

# ---------------------------------------------------------------------------
# Firewall - enabled inbound ALLOW rules
# ---------------------------------------------------------------------------
function Get-FirewallRulesSection {
    # Server-side filtering keeps the initial CIM payload small (the old form
    # enumerated every rule and filtered client-side).
    $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop

    # Piping each rule into Get-NetFirewallApplicationFilter / -PortFilter costs
    # a separate CIM round-trip per rule: ~3+ minutes and hundreds of MB for a
    # few hundred rules. Fetching all filters once and joining on InstanceID
    # (which equals the rule's Name) is effectively instant.
    $appByInstance = @{}
    $portByInstance = @{}
    try {
        foreach ($f in @(Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) {
            if ($f.InstanceID) { $appByInstance[[string]$f.InstanceID] = $f }
        }
    } catch { }
    try {
        foreach ($f in @(Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) {
            if ($f.InstanceID) { $portByInstance[[string]$f.InstanceID] = $f }
        }
    } catch { }

    $rows = foreach ($r in $rules) {
        $appPath = ''
        $ports = ''
        $key = [string]$r.Name
        if ($appByInstance.ContainsKey($key)) {
            $appPath = ConvertTo-NullSafeString $appByInstance[$key].Program
        }
        if ($portByInstance.ContainsKey($key)) {
            $pf = $portByInstance[$key]
            $ports = "$($pf.Protocol):$($pf.LocalPort)"
        }
        [PSCustomObject]@{
            Key         = $r.Name
            Name        = $r.Name
            DisplayName = $r.DisplayName
            Profile     = [string]$r.Profile
            Program     = $appPath
            Ports       = $ports
        }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# RDP enabled state
# ---------------------------------------------------------------------------
function Get-RdpEnabled {
    $val = Get-RegValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($null -eq $val) { return $null }
    return ($val -eq 0)
}

# ---------------------------------------------------------------------------
# Hosts file
# ---------------------------------------------------------------------------
function Get-HostsFileLines {
    $hostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hostsPath)) { return @() }
    $lines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop
    # Get-Content emits strings decorated with PSPath/PSDrive/PSProvider note
    # properties. ConvertTo-Json follows PSProvider into ImplementingType,
    # Capabilities, Drives... for EVERY line - that alone turned this snapshot
    # into a 115 MB file. Flatten to plain strings.
    return @($lines | ForEach-Object { [string]$_ })
}

# ---------------------------------------------------------------------------
# WMI event-consumer persistence
# ---------------------------------------------------------------------------
function Get-WmiPersistenceSection {
    $rows = New-Object System.Collections.Generic.List[object]

    try {
        $filters = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop
        foreach ($f in $filters) {
            $rows.Add([PSCustomObject]@{
                Key       = "root\subscription|__EventFilter|$($f.Name)"
                ClassType = '__EventFilter'
                Namespace = 'root\subscription'
                Name      = $f.Name
                Query     = ConvertTo-NullSafeString $f.Query
                QueryLanguage = ConvertTo-NullSafeString $f.QueryLanguage
            })
        }
    } catch {
        Add-CollectionError -Section 'WmiPersistence' -ErrorText "__EventFilter: $($_.Exception.Message)"
    }

    try {
        $consumers = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop
        foreach ($c in $consumers) {
            $className = $c.CimClass.CimClassName
            $detail = ''
            try {
                if ($c.PSObject.Properties.Match('CommandLineTemplate').Count -gt 0) {
                    $detail = ConvertTo-NullSafeString $c.CommandLineTemplate
                } elseif ($c.PSObject.Properties.Match('ScriptText').Count -gt 0) {
                    $detail = ConvertTo-NullSafeString $c.ScriptText
                } elseif ($c.PSObject.Properties.Match('Destination').Count -gt 0) {
                    $detail = ConvertTo-NullSafeString $c.Destination
                }
            } catch { }
            $rows.Add([PSCustomObject]@{
                Key       = "root\subscription|$className|$($c.Name)"
                ClassType = $className
                Namespace = 'root\subscription'
                Name      = $c.Name
                Detail    = $detail
            })
        }
    } catch {
        Add-CollectionError -Section 'WmiPersistence' -ErrorText "__EventConsumer: $($_.Exception.Message)"
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
    } catch {
        Add-CollectionError -Section 'WmiPersistence' -ErrorText "__FilterToConsumerBinding: $($_.Exception.Message)"
    }

    return $rows
}

# ---------------------------------------------------------------------------
# Recent files (only when IncidentWindowDays > 0)
# ---------------------------------------------------------------------------
function Get-RecentFilesSection {
    # CapCount bounds the RESULTS only. On a machine with big package/tool
    # caches under %LOCALAPPDATA% / %ProgramData% (node_modules, pip, nuget,
    # browser caches) almost nothing matches $extensions, so the result cap
    # never trips and the walk runs for hours while the directory stack grows
    # to multiple GB. MaxDirs and TimeBudgetSeconds bound the WALK itself.
    param([int]$WindowDays, [int]$CapCount = 500,
          [int]$MaxDirs = 40000, [int]$TimeBudgetSeconds = 120)

    $rows = New-Object System.Collections.Generic.List[object]
    if ($WindowDays -le 0) {
        # NOTE: @($list) on an EMPTY generic List throws "Argument types do not
        # match" in Windows PowerShell 5.1 - use .ToArray() everywhere instead.
        return [PSCustomObject]@{ Items = [object[]]$rows.ToArray(); CapHit = $false }
    }

    $cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-1 * $WindowDays)
    $extensions = @('.exe', '.dll', '.msi', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.scr', '.lnk')

    $roots = New-Object System.Collections.Generic.List[string]
    # Temp
    if ($env:TEMP) { $roots.Add($env:TEMP) }
    if ($env:WINDIR) { $roots.Add((Join-Path $env:WINDIR 'Temp')) }
    # AppData (current user)
    if ($env:APPDATA) { $roots.Add($env:APPDATA) }
    if ($env:LOCALAPPDATA) { $roots.Add($env:LOCALAPPDATA) }
    # Downloads (current user)
    if ($env:USERPROFILE) { $roots.Add((Join-Path $env:USERPROFILE 'Downloads')) }
    # Public
    if ($env:PUBLIC) { $roots.Add($env:PUBLIC) }
    # ProgramData
    if ($env:ProgramData) { $roots.Add($env:ProgramData) }

    $maxDepth = 6
    $capHit = $false

    # Directory names that are pure noise for this purpose and can each hold
    # hundreds of thousands of entries.
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
        if (-not (Test-Path -LiteralPath $root)) { continue }

        try {
            $rootDepth = ($root.TrimEnd('\') -split '\\').Count
            $stack = New-Object System.Collections.Generic.Stack[string]
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
                } catch {
                    continue
                }

                foreach ($child in $children) {
                    if ($rows.Count -ge $CapCount) { $capHit = $true; break }
                    if ($child.PSIsContainer) {
                        # Skip reparse points / junctions to avoid loops.
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
                    } catch { }
                }
                if ($capHit) { break }
            }
        } catch {
            Add-CollectionError -Section 'RecentFiles' -ErrorText "Walking $root : $($_.Exception.Message)"
        }
        if ($capHit) { break }
    }

    $walkWatch.Stop()
    if ($budgetHit) {
        $walkSecs = [int]$walkWatch.Elapsed.TotalSeconds
        Add-CollectionError -Section 'RecentFiles' -ErrorText "Walk budget exhausted after $dirsVisited directories / ${walkSecs}s; results are partial."
    }

    return [PSCustomObject]@{
        Items          = [object[]]$rows.ToArray()
        CapHit         = $capHit
        DirsVisited    = $dirsVisited
        WalkSeconds    = [math]::Round($walkWatch.Elapsed.TotalSeconds, 1)
        BudgetExhausted = $budgetHit
    }
}

# ---------------------------------------------------------------------------
# Retrospective execution artifacts (Stage 1 expansion)
#
# These sections answer "what ran here BEFORE the technician arrived", which
# live process lists cannot. All reads are read-only. Where an artifact lives
# in a locked/opaque store (SRUM's ESE database), we capture what we safely
# can (inventory + hash + copy attempt) instead of pretending to parse it,
# and record the limitation in the section output.
#
# IncidentWindowDays: every timestamped row carries InIncidentWindow (bool)
# computed against the window ending now. Rows are NEVER filtered out - the
# diff keys must stay stable regardless of when the snapshot is taken; the
# flag only marks which rows matter to the incident.
# ---------------------------------------------------------------------------

function Test-InIncidentWindow {
    param([int]$WindowDays, $TimestampUtc)
    if ($WindowDays -le 0) { return $false }
    if ($null -eq $TimestampUtc) { return $false }
    try {
        $cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-1 * $WindowDays)
        return ($TimestampUtc.ToUniversalTime() -ge $cutoffUtc)
    } catch {
        return $false
    }
}

function Convert-BamFileTime {
    # BAM/DAM values are REG_BINARY. Published layouts place the last-execution
    # FILETIME at offset 0; invalid/short payloads remain undecoded.
    param($Value)
    if ($Value -isnot [byte[]] -or $Value.Length -lt 8) { return $null }
    try {
        $fileTime = [BitConverter]::ToInt64($Value, 0)
        if ($fileTime -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($fileTime)
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Prefetch - C:\Windows\Prefetch\*.pf
#
# We deliberately do NOT parse the binary .pf body (the format varies across
# Windows versions: v17/v23/v26/v30/v31, compressed and uncompressed variants).
# The file NAME already carries the executed image name, and the filesystem
# timestamps give first-seen / last-executed approximations. This keeps the
# collector version-proof. Key = file name (stable identity of the artifact).
# ---------------------------------------------------------------------------
function Get-PrefetchSection {
    param([int]$WindowDays)

    $rows = New-Object System.Collections.Generic.List[object]
    $prefetchDir = Join-Path $env:WINDIR 'Prefetch'
    if (-not (Test-Path -LiteralPath $prefetchDir)) {
        # Not an error: Prefetch is disabled on SSDs by default on some builds
        # and entirely absent on Server SKUs.
        return $rows
    }

    $files = Get-ChildItem -LiteralPath $prefetchDir -Filter '*.pf' -File -ErrorAction Stop
    foreach ($f in $files) {
        # Layout: <EXEBASENAME>-<HASH>.pf  (hash disambiguates same-binary-
        # different-arguments traces; it is part of the artifact's identity).
        $execName = ''
        if ($f.BaseName -match '^(.+)-[A-F0-9]+$') { $execName = $Matches[1].ToUpperInvariant() }
        $lastWrite = $f.LastWriteTimeUtc
        $rows.Add([PSCustomObject]@{
            Key               = $f.Name
            FileName          = $f.Name
            ExecutableName    = $execName
            FullPath          = $f.FullName
            LengthBytes       = $f.Length
            CreatedUtc        = $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            LastWriteUtc      = $lastWrite.ToString('yyyy-MM-dd HH:mm:ss')
            InIncidentWindow  = (Test-InIncidentWindow -WindowDays $WindowDays -TimestampUtc $lastWrite)
        })
    }
    return $rows
}

# ---------------------------------------------------------------------------
# ShimCache (Application Compatibility Cache)
#   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
#
# Raw REG_BINARY metadata only. Windows 8.1/10/11 AppCompatCache has multiple
# layout revisions and this collector has no cross-version fixture set yet.
# Do NOT emit decoded paths from an unvalidated layout: retain a stable hash,
# byte length, and header preview plus a CollectionWarning until the Windows
# owner supplies fixtures and a separately verified decoder.
# ---------------------------------------------------------------------------
function Get-ShimCacheSection {
    param([int]$WindowDays)

    $rows = New-Object System.Collections.Generic.List[object]
    $keyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
    if (-not (Test-Path -LiteralPath $keyPath)) {
        Add-CollectionWarning -Section 'ShimCache' -WarningText "AppCompatCache key not found: $keyPath"
        return $rows
    }
    $item = Get-Item -LiteralPath $keyPath -ErrorAction Stop
    $valueName = 'AppCompatCache'
    if ($item.Property -notcontains $valueName) {
        Add-CollectionWarning -Section 'ShimCache' -WarningText 'AppCompatCache value not present'
        return $rows
    }
    $blob = (Get-ItemProperty -LiteralPath $keyPath -Name $valueName -ErrorAction Stop).$valueName
    $blobLength = 0
    if ($null -ne $blob) { $blobLength = [int]$blob.Length }
    if ($blobLength -eq 0) {
        Add-CollectionWarning -Section 'ShimCache' -WarningText 'AppCompatCache blob is empty'
        return $rows
    }

    $rawSha256 = ''
    $headerHex = ''
    try {
        $sha = [System.Security.Cryptography.SHA256CryptoServiceProvider]::Create()
        try {
            $rawSha256 = (([System.BitConverter]::ToString($sha.ComputeHash($blob))).Replace('-', '').ToLowerInvariant())
        } finally { $sha.Dispose() }
        $previewLength = [Math]::Min(16, $blobLength)
        $headerHex = (([System.BitConverter]::ToString($blob, 0, $previewLength)).Replace('-', '').ToLowerInvariant())
    } catch {
        Add-CollectionError -Section 'ShimCache' -ErrorText ("Raw blob hashing failed: " + $_.Exception.Message)
    }

    [void]$rows.Add([PSCustomObject]@{
        Key              = '__raw__'
        DecoderStatus    = 'RawOnly'
        BlobLengthBytes  = $blobLength
        RawSha256        = $rawSha256
        HeaderHex        = $headerHex
        InIncidentWindow = $false
    })
    Add-CollectionWarning -Section 'ShimCache' -WarningText 'ShimCache path decoding disabled pending validated Windows 8.1/10/11 fixtures; raw metadata retained.'
    return $rows
}

# ---------------------------------------------------------------------------
# BAM / DAM - Background Activity Moderator / Desktop Activity Moderator
#   HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
#   HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>
#
# Each value under a per-SID key is the FULL PATH of an executable that ran;
# the REG_BINARY value data carries the last-execution FILETIME at offset 0.
# The key's last-write time is retained separately as provenance metadata (not
# substituted for execution time), read through RegQueryInfoKey. Key =
# service|SID|value-name.
# ---------------------------------------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'SCC.RegKeyTimes').Type) {
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace SCC {
    public static class RegKeyTimes {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RegQueryInfoKey(
            IntPtr hKey, System.Text.StringBuilder lpClass, IntPtr lpcchClass,
            IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen,
            IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen,
            IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor,
            out long lpftLastWriteTime);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey,
            int ulOptions, int samDesired, out IntPtr phkResult);
        [DllImport("advapi32.dll")]
        private static extern int RegCloseKey(IntPtr hKey);

        // Returns UTC DateTime of the key's last write, or null on any failure.
        public static object GetLastWriteUtc(string fullPath) {
            IntPtr root = IntPtr.Zero;
            string rest = fullPath;
            if (fullPath.StartsWith("HKEY_LOCAL_MACHINE")) {
                root = new IntPtr(unchecked((int)0x80000002)); rest = fullPath.Substring(19);
            } else if (fullPath.StartsWith("HKEY_CURRENT_USER")) {
                root = new IntPtr(unchecked((int)0x80000001)); rest = fullPath.Substring(18);
            } else { return null; }
            IntPtr hk = IntPtr.Zero;
            long ft;
            try {
                if (RegOpenKeyEx(root, rest.TrimStart('\\'), 0, 0x20019, out hk) != 0) return null;
                if (RegQueryInfoKey(hk, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, out ft) != 0) return null;
                return DateTime.FromFileTimeUtc(ft);
            } catch { return null; }
            finally { if (hk != IntPtr.Zero) { RegCloseKey(hk); } }
        }
    }
}
"@ -ErrorAction Stop
    } catch {
        # P/Invoke unavailable (non-Windows / policy): timestamps degrade to blank.
    }
}

function Get-BamDamSection {
    param([int]$WindowDays)

    $rows = New-Object System.Collections.Generic.List[object]
    $specs = @(
        @{ Service = 'bam'; Root = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' },
        @{ Service = 'dam'; Root = 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings' }
    )
    foreach ($spec in $specs) {
        if (-not (Test-Path -LiteralPath $spec.Root)) { continue }
        $sidKeys = Get-ChildItem -LiteralPath $spec.Root -ErrorAction Stop
        foreach ($sk in $sidKeys) {
            $keyLastWrite = $null
            try {
                if ($null -ne ([System.Management.Automation.PSTypeName]'SCC.RegKeyTimes').Type) {
                    # RegQueryInfoKey requires a native hive name, not the
                    # provider-qualified HKLM:\ path or only the SID leaf.
                    $nativeRoot = if ($spec.Root -like 'HKLM:*') {
                        'HKEY_LOCAL_MACHINE' + $spec.Root.Substring(5)
                    } elseif ($spec.Root -like 'HKCU:*') {
                        'HKEY_CURRENT_USER' + $spec.Root.Substring(5)
                    } else { $spec.Root }
                    $nativeKeyPath = $nativeRoot.TrimEnd([char]92) + [char]92 + [string]$sk.PSChildName
                    $keyLastWrite = [SCC.RegKeyTimes]::GetLastWriteUtc($nativeKeyPath)
                }
            } catch { $keyLastWrite = $null }

            try {
                $item = Get-Item -LiteralPath $sk.PSPath -ErrorAction Stop
                foreach ($valueName in $item.Property) {
                    if ($valueName -in @('Version', 'SequenceNumber', 'UserPrettyName')) { continue }
                    $val = (Get-ItemProperty -LiteralPath $sk.PSPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
                    $executionTime = Convert-BamFileTime -Value $val
                    $rawDataHex = ''
                    $rawDataLength = 0
                    if ($val -is [byte[]]) {
                        $rawDataLength = $val.Length
                        $rawDataHex = [BitConverter]::ToString($val).Replace('-', '')
                    }
                    $progPath = ConvertTo-NullSafeString $valueName
                    if ([string]::IsNullOrWhiteSpace($progPath)) { continue }
                    $executionText = if ($executionTime) { $executionTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                    $rows.Add([PSCustomObject]@{
                        Key                 = "$($spec.Service)|$($sk.PSChildName)|$valueName"
                        Service             = $spec.Service
                        Sid                 = $sk.PSChildName
                        ValueName           = $valueName
                        ProgramPath         = $progPath
                        LastExecutionUtc    = $executionText
                        ValueDataLengthBytes = $rawDataLength
                        ValueDataHex        = $rawDataHex
                        KeyLastWriteUtc     = $(if ($keyLastWrite) { $keyLastWrite.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                        InIncidentWindow    = (Test-InIncidentWindow -WindowDays $WindowDays -TimestampUtc $executionTime)
                    })
                }
            } catch {
                Add-CollectionError -Section 'BamDam' -ErrorText "Reading $($sk.PSPath): $($_.Exception.Message)"
            }
        }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# UserAssist - HKCU\...\Explorer\UserAssist\<GUID>\Count
#
# Value names are ROT13-obfuscated program/shortcut paths; the DWORD payload
# carries run statistics and a last-run FILETIME at bytes 60-67. We decode ROT13,
# read RunCount (offset 4), and expose the last execution timestamp. Key =
# GUID|decoded name.
# ---------------------------------------------------------------------------
function Convert-Rot13 {
    param([string]$Text)
    $chars = $Text.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = [int]$chars[$i]
        if ($c -ge 65 -and $c -le 90)   { $chars[$i] = [char](((($c - 65) + 13) % 26) + 65) }
        elseif ($c -ge 97 -and $c -le 122) { $chars[$i] = [char](((($c - 97) + 13) % 26) + 97) }
    }
    return -join $chars
}

function Convert-UserAssistFileTime {
    # Modern UserAssist payloads place the last-run FILETIME at bytes 60-67.
    param($Value)
    if ($Value -isnot [byte[]] -or $Value.Length -lt 68) { return $null }
    try {
        $fileTime = [BitConverter]::ToInt64($Value, 60)
        if ($fileTime -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($fileTime)
    } catch {
        return $null
    }
}

function Get-UserAssistSection {
    param([int]$WindowDays)

    $rows = New-Object System.Collections.Generic.List[object]
    $root = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    if (-not (Test-Path -LiteralPath $root)) { return $rows }

    # The two well-known count GUIDs; unknown GUIDs are still collected and
    # labelled by their GUID so nothing is silently dropped.
    $guidNames = @{
        '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}' = 'ExecutableInvocation'
        '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}' = 'ShortcutLnkInvocation'
    }

    $guidKeys = Get-ChildItem -LiteralPath $root -ErrorAction Stop
    foreach ($gk in $guidKeys) {
        $guid = $gk.PSChildName
        $kind = 'UnknownGuid'
        if ($guidNames.ContainsKey($guid.ToUpperInvariant())) { $kind = $guidNames[$guid.ToUpperInvariant()] }
        $countKey = Join-Path $gk.PSPath 'Count'
        if (-not (Test-Path -LiteralPath $countKey)) { continue }
        try {
            $item = Get-Item -LiteralPath $countKey -ErrorAction Stop
            foreach ($valueName in $item.Property) {
                $decoded = Convert-Rot13 -Text $valueName
                $runCount = $null
                $lastExecution = $null
                try {
                    $data = (Get-ItemProperty -LiteralPath $countKey -Name $valueName -ErrorAction Stop).$valueName
                    if ($data -is [byte[]] -and $data.Length -ge 8) {
                        $runCount = [BitConverter]::ToUInt32($data, 4)
                        $lastExecution = Convert-UserAssistFileTime -Value $data
                    }
                } catch { }
                $lastExecutionText = if ($lastExecution) { $lastExecution.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                $rows.Add([PSCustomObject]@{
                    Key               = "$guid|$decoded"
                    Guid              = $guid
                    Kind              = $kind
                    EncodedName       = $valueName
                    ProgramName       = $decoded
                    RunCount          = $runCount
                    LastExecutionUtc  = $lastExecutionText
                    InIncidentWindow  = (Test-InIncidentWindow -WindowDays $WindowDays -TimestampUtc $lastExecution)
                })
            }
        } catch {
            Add-CollectionError -Section 'UserAssist' -ErrorText "Reading $($countKey): $($_.Exception.Message)"
        }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# SRUM - System Resource Usage Monitor
#   %SystemRoot%\System32\sru\SRUDB.dat  (+ \srudb.dat transaction logs)
#
# The per-application network-bytes-sent/received tables the incident cares
# about live INSIDE this ESE database, which Windows holds open with exclusive
# locks; correct extraction is an OFFLINE operation (VSS shadow copy or a
# post-shutdown copy, then an ESE reader). Reimplementing an ESE parser in
# PowerShell is out of scope, and running esentutl recovery against the LIVE
# db mutates it, so this section does what is safe online:
#   - inventory the DB + log files (size, timestamps)
#   - SHA-256 hash the main DB (proves whether it changed between snapshots)
#   - best-effort READ-ONLY copy next to the snapshot for later offline parse
# Everything else is recorded as explicit limitations, never silently skipped.
# ---------------------------------------------------------------------------
function Get-FileSha256Safe {
    param([string]$Path)
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $sha = [System.Security.Cryptography.SHA256CryptoServiceProvider]::Create()
            try {
                $hash = $sha.ComputeHash($stream)
                return (([System.BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant())
            } finally { $sha.Dispose() }
        } finally { $stream.Dispose() }
    } catch {
        return ''
    }
}

function Get-SrumSection {
    param([string]$SnapshotDir)

    $sruDir = Join-Path $env:WINDIR 'System32\sru'
    $dbPath = Join-Path $sruDir 'SRUDB.dat'

    $dbExists = Test-Path -LiteralPath $dbPath
    $inventory = New-Object System.Collections.Generic.List[object]
    try {
        if (Test-Path -LiteralPath $sruDir) {
            $files = Get-ChildItem -LiteralPath $sruDir -File -Force -ErrorAction Stop
            foreach ($f in $files) {
                $inventory.Add([PSCustomObject]@{
                    FileName     = $f.Name
                    LengthBytes  = $f.Length
                    LastWriteUtc = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                })
            }
        }
    } catch {
        Add-CollectionError -Section 'Srum' -ErrorText "Inventory: $($_.Exception.Message)"
    }

    $dbHash = ''
    if ($dbExists) { $dbHash = Get-FileSha256Safe -Path $dbPath }

    $copyPath = ''
    $copySucceeded = $false
    $copyError = ''
    if ($dbExists -and $SnapshotDir) {
        try {
            $dest = Join-Path $SnapshotDir ('SRUDB_' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss') + '.dat')
            # Read-only source access: share-read so we never disturb the live ESE instance.
            $srcStream = [System.IO.File]::Open($dbPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $dstStream = [System.IO.File]::Create($dest)
                try { $srcStream.CopyTo($dstStream) } finally { $dstStream.Dispose() }
            } finally { $srcStream.Dispose() }
            $copyPath = $dest
            $copySucceeded = (Test-Path -LiteralPath $dest)
        } catch {
            $copyError = $_.Exception.Message
        }
    }

    # NOTE: returned as a single object (like RecentFilesCapHit), not an array.
    return [PSCustomObject]@{
        DatabasePresent   = $dbExists
        DatabasePath      = $dbPath
        DatabaseSha256    = $dbHash
        Files             = [object[]]$inventory.ToArray()
        OfflineCopyPath   = $copyPath
        OfflineCopyOk     = $copySucceeded
        OfflineCopyError  = $copyError
        Limitations       = @(
            'Per-application network usage tables were NOT parsed: SRUDB.dat is an ESE database held exclusively open by Windows.'
            'Offline analysis path: capture a VSS shadow copy or copy SRUDB.dat after shutdown, then parse the NetworkUsage / AppResourceUseInfo tables with an ESE reader (e.g. esedbexport or NirSoft SRUM viewer).'
            'The OfflineCopy*.dat beside this snapshot, if OfflineCopyOk is true, is a point-in-time copy suitable for that offline parse (it may be transactionally inconsistent while the system runs - treat as best-effort).'
        )
    }
}

function Get-AmcacheSection {
    # Retro artifact: C:\Windows\AppCompat\Programs\Amcache.hve - the
    # registry-adjacent inventory of every application and binary the
    # AppCompat service has seen (the closest thing Windows keeps to an
    # offline program-execution ledger after ShimCache/BAM). Read it by
    # mounting the hive under HKLM:\Amcache with reg.exe, enumerating the
    # inventory keys, then unmounting. Admin required; a non-admin or
    # locked-hive run yields an empty section + an explicit CollectionWarning
    # when the artifact is absent, or a CollectionError for mount/read/unload
    # failures (never aborts the snapshot). InstallDate is NOT used as a window filter: its
    # format (YYYYMMDD) and reliability vary by Windows version, and every
    # entry is worth keeping for an investigation.
    $rows = New-Object System.Collections.Generic.List[object]
    $windir = $env:WINDIR
    if (-not $windir) { $windir = $env:SystemRoot }
    if (-not $windir) {
        Add-CollectionError -Section 'Amcache' -ErrorText '$env:WINDIR not set - cannot locate Amcache.hve'
        return , @()
    }
    $amcachePath = Join-Path $windir 'AppCompat\Programs\Amcache.hve'
    if (-not (Test-Path -LiteralPath $amcachePath)) {
        Add-CollectionWarning -Section 'Amcache' -WarningText "Amcache.hve not found at $amcachePath"
        return , @()
    }
    $regExe = $null
    try { $regExe = (Get-Command reg.exe -ErrorAction Stop).Source } catch { }
    if (-not $regExe) {
        Add-CollectionError -Section 'Amcache' -ErrorText 'reg.exe not available - cannot mount Amcache.hve'
        return , @()
    }
    $mountKey = 'HKLM\Amcache'
    $mountProviderPath = 'Registry::' + $mountKey
    $mounted = $false
    $alreadyMounted = $false
    try { $alreadyMounted = Test-Path -LiteralPath $mountProviderPath } catch { $alreadyMounted = $false }
    try {
        if (-not $alreadyMounted) {
            & $regExe load $mountKey $amcachePath 2>$null | Out-Null
            $loadCode = $LASTEXITCODE
            if ($loadCode -ne 0) {
                Add-CollectionError -Section 'Amcache' -ErrorText ("reg.exe load failed (exit " + $loadCode + ") - hive in use, or not elevated")
                return , @()
            }
            $mounted = $true
        }

        # InventoryApplicationFile: one subkey per binary file the service saw.
        $rootFile = 'Registry::' + $mountKey + '\Root\InventoryApplicationFile'
        if (Test-Path -LiteralPath $rootFile) {
            foreach ($k in @(Get-ChildItem -LiteralPath $rootFile -ErrorAction SilentlyContinue)) {
                try {
                    $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
                    $fileId = [string]$p.FileId
                    if (-not $fileId) { $fileId = $k.PSChildName }
                    $filePath = ConvertTo-NullSafeString $p.LowerCaseLongPath
                    if (-not $filePath) { $filePath = ConvertTo-NullSafeString $p.Path }
                    $fileVersion = ConvertTo-NullSafeString $p.ProductVersion
                    if (-not $fileVersion) { $fileVersion = ConvertTo-NullSafeString $p.Version }
                    $rows.Add([PSCustomObject]@{
                        Key       = 'AF:' + $fileId
                        Kind      = 'file'
                        Name      = ConvertTo-NullSafeString $p.Name
                        Path      = $filePath
                        Publisher = ConvertTo-NullSafeString $p.Publisher
                        Version   = $fileVersion
                        Hash      = ConvertTo-NullSafeString $p.Hash
                    })
                } catch {
                    Add-CollectionError -Section 'Amcache' -ErrorText ("File entry " + $k.PSChildName + ": " + $_.Exception.Message)
                }
            }
        }

        # InventoryApplication: application inventory records. These indicate
        # presence/metadata, not definitive execution by themselves.
        $rootApp = 'Registry::' + $mountKey + '\Root\InventoryApplication'
        if (Test-Path -LiteralPath $rootApp) {
            foreach ($k in @(Get-ChildItem -LiteralPath $rootApp -ErrorAction SilentlyContinue)) {
                try {
                    $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
                    $appId = [string]$p.AppId
                    if (-not $appId) { $appId = $k.PSChildName }
                    $appPath = ConvertTo-NullSafeString $p.RootDirPath
                    if (-not $appPath) { $appPath = ConvertTo-NullSafeString $p.FolderPath }
                    $appVersion = ConvertTo-NullSafeString $p.ProductVersion
                    if (-not $appVersion) { $appVersion = ConvertTo-NullSafeString $p.Version }
                    $rows.Add([PSCustomObject]@{
                        Key         = 'AP:' + $appId
                        Kind        = 'application'
                        Name        = ConvertTo-NullSafeString $p.Name
                        Publisher   = ConvertTo-NullSafeString $p.Publisher
                        Version     = $appVersion
                        InstallDate = ConvertTo-NullSafeString $p.InstallDate
                        Path        = $appPath
                    })
                } catch {
                    Add-CollectionError -Section 'Amcache' -ErrorText ("App entry " + $k.PSChildName + ": " + $_.Exception.Message)
                }
            }
        }
    } catch {
        Add-CollectionError -Section 'Amcache' -ErrorText $_.Exception.Message
    } finally {
        if ($mounted) {
            & $regExe unload $mountKey 2>$null | Out-Null
            $unloadCode = $LASTEXITCODE
            if ($unloadCode -ne 0) {
                Add-CollectionError -Section 'Amcache' -ErrorText ("reg.exe unload failed (exit " + $unloadCode + "); HKLM\\Amcache may remain mounted")
            }
        } elseif ($alreadyMounted) {
            Add-CollectionWarning -Section 'Amcache' -WarningText 'HKLM\\Amcache was already mounted; existing mount was reused and not unloaded'
        }
    }
    return , @($rows.ToArray())
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$startTime = Get-Date

if (-not $OutFile) {
    $hostName = Get-HostNameSafe
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $OutFile = Join-Path $scriptDir "snapshot_${hostName}_${stamp}.json"
}

Write-Info "Collecting snapshot (Label=$Label, IncidentWindowDays=$IncidentWindowDays)..."

# ---------------------------------------------------------------------------
# Single/group section mode (used by the parallel jobs below): collect one
# section (-Section) or a comma-separated group (-Sections), emit one JSON
# line, exit. Also lets a caller collect sections manually.
# ---------------------------------------------------------------------------
function Get-SectionDataByName {
    # Returns a FLAT row array for one section (capture-then-collect; see
    # Add-WaveData for why the comma-wrap idiom must not be used here).
    param([string]$Name)
    switch ($Name) {
        'ScheduledTasks'    { $out = Sort-ByKey (Invoke-Section -Name 'ScheduledTasks' -ScriptBlock { Get-ScheduledTasksSection }); return @($out) }
        'FirewallRules'     { $out = Sort-ByKey (Invoke-Section -Name 'FirewallRules' -ScriptBlock { Get-FirewallRulesSection }); return @($out) }
        'Connections'       { $out = Sort-ByKey (Invoke-Section -Name 'Connections' -ScriptBlock { Get-ConnectionsSection }); return @($out) }
        'Services'          { $out = Sort-ByKey (Invoke-Section -Name 'Services' -ScriptBlock { Get-ServicesSection }); return @($out) }
        'Processes'         { $out = Sort-ByKey (Invoke-Section -Name 'Processes' -ScriptBlock { Get-ProcessesSection }); return @($out) }
        'LocalAccounts'     { $out = Sort-ByKey (Invoke-Section -Name 'LocalAccounts' -ScriptBlock { Get-LocalAccountsSection }); return @($out) }
        'WmiPersistence'    { $out = Sort-ByKey (Invoke-Section -Name 'WmiPersistence' -ScriptBlock { Get-WmiPersistenceSection }); return @($out) }
        'RegistryAutoruns'  { $out = Sort-ByKey (Invoke-Section -Name 'RegistryAutoruns' -ScriptBlock { Get-RegistryAutorunsSection }); return @($out) }
        'InstalledPrograms' { $out = Sort-ByKey (Invoke-Section -Name 'InstalledPrograms' -ScriptBlock { Get-InstalledProgramsSection }); return @($out) }
        'BamDam'            { $out = Sort-ByKey (Invoke-Section -Name 'BamDam' -ScriptBlock { Get-BamDamSection -WindowDays $IncidentWindowDays }); return @($out) }
        'UserAssist'        { $out = Sort-ByKey (Invoke-Section -Name 'UserAssist' -ScriptBlock { Get-UserAssistSection -WindowDays $IncidentWindowDays }); return @($out) }
        'Prefetch'          { $out = Sort-ByKey (Invoke-Section -Name 'Prefetch' -ScriptBlock { Get-PrefetchSection -WindowDays $IncidentWindowDays }); return @($out) }
        'ShimCache'         { $out = Sort-ByKey (Invoke-Section -Name 'ShimCache' -ScriptBlock { Get-ShimCacheSection -WindowDays $IncidentWindowDays }); return @($out) }
        'Srum'              { return (Get-SrumSection -SnapshotDir (Split-Path -Parent $OutFile)) }
        'Amcache'           { $out = Sort-ByKey (Get-AmcacheSection); return @($out) }
        'StartupFolders'    { $out = Sort-ByKey (Invoke-Section -Name 'StartupFolders' -ScriptBlock { Get-StartupFoldersSection }); return @($out) }
        default { throw ("Unknown section: " + $Name) }
    }
}

if ($Section) {
    $out = Get-SectionDataByName -Name $Section
    $data = if ($Section -eq 'Srum') { $out } else { @($out) }
    $errs = New-Object System.Collections.ArrayList
    foreach ($e in $script:CollectionErrors) { [void]$errs.Add($e.Error) }
    $warns = New-Object System.Collections.ArrayList
    foreach ($w in $script:CollectionWarnings) { [void]$warns.Add($w.Warning) }
    [pscustomobject]@{ Section = $Section; Data = $data; Errors = $errs.ToArray(); Warnings = $warns.ToArray() } |
        ConvertTo-Json -Depth 8 -Compress | Write-Output
    exit 0
}

if ($Sections) {
    $map = [ordered]@{}
    foreach ($n in ($Sections -split ',')) {
        $n = $n.Trim()
        if (-not $n) { continue }
        $out = Get-SectionDataByName -Name $n
        if ($n -eq 'Srum') { $map[$n] = $out } else { $map[$n] = @($out) }
    }
    $errs = New-Object System.Collections.ArrayList
    foreach ($e in $script:CollectionErrors) { [void]$errs.Add([pscustomobject]@{ Section = $e.Section; Error = $e.Error }) }
    $warns = New-Object System.Collections.ArrayList
    foreach ($w in $script:CollectionWarnings) { [void]$warns.Add([pscustomobject]@{ Section = $w.Section; Warning = $w.Warning }) }
    [pscustomobject]@{ Sections = $map; Errors = $errs.ToArray(); Warnings = $warns.ToArray() } |
        ConvertTo-Json -Depth 8 -Compress | Write-Output
    exit 0
}

# ---------------------------------------------------------------------------
# Parallel section collection (v1.7.16 - concurrent GROUPS + live progress):
# the independent sections run in at most 4 concurrent background jobs - each
# job collects a GROUP of sections via -Sections mode and emits one JSON line
# {Sections: {name: data}, Errors: [{Section, Error}], Warnings: [{Section, Warning}]}.
# v1.7.6 parallelized 3 sections; v1.7.12 ran sequential waves (wall-clock =
# SUM of waves); v1.7.16 starts every group at once, so wall-clock = MAX of the
# groups (same 4-process peak as one old wave, only 4 job spawns instead of 14).
# payload failures fall back to the sections' sequential in-process blocks.
# A hard timeout stops the remaining jobs and marks those sections incomplete;
# it does NOT run an unbounded fallback after the deadline.
# ticks in the console so the technician can see the snapshot is still
# working - this is NOT gated by -Quiet (the guided runner runs -Quiet and
# the progress bar is exactly what the technician needs to see).
# Disable all background jobs with -NoParallel.
# ---------------------------------------------------------------------------
$script:waveData = @{}
$script:doneSections = 0
$script:groupTotal = 0

function Add-WaveData {
    # Store a section's rows FLAT. The comma-wrap idiom (", @(...)") that the
    # older wave code used double/triple-nested sections in the final JSON
    # (v1.7.12-15 shipped "[[[rows]]]" instead of "[rows]"). @($Data) collects
    # the captured pipeline output, which stays flat for empty and non-empty.
    param([string]$Name, $Data)
    $script:waveData[$Name] = @($Data)
    $script:doneSections++
}

function Write-Tick {
    # Live "still working" line, overwritten in place with a carriage return.
    param([switch]$ForceNewLine)
    $el = [int]((Get-Date) - $startTime).TotalSeconds
    $msg = "  [snapshot " + $Label + "] " + $script:doneSections + "/" + $script:groupTotal + " sections, " + $el + "s elapsed"
    if ($ForceNewLine) {
        Write-Host ("`r" + $msg + "      ")
    } else {
        Write-Host -NoNewline ("`r" + $msg + "      ")
    }
}

function Invoke-GroupJob {
    # Start ONE background job that collects $SectionList via -Sections mode.
    # Returns the job, or $null when the job could not be spawned.
    param([string]$SectionList, [string]$ScriptPath)
    try {
        return (Start-Job -ScriptBlock {
            param($p, $s, $w)
            & $p -Sections $s -Quiet -NoParallel -IncidentWindowDays $w
        } -ArgumentList $ScriptPath, $SectionList, $IncidentWindowDays)
    } catch {
        return $null
    }
}

function Receive-GroupJob {
    # Parse a group job's {Sections, Errors, Warnings} envelope and merge every section
    # into $script:waveData. Returns $true on success; $false on any failure
    # (the caller then runs that group's sections sequentially in-process).
    param([string]$Group, $Job, [string[]]$Members)
    if ($null -eq $Job) { return $false }
    try {
        $raw = Receive-Job -Job $Job -ErrorAction Stop
        $text = ($raw | Out-String).Trim()
        if (-not $text) { return $false }
        $parsed = $null
        try { $parsed = $text | ConvertFrom-Json } catch { }
        if ($null -eq $parsed -or $null -eq $parsed.Sections) { return $false }
        foreach ($n in $Members) {
            if ($null -ne $parsed.Sections.$n) {
                Add-WaveData -Name $n -Data @($parsed.Sections.$n)
            } else {
                Add-WaveData -Name $n -Data @()
            }
        }
        if ($parsed.Errors) {
            foreach ($pe in @($parsed.Errors)) {
                $secName = $pe.Section
                $errText = $pe.Error
                if (-not $secName) { $secName = $Group }
                Add-CollectionError -Section $secName -ErrorText ([string]$errText)
            }
        }
        if ($parsed.Warnings) {
            foreach ($pw in @($parsed.Warnings)) {
                $secName = $pw.Section
                $warningText = $pw.Warning
                if (-not $secName) { $secName = $Group }
                Add-CollectionWarning -Section $secName -WarningText ([string]$warningText)
            }
        }
        return $true
    } catch {
        return $false
    }
}

function Invoke-SectionGroups {
    # Start all group jobs at once (bounded at 4), wait with a live progress
    # tick, merge results. A failed group runs its sections sequentially
    # in-process instead. Results land in $script:waveData[<section>].
    param([string[]]$GroupNames, [hashtable]$GroupMembers, [hashtable]$Blocks, [string]$ScriptPath)
    foreach ($g in $GroupNames) { $script:groupTotal += @($GroupMembers[$g]).Count }

    if ($NoParallel) {
        foreach ($g in $GroupNames) {
            foreach ($n in @($GroupMembers[$g])) {
                Add-WaveData -Name $n -Data (& $Blocks[$n])
            }
        }
        Write-Tick -ForceNewLine
        return
    }

    $jobs = @{}
    foreach ($g in $GroupNames) {
        $jobs[$g] = Invoke-GroupJob -SectionList (@($GroupMembers[$g]) -join ',') -ScriptPath $ScriptPath
    }

    $pending = @($GroupNames)
    $timeoutSeconds = [Math]::Max(30, $ParallelTimeoutSeconds)
    $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSeconds)
    while ($pending.Count -gt 0) {
        if ([DateTime]::UtcNow -ge $deadline) {
            Write-Info ("  (parallel snapshot groups exceeded " + $timeoutSeconds + " seconds; stopping remaining jobs and marking sections incomplete)")
            foreach ($g in $pending) {
                if ($null -ne $jobs[$g]) {
                    try { Stop-Job -Job $jobs[$g] -ErrorAction SilentlyContinue } catch { }
                    try { Remove-Job -Job $jobs[$g] -Force -ErrorAction SilentlyContinue } catch { }
                }
                foreach ($n in @($GroupMembers[$g])) {
                    Add-CollectionError -Section $n -ErrorText ("parallel group timed out after " + $timeoutSeconds + " seconds")
                    Add-WaveData -Name $n -Data @()
                }
            }
            $pending = @()
            break
        }
        $live = @($pending | Where-Object { $null -ne $jobs[$_] })
        if ($live.Count -gt 0) {
            $null = Wait-Job -Job ($live | ForEach-Object { $jobs[$_] }) -Timeout 2
        }
        $still = @()
        foreach ($g in $pending) {
            if ($null -eq $jobs[$g]) {
                # job could not be spawned -> sequential fallback now
                Write-Info ("  (parallel group " + $g + " failed to start - using sequential path)")
                foreach ($n in @($GroupMembers[$g])) { Add-WaveData -Name $n -Data (& $Blocks[$n]) }
                continue
            }
            if ($jobs[$g].State -eq 'Running') { $still += $g; continue }
            # finished (Completed / Failed / Stopped): merge, or fall back
            $ok = Receive-GroupJob -Group $g -Job $jobs[$g] -Members @($GroupMembers[$g])
            Remove-Job -Job $jobs[$g] -Force
            if (-not $ok) {
                Write-Info ("  (parallel group " + $g + " returned nothing - using sequential path)")
                foreach ($n in @($GroupMembers[$g])) { Add-WaveData -Name $n -Data (& $Blocks[$n]) }
            }
        }
        $pending = $still
        Write-Tick
    }
    Write-Tick -ForceNewLine
}

$isAdmin = Test-IsAdmin

$osCaption = ''
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $osCaption = ConvertTo-NullSafeString $os.Caption
} catch {
    Add-CollectionError -Section 'OSInfo' -ErrorText $_.Exception.Message
}

$sectionBlocks = @{
    'ScheduledTasks'    = { Sort-ByKey (Invoke-Section -Name 'ScheduledTasks' -ScriptBlock { Get-ScheduledTasksSection }) }
    'Services'          = { Sort-ByKey (Invoke-Section -Name 'Services' -ScriptBlock { Get-ServicesSection }) }
    'Processes'         = { Sort-ByKey (Invoke-Section -Name 'Processes' -ScriptBlock { Get-ProcessesSection }) }
    'LocalAccounts'     = { Sort-ByKey (Invoke-Section -Name 'LocalAccounts' -ScriptBlock { Get-LocalAccountsSection }) }
    'WmiPersistence'    = { Sort-ByKey (Invoke-Section -Name 'WmiPersistence' -ScriptBlock { Get-WmiPersistenceSection }) }
    'Connections'       = { Sort-ByKey (Invoke-Section -Name 'Connections' -ScriptBlock { Get-ConnectionsSection }) }
    'FirewallRules'     = { Sort-ByKey (Invoke-Section -Name 'FirewallRules' -ScriptBlock { Get-FirewallRulesSection }) }
    'InstalledPrograms' = { Sort-ByKey (Invoke-Section -Name 'InstalledPrograms' -ScriptBlock { Get-InstalledProgramsSection }) }
    'RegistryAutoruns'  = { Sort-ByKey (Invoke-Section -Name 'RegistryAutoruns' -ScriptBlock { Get-RegistryAutorunsSection }) }
    'BamDam'            = { Sort-ByKey (Invoke-Section -Name 'BamDam' -ScriptBlock { Get-BamDamSection -WindowDays $IncidentWindowDays }) }
    'UserAssist'        = { Sort-ByKey (Invoke-Section -Name 'UserAssist' -ScriptBlock { Get-UserAssistSection -WindowDays $IncidentWindowDays }) }
    'StartupFolders'    = { Sort-ByKey (Invoke-Section -Name 'StartupFolders' -ScriptBlock { Get-StartupFoldersSection }) }
    'Prefetch'          = { Sort-ByKey (Invoke-Section -Name 'Prefetch' -ScriptBlock { Get-PrefetchSection -WindowDays $IncidentWindowDays }) }
    'ShimCache'         = { Sort-ByKey (Invoke-Section -Name 'ShimCache' -ScriptBlock { Get-ShimCacheSection -WindowDays $IncidentWindowDays }) }
}

# 14 sections collect in 4 CONCURRENT groups (same 4-process peak as one old
# wave, but wall-clock = the slowest group instead of the sum of all waves).
$groupMembers = @{
    'CIM'      = @('ScheduledTasks', 'Services', 'LocalAccounts', 'WmiPersistence')
    'Network'  = @('Connections', 'FirewallRules', 'Processes', 'InstalledPrograms')
    'Registry' = @('RegistryAutoruns', 'BamDam', 'UserAssist', 'StartupFolders')
    'Files'    = @('Prefetch', 'ShimCache')
}

Write-Info '  - Collecting 14 sections in 4 concurrent groups (CIM, network, registry, files)'
Invoke-SectionGroups -GroupNames @('CIM', 'Network', 'Registry', 'Files') -GroupMembers $groupMembers -Blocks $sectionBlocks -ScriptPath $PSCommandPath

$scheduledTasks    = $script:waveData['ScheduledTasks']
$services          = $script:waveData['Services']
$processes         = $script:waveData['Processes']
$localAccounts     = $script:waveData['LocalAccounts']
$wmiPersistence    = $script:waveData['WmiPersistence']
$connections       = $script:waveData['Connections']
$firewallRules     = $script:waveData['FirewallRules']
$installedPrograms = $script:waveData['InstalledPrograms']
$registryAutoruns  = $script:waveData['RegistryAutoruns']
$bamDam            = $script:waveData['BamDam']
$userAssist        = $script:waveData['UserAssist']
$startupFolders    = $script:waveData['StartupFolders']
$prefetch          = $script:waveData['Prefetch']
$shimCache         = $script:waveData['ShimCache']

# Serial tail: 4 more sections (system settings, recent files, SRUM, Amcache)
# so the progress counter runs to 18/18.
$script:groupTotal = 18

$rdpEnabled = $null
try {
    $rdpEnabled = Get-RdpEnabled
} catch {
    Add-CollectionError -Section 'SystemSettings' -ErrorText "RDP state: $($_.Exception.Message)"
}

$hostsLines = @()
try {
    $hostsLines = Get-HostsFileLines
} catch {
    Add-CollectionError -Section 'SystemSettings' -ErrorText "Hosts file: $($_.Exception.Message)"
}
$script:doneSections = 15
Write-Tick

$recentFiles = @()
$recentFilesCapHit = $false
if ($IncidentWindowDays -gt 0) {
    Write-Info '  - Recent files (incident window sweep)'
    try {
        $rf = Get-RecentFilesSection -WindowDays $IncidentWindowDays -CapCount 500
        $recentFiles = Sort-ByKey $rf.Items
        $recentFilesCapHit = $rf.CapHit
    } catch {
        $errLoc = ''
        if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) { $errLoc = ' @ line ' + $_.InvocationInfo.ScriptLineNumber }
        Add-CollectionError -Section 'RecentFiles' -ErrorText ($_.Exception.Message + $errLoc)
    }
}
$script:doneSections = 16
Write-Tick

$srumSnapshotDir = ''
try {
    if ($OutFile) {
        $srumSnapshotDir = Split-Path -Parent $OutFile
        if (-not (Test-Path -LiteralPath $srumSnapshotDir)) {
            New-Item -ItemType Directory -Path $srumSnapshotDir -Force | Out-Null
            # NOTE: creates ONLY the output directory for this run's own artifacts.
        }
    }
} catch {
    $srumSnapshotDir = ''
}

Write-Info '  - SRUM inventory'
try {
    $srum = Get-SrumSection -SnapshotDir $srumSnapshotDir
} catch {
    Add-CollectionError -Section 'Srum' -ErrorText $_.Exception.Message
    $srum = [PSCustomObject]@{
        DatabasePresent = $false; DatabasePath = ''; DatabaseSha256 = ''
        Files = @(); OfflineCopyPath = ''; OfflineCopyOk = $false
        OfflineCopyError = $_.Exception.Message; Limitations = @('Section failed entirely.')
    }
}
$script:doneSections = 17
Write-Tick

Write-Info '  - Amcache inventory'
try {
    $amcache = Sort-ByKey (Get-AmcacheSection)
} catch {
    Add-CollectionError -Section 'Amcache' -ErrorText $_.Exception.Message
    $amcache = @()
}
$script:doneSections = 18
Write-Tick -ForceNewLine

$result = [ordered]@{
    SchemaVersion      = $SchemaVersion
    Label              = $Label
    ComputerName       = Get-HostNameSafe
    CollectedUtc       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    IsAdmin            = $isAdmin
    OSCaption          = $osCaption
    IncidentWindowDays = $IncidentWindowDays
    CollectionComplete = (-not $script:CollectionIncomplete)
    CollectionErrors   = Get-CollectionErrorsArray
    CollectionWarnings = Get-CollectionWarningsArray
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
        Prefetch         = @($prefetch)
        ShimCache        = @($shimCache)
        BamDam           = @($bamDam)
        UserAssist       = @($userAssist)
        Srum             = $srum
        Amcache          = @($amcache)
        SystemSettings   = [ordered]@{
            RdpEnabled     = $rdpEnabled
            HostsFileLines = @($hostsLines)
        }
    }
}

Write-Info '  - Serializing'
# Depth 6 covers the real shape (result > Sections > array > row > scalar).
# Depth 12 made Windows PowerShell 5.1's ConvertTo-Json recurse into the .NET
# internals of any non-primitive left in a row, which pushed this step to
# multiple GB and many minutes on an ordinary workstation.
$json = $result | ConvertTo-Json -Depth 6

# Write as UTF-8 without BOM so the output stays consistent regardless of
# which PowerShell host writes it.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, $json, $utf8NoBom)

$elapsed = (Get-Date) - $startTime

Write-Info "Snapshot written to: $OutFile"
Write-Info ("Elapsed: {0:N1}s  IsAdmin={1}  CollectionErrors={2}" -f $elapsed.TotalSeconds, $isAdmin, $script:CollectionErrors.Count)

if ($script:CollectionErrors.Count -gt 0) {
    # ALWAYS visible, even under -Quiet: collection errors are evidence the
    # technician must act on and do not necessarily surface as a nonzero exit.
    Write-Host ("  [WARN] Snapshot contains " + $script:CollectionErrors.Count + " collection error(s) - see the snapshot JSON and log for details.") -ForegroundColor Yellow
    if (-not $Quiet) {
        Write-Info 'Sections with errors:'
        foreach ($e in $script:CollectionErrors) {
            Write-Info ("  - {0}: {1}" -f $e.Section, $e.Error)
        }
    }
}
