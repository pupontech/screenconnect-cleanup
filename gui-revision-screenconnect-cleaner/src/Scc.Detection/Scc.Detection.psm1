
# Ensure Microsoft.PowerShell.Utility cmdlets (Get-Date, New-Object, ConvertTo-Json,
# Out-Null, Add-Member, etc.) are visible inside this module's session state on every
# host. Without this, module functions fail with CommandNotFoundException on Windows
# when the module is loaded through Pester or a nested session state.
$null = Import-Module -Name 'Microsoft.PowerShell.Utility' -ErrorAction SilentlyContinue

<#
  Scc.Detection.psm1 - Detection module for ScreenConnect Cleaner

  ScreenConnect deep detection (relay identity extraction), other remote-access
  presence detection (config-driven), and trust matching against known-good
  relays.

  READ-ONLY: detection never modifies system state.

  Ported from legacy detect-remote-access.ps1 (v0.1.0-poc) and decomposed per
  AUDIT-02-detection.md. PowerShell 5.1 compatible. Pure ASCII source.
#>

# ---------------------------------------------------------------------------
# Embedded default targets - keeps the module standalone if targets.json is
# absent. targets.json, when present, wins (loaded at runtime).
# ---------------------------------------------------------------------------
$script:DefaultTargetsJson = @'
{
  "_comment": [
    "Toggle what detection looks for. Set enabled true/false.",
    "deep=true means there is a dedicated module for it (ScreenConnect only).",
    "deep=false means presence-only: service / process / directory / uninstall match.",
    "Paths may use %ENVVAR% - expanded at runtime."
  ],
  "targets": [
    { "id":"screenconnect", "name":"ScreenConnect / ConnectWise Control", "enabled":true, "deep":true,
      "servicePatterns":["ScreenConnect*"], "processPatterns":["ScreenConnect.*"],
      "pathPatterns":["%ProgramFiles(x86)%\\ScreenConnect Client*", "%ProgramFiles%\\ScreenConnect Client*", "%ProgramData%\\ScreenConnect*"],
      "uninstallPatterns":["ScreenConnect*", "ConnectWise Control*"] },
    { "id":"anydesk", "name":"AnyDesk", "enabled":false, "deep":false,
      "servicePatterns":["AnyDesk*"], "processPatterns":["AnyDesk*"],
      "pathPatterns":["%ProgramFiles(x86)%\\AnyDesk*", "%ProgramFiles%\\AnyDesk*", "%ProgramData%\\AnyDesk*", "%APPDATA%\\AnyDesk*"],
      "uninstallPatterns":["AnyDesk*"] },
    { "id":"teamviewer", "name":"TeamViewer", "enabled":false, "deep":false,
      "servicePatterns":["TeamViewer*"], "processPatterns":["TeamViewer*", "tv_*"],
      "pathPatterns":["%ProgramFiles(x86)%\\TeamViewer*", "%ProgramFiles%\\TeamViewer*"],
      "uninstallPatterns":["TeamViewer*"] },
    { "id":"ultraviewer", "name":"UltraViewer", "enabled":false, "deep":false,
      "servicePatterns":["UltraViewer*"], "processPatterns":["UltraViewer*"],
      "pathPatterns":["%ProgramFiles(x86)%\\UltraViewer*", "%ProgramFiles%\\UltraViewer*"],
      "uninstallPatterns":["UltraViewer*"] },
    { "id":"supremo", "name":"Supremo", "enabled":false, "deep":false,
      "servicePatterns":["Supremo*"], "processPatterns":["Supremo*"],
      "pathPatterns":["%ProgramFiles(x86)%\\Supremo*", "%ProgramFiles%\\Supremo*", "%APPDATA%\\Supremo*"],
      "uninstallPatterns":["Supremo*"] },
    { "id":"rustdesk", "name":"RustDesk", "enabled":false, "deep":false,
      "servicePatterns":["RustDesk*"], "processPatterns":["rustdesk*"],
      "pathPatterns":["%ProgramFiles%\\RustDesk*", "%ProgramFiles(x86)%\\RustDesk*", "%APPDATA%\\RustDesk*"],
      "uninstallPatterns":["RustDesk*"] },
    { "id":"splashtop", "name":"Splashtop (incl. SOS)", "enabled":false, "deep":false,
      "servicePatterns":["SplashtopRemoteService*", "Splashtop*"], "processPatterns":["SR*Service*", "Splashtop*", "strwinclt*"],
      "pathPatterns":["%ProgramFiles(x86)%\\Splashtop*", "%ProgramFiles%\\Splashtop*"],
      "uninstallPatterns":["Splashtop*"] },
    { "id":"logmein", "name":"LogMeIn / GoTo (incl. Rescue)", "enabled":false, "deep":false,
      "servicePatterns":["LMIGuardian*", "LogMeIn*"], "processPatterns":["LogMeIn*", "LMI*", "Support-LogMeInRescue*"],
      "pathPatterns":["%ProgramFiles(x86)%\\LogMeIn*", "%ProgramFiles%\\LogMeIn*"],
      "uninstallPatterns":["LogMeIn*", "GoTo*"] },
    { "id":"zohoassist", "name":"Zoho Assist", "enabled":false, "deep":false,
      "servicePatterns":["ZohoMeeting*", "Zoho*"], "processPatterns":["ZA*", "Zoho*"],
      "pathPatterns":["%ProgramFiles(x86)%\\ZohoMeeting*", "%ProgramFiles%\\ZohoMeeting*"],
      "uninstallPatterns":["Zoho Assist*", "Zoho*"] },
    { "id":"atera", "name":"Atera / AteraAgent", "enabled":false, "deep":false,
      "servicePatterns":["AteraAgent*"], "processPatterns":["AteraAgent*"],
      "pathPatterns":["%ProgramFiles(x86)%\\ATERA Networks*", "%ProgramFiles%\\ATERA Networks*"],
      "uninstallPatterns":["Atera*"] },
    { "id":"dwagent", "name":"DWAgent / DWService", "enabled":false, "deep":false,
      "servicePatterns":["DWAgent*"], "processPatterns":["dwagent*"],
      "pathPatterns":["%ProgramFiles%\\DWAgent*", "%ProgramFiles(x86)%\\DWAgent*"],
      "uninstallPatterns":["DWAgent*", "DWService*"] },
    { "id":"meshagent", "name":"MeshCentral agent", "enabled":false, "deep":false,
      "servicePatterns":["Mesh Agent*", "MeshAgent*"], "processPatterns":["MeshAgent*"],
      "pathPatterns":["%ProgramFiles%\\Mesh Agent*", "%ProgramFiles(x86)%\\Mesh Agent*"],
      "uninstallPatterns":["Mesh Agent*", "MeshCentral*"] },
    { "id":"netsupport", "name":"NetSupport Manager", "enabled":false, "deep":false,
      "servicePatterns":["Client32*", "NetSupport*"], "processPatterns":["client32*", "pcicfgui*"],
      "pathPatterns":["%ProgramFiles(x86)%\\NetSupport*", "%ProgramFiles%\\NetSupport*"],
      "uninstallPatterns":["NetSupport*"] },
    { "id":"remoteutilities", "name":"Remote Utilities", "enabled":false, "deep":false,
      "servicePatterns":["RManService*", "Remote Utilities*"], "processPatterns":["rutserv*", "rfusclient*"],
      "pathPatterns":["%ProgramFiles(x86)%\\Remote Utilities*", "%ProgramFiles%\\Remote Utilities*"],
      "uninstallPatterns":["Remote Utilities*"] },
    { "id":"vnc", "name":"VNC family (Ultra/Tight/Real/TigerVNC)", "enabled":false, "deep":false,
      "servicePatterns":["uvnc*", "tvnserver*", "vncserver*", "RealVNC*"], "processPatterns":["winvnc*", "tvnserver*", "vncserver*"],
      "pathPatterns":["%ProgramFiles%\\uvnc*", "%ProgramFiles%\\TightVNC*", "%ProgramFiles%\\RealVNC*", "%ProgramFiles(x86)%\\uvnc*", "%ProgramFiles(x86)%\\TightVNC*", "%ProgramFiles(x86)%\\RealVNC*"],
      "uninstallPatterns":["*VNC*"] }
  ]
}
'@

# ---------------------------------------------------------------------------
# ScreenConnect launch-parameter key map.
#
# ASSUMED, NOT CONFIRMED - this map is exactly what the detection exists to
# test. Any key not listed here is preserved verbatim under UnknownParameters
# so we can learn the real meaning from live output instead of guessing.
# ---------------------------------------------------------------------------
$script:ScKnownKeys = @{
    'e'  = 'SessionType'      # Access (unattended) / Support (one-shot) / Meeting
    'y'  = 'Role'             # typically Guest
    'h'  = 'RelayHost'        # THE decision key
    'p'  = 'RelayPort'        # default believed to be 8041
    's'  = 'SessionId'
    'k'  = 'ServerKey'        # encoded; corroborates the host
    'c1' = 'Custom1'; 'c2' = 'Custom2'; 'c3' = 'Custom3'; 'c4' = 'Custom4'
    'c5' = 'Custom5'; 'c6' = 'Custom6'; 'c7' = 'Custom7'; 'c8' = 'Custom8'
}

$script:BlobRegex = [regex]'(?i)(?:[a-z][a-z0-9]{0,3}=[^&\s"''<>\)]*&){2,}[a-z][a-z0-9]{0,3}=[^&\s"''<>\)]*'

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

function Get-Sha256Hex {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash  = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally { $sha.Dispose() }
}

function Expand-Env {
    param([string]$Path)
    if (-not $Path) { return $Path }
    return [System.Environment]::ExpandEnvironmentVariables($Path)
}

function Test-AnyLike {
    param([string]$Value, [string[]]$Patterns)
    if (-not $Value -or -not $Patterns) { return $false }
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    return $false
}

function Test-MalformedPercentEncoding {
    # Returns $true if the value contains a percent that is not part of a
    # valid %XX (two hex digits) sequence. Lets us flag bad encoding
    # deterministically instead of depending on UnescapeDataString throwing.
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value) -or $Value -notmatch '%') { return $false }
    $i = 0
    while ($i -lt $Value.Length) {
        if ($Value[$i] -eq '%') {
            if ($i + 2 -ge $Value.Length) { return $true }
            $h = $Value.Substring($i + 1, 2)
            if ($h -notmatch '^[0-9a-fA-F]{2}$') { return $true }
            $i += 3
        } else { $i++ }
    }
    return $false
}

# ---------------------------------------------------------------------------
# ScreenConnect parameter-blob extraction
#
# Deliberately assumption-light: rather than hunting for keys we think exist,
# find any run of 3+ "key=value&" pairs and keep the longest one that looks
# like a client launch string. If our key map is wrong, we still capture the
# data and can fix the map later.
# ---------------------------------------------------------------------------

function Find-ScParamBlob {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $hits = $script:BlobRegex.Matches($Text)
    if ($hits.Count -eq 0) { return $null }

    # Prefer a blob that carries a relay host or a recognisable session type.
    $best = $null
    foreach ($m in $hits) {
        if ($m.Value -match '(?i)(^|&)h=' -or $m.Value -match '(?i)(^|&)e=(Access|Support|Meeting)') {
            if ($null -eq $best -or $m.Value.Length -gt $best.Length) { $best = $m.Value }
        }
    }
    if ($null -ne $best) { return $best }

    # Nothing recognisable - hand back the longest candidate so a human can
    # look at it. This is how we learn what we got wrong.
    foreach ($m in $hits) {
        if ($null -eq $best -or $m.Value.Length -gt $best.Length) { $best = $m.Value }
    }
    return $best
}

function ConvertFrom-ScParamBlob {
    param(
        [string]$Blob,
        [ref]$Warnings
    )
    $out = [ordered]@{}
    if ([string]::IsNullOrEmpty($Blob)) { return $out }
    $b = $Blob.Trim()
    $b = $b.TrimStart('?')
    $b = $b.TrimStart('&')
    foreach ($pair in ($b -split '&')) {
        if ([string]::IsNullOrEmpty($pair)) { continue }
        $idx = $pair.IndexOf('=')
        if ($idx -lt 1) { continue }
        $k = $pair.Substring(0, $idx)
        $v = $pair.Substring($idx + 1)
        if (Test-MalformedPercentEncoding -Value $v) {
            if ($Warnings) { $Warnings.Value += ("Malformed percent-encoding in parameter '" + $k + "': '" + $v + "'") }
            # Leave the value as-is (raw) - do not attempt to decode it.
        } else {
            try { $v = [System.Uri]::UnescapeDataString($v) } catch { }
        }
        $out[$k] = $v
    }
    return $out
}

function Get-ScIdentifier {
    # "ScreenConnect Client (a1b2c3d4e5f6)" -> "a1b2c3d4e5f6"
    param([string]$Text)
    if (-not $Text) { return $null }
    $m = [regex]::Match($Text, '(?i)ScreenConnect Client \(([^)]+)\)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-FileFacts {
    param([string]$Path)
    $f = [ordered]@{
        Path = $Path; Exists = $false; SizeBytes = $null
        CreatedUtc = $null; ModifiedUtc = $null
        FileVersion = $null; ProductName = $null; CompanyName = $null
        Sha256 = $null; SignatureStatus = $null; SignerSubject = $null
    }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $f }
    $f.Exists = $true
    try {
        $item = Get-Item -LiteralPath $Path
        $f.SizeBytes   = $item.Length
        $f.CreatedUtc  = $item.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
        $f.ModifiedUtc = $item.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
        $f.FileVersion = $item.VersionInfo.FileVersion
        $f.ProductName = $item.VersionInfo.ProductName
        $f.CompanyName = $item.VersionInfo.CompanyName
    } catch { }
    try { $f.Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $f.SignatureStatus = $sig.Status.ToString()
        if ($sig.SignerCertificate) { $f.SignerSubject = $sig.SignerCertificate.Subject }
    } catch { }
    return $f
}

# ---------------------------------------------------------------------------
# System inventory (isolated so Pester can mock them).
# ---------------------------------------------------------------------------

function Get-SccServiceInventory {
    try {
        return @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Select-Object Name, DisplayName, PathName, State, StartMode, StartName, ProcessId, Description)
    } catch {
        return @()
    }
}

function Get-SccProcessInventory {
    try {
        return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate)
    } catch {
        return @()
    }
}

function Get-SccUninstallInventory {
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $out = [System.Collections.ArrayList]::new()
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        try {
            foreach ($k in (Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
                try {
                    $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                    if (-not $p.DisplayName) { continue }
                    [void]$out.Add([PSCustomObject]@{
                        RegistryKey          = ($k.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
                        KeyName              = $k.PSChildName
                        DisplayName          = $p.DisplayName
                        DisplayVersion       = $p.DisplayVersion
                        Publisher            = $p.Publisher
                        InstallDate          = $p.InstallDate
                        InstallLocation      = $p.InstallLocation
                        UninstallString      = $p.UninstallString
                        QuietUninstallString = $p.QuietUninstallString
                    })
                } catch { }
            }
        } catch { }
    }
    return $out.ToArray()
}

function Get-SccServiceInstallEvents {
    # Event ID 7045 = "A service was installed in the system". Survives the
    # agent being uninstalled, so it can show a removed instance and when it
    # arrived. Needs admin on most builds.
    param([int]$MaxEvents = 400)
    try {
        $evts = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } -MaxEvents $MaxEvents -ErrorAction Stop
        return @($evts | ForEach-Object {
            [PSCustomObject]@{
                TimeUtc = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
                Message = ($_.Message -replace '\s+', ' ').Trim()
            }
        })
    } catch {
        return @()
    }
}

function Get-SccConnectionsForPids {
    param([int[]]$Pids)
    if (-not $Pids -or $Pids.Count -eq 0) { return @() }
    try {
        return @(Get-NetTCPConnection -ErrorAction Stop |
            Where-Object { $Pids -contains $_.OwningProcess } |
            ForEach-Object {
                [PSCustomObject]@{
                    LocalAddress  = $_.LocalAddress
                    LocalPort     = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort    = $_.RemotePort
                    State         = $_.State.ToString()
                    OwningProcess = $_.OwningProcess
                }
            })
    } catch { return @() }
}

function Get-SccScDirs {
    # Wildcard directory match without relying on Get-Item wildcard escaping,
    # which trips over paths like "Program Files (x86)".
    param([string]$Pattern)
    $expanded = Expand-Env $Pattern
    $parent   = Split-Path -Path $expanded -Parent
    $leaf     = Split-Path -Path $expanded -Leaf
    if (-not $parent -or -not (Test-Path -LiteralPath $parent)) { return @() }
    try {
        return @(Get-ChildItem -LiteralPath $parent -Directory -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like $leaf } |
                 ForEach-Object {
                     [PSCustomObject]@{
                         Name            = $_.Name
                         FullName        = $_.FullName
                         CreationTimeUtc  = $_.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
                     }
                 })
    } catch { return @() }
}

# ---------------------------------------------------------------------------
# Config loading (targets + trusted relays)
# ---------------------------------------------------------------------------

function Get-SccModuleConfigDirs {
    # user -> machine -> new-tree config, in that order.
    $dirs = [System.Collections.ArrayList]::new()
    if ($env:LocalAppData) { [void]$dirs.Add((Join-Path $env:LocalAppData 'ScreenConnectCleaner\config')) }
    if ($env:ProgramData) { [void]$dirs.Add((Join-Path $env:ProgramData 'ScreenConnectCleaner\config')) }
    # new-tree config dir relative to this module file.
    $tree = Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'config'
    [void]$dirs.Add($tree)
    return $dirs.ToArray()
}

function Get-SccTargets {
    param([string]$TargetsFile)
    if (-not $TargetsFile) {
        foreach ($d in (Get-SccModuleConfigDirs)) {
            $cand = Join-Path $d 'targets.json'
            if (Test-Path -LiteralPath $cand) { $TargetsFile = $cand; break }
        }
    }
    if ($TargetsFile -and (Test-Path -LiteralPath $TargetsFile)) {
        try {
            $raw = Get-Content -LiteralPath $TargetsFile -Raw -ErrorAction Stop | ConvertFrom-Json
            if ($raw -and $raw.targets) { return $raw.targets }
        } catch { }
    }
    # Embedded fallback.
    $raw = $script:DefaultTargetsJson | ConvertFrom-Json
    return $raw.targets
}

function Get-SccTrustedRelays {
    param([object]$Config)
    if ($null -ne $Config) { return $Config }
    $file = $null
    foreach ($d in (Get-SccModuleConfigDirs)) {
        $cand = Join-Path $d 'trusted-relays.json'
        if (Test-Path -LiteralPath $cand) { $file = $cand; break }
    }
    if ($file) {
        try {
            $raw = Get-Content -LiteralPath $file -Raw -ErrorAction Stop | ConvertFrom-Json
            if ($raw -and $raw.trustedRelays) { return $raw.trustedRelays }
        } catch { }
    }
    # Standalone: empty trusted list.
    return @()
}

# ---------------------------------------------------------------------------
# ScreenConnect instance assembly
# ---------------------------------------------------------------------------

function New-ScInstanceTemplate {
    param([string]$Key)
    $slot = [PSCustomObject]@{
        Key                 = $Key
        Identifier          = $null
        RelayHost           = $null
        ServerKey           = $null
        ServerFingerprint   = $null
        SessionType         = $null
        Role                = $null
        RelayPort           = $null
        SessionId           = $null
        InstallPath         = $null
        ServiceName         = $null
        ServiceDisplayName  = $null
        ServiceState        = $null
        ServiceStartMode    = $null
        ServiceAccount      = $null
        ServiceImagePath    = $null
        ExecutablePath      = $null
        InstallTimestampUtc = $null
        Publisher           = $null
        DisplayVersion      = $null
        SignatureStatus     = $null
        FileVersion         = $null
        ProductVersion      = $null
        RawLaunchParameters = $null
        ParamBlobSource     = $null
        ParsedParameters    = [ordered]@{}
        UnknownParams       = [ordered]@{}
        CustomProperties    = [ordered]@{}
        ParserWarnings      = [System.Collections.ArrayList]::new()
        ParseIssue          = $null
        UninstallDisplayName    = $null
        UninstallString         = $null
        QuietUninstallString    = $null
        UninstallRegistryKey    = $null
        Persistence         = [System.Collections.ArrayList]::new()
        AssociatedProcesses = [System.Collections.ArrayList]::new()
        NetworkConnections  = @()
        ConfigFiles         = [System.Collections.ArrayList]::new()
        Sources             = [System.Collections.ArrayList]::new()
        Confidence          = $null
        TrustMatch          = 'Unknown'
        TrustedRelayEntry   = $null
        DetectionSources    = [System.Collections.ArrayList]::new()
    }
    return $slot
}

function Apply-ScParameters {
    param($Params, $Slot, [ref]$Warnings)
    $Slot.ParsedParameters = $Params
    foreach ($k in @($Params.Keys)) {
        $lk = $k.ToLower()
        if ($script:ScKnownKeys.ContainsKey($lk)) {
            $friendly = $script:ScKnownKeys[$lk]
            if ($friendly -like 'Custom*') { $Slot.CustomProperties[$friendly] = $Params[$k] }
            else { $Slot.$friendly = $Params[$k] }
        } else {
            $Slot.UnknownParams[$k] = $Params[$k]
        }
    }
    if ($Slot.ServerKey) {
        $fp = Get-Sha256Hex $Slot.ServerKey
        if ($fp) { $Slot.ServerFingerprint = $fp.Substring(0, 16) }
    }
}

function Resolve-SccScInstances {
    param(
        $Services,
        $Processes,
        $UninstallEntries,
        $Events,
        $Target,
        [object]$TrustedRelays
    )

    $instances   = [ordered]@{}   # key -> instance object
    $parseIssues = [System.Collections.ArrayList]::new()
    $rawCopied   = [System.Collections.ArrayList]::new()

    function Get-Slot {
        param([string]$Key)
        if (-not $instances.Contains($Key)) { $instances[$Key] = New-ScInstanceTemplate -Key $Key }
        return $instances[$Key]
    }

    # --- 1. Services -------------------------------------------------------
    foreach ($svc in $Services) {
        $isSc = (Test-AnyLike $svc.Name $Target.servicePatterns) -or
                (Test-AnyLike $svc.DisplayName $Target.servicePatterns) -or
                ($svc.PathName -and $svc.PathName -match '(?i)ScreenConnect')
        if (-not $isSc) { continue }

        $ident = Get-ScIdentifier $svc.Name
        if (-not $ident) { $ident = Get-ScIdentifier $svc.DisplayName }
        if (-not $ident) { $ident = Get-ScIdentifier $svc.PathName }
        $key = if ($ident) { $ident } else { "svc:" + $svc.Name }

        $slot = Get-Slot $key
        if ($slot.Sources -notcontains "service") { [void]$slot.Sources.Add("service") }
        $slot.Identifier         = $ident
        $slot.ServiceName        = $svc.Name
        $slot.ServiceDisplayName = $svc.DisplayName
        $slot.ServiceState       = $svc.State
        $slot.ServiceStartMode   = $svc.StartMode
        $slot.ServiceAccount     = $svc.StartName
        $slot.ServiceImagePath   = $svc.PathName

        $blob = Find-ScParamBlob $svc.PathName
        if ($blob) { $slot.RawLaunchParameters = $blob; $slot.ParamBlobSource = "service ImagePath" }

        if ($svc.PathName -and -not $slot.InstallPath) {
            $m = [regex]::Match($svc.PathName, '(?i)\"?([a-z]:\\[^\"]*?ScreenConnect[^\"\\]*)\\([^\"\\]+\.exe)')
            if ($m.Success) {
                $slot.InstallPath = $m.Groups[1].Value
                # Build the exe path by string join: Join-Path chokes on a
                # drive-letter path when this runs on a non-Windows host, and the
                # value is informational here.
                $slot.ExecutablePath = ($m.Groups[1].Value.TrimEnd('\') + '\' + $m.Groups[2].Value)
            }
        }
    }

    # --- 2. Install directories -------------------------------------------
    foreach ($pattern in $Target.pathPatterns) {
        foreach ($dir in (Get-SccScDirs -Pattern $pattern)) {
            $ident = Get-ScIdentifier $dir.Name
            $key   = if ($ident) { $ident } else { "dir:" + $dir.FullName }
            $slot  = Get-Slot $key
            if ($slot.Sources -notcontains "directory") { [void]$slot.Sources.Add("directory") }
            if (-not $slot.Identifier) { $slot.Identifier = $ident }
            if (-not $slot.InstallPath) { $slot.InstallPath = $dir.FullName }
            $slot.InstallTimestampUtc = $dir.CreationTimeUtc
        }
    }

    # --- 3. Uninstall registry entries ------------------------------------
    foreach ($u in $UninstallEntries) {
        if (-not (Test-AnyLike $u.DisplayName $Target.uninstallPatterns)) { continue }
        $ident = Get-ScIdentifier $u.DisplayName
        if (-not $ident) { $ident = Get-ScIdentifier $u.InstallLocation }
        $key = if ($ident) { $ident } else { "reg:" + $u.KeyName }
        $slot = Get-Slot $key
        if ($slot.Sources -notcontains "uninstall-registry") { [void]$slot.Sources.Add("uninstall-registry") }
        if (-not $slot.Identifier) { $slot.Identifier = $ident }
        if (-not $slot.InstallPath -and $u.InstallLocation) { $slot.InstallPath = $u.InstallLocation }
        $slot.Publisher            = $u.Publisher
        $slot.DisplayVersion       = $u.DisplayVersion
        $slot.UninstallDisplayName = $u.DisplayName
        $slot.UninstallString      = $u.UninstallString
        $slot.QuietUninstallString = $u.QuietUninstallString
        $slot.UninstallRegistryKey = $u.RegistryKey
        $slot.InstallTimestampUtc  = if (-not $slot.InstallTimestampUtc) { $u.InstallDate } else { $slot.InstallTimestampUtc }
    }

    # --- 4. Running processes ---------------------------------------------
    foreach ($p in $Processes) {
        $match = (Test-AnyLike $p.Name $Target.processPatterns) -or
                 ($p.ExecutablePath -and $p.ExecutablePath -match '(?i)ScreenConnect')
        if (-not $match) { continue }
        $ident = Get-ScIdentifier $p.ExecutablePath
        if (-not $ident) { $ident = Get-ScIdentifier $p.CommandLine }
        $key = if ($ident) { $ident } else { "proc:" + $p.Name }
        $slot = Get-Slot $key
        if ($slot.Sources -notcontains "process") { [void]$slot.Sources.Add("process") }
        if (-not $slot.Identifier) { $slot.Identifier = $ident }
        if (-not $slot.ExecutablePath) { $slot.ExecutablePath = $p.ExecutablePath }
        [void]$slot.AssociatedProcesses.Add([PSCustomObject]@{
            ProcessId       = $p.ProcessId
            ParentProcessId = $p.ParentProcessId
            Name            = $p.Name
            ExecutablePath  = $p.ExecutablePath
            CommandLine     = $p.CommandLine
            StartedUtc      = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
        })
        if (-not $slot.RawLaunchParameters) {
            $blob = Find-ScParamBlob $p.CommandLine
            if ($blob) { $slot.RawLaunchParameters = $blob; $slot.ParamBlobSource = "process CommandLine" }
        }
    }

    # --- 5. Config files + file facts ------------------------------------
    foreach ($key in @($instances.Keys)) {
        $slot = $instances[$key]
        if ($slot.InstallPath -and (Test-Path -LiteralPath $slot.InstallPath)) {
            $configs = @(Get-ChildItem -LiteralPath $slot.InstallPath -Filter "*.config" -ErrorAction SilentlyContinue)
            foreach ($cfg in $configs) {
                $text = $null
                try { $text = Get-Content -LiteralPath $cfg.FullName -Raw -ErrorAction Stop } catch { }
                [void]$slot.ConfigFiles.Add([PSCustomObject]@{
                    Name        = $cfg.Name
                    Path        = $cfg.FullName
                    SizeBytes   = $cfg.Length
                    ModifiedUtc = $cfg.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
                })
                if (-not $slot.RawLaunchParameters -and $text) {
                    $blob = Find-ScParamBlob $text
                    if ($blob) { $slot.RawLaunchParameters = $blob; $slot.ParamBlobSource = ("config file: " + $cfg.Name) }
                }
            }
        }
        if (-not $slot.ExecutablePath -and $slot.InstallPath -and (Test-Path -LiteralPath $slot.InstallPath)) {
            $exe = @(Get-ChildItem -LiteralPath $slot.InstallPath -Filter "*.exe" -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -match '(?i)ClientService' } | Select-Object -First 1)
            if (-not $exe) {
                $exe = @(Get-ChildItem -LiteralPath $slot.InstallPath -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1)
            }
            if ($exe) { $slot.ExecutablePath = $exe[0].FullName }
        }
        if ($slot.ExecutablePath) {
            $ff = Get-FileFacts -Path $slot.ExecutablePath
            $slot.SignatureStatus = $ff.SignatureStatus
            $slot.FileVersion     = $ff.FileVersion
            $slot.ProductVersion  = $ff.ProductName
        }
        if (-not $slot.InstallTimestampUtc -and $slot.InstallPath -and (Test-Path -LiteralPath $slot.InstallPath)) {
            try { $slot.InstallTimestampUtc = (Get-Item -LiteralPath $slot.InstallPath).CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss") } catch { }
        }
    }

    # --- 6. Parse the blob -------------------------------------------------
    foreach ($key in @($instances.Keys)) {
        $slot = $instances[$key]
        if (-not $slot.RawLaunchParameters) {
            $slot.ParseIssue = "No launch-parameter blob found in service ImagePath, command line, or any .config file"
            [void]$parseIssues.Add([PSCustomObject]@{
                Key              = $slot.Key
                Identifier       = $slot.Identifier
                InstallPath      = $slot.InstallPath
                Issue            = $slot.ParseIssue
                ServiceImagePath = $slot.ServiceImagePath
                ConfigFilesSeen  = @($slot.ConfigFiles | ForEach-Object { $_.Name })
            })
            continue
        }
        $warnings = [System.Collections.ArrayList]::new()
        $params = ConvertFrom-ScParamBlob -Blob $slot.RawLaunchParameters -Warnings ([ref]$warnings)
        foreach ($w in $warnings) { [void]$slot.ParserWarnings.Add($w) }
        Apply-ScParameters -Params $params -Slot $slot -Warnings ([ref]$slot.ParserWarnings)

        if (-not $slot.RelayHost) {
            $slot.ParseIssue = "Blob found and parsed but no relay host - the key map is probably wrong for this build"
            [void]$parseIssues.Add([PSCustomObject]@{
                Key              = $slot.Key
                Identifier       = $slot.Identifier
                InstallPath      = $slot.InstallPath
                Issue            = $slot.ParseIssue
                ParamBlob        = $slot.RawLaunchParameters
                KeysSeen         = @($params.Keys)
            })
        }
    }

    # --- 7. Connections + install events ----------------------------------
    foreach ($key in @($instances.Keys)) {
        $slot = $instances[$key]
        $pids = @($slot.AssociatedProcesses | ForEach-Object { [int]$_.ProcessId })
        $slot.NetworkConnections = Get-SccConnectionsForPids -Pids $pids
        foreach ($e in $Events) {
            if ($e.Message -match '(?i)ScreenConnect') {
                $hit = $false
                if ($slot.Identifier -and $e.Message -match [regex]::Escape($slot.Identifier)) { $hit = $true }
                elseif (-not $slot.Identifier -and $slot.ServiceName -and $e.Message -match [regex]::Escape($slot.ServiceName)) { $hit = $true }
                if ($hit) { [void]$slot.ServiceInstallEvents.Add($e) }
            }
        }
    }

    # --- 8. Historical instances from 7045 not present on disk ------------
    $historical = [System.Collections.ArrayList]::new()
    foreach ($e in $Events) {
        if ($e.Message -notmatch '(?i)ScreenConnect') { continue }
        $ident = Get-ScIdentifier $e.Message
        if ($ident -and $instances.Contains($ident)) { continue }
        [void]$historical.Add([PSCustomObject]@{
            TimeUtc    = $e.TimeUtc
            Identifier = $ident
            Message    = $e.Message
            Note       = "Service install event with no matching live install - possible removed or reinstalled instance"
        })
    }

    # --- 9. Confidence + trust + derived arrays ---------------------------
    foreach ($key in @($instances.Keys)) {
        $slot = $instances[$key]
        $distinct = @($slot.Sources | Sort-Object -Unique).Count
        $hasParseIssue = ($slot.ParserWarnings.Count -gt 0) -or ($null -ne $slot.ParseIssue)
        if ($hasParseIssue -or $distinct -le 1) { $slot.Confidence = 'Low' }
        elseif ($distinct -ge 3) { $slot.Confidence = 'High' }
        else { $slot.Confidence = 'Medium' }

        # Trust matching.
        if ($slot.RelayHost) {
            $tr = Test-SccTrustedRelay -Relay $slot.RelayHost -Instance $slot -Config $TrustedRelays
            $slot.TrustMatch = $tr.TrustMatch
            $slot.TrustedRelayEntry = $tr.Entry
        }

        # Detection sources list.
        if ($slot.Sources -contains "service") {
            [void]$slot.DetectionSources.Add([PSCustomObject]@{ Source = "service"; Key = $slot.ServiceName; Value = $slot.ServiceImagePath })
        }
        if ($slot.Sources -contains "directory") {
            [void]$slot.DetectionSources.Add([PSCustomObject]@{ Source = "directory"; Key = $slot.InstallPath; Value = $slot.InstallTimestampUtc })
        }
        if ($slot.Sources -contains "uninstall-registry") {
            [void]$slot.DetectionSources.Add([PSCustomObject]@{ Source = "uninstall-registry"; Key = $slot.Key; Value = $slot.Publisher })
        }
        if ($slot.Sources -contains "process") {
            foreach ($pr in $slot.AssociatedProcesses) {
                [void]$slot.DetectionSources.Add([PSCustomObject]@{ Source = "process"; Key = $pr.Name; Value = $pr.CommandLine })
            }
        }

        # Persistence summary.
        if ($slot.ServiceName) {
            [void]$slot.Persistence.Add([PSCustomObject]@{ Type = "Service"; Location = $slot.ServiceName; Details = $slot.ServiceImagePath })
        }
        if ($slot.InstallPath) {
            [void]$slot.Persistence.Add([PSCustomObject]@{ Type = "InstallDirectory"; Location = $slot.InstallPath; Details = $slot.InstallTimestampUtc })
        }
        if ($slot.Publisher) {
            [void]$slot.Persistence.Add([PSCustomObject]@{ Type = "UninstallEntry"; Location = $slot.Key; Details = $slot.Publisher })
        }
        foreach ($pr in $slot.AssociatedProcesses) {
            [void]$slot.Persistence.Add([PSCustomObject]@{ Type = "Process"; Location = $pr.Name; Details = $pr.CommandLine })
        }
    }

    return [PSCustomObject]@{
        Instances     = @($instances.Keys | ForEach-Object { $instances[$_] })
        ParseIssues   = $parseIssues.ToArray()
        Historical    = $historical.ToArray()
        RawFilesSaved = $rawCopied.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

function Get-SccScreenConnect {
    [CmdletBinding()]
    param(
        [string]$TargetsFile,
        [int]$IncidentWindowDays,
        [psobject]$Run
    )
    $targets = @(Get-SccTargets -TargetsFile $TargetsFile)
    $scTarget = $null
    foreach ($t in $targets) { if ($t.id -eq 'screenconnect') { $scTarget = $t; break } }
    if ($null -eq $scTarget) {
        # Fallback to embedded default SC definition.
        $scTarget = @($script:DefaultTargetsJson | ConvertFrom-Json).targets | Where-Object { $_.id -eq 'screenconnect' } | Select-Object -First 1
    }

    $services  = Get-SccServiceInventory
    $processes = Get-SccProcessInventory
    $uninstall = Get-SccUninstallInventory
    $events    = Get-SccServiceInstallEvents
    $trusted   = Get-SccTrustedRelays

    $result = Resolve-SccScInstances -Services $services -Processes $processes `
                 -UninstallEntries $uninstall -Events $events -Target $scTarget -TrustedRelays $trusted

    # Public shape: convert internal UnknownParams hashtable to an array and
    # expose the remaining ARCHITECTURE fields directly.
    $pub = [System.Collections.ArrayList]::new()
    foreach ($inst in $result.Instances) {
        $inst | Add-Member -MemberType NoteProperty -Name 'UnknownParameters' -Value @($inst.UnknownParams.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{ Key = $_.Key; Value = $_.Value }
        }) -Force
        [void]$pub.Add($inst)
    }
    return $pub.ToArray()
}

function Get-SccRemoteAccess {
    [CmdletBinding()]
    param(
        [string]$TargetsFile,
        [string[]]$Targets,
        [switch]$All
    )
    $allTargets = @(Get-SccTargets -TargetsFile $TargetsFile)

    if ($Targets -and $Targets.Count -gt 0) {
        $selected = @($allTargets | Where-Object { $Targets -contains $_.id })
    } elseif ($All) {
        $selected = $allTargets
    } else {
        $selected = @($allTargets | Where-Object { $_.enabled -eq $true })
    }
    # Only non-screenconnect (generic) targets.
    $selected = @($selected | Where-Object { $_.id -ne 'screenconnect' })

    $services  = Get-SccServiceInventory
    $processes = Get-SccProcessInventory
    $uninstall = Get-SccUninstallInventory

    $findings = [System.Collections.ArrayList]::new()
    foreach ($t in $selected) {
        $hits = [System.Collections.ArrayList]::new()

        foreach ($svc in $services) {
            if ((Test-AnyLike $svc.Name $t.servicePatterns) -or (Test-AnyLike $svc.DisplayName $t.servicePatterns)) {
                [void]$hits.Add([PSCustomObject]@{
                    Kind = "Service"; Name = $svc.Name; Detail = $svc.DisplayName
                    Path = $svc.PathName; State = $svc.State
                })
            }
        }
        foreach ($p in $processes) {
            if (Test-AnyLike $p.Name $t.processPatterns) {
                [void]$hits.Add([PSCustomObject]@{
                    Kind = "Process"; Name = $p.Name; Detail = ("PID " + $p.ProcessId)
                    Path = $p.ExecutablePath; State = $null
                })
            }
        }
        foreach ($pattern in $t.pathPatterns) {
            foreach ($d in (Get-SccScDirs -Pattern $pattern)) {
                [void]$hits.Add([PSCustomObject]@{
                    Kind = "Directory"; Name = $d.Name
                    Detail = ("created " + $d.CreationTimeUtc + "Z")
                    Path = $d.FullName; State = $null
                })
            }
        }
        foreach ($u in $uninstall) {
            if (Test-AnyLike $u.DisplayName $t.uninstallPatterns) {
                [void]$hits.Add([PSCustomObject]@{
                    Kind = "Uninstall"; Name = $u.DisplayName; Detail = $u.Publisher
                    Path = $u.InstallLocation; State = $null
                })
            }
        }

        [void]$findings.Add([PSCustomObject]@{
            Product  = $t.name
            Id       = $t.id
            Enabled  = [bool]$t.enabled
            Hits     = $hits.ToArray()
            Count    = $hits.Count
        })
    }
    return $findings.ToArray()
}

function Test-SccTrustedRelay {
    [CmdletBinding()]
    param(
        [string]$Relay,
        [psobject]$Instance,
        [object]$Config
    )
    $relays = Get-SccTrustedRelays -Config $Config
    $result = [PSCustomObject]@{ TrustMatch = 'Unknown'; Entry = $null; Relay = $Relay }
    if ([string]::IsNullOrEmpty($Relay)) { return $result }

    foreach ($r in $relays) {
        if ($null -eq $r) { continue }
        $rRelay = if ($r.PSObject.Properties['relay']) { [string]$r.relay } else { '' }
        if (-not $rRelay) { continue }
        if ($rRelay -ieq $Relay) {
            $expectedFp = if ($r.PSObject.Properties['fingerprint']) { [string]$r.fingerprint } else { '' }
            $instFp = if ($null -ne $Instance -and $Instance.PSObject.Properties['ServerFingerprint']) { [string]$Instance.ServerFingerprint } else { '' }
            $match = $true
            if ($expectedFp -and $instFp -and $expectedFp -ne $instFp) { $match = $false }
            if ($match) {
                $result.TrustMatch = 'Known'
                $result.Entry = $r
                return $result
            }
            # Relay matches but fingerprint does not: remember for reporting,
            # but the verdict stays Unknown.
            if ($null -eq $result.Entry) { $result.Entry = $r }
        }
    }
    return $result
}

function Invoke-SccDetection {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [string[]]$Targets,
        [switch]$All
    )
    $screenConnect = @(Get-SccScreenConnect)
    $remoteAccess  = @(Get-SccRemoteAccess -Targets $Targets -All:$All)

    $warnings = [System.Collections.ArrayList]::new()
    foreach ($inst in $screenConnect) {
        foreach ($w in $inst.ParserWarnings) { [void]$warnings.Add($w) }
        if ($inst.ParseIssue) { [void]$warnings.Add($inst.ParseIssue) }
    }

    $findings = [PSCustomObject]@{
        ComputerName   = $env:COMPUTERNAME
        DetectedUtc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        ScreenConnect  = $screenConnect
        RemoteAccess   = $remoteAccess
        Warnings       = $warnings.ToArray()
    }

    if ($Run -and $Run.PSObject.Properties['RunDir'] -and (Test-Path -LiteralPath $Run.RunDir)) {
        $jsonPath = Join-Path $Run.RunDir 'findings.json'
        try {
            $findings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        } catch { }
    }

    return $findings
}

function Invoke-SccDetectionSelfTest {
    [CmdletBinding()]
    param(
        [switch]$ThrowOnFail
    )
    $failures = [System.Collections.ArrayList]::new()

    $scTarget = @($script:DefaultTargetsJson | ConvertFrom-Json).targets | Where-Object { $_.id -eq 'screenconnect' } | Select-Object -First 1

    function Test-Assert {
        param([string]$Name, [scriptblock]$Condition, [string]$Detail)
        try {
            if (-not (& $Condition)) {
                [void]$failures.Add(("FAIL: " + $Name + " - " + $Detail))
            }
        } catch {
            [void]$failures.Add(("FAIL: " + $Name + " - threw: " + $_.Exception.Message))
        }
    }

    # Synthetic samples (made up, not real captures). Prove the parser does
    # what we intend, not that the intent matches reality.
    $samples = @(
        @{ Name = 'service ImagePath (Access / unattended)';
           Text = '"C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=support.example.com&p=8041&s=11111111-2222-3333-4444-555555555555&k=BgIAAACkAABSU0ExAAIAAAEAAQ%3d%3d&c1=Acme%20IT&c2=Site-3&c3=&c4=&c5=&c6=&c7=&c8="' },
        @{ Name = 'config file fragment (Support / one-shot)';
           Text = '<appSettings><add key="a" value="?e=Support&y=Guest&h=relay.badguy.example&p=443&s=99999999-8888-7777-6666-555555555555&k=ZZZZ" /></appSettings>' },
        @{ Name = 'unknown-key blob';
           Text = '?zz=1&qq=hello&h=host.example.net&ww=3' },
        @{ Name = 'no blob present at all';
           Text = '"C:\Program Files (x86)\Something\thing.exe" -service' },
        @{ Name = 'URL-encoded relay';
           Text = '?e=Access&y=Guest&h=relay%2eexample%2ecom&p=8041&s=11111111-2222-3333-4444-555555555555&k=KEY123' },
        @{ Name = 'malformed percent encoding';
           Text = '?e=Access&h=relay%zz%zz.example.com&p=8041' },
        @{ Name = 'value containing equals';
           Text = '?e=Access&h=host.example.com&k=a=b=c' },
        @{ Name = 'empty blob';
           Text = '' },
        @{ Name = 'leading ? and & trimmed';
           Text = '?e=Access&h=host.example.com&k=KEY123' },
        @{ Name = 'leading & trimmed';
           Text = '&e=Support&h=other.example.net&k=KEY456' }
    )

    foreach ($smp in $samples) {
        $warnings = [System.Collections.ArrayList]::new()
        $slot = New-ScInstanceTemplate -Key 'self'
        $blob = Find-ScParamBlob $smp.Text
        if ($smp.Name -eq 'no blob present at all' -or $smp.Name -eq 'empty blob') {
            Test-Assert -Name ($smp.Name + ' / no blob') -Condition { $null -eq $blob } -Detail ("blob was: " + $blob)
            continue
        }
        Test-Assert -Name ($smp.Name + ' / blob found') -Condition { $null -ne $blob } -Detail 'blob was null'
        $params = ConvertFrom-ScParamBlob -Blob $blob -Warnings ([ref]$warnings)
        Apply-ScParameters -Params $params -Slot $slot -Warnings ([ref]$warnings)

        switch ($smp.Name) {
            'service ImagePath (Access / unattended)' {
                Test-Assert -Name 'Access session type' -Condition { $slot.SessionType -eq 'Access' } -Detail $slot.SessionType
                Test-Assert -Name 'relay host' -Condition { $slot.RelayHost -eq 'support.example.com' } -Detail $slot.RelayHost
                Test-Assert -Name 'custom1 decoded' -Condition { $slot.CustomProperties['Custom1'] -eq 'Acme IT' } -Detail $slot.CustomProperties['Custom1']
                Test-Assert -Name 'fingerprint 16 hex' -Condition { $slot.ServerFingerprint -and $slot.ServerFingerprint.Length -eq 16 } -Detail $slot.ServerFingerprint
            }
            'config file fragment (Support / one-shot)' {
                Test-Assert -Name 'Support session type' -Condition { $slot.SessionType -eq 'Support' } -Detail $slot.SessionType
                Test-Assert -Name 'relay host badguy' -Condition { $slot.RelayHost -eq 'relay.badguy.example' } -Detail $slot.RelayHost
                Test-Assert -Name 'server key ZZZZ' -Condition { $slot.ServerKey -eq 'ZZZZ' } -Detail $slot.ServerKey
            }
            'unknown-key blob' {
                Test-Assert -Name 'relay host from h' -Condition { $slot.RelayHost -eq 'host.example.net' } -Detail $slot.RelayHost
                Test-Assert -Name 'unknown preserved zz' -Condition { @($slot.UnknownParams.Keys) -contains 'zz' } -Detail 'zz missing'
                Test-Assert -Name 'unknown preserved ww' -Condition { @($slot.UnknownParams.Keys) -contains 'ww' } -Detail 'ww missing'
            }
            'URL-encoded relay' {
                Test-Assert -Name 'relay decoded' -Condition { $slot.RelayHost -eq 'relay.example.com' } -Detail $slot.RelayHost
            }
            'malformed percent encoding' {
                Test-Assert -Name 'relay kept raw with %zz' -Condition { $slot.RelayHost -and $slot.RelayHost.Contains('%zz') } -Detail $slot.RelayHost
                Test-Assert -Name 'malformed warning recorded' -Condition { $warnings.Count -gt 0 } -Detail 'no warning'
            }
            'value containing equals' {
                Test-Assert -Name 'server key with equals' -Condition { $slot.ServerKey -eq 'a=b=c' } -Detail $slot.ServerKey
            }
            'leading ? and & trimmed' {
                Test-Assert -Name 'relay host trimmed' -Condition { $slot.RelayHost -eq 'host.example.com' } -Detail $slot.RelayHost
                Test-Assert -Name 'session type trimmed' -Condition { $slot.SessionType -eq 'Access' } -Detail $slot.SessionType
            }
            'leading & trimmed' {
                Test-Assert -Name 'relay host trimmed 2' -Condition { $slot.RelayHost -eq 'other.example.net' } -Detail $slot.RelayHost
                Test-Assert -Name 'session type trimmed 2' -Condition { $slot.SessionType -eq 'Support' } -Detail $slot.SessionType
            }
        }
    }

    # Multi-instance deduplication: two services with the same identifier
    # must collapse to a single instance.
    $fakeServices = @(
        [PSCustomObject]@{ Name = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'; DisplayName = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'; PathName = '"C:\x\ScreenConnect Client (a1b2c3d4e5f6a7b8)\Client.exe" "?e=Access&h=a.example.com&k=KEY"'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; ProcessId = 1; Description = '' },
        [PSCustomObject]@{ Name = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'; DisplayName = 'ScreenConnect Client (a1b2c3d4e5f6a7b8)'; PathName = '"C:\y\ScreenConnect Client (a1b2c3d4e5f6a7b8)\Client.exe" "?e=Access&h=a.example.com&k=KEY"'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; ProcessId = 2; Description = '' }
    )
    $resolved = Resolve-SccScInstances -Services $fakeServices -Processes @() -UninstallEntries @() -Events @() -Target $scTarget -TrustedRelays @()
    Test-Assert -Name 'multi-instance dedup -> 1 instance' -Condition { @($resolved.Instances).Count -eq 1 } -Detail ('count=' + @($resolved.Instances).Count)

    if ($ThrowOnFail -and $failures.Count -gt 0) {
        throw ($failures -join "`n")
    }
    return $failures.ToArray()
}

# Export only the public API.
Export-ModuleMember -Function @(
    'Get-SccScreenConnect',
    'Get-SccRemoteAccess',
    'Invoke-SccDetection',
    'Get-SccTrustedRelays',
    'Test-SccTrustedRelay',
    'Invoke-SccDetectionSelfTest'
)
