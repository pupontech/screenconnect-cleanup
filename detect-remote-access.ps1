<#
  detect-remote-access.ps1  -  ScreenConnect cleanup detector (v1.7.36)

  Read-only. Detects remote-access agents on this machine, with a deep module
  for ScreenConnect / ConnectWise Control that tries to extract the INSTANCE
  IDENTITY (relay host, port, session type, server key) - the only thing that
  can tell an authorised install apart from a scammer's, since both are the
  same signed software.

  This detector's identity output is deliberately evidence-first. Its real job is
  to answer one question: "can we reliably pull the relay identity out of a live
  install?"
  So it deliberately captures RAW EVIDENCE (service ImagePath, the .config
  files verbatim) even when parsing succeeds, and reports parse FAILURES
  loudly, so the parser can be corrected from real-world output.

  Nothing is changed, stopped, deleted or quarantined. Detection only.

  Runs standalone: copy just this .ps1 anywhere and it works (targets.json is
  optional - the same defaults are embedded).

  Requires PowerShell 5.1+. Admin is NOT required, but without it some data
  (notably the System event log) may be unavailable; the report says so.
#>

param(
    # Where to write results. A timestamped subfolder is created under here.
    [string]$OutRoot = "$env:USERPROFILE\Desktop\RemoteAccessScan",

    # Only scan these target ids (comma separated). Overrides targets.json.
    [string[]]$Target,

    # Scan every known target, not just the ones enabled in targets.json.
    [switch]$All,

    # Print the target list and exit.
    [switch]$ListTargets,

    # Alternate targets.json path.
    [string]$TargetsFile,

    # Skip zipping the output folder to the Desktop.
    [switch]$NoZip,

    # Don't wait for Enter at the end (for unattended / piped runs).
    [switch]$NoPause,

    # Run the parser against synthetic samples and exit. Proves the extraction
    # logic works without needing a live ScreenConnect install to hand.
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$ScriptVersion = "1.7.36"

# ---------------------------------------------------------------------------
# Embedded target defaults - keeps the script standalone if targets.json is
# absent. targets.json, when present, wins.
# ---------------------------------------------------------------------------
$DefaultTargetsJson = @'
{ "targets": [
  { "id":"screenconnect","name":"ScreenConnect / ConnectWise Control","enabled":true,"deep":true,
    "servicePatterns":["ScreenConnect*"],"processPatterns":["ScreenConnect.*"],
    "pathPatterns":["%ProgramFiles(x86)%\\ScreenConnect Client*","%ProgramFiles%\\ScreenConnect Client*","%ProgramData%\\ScreenConnect*"],
    "uninstallPatterns":["ScreenConnect*","ConnectWise Control*"] },
  { "id":"anydesk","name":"AnyDesk","enabled":false,"deep":false,
    "servicePatterns":["AnyDesk*"],"processPatterns":["AnyDesk*"],
    "pathPatterns":["%ProgramFiles(x86)%\\AnyDesk*","%ProgramFiles%\\AnyDesk*","%ProgramData%\\AnyDesk*","%APPDATA%\\AnyDesk*"],
    "uninstallPatterns":["AnyDesk*"] },
  { "id":"teamviewer","name":"TeamViewer","enabled":false,"deep":false,
    "servicePatterns":["TeamViewer*"],"processPatterns":["TeamViewer*","tv_*"],
    "pathPatterns":["%ProgramFiles(x86)%\\TeamViewer*","%ProgramFiles%\\TeamViewer*"],
    "uninstallPatterns":["TeamViewer*"] },
  { "id":"ultraviewer","name":"UltraViewer","enabled":false,"deep":false,
    "servicePatterns":["UltraViewer*"],"processPatterns":["UltraViewer*"],
    "pathPatterns":["%ProgramFiles(x86)%\\UltraViewer*","%ProgramFiles%\\UltraViewer*"],
    "uninstallPatterns":["UltraViewer*"] },
  { "id":"supremo","name":"Supremo","enabled":false,"deep":false,
    "servicePatterns":["Supremo*"],"processPatterns":["Supremo*"],
    "pathPatterns":["%ProgramFiles(x86)%\\Supremo*","%ProgramFiles%\\Supremo*","%APPDATA%\\Supremo*"],
    "uninstallPatterns":["Supremo*"] },
  { "id":"rustdesk","name":"RustDesk","enabled":false,"deep":false,
    "servicePatterns":["RustDesk*"],"processPatterns":["rustdesk*"],
    "pathPatterns":["%ProgramFiles%\\RustDesk*","%ProgramFiles(x86)%\\RustDesk*","%APPDATA%\\RustDesk*"],
    "uninstallPatterns":["RustDesk*"] },
  { "id":"splashtop","name":"Splashtop (incl. SOS)","enabled":false,"deep":false,
    "servicePatterns":["SplashtopRemoteService*","Splashtop*"],"processPatterns":["SR*Service*","Splashtop*","strwinclt*"],
    "pathPatterns":["%ProgramFiles(x86)%\\Splashtop*","%ProgramFiles%\\Splashtop*"],
    "uninstallPatterns":["Splashtop*"] },
  { "id":"logmein","name":"LogMeIn / GoTo (incl. Rescue)","enabled":false,"deep":false,
    "servicePatterns":["LMIGuardian*","LogMeIn*"],"processPatterns":["LogMeIn*","LMI*","Support-LogMeInRescue*"],
    "pathPatterns":["%ProgramFiles(x86)%\\LogMeIn*","%ProgramFiles%\\LogMeIn*"],
    "uninstallPatterns":["LogMeIn*","GoTo*"] },
  { "id":"zohoassist","name":"Zoho Assist","enabled":false,"deep":false,
    "servicePatterns":["ZohoMeeting*","Zoho*"],"processPatterns":["ZA*","Zoho*"],
    "pathPatterns":["%ProgramFiles(x86)%\\ZohoMeeting*","%ProgramFiles%\\ZohoMeeting*"],
    "uninstallPatterns":["Zoho Assist*","Zoho*"] },
  { "id":"atera","name":"Atera / AteraAgent","enabled":false,"deep":false,
    "servicePatterns":["AteraAgent*"],"processPatterns":["AteraAgent*"],
    "pathPatterns":["%ProgramFiles(x86)%\\ATERA Networks*","%ProgramFiles%\\ATERA Networks*"],
    "uninstallPatterns":["Atera*"] },
  { "id":"dwagent","name":"DWAgent / DWService","enabled":false,"deep":false,
    "servicePatterns":["DWAgent*"],"processPatterns":["dwagent*"],
    "pathPatterns":["%ProgramFiles%\\DWAgent*","%ProgramFiles(x86)%\\DWAgent*"],
    "uninstallPatterns":["DWAgent*","DWService*"] },
  { "id":"meshagent","name":"MeshCentral agent","enabled":false,"deep":false,
    "servicePatterns":["Mesh Agent*","MeshAgent*"],"processPatterns":["MeshAgent*"],
    "pathPatterns":["%ProgramFiles%\\Mesh Agent*","%ProgramFiles(x86)%\\Mesh Agent*"],
    "uninstallPatterns":["Mesh Agent*","MeshCentral*"] },
  { "id":"netsupport","name":"NetSupport Manager","enabled":false,"deep":false,
    "servicePatterns":["Client32*","NetSupport*"],"processPatterns":["client32*","pcicfgui*"],
    "pathPatterns":["%ProgramFiles(x86)%\\NetSupport*","%ProgramFiles%\\NetSupport*"],
    "uninstallPatterns":["NetSupport*"] },
  { "id":"remoteutilities","name":"Remote Utilities","enabled":false,"deep":false,
    "servicePatterns":["RManService*","Remote Utilities*"],"processPatterns":["rutserv*","rfusclient*"],
    "pathPatterns":["%ProgramFiles(x86)%\\Remote Utilities*","%ProgramFiles%\\Remote Utilities*"],
    "uninstallPatterns":["Remote Utilities*"] },
  { "id":"vnc","name":"VNC family (Ultra/Tight/Real/TigerVNC)","enabled":false,"deep":false,
    "servicePatterns":["uvnc*","tvnserver*","vncserver*","RealVNC*"],"processPatterns":["winvnc*","tvnserver*","vncserver*"],
    "pathPatterns":["%ProgramFiles%\\uvnc*","%ProgramFiles%\\TightVNC*","%ProgramFiles%\\RealVNC*","%ProgramFiles(x86)%\\uvnc*","%ProgramFiles(x86)%\\TightVNC*","%ProgramFiles(x86)%\\RealVNC*"],
    "uninstallPatterns":["*VNC*"] }
] }
'@

# ---------------------------------------------------------------------------
# ScreenConnect launch-parameter key map.
#
# ASSUMED, NOT CONFIRMED - this map is exactly what the PoC exists to test.
# Any key not listed here is preserved verbatim under UnknownParams so we can
# learn the real meaning from live output instead of guessing.
# ---------------------------------------------------------------------------
$ScKnownKeys = @{
    'e'  = 'SessionType'      # Access (unattended) / Support (one-shot) / Meeting
    'y'  = 'Role'             # typically Guest
    'h'  = 'RelayHost'        # THE decision key
    'p'  = 'RelayPort'        # default believed to be 8041
    's'  = 'SessionId'
    'k'  = 'ServerPublicKey'  # encoded; corroborates the host
    'c1' = 'Custom1'; 'c2' = 'Custom2'; 'c3' = 'Custom3'; 'c4' = 'Custom4'
    'c5' = 'Custom5'; 'c6' = 'Custom6'; 'c7' = 'Custom7'; 'c8' = 'Custom8'
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
$script:LogLines = New-Object System.Collections.ArrayList

function Write-Log {
    param([string]$Message, [string]$Color = "Gray", [switch]$NoConsole)
    $stamp = (Get-Date).ToString("HH:mm:ss")
    [void]$script:LogLines.Add("[$stamp] $Message")
    if (-not $NoConsole) { Write-Host $Message -ForegroundColor $Color }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("-" * 70) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("-" * 70) -ForegroundColor DarkCyan
    [void]$script:LogLines.Add("")
    [void]$script:LogLines.Add("=== $Title ===")
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

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

function Get-DirsMatching {
    # Wildcard directory match without relying on Get-Item wildcard escaping,
    # which trips over paths like "Program Files (x86)".
    param([string]$Pattern)
    $expanded = Expand-Env $Pattern
    $parent   = Split-Path -Path $expanded -Parent
    $leaf     = Split-Path -Path $expanded -Leaf
    if (-not $parent -or -not (Test-Path -LiteralPath $parent)) { return @() }
    try {
        return @(Get-ChildItem -LiteralPath $parent -Directory -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like $leaf })
    } catch { return @() }
}

function Test-AnyLike {
    param([string]$Value, [string[]]$Patterns)
    if (-not $Value -or -not $Patterns) { return $false }
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
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
$script:BlobRegex = [regex]'(?i)(?:[a-z][a-z0-9]{0,3}=[^&\s"''<>\)]*&){2,}[a-z][a-z0-9]{0,3}=[^&\s"''<>\)]*'

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
    param([string]$Blob)
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
        try { $v = [System.Uri]::UnescapeDataString($v) } catch { }
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
# System inventory (collected once, reused by every target)
# ---------------------------------------------------------------------------
function Get-AllServices {
    try {
        return @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Select-Object Name, DisplayName, PathName, State, StartMode, StartName, ProcessId, Description)
    } catch {
        Write-Log "  ! Could not enumerate services: $($_.Exception.Message)" "Yellow"
        return @()
    }
}

function Get-AllProcesses {
    try {
        return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate)
    } catch {
        Write-Log "  ! Could not enumerate processes: $($_.Exception.Message)" "Yellow"
        return @()
    }
}

function Get-AllUninstallEntries {
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $out = New-Object System.Collections.ArrayList
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

function Get-ServiceInstallEvents {
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
        $script:EventLogError = $_.Exception.Message
        return @()
    }
}

function Get-ConnectionsForPids {
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

# ---------------------------------------------------------------------------
# ScreenConnect deep module
# ---------------------------------------------------------------------------
function Invoke-ScreenConnectModule {
    param($Services, $Processes, $UninstallEntries, $Events, $Target, [string]$RawDir)

    $instances    = [ordered]@{}   # key -> instance hashtable
    $parseIssues  = New-Object System.Collections.ArrayList
    $rawCopied    = New-Object System.Collections.ArrayList

    function Get-Slot {
        param([string]$Key)
        if (-not $instances.Contains($Key)) {
            $instances[$Key] = [ordered]@{
                Key = $Key; Identifier = $null; InstallDir = $null
                Sources = New-Object System.Collections.ArrayList
                ServiceName = $null; ServiceDisplayName = $null; ServiceState = $null
                ServiceStartMode = $null; ServiceAccount = $null; ServiceImagePath = $null
                ParamBlob = $null; ParamBlobSource = $null
                RelayHost = $null; RelayPort = $null; SessionType = $null; Role = $null
                SessionId = $null; ServerPublicKey = $null; ServerKeyFingerprint = $null
                CustomProperties = [ordered]@{}
                UnknownParams    = [ordered]@{}
                AllParams        = [ordered]@{}
                MainExe = $null; File = $null
                InstallDirCreatedUtc = $null
                ConfigFiles = New-Object System.Collections.ArrayList
                UninstallDisplayName = $null; UninstallString = $null
                QuietUninstallString = $null; UninstallRegistryKey = $null
                InstallDate = $null; Publisher = $null; DisplayVersion = $null
                Processes   = New-Object System.Collections.ArrayList
                Connections = @()
                ServiceInstallEvents = New-Object System.Collections.ArrayList
            }
        }
        return $instances[$Key]
    }

    # --- 1. Services -------------------------------------------------------
    Write-Log "  Scanning services..."
    foreach ($svc in $Services) {
        $isSc = (Test-AnyLike $svc.Name $Target.servicePatterns) -or
                (Test-AnyLike $svc.DisplayName $Target.servicePatterns) -or
                ($svc.PathName -and $svc.PathName -match '(?i)ScreenConnect')
        if (-not $isSc) { continue }

        $ident = Get-ScIdentifier $svc.Name
        if (-not $ident) { $ident = Get-ScIdentifier $svc.DisplayName }
        if (-not $ident) { $ident = Get-ScIdentifier $svc.PathName }
        $key = if ($ident) { $ident } else { "svc:$($svc.Name)" }

        $slot = Get-Slot $key
        [void]$slot.Sources.Add("service")
        $slot.Identifier         = $ident
        $slot.ServiceName        = $svc.Name
        $slot.ServiceDisplayName = $svc.DisplayName
        $slot.ServiceState       = $svc.State
        $slot.ServiceStartMode   = $svc.StartMode
        $slot.ServiceAccount     = $svc.StartName
        $slot.ServiceImagePath   = $svc.PathName

        # The service ImagePath is believed to carry the full launch string on
        # many builds - try it first, it is the cheapest source.
        $blob = Find-ScParamBlob $svc.PathName
        if ($blob) { $slot.ParamBlob = $blob; $slot.ParamBlobSource = "service ImagePath" }

        # Derive the install directory from the ImagePath.
        if ($svc.PathName -and -not $slot.InstallDir) {
            $m = [regex]::Match($svc.PathName, '(?i)"?([a-z]:\\[^"]*?ScreenConnect[^"\\]*)\\([^"\\]+\.exe)')
            if ($m.Success) {
                $slot.InstallDir = $m.Groups[1].Value
                $slot.MainExe    = Join-Path $m.Groups[1].Value $m.Groups[2].Value
            }
        }
    }

    # --- 2. Install directories -------------------------------------------
    Write-Log "  Scanning install directories..."
    foreach ($pattern in $Target.pathPatterns) {
        foreach ($dir in (Get-DirsMatching $pattern)) {
            $ident = Get-ScIdentifier $dir.Name
            $key   = if ($ident) { $ident } else { "dir:$($dir.FullName)" }
            $slot  = Get-Slot $key
            if ($slot.Sources -notcontains "directory") { [void]$slot.Sources.Add("directory") }
            if (-not $slot.Identifier) { $slot.Identifier = $ident }
            if (-not $slot.InstallDir) { $slot.InstallDir = $dir.FullName }
            $slot.InstallDirCreatedUtc = $dir.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
        }
    }

    # --- 3. Uninstall registry entries ------------------------------------
    Write-Log "  Scanning uninstall registry entries..."
    foreach ($u in $UninstallEntries) {
        if (-not (Test-AnyLike $u.DisplayName $Target.uninstallPatterns)) { continue }
        $ident = Get-ScIdentifier $u.DisplayName
        if (-not $ident) { $ident = Get-ScIdentifier $u.InstallLocation }
        $key = if ($ident) { $ident } else { "reg:$($u.KeyName)" }
        $slot = Get-Slot $key
        if ($slot.Sources -notcontains "uninstall-registry") { [void]$slot.Sources.Add("uninstall-registry") }
        if (-not $slot.Identifier) { $slot.Identifier = $ident }
        if (-not $slot.InstallDir -and $u.InstallLocation) { $slot.InstallDir = $u.InstallLocation }
        $slot.UninstallDisplayName = $u.DisplayName
        $slot.UninstallString      = $u.UninstallString
        $slot.QuietUninstallString = $u.QuietUninstallString
        $slot.UninstallRegistryKey = $u.RegistryKey
        $slot.InstallDate          = $u.InstallDate
        $slot.Publisher            = $u.Publisher
        $slot.DisplayVersion       = $u.DisplayVersion
    }

    # --- 4. Running processes ---------------------------------------------
    Write-Log "  Scanning running processes..."
    foreach ($p in $Processes) {
        $match = (Test-AnyLike $p.Name $Target.processPatterns) -or
                 ($p.ExecutablePath -and $p.ExecutablePath -match '(?i)ScreenConnect')
        if (-not $match) { continue }
        $ident = Get-ScIdentifier $p.ExecutablePath
        if (-not $ident) { $ident = Get-ScIdentifier $p.CommandLine }
        $key = if ($ident) { $ident } else { "proc:$($p.Name)" }
        $slot = Get-Slot $key
        if ($slot.Sources -notcontains "process") { [void]$slot.Sources.Add("process") }
        if (-not $slot.Identifier) { $slot.Identifier = $ident }
        [void]$slot.Processes.Add([PSCustomObject]@{
            ProcessId       = $p.ProcessId
            ParentProcessId = $p.ParentProcessId
            Name            = $p.Name
            ExecutablePath  = $p.ExecutablePath
            CommandLine     = $p.CommandLine
            StartedUtc      = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
        })
        # A command line can also carry the launch string.
        if (-not $slot.ParamBlob) {
            $blob = Find-ScParamBlob $p.CommandLine
            if ($blob) { $slot.ParamBlob = $blob; $slot.ParamBlobSource = "process CommandLine" }
        }
    }

    # --- 5. Config files + raw evidence -----------------------------------
    Write-Log "  Reading client config files..."
    foreach ($key in @($instances.Keys)) {
        $slot = $instances[$key]
        if (-not $slot.InstallDir -or -not (Test-Path -LiteralPath $slot.InstallDir)) { continue }

        if (-not $slot.MainExe) {
            $exe = Get-ChildItem -LiteralPath $slot.InstallDir -Filter "*.exe" -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match '(?i)ClientService' } | Select-Object -First 1
            if (-not $exe) {
                $exe = Get-ChildItem -LiteralPath $slot.InstallDir -Filter "*.exe" -ErrorAction SilentlyContinue |
                       Select-Object -First 1
            }
            if ($exe) { $slot.MainExe = $exe.FullName }
        }

        $configs = @(Get-ChildItem -LiteralPath $slot.InstallDir -Filter "*.config" -ErrorAction SilentlyContinue)
        foreach ($cfg in $configs) {
            $text = $null
            try { $text = Get-Content -LiteralPath $cfg.FullName -Raw -ErrorAction Stop } catch { }
            [void]$slot.ConfigFiles.Add([PSCustomObject]@{
                Name        = $cfg.Name
                Path        = $cfg.FullName
                SizeBytes   = $cfg.Length
                ModifiedUtc = $cfg.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
            })

            # ALWAYS keep a verbatim copy - this is what lets us fix the
            # parser from real output instead of guessing again.
            if ($text -and $RawDir) {
                $safe = ("{0}__{1}" -f ($slot.Key -replace '[^A-Za-z0-9_.-]', '_'), $cfg.Name)
                $dest = Join-Path $RawDir $safe
                try {
                    Set-Content -LiteralPath $dest -Value $text -Encoding UTF8
                    [void]$rawCopied.Add($dest)
                } catch { }
            }

            if (-not $slot.ParamBlob -and $text) {
                $blob = Find-ScParamBlob $text
                if ($blob) { $slot.ParamBlob = $blob; $slot.ParamBlobSource = "config file: $($cfg.Name)" }
            }
        }

        if ($slot.MainExe) { $slot.File = Get-FileFacts $slot.MainExe }

        if (-not $slot.InstallDirCreatedUtc) {
            try {
                $slot.InstallDirCreatedUtc = (Get-Item -LiteralPath $slot.InstallDir).CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
            } catch { }
        }
    }

    # --- 6. Parse the blob -------------------------------------------------
    foreach ($key in @($instances.Keys)) {
        $slot = $instances[$key]
        if (-not $slot.ParamBlob) {
            [void]$parseIssues.Add([PSCustomObject]@{
                Key              = $slot.Key
                Identifier       = $slot.Identifier
                InstallDir       = $slot.InstallDir
                Issue            = "No launch-parameter blob found in service ImagePath, command line, or any .config file"
                ServiceImagePath = $slot.ServiceImagePath
                ConfigFilesSeen  = @($slot.ConfigFiles | ForEach-Object { $_.Name })
            })
            continue
        }

        $params = ConvertFrom-ScParamBlob $slot.ParamBlob
        $slot.AllParams = $params
        foreach ($k in $params.Keys) {
            $lk = $k.ToLower()
            if ($ScKnownKeys.ContainsKey($lk)) {
                $friendly = $ScKnownKeys[$lk]
                if ($friendly -like 'Custom*') { $slot.CustomProperties[$friendly] = $params[$k] }
                else { $slot[$friendly] = $params[$k] }
            } else {
                $slot.UnknownParams[$k] = $params[$k]
            }
        }

        if ($slot.ServerPublicKey) {
            $fp = Get-Sha256Hex $slot.ServerPublicKey
            if ($fp) { $slot.ServerKeyFingerprint = $fp.Substring(0, 16) }
        }

        if (-not $slot.RelayHost) {
            [void]$parseIssues.Add([PSCustomObject]@{
                Key              = $slot.Key
                Identifier       = $slot.Identifier
                InstallDir       = $slot.InstallDir
                Issue            = "Blob found and parsed but no relay host - the key map is probably wrong for this build"
                ParamBlob        = $slot.ParamBlob
                KeysSeen         = @($params.Keys)
            })
        }
    }

    # --- 7. Connections + install events ----------------------------------
    foreach ($key in @($instances.Keys)) {
        $slot = $instances[$key]
        $pids = @($slot.Processes | ForEach-Object { [int]$_.ProcessId })
        $slot.Connections = Get-ConnectionsForPids $pids
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
    $historical = New-Object System.Collections.ArrayList
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

    return [PSCustomObject]@{
        Instances     = @($instances.Keys | ForEach-Object { $instances[$_] })
        ParseIssues   = $parseIssues.ToArray()
        Historical    = $historical.ToArray()
        RawFilesSaved = $rawCopied.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Generic presence-only module (every non-deep target)
# ---------------------------------------------------------------------------
function Invoke-GenericModule {
    param($Services, $Processes, $UninstallEntries, $Target)

    $hits = New-Object System.Collections.ArrayList

    foreach ($svc in $Services) {
        if ((Test-AnyLike $svc.Name $Target.servicePatterns) -or (Test-AnyLike $svc.DisplayName $Target.servicePatterns)) {
            [void]$hits.Add([PSCustomObject]@{
                Kind = "service"; Name = $svc.Name; Detail = $svc.DisplayName
                Path = $svc.PathName; State = $svc.State; StartMode = $svc.StartMode
            })
        }
    }
    foreach ($p in $Processes) {
        if (Test-AnyLike $p.Name $Target.processPatterns) {
            [void]$hits.Add([PSCustomObject]@{
                Kind = "process"; Name = $p.Name; Detail = "PID $($p.ProcessId)"
                Path = $p.ExecutablePath; State = $null; StartMode = $null
            })
        }
    }
    foreach ($pattern in $Target.pathPatterns) {
        foreach ($d in (Get-DirsMatching $pattern)) {
            [void]$hits.Add([PSCustomObject]@{
                Kind = "directory"; Name = $d.Name
                Detail = "created " + $d.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss") + "Z"
                Path = $d.FullName; State = $null; StartMode = $null
            })
        }
    }
    foreach ($u in $UninstallEntries) {
        if (Test-AnyLike $u.DisplayName $Target.uninstallPatterns) {
            [void]$hits.Add([PSCustomObject]@{
                Kind = "installed-program"; Name = $u.DisplayName; Detail = $u.Publisher
                Path = $u.InstallLocation; State = $null; StartMode = $null
            })
        }
    }

    return $hits.ToArray()
}

# ===========================================================================
# MAIN
# ===========================================================================
$transcriptPath = "$env:USERPROFILE\Desktop\detect-remote-access_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').log"
try { Start-Transcript -Path $transcriptPath -Force | Out-Null } catch { }

$script:RunExitCode = 0
try {
    # Clear-Host touches $Host.UI.RawUI.CursorPosition, which throws
    # "The handle is invalid" when stdout is not a real console (CI runners,
    # redirected output). Guard it so non-interactive runs still work.
    try { Clear-Host } catch { }
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "   Remote Access Agent Detector  (PROOF OF CONCEPT $ScriptVersion)" -ForegroundColor Cyan
    Write-Host "   READ-ONLY - nothing is stopped, changed or removed" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""

    # --- Self test ---------------------------------------------------------
    # SYNTHETIC samples in the format we BELIEVE ScreenConnect uses. These are
    # made up, not captured from a real install - they prove the parser does
    # what we intend, NOT that the intent matches reality. Only a live test
    # can do that.
    if ($SelfTest) {
        $samples = @(
            @{ Name = 'service ImagePath (Access / unattended)'
               Text = '"C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6a7b8)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=support.example.com&p=8041&s=11111111-2222-3333-4444-555555555555&k=BgIAAACkAABSU0ExAAIAAAEAAQ%3d%3d&c1=Acme%20IT&c2=Site-3&c3=&c4=&c5=&c6=&c7=&c8="' }
            @{ Name = 'config file fragment (Support / one-shot)'
               Text = '<appSettings><add key="a" value="?e=Support&y=Guest&h=relay.badguy.example&p=443&s=99999999-8888-7777-6666-555555555555&k=ZZZZ" /></appSettings>' }
            @{ Name = 'unknown-key blob (map is wrong on purpose)'
               Text = '?zz=1&qq=hello&h=host.example.net&ww=3' }
            @{ Name = 'no blob present at all'
               Text = '"C:\Program Files (x86)\Something	hing.exe" -service' }
        )

        Write-Host "Parser self-test (SYNTHETIC samples - not real captures)" -ForegroundColor Cyan
        $fail = 0
        foreach ($smp in $samples) {
            Write-Host ""
            Write-Host ("  " + $smp.Name) -ForegroundColor White
            $blob = Find-ScParamBlob $smp.Text
            if (-not $blob) {
                Write-Host "    blob        : (none found)" -ForegroundColor DarkYellow
                continue
            }
            Write-Host ("    blob        : {0}" -f $blob) -ForegroundColor DarkGray
            $prm = ConvertFrom-ScParamBlob $blob
            $known = @(); $unknown = @()
            foreach ($k in $prm.Keys) {
                if ($ScKnownKeys.ContainsKey($k.ToLower())) {
                    $known += ("{0}({1})={2}" -f $ScKnownKeys[$k.ToLower()], $k, $prm[$k])
                } else { $unknown += ("{0}={1}" -f $k, $prm[$k]) }
            }
            foreach ($kv in $known)   { Write-Host ("    mapped      : {0}" -f $kv) -ForegroundColor Gray }
            if ($unknown.Count -gt 0) { Write-Host ("    UNMAPPED    : {0}" -f ($unknown -join ', ')) -ForegroundColor DarkYellow }
            $ident = Get-ScIdentifier $smp.Text
            if ($ident) { Write-Host ("    identifier  : {0}" -f $ident) -ForegroundColor Gray }
        }
        Write-Host ""
        Write-Host "  Reminder: passing this proves the CODE is consistent with our" -ForegroundColor Yellow
        Write-Host "  ASSUMPTIONS. It does not prove the assumptions are right." -ForegroundColor Yellow
        return
    }

    # --- Load targets ---
    $targetsRaw = $null
    $targetsSrc = "embedded defaults"
    if (-not $TargetsFile) { $TargetsFile = Join-Path $PSScriptRoot "targets.json" }
    if ($TargetsFile -and (Test-Path -LiteralPath $TargetsFile)) {
        try {
            $targetsRaw = (Get-Content -LiteralPath $TargetsFile -Raw) | ConvertFrom-Json
            $targetsSrc = $TargetsFile
        } catch {
            Write-Host "  ! targets.json is unreadable ($($_.Exception.Message)) - using embedded defaults" -ForegroundColor Yellow
        }
    }
    if (-not $targetsRaw) { $targetsRaw = $DefaultTargetsJson | ConvertFrom-Json }
    $allTargets = @($targetsRaw.targets)

    if ($ListTargets) {
        Write-Host "Targets (source: $targetsSrc)" -ForegroundColor Cyan
        Write-Host ""
        foreach ($t in $allTargets) {
            $mark = if ($t.enabled) { "[on ]" } else { "[off]" }
            $deep = if ($t.deep) { " (deep module)" } else { "" }
            Write-Host ("  {0}  {1,-18} {2}{3}" -f $mark, $t.id, $t.name, $deep)
        }
        Write-Host ""
        Write-Host "Enable/disable by editing targets.json, or use -Target id1,id2 / -All" -ForegroundColor DarkGray
        return
    }

    # --- Which targets are we running? ---
    # powershell.exe -File passes "a,b" as a single token rather than an array,
    # so the .bat launcher would otherwise break. Split defensively.
    if ($Target) {
        $Target = @($Target |
                    ForEach-Object { $_ -split ',' } |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ })
    }

    if ($Target -and $Target.Count -gt 0) {
        $selected = @($allTargets | Where-Object { $Target -contains $_.id })
        $unknown  = @($Target | Where-Object { $id = $_; -not ($allTargets | Where-Object { $_.id -eq $id }) })
        foreach ($u in $unknown) { Write-Host "  ! Unknown target id: $u" -ForegroundColor Yellow }
    } elseif ($All) {
        $selected = $allTargets
    } else {
        $selected = @($allTargets | Where-Object { $_.enabled })
    }
    if ($selected.Count -eq 0) {
        Write-Host "  ! No targets selected. Try -ListTargets." -ForegroundColor Yellow
        return
    }

    $isAdmin = Test-IsAdmin
    if (-not $isAdmin) {
        Write-Host "  NOTE: not running as administrator. Service and registry data are" -ForegroundColor Yellow
        Write-Host "        usually still readable, but the System event log (service" -ForegroundColor Yellow
        Write-Host "        install history) probably is not. Re-run elevated for the" -ForegroundColor Yellow
        Write-Host "        full picture." -ForegroundColor Yellow
        Write-Host ""
    }

    # --- Output folder ---
    $stamp   = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $outDir  = Join-Path $OutRoot "$env:COMPUTERNAME`_$stamp"
    $rawDir  = Join-Path $outDir "raw"
    New-Item -ItemType Directory -Path $rawDir -Force | Out-Null

    Write-Log "Output folder: $outDir" "Gray"
    Write-Log "Targets source: $targetsSrc" "Gray"
    Write-Log ("Targets selected: " + (($selected | ForEach-Object { $_.id }) -join ", ")) "Gray"

    # --- Inventory ---
    Write-Section "Collecting system inventory"
    $script:EventLogError = $null
    $services  = Get-AllServices;        Write-Log ("  services:           {0}" -f $services.Count)
    $processes = Get-AllProcesses;       Write-Log ("  processes:          {0}" -f $processes.Count)
    $uninstall = Get-AllUninstallEntries;Write-Log ("  installed programs: {0}" -f $uninstall.Count)
    $events    = Get-ServiceInstallEvents
    if ($script:EventLogError) {
        Write-Log ("  service-install events: UNAVAILABLE ({0})" -f $script:EventLogError) "Yellow"
    } else {
        Write-Log ("  service-install events (7045): {0}" -f $events.Count)
    }

    # Raw inventory dumps - cheap, and useful when something is missed.
    try {
        $services  | Export-Csv (Join-Path $rawDir "services.csv") -NoTypeInformation -Encoding UTF8
        $processes | Export-Csv (Join-Path $rawDir "processes.csv") -NoTypeInformation -Encoding UTF8
        $uninstall | Export-Csv (Join-Path $rawDir "installed-programs.csv") -NoTypeInformation -Encoding UTF8
        if ($events.Count -gt 0) { $events | Export-Csv (Join-Path $rawDir "service-install-events-7045.csv") -NoTypeInformation -Encoding UTF8 }
    } catch { Write-Log "  ! Could not write a raw dump: $($_.Exception.Message)" "Yellow" }

    # --- Run modules ---
    $scResult      = $null
    $genericResult = New-Object System.Collections.ArrayList

    foreach ($t in $selected) {
        Write-Section ("Target: {0}  [{1}]" -f $t.name, $t.id)
        if ($t.deep -and $t.id -eq "screenconnect") {
            $scResult = Invoke-ScreenConnectModule -Services $services -Processes $processes `
                        -UninstallEntries $uninstall -Events $events -Target $t -RawDir $rawDir
            Write-Log ("  instances found: {0}" -f @($scResult.Instances).Count) "White"
        } else {
            $hits = @(Invoke-GenericModule -Services $services -Processes $processes `
                      -UninstallEntries $uninstall -Target $t)
            Write-Log ("  artifacts found: {0}" -f $hits.Count) "White"
            [void]$genericResult.Add([PSCustomObject]@{ Id = $t.id; Name = $t.name; Hits = $hits; Count = $hits.Count })
        }
    }

    # --- Console report: ScreenConnect ---
    if ($scResult) {
        Write-Section "ScreenConnect instances"
        if (@($scResult.Instances).Count -eq 0) {
            Write-Host "  None found." -ForegroundColor Green
            [void]$script:LogLines.Add("  None found.")
        }
        foreach ($i in $scResult.Instances) {
            Write-Host ""
            Write-Host ("  Instance: {0}" -f $(if ($i.Identifier) { $i.Identifier } else { $i.Key })) -ForegroundColor White
            $rows = @(
                @("Install dir",     $i.InstallDir),
                @("Found via",       ($i.Sources -join ", ")),
                @("Service",         $i.ServiceName),
                @("Service state",   "$($i.ServiceState) / $($i.ServiceStartMode) / $($i.ServiceAccount)"),
                @("RELAY HOST",      $i.RelayHost),
                @("Relay port",      $i.RelayPort),
                @("Session type",    $i.SessionType),
                @("Role",            $i.Role),
                @("Session id",      $i.SessionId),
                @("Server key f/p",  $i.ServerKeyFingerprint),
                @("Blob source",     $i.ParamBlobSource),
                @("Dir created",     $i.InstallDirCreatedUtc),
                @("Uninstall entry", $i.UninstallDisplayName),
                @("Version",         $i.DisplayVersion),
                @("Publisher",       $i.Publisher)
            )
            foreach ($r in $rows) {
                if ($null -eq $r[1] -or "$($r[1])".Trim() -eq "" -or "$($r[1])" -eq " /  / ") { continue }
                $color = if ($r[0] -eq "RELAY HOST") { "Yellow" } else { "Gray" }
                $line = "    {0,-16} {1}" -f ($r[0] + ":"), $r[1]
                Write-Host $line -ForegroundColor $color
                [void]$script:LogLines.Add($line)
            }
            if ($i.File -and $i.File.SignatureStatus) {
                $line = "    {0,-16} {1} ({2})" -f "Signature:", $i.File.SignatureStatus, $i.File.SignerSubject
                Write-Host $line -ForegroundColor Gray
                [void]$script:LogLines.Add($line)
            }
            foreach ($cp in $i.CustomProperties.Keys) {
                if (-not $i.CustomProperties[$cp]) { continue }
                $line = "    {0,-16} {1}" -f ("$cp" + ":"), $i.CustomProperties[$cp]
                Write-Host $line -ForegroundColor Gray
                [void]$script:LogLines.Add($line)
            }
            if ($i.UnknownParams.Count -gt 0) {
                $line = "    {0,-16} {1}" -f "Unmapped keys:", (($i.UnknownParams.Keys) -join ", ")
                Write-Host $line -ForegroundColor DarkYellow
                [void]$script:LogLines.Add($line)
            }
            if (@($i.Connections).Count -gt 0) {
                foreach ($c in $i.Connections) {
                    $line = "    {0,-16} {1}:{2} -> {3}:{4} [{5}]" -f "Connection:", $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State
                    Write-Host $line -ForegroundColor Gray
                    [void]$script:LogLines.Add($line)
                }
            }
        }

        if (@($scResult.ParseIssues).Count -gt 0) {
            Write-Section "PARSE PROBLEMS - send these back so the parser can be fixed"
            foreach ($p in $scResult.ParseIssues) {
                Write-Host ("  [{0}] {1}" -f $(if ($p.Identifier) { $p.Identifier } else { $p.Key }), $p.Issue) -ForegroundColor Red
                [void]$script:LogLines.Add("  PARSE ISSUE [$($p.Key)]: $($p.Issue)")
            }
            Write-Host ""
            Write-Host "  The raw\ folder has the verbatim config files - that is what we need." -ForegroundColor Yellow
        }

        if (@($scResult.Historical).Count -gt 0) {
            Write-Section "Historical service installs (7045) with no live install"
            foreach ($h in $scResult.Historical) {
                $line = "  {0}  {1}" -f $h.TimeUtc, $(if ($h.Identifier) { $h.Identifier } else { "(no identifier parsed)" })
                Write-Host $line -ForegroundColor Yellow
                [void]$script:LogLines.Add($line)
            }
        }
    }

    # --- Console report: other targets ---
    foreach ($g in $genericResult) {
        if (@($g.Hits).Count -eq 0) { continue }
        Write-Section ("Other target: {0}" -f $g.Name)
        foreach ($h in $g.Hits) {
            $line = "    {0,-18} {1}  {2}" -f $h.Kind, $h.Name, $h.Path
            Write-Host $line -ForegroundColor Gray
            [void]$script:LogLines.Add($line)
        }
    }

    # --- Write results ---
    $result = [PSCustomObject]@{
        Tool            = "detect-remote-access.ps1"
        Version         = $ScriptVersion
        RunId           = (Split-Path -Leaf $outDir)
        GeneratedUtc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        ComputerName    = $env:COMPUTERNAME
        RunAsUser       = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin         = $isAdmin
        OSCaption       = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        PSVersion       = $PSVersionTable.PSVersion.ToString()
        TargetsSource   = $targetsSrc
        TargetsSelected = @($selected | ForEach-Object { $_.id })
        EventLogError   = $script:EventLogError
        ScreenConnect   = $scResult
        OtherTargets    = $genericResult.ToArray()
    }

    $jsonPath = Join-Path $outDir "findings.json"
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $sumPath = Join-Path $outDir "SUMMARY.txt"
    Set-Content -LiteralPath $sumPath -Value ($script:LogLines -join "`r`n") -Encoding UTF8

    Write-Section "Done"
    $scCount = 0
    if ($scResult) { $scCount = @($scResult.Instances).Count }
    $otherCount = 0
    foreach ($g in $genericResult) { $otherCount += @($g.Hits).Count }

    Write-Host ("  ScreenConnect instances : {0}" -f $scCount) -ForegroundColor $(if ($scCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host ("  Other target artifacts  : {0}" -f $otherCount) -ForegroundColor $(if ($otherCount -gt 0) { "Yellow" } else { "Green" })
    if ($scResult -and @($scResult.ParseIssues).Count -gt 0) {
        Write-Host ("  PARSE PROBLEMS          : {0}  <-- needs attention" -f @($scResult.ParseIssues).Count) -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  Results: $outDir" -ForegroundColor Cyan

    # --- Zip to Desktop (same convention as the log pullers) ---
    if (-not $NoZip) {
        $zipPath = "$env:USERPROFILE\Desktop\RemoteAccessScan_$env:COMPUTERNAME`_$stamp.zip"
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
            [System.IO.Compression.ZipFile]::CreateFromDirectory($outDir, $zipPath)
            Write-Host "  Zip:     $zipPath" -ForegroundColor Cyan
        } catch {
            Write-Host "  ! Could not create the zip: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Write-Host ""

} catch {
    Write-Host ""
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    $script:RunExitCode = 1
} finally {
    try { Stop-Transcript | Out-Null } catch { }
    if (-not $NoPause) {
        Write-Host ""
        Read-Host "Press Enter to close"
    }
}

# Surface failure to the caller (sc-cleanup.ps1 checks the exit code). Without
# this the catch above swallowed the error and the script always returned 0.
exit $script:RunExitCode
