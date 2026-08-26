# =====================================================================
# Scc.Core.psm1  -  Foundation module for ScreenConnect Cleaner (GUI)
#
# Provides: config, paths, runs, run-state, structured logging, computer
# info, network probes, per-process caches, file facts, safe JSON, and the
# stage-0 preflight logic (Invoke-SccPreflightStage).
#
# PowerShell 5.1 compatible. Pure ASCII, no BOM. No emoji.
# =====================================================================

Set-StrictMode -Version 1.0

# Cache registry (per-process). Key -> { Value; ExpiresUtc }.
$script:SccCache = @{}

# Resolved config cache (set by Get-SccConfig).
$script:SccConfig = $null

# Computer info cache (per-process).
$script:SccComputerInfo = $null

# Stage name table (0 Preflight .. 8 Report).
$script:SccStages = @(
    'Preflight',
    'SnapshotBefore',
    'Detection',
    'Review',
    'Remediate',
    'Scanners',
    'SnapshotAfter',
    'Compare',
    'Report'
)

# ---------------------------------------------------------------------
# Embedded default configuration (mirrors config/scc-config.json)
# ---------------------------------------------------------------------
$script:SccDefaultConfigJson = @'
{
  "SchemaVersion": 1,
  "nas": {
    "enabled": true,
    "path": "\\\\NAS\\TechnicianTools\\Security",
    "priorityOrder": ["local", "nas", "official"],
    "timeoutSeconds": 15
  },
  "paths": {
    "reportRoot": "%USERPROFILE%\\Documents\\ScreenConnect Cleanup\\Reports",
    "programData": "%ProgramData%\\ScreenConnectCleaner",
    "userData": "%LocalAppData%\\ScreenConnectCleaner"
  },
  "scanners": {
    "enabled": ["Defender", "KVRT", "MSERT"],
    "order": ["Defender", "KVRT", "MSERT"],
    "attended": ["AdwCleaner", "ESETOnline", "Malwarebytes"],
    "defaultTimeoutMinutes": 120
  },
  "download": {
    "allowed": true,
    "maxAttempts": 2,
    "timeoutSeconds": 300
  },
  "detection": {
    "incidentWindowDays": 7,
    "defaultTargets": ["screenconnect"]
  },
  "logging": {
    "level": "INFO",
    "retentionDays": 90
  },
  "safety": {
    "serverOsRefusal": true,
    "dryRunDefault": true,
    "removableProducts": ["screenconnect"]
  },
  "evidence": {
    "retentionDays": 30
  },
  "ui": {
    "confirmDestructive": true,
    "language": "en"
  }
}
'@

$script:SccDefaultTrustedRelaysJson = @'
{
  "trustedRelays": [
    {
      "relay": "support.example.com",
      "name": "Example MSP (rename or remove)",
      "fingerprint": "",
      "notes": "Company-managed ScreenConnect server."
    }
  ]
}
'@

# ---------------------------------------------------------------------
# Logging level ordering
# ---------------------------------------------------------------------
$script:SccLevelOrder = @{
    'TRACE'    = 0
    'DEBUG'    = 1
    'INFO'     = 2
    'WARNING'  = 3
    'ERROR'    = 4
    'CRITICAL' = 5
}

function Get-SccLevelRank {
    param([string]$Level)
    $l = ($Level -replace '[^A-Za-z]', '').ToUpper()
    if ($script:SccLevelOrder.ContainsKey($l)) { return $script:SccLevelOrder[$l] }
    return 2
}

# =====================================================================
# Resolve-SccEnv  -  expand %VAR% placeholders (portable)
# =====================================================================
function Resolve-SccEnv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Text
    )
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return [System.Environment]::ExpandEnvironmentVariables($Text)
}

# =====================================================================
# ConvertTo-SccJson / ConvertFrom-SccJson  -  safe JSON helpers
# =====================================================================
function ConvertTo-SccJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $InputObject,
        [int]$Depth = 10
    )
    # Always serialize via -InputObject so single-element arrays stay arrays
    # (the classic PowerShell pipeline-unwrap bug is avoided). We call
    # ConvertTo-Json directly (not via a splat) because splatting an array
    # value for -InputObject unrolls it. -MaxJsonLength is intentionally
    # omitted: it exists in Windows PowerShell 5.1 but not in PowerShell
    # (Core); the 2 MB default is ample for our payloads.
    try {
        return (ConvertTo-Json -InputObject $InputObject -Depth $Depth -Compress)
    } catch {
        # Last-resort fallback: stringify.
        return (ConvertTo-Json -InputObject ([string]$InputObject) -Compress -Depth 1)
    }
}

function ConvertFrom-SccJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-SccLog -Level WARNING -Stage 'Core' -Component 'Scc.Core' -Operation 'ConvertFrom-SccJson' -Message ("File not found: {0}" -f $Path)
        return $null
    }
    try {
        $raw = [System.IO.File]::ReadAllText($Path)
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return (ConvertFrom-Json -InputObject $raw)
    } catch {
        Write-SccLog -Level WARNING -Stage 'Core' -Component 'Scc.Core' -Operation 'ConvertFrom-SccJson' -Message ("Failed to parse JSON: {0}" -f $_.Exception.Message)
        return $null
    }
}

# =====================================================================
# Config merge helper
# =====================================================================
function Merge-SccConfig {
    param($Base, $Override)
    if ($null -eq $Override) { return $Base }
    if (($Base -is [PSCustomObject]) -and ($Override -is [PSCustomObject])) {
        foreach ($p in $Override.PSObject.Properties) {
            $existing = $null
            if ($Base.PSObject.Properties[$p.Name]) { $existing = $Base.PSObject.Properties[$p.Name].Value }
            $merged = Merge-SccConfig -Base $existing -Override $p.Value
            if ($Base.PSObject.Properties[$p.Name]) {
                $Base.PSObject.Properties[$p.Name].Value = $merged
            } else {
                $Base.PSObject.Properties.Add((New-Object PSNoteProperty($p.Name, $merged)))
            }
        }
        return $Base
    }
    return $Override
}

# =====================================================================
# Get-SccConfig  -  defaults merged with user/machine/-Path overrides
# =====================================================================
function Get-SccConfig {
    [CmdletBinding()]
    param(
        [string]$Path
    )

    $config = (ConvertFrom-Json -InputObject $script:SccDefaultConfigJson)

    # Attach embedded trusted-relays default.
    $config | Add-Member -MemberType NoteProperty -Name 'trustedRelays' -Value (ConvertFrom-Json -InputObject $script:SccDefaultTrustedRelaysJson).trustedRelays

    $files = @()

    # Machine file (lowest precedence of the file overrides).
    $machineDir = Join-Path (Resolve-SccEnv -Text '%ProgramData%\ScreenConnectCleaner') 'config'
    $files += (Join-Path $machineDir 'scc-config.json')

    # User file.
    $userDir = Join-Path (Resolve-SccEnv -Text '%LocalAppData%\ScreenConnectCleaner') 'config'
    $files += (Join-Path $userDir 'scc-config.json')

    # Explicit -Path (highest precedence).
    if ($Path) { $files += $Path }

    foreach ($f in $files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try {
            $text = [System.IO.File]::ReadAllText($f)
            $parsed = ConvertFrom-Json -InputObject $text
            if ($parsed -is [PSCustomObject]) {
                $config = Merge-SccConfig -Base $config -Override $parsed
            } else {
                Write-SccLog -Level WARNING -Stage 'Core' -Component 'Scc.Core' -Operation 'Get-SccConfig' -Message ("Config file is not a JSON object; ignored, using defaults: $f")
            }
        } catch {
            Write-SccLog -Level WARNING -Stage 'Core' -Component 'Scc.Core' -Operation 'Get-SccConfig' -Message ("Malformed config JSON ignored, using defaults: {0} ({1})" -f $f, $_.Exception.Message)
        }
    }

    # Try to load a real trusted-relays.json if present (override embedded).
    foreach ($tr in @((Join-Path $userDir 'trusted-relays.json'), (Join-Path $machineDir 'trusted-relays.json'))) {
        if (Test-Path -LiteralPath $tr) {
            try {
                $trp = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tr))
                if ($trp.trustedRelays) { $config.trustedRelays = $trp.trustedRelays }
            } catch { }
        }
    }

    $script:SccConfig = $config
    return $config
}

# =====================================================================
# Set-SccConfigValue  -  write a config value to user or machine scope
# =====================================================================
function Set-SccConfigValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        $Value,
        [switch]$UserScope,
        [switch]$MachineScope
    )

    $config = Get-SccConfig

    # Navigate dotted name, building intermediate objects as needed.
    $segments = $Name -split '\.'
    $node = $config
    for ($i = 0; $i -lt ($segments.Count - 1); $i++) {
        $seg = $segments[$i]
        if (-not $node.PSObject.Properties[$seg]) {
            $node.PSObject.Properties.Add((New-Object PSNoteProperty($seg, (New-Object PSCustomObject))))
        }
        $node = $node.PSObject.Properties[$seg].Value
    }
    $leaf = $segments[$segments.Count - 1]
    if ($node.PSObject.Properties[$leaf]) {
        $node.PSObject.Properties[$leaf].Value = $Value
    } else {
        $node.PSObject.Properties.Add((New-Object PSNoteProperty($leaf, $Value)))
    }

    if ($MachineScope) {
        $dir = Join-Path (Resolve-SccEnv -Text '%ProgramData%\ScreenConnectCleaner') 'config'
        $file = Join-Path $dir 'scc-config.json'
    } else {
        $dir = Join-Path (Resolve-SccEnv -Text '%LocalAppData%\ScreenConnectCleaner') 'config'
        $file = Join-Path $dir 'scc-config.json'
    }

    if (-not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }
    if ($PSCmdlet.ShouldProcess($file, 'Write config value')) {
        [System.IO.File]::WriteAllText($file, (ConvertTo-SccJson -InputObject $config -Depth 10), [System.Text.Encoding]::ASCII)
    }
    $script:SccConfig = $config
}

# =====================================================================
# Get-SccPaths  -  computed path object
# =====================================================================
function Get-SccPaths {
    [CmdletBinding()]
    param(
        [psobject]$Run
    )

    $config = Get-SccConfig

    $programDataDir = Resolve-SccEnv -Text $config.paths.programData
    $userDataDir    = Resolve-SccEnv -Text $config.paths.userData
    $reportRoot     = Resolve-SccEnv -Text $config.paths.reportRoot

    $obj = [PSCustomObject]@{
        AppBinDir       = $PSScriptRoot
        ProgramDataDir  = $programDataDir
        UserDataDir     = $userDataDir
        ReportRoot      = $reportRoot
        ToolCacheDir    = Join-Path $userDataDir 'tools'
        ConfigUserDir   = Join-Path $userDataDir 'config'
        ConfigMachineDir = Join-Path $programDataDir 'config'
        LogRoot         = Join-Path $programDataDir 'logs'
        TempDir         = Join-Path (Resolve-SccEnv -Text '%TEMP%\ScreenConnectCleaner') ''
        QuarantineRoot  = Join-Path $programDataDir 'Quarantine'
    }

    if ($Run -and $Run.RunId) {
        $obj.TempDir = Join-Path $obj.TempDir $Run.RunId
        $obj.QuarantineRoot = Join-Path $obj.QuarantineRoot $Run.RunId
    }

    return $obj
}

# =====================================================================
# Get-SccComputerInfo  -  cached per process
# =====================================================================
function Get-SccComputerInfo {
    [CmdletBinding()]
    param()

    if ($script:SccComputerInfo) { return $script:SccComputerInfo }

    $isWindows = ($env:OS -eq 'Windows_NT')

    $computerName = $env:COMPUTERNAME
    if (-not $computerName) { $computerName = $env:HOSTNAME }
    if (-not $computerName) {
        try { $computerName = [System.Net.Dns]::GetHostName() } catch { $computerName = 'unknown' }
    }

    $osCaption = 'Non-Windows'
    $osVersion = ''
    $isServer = $false
    $currentUser = $env:USERNAME
    if (-not $currentUser) { $currentUser = $env:USER }
    $domain = $env:USERDOMAIN
    if (-not $domain) { $domain = 'WORKGROUP' }

    $freeSpaceGB = -1
    $totalMemoryGB = -1
    $uptimeMinutes = -1
    $architecture = if ([System.Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }

    if ($isWindows) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $osCaption = $os.Caption
            $osVersion = $os.Version
            $isServer = ($osCaption -match '(?i)windows\s+server')
            $freeSpaceGB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
            $totalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
            $boot = $os.LastBootUpTime
            $uptimeMinutes = [math]::Round(((Get-Date) - $boot).TotalMinutes, 1)
        } catch { }
    } else {
        $osCaption = ("Non-Windows ({0} {1})" -f $PSVersionTable.Platform, $PSVersionTable.OS)
        try {
            $drive = New-Object System.IO.DriveInfo('/')
            $freeSpaceGB = [math]::Round($drive.AvailableFreeSpace / 1GB, 1)
        } catch { }
        try {
            $mem = [System.IO.File]::ReadAllText('/proc/meminfo')
            $m = [regex]::Match($mem, 'MemTotal:\s+(\d+)\s*kB')
            if ($m.Success) { $totalMemoryGB = [math]::Round([int]$m.Groups[1].Value / 1MB, 1) }
        } catch { }
        try {
            $up = [System.IO.File]::ReadAllText('/proc/uptime')
            $parts = $up -split '\s+'
            $uptimeMinutes = [math]::Round([double]$parts[0] / 60, 1)
        } catch { }
    }

    $info = [PSCustomObject]@{
        ComputerName   = $computerName
        OsCaption      = $osCaption
        OsVersion      = $osVersion
        Architecture   = $architecture
        CurrentUser    = $currentUser
        IsAdmin        = (Test-SccAdmin)
        FreeSpaceGB    = $freeSpaceGB
        TotalMemoryGB  = $totalMemoryGB
        IsServer       = $isServer
        Domain         = $domain
        UptimeMinutes  = $uptimeMinutes
    }

    $script:SccComputerInfo = $info
    return $info
}

# =====================================================================
# Test-SccAdmin  -  elevation check (portable)
# =====================================================================
function Test-SccAdmin {
    [CmdletBinding()]
    param()
    if ($env:OS -eq 'Windows_NT') {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch {
            return $false
        }
    }
    return $false
}

# =====================================================================
# Get-SccCache / Set-SccCache  -  per-process cache registry
# =====================================================================
function Get-SccCache {
    [CmdletBinding()]
    param(
        [string]$Key
    )
    if ($Key) {
        if ($script:SccCache.ContainsKey($Key)) {
            $entry = $script:SccCache[$Key]
            if ($entry.ExpiresUtc -lt (Get-Date)) {
                $script:SccCache.Remove($Key)
                return $null
            }
            return $entry.Value
        }
        return $null
    }
    return $script:SccCache
}

function Set-SccCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Value,
        [int]$TtlSeconds = 3600
    )
    $script:SccCache[$Key] = @{
        Value      = $Value
        ExpiresUtc = (Get-Date).AddSeconds($TtlSeconds)
    }
}

# =====================================================================
# Get-SccFileFacts  -  cached file metadata + hash + signature
# =====================================================================
function Get-SccNormalizedPath {
    param([string]$Path)
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        try { return [System.IO.Path]::GetFullPath($Path) } catch { }
    }
    return $Path
}

function Get-SccFileFacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [int]$TtlSeconds = 3600
    )

    $norm = Get-SccNormalizedPath -Path $Path
    $cacheKey = ('filefacts:' + $norm)
    $cached = Get-SccCache -Key $cacheKey
    if ($null -ne $cached) { return $cached }

    $facts = [PSCustomObject]@{
        Path            = $Path
        Exists          = $false
        Size            = $null
        SHA256          = $null
        FileVersion     = ''
        ProductVersion  = ''
        Publisher       = ''
        SignatureStatus = 'NotChecked'
        SignatureCert   = ''
        LastWriteUtc    = $null
        CreationUtc     = $null
        Architecture    = ''
    }

    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $facts.Exists = $true
        try {
            $item = Get-Item -LiteralPath $Path
            $facts.Size = $item.Length
            $facts.LastWriteUtc = $item.LastWriteTimeUtc.ToString('o')
            $facts.CreationUtc = $item.CreationTimeUtc.ToString('o')
            $vi = $item.VersionInfo
            $facts.FileVersion = if ($vi.FileVersion) { $vi.FileVersion } else { '' }
            $facts.ProductVersion = if ($vi.ProductVersion) { $vi.ProductVersion } else { '' }
        } catch { }

        try {
            $facts.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch { }

        try {
            if ($env:OS -eq 'Windows_NT') {
                $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
                $facts.SignatureStatus = $sig.Status.ToString()
                if ($sig.SignerCertificate) {
                    $facts.Publisher = $sig.SignerCertificate.Subject
                    $facts.SignatureCert = $sig.SignerCertificate.Thumbprint
                }
            } else {
                $facts.SignatureStatus = 'NotChecked'
            }
        } catch {
            $facts.SignatureStatus = 'Error'
        }
    }

    Set-SccCache -Key $cacheKey -Value $facts -TtlSeconds $TtlSeconds
    return $facts
}

# =====================================================================
# Write-SccLog  -  structured JSONL + master.log
# =====================================================================
function Write-SccLog {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [Parameter(Mandatory = $true)]
        [ValidateSet('TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [Parameter(Mandatory = $true)]
        [string]$Component,
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        $Data
    )

    # Threshold from config (already cached by Get-SccConfig when available).
    $threshold = 2
    if ($script:SccConfig -and $script:SccConfig.logging -and $script:SccConfig.logging.level) {
        $threshold = Get-SccLevelRank -Level $script:SccConfig.logging.level
    }
    $msgRank = Get-SccLevelRank -Level $Level
    if ($msgRank -lt $threshold) { return }

    $ts = (Get-Date).ToString('o')
    $runId = if ($Run -and $Run.RunId) { $Run.RunId } else { $null }

    $line = [PSCustomObject]@{
        ts        = $ts
        runId     = $runId
        level     = $Level
        stage     = $Stage
        component = $Component
        operation = $Operation
        message   = $Message
        data      = $Data
    }

    $jsonl = $null
    try { $jsonl = (ConvertTo-SccJson -InputObject $line -Depth 10) } catch { $jsonl = $null }
    if ($null -eq $jsonl) {
        $jsonl = ('{"ts":"' + $ts + '","level":"' + $Level + '","stage":"' + $Stage + '","message":"' + $Message.Replace('"', '') + '"}')
    }

    if ($Run -and $Run.RunDir) {
        $logDir = Join-Path $Run.RunDir 'logs'
    } else {
        $logDir = Join-Path (Resolve-SccEnv -Text '%ProgramData%\ScreenConnectCleaner') 'logs'
    }
    if (-not (Test-Path -LiteralPath $logDir)) {
        try { $null = New-Item -ItemType Directory -Path $logDir -Force } catch { return }
    }

    $jsonlFile = Join-Path $logDir ($Stage + '.jsonl')
    $masterFile = Join-Path $logDir 'master.log'

    $plain = ('{0} [{1}] {2}/{3}/{4}: {5}' -f $ts, $Level, $Stage, $Component, $Operation, $Message)
    try {
        Add-Content -LiteralPath $jsonlFile -Value $jsonl -Encoding ASCII
        Add-Content -LiteralPath $masterFile -Value $plain -Encoding ASCII
    } catch { }
}

# =====================================================================
# Run id + run directory
# =====================================================================
function Get-SccRunId {
    $hostName = $env:COMPUTERNAME
    if (-not $hostName) { $hostName = $env:HOSTNAME }
    if (-not $hostName) {
        try { $hostName = [System.Net.Dns]::GetHostName() } catch { $hostName = 'HOST' }
    }
    $hostName = $hostName.ToUpperInvariant()
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $hostName.ToCharArray()) {
        $bad = $false
        foreach ($ic in $invalid) { if ($c -eq $ic) { $bad = $true; break } }
        if (-not $bad) { $null = $sb.Append($c) } else { $null = $sb.Append('_') }
    }
    $hostName = $sb.ToString()
    if ($hostName.Length -gt 20) { $hostName = $hostName.Substring(0, 20) }
    if ([string]::IsNullOrEmpty($hostName)) { $hostName = 'HOST' }

    $stamp = (Get-Date).ToString('yyyyMMdd')
    $time = (Get-Date).ToString('HHmmss')
    return ('SC-{0}-{1}-{2}' -f $stamp, $hostName, $time)
}

function New-SccRun {
    [CmdletBinding()]
    param(
        [string]$IncidentDate,
        [string]$Technician,
        [string]$Client,
        [switch]$ForceServer,
        [string]$ReportRoot
    )

    $config = Get-SccConfig
    $info = Get-SccComputerInfo

    if ($info.IsServer -and -not $ForceServer -and $config.safety.serverOsRefusal) {
        throw 'Server OS detected and refused by safety.serverOsRefusal. Pass -ForceServer to override.'
    }

    if (-not $ReportRoot) {
        $ReportRoot = (Get-SccPaths).ReportRoot
    }
    $ReportRoot = Resolve-SccEnv -Text $ReportRoot

    $runId = Get-SccRunId
    $runDir = Join-Path $ReportRoot $runId

    $subDirs = @('evidence', 'snapshots', 'scanner-results', 'logs', 'quarantine-meta')
    if (-not (Test-Path -LiteralPath $runDir)) {
        $null = New-Item -ItemType Directory -Path $runDir -Force
    }
    foreach ($s in $subDirs) {
        $null = New-Item -ItemType Directory -Path (Join-Path $runDir $s) -Force
    }

    if (-not $IncidentDate) { $IncidentDate = (Get-Date).ToString('yyyy-MM-dd') }

    $run = [PSCustomObject]@{
        RunId        = $runId
        RunDir       = $runDir
        ReportRoot   = $ReportRoot
        IncidentDate = $IncidentDate
        Technician   = $Technician
        Client       = $Client
        CreatedUtc   = (Get-Date).ToString('o')
    }

    $stages = @()
    foreach ($name in $script:SccStages) {
        $stages += [PSCustomObject]@{
            Name      = $name
            Status    = 'Pending'
            StartedUtc = $null
            EndedUtc  = $null
            Detail    = $null
            Skippable = $false
        }
    }
    $runState = [PSCustomObject]@{
        RunId      = $runId
        CreatedUtc = $run.CreatedUtc
        Stages     = $stages
    }
    $stateFile = Join-Path $runDir 'runstate.json'
    [System.IO.File]::WriteAllText($stateFile, (ConvertTo-SccJson -InputObject $runState -Depth 10), [System.Text.Encoding]::ASCII)

    return $run
}

# =====================================================================
# Save-SccRunState / Get-SccRunState / Find-SccRecentRuns
# =====================================================================
function Save-SccRunState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Run,
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Completed', 'Interrupted', 'Pending', 'Failed', 'Skipped')]
        [string]$Status,
        [string]$Detail
    )

    $stateFile = Join-Path $Run.RunDir 'runstate.json'
    if (-not (Test-Path -LiteralPath $stateFile)) { return }
    $state = ConvertFrom-SccJson -Path $stateFile
    if (-not $state) { return }

    foreach ($st in $state.Stages) {
        if ($st.Name -eq $Stage) {
            $st.Status = $Status
            if ($Detail) { $st.Detail = $Detail }
            if ($Status -eq 'Pending') {
                $st.StartedUtc = $null
                $st.EndedUtc = $null
            } else {
                if (-not $st.StartedUtc) { $st.StartedUtc = (Get-Date).ToString('o') }
                if ($Status -in @('Completed', 'Interrupted', 'Failed', 'Skipped')) {
                    $st.EndedUtc = (Get-Date).ToString('o')
                }
            }
            break
        }
    }

    [System.IO.File]::WriteAllText($stateFile, (ConvertTo-SccJson -InputObject $state -Depth 10), [System.Text.Encoding]::ASCII)
}

function Get-SccRunState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunId,
        [string]$ReportRoot
    )
    $root = if ($ReportRoot) { Resolve-SccEnv -Text $ReportRoot } else { Resolve-SccEnv -Text (Get-SccPaths).ReportRoot }
    $stateFile = Join-Path (Join-Path $root $RunId) 'runstate.json'
    if (-not (Test-Path -LiteralPath $stateFile)) { return $null }
    return (ConvertFrom-SccJson -Path $stateFile)
}

function Find-SccRecentRuns {
    [CmdletBinding()]
    param(
        [int]$MaxAgeDays = 7,
        [string]$ReportRoot
    )
    $root = if ($ReportRoot) { Resolve-SccEnv -Text $ReportRoot } else { Resolve-SccEnv -Text (Get-SccPaths).ReportRoot }
    $results = @()
    if (-not (Test-Path -LiteralPath $root)) { return $results }

    $cutoff = (Get-Date).AddDays(-$MaxAgeDays)
    try {
        $dirs = Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop |
            Where-Object { $_.Name -like 'SC-*' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'runstate.json')) }
    } catch { return $results }

    foreach ($d in $dirs) {
        $created = $d.CreationTimeUtc
        if ($created -lt $cutoff) { continue }
        $state = ConvertFrom-SccJson -Path (Join-Path $d.FullName 'runstate.json')
        $overall = 'Pending'
        if ($state -and $state.Stages) {
            $last = $null
            foreach ($st in $state.Stages) { $last = $st.Status }
            $overall = $last
        }
        $results += [PSCustomObject]@{
            RunId      = $d.Name
            RunDir     = $d.FullName
            CreatedUtc = $created.ToString('o')
            OverallStatus = $overall
        }
    }

    $results = @($results | Sort-Object CreatedUtc -Descending)
    return $results
}

# =====================================================================
# Test-SccInternet
# =====================================================================
function Test-SccInternet {
    [CmdletBinding()]
    param(
        [int]$TimeoutSeconds = 10
    )
    $result = [PSCustomObject]@{ Reachable = $false; Detail = $null }
    try {
        $resp = Invoke-WebRequest -Method Head -Uri 'https://www.microsoft.com' -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop
        $result.Reachable = $true
        $result.Detail = ('HTTP {0}' -f [int]$resp.StatusCode)
    } catch {
        $result.Reachable = $false
        $result.Detail = $_.Exception.Message
    }
    return $result
}

# =====================================================================
# Test-SccNas
# =====================================================================
function Test-SccNas {
    [CmdletBinding()]
    param(
        [string]$NasPath
    )
    $result = [PSCustomObject]@{ Reachable = $false; Path = $NasPath; Error = $null }

    if ([string]::IsNullOrWhiteSpace($NasPath)) {
        $result.Error = 'No NAS path supplied'
        return $result
    }

    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $NasPath
    } catch {
        $result.Error = $_.Exception.Message
    }

    if ($exists) {
        $result.Reachable = $true
        return $result
    }

    # Not found. On non-Windows we cannot truly probe a network (UNC) share,
    # so report 'unknown' for remote paths; for local/missing paths report false.
    $isWindows = ($env:OS -eq 'Windows_NT')
    if (-not $isWindows -and ($NasPath -match '^\\\\' -or $NasPath -match '^//')) {
        $result.Reachable = 'unknown'
        $result.Error = 'Non-Windows host cannot probe remote share'
    } else {
        $result.Reachable = $false
        $result.Error = 'Path not found'
    }
    return $result
}

# =====================================================================
# Invoke-SccSafe  -  wrap a section; never let one fail kill the run
# =====================================================================
function Invoke-SccSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [Parameter(Mandatory = $true)]
        [string]$Component,
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        [int]$Throttle = 0,
        [psobject]$Run
    )

    $start = Get-Date
    Write-SccLog -Run $Run -Level DEBUG -Stage $Stage -Component $Component -Operation $Operation -Message 'Enter'

    try {
        $result = & $ScriptBlock
        $dur = (New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds
        Write-SccLog -Run $Run -Level DEBUG -Stage $Stage -Component $Component -Operation $Operation -Message ('Exit ok in {0:0.00}s' -f $dur)
        return $result
    } catch {
        $dur = (New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds
        $msg = $_.Exception.Message
        Write-SccLog -Run $Run -Level ERROR -Stage $Stage -Component $Component -Operation $Operation -Message ('Failed in {0:0.00}s: {1}' -f $dur, $msg)
        if ($Run) {
            try { Save-SccRunState -Run $Run -Stage $Stage -Status Failed -Detail $msg } catch { }
        }
        return $null
    }
}

# =====================================================================
# Invoke-SccPreflightStage  -  stage 0 logic (private helper, exported)
# =====================================================================
function Invoke-SccPreflightStage {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [int]$MinFreeGB = 10,
        [switch]$ForceServer
    )

    $config = Get-SccConfig
    $info = Get-SccComputerInfo

    $checks = @()
    $ok = $true

    # Admin check
    $adminCheck = [PSCustomObject]@{ Check = 'Admin'; Passed = $info.IsAdmin; Detail = if ($info.IsAdmin) { 'Running elevated' } else { 'Not running elevated' } }
    $checks += $adminCheck
    if (-not $info.IsAdmin -and ($env:OS -eq 'Windows_NT')) {
        $ok = $false
        $adminCheck.Detail = 'Not running elevated (required on Windows)'
    }

    # OS role check
    $serverCheck = [PSCustomObject]@{ Check = 'ServerOs'; Passed = (-not $info.IsServer); Detail = $info.OsCaption }
    $checks += $serverCheck
    if ($info.IsServer -and -not $ForceServer -and $config.safety.serverOsRefusal) {
        $ok = $false
        $serverCheck.Passed = $false
        $serverCheck.Detail = 'Windows Server refused by safety.serverOsRefusal; pass -ForceServer to override'
    }

    # Disk space
    $diskCheck = [PSCustomObject]@{ Check = 'DiskSpace'; Passed = ($info.FreeSpaceGB -ge $MinFreeGB); Detail = ('{0} GB free (min {1})' -f $info.FreeSpaceGB, $MinFreeGB) }
    $checks += $diskCheck
    if ($info.FreeSpaceGB -lt 0) {
        $diskCheck.Passed = $true
        $diskCheck.Detail = 'Could not determine free disk space (warning only)'
    } elseif ($info.FreeSpaceGB -lt $MinFreeGB) {
        $ok = $false
    }

    # Restore point + hive export: skipped silently on non-Windows.
    $restoreCheck = [PSCustomObject]@{ Check = 'RestorePoint'; Passed = $true; Detail = 'Skipped (non-Windows host)' }
    if ($env:OS -eq 'Windows_NT') {
        $restoreCheck.Detail = 'Not attempted by Core (Remedy stage owns restore point)'
    }
    $checks += $restoreCheck

    # Tool status snapshot via Scc.Tools if importable, else empty.
    $toolStatus = @()
    try {
        $toolsModule = Get-Module -Name Scc.Tools -ErrorAction SilentlyContinue
        if (-not $toolsModule) {
            $toolsModule = Get-Module -Name Scc.Tools -ListAvailable -ErrorAction SilentlyContinue
        }
        if ($toolsModule) {
            $toolStatus = @(Get-SccToolStatus -Run $Run -ErrorAction SilentlyContinue)
        }
    } catch {
        $toolStatus = @()
    }
    $toolCheck = [PSCustomObject]@{ Check = 'ToolStatus'; Passed = $true; Detail = ('{0} tool(s) reported' -f @($toolStatus).Count) }
    $checks += $toolCheck

    foreach ($c in $checks) {
        Write-SccLog -Run $Run -Level INFO -Stage 'Preflight' -Component 'Scc.Core' -Operation 'Invoke-SccPreflightStage' -Message ('Check {0}: {1} - {2}' -f $c.Check, $c.Passed, $c.Detail)
    }

    return [PSCustomObject]@{
        Ok          = $ok
        Admin       = $info.IsAdmin
        IsServer    = $info.IsServer
        OsCaption   = $info.OsCaption
        FreeSpaceGB = $info.FreeSpaceGB
        ToolStatus  = $toolStatus
        Checks      = $checks
    }
}

# ---------------------------------------------------------------------
# Export public API
# ---------------------------------------------------------------------
Export-ModuleMember -Function `
    Get-SccConfig,
    Set-SccConfigValue,
    Get-SccPaths,
    New-SccRun,
    Save-SccRunState,
    Get-SccRunState,
    Find-SccRecentRuns,
    Write-SccLog,
    Get-SccComputerInfo,
    Test-SccInternet,
    Test-SccNas,
    Get-SccCache,
    Set-SccCache,
    Get-SccFileFacts,
    Resolve-SccEnv,
    Invoke-SccSafe,
    ConvertTo-SccJson,
    ConvertFrom-SccJson,
    Invoke-SccPreflightStage
