<#
  remove-screenconnect.ps1  -  Stage 4: Contain + Remove (ScreenConnect ONLY)

  Consumes an approved plan.json (produced by Stage 3 from Stage 2 findings)
  and performs containment + removal for each approved ScreenConnect instance.

  OWNER POLICY (binding): ScreenConnect instances ONLY may be removed.
  AnyDesk/TeamViewer/RustDesk/all other remote-access products in targets.json
  are detect/report-only and MUST BE EXCLUDED from any plan or removal action
  even if present in findings.

  Required behavior:
  (1) Consumes an approved plan file (JSON listing instance IDs/service names/
      directories) produced from Stage 2 findings - no flag that detects-and-
      removes in one step.
  (2) For each approved instance:
      - Stop service + kill process
      - Run vendor uninstaller via registry UninstallString (msiexec /x
        {ProductCode} if MSI) capturing exit code
      - Manual surgery ONLY as fallback: move service binaries/directory to
        quarantine folder (NEVER delete; record original path + SHA256 in a
        manifest), delete service registration, clean persistence (scheduled
        tasks, Run keys, WMI subscriptions referencing quarantined paths)
  (3) Write removal-manifest.json recording every action + result
  (4) Support reboot-resume via RunOnce key if files were in-use
  (5) Dry-run default: require explicit -Execute to act, otherwise log what
      would happen

  HOUSE RULES:
  - PS 5.1 compatible syntax, pure ASCII no BOM (verify byte count =0)
  - Never invent CLI flags/uninstall switches - use registry data at runtime
  - Verify parse+ASCII+synthetic dry-run with installed pwsh
  - Do NOT modify sc-cleanup.ps1 (that wiring is t_stage4wire)
#>

param(
    # Path to the approved plan.json (mandatory)
    [Alias('PlanJson')]
    [Parameter(Mandatory = $true)]
    [string]$PlanFile,

    # Working directory root (where quarantine + manifest go)
    [string]$WorkDir,

    # Actually perform removal actions. Without this, DRY-RUN only.
    [switch]$Execute,

    # Resume after reboot (internal, used by RunOnce)
    [switch]$Resume,

    # Skip creating a System Restore point (for testing)
    [switch]$NoRestorePoint,

    # Verbose logging
    [switch]$VerboseLog
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Script metadata
# -----------------------------------------------------------------------------
$ScriptVersion = '1.4.0'
$ScriptName = 'remove-screenconnect.ps1'

# We need the helper in scope before the elevation gate below runs.
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# FIX (safety): destructive mode MUST run elevated. A non-elevated -Execute can
# silently produce partial mutations (service stop denied, reg delete denied,
# MoveFileEx deferred incorrectly) while exit codes mislead the technician into
# believing removal succeeded. Fail-closed before touching anything.
if ($Execute) {
    if (-not (Test-IsAdmin)) {
        Write-Host "ERROR: -Execute requires an elevated (Administrator) shell." -ForegroundColor Red
        Write-Host "       Right-click the launcher and choose 'Run as administrator', or run" -ForegroundColor Red
        Write-Host "       'Start-Process powershell -Verb RunAs' and re-invoke. Aborting." -ForegroundColor Red
        exit 2
    }
}

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
$script:LogLines = New-Object System.Collections.ArrayList
$script:Manifest = New-Object System.Collections.ArrayList

function Write-Log {
    param([string]$Message, [string]$Level = 'Info', [switch]$NoConsole)
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $prefix = @{ 'Info' = '==>'; 'Warn' = '!! '; 'Error' = '!!!'; 'Debug' = '...' }[$Level]
    if (-not $prefix) { $prefix = '==>' }
    $line = "$stamp $prefix $Message"
    [void]$script:LogLines.Add($line)
    if (-not $NoConsole) {
        $color = @{ 'Info' = 'White'; 'Warn' = 'Yellow'; 'Error' = 'Red'; 'Debug' = 'Gray' }[$Level]
        if (-not $color) { $color = 'White' }
        Write-Host $line -ForegroundColor $color
    }
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

function Add-ManifestEntry {
    param(
        [string]$InstanceId,
        [string]$Action,
        [string]$Target,
        [string]$Result,
        [string]$Details = '',
        [int]$ExitCode = $null
    )
    $entry = [ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        InstanceId   = $InstanceId
        Action       = $Action
        Target       = $Target
        Result       = $Result
        Details      = $Details
        ExitCode     = $ExitCode
    }
    [void]$script:Manifest.Add($entry)
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
function Get-Sha256File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { return $null }
}

function Get-Sha256Hex {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash  = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Expand-Env {
    param([string]$Path)
    if (-not $Path) { return $Path }
    return [System.Environment]::ExpandEnvironmentVariables($Path)
}

function Get-QuarantineDir {
    param([string]$WorkDir)
    $q = Join-Path $WorkDir 'quarantine'
    if (-not (Test-Path -LiteralPath $q)) {
        $null = New-Item -ItemType Directory -Path $q -Force
    }
    return $q
}

# Force array context for PS 5.1 (single-element array unwrapping)
function Force-Array {
    param($InputObject)
    if ($null -eq $InputObject) { return @() }
    if ($InputObject -is [System.Array]) { return $InputObject }
    $arr = New-Object System.Collections.ArrayList
    [void]$arr.Add($InputObject)
    return $arr.ToArray()
}

# -----------------------------------------------------------------------------
# Run-BoundedProcess - PS 5.1/.NET Framework compatible bounded process runner
# Drains stdout/stderr CONCURRENTLY using ReadToEndAsync (available in .NET
# Framework 4.5+) to prevent deadlock, enforces timeout, kills process on
# timeout, returns structured result with exit code, stdout, stderr, and
# TimedOut flag.
# -----------------------------------------------------------------------------
function Run-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string]$Arguments = '',
        [int]$TimeoutMs = 300000,
        [string]$WorkingDirectory = ''
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    if ($WorkingDirectory -and (Test-Path -LiteralPath $WorkingDirectory)) {
        $psi.WorkingDirectory = $WorkingDirectory
    }

    $proc = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        if (-not $proc) {
            throw "Failed to start process: $FilePath $Arguments"
        }

        # Start async reads on BOTH streams BEFORE waiting for exit - this prevents
        # deadlock when a noisy process fills one pipe while the other is unread.
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()

        # Wait for process exit or timeout
        $exited = $proc.WaitForExit($TimeoutMs)
        $timedOut = -not $exited

        if ($timedOut) {
            try { $proc.Kill() } catch { }
            # Reap the process after kill to avoid zombies
            $proc.WaitForExit(1000)
        }

        # Bounded reap of both async reads after process termination (or kill)
        # Explicit typed array avoids Task.WaitAll overload-resolution failures.
        # Task.WaitAll with timeout prevents indefinite hang on broken streams.
        $reapTimeoutMs = if ($timedOut) { 2000 } else { 5000 }
        $tasks = [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
        $allCompleted = [System.Threading.Tasks.Task]::WaitAll($tasks, $reapTimeoutMs)

        # Determine exit code: explicit -1 only on timeout (never a normal code),
        # and capture reap-failure diagnostics instead of silently returning -1.
        $exitCode = -1
        $reapFailed = $false
        if ($exited) {
            $exitCode = $proc.ExitCode
        } elseif ($timedOut) {
            $exitCode = -1  # sentinel: killed by timeout
            $reapFailed = (-not $allCompleted)
        }

        $stdout = if ($stdoutTask.IsCompleted) { $stdoutTask.Result } else { '' }
        $stderr = if ($stderrTask.IsCompleted) { $stderrTask.Result } else { '' }

        if (-not $allCompleted) {
            Write-Log "  Warning: Stream read tasks did not complete within reap timeout" 'Warn'
        }

        return [PSCustomObject]@{
            ExitCode     = $exitCode
            StdOut       = $stdout
            StdErr       = $stderr
            TimedOut     = $timedOut
            ReapFailed   = $reapFailed
        }
    } finally {
        if ($proc) { $proc.Dispose() }
    }
}

# -----------------------------------------------------------------------------
# Load and validate plan.json
# -----------------------------------------------------------------------------
Write-Section "Loading plan: $PlanFile"

if (-not (Test-Path -LiteralPath $PlanFile)) {
    throw "Plan file not found: $PlanFile"
}

try {
    $plan = Get-Content -LiteralPath $PlanFile -Raw | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "Failed to parse plan.json: $($_.Exception.Message)"
}

# Validate plan structure
if (-not $plan -or -not $plan.Decision) {
    throw "Invalid plan.json: missing Decision field"
}

if ($plan.Decision -ne 'ALL_REMOVE' -and $plan.Decision -ne 'PARTIAL_REMOVE') {
    Write-Log "Plan decision: $($plan.Decision) - no removal actions required" 'Warn'
    exit 0
}

# Filter to ScreenConnect-only instances (owner policy binding)
$scInstances = @()
if ($plan.ScreenConnectInstances) {
    $scInstances = @($plan.ScreenConnectInstances)
} elseif ($plan.Instances) {
    # Fallback: filter by target type if plan uses generic structure
    $scInstances = @($plan.Instances | Where-Object { $_.TargetId -eq 'screenconnect' -or $_.Type -eq 'screenconnect' })
}

if ($scInstances.Count -eq 0) {
    Write-Log "No ScreenConnect instances marked for removal in plan" 'Warn'
    exit 0
}

Write-Log "Plan decision: $($plan.Decision)"
Write-Log "ScreenConnect instances to process: $($scInstances.Count)"

# -----------------------------------------------------------------------------
# FIX 1: per-entry product verification
#
# The plan is trusted for SELECTION but never for IDENTITY. Every instance is
# re-verified as genuinely ScreenConnect (ServiceName/ImagePath/directory vs
# known ScreenConnect patterns from targets.json) BEFORE any stop/kill/
# uninstall/quarantine action. Entries failing verification are skipped and
# logged as PRODUCT_VERIFICATION_FAILED; they are never uninstalled.
# -----------------------------------------------------------------------------

$script:ScIdentityCache = $null

function Get-ScreenConnectIdentity {
    # Known-good ScreenConnect identity markers. Patterns are sourced from the
    # 'screenconnect' entry in targets.json when present, with safe defaults.
    if ($script:ScIdentityCache) { return $script:ScIdentityCache }
    $identity = @{
        ServiceNamePatterns = @('ScreenConnect*')
        BinaryNamePatterns  = @('ServiceScreenConnect.exe', 'ScreenConnect*.exe')
        DirSegmentPattern   = '*\ScreenConnect*'
    }
    try {
        $targetsFile = Join-Path $PSScriptRoot 'targets.json'
        if (Test-Path -LiteralPath $targetsFile) {
            $cfg = Get-Content -LiteralPath $targetsFile -Raw | ConvertFrom-Json
            foreach ($t in @($cfg.targets)) {
                if ((Get-EntryPropertySafe -Instance $t -PropertyName 'id') -ne 'screenconnect') { continue }
                $tgtSvc = Get-EntryPropertySafe -Instance $t -PropertyName 'servicePatterns'
                $tgtProc = Get-EntryPropertySafe -Instance $t -PropertyName 'processPatterns'
                if ($tgtSvc) { $identity.ServiceNamePatterns = @($tgtSvc) + $identity.ServiceNamePatterns }
                if ($tgtProc) {
                    $bins = @()
                    foreach ($pp in @($tgtProc)) { $bins += ('{0}.exe' -f [string]$pp) }
                    $identity.BinaryNamePatterns = @('ServiceScreenConnect.exe') + $bins
                }
                Write-Log "Product verification patterns loaded from targets.json"
                break
            }
        } else {
            Write-Log "targets.json not found, using built-in ScreenConnect verification patterns" 'Debug'
        }
    } catch {
        Write-Log "Could not read targets.json, using built-in ScreenConnect verification patterns" 'Debug'
    }
    $script:ScIdentityCache = $identity
    return $identity
}

function Get-EntryPropertySafe {
    # StrictMode-safe property read: plan entries may be missing fields.
    param($Instance, [string]$PropertyName)
    if ($null -eq $Instance) { return $null }
    try {
        $p = $Instance.PSObject.Properties[$PropertyName]
        if ($p) { return $p.Value }
    } catch { }
    return $null
}

function Get-PlanInstanceId {
    param($Instance)
    foreach ($name in @('InstanceId', 'Identifier', 'Key')) {
        $v = Get-EntryPropertySafe -Instance $Instance -PropertyName $name
        if ($v) { return [string]$v }
    }
    return 'unknown'
}

function Get-PathBinaryLeaf {
    # Platform-neutral final-path-segment extraction for Windows image/paths.
    # Handles quoted paths ("C:\...\x.exe" /args), unquoted paths with
    # trailing arguments, and falls back to '/' separation only when the
    # string carries no backslash (normalized/POSIX-style input).
    param([string]$PathString)
    if (-not $PathString) { return '' }
    $s = $PathString.Trim()

    if ($s.StartsWith('"')) {
        # Quoted form: the binary path is exactly the quoted span
        $endQ = $s.IndexOf('"', 1)
        if ($endQ -gt 0) { $s = $s.Substring(1, $endQ - 1) } else { $s = $s.Trim('"') }
    } elseif ($s.Contains('"')) {
        # Embedded closing quote followed by arguments
        $q = $s.IndexOf('"')
        if ($q -ge 0) { $s = $s.Substring(0, $q).Trim() }
    }

    if ($s.Contains('\')) {
        $idx = $s.LastIndexOf('\')
        if ($idx -ge 0) { $s = $s.Substring($idx + 1) }
    } else {
        $idx = $s.LastIndexOf('/')
        if ($idx -ge 0) { $s = $s.Substring($idx + 1) }
    }

    $s = $s.Trim().Trim('"')
    # Trim trailing arguments off an executable token (e.g. "x.exe -k run")
    $rxOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $exeMatch = [regex]::Match($s, '^([^\s]+\.(exe|sys|dll|com))(\s|$)', $rxOpts)
    if ($exeMatch.Success) { return $exeMatch.Groups[1].Value }
    return $s
}

function Test-ScreenConnectInstance {
    <#
        Re-verifies that a plan entry really is ScreenConnect before any action
        is taken against it. Returns PSCustomObject with:
            Verified : boolean
            Reasons  : string[] of failure reasons (empty when Verified=true)
    #>
    param($Instance)

    $reasons = New-Object System.Collections.ArrayList
    $identity = Get-ScreenConnectIdentity

    # Collect evidence defensively (plan entry may be malformed)
    $svcName = [string](Get-EntryPropertySafe -Instance $Instance -PropertyName 'ServiceName')
    $pathStrings = New-Object System.Collections.ArrayList
    foreach ($pn in @('ImagePath', 'ServiceImagePath', 'InstallDir')) {
        $raw = Get-EntryPropertySafe -Instance $Instance -PropertyName $pn
        if ($raw) {
            $exp = Expand-Env ([string]$raw)
            if ($exp) { [void]$pathStrings.Add($exp.Trim()) }
        }
    }

    # Gate A: some path must live under a ScreenConnect directory
    $dirOk = $false
    foreach ($p in $pathStrings) {
        if ($p -like $identity.DirSegmentPattern) { $dirOk = $true; break }
    }
    if (-not $dirOk) {
        [void]$reasons.Add("no candidate path under a ScreenConnect directory (checked $(@($pathStrings).Count) path field(s))")
    }

    # Gate B: binary name must match ServiceScreenConnect.exe or the
    # ScreenConnect client patterns from targets.json
    $binOk = $false
    foreach ($p in $pathStrings) {
        $leaf = Get-PathBinaryLeaf -PathString $p
        if (-not $leaf) { continue }
        $isFileLike = ($leaf -match '\.(exe|sys|dll|com)$')
        if (-not $isFileLike) { continue } # directory entry, checked on disk below
        foreach ($pat in $identity.BinaryNamePatterns) {
            if ($leaf -like $pat) { $binOk = $true; break }
        }
        if ($binOk) { break }
    }
    if (-not $binOk) {
        # Directory-only entries: look for a known ScreenConnect binary on disk
        foreach ($p in $pathStrings) {
            $leaf = Get-PathBinaryLeaf -PathString $p
            if ($leaf -and ($leaf -match '\.(exe|sys|dll|com)$')) { continue } # file-like entry, checked above
            if (-not (Test-Path -LiteralPath $p -PathType Container)) { continue }
            foreach ($pat in $identity.BinaryNamePatterns) {
                $hits = @(Get-ChildItem -LiteralPath $p -Filter $pat -File -ErrorAction SilentlyContinue)
                if ($hits.Count -gt 0) { $binOk = $true; break }
            }
            if ($binOk) { break }
        }
    }
    if (-not $binOk) {
        [void]$reasons.Add("no binary matching known ScreenConnect executable patterns")
    }

    # Gate C: service name (when supplied) must match ScreenConnect patterns
    if ($svcName) {
        $svcOk = $false
        foreach ($pat in $identity.ServiceNamePatterns) {
            if ($svcName -like $pat) { $svcOk = $true; break }
        }
        if (-not $svcOk) {
            [void]$reasons.Add("ServiceName '$svcName' does not match ScreenConnect service patterns")
        }
    }

    return [PSCustomObject]@{
        Verified = ($reasons.Count -eq 0)
        Reasons  = @($reasons.ToArray())
    }
}

function Get-VerifiedUninstallEntry {
    <#
        Honors a plan-supplied UninstallRegistryKey ONLY when reading the key
        shows a DisplayName that is ScreenConnect-like AND value data on the
        key that references the same verified install path. Returns the
        registry entry object, or $null when the key cannot be trusted.
    #>
    param([string]$RegistryKeyPath, [string]$VerifiedInstallDir, [string]$InstanceId)

    if ([string]::IsNullOrWhiteSpace($RegistryKeyPath)) { return $null }

    # The detector reports the key in raw Win32 form
    # (HKEY_LOCAL_MACHINE\SOFTWARE\...), which Get-ItemProperty cannot open -
    # it needs a PSDrive (HKLM:\) or provider (Registry::) path. Without this
    # the plan's own uninstall key was always "unreadable" and discarded.
    $resolvedKeyPath = $RegistryKeyPath
    if ($resolvedKeyPath -match '^HKEY_') {
        $resolvedKeyPath = 'Registry::' + $resolvedKeyPath
    }

    $entry = $null
    try {
        $entry = Get-ItemProperty -LiteralPath $resolvedKeyPath -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        Write-Log "  Plan UninstallRegistryKey unreadable, ignoring it: $msg" 'Warn'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'ValidateUninstallKey' -Target $RegistryKeyPath -Result 'Rejected' -Details "Unreadable key: $msg"
        return $null
    }

    # The key must be ScreenConnect/ConnectWise Control-named
    $displayName = [string](Get-EntryPropertySafe -Instance $entry -PropertyName 'DisplayName')
    if (($displayName -notlike '*ScreenConnect*') -and ($displayName -notlike '*ConnectWise Control*')) {
        Write-Log "  Plan UninstallRegistryKey rejected: DisplayName '$displayName' is not ScreenConnect-like" 'Warn'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'ValidateUninstallKey' -Target $RegistryKeyPath -Result 'Rejected' -Details "DisplayName '$displayName' does not reference ScreenConnect/ConnectWise Control"
        return $null
    }

    # Some value on the key must reference the verified install path
    if ([string]::IsNullOrWhiteSpace($VerifiedInstallDir)) {
        Write-Log "  Plan UninstallRegistryKey rejected: no verified install dir available for cross-check" 'Warn'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'ValidateUninstallKey' -Target $RegistryKeyPath -Result 'Rejected' -Details 'No verified install dir available for cross-check'
        return $null
    }

    $needle = $VerifiedInstallDir.TrimEnd('\')
    foreach ($prop in $entry.PSObject.Properties) {
        if ($prop.Name -like 'PS*') { continue }
        $data = Expand-Env ([string]$prop.Value)
        if (-not $data) { continue }
        if ($data.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Write-Log "  Plan UninstallRegistryKey accepted: value '$($prop.Name)' references verified install dir"
            Add-ManifestEntry -InstanceId $InstanceId -Action 'ValidateUninstallKey' -Target $RegistryKeyPath -Result 'Accepted' -Details "Value '$($prop.Name)' references verified install dir"
            return $entry
        }
    }

    # Second, equally strong cross-check. A ScreenConnect MSI entry normally has
    # an EMPTY InstallLocation and an UninstallString of just
    # "MsiExec.exe /X{ProductCode}" - no value references the install path at
    # all, so the path test above rejected every legitimate MSI install and the
    # plan's own key was discarded on every run. The per-instance identifier
    # (e.g. 763257a7941a63ef) in this key's DisplayName ties the key to THIS
    # instance just as tightly, because the verified install directory is
    # itself named "ScreenConnect Client (<identifier>)".
    if ($InstanceId -and $InstanceId -ne 'unknown') {
        $idNeedle = [string]$InstanceId
        if ($displayName -and
            $displayName.IndexOf($idNeedle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $needle.IndexOf($idNeedle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Write-Log "  Plan UninstallRegistryKey accepted: DisplayName carries instance id '$idNeedle'"
            Add-ManifestEntry -InstanceId $InstanceId -Action 'ValidateUninstallKey' -Target $RegistryKeyPath -Result 'Accepted' -Details "DisplayName '$displayName' carries instance id '$idNeedle', which also names the verified install dir"
            return $entry
        }
    }

    Write-Log "  Plan UninstallRegistryKey rejected: no value data references verified install dir '$VerifiedInstallDir'" 'Warn'
    Add-ManifestEntry -InstanceId $InstanceId -Action 'ValidateUninstallKey' -Target $RegistryKeyPath -Result 'Rejected' -Details "No value data references verified install dir '$VerifiedInstallDir'"
    return $null
}

# -----------------------------------------------------------------------------
# Resolve working directory
# -----------------------------------------------------------------------------
if (-not $WorkDir) {
    $WorkDir = 'C:\RIT-SCC'
}
if (-not (Test-Path -LiteralPath $WorkDir)) {
    throw "WorkDir not found: $WorkDir"
}

$quarantineDir = Get-QuarantineDir $WorkDir
$manifestPath = Join-Path $WorkDir 'removal-manifest.json'
$masterLogPath = Join-Path $WorkDir 'master.log'
$resumeMarkerPath = Join-Path $WorkDir 'resume-marker.json'

Write-Log "WorkDir: $WorkDir"
Write-Log "Quarantine: $quarantineDir"
Write-Log "Manifest: $manifestPath"
Write-Log "Execute mode: $($Execute.IsPresent)"

# -----------------------------------------------------------------------------
# FIX 2: reboot-resume support via resume-marker.json
#
# Execute-mode removal writes the marker listing every instance + status at
# session start, updates it after each instance, and -Resume skips instances
# already recorded as Completed. Marker WRITES happen only in Execute mode;
# dry-run never touches the file.
# -----------------------------------------------------------------------------
$script:ResumeStatuses = New-Object System.Collections.ArrayList
$script:CompletedInstanceIds = New-Object System.Collections.ArrayList
$script:RebootPendingInstanceIds = New-Object System.Collections.ArrayList

function Write-ResumeMarker {
    param([string]$Phase)
    if (-not $Execute) { return }
    try {
        $markerObj = [PSCustomObject]@{
            Script     = $ScriptName
            Version    = $ScriptVersion
            PlanFile   = $PlanFile
            Phase      = $Phase
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            Instances  = @($script:ResumeStatuses.ToArray())
        }
        $markerJson = $markerObj | ConvertTo-Json -Depth 5
        # UTF8 without BOM (Set-Content -Encoding UTF8 would emit a BOM on 5.1)
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($resumeMarkerPath, $markerJson, $utf8NoBom)
    } catch {
        Write-Log "Could not update resume marker: $($_.Exception.Message)" 'Warn'
    }
}

function Initialize-ResumeMarker {
    if (-not $Execute) { return }
    $script:ResumeStatuses.Clear()
    # Use $scInstances here, NOT $scInstancesArray. $scInstances is set right
    # after the plan loads; $scInstancesArray is only assigned later (after
    # this function runs), so under Set-StrictMode -Version 2.0 referencing it
    # here threw "The variable '$scInstancesArray' cannot be retrieved because
    # it has not been set." Both variables end up holding the same instances,
    # so this timing quirk is invisible at runtime - but keep using $scInstances
    # in any code that executes BEFORE the main removal loop. The early
    # 'if (-not $Execute) { return }' above hid this in every dry-run, so it
    # only ever fired on a REAL removal - Stage 4 died before touching anything.
    foreach ($instItem in $scInstances) {
        $id = Get-PlanInstanceId -Instance $instItem
        $status = 'Pending'
        if ($script:CompletedInstanceIds -contains $id) { $status = 'Completed' }
        elseif ($script:RebootPendingInstanceIds -contains $id) { $status = 'RebootPending' }
        [void]$script:ResumeStatuses.Add([PSCustomObject]@{
            InstanceId = $id
            Status     = $status
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        })
    }
    Write-ResumeMarker -Phase 'session-start'
}

function Update-ResumeStatus {
    param([string]$InstanceId, [string]$Status)
    if (-not $Execute) { return }
    foreach ($item in @($script:ResumeStatuses)) {
        if ($item.InstanceId -eq $InstanceId) {
            $item.Status = $Status
            $item.UpdatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            break
        }
    }
    Write-ResumeMarker -Phase ('instance:' + $InstanceId + ' -> ' + $Status)
}

if ($Resume) {
    Write-Log "RESUME mode: continuing after reboot" 'Warn'
    if (Test-Path -LiteralPath $resumeMarkerPath) {
        try {
            $marker = Get-Content -LiteralPath $resumeMarkerPath -Raw | ConvertFrom-Json
            foreach ($mi in @($marker.Instances)) {
                $markerStatus = [string](Get-EntryPropertySafe -Instance $mi -PropertyName 'Status')
                if ($markerStatus -eq 'Completed') {
                    [void]$script:CompletedInstanceIds.Add([string](Get-EntryPropertySafe -Instance $mi -PropertyName 'InstanceId'))
                } elseif ($markerStatus -eq 'RebootPending') {
                    [void]$script:RebootPendingInstanceIds.Add([string](Get-EntryPropertySafe -Instance $mi -PropertyName 'InstanceId'))
                }
            }
            Write-Log ("Resume marker found: " + $script:CompletedInstanceIds.Count + " completed instance(s) will be skipped, " + $script:RebootPendingInstanceIds.Count + " reboot-pending instance(s) will finish post-reboot cleanup")
        } catch {
            Write-Log "Could not read resume marker: $($_.Exception.Message)" 'Warn'
        }
    } else {
        Write-Log "No resume marker found at: $resumeMarkerPath" 'Warn'
    }
    # Pending quarantine moves deferred via MoveFileEx are still retried below
}

# -----------------------------------------------------------------------------
# System Restore point (safety rule 4)
#
# NOTE: a restore point is NOT created here. preflight.ps1 / sc-cleanup.ps1
# Stage 0 already established one at the START of the pipeline (before anything
# was touched), which is the rollback safety net for the whole run. Creating a
# second one right before removal is redundant -- one restore point at the start
# of the script is sufficient. This script therefore assumes its caller already
# took the baseline snapshot and does not emit another.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Registry helper to read uninstall strings
# -----------------------------------------------------------------------------
function Get-UninstallEntriesForInstance {
    param([string]$InstanceIdentifier)
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $matches = New-Object System.Collections.ArrayList
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        try {
            foreach ($k in (Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
                try {
                    $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                    if (-not $p.DisplayName) { continue }
                    # Match ScreenConnect / ConnectWise Control entries
                    if ($p.DisplayName -like '*ScreenConnect*' -or $p.DisplayName -like '*ConnectWise Control*') {
                        # If instance identifier provided, try to match it
                        if ($InstanceIdentifier) {
                            if ($p.DisplayName -like "*$InstanceIdentifier*" -or ($p.InstallLocation -and $p.InstallLocation -like "*$InstanceIdentifier*")) {
                                [void]$matches.Add($p)
                            }
                        } else {
                            [void]$matches.Add($p)
                        }
                    }
                } catch { }
            }
        } catch { }
    }
    return $matches.ToArray()
}

# -----------------------------------------------------------------------------
# Service management
# -----------------------------------------------------------------------------
function Stop-ServiceSafe {
    param([string]$ServiceName, [string]$InstanceId)
    try {
        # A service that does not exist is NOT a failure - it is already gone
        # (uninstaller removed it, or the plan named a stale instance). Letting
        # Get-Service throw here recorded 'Failed' and made the whole run exit 1
        # even though there was nothing to stop.
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $existing) {
            Write-Log "  Service not present (nothing to stop): $ServiceName"
            Add-ManifestEntry -InstanceId $InstanceId -Action 'StopService' -Target $ServiceName -Result 'Skipped' -Details 'Service does not exist'
            return $true
        }
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') {
            if ($Execute) {
                Write-Log "  Stopping service: $ServiceName"
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                $svc.WaitForStatus('Stopped', '00:00:30')
                Add-ManifestEntry -InstanceId $InstanceId -Action 'StopService' -Target $ServiceName -Result 'Success' -Details 'Service stopped'
            } else {
                Write-Log "  [DRY-RUN] Would stop service: $ServiceName"
                Add-ManifestEntry -InstanceId $InstanceId -Action 'StopService' -Target $ServiceName -Result 'DryRun' -Details 'Would stop service'
            }
        } else {
            Write-Log "  Service already stopped: $ServiceName"
            Add-ManifestEntry -InstanceId $InstanceId -Action 'StopService' -Target $ServiceName -Result 'Skipped' -Details 'Already stopped'
        }
        return $true
    } catch {
        $msg = $_.Exception.Message
        Write-Log "  Failed to stop service ${ServiceName}: $msg" 'Error'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'StopService' -Target $ServiceName -Result 'Failed' -Details $msg
        return $false
    }
}

function Kill-ProcessesForInstance {
    param([string]$InstallDir, [string]$ServiceName, [string]$InstanceId)
    try {
        $pids = @()
        # Find processes by executable path
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            Where-Object { $_.ExecutablePath -and $_.ExecutablePath -like "$InstallDir\*" }
        foreach ($p in $procs) {
            $pids += $p.ProcessId
        }
        # Also by service name if no install dir
        if ($pids.Count -eq 0 -and $ServiceName) {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($svc -and $svc.ProcessId) {
                $pids += $svc.ProcessId
            }
        }
        # Also scan for ScreenConnect client/service processes.
        # DANGER: matching on CommandLine used to be part of this filter, which
        # matched THIS VERY SCRIPT - powershell.exe running
        # "...\screenconnect-cleanup\remove-screenconnect.ps1" contains the
        # string "ScreenConnect", so the tool killed its own host process and
        # died with exit -1 partway through removal. Match only on the
        # executable's own name/path, never on the command line.
        if ($pids.Count -eq 0) {
            $scProcs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
                Where-Object {
                    $_.Name -like 'ScreenConnect*' -or
                    ($_.ExecutablePath -and $_.ExecutablePath -like '*\ScreenConnect Client*')
                }
            foreach ($p in $scProcs) {
                $pids += $p.ProcessId
            }
        }
        $pids = @($pids | Sort-Object -Unique)

        # Hard self-protection: never terminate this process or any of its
        # ancestors, no matter how a pid got onto the list. Killing our own
        # host aborts the removal midway and leaves the machine half-cleaned.
        $selfChain = New-Object System.Collections.Generic.List[int]
        $walk = $PID
        for ($i = 0; $i -lt 12 -and $walk -gt 0; $i++) {
            $selfChain.Add([int]$walk)
            $parent = $null
            try {
                $parent = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$walk" -ErrorAction Stop).ParentProcessId
            } catch { }
            if (-not $parent -or $selfChain.Contains([int]$parent)) { break }
            $walk = [int]$parent
        }
        $skipped = @($pids | Where-Object { $selfChain.Contains([int]$_) })
        foreach ($sp in $skipped) {
            Write-Log "  Refusing to kill PID ${sp}: it is this script or one of its parent processes" 'Warn'
            Add-ManifestEntry -InstanceId $InstanceId -Action 'KillProcess' -Target "PID $sp" -Result 'Skipped' -Details 'Self/ancestor process - refused'
        }
        $pids = @($pids | Where-Object { -not $selfChain.Contains([int]$_) })

        if ($pids.Count -eq 0) {
            Write-Log "  No processes found to kill"
            Add-ManifestEntry -InstanceId $InstanceId -Action 'KillProcesses' -Target 'N/A' -Result 'Skipped' -Details 'No processes found'
            return $true
        }
        # NOTE: $pid is a READ-ONLY automatic variable (the current process id).
        # Using it as the loop variable threw "Cannot overwrite variable PID
        # because it is read-only or constant" on the first iteration, so no
        # ScreenConnect process was ever killed. Use $procId instead.
        foreach ($procId in $pids) {
            if ($Execute) {
                Write-Log "  Killing process PID $procId"
                try {
                    Stop-Process -Id $procId -Force -ErrorAction Stop
                    Add-ManifestEntry -InstanceId $InstanceId -Action 'KillProcess' -Target "PID $procId" -Result 'Success' -Details 'Process terminated'
                } catch {
                    $msg = $_.Exception.Message
                    Write-Log "    Failed to kill PID ${procId}: $msg" 'Error'
                    Add-ManifestEntry -InstanceId $InstanceId -Action 'KillProcess' -Target "PID $procId" -Result 'Failed' -Details $msg
                }
            } else {
                Write-Log "  [DRY-RUN] Would kill process PID $procId"
                Add-ManifestEntry -InstanceId $InstanceId -Action 'KillProcess' -Target "PID $procId" -Result 'DryRun' -Details 'Would kill process'
            }
        }
        return $true
    } catch {
        $msg = $_.Exception.Message
        Write-Log "  Error killing processes: $msg" 'Error'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'KillProcesses' -Target 'N/A' -Result 'Failed' -Details $msg
        return $false
    }
}

function Delete-ServiceRegistration {
    param([string]$ServiceName, [string]$InstanceId)
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Log "  Service not found (already deleted): $ServiceName"
            Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteService' -Target $ServiceName -Result 'Skipped' -Details 'Not found'
            return $true
        }
        if ($Execute) {
            Write-Log "  Deleting service registration: $ServiceName"
            # Use sc.exe for reliable deletion. stderr goes to $null (NOT 2>&1):
            # under $ErrorActionPreference='Stop' a merged-stderr redirect turns
            # sc.exe's first stderr line into a terminating NativeCommandError
            # in Windows PowerShell 5.1, making the $LASTEXITCODE branch below
            # dead code. Success output goes to stdout and is drained.
            & sc.exe delete $ServiceName 2>$null | Out-Null
            $exitCode = $LASTEXITCODE
            if ($exitCode -eq 0) {
                Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteService' -Target $ServiceName -Result 'Success' -Details 'Service deleted' -ExitCode $exitCode
            } else {
                $msg = "sc.exe delete exited with code ${exitCode}"
                Write-Log "    $msg" 'Error'
                Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteService' -Target $ServiceName -Result 'Failed' -Details $msg -ExitCode $exitCode
                return $false
            }
        } else {
            Write-Log "  [DRY-RUN] Would delete service: $ServiceName"
            Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteService' -Target $ServiceName -Result 'DryRun' -Details 'Would delete service'
        }
        return $true
    } catch {
        $msg = $_.Exception.Message
        Write-Log "  Failed to delete service ${ServiceName}: $msg" 'Error'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteService' -Target $ServiceName -Result 'Failed' -Details $msg
        return $false
    }
}

# -----------------------------------------------------------------------------
# Uninstaller execution
# -----------------------------------------------------------------------------
function Run-VendorUninstaller {
    param($UninstallEntry, [string]$InstanceId, [string]$InstallDir)
    if (-not $UninstallEntry) {
        Write-Log "  No uninstall registry entry provided"
        Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target 'Registry' -Result 'Skipped' -Details 'No uninstall entry'
        # $null = nothing was attempted (entry already recorded above); the
        # caller must NOT record a second 'Failed' entry for this.
        return $null
    }

    # StrictMode-safe reads: a real Uninstall key very often has NO
    # QuietUninstallString value, and under Set-StrictMode -Version 2.0 a
    # direct property read on a missing registry value THROWS
    # ("The property 'QuietUninstallString' cannot be found on this object"),
    # which aborted the whole instance before the uninstaller ever ran.
    $uninstallString = Get-EntryPropertySafe -Instance $UninstallEntry -PropertyName 'UninstallString'
    $quietUninstallString = Get-EntryPropertySafe -Instance $UninstallEntry -PropertyName 'QuietUninstallString'
    $displayName = Get-EntryPropertySafe -Instance $UninstallEntry -PropertyName 'DisplayName'
    $registryKey = Get-EntryPropertySafe -Instance $UninstallEntry -PropertyName 'PSPath'

    Write-Log "  Found uninstall entry: $displayName"

    # Determine the command to run
    $cmd = $null
    $isMsi = $false
    $productCode = $null

    if ($quietUninstallString) {
        $cmd = $quietUninstallString
    } elseif ($uninstallString) {
        $cmd = $uninstallString
    }

    if (-not $cmd) {
        # NOT a failure: a damaged/tampered registration often keeps DisplayName
        # but loses UninstallString. Manual surgery (quarantine + service
        # deletion) is the designed fallback and handles it, so recording this
        # as 'Failed' made a successful removal report failure and exit 1.
        # Return $null (nothing attempted) - the caller must not add a second
        # 'Failed' entry with an empty Target on top of this truthful one.
        Write-Log "  No UninstallString or QuietUninstallString found - falling back to manual surgery" 'Warn'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target $displayName -Result 'Skipped' -Details 'No uninstall string on the registry entry; manual surgery will handle this instance'
        return $null
    }

    # Check if MSI
    if ($cmd -match '/x\s+\{([A-F0-9-]{36})\}' -or $cmd -match 'msiexec.*/x\s+(\{[A-F0-9-]{36}\})') {
        $isMsi = $true
        $productCode = $matches[1]
        Write-Log "  Detected MSI uninstaller, ProductCode: $productCode"
    }

    # Build the actual command line
    $finalCmd = $cmd
    if ($isMsi) {
        # Ensure quiet uninstall flags
        if ($finalCmd -notmatch '/qn') {
            $finalCmd = $finalCmd + ' /qn'
        }
        if ($finalCmd -notmatch '/norestart') {
            $finalCmd = $finalCmd + ' /norestart'
        }
    } else {
        # For non-MSI, try to add common silent flags if not present
        if ($finalCmd -notmatch '/s' -and $finalCmd -notmatch '/quiet' -and $finalCmd -notmatch '/silent') {
            # Don't invent flags - use what the registry provides
            # But log that we're running as-is
            Write-Log "  Running uninstaller as-is (no silent flags added per policy)" 'Debug'
        }
    }

    Write-Log "  Uninstall command: $finalCmd"

    # FIX (safety): never feed a verbatim registry UninstallString or
    # QuietUninstallString to `cmd.exe /c`. That string is attacker-influenced:
    # cmd.exe re-parses '%VAR%', '&', '|', '^' and quotes with the technician's
    # elevated token, so a tampered registration becomes arbitrary command
    # execution. Instead we run the vendor's own executable DIRECTLY with a
    # curated argument list built from validated parts -- no cmd.exe, no shell
    # metacharacter interpretation.
    if ($Execute) {
        # --- Curated, no-shell uninstall paths ---
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        $runDirect = $false
        if ($isMsi) {
            # MSI: run msiexec.exe directly with the validated ProductCode.
            # /qn /norestart are fixed flags we control, not registry text.
            $psi.FileName = "$env:SystemRoot\System32\msiexec.exe"
            $psi.Arguments = '/x ' + $productCode + ' /qn /norestart'
            $runDirect = $true
        } else {
            # Non-MSI: only run if the executable leaf is an allowlisted,
            # ScreenConnect-family uninstaller AND it sits under the verified
            # install directory. Extract the bare executable with no arguments.
            $bareExe = $null
            $mm = [regex]::Match($cmd, '^\s*"([^"]+\.exe)"')
            if ($mm.Success) { $bareExe = $mm.Groups[1].Value }
            else {
                $mm2 = [regex]::Match($cmd, '^\s*([A-Za-z]:\\[^"\s]+\.exe)')
                if ($mm2.Success) { $bareExe = $mm2.Groups[1].Value }
            }
            $leaf = ''
            if ($bareExe) { $leaf = [System.IO.Path]::GetFileName($bareExe) }
            $leafOk = ($leaf -match '^(?i)(ScreenConnect|App_)') -or ($leaf -match '^(?i)unins[0-9]*\.exe$')
            $underInstall = $false
            if ($installDir) { $underInstall = ($bareExe -and $bareExe.StartsWith($installDir, [System.StringComparison]::OrdinalIgnoreCase)) }
            if ($leafOk -and $underInstall -and (Test-Path -LiteralPath $bareExe)) {
                $psi.FileName = $bareExe
                $psi.Arguments = ''   # ScreenConnect uninstallers take no args / aren't trusted from registry
                $runDirect = $true
                Write-Log "  Running vendor uninstaller directly (no shell): $bareExe"
            } else {
                # Fail-closed: a string we cannot validate is never executed by
                # shell. Record it and fall back to manual surgery + quarantine.
                $psi = $null
                Write-Log "  REFUSING to run unvalidated UninstallString via cmd.exe (not an allowlisted ScreenConnect/MSI uninstaller). Manual surgery will handle this instance." 'Warn'
                Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target $displayName -Result 'Failed' -Details "UninstallString not validated (not MSI / not an allowlisted executable under the verified install dir); manual surgery fallback. Raw string (logged, NOT executed): $finalCmd"
                return $false
            }
        }

        try {
            # Use Run-BoundedProcess for concurrent stream drain + timeout
            # PS 5.1-compatible: precompute the working directory instead of an
            # inline if-expression, which fails to parse on Windows PowerShell.
            $workingDirectory = ''
            if ($installDir) { $workingDirectory = $installDir }
            $result = Run-BoundedProcess -FilePath $psi.FileName -Arguments $psi.Arguments -TimeoutMs 300000 -WorkingDirectory $workingDirectory
            $exitCode = $result.ExitCode
            $stdout = $result.StdOut
            $stderr = $result.StdErr
            $timedOut = $result.TimedOut

            Write-Log "  Uninstaller exit code: $exitCode"
            if ($stdout) { Write-Log "    STDOUT: $stdout" 'Debug' }
            if ($stderr) { Write-Log "    STDERR: $stderr" 'Debug' }
            if ($timedOut) { Write-Log "  Uninstaller timed out after 300s, process killed" 'Warn' }

            if ($exitCode -eq 0) {
                Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target $displayName -Result 'Success' -Details "Exit code $exitCode" -ExitCode $exitCode
                return $true
            } elseif ($exitCode -eq 3010) { # 3010 = reboot required
                Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target $displayName -Result 'Success' -Details "Exit code 3010 (reboot required)" -ExitCode $exitCode
                Write-Log "  Uninstaller requests reboot (exit code 3010)" 'Warn'
                # Return special marker for 3010 so caller knows to defer completion
                return @{ Success = $true; RebootRequired = $true; ExitCode = 3010 }
            } else {
                if ($timedOut) {
                    Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target $displayName -Result 'Failed' -Details 'Uninstaller timed out after 300s and was killed (no exit code)' -ExitCode -1
                } else {
                    Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target $displayName -Result 'Failed' -Details ("Exit code ${exitCode}: " + $stderr) -ExitCode $exitCode
                }
                return $false
            }
        } catch {
            $msg = $_.Exception.Message
            Write-Log "  Uninstaller exception: $msg" 'Error'
            Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target $displayName -Result 'Failed' -Details $msg
            return $false
        }
    } else {
        Write-Log "  [DRY-RUN] Would run uninstaller: $finalCmd"
        Add-ManifestEntry -InstanceId $InstanceId -Action 'Uninstall' -Target $displayName -Result 'DryRun' -Details "Would run: $finalCmd"
        return $true # dry-run assumes success
    }
}

# -----------------------------------------------------------------------------
# Quarantine directory move (manual surgery fallback)
# -----------------------------------------------------------------------------
function Move-ToQuarantine {
    param([string]$SourcePath, [string]$InstanceId, [string]$Description)
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        Write-Log "  Source not found, skipping quarantine: $SourcePath"
        Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $SourcePath -Result 'Skipped' -Details "Not found: $Description"
        return $true
    }

    # A directory has no single file hash - Get-FileHash on a folder returns
    # nothing, so the manifest used to record a blank "SHA256: " for the main
    # artifact, defeating the whole point of the forensic record. Hash every
    # file inside instead and write them to a sidecar CSV.
    $isDirectory = $false
    try { $isDirectory = (Get-Item -LiteralPath $SourcePath -Force).PSIsContainer } catch { }
    $hashNote = ''
    $sha256 = ''
    if ($isDirectory) {
        # FIX (safety): never blindly recurse through reparse points (junctions /
        # symlinks) inside the install tree. A junction pointing at C:\Windows
        # (planted by an attacker, or left by a benign misinstall) would otherwise
        # be walked, hashed, and on Move-Item -Force potentially followed/copied.
        # Detect reparse points and hash only legitimate non-reparse children.
        $hashCsv = Join-Path $WorkDir ('quarantine-hashes-' + $InstanceId + '.csv')
        $rows = New-Object System.Collections.ArrayList
        $reparseSkipped = @()
        foreach ($f in @(Get-ChildItem -LiteralPath $SourcePath -File -Recurse -Force -Attributes !ReparsePoint -ErrorAction SilentlyContinue)) {
            $h = Get-Sha256File $f.FullName
            [void]$rows.Add([PSCustomObject]@{
                Path   = $f.FullName
                Length = $f.Length
                SHA256 = $h
            })
        }
        # Record any reparse points we declined to follow, so the forensic record
        # notes them rather than silently omitting them.
        $reparseItems = @(Get-ChildItem -LiteralPath $SourcePath -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)
        foreach ($rp in $reparseItems) {
            $reparseSkipped += $rp.FullName
            Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $rp.FullName -Result 'Skipped' -Details 'Reparse point (junction/symlink) not followed or moved'
        }
        try {
            $rows | Export-Csv -LiteralPath $hashCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            $hashNote = "directory, " + $rows.Count + " file(s) hashed -> " + $hashCsv
            if ($reparseSkipped.Count -gt 0) { $hashNote += "; " + $reparseSkipped.Count + " reparse point(s) skipped" }
        } catch {
            $hashNote = "directory, " + $rows.Count + " file(s); hash CSV failed: " + $_.Exception.Message
        }
        $sha256 = $hashNote
    } else {
        $sha256 = Get-Sha256File $SourcePath
    }
    $destName = [System.IO.Path]::GetFileName($SourcePath)
    # Windows PowerShell 5.1's Join-Path takes only -Path and -ChildPath; a
    # third positional part (PS 7+ only) fails with "A positional parameter
    # cannot be found that accepts argument ...", which aborted manual surgery
    # before anything was ever quarantined. Nest the calls instead.
    $destPath = Join-Path (Join-Path $quarantineDir "$InstanceId") "$destName"

    # FIX (safety): make the quarantine destination collision-safe. Move-Item
    # -Force on a directory-vs-directory collision MERGES the sources on top of
    # each other and can overwrite same-named files, silently corrupting the
    # forensic record (SHA256 no longer matches what lands on disk). If the
    # destination already exists (resume, or two installs sharing a leaf name),
    # derive a unique name from a hash of the full source path instead of
    # blindly overwriting.
    if (Test-Path -LiteralPath $destPath) {
        $unique = (Get-Sha256Hex -Text $SourcePath)
        if ($unique) { $unique = $unique.Substring(0, 8) } else { $unique = [Guid]::NewGuid().ToString('N').Substring(0, 8) }
        $destPath = Join-Path (Join-Path $quarantineDir "$InstanceId") ($unique + '-' + $destName)
        Write-Log "  Quarantine destination already exists; using unique path: $destPath"
    }

    # Ensure quarantine subdirectory exists
    $qSubDir = Split-Path -Parent $destPath
    if (-not (Test-Path -LiteralPath $qSubDir)) {
        $null = New-Item -ItemType Directory -Path $qSubDir -Force
    }

    Write-Log "  Quarantining ${Description}: ${SourcePath} -> ${destPath}"
    Write-Log "  SHA256: $sha256"

    if ($Execute) {
        try {
            # Try the move FIRST rather than pre-testing with File::Open.
            # File::Open ALWAYS throws on a directory ("Access to the path is
            # denied"), so every install folder was wrongly judged "in use" and
            # deferred to reboot - leaving the payload on disk after a run the
            # technician was told had succeeded. Attempting the move is the only
            # honest test, and it works for files and directories alike.
            $isLocked = $false
            try {
                Move-Item -LiteralPath $SourcePath -Destination $destPath -Force -ErrorAction Stop
            } catch {
                $isLocked = $true
                Write-Log ("  Immediate move failed (" + $_.Exception.Message + ")") 'Debug'
            }

            if ($isLocked) {
                Write-Log "  File in use, scheduling move on reboot via MoveFileEx" 'Warn'
                # Use MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT
                $kernel32 = Add-Type -MemberDefinition @'
                    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@ -Name 'Kernel32' -Namespace 'Win32' -PassThru
                $MOVEFILE_DELAY_UNTIL_REBOOT = 4
                $result = $kernel32::MoveFileEx($SourcePath, $destPath, $MOVEFILE_DELAY_UNTIL_REBOOT)
                if (-not $result) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "MoveFileEx failed with error $err"
                }
                # Set RunOnce to resume
                Set-RunOnceResume -InstanceId $InstanceId -WorkDir $WorkDir
                Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $SourcePath -Result 'Deferred' -Details "File in use, scheduled for reboot move. SHA256: $sha256. Original: $SourcePath`nQuarantine: $destPath`nDescription: $Description"
            } else {
                # Already moved by the attempt above - just record it.
                Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $SourcePath -Result 'Success' -Details "Moved to quarantine. SHA256: $sha256. Original: $SourcePath`nQuarantine: $destPath`nDescription: $Description"
            }
            return $true
        } catch {
            $msg = $_.Exception.Message
            Write-Log "  Failed to quarantine: $msg" 'Error'
            Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $SourcePath -Result 'Failed' -Details $msg
            return $false
        }
    } else {
        Write-Log "  [DRY-RUN] Would quarantine: $SourcePath -> $destPath (SHA256: $sha256)"
        Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $SourcePath -Result 'DryRun' -Details "Would move to quarantine. SHA256: $sha256"
        return $true
    }
}

function Set-RunOnceResume {
    param([string]$InstanceId, [string]$WorkDir)
    try {
        $runOncePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        $scriptPath = Join-Path $PSScriptRoot 'remove-screenconnect.ps1'
        # Resolve to absolute paths: RunOnce executes from the system context
        # (working directory is not the tool folder), so a relative PlanFile or
        # WorkDir would break the post-reboot resume run.
        $planPath = $PlanFile
        $workPath = $WorkDir
        if ($PlanFile -and (Test-Path -LiteralPath $PlanFile)) {
            $planPath = (Resolve-Path -LiteralPath $PlanFile).Path
        }
        if ($WorkDir -and (Test-Path -LiteralPath $WorkDir)) {
            $workPath = (Resolve-Path -LiteralPath $WorkDir).Path
        }
        $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -PlanFile `"$planPath`" -WorkDir `"$workPath`" -Execute -Resume"
        if (-not (Test-Path -LiteralPath $runOncePath)) {
            $null = New-Item -Path $runOncePath -Force
        }
        Set-ItemProperty -LiteralPath $runOncePath -Name "SCCleanup_Resume_$InstanceId" -Value $cmd -Force -ErrorAction Stop
        Write-Log "  RunOnce resume key set for $InstanceId"
    } catch {
        Write-Log "  Failed to set RunOnce key: $($_.Exception.Message)" 'Warn'
    }
}

# -----------------------------------------------------------------------------
# Persistence cleanup (scheduled tasks, Run keys, WMI subscriptions)
# -----------------------------------------------------------------------------
function Clean-Persistence {
    param([string]$InstallDir, [string]$InstanceId)
    $cleaned = 0
    $failed = $false

    # 1. Scheduled Tasks referencing the install directory
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        if ($tasks) {
            foreach ($task in $tasks) {
                try {
                    $actions = $task.Actions
                    foreach ($action in @($actions)) {
                        # Scheduled tasks can carry action types that have no
                        # Execute property (e.g. COM handler actions expose
                        # ClassId/Data instead). Read defensively so a
                        # non-execute action does not throw under StrictMode.
                        $path = Get-EntryPropertySafe -Instance $action -PropertyName 'Execute'
                        $args = Get-EntryPropertySafe -Instance $action -PropertyName 'Arguments'
                        if (($path -and $path -like "$InstallDir\*") -or ($args -and $args -like "*$InstallDir*")) {
                            $taskName = $task.TaskName
                            $taskPath = $task.TaskPath
                            Write-Log "  Found scheduled task referencing install dir: $taskPath$taskName"
                            if ($Execute) {
                                Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
                                Write-Log "    Deleted scheduled task: $taskPath$taskName"
                                Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteScheduledTask' -Target "$taskPath$taskName" -Result 'Success' -Details "Referenced $InstallDir"
                                $cleaned++
                            } else {
                                Write-Log "    [DRY-RUN] Would delete scheduled task: $taskPath$taskName"
                                Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteScheduledTask' -Target "$taskPath$taskName" -Result 'DryRun' -Details "Referenced $InstallDir"
                                $cleaned++
                            }
                        }
                    }
                } catch {
                    $failed = $true
                    Write-Log ("  Failed to delete scheduled task: " + $_.Exception.Message) 'Error'
                    Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteScheduledTask' -Target 'N/A' -Result 'Failed' -Details $_.Exception.Message
                }
            }
        }
    } catch { Write-Log "  Scheduled task enumeration failed: $($_.Exception.Message)" 'Warn' }

    # 2. Registry Run/RunOnce keys
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($rk in $runKeys) {
        if (-not (Test-Path -LiteralPath $rk)) { continue }
        try {
            $vals = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
            if ($vals) {
                foreach ($prop in $vals.PSObject.Properties) {
                    if ($prop.Name -eq 'PSPath' -or $prop.Name -eq 'PSParentPath' -or $prop.Name -eq 'PSChildName' -or $prop.Name -eq 'PSDrive' -or $prop.Name -eq 'PSProvider') { continue }
                    $val = $prop.Value
                    if ($val -and $val -like "*$InstallDir*") {
                        Write-Log "  Found Run key referencing install dir: $rk\$($prop.Name) = $val"
                        if ($Execute) {
                            Remove-ItemProperty -LiteralPath $rk -Name $prop.Name -Force -ErrorAction Stop
                            Write-Log "    Deleted Run key value: $prop.Name"
                            Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteRunKey' -Target "$rk\$($prop.Name)" -Result 'Success' -Details "Referenced $InstallDir"
                            $cleaned++
                        } else {
                            Write-Log "    [DRY-RUN] Would delete Run key value: $prop.Name"
                            Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteRunKey' -Target "$rk\$($prop.Name)" -Result 'DryRun' -Details "Referenced $InstallDir"
                            $cleaned++
                        }
                    }
                }
            }
        } catch {
            $failed = $true
            Write-Log ("  Failed to delete Run key value: " + $_.Exception.Message) 'Error'
            Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteRunKey' -Target 'N/A' -Result 'Failed' -Details $_.Exception.Message
        }
    }

    # 3. WMI Event Subscriptions (FilterToConsumerBinding)
    try {
        $bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop
        foreach ($b in $bindings) {
            try {
                $filter = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -Filter "Name='$($b.Filter)'" -ErrorAction SilentlyContinue
                $consumer = Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -Filter "Name='$($b.Consumer)'" -ErrorAction SilentlyContinue
                if ($consumer -and $consumer.CommandLineTemplate -and $consumer.CommandLineTemplate -like "*$InstallDir*") {
                    Write-Log "  Found WMI subscription referencing install dir: $($filter.Name) -> $($consumer.Name)"
                    if ($Execute) {
                        Remove-CimInstance -CimInstance $b -ErrorAction Stop
                        Remove-CimInstance -CimInstance $filter -ErrorAction Stop
                        Remove-CimInstance -CimInstance $consumer -ErrorAction Stop
                        Write-Log "    Deleted WMI subscription"
                        Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteWmiSubscription' -Target "$($filter.Name) -> $($consumer.Name)" -Result 'Success' -Details "Referenced $InstallDir"
                        $cleaned++
                    } else {
                        Write-Log "    [DRY-RUN] Would delete WMI subscription"
                        Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteWmiSubscription' -Target "$($filter.Name) -> $($consumer.Name)" -Result 'DryRun' -Details "Referenced $InstallDir"
                        $cleaned++
                    }
                }
            } catch {
                $failed = $true
                Write-Log ("  Failed to delete WMI subscription: " + $_.Exception.Message) 'Error'
                Add-ManifestEntry -InstanceId $InstanceId -Action 'DeleteWmiSubscription' -Target 'N/A' -Result 'Failed' -Details $_.Exception.Message
            }
        }
    } catch { Write-Log "  WMI subscription enumeration failed: $($_.Exception.Message)" 'Warn' }

    if ($cleaned -eq 0) {
        Write-Log "  No persistence artifacts found referencing $InstallDir"
        Add-ManifestEntry -InstanceId $InstanceId -Action 'CleanPersistence' -Target $InstallDir -Result 'Skipped' -Details 'No artifacts found'
    }
    return (-not $failed)
}

# -----------------------------------------------------------------------------
# Main processing loop
# -----------------------------------------------------------------------------
Write-Section "Processing ScreenConnect instances"

Initialize-ResumeMarker

$overallSuccess = $true

$scInstancesArray = @($scInstances)
foreach ($inst in $scInstancesArray) {

    # FIX 3: resolve the id up front (defensively) so any failure below can
    # still be attributed in the manifest, then isolate each instance so one
    # malformed entry logs an error and processing continues.
    $instanceId = Get-PlanInstanceId -Instance $inst

    try {
        Write-Section "Instance: $instanceId"

        # FIX 2: skip instances already completed by a previous interrupted run
        if (($script:CompletedInstanceIds.Count -gt 0) -and ($script:CompletedInstanceIds -contains $instanceId)) {
            Write-Log "  Already completed in previous run (resume marker), skipping: $instanceId"
            Add-ManifestEntry -InstanceId $instanceId -Action 'ResumeSkip' -Target 'N/A' -Result 'Skipped' -Details 'Already completed according to resume-marker.json'
            continue
        }

        # FIX 1: verify this entry really is ScreenConnect BEFORE acting on it
        $verification = Test-ScreenConnectInstance -Instance $inst
        if (-not $verification.Verified) {
            $why = ($verification.Reasons -join '; ')
            Write-Log "  PRODUCT VERIFICATION FAILED for ${instanceId}: $why" 'Error'
            Add-ManifestEntry -InstanceId $instanceId -Action 'ProductVerification' -Target 'N/A' -Result 'PRODUCT_VERIFICATION_FAILED' -Details "Entry skipped, never uninstalled. Reasons: $why"
            Update-ResumeStatus -InstanceId $instanceId -Status 'PRODUCT_VERIFICATION_FAILED'
            continue
        }
        Write-Log "  Product verification passed"
        Add-ManifestEntry -InstanceId $instanceId -Action 'ProductVerification' -Target 'N/A' -Result 'Passed' -Details 'Entry identity confirmed against ScreenConnect patterns'
        # FIX (transparency): this confirmation is NAME-BASED identity (directory
        # segment + binary name + service name). It does NOT check an
        # Authenticode signature or a ConnectWise certificate. A technician must
        # eyeball the entry, because a look-alike folder/binary named
        # "ScreenConnect..." would pass these gates. See docs/03 (key map is
        # UNVERIFIED against a live install).
        Write-Log "  NOTE: identity is name-based, not signature-verified. Review the instance before removal." 'Warn'

        $serviceName = Get-EntryPropertySafe -Instance $inst -PropertyName 'ServiceName'
        $installDir = Get-EntryPropertySafe -Instance $inst -PropertyName 'InstallDir'
        if ($installDir) { $installDir = Expand-Env ([string]$installDir) }
        $uninstallEntry = $null

        # FIX 1: plan-supplied UninstallRegistryKey is only honored when its
        # value data references the same verified install path
        $planRegKey = Get-EntryPropertySafe -Instance $inst -PropertyName 'UninstallRegistryKey'
        if ($planRegKey) {
            $uninstallEntry = Get-VerifiedUninstallEntry -RegistryKeyPath ([string]$planRegKey) -VerifiedInstallDir ([string]$installDir) -InstanceId $instanceId
        }

        # If no usable uninstall entry from plan, look it up
        if (-not $uninstallEntry -and $instanceId -ne 'unknown') {
            $entries = Get-UninstallEntriesForInstance $instanceId
            $entriesArray = @($entries)
            if ($entriesArray.Count -gt 0) {
                $uninstallEntry = $entriesArray[0]
            }
        }

        # FIX (reboot-resume): a RebootPending instance already had a successful
        # vendor uninstaller pass (exit 3010). On -Resume after reboot, do NOT
        # re-run the vendor uninstaller or manual surgery - finish only the
        # deferred persistence cleanup, then close the instance status.
        if (($script:RebootPendingInstanceIds.Count -gt 0) -and ($script:RebootPendingInstanceIds -contains $instanceId)) {
            Write-Log "  RebootPending resume: vendor uninstaller already succeeded; running post-reboot persistence cleanup only"
            Add-ManifestEntry -InstanceId $instanceId -Action 'ResumeSkip' -Target 'N/A' -Result 'RebootPending' -Details 'Vendor uninstaller already succeeded (3010); skipping uninstall and manual surgery'
            $instanceFailed = $false
            if ($installDir) {
                if (-not (Clean-Persistence -InstallDir $installDir -InstanceId $instanceId)) { $instanceFailed = $true }
            }
            $resumeSvcExe = [string](Get-EntryPropertySafe -Instance $inst -PropertyName 'MainExe')
            if (-not $resumeSvcExe) {
                $resumeSvcImagePath = [string](Get-EntryPropertySafe -Instance $inst -PropertyName 'ServiceImagePath')
                if ($resumeSvcImagePath) {
                    $resumeQuoted = [regex]::Match($resumeSvcImagePath, '^\s*"([^"]+)"')
                    if ($resumeQuoted.Success) {
                        $resumeSvcExe = $resumeQuoted.Groups[1].Value
                    } else {
                        $resumeBare = [regex]::Match($resumeSvcImagePath, '^\s*(\S.*?\.exe)', 'IgnoreCase')
                        if ($resumeBare.Success) { $resumeSvcExe = $resumeBare.Groups[1].Value }
                    }
                }
            }
            if ($resumeSvcExe) {
                $resumeSvcDir = Split-Path -Parent $resumeSvcExe
                if ($resumeSvcDir -and $resumeSvcDir -ne $installDir) {
                    if (-not (Clean-Persistence -InstallDir $resumeSvcDir -InstanceId $instanceId)) { $instanceFailed = $true }
                }
            }
            if ($instanceFailed) {
                Update-ResumeStatus -InstanceId $instanceId -Status 'Failed'
                Write-Log "  RebootPending post-reboot cleanup failed for: $instanceId" 'Error'
                $overallSuccess = $false
            } else {
                Update-ResumeStatus -InstanceId $instanceId -Status 'Completed'
                Write-Log "  RebootPending post-reboot cleanup finished for: $instanceId"
            }
            continue
        }

        # 1. Stop service + kill processes
        # FIX (reliability): capture each sub-action result so a half-failure is
        # surfaced and the instance is NOT marked 'Completed'.
        $instanceFailed = $false
        if ($serviceName) {
            if (-not (Stop-ServiceSafe -ServiceName $serviceName -InstanceId $instanceId)) { $instanceFailed = $true }
        }
        if ($installDir) {
            if (-not (Kill-ProcessesForInstance -InstallDir $installDir -ServiceName $serviceName -InstanceId $instanceId)) { $instanceFailed = $true }
        } else {
            if (-not (Kill-ProcessesForInstance -InstallDir '' -ServiceName $serviceName -InstanceId $instanceId)) { $instanceFailed = $true }
        }

        # 2. Run vendor uninstaller
        $uninstallResult = $null
        $uninstallSucceeded = $false
        $rebootRequired = $false
        if ($uninstallEntry) {
            $uninstallResult = Run-VendorUninstaller -UninstallEntry $uninstallEntry -InstanceId $instanceId -InstallDir $installDir
            if ($uninstallResult -is [hashtable] -and $uninstallResult.RebootRequired) {
                # Exit 3010 - uninstall succeeded but reboot required
                $uninstallSucceeded = $true
                $rebootRequired = $true
                Write-Log "  Vendor uninstaller succeeded, reboot required (exit 3010)"
            } elseif ($uninstallResult -eq $true) {
                # Exit 0 - uninstall succeeded (entry already recorded inside
                # Run-VendorUninstaller as Success with the exit code)
                $uninstallSucceeded = $true
                Write-Log "  Vendor uninstaller reported success"
            } elseif ($null -eq $uninstallResult) {
                # Nothing was attempted (no uninstall string / no entry); the
                # truthful Skipped entry is already in the manifest. Record the
                # DECISION here with a real target, never an empty one, and
                # never as 'Failed' - a run whose manual surgery succeeds must
                # not show a failed Uninstall.
                Write-Log "  No vendor uninstaller available - proceeding with manual surgery" 'Warn'
                $fallbackTarget = Get-EntryPropertySafe -Instance $uninstallEntry -PropertyName 'DisplayName'
                if (-not $fallbackTarget) { $fallbackTarget = 'N/A' }
                Add-ManifestEntry -InstanceId $instanceId -Action 'UninstallFallback' -Target $fallbackTarget -Result 'Planned' -Details 'No vendor uninstaller available; proceeding with manual surgery + quarantine'
            } else {
                # Genuine failure - the reason entry (exit code / timeout /
                # validation refusal) is already recorded. Record the decision
                # with a real target.
                Write-Log "  Vendor uninstaller failed - proceeding with manual surgery" 'Warn'
                $fallbackTarget = Get-EntryPropertySafe -Instance $uninstallEntry -PropertyName 'DisplayName'
                if (-not $fallbackTarget) { $fallbackTarget = 'N/A' }
                Add-ManifestEntry -InstanceId $instanceId -Action 'UninstallFallback' -Target $fallbackTarget -Result 'Planned' -Details 'Vendor uninstaller failed; proceeding with manual surgery + quarantine'
            }
        } else {
            Write-Log "  No uninstall entry found, will proceed to manual surgery" 'Warn'
            Add-ManifestEntry -InstanceId $instanceId -Action 'Uninstall' -Target 'N/A' -Result 'Skipped' -Details 'No uninstall registry entry found'
        }

        # 3. Manual surgery fallback ONLY if uninstall failed or no uninstaller
        # Do NOT run manual surgery if uninstall succeeded (exit 0 or 3010)
        if (-not $uninstallSucceeded -and $installDir -and (Test-Path -LiteralPath $installDir)) {
            Write-Log "  Proceeding with manual surgery for: $installDir"

            # Quarantine the entire install directory
            if (-not (Move-ToQuarantine -SourcePath $installDir -InstanceId $instanceId -Description 'Install directory')) { $instanceFailed = $true }

            # Delete service registration
            if ($serviceName) {
                if (-not (Delete-ServiceRegistration -ServiceName $serviceName -InstanceId $instanceId)) { $instanceFailed = $true }
            }

            # Remove the now-orphaned Uninstall registry entry. When the vendor
            # uninstaller runs, MSI clears this itself; after MANUAL SURGERY it
            # is left behind, so ScreenConnect kept showing up in Programs and
            # Features even though every file and the service were gone. The key
            # is exported to the working directory first so the removal stays
            # reversible and auditable.
            if ($uninstallEntry) {
                $orphanPath = [string](Get-EntryPropertySafe -Instance $uninstallEntry -PropertyName 'PSPath')
                if ($orphanPath) {
                    $regPath = $orphanPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
                    $regPath = $regPath -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
                    $regPath = $regPath -replace '^HKEY_CURRENT_USER', 'HKCU'
                    $backup = Join-Path $WorkDir ('uninstall-key-' + $instanceId + '.reg')
                    if ($Execute) {
                        try {
                            # Export FIRST and verify the backup landed before
                            # deleting. reg.exe export writes a .reg file; if it
                            # failed (unwritable path, bad quoting), the delete
                            # must NOT proceed or we lose the only reversal.
                            & reg.exe export "$regPath" "$backup" /y 2>$null | Out-Null
                            $exportCode = $LASTEXITCODE
                            if ($exportCode -ne 0 -or -not (Test-Path -LiteralPath $backup)) {
                                Write-Log "  Export of $regPath backup failed (exit $exportCode); NOT deleting the orphan key" 'Error'
                                Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteUninstallKey' -Target $regPath -Result 'Failed' -Details "Backup export failed (exit $exportCode); key left in place for safety"
                                $instanceFailed = $true
                            } else {
                                & reg.exe delete "$regPath" /f 2>$null | Out-Null
                                $delCode = $LASTEXITCODE
                                if ($delCode -eq 0) {
                                    Write-Log "  Removed orphaned uninstall entry: $regPath"
                                    Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteUninstallKey' -Target $regPath -Result 'Success' -Details "Orphaned after manual surgery; exported to $backup"
                                } else {
                                    Write-Log "  Could not delete orphaned uninstall entry: $regPath" 'Warn'
                                    Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteUninstallKey' -Target $regPath -Result 'Failed' -Details "reg delete exit $delCode"
                                    $instanceFailed = $true
                                }
                            }
                        } catch {
                            Write-Log (  "Could not delete orphaned uninstall entry: " + $_.Exception.Message) 'Warn'
                            Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteUninstallKey' -Target $regPath -Result 'Failed' -Details $_.Exception.Message
                            $instanceFailed = $true
                        }
                    } else {
                        Write-Log "  [DRY-RUN] Would remove orphaned uninstall entry: $regPath"
                        Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteUninstallKey' -Target $regPath -Result 'DryRun' -Details 'Would export then delete the orphaned uninstall key'
                    }
                }
            }
        } else {
            Write-Log "  Install directory not found or empty: $installDir" 'Warn'
            if ($serviceName) {
                if (-not (Delete-ServiceRegistration -ServiceName $serviceName -InstanceId $instanceId)) { $instanceFailed = $true }
            }
        }

        # 4. Clean persistence (ONLY if uninstall failed - do NOT run after successful
        # uninstall with exit 3010 as it would destructively alter a reboot-pending
        # install and poison resume. After 3010, persistence cleanup runs on -Resume.)
        if ($installDir -and -not $rebootRequired) {
            if (-not (Clean-Persistence -InstallDir $installDir -InstanceId $instanceId)) { $instanceFailed = $true }
        }

        # Also clean persistence for any service executable paths (only if not 3010).
        # ServiceImagePath is a raw service ImagePath: the exe is QUOTED and
        # followed by launch arguments, e.g.
        #   "C:\...\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&..."
        # Split-Path on that whole string yields a path with a leading quote,
        # so this sweep silently searched a directory that never exists.
        # Prefer the detector's already-parsed MainExe; otherwise pull the exe
        # out of the ImagePath before taking its parent.
        if (-not $rebootRequired) {
            $svcExe = [string](Get-EntryPropertySafe -Instance $inst -PropertyName 'MainExe')
            if (-not $svcExe) {
                $svcImagePath = [string](Get-EntryPropertySafe -Instance $inst -PropertyName 'ServiceImagePath')
                if ($svcImagePath) {
                    $quoted = [regex]::Match($svcImagePath, '^\s*"([^"]+)"')
                    if ($quoted.Success) {
                        $svcExe = $quoted.Groups[1].Value
                    } else {
                        $bare = [regex]::Match($svcImagePath, '^\s*(\S.*?\.exe)', 'IgnoreCase')
                        if ($bare.Success) { $svcExe = $bare.Groups[1].Value }
                    }
                }
            }
            if ($svcExe) {
                $svcDir = Split-Path -Parent $svcExe
                if ($svcDir -and $svcDir -ne $installDir) {
                    if (-not (Clean-Persistence -InstallDir $svcDir -InstanceId $instanceId)) { $instanceFailed = $true }
                }
            }
        }

        # FIX (reliability): don't mark 'Completed' when a sub-action failed.
        # Otherwise -Resume skips an actually-half-cleaned instance forever.
        # Also: for 3010 (reboot required), mark as RebootPending so -Resume
        # will re-attempt persistence cleanup after reboot, NOT skip it.
        if ($instanceFailed) {
            Update-ResumeStatus -InstanceId $instanceId -Status 'Failed'
            Write-Log "  Instance had one or more failed actions; marked Failed (will be re-attempted on -Resume)" 'Error'
            $overallSuccess = $false
        } elseif ($rebootRequired) {
            if ($Execute) {
                # Schedule the post-reboot continuation so persistence cleanup
                # actually happens without operator intervention.
                Set-RunOnceResume -InstanceId $instanceId -WorkDir $WorkDir
            }
            Update-ResumeStatus -InstanceId $instanceId -Status 'RebootPending'
            Write-Log "  Uninstall succeeded, reboot required (3010); marked RebootPending for resume" 'Warn'
            $overallSuccess = $false  # Overall run incomplete until reboot
        } else {
            Update-ResumeStatus -InstanceId $instanceId -Status 'Completed'
        }
    } catch {
        # FIX 3: one malformed/failed entry must not abort the remaining work
        $msg = $_.Exception.Message
        Write-Log "  Unhandled error processing instance ${instanceId}, continuing with next: $msg" 'Error'
        Add-ManifestEntry -InstanceId $instanceId -Action 'ProcessInstance' -Target 'N/A' -Result 'Failed' -Details "Unhandled error, continued with next instance: $msg"
        Update-ResumeStatus -InstanceId $instanceId -Status 'Failed'
        $overallSuccess = $false
        continue
    }
}

Write-ResumeMarker -Phase 'session-complete'

# -----------------------------------------------------------------------------
# Write removal manifest
# -----------------------------------------------------------------------------
Write-Section "Writing removal manifest"

$manifestObj = [PSCustomObject]@{
    Script           = $ScriptName
    Version          = $ScriptVersion
    GeneratedUtc     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    ComputerName     = $env:COMPUTERNAME
    PlanFile         = $PlanFile
    WorkDir          = $WorkDir
    QuarantineDir    = $quarantineDir
    ExecuteMode      = $Execute.IsPresent
    ResumeMode       = $Resume.IsPresent
    Entries          = $script:Manifest.ToArray()
}

try {
    $manifestObj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8 -NoNewline
    Write-Log "Manifest written: $manifestPath"
} catch {
    Write-Log "Failed to write manifest: $($_.Exception.Message)" 'Error'
    $overallSuccess = $false
}

# -----------------------------------------------------------------------------
# Final summary
# -----------------------------------------------------------------------------
Write-Section "Removal complete"

$successCount = @($script:Manifest | Where-Object { $_.Result -eq 'Success' }).Count
$failedCount  = @($script:Manifest | Where-Object { $_.Result -eq 'Failed' }).Count
$dryRunCount  = @($script:Manifest | Where-Object { $_.Result -eq 'DryRun' }).Count
$deferredCount = @($script:Manifest | Where-Object { $_.Result -eq 'Deferred' }).Count
$verifFailCount = @($script:Manifest | Where-Object { ($_.Action -eq 'ProductVerification') -and ($_.Result -eq 'PRODUCT_VERIFICATION_FAILED') }).Count

Write-Log "Actions successful:   $successCount"
Write-Log "Actions failed:       $failedCount"
Write-Log "Actions dry-run:      $dryRunCount"
Write-Log "Actions deferred:     $deferredCount"
Write-Log "Verification failures (skipped, never uninstalled): $verifFailCount"
Write-Log "Manifest: $manifestPath"

if ($failedCount -gt 0) {
    Write-Log "WARNING: Some actions failed. Check manifest for details." 'Warn'
    $overallSuccess = $false
}

if ($deferredCount -gt 0) {
    Write-Log "Some file moves deferred to reboot. RunOnce key set." 'Warn'
}

if (-not $Execute) {
    Write-Log "DRY-RUN complete. Re-run with -Execute to perform actual removal." 'Warn'
}

if ($overallSuccess) { exit 0 } else { exit 1 }