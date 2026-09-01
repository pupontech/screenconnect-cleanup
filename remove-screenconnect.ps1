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
  (4) Support reboot-resume via a highest-privilege scheduled logon task if files were in-use
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
$ScriptVersion = '1.7.37'
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
        [int]$ExitCode = $null,
        [string]$SourcePath = '',
        [string]$DestinationPath = '',
        [string]$SourceIdentity = ''
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
    if ($SourcePath) { $entry.SourcePath = $SourcePath }
    if ($DestinationPath) { $entry.DestinationPath = $DestinationPath }
    if ($SourceIdentity) { $entry.SourceIdentity = $SourceIdentity }
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

function Get-PathIdentityHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        $hash = Get-Sha256File -Path $Path
        if (-not $hash) { throw "Could not hash source file: $Path" }
        return $hash.ToLowerInvariant()
    }
    $rootFull = [System.IO.Path]::GetFullPath($Path).TrimEnd([char[]]@([char]92, [char]47))
    $allChildren = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop)
    foreach ($child in $allChildren) {
        if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point encountered while hashing source tree: $($child.FullName)"
        }
    }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($child in @($allChildren | Where-Object { -not $_.PSIsContainer })) {
        $hash = Get-Sha256File -Path $child.FullName
        if (-not $hash) { throw "Could not hash source tree file: $($child.FullName)" }
        $relative = $child.FullName.Substring($rootFull.Length).TrimStart([char[]]@([char]92, [char]47))
        [void]$lines.Add(($relative.ToLowerInvariant() + '|' + [string]$child.Length + '|' + $hash.ToLowerInvariant()))
    }
    $identityText = 'directory`n' + (($lines.ToArray() | Sort-Object) -join "`n")
    return (Get-Sha256Hex -Text $identityText)
}

function Expand-Env {
    param([string]$Path)
    if (-not $Path) { return $Path }
    return [System.Environment]::ExpandEnvironmentVariables($Path)
}

function Test-PathContained {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Candidate)
    try {
        $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]]@([char]92, [char]47))
        if (-not (Test-Path -LiteralPath $rootFull)) { return $false }
        $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
        $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
        if (-not $candidateFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }

        # Lexical containment is not enough when a path component is a junction
        # or symlink. Walk existing components, including the nearest existing
        # parent of a not-yet-created candidate, and reject every reparse point.
        $current = $candidateFull
        while ($current) {
            if (Test-Path -LiteralPath $current) {
                $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            }
            if ($current.TrimEnd([char[]]@([char]92, [char]47)) -eq $rootFull) { break }
            $parent = [System.IO.Directory]::GetParent($current)
            if ($null -eq $parent) { return $false }
            $current = $parent.FullName
        }
        return $true
    } catch { return $false }
}

function Test-LiteralPathReference {
    param([string]$Text, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Path)) { return $false }
    $needle = $Path.Trim().Trim('"').TrimEnd([char[]]@([char]92, [char]47))
    if (-not $needle) { return $false }
    $start = 0
    while ($start -lt $Text.Length) {
        $index = $Text.IndexOf($needle, $start, [System.StringComparison]::OrdinalIgnoreCase)
        if ($index -lt 0) { return $false }
        $beforeOk = ($index -eq 0) -or ($Text[$index - 1] -in @([char]92, [char]47, [char]34, [char]32, [char]9))
        $afterIndex = $index + $needle.Length
        $afterOk = ($afterIndex -ge $Text.Length) -or ($Text[$afterIndex] -in @([char]92, [char]47, [char]34, [char]32, [char]9, [char]63, [char]59))
        if ($beforeOk -and $afterOk) { return $true }
        $start = $index + 1
    }
    return $false
}

function Protect-QuarantinePathAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($env:OS -ne 'Windows_NT') { return }
    $rootItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $items = New-Object System.Collections.ArrayList
    [void]$items.Add($rootItem)
    if ($rootItem.PSIsContainer) {
        $allChildren = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop)
        foreach ($child in $allChildren) {
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse point encountered while protecting quarantine: $($child.FullName)"
            }
            [void]$items.Add($child)
        }
    }
    $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($item in @($items)) {
        $acl = if ($item.PSIsContainer) {
            New-Object System.Security.AccessControl.DirectorySecurity
        } else {
            New-Object System.Security.AccessControl.FileSecurity
        }
        $acl.SetAccessRuleProtection($true, $false)
        $inheritance = if ($item.PSIsContainer) {
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
        } else {
            [System.Security.AccessControl.InheritanceFlags]::None
        }
        foreach ($sid in @($adminSid, $systemSid, $userSid)) {
            $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($rule)
        }
        $acl.SetOwner($adminSid)
        Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
        $verifiedAcl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        if (-not $verifiedAcl.AreAccessRulesProtected) { throw "ACL inheritance remains enabled: $($item.FullName)" }
    }
}

function Test-ResumeMaterialsTrusted {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    if ($env:OS -ne 'Windows_NT') { return $true }
    $writeMask = [int]([System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)
    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) { return $false }
        try {
            $current = [System.IO.Path]::GetFullPath($path)
            while ($current) {
                if (Test-Path -LiteralPath $current) {
                    $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
                    foreach ($rule in @($acl.Access)) {
                        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                        if (([int]$rule.FileSystemRights -band $writeMask) -eq 0) { continue }
                        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } catch { return $false }
                        $trusted = $sid.IsWellKnown([System.Security.Principal.WellKnownSidType]::LocalSystemSid) -or
                            $sid.IsWellKnown([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
                        if (-not $trusted) { return $false }
                    }
                }
                $parent = [System.IO.Directory]::GetParent($current)
                if ($null -eq $parent) { break }
                if ($parent.FullName -eq $current) { break }
                $current = $parent.FullName
            }
        } catch { return $false }
    }
    return $true
}

function Get-SafeInstanceDirectoryName {
    param([string]$InstanceId)
    $safe = [regex]::Replace([string]$InstanceId, '[^A-Za-z0-9._-]', '_')
    $safe = $safe.Trim(' ', '.')
    if ([string]::IsNullOrWhiteSpace($safe) -or $safe -eq '.' -or $safe -eq '..') { $safe = 'unknown' }
    if ($safe.Length -gt 96) { $safe = $safe.Substring(0, 96) }
    return $safe
}

function Get-SafeInstanceFileStem {
    param([string]$InstanceId)
    $safe = Get-SafeInstanceDirectoryName -InstanceId $InstanceId
    $digest = Get-Sha256Hex -Text ([string]$InstanceId)
    if ($digest) { return ($safe + '-' + $digest.Substring(0, 12)) }
    return $safe
}

function Get-QuarantineDir {
    param([string]$WorkDir, [switch]$Prepare)
    $q = Join-Path $WorkDir 'quarantine'
    if (-not (Test-PathContained -Root $WorkDir -Candidate $q)) {
        throw "Quarantine path escaped WorkDir: $q"
    }
    if ($Prepare -and -not (Test-Path -LiteralPath $q)) {
        $null = New-Item -ItemType Directory -Path $q -Force
    }
    if (-not (Test-PathContained -Root $WorkDir -Candidate $q)) {
        throw "Quarantine path escaped WorkDir after preparation: $q"
    }

    # Remove inherited write access. Keep SYSTEM, local Administrators, and the
    # current elevated operator so evidence can be reviewed without exposing it
    # to ordinary users or inheriting permissive parent ACLs.
    if ($Prepare -and $env:OS -eq 'Windows_NT') {
        try {
            Protect-QuarantinePathAcl -Path $q
        } catch {
            throw "Could not apply/verify restrictive quarantine ACL: $($_.Exception.Message)"
        }
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

# Destructive mode accepts only a plan produced by this tool's review gate.
# Dry-runs remain useful for fixture testing, but -Execute requires an explicit
# approval marker, a current findings file, a matching hash, and a run binding.
if ($Execute) {
    $provenanceErrors = @()
    $confirmedProp = $plan.PSObject.Properties['RemovalConfirmed']
    if (-not $confirmedProp -or $confirmedProp.Value -ne $true) {
        $provenanceErrors += 'RemovalConfirmed=true is required'
    }
    $schemaProp = $plan.PSObject.Properties['PlanSchemaVersion']
    if (-not $schemaProp -or [int]$schemaProp.Value -lt 2) {
        $provenanceErrors += 'PlanSchemaVersion 2 or newer is required'
    }
    $sourceProp = $plan.PSObject.Properties['SourceFindings']
    $sourceHashProp = $plan.PSObject.Properties['SourceFindingsSha256']
    $runProp = $plan.PSObject.Properties['RunId']
    $source = if ($sourceProp) { [string]$sourceProp.Value } else { '' }
    if (-not $source -or -not (Test-Path -LiteralPath $source -PathType Leaf)) {
        $provenanceErrors += 'SourceFindings must reference an existing findings.json'
    } else {
        $actualHash = Get-Sha256File $source
        if (-not $sourceHashProp -or [string]$sourceHashProp.Value -ne $actualHash) {
            $provenanceErrors += 'SourceFindingsSha256 does not match the findings file'
        }
        $sourceRun = Split-Path -Leaf (Split-Path -Parent $source)
        if (-not $runProp -or [string]$runProp.Value -ne $sourceRun) {
            $provenanceErrors += 'RunId does not match the findings directory'
        }
        try {
            $sourceObj = Get-Content -LiteralPath $source -Raw | ConvertFrom-Json -ErrorAction Stop
            $hostProp = $plan.PSObject.Properties['ComputerName']
            $sourceHostProp = $sourceObj.PSObject.Properties['ComputerName']
            if ($hostProp -and $hostProp.Value -and $env:COMPUTERNAME -and [string]$hostProp.Value -ne [string]$env:COMPUTERNAME) {
                $provenanceErrors += 'Plan ComputerName does not match the current computer'
            }
            if ($sourceHostProp -and $sourceHostProp.Value -and $env:COMPUTERNAME -and [string]$sourceHostProp.Value -ne [string]$env:COMPUTERNAME) {
                $provenanceErrors += 'Findings ComputerName does not match the current computer'
            }
            if ($hostProp -and $sourceHostProp -and $hostProp.Value -and $sourceHostProp.Value -and
                [string]$hostProp.Value -ne [string]$sourceHostProp.Value) {
                $provenanceErrors += 'Plan ComputerName does not match findings ComputerName'
            }
            $toolProp = $sourceObj.PSObject.Properties['Tool']
            if (-not $toolProp -or [string]$toolProp.Value -ne 'detect-remote-access.ps1') {
                $provenanceErrors += 'SourceFindings is not produced by detect-remote-access.ps1'
            }
            $sourceRunProp = $sourceObj.PSObject.Properties['RunId']
            if (-not $sourceRunProp -or [string]$sourceRunProp.Value -ne $sourceRun) {
                $provenanceErrors += 'Findings RunId does not match its containing directory'
            }
        } catch {
            $provenanceErrors += 'SourceFindings could not be parsed'
        }
    }
    if ($provenanceErrors.Count -gt 0) {
        Write-Host ('ERROR: refusing -Execute with untrusted plan: ' + ($provenanceErrors -join '; ')) -ForegroundColor Red
        exit 2
    }
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

function Get-PathBinaryPath {
    # Extract the executable path from a Windows service ImagePath/command
    # string. Gate D must verify the file itself, not the command line with
    # quotes and arguments still attached.
    param([string]$PathString)
    if (-not $PathString) { return '' }
    $s = [string]$PathString
    if ($s.StartsWith('"')) {
        $endQ = $s.IndexOf('"', 1)
        if ($endQ -gt 0) { return $s.Substring(1, $endQ - 1) }
        return $s.Trim('"')
    }
    $quote = $s.IndexOf('"')
    if ($quote -gt 0) { return $s.Substring(0, $quote).Trim() }
    $rxOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $exeMatch = [regex]::Match($s, '^(?<path>.+?\.(?:exe|com))(?:\s|$)', $rxOpts)
    if ($exeMatch.Success) { return $exeMatch.Groups['path'].Value }
    return $s.Trim()
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
    foreach ($pn in @('ImagePath', 'ServiceImagePath', 'InstallDir', 'MainExe', 'File')) {
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

    # Gate D: execute mode requires a real signed binary. Name/path matches are
    # useful for discovery but are not sufficient authorization for removal.
    if ($Execute) {
        $signedExe = $null
        foreach ($p in $pathStrings) {
            $candidate = Get-PathBinaryPath -PathString $p
            if ($candidate -match '\.(exe|com)$' -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                $signedExe = $candidate
                break
            }
        }
        if (-not $signedExe) {
            [void]$reasons.Add('execute mode requires an existing ScreenConnect executable')
        } else {
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $signedExe -ErrorAction Stop
                $subject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }
                if ([string]$sig.Status -ne 'Valid') {
                    [void]$reasons.Add("executable signature status is not Valid: $($sig.Status)")
                } elseif ($subject -notmatch '(?i)ConnectWise|ScreenConnect') {
                    [void]$reasons.Add("executable signer is not identified as ConnectWise/ScreenConnect: $subject")
                }
            } catch {
                [void]$reasons.Add("could not verify executable Authenticode signature: $($_.Exception.Message)")
            }
        }
    }

    return [PSCustomObject]@{
        Verified = ($reasons.Count -eq 0)
        Reasons  = @($reasons.ToArray())
    }
}

function ConvertTo-RegistryProviderPath {
    # Normalize the raw Win32 registry path emitted by the detector and accept
    # only the provider forms needed by the uninstall-root allowlist below.
    param([string]$RegistryKeyPath)
    if ([string]::IsNullOrWhiteSpace($RegistryKeyPath)) { return '' }
    $p = $RegistryKeyPath.Trim()
    foreach ($prefix in @('Microsoft.PowerShell.Core\Registry::', 'Registry::')) {
        if ($p.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $p = $p.Substring($prefix.Length)
            break
        }
    }
    $win32Prefixes = @(
        @{ Prefix = 'HKEY_LOCAL_MACHINE\'; Provider = 'HKLM:\' },
        @{ Prefix = 'HKEY_CURRENT_USER\'; Provider = 'HKCU:\' },
        @{ Prefix = 'HKLM\'; Provider = 'HKLM:\' },
        @{ Prefix = 'HKCU\'; Provider = 'HKCU:\' }
    )
    foreach ($item in $win32Prefixes) {
        if ($p.StartsWith($item.Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $item.Provider + $p.Substring($item.Prefix.Length)
        }
    }
    return $p
}

function Test-AllowedUninstallRegistryPath {
    param([string]$RegistryKeyPath)
    $normalized = ConvertTo-RegistryProviderPath -RegistryKeyPath $RegistryKeyPath
    if ([string]::IsNullOrWhiteSpace($normalized)) { return $false }
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        if ($normalized.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or
            $normalized.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
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

    $resolvedKeyPath = ConvertTo-RegistryProviderPath -RegistryKeyPath $RegistryKeyPath
    if (-not (Test-AllowedUninstallRegistryPath -RegistryKeyPath $resolvedKeyPath)) {
        Write-Log "  Plan UninstallRegistryKey rejected: path is outside approved uninstall roots" 'Warn'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'ValidateUninstallKey' -Target $RegistryKeyPath -Result 'Rejected' -Details 'Registry key is outside approved HKLM/HKCU uninstall roots'
        return $null
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

$quarantineDir = Get-QuarantineDir -WorkDir $WorkDir -Prepare:$Execute
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
$script:DeferredQuarantineInstanceIds = New-Object System.Collections.ArrayList
$script:DeferredQuarantineRecords = New-Object System.Collections.ArrayList
$script:PriorVerifiedInstanceIds = New-Object System.Collections.ArrayList
$script:ResumeMarkerWriteFailed = $false
$script:ResumeMarkerIdentityFailed = $false

function Write-ResumeMarker {
    param([string]$Phase)
    if (-not $Execute) { return $true }
    try {
        $markerObj = [PSCustomObject]@{
            Script     = $ScriptName
            Version    = $ScriptVersion
            PlanFile   = $PlanFile
            Phase      = $Phase
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            ScriptHash = Get-Sha256File -Path $PSCommandPath
            PlanHash   = Get-Sha256File -Path $PlanFile
            Instances  = @($script:ResumeStatuses.ToArray())
        }
        $markerJson = $markerObj | ConvertTo-Json -Depth 5
        # UTF8 without BOM (Set-Content -Encoding UTF8 would emit a BOM on 5.1)
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($resumeMarkerPath, $markerJson, $utf8NoBom)
        return $true
    } catch {
        Write-Log "Could not update resume marker: $($_.Exception.Message)" 'Error'
        return $false
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
    $markerOk = Write-ResumeMarker -Phase 'session-start'
    if (-not $markerOk) {
        throw 'Cannot establish resume marker; refusing to begin execute-mode removal'
    }
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
    $markerOk = Write-ResumeMarker -Phase ('instance:' + $InstanceId + ' -> ' + $Status)
    if (-not $markerOk) {
        $script:ResumeMarkerWriteFailed = $true
        return
    }
}

if ($Resume) {
    Write-Log "RESUME mode: continuing after reboot" 'Warn'
    $resumeScriptPath = (Resolve-Path -LiteralPath $PSCommandPath -ErrorAction Stop).Path
    $resumePlanPath = (Resolve-Path -LiteralPath $PlanFile -ErrorAction Stop).Path
    if (-not (Test-ResumeMaterialsTrusted -Paths @($resumeScriptPath, $resumePlanPath, $WorkDir))) {
        throw 'Resume materials or their parent paths are writable by an untrusted identity'
    }
    $currentScriptHash = Get-Sha256File -Path $resumeScriptPath
    $currentPlanHash = Get-Sha256File -Path $resumePlanPath
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $oldManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            foreach ($oldEntry in @($oldManifest.Entries)) {
                $oldAction = Get-EntryPropertySafe -Instance $oldEntry -PropertyName 'Action'
                $oldResult = Get-EntryPropertySafe -Instance $oldEntry -PropertyName 'Result'
                $oldId = [string](Get-EntryPropertySafe -Instance $oldEntry -PropertyName 'InstanceId')
                if ($oldAction -eq 'ProductVerification' -and $oldResult -eq 'Passed' -and $oldId) {
                    if ($script:PriorVerifiedInstanceIds -notcontains $oldId) {
                        [void]$script:PriorVerifiedInstanceIds.Add($oldId)
                    }
                }
                if ($oldAction -eq 'Quarantine' -and $oldResult -eq 'Deferred') {
                    if ($script:DeferredQuarantineInstanceIds -notcontains $oldId) {
                        [void]$script:DeferredQuarantineInstanceIds.Add($oldId)
                    }
                    $oldSource = [string](Get-EntryPropertySafe -Instance $oldEntry -PropertyName 'SourcePath')
                    $oldDestination = [string](Get-EntryPropertySafe -Instance $oldEntry -PropertyName 'DestinationPath')
                    $oldIdentity = [string](Get-EntryPropertySafe -Instance $oldEntry -PropertyName 'SourceIdentity')
                    [void]$script:DeferredQuarantineRecords.Add([PSCustomObject]@{
                        InstanceId = $oldId
                        SourcePath = $oldSource
                        DestinationPath = $oldDestination
                        SourceIdentity = $oldIdentity
                    })
                }
            }
        } catch {
            $script:ResumeMarkerIdentityFailed = $true
            Write-Log "Could not inspect prior manifest for deferred quarantine moves: $($_.Exception.Message)" 'Error'
        }
    }
    if (Test-Path -LiteralPath $resumeMarkerPath) {
        try {
            $marker = Get-Content -LiteralPath $resumeMarkerPath -Raw | ConvertFrom-Json
            $markerScriptHash = [string](Get-EntryPropertySafe -Instance $marker -PropertyName 'ScriptHash')
            $markerPlanHash = [string](Get-EntryPropertySafe -Instance $marker -PropertyName 'PlanHash')
            if (-not $markerScriptHash -or -not $markerPlanHash -or
                $markerScriptHash -ne $currentScriptHash -or $markerPlanHash -ne $currentPlanHash) {
                $script:ResumeMarkerIdentityFailed = $true
                throw 'Resume marker script/plan identity does not match current files'
            }
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
            $script:ResumeMarkerIdentityFailed = $true
            Write-Log "Could not read resume marker: $($_.Exception.Message)" 'Error'
        }
    } else {
        $script:ResumeMarkerIdentityFailed = $true
        Write-Log "No resume marker found at: $resumeMarkerPath" 'Error'
    }
    if ($script:ResumeMarkerIdentityFailed) {
        throw 'Resume marker identity proof failed; refusing reboot resume'
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
        # Find processes by executable path only when the plan supplied an
        # install directory. An empty directory must never become a wildcard.
        if ($InstallDir) {
            $expandedInstallDir = Expand-Env $InstallDir
            $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
                Where-Object { $_.ExecutablePath -and (Test-PathContained -Root $expandedInstallDir -Candidate $_.ExecutablePath) }
            foreach ($p in $procs) {
                $pids += $p.ProcessId
            }
        }
        # Also by service name if no install dir
        if ($pids.Count -eq 0 -and $ServiceName) {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($svc -and $svc.ProcessId) {
                $pids += $svc.ProcessId
            }
        }
        # Do not fall back to global name/path matching. A host may contain
        # multiple legitimate ScreenConnect instances; only a process proven by
        # this plan's install directory or service PID belongs to this instance.
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
            if ($installDir) { $underInstall = ($bareExe -and (Test-PathContained -Root $installDir -Candidate $bareExe)) }
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
    $sourceItem = Get-Item -LiteralPath $SourcePath -Force -ErrorAction Stop
    if (($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to quarantine reparse-point source: $SourcePath"
    }
    $isDirectory = $sourceItem.PSIsContainer
    $sourceIdentity = Get-PathIdentityHash -Path $SourcePath
    if (-not $sourceIdentity) { throw "Could not establish source identity: $SourcePath" }
    $hashNote = ''
    $sha256 = ''
    if ($isDirectory) {
        # A whole-tree move must not carry a junction/symlink across the
        # containment boundary. Fail closed instead of merely skipping it while
        # moving the rest of the tree.
        $reparseItems = @(Get-ChildItem -LiteralPath $SourcePath -Recurse -Force -Attributes ReparsePoint -ErrorAction Stop)
        if ($reparseItems.Count -gt 0) {
            foreach ($rp in $reparseItems) {
                Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $rp.FullName -Result 'Failed' -Details 'Reparse point (junction/symlink) blocks whole-tree quarantine'
            }
            throw "Refusing to quarantine tree containing $($reparseItems.Count) reparse point(s): $SourcePath"
        }
        $safeInstanceFileStem = Get-SafeInstanceFileStem -InstanceId $InstanceId
        $hashCsv = Join-Path $WorkDir ('quarantine-hashes-' + $safeInstanceFileStem + '.csv')
        if (-not (Test-PathContained -Root $WorkDir -Candidate $hashCsv)) {
            throw "Refusing quarantine hash sidecar outside WorkDir: $hashCsv"
        }
        $rows = New-Object System.Collections.ArrayList
        foreach ($f in @(Get-ChildItem -LiteralPath $SourcePath -File -Recurse -Force -ErrorAction Stop)) {
            $h = Get-Sha256File $f.FullName
            [void]$rows.Add([PSCustomObject]@{
                Path   = $f.FullName
                Length = $f.Length
                SHA256 = $h
            })
        }
        try {
            $rows | Export-Csv -LiteralPath $hashCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            $hashNote = "directory, " + $rows.Count + " file(s) hashed -> " + $hashCsv
        } catch {
            throw "Directory hash CSV failed: $($_.Exception.Message)"
        }
        $sha256 = $hashNote
    } else {
        $sha256 = Get-Sha256File $SourcePath
    }
    $destName = [System.IO.Path]::GetFileName($SourcePath)
    $instanceDirName = Get-SafeInstanceDirectoryName -InstanceId $InstanceId
    $instanceQDir = Join-Path $quarantineDir $instanceDirName
    if (-not (Test-PathContained -Root $quarantineDir -Candidate $instanceQDir)) {
        throw "Refusing quarantine destination outside quarantine root: $instanceQDir"
    }
    $destPath = Join-Path $instanceQDir $destName
    if (-not (Test-PathContained -Root $quarantineDir -Candidate $destPath)) {
        throw "Refusing quarantine destination outside quarantine root: $destPath"
    }

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
        $destPath = Join-Path $instanceQDir ($unique + '-' + $destName)
        if (-not (Test-PathContained -Root $quarantineDir -Candidate $destPath)) {
            throw "Refusing collision-safe quarantine destination outside quarantine root: $destPath"
        }
    }

    # Ensure quarantine subdirectory exists
    $qSubDir = Split-Path -Parent $destPath
    if (-not (Test-PathContained -Root $quarantineDir -Candidate $qSubDir)) {
        throw "Refusing quarantine subdirectory outside quarantine root: $qSubDir"
    }
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
                $kernelType = 'Win32.Kernel32' -as [type]
                if (-not $kernelType) {
                    $kernelType = Add-Type -MemberDefinition @'
                    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@ -Name 'Kernel32' -Namespace 'Win32' -PassThru
                }
                $MOVEFILE_DELAY_UNTIL_REBOOT = 4
                $result = $kernelType::MoveFileEx($SourcePath, $destPath, $MOVEFILE_DELAY_UNTIL_REBOOT)
                if (-not $result) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "MoveFileEx failed with error $err"
                }
                # Set RunOnce to resume; inability to register a resume path is
                # a safety failure, not a warning that can be ignored.
                if (-not (Set-RunOnceResume -InstanceId $InstanceId -WorkDir $WorkDir)) {
                    # Cancel the already-queued delayed move before returning
                    # failure; otherwise Windows may still move the payload at
                    # reboot without any resume cleanup attached.
                    $cancelled = $kernelType::MoveFileEx($SourcePath, $null, $MOVEFILE_DELAY_UNTIL_REBOOT)
                    if (-not $cancelled) {
                        $cancelError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        throw "Could not register reboot-resume action and could not cancel pending MoveFileEx (error $cancelError)"
                    }
                    throw 'Could not register an elevated reboot-resume action; pending move cancelled'
                }
                if (-not ($script:DeferredQuarantineInstanceIds -contains $InstanceId)) {
                    [void]$script:DeferredQuarantineInstanceIds.Add($InstanceId)
                }
                Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $SourcePath -Result 'Deferred' -Details "File in use, scheduled for reboot move. SHA256: $sha256. Original: $SourcePath`nQuarantine: $destPath`nDescription: $Description" -SourcePath $SourcePath -DestinationPath $destPath -SourceIdentity $sourceIdentity
            } else {
                $destinationIdentity = Get-PathIdentityHash -Path $destPath
                if ($destinationIdentity -ne $sourceIdentity) {
                    throw "Post-move identity mismatch for $SourcePath; quarantine content changed during move"
                }
                # Verify destination ACLs after the move; the source ACL is not
                # trusted to inherit the protected quarantine policy.
                Protect-QuarantinePathAcl -Path $destPath
                # Already moved by the attempt above - just record it.
                Add-ManifestEntry -InstanceId $InstanceId -Action 'Quarantine' -Target $SourcePath -Result 'Success' -Details "Moved to quarantine. SHA256: $sha256. Original: $SourcePath`nQuarantine: $destPath`nDescription: $Description" -SourcePath $SourcePath -DestinationPath $destPath -SourceIdentity $sourceIdentity
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
        $scriptPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'remove-screenconnect.ps1')).Path
        $planPath = (Resolve-Path -LiteralPath $PlanFile).Path
        $workPath = (Resolve-Path -LiteralPath $WorkDir).Path
        if (-not (Test-ResumeMaterialsTrusted -Paths @($scriptPath, $planPath, $workPath))) {
            throw 'Resume materials or their parent paths are writable by an untrusted identity'
        }
        $safeTaskId = Get-SafeInstanceFileStem -InstanceId $InstanceId
        $taskName = 'SCCleanup-Resume-' + $safeTaskId
        $taskArgs = '-NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -PlanFile "' + $planPath + '" -WorkDir "' + $workPath + '" -Execute -Resume'

        # Task Scheduler is used instead of a plain RunOnce command so the
        # continuation receives SYSTEM/highest privileges without depending on
        # the interactive user's token or a UAC prompt at logon.
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgs -ErrorAction Stop
        $trigger = New-ScheduledTaskTrigger -AtLogOn -ErrorAction Stop
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -ErrorAction Stop
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
        Write-Log "  Highest-privilege scheduled resume task registered: $taskName"
        return $true
    } catch {
        Write-Log "  Failed to register highest-privilege resume task: $($_.Exception.Message)" 'Error'
        return $false
    }
}

function Remove-ResumeTask {
    param([string]$InstanceId)
    try {
        $taskName = 'SCCleanup-Resume-' + (Get-SafeInstanceFileStem -InstanceId $InstanceId)
        if (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "  Could not remove completed resume task: $($_.Exception.Message)" 'Warn'
    }
}

# -----------------------------------------------------------------------------
# Persistence cleanup (scheduled tasks, Run keys, WMI subscriptions)
# -----------------------------------------------------------------------------
function Clean-Persistence {
    param([string]$InstallDir, [string]$InstanceId)
    $InstallDir = Expand-Env $InstallDir
    $cleaned = 0
    $failed = $false

    # 1. Scheduled Tasks referencing the install directory
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
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
                        if ($path) { $path = Expand-Env ([string]$path) }
                        if ($args) { $args = Expand-Env ([string]$args) }
                        $pathReferences = $path -and (Test-PathContained -Root $InstallDir -Candidate $path)
                        $argsReferences = $args -and (Test-LiteralPathReference -Text $args -Path $InstallDir)
                        if ($pathReferences -or $argsReferences) {
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
    } catch {
        $failed = $true
        Write-Log "  Scheduled task enumeration failed: $($_.Exception.Message)" 'Error'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'EnumerateScheduledTasks' -Target 'N/A' -Result 'Failed' -Details $_.Exception.Message
    }

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
                    $expandedVal = if ($val) { Expand-Env ([string]$val) } else { $val }
                    if ($expandedVal -and (Test-LiteralPathReference -Text ([string]$expandedVal) -Path $InstallDir)) {
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
                $consumerTemplate = if ($consumer -and $consumer.CommandLineTemplate) { Expand-Env ([string]$consumer.CommandLineTemplate) } else { $null }
                if ($consumerTemplate -and (Test-LiteralPathReference -Text ([string]$consumerTemplate) -Path $InstallDir)) {
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
    } catch {
        $failed = $true
        Write-Log "  WMI subscription enumeration failed: $($_.Exception.Message)" 'Error'
        Add-ManifestEntry -InstanceId $InstanceId -Action 'EnumerateWmiSubscriptions' -Target 'N/A' -Result 'Failed' -Details $_.Exception.Message
    }

    if ($cleaned -eq 0 -and -not $failed) {
        Write-Log "  No persistence artifacts found referencing $InstallDir"
        Add-ManifestEntry -InstanceId $InstanceId -Action 'CleanPersistence' -Target $InstallDir -Result 'Skipped' -Details 'No artifacts found'
    }
    return (-not $failed)
}

# -----------------------------------------------------------------------------
# Main processing loop
# -----------------------------------------------------------------------------
Write-Section "Processing ScreenConnect instances"

$null = Initialize-ResumeMarker

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

        $isRebootPendingResume = ($Resume -and
            ($script:RebootPendingInstanceIds -contains $instanceId) -and
            ($script:PriorVerifiedInstanceIds -contains $instanceId))
        if ($isRebootPendingResume) {
            # The prior run already passed product verification. On a 3010
            # reboot, the vendor may have removed the install directory before
            # this continuation starts, so a fresh on-disk identity check would
            # incorrectly block the persistence-only cleanup. Require both the
            # marker status and prior manifest proof; a marker alone is not
            # enough to bypass the current identity gate.
            Write-Log "  RebootPending resume: prior ProductVerification passed; current payload may already be absent"
            Add-ManifestEntry -InstanceId $instanceId -Action 'ProductVerification' -Target 'N/A' -Result 'Passed' -Details 'Inherited from prior run; RebootPending resume is limited to post-reboot cleanup'
        } else {
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
            Add-ManifestEntry -InstanceId $instanceId -Action 'ProductVerification' -Target 'N/A' -Result 'Passed' -Details 'Entry identity and Authenticode signer confirmed against ScreenConnect patterns'
            # The execute gate confirms a known binary name and a valid
            # ConnectWise/ScreenConnect Authenticode signer. Review the full
            # manifest before removal; signature proof does not replace operator
            # approval or the current-run plan binding.
            Write-Log "  NOTE: identity and Authenticode signer verified; review the instance before removal." 'Warn'
        }

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
        if ($isRebootPendingResume) {
            Write-Log "  RebootPending resume: vendor uninstaller already succeeded; running post-reboot persistence cleanup only"
            if ($script:DeferredQuarantineInstanceIds -contains $instanceId) {
                $deferredRecord = @($script:DeferredQuarantineRecords | Where-Object { $_.InstanceId -eq $instanceId } | Select-Object -First 1)
                $resumeSource = if ($deferredRecord.Count -gt 0) { [string]$deferredRecord[0].SourcePath } else { '' }
                $resumeDest = if ($deferredRecord.Count -gt 0) { [string]$deferredRecord[0].DestinationPath } else { '' }
                $expectedIdentity = if ($deferredRecord.Count -gt 0) { [string]$deferredRecord[0].SourceIdentity } else { '' }
                $resumeFailure = $null
                if (-not $resumeSource -or -not $resumeDest -or -not $expectedIdentity) {
                    $resumeFailure = 'Deferred manifest lacks structured source, destination, or source identity proof'
                } elseif (-not (Test-PathContained -Root $quarantineDir -Candidate $resumeDest)) {
                    $resumeFailure = 'Deferred quarantine destination failed canonical containment/reparse validation'
                } elseif (Test-Path -LiteralPath $resumeSource) {
                    $resumeFailure = 'Deferred quarantine source still exists after reboot'
                } elseif (-not (Test-Path -LiteralPath $resumeDest)) {
                    $resumeFailure = 'Deferred quarantine destination is missing after reboot'
                } else {
                    try {
                        $actualIdentity = Get-PathIdentityHash -Path $resumeDest
                        if ($actualIdentity -ne $expectedIdentity) {
                            $resumeFailure = "Deferred destination identity mismatch (expected $expectedIdentity, got $actualIdentity)"
                        } else {
                            Protect-QuarantinePathAcl -Path $resumeDest
                        }
                    } catch {
                        $resumeFailure = "Deferred destination identity/ACL verification failed: $($_.Exception.Message)"
                    }
                }
                if ($resumeFailure) {
                    Add-ManifestEntry -InstanceId $instanceId -Action 'ResumeVerify' -Target $resumeDest -Result 'Failed' -Details $resumeFailure
                    Update-ResumeStatus -InstanceId $instanceId -Status 'Failed'
                    Write-Log "  Deferred quarantine verification failed; instance remains incomplete: $resumeFailure" 'Error'
                    $overallSuccess = $false
                    continue
                }
                Add-ManifestEntry -InstanceId $instanceId -Action 'ResumeVerify' -Target $resumeDest -Result 'Success' -Details "Deferred quarantine source is absent and destination identity matches $expectedIdentity; ACLs verified"
            }
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
            $resumeResidual = @()
            if ($installDir -and (Test-Path -LiteralPath $installDir)) { $resumeResidual += 'install directory remains after reboot' }
            if ($serviceName -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { $resumeResidual += "service '$serviceName' remains after reboot" }
            if ($resumeResidual.Count -gt 0) {
                Add-ManifestEntry -InstanceId $instanceId -Action 'ResumePostcondition' -Target $installDir -Result 'Failed' -Details ($resumeResidual -join '; ')
                Write-Log ("  RebootPending postcondition failed: " + ($resumeResidual -join '; ')) 'Error'
                $instanceFailed = $true
            }
            if ($instanceFailed) {
                Update-ResumeStatus -InstanceId $instanceId -Status 'Failed'
                Write-Log "  RebootPending post-reboot cleanup failed for: $instanceId" 'Error'
                $overallSuccess = $false
            } else {
                Update-ResumeStatus -InstanceId $instanceId -Status 'Completed'
                Remove-ResumeTask -InstanceId $instanceId
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

        $uninstallPostconditionFailed = $false
        if ($Execute -and $uninstallSucceeded -and -not $rebootRequired) {
            $residual = @()
            if ($installDir -and (Test-Path -LiteralPath $installDir)) { $residual += 'install directory remains' }
            if ($serviceName -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { $residual += "service '$serviceName' remains" }
            if ($residual.Count -gt 0) {
                $uninstallPostconditionFailed = $true
                $uninstallSucceeded = $false
                $instanceFailed = $true
                $postconditionText = ($residual -join '; ')
                Write-Log "  Vendor uninstaller reported success but postcondition failed: $postconditionText" 'Error'
                Add-ManifestEntry -InstanceId $instanceId -Action 'UninstallPostcondition' -Target $installDir -Result 'Failed' -Details $postconditionText
            }
        }

        # 3. Manual surgery fallback ONLY if uninstall failed or no uninstaller
        # Do NOT run manual surgery if uninstall succeeded (exit 0 or 3010)
        if (-not $uninstallSucceeded -and $installDir -and (Test-Path -LiteralPath $installDir)) {
            Write-Log "  Proceeding with manual surgery for: $installDir"

            # Quarantine the entire install directory. No destructive metadata
            # surgery is allowed unless containment succeeded first.
            $quarantineSucceeded = Move-ToQuarantine -SourcePath $installDir -InstanceId $instanceId -Description 'Install directory'
            if (-not $quarantineSucceeded) { $instanceFailed = $true }

            if ($quarantineSucceeded) {
                # Delete service registration only after the payload is safely
                # in quarantine (or was already absent and recorded as skipped).
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
                    $safeInstanceFileStem = Get-SafeInstanceFileStem -InstanceId $instanceId
                    $backup = Join-Path $WorkDir ('uninstall-key-' + $safeInstanceFileStem + '.reg')
                    if (-not (Test-PathContained -Root $WorkDir -Candidate $backup)) {
                        throw "Refusing uninstall-key backup outside WorkDir: $backup"
                    }
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
                Write-Log "  Quarantine failed; leaving service and uninstall registry metadata in place for safety" 'Error'
                if ($serviceName) {
                    Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteService' -Target $serviceName -Result 'Skipped' -Details 'Quarantine failed; service registration left in place'
                }
                if ($uninstallEntry) {
                    Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteUninstallKey' -Target 'N/A' -Result 'Skipped' -Details 'Quarantine failed; uninstall registry key left in place'
                }
            }
        } elseif ($uninstallPostconditionFailed) {
            Write-Log "  Vendor uninstaller postcondition failed; leaving service and uninstall metadata in place" 'Error'
            if ($serviceName) {
                Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteService' -Target $serviceName -Result 'Skipped' -Details 'Uninstaller postcondition failed; service registration left in place'
            }
            if ($uninstallEntry) {
                Add-ManifestEntry -InstanceId $instanceId -Action 'DeleteUninstallKey' -Target 'N/A' -Result 'Skipped' -Details 'Uninstaller postcondition failed; uninstall registry key left in place'
            }
        } elseif ($uninstallSucceeded) {
            if ($rebootRequired) {
                Write-Log "  Vendor uninstaller requested reboot; skipping service and persistence surgery until resume" 'Warn'
                Add-ManifestEntry -InstanceId $instanceId -Action 'PostUninstall' -Target $installDir -Result 'RebootPending' -Details 'Exit 3010; no manual service/registry/persistence surgery before reboot'
            } else {
                Write-Log "  Vendor uninstaller postconditions passed; no manual surgery required"
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
        } elseif ($rebootRequired -or ($script:DeferredQuarantineInstanceIds -contains $instanceId)) {
            if ($rebootRequired) {
                # Schedule the post-reboot continuation so persistence cleanup
                # actually happens without operator intervention.
                if ($Execute -and -not (Set-RunOnceResume -InstanceId $instanceId -WorkDir $WorkDir)) {
                    $instanceFailed = $true
                }
            }
            if ($instanceFailed) {
                Update-ResumeStatus -InstanceId $instanceId -Status 'Failed'
                Write-Log "  Resume registration failed; instance remains incomplete" 'Error'
                $overallSuccess = $false
            } else {
                Update-ResumeStatus -InstanceId $instanceId -Status 'RebootPending'
                Write-Log "  Removal is deferred until reboot; marked RebootPending for resume" 'Warn'
                $overallSuccess = $false
            }
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

$finalMarkerOk = Write-ResumeMarker -Phase 'session-complete'
if ($Execute -and -not $finalMarkerOk) {
    $script:ResumeMarkerWriteFailed = $true
}
if ($Execute -and $script:ResumeMarkerWriteFailed) {
    $overallSuccess = $false
    Write-Log 'One or more resume-marker writes failed; removal remains incomplete for safe resume.' 'Error'
}

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
# Aggregate manifest counts BEFORE the human-readable report below: the report
# references these variables and runs under Set-StrictMode -Version 2.0, so
# computing them after the write threw "The variable '$successCount' cannot be
# retrieved because it has not been set." (observed live 2026-08-27 on
# DESTROYERLTC202 - manifest + exit 1 despite every action succeeding).
# -----------------------------------------------------------------------------
$successCount   = @($script:Manifest | Where-Object { $_.Result -eq 'Success' }).Count
$failedCount    = @($script:Manifest | Where-Object { $_.Result -eq 'Failed' }).Count
$dryRunCount    = @($script:Manifest | Where-Object { $_.Result -eq 'DryRun' }).Count
$deferredCount  = @($script:Manifest | Where-Object { $_.Result -eq 'Deferred' }).Count
$verifFailCount = @($script:Manifest | Where-Object { ($_.Action -eq 'ProductVerification') -and ($_.Result -eq 'PRODUCT_VERIFICATION_FAILED') }).Count

# -----------------------------------------------------------------------------
# Write a HUMAN-READABLE removal report (plain English .txt)
#
# The JSON manifest above is machine-readable (consumed by the report stage and
# resurrection logic), but it is not easy for a technician or client to read.
# This .txt file is the human-facing deliverable: every action in plain English,
# with the problems/failures called out up top.
# -----------------------------------------------------------------------------
$reportTxtPath = Join-Path $WorkDir 'removal-report.txt'
try {
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add("========================================================")
    [void]$lines.Add(" SCREENCONNECT REMOVAL REPORT")
    [void]$lines.Add("========================================================")
    [void]$lines.Add("")
    [void]$lines.Add("Generated (UTC) : $($manifestObj.GeneratedUtc)")
    [void]$lines.Add("Computer        : $($manifestObj.ComputerName)")
    [void]$lines.Add("Tool version    : $($manifestObj.Version)")
    [void]$lines.Add("Mode            : $(if ($manifestObj.ExecuteMode) { 'EXECUTE (real removal)' } else { 'DRY-RUN (no changes made)' })")
    [void]$lines.Add("Plan file       : $($manifestObj.PlanFile)")
    [void]$lines.Add("Working dir     : $($manifestObj.WorkDir)")
    [void]$lines.Add("Quarantine dir  : $($manifestObj.QuarantineDir)")
    [void]$lines.Add("")

    # --- PROBLEMS / FAILURES first (most important for a human) -------------
    $problems = @($script:Manifest | Where-Object { $_.Result -in @('Failed','Rejected','PRODUCT_VERIFICATION_FAILED','LaunchFailed','TimeoutLeftRunning') })
    [void]$lines.Add("--------------------------------------------------------")
    if ($problems.Count -eq 0) {
        [void]$lines.Add(" PROBLEMS: NONE - every attempted action succeeded.")
    } else {
        [void]$lines.Add(" PROBLEMS (" + $problems.Count + "):")
        [void]$lines.Add("--------------------------------------------------------")
        foreach ($p in $problems) {
            $who = if ($p.InstanceId) { "Instance $($p.InstanceId): " } else { '' }
            [void]$lines.Add("- $($who)$($p.Action) on [$($p.Target)] -> $($p.Result)")
            if ($p.Details) { [void]$lines.Add("    $($p.Details)") }
            if ($null -ne $p.ExitCode -and $p.ExitCode -ne '') { [void]$lines.Add("    Exit code: $($p.ExitCode)") }
        }
    }
    [void]$lines.Add("")

    # --- Plain-English summary counts -------------------------------------
    [void]$lines.Add("--------------------------------------------------------")
    [void]$lines.Add(" SUMMARY")
    [void]$lines.Add("--------------------------------------------------------")
    [void]$lines.Add(" Successful actions : $successCount")
    [void]$lines.Add(" Failed actions     : $failedCount")
    [void]$lines.Add(" Dry-run actions    : $dryRunCount")
    [void]$lines.Add(" Deferred to reboot : $deferredCount")
    [void]$lines.Add(" Verification skips : $verifFailCount (product could not be verified; left installed on purpose)")
    [void]$lines.Add("")

    # --- Full action log, in plain English, chronological ------------------
    [void]$lines.Add("--------------------------------------------------------")
    [void]$lines.Add(" FULL ACTION LOG")
    [void]$lines.Add("--------------------------------------------------------")
    foreach ($e in $script:Manifest.ToArray()) {
        $when = $e.TimestampUtc
        $who  = if ($e.InstanceId) { " [$($e.InstanceId)]" } else { '' }
        $line = "$when$who  $($e.Action): $($e.Target) -> $($e.Result)"
        [void]$lines.Add($line)
        if ($e.Details) { [void]$lines.Add("            $($e.Details)") }
    }
    [void]$lines.Add("")
    [void]$lines.Add("End of report. Machine-readable details are in removal-manifest.json.")
    [void]$lines.Add("========================================================")

    [System.IO.File]::WriteAllText($reportTxtPath, ($lines -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    Write-Log "Human-readable report written: $reportTxtPath"
} catch {
    Write-Log "Failed to write removal report: $($_.Exception.Message)" 'Error'
    $overallSuccess = $false
}


# -----------------------------------------------------------------------------
# Final summary
# -----------------------------------------------------------------------------
Write-Section "Removal complete"

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
    Write-Log "Some file moves deferred to reboot. Highest-privilege scheduled resume task set." 'Warn'
}

if (-not $Execute) {
    Write-Log "DRY-RUN complete. Re-run with -Execute to perform actual removal." 'Warn'
}

if ($overallSuccess) { exit 0 } else { exit 1 }