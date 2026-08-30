<# 
  sc-cleanup.ps1  -  Top-level stage runner for the ScreenConnect Cleanup Tool pipeline

  Runs the full incident investigation pipeline in order:
  Stage 0: Preflight
  Stage 1: Snapshot (BEFORE)  [never skippable]
  Stage 2: Remote-access detection
  Stage 3: Technician review gate
  Stage 4: Contain + Remove  [skip: -sr; explicit confirmation required]
  Stage 5: Scanners  [skip: -sa]
  Stage 6: Uninstall installed AV  [skip: -avu; attended GUI]
  Stage 7: Procmon  [opt-in: -procmon]
  Stage 8: Snapshot (AFTER) + Diff
  Stage 9: Report

  Nothing destructive is reachable without explicit flags and the review gate.
  -ExecuteRemoval pre-authorizes Stage 4 for lab/VM testing: every detected
  ScreenConnect instance is auto-marked REMOVE and the typed confirmation is
  waived (KEEP remains the default in the normal interactive review gate).
  It still honors -sr. Do not use it on a client machine.
  PowerShell 5.1 compatible. Pure ASCII, no BOM.
#>

param(
    # Skip flags
    [switch]$sa,          # skip antivirus scanners (Stage 5)
    [switch]$sr,          # skip removal (detect + report only)
    [switch]$avu,         # skip uninstalling installed AV (Stage 6)
    [switch]$np,          # no restore point
    [switch]$offline,     # use pre-staged tool pack, do not download
    [switch]$procmon,     # force Procmon stage (bounded live capture)
    [switch]$force,       # override server-OS refusal
    [switch]$ExecuteRemoval, # TEST MODE: pre-authorize removal (no typed confirmation)

    # Configuration
    [int]$ProcmonRuntime = 180,  # Stage 7 capture window in seconds (default 3 min)
    [string]$IncidentDate,   # incident window anchor (yyyy-MM-dd; never prompted - defaults to today)
    [string]$OutRoot,        # working directory root (default: C:\RIT-SCC)
    [string]$ToolDir,        # tool pack directory (default: <script dir>\tools)

    # Debug / development
    [switch]$WhatIf,         # show what would run, execute nothing
    [switch]$VerboseLog      # verbose stage logging
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Constants & script metadata
# -----------------------------------------------------------------------------
$ScriptVersion = '1.7.21'
$ScriptName = 'sc-cleanup.ps1'
$PipelineStages = @(
    @{ Id = 0; Name = 'Preflight';            SkipFlag = '' },
    @{ Id = 1; Name = 'Snapshot (Before)';    SkipFlag = '' },
    @{ Id = 2; Name = 'Detect';               SkipFlag = '' },
    @{ Id = 3; Name = 'Review Gate';          SkipFlag = '' },
    @{ Id = 4; Name = 'Contain + Remove';     SkipFlag = 'sr' },
    @{ Id = 5; Name = 'Scanners';             SkipFlag = 'sa' },
    @{ Id = 6; Name = 'Uninstall installed AV'; SkipFlag = 'avu' },
    @{ Id = 7; Name = 'Procmon';              SkipFlag = '' },
    @{ Id = 8; Name = 'Snapshot (After)+Diff'; SkipFlag = '' },
    @{ Id = 9; Name = 'Report';               SkipFlag = '' }
)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
function Write-StageLog {
    param([string]$Message, [string]$Level = 'Info')
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $prefix = @{ 'Info' = '==>'; 'Warn' = '!! '; 'Error' = '!!!'; 'Debug' = '...' }[$Level]
    if (-not $prefix) { $prefix = '==>' }
    $line = "$stamp $prefix $Message"
    Write-Host $line
    if (Test-Path variable:MasterLogPath) {
        if ($MasterLogPath -and (Test-Path $MasterLogPath) -and ($VerboseLog -or $Level -ne 'Debug')) {
            Add-Content -Path $MasterLogPath -Value $line -Encoding UTF8
        }
    }
}

function Write-Section {
    param([string]$Title)
    $bar = '-' * 70
    Write-Host ""
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor DarkCyan
    if ($MasterLogPath -and (Test-Path $MasterLogPath)) {
        Add-Content -Path $MasterLogPath -Value "" -Encoding UTF8
        Add-Content -Path $MasterLogPath -Value $bar -Encoding UTF8
        Add-Content -Path $MasterLogPath -Value "  $Title" -Encoding UTF8
        Add-Content -Path $MasterLogPath -Value $bar -Encoding UTF8
    }
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

function Test-UacEnabled {
    # HKLM\...\Policies\System!EnableLUA. Absent key = UAC on (pre-Vista-style
    # machines do not exist anymore); 0 = disabled; anything else = enabled.
    try {
        $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop
        return ($val.EnableLUA -ne 0)
    } catch {
        return $true
    }
}

function Test-IsServerOS {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = $os.Caption
        return $caption -match '(?i)Server'
    } catch {
        return $false
    }
}

function Get-AvailableDiskSpace {
    param([string]$Path)
    try {
        $drive = [System.IO.DriveInfo]::new($Path)
        return [math]::Floor($drive.AvailableFreeSpace / 1GB)
    } catch {
        return -1
    }
}

function Resolve-WorkingDir {
    param([string]$Root, [string]$HostName)
    $ts = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    $dir = Join-Path $Root ("$HostName-$ts")
    return $dir
}

function Get-JsonItems {
    # The unary comma is required: 'return @()' hands back $null once PowerShell
    # unrolls the empty array, and under Set-StrictMode 2.0 the caller's
    # $result.Count then blows up with "property 'Count' cannot be found".
    param($Value)
    if ($null -eq $Value) { return , @() }
    if ($Value -is [System.Array]) { return , @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return , @($Value) }
    return , @($Value)
}

function Get-PropertyValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

# Runs a child script in its OWN process so it cannot inherit the runner's
# variable table (PowerShell scope-bleed otherwise corrupts child scripts that
# use Get-Prop/Get-Items-style helpers). Fault containment + clean separation,
# matching how Tron spawns each of its tools. Returns the process exit code.
function Invoke-ChildScript {
    param(
        [string]$ScriptPath,
        [string[]]$ArgumentList,
        [string]$LogTag = 'child'
    )

    if (-not (Test-Path $ScriptPath)) {
        Write-StageLog ("$LogTag script not found: " + $ScriptPath) 'Error'
        return 1
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $runner = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $runner) { $runner = Get-Command powershell.exe -ErrorAction SilentlyContinue }
    if (-not $runner) {
        Write-StageLog "No PowerShell child-process host found." 'Error'
        return 1
    }
    $psi.FileName = $runner.Source
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $ScriptPath + '"'
    foreach ($a in $ArgumentList) {
        if ($null -eq $a) { $a = '' }
        # Quote arguments that contain spaces or special chars.
        if ($a -match '[\s"&|<>]') {
            $psi.Arguments += ' "' + ($a -replace '"', '\"') + '"'
        } else {
            $psi.Arguments += ' ' + $a
        }
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    } catch {
        Write-StageLog ("$LogTag failed to start: " + $_.Exception.Message) 'Error'
        return 1
    }

    # Read stderr asynchronously. Draining both pipes synchronously deadlocks
    # when the child fills one buffer while we are blocked on the other.
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $stderrTask.Result
    $proc.WaitForExit()
    $exitCode = $proc.ExitCode

    if ($stdout) {
        foreach ($line in ($stdout -split "`n")) {
            $line = $line.TrimEnd("`r")
            if ($line) { Write-StageLog ($LogTag + ": " + $line) }
        }
    }
    if ($stderr) {
        foreach ($line in ($stderr -split "`n")) {
            $line = $line.TrimEnd("`r")
            if ($line) { Write-StageLog ($LogTag + " ERR: " + $line) 'Warn' }
        }
    }

    return $exitCode
}

function Invoke-Stage {
    param(
        [int]$StageId,
        [string]$StageName,
        [scriptblock]$StageBlock,
        [string]$SkipFlag = ''
    )

    $skipFlagValue = $false
    if ($SkipFlag) {
        $skipFlagValue = (Get-Variable -Name $SkipFlag -ValueOnly -ErrorAction SilentlyContinue)
        if (-not $skipFlagValue) { $skipFlagValue = $false }
    }

    if ($skipFlagValue) {
        Write-StageLog ("Stage " + $StageId + " (" + $StageName + ") SKIPPED via -" + $SkipFlag) 'Warn'
        return @{ Skipped = $true; Result = $null }
    }

    Write-Section ("STAGE " + $StageId + ": " + $StageName)
    Write-StageLog ("Starting Stage " + $StageId + ": " + $StageName)

    $stageStart = Get-Date
    $stageResult = $null
    $stageError = $null

    try {
        if ($WhatIf) {
            Write-StageLog ("[WhatIf] Would execute: " + $StageName)
            $stageResult = @{ WhatIf = $true }
        } else {
            $stageResult = & $StageBlock
        }
    } catch {
        $stageError = $_.Exception.Message
        Write-StageLog ("Stage " + $StageId + " FAILED: " + $stageError) 'Error'
        throw
    } finally {
        $stageEnd = Get-Date
        $duration = [math]::Round(($stageEnd - $stageStart).TotalSeconds, 2)
        if ($stageError) {
            Write-StageLog ("Stage " + $StageId + " completed with ERROR in " + $duration + "s") 'Error'
        } else {
            Write-StageLog ("Stage " + $StageId + " completed in " + $duration + "s")
        }
    }

    return @{ Skipped = $false; Result = $stageResult; Duration = $duration; Error = $stageError }
}

# -----------------------------------------------------------------------------
# Main pipeline execution
# -----------------------------------------------------------------------------

# Initialize
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$isAdmin = Test-IsAdmin
$isServer = Test-IsServerOS
$hostName = $env:COMPUTERNAME
if (-not $hostName) { $hostName = $env:HOSTNAME }
if (-not $hostName) { try { $hostName = [System.Net.Dns]::GetHostName() } catch { $hostName = 'unknown' } }

$psVersion = $PSVersionTable.PSVersion.ToString()
$osCaption = $null
try {
    $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
} catch {
    $osCaption = $null
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  ScreenConnect Cleanup Tool  v$ScriptVersion" -ForegroundColor Cyan
Write-Host "  Pipeline: $($PipelineStages.Count) stages" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Host: $hostName  |  OS: $osCaption  |  PS: $psVersion  |  Admin: $isAdmin  |  Server: $isServer"
if ($ExecuteRemoval -and -not $sr) {
    Write-Host ""
    Write-Host "  *** -ExecuteRemoval: REMOVAL IS PRE-AUTHORIZED. THIS RUN WILL ACTUALLY" -ForegroundColor Red
    Write-Host "  *** STOP SERVICES, RUN UNINSTALLERS AND QUARANTINE FILES. LAB USE ONLY." -ForegroundColor Red
    Write-Host ""
}

# Resolve output root
if (-not $OutRoot) { $OutRoot = 'C:\RIT-SCC' }
if (-not (Test-Path $OutRoot)) {
    try { New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null }
    catch { throw "Cannot create output root '$OutRoot': $($_.Exception.Message)" }
}

# Check disk space
$freeGb = Get-AvailableDiskSpace $OutRoot
if ($freeGb -lt 5) {
    Write-StageLog ("WARNING: Only " + $freeGb + "GB free on " + $OutRoot + " (recommend 5GB+)") 'Warn'
}

# Resolve working directory
$WorkDir = Resolve-WorkingDir -Root $OutRoot -HostName $hostName
Write-StageLog "Working directory: $WorkDir"
$null = New-Item -ItemType Directory -Path $WorkDir -Force

# Master log
$MasterLogPath = Join-Path $WorkDir 'master.log'
Write-StageLog "Master log: $MasterLogPath"
Add-Content -Path $MasterLogPath -Value "sc-cleanup.ps1 v$ScriptVersion - Master Log" -Encoding UTF8
Add-Content -Path $MasterLogPath -Value "Started: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))" -Encoding UTF8
Add-Content -Path $MasterLogPath -Value "Host: $hostName  OS: $osCaption  PS: $psVersion  Admin: $isAdmin  Server: $isServer" -Encoding UTF8
Add-Content -Path $MasterLogPath -Value "Flags: sa=$sa sr=$sr np=$np offline=$offline procmon=$procmon force=$force ExecuteRemoval=$ExecuteRemoval" -Encoding UTF8
Add-Content -Path $MasterLogPath -Value "IncidentDate: $IncidentDate" -Encoding UTF8

# Resolve tool directory
if (-not $ToolDir) {
    $ToolDir = Join-Path $ScriptRoot 'tools'
}

# Resolve incident date (never prompted - owner directive 2026-08-27)
if (-not $IncidentDate) {
    $IncidentDate = (Get-Date).ToString('yyyy-MM-dd')
}

Write-StageLog "Incident window anchor: $IncidentDate"

# Preflight checks
if (-not $isAdmin) {
    Write-StageLog "WARNING: Not running as admin. On Windows, re-run elevated. Continuing on non-Windows test host." 'Warn'
    # throw "Admin rights required. Re-run elevated."
}

if ($isServer -and -not $force) {
    throw "Server OS detected. Use -force to override (not recommended for production servers)."
}

$uacEnabled = Test-UacEnabled
if (-not $uacEnabled -and -not $force) {
    throw "UAC (User Account Control) is DISABLED on this machine. This is itself a security finding worth investigating before touching anything else. Use -force to proceed anyway."
} elseif (-not $uacEnabled) {
    Write-StageLog "UAC is DISABLED on this machine (-force set, continuing). Record this as a finding." 'Warn'
} else {
    Write-StageLog "UAC check: enabled."
}

# -----------------------------------------------------------------------------
# Stage 0: Preflight
# -----------------------------------------------------------------------------
$stage0Result = Invoke-Stage -StageId 0 -StageName 'Preflight' -SkipFlag '' -StageBlock {
    # Admin check - report the truth. Non-admin is tolerated (non-Windows
    # test host / read-only runs), but it must never be logged as PASSED.
    $adminLine = "Admin check: " + $(if ($isAdmin) { 'PASSED' } else { 'FAILED (not elevated)' })
    Write-StageLog $adminLine
    Add-Content -Path $MasterLogPath -Value $adminLine -Encoding UTF8

    # OS role check
    Write-StageLog "OS: $osCaption  (Server: $isServer)"
    Add-Content -Path $MasterLogPath -Value "OS check: $osCaption (Server=$isServer)" -Encoding UTF8

    # Disk space
    Write-StageLog ("Disk space on " + $OutRoot + ": " + $freeGb + "GB free")
    Add-Content -Path $MasterLogPath -Value ("Disk space: " + $freeGb + "GB free") -Encoding UTF8

    # Working directory
    Write-StageLog "Working directory: $WorkDir"
    Add-Content -Path $MasterLogPath -Value "WorkDir: $WorkDir" -Encoding UTF8

    # Master log opened
    Write-StageLog "Master log opened: $MasterLogPath"

    # System Restore point
    $script:RestorePointFailed = $false
    if (-not $np) {
        Write-StageLog "Creating System Restore point..."
        try {
            Checkpoint-Computer -Description "ScreenConnect Cleanup - $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))" -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
            Write-StageLog "System Restore point created"
            Add-Content -Path $MasterLogPath -Value "Restore point: Created" -Encoding UTF8
        } catch {
            # Recorded so Stage 4 can fail closed before any destructive work.
            $script:RestorePointFailed = $true
            Write-StageLog "System Restore point creation failed: $($_.Exception.Message)" 'Warn'
            Add-Content -Path $MasterLogPath -Value "Restore point: FAILED - $($_.Exception.Message)" -Encoding UTF8
        }
    } else {
        Write-StageLog "Skipping System Restore point (-np specified)"
        Add-Content -Path $MasterLogPath -Value "Restore point: SKIPPED (-np)" -Encoding UTF8
    }

    # Registry hive export
    $hiveExportDir = Join-Path $WorkDir 'registry_hives'
    $null = New-Item -ItemType Directory -Path $hiveExportDir -Force
    Write-StageLog "Exporting registry hives to $hiveExportDir..."
    # reg.exe takes HKLM\SOFTWARE, NOT the PowerShell PSDrive form HKLM:\SOFTWARE
    # ("ERROR: Invalid key name"), which silently skipped every hive export.
    $hives = @('HKLM\SOFTWARE', 'HKLM\SYSTEM', 'HKCU\SOFTWARE')
    foreach ($hive in $hives) {
        $hiveName = ($hive -replace '\\', '_').Trim('_')
        $exportPath = Join-Path $hiveExportDir "$hiveName.reg"
        try {
            $regOutput = & reg.exe export $hive $exportPath /y 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw (($regOutput | Out-String).Trim())
            }
            Write-StageLog "  Exported $hive -> $exportPath"
        } catch {
            Write-StageLog ("  Failed to export " + $hive + ": " + $_.Exception.Message) 'Warn'
        }
    }

    # Tool pack verification
    Write-StageLog "Verifying tool pack at $ToolDir..."
    $getToolPack = Join-Path $ScriptRoot 'tools/Get-ToolPack.ps1'
    if (Test-Path $getToolPack) {
        # Get-ToolPack.ps1 signals failure with 'exit 1', which does NOT throw
        # into this scope - PASSED used to be logged unconditionally.
        $global:LASTEXITCODE = 0
        if (-not $offline) {
            Write-StageLog "Downloading/updating tool pack..."
            & $getToolPack -ToolDir $ToolDir -Quiet
        } else {
            Write-StageLog "Offline mode: verifying existing tool pack..."
            & $getToolPack -ToolDir $ToolDir -Verify -Quiet
        }
        if ($LASTEXITCODE -ne 0) {
            Write-StageLog ("Tool pack verification: FAILED (Get-ToolPack.ps1 exit code " + $LASTEXITCODE + "). Procmon/Autoruns stages will be unavailable.") 'Warn'
            Add-Content -Path $MasterLogPath -Value ("Tool pack: FAILED (exit " + $LASTEXITCODE + ")") -Encoding UTF8
        } else {
            Write-StageLog "Tool pack verification: PASSED"
            Add-Content -Path $MasterLogPath -Value "Tool pack: VERIFIED" -Encoding UTF8
        }
    } else {
        Write-StageLog "Get-ToolPack.ps1 not found at $getToolPack" 'Warn'
        Add-Content -Path $MasterLogPath -Value "Tool pack: Get-ToolPack.ps1 NOT FOUND" -Encoding UTF8
    }

    # AV scanner staging (KVRT / ESET Online Scanner) - separate from the
    # Sysinternals pack above. Malwarebytes is NOT staged here: since v1.7.3 it
    # is installed via winget (owner directive 2026-08-27) in Stage 5.
    # Never fatal: Stage 5 already treats a missing scanner as NotInstalled,
    # not a pipeline failure.
    $getAvTools = Join-Path $ScriptRoot 'tools/Get-AVTools.ps1'
    if ((Test-Path $getAvTools) -and -not $offline) {
        Write-StageLog "Staging AV scanners (KVRT / ESET Online Scanner; Malwarebytes via winget)..."
        $global:LASTEXITCODE = 0
        & $getAvTools -ToolDir (Join-Path $ToolDir 'AV') -Quiet
        if ($LASTEXITCODE -ne 0) {
            Write-StageLog "AV scanner staging: some tools unavailable (see above)." 'Warn'
        } else {
            Write-StageLog "AV scanner staging: done."
        }
    } elseif ($offline) {
        Write-StageLog "Offline mode: skipping AV scanner staging (needs internet)."
    } else {
        Write-StageLog "tools/Get-AVTools.ps1 not found - skipping AV scanner staging." 'Warn'
    }

    return @{
        WorkDir = $WorkDir
        MasterLog = $MasterLogPath
        ToolDir = $ToolDir
        IncidentDate = $IncidentDate
        IsServer = $isServer
    }
}

# -----------------------------------------------------------------------------
# Stage 1: Snapshot (BEFORE)
# -----------------------------------------------------------------------------
$stage1Result = Invoke-Stage -StageId 1 -StageName 'Snapshot (Before)' -SkipFlag '' -StageBlock {
    $collectSnapshot = Join-Path $ScriptRoot 'collect-snapshot.ps1'
    if (-not (Test-Path $collectSnapshot)) {
        throw "collect-snapshot.ps1 not found at $collectSnapshot"
    }

    $beforeSnapshot = Join-Path $WorkDir 'snapshot_before.json'
    $incidentDaysInt = 0
    if ($IncidentDate) {
        $incidentDateTime = [DateTime]::Parse($IncidentDate)
        $incidentDaysInt = [int]([math]::Max(0, [math]::Round((Get-Date).Subtract($incidentDateTime).TotalDays)))
    }

    Write-StageLog ("Running collect-snapshot.ps1 -Label before -OutFile " + $beforeSnapshot)
    $snapArgs = @('-Label', 'before', '-IncidentWindowDays', [string]$incidentDaysInt, '-OutFile', $beforeSnapshot)
    $rc = Invoke-ChildScript -ScriptPath $collectSnapshot -ArgumentList $snapArgs -LogTag 'Snapshot(before)'
    if ($rc -ne 0) { throw ("collect-snapshot.ps1 exited with code " + $rc) }
    Write-StageLog ("Snapshot saved: " + $beforeSnapshot)

    return @{ SnapshotPath = $beforeSnapshot }
}

# -----------------------------------------------------------------------------
# Stage 2: Remote-access detection
# -----------------------------------------------------------------------------
$stage2Result = Invoke-Stage -StageId 2 -StageName 'Detect' -SkipFlag '' -StageBlock {
    $detectScript = Join-Path $ScriptRoot 'detect-remote-access.ps1'
    if (-not (Test-Path $detectScript)) {
        throw "detect-remote-access.ps1 not found at $detectScript"
    }

    $detectOutRoot = Join-Path $WorkDir 'detect'
    $null = New-Item -ItemType Directory -Path $detectOutRoot -Force

    Write-StageLog ("Running detect-remote-access.ps1 -OutRoot " + $detectOutRoot)
    $detectArgs = @('-OutRoot', $detectOutRoot, '-NoPause', '-NoZip')
    $rc = Invoke-ChildScript -ScriptPath $detectScript -ArgumentList $detectArgs -LogTag 'Detect'
    if ($rc -ne 0) { throw ("detect-remote-access.ps1 exited with code " + $rc) }
    Write-StageLog ("Detection complete. Output in " + $detectOutRoot)

    # detect-remote-access.ps1 creates <OutRoot>\<COMPUTERNAME>_<stamp>\findings.json,
    # so resolve the newest one under the tree rather than assuming a flat path.
    $findingsItem = Get-ChildItem -Path $detectOutRoot -Filter 'findings.json' -Recurse -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $findingsItem) {
        throw "findings.json not produced by detect-remote-access.ps1 (searched $detectOutRoot recursively)"
    }
    $findingsJson = $findingsItem.FullName

    return @{ FindingsJson = $findingsJson; DetectDir = $detectOutRoot }
}

# -----------------------------------------------------------------------------
# Stage 3: Technician Review Gate
# -----------------------------------------------------------------------------
$stage3Result = Invoke-Stage -StageId 3 -StageName 'Review Gate' -SkipFlag '' -StageBlock {
    $findingsJson = $stage2Result.Result.FindingsJson
    $planJson = Join-Path $WorkDir 'plan.json'
    $findings = Get-Content -LiteralPath $findingsJson -Raw | ConvertFrom-Json
    $screenConnect = Get-PropertyValue $findings 'ScreenConnect'
    $instances = @()
    # NOTE: do NOT wrap this call in an outer @(). Get-JsonItems already
    # comma-protects its return value so an empty result stays Count=0; an
    # outer @() re-enumerates that single protected pipeline object and
    # turns a genuinely EMPTY array into a phantom 1-element array (whose
    # element is the empty array itself) - "Found 1 instance" with no real
    # data, which is why nothing was ever found to remove.
    if ($screenConnect) { $instances = Get-JsonItems (Get-PropertyValue $screenConnect 'Instances') }
    $removeInstances = New-Object System.Collections.ArrayList
    Write-StageLog ("Found " + $instances.Count + " ScreenConnect instance(s).")

    $instanceNumber = 0
    foreach ($instance in $instances) {
        $instanceNumber++
        $identifier = Get-PropertyValue $instance 'Identifier'
        if (-not $identifier) { $identifier = Get-PropertyValue $instance 'InstanceId' }
        if (-not $identifier) { $identifier = '(unidentified instance ' + $instanceNumber + ')' }
        $installDir = Get-PropertyValue $instance 'InstallDir'
        Write-Host ""
        Write-Host ("ScreenConnect instance " + $instanceNumber + "/" + $instances.Count + ": " + $identifier)
        if ($installDir) { Write-Host ("  Install directory: " + $installDir) }
        Write-Host "  Owner policy: ScreenConnect is eligible for removal; other products are detect-only."
        if ($ExecuteRemoval) {
            $decision = 'REMOVE'
            Write-Host "  -ExecuteRemoval: auto-selecting REMOVE (test mode)." -ForegroundColor Yellow
        } else {
            # KEEP is the default. ScreenConnect is legitimate software that a
            # client's own IT may have installed on purpose, so a technician
            # pressing Enter carelessly must NOT remove anything. Explicit 'y'
            # is required to mark an instance for removal. This matches the
            # safety model (docs/06: unknown must never silently become
            # removal) and Invoke-ReviewAndRemove.ps1 identically.
            do {
                $answer = Read-Host 'Remove this instance? [y/N]'
                if ([string]::IsNullOrWhiteSpace($answer)) { $answer = 'N' }
                $answer = $answer.Trim().Substring(0,1).ToUpperInvariant()
            } while ($answer -ne 'Y' -and $answer -ne 'N')
            if ($answer -eq 'Y') { $decision = 'REMOVE' } else { $decision = 'KEEP' }
        }
        if ($decision -eq 'REMOVE') {
            [void]$removeInstances.Add($instance)
            Write-StageLog ("Marked for removal: " + $identifier)
        } else { Write-StageLog ("Keeping: " + $identifier) }
    }

    $removalConfirmed = $false
    if ($removeInstances.Count -gt 0 -and -not $sr) {
        Write-Host ""
        Write-Host ($removeInstances.Count.ToString() + " ScreenConnect instance(s) marked REMOVE.")
        if ($ExecuteRemoval) {
            $removalConfirmed = $true
            Write-StageLog "-ExecuteRemoval: removal pre-authorized, typed confirmation waived (TEST MODE)." 'Warn'
        } else {
            Write-Host "Files are quarantined, never deleted. Type y to proceed."
            do {
                $confirmation = Read-Host 'Proceed with removal? [y/N]'
                if ([string]::IsNullOrWhiteSpace($confirmation)) { $confirmation = 'N' }
                $confirmation = $confirmation.Trim().Substring(0,1).ToUpperInvariant()
            } while ($confirmation -ne 'Y' -and $confirmation -ne 'N')
            if ($confirmation -eq 'Y') {
                $removalConfirmed = $true
                Write-StageLog "Removal confirmed."
            } else { Write-StageLog "Removal declined; Stage 4 will remain a dry-run." 'Warn' }
        }
    } elseif ($removeInstances.Count -gt 0 -and $sr) {
        Write-StageLog "-sr set: removal decisions recorded but removal is disabled." 'Warn'
    }

    $decision = 'KEEP_ALL'
    if ($removeInstances.Count -eq $instances.Count -and $instances.Count -gt 0) { $decision = 'ALL_REMOVE' }
    elseif ($removeInstances.Count -gt 0) { $decision = 'PARTIAL_REMOVE' }
    # OWNER POLICY: only ScreenConnectInstances is serialized as a removal surface.
    $plan = [ordered]@{
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        ComputerName = $env:COMPUTERNAME
        Decision = $decision
        SourceFindings = $findingsJson
        RemovalConfirmed = $removalConfirmed
        ScreenConnectInstances = $removeInstances.ToArray()
    }
    $plan | ConvertTo-Json -Depth 12 | Set-Content -Path $planJson -Encoding UTF8 -NoNewline
    Write-StageLog ("Review plan written: " + $planJson + " (" + $removeInstances.Count + " removal candidate(s))")
    return @{ PlanJson = $planJson; RemovalConfirmed = $removalConfirmed; RemovalCount = $removeInstances.Count }
}

# -----------------------------------------------------------------------------
# Stage 4: Contain + Remove (skipped if -sr)
# -----------------------------------------------------------------------------
$stage4Result = Invoke-Stage -StageId 4 -StageName 'Contain + Remove' -SkipFlag 'sr' -StageBlock {
    if ($sr) {
        Write-StageLog "Stage 4 SKIPPED via -sr (detect-only mode)"
        return @{ Skipped = $true }
    }

    $planJson = $stage3Result.Result.PlanJson
    $removeScript = Join-Path $ScriptRoot 'remove-screenconnect.ps1'
    if (-not (Test-Path $removeScript)) { throw "remove-screenconnect.ps1 not found at $removeScript" }
    # The rollback restore point is already established in Stage 0, so the
    # remover does not create its own.
    $removeArgs = @('-PlanJson', $planJson, '-WorkDir', $WorkDir)
    $confirmed = [bool]$stage3Result.Result.RemovalConfirmed

    # Fail closed: a confirmed DESTRUCTIVE run must not proceed when the Stage 0
    # restore point failed and the operator did not explicitly waive it with -np.
    # Do NOT throw here - Invoke-Stage rethrows and would abort Stages 5-8 before
    # any post-removal evidence is produced. Record a blocked result instead so
    # the snapshot/diff/report still run and the pipeline ends nonzero.
    if ($confirmed -and -not $sr -and $script:RestorePointFailed -and -not $np) {
        Write-StageLog "Stage 4 BLOCKED: the System Restore point failed in Stage 0 and -np was not specified. Destructive removal refused (fail closed)." 'Error'
        Add-Content -Path $MasterLogPath -Value "Removal: BLOCKED - no restore point and no -np" -Encoding UTF8
        return @{ Skipped = $false; ManifestPath = $null; Executed = $false; ExitCode = 2; RestorePointBlocked = $true }
    }

    if ($confirmed -and -not $sr) { $removeArgs += '-Execute' }
    if ($VerboseLog) { $removeArgs += '-VerboseLog' }
    if ($confirmed -and -not $sr) { Write-StageLog "Running approved ScreenConnect removal with -Execute." }
    else { Write-StageLog "Running removal helper in dry-run mode (no explicit authorization)." }
    $rc = Invoke-ChildScript -ScriptPath $removeScript -ArgumentList $removeArgs -LogTag 'Remove'
    # A partial/failed removal exits 1. That is precisely when the after-snapshot,
    # diff and report matter most, so record it and carry on rather than aborting
    # the pipeline before any of that is produced.
    if ($rc -ne 0) {
        Write-StageLog ("remove-screenconnect.ps1 exited with code " + $rc + " - removal incomplete. Continuing so the manifest, diff and report are still produced.") 'Warn'
        Add-Content -Path $MasterLogPath -Value ("Removal: INCOMPLETE (exit " + $rc + ")") -Encoding UTF8
    }
    $manifest = Join-Path $WorkDir 'removal-manifest.json'
    $reportTxt = Join-Path $WorkDir 'removal-report.txt'
    return @{ Skipped = $false; ManifestPath = $manifest; ReportTxtPath = $reportTxt; Executed = ($confirmed -and -not $sr); ExitCode = $rc }
}

# -----------------------------------------------------------------------------
# Stage 5: Scanners (skipped if -sa)
# -----------------------------------------------------------------------------
$stage5Result = Invoke-Stage -StageId 5 -StageName 'Scanners' -SkipFlag 'sa' -StageBlock {
    if ($sa) {
        Write-StageLog "Stage 5 SKIPPED via -sa (no scanners)"
        return @{ Skipped = $true }
    }

    # Stage 5 = KVRT + ESET Online Scanner (attended GUIs) + Malwarebytes
    # (installed via winget since v1.7.3 - owner directive 2026-08-27).
    # The technician drives each visible UI. The pipeline never invents silent
    # scan/clean flags; it only waits so the after-snapshot + report happen
    # after any GUI-driven cleaning has finished. AdwCleaner and Defender remain
    # removed from scope by owner decision.
    $scannerResults = @()
    $logsDir = Join-Path $WorkDir 'logs'
    $null = New-Item -ItemType Directory -Path $logsDir -Force

    $guiScanner = Join-Path $ScriptRoot 'Invoke-GUIScanner.ps1'
    if (Test-Path $guiScanner) {
        $scannerLaunches = @(
            @{ Scanner = 'KVRT'; Tool = 'KVRT.exe' },
            @{ Scanner = 'ESET'; Tool = 'esetonlinescanner.exe' },
            @{ Scanner = 'Malwarebytes'; Tool = 'Malwarebytes.Malwarebytes (winget install)' }
        )
        foreach ($launch in $scannerLaunches) {
            Write-StageLog ("Launching " + $launch.Scanner + " for attended scan (technician drives the GUI)...")
            $rc = Invoke-ChildScript -ScriptPath $guiScanner -ArgumentList @('-Scanner', $launch.Scanner, '-TimeoutMinutes', '240') -LogTag ("Scanner(" + $launch.Scanner + ")")
            $status = 'Completed'
            if ($rc -eq 2) { $status = 'LaunchFailed' }
            elseif ($rc -eq 3) { $status = 'NotInstalled' }
            elseif ($rc -eq 4) { $status = 'Timeout' }
            elseif ($rc -eq 5) { $status = 'ExitedEarly' }
            elseif ($rc -ne 0) { $status = 'Failed' }
            $scannerResults += @{ Tool = $launch.Tool; Scanner = $launch.Scanner; Status = $status; ExitCode = $rc }
            Write-StageLog ($launch.Scanner + " session recorded: Status=" + $status + " ExitCode=" + $rc) 'Cyan'
        }
    } else {
        Write-StageLog "Invoke-GUIScanner.ps1 not found - GUI scanners cannot be launched." 'Warn'
    }

    $scannerSummary = Join-Path $WorkDir 'scanner_results.json'
    $scannerResults | ConvertTo-Json -Depth 5 | Set-Content -Path $scannerSummary -Encoding UTF8 -NoNewline
    Write-StageLog "Scanner results summary: $scannerSummary"

    return @{ ScannerResults = $scannerResults; SummaryPath = $scannerSummary }
}

# -----------------------------------------------------------------------------
# Stage 6: Uninstall installed third-party AV (opt-in via -avu; attended GUI)
# -----------------------------------------------------------------------------
$stage6Result = Invoke-Stage -StageId 6 -StageName 'Uninstall installed AV' -SkipFlag 'avu' -StageBlock {
    if ($avu) {
        Write-StageLog "Stage 6 SKIPPED via -avu (no AV uninstall)"
        return @{ Skipped = $true }
    }

    # Attended only: open each detected AV product's uninstaller GUI and wait
    # for the technician to finish. Never invents silent uninstall flags.
    $avUninstaller = Join-Path $ScriptRoot 'Invoke-AVUninstaller.ps1'
    $logsDir = Join-Path $WorkDir 'logs'
    $null = New-Item -ItemType Directory -Path $logsDir -Force

    if (-not (Test-Path $avUninstaller)) {
        Write-StageLog ("Invoke-AVUninstaller.ps1 not found at " + $avUninstaller) 'Warn'
        return @{ Skipped = $false; Error = 'script-not-found' }
    }

    Write-StageLog "Launching installed-AV uninstallers (attended - technician drives each GUI)..."
    try {
        $avJson = & $avUninstaller -LogDir $logsDir -TimeoutMinutes 240 -ErrorAction Stop
        $avPath = Join-Path $logsDir 'av-uninstall-results.json'
        if (Test-Path -LiteralPath $avPath) {
            Write-StageLog ("AV uninstall session recorded: " + $avPath) 'Cyan'
        } else {
            Write-StageLog "AV uninstaller produced no results file." 'Warn'
        }
        return @{ Skipped = $false; ResultsPath = $avPath; Raw = $avJson }
    } catch {
        Write-StageLog ("AV uninstaller launch failed: " + $_.Exception.Message) 'Warn'
        return @{ Skipped = $false; Error = $_.Exception.Message }
    }
}

# -----------------------------------------------------------------------------
# Stage 7: Procmon (opt-in only via -procmon) - bounded live capture
# -----------------------------------------------------------------------------
$stage7Result = Invoke-Stage -StageId 7 -StageName 'Procmon' -SkipFlag '' -StageBlock {
    if (-not $procmon) {
        Write-StageLog "Stage 7 SKIPPED (not requested via -procmon)"
        return @{ Skipped = $true; Note = 'Opt-in only' }
    }

    # Targeted live capture, bounded by design. Procmon boot-logging and
    # pre-built path filters require GUI configuration (PMF) - there is no
    # reliable CLI equivalent (docs/07 Q6) - so this stage captures everything
    # for a bounded window while the technician reproduces the resurrection;
    # the Stage 8 diff then names the paths to focus on inside the saved .pml.
    $procmonExe = $null
    foreach ($candidate in @(
        (Join-Path $ToolDir 'ProcessMonitor\Procmon64.exe'),
        (Join-Path $ToolDir 'Procmon64.exe'),
        (Join-Path $ToolDir 'ProcessMonitor\Procmon.exe'),
        (Join-Path $ToolDir 'Procmon.exe')
    )) {
        if (Test-Path -LiteralPath $candidate) { $procmonExe = $candidate; break }
    }
    if (-not $procmonExe) {
        Write-StageLog ("Procmon not found in tool pack (" + $ToolDir + ") - run Step 1 / Stage 0 to fetch it. Stage 7 skipped (non-fatal).") 'Warn'
        return @{ Skipped = $true; Note = 'Procmon not staged'; PmlPath = $null }
    }

    $procmonDir = Join-Path $WorkDir 'logs\Procmon'
    $null = New-Item -ItemType Directory -Path $procmonDir -Force
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $pmlPath = Join-Path $procmonDir ("procmon-" + $stamp + ".pml")
    $runtimeSec = 180
    if ($ProcmonRuntime -gt 0) { $runtimeSec = $ProcmonRuntime }

    Write-StageLog ("Procmon capture: " + $procmonExe)
    Write-StageLog ("  capturing for " + $runtimeSec + "s -> " + $pmlPath)
    Write-StageLog "  REPRODUCE the resurrection now (watch Task Manager, re-run whatever reinstalls the agent)."
    Write-StageLog "  Capture is bounded; after the run, open the .pml and focus on the paths the Stage 8 diff flags."

    # /BackingFile path is quoted because the work dir can contain spaces.
    $argStr = '/AcceptEula /Quiet /Minimized /BackingFile "' + $pmlPath + '" /Runtime ' + $runtimeSec
    $proc = $null
    try {
        $proc = Start-Process -FilePath $procmonExe -ArgumentList $argStr -PassThru -ErrorAction Stop
    } catch {
        Write-StageLog ("Procmon failed to start: " + $_.Exception.Message) 'Error'
        return @{ Skipped = $false; Error = $_.Exception.Message; PmlPath = $null }
    }

    $timedOut = $false
    $exitCode = $null
    # Hard cap = runtime + 120s grace; Procmon /Runtime self-exits, this only
    # guards against a hung instance.
    if (-not $proc.WaitForExit(($runtimeSec + 120) * 1000)) {
        $timedOut = $true
        try { $proc.Kill() } catch { }
        Write-StageLog "Procmon capture exceeded its hard cap - killed (capture likely incomplete)." 'Warn'
    } else {
        try { $exitCode = $proc.ExitCode } catch { }
        Write-StageLog ("Procmon exited with code " + $exitCode + " after its capture window.")
    }

    if (Test-Path -LiteralPath $pmlPath) {
        Write-StageLog ("Procmon capture saved: " + $pmlPath) 'Cyan'
    } else {
        Write-StageLog "Procmon did not produce a .pml - capture failed." 'Warn'
    }

    return @{
        Skipped = $false
        Note = 'Bounded live capture (v1.7.21)'
        PmlPath = $pmlPath
        TimedOut = $timedOut
        ExitCode = $exitCode
        RuntimeSeconds = $runtimeSec
    }
}

# -----------------------------------------------------------------------------
# Stage 8: Snapshot (AFTER) + Diff
# -----------------------------------------------------------------------------
$stage8Result = Invoke-Stage -StageId 8 -StageName 'Snapshot (After)+Diff' -SkipFlag '' -StageBlock {
    $collectSnapshot = Join-Path $ScriptRoot 'collect-snapshot.ps1'
    if (-not (Test-Path $collectSnapshot)) {
        throw "collect-snapshot.ps1 not found at $collectSnapshot"
    }

    $afterSnapshot = Join-Path $WorkDir 'snapshot_after.json'
    $beforeSnapshot = $stage1Result.Result.SnapshotPath
    $incidentDaysInt = 0
    if ($IncidentDate) {
        $incidentDateTime = [DateTime]::Parse($IncidentDate)
        $incidentDaysInt = [int]([math]::Max(0, [math]::Round((Get-Date).Subtract($incidentDateTime).TotalDays)))
    }

    Write-StageLog ("Running collect-snapshot.ps1 -Label after -OutFile " + $afterSnapshot)
    $snapArgs = @('-Label', 'after', '-IncidentWindowDays', [string]$incidentDaysInt, '-OutFile', $afterSnapshot)
    $rc = Invoke-ChildScript -ScriptPath $collectSnapshot -ArgumentList $snapArgs -LogTag 'Snapshot(after)'
    if ($rc -ne 0) { throw ("collect-snapshot.ps1 (after) exited with code " + $rc) }
    Write-StageLog ("After-snapshot saved: " + $afterSnapshot)

    # Diff the two snapshots
    Write-StageLog "Computing diff between before/after snapshots..."
    $diffScript = Join-Path $ScriptRoot 'diff-snapshots.ps1'
    $diffPath = Join-Path $WorkDir 'snapshot_diff.json'

    if (Test-Path $diffScript) {
        $diffArgs = @('-Before', $beforeSnapshot, '-After', $afterSnapshot, '-OutFile', $diffPath)
        $rc = Invoke-ChildScript -ScriptPath $diffScript -ArgumentList $diffArgs -LogTag 'Diff'
        # diff-snapshots.ps1: 0 = CLEAN, 1 = RESURRECTION detected, 2 = failure.
        # Exit code 1 is a FINDING, not an error - treating it as fatal killed
        # the pipeline before Stage 8 in exactly the case the tool exists for.
        if ($rc -eq 1) {
            Write-StageLog "diff-snapshots.ps1 reports RESURRECTION (exit 1) - continuing to report." 'Warn'
        } elseif ($rc -ne 0) {
            throw ("diff-snapshots.ps1 exited with code " + $rc)
        }
        Write-StageLog ("Diff saved: " + $diffPath)
        $diffResult = Get-Content $diffPath -Raw | ConvertFrom-Json
    } else {
        Write-StageLog "diff-snapshots.ps1 not found - performing basic diff in-line" 'Warn'
        $before = Get-Content $beforeSnapshot -Raw | ConvertFrom-Json
        $after = Get-Content $afterSnapshot -Raw | ConvertFrom-Json
        $diffResult = @{
            BeforeFile = $beforeSnapshot
            AfterFile = $afterSnapshot
            DiffComputedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            Note = 'Basic diff - diff-snapshots.ps1 not available'
        }
        $diffResult | ConvertTo-Json -Depth 5 | Set-Content -Path $diffPath -Encoding UTF8 -NoNewline
    }

    # Feed the removal manifest into the resurrection evidence.
    $removalManifest = Join-Path $WorkDir 'removal-manifest.json'
    $manifest = $null
    if (Test-Path -LiteralPath $removalManifest) {
        $manifest = Get-Content -LiteralPath $removalManifest -Raw | ConvertFrom-Json
        Write-StageLog ("Loaded removal manifest for resurrection comparison: " + $removalManifest)
    } else {
        Write-StageLog "No removal manifest found; resurrection comparison is snapshot-only." 'Warn'
    }

    # Resurrection detection: correlate stable snapshot additions with manifest
    # targets when an action was recorded for the run.
    $resurrected = $false
    $resurrectionMatches = @()
    if ($diffResult) {
        Write-StageLog "Resurrection detection: checking for re-appearance of removed items..."
        $manifestEntries = @()
        if ($manifest -and $manifest.Entries) { $manifestEntries = Get-JsonItems $manifest.Entries }
        foreach ($section in (Get-JsonItems $diffResult.Sections)) {
            if ((Get-PropertyValue $section 'Kind') -ne 'stable') { continue }
            foreach ($added in (Get-JsonItems (Get-PropertyValue $section 'Added'))) {
                foreach ($entry in $manifestEntries) {
                    $target = [string](Get-PropertyValue $entry 'Target')
                    $instanceId = [string](Get-PropertyValue $entry 'InstanceId')
                    if (($target -and ([string]$added -like ('*' + $target + '*'))) -or
                        ($instanceId -and ([string]$added -like ('*' + $instanceId + '*')))) {
                        $resurrectionMatches += [string]$added
                        $resurrected = $true
                    }
                }
            }
        }
    }
    if ($resurrected) { Write-StageLog ("Resurrection match(es): " + ($resurrectionMatches -join ', ')) 'Warn' }
    else { Write-StageLog "No manifest-correlated resurrection found." }

    # Point the technician at the Procmon capture if one was made (Stage 7
    # with -procmon): the .pml is the evidence that answers "what reinstalled
    # it?" for the paths the diff just flagged.
    $procmonPml = $null
    if ($stage7Result -and $stage7Result.Result -and $stage7Result.Result.PmlPath -and (Test-Path -LiteralPath $stage7Result.Result.PmlPath)) {
        $procmonPml = $stage7Result.Result.PmlPath
    }
    if ($resurrected -and $procmonPml) {
        Write-StageLog ("Procmon capture available: " + $procmonPml) 'Cyan'
        Write-StageLog "  Open it in Procmon and filter on the resurrected path(s) above to find what re-created them."
    }

    Write-StageLog "Diff complete. Resurrected items detected: $resurrected"

    return @{
        AfterSnapshot = $afterSnapshot
        BeforeSnapshot = $beforeSnapshot
        DiffPath = $diffPath
        Resurrected = $resurrected
        DiffResult = $diffResult
        RemovalManifest = $removalManifest
        RemovalManifestData = $manifest
    }
}

# -----------------------------------------------------------------------------
# Stage 9: Report
# -----------------------------------------------------------------------------
$stage9Result = Invoke-Stage -StageId 9 -StageName 'Report' -SkipFlag '' -StageBlock {
    $reportScript = Join-Path $ScriptRoot 'New-InvestigationReport.ps1'
    if (-not (Test-Path $reportScript)) {
        throw "New-InvestigationReport.ps1 not found at $reportScript"
    }

    $findingsJson = $stage2Result.Result.FindingsJson
    $reportHtml = Join-Path $WorkDir 'report.html'
    $resultsJson = Join-Path $WorkDir 'results.json'

    Write-StageLog ("Generating HTML report from " + $findingsJson)
    $repArgs = @('-FindingsJson', $findingsJson, '-OutputPath', $reportHtml)
    $avUninstallResults = if ($stage6Result -and $stage6Result.Result -and $stage6Result.Result.ResultsPath) { $stage6Result.Result.ResultsPath } else { $null }
    if ($avUninstallResults -and (Test-Path -LiteralPath $avUninstallResults)) { $repArgs += @('-AVUninstall', $avUninstallResults) }
    # Scanner status into the report (docs/06 rules 9-10): pass the results
    # file when Stage 5 ran; pass -ScannersSkipped when -sa suppressed it so
    # the report never silently implies a clean malware verdict.
    $scannerSummary = if ($stage5Result -and $stage5Result.Result -and $stage5Result.Result.SummaryPath) { $stage5Result.Result.SummaryPath } else { $null }
    if ($scannerSummary -and (Test-Path -LiteralPath $scannerSummary)) { $repArgs += @('-ScannerSummary', $scannerSummary) }
    elseif ($stage5Result -and $stage5Result.Skipped) { $repArgs += '-ScannersSkipped' }
    $rc = Invoke-ChildScript -ScriptPath $reportScript -ArgumentList $repArgs -LogTag 'Report'
    if ($rc -ne 0) { throw ("New-InvestigationReport.ps1 exited with code " + $rc) }
    Write-StageLog ("Report generated: " + $reportHtml)

    # Owner directive 2026-08-27: end a run by opening the report folder
    # (Explorer) and the report itself (default browser) so the technician
    # sees the result immediately. Failures here are non-fatal - the report
    # already exists on disk.
    try {
        $null = Start-Process -FilePath explorer.exe -ArgumentList ('/select,"' + $reportHtml + '"') -ErrorAction Stop
    } catch {
        Write-StageLog ("Could not open report folder: " + $_.Exception.Message) 'Warn'
    }
    try {
        $null = Start-Process -FilePath $reportHtml -ErrorAction Stop
    } catch {
        Write-StageLog ("Could not open report: " + $_.Exception.Message) 'Warn'
    }

    # Also produce a machine-readable results.json with key findings
    $findings = Get-Content $findingsJson -Raw | ConvertFrom-Json
    # Safe nested access - stages may have been skipped (Result = $null).
    $beforeSnap = if ($stage1Result -and $stage1Result.Result) { $stage1Result.Result.SnapshotPath } else { $null }
    $afterSnap = if ($stage8Result -and $stage8Result.Result) { $stage8Result.Result.AfterSnapshot } else { $null }
    $diffPath = if ($stage8Result -and $stage8Result.Result) { $stage8Result.Result.DiffPath } else { $null }
    $removalManifest = if ($stage8Result -and $stage8Result.Result) { $stage8Result.Result.RemovalManifest } else { $null }
    $scannerSummary = if ($stage5Result -and $stage5Result.Result) { $stage5Result.Result.SummaryPath } else { $null }
    $planJson = if ($stage3Result -and $stage3Result.Result) { $stage3Result.Result.PlanJson } else { $null }
    $scCount = 0
    if ($findings -and $findings.ScreenConnect -and $findings.ScreenConnect.Instances) { $scCount = $findings.ScreenConnect.Instances.Count }
    $otherTotal = 0
    if ($findings -and $findings.OtherTargets) {
        $otherTotal = ($findings.OtherTargets | ForEach-Object { if ($_.Hits) { $_.Hits.Count } else { 0 } } | Measure-Object -Sum).Sum
        if ($null -eq $otherTotal) { $otherTotal = 0 }
    }
    $summary = @{
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        ComputerName = $findings.ComputerName
        OSCaption = $findings.OSCaption
        IncidentDate = $IncidentDate
        WorkDir = $WorkDir
        ReportHtml = $reportHtml
        FindingsJson = $findingsJson
        BeforeSnapshot = $beforeSnap
        AfterSnapshot = $afterSnap
        DiffPath = $diffPath
        RemovalManifest = $removalManifest
        ScannerSummary = $scannerSummary
        PlanJson = $planJson
        SCInstanceCount = $scCount
        OtherHitTotal = $otherTotal
    }
    $summary | ConvertTo-Json -Depth 5 | Set-Content -Path $resultsJson -Encoding UTF8 -NoNewline
    Write-StageLog "Results summary: $resultsJson"

    return @{ ReportHtml = $reportHtml; ResultsJson = $resultsJson }
}

# -----------------------------------------------------------------------------
# Pipeline complete
# -----------------------------------------------------------------------------
Write-Section "PIPELINE COMPLETE"
$removalExitCode = $null
if ($stage4Result -and $stage4Result.Result) {
    $stage4Payload = $stage4Result.Result
    # StrictMode-safe read: a WhatIf/skipped Stage 4 payload is a hashtable with
    # no ExitCode key, and direct property access would throw PropertyNotFoundStrict
    # under Set-StrictMode 2.0 on Windows PowerShell 5.1.
    if ($stage4Payload -is [System.Collections.IDictionary]) {
        if ($stage4Payload.Contains('ExitCode')) { $removalExitCode = $stage4Payload['ExitCode'] }
    } else {
        $ecProp = $stage4Payload.PSObject.Properties['ExitCode']
        if ($ecProp) { $removalExitCode = $ecProp.Value }
    }
}
$pipelineIncomplete = ($null -ne $removalExitCode -and $removalExitCode -ne 0)
if ($pipelineIncomplete) {
    Write-StageLog ("PIPELINE COMPLETED WITH ERRORS: Stage 4 removal did not complete cleanly (exit code " + $removalExitCode + "). Post-removal evidence was still produced.") 'Error'
} else {
    Write-StageLog "All stages executed successfully."
}
Write-StageLog ("Working directory: " + $WorkDir)
Write-StageLog ("Master log: " + $MasterLogPath)
$reportHtml = $null
$resultsJson = $null
if ($stage9Result -and $stage9Result.ContainsKey('Result') -and $stage9Result.Result -and $stage9Result.Result.ContainsKey('ReportHtml')) {
    $reportHtml = $stage9Result.Result.ReportHtml
}
if ($stage9Result -and $stage9Result.ContainsKey('Result') -and $stage9Result.Result -and $stage9Result.Result.ContainsKey('ResultsJson')) {
    $resultsJson = $stage9Result.Result.ResultsJson
}
if ($reportHtml) {
    Write-StageLog ("HTML report: " + $reportHtml)
}
if ($resultsJson) {
    Write-StageLog ("Results JSON: " + $resultsJson)
}

Add-Content -Path $MasterLogPath -Value "" -Encoding UTF8
Add-Content -Path $MasterLogPath -Value ("Pipeline completed: " + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) -Encoding UTF8
Add-Content -Path $MasterLogPath -Value ("WorkDir: " + $WorkDir) -Encoding UTF8

# Final summary to console
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  SCREENCONNECT CLEANUP PIPELINE COMPLETE" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ("Working directory: " + $WorkDir)
Write-Host ("Master log:       " + $MasterLogPath)
if ($reportHtml) {
    Write-Host ("Report (HTML):    " + $reportHtml)
}
if ($resultsJson) {
    Write-Host ("Results (JSON):   " + $resultsJson)
}
Write-Host "======================================================================" -ForegroundColor Green

# Truthful exit: a nonzero remove-screenconnect exit (or any recorded Stage 4
# problem) must propagate so launchers and operators see the incomplete run.
$finalOutcome = 'SUCCESS'
if ($pipelineIncomplete) { $finalOutcome = ("INCOMPLETE (Stage 4 exit " + $removalExitCode + ")") }
Add-Content -Path $MasterLogPath -Value ("Final outcome: " + $finalOutcome) -Encoding UTF8
if ($pipelineIncomplete) {
    exit 1
} else {
    exit 0
}
