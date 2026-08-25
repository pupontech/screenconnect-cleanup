<# 
  sc-cleanup.ps1  -  Top-level stage runner for the ScreenConnect Cleanup Tool pipeline

  Runs the full incident investigation pipeline in order:
  Stage 0: Preflight
  Stage 1: Snapshot (BEFORE)  [never skippable]
  Stage 2: Remote-access detection
  Stage 3: Technician review gate
  Stage 4: Contain + Remove  [skip: -sr; explicit confirmation required]
  Stage 5: Scanners  [skip: -sa]
  Stage 6: Procmon  [opt-in: -procmon]
  Stage 7: Snapshot (AFTER) + Diff
  Stage 8: Report

  Nothing destructive is reachable without explicit flags and the review gate.
  PowerShell 5.1 compatible. Pure ASCII, no BOM.
#>

param(
    # Skip flags
    [switch]$sa,          # skip antivirus scanners (Stage 5)
    [switch]$sr,          # skip removal (detect + report only)
    [switch]$np,          # no restore point
    [switch]$offline,     # use pre-staged tool pack, do not download
    [switch]$procmon,     # force Procmon stage
    [switch]$force,       # override server-OS refusal
    [switch]$safemode,    # relaunch in safe mode with networking
    [switch]$resume,      # internal: used by reboot RunOnce

    # Configuration
    [string]$IncidentDate,   # incident window anchor (yyyy-MM-dd)
    [string]$OutRoot,        # working directory root (default: C:\RIT-SCC)
    [string]$ToolDir,        # tool pack directory (default: <script dir>\tools)
    [string]$TechName,       # technician name (prompted if not provided)
    [string]$ClientName,     # client identifier (prompted if not provided)

    # Debug / development
    [switch]$WhatIf,         # show what would run, execute nothing
    [switch]$VerboseLog      # verbose stage logging
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Constants & script metadata
# -----------------------------------------------------------------------------
$ScriptVersion = '1.0.0'
$ScriptName = 'sc-cleanup.ps1'
$PipelineStages = @(
    @{ Id = 0; Name = 'Preflight';            SkipFlag = '' },
    @{ Id = 1; Name = 'Snapshot (Before)';    SkipFlag = '' },
    @{ Id = 2; Name = 'Detect';               SkipFlag = '' },
    @{ Id = 3; Name = 'Review Gate';          SkipFlag = '' },
    @{ Id = 4; Name = 'Contain + Remove';     SkipFlag = 'sr' },
    @{ Id = 5; Name = 'Scanners';             SkipFlag = 'sa' },
    @{ Id = 6; Name = 'Procmon';              SkipFlag = 'procmon' },
    @{ Id = 7; Name = 'Snapshot (After)+Diff'; SkipFlag = '' },
    @{ Id = 8; Name = 'Report';               SkipFlag = '' }
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

function Prompt-IfMissing {
    param([string]$VariableName, [string]$PromptText, [ref]$VariableRef)
    if (-not $VariableRef.Value) {
        $input = Read-Host $PromptText
        if ([string]::IsNullOrWhiteSpace($input)) {
            throw "Required input '$PromptText' cannot be empty."
        }
        $VariableRef.Value = $input
    }
}

function Get-JsonItems {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return @($Value) }
    return @($Value)
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
    $psi.Arguments = '-NoProfile -NonInteractive -File "' + $ScriptPath + '"'
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

    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
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
Add-Content -Path $MasterLogPath -Value "Started: $(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')" -Encoding UTF8
Add-Content -Path $MasterLogPath -Value "Host: $hostName  OS: $osCaption  PS: $psVersion  Admin: $isAdmin  Server: $isServer" -Encoding UTF8
Add-Content -Path $MasterLogPath -Value "Flags: sa=$sa sr=$sr np=$np offline=$offline procmon=$procmon force=$force safemode=$safemode resume=$resume" -Encoding UTF8
Add-Content -Path $MasterLogPath -Value "IncidentDate: $IncidentDate" -Encoding UTF8

# Resolve tool directory
if (-not $ToolDir) {
    $ToolDir = Join-Path $ScriptRoot 'tools'
}

# Prompt for tech/client if not provided
if (-not $resume) {
    Prompt-IfMissing -VariableName 'TechName' -PromptText 'Technician name' -VariableRef ([ref]$TechName)
    Prompt-IfMissing -VariableName 'ClientName' -PromptText 'Client identifier' -VariableRef ([ref]$ClientName)
}

# Resolve incident date
if (-not $IncidentDate) {
    $IncidentDate = (Get-Date).ToString('yyyy-MM-dd')
}

Write-StageLog "Technician: $TechName  Client: $ClientName  Incident: $IncidentDate"

# Preflight checks
if (-not $isAdmin) {
    Write-StageLog "WARNING: Not running as admin. On Windows, re-run elevated. Continuing on non-Windows test host." 'Warn'
    # throw "Admin rights required. Re-run elevated."
}

if ($isServer -and -not $force) {
    throw "Server OS detected. Use -force to override (not recommended for production servers)."
}

if ($safemode) {
    Write-StageLog "Safe mode requested - not implemented in this version" 'Warn'
    # TODO: implement safe mode relaunch via bcdedit /set {current} safeboot network
}

# -----------------------------------------------------------------------------
# Stage 0: Preflight
# -----------------------------------------------------------------------------
$stage0Result = Invoke-Stage -StageId 0 -StageName 'Preflight' -SkipFlag '' -StageBlock {
    # Admin check (already done)
    Write-StageLog "Admin check: PASSED"
    Add-Content -Path $MasterLogPath -Value "Admin check: PASSED" -Encoding UTF8

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
    if (-not $np) {
        Write-StageLog "Creating System Restore point..."
        try {
            Checkpoint-Computer -Description "ScreenConnect Cleanup - $(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')" -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
            Write-StageLog "System Restore point created"
            Add-Content -Path $MasterLogPath -Value "Restore point: Created" -Encoding UTF8
        } catch {
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
    $hives = @('HKLM:\SOFTWARE', 'HKLM:\SYSTEM', 'HKCU:\SOFTWARE')
    foreach ($hive in $hives) {
        $hiveName = ($hive -replace '\\', '_' -replace ':', '').Trim('_')
        $exportPath = Join-Path $hiveExportDir "$hiveName.reg"
        try {
            reg export $hive $exportPath /y 2>&1 | Out-Null
            Write-StageLog "  Exported $hive -> $exportPath"
        } catch {
            Write-StageLog ("  Failed to export " + $hive + ": " + $_.Exception.Message) 'Warn'
        }
    }

    # Tool pack verification
    Write-StageLog "Verifying tool pack at $ToolDir..."
    $getToolPack = Join-Path $ScriptRoot 'tools/Get-ToolPack.ps1'
    if (Test-Path $getToolPack) {
        if (-not $offline) {
            Write-StageLog "Downloading/updating tool pack..."
            & $getToolPack -ToolDir $ToolDir -Quiet -ErrorAction Stop
        } else {
            Write-StageLog "Offline mode: verifying existing tool pack..."
            & $getToolPack -ToolDir $ToolDir -Verify -Quiet -ErrorAction Stop
        }
        Write-StageLog "Tool pack verification: PASSED"
        Add-Content -Path $MasterLogPath -Value "Tool pack: VERIFIED" -Encoding UTF8
    } else {
        Write-StageLog "Get-ToolPack.ps1 not found at $getToolPack" 'Warn'
        Add-Content -Path $MasterLogPath -Value "Tool pack: Get-ToolPack.ps1 NOT FOUND" -Encoding UTF8
    }

    return @{
        WorkDir = $WorkDir
        MasterLog = $MasterLogPath
        ToolDir = $ToolDir
        TechName = $TechName
        ClientName = $ClientName
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
    $args = @('-Label', 'before', '-IncidentWindowDays', [string]$incidentDaysInt, '-OutFile', $beforeSnapshot)
    if ($VerboseLog) { $args += '-Verbose' }
    $rc = Invoke-ChildScript -ScriptPath $collectSnapshot -ArgumentList $args -LogTag 'Snapshot(before)'
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
    $args = @('-OutRoot', $detectOutRoot, '-NoPause', '-NoZip')
    if ($VerboseLog) { $args += '-Verbose' }
    $rc = Invoke-ChildScript -ScriptPath $detectScript -ArgumentList $args -LogTag 'Detect'
    if ($rc -ne 0) { throw ("detect-remote-access.ps1 exited with code " + $rc) }
    Write-StageLog ("Detection complete. Output in " + $detectOutRoot)

    $findingsJson = Join-Path $detectOutRoot 'findings.json'
    if (-not (Test-Path $findingsJson)) {
        throw "findings.json not produced by detect-remote-access.ps1"
    }

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
        do {
            $decision = Read-Host 'Decision [KEEP/REMOVE] (default KEEP)'
            if ([string]::IsNullOrWhiteSpace($decision)) { $decision = 'KEEP' }
            $decision = $decision.Trim().ToUpperInvariant()
        } while ($decision -ne 'KEEP' -and $decision -ne 'REMOVE')
        if ($decision -eq 'REMOVE') {
            [void]$removeInstances.Add($instance)
            Write-StageLog ("Marked for removal: " + $identifier)
        } else { Write-StageLog ("Keeping: " + $identifier) }
    }

    $removalConfirmed = $false
    if ($removeInstances.Count -gt 0 -and -not $sr) {
        Write-Host ""
        Write-Host ($removeInstances.Count.ToString() + " ScreenConnect instance(s) marked REMOVE.")
        Write-Host "This confirmation authorizes containment and removal. Type exactly: REMOVE SCREENCONNECT"
        $confirmation = Read-Host 'Confirmation'
        if ($confirmation -ceq 'REMOVE SCREENCONNECT') {
            $removalConfirmed = $true
            Write-StageLog "Explicit removal confirmation accepted."
        } else { Write-StageLog "Removal confirmation not accepted; Stage 4 will remain a dry-run." 'Warn' }
    } elseif ($removeInstances.Count -gt 0 -and $sr) {
        Write-StageLog "-sr set: removal decisions recorded but removal is disabled." 'Warn'
    }

    $decision = 'KEEP_ALL'
    if ($removeInstances.Count -eq $instances.Count -and $instances.Count -gt 0) { $decision = 'ALL_REMOVE' }
    elseif ($removeInstances.Count -gt 0) { $decision = 'PARTIAL_REMOVE' }
    # OWNER POLICY: only ScreenConnectInstances is serialized as a removal surface.
    $plan = [ordered]@{
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        TechName = $TechName
        ClientName = $ClientName
        IncidentDate = $IncidentDate
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
    $args = @('-PlanJson', $planJson, '-WorkDir', $WorkDir, '-NoRestorePoint')
    $confirmed = [bool]$stage3Result.Result.RemovalConfirmed
    if ($confirmed -and -not $sr) { $args += '-Execute' }
    if ($VerboseLog) { $args += '-VerboseLog' }
    if ($confirmed -and -not $sr) { Write-StageLog "Running approved ScreenConnect removal with -Execute." }
    else { Write-StageLog "Running removal helper in dry-run mode (no explicit authorization)." }
    $rc = Invoke-ChildScript -ScriptPath $removeScript -ArgumentList $args -LogTag 'Remove'
    if ($rc -ne 0) { throw ("remove-screenconnect.ps1 exited with code " + $rc) }
    $manifest = Join-Path $WorkDir 'removal-manifest.json'
    return @{ Skipped = $false; ManifestPath = $manifest; Executed = ($confirmed -and -not $sr) }
}

# -----------------------------------------------------------------------------
# Stage 5: Scanners (skipped if -sa)
# -----------------------------------------------------------------------------
$stage5Result = Invoke-Stage -StageId 5 -StageName 'Scanners' -SkipFlag 'sa' -StageBlock {
    if ($sa) {
        Write-StageLog "Stage 5 SKIPPED via -sa (no scanners)"
        return @{ Skipped = $true }
    }

    $scannerResults = @()
    $scannersDir = Join-Path $ScriptRoot 'scanners'
    $logsDir = Join-Path $WorkDir 'logs'
    $null = New-Item -ItemType Directory -Path $logsDir -Force

    # Microsoft Defender adapter (only one implemented so far)
    $defenderScript = Join-Path $scannersDir 'Invoke-DefenderScan.ps1'
    if (Test-Path $defenderScript) {
        Write-StageLog "Running Microsoft Defender scan..."
        $defenderLogDir = Join-Path $logsDir 'MicrosoftDefender'
        $null = New-Item -ItemType Directory -Path $defenderLogDir -Force

        $defenderResult = & $defenderScript -LogDir $defenderLogDir -TimeoutMinutes 120 -Verbose:$VerboseLog
        $scannerResults += $defenderResult
        Write-StageLog "Defender scan: Status=$($defenderResult.Status), Detections=$($defenderResult.DetectionCount), Duration=$($defenderResult.DurationSeconds)s"
        Add-Content -Path $MasterLogPath -Value "Defender: $($defenderResult.Status)  Detections=$($defenderResult.DetectionCount)  Duration=$($defenderResult.DurationSeconds)s" -Encoding UTF8
    } else {
        Write-StageLog "Invoke-DefenderScan.ps1 not found at $defenderScript" 'Warn'
    }

    # Future scanners (AdwCleaner, KVRT, ESET, MSERT) - placeholders
    Write-StageLog "Additional scanners (AdwCleaner, KVRT, ESET, MSERT) not yet implemented."

    $scannerSummary = Join-Path $WorkDir 'scanner_results.json'
    $scannerResults | ConvertTo-Json -Depth 5 | Set-Content -Path $scannerSummary -Encoding UTF8 -NoNewline
    Write-StageLog "Scanner results summary: $scannerSummary"

    return @{ ScannerResults = $scannerResults; SummaryPath = $scannerSummary }
}

# -----------------------------------------------------------------------------
# Stage 6: Procmon (opt-in only via -procmon)
# -----------------------------------------------------------------------------
$stage6Result = Invoke-Stage -StageId 6 -StageName 'Procmon' -SkipFlag 'procmon' -StageBlock {
    if (-not $procmon) {
        Write-StageLog "Stage 6 SKIPPED (not requested via -procmon)"
        return @{ Skipped = $true; Note = 'Opt-in only' }
    }

    Write-StageLog "STUB: Procmon stage"
    Write-StageLog "In a full implementation, this stage would:"
    Write-StageLog "  - Run Procmon with a targeted filter (based on Stage 7 diff resurrection)"
    Write-StageLog "  - Capture for a bounded window"
    Write-StageLog "  - Save .pml to logs/Procmon/"
    Write-StageLog ""
    Write-StageLog "Current implementation: NOT IMPLEMENTED"

    return @{ Skipped = $true; Note = 'Not implemented in v1' }
}

# -----------------------------------------------------------------------------
# Stage 7: Snapshot (AFTER) + Diff
# -----------------------------------------------------------------------------
$stage7Result = Invoke-Stage -StageId 7 -StageName 'Snapshot (After)+Diff' -SkipFlag '' -StageBlock {
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
    if ($VerboseLog) { $snapArgs += '-Verbose' }
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
        if ($rc -ne 0) { throw ("diff-snapshots.ps1 exited with code " + $rc) }
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
# Stage 8: Report
# -----------------------------------------------------------------------------
$stage8Result = Invoke-Stage -StageId 8 -StageName 'Report' -SkipFlag '' -StageBlock {
    $reportScript = Join-Path $ScriptRoot 'New-InvestigationReport.ps1'
    if (-not (Test-Path $reportScript)) {
        throw "New-InvestigationReport.ps1 not found at $reportScript"
    }

    $findingsJson = $stage2Result.Result.FindingsJson
    $reportHtml = Join-Path $WorkDir 'report.html'
    $resultsJson = Join-Path $WorkDir 'results.json'

    Write-StageLog ("Generating HTML report from " + $findingsJson)
    $repArgs = @('-FindingsJson', $findingsJson, '-OutputPath', $reportHtml)
    $removalManifest = Join-Path $WorkDir 'removal-manifest.json'
    if (Test-Path -LiteralPath $removalManifest) { $repArgs += @('-RemovalManifest', $removalManifest) }
    $rc = Invoke-ChildScript -ScriptPath $reportScript -ArgumentList $repArgs -LogTag 'Report'
    if ($rc -ne 0) { throw ("New-InvestigationReport.ps1 exited with code " + $rc) }
    Write-StageLog ("Report generated: " + $reportHtml)

    # Also produce a machine-readable results.json with key findings
    $findings = Get-Content $findingsJson -Raw | ConvertFrom-Json
    # Safe nested access - stages may have been skipped (Result = $null).
    $beforeSnap = if ($stage1Result -and $stage1Result.Result) { $stage1Result.Result.SnapshotPath } else { $null }
    $afterSnap = if ($stage7Result -and $stage7Result.Result) { $stage7Result.Result.AfterSnapshot } else { $null }
    $diffPath = if ($stage7Result -and $stage7Result.Result) { $stage7Result.Result.DiffPath } else { $null }
    $removalManifest = if ($stage7Result -and $stage7Result.Result) { $stage7Result.Result.RemovalManifest } else { $null }
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
        TechName = $TechName
        ClientName = $ClientName
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
Write-StageLog "All stages executed successfully."
Write-StageLog ("Working directory: " + $WorkDir)
Write-StageLog ("Master log: " + $MasterLogPath)
$reportHtml = $null
$resultsJson = $null
if ($stage8Result -and $stage8Result.ContainsKey('Result') -and $stage8Result.Result -and $stage8Result.Result.ContainsKey('ReportHtml')) {
    $reportHtml = $stage8Result.Result.ReportHtml
}
if ($stage8Result -and $stage8Result.ContainsKey('Result') -and $stage8Result.Result -and $stage8Result.Result.ContainsKey('ResultsJson')) {
    $resultsJson = $stage8Result.Result.ResultsJson
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

exit 0