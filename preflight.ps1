# =====================================================================
# preflight.ps1 -- STAGE 0 PREFLIGHT  (docs/02-architecture.md)
#
# Runs before anything else in the pipeline:
#   . admin check            (refuse when not elevated)
#   . OS role check          (refuse on Windows Server unless -Force)
#   . disk space check       (refuse below minimum free GB)
#   . working directory      C:\RIT-SCC\<host>-<timestamp>\
#   . master log open
#   . tech name / client prompt (incident date auto = computer's date)
#   . System Restore point + registry hive export   [skip: -NoRestorePoint]
#   . tool pack presence check via tools\Get-ToolPack.ps1 -Verify
#
# Read-only-adjacent: the ONLY things this stage changes on the machine
# are the restore point + registry exports (clearly logged, skippable)
# and its own working directory under C:\RIT-SCC.
#
# PS 5.1 compatible. Pure ASCII, no BOM.
# Exit codes: 0 = ok, 1 = preflight failure (abort pipeline).
# =====================================================================
[CmdletBinding()]
param(
    # Skip the restore point + registry hive export (docs flag: -np)
    [switch]$np,

    # Task-body alias for -np: restore-point creation is optional
    [switch]$SkipRestore,

    # Override the server-OS refusal (docs/02-architecture.md flags)
    [switch]$Force,

    # Full debug logger: console transcript + debug detail to <workDir>\logs\debug.log
    [switch]$Debug,

    # Minimum free space in GB on the system drive (default 10)
    [int]$MinFreeGB = 10,

    # Where the working directory root lives (default C:\RIT-SCC)
    [string]$WorkingRoot = 'C:\RIT-SCC',

    # Path to Get-ToolPack.ps1 (default: tools\ next to this script)
    [string]$ToolPackPath,

    # Internal: run the built-in selftest (safe on any OS, mutates nothing)
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0

$ErrorActionPreference = 'Stop'
$script:PreflightOk = $true

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

function Write-Stage {
    param([string]$Message)
    Write-Host "[preflight] $Message" -ForegroundColor Cyan
}

function Write-StageWarn {
    param([string]$Message)
    Write-Host "[preflight] WARN: $Message" -ForegroundColor Yellow
}

function Write-StageFail {
    param([string]$Message)
    Write-Host "[preflight] FAIL: $Message" -ForegroundColor Red
    $script:PreflightOk = $false
}

function Test-IsAdmin {
    # Windows: walk the admin security principal.
    # Non-Windows (dev/selftest): report not-admin honestly; callers gate on it.
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

function Test-UacEnabled {
    try {
        $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop
        return ($val.EnableLUA -ne 0)
    } catch {
        return $true
    }
}

function Get-HostNameSafe {
    # Portable host name: COMPUTERNAME -> HOSTNAME -> .NET -> 'unknown'
    if ($env:COMPUTERNAME) { return $env:COMPUTERNAME }
    if ($env:HOSTNAME)     { return $env:HOSTNAME }
    try { return [System.Net.Dns]::GetHostName() } catch { return 'unknown' }
}

function Get-OsCaptionSafe {
    try {
        if ($env:OS -eq 'Windows_NT') {
            $sysInfo = New-Object System.Collections.Specialized.StringDictionary
            $null = $sysInfo  # placeholder; use WMI-free approach below
        }
    } catch { }
    # Prefer registry-free, CIM-free path that works everywhere:
    if ($PSVersionTable.PSVersion.Major -ge 3 -and $env:OS -eq 'Windows_NT') {
        try {
            $caption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
            if ($caption) { return $caption }
        } catch { }
    } elseif ($env:OS -eq 'Windows_NT') {
        # PS 2.0-era fallback would use Get-WmiObject; 5.1 has it:
        try {
            $caption = (Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop).Caption
            if ($caption) { return $caption }
        } catch { }
    }
    return "Non-Windows ($($PSVersionTable.Platform) $($PSVersionTable.OS))"
}

function Test-IsServerOs {
    param([string]$Caption)
    return ($Caption -match '(?i)windows\s+server')
}

function Get-FreeSpaceGB {
    param([string]$DriveRoot)
    try {
        if ($env:OS -ne 'Windows_NT') { $DriveRoot = '/' }
        $drive = New-Object System.IO.DriveInfo($DriveRoot)
        return [math]::Round($drive.AvailableFreeSpace / 1GB, 1)
    } catch {
        return -1
    }
}

function Invoke-RestorePoint {
    # Creates a System Restore point + exports key registry hives.
    # Returns $true when the caller may continue.
    # Per docs/06-safety-model.md: CHECK System Restore is actually enabled;
    # a silently-failed restore point is worse than none.
    Write-Stage 'Creating System Restore point + registry hive export ...'

    if ($env:OS -ne 'Windows_NT') {
        Write-StageFail 'Restore point requires Windows (refusing to silently skip a safety step).'
        return $false
    }

    # Check System Restore is enabled on the system drive FIRST
    try {
        $srStatus = Get-CimInstance -ClassName 'SystemRestore' -Namespace 'root\default' `
                        -ErrorAction SilentlyContinue
        $srEnabled = $true
        try {
            $srConfig = Get-CimInstance -ClassName 'Win32_OSRecoveryConfiguration' `
                            -ErrorAction SilentlyContinue
        } catch { }

        # The reliable enablement probe: try reading SR config via wmic-style CIM.
        # If SystemRestore class returns nothing AND SR is disabled, fail loudly.
        $regValue = $null
        try {
            $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' `
                             -Name 'RPSessionInterval' -ErrorAction SilentlyContinue
        } catch { }
        if ($null -eq $srStatus -and $null -eq $regValue) {
            # Cannot confirm System Restore is enabled -> treat as NOT enabled
            Write-StageFail ('System Restore appears to be DISABLED or unreadable on this machine. ' +
                'Enable it manually (SystemPropertiesProtection.exe), then re-run preflight. ' +
                'A silently-failed restore point is worse than none.')
            return $false
        }
        $srEnabled = $true
    } catch {
        Write-StageWarn ("Could not probe System Restore status: {0}" -f $_.Exception.Message)
    }

    # Create the restore point (Checkpoint-Computer exists on 5.1+)
    try {
        if (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue) {
            Checkpoint-Computer -Description 'RIT-SCC ScreenConnect cleanup - preflight' `
                -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
            Write-Stage 'System Restore point created OK.'
        } else {
            Write-StageFail 'Checkpoint-Computer cmdlet not available on this OS.'
            return $false
        }
    } catch {
        Write-StageFail ("Failed to create restore point: {0}" -f $_.Exception.Message)
        return $false
    }

    return $true
}

function Export-RegistryHives {
    # Export the hives we are most likely to touch during removal.
    # Uses reg.exe SAVE (works while hives are locked/in use).
    #
    # DELIBERATELY EXCLUDES HKLM\SAM AND HKLM\SECURITY.
    # "reg save HKLM\SAM" + "HKLM\SECURITY" is the canonical credential-dumping
    # pattern (MITRE ATT&CK T1003.002) - it yields local account password hashes
    # and LSA secrets. Microsoft Defender and every other AV flag a script doing
    # it, which is why preflight.ps1 was being quarantined on client machines.
    # Those two hives are also USELESS here: nothing in ScreenConnect removal
    # reads them, they normally fail anyway without SYSTEM, and if they DID
    # succeed we would be writing credential material to C:\RIT-SCC on someone
    # else's machine. SOFTWARE + SYSTEM + HKCU cover services, uninstall keys
    # and Run keys - everything this tool actually touches.
    # This now matches the hive list in sc-cleanup.ps1 Stage 0.
    param([string]$DestDir)
    Write-Stage ("Exporting registry hives to {0} ..." -f $DestDir)
    if (-not (Test-Path $DestDir)) {
        $null = New-Item -ItemType Directory -Path $DestDir -Force
    }
    $hives = @(
        @{ Name = 'HKLM-SOFTWARE';  Args = 'HKLM\SOFTWARE' },
        @{ Name = 'HKLM-SYSTEM';    Args = 'HKLM\SYSTEM' },
        @{ Name = 'HKCU';           Args = 'HKCU' }
    )
    $allSaved = $true
    foreach ($hive in $hives) {
        $dest = Join-Path $DestDir ($hive.Name + '.hiv')
        # Out-Null is required: reg.exe writes "The operation completed
        # successfully." to STDOUT, which would otherwise be emitted as part of
        # this function's return value. The caller does
        # "if (-not (Export-RegistryHives ...))", and a non-empty array is
        # always truthy - so a real failure was silently swallowed.
        & reg.exe save $hive.Args $dest /y 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dest)) {
            Write-StageWarn ("Hive export failed: {0}" -f $hive.Name)
            $allSaved = $false
        } else {
            Write-Stage ("Hive saved: {0}" -f $dest)
        }
    }
    return $allSaved
}

function Test-ToolPack {
    # Presence-check the tool pack by invoking Get-ToolPack.ps1 -Verify.
    # Returns $true when every expected tool verifies.
    param([string]$ScriptPath)
    if (-not (Test-Path $ScriptPath)) {
        Write-StageFail ("Tool pack script not found: {0}" -f $ScriptPath)
        return $false
    }
    Write-Stage ("Verifying tool pack via {0} ..." -f $ScriptPath)
    try {
        & $ScriptPath -Verify -Quiet
        $rc = $LASTEXITCODE
    } catch {
        Write-StageFail ("Tool pack verification threw: {0}" -f $_.Exception.Message)
        return $false
    }
    if ($rc -ne 0) {
        Write-StageFail ("Tool pack verify FAILED (exit {0}). Run: powershell -File tools\Get-ToolPack.ps1" -f $rc)
        return $false
    }
    Write-Stage 'Tool pack verified.'
    return $true
}

# ---------------------------------------------------------------------
# Selftest: exercises pure logic only, mutates nothing, works on Linux CI.
# ---------------------------------------------------------------------
if ($SelfTest) {
    $failures = @()

    # Hostname helper must never be null/empty
    $hn = Get-HostNameSafe
    if ([string]::IsNullOrEmpty($hn)) { $failures += 'Get-HostNameSafe returned empty' }

    # OS caption helper must return non-empty string
    $cap = Get-OsCaptionSafe
    if ([string]::IsNullOrEmpty($cap)) { $failures += 'Get-OsCaptionSafe returned empty' }

    # Server detection
    if (-not (Test-IsServerOs -Caption 'Microsoft Windows Server 2019 Standard')) {
        $failures += 'Test-IsServerOs missed Server 2019 caption'
    }
    if (Test-IsServerOs -Caption 'Microsoft Windows 10 Pro') {
        $failures += 'Test-IsServerOs false-positive on Win10 Pro'
    }

    # Admin check returns bool (either value is fine off-Windows)
    $isAdmin = Test-IsAdmin
    if ($isAdmin -isnot [bool]) { $failures += 'Test-IsAdmin did not return bool' }

    # Free-space helper returns numeric (or -1 sentinel)
    $free = Get-FreeSpaceGB -DriveRoot '/'
    if ($free -isnot [double] -and $free -isnot [int]) {
        $failures += 'Get-FreeSpaceGB did not return numeric'
    }

    if ($failures.Count -gt 0) {
        foreach ($f in $failures) { Write-Host ("SELFTEST FAIL: {0}" -f $f) -ForegroundColor Red }
        exit 1
    }
    Write-Host ("SELFTEST OK (host={0}; os={1}; isAdmin={2}; freeGB={3})" -f $hn, $cap, $isAdmin, $free)
    exit 0
}

# ---------------------------------------------------------------------
# Stage 0 main sequence
# ---------------------------------------------------------------------
$host_ = Get-HostNameSafe
$stamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
$osCaption = Get-OsCaptionSafe

Write-Host ''
Write-Host '=== STAGE 0: PREFLIGHT ===' -ForegroundColor White
Write-Stage ("Host: {0} | OS: {1}" -f $host_, $osCaption)

# --- 1. Admin check ---
Write-Stage 'Checking elevation ...'
if (-not (Test-IsAdmin)) {
    if ($env:OS -eq 'Windows_NT') {
        Write-StageFail 'Not running elevated. Right-click -> Run as administrator.'
    } else {
        # Non-Windows dev/CI host: cannot be elevated; warn instead of failing
        # so the rest of preflight stays exercisable. Real runs are Windows.
        Write-StageWarn 'Non-Windows host: elevation cannot be verified here (ok for CI).'
    }
} else {
    Write-Stage 'Running elevated.'
}

# --- 1b. UAC check: a disabled UAC is itself a finding on an incident machine ---
if ($env:OS -eq 'Windows_NT') {
    if (-not (Test-UacEnabled)) {
        if ($Force) {
            Write-StageWarn 'UAC (User Account Control) is DISABLED. Continuing because -Force was passed - record this as a finding.'
        } else {
            # Owner directive 2026-08-28: preflight always runs - do not
            # hard-fail on a disabled UAC. Prompt the user to enable it and
            # WAIT, then re-check and continue the preflight. (F force-
            # continues with UAC disabled, like -Force.)
            Write-Host ''
            Write-Host '  *** UAC (User Account Control) is DISABLED on this machine.' -ForegroundColor Red
            Write-Host '  *** This is itself a security finding, and the tool needs UAC for safe' -ForegroundColor Red
            Write-Host '  *** elevation of the removal and scanner steps.' -ForegroundColor Red
            Write-Host '  *** Enable it now (as administrator):' -ForegroundColor Yellow
            Write-Host '  ***   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f' -ForegroundColor Yellow
            Write-Host '  ***   (a reboot is required for the change to fully apply)' -ForegroundColor Yellow
            Write-Host '  ***   KVRT and ESET scanners will likely fail to launch until UAC is enabled.' -ForegroundColor Yellow
            Write-Host ''
            $uacAnswer = ''
            do {
                $uacInput = Read-Host 'Type Y once UAC is enabled, or F to force-continue with UAC disabled'
                if ([string]::IsNullOrWhiteSpace($uacInput)) { $uacInput = 'Y' }
                $uacAnswer = $uacInput.Trim().Substring(0,1).ToUpperInvariant()
            } while ($uacAnswer -ne 'Y' -and $uacAnswer -ne 'F')
            if ($uacAnswer -eq 'F') {
                Write-StageWarn 'UAC still disabled (force-continued at the prompt) - record this as a finding.'
            } else {
                if (Test-UacEnabled) {
                    Write-Stage 'UAC check: enabled (confirmed after user action).'
                } else {
                    Write-StageWarn 'UAC reported enabled but EnableLUA still reads disabled (reboot pending?) - continuing on the user confirmation.'
                }
            }
        }
    } else {
        Write-Stage 'UAC check: enabled.'
    }
}

# --- 2. OS role check: refuse Server unless -force ---
if (Test-IsServerOs -Caption $osCaption) {
    if ($Force) {
        Write-StageWarn 'Windows Server detected, continuing because -Force was passed.'
    } else {
        Write-StageFail 'Windows Server detected. This tool targets workstations; pass -Force to override.'
    }
} else {
    Write-Stage 'OS role: workstation (ok).'
}

# --- 3. Disk space ---
$sysDrive = 'C:\'
if ($env:OS -ne 'Windows_NT') { $sysDrive = '/' }
$freeGB = Get-FreeSpaceGB -DriveRoot $sysDrive
if ($freeGB -lt 0) {
    Write-StageWarn 'Could not determine free disk space (continuing with a warning).'
} elseif ($freeGB -lt $MinFreeGB) {
    Write-StageFail ("Only {0} GB free on {1} (minimum {2} GB)." -f $freeGB, $sysDrive, $MinFreeGB)
} else {
    Write-Stage ("Disk space OK: {0} GB free." -f $freeGB)
}

# --- Abort here on hard failures so far ---
if (-not $script:PreflightOk) {
    Write-Host ''
    Write-Host 'PREFLIGHT FAILED. Pipeline aborted before any change.' -ForegroundColor Red
    exit 1
}

# --- 4. Working directory + master log ---
$workDir = Join-Path $WorkingRoot ('{0}-{1}' -f $host_, $stamp)
try {
    $null = New-Item -ItemType Directory -Path $workDir -Force
} catch {
    Write-StageFail ("Could not create working directory {0}: {1}" -f $workDir, $_.Exception.Message)
    exit 1
}
foreach ($sub in @('logs', 'quarantine', 'snapshots', 'registry')) {
    $null = New-Item -ItemType Directory -Path (Join-Path $workDir $sub) -Force
}
$masterLog = Join-Path $workDir 'master.log'
"=== RIT-SCC master log ===" | Out-File -FilePath $masterLog -Encoding ascii
Write-Stage ("Working directory: {0}" -f $workDir)
Write-Stage ("Master log:        {0}" -f $masterLog)

# --- 5. Master log header (technician/client/incident tags removed per
# ---    owner directive 2026-08-27: no prompts, no tags, just run + log) ---
"OS:         $osCaption"                  | Out-File $masterLog -Append -Encoding ascii

# --- 5b. Debug logger (v1.7.26): -Debug captures a full console transcript ---
$debugLogPath = $null
if ($Debug) {
    $debugLogPath = Join-Path $workDir 'logs\debug.log'
    try {
        Start-Transcript -Path $debugLogPath -Force -ErrorAction Stop | Out-Null
        Write-Stage ("DEBUG LOGGER ACTIVE - transcript: " + $debugLogPath)
        Write-Stage ("preflight.ps1 flags: np=" + $np + " Force=" + $Force + " MinFreeGB=" + $MinFreeGB + " WorkingRoot=" + $WorkingRoot)
    } catch {
        Write-StageWarn ("Could not start debug transcript: " + $_.Exception.Message)
        $debugLogPath = $null
    }
    trap {
        Write-StageFail ("UNHANDLED ERROR: " + $_.Exception.Message + " | " + $_.InvocationInfo.PositionMessage)
        if ($debugLogPath) {
            try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
            Write-Host ("Debug log: " + $debugLogPath) -ForegroundColor Yellow
        }
        exit 1
    }
}

# --- 6. Restore point + hive export (optional) ---
$skipRestore = $np -or $SkipRestore
if ($skipRestore) {
    Write-StageWarn 'Skipping restore point + registry export (-np/-SkipRestore). NO ROLLBACK WILL EXIST.'
    "[SKIPPED] restore point + hive export" | Out-File $masterLog -Append -Encoding ascii
} else {
    Write-Host ''
    Write-Host 'About to create a System Restore point and export registry hives.' -ForegroundColor Yellow
    if (Test-IsAdmin) {
        if (-not (Invoke-RestorePoint)) {
            Write-StageFail 'Aborting: proceeding without a restore point is forbidden.'
            exit 1
        }
        if (-not (Export-RegistryHives -DestDir (Join-Path $workDir 'registry'))) {
            Write-StageWarn 'Some critical hives failed to export (see above); continuing.'
        }
        "[OK] restore point + hive export" | Out-File $masterLog -Append -Encoding ascii
    } else {
        # Already failed admin check above but keep the ordering explicit
        Write-StageFail 'Cannot create restore point without elevation.'
        exit 1
    }
}

# --- 7. Tool pack presence check ---
$toolPackScript = $ToolPackPath
if (-not $toolPackScript) {
    $toolPackScript = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'tools\Get-ToolPack.ps1'
}
if (-not (Test-Path $toolPackScript)) {
    # On non-Windows dev boxes the backslash path won't resolve; try forward slash
    $alt = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'tools/Get-ToolPack.ps1'
    if (Test-Path $alt) { $toolPackScript = $alt }
}
if (Test-ToolPack -ScriptPath $toolPackScript) {
    "[OK] tool pack verified" | Out-File $masterLog -Append -Encoding ascii
} else {
    Write-StageFail 'Tool pack incomplete. Build it first: powershell -ExecutionPolicy Bypass -File tools\Get-ToolPack.ps1'
}

# --- Result ---
if ($debugLogPath) {
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
}
Write-Host ''
if ($script:PreflightOk) {
    Write-Host 'PREFLIGHT COMPLETE.' -ForegroundColor Green
    if ($debugLogPath) { Write-Host ("Debug log: " + $debugLogPath) -ForegroundColor Yellow }
    "PREFLIGHT COMPLETE $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $masterLog -Append -Encoding ascii
    # Machine-readable handoff for the orchestrator (stdout JSON on one line).
    # Technician/client/incident tags removed per owner directive 2026-08-27.
    @{ Stage = 0; Status = 'Complete'; WorkingDirectory = $workDir;
       MasterLog = $masterLog;
       RestorePointSkipped = [bool]$skipRestore } | ConvertTo-Json -Compress
    exit 0
} else {
    Write-Host 'PREFLIGHT FAILED. See messages above.' -ForegroundColor Red
    exit 1
}
