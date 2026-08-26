# =====================================================================
# Scc.Cleaner.ps1 - Entry point for ScreenConnect Cleaner (GUI + headless)
#
# GUI default: launches WPF shell via Scc.UI Start-SccApp.
# Headless: runs the shared stage state machine (Scc.UI workflow) without WPF.
#
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# Exit codes: 0 = pipeline finished, 1 = failed stage / incomplete,
#             2 = missing dependency, 3 = refused (Server OS etc).
# =====================================================================
[CmdletBinding()]
param(
    [switch]$Headless,
    [ValidateSet('Full','DetectOnly','ScanOnly')]
    [string]$Mode = 'Full',
    [switch]$SkipScanners,
    [string]$ResumeRunId,
    [string]$Config,
    [string]$PlanPath,
    [switch]$SkipPreflight,
    [switch]$NoRestorePoint
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------
# Self-elevation (Windows only, GUI or headless). Linux hosts always
# return true from IsAdmin check above so this block is Windows-only.
# ---------------------------------------------------------------------
function Test-SccCleanerIsAdmin {
    if ($env:OS -ne 'Windows_NT') {
        return $true
    }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# Avoid infinite relaunch loop: once elevated we set env marker.
if ($env:OS -eq 'Windows_NT') {
    if (-not (Test-SccCleanerIsAdmin)) {
        if (-not $env:SCC_ELEVATED) {
            $exe = 'powershell'
            try {
                $cmd = Get-Command -Name 'powershell' -ErrorAction SilentlyContinue
                if ($cmd -and $cmd.Source) { $exe = $cmd.Source }
            } catch { }
            $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $MyInvocation.MyCommand.Path + '"'))
            if ($Headless) { $argList += '-Headless' }
            if ($Mode) { $argList += '-Mode'; $argList += $Mode }
            if ($SkipScanners) { $argList += '-SkipScanners' }
            if ($ResumeRunId) { $argList += '-ResumeRunId'; $argList += ('"' + $ResumeRunId + '"') }
            if ($Config) { $argList += '-Config'; $argList += ('"' + $Config + '"') }
            if ($PlanPath) { $argList += '-PlanPath'; $argList += ('"' + $PlanPath + '"') }
            if ($SkipPreflight) { $argList += '-SkipPreflight' }
            if ($NoRestorePoint) { $argList += '-NoRestorePoint' }
            # Forward any unbound args (e.g. extra flags from .bat)
            if ($MyInvocation.UnboundArguments) {
                foreach ($u in $MyInvocation.UnboundArguments) { $argList += $u }
            }
            $joined = ($argList -join ' ')
            try {
                $env:SCC_ELEVATED = '1'
                $null = Start-Process -FilePath $exe -ArgumentList $joined -Verb RunAs -ErrorAction Stop
                Write-Host 'Elevation requested - restarting as administrator.' -ForegroundColor Yellow
                exit 0
            } catch {
                Write-Host ('Elevation failed or declined: ' + $_.Exception.Message) -ForegroundColor Red
                Write-Host 'Continuing without elevation (some stages may fail).' -ForegroundColor Yellow
            }
        } else {
            Write-Host 'Running without administrator rights (elevation declined or unavailable).' -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------
# Resolve script / src layout
# ---------------------------------------------------------------------
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$SrcRoot = Join-Path $ScriptRoot 'src'

# Make src discoverable as PSModulePath (src/Scc.Core etc.)
if ($SrcRoot -and (Test-Path -LiteralPath $SrcRoot)) {
    $sep = [System.IO.Path]::PathSeparator
    $env:PSModulePath = $SrcRoot + $sep + $env:PSModulePath
}

function Import-SccRequiredModule {
    param([string]$Name)
    $manifest = Join-Path $SrcRoot $Name "$Name.psd1"
    if (-not (Test-Path -LiteralPath $manifest)) {
        Write-Host ("Missing required module: {0} ({1} not found)" -f $Name, $manifest) -ForegroundColor Red
        exit 2
    }
    try {
        Import-Module -Name $manifest -Force -ErrorAction Stop
    } catch {
        Write-Host ("Failed to import module {0}: {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red
        exit 2
    }
}

function Write-SccStageSummary {
    param($Workflow)
    Write-Host ''
    Write-Host 'Stage summary:' -ForegroundColor Cyan
    foreach ($s in $Workflow.Stages) {
        $color = 'Gray'
        if ($s.Status -eq 'Completed') { $color = 'Green' }
        elseif ($s.Status -eq 'Failed') { $color = 'Red' }
        elseif ($s.Status -eq 'Skipped') { $color = 'DarkYellow' }
        elseif ($s.Status -eq 'AwaitingReview') { $color = 'Yellow' }
        elseif ($s.Status -eq 'Running') { $color = 'Cyan' }
        $line = ('  [{0}] {1}: {2}' -f $s.Index, $s.Name, $s.Status)
        if ($s.Detail) { $line = $line + (' - ' + $s.Detail) }
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ''
}

# ---------------------------------------------------------------------
# Headless path
# ---------------------------------------------------------------------
if ($Headless) {
    # Core is mandatory
    Import-SccRequiredModule -Name 'Scc.Core'

    # Config override
    if ($Config) {
        if (Test-Path -LiteralPath $Config) {
            try { $null = Get-SccConfig -Path $Config } catch { Write-Host ("Warning: Get-SccConfig -Path failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
        } else {
            Write-Host ("Config file not found: {0}" -f $Config) -ForegroundColor Yellow
        }
    } else {
        try { $null = Get-SccConfig } catch { }
    }

    # Server OS refusal (exit 3)
    try {
        $compInfo = Get-SccComputerInfo
        $cfg = Get-SccConfig
        $refuse = $false
        if ($cfg -and $cfg.safety -and $null -ne $cfg.safety.serverOsRefusal) { $refuse = [bool]$cfg.safety.serverOsRefusal }
        else { $refuse = $true }
        if ($compInfo.IsServer -and $refuse) {
            Write-Host ("Refused: Server OS detected ({0}). Use -ForceServer via config or run on workstation." -f $compInfo.OsCaption) -ForegroundColor Red
            exit 3
        }
    } catch {
        # Non-fatal: continue
    }

    # UI module provides the shared state machine (headless reuses it 100%)
    Import-SccRequiredModule -Name 'Scc.UI'

    # Ensure backend modules are present for the requested mode; warn but
    # degrade gracefully per stage (workflow marks stage Failed).
    $requiredBackends = @('Scc.Evidence','Scc.Detection','Scc.Snapshots','Scc.Report')
    if ($Mode -eq 'Full') { $requiredBackends += @('Scc.Remedy') }
    if (-not $SkipScanners) { $requiredBackends += @('Scc.Scanners') }
    foreach ($mod in $requiredBackends) {
        $mf = Join-Path $SrcRoot $mod "$mod.psd1"
        if (-not (Test-Path -LiteralPath $mf)) {
            Write-Host ("Missing backend module for mode {0}: {1}" -f $Mode, $mod) -ForegroundColor Red
            exit 2
        }
        try { Import-Module -Name $mf -Force -ErrorAction Stop } catch { Write-Host ("Failed to import {0}: {1}" -f $mod, $_.Exception.Message) -ForegroundColor Red; exit 2 }
    }
    # Tools is optional (preflight probe); import if present
    $toolsManifest = Join-Path $SrcRoot 'Scc.Tools' 'Scc.Tools.psd1'
    if (Test-Path -LiteralPath $toolsManifest) { try { Import-Module -Name $toolsManifest -Force -ErrorAction SilentlyContinue } catch { } }

    # Create or resume run
    $run = $null
    if ($ResumeRunId) {
        try {
            $state = Get-SccRunState -RunId $ResumeRunId -ErrorAction Stop
            if ($null -eq $state) {
                Write-Host ("ResumeRunId not found: {0}" -f $ResumeRunId) -ForegroundColor Red
                exit 1
            }
            $paths = Get-SccPaths
            $candidate = Join-Path $paths.ReportRoot $ResumeRunId
            if (-not (Test-Path -LiteralPath $candidate)) {
                # Fallback: search via Find-SccRecentRuns
                $found = Find-SccRecentRuns -MaxAgeDays 30 | Where-Object { $_.RunId -eq $ResumeRunId }
                if ($found) { $candidate = $found.RunDir }
            }
            if (-not (Test-Path -LiteralPath $candidate)) {
                Write-Host ("Run directory not found for ResumeRunId {0}" -f $ResumeRunId) -ForegroundColor Red
                exit 1
            }
            $run = [PSCustomObject]@{ RunId = $ResumeRunId; RunDir = $candidate }
            Write-Host ("Resuming run: {0} -> {1}" -f $ResumeRunId, $candidate) -ForegroundColor Cyan
        } catch {
            Write-Host ("Resume failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    } else {
        try {
            $run = New-SccRun -Technician $env:USERNAME -Client 'Headless'
            Write-Host ("Created run: {0} -> {1}" -f $run.RunId, $run.RunDir) -ForegroundColor Cyan
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'Server OS') {
                Write-Host $msg -ForegroundColor Red
                exit 3
            }
            Write-Host ("Failed to create run: {0}" -f $msg) -ForegroundColor Red
            exit 1
        }
    }

    # Handle -PlanPath for headless review bypass
    if ($PlanPath) {
        if (Test-Path -LiteralPath $PlanPath) {
            $destPlan = Join-Path $run.RunDir 'plan.json'
            try {
                Copy-Item -LiteralPath $PlanPath -Destination $destPlan -Force -ErrorAction Stop
                Write-Host ("Injected plan: {0} -> {1}" -f $PlanPath, $destPlan) -ForegroundColor Cyan
            } catch {
                Write-Host ("Failed to inject plan {0}: {1}" -f $PlanPath, $_.Exception.Message) -ForegroundColor Red
            }
        } else {
            Write-Host ("PlanPath not found: {0}" -f $PlanPath) -ForegroundColor Yellow
        }
    }

    # Log NoRestorePoint / SkipPreflight hints
    if ($NoRestorePoint) { Write-Host 'NoRestorePoint: restore point creation will be skipped (config safety).' -ForegroundColor Yellow }
    if ($SkipPreflight) { Write-Host 'SkipPreflight: stage 0 will be marked Skipped.' -ForegroundColor Yellow }

    # Build workflow
    $workflow = $null
    try {
        if ($SkipScanners) { $workflow = New-SccWorkflow -Run $run -Mode $Mode -SkipScanners }
        else { $workflow = New-SccWorkflow -Run $run -Mode $Mode }
    } catch {
        Write-Host ("Failed to create workflow: {0}" -f $_.Exception.Message) -ForegroundColor Red
        exit 1
    }

    if ($PlanPath -and (Test-Path -LiteralPath $PlanPath)) {
        $workflow.PlanPath = $PlanPath
    }

    if ($SkipPreflight) {
        # Mark preflight as already handled so Get-SccNextStage skips it
        $workflow.Stages[0].Status = 'Skipped'
        $workflow.Stages[0].Detail = 'Skipped via -SkipPreflight'
        try { Save-SccRunState -Run $run -Stage $workflow.Stages[0].Name -Status Skipped -Detail $workflow.Stages[0].Detail } catch { }
    }

    # Run the state machine
    try {
        if ($PlanPath -and (Test-Path -LiteralPath $PlanPath)) {
            $null = Start-SccWorkflow -Workflow $workflow -Mode $Mode -PlanPath $PlanPath -SkipScanners:$SkipScanners
        } elseif ($SkipScanners) {
            $null = Start-SccWorkflow -Workflow $workflow -Mode $Mode -SkipScanners
        } else {
            $null = Start-SccWorkflow -Workflow $workflow -Mode $Mode
        }
    } catch {
        Write-Host ("Workflow error: {0}" -f $_.Exception.Message) -ForegroundColor Red
        exit 1
    }

    Write-SccStageSummary -Workflow $workflow
    Write-Host ("Run dir: {0}" -f $run.RunDir) -ForegroundColor Cyan

    # AwaitingReview gate: never auto-approve
    $awaiting = @($workflow.Stages | Where-Object { $_.Status -eq 'AwaitingReview' })
    if (@($awaiting).Count -gt 0) {
        if ($PlanPath -and (Test-Path -LiteralPath $PlanPath)) {
            Write-Host 'Review gate still AwaitingReview after PlanPath injection: check plan.json format (must contain PlanVersion, Items).' -ForegroundColor Red
            exit 1
        } else {
            Write-Host 'Headless Review gate: awaiting remediation plan approval.' -ForegroundColor Yellow
            Write-Host 'No plan was provided - headless stops here. Create a plan.json externally (via New-SccPlan or manual review) and re-run with -PlanPath <path> to continue.' -ForegroundColor Yellow
            Write-Host 'Never auto-approving removal.' -ForegroundColor Yellow
            exit 1
        }
    }

    # Failed stage => exit 1 (but report still exists)
    $failed = @($workflow.Stages | Where-Object { $_.Status -eq 'Failed' })
    if (@($failed).Count -gt 0) {
        Write-Host ("Pipeline completed with {0} failed stage(s)." -f @($failed).Count) -ForegroundColor Red
        foreach ($f in $failed) { Write-Host ("  [{0}] {1}: {2}" -f $f.Index, $f.Name, $f.Detail) -ForegroundColor Red }
        # Partial run is never claimed complete
        exit 1
    }

    $pending = @($workflow.Stages | Where-Object { $_.Status -eq 'Pending' })
    if (@($pending).Count -gt 0) {
        Write-Host ("Pipeline incomplete: {0} stage(s) still pending." -f @($pending).Count) -ForegroundColor Yellow
        exit 1
    }

    # Success: all non-skipped stages completed
    Write-Host 'Headless pipeline finished successfully.' -ForegroundColor Green
    $reportHtml = Join-Path $run.RunDir 'report.html'
    $reportJson = Join-Path $run.RunDir 'report.json'
    $reportTxt = Join-Path $run.RunDir 'technician-summary.txt'
    if (Test-Path -LiteralPath $reportHtml) { Write-Host ("  report.html: {0}" -f $reportHtml) }
    if (Test-Path -LiteralPath $reportJson) { Write-Host ("  report.json: {0}" -f $reportJson) }
    if (Test-Path -LiteralPath $reportTxt) { Write-Host ("  technician-summary.txt: {0}" -f $reportTxt) }
    exit 0
}
else {
    # -----------------------------------------------------------------
    # GUI path (default)
    # -----------------------------------------------------------------
    Import-SccRequiredModule -Name 'Scc.Core'
    Import-SccRequiredModule -Name 'Scc.UI'

    if ($Config) {
        if (-not (Test-Path -LiteralPath $Config)) {
            Write-Host ("Config file not found: {0}" -f $Config) -ForegroundColor Yellow
        }
    }

    try {
        if ($ResumeRunId) {
            $null = Start-SccApp -Config $Config -ResumeRunId $ResumeRunId
        } elseif ($Config) {
            $null = Start-SccApp -Config $Config
        } else {
            $null = Start-SccApp
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'WPF is not available') {
            Write-Host $msg -ForegroundColor Red
            Write-Host 'Tip: use -Headless for non-Windows / CI hosts.' -ForegroundColor Yellow
            exit 2
        }
        Write-Host ("GUI failed: {0}" -f $msg) -ForegroundColor Red
        exit 1
    }
    exit 0
}
