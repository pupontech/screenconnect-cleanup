# ============================================================================
# Scc.UI - WPF shell + shared stage state machine for ScreenConnect Cleaner
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
#
# This module owns TWO things:
#   1. The stage state machine (stages 0..8). This is pure logic, fully
#      testable WITHOUT WPF, and is shared 100% by the GUI and headless modes.
#   2. The WPF application shell (Start-SccApp) and the background job wrapper
#      (Start-SccJob). WPF assemblies are loaded LAZILY inside Start-SccApp
#      only, so this module imports cleanly on Linux / headless hosts.
#
# Backend modules (Scc.Core / Detection / Evidence / Snapshots / Remedy /
# Scanners / Report) are imported on demand inside stage bodies and degrade
# gracefully: if a backend function is missing the stage is marked Failed with
# a clear Detail (never fatal to the whole run unless a hard prerequisite is
# unmet, in which case the dependent stage is Skipped).
# ============================================================================


# Ensure Microsoft.PowerShell.Utility cmdlets ([datetime]::UtcNow, New-Object, ConvertTo-Json,
# Out-Null, Add-Member, etc.) are visible inside this module's session state on every
# host. Without this, module functions fail with CommandNotFoundException on Windows
# when the module is loaded through Pester or a nested session state.
$null = Import-Module -Name 'Microsoft.PowerShell.Utility' -ErrorAction SilentlyContinue
$null = Import-Module -Name 'Microsoft.PowerShell.Management' -ErrorAction SilentlyContinue

$script:CurrentWorkflow = $null
$script:ActiveJob = $null
$script:Dash = $null
$script:MainWindow = $null
$script:AutoCloseAt = $null

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

function New-SccStageRecord {
    param([int]$Index, [string]$Name, [bool]$Skippable)
    return [pscustomobject]@{
        Index      = $Index
        Name       = $Name
        Status     = 'Pending'
        StartedUtc  = $null
        EndedUtc   = $null
        Detail     = ''
        Skippable  = [bool]$Skippable
    }
}

function Import-SccBackendModule {
    param([string]$Name)
    $m = Get-Module -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $m) {
        $m = Import-Module -Name $Name -Force -ErrorAction SilentlyContinue
    }
    return ($null -ne (Get-Module -Name $Name -ErrorAction SilentlyContinue))
}

function Assert-SccBackendFn {
    param([string]$Function, [string]$Module)
    if (-not (Get-Command -Name $Function -ErrorAction SilentlyContinue)) {
        throw ("Backend function '{0}' (module {1}) is not available. Stage degraded." -f $Function, $Module)
    }
}

function Save-SccStageState {
    param($Workflow, $Stage)
    try {
        if (-not (Import-SccBackendModule 'Scc.Core')) { return }
        if (Get-Command -Name Save-SccRunState -ErrorAction SilentlyContinue) {
            Save-SccRunState -Run $Workflow.Run -Stage $Stage.Name -Status $Stage.Status -Detail $Stage.Detail
        }
    } catch {
        # best-effort persistence only
    }
}

function ConvertFrom-SccJsonFile {
    param([string]$Path)
    $raw = Microsoft.PowerShell.Management\Get-Content -Path $Path -Raw -ErrorAction Stop
    return ($raw | ConvertFrom-Json)
}

function Get-SccPlanFromRun {
    param($Workflow)
    if ($Workflow.PlanPath -and (Microsoft.PowerShell.Management\Test-Path -Path $Workflow.PlanPath)) {
        return (ConvertFrom-SccJsonFile -Path $Workflow.PlanPath)
    }
    if ($Workflow.Run -and $Workflow.Run.RunDir -and (Microsoft.PowerShell.Management\Test-Path -Path $Workflow.Run.RunDir)) {
        $candidate = Join-Path -Path $Workflow.Run.RunDir -ChildPath 'plan.json'
        if (Microsoft.PowerShell.Management\Test-Path -Path $candidate) {
            return (ConvertFrom-SccJsonFile -Path $candidate)
        }
    }
    return $null
}

function Import-SccResumeState {
    param($Workflow)
    try {
        if (-not (Import-SccBackendModule 'Scc.Core')) { return }
        if (-not (Get-Command -Name Get-SccRunState -ErrorAction SilentlyContinue)) { return }
        $state = Get-SccRunState -RunId $Workflow.RunId -ErrorAction SilentlyContinue
        if ($null -eq $state -or $null -eq $state.Stages) { return }
        foreach ($s in $Workflow.Stages) {
            $found = $state.Stages | Where-Object { $_.Index -eq $s.Index }
            if ($found -and $found.Status -eq 'Completed') {
                $s.Status = 'Completed'
                $s.Detail = 'Resumed (previously completed)'
            }
        }
    } catch {
        # best-effort resume only
    }
}

function Test-SccStageApplicable {
    param($Workflow, [int]$StageIndex)
    $mode = $Workflow.Mode
    $applicable = @(0, 1, 2, 3, 4, 5, 6, 7, 8)
    if ($mode -eq 'DetectOnly') { $applicable = @(0, 1, 2, 3, 5, 6, 7, 8) }
    elseif ($mode -eq 'ScanOnly') { $applicable = @(0, 5, 8) }
    if ($StageIndex -eq 5 -and $Workflow.SkipScanners) { return $false }
    return ($applicable -contains $StageIndex)
}

# ---------------------------------------------------------------------------
# Stage bodies call private wrapper functions. The wrappers exist INSIDE this
# module so they are individually mockable for tests; at runtime they assert the
# real backend cmdlet is present and delegate to it (graceful degradation: a
# missing backend makes the stage Fail with a clear Detail).

function Invoke-SccBackendPreflight {
    Assert-SccBackendFn -Function 'Get-SccComputerInfo' -Module 'Scc.Core'
    $out = [ordered]@{}
    $out.ComputerInfo = Get-SccComputerInfo
    if (Get-Command -Name Test-SccInternet -ErrorAction SilentlyContinue) { $out.Internet = Test-SccInternet }
    if (Get-Command -Name Test-SccNas -ErrorAction SilentlyContinue) { $out.Nas = Test-SccNas }
    return $out
}

function Invoke-SccBackendSnapshot {
    param($Run, $Label, $Days)
    Assert-SccBackendFn -Function 'New-SccSnapshot' -Module 'Scc.Evidence'
    return (New-SccSnapshot -Run $Run -Label $Label -IncidentWindowDays $Days)
}

function Invoke-SccBackendDetection {
    param($Run)
    Assert-SccBackendFn -Function 'Invoke-SccDetection' -Module 'Scc.Detection'
    return (Invoke-SccDetection -Run $Run)
}

function Invoke-SccBackendRemediation {
    param($Run, $Plan, [switch]$Execute)
    Assert-SccBackendFn -Function 'Invoke-SccRemediation' -Module 'Scc.Remedy'
    if (Get-Command -Name Test-SccPlan -ErrorAction SilentlyContinue) {
        $null = Test-SccPlan -Run $Run -Plan $Plan
    }
    if ($Execute) {
        return (Invoke-SccRemediation -Run $Run -Plan $Plan -Execute)
    }
    return (Invoke-SccRemediation -Run $Run -Plan $Plan)
}

function Invoke-SccBackendScanners {
    param($Run, $Timeout)
    Assert-SccBackendFn -Function 'Invoke-SccScanner' -Module 'Scc.Scanners'
    $list = @()
    if (Get-Command -Name Get-SccScannerList -ErrorAction SilentlyContinue) {
        $list = Get-SccScannerList -EnabledOnly
    }
    $results = @()
    foreach ($s in $list) {
        $name = $s.Name
        if (-not $name) { $name = $s }
        $results += Invoke-SccScanner -Name $name -Run $Run -TimeoutMinutes $Timeout
    }
    return $results
}

function Invoke-SccBackendCompare {
    param($Before, $After, $Run)
    Assert-SccBackendFn -Function 'Compare-SccSnapshots' -Module 'Scc.Snapshots'
    return (Compare-SccSnapshots -Before $Before -After $After -Run $Run)
}

function Invoke-SccBackendReport {
    param($Run)
    Assert-SccBackendFn -Function 'New-SccReport' -Module 'Scc.Report'
    return (New-SccReport -Run $Run)
}

function Invoke-SccStageBody {
    param($Workflow, $Stage)

    switch ($Stage.Index) {
        0 {
            $r = Invoke-SccBackendPreflight
            $Workflow.Data.ComputerInfo = $r.ComputerInfo
            $Workflow.Data.Internet = $r.Internet
            $Workflow.Data.Nas = $r.Nas
            $Stage.Detail = 'Preflight checks collected'
            $Stage.Status = 'Completed'
        }
        1 {
            $Workflow.Data.SnapshotBefore = Invoke-SccBackendSnapshot -Run $Workflow.Run -Label before -Days $Workflow.IncidentWindowDays
            $Stage.Detail = 'Snapshot (before) collected'
            $Stage.Status = 'Completed'
        }
        2 {
            $Workflow.Data.Findings = Invoke-SccBackendDetection -Run $Workflow.Run
            $Stage.Detail = 'Detection complete'
            $Stage.Status = 'Completed'
        }
        3 {
            # Review gate
            if ($Workflow.Mode -ne 'Full') {
                $Stage.Status = 'Completed'
                $Stage.Detail = ('No remediation plan required in mode ' + $Workflow.Mode)
                return
            }
            $plan = Get-SccPlanFromRun -Workflow $Workflow
            if ($null -ne $plan) {
                $Workflow.Data.Plan = $plan
                $Stage.Status = 'Completed'
                $Stage.Detail = 'Remediation plan loaded'
                return
            }
            # No plan -> headless stops here. Auto-approval is FORBIDDEN.
            $Stage.Status = 'AwaitingReview'
            $Stage.Detail = 'Awaiting remediation plan approval (headless stops here; provide -PlanPath or approve in GUI)'
        }
        4 {
            $plan = $Workflow.Data.Plan
            if ($null -eq $plan) { $plan = Get-SccPlanFromRun -Workflow $Workflow }
            if ($null -eq $plan) { throw 'No remediation plan available for stage 4 (Remediate).' }
            # Dry-run unless the GUI review gate explicitly authorized execution
            # (two-step typed confirmation) by setting Data.ExecuteRemediation.
            $execute = ($Workflow.Data.ExecuteRemediation -eq $true)
            $Workflow.Data.Remediation = Invoke-SccBackendRemediation -Run $Workflow.Run -Plan $plan -Execute:$execute
            if ($execute) {
                $Stage.Detail = 'Remediation EXECUTED (explicit GUI confirmation)'
            } else {
                $Stage.Detail = 'Remediation dry-run (no changes)'
            }
            $Stage.Status = 'Completed'
        }
        5 {
            $Workflow.Data.ScannerResults = Invoke-SccBackendScanners -Run $Workflow.Run -Timeout $Workflow.ScannerTimeout
            $Stage.Detail = ('Scanners run: ' + @($Workflow.Data.ScannerResults).Count)
            $Stage.Status = 'Completed'
        }
        6 {
            $Workflow.Data.SnapshotAfter = Invoke-SccBackendSnapshot -Run $Workflow.Run -Label after -Days $Workflow.IncidentWindowDays
            $Stage.Detail = 'Snapshot (after) collected'
            $Stage.Status = 'Completed'
        }
        7 {
            $Workflow.Data.Diff = Invoke-SccBackendCompare -Before $Workflow.Data.SnapshotBefore -After $Workflow.Data.SnapshotAfter -Run $Workflow.Run
            $Stage.Detail = 'Before/After comparison complete'
            $Stage.Status = 'Completed'
        }
        8 {
            $Workflow.Data.Report = Invoke-SccBackendReport -Run $Workflow.Run
            $Stage.Detail = 'Report generated'
            $Stage.Status = 'Completed'
        }
    }
}

# ---------------------------------------------------------------------------
# Exported: state machine
# ---------------------------------------------------------------------------

function New-SccWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]$Run = $null,
        [ValidateSet('Full', 'DetectOnly', 'ScanOnly')][string]$Mode = 'Full',
        [switch]$SkipScanners,
        [switch]$Resume,
        [string]$RunId,
        [int]$IncidentWindowDays = 7,
        [int]$ScannerTimeout = 120
    )

    if ($null -eq $Run) {
        if ([string]::IsNullOrEmpty($RunId)) {
            $RunId = ('SC-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '-HOST-' + ([datetime]::UtcNow.ToString('HHmmss')))
        }
        $Run = [pscustomobject]@{
            RunId        = $RunId
            RunDir       = $null
            ComputerName = $env:COMPUTERNAME
        }
    }

    $stages = @(
        (New-SccStageRecord 0 'Preflight'      $false)
        (New-SccStageRecord 1 'SnapshotBefore' $false)
        (New-SccStageRecord 2 'Detection'      $false)
        (New-SccStageRecord 3 'Review'         $false)
        (New-SccStageRecord 4 'Remediate'      $true)
        (New-SccStageRecord 5 'Scanners'       $true)
        (New-SccStageRecord 6 'SnapshotAfter'  $false)
        (New-SccStageRecord 7 'Compare'        $false)
        (New-SccStageRecord 8 'Report'         $false)
    )

    $wf = [pscustomobject]@{
        RunId               = $Run.RunId
        Run                 = $Run
        Mode                = $Mode
        SkipScanners        = [bool]$SkipScanners
        PlanPath            = $null
        IncidentWindowDays  = $IncidentWindowDays
        ScannerTimeout      = $ScannerTimeout
        Stages              = $stages
        Data                = [ordered]@{}
        Status              = 'Created'
        StartedUtc          = $null
        EndedUtc            = $null
        StopRequested       = $false
    }

    if ($Resume) { Import-SccResumeState -Workflow $wf }
    return $wf
}

function Get-SccNextStage {
    [CmdletBinding()]
    param($Workflow)
    foreach ($s in $Workflow.Stages) {
        if ($s.Status -eq 'AwaitingReview') { return $s }
        if ($s.Status -eq 'Pending') { return $s }
    }
    return $null
}

function Step-SccWorkflow {
    [CmdletBinding()]
    param($Workflow)

    $stage = Get-SccNextStage -Workflow $Workflow
    if ($null -eq $stage -or $stage.Status -ne 'Pending') {
        return $Workflow
    }

    # Mode / user-skip applicability
    if (-not (Test-SccStageApplicable -Workflow $Workflow -StageIndex $stage.Index)) {
        $stage.Status = 'Skipped'
        $stage.Detail = 'Not applicable in mode or skipped by user'
        $stage.EndedUtc = [datetime]::UtcNow
        Save-SccStageState -Workflow $Workflow -Stage $stage
        return $Workflow
    }

    # Hard prerequisite checks (ARCHITECTURE section 4)
    if ($stage.Index -eq 4 -and $Workflow.Stages[3].Status -ne 'Completed') {
        $stage.Status = 'Skipped'
        $stage.Detail = 'Requires stage 3 (Review) Completed with a plan'
        $stage.EndedUtc = [datetime]::UtcNow
        Save-SccStageState -Workflow $Workflow -Stage $stage
        return $Workflow
    }
    if ($stage.Index -eq 6 -and $Workflow.Stages[5].Status -notin @('Completed', 'Skipped')) {
        $stage.Status = 'Skipped'
        $stage.Detail = 'Requires stage 5 (Scanners) Completed or Skipped'
        $stage.EndedUtc = [datetime]::UtcNow
        Save-SccStageState -Workflow $Workflow -Stage $stage
        return $Workflow
    }
    if ($stage.Index -eq 7 -and $Workflow.Stages[6].Status -ne 'Completed') {
        $stage.Status = 'Skipped'
        $stage.Detail = 'Requires stage 6 (SnapshotAfter) Completed'
        $stage.EndedUtc = [datetime]::UtcNow
        Save-SccStageState -Workflow $Workflow -Stage $stage
        return $Workflow
    }

    $stage.Status = 'Running'
    $stage.StartedUtc = [datetime]::UtcNow
    Save-SccStageState -Workflow $Workflow -Stage $stage

    try {
        Invoke-SccStageBody -Workflow $Workflow -Stage $stage
        if ($stage.Status -eq 'Running') { $stage.Status = 'Completed' }
    } catch {
        # Non-fatal: one failed stage must not abort the run.
        $stage.Status = 'Failed'
        $stage.Detail = ('Stage failed: ' + $_.Exception.Message)
    }

    $stage.EndedUtc = [datetime]::UtcNow
    Save-SccStageState -Workflow $Workflow -Stage $stage
    return $Workflow
}

function Start-SccWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Workflow,
        [ValidateSet('Full', 'DetectOnly', 'ScanOnly')][string]$Mode,
        [switch]$SkipScanners,
        [switch]$Resume,
        [string]$PlanPath
    )

    if ($Mode) { $Workflow.Mode = $Mode }
    if ($SkipScanners) { $Workflow.SkipScanners = $true }
    if ($PlanPath) { $Workflow.PlanPath = $PlanPath }

    if ($Resume) { Import-SccResumeState -Workflow $Workflow }

    $Workflow.Status = 'Running'
    $Workflow.StartedUtc = [datetime]::UtcNow
    $script:CurrentWorkflow = $Workflow

    do {
        if ($Workflow.StopRequested) {
            foreach ($s in $Workflow.Stages) {
                if ($s.Status -eq 'Pending') { $s.Status = 'Skipped'; $s.Detail = 'Skipped due to workflow stop' }
            }
            break
        }
        $next = Get-SccNextStage -Workflow $Workflow
        if ($null -eq $next) { break }
        if ($next.Status -eq 'AwaitingReview') {
            $Workflow.Status = 'AwaitingReview'
            break
        }
        # Suppress Step-SccWorkflow's return value: the function emits the
        # workflow per stage step, which would pollute the caller's pipeline
        # (the GUI job result must be exactly ONE workflow object).
        $null = Step-SccWorkflow -Workflow $Workflow
    } while ($true)

    if ($Workflow.Status -ne 'AwaitingReview') {
        $Workflow.Status = 'Completed'
        $Workflow.EndedUtc = [datetime]::UtcNow
    }
    return $Workflow
}

function Stop-SccWorkflow {
    [CmdletBinding()]
    param($Workflow)

    $Workflow.StopRequested = $true
    foreach ($s in $Workflow.Stages) {
        if ($s.Status -eq 'Running') {
            $s.Status = 'Interrupted'
            $s.EndedUtc = [datetime]::UtcNow
        } elseif ($s.Status -eq 'Pending') {
            $s.Status = 'Skipped'
            $s.Detail = 'Skipped due to workflow stop'
            $s.EndedUtc = [datetime]::UtcNow
        }
    }
    $Workflow.Status = 'Interrupted'
    $Workflow.EndedUtc = [datetime]::UtcNow
    return $Workflow
}

# ---------------------------------------------------------------------------
# Exported: background job wrapper (cooperative cancellation token)
#
# Design: the heavy runspace/pipeline objects live ONLY in a private
# $script:Jobs hashtable keyed by a job Id. Start-SccJob returns a LIGHT
# handle (Id + Token + status fields) that is a plain copy, NOT the live
# runspace object. All Stop/Wait/Update/Reset operations resolve the real
# runspace from $script:Jobs by Id. This fully decouples the caller's handle
# variable from the runspace lifecycle (the previous design held the same
# [pscustomobject] in both the caller and $script:ActiveJob, and PowerShell
# nulled the caller's variable when the runspace finalized).
# ---------------------------------------------------------------------------

$script:Jobs = @{ }

function Start-SccJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$ScriptBlock,
        [string]$Name = 'Job',
        $OnProgress = $null,
        $CancellationToken = $null
    )

    if ($script:Jobs.Count -gt 0) {
        # Only one concurrent Scc job is allowed (stages are sequential by design).
        throw 'Only one concurrent Scc job is allowed (stages are sequential by design).'
    }

    # The token is CALLER-OWNED. The runspace may READ .Cancelled but never
    # writes to it. The runspace keeps its own final-state object and emits it
    # as pipeline output (collected via EndInvoke).
    # IMPORTANT: the runspace receives its OWN token copy. Passing the same
    # [hashtable] object that the caller's handle also references causes
    # PowerShell to null the caller's handle variable when the runspace
    # pipeline is finalized/garbage-collected. Keeping them separate avoids
    # that host-state corruption.
    if ($null -eq $CancellationToken) {
        $CancellationToken = @{ Cancelled = $false }
    }
    # Optional payload fields (e.g. Workflow) ride along in the token copy so
    # GUI click handlers can hand the job the real workflow object without
    # sharing a live handle with the runspace.
    $runspaceToken = @{ Cancelled = $CancellationToken.Cancelled; Workflow = $CancellationToken.Workflow }

    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs

    # The job scriptblock is executed INSIDE the runspace and must bind to the
    # RUNSPACE's session state, never the caller's. Passing the caller's live
    # scriptblock object lets it carry the parent module's session state into
    # the runspace; executing module functions through it then corrupts the
    # caller's session state (Pester host-state corruption: later commands
    # like Start-Sleep stop resolving). Serialize to text and re-parse inside
    # the runspace; the wrapper imports Scc.UI (by path) so exported functions
    # (Invoke-SccGuiWorkflow, ...) resolve runspace-locally. Scriptblocks with
    # closures are NOT supported (GUI job scriptblocks use only their $Token
    # parameter and module functions).
    $scriptText = $ScriptBlock.ToString()
    $sccUiModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Scc.UI.psd1'
    if (-not (Microsoft.PowerShell.Management\Test-Path -Path $sccUiModulePath)) {
        $sccUiModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Scc.UI.psm1'
    }
    $sccSrcRoot = Split-Path -Parent $PSScriptRoot

    $wrapper = @'
param($Token, $ScriptBlockText, $ModulePath, $SrcRoot)
if ($SrcRoot -and $SrcRoot.Length -gt 0) {
    $sep = [System.IO.Path]::PathSeparator
    $env:PSModulePath = $SrcRoot + $sep + $env:PSModulePath
}
if ($ModulePath) {
    Import-Module -Name $ModulePath -Force -ErrorAction SilentlyContinue
}
$state = [System.Collections.Specialized.OrderedDictionary]::new()
$state['State'] = 'Running'
$state['Result'] = $null
$state['Error'] = $null
$state['Percent'] = 0
try {
    $result = & ([scriptblock]::Create($ScriptBlockText)) $Token
    $state['State'] = 'Completed'
    $state['Result'] = $result
    $state['Percent'] = 100
} catch {
    if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) {
        $state['State'] = 'Interrupted'
    } else {
        $state['State'] = 'Failed'
        $state['Error'] = ($_ | Out-String)
    }
}
[pscustomobject]$state
'@

    $null = $ps.AddScript($wrapper).AddArgument($runspaceToken).AddArgument($scriptText).AddArgument($sccUiModulePath).AddArgument($sccSrcRoot)
    $async = $ps.BeginInvoke()

    $id = [guid]::NewGuid().ToString()
    # Private store: the live runspace/pipeline, never handed to the caller.
    $script:Jobs[$id] = [pscustomobject]@{
        Id        = $id
        PowerShell = $ps
        Async     = $async
        Token     = $CancellationToken
        Start     = [datetime]::UtcNow
        Done      = $false
    }

    # Light handle returned to the caller (plain copy, no live runspace ref).
    return [pscustomobject]@{
        Id       = $id
        Name     = $Name
        State    = 'Running'
        Result   = $null
        Error    = $null
        Progress = $null
        Percent  = 0
        Elapsed  = [timespan]::Zero
        _Token   = $CancellationToken
        _Done    = $false
    }
}

function Update-SccJob {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Handle)

    if ($null -eq $Handle) { throw 'Update-SccJob: handle is null.' }
    $job = $script:Jobs[$Handle.Id]
    if ($null -eq $job) { throw ('Update-SccJob: unknown job id ' + $Handle.Id) }
    $Handle.Elapsed = ([datetime]::UtcNow - $job.Start)
    if ($job.Done) { $Handle.State = $Handle.State; return }

    if ($null -ne $job.Async -and $job.Async.IsCompleted) {
        $finalState = $null
        try { $out = $job.PowerShell.EndInvoke($job.Async); if ($null -ne $out) { $finalState = @($out)[-1] } } catch {}
        if ($null -ne $finalState) {
            $Handle.State   = $finalState.State
            $Handle.Result  = $finalState.Result
            $Handle.Error   = $finalState.Error
            $Handle.Percent = $finalState.Percent
        }
        $job.Done = $true
        $Handle._Done = $true
    }
}

function Wait-SccJob {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Handle)

    if ($null -eq $Handle) { throw 'Wait-SccJob: handle is null.' }
    $job = $script:Jobs[$Handle.Id]
    if ($null -eq $job) { throw ('Wait-SccJob: unknown job id ' + $Handle.Id) }
    $finalState = $null
    try { $out = $job.PowerShell.EndInvoke($job.Async); if ($null -ne $out) { $finalState = @($out)[-1] } } catch {}
    if ($null -ne $finalState) {
        $Handle.State   = $finalState.State
        $Handle.Result  = $finalState.Result
        $Handle.Error   = $finalState.Error
        $Handle.Percent = $finalState.Percent
    }
    $job.Done = $true
    $Handle._Done = $true
    $Handle.Elapsed = ([datetime]::UtcNow - $job.Start)
}

function Stop-SccJob {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Handle)

    if ($null -eq $Handle) { throw 'Stop-SccJob: handle is null.' }
    $job = $script:Jobs[$Handle.Id]
    if ($null -eq $job) { throw ('Stop-SccJob: unknown job id ' + $Handle.Id) }
    if ($null -ne $job.Token) { $job.Token.Cancelled = $true }
    if ($null -ne $Handle._Token) { $Handle._Token.Cancelled = $true }
    try { $job.PowerShell.Stop() } catch {}
    $finalState = $null
    try { $out = $job.PowerShell.EndInvoke($job.Async); if ($null -ne $out) { $finalState = @($out)[-1] } } catch {}
    if ($null -ne $finalState) {
        $Handle.State = $finalState.State
    } else {
        $Handle.State = 'Interrupted'
    }
    $job.Done = $true
    $Handle._Done = $true
    $Handle.Elapsed = ([datetime]::UtcNow - $job.Start)
}

function Reset-SccJob {
    # Force-clear any leaked job (e.g. between tests): stop + drain the
    # pipeline, then remove it from the private store.
    [CmdletBinding()]
    param()

    foreach ($id in @($script:Jobs.Keys)) {
        $job = $script:Jobs[$id]
        try {
            if ($null -ne $job.PowerShell) {
                try { $job.PowerShell.Stop() } catch {}
                try { $null = $job.PowerShell.EndInvoke($job.Async) } catch {}
                # NOTE: deliberately do NOT call PowerShell/Runspace.Dispose()
                # here. Disposing a runspace can corrupt the caller's current
                # scope variables (PowerShell host-state corruption), which
                # manifests as the caller's handle variable becoming null.
                # Leaving the runspace to the GC is safe; we just drop our
                # reference so a new job can start.
            }
        } catch {}
        $script:Jobs.Remove($id)
    }
}

# ---------------------------------------------------------------------------
# Exported: WPF application entry. WPF assemblies loaded LAZILY here only.
# ---------------------------------------------------------------------------

function Get-SccViewPath {
    param([string]$Name)
    $dir = Split-Path -Parent $MyInvocation.PSCommandPath
    return Join-Path -Path (Join-Path -Path $dir -ChildPath 'Views') -ChildPath ($Name + '.xaml')
}

function Import-SccXaml {
    param([string]$Path)
    [xml]$xaml = Microsoft.PowerShell.Management\Get-Content -Path $Path
    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    return [System.Windows.Markup.XamlReader]::Load($reader)
}

# ---------------------------------------------------------------------------
# GUI workflow runner (exported so it resolves inside the job runspace, which
# imports Scc.UI but cannot see private functions).
#
# Token shape: @{ Cancelled = <bool>; Workflow = <Scc workflow object> }
#   - Cancelled  : set true by Stop-SccJob -> job stops the workflow first.
#   - Workflow   : the live workflow object created by the click handler.
# Without a Workflow payload this throws, so a wiring regression fails loudly
# instead of silently completing a no-op run (the pre-fix behavior).
# ---------------------------------------------------------------------------

function Invoke-SccGuiWorkflow {
    [CmdletBinding()]
    param($Token)

    if ($null -eq $Token -or $null -eq $Token.Workflow) {
        throw 'GUI workflow token missing Workflow payload (internal wiring bug).'
    }
    $wf = $Token.Workflow
    if ($Token.Cancelled) {
        return (Stop-SccWorkflow -Workflow $wf)
    }
    return (Start-SccWorkflow -Workflow $wf -Mode $wf.Mode -SkipScanners:$wf.SkipScanners)
}

# ---------------------------------------------------------------------------
# Private GUI helpers (run on the UI thread)
# ---------------------------------------------------------------------------

function Set-DashText {
    param($Dash, [string]$Name, [string]$Text)
    try {
        $c = $Dash.FindName($Name)
        if ($null -ne $c) { $c.Text = $Text }
    } catch { }
}

function Set-SccGuiStatus {
    param([string]$Text)
    try {
        if ($null -ne $script:Dash) { Set-DashText -Dash $script:Dash -Name 'TxtStatus' -Text $Text }
    } catch { }
}

function Update-SccDashboardInfo {
    param($Dash)
    try {
        $info = $null
        if (Get-Command -Name Get-SccComputerInfo -ErrorAction SilentlyContinue) {
            $info = Get-SccComputerInfo
        }
        if ($null -ne $info) {
            Set-DashText -Dash $Dash -Name 'TxtComputer' -Text ([string]$info.ComputerName)
            $os = [string]$info.OsCaption
            if ($info.OsVersion) { $os += (' ' + $info.OsVersion) }
            Set-DashText -Dash $Dash -Name 'TxtOs' -Text $os
            Set-DashText -Dash $Dash -Name 'TxtArch' -Text ([string]$info.Architecture)
            Set-DashText -Dash $Dash -Name 'TxtUser' -Text ([string]$info.Domain + '\' + $info.CurrentUser)
            Set-DashText -Dash $Dash -Name 'TxtAdmin' -Text $(if ($info.IsAdmin) { 'Yes (elevated)' } else { 'No' })
            if ($info.FreeSpaceGB -ge 0) { Set-DashText -Dash $Dash -Name 'TxtDisk' -Text ($info.FreeSpaceGB.ToString() + ' GB free') }
        }
    } catch { }
    try {
        $version = ''
        $mod = Get-Module -Name 'Scc.UI' -ErrorAction SilentlyContinue
        if ($null -ne $mod -and $mod.Path) {
            $appRoot = Split-Path -Parent (Split-Path -Parent $mod.Path)
            $vf = Join-Path $appRoot 'VERSION'
            if (Microsoft.PowerShell.Management\Test-Path -Path $vf) {
                $version = (Microsoft.PowerShell.Management\Get-Content -Path $vf -Raw).Trim()
            }
        }
        if (-not $version) {
            $core = Get-Module -Name 'Scc.Core' -ErrorAction SilentlyContinue
            if ($null -ne $core -and $core.Version) { $version = $core.Version.ToString() }
        }
        if ($version) { Set-DashText -Dash $Dash -Name 'TxtAppVersion' -Text $version }
    } catch { }
}

function Update-SccRecentRunsList {
    param($Dash)
    try {
        if (-not (Get-Command -Name Find-SccRecentRuns -ErrorAction SilentlyContinue)) { return }
        $runs = @(Find-SccRecentRuns -MaxAgeDays 30 | Select-Object -First 20)
        $list = $Dash.FindName('LstPreviousRuns')
        if ($null -eq $list) { return }
        if ($runs.Count -gt 0) {
            $items = @($runs | ForEach-Object {
                [pscustomobject]@{
                    RunId = $_.RunId
                    RunDir = $_.RunDir
                    Display = ($_.RunId + '  [' + $_.RunDir + ']')
                }
            })
            $list.DisplayMemberPath = 'Display'
            $list.ItemsSource = $items
        }
    } catch { }
}

function Start-SccGuiJobWithToken {
    param($Token, [string]$JobName)
    try {
        $handle = Start-SccJob -ScriptBlock { param($t) Invoke-SccGuiWorkflow -Token $t } -Name $JobName -CancellationToken $Token
        $script:ActiveJob = $handle
        Set-SccGuiStatus -Text ('Running: ' + $JobName)
    } catch {
        [System.Windows.MessageBox]::Show($_.Exception.Message, 'ScreenConnect Cleaner', 'OK', 'Error') | Out-Null
    }
}

function Start-SccGuiJob {
    param([string]$Mode, [string]$JobName)
    $wf = New-SccWorkflow -Mode $Mode -Run (New-SccGuiRun)
    Start-SccGuiJobWithToken -Token @{ Cancelled = $false; Workflow = $wf } -JobName $JobName
}

function Show-SccViewWindow {
    param([string]$Name)
    try {
        $view = Import-SccXaml -Path (Get-SccViewPath -Name $Name)
        $w = [System.Windows.Window]::new()
        $w.Title = ('ScreenConnect Cleaner - ' + $Name)
        $w.Width = 1000
        $w.Height = 700
        $w.WindowStartupLocation = 'CenterOwner'
        $w.Content = $view
        $null = $w.ShowDialog()
    } catch {
        [System.Windows.MessageBox]::Show($_.Exception.Message, 'ScreenConnect Cleaner', 'OK', 'Error') | Out-Null
    }
}

function New-SccGuiRun {
    # GUI workflows need a REAL run (RunDir) so plan.json / reports /
    # evidence have a home. Falls back to a plain run object when the
    # Core backend is unavailable (tests / degraded environments).
    $run = $null
    if (Get-Command -Name New-SccRun -ErrorAction SilentlyContinue) {
        try {
            $tech = $env:USERNAME
            if (-not $tech) { $tech = $env:USER }
            if (-not $tech) { $tech = 'GUI' }
            $run = New-SccRun -Technician $tech -Client 'GUI'
        } catch { $run = $null }
    }
    if ($null -eq $run) {
        $run = [pscustomobject]@{
            RunId        = ('SC-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '-HOST-' + ([datetime]::UtcNow.ToString('HHmmss')))
            RunDir       = $null
            ComputerName = $env:COMPUTERNAME
        }
    }
    return $run
}

function New-SccGuiFindingsViewModel {
    param($Workflow)
    $out = @()
    try {
        $data = $Workflow.Data.Findings
        if ($null -eq $data) { return $out }
        $all = @()
        if ($null -ne $data.ScreenConnect) { $all += @($data.ScreenConnect) }
        if ($null -ne $data.RemoteAccess) { $all += @($data.RemoteAccess) }
        $seen = @{}
        foreach ($f in $all) {
            $fid = [string]$f.FindingId
            if (-not $fid) { $fid = 'unknown' }
            if ($seen.ContainsKey($fid)) { continue }
            $seen[$fid] = $true
            $display = [string]$f.DisplayText
            if (-not $display) { $display = ($fid + ' [' + $f.Product + ']') }
            $identity = [string]$f.ServiceName
            if (-not $identity) { $identity = [string]$f.InstallDir }
            if (-not $identity) { $identity = [string]$f.MainExe }
            if (-not $identity) { $identity = $fid }
            $trust = [string]$f.TrustMatch
            if (-not $trust) { $trust = 'Unknown' }
            $evidence = [string]$f.Detail
            $out += [pscustomobject]@{
                DisplayText = $display
                Identity    = $identity
                Trust       = ('Trust: ' + $trust)
                Evidence    = $evidence
                Remove      = $false
                Finding     = $f
            }
        }
    } catch { }
    return $out
}

function New-SccGuiPlan {
    param($Workflow, $ViewModels)
    # Build decisions from the checkbox state (default KEEP; only explicit
    # REMOVE checks become removals - owner policy enforced by New-SccPlan).
    $decisions = @{}
    foreach ($vm in @($ViewModels)) {
        if ($vm.Remove -eq $true) {
            $fid = [string]$vm.Finding.FindingId
            if (-not $fid) { $fid = 'unknown' }
            $decisions[$fid] = 'REMOVE'
        }
    }
    if (-not (Import-SccBackendModule 'Scc.Remedy')) {
        throw 'Scc.Remedy backend is not available; cannot build a remediation plan.'
    }
    if (-not (Get-Command -Name New-SccPlan -ErrorAction SilentlyContinue)) {
        throw 'New-SccPlan is not available; cannot build a remediation plan.'
    }
    $plan = New-SccPlan -Run $Workflow.Run -Findings @($ViewModels | ForEach-Object { $_.Finding }) -Decisions $decisions
    $Workflow.Data.Plan = $plan
    return $plan
}

function Show-SccFindingsWindow {
    param($Workflow)
    try {
        $view = Import-SccXaml -Path (Get-SccViewPath -Name 'Findings')
        $w = [System.Windows.Window]::new()
        $w.Title = 'ScreenConnect Cleaner - Findings Review'
        $w.Width = 1200
        $w.Height = 800
        $w.WindowStartupLocation = 'CenterOwner'
        $w.Content = $view

        $viewModels = New-SccGuiFindingsViewModel -Workflow $Workflow
        $list = $view.FindName('LstFindings')
        if ($null -ne $list) { $list.ItemsSource = $viewModels }

        $btnApprove = $view.FindName('BtnApprovePlan')
        if ($null -ne $btnApprove) {
            $handler = {
                param($sender, $e)
                try {
                    if (@($viewModels | Where-Object { $_.Remove -eq $true }).Count -eq 0) {
                        [System.Windows.MessageBox]::Show('No items marked for removal. Check the "Remove" box on at least one ScreenConnect finding, or close this window to keep everything.', 'ScreenConnect Cleaner', 'OK', 'Information') | Out-Null
                        return
                    }
                    $null = New-SccGuiPlan -Workflow $Workflow -ViewModels $viewModels
                    $Workflow.Data.ExecuteRemediation = $false
                    Set-SccGuiStatus -Text 'Plan approved - continuing workflow (dry-run remediation).'
                    $w.Close()
                    Start-SccGuiJobWithToken -Token @{ Cancelled = $false; Workflow = $Workflow } -JobName 'ContinueAfterReview'
                } catch {
                    [System.Windows.MessageBox]::Show($_.Exception.Message, 'ScreenConnect Cleaner', 'OK', 'Error') | Out-Null
                }
            }
            $btnApprove.Add_Click($handler.GetNewClosure())
        }

        $btnPreview = $view.FindName('BtnPreviewActions')
        if ($null -ne $btnPreview) {
            $handler = {
                param($sender, $e)
                try {
                    $plan = New-SccGuiPlan -Workflow $Workflow -ViewModels $viewModels
                    $w.Close()
                    Show-SccRemediationWindow -Workflow $Workflow -Plan $plan
                } catch {
                    [System.Windows.MessageBox]::Show($_.Exception.Message, 'ScreenConnect Cleaner', 'OK', 'Error') | Out-Null
                }
            }
            $btnPreview.Add_Click($handler.GetNewClosure())
        }

        $null = $w.ShowDialog()
    } catch {
        [System.Windows.MessageBox]::Show($_.Exception.Message, 'ScreenConnect Cleaner', 'OK', 'Error') | Out-Null
    }
}

function Show-SccRemediationWindow {
    param($Workflow, $Plan)
    try {
        $view = Import-SccXaml -Path (Get-SccViewPath -Name 'RemediationPreview')
        $w = [System.Windows.Window]::new()
        $w.Title = 'ScreenConnect Cleaner - Remediation Preview'
        $w.Width = 1200
        $w.Height = 800
        $w.WindowStartupLocation = 'CenterOwner'
        $w.Content = $view

        # Dry-run preview lines (Test-SccPlan also validates the plan).
        $actions = @()
        if (Get-Command -Name Test-SccPlan -ErrorAction SilentlyContinue) {
            try { $actions = @(Test-SccPlan -Run $Workflow.Run -Plan $Plan) } catch { }
        }
        $list = $view.FindName('LstActions')
        if ($null -ne $list) { $list.ItemsSource = $actions }

        $chkDry = $view.FindName('ChkDryRun')
        if ($null -ne $chkDry) { $chkDry.IsChecked = $true }

        $btnExec = $view.FindName('BtnExecuteRemediation')
        if ($null -ne $btnExec) {
            $handler = {
                param($sender, $e)
                try {
                    # Safety invariant #2: two explicit confirmations before any
                    # destructive action. Nothing runs without both.
                    if ($null -ne $chkDry -and $chkDry.IsChecked -eq $true) {
                        [System.Windows.MessageBox]::Show('Dry run is enabled - no changes will be made. Uncheck "Dry run" to enable execution.', 'ScreenConnect Cleaner', 'OK', 'Information') | Out-Null
                        return
                    }
                    $removeCount = @($Plan.Items | Where-Object { $_.Action -eq 'REMOVE' }).Count
                    if ($removeCount -le 0) {
                        [System.Windows.MessageBox]::Show('The approved plan contains no REMOVE actions; nothing to execute.', 'ScreenConnect Cleaner', 'OK', 'Information') | Out-Null
                        return
                    }
                    $r = [System.Windows.MessageBox]::Show(('You are about to REMOVE {0} ScreenConnect item(s) from this machine. This cannot be undone (artifacts are quarantined, not deleted).' -f $removeCount), 'ScreenConnect Cleaner - FINAL CONFIRMATION', 'YesNo', 'Warning')
                    if ($r -ne 'Yes') { return }
                    $phrase = ''
                    try {
                        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop | Out-Null
                        $phrase = [Microsoft.VisualBasic.Interaction]::InputBox(('Type exactly: PERMANENTLY REMOVE' + [Environment]::NewLine + 'to confirm remediation of ' + $removeCount + ' item(s).'), 'ScreenConnect Cleaner - Confirmation Required', '')
                    } catch { }
                    if ($phrase -ne 'PERMANENTLY REMOVE') {
                        [System.Windows.MessageBox]::Show('Confirmation phrase did not match. Execution cancelled - nothing was changed.', 'ScreenConnect Cleaner', 'OK', 'Information') | Out-Null
                        return
                    }
                    $Workflow.Data.ExecuteRemediation = $true
                    Set-SccGuiStatus -Text 'Execution authorized - running remediation.'
                    $w.Close()
                    Start-SccGuiJobWithToken -Token @{ Cancelled = $false; Workflow = $Workflow } -JobName 'RemediateExecute'
                } catch {
                    [System.Windows.MessageBox]::Show($_.Exception.Message, 'ScreenConnect Cleaner', 'OK', 'Error') | Out-Null
                }
            }
            $btnExec.Add_Click($handler.GetNewClosure())
        }

        $null = $w.ShowDialog()
    } catch {
        [System.Windows.MessageBox]::Show($_.Exception.Message, 'ScreenConnect Cleaner', 'OK', 'Error') | Out-Null
    }
}

function Start-SccApp {
    [CmdletBinding()]
    param(
        $Config,
        [string]$ResumeRunId,
        [int]$AutoCloseSeconds = 0
    )

    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        Add-Type -AssemblyName PresentationCore -ErrorAction Stop
        Add-Type -AssemblyName WindowsBase -ErrorAction Stop
    } catch {
        throw ('WPF is not available in this environment. ScreenConnect Cleaner requires Windows PowerShell 5.1 on a Windows desktop session. Use headless mode (Start-SccWorkflow) on this host. Detail: ' + $_.Exception.Message)
    }

    $dash = Import-SccXaml -Path (Get-SccViewPath -Name 'Dashboard')
    $script:Dash = $dash

    $window = [System.Windows.Window]::new()
    $window.Title = 'ScreenConnect Cleaner'
    $window.Width = 1200
    $window.Height = 850
    $window.Content = $dash
    $script:MainWindow = $window

    Update-SccDashboardInfo -Dash $dash
    Update-SccRecentRunsList -Dash $dash

    # Wire action buttons (names defined in Dashboard.xaml). The background job
    # runs the workflow so the UI thread never blocks (ARCHITECTURE sec. 8).
    $btnFull = $dash.FindName('BtnFullInvestigation')
    if ($null -ne $btnFull) {
        $btnFull.Add_Click({ Start-SccGuiJob -Mode Full -JobName 'FullInvestigation' })
    }
    $btnDetect = $dash.FindName('BtnDetectionOnly')
    if ($null -ne $btnDetect) {
        $btnDetect.Add_Click({ Start-SccGuiJob -Mode DetectOnly -JobName 'DetectionOnly' })
    }
    $btnScan = $dash.FindName('BtnScanOnly')
    if ($null -ne $btnScan) {
        $btnScan.Add_Click({ Start-SccGuiJob -Mode ScanOnly -JobName 'ScanOnly' })
    }
    $btnReview = $dash.FindName('BtnReviewPrevious')
    if ($null -ne $btnReview) {
        $btnReview.Add_Click({ Show-SccViewWindow -Name 'ReportView' })
    }
    $btnSettings = $dash.FindName('BtnSettings')
    if ($null -ne $btnSettings) {
        $btnSettings.Add_Click({ Show-SccViewWindow -Name 'Settings' })
    }
    $btnAdvanced = $dash.FindName('BtnAdvanced')
    if ($null -ne $btnAdvanced) {
        $btnAdvanced.Add_Click({ Show-SccViewWindow -Name 'Advanced' })
    }
    $btnResume = $dash.FindName('BtnResumeRun')
    if ($null -ne $btnResume) {
        $btnResume.Add_Click({
            $list = $null
            try { if ($null -ne $script:Dash) { $list = $script:Dash.FindName('LstPreviousRuns') } } catch { }
            $sel = $null
            if ($null -ne $list) { $sel = $list.SelectedItem }
            if ($null -eq $sel -or -not $sel.RunId) {
                [System.Windows.MessageBox]::Show('Select a previous run first.', 'ScreenConnect Cleaner', 'OK', 'Information') | Out-Null
                return
            }
            Start-SccGuiJobWithToken -Token @{ Cancelled = $false; Workflow = (New-SccWorkflow -Mode Full -Resume -RunId $sel.RunId) } -JobName ('Resume ' + $sel.RunId)
        })
    }

    # ResumeRunId from the command line: preselect that run in the list.
    if ($ResumeRunId) {
        try {
            $list = $dash.FindName('LstPreviousRuns')
            if ($null -ne $list) {
                foreach ($item in @($list.Items)) {
                    if ($item.RunId -eq $ResumeRunId) { $list.SelectedItem = $item; break }
                }
            }
        } catch { }
    }

    # UI polls the active job via a DispatcherTimer (200ms). On the Linux/CI
    # side this code path is never reached (Start-SccApp requires WPF).
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $timer.Add_Tick({
        if ($null -ne $script:ActiveJob) {
            try { Update-SccJob -Handle $script:ActiveJob } catch { }
            $job = $script:ActiveJob
            $status = ('Running: ' + $job.Name)
            if ($job.Percent -gt 0) { $status += (' (' + $job.Percent + '%)') }
            Set-SccGuiStatus -Text $status
            if ($job._Done) {
                $final = $job.State
                $detail = ''
                if ($job.Error) { $detail = ([string]$job.Error).Trim() }
                elseif ($null -ne $job.Result -and $null -ne $job.Result.Status) { $detail = ('Workflow: ' + $job.Result.Status) }
                $msg = ('Job finished: ' + $final)
                if ($detail) { $msg += (' - ' + $detail) }
                Set-SccGuiStatus -Text $msg
                $awaitingReview = ($null -ne $job.Result -and $job.Result.Status -eq 'AwaitingReview')
                $failedJob = ($final -eq 'Failed')
                Reset-SccJob
                $script:ActiveJob = $null
                # Review gate: Full-mode run reached stage 3 with no plan.
                # Open the Findings window so the technician can review and
                # approve/execute (safety invariant #2 - nothing runs without
                # explicit confirmation).
                if ($awaitingReview) {
                    try { Show-SccFindingsWindow -Workflow $job.Result } catch { }
                }
                if ($failedJob) {
                    [System.Windows.MessageBox]::Show($msg, 'ScreenConnect Cleaner', 'OK', 'Warning') | Out-Null
                }
            }
        }
        # CI smoke-test hook: auto-close after AutoCloseSeconds.
        if ($null -ne $script:AutoCloseAt -and [datetime]::UtcNow -ge $script:AutoCloseAt) {
            $script:AutoCloseAt = $null
            try { if ($null -ne $script:MainWindow) { $script:MainWindow.Close() } } catch { }
        }
    })
    if ($AutoCloseSeconds -gt 0) {
        $script:AutoCloseAt = [datetime]::UtcNow.AddSeconds($AutoCloseSeconds)
    }
    $timer.Start()

    try {
        $null = $window.ShowDialog()
    } finally {
        try { $timer.Stop() } catch { }
        $script:ActiveJob = $null
        $script:Dash = $null
        $script:MainWindow = $null
        $script:AutoCloseAt = $null
        try { Reset-SccJob } catch { }
    }
}

# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

Export-ModuleMember -Function @(
    'New-SccWorkflow',
    'Start-SccWorkflow',
    'Step-SccWorkflow',
    'Get-SccNextStage',
    'Stop-SccWorkflow',
    'Invoke-SccGuiWorkflow',
    'Start-SccJob',
    'Update-SccJob',
    'Wait-SccJob',
    'Stop-SccJob',
    'Reset-SccJob',
    'Start-SccApp'
)
