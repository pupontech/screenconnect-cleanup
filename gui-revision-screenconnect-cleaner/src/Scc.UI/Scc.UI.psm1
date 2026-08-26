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


# Ensure Microsoft.PowerShell.Utility cmdlets (Get-Date, New-Object, ConvertTo-Json,
# Out-Null, Add-Member, etc.) are visible inside this module's session state on every
# host. Without this, module functions fail with CommandNotFoundException on Windows
# when the module is loaded through Pester or a nested session state.
$null = Import-Module -Name 'Microsoft.PowerShell.Utility' -ErrorAction SilentlyContinue

$script:CurrentWorkflow = $null
$script:ActiveJob = $null

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
    $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
    return ($raw | ConvertFrom-Json)
}

function Get-SccPlanFromRun {
    param($Workflow)
    if ($Workflow.PlanPath -and (Test-Path -Path $Workflow.PlanPath)) {
        return (ConvertFrom-SccJsonFile -Path $Workflow.PlanPath)
    }
    if ($Workflow.Run -and $Workflow.Run.RunDir -and (Test-Path -Path $Workflow.Run.RunDir)) {
        $candidate = Join-Path -Path $Workflow.Run.RunDir -ChildPath 'plan.json'
        if (Test-Path -Path $candidate) {
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
    param($Run, $Plan)
    Assert-SccBackendFn -Function 'Invoke-SccRemediation' -Module 'Scc.Remedy'
    if (Get-Command -Name Test-SccPlan -ErrorAction SilentlyContinue) {
        $null = Test-SccPlan -Run $Run -Plan $Plan
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
            # Without -Execute this is a dry run only (safe, non-destructive).
            $Workflow.Data.Remediation = Invoke-SccBackendRemediation -Run $Workflow.Run -Plan $plan
            $Stage.Detail = 'Remediation executed (dry-run unless plan carried -Execute)'
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
            $RunId = ('SC-' + (Get-Date -Format 'yyyyMMdd') + '-HOST-' + (Get-Date -Format 'HHmmss'))
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
        Step-SccWorkflow -Workflow $Workflow
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
    $runspaceToken = @{ Cancelled = $CancellationToken.Cancelled }

    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs

    $wrapper = @'
param($Token, $ScriptBlock)
$state = [System.Collections.Specialized.OrderedDictionary]::new()
$state['State'] = 'Running'
$state['Result'] = $null
$state['Error'] = $null
$state['Percent'] = 0
try {
    $result = & $ScriptBlock $Token
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

    $null = $ps.AddScript($wrapper).AddArgument($runspaceToken).AddArgument($ScriptBlock)
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
    # Force-clear any leaked job (e.g. between tests): stop + drain + dispose
    # the runspace, then remove it from the private store.
    [CmdletBinding()]
    param()

    foreach ($id in @($script:Jobs.Keys)) {
        $job = $script:Jobs[$id]
        try {
            if ($null -ne $job.PowerShell) {
                try { $job.PowerShell.Stop() } catch {}
                try { $null = $job.PowerShell.EndInvoke($job.Async) } catch {}
                # NOTE: do NOT call PowerShell/Runspace.Dispose() here. Disposing
                # a runspace that is still finalizing can corrupt the caller's
                # current scope variables (PowerShell host-state corruption),
                # which manifests as the caller's handle variable becoming null.
                # Leaving the disposed-by-GC runspace is safe; we just drop our
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
    [xml]$xaml = Get-Content -Path $Path
    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    return [System.Windows.Markup.XamlReader]::Load($reader)
}

function Start-SccApp {
    [CmdletBinding()]
    param(
        $Config,
        [string]$ResumeRunId
    )

    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        Add-Type -AssemblyName PresentationCore -ErrorAction Stop
        Add-Type -AssemblyName WindowsBase -ErrorAction Stop
    } catch {
        throw ('WPF is not available in this environment. ScreenConnect Cleaner requires Windows PowerShell 5.1 on a Windows desktop session. Use headless mode (Start-SccWorkflow) on this host. Detail: ' + $_.Exception.Message)
    }

    $dash = Import-SccXaml -Path (Get-SccViewPath -Name 'Dashboard')

    $window = [System.Windows.Window]::new()
    $window.Title = 'ScreenConnect Cleaner'
    $window.Width = 1200
    $window.Height = 800
    $window.Content = $dash

    # Wire action buttons (names defined in Dashboard.xaml). The background job
    # runs the workflow so the UI thread never blocks (ARCHITECTURE sec. 8).
    $btnFull = $dash.FindName('BtnFullInvestigation')
    if ($null -ne $btnFull) {
        $btnFull.Add_Click({
            $wf = New-SccWorkflow -Mode Full
            $null = Start-SccJob -ScriptBlock { param($t) Start-SccWorkflow -Workflow $t } -Name 'FullInvestigation' -CancellationToken $wf
        })
    }
    $btnDetect = $dash.FindName('BtnDetectionOnly')
    if ($null -ne $btnDetect) {
        $btnDetect.Add_Click({
            $wf = New-SccWorkflow -Mode DetectOnly
            $null = Start-SccJob -ScriptBlock { param($t) Start-SccWorkflow -Workflow $t } -Name 'DetectionOnly' -CancellationToken $wf
        })
    }
    $btnScan = $dash.FindName('BtnScanOnly')
    if ($null -ne $btnScan) {
        $btnScan.Add_Click({
            $wf = New-SccWorkflow -Mode ScanOnly
            $null = Start-SccJob -ScriptBlock { param($t) Start-SccWorkflow -Workflow $t } -Name 'ScanOnly' -CancellationToken $wf
        })
    }

    # UI polls the active job via a DispatcherTimer (200ms) on the Linux/CI
    # side this code path is never reached.
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $timer.Add_Tick({
        if ($null -ne $script:ActiveJob) { Update-SccJob -Handle $script:ActiveJob }
    })
    $timer.Start()

    $null = $window.ShowDialog()
    try { $timer.Stop() } catch {}
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
    'Start-SccJob',
    'Update-SccJob',
    'Wait-SccJob',
    'Stop-SccJob',
    'Reset-SccJob',
    'Start-SccApp'
)
