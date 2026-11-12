<#
  Gui.Core.psm1 - the logic behind the ScreenConnect Cleanup GUI. NO WPF TYPES HERE.

  The GUI is a third front end, not a third engine (docs/14-gui-architecture.md, rule 1).
  Everything in this module either
    * turns gui\steps.json + the technician's answers into the exact command lines that
      START-HERE.bat runs, in the same order (Get-GuiNextAction / Complete-GuiAction),
    * starts ONE child powershell.exe at a time and pumps its output without blocking
      (Start-GuiChild / Update-GuiChild / Send-GuiAnswer), or
    * reads artifacts the engine scripts already wrote (Get-GuiFindingsView and friends).
  It contains no detection, snapshot, removal, scanner, persistence or report logic.

  Because it has no WPF types it is tested headless (tests\gui\*). Windows PowerShell 5.1,
  pure ASCII, no BOM.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------------------
# Argument quoting
# ---------------------------------------------------------------------------------------

function ConvertTo-GuiArg {
    # One value -> one command-line token, quoted the way CommandLineToArgvW expects.
    # Paths contain spaces and parentheses; nothing is ever routed through cmd.exe.
    param([AllowEmptyString()][AllowNull()][string]$Value)
    if ($null -eq $Value -or $Value -eq '') { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $backslashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq [char]'\') { $backslashes++; continue }
        if ($ch -eq [char]'"') {
            [void]$sb.Append([string]('\' * ($backslashes * 2 + 1)))
            [void]$sb.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) { [void]$sb.Append([string]('\' * $backslashes)); $backslashes = 0 }
        [void]$sb.Append($ch)
    }
    if ($backslashes -gt 0) { [void]$sb.Append([string]('\' * ($backslashes * 2))) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-GuiArgString {
    param([string[]]$Values)
    return ((@($Values) | ForEach-Object { ConvertTo-GuiArg $_ }) -join ' ')
}

# ---------------------------------------------------------------------------------------
# Catalog and session
# ---------------------------------------------------------------------------------------

function Get-GuiCatalog {
    param([string]$Path = (Join-Path $PSScriptRoot 'steps.json'))
    $text = [IO.File]::ReadAllText($Path)
    return ($text | ConvertFrom-Json)
}

function Get-GuiModeInfo {
    param([Parameter(Mandatory = $true)][string]$Mode, $Catalog)
    if (-not $Catalog) { $Catalog = Get-GuiCatalog }
    $p = $Catalog.Modes.PSObject.Properties[$Mode]
    if (-not $p) { throw ('Unknown GUI mode: ' + $Mode) }
    return $p.Value
}

function New-GuiSession {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Full', 'Offline', 'Online', 'Stage', 'Detect')][string]$Mode,
        [Parameter(Mandatory = $true)][string]$ToolRoot,
        [string]$RitRoot = 'C:\RIT-SCC',
        [string]$ComputerName = $env:COMPUTERNAME,
        [hashtable]$Answers,
        # The window sets this: the run then stops at each "Ask" point of the catalog until the
        # technician's answer arrives through Set-GuiAnswer. Without it the batch file's
        # defaults apply (the headless parity tests rely on that).
        [switch]$Interactive
    )
    $catalog = Get-GuiCatalog
    $info = Get-GuiModeInfo -Mode $Mode -Catalog $catalog
    $root = $ToolRoot
    if (-not $root.EndsWith('\')) { $root += '\' }

    # Defaults are the batch file's defaults: scanners Y, review windows Y, AV uninstall N,
    # power repair N, GPO reset N, keep nothing (= remove all, the batch file's default).
    $merged = @{
        ScanKvrt = $true; ScanEset = $true; ScanMalwarebytes = $true; OpenReview = $true
        Avu = $false; PowerRepair = $false; ResetGpo = $false
        KeepIdentifiers = @()
    }
    if ($Answers) { foreach ($k in $Answers.Keys) { $merged[$k] = $Answers[$k] } }

    $phase = [string]$info.Phase
    $plan = New-Object System.Collections.ArrayList
    foreach ($step in @($catalog.Steps)) {
        if (@($step.Phases) -notcontains $phase) { continue }
        foreach ($call in @($step.Calls)) {
            $callPhases = $call.PSObject.Properties['Phases']
            if ($callPhases -and @($callPhases.Value) -notcontains $phase) { continue }
            $destructive = $false
            if ($step.PSObject.Properties['Destructive']) { $destructive = [bool]$step.Destructive }
            [void]$plan.Add([pscustomobject]@{
                    StepId = [string]$step.Id; StepTitle = [string]$step.Title; Group = [string]$step.Group
                    Destructive = $destructive; Call = $call
                })
        }
    }

    return [pscustomobject]@{
        Mode = $Mode; Phase = $phase; ToolRoot = $root; RitRoot = $RitRoot; ComputerName = $ComputerName
        RunRoot = ''; FindingsJson = ''; PriorFindings = ''
        PipeRc = 0; PowerRepairRan = $false; ReportRc = 0; ReportOpened = $false
        ScannerOnly = $false; Shared = $false; ShareReport = ''; SharePDir = ''
        Answers = $merged
        Interactive = [bool]$Interactive; Asked = @{}
        Plan = $plan; Index = 0
        Results = (New-Object System.Collections.ArrayList)
        Stopped = $false; StopMessage = ''; Started = (Get-Date).ToUniversalTime()
        Current = $null
    }
}

function Test-GuiModeNeedsRunRoot {
    param($Session)
    return ((Get-GuiModeInfo -Mode $Session.Mode).RunRoot -ne 'none')
}

function New-GuiRunRoot {
    # Same shape :new_run_root in START-HERE.bat creates: <RitRoot>\<PC>-<guid N>.
    param($Session)
    $p = Join-Path $Session.RitRoot ($Session.ComputerName + '-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $p -Force
    $Session.RunRoot = $p
    return $p
}

function Invoke-GuiCapture {
    # Runs a short helper the batch file also captures with FOR /F (Find-OfflineRun.ps1, the locked
    # run-folder command) and returns its exit code, stdout lines and stderr text. Both streams are
    # read asynchronously so neither can block the other; a helper that outlives the timeout is
    # killed (with its tree) and reported as exit -1, never waited on forever.
    param([Parameter(Mandatory = $true)][string]$Arguments, [hashtable]$Environment, [int]$TimeoutSeconds = 60)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path $PSHOME 'powershell.exe')
    $psi.Arguments = $Arguments
    if ($Environment) { foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[$k] = [string]$Environment[$k] } }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $p.StandardInput.Close()
    $code = -1
    if ($p.WaitForExit($TimeoutSeconds * 1000)) { $p.WaitForExit(); $code = $p.ExitCode }
    else { try { & taskkill.exe /PID $p.Id /T /F | Out-Null } catch { } }
    $out = ''; $err = ''
    if ($outTask.Wait(2000)) { $out = [string]$outTask.Result }
    if ($errTask.Wait(2000)) { $err = [string]$errTask.Result }
    return [pscustomobject]@{
        ExitCode = $code
        Lines = @(($out -replace [string][char]0xFEFF, '') -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
        Error = $err.Trim()
    }
}

function Find-GuiPriorRun {
    # Online half: the finished offline-half run for this PC, or $null. Mirrors the batch
    # file's :select_run_root: the same helper, called with no arguments, and the same
    # "run|findings" line.
    param($Session)
    $script = Join-Path $Session.ToolRoot 'tools\Find-OfflineRun.ps1'
    if (-not (Test-Path -LiteralPath $script)) { return $null }
    $lines = @((Invoke-GuiCapture -Arguments ('-NoProfile -ExecutionPolicy Bypass -File ' + (ConvertTo-GuiArg $script))).Lines)
    if ($lines.Count -eq 0) { return $null }
    $parts = $lines[$lines.Count - 1].Split('|')
    if ($parts.Count -lt 2) { return $null }
    $findings = $parts[1]
    if ($findings -eq 'NONE') { $findings = '' }
    return [pscustomobject]@{ RunRoot = $parts[0]; FindingsJson = $findings }
}

function Initialize-GuiRunRoot {
    # Binds the session to a run folder. Online: -Prior continues that run; without it (or
    # when none exists) this is a scanner-only run, exactly as the batch file does.
    param($Session, $Prior)
    $kind = (Get-GuiModeInfo -Mode $Session.Mode).RunRoot
    if ($kind -eq 'none') { return '' }
    if ($kind -eq 'prior-or-new' -and $Prior) {
        $Session.RunRoot = [string]$Prior.RunRoot
        $Session.FindingsJson = [string]$Prior.FindingsJson
        $Session.PriorFindings = [string]$Prior.FindingsJson
        return $Session.RunRoot
    }
    if ($kind -eq 'prior-or-new') { $Session.ScannerOnly = $true }
    if ($kind -eq 'new-locked') { return (New-GuiLockedRunRoot -Session $Session) }
    return (New-GuiRunRoot -Session $Session)
}

function New-GuiLockedRunRoot {
    # The offline half's run folder is created already LOCKED (administrators and SYSTEM write,
    # users read only), because the online half continues it later and Find-OfflineRun.ps1
    # trusts only locked folders. Same helper and the same command line as START-HERE.bat's
    # :new_run_root_locked, run in a child process (the GUI loads no engine module itself).
    # Fails closed: no folder means no run.
    param($Session)
    $cmd = "Import-Module (Join-Path `$env:SCC_DP0 'tools\RunRootSecurity.psm1'); New-SccProtectedRunRoot -Root '" + ([string]$Session.RitRoot).Replace("'", "''") + "'"
    $r = Invoke-GuiCapture -Arguments ('-NoProfile -ExecutionPolicy Bypass -Command ' + (ConvertTo-GuiArg $cmd)) -Environment @{ SCC_DP0 = $Session.ToolRoot }
    $path = $(if (@($r.Lines).Count -gt 0) { $r.Lines[@($r.Lines).Count - 1].Trim() } else { '' })
    if ($r.ExitCode -ne 0 -or -not $path -or -not (Test-Path -LiteralPath $path -PathType Container)) {
        $why = $(if ($r.Error) { $r.Error } elseif ($r.ExitCode -eq -1) { 'the helper timed out' } else { 'exit ' + $r.ExitCode })
        throw ('Could not create a locked run folder under ' + $Session.RitRoot + ': ' + $why)
    }
    $Session.RunRoot = $path
    return $path
}

# ---------------------------------------------------------------------------------------
# Token expansion and conditions
# ---------------------------------------------------------------------------------------

function Get-GuiShareTargets {
    # What the online half shares: the offline report.html and persistence results, unless the
    # after-scans report was rebuilt (step 9r), in which case those (batch: SCC_SHARE_REPORT / SCC_SHARE_PDIR).
    param($Session)
    $report = [string]$Session.ShareReport
    $pdir = [string]$Session.SharePDir
    if (-not $report) { $report = [string]$Session.RunRoot + '\report.html' }
    if (-not $pdir) { $pdir = [string]$Session.RunRoot + '\persistence' }
    return [pscustomobject]@{ Report = $report; PDir = $pdir }
}

function Expand-GuiTokens {
    param($Session, [string]$Text)
    $share = Get-GuiShareTargets -Session $Session
    # The online half's persistence check runs again after the scanners, into after-scans (batch :persist_after_scans).
    $persistDir = [string]$Session.RunRoot
    if ($Session.Phase -eq 'ONLINE') { $persistDir = [string]$Session.RunRoot + '\after-scans' }
    return $Text.Replace('{ToolRoot}', $Session.ToolRoot).Replace('{RunRoot}', [string]$Session.RunRoot).Replace('{FindingsJson}', [string]$Session.FindingsJson).Replace('{PipeRc}', [string]$Session.PipeRc).Replace('{PersistWorkDir}', $persistDir).Replace('{SharePDir}', $share.PDir).Replace('{ShareReport}', $share.Report)
}

function Resolve-GuiListToken {
    # Whole-element tokens that expand to zero or more arguments. Each mirrors one of the
    # SCC_* variables the batch file builds.
    param($Session, [string]$Name)
    $phase = $Session.Phase
    switch ($Name) {
        'PreflightArgs' { if ($phase -eq 'OFFLINE' -or $phase -eq 'DETECT') { return @('-SkipToolPack') }; return @() }
        'PersistArgs'   { if ($phase -eq 'OFFLINE' -or $phase -eq 'ONLINE') { return @('-InventorySectionTimeoutSeconds', '240', '-InventoryTotalTimeoutSeconds', '600') }; return @() }
        'AfterScansReportArgs' {
            # batch :online_report SCC_OR_ARGS - the removal manifest first, then the kept instances.
            $out = @()
            $m = $Session.RunRoot + '\removal-manifest.json'
            if (Test-Path -LiteralPath $m -PathType Leaf) { $out += @('-RemovalManifest', $m) }
            $k = $Session.RunRoot + '\kept-instances.json'
            if (Test-Path -LiteralPath $k -PathType Leaf) { $out += @('-KeptInstances', $k) }
            return $out
        }
        'SubmitArgs'    { if ($phase -eq 'OFFLINE') { return @('-NoUpload') }; return @() }
        'KeepArgs' {
            $ids = @($Session.Answers['KeepIdentifiers'] | Where-Object { $_ })
            if ($ids.Count -gt 0) { return @('-KeepIdentifier', ($ids -join ',')) }
            return @()
        }
        'KeptArg' {
            $f = $Session.RunRoot + '\kept-instances.json'
            if (Test-Path -LiteralPath $f -PathType Leaf) { return @('-KeptInstances', $f) }
            return @()
        }
        'ManifestArgs' {
            $f = $Session.RunRoot + '/removal-manifest.json'
            if (Test-Path -LiteralPath $f -PathType Leaf) { return @('-RemovalManifest', $f) }
            return @()
        }
        'GpoArgs' { if ([bool]$Session.Answers['ResetGpo']) { return @('-ResetLocalGpo') }; return @() }
        'ReportArg' {
            $f = (Get-GuiShareTargets -Session $Session).Report
            if (Test-Path -LiteralPath $f -PathType Leaf) { return @('-ReportHtml', $f) }
            return @()
        }
        default { throw ('Unknown list token: ' + $Name) }
    }
}

function Expand-GuiArgs {
    param($Session, $Template)
    $out = New-Object System.Collections.ArrayList
    foreach ($a in @($Template)) {
        $m = [regex]::Match([string]$a, '^\{@(\w+)\}$')
        if ($m.Success) { foreach ($x in @(Resolve-GuiListToken -Session $Session -Name $m.Groups[1].Value)) { [void]$out.Add([string]$x) } }
        else { [void]$out.Add((Expand-GuiTokens -Session $Session -Text ([string]$a))) }
    }
    return @($out.ToArray())
}

function Test-GuiCondition {
    param($Session, [string]$Condition)
    $i = $Condition.IndexOf(':')
    if ($i -lt 1) { throw ('Bad condition: ' + $Condition) }
    $kind = $Condition.Substring(0, $i)
    $arg = $Condition.Substring($i + 1)
    switch ($kind) {
        'Answer' { return [bool]$Session.Answers[$arg] }
        'Flag'   { return [bool]$Session.$arg }
        'Has'    { return (-not [string]::IsNullOrEmpty([string]$Session.$arg)) }
        'Not'    { return (-not [bool]$Session.$arg) }
        'Exists' {
            $p = Expand-GuiTokens -Session $Session -Text $arg
            if ([string]::IsNullOrWhiteSpace($p)) { return $false }
            return (Test-Path -LiteralPath $p -PathType Leaf)
        }
        default  { throw ('Unknown condition kind: ' + $kind) }
    }
}

function Get-GuiCallProp {
    param($Call, [string]$Name, $Default = $null)
    $p = $Call.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

# ---------------------------------------------------------------------------------------
# The state machine
# ---------------------------------------------------------------------------------------

function Add-GuiResult {
    param($Session, $Entry, [string]$Status, [string]$Message, $ExitCode = $null)
    $rec = [pscustomobject]@{
        StepId = $Entry.StepId; Title = $Entry.StepTitle
        Script = [string](Get-GuiCallProp $Entry.Call 'Script' (Get-GuiCallProp $Entry.Call 'Builtin' ''))
        Status = $Status; ExitCode = $ExitCode; Message = $Message
        Utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    }
    [void]$Session.Results.Add($rec)
    return $rec
}

function Set-GuiPipeRc {
    param($Session, [int]$Rc)
    if ($Session.PipeRc -eq 0) { $Session.PipeRc = $Rc }
}

function Invoke-GuiBeforeHook {
    param($Session, [string]$Name)
    switch ($Name) {
        'EnsureLogsDir' {
            $d = $Session.RunRoot + '\logs'
            if (-not (Test-Path -LiteralPath $d)) { $null = New-Item -ItemType Directory -Path $d -Force }
        }
        default { throw ('Unknown before-hook: ' + $Name) }
    }
}

function Find-GuiFindings {
    # Only the detect\ folder of THIS run is searched; historical findings never authorize
    # removal (batch file, step 4).
    param($Session)
    $detect = Join-Path $Session.RunRoot 'detect'
    $Session.FindingsJson = ''
    if (-not (Test-Path -LiteralPath $detect)) { return }
    $dirs = @(Get-ChildItem -LiteralPath $detect -Directory -Filter '*_*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    foreach ($d in $dirs) {
        $f = Join-Path $d.FullName 'findings.json'
        if (Test-Path -LiteralPath $f -PathType Leaf) { $Session.FindingsJson = $f; return }
    }
}

function Get-GuiNextAction {
    # Returns the next thing to do, or $null when the run is finished or stopped.
    # Calls whose condition is false are recorded as Skipped and passed over. Does not
    # advance past a returned action: call Complete-GuiAction with its exit code.
    param($Session)
    while ((-not $Session.Stopped) -and $Session.Index -lt $Session.Plan.Count) {
        $entry = $Session.Plan[$Session.Index]
        $call = $entry.Call
        $builtin = Get-GuiCallProp $call 'Builtin' $null
        $script = Get-GuiCallProp $call 'Script' $null
        $scriptPath = $null
        if ($script) { $scriptPath = Join-Path $Session.ToolRoot $script }

        # A decision the batch file asks the technician (what to keep, which scanners, ...). Only asked
        # when the call would otherwise run, i.e. every condition that does not depend on an answer holds.
        $ask = [string](Get-GuiCallProp $call 'Ask' '')
        if ($ask -and $Session.Interactive -and -not $Session.Asked.ContainsKey($ask)) {
            $pre = $true
            foreach ($cond in @(Get-GuiCallProp $call 'When' @())) {
                if (([string]$cond) -notlike 'Answer:*' -and -not (Test-GuiCondition -Session $Session -Condition ([string]$cond))) { $pre = $false; break }
            }
            if ($pre -and ((-not $scriptPath) -or (Test-Path -LiteralPath $scriptPath -PathType Leaf))) {
                $action = [pscustomobject]@{ Kind = 'Ask'; Ask = $ask; Index = $Session.Index; StepId = $entry.StepId; Title = $entry.StepTitle
                    Destructive = $entry.Destructive; Builtin = $null; ScriptPath = $scriptPath; Args = @(); Call = $call; Entry = $entry }
                $Session.Current = $action
                return $action
            }
        }

        $handleMissing = {
            $mode = [string](Get-GuiCallProp $call 'OnMissing' 'WarnSkip')
            $msg = [string](Get-GuiCallProp $call 'MissingMessage' ($script + ' missing - skipped.'))
            if ($mode -eq 'Stop') {
                [void](Add-GuiResult $Session $entry 'Failed' $msg)
                $Session.Stopped = $true; $Session.StopMessage = $msg
            } else {
                if ($mode -eq 'WarnPipeSkip') { Set-GuiPipeRc $Session 1 }
                [void](Add-GuiResult $Session $entry 'Warn' $msg)
                $Session.Index++
            }
        }

        $missingFirst = [bool](Get-GuiCallProp $call 'CheckMissingFirst' $false)
        if ($scriptPath -and $missingFirst -and -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
            & $handleMissing; continue
        }

        $ok = $true
        foreach ($cond in @(Get-GuiCallProp $call 'When' @())) {
            if (-not (Test-GuiCondition -Session $Session -Condition ([string]$cond))) { $ok = $false; break }
        }
        if (-not $ok) {
            [void](Add-GuiResult $Session $entry 'Skipped' ([string](Get-GuiCallProp $call 'SkipText' 'Not needed.')))
            $Session.Index++; continue
        }

        if ($scriptPath -and -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
            & $handleMissing; continue
        }

        $needsOk = $true
        foreach ($cond in @(Get-GuiCallProp $call 'Needs' @())) {
            if (-not (Test-GuiCondition -Session $Session -Condition ([string]$cond))) { $needsOk = $false; break }
        }
        if (-not $needsOk) {
            [void](Add-GuiResult $Session $entry 'Warn' ([string](Get-GuiCallProp $call 'NeedsText' 'A required file is missing.')))
            $Session.Index++; continue
        }

        $before = Get-GuiCallProp $call 'Before' $null
        if ($before) { Invoke-GuiBeforeHook -Session $Session -Name ([string]$before) }

        if ($builtin) {
            $action = [pscustomobject]@{ Kind = 'Builtin'; Index = $Session.Index; StepId = $entry.StepId; Title = $entry.StepTitle
                Destructive = $entry.Destructive; Builtin = [string]$builtin; ScriptPath = $null; Args = @(); Call = $call; Entry = $entry }
        } else {
            $action = [pscustomobject]@{ Kind = 'Run'; Index = $Session.Index; StepId = $entry.StepId; Title = $entry.StepTitle
                Destructive = $entry.Destructive; Builtin = $null; ScriptPath = $scriptPath
                Args = @(Expand-GuiArgs -Session $Session -Template (Get-GuiCallProp $call 'Args' @())); Call = $call; Entry = $entry }
        }
        $Session.Current = $action
        return $action
    }
    $Session.Current = $null
    return $null
}

function Set-GuiAnswer {
    # Records the technician's answer to an Ask action. Values keys are the Answers names:
    #   KeepSelection -> KeepIdentifiers (string[])        Scanners -> ScanKvrt, ScanEset, ScanMalwarebytes
    #   OpenReview -> OpenReview                            AvUninstall -> Avu
    #   PowerRepair -> PowerRepair, ResetGpo
    # Nothing is ever answered on the technician's behalf: the caller passes what was clicked.
    param($Session, [Parameter(Mandatory = $true)][string]$Ask, [hashtable]$Values)
    $allowed = @{
        KeepSelection = @('KeepIdentifiers'); Scanners = @('ScanKvrt', 'ScanEset', 'ScanMalwarebytes')
        OpenReview = @('OpenReview'); AvUninstall = @('Avu'); PowerRepair = @('PowerRepair', 'ResetGpo')
    }
    if (-not $allowed.ContainsKey($Ask)) { throw ('Unknown ask: ' + $Ask) }
    if ($null -eq $Values) { $Values = @{} }
    foreach ($k in @($Values.Keys)) {
        if ($allowed[$Ask] -notcontains $k) { throw ('Ask ' + $Ask + ' cannot set ' + $k) }
        $Session.Answers[$k] = $Values[$k]
    }
    $Session.Asked[$Ask] = $true
    $Session.Current = $null
}

function Complete-GuiAction {
    # Applies the batch file's rules for a finished call. Returns
    #   Status  Done | Warn | Failed | Resurrection
    #   Stop    $true when the run must not continue
    #   Message text for the technician
    param($Session, $Action, [int]$ExitCode, [string]$Message = '')

    $call = $Action.Call
    $rule = [string](Get-GuiCallProp $call 'OnNonZero' 'Ignore')
    $status = 'Done'; $text = $Message; $stop = $false
    $nonZeroText = [string](Get-GuiCallProp $call 'NonZeroText' '')

    if ($ExitCode -ne 0) {
        switch ($rule) {
            'Ignore' { }
            'Warn' { $status = 'Warn'; $text = ($(if ($nonZeroText) { $nonZeroText } else { 'Exited ' + $ExitCode + '.' }) + ' (exit ' + $ExitCode + ')') }
            'WarnPipe' { $status = 'Warn'; Set-GuiPipeRc $Session $ExitCode; $text = ($(if ($nonZeroText) { $nonZeroText } else { 'Exited ' + $ExitCode + '.' }) + ' (exit ' + $ExitCode + ')') }
            'Stop' { $status = 'Failed'; $stop = $true; $text = [string](Get-GuiCallProp $call 'StopMessage' ('Failed with exit ' + $ExitCode + '.')) }
            'Diff' {
                if ($ExitCode -ge 2) { $status = 'Warn'; $text = 'Diff failed to run.' }
                else { $status = 'Resurrection'; $text = 'RESURRECTION DETECTED - removed items came back. See snapshot_diff.json.' }
            }
        }
    } elseif ($rule -eq 'Diff') {
        $text = 'Diff clean - nothing resurrected.'
    }

    if ((-not $stop) -and $ExitCode -eq 0) {
        $req = Get-GuiCallProp $call 'RequireOutput' $null
        if ($req -and -not (Test-Path -LiteralPath (Expand-GuiTokens -Session $Session -Text ([string]$req)) -PathType Leaf)) {
            $status = 'Failed'; $stop = $true
            $text = [string](Get-GuiCallProp $call 'StopMessage' 'A required output file was not written.')
        }
    }

    $after = Get-GuiCallProp $call 'After' $null
    if ($after -and -not $stop) {
        switch ([string]$after) {
            'FindFindings' {
                Find-GuiFindings -Session $Session
                if ([string]::IsNullOrEmpty($Session.FindingsJson)) { $text = 'No findings.json found - removal and the report need it.'; if ($status -eq 'Done') { $status = 'Warn' } }
                else { $text = 'Latest findings: ' + $Session.FindingsJson }
            }
            'MarkPowerRepair' { $Session.PowerRepairRan = (Test-Path -LiteralPath ($Session.RunRoot + '\power-options-repair.json') -PathType Leaf) }
            'MarkReport' {
                $Session.ReportRc = $ExitCode
                $Session.ReportOpened = $false
                if (-not (Test-Path -LiteralPath ($Session.RunRoot + '/report.html') -PathType Leaf)) {
                    Set-GuiPipeRc $Session 1
                    $status = 'Warn'; $text = 'Report was not produced.'
                }
            }
            'MarkShared' { $Session.Shared = ($ExitCode -eq 0) }
            'MarkAfterScansReport' {
                # Like the batch file: the exit code is not checked, only whether the file exists.
                $f = $Session.RunRoot + '\report-after-scans.html'
                if (Test-Path -LiteralPath $f -PathType Leaf) {
                    $Session.ShareReport = $f
                    $Session.SharePDir = $Session.RunRoot + '\after-scans\persistence'
                    $status = 'Done'; $text = 'Sharing report-after-scans.html. The offline report.html is kept unchanged.'
                } else {
                    $status = 'Warn'; $text = 'Could not build the after-scans report - sharing the offline report instead.'
                }
            }
            default { throw ('Unknown after-hook: ' + $after) }
        }
    }

    if ($stop) { $Session.Stopped = $true; $Session.StopMessage = $text }
    [void](Add-GuiResult $Session $Action.Entry $status $text $ExitCode)
    $Session.Index = $Action.Index + 1
    $Session.Current = $null
    return [pscustomobject]@{ Status = $status; Stop = $stop; Message = $text; ExitCode = $ExitCode; StepId = $Action.StepId }
}

function Get-GuiFinalStatus {
    # The run's final status is the first non-zero code, as PIPE_RC is in the batch file.
    param($Session)
    return [int]$Session.PipeRc
}

function Invoke-GuiBuiltin {
    # The few things the batch file does itself rather than through a script: open the
    # report and leave a copy on the Desktop. Returns an exit code (0 = fine).
    param($Session, $Action, [switch]$NoOpen, [string]$DesktopDir = '')
    $report = $Session.RunRoot + '/report.html'
    switch ($Action.Builtin) {
        'OpenReportAndDesktopCopy' {
            if ($NoOpen) { $Session.ReportOpened = $true; return 0 }
            $rc = 0
            try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"' + ($report -replace '/', '\') + '"') } catch { }
            try { Start-Process -FilePath ($report -replace '/', '\'); $Session.ReportOpened = $true } catch { $Session.ReportOpened = $false }
            try {
                $d = $DesktopDir
                if (-not $d) { $d = [Environment]::GetFolderPath('Desktop') }
                if (-not $d) { $d = Join-Path $env:USERPROFILE 'Desktop' }
                Copy-Item -LiteralPath ($report -replace '/', '\') -Destination (Join-Path $d 'report.html') -Force -ErrorAction Stop
            } catch { $rc = 1 }
            return $rc
        }
        'DesktopCopyRefresh' {
            if ($NoOpen) { return 0 }
            try {
                $d = $DesktopDir
                if (-not $d) { $d = [Environment]::GetFolderPath('Desktop') }
                if (-not $d) { $d = Join-Path $env:USERPROFILE 'Desktop' }
                # The share adds the paste link to the report it shared (the after-scans one when it was rebuilt).
                Copy-Item -LiteralPath (Get-GuiShareTargets -Session $Session).Report -Destination (Join-Path $d 'report.html') -Force -ErrorAction Stop
                return 0
            } catch { return 1 }
        }
        default { throw ('Unknown builtin: ' + $Action.Builtin) }
    }
}

# ---------------------------------------------------------------------------------------
# Console encoding (spike S2: Windows PowerShell 5.1 corrupts redirected stdin on code page 65001)
# ---------------------------------------------------------------------------------------

function Set-GuiConsoleEncoding {
    # A redirected powershell.exe child that inherits a UTF-8 (65001) console puts a byte
    # order mark in front of what Read-Host returns, so "y" arrives as U+FEFF + "y" and the
    # engine's y/N loop never accepts it. OEM code pages (437, 862) are clean. Windows 11's
    # "UTF-8 for worldwide language support" makes 65001 a real field case, so the GUI
    # switches the shared console to 437 for its lifetime and restores it on exit.
    $saved = [pscustomobject]@{ In = $null; Out = $null; Changed = $false }
    try {
        $saved.In = [Console]::InputEncoding
        $saved.Out = [Console]::OutputEncoding
        if ($saved.In.CodePage -eq 65001 -or $saved.Out.CodePage -eq 65001) {
            $e = [Text.Encoding]::GetEncoding(437)
            [Console]::InputEncoding = $e
            [Console]::OutputEncoding = $e
            $saved.Changed = $true
        }
    } catch { }
    return $saved
}

function Restore-GuiConsoleEncoding {
    param($Saved)
    if ($Saved -and $Saved.Changed) {
        try { [Console]::InputEncoding = $Saved.In; [Console]::OutputEncoding = $Saved.Out } catch { }
    }
}

# ---------------------------------------------------------------------------------------
# One child process at a time
# ---------------------------------------------------------------------------------------

function Start-GuiChild {
    param([Parameter(Mandatory = $true)][string]$ScriptPath, [string[]]$ArgumentList, [string]$WorkingDirectory)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path $PSHOME 'powershell.exe')
    $argText = '-NoProfile -ExecutionPolicy Bypass -File ' + (ConvertTo-GuiArg $ScriptPath)
    if (@($ArgumentList).Count -gt 0) { $argText += ' ' + (ConvertTo-GuiArgString $ArgumentList) }
    $psi.Arguments = $argText
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $enc = [Console]::OutputEncoding
    $psi.StandardOutputEncoding = $enc
    $psi.StandardErrorEncoding = $enc
    if ($WorkingDirectory -and (Test-Path -LiteralPath $WorkingDirectory)) { $psi.WorkingDirectory = $WorkingDirectory }

    $p = [System.Diagnostics.Process]::Start($psi)
    $outBuf = New-Object char[] 4096
    $errBuf = New-Object char[] 4096
    return [pscustomobject]@{
        Process = $p; CommandLine = ($psi.FileName + ' ' + $argText)
        OutBuf = $outBuf; ErrBuf = $errBuf
        OutTask = $p.StandardOutput.ReadAsync($outBuf, 0, $outBuf.Length)
        ErrTask = $p.StandardError.ReadAsync($errBuf, 0, $errBuf.Length)
        OutEof = $false; ErrEof = $false
        Tail = ''; ErrTail = ''
        PendingLines = (New-Object System.Collections.ArrayList)
        Transcript = (New-Object System.Text.StringBuilder)
        StartedUtc = (Get-Date).ToUniversalTime(); LastOutputUtc = (Get-Date).ToUniversalTime(); ExitedUtc = $null
        DismissedTail = ''; DismissedUtc = $null; Finished = $false; ExitCode = $null
    }
}

function Add-GuiChildText {
    param($Child, [string]$Text, [bool]$IsError)
    if ([string]::IsNullOrEmpty($Text)) { return }
    $Text = $Text.Replace([string][char]0xFEFF, '').Replace("`r`n", "`n").Replace("`r", "`n")
    [void]$Child.Transcript.Append($Text)
    $Child.LastOutputUtc = (Get-Date).ToUniversalTime()
    $prefix = ''
    if ($IsError) { $combined = $Child.ErrTail + $Text; $prefix = '[stderr] ' } else { $combined = $Child.Tail + $Text }
    $parts = $combined.Split([char]"`n")
    for ($i = 0; $i -lt $parts.Length - 1; $i++) { [void]$Child.PendingLines.Add($prefix + $parts[$i]) }
    if ($IsError) { $Child.ErrTail = $parts[$parts.Length - 1] } else { $Child.Tail = $parts[$parts.Length - 1] }
}

function Receive-GuiChildStream {
    param($Child, [bool]$IsError)
    if ($IsError) { $task = $Child.ErrTask; $buf = $Child.ErrBuf; $reader = $Child.Process.StandardError }
    else { $task = $Child.OutTask; $buf = $Child.OutBuf; $reader = $Child.Process.StandardOutput }
    $eof = $(if ($IsError) { $Child.ErrEof } else { $Child.OutEof })
    while ((-not $eof) -and $task.IsCompleted) {
        $n = 0
        if (-not $task.IsFaulted -and -not $task.IsCanceled) { $n = $task.Result }
        if ($n -le 0) { $eof = $true; break }
        Add-GuiChildText -Child $Child -Text (New-Object string -ArgumentList @(, $buf[0..($n - 1)])) -IsError $IsError
        $task = $reader.ReadAsync($buf, 0, $buf.Length)
    }
    if ($IsError) { $Child.ErrTask = $task; $Child.ErrEof = $eof } else { $Child.OutTask = $task; $Child.OutEof = $eof }
}

function Update-GuiChild {
    # Call from the UI timer (or a loop). Never blocks. Returns the new complete lines and,
    # once the process has exited and its output is drained, Exited = $true and ExitCode.
    param($Child)
    Receive-GuiChildStream -Child $Child -IsError $false
    Receive-GuiChildStream -Child $Child -IsError $true

    $exited = $false
    if ($Child.Process.HasExited) {
        if (-not $Child.ExitedUtc) { $Child.ExitedUtc = (Get-Date).ToUniversalTime() }
        # A scanner window the child started can inherit the pipe and keep it open after the
        # child is gone, so EOF is not awaited forever: 1.5 s of grace, then stop waiting.
        $grace = ((Get-Date).ToUniversalTime() - $Child.ExitedUtc).TotalMilliseconds
        if (($Child.OutEof -and $Child.ErrEof) -or $grace -gt 1500) { $exited = $true }
    }
    if ($exited -and -not $Child.Finished) {
        if ($Child.Tail -ne '') { [void]$Child.PendingLines.Add($Child.Tail); $Child.Tail = '' }
        if ($Child.ErrTail -ne '') { [void]$Child.PendingLines.Add('[stderr] ' + $Child.ErrTail); $Child.ErrTail = '' }
        $Child.Finished = $true
        $Child.ExitCode = [int]$Child.Process.ExitCode
    }
    $lines = @($Child.PendingLines.ToArray())
    $Child.PendingLines.Clear()
    return [pscustomobject]@{ Lines = $lines; Exited = $Child.Finished; ExitCode = $Child.ExitCode }
}

function Send-GuiAnswer {
    # Writes one answer line to the child's stdin as RAW BYTES in the console's own code
    # page (no byte order mark, spike S2). The caller must have shown a dialog that named
    # the thing being approved and must pass the technician's own choice.
    param($Child, [AllowEmptyString()][string]$Text)
    $enc = [Console]::InputEncoding
    $bytes = $enc.GetBytes($Text + "`r`n")
    $s = $Child.Process.StandardInput.BaseStream
    $s.Write($bytes, 0, $bytes.Length)
    $s.Flush()
    [void]$Child.Transcript.Append("`n[GUI sent answer: " + $(if ($Text -eq '') { '(empty line)' } else { $Text }) + "]`n")
    [void]$Child.PendingLines.Add('[GUI sent answer: ' + $(if ($Text -eq '') { '(empty line)' } else { $Text }) + ']')
    $Child.Tail = ''
    $Child.LastOutputUtc = (Get-Date).ToUniversalTime()
}

function Stop-GuiChild {
    # Ends a running step. By default the whole tree goes (a read-only step's helpers have no reason
    # to outlive it). -KeepDescendants ends only the step's own powershell.exe: closing the window
    # while a scanner is open must not close the scanner the technician is driving (design 7).
    param($Child, [switch]$KeepDescendants)
    if (-not $Child -or $Child.Process.HasExited) { return }
    if ($KeepDescendants) { try { $Child.Process.Kill() } catch { }; return }
    try { & taskkill.exe /PID $Child.Process.Id /T /F | Out-Null } catch { try { $Child.Process.Kill() } catch { } }
}

# ---------------------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------------------

function Get-GuiPromptTable {
    # Questions an engine script asks with Read-Host. A prompt is recognised when the unfinished
    # output line is exactly one of its Needles (the exact text the script prints). Under
    # redirected stdin Windows PowerShell 5.1 does NOT print Read-Host's own prompt argument
    # (spike S2), so every script listed here prints its prompt itself with Write-Host -NoNewline;
    # tests\gui\Test-GuiPromptContract.ps1 proves each one still does.
    # Accept / Refuse are the exact lines sent to the script. Refuse is also what closing a
    # dialog with the window X sends (4.3 rule 2): never yes.
    $rows = @(
        [pscustomobject]@{ Id = 'LowDisk'; Needles = @('Continue anyway? [y/N]')
            Scripts = @('preflight.ps1', 'Invoke-ReviewAndRemove.ps1'); Accept = 'y'; Refuse = 'n' }
        [pscustomobject]@{ Id = 'UacDisabled'; Needles = @('Type Y once UAC is enabled, or F to force-continue with UAC disabled')
            Scripts = @('preflight.ps1'); Accept = 'Y'; Force = 'F'; Refuse = '' }
        [pscustomobject]@{ Id = 'RemoveConfirm'; Needles = @('Remove all detected ScreenConnect instances? [y/N]', 'Remove the instances that are NOT kept? [y/N]')
            Scripts = @('Invoke-ReviewAndRemove.ps1'); Accept = 'y'; Refuse = 'n' }
        [pscustomobject]@{ Id = 'MbInstallDone'; Needles = @('When installation is finished, type DONE (anything else cancels this scanner step)')
            Scripts = @('Invoke-GUIScanner.ps1'); Accept = 'DONE'; Refuse = 'CANCEL' }
        [pscustomobject]@{ Id = 'MbScanDone'; Needles = @('When the Malwarebytes scan is finished and its window is closed, type DONE (anything else cancels this scanner step)')
            Scripts = @('Invoke-GUIScanner.ps1'); Accept = 'DONE'; Refuse = 'CANCEL' }
        [pscustomobject]@{ Id = 'PersistIndices'; Needles = @('Enter comma-separated candidate indices')
            Scripts = @('Persistence.Removal.psm1'); Accept = $null; Refuse = '' }
        [pscustomobject]@{ Id = 'PersistRemove'; Needles = @('Type REMOVE to confirm these exact targets')
            Scripts = @('Persistence.Removal.psm1'); Accept = $null; Refuse = '' }
    )
    return $rows
}

function Test-GuiPromptMatch {
    # True when the unfinished line is exactly one of the row's prompt texts.
    param($Row, [string]$Text)
    foreach ($n in @($Row.Needles)) { if ($Text -ceq $n) { return $true } }
    return $false
}

function Get-GuiPendingPrompt {
    # Looks at the UNFINISHED output line (the prompt is printed with -NoNewline). Known
    # prompts match the table. Anything else that sits unfinished and quiet for 5 seconds
    # becomes a generic "the tool is waiting for an answer" box (4.3 rule 4). Complete lines
    # never trigger the generic box, so a long quiet scan does not look like a question.
    # A box the technician marked "not a question" stays away for -RepeatSeconds; if the tool
    # is still sitting on the same text after that, it really is waiting, so it comes back
    # (a script blocked on Read-Host would otherwise wait forever).
    param($Child, [int]$QuietSeconds = 5, [int]$RepeatSeconds = 60)
    if ($Child.Finished) { return $null }
    $t = ([string]$Child.Tail).Trim()
    if ($t -eq '') { return $null }
    foreach ($row in (Get-GuiPromptTable)) {
        if (Test-GuiPromptMatch -Row $row -Text $t) {
            return [pscustomobject]@{ Kind = 'Known'; Row = $row; Text = $t }
        }
    }
    $now = (Get-Date).ToUniversalTime()
    $quiet = ($now - $Child.LastOutputUtc).TotalSeconds
    if ($quiet -lt $QuietSeconds) { return $null }
    if ($Child.DismissedTail -eq $t -and $Child.DismissedUtc -and ($now - $Child.DismissedUtc).TotalSeconds -lt $RepeatSeconds) { return $null }
    return [pscustomobject]@{ Kind = 'Unknown'; Row = $null; Text = $t }
}

function Set-GuiPromptDismissed {
    # The technician said the unfinished line is "not a question": stay quiet about it for a while.
    param($Child, [string]$Text)
    $Child.DismissedTail = $Text
    $Child.DismissedUtc = (Get-Date).ToUniversalTime()
}

function Get-GuiShareUrl {
    # The paste link the report share printed (Submit-ConnectWiseReport.ps1: "MICROBIN UPLOAD: <url>").
    param([string[]]$Lines)
    foreach ($l in @($Lines)) {
        $m = [regex]::Match([string]$l, '^\s*MICROBIN UPLOAD:\s*(\S+)\s*$')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    return ''
}

# ---------------------------------------------------------------------------------------
# Artifact readers (read-only; tolerate missing or half-written files)
# ---------------------------------------------------------------------------------------

function Read-GuiJson {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Ok = $false; Data = $null; Error = 'not available yet' }
    }
    try {
        $text = [IO.File]::ReadAllText($Path)
        if ([string]::IsNullOrWhiteSpace($text)) { return [pscustomobject]@{ Ok = $false; Data = $null; Error = 'file is empty' } }
        return [pscustomobject]@{ Ok = $true; Data = ($text | ConvertFrom-Json); Error = '' }
    } catch {
        return [pscustomobject]@{ Ok = $false; Data = $null; Error = ('could not be read: ' + $_.Exception.Message) }
    }
}

function Get-GuiProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-GuiItems {
    # The single-element array trap: a one-item JSON array can arrive as a bare object, and an
    # empty object means none.
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    if ($Value -is [pscustomobject] -and @($Value.PSObject.Properties).Count -eq 0) { return @() }
    return @($Value)
}

function Get-GuiFindingsView {
    # What panel 5 shows for each ScreenConnect instance. The relay host is the decision key
    # and is shown as plain data: this reader never labels a host safe, known or suspicious
    # (design decision D4).
    param([string]$Path)
    $view = [pscustomobject]@{
        Available = $false; Error = ''; Path = $Path; ComputerName = ''; GeneratedUtc = ''
        Instances = @(); OtherTargets = @(); ParseIssueCount = 0; HistoricalCount = 0
    }
    $r = Read-GuiJson -Path $Path
    if (-not $r.Ok) { $view.Error = $r.Error; return $view }
    $f = $r.Data
    $view.Available = $true
    $view.ComputerName = [string](Get-GuiProp $f 'ComputerName')
    $view.GeneratedUtc = [string](Get-GuiProp $f 'GeneratedUtc')
    $sc = Get-GuiProp $f 'ScreenConnect'
    $raw = @(ConvertTo-GuiItems (Get-GuiProp $sc 'Instances'))
    $view.ParseIssueCount = @(ConvertTo-GuiItems (Get-GuiProp $sc 'ParseIssues')).Count
    $view.HistoricalCount = @(ConvertTo-GuiItems (Get-GuiProp $sc 'Historical')).Count

    $items = New-Object System.Collections.ArrayList
    $n = 0
    foreach ($inst in $raw) {
        $n++
        $id = Get-GuiProp $inst 'Identifier'
        if (-not $id) { $id = Get-GuiProp $inst 'Key' }
        if (-not $id) { $id = '(unidentified)' }
        $hostName = [string](Get-GuiProp $inst 'RelayHost')
        $port = Get-GuiProp $inst 'RelayPort'
        $relay = $hostName
        if ($hostName -and $port) { $relay = $hostName + ':' + $port }
        $file = Get-GuiProp $inst 'File'
        [void]$items.Add([pscustomobject]@{
                Number = $n; Identifier = [string]$id
                Relay = $relay; RelayHost = $hostName; RelayPort = [string]$port
                SessionType = [string](Get-GuiProp $inst 'SessionType')
                ServiceName = [string](Get-GuiProp $inst 'ServiceName'); ServiceState = [string](Get-GuiProp $inst 'ServiceState')
                SignatureStatus = [string](Get-GuiProp $file 'SignatureStatus'); SignerSubject = [string](Get-GuiProp $file 'SignerSubject')
                InstalledUtc = [string](Get-GuiProp $inst 'InstallDirCreatedUtc'); InstallDir = [string](Get-GuiProp $inst 'InstallDir')
                KeepSelectable = $true
            })
    }
    # -KeepIdentifier matches by identifier, case-insensitively. An unidentified or repeated
    # identifier would match more than one card, so those cannot be kept one at a time.
    $groups = @{}
    foreach ($it in $items) { $k = $it.Identifier.ToLowerInvariant(); if ($groups.ContainsKey($k)) { $groups[$k]++ } else { $groups[$k] = 1 } }
    foreach ($it in $items) {
        if ($it.Identifier -eq '(unidentified)' -or $groups[$it.Identifier.ToLowerInvariant()] -gt 1 -or $it.Identifier.Contains(',')) { $it.KeepSelectable = $false }
    }
    $view.Instances = @($items.ToArray())

    $others = New-Object System.Collections.ArrayList
    foreach ($t in @(ConvertTo-GuiItems (Get-GuiProp $f 'OtherTargets'))) {
        $hits = @(ConvertTo-GuiItems (Get-GuiProp $t 'Hits'))
        if ($hits.Count -eq 0) { continue }
        [void]$others.Add([pscustomobject]@{ Name = [string](Get-GuiProp $t 'Name'); Count = $hits.Count
                Hits = @($hits | ForEach-Object { ([string](Get-GuiProp $_ 'Kind') + ' ' + [string](Get-GuiProp $_ 'Name') + ' ' + [string](Get-GuiProp $_ 'Path')).Trim() }) })
    }
    $view.OtherTargets = @($others.ToArray())
    return $view
}

function Get-GuiScannerResult {
    # Only Malwarebytes gets a result file in the guided path (START-HERE.bat passes
    # -ResultPath for it alone); KVRT and ESET have the exit code and nothing else.
    param([string]$RunRoot, [string]$Scanner)
    $path = Join-Path $RunRoot ('logs\scanner-' + $Scanner + '-result.json')
    $r = Read-GuiJson -Path $path
    if (-not $r.Ok) { return [pscustomobject]@{ Available = $false; Error = $r.Error; Data = $null } }
    return [pscustomobject]@{ Available = $true; Error = ''; Data = $r.Data }
}

function Get-GuiPersistenceView {
    # The persistence results the run wrote: persistence\ (offline half, full run) or
    # after-scans\persistence\ (the online half's second check). Heuristic matches, not verdicts.
    param([string]$RunRoot, [string]$SubDir = 'persistence')
    $dir = Join-Path $RunRoot $SubDir
    $inv = Read-GuiJson -Path (Join-Path $dir 'inventory.json')
    $res = Read-GuiJson -Path (Join-Path $dir 'result.json')
    $view = [pscustomobject]@{ Available = $inv.Ok; Error = $inv.Error; Status = ''; RunStatus = ''; Findings = @(); Dir = $dir }
    if ($inv.Ok) {
        $view.Status = [string](Get-GuiProp $inv.Data 'Status')
        $view.Findings = @(ConvertTo-GuiItems (Get-GuiProp $inv.Data 'Findings'))
    }
    if ($res.Ok) { $view.RunStatus = [string](Get-GuiProp $res.Data 'Status') }
    return $view
}

function Get-GuiDiffView {
    param([string]$RunRoot)
    $r = Read-GuiJson -Path (Join-Path $RunRoot 'snapshot_diff.json')
    return [pscustomobject]@{ Available = $r.Ok; Error = $r.Error; Data = $r.Data }
}

function Get-GuiReportInfo {
    param([string]$RunRoot)
    $report = Join-Path $RunRoot 'report.html'
    $zip = Join-Path $RunRoot 'connectwise-report.zip'
    return [pscustomobject]@{
        ReportPath = $report; ReportExists = (Test-Path -LiteralPath $report -PathType Leaf)
        ZipPath = $zip; ZipExists = (Test-Path -LiteralPath $zip -PathType Leaf)
        OfflineMarker = (Test-Path -LiteralPath (Join-Path $RunRoot 'phase-offline.json') -PathType Leaf)
        OnlineMarker = (Test-Path -LiteralPath (Join-Path $RunRoot 'phase-online.json') -PathType Leaf)
    }
}

# ---------------------------------------------------------------------------------------
# Display-only session file (never read to decide whether a step may run, G6)
# ---------------------------------------------------------------------------------------

function Save-GuiSession {
    # Returns $true when written (or when there is no run folder to write to), $false when the write
    # failed, so the window can say so once. The file is display data, so a failure stops nothing.
    param($Session)
    if ([string]::IsNullOrEmpty($Session.RunRoot) -or -not (Test-Path -LiteralPath $Session.RunRoot)) { return $true }
    try {
        $doc = [ordered]@{
            Note = 'Display data written by the GUI. Nothing reads this file to decide whether a step may run.'
            Mode = $Session.Mode; ComputerName = $Session.ComputerName; RunRoot = $Session.RunRoot
            FindingsJson = $Session.FindingsJson; FinalStatus = (Get-GuiFinalStatus $Session)
            Stopped = [bool]$Session.Stopped; StopMessage = $Session.StopMessage
            Steps = @($Session.Results | ForEach-Object { [ordered]@{ Step = $_.StepId; Title = $_.Title; Status = $_.Status; ExitCode = $_.ExitCode; Message = $_.Message; Utc = $_.Utc } })
        }
        ($doc | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $Session.RunRoot 'gui-session.json') -Encoding UTF8 -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Get-GuiWindowModes {
    # The modes the window offers, in catalog order, with their labels (steps.json "Window": true).
    $catalog = Get-GuiCatalog
    $out = @()
    foreach ($p in $catalog.Modes.PSObject.Properties) {
        $w = $p.Value.PSObject.Properties['Window']
        if ($w -and [bool]$w.Value) { $out += [pscustomobject]@{ Name = $p.Name; Label = [string]$p.Value.Label } }
    }
    return $out
}

Export-ModuleMember -Function `
    ConvertTo-GuiArg, ConvertTo-GuiArgString, Get-GuiCatalog, Get-GuiModeInfo, New-GuiSession, `
    Test-GuiModeNeedsRunRoot, New-GuiRunRoot, Find-GuiPriorRun, Initialize-GuiRunRoot, `
    Expand-GuiTokens, Expand-GuiArgs, Test-GuiCondition, Get-GuiNextAction, Set-GuiAnswer, Complete-GuiAction, `
    Get-GuiFinalStatus, Invoke-GuiBuiltin, Find-GuiFindings, `
    Set-GuiConsoleEncoding, Restore-GuiConsoleEncoding, `
    Start-GuiChild, Update-GuiChild, Send-GuiAnswer, Stop-GuiChild, `
    Get-GuiPromptTable, Test-GuiPromptMatch, Get-GuiPendingPrompt, Set-GuiPromptDismissed, Get-GuiShareUrl, `
    Read-GuiJson, ConvertTo-GuiItems, Get-GuiFindingsView, Get-GuiScannerResult, Get-GuiPersistenceView, Get-GuiDiffView, Get-GuiReportInfo, `
    Save-GuiSession, Get-GuiWindowModes
