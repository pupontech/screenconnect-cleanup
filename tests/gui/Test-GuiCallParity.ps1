<#
  Test-GuiCallParity.ps1 - THE acceptance test for the GUI (docs/14-gui-architecture.md, sec. 9).

  The GUI is a third front end, not a third engine, so it must make the same script calls as
  START-HERE.bat: same scripts, same arguments, same order. This test proves it.

  It reuses the stub harness of tests\Test-PhaseSplit.ps1 (every .ps1 in a COPY of the tool is
  replaced by a stub that records "script|arguments" and creates the one file the next step
  needs). That harness is not copied here: its functions are pulled out of Test-PhaseSplit.ps1
  with the PowerShell parser, so the two cannot drift apart.

  For each scenario the batch file is run against stubs, then Gui.Core drives a fresh set of
  stubs headless (no window), and the two traces must be identical. It also covers what the
  batch file does when a step fails, and a tool folder with spaces and parentheses in its name.

  Nothing real runs: no elevation, no detection, no removal, no network, no C:\RIT-SCC (run
  folders go to a temp directory), no Desktop write. Needs no admin.

  Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File tests\gui\Test-GuiCallParity.ps1
  Windows PowerShell 5.1, pure ASCII, no BOM. Exit 0 = all checks passed.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch]$KeepWork
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$work = Join-Path $env:TEMP ('scc-gui-parity-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force
$script:Failures = New-Object System.Collections.ArrayList
$script:Passes = 0
function Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passes++; Write-Host ('  [pass] ' + $Message) -ForegroundColor Green }
    else { [void]$script:Failures.Add($Message); Write-Host ('  [FAIL] ' + $Message) -ForegroundColor Red }
}

# ---- pull the batch harness out of Test-PhaseSplit.ps1 (no copy, no drift) -----------------
$splitPath = Join-Path $ToolRoot 'tests\Test-PhaseSplit.ps1'
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($splitPath, [ref]$tokens, [ref]$errs)
if (@($errs).Count -gt 0) { throw 'Test-PhaseSplit.ps1 does not parse.' }
$stubAssign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$stubText' }, $true)
if (-not $stubAssign) { throw 'Could not find $stubText in Test-PhaseSplit.ps1.' }
Invoke-Expression $stubAssign.Extent.Text
# The stubs retry a locked trace file 5 times; the hidden Keep-Awake stub of the batch run races them. Retry far longer.
$stubText = $stubText.Replace('$try -lt 5', '$try -lt 200')
# Every top-level function the file defines (New-Harness needs helpers such as Disable-ReportOpen,
# and a new helper added later must not silently go missing here).
$harnessFns = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })
foreach ($need in 'New-Harness', 'Invoke-Launcher', 'New-FlagWrapper', 'Has', 'CountOf', 'Normalize') {
    if (-not ($harnessFns | Where-Object { $_.Name -eq $need })) { throw ('Could not find function ' + $need + ' in Test-PhaseSplit.ps1.') }
}
foreach ($def in $harnessFns) { if ($def.Name -ne 'Check') { Invoke-Expression $def.Extent.Text } }

Import-Module (Join-Path $ToolRoot 'gui\Gui.Core.psm1') -Force
$consoleSaved = Set-GuiConsoleEncoding

# ---- headless driver: the same loop the window runs, minus the window ----------------------
function Invoke-GuiHeadless {
    param($Session, [string]$DesktopDir, [string]$Tag)
    $trace = Join-Path $work ($Tag + '.trace')
    Set-Content -LiteralPath $trace -Value '' -Encoding ASCII
    $env:SCC_TRACE = $trace
    $guard = 0
    while ($true) {
        $a = Get-GuiNextAction -Session $Session
        if (-not $a) { break }
        $guard++; if ($guard -gt 80) { throw 'Headless run did not end.' }
        if ($a.Kind -eq 'Builtin') {
            $rc = Invoke-GuiBuiltin -Session $Session -Action $a -NoOpen -DesktopDir $DesktopDir
            [void](Complete-GuiAction -Session $Session -Action $a -ExitCode $rc)
            continue
        }
        $child = Start-GuiChild -ScriptPath $a.ScriptPath -ArgumentList $a.Args -WorkingDirectory $Session.ToolRoot
        $deadline = (Get-Date).AddSeconds(120)
        do { Start-Sleep -Milliseconds 60; $u = Update-GuiChild -Child $child } until ($u.Exited -or (Get-Date) -gt $deadline)
        if (-not $u.Exited) { Stop-GuiChild $child; throw ('Child did not finish: ' + $a.ScriptPath) }
        [void](Complete-GuiAction -Session $Session -Action $a -ExitCode $u.ExitCode)
    }
    $lines = @(Get-Content -LiteralPath $trace | Where-Object { $_ -and $_ -notlike 'Keep-Awake.ps1|*' })
    return [pscustomobject]@{ Trace = $lines }
}

function Get-BatTrace {
    # The batch file's own battery check belongs to the launcher, not to the step sequence.
    param($Run)
    return @($Run.Trace | Where-Object { $_ -notlike 'Confirm-OnBattery.ps1|*' })
}
function Normalize-Keep {
    # The ONE deliberate difference from the batch file: how the keep choice reaches the review script.
    # The batch file passes -AskKeep (the offline half: the script asks "Keep any?") or -SelectKeep
    # (--select: the script's number picker); the window asks with its own Keep / Remove cards first and
    # passes the result as -KeepIdentifier, or nothing when everything is removed. So these three are
    # dropped before comparing; every other argument must match exactly.
    param([string[]]$Lines)
    return @($Lines | ForEach-Object { [regex]::Replace($_, ' ?(-SelectKeep|-AskKeep|-KeepIdentifier \S+)', '') })
}
function Same {
    param([string[]]$A, [string[]]$B)
    return (((Normalize-Keep $A) -join "`n") -eq ((Normalize-Keep $B) -join "`n"))
}
function Show-Diff {
    param([string[]]$Gui, [string[]]$Bat)
    Write-Host '  --- GUI:'; $Gui | ForEach-Object { Write-Host ('  ' + $_) }
    Write-Host '  --- START-HERE.bat:'; $Bat | ForEach-Object { Write-Host ('  ' + $_) }
}

try {
    $answersDefault = @('', '', '', '', '', '', '')
    $desktop = Join-Path $work 'desktop'
    $null = New-Item -ItemType Directory -Path $desktop -Force

    # ============================================================ FULL
    Write-Host 'FULL run' -ForegroundColor Cyan
    $hb = New-Harness 'bat-full' ''
    $bat = Invoke-Launcher $hb 'START-HERE.bat' $answersDefault 'bat-full'
    $hg = New-Harness 'gui-full' ''
    $s = New-GuiSession -Mode Full -ToolRoot $hg.Dir -RitRoot $hg.Rit -ComputerName $env:COMPUTERNAME
    [void](Initialize-GuiRunRoot -Session $s)
    $g = Invoke-GuiHeadless $s $desktop 'gui-full'
    $a = Normalize $g $hg; $b = Normalize ([pscustomobject]@{ Trace = (Get-BatTrace $bat) }) $hb
    Check (-not $bat.Timeout) 'batch full run finished'
    Check (Same $a $b) ('GUI full trace equals START-HERE.bat (' + $b.Count + ' calls)')
    if (-not (Same $a $b)) { Show-Diff $a $b }
    Check ($s.PipeRc -eq 0 -and -not $s.Stopped) 'GUI full run ends clean (status 0)'
    Check (@(Get-ChildItem -LiteralPath $hg.Rit -Directory).Count -eq 1) 'GUI created exactly one run folder'
    Check ((Get-GuiModeInfo -Mode Full).Launcher -eq 'START-HERE.bat') 'catalog names the launcher it mirrors'

    # ============================================================ OFFLINE then ONLINE (hand-off)
    Write-Host 'OFFLINE half, then ONLINE half continuing it' -ForegroundColor Cyan
    $hb = New-Harness 'bat-split' ''
    $batOff = Invoke-Launcher $hb 'START-HERE-OFFLINE.bat' $answersDefault 'bat-off'
    $batOn = Invoke-Launcher $hb 'START-HERE-ONLINE.bat' $answersDefault 'bat-on'
    $hg = New-Harness 'gui-split' ''
    $s1 = New-GuiSession -Mode Offline -ToolRoot $hg.Dir -RitRoot $hg.Rit
    [void](Initialize-GuiRunRoot -Session $s1)
    $gOff = Invoke-GuiHeadless $s1 $desktop 'gui-off'
    $a = Normalize $gOff $hg; $b = Normalize ([pscustomobject]@{ Trace = (Get-BatTrace $batOff) }) $hb
    Check (Same $a $b) ('GUI offline trace equals START-HERE-OFFLINE.bat (' + $b.Count + ' calls)')
    if (-not (Same $a $b)) { Show-Diff $a $b }
    Check (Test-Path -LiteralPath (Join-Path $s1.RunRoot 'phase-offline.json')) 'GUI offline half wrote phase-offline.json (real helper)'
    foreach ($never in 'Get-ToolPack.ps1', 'Get-AVTools.ps1', 'Invoke-GUIScanner.ps1', 'Invoke-AVUninstaller.ps1') {
        Check (-not (Has $gOff $never)) ('GUI offline never runs ' + $never)
    }
    $sub = @($gOff.Trace | Where-Object { $_ -like 'Submit-ConnectWiseReport.ps1|*' })[0]
    Check ($sub -like '*-NoUpload*') 'GUI offline builds the package with -NoUpload'
    $revBat = @($batOff.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' })[0]
    $revGui = @($gOff.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' })[0]
    Check ($revBat -like '*-AskKeep*' -and $revGui -notlike '*-AskKeep*') 'the declared difference: the batch passes -AskKeep, the window never does (it asks with its own cards)'
    # The offline run folder must be created LOCKED, or the online half (Find-OfflineRun.ps1) will not continue it.
    $acl = Get-Acl -LiteralPath $s1.RunRoot
    Check ($acl.AreAccessRulesProtected) 'the GUI offline run folder is created locked (no inherited C:\RIT-SCC permissions)'
    $usersWrite = @($acl.Access | Where-Object { $_.IdentityReference -match 'Users$|Authenticated Users' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData) })
    Check ($usersWrite.Count -eq 0) 'normal users cannot write to the GUI offline run folder'

    $s2 = New-GuiSession -Mode Online -ToolRoot $hg.Dir -RitRoot $hg.Rit
    $prior = Find-GuiPriorRun -Session $s2
    Check ($null -ne $prior -and $prior.RunRoot -eq $s1.RunRoot) 'GUI online half finds the offline run through the real Find-OfflineRun.ps1'
    [void](Initialize-GuiRunRoot -Session $s2 -Prior $prior)
    $gOn = Invoke-GuiHeadless $s2 $desktop 'gui-on'
    $a = Normalize $gOn $hg; $b = Normalize ([pscustomobject]@{ Trace = (Get-BatTrace $batOn) }) $hb
    Check (Same $a $b) ('GUI online trace equals START-HERE-ONLINE.bat (' + $b.Count + ' calls)')
    if (-not (Same $a $b)) { Show-Diff $a $b }
    Check (@(Get-ChildItem -LiteralPath $hg.Rit -Directory).Count -eq 1) 'GUI online continued the same run folder'
    Check (Test-Path -LiteralPath (Join-Path $s1.RunRoot 'phase-online.json')) 'GUI online half wrote phase-online.json'
    $subOn = @($gOn.Trace | Where-Object { $_ -like 'Submit-ConnectWiseReport.ps1|*' })
    Check ($subOn.Count -eq 1 -and $subOn[0] -notlike '*-NoUpload*') 'GUI online shares once, for real (no -NoUpload)'
    $perOn = @($gOn.Trace | Where-Object { $_ -like 'Invoke-PersistenceScan.ps1|*' })
    Check ($perOn.Count -eq 1 -and $perOn[0] -like '*-WorkDir *\after-scans -PreflightRoot*') 'GUI online runs the persistence check again, into after-scans'
    if (Test-Path -LiteralPath (Join-Path $s1.RunRoot 'after-scans\persistence\result.json')) {
        Check ((Has $gOn 'New-InvestigationReport.ps1') -and $subOn[0] -like '*-ReportHtml *report-after-scans.html*') 'GUI online rebuilds and shares report-after-scans.html'
        Check ($s2.ShareReport -like '*report-after-scans.html') 'the Desktop copy refresh uses the shared after-scans report'
    }
    # The online half must refuse to continue an offline run whose folder is NOT locked (older build, or tampered).
    $hu = New-Harness 'gui-unlocked' ''
    $su = New-GuiSession -Mode Offline -ToolRoot $hu.Dir -RitRoot $hu.Rit
    [void](New-GuiRunRoot -Session $su)   # a plain, inherited-permissions folder, as builds before offline.3 made
    '{"Phase":"offline"}' | Set-Content -LiteralPath (Join-Path $su.RunRoot 'phase-offline.json') -Encoding ASCII
    $sOn = New-GuiSession -Mode Online -ToolRoot $hu.Dir -RitRoot $hu.Rit
    Check ($null -eq (Find-GuiPriorRun -Session $sOn)) 'an unlocked offline run folder is not continued by the GUI online half'

    # ============================================================ ONLINE with nothing to continue
    Write-Host 'ONLINE half, no prior run' -ForegroundColor Cyan
    $hb = New-Harness 'bat-noprior' ''
    $bat = Invoke-Launcher $hb 'START-HERE-ONLINE.bat' $answersDefault 'bat-noprior'
    $hg = New-Harness 'gui-noprior' ''
    $s = New-GuiSession -Mode Online -ToolRoot $hg.Dir -RitRoot $hg.Rit
    Check ($null -eq (Find-GuiPriorRun -Session $s)) 'no finished offline run: nothing to continue'
    [void](Initialize-GuiRunRoot -Session $s -Prior $null)
    $g = Invoke-GuiHeadless $s $desktop 'gui-noprior'
    $a = Normalize $g $hg; $b = Normalize ([pscustomobject]@{ Trace = (Get-BatTrace $bat) }) $hb
    Check (Same $a $b) ('GUI scanner-only trace equals START-HERE-ONLINE.bat (' + $b.Count + ' calls)')
    if (-not (Same $a $b)) { Show-Diff $a $b }
    Check ($s.ScannerOnly -and -not (Has $g 'Submit-ConnectWiseReport.ps1')) 'scanner-only run shares nothing'

    # ============================================================ STAGE
    Write-Host 'STAGE (downloads only)' -ForegroundColor Cyan
    $hb = New-Harness 'bat-stage' ''
    $bat = Invoke-Launcher $hb (New-FlagWrapper $hb 'stage-wrapper.bat' '--stage') @('') 'bat-stage'
    $hg = New-Harness 'gui-stage' ''
    $s = New-GuiSession -Mode Stage -ToolRoot $hg.Dir -RitRoot $hg.Rit
    [void](Initialize-GuiRunRoot -Session $s)
    $g = Invoke-GuiHeadless $s $desktop 'gui-stage'
    $a = Normalize $g $hg; $b = Normalize ([pscustomobject]@{ Trace = (Get-BatTrace $bat) }) $hb
    Check (Same $a $b) ('GUI stage trace equals the batch --stage (' + $b.Count + ' calls)')
    Check (@(Get-ChildItem -LiteralPath $hg.Rit -Directory).Count -eq 0) 'GUI stage creates no run folder'

    # ============================================================ keep selection (-SelectKeep vs -KeepIdentifier)
    Write-Host 'Keep selection (the one deliberate difference: -KeepIdentifier instead of the picker)' -ForegroundColor Cyan
    $hb = New-Harness 'bat-sel' ''
    $bat = Invoke-Launcher $hb 'START-HERE-OFFLINE.bat' (@('y') + $answersDefault) 'bat-sel'
    $hg = New-Harness 'gui-sel' ''
    $s = New-GuiSession -Mode Offline -ToolRoot $hg.Dir -RitRoot $hg.Rit -Answers @{ KeepIdentifiers = @('aaaa1111aaaa1111', 'cccc3333cccc3333') }
    [void](Initialize-GuiRunRoot -Session $s)
    $g = Invoke-GuiHeadless $s $desktop 'gui-sel'
    $a = Normalize-Keep (Normalize $g $hg); $b = Normalize-Keep (Normalize ([pscustomobject]@{ Trace = (Get-BatTrace $bat) }) $hb)
    Check (Same $a $b) 'offline with a keep list: same calls as the batch select mode apart from the keep argument'
    if (-not (Same $a $b)) { Show-Diff $a $b }
    $rev = @($g.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' })[0]
    Check ($rev -like '*-KeepIdentifier aaaa1111aaaa1111,cccc3333cccc3333') 'GUI passes the kept identifiers as ONE comma string (spike S4)'
    Check ($rev -notlike '*-SelectKeep*') 'GUI never uses the interactive picker'

    # ============================================================ DETECT only (GUI-only mode, a strict subset)
    Write-Host 'DETECT only (phase 2 window mode)' -ForegroundColor Cyan
    $hg = New-Harness 'gui-detect' ''
    $s = New-GuiSession -Mode Detect -ToolRoot $hg.Dir -RitRoot $hg.Rit
    [void](Initialize-GuiRunRoot -Session $s)
    $g = Invoke-GuiHeadless $s $desktop 'gui-detect'
    $names = @($g.Trace | ForEach-Object { $_.Split('|')[0] })
    Check (($names -join ',') -eq 'preflight.ps1,collect-snapshot.ps1,detect-remote-access.ps1,New-InvestigationReport.ps1') 'detect-only runs preflight, before snapshot, detection and the report - nothing else'
    foreach ($never in 'Invoke-ReviewAndRemove.ps1', 'remove-screenconnect.ps1', 'Invoke-PersistenceScan.ps1', 'Submit-ConnectWiseReport.ps1', 'Repair-PowerOptions.ps1', 'Invoke-AVUninstaller.ps1') {
        Check (-not (Has $g $never)) ('detect-only never runs ' + $never)
    }
    $pre = @($g.Trace | Where-Object { $_ -like 'preflight.ps1|*' })[0]
    Check ($pre -like '*-SkipToolPack*') 'detect-only passes -SkipToolPack like the offline half'

    # ============================================================ optional steps follow the technician's answers
    Write-Host 'Answers: optional steps' -ForegroundColor Cyan
    $hg = New-Harness 'gui-ans' ''
    $s = New-GuiSession -Mode Full -ToolRoot $hg.Dir -RitRoot $hg.Rit -Answers @{ ScanKvrt = $false; ScanEset = $false; OpenReview = $false; Avu = $true; PowerRepair = $true; ResetGpo = $true }
    [void](Initialize-GuiRunRoot -Session $s)
    $g = Invoke-GuiHeadless $s $desktop 'gui-ans'
    Check ((CountOf $g 'Invoke-GUIScanner.ps1') -eq 1) 'skipping KVRT and ESET leaves only Malwarebytes'
    Check (-not (Has $g 'Show-PersistenceReview.ps1')) 'declining the review windows skips Show-PersistenceReview'
    Check (Has $g 'Invoke-AVUninstaller.ps1') 'AV uninstall runs only when asked'
    $pr = @($g.Trace | Where-Object { $_ -like 'Repair-PowerOptions.ps1|*' })[0]
    Check ($pr -like '*-Apply -Confirm*false*' -and $pr -like '*-ResetLocalGpo') 'power repair with the GPO reset passes -ResetLocalGpo last, like the batch file'
    if (-not ($pr -like '*-Apply -Confirm*false*' -and $pr -like '*-ResetLocalGpo')) { Write-Host ('  actual: ' + $pr) }
    Check ($s.PowerRepairRan -eq $false) 'PowerRepairRan reflects whether the repair wrote its result (stub wrote none)'

    # ============================================================ when a step fails
    Write-Host 'Failure handling (same rules as the batch file)' -ForegroundColor Cyan
    foreach ($case in @(
            @{ Script = 'preflight.ps1'; Stops = $true; After = 'collect-snapshot.ps1' },
            @{ Script = 'detect-remote-access.ps1'; Stops = $true; After = 'Invoke-ReviewAndRemove.ps1' },
            @{ Script = 'collect-snapshot.ps1'; Stops = $true; After = 'detect-remote-access.ps1' })) {
        $hg = New-Harness ('gui-fail-' + $case.Script) ''
        $stubPath = Get-ChildItem -Path $hg.Dir -Filter $case.Script -Recurse -File | Select-Object -First 1
        Set-Content -LiteralPath $stubPath.FullName -Value ($stubText.Replace('exit 0', 'exit 3')) -Encoding ASCII
        $s = New-GuiSession -Mode Offline -ToolRoot $hg.Dir -RitRoot $hg.Rit
        [void](Initialize-GuiRunRoot -Session $s)
        $g = Invoke-GuiHeadless $s $desktop ('gui-fail-' + $case.Script)
        Check ($s.Stopped -and -not (Has $g $case.After)) ($case.Script + ' failing stops the run before ' + $case.After)
        Check (@($g.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' }).Count -eq 0) ($case.Script + ' failing never reaches removal')
    }
    # removal reporting a problem: warn, remember the code, keep going to evidence and report
    $hg = New-Harness 'gui-fail-removal' ''
    $stubPath = Get-ChildItem -Path $hg.Dir -Filter 'Invoke-ReviewAndRemove.ps1' -Recurse -File | Select-Object -First 1
    Set-Content -LiteralPath $stubPath.FullName -Value ($stubText.Replace('exit 0', 'exit 1')) -Encoding ASCII
    $s = New-GuiSession -Mode Offline -ToolRoot $hg.Dir -RitRoot $hg.Rit
    [void](Initialize-GuiRunRoot -Session $s)
    $g = Invoke-GuiHeadless $s $desktop 'gui-fail-removal'
    Check ((-not $s.Stopped) -and (Has $g 'New-InvestigationReport.ps1') -and (CountOf $g 'collect-snapshot.ps1') -eq 2) 'removal exit 1: still takes the after snapshot and builds the report'
    Check ((Get-GuiFinalStatus $s) -eq 1) 'removal exit 1: the run ends with status 1 (first non-zero code)'
    # diff exit 1 is a finding, not a failure
    $hg = New-Harness 'gui-diff1' ''
    $stubPath = Get-ChildItem -Path $hg.Dir -Filter 'diff-snapshots.ps1' -Recurse -File | Select-Object -First 1
    Set-Content -LiteralPath $stubPath.FullName -Value ($stubText.Replace('exit 0', 'exit 1')) -Encoding ASCII
    $s = New-GuiSession -Mode Offline -ToolRoot $hg.Dir -RitRoot $hg.Rit
    [void](Initialize-GuiRunRoot -Session $s)
    $g = Invoke-GuiHeadless $s $desktop 'gui-diff1'
    $diffRes = @($s.Results | Where-Object { $_.StepId -eq '8c' })[0]
    Check ($diffRes.Status -eq 'Resurrection' -and (Get-GuiFinalStatus $s) -eq 0) 'diff exit 1 is reported as RESURRECTION and is not a pipeline failure'
    # a scanner that is not staged is a warning, not a stop
    $hg = New-Harness 'gui-nostage' ''
    Remove-Item -LiteralPath (Join-Path $hg.Dir 'tools\AV\KVRT.exe') -Force
    $s = New-GuiSession -Mode Online -ToolRoot $hg.Dir -RitRoot $hg.Rit
    [void](Initialize-GuiRunRoot -Session $s -Prior $null)
    $g = Invoke-GuiHeadless $s $desktop 'gui-nostage'
    $kv = @($s.Results | Where-Object { $_.StepId -eq '6a' })[0]
    Check ($kv.Status -eq 'Warn' -and $kv.Message -match 'not staged') 'KVRT.exe not staged: warns and the other scanners still run'
    Check ((CountOf $g 'Invoke-GUIScanner.ps1') -eq 2) 'only ESET and Malwarebytes were launched'

    # ============================================================ path with spaces and parentheses
    Write-Host 'Tool folder with spaces and parentheses' -ForegroundColor Cyan
    $hb = New-Harness 'bat par (1) x' ''
    $bat = Invoke-Launcher $hb 'START-HERE-OFFLINE.bat' $answersDefault 'bat-par'
    $hg = New-Harness 'gui par (1) x' ''
    $s = New-GuiSession -Mode Offline -ToolRoot $hg.Dir -RitRoot $hg.Rit
    [void](Initialize-GuiRunRoot -Session $s)
    $g = Invoke-GuiHeadless $s $desktop 'gui-par'
    $a = Normalize $g $hg; $b = Normalize ([pscustomobject]@{ Trace = (Get-BatTrace $bat) }) $hb
    Check (Same $a $b) ('GUI trace in "par (1) x" equals the batch file (' + $b.Count + ' calls)')
    if (-not (Same $a $b)) { Show-Diff $a $b }

    # ============================================================ quoting helper
    Write-Host 'Argument quoting' -ForegroundColor Cyan
    Check ((ConvertTo-GuiArg 'C:\a b\c') -eq '"C:\a b\c"') 'a path with a space is quoted'
    Check ((ConvertTo-GuiArg 'C:\a b\') -eq '"C:\a b\\"') 'a trailing backslash inside quotes is doubled'
    Check ((ConvertTo-GuiArg '') -eq '""') 'an empty value becomes ""'
    Check ((ConvertTo-GuiArg '-Confirm:$false') -eq '-Confirm:$false') 'a plain token is left alone'
    Check ((ConvertTo-GuiArg 'say "hi"') -eq '"say \"hi\""') 'embedded quotes are escaped'
} finally {
    Restore-GuiConsoleEncoding $consoleSaved
    Remove-Item Env:\SCC_TRACE -ErrorAction SilentlyContinue
    Remove-Item Env:\SCC_RUNNER_CHILD -ErrorAction SilentlyContinue
    if ($KeepWork) { Write-Host ('Work folder kept: ' + $work) -ForegroundColor Yellow }
    elseif (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0
