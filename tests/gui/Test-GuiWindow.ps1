<#
  Test-GuiWindow.ps1 - the real window, end to end, against STUBBED engine scripts.

  Starts gui\Start-CleanupGui.ps1 with -ToolRoot pointing at a COPY of the tool where every engine
  script is the Test-PhaseSplit.ps1 stub (nothing real runs) - except Invoke-ReviewAndRemove.ps1,
  which is the REAL script so its real prompts reach the window; the remover it calls
  (remove-screenconnect.ps1) is still a stub that only records the call, so nothing is ever removed.
  The detection stub writes a realistic findings.json (3 ScreenConnect instances).

  The window is started with -AutoStart -Mode <mode> -ResultPath. The technician's clicks are
  replaced by a JSON file of canned dialog answers (SCC_GUI_TEST=1, SCC_GUI_TEST_ANSWERS); a dialog
  with no entry behaves as if it was closed with the window X, i.e. it REFUSES. The window opens
  nothing and copies nowhere near the real Desktop, runs the flow on its own timer, writes its final
  state to the result file and closes itself; this test then checks that state and the calls made.

  Scenarios: Offline with a keep/remove choice and a typed REMOVE; Offline with the confirmation
  refused; a wrong typed word; the Online half continuing that run; Online skipping every scan;
  Stage; and an Offline run with every optional step switched on. The window offers no Full run
  (it is Offline then Online); asking for one is refused.

  Needs an interactive desktop for the live part; without one it FAILS loudly instead of passing.
  No admin. Windows PowerShell 5.1, pure ASCII, no BOM.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch]$KeepWork
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:TEMP ('scc-gui-window-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force
$script:Failures = New-Object System.Collections.ArrayList
$script:Passes = 0
function Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passes++; Write-Host ('  [pass] ' + $Message) -ForegroundColor Green }
    else { [void]$script:Failures.Add($Message); Write-Host ('  [FAIL] ' + $Message) -ForegroundColor Red }
}

# ---- reuse the batch stub harness exactly as Test-GuiCallParity does ---------------------------
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ToolRoot 'tests\Test-PhaseSplit.ps1'), [ref]$tokens, [ref]$errs)
$stubAssign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$stubText' }, $true)
Invoke-Expression $stubAssign.Extent.Text
$stubText = $stubText.Replace('$try -lt 5', '$try -lt 200')
foreach ($def in @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })) {
    if ($def.Name -in 'New-Harness', 'Disable-ReportOpen') { Invoke-Expression $def.Extent.Text }
}

$detectStub = @'
$leaf = Split-Path -Leaf $MyInvocation.MyCommand.Path
Add-Content -LiteralPath $env:SCC_TRACE -Value ($leaf + '|' + ($args -join ' ')) -Encoding ASCII
$i = [array]::IndexOf($args, '-OutRoot')
$o = [string]$args[$i + 1]
$d = Join-Path $o 'HOST_20260101_000000'
$null = New-Item -ItemType Directory -Path $d -Force
$mk = { param($id, $relay, $port) [ordered]@{ Key = 'svc:' + $id; Identifier = $id; InstallDir = 'C:\Program Files (x86)\ScreenConnect Client (' + $id + ')'; ServiceName = 'ScreenConnect Client (' + $id + ')'; ServiceState = 'Running'; RelayHost = $relay; RelayPort = $port; SessionType = 'Support'; File = [ordered]@{ SignatureStatus = 'Valid'; SignerSubject = 'CN=Example' }; InstallDirCreatedUtc = '2026-01-02 03:04:05' } }
Write-Host 'Stub detection: writing findings.json'
$doc = [ordered]@{ Tool = 'detect-remote-access.ps1'; RunId = 'T'; ComputerName = 'TESTPC'; GeneratedUtc = '2026-11-10 10:00:00'
    ScreenConnect = [ordered]@{ Instances = @((& $mk 'aaaa1111aaaa1111' 'evil.example.net' 8041), (& $mk 'bbbb2222bbbb2222' 'support.customer.example' 443), (& $mk 'cccc3333cccc3333' 'other.example.org' 8041)); ParseIssues = @(); Historical = @(); RawFilesSaved = @() }
    OtherTargets = @([pscustomobject]@{ Id = 'anydesk'; Name = 'AnyDesk'; Hits = @([pscustomobject]@{ Kind = 'directory'; Name = 'AnyDesk'; Path = 'C:\x' }); Count = 1 }) }
($doc | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath (Join-Path $d 'findings.json') -Encoding UTF8
exit 0
'@
# a power-repair stub that writes its result file, like the real one, so the restart offer's conditions can be met
$repairStub = $stubText.Replace("switch (`$leaf) {", "switch (`$leaf) {`n    'Repair-PowerOptions.ps1' { '{}' | Set-Content -LiteralPath (ArgAfter '-ResultPath') }")

# The share prints its paste link the way Submit-ConnectWiseReport.ps1 does; the window must pick it up.
$shareStub = @'
Add-Content -LiteralPath $env:SCC_TRACE -Value ('Submit-ConnectWiseReport.ps1|' + ($args -join ' ')) -Encoding ASCII
Write-Host 'MICROBIN UPLOAD: https://reports.example.invalid/p/abc123'
exit 0
'@
# KVRT's launch fails the first time and works the second: the window must offer to run it again.
$retryScannerStub = @'
Add-Content -LiteralPath $env:SCC_TRACE -Value ('Invoke-GUIScanner.ps1|' + ($args -join ' ')) -Encoding ASCII
if (($args -join ' ') -like '*-Scanner KVRT*') {
    $flag = Join-Path $PSScriptRoot 'kvrt-tried.flag'
    if (-not (Test-Path -LiteralPath $flag)) { Set-Content -LiteralPath $flag -Value 'x'; Write-Host 'Stub: KVRT launch failed'; exit 3 }
}
exit 0
'@

function Remove-Comments {
    param([string]$Text)
    $t = [regex]::Replace($Text, '(?s)<#.*?#>', '')
    return (($t -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^#' }) -join "`n")
}

function Invoke-Window {
    # Runs one window session. $Answers is the hashtable of canned dialog answers. Reuses $Harness when given
    # (the Online half must see the Offline half's run folder).
    param([string]$Name, [string]$ModeName, [hashtable]$Answers, $Harness = $null, [switch]$RealReview = $true, [switch]$RepairWritesResult, [hashtable]$Stubs)
    $h = $Harness
    if (-not $h) {
        $h = New-Harness $Name ''
        Set-Content -LiteralPath (Get-ChildItem -Path $h.Dir -Filter 'detect-remote-access.ps1' -Recurse -File | Select-Object -First 1).FullName -Value $detectStub -Encoding ASCII
        if ($RealReview) { Copy-Item -LiteralPath (Join-Path $ToolRoot 'Invoke-ReviewAndRemove.ps1') -Destination (Join-Path $h.Dir 'Invoke-ReviewAndRemove.ps1') -Force }
        if ($RepairWritesResult) { Set-Content -LiteralPath (Get-ChildItem -Path $h.Dir -Filter 'Repair-PowerOptions.ps1' -Recurse -File | Select-Object -First 1).FullName -Value $repairStub -Encoding ASCII }
    }
    # Per-scenario stub replacements (script file name -> stub text), applied to a new or a reused harness.
    if ($Stubs) { foreach ($k in $Stubs.Keys) { Set-Content -LiteralPath (Join-Path $h.Dir $k) -Value $Stubs[$k] -Encoding ASCII } }
    $trace = Join-Path $work ($Name + '.trace')
    Set-Content -LiteralPath $trace -Value '' -Encoding ASCII
    $ansFile = Join-Path $work ($Name + '.answers.json')
    ($Answers | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $ansFile -Encoding ASCII
    $resultFile = Join-Path $work ($Name + '\state.json')
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $resultFile) -Force
    $env:SCC_TRACE = $trace; $env:SCC_GUI_TEST = '1'; $env:SCC_GUI_TEST_ANSWERS = $ansFile
    try {
        # The REAL gui script from this checkout (the harness copy of it is a stub); only -ToolRoot is the stubbed engine.
        $p = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -PassThru -WindowStyle Minimized -ArgumentList @(
            '-NoLogo', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $guiPath + '"'),
            '-ToolRoot', ('"' + $h.Dir + '"'), '-RitRoot', ('"' + $h.Rit + '"'), '-AllowNotElevated', '-AutoStart', '-Mode', $ModeName, '-ResultPath', ('"' + $resultFile + '"'))
        $done = $p.WaitForExit(240000)
        if (-not $done) { try { $p.Kill() } catch { } }
    } finally { Remove-Item Env:\SCC_GUI_TEST, Env:\SCC_GUI_TEST_ANSWERS -ErrorAction SilentlyContinue }
    $state = $null
    if (Test-Path -LiteralPath $resultFile) { $state = [IO.File]::ReadAllText($resultFile) | ConvertFrom-Json }
    $calls = @(Get-Content -LiteralPath $trace | Where-Object { $_ -and $_ -notlike 'Keep-Awake.ps1|*' })
    return [pscustomobject]@{ Harness = $h; State = $state; Calls = $calls; Names = @($calls | ForEach-Object { $_.Split('|')[0] }); Exit = $(if ($done) { $p.ExitCode } else { -1 }); Done = $done }
}
function Get-Plan([string]$RunRoot) {
    $f = Join-Path $RunRoot 'plan.json'
    if (Test-Path -LiteralPath $f) { return ([IO.File]::ReadAllText($f) | ConvertFrom-Json) }
    return $null
}
function Ids($list) { return (@(@($list) | ForEach-Object { $_.Identifier }) | Sort-Object) -join ',' }

try {
    Write-Host 'Static rules for the window source' -ForegroundColor Cyan
    $guiPath = Join-Path $ToolRoot 'gui\Start-CleanupGui.ps1'
    $guiPs = [IO.File]::ReadAllText($guiPath)
    $coreSrc = [IO.File]::ReadAllText((Join-Path $ToolRoot 'gui\Gui.Core.psm1'))
    $xaml = [IO.File]::ReadAllText((Join-Path $ToolRoot 'gui\MainWindow.xaml'))
    $guiCode = Remove-Comments $guiPs
    $bomBytes = [IO.File]::ReadAllBytes($guiPath)
    Check ($coreSrc -notmatch 'System\.Windows\.|PresentationFramework|WindowsBase') 'Gui.Core.psm1 references no WPF types (it stays testable without a desktop)'
    Check ($guiCode -notmatch '(RunspaceFactory|CreateRunspace|Start-Job|Start-ThreadJob|Register-ObjectEvent|\[powershell\]::Create)') 'the window uses no runspaces, jobs or Register-ObjectEvent (one UI thread, one timer)'
    Check ($guiCode -notmatch '(Import-Module[^\r\n]*(Persistence|SystemRestore|PowerOptions)|(?m)^\s*\.\s+[\.\$])') 'the window imports no engine module and dot-sources nothing'
    Check ($guiCode -notmatch '(?i)remove-screenconnect|Set-Service|Stop-Service|Unregister-ScheduledTask|Remove-Item|Move-Item|\.Delete\(|Invoke-ReviewAndRemove|Invoke-PersistenceScan') 'the window contains no removal code and never names an engine script'
    Check ($guiCode -notmatch '(?i)(\bsafe\b|trusted|suspicious|known-good|allowlist)') 'no relay-host verdict wording or colouring in the window'
    Check ($guiCode -notmatch "Send-GuiAnswer[^\r\n]*-Text\s+('[^']|""[^""])") 'every answer sent to a script comes from a dialog result; the only literal is the empty line (the scripts'' own default)'
    Check ($guiCode -match "else \{\s*[^\r\n]*\r?\n\s*Send-GuiAnswer -Child \`$child -Text ''") 'closing the unknown-prompt box sends an empty line (the script''s default), so a waiting script is never left hanging'
    Check ($coreSrc -match 'RepeatSeconds' -and $guiCode -match 'Set-GuiPromptDismissed') '"This is not a question" comes back after a while if the tool is still waiting'
    Check ($guiCode -match '\$script:CloseLock = \[bool\]\$a\.Destructive') 'every Destructive step (5 removal, 7 AV uninstall, 8a power repair) locks the window while it runs'
    $cat = [IO.File]::ReadAllText((Join-Path $ToolRoot 'gui\steps.json')) | ConvertFrom-Json
    Check (((@($cat.Steps | Where-Object { $_.PSObject.Properties['Destructive'] -and $_.Destructive } | ForEach-Object { $_.Id }) | Sort-Object) -join ',') -eq '5,7,8a') 'the catalog marks exactly steps 5, 7 and 8a as Destructive'
    Check ($guiCode -match "Stop-GuiChild \`$script:Child -KeepDescendants" -and $coreSrc -match 'KeepDescendants') 'closing the window during a scan ends only the step, never the scanner window'
    Check ($guiCode -match '\$script:TestHooksAllowed = \(-not \$isAdmin\)') 'canned answers (and the render/hold hooks) are honoured only in a window that is NOT elevated - no unattended removal is possible'
    Check ($guiCode -match "-Id 'RemoveConfirm'[^\r\n]*-TypeWord 'REMOVE'" -and $guiCode -match "-Id 'PersistRemove'[^\r\n]*-TypeWord 'REMOVE'") 'both removal confirmations require the typed word REMOVE'
    Check ($guiCode -match "NeedsWord = \`$true") 'the approving button is gated on the typed word'
    Check ($guiCode -match 'SCC_GUI_TEST' -and $guiCode -match '\$script:TestMode = \(\$null -ne \$script:TestAnswers\) -and \$script:TestHooksAllowed') 'canned answers exist only in test mode (-ResultPath with SCC_GUI_TEST=1, not elevated)'
    Check ($guiCode -match "AutoStart -and \`$ResultPath -and \(\`$startMode -eq 'Detect' -or \`$script:TestMode\)") 'an unattended start of any mode but Detect needs the test answers'
    Check ($xaml -notmatch '[^\x00-\x7F]') 'MainWindow.xaml is pure ASCII'
    Check ($guiPs -notmatch '[^\x00-\x7F]' -and $coreSrc -notmatch '[^\x00-\x7F]') 'the GUI scripts are pure ASCII'
    Check (-not ($bomBytes.Length -ge 3 -and $bomBytes[0] -eq 0xEF -and $bomBytes[1] -eq 0xBB -and $bomBytes[2] -eq 0xBF)) 'no byte order mark in Start-CleanupGui.ps1'
    Check ($guiPs -match 'GetApartmentState' -and $guiPs -match '-STA') 'the window insists on an STA thread'

    Write-Host 'Window loads and every named control exists' -ForegroundColor Cyan
    $expected = ([regex]::Matches($xaml, 'x:Name="')).Count - 1   # minus the Window itself
    $load = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -STA -ExecutionPolicy Bypass -File $guiPath -LoadOnly -AllowNotElevated 2>&1
    Check (($load | Out-String) -match ('LOAD_OK controls=' + $expected + '\b')) ('XAML parses and all ' + $expected + ' named controls are found')
    foreach ($m in 'RbOffline', 'RbOnline', 'RbDetect', 'RbStage') { Check ($xaml.Contains('x:Name="' + $m + '"')) ('the mode toggle has ' + $m) }
    Import-Module (Join-Path $ToolRoot 'gui\Gui.Core.psm1') -Force
    $winModes = @(Get-GuiWindowModes | ForEach-Object { $_.Name })
    Check ((($winModes | Sort-Object) -join ',') -eq 'Detect,Offline,Online,Stage') ('gui\steps.json is the one list of window modes: ' + ($winModes -join ', '))
    Check (@($winModes | Where-Object { -not $xaml.Contains('x:Name="Rb' + $_ + '"') }).Count -eq 0) 'every window mode in the catalog has its button on the start panel'
    Check (-not $xaml.Contains('RbFull') -and $guiCode -notmatch "'Full'\s*=|Tag = 'Full'") 'the window offers no Full run (it is Offline then Online)'
    $full = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -STA -ExecutionPolicy Bypass -File $guiPath -AllowNotElevated -AutoStart -Mode Full -ResultPath (Join-Path $work 'full-refused.json') 2>&1
    Check ($LASTEXITCODE -eq 2 -and ($full | Out-String) -match 'unsupported mode') 'asking the window for -Mode Full is refused before anything runs'

    # ---------------------------------------------------------------- Offline: keep one, type REMOVE
    Write-Host 'Offline half: keep one instance, confirm removal by typing REMOVE' -ForegroundColor Cyan
    $r = Invoke-Window 'off-keep' 'Offline' @{
        KeepSelection = @{ Keep = @('bbbb2222bbbb2222') }
        RemoveConfirm = @{ Value = 'ok'; Text = 'REMOVE' }
        OpenReview = @{ Value = 'n' }; PowerRepair = @{ Value = 'go' }; LowDisk = @{ Value = 'y' } }
    if (-not $r.State) { Check $false 'the window wrote its result file (this needs a machine with an interactive desktop)' }
    else {
        $s = $r.State
        Check ($r.Done -and $r.Exit -eq 0) 'the window ran, closed itself and exited 0'
        Check (($r.Names -join ',') -eq 'preflight.ps1,collect-snapshot.ps1,detect-remote-access.ps1,remove-screenconnect.ps1,Invoke-PersistenceScan.ps1,collect-snapshot.ps1,diff-snapshots.ps1,New-InvestigationReport.ps1,Submit-ConnectWiseReport.ps1') ('offline calls in the batch file''s order (the real review script reached the stub remover): ' + ($r.Names -join ', '))
        $plan = Get-Plan $s.RunRoot
        Check ($plan -and $plan.Decision -eq 'PARTIAL_REMOVE') 'the real review script wrote a PARTIAL_REMOVE plan'
        Check ($plan -and (Ids $plan.ScreenConnectInstances) -eq 'aaaa1111aaaa1111,cccc3333cccc3333') 'the plan removes only the two instances left on Remove'
        Check ($plan -and (Ids $plan.KeptScreenConnectInstances) -eq 'bbbb2222bbbb2222') 'the plan records the kept instance (-KeepIdentifier reached the script)'
        Check (Test-Path -LiteralPath (Join-Path $s.RunRoot 'kept-instances.json')) 'kept-instances.json was written for the report'
        $rmCall = @($r.Calls | Where-Object { $_ -like 'remove-screenconnect.ps1|*' })[0]
        Check ($rmCall -like '*-PlanJson*plan.json*-Execute*') 'the remover was called with the plan and -Execute, after the typed confirmation'
        Check ($s.Steps.'5' -eq 'done' -and $s.Steps.'6d' -eq 'done' -and $s.Steps.'8c' -eq 'done') 'steps 5, 6d and 8c show done'
        Check ($s.Steps.'6e' -match '^skipped' -and $s.Steps.'8a' -match '^skipped') 'review windows and power repair, declined, show skipped'
        Check ((@($r.Names | Where-Object { $_ -in 'Get-ToolPack.ps1', 'Get-AVTools.ps1', 'Invoke-GUIScanner.ps1', 'Invoke-AVUninstaller.ps1' })).Count -eq 0) 'the offline half touches no download, scanner or AV uninstall'
        $subm = @($r.Calls | Where-Object { $_ -like 'Submit-ConnectWiseReport.ps1|*' })[0]
        Check ($subm -like '*-NoUpload*') 'the offline package is built with -NoUpload'
        Check (Test-Path -LiteralPath (Join-Path $s.RunRoot 'phase-offline.json')) 'phase-offline.json was written'
        Check (-not $s.Stopped -and $s.FinalStatus -eq 0 -and $s.Banner -match 'Nothing was downloaded or uploaded') 'the run ended clean and the banner points to the online half'
        Check ((@($s.KeepIdentifiers) -join ',') -eq 'bbbb2222bbbb2222') 'the window recorded the keep selection'
        Check ($s.RestartVisible -eq $false) 'no restart offer when no power repair ran'
        $guiLog = Join-Path $s.RunRoot 'logs\gui-console.log'
        Check ((Test-Path -LiteralPath $guiLog) -and ((Get-Content -LiteralPath $guiLog -Raw) -match 'GUI sent answer: y')) 'the console log records the answer sent to the script'
        $texts = @($s.CardTexts)
        Check ($texts -contains 'Results') 'the finished run shows a Results section'
        Check (@($texts | Where-Object { $_ -like 'Persistence check:*' }).Count -eq 1) 'the results show the persistence check'
        Check (@($texts | Where-Object { $_ -like 'Before / after diff: Clean*' }).Count -eq 1) 'the results show the diff outcome (clean)'
        Check (@($texts | Where-Object { $_ -like 'Report: package built*not uploaded*' }).Count -eq 1) 'the results say the offline report was packaged, not uploaded'
        Check ($s.Steps.'6a' -like 'skipped in this mode - needs internet*' -and $s.Steps.'1' -like 'skipped in this mode - needs internet*') 'steps outside the offline half are listed and say why (needs internet)'
    }

    # ---------------------------------------------------------------- Offline: confirmation refused
    Write-Host 'Offline half: removal confirmation closed with the window X (refused)' -ForegroundColor Cyan
    $r = Invoke-Window 'off-refuse' 'Offline' @{ OpenReview = @{ Value = 'n' }; PowerRepair = @{ Value = 'go' }; LowDisk = @{ Value = 'y' } }
    if ($r.State) {
        Check (-not (Test-Path -LiteralPath (Join-Path $r.State.RunRoot 'plan.json'))) 'no plan was written'
        Check (-not ($r.Names -contains 'remove-screenconnect.ps1')) 'the remover was never called'
        Check ((@($r.Names | Where-Object { $_ -eq 'Invoke-PersistenceScan.ps1' }).Count -eq 1) -and ($r.Names -contains 'New-InvestigationReport.ps1')) 'the run still goes on to persistence and the report, as the batch file does'
        Check ($r.State.FinalStatus -eq 0) 'declining is not a failure'
    } else { Check $false 'refusal scenario produced a result' }

    # ---------------------------------------------------------------- Offline: wrong typed word
    Write-Host 'Offline half: the wrong word typed (remove, not REMOVE)' -ForegroundColor Cyan
    $r = Invoke-Window 'off-wrongword' 'Offline' @{ RemoveConfirm = @{ Value = 'ok'; Text = 'remove' }; OpenReview = @{ Value = 'n' }; PowerRepair = @{ Value = 'go' }; LowDisk = @{ Value = 'y' } }
    if ($r.State) {
        Check ((-not (Test-Path -LiteralPath (Join-Path $r.State.RunRoot 'plan.json'))) -and -not ($r.Names -contains 'remove-screenconnect.ps1')) 'a confirmation not typed exactly as REMOVE removes nothing'
    } else { Check $false 'wrong-word scenario produced a result' }

    # ---------------------------------------------------------------- Offline then Online (same harness)
    Write-Host 'Offline half, then the Online half continuing that run' -ForegroundColor Cyan
    $off = Invoke-Window 'split-off' 'Offline' @{ OpenReview = @{ Value = 'n' }; PowerRepair = @{ Value = 'go' }; LowDisk = @{ Value = 'y' } }
    $on = Invoke-Window 'split-on' 'Online' @{
        ContinuePrior = @{ Value = 'continue' }
        Scanners = @{ Value = 'go'; Checks = @{ ScanKvrt = $true; ScanEset = $true; ScanMalwarebytes = $true } }
        Retry = @{ Value = 'retry' }
        AvUninstall = @{ Value = 'n' } } $off.Harness -Stubs @{ 'Submit-ConnectWiseReport.ps1' = $shareStub; 'Invoke-GUIScanner.ps1' = $retryScannerStub }
    if ($on.State -and $off.State) {
        Check ($on.State.RunRoot -eq $off.State.RunRoot) 'the Online half continued the offline run folder (no new one)'
        $kv = @($on.Calls | Where-Object { $_ -like 'Invoke-GUIScanner.ps1|*-Scanner KVRT*' })
        Check ($kv.Count -eq 2 -and $on.State.Steps.'6a' -eq 'done') 'a scanner whose launch failed was offered again, run again and then completed'
        Check ((@($on.Names | Where-Object { $_ -eq 'Invoke-GUIScanner.ps1' }).Count -eq 4) -and ($on.Names -contains 'Get-AVTools.ps1')) 'it staged the scanners and ran all three (KVRT twice)'
        $perOn = @($on.Calls | Where-Object { $_ -like 'Invoke-PersistenceScan.ps1|*' })
        Check ($perOn.Count -eq 1 -and $perOn[0] -like '*\after-scans -PreflightRoot*') 'the online half checks persistence again after the scans, into after-scans'
        $share0 = @($on.Calls | Where-Object { $_ -like 'Submit-ConnectWiseReport.ps1|*' })[0]
        Check ($share0 -like '*-ReportHtml *report-after-scans.html*' -and $share0 -like '*after-scans\persistence\result.json*') 'it shares the rebuilt after-scans report and persistence results'
        Check ($on.State.ShareUrl -eq 'https://reports.example.invalid/p/abc123' -and @($on.State.CardTexts) -contains 'https://reports.example.invalid/p/abc123') 'the paste link the share printed is shown in the results'
        Check (-not ($on.Names -contains 'preflight.ps1') -and -not ($on.Names -contains 'Invoke-AVUninstaller.ps1')) 'it repeated no offline step and skipped the AV uninstall as answered'
        $share = @($on.Calls | Where-Object { $_ -like 'Submit-ConnectWiseReport.ps1|*' })
        Check ($share.Count -eq 1 -and $share[0] -notlike '*-NoUpload*' -and $share[0] -like ('*' + $off.State.FindingsJson + '*')) 'it shares the offline findings once, for real (no -NoUpload)'
        Check (Test-Path -LiteralPath (Join-Path $on.State.RunRoot 'phase-online.json')) 'phase-online.json was written'
        Check ($on.State.Steps.'9o' -eq 'done' -and $on.State.Steps.'6a' -eq 'done') 'steps 6a and 9o show done'
    } else { Check $false 'offline then online produced results' }

    Write-Host 'Online half: every scan skipped, scanner-only run' -ForegroundColor Cyan
    $r = Invoke-Window 'online-skip' 'Online' @{ Scanners = @{ Value = 'skip' }; AvUninstall = @{ Value = 'y' } }
    if ($r.State) {
        Check (-not ($r.Names -contains 'Invoke-GUIScanner.ps1')) 'skipping every scan launches no scanner'
        $avu = @($r.Calls | Where-Object { $_ -like 'Invoke-AVUninstaller.ps1|*' })
        Check ($avu.Count -eq 1 -and $avu[0] -like '*-LogDir*logs') 'answering yes to the AV uninstall runs it once, with the run''s logs folder'
        Check (-not ($r.Names -contains 'Submit-ConnectWiseReport.ps1')) 'a scanner-only run shares nothing'
        Check ($r.State.Steps.'6a' -match '^skipped' -and $r.State.Steps.'6c' -match '^skipped') 'the scanner steps show skipped'
    } else { Check $false 'online-skip produced a result' }

    # ---------------------------------------------------------------- Stage
    Write-Host 'Stage tools only' -ForegroundColor Cyan
    $r = Invoke-Window 'stage' 'Stage' @{}
    if ($r.State) {
        Check ((($r.Names) -join ',') -eq 'Get-ToolPack.ps1,Get-ToolPack.ps1,Get-AVTools.ps1') 'stage downloads the pack twice (download, verify) and the scanners, nothing else'
        Check ([string]::IsNullOrEmpty($r.State.RunRoot) -and @(Get-ChildItem -LiteralPath $r.Harness.Rit -Directory -ErrorAction SilentlyContinue).Count -eq 0) 'stage creates no run folder'
        Check ($r.State.Banner -match 'Staging finished') 'the banner says staging finished'
    } else { Check $false 'stage produced a result' }

    # ---------------------------------------------------------------- Offline, every optional step on
    Write-Host 'Offline half with every optional step switched on' -ForegroundColor Cyan
    $r = Invoke-Window 'offline-all' 'Offline' @{
        KeepSelection = @{ Keep = @() }
        RemoveConfirm = @{ Value = 'ok'; Text = 'REMOVE' }
        OpenReview = @{ Value = 'y' }
        PowerRepair = @{ Value = 'go'; Checks = @{ PowerRepair = $true; ResetGpo = $true } }; LowDisk = @{ Value = 'y' } } -RepairWritesResult
    if ($r.State) {
        $plan = Get-Plan $r.State.RunRoot
        Check ($plan -and $plan.Decision -eq 'ALL_REMOVE' -and @($plan.ScreenConnectInstances).Count -eq 3) 'keeping nothing removes all three (the batch file''s default)'
        Check ((($r.Names) -join ',') -eq 'preflight.ps1,collect-snapshot.ps1,detect-remote-access.ps1,remove-screenconnect.ps1,Invoke-PersistenceScan.ps1,Show-PersistenceReview.ps1,Repair-PowerOptions.ps1,collect-snapshot.ps1,diff-snapshots.ps1,New-InvestigationReport.ps1,Submit-ConnectWiseReport.ps1') ('every optional offline step ran, in the batch file''s order: ' + ($r.Names -join ', '))
        $pr = @($r.Calls | Where-Object { $_ -like 'Repair-PowerOptions.ps1|*' })[0]
        Check ($pr -like '*-ResetLocalGpo') 'power repair with the GPO reset passes -ResetLocalGpo last'
        Check ($r.State.RestartVisible -eq $true) 'the restart offer appears: a repair ran, the report was written and opened'
        Check (-not $r.State.Stopped -and $r.State.FinalStatus -eq 0) 'the run ended clean'
    } else { Check $false 'offline-all produced a result' }
} finally {
    Remove-Item Env:\SCC_TRACE -ErrorAction SilentlyContinue
    Remove-Item Env:\SCC_RUNNER_CHILD -ErrorAction SilentlyContinue
    if ($KeepWork) { Write-Host ('Work folder kept: ' + $work) -ForegroundColor Yellow }
    elseif ($work -match 'scc-gui-window-[0-9a-f]{32}$' -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0
