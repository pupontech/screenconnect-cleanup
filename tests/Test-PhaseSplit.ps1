<#
  Test-PhaseSplit.ps1 - launcher-logic test for the offline / online split.

  Runs START-HERE-OFFLINE.bat, START-HERE-ONLINE.bat and START-HERE.bat (full run,
  plus --stage and --select through throwaway wrappers, since those flags have no
  launcher of their own) against a STUBBED copy of the tool: every .ps1 is
  replaced by a stub that only records "script|arguments" to a trace file (and
  creates the one file the batch needs next, e.g. findings.json). The real
  Find-OfflineRun.ps1 and Write-PhaseMarker.ps1 are kept, so the hand-off between
  the halves is tested for real.

  Nothing real runs: no elevation, no restore point, no detection, no removal, no
  network, no C:\RIT-SCC (run folders go to a temp directory). Needs no admin.

  Checks:
    OFFLINE  runs the local steps only, never touches downloads / scanners / AV
             uninstall, builds the package with -NoUpload, writes phase-offline.json
    ONLINE   continues that run: stages, runs the 3 scanners, shares WITHOUT
             -NoUpload using the offline run's findings, runs none of the local steps
    ONLINE   with no prior run: scanners only, nothing shared
    STAGE    downloads only; no battery check, no run folder
    FULL     (no flag) runs every step incl. share; if -OriginalBat is given, its trace
             is identical to the original START-HERE.bat's (default behavior unchanged)

  Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-PhaseSplit.ps1
          [-OriginalBat <path to the pre-split START-HERE.bat>]
  Exit 0 = all checks passed. Windows PowerShell 5.1, pure ASCII, no BOM.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OriginalBat = '',
    [switch]$KeepWork     # keep the temp folder (traces + batch output) for debugging
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$work = Join-Path $env:TEMP ('scc-phase-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force
$script:Failures = New-Object System.Collections.ArrayList
$script:Passes = 0

function Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passes++; Write-Host ('  [pass] ' + $Message) -ForegroundColor Green }
    else { [void]$script:Failures.Add($Message); Write-Host ('  [FAIL] ' + $Message) -ForegroundColor Red }
}

$stubText = @'
$leaf = Split-Path -Leaf $MyInvocation.MyCommand.Path
for ($try = 0; $try -lt 5; $try++) {
    try { Add-Content -LiteralPath $env:SCC_TRACE -Value ($leaf + '|' + ($args -join ' ')) -Encoding ASCII -ErrorAction Stop; break }
    catch { Start-Sleep -Milliseconds 80 }
}
$script:ScriptArgs = @($args)
function ArgAfter([string]$Name) {
    $i = [array]::IndexOf($script:ScriptArgs, $Name)
    if ($i -ge 0 -and ($i + 1) -lt $script:ScriptArgs.Count) { return [string]$script:ScriptArgs[$i + 1] }
    return $null
}
switch ($leaf) {
    'detect-remote-access.ps1' {
        $o = ArgAfter '-OutRoot'
        $d = Join-Path $o 'HOST_20260101_000000'
        $null = New-Item -ItemType Directory -Path $d -Force
        '{"stub":true}' | Set-Content -LiteralPath (Join-Path $d 'findings.json')
    }
    'preflight.ps1' { $null = New-Item -ItemType Directory -Path (Join-Path (ArgAfter '-WorkingRoot') 'HOST-20260101') -Force }   # like the real one: creates a folder under the run root
    'collect-snapshot.ps1' { '{}' | Set-Content -LiteralPath (ArgAfter '-OutFile') }
    'Invoke-PersistenceScan.ps1' {
        $pd = Join-Path (ArgAfter '-WorkDir') 'persistence'
        $null = New-Item -ItemType Directory -Path $pd -Force
        foreach ($n in 'inventory.json', 'removal.json', 'result.json') { '{"stub":true}' | Set-Content -LiteralPath (Join-Path $pd $n) }
    }
    'New-InvestigationReport.ps1' { '<html></html>' | Set-Content -LiteralPath (ArgAfter '-OutputPath') }
}
exit 0
'@

function Disable-ReportOpen {
    # The launcher opens report.html in the browser and selects it in Explorer.
    # In this test those are throwaway stub reports under %TEMP%: never open them.
    # Fail loudly if the lines move, so the test cannot silently start opening windows again.
    param([string]$Text)
    $openers = @(
        @('explorer /select,"!SCC_RUN_ROOT!/report.html"', 'echo [test] report.html would be selected in Explorer'),
        @('start "" "!SCC_RUN_ROOT!/report.html"', 'echo [test] report.html would be opened')
    )
    foreach ($pair in $openers) {
        if (-not $Text.Contains($pair[0])) { throw ('Test-PhaseSplit: report opener not found in START-HERE.bat: ' + $pair[0]) }
        $Text = $Text.Replace($pair[0], $pair[1])
    }
    return $Text
}

function New-Harness {
    param([string]$Name, [string]$BatPath)
    $dir = Join-Path $work $Name
    $null = New-Item -ItemType Directory -Path $dir -Force
    Copy-Item -Path (Join-Path $ToolRoot '*') -Destination $dir -Recurse -Force
    # drop anything that is not part of the tool (an old test harness, etc.)
    $ritRoot = Join-Path $work ($Name + '-rit-scc')
    $null = New-Item -ItemType Directory -Path $ritRoot -Force
    $deskDir = Join-Path $work ($Name + '-desktop')
    $null = New-Item -ItemType Directory -Path $deskDir -Force
    foreach ($ps in @(Get-ChildItem -Path $dir -Filter '*.ps1' -Recurse -File)) {
        if ($ps.Name -in @('Find-OfflineRun.ps1', 'Write-PhaseMarker.ps1')) { continue }
        if ($ps.FullName -like '*\tests\*') { continue }
        Set-Content -LiteralPath $ps.FullName -Value $stubText -Encoding ASCII
    }
    # real helpers must look in the temp run root, not C:\RIT-SCC
    $find = Join-Path $dir 'tools\Find-OfflineRun.ps1'
    $txt = [IO.File]::ReadAllText($find).Replace("C:\RIT-SCC", $ritRoot)
    [IO.File]::WriteAllText($find, $txt)
    # The real run-folder lock, but trusting the (non-elevated) test account instead of
    # BUILTIN\Administrators, which this test cannot set as owner. Throwaway copy only.
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sec = Join-Path $dir 'tools\RunRootSecurity.psm1'
    $txt = [IO.File]::ReadAllText($sec)
    $pairs = @(
        @("`$script:SccTrustedWriterSids = @('S-1-5-32-544', 'S-1-5-18')", "`$script:SccTrustedWriterSids = @('$me', 'S-1-5-32-544', 'S-1-5-18')"),
        @("`$script:SccRunRootOwnerSid = 'S-1-5-32-544'", "`$script:SccRunRootOwnerSid = '$me'"))
    foreach ($pair in $pairs) {
        if (-not $txt.Contains($pair[0])) { throw ('Test-PhaseSplit: RunRootSecurity.psm1 line not found: ' + $pair[0]) }
        $txt = $txt.Replace($pair[0], $pair[1])
    }
    [IO.File]::WriteAllText($sec, $txt)
    # staged scanners so the launch prompts have something to launch
    $av = Join-Path $dir 'tools\AV'
    $null = New-Item -ItemType Directory -Path $av -Force
    Set-Content -LiteralPath (Join-Path $av 'KVRT.exe') -Value 'x'
    Set-Content -LiteralPath (Join-Path $av 'esetonlinescanner.exe') -Value 'x'
    # every .bat: pretend we are already admin, and use the temp run root
    foreach ($b in @(Get-ChildItem -Path $dir -Filter '*.bat' -File)) {
        $raw = [IO.File]::ReadAllText($b.FullName)
        $raw = $raw.Replace('{exit 0}else{exit 1}', '{exit 0}else{exit 0}').Replace('C:\RIT-SCC', $ritRoot)
        # The report copy goes to the Desktop: point it at a temp folder, never the real one.
        $raw = $raw.Replace("[Environment]::GetFolderPath('Desktop')", "'" + $deskDir + "'")
        if ($b.Name -eq 'START-HERE.bat') { $raw = Disable-ReportOpen $raw }
        [IO.File]::WriteAllText($b.FullName, $raw, [Text.Encoding]::ASCII)
    }
    if ($BatPath) {
        # baseline: the ORIGINAL START-HERE.bat, patched the same way
        $raw = [IO.File]::ReadAllText($BatPath).Replace('{exit 0}else{exit 1}', '{exit 0}else{exit 0}').Replace('C:\RIT-SCC', $ritRoot).Replace("[Environment]::GetFolderPath('Desktop')", "'" + $deskDir + "'")
        $raw = Disable-ReportOpen $raw
        [IO.File]::WriteAllText((Join-Path $dir 'START-HERE.bat'), $raw, [Text.Encoding]::ASCII)
    }
    return [pscustomobject]@{ Dir = $dir; Rit = $ritRoot }
}

function Invoke-Launcher {
    param($Harness, [string]$Launcher, [string[]]$Answers, [string]$Tag)
    $trace = Join-Path $work ($Tag + '.trace')
    $out = Join-Path $work ($Tag + '.out')
    $ans = Join-Path $work ($Tag + '.in')
    if (Test-Path -LiteralPath $trace) { Remove-Item -LiteralPath $trace -Force }
    Set-Content -LiteralPath $trace -Value '' -Encoding ASCII
    Set-Content -LiteralPath $ans -Value (($Answers + @('', '', '', '', '', '', '', '')) -join "`r`n") -Encoding ASCII
    $env:SCC_TRACE = $trace
    $env:SCC_RUNNER_CHILD = '1'      # skip the dedicated-cmd relaunch so stdin redirection works
    $bat = Join-Path $Harness.Dir $Launcher
    $cmdLine = '/d /s /c ""' + $bat + '" < "' + $ans + '" > "' + $out + '" 2>&1"'
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList $cmdLine -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit(240000)) { try { $p.Kill() } catch { }; return [pscustomobject]@{ Timeout = $true; Exit = -1; Trace = @(); Out = '' } }
    # Keep-Awake is started asynchronously by the batch, so its line has no stable position.
    $lines = @(Get-Content -LiteralPath $trace | Where-Object { $_ -and $_ -notlike 'Keep-Awake.ps1|*' })
    $outText = ''
    if (Test-Path -LiteralPath $out) { $outText = [IO.File]::ReadAllText($out) }
    return [pscustomobject]@{ Timeout = $false; Exit = $p.ExitCode; Trace = $lines; Out = $outText }
}

function New-FlagWrapper {
    # START-HERE.bat with a flag that has no shipped launcher (--stage, --select).
    param($Harness, [string]$Name, [string]$Flag)
    $text = "@echo off`r`ncall `"%~dp0START-HERE.bat`" $Flag`r`nexit /b %errorlevel%`r`n"
    [IO.File]::WriteAllText((Join-Path $Harness.Dir $Name), $text, [Text.Encoding]::ASCII)
    return $Name
}

function Has { param($Run, [string]$Script) return (@($Run.Trace | Where-Object { $_ -like ($Script + '|*') }).Count -gt 0) }
function CountOf { param($Run, [string]$Script) return @($Run.Trace | Where-Object { $_ -like ($Script + '|*') }).Count }
function Normalize {
    param($Run, $Harness)
    return @($Run.Trace | ForEach-Object {
            # the run-folder root first: it starts with the tool folder's path
            $l = $_.Replace($Harness.Rit, '<RIT>').Replace($Harness.Dir, '<TOOL>')
            $l = [regex]::Replace($l, '<RIT>\\[^\\ "]+', '<RIT>\RUN')
            $l })
}

try {
    $answersFull = @('', '', '', '', '', '', '')        # Enter on every default prompt
    # ------------------------------------------------------------------ OFFLINE
    Write-Host 'OFFLINE half' -ForegroundColor Cyan
    $h = New-Harness 'main' ''
    $off = Invoke-Launcher $h 'START-HERE-OFFLINE.bat' $answersFull 'offline'
    Check (-not $off.Timeout) 'offline launcher finished (no hang)'
    foreach ($s in 'Get-ToolPack.ps1', 'Get-AVTools.ps1', 'Invoke-GUIScanner.ps1', 'Invoke-AVUninstaller.ps1') {
        Check (-not (Has $off $s)) ('offline never runs ' + $s)
    }
    foreach ($s in 'preflight.ps1', 'detect-remote-access.ps1', 'Invoke-ReviewAndRemove.ps1', 'Invoke-PersistenceScan.ps1', 'diff-snapshots.ps1', 'New-InvestigationReport.ps1', 'Submit-ConnectWiseReport.ps1') {
        Check (Has $off $s) ('offline runs ' + $s)
    }
    Check ((CountOf $off 'collect-snapshot.ps1') -eq 2) 'offline takes the before and after snapshots'
    # Real-PC finding 2026-11-09: preflight hard-failed on the missing Sysinternals pack, which the offline half never downloads.
    $perOff = @($off.Trace | Where-Object { $_ -like 'Invoke-PersistenceScan.ps1|*' })[0]
    Check ($perOff -like '*-InventorySectionTimeoutSeconds 240*') 'offline gives the persistence inventory write more time'
    $preOff = @($off.Trace | Where-Object { $_ -like 'preflight.ps1|*' })[0]
    Check ($preOff -like '*-SkipToolPack*') 'offline passes -SkipToolPack to preflight (pack is never staged offline)'
    $submit = @($off.Trace | Where-Object { $_ -like 'Submit-ConnectWiseReport.ps1|*' })[0]
    Check ($submit -like '*-NoUpload*') 'offline builds the package with -NoUpload (no share)'
    $runs = @(Get-ChildItem -LiteralPath $h.Rit -Directory)
    Check ($runs.Count -eq 1) 'offline created exactly one run folder'
    $marker = Join-Path $runs[0].FullName 'phase-offline.json'
    Check (Test-Path -LiteralPath $marker) 'offline wrote phase-offline.json'
    if (Test-Path -LiteralPath $marker) {
        $m = [IO.File]::ReadAllText($marker) | ConvertFrom-Json
        Check ($m.Phase -eq 'offline') 'marker says phase offline'
        Check ([string]$m.FindingsJson -like '*findings.json') 'marker records the findings.json path'
    }
    Check ($off.Out -match 'OFFLINE HALF FINISHED') 'offline prints the next-step banner'
    Check (([regex]::Matches($off.Out, 'report\.html would be opened')).Count -eq 1) 'offline opens exactly one report (the final report.html of this run)'
    # Offline screen: its own steps 1-7 only, nothing about the online half's steps.
    Check ($off.Out -match 'SCREENCONNECT CLEANUP - OFFLINE') 'offline banner names the offline run'
    foreach ($s in 'STEP 1/7: Preflight', 'STEP 2/7: Before snapshot', 'STEP 3/7: Remote-access detection', 'STEP 4/7: Review/remove ScreenConnect', 'STEP 5/7: Persistence inventory and review', 'STEP 5b/7: Open review windows', 'STEP 6/7: Optional power-options repair', 'STEP 7/7: Report') {
        Check ($off.Out.Contains($s)) ('offline shows "' + $s + '"')
    }
    Check (-not ($off.Out -match 'STEP \d+[a-e]?/9')) 'offline shows no 1-9 step numbers'
    Check (-not ($off.Out -match '(?i)skipped in the offline half|Tool pack \+ KVRT|Antivirus scans|Uninstall third-party AV|1 toolpack')) 'offline does not list the online steps as skipped'
    $revOffArgs = @($off.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' })[0]
    Check ($revOffArgs -like '*-AskKeep*' -and $revOffArgs -notlike '*-SelectKeep*') 'offline review gets -AskKeep (asks "Keep any?" only when instances are found)'
    Check (-not ($off.Out -match 'Keep any ScreenConnect')) 'the launcher itself no longer asks the keep question'
    # Fix 1: the run folder the online half will continue is created locked.
    $acl = Get-Acl -LiteralPath $runs[0].FullName
    Check ($acl.AreAccessRulesProtected) 'offline run folder is created locked (no inherited C:\RIT-SCC permissions)'
    $usersWrite = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -in @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0') -and ([int64]$_.FileSystemRights -band 0x50050156) -ne 0 })
    Check ($usersWrite.Count -eq 0) 'offline run folder gives Users / Authenticated Users / Everyone no write access'

    # ------------------------------------------------------------------ ONLINE (continues that run)
    Write-Host 'ONLINE half (continuing the offline run)' -ForegroundColor Cyan
    # Fix 1: an intruder running as the user plants a newer "finished offline run" with
    # its own findings. It is not locked, so the online half must refuse it.
    $fake = Join-Path $h.Rit ($env:COMPUTERNAME + '-' + ('f' * 32))
    $null = New-Item -ItemType Directory -Path (Join-Path $fake 'detect\X') -Force
    $fakeFindings = Join-Path $fake 'detect\X\findings.json'
    '{"fake":true}' | Set-Content -LiteralPath $fakeFindings
    $fakeMarker = [ordered]@{ SchemaVersion = 1; Phase = 'offline'; FindingsJson = $fakeFindings }
    ($fakeMarker | ConvertTo-Json) | Set-Content -LiteralPath (Join-Path $fake 'phase-offline.json')
    (Get-Item -LiteralPath (Join-Path $fake 'phase-offline.json')).LastWriteTimeUtc = [DateTime]::UtcNow.AddHours(1)
    $on = Invoke-Launcher $h 'START-HERE-ONLINE.bat' $answersFull 'online'
    Check ($on.Out -match 'Not continuing .*' + [regex]::Escape(('f' * 32))) 'online refuses the planted, unlocked run folder and says why'
    Check (@($on.Trace | Where-Object { $_ -like ('*' + $fake + '*') }).Count -eq 0) 'nothing in the online half touches the planted folder'
    Remove-Item -LiteralPath $fake -Recurse -Force
    Check (-not $on.Timeout) 'online launcher finished (no hang)'
    Check ((CountOf $on 'Get-ToolPack.ps1') -eq 2) 'online stages the tool pack (download + verify)'
    Check (Has $on 'Get-AVTools.ps1') 'online stages the AV scanners'
    Check ((CountOf $on 'Invoke-GUIScanner.ps1') -eq 3) 'online launches all three scanners'
    foreach ($s in 'preflight.ps1', 'collect-snapshot.ps1', 'detect-remote-access.ps1', 'Invoke-ReviewAndRemove.ps1', 'diff-snapshots.ps1') {
        Check (-not (Has $on $s)) ('online does not repeat ' + $s)
    }
    # Fix 2: persistence check again AFTER the scans, in its own folder, then a rebuilt report.
    $perOn = @($on.Trace | Where-Object { $_ -like 'Invoke-PersistenceScan.ps1|*' })
    Check ($perOn.Count -eq 1 -and $perOn[0] -like ('*-WorkDir ' + $runs[0].FullName + '\after-scans *') -and $perOn[0] -like '*-InventorySectionTimeoutSeconds 240*') 'online runs the persistence check again, into after-scans, with the longer limits'
    $scanIdx = [array]::IndexOf($on.Trace, @($on.Trace | Where-Object { $_ -like 'Invoke-GUIScanner.ps1|*' })[-1])
    $perIdx = [array]::IndexOf($on.Trace, $perOn[0])
    $avuIdx = [array]::IndexOf($on.Trace, @($on.Trace | Where-Object { $_ -like 'Invoke-AVUninstaller.ps1|*' } | Select-Object -First 1))
    Check ($perIdx -gt $scanIdx) 'online persistence check runs after the last scanner'
    Check (Test-Path -LiteralPath (Join-Path $runs[0].FullName 'persistence\result.json')) 'the offline persistence results are left in place'
    $repOn = @($on.Trace | Where-Object { $_ -like 'New-InvestigationReport.ps1|*' })
    Check ($repOn.Count -eq 1 -and $repOn[0] -like '*after-scans\persistence\result.json*' -and $repOn[0] -like '*-OutputPath*report-after-scans.html*') 'online rebuilds the report from the after-scans persistence results'
    Check (Test-Path -LiteralPath (Join-Path $runs[0].FullName 'report.html')) 'the offline report.html is kept'
    $submitOn = @($on.Trace | Where-Object { $_ -like 'Submit-ConnectWiseReport.ps1|*' })
    Check ($submitOn.Count -eq 1) 'online shares the report once'
    if ($submitOn.Count -eq 1) {
        Check ($submitOn[0] -notlike '*-NoUpload*') 'online share is a real upload (no -NoUpload)'
        Check ($submitOn[0] -like ('*' + $runs[0].FullName + '*findings.json*')) 'online share uses the offline run findings.json'
        Check ($submitOn[0] -like '*-ReportHtml *report-after-scans.html*' -and $submitOn[0] -like '*-PersistenceResult *after-scans\persistence\result.json*') 'online shares the after-scans report and persistence results'
    }
    Check (@(Get-ChildItem -LiteralPath $h.Rit -Directory).Count -eq 1) 'online continued the same run folder (no new one)'
    Check (Test-Path -LiteralPath (Join-Path $runs[0].FullName 'phase-online.json')) 'online wrote phase-online.json'
    Check ($on.Out -match 'SCREENCONNECT CLEANUP - ONLINE') 'online banner names the online run'
    Check ($on.Out.Contains('-- 2a: KVRT --') -and $on.Out.Contains('-- 2c: Malwarebytes --') -and -not $on.Out.Contains('-- 6a:')) 'online scanner sub-steps are 2a-2c'
    foreach ($s in 'STEP 1/5: Download the tool pack', 'STEP 2/5: Antivirus scans', 'STEP 3/5: Persistence check again, after the scans', 'STEP 3b/5: Open review windows', 'STEP 4/5: Uninstall third-party AV', 'STEP 5/5: Share the report') {
        Check ($on.Out.Contains($s)) ('online shows "' + $s + '"')
    }
    Check (-not ($on.Out -match 'STEP \d+[a-e]?/9')) 'online shows no 1-9 step numbers'

    # ------------------------------------------------------------------ ONLINE with no prior run
    Write-Host 'ONLINE half (no offline run on this PC)' -ForegroundColor Cyan
    $h2 = New-Harness 'noprior' ''
    $on2 = Invoke-Launcher $h2 'START-HERE-ONLINE.bat' $answersFull 'online-noprior'
    Check (-not $on2.Timeout) 'online-without-prior finished (no hang)'
    Check ((CountOf $on2 'Invoke-GUIScanner.ps1') -eq 3) 'scanner-only run still launches the three scanners'
    Check (-not (Has $on2 'Submit-ConnectWiseReport.ps1')) 'scanner-only run shares nothing'
    Check ($on2.Out -match 'scanner-only') 'scanner-only run says so'
    Check ((CountOf $on2 'Invoke-PersistenceScan.ps1') -eq 1) 'scanner-only run still checks persistence after the scans'

    # ------------------------------------------------------------------ STAGE
    Write-Host 'STAGE (download only)' -ForegroundColor Cyan
    $h3 = New-Harness 'stage' ''
    $st = Invoke-Launcher $h3 (New-FlagWrapper $h3 'stage-wrapper.bat' '--stage') @('') 'stage'
    Check (-not $st.Timeout) 'stage launcher finished (no hang)'
    Check ((CountOf $st 'Get-ToolPack.ps1') -eq 2 -and (Has $st 'Get-AVTools.ps1')) 'stage downloads the pack and the scanners'
    $others = @($st.Trace | Where-Object { $_ -notlike 'Get-ToolPack.ps1|*' -and $_ -notlike 'Get-AVTools.ps1|*' })
    Check ($others.Count -eq 0) 'stage runs nothing else (no battery check, preflight, scanners)'
    Check (@(Get-ChildItem -LiteralPath $h3.Rit -Directory).Count -eq 0) 'stage creates no run folder'

    # ------------------------------------------------------------------ FULL run, default behavior
    Write-Host 'FULL run (no flag)' -ForegroundColor Cyan
    $h4 = New-Harness 'full' ''
    $full = Invoke-Launcher $h4 'START-HERE.bat' $answersFull 'full'
    Check (-not $full.Timeout) 'full run finished (no hang)'
    foreach ($s in 'Get-ToolPack.ps1', 'Get-AVTools.ps1', 'preflight.ps1', 'detect-remote-access.ps1', 'Invoke-ReviewAndRemove.ps1', 'Invoke-GUIScanner.ps1', 'Invoke-PersistenceScan.ps1', 'diff-snapshots.ps1', 'New-InvestigationReport.ps1', 'Submit-ConnectWiseReport.ps1') {
        Check (Has $full $s) ('full run still runs ' + $s)
    }
    $submitFull = @($full.Trace | Where-Object { $_ -like 'Submit-ConnectWiseReport.ps1|*' })[0]
    Check ($submitFull -notlike '*-NoUpload*') 'full run still uploads (no -NoUpload)'
    $preFull = @($full.Trace | Where-Object { $_ -like 'preflight.ps1|*' })[0]
    Check ($preFull -notlike '*-SkipToolPack*') 'full run still requires the tool pack in preflight'
    foreach ($s in 'STEP 1/9: Tool pack + KVRT/ESET staging (Malwarebytes fallback at Step 6)', 'STEP 2/9: Preflight', 'STEP 5/9: Review/remove ScreenConnect', 'STEP 6/9: Antivirus scans', 'STEP 6d/9', 'STEP 7/9', 'STEP 8/9', 'STEP 9/9: Report') {
        Check ($full.Out.Contains($s)) ('full run still shows "' + $s + '"')
    }
    Check (-not ($full.Out -match 'Keep any ScreenConnect')) 'full run does not ask the keep question'
    Check ($full.Out.Contains('-- 6a: KVRT --') -and $full.Out.Contains('-- 6c: Malwarebytes --')) 'full run keeps scanner sub-steps 6a-6c'
    Check (@(Get-ChildItem -LiteralPath (Join-Path $work 'full-desktop') -Filter 'report.html').Count -eq 1) 'report Desktop copy went to the test folder, not the real Desktop'
    $perFull = @($full.Trace | Where-Object { $_ -like 'Invoke-PersistenceScan.ps1|*' })[0]
    Check ($perFull -notlike '*Timeout*') 'full run keeps the default persistence timeouts'
    $pfSrc = [IO.File]::ReadAllText((Join-Path $ToolRoot 'preflight.ps1'))
    Check ((Get-Acl -LiteralPath (@(Get-ChildItem -LiteralPath $h4.Rit -Directory)[0].FullName)).AreAccessRulesProtected -eq $false) 'full run folder is created exactly as before (not locked)'
    Check (($pfSrc -match '\[switch\]\$SkipToolPack') -and ($pfSrc -match 'if \(\$SkipToolPack\)')) 'preflight.ps1 declares -SkipToolPack and branches on it before the pack check'

    if ($OriginalBat) {
        Write-Host 'FULL run vs the ORIGINAL START-HERE.bat' -ForegroundColor Cyan
        $h5 = New-Harness 'orig' $OriginalBat
        $orig = Invoke-Launcher $h5 'START-HERE.bat' $answersFull 'orig'
        $a = Normalize $full $h4
        $b = Normalize $orig $h5
        Check (($a -join "`n") -eq ($b -join "`n")) ('full-run trace is identical to the original (' + $a.Count + ' calls)')
        if (($a -join "`n") -ne ($b -join "`n")) {
            Write-Host '  --- new:' ; $a | ForEach-Object { Write-Host ('  ' + $_) }
            Write-Host '  --- original:' ; $b | ForEach-Object { Write-Host ('  ' + $_) }
        }
    }

    # ------------------------------------------------------------------ static contract checks
    # ------------------------------------------------------------------ SELECT mode (keep chosen ScreenConnect instances)
    Write-Host 'SELECT mode' -ForegroundColor Cyan
    $revOff = @($off.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' })[0]
    Check ($revOff -notlike '*-SelectKeep*') 'offline does not force select mode (the review asks first)'
    Check ($submitFull -ne $null -and (@($full.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' })[0]) -notlike '*-SelectKeep*') 'plain full run does not use select mode'
    $h6 = New-Harness 'selfull' ''
    $selFull = Invoke-Launcher $h6 (New-FlagWrapper $h6 'select-wrapper.bat' '--select') $answersFull 'selfull'
    Check (-not $selFull.Timeout) 'START-HERE.bat --select finished (no hang)'
    Check ((@($selFull.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' })[0]) -like '*-SelectKeep*') 'START-HERE.bat --select runs the review in select mode'
    Check ((Has $selFull 'Get-ToolPack.ps1') -and (Has $selFull 'Invoke-GUIScanner.ps1')) 'START-HERE.bat --select is still the full run (stages + scanners)'
    Check ($selFull.Out -match 'SELECT MODE') 'START-HERE.bat --select says it is in select mode at Step 5'
    Check ((@($full.Trace | Where-Object { $_ -like 'Invoke-ReviewAndRemove.ps1|*' })[0]) -notlike '*-AskKeep*') 'full run never asks the keep question'
    $shipped = @(Get-ChildItem -LiteralPath $ToolRoot -Filter 'START-HERE*.bat' -File | ForEach-Object { $_.Name } | Sort-Object)
    # START-HERE-GUI.bat is the window front end (docs/14); it is covered by tests\gui\, not by this harness.
    $want = @('START-HERE-GUI.bat', 'START-HERE-OFFLINE.bat', 'START-HERE-ONLINE.bat', 'START-HERE.bat') | Sort-Object
    Check (($shipped -join ',') -eq ($want -join ',')) ('only the two launchers beside the engine, plus the GUI launcher (' + ($shipped -join ', ') + ')')
    Check (-not (Test-Path -LiteralPath (Join-Path $ToolRoot 'STAGE-TOOLS-ONLINE.bat'))) 'STAGE-TOOLS-ONLINE.bat is gone'
    Write-Host 'Static checks' -ForegroundColor Cyan
    $bat = [IO.File]::ReadAllText((Join-Path $ToolRoot 'START-HERE.bat'))
    Check ($bat.Contains('$env:SCC_PHASE_ARG')) 'UAC relaunch carries the phase flag'
    Check ($bat.Contains('SCC_PHASE_ARG=!SCC_PHASE_ARG! --select')) 'UAC relaunch also carries --select'
    Check ($bat.Contains("--elevation-attempted") -and $bat.Contains('-Verb RunAs')) 'single UAC relaunch with the loop guard is still present'
    Check (-not [regex]::IsMatch($bat, '[^\x00-\x7F]')) 'START-HERE.bat is pure ASCII'
    $crlf = ([regex]::Matches($bat, "`r`n")).Count; $lf = ([regex]::Matches($bat, "`n")).Count
    Check ($crlf -eq $lf) 'START-HERE.bat is CRLF throughout'
} finally {
    Remove-Item Env:\SCC_TRACE -ErrorAction SilentlyContinue
    Remove-Item Env:\SCC_RUNNER_CHILD -ErrorAction SilentlyContinue
    if ($KeepWork) { Write-Host ('Work folder kept: ' + $work) -ForegroundColor Yellow }
    elseif (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0
