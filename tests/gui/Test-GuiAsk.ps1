<#
  Test-GuiAsk.ps1 - the "Ask" mechanism of gui\Gui.Core.psm1: the points where the window stops and
  asks the technician what START-HERE.bat asks (what to keep, which scanners, review windows, AV
  uninstall, power repair). No window and no process is started: the plan is walked in memory.

  Checks: a non-interactive session (the headless parity tests) never asks; an interactive one asks
  each question once, at the right step, only when the step would otherwise run; the answers feed
  the same arguments the batch file builds; unknown or foreign answers are refused.

  No admin, no network. Windows PowerShell 5.1, pure ASCII, no BOM.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Failures = New-Object System.Collections.ArrayList
$script:Passes = 0
function Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passes++; Write-Host ('  [pass] ' + $Message) -ForegroundColor Green }
    else { [void]$script:Failures.Add($Message); Write-Host ('  [FAIL] ' + $Message) -ForegroundColor Red }
}

Import-Module (Join-Path $ToolRoot 'gui\Gui.Core.psm1') -Force
$work = Join-Path $env:TEMP ('scc-gui-ask-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force

function New-Walk {
    # A session whose run folder already holds what the earlier steps would have written, so the plan can be
    # walked without running anything.
    param([string]$Mode, [switch]$Interactive, [switch]$NoFindings, [hashtable]$Answers)
    $rit = Join-Path $work ($Mode + '-' + [guid]::NewGuid().ToString('N'))
    $params = @{ Mode = $Mode; ToolRoot = $ToolRoot; RitRoot = $rit }
    if ($Answers) { $params.Answers = $Answers }
    $s = New-GuiSession @params -Interactive:$Interactive
    $run = New-GuiRunRoot -Session $s
    Set-Content -LiteralPath (Join-Path $run 'snapshot_before.json') -Value '{}'
    if (-not $NoFindings) {
        $d = Join-Path $run 'detect\HOST_20260101_000000'
        $null = New-Item -ItemType Directory -Path $d -Force
        Set-Content -LiteralPath (Join-Path $d 'findings.json') -Value '{"ScreenConnect":{"Instances":[]}}'
    }
    return $s
}
function Invoke-Walk {
    # Walks the plan. Ask actions are answered with $Responder (scriptblock: param($ask) -> hashtable). Returns the order seen.
    param($Session, [scriptblock]$Responder)
    $seen = New-Object System.Collections.ArrayList
    $guard = 0
    while ($true) {
        $a = Get-GuiNextAction -Session $Session
        if (-not $a) { break }
        $guard++; if ($guard -gt 60) { throw 'walk did not end' }
        if ($a.Kind -eq 'Ask') { [void]$seen.Add('ASK:' + $a.Ask + '@' + $a.StepId); Set-GuiAnswer -Session $Session -Ask $a.Ask -Values (& $Responder $a.Ask); continue }
        [void]$seen.Add($a.StepId)
        if ($a.StepId -eq '8a' ) { '{}' | Set-Content -LiteralPath ($Session.RunRoot + '\power-options-repair.json') }
        if ($a.StepId -eq '9a') { '<html></html>' | Set-Content -LiteralPath ($Session.RunRoot + '\report.html') }
        if ($a.Kind -eq 'Builtin') { [void](Complete-GuiAction -Session $Session -Action $a -ExitCode 0); continue }
        if ($a.StepId -eq '4') { Find-GuiFindings -Session $Session }
        [void](Complete-GuiAction -Session $Session -Action $a -ExitCode 0)
    }
    return @($seen.ToArray())
}
$yes = { param($ask) switch ($ask) {
        'KeepSelection' { @{ KeepIdentifiers = @('aaaa1111aaaa1111', 'cccc3333cccc3333') } }
        'Scanners' { @{ ScanKvrt = $true; ScanEset = $true; ScanMalwarebytes = $true } }
        'OpenReview' { @{ OpenReview = $true } }
        'AvUninstall' { @{ Avu = $true } }
        'PowerRepair' { @{ PowerRepair = $true; ResetGpo = $true } } } }

try {
    Write-Host 'Non-interactive sessions never ask (the parity tests rely on it)' -ForegroundColor Cyan
    foreach ($m in 'Full', 'Offline', 'Online', 'Detect') {
        $s = New-Walk $m
        $seen = Invoke-Walk $s $yes
        Check (@($seen | Where-Object { $_ -like 'ASK:*' }).Count -eq 0) ($m + ': no question is asked without -Interactive')
    }

    Write-Host 'Offline, interactive: the questions come in the batch file''s places' -ForegroundColor Cyan
    $s = New-Walk 'Offline' -Interactive
    $seen = Invoke-Walk $s $yes
    $txt = $seen -join ' '
    # (8c, the diff, is skipped here: this walk runs no scripts, so no after-snapshot exists.)
    Check ($txt -match '^2 3 4 ASK:KeepSelection@5 5 6d ASK:OpenReview@6e 6e ASK:PowerRepair@8a 8a 8b (8c )?9a 9b 9c M$') ('order: ' + $txt)
    $five = @($s.Results | Where-Object { $_.StepId -eq '5' })[0]
    Check ($null -ne $five) 'step 5 ran after its question'

    Write-Host 'The answers become the batch file''s arguments' -ForegroundColor Cyan
    $s = New-Walk 'Offline' -Interactive
    $a = $null
    do { $a = Get-GuiNextAction -Session $s; if ($a.Kind -eq 'Run') { [void](Complete-GuiAction -Session $s -Action $a -ExitCode 0) } } until ($a.Kind -eq 'Ask')
    Check ($a.Ask -eq 'KeepSelection') 'the first question is the keep selection'
    Set-GuiAnswer -Session $s -Ask 'KeepSelection' -Values @{ KeepIdentifiers = @('aaaa1111aaaa1111', 'cccc3333cccc3333') }
    $a = Get-GuiNextAction -Session $s
    Check ($a.Kind -eq 'Run' -and $a.StepId -eq '5') 'after the answer the review step runs'
    $i = [array]::IndexOf($a.Args, '-KeepIdentifier')
    Check ($i -ge 0 -and $a.Args[$i + 1] -eq 'aaaa1111aaaa1111,cccc3333cccc3333') 'two kept instances become ONE comma-joined -KeepIdentifier value'
    $s2 = New-Walk 'Offline' -Interactive
    do { $a = Get-GuiNextAction -Session $s2; if ($a.Kind -eq 'Run') { [void](Complete-GuiAction -Session $s2 -Action $a -ExitCode 0) } } until ($a.Kind -eq 'Ask')
    Set-GuiAnswer -Session $s2 -Ask 'KeepSelection' -Values @{ KeepIdentifiers = @() }
    $a = Get-GuiNextAction -Session $s2
    Check (@($a.Args | Where-Object { $_ -like '-Keep*' -or $_ -eq '-SelectKeep' }).Count -eq 0) 'keeping nothing adds no keep argument: remove all, the batch file''s default'

    Write-Host 'Asked only when the step would otherwise run' -ForegroundColor Cyan
    $s = New-Walk 'Offline' -Interactive -NoFindings
    # no findings.json: the review step is skipped, so no keep question
    $a = $null; $asks = @()
    $guard = 0
    while ($a = Get-GuiNextAction -Session $s) {
        $guard++; if ($guard -gt 40) { break }
        if ($a.Kind -eq 'Ask') { $asks += $a.Ask; Set-GuiAnswer -Session $s -Ask $a.Ask -Values (& $yes $a.Ask); continue }
        if ($a.StepId -eq '4') { [void](Complete-GuiAction -Session $s -Action $a -ExitCode 0); continue }
        [void](Complete-GuiAction -Session $s -Action $a -ExitCode 0)
    }
    Check ($asks -notcontains 'KeepSelection') 'no findings.json: the keep question is not asked (step 5 is skipped)'

    Write-Host 'Online, interactive: scanners asked once for three steps' -ForegroundColor Cyan
    $s = New-Walk 'Online' -Interactive
    $s.ScannerOnly = $false
    $seen = Invoke-Walk $s $yes
    Check (@($seen | Where-Object { $_ -like 'ASK:Scanners*' }).Count -eq 1) 'the scanners question is asked once, not once per scanner'
    # (Step 1 is three calls. 6a and 6b are passed over when KVRT / ESET are not staged in this checkout, as they should be.)
    # (Since 1.8.12-beta.1-offline.3 the online half checks persistence again after the scans: 6d, then the review windows.)
    Check (($seen -join ' ') -match '^1 1 1 ASK:Scanners@6a (6a )?(6b )?6c 6d ASK:OpenReview@6e 6e ASK:AvUninstall@7 7 ') ('order: ' + ($seen -join ' '))
    $s = New-Walk 'Online' -Interactive
    $none = { param($ask) switch ($ask) { 'Scanners' { @{ ScanKvrt = $false; ScanEset = $false; ScanMalwarebytes = $false } } 'OpenReview' { @{ OpenReview = $false } } 'AvUninstall' { @{ Avu = $false } } } }
    $seen = Invoke-Walk $s $none
    Check (@($s.Results | Where-Object { $_.StepId -in '6a', '6b', '6c', '7' -and $_.Status -eq 'Skipped' }).Count -eq 4) 'declining every scan and the uninstall skips all four steps'

    Write-Host 'Full and Detect' -ForegroundColor Cyan
    $s = New-Walk 'Full' -Interactive
    $seen = Invoke-Walk $s $yes
    $asks = @($seen | Where-Object { $_ -like 'ASK:*' })
    Check (($asks -join ',') -eq 'ASK:KeepSelection@5,ASK:Scanners@6a,ASK:OpenReview@6e,ASK:AvUninstall@7,ASK:PowerRepair@8a') ('full run asks, in order: ' + ($asks -join ', '))
    $s = New-Walk 'Detect' -Interactive
    $seen = Invoke-Walk $s $yes
    Check (@($seen | Where-Object { $_ -like 'ASK:*' }).Count -eq 0) 'detect only asks nothing'

    Write-Host 'Answers are validated' -ForegroundColor Cyan
    $s = New-Walk 'Full' -Interactive
    $threw = $false; try { Set-GuiAnswer -Session $s -Ask 'KeepSelection' -Values @{ Avu = $true } } catch { $threw = $true }
    Check $threw 'an answer cannot set a value that belongs to another question'
    $threw = $false; try { Set-GuiAnswer -Session $s -Ask 'RemoveEverything' -Values @{} } catch { $threw = $true }
    Check $threw 'an unknown question is refused'
    Check ($s.Answers['Avu'] -eq $false -and $s.Answers['PowerRepair'] -eq $false) 'defaults stay the batch file''s defaults (AV uninstall N, power repair N)'
    Check (-not $s.Answers.ContainsKey('Remove') -and -not $s.Answers.ContainsKey('ConfirmRemoval')) 'there is no stored removal approval anywhere in the session'
} finally {
    if ($work -match 'scc-gui-ask-[0-9a-f]{32}$' -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0
