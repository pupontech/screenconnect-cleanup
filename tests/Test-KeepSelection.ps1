<#
  Test-KeepSelection.ps1 - runs the REAL Invoke-ReviewAndRemove.ps1 (not a stub) against a
  synthetic findings.json with three ScreenConnect instances and scripted answers, and checks
  what plan.json / kept-instances.json contain. -WhatIfOnly keeps the removal engine out of it.
  No admin, no network, nothing outside a temp folder is touched.

  Windows PowerShell 5.1. Pure ASCII, no BOM.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0
function Check([bool]$Ok, [string]$Name) {
    if ($Ok) { $script:pass++; Write-Host ('  [pass] ' + $Name) -ForegroundColor Green }
    else { $script:fail++; Write-Host ('  [FAIL] ' + $Name) -ForegroundColor Red }
}

$work = Join-Path $env:TEMP ('scc-keep-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force

function New-Findings([string]$Dir, [switch]$Empty) {
    $null = New-Item -ItemType Directory -Path $Dir -Force
    $mk = {
        param($id, $relay, $dir)
        [ordered]@{
            Key = 'svc:' + $id; Identifier = $id; InstallDir = $dir
            ServiceName = 'ScreenConnect Client (' + $id + ')'; ServiceState = 'Running'
            RelayHost = $relay; RelayPort = 8041; SessionType = 'Support'
            File = [ordered]@{ SignatureStatus = 'Valid'; SignerSubject = 'CN=Elsinore Technologies' }
            InstallDirCreatedUtc = '2026-01-02 03:04:05'
        }
    }
    $doc = [ordered]@{
        Tool = 'detect-remote-access.ps1'; Version = 'test'; RunId = 'T'; ComputerName = 'TESTPC'
        ScreenConnect = [ordered]@{
            Instances = @(
                (& $mk 'aaaa1111aaaa1111' 'evil.example.net' 'C:\Program Files (x86)\ScreenConnect Client (aaaa1111aaaa1111)'),
                (& $mk 'bbbb2222bbbb2222' 'support.customer.example' 'C:\Program Files (x86)\ScreenConnect Client (bbbb2222bbbb2222)'),
                (& $mk 'cccc3333cccc3333' 'other.example.org' 'C:\Program Files (x86)\ScreenConnect Client (cccc3333cccc3333)')
            )
            ParseIssues = @(); Historical = @(); RawFilesSaved = @()
        }
        OtherTargets = @()
    }
    if ($Empty) { $doc.ScreenConnect.Instances = @() }
    $path = Join-Path $Dir 'findings.json'
    $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Invoke-Review([string]$Name, [string[]]$Switches, [string]$Stdin, [switch]$NoInstances) {
    $dir = Join-Path $work $Name
    $findings = New-Findings (Join-Path $dir 'detect\RUN_1') -Empty:$NoInstances
    $wd = Join-Path $dir 'wd'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + (Join-Path $ToolRoot 'Invoke-ReviewAndRemove.ps1') + '"'),
                 '-FindingsJson', ('"' + $findings + '"'), '-WorkDir', ('"' + $wd + '"'), '-MinFreeGB', '0', '-WhatIfOnly') + $Switches
    $psi.Arguments = ($argList -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Write($Stdin)
    $p.StandardInput.Close()
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    if (-not $p.WaitForExit(60000)) { try { $p.Kill() } catch { } ; $timeout = $true } else { $timeout = $false }
    $planPath = Join-Path $wd 'plan.json'
    $keptPath = Join-Path $wd 'kept-instances.json'
    $plan = $null; $kept = $null
    if (Test-Path -LiteralPath $planPath) { $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json }
    if (Test-Path -LiteralPath $keptPath) { $kept = Get-Content -LiteralPath $keptPath -Raw | ConvertFrom-Json }
    return [pscustomobject]@{ Exit = $(if ($timeout) { -1 } else { $p.ExitCode }); Out = $out + $err; Plan = $plan; Kept = $kept; Timeout = $timeout }
}
function Ids($list) { return @(@($list) | ForEach-Object { $_.Identifier }) -join ',' }

try {
    Write-Host 'Default mode (no select switches) - must be unchanged' -ForegroundColor Cyan
    $r = Invoke-Review 'default' @() "y`n"
    Check ($r.Exit -eq 0) 'default: exits 0'
    Check ($r.Plan.Decision -eq 'ALL_REMOVE') 'default: decision ALL_REMOVE'
    Check ((@($r.Plan.ScreenConnectInstances)).Count -eq 3) 'default: all 3 instances in the plan'
    Check ($null -eq $r.Plan.PSObject.Properties['KeptScreenConnectInstances']) 'default: plan has no kept list'
    Check ($null -eq $r.Kept) 'default: no kept-instances.json'
    Check ($r.Out -match 'Remove all detected ScreenConnect instances\?') 'default: original prompt text'
    Check ($r.Out -notmatch 'SELECT MODE') 'default: no select-mode text'

    Write-Host 'Select mode, interactive' -ForegroundColor Cyan
    $r = Invoke-Review 'keep2' @('-SelectKeep') "2`ny`n"
    Check ($r.Exit -eq 0 -and -not $r.Timeout) 'keep 2: finished'
    Check ($r.Plan.Decision -eq 'PARTIAL_REMOVE') 'keep 2: decision PARTIAL_REMOVE'
    Check ((Ids $r.Plan.ScreenConnectInstances) -eq 'aaaa1111aaaa1111,cccc3333cccc3333') 'keep 2: plan removes only 1 and 3'
    Check ((Ids $r.Plan.KeptScreenConnectInstances) -eq 'bbbb2222bbbb2222') 'keep 2: plan records 2 as kept'
    Check ($r.Kept -and (Ids $r.Kept.Kept) -eq 'bbbb2222bbbb2222') 'keep 2: kept-instances.json lists 2'
    Check ($r.Out -match 'support\.customer\.example:8041') 'keep 2: relay host and port shown for choosing'
    Check ($r.Out -match 'Remove the instances that are NOT kept\?') 'keep 2: select-mode confirm prompt'

    $r = Invoke-Review 'keep13' @('-SelectKeep') "1, 3`ny`n"
    Check ((Ids $r.Plan.ScreenConnectInstances) -eq 'bbbb2222bbbb2222' -and (Ids $r.Plan.KeptScreenConnectInstances) -eq 'aaaa1111aaaa1111,cccc3333cccc3333') 'keep "1, 3": removes only 2'

    $r = Invoke-Review 'keepall' @('-SelectKeep') "a`n"
    Check ($r.Exit -eq 0) 'keep all: exits 0'
    Check ($null -eq $r.Plan) 'keep all: no plan.json (nothing to remove)'
    Check ($r.Kept -and @($r.Kept.Kept).Count -eq 3) 'keep all: kept-instances.json lists all 3'
    Check ($r.Out -match 'nothing to remove') 'keep all: says nothing to remove'

    $r = Invoke-Review 'keepnone' @('-SelectKeep') "`ny`n"
    Check ($r.Plan.Decision -eq 'ALL_REMOVE' -and @($r.Plan.ScreenConnectInstances).Count -eq 3) 'Enter (keep none): removes all 3'
    Check ($null -eq $r.Kept) 'Enter (keep none): no kept-instances.json'

    $r = Invoke-Review 'badthenok' @('-SelectKeep') "9`nx`n2`ny`n"
    Check ($r.Out -match 'not in the list' -and $r.Out -match "'x' is not a number") 'bad input is rejected with a reason, not guessed'
    Check ((Ids $r.Plan.KeptScreenConnectInstances) -eq 'bbbb2222bbbb2222') 'bad input then 2: keeps 2'

    $r = Invoke-Review 'declined' @('-SelectKeep') "2`nn`n"
    Check ($r.Exit -eq 0 -and $null -eq $r.Plan -and $null -eq $r.Kept) 'answering n: nothing written, nothing removed'

    $r = Invoke-Review 'eof' @('-SelectKeep') ''
    Check ($r.Exit -eq 0 -and -not $r.Timeout -and $null -eq $r.Plan) 'empty stdin: ends without hanging or removing'

    Write-Host 'Offline launcher (-AskKeep): "Keep any?" only when something was found' -ForegroundColor Cyan
    $r = Invoke-Review 'ask-enter' @('-AskKeep') "`ny`n"
    Check ($r.Out -match 'Keep any ScreenConnect\?') '-AskKeep with instances: asks "Keep any?"'
    Check ($r.Out -match '\[2\] bbbb2222bbbb2222' -and $r.Out -match 'support\.customer\.example:8041') '-AskKeep: shows the numbered list with relay host:port before asking'
    Check ($r.Plan.Decision -eq 'ALL_REMOVE' -and @($r.Plan.ScreenConnectInstances).Count -eq 3) '-AskKeep, Enter: removes all 3 (default unchanged)'
    Check ($null -eq $r.Kept -and $r.Out -notmatch 'Numbers to KEEP') '-AskKeep, Enter: no picker, no kept-instances.json'
    Check ($r.Out -match 'Remove all detected ScreenConnect instances\?') '-AskKeep, Enter: the original remove-all prompt'

    $r = Invoke-Review 'ask-yes' @('-AskKeep') "y`n2`ny`n"
    Check ($r.Out -match 'Numbers to KEEP') '-AskKeep, y: switches to the picker'
    Check ($r.Plan.Decision -eq 'PARTIAL_REMOVE' -and (Ids $r.Plan.KeptScreenConnectInstances) -eq 'bbbb2222bbbb2222') '-AskKeep, y then 2: keeps 2, removes 1 and 3'

    $r = Invoke-Review 'ask-eof' @('-AskKeep') ''
    Check ($r.Exit -eq 0 -and -not $r.Timeout -and $null -eq $r.Plan) '-AskKeep, empty stdin: ends without hanging or removing'

    $r = Invoke-Review 'ask-none' @('-AskKeep') "`n" -NoInstances
    Check ($r.Exit -eq 0 -and $r.Out -match 'nothing to remove') '-AskKeep, nothing found: says nothing to remove'
    Check ($r.Out -notmatch 'Keep any ScreenConnect') '-AskKeep, nothing found: the question is NOT asked'

    $r = Invoke-Review 'ask-select' @('-AskKeep', '-SelectKeep') "2`ny`n"
    Check ($r.Out -notmatch 'Keep any ScreenConnect' -and (Ids $r.Plan.KeptScreenConnectInstances) -eq 'bbbb2222bbbb2222') '-AskKeep with -SelectKeep: no extra question, straight to the picker'

    Write-Host 'Select mode, non-interactive (-KeepIdentifier)' -ForegroundColor Cyan
    $r = Invoke-Review 'byid' @('-KeepIdentifier', 'BBBB2222BBBB2222') "y`n"
    Check ($r.Plan.Decision -eq 'PARTIAL_REMOVE' -and (Ids $r.Plan.KeptScreenConnectInstances) -eq 'bbbb2222bbbb2222') '-KeepIdentifier keeps the matching instance (case-insensitive)'
    Check ($r.Out -notmatch 'Numbers to KEEP') '-KeepIdentifier does not ask the picker question'

    $r = Invoke-Review 'typo' @('-KeepIdentifier', 'bbbb2222bbbb222') "y`n"
    Check ($r.Exit -eq 2) '-KeepIdentifier typo: exit 2'
    Check ($null -eq $r.Plan) '-KeepIdentifier typo: nothing written, so nothing can be removed'

    Write-Host 'Plan the removal engine will receive' -ForegroundColor Cyan
    $r = Invoke-Review 'engine' @('-SelectKeep') "2`ny`n"
    $remover = Join-Path $ToolRoot 'remove-screenconnect.ps1'
    Check ((Get-Content -LiteralPath $remover -Raw) -match "PARTIAL_REMOVE") 'remove-screenconnect.ps1 accepts the PARTIAL_REMOVE decision'
    $planText = Get-Content -LiteralPath (Join-Path $work 'engine\wd\plan.json') -Raw
    Check ($planText -match '"SourceFindingsSha256"' -and $planText -match '"RemovalConfirmed":\s*true') 'plan keeps the provenance fields the remover requires'

    Write-Host 'Report labels kept instances' -ForegroundColor Cyan
    $f = Join-Path $work 'engine\detect\RUN_1\findings.json'
    $out = Join-Path $work 'engine\report.html'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ToolRoot 'New-InvestigationReport.ps1') -FindingsJson $f -KeptInstances (Join-Path $work 'engine\wd\kept-instances.json') -OutputPath $out | Out-Null
    $html = if (Test-Path -LiteralPath $out) { Get-Content -LiteralPath $out -Raw } else { '' }
    Check ($html.Length -gt 0) 'report builds with -KeptInstances'
    Check ([regex]::Matches($html, 'KEPT:').Count -eq 1) 'report marks exactly one instance KEPT'
    Check ($html -match '1 kept as legitimate') 'report heading says how many were kept'
    $out2 = Join-Path $work 'engine\report2.html'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ToolRoot 'New-InvestigationReport.ps1') -FindingsJson $f -OutputPath $out2 | Out-Null
    $html2 = if (Test-Path -LiteralPath $out2) { Get-Content -LiteralPath $out2 -Raw } else { '' }
    Check ($html2.Length -gt 0 -and $html2 -notmatch 'KEPT:') 'report without -KeptInstances shows no KEPT label'
}
finally {
    if ($work -and $work.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase) -and $work -match 'scc-keep-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host ('Result: ' + $script:pass + ' passed, ' + $script:fail + ' failed')
if ($script:fail -gt 0) { exit 1 }
exit 0
