<#
  Test-GuiPromptHandling.ps1 - drives REAL child powershell.exe processes through Gui.Core:
  output pumped without a newline, prompts recognised from the unfinished line, answers written
  to stdin as raw bytes, window-X = the refusing answer, the unknown-prompt fallback, exit codes,
  big output, and Stop-GuiChild. Also runs the real Invoke-ReviewAndRemove.ps1 (with
  -WhatIfOnly, so nothing is ever removed) to prove y / n / -KeepIdentifier a,b end to end.

  Spikes S1 and S2 of docs/14-gui-architecture.md live here as regression tests, including the
  UTF-8 console trap: on code page 65001 a redirected 5.1 child returns U+FEFF + "y" from
  Read-Host unless the GUI first switches the shared console to an OEM page.

  No admin, no network, no engine changes. Windows PowerShell 5.1, pure ASCII, no BOM.
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
$cpBefore = $null
try { $cpBefore = [Console]::OutputEncoding.CodePage } catch { }
$consoleSaved = Set-GuiConsoleEncoding
$work = Join-Path $env:TEMP ('scc-gui-prompt-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force

function Write-Script {
    param([string]$Name, [string]$Body)
    $p = Join-Path $work $Name
    Set-Content -LiteralPath $p -Value $Body -Encoding ASCII
    return $p
}

function Wait-GuiChild {
    # Pump like the window's timer does. $OnPrompt gets the pending prompt (or $null) each tick.
    param($Child, [scriptblock]$OnPrompt, [int]$TimeoutSeconds = 60, [int]$QuietSeconds = 5)
    $lines = New-Object System.Collections.ArrayList
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 100
        $u = Update-GuiChild -Child $Child
        foreach ($l in $u.Lines) { [void]$lines.Add($l) }
        if ($u.Exited) { return [pscustomobject]@{ Exited = $true; ExitCode = $u.ExitCode; Lines = @($lines.ToArray()) } }
        if ($OnPrompt) {
            $pp = Get-GuiPendingPrompt -Child $Child -QuietSeconds $QuietSeconds
            if ($pp) { & $OnPrompt $pp $Child }
        }
    }
    Stop-GuiChild $Child
    return [pscustomobject]@{ Exited = $false; ExitCode = $null; Lines = @($lines.ToArray()) }
}

try {
    Write-Host 'Console code page' -ForegroundColor Cyan
    if ($cpBefore -eq 65001) {
        Check ([Console]::OutputEncoding.CodePage -eq 437 -and $consoleSaved.Changed) 'UTF-8 console (65001) was switched to OEM 437 for the GUI'
    } else {
        Check (-not $consoleSaved.Changed) ('a non-UTF-8 console (' + $cpBefore + ') is left alone')
    }

    Write-Host 'Known prompts: seen without a newline, answered with raw bytes' -ForegroundColor Cyan
    $promptBody = @'
param([string]$Text, [string]$Tag)
Write-Host 'line before the prompt'
Write-Host $Text -NoNewline
$a = Read-Host
Write-Host ''
Write-Host ('GOT[' + $Tag + ']=<' + $a + '> len=' + $a.Length)
exit 7
'@
    $ps = Write-Script 'prompt.ps1' $promptBody
    $cases = @(
        @{ Id = 'LowDisk'; Text = 'Continue anyway? [y/N]'; Send = 'y'; Expect = 'y' },
        @{ Id = 'LowDisk'; Text = 'Continue anyway? [y/N]'; Send = 'n'; Expect = 'n' },
        @{ Id = 'UacDisabled'; Text = 'Type Y once UAC is enabled, or F to force-continue with UAC disabled'; Send = 'F'; Expect = 'F' },
        @{ Id = 'RemoveConfirm'; Text = 'Remove all detected ScreenConnect instances? [y/N]'; Send = 'y'; Expect = 'y' },
        @{ Id = 'RemoveConfirm'; Text = 'Remove the instances that are NOT kept? [y/N]'; Send = 'n'; Expect = 'n' }
    )
    $i = 0
    foreach ($c in $cases) {
        $i++
        $child = Start-GuiChild -ScriptPath $ps -ArgumentList @($c.Text, ('c' + $i))
        $state = @{ Seen = $null; Sent = $false }
        $r = Wait-GuiChild $child {
            param($pp, $ch)
            if ($pp.Kind -eq 'Known' -and -not $state.Sent) { $state.Seen = $pp.Row.Id; Send-GuiAnswer -Child $ch -Text $c.Send; $state.Sent = $true }
        }
        $txt = $child.Transcript.ToString()
        Check ($r.Exited -and $r.ExitCode -eq 7) ($c.Id + ' "' + $c.Send + '": child finished and its exit code came back')
        Check ($state.Seen -eq $c.Id) ($c.Id + ': recognised from the unfinished line')
        Check ($txt -match ('GOT\[c' + $i + '\]=<' + $c.Expect + '> len=' + $c.Expect.Length)) ($c.Id + ': the script received exactly "' + $c.Expect + '" (no byte order mark)')
        Check ($txt -notmatch [string][char]0xFEFF) ($c.Id + ': no U+FEFF anywhere in the transcript')
        Check ($txt -match '\[GUI sent answer: ') ($c.Id + ': the answer is recorded in the transcript')
    }

    Write-Host 'Empty line = the refusing answer for the UAC prompt' -ForegroundColor Cyan
    $child = Start-GuiChild -ScriptPath $ps -ArgumentList @('Type Y once UAC is enabled, or F to force-continue with UAC disabled', 'uac')
    $row = (Get-GuiPromptTable) | Where-Object { $_.Id -eq 'UacDisabled' }
    $r = Wait-GuiChild $child { param($pp, $ch) if ($pp.Kind -eq 'Known') { Send-GuiAnswer -Child $ch -Text $row.Refuse } }
    Check ($child.Transcript.ToString() -match 'GOT\[uac\]=<> len=0') 'closing the UAC dialog sends an empty line, never Y or F'

    Write-Host 'Unknown prompt fallback' -ForegroundColor Cyan
    $unk = Write-Script 'unknown.ps1' @'
Write-Host 'working...'
Write-Host 'Pick a colour:' -NoNewline
$a = Read-Host
Write-Host ''
Write-Host ('COLOUR=' + $a)
'@
    # Answer path: the technician types a reply into the generic box.
    $child = Start-GuiChild -ScriptPath $unk -ArgumentList @()
    $st = @{ Unknown = 0; Sent = $false }
    $r = Wait-GuiChild $child {
        param($pp, $ch)
        if ($pp.Kind -eq 'Unknown') { $st.Unknown++; if (-not $st.Sent) { Send-GuiAnswer -Child $ch -Text 'blue'; $st.Sent = $true } }
    } -QuietSeconds 1
    Check ($st.Unknown -ge 1) 'an unfinished, unrecognised line raises the generic box after the quiet period'
    Check ($child.Transcript.ToString() -match 'COLOUR=blue') 'the generic box answer reaches the script'

    # Dismiss path: "this is not a question" must not pop up again for the same text.
    $child = Start-GuiChild -ScriptPath $unk -ArgumentList @()
    $st = @{ Unknown = 0; Dismissed = $false; Finished = $false }
    $stop = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $stop) {
        Start-Sleep -Milliseconds 100
        [void](Update-GuiChild -Child $child)
        $pp = Get-GuiPendingPrompt -Child $child -QuietSeconds 1
        if ($pp -and $pp.Kind -eq 'Unknown') { $st.Unknown++; Set-GuiPromptDismissed -Child $child -Text $pp.Text; $st.Dismissed = $true }
    }
    Check ($st.Dismissed -and $st.Unknown -eq 1) 'a dismissed generic box does not come back right away for the same unfinished text'
    # ...but a script blocked on Read-Host must not wait forever: after the repeat interval it comes back.
    $back = $false
    $stop = (Get-Date).AddSeconds(8)
    while ((Get-Date) -lt $stop -and -not $back) {
        Start-Sleep -Milliseconds 100
        [void](Update-GuiChild -Child $child)
        $pp = Get-GuiPendingPrompt -Child $child -QuietSeconds 1 -RepeatSeconds 3
        if ($pp -and $pp.Kind -eq 'Unknown') { $back = $true }
    }
    Check $back 'if the tool is still waiting on the same text, the box comes back after the repeat interval'
    Send-GuiAnswer -Child $child -Text 'x'
    [void](Wait-GuiChild $child $null)

    # Scanner-safe stop: ending a step with -KeepDescendants leaves what it started running.
    $spawn = Write-Script 'spawn.ps1' '$p = Start-Process -FilePath $env:ComSpec -ArgumentList "/c ping -n 30 127.0.0.1 >nul" -WindowStyle Hidden -PassThru; Write-Host ("GRANDCHILD=" + $p.Id); Start-Sleep -Seconds 60'
    $child = Start-GuiChild -ScriptPath $spawn -ArgumentList @()
    $gc = 0; $stop = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $stop -and $gc -eq 0) { Start-Sleep -Milliseconds 100; [void](Update-GuiChild -Child $child); $m = [regex]::Match($child.Transcript.ToString(), 'GRANDCHILD=(\d+)'); if ($m.Success) { $gc = [int]$m.Groups[1].Value } }
    Stop-GuiChild $child -KeepDescendants
    $child.Process.WaitForExit(5000) | Out-Null
    $gp = Get-Process -Id $gc -ErrorAction SilentlyContinue
    Check ($child.Process.HasExited -and $null -ne $gp -and -not $gp.HasExited) 'Stop-GuiChild -KeepDescendants ends the step but leaves the program it started (a scanner) running'
    if ($gp) { try { $gp.Kill() } catch { } }

    $child = Start-GuiChild -ScriptPath (Write-Script 'quiet.ps1' "Write-Host 'a complete line'`nStart-Sleep -Seconds 3`nWrite-Host 'done'") -ArgumentList @()
    $st = @{ Raised = 0 }
    $r = Wait-GuiChild $child { param($pp, $ch) $st.Raised++ } -QuietSeconds 1
    Check ($r.Exited -and $st.Raised -eq 0) 'a long quiet step that ends its lines is NOT mistaken for a question'

    Write-Host 'Output handling' -ForegroundColor Cyan
    $big = Write-Script 'big.ps1' @'
1..5000 | ForEach-Object { Write-Host ('line ' + $_) }
[Console]::Error.WriteLine('an error line')
Write-Host 'no newline at the end' -NoNewline
exit 3
'@
    $child = Start-GuiChild -ScriptPath $big -ArgumentList @()
    $r = Wait-GuiChild $child $null
    Check ($r.Exited -and $r.ExitCode -eq 3) 'exit code 3 comes back'
    Check (@($r.Lines | Where-Object { $_ -like 'line *' }).Count -eq 5000) 'all 5000 lines were drained'
    Check (@($r.Lines | Where-Object { $_ -eq '[stderr] an error line' }).Count -eq 1) 'stderr lines are kept and marked'
    Check ($r.Lines[$r.Lines.Count - 1] -eq 'no newline at the end' -or @($r.Lines | Where-Object { $_ -eq 'no newline at the end' }).Count -eq 1) 'an unfinished last line is flushed when the child exits'

    $child = Start-GuiChild -ScriptPath (Write-Script 'sleep.ps1' 'Start-Sleep -Seconds 120') -ArgumentList @()
    Start-Sleep -Milliseconds 500
    Stop-GuiChild $child
    $child.Process.WaitForExit(5000) | Out-Null
    Check $child.Process.HasExited 'Stop-GuiChild ends a running child'

    $argEcho = Write-Script 'args.ps1' 'foreach ($a in $args) { Write-Host ("ARG<" + $a + ">") }'
    $child = Start-GuiChild -ScriptPath $argEcho -ArgumentList @('C:\a b (1)\c', '', 'say "hi"', '-Confirm:$false')
    $r = Wait-GuiChild $child $null
    $txt = $child.Transcript.ToString()
    Check ($txt.Contains('ARG<C:\a b (1)\c>') -and $txt.Contains('ARG<>') -and $txt.Contains('ARG<say "hi">')) 'paths with spaces and parentheses, empty and quoted values arrive intact'

    Write-Host 'The real Invoke-ReviewAndRemove.ps1 (-WhatIfOnly: nothing is removed)' -ForegroundColor Cyan
    function New-Findings([string]$Dir) {
        $null = New-Item -ItemType Directory -Path $Dir -Force
        $mk = { param($id, $relay) [ordered]@{ Key = 'svc:' + $id; Identifier = $id; InstallDir = 'C:\Program Files (x86)\ScreenConnect Client (' + $id + ')'; ServiceName = 'ScreenConnect Client (' + $id + ')'; ServiceState = 'Running'; RelayHost = $relay; RelayPort = 8041; SessionType = 'Support' } }
        $doc = [ordered]@{ Tool = 'detect-remote-access.ps1'; RunId = 'T'; ComputerName = 'TESTPC'
            ScreenConnect = [ordered]@{ Instances = @((& $mk 'aaaa1111aaaa1111' 'evil.example.net'), (& $mk 'bbbb2222bbbb2222' 'support.customer.example'), (& $mk 'cccc3333cccc3333' 'other.example.org')); ParseIssues = @(); Historical = @(); RawFilesSaved = @() }
            OtherTargets = @() }
        $path = Join-Path $Dir 'findings.json'
        ($doc | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }
    $review = Join-Path $ToolRoot 'Invoke-ReviewAndRemove.ps1'
    function Invoke-Review([string]$Name, [string[]]$Extra, [string]$Send) {
        $dir = Join-Path $work $Name
        $f = New-Findings (Join-Path $dir 'detect\RUN_1')
        $wd = Join-Path $dir 'wd'
        $child = Start-GuiChild -ScriptPath $review -ArgumentList (@('-FindingsJson', $f, '-WorkDir', $wd, '-MinFreeGB', '0', '-WhatIfOnly') + $Extra)
        $st = @{ Seen = ''; Sent = $false }
        $r = Wait-GuiChild $child {
            param($pp, $ch)
            if ($pp.Kind -eq 'Known' -and -not $st.Sent) { $st.Seen = $pp.Row.Id; Send-GuiAnswer -Child $ch -Text $Send; $st.Sent = $true }
        }
        $plan = $null
        if (Test-Path -LiteralPath (Join-Path $wd 'plan.json')) { $plan = [IO.File]::ReadAllText((Join-Path $wd 'plan.json')) | ConvertFrom-Json }
        return [pscustomobject]@{ Run = $r; Seen = $st.Seen; Plan = $plan; Out = $child.Transcript.ToString(); Wd = $wd }
    }
    $r = Invoke-Review 'accept' @() 'y'
    Check ($r.Seen -eq 'RemoveConfirm') 'the removal confirmation is recognised from the real script''s output'
    Check ($r.Run.ExitCode -eq 0 -and $r.Plan -and $r.Plan.Decision -eq 'ALL_REMOVE' -and @($r.Plan.ScreenConnectInstances).Count -eq 3) 'y from the GUI: the plan lists all 3 instances (end-to-end S1)'
    $r = Invoke-Review 'refuse' @() 'n'
    Check ($r.Run.ExitCode -eq 0 -and $null -eq $r.Plan -and $r.Out -match 'nothing was removed') 'n (window X): confirmation not given, no plan written, nothing removed'
    $r = Invoke-Review 'keep2' @('-KeepIdentifier', 'aaaa1111aaaa1111,cccc3333cccc3333') 'y'
    Check ($r.Seen -eq 'RemoveConfirm') 'select-mode confirmation text is recognised too'
    Check ($r.Plan -and @($r.Plan.KeptScreenConnectInstances).Count -eq 2 -and @($r.Plan.ScreenConnectInstances).Count -eq 1 -and $r.Plan.ScreenConnectInstances[0].Identifier -eq 'bbbb2222bbbb2222') '-KeepIdentifier a,b through the GUI keeps two and removes only the third (spike S4)'
    $r = Invoke-Review 'typo' @('-KeepIdentifier', 'aaaa1111aaaa1111,nosuchid') 'y'
    Check ($r.Run.ExitCode -eq 2 -and $null -eq $r.Plan) 'an identifier that matches nothing: exit 2, nothing written'
} finally {
    Restore-GuiConsoleEncoding $consoleSaved
    if ($work -and $work.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase) -and $work -match 'scc-gui-prompt-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0
