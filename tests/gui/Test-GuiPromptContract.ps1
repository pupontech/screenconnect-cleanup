<#
  Test-GuiPromptContract.ps1 - the GUI answers engine prompts by matching their text
  (gui\Gui.Core.psm1, Get-GuiPromptTable). If an engine script rewords a prompt, the GUI would
  stop recognising it. This test greps the engine for every prompt in the table so a reworded
  prompt breaks CI instead of a site visit (docs/14-gui-architecture.md, 4.3 rule 5).

  It also pins a finding from spike S2: under redirected stdin, Windows PowerShell 5.1 does
  NOT write the text of  Read-Host '<prompt>'  to stdout, so every prompt must be echoed with
  Write-Host ... -NoNewline (always, or guarded by [Console]::IsInputRedirected) to be visible
  to a GUI. A prompt that is not echoed would hang the window, so no row may be invisible.

  No admin, no network, nothing is run. Windows PowerShell 5.1, pure ASCII, no BOM.
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
$table = @(Get-GuiPromptTable)

function Get-EngineText {
    param([string]$Leaf)
    $hit = @(Get-ChildItem -LiteralPath $ToolRoot -Filter $Leaf -File -Recurse | Where-Object { $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\gui\\' })
    if ($hit.Count -eq 0) { return $null }
    return [IO.File]::ReadAllText($hit[0].FullName)
}

Write-Host 'Every prompt in the table still exists in the engine' -ForegroundColor Cyan
foreach ($row in $table) {
    Check (@($row.Needles).Count -ge 1) ($row.Id + ': has at least one prompt text')
    foreach ($script in $row.Scripts) {
        $text = Get-EngineText $script
        Check ($null -ne $text) ($row.Id + ': ' + $script + ' exists')
        if ($null -eq $text) { continue }
        foreach ($n in @($row.Needles)) {
            Check ($text.Contains($n)) ($row.Id + ': ' + $script + ' still contains "' + $n + '"')
        }
    }
}

Write-Host 'Every prompt is printed with Write-Host -NoNewline (a prompt the GUI cannot see would hang it)' -ForegroundColor Cyan
foreach ($row in $table) {
    foreach ($script in $row.Scripts) {
        $text = Get-EngineText $script
        if ($null -eq $text) { continue }
        foreach ($n in @($row.Needles)) {
            $esc = [regex]::Escape($n)
            Check ([regex]::IsMatch($text, "Write-Host\s+'" + $esc + "'\s+-NoNewline")) ($row.Id + ': ' + $script + ' echoes "' + $n + '" with -NoNewline')
        }
    }
    foreach ($n in @($row.Needles)) {
        Check (Test-GuiPromptMatch -Row $row -Text $n) ($row.Id + ': the window recognises the exact prompt text "' + $n + '"')
    }
    Check (-not (Test-GuiPromptMatch -Row $row -Text 'Press Enter to close')) ($row.Id + ': unrelated text is not taken for this prompt')
    Check (-not (Test-GuiPromptMatch -Row $row -Text ('x' + @($row.Needles)[0]))) ($row.Id + ': a line that merely ends with the prompt text is not taken for it')
}

Write-Host 'Prompts passed to Read-Host as an argument are echoed only when stdin is redirected' -ForegroundColor Cyan
# Windows PowerShell 5.1 prints Read-Host's own prompt only when stdin is a console. These scripts keep
# Read-Host '<text>' (their engine tests mock Read-Host by its prompt) and echo the same text when input
# is redirected, so interactive output is unchanged.
foreach ($row in @($table | Where-Object { $_.Id -in 'MbInstallDone', 'MbScanDone', 'PersistIndices', 'PersistRemove' })) {
    foreach ($script in $row.Scripts) {
        $text = Get-EngineText $script
        if ($null -eq $text) { continue }
        $esc = [regex]::Escape(@($row.Needles)[0])
        Check ([regex]::IsMatch($text, "IsInputRedirected\)\s*\{\s*Write-Host\s+'" + $esc + "'\s+-NoNewline\s*\}")) ($row.Id + ': ' + $script + ' echoes the prompt when input is redirected')
        Check ([regex]::IsMatch($text, "Read-Host\s+'" + $esc + "'")) ($row.Id + ': ' + $script + ' still passes the text to Read-Host (interactive display and the mocks in the engine tests are unchanged)')
    }
}

Write-Host 'Answers are safe' -ForegroundColor Cyan
foreach ($row in $table) {
    Check ($row.Refuse -cne 'y' -and $row.Refuse -cne 'Y' -and $row.Refuse -cne 'REMOVE' -and $row.Refuse -cne 'DONE') ($row.Id + ': the refusing answer (sent when a dialog is closed with the window X) is never an approval')
}
$rm = $table | Where-Object { $_.Id -eq 'RemoveConfirm' }
Check ($rm.Accept -ceq 'y') 'RemoveConfirm approves with the engine''s own y'
Check ($rm.Refuse -ceq 'n') 'RemoveConfirm refuses with n'
$uac = $table | Where-Object { $_.Id -eq 'UacDisabled' }
Check ($uac.Refuse -ceq '') 'UacDisabled refuses with an empty line (the script aborts on it)'

Write-Host 'The batch file and the GUI agree on which questions the batch file owns' -ForegroundColor Cyan
$bat = [IO.File]::ReadAllText((Join-Path $ToolRoot 'START-HERE.bat'))
foreach ($q in 'Launch KVRT? [Y/n]', 'Launch ESET Online Scanner? [Y/n]', 'Install and launch Malwarebytes now? [Y/n]', 'Open the review windows now? [Y/n]', 'Run installed-AV uninstall now? [y/N]', 'Repair missing power options now? [y/N]', 'Back up, then reset local Group Policy folders? [y/N]', 'Restart now through CMD? [y/N]', 'Continue that run? [Y/n]') {
    Check ($bat.Contains($q)) ('START-HERE.bat still asks "' + $q + '" (the GUI turns it into a button or tick box)')
}

Write-Host 'The keep question lives in the review script (-AskKeep) and the window never triggers it' -ForegroundColor Cyan
# Since 1.8.12-beta.1-offline.3 the offline half passes -AskKeep and the review script asks "Keep any?".
# The window asks with its own Keep / Remove cards instead and never passes -AskKeep, so that prompt is
# deliberately NOT in the prompt table: if it ever appeared, the generic box would show it.
$review = [IO.File]::ReadAllText((Join-Path $ToolRoot 'Invoke-ReviewAndRemove.ps1'))
Check ($review -match "Write-Host 'Keep any ScreenConnect\?[^']*\[y/N\]' -NoNewline") 'Invoke-ReviewAndRemove.ps1 asks the keep question itself, visibly (-AskKeep)'
Check ($bat -match '-AskKeep') 'START-HERE.bat --offline passes -AskKeep'
$catalog = [IO.File]::ReadAllText((Join-Path $ToolRoot 'gui\steps.json'))
Check (-not $catalog.Contains('-AskKeep') -and -not ([IO.File]::ReadAllText((Join-Path $ToolRoot 'gui\Gui.Core.psm1'))).Contains('-AskKeep')) 'the window never passes -AskKeep (its own cards decide what to keep)'

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0
