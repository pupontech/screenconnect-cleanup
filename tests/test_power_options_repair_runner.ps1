# Execute the production report-launch/reboot slice with inert command doubles.
# Never dot-source the full orchestrator or launch Windows processes.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$source = [IO.File]::ReadAllText((Join-Path $repoRoot 'sc-cleanup.ps1'))
$start = $source.IndexOf('    $reportLaunchSucceeded = $false')
$end = $source.IndexOf('    # Owner directive 2026-09-06:', $start)
if ($start -lt 0 -or $end -le $start) { throw 'Production report/reboot slice not found.' }
$slice = [scriptblock]::Create($source.Substring($start, $end - $start))
# Refuse unexpected commands before evaluating extracted production code.
$allowed = @('Start-Process', 'Write-StageLog', 'Write-Host', 'Read-Host', '$env:ComSpec', 'Test-Path')
$commands = $slice.Ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true)
foreach ($command in $commands) {
    $name = $command.GetCommandName()
    if (-not $name) { $name = $command.CommandElements[0].Extent.Text }
    if ($allowed -notcontains $name) { throw ('Unexpected production command: ' + $name) }
}
function Start-Process { param($FilePath, $ErrorAction) if ($script:launchFails) { throw 'synthetic launch refused' } }
function Write-StageLog { param($Message, $Level) }
function Write-Host { param($Object, $ForegroundColor, [switch]$NoNewline) }
function Read-Host { $script:prompts++; if ($script:promptFails) { throw 'synthetic closed prompt' }; return $script:answer }
function Test-Path { param($LiteralPath, $PathType) return $script:evidenceExists }
function Invoke-FakeShutdown { param($One, $Two, $Three) $script:shutdowns++; $script:shutdownArgs = @($One, $Two, $Three) }
$oldComSpec = $env:ComSpec
$script:failures = 0
try {
    $env:ComSpec = 'Invoke-FakeShutdown'
    $cases = @(
        @{ Name = 'repair not requested'; Requested = $false; Evidence = $true; LaunchFails = $false; Answer = 'yes'; PromptFails = $false; Prompts = 0; Shutdowns = 0 },
        @{ Name = 'report launch failed'; Requested = $true; Evidence = $true; LaunchFails = $true; Answer = 'yes'; PromptFails = $false; Prompts = 0; Shutdowns = 0 },
        @{ Name = 'missing current-run repair evidence'; Requested = $true; Evidence = $false; LaunchFails = $false; Answer = 'yes'; PromptFails = $false; Prompts = 0; Shutdowns = 0 },
        @{ Name = 'blank answer defaults No'; Requested = $true; Evidence = $true; LaunchFails = $false; Answer = ''; PromptFails = $false; Prompts = 1; Shutdowns = 0 },
        @{ Name = 'No declines restart'; Requested = $true; Evidence = $true; LaunchFails = $false; Answer = 'n'; PromptFails = $false; Prompts = 1; Shutdowns = 0 },
        @{ Name = 'closed prompt declines restart'; Requested = $true; Evidence = $true; LaunchFails = $false; Answer = 'yes'; PromptFails = $true; Prompts = 1; Shutdowns = 0 },
        @{ Name = 'explicit yes invokes only fake CMD'; Requested = $true; Evidence = $true; LaunchFails = $false; Answer = 'yes'; PromptFails = $false; Prompts = 1; Shutdowns = 1 },
        @{ Name = 'unrecognized answer declines restart'; Requested = $true; Evidence = $true; LaunchFails = $false; Answer = 'yesterday'; PromptFails = $false; Prompts = 1; Shutdowns = 0 }
    )
    foreach ($case in $cases) {
        $RepairPowerOptions = $case.Requested
        $powerOptionsRepairPath = 'synthetic-current-run/power-options-repair.json'
        $repairPath = $powerOptionsRepairPath
        $reportHtml = 'synthetic-report.html'
        $script:evidenceExists = $case.Evidence
        $script:launchFails = $case.LaunchFails
        $script:answer = $case.Answer
        $script:promptFails = $case.PromptFails
        $script:prompts = 0
        $script:shutdowns = 0
        $script:shutdownArgs = @()
        . $slice
        $passed = $script:prompts -eq $case.Prompts -and $script:shutdowns -eq $case.Shutdowns
        if ($passed -and $case.Shutdowns -eq 1) { $passed = ($script:shutdownArgs -join '|') -ceq '/d|/c|shutdown /r /t 0 /f' }
        if ($passed) { [Console]::WriteLine('PASS  ' + $case.Name) }
        else {
            [Console]::WriteLine('FAIL  ' + $case.Name + ': prompts=' + $script:prompts + ', fake shutdowns=' + $script:shutdowns)
            $script:failures++
        }
    }
} finally { $env:ComSpec = $oldComSpec }
if ($script:failures -gt 0) { exit 1 }
[Console]::WriteLine('ALL POWER-OPTIONS RUNNER BEHAVIOR TESTS PASSED')
exit 0
