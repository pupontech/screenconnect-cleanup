# =====================================================================
# Test-ScannerProcessContracts.ps1 -- CI gate for the scanner *process*
# execution contract in the Stage 5 scanner adapters.
#
# WHAT IT ENFORCES
#   Each scanner adapter opens its scanner with redirected stdout/stderr
#   and runs it under a hard TimeoutMinutes. The naive implementation
#   (poll $proc.HasExited until the deadline, THEN ReadToEnd each stream
#   synchronously) is broken: a redirected pipe buffers only a few
#   kilobytes, so a tool that fills the pipe blocks forever inside its
#   own write, HasExited never flips, and the advertised timeout becomes
#   ineffective - the scanner run deadlocks instead of timing out.
#
#   The required, PS 5.1-safe fix is a shared helper
#   `Invoke-ProcessWithTimeout` in EVERY adapter that:
#     * starts BOTH async stdout/stderr reads (ReadToEndAsync)
#       IMMEDIATELY, before any bounded wait, so a full pipe can never
#       deadlock the child;
#     * waits with a bounded WaitForExit(milliseconds) that honors
#       TimeoutMinutes;
#     * on timeout, terminates the scanner process and reaps it
#       (bounded), then collects both stream tasks;
#     * preserves the existing WhatIf and result-object contracts.
#
# NON-DESTRUCTIVE
#   Section 1 is purely static source/AST contract checking. Section 2
#   runs only a harmless SYNTHETIC child (this pwsh process); it NEVER
#   executes a vendor scanner binary and NEVER evaluates the adapter
#   source (production code is validated by source contract here and by
#   Windows CI; the drain+timeout behaviour is proved with an
#   independently written probe, not by running scanner code).
#
# Exit codes: 0 = contract satisfied, 1 = violation found.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scannerDir = Join-Path $repoRoot 'scanners'

$adapterFiles = @(
    (Join-Path $scannerDir 'Invoke-DefenderScan.ps1'),
    (Join-Path $scannerDir 'Invoke-ESETScan.ps1'),
    (Join-Path $scannerDir 'Invoke-KVRTScan.ps1')
)

$script:failures = @()

function Add-Failure {
    param([string]$Message)
    $script:failures += $Message
}

# Path to the running PowerShell, used as the harmless synthetic child.
$script:pwshPath = $null
try { $script:pwshPath = (Get-Process -Id $PID -ErrorAction Stop).Path } catch { }
if (-not $script:pwshPath) { $script:pwshPath = 'pwsh' }

# ---------------------------------------------------------------------
# Section 1 - static / AST source-contract checks on every adapter
# ---------------------------------------------------------------------
Write-Host 'Section 1: adapter source contracts'
foreach ($f in $adapterFiles) {
    $name = Split-Path -Leaf $f

    if (-not (Test-Path -LiteralPath $f)) {
        Add-Failure "$name : missing adapter file."
        continue
    }

    $text = [System.IO.File]::ReadAllText($f)

    # 1a. The shared drain+timeout helper must be defined in the file.
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$parseErrors)
    $funcs = @($ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq 'Invoke-ProcessWithTimeout'
    }, $true))
    if ($funcs.Count -eq 0) {
        Add-Failure "$name : missing function Invoke-ProcessWithTimeout (shared drain+timeout helper)."
    } else {
        Write-Host "  OK $name : defines Invoke-ProcessWithTimeout."
    }

    # 1b. Must drain BOTH redirected streams with ReadToEndAsync (>= 2
    #     uses, one per stream) and must NOT use blocking sync ReadToEnd().
    $asyncCount = ([regex]::Matches($text, 'ReadToEndAsync')).Count
    if ($asyncCount -lt 2) {
        Add-Failure "$name : need >= 2 ReadToEndAsync calls (one per redirected stream), found $asyncCount."
    }
    if ($text -match 'ReadToEnd\(\)') {
        Add-Failure "$name : blocking synchronous ReadToEnd() present; concurrent drain required instead."
    }

    # 1c. Must not fall back to the old HasExited poll loop - that loop is
    #     exactly what a full pipe defeated, making the timeout ineffective.
    #     (AST member-access check so prose in comments never trips it.)
    $hasExitedRefs = @($ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.MemberExpressionAst]
    }, $true) | Where-Object { $_.ToString() -match '\.HasExited\b' })
    if ($hasExitedRefs.Count -gt 0) {
        Add-Failure ("$name : {0} HasExited property access(es) detected; use bounded WaitForExit(ms) instead." -f $hasExitedRefs.Count)
    }
}

# ---------------------------------------------------------------------
# Section 2 - harmless synthetic process probe (independent of adapter
#             source). Proves the drain+timeout pattern itself works.
# ---------------------------------------------------------------------
Write-Host 'Section 2: synthetic process probe (drain + timeout)'

# Probe mirrors the required contract with TEST-LOCAL code only. It is the
# pattern every adapter's helper must implement; it is not the scanner code.
function New-ProcessWithTimeoutProbe {
    param(
        [string]$Command,
        [int]$TimeoutSeconds
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:pwshPath
    $psi.Arguments = ('-NoProfile -NonInteractive -Command "{0}"' -f $Command)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)

    # Drain both redirected streams concurrently BEFORE the bounded wait.
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $timedOut = -not $proc.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try { $proc.Kill() } catch { }
        $null = $proc.WaitForExit(2000)   # bounded reap
    }

    # Collect both stream tasks with a BOUNDED WaitAll (mirrors the adapter
    # helper): never block on the async reads, only read completed results.
    $stdout = ''
    $stderrText = ''
    $drainTimedOut = $false
    $streamTasks = [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
    if ([System.Threading.Tasks.Task]::WaitAll($streamTasks, 5000)) {
        try { $stdout = [string]$stdoutTask.GetAwaiter().GetResult() } catch { $stdout = '' }
        try { $stderrText = [string]$stderrTask.GetAwaiter().GetResult() } catch { $stderrText = '' }
    } else {
        $drainTimedOut = $true
    }

    $exitCode = $null
    if (-not $timedOut) { try { $exitCode = $proc.ExitCode } catch { } }
    return @{ TimedOut = $timedOut; StreamDrainTimedOut = $drainTimedOut; ExitCode = $exitCode; StdOut = $stdout; StdErr = $stderrText }
}

# 2a. Chatty child: writes far more than the pipe buffer (a few KB) to both
#     streams, then exits 0. With concurrent drain the probe returns promptly
#     with exit 0 and full output; a poll-then-read implementation deadlocks
#     here (the exact bug this contract prevents).
$chattyCommand = "1..4000 | ForEach-Object { 'x' * 200 }; 1..2000 | ForEach-Object { [Console]::Error.WriteLine('x' * 100) }"
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $probeChatty = New-ProcessWithTimeoutProbe -Command $chattyCommand -TimeoutSeconds 30
    $sw.Stop()
    if ($probeChatty.TimedOut) {
        Add-Failure 'probe 2a : chatty child timed out - did NOT drain concurrently.'
    } elseif ($probeChatty.ExitCode -ne 0) {
        Add-Failure ('probe 2a : chatty child exited {0}, expected 0.' -f $probeChatty.ExitCode)
    } elseif ($probeChatty.StdOut.Length -lt 100000) {
        Add-Failure ('probe 2a : stdout drained only {0} chars, expected > 100000 (pipe deadlock).' -f $probeChatty.StdOut.Length)
    } else {
        Write-Host ("  OK probe 2a : chatty child drained {0}/{1} chars in {2:0.0}s, exit 0 - no deadlock." -f $probeChatty.StdOut.Length, $probeChatty.StdErr.Length, $sw.Elapsed.TotalSeconds)
    }
} catch {
    Add-Failure ('probe 2a : exception - ' + $_.Exception.Message)
}

# 2b. Langorous child: sleeps far past the probe timeout. The probe must
#     terminate it, return TimedOut=$true with no exit code, and do so
#     promptly (bounded reap), not wait out the full sleep.
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $probeSleep = New-ProcessWithTimeoutProbe -Command 'Start-Sleep -Seconds 30' -TimeoutSeconds 3
    $sw.Stop()
    if (-not $probeSleep.TimedOut) {
        Add-Failure 'probe 2b : long-running child did NOT report a timeout.'
    } elseif ($null -ne $probeSleep.ExitCode) {
        Add-Failure ('probe 2b : killed child reported an exit code ({0}); a terminated run must report none.' -f $probeSleep.ExitCode)
    } elseif ($sw.Elapsed.TotalSeconds -ge 10) {
        Add-Failure ('probe 2b : timeout took {0:0.0}s (>= 10s) - reap was not bounded/prompt.' -f $sw.Elapsed.TotalSeconds)
    } else {
        Write-Host ("  OK probe 2b : 30s child terminated on a 3s timeout in {0:0.0}s, TimedOut=$true, no exit code." -f $sw.Elapsed.TotalSeconds)
    }
} catch {
    Add-Failure ('probe 2b : exception - ' + $_.Exception.Message)
}

# ---------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------
if ($script:failures.Count -gt 0) {
    Write-Host ''
    Write-Host ("CONTRACT VIOLATIONS ({0}):" -f $script:failures.Count)
    $script:failures | ForEach-Object { Write-Host ('  ' + $_) }
    exit 1
}

Write-Host ''
Write-Host ('Scanner-process contracts OK: {0} adapter(s) checked, synthetic probe drain+timeout passed.' -f $adapterFiles.Count)
exit 0