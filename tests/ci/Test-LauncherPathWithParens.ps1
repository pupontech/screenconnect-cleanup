<#
  Regression: START-HERE.bat must run from a folder whose name contains
  parentheses - the "screenconnect-cleanup-v1.8.8 (1)" folder Windows Explorer
  creates when the same ZIP is extracted twice.

  Why it broke: cmd expands %~dp0 / %~f0 at PARSE time, so a ( or ) inside the
  expanded path terminates the enclosing ( ... ) block early and the batch
  aborts with no message and no UAC prompt - the window just closes. The
  launcher must therefore route every path expansion through a run-time
  (!VAR!) substitution instead.

  Windows-only. Runs the REAL launcher from a paren-named directory and
  requires it to get past the wrapper (proved by the run root it creates),
  then stops it before Step 1 starts downloading tools.
#>
[CmdletBinding()]
param([string]$RepositoryRoot = '')

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) { $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
if ($env:OS -ne 'Windows_NT') { Write-Host 'skip: Windows-only batch launcher'; exit 0 }

$batPath = Join-Path $RepositoryRoot 'START-HERE.bat'
if (-not (Test-Path -LiteralPath $batPath)) { throw "START-HERE.bat not found at $batPath" }

# Static guard: the launcher must not expand a path/args token anywhere after
# the capture block (all uses go through !SCC_DP0! / !SCC_F0! / !SCC_ARG1! /
# !SCC_ARGS!). Comments are allowed to mention them.
$lines = Get-Content -LiteralPath $batPath
$captureEnd = -1
for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -eq 'setlocal EnableDelayedExpansion') { $captureEnd = $i; break } }
if ($captureEnd -lt 0) { throw 'setlocal EnableDelayedExpansion not found; launcher shape changed' }
$offenders = @()
for ($i = $captureEnd; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line.TrimStart().StartsWith('rem')) { continue }
    foreach ($token in @('%~dp0', '%~f0', '%~1', '%*')) {
        if ($line.Contains($token)) { $offenders += ("L" + ($i + 1) + " " + $token) }
    }
}
if ($offenders.Count -gt 0) {
    Write-Host ('FAIL: parse-time expansions remain after the capture block: ' + ($offenders -join ', ')) -ForegroundColor Red
    exit 1
}
Write-Host 'ok:   no parse-time path expansions remain in the launcher body'

$work = Join-Path $env:TEMP ('scc paren (1) ' + [guid]::NewGuid().ToString('N'))
$out = Join-Path $work 'run.out.txt'
$null = New-Item -ItemType Directory -Path $work -Force
$proc = $null
try {
    Copy-Item -Path (Join-Path $RepositoryRoot '*') -Destination $work -Recurse -Force
    if (-not (Test-Path -LiteralPath (Join-Path $work 'START-HERE.bat'))) { throw 'bundle copy missing START-HERE.bat' }

    # Negative control: the OLD construct (a parse-time %~f0 expansion inside an
    # if-block) must genuinely abort from this paren path - otherwise this test
    # could pass for the wrong reason and would not catch a regression.
    $control = Join-Path $work 'control-old-style.bat'
    $controlBody = @(
        '@echo off',
        'setlocal EnableDelayedExpansion',
        'if not defined X (',
        '    set "X=1"',
        '    echo OLD-STYLE-PATH=%~f0',
        ')',
        'echo OLD-STYLE-SURVIVED'
    )
    [IO.File]::WriteAllText($control, ($controlBody -join "`r`n") + "`r`n", [Text.Encoding]::ASCII)
    $controlOut = Join-Path $work 'control.out.txt'
    $cp = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/c', 'control-old-style.bat') -WorkingDirectory $work -RedirectStandardOutput $controlOut -RedirectStandardError ($controlOut + '.err') -PassThru -WindowStyle Hidden
    $null = $cp.WaitForExit(30000)
    $controlText = if (Test-Path -LiteralPath $controlOut) { Get-Content -LiteralPath $controlOut -Raw } else { '' }
    if ($controlText -match 'OLD-STYLE-SURVIVED') {
        Write-Host 'FAIL: negative control survived a paren path; the test cannot detect the regression' -ForegroundColor Red
        exit 1
    }
    Write-Host 'ok:   negative control confirms a paren path breaks the old %~f0-in-block form'

    $proc = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/c', 'START-HERE.bat') -WorkingDirectory $work -RedirectStandardOutput $out -RedirectStandardError ($out + '.err') -PassThru -WindowStyle Hidden
    # On a runner with no battery the launcher reaches its banner, creates a run
    # root, tries Step 1 (a 403 on the CI network is fine) and stops at preflight
    # (Windows Server). Bounded wait, then judge by what it printed: the banner
    # and a "Run: <path>" line are only reachable AFTER the self-relaunch wrapper
    # - the exact code that used to die on a ( ) path.
    $waited = $proc.WaitForExit(180000)
    if (-not $waited) { & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null }
    $text = if (Test-Path -LiteralPath $out) { Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue } else { '' }
    if (-not $waited) { $text += [Environment]::NewLine + (Get-Content -LiteralPath ($out + '.err') -Raw -ErrorAction SilentlyContinue) }

    if ($text -match 'unexpected at this time|syntax of the command is incorrect') {
        Write-Host ('FAIL: cmd parse error from the paren path:' + [Environment]::NewLine + $text) -ForegroundColor Red
        exit 1
    }
    if ($text -notmatch 'SCREENCONNECT CLEANUP - guided run') {
        Write-Host ('FAIL: launcher never reached its banner from "' + (Split-Path -Leaf $work) + '"' + [Environment]::NewLine + '--- captured output ---' + [Environment]::NewLine + $text) -ForegroundColor Red
        exit 1
    }
    if ($text -notmatch '(?m)^\s+Run: .+') {
        Write-Host ('FAIL: launcher reached the banner but created no run root:' + [Environment]::NewLine + $text) -ForegroundColor Red
        exit 1
    }
    Write-Host ('ok:   launcher self-relaunched from "' + (Split-Path -Leaf $work) + '", created its run root and reached the banner')
    Write-Host 'PASS: START-HERE.bat survives a path containing ( )'
    exit 0
} finally {
    if ($proc -and -not $proc.HasExited) { try { & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null } catch { } }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
