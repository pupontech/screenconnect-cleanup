# =====================================================================
# Test-GuiSmoke.ps1 - Windows-only GUI smoke test.
#
# Verifies the WPF shell actually OPENS on a real Windows desktop session
# (GitHub Actions windows runners), under BOTH PowerShell 5.1 (STA by
# default) and PowerShell 7 (must be launched with -Sta for WPF).
#
# Two checks:
#   1. Direct: Start-SccApp -AutoCloseSeconds 5 opens the Dashboard window,
#      lets the dispatcher pump run, then auto-closes. Success = the
#      process exits 0 and prints GUI_SMOKE_OK.
#   2. Entry point: Scc.Cleaner.ps1 (GUI path) stays alive for 10 seconds
#      (window open, message pump running), then is terminated. Success =
#      it did NOT exit early with an error. This exercises the real
#      launcher path incl. module import + Start-SccApp wiring.
#
# Exit codes: 0 = GUI opens, 1 = any check failed.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$appRoot = [System.IO.Path]::GetFullPath((Join-Path $here '..\..'))
$srcRoot = Join-Path $appRoot 'src'
$failures = @()

Write-Host "GUI smoke: appRoot=$appRoot"

# ---------------------------------------------------------------------
# Check 1 - direct Start-SccApp with auto-close
# ---------------------------------------------------------------------
$directScript = @'
param([string]$SrcRoot)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = $SrcRoot + [System.IO.Path]::PathSeparator + $env:PSModulePath
Import-Module (Join-Path $SrcRoot 'Scc.Core\Scc.Core.psd1') -Force -ErrorAction Stop
Import-Module (Join-Path $SrcRoot 'Scc.UI\Scc.UI.psd1') -Force -ErrorAction Stop
try {
    Start-SccApp -AutoCloseSeconds 5
    Write-Output 'GUI_SMOKE_OK'
    exit 0
} catch {
    Write-Output ('GUI_SMOKE_FAIL: ' + $_.Exception.Message)
    exit 1
}
'@

$tmpRoot = $env:TEMP
if (-not $tmpRoot) { $tmpRoot = $env:TMP }
if (-not $tmpRoot) { $tmpRoot = 'C:\Windows\Temp' }
$tmp = Join-Path $tmpRoot ('scc-gui-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$directPs1 = Join-Path $tmp 'direct.ps1'
[System.IO.File]::WriteAllText($directPs1, $directScript, [System.Text.Encoding]::ASCII)

function Invoke-SccGuiSmokeDirect {
    param([string]$ExeName, [string[]]$PreludeArgs)
    Write-Host "GUI smoke: direct check via $ExeName ..."
    $stdout = Join-Path $tmp ($ExeName + '.out')
    $stderr = Join-Path $tmp ($ExeName + '.err')
    $argTokens = @($PreludeArgs) + @('-File', ('"' + $directPs1 + '"'), ('-SrcRoot "' + $srcRoot + '"'))
    $argLine = ($argTokens -join ' ')
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $ExeName
    $psi.Arguments = $argLine
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $null = $proc.Start()
    $out = [string]$proc.StandardOutput.ReadToEnd()
    $err = [string]$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $exitCode = $proc.ExitCode
    Write-Host "  exit=$exitCode out=$($out.Trim()) err=$($err.Trim())"
    if ($exitCode -ne 0 -or $out -notmatch 'GUI_SMOKE_OK') {
        $script:failures += ("Direct GUI check failed under {0}: exit={1} out={2} err={3}" -f $ExeName, $exitCode, $out.Trim(), $err.Trim())
    }
}

try {
    Invoke-SccGuiSmokeDirect -ExeName 'powershell.exe' -PreludeArgs @('-NoProfile', '-ExecutionPolicy', 'Bypass')
    Invoke-SccGuiSmokeDirect -ExeName 'pwsh.exe' -PreludeArgs @('-NoProfile', '-Sta')

    # -----------------------------------------------------------------
    # Check 2 - entry point stays alive (window open) for 10 seconds
    # -----------------------------------------------------------------
    # NOTE: launched via -Command "& '<path>'". The launcher must keep the
    # GUI process alive; ANY early exit is a real failure and fails the
    # smoke test. (History: the 'A positional parameter cannot be found
    # that accepts argument Scc.Core.psd1' error observed on Windows
    # PowerShell 5.1 was NOT a harness quirk - that string never appears on
    # the command line. It was a 3-arg Join-Path inside
    # Import-SccRequiredModule binding -AdditionalChildPath, which only
    # exists in PowerShell 6+. Fixed in Scc.Cleaner.ps1; house-rule 5
    # guards against regression.)
    Write-Host 'GUI smoke: entry-point check (Scc.Cleaner.ps1 GUI path stays alive) ...'
    $entry = Join-Path $appRoot 'Scc.Cleaner.ps1'
    $entryCmd = ("& '" + $entry + "'")
    Write-Host "  cmd: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"$entryCmd`""
    $entryOut = Join-Path $tmp 'entry.out'
    $entryErr = Join-Path $tmp 'entry.err'
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = ('-NoProfile -ExecutionPolicy Bypass -Command "' + $entryCmd + '"')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $null = $proc.Start()
    # Read asynchronously so a chatty child cannot deadlock the harness.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    Start-Sleep -Seconds 10
    # IMPORTANT: check liveness BEFORE touching the output tasks. A healthy
    # child (GUI open) keeps stdout open, so $outTask.Result would block
    # forever; the streams are only drained after the process has exited
    # (or been killed), with a bounded wait.
    $stillAlive = -not $proc.HasExited
    if ($stillAlive) {
        Write-Host '  OK: process alive after 10s (window open) - terminating.'
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        try { $null = $outTask.Wait(3000) } catch { }
        try { $null = $errTask.Wait(3000) } catch { }
    } else {
        $entryOutText = ''
        $entryErrText = ''
        try { $entryOutText = [string]$outTask.Result } catch { }
        try { $entryErrText = [string]$errTask.Result } catch { }
        $exitCode = 0
        try { $exitCode = $proc.ExitCode } catch { }
        # The launcher persists GUI failures to %TEMP%\SccCleaner-gui-error.log so
        # the cause survives the console flash-close. Dump it here for the log.
        $errLogText = ''
        foreach ($c in @((Join-Path $env:TEMP 'SccCleaner-gui-error.log'), (Join-Path $env:TMP 'SccCleaner-gui-error.log'), 'C:\Windows\Temp\SccCleaner-gui-error.log')) {
            if ($c -and (Test-Path -LiteralPath $c)) {
                try { $errLogText = [string](Get-Content -LiteralPath $c -Raw -ErrorAction Stop) } catch { }
                if ($errLogText) { break }
            }
        }
        Write-Host "  FAILED: exited with $exitCode"
        Write-Host '  ---- child stdout ----'
        Write-Host $entryOutText
        Write-Host '  ---- child stderr ----'
        Write-Host $entryErrText
        if ($errLogText) {
            Write-Host '  ---- SccCleaner-gui-error.log ----'
            Write-Host $errLogText
        }
        # ANY early exit is a real failure: the launcher must keep the GUI
        # open. No quirk-masking here - the 'Scc.Core.psd1' error was a
        # genuine PS 5.1 bug in the launcher, now fixed.
        $failures += ("Entry point exited early (GUI did not stay open): exit={0} out={1} err={2} guierrlog={3}" -f $exitCode, $entryOutText.Trim(), $entryErrText.Trim(), $errLogText.Trim())
    }
} catch {
    $failures += ('Smoke harness error: ' + $_.Exception.Message)
    Write-Host ('SMOKE HARNESS ERROR at: ' + $_.InvocationInfo.PositionMessage)
    Write-Host $_.ScriptStackTrace
}

# Cleanup
try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch { }

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'GUI SMOKE FAILURES:'
    foreach ($f in $failures) { Write-Host ('  - ' + $f) }
    exit 1
}
Write-Host ''
Write-Host 'GUI_SMOKE_PASS: WPF shell opens and closes cleanly on this host.'
exit 0
