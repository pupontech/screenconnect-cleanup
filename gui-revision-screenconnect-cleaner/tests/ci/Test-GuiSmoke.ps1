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
    Write-Host 'GUI smoke: entry-point check (Scc.Cleaner.ps1 GUI path stays alive) ...'
    $entry = Join-Path $appRoot 'Scc.Cleaner.ps1'
    $entryOut = Join-Path $tmp 'entry.out'
    $entryErr = Join-Path $tmp 'entry.err'
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = ('-NoProfile -ExecutionPolicy Bypass -File "' + $entry + '"')
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
    $entryOutText = ''
    $entryErrText = ''
    try { $entryOutText = $outTask.Result } catch { }
    try { $entryErrText = $errTask.Result } catch { }
    $stillAlive = -not $proc.HasExited
    if ($stillAlive) {
        Write-Host '  OK: process alive after 10s (window open) - terminating.'
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    } else {
        $exitCode = $proc.ExitCode
        # The launcher persists GUI failures to %TEMP%\SccCleaner-gui-error.log so
        # the cause survives the console flash-close. Dump it here for the log.
        $errLogText = ''
        foreach ($c in @((Join-Path $env:TEMP 'SccCleaner-gui-error.log'), (Join-Path $env:TMP 'SccCleaner-gui-error.log'), 'C:\Windows\Temp\SccCleaner-gui-error.log')) {
            if ($c -and (Test-Path -LiteralPath $c)) {
                try { $errLogText = [string](Get-Content -LiteralPath $c -Raw -ErrorAction Stop) } catch { }
                if ($errLogText) { break }
            }
        }
        $failures += ("Entry point exited early (GUI did not stay open): exit={0} out={1} err={2} guierrlog={3}" -f $exitCode, $entryOutText.Trim(), $entryErrText.Trim(), $errLogText.Trim())
        Write-Host "  FAILED: exited with $exitCode"
        Write-Host '  ---- child stdout ----'
        Write-Host $entryOutText
        Write-Host '  ---- child stderr ----'
        Write-Host $entryErrText
        if ($errLogText) {
            Write-Host '  ---- SccCleaner-gui-error.log ----'
            Write-Host $errLogText
        }
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
