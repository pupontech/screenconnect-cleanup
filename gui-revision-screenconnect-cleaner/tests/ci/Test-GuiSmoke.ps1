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

$tmp = Join-Path $env:TEMP ('scc-gui-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$directPs1 = Join-Path $tmp 'direct.ps1'
[System.IO.File]::WriteAllText($directPs1, $directScript, [System.Text.Encoding]::ASCII)

foreach ($exe in @(@{ Name = 'powershell.exe'; Args = @('-NoProfile', '-ExecutionPolicy', 'Bypass') },
                   @{ Name = 'pwsh.exe';        Args = @('-NoProfile', '-Sta') })) {
    Write-Host "GUI smoke: direct check via $($exe.Name) ..."
    $stdout = Join-Path $tmp ($exe.Name + '.out')
    $stderr = Join-Path $tmp ($exe.Name + '.err')
    $args = @($exe.Args) + @('-File', ('"' + $directPs1 + '"'), ('-SrcRoot "' + $srcRoot + '"'))
    $p = Start-Process -FilePath $exe.Name -ArgumentList $args -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $out = ''
    if (Test-Path -LiteralPath $stdout) { $out = Get-Content -LiteralPath $stdout -Raw }
    $err = ''
    if (Test-Path -LiteralPath $stderr) { $err = Get-Content -LiteralPath $stderr -Raw }
    Write-Host "  exit=$($p.ExitCode) out=$($out.Trim()) err=$($err.Trim())"
    if ($p.ExitCode -ne 0 -or $out -notmatch 'GUI_SMOKE_OK') {
        $failures += ("Direct GUI check failed under {0}: exit={1} out={2} err={3}" -f $exe.Name, $p.ExitCode, $out.Trim(), $err.Trim())
    }
}

# ---------------------------------------------------------------------
# Check 2 - entry point stays alive (window open) for 10 seconds
# ---------------------------------------------------------------------
Write-Host 'GUI smoke: entry-point check (Scc.Cleaner.ps1 GUI path stays alive) ...'
$entry = Join-Path $appRoot 'Scc.Cleaner.ps1'
$p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $entry + '"')) -PassThru -NoNewWindow
Start-Sleep -Seconds 10
if ($p.HasExited) {
    $failures += ("Entry point exited early (GUI did not stay open): exit={0}" -f $p.ExitCode)
    Write-Host "  FAILED: exited with $($p.ExitCode)"
} else {
    Write-Host '  OK: process alive after 10s (window open) - terminating.'
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
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
