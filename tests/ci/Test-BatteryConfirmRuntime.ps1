# =====================================================================
# Test-BatteryConfirmRuntime.ps1 -- safe battery warning classifier checks.
#
# Runs only the helper's non-interactive self-test: no popup is shown and no
# cleanup stage runs. The test validates native power-status access and the
# AC-offline classifier under the selected PowerShell edition.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Host 'SKIP: Test-BatteryConfirmRuntime.ps1 requires Windows.'
    exit 0
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$helperPath = Join-Path $repoRoot 'tools\Confirm-OnBattery.ps1'
if (-not (Test-Path -LiteralPath $helperPath)) {
    Write-Host 'FAIL: tools\Confirm-OnBattery.ps1 is missing.'
    exit 1
}

if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $hostExe = Join-Path $PSHOME 'powershell.exe'
} else {
    $hostExe = (Get-Command pwsh -ErrorAction Stop).Source
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $hostExe
$psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $helperPath + '" -SelfTest'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

$process = [System.Diagnostics.Process]::Start($psi)
try {
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(20000)) {
        try { $process.Kill(); $null = $process.WaitForExit(5000) } catch { }
        Write-Host 'FAIL: battery confirmation self-test timed out.'
        exit 1
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0 -or $stdout -notmatch 'ON_BATTERY_SELFTEST_OK') {
        Write-Host ("FAIL: battery confirmation self-test (exit {0}). stdout={1}; stderr={2}" -f $process.ExitCode, $stdout.Trim(), $stderr.Trim())
        exit 1
    }
} finally {
    $process.Dispose()
}

Write-Host 'Battery confirmation runtime self-test passed; no dialog was shown.'
exit 0
