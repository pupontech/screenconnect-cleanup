# =====================================================================
# Test-KeepAwakeRuntime.ps1 -- safe keep-awake helper runtime checks.
#
# Exercises the real SetThreadExecutionState P/Invoke, then launches the
# production helper from a short-lived cmd.exe. The helper must remain alive
# while the runner is alive and exit after normal completion or forced close.
# No scanner, install, registry edit, or power-plan change is exercised.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Host 'SKIP: Test-KeepAwakeRuntime.ps1 requires Windows.'
    exit 0
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$helperPath = Join-Path $repoRoot 'tools\Keep-Awake.ps1'
if (-not (Test-Path -LiteralPath $helperPath)) {
    Write-Host 'FAIL: tools\Keep-Awake.ps1 is missing.'
    exit 1
}

$failures = 0
function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host ("PASS  {0}" -f $Name) }
    else {
        Write-Host ("FAIL  {0}  {1}" -f $Name, $Detail)
        $script:failures++
    }
}

function Get-HelperProcesses {
    $items = @()
    try {
        $all = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
        $items = @($all | Where-Object {
            $_.Name -ieq 'powershell.exe' -and
            $_.CommandLine -like '*Keep-Awake.ps1*'
        })
    } catch { }
    return ,$items
}

function Get-HelperForParent {
    param([int]$ParentProcessId)
    $items = @(Get-HelperProcesses | Where-Object { [int]$_.ParentProcessId -eq $ParentProcessId })
    return ,$items
}

function Wait-NewHelperProcess {
    param([int[]]$ExistingProcessIds, [int]$TimeoutSeconds = 20)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $items = @(Get-HelperProcesses | Where-Object { $ExistingProcessIds -notcontains [int]$_.ProcessId })
        if ($items.Count -gt 0) { return $items[0] }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    return $null
}

function Wait-HelperForParent {
    param([int]$ParentProcessId, [bool]$ShouldExist, [int]$TimeoutSeconds = 20)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $items = Get-HelperForParent -ParentProcessId $ParentProcessId
        if ($ShouldExist -and $items.Count -gt 0) { return $items[0] }
        if ((-not $ShouldExist) -and $items.Count -eq 0) { return $null }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    if ($ShouldExist) { return $null }
    return (Get-HelperForParent -ParentProcessId $ParentProcessId)
}

function Invoke-RunnerScenario {
    param(
        [string]$Name,
        [string]$BatchPath,
        [int]$RunnerSeconds,
        [switch]$KillRunner
    )

    $batchLines = @(
        '@echo off',
        'setlocal EnableDelayedExpansion',
        'if not defined SCC_RUNNER_CHILD (',
        '    set "SCC_RUNNER_CHILD=1"',
        '    start "" /b /wait cmd.exe /d /s /c ""%~f0""',
        '    set "SCC_RUNNER_RC=!errorlevel!"',
        '    exit /b !SCC_RUNNER_RC!',
        ')',
        'start "" powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "%SCC_KEEP_AWAKE_HELPER%"',
        ('timeout /t {0} /nobreak >nul' -f $RunnerSeconds),
        'exit /b 0'
    )
    [System.IO.File]::WriteAllLines($BatchPath, $batchLines, [System.Text.Encoding]::ASCII)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c ""' + $BatchPath + '""'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables['SCC_KEEP_AWAKE_HELPER'] = $helperPath

    $runner = $null
    $runnerOwner = $null
    $runnerOwnerId = 0
    $helper = $null
    $existingHelperIds = @((Get-HelperProcesses | ForEach-Object { [int]$_.ProcessId }))
    try {
        $runner = [System.Diagnostics.Process]::Start($psi)
        $helper = Wait-NewHelperProcess -ExistingProcessIds $existingHelperIds -TimeoutSeconds 20
        Check ("{0}: helper started under the isolated runner cmd.exe" -f $Name) ($null -ne $helper) ("outer cmd PID={0}" -f $runner.Id)
        if ($null -eq $helper) { return }

        $runnerOwnerId = [int]$helper.ParentProcessId
        $runnerOwner = [System.Diagnostics.Process]::GetProcessById($runnerOwnerId)
        Check ("{0}: helper watches a cmd.exe process" -f $Name) ($runnerOwner.ProcessName -ieq 'cmd') ("owner PID={0}, name={1}" -f $runnerOwnerId, $runnerOwner.ProcessName)

        Start-Sleep -Seconds 2
        $stillRunning = Get-HelperForParent -ParentProcessId $runnerOwnerId
        Check ("{0}: helper remains alive while cmd.exe is alive" -f $Name) ($stillRunning.Count -gt 0)

        if ($KillRunner) {
            try { $runnerOwner.Kill() } catch { }
            $null = $runnerOwner.WaitForExit(5000)
            $runner.WaitForExit(15000) | Out-Null
        } else {
            $runner.WaitForExit(20000) | Out-Null
            $null = $runnerOwner.WaitForExit(5000)
        }
        Check ("{0}: runner cmd.exe ended" -f $Name) $runnerOwner.HasExited

        $remaining = Wait-HelperForParent -ParentProcessId $runnerOwnerId -ShouldExist $false -TimeoutSeconds 15
        Check ("{0}: helper exits after runner cmd.exe ends" -f $Name) ($null -eq $remaining -or $remaining.Count -eq 0)
    } catch {
        Check ("{0}: scenario completed" -f $Name) $false $_.Exception.Message
    } finally {
        if ($runnerOwner) {
            try {
                if (-not $runnerOwner.HasExited) { $runnerOwner.Kill(); $null = $runnerOwner.WaitForExit(5000) }
            } catch { }
            try { $runnerOwner.Dispose() } catch { }
        }
        if ($runner) {
            try {
                $children = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                    $_.Name -ieq 'cmd.exe' -and
                    [int]$_.ParentProcessId -eq $runner.Id -and
                    $_.CommandLine -like ('*' + [System.IO.Path]::GetFileName($BatchPath) + '*')
                })
                foreach ($child in $children) {
                    Stop-Process -Id ([int]$child.ProcessId) -Force -ErrorAction SilentlyContinue
                }
            } catch { }
            try {
                if (-not $runner.HasExited) { $runner.Kill(); $null = $runner.WaitForExit(5000) }
            } catch { }
            try { $runner.Dispose() } catch { }
        }
        if ($runnerOwnerId -gt 0) {
            $null = Wait-HelperForParent -ParentProcessId $runnerOwnerId -ShouldExist $false -TimeoutSeconds 15
        }
    }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-keep-awake-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $hostExe = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
    if (-not $hostExe) {
        Check 'Windows PowerShell host is available for the helper test' $false
    } else {
        $selfPsi = New-Object System.Diagnostics.ProcessStartInfo
        $selfPsi.FileName = $hostExe
        $selfPsi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $helperPath + '" -SelfTest'
        $selfPsi.UseShellExecute = $false
        $selfPsi.RedirectStandardOutput = $true
        $selfPsi.RedirectStandardError = $true
        $selfPsi.CreateNoWindow = $true
        $selfProcess = [System.Diagnostics.Process]::Start($selfPsi)
        $stdoutTask = $selfProcess.StandardOutput.ReadToEndAsync()
        $stderrTask = $selfProcess.StandardError.ReadToEndAsync()
        if (-not $selfProcess.WaitForExit(15000)) {
            try { $selfProcess.Kill(); $null = $selfProcess.WaitForExit(5000) } catch { }
            Check 'SetThreadExecutionState self-test finishes' $false 'timed out'
        } else {
            $stdout = $stdoutTask.Result
            $stderr = $stderrTask.Result
            Check 'SetThreadExecutionState accepts and resets the requested flags' ($selfProcess.ExitCode -eq 0 -and $stdout -match 'KEEP_AWAKE_SELFTEST_OK') ("exit={0}; stdout={1}; stderr={2}" -f $selfProcess.ExitCode, $stdout.Trim(), $stderr.Trim())
        }
        $selfProcess.Dispose()
    }

    Invoke-RunnerScenario -Name 'normal completion' -BatchPath (Join-Path $tmp 'normal.cmd') -RunnerSeconds 10
    Invoke-RunnerScenario -Name 'forced close' -BatchPath (Join-Path $tmp 'forced.cmd') -RunnerSeconds 60 -KillRunner
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures -gt 0) {
    Write-Host ("Keep-awake runtime tests: {0} failure(s)." -f $failures)
    exit 1
}
Write-Host 'Keep-awake runtime tests passed.'
exit 0
