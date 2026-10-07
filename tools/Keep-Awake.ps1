# =====================================================================
# Keep-Awake.ps1 -- keep the display and system awake while START-HERE runs.
#
# The hidden helper watches the isolated START-HERE cmd.exe process. It uses
# only SetThreadExecutionState; it installs nothing and writes no files.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param(
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { exit 2 }

$nativeSource = @'
using System;
using System.Runtime.InteropServices;

public static class SccKeepAwakeNative
{
    public const uint ES_CONTINUOUS = 0x80000000u;
    public const uint ES_SYSTEM_REQUIRED = 0x00000001u;
    public const uint ES_DISPLAY_REQUIRED = 0x00000002u;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SetThreadExecutionState(uint esFlags);
}
'@

if (-not ('SccKeepAwakeNative' -as [type])) {
    Add-Type -TypeDefinition $nativeSource -ErrorAction Stop
}

$keepAwakeFlags = [SccKeepAwakeNative]::ES_CONTINUOUS -bor
    [SccKeepAwakeNative]::ES_SYSTEM_REQUIRED -bor
    [SccKeepAwakeNative]::ES_DISPLAY_REQUIRED

if ($SelfTest) {
    $requestSet = $false
    try {
        $previousState = [SccKeepAwakeNative]::SetThreadExecutionState($keepAwakeFlags)
        if ($previousState -eq 0) { throw 'SetThreadExecutionState request failed.' }
        $requestSet = $true
    } finally {
        if ($requestSet) {
            $resetState = [SccKeepAwakeNative]::SetThreadExecutionState([SccKeepAwakeNative]::ES_CONTINUOUS)
            if ($resetState -eq 0) { throw 'SetThreadExecutionState reset failed.' }
        }
    }
    Write-Output 'KEEP_AWAKE_SELFTEST_OK'
    exit 0
}

try {
    $helperProcess = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = {0}' -f $PID) -ErrorAction Stop
    if ($null -eq $helperProcess) { exit 0 }

    $runnerProcessId = [int]$helperProcess.ParentProcessId
    $runnerProcess = $null
    try {
        $runnerProcess = Get-Process -Id $runnerProcessId -ErrorAction Stop
        if ($runnerProcess.ProcessName -ine 'cmd') { exit 0 }
        $runnerStartTicks = $runnerProcess.StartTime.ToUniversalTime().Ticks
    } finally {
        if ($runnerProcess) { $runnerProcess.Dispose() }
    }
} catch {
    exit 0
}

$executionStateRequested = $false
try {
    while ($true) {
        $currentRunner = $null
        try {
            $currentRunner = Get-Process -Id $runnerProcessId -ErrorAction Stop
            $runnerAlive = ($currentRunner.ProcessName -ieq 'cmd') -and
                ($currentRunner.StartTime.ToUniversalTime().Ticks -eq $runnerStartTicks)
        } catch {
            $runnerAlive = $false
        } finally {
            if ($currentRunner) { $currentRunner.Dispose() }
        }
        if (-not $runnerAlive) { break }

        $previousState = [SccKeepAwakeNative]::SetThreadExecutionState($keepAwakeFlags)
        if ($previousState -eq 0) { break }
        $executionStateRequested = $true
        Start-Sleep -Seconds 5
    }
} finally {
    if ($executionStateRequested) {
        $null = [SccKeepAwakeNative]::SetThreadExecutionState([SccKeepAwakeNative]::ES_CONTINUOUS)
    }
}
