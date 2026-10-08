# Elevation must be bounded to ONE UAC request and decided by the real token.
# Fixture-only: a stub powershell.exe on PATH records calls; no UAC is shown.
[CmdletBinding()]
param([string]$RepositoryRoot = '')
$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) { $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
if ($env:OS -ne 'Windows_NT' -or -not (Get-Command cmd.exe -ErrorAction SilentlyContinue)) {
    Write-Host 'SKIP: launcher elevation fixture requires Windows cmd.exe.'
    exit 0
}
$failures = 0
function Check([bool]$Ok, [string]$Name, [string]$Detail = '') {
    if ($Ok) { Write-Host ("PASS  {0}" -f $Name) } else { Write-Host ("FAIL  {0}  {1}" -f $Name, $Detail); $script:failures++ }
}
$bat = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'START-HERE.bat'))
Check ($bat -notmatch '(?i)fltmc') 'launcher no longer depends on the fltmc probe'
Check ($bat -match 'WindowsBuiltInRole\]::Administrator') 'launcher decides elevation from the real admin token'
Check ($bat -match "--elevation-attempted") 'launcher passes a one-shot elevation marker on relaunch'
Check (([regex]::Matches($bat, '-Verb\s+RunAs')).Count -eq 1) 'exactly one elevation request exists in the launcher'

$root = Join-Path ([IO.Path]::GetTempPath()) ('scc elev fixture ' + [guid]::NewGuid().ToString('N'))
$shim = Join-Path $root 'shim'
$case = Join-Path $root 'case'
$null = New-Item -ItemType Directory -Path $shim -Force
$null = New-Item -ItemType Directory -Path $case -Force
try {
    # Stub powershell.exe: logs its argv and returns a scripted exit code.
    $stubSource = Join-Path $shim 'stub.cs'
    [IO.File]::WriteAllText($stubSource, 'using System; using System.IO; public class Stub { public static int Main(string[] args) { File.AppendAllText(Environment.GetEnvironmentVariable("SCC_STUB_LOG"), string.Join("|", args) + Environment.NewLine); int rc = 0; int.TryParse(Environment.GetEnvironmentVariable("SCC_STUB_RC"), out rc); return rc; } }', [Text.Encoding]::ASCII)
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
    if (-not (Test-Path -LiteralPath $compiler)) { throw 'Framework C# compiler unavailable for the elevation fixture.' }
    $stubExe = Join-Path $shim 'powershell.exe'
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $compile = & $compiler /nologo /target:exe ('/out:' + $stubExe) $stubSource 2>&1
        $compileRc = $LASTEXITCODE
    } finally { $ErrorActionPreference = $old }
    if ($compileRc -ne 0) { throw ('Elevation fixture compile failed: ' + ($compile -join ' ')) }

    # Replay only the launcher's elevation region (from the wrapper block to the
    # token probe) so the fixture never runs cleanup stages.
    $block = [regex]::Match($bat, '(?ms)^if not defined SCC_RUNNER_CHILD \(.*?^set "SCC_SELF="\r?$').Value
    if (-not $block) { throw 'Could not extract the launcher elevation block.' }
    $marker = Join-Path $case 'continues.txt'
    $log = Join-Path $case 'calls.log'
    $fixture = Join-Path $case 'replay.bat'
    $text = "@echo off`r`nsetlocal EnableDelayedExpansion`r`nset `"SCC_RUNNER_CHILD=1`"`r`n$block`r`necho continued>`"$marker`"`r`nexit /b 0`r`n"
    [IO.File]::WriteAllText($fixture, $text, [Text.Encoding]::ASCII)
    $env:SCC_STUB_LOG = $log
    $env:PATH = $shim + ';' + $env:PATH
    $cmd = (Get-Command cmd.exe).Source
    function Invoke-Replay([string]$Arguments, [string]$ProbeRc) {
        if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
        if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }
        $env:SCC_STUB_RC = $ProbeRc
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $cmd
        $psi.Arguments = '/d /s /c ""' + $fixture + '"' + $Arguments + '"'
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $p = [Diagnostics.Process]::Start($psi)
        $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(30000)) { $p.Kill(); throw 'Elevation replay exceeded its bounded wait.' }
        $out = $o.Result + $e.Result
        $calls = if (Test-Path -LiteralPath $log) { @(Get-Content -LiteralPath $log) } else { @() }
        $p.Dispose()
        return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $out; Calls = $calls; Continued = (Test-Path -LiteralPath $marker) }
    }

    # 1. Already elevated (probe reports admin): no elevation request at all.
    $r = Invoke-Replay '' '0'
    # The probe is itself a powershell call, so count ELEVATION requests only.
    $runAs = @($r.Calls | Where-Object { $_ -match 'RunAs' })
    Check ($runAs.Count -eq 0 -and $r.Continued) 'elevated console runs without any elevation request' ($r.Calls -join ' ; ')
    Check (@($r.Calls | Where-Object { $_ -match 'WindowsBuiltInRole' }).Count -eq 1) 'elevation is decided by exactly one token probe' ($r.Calls -join ' ; ')

    # 2. Not elevated, no marker yet: exactly one elevation request, then exit.
    $r = Invoke-Replay '' '1'
    $runAs = @($r.Calls | Where-Object { $_ -match 'RunAs' })
    Check ($runAs.Count -eq 1) 'first not-elevated run requests elevation exactly once' ($r.Calls -join ' ; ')
    Check ($runAs[0] -match 'elevation-attempted') 'relaunch carries the one-shot marker' ($runAs -join ' ; ')
    Check (-not $r.Continued) 'the un-elevated first run does not continue into the pipeline'

    # 3. Not elevated AND the marker is already present: abort, never re-prompt.
    $r = Invoke-Replay ' --elevation-attempted' '1'
    $runAs = @($r.Calls | Where-Object { $_ -match 'RunAs' })
    Check ($runAs.Count -eq 0) 'a still-unelevated relaunch never prompts a second time' ($r.Calls -join ' ; ')
    Check ($r.ExitCode -ne 0) 'the aborted relaunch returns a nonzero exit code' ("exit=$($r.ExitCode)")
    Check (-not $r.Continued) 'the aborted relaunch does not continue into the pipeline'
    Check ($r.Output -match 'will not ask again|Run as administrator') 'the abort explains how to elevate manually' $r.Output

    # 4. Elevated AND the marker present (UAC delayed): normal run, no prompt.
    $r = Invoke-Replay ' --elevation-attempted' '0'
    $runAs = @($r.Calls | Where-Object { $_ -match 'RunAs' })
    Check ($runAs.Count -eq 0 -and $r.Continued) 'a successful delayed elevation proceeds without a second prompt' ($r.Calls -join ' ; ')

    # 5. The wrapper forwards the marker to its dedicated child cmd.
    Check ($bat -match '(?ms)if not defined SCC_RUNNER_CHILD \(.*?%~f0" %\*"') 'the dedicated-child wrapper forwards arguments'
} finally {
    Remove-Item Env:SCC_STUB_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:SCC_STUB_RC -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ("Launcher elevation bound: failures={0} (fixture proof; no real UAC was shown)" -f $failures)
if ($failures) { exit 1 }
exit 0
