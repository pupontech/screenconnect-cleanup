# Safe native console-visibility regression; never runs cleanup or real dialogs.
[CmdletBinding()]
param([string]$RepositoryRoot = '')
$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) { $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
$batch = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'START-HERE.bat'))
$batteryLines = @($batch -split '\r?\n' | Where-Object { $_ -match '^powershell\.exe .*Confirm-OnBattery\.ps1' })
if ($batteryLines.Count -ne 1) { throw 'Expected exactly one foreground battery invocation.' }
$batteryLine = $batteryLines[0]
if ($batteryLine -match '(?i)-WindowStyle\s+Hidden') { throw 'Foreground battery check hides the attached runner console.' }
if ($batch -notmatch '(?m)^start "" powershell\.exe .*?-WindowStyle Hidden .*Keep-Awake\.ps1') { throw 'Separate keep-awake child must retain its hidden window.' }
Write-Host 'PASS: foreground battery invocation does not hide its console; separate keep-awake remains hidden.'
if ($env:OS -ne 'Windows_NT') { Write-Host 'SKIP: native window visibility requires Windows.'; exit 0 }

$root = Join-Path ([IO.Path]::GetTempPath()) ('scc-visible-' + [guid]::NewGuid().ToString('N'))
$tools = Join-Path $root 'tools'
New-Item -ItemType Directory -Path $tools | Out-Null
$csharp = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
public static class SccConsoleObserver {
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int mode);
    public static int Main(string[] args) {
        IntPtr window = GetConsoleWindow();
        bool before = window != IntPtr.Zero && IsWindowVisible(window);
        int rc = -1;
        bool after = false;
        try {
            var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec"));
            info.Arguments = "/d /s /c \"\"" + args[0] + "\"\"";
            info.UseShellExecute = false;
            info.CreateNoWindow = false;
            using (var child = Process.Start(info)) {
                if (!child.WaitForExit(15000)) { child.Kill(); return 2; }
                rc = child.ExitCode;
            }
            after = window != IntPtr.Zero && IsWindowVisible(window);
            File.WriteAllLines(args[1], new string[] {
                "WindowBefore=" + before, "WindowAfter=" + after, "ChildExit=" + rc
            }, Encoding.ASCII);
            return 0;
        } finally {
            // The deliberately buggy negative control must not leave hidden windows.
            if (window != IntPtr.Zero) ShowWindow(window, 5);
        }
    }
}
'@
try {
    $source = Join-Path $root 'Observer.cs'
    $exe = Join-Path $root 'Observer.exe'
    [IO.File]::WriteAllText($source, $csharp, [Text.Encoding]::ASCII)
    $compiler = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $compiler)) { throw 'Required Windows Framework C# compiler missing.' }
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $compileOutput = & $compiler /nologo /target:exe ("/out:" + $exe) $source 2>&1
        $compileExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $oldPreference }
    if ($compileExit -ne 0) { throw ('Native observer compile failed: ' + ($compileOutput -join ' ')) }
    foreach ($scenario in @('HiddenNegativeControl','ContinueVisible','CancelVisible')) {
        $exitCode = 0
        if ($scenario -eq 'CancelVisible') { $exitCode = 1 }
        [IO.File]::WriteAllText((Join-Path $tools 'Confirm-OnBattery.ps1'), ('exit ' + $exitCode), [Text.Encoding]::ASCII)
        $line = $batteryLine
        if ($scenario -eq 'HiddenNegativeControl') { $line = $line.Replace(' -STA ', ' -STA -WindowStyle Hidden ') }
        $marker = Join-Path $root ($scenario + '.continued')
        $fixture = Join-Path $root ($scenario + '.bat')
        $report = Join-Path $root ($scenario + '.report')
        $lines = @('@echo off', $line, 'if errorlevel 1 exit /b 1', ('echo continued>"' + $marker + '"'), 'exit /b 0')
        [IO.File]::WriteAllText($fixture, (($lines -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
        $process = Start-Process -FilePath $exe -ArgumentList ('"' + $fixture + '" "' + $report + '"') -WindowStyle Normal -PassThru
        try {
            if (-not $process.WaitForExit(25000)) { $process.Kill(); throw ($scenario + ' observer timed out.') }
            if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $report)) { throw ($scenario + ' observer did not finish with a report.') }
            $values = [IO.File]::ReadAllText($report)
            if ($values -notmatch 'WindowBefore=True') { throw ($scenario + ' fixture did not start with a visible console: ' + $values) }
            $expectedVisible = 'True'
            if ($scenario -eq 'HiddenNegativeControl') { $expectedVisible = 'False' }
            if ($values -notmatch ('WindowAfter=' + $expectedVisible) -or $values -notmatch ('ChildExit=' + $exitCode)) { throw ($scenario + ' unexpected native result: ' + $values) }
            if ((Test-Path -LiteralPath $marker) -ne ($exitCode -eq 0)) { throw ($scenario + ' continuation/cancellation marker was wrong.') }
            Write-Host ('PASS: ' + $scenario + ' ' + ($values.Trim() -replace '\r?\n', '; '))
        } finally { $process.Dispose() }
    }
    Write-Host 'PASS: native Windows console remains visible on continue/cancel; old Hidden flag reproduces disappearance. No cleanup ran; UAC consent and real battery dialog remain owner-live gates.'
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
