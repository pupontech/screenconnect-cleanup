<#
  Test-GuiLauncher.ps1 - START-HERE-GUI.bat.

  The launcher must start the way START-HERE.bat does, because every part of that preamble
  exists for a bug that was already paid for (parenthesised folder names, the dedicated cmd.exe
  for the keep-awake helper, ONE bounded UAC request, the battery check). The static checks pin
  the shared lines to START-HERE.bat byte for byte, so one cannot drift from the other. The
  runtime checks run the launcher against the Test-PhaseSplit.ps1 stubs: no admin, no UAC, no
  window, nothing real.

  Windows PowerShell 5.1, pure ASCII, no BOM.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch]$KeepWork
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:TEMP ('scc-gui-launcher-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force
$script:Failures = New-Object System.Collections.ArrayList
$script:Passes = 0
function Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passes++; Write-Host ('  [pass] ' + $Message) -ForegroundColor Green }
    else { [void]$script:Failures.Add($Message); Write-Host ('  [FAIL] ' + $Message) -ForegroundColor Red }
}

$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ToolRoot 'tests\Test-PhaseSplit.ps1'), [ref]$tokens, [ref]$errs)
$stubAssign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$stubText' }, $true)
Invoke-Expression $stubAssign.Extent.Text
$stubText = $stubText.Replace('$try -lt 5', '$try -lt 200')
foreach ($def in @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })) {
    if ($def.Name -ne 'Check') { Invoke-Expression $def.Extent.Text }
}

function Set-GuiStub {
    # The launcher's hidden Keep-Awake stub starts asynchronously and holds the output file for a moment;
    # a window stub that lingers 3 s lets it finish before the harness reads the output.
    param($Harness, [int]$ExitCode = 0)
    $f = Get-ChildItem -Path $Harness.Dir -Filter 'Start-CleanupGui.ps1' -Recurse -File | Select-Object -First 1
    if ($f) { Set-Content -LiteralPath $f.FullName -Value ($stubText.Replace('exit 0', 'Start-Sleep -Seconds 3; exit ' + $ExitCode)) -Encoding ASCII }
}

try {
    Write-Host 'Static: same start-up as START-HERE.bat' -ForegroundColor Cyan
    $gui = [IO.File]::ReadAllText((Join-Path $ToolRoot 'START-HERE-GUI.bat'))
    $main = [IO.File]::ReadAllText((Join-Path $ToolRoot 'START-HERE.bat'))
    $shared = @(
        'set "SCC_DP0=%~dp0"', 'set "SCC_F0=%~f0"', 'set "SCC_ARG1=%~1"', 'set "SCC_ARGS=%*"', 'setlocal EnableDelayedExpansion',
        'if not defined SCC_RUNNER_CHILD (', '    set "SCC_RUNNER_CHILD=1"',
        '        start "" /b /wait cmd.exe /d /s /c ""!SCC_F0!""', '        start "" /b /wait cmd.exe /d /s /c ""!SCC_F0!" !SCC_ARGS!"',
        '    set "SCC_RUNNER_RC=!errorlevel!"', '    exit /b !SCC_RUNNER_RC!',
        'set "SCC_SELF=!SCC_F0!"',
        'powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 0}else{exit 1}"',
        '    if /i "%%~A"=="--elevation-attempted" set "SCC_ELEV_ATTEMPTED=1"',
        'powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Confirm-OnBattery.ps1"',
        'if errorlevel 1 goto :battery_not_confirmed',
        'start "" powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Keep-Awake.ps1"',
        'cd /d "!SCC_DP0!"'
    )
    foreach ($line in $shared) {
        Check ($main.Contains($line) -and $gui.Contains($line)) ('both launchers contain: ' + $line.Trim().Substring(0, [Math]::Min(70, $line.Trim().Length)))
    }
    Check (([regex]::Matches($gui, '-Verb\s+RunAs')).Count -eq 1) 'exactly one elevation request'
    Check ($gui -match "--elevation-attempted" -and $gui -match 'WindowsBuiltInRole\]::Administrator') 'one-shot elevation marker and the real admin token check'
    Check ($gui -notmatch '(?i)fltmc') 'no fltmc probe'
    $nonInteractive = @($gui -split "`r?`n" | Where-Object { $_ -match '-NonInteractive' -and $_ -notmatch '^\s*rem' })
    Check ($nonInteractive.Count -eq 1 -and $nonInteractive[0] -match 'Keep-Awake\.ps1') '-NonInteractive appears only on the keep-awake helper (it would make Read-Host throw in the steps)'
    $guiLine = @($gui -split "`r?`n" | Where-Object { $_ -match 'Start-CleanupGui\.ps1' -and $_ -match '^\s*powershell' })
    Check ($guiLine.Count -eq 1 -and $guiLine[0] -match '-STA' -and $guiLine[0] -notmatch '-NonInteractive') 'the window is started with -STA and without -NonInteractive'
    Check ($gui -notmatch '[^\x00-\x7F]') 'START-HERE-GUI.bat is pure ASCII'
    $crlf = ([regex]::Matches($gui, "`r`n")).Count; $lf = ([regex]::Matches($gui, "`n")).Count
    Check ($crlf -eq $lf -and $crlf -gt 50) 'START-HERE-GUI.bat is CRLF throughout'
    Check ($gui -notmatch 'START-HERE\.bat"? *(--|%)' -and $gui -notmatch 'call .*START-HERE') 'it does not call START-HERE.bat (the two entry points stay independent)'

    Write-Host 'Runtime: the launcher against stubs' -ForegroundColor Cyan
    foreach ($case in @(@{ Name = 'plain'; Folder = 'gl-plain' }, @{ Name = 'parentheses'; Folder = 'gl par (1) x' })) {
        $h = New-Harness $case.Folder ''
        Set-GuiStub $h
        $r = Invoke-Launcher $h 'START-HERE-GUI.bat' @('') ('gl-' + $case.Name)
        $names = @($r.Trace | ForEach-Object { $_.Split('|')[0] })
        Check ((-not $r.Timeout) -and $r.Exit -eq 0) ($case.Name + ': finished with exit 0')
        Check (($names -join ',') -eq 'Confirm-OnBattery.ps1,Start-CleanupGui.ps1') ($case.Name + ': ran the battery check, then the window, and nothing else (' + ($names -join ', ') + ')')
        Check ($r.Out -match 'opening the window') ($case.Name + ': tells the technician to leave the console open')
        $dirs = @(Get-ChildItem -LiteralPath $h.Rit -Directory -ErrorAction SilentlyContinue)
        Check ($dirs.Count -eq 0) ($case.Name + ': the launcher creates no run folder itself (the window does)')
    }
    # a window that fails must pause so the error can be read, and pass its exit code on
    $h = New-Harness 'gl-fail' ''
    Set-GuiStub $h 5
    $r = Invoke-Launcher $h 'START-HERE-GUI.bat' @('', '') 'gl-fail'
    Check ($r.Exit -eq 5) 'a window that exits 5 makes the launcher exit 5'
    Check ($r.Out -match 'window ended with an error') 'and the console says so before pausing'
    # missing window script
    $h = New-Harness 'gl-missing' ''
    Remove-Item -LiteralPath (Join-Path $h.Dir 'gui') -Recurse -Force
    Start-Sleep -Seconds 1
    # This case returns instantly, so run it by hand and let the hidden Keep-Awake stub finish before reading the output.
    $mTrace = Join-Path $work 'gl-missing.trace'; $mOut = Join-Path $work 'gl-missing.out'; $mIn = Join-Path $work 'gl-missing.in'
    Set-Content -LiteralPath $mTrace -Value '' -Encoding ASCII
    Set-Content -LiteralPath $mIn -Value ((@('', '', '') -join "`r`n")) -Encoding ASCII
    $env:SCC_TRACE = $mTrace; $env:SCC_RUNNER_CHILD = '1'
    $mp = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/d /s /c ""' + (Join-Path $h.Dir 'START-HERE-GUI.bat') + '" < "' + $mIn + '" > "' + $mOut + '" 2>&1"') -PassThru -WindowStyle Hidden
    [void]$mp.WaitForExit(60000)
    $mCode = $mp.ExitCode
    Start-Sleep -Seconds 5
    $r = [pscustomobject]@{ Exit = $mCode; Out = [IO.File]::ReadAllText($mOut) }
    Check ($r.Exit -eq 1 -and $r.Out -match 'Start-CleanupGui\.ps1 is missing') 'no gui folder: a clear message, exit 1'
} finally {
    Remove-Item Env:\SCC_TRACE -ErrorAction SilentlyContinue
    Remove-Item Env:\SCC_RUNNER_CHILD -ErrorAction SilentlyContinue
    if ($KeepWork) { Write-Host ('Work folder kept: ' + $work) -ForegroundColor Yellow }
    elseif ($work -match 'scc-gui-launcher-[0-9a-f]{32}$' -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0
