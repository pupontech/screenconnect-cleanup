<#
  Test-GuiPackageLayout.ps1 - the release package's top-level launcher.

  The zip holds only START-HERE-GUI.bat at the top (source: packaging\START-HERE-GUI.bat);
  everything else is in files\. This test lays a package out the same way - the top launcher,
  and a copy of the tool in files\ whose scripts are the Test-PhaseSplit.ps1 stubs - in folders
  whose names contain spaces and parentheses, runs the top launcher and checks that it reaches
  files\START-HERE-GUI.bat and the window (stubbed), with no UAC prompt: the elevation probe of
  the copied launcher is patched to "already elevated", like the other launcher tests do.

  The zip itself (which files go where, the manifest, byte-for-byte sources) is checked by
  tests\verify_deploy_zip.py and tests\test_power_options_repair_package.py.

  No admin, no window, nothing real runs. Windows PowerShell 5.1, pure ASCII, no BOM.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch]$KeepWork
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:TEMP ('scc-gui-package-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force
$script:Failures = New-Object System.Collections.ArrayList
$script:Passes = 0
function Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passes++; Write-Host ('  [pass] ' + $Message) -ForegroundColor Green }
    else { [void]$script:Failures.Add($Message); Write-Host ('  [FAIL] ' + $Message) -ForegroundColor Red }
}

# The stub from the batch test harness (records "script|arguments").
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ToolRoot 'tests\Test-PhaseSplit.ps1'), [ref]$tokens, [ref]$errs)
$stubAssign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$stubText' }, $true)
Invoke-Expression $stubAssign.Extent.Text
$stubText = $stubText.Replace('$try -lt 5', '$try -lt 200')

function New-Package {
    # <work>\<name>\START-HERE-GUI.bat + <work>\<name>\files\<the tool, scripts stubbed>
    param([string]$Name, [switch]$NoFiles)
    $pkg = Join-Path $work $Name
    $files = Join-Path $pkg 'files'
    $null = New-Item -ItemType Directory -Path $pkg -Force
    Copy-Item -LiteralPath (Join-Path $ToolRoot 'packaging\START-HERE-GUI.bat') -Destination (Join-Path $pkg 'START-HERE-GUI.bat')
    if ($NoFiles) { return $pkg }
    $null = New-Item -ItemType Directory -Path $files -Force
    foreach ($item in 'START-HERE-GUI.bat', 'tools', 'gui') { Copy-Item -LiteralPath (Join-Path $ToolRoot $item) -Destination $files -Recurse -Force }
    foreach ($ps in @(Get-ChildItem -Path $files -Filter '*.ps1' -Recurse -File)) {
        # The window stub lingers 3 s so the hidden Keep-Awake stub is done before the output is read.
        $text = $(if ($ps.Name -eq 'Start-CleanupGui.ps1') { $stubText.Replace('exit 0', 'Start-Sleep -Seconds 3; exit 0') } else { $stubText })
        Set-Content -LiteralPath $ps.FullName -Value $text -Encoding ASCII
    }
    $bat = Join-Path $files 'START-HERE-GUI.bat'
    $raw = [IO.File]::ReadAllText($bat)
    if (-not $raw.Contains('{exit 0}else{exit 1}')) { throw 'elevation probe not found in START-HERE-GUI.bat' }
    [IO.File]::WriteAllText($bat, $raw.Replace('{exit 0}else{exit 1}', '{exit 0}else{exit 0}'), [Text.Encoding]::ASCII)
    return $pkg
}

function Invoke-TopLauncher {
    param([string]$Pkg, [string]$Tag)
    $trace = Join-Path $work ($Tag + '.trace'); $out = Join-Path $work ($Tag + '.out'); $in = Join-Path $work ($Tag + '.in')
    Set-Content -LiteralPath $trace -Value '' -Encoding ASCII
    Set-Content -LiteralPath $in -Value ((@('', '', '') -join "`r`n")) -Encoding ASCII
    $env:SCC_TRACE = $trace
    $env:SCC_RUNNER_CHILD = '1'      # skip the dedicated-cmd relaunch so stdin redirection works (as the launcher tests do)
    try {
        $p = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/d /s /c ""' + (Join-Path $Pkg 'START-HERE-GUI.bat') + '" < "' + $in + '" > "' + $out + '" 2>&1"') -PassThru -WindowStyle Hidden
        if (-not $p.WaitForExit(90000)) { try { $p.Kill() } catch { }; return [pscustomobject]@{ Exit = -1; Names = @(); Out = '' } }
        $code = $p.ExitCode
        Start-Sleep -Seconds 2
        $names = @(Get-Content -LiteralPath $trace | Where-Object { $_ -and $_ -notlike 'Keep-Awake.ps1|*' } | ForEach-Object { $_.Split('|')[0] })
        return [pscustomobject]@{ Exit = $code; Names = $names; Out = [IO.File]::ReadAllText($out) }
    } finally { Remove-Item Env:\SCC_TRACE, Env:\SCC_RUNNER_CHILD -ErrorAction SilentlyContinue }
}

try {
    Write-Host 'Static: the top launcher' -ForegroundColor Cyan
    $topPath = Join-Path $ToolRoot 'packaging\START-HERE-GUI.bat'
    $top = [IO.File]::ReadAllText($topPath)
    $bytes = [IO.File]::ReadAllBytes($topPath)
    Check (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0 -and -not ($bytes[0] -eq 0xEF)) 'pure ASCII, no BOM'
    Check (([regex]::Matches($top, "`r`n")).Count -eq ([regex]::Matches($top, "`n")).Count) 'CRLF throughout'
    Check ($top -match 'set "SCC_TOP_DP0=%~dp0"' -and $top -match 'call "%SCC_TOP_DP0%files\\START-HERE-GUI\.bat" %\*') 'captures %~dp0 once and calls files\START-HERE-GUI.bat with the arguments'
    $code = @($top -split "`r`n" | Where-Object { $_ -notmatch '^\s*rem\b' -and $_.Trim() -ne '' })
    Check (@($code | Where-Object { $_ -match '\(' -and $_ -notmatch '^\s*echo' }).Count -eq 0) 'no ( ) block anywhere: a folder name with parentheses cannot break it'
    Check ($top -notmatch '(?i)powershell|runas|-Verb') 'it runs nothing itself and never asks for elevation (files\START-HERE-GUI.bat does, once)'
    $bundler = [IO.File]::ReadAllText((Join-Path $ToolRoot 'make-deploy-bundle.sh'))
    Check ($bundler -match 'D="\$PKG/files"' -and $bundler -match 'cp "\$SRC/packaging/START-HERE-GUI\.bat" "\$PKG/START-HERE-GUI\.bat"') 'the bundler puts everything in files\ and only this launcher on top'

    Write-Host 'Runtime: the package layout, in folders with spaces and parentheses' -ForegroundColor Cyan
    foreach ($case in @(@{ Name = 'plain'; Folder = 'screenconnect-cleanup' }, @{ Name = 'parentheses'; Folder = 'screenconnect-cleanup (1)' })) {
        $pkg = New-Package $case.Folder
        $r = Invoke-TopLauncher $pkg ('pkg-' + $case.Name)
        Check ($r.Exit -eq 0) ($case.Name + ': the top launcher finished with exit 0')
        Check (($r.Names -join ',') -eq 'Confirm-OnBattery.ps1,Start-CleanupGui.ps1') ($case.Name + ': it reached files\START-HERE-GUI.bat, the battery check and the window (' + ($r.Names -join ', ') + ')')
        Check ($r.Out -match 'opening the window') ($case.Name + ': files\START-HERE-GUI.bat ran (it told the technician to leave the console open)')
    }
    $pkg = New-Package 'no files here' -NoFiles
    $r = Invoke-TopLauncher $pkg 'pkg-missing'
    Check ($r.Exit -eq 1 -and $r.Out -match 'files" folder is missing') 'without the files folder: a clear message (extract the whole zip) and exit 1'
    Check ($r.Names.Count -eq 0) 'without the files folder nothing runs'
} finally {
    if ($KeepWork) { Write-Host ('Work folder kept: ' + $work) -ForegroundColor Yellow }
    elseif ($work -match 'scc-gui-package-[0-9a-f]{32}$' -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0
