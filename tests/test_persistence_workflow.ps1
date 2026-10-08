[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$cleanupPath=Join-Path $root 'sc-cleanup.ps1'
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($cleanupPath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ('sc-cleanup parse errors: '+($parseErrors -join '; '))}
$stageAssign=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$stage5bResult'},$true)
if(-not $stageAssign){throw 'Could not locate actual Stage 5b assignment.'}
$invoke=$stageAssign.Right
$blockAst=$invoke.Find({param($n) $n -is [Management.Automation.Language.ScriptBlockExpressionAst] -and $n.Extent.Text -match 'Invoke-ChildScript'},$true)
if(-not $blockAst){throw 'Stage 5b has no StageBlock.'}
$block=[scriptblock]::Create($blockAst.ScriptBlock.EndBlock.Extent.Text)
$work=Join-Path ([IO.Path]::GetTempPath()) ('persistence workflow fixture '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $work -Force
$script:MockChildRc=0; $script:MockThrowChild=$false; $script:LastMockArguments=@()
function Invoke-ChildScript { param($ScriptPath,$ArgumentList,$LogTag) $script:LastMockArguments=@($ArgumentList); if($script:MockThrowChild){throw 'synthetic child launch failure'}; $idx=[array]::IndexOf($ArgumentList,'-WorkDir'); $wd=$ArgumentList[$idx+1]; $pd=Join-Path $wd 'persistence'; $null=New-Item -ItemType Directory -Path $pd -Force; @{SchemaVersion=1;Status=$(if($script:MockChildRc -eq 0){'Complete'}else{'Incomplete'});InventoryStatus='Complete';RemovalStatus='Skipped';Errors=@()}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $pd 'result.json'); return $script:MockChildRc }
function Write-StageLog { param($Message,$Level) }
function Write-Section { param($Message) }
function Write-Dbg { param($Message) }
$ScriptRoot=$root; $WorkDir=$work; $np=$false; $sr=$false; $WhatIf=$false
$script:RestorePointFailed=$false; $script:RegistryExportFailed=$false
$registry=Join-Path $work 'registry_hives'; $null=New-Item -ItemType Directory -Path $registry -Force
foreach($n in @('HKLM_SOFTWARE.reg','HKLM_SYSTEM.reg','HKCU_SOFTWARE.reg')){[IO.File]::WriteAllText((Join-Path $registry $n),'fixture')}
$result=& $block
if($result.ExitCode -ne 0 -or $script:LastMockArguments -notcontains '-RollbackReady'){throw ('Actual Stage 5b failed: result='+($result|ConvertTo-Json -Compress)+' args='+($script:LastMockArguments -join '|'))}
if($script:LastMockArguments[[array]::IndexOf($script:LastMockArguments,'-WorkDir')+1] -cne $work){throw 'WorkDir containing spaces was not passed as a single argument.'}
$script:MockChildRc=1
$result=& $block
if($result.ExitCode -ne 1 -or -not (Test-Path -LiteralPath $result.ResultPath)){throw 'Nonzero persistence child result was not retained for report continuation.'}
$script:MockChildRc=0
$script:MockThrowChild=$true
$result=& $block
if($result.ExitCode -ne 1){throw 'Child launch failure was not recorded for later reporting.'}
$script:MockThrowChild=$false
$missingRoot=Join-Path $work 'missing-root'; $ScriptRoot=$missingRoot
$result=& $block
if($result.ExitCode -ne 1){throw 'Missing child script was not recorded for later reporting.'}
# Exercise the production strict-mode-safe final outcome statements with an Invoke-Stage WhatIf result.
$finalAssignment=$ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$persistenceExitCode'},$true) | Select-Object -First 1
$pipelineAssignment=$ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$pipelineIncomplete'},$true) | Select-Object -First 1
if(-not $finalAssignment -or -not $pipelineAssignment){throw 'Production final persistence outcome expression not found.'}
$reportStage=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$stage9Result'},$true)
if(-not $reportStage -or $reportStage.Extent.StartOffset -lt $stageAssign.Extent.StartOffset){throw 'Report stage does not follow mandatory persistence stage.'}
Set-StrictMode -Version 2.0
$stage5bResult=@{Skipped=$false;Result=@{WhatIf=$true}}
$removalExitCode=$null; $diffIncomplete=$false; $reportUploadFailed=$false; $scannerStageFailure=$null
. ([scriptblock]::Create($finalAssignment.Extent.Text+';'+$pipelineAssignment.Extent.Text))
if($pipelineIncomplete){throw 'WhatIf stage was incorrectly reported incomplete by a missing ExitCode read.'}
$batText=[IO.File]::ReadAllText((Join-Path $root 'START-HERE.bat'))
if($batText -notmatch '(?m)^powershell .*Invoke-PersistenceScan\.ps1" -WorkDir "!SCC_RUN_ROOT!" -PreflightRoot "!SCC_RUN_ROOT!"') { throw 'Guided runner does not quote the run root and preflight root as arguments.' }
$batBytes=[IO.File]::ReadAllBytes((Join-Path $root 'START-HERE.bat'))
for($i=0;$i -lt $batBytes.Length;$i++){if($batBytes[$i] -eq 10 -and ($i -eq 0 -or $batBytes[$i-1] -ne 13)){throw 'START-HERE.bat contains a non-CRLF line ending.'}}
if($env:OS -eq 'Windows_NT' -and (Get-Command cmd.exe -ErrorAction SilentlyContinue)) {
    $step6d=[regex]::Match($batText,'(?ms)^rem ---- Step 6d:.*?(?=^rem ---- Step 7:)').Value
    if(-not $step6d){throw 'Could not extract the actual guided Step 6d command block.'}
    $shimDir=Join-Path $work 'cmd shim'; $null=New-Item -ItemType Directory -Path $shimDir -Force
    $logPath=Join-Path $work 'powershell args.txt'
    # Framework csc creates an executable usable from cmd.exe in both host
    # editions; PowerShell 7 Add-Type cannot emit ConsoleApplication output.
    $stubSource=Join-Path $shimDir 'stub.cs'
    [IO.File]::WriteAllText($stubSource,'using System; using System.IO; public class Stub { public static int Main(string[] args) { File.WriteAllLines(Environment.GetEnvironmentVariable("SCC_STUB_LOG"), args); int rc=0; int.TryParse(Environment.GetEnvironmentVariable("SCC_STUB_RC"),out rc); return rc; } }',[Text.Encoding]::ASCII)
    $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if(-not(Test-Path -LiteralPath $compiler)){$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'}
    if(-not(Test-Path -LiteralPath $compiler)){throw 'Windows fixture C# compiler is unavailable.'}
    $stubExe=Join-Path $shimDir 'powershell.exe'
    $compileOutput=& $compiler /nologo /target:exe ('/out:'+$stubExe) $stubSource 2>&1
    if($LASTEXITCODE -ne 0){throw ('cmd fixture compiler failed: '+($compileOutput -join ' | '))}
    $env:SCC_STUB_LOG=$logPath; $env:PATH=$shimDir+';'+$env:PATH
    $fixtureBat=Join-Path $work 'replay Step6d.bat'
    $fixtureText="@echo off`r`nsetlocal EnableDelayedExpansion`r`nset `"SCC_RUN_ROOT=$work`"`r`nset `"PIPE_RC=0`"`r`n$step6d`r
echo ReplayRC=!PIPE_RC!`r`nexit /b !PIPE_RC!`r`n"
    [IO.File]::WriteAllText($fixtureBat,$fixtureText,[Text.Encoding]::ASCII)
    $cmd=(Get-Command cmd.exe).Source
    $cmdInfo=New-Object Diagnostics.ProcessStartInfo
    $cmdInfo.FileName=$cmd
    $cmdInfo.Arguments='/d /s /c ""'+$fixtureBat+'""'
    $cmdInfo.UseShellExecute=$false;$cmdInfo.RedirectStandardOutput=$true;$cmdInfo.RedirectStandardError=$true
    $cmdProcess=[Diagnostics.Process]::Start($cmdInfo)
    $cmdOut=$cmdProcess.StandardOutput.ReadToEndAsync();$cmdErr=$cmdProcess.StandardError.ReadToEndAsync()
    if(-not $cmdProcess.WaitForExit(20000)){$cmdProcess.Kill();throw 'cmd Step 6d fixture exceeded its bounded wait.'}
    $replayOutput=$cmdOut.Result;$replayError=$cmdErr.Result
    if($cmdProcess.ExitCode -ne 0){throw ('cmd Step 6d replay failed: '+$replayOutput+' | '+$replayError)}
    $stubArgs=Get-Content -LiteralPath $logPath
    if($stubArgs -notcontains '-WorkDir' -or $stubArgs -notcontains $work -or $stubArgs -notcontains '-PreflightRoot'){throw 'cmd Step 6d replay lost a quoted path or omitted a mandatory argument.'}
    if(($replayOutput -join ' ') -notmatch 'STEP 6d/9'){throw 'cmd Step 6d did not execute unconditionally.'}
    $env:SCC_STUB_RC='3'
    $failedReplay=[Diagnostics.Process]::Start($cmdInfo)
    $failedOut=$failedReplay.StandardOutput.ReadToEndAsync();$failedErr=$failedReplay.StandardError.ReadToEndAsync()
    if(-not $failedReplay.WaitForExit(20000)){$failedReplay.Kill();throw 'cmd failure-path fixture exceeded its bounded wait.'}
    if($failedReplay.ExitCode -ne 3 -or $failedOut.Result -notmatch 'ReplayRC=3' -or $failedOut.Result -notmatch 'evidence will still be reported') {throw ('cmd failed persistence step did not continue truthfully: '+$failedOut.Result+' | '+$failedErr.Result)}
    Remove-Item Env:SCC_STUB_RC -ErrorAction SilentlyContinue
    Remove-Item Env:SCC_STUB_LOG -ErrorAction SilentlyContinue
}
$psHost=(Get-Command pwsh -ErrorAction Stop).Source
$whatIfWork=Join-Path $work 'direct WhatIf run'
$whatIfOutput=& $psHost -NoProfile -File (Join-Path $root 'Invoke-PersistenceScan.ps1') -WorkDir $whatIfWork -WhatIf 2>&1
if($LASTEXITCODE -ne 0){throw ('Direct WhatIf unexpectedly failed: '+($whatIfOutput -join ' | '))}
$whatIfResult=Get-Content -LiteralPath (Join-Path $whatIfWork 'persistence/result.json') -Raw | ConvertFrom-Json
if($whatIfResult.Status -ne 'Complete' -or $whatIfResult.InventoryStatus -ne 'Planned' -or $whatIfResult.RemovalStatus -ne 'Planned' -or -not (Test-Path -LiteralPath (Join-Path $whatIfWork 'persistence/removal.json'))) {throw 'Direct WhatIf did not persist coherent planned artifacts.'}
$badRoot=Join-Path $work 'preflight with spaces'
$run=Join-Path $badRoot 'host-20261008'; $null=New-Item -ItemType Directory -Path (Join-Path $run 'registry') -Force
[IO.File]::WriteAllText((Join-Path $run 'master.log'),"[OK] restore point + hive export`r`nPREFLIGHT COMPLETE fixture`r`n")
foreach($n in @('HKLM-SOFTWARE.hiv','HKLM-SYSTEM.hiv','HKCU.hiv')){[IO.File]::WriteAllText((Join-Path $run ('registry/'+$n)),'fixture')}
$readinessWork=Join-Path $work 'guided WhatIf'; $null=& $psHost -NoProfile -File (Join-Path $root 'Invoke-PersistenceScan.ps1') -WorkDir $readinessWork -PreflightRoot $badRoot -WhatIf; if($LASTEXITCODE -ne 0){throw 'Guided WhatIf preflight readiness fixture failed.'}
$readinessResult=Get-Content -LiteralPath (Join-Path $readinessWork 'persistence/result.json') -Raw | ConvertFrom-Json
if(-not $readinessResult.RollbackReady){throw 'Guided readiness rejected exact successful preflight fixture artifacts.'}
$missingScriptRoot=Join-Path $work 'runner without modules'; $null=New-Item -ItemType Directory -Path $missingScriptRoot -Force
Copy-Item -LiteralPath (Join-Path $root 'Invoke-PersistenceScan.ps1') -Destination $missingScriptRoot
$failedWork=Join-Path $work 'missing module run'; $failedOutput=& $psHost -NoProfile -File (Join-Path $missingScriptRoot 'Invoke-PersistenceScan.ps1') -WorkDir $failedWork 2>&1
if($LASTEXITCODE -eq 0){throw 'Missing inventory module was incorrectly reported successful.'}
if(-not (Test-Path -LiteralPath (Join-Path $failedWork 'persistence/removal.json')) -or -not (Test-Path -LiteralPath (Join-Path $failedWork 'persistence/result.json'))){throw 'Missing-module failure did not preserve removal and result artifacts.'}
Remove-Item -LiteralPath $work -Recurse -Force
Write-Host 'PASS: actual Stage 5b fixture invocation, child failures, quoted WorkDir, WhatIf refusal, and guided readiness fixtures.'
