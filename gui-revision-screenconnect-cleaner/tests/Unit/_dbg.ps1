$ErrorActionPreference = "Stop"
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "PSScriptRoot=$PSScriptRoot"
$moduleDir = Join-Path $PSScriptRoot '..' '..' 'src' 'Scc.Remedy'
$modulePath = Join-Path $moduleDir 'Scc.Remedy.psd1'
Write-Host "modulePath=$modulePath exists=$(Test-Path $modulePath)"
Import-Module $modulePath -Force -ErrorAction Stop
Write-Host "imported OK"
$hp = Join-Path $PSScriptRoot '_SccRemedyHelpers.ps1'
Write-Host "helper exists=$(Test-Path $hp)"
. $hp
Write-Host "dot-sourced OK"
$r = New-TestRun
Write-Host "New-TestRun OK rundir=$($r.RunDir)"
$f = New-Finding -Id sc1 -Product screenconnect -ServiceName 'ScreenConnect Client Service'
Write-Host "New-Finding OK id=$($f.FindingId)"
$plan = New-SccPlan -Findings @($f) -Decisions @{ 'sc1' = 'REMOVE' }
Write-Host "New-SccPlan OK action=$($plan.Items[0].Action)"
Remove-TestRun $r
Write-Host "DONE"
