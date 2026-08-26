$ErrorActionPreference = "Stop"
$cwd = Get-Location
$root = $cwd.Path
$mod = Join-Path $root 'src' 'Scc.Remedy' 'Scc.Remedy.psd1'
Import-Module $mod -Force -ErrorAction Stop
Write-Host "Scc.Remedy imported"
Write-Host "Write-SccLog available: $((Get-Command Write-SccLog -ErrorAction SilentlyContinue) -ne $null)"
Write-Host "ConvertTo-SccJson available: $((Get-Command ConvertTo-SccJson -ErrorAction SilentlyContinue) -ne $null)"
Write-Host "ConvertFrom-SccJson available: $((Get-Command ConvertFrom-SccJson -ErrorAction SilentlyContinue) -ne $null)"
Write-Host "New-SccPlan available: $((Get-Command New-SccPlan -ErrorAction SilentlyContinue) -ne $null)"
Write-Host "Get-SccQuarantineManifest available: $((Get-Command Get-SccQuarantineManifest -ErrorAction SilentlyContinue) -ne $null)"

$run = [PSCustomObject]@{ RunId='r1'; RunDir=(Join-Path ([System.IO.Path]::GetTempPath()) ('dbg_'+[guid]::NewGuid().ToString('N'))) }
New-Item -ItemType Directory -Path $run.RunDir -Force | Out-Null
$f = [PSCustomObject]@{ FindingId='sc1'; Product='screenconnect'; TargetType='Uninstall'; Detail=''; DisplayText='sc1'; ServiceName='ScreenConnect Client Service'; InstallDir='C:\SC\sc1'; MainExe=''; ServiceImagePath=''; UninstallRegistryKey=''; RelayHost='' }
$plan = New-SccPlan -Run $run -Findings @($f) -Decisions @{ 'sc1'='REMOVE' }
$pp = Join-Path $run.RunDir 'plan.json'
Write-Host "plan.json exists: $(Test-Path $pp)"
if (Test-Path $pp) { Write-Host "plan.json content: $([System.IO.File]::ReadAllText($pp))" }
Remove-Item -Path $run.RunDir -Recurse -Force -ErrorAction SilentlyContinue
