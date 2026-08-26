$ErrorActionPreference = "Stop"
$cwd = (Get-Location).Path
$mod = Join-Path $cwd 'src' 'Scc.Remedy' 'Scc.Remedy.psd1'
Write-Host "mod path: $mod"
Import-Module $mod -Force -ErrorAction Stop
Write-Host "PSScriptRoot of Scc.Remedy: $((Get-Module Scc.Remedy).ModuleBase)"
$coreMod = Join-Path ((Get-Module Scc.Remedy).ModuleBase) '..' 'Scc.Core' 'Scc.Core.psd1'
Write-Host "core mod path: $coreMod"
Write-Host "core exists: $(Test-Path -LiteralPath $coreMod)"
try {
    Import-Module -LiteralPath $coreMod -Force -ErrorAction SilentlyContinue
    Write-Host "manual core import result, Write-SccLog: $((Get-Command Write-SccLog -ErrorAction SilentlyContinue) -ne $null)"
} catch {
    Write-Host "manual core import ERROR: $($_.Exception.Message)"
}
