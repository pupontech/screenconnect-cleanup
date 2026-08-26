$ErrorActionPreference = "Stop"
$cwd = (Get-Location).Path
$coreMod = Join-Path $cwd 'src' 'Scc.Core' 'Scc.Core.psd1'
Get-Command Import-Module | Select-Object -ExpandProperty ParameterSets | ForEach-Object { $_.Name; $_.Parameters | ForEach-Object { "  -$($_.Name)" } }
Write-Host "--- trying positional ---"
try {
    Import-Module $coreMod -Force -ErrorAction Stop
    Write-Host "positional OK; Write-SccLog: $((Get-Command Write-SccLog -ErrorAction SilentlyContinue) -ne $null)"
} catch {
    Write-Host "positional ERROR: $($_.Exception.Message)"
}
