$ErrorActionPreference = "Stop"
$cwd = (Get-Location).Path
$coreMod = Join-Path $cwd 'src' 'Scc.Core' 'Scc.Core.psd1'
Write-Host "coreMod: $coreMod exists=$(Test-Path $coreMod)"
try {
    Import-Module -Path $coreMod -Force -ErrorAction Stop
    Write-Host "Import-Module -Path OK; Write-SccLog: $((Get-Command Write-SccLog -ErrorAction SilentlyContinue) -ne $null)"
} catch {
    Write-Host "Import-Module -Path ERROR: $($_.Exception.Message)"
}
try {
    Import-Module -LiteralPath $coreMod -Force -ErrorAction Stop
    Write-Host "Import-Module -LiteralPath OK"
} catch {
    Write-Host "Import-Module -LiteralPath ERROR: $($_.Exception.Message)"
}
