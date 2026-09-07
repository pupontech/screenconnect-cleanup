# Run the actual detector module against synthetic inventories and a fake TCP provider.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'detect-remote-access.ps1'), [ref]$tokens, [ref]$errors)
foreach ($name in @('Test-AnyLike','Get-ScIdentifier','Find-ScParamBlob','Get-ConnectionsForPids','Invoke-ScreenConnectModule')) {
    $f = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    . ([scriptblock]::Create($f.Extent.Text))
}
function Write-Log { param([string]$Message) }
function Get-NetTCPConnection {
    [CmdletBinding()]
    param()
    $script:tcpCalls++
    return $script:tcpRows
}
$target = @{ servicePatterns = @(); pathPatterns = @(); uninstallPatterns = @(); processPatterns = @('ScreenConnect*') }
$ids = @('aaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbb')
$processes = @(0..2 | ForEach-Object {
    $id = $ids[[int]($_ -gt 0)]
    [pscustomobject]@{ ProcessId = 100 + $_; ParentProcessId = 1; Name = 'ScreenConnect.ClientService.exe'; ExecutablePath = "C:\ScreenConnect Client ($id)\client.exe"; CommandLine = ''; CreationDate = $null }
})
$script:tcpRows = @(100,101,102,999 | ForEach-Object {
    [pscustomobject]@{ LocalAddress = '192.0.2.1'; LocalPort = 50000; RemoteAddress = '198.51.100.1'; RemotePort = 8041; State = 'Established'; OwningProcess = $_ }
})
$failures = 0
function Check {
    param([string]$Name, [bool]$Ok)
    if ($Ok) { Write-Host "PASS: $Name" }
    else { Write-Host "FAIL: $Name"; $script:failures++ }
}
$script:tcpCalls = 0
$r = Invoke-ScreenConnectModule -Services @() -Processes $processes -UninstallEntries @() -Events @() -Target $target -RawDir ''
Check 'two instances share one TCP inventory query' ($script:tcpCalls -eq 1)
Check 'fixture produces exactly two instances' (@($r.Instances).Count -eq 2)
$a = @($r.Instances | Where-Object { $_.Identifier -eq $ids[0] })[0]
$b = @($r.Instances | Where-Object { $_.Identifier -eq $ids[1] })[0]
Check 'singleton connection remains an array associated with its instance' ($a.Connections -is [array] -and $a.Connections.Count -eq 1 -and $a.Connections[0].OwningProcess -eq 100)
Check 'multiple process connections stay with the second instance' (@($b.Connections).Count -eq 2 -and (@($b.Connections.OwningProcess | Sort-Object) -join ',') -eq '101,102')
Check 'unrelated process connections are excluded' (@($r.Instances.Connections | Where-Object { $_.OwningProcess -eq 999 }).Count -eq 0)
$script:tcpRows = @()
$r = Invoke-ScreenConnectModule -Services @() -Processes $processes -UninstallEntries @() -Events @() -Target $target -RawDir ''
Check 'next invocation queries fresh evidence instead of reusing a cache' ($script:tcpCalls -eq 2 -and @($r.Instances | Where-Object { @($_.Connections).Count -ne 0 }).Count -eq 0)
$script:tcpCalls = 0
$r = Invoke-ScreenConnectModule -Services @() -Processes @() -UninstallEntries @() -Events @() -Target $target -RawDir ''
Check 'no detected process needs no TCP query' ($script:tcpCalls -eq 0)
if ($failures) { throw "$failures detector connection regression(s) failed" }
Write-Host 'PASS: detector connection inventory regressions'
