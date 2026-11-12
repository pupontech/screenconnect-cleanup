# Filesystem-only path gates: scratch files/junctions, no live repair.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'PowerOptionsRepair.Windows.psm1') -Force
$root = Join-Path ([IO.Path]::GetTempPath()) ('scc-power-paths-' + [guid]::NewGuid().ToString('N'))
$work = Join-Path $root 'work'
$outside = Join-Path $root 'outside'
$null = [IO.Directory]::CreateDirectory($work)
$null = [IO.Directory]::CreateDirectory($outside)
$script:failures = 0
function Check {
    param([string]$Name, [bool]$Condition)
    if ($Condition) { Write-Host ('PASS  ' + $Name) }
    else { Write-Host ('FAIL  ' + $Name); $script:failures++ }
}
function Refuses {
    param([string]$Path, [string]$Parent)
    try { Assert-PowerRepairSafePath -Path $Path -Root $Parent; return $false }
    catch { return $true }
}
$link = Join-Path $work 'redirect'
try {
    $command = Get-Command Assert-PowerRepairSafePath -ErrorAction SilentlyContinue
    Check 'production path validator is available' ($null -ne $command)
    if ($command) {
        $future = Join-Path $work 'new-backup/result.json'
        Assert-PowerRepairSafePath -Path $future -Root $work
        Check 'normal non-existing child is accepted without creating it' (-not [IO.Directory]::Exists((Split-Path $future -Parent)))
        Check 'sibling-prefix escape is refused' (Refuses -Path (Join-Path ($work + '-other') 'result.json') -Parent $work)
        Check 'parent traversal outside root is refused' (Refuses -Path (Join-Path $work '../outside/result.json') -Parent $work)
        Check 'relative path is refused' (Refuses -Path 'relative/result.json' -Parent $work)
        $kind = if ($env:OS -eq 'Windows_NT') { 'Junction' } else { 'SymbolicLink' }
        $null = New-Item -ItemType $kind -Path $link -Target $outside
        Check 'existing reparse destination is refused' (Refuses -Path $link -Parent $work)
        Check 'non-existing child below reparse parent is refused' (Refuses -Path (Join-Path $link 'new/result.json') -Parent $work)
        Check 'reparse work root is refused' (Refuses -Path (Join-Path $link 'result.json') -Parent $link)
        Check 'outside destination was not written' (@([IO.Directory]::GetFileSystemEntries($outside)).Count -eq 0)
    }
} finally {
    # Remove the link itself before recursively deleting our disposable tree.
    if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) }
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
}
if ($script:failures -gt 0) { exit 1 }
Write-Host 'ALL POWER-OPTIONS PATH TESTS PASSED'
exit 0
