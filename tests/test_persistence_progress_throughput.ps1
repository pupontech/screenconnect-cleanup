# Drive the real worker supervisor with a completed, harmless high-volume provider.
# A buffered progress backlog must not manufacture a provider timeout.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc progress throughput '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$hostExe=(Get-Process -Id $PID).Path
try {
    foreach($name in @('Invoke-PersistenceScan.ps1','Invoke-PersistenceInventoryWorker.ps1')) {
        Copy-Item -LiteralPath (Join-Path $repo $name) -Destination $temp
    }
    $fixture=@'
function Get-SccPersistenceInventory {
    param([string]$OutDir)
    Write-Host 'SCC_PERSISTENCE_SECTION|BufferedFixture'
    for($i=0;$i -lt 600;$i++){Write-Host ('fixture stdout '+$i)}
    @{SchemaVersion=1;Status='Complete';Findings=@();Sections=@{};Errors=@()} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutDir 'inventory.json') -Encoding UTF8
    [IO.File]::WriteAllText((Join-Path $OutDir 'provider-finished.txt'),'600 lines; provider completed')
    Write-Host 'SCC_PERSISTENCE_DONE|BufferedFixture'
}
Export-ModuleMember -Function Get-SccPersistenceInventory
'@
    [IO.File]::WriteAllText((Join-Path $temp 'Persistence.Inventory.psm1'),$fixture,[Text.Encoding]::ASCII)
    $run=Join-Path $temp 'run'
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=$hostExe
    $psi.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $temp 'Invoke-PersistenceScan.ps1')+'" -WorkDir "'+$run+'" -SkipRemoval -InventorySectionTimeoutSeconds 12 -InventoryTotalTimeoutSeconds 20'
    $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
    $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $process=[Diagnostics.Process]::Start($psi)
    try {
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(25000)){$process.Kill();throw 'Supervisor did not obey the fixture wall-clock bound.'}
        $seconds=$clock.Elapsed.TotalSeconds
        $persist=Join-Path $run 'persistence'
        if(-not (Test-Path -LiteralPath (Join-Path $persist 'provider-finished.txt'))){throw 'Fixture provider did not finish; this is not a buffered-drain reproduction.'}
        $result=Get-Content -LiteralPath (Join-Path $persist 'result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $log=Get-Content -LiteralPath (Join-Path $persist 'collection-progress.log') -Raw -Encoding UTF8
        Write-Host ('MEASURE: 600 buffered lines, elapsed='+$seconds.ToString('F3',[Globalization.CultureInfo]::InvariantCulture)+'s; status='+$result.Status)
        if($process.ExitCode -ne 0 -or $result.Status -ne 'Complete') {throw ('Completed provider was falsely timed out while draining progress: '+($result.Errors -join ' | '))}
        if($log -notmatch 'fixture stdout 599' -or $log -notmatch 'SCC_PERSISTENCE_DONE\|BufferedFixture'){throw 'Supervisor dropped buffered progress instead of draining it.'}
        Write-Host 'PASS: buffered progress is drained without throttling a completed provider into a timeout.'
    } finally {$process.Dispose()}
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
