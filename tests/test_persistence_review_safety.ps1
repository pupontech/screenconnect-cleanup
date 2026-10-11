# The attended review must not overwrite pre-existing/redirected evidence.
# All launch calls are injected; no real window or system operation is started.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc review safety '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $run=Join-Path $temp 'run';$persist=Join-Path $run 'persistence'
    $null=New-Item -ItemType Directory -Path $persist -Force
    $inventory=@{SchemaVersion=1;RunId='run';Status='Complete';Errors=@();Findings=@();Sections=@{StartupFiles=@{Items=@()};RemoteToolServices=@{Items=@()}}}
    [IO.File]::WriteAllText((Join-Path $persist 'inventory.json'),($inventory | ConvertTo-Json -Depth 8))
    $sentinel=Join-Path $temp 'outside-sentinel.txt'
    [IO.File]::WriteAllText($sentinel,'KEEP OUTSIDE BYTES')
    $record=Join-Path $persist 'review-opened.json'
    $null=New-Item -ItemType HardLink -Path $record -Target $sentinel
    $global:SccReviewSafetyLaunches=0
    $launcher={param($file,$argumentList) $global:SccReviewSafetyLaunches++}
    $output=& (Join-Path $repo 'Show-PersistenceReview.ps1') -WorkDir $run -Launcher $launcher *>&1
    $exitCode=$LASTEXITCODE
    if([IO.File]::ReadAllText($sentinel) -cne 'KEEP OUTSIDE BYTES'){throw 'Review writer overwrote an unrelated file through a hard-linked audit record.'}
    if($exitCode -eq 0 -or $global:SccReviewSafetyLaunches -ne 0){throw 'Pre-existing review evidence was not refused before opening windows.'}
    if(($output -join ' ') -notmatch 'existing|already exists|fresh'){throw 'Refusal did not explain the existing review record.'}
    Write-Host 'PASS: existing hard-linked review record refused before launch; outside bytes preserved.'
    Remove-Item -LiteralPath $record -Force
    $redirect=Join-Path $temp 'redirect'
    $linkType=if($env:OS -eq 'Windows_NT'){'Junction'}else{'SymbolicLink'}
    $null=New-Item -ItemType $linkType -Path $redirect -Target $run
    $global:SccReviewSafetyLaunches=0
    $output=& (Join-Path $repo 'Show-PersistenceReview.ps1') -WorkDir $redirect -Launcher $launcher *>&1
    if($LASTEXITCODE -eq 0 -or $global:SccReviewSafetyLaunches -ne 0 -or (Test-Path -LiteralPath $record)){throw 'Review followed a redirected evidence folder instead of refusing it.'}
    Write-Host 'PASS: redirected review evidence refused before reads, launches or writes.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
