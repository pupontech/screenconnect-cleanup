# Execute the actual Stage 8 statement with a failing child, then render its report.
# All system operations are stubbed; only disposable evidence files are written.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc after snapshot failure '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'sc-cleanup.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Pipeline source did not parse.'}
    $stageStatement=$ast.EndBlock.Statements | Where-Object {$_.Extent.Text -match '^\$stage8Result\s*=|^try\s*\{\s*\$stage8Result\s*='} | Select-Object -First 1
    if(-not $stageStatement){throw 'Could not find the real Stage 8 statement.'}
    $invoke=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Stage'},$true)
    . ([scriptblock]::Create($invoke.Extent.Text))
    function Write-StageLog {param($Message,$Level)}
    function Write-Section {param($Message)}
    function Write-Dbg {param($Message)}
    function Invoke-ChildScript {param($ScriptPath,$ArgumentList,$LogTag) return 4}
    $ScriptRoot=$repo;$WorkDir=$temp;$IncidentDate='';$WhatIf=$false
    $stage1Result=@{Result=@{SnapshotPath=(Join-Path $temp 'before.json')}}
    [IO.File]::WriteAllText($stage1Result.Result.SnapshotPath,'{}')
    $priorDiff=Join-Path $temp 'snapshot_diff.json'
    [IO.File]::WriteAllText($priorDiff,'KEEP PRIOR DIFF EVIDENCE')
    try {. ([scriptblock]::Create($stageStatement.Extent.Text))} catch {throw ('After-snapshot failure escaped Stage 8 instead of preserving the report path: '+$_.Exception.Message)}
    if(-not $stage8Result.Result.DiffIncomplete -or $stage8Result.Result.DiffVerdict -ne 'INCOMPLETE'){throw 'Failed collection did not retain an incomplete stage outcome.'}
    if(-not (Test-Path -LiteralPath $stage8Result.Result.DiffPath)){throw 'Failed collection did not persist reportable evidence.'}
    if([IO.File]::ReadAllText($priorDiff) -cne 'KEEP PRIOR DIFF EVIDENCE'){throw 'Failure reporting overwrote prior diff evidence.'}
    $diff=Get-Content -LiteralPath $stage8Result.Result.DiffPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if($diff.Verdict -ne 'INCOMPLETE' -or $diff.AfterCollectionComplete -ne $false -or @($diff.AfterCollectionErrors).Count -lt 1){throw 'Failed-stage evidence claimed a complete or clean comparison.'}
    $findings=Join-Path $temp 'findings.json'
    @{ComputerName='FIXTURE';OSCaption='Synthetic';ScreenConnect=@{Instances=@();Historical=@()};OtherTargets=@();CollectionErrors=@()} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $findings -Encoding UTF8
    $report=Join-Path $temp 'report.html'
    & (Join-Path $repo 'New-InvestigationReport.ps1') -FindingsJson $findings -OutputPath $report -DiffPath $stage8Result.Result.DiffPath
    $html=[IO.File]::ReadAllText($report)
    if($html -notmatch 'INCOMPLETE' -or $html -notmatch 'exited with code 4'){throw 'Real report lost the failed-stage diagnosis.'}
    Write-Host 'PASS: failed after-snapshot retains INCOMPLETE evidence and the real HTML report renders the failure.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
