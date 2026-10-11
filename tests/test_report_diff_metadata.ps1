# Incomplete/malformed comparison metadata must never receive green report status.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc-diff-report-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $findings=Join-Path $temp 'findings.json'; $diff=Join-Path $temp 'diff.json'; $htmlPath=Join-Path $temp 'report.html'
    [IO.File]::WriteAllText($findings,'{"ComputerName":"Fixture","ScreenConnect":{"Instances":[],"Historical":[],"ParseIssues":[]},"OtherTargets":[]}')
    foreach($invalid in @('{}','{"Note":"Basic comparison only"}','{"Verdict":"CLEAN","BeforeCollectionComplete":null,"AfterCollectionComplete":true,"BeforeCollectionErrors":[],"AfterCollectionErrors":[]}','{"Verdict":"CLEAN","BeforeCollectionComplete":true,"AfterCollectionComplete":true}','{"Verdict":"CLEAN","BeforeCollectionComplete":"true","AfterCollectionComplete":true,"BeforeCollectionErrors":[],"AfterCollectionErrors":[]}')) {
        [IO.File]::WriteAllText($diff,$invalid)
        & (Join-Path $repo 'New-InvestigationReport.ps1') -FindingsJson $findings -DiffPath $diff -OutputPath $htmlPath
        $html=[IO.File]::ReadAllText($htmlPath)
        if($html.Contains('No collection errors were recorded.') -or $html.Contains('badge badge-low">UNKNOWN') -or $html.Contains('badge badge-low">CLEAN')){throw 'Missing or invalid diff metadata received green status.'}
        if(-not $html.Contains('snapshot diff unavailable')){throw 'Invalid comparison metadata was not reported visibly.'}
    }
    foreach($partial in @('{"Verdict":"CLEAN","BeforeCollectionComplete":true,"AfterCollectionComplete":false,"BeforeCollectionErrors":[],"AfterCollectionErrors":[],"Sections":[]}','{"Verdict":"CLEAN","BeforeCollectionComplete":true,"AfterCollectionComplete":true,"BeforeCollectionErrors":[],"AfterCollectionErrors":[{"Section":"Fixture","Error":"coverage gap"}],"Sections":[]}')) {
        [IO.File]::WriteAllText($diff,$partial)
        & (Join-Path $repo 'New-InvestigationReport.ps1') -FindingsJson $findings -DiffPath $diff -OutputPath $htmlPath
        $html=[IO.File]::ReadAllText($htmlPath)
        if($html.Contains('badge badge-low">CLEAN') -or -not $html.Contains('badge badge-high">INCOMPLETE')){throw 'Contradictory CLEAN verdict defeated incomplete collection evidence.'}
    }
    Write-Host 'PASS: absent/invalid diff metadata and contradictory verdicts fail closed.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
