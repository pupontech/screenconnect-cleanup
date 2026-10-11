$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc-threat-shapes-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $findings=Join-Path $temp 'findings.json';$summary=Join-Path $temp 'scanners.json';$report=Join-Path $temp 'report.html'
    [IO.File]::WriteAllText($findings,'{"ComputerName":"Fixture","ScreenConnect":{"Instances":[],"Historical":[],"ParseIssues":[]},"OtherTargets":[]}')
    foreach($shape in @('{}','[]','null')) {
        [IO.File]::WriteAllText($summary,('[{"Scanner":"ESET","Status":"Completed","Findings":{"NotParseable":false,"ThreatCount":0,"Threats":'+$shape+'}}]'))
        & (Join-Path $repo 'New-InvestigationReport.ps1') -FindingsJson $findings -ScannerSummary $summary -OutputPath $report
        $html=[IO.File]::ReadAllText($report)
        if($html -match '\d+ threat\(s\) detected'){throw ('Empty threat shape fabricated a threat: '+$shape)}
        if(-not $html.Contains('Clean')){throw 'Empty parseable scanner results lost their clean label.'}
    }
    [IO.File]::WriteAllText($summary,'[{"Scanner":"ESET","Status":"Completed","Findings":{"NotParseable":false,"ThreatCount":1,"Threats":{"ThreatName":"FIXTURE_THREAT","Object":"<script>fixture</script>"}}}]')
    & (Join-Path $repo 'New-InvestigationReport.ps1') -FindingsJson $findings -ScannerSummary $summary -OutputPath $report
    $html=[IO.File]::ReadAllText($report)
    if(-not $html.Contains('FIXTURE_THREAT') -or -not $html.Contains('ESET - 1 threat(s) detected') -or $html.Contains('<script>fixture</script>')){throw 'Singleton threat rendering or escaping regressed.'}
    Write-Host 'PASS: null/empty-object/empty-array scanner threats do not fabricate detections; singleton threats remain escaped.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
