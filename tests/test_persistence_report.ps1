$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$reportScript = Join-Path $root 'New-InvestigationReport.ps1'
$uploadScript = Join-Path $root 'Submit-ConnectWiseReport.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('persistence-report-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $findings = Join-Path $tmp 'findings.json'
    [IO.File]::WriteAllText($findings, '{"ComputerName":"Fixture","Tool":"test","Version":"1","ScreenConnect":{"Instances":[],"ParseIssues":[],"Historical":[]}}')
    $inv = Join-Path $tmp 'inventory.json'
    $rem = Join-Path $tmp 'removal.json'
    $res = Join-Path $tmp 'result.json'
    [IO.File]::WriteAllText($inv, '{"SchemaVersion":1,"Status":"SecretInventoryStatus_SENTINEL","Errors":["<script>alert(1)</script> & inventory coverage gap"],"Sections":{"Tasks":{"Status":"Incomplete","Errors":["<img src=x onerror=alert(2)>"]}},"Findings":[{"Id":"abc","Kind":"RunKey","Target":"<img src=x onerror=alert(3)>","Command":"powershell <b>local command</b>","Reason":"review"},{"Id":"def","Kind":"RunKey","Target":"registry target two","Command":"second command","Reason":"review"},{"Id":"ghi","Kind":"SecretKind_SENTINEL","Target":"private identity","Command":"RAW_COMMAND_SENTINEL","Reason":"review"}]}')
    [IO.File]::WriteAllText($rem, '{"Status":"SecretRemovalStatus_SENTINEL","Errors":["<svg onload=alert(4)>","RAW_REMOVAL_ERROR_SENTINEL"],"Actions":[{"Kind":"RunKey","Status":"Removed","Target":"<b>local action target</b>","BackupPath":"C:\\run\\backup.bak","Error":"<script>alert(5)</script>"},{"Kind":"RunKey","Status":"SecretOutcome_SENTINEL","Target":"RAW_TARGET_SENTINEL","BackupPath":"RAW_PATH_SENTINEL","Error":"RAW_ACTION_ERROR_SENTINEL"}]}')
    [IO.File]::WriteAllText($res, '{"Status":"Complete","InventoryStatus":"Complete","RemovalStatus":"Declined","Errors":["coverage incomplete & checked"]}')
    $htmlPath = Join-Path $tmp 'report.html'
    & $reportScript -FindingsJson $findings -OutputPath $htmlPath -PersistenceInventory $inv -PersistenceRemoval $rem -PersistenceResult $res
    $html = [IO.File]::ReadAllText($htmlPath)
    if ($html -notmatch 'Persistence') { throw 'persistence section missing' }
    if ($html -notmatch 'Incomplete or inconsistent evidence' -or $html -notmatch 'Removal status: Incomplete') { throw 'persistence statuses do not reflect incomplete inventory/removal evidence' }
    if ($html -notmatch '&lt;script&gt;' -or $html -match '<script>alert') { throw 'hostile HTML was not escaped' }
    foreach ($expected in @('powershell &lt;b&gt;local command&lt;/b&gt;','&lt;b&gt;local action target&lt;/b&gt;','C:\run\backup.bak','Tasks','Inventory status: Incomplete','Removal status: Incomplete','coverage incomplete &amp; checked','inventory coverage gap','RAW_REMOVAL_ERROR_SENTINEL','&lt;svg onload=alert(4)&gt;','&lt;img src=x onerror=alert(2)&gt;')) { if ($html -notmatch [regex]::Escape($expected)) { throw "expected local report field missing or unescaped: $expected" } }

    $missingPath = Join-Path $tmp 'missing.html'
    & $reportScript -FindingsJson $findings -OutputPath $missingPath -PersistenceInventory (Join-Path $tmp 'absent.json')
    $missingHtml = [IO.File]::ReadAllText($missingPath)
    if ($missingHtml -notmatch 'not found' -or $missingHtml -notmatch 'Missing or unavailable') { throw 'missing/incomplete status not presented conservatively' }
    if ($missingHtml -match 'Current-run persistence status: Complete') { throw 'missing inventory/result was presented as complete' }

    [IO.File]::WriteAllText($inv, '{"SchemaVersion":1,"Status":"Complete","Errors":[],"Sections":{"Tasks":{"Status":"Complete","Errors":[]}},"Findings":[]}')
    [IO.File]::WriteAllText($rem, '{"Status":"Declined","Errors":[],"Actions":[]}')
    [IO.File]::WriteAllText($res, '{"Status":"Complete","InventoryStatus":"Complete","RemovalStatus":"Declined","Errors":[]}')
    $declinedPath = Join-Path $tmp 'declined.html'
    & $reportScript -FindingsJson $findings -OutputPath $declinedPath -PersistenceInventory $inv -PersistenceRemoval $rem -PersistenceResult $res
    $declinedHtml = [IO.File]::ReadAllText($declinedPath)
    if ($declinedHtml -notmatch 'Current-run persistence status: Complete' -or $declinedHtml -notmatch 'Removal status: Declined' -or $declinedHtml -notmatch 'This is not a malware verdict') { throw 'coherent declined/complete collection status missing or misleading' }

    Remove-Item -LiteralPath $rem
    [IO.File]::WriteAllText($res, '{"Status":"Complete","InventoryStatus":"Complete","RemovalStatus":"Skipped","Errors":[]}')
    $skippedPath = Join-Path $tmp 'skipped.html'
    & $reportScript -FindingsJson $findings -OutputPath $skippedPath -PersistenceInventory $inv -PersistenceRemoval $rem -PersistenceResult $res
    $skippedHtml = [IO.File]::ReadAllText($skippedPath)
    if ($skippedHtml -notmatch 'Removal status: Skipped \(no removal manifest\)' -or $skippedHtml -notmatch 'Current-run persistence status: Complete' -or $skippedHtml -notmatch 'not a malware verdict') { throw 'skipped removal without a manifest did not remain visibly conservative' }

    $work = Join-Path $tmp 'package'
    New-Item -ItemType Directory -Path $work | Out-Null
    [IO.File]::WriteAllText($inv, '{"SchemaVersion":1,"Status":"Complete","Errors":[],"Sections":{"Tasks":{"Status":"Complete","Errors":[]}},"Findings":[{"Kind":"RunKey","Command":"UPLOAD_COMMAND_SENTINEL"},{"Kind":"ScheduledTask","Command":"UPLOAD_COMMAND_SENTINEL_2"},{"Kind":"SecretKind_SENTINEL","Command":"RAW_COMMAND_SENTINEL"}]}')
    [IO.File]::WriteAllText($rem, '{"Status":"Completed","Errors":[],"Actions":[{"Kind":"RunKey","Status":"Removed","Target":"RAW_TARGET_SENTINEL","BackupPath":"RAW_PATH_SENTINEL"}]}')
    [IO.File]::WriteAllText($res, '{"Status":"Complete","InventoryStatus":"Complete","RemovalStatus":"Completed","Errors":[]}')
    & $uploadScript -FindingsJson $findings -WorkDir $work -NoUpload -PersistenceInventory $inv -PersistenceRemoval $rem -PersistenceResult $res
    $zipPath = Join-Path $work 'connectwise-report.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try { $entry = $archive.GetEntry('connectwise-report.json'); $reader = New-Object IO.StreamReader($entry.Open()); try { $packageText = $reader.ReadToEnd() } finally { $reader.Dispose() } } finally { $archive.Dispose() }
    $packageData = $packageText | ConvertFrom-Json
    if ($packageData.Persistence.Status -ne 'Complete' -or $packageData.Persistence.FindingsByKind.RunKey -ne 1 -or $packageData.Persistence.FindingsByKind.ScheduledTask -ne 1 -or $packageData.Persistence.FindingsByKind.Unknown -ne 1 -or $packageData.Persistence.RemovalStatus -ne 'Completed' -or $packageData.Persistence.OutcomeCounts.Removed -ne 1) { throw 'sanitized package missing fixed persistence status/count summary' }
    foreach ($sentinel in @('SecretKind_SENTINEL','SecretOutcome_SENTINEL','SecretInventoryStatus_SENTINEL','SecretRemovalStatus_SENTINEL','RAW_COMMAND_SENTINEL','UPLOAD_COMMAND_SENTINEL','UPLOAD_COMMAND_SENTINEL_2','RAW_TARGET_SENTINEL','RAW_PATH_SENTINEL','RAW_ACTION_ERROR_SENTINEL','private identity','powershell')) {
        if ($packageText.Contains($sentinel)) { throw "raw persistence evidence leaked into package: $sentinel" }
    }

    $missingPackageWork = Join-Path $tmp 'missing-package'
    New-Item -ItemType Directory -Path $missingPackageWork | Out-Null
    & $uploadScript -FindingsJson $findings -WorkDir $missingPackageWork -NoUpload
    $missingZip = [IO.Compression.ZipFile]::OpenRead((Join-Path $missingPackageWork 'connectwise-report.zip'))
    try { $missingEntry = $missingZip.GetEntry('connectwise-report.json'); $missingReader = New-Object IO.StreamReader($missingEntry.Open()); try { $missingPackageText = $missingReader.ReadToEnd() } finally { $missingReader.Dispose() } } finally { $missingZip.Dispose() }
    $missingPackageData = $missingPackageText | ConvertFrom-Json
    if ($missingPackageData.Persistence.Status -eq 'Complete' -or $missingPackageData.Persistence.InventoryStatus -ne 'Missing or unavailable' -or $missingPackageData.Persistence.RemovalStatus -ne 'Missing or unavailable') { throw 'missing artifacts were marked complete in sanitized package' }

    [IO.File]::WriteAllText($inv, '{"Status":"MALFORMED_INVENTORY_STATUS_SENTINEL","Errors":["MALFORMED_INVENTORY_ERROR_SENTINEL"],"Sections":{"Tasks":{"Status":"Complete","Errors":[]}},"Findings":[{"Kind":"MALFORMED_KIND_SENTINEL"}]}')
    [IO.File]::WriteAllText($rem, '{"Status":"MALFORMED_REMOVAL_STATUS_SENTINEL","Errors":["MALFORMED_REMOVAL_ERROR_SENTINEL"],"Actions":[{"Status":"MALFORMED_OUTCOME_SENTINEL"}]}')
    [IO.File]::WriteAllText($res, '{"Status":"Complete","InventoryStatus":"Complete","RemovalStatus":"Declined","Errors":["MALFORMED_RESULT_ERROR_SENTINEL"]}')
    $malformedPackageWork = Join-Path $tmp 'malformed-package'
    New-Item -ItemType Directory -Path $malformedPackageWork | Out-Null
    & $uploadScript -FindingsJson $findings -WorkDir $malformedPackageWork -NoUpload -PersistenceInventory $inv -PersistenceRemoval $rem -PersistenceResult $res
    $malformedZip = [IO.Compression.ZipFile]::OpenRead((Join-Path $malformedPackageWork 'connectwise-report.zip'))
    try { $malformedEntry = $malformedZip.GetEntry('connectwise-report.json'); $malformedReader = New-Object IO.StreamReader($malformedEntry.Open()); try { $malformedPackageText = $malformedReader.ReadToEnd() } finally { $malformedReader.Dispose() } } finally { $malformedZip.Dispose() }
    $malformedPackage = $malformedPackageText | ConvertFrom-Json
    if ($malformedPackage.Persistence.Status -eq 'Complete' -or $malformedPackage.Persistence.FindingsByKind.Unknown -ne 1 -or $malformedPackage.Persistence.OutcomeCounts.Unknown -ne 1) { throw 'malformed persistence enums were not reduced to safe unknown counts/status' }
    foreach ($sentinel in @('MALFORMED_INVENTORY_STATUS_SENTINEL','MALFORMED_REMOVAL_STATUS_SENTINEL','MALFORMED_KIND_SENTINEL','MALFORMED_OUTCOME_SENTINEL','MALFORMED_INVENTORY_ERROR_SENTINEL','MALFORMED_REMOVAL_ERROR_SENTINEL','MALFORMED_RESULT_ERROR_SENTINEL')) { if ($malformedPackageText.Contains($sentinel)) { throw "malformed persistence value leaked to share package: $sentinel" } }
    Write-Host 'PASS test_persistence_report'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
