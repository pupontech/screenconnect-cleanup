$ErrorActionPreference = 'Stop'
$reportScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'New-InvestigationReport.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('power-report-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmp
$failures = 0
function Check($Name, $Condition) { if (-not $Condition) { Write-Host "FAIL: $Name" -ForegroundColor Red; $script:failures++ } else { Write-Host "PASS: $Name" -ForegroundColor Green } }
try {
  $findings = Join-Path $tmp 'findings.json'; $htmlPath = Join-Path $tmp 'report.html'
  @{ ComputerName='synthetic'; ScreenConnect=@{Instances=@();ParseIssues=@();Historical=@();RawFilesSaved=@()}; OtherTargets=@() } | ConvertTo-Json -Depth 8 | Set-Content $findings -Encoding UTF8
  & $reportScript -FindingsJson $findings -OutputPath $htmlPath *> $null
  $legacy = Get-Content $htmlPath -Raw
  Check 'backward compatibility: omitted optional argument produces report without repair section' ((Test-Path $htmlPath) -and -not $legacy.Contains('id="power-options-repair"'))

  $repair = Join-Path $tmp 'repair.json'
  @{Status='Completed';BackupRoot='C:\backup';ResetLocalGpoRequested=$false;ManagementState=@{ExplicitOverride=$true};Actions=@(@{Action='Registry';Status='Completed';Detail='saved'},@{Action='GpUpdate';Status='Completed';Detail='ran'});Notes=@('performed');ManagementWarnings=@('policy may reapply')} | ConvertTo-Json -Depth 8 | Set-Content $repair -Encoding UTF8
  & $reportScript -FindingsJson $findings -OutputPath $htmlPath -PowerOptionsRepair $repair *> $null; $html=Get-Content $htmlPath -Raw
  Check 'Completed evidence rendered' ($html.Contains('id="power-options-repair"') -and $html.Contains('Completed') -and $html.Contains('C:\backup') -and $html.Contains('policy may reapply') -and $html.Contains('Reset local GPO') -and $html.Contains('managed-device override opt-in: Yes'))
  Check 'action outcomes and details rendered' ($html.Contains('Registry') -and $html.Contains('saved') -and $html.Contains('GpUpdate') -and $html.Contains('ran'))

  @{Status='Partial';Actions=@(@{Action='x';Status='Failed';Detail='no'});Notes=@();ManagementWarnings=@()} | ConvertTo-Json -Depth 8 | Set-Content $repair -Encoding UTF8
  & $reportScript -FindingsJson $findings -OutputPath $htmlPath -PowerOptionsRepair $repair *> $null; $html=Get-Content $htmlPath -Raw
  Check 'Partial is never success' ($html.Contains('Partial') -and -not ($html -match 'id="power-options-repair"[^>]*>\s*<h2>[^<]*<span class="badge badge-low"'))

  & $reportScript -FindingsJson $findings -OutputPath $htmlPath -PowerOptionsRepair (Join-Path $tmp 'missing.json') *> $null; $html=Get-Content $htmlPath -Raw
  Check 'missing supplied evidence explicit incomplete' ($html.Contains('incomplete') -or $html.Contains('Incomplete') -or $html.Contains('unknown') -or $html.Contains('Unknown'))
  [IO.File]::WriteAllText($repair, '{"Status":')
  & $reportScript -FindingsJson $findings -OutputPath $htmlPath -PowerOptionsRepair $repair *> $null; $html=Get-Content $htmlPath -Raw
  Check 'malformed evidence explicit incomplete' ($html.Contains('incomplete') -or $html.Contains('Incomplete') -or $html.Contains('unknown') -or $html.Contains('Unknown'))
  foreach ($bad in @('null','[]','{"Status":"Completed","Actions":"bogus"}')) { [IO.File]::WriteAllText($repair,$bad); & $reportScript -FindingsJson $findings -OutputPath $htmlPath -PowerOptionsRepair $repair *> $null; $html=Get-Content $htmlPath -Raw; Check "wrong-shaped evidence fail closed: $bad" ($html.Contains('incomplete') -or $html.Contains('Incomplete') -or $html.Contains('unknown') -or $html.Contains('Unknown')) }

  @{Status='Completed';BackupRoot='<script>alert(1)</script>';Actions=@{Action='<img src=x onerror=alert(2)>';Status='Completed';Detail='<svg onload=alert(3)>'};Notes=@('<script>note</script>');ManagementWarnings=@('<iframe>warning</iframe>')} | ConvertTo-Json -Depth 8 | Set-Content $repair -Encoding UTF8
  & $reportScript -FindingsJson $findings -OutputPath $htmlPath -PowerOptionsRepair $repair *> $null; $html=Get-Content $htmlPath -Raw
  Check 'XSS escaped and singleton action shown' (-not $html.Contains('<script>alert(1)</script>') -and -not $html.Contains('<img src=x') -and -not $html.Contains('<svg onload') -and $html.Contains('&lt;script&gt;alert(1)&lt;/script&gt;') -and $html.Contains('onerror=alert(2)'))
  Check 'notes and management warnings escaped' (-not $html.Contains('<script>note</script>') -and -not $html.Contains('<iframe>warning</iframe>') -and $html.Contains('&lt;iframe&gt;warning&lt;/iframe&gt;'))
  @{Status='Completed';Actions=@();Notes=@();ManagementWarnings=@()} | ConvertTo-Json -Depth 8 | Set-Content $repair -Encoding UTF8
  & $reportScript -FindingsJson $findings -OutputPath $htmlPath -PowerOptionsRepair $repair *> $null; $html=Get-Content $htmlPath -Raw
  Check 'empty actions rendered honestly' ($html.Contains('No action outcomes') -or $html.Contains('No actions') -or $html.Contains('none recorded'))
} finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
if ($failures) { exit 1 }; Write-Host 'ALL POWER OPTIONS REPORT TESTS PASSED'
