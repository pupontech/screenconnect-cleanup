$ErrorActionPreference = 'Stop'
$tmpRoot = if ($env:TEMP) { $env:TEMP } else { '/tmp' }
$tmp = Join-Path $tmpRoot ('scc-report-test-' + (Get-Random))
$null = New-Item -ItemType Directory -Path $tmp -Force
$repo = Split-Path -Parent $PSScriptRoot
$reportScript = Join-Path $repo 'New-InvestigationReport.ps1'
$reportSource = Get-Content -LiteralPath $reportScript -Raw

# Minimal but valid findings.json (hostile values to prove escaping still holds)
$findings = @{
    ComputerName = 'TESTPC'
    OSCaption    = '<img src=x onerror=alert(2)>'
    TargetsSelected = @('screenconnect')
    TargetsSource = 'embedded'
    ScreenConnect = @{
        Instances  = @()
        ParseIssues = @()
        Historical  = @()
        RawFilesSaved = @('C:\raw\x.config')
    }
    OtherTargets = @(
        @{ Id = 'anydesk'; Name = 'AnyDesk'; Hits = @() }
    )
}
$findingsJson = Join-Path $tmp 'findings.json'
$findings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $findingsJson -Encoding UTF8 -NoNewline

# A one-instance JSON result is serialized as a bare object by Windows
# PowerShell 5.1. The report must preserve array context before reading .Count.
$singleFindings = @{
    ComputerName = 'ONE-PC'
    OSCaption    = 'Windows'
    TargetsSelected = @('screenconnect')
    TargetsSource = 'embedded'
    ScreenConnect = @{
        Instances  = @(@{ Identifier = 'only-instance'; Key = 'only-instance'; Sources = @('service') })
        ParseIssues = @()
        Historical  = @()
        RawFilesSaved = @()
    }
    OtherTargets = @()
}
$singleFindingsJson = Join-Path $tmp 'single-findings.json'
$singleFindings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $singleFindingsJson -Encoding UTF8 -NoNewline
$singleOut = Join-Path $tmp 'single-report.html'
& $reportScript -FindingsJson $singleFindingsJson -OutputPath $singleOut *> $null
$singleHtml = Get-Content -LiteralPath $singleOut -Raw

# KVRT findings: encrypted traces are not parseable
$kvrtFindings = @{
    Scanner      = 'KVRT'
    NotParseable = $true
    Error        = 'KVRT reports are encrypted (.enc1) or missing. Re-run KVRT with -accepteula -dontencrypt -details to write plain-text reports under C:\KVRT_Data\Reports.'
    Threats      = @()
    ThreatCount  = 0
    Stats        = $null
    LogPath      = $null
    ScanDate     = $null
}
$kvrtFindingsPath = Join-Path $tmp 'scanner-KVRT-findings.json'
$kvrtFindings | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $kvrtFindingsPath -Encoding UTF8 -NoNewline

# ESET findings: two threats detected (clean scan with detections)
$esetFindings = @{
    Scanner      = 'ESET'
    NotParseable = $false
    Error        = $null
    Threats      = @(
        @{ ThreatName = 'Win32/Adware.SomeAd'; ThreatType = 'a variant of Win32/Adware.SomeAd'; Object = 'C:\Users\test\file1.exe'; Action = 'cleaned by deleting' },
        @{ ThreatName = 'JS/Redirector.NJU'; ThreatType = 'JS/Redirector.NJU'; Object = 'C:\Users\test\page.html'; Action = 'retained' }
    )
    ThreatCount  = 2
    Stats        = @{ 'Scanned objects' = 15000; 'Infected objects' = 2; 'Cleaned objects' = 1 }
    LogPath      = 'C:\Users\test\AppData\Local\Temp\log.txt'
    ScanDate     = '2026-09-06 14:32:15'
}
$esetFindingsPath = Join-Path $tmp 'scanner-ESET-findings.json'
$esetFindings | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $esetFindingsPath -Encoding UTF8 -NoNewline

# scanner_results.json as sc-cleanup.ps1 Stage 5 writes it
# KVRT gets NotParseable findings (encrypted traces); ESET has threats;
# Malwarebytes is InstallFailed with no findings.
$scannerResults = @(
    @{ Tool = 'KVRT.exe'; Scanner = 'KVRT'; Status = 'Completed'; ExitCode = 0; FindingsPath = $kvrtFindingsPath },
    @{ Tool = 'esetonlinescanner.exe'; Scanner = 'ESET'; Status = 'Completed'; ExitCode = 0; FindingsPath = $esetFindingsPath },
    @{ Tool = 'Malwarebytes.Malwarebytes (winget install)'; Scanner = '<script>alert(1)</script>'; Status = 'InstallFailed'; ExitCode = 6; FilterSuspected = $true; FilterClassification = 'FilterOrProxySuspected'; FilterNames = @('Techloq'); ResultPath = 'C:\logs\scanner-Malwarebytes-result.json' }
)
$scannerJson = Join-Path $tmp 'scanner_results.json'
$scannerResults | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $scannerJson -Encoding UTF8 -NoNewline

$failures = 0
function Check($name, $cond) {
    if ($cond) { Write-Host "PASS  $name" } else { Write-Host "FAIL  $name"; $script:failures++ }
}

Check 'report preserves singleton ScreenConnect array context' ($reportSource.Contains('$scCount = @($scInstances).Count'))
Check 'single ScreenConnect count appears in section heading' ($singleHtml.Contains('<h2>ScreenConnect instances (1)</h2>'))
Check 'single ScreenConnect count appears in summary card' ($singleHtml -match '(?s)<div class="stat-card stat-danger">\s*<div class="stat-number">1</div>\s*<div class="stat-label">ScreenConnect instance\(s\) found')

# 1. With -ScannerSummary: table rendered, statuses present, hostile scanner escaped
$out1 = Join-Path $tmp 'report1.html'
& $reportScript -FindingsJson $findingsJson -OutputPath $out1 -ScannerSummary $scannerJson *> $null
$html1 = Get-Content -LiteralPath $out1 -Raw
Check 'report1 written' (Test-Path -LiteralPath $out1)
Check 'report1 has scanners section' ($html1.Contains('<section id="scanners">'))
Check 'report1 has Scan findings column header' ($html1.Contains('<th>Scan findings</th>'))
Check 'report1 renders KVRT Completed' ($html1.Contains('>KVRT</td><td>KVRT.exe</td><td>Completed</td><td>0</td>'))
Check 'report1 renders ESET Completed' ($html1.Contains('>ESET</td><td>esetonlinescanner.exe</td><td>Completed</td><td>0</td>'))
Check 'report1 has 0 raw <script>' (-not $html1.Contains('<script>'))
Check 'report1 hostile scanner escaped' ($html1.Contains('&lt;script&gt;alert(1)&lt;/script&gt;'))
Check 'report1 surfaces suspected download filter interference' ($html1.Contains('possible web-filter/proxy interference') -and $html1.Contains('scanner-Malwarebytes-result.json'))
Check 'report1 names suspected filter evidence' ($html1.Contains('Named filter evidence: Techloq'))
# Findings column: KVRT shows Not parseable
Check 'report1 KVRT findings shows Not parseable' ($html1.Contains('Not parseable'))
Check 'report1 KVRT findings mentions encrypted' ($html1.Contains('KVRT reports are encrypted (.enc1) or missing'))
Check 'report1 KVRT findings tells technician to re-run with -dontencrypt' ($html1.Contains('dontencrypt') -and $html1.Contains('KVRT_Data\Reports'))
# Findings column: ESET shows threat count
Check 'report1 ESET findings shows threat count' ($html1.Contains('2 threat(s) detected'))
# Findings detail: ESET threat names appear
Check 'report1 ESET threat name rendered' ($html1.Contains('Win32/Adware.SomeAd'))
Check 'report1 ESET threat object rendered' ($html1.Contains('C:\Users\test\file1.exe'))
Check 'report1 ESET scan date rendered' ($html1.Contains('2026-09-06 14:32:15'))
# Findings detail: ESET threat values are escaped
Check 'report1 ESET detail table has Threat/Type/Object/Action headers' ($html1.Contains('<th>Threat</th><th>Type</th><th>Object</th><th>Action</th>'))
# Malwarebytes has no findings (InstallFailed), so no findings cell
# Clean: check no raw hostile script tags leaked
Check 'report1 findings display has 0 raw <script>' (-not ($html1 -match '(?s)id="scanners".*?<script>'))

# 2. With -ScannersSkipped: explicit skip line, no table
$out2 = Join-Path $tmp 'report2.html'
& $reportScript -FindingsJson $findingsJson -OutputPath $out2 -ScannersSkipped *> $null
$html2 = Get-Content -LiteralPath $out2 -Raw
Check 'report2 written' (Test-Path -LiteralPath $out2)
Check 'report2 says scanners skipped' ($html2.Contains('Scanners were SKIPPED for this run'))
Check 'report2 has 0 raw <script>' (-not $html2.Contains('<script>'))

# 3. Neither flag: no scanners section (regression - old behavior)
$out3 = Join-Path $tmp 'report3.html'
& $reportScript -FindingsJson $findingsJson -OutputPath $out3 *> $null
$html3 = Get-Content -LiteralPath $out3 -Raw
Check 'report3 written' (Test-Path -LiteralPath $out3)
Check 'report3 has no scanners section' (-not $html3.Contains('id="scanners"'))

# 4. -ScannerSummary pointing at a missing file: loud error row, not a crash
$out4 = Join-Path $tmp 'report4.html'
& $reportScript -FindingsJson $findingsJson -OutputPath $out4 -ScannerSummary (Join-Path $tmp 'nope.json') *> $null
$html4 = Get-Content -LiteralPath $out4 -Raw
Check 'report4 written' (Test-Path -LiteralPath $out4)
Check 'report4 missing-file error shown' ($html4.Contains('Could not load scanner results'))

# 5. A removal manifest is rendered when the orchestrator forwards it.
$manifestJson = Join-Path $tmp 'removal-manifest.json'
@{
    Entries = @(@{ InstanceId = 'synth-instance'; Action = 'Quarantine'; Target = 'C:\ScreenConnect'; Result = 'Success'; Details = 'moved' })
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestJson -Encoding UTF8 -NoNewline
$out5 = Join-Path $tmp 'report5.html'
& $reportScript -FindingsJson $findingsJson -OutputPath $out5 -RemovalManifest $manifestJson *> $null
$html5 = Get-Content -LiteralPath $out5 -Raw
Check 'report5 has removal section' ($html5.Contains('<section id="removal">'))
Check 'report5 renders manifest entry' ($html5.Contains('synth-instance') -and $html5.Contains('moved'))

# 6. A diff is rendered with its fail-closed verdict and escaped collection error.
$diffJson = Join-Path $tmp 'snapshot_diff.json'
@{
    Verdict = 'INCOMPLETE'
    BeforeCollectionComplete = $true
    AfterCollectionComplete = $false
    BeforeCollectionErrors = @()
    AfterCollectionErrors = @(@{ Section = 'Services'; Error = '<script>alert(3)</script>' })
    AfterCollectionWarnings = @(@{ Section = 'ShimCache'; Warning = 'decoder disabled' })
    Sections = @(@{ Section = 'Services'; Kind = 'stable'; Removed = @(); Added = @(); Changed = @() })
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $diffJson -Encoding UTF8 -NoNewline
$out6 = Join-Path $tmp 'report6.html'
& $reportScript -FindingsJson $findingsJson -OutputPath $out6 -DiffPath $diffJson *> $null
$html6 = Get-Content -LiteralPath $out6 -Raw
Check 'report6 has snapshot diff section' ($html6.Contains('<section id="snapshot-diff">'))
Check 'report6 renders incomplete verdict' ($html6.Contains('>INCOMPLETE</span>'))
Check 'report6 renders collection warning' ($html6.Contains('Collection warnings') -and $html6.Contains('decoder disabled'))
Check 'report6 escapes diff error' ($html6.Contains('&lt;script&gt;alert(3)&lt;/script&gt;') -and (-not $html6.Contains('<script>')))

# 7. Parser exceptions are untrusted text too: an attacker controls JSON keys.
$malformedJson = Join-Path $tmp 'malformed-scanners.json'
[IO.File]::WriteAllText($malformedJson, '{"<img src=x onerror=alert(4)>": invalid}')
$out7 = Join-Path $tmp 'report7.html'
& $reportScript -FindingsJson $findingsJson -OutputPath $out7 -ScannerSummary $malformedJson *> $null
$html7 = Get-Content -LiteralPath $out7 -Raw
Check 'report7 malformed scanner results are reported' ($html7.Contains('Could not load scanner results'))
Check 'report7 parser exception cannot inject an HTML element' (-not $html7.Contains('<img src=x onerror=alert(4)>'))

Write-Host ""
if ($failures -eq 0) { Write-Host "ALL REPORT TESTS PASSED" } else { Write-Host "$failures REPORT TEST(S) FAILED"; exit 1 }
