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

# scanner_results.json as sc-cleanup.ps1 Stage 5 writes it
$scannerResults = @(
    @{ Tool = 'KVRT.exe'; Scanner = 'KVRT'; Status = 'Completed'; ExitCode = 0 },
    @{ Tool = 'esetonlinescanner.exe'; Scanner = 'ESET'; Status = 'Timeout'; ExitCode = 4 },
    @{ Tool = 'Malwarebytes.Malwarebytes (winget install)'; Scanner = '<script>alert(1)</script>'; Status = 'InstallFailed'; ExitCode = 6; FilterSuspected = $true; FilterClassification = 'FilterOrProxySuspected'; FilterNames = @('Techloq'); ResultPath = 'C:\\logs\\scanner-Malwarebytes-result.json' }
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
Check 'report1 renders KVRT Completed' ($html1.Contains('>KVRT</td><td>KVRT.exe</td><td>Completed</td><td>0</td>'))
Check 'report1 renders ESET Timeout' ($html1.Contains('>ESET</td><td>esetonlinescanner.exe</td><td>Timeout</td><td>4</td>'))
Check 'report1 has 0 raw <script>' (-not $html1.Contains('<script>'))
Check 'report1 hostile scanner escaped' ($html1.Contains('&lt;script&gt;alert(1)&lt;/script&gt;'))
Check 'report1 surfaces suspected download filter interference' ($html1.Contains('possible web-filter/proxy interference') -and $html1.Contains('scanner-Malwarebytes-result.json'))
Check 'report1 names suspected filter evidence' ($html1.Contains('Named filter evidence: Techloq'))

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
    Entries = @(@{ InstanceId = 'synth-instance'; Action = 'Quarantine'; Target = 'C:\\ScreenConnect'; Result = 'Success'; Details = 'moved' })
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

Write-Host ""
if ($failures -eq 0) { Write-Host "ALL REPORT TESTS PASSED" } else { Write-Host "$failures REPORT TEST(S) FAILED"; exit 1 }
