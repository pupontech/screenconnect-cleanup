$ErrorActionPreference = 'Stop'
$tmpRoot = if ($env:TEMP) { $env:TEMP } else { '/tmp' }
$tmp = Join-Path $tmpRoot ('scc-report-test-' + (Get-Random))
$null = New-Item -ItemType Directory -Path $tmp -Force
$repo = Split-Path -Parent $PSScriptRoot
$reportScript = Join-Path $repo 'New-InvestigationReport.ps1'

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

# scanner_results.json as sc-cleanup.ps1 Stage 5 writes it
$scannerResults = @(
    @{ Tool = 'KVRT.exe'; Scanner = 'KVRT'; Status = 'Completed'; ExitCode = 0 },
    @{ Tool = 'esetonlinescanner.exe'; Scanner = 'ESET'; Status = 'Timeout'; ExitCode = 4 },
    @{ Tool = 'Malwarebytes.Malwarebytes (winget install)'; Scanner = '<script>alert(1)</script>'; Status = 'Failed'; ExitCode = 1 }
)
$scannerJson = Join-Path $tmp 'scanner_results.json'
$scannerResults | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $scannerJson -Encoding UTF8 -NoNewline

$failures = 0
function Check($name, $cond) {
    if ($cond) { Write-Host "PASS  $name" } else { Write-Host "FAIL  $name"; $script:failures++ }
}

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

Write-Host ""
if ($failures -eq 0) { Write-Host "ALL REPORT TESTS PASSED" } else { Write-Host "$failures REPORT TEST(S) FAILED"; exit 1 }
