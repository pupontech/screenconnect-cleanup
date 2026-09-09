$ErrorActionPreference = 'Stop'
<#
  test_scanner_findings_parser.ps1 - synthetic-fixture tests for
  Get-ScannerFindings.ps1 (ESET log, Malwarebytes XML, KVRT plain report,
  KVRT encrypted/missing fallback). Runs on any PowerShell 5.1+ host; the
  fixtures are written to a temp dir so no real scanner logs are needed.

  PS 5.1 compatible. Pure ASCII, no BOM.
#>

$tmpRoot = if ($env:TEMP) { $env:TEMP } else { '/tmp' }
$tmp = Join-Path $tmpRoot ('scc-findings-test-' + (Get-Random))
$null = New-Item -ItemType Directory -Path $tmp -Force
$repo = Split-Path -Parent $PSScriptRoot
$parser = Join-Path $repo 'Get-ScannerFindings.ps1'

$failures = 0
function Check($name, $cond) {
    if ($cond) { Write-Host "PASS  $name" } else { Write-Host "FAIL  $name"; $script:failures++ }
}

# ----------------------------------------------------------------------
# 1. ESET: UTF-16 log with a detected-threat block
# ----------------------------------------------------------------------
$esetLog = Join-Path $tmp 'eset-log.txt'
$esetContent = @"
ESET Online Scanner v1.4.0.0
esetonlinescanner, version = 1.4.0.0
started at 2026-09-09 10:00:00
options: full scan
================ detected =================
name = "Win32/Adware.SomeAd"
threat = "a variant of Win32/Adware.SomeAd"
object = "C:\Users\test\file1.exe"
action = "cleaned by deleting"
name = "JS/Redirector.NJU"
threat = "JS/Redirector.NJU"
object = "C:\Users\test\page.html"
action = "retained"
================ cleaned =================
number of scanned objects = 15000
number of infected objects = 2
number of cleaned objects = 1
"@
[System.IO.File]::WriteAllText($esetLog, $esetContent, [System.Text.Encoding]::Unicode)

$eset = & $parser -Scanner ESET -EsetLogPath $esetLog
Check 'ESET parser returns a result' ($null -ne $eset)
Check 'ESET parser finds 2 threats' ([int]$eset.ThreatCount -eq 2)
Check 'ESET threat 1 name' ($eset.Threats[0].ThreatName -eq 'Win32/Adware.SomeAd')
Check 'ESET threat 1 type' ($eset.Threats[0].ThreatType -eq 'a variant of Win32/Adware.SomeAd')
Check 'ESET threat 1 object' ($eset.Threats[0].Object -eq 'C:\Users\test\file1.exe')
Check 'ESET threat 1 action' ($eset.Threats[0].Action -eq 'cleaned by deleting')
Check 'ESET threat 2 name' ($eset.Threats[1].ThreatName -eq 'JS/Redirector.NJU')
Check 'ESET stats captured' ($null -ne $eset.Stats -and [int]$eset.Stats.'Scanned objects' -eq 15000)
Check 'ESET scan date captured' ($eset.ScanDate -eq '2026-09-09 10:00:00')
Check 'ESET not marked NotParseable' (-not $eset.NotParseable)

# ESET: clean log (no detected section) -> 0 threats, not parseable-error
$esetClean = Join-Path $tmp 'eset-clean.txt'
$esetCleanContent = @"
ESET Online Scanner v1.4.0.0
started at 2026-09-09 11:00:00
================ cleaned =================
number of scanned objects = 900
number of infected objects = 0
"@
[System.IO.File]::WriteAllText($esetClean, $esetCleanContent, [System.Text.Encoding]::Unicode)
$esetCleanResult = & $parser -Scanner ESET -EsetLogPath $esetClean
Check 'ESET clean scan -> 0 threats' ([int]$esetCleanResult.ThreatCount -eq 0)

# ESET: missing log -> Error set, no crash
$esetMissing = & $parser -Scanner ESET -EsetLogPath (Join-Path $tmp 'nope-eset.txt')
Check 'ESET missing log -> Error' (-not [string]::IsNullOrWhiteSpace($esetMissing.Error))

# ----------------------------------------------------------------------
# 2. Malwarebytes: XML report with one detection
# ----------------------------------------------------------------------
$mbamXml = Join-Path $tmp 'mbam-report.xml'
$mbamContent = @"
<?xml version="1.0" encoding="utf-8"?>
<report>
  <ScanResult>
    <ScanDate>2026-09-09 12:00:00</ScanDate>
    <Detections>
      <Detection>
        <MalwareName>Adware.SomeAd</MalwareName>
        <ObjectType>File</ObjectType>
        <Object>C:\Users\test\file2.exe</Object>
        <Action>Quarantined</Action>
      </Detection>
    </Detections>
  </ScanResult>
</report>
"@
[System.IO.File]::WriteAllText($mbamXml, $mbamContent, (New-Object System.Text.UTF8Encoding($false)))

$mbam = & $parser -Scanner Malwarebytes -MbamReportPath $mbamXml
Check 'Malwarebytes parser returns a result' ($null -ne $mbam)
Check 'Malwarebytes finds 1 threat' ([int]$mbam.ThreatCount -eq 1)
Check 'Malwarebytes threat name' ($mbam.Threats[0].ThreatName -eq 'Adware.SomeAd')
Check 'Malwarebytes threat object' ($mbam.Threats[0].Object -eq 'C:\Users\test\file2.exe')
Check 'Malwarebytes threat action' ($mbam.Threats[0].Action -eq 'Quarantined')
Check 'Malwarebytes scan date captured' ($mbam.ScanDate -eq '2026-09-09 12:00:00')

# Malwarebytes: missing report -> Error set, no crash
$mbamMissing = & $parser -Scanner Malwarebytes -MbamReportPath (Join-Path $tmp 'nope-mbam.xml')
Check 'Malwarebytes missing report -> Error' (-not [string]::IsNullOrWhiteSpace($mbamMissing.Error))

# ----------------------------------------------------------------------
# 3. KVRT: plain-text report (as written with -dontencrypt)
# ----------------------------------------------------------------------
$kvrtReport = Join-Path $tmp 'report_2026.09.09_13.00.00.klr'
$kvrtContent = @"
[2026-09-09 12:59:00.000] [INFO] Scan started
[2026-09-09 13:00:00.000] [WARN] Object C:\Users\test\virus.exe detected: HEUR:Trojan.Win32.Generic, action: deleted
[2026-09-09 13:00:01.000] [WARN] Object C:\Users\test\pup.dll detected: not-a-virus:AdWare.Win32.DealPly, action: skipped
[2026-09-09 13:00:02.000] [INFO] Object C:\Windows\system32\notepad.exe scanned
[2026-09-09 13:00:03.000] [INFO] Scan finished
"@
[System.IO.File]::WriteAllText($kvrtReport, $kvrtContent, (New-Object System.Text.UTF8Encoding($false)))

$kvrt = & $parser -Scanner KVRT -KvrtReportPath $kvrtReport
Check 'KVRT parser returns a result' ($null -ne $kvrt)
Check 'KVRT finds 2 threats (benign scanned-object lines ignored)' ([int]$kvrt.ThreatCount -eq 2)
Check 'KVRT threat 1 name' ($kvrt.Threats[0].ThreatName -eq 'HEUR:Trojan.Win32.Generic')
Check 'KVRT threat 1 object' ($kvrt.Threats[0].Object -eq 'C:\Users\test\virus.exe')
Check 'KVRT threat 1 action' ($kvrt.Threats[0].Action -eq 'cleaned')
Check 'KVRT threat 2 name' ($kvrt.Threats[1].ThreatName -eq 'not-a-virus:AdWare.Win32.DealPly')
Check 'KVRT threat 2 action' ($kvrt.Threats[1].Action -eq 'skipped')
# Compare canonical full names: Windows PowerShell 5.1 expands $env:TEMP to
# the 8.3 short path (RUNNER~1) while Get-Item returns the long name. The
# parser must report the canonical path either way.
$kvrtExpected = (Get-Item -LiteralPath $kvrtReport).FullName
Check 'KVRT report path recorded' ($kvrt.LogPath -eq $kvrtExpected)
Check 'KVRT not marked NotParseable' (-not $kvrt.NotParseable)

# KVRT: clean plain report -> 0 threats
$kvrtClean = Join-Path $tmp 'report_clean.klr'
$cleanContent = "[2026-09-09 14:00:00.000] [INFO] Scan finished, no threats detected`r`n"
[System.IO.File]::WriteAllText($kvrtClean, $cleanContent, (New-Object System.Text.UTF8Encoding($false)))
$kvrtCleanResult = & $parser -Scanner KVRT -KvrtReportPath $kvrtClean
Check 'KVRT clean report -> 0 threats' ([int]$kvrtCleanResult.ThreatCount -eq 0)
Check 'KVRT clean report parseable' (-not $kvrtCleanResult.NotParseable)

# KVRT: missing report path -> NotParseable with guidance
$kvrtMissing = & $parser -Scanner KVRT -KvrtReportPath (Join-Path $tmp 'nope-kvrt.klr')
Check 'KVRT missing report -> NotParseable' ($kvrtMissing.NotParseable)
Check 'KVRT missing report error names the path' ($kvrtMissing.Error.Contains('nope-kvrt.klr'))

# KVRT: no -KvrtReportPath and no KVRT_Data dirs on this host -> NotParseable
# fallback mentions the -dontencrypt remedy.
$kvrtFallback = & $parser -Scanner KVRT
Check 'KVRT no-reports fallback -> NotParseable' ($kvrtFallback.NotParseable)
Check 'KVRT fallback error tells technician to re-run with -dontencrypt' ($kvrtFallback.Error -match '-dontencrypt')

Write-Host ""
if ($failures -eq 0) { Write-Host "ALL FINDINGS PARSER TESTS PASSED" } else { Write-Host "$failures FINDINGS PARSER TEST(S) FAILED"; exit 1 }
