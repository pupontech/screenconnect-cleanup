# test_microbin_report_html_link.ps1 - focused regression test for stamping a
# successful MicroBin paste URL prominently in the generated HTML report.
# Runs locally with a disposable receiver only; no network, no live uploads.
# Covers the success path (LF and CRLF reports), HTML escaping of a
# query-bearing paste URL, upload failure leaving the report untouched,
# hostile Location headers never reaching the HTML, the </body>-only
# fallback, the no-marker loud failure, and the missing-report wiring error.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$uploaderPath = Join-Path $repoRoot 'Submit-ConnectWiseReport.ps1'
$uploaderSource = [System.IO.File]::ReadAllText($uploaderPath)
$startSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'START-HERE.bat'))
$cleanupSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'sc-cleanup.ps1'))
$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-microbin-html-link-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force
$scenarioProcesses = @()

$failures = @()
function Check {
    param([string]$Name, [bool]$Condition, [string]$Details)
    if ($Condition) {
        Write-Host ("PASS  " + $Name)
    } else {
        $message = "FAIL  " + $Name
        if ($Details) { $message += " - " + $Details }
        Write-Host $message
        $script:failures += $message
    }
}

# ---- Source-level contract checks ------------------------------------------
Check 'uploader declares the -ReportHtml parameter' $uploaderSource.Contains('$ReportHtml') $uploaderSource
Check 'uploader HTML-escapes the URL before writing it' $uploaderSource.Contains("Replace('&', '&amp;')") $uploaderSource
Check 'uploader has the paste-link annotator' $uploaderSource.Contains('Add-ReportPasteLink') $uploaderSource
Check 'annotator is only reachable after a successful upload' ($uploaderSource.LastIndexOf('Add-ReportPasteLink -ReportHtml') -gt $uploaderSource.IndexOf('MICROBIN UPLOAD: ')) $uploaderSource
Check 'guided launcher passes the report path to the uploader' $startSource.Contains('-ReportHtml') $startSource
Check 'cleanup runner passes the report path to the uploader' $cleanupSource.Contains('-ReportHtml') $cleanupSource
$guidedUpload = $startSource.IndexOf(' -ReportHtml ')
$guidedCopy = $startSource.IndexOf('Copy-Item -LiteralPath')
$guidedOpen = $startSource.IndexOf('start "" "!SCC_RUN_ROOT!/report.html"')
Check 'guided report is copied after the upload finishes' ($guidedUpload -ge 0 -and $guidedCopy -gt $guidedUpload) 'Report copy must follow the uploader invocation'
Check 'guided report opens after the upload finishes' ($guidedUpload -ge 0 -and $guidedOpen -gt $guidedUpload) 'Browser must open the final annotated report'
$directUpload = $cleanupSource.IndexOf('Invoke-ChildScript -ScriptPath $uploadScript')
$directCopy = $cleanupSource.IndexOf('Copy-Item -LiteralPath $reportHtml')
$directOpen = $cleanupSource.IndexOf('Start-Process -FilePath $reportHtml')
Check 'direct report is copied after the upload finishes' ($directUpload -ge 0 -and $directCopy -gt $directUpload) 'Report copy must follow the uploader invocation'
Check 'direct report opens after the upload finishes' ($directUpload -ge 0 -and $directOpen -gt $directUpload) 'Browser must open the final annotated report'


$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}

$workDir = Join-Path $probeRoot 'run'
$null = New-Item -ItemType Directory -Path $workDir -Force
$findingsPath = Join-Path $workDir 'findings.json'

$fixture = [ordered]@{
    SchemaVersion = 4
    GeneratedUtc = '2026-09-06T10:00:00Z'
    ComputerName = 'CLIENT-99'
    RunAsUser = 'Bob'
    DeliveryContext = 'malvertising'
    Instances = @(
        [ordered]@{
            Identifier = 'ABCDEF123456'
            RelayHost = 'evil-relay.example'
            RelayPort = 443
            InstallDir = 'C:\Users\Bob\AppData\Local\ScreenConnect Client'
            ParamBlob = 'do-not-upload-this-secret'
            Files = @(
                [ordered]@{
                    Path = 'C:\Users\Bob\Downloads\dropper.ps1'
                    SHA256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                    SignatureStatus = 'NotSigned'
                }
            )
        }
    )
}
$fixture | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $findingsPath -Encoding ASCII

# ---- Minimal generated-report fixtures -------------------------------------
# The real New-InvestigationReport.ps1 always emits <footer> ... </footer>
# then </body></html>; the fixtures mirror that shape plus the edge variants.
function Write-HtmlFixture {
    param([string]$Path, [string[]]$BodyLines, [bool]$Crlf)
    $separator = if ($Crlf) { "`r`n" } else { "`n" }
    $text = ($BodyLines -join $separator) + $separator
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $text, $utf8NoBom)
}

$reportLf = Join-Path $workDir 'report-lf.html'
Write-HtmlFixture -Path $reportLf -Crlf $false -BodyLines @(
    '<!DOCTYPE html>'
    '<html lang="en">'
    '<head><meta charset="utf-8"><title>Investigation report</title></head>'
    '<body>'
    '<main><p>SC-MARKER-KEEP-7f3a</p></main>'
    '<footer>'
    '  Generated by fixture.'
    '</footer>'
    '</body>'
    '</html>'
)

$reportCrlf = Join-Path $workDir 'report-crlf.html'
Write-HtmlFixture -Path $reportCrlf -Crlf $true -BodyLines @(
    '<!DOCTYPE html>'
    '<html lang="en">'
    '<head><meta charset="utf-8"><title>Investigation report</title></head>'
    '<body>'
    '<main><p>SC-MARKER-KEEP-7f3a</p></main>'
    '<footer>'
    '  Generated by fixture.'
    '</footer>'
    '</body>'
    '</html>'
)

$reportBodyOnly = Join-Path $workDir 'report-body-only.html'
Write-HtmlFixture -Path $reportBodyOnly -Crlf $false -BodyLines @(
    '<!DOCTYPE html>'
    '<html><body>'
    '<p>SC-MARKER-BODY-ONLY-19c2</p>'
    '</body></html>'
)

$reportNoMarker = Join-Path $workDir 'report-no-marker.html'
Write-HtmlFixture -Path $reportNoMarker -Crlf $false -BodyLines @(
    '<!DOCTYPE html>'
    '<html><body><p>no closing markers here</p>'
)

$reportMissing = Join-Path $workDir 'does-not-exist.html'

# ---- Disposable MicroBin receiver ------------------------------------------
$receiverScript = Join-Path $probeRoot 'microbin_receiver.py'
@'
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

port_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
mode = sys.argv[3]

class Receiver(BaseHTTPRequestHandler):
    seq = 0

    def do_POST(self):
        Receiver.seq += 1
        n = Receiver.seq
        length = int(self.headers.get('Content-Length', '-1'))
        body = self.rfile.read(length) if length > 0 else b''
        content_type = self.headers.get('Content-Type', '')
        fields = {}
        match = re.search(r'boundary=([^;]+)', content_type)
        if match:
            boundary = match.group(1).encode('utf-8')
            for part in body.split(b'--' + boundary):
                part = part.strip(b'\r\n')
                if not part or part == b'--' or b'\r\n\r\n' not in part:
                    continue
                head, value = part.split(b'\r\n\r\n', 1)
                if value.endswith(b'\r\n'):
                    value = value[:-2]
                name_match = re.search(r'name="([^"]+)"', head.decode('latin-1'))
                if name_match:
                    fields[name_match.group(1)] = value.decode('utf-8', 'replace')
        if mode == 'always503':
            status, location, response = 503, None, b'server error'
        elif mode == 'hostile':
            status, location, response = 302, '/upload/"><script>alert(1)</script>', b''
        elif mode == 'queryurl':
            base = 'http://127.0.0.1:%d' % self.server.server_port
            status, location, response = 302, base + '/upload/pig-dog-cat?aa=1&bb=two', b''
        else:
            status, location, response = 302, '/upload/pig-dog-cat', b''
        entry = {
            'n': n,
            'path': self.path,
            'content_type': content_type,
            'fields': fields,
            'status_sent': status,
            'location': location,
        }
        with log_path.open('a', encoding='utf-8') as log:
            log.write(json.dumps(entry) + '\n')
        self.send_response(status)
        if location:
            self.send_header('Location', location)
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        if response:
            self.wfile.write(response)

    def log_message(self, format, *args):
        pass

server = HTTPServer(('127.0.0.1', 0), Receiver)
port_path.write_text(str(server.server_port), encoding='ascii')
server.serve_forever()
'@ | Set-Content -LiteralPath $receiverScript -Encoding ASCII

$pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $pythonCommand) { $pythonCommand = Get-Command python -ErrorAction SilentlyContinue }
if (-not $pythonCommand) { throw 'python is required for the disposable MicroBin receiver test' }
$pythonPath = if ($pythonCommand.Source) { $pythonCommand.Source } else { $pythonCommand.Path }

function Start-MicroBinServer {
    param([string]$Mode)
    $suffix = [guid]::NewGuid().ToString('N')
    $portFile = Join-Path $probeRoot ('receiver-' + $Mode + '-' + $suffix + '.port')
    $logFile = Join-Path $probeRoot ('receiver-' + $Mode + '-' + $suffix + '.log')
    $stdOut = Join-Path $probeRoot ('receiver-' + $Mode + '-' + $suffix + '.stdout')
    $stdErr = Join-Path $probeRoot ('receiver-' + $Mode + '-' + $suffix + '.stderr')
    $serverArgs = @($receiverScript, $portFile, $logFile, $Mode)
    $proc = Start-Process -FilePath $pythonPath -ArgumentList $serverArgs -PassThru `
        -RedirectStandardOutput $stdOut -RedirectStandardError $stdErr
    $script:scenarioProcesses += $proc
    $port = $null
    for ($i = 0; $i -lt 50; $i++) {
        if (Test-Path -LiteralPath $portFile) {
            try { $port = [int](Get-Content -LiteralPath $portFile -Raw); break } catch { }
        }
        Start-Sleep -Milliseconds 100
    }
    if ($null -eq $port) { throw 'MicroBin receiver did not start' }
    return @{ Port = $port; Log = $logFile; ProcessId = $proc.Id; StdOut = $stdOut; StdErr = $stdErr }
}

function Invoke-UploaderRun {
    param([object[]]$ExtraArgs)
    $callArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $uploaderPath) + $ExtraArgs
    $runOutput = & $psHost @callArgs 2>&1
    return @{ Output = ($runOutput -join "`n"); Rc = $LASTEXITCODE }
}

function Read-ReportText {
    param([string]$Path)
    return [System.IO.File]::ReadAllText($Path)
}

function Test-ReportAsciiNoBom {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count -gt 0
    return (-not $hasBom) -and (-not $nonAscii)
}

function Test-ReportHasExactlyOnePasteLink {
    param([string]$Text)
    $comment = '<!-- ScreenConnect Cleanup: sanitized MicroBin paste of this report'
    $anchorCount = ([regex]::Matches($Text, '<a href=')).Count
    return $Text.Contains($comment) -and $Text.Contains('Sanitized paste (MicroBin)') -and $anchorCount -eq 1
}

try {
    # ---- 1. Successful upload appends the paste link (LF report) ------------
    $srv1 = Start-MicroBinServer -Mode 'success'
    $url1 = 'http://127.0.0.1:' + $srv1.Port
    $before1 = Read-ReportText $reportLf
    $out1 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url1, '-ReportHtml', $reportLf, '-AllowInsecureRelay')
    $text1 = $out1.Output
    Check 'successful upload annotates the report and exits 0' ($out1.Rc -eq 0 -and $text1 -match 'MICROBIN UPLOAD: ' -and $text1 -match 'MICROBIN PASTE LINK: added to') $text1
    $html1 = Read-ReportText $reportLf
    Check 'paste link names the paste URL' ($html1.Contains('href="' + $url1 + '/upload/pig-dog-cat"')) $html1
    Check 'exactly one link block was inserted' (Test-ReportHasExactlyOnePasteLink $html1) $html1
    Check 'paste URL is visible before the report content, not buried in the footer' ($html1.IndexOf('Sanitized paste (MicroBin)') -gt $html1.IndexOf('<body>') -and $html1.IndexOf('Sanitized paste (MicroBin)') -lt $html1.IndexOf('<main>')) $html1
    Check 'original report content is preserved' ($html1.Contains('SC-MARKER-KEEP-7f3a') -and $html1.EndsWith('</html>' + "`n") -or $html1.EndsWith('</html>')) $html1
    Check 'link block uses the report LF newline style' ($html1.Contains("`n<!-- ScreenConnect Cleanup") -and -not $html1.Contains("`r`n<!-- ScreenConnect Cleanup")) $html1
    Check 'rewritten report stays ASCII with no BOM' (Test-ReportAsciiNoBom $reportLf) $html1

    # ---- 2. Query-bearing paste URL is HTML-escaped (CRLF report) -----------
    $srv2 = Start-MicroBinServer -Mode 'queryurl'
    $url2 = 'http://127.0.0.1:' + $srv2.Port
    $out2 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url2, '-ReportHtml', $reportCrlf, '-AllowInsecureRelay')
    $text2 = $out2.Output
    Check 'query-bearing URL upload succeeds' ($out2.Rc -eq 0 -and $text2 -match 'MICROBIN UPLOAD: ') $text2
    $html2 = Read-ReportText $reportCrlf
    Check 'ampersand in the paste URL is HTML-escaped' ($html2.Contains('href="' + $url2 + '/upload/pig-dog-cat?aa=1&amp;bb=two"')) $html2
    Check 'raw ampersand never appears in the href' (-not $html2.Contains('?aa=1&bb=')) $html2
    Check 'link block uses the report CRLF newline style' ($html2.Contains("`r`n<!-- ScreenConnect Cleanup")) $html2
    Check 'CRLF report stays ASCII with no BOM' (Test-ReportAsciiNoBom $reportCrlf) $html2

    # A later upload replaces the old URL rather than stacking stale links.
    $repeatOut = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url2, '-ReportHtml', $reportLf, '-AllowInsecureRelay')
    $repeatHtml = Read-ReportText $reportLf
    Check 'repeat upload keeps exactly one link with the latest returned URL' ($repeatOut.Rc -eq 0 -and (Test-ReportHasExactlyOnePasteLink $repeatHtml) -and -not $repeatHtml.Contains($url1 + '/upload/') -and $repeatHtml.Contains($url2 + '/upload/pig-dog-cat?aa=1&amp;bb=two')) $repeatHtml

    $legacyReport = Join-Path $workDir 'legacy.html'
    $legacyComment = '<!-- ScreenConnect Cleanup: sanitized MicroBin paste of this report (added after a successful upload). -->'
    Write-HtmlFixture -Path $legacyReport -Crlf $false -BodyLines @(
        '<html><body><main>LEGACY-KEEP</main><footer>'
        $legacyComment
        '<p style="margin:0;padding:0.3em 0;">Sanitized paste (MicroBin): <a href="https://old.example/upload/old">https://old.example/upload/old</a></p>'
        '</footer></body></html>'
    )
    $legacyOut = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url1, '-ReportHtml', $legacyReport, '-AllowInsecureRelay')
    $legacyHtml = Read-ReportText $legacyReport
    Check 'old footer annotation becomes one current banner without losing evidence' ($legacyOut.Rc -eq 0 -and (Test-ReportHasExactlyOnePasteLink $legacyHtml) -and -not $legacyHtml.Contains('old.example') -and $legacyHtml.Contains('LEGACY-KEEP') -and $legacyHtml.IndexOf('Sanitized paste (MicroBin)') -lt $legacyHtml.IndexOf('<main>')) $legacyHtml

    # ---- 3. Upload failure never touches the report --------------------------
    $srv3 = Start-MicroBinServer -Mode 'always503'
    $url3 = 'http://127.0.0.1:' + $srv3.Port
    $before3 = Read-ReportText $reportLf
    $out3 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url3, '-ReportHtml', $reportLf, '-AllowInsecureRelay')
    $text3 = $out3.Output
    Check 'server failure fails the run loudly' ($out3.Rc -ne 0 -and $text3 -match 'MICROBIN UPLOAD FAILED: ') $text3
    Check 'failure output never claims a paste link was added' ($text3 -notmatch 'MICROBIN PASTE LINK: added') $text3
    Check 'report file is byte-identical after a failed upload' ((Read-ReportText $reportLf) -eq $before3) $text3

    # ---- 4. Hostile Location header is rejected before it reaches the HTML --
    $srv4 = Start-MicroBinServer -Mode 'hostile'
    $url4 = 'http://127.0.0.1:' + $srv4.Port
    $before4 = Read-ReportText $reportCrlf
    $out4 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url4, '-ReportHtml', $reportCrlf, '-AllowInsecureRelay')
    $text4 = $out4.Output
    Check 'markup-shaped Location is rejected as not a paste URL' ($out4.Rc -ne 0 -and $text4 -match 'does not look like a paste URL') $text4
    Check 'rejected Location never annotates the report' ((Read-ReportText $reportCrlf) -eq $before4) $text4

    # ---- 5. No report anywhere: upload without HTML still works -------------
    $srv5 = Start-MicroBinServer -Mode 'success'
    $url5 = 'http://127.0.0.1:' + $srv5.Port
    $out5 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url5, '-AllowInsecureRelay')
    Check 'upload without a report path still succeeds' ($out5.Rc -eq 0 -and $out5.Output -match 'MICROBIN UPLOAD: ') $out5.Output
    Check 'no paste-link step runs when no report exists' ($out5.Output -notmatch 'MICROBIN PASTE LINK') $out5.Output

    # Default to this run's report when a direct uploader caller omits the flag.
    $defaultReport = Join-Path $workDir 'report.html'
    Write-HtmlFixture -Path $defaultReport -Crlf $false -BodyLines @(
        '<!DOCTYPE html><html><body>'
        '<main><p>AUTO-REPORT-MARKER</p></main>'
        '<footer>Generated by fixture.</footer></body></html>'
    )
    $autoOut = Invoke-UploaderRun @('-RunPath', $workDir, '-MicroBinUrl', $url5, '-AllowInsecureRelay')
    $autoHtml = Read-ReportText $defaultReport
    Check 'RunPath upload automatically annotates its existing report.html' ($autoOut.Rc -eq 0 -and $autoHtml.Contains('href="' + $url5 + '/upload/pig-dog-cat"')) $autoOut.Output
    $workOut = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url2, '-AllowInsecureRelay')
    $workHtml = Read-ReportText $defaultReport
    Check 'WorkDir upload also discovers the report and keeps the exact escaped URL' ($workOut.Rc -eq 0 -and (Test-ReportHasExactlyOnePasteLink $workHtml) -and $workHtml.Contains($url2 + '/upload/pig-dog-cat?aa=1&amp;bb=two')) $workOut.Output
    $autoFailed = Invoke-UploaderRun @('-RunPath', $workDir, '-MicroBinUrl', $url3, '-AllowInsecureRelay')
    Check 'failed upload leaves the auto-discovered report unchanged' ($autoFailed.Rc -ne 0 -and (Read-ReportText $defaultReport) -eq $workHtml) $autoFailed.Output
    $autoDisabled = Invoke-UploaderRun @('-RunPath', $workDir, '-NoUpload')
    Check 'NoUpload leaves the auto-discovered report unchanged' ($autoDisabled.Rc -eq 0 -and (Read-ReportText $defaultReport) -eq $workHtml) $autoDisabled.Output
    $explicitOut = Invoke-UploaderRun @('-RunPath', $workDir, '-MicroBinUrl', $url1, '-ReportHtml', $reportBodyOnly, '-AllowInsecureRelay')
    Check 'explicit report wins without changing the default report' ($explicitOut.Rc -eq 0 -and (Read-ReportText $defaultReport) -eq $workHtml -and (Read-ReportText $reportBodyOnly).Contains($url1 + '/upload/pig-dog-cat')) $explicitOut.Output
    Remove-Item -LiteralPath $defaultReport -Force

    # ---- 6. Missing report path fails loudly (wiring error) ------------------
    $srv6 = Start-MicroBinServer -Mode 'success'
    $url6 = 'http://127.0.0.1:' + $srv6.Port
    $out6 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url6, '-ReportHtml', $reportMissing, '-AllowInsecureRelay')
    $text6 = $out6.Output
    Check 'upload succeeds but the missing report is a loud failure' ($out6.Rc -ne 0 -and $text6 -match 'MICROBIN UPLOAD: ' -and $text6 -match 'MICROBIN PASTE LINK FAILED: report HTML was not found') $text6

    # ---- 7. </body>-only report: link lands before </body> -------------------
    $srv7 = Start-MicroBinServer -Mode 'success'
    $url7 = 'http://127.0.0.1:' + $srv7.Port
    $out7 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url7, '-ReportHtml', $reportBodyOnly, '-AllowInsecureRelay')
    $text7 = $out7.Output
    Check 'body-only report is annotated and exits 0' ($out7.Rc -eq 0 -and $text7 -match 'MICROBIN PASTE LINK: added to') $text7
    $html7 = Read-ReportText $reportBodyOnly
    Check 'link is inserted before </body> and the tail is intact' ($html7.Contains('SC-MARKER-BODY-ONLY-19c2') -and $html7.IndexOf('<a href=') -gt 0 -and $html7.IndexOf('<a href=') -lt $html7.IndexOf('</body>') -and $html7.EndsWith('</body></html>' + "`n")) $html7

    # ---- 8. Report with no closing marker fails loudly, file untouched -------
    $srv8 = Start-MicroBinServer -Mode 'success'
    $url8 = 'http://127.0.0.1:' + $srv8.Port
    $before8 = Read-ReportText $reportNoMarker
    $out8 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $url8, '-ReportHtml', $reportNoMarker, '-AllowInsecureRelay')
    $text8 = $out8.Output
    Check 'marker-less report fails loudly' ($out8.Rc -ne 0 -and $text8 -match 'MICROBIN PASTE LINK FAILED: report HTML has no closing </body> marker') $text8
    Check 'marker-less report is left untouched' ((Read-ReportText $reportNoMarker) -eq $before8) $text8

    # Replay the actual guided report-stage batch on Windows with synthetic data.
    # Only desktop destination and shell presentation are redirected to probes;
    # the real report builder, uploader, saved-URL lookup and command order run.
    if ($env:OS -eq 'Windows_NT') {
        $guidedDir = Join-Path $probeRoot 'guided stage'
        $guidedRun = Join-Path $guidedDir 'run'
        $guidedDesktop = Join-Path $guidedDir 'desktop'
        $null = New-Item -ItemType Directory -Path $guidedRun, $guidedDesktop -Force
        foreach ($name in @('New-InvestigationReport.ps1', 'Submit-ConnectWiseReport.ps1')) {
            Copy-Item -LiteralPath (Join-Path $repoRoot $name) -Destination (Join-Path $guidedDir $name)
        }
        $srvGuided = Start-MicroBinServer -Mode 'success'
        $guidedUrl = 'http://127.0.0.1:' + $srvGuided.Port
        [System.IO.File]::WriteAllText((Join-Path $guidedDir 'microbin-url.txt'), $guidedUrl)
        $stageStart = $startSource.IndexOf('rem ---- Step 9: report + MicroBin share')
        $stageEnd = $startSource.IndexOf('set GO=', $stageStart)
        if ($stageStart -lt 0 -or $stageEnd -le $stageStart) { throw 'Guided report stage markers missing' }
        $stage = $startSource.Substring($stageStart, $stageEnd - $stageStart)
        $stage = $stage.Replace("[Environment]::GetFolderPath('Desktop')", '$env:SCC_TEST_DESKTOP')
        $stage = $stage.Replace('explorer /select,"!SCC_RUN_ROOT!/report.html"', 'rem Explorer suppressed in fixture')
        $openProbe = 'powershell -NoProfile -Command "if (-not ([IO.File]::ReadAllText($env:SCC_RUN_ROOT + ''/report.html'').Contains(''Sanitized paste (MicroBin)''))) { exit 9 }; [IO.File]::WriteAllText($env:SCC_RUN_ROOT + ''/opened.marker'', ''ok'')"'
        $stage = $stage.Replace('start "" "!SCC_RUN_ROOT!/report.html"', $openProbe)
        $stage = $stage.Replace('-ReportHtml "!SCC_RUN_ROOT!/report.html"', '-ReportHtml "!SCC_RUN_ROOT!/report.html" -AllowInsecureRelay')
        $bat = Join-Path $guidedDir 'report-stage.bat'
        [System.IO.File]::WriteAllText($bat, ("@echo off`r`nsetlocal EnableDelayedExpansion`r`nset PIPE_RC=0`r`n" + $stage + "`r`nexit /b !PIPE_RC!`r`n"), [System.Text.Encoding]::ASCII)
        $savedRun = $env:SCC_RUN_ROOT
        $savedFindings = $env:FINDINGS_JSON
        $savedDesktop = $env:SCC_TEST_DESKTOP
        $child = $null
        try {
            $env:SCC_RUN_ROOT = $guidedRun
            $env:FINDINGS_JSON = $findingsPath
            $env:SCC_TEST_DESKTOP = $guidedDesktop
            # Use a retained .NET process handle: Start-Process -PassThru can
            # expose a null ExitCode after external waits on PowerShell 5.1.
            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = $env:ComSpec
            $processInfo.Arguments = '/d /c ""' + $bat + '""'
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true
            $processInfo.EnvironmentVariables['PSModulePath'] = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
            # A nonzero control verifies that the harness does not mask exits.
            $processInfo.Arguments = '/d /c exit 7'
            $statusProbe = [System.Diagnostics.Process]::Start($processInfo)
            try {
                if (-not $statusProbe.WaitForExit(10000)) { throw 'Exit-status control timed out' }
                Check 'Windows process harness preserves nonzero exit codes' ($statusProbe.ExitCode -eq 7) ('ExitCode=' + $statusProbe.ExitCode)
            } finally {
                if (-not $statusProbe.HasExited) { $statusProbe.Kill() }
                $statusProbe.Dispose()
            }
            $processInfo.Arguments = '/d /c ""' + $bat + '""'
            $child = [System.Diagnostics.Process]::Start($processInfo)
            $stdoutTask = $child.StandardOutput.ReadToEndAsync()
            $stderrTask = $child.StandardError.ReadToEndAsync()
            if (-not $child.WaitForExit(120000)) { throw 'Guided report stage timed out' }
            $child.WaitForExit()
            if (-not $stdoutTask.Wait(5000) -or -not $stderrTask.Wait(5000)) { throw 'Guided report output streams did not close' }
            $guidedText = $stdoutTask.Result + $stderrTask.Result
            $guidedRc = $child.ExitCode
            Check 'Windows guided report stage exits successfully' ($guidedRc -eq 0) ('ExitCode=' + $guidedRc + "`n" + $guidedText)
            $desktopHtmlPath = Join-Path $guidedDesktop 'report.html'
            $runHtmlPath = Join-Path $guidedRun 'report.html'
            Check 'Windows guided stage opens only the annotated report' (Test-Path -LiteralPath (Join-Path $guidedRun 'opened.marker')) $guidedText
            if (Test-Path -LiteralPath $desktopHtmlPath) {
                $copiedHtml = [System.IO.File]::ReadAllText($desktopHtmlPath)
                Check 'Windows Desktop report contains the created paste URL' ($copiedHtml.Contains('href="' + $guidedUrl + '/upload/pig-dog-cat"')) $guidedText
                Check 'Windows Desktop paste link appears above the real report header' ($copiedHtml.IndexOf('id="scc-microbin-paste"') -gt $copiedHtml.IndexOf('<body>') -and $copiedHtml.IndexOf('id="scc-microbin-paste"') -lt $copiedHtml.IndexOf('<header>')) $guidedText
                Check 'Windows Desktop and run report copies match' ($copiedHtml -eq [System.IO.File]::ReadAllText($runHtmlPath)) $guidedText
            } else {
                Check 'Windows guided stage produces the Desktop copy' $false $guidedText
            }
        } finally {
            if ($child -and -not $child.HasExited) { Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
            $env:SCC_RUN_ROOT = $savedRun
            $env:FINDINGS_JSON = $savedFindings
            $env:SCC_TEST_DESKTOP = $savedDesktop
        }
    } else {
        Write-Host 'SKIP  actual cmd.exe report-stage replay requires Windows'
    }
} finally {
    foreach ($proc in $scenarioProcesses) {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) MicroBin report HTML link test(s) failed")
    exit 1
}
Write-Host 'ALL MICROBIN REPORT HTML LINK TESTS PASSED'
exit 0
