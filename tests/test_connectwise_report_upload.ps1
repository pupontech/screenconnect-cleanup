# test_connectwise_report_upload.ps1 - sanitized report-package regression test.
# Runs locally with a fixture only; no network or cleanup actions are used.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$uploaderPath = Join-Path $repoRoot 'Submit-ConnectWiseReport.ps1'
$cleanupSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'sc-cleanup.ps1'))
$detectorSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'detect-remote-access.ps1'))
$startSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'START-HERE.bat'))
$bundleSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'make-deploy-bundle.sh'))
$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-report-upload-' + [guid]::NewGuid().ToString('N'))
$workDir = Join-Path $probeRoot 'run'
$null = New-Item -ItemType Directory -Path $workDir -Force
$findingsPath = Join-Path $workDir 'findings.json'
$rawPath = Join-Path $workDir 'raw-secret.ps1'
$serverProcess = $null

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

Check 'cleanup pipeline references the uploader' ($cleanupSource.Contains('Submit-ConnectWiseReport.ps1')) $cleanupSource
Check 'cleanup suppresses nested detector upload' ($cleanupSource.Contains("'-NoReportUpload'")) $cleanupSource
Check 'standalone detector exposes automatic upload' ($detectorSource.Contains('$NoReportUpload') -and $detectorSource.Contains('Submit-ConnectWiseReport.ps1')) $detectorSource
Check 'guided launcher references the uploader' ($startSource.Contains('Submit-ConnectWiseReport.ps1') -and $startSource.Contains('-FindingsJson')) $startSource
Check 'deployment bundle includes the uploader' ($bundleSource.Contains('Submit-ConnectWiseReport.ps1')) $bundleSource

try {
    $fixture = [ordered]@{
        SchemaVersion = 4
        GeneratedUtc = '2026-09-03T12:00:00Z'
        ComputerName = 'CLIENT-42'
        RunAsUser = 'Alice'
        DeliveryContext = 'malvertising'
        Instances = @(
            [ordered]@{
                Identifier = 'ABCDEF123456'
                RelayHost = 'evil-relay.example'
                RelayPort = 443
                InstallDir = 'C:\Users\Alice\AppData\Local\ScreenConnect Client'
                ParamBlob = 'do-not-upload-this-secret'
                Files = @(
                    [ordered]@{
                        Path = 'C:\Users\Alice\Downloads\dropper.ps1'
                        SHA256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                        SignatureStatus = 'NotSigned'
                    }
                )
            }
        )
    }
    $fixture | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $findingsPath -Encoding ASCII
    'Write-Host do-not-upload-this-secret' | Set-Content -LiteralPath $rawPath -Encoding ASCII

    $psHost = $null
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $psHost = Join-Path $PSHOME 'powershell.exe'
    } else {
        $psHost = (Get-Command pwsh -ErrorAction Stop).Source
    }
    $output = & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $uploaderPath `
        -FindingsJson $findingsPath -WorkDir $workDir -NoUpload 2>&1
    $rc = $LASTEXITCODE
    $packagePath = Join-Path $workDir 'connectwise-report.zip'
    Check 'package-only mode succeeds' ($rc -eq 0 -and (Test-Path -LiteralPath $packagePath)) (($output -join "`n"))

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($packagePath)
    try {
        $names = @($archive.Entries | ForEach-Object { $_.FullName })
        Check 'package has the ConnectWise JSON summary' ($names -contains 'connectwise-report.json') ($names -join ', ')
        Check 'package has a human-readable summary' ($names -contains 'connectwise-report.txt') ($names -join ', ')
        Check 'raw evidence is excluded by default' ($names -notcontains 'raw-secret.ps1') ($names -join ', ')
        $jsonEntry = $archive.GetEntry('connectwise-report.json')
        $reader = New-Object System.IO.StreamReader($jsonEntry.Open())
        try { $reportText = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $report = $reportText | ConvertFrom-Json
        Check 'installation identifier is retained' ($report.ScreenConnect.Instances[0].Identifier -eq 'ABCDEF123456') $reportText
        Check 'relay host is retained' ($report.ScreenConnect.Instances[0].RelayHost -eq 'evil-relay.example') $reportText
        Check 'secret fields are omitted' ($reportText -notmatch 'do-not-upload-this-secret' -and $reportText -notmatch 'RunAsUser') $reportText
        Check 'user profile paths are normalized' ($reportText -notmatch 'C:\\Users\\Alice' -and $reportText -match '<USERPROFILE>') $reportText
    } finally {
        $archive.Dispose()
    }

    $serverScript = Join-Path $probeRoot 'receiver.py'
    @'
import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

port_path = Path(sys.argv[1])
body_path = Path(sys.argv[2])
meta_path = Path(sys.argv[3])
expected_token = sys.argv[4]

class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '-1'))
        body = self.rfile.read(length)
        body_path.write_bytes(body)
        meta_path.write_text(json.dumps({
            'auth_ok': self.headers.get('Authorization') == 'Bearer ' + expected_token,
            'method': self.command,
            'body_hash': hashlib.sha256(body).hexdigest(),
            'content_type': self.headers.get('Content-Type'),
            'report_hash': self.headers.get('X-Report-SHA256'),
        }), encoding='utf-8')
        response = json.dumps({
            'status': 'stored',
            'receipt_id': 'd' * 32,
            'sha256': hashlib.sha256(body).hexdigest(),
        }).encode('utf-8')
        self.send_response(201)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)
    def log_message(self, format, *args):
        pass

server = HTTPServer(('127.0.0.1', 0), Receiver)
port_path.write_text(str(server.server_port), encoding='ascii')
server.handle_request()
server.server_close()
'@ | Set-Content -LiteralPath $serverScript -Encoding ASCII
    $portFile = Join-Path $probeRoot 'receiver.port'
    $capturedBody = Join-Path $probeRoot 'received.zip'
    $capturedMeta = Join-Path $probeRoot 'received.json'
    $serverStdOut = Join-Path $probeRoot 'receiver.stdout'
    $serverStdErr = Join-Path $probeRoot 'receiver.stderr'
    $testToken = 'test-upload-token-1234567890'
    $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { $pythonCommand = Get-Command python -ErrorAction SilentlyContinue }
    if (-not $pythonCommand) { throw 'python is required for the disposable upload receiver test' }
    $pythonPath = if ($pythonCommand.Source) { $pythonCommand.Source } else { $pythonCommand.Path }
    $serverArgs = @($serverScript, $portFile, $capturedBody, $capturedMeta, $testToken)
    $serverProcess = Start-Process -FilePath $pythonPath -ArgumentList $serverArgs -PassThru `
        -RedirectStandardOutput $serverStdOut -RedirectStandardError $serverStdErr
    $port = $null
    for ($i = 0; $i -lt 50; $i++) {
        if (Test-Path -LiteralPath $portFile) {
            try { $port = [int](Get-Content -LiteralPath $portFile -Raw); break } catch { }
        }
        Start-Sleep -Milliseconds 100
    }
    if ($null -eq $port) { throw 'local upload receiver did not start' }
    $uploadOut = & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $uploaderPath `
        -FindingsJson $findingsPath -WorkDir $workDir -RelayUrl ("http://127.0.0.1:{0}/v1/uploads" -f $port) `
        -ReportUploadToken $testToken -AllowInsecureRelay 2>&1
    $uploadRc = $LASTEXITCODE
    $uploadText = ($uploadOut -join "`n")
    Check 'authenticated upload succeeds' ($uploadRc -eq 0 -and $uploadText -match 'REPORT UPLOAD: stored' -and (Test-Path -LiteralPath $capturedBody)) $uploadText
    Check 'upload output does not expose the token' ($uploadText -notmatch [regex]::Escape($testToken)) $uploadText
    if (Test-Path -LiteralPath $capturedMeta) {
        $received = Get-Content -LiteralPath $capturedMeta -Raw | ConvertFrom-Json
        Check 'receiver saw bearer authentication' ($received.auth_ok -eq $true) ($received | ConvertTo-Json)
        Check 'receiver saw the package content type' ($received.content_type -eq 'application/zip') ($received | ConvertTo-Json)
        $uploadedPackageHash = (Get-FileHash -LiteralPath $capturedBody -Algorithm SHA256).Hash.ToLowerInvariant()
        Check 'receiver body hash is bound to the request header' ($received.report_hash -eq $uploadedPackageHash -and $received.body_hash -eq $uploadedPackageHash) ($received | ConvertTo-Json)
    } else {
        Check 'receiver wrote upload metadata' $false (($uploadOut -join "`n"))
    }

    # ---- Retry / idempotency regression scenarios -----------------------------
    $scenarioProcesses = @()
    $scenarioScript = Join-Path $probeRoot 'scenario_receiver.py'
    @'
import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

port_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
expected_token = sys.argv[3]
mode = sys.argv[4]
fail_count = int(sys.argv[5]) if len(sys.argv) > 5 else 0

class Receiver(BaseHTTPRequestHandler):
    count = 0

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '-1'))
        body = self.rfile.read(length) if length > 0 else b''
        Receiver.count += 1
        n = Receiver.count
        auth_ok = self.headers.get('Authorization') == 'Bearer ' + expected_token
        if mode == 'always401':
            status = 401
            payload = {'error': 'unauthorized'}
        elif mode == 'always503' or (mode == 'failfirst' and n <= fail_count):
            status = 503
            payload = {'error': 'temporarily unavailable'}
        else:
            digest = hashlib.sha256(body).hexdigest()
            if mode == 'badreceipt':
                status = 200
                payload = {'status': 'stored', 'receipt_id': 'd' * 32, 'sha256': '0' * 64}
            else:
                status = 201
                payload = {'status': 'stored', 'receipt_id': 'd' * 32, 'sha256': digest}
        with log_path.open('a', encoding='ascii') as log:
            log.write(json.dumps({
                'n': n,
                'auth_ok': auth_ok,
                'status_sent': status,
                'body_sha256': hashlib.sha256(body).hexdigest() if body else None,
            }) + '\n')
        response = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        pass

server = HTTPServer(('127.0.0.1', 0), Receiver)
port_path.write_text(str(server.server_port), encoding='ascii')
server.serve_forever()
'@ | Set-Content -LiteralPath $scenarioScript -Encoding ASCII

    function Start-ScenarioServer {
        param([string]$Mode, [int]$FailCount)
        $suffix = [guid]::NewGuid().ToString('N')
        $portFile = Join-Path $probeRoot ('scenario-' + $Mode + '-' + $suffix + '.port')
        $logFile = Join-Path $probeRoot ('scenario-' + $Mode + '-' + $suffix + '.log')
        $stdOut = Join-Path $probeRoot ('scenario-' + $Mode + '-' + $suffix + '.stdout')
        $stdErr = Join-Path $probeRoot ('scenario-' + $Mode + '-' + $suffix + '.stderr')
        $serverArgs = @($scenarioScript, $portFile, $logFile, $testToken, $Mode, [string]$FailCount)
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
        if ($null -eq $port) { throw 'scenario receiver did not start' }
        return @{ Port = $port; Log = $logFile; ProcessId = $proc.Id }
    }

    function Invoke-UploaderRun {
        param([string]$RelayUrl, [switch]$AllowInsecureRelay)
        $callArgs = @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-RelayUrl', $RelayUrl, '-ReportUploadToken', $testToken)
        if ($AllowInsecureRelay) { $callArgs += '-AllowInsecureRelay' }
        $runOutput = & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $uploaderPath @callArgs 2>&1
        return @{ Output = ($runOutput -join "`n"); Rc = $LASTEXITCODE }
    }

    function Read-ScenarioLog {
        param([string]$LogPath)
        $entries = @()
        if (Test-Path -LiteralPath $LogPath) {
            foreach ($line in (Get-Content -LiteralPath $LogPath)) {
                if ($line -match 'body_sha256') { $entries += ($line | ConvertFrom-Json) }
            }
        }
        return ,$entries
    }

    # Identical findings must produce a byte-identical package even when the
    # re-run happens after a later wall-clock timestamp, otherwise the relay's
    # received-body dedupe can never fire for a delayed retry.
    $idemWorkDir = Join-Path $workDir 'idem'
    $null = New-Item -ItemType Directory -Path $idemWorkDir -Force
    & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $uploaderPath -FindingsJson $findingsPath -WorkDir $idemWorkDir -NoUpload *> $null
    $zipFirst = Join-Path $idemWorkDir 'connectwise-report.zip'
    Start-Sleep -Seconds 3
    & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $uploaderPath -FindingsJson $findingsPath -WorkDir $idemWorkDir -NoUpload *> $null
    $zipSecond = Get-ChildItem -LiteralPath $idemWorkDir -Filter 'connectwise-report-*.zip' | Select-Object -First 1
    if ((Test-Path -LiteralPath $zipFirst) -and $zipSecond) {
        $hashFirst = (Get-FileHash -LiteralPath $zipFirst -Algorithm SHA256).Hash.ToLowerInvariant()
        $hashSecond = (Get-FileHash -LiteralPath $zipSecond.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        Check 'identical findings yield a byte-identical package across delayed runs' ($hashFirst -eq $hashSecond) ($hashFirst + ' vs ' + $hashSecond)
    } else {
        Check 'identical findings yield a byte-identical package across delayed runs' $false ('package was not produced twice')
    }

    # HTTPS fail-closed: an http relay URL is refused unless explicitly allowed.
    $httpsOut = Invoke-UploaderRun -RelayUrl 'http://127.0.0.1:9/v1/uploads'
    Check 'uploader refuses a non-https relay URL' ($httpsOut.Rc -ne 0 -and $httpsOut.Output -match 'must use HTTPS') $httpsOut.Output

    # Explicitly supplied but missing token file: a loud failure, not a silent
    # no-enrollment skip. The URL is never contacted because token resolution
    # happens before any network attempt.
    $missingTokenPath = Join-Path $probeRoot 'missing-token.txt'
    $noTokOut = & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $uploaderPath `
        -FindingsJson $findingsPath -WorkDir $workDir -RelayUrl 'http://127.0.0.1:9/v1/uploads' `
        -ReportUploadTokenFile $missingTokenPath -AllowInsecureRelay 2>&1
    $noTokRc = $LASTEXITCODE
    $noTokText = ($noTokOut -join "`n")
    Check 'explicit missing token file fails loudly' ($noTokRc -ne 0 -and $noTokText -match 'report upload token file was not found') $noTokText

    # No token anywhere (implicit no-enrollment) still skips upload cleanly.
    $savedTokenEnv = $env:SCREENCONNECT_REPORT_UPLOAD_TOKEN
    $env:SCREENCONNECT_REPORT_UPLOAD_TOKEN = $null
    $implicitOut = $null
    try {
        $implicitOut = & $psHost -NoLogo -NoProfile -ExecutionPolicy Bypass -File $uploaderPath `
            -FindingsJson $findingsPath -WorkDir $workDir 2>&1
        $implicitRc = $LASTEXITCODE
    } finally {
        $env:SCREENCONNECT_REPORT_UPLOAD_TOKEN = $savedTokenEnv
    }
    $implicitText = ($implicitOut -join "`n")
    Check 'implicit no-enrollment skips upload cleanly' ($implicitRc -eq 0 -and $implicitText -match 'no authenticated relay token is configured') $implicitText

    # 401 is deterministic: one attempt, no retry loop.
    $srv401 = Start-ScenarioServer -Mode 'always401'
    $out401 = Invoke-UploaderRun -RelayUrl ("http://127.0.0.1:{0}/v1/uploads" -f $srv401.Port) -AllowInsecureRelay
    $log401 = Read-ScenarioLog $srv401.Log
    Check '401 fails without retry' ($out401.Rc -ne 0 -and $out401.Output -match '401' -and $log401.Count -eq 1 -and $out401.Output -notmatch 'retrying') $out401.Output
    Stop-Process -Id $srv401.ProcessId -Force -ErrorAction SilentlyContinue

    # An invalid receipt after a 2xx response is deterministic: no retry.
    $srvBad = Start-ScenarioServer -Mode 'badreceipt'
    $outBad = Invoke-UploaderRun -RelayUrl ("http://127.0.0.1:{0}/v1/uploads" -f $srvBad.Port) -AllowInsecureRelay
    $logBad = Read-ScenarioLog $srvBad.Log
    Check 'invalid receipt fails without retry' ($outBad.Rc -ne 0 -and $outBad.Output -match 'receipt hash does not match' -and $logBad.Count -eq 1) $outBad.Output
    Stop-Process -Id $srvBad.ProcessId -Force -ErrorAction SilentlyContinue

    # A transient server error is retried with the SAME package bytes and then
    # succeeds (lost-acknowledgement recovery is idempotent on the relay).
    $srvRetry = Start-ScenarioServer -Mode 'failfirst' -FailCount 1
    $outRetry = Invoke-UploaderRun -RelayUrl ("http://127.0.0.1:{0}/v1/uploads" -f $srvRetry.Port) -AllowInsecureRelay
    $logRetry = Read-ScenarioLog $srvRetry.Log
    $sameBody = ($logRetry.Count -eq 2 -and $logRetry[0].body_sha256 -eq $logRetry[1].body_sha256)
    Check 'transient 5xx retries the same package and succeeds' ($outRetry.Rc -eq 0 -and $outRetry.Output -match 'REPORT UPLOAD: stored' -and $outRetry.Output -match 'retrying with the same package' -and $logRetry.Count -eq 2 -and $sameBody) $outRetry.Output
    Stop-Process -Id $srvRetry.ProcessId -Force -ErrorAction SilentlyContinue

    # Persistent 5xx is bounded: exactly three attempts of the same package.
    $srv503 = Start-ScenarioServer -Mode 'always503'
    $out503 = Invoke-UploaderRun -RelayUrl ("http://127.0.0.1:{0}/v1/uploads" -f $srv503.Port) -AllowInsecureRelay
    $log503 = Read-ScenarioLog $srv503.Log
    Check 'persistent 5xx retries are bounded at three attempts' ($out503.Rc -ne 0 -and $log503.Count -eq 3 -and $out503.Output -match 'REPORT UPLOAD FAILED') $out503.Output
    Stop-Process -Id $srv503.ProcessId -Force -ErrorAction SilentlyContinue
} finally {
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
    }
    foreach ($scenarioProcess in $scenarioProcesses) {
        if ($scenarioProcess -and -not $scenarioProcess.HasExited) {
            Stop-Process -Id $scenarioProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) report upload test(s) failed")
    exit 1
}
Write-Host 'ALL CONNECTWISE REPORT UPLOAD TESTS PASSED'
exit 0
