# test_microbin_report_upload.ps1 - focused regression test for the optional
# MicroBin report-paste mode of Submit-ConnectWiseReport.ps1.
# Runs locally with a disposable receiver only; no network, no live uploads.
# Covers multipart field construction, URL/scheme validation, redirect/response
# handling, no-secret logging, -RunPath discovery, and sanitized-content-only
# uploads (raw-data exclusions).
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$uploaderPath = Join-Path $repoRoot 'Submit-ConnectWiseReport.ps1'
$cleanupSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'sc-cleanup.ps1'))
$detectorSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'detect-remote-access.ps1'))
$startSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'START-HERE.bat'))
$uploaderSource = [System.IO.File]::ReadAllText($uploaderPath)
$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-microbin-upload-' + [guid]::NewGuid().ToString('N'))
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
Check 'uploader declares MicroBin parameters' ($uploaderSource.Contains('$MicroBinUrl') -and $uploaderSource.Contains('$MicroBinUploaderPasswordFile') -and $uploaderSource.Contains('$RunPath')) $uploaderSource
Check 'cleanup runner passes MicroBin through' ($cleanupSource.IndexOf('-MicroBinUrl', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $cleanupSource.Contains('-MicroBinUploaderPasswordFile')) $cleanupSource
Check 'standalone detector passes MicroBin through' ($detectorSource.Contains('-MicroBinUrl') -and $detectorSource.Contains('-MicroBinUploaderPasswordFile')) $detectorSource
Check 'guided launcher shares through the uploader with no env wiring' (($startSource.Contains('Submit-ConnectWiseReport.ps1')) -and (-not $startSource.Contains('SCC_MICROBIN_URL')) -and (-not $startSource.Contains('SCC_MICROBIN_UPLOADER_PASSWORD_FILE'))) $startSource
Check 'uploader sends no expiry beyond the bounded default' ($uploaderSource.Contains("MicroBinExpiration = '1week'")) $uploaderSource
Check 'uploader refuses to follow redirects' ($uploaderSource.Contains('AllowAutoRedirect = $false')) $uploaderSource

$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}

$workDir = Join-Path $probeRoot 'run'
$null = New-Item -ItemType Directory -Path $workDir -Force
$findingsPath = Join-Path $workDir 'findings.json'
$rawPath = Join-Path $workDir 'raw-secret.ps1'

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
'Write-Host do-not-upload-this-secret-RAW-EVIDENCE' | Set-Content -LiteralPath $rawPath -Encoding ASCII

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
        if mode == 'wrongpw':
            status, location, response = 302, '/incorrect', b''
        elif mode == 'evilredirect':
            status, location, response = 302, 'https://evil.example/phish', b''
        elif mode == 'nolocation':
            status, location, response = 200, None, b'ok'
        elif mode == 'bigerror':
            status, location, response = 403, None, ('blocked-by-server-policy ' + ('x' * 200000)).encode('ascii')
        elif mode == 'always503':
            status, location, response = 503, None, b'server error'
        else:
            status, location, response = 302, '/upload/pig-dog-cat', b''
        entry = {
            'n': n,
            'path': self.path,
            'content_type': content_type,
            'auth': self.headers.get('Authorization'),
            'fields': fields,
            'status_sent': status,
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

function Read-MicroBinLog {
    param([string]$LogPath)
    $entries = @()
    if (Test-Path -LiteralPath $LogPath) {
        foreach ($line in (Get-Content -LiteralPath $LogPath)) {
            if ($line -match '"fields"') { $entries += ($line | ConvertFrom-Json) }
        }
    }
    return ,$entries
}

try {
    $secretFile = Join-Path $probeRoot 'microbin-uploader-password.txt'
    $fileSecret = 'MicroBinUploaderSecret-a1b2c3d4e5'
    Set-Content -LiteralPath $secretFile -Value $fileSecret -Encoding ASCII

    # ---- 1. Successful private readonly share: multipart fields + sanitized body
    $srvOk = Start-MicroBinServer -Mode 'success'
    $okUrl = 'http://127.0.0.1:' + $srvOk.Port
    $out = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $okUrl, '-AllowInsecureRelay', '-IncidentAuthorization', 'Authorized', '-IncidentDelivery', 'Other: SMS lure')
    $text = $out.Output
    Check 'microbin share succeeds and prints the paste URL' ($out.Rc -eq 0 -and $text -match ('MICROBIN UPLOAD: ' + [regex]::Escape($okUrl) + '/upload/pig-dog-cat')) $text
    $entries = Read-MicroBinLog $srvOk.Log
    Check 'exactly one create request was sent' ($entries.Count -eq 1) ($entries.Count)
    if ($entries.Count -eq 1) {
        $e = $entries[0]
        Check 'request path is the create endpoint' ($e.path -eq '/upload') $e.path
        Check 'multipart content type is sent with a boundary' ($e.content_type -match '^multipart/form-data; boundary=') $e.content_type
        $fields = $e.fields
        Check 'multipart sends privacy=readonly' ([string]$fields.privacy -eq 'readonly') ($fields | ConvertTo-Json -Compress)
        Check 'multipart sends a bounded expiration' ([string]$fields.expiration -eq '1week') ($fields | ConvertTo-Json -Compress)
        Check 'no uploader_password field when none is configured' ($null -eq $fields.PSObject.Properties['uploader_password']) ($fields | ConvertTo-Json -Compress)
        Check 'no bearer auth header is sent to the paste server' ([string]::IsNullOrEmpty($e.auth)) $e.auth
        $bodyText = [string]$fields.content
        $bodyJson = $null
        try { $bodyJson = $bodyText | ConvertFrom-Json } catch { }
        Check 'paste content is valid sanitized report JSON' ($null -ne $bodyJson -and [int]$bodyJson.SchemaVersion -eq 2 -and [string]$bodyJson.ComputerName -eq 'CLIENT-99') $bodyText
        Check 'paste carries the operator incident context' ($null -ne $bodyJson -and [string]$bodyJson.IncidentContext.Authorization -eq 'Authorized' -and [string]$bodyJson.IncidentContext.Delivery -eq 'Other: SMS lure') $bodyText
        Check 'paste has no screenshot or VirusTotal fields' ($bodyText -notmatch '(?i)screenshot|virustotal') $bodyText
        Check 'context description is never echoed to the console' ($text -notmatch 'SMS lure') $text
        Check 'sanitized identifiers and relay details are retained' ($bodyText -match 'ABCDEF123456' -and $bodyText -match 'evil-relay.example') $bodyText
        Check 'raw evidence and secrets are excluded from the paste' ($bodyText -notmatch 'do-not-upload-this-secret' -and $bodyText -notmatch 'RunAsUser') $bodyText
        Check 'user profile paths are normalized in the paste' ($bodyText -notmatch 'C:' + [regex]::Escape('\Users\Bob') -and $bodyText -match 'USERPROFILE') $bodyText
    } else {
        Check 'multipart field details were captured' $false (($out.Output -join "`n"))
    }

    # ---- 2. Uploader password from an explicit file, never echoed -------------
    $srvPw = Start-MicroBinServer -Mode 'success'
    $pwUrl = 'http://127.0.0.1:' + $srvPw.Port
    $outPw = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $pwUrl, '-MicroBinUploaderPasswordFile', $secretFile, '-AllowInsecureRelay')
    $pwText = $outPw.Output
    Check 'share with password file succeeds' ($outPw.Rc -eq 0 -and $pwText -match 'MICROBIN UPLOAD:') $pwText
    Check 'password never appears in output' ($pwText -notmatch [regex]::Escape($fileSecret)) $pwText
    $pwEntries = Read-MicroBinLog $srvPw.Log
    if ($pwEntries.Count -eq 1) {
        Check 'uploader_password field carries the configured value' ([string]$pwEntries[0].fields.uploader_password -eq $fileSecret) ($pwEntries[0].fields | ConvertTo-Json -Compress)
    } else {
        Check 'uploader_password field was captured' $false ('receiver saw ' + $pwEntries.Count + ' requests')
    }

    # ---- 3. Environment fallback for the uploader password --------------------
    $srvEnv = Start-MicroBinServer -Mode 'success'
    $envUrl = 'http://127.0.0.1:' + $srvEnv.Port
    $envSecret = 'MicroBinEnvSecret-z9y8x7w6'
    $savedEnv = $env:SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD
    $envOut = $null
    $envRc = $null
    try {
        $env:SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD = $envSecret
        $envRun = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $envUrl, '-AllowInsecureRelay')
        $envOut = $envRun.Output
        $envRc = $envRun.Rc
    } finally {
        $env:SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD = $savedEnv
    }
    Check 'share with environment password succeeds' ($envRc -eq 0 -and $envOut -match 'MICROBIN UPLOAD:') $envOut
    Check 'environment password never appears in output' ($envOut -notmatch [regex]::Escape($envSecret)) $envOut
    $envEntries = Read-MicroBinLog $srvEnv.Log
    if ($envEntries.Count -eq 1) {
        Check 'uploader_password env fallback reaches the server' ([string]$envEntries[0].fields.uploader_password -eq $envSecret) ($envEntries[0].fields | ConvertTo-Json -Compress)
    } else {
        Check 'uploader_password env fallback was captured' $false ('receiver saw ' + $envEntries.Count + ' requests')
    }

    # ---- 4. Wrong uploader password is a loud single-shot failure -------------
    $srvWrong = Start-MicroBinServer -Mode 'wrongpw'
    $wrongUrl = 'http://127.0.0.1:' + $srvWrong.Port
    $outWrong = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $wrongUrl, '-MicroBinUploaderPasswordFile', $secretFile, '-AllowInsecureRelay')
    $wrongText = $outWrong.Output
    Check 'rejected uploader password fails loudly' ($outWrong.Rc -ne 0 -and $wrongText -match 'rejected the uploader credentials') $wrongText
    Check 'rejection never retries (a create is not idempotent)' ((Read-MicroBinLog $srvWrong.Log).Count -eq 1) $wrongText
    Check 'password not leaked on the failure path' ($wrongText -notmatch [regex]::Escape($fileSecret)) $wrongText

    # ---- 5. Persistent server errors are not retried --------------------------
    $srv503 = Start-MicroBinServer -Mode 'always503'
    $errUrl = 'http://127.0.0.1:' + $srv503.Port
    $out503 = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $errUrl, '-AllowInsecureRelay')
    $text503 = $out503.Output
    Check 'server 5xx is reported' ($out503.Rc -ne 0 -and $text503 -match 'MicroBin returned HTTP 503') $text503
    Check 'server 5xx is not retried' ((Read-MicroBinLog $srv503.Log).Count -eq 1) $text503

    # ---- 6. Cross-origin Location is refused and never printed ----------------
    $srvEvil = Start-MicroBinServer -Mode 'evilredirect'
    $evilUrl = 'http://127.0.0.1:' + $srvEvil.Port
    $outEvil = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $evilUrl, '-AllowInsecureRelay')
    $evilText = $outEvil.Output
    Check 'cross-origin Location is refused' ($outEvil.Rc -ne 0 -and $evilText -match 'different origin') $evilText
    Check 'foreign Location is never printed' ($evilText -notmatch 'evil\.example') $evilText

    # ---- 7. A 2xx response without Location is an error -----------------------
    $srvNoLoc = Start-MicroBinServer -Mode 'nolocation'
    $noLocUrl = 'http://127.0.0.1:' + $srvNoLoc.Port
    $outNoLoc = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $noLocUrl, '-AllowInsecureRelay')
    $noLocText = $outNoLoc.Output
    Check 'missing Location header is an error' ($outNoLoc.Rc -ne 0 -and $noLocText -match 'no Location header') $noLocText

    # ---- 8. Large error bodies are bounded, message still visible --------------
    $srvBig = Start-MicroBinServer -Mode 'bigerror'
    $bigUrl = 'http://127.0.0.1:' + $srvBig.Port
    $outBig = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $bigUrl, '-AllowInsecureRelay')
    $bigText = $outBig.Output
    Check 'large error response is reported with bounded detail' ($outBig.Rc -ne 0 -and $bigText -match 'HTTP 403' -and $bigText -match 'blocked-by-server-policy') $bigText

    # ---- 9. HTTPS-only by default; nothing contacts a plain-http server --------
    $srvHttps = Start-MicroBinServer -Mode 'success'
    $httpUrl = 'http://127.0.0.1:' + $srvHttps.Port
    $outHttp = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $httpUrl)
    Check 'plain-http MicroBin URL is refused without the test switch' ($outHttp.Rc -ne 0 -and $outHttp.Output -match 'must use HTTPS') $outHttp.Output
    Check 'refused URL is never contacted' ((Read-MicroBinLog $srvHttps.Log).Count -eq 0) ($outHttp.Output)

    # ---- 10. URL validation -----------------------------------------------------
    $badFtp = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', 'ftp://example.org/bin', '-AllowInsecureRelay')
    Check 'non-http(s) scheme is rejected' ($badFtp.Rc -ne 0 -and $badFtp.Output -match 'must use http or https') $badFtp.Output
    $badRel = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', 'not-a-url')
    Check 'relative MicroBin URL is rejected' ($badRel.Rc -ne 0 -and $badRel.Output -match 'not an absolute URI') $badRel.Output
    $badCred = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', 'https://user:secret@example.org')
    Check 'MicroBin URL with embedded credentials is rejected' ($badCred.Rc -ne 0 -and $badCred.Output -match 'must not contain embedded credentials') $badCred.Output

    # ---- 11. Explicit missing password file fails loudly ------------------------
    $missingSecret = Join-Path $probeRoot 'does-not-exist.txt'
    $srvNone = Start-MicroBinServer -Mode 'success'
    $noneUrl = 'http://127.0.0.1:' + $srvNone.Port
    $outMissing = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $noneUrl, '-MicroBinUploaderPasswordFile', $missingSecret, '-AllowInsecureRelay')
    Check 'explicit missing password file fails loudly' ($outMissing.Rc -ne 0 -and $outMissing.Output -match 'MicroBin uploader password file was not found') $outMissing.Output
    Check 'missing password file never contacts the server' ((Read-MicroBinLog $srvNone.Log).Count -eq 0) ($outMissing.Output)

    # ---- 12. -NoUpload disables MicroBin without a network attempt -------------
    $srvNoUp = Start-MicroBinServer -Mode 'success'
    $noUpUrl = 'http://127.0.0.1:' + $srvNoUp.Port
    $outNoUp = Invoke-UploaderRun @('-FindingsJson', $findingsPath, '-WorkDir', $workDir, '-MicroBinUrl', $noUpUrl, '-NoUpload', '-AllowInsecureRelay')
    Check '-NoUpload skips the MicroBin share cleanly' ($outNoUp.Rc -eq 0 -and $outNoUp.Output -match 'MICROBIN UPLOAD: disabled by operator') $outNoUp.Output
    Check '-NoUpload never contacts the server' ((Read-MicroBinLog $srvNoUp.Log).Count -eq 0) ($outNoUp.Output)

    # ---- 13. -RunPath convenience mode ------------------------------------------
    $runRoot = Join-Path $probeRoot 'runs/direct-root'
    $null = New-Item -ItemType Directory -Path $runRoot -Force
    Copy-Item -LiteralPath $findingsPath -Destination (Join-Path $runRoot 'findings.json')
    $outRun = Invoke-UploaderRun @('-RunPath', $runRoot, '-NoUpload')
    Check '-RunPath finds findings.json in the run root' ($outRun.Rc -eq 0 -and $outRun.Output -match 'REPORT FINDINGS:') $outRun.Output
    Check '-RunPath writes the package into the run root' (Test-Path -LiteralPath (Join-Path $runRoot 'connectwise-report.zip')) ($outRun.Output)

    $guidedRoot = Join-Path $probeRoot 'runs/guided-root'
    $null = New-Item -ItemType Directory -Path (Join-Path $guidedRoot 'detect/CLIENTA_20260101000000') -Force
    Copy-Item -LiteralPath $findingsPath -Destination (Join-Path $guidedRoot 'detect/CLIENTA_20260101000000/findings.json')
    $outGuided = Invoke-UploaderRun @('-RunPath', $guidedRoot, '-NoUpload')
    Check '-RunPath finds the guided-run nested findings.json' ($outGuided.Rc -eq 0 -and $outGuided.Output -match 'CLIENTA_20260101000000') $outGuided.Output
    Check 'guided-style run root receives the package' (Test-Path -LiteralPath (Join-Path $guidedRoot 'connectwise-report.zip')) ($outGuided.Output)

    $null = New-Item -ItemType Directory -Path (Join-Path $guidedRoot 'detect/CLIENTB_20260102000000') -Force
    Copy-Item -LiteralPath $findingsPath -Destination (Join-Path $guidedRoot 'detect/CLIENTB_20260102000000/findings.json')
    $outMulti = Invoke-UploaderRun @('-RunPath', $guidedRoot, '-NoUpload')
    Check 'ambiguous -RunPath fails without guessing' ($outMulti.Rc -ne 0 -and $outMulti.Output -match 'multiple findings.json') $outMulti.Output

    $emptyRoot = Join-Path $probeRoot 'runs/empty-root'
    $null = New-Item -ItemType Directory -Path $emptyRoot -Force
    $outEmpty = Invoke-UploaderRun @('-RunPath', $emptyRoot, '-NoUpload')
    Check 'empty -RunPath fails with a clear message' ($outEmpty.Rc -ne 0 -and $outEmpty.Output -match 'no findings.json was found under the run path') $outEmpty.Output

    $outNone = Invoke-UploaderRun @('-NoUpload')
    Check 'no input at all fails with a clear message' ($outNone.Rc -ne 0 -and $outNone.Output -match 'findings JSON was not specified') $outNone.Output
} finally {
    foreach ($proc in $scenarioProcesses) {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) MicroBin report upload test(s) failed")
    exit 1
}
Write-Host 'ALL MICROBIN REPORT UPLOAD TESTS PASSED'
exit 0
