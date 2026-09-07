# test_connectwise_report_upload.ps1 - sanitized report-package regression test.
# Runs locally with a fixture only; no network or cleanup actions are used.
# Covers: local package contents, deterministic byte-identical re-runs, and the
# configured-URL skip behavior (MicroBin is the only share path; the relay ZIP
# upload was removed). PowerShell 5.1 compatible. Pure ASCII, no BOM.
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
Check 'cleanup suppresses the nested detector share' ($cleanupSource.Contains("'-NoReportShare'")) $cleanupSource
Check 'cleanup carries the MicroBin share flags' ($cleanupSource.Contains('$MicroBinUrl') -and $cleanupSource.Contains('$NoShare')) $cleanupSource
Check 'cleanup no longer passes relay parameters' (-not $cleanupSource.Contains('-RelayUrl') -and -not $cleanupSource.Contains('ReportUploadTokenFile') -and -not $cleanupSource.Contains('-NoReportUpload')) $cleanupSource
Check 'standalone detector exposes automatic sharing' ($detectorSource.Contains('$NoReportShare') -and $detectorSource.Contains('Submit-ConnectWiseReport.ps1')) $detectorSource
Check 'detector no longer declares relay parameters' (-not $detectorSource.Contains('ReportRelayUrl') -and -not $detectorSource.Contains('ReportUploadTokenFile')) $detectorSource
Check 'guided launcher references the uploader without an opt-in gate' ($startSource.Contains('Submit-ConnectWiseReport.ps1') -and $startSource.Contains('-FindingsJson') -and -not $startSource.Contains('Upload the sanitized report to MicroBin?')) $startSource
Check 'guided launcher no longer passes a relay URL' (-not $startSource.Contains('reports.aygross.xyz/v1/uploads')) $startSource
Check 'deployment bundle includes the uploader and URL file' ($bundleSource.Contains('Submit-ConnectWiseReport.ps1') -and $bundleSource.Contains('microbin-url.txt')) $bundleSource
Check 'deployment bundle drops the guided URL resolver' (-not $bundleSource.Contains('Resolve-MicroBinRunUrl.ps1')) $bundleSource

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
        Check 'user profile paths are normalized' ($reportText -notmatch 'C:' + [regex]::Escape('\Users\Alice') -and $reportText -match 'USERPROFILE') $reportText
    } finally {
        $archive.Dispose()
    }

    # Identical findings must produce a byte-identical package even when the
    # re-run happens after a later wall-clock timestamp.
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
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) report upload test(s) failed")
    exit 1
}
Write-Host 'ALL CONNECTWISE REPORT UPLOAD TESTS PASSED'
exit 0
