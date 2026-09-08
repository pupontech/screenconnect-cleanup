# test_incident_context_and_dates.ps1 - regression tests for the per-run
# incident context (authorization + delivery) and the per-instance observed
# installation date in the sanitized report pipeline:
#   - Resolve-IncidentContext.ps1: safe defaults, operator correction, closed
#     set / bounded-attempt validation, Other-with-description, no partial or
#     secret-bearing output files.
#   - Submit-ConnectWiseReport.ps1: context embedded in the sanitized JSON and
#     the human-readable TXT (and therefore the MicroBin paste, which posts
#     the same JSON), explicit-value validation, date precedence/absence,
#     absence of screenshot/VirusTotal fields, and no-secret logging.
# Runs locally with disposable fixtures; no network and no live uploads.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$resolverPath = Join-Path $repoRoot 'Resolve-IncidentContext.ps1'
$uploaderPath = Join-Path $repoRoot 'Submit-ConnectWiseReport.ps1'
$batPath = Join-Path $repoRoot 'START-HERE.bat'
$bundlePath = Join-Path $repoRoot 'make-deploy-bundle.sh'
$uploaderSource = [System.IO.File]::ReadAllText($uploaderPath)
$resolverSource = [System.IO.File]::ReadAllText($resolverPath)
$batSource = [System.IO.File]::ReadAllText($batPath)
$bundleSource = [System.IO.File]::ReadAllText($bundlePath)

$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-incident-context-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force

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

function Write-TextFile {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.ASCIIEncoding))
}

$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}

function Invoke-ResolverRun {
    param(
        [string]$OutFile,
        [AllowEmptyString()][string[]]$Answers
    )
    $callArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $resolverPath, '-OutFile', $OutFile)
    if ($null -eq $Answers -or $Answers.Count -eq 0) {
        $output = & $psHost @callArgs 2>&1
    } else {
        $output = (($Answers -join "`n") + "`n") | & $psHost @callArgs 2>&1
    }
    $text = ''
    if ($null -ne $output) { $text = ($output -join "`n") }
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = $text }
}

function Read-ContextFile {
    param([string]$Path)
    $lines = @()
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        foreach ($raw in [System.IO.File]::ReadLines($Path)) { $lines += $raw }
    }
    return ,$lines
}

function Invoke-UploaderRun {
    param([string]$FindingsJson, [string]$WorkDir, [object[]]$ExtraArgs)
    $callArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $uploaderPath,
        '-FindingsJson', $FindingsJson, '-WorkDir', $WorkDir, '-NoUpload') + $ExtraArgs
    $runOutput = & $psHost @callArgs 2>&1
    return @{ Output = ($runOutput -join "`n"); Rc = $LASTEXITCODE }
}

function Read-ReportPackage {
    param([string]$WorkDir)
    $packagePath = Join-Path $WorkDir 'connectwise-report.zip'
    if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) { return $null }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($packagePath)
    try {
        $result = [ordered]@{}
        foreach ($name in @('connectwise-report.json', 'connectwise-report.txt')) {
            $entry = $archive.GetEntry($name)
            if ($null -eq $entry) { continue }
            $reader = New-Object System.IO.StreamReader($entry.Open())
            try { $result[$name] = $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        return $result
    } finally {
        $archive.Dispose()
    }
}

try {
    # ==========================================================================
    # 1. Source-level wiring contracts
    # ==========================================================================
    Check 'launcher has no interactive incident-context step' (-not $batSource.Contains('Resolve-IncidentContext.ps1')) $batPath
    Check 'launcher has no incident-context answer variables' (-not $batSource.Contains('SCC_CTX_AUTH') -and -not $batSource.Contains('SCC_CTX_DELIVERY')) $batPath
    Check 'launcher does not invent or forward prompted context' (-not $batSource.Contains('-IncidentAuthorization') -and -not $batSource.Contains('-IncidentDelivery')) $batPath
    Check 'launcher shares via the uploader with no relay or opt-in gate' (($batSource.Contains('Submit-ConnectWiseReport.ps1')) -and (-not $batSource.Contains('reports.aygross.xyz/v1/uploads')) -and (-not $batSource.Contains('SCC_MICROBIN_URL'))) $batPath
    Check 'deploy bundle omits the retired interactive context helper' (-not $bundleSource.Contains('Resolve-IncidentContext.ps1')) $bundlePath
    Check 'uploader declares the incident-context parameters' ($uploaderSource.Contains('$IncidentAuthorization') -and $uploaderSource.Contains('$IncidentDelivery') -and $uploaderSource.Contains('$RunPath')) $uploaderPath
    Check 'uploader validates explicit context values' ($uploaderSource.Contains('Assert-IncidentAuthorization') -and $uploaderSource.Contains('Assert-IncidentDelivery')) $uploaderPath
    Check 'uploader computes the observed install date from detector evidence' ($uploaderSource.Contains('Get-ObservedInstallDate')) $uploaderPath
    Check 'report schema version is 2' ($uploaderSource.Contains('SchemaVersion   = 2')) $uploaderPath
    Check 'resolver and uploader share the safe defaults' ($resolverSource.Contains('Not authorized') -and $resolverSource.Contains('Email invite scam') -and $uploaderSource.Contains('Email invite scam')) 'default drift'
    Check 'sanitized report source never references screenshot or VirusTotal fields' ($uploaderSource -notmatch '(?i)screenshot|virustotal') $uploaderPath

    # ==========================================================================
    # 2. Resolver behavior: defaults, correction, validation, no secrets
    # ==========================================================================
    $ctxDir = Join-Path $probeRoot 'ctx'
    $null = New-Item -ItemType Directory -Path $ctxDir -Force

    $defaultsFile = Join-Path $ctxDir 'defaults.txt'
    $outDefaults = Invoke-ResolverRun -OutFile $defaultsFile -Answers @('', '')
    $defaultLines = Read-ContextFile $defaultsFile
    Check 'resolver defaults on blank answers: Not authorized + Email invite scam' ($outDefaults.ExitCode -eq 0 -and $defaultLines.Count -eq 2 -and $defaultLines[0] -eq 'Not authorized' -and $defaultLines[1] -eq 'Email invite scam') ($outDefaults.Text)

    $corrFile = Join-Path $ctxDir 'correction.txt'
    $outCorr = Invoke-ResolverRun -OutFile $corrFile -Answers @('A', 'e')
    $corrLines = Read-ContextFile $corrFile
    Check 'resolver accepts operator correction (Authorized / Email invite scam)' ($outCorr.ExitCode -eq 0 -and $corrLines[0] -eq 'Authorized' -and $corrLines[1] -eq 'Email invite scam') ($outCorr.Text)

    $otherFile = Join-Path $ctxDir 'other.txt'
    $labelSecret = 'Phoned from fake Microsoft support'
    $outOther = Invoke-ResolverRun -OutFile $otherFile -Answers @('n', 'o', $labelSecret)
    $otherLines = Read-ContextFile $otherFile
    Check 'resolver Other branch requires and stores a description' ($outOther.ExitCode -eq 0 -and $otherLines[0] -eq 'Not authorized' -and $otherLines[1] -eq ('Other: ' + $labelSecret)) ($outOther.Text)
    Check 'resolver never echoes the typed description' ($outOther.Text -notmatch [regex]::Escape($labelSecret)) $outOther.Text

    $invalidFirstFile = Join-Path $ctxDir 'invalid-first.txt'
    $outInvalidFirst = Invoke-ResolverRun -OutFile $invalidFirstFile -Answers @('zzz', 'A', 'E')
    $invalidFirstLines = Read-ContextFile $invalidFirstFile
    Check 'resolver refuses an invalid answer and re-prompts' ($outInvalidFirst.ExitCode -eq 0 -and $invalidFirstLines[0] -eq 'Authorized' -and $invalidFirstLines[1] -eq 'Email invite scam') $outInvalidFirst.Text
    Check 'invalid attempt shows the re-prompt hint' $outInvalidFirst.Text.Contains('Answer A for Authorized') $outInvalidFirst.Text

    $badLabelFile = Join-Path $ctxDir 'bad-label.txt'
    $badLabelText = 'evil%label'
    $outBadLabel = Invoke-ResolverRun -OutFile $badLabelFile -Answers @('n', 'o', $badLabelText, 'o', 'ok label')
    $badLabelLines = Read-ContextFile $badLabelFile
    Check 'resolver refuses a forbidden-character description and re-prompts' ($outBadLabel.ExitCode -eq 0 -and $badLabelLines[1] -eq 'Other: ok label') $outBadLabel.Text
    Check 'refused description never appears in output or file' ($outBadLabel.Text -notmatch [regex]::Escape($badLabelText) -and ($badLabelLines -join '|') -notmatch [regex]::Escape($badLabelText)) $outBadLabel.Text

    $exhaustedFile = Join-Path $ctxDir 'exhausted.txt'
    $outExhausted = Invoke-ResolverRun -OutFile $exhaustedFile -Answers @('x', 'y', 'z', 'E')
    Check 'three invalid answers fail closed with exit 4 and no file' ($outExhausted.ExitCode -eq 4 -and (-not (Test-Path -LiteralPath $exhaustedFile)) -and $outExhausted.Text.Contains('not recorded')) $outExhausted.Text

    $blockedParent = Join-Path $ctxDir 'blocker.txt'
    Write-TextFile -Path $blockedParent -Text 'i am a file, not a directory'
    $outWriteFail = Invoke-ResolverRun -OutFile (Join-Path $blockedParent 'nested.txt') -Answers @('A', 'E')
    Check 'resolver write failure is loud with exit 1' ($outWriteFail.ExitCode -eq 1 -and $outWriteFail.Text.Contains('Could not write the incident context file')) $outWriteFail.Text

    $oddDir = Join-Path $probeRoot "ctx dir with 'spaces'"
    $null = New-Item -ItemType Directory -Path $oddDir -Force
    $oddFile = Join-Path $oddDir 'incident-context.txt'
    $outOdd = Invoke-ResolverRun -OutFile $oddFile -Answers @('', '')
    $oddLines = Read-ContextFile $oddFile
    Check 'space/apostrophe output path stores the validated pair' ($outOdd.ExitCode -eq 0 -and $oddLines.Count -eq 2 -and $oddLines[1] -eq 'Email invite scam') $outOdd.Text

    # ==========================================================================
    # 3. Uploader behavior: context + observed install dates in JSON and TXT
    # ==========================================================================
    $fixturePath = Join-Path $probeRoot 'findings.json'
    $fixture = [ordered]@{
        SchemaVersion   = 4
        GeneratedUtc    = '2026-09-06T12:00:00Z'
        ComputerName    = 'CLIENT-77'
        RunAsUser       = 'Carol'
        DeliveryContext = 'malvertising'
        ScreenshotPath  = 'C:\shots\should-never-appear.png'
        VirusTotalResult = 'malicious-flag'
        Instances       = @(
            [ordered]@{
                Identifier  = 'INST-EVENT'
                RelayHost   = 'r0.evil.example'
                RelayPort   = 443
                InstallDir  = 'C:\Users\Carol\AppData\Local\ScreenConnect Client (INST-EVENT)'
                ParamBlob   = 'do-not-upload-this-secret-param-blob'
                InstallDirCreatedUtc = '2026-07-01 00:00:00'
                InstallDate = '20260601'
                ServiceInstallEvents = @(
                    [ordered]@{ TimeUtc = '2026-06-01 12:00:00'; Message = 'SecretEventText-2026-06-01' },
                    [ordered]@{ TimeUtc = '2026-01-15 09:30:00'; Message = 'SecretEventText-2026-01-15' },
                    [ordered]@{ TimeUtc = '2025-12-31 23:59:59'; Message = 'SecretEventText-2025-12-31' }
                )
            },
            [ordered]@{
                Identifier  = 'INST-DIR'
                RelayHost   = 'r1.evil.example'
                RelayPort   = 443
                InstallDir  = 'C:\Users\Carol\AppData\Local\ScreenConnect Client (INST-DIR)'
                InstallDirCreatedUtc = '2026-02-03 04:05:06'
                InstallDate = '20200101'
                ServiceInstallEvents = @()
            },
            [ordered]@{
                Identifier  = 'INST-REG'
                RelayHost   = 'r2.evil.example'
                RelayPort   = 443
                InstallDir  = 'C:\Users\Carol\AppData\Local\ScreenConnect Client (INST-REG)'
                InstallDate = '20230115'
            },
            [ordered]@{
                Identifier  = 'INST-JUNK'
                RelayHost   = 'r3.evil.example'
                RelayPort   = 443
                InstallDir  = 'C:\Users\Carol\AppData\Local\ScreenConnect Client (INST-JUNK)'
                InstallDirCreatedUtc = 'not-a-date'
                InstallDate = 'garbage'
            },
            [ordered]@{
                Identifier  = 'INST-NONE'
                RelayHost   = 'r4.evil.example'
                RelayPort   = 443
                InstallDir  = 'C:\Users\Carol\AppData\Local\ScreenConnect Client (INST-NONE)'
            }
        )
    }
    $fixture | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $fixturePath -Encoding ASCII

    # 3a. No explicit context: legacy findings context is carried; absence is
    #     reported honestly as Not available; nothing is invented.
    $workA = Join-Path $probeRoot 'run-a'
    $null = New-Item -ItemType Directory -Path $workA -Force
    $runA = Invoke-UploaderRun -FindingsJson $fixturePath -WorkDir $workA
    Check 'package-only run with no context args succeeds' ($runA.Rc -eq 0) $runA.Output
    $packageA = Read-ReportPackage $workA
    Check 'package A contains JSON and TXT entries' ($null -ne $packageA -and $packageA.Contains('connectwise-report.json') -and $packageA.Contains('connectwise-report.txt')) ($runA.Output)
    $jsonA = $null
    if ($packageA -and $packageA.Contains('connectwise-report.json')) {
        try { $jsonA = $packageA['connectwise-report.json'] | ConvertFrom-Json } catch { }
    }
    Check 'report A is schema version 2' ($null -ne $jsonA -and [int]$jsonA.SchemaVersion -eq 2) ($packageA['connectwise-report.json'])
    Check 'report A carries context: legacy delivery fallback, authorization Not available' ($null -ne $jsonA -and [string]$jsonA.IncidentContext.Delivery -eq 'malvertising' -and [string]$jsonA.IncidentContext.Authorization -eq 'Not available') ($packageA['connectwise-report.json'])
    Check 'flat legacy DeliveryContext key is gone from the report' ($null -ne $jsonA -and ($jsonA.PSObject.Properties.Name -notcontains 'DeliveryContext')) ($packageA['connectwise-report.json'])

    # 3b. Date precedence per instance: 7045 earliest, then dir creation, then
    #     registry InstallDate, then Not available.
    $instancesA = $null
    if ($null -ne $jsonA) { $instancesA = @($jsonA.ScreenConnect.Instances) }
    if ($instancesA -and $instancesA.Count -ge 5) {
        Check 'date basis 1: earliest matching 7045 event wins over dir/registry' ($instancesA[0].InstallDateObserved -eq '2025-12-31 23:59:59' -and $instancesA[0].InstallDateBasis -eq 'Windows service-install event 7045') ($packageA['connectwise-report.json'])
        Check 'date basis 2: install-directory creation time' ($instancesA[1].InstallDateObserved -eq '2026-02-03 04:05:06' -and $instancesA[1].InstallDateBasis -eq 'Install-directory creation time') ($packageA['connectwise-report.json'])
        Check 'date basis 3: registry InstallDate normalized to YYYY-MM-DD' ($instancesA[2].InstallDateObserved -eq '2023-01-15' -and $instancesA[2].InstallDateBasis -eq 'Registry InstallDate') ($packageA['connectwise-report.json'])
        Check 'unusable date evidence is reported as Not available' ($instancesA[3].InstallDateObserved -eq 'Not available' -and $instancesA[3].InstallDateBasis -eq 'Not available') ($packageA['connectwise-report.json'])
        Check 'absent evidence is reported as Not available' ($instancesA[4].InstallDateObserved -eq 'Not available' -and $instancesA[4].InstallDateBasis -eq 'Not available') ($packageA['connectwise-report.json'])
    } else {
        Check 'report A exposes per-instance date records' $false ($packageA['connectwise-report.json'])
    }

    # 3c. No screenshot/VirusTotal/raw fields anywhere in the sanitized outputs.
    $jsonTextA = [string]$packageA['connectwise-report.json']
    $txtTextA = [string]$packageA['connectwise-report.txt']
    Check 'sanitized JSON has no screenshot or VirusTotal fields' ($jsonTextA -notmatch '(?i)screenshot|virustotal') $jsonTextA
    Check 'sanitized TXT has no screenshot or VirusTotal fields' ($txtTextA -notmatch '(?i)screenshot|virustotal') $txtTextA
    Check 'sanitized JSON excludes raw 7045 event messages' ($jsonTextA -notmatch 'SecretEventText') $jsonTextA
    Check 'sanitized JSON excludes param blobs and account names' ($jsonTextA -notmatch 'do-not-upload-this-secret-param-blob' -and $jsonTextA -notmatch 'RunAsUser') $jsonTextA
    Check 'sanitized TXT excludes raw 7045 event messages' ($txtTextA -notmatch 'SecretEventText') $txtTextA
    Check 'human TXT lists the incident context' ($txtTextA.Contains('Incident authorization: Not available') -and $txtTextA.Contains('Incident delivery: malvertising')) $txtTextA
    Check 'human TXT lists per-instance observed install dates' ($txtTextA.Contains('Install date observed: 2025-12-31 23:59:59 (Windows service-install event 7045)') -and $txtTextA.Contains('Install date observed: 2023-01-15 (Registry InstallDate)') -and $txtTextA.Contains('Install date observed: Not available')) $txtTextA

    # 3d. Explicit operator context overrides the findings fallback.
    $workB = Join-Path $probeRoot 'run-b'
    $null = New-Item -ItemType Directory -Path $workB -Force
    $labelB = 'SMS lure'
    $runB = Invoke-UploaderRun -FindingsJson $fixturePath -WorkDir $workB -ExtraArgs @('-IncidentAuthorization', 'Authorized', '-IncidentDelivery', ('Other: ' + $labelB))
    Check 'package-only run with explicit context succeeds' ($runB.Rc -eq 0) $runB.Output
    $packageB = Read-ReportPackage $workB
    $jsonB = $null
    if ($packageB -and $packageB.Contains('connectwise-report.json')) {
        try { $jsonB = $packageB['connectwise-report.json'] | ConvertFrom-Json } catch { }
    }
    Check 'explicit context overrides the findings fallback' ($null -ne $jsonB -and [string]$jsonB.IncidentContext.Authorization -eq 'Authorized' -and [string]$jsonB.IncidentContext.Delivery -eq ('Other: ' + $labelB)) ($packageB['connectwise-report.json'])
    $txtTextB = [string]$packageB['connectwise-report.txt']
    Check 'human TXT shows the corrected context' ($txtTextB.Contains('Incident authorization: Authorized') -and $txtTextB.Contains('Incident delivery: Other: SMS lure')) $txtTextB
    Check 'context value is not echoed to the console' ($runB.Output -notmatch [regex]::Escape($labelB)) $runB.Output

    # 3e. Real detector shape: findings nested under ScreenConnect.Instances
    #     must feed the identical date/context records.
    $parsedFixture = Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json
    $nestedFixture = [ordered]@{
        SchemaVersion = $parsedFixture.SchemaVersion
        GeneratedUtc  = $parsedFixture.GeneratedUtc
        ComputerName  = $parsedFixture.ComputerName
        ScreenConnect = [ordered]@{
            Instances = @($parsedFixture.Instances)
        }
    }
    $nestedPath = Join-Path $probeRoot 'findings-nested.json'
    $nestedFixture | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $nestedPath -Encoding ASCII
    $workC = Join-Path $probeRoot 'run-c'
    $null = New-Item -ItemType Directory -Path $workC -Force
    $runC = Invoke-UploaderRun -FindingsJson $nestedPath -WorkDir $workC
    Check 'nested detector-shaped findings produce a package' ($runC.Rc -eq 0) $runC.Output
    $packageC = Read-ReportPackage $workC
    $jsonC = $null
    if ($packageC -and $packageC.Contains('connectwise-report.json')) {
        try { $jsonC = $packageC['connectwise-report.json'] | ConvertFrom-Json } catch { }
    }
    $instancesC = $null
    if ($null -ne $jsonC) { $instancesC = @($jsonC.ScreenConnect.Instances) }
    Check 'nested shape yields schema 2 and the incident context' ($null -ne $jsonC -and [int]$jsonC.SchemaVersion -eq 2 -and [string]$jsonC.IncidentContext.Authorization -eq 'Not available') ($packageC['connectwise-report.json'])
    Check 'nested shape yields the observed install dates' ($null -ne $instancesC -and $instancesC.Count -ge 5 -and $instancesC[0].InstallDateObserved -eq '2025-12-31 23:59:59' -and $instancesC[2].InstallDateObserved -eq '2023-01-15') ($packageC['connectwise-report.json'])

    # 3f. Explicit invalid context fails loudly before any package is built.
    $workBad = Join-Path $probeRoot 'run-bad'
    $null = New-Item -ItemType Directory -Path $workBad -Force
    $badAuth = Invoke-UploaderRun -FindingsJson $fixturePath -WorkDir $workBad -ExtraArgs @('-IncidentAuthorization', 'Maybe')
    Check 'invalid authorization value fails loudly' ($badAuth.Rc -ne 0 -and $badAuth.Output -match 'incident authorization must be exactly') $badAuth.Output
    $badOther = Invoke-UploaderRun -FindingsJson $fixturePath -WorkDir $workBad -ExtraArgs @('-IncidentDelivery', 'Other')
    Check 'bare Other without a description fails loudly' ($badOther.Rc -ne 0 -and $badOther.Output -match 'incident delivery must be') $badOther.Output
    $badLabel = Invoke-UploaderRun -FindingsJson $fixturePath -WorkDir $workBad -ExtraArgs @('-IncidentDelivery', 'Other: bad%label')
    Check 'forbidden characters in the description fail loudly' ($badLabel.Rc -ne 0 -and $badLabel.Output -match 'character that is not allowed') $badLabel.Output
    Check 'failed validation leaves no package behind' (-not (Test-Path -LiteralPath (Join-Path $workBad 'connectwise-report.zip') -PathType Leaf)) $badAuth.Output
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) incident-context/date test(s) failed")
    exit 1
}
Write-Host 'ALL INCIDENT CONTEXT AND DATE TESTS PASSED'
exit 0
