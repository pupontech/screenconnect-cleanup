# Submit-ConnectWiseReport.ps1 - create and optionally upload a sanitized report.
# PowerShell 5.1 compatible. Raw evidence and credential-bearing fields are not
# included in the automatic package. Uploads require an explicit bearer token.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FindingsJson,
    [Parameter(Mandatory = $true)]
    [string]$WorkDir,
    [string]$ReportHtml = '',
    [string]$ResultsJson = '',
    [string]$DiffJson = '',
    [string]$RelayUrl = 'https://reports.aygross.xyz/v1/uploads',
    [string]$ReportUploadToken = '',
    [string]$ReportUploadTokenFile = '',
    [switch]$NoUpload,
    [switch]$AllowInsecureRelay
)

$ErrorActionPreference = 'Stop'
$script:PackagePath = $null
$script:StageDir = $null

function Get-Field {
    param(
        [object]$Object,
        [string]$Name
    )
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-ArrayValue {
    param([object]$Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return $Value }
    return @($Value)
}

function Convert-ReportPath {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    $text = $text -replace '(?i)[A-Z]:\\Users\\[^\\]+', '<USERPROFILE>'
    $text = $text -replace '(?i)/home/[^/]+', '<USERPROFILE>'
    return $text
}

function Convert-ReportScalar {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (Convert-ReportPath $Value) }
    if ($Value -is [bool] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }
    return (Convert-ReportPath ([string]$Value))
}

function New-SafeFileRecord {
    param([object]$File)
    if ($null -eq $File) { return $null }
    return [ordered]@{
        Path            = Convert-ReportPath (Get-Field $File 'Path')
        Length          = Convert-ReportScalar (Get-Field $File 'Length')
        SizeBytes       = Convert-ReportScalar (Get-Field $File 'SizeBytes')
        SHA256          = Convert-ReportScalar (Get-Field $File 'SHA256')
        SignatureStatus = Convert-ReportScalar (Get-Field $File 'SignatureStatus')
        SignerSubject   = Convert-ReportScalar (Get-Field $File 'SignerSubject')
    }
}

function New-SafeConnectionRecord {
    param([object]$Connection)
    if ($null -eq $Connection) { return $null }
    return [ordered]@{
        LocalAddress  = Convert-ReportScalar (Get-Field $Connection 'LocalAddress')
        LocalPort     = Convert-ReportScalar (Get-Field $Connection 'LocalPort')
        RemoteAddress = Convert-ReportScalar (Get-Field $Connection 'RemoteAddress')
        RemotePort    = Convert-ReportScalar (Get-Field $Connection 'RemotePort')
        State         = Convert-ReportScalar (Get-Field $Connection 'State')
    }
}

function New-SafeInstanceRecord {
    param([object]$Instance)
    $fileValue = Get-Field $Instance 'Files'
    if ($null -eq $fileValue) { $fileValue = Get-Field $Instance 'File' }
    $safeFiles = @()
    foreach ($file in @(Get-ArrayValue $fileValue)) {
        $safeFile = New-SafeFileRecord $file
        if ($null -ne $safeFile) { $safeFiles += ,$safeFile }
    }

    $safeConnections = @()
    foreach ($connection in @(Get-ArrayValue (Get-Field $Instance 'Connections'))) {
        $safeConnection = New-SafeConnectionRecord $connection
        if ($null -ne $safeConnection) { $safeConnections += ,$safeConnection }
    }

    $unknownKeys = @()
    $unknown = Get-Field $Instance 'UnknownParams'
    if ($unknown -is [System.Collections.IDictionary]) {
        $unknownKeys = @($unknown.Keys | ForEach-Object { [string]$_ } | Sort-Object)
    } elseif ($null -ne $unknown) {
        $unknownKeys = @($unknown.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    }

    return [ordered]@{
        Identifier       = Convert-ReportScalar (Get-Field $Instance 'Identifier')
        Thumbprint       = Convert-ReportScalar (Get-Field $Instance 'Identifier')
        RelayHost        = Convert-ReportScalar (Get-Field $Instance 'RelayHost')
        RelayPort        = Convert-ReportScalar (Get-Field $Instance 'RelayPort')
        SessionType      = Convert-ReportScalar (Get-Field $Instance 'SessionType')
        Role             = Convert-ReportScalar (Get-Field $Instance 'Role')
        DisplayVersion   = Convert-ReportScalar (Get-Field $Instance 'DisplayVersion')
        Publisher        = Convert-ReportScalar (Get-Field $Instance 'Publisher')
        ServiceName      = Convert-ReportScalar (Get-Field $Instance 'ServiceName')
        InstallPath      = Convert-ReportPath (Get-Field $Instance 'InstallDir')
        Files            = @($safeFiles)
        Connections      = @($safeConnections)
        UnknownParamKeys = @($unknownKeys)
    }
}

function New-SafeParseIssue {
    param([object]$Issue)
    if ($null -eq $Issue) { return $null }
    return [ordered]@{
        Identifier = Convert-ReportScalar (Get-Field $Issue 'Identifier')
        Key        = Convert-ReportScalar (Get-Field $Issue 'Key')
        Issue      = Convert-ReportScalar (Get-Field $Issue 'Issue')
    }
}

function New-SafeHistoricalRecord {
    param([object]$Item)
    if ($null -eq $Item) { return $null }
    return [ordered]@{
        TimeUtc    = Convert-ReportScalar (Get-Field $Item 'TimeUtc')
        Identifier = Convert-ReportScalar (Get-Field $Item 'Identifier')
    }
}

function New-SafeOtherTarget {
    param([object]$Target)
    if ($null -eq $Target) { return $null }
    $hits = @()
    foreach ($hit in @(Get-ArrayValue (Get-Field $Target 'Hits'))) {
        if ($null -eq $hit) { continue }
        $hits += ,[ordered]@{
            Kind = Convert-ReportScalar (Get-Field $hit 'Kind')
            Name = Convert-ReportScalar (Get-Field $hit 'Name')
            Path = Convert-ReportPath (Get-Field $hit 'Path')
        }
    }
    return [ordered]@{
        Name = Convert-ReportScalar (Get-Field $Target 'Name')
        Hits = @($hits)
    }
}

function New-SafeReport {
    param([object]$Data)
    $screen = Get-Field $Data 'ScreenConnect'
    $instanceValue = $null
    $parseValue = $null
    $historicalValue = $null
    if ($null -ne $screen) {
        $instanceValue = Get-Field $screen 'Instances'
        $parseValue = Get-Field $screen 'ParseIssues'
        $historicalValue = Get-Field $screen 'Historical'
    }
    if ($null -eq $instanceValue) { $instanceValue = Get-Field $Data 'Instances' }
    if ($null -eq $parseValue) { $parseValue = Get-Field $Data 'ParseIssues' }
    if ($null -eq $historicalValue) { $historicalValue = Get-Field $Data 'Historical' }

    $instances = @()
    foreach ($instance in @(Get-ArrayValue $instanceValue)) {
        if ($null -ne $instance) { $instances += ,(New-SafeInstanceRecord $instance) }
    }
    $parseIssues = @()
    foreach ($issue in @(Get-ArrayValue $parseValue)) {
        $safeIssue = New-SafeParseIssue $issue
        if ($null -ne $safeIssue) { $parseIssues += ,$safeIssue }
    }
    $historical = @()
    foreach ($item in @(Get-ArrayValue $historicalValue)) {
        $safeItem = New-SafeHistoricalRecord $item
        if ($null -ne $safeItem) { $historical += ,$safeItem }
    }
    $otherTargets = @()
    foreach ($target in @(Get-ArrayValue (Get-Field $Data 'OtherTargets'))) {
        $safeTarget = New-SafeOtherTarget $target
        if ($null -ne $safeTarget -and @($safeTarget.Hits).Count -gt 0) { $otherTargets += ,$safeTarget }
    }

    return [ordered]@{
        SchemaVersion   = 1
        ReportType      = 'Potential malicious or fraudulent ScreenConnect activity'
        GeneratedUtc    = Convert-ReportScalar (Get-Field $Data 'GeneratedUtc')
        ToolVersion     = Convert-ReportScalar (Get-Field $Data 'Version')
        RunId           = Convert-ReportScalar (Get-Field $Data 'RunId')
        ComputerName    = Convert-ReportScalar (Get-Field $Data 'ComputerName')
        OSCaption       = Convert-ReportScalar (Get-Field $Data 'OSCaption')
        DeliveryContext = Convert-ReportScalar (Get-Field $Data 'DeliveryContext')
        TargetsSelected = @((Get-ArrayValue (Get-Field $Data 'TargetsSelected')) | ForEach-Object { Convert-ReportScalar $_ })
        EventLogError   = Convert-ReportScalar (Get-Field $Data 'EventLogError')
        ScreenConnect   = [ordered]@{
            Instances   = @($instances)
            ParseIssues = @($parseIssues)
            Historical  = @($historical)
        }
        OtherTargets    = @($otherTargets)
        RawEvidenceIncluded = $false
    }
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}

function New-HumanSummary {
    param([object]$Report)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    [void]$lines.Add('Report type: ' + [string](Get-Field $Report 'ReportType'))
    [void]$lines.Add('Generated UTC: ' + [string](Get-Field $Report 'GeneratedUtc'))
    [void]$lines.Add('Computer: ' + [string](Get-Field $Report 'ComputerName'))
    [void]$lines.Add('Delivery context: ' + [string](Get-Field $Report 'DeliveryContext'))
    [void]$lines.Add('')
    $screen = Get-Field $Report 'ScreenConnect'
    foreach ($instance in @(Get-ArrayValue (Get-Field $screen 'Instances'))) {
        [void]$lines.Add('ScreenConnect thumbprint: ' + [string](Get-Field $instance 'Identifier'))
        [void]$lines.Add('  Relay/server address: ' + [string](Get-Field $instance 'RelayHost') + ':' + [string](Get-Field $instance 'RelayPort'))
        [void]$lines.Add('  Version: ' + [string](Get-Field $instance 'DisplayVersion'))
        foreach ($file in @(Get-ArrayValue (Get-Field $instance 'Files'))) {
            [void]$lines.Add('  File: ' + [string](Get-Field $file 'Path') + ' [' + [string](Get-Field $file 'SignatureStatus') + ']')
        }
        foreach ($connection in @(Get-ArrayValue (Get-Field $instance 'Connections'))) {
            [void]$lines.Add('  Connection: ' + [string](Get-Field $connection 'RemoteAddress') + ':' + [string](Get-Field $connection 'RemotePort') + ' [' + [string](Get-Field $connection 'State') + ']')
        }
    }
    $issues = @(Get-ArrayValue (Get-Field $screen 'ParseIssues'))
    if ($issues.Count -gt 0) {
        [void]$lines.Add('')
        [void]$lines.Add('Parse issues: ' + [string]$issues.Count)
        foreach ($issue in $issues) { [void]$lines.Add('  ' + [string](Get-Field $issue 'Issue')) }
    }
    return ($lines -join "`r`n") + "`r`n"
}

function Get-DefaultTokenFile {
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        return (Join-Path $env:ProgramData 'ScreenConnectCleanup\report-relay-token.txt')
    }
    return $null
}

function Get-UploadToken {
    $token = $ReportUploadToken
    if ([string]::IsNullOrWhiteSpace($token)) { $token = $env:SCREENCONNECT_REPORT_UPLOAD_TOKEN }
    if ([string]::IsNullOrWhiteSpace($token)) {
        $explicitTokenFile = -not [string]::IsNullOrWhiteSpace($ReportUploadTokenFile)
        if ($explicitTokenFile) {
            $tokenPath = $ReportUploadTokenFile
        } else {
            $tokenPath = Get-DefaultTokenFile
        }
        if (-not [string]::IsNullOrWhiteSpace($tokenPath)) {
            if (Test-Path -LiteralPath $tokenPath -PathType Leaf) {
                try {
                    $token = [System.IO.File]::ReadAllText($tokenPath)
                } catch {
                    # An explicitly supplied token file that cannot be read is an
                    # operator error and must fail loudly. An implicit default
                    # token file that cannot be read also fails with a clear
                    # message instead of a raw IO exception.
                    throw ('report upload token file could not be read: ' + $tokenPath)
                }
            } elseif ($explicitTokenFile) {
                # An explicitly requested token file that is missing means the
                # operator intended an upload; this is not an implicit
                # no-enrollment state and must not silently skip the upload.
                throw ('report upload token file was not found: ' + $tokenPath)
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($token)) { return $null }
    $token = $token.Trim()
    if ($token -notmatch '^[A-Za-z0-9._~+/=-]{20,512}$') {
        throw 'report upload token has an invalid format'
    }
    return $token
}

function New-DeterministicPackage {
    param(
        [string]$StageDir,
        [string]$Destination
    )
    # Build the ZIP with a fixed entry timestamp and a fixed entry order so that
    # re-runs over identical findings produce byte-identical packages. The relay
    # deduplicates by the SHA-256 of the received body, so a stable package is
    # what makes retries idempotent across separate runs.
    $fixedTime = New-Object System.DateTimeOffset -ArgumentList 2020, 1, 1, 0, 0, 0, ([TimeSpan]::Zero)
    $entryNames = @('connectwise-report.json', 'connectwise-report.txt', 'package-manifest.json')
    $archive = [System.IO.Compression.ZipFile]::Open($Destination, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $entryNames) {
            $sourcePath = Join-Path $StageDir $name
            if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
                throw ('package entry is missing: ' + $name)
            }
            $entry = $archive.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $fixedTime
            $source = [System.IO.File]::OpenRead($sourcePath)
            try {
                $target = $entry.Open()
                try {
                    $buffer = New-Object byte[] 65536
                    while ($true) {
                        $read = $source.Read($buffer, 0, $buffer.Length)
                        if ($read -le 0) { break }
                        $target.Write($buffer, 0, $read)
                    }
                } finally {
                    $target.Dispose()
                }
            } finally {
                $source.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }
}

function Test-RetryableUploadFailure {
    param($Exception)
    # True only when the attempt may have failed before the relay could store
    # the body (transport error, timeout) or when the relay itself reported a
    # server-side error (HTTP 5xx). Re-sending the exact same package for those
    # cases is safe because the relay deduplicates by the SHA-256 of the received
    # body. Client errors (HTTP 4xx) and invalid receipts after a 2xx response
    # are deterministic and are never retried.
    $responseProperty = $Exception.PSObject.Properties['Response']
    $response = $null
    if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
        $response = $responseProperty.Value
    }
    if ($null -ne $response) {
        try {
            return ([int]$response.StatusCode -ge 500)
        } catch {
            return $false
        }
    }
    switch -Wildcard ($Exception.GetType().FullName) {
        'System.Net.WebException' { return $true }
        'System.Net.Http.HttpRequestException' { return $true }
        '*TaskCanceledException' { return $true }
        'System.TimeoutException' { return $true }
        'System.Net.Sockets.SocketException' { return $true }
        default { return $false }
    }
}

function Invoke-ReportUploadWithRetry {
    param(
        [string]$Path,
        [string]$Token,
        [string]$Uri,
        [string]$Digest
    )
    # Bounded retry of the SAME package file. Each attempt sends the identical
    # bytes and digest, so a lost acknowledgement that was actually stored
    # becomes an idempotent already_stored on the relay instead of a duplicate.
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            return Invoke-ReportUpload -Path $Path -Token $Token -Uri $Uri -Digest $Digest
        } catch {
            $lastError = $_
            if ($attempt -ge $maxAttempts -or -not (Test-RetryableUploadFailure $lastError.Exception)) {
                throw
            }
            Write-Host ('REPORT UPLOAD: attempt ' + $attempt + ' of ' + $maxAttempts + ' failed (' + $lastError.Exception.Message + ') - retrying with the same package')
            Start-Sleep -Seconds (2 * $attempt)
        }
    }
}

function Invoke-ReportUpload {
    param(
        [string]$Path,
        [string]$Token,
        [string]$Uri,
        [string]$Digest
    )
    $parsedUri = $null
    if (-not [System.Uri]::TryCreate($Uri, [System.UriKind]::Absolute, [ref]$parsedUri)) {
        throw 'report relay URL is not an absolute URI'
    }
    if ($parsedUri.Scheme -ne 'https' -and -not $AllowInsecureRelay) {
        throw 'report relay must use HTTPS (use -AllowInsecureRelay only for local tests)'
    }
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch { }
    $headers = @{
        Authorization       = 'Bearer ' + $Token
        'X-Report-Filename' = [System.IO.Path]::GetFileName($Path)
        'X-Report-SHA256'   = $Digest
    }
    $response = Invoke-WebRequest -Uri $Uri -Method Post -InFile $Path -ContentType 'application/zip' -Headers $headers -UseBasicParsing -TimeoutSec 120
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        throw ('report relay returned HTTP ' + [string]$response.StatusCode)
    }
    $receipt = $response.Content | ConvertFrom-Json
    if ($null -eq $receipt -or [string]$receipt.status -notin @('stored', 'already_stored')) {
        throw 'report relay returned an invalid receipt'
    }
    if ([string]$receipt.sha256 -ne $Digest) {
        throw 'report relay receipt hash does not match the local package'
    }
    if ([string]$receipt.receipt_id -notmatch '^[0-9a-f]{32}$') {
        throw 'report relay receipt identifier is invalid'
    }
    return $receipt
}

$exitCode = 0
try {
    if (-not (Test-Path -LiteralPath $FindingsJson -PathType Leaf)) { throw 'findings JSON was not found' }
    if (-not (Test-Path -LiteralPath $WorkDir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $WorkDir -Force
    }
    $findingsFullPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $FindingsJson).Path)
    $workFullPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $WorkDir).Path)
    $data = [System.IO.File]::ReadAllText($findingsFullPath) | ConvertFrom-Json
    if ($null -eq $data) { throw 'findings JSON was empty' }
    $report = New-SafeReport $data
    $reportJson = $report | ConvertTo-Json -Depth 20
    $sourceHash = (Get-FileHash -LiteralPath $findingsFullPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $script:StageDir = Join-Path $workFullPath ('connectwise-report-stage-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $script:StageDir -Force
    Write-Utf8NoBom (Join-Path $script:StageDir 'connectwise-report.json') ($reportJson + "`r`n")
    Write-Utf8NoBom (Join-Path $script:StageDir 'connectwise-report.txt') (New-HumanSummary $report)
    $manifest = [ordered]@{
        SchemaVersion        = 1
        ReportType           = 'Potential malicious or fraudulent ScreenConnect activity'
        SourceFindings       = 'findings.json'
        SourceFindingsSHA256 = $sourceHash
        RawEvidenceIncluded  = $false
        Contents             = @('connectwise-report.json', 'connectwise-report.txt', 'package-manifest.json')
    }
    Write-Utf8NoBom (Join-Path $script:StageDir 'package-manifest.json') (($manifest | ConvertTo-Json -Depth 8) + "`r`n")

    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $script:PackagePath = Join-Path $workFullPath 'connectwise-report.zip'
    if (Test-Path -LiteralPath $script:PackagePath) {
        $script:PackagePath = Join-Path $workFullPath ('connectwise-report-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.zip')
    }
    $temporaryZip = $script:PackagePath + '.tmp'
    New-DeterministicPackage -StageDir $script:StageDir -Destination $temporaryZip
    Move-Item -LiteralPath $temporaryZip -Destination $script:PackagePath
    $localDigest = (Get-FileHash -LiteralPath $script:PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ('REPORT PACKAGE: ' + $script:PackagePath)
    Write-Host ('REPORT PACKAGE SHA256: ' + $localDigest)

    if ($NoUpload) {
        Write-Host 'REPORT UPLOAD: disabled by operator'
    } else {
        $token = Get-UploadToken
        if ([string]::IsNullOrWhiteSpace($token)) {
            Write-Host 'REPORT UPLOAD: skipped; no authenticated relay token is configured'
        } else {
            $receipt = Invoke-ReportUploadWithRetry -Path $script:PackagePath -Token $token -Uri $RelayUrl -Digest $localDigest
            Write-Host ('REPORT UPLOAD: ' + [string]$receipt.status + '; receipt ' + [string]$receipt.receipt_id)
        }
    }
} catch {
    Write-Host ('REPORT UPLOAD FAILED: ' + $_.Exception.Message) -ForegroundColor Red
    $exitCode = 1
} finally {
    if ($script:StageDir -and (Test-Path -LiteralPath $script:StageDir)) {
        Remove-Item -LiteralPath $script:StageDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $temporaryZipPath = $null
    if ($script:PackagePath) { $temporaryZipPath = $script:PackagePath + '.tmp' }
    if ($temporaryZipPath -and (Test-Path -LiteralPath $temporaryZipPath)) {
        Remove-Item -LiteralPath $temporaryZipPath -Force -ErrorAction SilentlyContinue
    }
}
exit $exitCode
