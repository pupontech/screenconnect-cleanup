# Submit-ConnectWiseReport.ps1 - create a sanitized local report package and
# share it to MicroBin.
# PowerShell 5.1 compatible. Raw evidence and credential-bearing fields are not
# included in the package. The local connectwise-report.zip stays in the run
# root as an archive; the ONLY share path is a MicroBin paste of the sanitized
# report JSON (server base URL from -MicroBinUrl, falling back to the first
# nonblank line of microbin-url.txt beside this script). MicroBin is never a
# ConnectWise submission. A failed share fails loudly but keeps the local
# package; -NoUpload disables the share. After a successful MicroBin share the
# paste URL is shown at the top of the generated HTML report with HTML
# escaping; a failed upload never touches the report, and a report path that is
# missing or malformed fails loudly.
#
# The report carries incident context (Authorization and Delivery) from explicit
# uploader parameters or existing findings, and, per
# ScreenConnect instance, the best observed installation date with its basis.
# The date is derived from the detector's own evidence with fixed precedence
# (service-install event 7045 timestamp, then install-directory creation time,
# then registry InstallDate) and says 'Not available' when there is no
# evidence; nothing is invented, and raw event/config content stays out.
[CmdletBinding()]
param(
    [string]$FindingsJson,
    [string]$WorkDir,
    [string]$RunPath = '',
    # Optional path to the generated HTML report (report.html). After a
    # successful MicroBin upload the paste URL is HTML-escaped and shown at
    # the top of this file. If omitted, use an existing report.html in the
    # resolved run root. A failed upload never annotates either report.
    [string]$ReportHtml = '',
    [string]$ResultsJson = '',
    [string]$DiffJson = '',
    [string]$MicroBinUrl = '',
    [string]$MicroBinUploaderPasswordFile = '',
    # Optional operator-recorded context for direct invocations. When absent,
    # the report falls back to
    # context already present in the findings and finally to 'Not available';
    # it never guesses. Explicit values are validated to a closed set.
    [string]$IncidentAuthorization = '',
    [string]$IncidentDelivery = '',
    [switch]$NoUpload,
    [switch]$AllowInsecureRelay
)

$ErrorActionPreference = 'Stop'
$script:PackagePath = $null
$script:StageDir = $null

# ---------------------------------------------------------------------------
# Incident-context constants. The closed sets are shared by convention with
# Resolve-IncidentContext.ps1 (the guided-run prompt) - keep both in step.
# 'Not available' is also the honest absence marker for the per-instance
# observed install date.
# ---------------------------------------------------------------------------
$script:NotAvailable               = 'Not available'
$script:AuthorizationAuthorized    = 'Authorized'
$script:AuthorizationNotAuthorized = 'Not authorized'
$script:DeliveryEmailInviteScam    = 'Email invite scam'
$script:DeliveryOtherPrefix        = 'Other: '
$script:OtherLabelMaxLength        = 80
$script:ContextForbiddenChars      = @('"', '%', '!', '&', '|', '<', '>', '^', '(', ')')

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

function Assert-ContextLabel {
    param([string]$Label)
    # Shared by convention with Resolve-IncidentContext.ps1: a description
    # must be short, printable ASCII, and free of characters that are unsafe
    # on a batch command line. Throws so an invalid explicit value fails
    # loudly before any package is built.
    if ([string]::IsNullOrWhiteSpace($Label)) { throw 'incident context description must not be blank' }
    $clean = $Label.Trim()
    if ($clean.Length -gt $script:OtherLabelMaxLength) {
        throw ('incident context description must be at most ' + $script:OtherLabelMaxLength + ' characters')
    }
    foreach ($ch in $clean.ToCharArray()) {
        $code = [int]$ch
        if ($code -lt 0x20 -or $code -gt 0x7E) { throw 'incident context description must be printable ASCII' }
        if ($script:ContextForbiddenChars -contains ([string]$ch)) {
            throw 'incident context description contains a character that is not allowed'
        }
    }
    return $clean
}

function Assert-IncidentAuthorization {
    param([string]$Value)
    $v = ([string]$Value).Trim()
    if ($v -eq $script:AuthorizationNotAuthorized -or $v -eq $script:AuthorizationAuthorized) { return $v }
    throw 'incident authorization must be exactly "Authorized" or "Not authorized"'
}

function Assert-IncidentDelivery {
    param([string]$Value)
    $v = ([string]$Value).Trim()
    if ($v -eq $script:DeliveryEmailInviteScam) { return $v }
    if ($v.StartsWith($script:DeliveryOtherPrefix, [System.StringComparison]::Ordinal)) {
        $label = $v.Substring($script:DeliveryOtherPrefix.Length)
        $clean = Assert-ContextLabel -Label $label
        return $script:DeliveryOtherPrefix + $clean
    }
    throw 'incident delivery must be "Email invite scam" or "Other: <short printable-ASCII description>"'
}

function Resolve-IncidentContextValue {
    param([string]$Explicit, [object]$FindingsValue)
    # An operator-supplied (already validated) value wins; otherwise context
    # already present in the findings is carried through; otherwise the report
    # honestly says 'Not available' instead of guessing. Raw event messages
    # and config content never reach these fields.
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) { return $Explicit.Trim() }
    if ($null -ne $FindingsValue) {
        $fallback = ([string]$FindingsValue).Trim()
        if ($fallback.Length -gt 0) { return $fallback }
    }
    return $script:NotAvailable
}

function Get-ObservedInstallDate {
    param([object]$Instance)
    # Best observed installation date from the detector's existing evidence.
    # Precedence: (1) the earliest matching Windows service-install event 7045
    # timestamp, (2) the install-directory creation time, (3) the registry
    # InstallDate (the Windows uninstall YYYYMMDD value). Only scalars are
    # read - raw event message text is never copied - and absence reports
    # 'Not available' instead of inventing a date.
    $observed = $null
    $basis = $null
    foreach ($evt in @(Get-ArrayValue (Get-Field $Instance 'ServiceInstallEvents'))) {
        $t = ([string](Get-Field $evt 'TimeUtc')).Trim()
        if ($t -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$') {
            if ($null -eq $observed -or [string]::CompareOrdinal($t, $observed) -lt 0) {
                $observed = $t
                $basis = 'Windows service-install event 7045'
            }
        }
    }
    if ($null -eq $observed) {
        $dirCreated = ([string](Get-Field $Instance 'InstallDirCreatedUtc')).Trim()
        if ($dirCreated -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$') {
            $observed = $dirCreated
            $basis = 'Install-directory creation time'
        }
    }
    if ($null -eq $observed) {
        $regDate = ([string](Get-Field $Instance 'InstallDate')).Trim()
        if ($regDate -match '^\d{8}$') {
            $observed = $regDate.Substring(0, 4) + '-' + $regDate.Substring(4, 2) + '-' + $regDate.Substring(6, 2)
            $basis = 'Registry InstallDate'
        }
    }
    if ($null -eq $observed) { $observed = $script:NotAvailable }
    if ($null -eq $basis) { $basis = $script:NotAvailable }
    return [pscustomobject]@{ Observed = $observed; Basis = $basis }
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

    $installDate = Get-ObservedInstallDate $Instance

    return [ordered]@{
        Identifier          = Convert-ReportScalar (Get-Field $Instance 'Identifier')
        Thumbprint          = Convert-ReportScalar (Get-Field $Instance 'Identifier')
        RelayHost           = Convert-ReportScalar (Get-Field $Instance 'RelayHost')
        RelayPort           = Convert-ReportScalar (Get-Field $Instance 'RelayPort')
        SessionType         = Convert-ReportScalar (Get-Field $Instance 'SessionType')
        Role                = Convert-ReportScalar (Get-Field $Instance 'Role')
        DisplayVersion      = Convert-ReportScalar (Get-Field $Instance 'DisplayVersion')
        Publisher           = Convert-ReportScalar (Get-Field $Instance 'Publisher')
        ServiceName         = Convert-ReportScalar (Get-Field $Instance 'ServiceName')
        InstallPath         = Convert-ReportPath (Get-Field $Instance 'InstallDir')
        InstallDateObserved = $installDate.Observed
        InstallDateBasis    = $installDate.Basis
        Files               = @($safeFiles)
        Connections         = @($safeConnections)
        UnknownParamKeys    = @($unknownKeys)
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

    $contextAuthorization = Resolve-IncidentContextValue $IncidentAuthorization (Get-Field $Data 'Authorization')
    $contextDelivery = Resolve-IncidentContextValue $IncidentDelivery (Get-Field $Data 'DeliveryContext')

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
        SchemaVersion   = 2
        ReportType      = 'Potential malicious or fraudulent ScreenConnect activity'
        GeneratedUtc    = Convert-ReportScalar (Get-Field $Data 'GeneratedUtc')
        ToolVersion     = Convert-ReportScalar (Get-Field $Data 'Version')
        RunId           = Convert-ReportScalar (Get-Field $Data 'RunId')
        ComputerName    = Convert-ReportScalar (Get-Field $Data 'ComputerName')
        OSCaption       = Convert-ReportScalar (Get-Field $Data 'OSCaption')
        IncidentContext = [ordered]@{
            Authorization = $contextAuthorization
            Delivery      = $contextDelivery
        }
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
    $incidentContext = Get-Field $Report 'IncidentContext'
    [void]$lines.Add('Incident authorization: ' + [string](Get-Field $incidentContext 'Authorization'))
    [void]$lines.Add('Incident delivery: ' + [string](Get-Field $incidentContext 'Delivery'))
    [void]$lines.Add('')
    $screen = Get-Field $Report 'ScreenConnect'
    foreach ($instance in @(Get-ArrayValue (Get-Field $screen 'Instances'))) {
        [void]$lines.Add('ScreenConnect thumbprint: ' + [string](Get-Field $instance 'Identifier'))
        [void]$lines.Add('  Relay/server address: ' + [string](Get-Field $instance 'RelayHost') + ':' + [string](Get-Field $instance 'RelayPort'))
        [void]$lines.Add('  Version: ' + [string](Get-Field $instance 'DisplayVersion'))
        $installDateObserved = [string](Get-Field $instance 'InstallDateObserved')
        $installDateBasis = [string](Get-Field $instance 'InstallDateBasis')
        if ($installDateObserved -eq $script:NotAvailable) {
            [void]$lines.Add('  Install date observed: Not available')
        } else {
            [void]$lines.Add('  Install date observed: ' + $installDateObserved + ' (' + $installDateBasis + ')')
        }
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

function New-DeterministicPackage {
    param(
        [string]$StageDir,
        [string]$Destination
    )
    # Build the ZIP with a fixed entry timestamp and a fixed entry order so that
    # re-runs over identical findings produce byte-identical packages.
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

# ---------------------------------------------------------------------------
# MicroBin upload mode (the only report share path)
# ---------------------------------------------------------------------------
# MicroBin (https://github.com/szabodanika/microbin) exposes a multipart text
# upload at POST /upload. Current endpoint (master, 2026-06): recognized form
# fields are content, privacy, expiration, plain_key, random_key,
# encrypted_random_key, burn_after, syntax_highlight, uploader_password and
# file. privacy is a single selector (public / unlisted / readonly / private /
# secret); there is no separate readonly boolean. privacy=readonly creates a
# paste that is not publicly listed and cannot be edited, and is only honored
# when the server enables readonly (MICROBIN_ENABLE_READONLY); on other servers
# the same value degrades to an unlisted, unencrypted paste. privacy=private
# would switch on server-side encryption, which requires a key shared out of
# band, so a zero-fuss report share must not use it. A successful create
# answers with a 3xx whose Location is {path}/upload/<id> (or
# {path}/auth/<id>/success); a wrong uploader password on a read-only server
# answers with a redirect to {path}/incorrect instead. Expiration values are
# the bounded tokens 1min..16years plus never; "never" is refused here so a
# configured dropbox always expires the report.
$script:MicroBinExpiration = '1week'
$script:MicroBinBodyCap = 16384
$script:MicroBinBoundaryPrefix = '--------------------------ScreenConnectCleanup'

function Get-ConfiguredMicroBinUrl {
    # Fallback server base URL for the report share: when -MicroBinUrl is not
    # given, read the first nonblank trimmed line of microbin-url.txt beside
    # this script (the file the deploy bundle ships and the guided runner
    # used to maintain). A missing or empty file means no share is attempted.
    if (-not [string]::IsNullOrWhiteSpace($MicroBinUrl)) { return $MicroBinUrl.Trim() }
    $configFile = Join-Path $PSScriptRoot 'microbin-url.txt'
    if (-not (Test-Path -LiteralPath $configFile -PathType Leaf)) { return '' }
    foreach ($line in [System.IO.File]::ReadLines($configFile)) {
        $candidate = $line.Trim()
        if ($candidate.Length -gt 0) { return $candidate }
    }
    return ''
}

function Get-MicroBinUploaderPassword {
    # Returns the MicroBin uploader password when the operator configured one:
    # -MicroBinUploaderPasswordFile first, then the
    # SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD environment variable. The value
    # is never written to the console, logs, or error text, and is only sent
    # inside the multipart body over the validated transport.
    $password = ''
    $explicitFile = -not [string]::IsNullOrWhiteSpace($MicroBinUploaderPasswordFile)
    if ($explicitFile) {
        if (-not (Test-Path -LiteralPath $MicroBinUploaderPasswordFile -PathType Leaf)) {
            throw ('MicroBin uploader password file was not found: ' + $MicroBinUploaderPasswordFile)
        }
        $password = [System.IO.File]::ReadAllText($MicroBinUploaderPasswordFile)
        if ([string]::IsNullOrWhiteSpace($password)) {
            throw ('MicroBin uploader password file is empty: ' + $MicroBinUploaderPasswordFile)
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($env:SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD)) {
        $password = $env:SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD
    }
    return $password.Trim()
}

function Get-MicroBinUploadTarget {
    param([string]$Url)
    $parsedUri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$parsedUri)) {
        throw 'MicroBin URL is not an absolute URI'
    }
    if ($parsedUri.Scheme -ne 'https' -and -not $AllowInsecureRelay) {
        throw 'MicroBin target must use HTTPS (use -AllowInsecureRelay only for local tests)'
    }
    if ($parsedUri.Scheme -notin @('https', 'http')) {
        throw 'MicroBin URL must use http or https'
    }
    if (-not [string]::IsNullOrEmpty($parsedUri.UserInfo)) {
        throw 'MicroBin URL must not contain embedded credentials'
    }
    $base = $Url.Trim().TrimEnd('/')
    if ($base -match '(?i)/upload$') {
        $uploadUri = $base
    } else {
        $uploadUri = $base + '/upload'
    }
    return [pscustomobject]@{
        UploadUri = $uploadUri
        Origin    = $parsedUri.GetLeftPart([System.UriPartial]::Authority)
        Scheme    = $parsedUri.Scheme
        Authority = $parsedUri.Authority
    }
}

function New-MicroBinMultipartBody {
    param([string]$Content, [string]$Password, [string]$Boundary)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    [void]$parts.Add('--' + $Boundary)
    [void]$parts.Add('Content-Disposition: form-data; name="content"')
    [void]$parts.Add('')
    [void]$parts.Add($Content)
    [void]$parts.Add('--' + $Boundary)
    [void]$parts.Add('Content-Disposition: form-data; name="privacy"')
    [void]$parts.Add('')
    [void]$parts.Add('readonly')
    [void]$parts.Add('--' + $Boundary)
    [void]$parts.Add('Content-Disposition: form-data; name="expiration"')
    [void]$parts.Add('')
    [void]$parts.Add($script:MicroBinExpiration)
    if (-not [string]::IsNullOrEmpty($Password)) {
        [void]$parts.Add('--' + $Boundary)
        [void]$parts.Add('Content-Disposition: form-data; name="uploader_password"')
        [void]$parts.Add('')
        [void]$parts.Add($Password)
    }
    [void]$parts.Add('--' + $Boundary + '--')
    [void]$parts.Add('')
    $bodyText = ($parts -join "`r`n")
    return [System.Text.Encoding]::UTF8.GetBytes($bodyText)
}

function Read-MicroBinErrorBody {
    param($Response)
    # Bounded read of a non-2xx/3xx body for diagnostics only; never buffers
    # more than the cap even if the server streams an unbounded page.
    $text = ''
    try {
        $stream = $Response.GetResponseStream()
        if ($null -eq $stream) { return '' }
        $buffer = New-Object byte[] 8192
        $memory = New-Object System.IO.MemoryStream
        $readTotal = 0
        while ($readTotal -lt $script:MicroBinBodyCap) {
            $remaining = $script:MicroBinBodyCap - $readTotal
            $chunkSize = $buffer.Length
            if ($remaining -lt $chunkSize) { $chunkSize = $remaining }
            $read = $stream.Read($buffer, 0, $chunkSize)
            if ($read -le 0) { break }
            $memory.Write($buffer, 0, $read)
            $readTotal += $read
        }
        $text = [System.Text.Encoding]::UTF8.GetString($memory.ToArray())
        $memory.Dispose()
    } catch {
        $text = ''
    }
    $text = $text -replace '[^\x20-\x7E]+', ' '
    $text = $text.Trim()
    if ($text.Length -gt 300) { $text = $text.Substring(0, 300) }
    return $text
}

function Invoke-MicroBinCreate {
    param([string]$Content, [string]$Password)
    $target = Get-MicroBinUploadTarget $MicroBinUrl
    $boundary = $script:MicroBinBoundaryPrefix + [guid]::NewGuid().ToString('N')
    $body = New-MicroBinMultipartBody -Content $Content -Password $Password -Boundary $boundary
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch { }
    $request = [System.Net.HttpWebRequest]::Create($target.UploadUri)
    $request.Method = 'POST'
    $request.AllowAutoRedirect = $false
    $request.ContentType = 'multipart/form-data; boundary=' + $boundary
    $request.ContentLength = $body.Length
    $request.Timeout = 30000
    $request.ReadWriteTimeout = 30000
    $requestStream = $request.GetRequestStream()
    try { $requestStream.Write($body, 0, $body.Length) } finally { $requestStream.Dispose() }
    $response = $null
    try {
        $response = $request.GetResponse()
    } catch [System.Net.WebException] {
        # With AllowAutoRedirect=$false a 3xx response is returned normally;
        # HTTP error statuses (4xx/5xx) surface as a WebException that still
        # carries the response we need to inspect. Redirects are never
        # followed, so no Location from a later hop can be trusted.
        if ($null -eq $_.Exception.Response) {
            throw ('MicroBin server request failed: ' + $_.Exception.Message)
        }
        $response = $_.Exception.Response
    }
    try {
        $statusCode = [int]$response.StatusCode
        $location = [string]$response.Headers['Location']
        $errorBody = ''
        if ($statusCode -ge 400) { $errorBody = Read-MicroBinErrorBody $response }
        return [pscustomobject]@{
            StatusCode = $statusCode
            Location   = $location
            ErrorBody  = $errorBody
            Target     = $target
        }
    } finally {
        $response.Dispose()
    }
}

function Convert-MicroBinLocationToPasteUrl {
    param([object]$Result)
    $loc = [string]$Result.Location
    $target = $Result.Target
    if ([string]::IsNullOrWhiteSpace($loc)) {
        throw ('MicroBin responded with HTTP ' + [string]$Result.StatusCode + ' but no Location header was present')
    }
    $loc = $loc.Trim()
    $path = ''
    if ($loc -match '^[A-Za-z][A-Za-z0-9+.-]*://') {
        # Absolute URL. NOTE: Uri.TryCreate(Absolute) on .NET Core turns a
        # rooted path like /upload/x into a file:// URI, so an explicit scheme
        # check must gate the absolute branch.
        $parsed = $null
        if (-not [System.Uri]::TryCreate($loc, [System.UriKind]::Absolute, [ref]$parsed)) {
            throw 'MicroBin Location header is not a valid URL'
        }
        if ($parsed.Scheme -ne $target.Scheme -or -not [string]::Equals($parsed.Authority, $target.Authority, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'MicroBin redirect Location points to a different origin; it was not followed or reported'
        }
        $path = $parsed.AbsolutePath
        $isAbsolute = $true
    } else {
        if (-not $loc.StartsWith('/')) {
            throw 'MicroBin Location header is neither an absolute URL nor a site-relative path'
        }
        $questionIndex = $loc.IndexOf('?')
        $path = $loc
        if ($questionIndex -ge 0) { $path = $loc.Substring(0, $questionIndex) }
        $isAbsolute = $false
    }
    $path = $path.TrimEnd('/')
    if ($path -match '/incorrect$') {
        throw 'MicroBin rejected the uploader credentials (redirected to /incorrect); check -MicroBinUploaderPasswordFile or the SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD environment variable'
    }
    if ($path -notmatch '/(upload|auth)/[A-Za-z0-9_-]+(/success)?$') {
        throw ('MicroBin Location does not look like a paste URL: ' + $path)
    }
    if ($isAbsolute) { return $parsed.AbsoluteUri.TrimEnd('/') }
    return $target.Origin + $path
}

function Invoke-MicroBinUpload {
    param([string]$Content, [string]$Password)
    $result = Invoke-MicroBinCreate -Content $Content -Password $Password
    if ($result.StatusCode -lt 200 -or $result.StatusCode -ge 400) {
        $detail = ''
        if (-not [string]::IsNullOrWhiteSpace($result.ErrorBody)) { $detail = ' - ' + $result.ErrorBody }
        throw ('MicroBin returned HTTP ' + [string]$result.StatusCode + $detail)
    }
    return (Convert-MicroBinLocationToPasteUrl $result)
}

function ConvertTo-HtmlEscapedText {
    # HTML-escapes a value before it is embedded in the generated HTML
    # report. Same substitutions (and order) as Encode-Html in
    # New-InvestigationReport.ps1, so a paste URL can never close an
    # attribute or inject markup. Pure ASCII, PowerShell 5.1 compatible.
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s.Replace('&', '&amp;')
    $s = $s.Replace('<', '&lt;')
    $s = $s.Replace('>', '&gt;')
    $s = $s.Replace('"', '&quot;')
    $s = $s.Replace("'", '&#39;')
    return $s
}

function Add-ReportPasteLink {
    # Put the returned URL in a visible banner at the top after upload. Replace
    # our previous annotation without removing other report content. The caller
    # resolves the explicit or default run-root report; a missing or malformed
    # selected report fails loudly instead of silently skipping the annotation.
    param(
        [string]$ReportHtml,
        [string]$PasteUrl
    )
    if ([string]::IsNullOrWhiteSpace($ReportHtml)) { return }
    if ([string]::IsNullOrWhiteSpace($PasteUrl)) { throw 'a MicroBin paste URL is required to annotate the HTML report' }
    if (-not (Test-Path -LiteralPath $ReportHtml -PathType Leaf)) { throw ('report HTML was not found: ' + $ReportHtml) }
    $fullPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $ReportHtml).Path)
    $html = [System.IO.File]::ReadAllText($fullPath)
    if ([string]::IsNullOrEmpty($html)) { throw ('report HTML is empty: ' + $fullPath) }
    $escapedUrl = ConvertTo-HtmlEscapedText $PasteUrl
    $newline = "`r`n"
    if ($html.IndexOf("`r`n") -lt 0) { $newline = "`n" }
    $linkBlock = $newline +
        '<!-- ScreenConnect Cleanup: sanitized MicroBin paste of this report (added after a successful upload). -->' + $newline +
        '<p id="scc-microbin-paste" style="margin:1em 0;padding:1em;border:2px solid #2563eb;background:#eff6ff;color:#111827;overflow-wrap:anywhere;">Sanitized paste (MicroBin): <a href="' + $escapedUrl + '">' + $escapedUrl + '</a></p>'
    $bodyIndex = $html.LastIndexOf('</body>', [System.StringComparison]::OrdinalIgnoreCase)
    if ($bodyIndex -lt 0) {
        throw ('report HTML has no closing </body> marker; the paste link was not added: ' + $fullPath)
    }
    $bodyOpen = [regex]::Match($html, '(?i)<body\b[^>]*>')
    if (-not $bodyOpen.Success -or $bodyOpen.Index -ge $bodyIndex) {
        throw ('report HTML has no opening <body> marker; the paste link was not added: ' + $fullPath)
    }
    # Replace only our own annotation paragraph, including the older footer
    # form. Do not remove arbitrary links or any of the investigation content.
    $annotationComment = '<!-- ScreenConnect Cleanup: sanitized MicroBin paste of this report (added after a successful upload). -->'
    $annotationPattern = '(?:\r?\n)?' + [regex]::Escape($annotationComment) + '\s*<p\b[^>]*>Sanitized paste \(MicroBin\): <a href="[^"]*">[^<]*</a></p>(?:\r?\n)?'
    $html = [regex]::Replace($html, $annotationPattern, '')
    $bodyOpen = [regex]::Match($html, '(?i)<body\b[^>]*>')
    $html = $html.Insert($bodyOpen.Index + $bodyOpen.Length, $linkBlock + $newline)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fullPath, $html, $utf8NoBom)
}

$exitCode = 0
try {
    # Explicit incident-context values are validated before any work: an
    # invalid value means a broken caller and must fail loudly rather than
    # silently reaching the report.
    if (-not [string]::IsNullOrWhiteSpace($IncidentAuthorization)) {
        $null = Assert-IncidentAuthorization $IncidentAuthorization
    }
    if (-not [string]::IsNullOrWhiteSpace($IncidentDelivery)) {
        $null = Assert-IncidentDelivery $IncidentDelivery
    }
    # Input resolution: -RunPath finds the run root's findings.json the same
    # way the guided runner does, so operators never need to hunt for it.
    # An explicit -FindingsJson/-WorkDir pair keeps the historical contract.
    if (-not [string]::IsNullOrWhiteSpace($RunPath)) {
        if (-not (Test-Path -LiteralPath $RunPath -PathType Container)) { throw ('run path was not found: ' + $RunPath) }
        $runPathFull = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $RunPath).Path)
        if ([string]::IsNullOrWhiteSpace($FindingsJson)) {
            $candidates = New-Object 'System.Collections.Generic.List[string]'
            $directCandidate = Join-Path $runPathFull 'findings.json'
            if (Test-Path -LiteralPath $directCandidate -PathType Leaf) { [void]$candidates.Add($directCandidate) }
            $detectRoot = Join-Path $runPathFull 'detect'
            if (Test-Path -LiteralPath $detectRoot -PathType Container) {
                foreach ($sub in (Get-ChildItem -LiteralPath $detectRoot -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
                    $subCandidate = Join-Path $sub.FullName 'findings.json'
                    if (Test-Path -LiteralPath $subCandidate -PathType Leaf) { [void]$candidates.Add($subCandidate) }
                }
            }
            if ($candidates.Count -eq 0) { throw ('no findings.json was found under the run path: ' + $runPathFull) }
            if ($candidates.Count -gt 1) { throw ('multiple findings.json files were found under the run path; pass -FindingsJson explicitly: ' + ($candidates -join '; ')) }
            $findingsFullPath = $candidates[0]
            Write-Host ('REPORT FINDINGS: ' + $findingsFullPath)
        } else {
            if (-not (Test-Path -LiteralPath $FindingsJson -PathType Leaf)) { throw 'findings JSON was not found' }
            $findingsFullPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $FindingsJson).Path)
        }
        if ([string]::IsNullOrWhiteSpace($WorkDir)) {
            $workFullPath = $runPathFull
        } else {
            if (-not (Test-Path -LiteralPath $WorkDir -PathType Container)) { $null = New-Item -ItemType Directory -Path $WorkDir -Force }
            $workFullPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $WorkDir).Path)
        }
    } else {
        if ([string]::IsNullOrWhiteSpace($FindingsJson)) { throw 'findings JSON was not specified (pass -FindingsJson, or -RunPath for a run root)' }
        if ([string]::IsNullOrWhiteSpace($WorkDir)) { throw 'work directory was not specified (pass -WorkDir, or -RunPath for a run root)' }
        if (-not (Test-Path -LiteralPath $FindingsJson -PathType Leaf)) { throw 'findings JSON was not found' }
        if (-not (Test-Path -LiteralPath $WorkDir -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $WorkDir -Force
        }
        $findingsFullPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $FindingsJson).Path)
        $workFullPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $WorkDir).Path)
    }
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
        Write-Host 'MICROBIN UPLOAD: disabled by operator'
    } else {
        # MicroBin is the only report share path. The server base URL comes
        # from -MicroBinUrl or microbin-url.txt beside this script; with no
        # configured URL the local package stays and nothing is sent anywhere.
        if ([string]::IsNullOrWhiteSpace($MicroBinUrl)) { $MicroBinUrl = Get-ConfiguredMicroBinUrl }
        if ([string]::IsNullOrWhiteSpace($MicroBinUrl)) {
            Write-Host 'MICROBIN UPLOAD: skipped; no MicroBin server URL is configured'
        } else {
            try {
                $microBinPassword = Get-MicroBinUploaderPassword
                $pasteUrl = Invoke-MicroBinUpload -Content $reportJson -Password $microBinPassword
                Write-Host ('MICROBIN UPLOAD: ' + $pasteUrl)
                # Only a successful upload reaches this point, so only a
                # successful upload can annotate the HTML report. Annotation
                # is its own loud step: a wiring problem (missing/unreadable
                # report) must not silently pass as an upload success.
                # Direct uploads should not silently omit the link merely because
                # the caller left out -ReportHtml. Only inspect this run root;
                # never guess a Desktop report or another run's latest file.
                if ([string]::IsNullOrWhiteSpace($ReportHtml)) {
                    $runReport = Join-Path $workFullPath 'report.html'
                    if (Test-Path -LiteralPath $runReport -PathType Leaf) { $ReportHtml = $runReport }
                }
                if (-not [string]::IsNullOrWhiteSpace($ReportHtml)) {
                    try {
                        Add-ReportPasteLink -ReportHtml $ReportHtml -PasteUrl $pasteUrl
                        Write-Host ('MICROBIN PASTE LINK: added to ' + $ReportHtml)
                    } catch {
                        Write-Host ('MICROBIN PASTE LINK FAILED: ' + $_.Exception.Message) -ForegroundColor Red
                        $exitCode = 1
                    }
                }
            } catch {
                Write-Host ('MICROBIN UPLOAD FAILED: ' + $_.Exception.Message) -ForegroundColor Red
                $exitCode = 1
            }
        }
    }
} catch {
    Write-Host ('REPORT FAILED: ' + $_.Exception.Message) -ForegroundColor Red
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
