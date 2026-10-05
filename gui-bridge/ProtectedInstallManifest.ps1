<#
  Pure in-memory integrity validator for the protected-install manifest.
  PowerShell 5.1 compatible. This file defines validation functions only.
  It performs no file, process, registry, elevation, install, removal, or scan work.

  The caller must obtain ExpectedManifestSha256 through a separate trusted
  channel. A matching digest does not authenticate a publisher, grant approval,
  verify protected ACLs, or establish that bytes came from a protected file.
#>

function Stop-ProtectedInstallManifestValidation {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw ('PIM_' + $Code)
}

function Skip-ProtectedInstallJsonWhitespace {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)]$State
    )
    while ($State.Index -lt $Text.Length) {
        $character = $Text[$State.Index]
        if ($character -ceq ' ' -or $character -ceq "`t" -or $character -ceq "`r" -or $character -ceq "`n") {
            $State.Index++
        } else {
            break
        }
    }
}

function Read-ProtectedInstallJsonString {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)]$State
    )
    if ($State.Index -ge $Text.Length -or $Text[$State.Index] -cne '"') {
        Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON'
    }

    $builder = New-Object System.Text.StringBuilder
    $State.Index++
    $closed = $false
    while ($State.Index -lt $Text.Length) {
        $character = $Text[$State.Index]
        if ($character -ceq '"') {
            $State.Index++
            $closed = $true
            break
        }
        if ($character -ceq '\') {
            $State.Index++
            if ($State.Index -ge $Text.Length) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            $escape = $Text[$State.Index]
            switch -CaseSensitive ($escape) {
                '"' { [void]$builder.Append([char]34) }
                '\' { [void]$builder.Append([char]92) }
                '/' { [void]$builder.Append([char]47) }
                'b' { [void]$builder.Append([char]8) }
                'f' { [void]$builder.Append([char]12) }
                'n' { [void]$builder.Append([char]10) }
                'r' { [void]$builder.Append([char]13) }
                't' { [void]$builder.Append([char]9) }
                'u' {
                    if (($State.Index + 4) -ge $Text.Length) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
                    $hex = $Text.Substring($State.Index + 1, 4)
                    if ($hex -cnotmatch '^[0-9A-Fa-f]{4}$') { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
                    [void]$builder.Append([char][Convert]::ToInt32($hex, 16))
                    $State.Index += 4
                }
                default { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            }
        } else {
            if ([int]$character -lt 0x20) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            [void]$builder.Append($character)
        }
        $State.Index++
    }
    if (-not $closed) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }

    $value = $builder.ToString()
    for ($index = 0; $index -lt $value.Length; $index++) {
        if ([char]::IsHighSurrogate($value[$index])) {
            if (($index + 1) -ge $value.Length -or -not [char]::IsLowSurrogate($value[$index + 1])) {
                Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON'
            }
            $index++
        } elseif ([char]::IsLowSurrogate($value[$index])) {
            Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON'
        }
    }
    return ,$value
}

function Assert-ProtectedInstallJsonValue {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][int]$Depth
    )
    if ($Depth -gt 16) { Stop-ProtectedInstallManifestValidation 'JSON_LIMIT' }
    $State.Nodes++
    if ($State.Nodes -gt 4096) { Stop-ProtectedInstallManifestValidation 'JSON_LIMIT' }
    Skip-ProtectedInstallJsonWhitespace -Text $Text -State $State
    if ($State.Index -ge $Text.Length) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }

    $character = $Text[$State.Index]
    if ($character -ceq '"') {
        $null = Read-ProtectedInstallJsonString -Text $Text -State $State
        return
    }
    if ($character -ceq '{') {
        $State.Index++
        Skip-ProtectedInstallJsonWhitespace -Text $Text -State $State
        if ($State.Index -lt $Text.Length -and $Text[$State.Index] -ceq '}') {
            $State.Index++
            return
        }
        $memberNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        while ($true) {
            Skip-ProtectedInstallJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length -or $Text[$State.Index] -cne '"') { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            $memberName = Read-ProtectedInstallJsonString -Text $Text -State $State
            if (-not $memberNames.Add($memberName)) { Stop-ProtectedInstallManifestValidation 'DUPLICATE_JSON_MEMBER' }
            Skip-ProtectedInstallJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length -or $Text[$State.Index] -cne ':') { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            $State.Index++
            Assert-ProtectedInstallJsonValue -Text $Text -State $State -Depth ($Depth + 1)
            Skip-ProtectedInstallJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            if ($Text[$State.Index] -ceq '}') {
                $State.Index++
                break
            }
            if ($Text[$State.Index] -cne ',') { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            $State.Index++
        }
        return
    }
    if ($character -ceq '[') {
        $State.Index++
        Skip-ProtectedInstallJsonWhitespace -Text $Text -State $State
        if ($State.Index -lt $Text.Length -and $Text[$State.Index] -ceq ']') {
            $State.Index++
            return
        }
        while ($true) {
            Assert-ProtectedInstallJsonValue -Text $Text -State $State -Depth ($Depth + 1)
            Skip-ProtectedInstallJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            if ($Text[$State.Index] -ceq ']') {
                $State.Index++
                break
            }
            if ($Text[$State.Index] -cne ',') { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
            $State.Index++
        }
        return
    }

    foreach ($literal in @('true', 'false', 'null')) {
        if (($State.Index + $literal.Length) -le $Text.Length -and $Text.Substring($State.Index, $literal.Length) -ceq $literal) {
            $State.Index += $literal.Length
            return
        }
    }

    $numberStart = $State.Index
    if ($Text[$State.Index] -ceq '-') {
        $State.Index++
        if ($State.Index -ge $Text.Length) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
    }
    if ($Text[$State.Index] -ceq '0') {
        $State.Index++
    } elseif ([int]$Text[$State.Index] -ge 49 -and [int]$Text[$State.Index] -le 57) {
        while ($State.Index -lt $Text.Length -and [int]$Text[$State.Index] -ge 48 -and [int]$Text[$State.Index] -le 57) { $State.Index++ }
    } else {
        Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON'
    }
    if ($State.Index -lt $Text.Length -and $Text[$State.Index] -ceq '.') {
        $State.Index++
        if ($State.Index -ge $Text.Length -or [int]$Text[$State.Index] -lt 48 -or [int]$Text[$State.Index] -gt 57) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
        while ($State.Index -lt $Text.Length -and [int]$Text[$State.Index] -ge 48 -and [int]$Text[$State.Index] -le 57) { $State.Index++ }
    }
    if ($State.Index -lt $Text.Length -and ($Text[$State.Index] -ceq 'e' -or $Text[$State.Index] -ceq 'E')) {
        $State.Index++
        if ($State.Index -lt $Text.Length -and ($Text[$State.Index] -ceq '+' -or $Text[$State.Index] -ceq '-')) { $State.Index++ }
        if ($State.Index -ge $Text.Length -or [int]$Text[$State.Index] -lt 48 -or [int]$Text[$State.Index] -gt 57) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
        while ($State.Index -lt $Text.Length -and [int]$Text[$State.Index] -ge 48 -and [int]$Text[$State.Index] -le 57) { $State.Index++ }
    }
    if ($State.Index -eq $numberStart) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
}

function ConvertFrom-ProtectedInstallManifestBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Bytes.Length -lt 1 -or $Bytes.Length -gt 65536) { Stop-ProtectedInstallManifestValidation 'MANIFEST_SIZE' }
    if (($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) -or
        ($Bytes.Length -ge 2 -and (($Bytes[0] -eq 255 -and $Bytes[1] -eq 254) -or ($Bytes[0] -eq 254 -and $Bytes[1] -eq 255))) -or
        ($Bytes.Length -ge 4 -and (($Bytes[0] -eq 0 -and $Bytes[1] -eq 0 -and $Bytes[2] -eq 254 -and $Bytes[3] -eq 255) -or ($Bytes[0] -eq 255 -and $Bytes[1] -eq 254 -and $Bytes[2] -eq 0 -and $Bytes[3] -eq 0)))) {
        Stop-ProtectedInstallManifestValidation 'INVALID_BOM'
    }
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $text = $encoding.GetString($Bytes)
    } catch {
        Stop-ProtectedInstallManifestValidation 'INVALID_UTF8'
    }

    $state = @{ Index = 0; Nodes = 0 }
    Assert-ProtectedInstallJsonValue -Text $text -State $state -Depth 0
    Skip-ProtectedInstallJsonWhitespace -Text $text -State $state
    if ($state.Index -ne $text.Length) { Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON' }
    try {
        $value = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    } catch {
        Stop-ProtectedInstallManifestValidation 'MALFORMED_JSON'
    }
    if ($null -eq $value -or $value -is [string] -or $value -is [System.Array] -or $value -is [System.ValueType]) {
        Stop-ProtectedInstallManifestValidation 'INVALID_ROOT'
    }
    return $value
}

function Get-ProtectedInstallManifestFieldNames {
    param($InputObject)
    if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [System.Array] -or $InputObject -is [System.ValueType]) {
        Stop-ProtectedInstallManifestValidation 'INVALID_OBJECT'
    }
    $names = @()
    foreach ($property in $InputObject.PSObject.Properties) { $names += [string]$property.Name }
    return ,$names
}

function Assert-ProtectedInstallManifestFields {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )
    $names = Get-ProtectedInstallManifestFieldNames -InputObject $InputObject
    if ($names.Count -ne $Expected.Count) { Stop-ProtectedInstallManifestValidation 'INVALID_FIELDS' }
    for ($i = 0; $i -lt $names.Count; $i++) {
        for ($j = $i + 1; $j -lt $names.Count; $j++) {
            if ([string]::Equals($names[$i], $names[$j], [System.StringComparison]::OrdinalIgnoreCase)) {
                Stop-ProtectedInstallManifestValidation 'DUPLICATE_FIELD'
            }
        }
    }
    foreach ($expectedName in $Expected) {
        if ($names -cnotcontains $expectedName) { Stop-ProtectedInstallManifestValidation 'INVALID_FIELDS' }
    }
}

function Get-ProtectedInstallManifestField {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    foreach ($property in $InputObject.PSObject.Properties) {
        if ([string]$property.Name -ceq $Name) { return ,$property.Value }
    }
    Stop-ProtectedInstallManifestValidation 'MISSING_FIELD'
}

function Get-ProtectedInstallSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($Bytes)
    } finally {
        $algorithm.Dispose()
    }
    return [System.BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
}

function Assert-ProtectedInstallManifestVersion {
    param($Version)
    if ($Version -isnot [string] -or $Version -cnotmatch '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$') {
        Stop-ProtectedInstallManifestValidation 'INVALID_VERSION'
    }
    foreach ($part in $Version.Split('.')) {
        $number = 0
        if (-not [int]::TryParse($part, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number) -or $number -gt 65535) {
            Stop-ProtectedInstallManifestValidation 'INVALID_VERSION'
        }
    }
}

function Assert-ProtectedInstallManifestPath {
    param([string]$Path)
    $allowed = @(
        'payload/ProtectedEvidence.ps1',
        'payload/ProtectedPathPolicy.ps1',
        'payload/ProtectedRollbackProof.ps1',
        'payload/ProtectedInstallManifest.ps1'
    )
    if ($allowed -cnotcontains $Path) { Stop-ProtectedInstallManifestValidation 'UNTRUSTED_PAYLOAD_PATH' }
}

function Assert-ProtectedInstallPayloadMap {
    param(
        $PayloadBytesByPath,
        [Parameter(Mandatory = $true)][string[]]$ManifestPaths
    )
    if ($PayloadBytesByPath -isnot [System.Collections.IDictionary]) { Stop-ProtectedInstallManifestValidation 'INVALID_PAYLOAD_MAP' }
    $mapNames = @()
    foreach ($key in $PayloadBytesByPath.Keys) {
        if ($key -isnot [string]) { Stop-ProtectedInstallManifestValidation 'INVALID_PAYLOAD_PATH' }
        $name = [string]$key
        Assert-ProtectedInstallManifestPath -Path $name
        foreach ($priorName in $mapNames) {
            if ([string]::Equals($priorName, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                Stop-ProtectedInstallManifestValidation 'DUPLICATE_PAYLOAD_PATH'
            }
        }
        $mapNames += $name
    }
    if ($mapNames.Count -ne $ManifestPaths.Count) { Stop-ProtectedInstallManifestValidation 'PAYLOAD_SET_MISMATCH' }
    foreach ($path in $ManifestPaths) {
        if ($mapNames -cnotcontains $path) { Stop-ProtectedInstallManifestValidation 'PAYLOAD_SET_MISMATCH' }
    }
}

function Test-ProtectedInstallIntegralNumber {
    param($Value, [long]$Minimum, [long]$Maximum)
    if ($Value -isnot [int] -and $Value -isnot [long] -and
        $Value -isnot [double] -and $Value -isnot [decimal]) { return $false }
    $number = [double]$Value
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { return $false }
    return ($number -ge $Minimum -and $number -le $Maximum -and [Math]::Floor($number) -eq $number)
}

function Assert-ProtectedInstallManifestPayloads {
    param(
        $Manifest,
        $PayloadBytesByPath
    )
    $files = Get-ProtectedInstallManifestField -InputObject $Manifest -Name 'files'
    if ($files -isnot [System.Array] -or $files.Count -lt 1 -or $files.Count -gt 4) {
        Stop-ProtectedInstallManifestValidation 'INVALID_PAYLOAD_LIST'
    }

    $paths = @()
    $records = @()
    foreach ($file in $files) {
        Assert-ProtectedInstallManifestFields -InputObject $file -Expected @('path', 'sha256', 'size')
        $path = Get-ProtectedInstallManifestField -InputObject $file -Name 'path'
        if ($path -isnot [string]) { Stop-ProtectedInstallManifestValidation 'UNTRUSTED_PAYLOAD_PATH' }
        Assert-ProtectedInstallManifestPath -Path $path
        foreach ($priorPath in $paths) {
            if ([string]::Equals($priorPath, $path, [System.StringComparison]::OrdinalIgnoreCase)) {
                Stop-ProtectedInstallManifestValidation 'DUPLICATE_PAYLOAD_PATH'
            }
        }
        $paths += $path
        $records += ,@{
            Path = $path
            Sha256 = (Get-ProtectedInstallManifestField -InputObject $file -Name 'sha256')
            Size = (Get-ProtectedInstallManifestField -InputObject $file -Name 'size')
        }
    }

    Assert-ProtectedInstallPayloadMap -PayloadBytesByPath $PayloadBytesByPath -ManifestPaths $paths
    $totalBytes = [long]0
    foreach ($record in $records) {
        $expectedSize = $record.Size
        if (-not (Test-ProtectedInstallIntegralNumber -Value $expectedSize -Minimum 1 -Maximum 16777216)) {
            Stop-ProtectedInstallManifestValidation 'INVALID_PAYLOAD_SIZE'
        }
        $expectedHash = $record.Sha256
        if ($expectedHash -isnot [string] -or $expectedHash -cnotmatch '^[0-9a-f]{64}$') {
            Stop-ProtectedInstallManifestValidation 'INVALID_PAYLOAD_SHA256'
        }
        $payloadBytes = $PayloadBytesByPath[$record.Path]
        if ($payloadBytes -isnot [byte[]] -or $payloadBytes.Length -lt 1 -or $payloadBytes.Length -gt 16777216) {
            Stop-ProtectedInstallManifestValidation 'INVALID_PAYLOAD_BYTES'
        }
        if ($payloadBytes.Length -ne $expectedSize) { Stop-ProtectedInstallManifestValidation 'PAYLOAD_SIZE_MISMATCH' }
        $totalBytes += [long]$payloadBytes.Length
        if ($totalBytes -gt 67108864) { Stop-ProtectedInstallManifestValidation 'PAYLOAD_TOTAL_SIZE' }
        $actualHash = Get-ProtectedInstallSha256 -Bytes $payloadBytes
        if (-not [string]::Equals($actualHash, $expectedHash, [System.StringComparison]::Ordinal)) {
            Stop-ProtectedInstallManifestValidation 'PAYLOAD_SHA256_MISMATCH'
        }
    }
    return ,$paths
}

function Test-ProtectedInstallManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$ManifestBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedManifestSha256,
        [Parameter(Mandatory = $true)]$PayloadBytesByPath
    )

    $manifestHash = $null
    $expectedDigestMatched = $false
    $failureCode = $null
    $payloadNames = @()
    try {
        if ($ManifestBytes.Length -lt 1 -or $ManifestBytes.Length -gt 65536) { Stop-ProtectedInstallManifestValidation 'MANIFEST_SIZE' }
        if ($ExpectedManifestSha256 -cnotmatch '^[0-9a-f]{64}$') { Stop-ProtectedInstallManifestValidation 'INVALID_EXPECTED_SHA256' }
        $manifestHash = Get-ProtectedInstallSha256 -Bytes $ManifestBytes
        $expectedDigestMatched = [string]::Equals($manifestHash, $ExpectedManifestSha256, [System.StringComparison]::Ordinal)
        if (-not $expectedDigestMatched) { Stop-ProtectedInstallManifestValidation 'MANIFEST_SHA256_MISMATCH' }

        $manifest = ConvertFrom-ProtectedInstallManifestBytes -Bytes $ManifestBytes
        Assert-ProtectedInstallManifestFields -InputObject $manifest -Expected @('schemaVersion', 'component', 'version', 'files')
        $schemaVersion = Get-ProtectedInstallManifestField -InputObject $manifest -Name 'schemaVersion'
        if (-not (Test-ProtectedInstallIntegralNumber -Value $schemaVersion -Minimum 1 -Maximum 1)) {
            Stop-ProtectedInstallManifestValidation 'UNSUPPORTED_SCHEMA'
        }
        $component = Get-ProtectedInstallManifestField -InputObject $manifest -Name 'component'
        if ($component -isnot [string] -or $component -cne 'ScreenConnectCleanup.Protected') {
            Stop-ProtectedInstallManifestValidation 'WRONG_COMPONENT'
        }
        Assert-ProtectedInstallManifestVersion (Get-ProtectedInstallManifestField -InputObject $manifest -Name 'version')
        $payloadNames = Assert-ProtectedInstallManifestPayloads -Manifest $manifest -PayloadBytesByPath $PayloadBytesByPath
    } catch {
        $message = [string]$_.Exception.Message
        if ($message -cmatch '^PIM_([A-Z0-9_]+)$') {
            $failureCode = $Matches[1]
        } else {
            $failureCode = 'VALIDATION_FAILURE'
        }
    }

    $isValid = ($null -eq $failureCode)
    return [pscustomobject][ordered]@{
        IntegrityVerified = [bool]$isValid
        ManifestStatus = if ($isValid) { 'IntegrityVerified' } else { 'Rejected' }
        FailureCode = $failureCode
        ManifestSha256 = $manifestHash
        ExpectedDigestMatched = [bool]$expectedDigestMatched
        PayloadCount = [int]$payloadNames.Count
        PayloadNames = [string[]]$payloadNames
        InstallationAuthorized = $false
        RemovalAuthorized = $false
        PublisherAuthenticated = $false
        ExternalDigestChannelAuthenticated = $false
        ProtectedFilesystemTrustEstablished = $false
        ReparsePointsChecked = $false
        ExpectedDigestIsCallerSupplied = $true
    }
}
