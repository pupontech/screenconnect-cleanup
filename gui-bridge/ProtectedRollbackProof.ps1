<#
  Pure validator for the synthetic/produced Stage 0 rollback receipt contract.
  PowerShell 5.1 compatible. This file defines functions only: it performs no
  restore-point, registry, filesystem, process, or removal operations.

  A valid result checks receipt structure and consistency only. It does not
  establish producer trust, protected ACLs, file existence/content, Windows
  restore-point truth, or real registry-export provenance.
#>

function Stop-ProtectedRollbackProofValidation {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw ('PRP_' + $Code)
}

function Get-ProtectedRollbackFieldNames {
    param($InputObject)

    if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [System.Array] -or $InputObject -is [System.ValueType]) {
        Stop-ProtectedRollbackProofValidation 'INVALID_OBJECT'
    }

    $names = @()
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ($key -isnot [string]) { Stop-ProtectedRollbackProofValidation 'INVALID_FIELD_NAME' }
            $names += [string]$key
        }
    } else {
        foreach ($property in $InputObject.PSObject.Properties) {
            $names += [string]$property.Name
        }
    }
    return ,$names
}

function Assert-ProtectedRollbackObjectFields {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    $names = Get-ProtectedRollbackFieldNames -InputObject $InputObject
    if ($names.Count -ne $Expected.Count) { Stop-ProtectedRollbackProofValidation 'INVALID_FIELDS' }

    for ($i = 0; $i -lt $names.Count; $i++) {
        for ($j = $i + 1; $j -lt $names.Count; $j++) {
            if ([string]::Equals($names[$i], $names[$j], [System.StringComparison]::OrdinalIgnoreCase)) {
                Stop-ProtectedRollbackProofValidation 'DUPLICATE_FIELD'
            }
        }
    }
    foreach ($fieldName in $Expected) {
        if ($names -cnotcontains $fieldName) { Stop-ProtectedRollbackProofValidation 'INVALID_FIELDS' }
    }
}

function Get-ProtectedRollbackFieldValue {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -ceq $Name) { return ,$InputObject[$key] }
        }
    } else {
        foreach ($property in $InputObject.PSObject.Properties) {
            if ([string]$property.Name -ceq $Name) { return ,$property.Value }
        }
    }
    Stop-ProtectedRollbackProofValidation 'MISSING_FIELD'
}

function Assert-ProtectedRollbackText {
    param(
        $Value,
        [Parameter(Mandatory = $true)][int]$MaximumLength,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ($Value -isnot [string] -or $Value.Length -lt 1 -or $Value.Length -gt $MaximumLength -or $Value -match '[\x00-\x1f\x7f]') {
        Stop-ProtectedRollbackProofValidation $Code
    }
}

function Assert-ProtectedRollbackInteger {
    param(
        $Value,
        [switch]$AllowZero,
        [Parameter(Mandatory = $true)][string]$Code
    )

    $isInteger = ($Value -is [System.Byte] -or $Value -is [System.SByte] -or $Value -is [System.Int16] -or $Value -is [System.UInt16] -or $Value -is [System.Int32] -or $Value -is [System.UInt32] -or $Value -is [System.Int64] -or $Value -is [System.UInt64])
    if (-not $isInteger) { Stop-ProtectedRollbackProofValidation $Code }
    if ($AllowZero) {
        if ($Value -lt 0) { Stop-ProtectedRollbackProofValidation $Code }
    } elseif ($Value -le 0) {
        Stop-ProtectedRollbackProofValidation $Code
    }
}

function Assert-ProtectedRollbackSid {
    param(
        $Value,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ($Value -isnot [string] -or $Value -cnotmatch '^S-1-\d+(?:-\d+){1,14}$') {
        Stop-ProtectedRollbackProofValidation $Code
    }
}

function Assert-ProtectedRollbackUtcTimestamp {
    param($Value)

    if ($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') {
        Stop-ProtectedRollbackProofValidation 'INVALID_RESTORE_POINT_TIME'
    }
    try {
        [void][DateTime]::ParseExact(
            $Value,
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        )
    } catch {
        Stop-ProtectedRollbackProofValidation 'INVALID_RESTORE_POINT_TIME'
    }
}

function Read-ProtectedRollbackJsonString {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)]$State
    )

    if ($State.Index -ge $Text.Length -or $Text[$State.Index] -ne [char]34) {
        Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
    }
    $State.Index++
    $builder = [System.Text.StringBuilder]::new()
    while ($State.Index -lt $Text.Length) {
        $character = $Text[$State.Index]
        $State.Index++
        if ($character -eq [char]34) { return $builder.ToString() }
        if ([int]$character -lt 32) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
        if ($character -eq [char]92) {
            if ($State.Index -ge $Text.Length) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            $escape = $Text[$State.Index]
            $State.Index++
            if ($escape -eq [char]34) { [void]$builder.Append([char]34) }
            elseif ($escape -eq [char]92) { [void]$builder.Append([char]92) }
            elseif ($escape -eq [char]47) { [void]$builder.Append([char]47) }
            elseif ($escape -eq [char]98) { [void]$builder.Append([char]8) }
            elseif ($escape -eq [char]102) { [void]$builder.Append([char]12) }
            elseif ($escape -eq [char]110) { [void]$builder.Append([char]10) }
            elseif ($escape -eq [char]114) { [void]$builder.Append([char]13) }
            elseif ($escape -eq [char]116) { [void]$builder.Append([char]9) }
            elseif ($escape -eq [char]117) {
                if (($State.Index + 4) -gt $Text.Length) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
                $hex = $Text.Substring($State.Index, 4)
                if ($hex -cnotmatch '^[0-9A-Fa-f]{4}$') { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
                $codeUnit = [int]::Parse($hex, [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture)
                $State.Index += 4
                if ($codeUnit -ge 55296 -and $codeUnit -le 56319) {
                    if (($State.Index + 6) -gt $Text.Length -or $Text.Substring($State.Index, 2) -cne '\u') {
                        Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
                    }
                    $lowHex = $Text.Substring(($State.Index + 2), 4)
                    if ($lowHex -cnotmatch '^[0-9A-Fa-f]{4}$') { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
                    $lowCodeUnit = [int]::Parse($lowHex, [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture)
                    if ($lowCodeUnit -lt 56320 -or $lowCodeUnit -gt 57343) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
                    [void]$builder.Append([char]$codeUnit)
                    [void]$builder.Append([char]$lowCodeUnit)
                    $State.Index += 6
                } else {
                    if ($codeUnit -ge 56320 -and $codeUnit -le 57343) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
                    [void]$builder.Append([char]$codeUnit)
                }
            } else {
                Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
            }
            continue
        }
        if ([char]::IsHighSurrogate($character)) {
            if ($State.Index -ge $Text.Length -or -not [char]::IsLowSurrogate($Text[$State.Index])) {
                Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
            }
            [void]$builder.Append($character)
            [void]$builder.Append($Text[$State.Index])
            $State.Index++
            continue
        }
        if ([char]::IsLowSurrogate($character)) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
        [void]$builder.Append($character)
    }
    Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
}

function Skip-ProtectedRollbackJsonWhitespace {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)]$State
    )

    while ($State.Index -lt $Text.Length) {
        $character = $Text[$State.Index]
        if ($character -eq [char]32 -or $character -eq [char]9 -or $character -eq [char]10 -or $character -eq [char]13) {
            $State.Index++
        } else {
            break
        }
    }
}

function ConvertFrom-ProtectedRollbackJsonValue {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][int]$Depth
    )

    if ($Depth -gt 64) { Stop-ProtectedRollbackProofValidation 'JSON_TOO_DEEP' }
    $State.Nodes++
    if ($State.Nodes -gt 250000) { Stop-ProtectedRollbackProofValidation 'JSON_TOO_COMPLEX' }
    Skip-ProtectedRollbackJsonWhitespace -Text $Text -State $State
    if ($State.Index -ge $Text.Length) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
    $character = $Text[$State.Index]

    if ($character -eq [char]34) {
        return Read-ProtectedRollbackJsonString -Text $Text -State $State
    }
    if ($character -eq [char]123) {
        $State.Index++
        Skip-ProtectedRollbackJsonWhitespace -Text $Text -State $State
        if ($State.Index -lt $Text.Length -and $Text[$State.Index] -eq [char]125) {
            $State.Index++
            return ,([ordered]@{})
        }
        $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $valueObject = [ordered]@{}
        $memberCount = 0
        while ($true) {
            Skip-ProtectedRollbackJsonWhitespace -Text $Text -State $State
            $name = Read-ProtectedRollbackJsonString -Text $Text -State $State
            $memberCount++
            if ($memberCount -gt 8192) { Stop-ProtectedRollbackProofValidation 'TOO_MANY_JSON_MEMBERS' }
            if (-not $names.Add($name)) { Stop-ProtectedRollbackProofValidation 'DUPLICATE_JSON_MEMBER' }
            Skip-ProtectedRollbackJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length -or $Text[$State.Index] -ne [char]58) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            $State.Index++
            $memberValue = ConvertFrom-ProtectedRollbackJsonValue -Text $Text -State $State -Depth ($Depth + 1)
            $valueObject.Add($name, $memberValue)
            Skip-ProtectedRollbackJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            if ($Text[$State.Index] -eq [char]125) {
                $State.Index++
                return ,$valueObject
            }
            if ($Text[$State.Index] -ne [char]44) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            $State.Index++
        }
    }
    if ($character -eq [char]91) {
        $State.Index++
        Skip-ProtectedRollbackJsonWhitespace -Text $Text -State $State
        if ($State.Index -lt $Text.Length -and $Text[$State.Index] -eq [char]93) {
            $State.Index++
            return ,([object[]]@())
        }
        $values = [System.Collections.Generic.List[object]]::new()
        while ($true) {
            $arrayValue = ConvertFrom-ProtectedRollbackJsonValue -Text $Text -State $State -Depth ($Depth + 1)
            [void]$values.Add($arrayValue)
            Skip-ProtectedRollbackJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            if ($Text[$State.Index] -eq [char]93) {
                $State.Index++
                return ,($values.ToArray())
            }
            if ($Text[$State.Index] -ne [char]44) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            $State.Index++
        }
    }
    if ($character -eq [char]45 -or ($character -ge [char]48 -and $character -le [char]57)) {
        $numberStart = $State.Index
        if ($character -eq [char]45) {
            $State.Index++
            if ($State.Index -ge $Text.Length) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            $character = $Text[$State.Index]
        }
        if ($character -eq [char]48) {
            $State.Index++
        } elseif ($character -ge [char]49 -and $character -le [char]57) {
            while ($State.Index -lt $Text.Length -and $Text[$State.Index] -ge [char]48 -and $Text[$State.Index] -le [char]57) { $State.Index++ }
        } else {
            Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
        }
        if ($State.Index -lt $Text.Length -and $Text[$State.Index] -eq [char]46) {
            $State.Index++
            if ($State.Index -ge $Text.Length -or $Text[$State.Index] -lt [char]48 -or $Text[$State.Index] -gt [char]57) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            while ($State.Index -lt $Text.Length -and $Text[$State.Index] -ge [char]48 -and $Text[$State.Index] -le [char]57) { $State.Index++ }
        }
        if ($State.Index -lt $Text.Length -and ($Text[$State.Index] -eq [char]101 -or $Text[$State.Index] -eq [char]69)) {
            $State.Index++
            if ($State.Index -lt $Text.Length -and ($Text[$State.Index] -eq [char]43 -or $Text[$State.Index] -eq [char]45)) { $State.Index++ }
            if ($State.Index -ge $Text.Length -or $Text[$State.Index] -lt [char]48 -or $Text[$State.Index] -gt [char]57) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
            while ($State.Index -lt $Text.Length -and $Text[$State.Index] -ge [char]48 -and $Text[$State.Index] -le [char]57) { $State.Index++ }
        }
        $numberText = $Text.Substring($numberStart, ($State.Index - $numberStart))
        if ($numberText.IndexOfAny([char[]]@('.', 'e', 'E')) -ge 0) {
            try {
                return [double]::Parse($numberText, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture)
            } catch {
                Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
            }
        }
        try {
            return [long]::Parse($numberText, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture)
        } catch {
            try {
                return [ulong]::Parse($numberText, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture)
            } catch {
                Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
            }
        }
    }
    foreach ($literal in @('true', 'false', 'null')) {
        if (($State.Index + $literal.Length) -le $Text.Length -and $Text.Substring($State.Index, $literal.Length) -ceq $literal) {
            $State.Index += $literal.Length
            if ($literal -ceq 'true') { return $true }
            if ($literal -ceq 'false') { return $false }
            return $null
        }
    }
    Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON'
}

function ConvertFrom-ProtectedRollbackBytes {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    if ($Bytes.Length -lt 1 -or $Bytes.Length -gt (1024 * 1024)) { Stop-ProtectedRollbackProofValidation 'RECEIPT_SIZE' }
    $offset = 0
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) {
        $offset = 3
    } elseif (($Bytes.Length -ge 2 -and (($Bytes[0] -eq 255 -and $Bytes[1] -eq 254) -or ($Bytes[0] -eq 254 -and $Bytes[1] -eq 255))) -or
        ($Bytes.Length -ge 4 -and (($Bytes[0] -eq 0 -and $Bytes[1] -eq 0 -and $Bytes[2] -eq 254 -and $Bytes[3] -eq 255) -or ($Bytes[0] -eq 255 -and $Bytes[1] -eq 254 -and $Bytes[2] -eq 0 -and $Bytes[3] -eq 0)))) {
        Stop-ProtectedRollbackProofValidation 'INVALID_ENCODING'
    }

    try {
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $encoding.GetString($Bytes, $offset, ($Bytes.Length - $offset))
    } catch {
        Stop-ProtectedRollbackProofValidation 'INVALID_ENCODING'
    }
    $state = @{ Index = 0; Nodes = 0 }
    $value = ConvertFrom-ProtectedRollbackJsonValue -Text $text -State $state -Depth 0
    Skip-ProtectedRollbackJsonWhitespace -Text $text -State $state
    if ($state.Index -ne $text.Length) { Stop-ProtectedRollbackProofValidation 'MALFORMED_JSON' }
    return ,$value
}

function New-ProtectedRollbackProofResult {
    param(
        [bool]$IsValid,
        $FailureCode,
        [long]$RestorePointSequenceNumber,
        [int]$RegistryExportCount
    )

    return [pscustomobject][ordered]@{
        IsValid = $IsValid
        FailureCode = $FailureCode
        RestorePointSequenceNumber = $RestorePointSequenceNumber
        RegistryExportCount = $RegistryExportCount
    }
}

function Test-ProtectedRollbackProof {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$ReceiptBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedHkcuSid
    )

    try {
        $receipt = ConvertFrom-ProtectedRollbackBytes -Bytes $ReceiptBytes
        Assert-ProtectedRollbackSid -Value $ExpectedHkcuSid -Code 'INVALID_EXPECTED_HKCU_SID'
        Assert-ProtectedRollbackObjectFields -InputObject $receipt -Expected @(
            'schemaVersion', 'transactionId', 'status', 'restorePointWaiverUsed',
            'effectiveUserSid', 'restorePoint', 'registryExports', 'failureCodes'
        )

        $schemaVersion = Get-ProtectedRollbackFieldValue -InputObject $receipt -Name 'schemaVersion'
        Assert-ProtectedRollbackInteger -Value $schemaVersion -Code 'UNSUPPORTED_SCHEMA'
        if ($schemaVersion -ne 1) { Stop-ProtectedRollbackProofValidation 'UNSUPPORTED_SCHEMA' }

        $transactionId = Get-ProtectedRollbackFieldValue -InputObject $receipt -Name 'transactionId'
        if ($transactionId -isnot [string] -or $transactionId -cnotmatch '^[0-9a-fA-F]{32}$') {
            Stop-ProtectedRollbackProofValidation 'INVALID_TRANSACTION_ID'
        }

        $status = Get-ProtectedRollbackFieldValue -InputObject $receipt -Name 'status'
        if ($status -isnot [string] -or $status -cne 'Verified') { Stop-ProtectedRollbackProofValidation 'INCOMPLETE_RECEIPT' }

        $waiverUsed = Get-ProtectedRollbackFieldValue -InputObject $receipt -Name 'restorePointWaiverUsed'
        if ($waiverUsed -isnot [bool] -or $waiverUsed) { Stop-ProtectedRollbackProofValidation 'RESTORE_POINT_WAIVER' }

        $effectiveUserSid = Get-ProtectedRollbackFieldValue -InputObject $receipt -Name 'effectiveUserSid'
        Assert-ProtectedRollbackSid -Value $effectiveUserSid -Code 'INVALID_EFFECTIVE_USER_SID'
        if ($effectiveUserSid -cne $ExpectedHkcuSid) { Stop-ProtectedRollbackProofValidation 'HKCU_SID_MISMATCH' }

        $failureCodes = Get-ProtectedRollbackFieldValue -InputObject $receipt -Name 'failureCodes'
        if ($failureCodes -isnot [System.Array] -or $failureCodes.Count -ne 0) {
            Stop-ProtectedRollbackProofValidation 'RECEIPT_HAS_FAILURES'
        }

        $restorePoint = Get-ProtectedRollbackFieldValue -InputObject $receipt -Name 'restorePoint'
        Assert-ProtectedRollbackObjectFields -InputObject $restorePoint -Expected @(
            'attempted', 'status', 'description', 'preSequenceNumber',
            'postSequenceNumber', 'identity', 'queryRecords'
        )

        $attempted = Get-ProtectedRollbackFieldValue -InputObject $restorePoint -Name 'attempted'
        $restoreStatus = Get-ProtectedRollbackFieldValue -InputObject $restorePoint -Name 'status'
        if ($attempted -isnot [bool] -or -not $attempted -or $restoreStatus -isnot [string] -or $restoreStatus -cne 'Verified') {
            Stop-ProtectedRollbackProofValidation 'RESTORE_POINT_NOT_VERIFIED'
        }

        $expectedDescription = 'ScreenConnect Cleanup GUI ' + $transactionId
        $description = Get-ProtectedRollbackFieldValue -InputObject $restorePoint -Name 'description'
        Assert-ProtectedRollbackText -Value $description -MaximumLength 128 -Code 'INVALID_RESTORE_POINT_DESCRIPTION'
        if ($description -cne $expectedDescription) { Stop-ProtectedRollbackProofValidation 'RESTORE_POINT_DESCRIPTION_MISMATCH' }

        $preSequence = Get-ProtectedRollbackFieldValue -InputObject $restorePoint -Name 'preSequenceNumber'
        $postSequence = Get-ProtectedRollbackFieldValue -InputObject $restorePoint -Name 'postSequenceNumber'
        Assert-ProtectedRollbackInteger -Value $preSequence -AllowZero -Code 'INVALID_RESTORE_POINT_SEQUENCE'
        Assert-ProtectedRollbackInteger -Value $postSequence -Code 'INVALID_RESTORE_POINT_SEQUENCE'

        $queryRecords = Get-ProtectedRollbackFieldValue -InputObject $restorePoint -Name 'queryRecords'
        if ($queryRecords -isnot [System.Array] -or $queryRecords.Count -lt 1) {
            Stop-ProtectedRollbackProofValidation 'RESTORE_POINT_QUERY_MISSING'
        }

        $matchingRecords = @()
        $seenSequences = @()
        foreach ($queryRecord in $queryRecords) {
            Assert-ProtectedRollbackObjectFields -InputObject $queryRecord -Expected @('sequenceNumber', 'description', 'creationTimeUtc')
            $recordSequence = Get-ProtectedRollbackFieldValue -InputObject $queryRecord -Name 'sequenceNumber'
            $recordDescription = Get-ProtectedRollbackFieldValue -InputObject $queryRecord -Name 'description'
            $recordTime = Get-ProtectedRollbackFieldValue -InputObject $queryRecord -Name 'creationTimeUtc'
            Assert-ProtectedRollbackInteger -Value $recordSequence -Code 'INVALID_RESTORE_POINT_SEQUENCE'
            Assert-ProtectedRollbackText -Value $recordDescription -MaximumLength 128 -Code 'INVALID_RESTORE_POINT_DESCRIPTION'
            Assert-ProtectedRollbackUtcTimestamp -Value $recordTime

            if ($seenSequences -ccontains $recordSequence) { Stop-ProtectedRollbackProofValidation 'AMBIGUOUS_RESTORE_POINT' }
            $seenSequences += $recordSequence
            if ($recordDescription -ceq $expectedDescription) { $matchingRecords += ,$queryRecord }
        }
        if ($matchingRecords.Count -ne 1) { Stop-ProtectedRollbackProofValidation 'AMBIGUOUS_RESTORE_POINT' }

        $matchedRecord = $matchingRecords[0]
        $matchedSequence = Get-ProtectedRollbackFieldValue -InputObject $matchedRecord -Name 'sequenceNumber'
        if ($matchedSequence -le $preSequence -or $matchedSequence -ne $postSequence) {
            Stop-ProtectedRollbackProofValidation 'RESTORE_POINT_NOT_NEW'
        }

        $identity = Get-ProtectedRollbackFieldValue -InputObject $restorePoint -Name 'identity'
        Assert-ProtectedRollbackObjectFields -InputObject $identity -Expected @('sequenceNumber', 'description', 'creationTimeUtc')
        $identitySequence = Get-ProtectedRollbackFieldValue -InputObject $identity -Name 'sequenceNumber'
        $identityDescription = Get-ProtectedRollbackFieldValue -InputObject $identity -Name 'description'
        $identityTime = Get-ProtectedRollbackFieldValue -InputObject $identity -Name 'creationTimeUtc'
        Assert-ProtectedRollbackInteger -Value $identitySequence -Code 'INVALID_RESTORE_POINT_SEQUENCE'
        Assert-ProtectedRollbackText -Value $identityDescription -MaximumLength 128 -Code 'INVALID_RESTORE_POINT_DESCRIPTION'
        Assert-ProtectedRollbackUtcTimestamp -Value $identityTime
        if ($identitySequence -ne $matchedSequence -or $identityDescription -cne $description -or $identityTime -cne (Get-ProtectedRollbackFieldValue -InputObject $matchedRecord -Name 'creationTimeUtc')) {
            Stop-ProtectedRollbackProofValidation 'RESTORE_POINT_IDENTITY_MISMATCH'
        }

        $registryExports = Get-ProtectedRollbackFieldValue -InputObject $receipt -Name 'registryExports'
        if ($registryExports -isnot [System.Array] -or $registryExports.Count -lt 1 -or $registryExports.Count -gt 4) {
            Stop-ProtectedRollbackProofValidation 'REGISTRY_EXPORT_SET_MISMATCH'
        }
        $expectedHives = @('HKLM\SOFTWARE', 'HKLM\SYSTEM', 'HKCU\SOFTWARE')
        $seenHives = @()
        foreach ($export in $registryExports) {
            Assert-ProtectedRollbackObjectFields -InputObject $export -Expected @(
                'hive', 'status', 'exitCode', 'relativePath', 'length', 'sha256', 'hiveUserSid'
            )

            $hive = Get-ProtectedRollbackFieldValue -InputObject $export -Name 'hive'
            if ($hive -isnot [string] -or $expectedHives -cnotcontains $hive) {
                Stop-ProtectedRollbackProofValidation 'REGISTRY_EXPORT_SET_MISMATCH'
            }
            if ($seenHives -ccontains $hive) { Stop-ProtectedRollbackProofValidation 'DUPLICATE_REGISTRY_EXPORT' }
            $seenHives += $hive

            $exportStatus = Get-ProtectedRollbackFieldValue -InputObject $export -Name 'status'
            $exitCode = Get-ProtectedRollbackFieldValue -InputObject $export -Name 'exitCode'
            if ($exportStatus -isnot [string] -or $exportStatus -cne 'Verified') {
                Stop-ProtectedRollbackProofValidation 'REGISTRY_EXPORT_FAILED'
            }
            Assert-ProtectedRollbackInteger -Value $exitCode -AllowZero -Code 'REGISTRY_EXPORT_FAILED'
            if ($exitCode -ne 0) { Stop-ProtectedRollbackProofValidation 'REGISTRY_EXPORT_FAILED' }

            $expectedPath = $null
            $expectedHiveSid = $null
            if ($hive -ceq 'HKLM\SOFTWARE') { $expectedPath = 'rollback\registry_hives\HKLM_SOFTWARE.reg' }
            if ($hive -ceq 'HKLM\SYSTEM') { $expectedPath = 'rollback\registry_hives\HKLM_SYSTEM.reg' }
            if ($hive -ceq 'HKCU\SOFTWARE') {
                $expectedPath = 'rollback\registry_hives\HKCU_SOFTWARE.reg'
                $expectedHiveSid = $ExpectedHkcuSid
            }

            $relativePath = Get-ProtectedRollbackFieldValue -InputObject $export -Name 'relativePath'
            if ($relativePath -isnot [string] -or $relativePath -cne $expectedPath) {
                Stop-ProtectedRollbackProofValidation 'UNTRUSTED_REGISTRY_PATH'
            }

            $length = Get-ProtectedRollbackFieldValue -InputObject $export -Name 'length'
            Assert-ProtectedRollbackInteger -Value $length -Code 'INVALID_REGISTRY_LENGTH'

            $sha256 = Get-ProtectedRollbackFieldValue -InputObject $export -Name 'sha256'
            if ($sha256 -isnot [string] -or $sha256 -cnotmatch '^[0-9a-f]{64}$') {
                Stop-ProtectedRollbackProofValidation 'INVALID_REGISTRY_DIGEST'
            }

            $hiveUserSid = Get-ProtectedRollbackFieldValue -InputObject $export -Name 'hiveUserSid'
            if ($null -eq $expectedHiveSid) {
                if ($null -ne $hiveUserSid) { Stop-ProtectedRollbackProofValidation 'UNEXPECTED_HIVE_SID' }
            } elseif ($hiveUserSid -isnot [string] -or $hiveUserSid -cne $expectedHiveSid) {
                Stop-ProtectedRollbackProofValidation 'HKCU_SID_MISMATCH'
            }
        }

        if ($registryExports.Count -ne 3) { Stop-ProtectedRollbackProofValidation 'REGISTRY_EXPORT_SET_MISMATCH' }
        foreach ($expectedHive in $expectedHives) {
            if ($seenHives -cnotcontains $expectedHive) { Stop-ProtectedRollbackProofValidation 'REGISTRY_EXPORT_SET_MISMATCH' }
        }

        return (New-ProtectedRollbackProofResult -IsValid $true -FailureCode $null -RestorePointSequenceNumber ([long]$identitySequence) -RegistryExportCount 3)
    } catch {
        $failureCode = 'INVALID_RECEIPT'
        $message = [string]$_.Exception.Message
        if ($message -cmatch '^PRP_[A-Z0-9_]+$') { $failureCode = $message.Substring(4) }
        return (New-ProtectedRollbackProofResult -IsValid $false -FailureCode $failureCode -RestorePointSequenceNumber 0 -RegistryExportCount 0)
    }
}
