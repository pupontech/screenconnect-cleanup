<#
  Pure bounded validator for protected-review evidence bytes and a candidate plan.
  PowerShell 5.1 compatible. This file defines in-memory functions only.

  A successful result means the supplied bytes are structurally complete and
  agree with the explicitly supplied producer context and plan instance set.
  This code cannot authenticate that context or the producer, and it never
  approves removal or establishes provenance. The protected coordinator must
  independently prove producer ownership before calling this validator.
#>

function Stop-ProtectedEvidenceValidation {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw ('PE_' + $Code)
}

function Get-ProtectedEvidenceFieldNames {
    param($InputObject)

    if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [System.Array] -or $InputObject -is [System.ValueType]) {
        Stop-ProtectedEvidenceValidation 'INVALID_OBJECT'
    }

    $names = @()
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ($key -isnot [string]) { Stop-ProtectedEvidenceValidation 'INVALID_FIELD_NAME' }
            $names += [string]$key
        }
    } else {
        foreach ($property in $InputObject.PSObject.Properties) {
            if ($property.MemberType -eq 'NoteProperty' -or $property.MemberType -eq 'Property') {
                $names += [string]$property.Name
            }
        }
    }
    return ,$names
}

function Get-ProtectedEvidenceField {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) { Stop-ProtectedEvidenceValidation 'INVALID_OBJECT' }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ($key -is [string] -and [string]$key -ceq $Name) { return ,$InputObject[$key] }
        }
    } else {
        foreach ($property in $InputObject.PSObject.Properties) {
            if ([string]$property.Name -ceq $Name) { return ,$property.Value }
        }
    }
    Stop-ProtectedEvidenceValidation 'MISSING_FIELD'
}

function Assert-ProtectedEvidenceExactFields {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    $names = Get-ProtectedEvidenceFieldNames -InputObject $InputObject
    if ($names.Count -ne $Expected.Count) { Stop-ProtectedEvidenceValidation 'INVALID_FIELDS' }
    for ($index = 0; $index -lt $names.Count; $index++) {
        for ($other = $index + 1; $other -lt $names.Count; $other++) {
            if ([string]::Equals($names[$index], $names[$other], [System.StringComparison]::OrdinalIgnoreCase)) {
                Stop-ProtectedEvidenceValidation 'DUPLICATE_FIELD'
            }
        }
    }
    foreach ($expectedName in $Expected) {
        if ($names -cnotcontains $expectedName) { Stop-ProtectedEvidenceValidation 'INVALID_FIELDS' }
    }
}

function Assert-ProtectedEvidenceText {
    param(
        $Value,
        [Parameter(Mandatory = $true)][int]$MaximumLength,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or $Value -cne $Value.Trim() -or $Value.Length -gt $MaximumLength -or $Value -match '[\x00-\x1f\x7f]') {
        Stop-ProtectedEvidenceValidation $Code
    }
}

function Assert-ProtectedEvidenceId {
    param(
        $Value,
        [Parameter(Mandatory = $true)][string]$Code
    )

    Assert-ProtectedEvidenceText -Value $Value -MaximumLength 128 -Code $Code
    if ($Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $Value -ceq '.' -or $Value -ceq '..') {
        Stop-ProtectedEvidenceValidation $Code
    }
}

function Assert-ProtectedEvidenceHostName {
    param(
        $Value,
        [Parameter(Mandatory = $true)][string]$Code
    )

    Assert-ProtectedEvidenceText -Value $Value -MaximumLength 63 -Code $Code
    if ($Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $Value.EndsWith('.') -or $Value.EndsWith('-') -or $Value.Contains('..')) {
        Stop-ProtectedEvidenceValidation $Code
    }
}

function Assert-ProtectedEvidenceArray {
    param(
        $Value,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ($Value -isnot [System.Array] -or $Value.Rank -ne 1) { Stop-ProtectedEvidenceValidation $Code }
}

function Assert-ProtectedEvidenceDrivePath {
    param(
        $Value,
        [Parameter(Mandatory = $true)][string]$Code
    )

    Assert-ProtectedEvidenceText -Value $Value -MaximumLength 32767 -Code $Code
    if ($Value -cnotmatch '^[A-Za-z]:\\[^\\]') { Stop-ProtectedEvidenceValidation $Code }
    $remainder = $Value.Substring(3)
    if ($remainder.IndexOfAny([char[]]@('/', ':', '*', '?', '"', '<', '>', '|')) -ge 0) {
        Stop-ProtectedEvidenceValidation $Code
    }
    $segments = $remainder.Split([char]92)
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -ceq '.' -or $segment -ceq '..' -or $segment.EndsWith('.') -or $segment.EndsWith(' ')) {
            Stop-ProtectedEvidenceValidation $Code
        }
    }
}

function Get-ProtectedEvidenceInstanceIdentity {
    param($Instance)

    $key = Get-ProtectedEvidenceField -InputObject $Instance -Name 'Key'
    $identifier = Get-ProtectedEvidenceField -InputObject $Instance -Name 'Identifier'
    $installDir = Get-ProtectedEvidenceField -InputObject $Instance -Name 'InstallDir'
    Assert-ProtectedEvidenceText -Value $key -MaximumLength 512 -Code 'INVALID_INSTANCE_KEY'
    Assert-ProtectedEvidenceText -Value $identifier -MaximumLength 512 -Code 'INVALID_INSTANCE_IDENTIFIER'
    Assert-ProtectedEvidenceDrivePath -Value $installDir -Code 'INVALID_INSTANCE_PATH'
    return [pscustomobject][ordered]@{
        Key = $key
        Identifier = $identifier
        InstallDir = $installDir
    }
}

function Assert-ProtectedEvidenceUniqueInstances {
    param(
        [Parameter(Mandatory = $true)][object[]]$Instances,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ($Instances.Count -gt 5000) { Stop-ProtectedEvidenceValidation 'TOO_MANY_INSTANCES' }
    $identities = New-Object 'System.Collections.Generic.List[object]'
    $seenKeys = @{}
    $seenIdentifiers = @{}
    $seenPaths = @{}
    foreach ($instance in $Instances) {
        $identity = Get-ProtectedEvidenceInstanceIdentity -Instance $instance
        if ($seenKeys.ContainsKey($identity.Key) -or $seenIdentifiers.ContainsKey($identity.Identifier) -or $seenPaths.ContainsKey($identity.InstallDir)) {
            Stop-ProtectedEvidenceValidation $Code
        }
        $seenKeys[$identity.Key] = $true
        $seenIdentifiers[$identity.Identifier] = $true
        $seenPaths[$identity.InstallDir] = $true
        [void]$identities.Add($identity)
    }
    $identityArray = $identities.ToArray()
    return ,$identityArray
}

function Test-ProtectedEvidenceSameInstanceSet {
    param(
        [Parameter(Mandatory = $true)][object[]]$Observed,
        [Parameter(Mandatory = $true)][object[]]$Planned
    )

    if ($Observed.Count -eq 0 -or $Planned.Count -ne $Observed.Count) { return $false }
    $observedIdentities = Assert-ProtectedEvidenceUniqueInstances -Instances $Observed -Code 'DUPLICATE_FINDINGS_INSTANCE'
    $plannedIdentities = Assert-ProtectedEvidenceUniqueInstances -Instances $Planned -Code 'DUPLICATE_PLAN_INSTANCE'
    $observedByKey = @{}
    foreach ($observedIdentity in $observedIdentities) { $observedByKey[$observedIdentity.Key] = $observedIdentity }
    foreach ($plannedIdentity in $plannedIdentities) {
        if (-not $observedByKey.ContainsKey($plannedIdentity.Key)) { return $false }
        $observedIdentity = $observedByKey[$plannedIdentity.Key]
        if (-not [string]::Equals($observedIdentity.Identifier, $plannedIdentity.Identifier, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($observedIdentity.InstallDir, $plannedIdentity.InstallDir, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    return $true
}

function Read-ProtectedEvidenceJsonString {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)]$State
    )

    if ($State.Index -ge $Text.Length -or $Text[$State.Index] -ne [char]34) {
        Stop-ProtectedEvidenceValidation 'MALFORMED_JSON'
    }
    $State.Index++
    $builder = New-Object System.Text.StringBuilder
    while ($State.Index -lt $Text.Length) {
        $character = $Text[$State.Index]
        $State.Index++
        if ($character -eq [char]34) { return $builder.ToString() }
        if ([int]$character -lt 32) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
        if ($character -eq [char]92) {
            if ($State.Index -ge $Text.Length) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
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
                if (($State.Index + 4) -gt $Text.Length) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
                $hex = $Text.Substring($State.Index, 4)
                if ($hex -cnotmatch '^[0-9A-Fa-f]{4}$') { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
                $codeUnit = [int]::Parse($hex, [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture)
                $State.Index += 4
                if ($codeUnit -ge 55296 -and $codeUnit -le 56319) {
                    if (($State.Index + 6) -gt $Text.Length -or $Text.Substring($State.Index, 2) -cne '\u') {
                        Stop-ProtectedEvidenceValidation 'MALFORMED_JSON'
                    }
                    $lowHex = $Text.Substring(($State.Index + 2), 4)
                    if ($lowHex -cnotmatch '^[0-9A-Fa-f]{4}$') { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
                    $lowCodeUnit = [int]::Parse($lowHex, [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture)
                    if ($lowCodeUnit -lt 56320 -or $lowCodeUnit -gt 57343) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
                    [void]$builder.Append([char]$codeUnit)
                    [void]$builder.Append([char]$lowCodeUnit)
                    $State.Index += 6
                } else {
                    if ($codeUnit -ge 56320 -and $codeUnit -le 57343) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
                    [void]$builder.Append([char]$codeUnit)
                }
            } else {
                Stop-ProtectedEvidenceValidation 'MALFORMED_JSON'
            }
            continue
        }
        if ([char]::IsHighSurrogate($character)) {
            if ($State.Index -ge $Text.Length -or -not [char]::IsLowSurrogate($Text[$State.Index])) {
                Stop-ProtectedEvidenceValidation 'MALFORMED_JSON'
            }
            [void]$builder.Append($character)
            [void]$builder.Append($Text[$State.Index])
            $State.Index++
            continue
        }
        if ([char]::IsLowSurrogate($character)) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
        [void]$builder.Append($character)
    }
    Stop-ProtectedEvidenceValidation 'MALFORMED_JSON'
}

function Skip-ProtectedEvidenceJsonWhitespace {
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

function Assert-ProtectedEvidenceJsonValue {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][int]$Depth
    )

    if ($Depth -gt 64) { Stop-ProtectedEvidenceValidation 'JSON_TOO_DEEP' }
    $State.Nodes++
    if ($State.Nodes -gt 250000) { Stop-ProtectedEvidenceValidation 'JSON_TOO_COMPLEX' }
    Skip-ProtectedEvidenceJsonWhitespace -Text $Text -State $State
    if ($State.Index -ge $Text.Length) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
    $character = $Text[$State.Index]

    if ($character -eq [char]34) {
        [void](Read-ProtectedEvidenceJsonString -Text $Text -State $State)
        return
    }
    if ($character -eq [char]123) {
        $State.Index++
        Skip-ProtectedEvidenceJsonWhitespace -Text $Text -State $State
        if ($State.Index -lt $Text.Length -and $Text[$State.Index] -eq [char]125) {
            $State.Index++
            return
        }
        $names = @{}
        while ($true) {
            Skip-ProtectedEvidenceJsonWhitespace -Text $Text -State $State
            $name = Read-ProtectedEvidenceJsonString -Text $Text -State $State
            if ($names.Count -ge 8192) { Stop-ProtectedEvidenceValidation 'TOO_MANY_JSON_MEMBERS' }
            if ($names.ContainsKey($name)) { Stop-ProtectedEvidenceValidation 'DUPLICATE_JSON_MEMBER' }
            $names[$name] = $true
            Skip-ProtectedEvidenceJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length -or $Text[$State.Index] -ne [char]58) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
            $State.Index++
            Assert-ProtectedEvidenceJsonValue -Text $Text -State $State -Depth ($Depth + 1)
            Skip-ProtectedEvidenceJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
            if ($Text[$State.Index] -eq [char]125) {
                $State.Index++
                return
            }
            if ($Text[$State.Index] -ne [char]44) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
            $State.Index++
        }
    }
    if ($character -eq [char]91) {
        $State.Index++
        Skip-ProtectedEvidenceJsonWhitespace -Text $Text -State $State
        if ($State.Index -lt $Text.Length -and $Text[$State.Index] -eq [char]93) {
            $State.Index++
            return
        }
        while ($true) {
            Assert-ProtectedEvidenceJsonValue -Text $Text -State $State -Depth ($Depth + 1)
            Skip-ProtectedEvidenceJsonWhitespace -Text $Text -State $State
            if ($State.Index -ge $Text.Length) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
            if ($Text[$State.Index] -eq [char]93) {
                $State.Index++
                return
            }
            if ($Text[$State.Index] -ne [char]44) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
            $State.Index++
        }
    }
    if ($character -eq [char]45 -or ($character -ge [char]48 -and $character -le [char]57)) {
        if ($character -eq [char]45) {
            $State.Index++
            if ($State.Index -ge $Text.Length) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
            $character = $Text[$State.Index]
        }
        if ($character -eq [char]48) {
            $State.Index++
        } elseif ($character -ge [char]49 -and $character -le [char]57) {
            while ($State.Index -lt $Text.Length -and $Text[$State.Index] -ge [char]48 -and $Text[$State.Index] -le [char]57) { $State.Index++ }
        } else {
            Stop-ProtectedEvidenceValidation 'MALFORMED_JSON'
        }
        if ($State.Index -lt $Text.Length -and $Text[$State.Index] -eq [char]46) {
            $State.Index++
            if ($State.Index -ge $Text.Length -or $Text[$State.Index] -lt [char]48 -or $Text[$State.Index] -gt [char]57) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
            while ($State.Index -lt $Text.Length -and $Text[$State.Index] -ge [char]48 -and $Text[$State.Index] -le [char]57) { $State.Index++ }
        }
        if ($State.Index -lt $Text.Length -and ($Text[$State.Index] -eq [char]101 -or $Text[$State.Index] -eq [char]69)) {
            $State.Index++
            if ($State.Index -lt $Text.Length -and ($Text[$State.Index] -eq [char]43 -or $Text[$State.Index] -eq [char]45)) { $State.Index++ }
            if ($State.Index -ge $Text.Length -or $Text[$State.Index] -lt [char]48 -or $Text[$State.Index] -gt [char]57) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
            while ($State.Index -lt $Text.Length -and $Text[$State.Index] -ge [char]48 -and $Text[$State.Index] -le [char]57) { $State.Index++ }
        }
        return
    }
    foreach ($literal in @('true', 'false', 'null')) {
        if (($State.Index + $literal.Length) -le $Text.Length -and $Text.Substring($State.Index, $literal.Length) -ceq $literal) {
            $State.Index += $literal.Length
            return
        }
    }
    Stop-ProtectedEvidenceValidation 'MALFORMED_JSON'
}

function ConvertFrom-ProtectedEvidenceBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$MaximumBytes
    )

    if ($Bytes.Length -lt 1 -or $Bytes.Length -gt $MaximumBytes) { Stop-ProtectedEvidenceValidation 'EVIDENCE_SIZE' }
    $offset = 0
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) {
        $offset = 3
    } elseif (($Bytes.Length -ge 2 -and (($Bytes[0] -eq 255 -and $Bytes[1] -eq 254) -or ($Bytes[0] -eq 254 -and $Bytes[1] -eq 255))) -or
        ($Bytes.Length -ge 4 -and (($Bytes[0] -eq 0 -and $Bytes[1] -eq 0 -and $Bytes[2] -eq 254 -and $Bytes[3] -eq 255) -or ($Bytes[0] -eq 255 -and $Bytes[1] -eq 254 -and $Bytes[2] -eq 0 -and $Bytes[3] -eq 0)))) {
        Stop-ProtectedEvidenceValidation 'INVALID_ENCODING'
    }

    try {
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $encoding.GetString($Bytes, $offset, ($Bytes.Length - $offset))
    } catch {
        Stop-ProtectedEvidenceValidation 'INVALID_ENCODING'
    }
    $state = @{ Index = 0; Nodes = 0 }
    Assert-ProtectedEvidenceJsonValue -Text $text -State $state -Depth 0
    Skip-ProtectedEvidenceJsonWhitespace -Text $text -State $state
    if ($state.Index -ne $text.Length) { Stop-ProtectedEvidenceValidation 'MALFORMED_JSON' }
    try {
        $value = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    } catch {
        Stop-ProtectedEvidenceValidation 'MALFORMED_JSON'
    }
    if ($null -eq $value -or $value -is [string] -or $value -is [System.Array] -or $value -is [System.ValueType]) {
        Stop-ProtectedEvidenceValidation 'INVALID_ROOT'
    }
    return $value
}

function Assert-ProtectedEvidenceContext {
    param($Context)

    Assert-ProtectedEvidenceExactFields -InputObject $Context -Expected @(
        'ContextVersion', 'ProducerKind', 'ProtectedRunId', 'DetectorRunId', 'ComputerName'
    )
    $version = Get-ProtectedEvidenceField -InputObject $Context -Name 'ContextVersion'
    if ($version -isnot [int] -or $version -ne 1) { Stop-ProtectedEvidenceValidation 'INVALID_CONTEXT_VERSION' }
    $producerKind = Get-ProtectedEvidenceField -InputObject $Context -Name 'ProducerKind'
    if ($producerKind -isnot [string] -or $producerKind -cne 'TrustedProtectedProducer') { Stop-ProtectedEvidenceValidation 'UNTRUSTED_CONTEXT_KIND' }
    $protectedRunId = Get-ProtectedEvidenceField -InputObject $Context -Name 'ProtectedRunId'
    $detectorRunId = Get-ProtectedEvidenceField -InputObject $Context -Name 'DetectorRunId'
    $computerName = Get-ProtectedEvidenceField -InputObject $Context -Name 'ComputerName'
    Assert-ProtectedEvidenceId -Value $protectedRunId -Code 'INVALID_PROTECTED_RUN_ID'
    Assert-ProtectedEvidenceId -Value $detectorRunId -Code 'INVALID_DETECTOR_RUN_ID'
    Assert-ProtectedEvidenceHostName -Value $computerName -Code 'INVALID_CONTEXT_HOST'
    if ([string]::Equals($protectedRunId, $detectorRunId, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-ProtectedEvidenceValidation 'RUN_IDENTITIES_NOT_DISTINCT'
    }
    return [pscustomobject][ordered]@{
        ProtectedRunId = $protectedRunId
        DetectorRunId = $detectorRunId
        ComputerName = $computerName
    }
}

function Assert-ProtectedEvidenceFindings {
    param(
        $Findings,
        $Context
    )

    $tool = Get-ProtectedEvidenceField -InputObject $Findings -Name 'Tool'
    if ($tool -isnot [string] -or $tool -cne 'detect-remote-access.ps1') { Stop-ProtectedEvidenceValidation 'WRONG_DETECTOR' }
    $runId = Get-ProtectedEvidenceField -InputObject $Findings -Name 'RunId'
    $computerName = Get-ProtectedEvidenceField -InputObject $Findings -Name 'ComputerName'
    if ($runId -isnot [string] -or $runId -cne $Context.DetectorRunId) { Stop-ProtectedEvidenceValidation 'DETECTOR_RUN_MISMATCH' }
    if ($computerName -isnot [string] -or -not [string]::Equals($computerName, $Context.ComputerName, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-ProtectedEvidenceValidation 'FINDINGS_HOST_MISMATCH'
    }
    $complete = Get-ProtectedEvidenceField -InputObject $Findings -Name 'CollectionComplete'
    if ($complete -isnot [bool] -or -not $complete) { Stop-ProtectedEvidenceValidation 'FINDINGS_INCOMPLETE' }
    $errors = Get-ProtectedEvidenceField -InputObject $Findings -Name 'CollectionErrors'
    Assert-ProtectedEvidenceArray -Value $errors -Code 'INVALID_FINDINGS_ERRORS'
    if ($errors.Count -ne 0) { Stop-ProtectedEvidenceValidation 'FINDINGS_COLLECTION_ERRORS' }
    $eventLogError = Get-ProtectedEvidenceField -InputObject $Findings -Name 'EventLogError'
    if ($null -ne $eventLogError -and ($eventLogError -isnot [string] -or -not [string]::IsNullOrEmpty($eventLogError))) {
        Stop-ProtectedEvidenceValidation 'EVENT_LOG_ERROR'
    }
    $screenConnect = Get-ProtectedEvidenceField -InputObject $Findings -Name 'ScreenConnect'
    $instances = Get-ProtectedEvidenceField -InputObject $screenConnect -Name 'Instances'
    Assert-ProtectedEvidenceArray -Value $instances -Code 'INVALID_FINDINGS_INSTANCES'
    $parseIssues = Get-ProtectedEvidenceField -InputObject $screenConnect -Name 'ParseIssues'
    Assert-ProtectedEvidenceArray -Value $parseIssues -Code 'INVALID_PARSE_ISSUES'
    if ($parseIssues.Count -ne 0) { Stop-ProtectedEvidenceValidation 'FINDINGS_PARSE_ISSUES' }
    if ($instances.Count -eq 0) { Stop-ProtectedEvidenceValidation 'NO_REMOVAL_INSTANCES' }
    [void](Assert-ProtectedEvidenceUniqueInstances -Instances $instances -Code 'DUPLICATE_FINDINGS_INSTANCE')
    return ,$instances
}

function Assert-ProtectedEvidenceSnapshot {
    param(
        $Snapshot,
        $Context
    )

    $schemaVersion = Get-ProtectedEvidenceField -InputObject $Snapshot -Name 'SchemaVersion'
    if (($schemaVersion -isnot [int] -and $schemaVersion -isnot [long]) -or $schemaVersion -ne 2) { Stop-ProtectedEvidenceValidation 'UNSUPPORTED_SNAPSHOT_SCHEMA' }
    $label = Get-ProtectedEvidenceField -InputObject $Snapshot -Name 'Label'
    if ($label -isnot [string] -or $label -cne 'before') { Stop-ProtectedEvidenceValidation 'NOT_BEFORE_SNAPSHOT' }
    $computerName = Get-ProtectedEvidenceField -InputObject $Snapshot -Name 'ComputerName'
    if ($computerName -isnot [string] -or -not [string]::Equals($computerName, $Context.ComputerName, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-ProtectedEvidenceValidation 'SNAPSHOT_HOST_MISMATCH'
    }
    $complete = Get-ProtectedEvidenceField -InputObject $Snapshot -Name 'CollectionComplete'
    if ($complete -isnot [bool] -or -not $complete) { Stop-ProtectedEvidenceValidation 'SNAPSHOT_INCOMPLETE' }
    $errors = Get-ProtectedEvidenceField -InputObject $Snapshot -Name 'CollectionErrors'
    Assert-ProtectedEvidenceArray -Value $errors -Code 'INVALID_SNAPSHOT_ERRORS'
    if ($errors.Count -ne 0) { Stop-ProtectedEvidenceValidation 'SNAPSHOT_COLLECTION_ERRORS' }
    $warnings = Get-ProtectedEvidenceField -InputObject $Snapshot -Name 'CollectionWarnings'
    Assert-ProtectedEvidenceArray -Value $warnings -Code 'INVALID_SNAPSHOT_WARNINGS'

    $sections = Get-ProtectedEvidenceField -InputObject $Snapshot -Name 'Sections'
    $arraySections = @(
        'Services', 'ScheduledTasks', 'RegistryAutoruns', 'StartupFolders', 'Processes', 'Connections',
        'InstalledPrograms', 'LocalAccounts', 'FirewallRules', 'WmiPersistence', 'RecentFiles',
        'Prefetch', 'ShimCache', 'BamDam', 'UserAssist', 'Amcache'
    )
    foreach ($sectionName in $arraySections) {
        $section = Get-ProtectedEvidenceField -InputObject $sections -Name $sectionName
        Assert-ProtectedEvidenceArray -Value $section -Code 'INVALID_SNAPSHOT_SECTION'
    }
    $capHit = Get-ProtectedEvidenceField -InputObject $sections -Name 'RecentFilesCapHit'
    if ($capHit -isnot [bool]) { Stop-ProtectedEvidenceValidation 'INVALID_SNAPSHOT_SECTION' }
    $srum = Get-ProtectedEvidenceField -InputObject $sections -Name 'Srum'
    $databasePresent = Get-ProtectedEvidenceField -InputObject $srum -Name 'DatabasePresent'
    if ($databasePresent -isnot [bool]) { Stop-ProtectedEvidenceValidation 'INVALID_SNAPSHOT_SECTION' }
    $srumFiles = Get-ProtectedEvidenceField -InputObject $srum -Name 'Files'
    Assert-ProtectedEvidenceArray -Value $srumFiles -Code 'INVALID_SNAPSHOT_SECTION'
    $systemSettings = Get-ProtectedEvidenceField -InputObject $sections -Name 'SystemSettings'
    $rdpEnabled = Get-ProtectedEvidenceField -InputObject $systemSettings -Name 'RdpEnabled'
    # The producer emits null when the registry value is unavailable; preserve
    # that unknown state rather than coercing it to false or rejecting the snapshot.
    if ($null -ne $rdpEnabled -and $rdpEnabled -isnot [bool]) { Stop-ProtectedEvidenceValidation 'INVALID_SNAPSHOT_SECTION' }
    $hostsFileLines = Get-ProtectedEvidenceField -InputObject $systemSettings -Name 'HostsFileLines'
    Assert-ProtectedEvidenceArray -Value $hostsFileLines -Code 'INVALID_SNAPSHOT_SECTION'
}

function Assert-ProtectedEvidencePlan {
    param(
        $Plan,
        $Context,
        [Parameter(Mandatory = $true)][object[]]$FindingsInstances
    )

    $version = Get-ProtectedEvidenceField -InputObject $Plan -Name 'PlanSchemaVersion'
    $versionIsInteger = ($version -is [System.Byte] -or $version -is [System.SByte] -or $version -is [System.Int16] -or
        $version -is [System.UInt16] -or $version -is [System.Int32] -or $version -is [System.UInt32] -or
        $version -is [System.Int64] -or $version -is [System.UInt64])
    if (-not $versionIsInteger -or $version -ne 2) { Stop-ProtectedEvidenceValidation 'UNSUPPORTED_PLAN_SCHEMA' }
    $runId = Get-ProtectedEvidenceField -InputObject $Plan -Name 'RunId'
    $computerName = Get-ProtectedEvidenceField -InputObject $Plan -Name 'ComputerName'
    $decision = Get-ProtectedEvidenceField -InputObject $Plan -Name 'Decision'
    $removalConfirmed = Get-ProtectedEvidenceField -InputObject $Plan -Name 'RemovalConfirmed'
    $plannedInstances = Get-ProtectedEvidenceField -InputObject $Plan -Name 'ScreenConnectInstances'
    if ($runId -isnot [string] -or $runId -cne $Context.DetectorRunId) { Stop-ProtectedEvidenceValidation 'PLAN_RUN_MISMATCH' }
    if ($computerName -isnot [string] -or -not [string]::Equals($computerName, $Context.ComputerName, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-ProtectedEvidenceValidation 'PLAN_HOST_MISMATCH'
    }
    if ($decision -isnot [string] -or $decision -cne 'ALL_REMOVE') { Stop-ProtectedEvidenceValidation 'PLAN_NOT_ALL_REMOVE' }
    if ($removalConfirmed -isnot [bool]) { Stop-ProtectedEvidenceValidation 'INVALID_PLAN_CONFIRMATION_FIELD' }
    Assert-ProtectedEvidenceArray -Value $plannedInstances -Code 'INVALID_PLAN_INSTANCES'
    if (-not (Test-ProtectedEvidenceSameInstanceSet -Observed $FindingsInstances -Planned $plannedInstances)) {
        Stop-ProtectedEvidenceValidation 'PLAN_INSTANCE_SET_MISMATCH'
    }
}

function New-ProtectedEvidenceResult {
    param(
        [Parameter(Mandatory = $true)][bool]$IsValid,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$FailureCode,
        [string]$ProtectedRunId,
        [string]$DetectorRunId,
        [string]$ComputerName,
        [int]$InstanceCount
    )

    return [pscustomobject][ordered]@{
        IsValid = $IsValid
        EvidenceStatus = if ($IsValid) { 'Validated' } else { 'Rejected' }
        FailureCode = $FailureCode
        ProtectedRunId = $ProtectedRunId
        DetectorRunId = $DetectorRunId
        ComputerName = $ComputerName
        InstanceCount = $InstanceCount
        ProvenanceEstablished = $false
        ApprovalStatus = 'NotApproved'
        RemovalAuthorized = $false
    }
}

function Test-ProtectedEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$FindingsBytes,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$SnapshotBytes,
        [AllowNull()]$TrustedProducerContext,
        [AllowNull()][string]$ExpectedTransactionId,
        [AllowNull()][string]$ExpectedSnapshotSha256,
        [Parameter(Mandatory = $true)]$Plan
    )

    $context = $null
    $instanceCount = 0
    try {
        # Caller-supplied context and expected values are consistency inputs,
        # never authentication, producer provenance, or removal authority.
        if (-not $PSBoundParameters.ContainsKey('TrustedProducerContext') -or $null -eq $TrustedProducerContext) {
            Stop-ProtectedEvidenceValidation 'MISSING_CONTEXT'
        }
        if (-not $PSBoundParameters.ContainsKey('ExpectedTransactionId') -or [string]::IsNullOrWhiteSpace($ExpectedTransactionId)) {
            Stop-ProtectedEvidenceValidation 'MISSING_EXPECTED_TRANSACTION'
        }
        if (-not $PSBoundParameters.ContainsKey('ExpectedSnapshotSha256') -or $ExpectedSnapshotSha256 -cnotmatch '^[0-9a-f]{64}$') {
            Stop-ProtectedEvidenceValidation 'INVALID_EXPECTED_SNAPSHOT_DIGEST'
        }
        if ($FindingsBytes.Length -lt 1 -or $FindingsBytes.Length -gt (16 * 1024 * 1024) -or
            $SnapshotBytes.Length -lt 1 -or $SnapshotBytes.Length -gt (64 * 1024 * 1024)) {
            Stop-ProtectedEvidenceValidation 'EVIDENCE_SIZE'
        }
        $context = Assert-ProtectedEvidenceContext -Context $TrustedProducerContext
        if (-not [string]::Equals($ExpectedTransactionId, $context.ProtectedRunId, [System.StringComparison]::Ordinal)) {
            Stop-ProtectedEvidenceValidation 'TRANSACTION_BINDING_MISMATCH'
        }
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $actualSnapshotSha256 = ([BitConverter]::ToString($sha256.ComputeHash($SnapshotBytes))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
        if (-not [string]::Equals($ExpectedSnapshotSha256, $actualSnapshotSha256, [System.StringComparison]::Ordinal)) {
            Stop-ProtectedEvidenceValidation 'SNAPSHOT_DIGEST_MISMATCH'
        }
        $findings = ConvertFrom-ProtectedEvidenceBytes -Bytes $FindingsBytes -MaximumBytes (16 * 1024 * 1024)
        $snapshot = ConvertFrom-ProtectedEvidenceBytes -Bytes $SnapshotBytes -MaximumBytes (64 * 1024 * 1024)
        $findingsInstances = Assert-ProtectedEvidenceFindings -Findings $findings -Context $context
        $instanceCount = $findingsInstances.Count
        Assert-ProtectedEvidenceSnapshot -Snapshot $snapshot -Context $context
        Assert-ProtectedEvidencePlan -Plan $Plan -Context $context -FindingsInstances $findingsInstances
        return (New-ProtectedEvidenceResult -IsValid $true -FailureCode '' -ProtectedRunId $context.ProtectedRunId -DetectorRunId $context.DetectorRunId -ComputerName $context.ComputerName -InstanceCount $instanceCount)
    } catch {
        $failureCode = 'INVALID_EVIDENCE'
        $message = [string]$_.Exception.Message
        if ($message -cmatch '^PE_[A-Z0-9_]+$') { $failureCode = $message.Substring(3) }
        return (New-ProtectedEvidenceResult -IsValid $false -FailureCode $failureCode -ProtectedRunId $(if ($null -ne $context) { $context.ProtectedRunId } else { '' }) -DetectorRunId $(if ($null -ne $context) { $context.DetectorRunId } else { '' }) -ComputerName $(if ($null -ne $context) { $context.ComputerName } else { '' }) -InstanceCount $instanceCount)
    }
}
