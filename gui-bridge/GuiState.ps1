<#
  GUI state file writer. This file only validates and publishes gui-state.json;
  it does not launch or invoke any investigation stage.
  PowerShell 5.1 compatible. Pure ASCII, no BOM.
#>

$script:GuiStateStageDefinitions = @(
    @{ Id = 0; Name = 'Preflight' },
    @{ Id = 1; Name = 'Snapshot (Before)' },
    @{ Id = 2; Name = 'Detect' },
    @{ Id = 3; Name = 'Review Gate' },
    @{ Id = 4; Name = 'Contain + Remove' },
    @{ Id = 5; Name = 'Scanners' },
    @{ Id = 6; Name = 'Uninstall installed AV' },
    @{ Id = 7; Name = 'Procmon' },
    @{ Id = 8; Name = 'Snapshot (After)+Diff' },
    @{ Id = 9; Name = 'Report' }
)
$script:GuiStateStatuses = @('Pending', 'Running', 'NeedsAction', 'Completed', 'Warning', 'Failed', 'Skipped', 'RebootPending', 'Incomplete')
$script:GuiStateArtifactRoles = @('findings', 'beforeSnapshot', 'plan', 'removalManifest', 'scannerResults', 'avUninstallResults', 'procmon', 'afterSnapshot', 'diff', 'results', 'report', 'sanitizedPackage', 'log')
$script:GuiStateMaxJsonChars = 1048576
$script:GuiStateMaxMessages = 100
$script:GuiStateMaxMessageChars = 2048
$script:GuiStateMaxMessageTotalChars = 32768

function New-GuiState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$ComputerName
    )

    $now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $stages = @()
    foreach ($definition in $script:GuiStateStageDefinitions) {
        $stages += [pscustomobject][ordered]@{
            id = $definition.Id
            name = $definition.Name
            status = 'Pending'
            operation = ''
            startedUtc = $null
            endedUtc = $null
        }
    }

    return [pscustomobject][ordered]@{
        schemaVersion = 1
        runId = $RunId
        computerName = $ComputerName
        overallStatus = 'Pending'
        currentStage = $null
        stages = $stages
        warnings = @()
        errors = @()
        artifacts = [ordered]@{}
        updatedUtc = $now
    }
}

function Get-GuiStateFieldNames {
    param($InputObject)

    if ($InputObject -is [System.Collections.IDictionary]) {
        return , @($InputObject.Keys | ForEach-Object { [string]$_ })
    }
    if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [System.Array]) {
        throw 'Expected a JSON object.'
    }
    return , @($InputObject.PSObject.Properties | ForEach-Object { [string]$_.Name })
}

function Get-GuiStateField {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -ceq $Name) {
                $value = $InputObject[$key]
                if ($value -is [System.Array]) { return ,$value }
                return $value
            }
        }
        throw "Missing required field '$Name'."
    }
    if ($null -ne $InputObject) {
        foreach ($property in $InputObject.PSObject.Properties) {
            if ([string]$property.Name -ceq $Name) {
                $value = $property.Value
                if ($value -is [System.Array]) { return ,$value }
                return $value
            }
        }
    }
    throw "Missing required field '$Name'."
}

function Assert-GuiStateFields {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = Get-GuiStateFieldNames $InputObject
    foreach ($name in $Expected) {
        if (@($actual | Where-Object { $_ -ceq $name }).Count -ne 1) {
            throw "$Label must contain exactly one '$name' field."
        }
    }
    foreach ($name in $actual) {
        if ($Expected -cnotcontains $name) { throw "$Label contains unknown field '$name'." }
    }
    if ($actual.Count -ne $Expected.Count) { throw "$Label has an invalid field count." }
}

function Test-GuiStateInteger {
    param($Value)
    return ($Value -is [int] -or $Value -is [long] -or $Value -is [short])
}

function ConvertTo-GuiUtcDateTime {
    param(
        $Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$AllowNull
    )

    if ($null -eq $Value) {
        if ($AllowNull) { return $null }
        throw "$Label is required."
    }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    if ($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') {
        throw "$Label must be a UTC timestamp in yyyy-MM-ddTHH:mm:ssZ form."
    }
    try {
        return [DateTime]::ParseExact(
            $Value,
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        )
    } catch {
        throw "$Label is not a valid UTC timestamp."
    }
}

function Get-GuiStatePathAttributes {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        return [System.IO.File]::GetAttributes($Path)
    } catch [System.IO.FileNotFoundException] {
        return $null
    } catch [System.IO.DirectoryNotFoundException] {
        return $null
    }
}

function Assert-GuiStateNoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$RequireDirectory
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrEmpty($volumeRoot)) { throw "Cannot resolve path root for '$Path'." }

    $current = $volumeRoot
    $rootAttributes = Get-GuiStatePathAttributes $current
    if ($null -ne $rootAttributes -and ($rootAttributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Reparse-point path component is not allowed: '$current'."
    }

    $tail = $fullPath.Substring($volumeRoot.Length)
    $parts = @($tail.Split([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar), [StringSplitOptions]::RemoveEmptyEntries))
    for ($index = 0; $index -lt $parts.Count; $index++) {
        $current = [System.IO.Path]::Combine($current, $parts[$index])
        $attributes = Get-GuiStatePathAttributes $current
        if ($null -eq $attributes) { continue }
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse-point path component is not allowed: '$current'."
        }
        if ($index -lt ($parts.Count - 1) -and ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
            throw "A file blocks the directory path '$current'."
        }
    }

    if ($RequireDirectory) {
        if (-not [System.IO.Directory]::Exists($fullPath)) { throw "Run root is not an existing directory: '$fullPath'." }
    }
    return $fullPath
}

function Get-GuiStateRootLeaf {
    param([Parameter(Mandatory = $true)][string]$FullPath)

    $trimChars = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $trimmed = $FullPath.TrimEnd($trimChars)
    if ([string]::IsNullOrEmpty($trimmed)) { return '' }
    return [System.IO.Path]::GetFileName($trimmed)
}

function Assert-GuiArtifactPath {
    param(
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Role
    )

    if ($script:GuiStateArtifactRoles -cnotcontains $Role) { throw "Unknown artifact role '$Role'." }
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath.Length -gt 512) { throw "Artifact '$Role' path is empty or too long." }
    if ($RelativePath -match '[\\:]' -or $RelativePath.StartsWith('/') -or $RelativePath.StartsWith('//')) {
        throw "Artifact '$Role' path must be run-root-relative and use forward slashes."
    }
    if ($RelativePath -match '[\x00-\x1f\x7f<>"|?*]') { throw "Artifact '$Role' path contains an invalid character." }

    $segments = @($RelativePath.Split([char[]]@('/'), [StringSplitOptions]::None))
    if ($segments.Count -eq 0) { throw "Artifact '$Role' path is empty." }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -ceq '.' -or $segment -ceq '..') {
            throw "Artifact '$Role' path contains an empty or traversal segment."
        }
        if ($segment -match '^[.]+$' -or $segment -match '[. ]$') { throw "Artifact '$Role' path contains an unsafe segment." }
        $deviceStem = ($segment -split '\.')[0]
        if ($deviceStem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            throw "Artifact '$Role' path uses a reserved device name."
        }
    }

    $candidate = $RunRoot
    foreach ($segment in $segments) { $candidate = [System.IO.Path]::Combine($candidate, $segment) }
    $fullCandidate = [System.IO.Path]::GetFullPath($candidate)
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $rootPrefix = $RunRoot.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) + $separator
    $comparison = if ($env:OS -eq 'Windows_NT') { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not $fullCandidate.StartsWith($rootPrefix, $comparison)) { throw "Artifact '$Role' escapes the run root after canonicalization." }
    [void](Assert-GuiStateNoReparsePath -Path $fullCandidate)
    $attributes = Get-GuiStatePathAttributes $fullCandidate
    if ($null -ne $attributes -and ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        throw "Artifact '$Role' path points to a directory, not a file."
    }
}

function Assert-GuiStringArray {
    param(
        $Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -isnot [System.Array] -or $Value.Rank -ne 1) { throw "$Label must be an array of strings." }
    if ($Value.Count -gt $script:GuiStateMaxMessages) { throw "$Label exceeds the maximum of $($script:GuiStateMaxMessages) entries." }
    $total = 0
    foreach ($entry in $Value) {
        if ($entry -isnot [string]) { throw "$Label must contain only strings." }
        if ($entry.Length -gt $script:GuiStateMaxMessageChars) { throw "$Label contains an entry that is too long." }
        $total += $entry.Length
    }
    if ($total -gt $script:GuiStateMaxMessageTotalChars) { throw "$Label exceeds the total text limit." }
}

function Assert-GuiStateDocument {
    param(
        $State,
        [Parameter(Mandatory = $true)][string]$RunRoot
    )

    Assert-GuiStateFields $State @('schemaVersion', 'runId', 'computerName', 'overallStatus', 'currentStage', 'stages', 'warnings', 'errors', 'artifacts', 'updatedUtc') 'State'

    $schemaVersion = Get-GuiStateField $State 'schemaVersion'
    if (-not (Test-GuiStateInteger $schemaVersion) -or $schemaVersion -ne 1) { throw 'schemaVersion must be integer 1.' }

    $runId = Get-GuiStateField $State 'runId'
    if ($runId -isnot [string] -or $runId.Length -lt 1 -or $runId.Length -gt 128 -or $runId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'runId is empty, too long, or contains unsafe characters.'
    }
    if ($runId -ceq '.' -or $runId -ceq '..') { throw 'runId is invalid.' }

    $computerName = Get-GuiStateField $State 'computerName'
    if ($computerName -isnot [string] -or $computerName.Length -lt 1 -or $computerName.Length -gt 63 -or $computerName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'computerName is empty, too long, or contains unsafe characters.'
    }

    $fullRunRoot = Assert-GuiStateNoReparsePath -Path $RunRoot -RequireDirectory
    if ((Get-GuiStateRootLeaf $fullRunRoot) -cne $runId) { throw 'runId must match the run-root directory leaf exactly.' }

    $overallStatus = Get-GuiStateField $State 'overallStatus'
    if ($overallStatus -isnot [string] -or $script:GuiStateStatuses -cnotcontains $overallStatus) { throw 'overallStatus is not a recognized state.' }

    $currentStage = Get-GuiStateField $State 'currentStage'
    if ($null -ne $currentStage -and (-not (Test-GuiStateInteger $currentStage) -or $currentStage -lt 0 -or $currentStage -gt 9)) {
        throw 'currentStage must be null or an integer from 0 through 9.'
    }

    $stages = Get-GuiStateField $State 'stages'
    if ($stages -isnot [System.Array] -or $stages.Rank -ne 1 -or $stages.Count -ne 10) { throw 'stages must contain exactly ten records.' }
    for ($index = 0; $index -lt 10; $index++) {
        $stage = $stages[$index]
        Assert-GuiStateFields $stage @('id', 'name', 'status', 'operation', 'startedUtc', 'endedUtc') "Stage[$index]"
        $id = Get-GuiStateField $stage 'id'
        $name = Get-GuiStateField $stage 'name'
        $status = Get-GuiStateField $stage 'status'
        $operation = Get-GuiStateField $stage 'operation'
        if (-not (Test-GuiStateInteger $id) -or $id -ne $index) { throw "Stage[$index] has an invalid id or order." }
        if ($name -isnot [string] -or $name -cne $script:GuiStateStageDefinitions[$index].Name) { throw "Stage[$index] name does not match the engine stage table." }
        if ($status -isnot [string] -or $script:GuiStateStatuses -cnotcontains $status) { throw "Stage[$index] has an unrecognized status." }
        if ($operation -isnot [string] -or $operation.Length -gt 1024) { throw "Stage[$index] operation must be a string no longer than 1024 characters." }
        $started = ConvertTo-GuiUtcDateTime (Get-GuiStateField $stage 'startedUtc') "Stage[$index].startedUtc" -AllowNull
        $ended = ConvertTo-GuiUtcDateTime (Get-GuiStateField $stage 'endedUtc') "Stage[$index].endedUtc" -AllowNull
        if ($null -ne $started -and $null -ne $ended -and $ended -lt $started) { throw "Stage[$index] endedUtc precedes startedUtc." }
    }

    Assert-GuiStringArray (Get-GuiStateField $State 'warnings') 'warnings'
    Assert-GuiStringArray (Get-GuiStateField $State 'errors') 'errors'

    $artifacts = Get-GuiStateField $State 'artifacts'
    $artifactNames = Get-GuiStateFieldNames $artifacts
    if ($artifactNames.Count -gt $script:GuiStateArtifactRoles.Count) { throw 'artifacts contains too many entries.' }
    foreach ($role in $artifactNames) {
        if ($script:GuiStateArtifactRoles -cnotcontains $role) { throw "Unknown artifact role '$role'." }
        $relativePath = Get-GuiStateField $artifacts $role
        if ($relativePath -isnot [string]) { throw "Artifact '$role' path must be a string." }
        Assert-GuiArtifactPath -RunRoot $fullRunRoot -RelativePath $relativePath -Role $role
    }

    [void](ConvertTo-GuiUtcDateTime (Get-GuiStateField $State 'updatedUtc') 'updatedUtc')
    if ($overallStatus -ceq 'Completed') {
        foreach ($stage in $stages) {
            $stageStatus = Get-GuiStateField $stage 'status'
            if ($stageStatus -cnotin @('Completed', 'Skipped')) { throw 'overallStatus cannot be Completed while a stage is not Completed or Skipped.' }
        }
    }
    return $fullRunRoot
}

function Assert-GuiStateTransitions {
    param($Previous, $Next)

    $previousOverall = Get-GuiStateField $Previous 'overallStatus'
    $nextOverall = Get-GuiStateField $Next 'overallStatus'
    if ($previousOverall -cne $nextOverall) {
        Assert-GuiStateTransition -From $previousOverall -To $nextOverall -Label 'overallStatus'
    }

    $previousStages = Get-GuiStateField $Previous 'stages'
    $nextStages = Get-GuiStateField $Next 'stages'
    for ($index = 0; $index -lt 10; $index++) {
        $from = Get-GuiStateField $previousStages[$index] 'status'
        $to = Get-GuiStateField $nextStages[$index] 'status'
        if ($from -cne $to) { Assert-GuiStateTransition -From $from -To $to -Label "Stage[$index]" }
    }
    if ((Get-GuiStateField $Previous 'runId') -cne (Get-GuiStateField $Next 'runId')) { throw 'runId cannot change during a run.' }
    if ((Get-GuiStateField $Previous 'computerName') -cne (Get-GuiStateField $Next 'computerName')) { throw 'computerName cannot change during a run.' }
}

function Assert-GuiStateTransition {
    param(
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$To,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $allowed = @()
    switch -CaseSensitive ($From) {
        'Pending' { $allowed = @('Running', 'Skipped') }
        'Running' { $allowed = @('NeedsAction', 'Completed', 'Warning', 'Failed', 'Incomplete', 'RebootPending') }
        'NeedsAction' { $allowed = @('Running', 'Skipped', 'Incomplete') }
        # This library has no trusted resume-proof input; fail closed after reboot.
        'RebootPending' { $allowed = @('Incomplete') }
        default { $allowed = @() }
    }
    if ($allowed -cnotcontains $To) { throw "$Label cannot transition from '$From' to '$To'." }
}

function ConvertFrom-GuiJsonStringToken {
    param([Parameter(Mandatory = $true)][string]$Token)

    if ($Token.Length -lt 2 -or $Token[0] -cne '"' -or $Token[$Token.Length - 1] -cne '"') {
        throw 'Existing gui-state.json contains an invalid JSON member name.'
    }
    $builder = New-Object System.Text.StringBuilder
    for ($index = 1; $index -lt ($Token.Length - 1); $index++) {
        $character = $Token[$index]
        if ($character -cne '\') {
            if ([int]$character -lt 0x20) { throw 'Existing gui-state.json contains an invalid JSON member name.' }
            [void]$builder.Append($character)
            continue
        }

        $index++
        if ($index -ge ($Token.Length - 1)) { throw 'Existing gui-state.json contains an invalid JSON member escape.' }
        switch -CaseSensitive ($Token[$index]) {
            '"' { [void]$builder.Append('"') }
            '\' { [void]$builder.Append('\') }
            '/' { [void]$builder.Append('/') }
            'b' { [void]$builder.Append([char]8) }
            'f' { [void]$builder.Append([char]12) }
            'n' { [void]$builder.Append([char]10) }
            'r' { [void]$builder.Append([char]13) }
            't' { [void]$builder.Append([char]9) }
            'u' {
                if (($index + 4) -ge ($Token.Length - 1)) { throw 'Existing gui-state.json contains an invalid Unicode member escape.' }
                $hex = $Token.Substring($index + 1, 4)
                if ($hex -cnotmatch '^[0-9A-Fa-f]{4}$') { throw 'Existing gui-state.json contains an invalid Unicode member escape.' }
                [void]$builder.Append([char][Convert]::ToInt32($hex, 16))
                $index += 4
            }
            default { throw 'Existing gui-state.json contains an invalid JSON member escape.' }
        }
    }
    return $builder.ToString()
}

function Assert-GuiJsonNoDuplicateMembers {
    param([Parameter(Mandatory = $true)][string]$Json)

    $objectMembers = New-Object System.Collections.ArrayList
    $index = 0
    while ($index -lt $Json.Length) {
        $character = $Json[$index]
        if ($character -ceq '"') {
            $start = $index
            $index++
            $closed = $false
            while ($index -lt $Json.Length) {
                if ($Json[$index] -ceq '\') {
                    $index += 2
                    continue
                }
                if ($Json[$index] -ceq '"') {
                    $index++
                    $closed = $true
                    break
                }
                $index++
            }
            if (-not $closed) { throw 'Existing gui-state.json contains an unterminated JSON string.' }

            $afterString = $index
            while ($afterString -lt $Json.Length -and ($Json[$afterString] -ceq ' ' -or $Json[$afterString] -ceq "`t" -or $Json[$afterString] -ceq "`r" -or $Json[$afterString] -ceq "`n")) {
                $afterString++
            }
            if ($afterString -lt $Json.Length -and $Json[$afterString] -ceq ':') {
                if ($objectMembers.Count -eq 0) { throw 'Existing gui-state.json has a member outside an object.' }
                $nameToken = $Json.Substring($start, $index - $start)
                $name = ConvertFrom-GuiJsonStringToken -Token $nameToken
                $members = $objectMembers[$objectMembers.Count - 1]
                if (-not $members.Add($name)) { throw "Existing gui-state.json contains duplicate member name '$name'." }
                $index = $afterString + 1
                continue
            }
            continue
        }
        if ($character -ceq ':' -or $character -ceq '/' -or $character -ceq "'") {
            throw 'Existing gui-state.json must use strict JSON member syntax.'
        }
        if ($character -ceq '{') {
            $members = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            [void]$objectMembers.Add($members)
        } elseif ($character -ceq '}' -and $objectMembers.Count -gt 0) {
            $objectMembers.RemoveAt($objectMembers.Count - 1)
        }
        $index++
    }
}

function Read-GuiStateDocument {
    param([Parameter(Mandatory = $true)][string]$Path)

    $attributes = Get-GuiStatePathAttributes $Path
    if ($null -eq $attributes) { return $null }
    if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) { throw "State target is a directory: '$Path'." }
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'State target cannot be a reparse point.' }
    $readStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($readStream.Length -gt $script:GuiStateMaxJsonChars) { throw 'Existing gui-state.json exceeds the size limit.' }
        $buffer = New-Object byte[] ($script:GuiStateMaxJsonChars + 1)
        $byteCount = 0
        while ($byteCount -lt $buffer.Length) {
            $readCount = $readStream.Read($buffer, $byteCount, ($buffer.Length - $byteCount))
            if ($readCount -eq 0) { break }
            $byteCount += $readCount
        }
        if ($byteCount -gt $script:GuiStateMaxJsonChars) { throw 'Existing gui-state.json exceeds the size limit.' }
        $bytes = New-Object byte[] $byteCount
        [System.Array]::Copy($buffer, $bytes, $byteCount)
    } finally {
        $readStream.Dispose()
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
        throw 'Existing gui-state.json must be UTF-8 without a BOM.'
    }
    try {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $raw = $strictUtf8.GetString($bytes)
    } catch {
        throw 'Existing gui-state.json is not valid UTF-8.'
    }
    if ($raw.Length -eq 0 -or $raw.Length -gt $script:GuiStateMaxJsonChars) { throw 'Existing gui-state.json is empty or exceeds the size limit.' }
    Assert-GuiJsonNoDuplicateMembers -Json $raw
    try {
        $parsed = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    } catch {
        throw 'Existing gui-state.json is malformed; refusing to overwrite it.'
    }
    if ($null -eq $parsed -or $parsed -is [System.Array] -or $parsed -is [string]) { throw 'Existing gui-state.json root must be an object.' }
    return ,@($parsed, $raw)
}

function ConvertTo-GuiStateJsonDocument {
    param($State)

    $format = 'yyyy-MM-ddTHH:mm:ssZ'
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $stages = @()
    foreach ($stage in (Get-GuiStateField $State 'stages')) {
        $started = ConvertTo-GuiUtcDateTime (Get-GuiStateField $stage 'startedUtc') 'startedUtc' -AllowNull
        $ended = ConvertTo-GuiUtcDateTime (Get-GuiStateField $stage 'endedUtc') 'endedUtc' -AllowNull
        $startedText = if ($null -eq $started) { $null } else { $started.ToString($format, $culture) }
        $endedText = if ($null -eq $ended) { $null } else { $ended.ToString($format, $culture) }
        $id = Get-GuiStateField $stage 'id'
        $name = Get-GuiStateField $stage 'name'
        $status = Get-GuiStateField $stage 'status'
        $operation = Get-GuiStateField $stage 'operation'
        $stages += [ordered]@{
            id = $id
            name = $name
            status = $status
            operation = $operation
            startedUtc = $startedText
            endedUtc = $endedText
        }
    }

    $artifacts = [ordered]@{}
    $sourceArtifacts = Get-GuiStateField $State 'artifacts'
    foreach ($role in (Get-GuiStateFieldNames $sourceArtifacts)) {
        $artifacts[$role] = Get-GuiStateField $sourceArtifacts $role
    }
    $updated = ConvertTo-GuiUtcDateTime (Get-GuiStateField $State 'updatedUtc') 'updatedUtc'
    $warnings = Get-GuiStateField $State 'warnings'
    $errors = Get-GuiStateField $State 'errors'
    $schemaVersion = Get-GuiStateField $State 'schemaVersion'
    $runId = Get-GuiStateField $State 'runId'
    $computerName = Get-GuiStateField $State 'computerName'
    $overallStatus = Get-GuiStateField $State 'overallStatus'
    $currentStage = Get-GuiStateField $State 'currentStage'
    return [ordered]@{
        schemaVersion = $schemaVersion
        runId = $runId
        computerName = $computerName
        overallStatus = $overallStatus
        currentStage = $currentStage
        stages = $stages
        warnings = $warnings
        errors = $errors
        artifacts = $artifacts
        updatedUtc = $updated.ToString($format, $culture)
    }
}

function Write-GuiState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$State
    )
    process {
        $fullRunRoot = Assert-GuiStateDocument -State $State -RunRoot $RunRoot
        $targetPath = [System.IO.Path]::Combine($fullRunRoot, 'gui-state.json')
        [void](Assert-GuiStateNoReparsePath -Path $targetPath)

        $previousRecord = Read-GuiStateDocument -Path $targetPath
        $previous = $null
        $previousRaw = $null
        if ($null -ne $previousRecord) {
            $previous = $previousRecord[0]
            $previousRaw = [string]$previousRecord[1]
            [void](Assert-GuiStateDocument -State $previous -RunRoot $fullRunRoot)
            Assert-GuiStateTransitions -Previous $previous -Next $State
        } else {
            if ((Get-GuiStateField $State 'overallStatus') -cne 'Pending') { throw 'The first state publication must be Pending.' }
            if ($null -ne (Get-GuiStateField $State 'currentStage')) { throw 'The first state publication must not have a current stage.' }
            foreach ($stage in (Get-GuiStateField $State 'stages')) {
                if ((Get-GuiStateField $stage 'status') -cne 'Pending') { throw 'The first state publication must initialize every stage as Pending.' }
            }
        }

        $jsonDocument = ConvertTo-GuiStateJsonDocument -State $State
        $json = ConvertTo-Json -InputObject $jsonDocument -Depth 8 -ErrorAction Stop
        if ([string]::IsNullOrEmpty($json) -or $json.Length -gt $script:GuiStateMaxJsonChars) { throw 'Serialized gui-state.json is empty or exceeds the size limit.' }
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $bytes = $encoding.GetBytes($json)
        if ($bytes.Length -gt $script:GuiStateMaxJsonChars) { throw 'Serialized gui-state.json exceeds the byte size limit.' }
        $tempPath = [System.IO.Path]::Combine($fullRunRoot, ('.gui-state.json.' + [Guid]::NewGuid().ToString('N') + '.tmp'))
        $stream = $null
        try {
            [void](Assert-GuiStateNoReparsePath -Path $fullRunRoot -RequireDirectory)
            [void](Assert-GuiStateNoReparsePath -Path $targetPath)
            if ($null -ne $previousRaw) {
                $currentRaw = [System.IO.File]::ReadAllText($targetPath, [System.Text.Encoding]::UTF8)
                if ($currentRaw -cne $previousRaw) { throw 'gui-state.json changed during validation; refusing to overwrite it.' }
            } elseif ([System.IO.File]::Exists($targetPath)) {
                throw 'gui-state.json appeared during validation; refusing to overwrite it.'
            }

            $stream = New-Object System.IO.FileStream($tempPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
            $stream.Dispose()
            $stream = $null

            [void](Assert-GuiStateNoReparsePath -Path $fullRunRoot -RequireDirectory)
            [void](Assert-GuiStateNoReparsePath -Path $targetPath)
            if ($null -ne $previousRaw) {
                $currentRaw = [System.IO.File]::ReadAllText($targetPath, [System.Text.Encoding]::UTF8)
                if ($currentRaw -cne $previousRaw) { throw 'gui-state.json changed during publication; refusing to overwrite it.' }
                if ($env:OS -eq 'Windows_NT') {
                    [System.IO.File]::Replace($tempPath, $targetPath, $null)
                } else {
                    # Unix .NET requires a non-empty backup path for File.Replace.
                    $backupPath = [System.IO.Path]::Combine($fullRunRoot, ('.gui-state.json.' + [Guid]::NewGuid().ToString('N') + '.bak'))
                    [System.IO.File]::Replace($tempPath, $targetPath, $backupPath)
                    try { [System.IO.File]::Delete($backupPath) } catch { }
                }
            } else {
                [System.IO.File]::Move($tempPath, $targetPath)
            }
            return $targetPath
        } catch {
            if ($null -ne $stream) { $stream.Dispose() }
            if ([System.IO.File]::Exists($tempPath)) {
                try { [System.IO.File]::Delete($tempPath) } catch { }
            }
            throw
        }
    }
}
