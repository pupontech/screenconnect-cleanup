Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$libraryPath = Join-Path $repoRoot 'gui-bridge/ProtectedRollbackProof.ps1'
if (-not (Test-Path -LiteralPath $libraryPath -PathType Leaf)) { throw "Missing library: $libraryPath" }

$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "FAIL: $Message" }
}
function Assert-Rejected {
    param(
        $Receipt,
        [string]$ExpectedHkcuSid,
        [string]$ExpectedFailureCode,
        [string]$Message
    )
    $receiptBytes = ConvertTo-TestReceiptBytes -Receipt $Receipt
    $result = Test-ProtectedRollbackProof -ReceiptBytes $receiptBytes -ExpectedHkcuSid $ExpectedHkcuSid
    Assert-True ((-not $result.IsValid) -and $result.FailureCode -ceq $ExpectedFailureCode) $Message
}
function New-ValidReceipt {
    $transactionId = '0123456789abcdef0123456789abcdef'
    $description = 'ScreenConnect Cleanup GUI ' + $transactionId
    $restorePointIdentity = [ordered]@{
        sequenceNumber = 11
        description = $description
        creationTimeUtc = '2026-09-24T12:34:56Z'
    }
    return [ordered]@{
        schemaVersion = 1
        transactionId = $transactionId
        status = 'Verified'
        restorePointWaiverUsed = $false
        effectiveUserSid = 'S-1-5-21-100-200-300-1001'
        restorePoint = [ordered]@{
            attempted = $true
            status = 'Verified'
            description = $description
            preSequenceNumber = 10
            postSequenceNumber = 11
            identity = [ordered]@{
                sequenceNumber = $restorePointIdentity.sequenceNumber
                description = $restorePointIdentity.description
                creationTimeUtc = $restorePointIdentity.creationTimeUtc
            }
            queryRecords = @($restorePointIdentity)
        }
        registryExports = @(
            [ordered]@{
                hive = 'HKLM\SOFTWARE'
                status = 'Verified'
                exitCode = 0
                relativePath = 'rollback\registry_hives\HKLM_SOFTWARE.reg'
                length = 1024
                sha256 = ('a' * 64)
                hiveUserSid = $null
            },
            [ordered]@{
                hive = 'HKLM\SYSTEM'
                status = 'Verified'
                exitCode = 0
                relativePath = 'rollback\registry_hives\HKLM_SYSTEM.reg'
                length = 2048
                sha256 = ('b' * 64)
                hiveUserSid = $null
            },
            [ordered]@{
                hive = 'HKCU\SOFTWARE'
                status = 'Verified'
                exitCode = 0
                relativePath = 'rollback\registry_hives\HKCU_SOFTWARE.reg'
                length = 512
                sha256 = ('c' * 64)
                hiveUserSid = 'S-1-5-21-100-200-300-1001'
            }
        )
        failureCodes = @()
    }
}
function ConvertTo-TestReceiptBytes {
    param($Receipt)
    $json = ConvertTo-Json -InputObject $Receipt -Depth 32 -Compress -ErrorAction Stop
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    return ,$encoding.GetBytes($json)
}
function ConvertTo-TestReceiptJsonBytes {
    param([string]$Json)
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    return ,$encoding.GetBytes($Json)
}
function Assert-ReceiptJsonFailureCode {
    param(
        [string]$Json,
        [string]$ExpectedHkcuSid,
        [string]$ExpectedFailureCode,
        [string]$Message
    )
    $result = Test-ProtectedRollbackProof -ReceiptBytes (ConvertTo-TestReceiptJsonBytes -Json $Json) -ExpectedHkcuSid $ExpectedHkcuSid
    Assert-True ((-not $result.IsValid) -and $result.FailureCode -ceq $ExpectedFailureCode) $Message
}
function New-TestNestedArrayJson {
    param([int]$Depth)
    $builder = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $Depth; $i++) { [void]$builder.Append('[') }
    [void]$builder.Append('0')
    for ($i = 0; $i -lt $Depth; $i++) { [void]$builder.Append(']') }
    return $builder.ToString()
}
function New-TestJsonArray {
    param([int]$ValueCount)
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('[')
    for ($i = 0; $i -lt $ValueCount; $i++) {
        if ($i -gt 0) { [void]$builder.Append(',') }
        [void]$builder.Append('0')
    }
    [void]$builder.Append(']')
    return $builder.ToString()
}
function New-TestJsonObject {
    param([int]$MemberCount)
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('{')
    for ($i = 0; $i -lt $MemberCount; $i++) {
        if ($i -gt 0) { [void]$builder.Append(',') }
        [void]$builder.Append(('"member{0}":0' -f $i))
    }
    [void]$builder.Append('}')
    return $builder.ToString()
}

$tokens = $null
$parseErrors = $null
$libraryAst = [System.Management.Automation.Language.Parser]::ParseFile($libraryPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Library parse failed: $($parseErrors[0].Message)" }
$testTokens = $null
$testParseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$testTokens, [ref]$testParseErrors)
if ($testParseErrors.Count -gt 0) { throw "Test parse failed: $($testParseErrors[0].Message)" }

foreach ($sourcePath in @($libraryPath, $PSCommandPath)) {
    $sourceBytes = [System.IO.File]::ReadAllBytes($sourcePath)
    $hasBom = $sourceBytes.Length -ge 3 -and $sourceBytes[0] -eq 239 -and $sourceBytes[1] -eq 187 -and $sourceBytes[2] -eq 191
    Assert-True (-not $hasBom) "PowerShell source has no BOM: $sourcePath"
    $isAscii = $true
    foreach ($byte in $sourceBytes) { if ($byte -gt 127) { $isAscii = $false; break } }
    Assert-True $isAscii "PowerShell source is pure ASCII: $sourcePath"
}

$allowedLibraryCommands = @(
    'Stop-ProtectedRollbackProofValidation',
    'Get-ProtectedRollbackFieldNames',
    'Assert-ProtectedRollbackObjectFields',
    'Get-ProtectedRollbackFieldValue',
    'Assert-ProtectedRollbackText',
    'Assert-ProtectedRollbackInteger',
    'Assert-ProtectedRollbackSid',
    'Assert-ProtectedRollbackUtcTimestamp',
    'New-ProtectedRollbackProofResult',
    'Read-ProtectedRollbackJsonString',
    'Skip-ProtectedRollbackJsonWhitespace',
    'ConvertFrom-ProtectedRollbackJsonValue',
    'ConvertFrom-ProtectedRollbackBytes'
)
$libraryCommands = @($libraryAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
foreach ($command in $libraryCommands) {
    $commandName = $command.GetCommandName()
    Assert-True ($allowedLibraryCommands -ccontains $commandName) "validator invokes only an internal pure helper: $commandName"
}

. $libraryPath
$expectedSid = 'S-1-5-21-100-200-300-1001'
$validReceipt = New-ValidReceipt
$validBytes = ConvertTo-TestReceiptBytes -Receipt $validReceipt
$validResult = Test-ProtectedRollbackProof -ReceiptBytes $validBytes -ExpectedHkcuSid $expectedSid
Assert-True $validResult.IsValid ("complete synthetic Stage 0 receipt is accepted (failure code: $($validResult.FailureCode))")
Assert-True ($null -eq $validResult.FailureCode) 'valid proof has no failure code'
Assert-True ($validResult.RestorePointSequenceNumber -eq 11 -and $validResult.RegistryExportCount -eq 3) 'valid proof reports the correlated identity and exact export count'

foreach ($duplicateJson in @(
    '{"schemaVersion":1,"schema\u0056ersion":1}',
    '{"outer":{"name":"first","na\u006De":"second"}}'
)) {
    $duplicateBytes = [System.Text.Encoding]::UTF8.GetBytes($duplicateJson)
    $duplicateResult = Test-ProtectedRollbackProof -ReceiptBytes $duplicateBytes -ExpectedHkcuSid $expectedSid
    Assert-True ((-not $duplicateResult.IsValid) -and $duplicateResult.FailureCode -ceq 'DUPLICATE_JSON_MEMBER') 'serialized duplicate decoded JSON keys are refused before receipt object validation'
}
$malformedResult = Test-ProtectedRollbackProof -ReceiptBytes ([System.Text.Encoding]::UTF8.GetBytes('{')) -ExpectedHkcuSid $expectedSid
Assert-True ((-not $malformedResult.IsValid) -and $malformedResult.FailureCode -ceq 'MALFORMED_JSON') 'malformed serialized receipt is rejected'
$invalidUtf8Result = Test-ProtectedRollbackProof -ReceiptBytes ([byte[]]@(0xC3, 0x28)) -ExpectedHkcuSid $expectedSid
Assert-True ((-not $invalidUtf8Result.IsValid) -and $invalidUtf8Result.FailureCode -ceq 'INVALID_ENCODING') 'invalid UTF-8 receipt is rejected'
$invalidSurrogateJson = @(
    '{"value":"\uD800"}',
    '{"value":"\uDC00"}',
    '{"value":"\uD800\u0041"}'
)
foreach ($json in $invalidSurrogateJson) {
    Assert-ReceiptJsonFailureCode -Json $json -ExpectedHkcuSid $expectedSid -ExpectedFailureCode 'MALFORMED_JSON' 'escaped lone or mismatched surrogate code units are rejected by the JSON parser'
}
$escapedPair = ConvertFrom-ProtectedRollbackBytes -Bytes (ConvertTo-TestReceiptJsonBytes -Json '{"value":"\uD83D\uDE00"}')
$escapedPairValue = [string]$escapedPair['value']
Assert-True ($escapedPairValue.Length -eq 2 -and [int]$escapedPairValue[0] -eq 55357 -and [int]$escapedPairValue[1] -eq 56832) 'well-formed escaped surrogate pair is accepted and decoded by the JSON parser'

$depth64 = ConvertFrom-ProtectedRollbackBytes -Bytes (ConvertTo-TestReceiptJsonBytes -Json (New-TestNestedArrayJson -Depth 64))
$depth64Value = $depth64
$depth64ShapeValid = $true
for ($i = 0; $i -lt 64; $i++) {
    if ($depth64Value -isnot [System.Array] -or $depth64Value.Count -ne 1) { $depth64ShapeValid = $false; break }
    $depth64Value = $depth64Value[0]
}
Assert-True ($depth64ShapeValid -and $depth64Value -eq 0) 'serialized depth-64 JSON is accepted at the parser boundary'
Assert-ReceiptJsonFailureCode -Json (New-TestNestedArrayJson -Depth 65) -ExpectedHkcuSid $expectedSid -ExpectedFailureCode 'JSON_TOO_DEEP' 'serialized depth-65 JSON fails at the depth limit rather than receipt schema validation'

$members8192 = ConvertFrom-ProtectedRollbackBytes -Bytes (ConvertTo-TestReceiptJsonBytes -Json (New-TestJsonObject -MemberCount 8192))
Assert-True ($members8192.Count -eq 8192) 'serialized object with exactly 8192 members is accepted at the parser boundary'
Assert-ReceiptJsonFailureCode -Json (New-TestJsonObject -MemberCount 8193) -ExpectedHkcuSid $expectedSid -ExpectedFailureCode 'TOO_MANY_JSON_MEMBERS' 'serialized object with 8193 members fails at the object-member limit'

$values250000 = ConvertFrom-ProtectedRollbackBytes -Bytes (ConvertTo-TestReceiptJsonBytes -Json (New-TestJsonArray -ValueCount 249999))
Assert-True ($values250000.Count -eq 249999) 'serialized JSON containing exactly 250000 values, including its root array, is accepted at the parser boundary'
Assert-ReceiptJsonFailureCode -Json (New-TestJsonArray -ValueCount 250000) -ExpectedHkcuSid $expectedSid -ExpectedFailureCode 'JSON_TOO_COMPLEX' 'serialized JSON containing 250001 values, including its root array, fails at the value-count limit'
$emptyReceiptResult = Test-ProtectedRollbackProof -ReceiptBytes ([byte[]]@()) -ExpectedHkcuSid $expectedSid
Assert-True ((-not $emptyReceiptResult.IsValid) -and $emptyReceiptResult.FailureCode -ceq 'RECEIPT_SIZE') 'empty receipt bytes are explicitly refused'
$oversizeReceiptBytes = New-Object byte[] (1MB + 1)
$oversizeResult = Test-ProtectedRollbackProof -ReceiptBytes $oversizeReceiptBytes -ExpectedHkcuSid $expectedSid
Assert-True ((-not $oversizeResult.IsValid) -and $oversizeResult.FailureCode -ceq 'RECEIPT_SIZE') 'receipt bytes above the fixed limit are rejected'

$case = New-ValidReceipt
$case['np'] = $true
Assert-Rejected $case $expectedSid 'INVALID_FIELDS' 'unknown -np waiver field is rejected'
$case = New-ValidReceipt
$case.restorePointWaiverUsed = $true
Assert-Rejected $case $expectedSid 'RESTORE_POINT_WAIVER' 'explicit restore-point waiver is rejected'
$case = New-ValidReceipt
$case.status = 'Incomplete'
Assert-Rejected $case $expectedSid 'INCOMPLETE_RECEIPT' 'incomplete top-level receipt is rejected'
$case = New-ValidReceipt
$case.failureCodes = @('REGISTRY_EXPORT_FAILED')
Assert-Rejected $case $expectedSid 'RECEIPT_HAS_FAILURES' 'recorded Stage 0 failure is rejected'
$case = New-ValidReceipt
$case.effectiveUserSid = 'S-1-5-21-100-200-300-1002'
Assert-Rejected $case $expectedSid 'HKCU_SID_MISMATCH' 'receipt effective SID must match expected HKCU SID'
Assert-Rejected (New-ValidReceipt) 'not-a-sid' 'INVALID_EXPECTED_HKCU_SID' 'malformed expected HKCU SID is rejected'

$case = New-ValidReceipt
$case.restorePoint.attempted = $false
Assert-Rejected $case $expectedSid 'RESTORE_POINT_NOT_VERIFIED' 'unattempted restore point is rejected'
$case = New-ValidReceipt
$case.restorePoint.status = 'Failed'
Assert-Rejected $case $expectedSid 'RESTORE_POINT_NOT_VERIFIED' 'failed restore point is rejected'
$case = New-ValidReceipt
$case.restorePoint.queryRecords = @()
Assert-Rejected $case $expectedSid 'RESTORE_POINT_QUERY_MISSING' 'missing restore-point query is rejected'
$case = New-ValidReceipt
$case.restorePoint.queryRecords += [ordered]@{
    sequenceNumber = 12
    description = $case.restorePoint.description
    creationTimeUtc = '2026-09-24T12:35:00Z'
}
Assert-Rejected $case $expectedSid 'AMBIGUOUS_RESTORE_POINT' 'ambiguous correlated restore points are rejected'
$case = New-ValidReceipt
$case.restorePoint.identity.sequenceNumber = 12
Assert-Rejected $case $expectedSid 'RESTORE_POINT_IDENTITY_MISMATCH' 'identity must match the unique queried point'
$case = New-ValidReceipt
$case.restorePoint.postSequenceNumber = 12
Assert-Rejected $case $expectedSid 'RESTORE_POINT_NOT_NEW' 'post-query sequence must equal the correlated new point'
$case = New-ValidReceipt
$case.restorePoint.preSequenceNumber = 11
Assert-Rejected $case $expectedSid 'RESTORE_POINT_NOT_NEW' 'restore-point sequence must be newer than the pre-capture sequence'
$case = New-ValidReceipt
$case.restorePoint.queryRecords[0].creationTimeUtc = 'not-a-time'
Assert-Rejected $case $expectedSid 'INVALID_RESTORE_POINT_TIME' 'malformed restore-point timestamp is rejected'
$case = New-ValidReceipt
$case.restorePoint.identity.description = 'different point'
Assert-Rejected $case $expectedSid 'RESTORE_POINT_IDENTITY_MISMATCH' 'identity description must match transaction description'

$case = New-ValidReceipt
$case.registryExports = @($case.registryExports[0], $case.registryExports[1])
Assert-Rejected $case $expectedSid 'REGISTRY_EXPORT_SET_MISMATCH' 'missing registry export is rejected'
$case = New-ValidReceipt
$case.registryExports += $case.registryExports[0]
Assert-Rejected $case $expectedSid 'DUPLICATE_REGISTRY_EXPORT' 'duplicate registry hive is rejected'
$case = New-ValidReceipt
$case.registryExports[2].hive = 'HKCU\SYSTEM'
Assert-Rejected $case $expectedSid 'REGISTRY_EXPORT_SET_MISMATCH' 'unexpected registry hive is rejected'
$case = New-ValidReceipt
$case.registryExports[1].status = 'Failed'
Assert-Rejected $case $expectedSid 'REGISTRY_EXPORT_FAILED' 'failed registry export is rejected'
$case = New-ValidReceipt
$case.registryExports[0].exitCode = 1
Assert-Rejected $case $expectedSid 'REGISTRY_EXPORT_FAILED' 'nonzero registry export exit is rejected'
$case = New-ValidReceipt
$case.registryExports[0].length = 0
Assert-Rejected $case $expectedSid 'INVALID_REGISTRY_LENGTH' 'empty registry export is rejected'
$case = New-ValidReceipt
$case.registryExports[1].sha256 = 'not-a-digest'
Assert-Rejected $case $expectedSid 'INVALID_REGISTRY_DIGEST' 'malformed registry digest is rejected'
$case = New-ValidReceipt
$case.registryExports[0].relativePath = 'C:\Users\Public\HKLM_SOFTWARE.reg'
Assert-Rejected $case $expectedSid 'UNTRUSTED_REGISTRY_PATH' 'absolute registry export path is rejected'
$case = New-ValidReceipt
$case.registryExports[1].relativePath = 'rollback\..\HKLM_SYSTEM.reg'
Assert-Rejected $case $expectedSid 'UNTRUSTED_REGISTRY_PATH' 'traversing registry export path is rejected'
$case = New-ValidReceipt
$case.registryExports[2].hiveUserSid = 'S-1-5-21-100-200-300-1002'
Assert-Rejected $case $expectedSid 'HKCU_SID_MISMATCH' 'HKCU export SID must match expected user SID'
$case = New-ValidReceipt
$case.registryExports[0].hiveUserSid = $expectedSid
Assert-Rejected $case $expectedSid 'UNEXPECTED_HIVE_SID' 'HKLM export cannot claim an HKCU user SID'
$case = New-ValidReceipt
$case.registryExports[2].sha256 = ('A' * 64)
Assert-Rejected $case $expectedSid 'INVALID_REGISTRY_DIGEST' 'noncanonical uppercase digest is rejected'
$case = New-ValidReceipt
$case.registryExports[0]['absolutePath'] = 'C:\Windows\Temp\hive.reg'
Assert-Rejected $case $expectedSid 'INVALID_FIELDS' 'extra export path field is rejected'

$case = New-ValidReceipt
$case.restorePoint.identity['Identity'] = 'duplicate case-variant field'
Assert-Rejected $case $expectedSid 'INVALID_FIELDS' 'unexpected case-variant identity field is rejected'
$case = New-ValidReceipt
$case.transactionId = 'not-a-guid'
Assert-Rejected $case $expectedSid 'INVALID_TRANSACTION_ID' 'malformed transaction identity is rejected'
$case = New-ValidReceipt
$case.schemaVersion = 2
Assert-Rejected $case $expectedSid 'UNSUPPORTED_SCHEMA' 'unknown receipt schema is rejected'

Write-Output ("PASS: $script:Assertions assertions; synthetic-only rollback proof validation.")
