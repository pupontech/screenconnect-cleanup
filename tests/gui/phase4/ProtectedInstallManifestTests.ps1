<#
  Synthetic protected-install manifest integrity tests.
  PowerShell 5.1 compatible. Pure ASCII, no BOM.
  Fixtures are serialized UTF-8 bytes held in memory; no installation is performed.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$validatorPath = Join-Path $repoRoot 'gui-bridge/ProtectedInstallManifest.ps1'
$schemaPath = Join-Path $repoRoot 'tests/gui/phase4/protected-install-manifest.schema.json'
if (-not (Test-Path -LiteralPath $validatorPath -PathType Leaf)) { throw 'Missing protected install manifest validator.' }
if (-not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) { throw 'Missing protected install manifest schema.' }

foreach ($path in @($validatorPath, $schemaPath, $MyInvocation.MyCommand.Path)) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) { throw "BOM is not allowed: $path" }
    foreach ($byte in $bytes) { if ($byte -gt 127) { throw "Non-ASCII byte found in $path" } }
    if ([System.IO.Path]::GetExtension($path) -ceq '.ps1') {
        $tokens = $null
        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) { throw "Parse failed for $path : $($parseErrors[0].Message)" }
    }
}

. $validatorPath

$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "FAIL: $Message" }
}
function New-TestSha256 {
    param([byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($Bytes)
    } finally {
        $algorithm.Dispose()
    }
    return ([System.BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant())
}
function ConvertTo-TestUtf8Bytes {
    param([string]$Text)
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    return ,$encoding.GetBytes($Text)
}
function New-TestManifestFixture {
    $first = ConvertTo-TestUtf8Bytes 'synthetic protected evidence module bytes'
    $second = ConvertTo-TestUtf8Bytes 'synthetic protected path policy module bytes'
    $manifest = [ordered]@{
        schemaVersion = 1
        component = 'ScreenConnectCleanup.Protected'
        version = '1.0.0'
        files = @(
            [ordered]@{ path = 'payload/ProtectedEvidence.ps1'; sha256 = (New-TestSha256 $first); size = $first.Length },
            [ordered]@{ path = 'payload/ProtectedPathPolicy.ps1'; sha256 = (New-TestSha256 $second); size = $second.Length }
        )
    }
    $manifestJson = ConvertTo-Json -InputObject $manifest -Depth 8 -Compress -ErrorAction Stop
    $manifestBytes = ConvertTo-TestUtf8Bytes $manifestJson
    $members = [System.Collections.Generic.Dictionary[string, byte[]]]::new([System.StringComparer]::Ordinal)
    $members.Add('payload/ProtectedEvidence.ps1', $first)
    $members.Add('payload/ProtectedPathPolicy.ps1', $second)
    return [pscustomobject]@{
        Manifest = $manifest
        ManifestBytes = $manifestBytes
        ExpectedManifestSha256 = (New-TestSha256 $manifestBytes)
        PayloadBytesByPath = $members
    }
}

function Refresh-TestManifestBytes {
    param($Fixture)
    $json = ConvertTo-Json -InputObject $Fixture.Manifest -Depth 8 -Compress -ErrorAction Stop
    $Fixture.ManifestBytes = ConvertTo-TestUtf8Bytes $json
    $Fixture.ExpectedManifestSha256 = New-TestSha256 $Fixture.ManifestBytes
}
function Assert-Rejected {
    param($Fixture, [string]$Message)
    $result = Test-ProtectedInstallManifest -ManifestBytes $Fixture.ManifestBytes -ExpectedManifestSha256 $Fixture.ExpectedManifestSha256 -PayloadBytesByPath $Fixture.PayloadBytesByPath
    Assert-True ((-not $result.IntegrityVerified) -and $result.ManifestStatus -ceq 'Rejected') $Message
    Assert-True ($null -ne $result.FailureCode) "$Message returns a failure code"
    Assert-True (-not $result.InstallationAuthorized -and -not $result.RemovalAuthorized) "$Message cannot authorize installation or removal"
}
function Assert-FixtureRejected {
    param($Fixture, [string]$Message)
    Refresh-TestManifestBytes $Fixture
    Assert-Rejected $Fixture $Message
}

$fixture = New-TestManifestFixture
$result = Test-ProtectedInstallManifest -ManifestBytes $fixture.ManifestBytes -ExpectedManifestSha256 $fixture.ExpectedManifestSha256 -PayloadBytesByPath $fixture.PayloadBytesByPath
Assert-True ($result.IntegrityVerified -and $result.ManifestStatus -ceq 'IntegrityVerified') 'valid serialized manifest and exact in-memory payload map verify'
Assert-True ($result.PayloadCount -eq 2 -and $result.PayloadNames.Count -eq 2) 'validated result reports the exact payload set'
Assert-True (-not $result.InstallationAuthorized -and -not $result.RemovalAuthorized) 'integrity validation does not authorize installation or removal'
Assert-True (-not $result.PublisherAuthenticated -and -not $result.ExternalDigestChannelAuthenticated -and -not $result.ProtectedFilesystemTrustEstablished) 'digest comparison does not claim an authenticated channel, publisher, or protected filesystem trust'
Assert-True ($result.ExpectedDigestMatched -and $result.ManifestSha256 -ceq $fixture.ExpectedManifestSha256) 'manifest digest is checked against the separately supplied expected digest'
Assert-True ($result.ExpectedDigestIsCallerSupplied -and -not $result.ReparsePointsChecked) 'expected digest source is a caller boundary and in-memory validation does not claim reparse checks'

$badDigest = New-TestManifestFixture
$badDigest.ExpectedManifestSha256 = ('0' * 64)
Assert-Rejected $badDigest 'manifest bytes that differ from the separately supplied expected digest are rejected'
$badDigest = New-TestManifestFixture
$badDigest.ExpectedManifestSha256 = 'sha256-from-adjacent-file'
Assert-Rejected $badDigest 'malformed external SHA-256 is rejected'
$badDigest = New-TestManifestFixture
$badDigest.ExpectedManifestSha256 = ('A' * 64)
Assert-Rejected $badDigest 'noncanonical uppercase expected SHA-256 is rejected'

$badBytes = New-TestManifestFixture
$badBytes.ManifestBytes = [byte[]]@(0xC3, 0x28)
$badBytes.ExpectedManifestSha256 = New-TestSha256 $badBytes.ManifestBytes
Assert-Rejected $badBytes 'invalid UTF-8 is rejected after hashing the exact supplied bytes'
$badBytes = New-TestManifestFixture
$bomBody = $badBytes.ManifestBytes
$badBytes.ManifestBytes = New-Object byte[] ($bomBody.Length + 3)
$badBytes.ManifestBytes[0] = 239; $badBytes.ManifestBytes[1] = 187; $badBytes.ManifestBytes[2] = 191
[System.Array]::Copy($bomBody, 0, $badBytes.ManifestBytes, 3, $bomBody.Length)
$badBytes.ExpectedManifestSha256 = New-TestSha256 $badBytes.ManifestBytes
Assert-Rejected $badBytes 'UTF-8 BOM is rejected'
$badBytes = New-TestManifestFixture
$badBytes.ManifestBytes = [byte[]]@()
$badBytes.ExpectedManifestSha256 = New-TestSha256 $badBytes.ManifestBytes
Assert-Rejected $badBytes 'empty manifest is rejected'
$badBytes = New-TestManifestFixture
$badBytes.ManifestBytes = New-Object byte[] (65537)
$badBytes.ExpectedManifestSha256 = New-TestSha256 $badBytes.ManifestBytes
Assert-Rejected $badBytes 'oversized manifest is rejected'
$badBytes = New-TestManifestFixture
$badBytes.ManifestBytes = ConvertTo-TestUtf8Bytes '{'
$badBytes.ExpectedManifestSha256 = New-TestSha256 $badBytes.ManifestBytes
Assert-Rejected $badBytes 'malformed JSON is rejected'

$duplicateCases = @(
    '{"schemaVersion":1,"schemaVersion":1,',
    '{"schemaVersion":1,"schema\u0056ersion":1,',
    '{"schema\u0056ersion":1,"schemaVersion":1,'
)
foreach ($prefix in $duplicateCases) {
    $badDuplicate = New-TestManifestFixture
    $baseJson = [System.Text.Encoding]::UTF8.GetString($badDuplicate.ManifestBytes)
    $badDuplicate.ManifestBytes = ConvertTo-TestUtf8Bytes ($prefix + $baseJson.Substring(1 + '"schemaVersion":1,'.Length))
    $badDuplicate.ExpectedManifestSha256 = New-TestSha256 $badDuplicate.ManifestBytes
    Assert-Rejected $badDuplicate 'duplicate decoded root property is rejected before object conversion'
}
$caseAlias = New-TestManifestFixture
$caseAliasJson = [System.Text.Encoding]::UTF8.GetString($caseAlias.ManifestBytes).Replace('"schemaVersion":1,', '"schemaVersion":1,"SchemaVersion":1,')
$caseAlias.ManifestBytes = ConvertTo-TestUtf8Bytes $caseAliasJson
$caseAlias.ExpectedManifestSha256 = New-TestSha256 $caseAlias.ManifestBytes
Assert-Rejected $caseAlias 'case-aliased JSON property is rejected'
$nestedDuplicate = New-TestManifestFixture
$nestedDuplicateJson = [System.Text.Encoding]::UTF8.GetString($nestedDuplicate.ManifestBytes)
$pathMember = '"path":"payload/ProtectedEvidence.ps1"'
$nestedDuplicateJson = $nestedDuplicateJson.Replace($pathMember, $pathMember + ',"p\u0061th":"payload/ProtectedEvidence.ps1"')
$nestedDuplicate.ManifestBytes = ConvertTo-TestUtf8Bytes $nestedDuplicateJson
$nestedDuplicate.ExpectedManifestSha256 = New-TestSha256 $nestedDuplicate.ManifestBytes
Assert-Rejected $nestedDuplicate 'escaped-equivalent duplicate property in a nested file record is rejected'

$bad = New-TestManifestFixture
$bad.Manifest['manifestSha256'] = New-TestSha256 $bad.ManifestBytes
Assert-FixtureRejected $bad 'self-anchored manifest digest assertion is rejected as an unknown field'
$bad = New-TestManifestFixture
$bad.Manifest['scriptPath'] = 'C:\\Temp\\payload.ps1'
Assert-FixtureRejected $bad 'arbitrary script path field is rejected'
$bad = New-TestManifestFixture
$bad.Manifest['SchemaVersion'] = 1
Assert-FixtureRejected $bad 'unknown case-variant schema field is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.schemaVersion = 2
Assert-FixtureRejected $bad 'unsupported manifest schema version is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.component = 'Other.Product'
Assert-FixtureRejected $bad 'wrong component identity is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.version = '../1.0.0'
Assert-FixtureRejected $bad 'invalid component version is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files = @()
Assert-FixtureRejected $bad 'empty payload list is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files = @($bad.Manifest.files[0], $bad.Manifest.files[1], $bad.Manifest.files[0], $bad.Manifest.files[1], $bad.Manifest.files[0])
Assert-FixtureRejected $bad 'payload list above the fixed count bound is rejected'

foreach ($unsafePath in @(
    '../ProtectedEvidence.ps1',
    'payload/../ProtectedEvidence.ps1',
    'C:/payload/ProtectedEvidence.ps1',
    'C:\\payload\\ProtectedEvidence.ps1',
    '\\\\server\\share\\ProtectedEvidence.ps1',
    'payload/ProtectedEvidence.ps1:stream',
    'payload/./ProtectedEvidence.ps1',
    'payload/protectedevidence.ps1',
    'payload/Unknown.ps1'
)) {
    $bad = New-TestManifestFixture
    $bad.Manifest.files[0].path = $unsafePath
    Assert-FixtureRejected $bad "unsafe or non-allowlisted payload path is rejected: $unsafePath"
}
$bad = New-TestManifestFixture
$bad.Manifest.files[1].path = $bad.Manifest.files[0].path
Assert-FixtureRejected $bad 'duplicate manifest member path is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files[0]['SHA256'] = $bad.Manifest.files[0].sha256
Assert-FixtureRejected $bad 'unknown case-alias file property is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files[0].size = 0
Assert-FixtureRejected $bad 'zero-byte payload is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files[0].size = 4294967296
Assert-FixtureRejected $bad 'payload size above the fixed bound is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files[0].size = 1.5
Assert-FixtureRejected $bad 'fractional payload size is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files[0].sha256 = 'not-a-digest'
Assert-FixtureRejected $bad 'malformed member SHA-256 is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files[0].sha256 = ('A' * 64)
Assert-FixtureRejected $bad 'noncanonical uppercase member SHA-256 is rejected'

$missingMapMember = New-TestManifestFixture
[void]$missingMapMember.PayloadBytesByPath.Remove('payload/ProtectedPathPolicy.ps1')
Assert-Rejected $missingMapMember 'missing payload map member is rejected'
$extraMapMember = New-TestManifestFixture
$extraMapMember.PayloadBytesByPath.Add('payload/ProtectedRollbackProof.ps1', (ConvertTo-TestUtf8Bytes 'unexpected'))
Assert-Rejected $extraMapMember 'extra payload map member is rejected'
$caseMapMember = New-TestManifestFixture
$null = $caseMapMember.PayloadBytesByPath.Remove('payload/ProtectedEvidence.ps1')
$caseMapMember.PayloadBytesByPath.Add('payload/protectedevidence.ps1', (ConvertTo-TestUtf8Bytes 'synthetic protected evidence module bytes'))
Assert-Rejected $caseMapMember 'case-alias payload map path is rejected'
$badPayload = New-TestManifestFixture
$badPayload.PayloadBytesByPath['payload/ProtectedEvidence.ps1'] = ConvertTo-TestUtf8Bytes 'modified member bytes'
Assert-Rejected $badPayload 'payload digest mismatch is rejected'
$badPayload = New-TestManifestFixture
$badPayload.PayloadBytesByPath['payload/ProtectedEvidence.ps1'] = $null
Assert-Rejected $badPayload 'non-byte payload map value is rejected'
$bad = New-TestManifestFixture
$bad.Manifest.files[0].size = $bad.Manifest.files[0].size + 1
Assert-FixtureRejected $bad 'payload size mismatch is rejected'

$schema = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($schemaPath, (New-Object System.Text.UTF8Encoding($false, $true)))) -ErrorAction Stop
Assert-True ($schema.schemaVersion -eq 1 -and $schema.type -ceq 'object') 'published JSON schema parses and declares the fixed object schema'
Assert-True ($schema.additionalProperties -eq $false -and $schema.properties.files.items.additionalProperties -eq $false) 'published JSON schema rejects unknown manifest and file properties'

$validatorTokens = $null
$validatorErrors = $null
$validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($validatorPath, [ref]$validatorTokens, [ref]$validatorErrors)
$forbiddenCommands = @('Add-Content', 'Copy-Item', 'Move-Item', 'New-Item', 'Out-File', 'Remove-Item', 'Set-Content', 'Start-Process', 'Invoke-Expression', 'Set-ItemProperty')
$commandAsts = @($validatorAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
foreach ($commandAst in $commandAsts) {
    Assert-True ($forbiddenCommands -notcontains $commandAst.GetCommandName()) 'validator contains no filesystem, process, registry, installer, or payload-execution command'
}
$validatorSource = [System.IO.File]::ReadAllText($validatorPath)
Assert-True ($validatorSource -notmatch '(?i)System\.IO\.File|System\.Diagnostics\.Process|Microsoft\.Win32|Start-Process|Invoke-Expression') 'validator uses no file, process, registry, or dynamic execution API'

Write-Output "PASS: $script:Assertions assertions; pure in-memory protected-install manifest integrity foundation."
