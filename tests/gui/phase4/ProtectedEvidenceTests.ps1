<#
  Synthetic pure-evidence validation tests.
  PowerShell 5.1 compatible. Pure ASCII, no BOM.
  All producer data is synthetic and stays in memory; no host evidence or remover is used.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$validatorPath = Join-Path $repoRoot 'gui-bridge/ProtectedEvidence.ps1'
if (-not (Test-Path -LiteralPath $validatorPath -PathType Leaf)) { throw 'Missing protected evidence validator.' }

foreach ($path in @($validatorPath, $MyInvocation.MyCommand.Path)) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "Parse failed for $path : $($parseErrors[0].Message)" }
    $sourceBytes = [System.IO.File]::ReadAllBytes($path)
    if ($sourceBytes.Length -ge 3 -and $sourceBytes[0] -eq 239 -and $sourceBytes[1] -eq 187 -and $sourceBytes[2] -eq 191) { throw "BOM is not allowed: $path" }
    foreach ($byte in $sourceBytes) { if ($byte -gt 127) { throw "Non-ASCII byte found in $path" } }
}
. $validatorPath

$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "FAIL: $Message" }
}
function Assert-ResultRejected {
    param($Fixture, [string]$Message)
    $result = Invoke-TestEvidence -Fixture $Fixture
    Assert-True (-not $result.IsValid -and $result.EvidenceStatus -ceq 'Rejected') $Message
    Assert-True ($result.ApprovalStatus -ceq 'NotApproved' -and -not $result.RemovalAuthorized -and -not $result.ProvenanceEstablished) "$Message cannot establish provenance, approve, or authorize removal"
}
function Assert-ResultFailureCode {
    param($Fixture, [string]$ExpectedCode, [string]$Message)
    $result = Invoke-TestEvidence -Fixture $Fixture
    Assert-True (-not $result.IsValid -and $result.EvidenceStatus -ceq 'Rejected' -and $result.FailureCode -ceq $ExpectedCode) $Message
    Assert-True ($result.ApprovalStatus -ceq 'NotApproved' -and -not $result.RemovalAuthorized -and -not $result.ProvenanceEstablished) "$Message cannot establish provenance, approve, or authorize removal"
}
function New-TestInstance {
    param([string]$Key, [string]$Identifier, [string]$InstallDir)
    return [ordered]@{
        Key = $Key
        Identifier = $Identifier
        InstallDir = $InstallDir
        ServiceName = ('ScreenConnect ' + $Identifier)
    }
}
function New-TestContext {
    return [ordered]@{
        ContextVersion = 1
        ProducerKind = 'TrustedProtectedProducer'
        ProtectedRunId = 'protected-run-001'
        DetectorRunId = 'TESTHOST_2026-09-24_120000'
        ComputerName = 'TESTHOST'
    }
}
function New-TestFindings {
    param([object[]]$Instances)
    return [ordered]@{
        Tool = 'detect-remote-access.ps1'
        Version = '1.7.53'
        RunId = 'TESTHOST_2026-09-24_120000'
        GeneratedUtc = '2026-09-24 12:00:00'
        ComputerName = 'TESTHOST'
        RunAsUser = 'TESTDOMAIN\test-user'
        IsAdmin = $true
        EventLogError = $null
        CollectionComplete = $true
        CollectionErrors = @()
        ScreenConnect = [ordered]@{
            Instances = $Instances
            ParseIssues = @()
            Historical = @()
            RawFilesSaved = @()
        }
        OtherTargets = @()
    }
}
function New-TestSnapshot {
    return [ordered]@{
        SchemaVersion = 2
        Label = 'before'
        ComputerName = 'TESTHOST'
        CollectedUtc = '2026-09-24 12:00:00'
        IsAdmin = $true
        OSCaption = 'Synthetic Windows'
        IncidentWindowDays = 0
        CollectionComplete = $true
        CollectionErrors = @()
        CollectionWarnings = @()
        Sections = [ordered]@{
            Services = @()
            ScheduledTasks = @()
            RegistryAutoruns = @()
            StartupFolders = @()
            Processes = @()
            Connections = @()
            InstalledPrograms = @()
            LocalAccounts = @()
            FirewallRules = @()
            WmiPersistence = @()
            RecentFiles = @()
            RecentFilesCapHit = $false
            Prefetch = @()
            ShimCache = @()
            BamDam = @()
            UserAssist = @()
            Srum = [ordered]@{ DatabasePresent = $false; Files = @() }
            Amcache = @()
            SystemSettings = [ordered]@{ RdpEnabled = $false; HostsFileLines = @() }
        }
    }
}
function ConvertTo-TestJsonBytes {
    param($InputObject, [switch]$WithUtf8Bom)
    $json = ConvertTo-Json -InputObject $InputObject -Depth 24 -Compress -ErrorAction Stop
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $body = $encoding.GetBytes($json)
    if (-not $WithUtf8Bom) { return ,$body }
    $bytes = New-Object byte[] ($body.Length + 3)
    $bytes[0] = 239; $bytes[1] = 187; $bytes[2] = 191
    [System.Array]::Copy($body, 0, $bytes, 3, $body.Length)
    return ,$bytes
}
function ConvertFrom-TestJsonBytes {
    param([byte[]]$Bytes)
    $text = [System.Text.Encoding]::UTF8.GetString($Bytes)
    return ConvertFrom-Json -InputObject $text -ErrorAction Stop
}
function Set-TestSerializedPlanVersion {
    param($Fixture, [string]$JsonToken)
    $planBytes = ConvertTo-TestJsonBytes -InputObject $Fixture.Plan
    $planJson = [System.Text.Encoding]::UTF8.GetString($planBytes)
    $member = '"PlanSchemaVersion":2'
    if (-not $planJson.Contains($member)) { throw 'Synthetic plan schema member was not found.' }
    $planJson = $planJson.Replace($member, ('"PlanSchemaVersion":' + $JsonToken))
    $Fixture.Plan = ConvertFrom-Json -InputObject $planJson -ErrorAction Stop
}
function Get-TestSha256 {
    param([byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}
function Invoke-TestEvidence {
    param($Fixture)
    return Test-ProtectedEvidence -FindingsBytes $Fixture.FindingsBytes -SnapshotBytes $Fixture.SnapshotBytes -TrustedProducerContext $Fixture.Context -ExpectedTransactionId $Fixture.ExpectedTransactionId -ExpectedSnapshotSha256 $Fixture.ExpectedSnapshotSha256 -Plan $Fixture.Plan
}
function New-TestFixture {
    $first = New-TestInstance -Key 'sc-id-a' -Identifier 'id-a' -InstallDir 'C:\Program Files\ScreenConnect (id-a)'
    $second = New-TestInstance -Key 'sc-id-b' -Identifier 'id-b' -InstallDir 'D:\Apps\ScreenConnect (id-b)'
    $instances = [object[]]@($first, $second)
    $findings = New-TestFindings -Instances $instances
    $snapshot = New-TestSnapshot
    $plan = [ordered]@{
        PlanSchemaVersion = 2
        RunId = 'TESTHOST_2026-09-24_120000'
        ComputerName = 'TESTHOST'
        Decision = 'ALL_REMOVE'
        RemovalConfirmed = $true
        ScreenConnectInstances = [object[]]@($second, $first)
    }
    $snapshotBytes = ConvertTo-TestJsonBytes -InputObject $snapshot
    $planBytes = ConvertTo-TestJsonBytes -InputObject $plan
    return @{
        Context = New-TestContext
        Findings = $findings
        Snapshot = $snapshot
        Plan = (ConvertFrom-TestJsonBytes -Bytes $planBytes)
        FindingsBytes = (ConvertTo-TestJsonBytes -InputObject $findings -WithUtf8Bom)
        SnapshotBytes = $snapshotBytes
        ExpectedTransactionId = 'protected-run-001'
        ExpectedSnapshotSha256 = (Get-TestSha256 -Bytes $snapshotBytes)
    }
}
function Refresh-TestFindingsBytes {
    param($Fixture)
    $Fixture.FindingsBytes = ConvertTo-TestJsonBytes -InputObject $Fixture.Findings -WithUtf8Bom
}
function Refresh-TestSnapshotBytes {
    param($Fixture)
    $Fixture.SnapshotBytes = ConvertTo-TestJsonBytes -InputObject $Fixture.Snapshot
    $Fixture.ExpectedSnapshotSha256 = Get-TestSha256 -Bytes $Fixture.SnapshotBytes
}

try {
    $fixture = New-TestFixture
    $valid = Invoke-TestEvidence -Fixture $fixture
    Assert-True ($valid.IsValid -and $valid.EvidenceStatus -ceq 'Validated') 'valid synthetic producer-context fixture and reordered exact all-instance plan validate'
    $serializedPlanVersion = $fixture.Plan.PlanSchemaVersion
    Assert-True (($serializedPlanVersion -is [System.Int32] -or $serializedPlanVersion -is [System.Int64]) -and $serializedPlanVersion -eq 2) ("serialized plan schema is an integral numeric 2: $($serializedPlanVersion.GetType().FullName)")
    Assert-True ($valid.InstanceCount -eq 2 -and $valid.ProtectedRunId -ceq 'protected-run-001') 'outer protected run and nested detector run remain distinct'
    Assert-True ($valid.DetectorRunId -ceq 'TESTHOST_2026-09-24_120000' -and $valid.ComputerName -ceq 'TESTHOST') 'result reports the matched host and nested detector identity'
    Assert-True ($valid.ApprovalStatus -ceq 'NotApproved' -and -not $valid.RemovalAuthorized) 'successful evidence validation is not approval or removal authorization'
    Assert-True (-not $valid.ProvenanceEstablished) 'pure validation does not claim to authenticate producer provenance'
    Assert-True ($fixture.Snapshot.Contains('RunId') -eq $false) 'snapshot fixture follows producer schema and does not require a RunId'

    $replayedSnapshot = New-TestFixture
    $priorSnapshotBytes = $replayedSnapshot.SnapshotBytes
    $replayedSnapshot.Snapshot.CollectedUtc = '2026-09-24 11:59:59'
    Refresh-TestSnapshotBytes $replayedSnapshot
    $replayedSnapshot.SnapshotBytes = $priorSnapshotBytes
    Assert-ResultFailureCode $replayedSnapshot 'SNAPSHOT_DIGEST_MISMATCH' 'same-host prior snapshot bytes are rejected against the current snapshot digest'
    $wrongTransaction = New-TestFixture
    $wrongTransaction.ExpectedTransactionId = 'different-current-transaction'
    Assert-ResultFailureCode $wrongTransaction 'TRANSACTION_BINDING_MISMATCH' 'expected transaction must bind to the supplied run context'

    $missingContext = Test-ProtectedEvidence -FindingsBytes $fixture.FindingsBytes -SnapshotBytes $fixture.SnapshotBytes -ExpectedTransactionId $fixture.ExpectedTransactionId -ExpectedSnapshotSha256 $fixture.ExpectedSnapshotSha256 -Plan $fixture.Plan
    Assert-True (-not $missingContext.IsValid -and $missingContext.FailureCode -ceq 'MISSING_CONTEXT' -and -not $missingContext.ProvenanceEstablished -and $missingContext.ApprovalStatus -ceq 'NotApproved' -and -not $missingContext.RemovalAuthorized) 'missing producer context is refused explicitly without prompting or authority'
    $missingExpectedTransaction = Test-ProtectedEvidence -FindingsBytes $fixture.FindingsBytes -SnapshotBytes $fixture.SnapshotBytes -TrustedProducerContext $fixture.Context -ExpectedSnapshotSha256 $fixture.ExpectedSnapshotSha256 -Plan $fixture.Plan
    Assert-True (-not $missingExpectedTransaction.IsValid -and $missingExpectedTransaction.FailureCode -ceq 'MISSING_EXPECTED_TRANSACTION' -and -not $missingExpectedTransaction.ProvenanceEstablished -and $missingExpectedTransaction.ApprovalStatus -ceq 'NotApproved' -and -not $missingExpectedTransaction.RemovalAuthorized) 'missing expected transaction is refused explicitly without authority'
    $missingExpectedDigest = Test-ProtectedEvidence -FindingsBytes $fixture.FindingsBytes -SnapshotBytes $fixture.SnapshotBytes -TrustedProducerContext $fixture.Context -ExpectedTransactionId $fixture.ExpectedTransactionId -Plan $fixture.Plan
    Assert-True (-not $missingExpectedDigest.IsValid -and $missingExpectedDigest.FailureCode -ceq 'INVALID_EXPECTED_SNAPSHOT_DIGEST' -and -not $missingExpectedDigest.ProvenanceEstablished -and $missingExpectedDigest.ApprovalStatus -ceq 'NotApproved' -and -not $missingExpectedDigest.RemovalAuthorized) 'missing expected snapshot digest is refused explicitly without authority'

    $badContext = New-TestFixture
    $badContext.Context.ProducerKind = 'GuiRequest'
    Assert-ResultRejected $badContext 'GUI context cannot stand in for the protected producer context'
    $hashContext = New-TestFixture
    $hashContext.Context['FindingsSha256'] = ('a' * 64)
    Assert-ResultRejected $hashContext 'caller-supplied hash is not accepted as provenance'

    foreach ($duplicateJson in @(
        '{"RunId":"x","RunId":"y"}',
        '{"RunId":"x","Run\u0049d":"y"}',
        '{"Run\u0049d":"x","RunId":"y"}',
        '{"ScreenConnect":{"Instances":[],"Instances":[]}}'
    )) {
        $bad = New-TestFixture
        $raw = [System.Text.Encoding]::UTF8.GetBytes($duplicateJson)
        $bad.FindingsBytes = $raw
        Assert-ResultRejected $bad 'duplicate decoded JSON member is rejected before conversion'
    }
    $badSnapshotDuplicate = New-TestFixture
    $badSnapshotDuplicate.SnapshotBytes = [System.Text.Encoding]::UTF8.GetBytes('{"SchemaVersion":2,"Schema\u0056ersion":2}')
    Assert-ResultRejected $badSnapshotDuplicate 'duplicate decoded snapshot member is rejected before conversion'

    $duplicateValid = New-TestFixture
    $quote = [string][char]34
    $slash = [string][char]92
    $baseFindingsJson = [System.Text.Encoding]::UTF8.GetString($duplicateValid.FindingsBytes, 3, ($duplicateValid.FindingsBytes.Length - 3))
    $runIdName = $quote + 'RunId' + $quote
    $runIdStart = $baseFindingsJson.IndexOf($runIdName, [System.StringComparison]::Ordinal)
    $runIdEnd = $baseFindingsJson.IndexOf(',', $runIdStart)
    Assert-True ($runIdStart -ge 0 -and $runIdEnd -gt $runIdStart) 'valid synthetic findings JSON has a root RunId property'
    $runIdMember = $baseFindingsJson.Substring($runIdStart, ($runIdEnd - $runIdStart))
    $baseBeforeRunId = $baseFindingsJson.Substring(0, $runIdStart)
    $baseAfterRunId = $baseFindingsJson.Substring($runIdEnd)
    $escapedRunIdName = $quote + 'Run' + $slash + 'u0049d' + $quote
    $duplicateRunIdValue = $quote + 'TESTHOST_2026-09-24_120000' + $quote
    $duplicateRunIdCases = @(
        $runIdMember + ',' + $runIdName + ':' + $duplicateRunIdValue,
        $runIdMember + ',' + $escapedRunIdName + ':' + $duplicateRunIdValue,
        $escapedRunIdName + ':' + $duplicateRunIdValue + ',' + $runIdMember
    )
    foreach ($duplicateRunId in $duplicateRunIdCases) {
        $bad = New-TestFixture
        $bad.FindingsBytes = [System.Text.Encoding]::UTF8.GetBytes($baseBeforeRunId + $duplicateRunId + $baseAfterRunId)
        Assert-ResultFailureCode $bad 'DUPLICATE_JSON_MEMBER' 'otherwise-valid findings reject exact and escaped-equivalent duplicate RunId members'
    }
    $nestedName = $quote + 'ParseIssues' + $quote
    $nestedStart = $baseFindingsJson.IndexOf($nestedName, [System.StringComparison]::Ordinal)
    $nestedEnd = $baseFindingsJson.IndexOf('[]', $nestedStart, [System.StringComparison]::Ordinal) + 2
    Assert-True ($nestedStart -ge 0 -and $nestedEnd -gt $nestedStart) 'valid synthetic findings JSON has a nested ParseIssues array'
    $escapedNestedName = $quote + 'Parse' + $slash + 'u0049ssues' + $quote
    $nestedDuplicateJson = $baseFindingsJson.Insert($nestedEnd, ',' + $escapedNestedName + ':[]')
    $badNestedDuplicate = New-TestFixture
    $badNestedDuplicate.FindingsBytes = [System.Text.Encoding]::UTF8.GetBytes($nestedDuplicateJson)
    Assert-ResultFailureCode $badNestedDuplicate 'DUPLICATE_JSON_MEMBER' 'otherwise-valid findings reject escaped-equivalent duplicate nested ParseIssues members'
    $baseSnapshotJson = [System.Text.Encoding]::UTF8.GetString($duplicateValid.SnapshotBytes)
    $schemaName = $quote + 'SchemaVersion' + $quote
    $schemaStart = $baseSnapshotJson.IndexOf($schemaName, [System.StringComparison]::Ordinal)
    $schemaEnd = $baseSnapshotJson.IndexOf(',', $schemaStart)
    Assert-True ($schemaStart -ge 0 -and $schemaEnd -gt $schemaStart) 'valid synthetic snapshot JSON has a root SchemaVersion property'
    $schemaMember = $baseSnapshotJson.Substring($schemaStart, ($schemaEnd - $schemaStart))
    $schemaBefore = $baseSnapshotJson.Substring(0, $schemaStart)
    $schemaAfter = $baseSnapshotJson.Substring($schemaEnd)
    $escapedSchemaName = $quote + 'Schema' + $slash + 'u0056ersion' + $quote
    $badSnapshotDuplicate = New-TestFixture
    $badSnapshotDuplicate.SnapshotBytes = [System.Text.Encoding]::UTF8.GetBytes($schemaBefore + $schemaMember + ',' + $escapedSchemaName + ':2' + $schemaAfter)
    $badSnapshotDuplicate.ExpectedSnapshotSha256 = Get-TestSha256 -Bytes $badSnapshotDuplicate.SnapshotBytes
    Assert-ResultFailureCode $badSnapshotDuplicate 'DUPLICATE_JSON_MEMBER' 'otherwise-valid snapshot rejects escaped-equivalent duplicate decoded SchemaVersion members'

    $badJson = New-TestFixture
    $badJson.FindingsBytes = ConvertTo-TestJsonBytes -InputObject ([ordered]@{ broken = $true })
    $badJson.FindingsBytes = [System.Text.Encoding]::UTF8.GetBytes('{')
    Assert-ResultRejected $badJson 'malformed JSON is rejected'
    $trailingJson = New-TestFixture
    $trailingJson.FindingsBytes = [System.Text.Encoding]::UTF8.GetBytes('{} trailing')
    Assert-ResultRejected $trailingJson 'trailing non-JSON content is rejected'
    $badUtf8 = New-TestFixture
    $badUtf8.FindingsBytes = [byte[]]@(0xC3, 0x28)
    Assert-ResultRejected $badUtf8 'invalid UTF-8 is rejected'

    $badFindings = New-TestFixture
    $badFindings.Findings.Remove('CollectionErrors')
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'missing CollectionErrors is not treated as an empty array'
    $badFindings = New-TestFixture
    $badFindings.Findings.CollectionErrors = $null
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'null CollectionErrors is not treated as an empty array'
    $badFindings = New-TestFixture
    $badFindings.Findings.CollectionErrors = @('synthetic collection failure')
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'non-empty CollectionErrors refuses evidence'
    $badFindings = New-TestFixture
    $badFindings.Findings.CollectionComplete = $false
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'CollectionComplete false refuses evidence'
    $badFindings = New-TestFixture
    $badFindings.Findings.Remove('EventLogError')
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'missing EventLogError is not treated as success'
    $badFindings = New-TestFixture
    $badFindings.Findings.EventLogError = 'synthetic event log failure'
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'event-log collection error refuses evidence'
    $badFindings = New-TestFixture
    $badFindings.Findings.ScreenConnect.Remove('ParseIssues')
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'missing ParseIssues is not treated as an empty array'
    $badFindings = New-TestFixture
    $badFindings.Findings.ScreenConnect.ParseIssues = @('synthetic parse error')
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'non-empty ParseIssues refuses evidence'
    $badFindings = New-TestFixture
    $badFindings.Findings.ScreenConnect.Instances = $null
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'missing or null instance array refuses evidence'
    $badFindings = New-TestFixture
    $badFindings.Findings.RunId = 'different_nested_run'
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'nested detector RunId must match the trusted producer context'
    $badFindings = New-TestFixture
    $badFindings.Findings.ComputerName = 'OTHERHOST'
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'findings host must match the trusted producer context'
    $badFindings = New-TestFixture
    $badFindings.Findings.Tool = 'other-tool.ps1'
    Refresh-TestFindingsBytes $badFindings
    Assert-ResultRejected $badFindings 'wrong detector tool marker refuses evidence'

    $badSnapshot = New-TestFixture
    $badSnapshot.Snapshot.Remove('CollectionErrors')
    Refresh-TestSnapshotBytes $badSnapshot
    Assert-ResultRejected $badSnapshot 'missing snapshot CollectionErrors is not treated as empty'
    $badSnapshot = New-TestFixture
    $badSnapshot.Snapshot.CollectionErrors = @('synthetic snapshot failure')
    Refresh-TestSnapshotBytes $badSnapshot
    Assert-ResultRejected $badSnapshot 'snapshot collection errors refuse evidence'
    $badSnapshot = New-TestFixture
    $badSnapshot.Snapshot.CollectionComplete = $false
    Refresh-TestSnapshotBytes $badSnapshot
    Assert-ResultRejected $badSnapshot 'incomplete snapshot refuses evidence'
    $badSnapshot = New-TestFixture
    $badSnapshot.Snapshot.ComputerName = 'OTHERHOST'
    Refresh-TestSnapshotBytes $badSnapshot
    Assert-ResultRejected $badSnapshot 'snapshot host must match the trusted producer context'
    $badSnapshot = New-TestFixture
    $badSnapshot.Snapshot.Label = 'after'
    Refresh-TestSnapshotBytes $badSnapshot
    Assert-ResultRejected $badSnapshot 'only the before snapshot is accepted'
    $badSnapshot = New-TestFixture
    $badSnapshot.Snapshot.Sections.Remove('Processes')
    Refresh-TestSnapshotBytes $badSnapshot
    Assert-ResultRejected $badSnapshot 'missing required snapshot section refuses evidence'
    $badSnapshot = New-TestFixture
    $badSnapshot.Snapshot.Sections.Processes = $null
    Refresh-TestSnapshotBytes $badSnapshot
    Assert-ResultRejected $badSnapshot 'null required snapshot section is not treated as empty'
    $unknownRdp = New-TestFixture
    $unknownRdp.Snapshot.Sections.SystemSettings.RdpEnabled = $null
    Refresh-TestSnapshotBytes $unknownRdp
    $unknownRdpResult = Invoke-TestEvidence -Fixture $unknownRdp
    $unknownRdpSnapshot = ConvertFrom-TestJsonBytes -Bytes $unknownRdp.SnapshotBytes
    Assert-True ($unknownRdpResult.IsValid -and $null -eq $unknownRdpSnapshot.Sections.SystemSettings.RdpEnabled) 'serialized null RDP state is accepted as unknown without inventing a Boolean'
    $invalidRdp = New-TestFixture
    $invalidRdp.Snapshot.Sections.SystemSettings.RdpEnabled = 'unknown'
    Refresh-TestSnapshotBytes $invalidRdp
    Assert-ResultFailureCode $invalidRdp 'INVALID_SNAPSHOT_SECTION' 'non-null non-Boolean RDP state is rejected'

    $badPlan = New-TestFixture
    $badPlan.Plan.Decision = 'PARTIAL_REMOVE'
    Assert-ResultRejected $badPlan 'partial plan decision is rejected'
    foreach ($invalidVersionToken in @('"2"', '2.0', '2.5', 'true')) {
        $badPlan = New-TestFixture
        Set-TestSerializedPlanVersion -Fixture $badPlan -JsonToken $invalidVersionToken
        Assert-ResultFailureCode $badPlan 'UNSUPPORTED_PLAN_SCHEMA' ("serialized non-integer plan version '$invalidVersionToken' is rejected")
    }
    $badPlan = New-TestFixture
    $badPlan.Plan.RunId = 'other-detector-run'
    Assert-ResultRejected $badPlan 'plan nested detector run must match the trusted producer context'
    $badPlan = New-TestFixture
    $badPlan.Plan.ComputerName = 'OTHERHOST'
    Assert-ResultRejected $badPlan 'plan host must match the trusted producer context'
    $badPlan = New-TestFixture
    $badPlan.Plan.ScreenConnectInstances = [object[]]@($badPlan.Findings.ScreenConnect.Instances[0])
    Assert-ResultRejected $badPlan 'plan omitting a current instance is rejected'
    $badPlan = New-TestFixture
    $extra = New-TestInstance -Key 'sc-extra' -Identifier 'extra' -InstallDir 'E:\Apps\ScreenConnect (extra)'
    $badPlan.Plan.ScreenConnectInstances = [object[]]@($badPlan.Plan.ScreenConnectInstances + $extra)
    Assert-ResultRejected $badPlan 'plan adding an unobserved instance is rejected'
    $badPlan = New-TestFixture
    $badPlan.Plan.ScreenConnectInstances = [object[]]@($badPlan.Plan.ScreenConnectInstances + $badPlan.Plan.ScreenConnectInstances[0])
    Assert-ResultRejected $badPlan 'duplicate plan identity is rejected'
    $badPlan = New-TestFixture
    $badPlan.Plan.ScreenConnectInstances[0].InstallDir = 'D:\Apps\ScreenConnect (substituted)'
    Assert-ResultRejected $badPlan 'substituted plan path is rejected'
    $badPlan = New-TestFixture
    $badPlan.Findings.ScreenConnect.Instances[1].InstallDir = $badPlan.Findings.ScreenConnect.Instances[0].InstallDir
    Refresh-TestFindingsBytes $badPlan
    Assert-ResultRejected $badPlan 'duplicate findings install path is rejected'
    $badPlan = New-TestFixture
    $badPlan.Findings.ScreenConnect.Instances[0].InstallDir = 'relative\ScreenConnect'
    Refresh-TestFindingsBytes $badPlan
    Assert-ResultRejected $badPlan 'non-absolute findings install path is rejected'
    $badPlan = New-TestFixture
    $badPlan.Findings.ScreenConnect.Instances[0].Key = ''
    Refresh-TestFindingsBytes $badPlan
    Assert-ResultRejected $badPlan 'missing stable instance key is rejected'
    $badPlan = New-TestFixture
    $badPlan.Plan.RemovalConfirmed = $true
    $stillNotApproved = Invoke-TestEvidence -Fixture $badPlan
    Assert-True ($stillNotApproved.IsValid -and -not $stillNotApproved.RemovalAuthorized -and $stillNotApproved.ApprovalStatus -ceq 'NotApproved') 'RemovalConfirmed in a plan does not grant approval'
    $zero = New-TestFixture
    $zero.Findings.ScreenConnect.Instances = @()
    $zero.Plan.ScreenConnectInstances = @()
    Refresh-TestFindingsBytes $zero
    Assert-ResultRejected $zero 'empty all-instance set does not authorize a zero-instance removal plan'

    $oversize = New-TestFixture
    $oversize.FindingsBytes = New-Object byte[] (16MB + 1)
    Assert-ResultRejected $oversize 'findings bytes above the fixed size bound are rejected'
    $emptySnapshot = New-TestFixture
    $emptySnapshot.SnapshotBytes = [byte[]]@()
    $emptySnapshot.ExpectedSnapshotSha256 = Get-TestSha256 -Bytes $emptySnapshot.SnapshotBytes
    Assert-ResultFailureCode $emptySnapshot 'EVIDENCE_SIZE' 'empty snapshot bytes are rejected before digest processing'

    $validatorTokens = $null
    $validatorErrors = $null
    $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($validatorPath, [ref]$validatorTokens, [ref]$validatorErrors)
    $forbiddenCommands = @('Add-Content', 'Checkpoint-Computer', 'Move-Item', 'New-Item', 'Out-File', 'Remove-Item', 'Set-Content', 'Start-Process')
    $commandAsts = @($validatorAst.FindAll({ param($node) return $node -is [System.Management.Automation.Language.CommandAst] }, $true))
    foreach ($commandAst in $commandAsts) {
        Assert-True ($forbiddenCommands -notcontains $commandAst.GetCommandName()) 'validator contains no filesystem, process, registry, restore-point, or remover command'
    }
    $typeAsts = @($validatorAst.FindAll({ param($node) return $node -is [System.Management.Automation.Language.TypeExpressionAst] }, $true))
    foreach ($typeAst in $typeAsts) {
        Assert-True ($typeAst.TypeName.FullName -notmatch '(?i)^(System\.IO\.File|System\.Diagnostics|Microsoft\.Win32|System\.Management\.Automation\.Runspaces)(\.|$)') 'validator uses no file, process, registry, or runspace API'
    }

    Write-Output "PASS: $script:Assertions assertions; bounded in-memory producer evidence validation, exact-set checks, and no approval or host side effects."
} catch {
    throw
}
