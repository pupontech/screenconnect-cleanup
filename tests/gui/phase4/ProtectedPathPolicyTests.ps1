[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$policyPath = Join-Path $repoRoot 'gui-bridge/ProtectedPathPolicy.ps1'
if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
    throw "Missing protected path policy: $policyPath"
}

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($policyPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw "Protected path policy parse failed: $($parseErrors[0].Message)"
}
foreach ($sourcePath in @($policyPath, $MyInvocation.MyCommand.Path)) {
    $sourceBytes = [System.IO.File]::ReadAllBytes($sourcePath)
    if ($sourceBytes.Length -ge 3 -and $sourceBytes[0] -eq 239 -and $sourceBytes[1] -eq 187 -and $sourceBytes[2] -eq 191) {
        throw "PowerShell source has a UTF-8 BOM: $sourcePath"
    }
    foreach ($byte in $sourceBytes) {
        if ($byte -gt 127) { throw "PowerShell source is not pure ASCII: $sourcePath" }
    }
}
. $policyPath

$script:Assertions = 0
$script:ValidTransactionId = 'd2eb5f2d-3307-40d3-a911-72f206a71921'
$script:PathCalls = 0
$script:AclCalls = 0
$script:ReparseCalls = 0
$script:PathVerified = $true
$script:PathWithinRoot = $true
$script:PathCanonicalRoot = $null
$script:PathCanonicalWorkDir = $null
$script:AclFailureField = ''
$script:AclFailurePath = ''
$script:AclMissingField = ''
$script:ReparseFailurePath = ''
$script:ReparseThrows = $false

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $script:Assertions++
    $thrown = $false
    try {
        & $Action
    } catch {
        $thrown = $true
    }
    if (-not $thrown) {
        throw "FAIL: expected refusal: $Message"
    }
}

function Reset-TestVerifiers {
    $script:PathCalls = 0
    $script:AclCalls = 0
    $script:ReparseCalls = 0
    $script:PathVerified = $true
    $script:PathWithinRoot = $true
    $script:PathCanonicalRoot = $null
    $script:PathCanonicalWorkDir = $null
    $script:AclFailureField = ''
    $script:AclFailurePath = ''
    $script:AclMissingField = ''
    $script:ReparseFailurePath = ''
    $script:ReparseThrows = $false
}

$script:TestPathVerifier = {
    param($TrustedRoot, $Candidate)
    $script:PathCalls++
    $canonicalRoot = if ($null -ne $script:PathCanonicalRoot) { $script:PathCanonicalRoot } else { $TrustedRoot }
    $canonicalWorkDir = if ($null -ne $script:PathCanonicalWorkDir) { $script:PathCanonicalWorkDir } else { $Candidate }
    return [pscustomobject]@{
        Verified = [bool]$script:PathVerified
        WithinRoot = [bool]$script:PathWithinRoot
        CanonicalRoot = [string]$canonicalRoot
        CanonicalWorkDir = [string]$canonicalWorkDir
    }
}

$script:TestAclVerifier = {
    param($Path)
    $script:AclCalls++
    $evidence = [ordered]@{
        Verified = $true
        OwnerTrusted = $true
        UntrustedWrite = $false
        UntrustedDelete = $false
        UntrustedDeleteChild = $false
        UntrustedTakeOwnership = $false
        UntrustedChangeAcl = $false
    }
    if ($script:AclFailureField -and ($script:AclFailurePath -eq '' -or $Path -ieq $script:AclFailurePath)) {
        if ($script:AclFailureField -eq 'Verified' -or $script:AclFailureField -eq 'OwnerTrusted') {
            $evidence[$script:AclFailureField] = $false
        } else {
            $evidence[$script:AclFailureField] = $true
        }
    }
    if ($script:AclMissingField) {
        [void]$evidence.Remove($script:AclMissingField)
    }
    return [pscustomobject]$evidence
}

$script:TestReparseVerifier = {
    param($Path)
    $script:ReparseCalls++
    if ($script:ReparseThrows) {
        throw 'synthetic reparse verifier failure'
    }
    return [bool](-not $script:ReparseFailurePath -or $Path -ine $script:ReparseFailurePath)
}

function Invoke-TestPolicy {
    [CmdletBinding()]
    param(
        [string]$TestTransactionId,
        [string]$TestBoundTransactionId,
        [string]$TestCurrentHostName,
        [string]$TestBoundHostName,
        [switch]$SupplyWorkDir,
        [string]$TestWorkDir
    )

    $transactionId = if ($PSBoundParameters.ContainsKey('TestTransactionId')) { $TestTransactionId } else { $script:ValidTransactionId }
    $boundTransactionId = if ($PSBoundParameters.ContainsKey('TestBoundTransactionId')) { $TestBoundTransactionId } else { $script:ValidTransactionId }
    $currentHostName = if ($PSBoundParameters.ContainsKey('TestCurrentHostName')) { $TestCurrentHostName } else { 'synthetic-host' }
    $boundHostName = if ($PSBoundParameters.ContainsKey('TestBoundHostName')) { $TestBoundHostName } else { 'SYNTHETIC-HOST' }
    $arguments = @{
        TransactionId = $transactionId
        BoundTransactionId = $boundTransactionId
        CurrentHostName = $currentHostName
        BoundHostName = $boundHostName
        PathVerifier = $script:TestPathVerifier
        AclVerifier = $script:TestAclVerifier
        ReparseVerifier = $script:TestReparseVerifier
    }
    if ($SupplyWorkDir) {
        $arguments.WorkDir = $TestWorkDir
    }
    return Get-ProtectedWorkDirPolicy @arguments
}

Reset-TestVerifiers
$result = Invoke-TestPolicy
$expectedWorkDir = 'C:\ProgramData\ScreenConnectCleanup\Transactions\' + $script:ValidTransactionId
Assert-True ($result.Decision -ceq 'CandidateOnly') 'success is labeled as a candidate path decision, not approval'
Assert-True ($result.WorkDir -ceq $expectedWorkDir) 'WorkDir is fixed-root and transaction-derived'
Assert-True ($result.TrustedRoot -ceq 'C:\ProgramData\ScreenConnectCleanup\Transactions') 'the root is fixed in policy'
Assert-True ($result.TransactionId -ceq $script:ValidTransactionId) 'the transaction identifier is normalized'
Assert-True ($result.HostName -ceq 'synthetic-host') 'the current host context is preserved'
Assert-True ($result.TrustEstablished -eq $false) 'a path policy result does not claim real ACL trust'
Assert-True ($script:PathCalls -eq 1) 'canonical path verifier is injected and called once'
Assert-True ($script:AclCalls -eq 5 -and $script:ReparseCalls -eq 5) 'ACL and reparse verifiers inspect drive root through transaction leaf'
Assert-True ($result.CheckedAncestors.Count -eq 5) 'every ancestor from drive root through WorkDir is recorded'
Assert-True ($result.CheckedAncestors[0] -ceq 'C:\') 'drive root is checked'
Assert-True ($result.CheckedAncestors[-1] -ceq $expectedWorkDir) 'transaction leaf is checked'

Reset-TestVerifiers
Assert-Throws { $null = Invoke-TestPolicy -SupplyWorkDir -TestWorkDir 'C:\RIT-SCC' } 'legacy C:\RIT-SCC WorkDir is refused'
Assert-Throws { $null = Invoke-TestPolicy -SupplyWorkDir -TestWorkDir 'C:\Other\UserChosen' } 'arbitrary user-supplied WorkDir is refused'
Assert-Throws { $null = Invoke-TestPolicy -SupplyWorkDir -TestWorkDir '' } 'an explicitly empty WorkDir is still user-supplied'
Assert-Throws { $null = Invoke-TestPolicy -TestTransactionId 'd2eb5f2d-3307-40d3-a911-72f206a71921' -TestBoundTransactionId 'b75a9a98-e8b2-45c5-bda7-20f8c16cc323' } 'wrong bound transaction is refused'
Assert-Throws { $null = Invoke-TestPolicy -TestTransactionId 'not-a-guid' } 'malformed transaction identifier is refused'
Assert-Throws { $null = Invoke-TestPolicy -TestBoundTransactionId 'not-a-guid' } 'malformed bound transaction identifier is refused'
Assert-Throws { $null = Invoke-TestPolicy -TestBoundHostName 'other-host' } 'wrong host binding is refused'
Assert-Throws { $null = Invoke-TestPolicy -TestCurrentHostName 'synthetic/host' } 'malformed current host is refused'
Assert-Throws { $null = Invoke-TestPolicy -TestBoundHostName ' synthetic-host' } 'whitespace host identity is refused'

Reset-TestVerifiers
$script:PathVerified = $false
Assert-Throws { $null = Invoke-TestPolicy } 'unverified canonical path is refused'
Assert-True ($script:AclCalls -eq 0) 'ACL checks do not run after path verification failure'
Reset-TestVerifiers
$script:PathWithinRoot = $false
Assert-Throws { $null = Invoke-TestPolicy } 'path verifier containment failure is refused'
Reset-TestVerifiers
$script:PathCanonicalWorkDir = 'C:\RIT-SCC'
Assert-Throws { $null = Invoke-TestPolicy } 'canonical path mismatch is refused'

foreach ($field in @('Verified', 'OwnerTrusted', 'UntrustedWrite', 'UntrustedDelete', 'UntrustedDeleteChild', 'UntrustedTakeOwnership', 'UntrustedChangeAcl')) {
    Reset-TestVerifiers
    $script:AclFailureField = $field
    $script:AclFailurePath = 'C:\ProgramData'
    Assert-Throws { $null = Invoke-TestPolicy } ("ACL failure '$field' on an ancestor is refused")
    Assert-True ($script:AclCalls -eq 2) ("ACL failure '$field' stops before checking descendants")
}
Reset-TestVerifiers
$script:AclMissingField = 'UntrustedDelete'
Assert-Throws { $null = Invoke-TestPolicy } 'incomplete ACL verifier evidence is refused'
Reset-TestVerifiers
$script:ReparseFailurePath = 'C:\ProgramData\ScreenConnectCleanup'
Assert-Throws { $null = Invoke-TestPolicy } 'reparse point on an ancestor is refused'
Assert-True ($script:AclCalls -eq 3 -and $script:ReparseCalls -eq 3) 'reparse failure stops before descendant checks'
Reset-TestVerifiers
$script:ReparseThrows = $true
Assert-Throws { $null = Invoke-TestPolicy } 'reparse verifier errors are refused'

$policyTokens = $null
$policyErrors = $null
$policyAst = [System.Management.Automation.Language.Parser]::ParseFile($policyPath, [ref]$policyTokens, [ref]$policyErrors)
$forbiddenCommands = @('New-Item', 'Set-Acl', 'Remove-Item', 'Move-Item', 'Start-Process', 'Invoke-Expression')
$commandAsts = $policyAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
foreach ($commandAst in $commandAsts) {
    Assert-True ($forbiddenCommands -notcontains $commandAst.GetCommandName()) ("policy contains no side-effect command: " + $commandAst.GetCommandName())
}

Write-Output "PASS: $script:Assertions assertions; transaction-bound fixed-root derivation, host/transaction checks, injectable ancestor ACL/reparse/path refusal, and no policy side effects."
