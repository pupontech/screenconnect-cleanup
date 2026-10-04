# Pure Phase 4 path policy. This file does not create paths, alter ACLs, or launch processes.
# The fixed location is a policy constant, not proof that the path is protected.

function Get-ProtectedWorkDirAncestors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path -notmatch '^[A-Za-z]:\\') {
        throw 'Protected path must be an absolute drive path.'
    }

    $paths = New-Object 'System.Collections.Generic.List[string]'
    $current = $Path.Substring(0, 3)
    [void]$paths.Add($current)
    $segments = $Path.Substring(3).Split([char]92)
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -ceq '.' -or $segment -ceq '..') {
            throw 'Protected path contains an empty or traversal component.'
        }
        if ($segment.IndexOfAny([char[]]@(47, 92)) -ge 0) {
            throw 'Protected path contains a separator inside a component.'
        }
        $current = $current + $segment
        [void]$paths.Add($current)
        $current = $current + '\'
    }

    return $paths.ToArray()
}

function Get-ProtectedWorkDirPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TransactionId,

        [Parameter(Mandatory = $true)]
        [string]$BoundTransactionId,

        [Parameter(Mandatory = $true)]
        [string]$CurrentHostName,

        [Parameter(Mandatory = $true)]
        [string]$BoundHostName,

        [Parameter(Mandatory = $true)]
        [scriptblock]$PathVerifier,

        [Parameter(Mandatory = $true)]
        [scriptblock]$AclVerifier,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ReparseVerifier,

        [Alias('RequestedWorkDir')]
        [AllowNull()]
        [string]$WorkDir
    )

    # Any explicit WorkDir is untrusted input, including the legacy remover default.
    if ($PSBoundParameters.ContainsKey('WorkDir')) {
        throw 'Refusing user-supplied WorkDir; derive it from the protected transaction context.'
    }

    $transactionGuid = [Guid]::Empty
    $boundTransactionGuid = [Guid]::Empty
    if (-not [Guid]::TryParseExact($TransactionId, 'D', [ref]$transactionGuid)) {
        throw 'TransactionId must be a canonical GUID.'
    }
    if (-not [Guid]::TryParseExact($BoundTransactionId, 'D', [ref]$boundTransactionGuid)) {
        throw 'BoundTransactionId must be a canonical GUID.'
    }
    if ($transactionGuid -ne $boundTransactionGuid) {
        throw 'Transaction identity does not match the protected binding.'
    }

    foreach ($hostValue in @($CurrentHostName, $BoundHostName)) {
        if ([string]::IsNullOrWhiteSpace($hostValue) -or $hostValue -cne $hostValue.Trim()) {
            throw 'Host identity is missing or malformed.'
        }
        if ($hostValue -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$' -or
            $hostValue.EndsWith('.') -or $hostValue.EndsWith('-') -or $hostValue.Contains('..')) {
            throw 'Host identity contains invalid characters.'
        }
    }
    if (-not [string]::Equals($CurrentHostName, $BoundHostName, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Protected binding belongs to a different host.'
    }

    $trustedRoot = 'C:\ProgramData\ScreenConnectCleanup\Transactions'
    $canonicalTransactionId = $transactionGuid.ToString('D').ToLowerInvariant()
    $candidateWorkDir = $trustedRoot + '\' + $canonicalTransactionId

    # The injected verifier must resolve physical/canonical paths (including the
    # nearest existing parent for a not-yet-created leaf) and prove containment.
    # A matching path string alone is not a trust or ACL proof.
    $pathEvidence = & $PathVerifier -TrustedRoot $trustedRoot -Candidate $candidateWorkDir
    if ($null -eq $pathEvidence) {
        throw 'Path verifier returned no evidence.'
    }
    foreach ($field in @('Verified', 'WithinRoot')) {
        $property = $pathEvidence.PSObject.Properties[$field]
        if ($null -eq $property -or $property.Value -isnot [bool]) {
            throw "Path verifier evidence is missing Boolean field: $field"
        }
    }
    foreach ($field in @('CanonicalRoot', 'CanonicalWorkDir')) {
        $property = $pathEvidence.PSObject.Properties[$field]
        if ($null -eq $property -or $property.Value -isnot [string]) {
            throw "Path verifier evidence is missing string field: $field"
        }
    }
    if (-not $pathEvidence.Verified -or -not $pathEvidence.WithinRoot -or
        -not [string]::Equals($pathEvidence.CanonicalRoot, $trustedRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($pathEvidence.CanonicalWorkDir, $candidateWorkDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Protected path verification failed.'
    }

    $ancestors = @(Get-ProtectedWorkDirAncestors -Path $candidateWorkDir)
    $checkedAncestors = New-Object 'System.Collections.Generic.List[string]'
    $requiredTrueFields = @('Verified', 'OwnerTrusted')
    $requiredFalseFields = @(
        'UntrustedWrite',
        'UntrustedDelete',
        'UntrustedDeleteChild',
        'UntrustedTakeOwnership',
        'UntrustedChangeAcl'
    )
    $allAclFields = @($requiredTrueFields) + @($requiredFalseFields)

    foreach ($ancestor in $ancestors) {
        # ACL verifier must evaluate effective inherited and explicit rights and
        # owner/ACL-change rights. It is an injected read-only verifier, never Set-Acl.
        $aclEvidence = & $AclVerifier -Path $ancestor
        if ($null -eq $aclEvidence) {
            throw "ACL verifier returned no evidence for: $ancestor"
        }
        foreach ($field in $allAclFields) {
            $property = $aclEvidence.PSObject.Properties[$field]
            if ($null -eq $property -or $property.Value -isnot [bool]) {
                throw "ACL verifier evidence is missing Boolean field '$field' for: $ancestor"
            }
        }
        foreach ($field in $requiredTrueFields) {
            if (-not $aclEvidence.$field) {
                throw "ACL or owner verification failed for: $ancestor"
            }
        }
        foreach ($field in $requiredFalseFields) {
            if ($aclEvidence.$field) {
                throw "Untrusted write, delete, ownership, or ACL right detected for: $ancestor"
            }
        }

        # Check every ancestor, not just the final path. Unknown/error is refusal.
        $reparseSafe = & $ReparseVerifier -Path $ancestor
        if ($reparseSafe -isnot [bool] -or -not $reparseSafe) {
            throw "Reparse-point verification failed for: $ancestor"
        }
        [void]$checkedAncestors.Add($ancestor)
    }

    # CandidateOnly deliberately distinguishes this policy result from an
    # authorization, real ACL trust assertion, or permission to invoke a remover.
    return [pscustomobject][ordered]@{
        Decision = 'CandidateOnly'
        WorkDir = $candidateWorkDir
        TrustedRoot = $trustedRoot
        TransactionId = $canonicalTransactionId
        HostName = $CurrentHostName
        CheckedAncestors = $checkedAncestors.ToArray()
        TrustEstablished = $false
    }
}
