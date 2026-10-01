[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScratchRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$builderPath = Join-Path $repoRoot 'scripts/build-readonly-gui-prototype.ps1'
if (-not [System.IO.File]::Exists($builderPath)) { throw "Missing package builder: $builderPath" }

$testBytes = [System.IO.File]::ReadAllBytes($PSCommandPath)
if ($testBytes.Length -ge 3 -and $testBytes[0] -eq 239 -and $testBytes[1] -eq 187 -and $testBytes[2] -eq 191) {
    throw 'Packaging tests must be UTF-8 without BOM.'
}
foreach ($byte in $testBytes) {
    if ($byte -gt 127) { throw 'Packaging tests must contain ASCII bytes only.' }
}

$tokens = $null
$parseErrors = $null
$builderAst = [System.Management.Automation.Language.Parser]::ParseFile($builderPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Package builder parse failed: $($parseErrors[0].Message)" }
$builderSource = [System.IO.File]::ReadAllText($builderPath)

$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "FAIL: $Message" }
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message, [string]$ExpectedText)
    $script:Assertions++
    $exceptionText = $null
    try { & $Action } catch { $exceptionText = $_.Exception.ToString() }
    if ($null -eq $exceptionText) { throw "FAIL: expected rejection: $Message" }
    if (-not $exceptionText.Contains($ExpectedText)) {
        throw "FAIL: $Message rejected for the wrong reason: $exceptionText"
    }
}
function Set-FixtureText {
    param([string]$Path, [string]$Text)
    $parent = Split-Path -Parent $Path
    if (-not [System.IO.Directory]::Exists($parent)) { [void][System.IO.Directory]::CreateDirectory($parent) }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}
function Get-IndependentSha256 {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function New-SyntheticZip {
    param([string]$Path, [object[]]$Entries)
    $fileStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $archive = New-Object System.IO.Compression.ZipArchive($fileStream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($item in $Entries) {
                $entry = $archive.CreateEntry([string]$item.Name, [System.IO.Compression.CompressionLevel]::Optimal)
                $entryStream = $entry.Open()
                try {
                    $entryBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$item.Text)
                    $entryStream.Write($entryBytes, 0, $entryBytes.Length)
                } finally { $entryStream.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $fileStream.Dispose() }
}
function Invoke-ExtractedArchiveVerification {
    param([string]$Path, [string[]]$Names)
    $script:zipPath = $Path
    $script:stageNames = $Names
    $script:zipReadStream = [System.IO.File]::OpenRead($Path)
    try { & $script:ArchiveVerificationBlock }
    finally {
        if ($null -ne $script:zipReadStream) { $script:zipReadStream.Dispose() }
        $script:zipReadStream = $null
    }
}
function New-PrototypeSafetyFixture {
    param([string]$Root)
    $null = [System.IO.Directory]::CreateDirectory((Join-Path $Root 'gui/Services'))
    $null = [System.IO.Directory]::CreateDirectory((Join-Path $Root 'gui/ViewModels'))
    $null = [System.IO.Directory]::CreateDirectory((Join-Path $Root 'gui/Views'))
    $null = [System.IO.Directory]::CreateDirectory((Join-Path $Root 'gui-bridge'))
    $null = [System.IO.Directory]::CreateDirectory((Join-Path $Root 'docs'))
    Set-FixtureText (Join-Path $Root 'gui/Services/ReadOnlyRunLauncher.cs') 'private static bool IsSupportedOperation(string? operation) => string.Equals(operation, "DetectOnly", StringComparison.Ordinal);'
    Set-FixtureText (Join-Path $Root 'gui/ViewModels/ViewModels.cs') "private Task StartFullInvestigation(CancellationToken cancellationToken) => Task.CompletedTask;`nprivate bool CanExecuteFullInvestigation() => false;"
    Set-FixtureText (Join-Path $Root 'gui/Views/InvestigationView.xaml') '<Button Content="Full Investigation (Unavailable)" IsEnabled="False" />'
    Set-FixtureText (Join-Path $Root 'START-READONLY-GUI.bat') 'start "" "%~dp0ScreenConnectCleanup.Gui.exe"'
    $adapter = @'
$guiStateLibrary = Join-Path $PSScriptRoot 'GuiState.ps1'
$scriptPath = if ($Stage -eq 'SnapshotBefore') { Join-Path $ScriptRoot 'collect-snapshot.ps1' } else { Join-Path $ScriptRoot 'detect-remote-access.ps1' }
'-OutRoot', $detectRoot, '-NoPause', '-NoZip', '-NoReportShare', '-TranscriptCopyDir', $RunRoot
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { throw 'Fixed investigation stage script is missing.' }
. $guiStateLibrary
'@
    Set-FixtureText (Join-Path $Root 'gui-bridge/Invoke-GuiStage.ps1') $adapter
    Set-FixtureText (Join-Path $Root 'gui-bridge/GuiState.ps1') '# synthetic state library'
    $detector = @'
if (-not $NoReportShare) {
    $uploadRc = Invoke-ReportUploader
}
if (-not $NoZip) {
    $zipRc = Invoke-DesktopZip
}
'@
    Set-FixtureText (Join-Path $Root 'detect-remote-access.ps1') $detector
}

$functionNames = @(
    'Get-RelativePath',
    'Assert-NoReparsePath',
    'Assert-ParsedPowerShell',
    'Assert-PrototypeSafety',
    'Assert-ArchiveMemberSafety',
    'Get-Sha256Hex',
    'Get-EntrySha256'
)
foreach ($functionName in $functionNames) {
    $requestedName = $functionName
    $definitions = @($builderAst.FindAll({
        param($node)
        return ($node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $requestedName)
    }, $true))
    if ($definitions.Count -ne 1) { throw "Expected one extractable builder function named $functionName; got $($definitions.Count)." }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}

$verificationCandidates = @($builderAst.FindAll({
    param($node)
    if ($node -isnot [System.Management.Automation.Language.TryStatementAst] -or $null -eq $node.Finally) { return $false }
    $bodyText = $node.Body.Extent.Text
    $finallyText = $node.Finally.Extent.Text
    return ($bodyText.Contains('$actualEntries.Count -ne $stageNames.Count') -and
        $bodyText.Contains('$actualHash -cne $manifestMap[$entry.FullName]') -and
        $finallyText.Contains('$zipReadStream.Dispose()'))
}, $true))
if ($verificationCandidates.Count -ne 1) { throw "Expected one AST-bounded ZIP verification block; got $($verificationCandidates.Count)." }
$script:ArchiveVerificationBlock = [scriptblock]::Create($verificationCandidates[0].Extent.Text)

$topLevelStatements = @($builderAst.EndBlock.Statements)
$hashStatement = @($topLevelStatements | Where-Object { $_.Extent.Text.TrimStart().StartsWith('$zipHash =') })
$hashWriteStatement = @($topLevelStatements | Where-Object { $_.Extent.Text.Contains('[System.IO.File]::WriteAllText($zipHashPath') })
if ($hashStatement.Count -ne 1 -or $hashWriteStatement.Count -ne 1) {
    throw 'Could not isolate the builder ZIP digest and sidecar statements by AST.'
}
$script:ZipHashBlock = [scriptblock]::Create($hashStatement[0].Extent.Text + "`n" + $hashWriteStatement[0].Extent.Text)

$scratchFullPath = [System.IO.Path]::GetFullPath($ScratchRoot)
if (-not [System.IO.Directory]::Exists($scratchFullPath)) { [void][System.IO.Directory]::CreateDirectory($scratchFullPath) }
$testRoot = Join-Path $scratchFullPath ('gui-packaging-tests-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($testRoot)

try {
    Assert-True ($builderSource.Contains('[System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT')) 'the builder retains its Windows-only packaging guard'

    $relativePath = Get-RelativePath -Root $testRoot -Path (Join-Path $testRoot 'nested/file.txt')
    Assert-True ($relativePath -ceq 'nested/file.txt') 'relative package paths use ZIP separators'
    Assert-Throws { Get-RelativePath -Root $testRoot -Path (Join-Path $testRoot '../outside.txt') } 'relative path traversal is rejected' 'Path escaped its fixed package root'
    Assert-NoReparsePath -Path $testRoot
    Assert-True $true 'ordinary synthetic fixture paths pass reparse-point screening'

    $validPowerShell = Join-Path $testRoot 'valid-input.ps1'
    $invalidPowerShell = Join-Path $testRoot 'invalid-input.ps1'
    Set-FixtureText $validPowerShell "Write-Output 'synthetic only'"
    Set-FixtureText $invalidPowerShell 'if ('
    Assert-ParsedPowerShell -Path $validPowerShell
    Assert-True $true 'PowerShell parser accepts a synthetic valid source file'
    Assert-Throws { Assert-ParsedPowerShell -Path $invalidPowerShell } 'PowerShell parse errors are rejected' 'PowerShell parse failed'

    $allowedMembers = @(
        'ScreenConnectCleanup.Gui.exe',
        'System.Runtime.dll',
        'START-READONLY-GUI.bat',
        'BUILD-INFO.txt',
        'PACKAGE-MANIFEST.sha256',
        'docs/GUI-READONLY-PROTOTYPE.md',
        'gui-bridge/Invoke-GuiStage.ps1',
        'gui-bridge/GuiState.ps1',
        'detect-remote-access.ps1'
    )
    Assert-ArchiveMemberSafety -Names $allowedMembers
    Assert-True $true 'the reviewed DetectOnly package allowlist is accepted'

    $unsafeMembers = @(
        @{ Label = 'unapproved PowerShell script'; Name = 'scripts/extra.ps1'; Error = 'Unapproved executable PowerShell input' },
        @{ Label = 'snapshot collector'; Name = 'collect-snapshot.ps1'; Error = 'Forbidden file reached the prototype package' },
        @{ Label = 'cleanup runner'; Name = 'sc-cleanup.ps1'; Error = 'Forbidden file reached the prototype package' },
        @{ Label = 'remover'; Name = 'remove-screenconnect.ps1'; Error = 'Forbidden file reached the prototype package' },
        @{ Label = 'uploader'; Name = 'Submit-ConnectWiseReport.ps1'; Error = 'Forbidden file reached the prototype package' },
        @{ Label = 'environment secret'; Name = '.env.production'; Error = 'Secret-like file path reached the prototype package' },
        @{ Label = 'credential file'; Name = 'config/credentials.json'; Error = 'Secret-like file path reached the prototype package' },
        @{ Label = 'private key'; Name = 'certs/client.pfx'; Error = 'Secret-like file path reached the prototype package' },
        @{ Label = 'Phase 4 input'; Name = 'tests/gui/phase4/fixture.json'; Error = 'Test, tool, Phase 4, or Phase 5 input reached the package' },
        @{ Label = 'Phase 5 input'; Name = 'phase5/fixture.json'; Error = 'Test, tool, Phase 4, or Phase 5 input reached the package' },
        @{ Label = 'parent traversal'; Name = '../outside.txt'; Error = 'Unsafe ZIP member path' },
        @{ Label = 'nested traversal'; Name = 'docs/../../outside.txt'; Error = 'Unsafe ZIP member path' },
        @{ Label = 'absolute path'; Name = '/outside.txt'; Error = 'Unsafe ZIP member path' },
        @{ Label = 'drive path'; Name = 'C:/outside.txt'; Error = 'Unsafe ZIP member path' },
        @{ Label = 'backslash path'; Name = 'gui-bridge\evil.ps1'; Error = 'Unsafe ZIP member path' }
    )
    foreach ($unsafeMember in $unsafeMembers) {
        $memberName = [string]$unsafeMember.Name
        $expectedError = [string]$unsafeMember.Error
        Assert-Throws { Assert-ArchiveMemberSafety -Names @($memberName) } ([string]$unsafeMember.Label) $expectedError
    }

    $safetyFixtureRoot = Join-Path $testRoot 'prototype-safety-fixture'
    New-PrototypeSafetyFixture -Root $safetyFixtureRoot
    $originalRepoRoot = $repoRoot
    try {
        $repoRoot = $safetyFixtureRoot
        Assert-PrototypeSafety
        Assert-True $true 'synthetic DetectOnly launcher, adapter, and uploader gates pass prototype safety validation'

        $detectorPath = Join-Path $safetyFixtureRoot 'detect-remote-access.ps1'
        Set-FixtureText $detectorPath "if (`$NoReportShare) { `$uploadRc = Invoke-ReportUploader }`nif (-not `$NoZip) { `$zipRc = Invoke-DesktopZip }"
        Assert-Throws { Assert-PrototypeSafety } 'an uploader call outside its opt-out gate is rejected' 'Detector upload and Desktop-zip gates changed'
    } finally { $repoRoot = $originalRepoRoot }

    $payloadText = 'synthetic immutable payload'
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadText)
    $payloadHash = Get-IndependentSha256 -Bytes $payloadBytes
    $validManifest = "$payloadHash  payload.txt`n"
    $validZip = Join-Path $testRoot 'valid-package.zip'
    New-SyntheticZip -Path $validZip -Entries @(
        @{ Name = 'payload.txt'; Text = $payloadText },
        @{ Name = 'PACKAGE-MANIFEST.sha256'; Text = $validManifest }
    )
    $zipHashBefore = (Get-FileHash -LiteralPath $validZip -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-ExtractedArchiveVerification -Path $validZip -Names @('payload.txt', 'PACKAGE-MANIFEST.sha256')
    $zipHashAfter = (Get-FileHash -LiteralPath $validZip -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($zipHashBefore -ceq $zipHashAfter) 'successful verification leaves the ZIP bytes immutable'

    $validReadStream = [System.IO.File]::OpenRead($validZip)
    try {
        $validArchive = New-Object System.IO.Compression.ZipArchive($validReadStream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            $payloadEntryHash = Get-EntrySha256 -Entry $validArchive.GetEntry('payload.txt')
            Assert-True ($payloadEntryHash -ceq $payloadHash) 'the extracted member SHA-256 matches the independent payload digest'
        } finally { $validArchive.Dispose() }
    } finally { $validReadStream.Dispose() }
    $abcHex = Get-Sha256Hex -Bytes ([System.Text.Encoding]::ASCII.GetBytes('abc'))
    Assert-True ($abcHex -ceq '616263') 'the extracted byte-to-hex helper encodes supplied bytes without hashing them'

    $script:zipPath = $validZip
    $script:zipHashPath = "${validZip}.sha256"
    & $script:ZipHashBlock
    $sidecarText = [System.IO.File]::ReadAllText($script:zipHashPath)
    $sidecarBytes = [System.IO.File]::ReadAllBytes($script:zipHashPath)
    $sidecarHasBom = $sidecarBytes.Length -ge 3 -and $sidecarBytes[0] -eq 239 -and $sidecarBytes[1] -eq 187 -and $sidecarBytes[2] -eq 191
    Assert-True (-not $sidecarHasBom -and $sidecarText.TrimEnd([char[]]@([char]13, [char]10)) -ceq "$zipHashAfter  $( [System.IO.Path]::GetFileName($validZip) )") 'the extracted whole-ZIP digest writer emits the verified SHA-256 sidecar without a BOM'

    $duplicateZip = Join-Path $testRoot 'duplicate-members.zip'
    New-SyntheticZip -Path $duplicateZip -Entries @(
        @{ Name = 'payload.txt'; Text = 'first' },
        @{ Name = 'payload.txt'; Text = 'second' }
    )
    Assert-Throws { Invoke-ExtractedArchiveVerification -Path $duplicateZip -Names @('payload.txt', 'payload.txt') } 'duplicate ZIP members are rejected' 'Duplicate ZIP member'

    $duplicateManifestZip = Join-Path $testRoot 'duplicate-manifest.zip'
    $duplicateManifest = "$payloadHash  payload.txt`n$payloadHash  payload.txt`n"
    New-SyntheticZip -Path $duplicateManifestZip -Entries @(
        @{ Name = 'payload.txt'; Text = $payloadText },
        @{ Name = 'PACKAGE-MANIFEST.sha256'; Text = $duplicateManifest }
    )
    Assert-Throws { Invoke-ExtractedArchiveVerification -Path $duplicateManifestZip -Names @('payload.txt', 'PACKAGE-MANIFEST.sha256') } 'duplicate manifest members are rejected' 'Duplicate manifest member'

    $missingManifestZip = Join-Path $testRoot 'missing-manifest.zip'
    New-SyntheticZip -Path $missingManifestZip -Entries @(@{ Name = 'payload.txt'; Text = $payloadText })
    Assert-Throws { Invoke-ExtractedArchiveVerification -Path $missingManifestZip -Names @('payload.txt') } 'a missing ZIP manifest is rejected' 'ZIP is missing PACKAGE-MANIFEST.sha256'

    $missingCoverageZip = Join-Path $testRoot 'missing-coverage.zip'
    $missingCoverageManifest = "$payloadHash  other.txt`n"
    New-SyntheticZip -Path $missingCoverageZip -Entries @(
        @{ Name = 'payload.txt'; Text = $payloadText },
        @{ Name = 'PACKAGE-MANIFEST.sha256'; Text = $missingCoverageManifest }
    )
    Assert-Throws { Invoke-ExtractedArchiveVerification -Path $missingCoverageZip -Names @('payload.txt', 'PACKAGE-MANIFEST.sha256') } 'every ZIP payload member must appear in the manifest' 'ZIP payload is not covered by the package manifest'

    $mismatchZip = Join-Path $testRoot 'hash-mismatch.zip'
    $wrongManifest = ('0' * 64) + '  payload.txt' + "`n"
    New-SyntheticZip -Path $mismatchZip -Entries @(
        @{ Name = 'payload.txt'; Text = $payloadText },
        @{ Name = 'PACKAGE-MANIFEST.sha256'; Text = $wrongManifest }
    )
    Assert-Throws { Invoke-ExtractedArchiveVerification -Path $mismatchZip -Names @('payload.txt', 'PACKAGE-MANIFEST.sha256') } 'a changed ZIP member hash is rejected' 'ZIP member integrity check failed'

    Write-Output "PASS: $script:Assertions assertions; AST-extracted package guards, safe member allowlist, synthetic ZIP manifests, member hashes, whole-ZIP digest, and immutable verification."
} finally {
    if ([System.IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
