[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('(?i)^[0-9a-f]{40}$')]
    [string]$ReviewedSha,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$reviewedSha = $ReviewedSha.ToLowerInvariant()
Add-Type -AssemblyName System.IO.Compression

function Invoke-Git {
    param([Parameter(Mandatory = $true)][string[]]$GitArgs)
    $output = & git -C $repoRoot @GitArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git $($GitArgs -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return ($output -join [Environment]::NewLine).Trim()
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $rootPrefix = $Root.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) + [System.IO.Path]::DirectorySeparatorChar
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escaped its fixed package root: $Path"
    }
    return $fullPath.Substring($rootPrefix.Length).Replace([System.IO.Path]::DirectorySeparatorChar, '/')
}

function Assert-NoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($volumeRoot)) { throw "Cannot resolve filesystem root for $Path" }
    $current = $volumeRoot
    $rootAttributes = $null
    try { $rootAttributes = [System.IO.File]::GetAttributes($current) } catch [System.IO.IOException] { }
    if ($null -ne $rootAttributes -and ($rootAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse-point path component is not allowed: $current"
    }
    $parts = @($fullPath.Substring($volumeRoot.Length).Split([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar), [System.StringSplitOptions]::RemoveEmptyEntries))
    foreach ($part in $parts) {
        $current = [System.IO.Path]::Combine($current, $part)
        $attributes = $null
        try { $attributes = [System.IO.File]::GetAttributes($current) } catch [System.IO.FileNotFoundException] { continue } catch [System.IO.DirectoryNotFoundException] { continue }
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse-point path component is not allowed: $current"
        }
    }
}

function Assert-ParsedPowerShell {
    param([Parameter(Mandatory = $true)][string]$Path)
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "PowerShell parse failed for $Path`: $($parseErrors[0].Message)" }
}

function Assert-PrototypeSafety {
    $launcherPath = Join-Path $repoRoot 'gui/Services/ReadOnlyRunLauncher.cs'
    $viewModelPath = Join-Path $repoRoot 'gui/ViewModels/ViewModels.cs'
    $viewPath = Join-Path $repoRoot 'gui/Views/InvestigationView.xaml'
    $launcherBatchPath = Join-Path $repoRoot 'START-READONLY-GUI.bat'
    $adapterPath = Join-Path $repoRoot 'gui-bridge/Invoke-GuiStage.ps1'
    $statePath = Join-Path $repoRoot 'gui-bridge/GuiState.ps1'
    $detectorPath = Join-Path $repoRoot 'detect-remote-access.ps1'

    foreach ($path in @($launcherPath, $viewModelPath, $viewPath, $launcherBatchPath, $adapterPath, $statePath, $detectorPath)) {
        if (-not [System.IO.File]::Exists($path)) { throw "Required reviewed prototype input is missing: $path" }
    }

    $launcherSource = [System.IO.File]::ReadAllText($launcherPath)
    if ($launcherSource -notmatch 'private static bool IsSupportedOperation\(string\? operation\)\s*=>\s*string\.Equals\(operation,\s*"DetectOnly",\s*StringComparison\.Ordinal\);') {
        throw 'The launcher no longer restricts real runs to the exact DetectOnly operation.'
    }
    $viewModelSource = [System.IO.File]::ReadAllText($viewModelPath)
    if ($viewModelSource -notmatch 'private Task StartFullInvestigation\(CancellationToken cancellationToken\)\s*=>\s*Task\.CompletedTask;' -or
        $viewModelSource -notmatch 'private bool CanExecuteFullInvestigation\(\)\s*=>\s*false;') {
        throw 'FullInvestigation must remain inert and unavailable in the real-run view model.'
    }
    if ($viewModelSource -match 'RunAsync\s*\(\s*"FullInvestigation"') {
        throw 'A GUI code path attempts to launch FullInvestigation.'
    }
    $viewSource = [System.IO.File]::ReadAllText($viewPath)
    if ($viewSource -notmatch '(?s)Content="Full Investigation \(Unavailable\)".*?IsEnabled="False"') {
        throw 'The FullInvestigation UI action is not explicitly disabled.'
    }
    $batchSource = [System.IO.File]::ReadAllText($launcherBatchPath)
    if ($batchSource -notmatch '(?im)^\s*start\s+""\s+"%~dp0ScreenConnectCleanup\.Gui\.exe"\s*$' -or
        $batchSource -match '(?i)runas|requireadministrator|verb\s*=\s*runas') {
        throw 'The one-click launcher must start the packaged GUI directly without requesting elevation.'
    }

    $adapterSource = [System.IO.File]::ReadAllText($adapterPath)
    $normalizedAdapter = [System.Text.RegularExpressions.Regex]::Replace($adapterSource, '\s+', ' ').Trim()
    $requiredAdapterText = @(
        '$guiStateLibrary = Join-Path $PSScriptRoot ''GuiState.ps1''',
        "`$scriptPath = if (`$Stage -eq 'SnapshotBefore') { Join-Path `$ScriptRoot 'collect-snapshot.ps1' } else { Join-Path `$ScriptRoot 'detect-remote-access.ps1' }",
        "'-OutRoot', `$detectRoot, '-NoPause', '-NoZip', '-NoReportShare', '-TranscriptCopyDir', `$RunRoot",
        "if (-not (Test-Path -LiteralPath `$scriptPath -PathType Leaf)) { throw 'Fixed investigation stage script is missing.' }"
    )
    foreach ($required in $requiredAdapterText) {
        $normalized = [System.Text.RegularExpressions.Regex]::Replace($required, '\s+', ' ').Trim()
        if (-not $normalizedAdapter.Contains($normalized)) { throw "The fixed adapter safety contract changed: $required" }
    }
    $adapterTokens = $null
    $adapterErrors = $null
    $adapterAst = [System.Management.Automation.Language.Parser]::ParseFile($adapterPath, [ref]$adapterTokens, [ref]$adapterErrors)
    if ($adapterErrors.Count -gt 0) { throw "Adapter parse failed: $($adapterErrors[0].Message)" }
    $dotSources = @($adapterAst.FindAll({
        param($node)
        return ($node -is [System.Management.Automation.Language.CommandAst] -and $node.InvocationOperator.ToString() -eq 'Dot')
    }, $true))
    if ($dotSources.Count -ne 1 -or (($dotSources[0].Extent.Text -replace '\s+', ' ').Trim()) -cne '. $guiStateLibrary') {
        throw 'The fixed stage adapter may dot-source only its adjacent GuiState.ps1 library.'
    }

    $detectorSource = [System.IO.File]::ReadAllText($detectorPath)
    if ($detectorSource -notmatch '(?s)if\s*\(-not\s+\$NoReportShare\)\s*\{\s*\$uploadRc\s*=\s*Invoke-ReportUploader' -or
        $detectorSource -notmatch '(?s)if\s*\(-not\s+\$NoZip\)\s*\{') {
        throw 'Detector upload and Desktop-zip gates changed; refusing to package without a new safety review.'
    }

    Assert-ParsedPowerShell -Path $adapterPath
    Assert-ParsedPowerShell -Path $statePath
    Assert-ParsedPowerShell -Path $detectorPath
}

function Assert-ArchiveMemberSafety {
    param([Parameter(Mandatory = $true)][string[]]$Names)

    $allowedScripts = @(
        'gui-bridge/Invoke-GuiStage.ps1',
        'gui-bridge/GuiState.ps1',
        'detect-remote-access.ps1'
    )
    $forbiddenNames = @(
        'collect-snapshot.ps1', 'sc-cleanup.ps1', 'remove-screenconnect.ps1',
        'Invoke-ReviewAndRemove.ps1', 'Invoke-GUIScanner.ps1', 'Invoke-AVUninstaller.ps1',
        'Get-ScannerFindings.ps1', 'Get-MalwarebytesDownloadDiagnostics.ps1',
        'Submit-ConnectWiseReport.ps1', 'preflight.ps1', 'diff-snapshots.ps1',
        'New-InvestigationReport.ps1', 'Get-ToolPack.ps1', 'Get-AVTools.ps1',
        'targets.json', 'microbin-url.txt'
    )
    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name) -or $name.IndexOf([char]92) -ge 0 -or $name.Contains(':') -or $name.StartsWith('/') -or $name -match '(^|/)\.\.?(/|$)') {
            throw "Unsafe ZIP member path: $name"
        }
        $leaf = [System.IO.Path]::GetFileName($name)
        if ($forbiddenNames -contains $leaf) { throw "Forbidden file reached the prototype package: $name" }
        if ($name -match '(?i)(^|/)(tests|tools|phase4|phase5)(/|$)') { throw "Test, tool, Phase 4, or Phase 5 input reached the package: $name" }
        if ($name -match '(?i)(^|/)(\.env[^/]*|[^/]*(secret|credential|password)[^/]*|[^/]+\.(pem|pfx|key))$') {
            throw "Secret-like file path reached the prototype package: $name"
        }
        if ([System.IO.Path]::GetExtension($leaf) -ieq '.ps1' -and $allowedScripts -cnotcontains $name) {
            throw "Unapproved executable PowerShell input reached the package: $name"
        }
        if ([System.IO.Path]::GetExtension($leaf) -in @('.pdb', '.cs', '.xaml', '.psm1', '.psd1', '.cmd', '.sh', '.py', '.env')) {
            throw "Source, debug, or unrelated tooling file reached the package: $name"
        }
        if ([System.IO.Path]::GetExtension($leaf) -ieq '.bat' -and $name -cne 'START-READONLY-GUI.bat') {
            throw "Unapproved batch file reached the package: $name"
        }
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return ([System.BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant())
}

function Get-EntrySha256 {
    param([Parameter(Mandatory = $true)][System.IO.Compression.ZipArchiveEntry]$Entry)
    $stream = $Entry.Open()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return Get-Sha256Hex -Bytes $sha.ComputeHash($stream) }
    finally { $sha.Dispose(); $stream.Dispose() }
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'The self-contained WPF prototype must be packaged on Windows CI.'
}

$headSha = Invoke-Git -GitArgs @('rev-parse', 'HEAD')
if (-not [string]::Equals($headSha, $reviewedSha, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Checkout SHA $headSha does not match the reviewed source SHA $reviewedSha."
}
$sourceStatus = Invoke-Git -GitArgs @('status', '--porcelain=v1', '--untracked-files=all')
if (-not [string]::IsNullOrWhiteSpace($sourceStatus)) {
    throw "The working tree is not the exact reviewed checkout; refusing to package any dirty or untracked source:`n$sourceStatus"
}

$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$repoPrefix = $repoRoot.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) + [System.IO.Path]::DirectorySeparatorChar
if ([string]::Equals($outputRoot, $repoRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    $outputRoot.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must be outside the repository so no package artifacts can enter the source tree.'
}
Assert-NoReparsePath -Path $outputRoot
if ([System.IO.Directory]::Exists($outputRoot)) {
    if (@([System.IO.Directory]::EnumerateFileSystemEntries($outputRoot)).Count -gt 0) {
        throw "OutputDirectory must be empty; refusing to overwrite existing content: $outputRoot"
    }
} else {
    [void][System.IO.Directory]::CreateDirectory($outputRoot)
}

Assert-PrototypeSafety

$publishRoot = Join-Path $outputRoot 'publish'
$stageRoot = Join-Path $outputRoot 'stage'
$projectPath = Join-Path $repoRoot 'gui/ScreenConnectCleanup.Gui.csproj'
$zipPath = Join-Path $outputRoot 'gui-readonly-prototype-win-x64.zip'
$zipHashPath = "$zipPath.sha256"
[void][System.IO.Directory]::CreateDirectory($publishRoot)
[void][System.IO.Directory]::CreateDirectory($stageRoot)

& dotnet publish $projectPath --configuration Release --runtime win-x64 --self-contained true `
    --output $publishRoot -p:PublishSingleFile=false -p:DebugSymbols=false -p:DebugType=None -p:PublishReadyToRun=false
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }

$publishFiles = @(Get-ChildItem -LiteralPath $publishRoot -File -Recurse)
if ($publishFiles.Count -eq 0) { throw 'dotnet publish produced an empty directory.' }
if (@($publishFiles | Where-Object { $_.Name -ceq 'ScreenConnectCleanup.Gui.exe' }).Count -ne 1) {
    throw 'Published output must contain exactly one ScreenConnectCleanup.Gui.exe.'
}
foreach ($file in $publishFiles) {
    if ([System.IO.Path]::GetExtension($file.Name) -in @('.ps1', '.bat', '.cmd', '.pdb', '.cs', '.xaml', '.psm1', '.psd1', '.py', '.sh')) {
        throw "Unexpected script, source, or debug file in the WPF publish output: $($file.FullName)"
    }
    if ($file.Name -match '(?i)(\.env|secret|credential|password|\.pem$|\.pfx$|\.key$)') {
        throw "Secret-like file reached the WPF publish output: $($file.Name)"
    }
}

foreach ($file in $publishFiles) {
    $relative = Get-RelativePath -Root $publishRoot -Path $file.FullName
    $destination = Join-Path $stageRoot ($relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $destinationDirectory = Split-Path -Parent $destination
    if (-not [System.IO.Directory]::Exists($destinationDirectory)) { [void][System.IO.Directory]::CreateDirectory($destinationDirectory) }
    [System.IO.File]::Copy($file.FullName, $destination, $false)
}

$bridgeDirectory = Join-Path $stageRoot 'gui-bridge'
$docsDirectory = Join-Path $stageRoot 'docs'
[void][System.IO.Directory]::CreateDirectory($bridgeDirectory)
[void][System.IO.Directory]::CreateDirectory($docsDirectory)
[System.IO.File]::Copy((Join-Path $repoRoot 'gui-bridge/Invoke-GuiStage.ps1'), (Join-Path $bridgeDirectory 'Invoke-GuiStage.ps1'), $false)
[System.IO.File]::Copy((Join-Path $repoRoot 'gui-bridge/GuiState.ps1'), (Join-Path $bridgeDirectory 'GuiState.ps1'), $false)
[System.IO.File]::Copy((Join-Path $repoRoot 'detect-remote-access.ps1'), (Join-Path $stageRoot 'detect-remote-access.ps1'), $false)
[System.IO.File]::Copy((Join-Path $repoRoot 'START-READONLY-GUI.bat'), (Join-Path $stageRoot 'START-READONLY-GUI.bat'), $false)
[System.IO.File]::Copy((Join-Path $repoRoot 'docs/GUI-READONLY-PROTOTYPE.md'), (Join-Path $docsDirectory 'GUI-READONLY-PROTOTYPE.md'), $false)

$buildInfo = @(
    'Product=ScreenConnect Cleanup Detect-Only GUI Prototype',
    ('SourceCommit=' + $reviewedSha),
    'Runtime=win-x64; self-contained .NET 10 WPF',
    'Execution=DetectOnly only; non-elevated Windows PowerShell 5.1',
    'No detector, scanner, remover, upload, or live system action was run by this build.'
) -join "`n"
[System.IO.File]::WriteAllText((Join-Path $stageRoot 'BUILD-INFO.txt'), ($buildInfo + "`n"), (New-Object System.Text.UTF8Encoding($false)))

$stageFiles = @(Get-ChildItem -LiteralPath $stageRoot -File -Recurse | Sort-Object { Get-RelativePath -Root $stageRoot -Path $_.FullName })
$manifestLines = @()
foreach ($file in $stageFiles) {
    $relative = Get-RelativePath -Root $stageRoot -Path $file.FullName
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestLines += "$hash  $relative"
}
[System.IO.File]::WriteAllLines((Join-Path $stageRoot 'PACKAGE-MANIFEST.sha256'), [string[]]$manifestLines, (New-Object System.Text.UTF8Encoding($false)))

$allStageFiles = @(Get-ChildItem -LiteralPath $stageRoot -File -Recurse)
$stageNames = @($allStageFiles | ForEach-Object { Get-RelativePath -Root $stageRoot -Path $_.FullName })
Assert-ArchiveMemberSafety -Names $stageNames
if ($stageNames -cnotcontains 'START-READONLY-GUI.bat' -or
    $stageNames -cnotcontains 'detect-remote-access.ps1' -or
    $stageNames -cnotcontains 'gui-bridge/Invoke-GuiStage.ps1' -or
    $stageNames -cnotcontains 'gui-bridge/GuiState.ps1' -or
    $stageNames -cnotcontains 'docs/GUI-READONLY-PROTOTYPE.md' -or
    $stageNames -cnotcontains 'PACKAGE-MANIFEST.sha256' -or
    $stageNames -cnotcontains 'BUILD-INFO.txt') {
    throw 'The package is missing a required launcher, fixed read-only dependency, disclosure, or integrity record.'
}

$zipStream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try {
    $archive = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($file in ($allStageFiles | Sort-Object { Get-RelativePath -Root $stageRoot -Path $_.FullName })) {
            $relative = Get-RelativePath -Root $stageRoot -Path $file.FullName
            $entry = $archive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
            $sourceStream = [System.IO.File]::OpenRead($file.FullName)
            $entryStream = $entry.Open()
            try { $sourceStream.CopyTo($entryStream) }
            finally { $entryStream.Dispose(); $sourceStream.Dispose() }
        }
    } finally { $archive.Dispose() }
} finally { $zipStream.Dispose() }

$zipReadStream = [System.IO.File]::OpenRead($zipPath)
try {
    $archive = New-Object System.IO.Compression.ZipArchive($zipReadStream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $actualEntries = @($archive.Entries | ForEach-Object { $_.FullName })
        if ($actualEntries.Count -ne $stageNames.Count) { throw "ZIP member count mismatch: expected $($stageNames.Count), got $($actualEntries.Count)." }
        $actualSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $actualEntries) {
            if (-not $actualSet.Add($name)) { throw "Duplicate ZIP member: $name" }
        }
        foreach ($name in $stageNames) {
            if (-not $actualSet.Contains($name)) { throw "Required staged file is missing from ZIP: $name" }
        }
        Assert-ArchiveMemberSafety -Names $actualEntries

        $manifestEntry = $archive.GetEntry('PACKAGE-MANIFEST.sha256')
        if ($null -eq $manifestEntry) { throw 'ZIP is missing PACKAGE-MANIFEST.sha256.' }
        $manifestStream = $manifestEntry.Open()
        $manifestReader = New-Object System.IO.StreamReader($manifestStream, [System.Text.Encoding]::UTF8, $true)
        try { $manifestText = $manifestReader.ReadToEnd() }
        finally { $manifestReader.Dispose(); $manifestStream.Dispose() }
        $manifestMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($line in @($manifestText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Malformed package manifest line: $line" }
            if ($manifestMap.ContainsKey($Matches[2])) { throw "Duplicate manifest member: $($Matches[2])" }
            $manifestMap.Add($Matches[2], $Matches[1])
        }
        $contentEntries = @($archive.Entries | Where-Object { $_.FullName -cne 'PACKAGE-MANIFEST.sha256' })
        if ($manifestMap.Count -ne $contentEntries.Count) { throw 'Package manifest does not cover every ZIP payload member exactly once.' }
        foreach ($entry in $contentEntries) {
            if (-not $manifestMap.ContainsKey($entry.FullName)) { throw "ZIP payload is not covered by the package manifest: $($entry.FullName)" }
            $actualHash = Get-EntrySha256 -Entry $entry
            if ($actualHash -cne $manifestMap[$entry.FullName]) { throw "ZIP member integrity check failed: $($entry.FullName)" }
        }
    } finally { $archive.Dispose() }
} finally { $zipReadStream.Dispose() }

$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText($zipHashPath, "$zipHash  $([System.IO.Path]::GetFileName($zipPath))`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Verified ZIP: $zipPath"
Write-Host "SHA-256: $zipHash"
Write-Host "Source SHA: $reviewedSha"
