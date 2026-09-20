# Verifies a portable ScreenConnect Cleaner ZIP and its integrity metadata.
# Compatible with Windows PowerShell 5.1 and pwsh.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ZipPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

function Assert-SccPackage {
    param(
        [string]$Path,
        [string]$Message
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw $Message
    }
}

$extract = $null
try {
    $zip = [System.IO.Path]::GetFullPath($ZipPath)
    Assert-SccPackage -Path $zip -Message ('Portable ZIP not found: ' + $zip)
    if (-not $zip.EndsWith('.zip', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('Portable package must be a .zip file: ' + $zip)
    }

    $sidecar = $zip + '.sha256'
    Assert-SccPackage -Path $sidecar -Message ('ZIP SHA256 sidecar not found: ' + $sidecar)
    $sidecarText = ([System.IO.File]::ReadAllText($sidecar)).Trim()
    if ($sidecarText -notmatch '^([A-Fa-f0-9]{64})  (.+)$') {
        throw ('ZIP SHA256 sidecar has invalid format: ' + $sidecar)
    }
    $expectedZipHash = $Matches[1].ToLowerInvariant()
    $sidecarName = $Matches[2]
    if ($sidecarName -ne [System.IO.Path]::GetFileName($zip)) {
        throw ('ZIP SHA256 sidecar names a different archive: ' + $sidecarName)
    }
    $actualZipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
    if ($actualZipHash -ne $expectedZipHash) {
        throw ('ZIP SHA256 sidecar mismatch: expected ' + $expectedZipHash + ', got ' + $actualZipHash)
    }

    $extract = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-package-verify-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $extract -Force
    Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
    $roots = @(Get-ChildItem -LiteralPath $extract -Directory)
    if ($roots.Count -ne 1) {
        throw ('Portable ZIP must contain exactly one top-level directory; found ' + $roots.Count)
    }
    $root = $roots[0].FullName

    foreach ($relative in @('Scc.Cleaner.ps1', 'Start-ScreenConnectCleaner.bat', 'src', 'config', 'docs', 'SHA256SUMS.txt')) {
        Assert-SccPackage -Path (Join-Path $root $relative) -Message ('Portable package missing required item: ' + $relative)
    }

    $manifest = Join-Path $root 'SHA256SUMS.txt'
    $lines = @([System.IO.File]::ReadAllLines($manifest))
    if ($lines.Count -eq 0) {
        throw 'SHA256SUMS.txt contains no file entries.'
    }
    foreach ($line in $lines) {
        if ($line -notmatch '^([A-Fa-f0-9]{64})  (.+)$') {
            throw ('SHA256SUMS.txt has invalid entry: ' + $line)
        }
        $expectedHash = $Matches[1].ToLowerInvariant()
        $relative = $Matches[2]
        if ([System.IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
            throw ('SHA256SUMS.txt contains an unsafe relative path: ' + $relative)
        }
        $member = Join-Path $root ($relative -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        Assert-SccPackage -Path $member -Message ('SHA256SUMS.txt member is missing: ' + $relative)
        if (Test-Path -LiteralPath $member -PathType Container) {
            throw ('SHA256SUMS.txt member is not a file: ' + $relative)
        }
        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $member).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) {
            throw ('SHA256SUMS.txt mismatch for ' + $relative + ': expected ' + $expectedHash + ', got ' + $actualHash)
        }
    }

    Write-Host ('Portable package integrity verified: ' + $zip)
    exit 0
} catch {
    Write-Error ('Portable package verification failed: ' + $_.Exception.Message)
    exit 1
} finally {
    if ($extract -and (Test-Path -LiteralPath $extract)) {
        Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue
    }
}
