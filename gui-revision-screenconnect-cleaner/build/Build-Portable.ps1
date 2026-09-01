# =====================================================================
# Build-Portable.ps1 -- stage the ScreenConnect Cleaner portable folder
# and produce a versioned, hash-signed ZIP for distribution.
#
# Windows PowerShell 5.1 compatible. Pure ASCII, no BOM.
#
# What it does:
#   1. Resolve a version (param > VERSION file > git describe > 0.1.0).
#   2. Stage the portable tree into <OutDir>/ScreenConnectCleaner-<Version>/.
#   3. Compute SHA256 of every staged file into SHA256SUMS.txt.
#   4. Zip to ScreenConnectCleaner-<Version>-portable.zip plus a
#      ScreenConnectCleaner-<Version>-portable.zip.sha256 sidecar.
#
# The script is defensive: missing optional files (README.md, LICENSE,
# CHANGELOG.md, tools/ ...) are skipped with a warning, never fatal, so
# the build does not break while sibling modules are still landing.
#
# Exit codes: 0 = built, 1 = fatal error, 2 = argument error.
# =====================================================================
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [string]$Version = '',
    [bool]$Zip = $true,
    [bool]$IncludeConfigs = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

# ---------------------------------------------------------------------
# Resolve the app root (this script lives in <app>/build/).
# ---------------------------------------------------------------------
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$AppRoot = Split-Path -Parent $ScriptRoot

# ---------------------------------------------------------------------
# Helpers (private, not exported).
# ---------------------------------------------------------------------
function TrimEnd-SccSlash {
    param([string]$Text)
    if (-not $Text -or $Text.Length -eq 0) { return $Text }
    $t = $Text
    while ($t.Length -gt 0 -and ($t[$t.Length - 1] -eq '\' -or $t[$t.Length - 1] -eq '/')) {
        $t = $t.Substring(0, $t.Length - 1)
    }
    return $t
}

function Get-SccBuildVersion {
    param([string]$AppRoot, [string]$ForcedVersion)

    if ($ForcedVersion -and $ForcedVersion.Trim().Length -gt 0) {
        return $ForcedVersion.Trim()
    }

    # VERSION file at app root.
    $versionFile = Join-Path $AppRoot 'VERSION'
    if (Test-Path -LiteralPath $versionFile) {
        $v = ([System.IO.File]::ReadAllText($versionFile)).Trim()
        if ($v.Length -gt 0) { return $v }
    }

    # git describe (needs git; ignore failure on build hosts without it).
    try {
        $git = Get-Command -Name 'git' -ErrorAction SilentlyContinue
        if ($git) {
            $desc = (& git -C $AppRoot describe --tags --always 2>$null)
            if ($LASTEXITCODE -eq 0 -and $desc -and $desc.Trim().Length -gt 0) {
                # Normalize: replace chars unsafe for a filename.
                $clean = $desc.Trim() -replace '[^\w\.\-]', '-'
                if ($clean.Length -gt 0) { return $clean }
            }
        }
    } catch { }

    return '0.1.0'
}

function Get-SccFileSha256 {
    param([string]$Path)
    $algo = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $bytes = $algo.ComputeHash($stream)
        } finally {
            $stream.Close()
        }
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $bytes) {
            $null = $sb.Append($b.ToString('x2'))
        }
        return $sb.ToString()
    } finally {
        $algo.Dispose()
    }
}

function Copy-SccStageItem {
    param(
        [string]$Source,
        [string]$DestDir
    )
    if (-not (Test-Path -LiteralPath $Source)) {
        Write-Warning ("Build: optional source not found, skipping: {0}" -f $Source)
        return $false
    }
    $leaf = Split-Path -Leaf $Source
    $dest = Join-Path $DestDir $leaf
    if (Test-Path -LiteralPath $Source -PathType Container) {
        if (-not (Test-Path -LiteralPath $dest)) {
            $null = New-Item -ItemType Directory -Path $dest -Force
        }
        # Recursive copy preserving structure.
        $items = Get-ChildItem -Path $Source -Recurse -ErrorAction Stop
        foreach ($item in $items) {
            $srcBase = TrimEnd-SccSlash -Text $Source
            $rel = $item.FullName.Substring($srcBase.Length + 1)
            $target = Join-Path $dest $rel
            if ($item.PSIsContainer) {
                if (-not (Test-Path -LiteralPath $target)) {
                    $null = New-Item -ItemType Directory -Path $target -Force
                }
            } else {
                $parent = Split-Path -Parent $target
                if (-not (Test-Path -LiteralPath $parent)) {
                    $null = New-Item -ItemType Directory -Path $parent -Force
                }
                Copy-Item -LiteralPath $item.FullName -Destination $target -Force -ErrorAction Stop
            }
        }
    } else {
        Copy-Item -LiteralPath $Source -Destination $dest -Force -ErrorAction Stop
    }
    return $true
}

# Directories/files excluded from the portable tree.
$ExcludeDirs = @('tests', 'build', 'audit')
$ExcludeFiles = @('DEVIATIONS.md', 'DEVNOTES.md', '.gitignore', 'VERSION')
# Files whose name starts with DEVIATIONS (handles module-level notes too).
$ExcludePrefix = @('DEVIATIONS')

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
try {
    # OutDir default: <app>/build/output
    if (-not $OutDir -or $OutDir.Trim().Length -eq 0) {
        $OutDir = Join-Path $ScriptRoot 'output'
    }
    if (-not (Test-Path -LiteralPath $OutDir)) {
        $null = New-Item -ItemType Directory -Path $OutDir -Force
    }

    $Version = Get-SccBuildVersion -AppRoot $AppRoot -ForcedVersion $Version
    Write-Host ("Build: version = {0}" -f $Version)

    $StagedRoot = Join-Path $OutDir ("ScreenConnectCleaner-" + $Version)
    if (Test-Path -LiteralPath $StagedRoot) {
        # Clean prior staging for idempotency.
        Remove-Item -LiteralPath $StagedRoot -Recurse -Force -ErrorAction Stop
    }
    $null = New-Item -ItemType Directory -Path $StagedRoot -Force

    # --- Stage 1: entry point + launcher (always present) ---
    $null = Copy-SccStageItem -Source (Join-Path $AppRoot 'Scc.Cleaner.ps1') -DestDir $StagedRoot
    $null = Copy-SccStageItem -Source (Join-Path $AppRoot 'Start-ScreenConnectCleaner.bat') -DestDir $StagedRoot

    # --- Stage 2: source modules ---
    $null = Copy-SccStageItem -Source (Join-Path $AppRoot 'src') -DestDir $StagedRoot

    # --- Stage 3: config (optional) ---
    if ($IncludeConfigs) {
        $null = Copy-SccStageItem -Source (Join-Path $AppRoot 'config') -DestDir $StagedRoot
    }

    # --- Stage 4: docs (optional) ---
    $null = Copy-SccStageItem -Source (Join-Path $AppRoot 'docs') -DestDir $StagedRoot

    # --- Stage 5: tools (optional helper scripts) ---
    $null = Copy-SccStageItem -Source (Join-Path $AppRoot 'tools') -DestDir $StagedRoot

    # --- Stage 6: top-level readme/license/changelog (optional) ---
    foreach ($f in @('README.md', 'LICENSE', 'CHANGELOG.md')) {
        $null = Copy-SccStageItem -Source (Join-Path $AppRoot $f) -DestDir $StagedRoot
    }

    # --- Prune excluded items from the staged tree ---
    $pruned = 0
    $allItems = Get-ChildItem -Path $StagedRoot -Recurse -ErrorAction Stop
    foreach ($item in $allItems) {
        if ($item.PSIsContainer) {
            $leaf = Split-Path -Leaf $item.FullName
            if ($ExcludeDirs -contains $leaf) {
                Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
                $pruned++
            }
        } else {
            $leaf = Split-Path -Leaf $item.FullName
            if ($ExcludeFiles -contains $leaf) {
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                $pruned++
                continue
            }
            $isExcluded = $false
            foreach ($p in $ExcludePrefix) {
                if ($leaf.StartsWith($p)) { $isExcluded = $true; break }
            }
            if ($isExcluded) {
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                $pruned++
            }
        }
    }
    Write-Host ("Build: pruned {0} excluded item(s)." -f $pruned)

    # --- Compute SHA256 of every staged file ---
    $sumsPath = Join-Path $StagedRoot 'SHA256SUMS.txt'
    $fileList = Get-ChildItem -Path $StagedRoot -Recurse -File -ErrorAction Stop |
        Sort-Object -Property FullName
    $sumLines = New-Object System.Collections.ArrayList
    $base = TrimEnd-SccSlash -Text $StagedRoot
    foreach ($file in $fileList) {
        $hash = Get-SccFileSha256 -Path $file.FullName
        # Store relative path with forward slashes for portability.
        $rel = $file.FullName.Substring($base.Length + 1) -replace '\\', '/'
        $null = $sumLines.Add(("{0}  {1}" -f $hash, $rel))
    }
    [System.IO.File]::WriteAllText($sumsPath, ($sumLines -join [Environment]::NewLine) + [Environment]::NewLine, [System.Text.Encoding]::ASCII)
    Write-Host ("Build: wrote {0} hashes to SHA256SUMS.txt" -f $sumLines.Count)

    # --- Zip ---
    if ($Zip) {
        $zipName = ("ScreenConnectCleaner-{0}-portable.zip" -f $Version)
        $zipPath = Join-Path $OutDir $zipName
        if (Test-Path -LiteralPath $zipPath) {
            Remove-Item -LiteralPath $zipPath -Force -ErrorAction Stop
        }
        # Compress-Archive needs the parent of the folder, with the folder name
        # becoming the archive root entry.
        $parent = Split-Path -Parent $StagedRoot
        $entryName = Split-Path -Leaf $StagedRoot
        Compress-Archive -Path (Join-Path $parent $entryName) -DestinationPath $zipPath -CompressionLevel Optimal -ErrorAction Stop

        # Sidecar hash of the ZIP itself.
        $zipHash = Get-SccFileSha256 -Path $zipPath
        $sidecar = ($zipPath + '.sha256')
        [System.IO.File]::WriteAllText($sidecar, ($zipHash + "  " + $zipName + [Environment]::NewLine), [System.Text.Encoding]::ASCII)

        Write-Host ("Build: wrote {0} ({1} bytes)" -f $zipPath, (Get-Item -LiteralPath $zipPath).Length)
        Write-Host ("Build: wrote {0}" -f $sidecar)

        # Report
        Write-Host ''
        Write-Host 'Artifacts:'
        Write-Host ('  staged : {0}' -f $StagedRoot)
        Write-Host ('  zip    : {0}' -f $zipPath)
        Write-Host ('  sha256 : {0}' -f $sidecar)
    } else {
        Write-Host 'Build: zipping skipped (-Zip:$false). Staged folder only:'
        Write-Host ('  staged : {0}' -f $StagedRoot)
    }

    exit 0
} catch {
    Write-Error ("Build failed: {0}" -f $_.Exception.Message)
    if ($_.ScriptStackTrace) { Write-Error $_.ScriptStackTrace }
    exit 1
}
