# =====================================================================
# Install-Scc.ps1 -- optional installer for ScreenConnect Cleaner.
#
# Copies the portable tree to %ProgramFiles%\ScreenConnectCleaner,
# creates Start Menu shortcuts (app + docs), and writes a machine
# config stub under %ProgramData%\ScreenConnectCleaner\config.
#
# SAFETY MODEL (house rule 7 - destructive = dry-run default):
#   * Default behavior is a PREVIEW ONLY. Nothing is written, copied,
#     or deleted unless you pass -Install (or -Uninstall).
#   * -WhatIf forces a preview even when -Install is given.
#   * -Uninstall removes ONLY what this script installed under the
#     ScreenConnectCleaner program/data directories; it never touches
#     anything else on the system.
#
# Windows PowerShell 5.1 compatible. Pure ASCII, no BOM.
# Windows-only operations (COM shortcuts, env vars, Program Files) are
# guarded and only run on Windows_NT; non-Windows hosts get a clear
# "not supported here" preview.
#
# Exit codes: 0 = success / preview shown, 1 = fatal error.
# =====================================================================
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Source portable tree (folder containing Scc.Cleaner.ps1).
    # Defaults to the folder this script sits in (build/) parent, then
    # the current directory.
    [string]$SourceDir = '',
    # Perform the install (copy + shortcuts + config stub).
    [switch]$Install,
    # Remove what this script installed.
    [switch]$Uninstall,
    # Force a preview even with -Install.
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

$IsWindows = ($env:OS -eq 'Windows_NT')

# ---------------------------------------------------------------------
# Resolve source directory (portable tree).
# ---------------------------------------------------------------------
function Resolve-SccSourceDir {
    param([string]$Candidate)
    if ($Candidate -and (Test-Path -LiteralPath $Candidate)) {
        return (Resolve-Path -LiteralPath $Candidate).Path
    }
    # Script lives in <app>/build/ ; the portable tree is its parent.
    $scriptParent = Split-Path -Parent $PSScriptRoot
    if (Test-Path -LiteralPath (Join-Path $scriptParent 'Scc.Cleaner.ps1')) {
        return $scriptParent
    }
    # Current directory?
    if (Test-Path -LiteralPath (Join-Path (Get-Location).Path 'Scc.Cleaner.ps1')) {
        return (Get-Location).Path
    }
    return $null
}

# ---------------------------------------------------------------------
# Logging that respects preview mode.
# ---------------------------------------------------------------------
$PreviewMode = (-not $Install) -or $WhatIf
function Write-SccAction {
    param([string]$Message)
    if ($PreviewMode) {
        Write-Host ("  [preview] {0}" -f $Message)
    } else {
        Write-Host ("  [exec]    {0}" -f $Message)
    }
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
try {
    $src = Resolve-SccSourceDir -Candidate $SourceDir
    if (-not $src) {
        Write-Error 'Could not locate the portable tree (Scc.Cleaner.ps1). Use -SourceDir <path>.'
        exit 1
    }

    if (-not $IsWindows) {
        Write-Warning 'This installer performs Windows-only operations (Program Files, Start Menu).'
        Write-Warning 'On a non-Windows host it can only show a preview. Run on Windows to install.'
    }

    if ($Uninstall) {
        # ---- Uninstall: remove only what we installed. ----
        $progDir = $null
        $dataDir = $null
        if ($IsWindows) {
            $progDir = Join-Path $env:ProgramFiles 'ScreenConnectCleaner'
            $dataDir = Join-Path $env:ProgramData 'ScreenConnectCleaner'
        }
        Write-Host 'Uninstall preview/action:' -ForegroundColor Cyan
        if ($progDir) {
            if (Test-Path -LiteralPath $progDir) {
                Write-SccAction ("Remove directory: {0}" -f $progDir)
                if (-not $PreviewMode) { Remove-Item -LiteralPath $progDir -Recurse -Force -ErrorAction Stop }
            } else {
                Write-Host ("  (not present, skipping) {0}" -f $progDir)
            }
            # Start Menu shortcuts.
            $startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\ScreenConnect Cleaner'
            if (Test-Path -LiteralPath $startMenu) {
                Write-SccAction ("Remove Start Menu folder: {0}" -f $startMenu)
                if (-not $PreviewMode) { Remove-Item -LiteralPath $startMenu -Recurse -Force -ErrorAction Stop }
            }
            if ($dataDir -and (Test-Path -LiteralPath $dataDir)) {
                Write-SccAction ("Remove data directory: {0}" -f $dataDir)
                if (-not $PreviewMode) { Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction Stop }
            }
        }
        Write-Host 'Uninstall complete (preview only - no changes made).' -ForegroundColor Yellow
        if (-not $PreviewMode) { Write-Host 'Uninstall complete.' -ForegroundColor Green }
        exit 0
    }

    # ---- Install (or preview). ----
    if (-not $IsWindows) {
        Write-Host 'Preview of install (non-Windows host - no changes possible):' -ForegroundColor Cyan
    } else {
        Write-Host ('{0} install:' -f $(if ($PreviewMode) { 'Preview of' } else { 'Performing' })) -ForegroundColor Cyan
    }

    $progDir = $null
    $dataDir = $null
    $startMenuDir = $null
    if ($IsWindows) {
        $progDir = Join-Path $env:ProgramFiles 'ScreenConnectCleaner'
        $dataDir = Join-Path $env:ProgramData 'ScreenConnectCleaner'
        $startMenuDir = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\ScreenConnect Cleaner'
    }

    # 1. Copy portable tree to Program Files.
    if ($progDir) {
        Write-SccAction ("Copy portable tree '{0}' -> '{1}'" -f $src, $progDir)
        if (-not $PreviewMode) {
            if (-not (Test-Path -LiteralPath $progDir)) {
                $null = New-Item -ItemType Directory -Path $progDir -Force
            }
            # Mirror copy: clean target dir first to avoid stale files.
            $items = Get-ChildItem -Path $src -ErrorAction Stop
            foreach ($item in $items) {
                Copy-Item -LiteralPath $item.FullName -Destination $progDir -Recurse -Force -ErrorAction Stop
            }
        }
    } else {
        Write-SccAction ("(would copy portable tree to %ProgramFiles%\ScreenConnectCleaner)")
    }

    # 2. Write machine config stub under ProgramData.
    if ($dataDir) {
        $cfgDir = Join-Path $dataDir 'config'
        $stubPath = Join-Path $cfgDir 'scc-config.json'
        Write-SccAction ("Write machine config stub: {0}" -f $stubPath)
        if (-not $PreviewMode) {
            if (-not (Test-Path -LiteralPath $cfgDir)) {
                $null = New-Item -ItemType Directory -Path $cfgDir -Force
            }
            $stub = [PSCustomObject]@{
                SchemaVersion = 1
                _installedBy  = 'Install-Scc.ps1'
                _note         = 'Machine-wide override config. User scope wins per Scc.Core precedence.'
                paths         = [PSCustomObject]@{
                    reportRoot  = '%USERPROFILE%\Documents\ScreenConnect Cleanup\Reports'
                    programData = '%ProgramData%\ScreenConnectCleaner'
                    userData    = '%LocalAppData%\ScreenConnectCleaner'
                }
            }
            [System.IO.File]::WriteAllText($stubPath, (ConvertTo-Json -InputObject $stub -Depth 10), [System.Text.Encoding]::ASCII)
        }
    } else {
        Write-SccAction (' (would write machine config stub under %ProgramData%\ScreenConnectCleaner\config)')
    }

    # 3. Start Menu shortcuts (app + docs). Windows COM - guarded.
    if ($startMenuDir) {
        $appTarget = Join-Path $progDir 'Start-ScreenConnectCleaner.bat'
        $docsTarget = Join-Path $progDir 'docs\ARCHITECTURE.md'
        Write-SccAction ("Create Start Menu shortcuts in: {0}" -f $startMenuDir)
        Write-SccAction ("  shortcut 'ScreenConnect Cleaner' -> {0}" -f $appTarget)
        Write-SccAction ("  shortcut 'ScreenConnect Cleaner - Documentation' -> {0}" -f $docsTarget)
        if (-not $PreviewMode) {
            try {
                if (-not (Test-Path -LiteralPath $startMenuDir)) {
                    $null = New-Item -ItemType Directory -Path $startMenuDir -Force
                }
                $shell = New-Object -ComObject WScript.Shell
                $lnkApp = $shell.CreateShortcut((Join-Path $startMenuDir 'ScreenConnect Cleaner.lnk'))
                $lnkApp.TargetPath = $appTarget
                $lnkApp.WorkingDirectory = $progDir
                $lnkApp.Description = 'ScreenConnect Cleaner (technician GUI)'
                $lnkApp.Save()
                $lnkDocs = $shell.CreateShortcut((Join-Path $startMenuDir 'ScreenConnect Cleaner - Documentation.lnk'))
                $lnkDocs.TargetPath = $docsTarget
                $lnkDocs.WorkingDirectory = (Join-Path $progDir 'docs')
                $lnkDocs.Description = 'ScreenConnect Cleaner documentation'
                $lnkDocs.Save()
            } catch {
                Write-Warning ("Shortcut creation failed (non-fatal): {0}" -f $_.Exception.Message)
            }
        }
    } else {
        Write-SccAction (' (would create Start Menu shortcuts under Programs\ScreenConnect Cleaner)')
    }

    if ($PreviewMode) {
        Write-Host ''
        Write-Host 'PREVIEW ONLY - no changes were made.' -ForegroundColor Yellow
        Write-Host 'Re-run with -Install to perform the installation.' -ForegroundColor Yellow
    } else {
        Write-Host ''
        Write-Host 'Installation complete.' -ForegroundColor Green
    }
    exit 0
} catch {
    Write-Error ("Install failed: {0}" -f $_.Exception.Message)
    if ($_.ScriptStackTrace) { Write-Error $_.ScriptStackTrace }
    exit 1
}
