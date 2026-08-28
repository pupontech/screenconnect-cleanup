<#
  install-latest.ps1 - one-liner bootstrap for screenconnect-cleanup.

  Downloads the latest GitHub release zip of pupontech/screenconnect-cleanup,
  extracts it to your Desktop\ScreenConnect-Cleanup\<version>\ and launches the
  guided runner (START-HERE.bat). Designed to run from a copy-paste one-liner:

      irm https://raw.githubusercontent.com/pupontech/screenconnect-cleanup/main/install-latest.ps1 | iex

  What it does / does not do:
    - It only: queries the GitHub API for the latest release, downloads the
      deploy zip asset, expands it into a versioned folder on your Desktop,
      and starts START-HERE.bat (the same file you would double-click after a
      manual download). Nothing outside that folder is touched, and nothing
      from the zip runs except the guided runner itself.
    - No admin rights are needed to install. The guided runner elevates
      itself via UAC only when a step actually needs it (preflight/removal).
    - The zip is NOT hash-verified: you are trusting the release assets at
      github.com/pupontech/screenconnect-cleanup/releases. To verify, compare
      the sha256 published in the release notes against the downloaded zip.

  Parameters (useful when running the script directly, not via iex):
    -Destination <path>   install base folder (default: Desktop\ScreenConnect-Cleanup)
    -NoLaunch             do not start START-HERE.bat after installing
    -Force                overwrite/re-extract an existing <version> subfolder
                          (without it, a same-version re-run detects the
                          existing install and just launches it)

  PS 5.1 compatible. Pure ASCII, no BOM.
#>
[CmdletBinding()]
param(
    [string]$Destination = '',
    [switch]$NoLaunch,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = 'pupontech/screenconnect-cleanup'

if (-not $Destination) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not $desktop) { $desktop = Join-Path $env:USERPROFILE 'Desktop' }
    $Destination = Join-Path $desktop 'ScreenConnect-Cleanup'
}
if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }

Write-Host "== screenconnect-cleanup bootstrap ==" -ForegroundColor Cyan
Write-Host ("  repo:       " + $Repo)
Write-Host ("  install to: " + $Destination)

# 1. Resolve the latest release and its deploy zip asset.
$release = Invoke-RestMethod -Uri ("https://api.github.com/repos/" + $Repo + "/releases/latest") -Headers @{ 'User-Agent' = 'screenconnect-cleanup-bootstrap' } -UseBasicParsing -ErrorAction Stop
$asset = @($release.assets | Where-Object { $_.name -like 'screenconnect-cleanup-v*.zip' })[0]
if (-not $asset) { throw ("No deploy zip asset found in release " + $release.tag_name) }
Write-Host ("  release:    " + $release.tag_name + "  (" + $asset.size + " bytes)")

# 2. Same-version fast path: the release tag names the install folder, so an
# existing complete folder means this exact version is already installed.
# Skip the download and launch it - re-extracting would also delete any AV
# scanners the technician already staged into tools\AV inside that folder.
$runDir = Join-Path $Destination $release.tag_name
if (-not $Force -and (Test-Path -LiteralPath $runDir)) {
    $existingVer = $null
    $existingVerFile = Join-Path $runDir 'VERSION'
    $existingBat = Join-Path $runDir 'START-HERE.bat'
    try {
        if (Test-Path -LiteralPath $existingVerFile) {
            $existingVer = (Get-Content -LiteralPath $existingVerFile -Raw -ErrorAction Stop).Trim()
        }
    } catch { $existingVer = $null }
    if ($existingVer -eq $release.tag_name.TrimStart('v') -and (Test-Path -LiteralPath $existingBat)) {
        Write-Host ("  already installed and up to date: " + $runDir) -ForegroundColor Green
        Write-Host "  (pass -Force to re-extract a fresh copy)" -ForegroundColor DarkGray
        if ($NoLaunch) {
            Write-Host ("  -NoLaunch given; run START-HERE.bat from: " + $runDir)
        } else {
            Write-Host "  launching START-HERE.bat ..."
            Start-Process -FilePath $existingBat -WorkingDirectory $runDir
        }
        Write-Host "== done ==" -ForegroundColor Cyan
        exit 0
    }
    Write-Host ("  existing folder at " + $runDir + " is incomplete or does not match " + $release.tag_name + " - re-installing.") -ForegroundColor Yellow
    Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction Stop
}

# 3. Download the zip (to TEMP so the install folder stays clean).
$zip = Join-Path $env:TEMP $asset.name
Write-Host ("  downloading " + $asset.name + " ...")
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing -ErrorAction Stop

# 4. Extract into the versioned subfolder.
if (Test-Path -LiteralPath $runDir) {
    # Only reachable with -Force (the fast path above handled the rest).
    Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction Stop
}
$null = New-Item -ItemType Directory -Path $runDir -Force
Expand-Archive -Path $zip -DestinationPath $runDir -Force -ErrorAction Stop

# The zip nests everything under one 'screenconnect-cleanup' folder; lift the
# contents up so START-HERE.bat lives directly in the versioned folder.
$inner = Join-Path $runDir 'screenconnect-cleanup'
if (Test-Path -LiteralPath $inner) {
    Get-ChildItem -LiteralPath $inner -Force | Move-Item -Destination $runDir -Force
    Remove-Item -LiteralPath $inner -Force
}

# 5. Sanity: the bundle must be self-identifying and complete.
$verFile = Join-Path $runDir 'VERSION'
if (-not (Test-Path -LiteralPath $verFile)) { throw ("Bundle missing VERSION - install incomplete at " + $runDir) }
$ver = (Get-Content -LiteralPath $verFile -Raw).Trim()
$bat = Join-Path $runDir 'START-HERE.bat'
if (-not (Test-Path -LiteralPath $bat)) { throw ("Bundle missing START-HERE.bat - install incomplete at " + $runDir) }

Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue

Write-Host ("  installed:  v" + $ver + " -> " + $runDir) -ForegroundColor Green

# 6. Launch the guided runner (unless told not to).
if ($NoLaunch) {
    Write-Host ("  -NoLaunch given; run START-HERE.bat from: " + $runDir)
} else {
    Write-Host "  launching START-HERE.bat ..."
    Start-Process -FilePath $bat -WorkingDirectory $runDir
}
Write-Host "== done ==" -ForegroundColor Cyan
