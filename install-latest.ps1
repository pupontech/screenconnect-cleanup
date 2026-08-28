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
    -Force                overwrite an existing <version> subfolder

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

# 2. Download the zip (to TEMP so the install folder stays clean).
$zip = Join-Path $env:TEMP $asset.name
Write-Host ("  downloading " + $asset.name + " ...")
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing -ErrorAction Stop

# 3. Extract into a versioned subfolder under the destination.
$runDir = Join-Path $Destination $release.tag_name
if (Test-Path -LiteralPath $runDir) {
    if (-not $Force) {
        throw ("Already installed at " + $runDir + " - pass -Force to overwrite, or delete that folder.")
    }
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

# 4. Sanity: the bundle must be self-identifying and complete.
$verFile = Join-Path $runDir 'VERSION'
if (-not (Test-Path -LiteralPath $verFile)) { throw ("Bundle missing VERSION - install incomplete at " + $runDir) }
$ver = (Get-Content -LiteralPath $verFile -Raw).Trim()
$bat = Join-Path $runDir 'START-HERE.bat'
if (-not (Test-Path -LiteralPath $bat)) { throw ("Bundle missing START-HERE.bat - install incomplete at " + $runDir) }

Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue

Write-Host ("  installed:  v" + $ver + " -> " + $runDir) -ForegroundColor Green

# 5. Launch the guided runner (unless told not to).
if ($NoLaunch) {
    Write-Host ("  -NoLaunch given; run START-HERE.bat from: " + $runDir)
} else {
    Write-Host "  launching START-HERE.bat ..."
    Start-Process -FilePath $bat -WorkingDirectory $runDir
}
Write-Host "== done ==" -ForegroundColor Cyan
