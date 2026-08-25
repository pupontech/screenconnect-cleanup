<#
  tools/Get-ToolPack.ps1  -  Download + hash-verify the Sysinternals tool pack.

  Downloads the four Sysinternals tools this project drives (Autoruns, Sigcheck,
  ProcessMonitor, TCPView) from the OFFICIAL Microsoft download endpoint ONLY
  (never a third-party mirror), extracts each into its OWN subfolder under
  $ToolDir, and writes/updates manifest.json with a per-file SHA-256 so both this
  script (-Verify) and preflight.ps1 can prove the binaries are intact and
  untampered late.

  Modes:
    (default)      download + extract + write manifest
    -Verify        re-hash every manifest file and compare; exit 0 = all match
    -List          print what the manifest declares (paths, sizes, hashes)

  Design notes (from docs/08-work-log.md section 8 - the "manifest bug"):
    - Each tool extracts into $ToolDir\<ToolName>\, NOT a shared folder, so the
      manifest never accumulates every exe extracted so far.
    - The empty-manifest guard uses @($manifest.PSObject.Properties).Count, NOT
      .Count, because a PSCustomObject has no .Count on PS 5.1.
    - No new URLs or flags invented; the four source URLs and their hashes live
      in the committed tools/manifest.json.

  PS 5.1 compatible. Pure ASCII, no BOM.
#>

[CmdletBinding()]
param(
    # Where to place/extract the pack (default: tools\ next to this script).
    [string]$ToolDir,

    # Verify existing files against the manifest instead of downloading.
    [switch]$Verify,

    # List manifest contents and exit.
    [switch]$List,

    # Suppress non-error output (used by preflight.ps1 / sc-cleanup.ps1).
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ToolDir) { $ToolDir = Join-Path $ScriptDir '' }   # tools\ itself

$ManifestPath = Join-Path $ScriptDir 'manifest.json'

function Write-Info {
    param([string]$Message)
    if (-not $Quiet) { Write-Host $Message }
}
function Write-WarnMsg {
    param([string]$Message)
    Write-Host ("WARNING: " + $Message) -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Read the committed manifest (source of truth for URLs + expected hashes).
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    Write-Error "manifest.json not found at $ManifestPath. Cannot download or verify."
    exit 1
}
try {
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
} catch {
    Write-Error "Failed to parse manifest.json: $($_.Exception.Message)"
    exit 1
}
if (@($manifest.PSObject.Properties).Count -eq 0) {
    Write-Error "manifest.json present but empty. Cannot download or verify."
    exit 1
}

# -List mode
if ($List) {
    foreach ($tool in @($manifest.PSObject.Properties)) {
        Write-Info ("{0}" -f $tool.Name)
        foreach ($file in @($tool.Value.files.PSObject.Properties)) {
            Write-Info ("  {0}  {1} bytes  {2}" -f $file.Name, $file.Value.size, $file.Value.sha256)
        }
    }
    exit 0
}

# ---------------------------------------------------------------------------
# -Verify mode: re-hash every declared file, compare, report.
# ---------------------------------------------------------------------------
if ($Verify) {
    $mismatches = 0
    $missing = 0
    $checked = 0
    foreach ($tool in @($manifest.PSObject.Properties)) {
        $toolDir = Join-Path $ToolDir $tool.Name
        foreach ($file in @($tool.Value.files.PSObject.Properties)) {
            $fname = $file.Name
            $expected = [string]$file.Value.sha256
            $path = Join-Path $toolDir $fname
            if (-not (Test-Path -LiteralPath $path)) {
                Write-WarnMsg ("{0}\{1} missing" -f $tool.Name, $fname)
                $missing++
                continue
            }
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            $checked++
            if ($actual -ieq $expected) {
                Write-Info ("{0}: OK - {1}" -f $tool.Name, $fname)
            } else {
                Write-WarnMsg ("{0}: MISMATCH - {1} (got {2}, expected {3})" -f $tool.Name, $fname, $actual, $expected)
                $mismatches++
            }
        }
    }
    Write-Info ("Verify complete: {0} checked, {1} mismatch, {2} missing." -f $checked, $mismatches, $missing)
    if ($mismatches -gt 0 -or $missing -gt 0) { exit 1 }
    exit 0
}

# ---------------------------------------------------------------------------
# Download mode: fetch each tool zip from the manifest URL, extract into its
# own subfolder, and rewrite manifest.json with the freshly-observed hashes.
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $ToolDir)) {
    $null = New-Item -ItemType Directory -Path $ToolDir -Force
}

$newManifest = [ordered]@{}
$overallFailed = $false

foreach ($tool in @($manifest.PSObject.Properties)) {
    $toolName = $tool.Name
    $url = [string]$tool.Value.url
    if (-not $url) {
        Write-WarnMsg ("{0}: no url in manifest - skipped" -f $toolName)
        $overallFailed = $true
        continue
    }

    $zip = Join-Path $ToolDir ($toolName + '.zip')
    $extractDir = Join-Path $ToolDir $toolName

    Write-Info ("Downloading {0} from {1} ..." -f $toolName, $url)
    try {
        # TLS 1.2 for PS 5.1, which does not enable it by default on older builds.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-WarnMsg ("{0}: download failed - {1}" -f $toolName, $_.Exception.Message)
        $overallFailed = $true
        continue
    }

    if (-not (Test-Path -LiteralPath $zip)) {
        Write-WarnMsg ("{0}: download produced no file - skipped" -f $toolName)
        $overallFailed = $true
        continue
    }

    # Extract into a CLEAN per-tool subfolder (fixes the accumulation bug).
    if (Test-Path -LiteralPath $extractDir) { Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue }
    $null = New-Item -ItemType Directory -Path $extractDir -Force
    try {
        Expand-Archive -LiteralPath $zip -DestinationPath $extractDir -Force -ErrorAction Stop
    } catch {
        Write-WarnMsg ("{0}: extract failed - {1}" -f $toolName, $_.Exception.Message)
        $overallFailed = $true
        continue
    }

    # Manifest entries are scoped to ONLY this tool's own subfolder.
    $files = [ordered]@{}
    $extracted = 0
    foreach ($exe in (Get-ChildItem -LiteralPath $extractDir -Filter '*.exe' -File -ErrorAction SilentlyContinue)) {
        $h = (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash
        $files[$exe.Name] = [ordered]@{ size = $exe.Length; sha256 = $h }
        $extracted++
    }

    if ($extracted -eq 0) {
        Write-WarnMsg ("{0}: no .exe found in extracted zip - check the URL / zip layout" -f $toolName)
        $overallFailed = $true
    } else {
        Write-Info ("{0}: Extracted {1}" -f $toolName, $extracted)
    }

    $newManifest[$toolName] = [ordered]@{
        url        = $url
        downloaded = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        files      = $files
    }
}

# Persist the manifest (only when we actually produced entries).
if (@($newManifest.Keys).Count -gt 0) {
    $newManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8 -NoNewline
    Write-Info ("Manifest written: " + $ManifestPath)
}

if ($overallFailed) { exit 1 }
exit 0
