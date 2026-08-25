<#
  tools/Get-AVTools.ps1  -  Stage + verify the AV scanner executables.

  The three AV tools used by Stage 5 / the guided runner's step 6 are NOT
  downloadable from a stable direct URL the way Sysinternals tools are. They are
  interactive retail downloads:

    KVRT        Kaspersky Virus Removal Tool   https://www.kaspersky.com/downloads/free-virus-removal-tool
    ESET Online Scanner                        https://www.eset.com/int/home/online-scanner/
    Malwarebytes installer stub (MBSetup.exe)  https://www.malwarebytes.com/mwb-download

  House rule (docs/05/06): DO NOT invent download URLs, and never pull from a
  third-party mirror. So this script does NOT download them. Instead it:

    1. Ensures the staging directory (<ToolDir>, default tools\AV) exists.
    2. Reports, for each tool, whether the expected file is present with its
       size, and - when absent - prints the official page to fetch it from.
    3. Exits 0 when everything requested is staged, 1 otherwise, so the caller
       (sc-cleanup.ps1, START-HERE.bat) can tell the tech what's still missing.

  The expectation is that a technician stages these ONCE into tools\AV\ (or a
  shared internal share) - matching how START-HERE.bat expects KVRT.exe,
  esetonlinescanner.exe and MBSetup.exe to already sit in tools\AV\.

  NOTE: KVRT, ESET and Malwarebytes are NOT bundled on a client machine by this
  script; it only verifies presence. "Not staged" is a report, not an error, and
  Stage 5 treats a missing scanner as NotInstalled (non-fatal) regardless.

  PS 5.1 compatible. Pure ASCII, no BOM.
#>

[CmdletBinding()]
param(
    # Staging directory for the AV executables (default: tools\AV).
    [string]$ToolDir,

    # Suppress non-error output.
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ToolDir) { $ToolDir = Join-Path (Split-Path -Parent $ScriptDir) 'tools\AV' }

function Write-Info { param([string]$Message) if (-not $Quiet) { Write-Host $Message } }
function Write-WarnMsg { param([string]$Message) Write-Host ("WARNING: " + $Message) -ForegroundColor Yellow }

# Tool -> expected staged filename + official acquisition source. The filenames
# are exactly what START-HERE.bat (steps 6b/6c/6d) looks for.
$tools = [ordered]@{
    'KVRT'                 = 'KVRT.exe'
    'ESET Online Scanner'  = 'esetonlinescanner.exe'
    'Malwarebytes (stub)'  = 'MBSetup.exe'
}
$sources = [ordered]@{
    'KVRT.exe'                = 'https://www.kaspersky.com/downloads/free-virus-removal-tool'
    'esetonlinescanner.exe'   = 'https://www.eset.com/int/home/online-scanner/'
    'MBSetup.exe'             = 'https://www.malwarebytes.com/mwb-download'
}

if (-not (Test-Path -LiteralPath $ToolDir)) {
    $null = New-Item -ItemType Directory -Path $ToolDir -Force
    Write-Info ("Created staging directory: " + $ToolDir)
}

Write-Info ("AV scanner staging directory: " + $ToolDir)

$missing = @()
$present = @()
foreach ($name in @($tools.Keys)) {
    $file = $tools[$name]
    $path = Join-Path $ToolDir $file
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path
        if ($item.Length -gt 0) {
            Write-Info ("  [PRESENT] {0}  ({1} bytes)" -f $file, $item.Length)
            $present += $file
        } else {
            Write-WarnMsg ("{0} is zero bytes - re-stage it" -f $file)
            $missing += $file
        }
    } else {
        Write-WarnMsg ("{0} not staged - fetch it from {1}" -f $file, $sources[$file])
        $missing += $file
    }
}

Write-Info ("AV staging: {0} present, {1} missing." -f $present.Count, $missing.Count)

if ($missing.Count -gt 0) {
    Write-Info "Stage the missing tools into $ToolDir manually (official sites above), then re-run."
    exit 1
}
exit 0
