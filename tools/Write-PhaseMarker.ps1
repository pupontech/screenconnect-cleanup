<#
  Write-PhaseMarker.ps1 - record that one half of a split run has finished.

  The guided runner can be split into an OFFLINE half (cleanup that needs no
  internet) and an ONLINE half (stage + run scanners + share the report).
  When the offline half finishes, START-HERE-OFFLINE.bat calls this script to
  leave <RunRoot>\phase-offline.json behind. START-HERE-ONLINE.bat uses that
  file (via Find-OfflineRun.ps1) to pick up the same run folder: findings.json,
  report.html and the persistence evidence stay where the offline half put
  them, and the online half adds scanner results and the share on top.

  Writes ONLY the marker file inside the run root. Reads nothing. No network.
  Windows PowerShell 5.1 compatible. Pure ASCII source, no BOM.

  Exit 0 = marker written. Exit 1 = could not write it (run root missing,
  path is a reparse point, or an I/O error); the message says why.
#>
param(
    [Parameter(Mandatory = $true)][string]$RunRoot,
    [ValidateSet('offline', 'online')][string]$Phase = 'offline',
    [string]$FindingsJson = '',
    [int]$ExitCode = 0,
    [string]$ToolVersion = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try {
    if (-not (Test-Path -LiteralPath $RunRoot -PathType Container)) {
        throw ('run root does not exist: ' + $RunRoot)
    }
    $rootItem = Get-Item -LiteralPath $RunRoot -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'run root is a junction or symlink; refusing to write into it'
    }

    if (-not $ToolVersion) {
        $versionFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'VERSION'
        if (Test-Path -LiteralPath $versionFile -PathType Leaf) {
            $ToolVersion = ([IO.File]::ReadAllText($versionFile)).Trim()
        }
    }

    # Only record a findings path that really exists inside this run root.
    $findingsOut = ''
    if ($FindingsJson -and (Test-Path -LiteralPath $FindingsJson -PathType Leaf)) {
        $findingsOut = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $FindingsJson).Path)
    }
    $reportPath = Join-Path $RunRoot 'report.html'
    $reportOut = ''
    if (Test-Path -LiteralPath $reportPath -PathType Leaf) { $reportOut = $reportPath }

    $marker = [ordered]@{
        SchemaVersion = 1
        Phase         = $Phase
        Computer      = $env:COMPUTERNAME
        RunRoot       = [IO.Path]::GetFullPath($RunRoot)
        CompletedUtc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        ToolVersion   = $ToolVersion
        ExitCode      = $ExitCode
        FindingsJson  = $findingsOut
        ReportHtml    = $reportOut
    }
    $json = ConvertTo-Json -InputObject $marker -Depth 4
    $markerPath = Join-Path $RunRoot ('phase-' + $Phase + '.json')
    $tmp = $markerPath + '.tmp'
    [IO.File]::WriteAllText($tmp, $json + "`r`n", (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $markerPath -Force
    Write-Host ('Phase marker written: ' + $markerPath)
    exit 0
} catch {
    [Console]::Error.WriteLine('Write-PhaseMarker failed: ' + $_.Exception.Message)
    exit 1
}
