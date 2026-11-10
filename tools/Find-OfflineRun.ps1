<#
  Find-OfflineRun.ps1 - locate the newest finished OFFLINE-half run for this PC.

  Used by START-HERE-ONLINE.bat so the online half continues the run the
  offline half already produced instead of starting over.

  A run qualifies when its folder is <Root>\<COMPUTERNAME>-<guid> and it holds
  phase-offline.json (written by Write-PhaseMarker.ps1 when the offline half
  finished). The newest qualifying marker wins.

  Output (stdout, exactly one line, or nothing when no run qualifies):
      <run root>|<findings.json path, or NONE when that run had no findings>
  Extra diagnostics go to stderr so the batch file's FOR /F only sees the line.

  Read-only. No network. Windows PowerShell 5.1 compatible, pure ASCII, no BOM.
  Exit 0 always (no run found is a normal answer, not an error).
#>
param(
    [string]$Root = 'C:\RIT-SCC',
    [string]$ComputerName = $env:COMPUTERNAME
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { exit 0 }

    $candidates = New-Object System.Collections.ArrayList
    foreach ($dir in @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop)) {
        if ($dir.Name -notlike ($ComputerName + '-*')) { continue }
        if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $markerPath = Join-Path $dir.FullName 'phase-offline.json'
        if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { continue }
        [void]$candidates.Add([pscustomobject]@{
            Dir    = $dir.FullName
            Marker = $markerPath
            Time   = (Get-Item -LiteralPath $markerPath).LastWriteTimeUtc
        })
    }
    if ($candidates.Count -eq 0) { exit 0 }

    $newest = @($candidates | Sort-Object Time -Descending)[0]
    if ($candidates.Count -gt 1) {
        [Console]::Error.WriteLine(('Note: ' + $candidates.Count + ' finished offline runs found; using the newest.'))
    }

    $findings = 'NONE'
    try {
        $data = [IO.File]::ReadAllText($newest.Marker) | ConvertFrom-Json
        $names = @($data.PSObject.Properties.Name)
        if ($names -contains 'FindingsJson') {
            $candidate = [string]$data.FindingsJson
            # The findings file must still exist AND live inside this run root.
            if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                $full = [IO.Path]::GetFullPath($candidate)
                $rootFull = [IO.Path]::GetFullPath($newest.Dir).TrimEnd('\') + '\'
                if ($full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { $findings = $full }
            }
        }
    } catch {
        [Console]::Error.WriteLine('Note: could not read the phase marker (' + $_.Exception.Message + '); continuing without findings.')
    }

    Write-Output ($newest.Dir + '|' + $findings)
    exit 0
} catch {
    [Console]::Error.WriteLine('Find-OfflineRun failed: ' + $_.Exception.Message)
    exit 0
}
