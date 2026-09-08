# Shared test helpers for Scc.Remedy.Tests.ps1
# (dot-sourced from each Describe's BeforeAll so Pester 6 run-scope sees them)

function New-TestRun {
    $rd = Join-Path ([System.IO.Path]::GetTempPath()) ('scc_remedy_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $rd -Force | Out-Null
    return [PSCustomObject]@{ RunId = 'TESTRUN'; RunDir = $rd }
}

function Remove-TestRun {
    param($Run)
    if ($Run -and (Test-Path -LiteralPath $Run.RunDir)) {
        Remove-Item -LiteralPath $Run.RunDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function New-Finding {
    param([string]$Id, [string]$Product, [string]$ServiceName = '', [string]$InstallDir = '', [string]$MainExe = '')
    $o = [PSCustomObject]@{
        FindingId    = $Id
        Product      = $Product
        TargetType   = 'Uninstall'
        Detail       = ''
        DisplayText  = ($Id + ' [' + $Product + ']')
        ServiceName  = $ServiceName
        InstallDir   = $InstallDir
        MainExe      = $MainExe
    }
    return $o
}

# Read the remediation.json written by Invoke-SccRemediation (run-scope safe).
function Read-Remediation {
    param($Run)
    $p = Join-Path $Run.RunDir 'remediation.json'
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    return @(ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($p)))
}

# Read the quarantine-manifest.json written by Scc.Remedy (run-scope safe).
function Read-QuarantineManifest {
    param($Run)
    # Quarantine root = QuarantineRoot under ProgramData on Windows, or RunDir/Quarantine on Linux/test.
    $candidates = @(
        (Join-Path $Run.RunDir 'Quarantine' 'quarantine-manifest.json')
    )
    # Windows-style ProgramData path is also possible if resolved.
    $pd = $env:ProgramData
    if ($pd) {
        $candidates += (Join-Path $pd 'ScreenConnectCleaner' 'Quarantine' 'TESTRUN' 'quarantine-manifest.json')
    }
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) {
            return @(ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($c)))
        }
    }
    return @()
}
