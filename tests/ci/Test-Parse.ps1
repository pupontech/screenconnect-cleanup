# =====================================================================
# Test-Parse.ps1 -- parse-check every PowerShell script.
#
# Runs the parser (no execution) on all .ps1 files in the repo and
# reports syntax errors. Invoked under both powershell.exe (5.1) and
# pwsh so edition-specific breakage shows up in CI.
#
# Exit codes: 0 = all clean, 1 = parse errors found.
# Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$scripts = Get-ChildItem -Path $repoRoot -Recurse -Filter *.ps1 -File | Where-Object {
    $_.FullName -notmatch '\\tools\\(Autoruns|ProcessMonitor|Sigcheck|TCPView)\\'
}

if (-not $scripts) {
    Write-Host 'No .ps1 files found.'
    exit 1
}

$edition = $PSVersionTable.PSVersion.ToString()
$failed = 0

foreach ($s in $scripts) {
    $tokens = $null; $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $s.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        $failed++
        Write-Host ("PARSE FAIL [{0}] {1}" -f $edition, $s.FullName.Substring($repoRoot.Length + 1))
        foreach ($e in $errors) {
            Write-Host ("    line {0}: {1}" -f $e.Extent.StartLineNumber, $e.Message)
        }
    }
}

Write-Host ("Parser check under PS {0}: {1} script(s), {2} with errors." -f $edition, $scripts.Count, $failed)
exit $(if ($failed -gt 0) { 1 } else { 0 })
