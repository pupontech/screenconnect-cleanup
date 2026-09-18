# =====================================================================
# Test-Parse.ps1 -- parse-check every PowerShell script in the new tree.
#
# Runs the parser (no execution) on all .ps1/.psm1 files under
# gui-revision-screenconnect-cleaner/ and reports syntax errors.
# Runs under BOTH powershell 5.1 and pwsh (no PS7-only syntax here).
#
# Exit codes: 0 = all clean, 1 = parse errors found.
# Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$newRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$scripts = Get-ChildItem -Path $newRoot -Recurse -File -ErrorAction Stop | Where-Object {
    $ext = $_.Extension.ToLowerInvariant()
    $ext -eq '.ps1' -or $ext -eq '.psm1'
}

if (-not $scripts -or @($scripts).Count -eq 0) {
    Write-Host 'No .ps1/.psm1 files found.'
    exit 1
}

$edition = $PSVersionTable.PSVersion.ToString()
$failed = 0

foreach ($s in $scripts) {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $s.FullName, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -gt 0) {
        $failed++
        $rel = $s.FullName.Substring($newRoot.Length + 1)
        Write-Host ("PARSE FAIL [{0}] {1}" -f $edition, $rel)
        foreach ($e in $errors) {
            Write-Host ("    line {0}: {1}" -f $e.Extent.StartLineNumber, $e.Message)
        }
    }
}

Write-Host ("Parser check under PS {0}: {1} script(s), {2} with errors." -f $edition, @($scripts).Count, $failed)
if ($failed -gt 0) { exit 1 } else { exit 0 }
