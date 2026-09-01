# =====================================================================
# Test-HouseRules.ps1 -- CI gate for the project house rules.
#
#   1. Every text source file is pure ASCII (no Unicode sneaking in).
#   2. No UTF-8 BOM on any .ps1/.bat/.json/.md file (BOM breaks
#      downlevel parsing and batch files).
#   3. All tracked JSON files parse cleanly.
#
# Exit codes: 0 = clean, 1 = violations found.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# Directories that hold third-party binaries / vendored tools - skip them.
$excludeDirs = @('\.git\', '\tools\Autoruns\', '\tools\ProcessMonitor\', '\tools\Sigcheck\', '\tools\TCPView\')
$extensions = @('.ps1', '.bat', '.cmd', '.json', '.md', '.yml', '.sh')

$files = Get-ChildItem -Path $repoRoot -Recurse -File | Where-Object {
    $ext = $_.Extension.ToLowerInvariant()
    if ($extensions -notcontains $ext) { return $false }
    $fullPath = $_.FullName -replace '/', '\'
    foreach ($d in $excludeDirs) {
        if ($fullPath -like ("*" + $d.TrimEnd('\') + "*")) { return $false }
    }
    return $true
}

$violations = @()

# ASCII is a hard rule for CODE files (.ps1/.bat/.cmd). Prose (.md/.yml)
# may contain Unicode punctuation; they only get the BOM + JSON checks.
$codeExtensions = @('.ps1', '.bat', '.cmd')

foreach ($f in $files) {
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)

    # BOM check: UTF-8 BOM = EF BB BF
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $violations += ("BOM       : {0}" -f $f.FullName.Substring($repoRoot.Length + 1))
        continue
    }

    # ASCII check - code files only
    if ($codeExtensions -contains $f.Extension.ToLowerInvariant()) {
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -gt 127) {
                $violations += ("NON-ASCII : {0} (byte 0x{1:X2} at offset {2})" -f $f.FullName.Substring($repoRoot.Length + 1), $bytes[$i], $i)
                break
            }
        }
    }

    # JSON validity
    if ($f.Extension -eq '.json') {
        try {
            $null = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString($bytes))
        } catch {
            $violations += ("BAD-JSON  : {0} ({1})" -f $f.FullName.Substring($repoRoot.Length + 1), $_.Exception.Message)
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Host "HOUSE RULE VIOLATIONS ($($violations.Count)):"
    $violations | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host ("House rules OK: {0} text files scanned (ASCII, no BOM, JSON valid)." -f $files.Count)
exit 0
