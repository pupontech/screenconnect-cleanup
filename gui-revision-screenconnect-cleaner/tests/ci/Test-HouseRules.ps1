# =====================================================================
# Test-HouseRules.ps1 -- CI gate for house rules (new tree).
#
# Scans the NEW tree (gui-revision-screenconnect-cleaner/) recursively:
#   1. Every .ps1/.psm1/.psd1/.xaml/.json/.bat/.md/.ps1xml is pure ASCII no BOM
#   2. Every .json parses cleanly via ConvertFrom-Json
#   3. Every .bat is CRLF (no bare LF)
#   4. No *.zip / *.exe committed under the new tree
#
# Exit codes: 0 = clean, 1 = violations.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Resolve new tree root: tests/ci -> gui-revision-screenconnect-cleaner
$newRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not (Test-Path -LiteralPath $newRoot)) {
    Write-Host 'Cannot resolve new tree root.'
    exit 1
}

$extensions = @('.ps1','.psm1','.psd1','.xaml','.json','.bat','.md')

$files = Get-ChildItem -Path $newRoot -Recurse -File -ErrorAction Stop | Where-Object {
    $ext = $_.Extension.ToLowerInvariant()
    if ($extensions -notcontains $ext) { return $false }
    $full = $_.FullName -replace '/', '\'
    if ($full -like '*\audit\*') { return $false }
    if ($full -like '*\.git\*') { return $false }
    return $true
}

$violations = @()

foreach ($f in $files) {
    $rel = $f.FullName.Substring($newRoot.Length + 1)
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)

    # BOM check: UTF-8 BOM = EF BB BF
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $violations += ("BOM       : {0}" -f $rel)
        continue
    }

    # ASCII check: every file in the list must be pure ASCII (no byte > 127)
    $hasNonAscii = $false
    $off = -1
    $badByte = 0
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -gt 127) {
            $hasNonAscii = $true
            $off = $i
            $badByte = $bytes[$i]
            break
        }
    }
    if ($hasNonAscii) {
        $violations += ("NON-ASCII : {0} (byte 0x{1:X2} at offset {2})" -f $rel, $badByte, $off)
        continue
    }

    # JSON validity
    if ($f.Extension.ToLowerInvariant() -eq '.json') {
        try {
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $null = ConvertFrom-Json -InputObject $text -ErrorAction Stop
            }
        } catch {
            $violations += ("BAD-JSON  : {0} ({1})" -f $rel, $_.Exception.Message)
        }
    }

    # BAT CRLF check: every LF must be preceded by CR, and file must contain CRLF if it has any newline
    if ($f.Extension.ToLowerInvariant() -eq '.bat') {
        $hasLf = $false
        $hasCrLf = $false
        $bareLf = $false
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -eq 0x0A) {
                $hasLf = $true
                if ($i -gt 0 -and $bytes[$i - 1] -eq 0x0D) { $hasCrLf = $true }
                else { $bareLf = $true }
            }
        }
        if ($hasLf -and $bareLf) {
            $violations += ("BAD-CRLF  : {0} (bare LF without CR)" -f $rel)
        }
        elseif ($hasLf -and -not $hasCrLf) {
            $violations += ("BAD-CRLF  : {0} (no CRLF found)" -f $rel)
        }
        # Also ensure not empty and not missing newline check: if file has content but no CRLF but also no LF, it is single line bat which is OK.
    }
}

# Zip / exe check: no committed binaries under the new tree (exclude .git and audit)
$binaries = Get-ChildItem -Path $newRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
    $full = $_.FullName -replace '/', '\'
    if ($full -like '*\audit\*') { return $false }
    if ($full -like '*\.git\*') { return $false }
    $ext = $_.Extension.ToLowerInvariant()
    $ext -eq '.zip' -or $ext -eq '.exe'
}
foreach ($b in $binaries) {
    # Allow build/output ignored? .gitignore already excludes build/output/*.zip but CI still enforces no zip anywhere.
    $rel = $b.FullName.Substring($newRoot.Length + 1)
    $violations += ("BINARY    : {0} (zip/exe must not be committed)" -f $rel)
}

if (@($violations).Count -gt 0) {
    Write-Host ("HOUSE RULE VIOLATIONS ({0}):" -f @($violations).Count)
    foreach ($v in $violations) { Write-Host ("  " + $v) }
    exit 1
}

Write-Host ("House rules OK: {0} files scanned (ASCII, no BOM, JSON valid, CRLF, no binaries)." -f @($files).Count)
exit 0
