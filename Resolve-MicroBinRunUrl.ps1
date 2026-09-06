# Resolve-MicroBinRunUrl.ps1 - resolve the MicroBin server base URL for a run.
# Used by START-HERE.bat's start-of-run opt-in. A URL already configured in the
# operator's microbin-url.txt (first nonblank trimmed line) wins and is printed
# on stdout as the ONLY line. When the file is missing or has no usable line,
# the operator is prompted interactively for an https:// base URL; the typed
# value is validated before it is saved to that file for future runs. Typed
# values are never echoed back or written to any log, and the URL file never
# receives passwords (credential-bearing URLs are refused before saving).
#
# Exit codes (the caller branches on these):
#   0 - a URL is available. In -SkipPrompt mode stdout carries exactly that
#       URL; interactively the URL was validated and saved to the config file.
#   4 - no URL is configured and none was provided (never upload).
#   1 - environment error (config file unreadable/unwritable, etc).
#
# The value read from an existing file is used verbatim (only trimmed / BOM
# stripped): the uploader (Submit-ConnectWiseReport.ps1) performs the deep
# https/no-credentials validation at upload time and fails loudly while the
# local package is retained, per the run contract.
#
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param(
    # Path to the operator's microbin-url.txt (the file beside the tool).
    [Parameter(Mandatory = $true)]
    [string]$ConfigFile,

    # When set, never prompt: report the file state only (silent, no console
    # output except the URL itself on success). Used by the batch runner to
    # pre-flight the saved URL before deciding whether to prompt.
    [switch]$SkipPrompt
)

$ErrorActionPreference = 'Stop'

function Read-ConfiguredUrl {
    param([string]$Path)
    # First nonblank trimmed line. A UTF-8 BOM on the first line (Notepad saves
    # UTF-8 with BOM by default) is stripped so a visually valid URL still
    # parses. Trailing whitespace and CR are removed by Trim.
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    foreach ($raw in [System.IO.File]::ReadLines($Path)) {
        $line = [string]$raw
        $line = $line.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line[0] -eq [char]0xFEFF) {
            $line = $line.Substring(1).Trim()
            if ($line.Length -eq 0) { continue }
        }
        return $line
    }
    return $null
}

function Test-UsableMicroBinUrl {
    param([string]$Value)
    # Only an absolute https:// URL without embedded credentials and without a
    # password-in-the-URL shape is accepted for guided runs: the uploader
    # refuses plain http and embedded credentials, so anything else would be
    # saved only to fail on every later run. ASCII printable only, so the
    # persisted file stays plain ASCII.
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value.Length -lt 9 -or $Value.Length -gt 2048) { return $false }
    foreach ($c in $Value.ToCharArray()) {
        $code = [int]$c
        if ($code -lt 0x21 -or $code -gt 0x7E) { return $false }
    }
    $parsed = $null
    if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$parsed)) { return $false }
    if (-not [string]::Equals($parsed.Scheme, 'https', [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    if (-not [string]::IsNullOrEmpty($parsed.UserInfo)) { return $false }
    if ([string]::IsNullOrWhiteSpace($parsed.Host)) { return $false }
    return $true
}

function Write-ConfiguredUrl {
    param([string]$Path, [string]$Value)
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -Force
    }
    $encoding = New-Object System.Text.ASCIIEncoding
    [System.IO.File]::WriteAllText($Path, $Value + "`r`n", $encoding)
}

$configured = $null
try {
    $configured = Read-ConfiguredUrl -Path $ConfigFile
} catch {
    if (-not $SkipPrompt) {
        Write-Host ('[ERROR] Could not read the MicroBin URL file ' + $ConfigFile + ': ' + $_.Exception.Message)
    }
    exit 1
}

if (-not [string]::IsNullOrWhiteSpace($configured)) {
    Write-Output $configured
    exit 0
}

if ($SkipPrompt) {
    # Silent: the batch caller treats "no stdout, exit 4" as "not configured".
    exit 4
}

# Interactive: ask for the base URL, validate it, save it for future runs.
# Bounded attempts so a stuck or empty input stream cannot hang the runner.
# Input is read with [Console]::In.ReadLine() rather than Read-Host so that
# piped/redirected input is never echoed back into the captured output; on a
# real console the operator's keystrokes are echoed by the terminal itself,
# exactly like any text prompt. Values are never written to logs or files.
$attempt = 1
while ($attempt -le 3) {
    Write-Host '    MicroBin server base URL for report sharing (https://host):'
    $answer = $null
    try {
        $answer = [Console]::In.ReadLine()
    } catch {
        $answer = $null
    }
    $value = ''
    if ($null -ne $answer) { $value = ([string]$answer).Trim() }
    if (Test-UsableMicroBinUrl -Value $value) {
        try {
            Write-ConfiguredUrl -Path $ConfigFile -Value $value
            Write-Host '    [i] Saved to microbin-url.txt beside the tool; future runs reuse it.'
        } catch {
            Write-Host ('[ERROR] Could not save the MicroBin URL file ' + $ConfigFile + ': ' + $_.Exception.Message)
            exit 1
        }
        exit 0
    }
    if ($attempt -lt 3) {
        Write-Host '    [i] That value cannot be used - enter the server base URL as https://host (no embedded credentials).'
    }
    $attempt++
}
Write-Host '    [WARN] No usable MicroBin server URL was entered; report sharing is skipped for this run.'
exit 4
