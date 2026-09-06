# Resolve-MicroBinUploaderPassword.ps1 - optional hidden uploader-password
# prompt for the guided-run MicroBin share (START-HERE.bat).
#
# When the operator opted into MicroBin sharing and no uploader password is
# pre-configured, this helper asks for the optional uploader password with
# HIDDEN (masked) input and writes it to a run-scoped secret file - a path the
# batch caller chose inside that run's root. The password is never echoed to
# the console, never written to microbin-url.txt or any log, never stored
# beside the tool, and never printed on stdout: the batch caller branches on
# the exit code only. Error messages never include the typed value.
#
# Input handling:
#   - Real console (START-HERE.bat run by a technician): stdin is not
#     redirected, so Read-Host -AsSecureString masks every keystroke.
#   - Redirected/piped stdin (automated tests, CI): secure-string reading is
#     not available, so the line is read with [Console]::In.ReadLine(); piped
#     input is never echoed back by definition. Tests therefore exercise the
#     same code path the resolver tests use.
#
# Precedence mirrors Submit-ConnectWiseReport.ps1: when the
# SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD environment variable already holds
# a password, nothing is prompted and no file is written - the uploader reads
# that environment variable itself at upload time. The value is only ever sent
# inside the multipart body over the validated transport.
#
# Exit codes (the batch caller branches on these):
#   0 - a nonblank password was captured and written to -SecretFile.
#   4 - no password was entered (blank / Enter / end of input) - the run
#       continues without an uploader credential; the secret file is not
#       created. Blank at any attempt means "none".
#   3 - a password is already configured in the environment, so there is
#       nothing to prompt and no file to write.
#   1 - environment error (the secret file could not be written, or no usable
#       password after three refused attempts).
#
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param(
    # Full path of the run-scoped secret file to create. It is created only
    # when a nonblank password is entered; its parent directory must exist
    # (the batch caller points it inside this run's freshly created root).
    [Parameter(Mandatory = $true)]
    [string]$SecretFile,

    # Password ceiling. MicroBin documents no limit, so a generous bound keeps
    # the value sane without ever truncating. No password is ever shortened.
    [int]$MaxPasswordLength = 512
)

$ErrorActionPreference = 'Stop'

$envPassword = $env:SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD
if (-not [string]::IsNullOrWhiteSpace($envPassword)) {
    # Already configured: the uploader reads the environment itself. Never
    # print or re-type the value here.
    exit 3
}

function Test-UsablePassword {
    param([string]$Value)
    # Plain ASCII printable only (the URL file and the run-scoped secret file
    # stay plain text, matching the rest of the tool's ASCII rules), at most
    # MaxPasswordLength characters. The value arrives already trimmed.
    if ($Value.Length -eq 0) { return $false }
    if ($Value.Length -gt $MaxPasswordLength) { return $false }
    foreach ($c in $Value.ToCharArray()) {
        $code = [int]$c
        if ($code -lt 0x20 -or $code -gt 0x7E) { return $false }
    }
    return $true
}

function Read-PasswordLine {
    # Real console: masked input via a SecureString, converted in memory only.
    # Redirected/piped stdin (tests, automation): plain read - there is no
    # terminal echo to mask, and piped content is never echoed back anyway.
    if (-not [Console]::IsInputRedirected) {
        $secure = Read-Host '    MicroBin uploader password - hidden input; press Enter for none' -AsSecureString
        if ($secure.Length -eq 0) { return '' }
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    $line = $null
    try {
        $line = [Console]::In.ReadLine()
    } catch {
        $line = $null
    }
    if ($null -eq $line) { return '' }
    return [string]$line
}

function Write-SecretFile {
    param([string]$Path, [string]$Value)
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if ([string]::IsNullOrEmpty($parent)) { $parent = (Get-Location).Path }
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw ('secret file directory does not exist: ' + $parent)
    }
    # Exact value, no BOM, no trailing newline: the uploader reads the file and
    # trims, so the stored bytes are the password and nothing else.
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
    # Best-effort lock-down on Windows: drop inherited ACLs and keep only the
    # current user, SYSTEM and Administrators. A failure here is never fatal -
    # the run root is already a per-run, administrator-created directory.
    if ($env:OS -eq 'Windows_NT') {
        try {
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false)
            $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            foreach ($identity in @($userSid, $systemSid, $adminsSid)) {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $identity,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.AccessControlType]::Allow)
                $acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $Path -AclObject $acl
        } catch {
            # Best effort only; inherited run-root ACLs still apply.
        }
    }
}

$attempt = 1
while ($attempt -le 3) {
    $line = Read-PasswordLine
    $value = ''
    if ($null -ne $line) { $value = ([string]$line).Trim() }
    if ($value.Length -eq 0) {
        # Blank at any attempt means "no uploader credential for this run".
        # Nothing was typed, so there is nothing to protect or to log.
        exit 4
    }
    if (Test-UsablePassword -Value $value) {
        try {
            Write-SecretFile -Path $SecretFile -Value $value
        } catch {
            Write-Host ('[ERROR] Could not write the MicroBin uploader password file ' + $SecretFile + ': ' + $_.Exception.Message)
            exit 1
        }
        exit 0
    }
    if ($attempt -lt 3) {
        Write-Host '    [i] That password cannot be used - use up to 512 plain ASCII characters, or press Enter for none.'
    }
    $attempt++
}
Write-Host '    [WARN] No usable MicroBin uploader password was entered; continuing without one.'
exit 1
