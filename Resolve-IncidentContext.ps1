# Resolve-IncidentContext.ps1 - record the operator's incident context for a run.
# Used by START-HERE.bat's report stage. The technician is asked once per run
# for the two context facts that belong on the sanitized report:
#
#   Authorization - is the ScreenConnect activity authorized by the
#                   organization? Closed set: Authorized / Not authorized.
#                   Default (blank answer): Not authorized.
#   Delivery      - how did the session reach the user? Closed set:
#                   Email invite scam / Other. Default (blank answer):
#                   Email invite scam. Choosing Other requires a short,
#                   printable-ASCII description so the recorded value is
#                   never an empty or ambiguous label.
#
# The chosen values are written to the operator-supplied -OutFile as exactly
# two ASCII lines (CRLF): Authorization, then Delivery. The file lives inside
# the run root (a per-run artifact) and holds no secrets. Typed values are
# never echoed back into the output stream and never logged.
#
# Exit codes (the caller branches on these):
#   0 - the validated values were written to the output file.
#   4 - no valid context was entered after bounded attempts; no file written.
#   1 - environment error (output file could not be written).
#
# The uploader (Submit-ConnectWiseReport.ps1) applies the SAME closed-set
# validation to whatever it receives, so a hand-edited file or a different
# caller cannot smuggle an invalid value into the report.
#
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param(
    # Per-run output file for the two validated context values (two ASCII
    # lines: authorization, delivery).
    [Parameter(Mandatory = $true)]
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

# --- Closed sets shared (by convention) with Submit-ConnectWiseReport.ps1 ---
$script:AuthorizationAuthorized     = 'Authorized'
$script:AuthorizationNotAuthorized  = 'Not authorized'
$script:DeliveryEmailInviteScam     = 'Email invite scam'
$script:DeliveryOtherPrefix         = 'Other: '
$script:OtherLabelMaxLength         = 80
# Characters that would be unsafe to forward through the batch runner's
# quoted command line (percent and exclamation expand in cmd even inside
# quotes; the rest are cmd metacharacters). Everything else in printable
# ASCII is allowed in an Other description.
$script:ForbiddenLabelChars = @('"', '%', '!', '&', '|', '<', '>', '^', '(', ')')

function Read-AnswerLine {
    # [Console]::In.ReadLine() returns $null at end of input and never echoes
    # the typed value into a captured stream; on a real console the terminal
    # itself echoes keystrokes, exactly like any text prompt.
    try {
        return [Console]::In.ReadLine()
    } catch {
        return $null
    }
}

function Test-LabelAllowed {
    param([string]$Label)
    # A label must be short, printable ASCII, and free of characters that
    # would be unsafe or ambiguous when the value travels through the batch
    # runner into the report uploader.
    if ($Label.Length -lt 1 -or $Label.Length -gt $script:OtherLabelMaxLength) { return $false }
    foreach ($ch in $Label.ToCharArray()) {
        $code = [int]$ch
        if ($code -lt 0x20 -or $code -gt 0x7E) { return $false }
        if ($script:ForbiddenLabelChars -contains ([string]$ch)) { return $false }
    }
    return $true
}

function Write-ContextFile {
    param([string]$Path, [string]$Authorization, [string]$Delivery)
    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -Force
    }
    $encoding = New-Object System.Text.ASCIIEncoding
    [System.IO.File]::WriteAllText($Path, $Authorization + "`r`n" + $Delivery + "`r`n", $encoding)
}

$authorization = $script:AuthorizationNotAuthorized
$delivery = $script:DeliveryEmailInviteScam

# ---- Authorization: closed two-value set; blank means the safe default ----
$authAttempt = 1
$authResolved = $false
while (-not $authResolved -and $authAttempt -le 3) {
    Write-Host '    Incident context - Authorization: is this ScreenConnect activity authorized by the organization?'
    Write-Host '      [A]uthorized / [N]ot authorized   (Enter = Not authorized)'
    $answer = Read-AnswerLine
    $value = ''
    if ($null -ne $answer) { $value = ([string]$answer).Trim() }
    if ($value.Length -eq 0) {
        $authorization = $script:AuthorizationNotAuthorized
        $authResolved = $true
    } else {
        switch ($value.ToLowerInvariant()) {
            { $_ -in @('a', 'authorized', 'yes') } { $authorization = $script:AuthorizationAuthorized; $authResolved = $true }
            { $_ -in @('n', 'not authorized', 'no') } { $authorization = $script:AuthorizationNotAuthorized; $authResolved = $true }
            default {
                if ($authAttempt -lt 3) {
                    Write-Host '      [i] Answer A for Authorized or N for Not authorized (Enter accepts the Not authorized default).'
                }
            }
        }
    }
    $authAttempt++
}
if (-not $authResolved) {
    Write-Host '    [WARN] No valid authorization answer was entered; incident context was not recorded for this run.'
    exit 4
}

# ---- Delivery: Email invite scam by default; Other requires a description --
$deliveryResolved = $false
$deliveryAttempt = 1
while (-not $deliveryResolved -and $deliveryAttempt -le 3) {
    Write-Host '    Incident context - Delivery: how did the ScreenConnect session reach the user?'
    Write-Host '      [E]mail invite scam / [O]ther   (Enter = Email invite scam)'
    $answer = Read-AnswerLine
    $value = ''
    if ($null -ne $answer) { $value = ([string]$answer).Trim() }
    if ($value.Length -eq 0) {
        $delivery = $script:DeliveryEmailInviteScam
        $deliveryResolved = $true
    } elseif ($value.ToLowerInvariant() -in @('e', 'email', 'email invite scam')) {
        $delivery = $script:DeliveryEmailInviteScam
        $deliveryResolved = $true
    } elseif ($value.ToLowerInvariant() -in @('o', 'other')) {
        # A description is mandatory here: "Other" alone would be an
        # ambiguous context value, and a blank one is not the safe default
        # because the operator already chose to deviate from it.
        Write-Host '      Describe the delivery (printable ASCII, max 80 chars; no quotes, % ! & | < > ^ or parentheses):'
        $labelAnswer = Read-AnswerLine
        $label = ''
        if ($null -ne $labelAnswer) { $label = ([string]$labelAnswer).Trim() }
        if (Test-LabelAllowed -Label $label) {
            $delivery = $script:DeliveryOtherPrefix + $label
            $deliveryResolved = $true
        } elseif ($deliveryAttempt -lt 3) {
            Write-Host '      [i] That description cannot be used - keep it to printable ASCII without quotes or cmd metacharacters.'
        }
    } else {
        if ($deliveryAttempt -lt 3) {
            Write-Host '      [i] Answer E for Email invite scam or O for Other (Enter accepts the Email invite scam default).'
        }
    }
    $deliveryAttempt++
}
if (-not $deliveryResolved) {
    Write-Host '    [WARN] No valid delivery answer was entered; incident context was not recorded for this run.'
    exit 4
}

# ---- Persist the validated pair; a write failure must be loud ---------------
try {
    Write-ContextFile -Path $OutFile -Authorization $authorization -Delivery $delivery
} catch {
    Write-Host ('[ERROR] Could not write the incident context file ' + $OutFile + ': ' + $_.Exception.Message)
    exit 1
}
Write-Host '    [i] Incident context recorded for this run.'
exit 0
