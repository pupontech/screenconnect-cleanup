# test_microbin_uploader_password_prompt.ps1 - focused regression tests for
# the guided-run MicroBin uploader-password prompt added to START-HERE.bat:
#   - START-HERE.bat wiring: hidden prompt only after a usable URL is
#     confirmed, pre-configured password file reused without prompting,
#     run-scoped secret file under the run root, cleanup on the normal path
#     and on every failure exit, never deleting a pre-configured file, and
#     no secret anywhere in echoes/logs.
#   - Resolve-MicroBinUploaderPassword.ps1: hidden/masked input on a real
#     console, plain non-echoed read when stdin is piped, exit codes 0/1/3/4,
#     exact no-trailing-newline secret file write, blank = none, bounded
#     refusal of unusable values, environment-password short-circuit, and
#     no-secret logging on every path.
# Runs the helper as a real child PowerShell process (pwsh or 5.1) with
# disposable fixtures; no network and no live uploads.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$helperPath = Join-Path $repoRoot 'Resolve-MicroBinUploaderPassword.ps1'
$batPath = Join-Path $repoRoot 'START-HERE.bat'
$bundlePath = Join-Path $repoRoot 'make-deploy-bundle.sh'

$failures = @()
function Check {
    param([string]$Name, [bool]$Condition, [string]$Details)
    if ($Condition) {
        Write-Host ('PASS  ' + $Name)
    } else {
        $message = 'FAIL  ' + $Name
        if ($Details) { $message += ' - ' + $Details }
        Write-Host $message
        $script:failures += $message
    }
}

$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}

function Write-TextFile {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.ASCIIEncoding))
}

function Invoke-PasswordRun {
    param(
        [string]$SecretFile,
        [AllowEmptyString()][string[]]$Answers,
        [hashtable]$WithEnv
    )
    $callArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $helperPath, '-SecretFile', $SecretFile)
    $saved = @{}
    try {
        if ($null -ne $WithEnv) {
            foreach ($key in $WithEnv.Keys) {
                $saved[$key] = [Environment]::GetEnvironmentVariable($key)
                [Environment]::SetEnvironmentVariable($key, [string]$WithEnv[$key])
            }
        }
        $inputText = ''
        if ($null -ne $Answers -and $Answers.Count -gt 0) {
            $inputText = (($Answers -join "`n") + "`n")
        }
        $output = ($inputText | & $psHost @callArgs 2>&1)
        $text = ''
        if ($null -ne $output) { $text = ($output -join "`n") }
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = $text }
    } finally {
        if ($null -ne $WithEnv) {
            foreach ($key in $WithEnv.Keys) {
                [Environment]::SetEnvironmentVariable($key, [string]$saved[$key])
            }
        }
    }
}

$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-microbin-pwprompt-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force

try {
    # ---- Source-level contracts: START-HERE.bat wiring ----------------------
    $helperBytes = [System.IO.File]::ReadAllBytes($helperPath)
    $helperText = [System.Text.Encoding]::ASCII.GetString($helperBytes)
    $bat = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($batPath))
    $bundle = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($bundlePath))

    Check 'helper ships next to the launcher' (Test-Path -LiteralPath $helperPath -PathType Leaf) $helperPath
    Check 'helper is pure ASCII with no BOM' ($helperBytes.Length -ge 3 -and -not ($helperBytes[0] -eq 0xEF -and $helperBytes[1] -eq 0xBB -and $helperBytes[2] -eq 0xBF) -and -not ($helperText -match '[^\x00-\x7F]')) 'byte check failed'
    Check 'launcher references the hidden-password helper' ($bat.Contains('Resolve-MicroBinUploaderPassword.ps1')) $batPath

    $optinLabel = $bat.IndexOf("`r`n:microbin_optin`r`n", [System.StringComparison]::Ordinal)
    $optoutLabel = $bat.IndexOf("`r`n:microbin_optout`r`n", [System.StringComparison]::Ordinal)
    $doneLabel = $bat.IndexOf("`r`n:microbin_done`r`n", [System.StringComparison]::Ordinal)
    $helperIndex = $bat.IndexOf('Resolve-MicroBinUploaderPassword.ps1', [System.StringComparison]::Ordinal)
    $helperLastIndex = $bat.LastIndexOf('Resolve-MicroBinUploaderPassword.ps1', [System.StringComparison]::Ordinal)
    $createdIndex = $bat.IndexOf('SCC_MICROBIN_SECRET_CREATED=1', [System.StringComparison]::Ordinal)
    Check 'password prompt only lives inside the opt-in branch' ($helperIndex -gt $optinLabel -and $helperLastIndex -lt $optoutLabel -and $optoutLabel -gt $optinLabel) ('helper=' + $helperIndex + ' optinLabel=' + $optinLabel + ' optoutLabel=' + $optoutLabel)
    $helperCtxStart = [Math]::Max(0, $helperIndex - 500)
    $helperCtx = $bat.Substring($helperCtxStart, $helperIndex - $helperCtxStart)
    Check 'password prompt is gated behind a confirmed MicroBin URL' ($helperCtx.Contains('if defined SCC_MICROBIN_URL (') -and $helperCtx.Contains('!SCC_RUN_ROOT!\microbin-uploader-password.txt')) 'no URL gate or non-run-root path before the helper call'
    $optoutRegion = $bat.Substring($optoutLabel, $doneLabel - $optoutLabel)
    Check 'declined opt-in never reaches the password prompt' (-not $optoutRegion.Contains('Resolve-MicroBinUploaderPassword.ps1') -and -not $optoutRegion.Contains('microbin-uploader-password.txt') -and -not $optoutRegion.Contains('SCC_MICROBIN_SECRET_CREATED')) 'secret machinery reachable from the opt-out path'

    $secretLiteral = 'microbin-uploader-password.txt'
    Check 'run-scoped secret file name appears exactly once' ($bat.Split([string[]]@($secretLiteral), [System.StringSplitOptions]::None).Length -eq 2) 'expected a single set line'
    $secretSetIndex = $bat.IndexOf($secretLiteral, [System.StringComparison]::Ordinal)
    Check 'secret file is created inside this run root, never beside the tool' ($bat.Substring($secretSetIndex - 80, 100).Contains('!SCC_RUN_ROOT!')) 'not anchored under SCC_RUN_ROOT'

    Check 'pre-configured password file is reused without prompting' ($bat.Contains('Using the pre-configured MicroBin uploader password file')) $batPath
    Check 'prompt result branches on helper exit codes 4, 3 and 1' ($bat.Contains('if errorlevel 4 (') -and $bat.Contains('if errorlevel 3 (') -and $bat.Contains('if errorlevel 1 (')) $batPath
    Check 'a recorded password sets the run-created flag' ($createdIndex -gt $helperIndex) 'flag set outside the helper branch'
    Check 'cleanup is guarded by the run-created flag' ($bat.Contains('if defined SCC_MICROBIN_SECRET_CREATED (') -and $bat.Contains('SCC_MICROBIN_UPLOADER_PASSWORD_FILE=')) $batPath
    Check 'cleanup physically deletes the run-scoped secret file' ($bat.Contains('del /f /q')) $batPath
    Check 'cleanup runs on the normal path and every failure exit' (([regex]::Matches($bat, 'call :remove_microbin_secret')).Count -eq 6) ('calls=' + ([regex]::Matches($bat, 'call :remove_microbin_secret')).Count)
    Check 'report-step password file passthrough is preserved' ($bat.Contains('-MicroBinUploaderPasswordFile')) $batPath

    Check 'no SCREENCONNECT_ secret env name ever appears in the launcher' (-not $bat.Contains('SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD')) $batPath
    Check 'launcher never echoes the secret file variable or its name' (-not [regex]::IsMatch($bat, '(?im)echo[^\r\n]*(SCC_MICROBIN_UPLOADER_PASSWORD_FILE|SCC_MICROBIN_SECRET|microbin-uploader-password\.txt)')) 'secret echoed'
    Check 'deploy bundle carries the hidden-password helper' ($bundle.Contains('Resolve-MicroBinUploaderPassword.ps1')) $bundlePath

    # ---- Helper: environment short-circuit ----------------------------------
    $envDir = Join-Path $probeRoot 'env'
    $null = New-Item -ItemType Directory -Path $envDir -Force
    $envFile = Join-Path $envDir 'secret.txt'
    $outEnv = Invoke-PasswordRun -SecretFile $envFile -Answers @('TypedSecret-1') -WithEnv @{ 'SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD' = 'EnvSecret-9' }
    Check 'pre-configured env password: exit 3, no prompt, no file' ($outEnv.ExitCode -eq 3 -and -not (Test-Path -LiteralPath $envFile)) ('exit=' + $outEnv.ExitCode)
    Check 'env short-circuit output is silent and leak-free' ($outEnv.Text.Trim().Length -eq 0 -or (-not $outEnv.Text.Contains('EnvSecret-9') -and -not $outEnv.Text.Contains('TypedSecret-1'))) $outEnv.Text

    # ---- Helper: blank means no password ------------------------------------
    $noneDir = Join-Path $probeRoot 'none'
    $null = New-Item -ItemType Directory -Path $noneDir -Force
    $noneFile = Join-Path $noneDir 'secret.txt'
    $outBlank = Invoke-PasswordRun -SecretFile $noneFile -Answers @('')
    Check 'blank answer: exit 4, no secret file created' ($outBlank.ExitCode -eq 4 -and -not (Test-Path -LiteralPath $noneFile)) ('exit=' + $outBlank.ExitCode)
    Check 'blank answer output is empty' ($outBlank.Text.Trim().Length -eq 0) $outBlank.Text

    $outSpaces = Invoke-PasswordRun -SecretFile (Join-Path $noneDir 'spaces.txt') -Answers @('   ')
    Check 'whitespace-only answer: exit 4, no secret file created' ($outSpaces.ExitCode -eq 4 -and -not (Test-Path -LiteralPath (Join-Path $noneDir 'spaces.txt'))) ('exit=' + $outSpaces.ExitCode)

    # ---- Helper: password captured and stored exactly ------------------------
    $okDir = Join-Path $probeRoot 'ok'
    $null = New-Item -ItemType Directory -Path $okDir -Force
    $secretValue = 'SecretValue-42'
    $okFile = Join-Path $okDir 'secret.txt'
    $outOk = Invoke-PasswordRun -SecretFile $okFile -Answers @($secretValue)
    $storedOk = ''
    if (Test-Path -LiteralPath $okFile) { $storedOk = [System.IO.File]::ReadAllText($okFile) }
    Check 'valid password: exit 0 and file created' ($outOk.ExitCode -eq 0 -and (Test-Path -LiteralPath $okFile)) ('exit=' + $outOk.ExitCode)
    Check 'file holds exactly the password, no trailing newline' ($storedOk -eq $secretValue) ('stored=' + $storedOk)
    Check 'success output never contains the password' (-not $outOk.Text.Contains($secretValue)) $outOk.Text
    Check 'success writes nothing to stdout' ($outOk.Text.Trim().Length -eq 0) $outOk.Text

    $paddedValue = '  padded-pw-7  '
    $padFile = Join-Path $okDir 'padded.txt'
    $outPad = Invoke-PasswordRun -SecretFile $padFile -Answers @($paddedValue)
    $storedPad = ''
    if (Test-Path -LiteralPath $padFile) { $storedPad = [System.IO.File]::ReadAllText($padFile) }
    Check 'surrounding whitespace is trimmed, inner content kept' ($outPad.ExitCode -eq 0 -and $storedPad -eq 'padded-pw-7') $storedPad

    $innerValue = 'pa ss word-3'
    $innerFile = Join-Path $okDir 'inner.txt'
    $outInner = Invoke-PasswordRun -SecretFile $innerFile -Answers @($innerValue)
    $storedInner = ''
    if (Test-Path -LiteralPath $innerFile) { $storedInner = [System.IO.File]::ReadAllText($innerFile) }
    Check 'internal spaces are preserved' ($outInner.ExitCode -eq 0 -and $storedInner -eq $innerValue) $storedInner

    # ---- Helper: unusable values refused, never echoed, bounded --------------
    $longValue = ('A' * 600)
    $retryValue = 'ValidRetry-5'
    $longFile = Join-Path $okDir 'long.txt'
    $outLong = Invoke-PasswordRun -SecretFile $longFile -Answers @($longValue, $retryValue)
    $storedLong = ''
    if (Test-Path -LiteralPath $longFile) { $storedLong = [System.IO.File]::ReadAllText($longFile) }
    Check 'oversized value is refused and a later valid one wins' ($outLong.ExitCode -eq 0 -and $storedLong -eq $retryValue) $storedLong
    Check 'refusal hint is shown without echoing the refused value' ($outLong.Text.Contains('cannot be used') -and -not $outLong.Text.Contains($longValue)) $outLong.Text

    $outExhaust = Invoke-PasswordRun -SecretFile (Join-Path $okDir 'exhausted.txt') -Answers @($longValue, $longValue, $longValue)
    Check 'three refused attempts fail closed with exit 1' ($outExhaust.ExitCode -eq 1 -and -not (Test-Path -LiteralPath (Join-Path $okDir 'exhausted.txt'))) ('exit=' + $outExhaust.ExitCode)
    Check 'exhausted failure never logs the refused value' (-not $outExhaust.Text.Contains(('A' * 32))) $outExhaust.Text

    $tabValue = "bad`tvalue"
    $tabFile = Join-Path $okDir 'tab.txt'
    $outTab = Invoke-PasswordRun -SecretFile $tabFile -Answers @($tabValue, 'CleanPass-8')
    $storedTab = ''
    if (Test-Path -LiteralPath $tabFile) { $storedTab = [System.IO.File]::ReadAllText($tabFile) }
    Check 'non-printable value is refused, later valid one wins' ($outTab.ExitCode -eq 0 -and $storedTab -eq 'CleanPass-8') $storedTab

    # ---- Helper: environment failures are loud but never leak the value ------
    $missingDir = Join-Path $probeRoot 'no-such-dir-here'
    $missingFile = Join-Path $missingDir 'secret.txt'
    $noDirPass = 'NoDirPass-11'
    $outNoDir = Invoke-PasswordRun -SecretFile $missingFile -Answers @($noDirPass)
    Check 'unwritable target dir: exit 1 with an error, no file' ($outNoDir.ExitCode -eq 1 -and -not (Test-Path -LiteralPath $missingFile)) ('exit=' + $outNoDir.ExitCode)
    Check 'write failure message never contains the typed password' ($outNoDir.Text.Contains('[ERROR]') -and -not $outNoDir.Text.Contains($noDirPass)) $outNoDir.Text

    # ---- Helper: paths with spaces and apostrophes ----------------------------
    $oddDir = Join-Path $probeRoot "sec dir with 'spaces'"
    $null = New-Item -ItemType Directory -Path $oddDir -Force
    $oddFile = Join-Path $oddDir 'secret.txt'
    $oddValue = 'OddPathPass-2'
    $outOdd = Invoke-PasswordRun -SecretFile $oddFile -Answers @($oddValue)
    $storedOdd = ''
    if (Test-Path -LiteralPath $oddFile) { $storedOdd = [System.IO.File]::ReadAllText($oddFile) }
    Check 'space/apostrophe secret path stores the password' ($outOdd.ExitCode -eq 0 -and $storedOdd -eq $oddValue) $storedOdd
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) MicroBin uploader-password prompt test(s) failed")
    exit 1
}
Write-Host 'ALL MICROBIN UPLOADER-PASSWORD PROMPT TESTS PASSED'
exit 0
