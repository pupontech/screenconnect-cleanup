# test_microbin_run_url_config.ps1 - focused regression tests for the
# start-of-run MicroBin configuration flow of the guided runner:
#   - START-HERE.bat opt-in wiring: explicit [y/N], default no, no upload on
#     blank/no, relay-only behavior preserved when skipped.
#   - Resolve-MicroBinRunUrl.ps1: first-nonblank-trimmed-line file read,
#     missing/empty-file interactive prompt + save, invalid-input handling,
#     paths with spaces/apostrophes, and no-secret logging.
# Runs the resolver as a real child PowerShell process (pwsh or 5.1) with
# disposable fixtures; no network and no live uploads.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$resolverPath = Join-Path $repoRoot 'Resolve-MicroBinRunUrl.ps1'
$batPath = Join-Path $repoRoot 'START-HERE.bat'
$bundlePath = Join-Path $repoRoot 'make-deploy-bundle.sh'
$urlFileRoot = Join-Path $repoRoot 'microbin-url.txt'

$failures = @()
function Check {
    param([string]$Name, [bool]$Condition, [string]$Details)
    if ($Condition) {
        Write-Host ("PASS  " + $Name)
    } else {
        $message = "FAIL  " + $Name
        if ($Details) { $message += " - " + $Details }
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

function Invoke-ResolverRun {
    param(
        [string]$ConfigFile,
        [AllowEmptyString()][string[]]$Answers,
        [switch]$Skip
    )
    $callArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $resolverPath, '-ConfigFile', $ConfigFile)
    if ($Skip) { $callArgs += '-SkipPrompt' }
    if ($null -eq $Answers -or $Answers.Count -eq 0) {
        $output = & $psHost @callArgs 2>&1
    } else {
        $output = (($Answers -join "`n") + "`n") | & $psHost @callArgs 2>&1
    }
    $text = ''
    if ($null -ne $output) { $text = ($output -join "`n") }
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = $text }
}

$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-microbin-runurl-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force

try {
    # ---- Source-level contracts: START-HERE.bat opt-in wiring ---------------
    $bat = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($batPath))
    $bundle = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($bundlePath))

    Check 'launcher offers an explicit MicroBin opt-in prompt' ($bat.Contains('Upload the sanitized report to MicroBin? [y/N]')) $batPath
    Check 'launcher default-no gate requires an explicit y' ($bat.Contains('if /i "%GO%"=="y" goto :microbin_optin')) 'gate missing'
    $gateIndex = $bat.IndexOf('if /i "%GO%"=="y"', [System.StringComparison]::Ordinal)
    $resolverIndex = $bat.IndexOf('Resolve-MicroBinRunUrl.ps1', [System.StringComparison]::Ordinal)
    Check 'URL resolution only runs after the explicit-y gate' ($gateIndex -ge 0 -and $resolverIndex -gt $gateIndex) ('gate=' + $gateIndex + ' resolver=' + $resolverIndex)
    Check 'blank or no answer never reaches URL resolution' ($bat.Contains('goto :microbin_optout')) 'no default-no fallthrough'
    $optOut = [regex]::Match($bat, '(?s):microbin_optout\r\n(.*?):microbin_done\r\n')
    Check 'declined opt-in clears the URL and keeps the run relay-only' ($optOut.Success -and $optOut.Value.Contains('SCC_MICROBIN_URL=') -and $optOut.Value.Contains('relay behavior unchanged')) 'no clear-on-decline path'
    Check 'launcher reads/writes microbin-url.txt beside the tool' ($bat.Contains('microbin-url.txt')) $batPath
    Check 'launcher pre-flights the saved URL before prompting' ($bat.Contains('-SkipPrompt')) $batPath
    Check 'report-step MicroBin arg is gated on a resolved URL' ($bat.Contains('if defined SCC_MICROBIN_URL')) $batPath
    Check 'relay upload path is preserved' ($bat.Contains('reports.aygross.xyz/v1/uploads') -and $bat.Contains('-NoReportUpload')) $batPath
    Check 'uploader password is only forwarded, never defined or echoed in the launcher' ($bat.Contains('SCC_MICROBIN_UPLOADER_PASSWORD_FILE') -and -not $bat.Contains('SCREENCONNECT_MICROBIN_UPLOADER_PASSWORD')) $batPath
    Check 'launcher never echoes the configured URL' (-not [regex]::IsMatch($bat, '(?im)echo[^\r\n]*SCC_MICROBIN_URL')) $batPath
    Check 'deploy bundle carries the resolver and the empty URL placeholder' ($bundle.Contains('Resolve-MicroBinRunUrl.ps1') -and $bundle.Contains('microbin-url.txt')) $bundlePath
    Check 'repo ships an empty microbin-url.txt placeholder' ((Test-Path -LiteralPath $urlFileRoot -PathType Leaf) -and (Get-Item -LiteralPath $urlFileRoot).Length -eq 0) $urlFileRoot

    # ---- Saved-URL read behavior (skip mode: silent, stdout = URL only) -----
    $cfgDir = Join-Path $probeRoot 'read'
    $null = New-Item -ItemType Directory -Path $cfgDir -Force

    $missingCfg = Join-Path $cfgDir 'missing.txt'
    $outMissing = Invoke-ResolverRun -ConfigFile $missingCfg -Skip
    Check 'missing URL file with skip: exit 4, no output' ($outMissing.ExitCode -eq 4 -and $outMissing.Text.Trim().Length -eq 0) ($outMissing.Text)

    $emptyCfg = Join-Path $cfgDir 'empty.txt'
    Write-TextFile -Path $emptyCfg -Text ''
    $outEmpty = Invoke-ResolverRun -ConfigFile $emptyCfg -Skip
    Check 'empty URL file with skip: exit 4, no output' ($outEmpty.ExitCode -eq 4 -and $outEmpty.Text.Trim().Length -eq 0) ($outEmpty.Text)

    $blankCfg = Join-Path $cfgDir 'blank.txt'
    Write-TextFile -Path $blankCfg -Text "`r`n   `t`r`n`r`n"
    $outBlank = Invoke-ResolverRun -ConfigFile $blankCfg -Skip
    Check 'whitespace-only URL file with skip: exit 4, no output' ($outBlank.ExitCode -eq 4 -and $outBlank.Text.Trim().Length -eq 0) ($outBlank.Text)

    $goodCfg = Join-Path $cfgDir 'good.txt'
    Write-TextFile -Path $goodCfg -Text "https://paste.example.org`r`n"
    $outGood = Invoke-ResolverRun -ConfigFile $goodCfg -Skip
    Check 'configured URL file: exit 0, exact URL on stdout' ($outGood.ExitCode -eq 0 -and $outGood.Text.Trim() -eq 'https://paste.example.org') $outGood.Text

    $messyCfg = Join-Path $cfgDir 'messy.txt'
    Write-TextFile -Path $messyCfg -Text "`r`n   `r`n  https://paste.example.org/base   `r`nhttps://ignored.example.org`r`n"
    $outMessy = Invoke-ResolverRun -ConfigFile $messyCfg -Skip
    Check 'first nonblank trimmed line wins; later lines ignored' ($outMessy.ExitCode -eq 0 -and $outMessy.Text.Trim() -eq 'https://paste.example.org/base') $outMessy.Text

    $bomCfg = Join-Path $cfgDir 'bom.txt'
    [System.IO.File]::WriteAllBytes($bomCfg, ([System.Text.Encoding]::UTF8.GetPreamble()) + [System.Text.Encoding]::ASCII.GetBytes("https://bom.example.org`r`n"))
    $outBom = Invoke-ResolverRun -ConfigFile $bomCfg -Skip
    Check 'UTF-8 BOM on the first line is stripped' ($outBom.ExitCode -eq 0 -and $outBom.Text.Trim() -eq 'https://bom.example.org') $outBom.Text

    $verbatimCfg = Join-Path $cfgDir 'verbatim.txt'
    Write-TextFile -Path $verbatimCfg -Text "not a url at all`r`n"
    $outVerbatim = Invoke-ResolverRun -ConfigFile $verbatimCfg -Skip
    Check 'file value is used verbatim (uploader reports an invalid URL honestly)' ($outVerbatim.ExitCode -eq 0 -and $outVerbatim.Text.Trim() -eq 'not a url at all') $outVerbatim.Text

    # ---- Interactive prompt + save ------------------------------------------
    $promptDir = Join-Path $probeRoot 'prompt'
    $null = New-Item -ItemType Directory -Path $promptDir -Force

    $promptMissing = Join-Path $promptDir 'missing-url.txt'
    $outAsk = Invoke-ResolverRun -ConfigFile $promptMissing -Answers @('https://typed.example.org')
    Check 'missing file prompts and saves on a valid answer' ($outAsk.ExitCode -eq 0 -and (Test-Path -LiteralPath $promptMissing)) $outAsk.Text
    $savedText = ''
    if (Test-Path -LiteralPath $promptMissing) { $savedText = [System.IO.File]::ReadAllText($promptMissing) }
    Check 'saved file holds exactly the URL plus CRLF' ($savedText -eq "https://typed.example.org`r`n") $savedText
    Check 'prompt flow confirms the save without echoing the URL' ($outAsk.Text.Contains('Saved to microbin-url.txt') -and $outAsk.Text -notmatch 'typed\.example\.org') $outAsk.Text

    $promptEmpty = Join-Path $promptDir 'empty-url.txt'
    Write-TextFile -Path $promptEmpty -Text ''
    $outAskEmpty = Invoke-ResolverRun -ConfigFile $promptEmpty -Answers @('https://empty.example.org')
    Check 'empty file prompts and saves on a valid answer' ($outAskEmpty.ExitCode -eq 0 -and [System.IO.File]::ReadAllText($promptEmpty) -eq "https://empty.example.org`r`n") $outAskEmpty.Text

    $outBlankThen = Invoke-ResolverRun -ConfigFile (Join-Path $promptDir 'blank-first.txt') -Answers @('', 'https://after-blank.example.org')
    Check 'blank first answer is refused, a later valid answer saves' ($outBlankThen.ExitCode -eq 0 -and (Test-Path -LiteralPath (Join-Path $promptDir 'blank-first.txt'))) $outBlankThen.Text
    $blankFirstSaved = ''
    if (Test-Path -LiteralPath (Join-Path $promptDir 'blank-first.txt')) { $blankFirstSaved = [System.IO.File]::ReadAllText((Join-Path $promptDir 'blank-first.txt')) }
    Check 'blank-then-valid saved the valid URL only' ($blankFirstSaved -eq "https://after-blank.example.org`r`n") $blankFirstSaved

    $outInvalid = Invoke-ResolverRun -ConfigFile (Join-Path $promptDir 'invalid-then-valid.txt') -Answers @('not-a-url', 'http://insecure.example.org', 'https://final.example.org')
    Check 'invalid input is refused and re-prompted before a valid save' ($outInvalid.ExitCode -eq 0 -and $outInvalid.Text.Contains('cannot be used')) $outInvalid.Text
    $invalidSaved = ''
    if (Test-Path -LiteralPath (Join-Path $promptDir 'invalid-then-valid.txt')) { $invalidSaved = [System.IO.File]::ReadAllText((Join-Path $promptDir 'invalid-then-valid.txt')) }
    Check 'invalid values are never persisted' ($invalidSaved -eq "https://final.example.org`r`n") $invalidSaved
    Check 'invalid values are never echoed back into the output' ($outInvalid.Text -notmatch 'not-a-url' -and $outInvalid.Text -notmatch 'insecure\.example\.org') $outInvalid.Text

    $outExhaust = Invoke-ResolverRun -ConfigFile (Join-Path $promptDir 'exhausted.txt') -Answers @('bad-one', 'bad-two', 'bad-three')
    Check 'three invalid answers fail closed with exit 4' ($outExhaust.ExitCode -eq 4 -and $outExhaust.Text.Contains('skipped for this run')) $outExhaust.Text
    Check 'exhausted prompt never creates the URL file' (-not (Test-Path -LiteralPath (Join-Path $promptDir 'exhausted.txt'))) $outExhaust.Text
    Check 'typed invalid values are not logged on the failure path' ($outExhaust.Text -notmatch 'bad-one|bad-two|bad-three') $outExhaust.Text

    # ---- No-secret logging ----------------------------------------------------
    $secret = 'SuperSecretUploaderValue-9f8e7d6c'
    $outSecret = Invoke-ResolverRun -ConfigFile (Join-Path $promptDir 'secret-url.txt') -Answers @(('https://user:' + $secret + '@example.org'), 'https://clean.example.org')
    $secretSaved = ''
    if (Test-Path -LiteralPath (Join-Path $promptDir 'secret-url.txt')) { $secretSaved = [System.IO.File]::ReadAllText((Join-Path $promptDir 'secret-url.txt')) }
    Check 'credential-bearing URL is refused and never saved to the URL file' ($outSecret.ExitCode -eq 0 -and $secretSaved -eq "https://clean.example.org`r`n" -and $secretSaved -notmatch $secret) $secretSaved
    Check 'refused credential value never appears in the output' ($outSecret.Text -notmatch $secret -and $outSecret.Text -notmatch 'user:') $outSecret.Text

    # ---- Paths with spaces and apostrophes ------------------------------------
    $oddDir = Join-Path $probeRoot "cfg dir with 'spaces'"
    $null = New-Item -ItemType Directory -Path $oddDir -Force
    $oddCfg = Join-Path $oddDir 'microbin-url.txt'
    Write-TextFile -Path $oddCfg -Text 'https://spaced.example.org'
    $outOdd = Invoke-ResolverRun -ConfigFile $oddCfg -Skip
    Check 'space/apostrophe config path reads the saved URL' ($outOdd.ExitCode -eq 0 -and $outOdd.Text.Trim() -eq 'https://spaced.example.org') $outOdd.Text
    $oddSaveCfg = Join-Path $oddDir 'new-url.txt'
    $outOddSave = Invoke-ResolverRun -ConfigFile $oddSaveCfg -Answers @('https://saved-to-odd-path.example.org')
    Check 'space/apostrophe config path saves an interactive answer' ($outOddSave.ExitCode -eq 0 -and [System.IO.File]::ReadAllText($oddSaveCfg) -eq "https://saved-to-odd-path.example.org`r`n") $outOddSave.Text
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) MicroBin run-URL configuration test(s) failed")
    exit 1
}
Write-Host 'ALL MICROBIN RUN-URL CONFIGURATION TESTS PASSED'
exit 0
