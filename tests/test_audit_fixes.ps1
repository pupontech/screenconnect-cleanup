<#
  Regression for the audit-fix port (Claude 2026-10-11 pass folded into v1.8.6+).

  Covers, with AST/text evidence:
    1. sc-cleanup.ps1 / preflight.ps1 - the unhandled-error `trap` sits at the
       script level (its AST parent is the script block), not inside an `if`.
       A trap inside a statement block only covers that block.
    2. sc-cleanup.ps1 ConvertTo-ProcessArgument follows Windows argv quoting
       (backslashes doubled only before a quote / at the end of a quoted value;
       empty string survives). On Windows the helper is additionally round-
       tripped through the real CommandLineToArgvW.
    3. install-latest.ps1 has no top-level `exit` (that closes the technician's
       console under `irm | iex`) and keeps preferences session-local.
    4. relay/app.py routes early POST rejections through the draining _reject().

  PS 5.1 compatible. Run: pwsh -NoProfile -File tests/test_audit_fixes.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$failures = New-Object System.Collections.Generic.List[string]
function Assert-True { param([bool]$Condition, [string]$Message) if (-not $Condition) { $script:failures.Add($Message); Write-Host ("FAIL: " + $Message) } else { Write-Host ("ok:   " + $Message) } }

function Get-Ast { param([string]$Path) [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null) }

# --- 1. trap placement -------------------------------------------------------
foreach ($name in @('sc-cleanup.ps1', 'preflight.ps1')) {
    $path = Join-Path $RepoRoot $name
    $ast = Get-Ast $path
    $traps = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TrapStatementAst] }, $true)
    Assert-True ($traps.Count -ge 1) ("$name declares a trap")
    # A script-level trap's ancestors are NamedBlockAst -> ScriptBlockAst and
    # no IfStatementAst; a trap nested in `if ($Debug) { ... }` has an if
    # ancestor and only covers that statement block.
    $scriptLevel = @($traps | Where-Object {
        $p = $_.Parent; $hasIf = $false
        while ($null -ne $p) {
            if ($p -is [System.Management.Automation.Language.IfStatementAst]) { $hasIf = $true; break }
            $p = $p.Parent
        }
        -not $hasIf
    }).Count
    Assert-True ($scriptLevel -ge 1) ("$name trap is at script level (no if-statement ancestor)")
}

# --- 2. argument quoting helper ---------------------------------------------
$scPath = Join-Path $RepoRoot 'sc-cleanup.ps1'
$scAst = Get-Ast $scPath
$fn = $scAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConvertTo-ProcessArgument' }, $true) | Select-Object -First 1
Assert-True ($null -ne $fn) 'ConvertTo-ProcessArgument exists in sc-cleanup.ps1'
if ($fn) {
    . ([scriptblock]::Create($fn.Extent.Text))
    $cases = @(
        @{ In = 'plain';              Out = 'plain' },
        @{ In = '';                   Out = '""' },
        @{ In = 'a b';                Out = '"a b"' },
        @{ In = 'C:\dir with space\'; Out = '"C:\dir with space\\"' },
        @{ In = 'D:\Out Dir\';        Out = '"D:\Out Dir\\"' },
        @{ In = 'say "hi"';           Out = '"say \"hi\""' },
        @{ In = 'a\"b c';             Out = '"a\\\"b c"' }
    )
    foreach ($c in $cases) {
        $got = ConvertTo-ProcessArgument $c.In
        Assert-True ($got -eq $c.Out) ("quote {0} -> {1}" -f ($c.In -replace '\s','_'), $got)
    }
    # Windows-only: prove the encoding against the OS parser.
    if ($env:OS -eq 'Windows_NT') {
        if (-not ([System.Management.Automation.PSTypeName]'SccArgv').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SccArgv {
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);
}
'@
        }
        $n = 0
        $ptr = [SccArgv]::CommandLineToArgvW('x ' + (ConvertTo-ProcessArgument 'C:\dir with space\') + ' ' + (ConvertTo-ProcessArgument '') + ' ' + (ConvertTo-ProcessArgument 'say "hi"'), [ref]$n)
        $argv = @()
        for ($i = 0; $i -lt $n; $i++) { $argv += [System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::ReadIntPtr($ptr, $i * [IntPtr]::Size)) }
        Assert-True ($n -eq 4 -and $argv[1] -eq 'C:\dir with space\' -and $argv[2] -eq '' -and $argv[3] -eq 'say "hi"') 'CommandLineToArgvW round-trip (Windows)'
    } else {
        Write-Host 'skip: CommandLineToArgvW round-trip is Windows-only (Linux CI cannot parse Windows argv)'
    }
}

# --- 3. installer has no top-level exit -------------------------------------
$instPath = Join-Path $RepoRoot 'install-latest.ps1'
$instAst = Get-Ast $instPath
$exitCalls = $instAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true)
Assert-True (@($exitCalls).Count -eq 0) 'install-latest.ps1 contains no exit statement (would close the caller console under irm|iex)'
$instText = Get-Content -LiteralPath $instPath -Raw
Assert-True ($instText -match '(?m)^&\s*\{') 'install-latest.ps1 wraps its body in a scriptblock so preferences stay caller-local'

# --- 4. relay drains early rejections ---------------------------------------
$relayText = Get-Content -LiteralPath (Join-Path $RepoRoot 'relay/app.py') -Raw
Assert-True ($relayText -match 'def _reject\(') 'relay/_reject exists'
Assert-True (@([regex]::Matches($relayText, 'self\._reject\(')).Count -ge 6) 'all six early POST rejections call _reject'
Assert-True (@([regex]::Matches($relayText, 'close_connection = True')).Count -eq 1) 'close_connection is set only inside _reject (no early rejection aborts before responding)'

if ($failures.Count -gt 0) { Write-Host ("`n" + $failures.Count + ' failure(s)') -ForegroundColor Red; exit 1 }
Write-Host "`nPASS: audit-fix regressions"
exit 0
