# Exercise the real HTML error sink independently of engine-specific parser text.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'New-InvestigationReport.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Report source did not parse.'}
foreach($name in @('Encode-Html','Fmt')) {
    $fn=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    . ([scriptblock]::Create($fn.Extent.Text))
}
$sink=$ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$avNote'},$true)
if(-not $sink){throw 'Could not locate the actual AV error sink.'}
$avError='Invalid evidence: <img src=x onerror="bad()"> & <script>bad()</script>'
$AVUninstall='fixture';$qNote=''
. ([scriptblock]::Create($sink.Extent.Text))
if($avNote -match '<img|<script' -or $avNote -notmatch '&lt;img' -or $avNote -notmatch '&lt;script&gt;' -or $avNote -notmatch '&amp;'){throw 'AV error warning interpolated evidence markup without HTML escaping.'}
Write-Host 'PASS: actual AV warning sink HTML-escapes attacker-influenced exception text.'
