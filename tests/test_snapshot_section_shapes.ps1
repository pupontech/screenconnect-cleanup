# Test the actual single-section JSON envelope without consulting Windows providers.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'collect-snapshot.ps1'),[ref]$tokens,[ref]$errors)
$sectionIf=$ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -eq '$Section'} | Select-Object -First 1
if(-not $sectionIf){throw 'Could not find the actual single-section envelope.'}
# Exclude only the top-level exit statement so the fixture host remains alive.
$body=($sectionIf.Clauses[0].Item2.Statements | Where-Object {$_ -isnot [Management.Automation.Language.ExitStatementAst]} | ForEach-Object {$_.Extent.Text}) -join "`n"
$script:CollectionErrors=New-Object System.Collections.ArrayList
$script:CollectionWarnings=New-Object System.Collections.ArrayList
$Section='Services'
foreach($count in @(0,1,2)) {
    $script:FixtureRows=$count;$script:SectionCalls=0
    function Get-SectionDataByName {param($Name) $script:SectionCalls++;for($i=0;$i -lt $script:FixtureRows;$i++){[pscustomobject]@{Key=('service-'+$i);Name=('service-'+$i)}}}
    $json=& ([scriptblock]::Create($body))
    $result=$json | ConvertFrom-Json
    if($result.Data -isnot [array] -or $result.Data.Count -ne $count -or $script:SectionCalls -ne 1){throw ('Single-section envelope lost its array/count contract for '+$count+' rows: '+$json)}
}
$Section='Srum';$script:SectionCalls=0
function Get-SectionDataByName {param($Name) $script:SectionCalls++;[pscustomobject]@{Available=$false;Reason='fixture'}}
$json=& ([scriptblock]::Create($body))
$result=$json | ConvertFrom-Json
if($result.Data -is [array] -or $result.Data.Reason -ne 'fixture' -or $script:SectionCalls -ne 1){throw 'Object-valued SRUM section was wrongly normalized into a row collection.'}
Write-Host 'PASS: actual single-section envelope preserves empty/single/many arrays and the SRUM object with one collection call.'
