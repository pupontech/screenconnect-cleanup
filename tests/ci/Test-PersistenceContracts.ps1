# Static AST/interface checks. Runtime proof is in the separate fixture suites.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$passed=0;$failed=0
function Check([bool]$Condition,[string]$Name){if($Condition){$script:passed++;Write-Host ('PASS: '+$Name)}else{$script:failed++;Write-Host ('FAIL: '+$Name)}}
function Parse-Source([string]$Name){
    $path=Join-Path $repo $Name;$tokens=$null;$errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Check ($errors.Count -eq 0) ($Name+' target-runtime parser')
    return $tree
}
function Find-Assignment($Tree,[string]$Name){return $Tree.Find({param($node)$node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq ('$'+$Name)}.GetNewClosure(),$true)}
function Find-Command($Tree,[string]$Name){return $Tree.Find({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq $Name}.GetNewClosure(),$true)}
function Get-Argument($Command,[string]$Name){
    for($i=0;$i -lt $Command.CommandElements.Count;$i++){
        $part=$Command.CommandElements[$i]
        if($part -is [Management.Automation.Language.CommandParameterAst] -and $part.ParameterName -eq $Name){if($part.Argument){return $part.Argument};if($i+1 -lt $Command.CommandElements.Count){return $Command.CommandElements[$i+1]}}
    }
    return $null
}
$inventory=Parse-Source 'Persistence.Inventory.psm1'
$removal=Parse-Source 'Persistence.Removal.psm1'
$runner=Parse-Source 'Invoke-PersistenceScan.ps1'
$cleanup=Parse-Source 'sc-cleanup.ps1'
$report=Parse-Source 'New-InvestigationReport.ps1'
$share=Parse-Source 'Submit-ConnectWiseReport.ps1'
Check ((Get-Argument (Find-Command $inventory 'Export-ModuleMember') 'Function').Extent.Text -eq 'Get-SccPersistenceInventory') 'inventory public interface is explicitly exported'
Check ((Get-Argument (Find-Command $removal 'Export-ModuleMember') 'Function').Extent.Text -eq 'Invoke-SccPersistenceReview') 'removal exports review only, not private test hooks'
$stage=Find-Assignment $cleanup 'stage5bResult'
$scanner=Find-Assignment $cleanup 'stage5Result'
$reportStage=Find-Assignment $cleanup 'stage9Result'
Check ($stage -and $scanner -and $reportStage -and $scanner.Extent.StartOffset -lt $stage.Extent.StartOffset -and $stage.Extent.StartOffset -lt $reportStage.Extent.StartOffset) 'actual AST places mandatory persistence after scanner and before report'
$invoke=Find-Command $stage 'Invoke-Stage'
Check ((Get-Argument $invoke 'StageId').Extent.Text -eq "'5b'") 'persistence substage has the intended ID'
Check ((Get-Argument $invoke 'SkipFlag').Extent.Text -eq "''") 'persistence has no scanner/removal skip flag'
$stageFunction=$cleanup.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Stage'},$true)
$stageIdParameter=@($stageFunction.Body.ParamBlock.Parameters | Where-Object {$_.Name.VariablePath.UserPath -eq 'StageId'})[0]
$type=@($stageIdParameter.Attributes | Where-Object {$_ -is [Management.Automation.Language.TypeConstraintAst]})[0]
Check ($type.TypeName.FullName -eq 'string') 'stage ID type accepts 5b rather than invalid integer cast'
$child=Find-Command $stage 'Invoke-ChildScript'
Check (@($child.CommandElements | Where-Object {$_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Interactive'}).Count -eq 1) 'persistence child inherits visible interactive approval console'
foreach($paramName in @('PersistenceInventory','PersistenceRemoval','PersistenceResult')){
    Check (@($report.ParamBlock.Parameters | Where-Object {$_.Name.VariablePath.UserPath -eq $paramName}).Count -eq 1) ('report receives '+$paramName)
    Check (@($share.ParamBlock.Parameters | Where-Object {$_.Name.VariablePath.UserPath -eq $paramName}).Count -eq 1) ('sanitized share receives '+$paramName)
}
$batch=[IO.File]::ReadAllText((Join-Path $repo 'START-HERE.bat'))
Check ($batch.IndexOf(':skip_6c') -lt $batch.IndexOf('STEP 6d/9') -and $batch.IndexOf('STEP 6d/9') -lt $batch.IndexOf('STEP 8/9')) 'guided persistence runs after all scanner choices and before after-snapshot'
Check ($batch -match 'Invoke-PersistenceScan\.ps1" -WorkDir "!SCC_RUN_ROOT!" -PreflightRoot "!SCC_RUN_ROOT!"') 'guided current-run paths are explicitly quoted'
$build=[IO.File]::ReadAllText((Join-Path $repo 'make-deploy-bundle.sh'))
foreach($name in @('Invoke-PersistenceScan.ps1','Invoke-PersistenceInventoryWorker.ps1','Persistence.Inventory.psm1','Persistence.Removal.psm1')){Check ($build.Contains($name)) ('allowlisted bundle requires '+$name)}
$commands=@($inventory.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
Check (@($commands | Where-Object {$_ -in @('Unregister-ScheduledTask','Remove-ItemProperty','Remove-CimInstance','Start-Process','Invoke-Expression','Stop-Process')}).Count -eq 0) 'inventory has no system mutation or payload execution commands'
# Simplified Where-Object over external provider objects throws PSArgumentException
# as soon as one row lacks the named value; the collector must use the safe accessor.
# Comments are stripped so documentation of the anti-pattern is not flagged.
$source=[IO.File]::ReadAllText((Join-Path $repo 'Persistence.Inventory.psm1'))
$code=@($source -split '\r?\n' | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
$simplified=[regex]::Matches($code,'Where-Object\s+[A-Za-z_][A-Za-z0-9_]*\s+-(?:match|eq|ne|like|notlike|in|notin|gt|lt|ge|le)\b')
Check ($simplified.Count -eq 0) ('inventory uses no property-unresolved Where-Object form (found '+$simplified.Count+')')
Check ($source -match 'function Get-SccPropertyValue') 'inventory exposes the property-safe accessor'
Write-Host "Persistence static AST checks: passed=$passed failed=$failed (not live runtime proof)"
if($failed){exit 1}
exit 0
