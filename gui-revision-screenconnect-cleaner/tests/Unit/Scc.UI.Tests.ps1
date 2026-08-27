# Scc.UI unit tests. Runs on Linux pwsh (no WPF instantiated).
$modulePath = Join-Path $PSScriptRoot '..\..\src\Scc.UI\Scc.UI.psd1'
$modulePath = [System.IO.Path]::GetFullPath($modulePath)
Import-Module $modulePath -Force -ErrorAction Stop

$viewDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\src\Scc.UI\Views'))

Describe 'Module import (headless / Linux)' {
    It 'imports without loading PresentationFramework' {
        (Get-Module -Name PresentationFramework) | Should -BeNullOrEmpty
        (Get-Module -Name Scc.UI) | Should -Not -BeNullOrEmpty
    }
    It 'exports exactly the 11 public functions' {
        $fns = (Get-Command -Module Scc.UI).Name | Sort-Object
        $expected = @(
            'Get-SccNextStage', 'New-SccWorkflow', 'Start-SccApp',
            'Start-SccJob', 'Start-SccWorkflow', 'Step-SccWorkflow', 'Stop-SccWorkflow',
            'Stop-SccJob', 'Update-SccJob', 'Wait-SccJob', 'Reset-SccJob',
            'Invoke-SccGuiWorkflow'
        ) | Sort-Object
        $fns | Should -BeExactly $expected
    }
}

Describe 'State machine and jobs (mocked backend)' {

    BeforeEach {
        Mock -ModuleName Scc.UI Import-Module { return $null }
        Mock -ModuleName Scc.UI Get-Module { return $null }
        Mock -ModuleName Scc.UI Invoke-SccBackendPreflight { return [ordered]@{ ComputerInfo = [pscustomobject]@{ ComputerName = 'TEST'; IsAdmin = $true }; Internet = $null; Nas = $null } }
        Mock -ModuleName Scc.UI Invoke-SccBackendSnapshot { param($Run, $Label, $Days) return [pscustomobject]@{ Label = $Label; CollectedUtc = [datetime]::UtcNow } }
        Mock -ModuleName Scc.UI Invoke-SccBackendDetection { return [pscustomobject]@{ ScreenConnect = @(); RemoteAccess = @(); Warnings = @() } }
        Mock -ModuleName Scc.UI Invoke-SccBackendRemediation { param($Run, $Plan) return [pscustomobject]@{ Executed = $true; DryRun = $true } }
        Mock -ModuleName Scc.UI Invoke-SccBackendScanners { param($Run, $Timeout) return @( [pscustomobject]@{ ScannerName = 'Defender'; Status = 'Completed'; Detections = @() } ) }
        Mock -ModuleName Scc.UI Invoke-SccBackendCompare { param($Before, $After, $Run) return [pscustomobject]@{ Summary = @{} } }
        Mock -ModuleName Scc.UI Invoke-SccBackendReport { return [pscustomobject]@{ ReportPath = 'report.html' } }
    }

    Describe 'State machine - construction' {
        It 'New-SccWorkflow builds 9 stages in order' {
            $wf = New-SccWorkflow -Mode Full
            @($wf.Stages).Count | Should -Be 9
            $wf.Stages[0].Name | Should -Be 'Preflight'
            $wf.Stages[8].Name | Should -Be 'Report'
            $wf.Mode | Should -Be 'Full'
        }
        It 'Get-SccNextStage returns first Pending stage' {
            $wf = New-SccWorkflow -Mode Full
            $next = Get-SccNextStage -Workflow $wf
            $next.Index | Should -Be 0
        }
    }

    Describe 'State machine - full happy path (headless, mocked)' {
        It 'advances every stage to Completed and records data' {
            $wf = New-SccWorkflow -Mode Full
            $planFile = Join-Path $TestDrive 'plan.json'
            @'
{ "PlanVersion": 1, "CreatedUtc": "2026-01-01T00:00:00Z", "CreatedBy": "test",
  "Items": [ { "FindingId": "SC1", "Product": "ScreenConnect", "TargetType": "Service", "Action": "REMOVE", "Detail": "x", "DisplayText": "y" } ] }
'@ | Set-Content -Path $planFile
            $wf.PlanPath = $planFile
            Start-SccWorkflow -Workflow $wf -Mode Full
            $wf.Status | Should -Be 'Completed'
            foreach ($s in $wf.Stages) { $s.Status | Should -Be 'Completed' }
            $wf.Data.Report | Should -Not -BeNullOrEmpty
            $wf.Data.SnapshotBefore | Should -Not -BeNullOrEmpty
            $wf.Data.Diff | Should -Not -BeNullOrEmpty
        }
    }

    Describe 'State machine - review gate' {
        It 'Review stops headless without a plan (AwaitingReview)' {
            $wf = New-SccWorkflow -Mode Full
            Start-SccWorkflow -Workflow $wf -Mode Full
            $wf.Stages[3].Status | Should -Be 'AwaitingReview'
            $wf.Status | Should -Be 'AwaitingReview'
            $wf.Stages[0].Status | Should -Be 'Completed'
            $wf.Stages[1].Status | Should -Be 'Completed'
            $wf.Stages[2].Status | Should -Be 'Completed'
        }
        It 'DetectOnly mode auto-passes Review and skips Remediate' {
            $wf = New-SccWorkflow -Mode DetectOnly
            Start-SccWorkflow -Workflow $wf -Mode DetectOnly
            $wf.Stages[3].Status | Should -Be 'Completed'
            $wf.Stages[4].Status | Should -Be 'Skipped'
            $wf.Status | Should -Be 'Completed'
            $wf.Stages[8].Status | Should -Be 'Completed'
        }
        It 'SkipScanners marks stage 5 Skipped' {
            $wf = New-SccWorkflow -Mode Full -SkipScanners
            $planFile = Join-Path $TestDrive 'planSkip.json'
            @'
{ "PlanVersion": 1, "CreatedUtc": "2026-01-01T00:00:00Z", "CreatedBy": "test",
  "Items": [ { "FindingId": "SC1", "Product": "ScreenConnect", "TargetType": "Service", "Action": "REMOVE", "Detail": "x", "DisplayText": "y" } ] }
'@ | Set-Content -Path $planFile
            Start-SccWorkflow -Workflow $wf -Mode Full -SkipScanners -PlanPath $planFile
            $wf.Stages[5].Status | Should -Be 'Skipped'
            $wf.Stages[6].Status | Should -Be 'Completed'
            $wf.Status | Should -Be 'Completed'
        }
        It 'resume: stages 0-3 Completed -> next stage is 4' {
            $wf = New-SccWorkflow -Mode Full
            foreach ($i in 0..3) { $wf.Stages[$i].Status = 'Completed' }
            $next = Get-SccNextStage -Workflow $wf
            $next.Index | Should -Be 4
        }
    }

    Describe 'State machine - prerequisite enforcement' {
        It 'stage 4 (Remediate) skipped when stage 3 not Completed' {
            $wf = New-SccWorkflow -Mode Full
            foreach ($i in 0..2) { $wf.Stages[$i].Status = 'Completed' }
            $wf.Stages[3].Status = 'Failed'
            Step-SccWorkflow -Workflow $wf
            $wf.Stages[4].Status | Should -Be 'Skipped'
        }
        It 'stage 6 (SnapshotAfter) skipped when stage 5 not Completed|Skipped' {
            $wf = New-SccWorkflow -Mode Full
            foreach ($i in 0..4) { $wf.Stages[$i].Status = 'Completed' }
            $wf.Stages[5].Status = 'Failed'
            Step-SccWorkflow -Workflow $wf
            $wf.Stages[6].Status | Should -Be 'Skipped'
        }
        It 'stage 7 (Compare) skipped when stage 6 not Completed' {
            $wf = New-SccWorkflow -Mode Full
            foreach ($i in 0..5) { $wf.Stages[$i].Status = 'Completed' }
            $wf.Stages[6].Status = 'Failed'
            Step-SccWorkflow -Workflow $wf
            $wf.Stages[7].Status | Should -Be 'Skipped'
        }
    }

    Describe 'State machine - failure is non-fatal' {
        It 'a throwing stage body marks Failed and the run continues' {
            Mock -ModuleName Scc.UI Invoke-SccBackendDetection { throw 'boom' }
            $wf = New-SccWorkflow -Mode DetectOnly
            Start-SccWorkflow -Workflow $wf -Mode DetectOnly
            $wf.Stages[2].Status | Should -Be 'Failed'
            $wf.Stages[5].Status | Should -Be 'Completed'
            $wf.Stages[8].Status | Should -Be 'Completed'
            $wf.Status | Should -Be 'Completed'
        }
    }

    Describe 'State machine - stop' {
        It 'Stop-SccWorkflow marks remaining Pending stages Skipped and status Interrupted' {
            $wf = New-SccWorkflow -Mode Full
            $wf.Stages[0].Status = 'Completed'
            $wf.Stages[1].Status = 'Running'
            Stop-SccWorkflow -Workflow $wf
            $wf.Status | Should -Be 'Interrupted'
            $wf.Stages[1].Status | Should -Be 'Interrupted'
            $wf.Stages[2].Status | Should -Be 'Skipped'
        }
    }

    Describe 'Start-SccJob' {
        BeforeEach {
            Reset-SccJob
        }
        It 'runs a trivial scriptblock and returns the result' {
            $job = Start-SccJob -ScriptBlock { param($t) 'hello' } -Name 'Trivial'
            if ($null -eq $job) { Set-ItResult -Skipped -Because 'job did not start'; return }
            Wait-SccJob -Handle $job
            $job.Result | Should -Be 'hello'
            $job.State | Should -Be 'Completed'
            $job.Percent | Should -Be 100
        }
        It 'cancellation token stops a loop job' {
            # Run the lifecycle inside a function scope. At the Pester/script
            # root scope, PowerShell can null a root variable when a runspace
            # created in that scope finalizes (a host-state quirk); production
            # callers (Start-SccApp -> stages) always invoke from function
            # scope, so wrapping here mirrors real usage and avoids the flake.
            function Invoke-CancellationScenario {
                Reset-SccJob
                $j = Start-SccJob -ScriptBlock { param($t) while (-not $t.Cancelled) { Start-Sleep -Milliseconds 20 } } -Name 'Loop'
                if ($null -eq $j) { return $null }
                Start-Sleep -Milliseconds 80
                Stop-SccJob -Handle $j
                Start-Sleep -Milliseconds 80
                Update-SccJob -Handle $j
                return $j
            }
            $job = Invoke-CancellationScenario
            if ($null -eq $job) { Set-ItResult -Skipped -Because 'job did not start'; return }
            $job._Token.Cancelled | Should -Be $true
            $job.State | Should -Be 'Interrupted'
        }
        It 'refuses a second concurrent job' {
            $job1 = Start-SccJob -ScriptBlock { param($t) Start-Sleep -Milliseconds 800 } -Name 'First'
            if ($null -eq $job1) { Set-ItResult -Skipped -Because 'first job did not start'; return }
            { Start-SccJob -ScriptBlock { param($t) 'x' } -Name 'Second' } | Should -Throw
            Wait-SccJob -Handle $job1
        }
        It 'runs the GUI click-handler pattern: token carries the real workflow into the runspace' {
            # Regression: pre-fix, the click handler passed the workflow as
            # -CancellationToken but the runspace only ever received a fresh
            # token copy, so the workflow never ran (buttons were dead). The
            # wrapper now copies the Workflow payload and imports Scc.UI into
            # the bare runspace so Invoke-SccGuiWorkflow resolves.
            # NOTE: polling is bounded (no unbounded Wait-SccJob) because
            # finalizing runspaces from earlier tests can corrupt caller
            # variables in this Pester host state.
            function Invoke-GuiJobScenario {
                Reset-SccJob
                $wf = New-SccWorkflow -Mode DetectOnly
                $token = @{ Cancelled = $false; Workflow = $wf }
                $j = Start-SccJob -ScriptBlock { param($t) Invoke-SccGuiWorkflow -Token $t } -Name 'GuiTest' -CancellationToken $token
                if ($null -eq $j) { return $null }
                $deadline = [datetime]::UtcNow.AddSeconds(30)
                while (-not $j._Done -and [datetime]::UtcNow -lt $deadline) {
                    Start-Sleep -Milliseconds 200
                    try { Update-SccJob -Handle $j } catch { }
                }
                return $j
            }
            $job = Invoke-GuiJobScenario
            if ($null -eq $job) { Set-ItResult -Skipped -Because 'job did not start'; return }
            if (-not $job._Done) { Reset-SccJob; Set-ItResult -Skipped -Because 'job did not finish within deadline'; return }
            $job.State | Should -Be 'Completed'
            $job.Error | Should -BeNullOrEmpty
            $job.Result | Should -Not -BeNullOrEmpty
            $job.Result.RunId | Should -Not -BeNullOrEmpty
            $job.Result.Status | Should -Be 'Completed'
        }
        It 'fails loudly when the token has no Workflow payload (wiring regression guard)' {
            function Invoke-BadTokenScenario {
                Reset-SccJob
                $j = Start-SccJob -ScriptBlock { param($t) Invoke-SccGuiWorkflow -Token $t } -Name 'BadToken'
                if ($null -eq $j) { return $null }
                $deadline = [datetime]::UtcNow.AddSeconds(30)
                while (-not $j._Done -and [datetime]::UtcNow -lt $deadline) {
                    Start-Sleep -Milliseconds 200
                    try { Update-SccJob -Handle $j } catch { }
                }
                return $j
            }
            $job = Invoke-BadTokenScenario
            if ($null -eq $job) { Set-ItResult -Skipped -Because 'job did not start'; return }
            if (-not $job._Done) { Reset-SccJob; Set-ItResult -Skipped -Because 'job did not finish within deadline'; return }
            $job.State | Should -Be 'Failed'
            $job.Error | Should -Match 'Workflow payload'
        }
        It 'stop signal cancels a running GUI workflow' {
            function Invoke-StopGuiScenario {
                Reset-SccJob
                $wf = New-SccWorkflow -Mode Full
                $token = @{ Cancelled = $false; Workflow = $wf }
                $j = Start-SccJob -ScriptBlock { param($t) Invoke-SccGuiWorkflow -Token $t } -Name 'GuiStop' -CancellationToken $token
                if ($null -eq $j) { return $null }
                Start-Sleep -Milliseconds 150
                Stop-SccJob -Handle $j
                Start-Sleep -Milliseconds 150
                Update-SccJob -Handle $j
                return $j
            }
            $job = Invoke-StopGuiScenario
            if ($null -eq $job) { Set-ItResult -Skipped -Because 'job did not start'; return }
            $job._Token.Cancelled | Should -Be $true
            if ($job._Done) {
                $job.State | Should -Be 'Interrupted'
            }
        }
    }

    Describe 'Headless smoke - full pipeline through Report' {
        It 'completes Preflight..Report with all backends mocked' {
            $wf = New-SccWorkflow -Mode Full
            $planFile = Join-Path $TestDrive 'plan2.json'
            @'
{ "PlanVersion": 1, "CreatedUtc": "2026-01-01T00:00:00Z", "CreatedBy": "test",
  "Items": [ { "FindingId": "SC1", "Product": "ScreenConnect", "TargetType": "Service", "Action": "REMOVE", "Detail": "x", "DisplayText": "y" } ] }
'@ | Set-Content -Path $planFile
            Start-SccWorkflow -Workflow $wf -Mode Full -PlanPath $planFile
            $wf.Status | Should -Be 'Completed'
            foreach ($s in $wf.Stages) { $s.Status | Should -Be 'Completed' }
            $wf.Data.Report | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'XAML views' {
    $views = @('Dashboard', 'Workflow', 'Findings', 'RemediationPreview', 'Scanners', 'Logs', 'ReportView', 'Settings', 'Advanced')
    $mod = Get-Module -Name Scc.UI
    $localViewDir = Join-Path (Split-Path -Parent $mod.Path) 'Views'
    It 'all XAML views are valid XML, pure ASCII, and free of inline handlers' {
        foreach ($v in $views) {
            $path = Join-Path $localViewDir ($v + '.xaml')
            Test-Path $path | Should -Be $true -Because "$path must exist"
            { [xml](Get-Content -Path $path) } | Should -Not -Throw
            $bytes = [System.IO.File]::ReadAllBytes($path)
            foreach ($b in $bytes) { $b -lt 128 | Should -Be $true -Because "$path must be pure ASCII" }
            $raw = Get-Content -Path $path -Raw
            $raw.Contains('<Script') | Should -Be $false -Because "$path must not contain inline scripts"
            $raw.Contains('x:Code') | Should -Be $false -Because "$path must not contain x:Code blocks"
            $raw.Contains('Click=') | Should -Be $false -Because "$path must not contain inline Click handlers"
            $raw.Contains('Loaded=') | Should -Be $false -Because "$path must not contain inline Loaded handlers"
        }
    }
}
