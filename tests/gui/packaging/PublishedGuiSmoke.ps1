[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ZipPath,
    [Parameter(Mandatory = $true)][string]$ScratchRoot
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$zip = [IO.Path]::GetFullPath($ZipPath)
$root = [IO.Path]::GetFullPath($ScratchRoot)
if (-not [IO.File]::Exists($zip)) { throw "Package ZIP missing: $zip" }
if ([IO.Directory]::Exists($root)) { throw "Smoke extraction directory must not already exist: $root" }

function Find-ElementByName {
    param(
        [System.Windows.Automation.AutomationElement]$Window,
        [string]$Name
    )
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty, $Name)
    return $Window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}

function Get-VisibleElement {
    param(
        [System.Windows.Automation.AutomationElement]$Window,
        [string]$Name
    )
    $element = Find-ElementByName -Window $Window -Name $Name
    if ($null -eq $element) { throw "UI Automation element missing: '$Name'." }
    if ($element.Current.IsOffscreen) { throw "UI Automation element is offscreen: '$Name'." }
    return $element
}

function Assert-EnabledButton {
    param(
        [System.Windows.Automation.AutomationElement]$Window,
        [string]$Name
    )
    $button = Get-VisibleElement -Window $Window -Name $Name
    if ($button.Current.ControlType -ne [System.Windows.Automation.ControlType]::Button) {
        throw "UI Automation element is not a button: '$Name'."
    }
    if (-not $button.Current.IsEnabled) { throw "Button is disabled: '$Name'." }
    return $button
}

function Assert-EnabledModeControl {
    param(
        [System.Windows.Automation.AutomationElement]$Window,
        [string]$Name
    )
    $control = Get-VisibleElement -Window $Window -Name $Name
    if (-not $control.Current.IsEnabled) { throw "Mode control is disabled: '$Name'." }
    return $control
}

function Invoke-ModeControl {
    param([System.Windows.Automation.AutomationElement]$Control)
    $pattern = $null
    if ($Control.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
        $pattern.Invoke()
        return
    }
    $pattern = $null
    if ($Control.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$pattern)) {
        $pattern.Select()
        return
    }
    throw "Mode control has neither Invoke nor SelectionItem UI Automation pattern: '$($Control.Current.Name)'."
}

function Wait-ForEnabledModeControl {
    param(
        [System.Windows.Automation.AutomationElement]$Window,
        [string]$Name,
        [int]$TimeoutSeconds = 8
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $button = Find-ElementByName -Window $Window -Name $Name
        if ($null -ne $button -and -not $button.Current.IsOffscreen -and
            $button.Current.IsEnabled) { return $button }
        Start-Sleep -Milliseconds 200
    }
    throw "Enabled mode control did not appear: '$Name'."
}

function Wait-ForEnabledButton {
    param(
        [System.Windows.Automation.AutomationElement]$Window,
        [string]$Name,
        [int]$TimeoutSeconds = 8
    )
    [void](Wait-ForEnabledModeControl -Window $Window -Name $Name -TimeoutSeconds $TimeoutSeconds)
    return Assert-EnabledButton -Window $Window -Name $Name
}

function Assert-SimpleModeSurface {
    param([System.Windows.Automation.AutomationElement]$Window)
    $scanName = 'Start simple Detect Only scan'
    $scanCondition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty, $scanName)
    $scanButtons = $Window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $scanCondition)
    if ($scanButtons.Count -ne 1) { throw "Expected one Simple scan button; found $($scanButtons.Count)." }

    $buttonCondition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Button)
    $allButtons = $Window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $buttonCondition)
    $scanNamedButtons = @($allButtons | Where-Object { $_.Current.Name -match '(?i)\bscan\b' })
    if ($scanNamedButtons.Count -ne 1 -or $scanNamedButtons[0].Current.Name -cne $scanName) {
        throw "Expected exactly one visible button with a Scan name ('$scanName'); found $($scanNamedButtons.Count)."
    }
    $scan = $scanButtons.Item(0)
    if ($scan.Current.ControlType -ne [System.Windows.Automation.ControlType]::Button -or
        -not $scan.Current.IsEnabled -or $scan.Current.IsOffscreen) {
        throw 'Simple scan button is not a visible, enabled button.'
    }
    [void](Get-VisibleElement -Window $Window -Name 'Simple scan status')
    $items = Get-VisibleElement -Window $Window -Name 'Simple detected items'
    $bounds = $items.Current.BoundingRectangle
    if ($bounds.Height -lt 100 -or $bounds.Height -gt 600 -or $bounds.Width -lt 100) {
        throw "Simple detected-items viewport is unusable or unbounded: width=$($bounds.Width), height=$($bounds.Height)."
    }
    [void](Assert-EnabledModeControl -Window $Window -Name 'Use Advanced mode')
}

function Assert-ElementNotVisible {
    param(
        [System.Windows.Automation.AutomationElement]$Window,
        [string]$Name
    )
    $element = Find-ElementByName -Window $Window -Name $Name
    if ($null -ne $element -and -not $element.Current.IsOffscreen) {
        throw "UI Automation element should not be visible: '$Name'."
    }
}

function Assert-NoChildProcesses {
    param([System.Diagnostics.Process]$Process)
    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($Process.Id)"
    if (@($children).Count -ne 0) {
        throw 'GUI spawned a child process; this fixture-only smoke must not invoke a detector or machine action.'
    }
}

function Invoke-PublishedGuiSmokeCleanup {
    param(
        [object]$Process,
        [string]$FixtureRoot,
        [int]$ExitTimeoutMilliseconds = 10000,
        [scriptblock]$StopProcess = {
            param($ProcessToStop)
            Stop-Process -Id $ProcessToStop.Id -Force -ErrorAction Stop
        },
        [scriptblock]$DeleteFixture = {
            param($PathToDelete)
            if ([IO.Directory]::Exists($PathToDelete)) {
                Remove-Item -LiteralPath $PathToDelete -Recurse -Force -ErrorAction Stop
            }
        }
    )
    if ($ExitTimeoutMilliseconds -le 0) { throw 'Process exit timeout must be positive.' }

    if ($null -ne $Process) {
        $Process.Refresh()
        $stopFailure = $null
        if (-not $Process.HasExited) {
            try { & $StopProcess $Process } catch { $stopFailure = $_ }
        }
        if (-not $Process.WaitForExit($ExitTimeoutMilliseconds)) {
            $stopDetail = ''
            if ($null -ne $stopFailure) { $stopDetail = " Stop request failed: $($stopFailure.Exception.Message)" }
            throw "Packaged GUI process $($Process.Id) did not exit within $ExitTimeoutMilliseconds ms; retaining fixture '$FixtureRoot'.$stopDetail"
        }
    }

    & $DeleteFixture $FixtureRoot
}

[void][IO.Directory]::CreateDirectory($root)
$process = $null
try {
    Expand-Archive -LiteralPath $zip -DestinationPath $root
    $exe = Join-Path $root 'ScreenConnectCleanup.Gui.exe'
    if (-not [IO.File]::Exists($exe)) { throw 'Extracted package does not contain the GUI executable.' }
    $process = Start-Process -FilePath $exe -PassThru -WorkingDirectory $root
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    $window = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) { throw "Extracted GUI exited early with code $($process.ExitCode)." }
        $window = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
            [System.Windows.Automation.TreeScope]::Children,
            (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $process.Id)))
        if ($null -ne $window) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($null -eq $window) { throw 'No top-level UI Automation window appeared for the extracted packaged process.' }
    if ($window.Current.Name -notlike '*Detect-only Inspection*') { throw "Unexpected packaged window title: $($window.Current.Name)" }

    Assert-SimpleModeSurface -Window $window
    Assert-ElementNotVisible -Window $window -Name 'Start Detect Only inspection'
    Assert-NoChildProcesses -Process $process

    $advancedMode = Assert-EnabledModeControl -Window $window -Name 'Use Advanced mode'
    Invoke-ModeControl -Control $advancedMode
    [void](Wait-ForEnabledModeControl -Window $window -Name 'Use Simple mode')

    $nav = Get-VisibleElement -Window $window -Name 'Navigate to Investigation view'
    if ($nav.Current.ControlType -ne [System.Windows.Automation.ControlType]::Button -or
        -not $nav.Current.IsEnabled) { throw 'Investigation navigation control is not an enabled button in Advanced mode.' }
    $nav.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()

    [void](Wait-ForEnabledButton -Window $window -Name 'Start Detect Only inspection')
    $disabled = Get-VisibleElement -Window $window -Name 'Full Investigation unavailable because its snapshot may load and unload the Amcache registry hive'
    if ($disabled.Current.IsEnabled) { throw 'Full Investigation control is enabled.' }
    [void](Get-VisibleElement -Window $window -Name 'Detect-only inspection safety notice')
    Assert-NoChildProcesses -Process $process

    $simpleMode = Assert-EnabledModeControl -Window $window -Name 'Use Simple mode'
    Invoke-ModeControl -Control $simpleMode
    [void](Wait-ForEnabledButton -Window $window -Name 'Start simple Detect Only scan')
    Assert-SimpleModeSurface -Window $window
    Assert-ElementNotVisible -Window $window -Name 'Start Detect Only inspection'
    Assert-NoChildProcesses -Process $process

    Write-Output "PASS: extracted ZIP starts in Simple mode; Advanced exposes Detect Only enabled and Full Investigation disabled; Simple mode is restored; no Scan control was invoked and no child process was observed."
} finally {
    Invoke-PublishedGuiSmokeCleanup -Process $process -FixtureRoot $root
}
