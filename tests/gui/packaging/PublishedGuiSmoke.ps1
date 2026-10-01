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
[void][IO.Directory]::CreateDirectory($root)
try {
    Expand-Archive -LiteralPath $zip -DestinationPath $root
    $exe = Join-Path $root 'ScreenConnectCleanup.Gui.exe'
    if (-not [IO.File]::Exists($exe)) { throw 'Extracted package does not contain the GUI executable.' }
    $process = Start-Process -FilePath $exe -PassThru -WorkingDirectory $root
    try {
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
        $nav = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
            (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, 'Navigate to Investigation view')))
        if ($null -eq $nav) { throw 'Investigation navigation control missing from actual packaged window.' }
        $nav.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
        Start-Sleep -Milliseconds 500
        $disabled = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
            (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, 'Full Investigation unavailable because its snapshot may load and unload the Amcache registry hive')))
        if ($null -eq $disabled -or $disabled.Current.IsEnabled) { throw 'Full Investigation control is absent or enabled.' }
        $detect = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
            (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, 'Start Detect Only inspection')))
        if ($null -eq $detect -or -not $detect.Current.IsEnabled) { throw 'Detect Only control is absent or disabled.' }
        $notice = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
            (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, 'Detect-only inspection safety notice')))
        if ($null -eq $notice) { throw 'Detect-only safety notice missing from actual packaged window.' }
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($process.Id)"
        if (@($children).Count -ne 0) { throw 'GUI spawned a child process before any UI action; fixture-only smoke must not invoke machine actions.' }
        Write-Output "PASS: extracted ZIP GUI window/control UIA smoke (title='$($window.Current.Name)'); Detect Only enabled, Full Investigation disabled; no child process/action invoked."
    } finally {
        $process.Refresh()
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    }
} finally {
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
