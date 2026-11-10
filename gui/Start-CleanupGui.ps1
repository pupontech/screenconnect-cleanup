<#
  Start-CleanupGui.ps1 - the ScreenConnect Cleanup window (docs/14-gui-architecture.md).

  A third front end, not a third engine: every step is a child powershell.exe running the same
  script START-HERE.bat runs, with the same arguments, one at a time. This file only wires
  controls, one DispatcherTimer and a few dialogs to gui\Gui.Core.psm1. It contains no
  detection, snapshot, removal, scanner, persistence or report logic, loads no engine module
  and runs no engine code in this process.

  The start panel toggles between the Offline half (no internet), the Online half, Detect only and
  Stage tools - the same modes as START-HERE-OFFLINE.bat, START-HERE-ONLINE.bat and
  START-HERE.bat --stage (the full run is not offered: it is Offline then Online). The
  technician is asked the same questions the
  batch file asks. Rules that never bend:
    * an approving answer is written to a child ONLY as the direct result of the technician's
      own click or typing in a dialog that names what is being approved;
    * closing a dialog (window X) sends the engine's REFUSING answer, never yes;
    * removal needs the technician to type the word REMOVE, then the script's own y/N follows;
    * nothing is remembered between runs and there is no unattended mode.

  Started by START-HERE-GUI.bat (elevated, -STA). Windows PowerShell 5.1, pure ASCII, no BOM.

  Test hooks (tests\gui only): -LoadOnly loads the XAML, checks every named control and exits.
  -AutoStart -ResultPath <file> starts a run without a click, writes the final window state to the
  file and closes; it opens nothing and copies nowhere near the real Desktop. -AutoStart for any
  mode other than Detect additionally needs SCC_GUI_TEST=1 and SCC_GUI_TEST_ANSWERS=<json file>,
  which stands in for the technician's clicks; a dialog with no entry there behaves as if it was
  closed with the window X (the refusing answer). -AllowNotElevated lets tests run without admin.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$RitRoot = 'C:\RIT-SCC',
    [switch]$AllowNotElevated,
    [switch]$LoadOnly,
    [switch]$AutoStart,
    [string]$Mode = '',
    [string]$ResultPath = '',
    [int]$HoldSeconds = 0,
    [string]$RenderPng = '',
    # Light or dark design tokens; System follows the Windows app-mode setting.
    [ValidateSet('System', 'Light', 'Dark')][string]$Theme = 'System',
    # Builds the real dialogs without showing them and checks the typed-word gate and the design tokens.
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# WPF needs a single-threaded apartment. The launcher passes -STA; if this was started some other way, restart once.
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    # Forward every parameter that was given, whatever it is, so a new parameter cannot be forgotten here.
    $again = @('-NoLogo', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) { if ($kv.Value.IsPresent) { $again += ('-' + $kv.Key) } }
        else { $again += @(('-' + $kv.Key), [string]$kv.Value) }
    }
    & (Join-Path $PSHOME 'powershell.exe') @again
    exit $LASTEXITCODE
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Import-Module (Join-Path $PSScriptRoot 'Gui.Core.psm1') -Force

$script:Version = 'dev'
try { $script:Version = ([IO.File]::ReadAllText((Join-Path $ToolRoot 'VERSION'))).Trim() } catch { }

# ---- elevation: the launcher elevates once; the window never asks again ----------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $AllowNotElevated) {
    [void][System.Windows.MessageBox]::Show("This window must run as administrator.`n`nClose it and start START-HERE-GUI.bat, which asks for administrator rights once.", 'ScreenConnect Cleanup', 'OK', 'Warning')
    exit 1
}

# ---- load the window --------------------------------------------------------------------------
$xamlText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'MainWindow.xaml'))
$win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$xamlText)))
$ui = @{}
$controlNames = 'TitleText', 'InfoText', 'RunText', 'BtnOpenRitRoot', 'BtnOpenRunHeader', 'StepperHost', 'StartPanel',
'RbOffline', 'RbOnline', 'RbDetect', 'RbStage', 'BtnStart', 'PriorRunsText',
'RunPanel', 'StatusTitle', 'StatusDetail', 'Busy', 'Banner', 'BannerText', 'ReviewBar', 'ReviewSummary', 'BtnReviewContinue',
'CardsHost', 'BtnOpenReport', 'BtnOpenRun', 'BtnRestart', 'BtnNewRun', 'BtnCopy', 'BtnOpenLog', 'ConsoleBox'
$missing = @()
foreach ($n in $controlNames) {
    $c = $win.FindName($n)
    if ($null -eq $c) { $missing += $n } else { $ui[$n] = $c }
}
if ($missing.Count -gt 0) {
    Write-Host ('Window is missing controls: ' + ($missing -join ', ')) -ForegroundColor Red
    exit 1
}
if ($LoadOnly) { Write-Host ('LOAD_OK controls=' + $controlNames.Count); exit 0 }

# ---- state -------------------------------------------------------------------------------------
$script:Session = $null
$script:Action = $null
$script:Child = $null
$script:InDialog = $false
$script:Finished = $false
$script:StepRows = @{}
$script:LogPath = ''
$script:KeepRows = @()
$script:CloseLock = $false
$script:DlgValue = $null
$script:DlgChecks = @{}
$script:DlgText = $null
$script:ConsoleSaved = Set-GuiConsoleEncoding
$script:ShareUrl = ''
$script:SessionWriteWarned = $false
# The modes the window offers and their labels come from gui\steps.json ("Window": true), the one list.
# The core also knows 'Full' (START-HERE.bat with no flag), but in the window it would only repeat
# Offline followed by Online, so it is not offered (owner, 2026-11-10).
$script:ModeLabels = @{}
foreach ($m in (Get-GuiWindowModes)) { $script:ModeLabels[$m.Name] = $m.Label }

# Test hooks: canned dialog answers stand in for the technician's clicks (tests\gui only).
# They are honoured ONLY in a window that is NOT elevated. Nothing the engine does to the PC can
# succeed without administrator rights (preflight refuses, and the remover, services and Program
# Files need admin), so a canned answer can never approve a real removal - there is no unattended
# mode (docs/06 rule 2, docs/14 section 8). START-HERE-GUI.bat always runs the window elevated, so
# in a real run the hook does not exist. The same gate covers -RenderPng and -HoldSeconds.
$script:TestAnswers = $null
$script:TestHooksAllowed = (-not $isAdmin) -and [bool]$ResultPath
if ($script:TestHooksAllowed -and $env:SCC_GUI_TEST -eq '1' -and $env:SCC_GUI_TEST_ANSWERS -and (Test-Path -LiteralPath $env:SCC_GUI_TEST_ANSWERS)) {
    $script:TestAnswers = [IO.File]::ReadAllText($env:SCC_GUI_TEST_ANSWERS) | ConvertFrom-Json
}
$script:TestMode = ($null -ne $script:TestAnswers) -and $script:TestHooksAllowed
if (-not $script:TestHooksAllowed) { $HoldSeconds = 0; $RenderPng = '' }
$startMode = $(if ($Mode) { $Mode } else { 'Detect' })
if (-not $script:ModeLabels.ContainsKey($startMode)) {
    Write-Host ('Unknown or unsupported mode for this window: ' + $startMode + ' (use Offline, Online, Detect or Stage).') -ForegroundColor Red
    exit 2
}
$script:AutoStart = ($AutoStart -and $ResultPath -and ($startMode -eq 'Detect' -or $script:TestMode))

function Get-TestAnswer {
    param([string]$Id)
    if (-not $script:TestMode) { return $null }
    $p = $script:TestAnswers.PSObject.Properties[$Id]
    if ($p) { return $p.Value }
    return $null
}

function Get-Brush {
    # A design token from MainWindow.xaml ("Brush.<Tone>"). Never a literal colour: the token set is the
    # one place colours live, and it swaps as a whole for the dark theme. An unknown token throws.
    param([string]$Tone)
    return $win.FindResource('Brush.' + $Tone)
}

function Set-GuiTheme {
    # Light is what the XAML defines. Dark replaces every Brush.* token with the Theme.Dark set before any
    # element is built, so everything that uses the tokens (XAML via DynamicResource, code via Get-Brush)
    # follows. System = the Windows "app mode" setting (Settings > Personalization > Colors).
    param([string]$Name)
    $useDark = $false
    if ($Name -eq 'Dark') { $useDark = $true }
    elseif ($Name -eq 'System') {
        try {
            $v = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -ErrorAction Stop
            $useDark = ([int]$v.AppsUseLightTheme -eq 0)
        } catch { $useDark = $false }
    }
    if ($useDark) {
        $dark = $win.Resources['Theme.Dark']
        foreach ($k in @($dark.Keys)) { $win.Resources[$k] = $dark[$k] }
    }
    $script:ThemeName = $(if ($useDark) { 'Dark' } else { 'Light' })
}
Set-GuiTheme $Theme

function Set-ButtonStyle {
    # Buttons the script builds use the same component styles as the XAML ones.
    param($Button, [string]$Variant = 'Secondary')
    $Button.Style = $win.FindResource('Button.' + $Variant)
}

function Write-GuiLogText {
    param([string]$Text)
    if (-not $script:LogPath) { return }
    try { [IO.File]::AppendAllText($script:LogPath, $Text + "`r`n", (New-Object System.Text.UTF8Encoding($false))) } catch { }
}

function Add-ConsoleLines {
    param([string[]]$Lines)
    if (@($Lines).Count -eq 0) { return }
    $text = (@($Lines) -join "`r`n") + "`r`n"
    $ui.ConsoleBox.AppendText($text)
    if ($ui.ConsoleBox.Text.Length -gt 400000) { $ui.ConsoleBox.Text = $ui.ConsoleBox.Text.Substring(200000) }
    $ui.ConsoleBox.ScrollToEnd()
    Write-GuiLogText ((@($Lines)) -join "`r`n")
}

function Add-ConsoleNote {
    param([string]$Text)
    Add-ConsoleLines @('[GUI] ' + $Text)
}

# ---- stepper -----------------------------------------------------------------------------------
function Get-NotInModeReason {
    # Why a step of the guided runner does not run in the chosen mode (design 6: "A skipped step says why").
    param([string]$ModeName, $Step)
    $phases = @($Step.Phases)
    switch ($ModeName) {
        'Offline' { if ($phases -contains 'ONLINE') { return 'needs internet - run the Online half' }; return 'not part of the Offline half' }
        'Online' { if ($phases -contains 'OFFLINE') { return 'done by the Offline half' }; return 'not part of the Online half' }
        'Detect' { return 'not in Detect only (it changes nothing)' }
        'Stage' { return 'not in Stage tools (downloads only)' }
        default { return 'not in this mode' }
    }
}

function Initialize-Stepper {
    # Every step of the guided runner, in its order. Steps the chosen mode does not run stay listed,
    # greyed, with the reason.
    param($Plan, [string]$ModeName)
    $ui.StepperHost.Children.Clear()
    $script:StepRows = @{}
    $inMode = @{}
    foreach ($e in $Plan) { $inMode[$e.StepId] = $e }
    $seen = @{}
    foreach ($step in @((Get-GuiCatalog).Steps)) {
        $id = [string]$step.Id
        if ($seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $e = [pscustomobject]@{ StepId = $id; StepTitle = [string]$step.Title }
        $outside = -not $inMode.ContainsKey($id)
        # A row: a status dot, the step number and title, and the state underneath. Rounded, borderless
        # until the step is the one running or waiting, which gets an outline in its state colour.
        $border = New-Object System.Windows.Controls.Border
        $border.Padding = New-Object System.Windows.Thickness(10, 7, 10, 7)
        $border.Margin = New-Object System.Windows.Thickness(0, 0, 0, 3)
        $border.CornerRadius = New-Object System.Windows.CornerRadius(8)
        $border.BorderThickness = New-Object System.Windows.Thickness(1)
        $border.BorderBrush = [System.Windows.Media.Brushes]::Transparent
        $dock = New-Object System.Windows.Controls.DockPanel
        $dot = New-Object System.Windows.Shapes.Ellipse
        $dot.Width = 9; $dot.Height = 9; $dot.Margin = New-Object System.Windows.Thickness(0, 5, 10, 0); $dot.VerticalAlignment = 'Top'
        [System.Windows.Controls.DockPanel]::SetDock($dot, 'Left')
        $sp = New-Object System.Windows.Controls.StackPanel
        $title = New-Object System.Windows.Controls.TextBlock
        $title.Text = $e.StepId + '  ' + $e.StepTitle
        $title.TextWrapping = 'Wrap'
        $title.FontWeight = 'SemiBold'
        $title.Foreground = Get-Brush 'Foreground'
        $state = New-Object System.Windows.Controls.TextBlock
        $state.TextWrapping = 'Wrap'
        $state.FontSize = 11.5
        $state.Margin = New-Object System.Windows.Thickness(0, 1, 0, 0)
        [void]$sp.Children.Add($title); [void]$sp.Children.Add($state)
        [void]$dock.Children.Add($dot); [void]$dock.Children.Add($sp)
        $border.Child = $dock
        $reason = ''
        if ($outside) {
            $reason = Get-NotInModeReason -ModeName $ModeName -Step $step
            $title.Foreground = Get-Brush 'Subtle'; $title.FontWeight = 'Normal'
        }
        [void]$ui.StepperHost.Children.Add($border)
        $script:StepRows[$e.StepId] = [pscustomobject]@{ Border = $border; State = $state; Dot = $dot; OutsideReason = $reason }
    }
}

function Update-Stepper {
    foreach ($id in @($script:StepRows.Keys)) {
        $row = $script:StepRows[$id]
        if ($row.OutsideReason) {
            $row.State.Text = 'skipped in this mode - ' + $row.OutsideReason
            $row.State.Foreground = Get-Brush 'Subtle'
            $row.Border.Background = [System.Windows.Media.Brushes]::Transparent
            $row.Border.BorderBrush = [System.Windows.Media.Brushes]::Transparent
            $row.Dot.Fill = [System.Windows.Media.Brushes]::Transparent
            $row.Dot.Stroke = Get-Brush 'Border'; $row.Dot.StrokeThickness = 1.5
            continue
        }
        $word = 'waiting'; $note = ''; $bg = ''; $fg = 'Muted'; $dotTone = 'BorderStrong'; $active = $false
        $res = $null
        if ($script:Session) { $res = @($script:Session.Results | Where-Object { $_.StepId -eq $id }) | Select-Object -Last 1 }
        if ($script:Action -and $script:Action.StepId -eq $id) {
            $active = $true
            if ($script:Action.Kind -eq 'Ask') { $word = 'waiting for you'; $bg = 'WarningBg'; $fg = 'WarningFg' }
            else { $word = 'running'; $bg = 'InfoBg'; $fg = 'InfoFg' }
        }
        elseif ($res) {
            switch ($res.Status) {
                'Done' { $word = 'done'; $bg = 'SuccessBg'; $fg = 'SuccessFg' }
                'Warn' { $word = 'done with warning'; $bg = 'WarningBg'; $fg = 'WarningFg'; $note = $res.Message }
                'Failed' { $word = 'failed'; $bg = 'DangerBg'; $fg = 'DangerFg'; $note = $res.Message }
                'Skipped' { $word = 'skipped'; $bg = ''; $fg = 'Muted'; $note = $res.Message }
                'Resurrection' { $word = 'RESURRECTION found'; $bg = 'DangerBg'; $fg = 'DangerFg'; $note = $res.Message }
            }
            $dotTone = $(if ($fg -eq 'Muted') { 'Subtle' } else { $fg })
        }
        if ($active) { $dotTone = $fg }
        $row.State.Text = $word + $(if ($note) { ' - ' + $note } else { '' })
        $row.State.Foreground = Get-Brush $fg
        $row.Border.Background = $(if ($bg) { Get-Brush $bg } else { [System.Windows.Media.Brushes]::Transparent })
        $row.Border.BorderBrush = $(if ($active) { Get-Brush $fg } else { [System.Windows.Media.Brushes]::Transparent })
        $row.Dot.Fill = Get-Brush $dotTone
        $row.Dot.Stroke = $null
    }
}

# ---- dialogs -----------------------------------------------------------------------------------
function Test-ButtonNeedsWord {
    # Button specs are hashtables (@{ Text; Value; NeedsWord }); a hashtable's keys are NOT in
    # .PSObject.Properties, so read the key itself. (Reading PSObject.Properties here once left the
    # Remove button enabled without the typed word - see -SelfTest.)
    param($Spec)
    if ($Spec -is [System.Collections.IDictionary]) { return [bool]$Spec['NeedsWord'] }
    $p = $Spec.PSObject.Properties['NeedsWord']
    return ($p -and [bool]$p.Value)
}

function New-DialogWindow {
    # Builds (does not show) one modal dialog in the window's design tokens. See Show-Dialog.
    param(
        [string]$Title, [string]$Message, [string]$Detail = '', $Buttons,
        $Checks = @(), [switch]$TextInput, [string]$TypeWord = ''
    )
    $w = New-Object System.Windows.Window
    $w.Title = $Title; $w.SizeToContent = 'WidthAndHeight'; $w.MaxWidth = 660; $w.ResizeMode = 'NoResize'
    $w.ShowInTaskbar = $false; $w.WindowStartupLocation = 'CenterOwner'
    if ($win.IsLoaded) { $w.Owner = $win }
    # A dialog is its own window and does not see the main window's resources, so it gets a copy of
    # them (tokens already set to the current theme, plus the component styles that use them).
    foreach ($k in @($win.Resources.Keys)) { $w.Resources[$k] = $win.Resources[$k] }
    $w.Background = Get-Brush 'Background'; $w.Foreground = Get-Brush 'Foreground'
    $w.FontFamily = $win.FontFamily; $w.FontSize = $win.FontSize
    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.Margin = New-Object System.Windows.Thickness(22, 18, 22, 18)
    $head = New-Object System.Windows.Controls.TextBlock
    $head.Text = $Title; $head.FontSize = 15; $head.FontWeight = 'SemiBold'; $head.Margin = New-Object System.Windows.Thickness(0, 0, 0, 8)
    $head.Foreground = Get-Brush 'Foreground'
    [void]$sp.Children.Add($head)
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $Message; $tb.TextWrapping = 'Wrap'; $tb.MaxWidth = 610; $tb.Foreground = Get-Brush 'Muted'
    [void]$sp.Children.Add($tb)
    if ($Detail) {
        $d = New-Object System.Windows.Controls.TextBox
        $d.Text = $Detail; $d.IsReadOnly = $true; $d.TextWrapping = 'Wrap'; $d.FontFamily = 'Consolas'; $d.FontSize = 12
        $d.MaxHeight = 200; $d.VerticalScrollBarVisibility = 'Auto'; $d.Margin = New-Object System.Windows.Thickness(0, 12, 0, 0)
        $d.Padding = New-Object System.Windows.Thickness(8, 6, 8, 6)
        $d.Background = Get-Brush 'SurfaceSunken'; $d.Foreground = Get-Brush 'Foreground'; $d.BorderBrush = Get-Brush 'Border'
        [void]$sp.Children.Add($d)
    }
    $tag = @{ Checks = @{}; Text = $null; Word = $TypeWord; Gated = @() }
    foreach ($c in @($Checks)) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = $c.Text; $cb.IsChecked = [bool]$c.Checked; $cb.IsEnabled = $(if ($c.PSObject.Properties['Enabled']) { [bool]$c.Enabled } else { $true })
        $cb.Margin = New-Object System.Windows.Thickness(0, 10, 0, 0); $cb.Foreground = Get-Brush 'Foreground'
        if ($c.PSObject.Properties['DependsOn'] -and $c.DependsOn) { $cb.Tag = [string]$c.DependsOn }
        $tag.Checks[[string]$c.Key] = $cb
        [void]$sp.Children.Add($cb)
    }
    foreach ($cb in @($tag.Checks.Values)) {
        if ($cb.Tag) {
            # a tick box that only makes sense when another is ticked (e.g. the GPO reset needs the repair)
            $parent = $tag.Checks[[string]$cb.Tag]
            $child = $cb
            $apply = { param($s, $e) $child.IsEnabled = [bool]$parent.IsChecked; if (-not $parent.IsChecked) { $child.IsChecked = $false } }.GetNewClosure()
            $parent.add_Checked($apply); $parent.add_Unchecked($apply)
            & $apply $null $null
        }
    }
    if ($TextInput -or $TypeWord) {
        $box = New-Object System.Windows.Controls.TextBox
        $box.Margin = New-Object System.Windows.Thickness(0, 12, 0, 0); $box.FontFamily = 'Consolas'; $box.FontSize = 13
        $box.Padding = New-Object System.Windows.Thickness(8, 6, 8, 6)
        $box.Background = Get-Brush 'Surface'; $box.Foreground = Get-Brush 'Foreground'; $box.BorderBrush = Get-Brush 'BorderStrong'
        $box.CaretBrush = Get-Brush 'Foreground'
        $tag.Text = $box
        [void]$sp.Children.Add($box)
    }
    $wp = New-Object System.Windows.Controls.WrapPanel
    $wp.Margin = New-Object System.Windows.Thickness(0, 18, 0, 0)
    foreach ($b in $Buttons) {
        $btn = New-Object System.Windows.Controls.Button
        $btn.Content = $b.Text; $btn.Tag = $b.Value
        # Neutral buttons everywhere; only the approval that needs the typed word looks like what it does.
        $needs = ($TypeWord -and (Test-ButtonNeedsWord $b))
        Set-ButtonStyle $btn $(if ($needs) { 'Danger' } else { 'Secondary' })
        if ($needs) { $btn.IsEnabled = $false; $tag.Gated += $btn }
        $btn.add_Click({
                param($s, $e)
                $dw = [System.Windows.Window]::GetWindow($s)
                $script:DlgValue = [string]$s.Tag
                $script:DlgChecks = @{}
                foreach ($k in @($dw.Tag.Checks.Keys)) { $script:DlgChecks[$k] = [bool]$dw.Tag.Checks[$k].IsChecked }
                if ($dw.Tag.Text) { $script:DlgText = [string]$dw.Tag.Text.Text }
                $dw.Close()
            })
        [void]$wp.Children.Add($btn)
    }
    if ($TypeWord) {
        $gated = $tag.Gated; $word = $TypeWord; $boxRef = $tag.Text
        $boxRef.add_TextChanged({ param($s, $e) foreach ($g in $gated) { $g.IsEnabled = (([string]$boxRef.Text) -ceq $word) } }.GetNewClosure())
    }
    [void]$sp.Children.Add($wp)
    $w.Tag = $tag
    $w.Content = $sp
    return $w
}

function Show-Dialog {
    # One modal dialog primitive. Returns $null when it was closed with the window X (the caller then
    # sends the engine's REFUSING answer, never yes); otherwise an object with
    #   Value   the Value of the button that was clicked
    #   Checks  the tick boxes as a hashtable
    #   Text    what was typed, when -TextInput or -TypeWord is used
    # -TypeWord: the button marked NeedsWord stays disabled until the box holds exactly that word
    # (case-sensitive), so the approval is the technician's own typing, never a button alone.
    param(
        [string]$Id, [string]$Title, [string]$Message, [string]$Detail = '', $Buttons,
        $Checks = @(), [switch]$TextInput, [string]$TypeWord = ''
    )
    if ($script:TestMode) {
        $t = Get-TestAnswer $Id
        if ($null -eq $t) { return $null }
        if ($TypeWord -and ([string]$t.Text) -cne $TypeWord) { return $null }
        # (PowerShell variables are case-insensitive: do not name this $checks, it would overwrite the -Checks parameter.)
        $ticked = @{}
        foreach ($c in @($Checks)) { $ticked[$c.Key] = [bool]$c.Checked }
        if ($t.PSObject.Properties['Checks']) { foreach ($p in $t.Checks.PSObject.Properties) { $ticked[$p.Name] = [bool]$p.Value } }
        return [pscustomobject]@{ Value = [string]$t.Value; Checks = $ticked; Text = $(if ($t.PSObject.Properties['Text']) { [string]$t.Text } else { '' }) }
    }
    $script:DlgValue = $null; $script:DlgChecks = @{}; $script:DlgText = $null
    $w = New-DialogWindow -Title $Title -Message $Message -Detail $Detail -Buttons $Buttons -Checks $Checks -TextInput:$TextInput -TypeWord $TypeWord
    $script:InDialog = $true
    try { [void]$w.ShowDialog() } finally { $script:InDialog = $false }
    if ($null -eq $script:DlgValue) { return $null }
    return [pscustomobject]@{ Value = $script:DlgValue; Checks = $script:DlgChecks; Text = $script:DlgText }
}

function Get-RecentConsole {
    param([int]$Count = 6)
    $lines = @($ui.ConsoleBox.Text -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
    $take = [Math]::Min($Count, $lines.Count)
    if ($take -eq 0) { return '' }
    return (($lines[($lines.Count - $take)..($lines.Count - 1)]) -join "`r`n")
}

function Get-RemovalPlanText {
    # The exact instances the confirmation covers: what the findings say, minus what the technician marked KEEP.
    $view = Get-GuiFindingsView -Path $script:Session.FindingsJson
    $keep = @($script:Session.Answers['KeepIdentifiers'] | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $lines = @()
    foreach ($i in $view.Instances) {
        $tag = $(if ($keep -contains $i.Identifier.ToLowerInvariant()) { 'KEEP   ' } else { 'REMOVE ' })
        $lines += ($tag + $(if ($i.Relay) { $i.Relay } else { '(no relay host)' }) + '   ' + $i.Identifier)
    }
    return ($lines -join "`r`n")
}

function Resolve-Prompt {
    # Shows the dialog that names what is being asked and sends the technician's own answer.
    param($Pending)
    $child = $script:Child
    if ($Pending.Kind -eq 'Unknown') {
        $r = Show-Dialog -Id 'Unknown' -Title 'The tool is waiting for an answer' -Message ('The tool is waiting for an answer:' + "`r`n`r`n" + 'Type an answer and Send, or close this box to send an empty line (the tool''s own default). Choose "This is not a question" only if the tool is still working; this box comes back after a minute if it is still waiting.') -Detail $Pending.Text -TextInput -Buttons @(
            @{ Text = 'Send'; Value = 'send' }, @{ Text = 'This is not a question'; Value = 'skip' })
        if ($r -and $r.Value -eq 'skip') { Set-GuiPromptDismissed -Child $child -Text $Pending.Text; Add-ConsoleNote 'Marked as not a question; the tool keeps running.' }
        elseif ($r -and $r.Value -eq 'send') { Send-GuiAnswer -Child $child -Text $r.Text; Add-ConsoleNote 'Answer sent to the tool.' }
        else {
            # Window X: send the script's own default, an empty line (design 4.3 rule 2). Never a yes.
            Send-GuiAnswer -Child $child -Text ''
            Add-ConsoleNote 'Box closed: sent an empty line, the tool''s own default.'
        }
        return
    }
    $row = $Pending.Row
    $send = $row.Refuse
    switch ($row.Id) {
        'LowDisk' {
            $r = Show-Dialog -Id 'LowDisk' -Title 'Low disk space' -Message 'This PC is low on free disk space. The cleanup stores its evidence and quarantined files in the run folder. Continue anyway?' -Detail (Get-RecentConsole 5) -Buttons @(
                @{ Text = 'Continue anyway'; Value = $row.Accept }, @{ Text = 'Stop'; Value = $row.Refuse })
            if ($r) { $send = $r.Value }
        }
        'UacDisabled' {
            $r = Show-Dialog -Id 'UacDisabled' -Title 'UAC is disabled' -Message 'User Account Control is DISABLED on this PC. That is itself a security finding, and the scanners will likely fail to launch until it is enabled. Enable it (a restart is needed), or continue anyway.' -Detail (Get-RecentConsole 8) -Buttons @(
                @{ Text = 'UAC is now enabled'; Value = $row.Accept }, @{ Text = 'Force continue with UAC disabled'; Value = $row.Force }, @{ Text = 'Stop'; Value = $row.Refuse })
            if ($r) { $send = $r.Value }
        }
        'RemoveConfirm' {
            $r = Show-Dialog -Id 'RemoveConfirm' -Title 'Confirm removal' -TypeWord 'REMOVE' `
                -Message ('ScreenConnect will be removed from this PC for the instances marked REMOVE below. Files are quarantined, never deleted. Instances marked KEEP are not touched.' + "`r`n`r`nType REMOVE to confirm.") `
                -Detail (Get-RemovalPlanText) -Buttons @(@{ Text = 'Remove'; Value = 'ok'; NeedsWord = $true }, @{ Text = 'Do not remove'; Value = 'cancel' })
            if ($r -and $r.Value -eq 'ok') { $send = $row.Accept; $script:CloseLock = $true }
        }
        'MbInstallDone' {
            $r = Show-Dialog -Id 'MbInstallDone' -Title 'Malwarebytes installation' -Message 'Finish the Malwarebytes installation in its own window. This step will not continue automatically. When the installation is finished, click the button below.' -Buttons @(
                @{ Text = 'Installation finished'; Value = $row.Accept }, @{ Text = 'Cancel this scanner'; Value = $row.Refuse })
            if ($r) { $send = $r.Value }
        }
        'MbScanDone' {
            $r = Show-Dialog -Id 'MbScanDone' -Title 'Malwarebytes scan' -Message 'Finish the scan and any requested cleanup in Malwarebytes, then close its window. When that is done, click the button below.' -Buttons @(
                @{ Text = 'Scan finished and window closed'; Value = $row.Accept }, @{ Text = 'Cancel this scanner'; Value = $row.Refuse })
            if ($r) { $send = $r.Value }
        }
        'PersistIndices' {
            $r = Show-Dialog -Id 'PersistIndices' -Title 'Persistence cleanup - choose candidates' -TextInput `
                -Message 'The persistence review found the candidates listed below (heuristic matches, not malware verdicts). Type the numbers of the ones to remove, separated by commas, or choose Remove nothing.' `
                -Detail (Get-RecentConsole 30) -Buttons @(@{ Text = 'Continue'; Value = 'send' }, @{ Text = 'Remove nothing'; Value = 'skip' })
            if ($r -and $r.Value -eq 'send') { $send = $r.Text }
        }
        'PersistRemove' {
            $r = Show-Dialog -Id 'PersistRemove' -Title 'Confirm persistence cleanup' -TypeWord 'REMOVE' `
                -Message ('These exact persistence entries will be backed up and removed. Type REMOVE to confirm.') `
                -Detail (Get-RecentConsole 20) -Buttons @(@{ Text = 'Remove'; Value = 'ok'; NeedsWord = $true }, @{ Text = 'Do not remove'; Value = 'cancel' })
            if ($r -and $r.Value -eq 'ok') { $send = $r.Text; $script:CloseLock = $true }
        }
        default {
            Add-ConsoleNote ('This window has no dialog for the "' + $row.Id + '" question; refusing it.')
        }
    }
    Send-GuiAnswer -Child $child -Text $send
}

# ---- panels and findings -----------------------------------------------------------------------
function Show-Banner {
    param([string]$Text, [string]$Kind = 'info')
    $bg = 'SurfaceSunken'; $bd = 'Border'
    if ($Kind -eq 'ok') { $bg = 'SuccessBg'; $bd = 'SuccessBorder' }
    if ($Kind -eq 'warn') { $bg = 'WarningBg'; $bd = 'WarningBorder' }
    if ($Kind -eq 'bad') { $bg = 'DangerBg'; $bd = 'DangerBorder' }
    $fg = 'Foreground'
    if ($Kind -eq 'ok') { $fg = 'SuccessFg' }
    if ($Kind -eq 'warn') { $fg = 'WarningFg' }
    if ($Kind -eq 'bad') { $fg = 'DangerFg' }
    $ui.Banner.Background = Get-Brush $bg
    $ui.Banner.BorderBrush = Get-Brush $bd
    $ui.BannerText.Foreground = Get-Brush $fg
    $ui.BannerText.FontWeight = 'SemiBold'
    $ui.BannerText.Text = $Text
    $ui.Banner.Visibility = 'Visible'
}

function Add-Fact {
    param($Panel, [string]$Label, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.TextWrapping = 'Wrap'
    $tb.Margin = New-Object System.Windows.Thickness(0, 1, 0, 1)
    $r1 = New-Object System.Windows.Documents.Run ($Label + ': '); $r1.FontWeight = 'SemiBold'; $r1.Foreground = Get-Brush 'Muted'
    $r2 = New-Object System.Windows.Documents.Run $Value
    [void]$tb.Inlines.Add($r1); [void]$tb.Inlines.Add($r2)
    [void]$Panel.Children.Add($tb)
}

function New-InstanceCard {
    # Neutral on purpose: this window never colours, ranks or labels a relay host as safe, known
    # or suspicious (design decision D4). The technician decides. With -Choose the card gets a
    # Remove / Keep pair (Remove is the default); the pair is recorded in $script:KeepRows.
    param($Inst, [int]$Total, [switch]$Choose)
    $b = New-Object System.Windows.Controls.Border
    $b.Style = $win.FindResource('Card')
    $b.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
    $sp = New-Object System.Windows.Controls.StackPanel
    $lbl = New-Object System.Windows.Controls.TextBlock
    $lbl.Text = 'INSTANCE ' + $Inst.Number + ' OF ' + $Total + ' - RELAY HOST AND PORT'; $lbl.Style = $win.FindResource('Text.Overline')
    [void]$sp.Children.Add($lbl)
    $relay = New-Object System.Windows.Controls.TextBox
    $relay.IsReadOnly = $true; $relay.BorderThickness = New-Object System.Windows.Thickness(0); $relay.Background = [System.Windows.Media.Brushes]::Transparent
    $relay.FontSize = 24; $relay.FontWeight = 'SemiBold'; $relay.TextWrapping = 'Wrap'; $relay.Padding = New-Object System.Windows.Thickness(0)
    $relay.Foreground = Get-Brush 'Foreground'; $relay.Margin = New-Object System.Windows.Thickness(-2, 2, 0, 6)
    $relay.Text = $(if ($Inst.Relay) { $Inst.Relay } else { '(no relay host recorded)' })
    [void]$sp.Children.Add($relay)
    Add-Fact $sp 'Identifier' $Inst.Identifier
    Add-Fact $sp 'Session type' $Inst.SessionType
    Add-Fact $sp 'Service' ($Inst.ServiceName + $(if ($Inst.ServiceState) { ' (' + $Inst.ServiceState + ')' } else { '' }))
    Add-Fact $sp 'Signature' ($Inst.SignatureStatus + $(if ($Inst.SignerSubject) { ' - ' + $Inst.SignerSubject } else { '' }))
    Add-Fact $sp 'Installed (folder created, UTC)' $Inst.InstalledUtc
    Add-Fact $sp 'Install directory' $Inst.InstallDir
    if ($Choose) {
        $pair = New-Object System.Windows.Controls.StackPanel
        $pair.Orientation = 'Horizontal'; $pair.Margin = New-Object System.Windows.Thickness(0, 8, 0, 0)
        $rm = New-Object System.Windows.Controls.RadioButton
        $rm.Content = 'Remove (quarantine, never delete)'; $rm.IsChecked = $true; $rm.GroupName = ('inst' + $Inst.Number); $rm.Margin = New-Object System.Windows.Thickness(0, 0, 18, 0)
        $kp = New-Object System.Windows.Controls.RadioButton
        $kp.Content = 'Keep (this one is legitimate)'; $kp.GroupName = ('inst' + $Inst.Number)
        if (-not $Inst.KeepSelectable) {
            $kp.IsEnabled = $false
            $note = New-Object System.Windows.Controls.TextBlock
            $note.Text = '  Cannot be kept one at a time: its identifier is missing, repeated or contains a comma.'; $note.Foreground = Get-Brush 'WarningFg'; $note.FontSize = 12
        }
        $rm.add_Checked({ Update-ReviewSummary }); $kp.add_Checked({ Update-ReviewSummary })
        [void]$pair.Children.Add($rm); [void]$pair.Children.Add($kp)
        if (-not $Inst.KeepSelectable) { [void]$pair.Children.Add($note) }
        [void]$sp.Children.Add($pair)
        $script:KeepRows += [pscustomobject]@{ Inst = $Inst; Remove = $rm; Keep = $kp }
    }
    $b.Child = $sp
    return $b
}

function Show-Findings {
    param([switch]$Choose)
    $ui.CardsHost.Children.Clear()
    $script:KeepRows = @()
    $path = $script:Session.FindingsJson
    $view = Get-GuiFindingsView -Path $path
    if (-not $view.Available) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = 'Findings are not available (' + $view.Error + ').'; $tb.TextWrapping = 'Wrap'
        [void]$ui.CardsHost.Children.Add($tb)
        return $view
    }
    $head = New-Object System.Windows.Controls.TextBlock
    $head.FontSize = 15; $head.FontWeight = 'SemiBold'; $head.Margin = New-Object System.Windows.Thickness(0, 0, 0, 8)
    $n = @($view.Instances).Count
    $head.Text = $(if ($n -eq 0) { 'No ScreenConnect instance was found.' } else { 'ScreenConnect instances found: ' + $n })
    [void]$ui.CardsHost.Children.Add($head)
    if ($Choose -and $n -gt 0) {
        $hint = New-Object System.Windows.Controls.TextBlock
        $hint.TextWrapping = 'Wrap'; $hint.Margin = New-Object System.Windows.Thickness(0, 0, 0, 8); $hint.Foreground = Get-Brush 'Muted'
        $hint.Text = 'Check the relay host and the signature of each one. Every instance is set to Remove unless you mark it Keep. Nothing is removed until you confirm on the next screen.'
        [void]$ui.CardsHost.Children.Add($hint)
    }
    foreach ($inst in $view.Instances) { [void]$ui.CardsHost.Children.Add((New-InstanceCard -Inst $inst -Total $n -Choose:$Choose)) }
    if ($view.ParseIssueCount -gt 0) {
        $pi = New-Object System.Windows.Controls.TextBlock
        $pi.Text = 'Parse problems: ' + $view.ParseIssueCount + ' (see the report).'; $pi.Foreground = Get-Brush 'DangerFg'; $pi.Margin = New-Object System.Windows.Thickness(0, 0, 0, 8)
        [void]$ui.CardsHost.Children.Add($pi)
    }
    if (@($view.OtherTargets).Count -gt 0) {
        $oh = New-Object System.Windows.Controls.TextBlock
        $oh.Text = 'Other remote-access products (reported only - this tool never removes these)'; $oh.FontWeight = 'SemiBold'; $oh.Margin = New-Object System.Windows.Thickness(0, 6, 0, 4)
        [void]$ui.CardsHost.Children.Add($oh)
        foreach ($o in $view.OtherTargets) {
            $t = New-Object System.Windows.Controls.TextBlock
            $t.TextWrapping = 'Wrap'; $t.Margin = New-Object System.Windows.Thickness(0, 0, 0, 3)
            $t.Text = $o.Name + ' (' + $o.Count + ')'
            [void]$ui.CardsHost.Children.Add($t)
        }
    }
    return $view
}

function Update-ReviewSummary {
    if (-not $script:KeepRows -or @($script:KeepRows).Count -eq 0) { return }
    $keep = @($script:KeepRows | Where-Object { $_.Keep.IsChecked }).Count
    $rem = @($script:KeepRows).Count - $keep
    $ui.ReviewSummary.Text = 'Remove ' + $rem + ', keep ' + $keep + '.' + $(if ($rem -eq 0) { ' Nothing will be removed.' } else { ' You will be asked to confirm before anything is removed.' })
    $ui.BtnReviewContinue.Content = $(if ($rem -eq 0) { 'Continue (remove nothing)' } else { 'Continue to removal' })
}

function Show-Panel {
    param([string]$Which)
    $ui.StartPanel.Visibility = $(if ($Which -eq 'Start') { 'Visible' } else { 'Collapsed' })
    $ui.RunPanel.Visibility = $(if ($Which -eq 'Run') { 'Visible' } else { 'Collapsed' })
}

function Update-HeaderButtons {
    # The folder that holds every run (C:\RIT-SCC). The window never creates it; a run does.
    $ritExists = Test-Path -LiteralPath $RitRoot -PathType Container
    $ui.BtnOpenRitRoot.IsEnabled = [bool]$ritExists
    $ui.BtnOpenRitRoot.ToolTip = $(if ($ritExists) { 'Every run''s folder lives here: ' + $RitRoot } else { $RitRoot + ' does not exist yet - it is created by the first run on this PC' })
    $has = ($script:Session -and $script:Session.RunRoot -and (Test-Path -LiteralPath $script:Session.RunRoot))
    $ui.BtnOpenRunHeader.IsEnabled = [bool]$has
    $ui.BtnOpenRun.IsEnabled = [bool]$has
    $ui.BtnOpenLog.IsEnabled = [bool]($script:LogPath -and (Test-Path -LiteralPath $script:LogPath))
    $rep = $false
    if ($has) { $rep = (Get-GuiReportInfo -RunRoot $script:Session.RunRoot).ReportExists }
    $ui.BtnOpenReport.IsEnabled = [bool]$rep
}

# ---- asking the technician (the questions the batch file asks) ------------------------------------
function Resolve-Ask {
    # Returns $true when the answer is already in (the run can go on) and $false when the window now
    # waits for the technician (the keep/remove screen).
    param($A)
    $sess = $script:Session
    switch ($A.Ask) {
        'KeepSelection' {
            $view = Get-GuiFindingsView -Path $sess.FindingsJson
            if (-not $view.Available -or @($view.Instances).Count -eq 0) {
                Set-GuiAnswer -Session $sess -Ask 'KeepSelection' -Values @{ KeepIdentifiers = @() }
                return $true
            }
            [void](Show-Findings -Choose)
            $ui.StatusTitle.Text = 'Step ' + $A.StepId + ': ' + $A.Title + ' - choose what to keep'
            $ui.StatusDetail.Text = 'Nothing has been removed. The run waits here for you.'
            $ui.Busy.IsIndeterminate = $false
            $ui.ReviewBar.Visibility = 'Visible'
            Update-ReviewSummary
            if ($script:TestMode) {
                $t = Get-TestAnswer 'KeepSelection'
                if ($t) { foreach ($id in @($t.Keep)) { foreach ($r in $script:KeepRows) { if ($r.Inst.Identifier -ieq [string]$id -and $r.Inst.KeepSelectable) { $r.Keep.IsChecked = $true } } } }
                Complete-Review
                return $true
            }
            return $false
        }
        'Scanners' {
            $avDir = Join-Path $sess.ToolRoot 'tools\AV'
            $kv = Test-Path -LiteralPath (Join-Path $avDir 'KVRT.exe'); $es = Test-Path -LiteralPath (Join-Path $avDir 'esetonlinescanner.exe')
            $r = Show-Dialog -Id 'Scanners' -Title 'Antivirus scans' -Message 'Each scanner opens in its own window. Complete it, then return here. Choose the scans to run.' -Checks @(
                [pscustomobject]@{ Key = 'ScanKvrt'; Text = 'KVRT' + $(if ($kv) { '' } else { '  (not staged - run the Online or Stage step first)' }); Checked = $kv; Enabled = $kv },
                [pscustomobject]@{ Key = 'ScanEset'; Text = 'ESET Online Scanner' + $(if ($es) { '' } else { '  (not staged - run the Online or Stage step first)' }); Checked = $es; Enabled = $es },
                [pscustomobject]@{ Key = 'ScanMalwarebytes'; Text = 'Malwarebytes (installed through winget, then the official offline installer)'; Checked = $true; Enabled = $true }) `
                -Buttons @(@{ Text = 'Start the selected scans'; Value = 'go' }, @{ Text = 'Skip all scans'; Value = 'skip' })
            $vals = @{ ScanKvrt = $false; ScanEset = $false; ScanMalwarebytes = $false }
            if ($r -and $r.Value -eq 'go') { foreach ($k in @($vals.Keys)) { $vals[$k] = [bool]$r.Checks[$k] } }
            Set-GuiAnswer -Session $sess -Ask 'Scanners' -Values $vals
            return $true
        }
        'OpenReview' {
            $r = Show-Dialog -Id 'OpenReview' -Title 'Persistence review windows' -Message 'Open the evidence and startup folders, Services and Task Scheduler so you can inspect what the persistence scan flagged? Nothing is changed by opening them.' -Buttons @(
                @{ Text = 'Open the review windows'; Value = 'y' }, @{ Text = 'Skip'; Value = 'n' })
            Set-GuiAnswer -Session $sess -Ask 'OpenReview' -Values @{ OpenReview = [bool]($r -and $r.Value -eq 'y') }
            return $true
        }
        'AvUninstall' {
            $r = Show-Dialog -Id 'AvUninstall' -Title 'Uninstall third-party antivirus' -Message 'Malwarebytes uses winget; other antivirus uninstallers open for you to drive. Nothing is uninstalled silently. Defender is excluded. Run the installed-AV uninstall now?' -Buttons @(
                @{ Text = 'Run the AV uninstall'; Value = 'y' }, @{ Text = 'Skip'; Value = 'n' })
            Set-GuiAnswer -Session $sess -Ask 'AvUninstall' -Values @{ Avu = [bool]($r -and $r.Value -eq 'y') }
            return $true
        }
        'PowerRepair' {
            $r = Show-Dialog -Id 'PowerRepair' -Title 'Power-options repair (optional)' -Message 'The repair is opt-in. Managed devices may need administrator approval.' -Checks @(
                [pscustomobject]@{ Key = 'PowerRepair'; Text = 'Repair missing power options now'; Checked = $false },
                [pscustomobject]@{ Key = 'ResetGpo'; Text = 'Back up, then reset local Group Policy folders'; Checked = $false; Enabled = $false; DependsOn = 'PowerRepair' }) `
                -Buttons @(@{ Text = 'Continue'; Value = 'go' })
            $on = [bool]($r -and $r.Value -eq 'go' -and $r.Checks['PowerRepair'])
            Set-GuiAnswer -Session $sess -Ask 'PowerRepair' -Values @{ PowerRepair = $on; ResetGpo = [bool]($on -and $r.Checks['ResetGpo']) }
            return $true
        }
        default { throw ('Unknown ask: ' + $A.Ask) }
    }
}

function Complete-Review {
    # The technician pressed Continue on the keep/remove screen (or the test hook did the same).
    $kept = @($script:KeepRows | Where-Object { $_.Keep.IsChecked -and $_.Inst.KeepSelectable } | ForEach-Object { $_.Inst.Identifier })
    Set-GuiAnswer -Session $script:Session -Ask 'KeepSelection' -Values @{ KeepIdentifiers = $kept }
    Add-ConsoleNote ('Keep selection: keep ' + $kept.Count + ', remove ' + (@($script:KeepRows).Count - $kept.Count) + '.')
    $ui.ReviewBar.Visibility = 'Collapsed'
    $script:Action = $null
    Update-Stepper
    if (-not $script:TestMode) { Move-Next }
}

# ---- run control -------------------------------------------------------------------------------
function Get-SelectedMode {
    if ($ui.RbOnline.IsChecked) { return 'Online' }
    if ($ui.RbDetect.IsChecked) { return 'Detect' }
    if ($ui.RbStage.IsChecked) { return 'Stage' }
    return 'Offline'
}

function Set-PreviewMode {
    param([string]$ModeName)
    $tmp = New-GuiSession -Mode $ModeName -ToolRoot $ToolRoot -RitRoot $RitRoot
    Initialize-Stepper $tmp.Plan $ModeName
    $ui.InfoText.Text = 'PC: ' + $env:COMPUTERNAME + '     Mode: ' + $script:ModeLabels[$ModeName]
    Update-Stepper
}

function Start-Run {
    param([string]$ModeName)
    $script:Finished = $false
    $sess = New-GuiSession -Mode $ModeName -ToolRoot $ToolRoot -RitRoot $RitRoot -Interactive
    $prior = $null
    if ($ModeName -eq 'Online') {
        $prior = Find-GuiPriorRun -Session $sess
        if ($prior) {
            $r = Show-Dialog -Id 'ContinuePrior' -Title 'Continue the offline run?' -Message ('A finished offline-half run was found for this PC:' + "`r`n" + $prior.RunRoot + "`r`n`r`nContinue that run? Its report is shared at the end. Otherwise a scanner-only run starts and nothing is shared.") -Buttons @(
                @{ Text = 'Continue that run'; Value = 'continue' }, @{ Text = 'Start a scanner-only run'; Value = 'new' })
            if ($r -and $r.Value -eq 'new') { $prior = $null }
        }
    }
    try {
        $run = Initialize-GuiRunRoot -Session $sess -Prior $prior
    } catch {
        # The offline half's run folder is created locked; when that fails nothing runs (fail closed).
        $msg = $_.Exception.Message
        Add-ConsoleNote ('No run started: ' + $msg)
        if (-not $script:TestMode) { [void][System.Windows.MessageBox]::Show(('No run was started.' + "`n`n" + $msg), 'ScreenConnect Cleanup', 'OK', 'Error') }
        if ($script:AutoStart) { $win.Close() }
        return
    }
    $script:Session = $sess
    Initialize-Stepper $sess.Plan $ModeName
    $script:LogPath = ''
    if ($run) {
        $logs = Join-Path $run 'logs'
        if (-not (Test-Path -LiteralPath $logs)) { $null = New-Item -ItemType Directory -Path $logs -Force }
        $script:LogPath = Join-Path $logs 'gui-console.log'
    }
    $ui.ConsoleBox.Clear()
    $ui.CardsHost.Children.Clear()
    $ui.Banner.Visibility = 'Collapsed'
    $ui.ReviewBar.Visibility = 'Collapsed'
    $ui.BtnNewRun.Visibility = 'Collapsed'
    $ui.BtnRestart.Visibility = 'Collapsed'
    $ui.InfoText.Text = 'PC: ' + $env:COMPUTERNAME + '     Mode: ' + $script:ModeLabels[$ModeName]
    $ui.RunText.Text = $(if ($run) { 'Run folder: ' + $run } else { 'Run folder: none (this mode creates none)' })
    Show-Panel 'Run'
    Add-ConsoleNote ($script:ModeLabels[$ModeName] + $(if ($run) { '. Run folder: ' + $run } else { '' }))
    if ($sess.ScannerOnly) { Add-ConsoleNote 'No offline-half run is being continued: this is a scanner-only run. There is no report to share from it.' }
    Save-Session
    Update-Stepper
    Update-HeaderButtons
    Move-Next
}

function Move-Next {
    # Starts the next call, or asks the next question, or finishes. Runs only on the UI thread and
    # only when no child is alive.
    while ($true) {
        $a = Get-GuiNextAction -Session $script:Session
        if (-not $a) { Complete-Run; return }
        $script:Action = $a
        if ($a.Kind -eq 'Ask') {
            Update-Stepper
            if (Resolve-Ask $a) { $script:Action = $null; continue }
            return
        }
        if ($a.Kind -eq 'Builtin') {
            Add-ConsoleNote ('Step ' + $a.StepId + ': ' + $a.Title)
            # Test mode (-ResultPath): open nothing and copy to a folder beside the result file, never the real Desktop.
            if ($ResultPath) { $rc = Invoke-GuiBuiltin -Session $script:Session -Action $a -NoOpen -DesktopDir (Split-Path -Parent $ResultPath) }
            else { $rc = Invoke-GuiBuiltin -Session $script:Session -Action $a }
            $o = Complete-GuiAction -Session $script:Session -Action $a -ExitCode $rc
            $script:Action = $null
            Add-ConsoleNote ('Step ' + $o.StepId + ' ' + $o.Status + $(if ($o.Message) { ': ' + $o.Message } else { '' }))
            Update-Stepper
            continue
        }
        $ui.StatusTitle.Text = 'Step ' + $a.StepId + ': ' + $a.Title
        $ui.StatusDetail.Text = ''
        $ui.Busy.IsIndeterminate = $true
        # Steps marked Destructive in gui\steps.json (5 removal, 7 AV uninstall, 8a power repair) cannot be
        # closed while they run (design 7); persistence cleanup locks once REMOVE has been typed.
        $script:CloseLock = [bool]$a.Destructive
        Add-ConsoleLines @('', ('=== Step ' + $a.StepId + ': ' + $a.Title + ' ==='), ('> ' + [IO.Path]::GetFileName($a.ScriptPath) + ' ' + (ConvertTo-GuiArgString $a.Args)))
        try {
            $script:Child = Start-GuiChild -ScriptPath $a.ScriptPath -ArgumentList $a.Args -WorkingDirectory $script:Session.ToolRoot
        } catch {
            Add-ConsoleNote ('Could not start ' + $a.ScriptPath + ': ' + $_.Exception.Message)
            [void](Complete-GuiAction -Session $script:Session -Action $a -ExitCode 1 -Message $_.Exception.Message)
            $script:Action = $null
            continue
        }
        Update-Stepper
        return
    }
}

function Complete-Run {
    $script:Action = $null
    $script:Child = $null
    $script:CloseLock = $false
    $script:Finished = $true
    $sess = $script:Session
    $ui.Busy.IsIndeterminate = $false
    $ui.Busy.Value = 1
    $ui.StatusTitle.Text = $(if ($sess.Stopped) { 'Stopped' } else { 'Finished' })
    $ui.StatusDetail.Text = ''
    Save-Session
    if ($sess.FindingsJson) { [void](Show-Findings) }
    Show-RunSummary $sess
    $resur = @($sess.Results | Where-Object { $_.Status -eq 'Resurrection' }).Count
    $warns = @($sess.Results | Where-Object { $_.Status -eq 'Warn' -or $_.Status -eq 'Failed' }).Count
    $n = 0
    if ($sess.FindingsJson) { $n = @((Get-GuiFindingsView -Path $sess.FindingsJson).Instances).Count }
    $tail = ''
    if ($sess.Mode -eq 'Detect') { $tail = ' To remove ScreenConnect, start over and choose the Offline half.' }
    elseif ($sess.Mode -eq 'Offline') { $tail = ' Nothing was downloaded or uploaded. When this PC is online, start the Online half to run the scanners and share the report.' }
    if ($sess.Stopped) {
        Show-Banner ($sess.StopMessage + ' See the console output below and the log.') 'bad'
    } elseif ($resur -gt 0) {
        Show-Banner ('RESURRECTION DETECTED: items that were removed came back. See snapshot_diff.json in the run folder.' + $tail) 'bad'
    } elseif ((Get-GuiFinalStatus $sess) -ne 0 -or $warns -gt 0) {
        Show-Banner ('Finished with warnings (' + $warns + ' step(s) marked; first non-zero code ' + (Get-GuiFinalStatus $sess) + '). Review the steps marked with a warning.' + $tail) 'warn'
    } elseif ($sess.Mode -eq 'Stage') {
        Show-Banner 'Staging finished. Copy this whole folder to the client PC, then run the Offline half there.' 'ok'
    } else {
        Show-Banner ('Finished. ' + $n + ' ScreenConnect instance(s) were found on this PC.' + $(if ($sess.Mode -eq 'Detect') { ' Nothing was changed.' } else { '' }) + $tail) 'ok'
    }
    $ui.BtnNewRun.Visibility = 'Visible'
    # The restart offer appears under the batch file's three conditions only.
    if ($sess.PowerRepairRan -and $sess.ReportRc -eq 0 -and $sess.ReportOpened -and -not $sess.Stopped) { $ui.BtnRestart.Visibility = 'Visible' }
    Update-Stepper
    Update-HeaderButtons
    if ($ResultPath) { Write-ResultFile }
    if ($ResultPath -and $RenderPng) {
        # Test hook: render THIS window's own visual tree to a PNG (never a screen capture).
        try {
            $win.UpdateLayout()
            $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap ([int]$win.ActualWidth), ([int]$win.ActualHeight), 96, 96, ([System.Windows.Media.PixelFormats]::Pbgra32)
            $rtb.Render($win)
            $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
            $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))
            $fs = [IO.File]::Create($RenderPng); $enc.Save($fs); $fs.Close()
        } catch { }
    }
    if ($script:AutoStart) {
        if ($HoldSeconds -gt 0) {
            # Test hook: keep the finished window up long enough to look at.
            $script:HoldTimer = New-Object System.Windows.Threading.DispatcherTimer
            $script:HoldTimer.Interval = [TimeSpan]::FromSeconds($HoldSeconds)
            $script:HoldTimer.add_Tick({ $script:HoldTimer.Stop(); $win.Close() })
            $script:HoldTimer.Start()
        } else { $win.Close() }
    }
}

function Add-SummaryLine {
    param([string]$Label, [string]$Value, [string]$Tone = 'Foreground', [switch]$Selectable)
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.TextWrapping = 'Wrap'; $tb.Margin = New-Object System.Windows.Thickness(0, 2, 0, 2)
    $r1 = New-Object System.Windows.Documents.Run ($Label + ': '); $r1.FontWeight = 'SemiBold'
    [void]$tb.Inlines.Add($r1)
    if ($Selectable) {
        [void]$ui.CardsHost.Children.Add($tb)
        $box = New-Object System.Windows.Controls.TextBox
        $box.Text = $Value; $box.IsReadOnly = $true; $box.BorderThickness = New-Object System.Windows.Thickness(0); $box.Background = [System.Windows.Media.Brushes]::Transparent
        [void]$ui.CardsHost.Children.Add($box)
        return
    }
    $r2 = New-Object System.Windows.Documents.Run $Value; $r2.Foreground = Get-Brush $Tone
    [void]$tb.Inlines.Add($r2)
    [void]$ui.CardsHost.Children.Add($tb)
}

function Show-RunSummary {
    # What the run's own artifacts say (design 6, panels 6d, 8 and 9). Read-only; nothing here is a verdict.
    param($Sess)
    $res = @{}
    foreach ($r in $Sess.Results) { $res[$r.StepId] = $r }
    $planIds = @($Sess.Plan | ForEach-Object { $_.StepId })
    $head = New-Object System.Windows.Controls.TextBlock
    $head.Text = 'Results'; $head.FontSize = 15; $head.FontWeight = 'SemiBold'; $head.Margin = New-Object System.Windows.Thickness(0, 12, 0, 6)
    [void]$ui.CardsHost.Children.Add($head)

    if ($planIds -contains '6d' -and $Sess.RunRoot) {
        $sub = $(if ($Sess.Phase -eq 'ONLINE') { 'after-scans\persistence' } else { 'persistence' })
        $pv = Get-GuiPersistenceView -RunRoot $Sess.RunRoot -SubDir $sub
        if (-not $pv.Available) { Add-SummaryLine 'Persistence check' ('not available (' + $pv.Error + ')') 'WarningFg' }
        else {
            $st = $pv.Status + $(if ($pv.RunStatus -and $pv.RunStatus -ne $pv.Status) { ', review ' + $pv.RunStatus } else { '' })
            Add-SummaryLine 'Persistence check' ($st + ' - ' + @($pv.Findings).Count + ' finding(s)') $(if ($pv.Status -eq 'Complete') { 'Foreground' } else { 'WarningFg' })
            if (@($pv.Findings).Count -gt 0) {
                $h = New-Object System.Windows.Controls.TextBlock
                $h.Text = 'Heuristic matches, not malware verdicts'; $h.FontStyle = 'Italic'; $h.Foreground = Get-Brush 'Muted'
                [void]$ui.CardsHost.Children.Add($h)
                $grid = New-Object System.Windows.Controls.Grid
                $grid.Margin = New-Object System.Windows.Thickness(0, 4, 0, 6)
                foreach ($w in 120, 2, 1) {
                    $cd = New-Object System.Windows.Controls.ColumnDefinition
                    $cd.Width = $(if ($w -eq 120) { New-Object System.Windows.GridLength 120 } else { New-Object System.Windows.GridLength $w, ([System.Windows.GridUnitType]::Star) })
                    [void]$grid.ColumnDefinitions.Add($cd)
                }
                $rowNo = 0
                foreach ($f in (@('Kind|Target|Reason') + @($pv.Findings | Select-Object -First 50 | ForEach-Object { [string]$_.Kind + '|' + [string]$_.Target + '|' + [string]$_.Reason }))) {
                    [void]$grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
                    $cells = ([string]$f).Split([char]'|', 3)
                    for ($c = 0; $c -lt 3; $c++) {
                        $t = New-Object System.Windows.Controls.TextBlock
                        $t.Text = $(if ($c -lt $cells.Length) { $cells[$c] } else { '' }); $t.TextWrapping = 'Wrap'; $t.Margin = New-Object System.Windows.Thickness(0, 1, 8, 1); $t.FontSize = 12
                        if ($rowNo -eq 0) { $t.FontWeight = 'SemiBold' }
                        [System.Windows.Controls.Grid]::SetRow($t, $rowNo); [System.Windows.Controls.Grid]::SetColumn($t, $c)
                        [void]$grid.Children.Add($t)
                    }
                    $rowNo++
                }
                [void]$ui.CardsHost.Children.Add($grid)
                if (@($pv.Findings).Count -gt 50) { Add-SummaryLine 'More' ((@($pv.Findings).Count - 50).ToString() + ' further finding(s) are in the report') }
            }
        }
    }
    if ($planIds -contains '8c') {
        $d = $res['8c']
        if (-not $d) { Add-SummaryLine 'Before / after diff' 'not run' 'WarningFg' }
        else {
            switch ($d.Status) {
                'Done' { Add-SummaryLine 'Before / after diff' 'Clean - nothing that was removed came back' 'SuccessFg' }
                'Resurrection' { Add-SummaryLine 'Before / after diff' 'RESURRECTION DETECTED - see snapshot_diff.json' 'DangerFg' }
                'Skipped' { Add-SummaryLine 'Before / after diff' ('INCOMPLETE - ' + $d.Message) 'WarningFg' }
                default { Add-SummaryLine 'Before / after diff' ('diff failed - ' + $d.Message) 'DangerFg' }
            }
        }
    }
    foreach ($sid in '9b', '9o') {
        if ($planIds -notcontains $sid) { continue }
        $s = $res[$sid]
        if (-not $s) { Add-SummaryLine 'Report share' 'not reached' 'WarningFg'; continue }
        if ($s.Status -eq 'Skipped') { Add-SummaryLine 'Report share' ('not shared - ' + $s.Message) 'Muted' }
        elseif ($s.Status -ne 'Done') { Add-SummaryLine 'Report share' ('failed - ' + $s.Message + ' The local report is kept.') 'DangerFg' }
        elseif ($script:ShareUrl) { Add-SummaryLine 'Report shared - paste link' $script:ShareUrl -Selectable }
        elseif ($Sess.Phase -eq 'OFFLINE') { Add-SummaryLine 'Report' 'package built on this PC, not uploaded (the Online half shares it)' 'Muted' }
        else { Add-SummaryLine 'Report share' 'done (no paste link was printed)' 'Muted' }
    }
}

function Write-ResultFile {
    # Test hook only (-ResultPath): the final window state, for tests\gui.
    try {
        $steps = [ordered]@{}
        foreach ($id in @($script:StepRows.Keys | Sort-Object)) { $steps[$id] = $script:StepRows[$id].State.Text }
        $doc = [ordered]@{
            Mode = $script:Session.Mode
            Steps = $steps; Banner = $ui.BannerText.Text; BannerVisible = ($ui.Banner.Visibility -eq 'Visible')
            CardChildren = $ui.CardsHost.Children.Count; Stopped = [bool]$script:Session.Stopped; FinalStatus = (Get-GuiFinalStatus $script:Session)
            RunRoot = $script:Session.RunRoot; FindingsJson = $script:Session.FindingsJson
            ConsoleChars = $ui.ConsoleBox.Text.Length; OpenReportEnabled = [bool]$ui.BtnOpenReport.IsEnabled
            RestartVisible = ($ui.BtnRestart.Visibility -eq 'Visible')
            StartPanelVisible = ($ui.StartPanel.Visibility -eq 'Visible'); RunPanelVisible = ($ui.RunPanel.Visibility -eq 'Visible')
            KeepIdentifiers = @($script:Session.Answers['KeepIdentifiers'])
            ShareUrl = $script:ShareUrl
            # A TextBlock built from Runs (bold label + value) reports no .Text, so read its Runs.
            CardTexts = @($ui.CardsHost.Children | ForEach-Object {
                    if ($_ -is [System.Windows.Controls.TextBlock]) { $(if ($_.Inlines.Count -gt 0) { (@($_.Inlines | ForEach-Object { if ($_ -is [System.Windows.Documents.Run]) { $_.Text } }) -join '') } else { $_.Text }) }
                    elseif ($_ -is [System.Windows.Controls.TextBox]) { $_.Text } })
            Results = @($script:Session.Results | ForEach-Object { [ordered]@{ Step = $_.StepId; Status = $_.Status; ExitCode = $_.ExitCode; Message = $_.Message } })
        }
        ($doc | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    } catch { }
}

function Save-Session {
    # gui-session.json is display data; a failed write stops nothing but is said once.
    if (-not (Save-GuiSession $script:Session) -and -not $script:SessionWriteWarned) {
        $script:SessionWriteWarned = $true
        Add-ConsoleNote 'Could not write gui-session.json in the run folder (display data only; the run is not affected).'
    }
}

function Test-StepRetryable {
    param($Action)
    $p = $Action.Call.PSObject.Properties['Retry']
    return ($p -and [bool]$p.Value)
}

function Invoke-Tick {
    if ($script:InDialog -or -not $script:Child) { return }
    $u = Update-GuiChild -Child $script:Child
    if (@($u.Lines).Count -gt 0) {
        Add-ConsoleLines $u.Lines
        if ($script:Action -and ($script:Action.StepId -eq '9b' -or $script:Action.StepId -eq '9o')) {
            $url = Get-GuiShareUrl $u.Lines
            if ($url) { $script:ShareUrl = $url }
        }
    }
    if ($u.Exited) {
        $a = $script:Action
        $script:CloseLock = $false
        # A scanner whose launch failed, and the report share, may be run again (design 6). Nothing is
        # recorded for the failed attempt until the technician decides; the console keeps its output.
        if ([int]$u.ExitCode -ne 0 -and (Test-StepRetryable $a)) {
            $r = Show-Dialog -Id 'Retry' -Title ('Step ' + $a.StepId + ' did not finish cleanly') -Message ('"' + $a.Title + '" ended with exit code ' + $u.ExitCode + '. See the console output for why. Run this step again, or continue with the next one?') -Buttons @(
                @{ Text = 'Run it again'; Value = 'retry' }, @{ Text = 'Continue'; Value = 'continue' })
            if ($r -and $r.Value -eq 'retry') {
                Add-ConsoleNote ('Running step ' + $a.StepId + ' again at the technician''s request.')
                Add-ConsoleLines @('', ('=== Step ' + $a.StepId + ': ' + $a.Title + ' (again) ==='))
                $script:Child = Start-GuiChild -ScriptPath $a.ScriptPath -ArgumentList $a.Args -WorkingDirectory $script:Session.ToolRoot
                $script:CloseLock = [bool]$a.Destructive
                return
            }
        }
        $o = Complete-GuiAction -Session $script:Session -Action $a -ExitCode ([int]$u.ExitCode)
        $script:Child = $null
        $script:Action = $null
        Add-ConsoleNote ('Step ' + $o.StepId + ' ended with exit code ' + $o.ExitCode + ' (' + $o.Status + ')' + $(if ($o.Message) { ': ' + $o.Message } else { '' }))
        Save-Session
        if ($a.StepId -eq '4' -and $script:Session.FindingsJson) { [void](Show-Findings) }
        Update-Stepper
        Update-HeaderButtons
        Move-Next
        return
    }
    $elapsed = (Get-Date).ToUniversalTime() - $script:Child.StartedUtc
    $quiet = (Get-Date).ToUniversalTime() - $script:Child.LastOutputUtc
    $text = 'Running for ' + ('{0:00}:{1:00}' -f [int][Math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds)
    if ($quiet.TotalMinutes -ge 2) { $text += ' - no output for ' + [int][Math]::Floor($quiet.TotalMinutes) + ' minutes (information only; the tool is never stopped automatically)' }
    $ui.StatusDetail.Text = $text
    $pp = Get-GuiPendingPrompt -Child $script:Child
    if ($pp) { Resolve-Prompt $pp }
}

# ---- self-test (no window is shown, nothing runs) -------------------------------------------------
if ($SelfTest) {
    $fails = New-Object System.Collections.ArrayList
    function Test-Gate([string]$Name, $Win2) {
        $buttons = @($Win2.Content.Children[$Win2.Content.Children.Count - 1].Children)
        $approve = $buttons[0]; $other = $buttons[1]; $box = $Win2.Tag.Text
        if ($approve.IsEnabled) { [void]$fails.Add($Name + ': the approve button is enabled before anything is typed') }
        if (-not $other.IsEnabled) { [void]$fails.Add($Name + ': the refusing button is disabled') }
        foreach ($wrong in 'remove', 'REMOVE ', ' REMOVE', 'REMOV', 'Remove') {
            $box.Text = $wrong
            if ($approve.IsEnabled) { [void]$fails.Add($Name + ': "' + $wrong + '" enables the approve button') }
        }
        $box.Text = 'REMOVE'
        if (-not $approve.IsEnabled) { [void]$fails.Add($Name + ': typing exactly REMOVE does not enable the approve button') }
        $box.Text = ''
        if ($approve.IsEnabled) { [void]$fails.Add($Name + ': clearing the box leaves the approve button enabled') }
        if ($approve.Style -ne $win.FindResource('Button.Danger')) { [void]$fails.Add($Name + ': the approve button is not styled as Danger') }
    }
    Test-Gate 'RemoveConfirm' (New-DialogWindow -Title 'Confirm removal' -Message 'x' -Detail 'REMOVE a' -TypeWord 'REMOVE' -Buttons @(@{ Text = 'Remove'; Value = 'ok'; NeedsWord = $true }, @{ Text = 'Do not remove'; Value = 'cancel' }))
    Test-Gate 'PersistRemove' (New-DialogWindow -Title 'Confirm persistence cleanup' -Message 'x' -TypeWord 'REMOVE' -Buttons @(@{ Text = 'Remove'; Value = 'ok'; NeedsWord = $true }, @{ Text = 'Do not remove'; Value = 'cancel' }))
    $plain = New-DialogWindow -Title 'Plain' -Message 'x' -Buttons @(@{ Text = 'Continue'; Value = 'go' })
    if (-not @($plain.Content.Children[$plain.Content.Children.Count - 1].Children)[0].IsEnabled) { [void]$fails.Add('a dialog without a typed word has its button disabled') }
    # Both palettes define the same tokens, and every token the script asks for exists.
    $light = @($win.Resources.Keys | Where-Object { ([string]$_).StartsWith('Brush.') } | ForEach-Object { [string]$_ } | Sort-Object)
    $dark = @($win.Resources['Theme.Dark'].Keys | Where-Object { $_ -is [string] -and $_.StartsWith('Brush.') } | Sort-Object)
    if (($light -join ',') -ne ($dark -join ',')) { [void]$fails.Add('light and dark palettes define different tokens') }
    $src = [IO.File]::ReadAllText($PSCommandPath)
    foreach ($m in [regex]::Matches($src, "Get-Brush '(\w+)'")) { if ($light -notcontains ('Brush.' + $m.Groups[1].Value)) { [void]$fails.Add('unknown token: ' + $m.Groups[1].Value) } }
    if ($RenderPng) {
        # Test hook: draw the removal confirmation (not shown) to a PNG, to look at the dialog design.
        $dw = New-DialogWindow -Title 'Confirm removal' -TypeWord 'REMOVE' `
            -Message ('ScreenConnect will be removed from this PC for the instances marked REMOVE below. Files are quarantined, never deleted. Instances marked KEEP are not touched.' + "`r`n`r`nType REMOVE to confirm.") `
            -Detail ("REMOVE  evil.example.net:8041   aaaa1111aaaa1111`r`nKEEP    support.customer.example:443   bbbb2222bbbb2222") `
            -Buttons @(@{ Text = 'Remove'; Value = 'ok'; NeedsWord = $true }, @{ Text = 'Do not remove'; Value = 'cancel' })
        $dw.Tag.Text.Text = 'REMOV'
        $content = $dw.Content; $dw.Content = $null
        $frame = New-Object System.Windows.Controls.Border
        foreach ($k in @($dw.Resources.Keys)) { $frame.Resources[$k] = $dw.Resources[$k] }
        $frame.Background = Get-Brush 'Background'; $frame.Width = 640; $frame.Child = $content
        $frame.Measure((New-Object System.Windows.Size 640, ([double]::PositiveInfinity)))
        $frame.Arrange((New-Object System.Windows.Rect 0, 0, 640, $frame.DesiredSize.Height)); $frame.UpdateLayout()
        $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap 640, ([int][Math]::Ceiling($frame.ActualHeight)), 96, 96, ([System.Windows.Media.PixelFormats]::Pbgra32)
        $rtb.Render($frame)
        $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder; $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))
        $fs = [IO.File]::Create($RenderPng); $enc.Save($fs); $fs.Close()
    }
    if ($fails.Count -eq 0) { Write-Host ('SELFTEST_OK tokens=' + $light.Count + ' theme=' + $script:ThemeName); exit 0 }
    $fails | ForEach-Object { Write-Host ('SELFTEST_FAIL ' + $_) }
    exit 1
}

# ---- wiring --------------------------------------------------------------------------------------
$ui.TitleText.Text = 'ScreenConnect Cleanup  v' + $script:Version
$ui.RbOffline.Tag = 'Offline'; $ui.RbOnline.Tag = 'Online'; $ui.RbDetect.Tag = 'Detect'; $ui.RbStage.Tag = 'Stage'
foreach ($rb in $ui.RbOffline, $ui.RbOnline, $ui.RbDetect, $ui.RbStage) {
    $rb.add_Checked({ param($s, $e) if (-not $script:Session -or $script:Finished) { Set-PreviewMode ([string]$s.Tag) } })
}
Set-PreviewMode 'Offline'
Update-HeaderButtons

try {
    $prior = @(Get-ChildItem -LiteralPath $RitRoot -Directory -ErrorAction Stop | Where-Object { $_.Name -like ($env:COMPUTERNAME + '-*') } | Sort-Object LastWriteTime -Descending | Select-Object -First 3)
    if ($prior.Count -gt 0) {
        $ui.PriorRunsText.Text = "Earlier runs on this PC (view only, they are never resumed):`r`n" + (($prior | ForEach-Object { '  ' + $_.FullName + '   ' + $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }) -join "`r`n")
    }
} catch { }

$ui.BtnStart.add_Click({ Start-Run (Get-SelectedMode) })
$ui.BtnReviewContinue.add_Click({ Complete-Review })
$ui.BtnNewRun.add_Click({
        $script:Session = $null; $script:Action = $null; $script:Child = $null; $script:LogPath = ''; $script:Finished = $false
        $ui.RunText.Text = 'Run folder: none yet'
        Set-PreviewMode (Get-SelectedMode); Update-HeaderButtons; Show-Panel 'Start'
    })
$ui.BtnRestart.add_Click({
        $ans = [System.Windows.MessageBox]::Show("The report was opened above. Restart closes apps without warning and may lose unsaved work.`n`nCommand: shutdown /r /t 0 /f`n`nRestart now?", 'ScreenConnect Cleanup', 'YesNo', 'Warning')
        if ($ans -eq 'Yes') { Start-Process -FilePath 'cmd.exe' -ArgumentList '/d /c "shutdown /r /t 0 /f"' }
    })
$ui.BtnOpenRitRoot.add_Click({ if (Test-Path -LiteralPath $RitRoot -PathType Container) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $RitRoot + '"') } })
$ui.BtnOpenRunHeader.add_Click({ if ($script:Session -and $script:Session.RunRoot) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $script:Session.RunRoot + '"') } })
$ui.BtnOpenRun.add_Click({ if ($script:Session -and $script:Session.RunRoot) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $script:Session.RunRoot + '"') } })
$ui.BtnOpenReport.add_Click({ if ($script:Session) { $r = (Get-GuiReportInfo -RunRoot $script:Session.RunRoot); if ($r.ReportExists) { Start-Process -FilePath $r.ReportPath } } })
$ui.BtnOpenLog.add_Click({ if ($script:LogPath -and (Test-Path -LiteralPath $script:LogPath)) { Start-Process -FilePath 'notepad.exe' -ArgumentList ('"' + $script:LogPath + '"') } })
$ui.BtnCopy.add_Click({ try { [System.Windows.Clipboard]::SetText($ui.ConsoleBox.Text) } catch { } })

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(250)
$timer.add_Tick({
        try { Invoke-Tick }
        catch {
            $msg = 'GUI error: ' + $_.Exception.Message
            try { Add-ConsoleNote $msg } catch { }
            $errDir = $(if ($script:Session -and $script:Session.RunRoot) { Join-Path $script:Session.RunRoot 'logs' } else { $env:TEMP })
            try { [IO.File]::AppendAllText((Join-Path $errDir 'gui-error.log'), (Get-Date -Format 's') + ' ' + $_.ToString() + "`r`n") } catch { }
        }
    })

$win.add_Closing({
        param($s, $e)
        if ($script:Child -and -not $script:Child.Finished) {
            if ($script:CloseLock) {
                [void][System.Windows.MessageBox]::Show('Removal or an uninstall is in progress. Closing now can leave the PC half cleaned. Wait for this step to finish.', 'ScreenConnect Cleanup', 'OK', 'Warning')
                $e.Cancel = $true
                return
            }
            # A scanner the technician is driving is left open when the window closes (design 7):
            # only the step's own powershell.exe is ended, never the scanner it started.
            $isScanner = ($script:Action -and @('6a', '6b', '6c') -contains $script:Action.StepId)
            if (-not $script:AutoStart) {
                $q = $(if ($isScanner) { 'A scanner is still open. Close this window? The scanner window stays open; finish or close it yourself.' } else { 'A step is still running. Stop it and close? (Nothing has been approved for removal in this step yet.)' })
                $ans = [System.Windows.MessageBox]::Show($q, 'ScreenConnect Cleanup', 'YesNo', 'Question')
                if ($ans -ne 'Yes') { $e.Cancel = $true; return }
            }
            if ($isScanner) { Stop-GuiChild $script:Child -KeepDescendants } else { Stop-GuiChild $script:Child }
        } elseif ($script:Action -and $script:Action.Kind -eq 'Ask' -and -not $script:AutoStart) {
            $ans = [System.Windows.MessageBox]::Show('The run is waiting for your choice. Close the window? Nothing has been changed by this step yet.', 'ScreenConnect Cleanup', 'YesNo', 'Question')
            if ($ans -ne 'Yes') { $e.Cancel = $true }
        }
    })

[System.Windows.Threading.Dispatcher]::CurrentDispatcher.add_UnhandledException({
        param($s, $e)
        try {
            $errDir = $(if ($script:Session -and $script:Session.RunRoot) { Join-Path $script:Session.RunRoot 'logs' } else { $env:TEMP })
            [IO.File]::AppendAllText((Join-Path $errDir 'gui-error.log'), (Get-Date -Format 's') + ' ' + $e.Exception.ToString() + "`r`n")
            [void][System.Windows.MessageBox]::Show(('The window hit an error and will keep running a running step untouched:' + "`n`n" + $e.Exception.Message), 'ScreenConnect Cleanup', 'OK', 'Warning')
        } catch { }
        $e.Handled = $true
    })

$win.add_Loaded({
        $timer.Start()
        if ($script:AutoStart) { Start-Run $startMode }
    })

$exit = 0
try {
    [void]$win.ShowDialog()
} finally {
    $timer.Stop()
    if ($script:Child -and -not $script:Child.Finished) { Stop-GuiChild $script:Child }
    Restore-GuiConsoleEncoding $script:ConsoleSaved
}
# Exit 0 after a normal close (the run's own status is in gui-session.json). A non-zero exit
# means the window itself failed, which makes START-HERE-GUI.bat pause so the error can be read.
exit $exit
