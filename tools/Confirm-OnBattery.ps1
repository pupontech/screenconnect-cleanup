# =====================================================================
# Confirm-OnBattery.ps1 -- require explicit consent for a battery-powered run.
#
# The guided START-HERE.bat invokes this after UAC and before any cleanup work.
# No dialog is shown when Windows reports AC power online or unknown.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param(
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { exit 2 }

$nativeSource = @'
using System;
using System.Runtime.InteropServices;

public static class SccPowerStatusNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

    public static int GetACLineStatus()
    {
        SYSTEM_POWER_STATUS status;
        if (!GetSystemPowerStatus(out status)) { return -1; }
        return (int)status.ACLineStatus;
    }
}
'@

if (-not ('SccPowerStatusNative' -as [type])) {
    Add-Type -TypeDefinition $nativeSource -ErrorAction Stop
}

function Test-OnBattery {
    param([int]$ACLineStatus)
    return ($ACLineStatus -eq 0)
}

if ($SelfTest) {
    Write-Output 'ON_BATTERY_SELFTEST_TYPE_READY'
    if (-not (Test-OnBattery -ACLineStatus 0)) { throw 'AC-offline state was not recognized.' }
    if (Test-OnBattery -ACLineStatus 1) { throw 'AC-online state was misclassified as battery power.' }
    if (Test-OnBattery -ACLineStatus 255) { throw 'Unknown AC state was misclassified as battery power.' }
    if (Test-OnBattery -ACLineStatus -1) { throw 'Power-status API failure was misclassified as battery power.' }
    Write-Output 'ON_BATTERY_SELFTEST_CLASSIFIER_OK'
    Write-Output 'ON_BATTERY_SELFTEST_API_START'
    $actualStatus = [SccPowerStatusNative]::GetACLineStatus()
    Write-Output 'ON_BATTERY_SELFTEST_API_RETURNED'
    if ($actualStatus -notin @(-1, 0, 1, 255)) { throw ('Unexpected ACLineStatus value: ' + $actualStatus) }
    Write-Output ('ON_BATTERY_SELFTEST_OK ACLineStatus=' + $actualStatus)
    exit 0
}

$exitCode = 0
$form = $null
$warningIcon = $null
try {
    $acLineStatus = [SccPowerStatusNative]::GetACLineStatus()
    if (Test-OnBattery -ACLineStatus $acLineStatus) {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop

        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Battery power warning'
        $form.Width = 560
        $form.Height = 250
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.ShowInTaskbar = $true
        $form.TopMost = $true

        $warningIcon = New-Object System.Windows.Forms.PictureBox
        $warningIcon.Image = [System.Drawing.SystemIcons]::Warning.ToBitmap()
        $warningIcon.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
        $warningIcon.Location = New-Object -TypeName System.Drawing.Point -ArgumentList @(20, 24)
        $warningIcon.Size = New-Object -TypeName System.Drawing.Size -ArgumentList @(36, 36)
        $form.Controls.Add($warningIcon)

        $warningLabel = New-Object System.Windows.Forms.Label
        $warningLabel.Location = New-Object -TypeName System.Drawing.Point -ArgumentList @(70, 18)
        $warningLabel.Size = New-Object -TypeName System.Drawing.Size -ArgumentList @(460, 130)
        $warningLabel.Text = @'
WARNING: This computer is running on battery and is not connected to AC power.

The cleanup can take a while and will keep the computer and display awake. The battery may run low or the computer may shut down before the run finishes.

Connect the power adapter, or click "Confirm and continue" to proceed on battery. Cancel stops before cleanup starts.
'@
        $form.Controls.Add($warningLabel)

        $confirmButton = New-Object System.Windows.Forms.Button
        $confirmButton.Text = 'Confirm and continue'
        $confirmButton.Location = New-Object -TypeName System.Drawing.Point -ArgumentList @(230, 170)
        $confirmButton.Size = New-Object -TypeName System.Drawing.Size -ArgumentList @(180, 32)
        $confirmButton.TabIndex = 1
        $confirmButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Controls.Add($confirmButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = 'Cancel'
        $cancelButton.Location = New-Object -TypeName System.Drawing.Point -ArgumentList @(420, 170)
        $cancelButton.Size = New-Object -TypeName System.Drawing.Size -ArgumentList @(100, 32)
        $cancelButton.TabIndex = 0
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)
        $form.ActiveControl = $cancelButton

        $dialogResult = $form.ShowDialog()
        if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK) { $exitCode = 1 }
    }
} catch {
    $exitCode = 2
} finally {
    if ($warningIcon -and $warningIcon.Image) { $warningIcon.Image.Dispose() }
    if ($form) { $form.Dispose() }
}
exit $exitCode
