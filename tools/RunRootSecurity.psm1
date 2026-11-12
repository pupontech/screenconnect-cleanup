<#
  RunRootSecurity.psm1 - run folders that can be trusted across the offline / online split.

  C:\RIT-SCC inherits "Authenticated Users: Modify" from C:\, so any process running as a
  normal user (for example the remote-access intruder this tool is cleaning up) can create
  or edit run folders there. A fresh, randomly named folder used for one run is hard to
  attack, but the online half CONTINUES a folder the offline half left behind, possibly
  hours later. So the offline half creates its run folder already locked:

      owner      BUILTIN\Administrators
      full       BUILTIN\Administrators, NT AUTHORITY\SYSTEM
      read only  BUILTIN\Users
      no inheritance from C:\RIT-SCC

  and the online half (Find-OfflineRun.ps1) continues a run only when its folder still has
  exactly that shape: not a junction/symlink, a protected ACL, a trusted owner, and no
  write-type permission for anyone but the trusted writers. Fail closed: anything that cannot
  be read or checked is "not trusted".

  The folder is created WITH its security descriptor in one call
  ([IO.Directory]::CreateDirectory(path, security)), so there is no moment where it exists
  with the inherited, user-writable ACL.

  Windows PowerShell 5.1. Pure ASCII, no BOM. Reads/writes only the run folder it is given.
#>

Set-StrictMode -Version 2.0

# Trusted writers / owner. Tests that run without elevation replace these two lines in
# their own throwaway copy of this file (never through the environment: an intruder running
# as the user could set environment variables that an elevated child would inherit).
$script:SccTrustedWriterSids = @('S-1-5-32-544', 'S-1-5-18')
$script:SccRunRootOwnerSid = 'S-1-5-32-544'

# Readers: BUILTIN\Users may read (the report opens in a normal browser), never write.
$script:SccReaderSid = 'S-1-5-32-545'

# TrustedInstaller may legitimately hold rights on system-managed folders.
$script:SccTrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

# Rights that let someone change what is in the folder or who controls it.
$script:SccWriteMask = [int64](
    0x00000002 -bor   # WriteData / AddFile
    0x00000004 -bor   # AppendData / AddSubdirectory
    0x00000010 -bor   # WriteExtendedAttributes
    0x00000040 -bor   # DeleteSubdirectoriesAndFiles
    0x00000100 -bor   # WriteAttributes
    0x00010000 -bor   # Delete
    0x00040000 -bor   # ChangePermissions (WRITE_DAC)
    0x00080000 -bor   # TakeOwnership (WRITE_OWNER)
    0x10000000 -bor   # GENERIC_ALL
    0x40000000)       # GENERIC_WRITE

function New-SccRunRootSecurity {
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $prop = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in $script:SccTrustedWriterSids) {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $prop, $allow)))
    }
    $reader = New-Object System.Security.Principal.SecurityIdentifier($script:SccReaderSid)
    $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($reader, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inherit, $prop, $allow)))
    $sec.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($script:SccRunRootOwnerSid)))
    return $sec
}

function Test-SccIsReparsePoint {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Test-SccRunRootTrusted {
    <#
      $true only when $RunRoot is a real (non-reparse) folder whose parent is not a reparse
      point, whose ACL is protected, whose owner is a trusted writer, and which grants no
      write-type right to anyone but the trusted writers (and TrustedInstaller).
      -Reason receives a short human explanation when the answer is $false.
    #>
    param([Parameter(Mandatory = $true)][string]$RunRoot, [ref]$Reason)
    $why = ''
    try {
        if (-not (Test-Path -LiteralPath $RunRoot -PathType Container)) { $why = 'folder does not exist'; return $false }
        if (Test-SccIsReparsePoint $RunRoot) { $why = 'folder is a junction or symlink'; return $false }
        $parent = Split-Path -Parent ([IO.Path]::GetFullPath($RunRoot))
        if ($parent -and (Test-Path -LiteralPath $parent) -and (Test-SccIsReparsePoint $parent)) { $why = 'parent folder is a junction or symlink'; return $false }

        $acl = Get-Acl -LiteralPath $RunRoot -ErrorAction Stop
        if (-not $acl.AreAccessRulesProtected) { $why = 'folder still inherits the open C:\RIT-SCC permissions (not locked)'; return $false }

        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($script:SccTrustedWriterSids -notcontains $owner) { $why = ('owner is not an administrator account (' + $owner + ')'); return $false }

        $writers = @($script:SccTrustedWriterSids) + @($script:SccTrustedInstallerSid)
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = $rule.IdentityReference.Value
            if ($writers -contains $sid) { continue }
            if (([int64]$rule.FileSystemRights -band $script:SccWriteMask) -ne 0) {
                $why = ('someone other than administrators can write to it (' + $sid + ')')
                return $false
            }
        }
        return $true
    } catch {
        $why = ('could not check it: ' + $_.Exception.Message)
        return $false
    } finally {
        if ($Reason) { $Reason.Value = $why }
    }
}

function New-SccProtectedRunRoot {
    <#
      Creates <Root>\<COMPUTERNAME>-<guid> already locked (see the top of this file) and returns
      its path. Throws when the folder cannot be created locked or does not verify afterwards.
    #>
    param([string]$Root = 'C:\RIT-SCC')
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $Root -Force -ErrorAction Stop
    }
    if (Test-SccIsReparsePoint $Root) { throw ($Root + ' is a junction or symlink; refusing to create a run folder under it.') }
    $path = Join-Path $Root ($env:COMPUTERNAME + '-' + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $path) { throw ('Run folder already exists: ' + $path) }
    $null = [IO.Directory]::CreateDirectory($path, (New-SccRunRootSecurity))
    $reason = ''
    if (-not (Test-SccRunRootTrusted -RunRoot $path -Reason ([ref]$reason))) {
        throw ('New run folder did not verify as locked: ' + $reason)
    }
    if (@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop).Count -ne 0) {
        throw ('New run folder is not empty: ' + $path)
    }
    return $path
}

Export-ModuleMember -Function New-SccProtectedRunRoot, Test-SccRunRootTrusted
