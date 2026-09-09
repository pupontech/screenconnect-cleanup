<#
  Get-ScannerFindings.ps1 - parse AV scanner log files for threat detections.

  Reads the post-scan log/report that each GUI scanner leaves on disk and
  returns a compact findings object: threat count, per-threat details, and
  the scanner's own stats. Called by sc-cleanup.ps1 Stage 5 after the
  technician closes each scanner GUI.

  Parseable scanners:
    ESET Online Scanner - log.txt at %LOCALAPPDATA%\Temp\log.txt (UTF-16,
      appended across runs; this script reads the LAST scan block only);
      C:\Program Files\EsetOnlineScanner\log.txt is checked as a fallback.
    Malwarebytes        - XML report in %ProgramData%\Malwarebytes\.
    KVRT                - plain-text reports in C:\KVRT_Data\Reports or
      C:\KVRT2020_Data\Reports (*.txt / *.klr) when KVRT runs with
      -dontencrypt (Invoke-GUIScanner.ps1 passes -accepteula -dontencrypt
      -details for KVRT). Without -dontencrypt the reports are encrypted
      (.enc1) and KVRT returns NotParseable = true.

  Usage:
    $r = .\Get-ScannerFindings.ps1 -Scanner ESET
    $r = .\Get-ScannerFindings.ps1 -Scanner Malwarebytes
    $r = .\Get-ScannerFindings.ps1 -Scanner KVRT
    $r = .\Get-ScannerFindings.ps1 -Scanner ESET -EsetLogPath C:\path\log.txt
    $r = .\Get-ScannerFindings.ps1 -Scanner KVRT -KvrtReportPath C:\path\report.klr

  Returns a PSCustomObject with: Scanner, NotParseable, ScanDate, Threats,
  ThreatCount, Stats, Error, LogPath.

  House rules: PS 5.1 compatible, pure ASCII, no BOM.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('KVRT', 'ESET', 'Malwarebytes')]
    [string]$Scanner,
    [string]$EsetLogPath,
    [string]$MbamReportPath,
    [string]$KvrtReportPath
)

function Get-PropVal {
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    $names = @($Obj.PSObject.Properties.Name)
    if ($names -contains $Name) {
        $v = $Obj.$Name
        if ($null -eq $v) { return $Default }
        return $v
    }
    return $Default
}

# -----------------------------------------------------------------------
# KVRT: reports are plain text when KVRT runs with -dontencrypt
# (vendor doc: https://support.kaspersky.com/kvrt2024/269475). Reports
# land in C:\KVRT_Data\Reports (older builds) or
# C:\KVRT2020_Data\Reports (newer builds) as *.txt / *.klr. Without
# -dontencrypt they are encrypted (.enc1) and unparseable.
# -----------------------------------------------------------------------
if ($Scanner -eq 'KVRT') {
    $result = [pscustomobject]@{
        Scanner      = 'KVRT'
        NotParseable = $false
        Error        = $null
        Threats      = @()
        ThreatCount  = 0
        Stats        = $null
        LogPath      = $null
        ScanDate     = $null
    }

    $reportFile = $null
    if ($KvrtReportPath) {
        if (Test-Path -LiteralPath $KvrtReportPath) { $reportFile = Get-Item -LiteralPath $KvrtReportPath } 
        else {
            $result.NotParseable = $true
            $result.Error = 'KVRT report not found: ' + $KvrtReportPath
            return $result
        }
    } else {
        $reportDirs = @()
        foreach ($candidate in @('C:\KVRT_Data\Reports', 'C:\KVRT2020_Data\Reports')) {
            if (Test-Path -LiteralPath $candidate) { $reportDirs += $candidate }
        }
        $reportFiles = @()
        foreach ($dir in $reportDirs) {
            try {
                $reportFiles += @(Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop |
                                  Where-Object { $_.Extension -in @('.txt', '.klr') })
            } catch { }
        }
        if ($reportFiles.Count -eq 0) {
            $result.NotParseable = $true
            $result.Error = 'KVRT reports are encrypted (.enc1) or missing. Re-run KVRT with -accepteula -dontencrypt -details to write plain-text reports under C:\KVRT_Data\Reports.'
            return $result
        }
        $reportFile = ($reportFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    }

    $result.LogPath = $reportFile.FullName
    $result.ScanDate = $reportFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')

    try {
        $lines = @(Get-Content -LiteralPath $reportFile.FullName -ErrorAction Stop)
    } catch {
        $result.Error = 'Could not read KVRT report: ' + $_.Exception.Message
        return $result
    }

    # Tolerant, best-effort parse. KVRT report lines carry Kaspersky verdict
    # names and/or detection keywords; extract the verdict, the object path
    # and the recorded action per line. Details reports include every event,
    # so only lines with a verdict or a detection keyword + object are kept.
    $threats = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($rawLine in $lines) {
        $line = $rawLine.Trim()
        if (-not $line) { continue }

        $verdict = $null
        # Specific Kaspersky verdict prefixes (HEUR:, UDS:, PDM:, not-a-virus:)
        # are unambiguous. The generic family prefixes (Trojan., Virus., ...)
        # need a negative lookbehind so a plain file name inside a path
        # (C:\...\virus.exe) is never mistaken for a verdict.
        if ($line -match '(?i)(HEUR:[A-Za-z0-9._-]+|UDS:[A-Za-z0-9._-]+|PDM:[A-Za-z0-9._-]+|not-a-virus:[A-Za-z0-9._-]+|not-virus:[A-Za-z0-9._-]+|(?<![A-Za-z0-9_\\])(?:Trojan|Virus|Worm|Backdoor|Rootkit|Adware|Riskware|Ransom|Exploit|HackTool|Hoax|Keylogger|Packed|Pornware)[._-][A-Za-z0-9._-]+)') {
            $verdict = $Matches[1]
        }

        $isDetectionLine = $line -match '(?i)detected|infected|dangerous|malicious|suspicious'
        if (-not ($verdict -or $isDetectionLine)) { continue }

        $object = ''
        if ($line -match '([A-Za-z]:\\[^ \t,;<>]+)') { $object = $Matches[1] }

        if (-not $verdict -and -not $object) { continue }

        $action = ''
        if ($line -match '(?i)deleted|removed|disinfected|cleaned|cured') { $action = 'cleaned' }
        elseif ($line -match '(?i)quarantin') { $action = 'quarantined' }
        elseif ($line -match '(?i)skipped|ignored') { $action = 'skipped' }

        $key = ($verdict + '|' + $object)
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        [void]$threats.Add(@{
            ThreatName = if ($verdict) { $verdict } else { 'Detection event' }
            ThreatType = ''
            Object     = $object
            Action     = $action
        })
    }

    $result.Threats = @($threats)
    $result.ThreatCount = $threats.Count
    return $result
}

# -----------------------------------------------------------------------
# ESET Online Scanner
# -----------------------------------------------------------------------
if ($Scanner -eq 'ESET') {
    $logPath = $EsetLogPath
    if (-not $logPath) {
        # ESET KB: %LOCALAPPDATA%\Temp\log.txt; some builds keep it under
        # C:\Program Files\EsetOnlineScanner\log.txt instead.
        $logPath = Join-Path $env:LOCALAPPDATA 'Temp\log.txt'
        if (-not (Test-Path -LiteralPath $logPath)) {
            $altPath = Join-Path $env:ProgramFiles 'EsetOnlineScanner\log.txt'
            if (Test-Path -LiteralPath $altPath) { $logPath = $altPath }
        }
    }

    $result = [pscustomobject]@{
        Scanner      = 'ESET'
        NotParseable = $false
        Error        = $null
        Threats      = @()
        ThreatCount  = 0
        Stats        = $null
        LogPath      = $logPath
        ScanDate     = $null
    }

    if (-not (Test-Path -LiteralPath $logPath)) {
        $result.Error = 'ESET log not found at ' + $logPath
        return $result
    }

    try {
        # ESET Online Scanner appends to log.txt using UTF-16 LE (Unicode)
        # encoding. Get-Content -Encoding Unicode reads it correctly.
        $allLines = @(Get-Content -LiteralPath $logPath -Encoding Unicode -ErrorAction Stop)
    } catch {
        $result.Error = 'Could not read ESET log: ' + $_.Exception.Message
        return $result
    }

    if ($allLines.Count -eq 0) {
        $result.Error = 'ESET log is empty'
        return $result
    }

    # Find the last "Online Scanner" or "esetonlinescanner" header to locate
    # the most recent scan block (the log appends across runs).
    $lastScanStart = -1
    for ($i = $allLines.Count - 1; $i -ge 0; $i--) {
        $line = $allLines[$i]
        if ($line -match '(?i)^(esetonlinescanner|ESET Online Scanner)') {
            $lastScanStart = $i
            break
        }
    }
    if ($lastScanStart -lt 0) {
        $result.Error = 'Could not locate a scan block in the ESET log'
        return $result
    }

    $scanBlock = $allLines[$lastScanStart..($allLines.Count - 1)]

    # Parse key=value lines from the last scan block. Threats appear under
    # the "detected" section with "name=" entries; we also collect
    # "object=" (file path) and "threat=" (threat classification) that
    # follow each name= line. The "action=" line records what the scanner
    # did with the item.
    $threats = New-Object System.Collections.ArrayList
    $currentThreat = $null
    $inDetected = $false
    $stats = @{}
    $scanDate = $null

    foreach ($rawLine in $scanBlock) {
        $line = $rawLine.Trim()

        # ESET date headers look like "date = 2026-09-06 14:32:15" or contain
        # a timestamp in the header line itself.
        if ($line -match '^\s*date\s*=\s*(.+)$') {
            $scanDate = $Matches[1].Trim()
        } elseif ($line -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') {
            if (-not $scanDate) { $scanDate = $Matches[1] }
        }

        # Detect the "detected" section
        if ($line -match '(?i)^=+\s*detected') {
            $inDetected = $true
            continue
        }
        # Any new section header ends the detected section
        if ($inDetected -and $line -match '(?i)^=+\s' -and -not ($line -match '(?i)detected')) {
            $inDetected = $false
        }

        if ($inDetected -and $line -match '(?i)^\s*name\s*=\s*(.+)$') {
            # Flush previous threat
            if ($currentThreat) {
                [void]$threats.Add($currentThreat)
            }
            $currentThreat = @{
                ThreatName = ($Matches[1].Trim()).Trim('"')
                ThreatType = ''
                Object     = ''
                Action     = ''
            }
            continue
        }

        if ($currentThreat) {
            if ($line -match '(?i)^\s*threat\s*=\s*(.+)$') {
                $currentThreat.ThreatType = ($Matches[1].Trim()).Trim('"')
            } elseif ($line -match '(?i)^\s*object\s*=\s*(.+)$') {
                $currentThreat.Object = ($Matches[1].Trim()).Trim('"')
            } elseif ($line -match '(?i)^\s*action\s*=\s*(.+)$') {
                $currentThreat.Action = ($Matches[1].Trim()).Trim('"')
            }
        }

        # Collect scan statistics (number of scanned/infected/cleaned files)
        if ($line -match '(?i)^number of (scanned objects|infected objects|cleaned objects|objects)\s*[=:]\s*(\d+)') {
            $stats[$Matches[1].Trim()] = [int]$Matches[2]
        }
        # Also parse "scanned" / "infected" / "cleaned" as shorter key names
        if ($line -match '(?i)^scanned\s*[=:]\s*(\d+)') {
            $stats['Scanned objects'] = [int]$Matches[1]
        }
        if ($line -match '(?i)^infected\s*[=:]\s*(\d+)') {
            $stats['Infected objects'] = [int]$Matches[1]
        }
        if ($line -match '(?i)^cleaned\s*[=:]\s*(\d+)') {
            $stats['Cleaned objects'] = [int]$Matches[1]
        }
    }

    # Flush the last threat
    if ($currentThreat) {
        [void]$threats.Add($currentThreat)
    }

    $result.Threats = @($threats)
    $result.ThreatCount = $threats.Count
    $result.Stats = if ($stats.Count -gt 0) { $stats } else { $null }
    $result.ScanDate = $scanDate
    return $result
}

# -----------------------------------------------------------------------
# Malwarebytes
# -----------------------------------------------------------------------
if ($Scanner -eq 'Malwarebytes') {
    $reportPath = $MbamReportPath

    # Default search locations for Malwarebytes scan report XML files
    if (-not $reportPath) {
        $searchDirs = @()
        if ($env:ProgramData) {
            $searchDirs += (Join-Path $env:ProgramData 'Malwarebytes\MBAMService\ScanResults')
            $searchDirs += (Join-Path $env:ProgramData 'Malwarebytes\Malwarebytes Anti-Malware\Logs')
        }
        if ($env:APPDATA) {
            $searchDirs += (Join-Path $env:APPDATA 'Malwarebytes\Malwarebytes Anti-Malware\Logs')
        }

        # Find the most recent XML report file
        $latest = $null
        foreach ($dir in $searchDirs) {
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            try {
                $files = @(Get-ChildItem -Path $dir -Filter '*.xml' -File -ErrorAction SilentlyContinue |
                           Sort-Object LastWriteTime -Descending)
                if ($files.Count -gt 0) {
                    if ($null -eq $latest -or $files[0].LastWriteTime -gt $latest.LastWriteTime) {
                        $latest = $files[0]
                    }
                }
            } catch { }
        }
        if ($latest) { $reportPath = $latest.FullName }
    }

    $result = [pscustomobject]@{
        Scanner      = 'Malwarebytes'
        NotParseable = $false
        Error        = $null
        Threats      = @()
        ThreatCount  = 0
        Stats        = $null
        LogPath      = $reportPath
        ScanDate     = $null
    }

    if (-not $reportPath -or -not (Test-Path -LiteralPath $reportPath)) {
        $result.Error = 'Malwarebytes scan report not found'
        return $result
    }

    try {
        [xml]$xml = Get-Content -LiteralPath $reportPath -Raw -ErrorAction Stop
    } catch {
        $result.Error = 'Could not parse Malwarebytes report: ' + $_.Exception.Message
        return $result
    }

    $threats = New-Object System.Collections.ArrayList

    # Malwarebytes XML reports can have different root structures depending
    # on version. Common patterns: //ScanResult/Detections/Detection,
    # //Log/Scan/Result, or //results/object. We search for any element
    # with a "MalwareName" or "Name" child that also has a "Type" or
    # "ObjectType" child, which marks a detection entry.
    $detections = $xml.SelectNodes('//*[MalwareName or (Name and ObjectType)]')
    if ($null -eq $detections -or $detections.Count -eq 0) {
        # Try the flat detection list pattern
        $detections = $xml.SelectNodes('//Detection')
    }

    foreach ($det in @($detections)) {
        $name = [string](Get-PropVal $det 'MalwareName')
        if (-not $name) { $name = [string](Get-PropVal $det 'Name') }
        if (-not $name) { continue }

        $threatType = [string](Get-PropVal $det 'ObjectType')
        if (-not $threatType) { $threatType = [string](Get-PropVal $det 'Type') }
        $object = [string](Get-PropVal $det 'Object')
        if (-not $object) { $object = [string](Get-PropVal $det 'FileName') }
        $action = [string](Get-PropVal $det 'Action')
        if (-not $action) { $action = [string](Get-PropVal $det 'Disposition') }

        [void]$threats.Add(@{
            ThreatName = $name
            ThreatType = $threatType
            Object     = $object
            Action     = $action
        })
    }

    # Extract scan date from the XML if present
    $scanDate = $null
    $dateNode = $xml.SelectSingleNode('//ScanDate')
    if ($dateNode) { $scanDate = [string]$dateNode.InnerText }
    if (-not $scanDate) {
        $dateNode = $xml.SelectSingleNode('//Date')
        if ($dateNode) { $scanDate = [string]$dateNode.InnerText }
    }

    $result.Threats = @($threats)
    $result.ThreatCount = $threats.Count
    $result.ScanDate = $scanDate
    return $result
}
