param(
    [string]$ToolDir,
    [switch]$Force,
    [switch]$Verify,
    [switch]$Quiet
)

# Enforce TLS 1.2 for PS 5.1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Default ToolDir to script directory if not specified
if (-not $ToolDir) {
    $ToolDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Ensure ToolDir exists
if (-not (Test-Path $ToolDir)) {
    $null = New-Item -ItemType Directory -Path $ToolDir -Force
}

# Tools to download: array of @{Name; ZipName; ExesToCheck}
$tools = @(
    @{ Name = 'Autoruns'; ZipName = 'Autoruns.zip'; ExesToCheck = @('autorunsc64.exe') },
    @{ Name = 'Sigcheck'; ZipName = 'Sigcheck.zip'; ExesToCheck = @('sigcheck64.exe') },
    @{ Name = 'ProcessMonitor'; ZipName = 'ProcessMonitor.zip'; ExesToCheck = @('Procmon64.exe') },
    @{ Name = 'TCPView'; ZipName = 'TCPView.zip'; ExesToCheck = @() }
)

$baseUrl = 'https://download.sysinternals.com/files'
$manifestPath = Join-Path $ToolDir 'manifest.json'
$results = @()
$resultsObjects = @()
$hasErrors = $false

# Helper function to compute SHA-256
function Get-FileSha256 {
    param([string]$FilePath)
    try {
        $hash = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($FilePath)
        $hashBytes = $hash.ComputeHash($stream)
        $stream.Close()
        return [System.BitConverter]::ToString($hashBytes) -replace '-', ''
    } catch {
        return $null
    }
}

# Helper function to add result
function Add-Result {
    param([string]$Tool, [string]$Status, [int]$Count, [string]$Error)
    $script:results += @{ Tool = $Tool; Status = $Status; Count = $Count; Error = $Error }

    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name 'Tool' -Value $Tool
    $obj | Add-Member -MemberType NoteProperty -Name 'Status' -Value $Status
    $obj | Add-Member -MemberType NoteProperty -Name 'Files' -Value $Count
    $obj | Add-Member -MemberType NoteProperty -Name 'Error' -Value $Error
    $script:resultsObjects += $obj
}

# Helper function to load or create manifest
function Load-Manifest {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            $json = Get-Content -Path $Path -Raw -Encoding UTF8
            return ConvertFrom-Json -InputObject $json
        } catch {
            if (-not $Quiet) {
                Write-Host "Warning: Failed to parse existing manifest, starting fresh" -ForegroundColor Yellow
            }
            return New-Object PSObject
        }
    }
    return New-Object PSObject
}

function Test-ManifestToolFiles {
    param($Tool, $ManifestEntry)
    $count = 0
    if ($null -eq $ManifestEntry) {
        return [pscustomobject]@{ Valid = $false; Count = 0; Error = 'Manifest entry missing' }
    }
    $fileProp = $ManifestEntry.PSObject.Properties['files']
    if (-not $fileProp -or $null -eq $fileProp.Value) {
        return [pscustomobject]@{ Valid = $false; Count = 0; Error = 'Manifest entry has no files map' }
    }
    foreach ($fileEntry in @($fileProp.Value.PSObject.Properties)) {
        $fileName = [string]$fileEntry.Name
        $fileInfo = $fileEntry.Value
        $filePath = Join-Path (Join-Path $ToolDir $Tool.Name) $fileName
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            return [pscustomobject]@{ Valid = $false; Count = $count; Error = "Missing file: $fileName" }
        }
        $size = (Get-Item -LiteralPath $filePath).Length
        $hash = Get-FileSha256 -FilePath $filePath
        if (-not $hash -or [string]$hash -ne [string]$fileInfo.sha256 -or [int64]$size -ne [int64]$fileInfo.size) {
            return [pscustomobject]@{ Valid = $false; Count = $count; Error = "Hash/size mismatch: $fileName" }
        }
        $count++
    }
    foreach ($expected in @($Tool.ExesToCheck)) {
        $expectedPath = Join-Path (Join-Path $ToolDir $Tool.Name) $expected
        if (-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)) {
            return [pscustomobject]@{ Valid = $false; Count = $count; Error = "Expected executable missing: $expected" }
        }
    }
    if ($count -eq 0 -and @($Tool.ExesToCheck).Count -eq 0) {
        return [pscustomobject]@{ Valid = $false; Count = 0; Error = 'Manifest files map is empty' }
    }
    return [pscustomobject]@{ Valid = $true; Count = $count; Error = '' }
}

# Helper function to save manifest
function Save-Manifest {
    param($Data, [string]$Path)
    try {
        $json = ConvertTo-Json -InputObject $Data -Depth 10
        Set-Content -Path $Path -Value $json -Encoding UTF8 -NoNewline
        return $true
    } catch {
        return $false
    }
}

# VERIFY MODE: Check existing files against manifest
if ($Verify) {
    if (-not $Quiet) {
        Write-Host "Verifying files against manifest..." -ForegroundColor Cyan
    }

    $manifest = Load-Manifest $manifestPath

    # Count manifest top-level entries reliably across PS 5.1 and 7.x
    # (a PSCustomObject has no .Count on 5.1, so use .PSObject.Properties.Count).
    $manifestEntryCount = 0
    if ($null -ne $manifest) {
        $manifestEntryCount = @($manifest.PSObject.Properties).Count
    }

    if ($manifestEntryCount -eq 0) {
        Write-Host "ERROR: manifest.json not found or empty. Cannot verify." -ForegroundColor Red
        exit 1
    }

    foreach ($tool in $tools) {
        $toolEntry = $manifest.PSObject.Properties | Where-Object { $_.Name -eq $tool.Name }

        if (-not $toolEntry) {
            if (-not $Quiet) {
                Write-Host "$($tool.Name): MISSING from manifest" -ForegroundColor Red
            }
            Add-Result -Tool $tool.Name -Status 'MISSING' -Count 0 -Error 'Not in manifest'
            $hasErrors = $true
            continue
        }

        $toolData = $toolEntry.Value
        $fileCount = 0
        $toolStatus = 'OK'
        $toolError = ''

        # Check each file in this tool's manifest
        foreach ($fileEntry in $toolData.files.PSObject.Properties) {
            $fileName = $fileEntry.Name
            $fileInfo = $fileEntry.Value
            $filePath = Join-Path (Join-Path $ToolDir $tool.Name) $fileName

            if (-not (Test-Path $filePath)) {
                $toolStatus = 'MISSING'
                $toolError = "Missing file: $fileName"
                $hasErrors = $true
                if (-not $Quiet) {
                    Write-Host "$($tool.Name): MISSING - $fileName" -ForegroundColor Red
                }
            } else {
                $fileSize = (Get-Item $filePath).Length
                $fileHash = Get-FileSha256 $filePath

                if ($fileHash -ne $fileInfo.sha256) {
                    $toolStatus = 'MISMATCH'
                    $toolError = "Hash mismatch on $fileName"
                    $hasErrors = $true
                    if (-not $Quiet) {
                        Write-Host "$($tool.Name): MISMATCH - $fileName (got $fileHash, expected $($fileInfo.sha256))" -ForegroundColor Red
                    }
                } elseif ($fileSize -ne $fileInfo.size) {
                    $toolStatus = 'MISMATCH'
                    $toolError = "Size mismatch on $fileName"
                    $hasErrors = $true
                    if (-not $Quiet) {
                        Write-Host "$($tool.Name): MISMATCH - $fileName (size $fileSize vs $($fileInfo.size))" -ForegroundColor Yellow
                    }
                } else {
                    $fileCount++
                    if (-not $Quiet) {
                        Write-Host "$($tool.Name): OK - $fileName" -ForegroundColor Green
                    }
                }
            }
        }

        Add-Result -Tool $tool.Name -Status $toolStatus -Count $fileCount -Error $toolError
    }

    # Print summary table
    Write-Host ""
    Write-Host "Verification Summary:" -ForegroundColor Cyan
    $resultsObjects | Format-Table Tool, Status, Files, Error -AutoSize

    if ($hasErrors) {
        exit 1
    }
    exit 0
}

# DOWNLOAD MODE: Download and extract tools
$manifest = Load-Manifest $manifestPath
$downloadTimestamp = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

foreach ($tool in $tools) {
    $url = "$baseUrl/$($tool.ZipName)"
    $zipPath = Join-Path $ToolDir $tool.ZipName
    $toolStatus = 'OK'
    $toolError = ''
    $fileCount = 0

    $existingEntry = $manifest.PSObject.Properties | Where-Object { $_.Name -eq $tool.Name }
    if ($existingEntry -and -not $Force) {
        $existingCheck = Test-ManifestToolFiles -Tool $tool -ManifestEntry $existingEntry.Value
        if ($existingCheck.Valid) {
            $fileCount = $existingCheck.Count
            Add-Result -Tool $tool.Name -Status 'SKIPPED' -Count $fileCount -Error ''
            if (-not $Quiet) {
                Write-Host "$($tool.Name): OK (cached; -Force re-downloads)" -ForegroundColor Yellow
            }
            continue
        }
        if (-not $Quiet) {
            Write-Host "$($tool.Name): stale/incomplete manifest entry ($($existingCheck.Error)); re-downloading." -ForegroundColor Yellow
        }
    }

    # Download the tool
    if (-not $Quiet) {
        Write-Host "Downloading $($tool.Name)..." -ForegroundColor Cyan
    }

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url -OutFile $zipPath -ErrorAction Stop
    } catch {
        $toolStatus = 'FAILED'
        $toolError = "Download failed: $($_.Exception.Message)"
        $hasErrors = $true
        Add-Result -Tool $tool.Name -Status $toolStatus -Count 0 -Error $toolError
        if (-not $Quiet) {
            Write-Host "ERROR: $($tool.Name) download failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        continue
    }

    # Extract the zip into its own subfolder so each tool's manifest entries are
    # scoped to exactly what this zip contained (avoids cross-tool contamination
    # when multiple tools land in the same ToolDir).
    $extractDir = Join-Path $ToolDir $tool.Name

    if (-not $Quiet) {
        Write-Host "Extracting $($tool.Name)..." -ForegroundColor Cyan
    }

    # Extract to a staging folder and only swap it into place once the whole
    # archive is out. Extracting straight into $extractDir meant an interrupted
    # run (killed process, dropped connection) left a HALF-POPULATED tool folder
    # with no manifest entry - after which -Verify failed permanently and
    # -offline had no way to repair it.
    $stagingDir = Join-Path $ToolDir ($tool.Name + '.incoming')
    if (Test-Path $stagingDir) {
        Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $null = New-Item -ItemType Directory -Path $stagingDir -Force

    try {
        Expand-Archive -Path $zipPath -DestinationPath $stagingDir -Force -ErrorAction Stop
        # Swap: remove the old copy only after a successful full extraction.
        if (Test-Path $extractDir) {
            Remove-Item -Path $extractDir -Recurse -Force -ErrorAction Stop
        }
        Move-Item -Path $stagingDir -Destination $extractDir -Force -ErrorAction Stop
    } catch {
        if (Test-Path $stagingDir) {
            Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        $toolStatus = 'FAILED'
        $toolError = "Extraction failed: $($_.Exception.Message)"
        $hasErrors = $true
        Add-Result -Tool $tool.Name -Status $toolStatus -Count 0 -Error $toolError
        if (-not $Quiet) {
            Write-Host "ERROR: $($tool.Name) extraction failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        if (Test-Path $zipPath) {
            Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        }
        continue
    }

    # Remove the zip file
    try {
        Remove-Item -Path $zipPath -Force -ErrorAction Stop
    } catch {
        if (-not $Quiet) {
            Write-Host "Warning: Could not delete $($tool.Name) zip file" -ForegroundColor Yellow
        }
    }

    # Find the .exe files that this tool's zip just produced
    $exeFiles = @(Get-ChildItem -Path $extractDir -Filter '*.exe' -File -Recurse -ErrorAction SilentlyContinue)

    if ($exeFiles.Count -eq 0) {
        $toolStatus = 'FAILED'
        $toolError = 'No executable files found after extraction'
        $hasErrors = $true
        Add-Result -Tool $tool.Name -Status $toolStatus -Count 0 -Error $toolError
        if (-not $Quiet) {
            Write-Host "ERROR: $($tool.Name) - no .exe files found" -ForegroundColor Red
        }
        continue
    }

    # Compute SHA-256 for each exe and build file list
    $fileDict = @{}
    foreach ($exe in $exeFiles) {
        $sha256 = Get-FileSha256 $exe.FullName
        if ($null -eq $sha256) {
            $toolStatus = 'FAILED'
            $toolError = "Could not hash $($exe.Name)"
            $hasErrors = $true
            if (-not $Quiet) {
                Write-Host "ERROR: Could not compute hash for $($exe.Name)" -ForegroundColor Red
            }
        } else {
            $fileDict[$exe.Name] = @{
                size = $exe.Length
                sha256 = $sha256
            }
            $fileCount++
        }
    }

    # Update manifest
    if ($fileCount -gt 0) {
        $toolObj = New-Object PSObject
        $toolObj | Add-Member -MemberType NoteProperty -Name 'url' -Value $url
        $toolObj | Add-Member -MemberType NoteProperty -Name 'downloaded' -Value $downloadTimestamp

        $filesObj = New-Object PSObject
        foreach ($fileName in $fileDict.Keys) {
            $filesObj | Add-Member -MemberType NoteProperty -Name $fileName -Value $fileDict[$fileName]
        }
        $toolObj | Add-Member -MemberType NoteProperty -Name 'files' -Value $filesObj

        $manifest | Add-Member -MemberType NoteProperty -Name $tool.Name -Value $toolObj -Force
    }

    Add-Result -Tool $tool.Name -Status $toolStatus -Count $fileCount -Error $toolError
    if (-not $Quiet) {
        Write-Host "$($tool.Name): Extracted $fileCount file(s)" -ForegroundColor Green
    }
}

# Save updated manifest
if (-not $Quiet) {
    Write-Host "Saving manifest..." -ForegroundColor Cyan
}

if (-not (Save-Manifest $manifest $manifestPath)) {
    Write-Host "ERROR: Failed to save manifest.json" -ForegroundColor Red
    exit 1
}

# Print summary table - the summary is the second pass's job in the guided
# runner, so keep it quiet when -Quiet is set.
if (-not $Quiet) {
    Write-Host ""
    Write-Host "Download Summary:" -ForegroundColor Cyan
    $resultsObjects | Format-Table Tool, Status, Files, Error -AutoSize
}

if ($hasErrors) {
    Write-Host ""
    Write-Host "Download completed with errors. Check above for details." -ForegroundColor Yellow
    exit 1
}

if (-not $Quiet) {
    Write-Host ""
    Write-Host "All tools downloaded and verified successfully." -ForegroundColor Green
}
exit 0
