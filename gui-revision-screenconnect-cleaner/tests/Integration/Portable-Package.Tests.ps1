# Portable-package integrity contract. Runs on pwsh without Windows APIs.
# The verifier itself is under tests/ci because the release workflow invokes it.

BeforeAll {
    $ErrorActionPreference = 'Stop'
    $script:verifyScript = Join-Path $PSScriptRoot '../ci/Test-PortablePackage.ps1'
    $script:tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-package-test-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $script:tempRoot -Force

    function New-TestPortablePackage {
        param([string]$Version = '1.2.3')

        $root = Join-Path $script:tempRoot ('ScreenConnectCleaner-' + $Version)
        $null = New-Item -ItemType Directory -Path $root -Force
        foreach ($directory in @('src', 'config', 'docs')) {
            $null = New-Item -ItemType Directory -Path (Join-Path $root $directory) -Force
        }
        Set-Content -LiteralPath (Join-Path $root 'Scc.Cleaner.ps1') -Value 'Write-Output test' -Encoding ascii
        Set-Content -LiteralPath (Join-Path $root 'Start-ScreenConnectCleaner.bat') -Value '@echo off' -Encoding ascii
        Set-Content -LiteralPath (Join-Path $root 'src/Scc.Core.psm1') -Value 'function Get-Test { }' -Encoding ascii
        Set-Content -LiteralPath (Join-Path $root 'config/scc-config.json') -Value '{}' -Encoding ascii
        Set-Content -LiteralPath (Join-Path $root 'docs/README.md') -Value '# Test package' -Encoding ascii

        $manifest = Join-Path $root 'SHA256SUMS.txt'
        $lines = foreach ($file in (Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($root.Length + 1).Replace('\', '/')
            ('{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant(), $relative)
        }
        [System.IO.File]::WriteAllLines($manifest, [string[]]$lines, [System.Text.Encoding]::ASCII)

        $zip = Join-Path $script:tempRoot ('ScreenConnectCleaner-' + $Version + '-portable.zip')
        Compress-Archive -LiteralPath $root -DestinationPath $zip -Force
        $sidecar = $zip + '.sha256'
        $zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
        [System.IO.File]::WriteAllText($sidecar, ($zipHash + '  ' + [System.IO.Path]::GetFileName($zip) + [Environment]::NewLine), [System.Text.Encoding]::ASCII)
        return $zip
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Test-PortablePackage' {
    It 'accepts a package whose ZIP sidecar and staged manifest both match' {
        $zip = New-TestPortablePackage
        & pwsh -NoProfile -File $script:verifyScript -ZipPath $zip
        $LASTEXITCODE | Should -Be 0
    }

    It 'rejects a package whose ZIP sidecar does not match the archive' {
        $zip = New-TestPortablePackage -Version '1.2.4'
        [System.IO.File]::WriteAllText(($zip + '.sha256'), ('0' * 64) + '  ' + [System.IO.Path]::GetFileName($zip), [System.Text.Encoding]::ASCII)
        & pwsh -NoProfile -File $script:verifyScript -ZipPath $zip
        $LASTEXITCODE | Should -Not -Be 0
    }
}
