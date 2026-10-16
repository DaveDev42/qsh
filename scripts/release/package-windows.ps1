# Builds the Windows release zip and proves what is inside it.
#
# The zip holds `qsh.exe` and `man/<name>.1` (the same bytes as docs/man/),
# nothing else. Entry names use forward slashes whatever the host, which is
# what scripts/install.ps1 matches on. After writing the zip the script opens
# it again and compares the member list and every member's SHA-256 with the
# sources, so a packaging step that quietly lost a page fails the job
# instead of shipping.
#
# Usage:
#   package-windows.ps1 -Binary <qsh.exe> -ManDir <docs/man> -Asset <out.zip>
#
# Archive naming (qsh-<tag>-<target>.zip) is a contract with
# .github/workflows/release.yml and scripts/install.ps1.

param(
    [string]$Binary,
    [string]$ManDir,
    [string]$Asset
)

$ErrorActionPreference = 'Stop'

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-QshZip {
    param([string]$Binary, [string]$ManDir, [string]$Asset)

    if (-not $Binary -or -not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
        throw "-Binary must name an existing file (got '$Binary')"
    }
    if (-not $ManDir -or -not (Test-Path -LiteralPath $ManDir -PathType Container)) {
        throw "-ManDir must name an existing directory (got '$ManDir')"
    }
    if (-not $Asset) {
        throw '-Asset must name the zip to write'
    }

    # An empty docs/man/ is a packaging bug, not something to ship quietly.
    $pages = @(Get-ChildItem -LiteralPath $ManDir -Filter '*.1' -File)
    if ($pages.Count -eq 0) {
        throw "no *.1 pages in $ManDir"
    }
    # Ordinal order, so the member list does not depend on the host's locale.
    $names = [string[]]@($pages | ForEach-Object { $_.Name })
    [Array]::Sort($names, [StringComparer]::Ordinal)

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    if (Test-Path -LiteralPath $Asset) {
        Remove-Item -LiteralPath $Asset -Force
    }
    $zip = [System.IO.Compression.ZipFile]::Open($Asset, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Resolve-Path -LiteralPath $Binary).Path, 'qsh.exe')
        foreach ($name in $names) {
            $src = (Resolve-Path -LiteralPath (Join-Path $ManDir $name)).Path
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $src, "man/$name")
        }
    } finally {
        $zip.Dispose()
    }

    $expected = @('qsh.exe') + @($names | ForEach-Object { "man/$_" })
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Asset)
    try {
        $actual = @($zip.Entries | ForEach-Object { $_.FullName })
        $missing = @($expected | Where-Object { $actual -cnotcontains $_ })
        $extra = @($actual | Where-Object { $expected -cnotcontains $_ })
        if ($missing.Count -gt 0 -or $extra.Count -gt 0 -or $actual.Count -ne $expected.Count) {
            throw "zip members differ from the sources: missing [$($missing -join ', ')], unexpected [$($extra -join ', ')]"
        }
        foreach ($entry in $zip.Entries) {
            $src = if ($entry.FullName -ceq 'qsh.exe') { $Binary } else { Join-Path $ManDir ($entry.FullName.Substring(4)) }
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $tmp, $true)
                if ((Get-Sha256 $tmp) -ne (Get-Sha256 $src)) {
                    throw "member $($entry.FullName) differs from $src"
                }
            } finally {
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            }
        }
    } finally {
        $zip.Dispose()
    }

    Write-Host "archive members: $($expected.Count) ($($names.Count) man pages)"
}

if ($MyInvocation.InvocationName -ne '.') {
    New-QshZip -Binary $Binary -ManDir $ManDir -Asset $Asset
}
