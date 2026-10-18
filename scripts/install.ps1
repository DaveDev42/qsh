# QSH installer for Windows -- downloads a prebuilt release zip, verifies it
# against the release's SHA256SUMS, and installs `qsh.exe` and its man pages.
# No Rust toolchain required, no administrator rights required.
#
# Usage:
#   irm https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.ps1 | iex
#
# Env vars (the same names scripts/install.sh uses where the meaning is the
# same):
#   QSH_VERSION      Release tag to install, e.g. "v0.5.0". Defaults to the
#                    newest release, prereleases included.
#   QSH_INSTALL_DIR  Directory `qsh.exe` goes into. Defaults to
#                    "%USERPROFILE%\.local\bin". Created if missing.
#   QSH_REPO         "owner/repo" to install from. Defaults to
#                    "DaveDev42/qsh". Mainly for forks/testing.
#   QSH_MAN_DIR      Directory the man pages from the zip's `man/` go into.
#                    Defaults to "%USERPROFILE%\.local\share\man\man1".
#   QSH_NO_MAN       Set to exactly "1" to skip the man pages.
#   QSH_NO_MODIFY_PATH
#                    Set to exactly "1" to leave the user PATH alone. By
#                    default the install directory is appended to the user
#                    PATH when it is not already on it.
#
# Unlike install.sh there is no way to skip the SHA256SUMS check:
# QSH_INSECURE_SKIP_VERIFY is ignored here.
#
# The architecture is picked from the Windows installation: x86_64 on AMD64,
# aarch64 on ARM64. Anything else is refused.
#
# Nothing here asks for elevation. Everything lands under the user profile and
# the only environment change is to the user's own PATH.
#
# What the check does and does not prove. SHA256SUMS is fetched from the same
# release as the zip, so it catches a truncated or corrupted download, not a
# compromised release. It is an integrity check, not a signature. The check
# always runs before the zip is opened. Unlike install.sh this script does not
# run `gh attestation verify`; to check build provenance, run it yourself on
# the downloaded zip. Windows assets are unsigned (ADR-0035 revision history,
# 2026-10-19), so there is no signature for this script to check.
#
# The file is plain ASCII so that it does not depend on a byte order mark.
#
# Archive naming is a contract with .github/workflows/release.yml:
# qsh-<tag>-<target>.zip holding `qsh.exe` and `man/<name>.1`, with a
# SHA256SUMS file covering every asset of the release. Keep the two in sync if
# either changes.

function Write-QshLog([string]$Message) {
    Write-Host $Message
}

function Write-QshWarning([string]$Message) {
    Write-Host "warning: $Message"
}

function Get-QshTarget {
    # PROCESSOR_ARCHITEW6432 is set only for a 32-bit process on a 64-bit
    # Windows and names the machine's architecture then.
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { return 'x86_64-pc-windows-msvc' }
        'ARM64' { return 'aarch64-pc-windows-msvc' }
        default { throw "install.ps1: unsupported Windows architecture '$arch'; qsh publishes x86_64 and aarch64 builds" }
    }
}

# Resolves the tag of the newest release, prereleases included, since the
# archive filename embeds the tag.
function Get-QshLatestTag([string]$Repo) {
    $url = "https://api.github.com/repos/$Repo/releases?per_page=1"
    try {
        $releases = @(Invoke-RestMethod -Uri $url -Headers @{ 'User-Agent' = 'qsh-install.ps1' })
    } catch {
        throw "install.ps1: could not resolve the latest release of $Repo ($($_.Exception.Message)). Set QSH_VERSION to pick a tag explicitly."
    }
    if ($releases.Count -eq 0 -or -not $releases[0].tag_name) {
        throw "install.ps1: $Repo has no published release. Set QSH_VERSION to pick a tag explicitly."
    }
    return [string]$releases[0].tag_name
}

function Save-QshFile([string]$Url, [string]$Destination) {
    Write-QshLog "downloading $Url"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination
    } catch {
        throw "install.ps1: failed to download $Url ($($_.Exception.Message))"
    }
}

# Fail closed: no entry, more than one entry, or anything that is not a single
# 64-character hex digest aborts before the zip is opened. The file name is
# matched as a whole field, not as a pattern, so the dots in the asset name
# cannot match some other archive's line.
function Assert-QshChecksum([string]$SumsPath, [string]$Asset, [string]$ArchivePath) {
    $digests = @()
    foreach ($line in (Get-Content -LiteralPath $SumsPath)) {
        $fields = @($line.Trim() -split '\s+')
        if ($fields.Count -ge 2 -and $fields[1] -ceq $Asset) {
            $digests += $fields[0]
        }
    }
    if ($digests.Count -eq 0) {
        throw "install.ps1: SHA256SUMS has no entry for $Asset; refusing to install"
    }
    if ($digests.Count -gt 1) {
        throw "install.ps1: SHA256SUMS has $($digests.Count) entries for $Asset; refusing to install"
    }
    $want = $digests[0]
    if ($want -notmatch '^[0-9a-fA-F]{64}$') {
        throw "install.ps1: the SHA256SUMS entry for $Asset is not a single 64-character hex digest; refusing to install"
    }
    $got = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
    if ($want -ine $got) {
        throw "install.ps1: checksum mismatch for ${Asset}: expected $want, got $got; refusing to install"
    }
}

# Returns the new PATH string with $Dir appended, or $null when $Dir is
# already one of the entries (compared after expanding %VARS% and ignoring
# case and a trailing backslash).
function Add-QshDirToPathString([string]$Path, [string]$Dir) {
    $want = [Environment]::ExpandEnvironmentVariables($Dir).TrimEnd('\')
    foreach ($entry in ($Path -split ';')) {
        if (-not $entry) { continue }
        if ([Environment]::ExpandEnvironmentVariables($entry).TrimEnd('\') -ieq $want) {
            return $null
        }
    }
    if (-not $Path) { return $Dir }
    return $Path.TrimEnd(';') + ';' + $Dir
}

# Appends $Dir to the user's persistent PATH (HKCU\Environment). The value is
# read without expanding %VARS% and written back with its original registry
# type, so an existing "%USERPROFILE%\bin" entry stays that. Returns $true when
# it changed the PATH. $SubKey exists so a test can aim this at a scratch key.
function Update-QshUserPath([string]$Dir, [string]$SubKey = 'Environment') {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKey, $true)
    if ($null -eq $key) {
        throw "install.ps1: cannot open HKCU\$SubKey for writing"
    }
    try {
        $current = ''
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ($key.GetValueNames() -contains 'Path') {
            $current = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = $key.GetValueKind('Path')
        }
        $updated = Add-QshDirToPathString $current $Dir
        if ($null -eq $updated) { return $false }
        $key.SetValue('Path', $updated, $kind)
    } finally {
        $key.Close()
    }
    if ($SubKey -eq 'Environment') {
        # Writing the registry does not tell running programs. Setting and
        # clearing a throwaway user variable makes .NET broadcast
        # WM_SETTINGCHANGE, so new terminals see the change without a logoff.
        [Environment]::SetEnvironmentVariable('QSH_ENV_REFRESH', '1', 'User')
        [Environment]::SetEnvironmentVariable('QSH_ENV_REFRESH', $null, 'User')
    }
    return $true
}

# Installs the zip's `man/<name>.1` pages. Only members shaped exactly like
# that are extracted, by name; anything else is reported and left in the zip.
# Each page is copied to a temporary name in the destination and renamed into
# place, like the binary. Man pages are best effort: a problem here is a
# warning and never undoes the binary install.
function Install-QshManPages($Zip, [string]$ManDir) {
    $pages = @($Zip.Entries | Where-Object { $_.FullName -cmatch '^man/[A-Za-z0-9][A-Za-z0-9._-]*\.1$' })
    foreach ($entry in $Zip.Entries) {
        $name = $entry.FullName
        if ($name -ceq 'qsh.exe' -or $name -ceq 'man/') { continue }
        if ($name -cmatch '^man/[A-Za-z0-9][A-Za-z0-9._-]*\.1$') { continue }
        Write-QshWarning "not installing archive member '$name': not a man/<name>.1 page"
    }
    # A zip from before the pages shipped: nothing to do, nothing to say.
    if ($pages.Count -eq 0) { return }

    if ((Test-Path -LiteralPath $ManDir) -and -not (Test-Path -LiteralPath $ManDir -PathType Container)) {
        throw "$ManDir exists and is not a directory"
    }
    New-Item -ItemType Directory -Force -Path $ManDir | Out-Null

    $count = 0
    foreach ($entry in $pages) {
        $name = $entry.FullName.Substring(4)
        $final = Join-Path $ManDir $name
        if (Test-Path -LiteralPath $final -PathType Container) {
            Write-QshWarning "not installing ${name}: $final is a directory"
            continue
        }
        $staged = Join-Path $ManDir ".$name.install.$PID"
        try {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $staged, $true)
            Move-Item -LiteralPath $staged -Destination $final -Force
            $count++
        } catch {
            Write-QshWarning "failed to install ${name} into ${ManDir}: $($_.Exception.Message)"
        } finally {
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }
    }
    Write-QshLog "installed $count man page(s) to $ManDir"
}

function Install-Qsh {
    $ErrorActionPreference = 'Stop'
    # The progress bar makes Invoke-WebRequest several times slower in
    # Windows PowerShell 5.1.
    $ProgressPreference = 'SilentlyContinue'

    if ($env:OS -ne 'Windows_NT') {
        throw 'install.ps1: this installer is for Windows; use scripts/install.sh on macOS and Linux'
    }
    $profileDir = $env:USERPROFILE
    if (-not $profileDir -and (-not $env:QSH_INSTALL_DIR -or ($env:QSH_NO_MAN -ne '1' -and -not $env:QSH_MAN_DIR))) {
        throw 'install.ps1: USERPROFILE is not set; set QSH_INSTALL_DIR (and QSH_MAN_DIR) to say where to install'
    }

    $repo = if ($env:QSH_REPO) { $env:QSH_REPO } else { 'DaveDev42/qsh' }
    $installDir = if ($env:QSH_INSTALL_DIR) { $env:QSH_INSTALL_DIR } else { Join-Path $profileDir '.local\bin' }
    $manDir = if ($env:QSH_MAN_DIR) { $env:QSH_MAN_DIR } else { if ($profileDir) { Join-Path $profileDir '.local\share\man\man1' } else { '' } }

    # Windows PowerShell 5.1 negotiates TLS 1.0/1.1 by default, which GitHub
    # refuses. Newer hosts already allow 1.2, so a failure here is harmless.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
        $null = $_
    }

    $target = Get-QshTarget
    Write-QshLog "detected target: $target"

    if ($env:QSH_VERSION) {
        $version = $env:QSH_VERSION
    } else {
        Write-QshLog 'QSH_VERSION not set, resolving latest release...'
        $version = Get-QshLatestTag $repo
    }
    Write-QshLog "installing version: $version"

    $baseUrl = "https://github.com/$repo/releases/download/$version"
    $asset = "qsh-$version-$target.zip"

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ('qsh-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $zip = $null
    try {
        $archive = Join-Path $work $asset
        Save-QshFile "$baseUrl/$asset" $archive
        $sums = Join-Path $work 'SHA256SUMS'
        Save-QshFile "$baseUrl/SHA256SUMS" $sums
        Write-QshLog 'verifying checksum'
        Assert-QshChecksum $sums $asset $archive

        # Only past this point is the zip opened. The members are extracted
        # one at a time by exact name, so a surprise path inside the zip
        # cannot write outside the directories chosen above.
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        Write-QshLog 'unpacking'
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
        } catch {
            throw "install.ps1: $asset is not a readable zip ($($_.Exception.Message))"
        }
        $exe = @($zip.Entries | Where-Object { $_.FullName -ceq 'qsh.exe' })
        if ($exe.Count -ne 1) {
            throw "install.ps1: $asset did not contain a single 'qsh.exe' at the archive root"
        }

        if ((Test-Path -LiteralPath $installDir) -and -not (Test-Path -LiteralPath $installDir -PathType Container)) {
            throw "install.ps1: $installDir exists and is not a directory"
        }
        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
        $final = Join-Path $installDir 'qsh.exe'
        if (Test-Path -LiteralPath $final -PathType Container) {
            throw "install.ps1: $final is a directory; move it out of the way first"
        }

        # Extract to a temporary name inside the destination directory, then
        # rename it into place, so a failure mid-copy never leaves a partial
        # binary at the final path.
        $staged = Join-Path $installDir ".qsh.install.$PID.exe"
        try {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($exe[0], $staged, $true)
            try {
                Move-Item -LiteralPath $staged -Destination $final -Force
            } catch {
                throw "install.ps1: could not replace $final ($($_.Exception.Message)). If qsh is running, close it and run the installer again."
            }
        } finally {
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }
        Write-QshLog "installed qsh $version to $final"

        if ($env:QSH_NO_MAN -ne '1') {
            try {
                if (-not $manDir) { throw 'neither QSH_MAN_DIR nor USERPROFILE is set; set QSH_MAN_DIR to install man pages' }
                Install-QshManPages $zip $manDir
            } catch {
                Write-QshWarning "man pages were not installed ($($_.Exception.Message)); the qsh binary is installed regardless"
            }
        }
    } finally {
        if ($null -ne $zip) { $zip.Dispose() }
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($env:QSH_NO_MODIFY_PATH -eq '1') {
        Write-QshLog "QSH_NO_MODIFY_PATH=1: leaving PATH alone. Add $installDir to it yourself."
    } else {
        try {
            if (Update-QshUserPath $installDir) {
                Write-QshLog "added $installDir to your user PATH; open a new terminal to pick it up"
            }
        } catch {
            Write-QshWarning "could not update the user PATH ($($_.Exception.Message)). Add $installDir to it yourself."
        }
        if ($null -ne (Add-QshDirToPathString $env:Path $installDir)) {
            $env:Path = $env:Path.TrimEnd(';') + ';' + $installDir
        }
    }
}

# Dot-sourcing (`. .\install.ps1`) only defines the functions, which is how
# the tests reach the PATH helpers. Running the file, or piping it to iex,
# installs.
if ($MyInvocation.InvocationName -ne '.') {
    Install-Qsh
}
