//! The remote command lines of the install (ADR-0051 decision 3).
//!
//! Every command is one ssh argv tail that means the same thing to the three
//! shells a remote account may have (POSIX `sh` family, `cmd.exe`,
//! PowerShell):
//!
//! - Unix: `sh -c '<script>'`. The script has no single quote and no `!`,
//!   so the quoting survives `sh`, `bash`, `zsh`, `fish` and `csh`. It is
//!   one line.
//! - Windows: `powershell -NoProfile ... -EncodedCommand <base64>`. The
//!   script travels as UTF-16LE base64, a token that is plain text to every
//!   shell, so no quoting rule is involved.
//!
//! The scripts report in two ways. A successful run prints one
//! `QSH_INSTALLED=<absolute path>` line on standard output. A failed run
//! ends with one of the exit codes below, which the client maps to a
//! reason. Nothing is written outside the user's home (`~/.local/bin`) and
//! no script runs `sudo`.
//!
//! Neither script ever reads or writes `qsh`'s own config or state.

use base64::Engine as _;

use super::fetch::ReleaseSource;
use crate::pairing::shell_single_quoted;

/// The remote cannot reach the release host (no `curl`, or the download of
/// the installer failed). The only exit that moves on to streaming the
/// archive from this machine.
pub(super) const EXIT_UNREACHABLE: i32 = 71;
/// The release installer ran and refused or failed (checksum, provenance,
/// unpack, permissions). Never retried by streaming: that could step around
/// a refusal the installer made on purpose.
pub(super) const EXIT_INSTALLER_FAILED: i32 = 72;
/// No scratch space, or the archive could not be written to it.
pub(super) const EXIT_SCRATCH: i32 = 74;
/// Neither `sha256sum` nor `shasum` exists on the remote.
pub(super) const EXIT_NO_SHA: i32 = 75;
/// The archive that arrived does not match the digest this machine sent.
pub(super) const EXIT_SHA_MISMATCH: i32 = 76;
/// The archive has no usable `qsh` member.
pub(super) const EXIT_BAD_ARCHIVE: i32 = 77;
/// `~/.local/bin` cannot be created or written, or `HOME` is unset.
pub(super) const EXIT_NOT_WRITABLE: i32 = 78;

/// The prefix of the success line.
pub(super) const INSTALLED_MARK: &str = "QSH_INSTALLED=";

/// Path 1 on a Unix remote: the remote fetches the pinned tag's `install.sh`
/// and runs it, with the install directory forced to `~/.local/bin`.
pub(super) fn unix_installer_words(source: &ReleaseSource, tag: &str) -> Vec<String> {
    let script = [
        "set -eu".to_string(),
        "command -v curl >/dev/null 2>&1 || exit 71".to_string(),
        "[ -n \"${HOME:-}\" ] || exit 78".to_string(),
        "dir=\"$HOME/.local/bin\"".to_string(),
        "work=\"$(mktemp -d)\" || exit 74".to_string(),
        "cleanup() { rm -rf \"$work\"; }".to_string(),
        "trap cleanup EXIT".to_string(),
        format!(
            "curl -fsSL --connect-timeout 15 --max-time 60 -o \"$work/install.sh\" \"{}\" || exit 71",
            source.installer_url(tag, false)
        ),
        format!(
            "QSH_VERSION={tag} QSH_REPO={} QSH_INSTALL_DIR=\"$dir\" QSH_NO_MAN=1 \
             sh \"$work/install.sh\" >&2 || exit 72",
            source.repo()
        ),
        format!("printf \"{INSTALLED_MARK}%s\\n\" \"$dir/qsh\""),
    ]
    .join("; ");
    sh_c(&script)
}

/// Path 2 on a Unix remote: the archive arrives on standard input, is
/// written to a scratch file, its sha256 is compared with `sha256_hex`, the
/// `qsh` member is unpacked and renamed into `~/.local/bin` atomically.
pub(super) fn unix_stream_words(sha256_hex: &str) -> Vec<String> {
    let script = [
        "set -eu".to_string(),
        "[ -n \"${HOME:-}\" ] || exit 78".to_string(),
        "dir=\"$HOME/.local/bin\"".to_string(),
        "work=\"$(mktemp -d)\" || exit 74".to_string(),
        "cleanup() { rm -rf \"$work\"; }".to_string(),
        "trap cleanup EXIT".to_string(),
        "cat > \"$work/a\" || exit 74".to_string(),
        "if command -v sha256sum >/dev/null 2>&1; then got=\"$(sha256sum \"$work/a\")\"; \
         elif command -v shasum >/dev/null 2>&1; then got=\"$(shasum -a 256 \"$work/a\")\"; \
         else exit 75; fi"
            .to_string(),
        "got=\"${got%% *}\"".to_string(),
        format!("[ \"$got\" = \"{sha256_hex}\" ] || exit 76"),
        "tar xzf \"$work/a\" -C \"$work\" qsh || exit 77".to_string(),
        "[ -f \"$work/qsh\" ] && [ ! -L \"$work/qsh\" ] || exit 77".to_string(),
        "mkdir -p \"$dir\" || exit 78".to_string(),
        "[ ! -d \"$dir/qsh\" ] || exit 78".to_string(),
        "staged=\"$dir/.qsh.install.$$\"".to_string(),
        "{ cp \"$work/qsh\" \"$staged\" && chmod 0755 \"$staged\" && mv -f \"$staged\" \"$dir/qsh\"; } \
         || { rm -f \"$staged\"; exit 78; }"
            .to_string(),
        "if [ \"$(uname -s)\" = Darwin ] && command -v xattr >/dev/null 2>&1; then \
         xattr -d com.apple.quarantine \"$dir/qsh\" 2>/dev/null || true; fi"
            .to_string(),
        format!("printf \"{INSTALLED_MARK}%s\\n\" \"$dir/qsh\""),
    ]
    .join("; ");
    sh_c(&script)
}

/// Path 1 on a Windows remote: the remote fetches the pinned tag's
/// `install.ps1` and runs it with the install directory forced to
/// `%USERPROFILE%\.local\bin` and the user `PATH` left alone (the responder
/// is run by absolute path).
pub(super) fn windows_installer_words(source: &ReleaseSource, tag: &str) -> Vec<String> {
    let script = format!(
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';\
         try{{\
         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;\
         $d=Join-Path $env:USERPROFILE '.local\\bin';\
         try{{$s=Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 '{url}'}}catch{{exit {unreachable}}};\
         $env:QSH_VERSION='{tag}';$env:QSH_REPO='{repo}';$env:QSH_INSTALL_DIR=$d;\
         $env:QSH_NO_MODIFY_PATH='1';$env:QSH_NO_MAN='1';\
         Invoke-Expression $s;\
         Write-Output ('{mark}'+(Join-Path $d 'qsh.exe'))\
         }}catch{{[Console]::Error.WriteLine($_.Exception.Message);exit {failed}}}",
        url = source.installer_url(tag, true),
        repo = source.repo(),
        mark = INSTALLED_MARK,
        unreachable = EXIT_UNREACHABLE,
        failed = EXIT_INSTALLER_FAILED,
    );
    powershell_words(&script)
}

/// Path 2 on a Windows remote: the zip arrives on standard input, is written
/// to a scratch file, checked against `sha256_hex`, and `qsh.exe` is
/// extracted and moved into `%USERPROFILE%\.local\bin`. A `qsh.exe` that is
/// running cannot be overwritten, so it is renamed to `qsh.exe.old` first.
pub(super) fn windows_stream_words(sha256_hex: &str) -> Vec<String> {
    let script = format!(
        "$ErrorActionPreference='Stop';$w=$null;\
         try{{\
         $d=Join-Path $env:USERPROFILE '.local\\bin';\
         $w=Join-Path ([IO.Path]::GetTempPath()) ('qsh-'+[Guid]::NewGuid().ToString('N'));\
         [void](New-Item -ItemType Directory -Path $w);\
         $a=Join-Path $w 'a.zip';\
         $f=[IO.File]::Create($a);\
         try{{[Console]::OpenStandardInput().CopyTo($f)}}finally{{$f.Dispose()}};\
         $h=(Get-FileHash -Algorithm SHA256 -LiteralPath $a).Hash.ToLowerInvariant();\
         if($h -ne '{sha256_hex}'){{exit {mismatch}}};\
         Add-Type -AssemblyName System.IO.Compression.FileSystem;\
         [void](New-Item -ItemType Directory -Force -Path $d);\
         $s=Join-Path $d ('.qsh.install.'+$PID+'.exe');\
         $z=[IO.Compression.ZipFile]::OpenRead($a);\
         try{{\
         $e=@($z.Entries|Where-Object{{$_.FullName -ceq 'qsh.exe'}});\
         if($e.Count -ne 1){{exit {bad}}};\
         [IO.Compression.ZipFileExtensions]::ExtractToFile($e[0],$s,$true)\
         }}finally{{$z.Dispose()}};\
         $t=Join-Path $d 'qsh.exe';\
         if(Test-Path -LiteralPath $t){{\
         try{{Move-Item -Force -LiteralPath $s -Destination $t}}\
         catch{{Move-Item -Force -LiteralPath $t -Destination ($t+'.old');Move-Item -Force -LiteralPath $s -Destination $t}}\
         }}else{{Move-Item -LiteralPath $s -Destination $t}};\
         Write-Output ('{mark}'+$t)\
         }}catch{{[Console]::Error.WriteLine($_.Exception.Message);exit {writable}}}\
         finally{{if($w){{Remove-Item -Recurse -Force -LiteralPath $w -ErrorAction SilentlyContinue}}}}",
        mismatch = EXIT_SHA_MISMATCH,
        bad = EXIT_BAD_ARCHIVE,
        writable = EXIT_NOT_WRITABLE,
        mark = INSTALLED_MARK,
    );
    powershell_words(&script)
}

/// `sh -c '<script>'` as remote command words.
fn sh_c(script: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), shell_single_quoted(script)]
}

/// The remote command words that run `script` in Windows PowerShell:
/// `-EncodedCommand` takes base64 of the UTF-16LE text, so the script
/// crosses `cmd.exe`, PowerShell and sshd's command line unchanged.
pub(super) fn powershell_words(script: &str) -> Vec<String> {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-EncodedCommand".into(),
        base64::engine::general_purpose::STANDARD.encode(utf16),
    ]
}
