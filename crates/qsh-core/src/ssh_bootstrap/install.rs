//! Installing `qsh` on the remote with the person's consent (ADR-0051
//! decision 3).
//!
//! When the responder call ends `remote_qsh_missing` (no `qsh`) or
//! `remote_qsh_too_old` (an older `qsh` that does not know `pair
//! ssh-respond`), the bootstrap can put this machine's own release on the
//! remote account and carry on. The pieces:
//!
//! - [`consent`]: the answer. A flag (`--install-remote`,
//!   `--no-install-remote`) decides first; without one, a terminal run asks
//!   the registered question ([`crate::prompts`]) and every other run does
//!   not install.
//! - [`probe_platform`]: the remote OS and architecture over the same ssh
//!   (`uname -sm`; on Windows `cmd /c ver` and `PROCESSOR_ARCHITECTURE`),
//!   mapped to a release target. Anything without a release asset is
//!   `remote_arch_unsupported`.
//! - [`install_remote`]: path 1, the remote runs the pinned tag's
//!   installer; if the remote cannot reach the release host (exit 71 and
//!   nothing else), path 2, this machine fetches the archive, checks it
//!   against `SHA256SUMS` (and `gh attestation` when it can), and streams it
//!   over ssh to a script that re-checks the sha256 and renames the binary
//!   into place. A refusal by the installer, a checksum mismatch or a failed
//!   attestation never falls through to the other path.
//!
//! Nothing runs `sudo`; the install directory is `~/.local/bin` of the ssh
//! account. The caller runs the responder by the returned absolute path (a
//! non-interactive shell often has no `~/.local/bin` on its `PATH`) and the
//! pin keeps it as `remote_qsh`. A `qsh serve` already running on the remote
//! is not touched: the new file is renamed over the old name, so the running
//! process keeps its own inode (Windows moves the old file aside first).
//!
//! The trust basis is the ssh login and host key check, plus the release
//! checksum. The scripts and their exit codes are in the private `scripts` module, the
//! download side in `fetch`.

mod fetch;
mod scripts;
#[cfg(test)]
mod tests;

use std::time::Duration;

use qsh_proto::{ErrorCode, PairSshInstallMethod, PairSshInstalled};
use serde_json::json;

pub use fetch::{DEFAULT_REPO, FetchedAsset, Provenance, ReleaseSource, fetch_verified};

use super::dest::Dest;
use super::options::SshOptions;
use super::ssh::{RemoteOutput, RemoteRun, SshExit, SshRunner, map_ssh_exit};
use crate::ops::{CancelToken, OpError};
use crate::prompts::{self, Prompt, Prompter};
use fetch::install_failed;

/// The `--install-remote` / `--no-install-remote` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InstallRemote {
    /// Neither flag: ask on a terminal, otherwise do not install.
    #[default]
    Ask,
    /// `--install-remote`: install or upgrade without asking.
    Yes,
    /// `--no-install-remote`: never install, never ask.
    No,
}

/// Why an install is on the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallReason {
    /// `remote_qsh_missing`: the remote shell found no `qsh`.
    Missing,
    /// `remote_qsh_too_old`: the remote `qsh` does not know the responder.
    TooOld,
}

impl InstallReason {
    /// The reason an error from the responder call carries, if it is one an
    /// install can fix.
    pub fn of(err: &OpError) -> Option<Self> {
        match err.details.get("reason")?.as_str()? {
            "remote_qsh_missing" => Some(Self::Missing),
            "remote_qsh_too_old" => Some(Self::TooOld),
            _ => None,
        }
    }

    fn prompt(self) -> &'static Prompt {
        match self {
            Self::Missing => &prompts::INSTALL_REMOTE,
            Self::TooOld => &prompts::UPGRADE_REMOTE,
        }
    }
}

/// The release tag of this machine's own `qsh`: what gets installed.
pub fn release_tag() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// Where the install goes, as the question shows it.
pub const INSTALL_DIR_TEXT: &str = "~/.local/bin";

/// The question for `reason`, naming the host, the version and the
/// directory. It also says the bootstrap may start a serve there: the
/// installed `qsh` does that on connect (ADR-0051 decision 2).
pub fn question(reason: InstallReason, host: &str, tag: &str) -> String {
    match reason {
        InstallReason::Missing => format!(
            "{host} has no qsh. Install qsh {tag} into {INSTALL_DIR_TEXT}? (it will also start a \
             serve there when you connect)"
        ),
        InstallReason::TooOld => format!(
            "qsh on {host} is too old for this client. Upgrade it to {tag} in {INSTALL_DIR_TEXT}? \
             (a running serve is left alone)"
        ),
    }
}

/// Whether to install: the flag first, then the question, else no. The
/// prompter is not consulted when a flag decides, and it returns `None`
/// (not asked) for a run without a terminal or in machine mode.
pub fn consent(
    flag: InstallRemote,
    prompter: &dyn Prompter,
    reason: InstallReason,
    host: &str,
    tag: &str,
) -> bool {
    match flag {
        InstallRemote::Yes => true,
        InstallRemote::No => false,
        InstallRemote::Ask => prompter
            .ask_text(reason.prompt(), &question(reason, host, tag))
            .unwrap_or(false),
    }
}

// ---------------------------------------------------------------------
// the remote platform
// ---------------------------------------------------------------------

/// What the remote runs, as far as a release asset is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePlatform {
    /// A Windows remote (zip, `qsh.exe`, PowerShell scripts) rather than a
    /// Unix one (tar.gz, `sh` scripts).
    pub windows: bool,
    /// The Rust target triple of the release asset.
    pub target: &'static str,
}

impl RemotePlatform {
    /// `qsh-<tag>-<target>.tar.gz`, `.zip` on Windows: the naming contract
    /// with `release.yml` that the installers share.
    pub fn asset_name(&self, tag: &str) -> String {
        let ext = if self.windows { "zip" } else { "tar.gz" };
        format!("qsh-{tag}-{}.{ext}", self.target)
    }
}

/// The platform `uname -sm` output names. `Err` carries the `(os, arch)` to
/// report when there is no release for it.
pub(crate) fn platform_from_uname(output: &str) -> Result<RemotePlatform, (String, String)> {
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("");
    let mut fields = line.split_whitespace();
    let kernel = fields.next().unwrap_or("");
    let arch = fields.next().unwrap_or("");
    let target = match (kernel, arch) {
        ("Linux", "x86_64" | "amd64") => "x86_64-unknown-linux-gnu",
        ("Linux", "aarch64" | "arm64") => "aarch64-unknown-linux-gnu",
        ("Darwin", "arm64") => "aarch64-apple-darwin",
        ("Darwin", "x86_64") => "x86_64-apple-darwin",
        _ => return Err((clean(kernel), clean(arch))),
    };
    Ok(RemotePlatform {
        windows: false,
        target,
    })
}

/// The platform the Windows probe output names: a `ver` line, then
/// `PROCESSOR_ARCHITECTURE`, then `PROCESSOR_ARCHITEW6432` (a 32-bit shell
/// on 64-bit Windows; `install.ps1` prefers it, and so does this).
pub(crate) fn platform_from_windows(output: &str) -> Result<RemotePlatform, (String, String)> {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let Some(ver) = lines
        .iter()
        .position(|line| line.starts_with("Microsoft Windows"))
    else {
        return Err(("unknown".into(), String::new()));
    };
    let arch_of = |name: &str| match name.to_ascii_uppercase().as_str() {
        "AMD64" => Some(("AMD64", "x86_64-pc-windows-msvc")),
        "ARM64" => Some(("ARM64", "aarch64-pc-windows-msvc")),
        _ => None,
    };
    let after = &lines[ver + 1..];
    let wow = after.get(1).copied().and_then(arch_of);
    let native = after.first().copied();
    match wow.or_else(|| native.and_then(arch_of)) {
        Some((_, target)) => Ok(RemotePlatform {
            windows: true,
            target,
        }),
        None => Err(("windows".into(), clean(native.unwrap_or("")))),
    }
}

/// A remote-authored word made safe to show: ASCII graphic, short.
fn clean(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_graphic)
        .take(40)
        .collect()
}

fn arch_unsupported(os: &str, arch: &str) -> OpError {
    let what = match (os.is_empty(), arch.is_empty()) {
        (true, _) => "an unknown system".to_string(),
        (false, true) => os.to_string(),
        (false, false) => format!("{os} {arch}"),
    };
    OpError::new(
        ErrorCode::Unsupported,
        format!(
            "there is no qsh release for {what}, so nothing was installed; build qsh there \
             yourself (`cargo install qsh-cli`) and run this again"
        ),
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "remote_arch_unsupported", "os": os, "arch": arch }))
}

/// The remote command words of the Windows probe: one `cmd /c` line that
/// prints the `ver` banner and the two architecture variables. Quoted for
/// `cmd.exe` and PowerShell alike; a POSIX shell just does not find `cmd`.
fn windows_probe_words() -> Vec<String> {
    vec![
        "cmd".into(),
        "/c".into(),
        "\"ver & echo %PROCESSOR_ARCHITECTURE% & echo %PROCESSOR_ARCHITEW6432%\"".into(),
    ]
}

/// What an install call needs to reach the remote.
pub struct InstallCtx<'a> {
    /// The ssh program.
    pub runner: &'a SshRunner,
    /// The destination.
    pub dest: &'a Dest,
    /// The root form's ssh options.
    pub ssh: &'a SshOptions,
    /// `BatchMode` (machine output or no terminal).
    pub batch: bool,
    /// Fires on interrupt.
    pub cancel: &'a CancelToken,
    /// Where the release files come from.
    pub source: &'a ReleaseSource,
    /// The tag to install ([`release_tag`]).
    pub tag: &'a str,
}

impl InstallCtx<'_> {
    /// Longest a probe may take: a minute without a terminal, and long
    /// enough to type a password with one.
    fn probe_timeout(&self) -> Duration {
        if self.batch {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(600)
        }
    }

    async fn run(
        &self,
        words: &[String],
        stdin: Option<&std::path::Path>,
        forward_stderr: bool,
        timeout: Duration,
    ) -> Result<RemoteOutput, OpError> {
        self.runner
            .run_remote(RemoteRun {
                dest: self.dest,
                words,
                batch_mode: self.batch,
                ssh: self.ssh,
                stdin,
                forward_stderr,
                timeout,
                cancel: self.cancel,
            })
            .await
    }
}

/// Ask the remote what it runs. Unix first (`uname -sm`); a remote that does
/// not know `uname` is asked the Windows way.
pub async fn probe_platform(ctx: &InstallCtx<'_>) -> Result<RemotePlatform, OpError> {
    let uname = ctx
        .run(
            &["uname".into(), "-sm".into()],
            None,
            false,
            ctx.probe_timeout(),
        )
        .await?;
    match uname.exit {
        SshExit::Code(0) => {
            let text = String::from_utf8_lossy(&uname.stdout);
            return platform_from_uname(&text).map_err(|(os, arch)| arch_unsupported(&os, &arch));
        }
        SshExit::Code(255) | SshExit::Signal(_) => return Err(map_ssh_exit(uname.exit, true)),
        _ => {}
    }
    let windows = ctx
        .run(&windows_probe_words(), None, false, ctx.probe_timeout())
        .await?;
    match windows.exit {
        SshExit::Code(0) => {
            let text = String::from_utf8_lossy(&windows.stdout);
            platform_from_windows(&text).map_err(|(os, arch)| arch_unsupported(&os, &arch))
        }
        SshExit::Code(255) | SshExit::Signal(_) => Err(map_ssh_exit(windows.exit, true)),
        _ => Err(arch_unsupported("unknown", "")),
    }
}

// ---------------------------------------------------------------------
// the install
// ---------------------------------------------------------------------

/// A finished install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    /// What `pair.ssh` reports as `installed`.
    pub installed: PairSshInstalled,
    /// Human-mode stderr lines, in order.
    pub notices: Vec<String>,
}

/// Install this machine's tag on the remote (`upgrade` says it replaces an
/// older `qsh`; it changes only the report).
pub async fn install_remote(
    ctx: &InstallCtx<'_>,
    upgrade: bool,
) -> Result<InstallOutcome, OpError> {
    let platform = probe_platform(ctx).await?;
    let mut notices = vec![format!(
        "installing qsh {} on {} ({})",
        ctx.tag,
        ctx.dest.host(),
        platform.target
    )];

    let (path, method) = match run_remote_installer(ctx, &platform).await? {
        Some(path) => (path, PairSshInstallMethod::RemoteInstaller),
        None => {
            notices.push(format!(
                "{} cannot reach the release host; sending the archive over ssh instead",
                ctx.dest.host()
            ));
            let (path, provenance) = stream_install(ctx, &platform).await?;
            if let Provenance::NotVerified(why) = provenance {
                notices.push(format!(
                    "provenance not verified: {why}; the install rests on the SHA256SUMS check \
                     alone"
                ));
            }
            (path, PairSshInstallMethod::Streamed)
        }
    };
    notices.push(format!("installed qsh {} at {path}", ctx.tag));
    Ok(InstallOutcome {
        installed: PairSshInstalled {
            version: ctx.tag.to_string(),
            path,
            method,
            upgraded: upgrade,
        },
        notices,
    })
}

/// Path 1. `Ok(None)` is "the remote cannot reach the release host": the
/// one case that moves on to path 2.
async fn run_remote_installer(
    ctx: &InstallCtx<'_>,
    platform: &RemotePlatform,
) -> Result<Option<String>, OpError> {
    let words = if platform.windows {
        scripts::windows_installer_words(ctx.source, ctx.tag)
    } else {
        scripts::unix_installer_words(ctx.source, ctx.tag)
    };
    let out = ctx
        .run(&words, None, true, Duration::from_secs(600))
        .await?;
    if out.exit == SshExit::Code(scripts::EXIT_UNREACHABLE) {
        return Ok(None);
    }
    installed_path(&out, platform, "installer").map(Some)
}

/// Path 2: fetch here, check, stream. The archive file is removed when this
/// returns.
async fn stream_install(
    ctx: &InstallCtx<'_>,
    platform: &RemotePlatform,
) -> Result<(String, Provenance), OpError> {
    let asset = platform.asset_name(ctx.tag);
    let fetched = fetch_verified(ctx.source, ctx.tag, &asset, ctx.cancel).await?;
    let words = if platform.windows {
        scripts::windows_stream_words(&fetched.sha256)
    } else {
        scripts::unix_stream_words(&fetched.sha256)
    };
    let out = ctx
        .run(&words, Some(&fetched.path), true, Duration::from_secs(600))
        .await?;
    let path = installed_path(&out, platform, "stream")?;
    Ok((path, fetched.provenance.clone()))
}

/// The absolute path a finished install script printed, or the error its
/// exit stands for.
fn installed_path(
    out: &RemoteOutput,
    platform: &RemotePlatform,
    stage: &str,
) -> Result<String, OpError> {
    match out.exit {
        SshExit::Code(0) => {}
        SshExit::Code(255) | SshExit::Signal(_) => return Err(map_ssh_exit(out.exit, true)),
        SshExit::Code(code) => return Err(exit_error(code, stage)),
        SshExit::Interrupted => return Err(map_ssh_exit(out.exit, true)),
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let reported = text
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(scripts::INSTALLED_MARK))
        .map(str::trim);
    match reported.filter(|path| valid_installed_path(path, platform.windows)) {
        Some(path) => Ok(path.to_string()),
        None => Err(install_failed(
            stage,
            "the remote install finished but did not report where qsh went".into(),
        )),
    }
}

/// An absolute path to `qsh` / `qsh.exe` made of printable characters: it is
/// remote-authored text that later becomes a command word.
pub(crate) fn valid_installed_path(path: &str, windows: bool) -> bool {
    if path.is_empty() || path.len() > 1024 || path.chars().any(char::is_control) {
        return false;
    }
    if windows {
        let bytes = path.as_bytes();
        let drive = bytes.len() > 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\';
        drive && path.ends_with("\\qsh.exe")
    } else {
        path.starts_with('/') && path.ends_with("/qsh")
    }
}

/// The error for a script that ended with `code`.
fn exit_error(code: i32, stage: &str) -> OpError {
    let why = match code {
        scripts::EXIT_INSTALLER_FAILED => {
            "the release installer failed on the remote (its output is above)"
        }
        scripts::EXIT_SCRATCH => "the remote has no scratch space for the download",
        scripts::EXIT_NO_SHA => "the remote has neither sha256sum nor shasum to check the archive",
        scripts::EXIT_SHA_MISMATCH => {
            "the archive that reached the remote did not match its sha256; nothing was installed"
        }
        scripts::EXIT_BAD_ARCHIVE => "the archive has no usable qsh binary; nothing was installed",
        scripts::EXIT_NOT_WRITABLE => {
            "the remote cannot write ~/.local/bin (or HOME is unset); this never uses sudo"
        }
        _ => "the remote install command failed",
    };
    install_failed(stage, format!("{why} (exit {code})")).with_details(
        json!({ "reason": "remote_install_failed", "stage": stage, "remote_exit": code }),
    )
}
