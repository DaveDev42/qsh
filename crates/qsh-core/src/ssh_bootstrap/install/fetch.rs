//! Where the release assets come from, and this machine's side of the
//! streamed install (ADR-0051 decision 3, path 2): fetch the archive and
//! `SHA256SUMS`, check them, and hand back a file the caller streams over
//! ssh.
//!
//! The download is `curl`, the tool the release installers use too: no HTTP
//! stack is linked into qsh for this. The checks are the installers':
//! `SHA256SUMS` must carry exactly one 64-digit entry for the asset and the
//! archive must hash to it (an integrity check, not a signature, see
//! `scripts/README.md`), and when the GitHub CLI is installed and logged in
//! `gh attestation verify` must pass (fail closed). Without a usable `gh`
//! the install goes ahead on the checksum alone and says so.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::process::Command;

use crate::ops::{CancelToken, OpError};
use qsh_proto::ErrorCode;

/// The repository releases come from unless `QSH_REPO` says otherwise: the
/// same variable and default `scripts/install.sh` uses.
pub const DEFAULT_REPO: &str = "DaveDev42/qsh";

/// Longest a single download may take.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Where a release's files live.
///
/// By default GitHub: assets under
/// `https://github.com/<repo>/releases/download/<tag>/` and the installers
/// under `https://raw.githubusercontent.com/<repo>/<tag>/scripts/`.
/// `QSH_RELEASE_BASE_URL` replaces both with `<base>/<tag>/<file>`, for a
/// mirror or a test server (`install.sh`, `install.ps1`, `SHA256SUMS` and the
/// archives all live there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSource {
    repo: String,
    base: Option<String>,
    gh_program: String,
}

impl ReleaseSource {
    /// The source `QSH_REPO`, `QSH_RELEASE_BASE_URL` and `QSH_GH` describe,
    /// defaulting to GitHub and `gh`.
    pub fn from_env() -> Result<Self, OpError> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let repo = var("QSH_REPO").unwrap_or_else(|| DEFAULT_REPO.to_string());
        let mut source = Self::new(&repo)?;
        if let Some(base) = var("QSH_RELEASE_BASE_URL") {
            source = source.with_base_url(&base)?;
        }
        if let Some(gh) = var("QSH_GH") {
            source = source.with_gh_program(gh);
        }
        Ok(source)
    }

    /// GitHub's `owner/repo`. Only `[A-Za-z0-9._/-]` is accepted: the value
    /// is written into remote command lines.
    pub fn new(repo: &str) -> Result<Self, OpError> {
        let ok = !repo.is_empty()
            && repo.len() <= 200
            && repo
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'));
        if !ok {
            return Err(source_error("QSH_REPO must look like owner/repo"));
        }
        Ok(Self {
            repo: repo.to_string(),
            base: None,
            gh_program: "gh".into(),
        })
    }

    /// Serve everything from `base` (`http://host:port/prefix`, no trailing
    /// slash needed). The characters that could break out of a quoted word
    /// on a remote shell are refused.
    pub fn with_base_url(mut self, base: &str) -> Result<Self, OpError> {
        let base = base.trim_end_matches('/');
        let ok = (base.starts_with("https://") || base.starts_with("http://"))
            && base.len() <= 500
            && base.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '.' | '_' | '~' | ':' | '/' | '-' | '%' | '@' | '+' | '=')
            });
        if !ok {
            return Err(source_error(
                "QSH_RELEASE_BASE_URL must be an http(s) URL of plain characters",
            ));
        }
        self.base = Some(base.to_string());
        Ok(self)
    }

    /// The `gh` program (default `gh`); a path that does not exist reads as
    /// "no GitHub CLI".
    pub fn with_gh_program(mut self, program: impl Into<String>) -> Self {
        self.gh_program = program.into();
        self
    }

    /// `owner/repo`.
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Where the archives and `SHA256SUMS` of `tag` are.
    pub fn assets_url(&self, tag: &str) -> String {
        match &self.base {
            Some(base) => format!("{base}/{tag}"),
            None => format!("https://github.com/{}/releases/download/{tag}", self.repo),
        }
    }

    /// The installer of `tag`: `install.ps1` when `windows`, else `install.sh`.
    pub fn installer_url(&self, tag: &str, windows: bool) -> String {
        let file = if windows { "install.ps1" } else { "install.sh" };
        match &self.base {
            Some(base) => format!("{base}/{tag}/{file}"),
            None => format!(
                "https://raw.githubusercontent.com/{}/{tag}/scripts/{file}",
                self.repo
            ),
        }
    }
}

fn source_error(message: &str) -> OpError {
    OpError::new(ErrorCode::ConfigError, message).with_retryable(false)
}

/// What the provenance check could say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// `gh attestation verify` passed.
    Verified,
    /// It could not run; the install rests on the checksum. The text says why
    /// and is shown to the person.
    NotVerified(String),
}

/// An archive fetched and checked, in a scratch directory that is removed
/// when this is dropped.
#[derive(Debug)]
pub struct FetchedAsset {
    dir: PathBuf,
    /// The archive.
    pub path: PathBuf,
    /// Its sha256, lowercase hex, as `SHA256SUMS` lists it.
    pub sha256: String,
    /// What the provenance check said.
    pub provenance: Provenance,
}

impl Drop for FetchedAsset {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Download `asset` and `SHA256SUMS` of `tag` and check the one against the
/// other, then the provenance when `gh` can.
///
/// Fails with `REMOTE_ERROR` / `remote_install_failed` (stage `fetch`,
/// `checksum` or `provenance`) and leaves nothing behind.
pub async fn fetch_verified(
    source: &ReleaseSource,
    tag: &str,
    asset: &str,
    cancel: &CancelToken,
) -> Result<FetchedAsset, OpError> {
    let dir = scratch_dir()?;
    // Dropped (and removed) on every early return below.
    let mut fetched = FetchedAsset {
        dir: dir.clone(),
        path: dir.join(asset),
        sha256: String::new(),
        provenance: Provenance::NotVerified(String::new()),
    };
    let base = source.assets_url(tag);
    let sums_path = dir.join("SHA256SUMS");
    download(&format!("{base}/SHA256SUMS"), &sums_path, cancel).await?;
    download(&format!("{base}/{asset}"), &fetched.path, cancel).await?;

    let sums = std::fs::read_to_string(&sums_path)
        .map_err(|_| fetch_failed("SHA256SUMS is not readable text"))?;
    let want = checksum_for(&sums, asset)?;
    let path = fetched.path.clone();
    let got = tokio::task::spawn_blocking(move || sha256_file(&path))
        .await
        .map_err(|_| fetch_failed("could not hash the archive"))?
        .map_err(|_| fetch_failed("could not hash the archive"))?;
    if got != want {
        return Err(install_failed(
            "checksum",
            format!(
                "checksum mismatch for {asset}: SHA256SUMS says {want}, the download is {got}; \
                 nothing was sent to the remote"
            ),
        ));
    }
    fetched.sha256 = want;
    fetched.provenance = verify_provenance(source, &fetched.path, cancel).await?;
    Ok(fetched)
}

/// The digest `sums` lists for `asset`: exactly one line whose second field
/// is the asset name, with one 64-digit hex digest. The same fail-closed
/// rule as `scripts/install.sh`. Lowercase on return.
pub(crate) fn checksum_for(sums: &str, asset: &str) -> Result<String, OpError> {
    let mut found = sums.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let name = fields.next()?;
        // `sha256sum` marks a binary-mode file with a leading `*`.
        (name.strip_prefix('*').unwrap_or(name) == asset && fields.next().is_none())
            .then_some(digest)
    });
    let Some(digest) = found.next() else {
        return Err(install_failed(
            "checksum",
            format!("SHA256SUMS has no entry for {asset}; nothing was sent to the remote"),
        ));
    };
    if found.next().is_some() {
        return Err(install_failed(
            "checksum",
            format!("SHA256SUMS has more than one entry for {asset}; nothing was sent"),
        ));
    }
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(install_failed(
            "checksum",
            format!("the SHA256SUMS entry for {asset} is not a 64-digit hex digest"),
        ));
    }
    Ok(digest.to_ascii_lowercase())
}

/// Lowercase hex sha256 of a file.
pub(crate) fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// `curl -fsSL` of `url` into `out`. The child is killed when the call is
/// dropped or canceled.
async fn download(url: &str, out: &Path, cancel: &CancelToken) -> Result<(), OpError> {
    let mut command = Command::new("curl");
    command
        .args(["-fsSL", "--connect-timeout", "15", "--max-time"])
        .arg(DOWNLOAD_TIMEOUT.as_secs().to_string())
        .arg("-o")
        .arg(out)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = spawn(&mut command).map_err(|err| {
        fetch_failed(&format!(
            "could not run curl to download {url}: {}; install curl, or install qsh on the \
             remote by hand",
            err.kind()
        ))
    })?;
    let status = tokio::select! {
        biased;
        () = cancel.canceled() => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(OpError::new(ErrorCode::Canceled, "canceled while downloading qsh")
                .with_retryable(false));
        }
        status = child.wait() => status,
    };
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => Err(fetch_failed(&format!(
            "could not download {url} (does that release exist for this target?)"
        ))),
    }
}

/// `gh attestation verify`, when `gh` is installed and logged in. A failed
/// verification is an error; no usable `gh` is [`Provenance::NotVerified`].
async fn verify_provenance(
    source: &ReleaseSource,
    archive: &Path,
    cancel: &CancelToken,
) -> Result<Provenance, OpError> {
    let gh = &source.gh_program;
    let mut auth = Command::new(gh);
    auth.args(["auth", "status"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let logged_in = match spawn(&mut auth) {
        Ok(mut child) => child.wait().await,
        Err(err) => Err(err),
    };
    match logged_in {
        Err(_) => {
            return Ok(Provenance::NotVerified(
                "'gh' (GitHub CLI) is not installed".into(),
            ));
        }
        Ok(status) if !status.success() => {
            return Ok(Provenance::NotVerified("'gh' is not logged in".into()));
        }
        Ok(_) => {}
    }
    let mut verify = Command::new(gh);
    verify
        .args(["attestation", "verify"])
        .arg(archive)
        .args(["--repo", source.repo()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = spawn(&mut verify).map_err(|_| fetch_failed("could not run gh"))?;
    let status = tokio::select! {
        biased;
        () = cancel.canceled() => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(OpError::new(ErrorCode::Canceled, "canceled while verifying qsh")
                .with_retryable(false));
        }
        status = child.wait() => status,
    };
    match status {
        Ok(status) if status.success() => Ok(Provenance::Verified),
        _ => Err(install_failed(
            "provenance",
            "provenance verification failed (gh attestation verify); nothing was sent to the \
             remote"
                .into(),
        )),
    }
}

fn spawn(command: &mut Command) -> std::io::Result<tokio::process::Child> {
    // Not while another spawn has handles inheritable (`winproc`).
    #[cfg(windows)]
    let _spawning = crate::winproc::spawn_guard();
    command.spawn()
}

/// A fresh private scratch directory.
fn scratch_dir() -> Result<PathBuf, OpError> {
    let dir = std::env::temp_dir().join(format!("qsh-install-{}", ulid::Ulid::generate()));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(&dir)
        .map_err(|_| fetch_failed("could not create a scratch directory"))?;
    Ok(dir)
}

fn fetch_failed(message: &str) -> OpError {
    install_failed("fetch", message.to_string())
}

/// `REMOTE_ERROR` with `details.reason = remote_install_failed` (ADR-0051
/// decision 14) and the `stage` that failed.
pub(super) fn install_failed(stage: &str, message: String) -> OpError {
    OpError::new(ErrorCode::RemoteError, message)
        .with_retryable(false)
        .with_details(json!({ "reason": "remote_install_failed", "stage": stage }))
}

/// Lowercase hex sha256 of `bytes`, for tests of the remote script (unix
/// only: they run it under `sh`).
#[cfg(all(test, unix))]
pub(super) fn sha256_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
