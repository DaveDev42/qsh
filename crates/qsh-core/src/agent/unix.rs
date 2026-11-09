//! The unix half of the agent endpoint (ADR-0055 decision 6): a socket in a
//! private `agent/` directory under the runtime directory, or in a private
//! `/tmp/qsh-agent-XXXXXXXXXX` directory when the first path would not fit
//! `sun_path`.

use std::io;
use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand::Rng as _;
use tokio::net::{UnixListener, UnixStream};

use super::{
    AgentConn, AgentStats, Counters, MAX_AGENT_STREAMS_PER_SOCKET, RefusalReason, StreamBudget,
    random_hex_name,
};
use crate::config::ensure_private_dir_io;
use crate::localctl::transport::{authorized_peer, bind_with_narrow_umask};

/// `sizeof(sun_path)`: 104 on macOS, 108 on Linux. A path must be shorter
/// than this (the kernel wants room for the terminating NUL).
#[cfg(target_os = "macos")]
const SUN_PATH_MAX: usize = 104;
#[cfg(not(target_os = "macos"))]
const SUN_PATH_MAX: usize = 108;

/// The directory under the runtime directory that holds the sockets.
const AGENT_DIR: &str = "agent";
/// Where the long-path fallback directory is made.
const FALLBACK_PARENT: &str = "/tmp";
const FALLBACK_PREFIX: &str = "qsh-agent-";
const FALLBACK_SUFFIX_LEN: usize = 10;

/// A sweep leaves sockets younger than this alone: `bind` makes the node a
/// moment before `listen`, and a connect in between is refused by a socket
/// that is about to be live.
const SWEEP_MIN_AGE: Duration = Duration::from_secs(5);

/// A listening agent socket. Dropping it (or calling [`Self::close`])
/// removes the socket node and, for the long-path fallback, its directory.
#[derive(Debug)]
pub struct AgentListener {
    listener: UnixListener,
    socket_path: PathBuf,
    fallback_dir: Option<PathBuf>,
    slots: StreamBudget,
    counters: Arc<Counters>,
}

impl AgentListener {
    /// Create a socket under `runtime_dir` with the default per-socket cap.
    /// Must run inside a tokio runtime. An error means no endpoint exists;
    /// the session layer answers it as `UNAVAILABLE`.
    pub fn create(runtime_dir: &Path) -> io::Result<Self> {
        Self::create_with_cap(runtime_dir, MAX_AGENT_STREAMS_PER_SOCKET)
    }

    /// [`Self::create`] with an explicit per-socket cap.
    pub fn create_with_cap(runtime_dir: &Path, cap: usize) -> io::Result<Self> {
        Self::create_in(runtime_dir, cap, Path::new(FALLBACK_PARENT))
    }

    /// [`Self::create_with_cap`] with an explicit parent for the fallback
    /// directory, so a test does not litter the real `/tmp`.
    pub(crate) fn create_in(
        runtime_dir: &Path,
        cap: usize,
        fallback_parent: &Path,
    ) -> io::Result<Self> {
        let dir = runtime_dir.join(AGENT_DIR);
        ensure_private_dir_io(&dir)?;
        check_private_dir(&dir)?;

        let name = format!("{}.sock", random_hex_name());
        let mut socket_path = dir.join(&name);
        let mut fallback_dir = None;
        if !path_fits(&socket_path) {
            let fallback = make_fallback_dir(fallback_parent)?;
            socket_path = fallback.join(&name);
            fallback_dir = Some(fallback);
        }

        match bind_private_socket(&socket_path) {
            Ok(listener) => Ok(Self {
                listener,
                socket_path,
                fallback_dir,
                slots: StreamBudget::new(cap),
                counters: Arc::new(Counters::default()),
            }),
            Err(err) => {
                let _ = std::fs::remove_file(&socket_path);
                if let Some(dir) = &fallback_dir {
                    let _ = std::fs::remove_dir(dir);
                }
                Err(err)
            }
        }
    }

    /// The value for `SSH_AUTH_SOCK`.
    pub fn auth_sock(&self) -> &Path {
        &self.socket_path
    }

    /// Whether the socket lives in a `/tmp` fallback directory.
    pub fn uses_fallback_dir(&self) -> bool {
        self.fallback_dir.is_some()
    }

    /// Connections handled so far.
    pub fn stats(&self) -> AgentStats {
        self.counters.snapshot()
    }

    /// Slots of the per-socket budget currently taken.
    pub fn connections_open(&self) -> usize {
        self.slots.in_use()
    }

    /// Wait for the next usable connection. A peer of another user and a
    /// connection over the per-socket cap are closed here and the wait goes
    /// on. An error is from `accept(2)` itself.
    pub async fn accept(&mut self) -> io::Result<AgentConn> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            match authorized_peer(&stream) {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    self.counters.refused(RefusalReason::PeerUid);
                    continue;
                }
            }
            let Some(slot) = self.slots.try_acquire() else {
                self.counters.refused(RefusalReason::Cap);
                continue;
            };
            self.counters.accepted();
            return Ok(AgentConn::new(stream, slot));
        }
    }

    /// Stop accepting and remove the socket (same as dropping).
    pub fn close(self) {}
}

impl Drop for AgentListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(dir) = &self.fallback_dir {
            let _ = std::fs::remove_dir(dir);
        }
        tracing::info!(target: "qsh::agent", event = "socket_removed");
    }
}

fn path_fits(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    path.as_os_str().as_bytes().len() < SUN_PATH_MAX
}

fn euid() -> u32 {
    // SAFETY: `geteuid(2)` takes no arguments, touches no memory and cannot
    // fail.
    unsafe { libc::geteuid() }
}

/// Fail unless `dir` is a real directory owned by this user with mode 0700.
fn check_private_dir(dir: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != euid() || meta.mode() & 0o777 != 0o700 {
        return Err(io::Error::other(format!(
            "agent directory {} is not a private directory owned by this user",
            dir.display()
        )));
    }
    Ok(())
}

/// A fresh 0700 directory `<parent>/qsh-agent-XXXXXXXXXX`, the way
/// `mkdtemp(3)` makes one: create-or-fail with the mode, retried on a name
/// clash, and checked afterwards.
fn make_fallback_dir(parent: &Path) -> io::Result<PathBuf> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for _ in 0..16 {
        let mut raw = [0u8; FALLBACK_SUFFIX_LEN];
        rand::rng().fill_bytes(&mut raw);
        let suffix: String = raw
            .iter()
            .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
            .collect();
        let dir = parent.join(format!("{FALLBACK_PREFIX}{suffix}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {
                if let Err(err) = check_private_dir(&dir) {
                    let _ = std::fs::remove_dir(&dir);
                    return Err(err);
                }
                return Ok(dir);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::other(
        "could not create a fallback agent directory",
    ))
}

/// Bind `path` under a narrowed umask, then check what was made: a socket
/// node of mode 0600 owned by this user.
fn bind_private_socket(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;
    let listener = bind_with_narrow_umask(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || meta.uid() != euid() || meta.mode() & 0o777 != 0o600 {
        return Err(io::Error::other("agent socket was not created as 0600"));
    }
    tracing::info!(target: "qsh::agent", event = "socket_created");
    Ok(listener)
}

/// Remove the dead sockets in `<runtime_dir>/agent/` (ADR-0055 decision 8):
/// a socket node that refuses connections. A live socket, a socket younger
/// than a few seconds, anything that is not a socket named `*.sock`, and
/// anything that cannot be examined is left alone. Returns how many were
/// removed. A missing directory is not an error.
pub async fn sweep_stale(runtime_dir: &Path) -> io::Result<usize> {
    sweep_stale_older_than(runtime_dir, SWEEP_MIN_AGE).await
}

/// [`sweep_stale`] with an explicit minimum age.
pub async fn sweep_stale_older_than(runtime_dir: &Path, min_age: Duration) -> io::Result<usize> {
    let dir = runtime_dir.join(AGENT_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let mut removed = 0;
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sock") {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_socket() {
            continue;
        }
        let age = meta
            .modified()
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .unwrap_or_default();
        if age < min_age {
            continue;
        }
        // Only a refusal proves nothing listens. A full backlog is
        // `WouldBlock` on a non-blocking connect, and a live socket
        // connects; both leave the node in place.
        if let Err(err) = UnixStream::connect(&path).await
            && err.kind() == io::ErrorKind::ConnectionRefused
            && std::fs::remove_file(&path).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}
