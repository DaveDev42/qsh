//! The stateless reset key of the server endpoint
//! (`docs/adr/0036-stateless-reset-key.md`, `docs/design/reexec-estimate.md`
//! §3 H1b, RFC 9000 §10.3).
//!
//! quinn derives a stateless reset token for every connection ID from an
//! HMAC key. By default that key is drawn fresh at every process start, so
//! a restarted `qsh serve`/`qsh listen` cannot answer a packet for a
//! connection it no longer knows with a token the client accepts, and the
//! client learns about the loss only through path watch or the 45 s idle
//! timeout. Keeping the key across restarts turns that into one round
//! trip. The session is still gone; only the detection gets faster.
//!
//! The key is an optimisation, not a correctness precondition, so a file
//! that cannot be used never stops the server (ADR-0036 decision 5):
//!
//! * absent: created once, mode 0600, installed with `link(2)` so two
//!   first starts agree on one key and no reader sees a partial file;
//! * present with a mode wider than 0600: used as is, one diagnostic;
//! * unreadable or not exactly [`RESET_KEY_LEN`] bytes: **never** replaced,
//!   truncated or deleted. The server runs on a throwaway in-memory key
//!   for this process and prints one diagnostic naming the path and the
//!   error kind.
//!
//! Hygiene (`crate::resume`'s token discipline): the key lives in a
//! [`Zeroizing`] buffer, [`LoadedResetKey`]'s `Debug` is redacted, and the
//! diagnostics are built from the path, a mode and an error kind only.

use std::fmt;
use std::io::{self, Read as _, Write as _};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use qsh_transport::{Listener, LocalIdentity, RESET_KEY_LEN, SetupError, TrustEvaluator};
use rand::RngCore as _;
use zeroize::Zeroizing;

use crate::config::Paths;

/// File name of the key under the config directory
/// (`Paths::stateless_reset_key_file`).
pub const RESET_KEY_FILE_NAME: &str = "stateless_reset.key";

/// Leading words of the diagnostic for a key file that is usable but
/// readable by more than its owner.
pub const RESET_KEY_WIDE_MODE_HEADLINE: &str =
    "stateless reset key file has a mode wider than 0600";

/// Clause of the wide-mode diagnostic: what happens to the key.
pub const RESET_KEY_WIDE_MODE_CLAUSE: &str = "the key is used as is";

/// Remedy of the wide-mode diagnostic.
pub const RESET_KEY_WIDE_MODE_REMEDY: &str =
    "narrow it with chmod 600, or delete the file and restart to get a new key";

/// Leading words of the diagnostic for a key file that cannot be used.
pub const RESET_KEY_UNUSABLE_HEADLINE: &str = "cannot use the stateless reset key file";

/// Consequence clause of the unusable-file diagnostic.
pub const RESET_KEY_UNUSABLE_CONSEQUENCE: &str = "running on a temporary in-memory key for this run, so after a restart attached clients notice the lost session only through path watch or the idle timeout";

/// Remedy of the unusable-file diagnostic.
pub const RESET_KEY_UNUSABLE_REMEDY: &str =
    "the file is left untouched; fix or delete it and the next start uses a persistent key";

/// The key plus the diagnostic (if any) the caller has to print once.
pub struct LoadedResetKey {
    key: Zeroizing<[u8; RESET_KEY_LEN]>,
    /// The single startup diagnostic line for this run, without a
    /// `qsh serve: ` style prefix. `None` on the normal paths.
    pub diagnostic: Option<String>,
    persistent: bool,
}

impl LoadedResetKey {
    /// The key bytes, for [`Listener::bind_with_reset_key`] only.
    pub fn bytes(&self) -> &[u8; RESET_KEY_LEN] {
        &self.key
    }

    /// Whether the key came from the file (so it survives a restart) and
    /// not from the throwaway fallback.
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }
}

impl fmt::Debug for LoadedResetKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedResetKey")
            .field("key", &"<redacted>")
            .field("persistent", &self.persistent)
            .field("diagnostic", &self.diagnostic)
            .finish()
    }
}

/// Bind the server endpoint with the persistent reset key
/// (`<config_dir>/stateless_reset.key`). The one place `qsh serve`,
/// `qsh listen` and the testkit get their [`Listener`] from. Returns the
/// startup diagnostic (if any) for the caller to print once on stderr.
pub fn bind_listener(
    paths: &Paths,
    bind: SocketAddr,
    identity: LocalIdentity,
    evaluator: Arc<dyn TrustEvaluator>,
) -> Result<(Listener, Option<String>), SetupError> {
    let loaded = load_or_create(&paths.stateless_reset_key_file());
    let listener = Listener::bind_with_reset_key(bind, identity, evaluator, loaded.bytes())?;
    Ok((listener, loaded.diagnostic))
}

/// Read the key at `path`, creating it when it does not exist, following
/// the ADR-0036 rules in this module's doc.
pub fn load_or_create(path: &Path) -> LoadedResetKey {
    match read_existing(path) {
        Ok(Some(found)) => return found.into_loaded(path),
        Ok(None) => {}
        Err(reason) => return fallback(path, &reason),
    }
    match create(path) {
        Ok(()) => {}
        // Lost the race to another first start: its file is complete by
        // construction (it was linked into place whole).
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return fallback(path, &format!("{:?}", err.kind())),
    }
    match read_existing(path) {
        Ok(Some(found)) => found.into_loaded(path),
        // The file vanished again between create and read: nothing to use.
        Ok(None) => fallback(path, &format!("{:?}", io::ErrorKind::NotFound)),
        Err(reason) => fallback(path, &reason),
    }
}

struct Found {
    key: Zeroizing<[u8; RESET_KEY_LEN]>,
    /// Permission bits when they are wider than 0600 (unix only).
    wide_mode: Option<u32>,
}

impl Found {
    fn into_loaded(self, path: &Path) -> LoadedResetKey {
        let diagnostic = self.wide_mode.map(|mode| {
            format!(
                "{RESET_KEY_WIDE_MODE_HEADLINE}: {} has mode {mode:04o}; \
                 {RESET_KEY_WIDE_MODE_CLAUSE}; {RESET_KEY_WIDE_MODE_REMEDY}",
                path.display()
            )
        });
        LoadedResetKey {
            key: self.key,
            diagnostic,
            persistent: true,
        }
    }
}

/// `Ok(None)` when the file does not exist; `Err(reason)` when it exists
/// but cannot be used (`reason` is an error kind or a fixed word, never
/// file contents).
fn read_existing(path: &Path) -> Result<Option<Found>, String> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("{:?}", err.kind())),
    };
    #[cfg(unix)]
    let wide_mode = {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = file.metadata().map_err(|err| format!("{:?}", err.kind()))?;
        let mode = meta.permissions().mode() & 0o777;
        (mode & 0o077 != 0).then_some(mode)
    };
    #[cfg(not(unix))]
    let wide_mode = None;
    // One byte more than the key, so an over-long file is told apart from
    // an exact one without reading it whole.
    let mut buf = Zeroizing::new([0u8; RESET_KEY_LEN + 1]);
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(format!("{:?}", err.kind())),
        }
    }
    if filled != RESET_KEY_LEN {
        return Err(format!("malformed (expected {RESET_KEY_LEN} bytes)"));
    }
    let mut key = Zeroizing::new([0u8; RESET_KEY_LEN]);
    key.copy_from_slice(&buf[..RESET_KEY_LEN]);
    Ok(Some(Found { key, wide_mode }))
}

/// Write a fresh key to a temp file next to `path` (0600, fsynced) and
/// `link(2)` it into place, which fails with `AlreadyExists` instead of
/// replacing a file another process (or an operator) put there first.
fn create(path: &Path) -> io::Result<()> {
    let mut key = Zeroizing::new([0u8; RESET_KEY_LEN]);
    rand::rng().fill_bytes(key.as_mut());

    let tmp = crate::fsutil::temp_path_for(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| -> io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(key.as_ref())?;
        file.sync_all()?;
        drop(file);
        std::fs::hard_link(&tmp, path)
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

fn fallback(path: &Path, reason: &str) -> LoadedResetKey {
    let mut key = Zeroizing::new([0u8; RESET_KEY_LEN]);
    rand::rng().fill_bytes(key.as_mut());
    LoadedResetKey {
        key,
        diagnostic: Some(format!(
            "{RESET_KEY_UNUSABLE_HEADLINE} {}: {reason}; \
             {RESET_KEY_UNUSABLE_CONSEQUENCE}; {RESET_KEY_UNUSABLE_REMEDY}",
            path.display()
        )),
        persistent: false,
    }
}

#[cfg(test)]
mod tests;
