//! The three private-key stores behind `identity.key_store`
//! (`docs/design/architecture.md` §5).
//!
//! | mode | store | notes |
//! |---|---|---|
//! | `platform` | [`PlatformKeyStore`] | keyring 3.x: macOS Keychain / Linux Secret Service |
//! | `file` | [`FileKeyStore`] | `identity/device.key`, 0600 in a 0700 directory |
//! | (tests) | [`MemoryKeyStore`] | process-local, never touches disk |
//!
//! `auto` is not a store: it is the *policy* of trying `platform` and
//! falling back to `file` when the platform store reports
//! [`KeyStoreError::Unavailable`] (headless Linux without a Secret Service /
//! D-Bus session — "the path that matters most in practice",
//! `docs/ROADMAP.md` §4 risk 3). That policy lives in
//! [`crate::identity::init`].
//!
//! Key bytes are always handed around inside [`Zeroizing`] and are never
//! logged, `Debug`-printed or put in an error message.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use qsh_proto::KeyStoreKind;
use thiserror::Error;
use zeroize::Zeroizing;

use super::pem;

/// Credential-store service name used for every QSH platform entry.
pub const KEYRING_SERVICE: &str = "qsh";

/// Why a key-store operation failed.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// The platform credential store is not reachable at all (no Secret
    /// Service, no D-Bus session, locked/absent keychain). This — and only
    /// this — is what makes `auto` fall back to the file store.
    #[error("platform key store unavailable: {0}")]
    Unavailable(String),
    /// Filesystem failure in the file store.
    #[error("key store I/O error: {0}")]
    Io(#[from] io::Error),
    /// Anything else (malformed stored key, encoding failure…).
    #[error("key store error: {0}")]
    Other(String),
}

/// A place a device private key can live.
///
/// Implementations must never log, `Debug`-print or otherwise leak the key
/// bytes they handle.
pub trait KeyStore: Send + Sync {
    /// Which concrete store this is, as reported by `identity.init`.
    fn kind(&self) -> KeyStoreKind;

    /// Persist a PKCS#8 DER private key, replacing any previous value.
    fn store(&self, key_pkcs8_der: &[u8]) -> Result<(), KeyStoreError>;

    /// Load the PKCS#8 DER private key, or `None` if this store holds none.
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;

    /// Remove the stored key. Removing a non-existent key is not an error.
    fn delete(&self) -> Result<(), KeyStoreError>;
}

// ---------------------------------------------------------------------------
// File
// ---------------------------------------------------------------------------

/// A 0600 PKCS#8 PEM file inside the 0700 identity directory — the same
/// posture as an sshd host key.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    /// Store the key at `path` (conventionally `<config>/identity/device.key`).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this store writes.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyStore for FileKeyStore {
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::File
    }

    fn store(&self, key_pkcs8_der: &[u8]) -> Result<(), KeyStoreError> {
        if let Some(parent) = self.path.parent() {
            crate::config::ensure_private_dir_io(parent)?;
        }
        // The PEM text is key material too: zeroize it after writing.
        let text = Zeroizing::new(pem::encode(pem::PRIVATE_KEY, key_pkcs8_der));
        crate::config::write_private_file_io(&self.path, text.as_bytes())?;
        Ok(())
    }

    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => Zeroizing::new(text),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(KeyStoreError::Io(err)),
        };
        let der = pem::decode_first(pem::PRIVATE_KEY, &text)
            .map_err(|err| KeyStoreError::Other(format!("{}: {err}", self.path.display())))?;
        Ok(Some(Zeroizing::new(der)))
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(KeyStoreError::Io(err)),
        }
    }
}

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

/// The OS credential store (macOS Keychain, Linux Secret Service) via
/// keyring 3.x, keyed by `("qsh", <device_id>)` so two config directories on
/// one machine never collide.
///
/// The key is stored Base64-encoded because the credential stores this
/// backend targets hold UTF-8 secrets.
///
/// **Runtime note:** the Linux backend drives D-Bus with its own blocking
/// executor, which must never run *on* a tokio worker (it would panic on a
/// nested `block_on` or wedge the worker). Every operation therefore runs
/// on a short-lived dedicated OS thread, so callers may be sync or async.
#[derive(Debug, Clone)]
pub struct PlatformKeyStore {
    account: String,
}

impl PlatformKeyStore {
    /// Address the entry for `account` (the `device_id`).
    pub fn new(account: impl Into<String>) -> Self {
        Self {
            account: account.into(),
        }
    }

    /// The credential-store account name (never the key itself).
    pub fn account(&self) -> &str {
        &self.account
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform_impl {
    use super::{KeyStoreError, PlatformKeyStore};

    /// Map a keyring failure onto our error taxonomy: only "the store
    /// itself is not reachable" becomes [`KeyStoreError::Unavailable`], the
    /// signal `auto` uses to fall back to a file.
    pub(super) fn map_error(err: keyring::Error) -> KeyStoreError {
        match err {
            keyring::Error::PlatformFailure(inner) => KeyStoreError::Unavailable(inner.to_string()),
            keyring::Error::NoStorageAccess(inner) => KeyStoreError::Unavailable(inner.to_string()),
            other => KeyStoreError::Other(other.to_string()),
        }
    }

    pub(super) fn entry(store: &PlatformKeyStore) -> Result<keyring::Entry, KeyStoreError> {
        keyring::Entry::new(super::KEYRING_SERVICE, &store.account).map_err(map_error)
    }

    /// Run `f` on a dedicated OS thread and wait for it. Isolates the
    /// credential-store client (and, on Linux, its private executor) from
    /// whatever runtime the caller is on.
    pub(super) fn off_runtime<T: Send>(
        f: impl FnOnce() -> Result<T, KeyStoreError> + Send,
    ) -> Result<T, KeyStoreError> {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("qsh-keystore".into())
                .spawn_scoped(scope, f)
                .map_err(|err| KeyStoreError::Other(format!("keystore thread: {err}")))?
                .join()
                .map_err(|_| KeyStoreError::Other("keystore thread panicked".to_string()))?
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl KeyStore for PlatformKeyStore {
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::Platform
    }

    fn store(&self, key_pkcs8_der: &[u8]) -> Result<(), KeyStoreError> {
        use base64::Engine as _;

        platform_impl::off_runtime(|| {
            let entry = platform_impl::entry(self)?;
            let encoded =
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key_pkcs8_der));
            entry
                .set_password(&encoded)
                .map_err(platform_impl::map_error)
        })
    }

    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        use base64::Engine as _;

        platform_impl::off_runtime(|| {
            let entry = platform_impl::entry(self)?;
            let encoded = match entry.get_password() {
                Ok(value) => Zeroizing::new(value),
                Err(keyring::Error::NoEntry) => return Ok(None),
                Err(err) => return Err(platform_impl::map_error(err)),
            };
            let der = base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| {
                    KeyStoreError::Other("stored credential is not valid base64".to_string())
                })?;
            Ok(Some(Zeroizing::new(der)))
        })
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        platform_impl::off_runtime(|| {
            let entry = platform_impl::entry(self)?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(err) => Err(platform_impl::map_error(err)),
            }
        })
    }
}

/// On targets QSH does not (yet) support as hosts there is no credential
/// store wired up at all: every operation reports `Unavailable`, so
/// `auto` degrades to the file store and `platform` fails loudly.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl KeyStore for PlatformKeyStore {
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::Platform
    }

    fn store(&self, _key_pkcs8_der: &[u8]) -> Result<(), KeyStoreError> {
        Err(unsupported())
    }

    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        Err(unsupported())
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        Err(unsupported())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unsupported() -> KeyStoreError {
    KeyStoreError::Unavailable(format!(
        "no OS credential store is wired up for {}",
        std::env::consts::OS
    ))
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// A process-local key store for tests and harnesses: nothing is written to
/// disk or to the OS credential store.
#[derive(Default)]
pub struct MemoryKeyStore {
    slot: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl std::fmt::Debug for MemoryKeyStore {
    /// Never renders the key bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryKeyStore").finish_non_exhaustive()
    }
}

impl MemoryKeyStore {
    /// An empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn kind(&self) -> KeyStoreKind {
        // Memory is not a persistent posture; it reports `file` so nothing
        // can mistake a test harness for a platform-backed key.
        KeyStoreKind::File
    }

    fn store(&self, key_pkcs8_der: &[u8]) -> Result<(), KeyStoreError> {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(Zeroizing::new(key_pkcs8_der.to_vec()));
        Ok(())
    }

    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        Ok(slot.clone())
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        *slot = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"not a real pkcs8 key, just bytes";

    #[test]
    fn memory_store_round_trips_and_deletes() {
        let store = MemoryKeyStore::new();
        assert!(store.load().unwrap().is_none());
        store.store(KEY).unwrap();
        assert_eq!(store.load().unwrap().unwrap().as_slice(), KEY);
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
        // Deleting twice is fine.
        store.delete().unwrap();
    }

    #[test]
    fn file_store_round_trips_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path().join("identity/device.key"));
        assert!(store.load().unwrap().is_none());
        store.store(KEY).unwrap();
        assert_eq!(store.load().unwrap().unwrap().as_slice(), KEY);
        assert_eq!(store.kind(), KeyStoreKind::File);

        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----"));

        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
        store.delete().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_store_uses_0600_in_a_0700_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let identity_dir = dir.path().join("identity");
        let store = FileKeyStore::new(identity_dir.join("device.key"));
        store.store(KEY).unwrap();

        let key_mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(key_mode & 0o777, 0o600, "device.key must be 0600");
        let dir_mode = std::fs::metadata(&identity_dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "identity dir must be 0700");
    }

    #[test]
    fn file_store_rejects_a_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        std::fs::write(&path, "definitely not pem").unwrap();
        let store = FileKeyStore::new(&path);
        let err = store.load().unwrap_err();
        assert!(matches!(err, KeyStoreError::Other(_)), "{err:?}");
    }

    /// Touches the real OS credential store, so it is opt-in:
    /// `QSH_TEST_PLATFORM_KEYSTORE=1 cargo test -- --ignored`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    #[ignore = "touches the OS credential store; run with QSH_TEST_PLATFORM_KEYSTORE=1 -- --ignored"]
    fn platform_store_round_trips() {
        if std::env::var_os("QSH_TEST_PLATFORM_KEYSTORE").is_none() {
            eprintln!("set QSH_TEST_PLATFORM_KEYSTORE=1 to run this test");
            return;
        }
        let account = format!("device_test_{}", ulid::Ulid::new());
        let store = PlatformKeyStore::new(account);
        assert_eq!(store.kind(), KeyStoreKind::Platform);
        assert!(store.load().unwrap().is_none());
        store.store(KEY).unwrap();
        assert_eq!(store.load().unwrap().unwrap().as_slice(), KEY);
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
