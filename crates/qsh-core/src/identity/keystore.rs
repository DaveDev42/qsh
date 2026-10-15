//! The three private-key stores behind `identity.key_store`
//! (`docs/design/architecture.md` §5).
//!
//! | mode | store | notes |
//! |---|---|---|
//! | `platform` | [`PlatformKeyStore`] | keyring-core 1.x with a per-platform store crate: macOS Keychain / Linux Secret Service / Windows Credential Manager |
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

/// The OS credential store (macOS Keychain, Linux Secret Service, Windows
/// Credential Manager) via keyring-core 1.x plus `apple-native-keyring-store`
/// (macOS), `zbus-secret-service-keyring-store` (Linux) or
/// `windows-native-keyring-store` (Windows), keyed by
/// `("qsh", <device_id>)` so two config directories on one machine never
/// collide. The stored format (service `qsh`, account `device_id`, Base64
/// PKCS#8 DER) is the same one the keyring 3.x backends wrote, so an
/// identity created by an older binary loads unchanged.
///
/// The key is stored Base64-encoded because the credential stores this
/// backend targets hold UTF-8 secrets.
///
/// **Windows entry:** a `CRED_TYPE_GENERIC` credential whose `UserName` is
/// the `device_id`, whose `TargetName` is `<device_id>.qsh`
/// (`windows_target_name`) and whose persistence is
/// `CRED_PERSIST_LOCAL_MACHINE` (`WINDOWS_PERSISTENCE`): it survives
/// reboots and stays on this machine instead of roaming with the profile.
/// The target carries the device id because a Credential Manager entry is
/// addressed by target alone, so a bare `qsh` target would let a second
/// config directory overwrite the first one's key. The blob is the Base64
/// text as UTF-16, far below the 2560-byte `CRED_MAX_CREDENTIAL_BLOB_SIZE`
/// for the 48-byte Ed25519 PKCS#8 key (`windows_blob_for_an_ed25519_key_fits_the_credential_limit`).
///
/// **Runtime note:** the Linux backend drives D-Bus with its own blocking
/// executor, which must never run *on* a tokio worker (it would panic on a
/// nested `block_on` or wedge the worker). Every operation therefore runs
/// on a short-lived dedicated OS thread, so callers may be sync or async.
/// The store handle is opened inside that thread for each operation and is
/// never installed as keyring's process-global default store, so a store
/// that comes up later (a D-Bus session that starts after the first
/// attempt) is picked up by the next call.
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

/// The `persistence` modifier `windows-native-keyring-store` maps to
/// `CRED_PERSIST_LOCAL_MACHINE` (its default, `Enterprise`, would roam with
/// a domain profile). Pure so every target's tests can pin it.
#[cfg(any(windows, test))]
pub(crate) const WINDOWS_PERSISTENCE: &str = "Local";

/// The Credential Manager `TargetName` for `account`: the store's default
/// scheme, `<account>.<service>`. Test-only on purpose: production leaves the
/// target to the store (an explicit `target` modifier would drop the entry's
/// `UserName`), and `credential_manager_round_trip_on_the_runner` compares
/// this name with the real entry to catch drift.
#[cfg(test)]
pub(crate) fn windows_target_name(account: &str) -> String {
    format!("{account}.{KEYRING_SERVICE}")
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
mod platform_impl {
    use super::{KeyStoreError, PlatformKeyStore};

    /// Map a keyring failure onto our error taxonomy: only "the store
    /// itself is not reachable" becomes [`KeyStoreError::Unavailable`], the
    /// signal `auto` uses to fall back to a file.
    pub(super) fn map_error(err: keyring_core::Error) -> KeyStoreError {
        match err {
            keyring_core::Error::PlatformFailure(inner) => {
                KeyStoreError::Unavailable(inner.to_string())
            }
            keyring_core::Error::NoStorageAccess(inner) => {
                KeyStoreError::Unavailable(inner.to_string())
            }
            keyring_core::Error::NoDefaultStore => {
                KeyStoreError::Unavailable("no default credential store".to_string())
            }
            other => KeyStoreError::Other(other.to_string()),
        }
    }

    /// Connect to the OS credential store. Built per operation and never
    /// registered as keyring's process-global default store, so a store that
    /// was unreachable once (no D-Bus session yet, locked keychain) is
    /// retried by the next call instead of being remembered as failed.
    #[cfg(target_os = "linux")]
    fn open_store() -> keyring_core::Result<std::sync::Arc<keyring_core::api::CredentialStore>> {
        let store: std::sync::Arc<keyring_core::api::CredentialStore> =
            zbus_secret_service_keyring_store::Store::new()?;
        Ok(store)
    }

    #[cfg(target_os = "macos")]
    fn open_store() -> keyring_core::Result<std::sync::Arc<keyring_core::api::CredentialStore>> {
        let store: std::sync::Arc<keyring_core::api::CredentialStore> =
            apple_native_keyring_store::keychain::Store::new()?;
        Ok(store)
    }

    #[cfg(windows)]
    fn open_store() -> keyring_core::Result<std::sync::Arc<keyring_core::api::CredentialStore>> {
        let store: std::sync::Arc<keyring_core::api::CredentialStore> =
            windows_native_keyring_store::Store::new()?;
        Ok(store)
    }

    /// Per-entry modifiers: none on macOS and Linux; on Windows only the
    /// persistence class ([`super::WINDOWS_PERSISTENCE`]). The target name is
    /// deliberately left to the store's default scheme: an explicit `target`
    /// modifier makes the store drop the user name, and the entry must carry
    /// `device_id` as its `UserName` (`windows_target_name` pins the result).
    #[cfg(windows)]
    fn modifiers() -> Option<std::collections::HashMap<&'static str, &'static str>> {
        Some(std::collections::HashMap::from([(
            "persistence",
            super::WINDOWS_PERSISTENCE,
        )]))
    }

    #[cfg(not(windows))]
    fn modifiers() -> Option<std::collections::HashMap<&'static str, &'static str>> {
        None
    }

    pub(super) fn entry(store: &PlatformKeyStore) -> Result<keyring_core::Entry, KeyStoreError> {
        open_store()
            .and_then(|s| s.build(super::KEYRING_SERVICE, &store.account, modifiers().as_ref()))
            .map_err(map_error)
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

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
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
                Err(keyring_core::Error::NoEntry) => return Ok(None),
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
                Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
                Err(err) => Err(platform_impl::map_error(err)),
            }
        })
    }
}

/// On targets QSH does not (yet) support as hosts there is no credential
/// store wired up at all: every operation reports `Unavailable`, so
/// `auto` degrades to the file store and `platform` fails loudly.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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

    /// ADR-0035 결정 12: the Windows entry is a generic credential with
    /// `LOCAL_MACHINE` persistence, user name `device_id`, under a target
    /// that ends in the `qsh` service. The pure half of the pin; the entry
    /// the store really writes is read back in
    /// `credential_manager_round_trip_on_the_runner`.
    #[test]
    fn credential_entry_attributes_are_generic_local_machine_under_target_qsh() {
        assert_eq!(KEYRING_SERVICE, "qsh");
        assert_eq!(WINDOWS_PERSISTENCE, "Local");
        assert_eq!(
            windows_target_name("device_01JABCDEF"),
            "device_01JABCDEF.qsh"
        );
        // Two devices on one machine never share an entry.
        assert_ne!(
            windows_target_name("device_a"),
            windows_target_name("device_b")
        );
    }

    /// The Credential Manager keeps the Base64 text as UTF-16; the key
    /// `qsh init` generates (and the only kind `--import-ssh-key` reads,
    /// Ed25519) stays far below its 2560-byte blob limit.
    #[test]
    fn windows_blob_for_an_ed25519_key_fits_the_credential_limit() {
        use base64::Engine as _;

        const CRED_MAX_CREDENTIAL_BLOB_SIZE: usize = 5 * 512;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(key.serialize_der());
        assert!(encoded.encode_utf16().count() * 2 <= CRED_MAX_CREDENTIAL_BLOB_SIZE);
    }

    /// A unique `qsh` entry that is deleted when the test ends, even when an
    /// assertion fails first, so the real Credential Manager keeps nothing.
    #[cfg(windows)]
    struct ScratchEntry(PlatformKeyStore);

    #[cfg(windows)]
    impl ScratchEntry {
        fn new() -> Self {
            Self(PlatformKeyStore::new(format!(
                "device_test_{}",
                ulid::Ulid::generate()
            )))
        }
    }

    #[cfg(windows)]
    impl Drop for ScratchEntry {
        fn drop(&mut self) {
            let _ = self.0.delete();
        }
    }

    /// What `CredReadW` returns for `target` as a generic credential:
    /// `(user name, persistence, blob bytes)`, or `None` when no generic
    /// credential has that target.
    #[cfg(windows)]
    fn raw_generic_credential(target: &str) -> Option<(String, u32, Vec<u8>)> {
        use windows_sys::Win32::Security::Credentials::{
            CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
        };

        let wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; on success
        // `raw` points at a credential that is read and then freed once.
        unsafe {
            if CredReadW(wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) == 0 {
                return None;
            }
            let credential = &*raw;
            let mut user = Vec::new();
            let mut at = credential.UserName;
            while !at.is_null() && *at != 0 {
                user.push(*at);
                at = at.add(1);
            }
            let blob = std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            )
            .to_vec();
            let persist = credential.Persist;
            CredFree(raw as *const _);
            Some((String::from_utf16_lossy(&user), persist, blob))
        }
    }

    /// The real Credential Manager of the account running the tests (the
    /// runner's, or the user's in a manual run): a unique target name per
    /// test, deleted by [`ScratchEntry`]'s drop even on failure
    /// (ADR-0035 결정 12). Reads the entry back with `CredReadW` to pin what
    /// the store crate wrote: a generic credential, `CRED_PERSIST_LOCAL_MACHINE`,
    /// user name `device_id`, target `<device_id>.qsh`.
    #[cfg(windows)]
    #[test]
    fn credential_manager_round_trip_on_the_runner() {
        use windows_sys::Win32::Security::Credentials::CRED_PERSIST_LOCAL_MACHINE;

        let scratch = ScratchEntry::new();
        let store = &scratch.0;
        assert_eq!(store.kind(), KeyStoreKind::Platform);
        assert!(store.load().unwrap().is_none(), "a fresh entry is absent");
        store.store(KEY).unwrap();
        assert_eq!(store.load().unwrap().unwrap().as_slice(), KEY);

        let target = windows_target_name(store.account());
        let (user, persist, _) = raw_generic_credential(&target)
            .expect("a CRED_TYPE_GENERIC credential under <device_id>.qsh");
        assert_eq!(user, store.account());
        assert_eq!(persist, CRED_PERSIST_LOCAL_MACHINE);

        // Writing again replaces the value instead of failing or duplicating.
        store.store(b"another key").unwrap();
        assert_eq!(store.load().unwrap().unwrap().as_slice(), b"another key");

        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
        assert!(raw_generic_credential(&target).is_none());
        store.delete().unwrap();
    }

    /// The blob is the Base64 text of the PKCS#8 DER, as UTF-16 (the form a
    /// keyring-based reader on any platform decodes), so the key stored on
    /// Windows is the same bytes the other stores hold.
    #[cfg(windows)]
    #[test]
    fn credential_manager_blob_is_the_same_pkcs8_base64_as_other_platforms() {
        use base64::Engine as _;

        let scratch = ScratchEntry::new();
        let store = &scratch.0;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let der = key.serialize_der();
        store.store(&der).unwrap();

        let (_, _, blob) = raw_generic_credential(&windows_target_name(store.account()))
            .expect("the entry was written");
        let units: Vec<u16> = blob
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        let text = String::from_utf16(&units).expect("the blob is UTF-16 text");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .unwrap(),
            der
        );
    }

    /// Touches the real OS credential store, so it is opt-in:
    /// `QSH_TEST_PLATFORM_KEYSTORE=1 cargo test -- --ignored`.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    #[test]
    #[ignore = "touches the OS credential store; run with QSH_TEST_PLATFORM_KEYSTORE=1 -- --ignored"]
    fn platform_store_round_trips() {
        if std::env::var_os("QSH_TEST_PLATFORM_KEYSTORE").is_none() {
            eprintln!("set QSH_TEST_PLATFORM_KEYSTORE=1 to run this test");
            return;
        }
        let account = format!("device_test_{}", ulid::Ulid::generate());
        let store = PlatformKeyStore::new(account);
        assert_eq!(store.kind(), KeyStoreKind::Platform);
        assert!(store.load().unwrap().is_none());
        store.store(KEY).unwrap();
        assert_eq!(store.load().unwrap().unwrap().as_slice(), KEY);
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
