//! The trust store (`<config_dir>/trust.toml`): pinned peers and private CA
//! roots (`docs/design/architecture.md` §5, §7).
//!
//! ```toml
//! [[peer]]
//! name = "personal-mac"
//! fingerprint = "sha256:BASE64FINGERPRINT"
//! address = "personal-mac.example.com:4433"
//! added_at = "2026-08-17T00:00:00Z"
//!
//! [[ca]]
//! name = "corp-root"
//! cert_pem = "-----BEGIN CERTIFICATE-----\n…"
//! ```
//!
//! Verification logic itself lives in `qsh-transport`
//! ([`qsh_transport::QshPeerVerifier`]); this module only *evaluates* trust
//! and injects the answer through [`qsh_transport::TrustEvaluator`], which
//! [`SharedTrustStore`] implements.
//!
//! Until the hosts.toml directory lands in M7, the pinned peers here are
//! also the single source of truth for `qsh exec <host>`'s host → address
//! resolution ([`TrustStore::resolve_host`], `docs/CLI.md` §6.8).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use qsh_proto::{ErrorCode, TrustPeer};
use qsh_transport::{CertificateDer, Fingerprint, Principal, TrustEvaluator};
use serde::{Deserialize, Serialize};

use crate::config::{config_io_error, ensure_private_dir, write_private_file};
use crate::identity::pem;
use crate::ops::OpError;

/// A private CA root the verifier accepts chains against.
///
/// No CLI surfaces CA entries in M1 (private CA is M6 scope), but the store
/// loads, saves and serves them so an operator-provisioned `trust.toml`
/// round-trips without loss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaEntry {
    /// Operator-chosen label.
    pub name: String,
    /// PEM-encoded root certificate.
    pub cert_pem: String,
}

/// `trust.toml` as serialized.
#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustFile {
    #[serde(default, rename = "peer", skip_serializing_if = "Vec::is_empty")]
    peers: Vec<TrustPeer>,
    #[serde(default, rename = "ca", skip_serializing_if = "Vec::is_empty")]
    cas: Vec<CaEntry>,
}

/// An in-memory snapshot of the trust store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustStore {
    peers: Vec<TrustPeer>,
    cas: Vec<CaEntry>,
}

impl TrustStore {
    /// Load `path`. A missing file is an empty store (not an error); a
    /// malformed one is `CONFIG_ERROR` — QSH never guesses at trust.
    pub fn load(path: &Path) -> Result<Self, OpError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(config_io_error(path, "read", &err)),
        };
        let file: TrustFile = toml::from_str(&text).map_err(|err| {
            OpError::new(
                ErrorCode::ConfigError,
                format!("invalid trust store {}: {err}", path.display()),
            )
            .with_retryable(false)
        })?;
        Ok(Self {
            peers: file.peers,
            cas: file.cas,
        })
    }

    /// Write the store to `path` (0600, in a 0700 directory, atomically).
    pub fn save(&self, path: &Path) -> Result<(), OpError> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        let file = TrustFile {
            peers: self.peers.clone(),
            cas: self.cas.clone(),
        };
        let text = toml::to_string_pretty(&file).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("failed to encode trust store {}: {err}", path.display()),
            )
            .with_retryable(false)
        })?;
        write_private_file(path, text.as_bytes())
    }

    /// All pinned peers, in store order.
    pub fn peers(&self) -> &[TrustPeer] {
        &self.peers
    }

    /// All private CA roots, in store order.
    pub fn cas(&self) -> &[CaEntry] {
        &self.cas
    }

    /// The pin named `name`, if any.
    pub fn find(&self, name: &str) -> Option<&TrustPeer> {
        self.peers.iter().find(|p| p.name == name)
    }

    /// Host → address resolution for `qsh exec <host>` (M7 replaces this
    /// with `hosts.toml`). Only peers that actually carry a dial address
    /// resolve.
    pub fn resolve_host(&self, name: &str) -> Option<&TrustPeer> {
        self.find(name).filter(|p| !p.address.is_empty())
    }

    /// Pin `name`, idempotently.
    ///
    /// Returns `(peer, created)`. If `name` is already pinned the existing
    /// entry is returned **unchanged** with `created == false` — even when
    /// the supplied fingerprint differs. Re-pinning is a deliberate
    /// operator action (remove, then add), never a side effect of a repeated
    /// `trust add` (`docs/CLI.md` §6.11).
    pub fn add_peer(
        &mut self,
        name: impl Into<String>,
        address: Option<String>,
        fingerprint: Fingerprint,
        now: String,
    ) -> (TrustPeer, bool) {
        let name = name.into();
        if let Some(existing) = self.find(&name) {
            return (existing.clone(), false);
        }
        let peer = TrustPeer {
            name,
            fingerprint: fingerprint.to_string(),
            address: address.unwrap_or_default(),
            added_at: now,
        };
        self.peers.push(peer.clone());
        (peer, true)
    }

    /// Remove the pin named `name`. `false` if there was none (idempotent).
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.name != name);
        self.peers.len() != before
    }

    /// Pins as `(fingerprint, principal)` pairs. Entries whose fingerprint
    /// string does not parse are skipped with a `WARN` — a corrupt line
    /// must never widen trust, and must not disable the rest of the store.
    fn parsed_pins(&self) -> Vec<(Fingerprint, Principal)> {
        self.peers
            .iter()
            .filter_map(|peer| match peer.fingerprint.parse::<Fingerprint>() {
                Ok(fp) => Some((fp, Principal::Device(peer.name.clone()))),
                Err(err) => {
                    tracing::warn!(peer = %peer.name, %err, "ignoring pin with an unparsable fingerprint");
                    None
                }
            })
            .collect()
    }

    /// CA roots as DER. Unparsable PEM is skipped with a `WARN`.
    fn parsed_cas(&self) -> Vec<CertificateDer<'static>> {
        self.cas
            .iter()
            .filter_map(|ca| match pem::decode_first(pem::CERTIFICATE, &ca.cert_pem) {
                Ok(der) => Some(CertificateDer::from(der)),
                Err(err) => {
                    tracing::warn!(ca = %ca.name, %err, "ignoring CA entry with unparsable PEM");
                    None
                }
            })
            .collect()
    }
}

/// The cached, parsed view [`SharedTrustStore`] serves to the verifier.
#[derive(Debug)]
struct Cached {
    mtime: Option<SystemTime>,
    store: TrustStore,
    pins: Vec<(Fingerprint, Principal)>,
    cas: Vec<CertificateDer<'static>>,
}

impl Cached {
    fn new(mtime: Option<SystemTime>, store: TrustStore) -> Self {
        Self {
            pins: store.parsed_pins(),
            cas: store.parsed_cas(),
            store,
            mtime,
        }
    }
}

/// A process-wide, reload-on-change view of `trust.toml` that satisfies
/// [`TrustEvaluator`].
///
/// The file's mtime is checked on every lookup and the store is re-read when
/// it moves, so `qsh trust add` on a *running* `qsh serve` takes effect
/// without a restart. A failed reload keeps the last good snapshot (a
/// half-written file must not silently un-trust every peer); it never
/// *widens* trust, because widening requires a successful parse.
pub struct SharedTrustStore {
    path: PathBuf,
    cache: RwLock<Cached>,
}

impl std::fmt::Debug for SharedTrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedTrustStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SharedTrustStore {
    /// Open (and eagerly load) the trust store at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Result<Arc<Self>, OpError> {
        let path = path.into();
        let store = TrustStore::load(&path)?;
        Ok(Arc::new(Self {
            cache: RwLock::new(Cached::new(mtime_of(&path), store)),
            path,
        }))
    }

    /// The file this view is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A copy of the current (possibly reloaded) store contents.
    pub fn snapshot(&self) -> TrustStore {
        self.refresh();
        self.read().store.clone()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Cached> {
        self.cache.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Re-read `trust.toml` if its mtime moved since the cached snapshot.
    fn refresh(&self) {
        let current = mtime_of(&self.path);
        if self.read().mtime == current {
            return;
        }
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if cache.mtime == current {
            return;
        }
        match TrustStore::load(&self.path) {
            Ok(store) => *cache = Cached::new(current, store),
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %err,
                    "failed to reload the trust store; keeping the last good snapshot"
                );
            }
        }
    }
}

fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

impl TrustEvaluator for SharedTrustStore {
    fn lookup_pin(&self, fingerprint: &Fingerprint) -> Option<Principal> {
        self.refresh();
        self.read()
            .pins
            .iter()
            .find(|(fp, _)| fp == fingerprint)
            .map(|(_, principal)| principal.clone())
    }

    fn ca_roots(&self) -> Vec<CertificateDer<'static>> {
        self.refresh();
        self.read().cas.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_spki_der(seed)
    }

    #[test]
    fn add_list_find_and_remove() {
        let mut store = TrustStore::default();
        assert!(store.peers().is_empty());

        let (peer, created) = store.add_peer(
            "mac",
            Some("mac.example:4433".into()),
            fp(b"one"),
            "2026-08-17T00:00:00Z".into(),
        );
        assert!(created);
        assert_eq!(peer.name, "mac");
        assert_eq!(peer.fingerprint, fp(b"one").to_string());
        assert_eq!(peer.address, "mac.example:4433");
        assert_eq!(store.peers().len(), 1);
        assert_eq!(store.find("mac"), Some(&peer));
        assert_eq!(store.find("nope"), None);

        assert!(store.remove("mac"));
        assert!(!store.remove("mac"));
        assert!(store.peers().is_empty());
    }

    #[test]
    fn re_adding_is_idempotent_and_never_overwrites() {
        let mut store = TrustStore::default();
        let (first, created) = store.add_peer(
            "mac",
            Some("a:1".into()),
            fp(b"one"),
            "2026-08-17T00:00:00Z".into(),
        );
        assert!(created);

        // Same fingerprint again.
        let (again, created) = store.add_peer(
            "mac",
            Some("a:1".into()),
            fp(b"one"),
            "2026-08-18T00:00:00Z".into(),
        );
        assert!(!created);
        assert_eq!(again, first);

        // A *different* fingerprint must not silently re-pin.
        let (conflicting, created) = store.add_peer(
            "mac",
            Some("b:2".into()),
            fp(b"two"),
            "2026-08-19T00:00:00Z".into(),
        );
        assert!(!created);
        assert_eq!(conflicting, first);
        assert_eq!(store.peers().len(), 1);
        assert_eq!(
            store.find("mac").unwrap().fingerprint,
            fp(b"one").to_string()
        );
    }

    #[test]
    fn address_is_empty_when_absent_and_does_not_resolve_as_a_host() {
        let mut store = TrustStore::default();
        let (peer, _) = store.add_peer("client-only", None, fp(b"c"), "t".into());
        assert_eq!(peer.address, "");
        assert!(store.find("client-only").is_some());
        assert!(store.resolve_host("client-only").is_none());

        store.add_peer("server", Some("h:4433".into()), fp(b"s"), "t".into());
        assert_eq!(store.resolve_host("server").unwrap().address, "h:4433");
        assert!(store.resolve_host("absent").is_none());
    }

    #[test]
    fn missing_file_loads_as_empty_and_round_trips_with_a_ca_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let loaded = TrustStore::load(&path).unwrap();
        assert!(loaded.peers().is_empty() && loaded.cas().is_empty());

        let mut store = TrustStore::default();
        store.add_peer(
            "mac",
            Some("mac.example:4433".into()),
            fp(b"one"),
            "2026-08-17T00:00:00Z".into(),
        );
        store.cas.push(CaEntry {
            name: "corp-root".into(),
            cert_pem: pem::encode(pem::CERTIFICATE, b"pretend der"),
        });
        store.save(&path).unwrap();

        let back = TrustStore::load(&path).unwrap();
        assert_eq!(back, store);
        assert_eq!(back.cas()[0].name, "corp-root");
        assert_eq!(back.parsed_cas().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn saved_store_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg/trust.toml");
        TrustStore::default().save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    #[test]
    fn malformed_store_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        std::fs::write(&path, "[[peer]]\nname = ").unwrap();
        let err = TrustStore::load(&path).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
        assert!(!err.retryable);
    }

    #[test]
    fn shared_store_reloads_when_the_file_mtime_moves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");

        let mut store = TrustStore::default();
        store.add_peer("first", None, fp(b"one"), "t".into());
        store.save(&path).unwrap();

        let shared = SharedTrustStore::open(&path).unwrap();
        assert_eq!(
            shared.lookup_pin(&fp(b"one")),
            Some(Principal::Device("first".into()))
        );
        assert_eq!(shared.lookup_pin(&fp(b"two")), None);

        // Rewrite with an extra pin and push the mtime forward explicitly,
        // so the test never depends on filesystem timestamp granularity.
        store.add_peer("second", None, fp(b"two"), "t".into());
        store.save(&path).unwrap();
        let bumped = SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(bumped)
            .unwrap();

        assert_eq!(
            shared.lookup_pin(&fp(b"two")),
            Some(Principal::Device("second".into())),
            "a changed trust.toml must be picked up without a restart"
        );
        assert_eq!(shared.snapshot().peers().len(), 2);
    }

    #[test]
    fn shared_store_keeps_the_last_good_snapshot_on_a_broken_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let mut store = TrustStore::default();
        store.add_peer("first", None, fp(b"one"), "t".into());
        store.save(&path).unwrap();

        let shared = SharedTrustStore::open(&path).unwrap();
        assert!(shared.lookup_pin(&fp(b"one")).is_some());

        std::fs::write(&path, "[[peer]]\nname = ").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() + std::time::Duration::from_secs(5))
            .unwrap();

        assert!(
            shared.lookup_pin(&fp(b"one")).is_some(),
            "a broken reload must not drop existing pins"
        );
    }

    #[test]
    fn unparsable_pin_is_ignored_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        std::fs::write(
            &path,
            format!(
                "[[peer]]\nname = \"bad\"\nfingerprint = \"nonsense\"\naddress = \"\"\nadded_at = \"t\"\n\n\
                 [[peer]]\nname = \"good\"\nfingerprint = \"{}\"\naddress = \"\"\nadded_at = \"t\"\n",
                fp(b"good")
            ),
        )
        .unwrap();

        let shared = SharedTrustStore::open(&path).unwrap();
        assert_eq!(
            shared.lookup_pin(&fp(b"good")),
            Some(Principal::Device("good".into()))
        );
        assert_eq!(shared.snapshot().peers().len(), 2);
    }

    #[test]
    fn shared_store_opens_a_missing_file_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let shared = SharedTrustStore::open(dir.path().join("trust.toml")).unwrap();
        assert!(shared.snapshot().peers().is_empty());
        assert!(shared.ca_roots().is_empty());
        assert_eq!(shared.lookup_pin(&fp(b"x")), None);
    }
}
