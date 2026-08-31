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
//! The pinned peers here are still the sole source of *identity* for every
//! host — [`TrustStore::resolve_host`] is one input `crate::ops::host`'s
//! `resolve_forward` layers `crate::hosts::HostsFile` over for `qsh exec
//! <host>`'s host → address resolution (`PLAN.md` M7 Step 3, §4.1 #4,
//! `docs/CLI.md` §6.8): `hosts.toml` may supply or override the *address*,
//! but never the fingerprint — a peer's identity is decided here alone.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::SystemTime;

use qsh_proto::{ErrorCode, TrustPeer};
use qsh_transport::{CertificateDer, Fingerprint, Principal, TrustEvaluator};
use serde::{Deserialize, Serialize};

use crate::config::{config_io_error, ensure_private_dir, write_private_file};
use crate::identity::pem;
use crate::ops::OpError;

pub mod pairing;
pub use pairing::SharedInviteStore;

/// A private CA root the verifier accepts chains against.
///
/// Written by `qsh cert issue` (`docs/adr/0008-private-ca-cert-issuance.md`,
/// `PLAN.md` M7 Step 5) via [`TrustStore::add_ca`], and equally loadable
/// from an operator-provisioned `trust.toml` that was never touched by
/// `qsh cert` at all — this store only ever *evaluates* `[[ca]]` entries,
/// it never assumes how one got here.
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
        match read_raw(path)? {
            Some(text) => Self::parse(path, &text),
            None => Ok(Self::default()),
        }
    }

    /// Parse `text` (already-read bytes at `path`, used only for error
    /// messages). Split out of [`TrustStore::load`] so
    /// [`SharedTrustStore::refresh`] can reuse it without re-reading a file
    /// it already has in hand — the content it just read *is* the
    /// invalidation check (`PLAN.md` M7 Step 2 P2-2), so by the time this
    /// runs the bytes are already sitting in memory.
    fn parse(path: &Path, text: &str) -> Result<Self, OpError> {
        let file: TrustFile = toml::from_str(text).map_err(|err| {
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

    /// Acquire the cross-process advisory lock guarding `path`'s whole
    /// read-modify-write cycle (`PLAN.md` M7 Step 7-1). Every caller must
    /// acquire this **before** [`TrustStore::load`] and hold the returned
    /// guard until after [`TrustStore::save`] — locking only around the
    /// write (the pre-Step-7-1 state) still lets two writers each load a
    /// stale copy, mutate it, and have the later `save` silently discard
    /// the earlier writer's change. Two scenarios this closes:
    ///
    /// - **S1** (lost update): a `qsh serve` pairing response loads
    ///   `trust.toml`, and while it is composing its own save a concurrent
    ///   `qsh trust remove` finishes its own load→mutate→save first — the
    ///   pairing response's save then overwrites the file with a copy
    ///   that still has the just-removed peer in it, silently resurrecting
    ///   a pin the operator just revoked.
    /// - **S3** (file corruption): two pairing responses land on the same
    ///   `qsh serve` process at once (`tokio::spawn` per connection) and
    ///   both reach `TrustStore::save` around the same time — without a
    ///   cross-writer lock, [`crate::config::write_private_file_io`]'s
    ///   writer-scoped temp ticket keeps their temp files from colliding,
    ///   but the two renames can still interleave so that whichever loses
    ///   the race clobbers the winner's just-written file with its own
    ///   stale copy.
    ///
    /// **Lock order**: any `RwLock`/`Mutex` the caller already holds must
    /// be acquired **before** this call, never after — see
    /// [`crate::config::FileLock`]'s own doc for why reversing it risks a
    /// deadlock.
    pub(crate) fn lock(path: &Path) -> Result<crate::config::FileLock, OpError> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        crate::config::FileLock::acquire(&crate::config::lock_path_for(path))
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

    /// This store's own half of host → address resolution: only peers
    /// that actually carry a dial address resolve. `crate::ops::host`'s
    /// `resolve_forward` (`PLAN.md` M7 Step 3) is what layers
    /// `hosts.toml` over this — callers that need the *actual* resolution
    /// `qsh exec <host>`/`qsh <host>` use should go through that, not
    /// this method directly, unless they deliberately want the
    /// trust-only view (e.g. `forward_hosts`' own name enumeration).
    pub fn resolve_host(&self, name: &str) -> Option<&TrustPeer> {
        self.find(name).filter(|p| !p.address.is_empty())
    }

    /// Pin `name`, idempotently — with one deliberate exception (`PLAN.md`
    /// M7 Step 2 decision B): re-adding an already-pinned name under the
    /// *same* fingerprint but a *different* `address` overwrites the
    /// stored address in place (the M6 mobility campaign's backlog item —
    /// a host that changed its reachable address had no way to update a
    /// client's pin short of `remove` + `add`).
    ///
    /// Returns `(peer, created, updated)`:
    /// - **New name:** `created = true`, `updated = false`, `peer` is the
    ///   freshly written pin.
    /// - **Existing name, same fingerprint, address unchanged (or none
    ///   given):** a pure no-op — `created = false`, `updated = false`,
    ///   `peer` is the existing entry, untouched.
    /// - **Existing name, same fingerprint, a different address given:**
    ///   the stored address is overwritten in place — `created = false`,
    ///   `updated = true`, `peer` is the entry with its new address.
    ///   `added_at` is left as it was (it records when the *identity* was
    ///   first pinned, not when the address last changed).
    /// - **Existing name, a *different* fingerprint:** nothing changes at
    ///   all — `created = false`, `updated = false`, `peer` is the existing
    ///   entry, untouched. Re-binding an identity is a deliberate operator
    ///   action (remove, then add), never a side effect of a repeated
    ///   `trust add` (`docs/CLI.md` §6.11).
    pub fn add_peer(
        &mut self,
        name: impl Into<String>,
        address: Option<String>,
        fingerprint: Fingerprint,
        now: String,
    ) -> (TrustPeer, bool, bool) {
        let name = name.into();
        let fingerprint = fingerprint.to_string();
        if let Some(existing) = self.find(&name) {
            if existing.fingerprint != fingerprint {
                return (existing.clone(), false, false);
            }
            let Some(new_address) = address else {
                return (existing.clone(), false, false);
            };
            if existing.address == new_address {
                return (existing.clone(), false, false);
            }
            let index = self
                .peers
                .iter()
                .position(|p| p.name == name)
                .expect("just found by find()");
            self.peers[index].address = new_address;
            return (self.peers[index].clone(), false, true);
        }
        let peer = TrustPeer {
            name,
            fingerprint,
            address: address.unwrap_or_default(),
            added_at: now,
        };
        self.peers.push(peer.clone());
        (peer, true, false)
    }

    /// Register a private CA root, idempotently (`qsh cert issue`,
    /// `docs/adr/0008-private-ca-cert-issuance.md` §6 결과: "trust.toml
    /// [[ca]] 등재는 additive·append-only이며 중복 방지·갱신 semantics는
    /// trust add(Step 2) 선례를 따른다") — the same created/updated shape
    /// as [`TrustStore::add_peer`], keyed on `name` instead of
    /// fingerprint since a CA root has no principal of its own.
    ///
    /// Returns `(entry, created, updated)`:
    /// - **New name:** `created = true`, `updated = false`.
    /// - **Existing name, identical `cert_pem`:** a pure no-op —
    ///   `created = false`, `updated = false`. Re-running `qsh cert issue`
    ///   against the same local CA never rewrites `trust.toml`.
    /// - **Existing name, a different `cert_pem`:** the stored PEM is
    ///   overwritten in place — `created = false`, `updated = true`. This
    ///   only happens by construction from a *local* re-init of the CA
    ///   under the same name; nothing here fetches or trusts a remote
    ///   root on the strength of a name match.
    pub fn add_ca(&mut self, name: impl Into<String>, cert_pem: String) -> (CaEntry, bool, bool) {
        let name = name.into();
        if let Some(index) = self.cas.iter().position(|ca| ca.name == name) {
            if self.cas[index].cert_pem == cert_pem {
                return (self.cas[index].clone(), false, false);
            }
            self.cas[index].cert_pem = cert_pem;
            return (self.cas[index].clone(), false, true);
        }
        let entry = CaEntry { name, cert_pem };
        self.cas.push(entry.clone());
        (entry, true, false)
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
    /// The exact on-disk text this snapshot was parsed from (`None` for a
    /// missing file). This — not `mtime` — is the final arbiter of whether
    /// [`SharedTrustStore::refresh`] reloads: it is compared byte-for-byte
    /// on *every* refresh call. A filesystem with 1-2s mtime resolution
    /// (HFS+, exFAT/FAT, some SMB/NFS mounts) can otherwise leave a
    /// same-tick content change invisible to an mtime-only check
    /// (`PLAN.md` M7 Step 2 P2-2) — `trust.toml` is small enough that
    /// reading it in full on every handshake costs nothing next to the TLS
    /// handshake that triggers it.
    raw: Option<String>,
    /// Last observed mtime. No longer gates a reload (`raw` does); kept
    /// only as non-load-bearing metadata.
    mtime: Option<SystemTime>,
    store: TrustStore,
    pins: Vec<(Fingerprint, Principal)>,
    cas: Vec<CertificateDer<'static>>,
}

impl Cached {
    fn new(raw: Option<String>, mtime: Option<SystemTime>, store: TrustStore) -> Self {
        Self {
            pins: store.parsed_pins(),
            cas: store.parsed_cas(),
            store,
            raw,
            mtime,
        }
    }
}

/// A process-wide, reload-on-change view of `trust.toml` that satisfies
/// [`TrustEvaluator`].
///
/// The file's full content is read and compared on every lookup, and the
/// store is re-parsed whenever that content differs from the cached
/// snapshot — not merely when `mtime` moves (`PLAN.md` M7 Step 2 P2-2: an
/// mtime-only check is fail-open on a 1-2s-resolution filesystem, where two
/// edits inside the same tick share an mtime). `trust.toml` is small, so
/// this costs nothing next to the TLS handshake that triggers it. `qsh
/// trust add`/`remove` on a *running* `qsh serve` therefore takes effect
/// without a restart, deterministically, regardless of filesystem mtime
/// resolution. A failed reload keeps the last good snapshot (a
/// half-written file must not silently un-trust every peer); it never
/// *widens* trust, because widening requires a successful parse.
pub struct SharedTrustStore {
    path: PathBuf,
    cache: RwLock<Cached>,
    /// Set once, after construction, by [`SharedTrustStore::attach_pairing`]
    /// — never at `open()` time, because the pairing store is optional
    /// (only `qsh serve` wires one; a one-shot dial like `probe_fingerprint`
    /// never does) and because `Server::new`'s existing call sites must not
    /// change shape (`PLAN.md` M7 Step 4, same `OnceLock`-after-construction
    /// pattern `crate::server::Server` uses for its own pairing store).
    /// `pairing_open()` answers `false` whenever this is unset — identical
    /// to `TrustEvaluator::pairing_open`'s own default, so an evaluator that
    /// never attaches one behaves exactly as it did before this step.
    pairing: OnceLock<Arc<SharedInviteStore>>,
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
        let raw = read_raw(&path)?;
        let store = match &raw {
            Some(text) => TrustStore::parse(&path, text)?,
            None => TrustStore::default(),
        };
        Ok(Arc::new(Self {
            cache: RwLock::new(Cached::new(raw, mtime_of(&path), store)),
            path,
            pairing: OnceLock::new(),
        }))
    }

    /// The file this view is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Wire an invite store into this trust view's
    /// [`TrustEvaluator::pairing_open`] answer (`qsh serve`'s startup path,
    /// `PLAN.md` M7 Step 4). A no-op past the first call — matching every
    /// other `OnceLock`-after-construction seam in this step (`Server`'s own
    /// pairing store): a `Server`/`SharedTrustStore` is built once per
    /// process, so "attach exactly once, right after construction" is the
    /// only shape that matters in practice.
    pub fn attach_pairing(&self, store: Arc<SharedInviteStore>) {
        let _ = self.pairing.set(store);
    }

    /// A copy of the current (possibly reloaded) store contents.
    pub fn snapshot(&self) -> TrustStore {
        self.refresh();
        self.read().store.clone()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Cached> {
        self.cache.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Re-read `trust.toml` if its on-disk *content* differs from the
    /// cached snapshot. Compared in full on every call — not gated on
    /// `mtime` — because `lookup_pin`/`ca_roots` call this on every TLS
    /// handshake and a coarse-granularity filesystem's mtime can miss a
    /// same-tick edit (`PLAN.md` M7 Step 2 P2-2). A read failure other
    /// than "file does not exist" (e.g. a permissions change) keeps the
    /// last good snapshot rather than un-trusting everyone; a missing file
    /// reloads as an empty store — fail-closed, mirroring
    /// [`TrustStore::load`]'s own contract.
    fn refresh(&self) {
        let raw = match read_raw(&self.path) {
            Ok(raw) => raw,
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %err,
                    "failed to read the trust store for a refresh; keeping the last good snapshot"
                );
                return;
            }
        };
        // Double-checked: a cheap read-lock check first (the common case,
        // where nothing changed), then re-check under the write lock in
        // case another thread already applied the same reload.
        if self.read().raw == raw {
            return;
        }
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if cache.raw == raw {
            return;
        }
        let parsed = match &raw {
            Some(text) => TrustStore::parse(&self.path, text),
            None => Ok(TrustStore::default()),
        };
        match parsed {
            Ok(store) => {
                // Content changed (we would not be here otherwise) but the
                // mtime did not move: the coarse-granularity-filesystem
                // scenario P2-2 identified. Not actionable — the content
                // check already caught it — but worth a trace for whoever
                // is debugging a filesystem that behaves this way.
                let new_mtime = mtime_of(&self.path);
                if new_mtime.is_some() && new_mtime == cache.mtime {
                    tracing::debug!(
                        path = %self.path.display(),
                        "trust store content changed with no mtime movement \
                         (coarse filesystem mtime resolution?); reloaded anyway"
                    );
                }
                *cache = Cached::new(raw, new_mtime, store);
            }
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

/// Read `path` in full. A missing file is `Ok(None)` (an empty store, not
/// an error, mirroring [`TrustStore::load`]'s contract); any other read
/// failure is `Err`.
fn read_raw(path: &Path) -> Result<Option<String>, OpError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(config_io_error(path, "read", &err)),
    }
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

    /// `true` iff an invite store is attached ([`Self::attach_pairing`])
    /// and it currently reports at least one record within its retention
    /// window (`crate::trust::pairing`'s module doc) — `false` (the trait's
    /// own default) when nothing is attached at all, e.g. a one-shot dial
    /// evaluator that never calls `attach_pairing`.
    fn pairing_open(&self) -> bool {
        match self.pairing.get() {
            Some(store) => store.pairing_open(SystemTime::now()),
            None => false,
        }
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

        let (peer, created, updated) = store.add_peer(
            "mac",
            Some("mac.example:4433".into()),
            fp(b"one"),
            "2026-08-17T00:00:00Z".into(),
        );
        assert!(created);
        assert!(!updated);
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
    fn re_adding_with_the_same_address_is_a_pure_no_op() {
        let mut store = TrustStore::default();
        let (first, created, updated) = store.add_peer(
            "mac",
            Some("a:1".into()),
            fp(b"one"),
            "2026-08-17T00:00:00Z".into(),
        );
        assert!(created);
        assert!(!updated);

        // Same fingerprint, same address again.
        let (again, created, updated) = store.add_peer(
            "mac",
            Some("a:1".into()),
            fp(b"one"),
            "2026-08-18T00:00:00Z".into(),
        );
        assert!(!created);
        assert!(!updated);
        assert_eq!(again, first);
    }

    /// A *different* fingerprint must not silently re-pin, and must not
    /// touch the stored address either — a fingerprint mismatch is a hard
    /// no-op on the whole entry (`PLAN.md` M7 Step 2 decision B: identity
    /// rebind is a deliberate `remove` + `add`, never a side effect).
    #[test]
    fn re_adding_with_a_different_fingerprint_never_overwrites() {
        let mut store = TrustStore::default();
        let (first, ..) = store.add_peer(
            "mac",
            Some("a:1".into()),
            fp(b"one"),
            "2026-08-17T00:00:00Z".into(),
        );

        let (conflicting, created, updated) = store.add_peer(
            "mac",
            Some("b:2".into()),
            fp(b"two"),
            "2026-08-19T00:00:00Z".into(),
        );
        assert!(!created);
        assert!(!updated);
        assert_eq!(conflicting, first);
        assert_eq!(store.peers().len(), 1);
        assert_eq!(
            store.find("mac").unwrap().fingerprint,
            fp(b"one").to_string()
        );
        assert_eq!(store.find("mac").unwrap().address, "a:1");
    }

    /// M7 Step 2 decision B, the address-refresh path itself: same name,
    /// same fingerprint, a *different* address overwrites the stored
    /// address in place — the M6 mobility campaign backlog item (host
    /// address changed; a client re-runs `trust add` with the same
    /// identity to follow it) reproduced at the `TrustStore` level.
    #[test]
    fn re_adding_with_the_same_fingerprint_and_a_new_address_updates_in_place() {
        let mut store = TrustStore::default();
        let (first, created, updated) = store.add_peer(
            "mac",
            Some("old.example:4433".into()),
            fp(b"one"),
            "2026-08-17T00:00:00Z".into(),
        );
        assert!(created);
        assert!(!updated);

        let (moved, created, updated) = store.add_peer(
            "mac",
            Some("new.example:5555".into()),
            fp(b"one"),
            "2026-08-19T00:00:00Z".into(),
        );
        assert!(!created, "identity already pinned — never re-created");
        assert!(updated, "address must be reported as updated");
        assert_eq!(moved.address, "new.example:5555");
        assert_eq!(moved.name, first.name);
        assert_eq!(moved.fingerprint, first.fingerprint);
        // `added_at` records when the *identity* was first pinned, not
        // when the address last moved — untouched by the update.
        assert_eq!(moved.added_at, first.added_at);
        assert_eq!(store.peers().len(), 1, "still one entry, not a duplicate");
        assert_eq!(store.find("mac"), Some(&moved));

        // Omitting `--address` entirely on a further re-add must not clear
        // the address back out — only an explicit *different* address
        // triggers the update path.
        let (unchanged, created, updated) =
            store.add_peer("mac", None, fp(b"one"), "2026-08-20T00:00:00Z".into());
        assert!(!created);
        assert!(!updated);
        assert_eq!(unchanged.address, "new.example:5555");
    }

    /// [`TrustStore::add_ca`]'s own created/updated tri-state, mirroring
    /// [`TrustStore::add_peer`]'s tests: new name creates, same name +
    /// identical PEM is a pure no-op, same name + a different PEM updates
    /// in place (`docs/adr/0008-private-ca-cert-issuance.md` §6).
    #[test]
    fn add_ca_creates_then_is_idempotent_then_updates_on_a_changed_pem() {
        let mut store = TrustStore::default();
        assert!(store.cas().is_empty());

        let pem_a = pem::encode(pem::CERTIFICATE, b"root a");
        let (entry, created, updated) = store.add_ca("local", pem_a.clone());
        assert!(created);
        assert!(!updated);
        assert_eq!(entry.name, "local");
        assert_eq!(entry.cert_pem, pem_a);
        assert_eq!(store.cas().len(), 1);

        // Same name, identical PEM again: a pure no-op.
        let (again, created, updated) = store.add_ca("local", pem_a.clone());
        assert!(!created);
        assert!(!updated);
        assert_eq!(again, entry);
        assert_eq!(store.cas().len(), 1);

        // Same name, a different PEM: overwritten in place, not duplicated.
        let pem_b = pem::encode(pem::CERTIFICATE, b"root b");
        let (moved, created, updated) = store.add_ca("local", pem_b.clone());
        assert!(!created, "same name — never re-created");
        assert!(
            updated,
            "a changed PEM under the same name must be reported as updated"
        );
        assert_eq!(moved.name, "local");
        assert_eq!(moved.cert_pem, pem_b);
        assert_eq!(store.cas().len(), 1, "still one entry, not a duplicate");
        assert_eq!(store.cas()[0].cert_pem, pem_b);
    }

    /// A distinct name never collides with an existing one, even if it
    /// happens to carry the identical PEM (a name, not a fingerprint, is
    /// the dedup key — a CA root has no principal of its own).
    #[test]
    fn add_ca_with_a_distinct_name_never_collides() {
        let mut store = TrustStore::default();
        let pem = pem::encode(pem::CERTIFICATE, b"shared root bytes");
        store.add_ca("local", pem.clone());
        let (entry, created, updated) = store.add_ca("partner", pem.clone());
        assert!(created);
        assert!(!updated);
        assert_eq!(entry.name, "partner");
        assert_eq!(store.cas().len(), 2);
    }

    #[test]
    fn address_is_empty_when_absent_and_does_not_resolve_as_a_host() {
        let mut store = TrustStore::default();
        let (peer, ..) = store.add_peer("client-only", None, fp(b"c"), "t".into());
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

    /// **`PLAN.md` M7 Step 2 P2-2, regression.** An mtime-only invalidator
    /// is fail-open on a coarse-granularity filesystem (HFS+, exFAT/FAT,
    /// some SMB/NFS mounts, 1-2s resolution): two edits landing in the same
    /// tick share an mtime, so a check gated on `mtime != cached_mtime`
    /// alone would never notice the second edit. This pins the file's mtime
    /// back to its pre-edit value with [`std::fs::FileTimes`] — simulating
    /// exactly that collision deterministically, no timing dependency — and
    /// asserts the reload happens anyway, because `refresh` now compares
    /// full file *content* on every call, never gated on `mtime`.
    #[test]
    fn refresh_reloads_on_a_content_change_even_when_the_mtime_does_not_move() {
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

        // The mtime the store was opened with — the value a same-tick edit
        // on a coarse filesystem would collide on.
        let pinned_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();

        // Different content (peer "second" instead of "first"), written
        // normally (so its natural mtime is "now", not `pinned_mtime`)...
        let mut store2 = TrustStore::default();
        store2.add_peer("second", None, fp(b"two"), "t".into());
        store2.save(&path).unwrap();

        // ...then pinned back to the exact mtime the cache already has,
        // reproducing the same-tick collision without depending on the
        // filesystem's actual timestamp resolution or any sleep.
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(pinned_mtime))
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            pinned_mtime,
            "test setup: the mtime must be pinned back to the cached value"
        );

        // mtime is unchanged from the cached snapshot; content is not. The
        // reload must still happen — content is the final arbiter.
        assert_eq!(
            shared.lookup_pin(&fp(b"one")),
            None,
            "a same-mtime content change must drop the old pin"
        );
        assert_eq!(
            shared.lookup_pin(&fp(b"two")),
            Some(Principal::Device("second".into())),
            "a same-mtime content change must pick up the new pin"
        );
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

    /// Regression for `PLAN.md` M7 Step 7-1's S1/general lost-update fix:
    /// 8 threads, each doing a full `TrustStore::lock` → `load` →
    /// `add_peer` → `save` cycle for a distinct peer, must not lose each
    /// other's addition. Locking only around `save` (the pre-Step-7-1
    /// state) would let a later writer's `save` silently overwrite an
    /// earlier writer's still-unseen addition with a stale copy —
    /// mirrors `crate::resume`'s own
    /// `concurrent_writers_do_not_lose_each_others_entries`, the
    /// precedent this lock was lifted from.
    #[test]
    fn concurrent_full_rmw_cycles_do_not_lose_each_others_peers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let mut threads = Vec::new();
        for i in 0..8u8 {
            let path = path.clone();
            threads.push(std::thread::spawn(move || {
                let _lock = TrustStore::lock(&path).unwrap();
                let mut store = TrustStore::load(&path).unwrap();
                store.add_peer(
                    format!("peer-{i}"),
                    None,
                    fp(&[i; 4]),
                    "2026-08-17T00:00:00Z".into(),
                );
                store.save(&path).unwrap();
            }));
        }
        for t in threads {
            t.join().expect("writer");
        }
        let final_store = TrustStore::load(&path).unwrap();
        assert_eq!(
            final_store.peers().len(),
            8,
            "a concurrent read-modify-write lost a peer"
        );
    }

    /// Regression for `PLAN.md` M7 Step 7-1's S1 scenario specifically: a
    /// pairing response's `add_peer` and an operator's concurrent `trust
    /// remove` must not race into "the removed peer comes back" — the
    /// worst outcome on this step's list, a revoked trust decision
    /// silently un-revoking itself. This is the `TrustStore`-level
    /// equivalent of the real race (`qsh serve`'s pairing responder vs. a
    /// `qsh trust remove` CLI process); driving the actual server accept
    /// loop concurrently with a CLI subprocess is integration-test
    /// territory this crate's unit tests don't reach.
    #[test]
    fn a_concurrent_add_never_resurrects_a_concurrent_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");

        let mut seed = TrustStore::default();
        seed.add_peer(
            "old-laptop",
            None,
            fp(b"old"),
            "2026-08-17T00:00:00Z".into(),
        );
        seed.save(&path).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let remover = {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let _lock = TrustStore::lock(&path).unwrap();
                let mut store = TrustStore::load(&path).unwrap();
                store.remove("old-laptop");
                store.save(&path).unwrap();
            })
        };
        let adder = {
            let path = path.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let _lock = TrustStore::lock(&path).unwrap();
                let mut store = TrustStore::load(&path).unwrap();
                store.add_peer(
                    "new-device",
                    None,
                    fp(b"new"),
                    "2026-08-17T00:00:01Z".into(),
                );
                store.save(&path).unwrap();
            })
        };
        remover.join().expect("remover");
        adder.join().expect("adder");

        let final_store = TrustStore::load(&path).unwrap();
        assert!(
            final_store.find("old-laptop").is_none(),
            "a removed peer was resurrected by a concurrent pairing write"
        );
        assert!(
            final_store.find("new-device").is_some(),
            "a concurrent addition was lost"
        );
    }

    /// Regression for `PLAN.md` M7 Step 7-1's file-corruption fix in
    /// `crate::config::write_private_file_io` (the writer-scoped temp
    /// ticket): many concurrent `save` calls racing the very same path,
    /// deliberately **without** `TrustStore::lock` — every real call site
    /// now holds it, but this isolates the temp-file ticket's own
    /// guarantee from the lock's. Before the ticket, every writer shared
    /// the same `.tmp<pid>` name: whichever writer's `rename` lost the
    /// race hit `ENOENT` (its target already moved by the winner) rather
    /// than a merely lost update, and depending on how the two writers'
    /// writes interleaved on that one shared inode before either
    /// renamed, the file that *did* land could carry bytes from more
    /// than one writer — a corrupt `trust.toml`, not just a stale one.
    ///
    /// Repeated 16 times (fresh path each round): a standalone reproduction
    /// outside this repo (`PLAN.md` M7 Step 7-1 검증 라운드 A5) measured the
    /// per-round corruption rate at 8/40 (20%) once the ticket is removed —
    /// a single round only catches a reverted ticket about 4 times out of
    /// 5. 16 independent rounds raise that to `1 - 0.8^16 ≈ 97%`, without
    /// which this test's pass/fail is closer to a coin flip than a
    /// regression gate for the one property this diff is graded on.
    #[test]
    fn concurrent_saves_to_the_same_path_never_corrupt_the_file() {
        let dir = tempfile::tempdir().unwrap();
        const WRITERS: u8 = 24;
        const ROUNDS: u32 = 16;

        for round in 0..ROUNDS {
            let path = dir.path().join(format!("trust-{round}.toml"));

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS as usize));
            let mut threads = Vec::new();
            for i in 0..WRITERS {
                let path = path.clone();
                let barrier = barrier.clone();
                threads.push(std::thread::spawn(move || {
                    let mut store = TrustStore::default();
                    for j in 0..32u8 {
                        store.add_peer(
                            format!("round-{round}-writer-{i}-peer-{j}"),
                            None,
                            fp(&[i, j]),
                            "2026-08-17T00:00:00Z".into(),
                        );
                    }
                    barrier.wait();
                    store.save(&path).unwrap();
                    store
                }));
            }
            let candidates: Vec<TrustStore> = threads
                .into_iter()
                .map(|t| t.join().expect("writer"))
                .collect();

            let final_store = TrustStore::load(&path)
                .expect("the file must always be valid, parseable TOML, never corrupted");
            assert!(
                candidates.contains(&final_store),
                "round {round}: final trust.toml matches none of the writers exactly — \
                 bytes from two writers were interleaved into it"
            );
        }
    }
}
