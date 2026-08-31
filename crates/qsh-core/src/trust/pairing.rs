//! Open pairing invites (`<config_dir>/invites.toml`, ADR-0002, `PLAN.md`
//! M7 Step 4, `docs/design/protocol.md` §15).
//!
//! `qsh trust invite` mints a 160-bit CSPRNG secret
//! ([`qsh_proto::pairing::INVITE_SECRET_LEN`]), displays it to the operator
//! as a Crockford Base32 code, and persists **only**
//! `mac_key = blake3::hash(secret)` here — the raw secret is never written
//! to disk (`docs/CLI.md` §6.11). `qsh trust accept <address> <code>`
//! re-derives `mac_key` from the code it was given and proves possession of
//! it over a TLS-exporter-bound channel (`crate::pairing`, the wire
//! exchange this store backs); this module only owns the invite's
//! lifecycle: creation, lookup-by-proof, single-use consumption, and expiry.
//!
//! ```toml
//! [[invite]]
//! mac_key = "BASE64(blake3::hash(secret))"
//! created_at = "2026-08-31T00:00:00Z"
//! consumed_at = "2026-08-31T00:03:00Z"   # absent while still open
//! ```
//!
//! **Lifecycle.** A record is *redeemable* for [`INVITE_TTL`] (10 minutes)
//! from `created_at`. It is not deleted the instant it expires or is
//! consumed — it is kept until [`INVITE_RETENTION`] (20 minutes total from
//! creation: one full TTL of validity, plus one more TTL of "expired/
//! consumed but still answerable") has passed, so a proof that arrives for
//! an already-expired or already-consumed invite still gets a specific,
//! distinguishable answer (`TRUST_REQUIRED`/`SESSION_CONFLICT`, decided by
//! [`SharedInviteStore::redeem`]'s caller) instead of an opaque "no such
//! invite". [`SharedInviteStore::pairing_open`] — the
//! [`qsh_transport::TrustEvaluator::pairing_open`] answer — is `true` for
//! that entire retention window, not just the shorter TTL window: this is
//! deliberately broader than "there is a currently redeemable invite",
//! because it is what lets a proof that arrives just after expiry or reuse
//! still reach [`SharedInviteStore::redeem`] at all (a `pairing_open() ==
//! false` peer never gets past the TLS handshake to receive any answer).
//! This is safe regardless of how long the window stays open: a connection
//! admitted only via the pairing fallback (`Principal::Pairing`) can never
//! reach any resource other than the one pairing exchange itself
//! (`crate::server::Server::serve_pairing_connection`) — see that method's
//! own doc for the structural argument.
//!
//! Reload-on-change follows exactly [`super::SharedTrustStore`]'s
//! content-based (not mtime-based) precedent: a running `qsh serve` picks
//! up a freshly written invite, or a just-consumed one, without a restart
//! (`PLAN.md` M7 Step 2 P2-2, invariant #6 of this step's brief).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_proto::ErrorCode;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::config::{config_io_error, ensure_private_dir, write_private_file};
use crate::ops::OpError;

/// How long a fresh invite is redeemable (ADR-0002 design values,
/// `docs/CLI.md` §6.11).
pub const INVITE_TTL: Duration = Duration::from_secs(10 * 60);

/// Total on-disk lifetime of a record from `created_at` — see the module
/// doc's "Lifecycle" paragraph for why this is longer than [`INVITE_TTL`].
pub const INVITE_RETENTION: Duration = Duration::from_secs(20 * 60);

/// Domain-separation suffixes appended to the exported keying material
/// before each direction's proof is derived (`docs/design/protocol.md`
/// §15). Without this, `PairingProof.proof` and `PairingAccepted.proof`
/// would be the *same* value on a genuine connection (identical `mac_key`,
/// identical exporter output), which a rogue responder could trivially
/// "produce" by echoing the initiator's own bytes straight back — no
/// knowledge of the secret required. Distinct suffixes mean only a party
/// that actually holds `mac_key` can compute either direction's proof.
const CLIENT_PROOF_DOMAIN: u8 = 0x01;
const SERVER_PROOF_DOMAIN: u8 = 0x02;

fn proof_input(exported_keying_material: &[u8], domain: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(exported_keying_material.len() + 1);
    v.extend_from_slice(exported_keying_material);
    v.push(domain);
    v
}

/// `blake3(secret)` — the only form of an invite's secret this store ever
/// holds. 32 bytes, same width as [`blake3::Hash`] and the key
/// `blake3::keyed_hash` requires.
#[derive(Clone, Copy)]
struct MacKey([u8; 32]);

impl MacKey {
    fn of(secret: &[u8]) -> Self {
        Self(*blake3::hash(secret).as_bytes())
    }

    fn to_base64(self) -> String {
        BASE64.encode(self.0)
    }

    fn from_base64(text: &str) -> Option<Self> {
        let bytes = BASE64.decode(text).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    /// The proof a party holding this key derives for `domain`
    /// ([`CLIENT_PROOF_DOMAIN`] or [`SERVER_PROOF_DOMAIN`]) over the given
    /// TLS exporter value.
    fn proof(self, exported_keying_material: &[u8], domain: u8) -> [u8; 32] {
        *blake3::keyed_hash(&self.0, &proof_input(exported_keying_material, domain)).as_bytes()
    }
}

/// Compute both directions' proofs directly from a raw invite secret — the
/// initiator's own path (`crate::pairing`'s `AcceptAnyForPairing` dial): it
/// holds the secret in plaintext (from `qsh trust accept`'s `<code>`
/// argument), never a stored [`MacKey`]. Returns `(client_proof,
/// server_proof)`: the initiator sends `client_proof` in its own
/// `PairingProof.proof` and must verify the responder's
/// `PairingAccepted.proof` against `server_proof` — constant-time, and
/// **before** pinning anything (see [`PairingAccepted`]'s own doc in
/// `v1.proto` for why this check is not optional).
pub fn proofs_from_secret(secret: &[u8], exported_keying_material: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mac_key = MacKey::of(secret);
    (
        mac_key.proof(exported_keying_material, CLIENT_PROOF_DOMAIN),
        mac_key.proof(exported_keying_material, SERVER_PROOF_DOMAIN),
    )
}

impl std::fmt::Debug for MacKey {
    /// Redacted: this derives the pairing proof, so it is treated as key
    /// material even though it is itself already a one-way hash of the
    /// secret (`architecture.md` §5: never log key material).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MacKey(<redacted>)")
    }
}

impl ConstantTimeEq for MacKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// One invite, on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InviteRecordFile {
    mac_key: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed_at: Option<String>,
}

/// `invites.toml` as serialized.
#[derive(Debug, Default, Serialize, Deserialize)]
struct InviteFile {
    #[serde(default, rename = "invite", skip_serializing_if = "Vec::is_empty")]
    invites: Vec<InviteRecordFile>,
}

/// A parsed invite, with its timestamps as `SystemTime` for arithmetic.
#[derive(Clone)]
struct Record {
    mac_key: MacKey,
    created_at: SystemTime,
    consumed_at: Option<SystemTime>,
}

impl Record {
    fn redeemable(&self, now: SystemTime) -> bool {
        self.consumed_at.is_none()
            && now
                .duration_since(self.created_at)
                .is_ok_and(|age| age < INVITE_TTL)
    }

    fn within_retention(&self, now: SystemTime) -> bool {
        now.duration_since(self.created_at)
            .is_ok_and(|age| age < INVITE_RETENTION)
    }
}

/// An in-memory snapshot of the invite store.
#[derive(Default)]
pub struct InviteStore {
    records: Vec<InviteRecordFile>,
}

impl InviteStore {
    /// Load `path`. A missing file is an empty store, mirroring
    /// [`super::TrustStore::load`].
    pub fn load(path: &Path) -> Result<Self, OpError> {
        match read_raw(path)? {
            Some(text) => Self::parse(path, &text),
            None => Ok(Self::default()),
        }
    }

    fn parse(path: &Path, text: &str) -> Result<Self, OpError> {
        let file: InviteFile = toml::from_str(text).map_err(|err| {
            OpError::new(
                ErrorCode::ConfigError,
                format!("invalid invite store {}: {err}", path.display()),
            )
            .with_retryable(false)
        })?;
        Ok(Self {
            records: file.invites,
        })
    }

    /// Write the store to `path` (0600, in a 0700 directory, atomically).
    ///
    /// **Report F-9.** Two different *processes* read-modify-write this
    /// same file with no lock: a `qsh trust invite` CLI process
    /// (`Ops::trust_invite`'s load→prune→add→save) and a running `qsh
    /// serve`'s own [`SharedInviteStore::redeem`]. `write_private_file`'s
    /// pid-scoped-temp-file-plus-rename means a write can never be *torn*,
    /// but it does nothing to stop a *lost update*: without this merge, a
    /// `trust invite` process that read the file before `redeem` marked a
    /// record consumed, then saves its own (stale) in-memory copy after
    /// `redeem`'s write, would overwrite `redeem`'s `consumed_at` right
    /// back to unset — un-consuming an invite that already pinned a device.
    /// Immediately before writing, this re-reads whatever is currently on
    /// disk and merges it in: any record the caller doesn't know about yet
    /// (minted by the *other* writer since this copy was loaded) is kept
    /// rather than silently dropped, and a `consumed_at` already recorded
    /// on disk is never reverted to `None` by a writer whose own copy
    /// predates it (monotonic on consumption — a completed pairing is
    /// never allowed to un-happen).
    ///
    /// **Not a full fix.** This narrows the lost-update window to the gap
    /// between this merge-read and the write immediately following it,
    /// rather than closing it: two writers whose merge-reads both land
    /// before either one's write can still each observe the same
    /// pre-image and independently decide their own record is the winner.
    /// Real file locking is Step 7 debt (`PLAN.md` M7 (a)-추기 ③, carried
    /// forward from the M6 "trust store no-locking" item, now extended to
    /// `invites.toml` too).
    pub fn save(&mut self, path: &Path) -> Result<(), OpError> {
        self.merge_consumption_from_disk(path)?;
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        let file = InviteFile {
            invites: self.records.clone(),
        };
        let text = toml::to_string_pretty(&file).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("failed to encode invite store {}: {err}", path.display()),
            )
            .with_retryable(false)
        })?;
        write_private_file(path, text.as_bytes())
    }

    /// The merge step [`Self::save`]'s doc describes: re-read `path` and,
    /// keyed by `mac_key` (unique per invite — a fresh 160-bit CSPRNG
    /// secret per `qsh trust invite` call), (1) adopt any record present on
    /// disk but not in `self` **and still within [`INVITE_RETENTION`] of
    /// its `created_at`** (the other writer minted it after this copy was
    /// loaded — union, not silent drop) and (2) adopt disk's `consumed_at`
    /// for any record where `self`'s copy still has it unset (monotonic —
    /// never let a writer's stale "not yet consumed" view revert a
    /// consumption the other writer already recorded). A record this copy
    /// already believes is consumed is left exactly as this writer set it
    /// (the common case: this *is* the writer that just consumed it).
    ///
    /// The retention filter on (1) matters: without it, `Ops::trust_invite`'s
    /// own `prune()` (called immediately before every `add`/`save`) would
    /// be silently undone by this same merge — a record `prune()` just
    /// dropped from `self.records` for having aged out is still sitting on
    /// disk (the file hasn't been rewritten yet), so a naive "restore
    /// anything unknown to me" union would resurrect exactly what pruning
    /// just removed. Filtering to "still within retention" keeps the
    /// concurrently-minted-invite case (always freshly created, always
    /// within retention) while leaving a genuinely expired record dropped.
    fn merge_consumption_from_disk(&mut self, path: &Path) -> Result<(), OpError> {
        let Some(text) = read_raw(path)? else {
            return Ok(()); // nothing on disk yet — nothing to merge.
        };
        let disk = Self::parse(path, &text)?;
        let now = SystemTime::now();
        for disk_rec in &disk.records {
            match self
                .records
                .iter_mut()
                .find(|r| r.mac_key == disk_rec.mac_key)
            {
                Some(mine) => {
                    if mine.consumed_at.is_none() {
                        mine.consumed_at = disk_rec.consumed_at.clone();
                    }
                }
                None => {
                    let still_live = parse_rfc3339(&disk_rec.created_at).is_some_and(|created| {
                        now.duration_since(created)
                            .is_ok_and(|age| age < INVITE_RETENTION)
                    });
                    if still_live {
                        self.records.push(disk_rec.clone());
                    }
                }
            }
        }
        Ok(())
    }

    /// Drop every record whose [`INVITE_RETENTION`] window has passed.
    /// Called before every `add`/`save` so the file never grows unbounded
    /// (`qsh trust invite` is the only writer that prunes; the read-only,
    /// reload-on-change `SharedInviteStore` never persists).
    pub fn prune(&mut self, now: SystemTime) {
        self.records.retain(|r| {
            // An unparseable timestamp can never expire on its own — drop
            // it rather than let it linger forever.
            parse_rfc3339(&r.created_at).is_some_and(|created_at| {
                now.duration_since(created_at)
                    .is_ok_and(|age| age < INVITE_RETENTION)
            })
        });
    }

    /// Mint a fresh invite from `secret` (already generated by the caller —
    /// this store never generates the secret itself, so the raw bytes never
    /// pass through more layers than necessary before being zeroized).
    /// Returns the RFC 3339 `created_at`/`expires_at` pair.
    pub fn add(&mut self, secret: &[u8], now: SystemTime) -> (String, String) {
        let created_at = rfc3339_at(now);
        let expires_at = rfc3339_at(now + INVITE_TTL);
        self.records.push(InviteRecordFile {
            mac_key: MacKey::of(secret).to_base64(),
            created_at: created_at.clone(),
            consumed_at: None,
        });
        (created_at, expires_at)
    }

    fn parsed(&self) -> Vec<(usize, Record)> {
        self.records
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                let mac_key = MacKey::from_base64(&r.mac_key)?;
                let created_at = parse_rfc3339(&r.created_at)?;
                let consumed_at = r.consumed_at.as_deref().and_then(parse_rfc3339);
                Some((
                    i,
                    Record {
                        mac_key,
                        created_at,
                        consumed_at,
                    },
                ))
            })
            .collect()
    }
}

/// The outcome of a redemption attempt (`crate::pairing`'s wire exchange is
/// the only caller). Deliberately distinguishing — unlike a resume-token
/// redemption (`broker::resume::ResumeDenied`, single indistinguishable
/// failure by design), an invite's failure modes are meant to be
/// distinguishable: the secret space is 160 bits, so there is no
/// warmer/colder oracle concern from telling the caller *why* (this step's
/// brief, invariant #2 and report §B7/§B8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemOutcome {
    /// A live, unexpired, unconsumed record matched — now marked consumed.
    /// Carries this record's independently-derived server-direction proof
    /// (`SERVER_PROOF_DOMAIN`) for the caller to send back in
    /// `PairingAccepted.proof` — see that field's doc in `v1.proto` for why
    /// this, not an echo of the received proof, is what makes the exchange
    /// bidirectional.
    Accepted { server_proof: [u8; 32] },
    /// A live, unexpired, unconsumed record matched, but the caller's
    /// `on_matched` hook (`crate::pairing::respond`'s local-pin collision
    /// check, this step's brief invariant #5) declined it — the record is
    /// left exactly as it was: **not** marked consumed, so a renamed or
    /// removed conflicting pin can retry within the same invite's TTL.
    Rejected,
    /// The matching record's [`INVITE_TTL`] has already passed.
    Expired,
    /// The matching record was already consumed by an earlier redemption.
    AlreadyConsumed,
    /// No record (live or retained) matched this proof at all.
    NoMatch,
}

/// A process-wide, reload-on-change view of `invites.toml` that satisfies
/// [`qsh_transport::TrustEvaluator::pairing_open`] and answers redemption
/// attempts. See the module doc for the reload and retention contracts —
/// identical in shape to [`super::SharedTrustStore`].
pub struct SharedInviteStore {
    path: PathBuf,
    cache: RwLock<Cached>,
}

struct Cached {
    raw: Option<String>,
    store: InviteStore,
}

impl std::fmt::Debug for SharedInviteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedInviteStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SharedInviteStore {
    /// Open (and eagerly load) the invite store at `path`. A missing file
    /// is an empty store — `qsh serve` starts fine before any `qsh trust
    /// invite` has ever run.
    pub fn open(path: impl Into<PathBuf>) -> Result<Arc<Self>, OpError> {
        let path = path.into();
        let raw = read_raw(&path)?;
        let store = match &raw {
            Some(text) => InviteStore::parse(&path, text)?,
            None => InviteStore::default(),
        };
        Ok(Arc::new(Self {
            cache: RwLock::new(Cached { raw, store }),
            path,
        }))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Cached> {
        self.cache.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Re-read `invites.toml` if its content changed — see
    /// [`super::SharedTrustStore::refresh`]'s doc, same content-based
    /// contract, same rationale (`PLAN.md` M7 Step 2 P2-2).
    fn refresh(&self) {
        let raw = match read_raw(&self.path) {
            Ok(raw) => raw,
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %err,
                    "failed to read the invite store for a refresh; keeping the last good snapshot"
                );
                return;
            }
        };
        if self.read().raw == raw {
            return;
        }
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if cache.raw == raw {
            return;
        }
        let parsed = match &raw {
            Some(text) => InviteStore::parse(&self.path, text),
            None => Ok(InviteStore::default()),
        };
        match parsed {
            Ok(store) => *cache = Cached { raw, store },
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %err,
                    "failed to reload the invite store; keeping the last good snapshot"
                );
            }
        }
    }

    /// [`qsh_transport::TrustEvaluator::pairing_open`]'s answer: `true` iff
    /// at least one record is still within [`INVITE_RETENTION`] of its
    /// `created_at` — see the module doc for why this window, not the
    /// shorter TTL, is the right one.
    pub fn pairing_open(&self, now: SystemTime) -> bool {
        self.refresh();
        self.read()
            .store
            .parsed()
            .iter()
            .any(|(_, r)| r.within_retention(now))
    }

    /// Attempt to redeem `proof` (received over the wire) against every
    /// retained invite, using `exported_keying_material` (the TLS-exporter
    /// value this connection's own responder independently computed) to
    /// derive each candidate's expected proof.
    ///
    /// **Try-all, constant-time-compare-each**: no wire field names which
    /// invite is meant (`docs/design/protocol.md` §15's minimal wire
    /// schema), so every retained record is a candidate; the equality
    /// check itself is [`ConstantTimeEq`] so a match cannot be distinguished
    /// from a near-match by comparison timing (this step's brief, invariant
    /// #3).
    ///
    /// `on_matched` runs **after** a live, redeemable record's proof has
    /// verified but **before** it is marked consumed or saved — this is
    /// what lets `crate::pairing::respond` attempt its local pin (this
    /// step's brief invariant #5) and, on a name collision, decline via
    /// [`RedeemOutcome::Rejected`] while leaving the invite entirely
    /// untouched. It is called at most once, synchronously, with the store
    /// lock held — it must not block.
    ///
    /// On [`RedeemOutcome::Accepted`], the matching record is marked
    /// consumed and the store is persisted before this returns — the
    /// caller must not treat the invite as spent until it has this outcome
    /// in hand.
    pub fn redeem(
        &self,
        exported_keying_material: &[u8],
        client_proof: &[u8; 32],
        now: SystemTime,
        on_matched: impl FnOnce() -> bool,
    ) -> Result<RedeemOutcome, OpError> {
        self.refresh();
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        let candidates = cache.store.parsed();
        let matched = candidates.into_iter().find(|(_, r)| {
            let expected = r
                .mac_key
                .proof(exported_keying_material, CLIENT_PROOF_DOMAIN);
            bool::from(expected.ct_eq(client_proof)) && r.within_retention(now)
        });
        let Some((index, record)) = matched else {
            return Ok(RedeemOutcome::NoMatch);
        };
        if record.consumed_at.is_some() {
            return Ok(RedeemOutcome::AlreadyConsumed);
        }
        if !record.redeemable(now) {
            return Ok(RedeemOutcome::Expired);
        }
        if !on_matched() {
            return Ok(RedeemOutcome::Rejected);
        }
        let server_proof = record
            .mac_key
            .proof(exported_keying_material, SERVER_PROOF_DOMAIN);
        cache.store.records[index].consumed_at = Some(rfc3339_at(now));
        cache.store.save(&self.path)?;
        // Keep `cache.raw` in sync with what was just written so the next
        // `refresh()` sees no (spurious) external change.
        cache.raw = read_raw(&self.path)?;
        Ok(RedeemOutcome::Accepted { server_proof })
    }
}

fn read_raw(path: &Path) -> Result<Option<String>, OpError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(config_io_error(path, "read", &err)),
    }
}

/// `SystemTime` → RFC 3339, whole-second precision, same shape
/// [`crate::config::now_rfc3339`] produces.
fn rfc3339_at(at: SystemTime) -> String {
    time::OffsetDateTime::from(at)
        .replace_nanosecond(0)
        .unwrap_or_else(|_| at.into())
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// RFC 3339 → `SystemTime`, `None` if it does not parse. Mirrors
/// `crate::resume`'s private helper of the same shape.
fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(SystemTime::from)
}

/// A generated secret, zeroized on drop — the only place the raw bytes
/// exist before `qsh trust invite` prints the display code and returns.
pub type InviteSecret = Zeroizing<[u8; qsh_proto::pairing::INVITE_SECRET_LEN]>;

/// Mint a fresh 160-bit invite secret from the OS CSPRNG.
pub fn generate_secret() -> InviteSecret {
    use rand::RngCore as _;
    let mut bytes = Zeroizing::new([0u8; qsh_proto::pairing::INVITE_SECRET_LEN]);
    rand::rng().fill_bytes(bytes.as_mut());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(seed: u8) -> [u8; qsh_proto::pairing::INVITE_SECRET_LEN] {
        [seed; qsh_proto::pairing::INVITE_SECRET_LEN]
    }

    fn ekm(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    /// The client-direction proof `store.redeem` expects, via the same
    /// `proofs_from_secret` real callers (`crate::pairing`) use — not a
    /// hand-rolled recomputation, so a future change to the domain
    /// separation cannot silently desync the test fixture from production.
    fn client_proof_for(secret: &[u8], ekm: &[u8]) -> [u8; 32] {
        proofs_from_secret(secret, ekm).0
    }

    #[test]
    fn add_load_save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let now = SystemTime::now();

        let mut store = InviteStore::default();
        let (created_at, expires_at) = store.add(&secret(1), now);
        assert!(!created_at.is_empty());
        assert!(!expires_at.is_empty());
        store.save(&path).unwrap();

        let back = InviteStore::load(&path).unwrap();
        assert_eq!(back.records.len(), 1);
        assert_eq!(back.records[0].created_at, created_at);
        assert!(back.records[0].consumed_at.is_none());
    }

    #[test]
    fn redeem_accepts_a_correct_proof_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let now = SystemTime::now();
        let s = secret(7);
        let e = ekm(9);

        let mut store = InviteStore::default();
        store.add(&s, now);
        store.save(&path).unwrap();

        let shared = SharedInviteStore::open(&path).unwrap();
        assert!(shared.pairing_open(now));

        let (client_proof, expected_server_proof) = proofs_from_secret(&s, &e);
        match shared.redeem(&e, &client_proof, now, || true).unwrap() {
            RedeemOutcome::Accepted { server_proof } => {
                assert_eq!(
                    server_proof, expected_server_proof,
                    "the responder's returned proof must be the real, \
                     independently-derived server-direction value — never \
                     an echo of what the client sent"
                );
                assert_ne!(
                    server_proof, client_proof,
                    "client/server proofs must be domain-separated, not equal"
                );
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
        // Second attempt with the same proof: already consumed.
        assert_eq!(
            shared.redeem(&e, &client_proof, now, || true).unwrap(),
            RedeemOutcome::AlreadyConsumed
        );
    }

    #[test]
    fn redeem_leaves_the_invite_untouched_when_on_matched_declines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let now = SystemTime::now();
        let s = secret(11);
        let e = ekm(12);

        let mut store = InviteStore::default();
        store.add(&s, now);
        store.save(&path).unwrap();

        let shared = SharedInviteStore::open(&path).unwrap();
        let proof = client_proof_for(&s, &e);

        // A verified proof whose `on_matched` hook declines (the caller's
        // local-pin collision check, `crate::pairing::respond`) must not
        // consume the invite at all — this is what lets the operator
        // rename/remove the conflicting pin and retry within the same TTL
        // (this step's brief invariant #5).
        assert_eq!(
            shared.redeem(&e, &proof, now, || false).unwrap(),
            RedeemOutcome::Rejected
        );
        match shared.redeem(&e, &proof, now, || true).unwrap() {
            RedeemOutcome::Accepted { .. } => {}
            other => panic!("expected the still-live invite to redeem on retry, got {other:?}"),
        }
    }

    #[test]
    fn redeem_rejects_a_wrong_proof_as_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let now = SystemTime::now();

        let mut store = InviteStore::default();
        store.add(&secret(1), now);
        store.save(&path).unwrap();

        let shared = SharedInviteStore::open(&path).unwrap();
        let garbage = [0xAAu8; 32];
        assert_eq!(
            shared.redeem(&ekm(1), &garbage, now, || true).unwrap(),
            RedeemOutcome::NoMatch
        );
        // A failed attempt never consumes or otherwise disturbs the record
        // (this step's brief, invariant #3 / report §B8: no burn-on-failure).
        let proof = client_proof_for(&secret(1), &ekm(1));
        assert!(matches!(
            shared.redeem(&ekm(1), &proof, now, || true).unwrap(),
            RedeemOutcome::Accepted { .. }
        ));
    }

    #[test]
    fn redeem_after_ttl_reports_expired_not_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let created = SystemTime::now() - Duration::from_secs(60);
        let s = secret(3);
        let e = ekm(4);

        let mut store = InviteStore::default();
        store.add(&s, created);
        store.save(&path).unwrap();

        let shared = SharedInviteStore::open(&path).unwrap();
        let after_ttl = created + INVITE_TTL + Duration::from_secs(1);
        let proof = client_proof_for(&s, &e);
        assert_eq!(
            shared.redeem(&e, &proof, after_ttl, || true).unwrap(),
            RedeemOutcome::Expired
        );
        // Still within retention: pairing_open() stays true so this exact
        // exchange could happen at all.
        assert!(shared.pairing_open(after_ttl));
    }

    #[test]
    fn pairing_open_is_false_once_every_record_ages_out_of_retention() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let created = SystemTime::now() - Duration::from_secs(60);

        let mut store = InviteStore::default();
        store.add(&secret(5), created);
        store.save(&path).unwrap();

        let shared = SharedInviteStore::open(&path).unwrap();
        assert!(shared.pairing_open(created + Duration::from_secs(1)));
        let after_retention = created + INVITE_RETENTION + Duration::from_secs(1);
        assert!(!shared.pairing_open(after_retention));
    }

    #[test]
    fn prune_drops_records_past_retention_and_keeps_live_ones() {
        let now = SystemTime::now();
        let mut store = InviteStore::default();
        store.add(&secret(1), now - INVITE_RETENTION - Duration::from_secs(1));
        store.add(&secret(2), now);
        assert_eq!(store.records.len(), 2);
        store.prune(now);
        assert_eq!(store.records.len(), 1);
    }

    #[test]
    fn shared_store_reloads_a_freshly_added_invite_without_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let now = SystemTime::now();

        let shared = SharedInviteStore::open(&path).unwrap();
        assert!(!shared.pairing_open(now), "no invite yet");

        let mut store = InviteStore::default();
        store.add(&secret(1), now);
        store.save(&path).unwrap();

        assert!(
            shared.pairing_open(now),
            "a freshly written invite must be picked up without a restart"
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_store_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg/invites.toml");
        InviteStore::default().save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Report F-9, direction 1: `Ops::trust_invite`'s writer path (load,
    /// mutate a stale in-memory copy, save) must not un-consume an invite
    /// that a *different* process (`qsh serve`'s `SharedInviteStore::
    /// redeem`) already marked consumed on disk in the meantime. This is
    /// the exact lost-update the verification round's minimal repro
    /// produced: without the merge, a `trust invite` process's save would
    /// silently revert `consumed_at` back to unset, making the invite
    /// redeemable a second time.
    #[test]
    fn save_never_reverts_a_consumption_recorded_on_disk_by_another_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");

        // Writer A (`trust invite`-shaped): load a store with one live
        // invite.
        let mut writer_a = InviteStore::default();
        writer_a.add(&secret(1), SystemTime::now());
        writer_a.save(&path).unwrap();
        let mut stale_copy = InviteStore::load(&path).unwrap();

        // Writer B (`qsh serve`-shaped): independently loads the *same*
        // file, then consumes the record and saves — simulating a
        // `redeem()` that completed while writer A was still holding its
        // own, now-stale, in-memory copy.
        let mut writer_b = InviteStore::load(&path).unwrap();
        writer_b.records[0].consumed_at = Some("2026-08-31T00:03:00Z".to_string());
        writer_b.save(&path).unwrap();

        // Writer A now saves its stale copy (e.g. after mint-ing a second,
        // unrelated invite) — must not blow away writer B's consumption.
        stale_copy.add(&secret(2), SystemTime::now());
        stale_copy.save(&path).unwrap();

        let final_state = InviteStore::load(&path).unwrap();
        assert_eq!(final_state.records.len(), 2, "both invites must survive");
        let first = final_state
            .records
            .iter()
            .find(|r| r.mac_key == MacKey::of(&secret(1)).to_base64())
            .expect("writer A's original record survives");
        assert_eq!(
            first.consumed_at.as_deref(),
            Some("2026-08-31T00:03:00Z"),
            "a consumption already on disk must never be reverted by a \
             writer whose own copy predates it"
        );
    }

    /// Report F-9, direction 2: the reverse lost-update — `SharedInviteStore
    /// ::redeem`'s save (writing back its own, possibly-stale full record
    /// set) must not silently drop an invite a *different* process
    /// (`trust invite`) minted after `redeem`'s in-memory copy was loaded.
    #[test]
    fn save_does_not_drop_an_invite_minted_by_another_writer_after_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");

        let mut writer_a = InviteStore::default();
        writer_a.add(&secret(1), SystemTime::now());
        writer_a.save(&path).unwrap();

        // `redeem`-shaped writer loads the current (one-record) state.
        let mut redeemer = InviteStore::load(&path).unwrap();

        // A concurrent `trust invite` process mints a second invite and
        // saves, independently, before the redeemer writes back.
        let mut inviter = InviteStore::load(&path).unwrap();
        inviter.add(&secret(2), SystemTime::now());
        inviter.save(&path).unwrap();

        // The redeemer now consumes its (only known) record and saves its
        // own, still one-record-stale, copy.
        redeemer.records[0].consumed_at = Some("2026-08-31T00:03:00Z".to_string());
        redeemer.save(&path).unwrap();

        let final_state = InviteStore::load(&path).unwrap();
        assert_eq!(
            final_state.records.len(),
            2,
            "the concurrently-minted invite must not be silently dropped"
        );
        assert!(
            final_state
                .records
                .iter()
                .any(|r| r.mac_key == MacKey::of(&secret(2)).to_base64()),
            "the other writer's fresh invite must survive"
        );
    }

    /// The F-9 merge above must not undo a legitimate `prune()` — an
    /// expired-past-retention record dropped from `self.records` before
    /// `save()` must not come back just because it is still sitting
    /// on-disk at the moment `save()` re-reads the file to merge.
    #[test]
    fn save_still_drops_a_pruned_record_even_though_it_is_still_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let now = SystemTime::now();

        let mut store = InviteStore::default();
        store.add(&secret(1), now - INVITE_RETENTION - Duration::from_secs(1));
        store.save(&path).unwrap();
        assert_eq!(InviteStore::load(&path).unwrap().records.len(), 1);

        // `Ops::trust_invite`'s real sequence: load, prune, add, save.
        let mut store = InviteStore::load(&path).unwrap();
        store.prune(now);
        assert_eq!(store.records.len(), 0, "pruned in memory");
        store.add(&secret(2), now);
        store.save(&path).unwrap();

        let final_state = InviteStore::load(&path).unwrap();
        assert_eq!(
            final_state.records.len(),
            1,
            "the expired record must stay pruned, not be resurrected by \
             the F-9 merge's union step: {:?}",
            final_state.records
        );
        assert_eq!(
            final_state.records[0].mac_key,
            MacKey::of(&secret(2)).to_base64()
        );
    }

    #[test]
    fn on_disk_record_never_contains_the_raw_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let s = secret(0x42);

        let mut store = InviteStore::default();
        store.add(&s, SystemTime::now());
        store.save(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let hex_secret = s.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert!(!text.contains(&hex_secret));
        // The base64 of the raw secret bytes must not appear either.
        assert!(!text.contains(&BASE64.encode(s.as_ref())));
    }
}
