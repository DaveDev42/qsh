//! Client custody of resume tokens: `$XDG_STATE_HOME/qsh/resume.json`
//! ([ADR-0007](../../../docs/adr/0007-session-ref-and-resume-token-custody.md),
//! `docs/design/protocol.md` §10, `docs/CLI.md` §6.3).
//!
//! The token is the one credential that survives a dead connection, and it
//! is deliberately **not** part of any contract surface: it never appears
//! in a `qsh.cli/v1` envelope, a `qsh.event/v1` event, an audit record or a
//! log line. Machine callers re-attach with a `session_ref` alone; looking
//! the token up and presenting it is this module's job.
//!
//! What the file guarantees:
//!
//! - **0600, atomic replacement.** Written to `resume.json.tmp<pid>` in the
//!   same directory, `fsync`ed, then `rename(2)`d, and on unix the
//!   directory is `fsync`ed too — a crash leaves either the old file or the
//!   new one, never half of either.
//! - **Cross-process serialisation.** A `qsh session read --follow`, a
//!   `qsh mcp` and an interactive attach can all rotate a token at once, so
//!   every read-modify-write holds an exclusive advisory lock on a sidecar
//!   lock file for its whole duration ([`std::fs::File::lock`] — `flock(2)`
//!   on unix, `LockFileEx` on Windows).
//! - **Damage containment.** One unparseable record costs that record and
//!   nothing else: the rest of the file is salvaged entry by entry, and a
//!   file that does not parse at all is moved aside rather than silently
//!   replaced with an empty one. A single bad byte must not orphan every
//!   live session on the device.
//!
//! What it does **not** guarantee yet: on Windows the file is created with
//! the inherited directory ACL, because there is no `mode(0o600)` there —
//! the Windows client is P1 (`docs/ROADMAP.md` §3), and confidentiality of
//! `resume.json` on that platform is part of it.
//! - **Peer binding.** An entry records the `peer_spki_sha256` it was
//!   issued to. [`ResumeStore::take_for`] hands a token out only if the
//!   connected peer matches; a mismatch discards the entry and fails closed
//!   (`SESSION_NOT_FOUND`, `details.reason: "peer_mismatch"`).
//! - **Hygiene.** Tokens live in [`Zeroizing`] buffers and every type that
//!   holds one renders as `<redacted>`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_proto::ErrorCode;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::broker::RESUME_TOKEN_LEN;
use crate::config::{FileLock, Paths, config_io_error, ensure_private_dir, now_rfc3339};
use crate::ops::OpError;

/// Why a stored token could not be presented. Both variants become the
/// **local** `SESSION_NOT_FOUND` of CLI.md §6.3 — no request is sent, so a
/// missing or mis-bound token never becomes audit noise on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoToken {
    /// Nothing stored for that `session_ref` (another device, a wiped
    /// state file, or an entry already cleaned up).
    Missing,
    /// An entry exists but was issued to a different peer — the alias was
    /// re-pinned to another device. The entry is discarded.
    PeerMismatch,
}

impl NoToken {
    /// The `details.reason` string CLI.md §6.3 specifies.
    pub fn reason(self) -> &'static str {
        match self {
            NoToken::Missing => "no_resume_token",
            NoToken::PeerMismatch => "peer_mismatch",
        }
    }

    /// The ready-made local failure (fail closed, never a remote call).
    pub fn into_error(self, session_ref: &str) -> OpError {
        OpError::new(
            ErrorCode::SessionNotFound,
            format!(
                "no resume credential for {session_ref} on this device; \
                 the session may still be readable with `qsh session read` \
                 and closable with `qsh session close`"
            ),
        )
        .with_details(serde_json::json!({ "reason": self.reason() }))
    }
}

/// A 32-byte resume token held by the client. Zeroized on drop, redacted
/// in `Debug`, and serialised as standard Base64.
#[derive(Clone)]
pub struct StoredToken(Zeroizing<[u8; RESUME_TOKEN_LEN]>);

impl StoredToken {
    /// Wrap raw bytes; anything but exactly [`RESUME_TOKEN_LEN`] is `None`.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; RESUME_TOKEN_LEN] = bytes.try_into().ok()?;
        Some(Self(Zeroizing::new(arr)))
    }

    /// The plaintext, for the one caller allowed to see it: the wire
    /// encoder filling `SessionAttach.resume_token`.
    pub fn expose(&self) -> &[u8; RESUME_TOKEN_LEN] {
        &self.0
    }
}

impl fmt::Debug for StoredToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredToken(<redacted>)")
    }
}

/// Constant time, like every other comparison of this value in the
/// codebase — a byte-at-a-time `==` on a credential is a habit worth not
/// having, even where both comparands are local.
impl PartialEq for StoredToken {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.as_ref().ct_eq(other.0.as_ref()).into()
    }
}

impl Eq for StoredToken {}

impl Serialize for StoredToken {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(self.0.as_ref()))
    }
}

impl<'de> Deserialize<'de> for StoredToken {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let text = Zeroizing::new(String::deserialize(d)?);
        let bytes = Zeroizing::new(
            BASE64
                .decode(text.as_bytes())
                .map_err(|e| D::Error::custom(format!("token is not Base64: {e}")))?,
        );
        StoredToken::from_slice(&bytes).ok_or_else(|| D::Error::custom("token is not 32 bytes"))
    }
}

/// One `session_ref → credential` record (ADR-0007 결과 절).
#[derive(Clone, Serialize, Deserialize)]
pub struct ResumeEntry {
    /// The credential itself.
    pub token: StoredToken,
    /// Host alias the `session_ref` names.
    pub host_alias: String,
    /// Host-issued session id.
    pub session_id: String,
    /// SPKI fingerprint (`sha256:BASE64`) of the peer the token was issued
    /// to. A token is only ever presented to that same peer.
    pub peer_spki_sha256: String,
    /// RFC 3339 instant the host said the session/token TTL lapses.
    pub expires_at: String,
    /// RFC 3339 instant this entry was last written.
    pub updated_at: String,
}

impl fmt::Debug for ResumeEntry {
    /// Deliberately hand-written: a `#[derive(Debug)]` here would print
    /// whatever `token`'s `Debug` prints, and this type is exactly the one
    /// that must never end up in a log line by accident.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumeEntry")
            .field("token", &"<redacted>")
            .field("host_alias", &self.host_alias)
            .field("session_id", &self.session_id)
            .field("peer_spki_sha256", &self.peer_spki_sha256)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The on-disk document. A map so an unknown `session_ref` is simply
/// absent, and `#[serde(default)]` so a future additive field never makes
/// an older file unreadable.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    sessions: BTreeMap<String, ResumeEntry>,
}

/// The client's resume-token store.
#[derive(Debug, Clone)]
pub struct ResumeStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl ResumeStore {
    /// The store under `paths` (`<state_dir>/resume.json`).
    pub fn new(paths: &Paths) -> Self {
        Self {
            path: paths.resume_file(),
            lock_path: paths.resume_lock_file(),
        }
    }

    /// The store at an explicit path (tests).
    pub fn at(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut lock_path = path.clone();
        lock_path.as_mut_os_string().push(".lock");
        Self { path, lock_path }
    }

    /// Where the file lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record (or replace) the credential for `session_ref` and make it
    /// durable before returning.
    ///
    /// Rotation goes through here **before** the data stream is used: the
    /// token is single-generation, so a write that did not reach the disk
    /// is an orphaned session (ADR-0007) — the caller treats a failure as
    /// an attach failure.
    pub fn put(
        &self,
        session_ref: &str,
        host_alias: &str,
        session_id: &str,
        token: StoredToken,
        peer_spki_sha256: &str,
        expires_at: &str,
    ) -> Result<(), OpError> {
        self.update(|doc| {
            doc.sessions.insert(
                session_ref.to_string(),
                ResumeEntry {
                    token,
                    host_alias: host_alias.to_string(),
                    session_id: session_id.to_string(),
                    peer_spki_sha256: peer_spki_sha256.to_string(),
                    expires_at: expires_at.to_string(),
                    updated_at: now_rfc3339(),
                },
            );
        })
    }

    /// Forget `session_ref` — on `session.closed`, on an attach refused
    /// with `AUTH_FAILED`/`SESSION_NOT_FOUND`, or once it expired
    /// (ADR-0007 "정리").
    pub fn forget(&self, session_ref: &str) -> Result<(), OpError> {
        self.update(|doc| {
            doc.sessions.remove(session_ref);
        })
    }

    /// The credential to present for `session_ref` on a connection to
    /// `peer` (its `sha256:…` fingerprint), or why there is none.
    ///
    /// Expired entries are cleaned up on the way (ADR-0007 "정리": the host
    /// answers a stale token with a non-distinguishing `AUTH_FAILED`, so
    /// presenting one only buys a wasted round trip and an audit deny), and
    /// a peer mismatch discards the entry: an alias re-pinned to another
    /// device must not keep offering a credential that device cannot hold.
    pub fn take_for(&self, session_ref: &str, peer: &str) -> Result<StoredToken, NoToken> {
        let doc = self.load().unwrap_or_default();
        let Some(entry) = doc.sessions.get(session_ref) else {
            return Err(NoToken::Missing);
        };
        if entry.peer_spki_sha256 != peer {
            let _ = self.forget(session_ref);
            return Err(NoToken::PeerMismatch);
        }
        if is_expired(entry, SystemTime::now()) {
            let _ = self.forget(session_ref);
            return Err(NoToken::Missing);
        }
        Ok(entry.token.clone())
    }

    /// Push `session_ref`'s expiry out to `now + ttl` without touching the
    /// credential itself.
    ///
    /// A live attach *is* proof the session is alive, and the host anchors
    /// the credential to the session (the session's own TTL does not run
    /// while it is attached). The stored `expires_at` is a snapshot taken
    /// when the entry was written, so without this a session worked in for
    /// longer than `[serve].resume_ttl` would have its still-good
    /// credential purged locally and be orphaned by the next disconnect.
    /// A no-op if nothing is stored for `session_ref`.
    pub fn renew(&self, session_ref: &str, ttl: Duration) -> Result<(), OpError> {
        let until = rfc3339_at(SystemTime::now() + ttl);
        self.update(|doc| {
            if let Some(entry) = doc.sessions.get_mut(session_ref) {
                entry.expires_at = until;
                entry.updated_at = now_rfc3339();
            }
        })
    }

    /// Read the raw entry (tests and diagnostics; never rendered).
    pub fn get(&self, session_ref: &str) -> Option<ResumeEntry> {
        self.load().ok()?.sessions.get(session_ref).cloned()
    }

    /// How many credentials are stored.
    pub fn len(&self) -> usize {
        self.load().map(|d| d.sessions.len()).unwrap_or(0)
    }

    /// Whether nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every entry whose `expires_at` is in the past. Called on every
    /// write, so a state file left behind by a dead laptop does not
    /// accumulate credentials for sessions the host reaped long ago.
    fn purge_expired(doc: &mut Document, now: SystemTime) {
        doc.sessions.retain(|_, e| !is_expired(e, now));
    }

    /// Read-modify-write under an exclusive cross-process lock.
    fn update(&self, edit: impl FnOnce(&mut Document)) -> Result<(), OpError> {
        let dir = self
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        ensure_private_dir(&dir)?;
        let _guard = FileLock::acquire(&self.lock_path)?;
        let mut doc = match self.read() {
            Ok(doc) => doc,
            // Nothing could be salvaged. Keep the bytes: they are the only
            // evidence of what went wrong, and overwriting them in place is
            // exactly the step that would make a recoverable mistake
            // permanent.
            Err(Unreadable) => {
                let mut aside = self.path.clone();
                aside.as_mut_os_string().push(".corrupt");
                let _ = std::fs::rename(&self.path, &aside);
                tracing::warn!(
                    path = %self.path.display(),
                    moved_to = %aside.display(),
                    "resume.json could not be parsed; moved aside and started a new one"
                );
                Document::default()
            }
        };
        Self::purge_expired(&mut doc, SystemTime::now());
        edit(&mut doc);
        let body = Zeroizing::new(
            serde_json::to_vec_pretty(&doc)
                .map_err(|e| OpError::new(ErrorCode::Internal, format!("resume.json: {e}")))?,
        );
        write_durably(&self.path, &body).map_err(|e| config_io_error(&self.path, "write", &e))
    }

    /// The document, degrading to "no token" (fail closed) rather than
    /// failing a session command outright.
    fn load(&self) -> Result<Document, OpError> {
        Ok(self.read().unwrap_or_default())
    }

    /// The document, distinguishing "nothing survived" from "empty" so the
    /// writer can decide whether it is safe to replace the file.
    fn read(&self) -> Result<Document, Unreadable> {
        let raw = match std::fs::read(&self.path) {
            Ok(raw) => Zeroizing::new(raw),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Document::default()),
            // An unreadable file is not an empty one; treat it like a
            // corrupt one rather than proposing to overwrite it.
            Err(_) => return Err(Unreadable),
        };
        if let Ok(doc) = serde_json::from_slice::<Document>(&raw) {
            return Ok(doc);
        }
        // One bad record must cost that record and nothing else: a token
        // that is not 32 bytes, a hand edit, a truncated write. Dropping
        // every entry instead would orphan every live session on the
        // device, and single-generation tokens make that unrecoverable.
        salvage(&raw)
    }
}

/// The file yielded no usable document at all.
struct Unreadable;

/// Parse `raw` entry by entry, keeping the records that survive.
///
/// [`RawValue`] borrows out of `raw`, so a salvage pass makes no extra
/// copy of a credential.
///
/// [`RawValue`]: serde_json::value::RawValue
fn salvage(raw: &[u8]) -> Result<Document, Unreadable> {
    #[derive(Deserialize)]
    struct Loose<'a> {
        #[serde(default, borrow)]
        sessions: BTreeMap<String, &'a serde_json::value::RawValue>,
    }
    let Ok(loose) = serde_json::from_slice::<Loose<'_>>(raw) else {
        return Err(Unreadable);
    };
    let kept: BTreeMap<String, ResumeEntry> = loose
        .sessions
        .into_iter()
        .filter_map(|(key, value)| {
            serde_json::from_str::<ResumeEntry>(value.get())
                .ok()
                .map(|entry| (key, entry))
        })
        .collect();
    Ok(Document { sessions: kept })
}

/// Whether `entry`'s stated expiry has passed.
///
/// An unparseable stamp is **not** expired: the host is the authority on
/// whether a token still works, and dropping one on a parse quirk would
/// strand a live session.
fn is_expired(entry: &ResumeEntry, now: SystemTime) -> bool {
    parse_rfc3339(&entry.expires_at).is_some_and(|at| at <= now)
}

/// How long from now the RFC 3339 stamp `expires_at` is, or `None` if it
/// does not parse or has already passed.
///
/// This is the client's read of the credential window the host reported —
/// used to decide how often a live attach pushes its stored entry forward.
pub fn ttl_until(expires_at: &str) -> Option<Duration> {
    let at = parse_rfc3339(expires_at)?;
    at.duration_since(SystemTime::now())
        .ok()
        .filter(|d| !d.is_zero())
}

/// `SystemTime` → RFC 3339, in the same shape [`now_rfc3339`] produces.
fn rfc3339_at(at: SystemTime) -> String {
    time::OffsetDateTime::from(at)
        .replace_nanosecond(0)
        .unwrap_or_else(|_| at.into())
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// RFC 3339 → `SystemTime`, `None` if it does not parse.
fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(SystemTime::from)
}

/// Write `body` to `path` with mode 0600, atomically **and** durably: the
/// temp file is `fsync`ed before the rename and (on unix) the directory is
/// `fsync`ed after it, so the rename itself survives a crash. The plain
/// `write_private_file` stops one step short of that, and a lost rotation
/// is an orphaned session rather than a retry.
fn write_durably(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    // Unique per writer, not just per process: the `flock` already
    // serialises writers on unix, but a temp name two of them could share
    // would be the one way this corrupts a file rather than losing an
    // update, and that is a much worse failure.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ticket = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp = dir.join(file_name);
    tmp.as_mut_os_string()
        .push(format!(".tmp{}-{ticket}", std::process::id()));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            // Durability of the rename itself.
            if let Ok(dir) = std::fs::File::open(dir) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const OTHER_PEER: &str = "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    fn store() -> (tempfile::TempDir, ResumeStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ResumeStore::at(dir.path().join("resume.json"));
        (dir, store)
    }

    fn token(byte: u8) -> StoredToken {
        StoredToken::from_slice(&[byte; RESUME_TOKEN_LEN]).expect("token")
    }

    fn far_future() -> String {
        "2099-01-01T00:00:00Z".to_string()
    }

    #[test]
    fn a_token_round_trips_and_is_bound_to_its_peer() {
        let (_dir, store) = store();
        store
            .put("mac/01K0", "mac", "01K0", token(1), PEER, &far_future())
            .unwrap();

        assert_eq!(
            store.take_for("mac/01K0", PEER).unwrap().expose(),
            token(1).expose()
        );
        assert_eq!(
            store.take_for("mac/01K0", OTHER_PEER),
            Err(NoToken::PeerMismatch)
        );
        // A mismatch discards the entry: the alias now points elsewhere.
        assert_eq!(store.take_for("mac/01K0", PEER), Err(NoToken::Missing));
    }

    #[test]
    fn an_unknown_session_ref_is_missing_not_an_error() {
        let (_dir, store) = store();
        assert_eq!(store.take_for("mac/nope", PEER), Err(NoToken::Missing));
        assert!(store.is_empty());
    }

    #[test]
    fn rotation_replaces_the_previous_generation() {
        let (_dir, store) = store();
        store
            .put("mac/01K0", "mac", "01K0", token(1), PEER, &far_future())
            .unwrap();
        store
            .put("mac/01K0", "mac", "01K0", token(2), PEER, &far_future())
            .unwrap();
        assert_eq!(
            store.take_for("mac/01K0", PEER).unwrap().expose(),
            token(2).expose()
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn expired_entries_are_purged_on_the_next_write() {
        let (_dir, store) = store();
        store
            .put(
                "mac/old",
                "mac",
                "old",
                token(1),
                PEER,
                "2000-01-01T00:00:00Z",
            )
            .unwrap();
        store
            .put("mac/new", "mac", "new", token(2), PEER, &far_future())
            .unwrap();
        assert!(store.get("mac/old").is_none(), "expired entry survived");
        assert!(store.get("mac/new").is_some());
    }

    #[test]
    fn forgetting_removes_exactly_one_entry() {
        let (_dir, store) = store();
        store
            .put("mac/a", "mac", "a", token(1), PEER, &far_future())
            .unwrap();
        store
            .put("mac/b", "mac", "b", token(2), PEER, &far_future())
            .unwrap();
        store.forget("mac/a").unwrap();
        assert_eq!(store.take_for("mac/a", PEER), Err(NoToken::Missing));
        assert!(store.get("mac/b").is_some());
    }

    #[test]
    fn the_file_is_private_and_holds_no_plaintext_token() {
        let (_dir, store) = store();
        store
            .put("mac/01K0", "mac", "01K0", token(0xAB), PEER, &far_future())
            .unwrap();
        let raw = std::fs::read(store.path()).unwrap();
        // Base64, not raw bytes — and definitely not a readable field name
        // that would tempt a `--json` renderer.
        assert!(!raw.windows(8).any(|w| w == [0xABu8; 8]), "raw token bytes");
        assert!(String::from_utf8_lossy(&raw).contains("peer_spki_sha256"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "resume.json must be 0600");
        }
    }

    #[test]
    fn a_corrupt_state_file_degrades_to_no_token_and_is_kept_for_evidence() {
        let (_dir, store) = store();
        std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        std::fs::write(store.path(), b"{ this is not json").unwrap();
        assert_eq!(store.take_for("mac/01K0", PEER), Err(NoToken::Missing));
        // …and a later write repairs the file rather than failing.
        store
            .put("mac/01K0", "mac", "01K0", token(1), PEER, &far_future())
            .unwrap();
        assert!(store.get("mac/01K0").is_some());
        // The bytes that could not be parsed are moved aside, not
        // overwritten: they are the only evidence of what went wrong.
        let mut aside = store.path().to_path_buf();
        aside.as_mut_os_string().push(".corrupt");
        assert_eq!(std::fs::read(&aside).unwrap(), b"{ this is not json");
    }

    /// One bad record costs that record and nothing else. Under
    /// single-generation tokens, dropping the whole file would orphan every
    /// live session on the device — unrecoverably.
    #[test]
    fn one_unparseable_entry_does_not_cost_the_others() {
        let (_dir, store) = store();
        store
            .put("mac/good", "mac", "good", token(1), PEER, &far_future())
            .unwrap();
        store
            .put("mac/also", "mac", "also", token(2), PEER, &far_future())
            .unwrap();

        // Corrupt exactly one entry's token, the way a truncated write or a
        // hand edit would.
        let raw = std::fs::read_to_string(store.path()).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        doc["sessions"]["mac/also"]["token"] = serde_json::json!("not-32-bytes");
        std::fs::write(store.path(), serde_json::to_vec(&doc).unwrap()).unwrap();

        assert!(store.take_for("mac/good", PEER).is_ok(), "survivor lost");
        assert_eq!(store.take_for("mac/also", PEER), Err(NoToken::Missing));
        // The repair is durable: the salvaged document is what gets written
        // back on the next update.
        store.forget("mac/nothing").unwrap();
        assert_eq!(store.len(), 1);
    }

    /// ADR-0007 "정리" (iii): an expired entry is dropped on the way out,
    /// not presented for the host to refuse.
    #[test]
    fn an_expired_entry_is_dropped_instead_of_being_presented() {
        let (_dir, store) = store();
        store
            .put(
                "mac/old",
                "mac",
                "old",
                token(1),
                PEER,
                "2000-01-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(store.take_for("mac/old", PEER), Err(NoToken::Missing));
        assert!(store.get("mac/old").is_none(), "and it is gone");
    }

    /// The other half of the same rule: a session that stays attached
    /// longer than the window must not have its still-good credential
    /// purged out from under it. A live attach pushes the stamp forward.
    #[test]
    fn a_renewed_entry_outlives_its_original_window() {
        let (_dir, store) = store();
        let soon = rfc3339_at(SystemTime::now() + Duration::from_secs(2));
        store
            .put("mac/01K0", "mac", "01K0", token(1), PEER, &soon)
            .unwrap();
        store.renew("mac/01K0", Duration::from_secs(3600)).unwrap();
        let entry = store.get("mac/01K0").expect("still there");
        assert!(
            parse_rfc3339(&entry.expires_at).unwrap()
                > SystemTime::now() + Duration::from_secs(3000),
            "{}",
            entry.expires_at
        );
        assert_eq!(
            store.take_for("mac/01K0", PEER).unwrap().expose(),
            token(1).expose(),
            "renewal must not disturb the credential itself"
        );
        // Renewing something that is not there is not an error.
        store.renew("mac/nope", Duration::from_secs(60)).unwrap();
    }

    /// The lock is what makes a read-modify-write safe when a `qsh attach`,
    /// a `qsh session read --follow` and an MCP server all rotate tokens at
    /// once. `std::fs::File::lock` is real on every supported platform, so
    /// this asserts the guarantee everywhere rather than only where
    /// `flock(2)` is spelled that way.
    #[test]
    fn concurrent_writers_do_not_lose_each_others_entries() {
        let (_dir, store) = store();
        let mut threads = Vec::new();
        for i in 0..8u8 {
            let store = store.clone();
            threads.push(std::thread::spawn(move || {
                let name = format!("mac/{i}");
                store
                    .put(&name, "mac", &format!("{i}"), token(i), PEER, &far_future())
                    .unwrap();
            }));
        }
        for t in threads {
            t.join().expect("writer");
        }
        assert_eq!(store.len(), 8, "a concurrent write lost an entry");
    }

    #[test]
    fn secrets_redact_themselves() {
        let entry = ResumeEntry {
            token: token(0xCD),
            host_alias: "mac".into(),
            session_id: "01K0".into(),
            peer_spki_sha256: PEER.into(),
            expires_at: far_future(),
            updated_at: far_future(),
        };
        let rendered = format!("{entry:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("cdcd"), "{rendered}");
        assert_eq!(format!("{:?}", token(1)), "StoredToken(<redacted>)");
    }

    #[test]
    fn the_local_failure_carries_the_documented_reason() {
        let err = NoToken::Missing.into_error("mac/01K0");
        assert_eq!(err.code, ErrorCode::SessionNotFound);
        assert_eq!(err.details["reason"], "no_resume_token");
        let err = NoToken::PeerMismatch.into_error("mac/01K0");
        assert_eq!(err.details["reason"], "peer_mismatch");
    }
}
