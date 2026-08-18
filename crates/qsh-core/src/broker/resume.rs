//! Host custody of session resume credentials (`docs/design/protocol.md`
//! §10, ADR-0007).
//!
//! A `session.open` mints a 32-byte CSPRNG [`ResumeToken`] and hands the
//! **plaintext** to the client exactly once. The host keeps only
//! `blake3(token)` beside the session's bound peer identity and an expiry
//! — so a stolen host-side store cannot be replayed against the host, and
//! a stolen token cannot be redeemed from another device (redemption also
//! needs a mutually-authenticated TLS connection whose peer SPKI matches).
//!
//! Rotation is single-generation: every successful [`ResumeRegistry::rotate`]
//! replaces the stored hash, so the presented token dies at the moment it
//! is honoured and two clients racing on the same token means exactly one
//! of them wins (protocol.md §10 "Rotation").
//!
//! Everything here is transport-free (`peer` is a raw 32-byte SPKI digest,
//! never a `qsh_transport::Fingerprint`) because `xtask arch` bans
//! transport types under `broker/` — the seam has to be able to cross a
//! process boundary later (ADR-0003).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngCore as _;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::clock::Clock;
use super::session::InputStreamId;
use super::{SessionId, session::FIRST_INPUT_STREAM};

/// Length of a resume token, in bytes (`docs/design/protocol.md` §10).
pub const RESUME_TOKEN_LEN: usize = 32;

/// Length of the SPKI SHA-256 digest a session's resume credential is
/// bound to.
pub const PEER_FINGERPRINT_LEN: usize = 32;

/// A resume token in plaintext. Zeroized on drop and redacted in `Debug`,
/// so it cannot reach a log line by accident (`architecture.md` §5).
#[derive(Clone)]
pub struct ResumeToken(Zeroizing<[u8; RESUME_TOKEN_LEN]>);

impl PartialEq for ResumeToken {
    /// Constant time, so a `==` written in a test (or, later, in
    /// production) cannot become a timing oracle.
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.as_ref().ct_eq(other.0.as_ref()))
    }
}

impl Eq for ResumeToken {}

impl ResumeToken {
    /// Mint a fresh token from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; RESUME_TOKEN_LEN]);
        rand::rng().fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// Wrap raw bytes (a token read back from client state, or a wire
    /// field). Anything but exactly [`RESUME_TOKEN_LEN`] bytes is `None`.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; RESUME_TOKEN_LEN] = bytes.try_into().ok()?;
        Some(Self(Zeroizing::new(arr)))
    }

    /// The plaintext bytes. Only two callers may exist: the wire encoder
    /// that hands the token to its owner, and the client state file.
    pub fn expose(&self) -> &[u8; RESUME_TOKEN_LEN] {
        &self.0
    }

    /// `blake3(token)` — what the host stores.
    pub fn hash(&self) -> TokenHash {
        TokenHash::of(self.0.as_ref())
    }
}

impl fmt::Debug for ResumeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResumeToken(<redacted>)")
    }
}

/// `blake3` digest of a resume token — the only form the host retains.
#[derive(Clone, Copy)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// Hash a token's plaintext bytes.
    pub fn of(token: &[u8]) -> Self {
        Self(*blake3::hash(token).as_bytes())
    }
}

impl fmt::Debug for TokenHash {
    /// Redacted: the digest verifies a credential, so it is treated as one
    /// even though it is not invertible.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash(<redacted>)")
    }
}

impl ConstantTimeEq for TokenHash {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// SHA-256 of a peer's DER `SubjectPublicKeyInfo` — the identity a resume
/// credential is bound to (protocol.md §10, PRD §9).
///
/// Deliberately a broker-local newtype rather than
/// `qsh_transport::Fingerprint`: `xtask arch` bans transport types under
/// `broker/`, and the seam has to be able to cross a process boundary
/// (ADR-0003). The dispatch edge converts.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerFingerprint([u8; PEER_FINGERPRINT_LEN]);

impl PeerFingerprint {
    /// Wrap a raw digest.
    pub fn new(digest: [u8; PEER_FINGERPRINT_LEN]) -> Self {
        Self(digest)
    }

    /// The raw digest.
    pub fn as_bytes(&self) -> &[u8; PEER_FINGERPRINT_LEN] {
        &self.0
    }
}

impl fmt::Debug for PeerFingerprint {
    /// Short prefix only — a full fingerprint in a log line is noise, and
    /// the audit record already names the principal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerFingerprint({:02x}{:02x}…)", self.0[0], self.0[1])
    }
}

impl ConstantTimeEq for PeerFingerprint {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// The single, non-distinguishing failure of a resume redemption.
///
/// There is deliberately **one** variant: an unknown session, a wrong
/// token, an expired token and a foreign peer must be indistinguishable to
/// the peer that asked (protocol.md §10-2), so the type cannot even
/// express the difference and no caller can leak it by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("resume credential rejected")]
pub struct ResumeDenied;

/// One stored credential.
struct Entry {
    hash: TokenHash,
    peer: PeerFingerprint,
    expires_at: Instant,
    /// The input axis this credential's lineage last used. A redemption
    /// forks its own axis from this one, so the un-acked tail a resumed
    /// client retransmits is deduplicated against what the child already
    /// ran (protocol.md §10-5).
    input_stream: InputStreamId,
}

/// The host's resume-credential store: `session_id → (blake3(token),
/// peer_spki_sha256, expires_at)`.
///
/// Keyed by the **session id**, which the peer names in the clear, so a
/// lookup leaks nothing: every secret-dependent comparison below is
/// [`ConstantTimeEq`], and a missing entry does the same work as a present
/// one.
pub struct ResumeRegistry {
    clock: Arc<dyn Clock>,
    entries: Mutex<HashMap<SessionId, Entry>>,
}

impl fmt::Debug for ResumeRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumeRegistry")
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

impl ResumeRegistry {
    /// A store on the broker's injected clock (so TTL is testable without
    /// wall-clock sleeps — `docs/design/testing.md` L2).
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Number of credentials held (tests/diagnostics).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no credential is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Mint the session's first token, bound to `peer` and living `ttl`.
    /// Replaces any existing credential for `id` (single generation).
    ///
    /// The lineage starts on [`FIRST_INPUT_STREAM`], which is the axis
    /// `session.open`'s own ticket carries.
    pub fn issue(&self, id: &SessionId, peer: PeerFingerprint, ttl: Duration) -> ResumeToken {
        let token = ResumeToken::generate();
        let expires_at = self.clock.now() + ttl;
        self.lock().insert(
            id.clone(),
            Entry {
                hash: token.hash(),
                peer,
                expires_at,
                input_stream: FIRST_INPUT_STREAM,
            },
        );
        token
    }

    /// Check a presented token against the stored credential **without**
    /// consuming it: hash equality, expiry, and the bound peer identity,
    /// in that order but with no early return — the three are folded into
    /// one `Choice` so the answer costs the same whatever failed
    /// (protocol.md §10-2).
    ///
    /// A pass means the peer proved custody of the session; the caller
    /// still owes the ACL check before anything is issued. On success the
    /// lineage's current input axis comes back with it — the axis the
    /// redemption forks from.
    pub fn verify(
        &self,
        id: &SessionId,
        presented: &[u8],
        peer: PeerFingerprint,
    ) -> Result<InputStreamId, ResumeDenied> {
        let now = self.clock.now();
        let entries = self.lock();
        let entry = entries.get(id);
        // A missing session compares against zeros, so the work — and
        // therefore the timing — does not depend on whether it exists.
        let present = subtle::Choice::from(u8::from(entry.is_some()));
        let stored_hash = entry.map_or(TokenHash([0u8; 32]), |e| e.hash);
        let stored_peer = entry.map_or(PeerFingerprint([0u8; PEER_FINGERPRINT_LEN]), |e| e.peer);
        let fresh = subtle::Choice::from(u8::from(entry.is_some_and(|e| e.expires_at > now)));
        let hash_ok = TokenHash::of(presented).ct_eq(&stored_hash);
        let peer_ok = stored_peer.ct_eq(&peer);
        if bool::from(present & hash_ok & peer_ok & fresh) {
            Ok(entry.map_or(FIRST_INPUT_STREAM, |e| e.input_stream))
        } else {
            Err(ResumeDenied)
        }
    }

    /// Honour a verified redemption: kill the presented generation and
    /// mint the next one, re-bound to `peer` and living another `ttl`.
    ///
    /// Re-runs [`verify`](Self::verify) under the same lock, so two peers
    /// racing on one token cannot both be handed a successor.
    pub fn rotate(
        &self,
        id: &SessionId,
        presented: &[u8],
        peer: PeerFingerprint,
        ttl: Duration,
        input_stream: InputStreamId,
    ) -> Result<ResumeToken, ResumeDenied> {
        let now = self.clock.now();
        let mut entries = self.lock();
        // Folded like `verify`, against zeros when the id is unknown, so
        // this cannot become the timing oracle `verify` refuses to be.
        let entry = entries.get(id);
        let present = subtle::Choice::from(u8::from(entry.is_some()));
        let stored_hash = entry.map_or(TokenHash([0u8; 32]), |e| e.hash);
        let stored_peer = entry.map_or(PeerFingerprint([0u8; PEER_FINGERPRINT_LEN]), |e| e.peer);
        let fresh = subtle::Choice::from(u8::from(entry.is_some_and(|e| e.expires_at > now)));
        let ok = present
            & TokenHash::of(presented).ct_eq(&stored_hash)
            & stored_peer.ct_eq(&peer)
            & fresh;
        if !bool::from(ok) {
            return Err(ResumeDenied);
        }
        let token = ResumeToken::generate();
        entries.insert(
            id.clone(),
            Entry {
                hash: token.hash(),
                peer,
                expires_at: now + ttl,
                input_stream,
            },
        );
        Ok(token)
    }

    /// Drop the session's credential — the session is gone, so a later
    /// attach must be indistinguishable from one naming an id that never
    /// existed (CLI.md §6.4: a closed session's `session.attach` answers
    /// `AUTH_FAILED`).
    pub fn forget(&self, id: &SessionId) {
        self.lock().remove(id);
    }

    /// Drop every credential whose TTL has lapsed. Called by the same
    /// reaper pass that closes expired sessions.
    pub fn purge_expired(&self) {
        let now = self.clock.now();
        self.lock().retain(|_, e| e.expires_at > now);
    }

    /// Re-anchor every credential to its session's own deadline, then drop
    /// the ones whose session is gone and whose TTL has lapsed.
    ///
    /// A credential must live exactly as long as the session it resumes.
    /// Anchoring it to the moment it was *issued* instead is what would
    /// make a session that stays attached longer than `[serve].resume_ttl`
    /// — the product's whole premise — alive but permanently unresumable:
    /// the session's own TTL does not run while attached, so a credential
    /// on a separate clock expires under a healthy session and the next
    /// disconnect orphans it (`docs/PRD.md` §13).
    pub fn sync_expiry(&self, deadlines: &HashMap<SessionId, Instant>) {
        let now = self.clock.now();
        self.lock().retain(|id, e| match deadlines.get(id) {
            Some(&deadline) => {
                e.expires_at = deadline;
                true
            }
            None => e.expires_at > now,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::TestClock;

    const TTL: Duration = Duration::from_secs(60);

    fn peer(byte: u8) -> PeerFingerprint {
        PeerFingerprint::new([byte; PEER_FINGERPRINT_LEN])
    }

    fn rig() -> (TestClock, ResumeRegistry, SessionId) {
        let clock = TestClock::new();
        let registry = ResumeRegistry::new(Arc::new(clock.clone()));
        (clock, registry, SessionId("01K0SESSION".into()))
    }

    const AXIS: InputStreamId = InputStreamId(7);

    #[test]
    fn a_token_is_accepted_once_and_its_successor_replaces_it() {
        let (_clock, registry, id) = rig();
        let first = registry.issue(&id, peer(1), TTL);

        // A fresh credential's lineage starts on the axis `session.open`'s
        // own ticket carries.
        assert_eq!(
            registry.verify(&id, first.expose(), peer(1)),
            Ok(FIRST_INPUT_STREAM)
        );
        let second = registry
            .rotate(&id, first.expose(), peer(1), TTL, AXIS)
            .expect("first redemption");

        assert_ne!(first.expose(), second.expose());
        // Single generation: the presented token died at rotation.
        assert_eq!(
            registry.verify(&id, first.expose(), peer(1)),
            Err(ResumeDenied)
        );
        assert_eq!(
            registry.rotate(&id, first.expose(), peer(1), TTL, AXIS),
            Err(ResumeDenied)
        );
        // …and the successor carries the lineage the redemption forked on,
        // so the next resume deduplicates against the right axis.
        assert_eq!(registry.verify(&id, second.expose(), peer(1)), Ok(AXIS));
    }

    #[test]
    fn two_peers_racing_on_one_token_cannot_both_win() {
        let (_clock, registry, id) = rig();
        let token = registry.issue(&id, peer(1), TTL);
        let a = registry.rotate(&id, token.expose(), peer(1), TTL, AXIS);
        let b = registry.rotate(&id, token.expose(), peer(1), TTL, AXIS);
        assert!(a.is_ok());
        assert_eq!(b, Err(ResumeDenied));
    }

    #[test]
    fn a_live_session_keeps_its_credential_past_the_issue_ttl() {
        let (clock, registry, id) = rig();
        let token = registry.issue(&id, peer(1), TTL);
        // The session is attached, so its own TTL is not running: the
        // reaper re-anchors the credential to the session's deadline on
        // every pass.
        for _ in 0..4 {
            clock.advance(TTL / 2);
            let deadlines = HashMap::from([(id.clone(), clock.now() + TTL)]);
            registry.sync_expiry(&deadlines);
        }
        assert!(
            registry.verify(&id, token.expose(), peer(1)).is_ok(),
            "a session alive past `resume_ttl` must still be resumable"
        );

        // Once the session is gone from the registry, the credential is on
        // its own clock again and lapses.
        clock.advance(TTL + Duration::from_secs(1));
        registry.sync_expiry(&HashMap::new());
        assert!(registry.is_empty());
    }

    #[test]
    fn an_expired_token_is_denied() {
        let (clock, registry, id) = rig();
        let token = registry.issue(&id, peer(1), TTL);
        clock.advance(TTL - Duration::from_millis(1));
        registry.verify(&id, token.expose(), peer(1)).unwrap();
        clock.advance(Duration::from_millis(1));
        assert_eq!(
            registry.verify(&id, token.expose(), peer(1)),
            Err(ResumeDenied)
        );
        registry.purge_expired();
        assert!(registry.is_empty());
    }

    #[test]
    fn a_different_peer_cannot_redeem_a_stolen_token() {
        let (_clock, registry, id) = rig();
        let token = registry.issue(&id, peer(1), TTL);
        // Same failure as a wrong token and as an unknown session: the
        // error type cannot express which.
        assert_eq!(
            registry.verify(&id, token.expose(), peer(2)),
            Err(ResumeDenied)
        );
        assert_eq!(
            registry.verify(&id, b"not the token", peer(1)),
            Err(ResumeDenied)
        );
        assert_eq!(
            registry.verify(&SessionId("01K0OTHER".into()), token.expose(), peer(1)),
            Err(ResumeDenied)
        );
        // …and the legitimate owner is unaffected by the failed attempts.
        registry.verify(&id, token.expose(), peer(1)).unwrap();
    }

    #[test]
    fn forgetting_a_session_denies_its_token() {
        let (_clock, registry, id) = rig();
        let token = registry.issue(&id, peer(1), TTL);
        registry.forget(&id);
        assert_eq!(
            registry.verify(&id, token.expose(), peer(1)),
            Err(ResumeDenied)
        );
    }

    #[test]
    fn the_secret_types_redact_themselves() {
        let token = ResumeToken::generate();
        assert_eq!(format!("{token:?}"), "ResumeToken(<redacted>)");
        assert_eq!(format!("{:?}", token.hash()), "TokenHash(<redacted>)");

        // A container that actually embeds the secret is where a stray
        // `#[derive(Debug)]` would leak, so that is what this asserts on —
        // `ResumeRegistry`'s own `Debug` prints a count and would pass
        // however the redaction was broken.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            token: ResumeToken,
            hash: TokenHash,
            peer: PeerFingerprint,
        }
        let rendered = format!(
            "{:?}",
            Holder {
                token: token.clone(),
                hash: token.hash(),
                peer: peer(0xAB),
            }
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        let hex: String = token.expose().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&hex), "{rendered}");
        // A fingerprint is not a secret, but a whole one in a log line is
        // noise: only a short prefix is printed.
        assert!(rendered.contains("PeerFingerprint(abab…)"), "{rendered}");

        // …and the registry still prints nothing but a count.
        let registry = ResumeRegistry::new(Arc::new(TestClock::new()));
        let id = SessionId("01K0SESSION".into());
        let token = registry.issue(&id, peer(1), TTL);
        let rendered = format!("{registry:?}");
        let hex: String = token.expose().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&hex), "{rendered}");
    }

    #[test]
    fn a_wrong_length_token_is_not_a_token() {
        assert!(ResumeToken::from_slice(&[]).is_none());
        assert!(ResumeToken::from_slice(&[0u8; 31]).is_none());
        assert!(ResumeToken::from_slice(&[0u8; 33]).is_none());
        assert!(ResumeToken::from_slice(&[0u8; RESUME_TOKEN_LEN]).is_some());
    }
}
