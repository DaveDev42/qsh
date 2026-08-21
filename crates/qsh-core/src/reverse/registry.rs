//! The controller-side reverse-registration table (`docs/design/protocol.md`
//! §11-2, `PLAN.md` Step 3, PR 3a).
//!
//! [`Registry`] holds **metadata only**: `name → `[`ReverseEntry`]. It never
//! names a live connection or a `client::Session` — the transport
//! connection a registration rides on belongs to PR 3b's
//! `reverse/listen.rs` connection table, keyed by `(name, generation)`.
//! Folding a connection into this registry would make it transitively hold
//! a `qsh_transport::Connection`, defeating the point of keeping
//! registration bookkeeping separate from connection ownership (`PLAN.md`
//! Step 3 (b)).
//!
//! This file is also, deliberately, **transport-free**: it names no
//! `qsh_transport` type at all (`fingerprint`/`principal` are stored in
//! their canonical `Display` string forms, exactly the way
//! `broker::resume::PeerFingerprint` and `audit::AuditRecord::principal`
//! already do for the same reason). `PLAN.md` Step 5 commits to banning
//! `qsh_transport`/`quinn`/`rustls`/`crate::client`/`crate::Principal`/
//! `crate::Fingerprint` in this exact file — the same six tokens
//! `xtask/src/arch.rs`'s `BROKER_DIR` rule already bans in `broker/` — so
//! this module is shaped to satisfy that lint on day one rather than
//! deferring the narrowing to Step 5. The `host.reverse` ACL choke point
//! (which *does* need `Principal`/`AuthPath`/`Authorizer`) lives next door
//! in [`super::admit`], which this file has no knowledge of.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qsh_proto::{ErrorCode, wire};

use crate::broker::Clock;
use crate::ops::OpError;

/// Registration state of a [`ReverseEntry`]. `Stale` is Step 4's
/// connection-loss bookkeeping (`docs/design/protocol.md` §11-4): a dead
/// connection's entry is marked `Stale` rather than removed outright, and
/// [`Registry::sweep_expired`] removes it once `[listen].stale_retention`
/// has elapsed since [`Registry::mark_stale`] transitioned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// As far as this registry knows, the registering connection is still
    /// up.
    Live,
    /// The connection that registered this entry has died. Still resolvable
    /// (`docs/CLI.md` §6.13's "있었다가 끊겼다" — a vanished host is shown,
    /// not silently erased) until [`Registry::sweep_expired`] removes it.
    Stale,
}

/// One registered reverse host — metadata only, never a connection (see the
/// module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseEntry {
    /// The name this host is reachable as. Controller-assigned — see
    /// [`Registry::resolve_name`]; never the raw, unauthenticated
    /// `offered_name` unless that was explicitly permitted.
    pub name: String,
    /// SPKI SHA-256 fingerprint of the registering peer's verified leaf
    /// certificate, in its canonical `sha256:<base64>` `Display` form
    /// (`qsh_transport::Fingerprint::to_string`) — never the typed
    /// `Fingerprint` itself (module docs).
    pub fingerprint: String,
    /// The peer's authenticated principal, in its canonical
    /// `device:<name>` / `user:<name>` / `fp:<sha256:…>` `Display` form
    /// (`qsh_transport::Principal::to_string`, the same string
    /// `audit::AuditRecord::principal` uses) — never the typed `Principal`
    /// itself (module docs).
    pub principal: String,
    /// The peer's socket address at registration time. Diagnostic only —
    /// reverse hosts are never dialed back by the controller; this just
    /// records where the inbound connection came from.
    pub address: SocketAddr,
    /// Capabilities the target's `Hello` negotiated.
    pub capabilities: Vec<String>,
    /// RFC 3339 registration timestamp, from the registry's injected
    /// [`Clock`] (so tests are deterministic — `docs/design/testing.md`
    /// L2).
    pub registered_at: String,
    /// Monotonically increasing per-name counter: `0` on first
    /// registration, `+1` each time the *same* fingerprint re-registers
    /// under this name (the NAT-rebind reconnect path, Step 4). A
    /// *different* fingerprint registering under a live name is a conflict,
    /// never a replace — see [`Registry::admit`].
    pub generation: u64,
    /// Live vs. stale. Every fresh or replacing registration inserts
    /// [`EntryState::Live`]; [`Registry::mark_stale`] is the only path to
    /// [`EntryState::Stale`].
    pub state: EntryState,
    /// When [`Registry::mark_stale`] transitioned this entry to
    /// [`EntryState::Stale`] — `None` for a [`EntryState::Live`] entry.
    /// [`Registry::sweep_expired`] reads this against the injected
    /// [`Clock`] to decide whether `[listen].stale_retention` has elapsed.
    /// Monotonic ([`Clock::now`]), never the wall-clock `registered_at`
    /// string — the same reasoning `broker::resume`'s TTL deadlines use
    /// (immune to wall-clock adjustment).
    pub stale_since: Option<Instant>,
}

/// The outcome of a successful [`Registry::admit`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterOutcome {
    /// The entry now live in the registry under `entry.name`.
    pub entry: ReverseEntry,
    /// `Some(previous_generation)` when this call *replaced* a live entry
    /// registered by the same fingerprint (a reconnect). Closing the
    /// connection that owned the previous generation is 3b's job — this
    /// registry only tracks the number (module docs).
    pub replaced_generation: Option<u64>,
    /// The full entry this call replaced, when it replaced one — the
    /// pre-image [`Registry::rollback`] restores if 3b's caller has to
    /// undo this admission (the peer's control-stream reply after
    /// `Registry::admit` ran never actually reached it, e.g. the
    /// connection died mid-`Hello`-reply — `reverse/listen.rs`'s
    /// `register_connection`). `None` exactly when `replaced_generation`
    /// is `None`.
    pub replaced_entry: Option<ReverseEntry>,
}

/// Metadata about one connection's `Hello.reverse` needed to actually
/// insert a [`ReverseEntry`], once [`super::admit`] has already resolved
/// the name and passed the `host.reverse` choke point. Plain strings only
/// (module docs) — the canonical `Display` form of the fingerprint and
/// principal, computed by the caller.
pub struct AdmittedEntry<'a> {
    /// `qsh_transport::Fingerprint::to_string()`, canonical form.
    pub fingerprint: &'a str,
    /// `qsh_transport::Principal::to_string()`, canonical form.
    pub principal: &'a str,
    /// Peer socket address at connection time.
    pub address: SocketAddr,
    /// `Hello.capabilities` (the negotiated intersection).
    pub capabilities: Vec<String>,
}

/// The controller-side reverse-registration table (module docs).
///
/// One `Registry` is built per `qsh listen` process (3b's `host_runtime`-
/// style factory, analogous to `serve.rs`'s broker construction) and shared
/// across every accepted connection. It has **no** `Authorizer`/`AuditSink`
/// of its own — those live in [`super::admit`], which is the only caller of
/// [`Registry::admit`].
pub struct Registry {
    clock: Arc<dyn Clock>,
    /// `[listen].allow_advertised_names` (default `false`, `docs/CLI.md`
    /// §6.13) — resolved once at construction, like `Server`'s
    /// `authorizer`/`audit`.
    allow_advertised_names: bool,
    state: Mutex<RegistryState>,
}

/// Entries plus the generation tombstone, under one lock (module docs on
/// [`Registry::admit`]'s generation derivation for why a plain
/// `HashMap<String, ReverseEntry>` is not enough on its own).
#[derive(Default)]
struct RegistryState {
    entries: HashMap<String, ReverseEntry>,
    /// Per-name high-water mark of `generation`, kept **even after an entry
    /// is removed** (`Registry::sweep_expired`'s eviction). Without this a
    /// name that gets evicted and re-registered would restart at generation
    /// `0` and collide with `reverse/listen.rs`'s `(name, generation)`-keyed
    /// connection-table history — the exact defect PR 3a's `admit` doc
    /// comment flagged and Step 4 commits to fixing (see git blame on this
    /// struct).
    last_generation: HashMap<String, u64>,
}

/// Hard cap on [`RegistryState::last_generation`]'s size. Comfortably above
/// any realistic number of distinct names one `qsh listen` process serves —
/// this exists only to keep growth *bounded*, not to reflect a real
/// resource budget. Only reachable at all with `[listen].allow_advertised_names`
/// set: a pinned peer can then advertise an unbounded number of distinct
/// names over its lifetime, each leaving a tombstone that
/// [`Registry::sweep_expired`] deliberately never removes (adversarial
/// review finding).
const MAX_TOMBSTONES: usize = 10_000;

/// Evict tombstones once [`MAX_TOMBSTONES`] is exceeded — but only for
/// names with no entry currently in `entries`. A name still registered
/// (live or stale) must keep its tombstone no matter how large the map
/// gets: evicting it would let a later `admit` reissue a generation that
/// name's own history already used, exactly the invariant `Registry::admit`'s
/// replace branch and [`Registry::rollback`] depend on. Eviction order is
/// arbitrary (`HashMap` iteration order), not least-recently-used — the
/// goal is only to keep the structure bounded, not to evict optimally.
fn prune_tombstones(state: &mut RegistryState) {
    if state.last_generation.len() <= MAX_TOMBSTONES {
        return;
    }
    let overflow = state.last_generation.len() - MAX_TOMBSTONES;
    let evictable: Vec<String> = state
        .last_generation
        .keys()
        .filter(|name| !state.entries.contains_key(*name))
        .take(overflow)
        .cloned()
        .collect();
    for name in evictable {
        state.last_generation.remove(&name);
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("allow_advertised_names", &self.allow_advertised_names)
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// Build an empty registry.
    pub fn new(clock: Arc<dyn Clock>, allow_advertised_names: bool) -> Self {
        Self {
            clock,
            allow_advertised_names,
            state: Mutex::new(RegistryState::default()),
        }
    }

    /// The entry registered under `name`, if any (live or stale).
    pub fn get(&self, name: &str) -> Option<ReverseEntry> {
        self.lock().entries.get(name).cloned()
    }

    /// Every entry, sorted by name — deterministic, for `host.list` (Step
    /// 5) and tests.
    pub fn snapshot(&self) -> Vec<ReverseEntry> {
        let mut entries: Vec<_> = self.lock().entries.values().cloned().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Resolve the name a peer would register under, or refuse before it
    /// ever becomes an ACL resource (`docs/design/protocol.md` §11-2). In
    /// order:
    ///
    /// 1. **Shape** — `offered_name` must be empty or satisfy
    ///    [`wire::valid_host_name`]. A violation is `INVALID_ARGUMENT` and
    ///    is **never audited**: this runs before the choke point and
    ///    doesn't depend on who the peer is (protocol.md §9's "check shape
    ///    first" discipline, applied here exactly as it is to
    ///    `session_id`).
    /// 2. **Name resolution** — `alias` (the peer's trust-store alias, if
    ///    it has one — [`super::admit`] computes this from
    ///    `(auth_path, principal)`, since that mapping is a transport-typed
    ///    question this file doesn't ask) wins if present, **provided it
    ///    also satisfies [`wire::valid_host_name`]** (see below); else
    ///    `offered_name`, but only when this registry's
    ///    `allow_advertised_names` was set at construction; else
    ///    `PERMISSION_DENIED`. `offered_name` is never itself an
    ///    authentication input (name-squatting prevention).
    ///
    /// The alias is an operator-chosen label (`trust add <name>`), not
    /// peer-supplied wire input — but `Ops::trust_add`
    /// (`crates/qsh-core/src/ops/mod.rs`) only rejects an *empty* name, so
    /// nothing today stops an operator from pinning an alias like
    /// `"mac/work"` or a multi-KB string. Once resolved, the alias becomes
    /// this registry's `HashMap` key, an ACL resource, and an audit field,
    /// and Step 5 plans to address sessions as `<name>/<session_id>` — an
    /// oversized or separator-containing alias would make that ambiguous.
    /// So an alias is held to the exact same shape rule as `offered_name`
    /// here, and a violation fails closed with the identical generic
    /// [`host_reverse_denied`] the no-alias case below returns (never
    /// revealing the alias content or that a pin exists — see
    /// [`host_reverse_denied`]'s docs). Tightening `Ops::trust_add` itself
    /// to enforce this at pin time would be a user-visible CLI behavior
    /// change, out of this PR's zero-behavior-change scope — `trust_add` is
    /// the other end of this invariant and remains permissive for now.
    ///
    /// This step only reads state — nothing is created — and returning an
    /// error here leaves the registry exactly as it was.
    pub fn resolve_name(&self, alias: Option<&str>, offered_name: &str) -> Result<String, OpError> {
        validate_offered_name_shape(offered_name)?;
        if let Some(alias) = alias {
            if !wire::valid_host_name(alias) {
                return Err(host_reverse_denied());
            }
            return Ok(alias.to_string());
        }
        // `allow_advertised_names=true` accepts `offered_name` verbatim
        // (already shape-checked above) with no check against the
        // trust-store alias namespace — this file deliberately holds no
        // view of that namespace (module docs). So a CA-authenticated peer
        // could squat an offline pinned peer's alias here. Unreachable
        // today: the interim `AllowAllPinned` policy denies every
        // non-`Pin` peer at the `host.reverse` choke point regardless of
        // the name it resolves to, so a CA-path registration never
        // succeeds. This stops being latent the moment M5's policy engine
        // can allow a CA principal — consciously deferred to Step 5/M5,
        // not forgotten (`docs/design/protocol.md` §11-2).
        if self.allow_advertised_names && !offered_name.is_empty() {
            return Ok(offered_name.to_string());
        }
        Err(host_reverse_denied())
    }

    /// Insert an already-authorized registration under `name`
    /// (`docs/design/protocol.md` §11-2 step 4). [`super::admit`] calls
    /// this exactly once, only after [`Registry::resolve_name`] succeeded
    /// and the `host.reverse` choke point allowed the request — this
    /// method itself performs no authorization and assumes none is needed
    /// by the time it's called.
    ///
    /// Conflict rule: a live entry already registered under `name` blocks
    /// the new registration (`INVALID_ARGUMENT` — no silent overwrite)
    /// unless it was registered by the *same* fingerprint, in which case it
    /// is replaced and `generation` advances by one (the NAT-rebind
    /// reconnect path).
    pub fn admit(
        &self,
        name: String,
        entry: AdmittedEntry<'_>,
    ) -> Result<RegisterOutcome, OpError> {
        let mut state = self.lock();
        // Conflict rule applies identically to a `Live` or `Stale` existing
        // entry (`EntryState` doesn't enter this match at all): a name is
        // "occupied" by whichever fingerprint last held it until that
        // entry is actually removed by `sweep_expired`, stale or not — that
        // is the entire point of staying `Stale` instead of vanishing
        // immediately (`docs/design/protocol.md` §11-4's rationale doubles
        // as the name-squatting-during-the-gap defense).
        let (generation, replaced_generation, replaced_entry) = match state.entries.get(&name) {
            Some(existing) if existing.fingerprint != entry.fingerprint => {
                return Err(OpError::new(
                    ErrorCode::InvalidArgument,
                    format!("{name:?} is already registered to a different peer"),
                )
                .with_retryable(false));
            }
            Some(existing) => {
                // Not just `existing.generation + 1`: after a `rollback`
                // restores an older snapshot, `existing.generation` can be
                // *behind* the tombstone (`rollback`'s own doc comment —
                // "generation was handed out and must never be reissued").
                // Taking the max keeps that invariant true here too,
                // rather than only in the untouched `None` branch below
                // (adversarial review finding: without this, the very next
                // `admit` after a rollback reissued the rolled-back
                // generation number).
                let next_from_tombstone =
                    state.last_generation.get(&name).map(|g| g + 1).unwrap_or(0);
                (
                    next_from_tombstone.max(existing.generation + 1),
                    Some(existing.generation),
                    Some(existing.clone()),
                )
            }
            // No current entry — either this name has never been seen, or
            // its last entry was evicted by `sweep_expired`. Either way,
            // continue from the tombstoned high-water mark rather than
            // restarting at `0` (`RegistryState::last_generation`'s docs) —
            // `unwrap_or(0)` covers the genuinely-never-seen case.
            None => (
                state.last_generation.get(&name).map(|g| g + 1).unwrap_or(0),
                None,
                None,
            ),
        };
        let new_entry = ReverseEntry {
            name: name.clone(),
            fingerprint: entry.fingerprint.to_string(),
            principal: entry.principal.to_string(),
            address: entry.address,
            capabilities: entry.capabilities,
            registered_at: crate::config::rfc3339_of(self.clock.wall_now()),
            generation,
            state: EntryState::Live,
            stale_since: None,
        };
        state.last_generation.insert(name.clone(), generation);
        state.entries.insert(name, new_entry.clone());
        // Bounds `last_generation`'s growth (module docs on
        // `RegistryState::last_generation`) — runs after the insert above
        // so the tombstone this call just wrote can never be the one
        // pruned.
        prune_tombstones(&mut state);
        Ok(RegisterOutcome {
            entry: new_entry,
            replaced_generation,
            replaced_entry,
        })
    }

    /// Undo an [`Registry::admit`] whose caller never got to publish the
    /// connection it authorized (`reverse/listen.rs`'s `register_connection`:
    /// the control-stream `Hello` reply that would have confirmed the
    /// registration to the peer failed to send). Only touches the entry
    /// currently under `name` if it is still exactly the one `admit`
    /// produced (`generation` match) — a concurrent successful
    /// re-registration already superseding it must not be clobbered by a
    /// late rollback of the admission it replaced.
    ///
    /// `replaced` is the [`RegisterOutcome::replaced_entry`] from the same
    /// `admit` call: `None` restores nothing (a fresh registration simply
    /// disappears, freeing the name); `Some` restores the exact entry that
    /// admission replaced, so a NAT-rebind reconnect whose *second* `Hello`
    /// reply fails to send leaves the still-live first connection's
    /// registry row exactly as it was before the failed attempt.
    pub fn rollback(&self, name: &str, generation: u64, replaced: Option<ReverseEntry>) {
        let mut state = self.lock();
        let still_current =
            matches!(state.entries.get(name), Some(e) if e.generation == generation);
        if !still_current {
            return;
        }
        // Deliberately does not touch `last_generation`: even though this
        // registration is undone, `generation` was handed out and must
        // never be reissued (`admit`'s docs — the tombstone survives a
        // rollback exactly like it survives a `sweep_expired` eviction).
        match replaced {
            Some(previous) => {
                state.entries.insert(name.to_string(), previous);
            }
            None => {
                state.entries.remove(name);
            }
        }
    }

    /// Transition a live entry to [`EntryState::Stale`] on connection loss
    /// (`docs/design/protocol.md` §11-4). Called by `reverse/listen.rs`'s
    /// probe driver when [`crate::client::pathwatch::PathWatch::dead`]
    /// fires for a registered connection.
    ///
    /// A no-op — mirrors [`Registry::rollback`]'s "only touch what I still
    /// recognize" guard — unless `(name, generation)` is still exactly the
    /// live entry: a newer registration may already have superseded it
    /// (`admit`'s replace path), or a previous death report for the same
    /// generation may already have marked it stale (this method is not
    /// idempotent-by-accident, it is idempotent because a second call finds
    /// `state != Live` and declines). Returns the entry as it stands right
    /// after the transition on success, so the caller's `"lost"` diagnostic
    /// needs no second [`Registry::get`].
    pub fn mark_stale(&self, name: &str, generation: u64) -> Option<ReverseEntry> {
        let mut state = self.lock();
        let entry = state.entries.get_mut(name)?;
        if entry.generation != generation || entry.state != EntryState::Live {
            return None;
        }
        entry.state = EntryState::Stale;
        entry.stale_since = Some(self.clock.now());
        Some(entry.clone())
    }

    /// Remove every [`EntryState::Stale`] entry whose `retention` has
    /// elapsed since [`Registry::mark_stale`] transitioned it
    /// (`docs/design/protocol.md` §11-4 — "표시했다가 `stale_retention` 후
    /// 제거한다"). Pure state, driven by this registry's injected
    /// [`Clock`] — `reverse/listen.rs`'s sweeper decides *when* to call
    /// this (a periodic tick, `Broker::run_reaper`'s exact shape); this
    /// method only decides *what* is due. Removing an entry never touches
    /// its `last_generation` tombstone (`admit`'s docs) — a later
    /// registration under the freed name still continues the same counter.
    /// Returns the entries removed, for the caller's `"expired"`
    /// diagnostic.
    pub fn sweep_expired(&self, retention: Duration) -> Vec<ReverseEntry> {
        let now = self.clock.now();
        let mut state = self.lock();
        let due: Vec<String> = state
            .entries
            .iter()
            .filter_map(|(name, e)| match (e.state, e.stale_since) {
                (EntryState::Stale, Some(since))
                    if now.saturating_duration_since(since) >= retention =>
                {
                    Some(name.clone())
                }
                _ => None,
            })
            .collect();
        due.into_iter()
            .filter_map(|name| state.entries.remove(&name))
            .collect()
    }
}

/// Shape check applied to `offered_name` before it is ever treated as an
/// ACL resource — see [`Registry::resolve_name`].
fn validate_offered_name_shape(offered_name: &str) -> Result<(), OpError> {
    if offered_name.is_empty() || wire::valid_host_name(offered_name) {
        Ok(())
    } else {
        Err(OpError::new(
            ErrorCode::InvalidArgument,
            "offered_name must be empty or a valid host name (1..=64 of [A-Za-z0-9._-])",
        )
        .with_retryable(false))
    }
}

/// The one `PERMISSION_DENIED` refusal every failure mode at the
/// `host.reverse` seam returns: no principal, no resource, no hint of
/// *which* check failed. Mirrors `Server::authorize`'s deliberately opaque
/// idiom (`crates/qsh-core/src/server/mod.rs`, `"peer is not allowed to
/// {action} on this host"` — `docs/design/architecture.md` §6) so that a
/// peer probing this seam cannot distinguish "no trust-store alias", "alias
/// failed shape validation" (this file, [`Registry::resolve_name`]), or
/// "denied by ACL policy" (`super::admit`'s choke point) from one another —
/// any of those distinctions would leak whether this peer's certificate is
/// pinned or let it learn the controller's configuration posture
/// (adversarial review finding). `super::admit` reuses this exact function
/// for its choke-point deny so all refusals at this seam read identically;
/// operator-facing detail belongs in the audit record instead
/// (`docs/design/architecture.md` §6), never in this message.
pub(crate) fn host_reverse_denied() -> OpError {
    OpError::new(
        ErrorCode::PermissionDenied,
        "peer is not allowed to host.reverse on this host",
    )
    .with_retryable(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::TestClock;
    use proptest::prelude::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:4433".parse().unwrap()
    }

    fn registry(allow_advertised_names: bool) -> Registry {
        Registry::new(Arc::new(TestClock::new()), allow_advertised_names)
    }

    fn entry<'a>(fingerprint: &'a str, principal: &'a str) -> AdmittedEntry<'a> {
        AdmittedEntry {
            fingerprint,
            principal,
            address: addr(),
            capabilities: vec!["exec".to_string()],
        }
    }

    fn stub_entry(name: &str, generation: u64) -> ReverseEntry {
        ReverseEntry {
            name: name.to_string(),
            fingerprint: "sha256:a".to_string(),
            principal: "device:x".to_string(),
            address: addr(),
            capabilities: Vec::new(),
            registered_at: "2026-01-01T00:00:00Z".to_string(),
            generation,
            state: EntryState::Live,
            stale_since: None,
        }
    }

    // ---- name resolution priority table (PLAN.md Step 3 (c)) ----

    #[test]
    fn alias_present_wins_over_offered_name() {
        let r = registry(true);
        let name = r
            .resolve_name(Some("personal-mac"), "attacker-chosen-name")
            .expect("alias wins");
        assert_eq!(name, "personal-mac");
    }

    #[test]
    fn empty_offered_name_with_alias_resolves_to_the_alias() {
        let r = registry(false);
        let name = r
            .resolve_name(Some("personal-mac"), "")
            .expect("empty offered_name is fine when an alias exists");
        assert_eq!(name, "personal-mac");
    }

    #[test]
    fn no_alias_and_advertised_names_disallowed_is_permission_denied() {
        let r = registry(false);
        let err = r
            .resolve_name(None, "some-name")
            .expect_err("no alias, advertised names off");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn no_alias_and_advertised_names_allowed_uses_offered_name() {
        let r = registry(true);
        let name = r
            .resolve_name(None, "advertised-name")
            .expect("advertised name accepted");
        assert_eq!(name, "advertised-name");
    }

    #[test]
    fn shape_violation_is_invalid_argument() {
        let r = registry(true);
        // Contains a space: not `valid_host_name` and not empty.
        let err = r
            .resolve_name(Some("personal-mac"), "not a valid name")
            .expect_err("malformed offered_name");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn no_alias_no_offered_name_and_advertised_names_disallowed_is_permission_denied() {
        let r = registry(false);
        let err = r.resolve_name(None, "").expect_err("nothing to resolve to");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    /// An operator-pinned alias that doesn't satisfy `wire::valid_host_name`
    /// (`Ops::trust_add` only rejects *empty* names, so this is reachable in
    /// practice) must fail closed — `PERMISSION_DENIED`, not
    /// `INVALID_ARGUMENT` — with the exact same opaque message the no-alias
    /// case uses, never revealing the alias content (adversarial review
    /// finding).
    #[test]
    fn malformed_alias_is_permission_denied_with_the_generic_message() {
        let r = registry(true);
        let err = r
            .resolve_name(Some("mac/work"), "attacker-chosen-name")
            .expect_err("alias contains '/', not a valid host name");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.message, host_reverse_denied().message);
    }

    #[test]
    fn oversized_alias_is_permission_denied() {
        let r = registry(true);
        let huge = "a".repeat(65);
        let err = r
            .resolve_name(Some(&huge), "")
            .expect_err("alias exceeds the 64-byte host-name bound");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    /// The no-alias `PERMISSION_DENIED` and the malformed-alias
    /// `PERMISSION_DENIED` must be textually indistinguishable — that's the
    /// whole point of [`host_reverse_denied`] (finding 2).
    #[test]
    fn no_alias_and_malformed_alias_denials_carry_the_identical_message() {
        let r = registry(false);
        let no_alias = r.resolve_name(None, "").expect_err("no alias");
        let bad_alias = r
            .resolve_name(Some("mac/work"), "")
            .expect_err("malformed alias");
        assert_eq!(no_alias.message, bad_alias.message);
    }

    // ---- conflict / generation ----

    #[test]
    fn conflicting_fingerprint_under_a_live_name_is_invalid_argument_and_creates_nothing() {
        let r = registry(false);
        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        assert_eq!(first.entry.generation, 0);

        let err = r
            .admit("shared".to_string(), entry("sha256:b", "device:shared"))
            .expect_err("different fingerprint, same name");
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        // The original entry is untouched — no silent overwrite.
        let still = r.get("shared").expect("original entry remains");
        assert_eq!(still.fingerprint, "sha256:a");
        assert_eq!(still.generation, 0);
    }

    #[test]
    fn conflicting_fingerprint_under_a_stale_name_is_also_denied() {
        // A stale entry still "occupies" its name — the whole point of
        // staying `Stale` instead of vanishing immediately is to deny a
        // squatter the gap between death and retention expiry
        // (`admit`'s doc comment).
        let (r, _clock) = clocked_registry(false);
        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        r.mark_stale("shared", first.entry.generation)
            .expect("goes stale");

        let err = r
            .admit("shared".to_string(), entry("sha256:b", "device:shared"))
            .expect_err("different fingerprint, stale name");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        let still = r.get("shared").expect("stale entry untouched");
        assert_eq!(still.fingerprint, "sha256:a");
        assert_eq!(still.state, EntryState::Stale);
    }

    #[test]
    fn same_fingerprint_reregistering_a_stale_name_revives_it_as_live() {
        let (r, _clock) = clocked_registry(false);
        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        r.mark_stale("shared", first.entry.generation)
            .expect("goes stale");

        let second = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("same fingerprint revives it");
        assert_eq!(second.entry.state, EntryState::Live);
        assert!(second.entry.stale_since.is_none());
        assert_eq!(second.entry.generation, 1);
        assert_eq!(second.replaced_generation, Some(0));
    }

    #[test]
    fn same_fingerprint_reregistering_replaces_and_advances_generation() {
        let r = registry(false);
        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        assert_eq!(first.entry.generation, 0);
        assert!(first.replaced_generation.is_none());

        let second = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("reconnect from the same peer replaces the entry");
        assert_eq!(second.entry.generation, 1);
        assert_eq!(second.replaced_generation, Some(0));
        assert_eq!(r.snapshot().len(), 1, "replaced, not duplicated");
    }

    #[test]
    fn registered_at_uses_the_injected_clock() {
        let r = registry(false);
        let outcome = r
            .admit(
                "personal-mac".to_string(),
                entry("sha256:a", "device:personal-mac"),
            )
            .expect("registers");
        // Pin the literal RFC 3339 shape against `TestClock`'s fixed start
        // instant (`broker::clock::TestClock::WALL_START_UNIX_SECS` =
        // 2026-01-01T00:00:00Z) instead of recomputing the expected value
        // with the function under test — a self-referential assertion would
        // never catch a formatting regression.
        assert_eq!(outcome.entry.registered_at, "2026-01-01T00:00:00Z");
    }

    // ---- rollback (undo an admit whose Hello reply never made it out) ----

    #[test]
    fn rollback_of_a_fresh_registration_frees_the_name() {
        let r = registry(false);
        let outcome = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        assert!(outcome.replaced_entry.is_none());

        r.rollback("shared", outcome.entry.generation, outcome.replaced_entry);
        assert!(r.get("shared").is_none(), "name is free again");
        assert!(r.snapshot().is_empty());
    }

    #[test]
    fn rollback_of_a_replace_restores_the_previous_entry() {
        let r = registry(false);
        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        let second = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("same-fingerprint reconnect replaces");
        assert_eq!(second.entry.generation, 1);
        assert_eq!(second.replaced_entry.as_ref(), Some(&first.entry));

        r.rollback(
            "shared",
            second.entry.generation,
            second.replaced_entry.clone(),
        );
        let restored = r.get("shared").expect("the first entry is back");
        assert_eq!(restored, first.entry, "byte-for-byte the pre-image");
    }

    #[test]
    fn a_rolled_back_generation_is_never_reissued() {
        // Regression for the adversarial review finding: `rollback`'s own
        // doc comment claims a rolled-back generation "must never be
        // reissued", but the replace branch used to compute the next
        // generation purely from `existing.generation`, which a rollback
        // moves *backwards* — so the very next admit handed the same
        // number straight back out.
        let r = registry(false);
        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        let second = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("reconnect");
        assert_eq!(second.entry.generation, 1);

        r.rollback(
            "shared",
            second.entry.generation,
            second.replaced_entry.clone(),
        );
        assert_eq!(
            r.get("shared").unwrap().generation,
            0,
            "rollback restores generation 0"
        );

        let third = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("registers again after the rollback");
        assert_eq!(
            third.entry.generation, 2,
            "generation 1 was already handed out once and rolled back — it must not come back"
        );
        assert_ne!(third.entry.generation, first.entry.generation);
        assert_ne!(third.entry.generation, second.entry.generation);
    }

    #[test]
    fn prune_tombstones_bounds_growth_without_evicting_a_live_names_tombstone() {
        let mut state = RegistryState::default();
        state
            .entries
            .insert("still-live".to_string(), stub_entry("still-live", 0));
        state.last_generation.insert("still-live".to_string(), 0);
        for i in 0..(MAX_TOMBSTONES + 5) {
            state.last_generation.insert(format!("cold-{i}"), 0);
        }
        assert!(state.last_generation.len() > MAX_TOMBSTONES);

        prune_tombstones(&mut state);

        assert!(
            state.last_generation.len() <= MAX_TOMBSTONES,
            "growth must be bounded once the cap is exceeded"
        );
        assert!(
            state.last_generation.contains_key("still-live"),
            "a currently registered name's tombstone must never be evicted \
             — doing so would let a later admit reissue a generation that \
             name's own history already used"
        );
    }

    #[test]
    fn rollback_is_a_no_op_once_a_newer_registration_already_superseded_it() {
        let r = registry(false);
        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        // A concurrent successful reconnect moves the name to generation 1
        // before the late rollback of generation 0 arrives.
        r.admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("reconnect");

        r.rollback("shared", first.entry.generation, None);
        let still = r.get("shared").expect("generation 1 must survive");
        assert_eq!(
            still.generation, 1,
            "late rollback of a stale generation is a no-op"
        );
    }

    #[test]
    fn admit_stores_a_fresh_entry_as_live() {
        let r = registry(false);
        let outcome = r
            .admit(
                "personal-mac".to_string(),
                entry("sha256:a", "device:personal-mac"),
            )
            .expect("registers");
        assert_eq!(outcome.entry.state, EntryState::Live);
        assert!(outcome.entry.stale_since.is_none());
        assert_eq!(
            r.get("personal-mac").expect("entry present").state,
            EntryState::Live
        );
    }

    // ---- stale transition (`PLAN.md` M3 Step 4) ----

    /// A `TestClock`-backed registry, for the deterministic stale/retention
    /// tests below (`docs/design/testing.md` L2 — no `sleep()`).
    fn clocked_registry(allow_advertised_names: bool) -> (Registry, TestClock) {
        let clock = TestClock::new();
        (
            Registry::new(Arc::new(clock.clone()), allow_advertised_names),
            clock,
        )
    }

    #[test]
    fn mark_stale_transitions_a_live_entry_and_stamps_stale_since() {
        let (r, clock) = clocked_registry(false);
        let outcome = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        clock.advance(Duration::from_secs(7));

        let staled = r
            .mark_stale("shared", outcome.entry.generation)
            .expect("live entry at this generation transitions");
        assert_eq!(staled.state, EntryState::Stale);
        assert_eq!(staled.stale_since, Some(clock.now()));
        // Nothing else about the entry changes.
        assert_eq!(staled.fingerprint, "sha256:a");
        assert_eq!(staled.generation, outcome.entry.generation);

        let still = r.get("shared").expect("entry remains, just stale");
        assert_eq!(still.state, EntryState::Stale);
    }

    #[test]
    fn mark_stale_is_a_no_op_once_a_newer_registration_already_superseded_it() {
        let (r, _clock) = clocked_registry(false);
        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        // A reconnect replaces it before the old connection's death report
        // arrives — the exact race `Registry::rollback`'s doc comment
        // already documents for the sibling method.
        r.admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("reconnect replaces");

        let result = r.mark_stale("shared", first.entry.generation);
        assert!(result.is_none(), "stale generation is not the live one");
        let still = r.get("shared").expect("generation 1 must survive live");
        assert_eq!(still.state, EntryState::Live);
        assert_eq!(still.generation, 1);
    }

    #[test]
    fn mark_stale_is_idempotent_on_a_repeated_call() {
        let (r, clock) = clocked_registry(false);
        let outcome = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        clock.advance(Duration::from_secs(1));
        let first = r
            .mark_stale("shared", outcome.entry.generation)
            .expect("first transition succeeds");
        clock.advance(Duration::from_secs(1));
        // A second death report for the same generation (e.g. both the
        // probe driver and a concurrent path) must not re-stamp
        // `stale_since` or otherwise change anything.
        let second = r.mark_stale("shared", outcome.entry.generation);
        assert!(second.is_none());
        assert_eq!(
            r.get("shared").unwrap().stale_since,
            first.stale_since,
            "stale_since is stamped once, not refreshed"
        );
    }

    #[test]
    fn mark_stale_unknown_name_is_a_no_op() {
        let (r, _clock) = clocked_registry(false);
        assert!(r.mark_stale("nobody-home", 0).is_none());
    }

    // ---- retention expiry (`docs/design/protocol.md` §11-4) ----

    #[test]
    fn sweep_expired_removes_nothing_before_retention_elapses() {
        let (r, clock) = clocked_registry(false);
        let outcome = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("registers");
        r.mark_stale("shared", outcome.entry.generation)
            .expect("goes stale");

        let retention = Duration::from_secs(120);
        clock.advance(Duration::from_secs(119));
        let removed = r.sweep_expired(retention);
        assert!(removed.is_empty(), "not due yet");
        assert!(
            r.get("shared").is_some(),
            "entry still present, still stale"
        );
    }

    #[test]
    fn sweep_expired_removes_exactly_at_the_retention_boundary() {
        let (r, clock) = clocked_registry(false);
        let outcome = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("registers");
        r.mark_stale("shared", outcome.entry.generation)
            .expect("goes stale");

        let retention = Duration::from_secs(120);
        clock.advance(retention);
        let removed = r.sweep_expired(retention);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "shared");
        assert!(r.get("shared").is_none(), "removed, not just marked");
        assert!(r.snapshot().is_empty());
    }

    #[test]
    fn sweep_expired_never_touches_a_live_entry() {
        let (r, clock) = clocked_registry(false);
        r.admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("registers, stays live");
        clock.advance(Duration::from_secs(10_000));
        let removed = r.sweep_expired(Duration::from_secs(1));
        assert!(removed.is_empty());
        assert_eq!(
            r.get("shared").expect("still there").state,
            EntryState::Live
        );
    }

    #[test]
    fn sweep_expired_only_removes_entries_actually_due_leaving_others() {
        let (r, clock) = clocked_registry(false);
        let old = r
            .admit("old".to_string(), entry("sha256:a", "device:old"))
            .expect("registers");
        r.mark_stale("old", old.entry.generation).expect("stale");
        clock.advance(Duration::from_secs(60));
        let recent = r
            .admit("recent".to_string(), entry("sha256:b", "device:recent"))
            .expect("registers");
        r.mark_stale("recent", recent.entry.generation)
            .expect("stale");

        // "old" went stale at t=0, "recent" at t=60. At t=125 only "old"
        // (125s stale) has cleared a 120s retention; "recent" (65s stale)
        // has not.
        clock.advance(Duration::from_secs(65));
        let removed = r.sweep_expired(Duration::from_secs(120));
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "old");
        assert!(r.get("old").is_none());
        assert!(r.get("recent").is_some(), "not due yet");
    }

    // ---- generation monotonicity across replace/stale/remove (`PLAN.md`
    // M3 Step 4 (1): "the registry generation stays strictly monotonic
    // across replace/stale/remove") ----

    #[test]
    fn generation_survives_a_stale_eviction_and_keeps_advancing() {
        let (r, clock) = clocked_registry(false);
        let retention = Duration::from_secs(120);

        let first = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        assert_eq!(first.entry.generation, 0);
        r.mark_stale("shared", 0).expect("goes stale");
        clock.advance(retention);
        let removed = r.sweep_expired(retention);
        assert_eq!(removed.len(), 1, "the name is fully freed");
        assert!(r.get("shared").is_none());

        // Re-registration under the freed name — by the same fingerprint,
        // as a real reconnect would be, or even a different one now that
        // the slot is genuinely empty — must not restart at generation 0.
        let second = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("re-registers after eviction");
        assert_eq!(
            second.entry.generation, 1,
            "generation must never repeat, even across a full remove"
        );
        assert!(
            second.replaced_generation.is_none(),
            "no live entry to replace"
        );
    }

    #[test]
    fn generation_survives_a_rollback_and_keeps_advancing() {
        let (r, _clock) = clocked_registry(false);
        let outcome = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("first registration");
        r.rollback("shared", outcome.entry.generation, None);
        assert!(r.get("shared").is_none(), "rolled back, name is free");

        let second = r
            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
            .expect("re-registers");
        assert_eq!(
            second.entry.generation, 1,
            "a rolled-back generation must never be reissued"
        );
    }

    proptest! {
        /// Any sequence of admit / mark_stale-then-sweep / rollback
        /// operations on one name never produces a repeated `generation`
        /// value across the whole history — the property `PLAN.md` M3 Step
        /// 4 (1) names explicitly. `docs/design/testing.md` L2 property
        /// test discipline.
        #[test]
        fn generation_is_never_repeated_across_any_replace_stale_remove_sequence(
            ops in proptest::collection::vec(0u8..3, 1..30),
        ) {
            let (r, clock) = clocked_registry(false);
            let retention = Duration::from_secs(10);
            let mut seen = std::collections::HashSet::new();
            let mut live_generation: Option<u64> = None;

            for op in ops {
                match op {
                    // Register (fresh or same-fingerprint replace).
                    0 => {
                        let outcome = r
                            .admit("shared".to_string(), entry("sha256:a", "device:shared"))
                            .expect("same fingerprint always admits");
                        prop_assert!(
                            seen.insert(outcome.entry.generation),
                            "generation {} reused",
                            outcome.entry.generation
                        );
                        live_generation = Some(outcome.entry.generation);
                    }
                    // Mark the live entry stale, then let retention elapse
                    // and sweep it away.
                    1 => {
                        if let Some(generation) = live_generation
                            && r.mark_stale("shared", generation).is_some()
                        {
                            clock.advance(retention);
                            r.sweep_expired(retention);
                            live_generation = None;
                        }
                    }
                    // Roll back the live entry to nothing.
                    _ => {
                        if let Some(generation) = live_generation {
                            r.rollback("shared", generation, None);
                            live_generation = None;
                        }
                    }
                }
            }
        }
    }
}
