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

use qsh_proto::{ErrorCode, wire};

use crate::broker::Clock;
use crate::ops::OpError;

/// Registration state of a [`ReverseEntry`]. PR 3a only ever produces
/// [`EntryState::Live`] — `Stale` is Step 4's connection-loss bookkeeping
/// (`docs/design/protocol.md` §11-4, `PLAN.md` Step 4). The variant is
/// reserved now so the field never needs a breaking shape change later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// As far as this registry knows, the registering connection is still
    /// up.
    Live,
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
    /// Live vs. stale. PR 3a only ever inserts [`EntryState::Live`]; Step 4
    /// adds the stale transition.
    pub state: EntryState,
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
    entries: Mutex<HashMap<String, ReverseEntry>>,
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
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The entry registered under `name`, if any.
    pub fn get(&self, name: &str) -> Option<ReverseEntry> {
        self.lock().get(name).cloned()
    }

    /// Every entry, sorted by name — deterministic, for `host.list` (Step
    /// 5) and tests.
    pub fn snapshot(&self) -> Vec<ReverseEntry> {
        let mut entries: Vec<_> = self.lock().values().cloned().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ReverseEntry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
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
        let mut entries = self.lock();
        // The next generation is derived purely from the live entry
        // (`existing.generation + 1`, or `0` when there is none) — there is
        // no per-name counter that survives entry removal. PR 3a never
        // removes entries, so this is not a live defect yet, but Step 4's
        // stale-eviction (`docs/design/protocol.md` §11-4) removes entries
        // on connection loss, and once it does, a name that gets evicted
        // and re-registered would silently restart at generation `0` here —
        // colliding with 3b's `(name, generation)`-keyed connection table.
        // Step 4 MUST introduce a per-name counter (or tombstone) that
        // survives removal; this map-derived computation is only valid
        // while entries are never removed.
        let (generation, replaced_generation, replaced_entry) = match entries.get(&name) {
            Some(existing) if existing.fingerprint != entry.fingerprint => {
                return Err(OpError::new(
                    ErrorCode::InvalidArgument,
                    format!("{name:?} is already registered to a different peer"),
                )
                .with_retryable(false));
            }
            Some(existing) => (
                existing.generation + 1,
                Some(existing.generation),
                Some(existing.clone()),
            ),
            None => (0, None, None),
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
        };
        entries.insert(name, new_entry.clone());
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
        let mut entries = self.lock();
        let still_current = matches!(entries.get(name), Some(e) if e.generation == generation);
        if !still_current {
            return;
        }
        match replaced {
            Some(previous) => {
                entries.insert(name.to_string(), previous);
            }
            None => {
                entries.remove(name);
            }
        }
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
        assert_eq!(
            r.get("personal-mac").expect("entry present").state,
            EntryState::Live
        );
    }
}
