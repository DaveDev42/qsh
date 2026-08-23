//! The pure, single-threaded `LOCAL_CONTROL` multiplexer core
//! (`docs/design/protocol.md` §11-3, `PLAN.md` M3 Step 6).
//!
//! One `Listen`-side daemon holds exactly one live reverse QUIC connection
//! per registered host and, on top of it, zero or more `LOCAL_CONTROL`
//! conduits — one per attached CLI process. Every conduit mints its own
//! `ControlMessage.request_id` space independently (`PLAN.md` M3 Step 6
//! (a)), so two different CLI processes can legitimately send a request
//! with the *same* `peer_request_id` at the same time. [`ControlMux`] is
//! the table that keeps those spaces apart: it hands out a fresh,
//! globally-unique `daemon_request_id` for every outbound request, remembers
//! which `(ConduitId, peer_request_id)` minted it, and — when the matching
//! `Response` comes back on the shared QUIC control stream — resolves the
//! `daemon_request_id` back to exactly that pair so the daemon can restore
//! the peer's id and deliver the `Response` to (only) the conduit that
//! asked for it.
//!
//! This module owns **no I/O**: no socket, no QUIC stream, no async. It is
//! deliberately a plain, synchronous state machine so it can be driven and
//! checked by property tests without a runtime (`docs/design/testing.md`
//! L3) and so [`crate::localctl::daemon`] (the transport bridge, PR
//! following this one) can hold it behind a plain `Mutex` or run it
//! inline on whatever task owns the QUIC connection. Nothing here names
//! `qsh_transport`, `quinn`, `rustls`, or a UDS type.
//!
//! ## The one invariant that matters
//!
//! **Every table insert has exactly one removal**, and the removal is
//! always one of these three, never more than one:
//!
//! 1. the matching [`ControlMux::map_inbound`] call, when the target's
//!    `Response` for that `daemon_request_id` arrives;
//! 2. [`ControlMux::unregister_conduit`], when that conduit's own UDS
//!    connection dies — every entry it still owns is removed *in full*
//!    from this table (no leaked local bookkeeping); the *target-side*
//!    work behind a still-in-flight long-poll cannot be cancelled
//!    per-request on the shared QUIC control stream, so
//!    `crate::reverse::listen::ControlHub` bounds exposure to that
//!    instead of cancelling it (its own module docs) — and a `Response`
//!    that later arrives for one of these now-gone ids is simply dropped
//!    by the caller ([`Self::map_inbound`] returning `None`), no
//!    exception: session lifetime is decoupled from connection lifetime
//!    (`docs/PRD.md`'s core premise), so the session the target may have
//!    already created for it stays alive exactly as it would on the
//!    forward route — discoverable via `session.list`, closable via
//!    `session.close` — and the relay never originates a `session.close`
//!    on its own initiative;
//! 3. the daemon iterating [`ControlMux::conduit_ids`] and calling
//!    `unregister_conduit` on each, when the reverse QUIC connection
//!    itself dies (every conduit of that host ends together).
//!
//! A `daemon_request_id` that is still in the table after all three have
//! had their chance is a bug in the caller, not in this module — the table
//! never times entries out or drops them silently.
//!
//! ## What this module does *not* decide
//!
//! - **Ping/Pong** never enters the request table at all: [`classify`]
//!   lets the daemon recognize a `Ping` body before it would otherwise
//!   call [`ControlMux::map_outbound`], because a `Ping` is answered
//!   locally with a `Pong` and never forwarded onto the QUIC connection
//!   (`PLAN.md` M3 Step 6 (a) — "liveness는 연결 소유자의 몫").
//! - **Authorization.** This table only ever moves opaque ids and
//!   [`crate::broker::SessionId`] values around; it never inspects a
//!   request body, never calls `Authorizer::check`, and is not itself a
//!   place any ACL decision could hide (`docs/CLI.md` §11, this module's
//!   parent docs). The target evaluates its own ACL against the
//!   controller principal exactly as it does on the forward path —
//!   nothing here grants reachability *or* authority.
//! - **Wire I/O.** Callers pass in already-decoded
//!   [`qsh_proto::wire::SessionEvent`] values and get back the
//!   [`ConduitId`]s to deliver them to; encoding/decoding and the actual
//!   socket writes happen one layer up.

use std::collections::{HashMap, HashSet};

use qsh_proto::wire::{self, control_message};

use crate::broker::SessionId;

/// Identifies one `LOCAL_CONTROL` conduit — one accepted UDS connection
/// multiplexed onto a host's reverse QUIC connection. The daemon mints
/// these (e.g. from a per-process monotonic counter); [`ControlMux`]
/// treats the value as opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConduitId(pub u64);

/// Per-conduit in-flight cap. Deliberately the same magnitude as
/// [`crate::server::MAX_INFLIGHT_REQUESTS_PER_CONN`] (`PLAN.md` M3 Step 6
/// (a): "conduit당 상한(`MAX_INFLIGHT_REQUESTS_PER_CONN`과 같은 64)") but
/// kept as an independent constant — the two bound different things (one
/// QUIC connection's inflight blocking requests vs. one local conduit's
/// inflight relayed requests) and must be free to move independently.
pub const MAX_INFLIGHT_PER_CONDUIT: usize = 64;

/// Returned by [`ControlMux::map_outbound`] when `conduit` already has
/// [`MAX_INFLIGHT_PER_CONDUIT`] requests awaiting a response. The caller
/// answers the peer's request with `RESOURCE_EXHAUSTED`
/// (`docs/CLI.md` §3.3) locally, without ever placing it on the QUIC
/// connection — this conduit's own overload never affects any other
/// conduit's cap or the underlying connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exhausted;

/// What a decoded `ControlMessage` body is, for the distinctions this
/// module needs the daemon to make before touching the request table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A `Ping` — answer locally with a `Pong`, never call
    /// [`ControlMux::map_outbound`] for it.
    Ping,
    /// A body shape a conduit may legitimately send that expects a
    /// correlated `Response` — route it through [`ControlMux::map_outbound`].
    Request,
    /// A body shape a conduit must never send (`Pong`, `Response`,
    /// `SessionEvent`, `Hello`, or an unset/unrecognized oneof) — these
    /// are conduit protocol errors, not requests: forwarding one onto the
    /// shared QUIC control stream would either never be answered
    /// (permanently burning an in-flight slot for a `Response` that never
    /// arrives — a target never replies to a `Pong`/`Response`/
    /// `SessionEvent`) or perturb every other conduit of the same host
    /// (an injected `Pong` resets the target's own liveness-probe strike
    /// counter; a mid-connection `Hello` is meaningless post-registration)
    /// (adversarial review finding). The caller answers `INVALID_ARGUMENT`
    /// on this conduit only, without ever touching [`ControlMux::map_outbound`]
    /// or the QUIC connection.
    Invalid,
}

/// Classify a `ControlMessage` body a conduit sent. This function only
/// exists to pull `Ping` out before it reaches the request table and to
/// reject the shapes a conduit must never legitimately send — it is not
/// itself an ACL decision (this module's own docs).
pub fn classify(body: &control_message::Body) -> MessageKind {
    match body {
        control_message::Body::Ping(_) => MessageKind::Ping,
        control_message::Body::Pong(_)
        | control_message::Body::Response(_)
        | control_message::Body::SessionEvent(_)
        | control_message::Body::Hello(_) => MessageKind::Invalid,
        control_message::Body::SessionOpen(_)
        | control_message::Body::SessionGet(_)
        | control_message::Body::SessionList(_)
        | control_message::Body::SessionRead(_)
        | control_message::Body::SessionWrite(_)
        | control_message::Body::SessionResize(_)
        | control_message::Body::SessionClose(_)
        | control_message::Body::SessionAttach(_)
        | control_message::Body::ExecStart(_) => MessageKind::Request,
    }
}

/// The pure `LOCAL_CONTROL` multiplexer state. See the module docs for the
/// invariant every method call must preserve.
#[derive(Debug)]
pub struct ControlMux {
    /// Next `daemon_request_id` to hand out. Monotonically increasing for
    /// the lifetime of one `ControlMux` (one host's reverse connection) —
    /// never reused, so a late/duplicate `Response` for a since-removed
    /// id can never collide with a fresh request. Starts at **1**, never
    /// 0: `qsh/wire/v1.proto`'s `ControlMessage.request_id` reserves 0 for
    /// asynchronous events (`docs/design/protocol.md` §9) and the target's
    /// `authorize_stream` treats a `request_id` of 0 as its own
    /// connection-level-decision sentinel (`server/mod.rs`) — handing out
    /// 0 here would make the daemon's first relayed request on every hub
    /// collide with both (adversarial review finding).
    next_daemon_request_id: u64,
    /// `daemon_request_id -> (conduit, peer_request_id)`. The single
    /// source of truth for in-flight requests; every other collection
    /// below is a redundant index over this one, kept in lock-step.
    inflight: HashMap<u64, (ConduitId, u64)>,
    /// `conduit -> its own daemon_request_ids currently in `inflight``.
    /// A conduit's key exists here (possibly with an empty set) from
    /// [`Self::register_conduit`] until [`Self::unregister_conduit`] —
    /// that presence is also how [`Self::conduit_ids`] and the
    /// `writer_changed` broadcast in [`Self::route_event`] know which
    /// conduits are live.
    per_conduit: HashMap<ConduitId, HashSet<u64>>,
    /// `session_id -> conduits subscribed to that session's events`.
    subscriptions: HashMap<SessionId, HashSet<ConduitId>>,
    /// `conduit -> session_ids it is subscribed to` — the reverse index
    /// [`Self::unregister_conduit`] needs to remove a dying conduit's
    /// subscriptions without a full scan of `subscriptions`.
    conduit_subscriptions: HashMap<ConduitId, HashSet<SessionId>>,
}

impl Default for ControlMux {
    fn default() -> Self {
        Self {
            // See the field's own doc comment: 0 is reserved on the wire,
            // so the counter starts at 1.
            next_daemon_request_id: 1,
            inflight: HashMap::new(),
            per_conduit: HashMap::new(),
            subscriptions: HashMap::new(),
            conduit_subscriptions: HashMap::new(),
        }
    }
}

impl ControlMux {
    /// A fresh multiplexer for one host's reverse connection, with no
    /// conduits registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a conduit before routing any of its requests or events
    /// through it. Idempotent: registering an already-registered conduit
    /// leaves its existing in-flight table and subscriptions untouched.
    /// A conduit with zero in-flight requests is still present for
    /// [`Self::conduit_ids`] and the `writer_changed` broadcast in
    /// [`Self::route_event`] — registration, not "has ever sent a
    /// request", is what makes a conduit live.
    pub fn register_conduit(&mut self, conduit: ConduitId) {
        self.per_conduit.entry(conduit).or_default();
    }

    /// Remove a conduit and everything it owns: every `daemon_request_id`
    /// still in flight for it (returned, sorted — `crate::reverse::listen::ControlHub::unregister_conduit`
    /// uses it to drop the local table entries for these ids; the shared
    /// QUIC control stream itself is not, and cannot be, reset per-request
    /// — see that method's own doc for what actually bounds the exposure,
    /// `docs/design/protocol.md` §11-3), and every session subscription
    /// it held. A conduit that was never registered (or was already
    /// unregistered) returns an empty vec — unregistering twice is safe
    /// and a no-op the second time.
    pub fn unregister_conduit(&mut self, conduit: ConduitId) -> Vec<u64> {
        let ids = self.per_conduit.remove(&conduit).unwrap_or_default();
        for id in &ids {
            self.inflight.remove(id);
        }
        if let Some(sessions) = self.conduit_subscriptions.remove(&conduit) {
            for session_id in sessions {
                if let Some(subscribers) = self.subscriptions.get_mut(&session_id) {
                    subscribers.remove(&conduit);
                    if subscribers.is_empty() {
                        self.subscriptions.remove(&session_id);
                    }
                }
            }
        }
        let mut out: Vec<u64> = ids.into_iter().collect();
        out.sort_unstable();
        out
    }

    /// Every currently-registered conduit, sorted. The daemon walks this
    /// (calling [`Self::unregister_conduit`] on each) when the underlying
    /// reverse QUIC connection dies, so "every conduit of that host ends
    /// with a clear typed error" (`PLAN.md` M3 Step 6 (a)) has a concrete
    /// set to iterate.
    pub fn conduit_ids(&self) -> Vec<ConduitId> {
        let mut ids: Vec<ConduitId> = self.per_conduit.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// How many requests are currently in flight for `conduit` (for tests
    /// and for a caller that wants to pre-check the cap; `map_outbound`
    /// enforces it regardless).
    pub fn in_flight_count(&self, conduit: ConduitId) -> usize {
        self.per_conduit.get(&conduit).map_or(0, HashSet::len)
    }

    /// Allocate a fresh, globally-unique `daemon_request_id` for a request
    /// `conduit` is sending under its own `peer_request_id`, and remember
    /// the pair so a later [`Self::map_inbound`] can resolve it. Implicitly
    /// registers `conduit` if it was not already (mirrors
    /// [`Self::register_conduit`]'s idempotence). Fails with [`Exhausted`]
    /// — without allocating an id or touching any state — once `conduit`
    /// already has [`MAX_INFLIGHT_PER_CONDUIT`] requests outstanding;
    /// every other conduit's cap and the global id counter are unaffected.
    pub fn map_outbound(
        &mut self,
        conduit: ConduitId,
        peer_request_id: u64,
    ) -> Result<u64, Exhausted> {
        let owned = self.per_conduit.entry(conduit).or_default();
        if owned.len() >= MAX_INFLIGHT_PER_CONDUIT {
            return Err(Exhausted);
        }
        let daemon_request_id = self.next_daemon_request_id;
        self.next_daemon_request_id += 1;
        owned.insert(daemon_request_id);
        self.inflight
            .insert(daemon_request_id, (conduit, peer_request_id));
        Ok(daemon_request_id)
    }

    /// Resolve a `Response`'s `daemon_request_id` back to the
    /// `(conduit, peer_request_id)` that minted it, removing the entry —
    /// the daemon restores `peer_request_id` onto the `Response` and
    /// delivers it to `conduit`, and no other conduit ever sees it.
    /// Returns `None` for an unknown id (already answered, or the owning
    /// conduit already died and had its entries cleared by
    /// [`Self::unregister_conduit`]) — the daemon drops such a late
    /// `Response` rather than routing it anywhere.
    pub fn map_inbound(&mut self, daemon_request_id: u64) -> Option<(ConduitId, u64)> {
        let (conduit, peer_request_id) = self.inflight.remove(&daemon_request_id)?;
        if let Some(owned) = self.per_conduit.get_mut(&conduit) {
            owned.remove(&daemon_request_id);
        }
        Some((conduit, peer_request_id))
    }

    /// Subscribe `conduit` to asynchronous `SessionEvent`s for
    /// `session_id` (`request_id = 0`, `docs/design/protocol.md` §11-3).
    /// A conduit typically subscribes to a session the moment its
    /// `session_open`/`session_attach` response comes back. Subscribing
    /// twice to the same session is a no-op.
    pub fn subscribe(&mut self, conduit: ConduitId, session_id: SessionId) {
        self.subscriptions
            .entry(session_id.clone())
            .or_default()
            .insert(conduit);
        self.conduit_subscriptions
            .entry(conduit)
            .or_default()
            .insert(session_id);
    }

    /// Which conduits `event` must be delivered to, sorted. `WriterChanged`
    /// is broadcast to *every* registered conduit of this host regardless
    /// of subscription — `docs/CLI.md` §6.4's "모든 read 소비자에게
    /// broadcast" contract, mirrored here at the conduit granularity
    /// (`PLAN.md` M3 Step 6 (a)). Every other event kind (and any event
    /// for a `session_id` nobody subscribed to — including one no conduit
    /// on this host has ever heard of) goes only to that session's
    /// subscribers, which is an empty vec when there are none.
    pub fn route_event(&self, event: &wire::SessionEvent) -> Vec<ConduitId> {
        let is_writer_changed = matches!(
            event.body,
            Some(wire::session_event::Body::WriterChanged(_))
        );
        if is_writer_changed {
            return self.conduit_ids();
        }
        let session_id = SessionId(event.session_id.clone());
        let mut targets: Vec<ConduitId> = self
            .subscriptions
            .get(&session_id)
            .map(|subscribers| subscribers.iter().copied().collect())
            .unwrap_or_default();
        targets.sort_unstable();
        targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cid(n: u64) -> ConduitId {
        ConduitId(n)
    }

    #[test]
    fn daemon_request_id_never_hands_out_the_reserved_zero() {
        // `request_id = 0` is reserved on the wire for asynchronous events
        // (`qsh/wire/v1.proto`) and, separately, as `authorize_stream`'s
        // "connection-level decision, not a reply" sentinel
        // (`crate::server`). A fresh `ControlMux`'s very first allocation
        // must not collide with either (adversarial review finding).
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        let first = mux.map_outbound(cid(1), 0).unwrap();
        assert_ne!(first, 0, "the first daemon_request_id must never be 0");
        let second = mux.map_outbound(cid(1), 1).unwrap();
        assert_ne!(second, 0);
    }

    #[test]
    fn map_inbound_resolves_and_removes() {
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        let daemon_id = mux.map_outbound(cid(1), 7).unwrap();
        assert_eq!(mux.in_flight_count(cid(1)), 1);
        assert_eq!(mux.map_inbound(daemon_id), Some((cid(1), 7)));
        // Removed: a second resolution of the same id sees nothing.
        assert_eq!(mux.map_inbound(daemon_id), None);
        assert_eq!(mux.in_flight_count(cid(1)), 0);
    }

    #[test]
    fn same_peer_request_id_on_two_conduits_never_crosses() {
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        mux.register_conduit(cid(2));
        let a = mux.map_outbound(cid(1), 0).unwrap();
        let b = mux.map_outbound(cid(2), 0).unwrap();
        assert_ne!(
            a, b,
            "daemon ids must be globally unique even for the same peer_request_id"
        );
        // Resolve out of send order — still routes correctly.
        assert_eq!(mux.map_inbound(b), Some((cid(2), 0)));
        assert_eq!(mux.map_inbound(a), Some((cid(1), 0)));
    }

    #[test]
    fn cap_exhausted_on_one_conduit_does_not_affect_another() {
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        mux.register_conduit(cid(2));
        for i in 0..MAX_INFLIGHT_PER_CONDUIT as u64 {
            mux.map_outbound(cid(1), i).unwrap();
        }
        assert_eq!(mux.in_flight_count(cid(1)), MAX_INFLIGHT_PER_CONDUIT);
        assert_eq!(mux.map_outbound(cid(1), 9999), Err(Exhausted));
        // Table state is unchanged by the failed attempt.
        assert_eq!(mux.in_flight_count(cid(1)), MAX_INFLIGHT_PER_CONDUIT);
        // A different conduit is entirely unaffected.
        assert!(mux.map_outbound(cid(2), 0).is_ok());
    }

    #[test]
    fn unregister_returns_exactly_the_in_flight_set_and_leaves_nothing() {
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        mux.register_conduit(cid(2));
        let a = mux.map_outbound(cid(1), 10).unwrap();
        let b = mux.map_outbound(cid(1), 11).unwrap();
        let _other = mux.map_outbound(cid(2), 10).unwrap();

        let mut returned = mux.unregister_conduit(cid(1));
        returned.sort_unstable();
        let mut expected = [a, b];
        expected.sort_unstable();
        assert_eq!(returned, expected);

        assert_eq!(mux.in_flight_count(cid(1)), 0);
        assert!(!mux.conduit_ids().contains(&cid(1)));
        // Unregistered conduit's ids are gone from the table entirely.
        assert_eq!(mux.map_inbound(a), None);
        assert_eq!(mux.map_inbound(b), None);
        // The other conduit is untouched.
        assert_eq!(mux.in_flight_count(cid(2)), 1);

        // Unregistering again is a safe no-op.
        assert_eq!(mux.unregister_conduit(cid(1)), Vec::<u64>::new());
    }

    #[test]
    fn ping_classifies_separately_from_every_request_body() {
        assert_eq!(
            classify(&control_message::Body::Ping(wire::Ping {})),
            MessageKind::Ping
        );
        assert_eq!(
            classify(&control_message::Body::SessionList(wire::SessionList {})),
            MessageKind::Request
        );
    }

    #[test]
    fn writer_changed_broadcasts_to_every_registered_conduit_including_non_subscribers() {
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        mux.register_conduit(cid(2));
        mux.register_conduit(cid(3));
        // Only conduit 1 ever subscribed to this session; the others are
        // registered but have no subscription at all.
        mux.subscribe(cid(1), SessionId("s1".into()));

        let event = wire::SessionEvent::writer_changed("s1", Some("controller-cli".into()), 42);
        assert_eq!(mux.route_event(&event), vec![cid(1), cid(2), cid(3)]);
    }

    #[test]
    fn non_writer_changed_events_reach_only_subscribers() {
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        mux.register_conduit(cid(2));
        mux.subscribe(cid(1), SessionId("s1".into()));

        let event = wire::SessionEvent::closed("s1", "closed", 10);
        assert_eq!(mux.route_event(&event), vec![cid(1)]);
    }

    #[test]
    fn event_for_unknown_session_routes_nowhere() {
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        mux.subscribe(cid(1), SessionId("s1".into()));

        let event = wire::SessionEvent::closed("no-such-session", "closed", 0);
        assert_eq!(mux.route_event(&event), Vec::<ConduitId>::new());
    }

    #[test]
    fn unregistering_a_subscriber_stops_future_delivery() {
        let mut mux = ControlMux::new();
        mux.register_conduit(cid(1));
        mux.register_conduit(cid(2));
        mux.subscribe(cid(1), SessionId("s1".into()));
        mux.subscribe(cid(2), SessionId("s1".into()));

        mux.unregister_conduit(cid(1));

        let event = wire::SessionEvent::closed("s1", "closed", 0);
        assert_eq!(mux.route_event(&event), vec![cid(2)]);
    }

    // -- Adversarial property test (`docs/design/testing.md` L3): seeded
    // interleavings of N requests across M conduits that reuse the same
    // peer_request_ids, asserting zero crossed responses and an empty
    // table once every response has been resolved. --

    #[derive(Debug, Clone)]
    enum Op {
        /// Send a request from `conduit` (index into a fixed small pool)
        /// carrying `peer_request_id` (also drawn from a small, deliberately
        /// colliding range).
        Send { conduit: u64, peer_request_id: u64 },
        /// Resolve the oldest still-unresolved send, by position in the
        /// order sends were issued (index is taken modulo the number of
        /// currently-outstanding sends, so every generated `Resolve` is
        /// always valid to apply).
        Resolve { pick: usize },
        /// A conduit dies mid-flight — the one operation the "every insert
        /// has exactly one removal" invariant most depends on (module
        /// docs), previously exercised only by one hand-written unit test
        /// (adversarial review finding). `map_outbound`'s own "implicitly
        /// registers if not already" contract means a `Send` for this
        /// same `conduit` index right after a `Kill` is still valid — the
        /// oracle needs no special handling for that.
        Kill { conduit: u64 },
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => (0u64..4, 0u64..6)
                .prop_map(|(conduit, peer_request_id)| Op::Send { conduit, peer_request_id }),
            2 => (0usize..64).prop_map(|pick| Op::Resolve { pick }),
            1 => (0u64..4).prop_map(|conduit| Op::Kill { conduit }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn interleaved_reused_peer_ids_never_cross(ops in prop::collection::vec(op_strategy(), 1..200)) {
            let mut mux = ControlMux::new();
            for c in 0..4u64 {
                mux.register_conduit(cid(c));
            }
            // Oracle: outstanding daemon_request_id -> the (conduit,
            // peer_request_id) it was minted for, plus the send order for
            // `Resolve { pick }` to index into.
            let mut oracle: HashMap<u64, (ConduitId, u64)> = HashMap::new();
            let mut outstanding_order: Vec<u64> = Vec::new();

            for op in ops {
                match op {
                    Op::Send { conduit, peer_request_id } => {
                        let c = cid(conduit);
                        match mux.map_outbound(c, peer_request_id) {
                            Ok(daemon_id) => {
                                prop_assert!(oracle.insert(daemon_id, (c, peer_request_id)).is_none(),
                                    "daemon_request_id must never be reused while still outstanding");
                                outstanding_order.push(daemon_id);
                            }
                            Err(Exhausted) => {
                                // Only possible once that conduit is at cap.
                                prop_assert_eq!(mux.in_flight_count(c), MAX_INFLIGHT_PER_CONDUIT);
                            }
                        }
                    }
                    Op::Resolve { pick } => {
                        if outstanding_order.is_empty() {
                            continue;
                        }
                        let idx = pick % outstanding_order.len();
                        let daemon_id = outstanding_order.remove(idx);
                        let expected = oracle.remove(&daemon_id).unwrap();
                        prop_assert_eq!(mux.map_inbound(daemon_id), Some(expected));
                        // Already-removed: resolving again yields nothing.
                        prop_assert_eq!(mux.map_inbound(daemon_id), None);
                    }
                    Op::Kill { conduit } => {
                        let c = cid(conduit);
                        let mut dropped = mux.unregister_conduit(c);
                        dropped.sort_unstable();
                        let mut expected: Vec<u64> = oracle
                            .iter()
                            .filter(|(_, (owner, _))| *owner == c)
                            .map(|(id, _)| *id)
                            .collect();
                        expected.sort_unstable();
                        prop_assert_eq!(
                            &dropped, &expected,
                            "unregister_conduit must return exactly this conduit's \
                             outstanding daemon_request_ids, no more and no fewer"
                        );
                        for id in &dropped {
                            oracle.remove(id);
                        }
                        outstanding_order.retain(|id| !dropped.contains(id));
                    }
                }
            }

            // Drain everything still outstanding and check every single one
            // resolves to exactly its originator — the core "zero crossed
            // responses" property.
            for daemon_id in outstanding_order {
                let expected = oracle.remove(&daemon_id).unwrap();
                prop_assert_eq!(mux.map_inbound(daemon_id), Some(expected));
            }
            prop_assert!(oracle.is_empty());

            // Table is empty after every response has been resolved.
            for c in 0..4u64 {
                prop_assert_eq!(mux.in_flight_count(cid(c)), 0);
            }
        }
    }
}
