//! Resource quotas (`PLAN.md` M8 Step 3, `docs/adr/0010-resource-quotas.md`).
//!
//! Everything here enforces a *post-authorization* limit — the ACL choke
//! point has already run by the time any caller reaches this module
//! (`CLAUDE.md` security defaults: never create a resource before
//! authorization succeeds). An unauthorized principal must always see
//! `PERMISSION_DENIED`, never a quota rejection — that would be an oracle
//! on how saturated the host currently is. Quota rejections are
//! `RESOURCE_EXHAUSTED`, always `retryable: true` (the defining property of
//! a quota, as opposed to a policy denial: the resource comes back).
//!
//! **Lock discipline (verdict arbitration item 8, mirroring `crate::
//! admission::Gate`'s `WindowState`).** [`Quotas`]'s mutex (and each
//! `crate::admission::AuditWindow`'s) is always the **leaf-most** lock
//! taken: nothing else is ever locked while it is held, it is never held
//! across an `.await`, and it is never held while a session or child
//! handle is dropped (a `Drop` impl that runs arbitrary destructor code
//! under this lock is exactly the shape that turns a lock-order mistake
//! elsewhere into a deadlock nobody can see in a diff). A caller that must
//! drop a collection of entries after releasing a quota permit collects
//! them into a `Vec` first and drops that outside any guard.
//!
//! Session counting is deliberately **not** done here — `crate::broker::
//! Broker` derives its live-session count from its own registry (no
//! separate counter — see that module's doc), so a session slot can never
//! leak the way a hand-maintained counter's decrement-site sprawl invites.
//! This module owns the audit aggregation windows for *every*
//! [`QuotaKind`], including the broker-enforced ones, so a rejection's
//! audit trail is centralized in one place regardless of which module
//! holds the counter that produced it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use crate::admission::{AUDIT_AGGREGATION_WINDOW, WindowState};
use crate::audit::AuditRecord;
use crate::broker::Clock;
use crate::config::ServeConfig;

/// Which resource axis a quota rejection came from. Also the vocabulary
/// [`QuotaKind::category`] hands to [`AuditRecord::quota_rejected`]/
/// [`AuditRecord::quota_rejected_summary`] (`docs/CLI.md` audit section,
/// mirroring `crate::admission::RejectReason::category`).
///
/// Declaration order matches [`Quotas`]'s internal `windows` array — each
/// variant's `as usize` is that array's index (same trick `crate::
/// admission::Gate` uses for its two `RejectReason`s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    /// The global live-session cap (`[serve].max_sessions`) —
    /// enforced by `crate::broker::Broker`, not this module.
    Sessions,
    /// The per-principal live-session cap
    /// (`[serve].max_sessions_per_principal`) — enforced by
    /// `crate::broker::Broker`, not this module.
    SessionsPerPrincipal,
    /// The per-principal concurrent-`exec.run` cap
    /// (`[serve].max_exec_per_principal`) — enforced by
    /// [`Quotas::reserve_exec`].
    ExecPerPrincipal,
    /// The host-wide concurrent-`exec.run` cap (`[serve].max_exec`) —
    /// enforced by [`Quotas::reserve_exec`], checked *before* the
    /// per-principal axis (host → principal, matching `reserve_exec`'s own
    /// order and the broker's global-then-per-principal order). Derived as
    /// `Σ exec_in_use` — no separate counter (this module's own "no
    /// hand-maintained counter" discipline).
    ExecHost,
    /// The per-principal cap on concurrently open tunnel (`-L`) streams
    /// (`[serve].max_tunnel_streams_per_principal`) — enforced by
    /// [`Quotas::reserve_tunnel_stream`].
    TunnelStreamsPerPrincipal,
    /// The per-`(principal, destination)` cap on concurrently open tunnel
    /// streams (`[serve].max_tunnel_streams_per_forward`) — enforced by
    /// [`Quotas::reserve_tunnel_stream`].
    TunnelStreamsPerForward,
    /// The per-principal cap on concurrently open remote-forward (`-R`)
    /// listeners (`[serve].max_remote_forwards_per_principal`) — enforced
    /// in a later M8 Step 3b stage.
    RemoteForwardsPerPrincipal,
    /// The per-principal cap on concurrently open connections
    /// (`[serve].max_connections_per_principal`) — enforced in a later M8
    /// Step 3b stage.
    ConnectionsPerPrincipal,
    /// The accept-arm-wide cap on concurrently open connections
    /// (`[serve].max_connections`) — enforced in a later M8 Step 3b stage.
    Connections,
    /// The fixed cap on concurrently open pre-identity (pairing) connections
    /// ([`MAX_CONCURRENT_PAIRING_CONNECTIONS`], not configurable) —
    /// enforced in a later M8 Step 3b stage.
    PairingConnections,
}

/// Fixed cap on concurrently open pairing connections (`Principal::
/// Pairing`, pre-identity) — no config key: a pairing connection has no
/// principal to key a per-principal cap by, so this is the only axis for
/// it, and it is deliberately not operator-tunable (M8 Step 3b ruling R2).
pub const MAX_CONCURRENT_PAIRING_CONNECTIONS: usize = 8;

/// Cap on how many distinct principals' audit windows one [`QuotaKind`]
/// category keeps open at once (R2 설계 검토 (a-4)/(a-6)). Below this, a
/// rejection's audit window is keyed on `(category, principal)`, so one
/// principal's flood can never absorb another principal's first rejection
/// into its own summary line. Above it, the offending principal's window
/// lands in that category's single `CategoryWindows::overflow` slot
/// instead of growing the map further — the row-count trade-off this
/// bounds is documented on `CategoryWindows` itself.
///
/// `pub` for the same reason [`crate::admission::AUDIT_AGGREGATION_
/// WINDOW`] is: `docs/CLI.md`/`docs/design/architecture.md`'s doc-drift
/// pin (`crates/qsh-core/tests/quota_docs.rs`'s `cli_md_and_architecture_
/// md_name_the_audit_window_principal_cap_and_row_bound`) reads this
/// constant instead of a hardcoded copy of `64`, not an invitation for
/// another crate to depend on the value.
pub const MAX_AUDIT_WINDOW_PRINCIPALS: usize = 64;

impl QuotaKind {
    /// Every variant, in the same order as [`Quotas`]'s internal window
    /// array — a fixed, non-growing list (Step 2's "a growing structure
    /// is the surface" principle applies here too, `docs/adr/0009-
    /// admission-defenses.md`).
    pub const ALL: &'static [QuotaKind] = &[
        QuotaKind::Sessions,
        QuotaKind::SessionsPerPrincipal,
        QuotaKind::ExecPerPrincipal,
        QuotaKind::ExecHost,
        QuotaKind::TunnelStreamsPerPrincipal,
        QuotaKind::TunnelStreamsPerForward,
        QuotaKind::RemoteForwardsPerPrincipal,
        QuotaKind::ConnectionsPerPrincipal,
        QuotaKind::Connections,
        QuotaKind::PairingConnections,
    ];

    /// The audit/log category word — the exact `quota_*` vocabulary
    /// `docs/adr/0010-resource-quotas.md` §2.4 settles on (M8 Step 3b
    /// ruling R5 for the 7 variants 3b adds).
    pub fn category(self) -> &'static str {
        match self {
            QuotaKind::Sessions => "quota_sessions_host",
            QuotaKind::SessionsPerPrincipal => "quota_sessions_principal",
            QuotaKind::ExecPerPrincipal => "quota_exec_principal",
            QuotaKind::ExecHost => "quota_exec_host",
            QuotaKind::TunnelStreamsPerPrincipal => "quota_tunnels_principal",
            QuotaKind::TunnelStreamsPerForward => "quota_tunnels_forward",
            QuotaKind::RemoteForwardsPerPrincipal => "quota_remote_forwards_principal",
            QuotaKind::ConnectionsPerPrincipal => "quota_connections_principal",
            QuotaKind::Connections => "quota_connections_host",
            QuotaKind::PairingConnections => "quota_connections_pairing",
        }
    }

    /// The ACL action word this kind's rejection is *for* — `docs/CLI.md`'s
    /// audit prose states the `action` field on a quota-reject record is
    /// `"session.open"` (either session axis), `"exec.run"` (either exec
    /// axis), `"forward.local"` (either tunnel-stream axis — the exact word
    /// `Server::authorize_and_dial_tunnel` checks via
    /// `crate::acl::Op::ForwardLocal.action()`, `server/mod.rs:2949`),
    /// `"forward.remote"` (the remote-forward-listener axis, matching
    /// `crate::acl::Action::ForwardRemote::as_str()`), or `"connect"` (any
    /// connection axis — the same word `AuditRecord::handshake_rejected`
    /// already uses for a connection-axis rejection, `audit.rs:224`) —
    /// matching the relevant `crate::acl::Action::as_str()` byte for byte
    /// without pulling an `acl` dependency into this leaf-most module — see
    /// [`crate::audit::AuditRecord::quota_rejected`], which is the sole
    /// caller.
    pub fn action(self) -> &'static str {
        match self {
            QuotaKind::Sessions | QuotaKind::SessionsPerPrincipal => "session.open",
            QuotaKind::ExecPerPrincipal | QuotaKind::ExecHost => "exec.run",
            QuotaKind::TunnelStreamsPerPrincipal | QuotaKind::TunnelStreamsPerForward => {
                "forward.local"
            }
            QuotaKind::RemoteForwardsPerPrincipal => "forward.remote",
            QuotaKind::ConnectionsPerPrincipal
            | QuotaKind::Connections
            | QuotaKind::PairingConnections => "connect",
        }
    }

    /// The wire-facing rejection string `crate::broker::BrokerError::
    /// QuotaExceeded` displays (`docs/CLI.md` §6.12, `docs/adr/
    /// 0010-resource-quotas.md` §5).
    ///
    /// Uniform *per resource type*, not per variant: every axis of one
    /// resource type shares a string, distinct only across resource types.
    /// Which axis actually rejected the request is carried solely by the
    /// audit record's `resource` field ([`QuotaKind::category`]) — a client
    /// parsing this message alone cannot and is not meant to distinguish
    /// host-wide from per-principal within the same resource type.
    /// [`QuotaKind::PairingConnections`] never reaches the wire (a pairing
    /// rejection closes the connection without a frame — M8 Step 3b ruling
    /// R2) but this match is total, so it still returns the connection-axis
    /// string rather than special-casing `"-"`.
    pub fn wire_message(self) -> &'static str {
        match self {
            QuotaKind::Sessions | QuotaKind::SessionsPerPrincipal => "session quota exceeded",
            QuotaKind::ExecPerPrincipal | QuotaKind::ExecHost => "exec quota exceeded",
            QuotaKind::TunnelStreamsPerPrincipal | QuotaKind::TunnelStreamsPerForward => {
                "tunnel quota exceeded"
            }
            QuotaKind::RemoteForwardsPerPrincipal => "remote forward quota exceeded",
            QuotaKind::ConnectionsPerPrincipal
            | QuotaKind::Connections
            | QuotaKind::PairingConnections => "connection quota exceeded",
        }
    }
}

/// Effective, already-defaulted quota values resolved from `[serve]`
/// (mirrors `crate::broker::BrokerConfig::from_serve`'s shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    /// Global cap on live sessions (`[serve].max_sessions`).
    pub max_sessions: usize,
    /// Per-principal cap on live sessions
    /// (`[serve].max_sessions_per_principal`).
    pub max_sessions_per_principal: usize,
    /// Per-principal cap on concurrently running `exec.run` children
    /// (`[serve].max_exec_per_principal`).
    pub max_exec_per_principal: usize,
    /// Host-wide cap on concurrently running `exec.run` children
    /// (`[serve].max_exec`), checked before the per-principal axis
    /// ([`Quotas::reserve_exec`]).
    pub max_exec: usize,
    /// Per-principal cap on concurrently open tunnel (`-L`) streams
    /// (`[serve].max_tunnel_streams_per_principal`).
    pub max_tunnel_streams_per_principal: usize,
    /// Per-`(principal, destination)` cap on concurrently open tunnel
    /// streams (`[serve].max_tunnel_streams_per_forward`).
    pub max_tunnel_streams_per_forward: usize,
    /// Per-principal cap on concurrently open remote-forward (`-R`)
    /// listeners (`[serve].max_remote_forwards_per_principal`).
    pub max_remote_forwards_per_principal: usize,
    /// Per-principal cap on concurrently open connections
    /// (`[serve].max_connections_per_principal`).
    pub max_connections_per_principal: usize,
    /// Accept-arm-wide cap on concurrently open connections
    /// (`[serve].max_connections`).
    pub max_connections: usize,
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            max_sessions: ServeConfig::DEFAULT_MAX_SESSIONS,
            max_sessions_per_principal: ServeConfig::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL,
            max_exec_per_principal: ServeConfig::DEFAULT_MAX_EXEC_PER_PRINCIPAL,
            max_exec: ServeConfig::DEFAULT_MAX_EXEC,
            max_tunnel_streams_per_principal: ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_PRINCIPAL,
            max_tunnel_streams_per_forward: ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_FORWARD,
            max_remote_forwards_per_principal:
                ServeConfig::DEFAULT_MAX_REMOTE_FORWARDS_PER_PRINCIPAL,
            max_connections_per_principal: ServeConfig::DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL,
            max_connections: ServeConfig::DEFAULT_MAX_CONNECTIONS,
        }
    }
}

impl QuotaLimits {
    /// Resolve from a parsed `[serve]` section, applying the documented
    /// defaults (`0`/unset ⇒ default, never "unlimited") for any unset
    /// field.
    pub fn from_serve(serve: &ServeConfig) -> Self {
        Self {
            max_sessions: serve.max_sessions(),
            max_sessions_per_principal: serve.max_sessions_per_principal(),
            max_exec_per_principal: serve.max_exec_per_principal(),
            max_exec: serve.max_exec(),
            max_tunnel_streams_per_principal: serve.max_tunnel_streams_per_principal(),
            max_tunnel_streams_per_forward: serve.max_tunnel_streams_per_forward(),
            max_remote_forwards_per_principal: serve.max_remote_forwards_per_principal(),
            max_connections_per_principal: serve.max_connections_per_principal(),
            max_connections: serve.max_connections(),
        }
    }
}

/// Mutable state behind [`Quotas`]'s single leaf-most lock.
#[derive(Default)]
struct QuotaState {
    /// Live (unreleased) `exec.run` reservations, keyed by the same
    /// `opener_key` string `crate::broker::Broker` keys sessions by. An
    /// entry is removed the instant its count reaches zero — cardinality
    /// is bounded by the number of distinct principals currently holding
    /// at least one reservation, which is itself bounded by `Σ
    /// max_exec_per_principal` (the same "no entry without a live
    /// resource" invariant `docs/adr/0010-resource-quotas.md` §2.1
    /// states for the tunnel/connection maps 3b adds).
    exec_in_use: HashMap<String, usize>,
    /// Live tunnel-stream reservations per principal (M8 Step 3b,
    /// [`Quotas::reserve_tunnel_stream`]) — same "no entry without a live
    /// resource" invariant as `exec_in_use`.
    tunnel_streams_per_principal: HashMap<String, usize>,
    /// Live tunnel-stream reservations per `(principal, destination)`
    /// (M8 Step 3b, [`Quotas::reserve_tunnel_stream`]) — `destination` is
    /// the same canonical `host:port` string
    /// [`crate::server::Server::authorize_and_dial_tunnel`] uses as its
    /// ACL resource. Cardinality is bounded by `Σ
    /// max_tunnel_streams_per_forward` the same way `exec_in_use`'s is.
    tunnel_streams_per_forward: HashMap<(String, String), usize>,
    /// Live remote-forward listener reservations per principal (M8 Step
    /// 3b, [`Quotas::reserve_remote_forward`]) — same "no entry without a
    /// live resource" invariant as `exec_in_use`.
    remote_forwards_per_principal: HashMap<String, usize>,
    /// Live connection reservations per opener key (M8 Step 3b,
    /// [`Quotas::reserve_connection`]) — same "no entry without a live
    /// resource" invariant as `exec_in_use`. The host-wide axis
    /// ([`QuotaKind::Connections`]) is derived as `Σ
    /// connections_per_principal.values()`, no separate counter, same
    /// discipline as `exec_in_use`/[`QuotaKind::ExecHost`].
    connections_per_principal: HashMap<String, usize>,
    /// Live pre-identity (`Principal::Pairing`) connection reservations
    /// (M8 Step 3b ruling R2, [`Quotas::reserve_pairing_connection`]) — a
    /// plain counter, not a map: a pairing connection has no principal to
    /// key by, so there is only ever this one fixed-cap axis.
    pairing_connections_in_use: usize,
}

/// One [`QuotaKind`] category's audit-window bookkeeping (R2 설계 검토
/// (a-1)/(a-5)): a per-principal map plus one fixed overflow slot, rather
/// than a single map keyed by an enum that folds "this principal" and
/// "overflow" into the same variant space.
///
/// Two reasons this is a struct with a dedicated `overflow` field, not
/// `HashMap<WindowKey, WindowState>` with a `WindowKey::Overflow` variant:
///
/// - **Allocation.** `per_principal.get_mut(principal)` looks up by `&str`
///   with no allocation. A `WindowKey::Principal(String)` probe key would
///   need a fresh `String` on every lookup unless `Borrow<str>` were
///   hand-implemented — one heap allocation per rejection, on the exact
///   flood path this module exists to bound. Once a category is at its
///   cap ([`MAX_AUDIT_WINDOW_PRINCIPALS`], the attacker's own steady
///   state), every further rejection from a new principal name is a
///   lookup only — zero allocations.
/// - **Type-level separation.** "overflow is never a principal" is a
///   struct shape, not a string convention a caller could get wrong —
///   `per_principal.len()` is exactly the live principal-window count, so
///   the cap check is a single comparison rather than a scan for a
///   sentinel key.
///
/// **Memory bound.** `per_principal` holds at most
/// [`MAX_AUDIT_WINDOW_PRINCIPALS`] entries per category (a closed window
/// is deleted, not merely reset — see [`Quotas::flush_expired`]), so the
/// whole `Quotas` never holds more than `QuotaKind::ALL.len() ×
/// (MAX_AUDIT_WINDOW_PRINCIPALS + 1)` windows at once — 10 × 65 = 650
/// today. Each entry is a `String` key (principal name, length `L`) plus
/// a small `WindowState`; with hashbrown's ~2× load-factor overhead the
/// skeleton (`L = 0`) is bounded by roughly `2 × 650 × 64` bytes ≈ 83
/// KiB, plus `2 × 650 × L` for the strings themselves. **`L` is not
/// bounded by this module** (R2 review A/B, F4/B6) — on the CA path
/// `qsh_transport::identity::valid_segment` accepts any non-empty SAN
/// segment containing no `/`, so `L` is bounded only by the peer
/// certificate the attacker presents, not by anything this module
/// controls: a realistic `L ≤ 1 KiB` gives ~1.4 MB total, a pathological
/// 64 KiB SAN gives ~83 MB. Bounding principal-name length itself is a
/// separate question, out of scope here. This is not a *new* attack
/// surface of that shape, though — the same principal string already
/// lives in at least one longer-lived structure (a live connection's own
/// `connections_per_principal` entry) for as long as the connection it
/// names is open, and this module's own [`QuotaLimits::
/// max_connections_per_principal`] and [`QuotaLimits::max_connections`]
/// already bound how many such live entries exist at once — an audit
/// window can, however, outlive the connection it was opened for by up
/// to one housekeeping tick ([`Quotas::flush_expired`]'s own sweep
/// cadence), so this map's cardinality is not strictly a subset of that
/// one's at every instant.
#[derive(Default)]
struct CategoryWindows {
    /// One audit window per principal that has been rejected in this
    /// category and is still within [`AUDIT_AGGREGATION_WINDOW`] of its
    /// first rejection. Capped at [`MAX_AUDIT_WINDOW_PRINCIPALS`] entries;
    /// a closed window's entry is deleted outright, not reset in place
    /// (see [`Quotas::flush_expired`]).
    per_principal: HashMap<String, WindowState>,
    /// The single shared window for every principal that arrives after
    /// `per_principal` is already at [`MAX_AUDIT_WINDOW_PRINCIPALS`] —
    /// its *summary* line is audited under the sentinel principal `"-"`
    /// rather than under whichever principal happened to fill it, since
    /// more than one principal can share it over its lifetime (its own
    /// *first* line, one per rejection until the window itself goes
    /// stale, still carries the real name — only the summary spans
    /// principals). The bare string `"-"` is also routed here directly by
    /// [`Quotas::record_rejection`] regardless of map size (R2 review B,
    /// B1) — it is a reserved sentinel, never a legitimate `per_principal`
    /// key, so a pre-identity axis auditing under it (matching
    /// `docs/CLI.md` §6.12's admission convention) cannot open a window
    /// indistinguishable from an actual overflow summary.
    overflow: WindowState,
}

/// The quota decision-maker for the resource axes this module directly
/// enforces (today: `exec.run` concurrency), plus the shared audit
/// aggregation windows for every [`QuotaKind`] regardless of which module
/// enforces it. Constructed as an `Arc` so [`Quotas::reserve_exec`]'s
/// returned [`ExecPermit`] can release its reservation from an arbitrary
/// `'static` task without borrowing back into whatever owns the `Quotas`
/// itself (a [`Weak`] back-reference, upgraded on `Drop` — if the whole
/// `Quotas` has already been torn down, there is nothing left to
/// decrement into, so the permit's `Drop` is simply a no-op rather than a
/// panic).
pub struct Quotas {
    limits: QuotaLimits,
    clock: Arc<dyn Clock>,
    self_weak: Weak<Quotas>,
    state: Mutex<QuotaState>,
    windows: [Mutex<CategoryWindows>; QuotaKind::ALL.len()],
    /// Soak observability (M8 Step 5a) — see [`ConnectionCounters`].
    connection_counters: ConnectionCounters,
    /// Per-[`QuotaKind`] rejection tally, incremented on every call to [`Quotas::
    /// record_rejection`], regardless of whether that call's own audit
    /// line was window-suppressed — suppression is an audit-*emission*
    /// concern (`AUDIT_AGGREGATION_WINDOW`'s first-then-summary shape),
    /// never a counting one. This is what closes the gap the accept-loop
    /// heartbeat's old `quota_refused` field had: that field only ever
    /// summed the two `reserve_connection`/`reserve_pairing_connection`
    /// counters (renamed [`ConnectionCounters::connection_refused`]/
    /// `pairing_refused`, now surfaced as `connection_quota_refused`), so
    /// a 100-session soak binding on `max_sessions` or
    /// `max_exec_per_principal` logged zero quota pressure the whole run.
    rejections: [AtomicU64; QuotaKind::ALL.len()],
}

/// Lock-free tally of every [`Quotas::reserve_connection`]/
/// [`Quotas::reserve_pairing_connection`] outcome since construction — the
/// same soak-observability role as `crate::admission::DecisionCounters`,
/// not an enforcement mechanism. Individual reservation decisions are
/// `tracing::trace!`-only (target `qsh_core::quota`); this snapshot is
/// what an accept-loop heartbeat or a soak harness reads instead.
#[derive(Debug, Default)]
struct ConnectionCounters {
    connection_reserved: AtomicU64,
    connection_refused: AtomicU64,
    pairing_reserved: AtomicU64,
    pairing_refused: AtomicU64,
}

/// A point-in-time snapshot of `ConnectionCounters` plus every
/// [`QuotaKind`]'s rejection tally — what [`Quotas::counters`] returns.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QuotaCounters {
    pub connection_reserved: u64,
    pub connection_refused: u64,
    pub pairing_reserved: u64,
    pub pairing_refused: u64,
    /// One slot per [`QuotaKind`] (index = `kind as
    /// usize`), each counting every [`Quotas::record_rejection`] call
    /// against that axis — every quota a soak can bind on, not just the
    /// two connection-reservation counters above.
    pub rejections_by_kind: [u64; QuotaKind::ALL.len()],
}

impl QuotaCounters {
    /// Sum of [`Self::rejections_by_kind`] across every axis — the
    /// accept-loop heartbeat's `quota_rejections` field.
    pub fn rejections_total(&self) -> u64 {
        self.rejections_by_kind.iter().sum()
    }
}

impl std::fmt::Debug for Quotas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Quotas")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Quotas {
    /// Build a quota tracker with the given limits, driven by an injected
    /// [`Clock`] so every invariant here is testable without real
    /// wall-clock time (same discipline as `crate::admission::Gate::new`).
    pub fn new(limits: QuotaLimits, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            limits,
            clock,
            self_weak: weak.clone(),
            state: Mutex::new(QuotaState::default()),
            windows: Default::default(),
            connection_counters: ConnectionCounters::default(),
            rejections: Default::default(),
        })
    }

    /// Snapshot the running tally of every [`Quotas::reserve_connection`]/
    /// [`Quotas::reserve_pairing_connection`] outcome since construction
    /// (M8 Step 5a) — for the accept-loop heartbeat and soak harnesses,
    /// not for enforcement decisions.
    pub fn counters(&self) -> QuotaCounters {
        QuotaCounters {
            connection_reserved: self
                .connection_counters
                .connection_reserved
                .load(Ordering::Relaxed),
            connection_refused: self
                .connection_counters
                .connection_refused
                .load(Ordering::Relaxed),
            pairing_reserved: self
                .connection_counters
                .pairing_reserved
                .load(Ordering::Relaxed),
            pairing_refused: self
                .connection_counters
                .pairing_refused
                .load(Ordering::Relaxed),
            rejections_by_kind: std::array::from_fn(|i| self.rejections[i].load(Ordering::Relaxed)),
        }
    }

    /// The quotas' own clock, for a caller that needs `now` to pass to
    /// [`Quotas::record_rejection`]/[`Quotas::flush_expired`] without
    /// duplicating which clock that is (mirrors `crate::admission::
    /// Gate::now`).
    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QuotaState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserve one `exec.run` slot for `principal_key`, or refuse with
    /// [`QuotaKind::ExecPerPrincipal`] if that principal is already at
    /// [`QuotaLimits::max_exec_per_principal`]. The counter tracks *live*
    /// (unredeemed-ticket) children only — a released [`ExecPermit`]
    /// (child reaped) frees the slot immediately, so a principal that
    /// keeps redeeming and reaping tickets never accumulates an unbounded
    /// backlog the way `crate::server`'s pending-ticket budget alone
    /// would allow (verdict arbitration item 5). An expired, never-
    /// redeemed ticket is not this immediate — its `ExecPermit` is
    /// released only by the next sweep of `crate::server`'s ticket map
    /// (any ticket-issuing request, a connection purge, or
    /// `Server::quota_housekeeping`'s periodic tick), not the instant it
    /// expires.
    pub fn reserve_exec(&self, principal_key: &str) -> Result<ExecPermit, QuotaKind> {
        let mut state = self.lock();
        // Read-only checks first (F9 of the M8 Step 3a conformance sweep):
        // `entry(..).or_insert(0)` ahead of either cap test would plant a
        // zero-valued map entry for a *refused* principal too, breaking
        // this module's own "no entry without a live resource" invariant
        // (this struct's doc comment) the moment a cap is `0` —
        // unreachable from parsed config (`0` degrades to the default
        // there) but reachable from any hand-built `QuotaLimits`, which is
        // exactly how tests (and 3b) construct one.
        //
        // Host axis first, then per-principal (M8 Step 3b, `QuotaLimits::
        // max_exec`): the host-wide count is derived as `Σ
        // exec_in_use.values()` — no separate counter, so it can never
        // drift from the per-principal counts that back it (this module's
        // own no-hand-maintained-counter discipline, restated for this
        // axis).
        let host_in_use: usize = state.exec_in_use.values().sum();
        if host_in_use >= self.limits.max_exec {
            return Err(QuotaKind::ExecHost);
        }
        let current = state.exec_in_use.get(principal_key).copied().unwrap_or(0);
        if current >= self.limits.max_exec_per_principal {
            return Err(QuotaKind::ExecPerPrincipal);
        }
        *state
            .exec_in_use
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        drop(state);
        Ok(ExecPermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
        })
    }

    /// Current live `exec.run` reservation count for `principal_key` —
    /// test/diagnostic use only.
    pub fn exec_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .exec_in_use
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Number of distinct principals with a map entry in `exec_in_use` —
    /// test-only, distinct from [`Quotas::exec_in_use`] itself: that
    /// method's `unwrap_or(0)` cannot tell "no entry" apart from "entry
    /// present holding `0`", which is exactly the distinction the F9
    /// no-entry-without-a-live-resource invariant (this struct's own
    /// doc comment) needs a test to pin.
    #[cfg(test)]
    fn exec_in_use_principal_count(&self) -> usize {
        self.lock().exec_in_use.len()
    }

    /// Reserve one tunnel (`-L`) stream slot for `principal_key` dialing
    /// `resource` (`host:port`, [`qsh_proto::wire::format_host_port`]'s
    /// canonical form — the same string
    /// `crate::server::Server::authorize_and_dial_tunnel` uses as its ACL
    /// resource), or refuse with [`QuotaKind::TunnelStreamsPerPrincipal`]
    /// / [`QuotaKind::TunnelStreamsPerForward`] if either axis is already
    /// at its cap.
    ///
    /// Principal axis checked first, forward axis second — broader before
    /// narrower, same direction as [`Quotas::reserve_exec`]'s
    /// host-before-principal order: every forward-axis count is a subset
    /// of its principal's total, so a caller already at the broader cap
    /// learns *that* reason rather than the narrower one. Read-only
    /// checks first, same F9 discipline as `reserve_exec` (a `0` cap must
    /// never plant a zero-valued entry for a refused principal).
    pub fn reserve_tunnel_stream(
        &self,
        principal_key: &str,
        resource: &str,
    ) -> Result<TunnelStreamPermit, QuotaKind> {
        let mut state = self.lock();
        let principal_count = state
            .tunnel_streams_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0);
        if principal_count >= self.limits.max_tunnel_streams_per_principal {
            return Err(QuotaKind::TunnelStreamsPerPrincipal);
        }
        let forward_key = (principal_key.to_string(), resource.to_string());
        let forward_count = state
            .tunnel_streams_per_forward
            .get(&forward_key)
            .copied()
            .unwrap_or(0);
        if forward_count >= self.limits.max_tunnel_streams_per_forward {
            return Err(QuotaKind::TunnelStreamsPerForward);
        }
        *state
            .tunnel_streams_per_principal
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        *state
            .tunnel_streams_per_forward
            .entry(forward_key)
            .or_insert(0) += 1;
        drop(state);
        Ok(TunnelStreamPermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
            resource: resource.to_string(),
        })
    }

    /// Current live tunnel-stream reservation count for `principal_key`
    /// across every destination — test/diagnostic use only.
    ///
    /// `pub(crate)`, not module-private: `tunnel::remote`'s own
    /// principal-axis test observes this axis the same way the
    /// forward-axis tests observe theirs.
    #[cfg(test)]
    pub(crate) fn tunnel_streams_per_principal_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .tunnel_streams_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Current live tunnel-stream reservation count for
    /// `(principal_key, resource)` — test-only observation, the forward-axis
    /// twin of [`Quotas::tunnel_streams_per_principal_in_use`].
    ///
    /// `#[cfg(test)]` rather than `pub` (M8 Step 4b): the `-R` accept-permit
    /// e2e in `qsh-testkit` observes the permit through the refused TCP
    /// accept and the audit row, so no caller outside this crate exists.
    /// Widen to `pub` (as [`Quotas::pairing_connections_in_use`] is) only
    /// when one appears. No logic beyond the lookup; not part of the permit
    /// decision itself.
    #[cfg(test)]
    pub(crate) fn tunnel_streams_per_forward_in_use(
        &self,
        principal_key: &str,
        resource: &str,
    ) -> usize {
        self.lock()
            .tunnel_streams_per_forward
            .get(&(principal_key.to_string(), resource.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Number of distinct principals with a map entry in
    /// `tunnel_streams_per_principal` — test-only, same "entry present
    /// holding `0`" distinction `exec_in_use_principal_count` exists for.
    #[cfg(test)]
    fn tunnel_streams_per_principal_entry_count(&self) -> usize {
        self.lock().tunnel_streams_per_principal.len()
    }

    /// Number of distinct `(principal, destination)` pairs with a map
    /// entry in `tunnel_streams_per_forward` — test-only, same purpose as
    /// [`Quotas::tunnel_streams_per_principal_entry_count`] for the
    /// narrower axis.
    #[cfg(test)]
    fn tunnel_streams_per_forward_entry_count(&self) -> usize {
        self.lock().tunnel_streams_per_forward.len()
    }

    /// Reserve one live remote-forward listener for `principal_key`
    /// (`[serve].max_remote_forwards_per_principal`, M8 Step 3b). `Err(
    /// QuotaKind::RemoteForwardsPerPrincipal)` if the principal is already
    /// at its cap — read-only check first, same F9 discipline as
    /// [`Quotas::reserve_exec`]/[`Quotas::reserve_tunnel_stream`] (a `0`
    /// cap must never plant a zero-valued entry for a refused principal).
    pub fn reserve_remote_forward(
        &self,
        principal_key: &str,
    ) -> Result<RemoteForwardPermit, QuotaKind> {
        let mut state = self.lock();
        let count = state
            .remote_forwards_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0);
        if count >= self.limits.max_remote_forwards_per_principal {
            return Err(QuotaKind::RemoteForwardsPerPrincipal);
        }
        *state
            .remote_forwards_per_principal
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        drop(state);
        Ok(RemoteForwardPermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
        })
    }

    /// Current live remote-forward reservation count for `principal_key`
    /// — test/diagnostic use only. `pub`, not `#[cfg(test)]`, matching
    /// [`Quotas::exec_in_use`]'s own visibility, since `crate::server`'s
    /// own test module (a different module in the same crate) needs it
    /// too.
    pub fn remote_forwards_per_principal_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .remote_forwards_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Number of distinct principals with a map entry in
    /// `remote_forwards_per_principal` — test-only, same "entry present
    /// holding `0`" distinction `exec_in_use_principal_count` exists for.
    #[cfg(test)]
    fn remote_forwards_per_principal_entry_count(&self) -> usize {
        self.lock().remote_forwards_per_principal.len()
    }

    /// Reserve one live connection slot for `principal_key` (an
    /// [`crate::acl::opener_key`] string, same as every other per-
    /// principal axis in this module), or refuse with
    /// [`QuotaKind::Connections`] (host/accept-arm-wide,
    /// `[serve].max_connections`) or [`QuotaKind::ConnectionsPerPrincipal`]
    /// (`[serve].max_connections_per_principal`) if either axis is already
    /// at its cap.
    ///
    /// Host axis first, then per-principal — same order as
    /// [`Quotas::reserve_exec`] (host → principal, M8 Step 3b ruling R3),
    /// derived as `Σ connections_per_principal.values()` rather than a
    /// separate counter, same discipline as `reserve_exec`'s
    /// `ExecHost`. Read-only checks first, same F9 discipline as every
    /// other `reserve_*` here (a `0` cap must never plant a zero-valued
    /// entry for a refused principal).
    ///
    /// Called from the *outer* frame of a connection's accept path
    /// (`crate::server::Server::serve_connection`,
    /// `crate::reverse::listen::Listen::accept_and_register_permitted`) —
    /// before the inner `Hello` exchange even runs, so a peer that never
    /// sends `Hello` at all is still counted (ruling R3).
    pub fn reserve_connection(&self, principal_key: &str) -> Result<ConnectionPermit, QuotaKind> {
        let mut state = self.lock();
        let host_in_use: usize = state.connections_per_principal.values().sum();
        if host_in_use >= self.limits.max_connections {
            self.connection_counters
                .connection_refused
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(
                target: "qsh_core::quota",
                kind = ?QuotaKind::Connections,
                "quota decision: refuse"
            );
            return Err(QuotaKind::Connections);
        }
        let current = state
            .connections_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0);
        if current >= self.limits.max_connections_per_principal {
            self.connection_counters
                .connection_refused
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(
                target: "qsh_core::quota",
                kind = ?QuotaKind::ConnectionsPerPrincipal,
                "quota decision: refuse"
            );
            return Err(QuotaKind::ConnectionsPerPrincipal);
        }
        *state
            .connections_per_principal
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        drop(state);
        self.connection_counters
            .connection_reserved
            .fetch_add(1, Ordering::Relaxed);
        tracing::trace!(target: "qsh_core::quota", "quota decision: reserve connection");
        Ok(ConnectionPermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
        })
    }

    /// Current live connection reservation count for `principal_key` —
    /// `pub`, not `#[cfg(test)]`, matching [`Quotas::
    /// remote_forwards_per_principal_in_use`]'s own visibility: both
    /// `crate::server` and `crate::reverse::listen`'s test modules need
    /// it.
    pub fn connections_per_principal_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .connections_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Total live connection reservations across every principal — the
    /// same `Σ connections_per_principal.values()` [`Quotas::
    /// reserve_connection`]'s own host-axis check already computes
    /// (M8 Step 5a: the accept-loop heartbeat's `live_conns` field).
    pub fn total_connections_in_use(&self) -> usize {
        self.lock().connections_per_principal.values().sum()
    }

    /// Number of distinct principals with a map entry in
    /// `connections_per_principal` — test-only, same "entry present
    /// holding `0`" distinction `exec_in_use_principal_count` exists for.
    #[cfg(test)]
    fn connections_per_principal_entry_count(&self) -> usize {
        self.lock().connections_per_principal.len()
    }

    /// Reserve one of the fixed [`MAX_CONCURRENT_PAIRING_CONNECTIONS`]
    /// slots for a pre-identity (`Principal::Pairing`) connection, or
    /// refuse with [`QuotaKind::PairingConnections`]. Not configurable
    /// (M8 Step 3b ruling R2) and not keyed by principal — a pairing
    /// connection has none yet.
    pub fn reserve_pairing_connection(&self) -> Result<PairingConnectionPermit, QuotaKind> {
        let mut state = self.lock();
        if state.pairing_connections_in_use >= MAX_CONCURRENT_PAIRING_CONNECTIONS {
            self.connection_counters
                .pairing_refused
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(
                target: "qsh_core::quota",
                kind = ?QuotaKind::PairingConnections,
                "quota decision: refuse"
            );
            return Err(QuotaKind::PairingConnections);
        }
        state.pairing_connections_in_use += 1;
        drop(state);
        self.connection_counters
            .pairing_reserved
            .fetch_add(1, Ordering::Relaxed);
        tracing::trace!(target: "qsh_core::quota", "quota decision: reserve pairing connection");
        Ok(PairingConnectionPermit {
            quotas: self.self_weak.clone(),
        })
    }

    /// Current live pairing-connection reservation count — test/
    /// diagnostic use only.
    pub fn pairing_connections_in_use(&self) -> usize {
        self.lock().pairing_connections_in_use
    }

    /// Record one rejection of `kind` against `principal`, returning the
    /// [`AuditRecord`]s the caller should hand to its
    /// [`crate::audit::AuditSink`] — first-occurrence-then-summary
    /// aggregation, same [`AUDIT_AGGREGATION_WINDOW`] (10 s), same
    /// single-lock-per-window shape, and now (main-session arbitration
    /// round, S1 deviation 2 overturned) the exact same up-to-two-record
    /// return shape as `crate::admission::Gate::record_rejection`: a
    /// *stale* window (one that ran past the aggregation bound with
    /// nothing to close it) closes with its own summary record *and* the
    /// triggering rejection still gets its own fresh first-line record —
    /// never one at the other's expense. The single-`Option` version this
    /// replaced could lose an isolated rejection's own line entirely when
    /// it happened to be the one that reopened a stale window (that
    /// version's own doc comment named the trade); a single unattributed
    /// probe against an otherwise-idle category is exactly the audit line
    /// an investigation most needs, so this module now costs the same one
    /// extra `Vec` slot `Gate::record_rejection` already pays for the same
    /// guarantee.
    ///
    /// `request_id`/`auth_path` are the calling request's own — passed
    /// through untouched to the immediate (non-summary) record so the ACL
    /// `allow` line and this `deny` line for the *same* request share a
    /// `request_id` and can be correlated (verdict ruling 11①). A summary
    /// record spans many requests, so it keeps the pre-existing `"-"`
    /// convention regardless of what is passed here. `request_id` is
    /// `Option<u64>` (M8 Step 3b ruling R9): a control request (session,
    /// exec, `RemoteForwardOpen`) has a real one to pass as `Some`; a data
    /// stream (tunnel dial) or a connection-axis rejection (S4) has none,
    /// and passes `None` rather than the ambiguous sentinel `0` — the same
    /// "no id" shape `authorize_stream`'s connection-level callers already
    /// use. [`AuditRecord::quota_rejected`] writes `None` as the audit
    /// string `"-"`.
    ///
    /// `peer_addr` (M8 Step 3b ruling R4, reversing the 3a "this module has
    /// no address to hand" note) is likewise the caller's own live value —
    /// this module stays connection-agnostic (`architecture.md` §1): it
    /// only carries the address through to [`AuditRecord::quota_rejected`]
    /// as an opaque value, never inspects or validates it. Every caller
    /// today (session/exec axes) passes its `ConnCtx::peer_addr`; the
    /// summary record still hardcodes `"-"` — one aggregation window can
    /// span many peers.
    ///
    /// **Window key (R2 설계 검토 (a-2)/(a-3)):** the window this call
    /// opens or bumps is keyed on `(kind, principal)`, not `kind` alone —
    /// `CategoryWindows::per_principal` holds one `WindowState` per
    /// principal currently within its own aggregation window, so one
    /// principal's flood can never suppress a *different* principal's
    /// first rejection into a summary line. Once a category already has
    /// [`MAX_AUDIT_WINDOW_PRINCIPALS`] live principal windows, a rejection
    /// from any further new principal falls into that category's single
    /// `overflow` window instead of growing the map — its own first line
    /// still carries the rejected principal's real name (only the later
    /// *summary* line for that shared window is audited under `"-"`, see
    /// [`Quotas::flush_expired`]). `"-"` is itself a reserved sentinel
    /// (R2 review B, B1) and is routed straight to `overflow` regardless
    /// of the map's current size, so no caller — today or in the future —
    /// can accidentally open a normal `per_principal` window whose
    /// summary would then be indistinguishable from an actual overflow
    /// summary. This call only ever touches its own
    /// key's window; it never inspects or closes another principal's
    /// still-open window in the same category, so the critical section
    /// stays O(1) regardless of how many other principals are currently
    /// being tracked (the deliberate trade documented on
    /// `CategoryWindows`/[`Quotas::flush_expired`]: a window that has
    /// gone stale but has not yet been swept can occupy a map slot for up
    /// to one more housekeeping tick before a *new* principal beyond the
    /// cap is pushed to overflow — an audit-attribution quality question,
    /// never a cap-enforcement one).
    pub fn record_rejection(
        &self,
        kind: QuotaKind,
        principal: &str,
        peer_addr: std::net::SocketAddr,
        now: Instant,
        request_id: Option<u64>,
        auth_path: qsh_transport::AuthPath,
    ) -> Vec<AuditRecord> {
        // Counted on every call, independent of the
        // window-suppression decision below — suppression governs whether
        // *this* call also emits its own audit line, not whether it
        // happened at all.
        self.rejections[kind as usize].fetch_add(1, Ordering::Relaxed);
        let mut cat = self.windows[kind as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // `is_overflow` records which window this rejection landed in so
        // the summary line built after the lock is dropped below can pick
        // the right principal string ("-" for overflow, the window's own
        // owner otherwise) without holding the lock while formatting it.
        //
        // R2 review B (B1): `"-"` is reserved for the overflow summary and
        // must never become a `per_principal` key in its own right — a
        // caller that (today or in the future) audits a pre-identity axis
        // under the same sentinel admission already uses for it
        // (`docs/CLI.md` §6.12's admission-reject `principal: "-"`) would
        // otherwise open a normal, indistinguishable window under that
        // string, and its summary line would then be byte-for-byte
        // identical to an actual overflow summary. Routing it to
        // `overflow` up front makes that invariant a type fact instead of
        // a convention every future caller has to already know.
        let (state, is_overflow) = if principal == "-" {
            (&mut cat.overflow, true)
        } else if let Some(state) = cat.per_principal.get_mut(principal) {
            (state, false)
        } else if cat.per_principal.len() >= MAX_AUDIT_WINDOW_PRINCIPALS {
            (&mut cat.overflow, true)
        } else {
            (
                cat.per_principal.entry(principal.to_string()).or_default(),
                false,
            )
        };
        let window_is_fresh = match state.start {
            None => true,
            Some(start) => now.saturating_duration_since(start) >= AUDIT_AGGREGATION_WINDOW,
        };
        if !window_is_fresh {
            // Same critical section as the freshness check above — no gap
            // a concurrent `flush_expired` could land its close inside
            // (mirrors `Gate::record_rejection`'s own identical note).
            state.suppressed = state.suppressed.saturating_add(1);
            return Vec::new();
        }
        let prior_suppressed = state.suppressed;
        state.suppressed = 0;
        state.start = Some(now);
        drop(cat);
        let mut records = Vec::with_capacity(2);
        if prior_suppressed > 0 {
            records.push(AuditRecord::quota_rejected_summary(
                kind,
                if is_overflow { "-" } else { principal },
                prior_suppressed,
            ));
        }
        records.push(AuditRecord::quota_rejected(
            kind, principal, peer_addr, request_id, auth_path,
        ));
        records
    }

    /// Force-close every category window whose `start` is at least
    /// [`AUDIT_AGGREGATION_WINDOW`] old, emitting a
    /// [`AuditRecord::quota_rejected_summary`] for any that suppressed at
    /// least one rejection — mirrors `crate::admission::Gate::
    /// flush_expired` exactly (same rationale: a flood that has already
    /// stopped still gets its last window's summary within one more
    /// tick, even with nothing left to trigger the lazy path in
    /// [`Quotas::record_rejection`]).
    ///
    /// A closed principal window's entry is *deleted* from
    /// `CategoryWindows::per_principal`, not reset in place — this is
    /// what keeps the map's cardinality bounded by
    /// [`MAX_AUDIT_WINDOW_PRINCIPALS`] rather than growing by one for
    /// every distinct principal ever rejected over the process's
    /// lifetime. The only thing dropped under the category lock is a
    /// `String` (the deleted key) — not a session or child-process
    /// handle — so this stays within the module's own "collect under the
    /// guard, drop outside" lock discipline (top-of-file doc). The
    /// `overflow` slot is a fixed field, never deleted, only closed
    /// (`start = None`) the same way a principal window used to be.
    ///
    /// One consequence worth naming: with up to
    /// [`MAX_AUDIT_WINDOW_PRINCIPALS`] principal windows live per
    /// category, a single tick's return can carry up to
    /// `QuotaKind::ALL.len() × (MAX_AUDIT_WINDOW_PRINCIPALS + 1)` summary
    /// records (650 today) instead of the old at-most-10. `crate::audit::
    /// write_quota_audit`'s sink write can return `AuditError::QueueFull`
    /// under that burst; that path does not latch the sink `degraded` (only
    /// a hard write failure does, `crate::audit::writer::RotatingAuditSink
    /// ::record`), and the caller already treats a failed quota-audit
    /// enqueue as fail-open (the request itself is already being refused,
    /// so a lost *summary* line only degrades the diagnostic, not any
    /// enforcement decision).
    ///
    /// **R2 review A (F1): this burst is not free of effect on other
    /// traffic, and the previous wording here overstated that it was.**
    /// `write_quota_audit` shares one `AuditSink` — and one bounded queue —
    /// with `Server::authorize`/`authorize_stream`'s own enqueues, and
    /// *those* choke points are where the actual `docs/CLI.md` §6.12
    /// fail-closed rule lives: an allow verdict whose own audit enqueue
    /// fails is denied (`server/mod.rs`'s `verdict.is_allow() &&
    /// recorded.is_ok()` / `!verdict.is_allow() || recorded.is_err()`
    /// shape). A 650-record burst landing in the same queue at the same
    /// instant as a legitimate request's own enqueue can push that
    /// request's enqueue into `QueueFull` too, and the fail-closed rule
    /// then denies a request that was never itself over any quota — an
    /// availability cost, not a fail-closed *violation* (no allow ever
    /// reaches a peer without a durable record; the queue-full request is
    /// simply refused instead). The default `[audit].queue_depth` (1024)
    /// leaves headroom over the 650-record ceiling; the test
    /// `flush_expired_worst_case_burst_fits_under_the_default_audit_queue_
    /// depth` below pins that relationship so a future `QuotaKind::ALL`
    /// growth (or a cap increase) that closes the gap fails loudly instead
    /// of silently. An operator who lowers `[audit].queue_depth` below the
    /// per-tick ceiling trades that headroom away themselves.
    ///
    /// **R2 review B (B5):** the same row-count increase (2 → up to 130
    /// per category per window, before this change) also shortens how
    /// long a deny record actually survives on disk under a
    /// principal-rotating flood. `[audit].max_bytes × (retain + 1)` still
    /// bounds the audit directory's total *volume* (`docs/CLI.md` §6.12),
    /// but a flood that fills the same volume with more rows pushes older
    /// deny records past `[audit].retain`'s rotation boundary sooner —
    /// this is ordinary rotation working as designed, not a new bound
    /// violation, but it means "audit flood does not grow the log" is no
    /// longer the same claim as "audit flood does not shorten retention".
    pub fn flush_expired(&self, now: Instant) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        for (window, kind) in self.windows.iter().zip(QuotaKind::ALL.iter().copied()) {
            let mut closed: Vec<(String, u32)> = Vec::new();
            let mut overflow_suppressed = None;
            {
                let mut cat = window.lock().unwrap_or_else(|e| e.into_inner());
                cat.per_principal.retain(|principal, state| {
                    let Some(start) = state.start else {
                        return false;
                    };
                    if now.saturating_duration_since(start) < AUDIT_AGGREGATION_WINDOW {
                        return true;
                    }
                    closed.push((principal.clone(), state.suppressed));
                    false
                });
                if let Some(start) = cat.overflow.start
                    && now.saturating_duration_since(start) >= AUDIT_AGGREGATION_WINDOW
                {
                    overflow_suppressed = Some(cat.overflow.suppressed);
                    cat.overflow.start = None;
                    cat.overflow.suppressed = 0;
                }
            }
            for (principal, suppressed) in closed {
                if suppressed > 0 {
                    records.push(AuditRecord::quota_rejected_summary(
                        kind, &principal, suppressed,
                    ));
                }
            }
            if let Some(suppressed) = overflow_suppressed
                && suppressed > 0
            {
                records.push(AuditRecord::quota_rejected_summary(kind, "-", suppressed));
            }
        }
        records
    }

    /// Test-only accessors replacing the direct `windows[..].is_open()`
    /// field access the pre-Step-5 single-window-per-category shape used
    /// — `CategoryWindows`'s two fields are private so the invariants in
    /// its own doc comment (map cardinality, overflow separation) cannot
    /// be violated from outside this module even in tests.
    #[cfg(test)]
    fn audit_window_is_open(&self, kind: QuotaKind, principal: &str) -> bool {
        // A deleted entry (`flush_expired`) reads as closed — deletion
        // *is* closure in this design, not merely "closure implies
        // deletion eventually".
        self.windows[kind as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .per_principal
            .get(principal)
            .is_some_and(|state| state.start.is_some())
    }

    #[cfg(test)]
    fn audit_window_principal_count(&self, kind: QuotaKind) -> usize {
        self.windows[kind as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .per_principal
            .len()
    }

    #[cfg(test)]
    fn audit_overflow_window_is_open(&self, kind: QuotaKind) -> bool {
        self.windows[kind as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .overflow
            .start
            .is_some()
    }
}

/// RAII `exec.run` concurrency reservation ([`Quotas::reserve_exec`]).
/// `Drop` decrements the principal's in-use count (removing the map entry
/// entirely once it reaches zero, so the map's cardinality never exceeds
/// the number of principals currently holding a live reservation) — this
/// runs on every exit path (normal completion, early `?` return, task
/// abort's unwind), so a slot can never leak the way a hand-maintained
/// counter's scattered decrement sites invite (`crate::broker`'s own
/// registry-derived-count rationale, restated here for the same reason).
#[derive(Debug)]
pub struct ExecPermit {
    quotas: Weak<Quotas>,
    principal_key: String,
}

impl Drop for ExecPermit {
    fn drop(&mut self) {
        // B4 (M8 Step 3a fix-3 sweep): the mechanical half of ADR-0010
        // §9's "collect under the guard, drop outside" rule — an
        // `ExecPermit` (this struct) is what a `Ticket` carries, so its
        // `Drop` is exactly the thing that must never run while a
        // higher-level lock (`crate::server::Server`'s tickets map) is
        // still held. `lock_order::violations()` never panics inside a
        // `Drop` impl (a panicking `Drop` during unwind aborts the
        // process) — it only records the violation for a test's own
        // assertion to fail on.
        #[cfg(test)]
        if lock_order::DEPTH.with(|d| d.get()) > 0 {
            lock_order::VIOLATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        let Some(quotas) = self.quotas.upgrade() else {
            return;
        };
        let mut state = quotas.lock();
        if let Some(count) = state.exec_in_use.get_mut(&self.principal_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.exec_in_use.remove(&self.principal_key);
            }
        }
    }
}

/// RAII tunnel-stream concurrency reservation ([`Quotas::
/// reserve_tunnel_stream`], M8 Step 3b). `Drop` decrements both the
/// per-principal and per-`(principal, destination)` counts (removing
/// either map entry entirely once it reaches zero), the same discipline
/// as [`ExecPermit`]'s own `Drop` for the same reason — this is what
/// `crate::server::Server::handle_tcp_connect` holds across the whole
/// spliced connection, so every exit path (clean close, error, task
/// abort's unwind) must release both axes exactly once.
#[derive(Debug)]
pub struct TunnelStreamPermit {
    quotas: Weak<Quotas>,
    principal_key: String,
    resource: String,
}

impl Drop for TunnelStreamPermit {
    fn drop(&mut self) {
        // Same B4 lock-order tripwire as `ExecPermit::drop` — this
        // permit's `Drop` must never run while a higher-level lock (e.g.
        // `crate::server::Server`'s tickets map) is still held.
        #[cfg(test)]
        if lock_order::DEPTH.with(|d| d.get()) > 0 {
            lock_order::VIOLATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        let Some(quotas) = self.quotas.upgrade() else {
            return;
        };
        let mut state = quotas.lock();
        if let Some(count) = state
            .tunnel_streams_per_principal
            .get_mut(&self.principal_key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state
                    .tunnel_streams_per_principal
                    .remove(&self.principal_key);
            }
        }
        let forward_key = (self.principal_key.clone(), self.resource.clone());
        if let Some(count) = state.tunnel_streams_per_forward.get_mut(&forward_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.tunnel_streams_per_forward.remove(&forward_key);
            }
        }
    }
}

/// RAII remote-forward-listener concurrency reservation ([`Quotas::
/// reserve_remote_forward`], M8 Step 3b). `Drop` decrements the
/// principal's in-use count (removing the map entry entirely once it
/// reaches zero), the same discipline as [`ExecPermit`]'s own `Drop` for
/// the same reason — `crate::server::Server`'s `RemoteForwardEntry` holds
/// exactly one of these, so both removal sites
/// (`crate::server::Server::handle_rfwd_close`,
/// [`crate::server::Server::purge_connection`]) release it automatically
/// by dropping the entry, rather than each having to remember a manual
/// decrement.
#[derive(Debug)]
pub struct RemoteForwardPermit {
    quotas: Weak<Quotas>,
    principal_key: String,
}

impl Drop for RemoteForwardPermit {
    fn drop(&mut self) {
        // Same B4 lock-order tripwire as `ExecPermit::drop`/
        // `TunnelStreamPermit::drop` — this permit's `Drop` must never run
        // while a higher-level lock (e.g. `crate::server::Server`'s
        // `remote_forwards` map) is still held.
        #[cfg(test)]
        if lock_order::DEPTH.with(|d| d.get()) > 0 {
            lock_order::VIOLATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        let Some(quotas) = self.quotas.upgrade() else {
            return;
        };
        let mut state = quotas.lock();
        if let Some(count) = state
            .remote_forwards_per_principal
            .get_mut(&self.principal_key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state
                    .remote_forwards_per_principal
                    .remove(&self.principal_key);
            }
        }
    }
}

/// RAII connection-count reservation ([`Quotas::reserve_connection`], M8
/// Step 3b). `Drop` decrements the principal's in-use count (removing the
/// map entry entirely once it reaches zero), same discipline as
/// [`ExecPermit`]'s own `Drop` for the same reason —
/// `crate::server::Server::serve_connection` and `crate::reverse::listen::
/// Listen::accept_and_register_permitted` each hold exactly one of these
/// across their whole connection lifetime, dropping it only after their
/// own cleanup (`purge_connection`/`conns.remove_if`) has already run
/// (ruling R3: releasing it any earlier would let a dead connection's
/// forwards outlive its slot).
#[derive(Debug)]
pub struct ConnectionPermit {
    quotas: Weak<Quotas>,
    principal_key: String,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        // Same B4 lock-order tripwire as `ExecPermit::drop` — this
        // permit's `Drop` must never run while a higher-level lock is
        // still held.
        #[cfg(test)]
        if lock_order::DEPTH.with(|d| d.get()) > 0 {
            lock_order::VIOLATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        let Some(quotas) = self.quotas.upgrade() else {
            return;
        };
        let mut state = quotas.lock();
        if let Some(count) = state.connections_per_principal.get_mut(&self.principal_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.connections_per_principal.remove(&self.principal_key);
            }
        }
    }
}

/// RAII pairing-connection-count reservation ([`Quotas::
/// reserve_pairing_connection`], M8 Step 3b ruling R2). `Drop` decrements
/// the fixed counter — no map, no principal key, same reasoning as
/// [`ConnectionPermit`]'s own `Drop`.
#[derive(Debug)]
pub struct PairingConnectionPermit {
    quotas: Weak<Quotas>,
}

impl Drop for PairingConnectionPermit {
    fn drop(&mut self) {
        // Same B4 lock-order tripwire as every other permit's `Drop` here.
        #[cfg(test)]
        if lock_order::DEPTH.with(|d| d.get()) > 0 {
            lock_order::VIOLATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        let Some(quotas) = self.quotas.upgrade() else {
            return;
        };
        let mut state = quotas.lock();
        state.pairing_connections_in_use = state.pairing_connections_in_use.saturating_sub(1);
    }
}

/// `cfg(test)`-only lock-order tripwire (M8 Step 3a fix-3 sweep, B4):
/// mechanically enforces ADR-0010 §9's "collect under the guard, drop
/// outside" rule instead of leaving it to convention and code review
/// alone. `crate::server::Server` routes every `self.tickets.lock()`
/// acquisition through one helper (`lock_tickets`) whose returned guard
/// holds a [`NonLeafGuard`] for as long as the tickets map is locked;
/// [`ExecPermit`]'s own `Drop` (above) checks [`DEPTH`] and records a
/// violation in [`VIOLATIONS`] if it runs while some `NonLeafGuard` is
/// still alive on this thread — an `ExecPermit` dropped while a
/// higher-level lock is held is precisely the ordering ADR-0010 §9
/// forbids (its own `Drop` takes the *leaf-most* quota lock, safe to run
/// underneath another lock, never while one is still held).
///
/// [`VIOLATIONS`] is process-global, not per-test: `cargo nextest` runs
/// one test per process, so a nonzero count read back within a single
/// test's own assertion is never cross-test noise.
#[cfg(test)]
pub(crate) mod lock_order {
    use std::cell::Cell;
    use std::sync::atomic::AtomicUsize;

    thread_local! {
        pub(super) static DEPTH: Cell<u32> = const { Cell::new(0) };
    }

    pub(super) static VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

    /// Held for the lifetime of a non-leaf lock scope (today: just
    /// `crate::server::Server`'s tickets map, via its `TicketsGuard`).
    /// The constructor increments [`DEPTH`]; `Drop` decrements it — so a
    /// thread nesting two non-leaf scopes (not that any do today) is
    /// still tracked correctly by depth, not a boolean.
    pub(crate) struct NonLeafGuard;

    impl NonLeafGuard {
        pub(crate) fn new() -> Self {
            DEPTH.with(|d| d.set(d.get() + 1));
            Self
        }
    }

    impl Drop for NonLeafGuard {
        fn drop(&mut self) {
            DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
        }
    }

    /// Read back by a test after exercising every sweep site once.
    pub(crate) fn violations() -> usize {
        VIOLATIONS.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests;
