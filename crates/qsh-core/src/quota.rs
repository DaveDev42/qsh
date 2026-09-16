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

mod audit;
mod connection;
mod exec;
mod pairing;
mod remote_forward;
mod tunnel_stream;

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
