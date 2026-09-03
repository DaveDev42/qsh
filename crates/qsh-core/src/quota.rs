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
//! [`crate::admission::AuditWindow`]'s) is always the **leaf-most** lock
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
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use crate::admission::{AUDIT_AGGREGATION_WINDOW, AuditWindow};
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
    windows: [AuditWindow; QuotaKind::ALL.len()],
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
        })
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
    #[cfg(test)]
    fn tunnel_streams_per_principal_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .tunnel_streams_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Current live tunnel-stream reservation count for
    /// `(principal_key, resource)` — test/diagnostic use only.
    #[cfg(test)]
    fn tunnel_streams_per_forward_in_use(&self, principal_key: &str, resource: &str) -> usize {
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
            return Err(QuotaKind::Connections);
        }
        let current = state
            .connections_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0);
        if current >= self.limits.max_connections_per_principal {
            return Err(QuotaKind::ConnectionsPerPrincipal);
        }
        *state
            .connections_per_principal
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        drop(state);
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
            return Err(QuotaKind::PairingConnections);
        }
        state.pairing_connections_in_use += 1;
        drop(state);
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
    pub fn record_rejection(
        &self,
        kind: QuotaKind,
        principal: &str,
        peer_addr: std::net::SocketAddr,
        now: Instant,
        request_id: Option<u64>,
        auth_path: qsh_transport::AuthPath,
    ) -> Vec<AuditRecord> {
        let window = &self.windows[kind as usize];
        let mut guard = window.state.lock().unwrap_or_else(|e| e.into_inner());
        let window_is_fresh = match guard.start {
            None => true,
            Some(start) => now.saturating_duration_since(start) >= AUDIT_AGGREGATION_WINDOW,
        };
        if !window_is_fresh {
            // Same critical section as the freshness check above — no gap
            // a concurrent `flush_expired` could land its close inside
            // (mirrors `Gate::record_rejection`'s own identical note).
            guard.suppressed = guard.suppressed.saturating_add(1);
            return Vec::new();
        }
        let prior_suppressed = guard.suppressed;
        guard.suppressed = 0;
        guard.start = Some(now);
        drop(guard);
        let mut records = Vec::with_capacity(2);
        if prior_suppressed > 0 {
            records.push(AuditRecord::quota_rejected_summary(
                kind,
                "-",
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
    pub fn flush_expired(&self, now: Instant) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        for (window, kind) in self.windows.iter().zip(QuotaKind::ALL.iter().copied()) {
            let mut guard = window.state.lock().unwrap_or_else(|e| e.into_inner());
            let Some(start) = guard.start else {
                continue;
            };
            if now.saturating_duration_since(start) < AUDIT_AGGREGATION_WINDOW {
                continue;
            }
            let suppressed = guard.suppressed;
            guard.start = None;
            guard.suppressed = 0;
            drop(guard);
            if suppressed > 0 {
                records.push(AuditRecord::quota_rejected_summary(kind, "-", suppressed));
            }
        }
        records
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
/// ([`crate::server::Server::handle_rfwd_close`],
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
mod tests {
    use super::*;
    use crate::broker::TestClock;

    fn quotas_with(max_exec_per_principal: usize) -> Arc<Quotas> {
        Quotas::new(
            QuotaLimits {
                max_exec_per_principal,
                ..QuotaLimits::default()
            },
            Arc::new(TestClock::new()),
        )
    }

    #[test]
    fn reserve_exec_refuses_past_the_cap_and_release_frees_the_slot() {
        let quotas = quotas_with(2);
        let p1 = quotas.reserve_exec("device:a").unwrap();
        let p2 = quotas.reserve_exec("device:a").unwrap();
        assert_eq!(quotas.exec_in_use("device:a"), 2);
        assert_eq!(
            quotas.reserve_exec("device:a").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );

        drop(p1);
        assert_eq!(quotas.exec_in_use("device:a"), 1);
        let p3 = quotas.reserve_exec("device:a").unwrap();
        assert_eq!(quotas.exec_in_use("device:a"), 2);

        drop(p2);
        drop(p3);
        assert_eq!(quotas.exec_in_use("device:a"), 0);
    }

    /// Adversary finding A8: `exec_in_use`'s comparison against
    /// `max_exec_per_principal` used to cast the limit down to `u32`,
    /// truncating any limit above `u32::MAX` back into a small (even
    /// zero) effective cap. `exec_in_use` is `usize` now, so a limit this
    /// large must still admit the very first reservation.
    #[test]
    fn reserve_exec_is_not_truncated_by_a_limit_above_u32_max() {
        let quotas = quotas_with(1usize << 32);
        assert!(quotas.reserve_exec("device:a").is_ok());
    }

    fn quotas_with_tunnel(
        max_tunnel_streams_per_principal: usize,
        max_tunnel_streams_per_forward: usize,
    ) -> Arc<Quotas> {
        Quotas::new(
            QuotaLimits {
                max_tunnel_streams_per_principal,
                max_tunnel_streams_per_forward,
                ..QuotaLimits::default()
            },
            Arc::new(TestClock::new()),
        )
    }

    /// [`TunnelStreamPermit::drop`] must decrement both axes it
    /// incremented and, once either count reaches zero, remove that map
    /// entry entirely — the same "no entry without a live resource"
    /// invariant `reserve_exec_refuses_past_the_cap_and_release_frees_
    /// the_slot` pins for `ExecPermit`. Distinct from that test in
    /// checking cardinality (`_entry_count`) as well as the count itself:
    /// `_in_use`'s `unwrap_or(0)` alone cannot tell "no entry" apart from
    /// "entry present holding `0`".
    #[test]
    fn tunnel_permit_release_frees_the_slot_and_drops_the_map_entry() {
        let quotas = quotas_with_tunnel(64, 2);
        let p1 = quotas
            .reserve_tunnel_stream("device:a", "db.internal:5432")
            .unwrap();
        let p2 = quotas
            .reserve_tunnel_stream("device:a", "db.internal:5432")
            .unwrap();
        assert_eq!(
            quotas.tunnel_streams_per_forward_in_use("device:a", "db.internal:5432"),
            2
        );
        assert_eq!(quotas.tunnel_streams_per_principal_in_use("device:a"), 2);
        assert_eq!(
            quotas
                .reserve_tunnel_stream("device:a", "db.internal:5432")
                .unwrap_err(),
            QuotaKind::TunnelStreamsPerForward
        );

        drop(p1);
        assert_eq!(
            quotas.tunnel_streams_per_forward_in_use("device:a", "db.internal:5432"),
            1
        );
        assert_eq!(quotas.tunnel_streams_per_principal_entry_count(), 1);

        drop(p2);
        assert_eq!(
            quotas.tunnel_streams_per_forward_in_use("device:a", "db.internal:5432"),
            0
        );
        assert_eq!(
            quotas.tunnel_streams_per_forward_entry_count(),
            0,
            "the last release must remove the map entry, not just zero it"
        );
        assert_eq!(quotas.tunnel_streams_per_principal_entry_count(), 0);
    }

    /// The forward axis is keyed by `(principal, destination)`, not by
    /// either alone: the same principal dialing two destinations gets two
    /// independent forward budgets, and two principals dialing the same
    /// destination get two independent budgets too — only the
    /// per-principal axis (checked first) is shared across destinations
    /// for one principal.
    #[test]
    fn the_tunnel_quota_is_keyed_by_principal_and_destination() {
        let quotas = quotas_with_tunnel(64, 1);
        let _a_db = quotas
            .reserve_tunnel_stream("device:a", "db.internal:5432")
            .unwrap();
        // Same principal, different destination: forward axis is
        // independent, so this must not see "device:a"/"db" 's count.
        let _a_web = quotas
            .reserve_tunnel_stream("device:a", "web.internal:443")
            .unwrap();
        assert_eq!(quotas.tunnel_streams_per_principal_in_use("device:a"), 2);

        // Different principal, same destination: also independent.
        let _b_db = quotas
            .reserve_tunnel_stream("device:b", "db.internal:5432")
            .unwrap();
        assert_eq!(
            quotas.tunnel_streams_per_forward_in_use("device:b", "db.internal:5432"),
            1
        );

        // But "device:a" against "db.internal:5432" is still at its own
        // forward cap of 1.
        assert_eq!(
            quotas
                .reserve_tunnel_stream("device:a", "db.internal:5432")
                .unwrap_err(),
            QuotaKind::TunnelStreamsPerForward
        );
    }

    fn quotas_with_remote_forward(max_remote_forwards_per_principal: usize) -> Arc<Quotas> {
        Quotas::new(
            QuotaLimits {
                max_remote_forwards_per_principal,
                ..QuotaLimits::default()
            },
            Arc::new(TestClock::new()),
        )
    }

    /// [`RemoteForwardPermit::drop`] must decrement the principal's
    /// in-use count and, once it reaches zero, remove the map entry
    /// entirely — the M8 Step 3b twin of `reserve_exec_refuses_past_the_
    /// cap_and_release_frees_the_slot`/`tunnel_permit_release_frees_the_
    /// slot_and_drops_the_map_entry` for the listener axis.
    #[test]
    fn remote_forward_permit_release_frees_the_slot_and_drops_the_map_entry() {
        let quotas = quotas_with_remote_forward(2);
        let p1 = quotas.reserve_remote_forward("device:a").unwrap();
        let p2 = quotas.reserve_remote_forward("device:a").unwrap();
        assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 2);
        assert_eq!(
            quotas.reserve_remote_forward("device:a").unwrap_err(),
            QuotaKind::RemoteForwardsPerPrincipal
        );

        drop(p1);
        assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 1);
        assert_eq!(quotas.remote_forwards_per_principal_entry_count(), 1);
        let p3 = quotas.reserve_remote_forward("device:a").unwrap();
        assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 2);

        drop(p2);
        drop(p3);
        assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 0);
        assert_eq!(
            quotas.remote_forwards_per_principal_entry_count(),
            0,
            "the last release must remove the map entry, not just zero it"
        );
    }

    /// Isolated per principal, same as `exec_quota_is_isolated_per_
    /// principal`/`the_tunnel_quota_is_keyed_by_principal_and_
    /// destination`'s own principal axis: one principal at its cap never
    /// blocks another.
    #[test]
    fn remote_forward_quota_is_isolated_per_principal() {
        let quotas = quotas_with_remote_forward(1);
        let _a = quotas.reserve_remote_forward("device:a").unwrap();
        let _b = quotas.reserve_remote_forward("device:b").unwrap();
        assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 1);
        assert_eq!(quotas.remote_forwards_per_principal_in_use("device:b"), 1);
        assert_eq!(
            quotas.reserve_remote_forward("device:a").unwrap_err(),
            QuotaKind::RemoteForwardsPerPrincipal
        );
    }

    fn quotas_with_connections(
        max_connections: usize,
        max_connections_per_principal: usize,
    ) -> Arc<Quotas> {
        Quotas::new(
            QuotaLimits {
                max_connections,
                max_connections_per_principal,
                ..QuotaLimits::default()
            },
            Arc::new(TestClock::new()),
        )
    }

    /// [`ConnectionPermit::drop`] must decrement the principal's in-use
    /// count and, once it reaches zero, remove the map entry entirely —
    /// the M8 Step 3b twin of `remote_forward_permit_release_frees_the_
    /// slot_and_drops_the_map_entry` for the connection axis.
    #[test]
    fn connection_permit_release_frees_the_slot_and_drops_the_map_entry() {
        let quotas = quotas_with_connections(100, 2);
        let p1 = quotas.reserve_connection("device:a").unwrap();
        let p2 = quotas.reserve_connection("device:a").unwrap();
        assert_eq!(quotas.connections_per_principal_in_use("device:a"), 2);
        assert_eq!(
            quotas.reserve_connection("device:a").unwrap_err(),
            QuotaKind::ConnectionsPerPrincipal
        );

        drop(p1);
        assert_eq!(quotas.connections_per_principal_in_use("device:a"), 1);
        assert_eq!(quotas.connections_per_principal_entry_count(), 1);
        let p3 = quotas.reserve_connection("device:a").unwrap();
        assert_eq!(quotas.connections_per_principal_in_use("device:a"), 2);

        drop(p2);
        drop(p3);
        assert_eq!(quotas.connections_per_principal_in_use("device:a"), 0);
        assert_eq!(
            quotas.connections_per_principal_entry_count(),
            0,
            "the last release must remove the map entry, not just zero it"
        );
    }

    /// Host axis first, then per-principal — same order
    /// `exec_reservation_refuses_on_the_host_cap_before_the_principal_cap`
    /// pins for `reserve_exec`, restated here for `reserve_connection`
    /// (M8 Step 3b ruling R3: "host → principal, matching `reserve_exec`'s
    /// own order").
    #[test]
    fn connection_reservation_refuses_on_the_host_cap_before_the_principal_cap() {
        let quotas = quotas_with_connections(1, 100);
        let _first = quotas.reserve_connection("device:a").unwrap();

        // A second, entirely distinct principal — nowhere near its own
        // per-principal budget — is still refused, and refused for the
        // host reason, not the (irrelevant, unreached) per-principal one.
        assert_eq!(
            quotas.reserve_connection("device:b").unwrap_err(),
            QuotaKind::Connections
        );
        assert_eq!(quotas.connections_per_principal_in_use("device:b"), 0);

        // The principal that filled the host cap is bound by it too.
        assert_eq!(
            quotas.reserve_connection("device:a").unwrap_err(),
            QuotaKind::Connections
        );
    }

    /// Isolated per principal, same as every other per-principal axis in
    /// this module.
    #[test]
    fn connection_quota_is_isolated_per_principal() {
        let quotas = quotas_with_connections(100, 1);
        let _a = quotas.reserve_connection("device:a").unwrap();
        let _b = quotas.reserve_connection("device:b").unwrap();
        assert_eq!(quotas.connections_per_principal_in_use("device:a"), 1);
        assert_eq!(quotas.connections_per_principal_in_use("device:b"), 1);
        assert_eq!(
            quotas.reserve_connection("device:a").unwrap_err(),
            QuotaKind::ConnectionsPerPrincipal
        );
    }

    /// [`PairingConnectionPermit::drop`] must decrement the fixed counter
    /// — no map, no principal key, same discipline as every other
    /// permit's `Drop` in this module. Also pins the fixed cap itself
    /// (`MAX_CONCURRENT_PAIRING_CONNECTIONS = 8`, M8 Step 3b ruling R2):
    /// not configurable, so this test (unlike every other `reserve_*`
    /// test here) needs no `QuotaLimits` override to reach it.
    #[test]
    fn pairing_connection_permit_release_frees_the_fixed_slot() {
        let quotas = Quotas::new(QuotaLimits::default(), Arc::new(TestClock::new()));
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_PAIRING_CONNECTIONS {
            permits.push(quotas.reserve_pairing_connection().unwrap());
        }
        assert_eq!(
            quotas.pairing_connections_in_use(),
            MAX_CONCURRENT_PAIRING_CONNECTIONS
        );
        assert_eq!(
            quotas.reserve_pairing_connection().unwrap_err(),
            QuotaKind::PairingConnections
        );

        drop(permits.pop().unwrap());
        assert_eq!(
            quotas.pairing_connections_in_use(),
            MAX_CONCURRENT_PAIRING_CONNECTIONS - 1
        );
        let _fresh = quotas.reserve_pairing_connection().unwrap();
        assert_eq!(
            quotas.pairing_connections_in_use(),
            MAX_CONCURRENT_PAIRING_CONNECTIONS
        );

        permits.clear();
        drop(_fresh);
        assert_eq!(quotas.pairing_connections_in_use(), 0);
    }

    #[test]
    fn exec_quota_is_isolated_per_principal() {
        let quotas = quotas_with(1);
        let _a = quotas.reserve_exec("device:a").unwrap();
        // A's cap is full, but B is a distinct key and still admits.
        let _b = quotas.reserve_exec("device:b").unwrap();
        assert_eq!(quotas.exec_in_use("device:a"), 1);
        assert_eq!(quotas.exec_in_use("device:b"), 1);
        assert_eq!(
            quotas.reserve_exec("device:a").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );
        assert_eq!(
            quotas.reserve_exec("device:b").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );
    }

    /// F9 of the M8 Step 3a conformance sweep: `reserve_exec` must test
    /// the cap *before* touching `exec_in_use`'s map, not
    /// `entry(..).or_insert(0)` ahead of the check. With
    /// `max_exec_per_principal == 0` (unreachable through parsed config,
    /// where `0` degrades to the default — `QuotaLimits::from_serve` — but
    /// directly reachable through a hand-built `QuotaLimits` the way this
    /// test, and 3b's tunnel/connection quotas, construct one) every
    /// refused reservation must leave the map exactly as it found it: no
    /// zero-valued entry surviving under the refused principal's key.
    #[test]
    fn reserve_exec_leaves_no_entry_behind_when_the_cap_is_zero() {
        let quotas = quotas_with(0);
        assert_eq!(
            quotas.reserve_exec("device:a").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );
        assert_eq!(quotas.exec_in_use("device:a"), 0);
        assert_eq!(
            quotas.exec_in_use_principal_count(),
            0,
            "a refused reservation against a zero cap must not plant a \
             zero-valued map entry — the module's own \"no entry without \
             a live resource\" invariant"
        );

        // A second, distinct principal against the same zero cap: same
        // refusal, same empty map afterward.
        assert_eq!(
            quotas.reserve_exec("device:b").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );
        assert_eq!(quotas.exec_in_use_principal_count(), 0);
    }

    #[test]
    fn quota_audit_reports_first_then_summary() {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        // First rejection in a fresh window: an immediate, real record.
        let first_batch = quotas.record_rejection(
            QuotaKind::ExecPerPrincipal,
            "device:a",
            peer,
            t0,
            Some(1),
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(
            first_batch.len(),
            1,
            "just the fresh window's own first line"
        );
        let first = &first_batch[0];
        assert_eq!(first.principal, "device:a");
        assert_eq!(first.resource, QuotaKind::ExecPerPrincipal.category());
        assert_eq!(first.count, None);

        // Two more within the same window: suppressed, no record yet.
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::ExecPerPrincipal,
                    "device:a",
                    peer,
                    t0 + std::time::Duration::from_secs(1),
                    Some(1),
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::ExecPerPrincipal,
                    "device:a",
                    peer,
                    t0 + std::time::Duration::from_secs(2),
                    Some(1),
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );

        // Flushing before the window has aged out reports nothing.
        assert!(
            quotas
                .flush_expired(t0 + std::time::Duration::from_secs(3))
                .is_empty()
        );

        // Once the window has aged past AUDIT_AGGREGATION_WINDOW, flush
        // closes it with a summary counting the two suppressed rejections.
        let flushed =
            quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].principal, "-");
        assert_eq!(flushed[0].count, Some(2));
        assert_eq!(flushed[0].resource, QuotaKind::ExecPerPrincipal.category());
    }

    /// M8 Step 3b S5: twin of `quota_audit_reports_first_then_summary`,
    /// but for a tunnel-stream category and interleaved with rejections
    /// on an unrelated category (`ExecPerPrincipal`) in the same window —
    /// `windows` is one slot per `QuotaKind`, so the tunnel category's
    /// first-line/summary count must reflect only *its own* rejections,
    /// never the other category's, even though both windows are open and
    /// aging over the exact same wall-clock span.
    #[test]
    fn a_tunnel_quota_rejection_reports_first_then_summary_in_its_own_window() {
        let quotas = quotas_with_tunnel(1, 64);
        let clock = TestClock::new();
        let t0 = clock.now();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let sec = std::time::Duration::from_secs(1);

        // First tunnel rejection in a fresh window: real record.
        let first = quotas.record_rejection(
            QuotaKind::TunnelStreamsPerPrincipal,
            "device:a",
            peer,
            t0,
            None,
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(first.len(), 1);
        assert_eq!(
            first[0].resource,
            QuotaKind::TunnelStreamsPerPrincipal.category()
        );

        // An unrelated category's own first rejection, same instant: its
        // own window opens independently and must not be folded into the
        // tunnel window's count.
        let unrelated_first = quotas.record_rejection(
            QuotaKind::ExecPerPrincipal,
            "device:a",
            peer,
            t0,
            Some(9),
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(unrelated_first.len(), 1);

        // Three more tunnel rejections within the window: suppressed.
        for i in 1..=3u64 {
            assert!(
                quotas
                    .record_rejection(
                        QuotaKind::TunnelStreamsPerPrincipal,
                        "device:a",
                        peer,
                        t0 + sec * i as u32,
                        None,
                        qsh_transport::AuthPath::Ca,
                    )
                    .is_empty()
            );
        }
        // One more on the unrelated category too, so both windows close
        // at the same flush with different suppressed counts.
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::ExecPerPrincipal,
                    "device:a",
                    peer,
                    t0 + sec,
                    Some(9),
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );

        let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
        assert_eq!(flushed.len(), 2, "both windows close at this flush");
        let tunnel_summary = flushed
            .iter()
            .find(|r| r.resource == QuotaKind::TunnelStreamsPerPrincipal.category())
            .expect("tunnel summary present");
        assert_eq!(
            tunnel_summary.count,
            Some(3),
            "tunnel window must count exactly its own 3 suppressed \
             rejections, not the unrelated category's"
        );
        let exec_summary = flushed
            .iter()
            .find(|r| r.resource == QuotaKind::ExecPerPrincipal.category())
            .expect("exec summary present");
        assert_eq!(exec_summary.count, Some(1));
    }

    /// M8 Step 3b S5: `Quotas::windows` grew from 3 slots to
    /// `QuotaKind::ALL.len()` (10) across S1-S4. This pins that every one
    /// of the 7 categories S1 added closes its own window with a real
    /// summary — not just that `flush_expired_summary_names_the_correct_
    /// kind_for_every_category` above sees *a* record (which a stray
    /// hardcoded `windows: [AuditWindow; 3]` would already fail loudly
    /// on, via an out-of-bounds index panic long before this test could
    /// even run) but that the suppressed-count arithmetic for each new
    /// slot is independent and correct.
    #[test]
    fn flush_expired_closes_every_new_category_window() {
        let new_kinds = [
            QuotaKind::ExecHost,
            QuotaKind::TunnelStreamsPerPrincipal,
            QuotaKind::TunnelStreamsPerForward,
            QuotaKind::RemoteForwardsPerPrincipal,
            QuotaKind::ConnectionsPerPrincipal,
            QuotaKind::Connections,
            QuotaKind::PairingConnections,
        ];
        assert_eq!(
            new_kinds.len() + 3,
            QuotaKind::ALL.len(),
            "this test's own table must cover every category S1 added \
             on top of the pre-existing 3"
        );
        for kind in new_kinds {
            let quotas = quotas_with(1);
            let clock = TestClock::new();
            let t0 = clock.now();
            let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
            let sec = std::time::Duration::from_secs(1);

            let first = quotas.record_rejection(
                kind,
                "device:a",
                peer,
                t0,
                None,
                qsh_transport::AuthPath::Ca,
            );
            assert_eq!(first.len(), 1, "kind {kind:?}: first line");
            for i in 1..=2u64 {
                assert!(
                    quotas
                        .record_rejection(
                            kind,
                            "device:a",
                            peer,
                            t0 + sec * i as u32,
                            None,
                            qsh_transport::AuthPath::Ca,
                        )
                        .is_empty(),
                    "kind {kind:?}: suppressed rejection #{i}"
                );
            }
            let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
            assert_eq!(flushed.len(), 1, "kind {kind:?}: summary on flush");
            assert_eq!(
                flushed[0].count,
                Some(2),
                "kind {kind:?}: must count exactly its own 2 suppressed \
                 rejections"
            );
            assert_eq!(flushed[0].resource, kind.category());
            assert!(
                !quotas.windows[kind as usize].is_open(),
                "kind {kind:?}: flush must actually close its window"
            );
        }
    }

    /// `record_rejection` indexes `Quotas`'s internal `windows` array by
    /// `kind as usize` (this module's `windows: [AuditWindow;
    /// QuotaKind::ALL.len()]` field), while `flush_expired` walks
    /// `windows` zipped in lockstep with `QuotaKind::ALL`'s own iteration
    /// order — the two only agree with each other if `ALL`'s declared
    /// order exactly matches each variant's discriminant.
    #[test]
    fn quota_kind_all_is_declared_in_discriminant_order() {
        for (i, k) in QuotaKind::ALL.iter().enumerate() {
            assert_eq!(*k as usize, i);
        }
    }

    /// Twin of the discriminant-order pin above, exercised through the
    /// actual read/write path rather than the raw enum values: a window
    /// `record_rejection` opens for `kind` (via `kind as usize`) must be
    /// the exact same slot `flush_expired`'s `windows.iter().zip(ALL)`
    /// later reports back out *as* `kind` — reordering `QuotaKind::ALL`
    /// relative to declaration order would make `flush_expired` attribute
    /// one category's suppressed rejections to a different one.
    #[test]
    fn flush_expired_summary_names_the_correct_kind_for_every_category() {
        for &kind in QuotaKind::ALL {
            let quotas = quotas_with(1);
            let clock = TestClock::new();
            let t0 = clock.now();
            let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
            let sec = std::time::Duration::from_secs(1);

            let first = quotas.record_rejection(
                kind,
                "device:a",
                peer,
                t0,
                Some(1),
                qsh_transport::AuthPath::Ca,
            );
            assert_eq!(first.len(), 1, "kind {kind:?}: first line");
            assert_eq!(
                first[0].peer_addr,
                peer.to_string(),
                "kind {kind:?}: R4 — first line must carry the live peer, not \"-\""
            );
            assert_eq!(
                first[0].request_id, "1",
                "kind {kind:?}: R9 — a Some(1) request_id must audit as \"1\", not the \"-\" sentinel"
            );
            assert!(
                quotas
                    .record_rejection(
                        kind,
                        "device:a",
                        peer,
                        t0 + sec,
                        Some(1),
                        qsh_transport::AuthPath::Ca
                    )
                    .is_empty(),
                "kind {kind:?}: second rejection suppressed"
            );

            let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
            assert_eq!(flushed.len(), 1, "kind {kind:?}: summary");
            assert_eq!(
                flushed[0].resource,
                kind.category(),
                "kind {kind:?}: summary named the wrong category"
            );
            assert_eq!(
                flushed[0].peer_addr, "-",
                "kind {kind:?}: R4 — a summary record spans many peers and stays \"-\""
            );
            assert_eq!(
                flushed[0].request_id, "-",
                "kind {kind:?}: R9 — a summary record spans many requests and stays \"-\""
            );
        }
    }

    #[test]
    fn quota_flush_expired_closes_a_window_with_no_further_rejections() {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        let first = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:a",
            peer,
            t0,
            Some(1),
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(first.len(), 1, "first rejection reported");
        // Nothing else ever calls record_rejection again for this
        // category — the flood already stopped. The periodic tick must
        // still close the window on its own.
        let flushed =
            quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
        // No further rejections were suppressed, so there is nothing to
        // summarize — but the window itself must be closed (a second
        // flush at the same instant reports nothing new either).
        assert!(flushed.is_empty());
        // Directly on the window's own state, not merely inferred from
        // "nothing was reported": an empty `flushed` is also what a bug
        // that re-stamped `guard.start = Some(start)` instead of clearing
        // it to `None` would produce, since that bug leaves nothing new
        // to summarize either. `AuditWindow::is_open` reads `start`
        // itself, so it fails the way that bug should.
        assert!(
            !quotas.windows[QuotaKind::Sessions as usize].is_open(),
            "flush_expired must actually close the window (guard.start = \
             None), not just decline to report anything"
        );
        assert!(
            quotas
                .flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1))
                .is_empty()
        );

        // A rejection after the close starts a brand new window and is
        // reported immediately, proving the old one did not linger open.
        let reopened = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:b",
            peer,
            t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(2),
            Some(2),
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(
            reopened.len(),
            1,
            "closed window reopens on the next rejection"
        );
        assert_eq!(reopened[0].principal, "device:b");
        assert_eq!(reopened[0].count, None);
    }

    /// The quota module's twin of
    /// `crate::admission::tests::gate_record_rejection_and_flush_expired_
    /// both_reset_suppressed_not_just_report_it`, which `Quotas` never got
    /// when it copied `Gate::flush_expired`'s shape. `flush_expired` must
    /// *consume* the suppressed count it reports, not merely read it —
    /// otherwise the next rejection to reopen that category's window
    /// re-emits a phantom summary for suppressions that were already
    /// summarized one window ago.
    #[test]
    fn quota_flush_expired_resets_suppressed_not_just_reports_it() {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let sec = std::time::Duration::from_secs(1);

        assert_eq!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    "device:a",
                    peer,
                    t0,
                    Some(1),
                    qsh_transport::AuthPath::Ca
                )
                .len(),
            1
        );
        for n in 1..=2u64 {
            assert!(
                quotas
                    .record_rejection(
                        QuotaKind::Sessions,
                        "device:a",
                        peer,
                        t0 + sec * (n as u32),
                        Some(1),
                        qsh_transport::AuthPath::Ca,
                    )
                    .is_empty()
            );
        }

        let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].count, Some(2));

        // A later, isolated rejection opens a brand new window: it owes
        // exactly one fresh first line and nothing else. A second summary
        // here would be re-reporting the two suppressions the flush above
        // already accounted for.
        let later = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:b",
            peer,
            t0 + AUDIT_AGGREGATION_WINDOW + sec * 2,
            Some(7),
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(
            later.len(),
            1,
            "flush_expired must consume the suppressed count it reported — \
             got a phantom second summary: {later:?}"
        );
        assert_eq!(later[0].principal, "device:b");
        assert!(later[0].count.is_none());
    }

    /// Main-session arbitration round, item 4 (S1 deviation 2 overturned):
    /// the stale-reopen branch must return *both* the closing window's
    /// summary and the triggering rejection's own first line, mirroring
    /// `crate::admission::Gate::record_rejection` exactly — not the single
    /// `Option` the M8 Step 3a S1 stage had shipped, which could only ever
    /// return one of the two.
    #[test]
    fn quota_rejection_reopens_a_stale_window_with_both_its_summary_and_a_fresh_first_line() {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Three rejections in one window: one immediate first line, two
        // suppressed.
        let first = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:a",
            peer,
            t0,
            Some(1),
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(first.len(), 1);
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    "device:a",
                    peer,
                    t0 + std::time::Duration::from_secs(1),
                    Some(1),
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    "device:a",
                    peer,
                    t0 + std::time::Duration::from_secs(2),
                    Some(1),
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );

        // Advance past the window with nothing to close it (no
        // `flush_expired` tick), then one more rejection: this call alone
        // must close the stale window (summary, 2 suppressed) *and* report
        // its own fresh first line — never one at the other's expense.
        let stale_reopen = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:b",
            peer,
            t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1),
            Some(9),
            qsh_transport::AuthPath::Pin,
        );
        assert_eq!(
            stale_reopen.len(),
            2,
            "the closing summary and the reopening rejection's own line, \
             both — got {stale_reopen:?}"
        );
        assert_eq!(stale_reopen[0].principal, "-");
        assert_eq!(stale_reopen[0].count, Some(2));
        assert_eq!(stale_reopen[0].resource, QuotaKind::Sessions.category());
        assert_eq!(stale_reopen[1].principal, "device:b");
        assert_eq!(stale_reopen[1].count, None);
        assert_eq!(stale_reopen[1].request_id, "9");
        assert_eq!(stale_reopen[1].auth_path, "pin");

        // The window this rejection just opened is fresh — a flush at the
        // same instant reports nothing new for it.
        assert!(
            quotas
                .flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1))
                .is_empty()
        );
    }

    /// M8 Step 3b S1: `Quotas::windows` is sized `[AuditWindow;
    /// QuotaKind::ALL.len()]` and every `record_rejection`/`flush_expired`
    /// index into it is `kind as usize` — so `ALL`'s length (and, via the
    /// discriminant-order test above, its declaration order) is exactly
    /// what keeps the two in lockstep. This test pins the length half of
    /// that invariant directly, independent of the discriminant-order
    /// test, so a mutation that drops a variant from `ALL` without
    /// touching declaration order still gets caught.
    #[test]
    fn quota_kind_all_stays_in_lockstep_with_the_window_array() {
        let quotas = quotas_with(1);
        // `Quotas::windows` is declared `[AuditWindow; QuotaKind::ALL.len()]`
        // — its length can never mechanically diverge from `ALL.len()`, so
        // the invariant this test exists to pin is that *count* against a
        // literal (10, the full 3b vocabulary), not against `ALL.len()`
        // itself: comparing a derived quantity to the very expression it
        // was derived from can never fail no matter how many variants a
        // mutation drops from `ALL`.
        assert_eq!(
            quotas.windows.len(),
            10,
            "Quotas::windows must have exactly one slot per QuotaKind::ALL entry \
             (10 variants after M8 Step 3b S1)"
        );
        assert_eq!(
            QuotaKind::ALL.len(),
            10,
            "QuotaKind::ALL must list all 10 variants"
        );
        // Every kind must be reachable as a valid index — a variant added
        // to the enum but left out of ALL would panic here instead of
        // silently aliasing another kind's window.
        for &kind in QuotaKind::ALL {
            let _ = &quotas.windows[kind as usize];
        }
    }

    /// M8 Step 3b ruling R5: pins the full, exact vocabulary for every one
    /// of the 10 `QuotaKind` variants — `category()`, `action()`, and
    /// `wire_message()` — against the ruling's own table, so a variant
    /// added to the enum without a matching arm in one of these three
    /// functions (or a typo in the string a match arm returns) fails here
    /// instead of only being caught by a doc-contract test much later.
    #[test]
    fn every_quota_kind_maps_to_its_documented_category_action_and_wire_message() {
        let expected: &[(QuotaKind, &str, &str, &str)] = &[
            (
                QuotaKind::Sessions,
                "quota_sessions_host",
                "session.open",
                "session quota exceeded",
            ),
            (
                QuotaKind::SessionsPerPrincipal,
                "quota_sessions_principal",
                "session.open",
                "session quota exceeded",
            ),
            (
                QuotaKind::ExecPerPrincipal,
                "quota_exec_principal",
                "exec.run",
                "exec quota exceeded",
            ),
            (
                QuotaKind::ExecHost,
                "quota_exec_host",
                "exec.run",
                "exec quota exceeded",
            ),
            (
                QuotaKind::TunnelStreamsPerPrincipal,
                "quota_tunnels_principal",
                "forward.local",
                "tunnel quota exceeded",
            ),
            (
                QuotaKind::TunnelStreamsPerForward,
                "quota_tunnels_forward",
                "forward.local",
                "tunnel quota exceeded",
            ),
            (
                QuotaKind::RemoteForwardsPerPrincipal,
                "quota_remote_forwards_principal",
                "forward.remote",
                "remote forward quota exceeded",
            ),
            (
                QuotaKind::ConnectionsPerPrincipal,
                "quota_connections_principal",
                "connect",
                "connection quota exceeded",
            ),
            (
                QuotaKind::Connections,
                "quota_connections_host",
                "connect",
                "connection quota exceeded",
            ),
            (
                QuotaKind::PairingConnections,
                "quota_connections_pairing",
                "connect",
                "connection quota exceeded",
            ),
        ];
        assert_eq!(
            expected.len(),
            QuotaKind::ALL.len(),
            "this test's own table must cover every QuotaKind::ALL entry"
        );
        for &(kind, category, action, wire_message) in expected {
            assert_eq!(kind.category(), category, "kind {kind:?}: category");
            assert_eq!(kind.action(), action, "kind {kind:?}: action");
            assert_eq!(
                kind.wire_message(),
                wire_message,
                "kind {kind:?}: wire_message"
            );
        }
    }

    /// M8 Step 3b S1: `reserve_exec` checks the host-wide axis
    /// (`QuotaLimits::max_exec`, derived as `Σ exec_in_use.values()`)
    /// before the per-principal axis — a host at its host cap must refuse
    /// with `QuotaKind::ExecHost` even for a principal nowhere near its own
    /// per-principal cap, and must never touch that principal's map entry
    /// while refusing.
    #[test]
    fn exec_reservation_refuses_on_the_host_cap_before_the_principal_cap() {
        let quotas = Quotas::new(
            QuotaLimits {
                max_exec: 1,
                max_exec_per_principal: 100,
                ..QuotaLimits::default()
            },
            Arc::new(TestClock::new()),
        );
        // One reservation for device:a fills the host cap (1) while
        // leaving device:a's own per-principal cap (100) nowhere near
        // exhausted.
        let _first = quotas.reserve_exec("device:a").unwrap();

        // A second principal, entirely within its own per-principal
        // budget, must still be refused — and refused for the host reason,
        // not the (irrelevant, unreached) per-principal one.
        assert_eq!(
            quotas.reserve_exec("device:b").unwrap_err(),
            QuotaKind::ExecHost
        );
        // The refused principal must get no map entry at all (F9
        // discipline, extended to the host axis).
        assert_eq!(quotas.exec_in_use("device:b"), 0);

        // The same principal already holding the one live reservation is
        // refused too — the host cap binds everyone once it is full,
        // including the principal that filled it.
        assert_eq!(
            quotas.reserve_exec("device:a").unwrap_err(),
            QuotaKind::ExecHost
        );
    }

    /// M8 Step 3b S1: every new `[serve]` key degrades `0`/unset to its
    /// documented default, the same discipline every existing quota key
    /// already follows (`ServeConfig::max_exec_per_principal`, etc.) —
    /// exercised through `QuotaLimits::from_serve` end to end rather than
    /// each individual getter in isolation, so a mismatch between
    /// `QuotaLimits::from_serve`'s field wiring and the getters it calls
    /// is caught here too.
    #[test]
    fn an_unset_or_zero_quota_key_degrades_to_its_documented_default() {
        let unset = crate::config::ServeConfig::default();
        let limits = QuotaLimits::from_serve(&unset);
        assert_eq!(
            limits.max_exec,
            crate::config::ServeConfig::DEFAULT_MAX_EXEC
        );
        assert_eq!(
            limits.max_tunnel_streams_per_principal,
            crate::config::ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_PRINCIPAL
        );
        assert_eq!(
            limits.max_tunnel_streams_per_forward,
            crate::config::ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_FORWARD
        );
        assert_eq!(
            limits.max_remote_forwards_per_principal,
            crate::config::ServeConfig::DEFAULT_MAX_REMOTE_FORWARDS_PER_PRINCIPAL
        );
        assert_eq!(
            limits.max_connections_per_principal,
            crate::config::ServeConfig::DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL
        );
        assert_eq!(
            limits.max_connections,
            crate::config::ServeConfig::DEFAULT_MAX_CONNECTIONS
        );

        // Explicit `0` degrades exactly the same way as unset.
        let zeroed = crate::config::ServeConfig {
            max_exec: Some(0),
            max_tunnel_streams_per_principal: Some(0),
            max_tunnel_streams_per_forward: Some(0),
            max_remote_forwards_per_principal: Some(0),
            max_connections_per_principal: Some(0),
            max_connections: Some(0),
            ..crate::config::ServeConfig::default()
        };
        let zeroed_limits = QuotaLimits::from_serve(&zeroed);
        assert_eq!(zeroed_limits.max_exec, limits.max_exec);
        assert_eq!(
            zeroed_limits.max_tunnel_streams_per_principal,
            limits.max_tunnel_streams_per_principal
        );
        assert_eq!(
            zeroed_limits.max_tunnel_streams_per_forward,
            limits.max_tunnel_streams_per_forward
        );
        assert_eq!(
            zeroed_limits.max_remote_forwards_per_principal,
            limits.max_remote_forwards_per_principal
        );
        assert_eq!(
            zeroed_limits.max_connections_per_principal,
            limits.max_connections_per_principal
        );
        assert_eq!(zeroed_limits.max_connections, limits.max_connections);
    }
}
