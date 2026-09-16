//! Host side of the protocol: accept loop, per-connection `Hello`
//! negotiation, control-message [`dispatch`](Server::dispatch), and data
//! stream admission by ticket.
//!
//! `dispatch` is the **single ACL choke point** (`docs/design/architecture.md`
//! §6): every request is decided by [`Authorizer::check`] and audited
//! *before* a ticket is issued or a session is created, and an exec child
//! is only spawned when a data stream redeems a valid ticket. `dispatch`
//! itself is pure with respect to transport — it takes a decoded
//! [`ControlMessage`] plus a [`ConnCtx`] and returns the response message —
//! so the broker (through the transport-free [`SessionBackend`] seam,
//! ADR-0003) and the P1 supervisor sit on the same seam without touching
//! quinn types.
//!
//! **Sync vs. async (M2 Step 3).** `dispatch` is `async` because the
//! session ops it now routes are: `SessionRead` long-polls the broker's
//! cursor-pull primitive for up to `wait_ms`, `SessionClose` awaits the
//! signal escalation, and `SessionWrite` awaits the actual write. The
//! choke point discipline is unchanged — every handler runs the ACL check
//! and the audit record synchronously, before its first `.await` and
//! before any resource exists. The connection driver spawns one bounded
//! task per control message so a long-poll never blocks pings, other
//! requests or data-stream admission on the same connection.
//!
//! Connection direction (initiator/responder) and QSH role (who serves the
//! request) are separate axes (`docs/ROADMAP.md` principle 7c): this module
//! is "the side that answers requests", regardless of who dialed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use qsh_proto::ErrorCode;
use qsh_proto::wire::{
    self, ControlMessage, ExecStart, ExecStarted, Hello, StreamHeader, StreamKind, control_message,
    response, session_read_event,
};
use qsh_transport::endpoint::CLOSE_CODE_PROTOCOL;
use qsh_transport::{AuthPath, Connection, FramedStream, Incoming, Listener, Principal};
use rand::RngCore;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::acl::{Action, Authorizer, Decision, ResourceRef, opener_key};
use crate::audit::{AuditRecord, AuditSink};
use crate::broker::{
    BrokerError, CloseReason, ConnectionId, ControlEvent, Cursor, FIRST_INPUT_STREAM,
    InputStreamId, PeerFingerprint, ReplayEvent, ResumeDenied, SessionBackend, SessionId,
    SessionSpec, Signal, TakeOutcome,
};
use crate::exec::{ExecSpec, run_exec};
use crate::session_stream::SessionStream;
use crate::tunnel::dial::{SystemDialer, TunnelDialer};
use crate::tunnel::remote::{BindHostResolver, RemoteForwardBinder, SystemBinder, SystemResolver};
use crate::tunnel::splice::splice_tcp_quic;

/// How long a peer has to send its `Hello` (and open the control stream).
/// Single definition now lives in [`crate::handshake`]; re-exported here so
/// this path stays stable.
pub use crate::handshake::HELLO_TIMEOUT;
/// How long a data stream has to send its `StreamHeader`.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Ticket lifetime (`docs/design/protocol.md` §7).
pub const TICKET_TTL: Duration = Duration::from_secs(30);
/// Ticket size in bytes (128-bit random).
pub const TICKET_LEN: usize = 16;

/// Upper bound on [`Server::drain`]'s wait for every session to close.
///
/// The ordinary case is already bounded without this: sessions close
/// concurrently ([`crate::broker::Broker::close_all`]), so the wall-clock
/// cost of draining any number of them is one session's own close
/// escalation — up to three `[serve].close_grace_ms` periods (CLI.md §6.7),
/// 15 s at the documented default. This is *defense in depth* for the case
/// a session's close never returns at all (a wedged PTY reap, a stuck
/// actor) — past it, `drain` stops waiting so the process can still exit,
/// rather than hang the SIGTERM shutdown forever on one session. Four times
/// the default per-session bound: generous enough not to cut a legitimate
/// escalation short under scheduler contention, finite so "drain never
/// returns" cannot happen.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Grace period [`Server::drain`] waits, after every session has closed,
/// before returning to a caller that is about to force-close the
/// connection/listener out from under whatever is still in flight.
///
/// `drain` only guarantees the broker's replay ring carries
/// `session.closed` (`Broker::close_all`'s own return) — *delivering* that
/// entry to an attached consumer is a second, decoupled hop:
/// `session_stream.rs`'s `output_pump` has to wake on the ring, `notify()`
/// it onto this connection's control-stream reply queue, and
/// `Server::serve_control`'s loop has to actually write it to the wire.
/// None of that is awaited by `drain` itself, so a caller that closes the
/// connection the instant `drain` returns (`Server::run`, `reverse::target`)
/// can — and, absent this, empirically does — win that race: the peer sees
/// the connection die instead of the `session.closed` it was owed (an L5
/// real-process test, not a unit test, is what catches this — the in-crate
/// unit tests below call `drain` against the broker directly and never
/// exercise the wire hop at all). Same shape of problem as
/// [`crate::handshake::REJECTION_DRAIN_TIMEOUT`] (let one last queued frame
/// actually leave before the stream goes away), same order of magnitude:
/// generous for one small in-process handoff plus one local write, not a
/// promise against a peer or path that is genuinely gone.
pub const DRAIN_FLUSH_GRACE: Duration = Duration::from_millis(500);

/// Stream reset code: the `StreamHeader` was missing, unknown, or its
/// ticket was invalid/expired/foreign/of the wrong kind.
pub const RESET_CODE_BAD_HEADER: u32 = 0x2001;

/// Stream reset code: the header and ticket were valid but this build does
/// not pump that stream kind yet. The ticket is consumed either way.
pub const RESET_CODE_NOT_IMPLEMENTED: u32 = 0x2002;

/// Stream reset code: the ticket was valid but the ACL denied the action
/// the stream performs. A stream has no control-stream reply to carry a
/// `PERMISSION_DENIED` envelope, so the refusal is the reset itself — and
/// like every denial it is non-distinguishing.
pub const RESET_CODE_FORBIDDEN: u32 = 0x2003;

/// Stream reset code: the attach asked for `no_steal` and another
/// principal holds the session's writer lease (protocol.md §10). Distinct
/// from [`RESET_CODE_FORBIDDEN`] so a client can tell "not allowed" from
/// "someone else is driving".
pub const RESET_CODE_SESSION_CONFLICT: u32 = 0x2004;

/// Stream reset code: the ticket/ACL/shape checks all passed but a
/// resource quota was already at its cap (M8 Step 3b,
/// `crate::quota::Quotas::reserve_tunnel_stream`). Distinct from every
/// other reset code here because — unlike `FORBIDDEN` — the resource
/// comes back once something else releases: a client that reads this
/// code alone (with no `ConnectResult` frame reachable, e.g. before the
/// framed reply lands) still learns "retry", not "never".
pub const RESET_CODE_RESOURCE_EXHAUSTED: u32 = 0x200D;

/// Connection close code: the accept-arm's connection-count quota (M8
/// Step 3b, `[serve].max_connections`/`max_connections_per_principal`, or
/// the fixed pairing cap) was already at its cap when this connection
/// reached the front of `Server::serve_connection` — used only for the
/// pre-identity (`Principal::Pairing`) refusal (ruling R2), which closes
/// the connection outright rather than writing a `ConnectResult`/`Error`
/// frame (a pairing connection's own non-distinguishing discipline,
/// `docs/design/protocol.md` §10-2/§15.5, applies to capacity the same
/// way it applies to a missing invite). A regular (non-pairing) refusal
/// instead reaches the peer as a normal `RESOURCE_EXHAUSTED` error frame
/// through `handshake::respond` (ruling R3) — this code exists for the
/// one path that never gets that far. Next free value after
/// `qsh_transport::endpoint::CLOSE_CODE_PROTOCOL` (`0x1002`); lives here,
/// not in `qsh-transport`, because it is only ever an opaque argument to
/// `Connection::close` — zero transport-crate change.
pub const CLOSE_CODE_RESOURCE_EXHAUSTED: u32 = 0x1003;

/// Maximum number of unredeemed tickets one connection may hold. Bounds
/// the memory a (pinned) peer can pin down by issuing requests it never
/// follows up on; further ticket-issuing requests get `RESOURCE_EXHAUSTED`
/// until tickets are redeemed or expire.
pub const MAX_PENDING_TICKETS_PER_CONN: usize = 32;

/// Maximum number of blocking control requests (`SessionRead` long-poll,
/// `SessionClose` mid-escalation) one connection may have in flight
/// (dispatched but not yet answered). Those are the only control messages
/// that run concurrently with the control stream (a read can park for up
/// to [`SESSION_READ_MAX_WAIT`]); every other message is handled inline,
/// in arrival order. Beyond this the request is answered
/// `RESOURCE_EXHAUSTED` (retryable) without being dispatched.
pub const MAX_INFLIGHT_REQUESTS_PER_CONN: usize = 64;

/// Upper bound the host applies to `SessionRead.wait_ms` (JSON `--wait`):
/// a longer wait is clamped, never rejected — the sibling of
/// `SESSION_READ_MAX_BYTES` (protocol.md §9). Bounds how long one parked
/// long-poll can hold its in-flight slot; a client wanting a longer wait
/// re-issues the read with the same cursor (`after` + `ctl_after`).
pub const SESSION_READ_MAX_WAIT: Duration = Duration::from_secs(60);

/// Upper bound on a `session_id` a peer may name in a request. Host-issued
/// ids are 26-char ULIDs; anything longer is not one of ours and is
/// rejected as `INVALID_ARGUMENT` before it becomes an ACL resource / audit
/// field. Existence-independent, so non-distinguishing (protocol.md §10).
pub const SESSION_ID_MAX_LEN: usize = 64;

/// The ACL `resource` string for requests that do not target an existing
/// session (`session.open`, `session.list`).
pub const SESSION_RESOURCE: &str = "session";

/// Per-connection context handed to `dispatch`. Contains everything a
/// decision needs and nothing transport-specific.
#[derive(Debug, Clone)]
pub struct ConnCtx {
    /// Authenticated peer principal (from the certificate — the ACL input).
    pub principal: Principal,
    /// How the peer authenticated (pin vs. CA) — the other ACL input.
    pub auth_path: AuthPath,
    /// SPKI SHA-256 of the peer's verified leaf certificate. **Not** an ACL
    /// input (that is `principal`): this is the identity a resume
    /// credential is bound to (protocol.md §10, PRD §9), so a token stolen
    /// off one device cannot be redeemed from another. `None` means the
    /// leaf did not re-parse, which fails resume closed.
    pub peer_fingerprint: Option<PeerFingerprint>,
    /// Peer address at connection time (audit only).
    pub peer_addr: SocketAddr,
    /// Connection identity used to bind tickets to the connection that
    /// earned them and to hold writer leases.
    pub conn_id: usize,
    /// Capabilities negotiated in `Hello` (intersection).
    pub capabilities: Vec<String>,
    /// Whether this connection is a `qsh reverse` target's own long-lived
    /// registration to a `qsh listen` daemon (`reverse/target.rs`'s own
    /// `ConnCtx` construction — the only site that sets this `true`) —
    /// **not** merely "the connection identifies as reverse" (`qsh
    /// serve`/`ReversePairHarness` never do; `Hello.reverse` is refused
    /// outright at `serve_connection_inner`).
    ///
    /// The one thing this decides: whether a `SESSION_DATA` stream's
    /// writer-lease identity (`attach_lease_owner`, `handle_data_stream`)
    /// is derived from the redeemed ticket instead of `connection_id()`.
    /// A real registration is genuinely shared — every local CLI process a
    /// `qsh listen` daemon relays for opens its own `SESSION_DATA` stream
    /// on this *one* physical connection, so `connection_id()` alone
    /// cannot tell two concurrent attaches apart
    /// (`WriterLease::take_owned`'s own doc). Every other connection this
    /// crate ever builds a `ConnCtx` for — a forward `qsh serve` client,
    /// or a test harness that reaches this dispatch loop by a different
    /// route (`qsh-testkit`'s `LoopbackHarness`/`ReversePairHarness`,
    /// which dial a *fresh* connection per logical session on purpose,
    /// `ReversePairHarness`'s own module doc) — is one physical connection
    /// per attach, so `connection_id()` is already a correct, stable
    /// per-attach identity there; diverging from it for those would only
    /// desynchronize an attach's own `SessionStream` from a `session
    /// write`/`session resize` value op issued on that *same* connection
    /// (both derive their lease identity independently, and only
    /// `connection_id()` is guaranteed to agree on both sides of that
    /// split) — exactly the regression a blanket ticket-derived identity
    /// caused before this field existed (adversarial review fixer
    /// finding: `a_stolen_lease_demotes_the_attach_to_read_only_and_a_steal_back_resumes_it`
    /// hung on both the forward *and* reverse variant, since neither
    /// route's harness actually multiplexes a connection — the bug was
    /// never reverse-specific, it just happened to be introduced while
    /// fixing a reverse-specific one).
    pub is_reverse_registration: bool,
}

impl ConnCtx {
    fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }

    /// The broker-side identity of this connection (`ConnectionId` is a
    /// plain `u64` so the broker never names a transport type).
    fn connection_id(&self) -> ConnectionId {
        ConnectionId(self.conn_id as u64)
    }
}

/// An authorized exec waiting for its data stream.
///
/// Not [`Clone`] (as of `PLAN.md` M8 Step 3): [`Self::permit`] is an RAII
/// reservation ([`crate::quota::ExecPermit`]), and nothing in this crate
/// ever actually clones a [`Ticket`]/[`TicketPurpose`]/`PendingExec`
/// (confirmed by grep before dropping the derive) — cloning one would
/// double-count the reservation it represents.
#[derive(Debug)]
pub struct PendingExec {
    /// Opaque exec identifier (ULID).
    pub exec_id: String,
    /// What to run once the stream arrives.
    pub spec: ExecSpec,
    /// The `exec.run` concurrency slot this ticket holds
    /// (`[serve].max_exec_per_principal`, verdict arbitration item 5).
    /// Reserved in `Server::handle_exec_start` before the ticket is
    /// issued; released by `Drop` whenever this value's last owner goes
    /// away — the ticket map's lazy/periodic/`purge_connection` expiry
    /// sweeps (`Server::issue_ticket`, `Server::pending_tickets_for`,
    /// [`Server::purge_connection`]) all drop it the same way an
    /// unredeemed ticket is dropped, and a *redeemed* ticket's
    /// [`TicketPurpose::Exec`] moves it into the data-stream task that
    /// runs the child, so it releases when that task's `run_exec(..)` call
    /// returns — child exit or spawn failure alike, since
    /// [`crate::exec::run_exec`] reports a spawn failure as an `Ok`
    /// outcome (shell-convention exit code) rather than an early `Err`
    /// that would skip straight past the drop.
    pub permit: crate::quota::ExecPermit,
}

/// An authorized `session.write` whose bytes have not reached the child
/// yet: the ACL decision, the audit record and the writer lease are already
/// done, only the parking half is left.
#[derive(Debug)]
pub struct PendingWrite {
    request_id: u64,
    id: SessionId,
    conn: ConnectionId,
    data: Vec<u8>,
}

/// What a ticket authorizes once a data stream redeems it.
///
/// Not [`Clone`] — see [`PendingExec`]'s own doc.
#[derive(Debug)]
pub enum TicketPurpose {
    /// An `EXEC_DATA` stream for this exec.
    Exec(PendingExec),
    /// A `SESSION_DATA` stream attached to this session.
    Session {
        /// The session the stream attaches to.
        session_id: SessionId,
        /// Cumulative output offset the stream replays from — the
        /// `replay_from` already promised in the reply, so the ticket, not
        /// the peer, decides where the pump starts.
        replay_from: u64,
        /// Whether the attach refuses to steal a live foreign lease
        /// (protocol.md §10). Carried on the ticket, not re-asked of the
        /// peer, so redeeming cannot quietly upgrade a careful attach into
        /// a stealing one.
        no_steal: bool,
        /// Whether `session.attach` was already decided and audited for
        /// this session (a ticket minted by `session.attach`). A ticket
        /// minted by `session.open` carries `false`: opening its data
        /// stream *is* an attach, so the ACL choke point runs at
        /// redemption instead.
        attach_authorized: bool,
        /// The logical input stream this attach continues. A **resumed**
        /// attach keeps the session's current id, so the session's dedup
        /// cursor still covers its retransmissions; every other attach
        /// carries a fresh one (protocol.md §10-5).
        input_stream: InputStreamId,
        /// Cumulative input offset already promised to the peer in
        /// `SessionAttached.input_seq`.
        input_from: u64,
    },
}

impl TicketPurpose {
    /// The stream kind that may redeem this ticket.
    fn stream_kind(&self) -> StreamKind {
        match self {
            TicketPurpose::Exec(_) => StreamKind::ExecData,
            TicketPurpose::Session { .. } => StreamKind::SessionData,
        }
    }
}

/// An issued, unredeemed ticket.
///
/// Not [`Clone`] — see [`PendingExec`]'s own doc.
#[derive(Debug)]
pub struct Ticket {
    /// What redeeming it authorizes.
    pub purpose: TicketPurpose,
    /// Connection the ticket was issued to.
    pub conn_id: usize,
    /// When the ticket stops being redeemable.
    pub expires_at: Instant,
}

/// Errors from the accept loop.
#[derive(Debug, Error)]
pub enum ServerError {
    /// The listener could not be built.
    #[error(transparent)]
    Setup(#[from] qsh_transport::SetupError),
}

/// One live remote-forward listener, everything [`Server::handle_rfwd_close`]
/// and [`Server::purge_connection`] need about it (`PLAN.md` M5 Step 5 (a)
/// restructured this from a `conn_id`-first nested map — see
/// [`Server::remote_forwards`]'s own doc for why).
struct RemoteForwardEntry {
    /// The connection that opened this forward — [`Server::
    /// purge_connection`]'s own axis, orthogonal to `owner` (a connection
    /// dying tears down every forward *it* opened, regardless of who else
    /// might share that principal).
    conn_id: usize,
    /// The opening principal's [`opener_key`] — the ACL ownership axis
    /// [`Server::handle_rfwd_close`] checks. Principal-based, not
    /// `conn_id`-based (`PLAN.md` M5 Step 5 §4.2, `docs/CLI.md` §2.5's
    /// "소유 peer" wording taken literally) — but *not* because a forward
    /// outlives its opening connection: it does not. [`Server::
    /// purge_connection`] tears down every forward its `conn_id` (above)
    /// opened the moment that connection dies, so "the same principal
    /// reconnects after a resume" is not a scenario `RemoteForwardClose`
    /// can ever actually reach (F7, M5 Step 5 adversarial review). The
    /// operative benefit is the *concurrent* case instead: the same
    /// principal holding a **second, still-live** connection — a fresh
    /// `qsh` invocation, a second terminal, anything else authenticating as
    /// the same device while the first connection is untouched — can close
    /// a forward it opened on the first, which is exactly what
    /// `remote_forward_close_allows_the_same_principal_from_a_different_connection`
    /// (`crates/qsh-testkit/tests/tunnel_remote_loopback.rs`) drives and
    /// proves. Keying on principal instead of `conn_id` also keeps this
    /// axis the same vocabulary `session.control`'s ownership gate uses —
    /// `opener_key` is shared, not reimplemented — so the win here is
    /// consistency with that gate, not surviving a connection's death.
    owner: String,
    /// The accept loop's own task handle
    /// ([`crate::tunnel::remote::serve_remote_forward`]); aborting it drops
    /// the [`tokio::net::TcpListener`] it owns, which is the whole
    /// teardown — nothing else to release, the same shape as
    /// [`crate::tunnel::local::LocalForwardHandle`]'s `Drop`.
    task: tokio::task::JoinHandle<()>,
    /// This listener's `[serve].max_remote_forwards_per_principal`
    /// reservation (M8 Step 3b, [`crate::quota::Quotas::
    /// reserve_remote_forward`]) — held for the entry's whole lifetime and
    /// never read, only kept alive so its `Drop` runs exactly when the
    /// entry itself is removed. Both removal sites
    /// ([`Server::handle_rfwd_close`], [`Server::purge_connection`]) take
    /// this `RemoteForwardEntry` out of [`Server::remote_forwards`] by
    /// value, so the permit releases automatically with no manual
    /// decrement at either site — same "let the map remove do the
    /// releasing" shape a `Ticket`'s `ExecPermit` already relies on.
    _quota: crate::quota::RemoteForwardPermit,
}

/// One accept-loop heartbeat tick's worth of counter snapshots (M8 Step
/// 5a) — `PartialEq` so [`Server::log_accept_heartbeat`] can tell "nothing
/// moved since the last logged tick" without comparing each field by
/// hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AcceptHeartbeat {
    admitted: u64,
    retry: u64,
    ignore: u64,
    refuse: u64,
    /// Renamed from `quota_refused` — this is only ever
    /// the two connection-*reservation* counters
    /// (`Quotas::reserve_connection`/`reserve_pairing_connection`), never
    /// the other eight [`crate::quota::QuotaKind`] axes. `quota_rejections`
    /// below (`crate::quota::QuotaCounters::rejections_total`) is the
    /// field that actually covers every axis.
    connection_quota_refused: u64,
    live_conns: u64,
    pending_tickets: u64,
    /// Sum of every [`crate::quota::QuotaKind`] axis's
    /// [`crate::quota::Quotas::record_rejection`] tally
    /// (`crate::quota::QuotaCounters::rejections_total`) — the field a
    /// soak should actually read to see "is the host shedding load
    /// anywhere?", since `connection_quota_refused` above only covers the
    /// connection-reservation axes.
    quota_rejections: u64,
}

/// The host: policy + audit + ticket registry + session backend. Shared
/// across connections.
pub struct Server {
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<dyn AuditSink>,
    sessions: Arc<dyn SessionBackend>,
    device_name: String,
    tickets: Mutex<HashMap<[u8; TICKET_LEN], Ticket>>,
    /// Live remote-forward listeners, keyed by `forward_id` — flat, not
    /// nested under the owning connection's `conn_id`, since `PLAN.md` M5
    /// Step 5 made forward ownership principal-based rather than
    /// connection-based (`RemoteForwardEntry::owner`'s own doc): a
    /// `conn_id`-first map could only ever express "this connection's own
    /// forwards", which is too narrow an ownership axis once the same
    /// principal reconnecting on a fresh connection must still be able to
    /// close what it opened. [`Server::handle_rfwd_close`] looks a
    /// `forward_id` up here, checks `Action::ForwardRemote` +
    /// `RemoteForwardEntry::owner` through the ordinary `scope = "owned"`
    /// choke point (`Server::authorize_owned`), and only then removes it;
    /// [`Server::purge_connection`] instead filters by
    /// `RemoteForwardEntry::conn_id`, its own, connection-bound axis
    /// (`PLAN.md` M4 Step 4's "`RemoteForwardClose{forward_id}` 또는 연결
    /// 종료 시 리스너를 닫는다").
    remote_forwards: Mutex<HashMap<String, RemoteForwardEntry>>,
    /// Set once by [`Server::drain`] (SIGTERM, `docs/CLI.md` §6.12,
    /// ADR-0003). Checked at the top of `session.open`/`session.attach`,
    /// before any other gate — draining is a hard stop this host applies to
    /// every connection it still holds, not a per-request policy decision.
    draining: AtomicBool,
    /// This host's own trust store and its open pairing invites (ADR-0002,
    /// M7 Step 4), set together, once, after construction by
    /// [`Server::set_pairing`] — `Server::new`'s existing call sites (12 of
    /// them, across `qsh-core`) must not change shape, so this follows the
    /// same `OnceLock`-after-construction pattern as
    /// `trust::SharedTrustStore::attach_pairing`. `None` (never attached —
    /// every non-`qsh serve` caller, e.g. `qsh-testkit`'s pair harnesses)
    /// means [`Server::serve_pairing_connection`] is simply never reached:
    /// a connection only carries `Principal::Pairing` at all when *some*
    /// evaluator's `pairing_open()` answered `true`, and nothing answers
    /// `true` without an attached invite store on the trust-evaluator side
    /// too.
    pairing: OnceLock<PairingState>,
    /// L2-L3 of the L0-L5 admission ordering (`PLAN.md` M8 Step 2,
    /// `docs/adr/0009-admission-defenses.md`) — consulted by [`Self::run`]
    /// before an `Incoming` ever reaches [`Self::accept_and_serve`].
    /// Defaulted to `crate::config::ServeConfig`'s own defaults by
    /// [`Server::new`]; production (`crate::serve::run_serve`) instead
    /// builds one from the operator's actual config via
    /// [`Server::with_admission`].
    admission: crate::admission::Gate,
    /// Post-authorization resource quotas (`PLAN.md` M8 Step 3, `docs/adr/
    /// 0010-resource-quotas.md`) — the `exec.run` concurrency reservation
    /// ([`Self::handle_exec_start`]) plus the shared audit-aggregation
    /// windows for every [`crate::quota::QuotaKind`], including the
    /// session-count axes `crate::broker::Broker` enforces from its own
    /// registry ([`Self::handle_session_open`] turns a returned
    /// `BrokerError::QuotaExceeded` into the audited rejection here, since
    /// the broker itself never touches an [`AuditSink`]). Defaulted by
    /// [`Server::new`]/[`Server::with_admission`]; production
    /// (`crate::serve::host_runtime`) instead builds one from the
    /// operator's actual `[serve]` limits via
    /// [`Server::with_admission_and_quotas`].
    quotas: Arc<crate::quota::Quotas>,
}

/// [`Server`]'s own write access to the trust store (to pin a
/// successfully-paired peer) plus the invite store (to redeem a proof) —
/// bundled so [`Server::set_pairing`] wires both atomically, since a
/// running daemon that had one without the other could reach
/// `Principal::Pairing` (via the trust store's `pairing_open()`) with no
/// way to actually complete the exchange, or vice versa.
struct PairingState {
    trust: Arc<crate::trust::SharedTrustStore>,
    invites: Arc<crate::trust::SharedInviteStore>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

/// [`Server::lock_tickets`]'s return type — a `self.tickets.lock()`
/// `MutexGuard`, plus (under `#[cfg(test)]`) a
/// [`crate::quota::lock_order::NonLeafGuard`] marking this thread as
/// inside a non-leaf lock scope for as long as the guard lives. Field
/// order is deliberate: the `MutexGuard` drops first, the `NonLeafGuard`
/// second — see `lock_tickets`'s own doc.
struct TicketsGuard<'a> {
    guard: MutexGuard<'a, HashMap<[u8; TICKET_LEN], Ticket>>,
    #[cfg(test)]
    _non_leaf: crate::quota::lock_order::NonLeafGuard,
}

impl std::ops::Deref for TicketsGuard<'_> {
    type Target = HashMap<[u8; TICKET_LEN], Ticket>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl std::ops::DerefMut for TicketsGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

/// [`Server::lock_remote_forwards`]'s return type — same shape as
/// [`TicketsGuard`], for the same reason (M8 Step 3b ruling A4):
/// [`Server::remote_forwards`] is the second lock `purge_connection`'s
/// "collect under the guard, drop outside" discipline applies to (a
/// removed [`RemoteForwardEntry`] carries a task handle, not a quota
/// permit, today — but nothing stops a future edit from adding one, and
/// this tripwire exists precisely so that edit cannot silently violate
/// ADR-0010 §9). Field order matters here too: the `MutexGuard` drops
/// first, the `NonLeafGuard` second.
struct RemoteForwardsGuard<'a> {
    guard: MutexGuard<'a, HashMap<String, RemoteForwardEntry>>,
    #[cfg(test)]
    _non_leaf: crate::quota::lock_order::NonLeafGuard,
}

impl std::ops::Deref for RemoteForwardsGuard<'_> {
    type Target = HashMap<String, RemoteForwardEntry>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl std::ops::DerefMut for RemoteForwardsGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Server {
    /// Build a server with the given policy, audit sink and session
    /// backend.
    pub fn new(
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        sessions: Arc<dyn SessionBackend>,
        device_name: impl Into<String>,
    ) -> Arc<Self> {
        let admission = crate::admission::Gate::new(
            Arc::new(crate::broker::SystemClock),
            crate::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
            crate::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
            crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
        );
        Self::with_admission(authorizer, audit, sessions, device_name, admission)
    }

    /// [`Server::new`] plus an explicit [`crate::admission::Gate`] —
    /// `crate::serve::run_serve` uses this to build the gate from the
    /// operator's actual `[serve].max_concurrent_handshakes`/
    /// `handshake_rate_per_source` (`PLAN.md` M8 Step 2) instead of the
    /// hardcoded defaults `Server::new` uses. A separate constructor
    /// rather than a config-file parameter on `Server::new` itself: every
    /// other call site (a dozen across `qsh-core`/`qsh-testkit`) has no
    /// need for anything but the defaults, and adding an eleventh
    /// positional parameter to `new` would just move the same `Arc::new(
    /// SystemClock)`/`ServeConfig::DEFAULT_*` boilerplate into all of
    /// them instead of the one production call site that actually varies
    /// it.
    pub fn with_admission(
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        sessions: Arc<dyn SessionBackend>,
        device_name: impl Into<String>,
        admission: crate::admission::Gate,
    ) -> Arc<Self> {
        let quotas = crate::quota::Quotas::new(
            crate::quota::QuotaLimits::default(),
            Arc::new(crate::broker::SystemClock),
        );
        Self::with_admission_and_quotas(authorizer, audit, sessions, device_name, admission, quotas)
    }

    /// [`Server::with_admission`] plus explicit [`crate::quota::Quotas`] —
    /// `crate::serve::host_runtime` uses this to build the quota tracker
    /// from the operator's actual `[serve].max_sessions`/
    /// `max_sessions_per_principal`/`max_exec_per_principal` (`PLAN.md` M8
    /// Step 3) instead of [`crate::quota::QuotaLimits::default`]. A
    /// separate constructor for the same reason [`Server::with_admission`]
    /// itself is one and not a parameter on [`Server::new`]: every other
    /// call site has no need for anything but the default limits.
    pub fn with_admission_and_quotas(
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        sessions: Arc<dyn SessionBackend>,
        device_name: impl Into<String>,
        admission: crate::admission::Gate,
        quotas: Arc<crate::quota::Quotas>,
    ) -> Arc<Self> {
        Arc::new(Self {
            authorizer,
            audit,
            sessions,
            device_name: device_name.into(),
            tickets: Mutex::new(HashMap::new()),
            remote_forwards: Mutex::new(HashMap::new()),
            draining: AtomicBool::new(false),
            pairing: OnceLock::new(),
            admission,
            quotas,
        })
    }

    /// Wire this host's trust store and invite store together so `qsh
    /// serve`'s connection driver can answer a `Principal::Pairing`
    /// connection (`Self::serve_pairing_connection`): verify the
    /// initiator's proof against `invites`, and — only once that succeeds —
    /// pin the peer into `trust`. No-op past the first call —
    /// `crate::serve`'s startup path calls this exactly once, immediately
    /// after [`Server::new`], with the *same* `Arc`s the transport layer's
    /// own `TrustEvaluator` was built from (single source of truth for
    /// `trust.toml`).
    pub fn set_pairing(
        &self,
        trust: Arc<crate::trust::SharedTrustStore>,
        invites: Arc<crate::trust::SharedInviteStore>,
    ) {
        let _ = self.pairing.set(PairingState { trust, invites });
    }

    /// The `Hello` this host sends. `reverse` is `Some` only when this
    /// `Hello` is a reverse target's self-registration on an initiator+host
    /// connection (M3 Step 3's `qsh reverse` fills this in via
    /// [`crate::handshake::initiate`]; every call site through this step
    /// passes `None`).
    pub fn local_hello(&self, reverse: Option<wire::ReverseRegistration>) -> Hello {
        Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: self.device_name.clone(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            reverse,
        }
    }

    /// The session backend this host serves from.
    pub fn sessions(&self) -> &Arc<dyn SessionBackend> {
        &self.sessions
    }

    /// The one choke point for every `self.tickets.lock()` acquisition
    /// (M8 Step 3a fix-3 sweep, B4): `TicketsGuard`'s field order —
    /// `MutexGuard` first, [`crate::quota::lock_order::NonLeafGuard`]
    /// second, `#[cfg(test)]` only — is how `docs/adr/0010-resource-
    /// quotas.md` §9's "collect under the guard, drop outside" rule is
    /// enforced mechanically in tests: Rust drops a struct's fields in
    /// declaration order, so the mutex releases first and the depth
    /// tracked for [`crate::quota::ExecPermit`]'s own `Drop` to check is
    /// only decremented after that — an `ExecPermit` dropped while any
    /// copy of this guard is still alive on this thread is exactly the
    /// ordering violation the rule forbids.
    fn lock_tickets(&self) -> TicketsGuard<'_> {
        TicketsGuard {
            guard: self.tickets.lock().unwrap_or_else(|e| e.into_inner()),
            #[cfg(test)]
            _non_leaf: crate::quota::lock_order::NonLeafGuard::new(),
        }
    }

    /// The choke point for `self.remote_forwards.lock()` in
    /// [`Self::purge_connection`] (M8 Step 3b ruling A4) — same shape and
    /// same reasoning as [`Self::lock_tickets`] above, extended to this
    /// crate's second non-leaf lock.
    fn lock_remote_forwards(&self) -> RemoteForwardsGuard<'_> {
        RemoteForwardsGuard {
            guard: self
                .remote_forwards
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            #[cfg(test)]
            _non_leaf: crate::quota::lock_order::NonLeafGuard::new(),
        }
    }

    /// Number of tickets currently outstanding (tests/diagnostics). Does
    /// **not** purge expired entries — [`Self::pending_unexpired_tickets`]
    /// is the purging twin the accept-loop heartbeat uses; this one stays
    /// as-is because a handful of existing tests depend on its
    /// non-purging count.
    pub fn pending_tickets(&self) -> usize {
        self.lock_tickets().len()
    }

    /// Number of *unexpired* tickets currently outstanding — the
    /// heartbeat's own read, unlike [`Self::pending_tickets`]:
    /// expiry there is lazy (only swept when some connection next calls
    /// `Self::pending_tickets_for`), so a quiet-period backlog of
    /// expired-but-unswept tickets would otherwise make
    /// [`Self::pending_tickets`] read non-zero on a fully idle listener —
    /// a genuine leak and an idle backlog would look identical. Same
    /// "collect under the guard, drop outside" discipline as
    /// `Self::pending_tickets_for`: the expired [`Ticket`]s (and any
    /// [`crate::quota::ExecPermit`] each carries) are dropped only after
    /// the tickets lock is released.
    pub fn pending_unexpired_tickets(&self) -> usize {
        let mut tickets = self.lock_tickets();
        let now = Instant::now();
        let expired = extract_tickets(&mut tickets, |p| p.expires_at > now);
        let count = tickets.len();
        drop(tickets);
        drop(expired);
        count
    }

    /// Number of unexpired tickets outstanding for `conn_id`. Expired
    /// entries are dropped on the way so a stale backlog never counts.
    fn pending_tickets_for(&self, conn_id: usize) -> usize {
        let mut tickets = self.lock_tickets();
        let now = Instant::now();
        let expired = extract_tickets(&mut tickets, |p| p.expires_at > now);
        let count = tickets.values().filter(|p| p.conn_id == conn_id).count();
        drop(tickets);
        // `expired`'s removed `Ticket`s (and any `ExecPermit`s inside)
        // drop here, after the tickets lock above has already been
        // released (main-session arbitration item 2, F7 of the M8 Step 3a
        // conformance sweep: "collect under the guard, drop outside").
        drop(expired);
        count
    }

    // ------------------------------------------------------------------
    // dispatch — the choke point
    // ------------------------------------------------------------------

    /// Decide and answer one control message. Returns `None` when no reply
    /// is due (e.g. an unsolicited `Pong`). Every handler authorizes and
    /// audits before its first `.await` and before touching any resource.
    pub async fn dispatch(&self, ctx: &ConnCtx, msg: &ControlMessage) -> Option<ControlMessage> {
        let request_id = msg.request_id;
        match &msg.body {
            Some(control_message::Body::ExecStart(req)) => {
                Some(self.handle_exec_start(ctx, request_id, req))
            }
            Some(control_message::Body::Ping(_)) => Some(ControlMessage::new(
                request_id,
                control_message::Body::Pong(wire::Pong {}),
            )),
            Some(control_message::Body::Pong(_)) | Some(control_message::Body::Response(_)) => None,
            Some(control_message::Body::SessionOpen(req)) => {
                Some(self.handle_session_open(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionList(_)) => {
                Some(self.handle_session_list(ctx, request_id))
            }
            Some(control_message::Body::SessionGet(req)) => {
                Some(self.handle_session_get(ctx, request_id, req))
            }
            Some(control_message::Body::SessionRead(req)) => {
                Some(self.handle_session_read(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionWrite(req)) => {
                Some(self.handle_session_write(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionResize(req)) => {
                Some(self.handle_session_resize(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionClose(req)) => {
                Some(self.handle_session_close(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionAttach(req)) => {
                Some(self.handle_session_attach(ctx, request_id, req).await)
            }
            // A host never consumes SessionEvent (it is the producer);
            // an unsolicited one is dropped like a stray Pong.
            Some(control_message::Body::SessionEvent(_)) => None,
            Some(control_message::Body::Hello(_)) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::InvalidArgument,
                    "unexpected Hello after handshake",
                    false,
                ),
            )),
            // Pairing (ADR-0002, M7 Step 4) has its own, much smaller
            // dispatch loop (`Server::serve_pairing_connection`), reachable
            // only on a connection whose principal is `Principal::Pairing`
            // — `Server::serve_connection_inner` routes such a connection
            // there *before* it ever reaches this ordinary `Hello`/dispatch
            // path. A `PairingProof`/`PairingAccepted` arriving here means
            // an already-authenticated peer sent a pairing message on its
            // normal connection, which is never valid — refused exactly
            // like a stray `Hello`, above.
            Some(control_message::Body::PairingProof(_)) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::InvalidArgument,
                    "unexpected PairingProof on an authenticated connection",
                    false,
                ),
            )),
            Some(control_message::Body::PairingAccepted(_)) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::InvalidArgument,
                    "unexpected PairingAccepted on an authenticated connection",
                    false,
                ),
            )),
            // `RemoteForwardOpen` (M4 Step 4) needs a live `Connection` to
            // open the `TCP_ACCEPTED` streams its listener will hand out —
            // something no `dispatch` caller has (`dispatch`'s own module
            // doc: "pure with respect to transport"). `Server::serve_control`
            // intercepts it before it ever reaches this match, the same
            // shape as the `SessionWrite` special case just above in that
            // loop, and calls `Server::handle_rfwd_open` (which does have
            // one) directly. A caller that dispatches this body straight
            // (every unit test in this file included) has no connection to
            // open anything on, so it draws `UNSUPPORTED` here — the ACL +
            // loopback choke point itself is still fully unit-testable, via
            // `Server::authorize_and_bind_remote_forward` directly, which
            // needs no connection either.
            Some(control_message::Body::RfwdOpen(_)) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "remote forward open requires a live connection; \
                     not answerable by direct dispatch",
                    false,
                ),
            )),
            // `RemoteForwardClose` needs no connection — it is an ACL
            // choke point (`Server::authorize_owned`, `PLAN.md` M5 Step 5)
            // over a `Server::remote_forwards` lookup plus an abort — so it
            // is handled inline here like every other control op.
            Some(control_message::Body::RfwdClose(req)) => {
                Some(self.handle_rfwd_close(ctx, request_id, req))
            }
            // No body this build understands. prost drops unknown fields,
            // so a reserved (25 `SessionSignal`) or future control number
            // decodes to `body: None` exactly like an empty message;
            // CLI.md §2.4 / protocol.md §9 require UNSUPPORTED for those,
            // and CLI.md §3.3 assigns un-negotiated features the same code.
            None => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "unknown, reserved or empty control message",
                    false,
                ),
            )),
        }
    }

    /// The choke point proper: decide `action` on `resource` for this
    /// connection and write the audit line. `Err` is the ready-made
    /// `PERMISSION_DENIED` reply. Callers create nothing before this
    /// returns `Ok`.
    /// The ACL choke point for a path that has no control-stream reply to
    /// carry a denial: a peer-opened data stream. Decides and audits
    /// exactly like [`Server::authorize`], then answers yes/no — the caller
    /// resets the stream, which is non-distinguishing by construction.
    fn authorize_stream(&self, ctx: &ConnCtx, action: Action, resource: &str) -> bool {
        let verdict = self.authorizer.check(
            &ctx.principal,
            ctx.auth_path,
            action,
            ResourceRef::unowned(resource),
        );
        // No request id: a stream is not a control-stream request, so this
        // is a connection-level record (`request_id: "-"`), same as
        // `reverse::admit`.
        let recorded = self.audit.record(&AuditRecord::connection_level(
            &ctx.principal,
            ctx.auth_path,
            action,
            resource,
            verdict.decision,
            verdict.rule,
            ctx.peer_addr,
        ));
        // Fail-closed (`CLAUDE.md` "never create a resource before
        // authorization succeeds"): an unrecorded allow is treated as a
        // deny, same as an unrecorded allow at every other choke point.
        verdict.is_allow() && recorded.is_ok()
    }

    fn authorize(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        resource: &str,
    ) -> Result<(), Box<ControlMessage>> {
        let verdict = self.authorizer.check(
            &ctx.principal,
            ctx.auth_path,
            action,
            ResourceRef::unowned(resource),
        );
        let recorded = self.audit.record(&AuditRecord::now(
            request_id,
            &ctx.principal,
            ctx.auth_path,
            action,
            resource,
            verdict.decision,
            verdict.rule,
            ctx.peer_addr,
        ));
        // Fail-closed: an allow verdict that failed to make it into the
        // audit log is denied — never create the resource this authorizes
        // without a durable record of having authorized it.
        if !verdict.is_allow() || recorded.is_err() {
            return Err(Box::new(Self::permission_denied(request_id, action)));
        }
        Ok(())
    }

    /// `Action::SessionControl` on `id`, with ownership folded into the
    /// same decision as an ordinary `scope = "owned"` policy judgment
    /// (`PLAN.md` M5 Step 5 (a), `docs/design/architecture.md` §6's ④):
    /// [`Self::require_opener`] is now a thin broker lookup that fills
    /// [`ResourceRef::owner`] for [`Self::authorize_owned`], not a second
    /// gate run after the fact — so there is exactly one
    /// [`Authorizer::check`] call and exactly one terminal audit record per
    /// request, the same "single decision, single record" property the old
    /// two-step version (`Self::authorize` + a separate `require_opener`
    /// deny) had to work to preserve (`PLAN.md` Step 3.5 PR② review: a
    /// foreign principal's refused write must not also read as an `allow`
    /// in the audit log — see
    /// `crates/qsh-testkit/tests/session_loopback.rs`'s
    /// `session_control_binds_write_and_resize_to_the_opener`), now true by
    /// construction instead of by careful sequencing.
    /// `action` is the caller's own `crate::acl::Op::X.action()` lookup
    /// (`Op::SessionWrite`/`Op::SessionResize`, `PLAN.md` M5 Step 8) — both
    /// resolve to `Action::SessionControl` today, but sourcing it from the
    /// registry at each call site (rather than hardcoding the enum
    /// variant here) is what keeps this shared helper and `OP_REGISTRY`
    /// from being able to drift silently.
    fn authorize_session_control(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        id: &SessionId,
    ) -> Result<(), Box<ControlMessage>> {
        // `require_opener` itself denies (and audits) on an ambiguous
        // broker lookup failure — see its own doc. A `NotFound` id passes
        // through as `owner: None`, same as any other unowned resource,
        // so the ACL decision below still runs and the caller's own
        // subsequent broker call is what eventually answers
        // `SESSION_NOT_FOUND` — this function never invents that answer.
        let owner = self.require_opener(ctx, request_id, action, id)?;
        self.authorize_owned(
            ctx,
            request_id,
            action,
            ResourceRef {
                id: &id.0,
                owner: owner.as_deref(),
            },
        )
    }

    /// [`Self::authorize`]'s owner-aware sibling (`PLAN.md` M5 Step 5): one
    /// [`Authorizer::check`] call over a [`ResourceRef`] that already
    /// carries `owner`, and exactly one terminal audit record either way.
    /// Its two callers are [`Self::authorize_session_control`] (owner from
    /// [`Self::require_opener`]'s broker lookup) and
    /// [`Self::handle_rfwd_close`] (owner from `Server::remote_forwards`'s
    /// own registration record) — both need a `ResourceRef` [`Self::
    /// authorize`] cannot build, since that helper always passes
    /// [`ResourceRef::unowned`].
    fn authorize_owned(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Result<(), Box<ControlMessage>> {
        let verdict = self
            .authorizer
            .check(&ctx.principal, ctx.auth_path, action, resource);
        let recorded = self.audit.record(&AuditRecord::now(
            request_id,
            &ctx.principal,
            ctx.auth_path,
            action,
            resource.id,
            verdict.decision,
            verdict.rule,
            ctx.peer_addr,
        ));
        // Fail-closed: this is the terminal record for the combined
        // policy + ownership decision — an allow that failed to land in
        // the audit log flips to denied, same as `Self::authorize`.
        if !verdict.is_allow() || recorded.is_err() {
            return Err(Box::new(Self::permission_denied(request_id, action)));
        }
        Ok(())
    }

    /// The `PERMISSION_DENIED` reply for `action`. The **only** place this
    /// wording is built, so [`Server::authorize`]'s policy deny,
    /// [`Server::require_opener`]'s ownership deny, and every audit-
    /// record-failure fail-closed deny are byte-identical — a peer must
    /// not be able to tell "the policy forbids this" from "this session
    /// exists but is someone else's" from "the audit log failed to write"
    /// (`PLAN.md` Step 3.5 PR②, M5 Step 4 §4.2). The reply body is always
    /// [`crate::acl::PERMISSION_DENIED_MESSAGE`] verbatim — `action` never
    /// reaches the wire (that would turn the message into a capability-
    /// enumeration oracle, see that constant's doc) and is used only for
    /// a host-side `tracing` diagnostic, never logged to the peer.
    fn permission_denied(request_id: u64, action: Action) -> ControlMessage {
        tracing::debug!(%request_id, %action, "denying: PERMISSION_DENIED");
        ControlMessage::error(
            request_id,
            wire::Error::new(
                ErrorCode::PermissionDenied,
                crate::acl::PERMISSION_DENIED_MESSAGE,
                false,
            ),
        )
    }

    /// `session.control`'s ownership *lookup* (audit A2 P0, `PLAN.md` Step
    /// 3.5 PR②, PRD §6, M5 Step 5 (a)): finds the session's recorded
    /// opener, for [`Self::authorize_session_control`] to fold into the
    /// `ResourceRef` it hands the ordinary `Authorizer::check` call — the
    /// actual `scope = "owned"` comparison against it now lives in the
    /// authorizer (`AllowAllPinned::check`/`Policy::decide`), not here.
    /// Named `require_opener` still: `PLAN.md` M5 Step 5 (a) keeps the name
    /// across this shrink from "the ownership gate itself" to "the thin
    /// broker lookup that feeds it".
    ///
    /// A session this host cannot find is left alone (`Ok(None)`):
    /// existence is decided by the caller's own subsequent broker call
    /// ([`SessionBackend::get`]/`take_lease`/`resize`), never invented here
    /// — inventing a denial for "no such session" would make this gate an
    /// oracle the ACL choke point deliberately is not (`session.write`/
    /// `resize` already answer `SESSION_NOT_FOUND` for an unknown id, same
    /// as before this check existed). `owner: None` also happens to be
    /// exactly the "no owner concept" shape every unowned resource uses
    /// (`ResourceRef`'s own doc), so the ACL decision that follows treats a
    /// not-yet-found session the same way it treats `exec.run` — never
    /// filtered by scope — which is what lets this passthrough work without
    /// a special case in the authorizer.
    ///
    /// Any *other* lookup failure (an out-of-process `SessionBackend`
    /// timing out, say) is ambiguous, not "no such session", and
    /// `CLAUDE.md`'s "fail closed on any ambiguous auth/ACL state" applies:
    /// this function denies (and writes the sole audit record for that
    /// denial itself — its caller never reaches its own `Authorizer::check`
    /// call in this branch, so there is still exactly one terminal record)
    /// rather than silently waving the request through.
    ///
    /// `session.get`/`read`/`close`/`list`, `session.open` and
    /// `session.attach` are **not** gated by ownership at all — PRD §6
    /// keeps them cross-device within ACL scope, and attach is already
    /// device-bound by its resume credential (ADR-0007) — so nothing calls
    /// this outside [`Self::authorize_session_control`].
    ///
    /// The returned owner is the session's recorded [`opener_key`] — a
    /// `(principal, auth_path)` pair folded at `session.open` time (see
    /// that handler's own call), not `ctx.principal` alone: `Principal` by
    /// itself cannot tell a pin from a CA leaf asserting the same name
    /// (`qsh-transport::tls::AuthPath`'s own doc), so a bare principal
    /// string would let a CA-issued leaf assert a pinned opener's identity
    /// the moment the authorizer that compares it admits any
    /// CA-authenticated peer for `session.control` at all.
    fn require_opener(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        id: &SessionId,
    ) -> Result<Option<String>, Box<ControlMessage>> {
        match self.sessions.get(id) {
            Ok(info) => Ok(Some(info.opener)),
            // `NotFound` alone is left alone — existence is decided by the
            // caller's own subsequent broker call, per the doc above.
            Err(BrokerError::NotFound) => Ok(None),
            // Ambiguous, not "no such session": fail closed. Not a
            // policy-rule decision, so there is no rule index to carry.
            Err(_) => {
                let _ = self.audit.record(&AuditRecord::now(
                    request_id,
                    &ctx.principal,
                    ctx.auth_path,
                    action,
                    &id.0,
                    Decision::Deny,
                    None,
                    ctx.peer_addr,
                ));
                Err(Box::new(Self::permission_denied(request_id, action)))
            }
        }
    }

    fn handle_exec_start(&self, ctx: &ConnCtx, request_id: u64, req: &ExecStart) -> ControlMessage {
        if !ctx.has_capability(wire::CAP_EXEC) {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "peer did not negotiate the exec capability",
                    false,
                ),
            );
        }
        if req.argv.is_empty() {
            return ControlMessage::error(
                request_id,
                wire::Error::new(ErrorCode::InvalidArgument, "argv must not be empty", false),
            );
        }

        // ---- ACL choke point: decide + audit BEFORE any resource. ----
        if let Err(denied) =
            self.authorize(ctx, request_id, crate::acl::Op::ExecRun.action(), "exec")
        {
            return *denied;
        }

        // ---- Resource bound: no more outstanding tickets for this peer. ----
        //
        // After the ACL choke point above (main-session arbitration round,
        // item 3), *not* ahead of it the way the M8 Step 3a conformance
        // sweep's F4 had left it: `check_ticket_budget` creates nothing —
        // there was never a "never create a resource before authorization"
        // reason to run it first — and putting any capacity check ahead of
        // ACL makes `RESOURCE_EXHAUSTED` vs. `PERMISSION_DENIED` a
        // same-connection oracle for whether the *caller's own* prior
        // requests are what is being counted, which an unauthorized
        // principal has no business learning either way.
        // `exec_ticket_budget_follows_the_acl_choke_point_on_the_same_
        // connection` below pins the order this call site now has.
        if let Err(reply) = self.check_ticket_budget(ctx, request_id) {
            return *reply;
        }

        // ---- Drain gate (CLI.md §6.12, ADR-0003): after the ACL decision,
        // same placement as `session.open`/`session.attach` — otherwise
        // `exec.run` would keep admitting brand-new host processes for the
        // whole drain window while sessions are being torn down around it.
        if let Err(reply) = self.require_not_draining(request_id) {
            return *reply;
        }

        // ---- exec.run concurrency quota (`[serve].max_exec_per_principal`,
        // verdict arbitration item 5): after the ACL decision (an
        // unauthorized principal must see `PERMISSION_DENIED`, never a
        // quota oracle), before anything is issued. The ticket budget above
        // only bounds *unredeemed* tickets — a principal that keeps
        // redeeming and reaping children never accumulates an unbounded
        // backlog through that alone, so this reserves against *live*
        // children instead. ----
        let opener = opener_key(&ctx.principal, ctx.auth_path);
        let permit = match self.quotas.reserve_exec(&opener) {
            Ok(permit) => permit,
            Err(kind) => {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    ctx.peer_addr,
                    self.quotas.now(),
                    Some(request_id),
                    ctx.auth_path,
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                return broker_error(request_id, BrokerError::QuotaExceeded(kind));
            }
        };

        // ---- Allowed: issue a single-use ticket. Nothing spawned yet. ----
        let spec = ExecSpec {
            argv: req.argv.clone(),
            env: req
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            timeout: (req.timeout_ms > 0).then(|| Duration::from_millis(req.timeout_ms)),
        };
        let exec_id = ulid::Ulid::new().to_string();
        let ticket = self.issue_ticket(
            ctx.conn_id,
            TicketPurpose::Exec(PendingExec {
                exec_id: exec_id.clone(),
                spec,
                permit,
            }),
        );
        tracing::info!(
            principal = %ctx.principal,
            peer = %ctx.peer_addr,
            %exec_id,
            "exec.run authorized"
        );
        ControlMessage::response(
            request_id,
            response::Body::ExecStarted(ExecStarted {
                exec_id,
                ticket: ticket.to_vec(),
            }),
        )
    }

    // ------------------------------------------------------------------
    // session ops (M2 Step 3) — CLI.md §6.2–6.7, action mapping §2.5
    // ------------------------------------------------------------------

    /// Shape check on a peer-supplied `session_id` before it becomes the
    /// ACL resource and an audit field: non-empty, URL-safe
    /// (`[A-Za-z0-9_-]`) and at most [`SESSION_ID_MAX_LEN`] bytes. The
    /// check does not consult the broker, so it discloses nothing about
    /// which sessions exist.
    fn require_session_id(request_id: u64, id: &str) -> Result<(), Box<ControlMessage>> {
        if valid_session_id(id) {
            Ok(())
        } else {
            Err(Box::new(invalid_argument(
                request_id,
                "session_id must be 1..=64 URL-safe characters",
            )))
        }
    }

    /// SIGTERM graceful drain (`docs/CLI.md` §6.12, ADR-0003): refuse every
    /// `session.open`/`session.attach` arriving on a connection this host
    /// already holds, from the moment [`Server::drain`] is called.
    /// `RESOURCE_EXHAUSTED` rather than a new code (CLI.md §3.3:
    /// "server-side limit exceeded") — the host's capacity for new sessions
    /// is now zero — and non-retryable, because retrying against this same
    /// process cannot ever succeed again.
    fn require_not_draining(&self, request_id: u64) -> Result<(), Box<ControlMessage>> {
        if self.draining.load(Ordering::Acquire) {
            return Err(Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::ResourceExhausted,
                    "qsh serve is shutting down: refusing new sessions",
                    false,
                ),
            )));
        }
        Ok(())
    }

    /// Drain the host: refuse every new `session.open`/`session.attach`
    /// from this call forward, then close every live session through the
    /// same procedure `session.close` uses — signal escalation,
    /// `session.closed{reason:"closed"}` to every attached consumer,
    /// `close_grace_ms` per step (CLI.md §6.7) — so no PTY child outlives
    /// the process (§6.12, ADR-0003).
    ///
    /// Bounded by [`DRAIN_TIMEOUT`] as a last resort; not otherwise. Setting
    /// the flag before closing sessions (rather than relying on the accept
    /// loop having already stopped) is what covers a request racing in on a
    /// connection this host had already accepted. Idempotent — a second
    /// call finds nothing left to close.
    pub async fn drain(&self) {
        self.draining.store(true, Ordering::Release);
        if tokio::time::timeout(DRAIN_TIMEOUT, self.sessions.drain(CloseReason::Closed))
            .await
            .is_err()
        {
            tracing::warn!(
                timeout_secs = DRAIN_TIMEOUT.as_secs(),
                "qsh serve drain: timed out waiting for every session to close; exiting anyway"
            );
        }
        // See [`DRAIN_FLUSH_GRACE`]: every session is closed in the broker
        // at this point, but delivering that to an attached consumer is a
        // separate hop this call has not waited for.
        tokio::time::sleep(DRAIN_FLUSH_GRACE).await;
    }

    /// Common preamble of every session op: the peer must have negotiated
    /// the `session` capability. Not audited (no decision was made).
    fn require_session_capability(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
    ) -> Result<(), Box<ControlMessage>> {
        if ctx.has_capability(wire::CAP_SESSION) {
            Ok(())
        } else {
            Err(Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "peer did not negotiate the session capability",
                    false,
                ),
            )))
        }
    }

    fn check_ticket_budget(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
    ) -> Result<(), Box<ControlMessage>> {
        if self.pending_tickets_for(ctx.conn_id) >= MAX_PENDING_TICKETS_PER_CONN {
            return Err(Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::ResourceExhausted,
                    "too many outstanding tickets on this connection",
                    true,
                ),
            )));
        }
        Ok(())
    }

    /// `session.open`: ACL `session.open` → `user` hint → spawn → ticket.
    async fn handle_session_open(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionOpen,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        let Some((cols, rows)) = window_size(req.cols, req.rows) else {
            return invalid_argument(request_id, "cols/rows must fit in 16 bits");
        };

        // ---- ACL choke point: decide + audit BEFORE any resource. ----
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionOpen.action(),
            SESSION_RESOURCE,
        ) {
            return *denied;
        }

        // ---- Drain gate, same placement as `session.attach`: after the
        // ACL decision so `authorize`'s audit record is still written for a
        // request arriving during drain — the gate creates no resource
        // either way, so there is nothing to save by short-circuiting
        // earlier, and doing so would make `RESOURCE_EXHAUSTED` vs.
        // `PERMISSION_DENIED` an oracle for host shutdown state. ----
        if let Err(reply) = self.require_not_draining(request_id) {
            return *reply;
        }

        // ---- Resource bound: no more outstanding tickets for this peer. ----
        //
        // After the ACL choke point above (main-session arbitration round,
        // item 3) — not ahead of it the way the M8 Step 3a conformance
        // sweep had instead left this call site (adversary finding A1):
        // `check_ticket_budget` creates nothing, so there was never a
        // "never create a resource before authorization" reason to run it
        // first, and putting any capacity check ahead of ACL makes
        // `RESOURCE_EXHAUSTED` vs. `PERMISSION_DENIED` a same-connection
        // oracle for whether the *caller's own* prior requests are what is
        // being counted, which an unauthorized principal has no business
        // learning either way. Placed after the drain gate immediately
        // above, matching `session.attach`'s own ACL → drain → ticket-
        // budget order (see that handler's "same reasoning as
        // exec.run/session.open" comment) rather than `exec.run`'s ACL →
        // ticket-budget → drain order — `session.open` and
        // `session.attach` share a drain-gate rationale that `exec.run`
        // does not, so the two session ops stay in lockstep with each
        // other here.
        // `session_open_ticket_budget_follows_the_acl_choke_point_on_the_
        // same_connection` below pins the order this call site now has.
        if let Err(reply) = self.check_ticket_budget(ctx, request_id) {
            return *reply;
        }

        // ---- `user@` hint (CLI.md §7): only after the ACL decision, so an
        // unauthorized peer never learns the serve account's login name.
        if let Some(user) = req.user.as_deref()
            && !user_hint_matches(user)
        {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "user switching is not supported: sessions run as the qsh serve account",
                    false,
                ),
            );
        }

        // ---- Allowed: create the session, then a single-use ticket. ----
        let mut env: Vec<(String, String)> = req
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        env.sort();
        let spec = SessionSpec {
            argv: req.argv.clone(),
            env,
            term: (!req.term.is_empty()).then(|| req.term.clone()),
            cols,
            rows,
            user: req.user.clone(),
        };
        // The opener is recorded as this session's owner (`PLAN.md` Step
        // 3.5 PR②) — `session.write`/`session.resize` bind to it from here
        // on. `opener_key`, not `ctx.principal.to_string()` alone: see its
        // doc comment.
        let opener = opener_key(&ctx.principal, ctx.auth_path);
        let session_id = match self.sessions.open(&spec, &opener) {
            Ok(id) => id,
            // A session-count quota (`[serve].max_sessions`/
            // `max_sessions_per_principal`, `PLAN.md` M8 Step 3) was
            // already saturated when `Broker::open` reserved a slot for
            // this opener — reached strictly after the ACL `allow` above
            // was decided and audited, so this can never substitute for a
            // `PERMISSION_DENIED` an unauthorized principal should have
            // seen instead. The broker itself never touches an
            // `AuditSink` (`crate::quota` is leaf-most/connection-agnostic
            // — architecture.md §1), so the rejection is recorded here.
            Err(BrokerError::QuotaExceeded(kind)) => {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    ctx.peer_addr,
                    self.quotas.now(),
                    Some(request_id),
                    ctx.auth_path,
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                return broker_error(request_id, BrokerError::QuotaExceeded(kind));
            }
            Err(err) => return broker_error(request_id, err),
        };
        let ticket = self.issue_ticket(
            ctx.conn_id,
            TicketPurpose::Session {
                session_id: session_id.clone(),
                replay_from: 0,
                // `session.open` never steals: nobody else can hold the
                // lease of a session that did not exist a moment ago.
                no_steal: false,
                // Only `session.open` was authorized here; the attach the
                // data stream performs is decided when it arrives.
                attach_authorized: false,
                // A fresh session's first input stream, counting from zero.
                // The resume credential minted just below starts its
                // lineage on the same axis.
                input_stream: FIRST_INPUT_STREAM,
                input_from: 0,
            },
        );
        // The resume credential (protocol.md §10). Bound to the peer's SPKI:
        // without a verified leaf there is nothing to bind to, so no token
        // is issued at all and the session simply cannot be resumed — fail
        // closed rather than mint an unbound credential.
        let resume_token = match ctx.peer_fingerprint {
            Some(peer) => Some(self.sessions.issue_resume(&session_id, peer)),
            None => {
                tracing::warn!(
                    principal = %ctx.principal,
                    %session_id,
                    "no peer SPKI fingerprint: session opened without a resume credential"
                );
                None
            }
        };
        let expires_at = rfc3339_after(self.sessions.resume_ttl());
        tracing::info!(
            principal = %ctx.principal,
            peer = %ctx.peer_addr,
            %session_id,
            "session.open authorized"
        );
        ControlMessage::response(
            request_id,
            response::Body::SessionOpened(wire::SessionOpened {
                session_id: session_id.0,
                // The only time this plaintext ever leaves the host. It is
                // never logged, never audited and never rendered as JSON
                // (ADR-0007).
                resume_token: resume_token
                    .as_ref()
                    .map(|t| t.expose().to_vec())
                    .unwrap_or_default(),
                ticket: ticket.to_vec(),
                initial_seq: 0,
                expires_at,
            }),
        )
    }

    /// `session.list`: ACL `session.list` on the session namespace.
    fn handle_session_list(&self, ctx: &ConnCtx, request_id: u64) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionList.action(),
            SESSION_RESOURCE,
        ) {
            return *denied;
        }
        let sessions = self
            .sessions
            .list()
            .into_iter()
            .map(session_info_to_wire)
            .collect();
        ControlMessage::response(
            request_id,
            response::Body::SessionListResult(wire::SessionListResult { sessions }),
        )
    }

    /// `session.get`: ACL `session.list` on the session id.
    fn handle_session_get(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionGet,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionGet.action(),
            &req.session_id,
        ) {
            return *denied;
        }
        match self.sessions.get(&SessionId(req.session_id.clone())) {
            Ok(info) => ControlMessage::response(
                request_id,
                response::Body::SessionInfo(session_info_to_wire(info)),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.read`: ACL `session.attach` on the session id, then one
    /// cursor pull (the same primitive `--follow` and a long-running
    /// external process's, e.g. an agent tool, long-poll use).
    async fn handle_session_read(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionRead,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionRead.action(),
            &req.session_id,
        ) {
            return *denied;
        }
        // Clamp, never reject (protocol.md §9): 0 = host default = the cap.
        let max_bytes = match usize::try_from(req.max_bytes) {
            Ok(0) | Err(_) => wire::SESSION_READ_MAX_BYTES,
            Ok(n) => n.min(wire::SESSION_READ_MAX_BYTES),
        };
        // Same treatment for the wait: clamp, never reject.
        let wait = Duration::from_millis(req.wait_ms).min(SESSION_READ_MAX_WAIT);
        // The cursor is (output offset, control id) — control entries are
        // zero-length, so `after` alone cannot say whether one positioned
        // exactly at `after` was already delivered. A caller that echoes
        // `next_ctl_after` back gets every control exactly once; one that
        // does not (`ctl_after: 0`) gets at-least-once (protocol.md §9).
        let out = match self
            .sessions
            .pull(
                &SessionId(req.session_id.clone()),
                Cursor {
                    after: req.after,
                    ctl_after: req.ctl_after,
                },
                max_bytes,
                wait,
            )
            .await
        {
            Ok(out) => out,
            Err(err) => return broker_error(request_id, err),
        };
        let next = out.next;
        let events = out
            .events
            .into_iter()
            .flat_map(replay_event_to_wire)
            .collect();
        ControlMessage::response(
            request_id,
            response::Body::SessionReadResult(wire::SessionReadResult {
                events,
                next_after: next.after,
                next_ctl_after: next.ctl_after,
            }),
        )
    }

    /// `session.write`: [`prepare_session_write`](Self::prepare_session_write)
    /// then [`finish_session_write`](Self::finish_session_write). The
    /// connection loop splits the two so the parking half never runs on the
    /// control stream; `dispatch` keeps them together.
    async fn handle_session_write(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionWrite,
    ) -> ControlMessage {
        match self.prepare_session_write(ctx, request_id, req).await {
            Ok(pending) => self.finish_session_write(pending).await,
            Err(reply) => *reply,
        }
    }

    /// The non-parking half of `session.write`: ACL `session.control` on
    /// the session id and ownership
    /// ([`Server::authorize_session_control`], `PLAN.md` Step 3.5 PR②/M5
    /// Step 5), then take the writer lease with `no_steal: true` fixed
    /// (below) regardless of what the ACL layer decided. Under the default
    /// `scope = "owned"` (M3's P0, still what `AllowAllPinned` and every
    /// `acl.toml` row without an explicit `scope = "any"` enforce), the
    /// ownership check above already narrows every caller reaching this
    /// line to the session's own opener, so `TakeOutcome::Conflict` can
    /// never actually fire here — the lease's live holder is that same
    /// opener too (architecture.md §3 rule (b)'s amendment note). An
    /// explicit `scope = "any"` grant (M5 Step 5) reopens that path: a
    /// foreign principal can now pass the ACL gate above. Whether it then
    /// reaches `Conflict` here depends on the lease already being *live*
    /// (F3, M5 Step 5 adversarial review): if the opener has already
    /// written or attached first, the foreign principal's own write lands
    /// on that live lease and `no_steal: true` — unconditional — refuses it
    /// with `Conflict`, so `scope` widens ACL admission only, never the
    /// writer-lease's own never-silently-steal-from-someone-else guarantee.
    /// But a lease nobody has taken yet (fresh out of `session.open`,
    /// `WriterLease::new()`) has no live holder to conflict with, so a
    /// foreign principal that reaches this line *first* just takes it — and
    /// it is the **opener's own subsequent write** that then meets
    /// `Conflict` instead
    /// (`session_write_scope_any_lets_a_foreign_first_writer_take_the_free_lease`,
    /// `crates/qsh-testkit/tests/session_loopback.rs`). This residual
    /// window is the documented trade-off, not a bug: `scope` only ever
    /// decides who may *reach* the lease, never who wins a race for a free
    /// one. The two gates are independent on purpose.
    ///
    /// Everything here is bounded — the session actor's loop never blocks
    /// on the child — so this side is safe to run inline on the control
    /// stream, which is what keeps two pipelined writes in arrival order
    /// and keeps the lease from being taken after `purge_connection`.
    /// `Err` is the finished reply; `Ok` is a write still owed to the PTY.
    async fn prepare_session_write(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionWrite,
    ) -> Result<PendingWrite, Box<ControlMessage>> {
        self.require_session_capability(ctx, request_id)?;
        Self::require_session_id(request_id, &req.session_id)?;
        if let Err(err) = req.validate() {
            return Err(Box::new(invalid_argument(request_id, err.to_string())));
        }
        let id = SessionId(req.session_id.clone());
        self.authorize_session_control(
            ctx,
            request_id,
            crate::acl::Op::SessionWrite.action(),
            &id,
        )?;
        let conn = ctx.connection_id();
        if req.data.is_empty() {
            // Nothing to write: answer without touching the lease, so an
            // empty write is not a side-channel for displacing (or
            // flapping) the current writer. Existence is still checked
            // (the ACL decision above already covers disclosure).
            return Err(Box::new(match self.sessions.get(&id) {
                Ok(_) => ControlMessage::response(
                    request_id,
                    response::Body::SessionWritten(wire::SessionWritten { bytes_written: 0 }),
                ),
                Err(err) => broker_error(request_id, err),
            }));
        }
        match self
            .sessions
            .take_lease(&id, ctx.principal.to_string(), conn, true)
            .await
        {
            Ok(TakeOutcome::Conflict { .. }) => {
                return Err(Box::new(ControlMessage::error(
                    request_id,
                    wire::Error::new(
                        ErrorCode::SessionConflict,
                        "another principal holds the session's writer lease",
                        true,
                    ),
                )));
            }
            Ok(_) => {}
            Err(err) => return Err(Box::new(broker_error(request_id, err))),
        }
        Ok(PendingWrite {
            request_id,
            id,
            conn,
            data: req.data.clone(),
        })
    }

    /// The parking half of `session.write`: hand the bytes to the session.
    /// This can wait indefinitely — a child that stops draining its PTY
    /// input buffer blocks its writer task — so the connection loop runs it
    /// on a per-connection queue, never inline.
    async fn finish_session_write(&self, pending: PendingWrite) -> ControlMessage {
        let PendingWrite {
            request_id,
            id,
            conn,
            data,
        } = pending;
        let bytes_written = data.len() as u64;
        match self.sessions.write(&id, conn, data).await {
            Ok(()) => ControlMessage::response(
                request_id,
                response::Body::SessionWritten(wire::SessionWritten { bytes_written }),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.resize`: ACL `session.control` on the session id and the
    /// opener binding, combined
    /// ([`Server::authorize_session_control`], `PLAN.md` Step 3.5 PR②).
    async fn handle_session_resize(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionResize,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        let Some((cols, rows)) = window_size(req.cols, req.rows) else {
            return invalid_argument(request_id, "cols/rows must fit in 16 bits");
        };
        if cols == 0 || rows == 0 {
            return invalid_argument(request_id, "cols and rows must be positive");
        }
        let id = SessionId(req.session_id.clone());
        if let Err(denied) = self.authorize_session_control(
            ctx,
            request_id,
            crate::acl::Op::SessionResize.action(),
            &id,
        ) {
            return *denied;
        }
        match self.sessions.resize(&id, cols, rows).await {
            Ok(()) => ControlMessage::response(
                request_id,
                response::Body::SessionResized(wire::SessionResized {
                    cols: u32::from(cols),
                    rows: u32::from(rows),
                }),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.close`: ACL `session.control` on the session id, then the
    /// HUP → TERM → KILL escalation (`--signal` overrides the first step).
    async fn handle_session_close(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionClose,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        let signal = match req.signal.as_deref() {
            None => None,
            Some(name) => match Signal::parse(name) {
                Some(signal) => Some(signal),
                None => {
                    return invalid_argument(
                        request_id,
                        "signal must be one of HUP|INT|QUIT|TERM|USR1|USR2|KILL",
                    );
                }
            },
        };
        // Deliberately the *unowned* path — `Self::authorize`, not
        // `Self::authorize_session_control` — even though `close` shares
        // `Action::SessionControl` with `write`/`resize`. This is an
        // **exemption**, not a gap (F1, M5 Step 5 adversarial review,
        // arbitrated): PRD §6's 세션 복구 section is explicit that a device
        // without this session's resume credential can still act on it —
        // "다른 장비에서는 `qsh sessions`에 보이더라도 attach는
        // `SESSION_NOT_FOUND`이며, 조회·읽기·종료는 ACL 범위에서 가능하다" — and
        // M3 already shipped `close` cross-device
        // (`session_control_binding_does_not_reach_get_read_or_close`,
        // `crates/qsh-testkit/tests/session_loopback.rs`). This step's own
        // invariant is "no behavior change" to that: a `scope = "owned"`
        // rule still narrows `write`/`resize` to the opener
        // (`Self::authorize_session_control`, above) but never narrows
        // `close`, on purpose. The scenario this serves: a laptop that
        // opened a session goes dark (lid closed, battery dead, network
        // partition) and a desktop sharing the same principal set —
        // granted `session.control`, not necessarily the opener — needs to
        // reap the orphaned child rather than wait out `resume_ttl`. No
        // ACL vocabulary restricts *who* may close *whose* session today;
        // narrowing that would need a new action (e.g. splitting
        // `session.control` so `close` has its own scope-able name) decided
        // by its own ADR, not a silent reinterpretation of this choke
        // point.
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionClose.action(),
            &req.session_id,
        ) {
            return *denied;
        }
        let id = SessionId(req.session_id.clone());
        // `final_seq` is the offset at removal time (CLI.md §6.7): whatever
        // the child emitted while dying is included, and it equals the
        // `sequence` on the trailing `session.closed` entry.
        let result = self.sessions.close(&id, CloseReason::Closed, signal).await;
        if result.is_ok() {
            // A closed session's own unredeemed tickets are now ghosts —
            // no `SESSION_DATA` stream can attach to a session the broker
            // no longer has, so their `MAX_PENDING_TICKETS_PER_CONN` slots
            // would otherwise sit dead until `TICKET_TTL` (30 s) or a
            // connection-wide `purge_connection` reclaimed them. `handle_
            // session_attach` mints exactly one ticket per call but does
            // not invalidate a still-pending one from an earlier attach of
            // the *same* session (confirmed by reading it above — its only
            // ticket-map access before its own `issue_ticket` is
            // `check_ticket_budget`, which only sweeps expired tickets and
            // counts what is left; it invalidates nothing), so more than
            // one `TicketPurpose::Session` ticket can be outstanding for
            // one `session_id` at once; that is exactly why this matches
            // on `session_id` rather than assuming a single ticket.
            //
            // Deliberately *not* also scoped to `t.conn_id == ctx.conn_id`
            // (라운드 1 판정 (c)): `close` is the unowned path (see above) —
            // any connection may close a session it did not open — so
            // scoping to the closer's own connection would strand the
            // opener's ticket forever whenever a different device reaps
            // the session. A session that no longer exists cannot be
            // attached to from *any* connection, so every `Session` ticket
            // naming it is equally dead; all of them go, regardless of
            // which connection minted them. The one race this still
            // leaves open — `handle_session_attach` confirming the broker
            // still has the session, then this `close` running, then that
            // same attach's `issue_ticket` minting a ticket for a session
            // that is already gone — is real but narrow (single `.await`
            // wide) and self-healing: `TICKET_TTL` (30 s) is its upper
            // bound even if this exact interleaving is hit.
            let dropped = {
                let mut tickets = self.lock_tickets();
                extract_tickets(
                    &mut tickets,
                    |t| !matches!(&t.purpose, TicketPurpose::Session { session_id, .. } if *session_id == id),
                )
            };
            // Same "collect under the guard, drop outside" discipline
            // (ADR-0010 §9) as `issue_ticket`/`pending_tickets_for`'s
            // expiry sweep and `purge_connection`'s connection-close
            // sweep — even though the `TicketPurpose::Session` tickets
            // dropped here never carry a `crate::quota::ExecPermit` (only
            // `TicketPurpose::Exec` does), so this particular `drop` can
            // never re-take the quota lock today. Keeping the same shape
            // as those other three `extract_tickets` call sites anyway
            // means a future `TicketPurpose` variant that *does* carry a
            // permit cannot silently violate ADR-0010 §9 just because this
            // call site looked different.
            drop(dropped);
        }
        match result {
            Ok(final_seq) => ControlMessage::response(
                request_id,
                response::Body::SessionClosed(wire::SessionClosed { final_seq }),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.attach` (stream op), including **resume** (protocol.md §10).
    ///
    /// The order is the protocol's, and it is load-bearing:
    ///
    /// 1. the presented `resume_token` must hash to the stored credential
    ///    and not be expired, **and** the connection's peer SPKI must be
    ///    the one the session is bound to. Both are one non-distinguishing
    ///    `AUTH_FAILED`: an unauthorized peer must not be able to tell an
    ///    unknown session from a wrong token from a foreign device
    ///    (protocol.md §10-2);
    /// 2. the ACL choke point (`session.attach` on the id, audited like
    ///    every other session op);
    /// 3. **only then** the writer lease, the successor token — which
    ///    kills the presented one — and the single-use `SESSION_DATA`
    ///    ticket.
    ///
    /// `SESSION_NOT_FOUND` is reachable only past step 1, so it never
    /// discloses existence to a peer that failed the identity check.
    ///
    /// A `SessionAttach` carrying **no** credential is refused outright,
    /// with the same non-distinguishing `AUTH_FAILED`. The credential is
    /// what binds an attach to the device that opened the session
    /// (ADR-0007 결정 2, protocol.md §10), and a check the client performs
    /// on itself is not a boundary: making the field optional would let any
    /// peer the ACL admits — under the M1–M4 allow-all-pinned posture, any
    /// pinned device — take an RW PTY on somebody else's shell just by
    /// leaving the field empty. The first stream of a freshly opened
    /// session does not come through here: `session.open` mints its own
    /// `SESSION_DATA` ticket.
    async fn handle_session_attach(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionAttach,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        if req.attach_mode() != Some(wire::AttachMode::Rw) {
            return invalid_argument(request_id, "attach mode must be RW");
        }
        let id = SessionId(req.session_id.clone());
        // ---- Step 1: credential + bound identity, before anything else
        // touches the registry. ----
        let lineage = match ctx.peer_fingerprint {
            // An empty field never reaches `verify` as a token: it is
            // refused here, so the gate cannot be opted out of.
            Some(peer) if !req.resume_token.is_empty() => {
                self.sessions.verify_resume(&id, &req.resume_token, peer)
            }
            // No verified leaf to bind against, or no credential presented:
            // fail closed, and answer exactly as a bad credential does.
            _ => Err(ResumeDenied),
        };
        let lineage = match lineage {
            Ok(stream) => stream,
            Err(_) => {
                // Structural only — the record names the op, the principal
                // and the decision, never the credential (CLAUDE.md).
                // Already denying (same exception as `handshake_rejected`):
                // a failure to record this deny doesn't change the
                // outcome, only the diagnostic.
                let _ = self.audit.record(&AuditRecord::now(
                    request_id,
                    &ctx.principal,
                    ctx.auth_path,
                    crate::acl::Op::SessionAttach.action(),
                    &req.session_id,
                    crate::acl::Decision::Deny,
                    // Not a policy-rule decision — a credential-
                    // verification failure upstream of `Authorizer::
                    // check`, so no rule index applies.
                    None,
                    ctx.peer_addr,
                ));
                tracing::warn!(
                    principal = %ctx.principal,
                    peer = %ctx.peer_addr,
                    "session.attach rejected: resume credential did not verify"
                );
                return auth_failed(request_id);
            }
        };
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionAttach.action(),
            &req.session_id,
        ) {
            return *denied;
        }

        // ---- Resource bound and drain gate, same reasoning as
        // `exec.run`/`session.open`. ----
        //
        // Both placed *after* the credential and the ACL rather than
        // before them, unlike the capability check above: either answer
        // before the identity gate is one a peer with no credential could
        // tell apart from `AUTH_FAILED`, and protocol.md §10-2 requires
        // that every pre-identity refusal look the same. Placed before the
        // lease probe and the rotation, so a refused attach still spends
        // no credential and moves nothing.
        if let Err(reply) = self.require_not_draining(request_id) {
            return *reply;
        }
        if let Err(reply) = self.check_ticket_budget(ctx, request_id) {
            return *reply;
        }

        // ---- Allowed: lease, then a single-use ticket. ----
        //
        // `broker_error` here and at the two registry calls below can
        // spell `SESSION_NOT_FOUND`, which protocol.md §10-2 forbids on the
        // attach path — an unauthorized peer must not learn whether a
        // session exists. It stays unreachable rather than being mapped:
        // every removal path (`Broker::close`, the reaper) calls
        // `resume.forget` with the session, so a credential can only verify
        // in step 1 while the session is still registered, and the gap
        // between the two is not observable from outside the broker lock.
        // Left as-is deliberately — folding it into `AUTH_FAILED` would
        // hide a genuine broker bug behind a credential answer.
        let info = match self.sessions.get(&id) {
            Ok(info) => info,
            Err(err) => return broker_error(request_id, err),
        };
        // Interactive attach steals by default (architecture.md §3 rule b);
        // `no_steal` makes a live foreign lease a `SESSION_CONFLICT`.
        //
        // A **probe**, not a take: the redemption is not decided yet (the
        // rotation below can still lose a race), and CLAUDE.md's "never
        // create a resource before authorization succeeds" applies just as
        // much to moving one that already exists. Stealing here and failing
        // afterwards would leave the legitimate writer demoted in favour of
        // a connection that never attached. The real, actor-serialised take
        // happens where the data stream opens, which is also where a lease
        // that changed hands in between is caught.
        if req.no_steal
            && self
                .sessions
                .lease_conflict(&id, &ctx.principal.to_string())
        {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::SessionConflict,
                    "another principal holds the session's writer lease",
                    true,
                ),
            );
        }
        // A cursor past the end of the stream is `INVALID_ARGUMENT` at the
        // ring; clamp instead, so a client that over-reports simply gets
        // everything from the current end.
        let replay_from = req.last_output_seq.min(info.last_sequence);
        // The id of this attach's own input axis — reserved, not yet
        // created. The credential rotation below has to name the axis it
        // hands to the next generation, and the rotation is the point where
        // this redemption becomes final; creating the axis first would mint
        // session state for an attach that can still lose its race, which is
        // the same reason `no_steal` above is a probe rather than a take.
        // Reserving costs a counter value and no axis slot, so a lost race
        // cannot evict a live peer's axis from the bounded window.
        let input_stream = match self.sessions.reserve_input_stream(&id) {
            Ok(stream) => stream,
            Err(err) => return broker_error(request_id, err),
        };
        // The successor credential. Minted last, after every check passed:
        // the presented token dies here, so a redemption that got this far
        // is the one and only winner (protocol.md §10 "Rotation").
        let new_resume_token = {
            let Some(peer) = ctx.peer_fingerprint else {
                return auth_failed(request_id);
            };
            match self
                .sessions
                .rotate_resume(&id, &req.resume_token, peer, input_stream)
            {
                Ok(token) => token,
                // Lost the race with another redemption of the same token
                // between step 1 and here. Same non-distinguishing answer,
                // and no axis was created to leak.
                Err(_) => return auth_failed(request_id),
            }
        };
        // Won. Now create the axis, forked from the one the credential
        // named and seeded with that axis's applied offset: the un-acked
        // tail the client retransmits is deduplicated against what the child
        // already ran, and the attach this one succeeds — which may still be
        // connected and typing after its demotion — cannot move the cursor
        // (protocol.md §10-5).
        let input_from = match self
            .sessions
            .seed_input_stream(&id, input_stream, Some(lineage))
        {
            Ok(from) => from,
            Err(err) => return broker_error(request_id, err),
        };
        let ticket = self.issue_ticket(
            ctx.conn_id,
            TicketPurpose::Session {
                session_id: id.clone(),
                replay_from,
                no_steal: req.no_steal,
                attach_authorized: true,
                input_stream,
                input_from,
            },
        );
        let expires_at = rfc3339_after(self.sessions.resume_ttl());
        tracing::info!(
            principal = %ctx.principal,
            peer = %ctx.peer_addr,
            session_id = %id,
            replay_from,
            "session.attach authorized"
        );
        ControlMessage::response(
            request_id,
            response::Body::SessionAttached(wire::SessionAttached {
                ticket: ticket.to_vec(),
                new_resume_token: new_resume_token.expose().to_vec(),
                replay_from,
                writer_lease: true,
                expires_at,
                input_seq: input_from,
            }),
        )
    }

    // ------------------------------------------------------------------
    // tickets
    // ------------------------------------------------------------------

    fn issue_ticket(&self, conn_id: usize, purpose: TicketPurpose) -> [u8; TICKET_LEN] {
        let pending = Ticket {
            purpose,
            conn_id,
            expires_at: Instant::now() + TICKET_TTL,
        };
        let mut tickets = self.lock_tickets();
        let now = Instant::now();
        let expired = extract_tickets(&mut tickets, |p| p.expires_at > now);
        let ticket = loop {
            let mut ticket = [0u8; TICKET_LEN];
            rand::rng().fill_bytes(&mut ticket);
            if let std::collections::hash_map::Entry::Vacant(slot) = tickets.entry(ticket) {
                slot.insert(pending);
                break ticket;
            }
        };
        drop(tickets);
        // Same "collect under the guard, drop outside" discipline as
        // `pending_tickets_for` — see `extract_tickets`'s own doc.
        drop(expired);
        ticket
    }

    /// Redeem a ticket presented on `conn_id` by a stream of `kind`.
    /// Single use: a successful redemption removes it. Fails (returns
    /// `None`) if unknown, expired, malformed, issued to a different
    /// connection, or issued for a different stream kind.
    pub fn redeem_ticket(&self, conn_id: usize, kind: StreamKind, ticket: &[u8]) -> Option<Ticket> {
        let key: [u8; TICKET_LEN] = ticket.try_into().ok()?;
        let mut tickets = self.lock_tickets();
        let matches = tickets.get(&key).is_some_and(|p| {
            p.conn_id == conn_id && p.expires_at > Instant::now() && p.purpose.stream_kind() == kind
        });
        if matches { tickets.remove(&key) } else { None }
    }

    /// Periodic and last-chance quota housekeeping shared by
    /// [`Server::run`]'s own periodic tick, its post-loop shutdown call,
    /// [`Server::purge_connection`] (design §2.4 path ③), and
    /// `reverse::target`'s per-connection tick — `pub(crate)`, not
    /// private, so that last caller (a different module) can reach it
    /// without duplicating this pairing of calls or reaching into
    /// `Server`'s private `tickets`/`quotas`/`audit` fields itself.
    ///
    /// Two things, in order. First, sweep every expired, unredeemed
    /// ticket across *all* connections — same collect-under-the-guard,
    /// drop-outside shape as `pending_tickets_for` (main-session
    /// arbitration item 2, F7 of the M8 Step 3a conformance sweep): this
    /// bounds how long an expired unredeemed exec ticket can hold its
    /// `ExecPermit` to `TICKET_TTL` plus one tick, instead of "until the
    /// next request happens to reach `pending_tickets_for` or
    /// `issue_ticket`". Second, force-close every quota-rejection audit
    /// window past its staleness bound and write whatever summary/
    /// first-line records that produces to the audit sink
    /// (`crate::quota::Quotas::flush_expired`).
    pub(crate) fn quota_housekeeping(&self) {
        let expired_tickets = {
            let mut tickets = self.lock_tickets();
            let now = Instant::now();
            extract_tickets(&mut tickets, |p| p.expires_at > now)
        };
        // `expired_tickets`'s removed `Ticket`s (and any `ExecPermit`s
        // inside) drop here, after the tickets lock above has already
        // been released.
        drop(expired_tickets);

        let records = self.quotas.flush_expired(self.quotas.now());
        crate::audit::write_quota_audit(self.audit.as_ref(), &records);
    }

    /// The connection is gone: drop every ticket issued to it, abort every
    /// remote-forward listener it opened (`PLAN.md` M4 Step 4's
    /// connection-bound lifetime — see `Server::remote_forwards`'s own
    /// doc), and release every writer lease it held. Sessions (and their
    /// children) survive — that is the point of the broker
    /// (architecture.md §3 rule c).
    ///
    /// `held` is the connection-count permit this connection's slot was
    /// reserved with (`ConnectionPermit`, `PairingConnectionPermit`, or
    /// `()` from a test with nothing to hold) — M8 Step 3b ruling B3.
    /// It is released by this function, as its own last statement, once
    /// every other teardown step above has run to completion. A caller
    /// that wants the slot released *before* teardown finishes has no
    /// way to ask for that here: `held` is moved in by value, so passing
    /// anything other than the real permit — `None` on an `Option<..>`,
    /// say — is a visible, deliberate choice at the call site, exactly
    /// the kind of thing a reviewer is expected to catch. This replaces
    /// the source-text tripwire this function's call sites used to be
    /// pinned by (`the_connection_permit_is_released_after_purge_
    /// connection_not_before`, deleted): that test could not tell a
    /// same-line-text-but-early `drop` apart from the real thing (B3's
    /// own mutation demonstrated it surviving); ownership can.
    pub async fn purge_connection<P: Send>(&self, conn_id: usize, held: P) {
        // Collected under the tickets lock, dropped only after it (and
        // `remote_forwards`'s lock below) are released — main-session
        // arbitration item 2, F7 of the M8 Step 3a conformance sweep:
        // "collect under the guard, drop outside". A removed `Ticket` can
        // carry a `crate::quota::ExecPermit` whose own `Drop` takes the
        // quota lock; that lock is leaf-most (`docs/adr/0010-resource-
        // quotas.md` §9) precisely so it is safe to run *underneath*
        // another lock, but there is no reason to run it *while* this one
        // is still held.
        let expired_tickets = {
            let mut tickets = self.lock_tickets();
            extract_tickets(&mut tickets, |p| p.conn_id != conn_id)
        };
        // `conn_id`-scoped, not `owner`-scoped (`Server::remote_forwards`'s
        // own doc): a dead connection tears down every forward *it*
        // opened, regardless of whether the same principal still has a
        // live connection elsewhere. Same collect-under-guard shape as
        // `expired_tickets` above — `entry.task.abort()` runs after
        // `forwards`'s guard is released, not before.
        let dying_forwards: Vec<RemoteForwardEntry> = {
            let mut forwards = self.lock_remote_forwards();
            let dying: Vec<String> = forwards
                .iter()
                .filter(|(_, entry)| entry.conn_id == conn_id)
                .map(|(forward_id, _)| forward_id.clone())
                .collect();
            dying
                .into_iter()
                .filter_map(|forward_id| forwards.remove(&forward_id))
                .collect()
        };
        for entry in &dying_forwards {
            entry.task.abort();
        }
        self.sessions
            .release_connection(ConnectionId(conn_id as u64))
            .await;
        // Design §2.4 path ③ (main-session arbitration item 5, S2
        // deviation 2): a dying connection's own quota-rejection windows
        // must not linger open forever waiting for the next rejection or
        // the accept loop's periodic tick — this matters most for the
        // reverse **target** arm, whose per-connection loop has no
        // accept-loop tick of its own to lean on at all (`reverse::
        // target`'s own periodic flush, added alongside this call, covers
        // the case where the connection never dies).
        self.quota_housekeeping();
        // `expired_tickets`'/`dying_forwards`' removed values drop here,
        // after every lock this function took has already been released.
        drop(expired_tickets);
        drop(dying_forwards);
        // `held` (the connection-count permit) is released last, after
        // every other teardown step above has completed — B3's doc
        // comment on this function's signature is the actual contract;
        // this is the enforcement.
        drop(held);
    }

    // ------------------------------------------------------------------
    // connection driver
    // ------------------------------------------------------------------

    /// Emit (or suppress) one accept-loop heartbeat tick. `tracing::
    /// debug!` only — silent at the default `info` filter, visible under
    /// `QSH_LOG=debug` — and, per §3.2, logged only every 5th tick while
    /// every counter is unchanged from the last tick actually logged, so
    /// an idle 24h listener logs this line once every 5 s instead of once
    /// a second — that reduction, not silence: a fully idle listener
    /// still emits 17,280 lines over 24h, which is the point, not a bug.
    /// A tick where anything moved always logs
    /// immediately and resets the idle-tick counter.
    fn log_accept_heartbeat(
        &self,
        last_logged: &mut Option<AcceptHeartbeat>,
        ticks_since_log: &mut u32,
    ) {
        let admission = self.admission.counters();
        let quota = self.quotas.counters();
        let snapshot = AcceptHeartbeat {
            admitted: admission.admit,
            retry: admission.retry,
            ignore: admission.ignore,
            refuse: admission.refuse,
            connection_quota_refused: quota.connection_refused + quota.pairing_refused,
            live_conns: self.quotas.total_connections_in_use() as u64,
            // Purged, not `pending_tickets()` — an idle
            // listener with a backlog of expired-but-unswept tickets must
            // not read as "tickets outstanding".
            pending_tickets: self.pending_unexpired_tickets() as u64,
            quota_rejections: quota.rejections_total(),
        };
        let unchanged = last_logged.as_ref() == Some(&snapshot);
        if unchanged {
            *ticks_since_log += 1;
            if *ticks_since_log < 5 {
                return;
            }
        }
        *ticks_since_log = 0;
        *last_logged = Some(snapshot);
        tracing::debug!(
            target: "qsh_core::server",
            admitted = snapshot.admitted,
            retry = snapshot.retry,
            ignore = snapshot.ignore,
            refuse = snapshot.refuse,
            connection_quota_refused = snapshot.connection_quota_refused,
            live_conns = snapshot.live_conns,
            pending_tickets = snapshot.pending_tickets,
            quota_rejections = snapshot.quota_rejections,
            "accept loop heartbeat"
        );
    }

    /// Accept loop. Runs until `shutdown` resolves or the listener closes,
    /// then [`drain`](Self::drain)s the host and closes the endpoint.
    pub async fn run(
        self: Arc<Self>,
        listener: Listener,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        // Bounded-latency admission-audit flush (`PLAN.md` M8 Step 2
        // verification round, P1-3/F1): a flood that stops still gets its
        // last (possibly partial) aggregation window's summary within one
        // more tick, instead of only ever flushing lazily on the *next*
        // rejection — which, once the flood truly ends, may be never.
        // `MissedTickBehavior::Delay` (not `Burst`): if this loop is ever
        // busy long enough to miss a tick, catching up with a burst of
        // ticks would only replay `flush_expired` against a `now` that has
        // already moved past every window it could still meaningfully
        // close — a single delayed tick is strictly better here.
        let mut audit_flush = tokio::time::interval(crate::admission::AUDIT_AGGREGATION_WINDOW);
        audit_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Accept-loop heartbeat (M8 Step 5a): a 1 s tick in the same
        // `select!` as the accept arm and the audit-flush tick, so it
        // shares this loop's own scheduling rather than running on a
        // separate task that could observe a different `now`. Silent at
        // the default (info) filter — `tracing::debug!` only, visible
        // under `QSH_LOG=debug` — and rate-limited to once every 5 ticks
        // while every counter it reports is unchanged from the last tick
        // it actually logged, so a 24h idle listener logs this line once
        // every 5 s instead of once a second.
        let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_logged_heartbeat: Option<AcceptHeartbeat> = None;
        let mut ticks_since_heartbeat_log: u32 = 0;
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                incoming = listener.accept() => {
                    let Some(incoming) = incoming else { break };
                    self.clone().admit(incoming);
                }
                _ = audit_flush.tick() => {
                    let records = self.admission.flush_expired(self.admission.now());
                    crate::audit::write_admission_audit(self.audit.as_ref(), &records);
                    // Same bounded-latency rationale, for the quota
                    // rejection windows (`PLAN.md` M8 Step 3, `docs/adr/
                    // 0010-resource-quotas.md` §2.4): a flood that has
                    // already stopped still gets its last window's summary
                    // within one more tick instead of only on the next
                    // rejection, which — once the flood truly ends — may be
                    // never.
                    self.quota_housekeeping();
                }
                _ = heartbeat.tick() => {
                    self.log_accept_heartbeat(&mut last_logged_heartbeat, &mut ticks_since_heartbeat_log);
                }
            }
        }
        // One more flush on the way out — a shutdown that lands mid-window
        // must not strand that window's summary forever (nothing will ever
        // tick this interval again after this function returns).
        let records = self.admission.flush_expired(self.admission.now());
        crate::audit::write_admission_audit(self.audit.as_ref(), &records);
        self.quota_housekeeping();
        // SIGTERM graceful drain (CLI.md §6.12, ADR-0003) runs *before* the
        // listener closes: closing it first would sever every control
        // stream — including the ones carrying `session.closed` to an
        // attached consumer — before `drain` gets a chance to send it.
        self.drain().await;
        listener.close(0, b"shutdown");
        listener.endpoint().wait_idle().await;
    }

    /// L2-L4 of the L0-L5 admission ordering (`PLAN.md` M8 Step 2,
    /// `docs/adr/0009-admission-defenses.md`): consult [`Self::admission`]
    /// synchronously (`crate::admission::Gate::decide` never awaits) and
    /// dispatch the `Incoming` accordingly, *before* spawning anything.
    /// A rejected attempt (`Retry`/`Ignore`/`Refuse`) is therefore
    /// resolved — and its slab slot freed — without ever costing a task;
    /// only an admitted attempt is handed to a spawned
    /// [`Self::accept_and_serve_permitted`], so the (potentially slow) TLS
    /// handshake runs off this accept loop.
    fn admit(self: Arc<Self>, incoming: Incoming) {
        let peer = incoming.remote_address();
        let validated = incoming.remote_address_validated();
        let now = self.admission.now();
        match self.admission.decide(peer, validated, now) {
            crate::admission::Decision::Retry => {
                if let Err(returned) = incoming.retry() {
                    // Should be unreachable — `decide` only returns
                    // `Retry` when `!validated`, and quinn's own contract
                    // (`qsh_transport::endpoint`'s
                    // `retry_on_validated_incoming_errs`) guarantees an
                    // unvalidated `Incoming` may always retry. Fail safe
                    // rather than loop: drop the attempt with no state
                    // left behind.
                    returned.ignore();
                }
            }
            crate::admission::Decision::Ignore(_, records) => {
                crate::audit::write_admission_audit(self.audit.as_ref(), &records);
                incoming.ignore();
            }
            crate::admission::Decision::Refuse(_, records) => {
                crate::audit::write_admission_audit(self.audit.as_ref(), &records);
                incoming.refuse();
            }
            crate::admission::Decision::Admit(permit) => {
                tokio::spawn(async move {
                    self.accept_and_serve_permitted(incoming, |_| {}, Some(permit))
                        .await;
                });
            }
        }
    }

    /// Accept one inbound connection and drive it: run the handshake, audit
    /// a rejection with its category, then serve the verified connection.
    /// `on_accept` observes that connection after verification and before it
    /// is served.
    ///
    /// [`run`](Self::run) reaches this only through `Self::admit`, which
    /// already consulted `Self::admission` and is holding the resulting
    /// handshake permit. It is still a public seam with no permit
    /// (`accept_and_serve`, below) so an alternative accept loop —
    /// `qsh-testkit`'s L4 chaos harness runs one, to watch the host-side
    /// peer address across a migration — reuses the rejection/audit path
    /// instead of copying it, without needing a `Gate` of its own.
    pub async fn accept_and_serve(
        self: Arc<Self>,
        incoming: Incoming,
        on_accept: impl FnOnce(&Connection),
    ) {
        self.accept_and_serve_permitted(incoming, on_accept, None)
            .await;
    }

    /// [`Self::accept_and_serve`] plus an optional handshake permit,
    /// dropped the instant [`qsh_transport::Incoming::accept`] resolves —
    /// success or failure — and strictly before [`Self::serve_connection`]
    /// runs (`crate::admission::Decision::Admit`'s own doc: a handshake
    /// slot must never outlive the handshake itself).
    async fn accept_and_serve_permitted(
        self: Arc<Self>,
        incoming: Incoming,
        on_accept: impl FnOnce(&Connection),
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) {
        let peer = incoming.remote_address();
        let result = incoming.accept().await;
        drop(permit);
        match result {
            Ok(conn) => {
                on_accept(&conn);
                self.serve_connection(conn).await;
            }
            Err(err) => {
                let category = match &err {
                    qsh_transport::AcceptError::Unverified(reason) => {
                        format!("{reason:?}").to_lowercase()
                    }
                    _ => "handshake".to_string(),
                };
                // Already rejecting the connection outright: a failure to
                // record it doesn't change the outcome (there is nothing
                // left to deny), only the diagnostic — same exception as
                // the resume-credential deny above.
                if let Err(audit_err) = self
                    .audit
                    .record(&AuditRecord::handshake_rejected(peer, &category))
                {
                    tracing::warn!(%peer, %audit_err, "failed to record handshake rejection");
                }
                tracing::warn!(%peer, %err, "connection rejected");
            }
        }
    }

    /// Drive one authenticated connection to completion.
    ///
    /// M8 Step 3b (rulings R2/R3): the connection-count quota is reserved
    /// **here**, before `Self::serve_connection_inner` ever runs — a
    /// peer that never sends `Hello` at all is still counted — and
    /// released only after [`Self::purge_connection`] below (never
    /// earlier: a dead connection's forwards must never outlive its
    /// slot). `Principal::Pairing` uses a separate, fixed axis
    /// ([`crate::quota::Quotas::reserve_pairing_connection`]) and, on
    /// refusal, never reaches `serve_connection_inner`/`handshake::
    /// respond` at all — no stream accepted, no proof read, no frame
    /// written, just an immediate [`CLOSE_CODE_RESOURCE_EXHAUSTED`]
    /// close (ruling R2: the cap this guards is itself non-distinguishing
    /// from every other pairing refusal). A regular refusal instead lets
    /// `serve_connection_inner` run with `refused: Some(kind)`, so the
    /// peer still gets a normal `RESOURCE_EXHAUSTED` `Hello` reply
    /// through the ordinary drained-rejection path (ruling R3) — the
    /// out-param this function threads through is the one new parameter
    /// that ruling allows.
    pub async fn serve_connection(self: Arc<Self>, conn: Connection) {
        let peer_addr = conn.remote_address();
        let principal = conn.principal().clone();
        let conn_id = conn.stable_id();
        tracing::info!(%principal, peer = %peer_addr, "connection accepted");

        if *conn.principal() == Principal::Pairing {
            match self.quotas.reserve_pairing_connection() {
                Ok(permit) => {
                    let result = self.clone().serve_connection_inner(&conn, None).await;
                    self.purge_connection(conn_id, permit).await;
                    self.log_and_close_on_error(&conn, &principal, peer_addr, result);
                }
                Err(kind) => {
                    // Ruling R2: audited with the connection's own
                    // `principal().to_string()`, not `opener_key` — a
                    // pairing principal has no `auth_path` worth folding
                    // in (pre-identity), and the ADR's own §6 table names
                    // this field by the bare principal.
                    let records = self.quotas.record_rejection(
                        kind,
                        &principal.to_string(),
                        peer_addr,
                        self.quotas.now(),
                        None,
                        conn.auth_path(),
                    );
                    crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                    conn.close(CLOSE_CODE_RESOURCE_EXHAUSTED, b"at capacity");
                }
            }
            return;
        }

        let opener = opener_key(conn.principal(), conn.auth_path());
        let (permit, refused) = match self.quotas.reserve_connection(&opener) {
            Ok(permit) => (Some(permit), None),
            Err(kind) => {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    peer_addr,
                    self.quotas.now(),
                    None,
                    conn.auth_path(),
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                (None, Some(kind))
            }
        };

        let result = self.clone().serve_connection_inner(&conn, refused).await;
        self.purge_connection(conn_id, permit).await;
        self.log_and_close_on_error(&conn, &principal, peer_addr, result);
    }

    /// Shared tail of [`Self::serve_connection`]'s two branches (pairing
    /// and regular): the same logging/close-on-protocol-error behavior
    /// this function's body used to inline once, before the connection
    /// quota reservation above needed two separate call sites for it.
    fn log_and_close_on_error(
        &self,
        conn: &Connection,
        principal: &Principal,
        peer_addr: SocketAddr,
        result: Result<(), ConnError>,
    ) {
        match result {
            Ok(()) => tracing::info!(%principal, peer = %peer_addr, "connection closed"),
            // The peer went away (closed, idle timeout, reset). Ordinary
            // for a mobile client — informational, not a protocol fault.
            Err(err) if err.is_connection_lost() => {
                tracing::info!(%principal, peer = %peer_addr, %err, "connection lost");
            }
            Err(err) => {
                tracing::warn!(%principal, peer = %peer_addr, %err, "connection ended with protocol error");
                conn.close(CLOSE_CODE_PROTOCOL, b"protocol error");
            }
        }
    }

    async fn serve_connection_inner(
        self: Arc<Self>,
        conn: &Connection,
        refused: Option<crate::quota::QuotaKind>,
    ) -> Result<(), ConnError> {
        // ADR-0002 / M7 Step 4's structural guarantee (report §B1): a
        // pairing-authenticated connection never reaches `handshake::
        // respond`, `ConnCtx`, `Self::dispatch` or the ACL choke point at
        // all — it is routed to `serve_pairing_connection`, whose only
        // reachable code path can verify one proof, maybe pin, and close.
        // This is checked *before* anything else in this function, so "no
        // resource before pairing verification succeeds" is guaranteed by
        // the shape of the code, not by an ACL rule a future refactor could
        // misconfigure or bypass.
        if *conn.principal() == Principal::Pairing {
            return self.serve_pairing_connection(conn).await;
        }

        let (ctl, peer_hello) = crate::handshake::respond(conn, |peer_hello| {
            // M8 Step 3b ruling R3: the connection-count refusal decided
            // in `Self::serve_connection`, before this callback ever ran,
            // surfaces first — ahead of the reverse-registration check
            // below. It is unrelated to anything this peer's `Hello`
            // says (the cap was already exceeded the instant this
            // connection was accepted), so nothing about `peer_hello`
            // could change the answer; checking it first also means a
            // saturated host never spends a cycle deciding whether this
            // would-be registration is otherwise well-formed.
            if let Some(kind) = refused {
                return Err(wire::Error::new(
                    ErrorCode::ResourceExhausted,
                    kind.wire_message(),
                    true,
                ));
            }
            // A forward host does not accept registrations — the
            // symmetric-protocol counterpart of `qsh listen` refusing a
            // peer with no `Hello.reverse` at all (`docs/design/
            // protocol.md` §11-2, `PLAN.md` M3 Step 3). Zero resources:
            // this runs inside `respond`'s callback, strictly before any
            // session/ticket/registry state could exist, and the rejection
            // error frame this writes gets the same bounded drain as every
            // other decline on this seam (`handshake::REJECTION_DRAIN_TIMEOUT`).
            if peer_hello.reverse.is_some() {
                return Err(wire::Error::new(
                    ErrorCode::Unsupported,
                    "this host does not accept reverse registrations",
                    false,
                ));
            }
            Ok(self.local_hello(None))
        })
        .await
        .map_err(map_hello_error)?;

        let ctx = ConnCtx {
            principal: conn.principal().clone(),
            auth_path: conn.auth_path(),
            peer_fingerprint: conn
                .peer_fingerprint()
                .map(|fp| PeerFingerprint::new(*fp.as_bytes())),
            peer_addr: conn.remote_address(),
            conn_id: conn.stable_id(),
            capabilities: crate::handshake::negotiated_capabilities(&peer_hello),
            // A forward `qsh serve` connection: `Hello.reverse` was
            // refused above, so this is never a shared registration
            // (`ConnCtx::is_reverse_registration`'s own doc).
            is_reverse_registration: false,
        };

        // `None`: a forward `qsh serve` host relies on the *client's* own
        // `ops/session.rs` recovery driver to notice a dead path — nobody
        // here needs to watch this connection's own liveness
        // (`serve_control`'s `probe` doc comment).
        self.serve_control(conn, ctl, ctx, None).await
    }

    /// Answer a `Principal::Pairing` connection (ADR-0002, `PLAN.md` M7
    /// Step 4): verify the initiator's proof against this host's own
    /// invite store, and — only once that verification succeeds — pin the
    /// initiator into `trust.toml` via the same
    /// [`crate::trust::TrustStore::add_peer`] path `qsh trust add` uses
    /// (Step 2's content-based reload picks the write up on this host's own
    /// [`crate::trust::SharedTrustStore`] without a restart, invariant #6).
    ///
    /// This is the *only* code such a connection ever reaches — routed here
    /// from [`Self::serve_connection_inner`] before `handshake::respond`,
    /// `ConnCtx` or [`Self::dispatch`] are ever touched, so "no resource
    /// before pairing verification succeeds" (this step's brief invariant
    /// #1) is a property of the call graph, not a check a future refactor
    /// could accidentally bypass.
    ///
    /// Unlike `trust add`'s own deliberate silent no-op on a name collision
    /// (`TrustStore::add_peer`'s own doc, `PLAN.md` M7 Step 2 decision B),
    /// pairing fails loudly on one (invariant #5): the `try_pin` hook below
    /// returns `false` on a collision, which `crate::pairing::respond` turns
    /// into `PairingError::PinCollision` (`SESSION_CONFLICT`) — and because
    /// that hook runs *before* the matched invite is marked consumed
    /// (`crate::trust::pairing::SharedInviteStore::redeem`'s `on_matched`),
    /// the invite is left entirely untouched, so a renamed or removed
    /// conflicting pin can retry within the same TTL.
    async fn serve_pairing_connection(self: Arc<Self>, conn: &Connection) -> Result<(), ConnError> {
        let peer_addr = conn.remote_address();

        // Structurally unreachable under correct startup wiring
        // (`crate::serve`'s host runtime calls `Server::set_pairing` with
        // the very evaluator `qsh_transport::TrustEvaluator::pairing_open`
        // answered `true` from), but a connection has already been admitted
        // by the time this runs — a misconfigured caller (a stray test
        // harness, a future embedder) fails closed with a clear diagnostic
        // rather than panicking.
        let Some(state) = self.pairing.get() else {
            tracing::error!(
                "pairing-principal connection admitted but no pairing store is attached; closing"
            );
            let _ = self.audit.record(&AuditRecord::pairing(
                peer_addr,
                Decision::Deny,
                "not-configured",
            ));
            conn.close(CLOSE_CODE_PROTOCOL, b"pairing not configured");
            return Ok(());
        };

        // Likewise structurally unreachable in practice (mutual TLS always
        // yields a peer certificate once the handshake itself completed),
        // but `peer_fingerprint()` is an `Option`, so this stays fail-closed
        // rather than unwrapping.
        let Some(observed_fp) = conn.peer_fingerprint() else {
            tracing::error!("pairing connection has no peer certificate fingerprint; closing");
            let _ = self.audit.record(&AuditRecord::pairing(
                peer_addr,
                Decision::Deny,
                "no-fingerprint",
            ));
            conn.close(CLOSE_CODE_PROTOCOL, b"no peer certificate");
            return Ok(());
        };

        let trust = &state.trust;
        let result =
            crate::pairing::respond(conn, &state.invites, &self.device_name, |initiator_name| {
                let path = trust.path();
                // Whole load→mutate→save under lock, not just the write —
                // same discipline as `Ops::trust_add`/`trust_remove`
                // (`TrustStore::lock`'s own doc, `PLAN.md` M7 Step 7-1
                // S1). This closure runs synchronously inside
                // `SharedInviteStore::redeem`, which already holds its
                // cache `RwLock` — that lock is acquired first, this one
                // second, matching `TrustStore::lock`'s required order.
                // Blocking here (a `flock` wait, then a small TOML
                // rewrite) briefly parks the current tokio worker thread;
                // see `PLAN.md` M7 Step 7-1's report for why that is
                // accepted rather than moved to `spawn_blocking`.
                let _lock = match crate::trust::TrustStore::lock(path) {
                    Ok(lock) => lock,
                    Err(err) => {
                        tracing::error!(%err, "failed to lock the trust store during pairing");
                        return false;
                    }
                };
                let mut store = match crate::trust::TrustStore::load(path) {
                    Ok(store) => store,
                    Err(err) => {
                        tracing::error!(%err, "failed to load the trust store during pairing");
                        return false;
                    }
                };
                let (peer, created, updated) = store.add_peer(
                    initiator_name,
                    None,
                    observed_fp,
                    crate::config::now_rfc3339(),
                );
                if !created && !updated && peer.fingerprint != observed_fp.to_string() {
                    tracing::warn!(
                        name = %initiator_name,
                        "pairing declined: name already pinned under a different identity"
                    );
                    return false;
                }
                if (created || updated)
                    && let Err(err) = store.save(path)
                {
                    tracing::error!(%err, "failed to persist the trust store during pairing");
                    return false;
                }
                true
            })
            .await;

        match result {
            Ok(success) => {
                tracing::info!(peer = %success.peer_device_name, "pairing succeeded");
                let _ = self.audit.record(&AuditRecord::pairing(
                    peer_addr,
                    Decision::Allow,
                    &success.peer_device_name,
                ));
                conn.close(0, b"paired");
                Ok(())
            }
            Err(err) => {
                if !err.is_connection_lost() {
                    let category = pairing_audit_category(&err);
                    let _ = self.audit.record(&AuditRecord::pairing(
                        peer_addr,
                        Decision::Deny,
                        category,
                    ));
                    tracing::warn!(%err, "pairing exchange failed");
                }
                Err(ConnError::Pairing(err))
            }
        }
    }

    /// Drive the dispatch loop over an already-negotiated control stream
    /// (`ctl`, with `ctx` already built from the completed `Hello`
    /// exchange). Public for the same reason [`Self::accept_and_serve`] is:
    /// a caller that establishes the control stream a different way reaches
    /// this same dispatch loop instead of duplicating it. Two such callers
    /// exist — M3's reverse-target path (`qsh-core`'s own
    /// `reverse::target::run_reverse`, which dials out and runs
    /// [`crate::handshake::initiate`] with the *host* role instead of
    /// [`crate::handshake::respond`]), and `qsh-testkit`'s role-swapped
    /// connected-pair harness (`crates/qsh-testkit/src/reverse.rs`'s
    /// `ReversePairHarness`, `PLAN.md` M3 Step 3 PR 3b's role-axis-
    /// independence proof), which needs this reachable from outside the
    /// crate — hence `pub`, not `pub(crate)`.
    ///
    /// `probe`, when `Some`, wires this connection's own outbound liveness
    /// `Ping`/`Pong` correlation (`docs/design/protocol.md` §10/§11-4,
    /// `PLAN.md` M3 Step 4 "target 재접속"): a [`ControlPinger`] is built
    /// from the given [`crate::client::pathwatch::PathWatch`] over this
    /// call's own `reply_tx` (so a probe queues behind whatever this
    /// connection is already sending, exactly like every other reply —
    /// `ControlPinger`'s own doc comment), [`drive_probes`] is spawned into
    /// this call's `blocking` set (so it is aborted alongside every other
    /// per-connection task on the way out, never outliving the
    /// connection), and every inbound [`ControlMessage`] is offered to
    /// [`ControlPinger::record`] before it reaches [`Self::dispatch`] — a
    /// correlated `Pong` is consumed there and never dispatched (there is
    /// nothing for `dispatch` to do with a `Pong` either way); an inbound
    /// `Ping` this pinger didn't send counts as bare liveness only (under
    /// symmetric probing it is the peer's own probe loop, never real
    /// traffic — `ControlPinger::record`'s doc comment), and everything
    /// else counts as this connection's own session traffic
    /// ([`crate::client::pathwatch::PathWatch::traffic`]), matching the
    /// module doc's "any inbound traffic … proves the path carries
    /// packets". `None` (forward `qsh serve` hosts, and `qsh-testkit`'s
    /// pair harness) leaves this call byte-for-byte what it was before
    /// M3 Step 4 — a peer `Ping` still gets an ordinary `Pong` reply via
    /// [`Self::dispatch`], there is just nobody watching *this*
    /// connection's own liveness from the host side.
    pub async fn serve_control(
        self: Arc<Self>,
        conn: &Connection,
        mut ctl: FramedStream,
        ctx: ConnCtx,
        probe: Option<(
            crate::client::pathwatch::PathWatch,
            Arc<tokio::sync::Notify>,
        )>,
    ) -> Result<(), ConnError> {
        // Control messages are handled inline, in arrival order, so the
        // control stream keeps its ordering guarantee for mutating ops. The
        // two exceptions never park this loop:
        //
        // - `is_long_poll` (the `SessionRead` long-poll and `SessionClose`'s
        //   escalation) runs in tasks owned by `blocking` (bounded by
        //   `inflight`);
        // - `SessionWrite` is *split*: its ACL decision, audit record and
        //   lease take run inline (bounded — the session actor never blocks
        //   on the child), and only the handoff to the PTY, which parks for
        //   as long as the child refuses to drain its input buffer, goes on
        //   the per-connection `writes` queue. One queue, so two pipelined
        //   writes still reach the child in arrival order (protocol.md §9),
        //   and a wedged child costs at most `RESOURCE_EXHAUSTED` on further
        //   writes instead of freezing every other op on the connection.
        //   The queue is per *connection*, not per session, so a wedged
        //   child does eventually exhaust the backlog shared with the
        //   connection's other sessions — a bounded, retryable refusal, not
        //   a stall. Per-session queues would need their own cap on how
        //   many a peer may create; that is a separate change.
        //
        // All replies funnel back through `reply_rx` to the single
        // control-stream writer. Nothing may outlive the connection, but
        // dropping a `JoinSet` only *requests* an abort — a parked task can
        // still be mid-`await` on the session actor when `purge_connection`
        // runs and re-take the lease it just released. `blocking.shutdown()`
        // below is what actually joins every task before this function
        // returns, so `purge_connection` sees the connection's final state.
        let (reply_tx, mut reply_rx) =
            tokio::sync::mpsc::channel::<ControlMessage>(MAX_INFLIGHT_REQUESTS_PER_CONN);
        let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_REQUESTS_PER_CONN));
        let mut blocking: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

        // This connection's own outbound liveness probing (`probe`'s doc
        // comment above): built over `reply_tx` so a `Ping` queues exactly
        // like any other reply, and `drive_probes` is owned by `blocking`
        // so it is aborted alongside every other per-connection task when
        // this function returns (`blocking.shutdown()` below) rather than
        // outliving the connection.
        let pinger = probe.map(|(watch, probes)| {
            let pinger = Arc::new(ControlPinger::new(watch, reply_tx.clone()));
            let driver = pinger.clone();
            blocking.spawn(async move { drive_probes(driver, probes).await });
            pinger
        });

        let (writes_tx, mut writes_rx) =
            tokio::sync::mpsc::channel::<PendingWrite>(MAX_INFLIGHT_REQUESTS_PER_CONN);
        {
            let server = self.clone();
            let reply_tx = reply_tx.clone();
            blocking.spawn(async move {
                while let Some(pending) = writes_rx.recv().await {
                    let reply = server.finish_session_write(pending).await;
                    if reply_tx.send(reply).await.is_err() {
                        return;
                    }
                }
            });
        }

        // Nothing detached may still be running when `purge_connection`
        // releases this connection's leases: `JoinSet::drop` only *requests*
        // an abort, so a data stream that already queued its `TakeLease`
        // could have it applied after the release and pin the lease to a
        // dead connection for ever. `shutdown().await` below joins every
        // task first, which is the ordering protocol.md §9 requires.
        let result: Result<(), ConnError> = async {
            loop {
                tokio::select! {
                    msg = ctl.recv.recv::<ControlMessage>() => match msg {
                        Ok(Some(msg)) => {
                            if let Some(pinger) = &pinger {
                                // A correlated `Pong` is this pinger's own
                                // answer — consumed, and never reaches
                                // `dispatch` (which has nothing to do with
                                // a `Pong` anyway, `Body::Pong(_) => None`
                                // below). Anything else clears every
                                // outstanding probe and is reported to
                                // `watch` — bare liveness for an inbound
                                // `Ping` (under symmetric probing that is
                                // the peer's own probe loop, not real
                                // traffic), full traffic for everything
                                // else. See [`ControlPinger::record`].
                                if pinger.record(&msg) {
                                    continue;
                                }
                            }
                            if let Some(control_message::Body::SessionWrite(req)) = &msg.body {
                                // Reserve the queue slot *before* authorizing,
                                // so a full backlog never leaves a lease taken
                                // for a write we then refuse.
                                let Ok(slot) = writes_tx.try_reserve() else {
                                    ctl.send.send(&ControlMessage::error(
                                        msg.request_id,
                                        wire::Error::new(
                                            ErrorCode::ResourceExhausted,
                                            "session input backlog is full on this connection",
                                            true,
                                        ),
                                    )).await?;
                                    continue;
                                };
                                match self.prepare_session_write(&ctx, msg.request_id, req).await {
                                    Ok(pending) => slot.send(pending),
                                    Err(reply) => ctl.send.send(&reply).await?,
                                }
                                continue;
                            }
                            // `RemoteForwardOpen` needs a live `Connection`
                            // to open this forward's future `TCP_ACCEPTED`
                            // streams on — `dispatch` has none
                            // (`Server::handle_rfwd_open`'s own doc), so it
                            // is intercepted here, the same shape as the
                            // `SessionWrite` special case just above.
                            if let Some(control_message::Body::RfwdOpen(req)) = &msg.body {
                                let reply = self
                                    .handle_rfwd_open(&ctx, conn, msg.request_id, req)
                                    .await;
                                ctl.send.send(&reply).await?;
                                continue;
                            }
                            if !is_long_poll(&msg) {
                                if let Some(reply) = self.dispatch(&ctx, &msg).await {
                                    ctl.send.send(&reply).await?;
                                }
                                continue;
                            }
                            let Ok(permit) = inflight.clone().try_acquire_owned() else {
                                ctl.send.send(&ControlMessage::error(
                                    msg.request_id,
                                    wire::Error::new(
                                        ErrorCode::ResourceExhausted,
                                        "too many requests in flight on this connection",
                                        true,
                                    ),
                                )).await?;
                                continue;
                            };
                            let server = self.clone();
                            let ctx = ctx.clone();
                            let reply_tx = reply_tx.clone();
                            blocking.spawn(async move {
                                let reply = server.dispatch(&ctx, &msg).await;
                                drop(permit);
                                if let Some(reply) = reply {
                                    // The connection driver may be gone; then
                                    // there is nobody to answer.
                                    let _ = reply_tx.send(reply).await;
                                }
                            });
                        }
                        Ok(None) => return Ok(()),
                        Err(err) => return Err(err.into()),
                    },
                    Some(reply) = reply_rx.recv() => {
                        ctl.send.send(&reply).await?;
                    }
                    // Reap finished tasks so the set never grows unbounded.
                    Some(_) = blocking.join_next(), if !blocking.is_empty() => {}
                    stream = conn.accept_bi() => match stream {
                        Ok((send, recv)) => {
                            let server = self.clone();
                            let ctx = ctx.clone();
                            let conn = conn.clone();
                            let events = reply_tx.clone();
                            // Owned by `blocking`, so a data stream — and the
                            // attach token that suspends its session's resume
                            // TTL — can never outlive the connection.
                            blocking.spawn(async move {
                                server.handle_data_stream(
                                    ctx,
                                    FramedStream::data(send, recv),
                                    conn,
                                    events,
                                ).await;
                            });
                        }
                        Err(_) => return Ok(()),
                    },
                }
            }
        }
        .await;
        blocking.shutdown().await;
        result
    }

    /// Host side of a local forward (`-L`): a peer-opened `TCP_CONNECT`
    /// stream asking this host to dial `header.host:header.port` and splice
    /// the bytes.
    ///
    /// **Why the ACL check is inline here and not at the control-stream
    /// choke point** (`docs/design/protocol.md` §7, `PLAN.md` M4 Step 3):
    /// every other data stream must first redeem a ticket that a control
    /// request already got authorized for, which is what makes "no resource
    /// before authorization" structural. `TCP_CONNECT` is §7's *sole*
    /// exception — one TCP connection through the forward would otherwise
    /// cost a full control-stream RPC round-trip before its first byte,
    /// which is exactly the latency a port forward exists to avoid. The
    /// exception is to the *ticket*, never to the authorization: this
    /// function runs [`Authorizer::check`] + [`AuditRecord`] as the very
    /// first thing it does with the destination, and only a `Decision::
    /// Allow` can reach the dialer below. On a deny nothing is dialed, no
    /// socket exists, and the stream is refused — the same posture the
    /// ticket would have enforced, moved inline (`docs/PRD.md` §9,
    /// `docs/design/architecture.md` §6).
    ///
    /// **Concurrency bound.** Nothing here caps how many `TCP_CONNECT`
    /// streams one connection may have in flight, because the transport
    /// already does: `qsh_transport::endpoint::MAX_CONCURRENT_BIDI_STREAMS`
    /// (1024) is the peer's whole bidi-stream allowance, so concurrent
    /// tunnel splices — and the upstream fds they hold open — are bounded
    /// at 1024 per connection, on a peer that is mTLS-pinned to begin with
    /// (the M1-M4 interim allow-all-pinned posture). A tunnel-specific
    /// quota tighter than that connection-wide cap (per principal, per
    /// forward) **is** M8 Step 3b scope now:
    /// [`Server::authorize_and_dial_tunnel`]'s [`crate::quota::
    /// TunnelStreamPermit`] is held for this whole function's lifetime
    /// (bound below, released only when this function returns — normal
    /// completion, error, or task-abort unwind alike), so the splice
    /// itself never has to know the quota exists.
    async fn handle_tcp_connect(
        &self,
        ctx: &ConnCtx,
        mut stream: FramedStream,
        header: &StreamHeader,
    ) {
        // Tunnel bytes must never outrank a PTY chunk in the local send
        // queue (`docs/design/protocol.md` §12). Set before anything is
        // written on this stream, including the `ConnectResult`.
        stream.send.set_priority(wire::PRIORITY_TUNNEL);

        // `SystemDialer::default()` carries the production
        // `TUNNEL_DIAL_TIMEOUT`; only tests ever build one with a
        // different bound.
        let dialed = self
            .authorize_and_dial_tunnel(ctx, header, &SystemDialer::default())
            .await;

        let (upstream, _permit) = match dialed {
            Err(rejection) => {
                // §7 requires the requester learn *why*, so the refusal is
                // a `ConnectResult` frame and a clean FIN — `reset()` here
                // would discard the frame we just wrote and leave the peer
                // guessing. The refusal is still terminal: the receive half
                // is stopped, nothing was dialed, nothing is spliced.
                // The teardown signal alongside it is picked to match the
                // reason, so a peer reading only the QUIC code is not
                // misinformed: a policy refusal is `FORBIDDEN`, a
                // malformed destination is `BAD_HEADER`, and a destination
                // that simply would not accept is nobody's protocol error
                // — code 0, "we are just done reading".
                let stop_code = match rejection.code.parse::<ErrorCode>() {
                    Ok(ErrorCode::PermissionDenied) => RESET_CODE_FORBIDDEN,
                    Ok(ErrorCode::InvalidArgument) => RESET_CODE_BAD_HEADER,
                    Ok(ErrorCode::ResourceExhausted) => RESET_CODE_RESOURCE_EXHAUSTED,
                    _ => 0,
                };
                let _ = stream.send.send(&rejection).await;
                let _ = stream.send.finish();
                stream.recv.stop(stop_code);
                return;
            }
            Ok((upstream, permit)) => {
                if stream
                    .send
                    .send(&wire::ConnectResult {
                        ok: true,
                        code: String::new(),
                        message: String::new(),
                    })
                    .await
                    .is_err()
                {
                    // Peer went away between the dial and the reply; drop
                    // the freshly-dialed socket (and the quota permit
                    // with it) rather than splice into nothing.
                    return;
                }
                // `permit` is carried out to the outer `let` below — held
                // until this function returns (see the doc comment above
                // `handle_tcp_connect`, `crate::quota::TunnelStreamPermit`).
                (upstream, permit)
            }
        };

        // Framing ends with the `ConnectResult{ok:true}` just written: from
        // here this stream is a raw, unframed byte pipe in both directions
        // (`docs/design/protocol.md` §5, §7), so both halves are
        // surrendered to `crate::tunnel::splice`, which copies bytes
        // without parsing or logging a single one of them (`CLAUDE.md`
        // "never log payload"). `into_raw` on the receive half also hands
        // back whatever the requester pipelined behind its `StreamHeader`
        // frame — bytes already read into the frame decoder, which the
        // splice must write to the destination *first* or the forwarded
        // connection loses its own first bytes.
        let (send, recv) = stream.split();
        let (raw_recv, residue) = recv.into_raw();
        let outcome = splice_tcp_quic(upstream, send.into_raw(), raw_recv, residue).await;

        // Structural only: destination and byte counts, never payload
        // (`PLAN.md` M4 §4 "터널 payload 로그 금지" — `SpliceStats` has no
        // field a payload byte could hide in).
        match outcome {
            // `sent`/`received` are **this end's** view of the tunnel, the
            // same convention the requester's own log uses
            // (`crate::tunnel::local::LocalForward::run`): `sent` is what
            // this process pushed into the tunnel stream, `received` is
            // what it took out of it. So the field-to-label mapping is
            // identical on both ends — `local_to_remote` is always the
            // splice's TCP-socket-to-tunnel direction, hence always
            // `sent` — even though "local" names a different socket on
            // each end (here the dialed destination, there the local
            // application). Reading one tunnel's two logs, this host's
            // `received` is the requester's `sent` and vice versa, which
            // is what endpoint-relative counters are supposed to say.
            Ok(stats) => tracing::debug!(
                principal = %ctx.principal,
                host = header.host,
                port = header.port,
                sent = stats.local_to_remote,
                received = stats.remote_to_local,
                "tunnel: local forward closed"
            ),
            Err(err) => tracing::debug!(
                principal = %ctx.principal,
                host = header.host,
                port = header.port,
                %err,
                "tunnel: local forward aborted"
            ),
        }
    }

    /// The `forward.local` gate, factored out of [`Server::handle_tcp_connect`]
    /// so it is testable with no transport at all: **authorize, then — and
    /// only then — dial**.
    ///
    /// Order is the whole contract of this function:
    /// 1. shape-check the destination (nothing created, no decision made);
    /// 2. [`Server::authorize_stream`] — `Authorizer::check` + one
    ///    [`AuditRecord`] line for allow *and* deny alike;
    /// 3. `dialer.dial(...)` — unreachable unless step 2 returned allow.
    ///
    /// A local forward's destination is chosen by the requester and is
    /// **not** restricted here (unlike `-R`'s loopback-only bind, Step 4):
    /// `host:port` is the ACL resource, so restricting destinations is the
    /// policy engine's job (M5), not this code's.
    ///
    /// `Err` is the [`wire::ConnectResult`] to hand the requester verbatim.
    pub(crate) async fn authorize_and_dial_tunnel(
        &self,
        ctx: &ConnCtx,
        header: &StreamHeader,
        dialer: &dyn TunnelDialer,
    ) -> Result<(tokio::net::TcpStream, crate::quota::TunnelStreamPermit), wire::ConnectResult>
    {
        // (1) Shape. A malformed destination never becomes an ACL decision
        // (there is nothing to decide *about*) and never becomes a socket
        // — same discipline as `docs/design/protocol.md` §9's "check the
        // shape of a session id before the choke point".
        let Ok(port) = u16::try_from(header.port) else {
            return Err(connect_rejected(
                ErrorCode::InvalidArgument,
                "destination port out of range",
            ));
        };
        if header.host.is_empty() || port == 0 {
            return Err(connect_rejected(
                ErrorCode::InvalidArgument,
                "destination host and port are required",
            ));
        }
        // A host this long is never a real DNS name (255-octet wire
        // limit, RFC 1035 §3.1) or a literal IP — nothing legitimate is
        // refused here, but an unbounded host string is an unbounded ACL
        // resource / audit field / quota map key (M8 Step 3b ruling: this
        // shape check belongs beside the others, before the ACL choke
        // point, same "nothing to decide about" reasoning).
        if header.host.len() > 255 {
            return Err(connect_rejected(
                ErrorCode::InvalidArgument,
                "destination host is too long",
            ));
        }
        // Canonical `host:port` — bracketed for an IPv6 literal, which
        // `parse_forward_spec` delivers bracket-stripped, so a plain
        // `format!` would build the unsplittable `::1:5432`. This string
        // is the ACL resource *and* the audit field, and M5's policy
        // engine will pattern-match rules against it, so the canonical
        // form is pinned in the contract crate rather than improvised
        // here (`qsh_proto::wire::format_host_port`).
        let resource = wire::format_host_port(&header.host, port);

        // (2) THE gate. Nothing exists yet: no socket, no resolver call, no
        // file descriptor of any kind. `authorize_stream` is the same
        // helper `SESSION_DATA`'s inline attach check uses — it decides and
        // writes the audit line for both outcomes (SC6: every privileged op
        // leaves an audit record).
        if !self.authorize_stream(ctx, crate::acl::Op::ForwardLocal.action(), &resource) {
            // The same constant the control-stream `PERMISSION_DENIED`
            // uses (`Server::permission_denied`): a denial must not tell
            // the peer *which* rule refused it.
            return Err(connect_rejected(
                ErrorCode::PermissionDenied,
                crate::acl::PERMISSION_DENIED_MESSAGE,
            ));
        }

        // (2.5) The tunnel-stream concurrency quota (M8 Step 3b,
        // `[serve].max_tunnel_streams_per_principal`/
        // `max_tunnel_streams_per_forward`): after the ACL decision (an
        // unauthorized principal must see `PERMISSION_DENIED`, never a
        // quota oracle — `crate::quota`'s own module doc), before the
        // dial (nothing is created before a reservation succeeds). Same
        // shape as `handle_exec_start`'s `reserve_exec` gate
        // (`server/mod.rs` exec path).
        let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);
        let permit = match self.quotas.reserve_tunnel_stream(&opener, &resource) {
            Ok(permit) => permit,
            Err(kind) => {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    ctx.peer_addr,
                    self.quotas.now(),
                    None,
                    ctx.auth_path,
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                return Err(connect_rejected(
                    ErrorCode::ResourceExhausted,
                    kind.wire_message(),
                ));
            }
        };

        // (3) Only now may a resource come into existence.
        match dialer.dial(&header.host, port).await {
            Ok(upstream) => Ok((upstream, permit)),
            Err(err) => {
                // The destination, not the payload: safe to log, and the
                // only thing about this tunnel that ever is.
                tracing::debug!(principal = %ctx.principal, %resource, %err, "tunnel dial failed");
                Err(connect_rejected(err.code(), err.to_string()))
            }
        }
    }

    // ------------------------------------------------------------------
    // remote forward (`-R`), M4 Step 4 — `RemoteForwardOpen`/`Close`
    // ------------------------------------------------------------------

    /// The `forward.remote` choke point, factored out of
    /// [`Server::handle_rfwd_open`] so it is unit-testable with **no
    /// transport connection at all** — mirrors
    /// [`Server::authorize_and_dial_tunnel`]'s shape exactly, one gate
    /// later:
    ///
    /// 1. shape-check the request (nothing created, no decision made);
    /// 2. [`Server::authorize`] — `Authorizer::check` + one [`AuditRecord`]
    ///    line for allow *and* deny alike, `Action::ForwardRemote` on
    ///    `bind_host:bind_port` (`PLAN.md` M4 Step 4's choke point);
    /// 3. **loopback enforcement** —
    ///    `crate::tunnel::remote::resolve_loopback_bind_addr`, which
    ///    resolves `bind_host` **once** and hands back the very address it
    ///    validated, so step 4 binds exactly what step 3 approved (that
    ///    function's own doc explains why a second resolution would be a
    ///    peer-steerable bypass, not a theoretical one). Deliberately
    ///    **after** the ACL gate and **not itself one**: a principal that
    ///    holds `forward.remote` outright still cannot bind non-loopback,
    ///    because this is a request constraint the host applies to every
    ///    principal alike, never a per-principal permission
    ///    (`crate::acl::Action::ForwardRemote`'s own doc,
    ///    `crate::tunnel::remote`'s module doc). A failure here is
    ///    therefore [`ErrorCode::InvalidArgument`] — a bad request — never
    ///    `PermissionDenied`, which would claim this principal specifically
    ///    was refused;
    /// 4. `binder.bind(...)` — unreachable unless steps 2 *and* 3 both
    ///    passed. Nothing before this point ever creates a socket.
    ///
    /// Returns the bound listener; minting a `forward_id`, spawning the
    /// accept loop and registering it are [`Server::handle_rfwd_open`]'s
    /// job, because those need a [`Connection`] this function is
    /// deliberately never given (see that method's own doc).
    pub(crate) async fn authorize_and_bind_remote_forward(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::RemoteForwardOpen,
        resolver: &dyn BindHostResolver,
        binder: &dyn RemoteForwardBinder,
    ) -> Result<(tokio::net::TcpListener, crate::quota::RemoteForwardPermit), Box<ControlMessage>>
    {
        // (1) Shape. A malformed request never becomes an ACL decision or a
        // socket, same discipline as `authorize_and_dial_tunnel`'s own (1).
        let Ok(bind_port) = u16::try_from(req.bind_port) else {
            return Err(Box::new(invalid_argument(
                request_id,
                "bind_port out of range",
            )));
        };
        let Ok(forward_port) = u16::try_from(req.forward_port) else {
            return Err(Box::new(invalid_argument(
                request_id,
                "forward_port out of range",
            )));
        };
        if req.forward_host.is_empty() || forward_port == 0 {
            return Err(Box::new(invalid_argument(
                request_id,
                "forward_host and forward_port are required",
            )));
        }

        // (2) THE gate. `bind_host:bind_port` is the ACL resource — the
        // canonical bracketed form, same helper and same reasoning
        // `authorize_and_dial_tunnel`'s own resource string uses. An empty
        // `bind_host` (no `bind:` prefix — the ordinary `-R rport:host:
        // hport` shape) is the wire default for loopback
        // (`crate::tunnel::remote::resolve_loopback_bind_addr`'s own doc),
        // so it is displayed as the address it actually binds rather than
        // literally empty — the same substitution
        // `crate::ops::tunnel::remote_tunnel_dto` already makes, so the
        // audit line names the address this forward really binds instead
        // of a resource string no policy or operator could act on.
        //
        // `bind_host` is peer-supplied text on its way into an audit
        // record and a log line, so it is sanitized first: a raw one could
        // carry ANSI/OSC escapes into an operator's terminal or forge
        // extra lines in an audit sink
        // (`qsh_proto::wire::sanitize_peer_text`'s own doc, the same
        // treatment Step 3 gave peer tunnel text). Sanitizing cannot widen
        // what binds — a host name carrying control characters resolves to
        // nothing, and only the raw string is ever handed to the resolver.
        let display_bind_host = if req.bind_host.is_empty() {
            "127.0.0.1".to_string()
        } else {
            wire::sanitize_peer_text(&req.bind_host)
        };
        let resource = wire::format_host_port(&display_bind_host, bind_port);
        self.authorize(
            ctx,
            request_id,
            crate::acl::Op::ForwardRemote.action(),
            &resource,
        )?;

        // (3) Loopback-only bind — see this function's own doc for why
        // this is `InvalidArgument`, never `PermissionDenied`. One
        // resolution decides it, and the address it returns is the address
        // step (4) binds: no second lookup can slip a routable address in
        // behind the check. A resolve failure is folded into "not
        // loopback": there is nothing to bind either way, and the caller
        // learns the same thing a genuinely non-loopback answer would tell
        // it.
        let addr =
            crate::tunnel::remote::resolve_loopback_bind_addr(resolver, &req.bind_host, bind_port)
                .await
                .map_err(|err| Box::new(invalid_argument(request_id, err.to_string())))?;

        // (3.5) The remote-forward-listener concurrency quota (M8 Step 3b,
        // `[serve].max_remote_forwards_per_principal`): after the ACL
        // decision and the loopback shape check (an unauthorized principal
        // must see `PERMISSION_DENIED`, and a non-loopback bind must see
        // `INVALID_ARGUMENT` — neither should ever be shadowed by
        // `RESOURCE_EXHAUSTED`), strictly **before** `binder.bind` below:
        // nothing may be created before the reservation succeeds, same
        // shape as `authorize_and_dial_tunnel`'s own `reserve_tunnel_
        // stream` gate. A spy `binder` in this module's own unit tests
        // must observe zero `bind` calls on a refusal here.
        let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);
        let quota = self
            .quotas
            .reserve_remote_forward(&opener)
            .map_err(|kind| {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    ctx.peer_addr,
                    self.quotas.now(),
                    Some(request_id),
                    ctx.auth_path,
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                Box::new(ControlMessage::error(
                    request_id,
                    wire::Error::new(ErrorCode::ResourceExhausted, kind.wire_message(), true),
                ))
            })?;

        // (4) Only now may a resource come into existence.
        let listener = binder.bind(addr).await.map_err(|err| {
            Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::ConnectionFailed,
                    format!("failed to bind {addr}: {err}"),
                    false,
                ),
            ))
        })?;
        Ok((listener, quota))
    }

    /// Full production handling of `RemoteForwardOpen`: the choke point
    /// ([`Server::authorize_and_bind_remote_forward`]) plus the parts that
    /// need a live [`Connection`] — minting the `forward_id`, spawning
    /// [`crate::tunnel::remote::serve_remote_forward`], and registering it
    /// in [`Server::remote_forwards`] for [`Server::handle_rfwd_close`]/
    /// [`Server::purge_connection`] to find later.
    ///
    /// Called only from [`Server::serve_control`]'s message loop — the one
    /// place a [`Connection`] to open this forward's future `TCP_ACCEPTED`
    /// streams on is actually available (`dispatch`'s own RfwdOpen arm
    /// documents why it cannot do this itself).
    async fn handle_rfwd_open(
        self: &Arc<Self>,
        ctx: &ConnCtx,
        conn: &Connection,
        request_id: u64,
        req: &wire::RemoteForwardOpen,
    ) -> ControlMessage {
        let (listener, quota) = match self
            .authorize_and_bind_remote_forward(ctx, request_id, req, &SystemResolver, &SystemBinder)
            .await
        {
            Ok(pair) => pair,
            Err(reply) => return *reply,
        };
        let actual_addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                // Bound but unreadable back — treat the listener as
                // unusable; dropping it here (end of scope) closes it, so
                // this is still a clean "nothing left running" failure.
                return ControlMessage::error(
                    request_id,
                    wire::Error::new(
                        ErrorCode::ConnectionFailed,
                        format!("bound remote-forward listener has no local address: {err}"),
                        false,
                    ),
                );
            }
        };
        let actual_port = actual_addr.port();

        // Structural record at bind success (`PLAN.md` §4.1's Step 4
        // adversarial-review carryover): the authorization record above
        // (`authorize_and_bind_remote_forward`'s step (2)) names the
        // *requested* `bind_host:bind_port` and has to — a kernel-assigned
        // ephemeral port is not knowable before a bind, and authorizing it
        // would mean creating the resource before authorization succeeds.
        // That leaves an incident reader unable to tell what was actually
        // opened from `localhost:0`. This is the other half: op,
        // principal, result, and the address the kernel actually handed
        // back — nothing payload-shaped ever reaches this line, only what
        // `TcpListener::local_addr` reports.
        tracing::info!(
            op = "forward.remote.bind",
            result = "ok",
            principal = %ctx.principal,
            %actual_addr,
            "tunnel: remote-forward listener bound"
        );

        let forward_id = ulid::Ulid::new().to_string();
        // Self-removal on a fatal accept error (M8 Step 3b) — factored
        // into `run_remote_forward_accept_loop` (this module's own free
        // fn, below, generic over the serve future) both so this spawn
        // stays short and so a test can drive the exact same production
        // self-removal tail with a cheap stand-in future instead of a
        // real listener (R10).
        let task = tokio::spawn(run_remote_forward_accept_loop(
            Arc::downgrade(self),
            crate::tunnel::remote::serve_remote_forward(
                listener,
                conn.clone(),
                forward_id.clone().into_bytes(),
                Arc::clone(&self.quotas),
                Arc::clone(&self.audit),
            ),
            forward_id.clone(),
        ));
        // Recorded under this connection's authenticated `(principal,
        // auth_path)`, not `ctx.conn_id` alone — the ACL ownership axis
        // `Server::handle_rfwd_close` checks (`Server::remote_forwards`'s
        // own doc, `PLAN.md` M5 Step 5 (a)).
        self.remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                forward_id.clone(),
                RemoteForwardEntry {
                    conn_id: ctx.conn_id,
                    owner: opener_key(&ctx.principal, ctx.auth_path),
                    task,
                    _quota: quota,
                },
            );

        // `bind_host` is peer-supplied text on its way to a log line, so
        // it is sanitized (`authorize_and_bind_remote_forward`'s step (2)
        // makes the same substitution for the audit resource, and for the
        // same reason). `forward_id` is host-minted here — a ULID, so
        // `wire::valid_forward_id` holds by construction; the test
        // `minted_forward_ids_satisfy_the_wire_shape` pins that.
        tracing::info!(
            principal = %ctx.principal,
            %forward_id,
            bind_host = %wire::sanitize_peer_text(&req.bind_host),
            actual_port,
            "tunnel: remote forward opened"
        );

        ControlMessage::response(
            request_id,
            response::Body::RfwdOpened(wire::RemoteForwardOpened {
                forward_id,
                actual_port: u32::from(actual_port),
            }),
        )
    }

    /// `RemoteForwardClose`: the `Action::ForwardRemote` choke point
    /// (`PLAN.md` M5 Step 5 (a)) over this `forward_id`'s registered
    /// owner, then — only on a pass — abort and drop it.
    ///
    /// In order:
    ///
    /// 1. **Shape** — before this peer-supplied string is used to look
    ///    anything up, tear anything down, reach an ACL decision, or reach
    ///    a log line (`qsh_proto::wire::valid_forward_id`, the same "check
    ///    shape before it becomes a resource or an audit field" discipline
    ///    `valid_host_name` states and `valid_session_id` follows).
    /// 2. **Owner lookup** — a read-only peek at `Server::remote_forwards`
    ///    for this `forward_id`'s recorded owner, `None` if this host has
    ///    no such forward at all (already closed, never opened, or a
    ///    peer-supplied id that never existed). This step decides nothing
    ///    by itself and changes no wire-visible behavior on its own — it
    ///    only fills [`ResourceRef::owner`] for step 3, so a `DenyAll`
    ///    host still answers `PERMISSION_DENIED` for an unknown
    ///    `forward_id` exactly as it would for a real one (the choke point
    ///    fires **before** the existence question is ever answered on the
    ///    wire — no "which failure mode" oracle).
    /// 3. **The choke point proper** — [`Self::authorize_owned`],
    ///    `Action::ForwardRemote` on `forward_id` with the owner from step
    ///    2. `owner: None` (no such forward) is never filtered by scope
    ///    (`ResourceRef`'s own doc), so this step's own verdict depends
    ///    only on the ordinary policy match for that case — never a
    ///    manufactured allow or deny. A different principal than the one
    ///    that opened it is refused here under `scope = "owned"`,
    ///    byte-identically to any other `PERMISSION_DENIED`
    ///    (`crate::acl::PERMISSION_DENIED_MESSAGE`'s own doc) — but the
    ///    *same* principal reconnected on a different `conn_id` is still
    ///    the forward's owner (`RemoteForwardEntry::owner`'s own doc) and
    ///    passes.
    /// 4. **Remove** — only reachable past a pass at step 3. `None` here
    ///    (nothing to remove) is `InvalidArgument`, not a second
    ///    `PermissionDenied`: by this point the request already cleared
    ///    the ACL choke point (owner was `None`, so `scope` admitted it
    ///    unconditionally), so "no such forward_id" is an ordinary bad
    ///    request, the same shape `session.write`/`resize` already give an
    ///    unknown `session_id` past their own ownership gate.
    ///
    /// `docs/CLI.md` §2.5's full owning-peer semantics for `tunnel.close`
    /// (as an `Ops` surface) are `PLAN.md` M4 Step 5 scope; this is the
    /// wire-level primitive that step builds on.
    fn handle_rfwd_close(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::RemoteForwardClose,
    ) -> ControlMessage {
        // (1) Shape. Every id this map can hold is a host-minted ULID,
        // which satisfies the predicate by construction, so a malformed
        // one could only ever have missed — but it must miss *without*
        // being touched. Past this point the id is `[A-Za-z0-9_-]{1,64}`,
        // strictly stronger than sanitizing, so the success line below
        // logs it as it is.
        if !wire::valid_forward_id(&req.forward_id) {
            tracing::warn!(
                principal = %ctx.principal,
                forward_id_len = req.forward_id.len(),
                "tunnel: malformed forward_id on RemoteForwardClose"
            );
            return invalid_argument(request_id, "malformed forward_id");
        }

        // (2) Owner lookup — decides nothing, only fills `ResourceRef`.
        let owner = self
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&req.forward_id)
            .map(|entry| entry.owner.clone());

        // (3) THE gate.
        if let Err(reply) = self.authorize_owned(
            ctx,
            request_id,
            crate::acl::Op::ForwardRemoteClose.action(),
            ResourceRef {
                id: &req.forward_id,
                owner: owner.as_deref(),
            },
        ) {
            return *reply;
        }

        // (4) Allowed: remove and abort, or (an unknown id, which always
        // has `owner: None` and so always cleared step 3) answer that
        // there was nothing to close.
        let removed = self
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&req.forward_id);
        match removed {
            Some(entry) => {
                entry.task.abort();
                tracing::info!(
                    principal = %ctx.principal,
                    forward_id = req.forward_id,
                    "tunnel: remote forward closed"
                );
                // Bare success (`v1.proto`'s own comment on
                // `RemoteForwardClose`: "no dedicated payload").
                ControlMessage::new(
                    request_id,
                    control_message::Body::Response(wire::Response { body: None }),
                )
            }
            None => invalid_argument(request_id, "no such forward_id"),
        }
    }

    /// Admit a peer-opened data stream: read the header, redeem the ticket
    /// for that stream kind, run the exec. Anything else resets the stream
    /// without touching any resource.
    async fn handle_data_stream(
        &self,
        ctx: ConnCtx,
        mut stream: FramedStream,
        conn: Connection,
        events: tokio::sync::mpsc::Sender<ControlMessage>,
    ) {
        let header =
            match tokio::time::timeout(HEADER_TIMEOUT, stream.recv.recv::<StreamHeader>()).await {
                Ok(Ok(Some(h))) => h,
                _ => {
                    stream.send.reset(RESET_CODE_BAD_HEADER);
                    stream.recv.stop(RESET_CODE_BAD_HEADER);
                    return;
                }
            };
        // `TCP_CONNECT` is the one stream kind that carries **no ticket**
        // (`docs/design/protocol.md` §7: "유일한 예외는 `TCP_CONNECT`"), so it
        // branches off before ticket redemption — see
        // [`Server::handle_tcp_connect`] for why the ACL check is inline
        // here instead of at the control-stream choke point.
        if header.stream_kind() == Some(StreamKind::TcpConnect) {
            self.handle_tcp_connect(&ctx, stream, &header).await;
            return;
        }
        let kind = match header.stream_kind() {
            Some(kind @ (StreamKind::ExecData | StreamKind::SessionData)) => kind,
            _ => {
                tracing::debug!(principal = %ctx.principal, kind = header.kind, "unsupported stream kind");
                stream.send.reset(RESET_CODE_BAD_HEADER);
                stream.recv.stop(RESET_CODE_BAD_HEADER);
                return;
            }
        };
        let Some(ticket) = self.redeem_ticket(ctx.conn_id, kind, &header.ticket) else {
            tracing::warn!(principal = %ctx.principal, ?kind, "data stream with invalid ticket");
            stream.send.reset(RESET_CODE_BAD_HEADER);
            stream.recv.stop(RESET_CODE_BAD_HEADER);
            return;
        };
        match ticket.purpose {
            TicketPurpose::Exec(pending) => {
                let exec_id = pending.exec_id.clone();
                stream.send.set_priority(wire::PRIORITY_EXEC_DATA);
                match run_exec(pending.spec, stream.send, stream.recv).await {
                    Ok(outcome) => tracing::info!(
                        principal = %ctx.principal,
                        %exec_id,
                        exit_code = outcome.exit_code,
                        timed_out = outcome.timed_out,
                        "exec finished"
                    ),
                    // The peer going away mid-exec (its own `--timeout`, a
                    // crash, a network drop) is ordinary operation, not a
                    // host-side fault: the child was killed and reaped,
                    // nothing to alarm about.
                    Err(err) if err.is_peer_gone() => tracing::info!(
                        principal = %ctx.principal,
                        %exec_id,
                        %err,
                        "exec aborted: peer went away; command killed"
                    ),
                    Err(err) => {
                        tracing::warn!(principal = %ctx.principal, %exec_id, %err, "exec failed")
                    }
                }
            }
            TicketPurpose::Session {
                session_id,
                replay_from,
                no_steal,
                attach_authorized,
                input_stream,
                input_from,
            } => {
                // Opening the session's data stream *is* the attach, and an
                // attach is RW (protocol.md §9), so it holds the writer
                // lease. A ticket minted by `session.attach` already passed
                // the ACL choke point; one minted by `session.open` did
                // not — `session.open` only authorized *opening*. Decide
                // and audit it here, before anything is taken, so a
                // principal allowed to open but not to attach cannot get an
                // interactive attach through the back door.
                //
                // Deliberately the literal `Action::SessionAttach`, not an
                // `acl::Op::SessionAttach.action()` lookup: this seam is
                // `DENY_SEAMS`'s `"session.attach@data-stream"` row, which
                // has no `OP_REGISTRY` entry of its own (`OpSpec`'s own
                // doc, `PLAN.md` M5 Step 8) — it shares the control-stream
                // `session.attach` op's `Action` but is a distinct wire
                // path with no CLI.md-documented name to look up.
                if !attach_authorized
                    && !self.authorize_stream(&ctx, Action::SessionAttach, session_id.as_str())
                {
                    stream.send.reset(RESET_CODE_FORBIDDEN);
                    stream.recv.stop(RESET_CODE_FORBIDDEN);
                    return;
                }
                // Steal-by-default is the interactive rule (architecture.md
                // §3 rule b); `no_steal` rides on the ticket so redeeming
                // cannot upgrade a careful attach into a stealing one. A
                // re-take on the connection that already holds the lease is
                // a no-op, so this is idempotent for an attach ticket — and
                // still honours `no_steal` if the lease changed hands
                // between the reply and this stream.
                //
                // `owner` is derived from the ticket, not
                // `ctx.connection_id()`, but **only** on a real reverse
                // registration (`ConnCtx::is_reverse_registration`'s own
                // doc): there, every local CLI process's data stream is
                // redeemed on the daemon's one shared registration
                // connection, so the physical connection alone cannot
                // tell two concurrent attaches apart
                // (`WriterLease::take_owned`'s own doc). Every other
                // connection this crate ever attaches over is already one
                // physical connection per attach, so `ctx.connection_id()`
                // is already a correct, stable identity there — and has
                // to stay `owner` on those routes, because a `session
                // write`/`session resize` value op issued on that *same*
                // connection (`Server::prepare_session_write`) derives its
                // own lease identity independently, straight from
                // `ctx.connection_id()`, with no ticket in sight to agree
                // on: diverging this attach's identity from that on a
                // route where they are the same physical asker would
                // desynchronize the two the moment either one re-takes
                // the lease (adversarial review fixer finding: exactly
                // this desync hung a steal-back on *both* the forward and
                // reverse variant of
                // `a_stolen_lease_demotes_the_attach_to_read_only_and_a_steal_back_resumes_it`,
                // neither of which actually multiplexes a connection).
                // `physical` stays `ctx.connection_id()` unconditionally
                // either way, so a dead connection — reverse registration
                // or forward attach alike — still releases whichever
                // attach currently holds the lease.
                let owner = if ctx.is_reverse_registration {
                    attach_lease_owner(&header.ticket)
                } else {
                    ctx.connection_id()
                };
                match self
                    .sessions
                    .take_lease_owned(
                        &session_id,
                        ctx.principal.to_string(),
                        owner,
                        ctx.connection_id(),
                        no_steal,
                    )
                    .await
                {
                    Ok(TakeOutcome::Conflict { .. }) => {
                        tracing::info!(
                            principal = %ctx.principal,
                            %session_id,
                            "session data stream refused: another principal holds the writer lease"
                        );
                        stream.send.reset(RESET_CODE_SESSION_CONFLICT);
                        stream.recv.stop(RESET_CODE_SESSION_CONFLICT);
                        return;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::debug!(
                            principal = %ctx.principal,
                            %session_id,
                            %err,
                            "session data stream refused: lease unavailable"
                        );
                        stream.send.reset(RESET_CODE_BAD_HEADER);
                        stream.recv.stop(RESET_CODE_BAD_HEADER);
                        return;
                    }
                }
                let pump = SessionStream {
                    sessions: Arc::clone(&self.sessions),
                    session_id: session_id.clone(),
                    // The same `owner` `take_lease_owned` above just took
                    // the lease as (this is the `is_held_by` check on
                    // every subsequent `Input`/`Resize` frame on *this*
                    // stream) — ticket-derived on a real reverse
                    // registration, `ctx.connection_id()` everywhere else,
                    // matching whichever identity a `session write`/
                    // `session resize` value op on this same connection
                    // would also use.
                    conn: owner,
                    cursor: Cursor::from_offset(replay_from),
                    input_stream,
                    input_from,
                    events: Some(events),
                };
                match pump.run(stream, &conn).await {
                    Ok(()) => tracing::info!(
                        principal = %ctx.principal,
                        %session_id,
                        "session data stream finished"
                    ),
                    Err(err) if err.is_peer_gone() => tracing::info!(
                        principal = %ctx.principal,
                        %session_id,
                        %err,
                        "session data stream ended: peer went away"
                    ),
                    Err(err) => tracing::warn!(
                        principal = %ctx.principal,
                        %session_id,
                        %err,
                        "session data stream failed"
                    ),
                }
            }
        }
    }
}

// ----------------------------------------------------------------------
// helpers: wire ⇄ broker
// ----------------------------------------------------------------------

/// The writer-lease *identity* a `SESSION_DATA` stream on a real reverse
/// registration (`ConnCtx::is_reverse_registration`) takes its lease as
/// (`WriterLease::take_owned`'s own doc), derived from the single-use
/// ticket it just redeemed rather than the physical connection it arrived
/// on. A ticket is minted fresh by exactly one `session.open`/
/// `session.attach` call and is removed from [`Server::redeem_ticket`]'s
/// table on redemption, so distinct attaches — including two concurrent
/// reverse attaches sharing one daemon registration connection — always
/// derive distinct identities here, while the *same* attach's own
/// subsequent `Input`/`Resize` frames (which never re-derive this; they
/// reuse the value stashed on `SessionStream::conn`) keep comparing equal
/// to themselves. Every other route keeps `ctx.connection_id()` as its
/// owner instead (this function's call site) — see
/// `ConnCtx::is_reverse_registration`'s own doc for why only a real
/// registration needs this.
///
/// Deliberately not cryptographically strong — this is bookkeeping for the
/// single-writer UX invariant, not an authorization boundary (the ACL
/// choke point and the ticket redemption above it already gate access);
/// only the ticket's *entropy*, not its unlinkability, matters here.
/// Remove every entry of `tickets` that `keep` rejects, returning the
/// removed [`Ticket`]s instead of dropping them in place — so a caller
/// still holding `tickets`'s `MutexGuard` can drop the returned `Vec`
/// only *after* releasing that guard (main-session arbitration item 2,
/// F7 of the M8 Step 3a conformance sweep: "collect under the guard,
/// drop outside"). A `Ticket` can carry a `crate::quota::ExecPermit`
/// (`PendingExec.permit` is a mandatory, non-`Option` field — `docs/adr/
/// 0010-resource-quotas.md` §3 — so a ticket can never exist without
/// one), and that permit's own `Drop` takes the quota lock; the quota
/// lock is leaf-most by design (ADR-0010 §9), so nesting it *under* the
/// tickets lock is safe, but there is no reason to run it *while* the
/// tickets lock is still held. `crate::server::Server::issue_ticket`,
/// `Server::pending_tickets_for` and `Server::purge_connection` are the
/// three retain sites this replaces (`std::collections::HashMap::
/// retain`'s own removed values drop exactly where they stood, inside
/// the closure — the one shape this function exists to avoid).
fn extract_tickets(
    tickets: &mut HashMap<[u8; TICKET_LEN], Ticket>,
    mut keep: impl FnMut(&Ticket) -> bool,
) -> Vec<Ticket> {
    let doomed: Vec<[u8; TICKET_LEN]> = tickets
        .iter()
        .filter(|(_, p)| !keep(p))
        .map(|(k, _)| *k)
        .collect();
    doomed
        .into_iter()
        .filter_map(|k| tickets.remove(&k))
        .collect()
}

fn attach_lease_owner(ticket: &[u8]) -> ConnectionId {
    let mut half = [0u8; 8];
    let n = ticket.len().min(half.len());
    half[..n].copy_from_slice(&ticket[..n]);
    ConnectionId(u64::from_le_bytes(half))
}

/// The control messages that may block for a long time — the `SessionRead`
/// long-poll (up to [`SESSION_READ_MAX_WAIT`]) and `SessionClose` (the
/// HUP → TERM → KILL escalation, up to two `close_grace` periods) — and
/// therefore run off the control stream's ordered path. Neither reorders
/// input: reads do not mutate, and a close is terminal for the session.
fn is_long_poll(msg: &ControlMessage) -> bool {
    matches!(
        msg.body,
        Some(control_message::Body::SessionRead(_)) | Some(control_message::Body::SessionClose(_))
    )
}

/// Shape of a session id a peer may name: `1..=SESSION_ID_MAX_LEN` bytes of
/// `[A-Za-z0-9_-]` (the URL-safe alphabet host-issued ULIDs live in).
pub fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= SESSION_ID_MAX_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The non-distinguishing refusal of a resume redemption (protocol.md
/// §10-2): the same answer for an unknown session, a wrong or expired
/// token, and a peer the session is not bound to. Nothing in the message
/// varies with which of those it was.
fn auth_failed(request_id: u64) -> ControlMessage {
    ControlMessage::error(
        request_id,
        wire::Error::new(ErrorCode::AuthFailed, "resume credential rejected", false),
    )
}

fn invalid_argument(request_id: u64, message: impl Into<String>) -> ControlMessage {
    ControlMessage::error(
        request_id,
        wire::Error::new(ErrorCode::InvalidArgument, message, false),
    )
}

/// Runs `serve` (in production, [`crate::tunnel::remote::
/// serve_remote_forward`]) to its own completion — reachable only via a
/// `Fatal` accept disposition (that function's own doc: every other
/// accept error is `Retry`/`Backoff`'d away inside its loop) — then
/// removes this forward's own `forward_id` from `server`'s [`Server::
/// remote_forwards`], releasing its [`crate::quota::RemoteForwardPermit`]
/// (M8 Step 3b). Without this, a listener that died on its own left its
/// entry — and permit — registered forever: a leak, and a `forward_id`
/// `RemoteForwardOpen` could never reuse (`docs/CLI.md` §2.5's `-R` retry
/// path) even though nothing is actually listening any more.
///
/// `server` is [`Weak`], not [`Arc`]: this task must never be the thing
/// keeping the whole host alive past its own shutdown, the same
/// reasoning [`crate::quota::ExecPermit`]/[`crate::quota::
/// TunnelStreamPermit`] hold a `Weak<Quotas>` for. `Self::handle_rfwd_
/// close`/[`Server::purge_connection`] both already remove the entry
/// themselves before calling [`tokio::task::JoinHandle::abort`], and an
/// abort drops this future at whatever `.await` point it was suspended
/// on — the removal below simply never runs on that path, so an aborted
/// forward is never double-removed by both this task and its closer.
///
/// `serve` is generic (`F: Future<Output = ()>`), not a concrete
/// `TcpListener` + [`Connection`] pair, so a test can drive this exact
/// production self-removal tail with a cheap stand-in future (`async {}`
/// to exercise the return path, [`std::future::pending`] to exercise the
/// abort path) instead of coaxing a real listener into a fatal OS-level
/// accept error (M8 Step 3b, R10: an earlier version of this test closed
/// a live listener's file descriptor out from under tokio's reactor to
/// force one, which is unsound and Windows-hostile — no test needs to do
/// that once the loop body itself is generic).
///
/// A free fn, not a [`Server`] method, so [`Server::handle_rfwd_open`]'s
/// spawn can pass it a plain [`Weak`] rather than the whole `self: &Arc<
/// Self>` receiver holding a strong reference into the spawned task.
async fn run_remote_forward_accept_loop<F: std::future::Future<Output = ()>>(
    server: std::sync::Weak<Server>,
    serve: F,
    forward_id: String,
) {
    serve.await;
    if let Some(server) = server.upgrade() {
        server
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&forward_id);
    }
}

/// The `BrokerError` → `ErrorCode` table (PLAN M2 Step 2 handoff): the
/// broker never names the CLI vocabulary; the dispatch edge does.
fn broker_error(request_id: u64, err: BrokerError) -> ControlMessage {
    let (code, retryable) = match &err {
        BrokerError::NotFound => (ErrorCode::SessionNotFound, false),
        BrokerError::InvalidArgument(_) => (ErrorCode::InvalidArgument, false),
        BrokerError::Conflict | BrokerError::NotWriter | BrokerError::NotRunning => {
            (ErrorCode::SessionConflict, false)
        }
        BrokerError::Backpressure => (ErrorCode::ResourceExhausted, true),
        // Same code as `require_not_draining`'s own refusal (this is the
        // rare race that check alone cannot close, `Broker::open_with`'s
        // comment) and non-retryable for the same reason: retrying against
        // this process cannot ever succeed again.
        BrokerError::Draining => (ErrorCode::ResourceExhausted, false),
        // A policy/platform refusal, not a failure — nothing was spawned
        // (no PTY backend on this host, or a foreign `user` hint; CLI.md §7).
        BrokerError::Unsupported(_) => (ErrorCode::Unsupported, false),
        BrokerError::Spawn(_) | BrokerError::Io(_) | BrokerError::Gone => {
            (ErrorCode::Internal, false)
        }
        // A session quota was saturated (`PLAN.md` M8 Step 3, `docs/adr/
        // 0010-resource-quotas.md`): retryable, unlike `Draining` —
        // retrying against this same process can succeed once some other
        // session closes. Structural message only, no payload.
        BrokerError::QuotaExceeded(_) => (ErrorCode::ResourceExhausted, true),
    };
    ControlMessage::error(
        request_id,
        wire::Error::new(code, err.to_string(), retryable),
    )
}

/// Narrow the wire's `uint32` window size to the broker's `u16`. `0` means
/// "host default" on open and is passed through as such.
fn window_size(cols: u32, rows: u32) -> Option<(u16, u16)> {
    Some((u16::try_from(cols).ok()?, u16::try_from(rows).ok()?))
}

fn session_info_to_wire(info: crate::broker::SessionInfo) -> wire::SessionInfo {
    wire::SessionInfo {
        session_id: info.session_id,
        state: info.state.as_str().to_string(),
        writer: info.writer,
        created_at: info.created_at,
        last_sequence: info.last_sequence,
    }
}

/// One replay-ring event → its `SessionReadEvent` counterpart. An `Output`
/// larger than the wire chunk cap is split (the ring's chunk cap equals
/// `SESSION_CHUNK_MAX`, so this is defensive), never rejected.
fn replay_event_to_wire(event: ReplayEvent) -> Vec<wire::SessionReadEvent> {
    use session_read_event::Body;
    match event {
        ReplayEvent::Output { sequence, data } => {
            let start = sequence - data.len() as u64;
            data.chunks(wire::SESSION_CHUNK_MAX)
                .scan(start, |offset, chunk| {
                    *offset += chunk.len() as u64;
                    Some(wire::SessionReadEvent::from_body(Body::Output(
                        wire::Output {
                            sequence: *offset,
                            data: chunk.to_vec(),
                        },
                    )))
                })
                .collect()
        }
        ReplayEvent::Gap {
            requested_after,
            available_from,
        } => vec![wire::SessionReadEvent::from_body(Body::Gap(wire::Gap {
            requested_after,
            available_from,
        }))],
        ReplayEvent::Control {
            sequence, event, ..
        } => vec![wire::SessionReadEvent::from_body(match event {
            ControlEvent::Exit { exit_code, signal } => Body::Exit(wire::Exit {
                final_seq: sequence,
                // The wire `exit_code` is not optional: a signal-terminated
                // child carries `-1` and its `signal`; the client maps that
                // back to `exit_code: null` (CLI.md §6.4).
                exit_code: exit_code.unwrap_or(-1),
                signal,
            }),
            ControlEvent::WriterChanged { writer } => Body::WriterChanged(wire::WriterChanged {
                new_writer: writer,
                seq: sequence,
            }),
            ControlEvent::Closed { reason } => Body::Closed(wire::Closed {
                reason: reason.as_str().to_string(),
                seq: sequence,
            }),
        })],
    }
}

/// RFC 3339 (whole seconds) for `now + ttl`.
fn rfc3339_after(ttl: Duration) -> String {
    let at = OffsetDateTime::now_utc()
        .checked_add(time::Duration::try_from(ttl).unwrap_or(time::Duration::MAX))
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// A coarse, structural-only label for a failed pairing exchange's audit
/// record ([`AuditRecord::pairing`]) — never the invite code, proof bytes or
/// exported keying material, matching every other `PairingError` variant's
/// own already-redacted `Display`.
fn pairing_audit_category(err: &crate::pairing::PairingError) -> &'static str {
    use crate::pairing::PairingError;
    match err {
        PairingError::Timeout => "timeout",
        PairingError::ClosedEarly => "closed-early",
        PairingError::UnexpectedMessage => "unexpected-message",
        PairingError::ExporterUnavailable => "exporter-unavailable",
        PairingError::NoMatch => "no-match",
        PairingError::Expired => "expired",
        PairingError::AlreadyConsumed => "already-consumed",
        PairingError::PinCollision => "pin-collision",
        PairingError::InvalidDeviceName { .. } => "invalid-device-name",
        PairingError::ResponderProofMismatch => "responder-proof-mismatch",
        PairingError::Remote { .. } => "remote-error",
        PairingError::Stream(_) => "stream-error",
        PairingError::Connection(_) => "connection-error",
        PairingError::Store(_) => "store-error",
    }
}

/// Whether the `user@` hint names the account `qsh serve` runs as
/// (CLI.md §7: exact, case-sensitive match against the login name from
/// `getpwuid(geteuid())`, never `$USER`/`$LOGNAME`). Anything that cannot
/// be verified — no passwd entry, or a platform without one — is a
/// mismatch: fail closed.
fn user_hint_matches(hint: &str) -> bool {
    serve_login_name().is_some_and(|name| name == hint)
}

/// The login name of the account this process runs as, or `None` if it
/// cannot be determined. Cached: it cannot change for the process
/// lifetime.
pub fn serve_login_name() -> Option<String> {
    static LOGIN_NAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    LOGIN_NAME.get_or_init(lookup_login_name).clone()
}

#[cfg(unix)]
fn lookup_login_name() -> Option<String> {
    use std::ffi::CStr;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    // getpwuid_r needs a caller buffer for the strings; grow on ERANGE.
    let mut buf: Vec<libc::c_char> = vec![0; 1024];
    loop {
        // SAFETY: passwd is a plain C struct; all-zero is a valid initial
        // value that getpwuid_r overwrites.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call — `pwd` and `result`
        // are live locals, `buf` is a live allocation of `buf.len()` bytes,
        // and getpwuid_r is the reentrant (thread-safe) variant.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: on success `pw_name` points at a NUL-terminated string
        // inside `buf`, which is still alive here.
        let name = unsafe { CStr::from_ptr(pwd.pw_name) };
        return name.to_str().ok().map(str::to_owned);
    }
}

#[cfg(not(unix))]
fn lookup_login_name() -> Option<String> {
    // No passwd database to compare against: every `user@` hint is a
    // mismatch (fail closed) until a Windows host lands (P2).
    None
}

/// Per-connection protocol failures (all end the connection). `pub` because
/// [`Server::serve_control`] is (same reasoning, same doc comment).
#[derive(Debug, Error)]
pub enum ConnError {
    #[error("peer did not send Hello within {HELLO_TIMEOUT:?}")]
    HelloTimeout,
    #[error("peer closed the control stream before Hello")]
    ClosedBeforeHello,
    #[error("first control message was not Hello")]
    ExpectedHello,
    #[error("no common wire minor version")]
    VersionMismatch,
    /// `respond()`'s `make_local_hello` callback declined the peer's
    /// `Hello`; the rejection was already sent as an error frame over the
    /// control stream (`handshake::respond_on`), so this variant is purely
    /// for the caller's own logging/close path. Never constructed while
    /// `serve_connection_inner`'s callback always returns `Ok` (M3 Step 2
    /// and earlier) — added now, ahead of Step 3 wiring a real rejection
    /// into that callback, so the mapping in `map_hello_error` never has
    /// to be `unreachable!()` for a peer-triggerable outcome (fail-closed
    /// per `CLAUDE.md` "Security defaults": an authz-decline path must
    /// never end in a panic).
    #[error("{}: {}", .0.error_code(), .0.message)]
    Rejected(wire::Error),
    /// The peer's first control message was a `PairingProof` sent to a
    /// connection this host's TLS layer already recognized via pin or CA
    /// (report F-2, `docs/design/protocol.md` §15.1's pin/CA priority over
    /// the pairing fallback) — `handshake::respond_on` already wrote and
    /// drained an explicit, non-retryable `SESSION_CONFLICT` error frame
    /// before returning this, so (like [`ConnError::Rejected`]) it exists
    /// purely for this caller's own logging/close path.
    #[error("{}: {}", .0.error_code(), .0.message)]
    AlreadyPaired(wire::Error),
    #[error(transparent)]
    Stream(#[from] qsh_transport::StreamError),
    #[error(transparent)]
    Connection(#[from] qsh_transport::ConnectionError),
    /// A pairing exchange (ADR-0002, M7 Step 4) ended in failure —
    /// `crate::pairing::respond` already wrote and drained the
    /// corresponding wire `Error` frame before returning this, so (like
    /// [`ConnError::Rejected`]) it exists purely for
    /// `Server::serve_pairing_connection`'s own logging/close path.
    #[error(transparent)]
    Pairing(#[from] crate::pairing::PairingError),
}

impl ConnError {
    /// Whether the failure is the connection going away (peer close, idle
    /// timeout, reset) rather than the peer misbehaving on an open one.
    fn is_connection_lost(&self) -> bool {
        match self {
            ConnError::Connection(_) => true,
            ConnError::Stream(qsh_transport::StreamError::Read(
                qsh_transport::ReadError::ConnectionLost(_),
            ))
            | ConnError::Stream(qsh_transport::StreamError::Write(
                qsh_transport::WriteError::ConnectionLost(_),
            )) => true,
            ConnError::Stream(_) => false,
            ConnError::HelloTimeout
            | ConnError::ClosedBeforeHello
            | ConnError::ExpectedHello
            | ConnError::VersionMismatch
            | ConnError::Rejected(_)
            | ConnError::AlreadyPaired(_) => false,
            ConnError::Pairing(e) => e.is_connection_lost(),
        }
    }
}

/// Map [`crate::handshake::HelloError`] onto the responder's pre-existing
/// [`ConnError`] surface, preserving every message exactly as it read
/// before the handshake exchange moved into `handshake.rs` (PLAN M3 Step 2
/// (d) — zero observable behavior change).
fn map_hello_error(err: crate::handshake::HelloError) -> ConnError {
    use crate::handshake::HelloError;
    match err {
        HelloError::Timeout => ConnError::HelloTimeout,
        HelloError::ClosedBeforeHello => ConnError::ClosedBeforeHello,
        HelloError::ExpectedHello => ConnError::ExpectedHello,
        HelloError::VersionMismatch => ConnError::VersionMismatch,
        HelloError::Stream(e) => ConnError::Stream(e),
        HelloError::Connection(e) => ConnError::Connection(e),
        // `handshake::respond` only ever reads the peer's first message as
        // a plain `Hello` (never as a reply to one of our own), so this
        // arm stays structurally unreachable regardless of what any
        // `make_local_hello` callback does — unlike `Rejected` below, it
        // is not something a future step starts constructing.
        HelloError::Remote { .. } => {
            unreachable!("respond() never parses a reply to our own Hello")
        }
        // `serve_connection_inner`'s callback always returns `Ok` in M3
        // Step 2 and earlier, so this arm is not exercised yet — but it is
        // peer-triggerable from Step 3 onward (registration/ACL decline),
        // so it maps to a real `ConnError` variant rather than panicking.
        HelloError::Rejected(e) => ConnError::Rejected(e),
        HelloError::AlreadyPaired(e) => ConnError::AlreadyPaired(e),
    }
}

// ---------------------------------------------------------------------
// Outbound liveness probing (M3 Step 4, `PLAN.md` "target 재접속" Stage A)
// ---------------------------------------------------------------------

/// The host role's counterpart to the client attach's control pump
/// (`ops/session.rs`'s `pump_attach_control`): sends this connection's own
/// liveness `Ping`s and correlates the `Pong`s that answer them, so
/// [`crate::client::pathwatch::PathWatch`] — until this step wired only
/// into a client attach — can watch a connection this process is the
/// *host* role on. Legitimate under `docs/design/protocol.md` §11's
/// preamble: TLS role (who dialed) and QSH role (who serves) are separate
/// axes, and nothing about "I am the host on this connection" says the
/// host cannot also be the one asking "are you still there".
///
/// The judgment policy itself — two cadences, RTT-scaled deadline,
/// 3-strike, consumer-stall-is-not-death — is entirely
/// [`crate::client::pathwatch`]'s and is untouched by this step
/// (`docs/design/protocol.md` §10). `ControlPinger` is only the adapter
/// that lets the host role feed that policy: it turns a `Verdict::Probe`
/// into an actual `Ping` on the wire (via [`Self::send_probe`]) and turns
/// the matching `Pong` back into [`crate::client::pathwatch::PathWatch::inbound`] (via
/// [`Self::observe`]).
///
/// ## Why this doesn't fight `serve_control`
///
/// [`Server::serve_control`]'s `select!` loop is the *only* task that ever
/// touches `ctl.recv`/`ctl.send` directly (that function's own doc
/// comment). `ControlPinger` never reaches around that split:
///
/// - **Outbound.** [`Self::send_probe`] does not write to the wire. It
///   hands a freshly-numbered `Ping` to the same `reply_tx` queue every
///   dispatch reply already funnels through (`serve_control`'s "All
///   replies funnel back through `reply_rx`" comment), so a probe takes
///   its turn behind whatever the connection is already sending instead of
///   racing it for the write half. `send(..).await` rather than
///   `try_send`, matching the backpressure every other seam onto this
///   queue already uses (`pump_attach_control`'s `session.send_ping()`,
///   `drive_registered_session`'s `session.send_ping()`): `PathState::verdict`
///   counts a probe as a strike the moment it decides to send one — before
///   this method ever runs — so silently dropping it on a momentarily-full
///   queue would spend that strike on a `Ping` that never reached the
///   wire, and three such drops is a false `Verdict::Dead` on a connection
///   whose only fault was a backed-up reply queue. Blocking this call
///   instead means a probe under real backpressure goes out (late) rather
///   than vanishing; it only ever runs on [`drive_probes`]'s own task, so
///   blocking it never stalls `serve_control`'s own select loop.
/// - **Inbound.** `serve_control`'s read arm stays the only reader of
///   `ctl.recv`. [`Self::observe`] is a plain, non-blocking method meant to
///   be called with every decoded [`ControlMessage`] *before* it reaches
///   [`Server::dispatch`]: a `true` return means this was this pinger's
///   own `Pong` and the caller must not also hand it to `dispatch` (there
///   is nothing for `dispatch` to do with it either way — it already
///   treats every `Pong` as a reply needing none — `observe` just gets
///   first look so a correlated one can update `PathWatch` before falling
///   through). A `Pong` whose `request_id` this pinger never allocated
///   returns `false` and is left exactly as unsolicited as `dispatch`
///   already treats every `Pong` today (`Server::dispatch`'s
///   `Body::Pong(_) => None` arm) — this step does not change what an
///   unrecognised `Pong` does, only what a recognised one now does.
///
/// ## Status: wired on the target side only
///
/// [`Server::serve_control`] is the sole constructor: when its `probe`
/// argument is `Some((watch, probes))` it builds a `ControlPinger` over
/// `watch`, spawns [`drive_probes`] against it (owned by its own
/// `blocking` `JoinSet`), and its own read arm calls
/// [`ControlPinger::record`] on every inbound `ControlMessage` before
/// `dispatch` ever sees it. `reverse/target.rs`'s `run_reverse_unix` is the
/// only caller that passes `Some(..)` today — the target watching the one
/// connection it dialed to its controller — so this is symmetric probing
/// from the target's side. `reverse/listen.rs`'s
/// `drive_registered_session` (the controller watching each connection it
/// has registered) runs the *other* half of the same
/// [`crate::client::pathwatch::watch_path`]/`PathWatch` policy but does not
/// go through `ControlPinger` at all: it drives `Session::send_ping`/
/// `send_pong` directly against its own `select!` loop, with no
/// `request_id` correlation, since a controller only ever has one
/// outstanding probe of its own at a time on a connection it does not
/// otherwise write to.
pub struct ControlPinger {
    next_request_id: std::sync::atomic::AtomicU64,
    outstanding: Mutex<std::collections::HashSet<u64>>,
    watch: crate::client::pathwatch::PathWatch,
    out: tokio::sync::mpsc::Sender<ControlMessage>,
}

impl ControlPinger {
    /// Build a pinger for one connection's outbound probes, writing
    /// through `out` (that connection's `reply_tx`, once wired) and
    /// reporting answers onto `watch`.
    pub fn new(
        watch: crate::client::pathwatch::PathWatch,
        out: tokio::sync::mpsc::Sender<ControlMessage>,
    ) -> Self {
        Self {
            next_request_id: std::sync::atomic::AtomicU64::new(1),
            outstanding: Mutex::new(std::collections::HashSet::new()),
            watch,
            out,
        }
    }

    /// The [`PathWatch`](crate::client::pathwatch::PathWatch) this pinger
    /// feeds — the caller wiring this in (`watch_path`'s other caller)
    /// shares the same handle.
    pub fn watch(&self) -> &crate::client::pathwatch::PathWatch {
        &self.watch
    }

    /// Allocate a fresh `request_id` — monotonic per connection, matching
    /// the allocation discipline `client::Session::request` already uses
    /// for its own outbound requests (`client/mod.rs`) — remember it as
    /// outstanding, and queue a `Ping` carrying it, waiting for room in the
    /// outbound queue if there is none right now (the module doc's
    /// "Outbound" note). Returns the id (tests correlate on it); `None`
    /// only once the connection is already gone (the outbound queue's
    /// receiver dropped) — in that case the id is un-registered from
    /// `outstanding` again, since no `Ping` carrying it ever went out.
    pub async fn send_probe(&self) -> Option<u64> {
        let id = self
            .next_request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.outstanding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id);
        let msg = ControlMessage::new(id, control_message::Body::Ping(wire::Ping {}));
        if self.out.send(msg).await.is_err() {
            self.outstanding
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
            return None;
        }
        Some(id)
    }

    /// Feed one inbound control message. `true` means this was this
    /// pinger's own `Pong` — the caller must not also route it to
    /// `dispatch` — and [`crate::client::pathwatch::PathWatch::inbound`] has already been reported.
    /// `false` covers everything else, including a `Pong` whose
    /// `request_id` was never one of ours (dropped, unchanged from today's
    /// `dispatch` behavior — see the module doc's "Inbound" note) and a
    /// duplicate delivery of a `Pong` this pinger already consumed once.
    pub fn observe(&self, msg: &ControlMessage) -> bool {
        let Some(control_message::Body::Pong(_)) = &msg.body else {
            return false;
        };
        let matched = self
            .outstanding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&msg.request_id);
        if matched {
            self.watch.inbound();
        }
        matched
    }

    /// Any inbound control message that is *not* one of this pinger's own
    /// correlated `Pong`s — the fallback branch the caller falls into once
    /// [`Self::observe`] returns `false` — still proves the path carries
    /// packets, and [`crate::client::pathwatch::PathState::observe_inbound`]
    /// already treats that as answering every probe outstanding (it resets
    /// the strike counter unconditionally, not per-id). `outstanding` here
    /// is a separate ledger kept only to correlate a *specific* `Pong` to
    /// the `Ping` it answers (`Self::observe`'s reordering guarantee), so
    /// without this it would never shrink for an id whose `Ping` was never
    /// answered, or whose `send_probe` call lost the race with the
    /// connection closing, even once the connection is proven alive by
    /// other means. Clearing it here — but never inside `observe` itself,
    /// which must keep tracking every other still-outstanding id so a
    /// reordered `Pong` for an *earlier* probe still correlates — closes
    /// that leak without disturbing correlation.
    pub fn note_inbound(&self) {
        self.outstanding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Feed one inbound [`ControlMessage`] end-to-end and report it to
    /// [`Self::watch`]. `true` means [`Self::observe`] consumed it as this
    /// pinger's own correlated `Pong` — the caller must not also dispatch
    /// it, same contract as `observe` alone. `false` means [`Self::note_inbound`]
    /// ran (clearing every still-outstanding id, since this message proves
    /// the path regardless of whether it was ours) and the message was
    /// reported onward: a `Ping` or an *uncorrelated* `Pong` as bare
    /// liveness — under symmetric probing (both ends of a registered
    /// connection running their own `PathWatch`, `PLAN.md` M3 Step 4) an
    /// inbound `Ping` this pinger did not send is the *peer's* probe loop
    /// asking the same question back, never real session traffic, so
    /// treating it as activity would re-arm `active_window` on every reply
    /// and pin both peers to the fast cadence forever
    /// (`PathState::observe_inbound`'s doc comment names the identical
    /// failure for an inbound `Pong`). An uncorrelated `Pong` gets the same
    /// treatment for the same reason: `note_inbound` above clears
    /// `outstanding` on *every* non-correlated message, so a peer `Ping`
    /// landing between our own `Ping` and its answering `Pong` makes that
    /// `Pong` arrive uncorrelated here too — it is still just this
    /// watchdog talking to itself, not session use. Everything else is
    /// full [`crate::client::pathwatch::PathWatch::traffic`].
    pub fn record(&self, msg: &ControlMessage) -> bool {
        if self.observe(msg) {
            return true;
        }
        self.note_inbound();
        match &msg.body {
            Some(control_message::Body::Ping(_)) | Some(control_message::Body::Pong(_)) => {
                self.watch.inbound()
            }
            _ => self.watch.traffic(),
        }
        false
    }
}

/// Send this connection's outbound liveness `Ping`s when
/// [`crate::client::pathwatch::watch_path`]'s watchdog asks for one.
/// Pairs with `watch_path(source, watch, probes)`: `probes` is the same
/// [`tokio::sync::Notify`] both are given, so a `Verdict::Probe` wakes this
/// loop rather than the watchdog writing to the wire itself — the same
/// split `ops/session.rs`'s `pump_attach_control` keeps on the client side,
/// for the same cancel-safety reason (`ProbeSource`'s doc comment,
/// `pathwatch.rs`).
///
/// Runs until `probes` (and every clone of it) is dropped — ordinarily for
/// as long as `serve_control` is driving the connection this pinger
/// belongs to.
pub async fn drive_probes(pinger: Arc<ControlPinger>, probes: Arc<tokio::sync::Notify>) {
    loop {
        probes.notified().await;
        // `None` only once the outbound queue's receiver is gone — the
        // connection this pinger belongs to is already done, and every
        // future `send_probe` would fail the same way, so stop rather than
        // spin on `notified()` forever with nothing left to send to.
        if pinger.send_probe().await.is_none() {
            return;
        }
    }
}

/// The only place a rejecting [`wire::ConnectResult`] is built, so every
/// `TCP_CONNECT` refusal carries a code from the single [`ErrorCode`] enum
/// (`CLAUDE.md` "Error codes come from the single `ErrorCode` enum") and
/// never an ad-hoc string. `message` is host-authored prose about the
/// *request* — never a payload byte, never key material.
fn connect_rejected(code: ErrorCode, message: impl Into<String>) -> wire::ConnectResult {
    wire::ConnectResult {
        ok: false,
        code: code.as_str().to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
