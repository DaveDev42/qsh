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
    /// Reserved in [`Server::handle_exec_start`] before the ticket is
    /// issued; released by `Drop` whenever this value's last owner goes
    /// away — the ticket map's lazy/periodic/`purge_connection` expiry
    /// sweeps ([`Server::issue_ticket`], [`Server::pending_tickets_for`],
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
    /// connection ([`Self::serve_pairing_connection`]): verify the
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

    /// Number of tickets currently outstanding (tests/diagnostics).
    pub fn pending_tickets(&self) -> usize {
        self.lock_tickets().len()
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
    /// cursor pull (the same primitive `--follow` and MCP long-poll use).
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
        match self.sessions.close(&id, CloseReason::Closed, signal).await {
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
    /// connection-bound lifetime — see [`Server::remote_forwards`]'s own
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
    /// [`run`](Self::run) reaches this only through [`Self::admit`], which
    /// already consulted [`Self::admission`] and is holding the resulting
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
    /// **here**, before [`Self::serve_connection_inner`] ever runs — a
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
    /// [`Server::serve_pairing_connection`]'s own logging/close path.
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
/// the matching `Pong` back into [`PathWatch::inbound`] (via
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
    /// `dispatch` — and [`PathWatch::inbound`] has already been reported.
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
    /// full [`PathWatch::traffic`].
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
mod tests {
    use super::*;
    use crate::acl::{AllowAllPinned, DenyAll};
    use crate::audit::{FailingAuditSink, MemoryAuditSink};
    use crate::broker::{
        Broker, BrokerConfig, PipeFactory, PipeHandle, RESUME_TOKEN_LEN, SessionState, SourceExit,
        TestClock,
    };

    const ALL_CAPS: &[&str] = &["exec", "session"];

    fn ctx(principal: Principal, caps: &[&str]) -> ConnCtx {
        ConnCtx {
            principal,
            auth_path: AuthPath::Pin,
            peer_fingerprint: Some(PeerFingerprint::new([7u8; 32])),
            peer_addr: "127.0.0.1:5000".parse().unwrap(),
            conn_id: 42,
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
            is_reverse_registration: false,
        }
    }

    /// A server over a fresh test broker (pipe sources, injected clock).
    struct Rig {
        server: Arc<Server>,
        audit: Arc<MemoryAuditSink>,
        broker: Arc<Broker>,
        pipes: Arc<PipeFactory>,
        clock: TestClock,
        /// Same object as `server`'s own (private) `quotas` field — kept
        /// here too so a test can call `flush_expired`/`exec_in_use`
        /// without reaching through `server` (still fine either way: this
        /// module is `crate::server`'s own `tests` submodule, so `Server`'s
        /// private fields are visible from here regardless).
        quotas: Arc<crate::quota::Quotas>,
    }

    fn rig(authorizer: Arc<dyn Authorizer>) -> Rig {
        rig_with(
            authorizer,
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
        )
    }

    /// A rig over a caller-built source factory / close grace, so a test can
    /// give the "child" its own behaviour (e.g. ignoring SIGHUP).
    fn rig_with(
        authorizer: Arc<dyn Authorizer>,
        pipes: Arc<PipeFactory>,
        close_grace: Duration,
    ) -> Rig {
        rig_with_quota_limits(
            authorizer,
            pipes,
            close_grace,
            crate::quota::QuotaLimits::default(),
        )
    }

    /// [`rig_with`] plus caller-chosen [`crate::quota::QuotaLimits`], so a
    /// quota-cap test does not have to open/reserve hundreds of times to
    /// reach the default limits. The broker and the `Server`'s own
    /// [`crate::quota::Quotas`] share the same [`TestClock`], so advancing
    /// `rig.clock` moves both the session-count and the `exec.run`/audit
    /// window axes together, the same way the real `SystemClock` is one
    /// clock in production.
    fn rig_with_quota_limits(
        authorizer: Arc<dyn Authorizer>,
        pipes: Arc<PipeFactory>,
        close_grace: Duration,
        quota_limits: crate::quota::QuotaLimits,
    ) -> Rig {
        let clock = TestClock::new();
        let broker = Broker::new(
            Arc::new(clock.clone()),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace,
                quota_limits,
            },
            pipes.clone(),
        );
        let audit = Arc::new(MemoryAuditSink::new());
        let quotas = crate::quota::Quotas::new(quota_limits, Arc::new(clock.clone()));
        let admission = crate::admission::Gate::new(
            Arc::new(clock.clone()),
            crate::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
            crate::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
            crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
        );
        let server = Server::with_admission_and_quotas(
            authorizer,
            audit.clone(),
            broker.clone(),
            "host",
            admission,
            quotas.clone(),
        );
        Rig {
            server,
            audit,
            broker,
            pipes,
            clock,
            quotas,
        }
    }

    fn allow_rig() -> Rig {
        rig(Arc::new(AllowAllPinned))
    }

    fn exec_start(request_id: u64, argv: &[&str]) -> ControlMessage {
        ControlMessage::new(
            request_id,
            control_message::Body::ExecStart(ExecStart {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                env: Default::default(),
                timeout_ms: 0,
            }),
        )
    }

    fn session_open(request_id: u64) -> ControlMessage {
        ControlMessage::new(
            request_id,
            control_message::Body::SessionOpen(wire::SessionOpen {
                argv: vec!["sh".into()],
                cols: 80,
                rows: 24,
                ..Default::default()
            }),
        )
    }

    fn error_code(msg: &ControlMessage) -> Option<ErrorCode> {
        match &msg.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => Some(e.error_code()),
            _ => None,
        }
    }

    fn response_body(msg: &ControlMessage) -> &response::Body {
        match &msg.body {
            Some(control_message::Body::Response(wire::Response { body: Some(body) })) => body,
            other => panic!("expected a response, got {other:?}"),
        }
    }

    async fn open_session(rig: &Rig, ctx: &ConnCtx) -> (String, Vec<u8>, PipeHandle) {
        let (opened, pipe) = open_session_full(rig, ctx).await;
        (opened.session_id, opened.ticket, pipe)
    }

    /// The whole `SessionOpened`, for the tests that need the session's
    /// resume credential (every `session.attach` presents one).
    async fn open_session_full(rig: &Rig, ctx: &ConnCtx) -> (wire::SessionOpened, PipeHandle) {
        let reply = rig.server.dispatch(ctx, &session_open(1)).await.unwrap();
        let opened = match response_body(&reply) {
            response::Body::SessionOpened(o) => o.clone(),
            other => panic!("expected SessionOpened, got {other:?}"),
        };
        let pipe = rig.pipes.take().expect("pipe handle for the new session");
        (opened, pipe)
    }

    /// Every session op with a fixed id, as (op name, body) — the set the
    /// choke-point tests iterate over.
    fn session_bodies(id: &str) -> Vec<(&'static str, control_message::Body)> {
        use control_message::Body;
        vec![
            (
                "open",
                Body::SessionOpen(wire::SessionOpen {
                    argv: vec!["sh".into()],
                    ..Default::default()
                }),
            ),
            ("list", Body::SessionList(wire::SessionList {})),
            (
                "get",
                Body::SessionGet(wire::SessionGet {
                    session_id: id.into(),
                }),
            ),
            (
                "read",
                Body::SessionRead(wire::SessionRead {
                    session_id: id.into(),
                    ..Default::default()
                }),
            ),
            (
                "write",
                Body::SessionWrite(wire::SessionWrite {
                    session_id: id.into(),
                    data: b"ls\n".to_vec(),
                }),
            ),
            (
                "resize",
                Body::SessionResize(wire::SessionResize {
                    session_id: id.into(),
                    cols: 80,
                    rows: 24,
                }),
            ),
            (
                "close",
                Body::SessionClose(wire::SessionClose {
                    session_id: id.into(),
                    signal: None,
                }),
            ),
        ]
    }

    // ---- exec (M1) — unchanged behaviour ------------------------------

    #[tokio::test]
    async fn allowed_exec_issues_ticket_and_audits_allow() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(5, &["true"]))
            .await
            .unwrap();
        assert_eq!(reply.request_id, 5);
        let ticket = match response_body(&reply) {
            response::Body::ExecStarted(started) => started.ticket.clone(),
            other => panic!("expected ExecStarted, got {other:?}"),
        };
        assert_eq!(ticket.len(), TICKET_LEN);
        assert_eq!(rig.server.pending_tickets(), 1);
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "allow");
        assert_eq!(recs[0].principal, "device:laptop");
        assert_eq!(recs[0].action, "exec.run");
        assert_eq!(recs[0].request_id, "5");
        // Redeem: bound to the connection and the stream kind, single use.
        assert!(
            rig.server
                .redeem_ticket(41, StreamKind::ExecData, &ticket)
                .is_none(),
            "foreign conn"
        );
        assert!(
            rig.server
                .redeem_ticket(42, StreamKind::SessionData, &ticket)
                .is_none(),
            "wrong stream kind"
        );
        let pending = rig
            .server
            .redeem_ticket(42, StreamKind::ExecData, &ticket)
            .expect("redeem once");
        match pending.purpose {
            TicketPurpose::Exec(exec) => assert_eq!(exec.spec.argv, vec!["true"]),
            other => panic!("expected an exec ticket, got {other:?}"),
        }
        assert!(
            rig.server
                .redeem_ticket(42, StreamKind::ExecData, &ticket)
                .is_none(),
            "single use"
        );
        assert_eq!(rig.server.pending_tickets(), 0);
    }

    #[tokio::test]
    async fn denied_exec_issues_no_ticket_and_audits_deny() {
        let rig = rig(Arc::new(DenyAll));
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(6, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        assert_eq!(rig.server.pending_tickets(), 0, "no ticket before ACL pass");
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "deny");
    }

    #[tokio::test]
    async fn unpinned_principal_is_denied_under_interim_policy() {
        let rig = allow_rig();
        // A CA-authenticated peer — user or device — is not pinned.
        for principal in [
            Principal::User("dave".into()),
            Principal::Device("laptop".into()),
        ] {
            let mut ctx = ctx(principal, &["exec"]);
            ctx.auth_path = AuthPath::Ca;
            let reply = rig
                .server
                .dispatch(&ctx, &exec_start(1, &["true"]))
                .await
                .unwrap();
            assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        }
        assert_eq!(rig.server.pending_tickets(), 0);
        let records = rig.audit.records();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.decision == "deny"));
    }

    /// The subject here is the *per-connection ticket budget*, which
    /// `PLAN.md` M8 Step 3 left untouched. It needs an exec quota well
    /// clear of that budget to stay observable, because the two now share
    /// a numeric boundary: `MAX_PENDING_TICKETS_PER_CONN` and the default
    /// `[serve].max_exec_per_principal` are both 32, and an unredeemed
    /// exec ticket holds its `ExecPermit` — so under the defaults a single
    /// principal's 33rd concurrent exec is refused by the (cross-
    /// connection) exec quota before this (per-connection) budget's own
    /// "another connection is unaffected" arm can be reached. Raising only
    /// this rig's quota keeps the budget's contract asserted exactly as it
    /// was; the quota's own boundary is asserted by
    /// `exec_cap_rejects_past_the_limit_and_audits_quota_exec_principal`.
    #[tokio::test]
    async fn outstanding_tickets_per_connection_are_bounded() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_exec_per_principal: MAX_PENDING_TICKETS_PER_CONN * 4,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        for i in 0..MAX_PENDING_TICKETS_PER_CONN {
            let reply = rig
                .server
                .dispatch(&ctx, &exec_start(i as u64, &["true"]))
                .await
                .unwrap();
            assert_eq!(error_code(&reply), None, "ticket {i} must be issued");
        }
        assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(999, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));
        assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
        // `check_ticket_budget` now runs *after* the ACL choke point
        // (main-session arbitration item 3, `handle_exec_start`'s own
        // comment) — so the refused, over-budget request still reaches
        // (and is audited by) ACL first, one more `allow` line than the
        // `MAX_PENDING_TICKETS_PER_CONN` successful opens' own lines.
        assert_eq!(rig.audit.records().len(), MAX_PENDING_TICKETS_PER_CONN + 1);
        // Another connection is unaffected by this one's backlog.
        let mut other = ctx.clone();
        other.conn_id += 1;
        let reply = rig
            .server
            .dispatch(&other, &exec_start(1, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), None);
        assert_eq!(
            rig.server.pending_tickets(),
            MAX_PENDING_TICKETS_PER_CONN + 1
        );
    }

    #[tokio::test]
    async fn exec_without_capability_is_unsupported_and_not_audited() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), &[]);
        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(1, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
        assert!(rig.audit.records().is_empty());
        assert_eq!(rig.server.pending_tickets(), 0);
    }

    // ---- exec.run concurrency quota (`PLAN.md` M8 Step 3, `docs/adr/
    // 0010-resource-quotas.md`, verdict arbitration item 5) --------------

    #[tokio::test]
    async fn exec_cap_rejects_past_the_limit_and_audits_quota_exec_principal() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_exec_per_principal: 1,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let opener = opener_key(&ctx.principal, ctx.auth_path);

        // First exec.run reserves the sole permit.
        let ok = rig
            .server
            .dispatch(&ctx, &exec_start(1, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&ok), None);
        assert_eq!(rig.quotas.exec_in_use(&opener), 1);

        // Second, while the first ticket is still unredeemed, is refused by
        // the per-principal exec cap — not the (much larger) ticket budget.
        let refused = rig
            .server
            .dispatch(&ctx, &exec_start(2, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&refused), Some(ErrorCode::ResourceExhausted));
        match response_body(&refused) {
            response::Body::Error(e) => {
                assert!(e.retryable, "a quota rejection is retryable");
                // The exec axis gets its own wire message, distinct from
                // the session axis's ("session quota exceeded") — see
                // `QuotaKind::wire_message` (docs/CLI.md §6.12).
                assert_eq!(e.message, "exec quota exceeded");
            }
            other => panic!("expected an error response, got {other:?}"),
        }
        // Still only the one ticket the first call issued.
        assert_eq!(rig.server.pending_tickets(), 1);

        let recs = rig.audit.records();
        assert_eq!(
            recs.len(),
            3,
            "first open's ACL allow, second's ACL allow, second's quota deny"
        );
        assert_eq!(recs[0].decision, "allow");
        assert_eq!(recs[1].decision, "allow");
        assert_eq!(recs[2].decision, "deny");
        assert_eq!(recs[2].resource, "quota_exec_principal");
        assert_eq!(recs[2].principal, opener);
        assert_eq!(
            recs[2].request_id, "2",
            "R9 — the exec axis has a real control request id to carry"
        );
        assert_eq!(
            recs[2].peer_addr,
            ctx.peer_addr.to_string(),
            "R4 — the quota deny record must carry the live peer, not \"-\""
        );
    }

    /// [`crate::exec::run_exec`] reports even a spawn failure ("argv that
    /// cannot exec", `ENOENT`) as an `Ok` outcome carrying a
    /// shell-convention exit code (its own doc) — there is no early `Err`
    /// return that would skip past dropping the exec's `PendingExec`. So
    /// the one release point after redemption — [`Server::
    /// serve_data_stream`]'s match arm drops `pending` (the permit with
    /// it) once `run_exec(pending.spec, ..)` returns — covers "released on
    /// child exit" and "released on spawn failure" identically: both are
    /// this same drop, at the same point in the same function, differing
    /// only in `spec.argv`. Exercising that literal drop through an actual
    /// spawned child needs a real QUIC data stream (`FramedSend`/
    /// `FramedRecv` wrap `quinn::{Send,Recv}Stream` directly, `qsh-
    /// transport`'s `control.rs`) that this in-process `Rig` has no way to
    /// create — that level of exercise belongs to `qsh-testkit`'s loopback
    /// harness, not this file. What *is* unit-testable here, and is the
    /// actual mechanism both scenarios rely on, is that redeeming an exec
    /// ticket really does hand the permit to the caller (not leave a
    /// second claim on it behind in the ticket map) and that dropping the
    /// redeemed value releases it — exactly what `serve_data_stream` does,
    /// unconditionally, right after `run_exec` returns.
    #[tokio::test]
    async fn exec_permit_moves_with_the_redeemed_ticket_and_releases_when_it_is_dropped() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_exec_per_principal: 1,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let opener = opener_key(&ctx.principal, ctx.auth_path);

        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(1, &["true"]))
            .await
            .unwrap();
        let ticket = match response_body(&reply) {
            response::Body::ExecStarted(started) => started.ticket.clone(),
            other => panic!("expected ExecStarted, got {other:?}"),
        };
        assert_eq!(rig.quotas.exec_in_use(&opener), 1);

        // Redeem — the real production method (`Server::serve_data_stream`'s
        // own call). Redemption moves the permit out of the ticket map; it
        // does not itself release it.
        let redeemed = rig
            .server
            .redeem_ticket(ctx.conn_id, StreamKind::ExecData, &ticket)
            .expect("redeem once");
        assert_eq!(
            rig.quotas.exec_in_use(&opener),
            1,
            "redeeming a ticket must not itself free the slot"
        );

        // What `serve_data_stream` does next — `run_exec(pending.spec,
        // ..).await` — needs a real stream and is unreachable here; what it
        // does *after* that call, on every outcome (child exit or spawn
        // failure alike), is drop `pending`. That is what this reproduces.
        drop(redeemed);
        assert_eq!(
            rig.quotas.exec_in_use(&opener),
            0,
            "the permit is released once the redeemed ticket is dropped"
        );

        // And the slot really is usable again, not just reported as such.
        let second = rig
            .server
            .dispatch(&ctx, &exec_start(2, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&second), None);
    }

    /// The path the verdict flags: an unredeemed exec ticket's permit must
    /// not survive the ticket itself. Production reaches an expired ticket
    /// after `TICKET_TTL` (30 s) of real wall-clock time — `expires_at`
    /// uses `std::time::Instant::now()` directly, not the injected
    /// `TestClock`, so this test forces the same state by hand and
    /// exercises the sweep itself (`Server::pending_tickets_for`, reached
    /// through `check_ticket_budget` on the next request), not the wait.
    #[tokio::test]
    async fn exec_permit_is_released_when_its_ticket_expires() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_exec_per_principal: 1,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let opener = opener_key(&ctx.principal, ctx.auth_path);

        let first = rig
            .server
            .dispatch(&ctx, &exec_start(1, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&first), None);
        assert_eq!(rig.quotas.exec_in_use(&opener), 1);

        // Confirms the slot really is still held while the ticket lives.
        let refused = rig
            .server
            .dispatch(&ctx, &exec_start(2, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&refused), Some(ErrorCode::ResourceExhausted));

        // Force the outstanding ticket to look expired.
        {
            let mut tickets = rig.server.tickets.lock().unwrap_or_else(|e| e.into_inner());
            for ticket in tickets.values_mut() {
                ticket.expires_at = Instant::now() - Duration::from_secs(1);
            }
        }

        // Any call that reaches `pending_tickets_for` (via
        // `check_ticket_budget`) sweeps expired entries first — dropping
        // the expired `PendingExec` and, with it, its `ExecPermit`.
        let after_sweep = rig
            .server
            .dispatch(&ctx, &exec_start(3, &["true"]))
            .await
            .unwrap();
        assert_eq!(
            error_code(&after_sweep),
            None,
            "the freed slot admits a new exec"
        );
        assert_eq!(
            rig.quotas.exec_in_use(&opener),
            1,
            "exactly one live permit, not two"
        );
    }

    /// `Server::quota_housekeeping`'s new first step (A9 of the M8 Step
    /// 3a fix-3 sweep): sweeping expired tickets is no longer something
    /// only a *request* reaches through `check_ticket_budget`/
    /// `pending_tickets_for` — the housekeeping call itself must do it,
    /// so `Server::run`'s tick, its post-loop shutdown call,
    /// `purge_connection`, and `reverse::target`'s per-connection tick
    /// all bound an expired unredeemed exec ticket's `ExecPermit` to
    /// `TICKET_TTL` plus one tick, with no request required to free it.
    #[tokio::test]
    async fn quota_housekeeping_sweeps_expired_tickets_before_flushing_audit() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_exec_per_principal: 1,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let opener = opener_key(&ctx.principal, ctx.auth_path);

        let first = rig
            .server
            .dispatch(&ctx, &exec_start(1, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&first), None);
        assert_eq!(rig.quotas.exec_in_use(&opener), 1);

        // Force the outstanding ticket to look expired, same as
        // `exec_permit_is_released_when_its_ticket_expires` above.
        {
            let mut tickets = rig.server.tickets.lock().unwrap_or_else(|e| e.into_inner());
            for ticket in tickets.values_mut() {
                ticket.expires_at = Instant::now() - Duration::from_secs(1);
            }
        }

        // No request in between — `quota_housekeeping` alone sweeps it.
        rig.server.quota_housekeeping();

        assert_eq!(
            rig.quotas.exec_in_use(&opener),
            0,
            "quota_housekeeping released the expired ticket's permit on its own"
        );
    }

    /// Mechanical form of `docs/adr/0010-resource-quotas.md` §9's
    /// "collect under the guard, drop outside" rule (B4 of the M8 Step 3a
    /// fix-3 sweep, extended by M8 Step 3b ruling A4 to the
    /// `remote_forwards` lock as well): exercises all four sites that
    /// sweep expired tickets — `pending_tickets_for`, `issue_ticket`,
    /// `purge_connection`, `quota_housekeeping` — each against an expired
    /// ticket whose `ExecPermit` is about to drop, plus (at the
    /// `purge_connection` site) a live `RemoteForwardEntry` whose own
    /// `RemoteForwardPermit` is about to drop from the same call, and
    /// asserts `crate::quota::lock_order::violations() == 0` once all
    /// four have run. `VIOLATIONS` is process-global, not per-test
    /// (`lock_order`'s own doc) — `cargo nextest` runs one test per
    /// process, so a nonzero count read back here is never cross-test
    /// noise.
    #[tokio::test]
    async fn ticket_sweep_sites_never_drop_an_exec_permit_while_the_tickets_lock_is_held() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                // Generous — this test is about lock order, not about
                // exhausting the exec cap, and each site below leaves one
                // extra permit outstanding for the next site to sweep.
                max_exec_per_principal: 8,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let opener = opener_key(&ctx.principal, ctx.auth_path);
        let conn_id = ctx.conn_id;

        // Reserve a real `ExecPermit` and wrap it in an already-expired
        // `Ticket`, the same shape `Server::handle_exec_start` builds
        // before `issue_ticket` — but built directly so each site below
        // can be called on its own, not only reachable through
        // `dispatch`'s own call chain (which would sweep at
        // `pending_tickets_for` before any later site got a turn).
        let expired_exec_ticket = |exec_id: &str| -> Ticket {
            let permit = rig.quotas.reserve_exec(&opener).unwrap();
            Ticket {
                purpose: TicketPurpose::Exec(PendingExec {
                    exec_id: exec_id.to_string(),
                    spec: crate::exec::ExecSpec {
                        argv: vec!["true".to_string()],
                        env: Vec::new(),
                        timeout: None,
                    },
                    permit,
                }),
                conn_id,
                expires_at: Instant::now() - Duration::from_secs(1),
            }
        };
        let insert = |key: u8, ticket: Ticket| {
            let mut tickets = rig.server.tickets.lock().unwrap_or_else(|e| e.into_inner());
            tickets.insert([key; TICKET_LEN], ticket);
        };

        // Site 1: `pending_tickets_for`.
        insert(1, expired_exec_ticket("a"));
        let _ = rig.server.pending_tickets_for(conn_id);

        // Site 2: `issue_ticket`'s own sweep (distinct from
        // `pending_tickets_for`'s — see `check_ticket_budget`'s call
        // order, which always runs the latter first inside `dispatch`).
        insert(2, expired_exec_ticket("b"));
        let fresh_permit = rig.quotas.reserve_exec(&opener).unwrap();
        let _ = rig.server.issue_ticket(
            conn_id,
            TicketPurpose::Exec(PendingExec {
                exec_id: "c".to_string(),
                spec: crate::exec::ExecSpec {
                    argv: vec!["true".to_string()],
                    env: Vec::new(),
                    timeout: None,
                },
                permit: fresh_permit,
            }),
        );

        // Site 3: `purge_connection` — removes every ticket for `conn_id`
        // regardless of expiry, including the still-live one `issue_ticket`
        // just inserted above; also (A4) removes every `RemoteForwardEntry`
        // this `conn_id` opened, whose own `RemoteForwardPermit` must drop
        // only after `remote_forwards`'s lock is released, exactly like
        // `ExecPermit` above and the tickets lock.
        {
            let remote_forward_permit = rig.quotas.reserve_remote_forward(&opener).unwrap();
            let task = tokio::spawn(std::future::pending::<()>());
            rig.server.lock_remote_forwards().insert(
                "adv-a4-forward".to_string(),
                RemoteForwardEntry {
                    conn_id,
                    owner: opener.clone(),
                    task,
                    _quota: remote_forward_permit,
                },
            );
        }
        rig.server.purge_connection(conn_id, ()).await;

        // Site 4: `quota_housekeeping`.
        insert(4, expired_exec_ticket("e"));
        rig.server.quota_housekeeping();

        assert_eq!(
            crate::quota::lock_order::violations(),
            0,
            "a quota permit (ExecPermit or RemoteForwardPermit) dropped while a non-leaf lock \
             (tickets or remote_forwards) was still held"
        );
    }

    #[tokio::test]
    async fn exec_quota_rejections_aggregate_into_one_first_line_and_one_summary() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_exec_per_principal: 1,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);

        let first = rig
            .server
            .dispatch(&ctx, &exec_start(1, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&first), None);
        let before = rig.audit.records().len();

        // A burst of 3 rejections, all inside the same aggregation window.
        for i in 0..3u64 {
            let reply = rig
                .server
                .dispatch(&ctx, &exec_start(100 + i, &["true"]))
                .await
                .unwrap();
            assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));
        }
        // Each of the 3 rejected calls still writes its own ACL *allow*
        // line (`check_ticket_budget`/ACL run before the quota check, same
        // as `exec_cap_rejects_past_the_limit_and_audits_quota_exec_
        // principal`) — what this test pins is that only one of those
        // three calls also produced a *quota* line, not that the audit log
        // grew by exactly one record overall.
        let quota_lines: Vec<_> = rig
            .audit
            .records()
            .into_iter()
            .skip(before)
            .filter(|r| r.resource == "quota_exec_principal")
            .collect();
        assert_eq!(
            quota_lines.len(),
            1,
            "only the burst's first rejection gets its own quota line"
        );
        assert_eq!(quota_lines[0].count, None);

        // The tick `Server::run`'s accept loop drives, exercised directly:
        // the burst has already stopped, so only the periodic flush (not
        // the lazy `record_rejection` path) can close this window.
        rig.clock
            .advance(crate::admission::AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));
        let flushed = rig.quotas.flush_expired(rig.quotas.now());
        for record in &flushed {
            rig.audit.record(record).unwrap();
        }
        assert_eq!(flushed.len(), 1);
        assert_eq!(
            flushed[0].count,
            Some(2),
            "the two suppressed rejections after the burst's first line"
        );
        assert_eq!(flushed[0].resource, "quota_exec_principal");

        // A second flush at the same instant finds nothing left to close.
        assert!(rig.quotas.flush_expired(rig.quotas.now()).is_empty());
    }

    // ---- session-count quota (`Broker::open_with_opener`'s own
    // `reserve_session`) + ACL-vs-quota ordering (verdict arbitration item
    // 11) --------------------------------------------------------------

    /// An unauthorized principal must never learn "the host is at
    /// capacity" as a substitute for "you are not allowed here" — that
    /// would be an oracle on occupancy to a peer who should learn nothing.
    #[tokio::test]
    async fn saturated_quota_still_answers_permission_denied_to_an_unauthorized_principal() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_sessions: 1,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let allowed_ctx = ctx(Principal::Device("laptop".into()), &["session"]);
        let _opened = open_session(&rig, &allowed_ctx).await;
        assert_eq!(rig.broker.session_count(), 1);

        // A CA-asserted principal is not pinned, so `AllowAllPinned` denies
        // it outright (same setup as
        // `unpinned_principal_is_denied_under_interim_policy`) — and the
        // host's single session slot is already saturated by the open
        // above.
        let mut denied_ctx = allowed_ctx.clone();
        denied_ctx.principal = Principal::User("mallory".into());
        denied_ctx.auth_path = AuthPath::Ca;
        denied_ctx.conn_id += 1;

        let reply = rig
            .server
            .dispatch(&denied_ctx, &session_open(9))
            .await
            .unwrap();
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::PermissionDenied),
            "ACL must run before the quota check"
        );
        // Nothing was created for the refused attempt.
        assert_eq!(rig.broker.session_count(), 1);
        assert_eq!(
            rig.server.pending_tickets(),
            1,
            "only the first, allowed open's ticket"
        );
    }

    /// Main-session arbitration round, item 3: `handle_exec_start` now
    /// runs `check_ticket_budget` *after* the ACL choke point (F4 of the
    /// M8 Step 3a conformance sweep had instead documented — and pinned —
    /// the pre-existing order where the ticket-budget check ran first;
    /// this reverses that call). `check_ticket_budget` creates nothing, so
    /// there was never a resource-creation reason to run it early, and
    /// leaving it first made `RESOURCE_EXHAUSTED` vs. `PERMISSION_DENIED`
    /// tell an unauthorized caller something about its own connection's
    /// state before ACL ever got a say. This pins the order directly, on
    /// one connection whose ticket budget is genuinely exhausted: a
    /// principal ACL denies still sees `PERMISSION_DENIED` (proving ACL
    /// runs first), and a principal ACL allows still sees
    /// `RESOURCE_EXHAUSTED` (proving the ticket-budget check still runs,
    /// second).
    #[tokio::test]
    async fn exec_ticket_budget_follows_the_acl_choke_point_on_the_same_connection() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_exec_per_principal: MAX_PENDING_TICKETS_PER_CONN * 4,
                ..crate::quota::QuotaLimits::default()
            },
        );
        // A pinned device fills its own connection's ticket budget under
        // an ACL that allows it — ordinary, authorized traffic.
        let allowed_ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        for i in 0..MAX_PENDING_TICKETS_PER_CONN {
            let reply = rig
                .server
                .dispatch(&allowed_ctx, &exec_start(i as u64, &["true"]))
                .await
                .unwrap();
            assert_eq!(error_code(&reply), None, "ticket {i} must be issued");
        }
        assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);

        // The SAME connection (`conn_id` unchanged), but the principal on
        // this next request is one `AllowAllPinned` denies outright — not
        // a realistic mid-connection identity change, just the sharpest
        // way to isolate which check answers first.
        let mut denied_same_conn = allowed_ctx.clone();
        denied_same_conn.principal = Principal::User("mallory".into());
        denied_same_conn.auth_path = AuthPath::Ca;

        let reply = rig
            .server
            .dispatch(&denied_same_conn, &exec_start(999, &["true"]))
            .await
            .unwrap();
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::PermissionDenied),
            "ACL now runs before check_ticket_budget — an unauthorized \
             principal must never see RESOURCE_EXHAUSTED as a substitute \
             for PERMISSION_DENIED, even on a connection whose ticket \
             budget happens to be exhausted"
        );
        assert_eq!(
            rig.server.pending_tickets(),
            MAX_PENDING_TICKETS_PER_CONN,
            "the denied attempt must not have issued a ticket"
        );

        // The SAME connection, still at its ticket budget, but a principal
        // ACL allows: PERMISSION_DENIED is off the table, so the ticket
        // budget check underneath must still fire.
        let reply = rig
            .server
            .dispatch(&allowed_ctx, &exec_start(1000, &["true"]))
            .await
            .unwrap();
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::ResourceExhausted),
            "an ACL-allowed principal must still be bounded by its \
             connection's own ticket budget"
        );
        assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
    }

    /// `handle_session_open`'s twin of the pin above: the M8 Step 3a
    /// conformance sweep's F4 had also left `session.open` checking its
    /// ticket budget ahead of the ACL choke point (adversary finding A1) —
    /// this pins the corrected order the same way, on one connection whose
    /// ticket budget is genuinely exhausted: a principal ACL denies still
    /// sees `PERMISSION_DENIED` (proving ACL runs first) *and* still gets
    /// its own ACL-deny audit row (proving the denied attempt reached the
    /// choke point rather than being short-circuited by the ticket-budget
    /// check before ACL ever ran), while a principal ACL allows still sees
    /// `RESOURCE_EXHAUSTED` (proving the ticket-budget check still runs,
    /// second).
    #[tokio::test]
    async fn session_open_ticket_budget_follows_the_acl_choke_point_on_the_same_connection() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_sessions: MAX_PENDING_TICKETS_PER_CONN * 4,
                max_sessions_per_principal: MAX_PENDING_TICKETS_PER_CONN * 4,
                ..crate::quota::QuotaLimits::default()
            },
        );
        // A pinned device fills its own connection's ticket budget under
        // an ACL that allows it — ordinary, authorized traffic.
        let allowed_ctx = ctx(Principal::Device("laptop".into()), &["session"]);
        for i in 0..MAX_PENDING_TICKETS_PER_CONN {
            let reply = rig
                .server
                .dispatch(&allowed_ctx, &session_open(i as u64))
                .await
                .unwrap();
            assert_eq!(error_code(&reply), None, "ticket {i} must be issued");
        }
        assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
        let records_before_deny = rig.audit.records().len();

        // The SAME connection (`conn_id` unchanged), but the principal on
        // this next request is one `AllowAllPinned` denies outright — not
        // a realistic mid-connection identity change, just the sharpest
        // way to isolate which check answers first.
        let mut denied_same_conn = allowed_ctx.clone();
        denied_same_conn.principal = Principal::User("mallory".into());
        denied_same_conn.auth_path = AuthPath::Ca;

        let reply = rig
            .server
            .dispatch(&denied_same_conn, &session_open(999))
            .await
            .unwrap();
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::PermissionDenied),
            "ACL now runs before check_ticket_budget on session.open too — \
             an unauthorized principal must never see RESOURCE_EXHAUSTED as \
             a substitute for PERMISSION_DENIED, even on a connection whose \
             ticket budget happens to be exhausted"
        );
        assert_eq!(
            rig.server.pending_tickets(),
            MAX_PENDING_TICKETS_PER_CONN,
            "the denied attempt must not have issued a ticket"
        );
        let recs = rig.audit.records();
        assert_eq!(
            recs.len(),
            records_before_deny + 1,
            "the ACL choke point still writes an audit row for the denied \
             attempt — it was reached and it decided, it did not get \
             short-circuited by a ticket-budget check running first"
        );
        assert_eq!(
            recs.last().unwrap().decision,
            "deny",
            "the denied attempt's own audit row records the ACL deny"
        );

        // The SAME connection, still at its ticket budget, but a principal
        // ACL allows: PERMISSION_DENIED is off the table, so the ticket
        // budget check underneath must still fire.
        let reply = rig
            .server
            .dispatch(&allowed_ctx, &session_open(1000))
            .await
            .unwrap();
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::ResourceExhausted),
            "an ACL-allowed principal must still be bounded by its \
             connection's own ticket budget"
        );
        assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
    }

    /// The ACL choke point's own audit line for an *allowed* principal must
    /// still be written even though that same open then fails on a
    /// saturated quota — a quota rejection is a distinct, later decision,
    /// not a reason to suppress the (already true) ACL verdict that
    /// preceded it.
    #[tokio::test]
    async fn quota_rejection_still_leaves_the_acl_allow_audit_line() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_sessions: 1,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["session"]);
        let _opened = open_session(&rig, &ctx).await;
        assert_eq!(
            rig.audit.records().len(),
            1,
            "first open's own ACL allow line"
        );

        // Same, allowed principal, second connection — ACL allows again
        // (unowned resource, still pinned), but the global session cap is
        // already saturated by the first open.
        let mut second_conn = ctx.clone();
        second_conn.conn_id += 1;
        let reply = rig
            .server
            .dispatch(&second_conn, &session_open(2))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));

        let recs = rig.audit.records();
        assert_eq!(
            recs.len(),
            3,
            "first open's allow, second open's allow, second's quota deny"
        );
        assert_eq!(
            recs[1].decision, "allow",
            "the ACL allow line is written even though the open then fails on quota"
        );
        assert_eq!(recs[2].decision, "deny");
        assert_eq!(recs[2].resource, "quota_sessions_host");
        assert_eq!(recs[2].action, "session.open");
        assert_eq!(
            recs[1].request_id, recs[2].request_id,
            "the ACL allow line and the quota deny line for the SAME request \
             must share a request_id, or the two cannot be correlated \
             (verdict ruling 11①)"
        );
        assert_ne!(
            recs[2].request_id, "-",
            "the quota deny record must carry the real request_id, not the \
             placeholder used before F2 threaded it through"
        );
        assert_eq!(
            recs[2].request_id, "2",
            "R9 — the session axis has a real control request id to carry"
        );
        assert_eq!(
            recs[2].peer_addr,
            ctx.peer_addr.to_string(),
            "R4 — the quota deny record must carry the live peer, not \"-\""
        );
    }

    /// `PLAN.md` M5 Step 3(c) "disk-full fail-closed": an
    /// `AllowAllPinned`-eligible peer's `session.open` is denied — and no
    /// session is created — while the audit sink cannot durably record the
    /// allow, then succeeds once the sink recovers. Exercises
    /// `Server::authorize`, the first of the four fail-closed choke points
    /// (`PLAN.md` §1's "four authorization points").
    #[tokio::test]
    async fn session_open_fails_closed_when_the_audit_sink_cannot_record_an_allow() {
        let clock = TestClock::new();
        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(clock.clone()),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
                quota_limits: crate::quota::QuotaLimits::default(),
            },
            pipes.clone(),
        );
        let audit = Arc::new(FailingAuditSink::new());
        let server = Server::new(
            Arc::new(AllowAllPinned),
            audit.clone(),
            broker.clone(),
            "host",
        );
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

        // Policy would allow this peer — but the audit sink cannot durably
        // record the decision, so the choke point denies it rather than
        // create a session with no durable record of having authorized it.
        audit.fail();
        let reply = server.dispatch(&ctx, &session_open(1)).await.unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        assert_eq!(
            broker.session_count(),
            0,
            "no session created while the audit sink is degraded"
        );
        // F8 (M5 Step 4 adversarial review): the degraded-deny reply must
        // carry the exact same wire message as an ordinary policy deny —
        // a peer must not be able to tell "the audit sink is degraded"
        // from "policy said no" by reading `message` (`PERMISSION_DENIED_
        // MESSAGE`'s own doc, `Server::permission_denied`'s doc).
        match &reply.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => assert_eq!(
                e.message,
                crate::acl::PERMISSION_DENIED_MESSAGE,
                "fail-closed audit-degraded deny must use the uniform message, byte for byte"
            ),
            other => panic!("expected an error response, got {other:?}"),
        }

        // The writer recovers: the same policy-allowed request now
        // succeeds, and only now does a session exist.
        audit.clear();
        let reply = server.dispatch(&ctx, &session_open(2)).await.unwrap();
        assert!(matches!(
            response_body(&reply),
            response::Body::SessionOpened(_)
        ));
        assert_eq!(broker.session_count(), 1);
        assert_eq!(
            audit.records().len(),
            1,
            "the denied attempt was never durably recorded, only the recovered allow"
        );
    }

    /// `ARBITRATION-4.md` J7 고리4: fail-closed extended to the attach
    /// choke point — [`Server::authorize`] is the same choke point
    /// `session.open` goes through
    /// (`session_open_fails_closed_when_the_audit_sink_cannot_record_
    /// an_allow` pins that axis), so a `session.attach` whose credential
    /// verifies but whose allow cannot be durably recorded is denied with
    /// the exact same [`crate::acl::PERMISSION_DENIED_MESSAGE`],
    /// byte-for-byte — a peer must not be able to tell "audit degraded"
    /// from "policy said no." The still-valid resume token is untouched
    /// by the denial (`Broker::rotate_resume` only runs once the ACL
    /// choke point has already passed), so the same token attaches
    /// successfully once the sink recovers.
    #[tokio::test]
    async fn session_attach_fails_closed_when_the_audit_sink_cannot_record_an_allow() {
        let clock = TestClock::new();
        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(clock.clone()),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
                quota_limits: crate::quota::QuotaLimits::default(),
            },
            pipes.clone(),
        );
        let audit = Arc::new(FailingAuditSink::new());
        let server = Server::new(
            Arc::new(AllowAllPinned),
            audit.clone(),
            broker.clone(),
            "host",
        );
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

        // Open the session while the sink is healthy — the axis under
        // test is `session.attach`, not `session.open`.
        let reply = server.dispatch(&ctx, &session_open(1)).await.unwrap();
        let opened = match response_body(&reply) {
            response::Body::SessionOpened(o) => o.clone(),
            other => panic!("expected SessionOpened, got {other:?}"),
        };
        let _pipe = pipes.take().expect("pipe handle for the new session");

        let attach = |token: Vec<u8>| wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: token,
            mode: wire::AttachMode::Rw as i32,
            ..Default::default()
        };

        audit.fail();
        let reply = server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    2,
                    control_message::Body::SessionAttach(attach(opened.resume_token.clone())),
                ),
            )
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        match &reply.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => assert_eq!(
                e.message,
                crate::acl::PERMISSION_DENIED_MESSAGE,
                "fail-closed audit-degraded deny must use the uniform message, byte for byte"
            ),
            other => panic!("expected an error response, got {other:?}"),
        }

        // Recovery: the same still-valid resume token now succeeds — a
        // degraded audit sink must never burn the credential it denied
        // under.
        audit.clear();
        let reply = server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    3,
                    control_message::Body::SessionAttach(attach(opened.resume_token.clone())),
                ),
            )
            .await
            .unwrap();
        assert!(
            matches!(response_body(&reply), response::Body::SessionAttached(_)),
            "expected SessionAttached once the audit sink recovers, got {reply:?}"
        );
    }

    /// `ARBITRATION-4.md` M8 Step 4 fixer round F2 (A-P2-1): fail-closed
    /// extended to the ownership-aware choke point — [`Server::
    /// authorize_owned`] is a *different* fail-closed branch than
    /// [`Server::authorize`] (`session_open_fails_closed_when_the_audit_
    /// sink_cannot_record_an_allow` and `session_attach_fails_closed_
    /// when_the_audit_sink_cannot_record_an_allow` both only exercise the
    /// latter, via [`Server::authorize`]'s own `!verdict.is_allow() ||
    /// recorded.is_err()`). `session.write` reaches `authorize_owned`
    /// through `authorize_session_control` → `require_opener`
    /// (`Server::prepare_session_write`'s doc), and only the session's own
    /// opener gets an `is_allow()` verdict under the default `scope =
    /// "owned"` policy — a foreign principal's write is already denied by
    /// ownership before `authorize_owned`'s own fail-closed branch is
    /// ever reached, which is exactly why this test must write as the
    /// opener, the same way `write_by_another_principal_is_denied_by_
    /// ownership_not_the_lease` pins the foreign-principal side of the
    /// same choke point. Same byte-identical `PERMISSION_DENIED_MESSAGE`
    /// contract, same recovery-without-burning-anything shape.
    #[tokio::test]
    async fn session_write_fails_closed_when_the_audit_sink_cannot_record_an_allow() {
        let clock = TestClock::new();
        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(clock.clone()),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
                quota_limits: crate::quota::QuotaLimits::default(),
            },
            pipes.clone(),
        );
        let audit = Arc::new(FailingAuditSink::new());
        let server = Server::new(
            Arc::new(AllowAllPinned),
            audit.clone(),
            broker.clone(),
            "host",
        );
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

        // Open the session while the sink is healthy — the axis under
        // test is `session.write`, not `session.open`.
        let reply = server.dispatch(&ctx, &session_open(1)).await.unwrap();
        let opened = match response_body(&reply) {
            response::Body::SessionOpened(o) => o.clone(),
            other => panic!("expected SessionOpened, got {other:?}"),
        };
        let _pipe = pipes.take().expect("pipe handle for the new session");

        let write = |request_id: u64| {
            ControlMessage::new(
                request_id,
                control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: opened.session_id.clone(),
                    data: b"x".to_vec(),
                }),
            )
        };

        audit.fail();
        let reply = server.dispatch(&ctx, &write(2)).await.unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        match &reply.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => assert_eq!(
                e.message,
                crate::acl::PERMISSION_DENIED_MESSAGE,
                "fail-closed audit-degraded deny must use the uniform message, byte for byte"
            ),
            other => panic!("expected an error response, got {other:?}"),
        }

        // Recovery: the same opener's write now succeeds once the sink
        // recovers.
        audit.clear();
        let reply = server.dispatch(&ctx, &write(3)).await.unwrap();
        assert_eq!(
            error_code(&reply),
            None,
            "expected session.write to succeed once the audit sink recovers, got {reply:?}"
        );
    }

    /// An unsolicited SessionEvent (host → client only) is dropped.
    #[tokio::test]
    async fn inbound_session_event_is_ignored() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let msg = ControlMessage::new(
            0,
            control_message::Body::SessionEvent(wire::SessionEvent::closed(
                "01K0SESSION",
                "closed",
                1,
            )),
        );
        assert!(rig.server.dispatch(&ctx, &msg).await.is_none());
    }

    /// Reserved control number 25 (`SessionSignal`, CLI.md §2.4) and any
    /// still-unknown number decode to `body: None` and are answered
    /// UNSUPPORTED without creating anything. Tags 40/41 are NO LONGER in
    /// that set — M4 Step 1 realized them as `RemoteForwardOpen`/`Close`, so
    /// prost decodes them to a real (empty) body and they take a dedicated
    /// UNSUPPORTED arm until the host handler lands (M4 Step 4/5); that path
    /// is covered separately below.
    #[tokio::test]
    async fn reserved_and_unknown_control_numbers_are_unsupported() {
        // request_id = 7 (field 1 varint), then field N (LEN) with an empty
        // body: tag = (N << 3) | 2 as a varint.
        fn raw_with_field(field: u32) -> Vec<u8> {
            let mut b = vec![0x08, 0x07];
            let tag = (field << 3) | 2;
            let mut v = tag;
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    b.push(byte);
                    break;
                }
                b.push(byte | 0x80);
            }
            b.push(0x00);
            b
        }
        for field in [25u32, 200] {
            let msg: ControlMessage = wire::decode_msg(&raw_with_field(field)).unwrap();
            assert_eq!(msg.request_id, 7);
            assert!(
                msg.body.is_none(),
                "field {field} should be dropped by prost"
            );
            let rig = allow_rig();
            let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
            let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();
            assert_eq!(reply.request_id, 7);
            assert_eq!(
                error_code(&reply),
                Some(ErrorCode::Unsupported),
                "field {field}"
            );
            assert!(rig.audit.records().is_empty());
            assert_eq!(rig.server.pending_tickets(), 0);
            assert_eq!(rig.broker.session_count(), 0);
        }
        // Tunnel control (40/41) is realized (M4 Step 1) and now has real
        // host handlers (M4 Step 4). `RfwdOpen` still draws `UNSUPPORTED`
        // from a *bare* `dispatch` call specifically — not because the op
        // is unimplemented, but because opening a remote forward needs a
        // live `Connection` this call has none of
        // (`Server::handle_rfwd_open`'s own doc; the real path is
        // `serve_control`'s early interception, covered by
        // `rfwd_open_end_to_end_streams_tcp_accepted_then_close_tears_down`).
        // `RfwdClose` needs no connection, so `dispatch` runs it for real —
        // an unregistered `forward_id` (the zero value `default()` gives)
        // is `INVALID_ARGUMENT`, not `UNSUPPORTED`.
        for (body, want) in [
            (
                control_message::Body::RfwdOpen(wire::RemoteForwardOpen::default()),
                ErrorCode::Unsupported,
            ),
            (
                control_message::Body::RfwdClose(wire::RemoteForwardClose::default()),
                ErrorCode::InvalidArgument,
            ),
        ] {
            assert!(
                ControlMessage::new(7, body.clone()).body.is_some(),
                "40/41 are realized, not dropped to None"
            );
            let rig = allow_rig();
            let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
            let reply = rig
                .server
                .dispatch(&ctx, &ControlMessage::new(7, body))
                .await
                .unwrap();
            assert_eq!(reply.request_id, 7);
            assert_eq!(error_code(&reply), Some(want));
            assert!(rig.audit.records().is_empty());
            assert_eq!(rig.server.pending_tickets(), 0);
            assert_eq!(rig.broker.session_count(), 0);
        }
        // A genuinely empty message gets the same answer.
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage {
                    request_id: 9,
                    body: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
    }

    #[tokio::test]
    async fn empty_argv_is_invalid_argument() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(1, &[]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::InvalidArgument));
    }

    #[tokio::test]
    async fn ping_gets_pong_with_same_request_id() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(77, control_message::Body::Ping(wire::Ping {})),
            )
            .await
            .unwrap();
        assert_eq!(reply.request_id, 77);
        assert!(matches!(reply.body, Some(control_message::Body::Pong(_))));
        assert!(
            rig.server
                .dispatch(
                    &ctx,
                    &ControlMessage::new(78, control_message::Body::Pong(wire::Pong {}))
                )
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn purge_connection_drops_its_tickets_and_leases_but_keeps_sessions() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        rig.server.dispatch(&ctx, &exec_start(1, &["true"])).await;
        let (id, _ticket, _pipe) = open_session(&rig, &ctx).await;
        assert_eq!(rig.server.pending_tickets(), 2);
        // A write takes the writer lease for this connection.
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    3,
                    control_message::Body::SessionWrite(wire::SessionWrite {
                        session_id: id.clone(),
                        data: b"x".to_vec(),
                    }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(error_code(&reply), None, "{reply:?}");
        let sid = SessionId(id.clone());
        assert_eq!(
            rig.broker.get(&sid).unwrap().info().writer.as_deref(),
            Some("device:laptop")
        );

        rig.server.purge_connection(42, ()).await;
        assert_eq!(rig.server.pending_tickets(), 0);
        assert_eq!(rig.broker.get(&sid).unwrap().info().writer, None);
        assert_eq!(rig.broker.session_count(), 1, "the session survives");
    }

    // ---- session ops: choke point --------------------------------------

    /// Under `DenyAll` every session op is PERMISSION_DENIED, audited as a
    /// deny, and creates nothing — no session, no ticket. This includes
    /// ops on a session that does exist: an unauthorized peer gets the
    /// same answer whether or not the id is real (non-distinguishing).
    #[tokio::test]
    async fn denied_session_ops_create_nothing_and_do_not_disclose_existence() {
        // A real session, created by an allowed rig sharing the broker…
        let allowed = allow_rig();
        let ctx_ok = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (real_id, _t, _pipe) = open_session(&allowed, &ctx_ok).await;
        // …seen through a deny-all server on the same broker.
        let denying = Server::new(
            Arc::new(DenyAll),
            allowed.audit.clone(),
            allowed.broker.clone(),
            "host",
        );
        allowed.audit.clear();
        let ctx_deny = ctx(Principal::Device("intruder".into()), ALL_CAPS);
        let mut replies = Vec::new();
        for id in [real_id.as_str(), "01K0NOSUCHSESSION"] {
            for (i, (name, body)) in session_bodies(id).into_iter().enumerate() {
                let request_id = 100 + i as u64;
                let reply = denying
                    .dispatch(&ctx_deny, &ControlMessage::new(request_id, body))
                    .await
                    .expect("session requests get a reply");
                assert_eq!(reply.request_id, request_id);
                assert_eq!(
                    error_code(&reply),
                    Some(ErrorCode::PermissionDenied),
                    "{name} on {id}"
                );
                replies.push((name, error_code(&reply)));
            }
        }
        // Identical answers for the real and the fabricated id.
        let (real, fake) = replies.split_at(replies.len() / 2);
        assert_eq!(real, fake, "existence must not be distinguishable");
        // Nothing created.
        assert_eq!(denying.pending_tickets(), 0);
        assert_eq!(
            allowed.broker.session_count(),
            1,
            "only the pre-existing one"
        );
        assert_eq!(allowed.pipes.pending(), 0);
        // One structural audit line per op, all denies, all through Action.
        let recs = allowed.audit.records();
        assert_eq!(recs.len(), 14);
        assert!(recs.iter().all(|r| r.decision == "deny"));
        assert!(recs.iter().all(|r| r.principal == "device:intruder"));
        let actions: std::collections::BTreeSet<&str> =
            recs.iter().map(|r| r.action.as_str()).collect();
        // The distinct actions among the 7 session ops, sourced from
        // `OP_REGISTRY` (`PLAN.md` M5 Step 8) rather than named a second
        // time as `Action` literals — a dedup set, since `session.write`/
        // `resize`/`close` all resolve to `Action::SessionControl`.
        let expected_actions: std::collections::BTreeSet<&str> = [
            crate::acl::Op::SessionOpen,
            crate::acl::Op::SessionList,
            crate::acl::Op::SessionGet,
            crate::acl::Op::SessionRead,
            crate::acl::Op::SessionWrite,
            crate::acl::Op::SessionResize,
            crate::acl::Op::SessionClose,
        ]
        .iter()
        .map(|op| op.action().as_str())
        .collect();
        assert_eq!(actions, expected_actions);
    }

    /// Each session op is audited under exactly the action CLI.md §2.5
    /// maps it to, with the session id (or "session") as resource.
    #[tokio::test]
    async fn every_session_op_passes_the_choke_point_with_the_mapped_action() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, _pipe) = open_session(&rig, &ctx).await;
        rig.audit.clear();
        let mut expected: Vec<(&str, Action, String)> = Vec::new();
        for (name, body) in session_bodies(&id) {
            let reply = rig
                .server
                .dispatch(&ctx, &ControlMessage::new(7, body))
                .await
                .unwrap();
            assert_eq!(error_code(&reply), None, "{name}: {reply:?}");
            // `Action`s sourced from `OP_REGISTRY` by dotted op name
            // (`PLAN.md` M5 Step 8), not named a second time as literals —
            // `resource` still depends on which sentinel/id shape each op
            // uses (`OpSpec::resource_kind` documents the shape; the
            // literal string is still the request's own, same as before).
            let (action, resource) = match name {
                "open" => (
                    crate::acl::Op::SessionOpen.action(),
                    SESSION_RESOURCE.to_string(),
                ),
                "list" => (
                    crate::acl::Op::SessionList.action(),
                    SESSION_RESOURCE.to_string(),
                ),
                "get" => (crate::acl::Op::SessionGet.action(), id.clone()),
                "read" => (crate::acl::Op::SessionRead.action(), id.clone()),
                "write" => (crate::acl::Op::SessionWrite.action(), id.clone()),
                "resize" => (crate::acl::Op::SessionResize.action(), id.clone()),
                "close" => (crate::acl::Op::SessionClose.action(), id.clone()),
                other => panic!("unexpected op {other}"),
            };
            expected.push((name, action, resource));
        }
        let recs = rig.audit.records();
        assert_eq!(recs.len(), expected.len());
        for (rec, (name, action, resource)) in recs.iter().zip(&expected) {
            assert_eq!(rec.action, action.as_str(), "{name}");
            assert_eq!(&rec.resource, resource, "{name}");
            assert_eq!(rec.decision, "allow", "{name}");
            assert_eq!(rec.request_id, "7", "{name}");
        }
        // The extra `open` in the loop created a second session + ticket.
        assert_eq!(rig.broker.session_count(), 1, "the loop closed the first");
        assert_eq!(rig.server.pending_tickets(), 2);
    }

    #[tokio::test]
    async fn session_ops_without_capability_are_unsupported_and_not_audited() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        for (name, body) in session_bodies("01K0SESSION") {
            let reply = rig
                .server
                .dispatch(&ctx, &ControlMessage::new(1, body))
                .await
                .unwrap();
            assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported), "{name}");
        }
        assert!(rig.audit.records().is_empty());
        assert_eq!(rig.server.pending_tickets(), 0);
        assert_eq!(rig.broker.session_count(), 0);
    }

    // ---- session ops: behaviour ---------------------------------------

    #[tokio::test]
    async fn open_creates_a_session_and_a_session_data_ticket() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let reply = rig.server.dispatch(&ctx, &session_open(1)).await.unwrap();
        let opened = match response_body(&reply) {
            response::Body::SessionOpened(o) => o.clone(),
            other => panic!("expected SessionOpened, got {other:?}"),
        };
        assert_eq!(opened.initial_seq, 0);
        // A resume credential is issued with the session and bound to the
        // connection's verified peer (protocol.md §10). It is the one
        // thing in this reply that never reaches a log or an envelope.
        assert_eq!(
            opened.resume_token.len(),
            RESUME_TOKEN_LEN,
            "session.open must issue a resume credential"
        );
        assert!(!opened.expires_at.is_empty());
        assert_eq!(opened.ticket.len(), TICKET_LEN);
        assert_eq!(rig.broker.session_count(), 1);
        assert_eq!(rig.pipes.pending(), 1);
        // The ticket redeems for SESSION_DATA only, once, on this connection.
        assert!(
            rig.server
                .redeem_ticket(42, StreamKind::ExecData, &opened.ticket)
                .is_none()
        );
        let ticket = rig
            .server
            .redeem_ticket(42, StreamKind::SessionData, &opened.ticket)
            .expect("session ticket");
        assert!(matches!(
            ticket.purpose,
            TicketPurpose::Session { session_id, .. } if session_id.0 == opened.session_id
        ));
        assert!(
            rig.server
                .redeem_ticket(42, StreamKind::SessionData, &opened.ticket)
                .is_none()
        );
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action, "session.open");
        assert_eq!(recs[0].resource, SESSION_RESOURCE);
    }

    #[tokio::test]
    async fn open_with_a_foreign_user_hint_is_unsupported_after_acl_and_creates_nothing() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let msg = ControlMessage::new(
            1,
            control_message::Body::SessionOpen(wire::SessionOpen {
                user: Some("definitely-not-the-serve-account-\u{1f512}".into()),
                ..Default::default()
            }),
        );
        let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
        assert_eq!(rig.broker.session_count(), 0);
        assert_eq!(rig.server.pending_tickets(), 0);
        // The ACL decision was made (and audited as allow) before the hint
        // check — hint validation is post-authorization only.
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "allow");

        // An unauthorized peer with the same hint is PERMISSION_DENIED,
        // never UNSUPPORTED (no login-name oracle).
        let denying = Server::new(
            Arc::new(DenyAll),
            rig.audit.clone(),
            rig.broker.clone(),
            "host",
        );
        let reply = denying.dispatch(&ctx, &msg).await.unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn open_with_the_serve_accounts_login_name_as_hint_succeeds() {
        let Some(me) = serve_login_name() else {
            eprintln!("no passwd entry for this uid; skipping");
            return;
        };
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let msg = ControlMessage::new(
            1,
            control_message::Body::SessionOpen(wire::SessionOpen {
                user: Some(me),
                ..Default::default()
            }),
        );
        let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();
        assert_eq!(error_code(&reply), None, "{reply:?}");
        assert_eq!(rig.broker.session_count(), 1);
    }

    #[tokio::test]
    async fn write_read_resize_get_list_close_roundtrip() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, mut pipe) = open_session(&rig, &ctx).await;
        let sid = SessionId(id.clone());

        // output arrives → read after 0 returns it with the right sequence.
        pipe.write_output(b"hi\r\n").await.unwrap();
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    3,
                    control_message::Body::SessionRead(wire::SessionRead {
                        session_id: id.clone(),
                        after: 0,
                        max_bytes: 0,
                        wait_ms: 30_000,
                        ctl_after: 0,
                    }),
                ),
            )
            .await
            .unwrap();
        let events = match response_body(&reply) {
            response::Body::SessionReadResult(r) => r.events.clone(),
            other => panic!("expected SessionReadResult, got {other:?}"),
        };
        let mut bytes = Vec::new();
        let mut last_seq = 0;
        for event in &events {
            if let Some(session_read_event::Body::Output(o)) = &event.body {
                bytes.extend_from_slice(&o.data);
                last_seq = o.sequence;
            }
        }
        assert_eq!(bytes, b"hi\r\n");
        assert_eq!(last_seq, 4);

        // write → the pipe sees the input, bytes_written reported.
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    2,
                    control_message::Body::SessionWrite(wire::SessionWrite {
                        session_id: id.clone(),
                        data: b"echo hi\n".to_vec(),
                    }),
                ),
            )
            .await
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionWritten(w) => assert_eq!(w.bytes_written, 8),
            other => panic!("expected SessionWritten, got {other:?}"),
        }
        assert_eq!(pipe.read_input(64).await.unwrap(), b"echo hi\n");

        // Non-blocking read past everything: no output (only the
        // writer_changed control positioned at 4), not an error.
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    4,
                    control_message::Body::SessionRead(wire::SessionRead {
                        session_id: id.clone(),
                        after: 4,
                        max_bytes: 0,
                        wait_ms: 0,
                        ctl_after: 0,
                    }),
                ),
            )
            .await
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionReadResult(r) => assert!(
                r.events
                    .iter()
                    .all(|e| { !matches!(e.body, Some(session_read_event::Body::Output(_))) })
            ),
            other => panic!("expected SessionReadResult, got {other:?}"),
        }
        // Beyond the end is INVALID_ARGUMENT, not NOT_FOUND.
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    5,
                    control_message::Body::SessionRead(wire::SessionRead {
                        session_id: id.clone(),
                        after: 999,
                        ..Default::default()
                    }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::InvalidArgument));

        // resize reaches the source; get/list reflect the state.
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    6,
                    control_message::Body::SessionResize(wire::SessionResize {
                        session_id: id.clone(),
                        cols: 120,
                        rows: 40,
                    }),
                ),
            )
            .await
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionResized(r) => assert_eq!((r.cols, r.rows), (120, 40)),
            other => panic!("expected SessionResized, got {other:?}"),
        }
        assert_eq!(pipe.resizes(), vec![(120, 40)]);
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    7,
                    control_message::Body::SessionGet(wire::SessionGet {
                        session_id: id.clone(),
                    }),
                ),
            )
            .await
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionInfo(info) => {
                assert_eq!(info.session_id, id);
                assert_eq!(info.state, "running");
                assert_eq!(info.writer.as_deref(), Some("device:laptop"));
                assert_eq!(info.last_sequence, 4);
            }
            other => panic!("expected SessionInfo, got {other:?}"),
        }
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(8, control_message::Body::SessionList(wire::SessionList {})),
            )
            .await
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionListResult(list) => {
                assert_eq!(list.sessions.len(), 1);
                assert_eq!(list.sessions[0].session_id, id);
            }
            other => panic!("expected SessionListResult, got {other:?}"),
        }

        // close: the pipe gets HUP and exits; final_seq is the offset.
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    9,
                    control_message::Body::SessionClose(wire::SessionClose {
                        session_id: id.clone(),
                        signal: None,
                    }),
                ),
            )
            .await
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionClosed(c) => assert_eq!(c.final_seq, 4),
            other => panic!("expected SessionClosed, got {other:?}"),
        }
        assert_eq!(pipe.signals(), vec![Signal::Hup]);
        assert!(matches!(rig.broker.get(&sid), Err(BrokerError::NotFound)));

        // Afterwards get/write/resize/close are SESSION_NOT_FOUND, but a
        // read still drains the trailing `closed` control event.
        for (name, body) in session_bodies(&id) {
            if matches!(name, "open" | "list" | "read") {
                continue;
            }
            let reply = rig
                .server
                .dispatch(&ctx, &ControlMessage::new(10, body))
                .await
                .unwrap();
            assert_eq!(
                error_code(&reply),
                Some(ErrorCode::SessionNotFound),
                "{name}"
            );
        }
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    11,
                    control_message::Body::SessionRead(wire::SessionRead {
                        session_id: id.clone(),
                        after: 4,
                        ..Default::default()
                    }),
                ),
            )
            .await
            .unwrap();
        let events = match response_body(&reply) {
            response::Body::SessionReadResult(r) => r.events.clone(),
            other => panic!("expected SessionReadResult, got {other:?}"),
        };
        let kinds: Vec<&str> = events
            .iter()
            .map(|e| match &e.body {
                Some(session_read_event::Body::WriterChanged(_)) => "writer_changed",
                Some(session_read_event::Body::Exit(_)) => "exit",
                Some(session_read_event::Body::Closed(_)) => "closed",
                other => panic!("unexpected event {other:?}"),
            })
            .collect();
        assert_eq!(kinds.last(), Some(&"closed"));
        assert!(kinds.contains(&"exit"));
        match &events.iter().find_map(|e| match &e.body {
            Some(session_read_event::Body::Exit(x)) => Some(x.clone()),
            _ => None,
        }) {
            Some(exit) => {
                assert_eq!(exit.final_seq, 4);
                assert_eq!(exit.exit_code, -1, "signal exit carries -1");
                assert_eq!(exit.signal.as_deref(), Some("SIGHUP"));
            }
            None => panic!("no exit event"),
        }
    }

    /// `PLAN.md` Step 3.5 PR②: `session.write` binds to the session's
    /// opener, so a foreign principal is refused by ownership before the
    /// lease is ever consulted — `SESSION_CONFLICT` from a genuinely
    /// foreign principal is no longer reachable through `session.write` at
    /// all (`broker::lease`'s own unit tests still cover the underlying
    /// `no_steal` mechanics directly). The same principal on a second
    /// connection is unaffected: ownership binds to the principal, not the
    /// connection.
    #[tokio::test]
    async fn write_by_another_principal_is_denied_by_ownership_not_the_lease() {
        let rig = allow_rig();
        let a = ctx(Principal::Device("a".into()), ALL_CAPS);
        let mut b = ctx(Principal::Device("b".into()), ALL_CAPS);
        b.conn_id = 43;
        let (id, _t, _pipe) = open_session(&rig, &a).await;
        let write = |cid: u64| {
            ControlMessage::new(
                cid,
                control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: id.clone(),
                    data: b"x".to_vec(),
                }),
            )
        };
        assert_eq!(
            error_code(&rig.server.dispatch(&a, &write(1)).await.unwrap()),
            None
        );
        let reply = rig.server.dispatch(&b, &write(2)).await.unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        assert_eq!(
            rig.broker
                .get(&SessionId(id.clone()))
                .unwrap()
                .info()
                .writer
                .as_deref(),
            Some("device:a"),
            "a denied write must not move the lease"
        );
        // Same principal on another connection still takes over.
        let mut a2 = a.clone();
        a2.conn_id = 44;
        assert_eq!(
            error_code(&rig.server.dispatch(&a2, &write(3)).await.unwrap()),
            None
        );
    }

    #[tokio::test]
    async fn invalid_session_arguments_are_rejected_before_the_broker() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, _pipe) = open_session(&rig, &ctx).await;
        rig.audit.clear();
        let cases = vec![
            control_message::Body::SessionWrite(wire::SessionWrite {
                session_id: id.clone(),
                data: vec![0u8; wire::SESSION_CHUNK_MAX + 1],
            }),
            control_message::Body::SessionResize(wire::SessionResize {
                session_id: id.clone(),
                cols: 70_000,
                rows: 24,
            }),
            control_message::Body::SessionResize(wire::SessionResize {
                session_id: id.clone(),
                cols: 0,
                rows: 24,
            }),
            control_message::Body::SessionClose(wire::SessionClose {
                session_id: id.clone(),
                signal: Some("STOP".into()),
            }),
            control_message::Body::SessionOpen(wire::SessionOpen {
                cols: 1 << 20,
                ..Default::default()
            }),
            control_message::Body::SessionAttach(wire::SessionAttach {
                session_id: id.clone(),
                mode: 0,
                ..Default::default()
            }),
            control_message::Body::SessionAttach(wire::SessionAttach {
                session_id: id.clone(),
                mode: wire::AttachMode::Ro as i32,
                ..Default::default()
            }),
        ];
        for body in cases {
            let reply = rig
                .server
                .dispatch(&ctx, &ControlMessage::new(1, body.clone()))
                .await
                .unwrap();
            assert_eq!(
                error_code(&reply),
                Some(ErrorCode::InvalidArgument),
                "{body:?}"
            );
        }
        // Argument validation is not a decision: nothing audited.
        assert!(rig.audit.records().is_empty());
        assert_eq!(rig.broker.session_count(), 1);
        assert_eq!(rig.pipes.pending(), 0);
    }

    #[tokio::test]
    async fn attach_redeems_a_credential_and_anything_else_is_refused() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (opened, _pipe) = open_session_full(&rig, &ctx).await;
        let id = opened.session_id.clone();
        rig.audit.clear();

        let attach = |sid: String, token: Vec<u8>| wire::SessionAttach {
            session_id: sid,
            resume_token: token,
            mode: wire::AttachMode::Rw as i32,
            ..Default::default()
        };
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    1,
                    control_message::Body::SessionAttach(attach(
                        id.clone(),
                        opened.resume_token.clone(),
                    )),
                ),
            )
            .await
            .unwrap();
        let response::Body::SessionAttached(a) = response_body(&reply) else {
            panic!("expected SessionAttached, got {reply:?}");
        };
        assert_eq!(a.ticket.len(), TICKET_LEN);
        assert_eq!(a.replay_from, 0);
        assert!(a.writer_lease);
        // A redemption always mints the next generation, and it is never
        // the one that was spent (protocol.md §10 "Rotation").
        assert_eq!(a.new_resume_token.len(), RESUME_TOKEN_LEN);
        assert_ne!(a.new_resume_token, opened.resume_token);
        assert_eq!(
            a.input_seq, 0,
            "the axis is forked from the open's, which has applied nothing"
        );
        assert_eq!(
            rig.server.pending_tickets(),
            2,
            "the open's ticket plus this one"
        );

        // Every other shape gets the same non-distinguishing answer: no
        // credential at all, a credential that does not verify, a real id,
        // a fabricated one. `SESSION_NOT_FOUND` is not reachable from here,
        // so an unauthorized peer cannot use attach as an existence oracle
        // (protocol.md §10-2).
        let refusals = [
            (2u64, id.clone(), Vec::new()),
            (3, "01K0NOSUCHSESSION".into(), Vec::new()),
            (4, id.clone(), vec![7u8; RESUME_TOKEN_LEN]),
            (5, "01K0NOSUCHSESSION".into(), vec![7u8; RESUME_TOKEN_LEN]),
            // …including the credential that was just spent.
            (6, id.clone(), opened.resume_token.clone()),
        ];
        for (request_id, sid, token) in refusals {
            let reply = rig
                .server
                .dispatch(
                    &ctx,
                    &ControlMessage::new(
                        request_id,
                        control_message::Body::SessionAttach(attach(sid.clone(), token.clone())),
                    ),
                )
                .await
                .unwrap();
            assert_eq!(
                error_code(&reply),
                Some(ErrorCode::AuthFailed),
                "request {request_id} on {sid}"
            );
        }
        assert_eq!(
            rig.server.pending_tickets(),
            2,
            "a refused attach mints nothing"
        );

        // Every attempt was audited. A refused credential is a denial, not
        // a silent drop — and the record is structural: op, principal,
        // resource, decision, never the credential.
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 6, "{recs:?}");
        assert!(recs.iter().all(|r| r.action == "session.attach"));
        assert_eq!(recs[0].resource, id);
        assert_eq!(recs[0].decision, "allow");
        assert!(recs[1..].iter().all(|r| r.decision == "deny"), "{recs:?}");

        // Denied peers are audited too. They never reach the ACL, because
        // they hold no credential — and the answer is the same either way.
        let denied = self::rig(Arc::new(DenyAll));
        let dctx = self::ctx(Principal::Device("stranger".into()), ALL_CAPS);
        let reply = denied
            .server
            .dispatch(
                &dctx,
                &ControlMessage::new(
                    2,
                    control_message::Body::SessionAttach(wire::SessionAttach {
                        session_id: "01K0NOSUCHSESSION".into(),
                        mode: wire::AttachMode::Rw as i32,
                        ..Default::default()
                    }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::AuthFailed));
        let recs = denied.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "deny");
        assert_eq!(recs[0].action, "session.attach");
    }

    // ---- SIGTERM graceful drain (CLI.md §6.12, ADR-0003) --------------

    /// [`Server::drain`] closes every live session through the broker's
    /// ordinary close procedure — `session.closed{reason:"closed"}` lands
    /// in the ring exactly like an explicit `session.close` would.
    #[tokio::test]
    async fn drain_closes_every_live_session_with_reason_closed() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id1, _ticket1, _pipe1) = open_session(&rig, &ctx).await;
        let (id2, _ticket2, _pipe2) = open_session(&rig, &ctx).await;
        assert_eq!(rig.broker.session_count(), 2);

        rig.server.drain().await;

        assert_eq!(rig.broker.session_count(), 0);
        for id in [id1, id2] {
            let out = SessionBackend::pull(
                rig.broker.as_ref(),
                &SessionId(id),
                Cursor::from_offset(0),
                1024,
                Duration::ZERO,
            )
            .await
            .unwrap();
            assert!(matches!(
                out.events.last(),
                Some(ReplayEvent::Control {
                    event: ControlEvent::Closed {
                        reason: CloseReason::Closed
                    },
                    ..
                })
            ));
        }
    }

    /// Once draining, `session.open` is refused — `RESOURCE_EXHAUSTED`,
    /// never a session created.
    #[tokio::test]
    async fn draining_refuses_a_new_open_before_creating_a_session() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

        rig.server.drain().await;

        let reply = rig.server.dispatch(&ctx, &session_open(10)).await.unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));
        assert_eq!(
            rig.broker.session_count(),
            0,
            "a refused open must not create a session, draining or not"
        );
    }

    /// The gate an in-flight `session.open`/`session.attach` races against:
    /// `require_not_draining` has to refuse a session that is *still live*,
    /// not only one `drain` already finished closing — otherwise the only
    /// window it would ever cover is the instant after every session is
    /// already gone, where `session.attach`'s credential check fails first
    /// on its own (`AuthFailed`, protocol.md §10-2) and never reaches it.
    ///
    /// The session's source ignores `SIGHUP`, so [`Broker::close_all`]'s
    /// per-session `close` parks on the injected clock instead of finishing
    /// immediately — the real-world equivalent of a child slow to react to
    /// the first escalation step, held open here on purpose to observe
    /// `draining = true` with the victim session still in the registry and
    /// its credential still valid.
    #[tokio::test]
    async fn draining_refuses_a_still_live_attach_mid_drain() {
        let grace = Duration::from_secs(5);
        let rig = rig_with(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::with_ignored_signals(64 * 1024, &[Signal::Hup])),
            grace,
        );
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (opened, _pipe) = open_session_full(&rig, &ctx).await;
        let pending_before = rig.server.pending_tickets();

        let server = rig.server.clone();
        let draining = tokio::spawn(async move { server.drain().await });
        // Let `drain` set the flag and `close_all` send its HUP; the ignored
        // signal leaves `close` parked on `clock.sleep(grace)`, not finished.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!draining.is_finished(), "drain must still be in flight");
        assert_eq!(
            rig.broker.session_count(),
            1,
            "the victim session must still be live for this test to mean anything"
        );

        let attach_reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    11,
                    control_message::Body::SessionAttach(wire::SessionAttach {
                        session_id: opened.session_id.clone(),
                        resume_token: opened.resume_token.clone(),
                        mode: wire::AttachMode::Rw as i32,
                        ..Default::default()
                    }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(
            error_code(&attach_reply),
            Some(ErrorCode::ResourceExhausted),
            "a live session must still be refused while draining, not silently attachable"
        );
        assert_eq!(
            rig.server.pending_tickets(),
            pending_before,
            "a refused attach mints no ticket"
        );

        // Escalate past the ignored HUP: the pipe does not ignore TERM, so
        // one more grace period is all `close` needs to finish, and the
        // spawned `drain` task — and the test — can end cleanly.
        rig.clock.advance(grace);
        draining.await.expect("drain task did not panic");
        assert_eq!(rig.broker.session_count(), 0);
    }

    /// `no_steal` (protocol.md §10, for "신중한 자동화") has to survive the
    /// round trip: it decides the attach *and* rides on the ticket, so
    /// redeeming the ticket — which is where the data stream actually takes
    /// the lease — cannot quietly upgrade a careful attach into a stealing
    /// one. And a ticket minted by `session.open` carries no attach
    /// decision at all, because `session.open` only decided `session.open`.
    ///
    /// The control message *probes* the lease rather than taking it: a
    /// redemption is not final until its successor credential is minted, and
    /// a steal that happened before a failure would leave the real writer
    /// demoted in favour of a connection that never attached.
    #[tokio::test]
    async fn no_steal_is_honoured_at_attach_and_rides_on_the_ticket() {
        let rig = allow_rig();
        let owner = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (opened, _pipe) = open_session_full(&rig, &owner).await;
        let id = opened.session_id.clone();
        let sid = SessionId(id.clone());

        // What `session.open` minted: no steal, and no attach decision.
        let purpose = rig
            .server
            .redeem_ticket(owner.conn_id, StreamKind::SessionData, &opened.ticket)
            .expect("the open's ticket is redeemable")
            .purpose;
        let TicketPurpose::Session {
            no_steal,
            attach_authorized,
            ..
        } = purpose
        else {
            panic!("expected a Session ticket, got {purpose:?}");
        };
        assert!(!no_steal);
        assert!(
            !attach_authorized,
            "session.open never decided session.attach"
        );

        // The owner takes the writer lease.
        let reply = rig
            .server
            .dispatch(
                &owner,
                &ControlMessage::new(
                    2,
                    control_message::Body::SessionWrite(wire::SessionWrite {
                        session_id: id.clone(),
                        data: b"x".to_vec(),
                    }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(error_code(&reply), None, "{reply:?}");

        let attach = |token: Vec<u8>, no_steal: bool| wire::SessionAttach {
            session_id: id.clone(),
            resume_token: token,
            mode: wire::AttachMode::Rw as i32,
            no_steal,
            ..Default::default()
        };
        let careful = ConnCtx {
            principal: Principal::Device("phone".into()),
            conn_id: 43,
            ..owner.clone()
        };

        // A different principal, refusing to steal: SESSION_CONFLICT, and
        // the lease does not move.
        let reply = rig
            .server
            .dispatch(
                &careful,
                &ControlMessage::new(
                    3,
                    control_message::Body::SessionAttach(attach(opened.resume_token.clone(), true)),
                ),
            )
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::SessionConflict));
        assert_eq!(
            rig.broker.get(&sid).unwrap().info().writer.as_deref(),
            Some("device:laptop"),
            "a refused attach must not move the lease"
        );

        // Steal-by-default wins, and the ticket records that it may. The
        // conflict above was decided before the rotation, so the credential
        // it refused is still the one that works here.
        let reply = rig
            .server
            .dispatch(
                &careful,
                &ControlMessage::new(
                    4,
                    control_message::Body::SessionAttach(attach(
                        opened.resume_token.clone(),
                        false,
                    )),
                ),
            )
            .await
            .unwrap();
        let response::Body::SessionAttached(a) = response_body(&reply) else {
            panic!("expected SessionAttached, got {reply:?}");
        };
        assert_eq!(
            rig.broker.get(&sid).unwrap().info().writer.as_deref(),
            Some("device:laptop"),
            "the steal lands when the data stream opens, not before"
        );
        let next_token = a.new_resume_token.clone();
        let purpose = rig
            .server
            .redeem_ticket(careful.conn_id, StreamKind::SessionData, &a.ticket)
            .expect("the attach ticket is redeemable")
            .purpose;
        let TicketPurpose::Session {
            no_steal,
            attach_authorized,
            ..
        } = purpose
        else {
            panic!("expected a Session ticket, got {purpose:?}");
        };
        assert!(!no_steal);
        assert!(attach_authorized, "session.attach already decided it");

        // A careful attach that *does* win — the lease is the requester's
        // own principal — still stamps `no_steal` on its ticket, so the
        // data stream inherits the promise.
        let reply = rig
            .server
            .dispatch(
                &owner,
                &ControlMessage::new(
                    5,
                    control_message::Body::SessionAttach(attach(next_token, true)),
                ),
            )
            .await
            .unwrap();
        let response::Body::SessionAttached(a) = response_body(&reply) else {
            panic!("expected SessionAttached, got {reply:?}");
        };
        let purpose = rig
            .server
            .redeem_ticket(owner.conn_id, StreamKind::SessionData, &a.ticket)
            .expect("the attach ticket is redeemable")
            .purpose;
        let TicketPurpose::Session { no_steal, .. } = purpose else {
            panic!("expected a Session ticket, got {purpose:?}");
        };
        assert!(no_steal, "the ticket carries the flag the attach asked for");
    }

    #[tokio::test]
    async fn close_with_kill_and_exit_events_survive_for_late_readers() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, mut pipe) = open_session(&rig, &ctx).await;
        pipe.write_output(b"bye").await.unwrap();
        // Blocking read from 0 lands once the output is in the ring.
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    1,
                    control_message::Body::SessionRead(wire::SessionRead {
                        session_id: id.clone(),
                        after: 0,
                        max_bytes: 0,
                        wait_ms: 30_000,
                        ctl_after: 0,
                    }),
                ),
            )
            .await
            .unwrap();
        assert!(matches!(
            response_body(&reply),
            response::Body::SessionReadResult(r) if !r.events.is_empty()
        ));
        pipe.exit(SourceExit {
            exit_code: Some(3),
            signal: None,
        });
        // Wait for the exit to be recorded via a blocking read.
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    2,
                    control_message::Body::SessionRead(wire::SessionRead {
                        session_id: id.clone(),
                        after: 3,
                        max_bytes: 0,
                        wait_ms: 30_000,
                        ctl_after: 0,
                    }),
                ),
            )
            .await
            .unwrap();
        let events = match response_body(&reply) {
            response::Body::SessionReadResult(r) => r.events.clone(),
            other => panic!("expected SessionReadResult, got {other:?}"),
        };
        let exit = events
            .iter()
            .find_map(|e| match &e.body {
                Some(session_read_event::Body::Exit(x)) => Some(x.clone()),
                _ => None,
            })
            .expect("exit event");
        assert_eq!(exit.exit_code, 3);
        assert_eq!(exit.signal, None);
        assert_eq!(exit.final_seq, 3);
        assert_eq!(
            rig.broker.get(&SessionId(id.clone())).unwrap().state(),
            SessionState::Exited
        );
        // Closing an exited session sends no signal (CLI.md §6.7).
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    3,
                    control_message::Body::SessionClose(wire::SessionClose {
                        session_id: id.clone(),
                        signal: Some("kill".into()),
                    }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(error_code(&reply), None, "{reply:?}");
        assert!(pipe.signals().is_empty());
        let _ = &rig.clock;
    }

    /// A malformed / oversize `session_id` is `INVALID_ARGUMENT` before
    /// the choke point (nothing audited) — a pinned peer cannot pump 256 KiB
    /// per request into the audit log, and the check discloses nothing.
    #[tokio::test]
    async fn malformed_session_ids_are_rejected_before_the_choke_point() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let too_long = "A".repeat(SESSION_ID_MAX_LEN + 1);
        for bad in ["", "has space", "slash/inside", "../etc", too_long.as_str()] {
            for (name, body) in session_bodies(bad) {
                if matches!(name, "open" | "list") {
                    continue; // no id in those
                }
                let reply = rig
                    .server
                    .dispatch(&ctx, &ControlMessage::new(1, body))
                    .await
                    .unwrap();
                assert_eq!(
                    error_code(&reply),
                    Some(ErrorCode::InvalidArgument),
                    "{name} with {bad:?}"
                );
            }
        }
        assert!(rig.audit.records().is_empty(), "rejected before audit");
        assert_eq!(rig.broker.session_count(), 0);
        // The exact-length boundary is fine, and ULIDs (the real shape) pass.
        assert!(valid_session_id(&"a".repeat(SESSION_ID_MAX_LEN)));
        assert!(valid_session_id("01K0SESSIONULID0000000000_"));
        assert!(!valid_session_id(""));
    }

    /// Control entries are zero-length: they sit *at* an output offset
    /// without advancing it, so `after` alone cannot say whether one was
    /// already delivered. A caller that echoes `next_ctl_after` back sees
    /// each control exactly once and its long-poll parks; one that does not
    /// gets the documented at-least-once re-delivery (protocol.md §9).
    /// Without the cursor a `--wait` loop would spin for ever.
    #[tokio::test]
    async fn echoed_control_cursor_makes_a_long_poll_park() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, _pipe) = open_session(&rig, &ctx).await;
        // Taking the writer lease appends a control entry at offset 0.
        rig.server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    2,
                    control_message::Body::SessionWrite(wire::SessionWrite {
                        session_id: id.clone(),
                        data: b"x".to_vec(),
                    }),
                ),
            )
            .await
            .unwrap();

        let read = |request_id, after, ctl_after, wait_ms| {
            let server = rig.server.clone();
            let ctx = ctx.clone();
            let id = id.clone();
            async move {
                let reply = server
                    .dispatch(
                        &ctx,
                        &ControlMessage::new(
                            request_id,
                            control_message::Body::SessionRead(wire::SessionRead {
                                session_id: id,
                                after,
                                max_bytes: 0,
                                wait_ms,
                                ctl_after,
                            }),
                        ),
                    )
                    .await
                    .unwrap();
                match response_body(&reply) {
                    response::Body::SessionReadResult(r) => r.clone(),
                    other => panic!("expected SessionReadResult, got {other:?}"),
                }
            }
        };

        let first = read(3, 0, 0, 0).await;
        assert_eq!(first.events.len(), 1, "writer_changed at offset 0");
        assert_eq!(first.next_after, 0);
        assert!(first.next_ctl_after > 0);

        // Stateless repeat: same event again (at-least-once), returns at
        // once even with a long wait — this is the loop the cursor fixes.
        let repeat = read(4, first.next_after, 0, 30_000).await;
        assert_eq!(repeat.events.len(), 1);

        // Echoing the cursor back: nothing new, so the read parks until the
        // wait elapses on the injected clock.
        let parked = tokio::spawn(read(5, first.next_after, first.next_ctl_after, 30_000));
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(!parked.is_finished(), "parked instead of spinning");
        rig.clock.advance(Duration::from_millis(30_000));
        let out = tokio::time::timeout(Duration::from_secs(5), parked)
            .await
            .expect("returned once the wait elapsed")
            .unwrap();
        assert!(out.events.is_empty(), "{:?}", out.events);
        assert_eq!(out.next_ctl_after, first.next_ctl_after);
    }

    /// `wait_ms` is clamped to `SESSION_READ_MAX_WAIT` (like `max_bytes`,
    /// never rejected): a read asking to park "forever" returns once the
    /// injected clock passes the cap, with no data.
    #[tokio::test]
    async fn session_read_wait_is_clamped_to_the_cap() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, _pipe) = open_session(&rig, &ctx).await;
        let reader = {
            let server = rig.server.clone();
            let ctx = ctx.clone();
            let id = id.clone();
            tokio::spawn(async move {
                server
                    .dispatch(
                        &ctx,
                        &ControlMessage::new(
                            2,
                            control_message::Body::SessionRead(wire::SessionRead {
                                session_id: id,
                                after: 0,
                                max_bytes: 0,
                                wait_ms: u64::MAX,
                                ctl_after: 0,
                            }),
                        ),
                    )
                    .await
                    .unwrap()
            })
        };
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(!reader.is_finished(), "still parked before the cap");
        // Just short of the cap: still parked. Past it: returns.
        rig.clock
            .advance(SESSION_READ_MAX_WAIT - Duration::from_millis(1));
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(!reader.is_finished(), "still parked just short of the cap");
        rig.clock.advance(Duration::from_millis(1));
        let reply = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("read returned once the clamped wait elapsed")
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionReadResult(r) => assert!(r.events.is_empty()),
            other => panic!("expected SessionReadResult, got {other:?}"),
        }
    }

    /// `SessionClosed.final_seq` is the offset at removal time (CLI.md
    /// §6.7): output the child emits while dying — after HUP, before TERM
    /// lands — is included, and it equals the offset on the trailing
    /// `session.closed` entry.
    #[tokio::test]
    async fn close_final_seq_includes_output_emitted_while_dying() {
        let grace = Duration::from_millis(100);
        let rig = rig_with(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::with_ignored_signals(64 * 1024, &[Signal::Hup])),
            grace,
        );
        let clock = rig.clock.clone();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, mut pipe) = open_session(&rig, &ctx).await;
        pipe.write_output(b"$ ").await.unwrap();

        let closer = {
            let server = rig.server.clone();
            let ctx = ctx.clone();
            let id = id.clone();
            tokio::spawn(async move {
                server
                    .dispatch(
                        &ctx,
                        &ControlMessage::new(
                            2,
                            control_message::Body::SessionClose(wire::SessionClose {
                                session_id: id,
                                signal: None,
                            }),
                        ),
                    )
                    .await
                    .unwrap()
            })
        };
        // HUP is ignored by this child; it keeps talking while dying.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(!closer.is_finished());
        assert_eq!(pipe.signals(), vec![Signal::Hup]);
        pipe.write_output(b"bye").await.unwrap();
        // Let the dying output reach the ring before TERM ends the child.
        let backend: &dyn SessionBackend = rig.broker.as_ref();
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            backend.pull(
                &SessionId(id.clone()),
                Cursor::from_offset(2),
                1024,
                Duration::from_secs(30),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            out.events
                .iter()
                .any(|e| matches!(e, ReplayEvent::Output { .. }))
        );
        clock.advance(grace);
        let reply = tokio::time::timeout(Duration::from_secs(5), closer)
            .await
            .expect("close finished after TERM")
            .unwrap();
        let final_seq = match response_body(&reply) {
            response::Body::SessionClosed(c) => c.final_seq,
            other => panic!("expected SessionClosed, got {other:?}"),
        };
        assert_eq!(final_seq, 5, "'$ ' + 'bye'");
        assert_eq!(pipe.signals(), vec![Signal::Hup, Signal::Term]);
        // The trailing closed entry carries the same offset.
        let out = backend
            .pull(&SessionId(id), Cursor::from_offset(5), 1024, Duration::ZERO)
            .await
            .unwrap();
        assert!(
            matches!(
                out.events.last(),
                Some(ReplayEvent::Control { sequence: 5, .. })
            ),
            "{:?}",
            out.events
        );
    }

    /// An empty `SessionWrite` passes ACL + existence but takes no lease,
    /// so it can neither displace nor flap the current writer.
    #[tokio::test]
    async fn empty_write_takes_no_lease() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, _pipe) = open_session(&rig, &ctx).await;
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    2,
                    control_message::Body::SessionWrite(wire::SessionWrite {
                        session_id: id.clone(),
                        data: Vec::new(),
                    }),
                ),
            )
            .await
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionWritten(w) => assert_eq!(w.bytes_written, 0),
            other => panic!("expected SessionWritten, got {other:?}"),
        }
        assert_eq!(rig.broker.get(&SessionId(id)).unwrap().info().writer, None);
        assert_eq!(rig.audit.records().len(), 2, "open + write both audited");
    }

    #[test]
    fn replay_events_map_to_wire_and_oversize_output_is_split() {
        let big = bytes::Bytes::from(vec![7u8; wire::SESSION_CHUNK_MAX * 2 + 5]);
        let events = replay_event_to_wire(ReplayEvent::Output {
            sequence: 100 + big.len() as u64,
            data: big.clone(),
        });
        assert_eq!(events.len(), 3);
        let seqs: Vec<u64> = events
            .iter()
            .map(|e| match &e.body {
                Some(session_read_event::Body::Output(o)) => o.sequence,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            seqs,
            vec![
                100 + wire::SESSION_CHUNK_MAX as u64,
                100 + 2 * wire::SESSION_CHUNK_MAX as u64,
                100 + big.len() as u64
            ]
        );
        let closed = replay_event_to_wire(ReplayEvent::Control {
            sequence: 9,
            ctl_id: 1,
            event: ControlEvent::Closed {
                reason: CloseReason::TtlExpired,
            },
        });
        assert!(matches!(
            &closed[0].body,
            Some(session_read_event::Body::Closed(c)) if c.reason == "ttl_expired" && c.seq == 9
        ));
        assert!(rfc3339_after(Duration::from_secs(60)).ends_with('Z'));
    }

    // ------------------------------------------------------------------
    // ControlPinger (M3 Step 4 Stage A) — `PLAN.md` "L2 유닛 테스트" list:
    // request_id monotonic per connection, timeout judgment on a paused
    // clock, unsolicited Pong dropped, correlation across interleaved
    // inbound traffic. No `sleep()` anywhere below.
    // ------------------------------------------------------------------

    use crate::client::pathwatch::{PathWatch, PathWatchConfig, ProbeSource, watch_path};

    fn pinger() -> (ControlPinger, tokio::sync::mpsc::Receiver<ControlMessage>) {
        let (tx, rx) = tokio::sync::mpsc::channel(MAX_INFLIGHT_REQUESTS_PER_CONN);
        (
            ControlPinger::new(PathWatch::new(PathWatchConfig::default()), tx),
            rx,
        )
    }

    #[tokio::test]
    async fn request_ids_are_monotonic_per_connection() {
        let (pinger, _out) = pinger();
        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(pinger.send_probe().await.unwrap());
        }
        assert_eq!(
            ids,
            vec![1, 2, 3, 4, 5],
            "each probe on one connection must get a fresh, increasing id"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn send_probe_backpressures_on_a_full_queue_instead_of_dropping_silently() {
        // The regression finding `4` (M3 Step 4 review): `PathState::verdict`
        // counts a probe as a strike the moment it decides to send one, so
        // a `send_probe` that silently drops on a momentarily-full queue
        // spends that strike on a `Ping` that never reached the wire.
        // `send_probe` must instead wait for room, exactly like every other
        // seam onto this queue (`serve_control`'s "All replies funnel back
        // through `reply_rx`" doc).
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let filler = tx.clone();
        let pinger = ControlPinger::new(PathWatch::new(PathWatchConfig::default()), tx);
        filler
            .try_send(ControlMessage::new(
                0,
                control_message::Body::SessionList(wire::SessionList {}),
            ))
            .expect("capacity-1 queue must accept the first message");

        let mut pending = Box::pin(pinger.send_probe());
        // A bounded deadline backstop under a paused clock, not a sleep
        // standing in for ordering (`docs/design/testing.md` L2): nothing
        // else is runnable, so this resolves the instant tokio proves the
        // future is still pending — it never advances any real wall time.
        assert!(
            tokio::time::timeout(Duration::from_secs(3600), &mut pending)
                .await
                .is_err(),
            "send_probe must not resolve while the outbound queue is full — a full queue is \
             backpressure, not a license to drop the probe"
        );

        // Drain the queue: room exists now, so the pending probe can land.
        let filler_msg = rx
            .recv()
            .await
            .expect("the filler message must still be queued");
        assert_eq!(filler_msg.request_id, 0);
        let id = pending
            .await
            .expect("send_probe must complete once the queue has room, not be dropped");
        let queued = rx
            .recv()
            .await
            .expect("the probe itself must have been queued, not silently discarded");
        assert_eq!(queued.request_id, id);
        assert!(matches!(queued.body, Some(control_message::Body::Ping(_))));
    }

    #[tokio::test]
    async fn send_probe_queues_a_ping_carrying_its_own_id() {
        let (pinger, mut out) = pinger();
        let id = pinger.send_probe().await.unwrap();
        let queued = out.try_recv().expect("send_probe must queue something");
        assert_eq!(queued.request_id, id);
        assert!(matches!(queued.body, Some(control_message::Body::Ping(_))));
    }

    #[tokio::test]
    async fn a_pong_for_an_unknown_request_id_is_dropped() {
        let (pinger, _out) = pinger();
        let _ours = pinger.send_probe().await.unwrap();
        // Never one of ours: nowhere near the counter's range.
        let stray = ControlMessage::new(999_999, control_message::Body::Pong(wire::Pong {}));
        assert!(
            !pinger.observe(&stray),
            "an unsolicited Pong must not be reported as a correlated answer"
        );
        assert!(
            !pinger.watch().is_dead(),
            "observing a stray Pong must not perturb this pinger's watch at all"
        );
    }

    #[tokio::test]
    async fn a_non_pong_message_is_never_treated_as_an_answer() {
        let (pinger, _out) = pinger();
        let id = pinger.send_probe().await.unwrap();
        // Same request_id, but not a `Pong` — must not be mistaken for the
        // answer to our own probe.
        let echo =
            ControlMessage::new(id, control_message::Body::SessionList(wire::SessionList {}));
        assert!(!pinger.observe(&echo));
    }

    #[tokio::test]
    async fn correlation_survives_interleaved_traffic_and_reordering() {
        let (pinger, _out) = pinger();
        let first = pinger.send_probe().await.unwrap();
        let second = pinger.send_probe().await.unwrap();

        // Unrelated inbound traffic between the probes going out and
        // either being answered.
        let unrelated_request = ControlMessage::new(
            900,
            control_message::Body::SessionList(wire::SessionList {}),
        );
        assert!(!pinger.observe(&unrelated_request));
        let foreign_pong = ControlMessage::new(4_242, control_message::Body::Pong(wire::Pong {}));
        assert!(!pinger.observe(&foreign_pong));

        // The second probe's answer arrives first (realistic under
        // reordering) — it must correlate to its own id, not the first's.
        assert!(pinger.observe(&ControlMessage::new(
            second,
            control_message::Body::Pong(wire::Pong {})
        )));
        // The first, answered later, still correlates.
        assert!(pinger.observe(&ControlMessage::new(
            first,
            control_message::Body::Pong(wire::Pong {})
        )));
        // Both already consumed: a duplicate delivery of either answers
        // nothing a second time.
        assert!(!pinger.observe(&ControlMessage::new(
            first,
            control_message::Body::Pong(wire::Pong {})
        )));
        assert!(!pinger.observe(&ControlMessage::new(
            second,
            control_message::Body::Pong(wire::Pong {})
        )));
    }

    #[tokio::test]
    async fn note_inbound_clears_every_outstanding_id_even_ones_never_answered() {
        let (pinger, _out) = pinger();
        let leaked = pinger.send_probe().await.unwrap();
        let _also_outstanding = pinger.send_probe().await.unwrap();

        // Some other inbound message proves the path without answering
        // either probe by id (e.g. ordinary session traffic, or an
        // uncorrelated `Ping` from the peer's own probe loop).
        pinger.note_inbound();

        // Both ids are gone — a late `Pong` for either no longer
        // correlates, because the connection has already proven itself
        // alive by other means and holding them further would only leak.
        assert!(
            !pinger.observe(&ControlMessage::new(
                leaked,
                control_message::Body::Pong(wire::Pong {})
            )),
            "note_inbound must clear ids that were never individually answered"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cadence_survives_a_reply_storm_of_uncorrelated_pings() {
        // The regression `finding 1` (M3 Step 4 review) named: symmetric
        // probing must not pin a registered connection to the fast
        // cadence forever. Simulates the peer's own probe loop hammering
        // this side with `Ping`s (never this pinger's own — `record`
        // never sees a `Pong`) while nothing else happens, and asserts the
        // idle cadence is still reached — exactly
        // `pathwatch.rs`'s own `a_healthy_idle_path_falls_to_the_slow_cadence`
        // guard, but through `ControlPinger::record` rather than
        // `PathState` directly.
        let (pinger, _out) = pinger();
        let watch = pinger.watch().clone();
        let cfg = *watch.config();

        let mut request_id = 0u64;
        let mut elapsed = Duration::ZERO;
        while elapsed < cfg.active_window + Duration::from_secs(1) {
            tokio::time::advance(Duration::from_millis(100)).await;
            elapsed += Duration::from_millis(100);
            request_id += 1;
            let ping = ControlMessage::new(request_id, control_message::Body::Ping(wire::Ping {}));
            assert!(!pinger.record(&ping));
        }

        assert_eq!(
            watch.cadence(),
            cfg.idle_probe_interval,
            "a stream of inbound Pings alone must not hold this side's watch on the fast cadence"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cadence_survives_a_reply_storm_of_uncorrelated_pongs() {
        // The Pong half of the same regression: `note_inbound` clears
        // `outstanding` on *every* non-correlated inbound message, so a
        // peer `Ping` landing between our own `Ping` and its answering
        // `Pong` makes that `Pong` arrive with nothing left to match —
        // `record` must still treat it as bare liveness
        // (`PathState::observe_inbound`), never as `traffic`, or the
        // watch never reaches the idle cadence on a perfectly quiet
        // connection.
        let (pinger, _out) = pinger();
        let watch = pinger.watch().clone();
        let cfg = *watch.config();

        let mut request_id = 0u64;
        let mut elapsed = Duration::ZERO;
        while elapsed < cfg.active_window + Duration::from_secs(1) {
            tokio::time::advance(Duration::from_millis(100)).await;
            elapsed += Duration::from_millis(100);
            request_id += 1;
            // Never correlated: this pinger never allocated `request_id`
            // through `send_probe`, so `observe` always misses and this
            // falls through to `record`'s fallback match.
            let pong = ControlMessage::new(request_id, control_message::Body::Pong(wire::Pong {}));
            assert!(!pinger.record(&pong));
        }

        assert_eq!(
            watch.cadence(),
            cfg.idle_probe_interval,
            "a stream of uncorrelated inbound Pongs alone must not hold this side's watch on \
             the fast cadence"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_correlated_pong_clears_strikes_the_same_way_answered_traffic_always_has() {
        use crate::client::pathwatch::Verdict;

        let (pinger, mut out) = pinger();
        let watch = pinger.watch().clone();

        // Silence past the fast cadence earns a strike (mirrors
        // `pathwatch.rs`'s own `silence_earns_probes_and_then_a_verdict`).
        tokio::time::advance(watch.config().probe_interval + Duration::from_millis(1)).await;
        assert_eq!(watch.verdict(Duration::from_millis(1)), Verdict::Probe);

        // Answer it through the pinger's correlation path rather than
        // `PathWatch::inbound` directly — the point of this test is that
        // `ControlPinger::observe` is what reaches `inbound`, not that
        // `inbound` itself clears strikes (already covered in
        // `pathwatch.rs`).
        let id = pinger.send_probe().await.unwrap();
        let queued = out.try_recv().expect("send_probe must have queued a Ping");
        assert_eq!(queued.request_id, id);
        assert!(pinger.observe(&ControlMessage::new(
            id,
            control_message::Body::Pong(wire::Pong {})
        )));

        // Immediately after, the path is not silent — the pending strike
        // must not compound and the connection must not be declared dead
        // even after another `probe_interval` of quiet.
        tokio::time::advance(watch.config().probe_interval).await;
        assert_ne!(watch.verdict(Duration::from_millis(1)), Verdict::Dead);
    }

    /// A stub `ProbeSource` that never closes on its own — the death in
    /// this test must come purely from unanswered probes going silent,
    /// exactly like a real connection whose packets stop arriving without
    /// QUIC itself noticing anything (`pathwatch.rs`'s module doc).
    #[derive(Clone)]
    struct NeverCloses;

    impl ProbeSource for NeverCloses {
        async fn closed(&self) {
            std::future::pending::<()>().await
        }

        fn rtt(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_probes_are_judged_dead_on_a_paused_clock() {
        let watch = PathWatch::new(PathWatchConfig::default());
        let (tx, mut out) = tokio::sync::mpsc::channel(MAX_INFLIGHT_REQUESTS_PER_CONN);
        let pinger = Arc::new(ControlPinger::new(watch.clone(), tx));
        let probes = Arc::new(tokio::sync::Notify::new());

        // Nobody ever answers a queued Ping — the outbound queue is
        // drained (as `serve_control`'s writer would) but no reply comes
        // back, which is exactly "the path stopped carrying packets".
        let drain = tokio::spawn(async move { while out.recv().await.is_some() {} });
        let watchdog = tokio::spawn(watch_path(NeverCloses, watch.clone(), probes.clone()));
        let driver = tokio::spawn(drive_probes(pinger.clone(), probes));

        tokio::time::timeout(Duration::from_secs(5), watch.dead())
            .await
            .expect("a connection whose probes are never answered must be judged dead");

        watchdog.await.unwrap();
        driver.abort();
        drain.abort();
    }

    // ---------------------------------------------------------------
    // `forward.local` — the inline ACL on a peer-opened `TCP_CONNECT`
    // stream (`PLAN.md` M4 Step 3, `docs/design/protocol.md` §7,
    // `docs/design/testing.md` L2).
    // ---------------------------------------------------------------

    fn tcp_connect_header(host: &str, port: u32) -> StreamHeader {
        StreamHeader {
            kind: StreamKind::TcpConnect as i32,
            // §7's ticket exception: a `TCP_CONNECT` stream carries none.
            ticket: Vec::new(),
            host: host.to_string(),
            port,
        }
    }

    /// A [`TunnelDialer`] that counts every call before doing anything
    /// else, so "the host dialed nothing" is an assertion and not a hope.
    /// With `target: Some(addr)` it makes a real loopback connection (so
    /// the allow path is proved end-to-end, not stubbed); with `None`
    /// every dial fails, standing in for a refused destination.
    struct CountingDialer {
        calls: std::sync::atomic::AtomicUsize,
        target: Option<SocketAddr>,
    }

    impl CountingDialer {
        fn refusing() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                target: None,
            }
        }

        fn to(target: SocketAddr) -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                target: Some(target),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl TunnelDialer for CountingDialer {
        fn dial<'a>(&'a self, _host: &'a str, _port: u16) -> crate::tunnel::dial::DialFuture<'a> {
            // Count first: an implementation that dialed before checking
            // the ACL would be recorded here even if the dial then failed.
            self.calls.fetch_add(1, Ordering::SeqCst);
            let target = self.target;
            Box::pin(async move {
                match target {
                    Some(addr) => tokio::net::TcpStream::connect(addr)
                        .await
                        .map_err(crate::tunnel::dial::DialError::Connect),
                    None => Err(crate::tunnel::dial::DialError::Connect(
                        std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "mock dialer refuses everything",
                        ),
                    )),
                }
            })
        }
    }

    /// The security core of M4 Step 3: under a denying policy a
    /// `TCP_CONNECT` stream must reach **zero** dials (`docs/PRD.md` §9,
    /// `docs/design/protocol.md` §13's "socket creation is 0 on the
    /// un-authorized path"), and be refused with `PERMISSION_DENIED`.
    ///
    /// Discriminating by construction: the dial counter is incremented as
    /// the very first statement of `CountingDialer::dial`, before the
    /// returned future can even fail, so an implementation that dialed
    /// first and consulted the ACL afterwards — the exact ordering bug
    /// this test exists for — would land `calls == 1` here and fail, and
    /// would fail identically whether that speculative dial succeeded or
    /// not. `..._allowed_dials_exactly_once...` below proves the counter
    /// is wired at all (it reaches 1 there), so `0` here is a real
    /// observation and not a counter that never moves.
    #[tokio::test]
    async fn tcp_connect_denied_dials_nothing_and_reports_permission_denied() {
        let rig = rig(Arc::new(DenyAll));
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let dialer = CountingDialer::refusing();

        let header = tcp_connect_header("db.internal", 5432);
        let rejection = rig
            .server
            .authorize_and_dial_tunnel(&ctx, &header, &dialer)
            .await
            .expect_err("a denied forward.local must not yield a socket");

        assert_eq!(
            dialer.calls(),
            0,
            "the host must not dial before (or after) a forward.local deny"
        );
        assert!(!rejection.ok);
        assert_eq!(rejection.code, ErrorCode::PermissionDenied.as_str());

        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1, "exactly one audit line per decision");
        assert_eq!(recs[0].action, "forward.local");
        assert_eq!(recs[0].decision, "deny");
        assert_eq!(
            recs[0].resource, "db.internal:5432",
            "the audited resource is the requested destination"
        );
    }

    /// The host's whole `TCP_CONNECT` leg over a real QUIC stream (M4
    /// Step 3): header → gate → dial → `ConnectResult{ok:true}` → **raw
    /// byte splice**, with a real loopback destination on the far end. The
    /// three earlier tests stop at the gate; this one is the only place the
    /// bytes actually move, and it asserts the two things the splice can
    /// silently get wrong:
    ///
    /// 1. **Residue.** The requester writes payload immediately behind its
    ///    `StreamHeader` frame, so the host's framed reader has very likely
    ///    already swallowed those bytes by the time the header decodes
    ///    (`qsh_transport::FramedRecv::into_raw`). They must reach the
    ///    destination *first* — a splice that ignored the decoder's
    ///    leftovers would drop `"pipelined-"` here and echo only `"tail"`.
    /// 2. **Half-close.** The requester finishes its send half while still
    ///    reading. The host must translate that into a `shutdown(SHUT_WR)`
    ///    on the destination socket — not a teardown — and keep the other
    ///    direction running: the destination answers the EOF with a
    ///    farewell (`"bye"`), which can only reach the requester if the
    ///    half-closed tunnel is still alive in that direction.
    #[tokio::test]
    async fn tcp_connect_allowed_splices_raw_bytes_both_ways() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A destination that echoes until EOF, then half-closes back.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _peer) = echo.accept().await.unwrap();
            let mut buf = [0u8; 512];
            loop {
                match sock.read(&mut buf).await.unwrap() {
                    0 => break,
                    n => sock.write_all(&buf[..n]).await.unwrap(),
                }
            }
            // Answer the half-close: a destination that speaks after its
            // peer stopped speaking is exactly what a teardown-on-first-EOF
            // splice would silence.
            sock.write_all(b"bye").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (client, host_conn) = crate::tunnel::testutil::loopback_pair().await;
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let header = tcp_connect_header("127.0.0.1", u32::from(echo_addr.port()));

        // Requester: open the stream, send the header, and pipeline
        // payload straight behind it without waiting for the verdict.
        let (send, recv) = client.open_bi().await.unwrap();
        let mut framed = FramedStream::data(send, recv);
        framed.send.send(&header).await.unwrap();
        let (send, mut recv) = framed.split();
        let mut raw_send = send.into_raw();
        raw_send.write_all(b"pipelined-").await.unwrap();

        // Host: exactly what `handle_data_stream` does — read the header
        // off the stream, then hand both to `handle_tcp_connect`.
        let server = rig.server.clone();
        // A clone: the last `Connection` handle's drop closes the whole
        // QUIC connection with application code 0, discarding stream data
        // the peer has not read yet — so the test keeps its own handle
        // alive until it has drained everything.
        let host_handle = host_conn.clone();
        let host_side = tokio::spawn(async move {
            let (send, recv) = host_handle.accept_bi().await.unwrap();
            let mut framed = FramedStream::data(send, recv);
            let header: StreamHeader = framed.recv.recv().await.unwrap().expect("header frame");
            server.handle_tcp_connect(&ctx, framed, &header).await;
        });

        let result: wire::ConnectResult = recv.recv().await.unwrap().expect("ConnectResult");
        assert!(
            result.ok,
            "an allowed forward.local must connect: {result:?}"
        );

        raw_send.write_all(b"tail").await.unwrap();
        raw_send.finish().unwrap();
        let (mut raw_recv, residue) = recv.into_raw();
        assert!(
            residue.is_empty(),
            "the host sends nothing behind ConnectResult"
        );
        // `quinn::RecvStream` has its own inherent `read_to_end(limit)`,
        // which shadows `AsyncReadExt::read_to_end`.
        let got = raw_recv.read_to_end(4096).await.unwrap();
        assert_eq!(
            got, b"pipelined-tailbye",
            "every byte, in order, exactly once: the payload pipelined \
             behind the header frame, the payload after it, and the \
             destination's answer to the half-close"
        );

        host_side.await.unwrap();
        drop(host_conn);

        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action, "forward.local");
        assert_eq!(recs[0].decision, "allow");
    }

    /// The `forward.local` resource an IPv6 destination earns is
    /// bracketed — `[::1]:5432`, not the unsplittable `::1:5432` that
    /// plain concatenation produces. This string is what M5's policy
    /// engine will pattern-match rules against and what the audit record
    /// carries, so its canonical form is asserted here rather than
    /// discovered later (`qsh_proto::wire::format_host_port`).
    #[tokio::test]
    async fn tcp_connect_audits_an_ipv6_destination_in_bracketed_form() {
        let rig = rig(Arc::new(DenyAll));
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let dialer = CountingDialer::refusing();

        // What `parse_forward_spec` actually delivers: an IPv6 literal
        // with its brackets already stripped off the `[::1]` token.
        let header = tcp_connect_header("::1", 5432);
        let rejection = rig
            .server
            .authorize_and_dial_tunnel(&ctx, &header, &dialer)
            .await
            .expect_err("a denied forward.local must not yield a socket");

        assert_eq!(dialer.calls(), 0);
        assert_eq!(rejection.code, ErrorCode::PermissionDenied.as_str());

        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action, "forward.local");
        assert_eq!(recs[0].decision, "deny");
        assert_eq!(
            recs[0].resource, "[::1]:5432",
            "an IPv6 ACL resource must be splittable back into host and port"
        );
    }

    /// The allow leg of the same gate: one dial, after the decision, and
    /// an `allow` audit line carrying `forward.local`. The dial is a real
    /// loopback connection, so `Ok` here means an actual socket exists.
    #[tokio::test]
    async fn tcp_connect_allowed_dials_exactly_once_and_audits_forward_local() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let dialer = CountingDialer::to(addr);

        let header = tcp_connect_header("127.0.0.1", u32::from(addr.port()));
        let upstream = rig
            .server
            .authorize_and_dial_tunnel(&ctx, &header, &dialer)
            .await
            .expect("an allowed forward.local dials the destination");

        assert_eq!(dialer.calls(), 1, "exactly one dial per TCP_CONNECT");
        let (accepted, _peer) = listener.accept().await.unwrap();
        drop(accepted);
        drop(upstream);

        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action, "forward.local");
        assert_eq!(recs[0].decision, "allow");
        assert_eq!(recs[0].resource, format!("127.0.0.1:{}", addr.port()));
    }

    /// An authorized destination that will not accept: the requester gets
    /// `CONNECTION_FAILED` (`docs/CLI.md` §3.3), and the `allow` decision
    /// is still audited — a failed dial is not a policy event.
    #[tokio::test]
    async fn tcp_connect_dial_failure_reports_connection_failed() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let dialer = CountingDialer::refusing();

        let header = tcp_connect_header("127.0.0.1", 9);
        let rejection = rig
            .server
            .authorize_and_dial_tunnel(&ctx, &header, &dialer)
            .await
            .expect_err("a refused destination is not a socket");

        assert_eq!(dialer.calls(), 1);
        assert!(!rejection.ok);
        assert_eq!(rejection.code, ErrorCode::ConnectionFailed.as_str());

        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action, "forward.local");
        assert_eq!(recs[0].decision, "allow");
    }

    /// A malformed destination is refused on shape, before the ACL is
    /// consulted: nothing to decide about, so no audit line is invented
    /// and — as on every other refusal — nothing is dialed
    /// (`docs/design/protocol.md` §9's "check the shape first" pattern).
    #[tokio::test]
    async fn tcp_connect_malformed_destination_is_invalid_argument_and_dials_nothing() {
        for header in [
            tcp_connect_header("", 80),
            tcp_connect_header("localhost", 0),
            tcp_connect_header("localhost", 70_000),
        ] {
            let rig = allow_rig();
            let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
            let dialer = CountingDialer::refusing();

            let rejection = rig
                .server
                .authorize_and_dial_tunnel(&ctx, &header, &dialer)
                .await
                .expect_err("a malformed destination is never dialed");

            assert_eq!(dialer.calls(), 0, "{header:?}");
            assert_eq!(rejection.code, ErrorCode::InvalidArgument.as_str());
            assert!(
                rig.audit.records().is_empty(),
                "no ACL decision was made, so no audit line: {header:?}"
            );
        }
    }

    /// A destination host past the 255-octet DNS-name limit is refused on
    /// shape, same discipline as the empty-host/zero-port/out-of-range-port
    /// cases above: nothing to decide about, so no ACL call, no audit
    /// line, and no dial (M8 Step 3b).
    #[tokio::test]
    async fn an_over_long_destination_host_is_refused_as_invalid_argument() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let dialer = CountingDialer::refusing();

        let long_host = "a".repeat(256);
        let header = tcp_connect_header(&long_host, 5432);
        let rejection = rig
            .server
            .authorize_and_dial_tunnel(&ctx, &header, &dialer)
            .await
            .expect_err("a 256-octet host is never a real destination");

        assert_eq!(dialer.calls(), 0);
        assert_eq!(rejection.code, ErrorCode::InvalidArgument.as_str());
        assert!(
            rig.audit.records().is_empty(),
            "no ACL decision was made, so no audit line"
        );
    }

    /// The security core of the tunnel-stream quota (M8 Step 3b, mirrors
    /// `tcp_connect_denied_dials_nothing_and_reports_permission_denied`'s
    /// own reasoning for the ACL axis): a principal already at its
    /// `max_tunnel_streams_per_forward` cap must see **zero** dials and a
    /// `RESOURCE_EXHAUSTED` `ConnectResult`, with the deny audited under
    /// the quota category rather than `forward.local`'s allow/deny pair.
    #[tokio::test]
    async fn a_tunnel_dial_past_the_quota_never_reaches_the_dialer() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_tunnel_streams_per_forward: 0,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let dialer = CountingDialer::refusing();

        let header = tcp_connect_header("db.internal", 5432);
        let rejection = rig
            .server
            .authorize_and_dial_tunnel(&ctx, &header, &dialer)
            .await
            .expect_err("a principal already at its forward cap must not dial");

        assert_eq!(
            dialer.calls(),
            0,
            "the quota gate sits before the dial, same as the ACL gate"
        );
        assert!(!rejection.ok);
        assert_eq!(rejection.code, ErrorCode::ResourceExhausted.as_str());
        assert_eq!(rejection.message, "tunnel quota exceeded");

        // The ACL `allow` line for `forward.local` is still audited
        // (`authorize_stream` ran and passed) — the quota rejection is a
        // *second*, distinct line under its own category, not a
        // replacement for the ACL decision.
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 2, "{recs:?}");
        assert_eq!(recs[0].action, "forward.local");
        assert_eq!(recs[0].decision, "allow");
        assert_eq!(recs[1].resource, "quota_tunnels_forward");
        assert_eq!(recs[1].decision, "deny");
        assert_eq!(
            recs[1].request_id, "-",
            "R9 — the tunnel axis has no control request id (a data stream dial)"
        );
        assert_eq!(
            recs[1].peer_addr,
            ctx.peer_addr.to_string(),
            "R4 — the quota deny record must carry the live peer, not \"-\""
        );
    }

    /// The wire-level shape of a quota refusal on a real QUIC stream: the
    /// requester's receive half is stopped with
    /// [`RESET_CODE_RESOURCE_EXHAUSTED`], not the generic `0` a plain
    /// "destination would not accept" refusal uses — a client reading
    /// only the QUIC stop code (no `ConnectResult` frame reachable, e.g.
    /// racing a connection teardown) still learns "retry" rather than
    /// misreading a capacity refusal as "we are just done reading".
    #[tokio::test]
    async fn a_quota_refusal_stops_the_receive_half_with_resource_exhausted() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_tunnel_streams_per_forward: 0,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let header = tcp_connect_header("db.internal", 5432);

        let (client, host_conn) = crate::tunnel::testutil::loopback_pair().await;

        let (send, recv) = client.open_bi().await.unwrap();
        let mut framed = FramedStream::data(send, recv);
        framed.send.send(&header).await.unwrap();
        let (send, mut recv) = framed.split();
        // Nothing more is ever written on this half — into_raw is safe to
        // call immediately, and is the only way to read back the peer's
        // `STOP_SENDING` error code (`FramedSend::stopped` discards it).
        let raw_send = send.into_raw();

        let server = rig.server.clone();
        let host_handle = host_conn.clone();
        let host_side = tokio::spawn(async move {
            let (send, recv) = host_handle.accept_bi().await.unwrap();
            let mut framed = FramedStream::data(send, recv);
            let header: StreamHeader = framed.recv.recv().await.unwrap().expect("header frame");
            server.handle_tcp_connect(&ctx, framed, &header).await;
        });

        let result: wire::ConnectResult = recv.recv().await.unwrap().expect("ConnectResult");
        assert!(!result.ok);
        assert_eq!(result.code, ErrorCode::ResourceExhausted.as_str());

        let stop = tokio::time::timeout(Duration::from_secs(5), raw_send.stopped())
            .await
            .expect("the host must stop the receive half promptly")
            .expect("stopped() must observe the STOP_SENDING, not a connection error");
        assert_eq!(
            stop.map(|code| code.into_inner()),
            Some(u64::from(RESET_CODE_RESOURCE_EXHAUSTED)),
            "a quota refusal must stop with RESET_CODE_RESOURCE_EXHAUSTED, not the generic 0"
        );

        host_side.await.unwrap();
        drop(host_conn);
    }

    // ------------------------------------------------------------------
    // connection caps, M8 Step 3b S4 — host/principal/pairing
    // ------------------------------------------------------------------

    /// M8 Step 3b ruling R3: a peer past the host connection cap must
    /// never receive the ordinary local `Hello` — the refusal is decided
    /// entirely in `Server::serve_connection`, *before*
    /// `serve_connection_inner` (and the `local_hello` it builds) ever
    /// runs, and reaches the peer as a normal `RESOURCE_EXHAUSTED` reply
    /// to its own `Hello` (not a raw connection close — that shape is
    /// pairing-only, ruling R2). The occupant below holds a *different*
    /// principal's slot, proving this is the host axis
    /// ([`QuotaKind::Connections`]), not the (nowhere-near-exhausted)
    /// per-principal one.
    #[tokio::test]
    async fn a_connection_past_the_host_cap_is_refused_with_resource_exhausted_before_the_local_hello()
     {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_connections: 1,
                max_connections_per_principal: 100,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let occupant = opener_key(&Principal::Device("occupant".into()), AuthPath::Pin);
        let _occupant_permit = rig.quotas.reserve_connection(&occupant).unwrap();
        assert_eq!(rig.quotas.connections_per_principal_in_use(&occupant), 1);

        let (client, host_conn) = crate::tunnel::testutil::loopback_pair().await;
        let server = rig.server.clone();
        let host_side = tokio::spawn(async move { server.serve_connection(host_conn).await });

        let local_hello = rig.server.local_hello(None);
        let err = match crate::handshake::initiate(&client, local_hello).await {
            Ok(_) => panic!("a connection past the host cap must never get a Hello reply"),
            Err(err) => err,
        };
        match err {
            crate::handshake::HelloError::Remote {
                code,
                message,
                retryable,
            } => {
                assert_eq!(code, ErrorCode::ResourceExhausted);
                assert_eq!(message, "connection quota exceeded");
                assert!(retryable, "a quota refusal must be retryable");
            }
            other => panic!("expected a Remote RESOURCE_EXHAUSTED rejection, got {other:?}"),
        }

        host_side.await.unwrap();
        // The refused connection was never counted — only the
        // manually-seeded occupant still holds a slot.
        assert_eq!(rig.quotas.connections_per_principal_in_use(&occupant), 1);
        drop(client);
    }

    /// M8 Step 3b ruling R2: a pre-identity (`Principal::Pairing`)
    /// connection past the fixed pairing cap is refused *without ever
    /// naming the reason* — no control stream accepted, no proof read,
    /// no error frame written, just an immediate close carrying
    /// [`CLOSE_CODE_RESOURCE_EXHAUSTED`] — the same non-distinguishing
    /// discipline `docs/design/protocol.md` §10-2/§15.5 already apply to
    /// every other pairing refusal (a missing invite looks identical on
    /// the wire).
    #[tokio::test]
    async fn a_pairing_connection_past_its_fixed_cap_is_refused_without_naming_the_reason() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits::default(),
        );
        let mut occupants = Vec::new();
        for _ in 0..crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS {
            occupants.push(rig.quotas.reserve_pairing_connection().unwrap());
        }

        let (client, host_conn) = crate::tunnel::testutil::pairing_loopback_pair().await;
        assert_eq!(*host_conn.principal(), Principal::Pairing);
        let server = rig.server.clone();
        let host_side = tokio::spawn(async move { server.serve_connection(host_conn).await });

        // No stream accepted, no proof read, no frame written (R2): the
        // client's own `open_bi` must never even be answered — the
        // connection is simply closed out from under it.
        let close_err = client.closed().await;
        match close_err {
            quinn::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(
                    u64::from(close.error_code),
                    u64::from(CLOSE_CODE_RESOURCE_EXHAUSTED)
                );
                assert_eq!(&close.reason[..], b"at capacity");
            }
            other => panic!("expected ApplicationClosed, got {other:?}"),
        }

        host_side.await.unwrap();
        // Every occupant slot is still held — the refusal created and
        // consumed no ninth permit.
        assert_eq!(
            rig.quotas.pairing_connections_in_use(),
            crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS
        );
        drop(occupants);
    }

    /// M8 Step 3b ruling B3 (adversary A1/B3): behavioral twin of the
    /// former source-text tripwire — a connection served by the real
    /// accept path must take exactly one slot on its own principal and
    /// give it back once the connection is over. `purge_connection` now
    /// takes the permit by value and drops it as its own last statement
    /// (see that function's doc), so "released only after purge" is a
    /// compile-time property of `serve_connection`'s two call sites, not
    /// something a test has to watch for by re-reading source text; this
    /// test instead pins the *externally observable* half of that
    /// contract — the slot is really held while the connection is live
    /// and really given back once it ends.
    #[tokio::test]
    async fn a_served_connection_holds_and_returns_its_connection_slot() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits::default(),
        );
        let (client, host_conn) = crate::tunnel::testutil::loopback_pair().await;
        let opener = opener_key(host_conn.principal(), host_conn.auth_path());
        let server = rig.server.clone();
        let host_side = tokio::spawn(async move { server.serve_connection(host_conn).await });
        let local_hello = rig.server.local_hello(None);
        let ctl = match crate::handshake::initiate(&client, local_hello).await {
            Ok(ctl) => ctl,
            Err(err) => panic!("the handshake must succeed under an empty quota: {err:?}"),
        };
        assert_eq!(
            rig.quotas.connections_per_principal_in_use(&opener),
            1,
            "a live served connection must hold exactly one connection slot"
        );
        drop(ctl);
        drop(client);
        host_side.await.unwrap();
        assert_eq!(
            rig.quotas.connections_per_principal_in_use(&opener),
            0,
            "the connection slot must be released once the connection is over"
        );
    }

    /// Pairing sibling of the above: the fixed pairing axis
    /// ([`crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS`] == 8) behaves
    /// the same way for a connection that actually clears the cap and gets
    /// served, not just for one manually seeded and never served. Seven
    /// occupants are hand-seeded (leaving exactly one slot), then the
    /// eighth is driven through the real pairing protocol
    /// (`crate::pairing::accept`/`respond`) so `serve_connection`'s
    /// pairing arm — real `reserve_pairing_connection`, real
    /// `serve_connection_inner`, real `purge_connection` — is what holds
    /// and releases the slot, not the test.
    #[tokio::test]
    async fn a_served_pairing_connection_holds_and_returns_its_pairing_slot() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits::default(),
        );

        let mut occupants = Vec::new();
        for _ in 0..crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS - 1 {
            occupants.push(rig.quotas.reserve_pairing_connection().unwrap());
        }
        assert_eq!(
            rig.quotas.pairing_connections_in_use(),
            crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS - 1
        );

        // Wire up a real, minimal invite + trust store so the eighth
        // connection clears `serve_pairing_connection`'s "not configured"
        // guard and runs the actual wire exchange.
        let dir = tempfile::tempdir().unwrap();
        let invite_path = dir.path().join("invites.toml");
        let secret = crate::trust::pairing::generate_secret();
        {
            let _lock = crate::trust::pairing::InviteStore::lock(&invite_path).unwrap();
            let mut store = crate::trust::pairing::InviteStore::load(&invite_path).unwrap();
            store.add(secret.as_slice(), std::time::SystemTime::now());
            store.save(&invite_path).unwrap();
        }
        let invites = crate::trust::pairing::SharedInviteStore::open(&invite_path).unwrap();
        let trust = crate::trust::SharedTrustStore::open(dir.path().join("trust.toml")).unwrap();
        rig.server.set_pairing(trust, invites);

        let (client, host_conn) = crate::tunnel::testutil::pairing_loopback_pair().await;
        assert_eq!(*host_conn.principal(), Principal::Pairing);
        let server = rig.server.clone();
        let host_side = tokio::spawn(async move { server.serve_connection(host_conn).await });

        let accepted = crate::pairing::accept(&client, "adv-a1-b-client", secret.as_slice())
            .await
            .expect("the eighth pairing connection must clear the cap and pair successfully");
        assert_eq!(accepted.peer_device_name, rig.server.device_name);
        assert_eq!(
            rig.quotas.pairing_connections_in_use(),
            crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS,
            "the eighth, just-served pairing connection must hold the last slot"
        );
        // A ninth reservation must fail while all eight are held.
        assert!(matches!(
            rig.quotas.reserve_pairing_connection(),
            Err(crate::quota::QuotaKind::PairingConnections)
        ));

        drop(client);
        host_side.await.unwrap();
        assert_eq!(
            rig.quotas.pairing_connections_in_use(),
            crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS - 1,
            "the pairing slot must be released once the connection is over"
        );

        drop(occupants);
    }

    // ------------------------------------------------------------------
    // remote forward (`-R`), M4 Step 4 — choke point + accept loop
    // ------------------------------------------------------------------

    fn rfwd_open(
        bind_host: &str,
        bind_port: u32,
        forward_host: &str,
        forward_port: u32,
    ) -> wire::RemoteForwardOpen {
        wire::RemoteForwardOpen {
            bind_host: bind_host.to_string(),
            bind_port,
            forward_host: forward_host.to_string(),
            forward_port,
            claim_token: Vec::new(),
        }
    }

    /// A [`RemoteForwardBinder`] that counts every call before doing
    /// anything else, so "the host bound nothing" is an assertion and not
    /// a hope — the remote-forward twin of `CountingDialer` above. With
    /// `real: true` it makes a real loopback bind (so the allow path is
    /// proved end-to-end); otherwise every bind fails, standing in for a
    /// destination that must never be touched.
    struct CountingBinder {
        calls: std::sync::atomic::AtomicUsize,
        /// Every address `bind` was asked for, in order — so a test can
        /// assert not just *how many* binds happened but *which address*
        /// each one was for. That distinction is the whole content of
        /// "the address bound is the address validated".
        attempted: std::sync::Mutex<Vec<SocketAddr>>,
        real: bool,
    }

    impl CountingBinder {
        fn refusing() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                attempted: std::sync::Mutex::new(Vec::new()),
                real: false,
            }
        }

        fn real() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                attempted: std::sync::Mutex::new(Vec::new()),
                real: true,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn attempted(&self) -> Vec<SocketAddr> {
            self.attempted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl RemoteForwardBinder for CountingBinder {
        fn bind<'a>(&'a self, addr: SocketAddr) -> crate::tunnel::remote::BindFuture<'a> {
            // Count first: a caller that bound before checking the ACL
            // (or the loopback gate) would be recorded here even if the
            // bind then failed — the same discriminating shape
            // `CountingDialer::dial`'s own doc explains.
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.attempted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(addr);
            let real = self.real;
            Box::pin(async move {
                if real {
                    tokio::net::TcpListener::bind(addr).await
                } else {
                    Err(std::io::Error::other("mock binder refuses everything"))
                }
            })
        }
    }

    /// The security core of M4 Step 4, the remote-forward twin of
    /// `tcp_connect_denied_dials_nothing_and_reports_permission_denied`:
    /// under a denying policy, `RemoteForwardOpen` must bind **zero**
    /// listeners (`docs/PRD.md` §9, `docs/design/protocol.md` §13) and be
    /// refused with `PERMISSION_DENIED`, with one audit line naming
    /// `forward.remote`.
    #[tokio::test]
    async fn rfwd_open_denied_binds_nothing_and_reports_permission_denied() {
        let rig = rig(Arc::new(DenyAll));
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let binder = CountingBinder::refusing();

        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 5432);
        let rejection = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
            .await
            .expect_err("a denied forward.remote must not bind");

        assert_eq!(
            binder.calls(),
            0,
            "the host must not bind before (or after) a forward.remote deny"
        );
        assert_eq!(error_code(&rejection), Some(ErrorCode::PermissionDenied));

        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1, "exactly one audit line per decision");
        assert_eq!(recs[0].action, "forward.remote");
        assert_eq!(recs[0].decision, "deny");
        assert_eq!(
            recs[0].resource, "127.0.0.1:0",
            "the audited resource is bind_host:bind_port, never the requester's own destination"
        );
    }

    /// **DoD 2's closing assertion.** A non-loopback `bind_host` is
    /// refused even under an allow-everything policy: loopback-only is a
    /// request constraint, not a principal permission
    /// (`Server::authorize_and_bind_remote_forward`'s own doc,
    /// `crate::acl::Action::ForwardRemote`'s). Every non-loopback case
    /// binds **zero** listeners and reports `INVALID_ARGUMENT` over an
    /// `allow` audit decision (the ACL gate itself passed; only the
    /// separate loopback gate refused); every loopback case — including
    /// the empty-string wire default and `localhost` — binds **exactly
    /// once**, to a genuinely loopback address.
    #[tokio::test]
    async fn rfwd_open_loopback_table_binds_only_the_loopback_cases() {
        let non_loopback = ["0.0.0.0", "::", "203.0.113.9", "192.168.1.10"];
        // Not `127.0.0.53`: it *classifies* as loopback (the whole
        // `127.0.0.0/8` block does — `resolve_loopback_bind_addr`'s own
        // `loopback_bind_host_table` test already proves that in
        // isolation), but actually binding it depends on the runner
        // having that address assigned to an interface, which only Linux
        // does by default — macOS refuses it with `EADDRNOTAVAIL`. This
        // table only needs one genuinely-bindable loopback case per
        // platform to prove the choke point calls `bind` at all.
        let loopback = ["127.0.0.1", "::1", "localhost", ""];

        for bind_host in non_loopback {
            let rig = allow_rig();
            let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
            let binder = CountingBinder::refusing();
            let req = rfwd_open(bind_host, 0, "127.0.0.1", 5432);

            let rejection = rig
                .server
                .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
                .await
                .expect_err("a non-loopback bind must be refused");

            assert_eq!(binder.calls(), 0, "{bind_host:?} must bind nothing");
            assert_eq!(
                error_code(&rejection),
                Some(ErrorCode::InvalidArgument),
                "{bind_host:?} must be INVALID_ARGUMENT, not PERMISSION_DENIED — \
                 this principal DOES hold forward.remote"
            );
            let recs = rig.audit.records();
            assert_eq!(recs.len(), 1, "{bind_host:?}");
            assert_eq!(recs[0].action, "forward.remote", "{bind_host:?}");
            assert_eq!(
                recs[0].decision, "allow",
                "{bind_host:?}: the ACL decision itself was an allow — only \
                 the non-ACL loopback gate refused this request"
            );
        }

        for bind_host in loopback {
            let rig = allow_rig();
            let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
            let binder = CountingBinder::real();
            let req = rfwd_open(bind_host, 0, "127.0.0.1", 5432);

            let (listener, _quota) = rig
                .server
                .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
                .await
                .unwrap_or_else(|err| panic!("{bind_host:?} must bind: {err:?}"));

            assert_eq!(binder.calls(), 1, "{bind_host:?} must bind exactly once");
            assert!(
                listener.local_addr().unwrap().ip().is_loopback(),
                "{bind_host:?} must bind a loopback address"
            );
            let recs = rig.audit.records();
            assert_eq!(recs.len(), 1, "{bind_host:?}");
            assert_eq!(recs[0].action, "forward.remote", "{bind_host:?}");
            assert_eq!(recs[0].decision, "allow", "{bind_host:?}");
        }
    }

    /// **The check-then-use regression guard, at the choke point.** The
    /// loopback gate and the bind must agree on one address, because
    /// `bind_host` arrives verbatim in the peer's `RemoteForwardOpen`: a
    /// peer that controls a DNS zone can answer loopback to one lookup and
    /// a routable address to the next with nothing but a short TTL or
    /// round-robin — no host compromise required — and an
    /// authenticated-but-restricted peer escalating to a non-loopback bind
    /// is precisely what DoD 2 exists to prevent.
    ///
    /// So: a resolver whose first answer is loopback and whose second is
    /// routable must produce **zero** non-loopback binds. It is resolved
    /// exactly once, and the only address `bind` is ever asked for is the
    /// one that answer certified.
    ///
    /// Mutation-checked: reintroducing a second resolution between the
    /// check and the bind makes this test fail (the bind is attempted on
    /// `203.0.113.9`, which is both non-loopback and unbindable here).
    #[tokio::test]
    async fn rfwd_open_binds_the_address_it_validated_never_a_second_resolution() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let binder = CountingBinder::real();
        let resolver = crate::tunnel::testutil::ScriptedResolver::new(vec![
            vec![crate::tunnel::testutil::addr("127.0.0.1:0")],
            vec![crate::tunnel::testutil::addr("203.0.113.9:0")],
        ]);
        let req = rfwd_open("rebinder.example", 0, "127.0.0.1", 5432);

        let (listener, _quota) = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &resolver, &binder)
            .await
            .expect("the validated answer was loopback, so the bind must succeed");

        assert_eq!(
            resolver.calls(),
            1,
            "bind_host must be resolved exactly once per RemoteForwardOpen"
        );
        assert_eq!(
            binder.attempted(),
            vec![crate::tunnel::testutil::addr("127.0.0.1:0")],
            "the only address bound must be the one the loopback gate validated"
        );
        assert!(
            binder.attempted().iter().all(|a| a.ip().is_loopback()),
            "zero non-loopback binds"
        );
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    /// The other half of the same seam: a resolver whose (single) answer
    /// set mixes loopback with a routable address is refused whole, and
    /// binds nothing at all — "some resolved address is loopback" is not a
    /// safety property (`crate::tunnel::remote::all_loopback`'s own doc).
    #[tokio::test]
    async fn rfwd_open_mixed_answer_set_binds_nothing() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let binder = CountingBinder::refusing();
        let resolver = crate::tunnel::testutil::ScriptedResolver::new(vec![vec![
            crate::tunnel::testutil::addr("127.0.0.1:0"),
            crate::tunnel::testutil::addr("203.0.113.9:0"),
        ]]);
        let req = rfwd_open("split.example", 0, "127.0.0.1", 5432);

        let rejection = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &resolver, &binder)
            .await
            .expect_err("a split-horizon answer must be refused");

        assert_eq!(binder.calls(), 0, "nothing may be bound");
        assert_eq!(error_code(&rejection), Some(ErrorCode::InvalidArgument));
    }

    /// A malformed request (empty/zero-port destination, out-of-range
    /// ports) is refused on shape, before the ACL is consulted: nothing
    /// to decide about, so no audit line is invented and nothing is bound
    /// — the remote-forward twin of
    /// `tcp_connect_malformed_destination_is_invalid_argument_and_dials_nothing`.
    #[tokio::test]
    async fn rfwd_open_malformed_request_is_invalid_argument_and_binds_nothing() {
        for req in [
            rfwd_open("127.0.0.1", 0, "", 80),
            rfwd_open("127.0.0.1", 0, "127.0.0.1", 0),
            rfwd_open("127.0.0.1", 0, "127.0.0.1", 70_000),
            rfwd_open("127.0.0.1", 70_000, "127.0.0.1", 80),
        ] {
            let rig = allow_rig();
            let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
            let binder = CountingBinder::refusing();

            let rejection = rig
                .server
                .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
                .await
                .expect_err("a malformed request is never bound");

            assert_eq!(binder.calls(), 0, "{req:?}");
            assert_eq!(error_code(&rejection), Some(ErrorCode::InvalidArgument));
            assert!(
                rig.audit.records().is_empty(),
                "no ACL decision was made, so no audit line: {req:?}"
            );
        }
    }

    /// The security core of M8 Step 3b's listener quota, the
    /// remote-forward twin of `a_tunnel_dial_past_the_quota_never_reaches_
    /// the_dialer`: a principal already at `max_remote_forwards_per_
    /// principal` must be refused **before** `binder.bind` ever runs — a
    /// spy binder observes zero calls, not one bind-then-unwind.
    #[tokio::test]
    async fn a_remote_forward_past_the_quota_is_refused_before_the_binder_runs() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_remote_forwards_per_principal: 0,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let binder = CountingBinder::real();
        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 5432);

        let rejection = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
            .await
            .expect_err("a principal already at its listener cap must not bind");

        assert_eq!(
            binder.calls(),
            0,
            "the quota gate sits before the bind, same as the ACL and loopback gates"
        );
        assert_eq!(error_code(&rejection), Some(ErrorCode::ResourceExhausted));

        // The ACL `allow` line for `forward.remote` is still audited — the
        // quota rejection is a *second*, distinct line under its own
        // category, not a replacement for the ACL decision.
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 2, "{recs:?}");
        assert_eq!(recs[0].action, "forward.remote");
        assert_eq!(recs[0].decision, "allow");
        assert_eq!(recs[1].resource, "quota_remote_forwards_principal");
        assert_eq!(recs[1].decision, "deny");
        // R9 (per `Quotas::record_rejection`'s own doc: "a control request
        // (session, exec, `RemoteForwardOpen`) has a real one to pass as
        // `Some`") — remote-forward is a control request, so this axis's
        // first row carries the real request_id, same as session/exec.
        // REBUTTAL B2 (see F3 handoff): the arbitration table's summary
        // grouped remote-forward with the tunnel/connection/pairing "-"
        // axes, but `authorize_and_bind_remote_forward` passes
        // `Some(request_id)`, not `None` — implemented against the actual
        // call site instead.
        assert_eq!(
            recs[1].request_id, "1",
            "R9 — the remote-forward axis has a real control request id (RemoteForwardOpen)"
        );
        assert_eq!(
            recs[1].peer_addr,
            ctx.peer_addr.to_string(),
            "R4 — the quota deny record must carry the live peer, not \"-\""
        );
    }

    /// Both places a live [`RemoteForwardEntry`] is ever removed —
    /// [`Server::handle_rfwd_close`] and [`Server::purge_connection`] —
    /// must release its [`crate::quota::RemoteForwardPermit`], not just
    /// one of them. Proved indirectly, the same way the tunnel-stream twin
    /// tests reopening past a cap: with `max_remote_forwards_per_
    /// principal: 1`, a second open by the same principal only ever
    /// succeeds again after whichever removal path just ran actually
    /// dropped the permit.
    #[tokio::test]
    async fn the_listener_permit_is_released_by_both_removal_sites() {
        let rig = rig_with_quota_limits(
            Arc::new(AllowAllPinned),
            Arc::new(PipeFactory::new(64 * 1024)),
            Duration::from_millis(100),
            crate::quota::QuotaLimits {
                max_remote_forwards_per_principal: 1,
                ..crate::quota::QuotaLimits::default()
            },
        );
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);

        // --- purge_connection path ---
        let (client1, host1) = crate::tunnel::testutil::loopback_pair().await;
        let reply1 = rig.server.handle_rfwd_open(&ctx, &host1, 1, &req).await;
        let response::Body::RfwdOpened(_opened1) = response_body(&reply1) else {
            panic!("expected RfwdOpened, got {reply1:?}");
        };

        rig.server.purge_connection(ctx.conn_id, ()).await;

        let (client2, host2) = crate::tunnel::testutil::loopback_pair().await;
        let ctx2 = ConnCtx {
            conn_id: 99,
            ..ctx.clone()
        };
        let reply2 = rig.server.handle_rfwd_open(&ctx2, &host2, 2, &req).await;
        let response::Body::RfwdOpened(opened2) = response_body(&reply2) else {
            panic!("purge_connection did not release the listener permit: {reply2:?}");
        };
        let opened2 = opened2.clone();

        // At the cap again (opened2 is still live) — a third open must be
        // refused, so the test below actually proves a release rather than
        // an accident of the cap being loose.
        let reply3 = rig.server.handle_rfwd_open(&ctx2, &host2, 3, &req).await;
        assert_eq!(error_code(&reply3), Some(ErrorCode::ResourceExhausted));

        // --- handle_rfwd_close path ---
        let close = wire::RemoteForwardClose {
            forward_id: opened2.forward_id.clone(),
        };
        let closed = rig.server.handle_rfwd_close(&ctx2, 4, &close);
        assert_eq!(error_code(&closed), None, "{closed:?}");

        let reply4 = rig.server.handle_rfwd_open(&ctx2, &host2, 5, &req).await;
        let response::Body::RfwdOpened(_opened4) = response_body(&reply4) else {
            panic!("handle_rfwd_close did not release the listener permit: {reply4:?}");
        };

        drop(client1);
        drop(client2);
    }

    /// U11a (R10): when its `serve` future returns on its own — in
    /// production, only a `Fatal` accept disposition ends `serve_remote_
    /// forward`, `crate::tunnel::remote`'s own doc — the accept loop must
    /// remove its own `forward_id` from [`Server::remote_forwards`] and
    /// release the listener permit, freeing the id for `RemoteForwardOpen`
    /// to reuse. Registers the entry exactly the way `handle_rfwd_open`'s
    /// own production path does (same `authorize_and_bind_remote_forward`
    /// choke point), then drives `run_remote_forward_accept_loop` (the
    /// exact free fn `handle_rfwd_open`'s own spawn calls) with `async {}`
    /// standing in for `serve_remote_forward` — an immediately-ready
    /// future exercises the exact same self-removal tail a real `Fatal`
    /// return does, without needing a real listener broken from outside
    /// tokio's reactor to produce one (R10 rejects that: unsound double
    /// `close`, Windows-hostile `AsRawFd`).
    #[tokio::test]
    async fn the_accept_loop_removes_its_own_forward_and_releases_the_permit_when_it_returns() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);

        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
        let (_listener, quota) = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &SystemBinder)
            .await
            .expect("loopback bind must succeed");
        assert_eq!(
            rig.quotas.remote_forwards_per_principal_in_use(&opener),
            1,
            "the permit is reserved once the bind succeeds"
        );

        // Register it the way `handle_rfwd_open` would — a harmless
        // already-finished task stands in for the real spawn, since this
        // test drives the accept loop itself rather than through
        // `tokio::spawn`.
        let forward_id = "self-removal-test-forward".to_string();
        let task = tokio::spawn(async {});
        rig.server
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                forward_id.clone(),
                RemoteForwardEntry {
                    conn_id: ctx.conn_id,
                    owner: opener.clone(),
                    task,
                    _quota: quota,
                },
            );

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            run_remote_forward_accept_loop(
                Arc::downgrade(&rig.server),
                async {},
                forward_id.clone(),
            ),
        )
        .await
        .expect("an immediately-ready serve future must not hang the accept loop");

        assert!(
            rig.server
                .remote_forwards
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&forward_id)
                .is_none(),
            "the accept loop must remove its own forward_id once its serve future returns"
        );
        assert_eq!(
            rig.quotas.remote_forwards_per_principal_in_use(&opener),
            0,
            "the listener permit must release along with the registry entry"
        );
    }

    /// U11b (R10): the other half of the self-removal tail's safety —
    /// when this forward is torn down by its closer (`handle_rfwd_close`/
    /// `purge_connection`: remove the entry, then `abort()` the task) the
    /// accept loop's own `.await` on `serve` is dropped mid-flight and its
    /// removal tail below that `.await` never runs, so the forward is
    /// removed exactly once — never by both the closer and the aborted
    /// task. Drives the same production fn with `std::future::pending()`
    /// standing in for a `serve_remote_forward` that would otherwise run
    /// forever, then reproduces `handle_rfwd_close`'s own remove-then-abort
    /// sequence on it directly.
    #[tokio::test]
    async fn an_aborted_accept_loop_is_removed_once_by_its_closer_and_never_again() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);

        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
        let (_listener, quota) = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &SystemBinder)
            .await
            .expect("loopback bind must succeed");
        assert_eq!(
            rig.quotas.remote_forwards_per_principal_in_use(&opener),
            1,
            "the permit is reserved once the bind succeeds"
        );

        let forward_id = "abort-test-forward".to_string();
        let task = tokio::spawn(run_remote_forward_accept_loop(
            Arc::downgrade(&rig.server),
            std::future::pending(),
            forward_id.clone(),
        ));
        rig.server
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                forward_id.clone(),
                RemoteForwardEntry {
                    conn_id: ctx.conn_id,
                    owner: opener.clone(),
                    task,
                    _quota: quota,
                },
            );

        // Mirror `handle_rfwd_close`'s closer sequence exactly: remove the
        // entry from the registry first (this alone drops `_quota` and
        // releases the permit), then abort the task.
        let entry = rig
            .server
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&forward_id)
            .expect("the entry must be present before its closer runs");
        let RemoteForwardEntry { task, _quota, .. } = entry;
        task.abort();
        // `handle_rfwd_close`'s own order: `entry.task.abort()` runs while
        // the entry (and its permit) is still alive, and the entry drops
        // — releasing the permit — immediately after, at the end of that
        // match arm. `drop(_quota)` here stands in for that implicit drop.
        drop(_quota);
        assert_eq!(
            rig.quotas.remote_forwards_per_principal_in_use(&opener),
            0,
            "the closer's remove-then-drop must release the permit right away, before the \
             aborted task is even polled again"
        );
        let join_result = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .expect("an aborted task must resolve promptly, not hang");
        assert!(
            join_result.is_err_and(|e| e.is_cancelled()),
            "an aborted accept loop's handle must report cancellation, not a panic"
        );

        // The loop's own `.await` on `pending()` was dropped mid-flight —
        // its self-removal tail never ran, so the permit was released
        // exactly once (by the closer above), never twice.
        assert_eq!(
            rig.quotas.remote_forwards_per_principal_in_use(&opener),
            0,
            "an aborted accept loop must not release its permit a second time"
        );
        assert!(
            rig.server
                .remote_forwards
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&forward_id)
                .is_none(),
            "the closer's own removal must stand; the aborted loop must not re-insert or re-touch it"
        );
    }

    /// The full production path — the part
    /// `authorize_and_bind_remote_forward`'s own unit tests above cannot
    /// exercise, because it takes no `Connection` by construction
    /// (`Server::handle_rfwd_open`'s own doc): a bound listener's accepted
    /// connection becomes a `TCP_ACCEPTED` stream on the peer, carrying
    /// the minted `forward_id` as its ticket, opened with no handshake
    /// reply to wait for (`crate::tunnel::remote`'s module doc). Then
    /// `RemoteForwardClose` tears the listener down, and closing it again
    /// finds nothing.
    #[tokio::test]
    async fn rfwd_open_end_to_end_streams_tcp_accepted_then_close_tears_down() {
        let (client_conn, host_conn) = crate::tunnel::testutil::loopback_pair().await;
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

        // `forward_host`/`forward_port` are the *requester's* destination
        // (Step 4's client leg, out of this stage's scope) — the host
        // never dials them, so any shape-valid value is fine here.
        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
        let reply = rig.server.handle_rfwd_open(&ctx, &host_conn, 7, &req).await;
        let response::Body::RfwdOpened(opened) = response_body(&reply) else {
            panic!("expected RfwdOpened, got {reply:?}");
        };
        assert!(!opened.forward_id.is_empty());
        assert_ne!(
            opened.actual_port, 0,
            "a port-0 request resolves to a real port"
        );

        let bound: SocketAddr = format!("127.0.0.1:{}", opened.actual_port).parse().unwrap();
        let _tcp = tokio::net::TcpStream::connect(bound).await.unwrap();

        let (send, recv) = client_conn.accept_bi().await.unwrap();
        let mut framed = FramedStream::data(send, recv);
        let header: StreamHeader = framed
            .recv
            .recv()
            .await
            .unwrap()
            .expect("TCP_ACCEPTED header");
        assert_eq!(header.stream_kind(), Some(StreamKind::TcpAccepted));
        assert_eq!(
            header.ticket,
            opened.forward_id.as_bytes(),
            "the ticket is the forward_id, verbatim"
        );

        let close = wire::RemoteForwardClose {
            forward_id: opened.forward_id.clone(),
        };
        let closed = rig.server.handle_rfwd_close(&ctx, 8, &close);
        assert!(
            matches!(
                &closed.body,
                Some(control_message::Body::Response(wire::Response {
                    body: None
                }))
            ),
            "RemoteForwardClose succeeds with a bare Response, no dedicated payload: {closed:?}"
        );

        let again = rig.server.handle_rfwd_close(&ctx, 9, &close);
        assert_eq!(
            error_code(&again),
            Some(ErrorCode::InvalidArgument),
            "closing an already-closed forward_id finds nothing"
        );

        drop(host_conn);
        drop(client_conn);
    }

    /// A `forward_id` on `RemoteForwardClose` arrives **from the peer**,
    /// so it is shape-checked (`qsh_proto::wire::valid_forward_id`) before
    /// it is used to look anything up, tear anything down, or reach a log
    /// line. A malformed one is `INVALID_ARGUMENT` and leaves the live
    /// forward it was aimed at untouched — including the escape-sequence
    /// and control-character shapes, which must never reach an operator's
    /// terminal through the host's own logs.
    #[tokio::test]
    async fn rfwd_close_malformed_forward_id_is_invalid_argument_and_closes_nothing() {
        let (client_conn, host_conn) = crate::tunnel::testutil::loopback_pair().await;
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
        let reply = rig.server.handle_rfwd_open(&ctx, &host_conn, 7, &req).await;
        let response::Body::RfwdOpened(opened) = response_body(&reply) else {
            panic!("expected RfwdOpened, got {reply:?}");
        };

        for id in [
            "",
            "a\u{1b}[31mb",
            "fwd\nqsh: forged line",
            "fwd\u{0}-1",
            "fwd.1",
            &"x".repeat(65),
        ] {
            let close = wire::RemoteForwardClose {
                forward_id: id.to_string(),
            };
            let reply = rig.server.handle_rfwd_close(&ctx, 8, &close);
            assert_eq!(
                error_code(&reply),
                Some(ErrorCode::InvalidArgument),
                "{id:?} must be refused on shape"
            );
        }

        // Untouched: the real forward still closes cleanly afterwards.
        let close = wire::RemoteForwardClose {
            forward_id: opened.forward_id.clone(),
        };
        let closed = rig.server.handle_rfwd_close(&ctx, 9, &close);
        assert!(
            matches!(
                &closed.body,
                Some(control_message::Body::Response(wire::Response {
                    body: None
                }))
            ),
            "the live forward must survive every malformed close: {closed:?}"
        );

        drop(host_conn);
        drop(client_conn);
    }

    /// The host-minted side of the same predicate: the `forward_id` this
    /// host issues is a ULID, which satisfies
    /// `qsh_proto::wire::valid_forward_id` by construction — so the peer's
    /// own `RemoteForwardClose` and its `TCP_ACCEPTED` tickets can be held
    /// to that shape without ever refusing an id this host itself minted.
    #[test]
    fn minted_forward_ids_satisfy_the_wire_shape() {
        for _ in 0..64 {
            let id = ulid::Ulid::new().to_string();
            assert!(
                wire::valid_forward_id(&id),
                "a minted forward_id must satisfy the wire shape: {id:?}"
            );
        }
    }

    /// `RemoteForwardOpen` genuinely cannot be answered by a bare
    /// `dispatch` call — there is no `Connection` to open this forward's
    /// future `TCP_ACCEPTED` streams on — so it draws `UNSUPPORTED`
    /// there, documented at the match arm itself. The real path is
    /// `Server::serve_control`'s early interception calling
    /// `Server::handle_rfwd_open` directly, exercised above.
    #[tokio::test]
    async fn dispatch_rfwd_open_with_no_connection_is_unsupported() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 5432);
        let msg = ControlMessage::new(3, control_message::Body::RfwdOpen(req));

        let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();

        assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
    }

    /// `RemoteForwardClose`, unlike `RemoteForwardOpen`, needs no
    /// connection — it is an ACL choke point over a `Server::
    /// remote_forwards` lookup plus an abort — so it is handled by
    /// `dispatch` itself, end to end. An unknown `forward_id` has
    /// `owner: None`, so under `AllowAllPinned` (this test's `allow_rig`)
    /// the choke point admits it unconditionally and the refusal below is
    /// step 4's ordinary "nothing to remove", not a `PermissionDenied`.
    #[tokio::test]
    async fn dispatch_rfwd_close_unknown_forward_is_invalid_argument() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let msg = ControlMessage::new(
            4,
            control_message::Body::RfwdClose(wire::RemoteForwardClose {
                forward_id: "nope".to_string(),
            }),
        );

        let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();

        assert_eq!(error_code(&reply), Some(ErrorCode::InvalidArgument));
    }

    /// The connection-bound lifetime half of `PLAN.md` M4 Step 4 (b): a
    /// dead connection's remote forwards are aborted and forgotten by
    /// `purge_connection`, the same way its tickets and writer leases are
    /// — nothing keyed to a `conn_id` outlives that connection.
    #[tokio::test]
    async fn purge_connection_removes_and_aborts_this_connections_remote_forwards() {
        let (client_conn, host_conn) = crate::tunnel::testutil::loopback_pair().await;
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

        let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
        let reply = rig.server.handle_rfwd_open(&ctx, &host_conn, 1, &req).await;
        let response::Body::RfwdOpened(opened) = response_body(&reply) else {
            panic!("expected RfwdOpened, got {reply:?}");
        };

        assert!(
            rig.server
                .remote_forwards
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&opened.forward_id),
            "the forward must be registered before purge"
        );

        rig.server.purge_connection(ctx.conn_id, ()).await;

        assert!(
            !rig.server
                .remote_forwards
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&opened.forward_id),
            "purge_connection must remove every remote forward this connection opened"
        );

        drop(host_conn);
        drop(client_conn);
    }
}
