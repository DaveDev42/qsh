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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qsh_proto::ErrorCode;
use qsh_proto::wire::{
    self, ControlMessage, ExecStart, ExecStarted, Hello, StreamHeader, StreamKind, control_message,
    response, session_read_event,
};
use qsh_transport::endpoint::CLOSE_CODE_PROTOCOL;
use qsh_transport::{AuthPath, Connection, FramedStream, Listener, Principal};
use rand::RngCore;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::acl::{Action, Authorizer};
use crate::audit::{AuditRecord, AuditSink};
use crate::broker::{
    BrokerError, CloseReason, ConnectionId, ControlEvent, Cursor, ReplayEvent, SessionBackend,
    SessionId, SessionSpec, Signal, TakeOutcome,
};
use crate::exec::{ExecSpec, run_exec};

/// How long a peer has to send its `Hello` (and open the control stream).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a data stream has to send its `StreamHeader`.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Ticket lifetime (`docs/design/protocol.md` §7).
pub const TICKET_TTL: Duration = Duration::from_secs(30);
/// Ticket size in bytes (128-bit random).
pub const TICKET_LEN: usize = 16;

/// Stream reset code: the `StreamHeader` was missing, unknown, or its
/// ticket was invalid/expired/foreign/of the wrong kind.
pub const RESET_CODE_BAD_HEADER: u32 = 0x2001;

/// Stream reset code: the header and ticket were valid but this build does
/// not pump that stream kind yet. Only `SESSION_DATA` uses it, until the
/// attach pump lands (PLAN M2 Step 5); the ticket is consumed either way.
pub const RESET_CODE_NOT_IMPLEMENTED: u32 = 0x2002;

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
    /// Peer address at connection time (audit only).
    pub peer_addr: SocketAddr,
    /// Connection identity used to bind tickets to the connection that
    /// earned them and to hold writer leases.
    pub conn_id: usize,
    /// Capabilities negotiated in `Hello` (intersection).
    pub capabilities: Vec<String>,
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
#[derive(Debug, Clone)]
pub struct PendingExec {
    /// Opaque exec identifier (ULID).
    pub exec_id: String,
    /// What to run once the stream arrives.
    pub spec: ExecSpec,
}

/// What a ticket authorizes once a data stream redeems it.
#[derive(Debug, Clone)]
pub enum TicketPurpose {
    /// An `EXEC_DATA` stream for this exec.
    Exec(PendingExec),
    /// A `SESSION_DATA` stream attached to this session.
    Session {
        /// The session the stream attaches to.
        session_id: SessionId,
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
#[derive(Debug, Clone)]
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

/// The host: policy + audit + ticket registry + session backend. Shared
/// across connections.
pub struct Server {
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<dyn AuditSink>,
    sessions: Arc<dyn SessionBackend>,
    device_name: String,
    tickets: Mutex<HashMap<[u8; TICKET_LEN], Ticket>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
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
        Arc::new(Self {
            authorizer,
            audit,
            sessions,
            device_name: device_name.into(),
            tickets: Mutex::new(HashMap::new()),
        })
    }

    /// The `Hello` this host sends.
    pub fn local_hello(&self) -> Hello {
        Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: self.device_name.clone(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// The session backend this host serves from.
    pub fn sessions(&self) -> &Arc<dyn SessionBackend> {
        &self.sessions
    }

    /// Number of tickets currently outstanding (tests/diagnostics).
    pub fn pending_tickets(&self) -> usize {
        self.tickets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Number of unexpired tickets outstanding for `conn_id`. Expired
    /// entries are dropped on the way so a stale backlog never counts.
    fn pending_tickets_for(&self, conn_id: usize) -> usize {
        let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        tickets.retain(|_, p| p.expires_at > now);
        tickets.values().filter(|p| p.conn_id == conn_id).count()
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
                Some(self.handle_session_attach(ctx, request_id, req))
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
            // No body this build understands. prost drops unknown fields,
            // so a reserved (25 `SessionSignal`, 40/41) or future control
            // number decodes to `body: None` exactly like an empty message;
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
    fn authorize(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        resource: &str,
    ) -> Result<(), Box<ControlMessage>> {
        let decision = self
            .authorizer
            .check(&ctx.principal, ctx.auth_path, action, resource);
        self.audit.record(&AuditRecord::now(
            request_id,
            &ctx.principal,
            action,
            resource,
            decision,
            ctx.peer_addr,
        ));
        if !decision.is_allow() {
            return Err(Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::PermissionDenied,
                    format!("peer is not allowed to {action} on this host"),
                    false,
                ),
            )));
        }
        Ok(())
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

        // ---- Resource bound: no more outstanding tickets for this peer. ----
        if let Err(reply) = self.check_ticket_budget(ctx, request_id) {
            return *reply;
        }

        // ---- ACL choke point: decide + audit BEFORE any resource. ----
        if let Err(denied) = self.authorize(ctx, request_id, Action::ExecRun, "exec") {
            return *denied;
        }

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
        if let Err(reply) = self.check_ticket_budget(ctx, request_id) {
            return *reply;
        }

        // ---- ACL choke point: decide + audit BEFORE any resource. ----
        if let Err(denied) = self.authorize(ctx, request_id, Action::SessionOpen, SESSION_RESOURCE)
        {
            return *denied;
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
        let session_id = match self.sessions.open(&spec) {
            Ok(id) => id,
            Err(err) => return broker_error(request_id, err),
        };
        let ticket = self.issue_ticket(
            ctx.conn_id,
            TicketPurpose::Session {
                session_id: session_id.clone(),
            },
        );
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
                // Resume tokens land with PLAN M2 Step 7; until then no
                // token is issued and `SessionAttach` is UNSUPPORTED.
                resume_token: Vec::new(),
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
        if let Err(denied) = self.authorize(ctx, request_id, Action::SessionList, SESSION_RESOURCE)
        {
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
        if let Err(denied) = self.authorize(ctx, request_id, Action::SessionList, &req.session_id) {
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
        if let Err(denied) = self.authorize(ctx, request_id, Action::SessionAttach, &req.session_id)
        {
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

    /// `session.write`: ACL `session.control` on the session id, then take
    /// the writer lease (programmatic ⇒ `no_steal`: another principal's
    /// live lease is `SESSION_CONFLICT`, architecture.md §3 rule b) and
    /// write.
    async fn handle_session_write(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionWrite,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        if let Err(err) = req.validate() {
            return invalid_argument(request_id, err.to_string());
        }
        if let Err(denied) =
            self.authorize(ctx, request_id, Action::SessionControl, &req.session_id)
        {
            return *denied;
        }
        let id = SessionId(req.session_id.clone());
        let conn = ctx.connection_id();
        if req.data.is_empty() {
            // Nothing to write: answer without touching the lease, so an
            // empty write is not a side-channel for displacing (or
            // flapping) the current writer. Existence is still checked
            // (the ACL decision above already covers disclosure).
            return match self.sessions.get(&id) {
                Ok(_) => ControlMessage::response(
                    request_id,
                    response::Body::SessionWritten(wire::SessionWritten { bytes_written: 0 }),
                ),
                Err(err) => broker_error(request_id, err),
            };
        }
        match self
            .sessions
            .take_lease(&id, ctx.principal.to_string(), conn, true)
            .await
        {
            Ok(TakeOutcome::Conflict { .. }) => {
                return ControlMessage::error(
                    request_id,
                    wire::Error::new(
                        ErrorCode::SessionConflict,
                        "another principal holds the session's writer lease",
                        true,
                    ),
                );
            }
            Ok(_) => {}
            Err(err) => return broker_error(request_id, err),
        }
        let bytes_written = req.data.len() as u64;
        match self.sessions.write(&id, conn, req.data.clone()).await {
            Ok(()) => ControlMessage::response(
                request_id,
                response::Body::SessionWritten(wire::SessionWritten { bytes_written }),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.resize`: ACL `session.control` on the session id.
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
        if let Err(denied) =
            self.authorize(ctx, request_id, Action::SessionControl, &req.session_id)
        {
            return *denied;
        }
        match self
            .sessions
            .resize(&SessionId(req.session_id.clone()), cols, rows)
            .await
        {
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
        if let Err(denied) =
            self.authorize(ctx, request_id, Action::SessionControl, &req.session_id)
        {
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

    /// `session.attach` (stream op): resume tokens and the attach data
    /// pump land with PLAN M2 Steps 5/7. Until then the host validates the
    /// mode (an unset/unknown/RO mode is `INVALID_ARGUMENT`, never RW —
    /// protocol.md §9), passes the ACL choke point (`session.attach` on
    /// the id, audited like every other session op) and only then answers
    /// `UNSUPPORTED` without consulting the broker, so nothing is created
    /// and session existence is not disclosed. Step 7 inserts the
    /// token → fingerprint checks *before* the ACL call (protocol.md
    /// §10-2); the choke point itself is already in place.
    fn handle_session_attach(
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
        if let Err(denied) = self.authorize(ctx, request_id, Action::SessionAttach, &req.session_id)
        {
            return *denied;
        }
        ControlMessage::error(
            request_id,
            wire::Error::new(
                ErrorCode::Unsupported,
                "session.attach (resume) is not implemented by this host yet",
                false,
            ),
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
        let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        tickets.retain(|_, p| p.expires_at > now);
        loop {
            let mut ticket = [0u8; TICKET_LEN];
            rand::rng().fill_bytes(&mut ticket);
            if let std::collections::hash_map::Entry::Vacant(slot) = tickets.entry(ticket) {
                slot.insert(pending);
                return ticket;
            }
        }
    }

    /// Redeem a ticket presented on `conn_id` by a stream of `kind`.
    /// Single use: a successful redemption removes it. Fails (returns
    /// `None`) if unknown, expired, malformed, issued to a different
    /// connection, or issued for a different stream kind.
    pub fn redeem_ticket(&self, conn_id: usize, kind: StreamKind, ticket: &[u8]) -> Option<Ticket> {
        let key: [u8; TICKET_LEN] = ticket.try_into().ok()?;
        let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        let matches = tickets.get(&key).is_some_and(|p| {
            p.conn_id == conn_id && p.expires_at > Instant::now() && p.purpose.stream_kind() == kind
        });
        if matches { tickets.remove(&key) } else { None }
    }

    /// The connection is gone: drop every ticket issued to it and release
    /// every writer lease it held. Sessions (and their children) survive —
    /// that is the point of the broker (architecture.md §3 rule c).
    pub async fn purge_connection(&self, conn_id: usize) {
        self.tickets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, p| p.conn_id != conn_id);
        self.sessions
            .release_connection(ConnectionId(conn_id as u64))
            .await;
    }

    // ------------------------------------------------------------------
    // connection driver
    // ------------------------------------------------------------------

    /// Accept loop. Runs until `shutdown` resolves or the listener closes,
    /// then closes the endpoint and waits for it to drain.
    pub async fn run(
        self: Arc<Self>,
        listener: Listener,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                incoming = listener.accept() => {
                    let Some(incoming) = incoming else { break };
                    let server = self.clone();
                    tokio::spawn(async move {
                        let peer = incoming.remote_address();
                        match incoming.accept().await {
                            Ok(conn) => server.serve_connection(conn).await,
                            Err(err) => {
                                let category = match &err {
                                    qsh_transport::AcceptError::Unverified(reason) => {
                                        format!("{reason:?}").to_lowercase()
                                    }
                                    _ => "handshake".to_string(),
                                };
                                server
                                    .audit
                                    .record(&AuditRecord::handshake_rejected(peer, &category));
                                tracing::warn!(%peer, %err, "connection rejected");
                            }
                        }
                    });
                }
            }
        }
        listener.close(0, b"shutdown");
        listener.endpoint().wait_idle().await;
    }

    /// Drive one authenticated connection to completion.
    pub async fn serve_connection(self: Arc<Self>, conn: Connection) {
        let peer_addr = conn.remote_address();
        let principal = conn.principal().clone();
        let conn_id = conn.stable_id();
        tracing::info!(%principal, peer = %peer_addr, "connection accepted");

        let result = self.clone().serve_connection_inner(&conn).await;
        self.purge_connection(conn_id).await;
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

    async fn serve_connection_inner(self: Arc<Self>, conn: &Connection) -> Result<(), ConnError> {
        let (send, recv) = tokio::time::timeout(HELLO_TIMEOUT, conn.accept_bi())
            .await
            .map_err(|_| ConnError::HelloTimeout)??;
        let mut ctl = FramedStream::control(send, recv);

        let first = tokio::time::timeout(HELLO_TIMEOUT, ctl.recv.recv::<ControlMessage>())
            .await
            .map_err(|_| ConnError::HelloTimeout)??
            .ok_or(ConnError::ClosedBeforeHello)?;
        let Some(control_message::Body::Hello(peer_hello)) = first.body else {
            return Err(ConnError::ExpectedHello);
        };

        let versions: Vec<u32> = wire::WIRE_MINOR_VERSIONS
            .iter()
            .copied()
            .filter(|v| peer_hello.versions.contains(v))
            .collect();
        if versions.is_empty() {
            let _ = ctl
                .send
                .send(&ControlMessage::error(
                    0,
                    wire::Error::new(
                        ErrorCode::Unsupported,
                        "no common wire minor version",
                        false,
                    ),
                ))
                .await;
            return Err(ConnError::VersionMismatch);
        }
        let capabilities: Vec<String> = wire::LOCAL_CAPABILITIES
            .iter()
            .filter(|c| peer_hello.capabilities.iter().any(|p| p == *c))
            .map(|c| c.to_string())
            .collect();

        ctl.send
            .send(&ControlMessage::new(
                0,
                control_message::Body::Hello(self.local_hello()),
            ))
            .await?;

        let ctx = ConnCtx {
            principal: conn.principal().clone(),
            auth_path: conn.auth_path(),
            peer_addr: conn.remote_address(),
            conn_id: conn.stable_id(),
            capabilities,
        };

        // Control messages are handled inline, in arrival order, so the
        // control stream keeps its ordering guarantee for mutating ops
        // (two pipelined `SessionWrite`s reach the PTY in the order they
        // were sent — protocol.md §9). The exceptions are the messages
        // that may block (`is_long_poll`: the `SessionRead` long-poll and
        // `SessionClose`'s escalation), which must not stall the stream:
        // those run in tasks owned by `blocking` (bounded by `inflight`),
        // whose replies funnel back through `reply_rx` to the single
        // control-stream writer. When this function returns, `blocking` is
        // dropped and every parked task is aborted with it — nothing
        // outlives the connection, and `purge_connection` (which runs
        // after) therefore sees the connection's final state.
        let (reply_tx, mut reply_rx) =
            tokio::sync::mpsc::channel::<ControlMessage>(MAX_INFLIGHT_REQUESTS_PER_CONN);
        let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_REQUESTS_PER_CONN));
        let mut blocking: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                msg = ctl.recv.recv::<ControlMessage>() => match msg {
                    Ok(Some(msg)) => {
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
                        tokio::spawn(async move {
                            server.handle_data_stream(ctx, FramedStream::data(send, recv)).await;
                        });
                    }
                    Err(_) => return Ok(()),
                },
            }
        }
    }

    /// Admit a peer-opened data stream: read the header, redeem the ticket
    /// for that stream kind, run the exec. Anything else resets the stream
    /// without touching any resource.
    async fn handle_data_stream(&self, ctx: ConnCtx, mut stream: FramedStream) {
        let header =
            match tokio::time::timeout(HEADER_TIMEOUT, stream.recv.recv::<StreamHeader>()).await {
                Ok(Ok(Some(h))) => h,
                _ => {
                    stream.send.reset(RESET_CODE_BAD_HEADER);
                    stream.recv.stop(RESET_CODE_BAD_HEADER);
                    return;
                }
            };
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
            // The `SESSION_DATA` pump lands with PLAN M2 Step 5. The ticket
            // was valid and is now consumed; the stream is reset cleanly so
            // the peer sees a definite failure rather than a hang.
            TicketPurpose::Session { session_id } => {
                tracing::debug!(
                    principal = %ctx.principal,
                    %session_id,
                    "SESSION_DATA stream not implemented yet; resetting"
                );
                stream.send.reset(RESET_CODE_NOT_IMPLEMENTED);
                stream.recv.stop(RESET_CODE_NOT_IMPLEMENTED);
            }
        }
    }
}

// ----------------------------------------------------------------------
// helpers: wire ⇄ broker
// ----------------------------------------------------------------------

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

fn invalid_argument(request_id: u64, message: impl Into<String>) -> ControlMessage {
    ControlMessage::error(
        request_id,
        wire::Error::new(ErrorCode::InvalidArgument, message, false),
    )
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
        BrokerError::Spawn(_) | BrokerError::Io(_) | BrokerError::Gone => {
            (ErrorCode::Internal, false)
        }
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

/// Per-connection protocol failures (all end the connection).
#[derive(Debug, Error)]
enum ConnError {
    #[error("peer did not send Hello within {HELLO_TIMEOUT:?}")]
    HelloTimeout,
    #[error("peer closed the control stream before Hello")]
    ClosedBeforeHello,
    #[error("first control message was not Hello")]
    ExpectedHello,
    #[error("no common wire minor version")]
    VersionMismatch,
    #[error(transparent)]
    Stream(#[from] qsh_transport::StreamError),
    #[error(transparent)]
    Connection(#[from] qsh_transport::ConnectionError),
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
            | ConnError::VersionMismatch => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AllowAllPinned, DenyAll};
    use crate::audit::MemoryAuditSink;
    use crate::broker::{
        Broker, BrokerConfig, PipeFactory, PipeHandle, SessionState, SourceExit, TestClock,
    };

    const ALL_CAPS: &[&str] = &["exec", "session"];

    fn ctx(principal: Principal, caps: &[&str]) -> ConnCtx {
        ConnCtx {
            principal,
            auth_path: AuthPath::Pin,
            peer_addr: "127.0.0.1:5000".parse().unwrap(),
            conn_id: 42,
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A server over a fresh test broker (pipe sources, injected clock).
    struct Rig {
        server: Arc<Server>,
        audit: Arc<MemoryAuditSink>,
        broker: Arc<Broker>,
        pipes: Arc<PipeFactory>,
        clock: TestClock,
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
        let clock = TestClock::new();
        let broker = Broker::new(
            Arc::new(clock.clone()),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace,
            },
            pipes.clone(),
        );
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(authorizer, audit.clone(), broker.clone(), "host");
        Rig {
            server,
            audit,
            broker,
            pipes,
            clock,
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
        let reply = rig.server.dispatch(ctx, &session_open(1)).await.unwrap();
        let (id, ticket) = match response_body(&reply) {
            response::Body::SessionOpened(o) => (o.session_id.clone(), o.ticket.clone()),
            other => panic!("expected SessionOpened, got {other:?}"),
        };
        let pipe = rig.pipes.take().expect("pipe handle for the new session");
        (id, ticket, pipe)
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

    #[tokio::test]
    async fn outstanding_tickets_per_connection_are_bounded() {
        let rig = allow_rig();
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
        // Not an authorization decision: nothing extra in the audit log.
        assert_eq!(rig.audit.records().len(), MAX_PENDING_TICKETS_PER_CONN);
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
    /// other unknown number decode to `body: None` and are answered
    /// UNSUPPORTED without creating anything.
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
        for field in [25u32, 40, 41, 200] {
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

        rig.server.purge_connection(42).await;
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
        assert_eq!(
            actions,
            [
                Action::SessionOpen,
                Action::SessionList,
                Action::SessionAttach,
                Action::SessionControl,
            ]
            .iter()
            .map(|a| a.as_str())
            .collect()
        );
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
            let (action, resource) = match name {
                "open" => (Action::SessionOpen, SESSION_RESOURCE.to_string()),
                "list" => (Action::SessionList, SESSION_RESOURCE.to_string()),
                "get" => (Action::SessionList, id.clone()),
                "read" => (Action::SessionAttach, id.clone()),
                "write" | "resize" | "close" => (Action::SessionControl, id.clone()),
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
        assert!(opened.resume_token.is_empty(), "no token before Step 7");
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
            TicketPurpose::Session { session_id } if session_id.0 == opened.session_id
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

    #[tokio::test]
    async fn write_by_another_principal_over_a_live_lease_is_session_conflict() {
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
        assert_eq!(error_code(&reply), Some(ErrorCode::SessionConflict));
        // Same principal on another connection takes over.
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
    async fn attach_is_unsupported_until_resume_lands_and_creates_nothing() {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let (id, _t, _pipe) = open_session(&rig, &ctx).await;
        rig.audit.clear();
        for sid in [id.as_str(), "01K0NOSUCHSESSION"] {
            let reply = rig
                .server
                .dispatch(
                    &ctx,
                    &ControlMessage::new(
                        1,
                        control_message::Body::SessionAttach(wire::SessionAttach {
                            session_id: sid.into(),
                            mode: wire::AttachMode::Rw as i32,
                            ..Default::default()
                        }),
                    ),
                )
                .await
                .unwrap();
            assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported), "{sid}");
        }
        // Both attempts passed the choke point (`session.attach` on the id)
        // and were audited before the UNSUPPORTED answer; nothing created.
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 2, "{recs:?}");
        assert!(recs.iter().all(|r| r.action == "session.attach"));
        assert_eq!(recs[0].resource, id);
        assert_eq!(recs[1].resource, "01K0NOSUCHSESSION");
        assert_eq!(rig.server.pending_tickets(), 1, "only the open's ticket");

        // Denied peers are audited too, and get the same non-distinguishing
        // PERMISSION_DENIED for a real and a fabricated id.
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
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        let recs = denied.audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "deny");
        assert_eq!(recs[0].action, "session.attach");
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
}
