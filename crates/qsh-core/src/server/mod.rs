//! Host side of the protocol: accept loop, per-connection `Hello`
//! negotiation, control-message [`dispatch`](Server::dispatch), and data
//! stream admission by ticket.
//!
//! `dispatch` is the **single ACL choke point** (`docs/design/architecture.md`
//! §6): every request is decided by [`Authorizer::check`] and audited
//! *before* a ticket is issued, and a child process is only spawned when a
//! data stream redeems a valid ticket. `dispatch` itself is pure with
//! respect to transport — it takes a decoded [`ControlMessage`] plus a
//! [`ConnCtx`] and returns the response message — so the M2 broker and the
//! P1 supervisor can sit on the same seam without touching quinn types.
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
    response,
};
use qsh_transport::endpoint::CLOSE_CODE_PROTOCOL;
use qsh_transport::{AuthPath, Connection, FramedStream, Listener, Principal};
use rand::RngCore;
use thiserror::Error;

use crate::acl::{Action, Authorizer, Decision};
use crate::audit::{AuditRecord, AuditSink};
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
/// ticket was invalid/expired/foreign.
pub const RESET_CODE_BAD_HEADER: u32 = 0x2001;

/// Maximum number of unredeemed tickets one connection may hold. Bounds
/// the memory a (pinned) peer can pin down by issuing `ExecStart`s it never
/// follows up on; further requests get `RESOURCE_EXHAUSTED` until tickets
/// are redeemed or expire.
pub const MAX_PENDING_TICKETS_PER_CONN: usize = 32;

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
    /// earned them.
    pub conn_id: usize,
    /// Capabilities negotiated in `Hello` (intersection).
    pub capabilities: Vec<String>,
}

impl ConnCtx {
    fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }
}

/// An authorized exec waiting for its data stream.
#[derive(Debug, Clone)]
pub struct PendingExec {
    /// Opaque exec identifier (ULID).
    pub exec_id: String,
    /// What to run once the stream arrives.
    pub spec: ExecSpec,
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

/// The host: policy + audit + ticket registry. Shared across connections.
pub struct Server {
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<dyn AuditSink>,
    device_name: String,
    tickets: Mutex<HashMap<[u8; TICKET_LEN], PendingExec>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Build a server with the given policy and audit sink.
    pub fn new(
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        device_name: impl Into<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            authorizer,
            audit,
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
    /// is due (e.g. an unsolicited `Pong`). Never creates a resource; the
    /// only side effects are the audit record and, on allow, a ticket.
    pub fn dispatch(&self, ctx: &ConnCtx, msg: &ControlMessage) -> Option<ControlMessage> {
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
            // Session control (M2). The wire contract exists (PLAN Step 1)
            // but the broker is not wired in yet (Step 3): answer
            // UNSUPPORTED without touching any state — no session, ticket
            // or audit line is created for these.
            Some(
                control_message::Body::SessionOpen(_)
                | control_message::Body::SessionAttach(_)
                | control_message::Body::SessionList(_)
                | control_message::Body::SessionGet(_)
                | control_message::Body::SessionResize(_)
                | control_message::Body::SessionClose(_)
                | control_message::Body::SessionRead(_)
                | control_message::Body::SessionWrite(_),
            ) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "session operations are not implemented by this host yet",
                    false,
                ),
            )),
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
            None => Some(ControlMessage::error(
                request_id,
                wire::Error::new(ErrorCode::InvalidArgument, "empty control message", false),
            )),
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

        // ---- Resource bound: no more outstanding tickets for this peer. ----
        if self.pending_tickets_for(ctx.conn_id) >= MAX_PENDING_TICKETS_PER_CONN {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::ResourceExhausted,
                    "too many outstanding exec tickets on this connection",
                    true,
                ),
            );
        }

        // ---- ACL choke point: decide + audit BEFORE any resource. ----
        let decision =
            self.authorizer
                .check(&ctx.principal, ctx.auth_path, Action::ExecRun, "exec");
        self.audit.record(&AuditRecord::now(
            request_id,
            &ctx.principal,
            Action::ExecRun,
            "exec",
            decision,
            ctx.peer_addr,
        ));
        if decision == Decision::Deny {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::PermissionDenied,
                    "peer is not allowed to run commands on this host",
                    false,
                ),
            );
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
        let ticket = self.issue_ticket(PendingExec {
            exec_id: exec_id.clone(),
            spec,
            conn_id: ctx.conn_id,
            expires_at: Instant::now() + TICKET_TTL,
        });
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

    fn issue_ticket(&self, pending: PendingExec) -> [u8; TICKET_LEN] {
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

    /// Redeem a ticket presented on `conn_id`. Single use: a successful
    /// redemption removes it. Fails (returns `None`) if unknown, expired,
    /// malformed, or issued to a different connection.
    pub fn redeem_ticket(&self, conn_id: usize, ticket: &[u8]) -> Option<PendingExec> {
        let key: [u8; TICKET_LEN] = ticket.try_into().ok()?;
        let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        let matches = tickets
            .get(&key)
            .is_some_and(|p| p.conn_id == conn_id && p.expires_at > Instant::now());
        if matches { tickets.remove(&key) } else { None }
    }

    /// Drop every ticket issued to `conn_id` (connection gone).
    pub fn purge_connection(&self, conn_id: usize) {
        self.tickets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, p| p.conn_id != conn_id);
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
        self.purge_connection(conn_id);
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

        loop {
            tokio::select! {
                msg = ctl.recv.recv::<ControlMessage>() => match msg {
                    Ok(Some(msg)) => {
                        if let Some(reply) = self.dispatch(&ctx, &msg) {
                            ctl.send.send(&reply).await?;
                        }
                    }
                    Ok(None) => return Ok(()),
                    Err(err) => return Err(err.into()),
                },
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

    /// Admit a peer-opened data stream: read the header, redeem the ticket,
    /// run the exec. Anything else resets the stream without touching any
    /// resource.
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
        match header.stream_kind() {
            Some(StreamKind::ExecData) => {}
            _ => {
                tracing::debug!(principal = %ctx.principal, kind = header.kind, "unsupported stream kind");
                stream.send.reset(RESET_CODE_BAD_HEADER);
                stream.recv.stop(RESET_CODE_BAD_HEADER);
                return;
            }
        }
        let Some(pending) = self.redeem_ticket(ctx.conn_id, &header.ticket) else {
            tracing::warn!(principal = %ctx.principal, "exec data stream with invalid ticket");
            stream.send.reset(RESET_CODE_BAD_HEADER);
            stream.recv.stop(RESET_CODE_BAD_HEADER);
            return;
        };
        let exec_id = pending.exec_id.clone();
        match run_exec(pending.spec, stream.send, stream.recv).await {
            Ok(outcome) => tracing::info!(
                principal = %ctx.principal,
                %exec_id,
                exit_code = outcome.exit_code,
                timed_out = outcome.timed_out,
                "exec finished"
            ),
            // The peer going away mid-exec (its own `--timeout`, a crash, a
            // network drop) is ordinary operation, not a host-side fault:
            // the child was killed and reaped, nothing to alarm about.
            Err(err) if err.is_peer_gone() => tracing::info!(
                principal = %ctx.principal,
                %exec_id,
                %err,
                "exec aborted: peer went away; command killed"
            ),
            Err(err) => tracing::warn!(principal = %ctx.principal, %exec_id, %err, "exec failed"),
        }
    }
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

    fn ctx(principal: Principal, caps: &[&str]) -> ConnCtx {
        ConnCtx {
            principal,
            auth_path: AuthPath::Pin,
            peer_addr: "127.0.0.1:5000".parse().unwrap(),
            conn_id: 42,
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
        }
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

    fn error_code(msg: &ControlMessage) -> Option<ErrorCode> {
        match &msg.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => Some(e.error_code()),
            _ => None,
        }
    }

    #[test]
    fn allowed_exec_issues_ticket_and_audits_allow() {
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(Arc::new(AllowAllPinned), audit.clone(), "host");
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = server.dispatch(&ctx, &exec_start(5, &["true"])).unwrap();
        assert_eq!(reply.request_id, 5);
        let ticket = match &reply.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::ExecStarted(started)),
            })) => started.ticket.clone(),
            other => panic!("expected ExecStarted, got {other:?}"),
        };
        assert_eq!(ticket.len(), TICKET_LEN);
        assert_eq!(server.pending_tickets(), 1);
        let recs = audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "allow");
        assert_eq!(recs[0].principal, "device:laptop");
        assert_eq!(recs[0].action, "exec.run");
        assert_eq!(recs[0].request_id, "5");
        // Redeem: bound to the connection, single use.
        assert!(server.redeem_ticket(41, &ticket).is_none(), "foreign conn");
        let pending = server.redeem_ticket(42, &ticket).expect("redeem once");
        assert_eq!(pending.spec.argv, vec!["true"]);
        assert!(server.redeem_ticket(42, &ticket).is_none(), "single use");
        assert_eq!(server.pending_tickets(), 0);
    }

    #[test]
    fn denied_exec_issues_no_ticket_and_audits_deny() {
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(Arc::new(DenyAll), audit.clone(), "host");
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = server.dispatch(&ctx, &exec_start(6, &["true"])).unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        assert_eq!(server.pending_tickets(), 0, "no ticket before ACL pass");
        let recs = audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "deny");
    }

    #[test]
    fn unpinned_principal_is_denied_under_interim_policy() {
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(Arc::new(AllowAllPinned), audit.clone(), "host");
        // A CA-authenticated peer — user or device — is not pinned.
        for principal in [
            Principal::User("dave".into()),
            Principal::Device("laptop".into()),
        ] {
            let mut ctx = ctx(principal, &["exec"]);
            ctx.auth_path = AuthPath::Ca;
            let reply = server.dispatch(&ctx, &exec_start(1, &["true"])).unwrap();
            assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
        }
        assert_eq!(server.pending_tickets(), 0);
        let records = audit.records();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.decision == "deny"));
    }

    #[test]
    fn outstanding_tickets_per_connection_are_bounded() {
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(Arc::new(AllowAllPinned), audit.clone(), "host");
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        for i in 0..MAX_PENDING_TICKETS_PER_CONN {
            let reply = server
                .dispatch(&ctx, &exec_start(i as u64, &["true"]))
                .unwrap();
            assert_eq!(error_code(&reply), None, "ticket {i} must be issued");
        }
        assert_eq!(server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
        let reply = server.dispatch(&ctx, &exec_start(999, &["true"])).unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));
        assert_eq!(server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
        // Not an authorization decision: nothing extra in the audit log.
        assert_eq!(audit.records().len(), MAX_PENDING_TICKETS_PER_CONN);
        // Another connection is unaffected by this one's backlog.
        let mut other = ctx.clone();
        other.conn_id += 1;
        let reply = server.dispatch(&other, &exec_start(1, &["true"])).unwrap();
        assert_eq!(error_code(&reply), None);
        assert_eq!(server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN + 1);
    }

    #[test]
    fn exec_without_capability_is_unsupported_and_not_audited() {
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(Arc::new(AllowAllPinned), audit.clone(), "host");
        let ctx = ctx(Principal::Device("laptop".into()), &[]);
        let reply = server.dispatch(&ctx, &exec_start(1, &["true"])).unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
        assert!(audit.records().is_empty());
        assert_eq!(server.pending_tickets(), 0);
    }

    #[test]
    fn empty_argv_is_invalid_argument() {
        let server = Server::new(
            Arc::new(AllowAllPinned),
            Arc::new(MemoryAuditSink::new()),
            "h",
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = server.dispatch(&ctx, &exec_start(1, &[])).unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::InvalidArgument));
    }

    #[test]
    fn ping_gets_pong_with_same_request_id() {
        let server = Server::new(
            Arc::new(AllowAllPinned),
            Arc::new(MemoryAuditSink::new()),
            "h",
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        let reply = server
            .dispatch(
                &ctx,
                &ControlMessage::new(77, control_message::Body::Ping(wire::Ping {})),
            )
            .unwrap();
        assert_eq!(reply.request_id, 77);
        assert!(matches!(reply.body, Some(control_message::Body::Pong(_))));
        assert!(
            server
                .dispatch(
                    &ctx,
                    &ControlMessage::new(78, control_message::Body::Pong(wire::Pong {}))
                )
                .is_none()
        );
    }

    #[test]
    fn purge_connection_drops_its_tickets() {
        let server = Server::new(
            Arc::new(AllowAllPinned),
            Arc::new(MemoryAuditSink::new()),
            "h",
        );
        let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
        server.dispatch(&ctx, &exec_start(1, &["true"]));
        server.dispatch(&ctx, &exec_start(2, &["true"]));
        assert_eq!(server.pending_tickets(), 2);
        server.purge_connection(42);
        assert_eq!(server.pending_tickets(), 0);
    }
}
