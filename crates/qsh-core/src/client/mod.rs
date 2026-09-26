//! Requester side of the protocol: `Hello` negotiation over a dialed
//! connection and the client half of `exec.run` (control request → ticket
//! → `EXEC_DATA` stream → assemble stdout/stderr/exit).
//!
//! This module speaks in wire terms and typed errors; the `Ops` façade maps
//! [`ClientError`] to `OpError`/`ErrorCode` for the CLI.

use std::time::{Duration, Instant};

use qsh_proto::ErrorCode;
use qsh_proto::wire::{
    self, ControlMessage, ExecFrame, ExecStart, ExecStarted, Hello, SessionFrame, StreamHeader,
    control_message, exec_frame, response, session_frame,
};
use qsh_transport::{Connection, FramedStream, StreamError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::exec::ExecSpec;
// `crate::localctl` is `#[cfg(unix)]`-only (`lib.rs`) — this whole reverse
// (`LOCAL_CONTROL`) leg is unix-only, mirroring `ops/session.rs`'s own
// `connect_reverse`/`dial_reverse` twin-cfg discipline (Windows leg trap
// (b): an ungated import consumed only by unix-only code trips
// `unused_imports` under Windows clippy).
#[cfg(unix)]
use crate::localctl::client::ControlConduit;
#[cfg(unix)]
use crate::ops::OpError;

pub mod link;
pub mod pathwatch;
pub mod reconnect;

use link::{ControlLink, DataKillSwitch, DataRecv, DataSend};

/// How long to wait for the peer's `Hello`. Single definition now lives in
/// [`crate::handshake`]; re-exported here so this path stays stable.
pub use crate::handshake::HELLO_TIMEOUT;

/// Client-side protocol errors.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The peer answered a request with a wire error. `code` is the peer's
    /// error code verbatim (e.g. `PERMISSION_DENIED`).
    #[error("{code}: {message}")]
    Remote {
        /// Peer-reported code.
        code: ErrorCode,
        /// Peer-reported message.
        message: String,
        /// Peer-reported retryability.
        retryable: bool,
    },
    /// The peer does not offer what we need (no common version/capability).
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The peer violated the protocol.
    #[error("protocol: {0}")]
    Protocol(String),
    /// A stream failed.
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// The connection failed.
    #[error("connection: {0}")]
    Connection(#[from] qsh_transport::ConnectionError),
    /// The peer's `Hello` did not arrive in time.
    #[error("timed out waiting for peer Hello")]
    HelloTimeout,
    /// The remote command produced more output than this client is willing
    /// to buffer ([`EXEC_OUTPUT_MAX`]).
    #[error("remote command output exceeded {limit} bytes")]
    OutputTooLarge {
        /// The cap that was hit.
        limit: usize,
    },
}

/// Upper bound on the bytes of stdout + stderr an `exec` buffers before it
/// gives up with [`ClientError::OutputTooLarge`]. `exec.run` returns the
/// whole output in one JSON envelope, so it must be bounded; streaming
/// output belongs to sessions (M2).
pub const EXEC_OUTPUT_MAX: usize = 64 * 1024 * 1024;

/// Map [`crate::handshake::HelloError`] onto the initiator's pre-existing
/// [`ClientError`] surface, preserving every message exactly as it read
/// before the handshake exchange moved into `handshake.rs` (PLAN M3 Step 2
/// (d) — zero observable behavior change). `pub` — Step 3's `qsh reverse`
/// (`crate::reverse::target::run_reverse`) is another `handshake::initiate`
/// caller and reuses this exact mapping (chained into
/// `ops::exec::map_client_error`) rather than a second copy of it; `qsh-
/// testkit`'s integration tests reuse the same chain to assert what a
/// denied registration actually maps to, rather than re-deriving it.
pub fn map_hello_error(err: crate::handshake::HelloError) -> ClientError {
    use crate::handshake::HelloError;
    match err {
        HelloError::Timeout => ClientError::HelloTimeout,
        HelloError::ClosedBeforeHello => {
            ClientError::Protocol("peer closed control stream before Hello".into())
        }
        HelloError::ExpectedHello => {
            ClientError::Protocol("first control message was not Hello".into())
        }
        HelloError::VersionMismatch => {
            ClientError::Unsupported("no common wire minor version".into())
        }
        HelloError::Remote {
            code,
            message,
            retryable,
        } => ClientError::Remote {
            code,
            message,
            retryable,
        },
        HelloError::Stream(e) => ClientError::Stream(e),
        HelloError::Connection(e) => ClientError::Connection(e),
        // `handshake::initiate` never supplies a rejecting callback — only
        // `respond`'s `make_local_hello` can produce this.
        HelloError::Rejected(_) => {
            unreachable!("initiate() never invokes a rejecting callback")
        }
        // `AlreadyPaired` is constructed only by `respond_on` (report F-2)
        // when the *responder's* first control message is a `PairingProof`
        // — `initiate_on` never parses its peer's first message as
        // anything but a reply to its own `Hello`, so this side of the
        // exchange can never produce it either.
        HelloError::AlreadyPaired(_) => {
            unreachable!("initiate() never reads a PairingProof as its own peer's Hello")
        }
    }
}

/// A negotiated connection: control stream open, `Hello` exchanged.
///
/// `conn` is `None` exactly when `Self::link` is
/// `ControlLink::Local` (the reverse route,
/// `PLAN.md` M3 Step 6): a CLI process relaying through its resident
/// daemon is not itself a QUIC endpoint on the underlying connection, so
/// there is no [`Connection`] to hold. Every data stream this `Session`
/// opens — [`Self::exec`]'s `EXEC_DATA` (issue #5) and
/// [`Self::open_attach_stream`]'s `SESSION_DATA` (`docs/design/protocol.md`
/// §11-3) — goes through `Self::open_data_link` instead, which opens a fresh
/// `LOCAL_STREAM` conduit to the same daemon socket and host `local`
/// recorded on this route, rather than a QUIC `open_bi()` a reverse-linked
/// `Session` has no connection to make.
pub struct Session {
    conn: Option<Connection>,
    link: ControlLink,
    /// The daemon socket and host alias [`Self::link`]'s `LOCAL_CONTROL`
    /// conduit came from — `Some` exactly when `conn` is `None`. Recorded
    /// so a later [`Self::open_attach_stream`] can open a fresh
    /// `LOCAL_STREAM` conduit to that *same* daemon for that *same* host
    /// without this module having to thread a
    /// [`crate::ops::LocalRoute`] through (which would reach backwards
    /// from `client` into `ops`, the wrong dependency direction —
    /// `CLAUDE.md`'s workspace map).
    #[cfg(unix)]
    local: Option<(std::path::PathBuf, String)>,
    /// The `LOCAL_CONTROL` leg's own `LocalHelloAck` identity —
    /// `(peer_fingerprint, generation)` — `Some` exactly when
    /// [`Self::local`] is `Some`. Compared against the `LOCAL_STREAM`
    /// conduit's own ack in [`Self::open_local_data_link`] so a
    /// registration that died and reconnected (or was superseded)
    /// between the two handshakes is caught as a stale route rather than
    /// silently opening a data stream against a peer the control leg
    /// never actually bound to (see that method's own doc).
    #[cfg(unix)]
    local_ack: Option<(String, u64)>,
    next_request_id: u64,
    /// Capabilities both sides support.
    pub capabilities: Vec<String>,
    /// The peer's display name from its `Hello` (informational only —
    /// never an identity).
    pub peer_device_name: String,
}

impl Session {
    /// Open the control stream and exchange `Hello` on a fresh connection.
    pub async fn negotiate(conn: Connection, device_name: &str) -> Result<Self, ClientError> {
        let local_hello = Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: device_name.to_string(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            reverse: None,
        };
        let (ctl, peer_hello) = crate::handshake::initiate(&conn, local_hello)
            .await
            .map_err(map_hello_error)?;
        Ok(Self::from_control(conn, ctl, peer_hello))
    }

    /// Build a [`Session`] from an already-negotiated control stream (the
    /// `ctl`/`peer_hello` [`crate::handshake::initiate`] just produced).
    /// Split out so a caller that reaches the control stream a different
    /// way — M3's reverse controller (`qsh listen`), which *accepts* the
    /// reverse target's dialed-in connection and runs
    /// [`crate::handshake::respond`] instead of `initiate` — can still end
    /// up with a `Session` through the same construction.
    pub fn from_control(conn: Connection, ctl: FramedStream, peer_hello: Hello) -> Self {
        Self {
            conn: Some(conn),
            link: ControlLink::Quic(ctl),
            #[cfg(unix)]
            local: None,
            #[cfg(unix)]
            local_ack: None,
            next_request_id: 1,
            capabilities: crate::handshake::negotiated_capabilities(&peer_hello),
            peer_device_name: peer_hello.device_name,
        }
    }

    /// Build a [`Session`] over a `LOCAL_CONTROL` conduit already past its
    /// `LocalHelloAck` (`crate::localctl::client::open_control`) — the
    /// reverse-route sibling of [`Self::from_control`]
    /// (`docs/design/protocol.md` §11-3, `PLAN.md` M3 Step 6). There is no
    /// `Hello` exchange on this leg (the daemon already negotiated one
    /// with the peer on the CLI process's behalf), so `capabilities` and
    /// `peer_device_name` come straight from the ack instead —
    /// `LocalHelloAck.capabilities` and `.host` respectively.
    #[cfg(unix)]
    pub(crate) fn from_local_control(
        conduit: ControlConduit,
        capabilities: Vec<String>,
        host: String,
        socket: std::path::PathBuf,
        peer_fingerprint: String,
        generation: u64,
    ) -> Self {
        Self {
            conn: None,
            link: ControlLink::Local(conduit),
            local: Some((socket, host.clone())),
            local_ack: Some((peer_fingerprint, generation)),
            next_request_id: 1,
            capabilities,
            peer_device_name: host,
        }
    }

    /// The underlying connection.
    ///
    /// Only ever `None` on the reverse route (see [`Self`]'s own doc);
    /// every daemon-side session (`crate::reverse::listen`, always dialed
    /// to a real target) and every forward CLI session is `Some`, so this
    /// panics rather than returning `Option<&Connection>` — a signature
    /// change every existing caller (all forward/daemon-side) would have
    /// to thread through for a case that provably cannot reach them.
    pub fn connection(&self) -> &Connection {
        self.conn
            .as_ref()
            .expect("connection() is never called on a reverse-route (LOCAL_CONTROL) Session")
    }

    /// Open a fresh data link and send `header` as its first frame, at
    /// `priority` on the forward route — a QUIC bidi stream dialed
    /// straight to the peer (unchanged since M1 for
    /// `SESSION_DATA`/`PRIORITY_SESSION_DATA`; issue #5 is what
    /// makes [`Self::exec`] call this too, at `PRIORITY_EXEC_DATA`), or a
    /// fresh `LOCAL_STREAM` conduit to the same daemon
    /// [`Self::local`]'s `LOCAL_CONTROL` handshake came from on the
    /// reverse route (`docs/design/protocol.md` §11-3; `priority` has no
    /// equivalent there — [`Self::open_local_data_link`]'s own doc). The third
    /// element is a hard-stop primitive for
    /// [`crate::ops::session::AttachHandle::detach`] and for
    /// [`Self::exec`]'s own output cap — live only on the reverse route
    /// (`link::DataKillSwitch`'s own doc explains why the forward route
    /// needs no equivalent of its own: closing [`Self::connection`], or
    /// resetting the stream directly, already does that job there).
    async fn open_data_link(
        &self,
        header: &StreamHeader,
        priority: i32,
    ) -> Result<(DataSend, DataRecv, DataKillSwitch), ClientError> {
        if let Some(conn) = self.conn.as_ref() {
            let (send, recv) = conn.open_bi().await?;
            let mut data = FramedStream::data(send, recv);
            data.send.set_priority(priority);
            data.send.send(header).await?;
            let (send, recv) = data.split();
            return Ok((
                DataSend::Quic(send),
                DataRecv::Quic(recv),
                DataKillSwitch::default(),
            ));
        }
        self.open_local_data_link(header).await
    }

    /// [`Self::open_data_link`]'s reverse-route branch: a fresh
    /// `LOCAL_STREAM` conduit to [`Self::local`]'s daemon socket and host
    /// (`crate::localctl::client::open_stream` sends `header` itself —
    /// see that function's own doc for why).
    #[cfg(unix)]
    async fn open_local_data_link(
        &self,
        header: &StreamHeader,
    ) -> Result<(DataSend, DataRecv, DataKillSwitch), ClientError> {
        let Some((socket, host)) = self.local.as_ref() else {
            return Err(ClientError::Protocol(
                "reverse-route session has no LOCAL_CONTROL daemon socket recorded".into(),
            ));
        };
        let handshake = crate::localctl::client::open_stream(socket, host, header)
            .await
            .map_err(|err| map_local_stream_open_error(err, header, host))?;
        // Fail closed on a stale route (`CLAUDE.md`'s "fail closed on any
        // ambiguous auth/ACL state"): if the registration died and came
        // back — or was superseded by a new one — between this session's
        // `LOCAL_CONTROL` handshake and this `LOCAL_STREAM` one, the two
        // acks disagree, and redeeming the ticket anyway would only reach
        // `redeem_ticket` on a target whose per-connection ticket table
        // never saw it, surfacing as an opaque stream reset instead of
        // this diagnosable stale-route error.
        if let Some((expected_fingerprint, expected_generation)) = self.local_ack.as_ref()
            && (&handshake.peer_fingerprint != expected_fingerprint
                || handshake.generation != *expected_generation)
        {
            return Err(ClientError::Remote {
                code: ErrorCode::HostNotFound,
                message: format!(
                    "{host}'s registration changed between the control and data \
                     handshakes (stale route)"
                ),
                retryable: true,
            });
        }
        let kill = DataKillSwitch::new(handshake.socket);
        Ok((
            DataSend::Local(handshake.send),
            DataRecv::Local(handshake.recv),
            kill,
        ))
    }

    /// Windows twin of [`Self::open_local_data_link`]: unreachable in
    /// practice (`Self::local` is always `None` there — localctl/UDS does
    /// not exist on that platform, `link::ControlLink`'s own doc), kept so
    /// [`Self::open_data_link`]'s `None` branch compiles everywhere.
    #[cfg(not(unix))]
    async fn open_local_data_link(
        &self,
        _header: &StreamHeader,
    ) -> Result<(DataSend, DataRecv, DataKillSwitch), ClientError> {
        Err(ClientError::Unsupported(
            "this platform has no LOCAL_CONTROL/LOCAL_STREAM carrier".into(),
        ))
    }

    fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }

    /// Send one request and wait for its correlated response.
    async fn request(
        &mut self,
        body: control_message::Body,
    ) -> Result<wire::Response, ClientError> {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.link
            .send(&ControlMessage::new(request_id, body))
            .await?;
        loop {
            let msg = self.link.recv().await?.ok_or_else(|| {
                ClientError::Protocol("peer closed control stream mid-request".into())
            })?;
            match msg.body {
                Some(control_message::Body::Response(resp)) if msg.request_id == request_id => {
                    return Ok(resp);
                }
                Some(control_message::Body::Ping(_)) => {
                    self.link
                        .send(&ControlMessage::new(
                            msg.request_id,
                            control_message::Body::Pong(wire::Pong {}),
                        ))
                        .await?;
                }
                // Responses to other requests / events: none exist in M1;
                // ignore rather than fail.
                _ => {}
            }
        }
    }

    /// Phase one of an exec: ask the peer to authorize `spec` and issue a
    /// data-stream ticket. Nothing runs until the ticket is redeemed by
    /// opening an `EXEC_DATA` stream (see [`exec`](Self::exec), which does
    /// both).
    pub async fn exec_start(&mut self, spec: &ExecSpec) -> Result<ExecStarted, ClientError> {
        if !self.has_capability(wire::CAP_EXEC) {
            return Err(ClientError::Unsupported(
                "peer does not support exec".into(),
            ));
        }
        let resp = self
            .request(control_message::Body::ExecStart(ExecStart {
                argv: spec.argv.clone(),
                env: spec.env.iter().cloned().collect(),
                timeout_ms: spec
                    .timeout
                    .map_or(0, |t| t.as_millis().min(u64::MAX as u128) as u64),
            }))
            .await?;
        match resp.body {
            Some(response::Body::ExecStarted(s)) => Ok(s),
            Some(response::Body::Error(e)) => Err(ClientError::Remote {
                code: e.error_code(),
                message: e.message,
                retryable: e.retryable,
            }),
            _ => Err(ClientError::Protocol(
                "unexpected response to ExecStart".into(),
            )),
        }
    }

    /// Run `spec` on the peer. `stdin`, if given, is streamed to the remote
    /// process until EOF; `None` sends an immediate EOF.
    ///
    /// `kill_tx`, if given, receives a clone of this exec's data-conduit
    /// [`DataKillSwitch`] the moment the data link opens — before this
    /// method's own receive loop starts, and regardless of which route
    /// this `Session` rides. A caller racing this call against its own
    /// deadline (`crate::ops::exec::exec_async_reverse`, issue #5) uses it
    /// to shut the conduit down at the OS level the instant that deadline
    /// hits: on the reverse route this method's stdin pump moves the send
    /// half into a detached `tokio::spawn` (see `pump_stdin`'s own doc),
    /// so simply dropping a cancelled call to this method does not
    /// promptly close it the way the forward route's caller closing the
    /// whole `Connection` does. `None` (every forward-route caller today)
    /// costs nothing beyond the one channel send this skips.
    pub async fn exec(
        &mut self,
        spec: &ExecSpec,
        stdin: Option<Box<dyn AsyncRead + Send + Unpin>>,
        kill_tx: Option<tokio::sync::oneshot::Sender<DataKillSwitch>>,
    ) -> Result<ExecResult, ClientError> {
        let started = Instant::now();
        let started_msg = self.exec_start(spec).await?;

        // Data stream: header first, then pump — a QUIC bidi stream on
        // the forward route, or a fresh `LOCAL_STREAM` conduit to the
        // same daemon and host this `Session`'s `LOCAL_CONTROL` handshake
        // came from on the reverse route (`Self::open_data_link` — issue #5
        // gives `exec.run` the reverse leg it did not have before).
        let (mut send_half, mut recv_half, kill) = self
            .open_data_link(
                &StreamHeader::exec_data(started_msg.ticket),
                wire::PRIORITY_EXEC_DATA,
            )
            .await?;
        if let Some(tx) = kill_tx {
            // A dropped receiver (the caller's own deadline already fired
            // between `exec_start` and here) is not this method's
            // problem — the switch was offered, taking it is optional.
            let _ = tx.send(kill.clone());
        }

        // stdin pump runs concurrently with output collection.
        let stdin_task = tokio::spawn(async move {
            let result = pump_stdin(stdin, &mut send_half).await;
            (send_half, result)
        });

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let outcome = loop {
            let frame = match recv_half.recv::<ExecFrame>().await {
                Ok(frame) => frame,
                Err(err) => {
                    stdin_task.abort();
                    return Err(err);
                }
            };
            match frame {
                Some(ExecFrame {
                    body: Some(exec_frame::Body::Stdout(chunk)),
                }) => stdout.extend_from_slice(&chunk.data),
                Some(ExecFrame {
                    body: Some(exec_frame::Body::Stderr(chunk)),
                }) => stderr.extend_from_slice(&chunk.data),
                Some(ExecFrame {
                    body: Some(exec_frame::Body::ExecExit(exit)),
                }) => break Some(exit),
                Some(_) => {} // stdin frames from the peer would be a slip; ignore
                None => break None,
            }
            if stdout.len() + stderr.len() > EXEC_OUTPUT_MAX {
                // Stop reading; the host notices the reset and kills the
                // command instead of streaming into the void.
                stdin_task.abort();
                recv_half.abort(1, &kill);
                return Err(ClientError::OutputTooLarge {
                    limit: EXEC_OUTPUT_MAX,
                });
            }
        };
        stdin_task.abort();
        let _ = stdin_task.await;

        let exit = outcome
            .ok_or_else(|| ClientError::Protocol("exec stream ended without ExecExit".into()))?;
        Ok(ExecResult {
            exec_id: started_msg.exec_id,
            stdout,
            stderr,
            exit_code: exit.exit_code,
            signal: exit.signal,
            timed_out: exit.timed_out,
            duration: started.elapsed(),
        })
    }

    // ------------------------------------------------------------------
    // session.* value ops (M2 Step 3): one request, one typed response.
    // ------------------------------------------------------------------

    /// Send one `session.*` control request and return the raw response
    /// body, mapping a wire `Error` to [`ClientError::Remote`]. Requires the
    /// negotiated `session` capability.
    async fn session_request(
        &mut self,
        body: control_message::Body,
    ) -> Result<response::Body, ClientError> {
        if !self.has_capability(wire::CAP_SESSION) {
            return Err(ClientError::Unsupported(
                "peer does not support sessions".into(),
            ));
        }
        let resp = self.request(body).await?;
        match resp.body {
            Some(response::Body::Error(e)) => Err(ClientError::Remote {
                code: e.error_code(),
                message: e.message,
                retryable: e.retryable,
            }),
            Some(body) => Ok(body),
            None => Err(ClientError::Protocol("empty response body".into())),
        }
    }

    /// `session.open`: create a session on the peer. The returned ticket
    /// authorizes one `SESSION_DATA` stream (attach pump — M2 Step 5).
    pub async fn session_open(
        &mut self,
        req: wire::SessionOpen,
    ) -> Result<wire::SessionOpened, ClientError> {
        match self
            .session_request(control_message::Body::SessionOpen(req))
            .await?
        {
            response::Body::SessionOpened(o) => Ok(o),
            other => Err(unexpected("SessionOpen", &other)),
        }
    }

    /// `session.list`: every session the peer will show us.
    pub async fn session_list(&mut self) -> Result<Vec<wire::SessionInfo>, ClientError> {
        match self
            .session_request(control_message::Body::SessionList(wire::SessionList {}))
            .await?
        {
            response::Body::SessionListResult(r) => Ok(r.sessions),
            other => Err(unexpected("SessionList", &other)),
        }
    }

    /// `session.get`: one session's snapshot.
    pub async fn session_get(
        &mut self,
        session_id: &str,
    ) -> Result<wire::SessionInfo, ClientError> {
        match self
            .session_request(control_message::Body::SessionGet(wire::SessionGet {
                session_id: session_id.to_string(),
            }))
            .await?
        {
            response::Body::SessionInfo(i) => Ok(i),
            other => Err(unexpected("SessionGet", &other)),
        }
    }

    /// `session.read`: one cursor pull (`after`/`ctl_after`, bounded by
    /// `max_bytes`, long-polling up to `wait_ms`). The whole result is
    /// returned so the caller can feed `next_after`/`next_ctl_after` back
    /// as the next cursor.
    pub async fn session_read(
        &mut self,
        req: wire::SessionRead,
    ) -> Result<wire::SessionReadResult, ClientError> {
        match self
            .session_request(control_message::Body::SessionRead(req))
            .await?
        {
            response::Body::SessionReadResult(r) => {
                // Receiver-side chunk check (protocol.md §9): a host not
                // running our encoder is bounded only by the frame cap.
                r.validate()
                    .map_err(|e| ClientError::Protocol(format!("SessionReadResult: {e}")))?;
                Ok(r)
            }
            other => Err(unexpected("SessionRead", &other)),
        }
    }

    /// `session.write`: one chunk (≤ [`wire::SESSION_CHUNK_MAX`]) of input.
    pub async fn session_write(
        &mut self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<u64, ClientError> {
        match self
            .session_request(control_message::Body::SessionWrite(wire::SessionWrite {
                session_id: session_id.to_string(),
                data,
            }))
            .await?
        {
            response::Body::SessionWritten(w) => Ok(w.bytes_written),
            other => Err(unexpected("SessionWrite", &other)),
        }
    }

    /// `session.resize`.
    pub async fn session_resize(
        &mut self,
        session_id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<(u16, u16), ClientError> {
        match self
            .session_request(control_message::Body::SessionResize(wire::SessionResize {
                session_id: session_id.to_string(),
                cols: u32::from(cols),
                rows: u32::from(rows),
            }))
            .await?
        {
            response::Body::SessionResized(r) => Ok((
                u16::try_from(r.cols).unwrap_or(u16::MAX),
                u16::try_from(r.rows).unwrap_or(u16::MAX),
            )),
            other => Err(unexpected("SessionResize", &other)),
        }
    }

    /// `session.close`; returns the final sequence.
    pub async fn session_close(
        &mut self,
        session_id: &str,
        signal: Option<String>,
    ) -> Result<u64, ClientError> {
        match self
            .session_request(control_message::Body::SessionClose(wire::SessionClose {
                session_id: session_id.to_string(),
                signal,
            }))
            .await?
        {
            response::Body::SessionClosed(c) => Ok(c.final_seq),
            other => Err(unexpected("SessionClose", &other)),
        }
    }

    // ------------------------------------------------------------------
    // `-R` remote forward control messages (M4 Step 4). Neither carries a
    // capability gate — like a local forward's ticket-less `TCP_CONNECT`,
    // these are authorized on the peer at the choke point
    // (`crate::server::Server::authorize_and_bind_remote_forward`), not
    // negotiated as a peer feature (`crate::acl::Action::ForwardRemote`'s
    // own doc). [`Self::request`] rather than [`Self::session_request`]
    // for exactly that reason: the latter's `CAP_SESSION` gate does not
    // apply here.
    // ------------------------------------------------------------------

    /// `RemoteForwardOpen`: ask the peer to bind `req.bind_host:req.
    /// bind_port` and forward each connection it accepts back to us as a
    /// `TCP_ACCEPTED` stream. The peer's own loopback-only enforcement and
    /// `forward.remote` ACL check both happen before it ever replies —
    /// success here means a listener already exists on the peer.
    pub async fn rfwd_open(
        &mut self,
        req: wire::RemoteForwardOpen,
    ) -> Result<wire::RemoteForwardOpened, ClientError> {
        let resp = self.request(control_message::Body::RfwdOpen(req)).await?;
        match resp.body {
            // The `forward_id` is host-minted but peer-supplied *to us*,
            // and from here it becomes this side's dispatch-table key and
            // the `Tunnel` DTO's `tunnel_id` (`crate::ops::tunnel::
            // remote_tunnel_dto`). It is held to the shape `v1.proto`
            // states for it (`wire::valid_forward_id`) at this ingress, so
            // a peer cannot seat an unusable — or terminal-hostile — id in
            // either place. Rejecting here also keeps the requester's own
            // `TCP_ACCEPTED` ticket check (`crate::tunnel::remote::
            // handle_accepted_stream`) from being the first thing to
            // notice, which would show up as a forward that silently never
            // carries a connection.
            Some(response::Body::RfwdOpened(opened))
                if wire::valid_forward_id(&opened.forward_id) =>
            {
                Ok(opened)
            }
            Some(response::Body::RfwdOpened(_)) => Err(ClientError::Protocol(
                "RemoteForwardOpened carried a malformed forward_id".into(),
            )),
            Some(response::Body::Error(e)) => Err(ClientError::Remote {
                code: e.error_code(),
                message: e.message,
                retryable: e.retryable,
            }),
            Some(other) => Err(unexpected("RemoteForwardOpen", &other)),
            None => Err(ClientError::Protocol(
                "empty response to RemoteForwardOpen".into(),
            )),
        }
    }

    /// `RemoteForwardClose`: ask the peer to close the listener it opened
    /// for `req.forward_id` and tear down every connection it is
    /// currently serving. Bare success carries no payload
    /// (`v1.proto`'s own comment on the message) — a `None` response body
    /// is the success case, not a protocol error.
    pub async fn rfwd_close(&mut self, req: wire::RemoteForwardClose) -> Result<(), ClientError> {
        let resp = self.request(control_message::Body::RfwdClose(req)).await?;
        match resp.body {
            None => Ok(()),
            Some(response::Body::Error(e)) => Err(ClientError::Remote {
                code: e.error_code(),
                message: e.message,
                retryable: e.retryable,
            }),
            Some(other) => Err(unexpected("RemoteForwardClose", &other)),
        }
    }

    /// `session.attach` (stream op): authorize the attach, then open the
    /// `SESSION_DATA` stream and redeem the ticket on it. The returned
    /// [`Attached`] is the live stream; the control stream stays with this
    /// [`Session`], so the caller drives both.
    ///
    /// A non-empty `req.resume_token` makes this a **resume** across
    /// connections (protocol.md §10): the host checks the credential and
    /// the bound peer identity before its ACL call, and answers with a
    /// successor token the caller must persist before using the stream.
    pub async fn attach(&mut self, req: wire::SessionAttach) -> Result<Attached, ClientError> {
        let attached = self.attach_request(req).await?;
        self.open_attach_stream(attached).await
    }

    /// The control half of an attach: authorize it and get the ticket and
    /// the successor credential, **without** opening the data stream yet.
    ///
    /// Split out from [`Session::attach`] because the successor token has
    /// to be made durable before the stream is used (ADR-0007). It is
    /// single-generation: the presented token died on the host the moment
    /// this returned, so a successor lost between here and the first byte
    /// is a session nobody can ever attach to again.
    pub async fn attach_request(
        &mut self,
        req: wire::SessionAttach,
    ) -> Result<wire::SessionAttached, ClientError> {
        match self
            .session_request(control_message::Body::SessionAttach(req))
            .await?
        {
            response::Body::SessionAttached(a) => Ok(a),
            other => Err(unexpected("SessionAttach", &other)),
        }
    }

    /// The data half: redeem `attached`'s ticket on a fresh
    /// `SESSION_DATA` link (`PLAN.md` M3 Step 7: a QUIC stream on the
    /// forward route, a `LOCAL_STREAM` conduit on the reverse route —
    /// `Self::open_data_link`).
    pub async fn open_attach_stream(
        &mut self,
        attached: wire::SessionAttached,
    ) -> Result<Attached, ClientError> {
        let (send, recv, kill) = self
            .open_data_link(
                &StreamHeader::session_data(attached.ticket.clone()),
                wire::PRIORITY_SESSION_DATA,
            )
            .await?;
        Ok(Attached {
            replay_from: attached.replay_from,
            writer_lease: attached.writer_lease,
            expires_at: attached.expires_at,
            new_resume_token: attached.new_resume_token,
            input_from: attached.input_seq,
            kill,
            writer: AttachWriter {
                send,
                // Continue the host's axis, not a private one: this is what
                // makes a reattach's retransmission line up with the
                // session's dedup cursor (protocol.md §10-5).
                input_seq: attached.input_seq,
            },
            reader: AttachReader { recv },
        })
    }

    /// Read the next unsolicited control message — the asynchronous
    /// `SessionEvent`s an attached peer is owed (protocol.md §9). Pings are
    /// answered on the way; correlated responses are skipped.
    ///
    /// **Not cancel-safe**: answering a peer `Ping` writes, and losing a
    /// `select!` race mid-write leaves half a frame on the wire. A caller
    /// that must race this against anything else uses
    /// [`next_control`](Self::next_control), which only reads.
    pub async fn next_event(&mut self) -> Result<Option<wire::SessionEvent>, ClientError> {
        loop {
            match self.next_control().await? {
                None => return Ok(None),
                Some(ControlIn::Event(ev)) => return Ok(Some(ev)),
                Some(ControlIn::Ping { request_id }) => self.send_pong(request_id).await?,
                Some(ControlIn::Pong) => {}
                // See `ControlIn::Request`'s docs: unreachable on a
                // forward attach in practice, but answered rather than
                // dropped.
                Some(ControlIn::Request { request_id }) => {
                    self.reject_unsupported(request_id).await?
                }
            }
        }
    }

    /// Read the next inbound control message that is not a correlated
    /// response, **without writing anything**.
    ///
    /// This is [`next_event`](Self::next_event) with the reply to a peer
    /// `Ping` handed back to the caller instead of sent inline, which is
    /// what makes it cancel-safe: the only await is a framed read, whose
    /// partial state lives in the decoder rather than on the stack. A
    /// caller that races it in a `select!` — the attach's control pump,
    /// which must also be able to send a liveness probe — can drop the
    /// future at any poll and lose nothing.
    pub async fn next_control(&mut self) -> Result<Option<ControlIn>, ClientError> {
        loop {
            let Some(msg) = self.link.recv().await? else {
                return Ok(None);
            };
            return Ok(Some(match msg.body {
                Some(control_message::Body::SessionEvent(ev)) => ControlIn::Event(ev),
                Some(control_message::Body::Ping(_)) => ControlIn::Ping {
                    request_id: msg.request_id,
                },
                Some(control_message::Body::Pong(_)) => ControlIn::Pong,
                // A response to a request nobody here is waiting for
                // (`request()` reads its own correlated reply directly, not
                // through this loop): ignore, not a request needing an
                // answer.
                Some(control_message::Body::Response(_)) => continue,
                // Everything else the oneof can carry is request-shaped —
                // `Hello` (unexpected after the handshake), every
                // `session_*`/`exec_start` request, or an unknown/reserved
                // control number decoding to `body: None` — and this
                // client role serves none of it (see `ControlIn::Request`).
                _ => ControlIn::Request {
                    request_id: msg.request_id,
                },
            }));
        }
    }

    /// Answer a peer `Ping`.
    pub async fn send_pong(&mut self, request_id: u64) -> Result<(), ClientError> {
        self.link
            .send(&ControlMessage::new(
                request_id,
                control_message::Body::Pong(wire::Pong {}),
            ))
            .await
    }

    /// Answer an inbound [`ControlIn::Request`] with `UNSUPPORTED` —
    /// creates no resource, same as every other refusal at this seam
    /// (`docs/design/protocol.md` §11-3). The forward client never has one
    /// to answer in practice; `qsh listen` (`PLAN.md` M3 Step 3) is the
    /// first real caller.
    pub async fn reject_unsupported(&mut self, request_id: u64) -> Result<(), ClientError> {
        self.link
            .send(&ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "this connection's client role does not serve requests",
                    false,
                ),
            ))
            .await
    }

    /// Send a liveness `Ping`; the peer answers with a `Pong` that arrives
    /// as [`ControlIn::Pong`].
    ///
    /// The reply is deliberately **not** awaited here. A probe that blocked
    /// on its own answer could not be issued from the same task that reads
    /// them, and the thing being measured is whether *anything* comes back
    /// at all — a `Pong`, a `SessionEvent`, a session output frame — not
    /// the correlation of one particular request.
    pub async fn send_ping(&mut self) -> Result<(), ClientError> {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.link
            .send(&ControlMessage::new(
                request_id,
                control_message::Body::Ping(wire::Ping {}),
            ))
            .await
    }

    /// Finish the control link and close the underlying connection, if
    /// this session has one (see [`Self`]'s own doc on `conn`).
    pub fn close(mut self) {
        self.link.finish();
        if let Some(conn) = self.conn.take() {
            conn.close(0, b"done");
        }
    }

    // ------------------------------------------------------------------
    // Raw control-message I/O (M3 Step 6): the reverse controller's
    // `LOCAL_CONTROL` relay (`crate::reverse::listen`, `crate::localctl`)
    // needs to forward an already-built `ControlMessage` verbatim under an
    // id *it* chooses (the multiplexer's `daemon_request_id`,
    // `docs/design/protocol.md` §11-3's "request_id 재매핑"), and needs to
    // see every inbound frame — including a correlated `Response`, which
    // [`Self::request`]/[`Self::next_control`] both consume internally
    // (the former to resolve its own call, the latter by design: its doc
    // comment notes `request()` owns response correlation). Neither
    // existing pair fits a caller that must multiplex many *concurrent*
    // logical requests over this one physical control stream while also
    // never dropping an interleaved `SessionEvent` — so these two methods
    // are additive raw primitives, not replacements: every existing
    // caller of `request`/`next_control`/`next_event` is unchanged and
    // must keep being the *only* reader/writer of a `Session` it uses that
    // way (this pair is for a caller — today, only the reverse
    // controller's per-host driver — that instead becomes the *sole*
    // reader/writer for its `Session` and does its own classification of
    // every inbound frame, `Response` included).
    //
    /// Send an already-built `ControlMessage` verbatim, bypassing this
    /// `Session`'s own internal id counter entirely (that counter is
    /// otherwise only advanced by `Self::request`/[`Self::send_ping`],
    /// whose replies this caller is not using — see this section's docs).
    pub async fn send_control_message(&mut self, msg: &ControlMessage) -> Result<(), ClientError> {
        self.link.send(msg).await
    }

    /// Read the next inbound `ControlMessage` whole — `request_id` and
    /// `body` both, `Response` included — with **no** classification and
    /// **no** answer written on the caller's behalf (not even a peer
    /// `Ping`, unlike [`Self::next_event`]): the caller (see this
    /// section's docs) decides everything, including liveness replies,
    /// itself. `Ok(None)` on a clean end-of-stream, matching
    /// [`Self::next_control`]'s own contract.
    pub async fn next_control_message(&mut self) -> Result<Option<ControlMessage>, ClientError> {
        self.link.recv().await
    }
}

/// One inbound control message that is not a correlated response
/// (`docs/design/protocol.md` §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlIn {
    /// An asynchronous session event (`writer_changed`, `closed`, …).
    Event(wire::SessionEvent),
    /// The peer is asking whether we are alive. Answer with
    /// [`Session::send_pong`], carrying this id back.
    Ping {
        /// Correlation id to echo in the `Pong`.
        request_id: u64,
    },
    /// The peer answered a [`Session::send_ping`].
    Pong,
    /// An inbound REQUEST-shaped frame this client role does not serve: a
    /// `session.*`/`exec.run` request, a stray `Hello`, or an unknown/
    /// reserved control number (`body: None`) — everything the wire oneof
    /// can carry other than `Event`/`Ping`/`Pong`/a correlated `Response`.
    /// Answer with [`Session::reject_unsupported`], which creates no
    /// resource either way.
    ///
    /// Before M3 this variant was unreachable — a plain forward `qsh
    /// <host>`/`qsh exec` peer (the host) never sends a request back to
    /// its client. `qsh listen` (`PLAN.md` Step 3) is the first real
    /// producer: on a registered reverse connection the *controller* is
    /// the client role, and the peer (the target, now a host) can still
    /// legally attempt a request — `docs/design/protocol.md` §11-3:
    /// registration grants reachability, never authority, so it must be
    /// representable here instead of silently dropped.
    Request {
        /// Correlation id to answer with [`Session::reject_unsupported`].
        request_id: u64,
    },
}

/// Assembled result of a remote exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// Peer-assigned exec id.
    pub exec_id: String,
    /// Remote stdout bytes.
    pub stdout: Vec<u8>,
    /// Remote stderr bytes.
    pub stderr: Vec<u8>,
    /// Remote exit code (`128 + signo` if signaled).
    pub exit_code: i32,
    /// Terminating signal name, if any.
    pub signal: Option<String>,
    /// The host killed the command because the requested timeout elapsed.
    pub timed_out: bool,
    /// Wall-clock time from request to exit.
    pub duration: Duration,
}

/// A live `SESSION_DATA` stream (`docs/design/protocol.md` §9). Output,
/// gaps, input acks and the final exit arrive as [`AttachEvent`]s; input
/// and resizes go the other way.
pub struct Attached {
    /// Offset the host replays from (unless a `Gap` corrects it).
    pub replay_from: u64,
    /// Whether this attach holds the writer lease.
    pub writer_lease: bool,
    /// When the session's resume window ends (RFC 3339).
    pub expires_at: String,
    /// The successor resume credential (protocol.md §10 "Rotation"), empty
    /// when this attach presented no token. The caller must persist it
    /// **durably before using the stream**: it is single-generation, so
    /// losing it orphans the session (ADR-0007).
    pub new_resume_token: Vec<u8>,
    /// Cumulative input offset this attach continues from
    /// (`SessionAttached.input_seq`). A resumed attach gets back the offset
    /// the host applied on the stream it left, so its un-acked tail can be
    /// retransmitted without the child seeing a byte twice.
    pub input_from: u64,
    /// A synchronous, any-thread hard-stop for this attach's data link —
    /// live only on the reverse route, a no-op otherwise
    /// (`link::DataKillSwitch`'s own doc). `crate::ops::session`'s
    /// `RecoveryLink` is built from this right after `open_attach_stream`
    /// returns, before [`Self::split`] hands the writer/reader off to the
    /// attach driver.
    pub(crate) kill: DataKillSwitch,
    writer: AttachWriter,
    reader: AttachReader,
}

/// One host → client event on an attach stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachEvent {
    /// Session output ending at cumulative offset `sequence`.
    Output {
        /// Cumulative output offset after `data`.
        sequence: u64,
        /// The bytes.
        data: Vec<u8>,
    },
    /// The requested offset was evicted; the stream resumes at
    /// `available_from`.
    Gap {
        /// The offset that was asked for.
        requested_after: u64,
        /// Where the following output starts.
        available_from: u64,
    },
    /// The host has applied every input byte up to `acked_input_seq`.
    InputAck {
        /// Cumulative input offset the host has applied.
        acked_input_seq: u64,
    },
    /// The child exited; the last frame of the stream.
    Exit {
        /// Final cumulative output offset.
        final_seq: u64,
        /// Exit code (`-1` when signaled).
        exit_code: i32,
        /// Terminating signal name, if any.
        signal: Option<String>,
    },
}

impl Attached {
    /// Read the next event. `Ok(None)` when the host finished the stream.
    pub async fn next(&mut self) -> Result<Option<AttachEvent>, ClientError> {
        self.reader.next().await
    }

    /// Send input, splitting at [`wire::SESSION_CHUNK_MAX`]. Returns the
    /// cumulative input offset after this call — what a later
    /// [`AttachEvent::InputAck`] is compared against.
    pub async fn send_input(&mut self, data: &[u8]) -> Result<u64, ClientError> {
        self.writer.send_input(data).await
    }

    /// Cumulative input offset sent so far.
    pub fn input_seq(&self) -> u64 {
        self.writer.input_seq()
    }

    /// Tell the host the terminal window changed.
    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ClientError> {
        self.writer.resize(cols, rows).await
    }

    /// Split into halves so input and output can be driven concurrently
    /// (what the M2 Step 6 TUI needs).
    pub fn split(self) -> (AttachWriter, AttachReader) {
        (self.writer, self.reader)
    }

    /// Finish our send half; the host drains what is left and exits.
    pub fn finish(self) {
        self.writer.finish();
    }
}

/// Client → host half of an attach stream.
pub struct AttachWriter {
    send: DataSend,
    input_seq: u64,
}

impl AttachWriter {
    /// See [`Attached::send_input`].
    pub async fn send_input(&mut self, data: &[u8]) -> Result<u64, ClientError> {
        for chunk in data.chunks(wire::SESSION_CHUNK_MAX) {
            self.input_seq += chunk.len() as u64;
            self.send
                .send(&SessionFrame::input(self.input_seq, chunk.to_vec()))
                .await?;
        }
        Ok(self.input_seq)
    }

    /// See [`Attached::resize`].
    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ClientError> {
        self.send
            .send(&SessionFrame::resize(u32::from(cols), u32::from(rows)))
            .await?;
        Ok(())
    }

    /// Cumulative input offset sent so far.
    pub fn input_seq(&self) -> u64 {
        self.input_seq
    }

    /// Finish our send half.
    ///
    /// Only queues the FIN. It says nothing about the bytes ahead of it
    /// having been delivered, let alone applied — a caller that closes the
    /// connection next has to establish that for itself, which on this
    /// stream is what [`AttachEvent::InputAck`] is for.
    pub fn finish(mut self) {
        self.send.finish();
    }
}

/// Host → client half of an attach stream.
pub struct AttachReader {
    recv: DataRecv,
}

impl AttachReader {
    /// See [`Attached::next`].
    pub async fn next(&mut self) -> Result<Option<AttachEvent>, ClientError> {
        loop {
            let Some(frame) = self.recv.recv::<SessionFrame>().await? else {
                return Ok(None);
            };
            // Receiver-side chunk check (protocol.md §9): a host not
            // running our encoder is bounded only by the frame cap.
            frame
                .validate()
                .map_err(|e| ClientError::Protocol(format!("SessionFrame: {e}")))?;
            return Ok(Some(match frame.body {
                Some(session_frame::Body::Output(o)) => AttachEvent::Output {
                    sequence: o.sequence,
                    data: o.data,
                },
                Some(session_frame::Body::Gap(g)) => AttachEvent::Gap {
                    requested_after: g.requested_after,
                    available_from: g.available_from,
                },
                Some(session_frame::Body::InputAck(a)) => AttachEvent::InputAck {
                    acked_input_seq: a.acked_input_seq,
                },
                Some(session_frame::Body::Exit(x)) => AttachEvent::Exit {
                    final_seq: x.final_seq,
                    exit_code: x.exit_code,
                    signal: x.signal,
                },
                // Client → host frames coming back from a host are a slip;
                // skip them rather than failing the stream.
                Some(_) | None => continue,
            }));
        }
    }
}

fn unexpected(request: &str, body: &response::Body) -> ClientError {
    ClientError::Protocol(format!(
        "unexpected response to {request}: {}",
        response_kind(body)
    ))
}

/// The variant name of a response body (never its payload).
fn response_kind(body: &response::Body) -> &'static str {
    match body {
        response::Body::Error(_) => "Error",
        response::Body::ExecStarted(_) => "ExecStarted",
        response::Body::SessionOpened(_) => "SessionOpened",
        response::Body::SessionAttached(_) => "SessionAttached",
        response::Body::SessionReadResult(_) => "SessionReadResult",
        response::Body::SessionListResult(_) => "SessionListResult",
        response::Body::SessionInfo(_) => "SessionInfo",
        response::Body::SessionWritten(_) => "SessionWritten",
        response::Body::SessionResized(_) => "SessionResized",
        response::Body::SessionClosed(_) => "SessionClosed",
        response::Body::RfwdOpened(_) => "RemoteForwardOpened",
    }
}

/// [`crate::localctl::client::open_stream`]'s error, mapped for
/// [`Session::open_local_data_link`] — verbatim
/// ([`link::op_error_to_client_error`]) for every case but one: a
/// pre-issue-#5 `qsh listen` daemon still rejects an `EXEC_DATA`
/// `StreamHeader` with a bare `InvalidArgument` (`local_stream_relay_kind`
/// did not exist yet on that build, so `serve_stream`'s old three-way
/// match refused the fourth kind), and that generic "first frame must
/// be..." text does not tell an operator what actually predates what.
/// Since a *current* daemon never answers `InvalidArgument` to a
/// well-formed `EXEC_DATA` header — [`local_stream_relay_kind`]
/// (`crate::localctl::daemon`) accepts it unconditionally — seeing this
/// pair (`ExecData` header, `InvalidArgument` reply) is diagnostic on its
/// own: this machine's resident `qsh listen` predates reverse exec
/// support. The code is left exactly as the daemon sent it (still a
/// protocol-shape rejection, not reclassified as `Unsupported`); only the
/// message names the cause and the fix (`exec_data_rejected_by_an_old_daemon_names_the_stale_qsh_listen`
/// below, `docs/CLI.md` §6.13's reverse-relay list).
#[cfg(unix)]
fn map_local_stream_open_error(err: OpError, header: &StreamHeader, host: &str) -> ClientError {
    if err.code == ErrorCode::InvalidArgument
        && header.stream_kind() == Some(wire::StreamKind::ExecData)
    {
        return ClientError::Remote {
            code: err.code,
            message: format!(
                "this machine's `qsh listen` daemon (relaying to {host}) rejected an EXEC_DATA \
                 data stream: it predates reverse exec support — restart or upgrade it and \
                 retry. (daemon said: {})",
                err.message
            ),
            retryable: err.retryable,
        };
    }
    link::op_error_to_client_error(err)
}

/// Pump the client's stdin onto `send` as `ExecFrame::Stdin` chunks, always
/// ending with a `StdinEof` frame — on both carriers alike, and always
/// sent, even when `stdin` is `None` (an immediate EOF). This is the one
/// and only stdin-end signal the wire protocol has: nothing on the normal
/// path ever half-closes `send` itself (finishes or resets it) to mean the
/// same thing — the reverse route's `EXEC_DATA` UDS-EOF→reset rule
/// (`crate::localctl::daemon`'s `local_stream_relay_kind`) depends on that
/// staying true, since a clean stream end there is read as "the peer is
/// gone", not "stdin ended" (a command that outlives this pump — reading
/// past its own stdin EOF — must still see its output through to
/// `ExecExit`, never be killed by this pump's own completion).
async fn pump_stdin(
    stdin: Option<Box<dyn AsyncRead + Send + Unpin>>,
    send: &mut DataSend,
) -> Result<(), ClientError> {
    if let Some(mut stdin) = stdin {
        let mut buf = vec![0u8; wire::EXEC_CHUNK_MAX];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => send.send(&ExecFrame::stdin(buf[..n].to_vec())).await?,
            }
        }
    }
    send.send(&ExecFrame::stdin_eof()).await
}

// `Session::from_local_control`/`open_local_data_link` are unix-only
// (`crate::localctl` is a `#[cfg(unix)]` module — `lib.rs`), so the whole
// module is rather than gating each test individually.
#[cfg(all(test, unix))]
mod reverse_tests {
    use qsh_proto::local::{
        LocalHello, LocalHelloAck, LocalResponse, LocalStreamKind, local_response,
    };
    use tokio::net::UnixListener;

    use super::*;
    use crate::localctl::frame::LocalConduit;

    /// A `from_local_control` [`Session`]'s [`Session::open_attach_stream`]
    /// dials a **fresh** `LOCAL_STREAM` conduit to the exact same daemon
    /// socket and host its `LOCAL_CONTROL` handshake came from
    /// (`Self::local`'s own doc) — proven end to end against a fake daemon
    /// that serves both conduit kinds, one after the other, on the same
    /// socket path.
    #[tokio::test]
    async fn open_attach_stream_on_a_reverse_session_reaches_the_same_daemon_socket_and_host() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("reverse-attach.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let daemon = tokio::spawn(async move {
            // First conduit: LOCAL_CONTROL, exactly what
            // `dial_reverse`/`open_control` produce.
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut control = LocalConduit::new(stream);
            let hello: LocalHello = control.recv().await.unwrap().unwrap();
            assert_eq!(hello.kind, LocalStreamKind::LocalControl as i32);
            assert_eq!(hello.host, "phone");
            control
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();

            // Second conduit, same socket path: LOCAL_STREAM, opened by
            // `open_attach_stream` — proves it is a fresh conduit to the
            // *same* daemon/host rather than reusing the control conduit
            // or dialing somewhere else.
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut data = LocalConduit::new(stream);
            let hello: LocalHello = data.recv().await.unwrap().unwrap();
            assert_eq!(hello.kind, LocalStreamKind::LocalStream as i32);
            assert_eq!(hello.host, "phone");
            data.send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();
            let header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
            assert_eq!(header.stream_kind(), Some(wire::StreamKind::SessionData));
            header.ticket
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let mut session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            sock.clone(),
            handshake.peer_fingerprint,
            handshake.generation,
        );

        let attached = session
            .open_attach_stream(wire::SessionAttached {
                ticket: vec![7, 7, 7],
                new_resume_token: Vec::new(),
                replay_from: 0,
                writer_lease: true,
                expires_at: String::new(),
                input_seq: 0,
            })
            .await
            .unwrap();
        // A live `LOCAL_STREAM` conduit, not the forward route's
        // synchronous no-op — `DataKillSwitch::kill`'s own doc.
        attached.kill.kill();

        let seen_ticket = daemon.await.unwrap();
        assert_eq!(seen_ticket, vec![7, 7, 7]);
    }

    fn exec_spec() -> ExecSpec {
        ExecSpec {
            argv: vec!["true".to_string()],
            env: Vec::new(),
            timeout: None,
        }
    }

    /// Issue #5's own regression: a `from_local_control` `Session`
    /// (the reverse route) opens `exec`'s `EXEC_DATA` stream on the *same*
    /// daemon socket and host its `LOCAL_CONTROL` handshake came from —
    /// [`Session::exec`]'s counterpart to
    /// [`open_attach_stream_on_a_reverse_session_reaches_the_same_daemon_socket_and_host`]
    /// above, proving `EXEC_DATA` now goes through the same generalized
    /// [`Session::open_data_link`] `SESSION_DATA` already used, rather than
    /// [`Session::exec`]'s old `require_connection()`-guarded QUIC-only
    /// path (which failed every reverse-linked `Session` with
    /// `ClientError::Unsupported` before issue #5's daemon `EXEC_DATA`
    /// relay, `crate::localctl::daemon::local_stream_relay_kind`).
    #[tokio::test]
    async fn open_data_link_for_exec_data_on_a_reverse_session_opens_its_stream_on_the_same_daemon_socket_and_host()
     {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("reverse-exec.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let daemon = tokio::spawn(async move {
            // First conduit: LOCAL_CONTROL, exactly what
            // `dial_reverse`/`open_control` produce.
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut control = LocalConduit::new(stream);
            let hello: LocalHello = control.recv().await.unwrap().unwrap();
            assert_eq!(hello.kind, LocalStreamKind::LocalControl as i32);
            assert_eq!(hello.host, "phone");
            control
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                            .to_string(),
                        generation: 1,
                        capabilities: vec![wire::CAP_EXEC.to_string()],
                    })),
                })
                .await
                .unwrap();

            // The control phase of `exec`: an `ExecStart` request over the
            // same conduit, answered with an `ExecStarted` ticket — exactly
            // what `crate::localctl::mux::classify`'s own
            // `MessageKind::Request` already relayed before issue #5, which
            // changes nothing about this control leg (only `EXEC_DATA`'s
            // data leg below is new).
            let req: ControlMessage = control.recv().await.unwrap().unwrap();
            let request_id = req.request_id;
            assert!(matches!(
                req.body,
                Some(control_message::Body::ExecStart(_))
            ));
            control
                .send(&ControlMessage::new(
                    request_id,
                    control_message::Body::Response(wire::Response {
                        body: Some(response::Body::ExecStarted(ExecStarted {
                            exec_id: "e1".to_string(),
                            ticket: vec![9, 9, 9],
                        })),
                    }),
                ))
                .await
                .unwrap();

            // Second conduit, same socket: LOCAL_STREAM carrying an
            // EXEC_DATA header — proves a fresh conduit to the *same*
            // daemon/host, not the control conduit reused or a QUIC
            // `open_bi()` this `Session` has no connection to make.
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut data = LocalConduit::new(stream);
            let hello: LocalHello = data.recv().await.unwrap().unwrap();
            assert_eq!(hello.kind, LocalStreamKind::LocalStream as i32);
            assert_eq!(hello.host, "phone");
            data.send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();
            let header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
            assert_eq!(header.stream_kind(), Some(wire::StreamKind::ExecData));
            // `EXEC_DATA` gets an explicit ack before the splice
            // (`daemon::LocalStreamRelay::OpenBidiAndSplice`'s
            // `ack_before_splice` doc) — unlike `SESSION_DATA`, which stays
            // silent on success.
            data.send(&LocalResponse {
                body: Some(local_response::Body::ClaimGranted(
                    qsh_proto::local::LocalClaimGranted {},
                )),
            })
            .await
            .unwrap();
            header.ticket
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let mut session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            sock.clone(),
            handshake.peer_fingerprint,
            handshake.generation,
        );

        let started = session.exec_start(&exec_spec()).await.unwrap();
        assert_eq!(started.ticket, vec![9, 9, 9]);
        let (_send, _recv, kill) = session
            .open_data_link(
                &StreamHeader::exec_data(started.ticket),
                wire::PRIORITY_EXEC_DATA,
            )
            .await
            .unwrap();
        // A live `LOCAL_STREAM` conduit, not the forward route's
        // synchronous no-op — `DataKillSwitch::kill`'s own doc.
        kill.kill();

        let seen_ticket = daemon.await.unwrap();
        assert_eq!(seen_ticket, vec![9, 9, 9]);
    }

    /// The same stale-route check [`open_attach_stream`](Session::open_attach_stream)
    /// already inherits (`Session::open_local_data_link`'s own doc) applies
    /// to `exec` too, now that both go through the same
    /// [`Session::open_data_link`]: if the registration's `(peer_fingerprint,
    /// generation)` the `LOCAL_STREAM` conduit's own ack reports disagrees
    /// with what this `Session`'s `LOCAL_CONTROL` handshake recorded, the
    /// data phase fails closed with a retryable `HOST_NOT_FOUND` rather
    /// than redeeming the ticket against whatever now answers that name.
    #[tokio::test]
    async fn open_data_link_for_exec_data_on_a_reverse_session_fails_closed_when_the_registration_generation_changed()
     {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("reverse-exec-stale.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut control = LocalConduit::new(stream);
            let _hello: LocalHello = control.recv().await.unwrap().unwrap();
            control
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:2222222222222222222222222222222222222222222"
                            .to_string(),
                        generation: 1,
                        capabilities: vec![wire::CAP_EXEC.to_string()],
                    })),
                })
                .await
                .unwrap();

            let req: ControlMessage = control.recv().await.unwrap().unwrap();
            let request_id = req.request_id;
            control
                .send(&ControlMessage::new(
                    request_id,
                    control_message::Body::Response(wire::Response {
                        body: Some(response::Body::ExecStarted(ExecStarted {
                            exec_id: "e1".to_string(),
                            ticket: vec![5, 5, 5],
                        })),
                    }),
                ))
                .await
                .unwrap();

            // Second conduit, same socket and host — but its own ack
            // reports a *different* generation: the registration changed
            // (died and came back, or was superseded) between the two
            // handshakes.
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut data = LocalConduit::new(stream);
            let _hello: LocalHello = data.recv().await.unwrap().unwrap();
            data.send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:2222222222222222222222222222222222222222222"
                        .to_string(),
                    generation: 2,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();
            // `open_stream_over_inner` sends the header unconditionally
            // right after the ack, before this `Session`'s own stale-route
            // comparison ever runs (`crate::localctl::client`'s own doc) —
            // read it so this daemon task ends cleanly rather than racing
            // this connection's drop.
            let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
            // `EXEC_DATA` always gets this ack before `open_stream_over_inner`
            // returns (`ack_before_splice`'s own doc) — sent here so the
            // client's stale-route check, which runs only after that
            // handshake completes, is what actually rejects this call, not
            // an unrelated handshake timeout.
            data.send(&LocalResponse {
                body: Some(local_response::Body::ClaimGranted(
                    qsh_proto::local::LocalClaimGranted {},
                )),
            })
            .await
            .unwrap();
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let mut session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            sock.clone(),
            handshake.peer_fingerprint,
            handshake.generation,
        );

        let started = session.exec_start(&exec_spec()).await.unwrap();
        // Not `.unwrap_err()`: the `Ok` side holds `DataSend`/`DataRecv`,
        // which (like `localctl::client`'s own raw `UnixStream` halves)
        // has no `Debug` impl, so this matches instead.
        match session
            .open_data_link(
                &StreamHeader::exec_data(started.ticket),
                wire::PRIORITY_EXEC_DATA,
            )
            .await
        {
            Ok(_) => panic!("a changed registration generation must fail closed, not redeem"),
            Err(ClientError::Remote {
                code, retryable, ..
            }) => {
                assert_eq!(code, ErrorCode::HostNotFound);
                assert!(retryable, "a stale route must be retryable");
            }
            Err(other) => panic!("expected ClientError::Remote{{HostNotFound}}, got {other:?}"),
        }

        daemon.await.unwrap();
    }

    /// Issue #5's `pump_stdin` regression: a reverse `exec` whose command keeps
    /// writing output *after* the local `stdin` has already reached EOF
    /// must still succeed — `stdin` EOF has no stream-close meaning
    /// (`pump_stdin`'s own doc): it sends exactly one application-level
    /// `ExecFrame::StdinEof`, over the same `DataSend` the stdin pump task
    /// keeps alive until `exec` itself returns, never
    /// `finish()`/`shutdown()`s the underlying conduit. The fake daemon
    /// here is the adversarial case that regresses if that stopped being
    /// true: it deliberately answers the client's `Stdin`/`StdinEof`
    /// frames with more `Stdout` *after* `StdinEof`, then only later sends
    /// `ExecExit` — if anything on the client tore the conduit down (or
    /// stopped reading) once its own `StdinEof` went out, this output
    /// would never arrive and `exec` would hang or end early instead of
    /// collecting it. Right after draining `StdinEof`, the fake daemon
    /// also probes with a short-timeout read of its own: collecting the
    /// output alone would not catch a regression where `exec` finishes its
    /// `send` half but the daemon still relays `Stdout`/`ExecExit`
    /// regardless (a read half, not a write half, is what carries that
    /// output back) — the probe pins that the client's send half is still
    /// open, not just that the output arrives.
    #[tokio::test]
    async fn exec_on_a_reverse_session_still_collects_output_sent_after_stdin_eof() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("reverse-exec-after-eof.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut control = LocalConduit::new(stream);
            let _hello: LocalHello = control.recv().await.unwrap().unwrap();
            control
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:3333333333333333333333333333333333333333333"
                            .to_string(),
                        generation: 1,
                        capabilities: vec![wire::CAP_EXEC.to_string()],
                    })),
                })
                .await
                .unwrap();

            let req: ControlMessage = control.recv().await.unwrap().unwrap();
            let request_id = req.request_id;
            control
                .send(&ControlMessage::new(
                    request_id,
                    control_message::Body::Response(wire::Response {
                        body: Some(response::Body::ExecStarted(ExecStarted {
                            exec_id: "e1".to_string(),
                            ticket: vec![7, 7, 7],
                        })),
                    }),
                ))
                .await
                .unwrap();

            let (stream, _addr) = listener.accept().await.unwrap();
            let mut data = LocalConduit::new(stream);
            let _hello: LocalHello = data.recv().await.unwrap().unwrap();
            data.send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:3333333333333333333333333333333333333333333"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();
            let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
            // `EXEC_DATA`'s own ack before the splice.
            data.send(&LocalResponse {
                body: Some(local_response::Body::ClaimGranted(
                    qsh_proto::local::LocalClaimGranted {},
                )),
            })
            .await
            .unwrap();

            // Drain the client's stdin frames up through StdinEof.
            loop {
                let frame: ExecFrame = data.recv().await.unwrap().unwrap();
                if matches!(frame.body, Some(exec_frame::Body::StdinEof(_))) {
                    break;
                }
            }

            // `pump_stdin`'s own doc: `StdinEof` is the one and only
            // stdin-end signal on the wire, and nothing on the normal path
            // ever half-closes `send` itself to mean the same thing. If
            // `exec` finished/shut down its `DataSend` right after
            // `StdinEof` went out, this conduit would already be at a
            // clean end from the daemon's side — a short-timeout read here
            // would see that immediately instead of timing out with
            // nothing more incoming.
            match tokio::time::timeout(Duration::from_millis(200), data.recv::<ExecFrame>()).await {
                Err(_elapsed) => {} // still open, nothing more incoming — expected
                Ok(Ok(None)) => panic!(
                    "the client's LOCAL_STREAM send half closed right after StdinEof; \
                     pump_stdin must never half-close it on the normal path"
                ),
                Ok(Ok(Some(frame))) => panic!("unexpected extra frame from the client: {frame:?}"),
                Ok(Err(err)) => panic!("conduit error while probing for an early close: {err:?}"),
            }

            // Only now, after StdinEof, does more output arrive — the
            // exact ordering the client must not give up on.
            data.send(&ExecFrame::stdout(b"after eof".to_vec()))
                .await
                .unwrap();
            data.send(&ExecFrame::exec_exit(0, None)).await.unwrap();
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let mut session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            sock.clone(),
            handshake.peer_fingerprint,
            handshake.generation,
        );

        let stdin: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(b"hi".to_vec()));
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            session.exec(&exec_spec(), Some(stdin), None),
        )
        .await
        .expect("must not hang once StdinEof has gone out")
        .unwrap();
        assert_eq!(result.stdout, b"after eof");
        assert_eq!(result.exit_code, 0);

        daemon.await.unwrap();
    }

    /// A pre-issue-#5 `qsh listen` daemon rejects
    /// `EXEC_DATA` on `LOCAL_STREAM` with a bare `INVALID_ARGUMENT` (its
    /// `serve_stream` never heard of the kind) — the fake daemon here
    /// answers exactly that, over a real `open_stream` handshake, and the
    /// mapped [`ClientError`] must name the stale `qsh listen` daemon
    /// rather than repeat the daemon's generic shape-check text verbatim,
    /// so an operator sees the fix (restart/upgrade this machine's `qsh
    /// listen`), not just the symptom. Must not hang either way.
    #[tokio::test]
    async fn exec_data_rejected_by_an_old_daemon_names_the_stale_qsh_listen() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("reverse-exec-old-daemon.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let daemon = tokio::spawn(async move {
            // First conduit: LOCAL_CONTROL — what the test's own
            // `open_control` call below needs to build a `Session` at all.
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut control = LocalConduit::new(stream);
            let _hello: LocalHello = control.recv().await.unwrap().unwrap();
            control
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:3333333333333333333333333333333333333333333"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();

            // Second conduit: LOCAL_STREAM carrying the EXEC_DATA header —
            // this is the one an old daemon rejects.
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut data = LocalConduit::new(stream);
            let _hello: LocalHello = data.recv().await.unwrap().unwrap();
            data.send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:3333333333333333333333333333333333333333333"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();
            let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
            // The pre-issue-#5 `serve_stream`'s own literal refusal text
            // (`crate::localctl::daemon`, before `local_stream_relay_kind`
            // existed) — never inspected structurally by the mapping this
            // test pins, only by code + header kind.
            data.send(&LocalResponse {
                body: Some(local_response::Body::Error(
                    qsh_proto::local::LocalError::from_code(
                        ErrorCode::InvalidArgument,
                        "LOCAL_STREAM's first frame must be a SESSION_DATA, TCP_CONNECT, or \
                         TCP_ACCEPTED StreamHeader",
                    ),
                )),
            })
            .await
            .unwrap();
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            sock.clone(),
            handshake.peer_fingerprint,
            handshake.generation,
        );

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            session.open_data_link(
                &StreamHeader::exec_data(vec![1, 2, 3]),
                wire::PRIORITY_EXEC_DATA,
            ),
        )
        .await
        .expect("an old daemon's rejection must be answered promptly, never hang");

        match result {
            Ok(_) => panic!("an old daemon's INVALID_ARGUMENT must not be read as success"),
            Err(ClientError::Remote { code, message, .. }) => {
                assert_eq!(code, ErrorCode::InvalidArgument);
                assert!(
                    message.contains("qsh listen") && message.contains("restart"),
                    "message must name the stale `qsh listen` daemon and its fix: {message}"
                );
            }
            Err(other) => panic!("expected ClientError::Remote{{InvalidArgument}}, got {other:?}"),
        }

        daemon.await.unwrap();
    }

    /// `AttachHandle::detach` on the reverse route ends the attach's own
    /// `LOCAL_STREAM` conduit synchronously — no connection, no runtime,
    /// no cooperation from the daemon needed (`DataKillSwitch::kill`'s own
    /// doc). Killing it must be a clean, typed end of conduit on the
    /// reader's side, never a panic or a hang.
    #[tokio::test]
    async fn killing_a_reverse_attachs_data_conduit_ends_the_reader_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("reverse-kill.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut control = LocalConduit::new(stream);
            let _hello: LocalHello = control.recv().await.unwrap().unwrap();
            control
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();

            let (stream, _addr) = listener.accept().await.unwrap();
            let mut data = LocalConduit::new(stream);
            let _hello: LocalHello = data.recv().await.unwrap().unwrap();
            data.send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();
            let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
            // Never write, never close from this side — the reader on the
            // other end must unblock from `kill()` alone.
            std::future::pending::<()>().await
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let mut session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            sock.clone(),
            handshake.peer_fingerprint,
            handshake.generation,
        );
        let attached = session
            .open_attach_stream(wire::SessionAttached {
                ticket: vec![1],
                new_resume_token: Vec::new(),
                replay_from: 0,
                writer_lease: true,
                expires_at: String::new(),
                input_seq: 0,
            })
            .await
            .unwrap();
        let kill = attached.kill.clone();
        let (_writer, mut reader) = attached.split();

        kill.kill();
        let end = tokio::time::timeout(Duration::from_secs(5), reader.next())
            .await
            .expect("kill() must unblock the reader promptly, not hang");
        assert!(
            end.unwrap().is_none(),
            "a killed conduit must end cleanly, not error"
        );

        daemon.abort();
    }
}
