//! Requester side of the protocol: `Hello` negotiation over a dialed
//! connection and the client half of `exec.run` (control request → ticket
//! → `EXEC_DATA` stream → assemble stdout/stderr/exit).
//!
//! This module speaks in wire terms and typed errors; the `Ops` façade maps
//! [`ClientError`] to `OpError`/`ErrorCode` for the CLI.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use prost::Message as _;
use qsh_proto::ErrorCode;
use qsh_proto::datagram::{ChannelId, DatagramFrame, DatagramKind};
use qsh_proto::wire::{
    self, ControlMessage, ExecFrame, ExecStart, ExecStarted, Hello, SessionFrame, StreamHeader,
    control_message, exec_frame, response, session_frame,
};
use qsh_transport::{Connection, FramedStream, StreamError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::datagram::{DatagramHub, DatagramRx, channel_from};
use crate::exec::ExecSpec;
// `crate::localctl` builds on every platform, so the reverse
// (`LOCAL_CONTROL`) leg does too.
use crate::localctl::client::ControlConduit;
use crate::ops::OpError;

pub(crate) mod file;
pub mod link;
pub mod linkstatus;
pub mod pathwatch;
pub mod predict;
pub mod predict_drive;
pub mod reconnect;
pub mod render;
pub mod screen;
pub mod wake;

mod echo;
use echo::EchoFilter;
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
/// before the handshake exchange moved into `handshake.rs` (M3 plan Step 2 (2473c88)
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
/// M3 plan Step 6 (2473c88)): a CLI process relaying through its resident
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
    local: Option<(std::path::PathBuf, String)>,
    /// The `LOCAL_CONTROL` leg's own `LocalHelloAck` identity —
    /// `(peer_fingerprint, generation)` — `Some` exactly when
    /// [`Self::local`] is `Some`. Compared against the `LOCAL_STREAM`
    /// conduit's own ack in [`Self::open_local_data_link`] so a
    /// registration that died and reconnected (or was superseded)
    /// between the two handshakes is caught as a stale route rather than
    /// silently opening a data stream against a peer the control leg
    /// never actually bound to (see that method's own doc).
    local_ack: Option<(String, u64)>,
    next_request_id: u64,
    /// The `RendezvousQuery` in flight and what to hand its answer to
    /// ([`Self::learn_rendezvous`]).
    hint: Option<(u64, RendezvousSink)>,
    /// Capabilities both sides support.
    pub capabilities: Vec<String>,
    /// The peer's display name from its `Hello` (informational only —
    /// never an identity).
    pub peer_device_name: String,
}

/// Receives the fingerprints of a host's `RendezvousList` once
/// ([`Session::learn_rendezvous`]).
pub type RendezvousSink = std::sync::Arc<dyn Fn(Vec<Vec<u8>>) + Send + Sync>;

impl Session {
    /// Open the control stream and exchange `Hello` on a fresh connection.
    pub async fn negotiate(conn: Connection, device_name: &str) -> Result<Self, ClientError> {
        Self::negotiate_hiding(conn, device_name, &[]).await
    }

    /// [`Session::negotiate`] as a client that predates the capabilities in
    /// `hide`: they are left out of its `Hello` and out of the negotiated
    /// set. For the old-peer combination tests (ADR-0052 decision 18-4);
    /// production passes none.
    pub async fn negotiate_hiding(
        conn: Connection,
        device_name: &str,
        hide: &[&str],
    ) -> Result<Self, ClientError> {
        let local_hello = Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: device_name.to_string(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .filter(|c| !hide.contains(c))
                .map(|s| s.to_string())
                .collect(),
            reverse: None,
        };
        let (ctl, peer_hello) = crate::handshake::initiate(&conn, local_hello)
            .await
            .map_err(map_hello_error)?;
        let mut session = Self::from_control(conn, ctl, peer_hello);
        session.capabilities.retain(|c| !hide.contains(&c.as_str()));
        Ok(session)
    }

    /// Asks the host which controllers it is registered with, for the
    /// rendezvous hints (ADR-0054 decision 5). The query is written and not
    /// waited for: the answer is taken by whichever control-stream read sees
    /// it first and handed to `sink`, and a session that ends first just
    /// never learns. Sent at most once per session, and only when `punch.v1`
    /// was negotiated on a connection of our own. Every failure is silent.
    pub async fn learn_rendezvous(&mut self, sink: RendezvousSink) {
        if self.conn.is_none() || self.hint.is_some() || !self.has_capability(wire::CAP_PUNCH_V1) {
            return;
        }
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        let query = ControlMessage::new(
            request_id,
            control_message::Body::RendezvousQuery(wire::RendezvousQuery {}),
        );
        if self.link.send(&query).await.is_ok() {
            self.hint = Some((request_id, sink));
        }
    }

    /// A response nobody here waited for. If it answers the rendezvous
    /// query, hand the list over; an error answer ends the query.
    fn note_response(&mut self, request_id: u64, response: &wire::Response) {
        if self.hint.as_ref().is_none_or(|(id, _)| *id != request_id) {
            return;
        }
        let Some((_, sink)) = self.hint.take() else {
            return;
        };
        if let Some(response::Body::RendezvousList(list)) = &response.body {
            sink(list.fingerprints.clone());
        }
    }

    /// Whether both sides negotiated screen state sync (`screen.v1`). A
    /// `screen` request is sent only when this is true.
    pub fn screen_supported(&self) -> bool {
        self.has_capability(wire::CAP_SCREEN_V1)
    }

    /// Whether the peer advertised `agent.v1` (ADR-0055 decision 3). A
    /// request carries `agent_channel` only when this is true; an older host
    /// would skip the field and the client would believe forwarding is on.
    pub fn agent_supported(&self) -> bool {
        self.has_capability(wire::CAP_AGENT_V1)
    }

    /// The `ScreenRequest` to put in `SessionOpen`/`SessionAttach`, or
    /// `None` when the peer did not negotiate `screen.v1` (the sender then
    /// takes the byte path). `fg`/`bg` are 0xRRGGBB.
    pub fn screen_request(
        &self,
        cols: u16,
        rows: u16,
        fg: Option<u32>,
        bg: Option<u32>,
    ) -> Option<wire::ScreenRequest> {
        self.screen_supported().then(|| wire::ScreenRequest {
            cols: u32::from(cols),
            rows: u32::from(rows),
            fg,
            bg,
        })
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
            link: ControlLink::Direct(ctl),
            local: None,
            local_ack: None,
            next_request_id: 1,
            hint: None,
            capabilities: crate::handshake::negotiated_capabilities(&peer_hello),
            peer_device_name: peer_hello.device_name,
        }
    }

    /// Build a [`Session`] over a `LOCAL_CONTROL` conduit already past its
    /// `LocalHelloAck` (`crate::localctl::client::open_control`) — the
    /// reverse-route sibling of [`Self::from_control`]
    /// (`docs/design/protocol.md` §11-3, M3 plan Step 6 (2473c88)). There is no
    /// `Hello` exchange on this leg (the daemon already negotiated one
    /// with the peer on the CLI process's behalf), so `capabilities` and
    /// `peer_device_name` come straight from the ack instead —
    /// `LocalHelloAck.capabilities` and `.host` respectively.
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
            hint: None,
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
                DataSend::Direct(send),
                DataRecv::Direct(recv),
                DataKillSwitch::default(),
            ));
        }
        self.open_local_data_link(header).await
    }

    /// [`Self::open_data_link`]'s reverse-route branch: a fresh
    /// `LOCAL_STREAM` conduit to [`Self::local`]'s daemon socket and host
    /// (`crate::localctl::client::open_stream` sends `header` itself —
    /// see that function's own doc for why).
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
                // The answer to the rendezvous query rides in here.
                Some(control_message::Body::Response(resp)) => {
                    self.note_response(msg.request_id, &resp);
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
        self.exec_start_with_agent(spec, Vec::new()).await
    }

    /// [`Self::exec_start`] asking for agent forwarding (ADR-0055 decision
    /// 3). A peer without `agent.v1` is never sent `agent_channel`; the
    /// field is dropped and the reply's `agent` stays `UNSPECIFIED`.
    pub async fn exec_start_with_agent(
        &mut self,
        spec: &ExecSpec,
        agent_channel: Vec<u8>,
    ) -> Result<ExecStarted, ClientError> {
        let agent_channel = if self.agent_supported() {
            agent_channel
        } else {
            Vec::new()
        };
        if !self.has_capability(wire::CAP_EXEC) {
            return Err(ClientError::Unsupported(
                "peer does not support exec".into(),
            ));
        }
        // A host that predates `shell-command.v1` skips the shell fields as
        // unknown and would see an empty argv, so the request is refused
        // here, before anything is sent (`docs/design/protocol.md` §7.1).
        let (shell_command, login_shell) = match &spec.shell {
            None => (None, false),
            Some(_) if !self.has_capability(wire::CAP_SHELL_COMMAND_V1) => {
                return Err(ClientError::Unsupported(
                    crate::ops::SHELL_COMMAND_UNSUPPORTED_MESSAGE.into(),
                ));
            }
            Some(crate::shell::ShellRequest::Command(command)) => (Some(command.clone()), false),
            Some(crate::shell::ShellRequest::Login) => (None, true),
        };
        let resp = self
            .request(control_message::Body::ExecStart(ExecStart {
                argv: spec.argv.clone(),
                env: spec.env.iter().cloned().collect(),
                timeout_ms: spec
                    .timeout
                    .map_or(0, |t| t.as_millis().min(u64::MAX as u128) as u64),
                shell_command,
                login_shell,
                agent_channel,
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
        self.exec_with_agent(spec, stdin, kill_tx, Vec::new()).await
    }

    /// [`Self::exec`] asking for agent forwarding with `agent_channel`
    /// (ADR-0055 decision 3); an empty channel asks for nothing. The caller
    /// has registered the channel and is already accepting `AGENT` streams.
    pub async fn exec_with_agent(
        &mut self,
        spec: &ExecSpec,
        stdin: Option<Box<dyn AsyncRead + Send + Unpin>>,
        kill_tx: Option<tokio::sync::oneshot::Sender<DataKillSwitch>>,
        agent_channel: Vec<u8>,
    ) -> Result<ExecResult, ClientError> {
        let started = Instant::now();
        let agent_requested = !agent_channel.is_empty();
        let started_msg = self.exec_start_with_agent(spec, agent_channel).await?;
        // Both routes can carry it: the forward route's caller runs a
        // dispatcher on the connection, the reverse route's a claim loop
        // against the daemon (ADR-0055 decisions 13 and 14).
        let agent =
            crate::agent::grant_label(agent_requested, self.agent_supported(), started_msg.agent);

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
            agent,
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
        mut req: wire::SessionOpen,
    ) -> Result<wire::SessionOpened, ClientError> {
        // Never send screen fields to a peer that did not advertise
        // `screen.v1` (ADR-0052 decision 9).
        if !self.screen_supported() {
            req.screen = None;
        }
        // Same rule for the agent field (ADR-0055 decision 3).
        if !self.agent_supported() {
            req.agent_channel.clear();
        }
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
        mut req: wire::SessionAttach,
    ) -> Result<wire::SessionAttached, ClientError> {
        if !self.screen_supported() {
            req.screen = None;
        }
        if !self.agent_supported() {
            req.agent_channel.clear();
        }
        match self
            .session_request(control_message::Body::SessionAttach(req))
            .await?
        {
            response::Body::SessionAttached(a) => Ok(a),
            other => Err(unexpected("SessionAttach", &other)),
        }
    }

    /// The data half: redeem `attached`'s ticket on a fresh
    /// `SESSION_DATA` link (M3 plan Step 7 (2473c88): a QUIC stream on the
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
        // The datagram carrier (ADR-0052 decisions 6 to 9): a forward
        // connection, `datagram.v1` negotiated, and a channel id from the
        // host. The channel is registered before the first byte of the
        // stream is read, so nothing the host sends is counted unknown.
        let datagram = match (&self.conn, channel_from(&attached.screen_channel)) {
            (Some(conn), Some(channel)) if self.has_capability(wire::CAP_DATAGRAM_V1) => {
                let hub = DatagramHub::of(conn);
                let rx = hub.register(channel);
                Some((ClientDatagram { hub, channel }, rx))
            }
            _ => None,
        };
        // Input bytes this attach has sent: the bound a `ScreenEcho` is
        // checked against (ADR-0053 decision 3). Shared with the writer.
        let sent = Arc::new(AtomicU64::new(attached.input_seq));
        let echo = EchoFilter::new(
            self.has_capability(wire::CAP_SCREEN_ECHO_V1) && !attached.screen_channel.is_empty(),
            Arc::clone(&sent),
        );
        let (dg_tx, dg_rx) = match datagram {
            Some((tx, rx)) => (Some(tx), Some(rx)),
            None => (None, None),
        };
        Ok(Attached {
            replay_from: attached.replay_from,
            writer_lease: attached.writer_lease,
            expires_at: attached.expires_at,
            new_resume_token: attached.new_resume_token,
            input_from: attached.input_seq,
            output_end: attached.output_end,
            screen_channel: attached.screen_channel,
            kill,
            writer: AttachWriter {
                send,
                // Continue the host's axis, not a private one: this is what
                // makes a reattach's retransmission line up with the
                // session's dedup cursor (protocol.md §10-5).
                input_seq: attached.input_seq,
                sent,
                datagram: dg_tx,
                governor: self
                    .conn
                    .as_ref()
                    .map(crate::adapt::BulkGovernor::for_connection),
            },
            reader: AttachReader {
                recv: Some(recv),
                pending: None,
                datagram: dg_rx,
                echo,
            },
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
                Some(control_message::Body::Response(resp)) => {
                    self.note_response(msg.request_id, &resp);
                    continue;
                }
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
    /// to answer in practice; `qsh listen` (M3 plan Step 3 (2473c88)) is the
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
    /// its client. `qsh listen` (M3 plan Step 3 (2473c88)) is the first real
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
    /// The host's answer to `-A` as the JSON word (ADR-0055 decision 19);
    /// `None` when the request carried no channel.
    pub agent: Option<&'static str>,
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
    /// Cumulative output offset of the session's end when the host
    /// authorized this attach (`SessionAttached.output_end`): output below it
    /// is replay, output at or above it is live. `0` from a host that
    /// predates the field.
    pub output_end: u64,
    /// The channel id the host issued when it accepted screen sync for this
    /// attach (`screen_channel` of the reply). Non-empty means the stream
    /// carries `ScreenUpdate` and no `Output`; empty is the byte path.
    pub screen_channel: Vec<u8>,
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
    /// One part of a screen update (ADR-0052). Only on an attach whose
    /// reply carried a `screen_channel`. Feed it to
    /// [`screen::ClientScreen::on_part`].
    Screen(wire::ScreenUpdate),
    /// One part of a screen update that came as a datagram. Feed it to
    /// [`screen::ClientScreen::on_datagram_part`]. Only on an attach whose
    /// reply carried a `screen_channel` and whose connection negotiated
    /// `datagram.v1`.
    ScreenDatagram(wire::ScreenUpdate),
    /// Lines that scrolled off the host screen (ADR-0052 decision 10), on
    /// the stream only. Only on an attach whose reply carried a
    /// `screen_channel`; the attach driver draws them into the local
    /// scrollback. They are PTY content: never log them.
    ScreenHistory(wire::ScreenHistory),
    /// The host's input reflection point and tty echo state (ADR-0053
    /// decision 3). Only on a screen-sync attach whose connection negotiated
    /// `screen-echo.v1`. Already checked: `input_seq` never exceeds what this
    /// attach sent, and a signal older than one already delivered is gone, so
    /// the consumer sees `(state_num, input_seq)` move forward. Offsets and a
    /// flag, no PTY content.
    ScreenEcho(wire::ScreenEcho),
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

    /// How many `ScreenEcho`s were dropped for naming an input offset this
    /// attach never sent.
    pub fn echo_rejected(&self) -> u64 {
        self.reader.echo_rejected()
    }

    /// Tell the host the terminal window changed.
    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ClientError> {
        self.writer.resize(cols, rows).await
    }

    /// Acknowledge screen state `state_num`; 0 asks the host for the full
    /// screen. Only on a screen-sync attach. With the datagram carrier
    /// available the ack goes out on both carriers: the datagram is quick
    /// and the stream one is certain.
    pub async fn send_screen_ack(&mut self, state_num: u64) -> Result<(), ClientError> {
        self.writer.send_screen_ack(state_num).await
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
    /// `input_seq` as the reader sees it, moved before the bytes go out.
    sent: Arc<AtomicU64>,
    datagram: Option<ClientDatagram>,
    /// Reports keys to the connection's bulk governor (ADR-0052 decision 12
    /// (a)), so this side's own bulk senders yield while the user types.
    /// `None` on a route with no QUIC connection of ours (reverse).
    governor: Option<std::sync::Arc<crate::adapt::BulkGovernor>>,
}

/// The sending side of the datagram carrier on the client.
#[derive(Clone)]
struct ClientDatagram {
    hub: std::sync::Arc<DatagramHub>,
    channel: ChannelId,
}

impl ClientDatagram {
    /// Best effort: a datagram that does not go out changes nothing, its
    /// stream twin carries the message.
    fn send(&self, kind: DatagramKind, payload: Vec<u8>) {
        if self.hub.max_datagram_size().is_none() {
            return;
        }
        let _ = self.hub.send(&DatagramFrame {
            channel: self.channel,
            kind,
            payload,
        });
    }

    /// Whether `payload` fits one datagram now.
    fn fits(&self, payload_len: usize) -> bool {
        self.hub
            .max_datagram_size()
            .is_some_and(|max| DatagramFrame::HEADER_LEN + payload_len <= max)
    }
}

impl AttachWriter {
    /// See [`Attached::send_input`].
    pub async fn send_input(&mut self, data: &[u8]) -> Result<u64, ClientError> {
        if let Some(governor) = &self.governor {
            governor.note_interactive();
        }
        for chunk in data.chunks(wire::SESSION_CHUNK_MAX) {
            self.input_seq += chunk.len() as u64;
            self.sent.store(self.input_seq, Ordering::Release);
            // The datagram copy (ADR-0052 decision 8) goes first: it is the
            // one that can beat a stream retransmission. The stream copy is
            // the authoritative one and always follows.
            if let Some(dg) = &self.datagram {
                let copy = wire::Input {
                    input_seq: self.input_seq,
                    data: chunk.to_vec(),
                };
                if dg.fits(copy.encoded_len()) {
                    dg.send(DatagramKind::Input, copy.encode_to_vec());
                }
            }
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

    /// See [`Attached::send_screen_ack`].
    pub async fn send_screen_ack(&mut self, state_num: u64) -> Result<(), ClientError> {
        if let Some(dg) = &self.datagram {
            dg.send(
                DatagramKind::ScreenAck,
                wire::ScreenAck { state_num }.encode_to_vec(),
            );
        }
        self.send.send(&SessionFrame::screen_ack(state_num)).await?;
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

/// A stream read in flight. Kept across calls so that racing it against the
/// datagram channel never drops a half-read frame.
type PendingFrame = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (DataRecv, Result<Option<SessionFrame>, ClientError>)>
            + Send,
    >,
>;

/// Host → client half of an attach stream.
pub struct AttachReader {
    /// The receive half; `None` only while `pending` owns it.
    recv: Option<DataRecv>,
    pending: Option<PendingFrame>,
    datagram: Option<DatagramRx>,
    echo: EchoFilter,
}

impl AttachReader {
    /// See [`Attached::echo_rejected`].
    pub fn echo_rejected(&self) -> u64 {
        self.echo.rejected.load(Ordering::Relaxed)
    }

    /// See [`Attached::next`].
    pub async fn next(&mut self) -> Result<Option<AttachEvent>, ClientError> {
        loop {
            let Some(frame) = self.next_frame().await? else {
                return Ok(None);
            };
            let frame = match frame {
                Source::Stream(Some(frame)) => frame,
                Source::Stream(None) => return Ok(None),
                Source::Datagram(AttachEvent::ScreenEcho(echo)) => match self.echo.accept(echo) {
                    Some(echo) => return Ok(Some(AttachEvent::ScreenEcho(echo))),
                    None => continue,
                },
                Source::Datagram(event) => return Ok(Some(event)),
                Source::Skip => continue,
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
                Some(session_frame::Body::ScreenUpdate(u)) => AttachEvent::Screen(u),
                Some(session_frame::Body::ScreenHistory(h)) => AttachEvent::ScreenHistory(h),
                Some(session_frame::Body::ScreenEcho(e)) => match self.echo.accept(e) {
                    Some(e) => AttachEvent::ScreenEcho(e),
                    None => continue,
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

    /// The next thing to happen on either carrier. Without a datagram
    /// channel this is a plain stream read.
    async fn next_frame(&mut self) -> Result<Option<Source>, ClientError> {
        if self.datagram.is_none() && self.pending.is_none() {
            let Some(recv) = self.recv.as_mut() else {
                return Ok(None);
            };
            return Ok(Some(Source::Stream(recv.recv::<SessionFrame>().await?)));
        }
        if self.pending.is_none() {
            let Some(mut recv) = self.recv.take() else {
                return Ok(None);
            };
            self.pending = Some(Box::pin(async move {
                let frame = recv.recv::<SessionFrame>().await;
                (recv, frame)
            }));
        }
        let pending = self.pending.as_mut().expect("set above");
        tokio::select! {
            biased;
            datagram = recv_datagram(&mut self.datagram) => {
                Ok(Some(match datagram {
                    Some(frame) => datagram_event(frame).map_or(Source::Skip, Source::Datagram),
                    None => {
                        // The hub is gone with the connection; the stream
                        // read in flight reports it.
                        self.datagram = None;
                        Source::Skip
                    }
                }))
            }
            (recv, frame) = pending => {
                self.pending = None;
                self.recv = Some(recv);
                Ok(Some(Source::Stream(frame?)))
            }
        }
    }
}

/// What [`AttachReader::next_frame`] saw.
enum Source {
    Stream(Option<SessionFrame>),
    Datagram(AttachEvent),
    Skip,
}

async fn recv_datagram(rx: &mut Option<DatagramRx>) -> Option<DatagramFrame> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// A datagram from the host as an attach event. Anything that is not a
/// well-formed `ScreenUpdate` part is dropped: it is untrusted input to a
/// carrier that is allowed to lose.
fn datagram_event(frame: DatagramFrame) -> Option<AttachEvent> {
    if frame.kind == DatagramKind::ScreenEcho {
        // Checked against the sent offset by the reader's `EchoFilter`.
        return wire::ScreenEcho::decode(frame.payload.as_slice())
            .ok()
            .map(AttachEvent::ScreenEcho);
    }
    if frame.kind != DatagramKind::ScreenUpdate {
        return None;
    }
    let part = wire::ScreenUpdate::decode(frame.payload.as_slice()).ok()?;
    part.validate().ok()?;
    Some(AttachEvent::ScreenDatagram(part))
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
        response::Body::FileReadOpened(_) => "FileReadOpened",
        response::Body::FileWriteOpened(_) => "FileWriteOpened",
        response::Body::FileListed(_) => "FileListed",
        response::Body::FileMkdirDone(_) => "FileMkdirDone",
        response::Body::PunchReply(_) => "PunchReply",
        response::Body::PunchAnswer(_) => "PunchAnswer",
        response::Body::RendezvousList(_) => "RendezvousList",
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

// These tests drive `Session::from_local_control`/`open_local_data_link`
// against a fake daemon bound to a `UnixListener`, so the whole module is
// unix-only, rather than gating each test individually.
#[cfg(all(test, unix))]
mod reverse_tests;
