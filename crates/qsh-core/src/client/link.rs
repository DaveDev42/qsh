//! The two concrete carriers a `Session`'s control channel can run over
//! (`docs/design/protocol.md` §11-3, `PLAN.md` M3 Step 6): a QUIC control
//! stream dialed straight to the peer (the forward route, unchanged since
//! M1), or a `LOCAL_CONTROL` conduit to this machine's resident `qsh
//! listen` daemon, which relays to the peer over its live reverse
//! registration (`crate::localctl::client`, `crate::reverse::listen`'s
//! `ControlHub` on the daemon side).
//!
//! [`ControlLink`] is deliberately an **enum**, never a generic type
//! parameter or an ADR-0005 `Transport`/`StreamMux` trait object — a
//! `Session` is either dialed or relayed, never a third thing, and every
//! caller (`crate::client::Session`) already knows the wire messages it
//! sends and receives (`qsh.wire.v1::ControlMessage`) regardless of which
//! carrier is underneath, so there is nothing a trait's extra indirection
//! would buy here.
//!
//! Dependency direction: this file depends on [`crate::localctl::client`],
//! never the reverse — `localctl::client` stays transport-free (it must
//! never name `qsh_transport`/`quinn`/`rustls`, `xtask arch`'s
//! `LOCALCTL_CLIENT_FILE` ban) and has no reason to know this enum exists.
//!
//! Only the surface [`crate::client::Session`] actually uses is exposed:
//! send one `ControlMessage`, receive the next one, and a best-effort
//! half-close. Nothing here decides *when* to reconnect or *what* a
//! session_open/get/list/read/write/resize/close request looks like —
//! that stays entirely in `crate::ops::session`, unchanged by which
//! variant is underneath (`PLAN.md` M3 Step 6's "Zero reverse-specific
//! business logic" rule).

use prost::Message;
use qsh_proto::wire::{ControlMessage, StreamHeader};
use qsh_transport::{Connection, FramedRecv, FramedSend, FramedStream};

// `crate::localctl` is `#[cfg(unix)]`-only (`lib.rs`) — the `Local`
// carrier this file adds exists only there; `Quic` (unchanged since M1)
// stays available on every platform. Windows leg trap (b): an ungated
// import consumed only by unix-only code trips `unused_imports` under
// Windows clippy.
#[cfg(unix)]
use crate::localctl::client::{ControlConduit, DataRecvHalf, DataSendHalf};
#[cfg(unix)]
use crate::ops::OpError;

use super::ClientError;

/// A `Session`'s control channel: either half of a QUIC control stream
/// dialed straight to the peer, or a `LOCAL_CONTROL` conduit to this
/// machine's resident daemon that relays the exact same
/// `ControlMessage`/`Response` pair onto the peer's live reverse
/// registration (`docs/design/protocol.md` §11-3's "conn 이 아니라
/// stream 이 대상" framing extended to a second carrier).
pub(crate) enum ControlLink {
    /// Dialed straight to the peer over QUIC (forward route).
    Quic(FramedStream),
    /// Relayed through this machine's `qsh listen` daemon over a
    /// `LOCAL_CONTROL` conduit (reverse route). `#[cfg(unix)]`: localctl
    /// (UDS) is unix-only (`crate::localctl`'s own gate in `lib.rs`) —
    /// on Windows this carrier simply does not exist, and
    /// `Ops::resolve_route` never produces a reverse route there either
    /// (`ops/host.rs`'s own Windows-leg doc), so nothing ever needs to
    /// construct this variant on that platform.
    #[cfg(unix)]
    Local(ControlConduit),
}

impl ControlLink {
    /// Encode + send one `ControlMessage`, whichever carrier this is.
    pub(crate) async fn send(&mut self, msg: &ControlMessage) -> Result<(), ClientError> {
        match self {
            ControlLink::Quic(stream) => Ok(stream.send.send(msg).await?),
            #[cfg(unix)]
            ControlLink::Local(conduit) => {
                conduit.send(msg).await.map_err(op_error_to_client_error)
            }
        }
    }

    /// Read the next `ControlMessage`. `Ok(None)` on a clean end of the
    /// link — a QUIC stream FIN at a frame boundary, or the daemon closing
    /// the UDS conduit the same way (`crate::localctl::daemon`'s
    /// `serve_control`: a dead host ends every conduit of that host this
    /// way, so this is also how the CLI side learns of a reverse
    /// connection's death — `docs/design/protocol.md` §11-3).
    pub(crate) async fn recv(&mut self) -> Result<Option<ControlMessage>, ClientError> {
        match self {
            ControlLink::Quic(stream) => Ok(stream.recv.recv::<ControlMessage>().await?),
            #[cfg(unix)]
            ControlLink::Local(conduit) => conduit.recv().await.map_err(op_error_to_client_error),
        }
    }

    /// Best-effort half-close of the send side (`Session::close`'s
    /// "finish, then close the connection" sequence). Errors are ignored
    /// here exactly as [`qsh_transport::control::FramedSend::finish`]'s own
    /// doc allows ("a second call errors with `ClosedStream`, which
    /// callers may ignore") — the Local carrier has no equivalent
    /// close-frame drain to wait for: dropping the underlying `UnixStream`
    /// (this `Session`'s eventual drop) closes the fd, which the daemon
    /// sees as a clean EOF on its own read, the same signal a QUIC FIN
    /// gives it.
    // Two bodies, not one `if let`: without the `Local` variant (Windows,
    // no `unix` cfg), `ControlLink` has exactly one variant, so `if let
    // ControlLink::Quic(stream) = self` becomes an irrefutable pattern —
    // `-D warnings` under Windows clippy (`irrefutable_let_patterns`).
    #[cfg(unix)]
    pub(crate) fn finish(&mut self) {
        if let ControlLink::Quic(stream) = self {
            let _ = stream.send.finish();
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn finish(&mut self) {
        let ControlLink::Quic(stream) = self;
        let _ = stream.send.finish();
    }
}

/// [`OpError`] (what [`crate::localctl::client`]'s conduit calls return) →
/// [`ClientError`] (what every other `Session` method returns), preserving
/// the code/message/retryable triple verbatim — the same "nothing to
/// translate" shape as `crate::localctl::client::remote_error`'s
/// `LocalError` → `OpError` mapping one layer down.
#[cfg(unix)]
pub(crate) fn op_error_to_client_error(err: OpError) -> ClientError {
    ClientError::Remote {
        code: err.code,
        message: err.message,
        retryable: err.retryable,
    }
}

/// A synchronous, any-thread "end this attach's data conduit right now"
/// primitive for the reverse route (`PLAN.md` M3 Step 7) — the
/// `LOCAL_STREAM` UDS socket's counterpart to
/// [`qsh_transport::Connection::close`]'s own nature: queues the teardown
/// and returns immediately, needs no Tokio runtime, and unblocks a pending
/// local read with no cooperation from the daemon or the peer needed
/// (`docs/design/protocol.md` §11-3) — the forward route's equivalent
/// relies on the whole QUIC connection being this one attach's alone to
/// close, which the reverse route's single shared registration is not
/// (`crate::ops::session`'s `RecoveryLink` doc explains why that
/// difference is exactly what makes reverse recovery Step 8's problem, not
/// this one's).
///
/// Always constructible (`Default`, inert — nothing to kill) so callers on
/// the forward route or on non-unix builds never need an `Option` wrapper
/// around this type; only [`Self::new`] (unix-only — the socket it wraps
/// does not exist elsewhere) produces a live one.
#[derive(Clone, Default)]
pub(crate) struct DataKillSwitch {
    #[cfg(unix)]
    socket: Option<std::sync::Arc<tokio::net::UnixStream>>,
}

impl DataKillSwitch {
    /// Wrap a live `LOCAL_STREAM` socket. `socket` should be a clone of
    /// the same `Arc` [`DataSend`]/[`DataRecv`]'s `Local` halves hold
    /// (`crate::localctl::client::open_stream_over_inner`'s own doc on
    /// why a held clone, never a bare fd, is what makes [`Self::kill`]
    /// safe to call at any time) — this is the third clone, kept only for
    /// this purpose.
    #[cfg(unix)]
    pub(crate) fn new(socket: std::sync::Arc<tokio::net::UnixStream>) -> Self {
        Self {
            socket: Some(socket),
        }
    }

    /// Shut both directions of the underlying socket down immediately. A
    /// no-op when nothing was ever wrapped (the forward route, or a
    /// non-unix build — see [`Self`]'s own doc): there is nothing to kill
    /// there, and this is called unconditionally by
    /// [`crate::ops::session::AttachHandle::detach`] regardless of which
    /// route an attach rides.
    pub(crate) fn kill(&self) {
        #[cfg(unix)]
        if let Some(socket) = &self.socket {
            use std::os::fd::AsRawFd as _;
            // SAFETY: `socket.as_raw_fd()` names a descriptor this `Arc`
            // keeps open for as long as `self` (or any clone of it, per
            // `Self`'s own doc) is alive — `shutdown(2)` only changes that
            // socket's read/write state, never the process's fd table, so
            // it cannot race a `close` of the same number happening
            // elsewhere.
            unsafe {
                libc::shutdown(socket.as_raw_fd(), libc::SHUT_RDWR);
            }
        }
    }
}

/// A `Session`'s attach data channel (`docs/design/protocol.md` §9): a
/// `SESSION_DATA` QUIC stream dialed straight to the peer, or a
/// `LOCAL_STREAM` conduit relayed through this machine's resident daemon
/// — the data-plane sibling of [`ControlLink`], split into send/recv
/// halves the same way [`qsh_transport::control::FramedStream`] already
/// is (`crate::client::AttachWriter`/`AttachReader` hold one each).
pub(crate) enum DataSend {
    /// Dialed straight to the peer over QUIC (forward route).
    Quic(FramedSend),
    /// Relayed through this machine's `qsh listen` daemon over a
    /// `LOCAL_STREAM` conduit (reverse route). `#[cfg(unix)]`: see
    /// [`ControlLink::Local`]'s own doc — the same reasoning applies
    /// verbatim.
    #[cfg(unix)]
    Local(DataSendHalf),
}

impl DataSend {
    /// Encode + send one `SessionFrame`, whichever carrier this is.
    pub(crate) async fn send<M: Message>(&mut self, msg: &M) -> Result<(), ClientError> {
        match self {
            DataSend::Quic(send) => Ok(send.send(msg).await?),
            #[cfg(unix)]
            DataSend::Local(send) => send.send(msg).await.map_err(op_error_to_client_error),
        }
    }

    /// Finish our send half (`crate::client::AttachWriter::finish`'s own
    /// doc: "only queues the FIN"). Both variants are synchronous and
    /// swallow their own error — a second finish, or a conduit already
    /// gone, is not this caller's problem to report (matching
    /// [`ControlLink::finish`]'s identical choice).
    pub(crate) fn finish(&mut self) {
        match self {
            DataSend::Quic(send) => {
                let _ = send.finish();
            }
            #[cfg(unix)]
            DataSend::Local(send) => send.finish(),
        }
    }

    /// End this stream's framed phase and surrender the raw QUIC send
    /// stream, for the one caller that needs an unframed byte pipe: a
    /// tunnel stream past its handshake (`docs/design/protocol.md` §5, §7,
    /// [`crate::tunnel::splice`]).
    ///
    /// `Err(self)` — never a panic — for the reverse `LOCAL_STREAM`
    /// carrier, which has no single QUIC stream to surrender: its raw
    /// counterpart is [`Self::into_raw_local`] instead
    /// (`crate::tunnel::splice::splice_tcp_uds`, `PLAN.md` M4 Step 5 (a)).
    /// A caller that holds the wrong carrier gets its value back rather
    /// than a panic, so the stream stays alive to be torn down properly.
    pub(crate) fn into_raw_quic(self) -> Result<quinn::SendStream, Self> {
        match self {
            DataSend::Quic(send) => Ok(send.into_raw()),
            #[cfg(unix)]
            other @ DataSend::Local(_) => Err(other),
        }
    }

    /// [`Self::into_raw_quic`]'s mirror for the reverse `LOCAL_STREAM`
    /// carrier — surrenders the raw UDS byte writer
    /// [`crate::tunnel::splice::splice_tcp_uds`] pumps a tunnel's unframed
    /// payload onto. `Err(self)` for the forward `Quic` carrier, same
    /// reasoning as [`Self::into_raw_quic`]'s own doc, reversed.
    #[cfg(unix)]
    pub(crate) fn into_raw_local(self) -> Result<crate::localctl::client::RawUdsWrite, Self> {
        match self {
            DataSend::Local(send) => Ok(send.into_raw()),
            other @ DataSend::Quic(_) => Err(other),
        }
    }
}

/// See [`DataSend`]'s own doc — this is its receive-half sibling.
pub(crate) enum DataRecv {
    /// Dialed straight to the peer over QUIC (forward route).
    Quic(FramedRecv),
    /// Relayed through this machine's `qsh listen` daemon over a
    /// `LOCAL_STREAM` conduit (reverse route). `#[cfg(unix)]`: see
    /// [`ControlLink::Local`]'s own doc.
    #[cfg(unix)]
    Local(DataRecvHalf),
}

impl DataRecv {
    /// Read the next `SessionFrame`. `Ok(None)` on a clean end of the
    /// stream/conduit.
    pub(crate) async fn recv<M: Message + Default>(&mut self) -> Result<Option<M>, ClientError> {
        match self {
            DataRecv::Quic(recv) => Ok(recv.recv::<M>().await?),
            #[cfg(unix)]
            DataRecv::Local(recv) => recv.recv::<M>().await.map_err(op_error_to_client_error),
        }
    }

    /// The receive-half sibling of [`DataSend::into_raw_quic`], returning
    /// the raw QUIC stream **and** the handshake residue behind it — bytes
    /// the peer pipelined after its last framed message, which
    /// [`qsh_transport::FramedRecv::into_raw`]'s own doc explains must be
    /// delivered ahead of everything read from the stream afterwards.
    ///
    /// `Err(self)` for the reverse `LOCAL_STREAM` carrier — its raw
    /// counterpart is [`Self::into_raw_local`].
    pub(crate) fn into_raw_quic(self) -> Result<(quinn::RecvStream, Vec<u8>), Self> {
        match self {
            DataRecv::Quic(recv) => Ok(recv.into_raw()),
            #[cfg(unix)]
            other @ DataRecv::Local(_) => Err(other),
        }
    }

    /// [`Self::into_raw_quic`]'s mirror for the reverse `LOCAL_STREAM`
    /// carrier — see [`DataSend::into_raw_local`]'s own doc.
    #[cfg(unix)]
    pub(crate) fn into_raw_local(
        self,
    ) -> Result<(crate::localctl::client::RawUdsRead, Vec<u8>), Self> {
        match self {
            DataRecv::Local(recv) => Ok(recv.into_raw()),
            other @ DataRecv::Quic(_) => Err(other),
        }
    }
}

/// A carrier this process can open a **fresh** data stream on — the same
/// forward/reverse axis as [`ControlLink`] and [`DataSend`]/[`DataRecv`],
/// but where those two represent a stream already opened, this borrows
/// what opening *another* one needs (the live connection, or the daemon
/// socket + host name), so more than one call site can open data streams
/// the same way without each having to know both carriers' handshakes
/// (`PLAN.md` M4 Step 2 — [`crate::tunnel::open_stream`] is the first such
/// second call site; [`crate::client::Session::open_data_link`] predates
/// this type and is left as its own inline forward/reverse match rather
/// than rebuilt on top of it, so this addition changes no observable
/// session behavior).
///
/// Deliberately an enum, never a generic type parameter or an ADR-0005
/// `Transport`/`StreamMux` trait object — see [`ControlLink`]'s own doc for
/// why that axis split is the house style here, not a trait.
///
/// `#[allow(dead_code)]`-adjacent items below: nothing outside
/// `crate::tunnel`'s own tests calls this yet — `PLAN.md` M4 Step 2 lands
/// only the seam, Step 3/4 add the local/remote forward business logic
/// that actually opens tunnel streams through it.
#[allow(dead_code)]
pub(crate) enum DataLink<'a> {
    /// A live QUIC connection dialed straight to the peer (forward route).
    Quic(&'a Connection),
    /// This machine's resident `qsh listen` daemon socket, plus the host
    /// name it should relay the new `LOCAL_STREAM` conduit to (reverse
    /// route). `#[cfg(unix)]`: see [`ControlLink::Local`]'s own doc — the
    /// same reasoning applies verbatim.
    #[cfg(unix)]
    Local {
        /// The daemon's UDS socket path.
        socket: &'a std::path::Path,
        /// The registered host name to relay to.
        host: &'a str,
    },
}

#[allow(dead_code)]
impl DataLink<'_> {
    /// Open a fresh data stream and send `header` as its first frame,
    /// applying quinn's per-stream `priority` (`docs/design/protocol.md`
    /// §12) on the forward route. The reverse `LOCAL_STREAM` conduit has
    /// no QUIC-level notion of send priority of its own, so `priority` is
    /// silently dropped on this route today — it is accepted here
    /// uniformly so callers do not need to special-case which carrier
    /// they hold, but the daemon does **not** yet apply the caller's
    /// intended priority on its behalf: `crate::localctl::daemon`'s
    /// `serve_stream` unconditionally opens the relayed QUIC stream at
    /// `wire::PRIORITY_SESSION_DATA` and, as of M3, hard-rejects any
    /// non-`SESSION_DATA` header before opening anything on QUIC. Giving
    /// the daemon a priority/kind-aware relay path (so a tunnel header
    /// routed over this carrier rides at `PRIORITY_TUNNEL` instead) is
    /// `PLAN.md` M4 Step 5 PR 5a's job, not this seam's — this Step 2 seam
    /// only fixes the call shape so callers don't need to know which
    /// carrier they hold.
    pub(crate) async fn open_stream(
        &self,
        header: &StreamHeader,
        priority: i32,
    ) -> Result<(DataSend, DataRecv, DataKillSwitch), ClientError> {
        self.open_stream_with_wait(header, priority, 0).await
    }

    /// [`Self::open_stream`], but with the reverse route's `LocalHello.wait_ms`
    /// threaded through rather than fixed at `0`. Every caller before
    /// `PLAN.md` M4 Step 5 (a) had nothing to wait on (`open_stream`'s own
    /// doc — a live registration or a fresh dial, never a queued arrival),
    /// so `open_stream` stays the zero-wait default; `crate::tunnel::remote`'s
    /// `-R over reverse` claim loop is the one caller that needs a real
    /// budget, to long-poll a `TCP_ACCEPTED{forward_id}` claim instead of
    /// busy-opening a fresh conduit per attempt
    /// (`crate::localctl::client::open_stream_with_wait`'s own doc). On the
    /// forward `Quic` carrier `wait_ms` is accepted uniformly but has
    /// nothing to apply to — a fresh `open_bi()` never waits on anything.
    // `wait_ms` is read only by the `#[cfg(unix)]` `Local` arm below — the
    // `Quic` arm never waits on anything (this doc comment's own "nothing
    // to apply to"), so on Windows (no `Local` variant at all) the
    // parameter goes unused. Dead, not absent, on that platform — same
    // idiom as `HUB_WAIT_POLL` (`reverse/listen.rs`).
    #[cfg_attr(not(unix), allow(unused_variables))]
    pub(crate) async fn open_stream_with_wait(
        &self,
        header: &StreamHeader,
        priority: i32,
        wait_ms: u32,
    ) -> Result<(DataSend, DataRecv, DataKillSwitch), ClientError> {
        match self {
            DataLink::Quic(conn) => {
                let (send, recv) = conn.open_bi().await?;
                let mut data = FramedStream::data(send, recv);
                data.send.set_priority(priority);
                data.send.send(header).await?;
                let (send, recv) = data.split();
                Ok((
                    DataSend::Quic(send),
                    DataRecv::Quic(recv),
                    DataKillSwitch::default(),
                ))
            }
            #[cfg(unix)]
            DataLink::Local { socket, host } => {
                let handshake =
                    crate::localctl::client::open_stream_with_wait(socket, host, header, wait_ms)
                        .await
                        .map_err(op_error_to_client_error)?;
                let kill = DataKillSwitch::new(handshake.socket.clone());
                Ok((
                    DataSend::Local(handshake.send),
                    DataRecv::Local(handshake.recv),
                    kill,
                ))
            }
        }
    }
}

// Both tests below exercise the `Local` carrier (`ControlLink::Local`,
// `OpError`, `op_error_to_client_error`) or `crate::localctl` directly,
// all `#[cfg(unix)]`-only — so the whole module is, rather than splitting
// each test individually.
#[cfg(all(test, unix))]
mod tests {
    use qsh_proto::ErrorCode;
    use qsh_proto::local::{LocalHelloAck, LocalResponse, local_response};
    use qsh_proto::wire::{Ping, control_message};
    use tokio::net::UnixListener;

    use super::*;

    /// Proves the enum actually **dispatches** — a `Local`-carried
    /// `ControlLink` sends and receives real `ControlMessage` frames
    /// through a live `LOCAL_CONTROL` conduit, exactly the same call
    /// shape `crate::client::Session::request` uses regardless of which
    /// variant is underneath. The `Quic` variant's dispatch is exercised
    /// by every pre-existing forward-path `client::Session` test in this
    /// crate (nothing about `ControlLink::send`/`recv` changes that
    /// behavior — see `crate::client::mod`'s `request`), so this test adds
    /// coverage for the one variant that is actually new.
    #[tokio::test]
    async fn control_link_local_dispatches_send_and_recv_through_the_conduit() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("link-dispatch.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = crate::localctl::frame::LocalConduit::new(stream);
            let _hello: qsh_proto::local::LocalHello = conduit.recv().await.unwrap().unwrap();
            conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();
            let echoed: ControlMessage = conduit.recv().await.unwrap().unwrap();
            conduit.send(&echoed).await.unwrap();
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let mut link = ControlLink::Local(handshake.conduit);

        let ping = ControlMessage::new(1, control_message::Body::Ping(Ping {}));
        link.send(&ping).await.unwrap();
        let echoed = link.recv().await.unwrap().expect("daemon echoed a frame");
        assert_eq!(echoed, ping);

        // A no-op on the Local carrier (see `finish`'s own doc) — must not
        // panic or hang.
        link.finish();

        daemon.await.unwrap();
    }

    /// [`DataSend`]/[`DataRecv`]'s `Local` carrier, dispatch-tested the
    /// same way [`control_link_local_dispatches_send_and_recv_through_the_conduit`]
    /// proves `ControlLink::Local` — a real `LOCAL_STREAM` handshake
    /// (`crate::localctl::client::open_stream`) against a fake daemon that
    /// then echoes raw bytes exactly the way
    /// `crate::localctl::daemon::LocalctlDaemon::serve_stream`'s own splice
    /// does past the header, proving a real `SessionFrame` round-trips
    /// through both the framed handshake and the raw byte pump underneath.
    #[tokio::test]
    async fn data_link_local_dispatches_send_and_recv_of_real_session_frames() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("data-link-dispatch.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = crate::localctl::frame::LocalConduit::new(stream);
            let hello: qsh_proto::local::LocalHello = conduit.recv().await.unwrap().unwrap();
            assert_eq!(
                hello.kind,
                qsh_proto::local::LocalStreamKind::LocalStream as i32
            );
            assert_eq!(hello.host, "phone");
            conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();
            let _header: qsh_proto::wire::StreamHeader = conduit.recv().await.unwrap().unwrap();
            // Past the header this conduit is a raw byte splice, exactly
            // like the real daemon's `serve_stream`: echo whatever
            // arrives until the client's own write half closes.
            let (mut raw, prefetched) = conduit.into_raw();
            if !prefetched.is_empty() {
                raw.write_all(&prefetched).await.unwrap();
            }
            let mut buf = vec![0u8; 4096];
            loop {
                let n = raw.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                raw.write_all(&buf[..n]).await.unwrap();
            }
        });

        let header = qsh_proto::wire::StreamHeader::session_data(vec![9, 9, 9]);
        let handshake = crate::localctl::client::open_stream(&sock, "phone", &header)
            .await
            .unwrap();
        let mut send = DataSend::Local(handshake.send);
        let mut recv = DataRecv::Local(handshake.recv);

        let frame = qsh_proto::wire::SessionFrame::output(3, b"echo".to_vec());
        send.send(&frame).await.unwrap();
        let echoed: qsh_proto::wire::SessionFrame =
            recv.recv().await.unwrap().expect("daemon echoed a frame");
        assert_eq!(echoed, frame);

        // Half-close: the daemon's echo loop reads a clean EOF, exits, and
        // drops its own end — this end then sees a clean end of conduit
        // too (`docs/design/protocol.md` §11-3's "UDS EOF" propagation).
        send.finish();
        let end: Option<qsh_proto::wire::SessionFrame> = recv.recv().await.unwrap();
        assert!(
            end.is_none(),
            "expected a clean end of conduit, got {end:?}"
        );

        daemon.await.unwrap();
    }

    /// [`crate::localctl::client::open_stream`]'s handshake errors map
    /// through [`DataSend`]/[`DataRecv`]'s callers exactly like
    /// `open_control`'s do — a `LocalError` the daemon sends back is not
    /// this layer's problem to interpret, only to relay
    /// (`crate::localctl::client::remote_error`).
    #[tokio::test]
    async fn open_stream_maps_a_local_error_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("data-link-error.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = crate::localctl::frame::LocalConduit::new(stream);
            let _hello: qsh_proto::local::LocalHello = conduit.recv().await.unwrap().unwrap();
            conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::Error(
                        qsh_proto::local::LocalError::from_code(
                            ErrorCode::HostNotFound,
                            "unknown host",
                        ),
                    )),
                })
                .await
                .unwrap();
        });

        let header = qsh_proto::wire::StreamHeader::session_data(vec![1]);
        // Not `.unwrap_err()`: the `Ok` side (`DataHandshake`) holds a raw
        // `UnixStream` split across three owners and has no `Debug` impl,
        // so this matches instead.
        let err = match crate::localctl::client::open_stream(&sock, "ghost", &header).await {
            Ok(_) => panic!("expected the daemon's LocalError to surface"),
            Err(err) => err,
        };
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert_eq!(err.message, "unknown host");
        daemon.await.unwrap();
    }

    #[test]
    fn op_error_maps_to_client_error_remote_verbatim() {
        let err = OpError::new(ErrorCode::HostNotFound, "no such host").with_retryable(false);
        match op_error_to_client_error(err) {
            ClientError::Remote {
                code,
                message,
                retryable,
            } => {
                assert_eq!(code, ErrorCode::HostNotFound);
                assert_eq!(message, "no such host");
                assert!(!retryable);
            }
            other => panic!("expected ClientError::Remote, got {other:?}"),
        }
    }
}
