//! In-process loopback **tunnel** harness (L3, `docs/design/testing.md`;
//! `PLAN.md` M4 Step 3 (b)).
//!
//! One process, three real parties and no subprocess, no sleeps, no fixed
//! ports:
//!
//! ```text
//!   TcpStream ──▶ LocalForwardHandle ══QUIC══▶ Server ──▶ EchoServer
//!   (the test)     (client `-L`)                (host)     (destination)
//! ```
//!
//! The middle leg is a real [`LoopbackHarness`] — the same mutually-pinned
//! forward QUIC pair every other L3 suite uses, with the same
//! `AllowAllPinned` interim policy and the same [`MemoryAuditSink`]. This
//! module adds only what a tunnel needs on either end of it: a destination
//! to reach ([`EchoServer`]), a requester-side `-L` listener
//! ([`TunnelHarness::local_forward`], the production
//! [`LocalForwardHandle`]), and a way to ask the host for one tunnel
//! stream by hand ([`TunnelHarness::tcp_connect`]) so a test can assert on
//! the `ConnectResult` the wire contract promises rather than only on
//! whether bytes happened to flow.
//!
//! **Why the harness builds `ForwardSpec` literally.** `-L`'s grammar
//! rejects listen port 0 (`1..=65535`, `docs/CLI.md` §6.9), so a real
//! command line cannot ask for an ephemeral local port — but
//! `docs/design/testing.md`'s CI rule requires one. [`ForwardSpec`] is a
//! plain struct, so this harness expresses what the grammar cannot,
//! exactly as `qsh_core`'s own `tunnel::local` unit tests do. DoD 1's
//! `8080` is illustrative; nothing here hardcodes a port.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use qsh_core::acl::{AllowAllPinned, Authorizer};
use qsh_core::audit::MemoryAuditSink;
use qsh_core::tunnel::LocalForwardHandle;
use qsh_proto::wire::{
    ConnectResult, ForwardDirection, ForwardSpec, PRIORITY_TUNNEL, StreamHeader, StreamKind,
};
use qsh_transport::{Connection, FramedRecv, FramedSend, FramedStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::loopback::LoopbackHarness;

/// A TCP echo server on `127.0.0.1:0` — the tunnel's destination.
///
/// Echoes each connection to EOF and then half-closes, which is what lets
/// a test observe the splice's own half-close discipline end to end: the
/// destination's last bytes have to arrive *after* the requester stopped
/// writing, and the requester's read has to end without a timer.
pub struct EchoServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl EchoServer {
    /// Bind and start echoing. Port 0 (`docs/design/testing.md` CI rule).
    pub async fn start() -> io::Result<Self> {
        Self::serve(TcpListener::bind("127.0.0.1:0").await?)
    }

    /// Bind and start echoing on a **named** loopback port.
    ///
    /// The one thing port 0 cannot express: a destination that a forward
    /// is *already* pointing at. A `-L` forward's destination is fixed at
    /// bind time, so a test that wants one forward to see a refusal and
    /// then a success has to reserve a port ([`dead_port`]), point the
    /// forward at it, and only then bring this up behind it.
    pub async fn start_on(port: u16) -> io::Result<Self> {
        Self::serve(TcpListener::bind(("127.0.0.1", port)).await?)
    }

    fn serve(listener: TcpListener) -> io::Result<Self> {
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.into_split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                    // Half-close rather than drop: the requester is
                    // waiting for an orderly EOF, and an RST here would
                    // make a correct splice look broken.
                    let _ = write.shutdown().await;
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// The address the tunnel's destination half should dial.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The echo server's port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A loopback port with nothing behind it: bound to learn the number, then
/// released. Connecting to it is refused, which is how a test provokes the
/// host's `CONNECTION_FAILED` without depending on an unroutable address
/// or a timeout.
pub async fn dead_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// A host, a client connection to it, and an echo destination — the three
/// parties a local forward needs.
pub struct TunnelHarness {
    /// The host, its audit sink and its policy (see [`LoopbackHarness`]).
    pub host: LoopbackHarness,
    /// The echo destination the host dials.
    pub echo: EchoServer,
    connection: Connection,
    /// The negotiated control stream. Held for the harness's lifetime: it
    /// is what keeps this connection's `serve_connection` loop — the thing
    /// that answers `TCP_CONNECT` — alive and accepting streams.
    _control: FramedStream,
}

impl TunnelHarness {
    /// Start with the interim allow-all-pinned policy.
    pub async fn start() -> Self {
        Self::start_with(Arc::new(AllowAllPinned)).await
    }

    /// Start with a custom policy — how a test provokes the host's inline
    /// `forward.local` denial (`docs/design/protocol.md` §7).
    pub async fn start_with(authorizer: Arc<dyn Authorizer>) -> Self {
        let host = LoopbackHarness::start_with(authorizer).await;
        // `raw_session`, not `session`: a local forward needs a live,
        // handshaken connection and nothing else — no PTY session is
        // involved, and `TCP_CONNECT` carries no ticket (§7's sole ticket
        // exception), so there is nothing for a session to hold.
        let (connection, control) = host.raw_session().await;
        let echo = EchoServer::start().await.expect("bind echo server");
        Self {
            host,
            echo,
            connection,
            _control: control,
        }
    }

    /// The client's connection to the host — the carrier a `-L` rides.
    pub fn connection(&self) -> Connection {
        self.connection.clone()
    }

    /// Every audit record the host produced.
    pub fn audit(&self) -> &Arc<MemoryAuditSink> {
        &self.host.audit
    }

    /// Bind a `-L` listener on an **ephemeral** loopback port forwarding to
    /// `host:port` as the host sees it, and start serving it over this
    /// harness's connection. The returned handle owns the listener: drop it
    /// to tear the forward down (`PLAN.md` M4 §4.1 #1).
    ///
    /// This is the production entry point the CLI's `-L` uses, reached the
    /// same way — nothing about the requester leg is re-implemented here.
    pub async fn local_forward(&self, host: &str, port: u16) -> LocalForwardHandle {
        LocalForwardHandle::start(&ephemeral_local_spec(host, port), self.connection())
            .await
            .expect("bind local forward")
    }

    /// Open one `TCP_CONNECT` stream by hand and return the host's
    /// [`ConnectResult`] verbatim.
    ///
    /// The forward path above deliberately hides a refusal (it closes the
    /// local socket and keeps serving), so this is how a test asserts the
    /// *wire* answer `docs/design/protocol.md` §7 specifies — the code, on
    /// the stream, before any byte pipe exists.
    pub async fn tcp_connect(&self, host: &str, port: u16) -> ConnectResult {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .expect("open a tunnel stream");
        let mut send = FramedSend::data(send);
        send.set_priority(PRIORITY_TUNNEL);
        send.send(&StreamHeader {
            kind: StreamKind::TcpConnect as i32,
            // §7: `TCP_CONNECT` is the one stream kind with no ticket.
            ticket: Vec::new(),
            host: host.to_string(),
            port: u32::from(port),
        })
        .await
        .expect("send the TCP_CONNECT header");
        let mut recv = FramedRecv::data(recv);
        recv.recv()
            .await
            .expect("read the ConnectResult")
            .expect("§7 requires a ConnectResult either way")
    }

    /// Open a TCP connection to a bound forward, write `payload`,
    /// half-close, and read the answer to EOF.
    ///
    /// Write and read run concurrently on purpose: a payload larger than
    /// the socket buffers and the QUIC window would deadlock a
    /// write-everything-then-read test, and the point of the large-payload
    /// case is the splice's chunking, not the harness's patience.
    pub async fn round_trip(addr: SocketAddr, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        let stream = TcpStream::connect(addr).await?;
        let (mut read, mut write) = stream.into_split();
        let writer = tokio::spawn(async move {
            write.write_all(&payload).await?;
            // The echo server answers only at EOF, so the half-close is
            // part of the request.
            write.shutdown().await
        });
        let mut got = Vec::new();
        let read_result = read.read_to_end(&mut got).await;
        writer.await.expect("writer task")?;
        read_result?;
        Ok(got)
    }

    /// Stop the host and drain it.
    pub async fn shutdown(self) {
        self.host.shutdown().await;
    }
}

/// A `-L` spec on an ephemeral local port. See this module's doc for why it
/// is built rather than parsed.
pub fn ephemeral_local_spec(host: &str, port: u16) -> ForwardSpec {
    ForwardSpec {
        direction: ForwardDirection::Local,
        // No `bind:` — the default is loopback (`PLAN.md` M4 §4.1 #3).
        bind: None,
        listen_port: 0,
        host: host.to_string(),
        host_port: port,
    }
}
