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
use qsh_core::client::Session;
use qsh_core::tunnel::{LocalForwardHandle, RemoteForwardAcceptor};
use qsh_proto::wire::{
    self, ConnectResult, ForwardDirection, ForwardSpec, PRIORITY_TUNNEL, StreamHeader, StreamKind,
};
use qsh_transport::{Connection, FramedRecv, FramedSend, FramedStream, StaticTrust};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::loopback::{LoopbackHarness, TestIdentity};

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

/// A TCP sink on `127.0.0.1:0` for exactly one connection: reads and
/// discards every byte, counting them as it goes. Used by the perf
/// benchmarks (`PLAN.md` M4 Step 7, DoD 3/4) that want to saturate the
/// *forward* direction only — an [`EchoServer`]'s own reply writes would
/// contend for the same tunnel/QUIC bandwidth the benchmark is trying to
/// measure, muddying a one-directional throughput number.
pub struct DiscardServer {
    addr: SocketAddr,
    total: Arc<std::sync::atomic::AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl DiscardServer {
    /// Bind and accept exactly one connection, discarding everything it
    /// sends. The returned receiver resolves with the final byte count
    /// once that connection's read side reaches EOF — a real signal that
    /// the splice's own half-close propagated all the way through (client
    /// write-shutdown → requester leg → tunnel stream finish → host leg →
    /// this socket), not a polled guess (`docs/design/testing.md` CI
    /// 규율: no `sleep()`-based synchronisation).
    pub async fn start() -> io::Result<(Self, tokio::sync::oneshot::Receiver<u64>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let counter = Arc::clone(&total);
        let task = tokio::spawn(async move {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        counter.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            let _ = done_tx.send(counter.load(std::sync::atomic::Ordering::Relaxed));
        });
        Ok((Self { addr, total, task }, done_rx))
    }

    /// The address a forward's destination should point at.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bytes discarded so far — live, for a saturation loop that wants to
    /// report progress without waiting for EOF.
    pub fn total_bytes(&self) -> u64 {
        self.total.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for DiscardServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One outbound `write_all` per iteration of [`FloodServer`]'s loop — an
/// implementation-detail chunk size (how the infinite output stream is
/// segmented for the syscall), not a contract on the transfer itself.
const FLOOD_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// A TCP source on `127.0.0.1:0` for exactly one connection: writes a
/// shared buffer in a loop until the peer closes or a write fails — the
/// converse of [`DiscardServer`]. Used by the M4 DoD 4 saturation
/// benchmark (`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`) to
/// saturate the **host→client** direction of a `-L` tunnel: point the
/// forward's destination at this server, and the bulk bytes it emits ride
/// the tunnel stream *back toward the client* — landing on the **host's**
/// send scheduler, where `PRIORITY_TUNNEL` bulk competes with
/// `PRIORITY_SESSION_DATA` PTY output for priority (`docs/design/protocol.md`
/// §12), instead of the client's. A [`DiscardServer`]-fed forward instead
/// saturates the client's own send scheduler, which is the wrong party —
/// the client never has PTY output competing with anything.
pub struct FloodServer {
    addr: SocketAddr,
    total: Arc<std::sync::atomic::AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl FloodServer {
    /// Bind and start flooding the first connection accepted. The
    /// returned receiver resolves with the final byte count once the
    /// connection's write side errors (the peer closed) — the flood's own
    /// analogue of [`DiscardServer`]'s EOF signal.
    pub async fn start() -> io::Result<(Self, tokio::sync::oneshot::Receiver<u64>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let counter = Arc::clone(&total);
        let task = tokio::spawn(async move {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                return;
            };
            let chunk = vec![0xcd_u8; FLOOD_CHUNK_BYTES];
            loop {
                if stream.write_all(&chunk).await.is_err() {
                    break;
                }
                counter.fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            let _ = done_tx.send(counter.load(std::sync::atomic::Ordering::Relaxed));
        });
        Ok((Self { addr, total, task }, done_rx))
    }

    /// The address a forward's destination should point at.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bytes written so far — live, mirroring [`DiscardServer::total_bytes`].
    pub fn total_bytes(&self) -> u64 {
        self.total.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for FloodServer {
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
        Self::start_inner(LoopbackHarness::start_with(authorizer).await).await
    }

    /// Start with the interim allow-all-pinned policy and an explicit
    /// [`qsh_core::quota::QuotaLimits`] instead of `ServeConfig`'s
    /// defaults — the tunnel-flavored twin of [`LoopbackHarness::
    /// start_with_quotas`], for the tunnel-stream quota's own e2e pins
    /// (`crates/qsh-testkit/tests/quota.rs`, M8 Step 3b).
    pub async fn start_with_quotas(limits: qsh_core::quota::QuotaLimits) -> Self {
        Self::start_inner(LoopbackHarness::start_with_quotas(limits).await).await
    }

    /// Start with a custom policy, a caller-provided client identity and a
    /// caller-provided host trust store — the tunnel-flavored twin of
    /// [`LoopbackHarness::start_custom`]. For a test that needs a *second*,
    /// distinct principal pinned on the same host (`PLAN.md` M5 Step 5's
    /// `forward.remote.close` ownership tests: one identity opens the `-R`
    /// forward via [`Self::remote_forward`], another — pinned here too —
    /// dials separately to prove it cannot close a forward it does not
    /// own).
    pub async fn start_custom(
        authorizer: Arc<dyn Authorizer>,
        client: TestIdentity,
        server_trust: StaticTrust,
    ) -> Self {
        Self::start_inner(LoopbackHarness::start_custom(authorizer, client, server_trust).await)
            .await
    }

    /// Start with the interim allow-all-pinned policy, reachable only
    /// through a seeded chaos proxy (`docs/design/testing.md` L4,
    /// `PLAN.md` M4 Step 8 (a)/(b)) — the tunnel-flavored twin of
    /// [`LoopbackHarness::start_chaotic`], for `repath()`/`sever()`
    /// scenarios that need a live tunnel splice riding the same connection
    /// the fault is injected on. [`Self::connection`] (and so
    /// [`Self::local_forward`]/[`Self::remote_forward`]) dials through the
    /// proxy transparently, exactly like `raw_session`'s own `dial()` call
    /// does under [`LoopbackHarness::start_chaotic`].
    pub async fn start_chaotic(policy: crate::chaos::ChaosPolicy) -> Self {
        Self::start_chaotic_with(Arc::new(AllowAllPinned), policy).await
    }

    /// [`Self::start_chaotic`] with a custom policy engine.
    pub async fn start_chaotic_with(
        authorizer: Arc<dyn Authorizer>,
        policy: crate::chaos::ChaosPolicy,
    ) -> Self {
        Self::start_inner(LoopbackHarness::start_chaotic_with(authorizer, policy).await).await
    }

    async fn start_inner(host: LoopbackHarness) -> Self {
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

    /// The chaos proxy in front of this harness's host. Panics unless the
    /// harness was started with [`Self::start_chaotic`].
    pub fn chaos(&self) -> &crate::chaos::ChaosProxy {
        self.host.chaos()
    }

    /// The one-line context every chaos assertion message must carry —
    /// passthrough of [`LoopbackHarness::context`].
    pub fn chaos_context(&self) -> String {
        self.host.context()
    }

    /// [`Self::chaos_context`] plus a freshly read [`crate::chaos::ChaosStats`]
    /// — passthrough of [`LoopbackHarness::detail`]. Call it at the
    /// assertion site.
    pub fn chaos_detail(&self) -> String {
        self.host.detail()
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

    /// Open a `-R` remote forward the production way (`PLAN.md` M4 Step 4):
    /// a **fresh** [`Session`] to the host (not
    /// [`Self::connection`]/[`Self::tcp_connect`]'s — a `-R` forward gets
    /// its own connection here for the same reason `qsh tunnel_open`'s
    /// `ForwardDirection::Remote` arm does not reuse anything, and so the
    /// requester-leg-death tests below can kill *this* connection without
    /// taking the harness's `TCP_CONNECT` connection down with it) sends
    /// `RemoteForwardOpen{bind_host: "", forward_host, forward_port}`
    /// (empty `bind_host` = the wire default = loopback,
    /// `docs/design/protocol.md` §7), spawns the real
    /// [`RemoteForwardAcceptor`] on that connection, and registers the
    /// `forward_id` the host minted — exactly
    /// [`qsh_core::ops::Ops::tunnel_open`]'s `ForwardDirection::Remote`
    /// arm, called directly rather than through `Ops`'s host-registry
    /// (which this in-process harness has no config/`Paths` for).
    pub async fn remote_forward(
        &self,
        forward_host: &str,
        forward_port: u16,
    ) -> RemoteForwardBinding {
        let mut session = self.host.session().await;
        let connection = session.connection().clone();
        let acceptor = RemoteForwardAcceptor::spawn(connection).await;
        let opened = session
            .rfwd_open(wire::RemoteForwardOpen {
                bind_host: String::new(),
                bind_port: 0,
                forward_host: forward_host.to_string(),
                forward_port: u32::from(forward_port),
                claim_token: Vec::new(),
            })
            .await
            .expect("RemoteForwardOpen");
        acceptor.register(
            opened.forward_id.clone(),
            forward_host.to_string(),
            forward_port,
        );
        let actual_port =
            u16::try_from(opened.actual_port).expect("actual_port fits u16 on loopback");
        RemoteForwardBinding {
            forward_id: opened.forward_id,
            actual_port,
            session,
            acceptor,
        }
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

/// A live `-R` remote forward, from [`TunnelHarness::remote_forward`].
///
/// Owns the requester leg end to end: the [`Session`] `RemoteForwardOpen`/
/// `RemoteForwardClose` ride, and the [`RemoteForwardAcceptor`] dispatching
/// this connection's `TCP_ACCEPTED` streams. The *host's* listener is not
/// owned by this value — it lives on the harness's [`LoopbackHarness`]
/// (`crate::server::Server::remote_forwards`) — so tearing it down needs
/// either [`Self::close`] (asks the host, the ordinary path) or
/// [`Self::abandon`] (kills the connection without asking, the "requester
/// vanished" path `crate::server::Server::purge_connection` exists for).
pub struct RemoteForwardBinding {
    forward_id: String,
    actual_port: u16,
    session: Session,
    acceptor: RemoteForwardAcceptor,
}

impl RemoteForwardBinding {
    /// The loopback address **on the host** this forward bound — connect
    /// here to reach whatever the requester leg dials on each accept.
    pub fn host_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.actual_port))
    }

    /// The host-minted `forward_id` this binding was registered under.
    pub fn forward_id(&self) -> &str {
        &self.forward_id
    }

    /// Ask the host to close this forward's listener
    /// (`RemoteForwardClose`), and stop this side's own dispatch first —
    /// the same order [`qsh_core::ops::TunnelHold::close`] uses, so a
    /// `TCP_ACCEPTED` racing the close can never land after this side
    /// stopped expecting one.
    pub async fn close(mut self) {
        self.acceptor.unregister(&self.forward_id);
        self.session
            .rfwd_close(wire::RemoteForwardClose {
                forward_id: self.forward_id.clone(),
            })
            .await
            .expect("RemoteForwardClose");
    }

    /// Kill the connection this forward rides **without** sending
    /// `RemoteForwardClose` — a requester that crashed or lost its network
    /// rather than one that closed cleanly. The host has no
    /// `RemoteForwardClose` to react to here; its cleanup is
    /// connection-bound (`crate::server::Server::purge_connection`, called
    /// from `serve_connection` once the connection's own task ends for any
    /// reason), which is the thing this method exists to provoke.
    pub fn abandon(self) {
        self.session.connection().close(0, b"abandoned");
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
