//! [`PunchEndpoint`]: one QUIC endpoint on one UDP socket that can also send
//! and receive the hole-punch datagram (ADR-0054 decisions 3, 7 and 13).
//!
//! A punch only means something if the NAT mapping it opens is the one the
//! QUIC handshake then uses, so the datagram has to leave from the very
//! socket quinn owns. quinn lets us hand it an abstract socket
//! (`Endpoint::new_with_abstract_socket`); [`PunchSocket`] wraps the real one
//! and does two things:
//!
//! * [`PunchEndpoint::send_punch`] writes a 16-byte datagram to the inner
//!   socket. It takes a tag and nothing else, so `qsh-core` has no way to put
//!   other bytes on this socket.
//! * `poll_recv` looks at every received datagram (every segment of a
//!   GRO-coalesced buffer) before quinn does. A 16-byte datagram that starts
//!   with the punch head never reaches quinn. If its tag belongs to an
//!   attempt registered with [`PunchEndpoint::expect`] it is handed to that
//!   [`PunchInbox`] as `(source, tag)`; otherwise it is dropped and counted.
//!   Everything else passes through untouched.
//!
//! The server side is off by default: the endpoint answers nobody, so the
//! port is invisible to a scan. [`PunchEndpoint::open_window`] turns the
//! server configuration on for as long as the returned guard (or any other
//! open window) lives.

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use qsh_proto::punch::{PunchTag, decode_punch_datagram, encode_punch_datagram};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};
use tokio::sync::mpsc;

use super::{
    Connection, DialError, Dialed, Endpoint, Fingerprint, Incoming, LocalIdentity, SetupError,
    TransportTuning, bind_tuned_udp_socket, classify_dial_failure, client_tls_config, finish_dial,
    server_config, transport_config,
};
use crate::error::ConnectError;
use crate::tls::{QshPeerVerifier, RejectReason, TrustEvaluator};

/// How many server windows may be open on one endpoint at once
/// (ADR-0054 decision 11, `MAX_PUNCH_WINDOWS`).
pub const MAX_PUNCH_WINDOWS: usize = 4;

/// Datagrams one inbox buffers before dropping the newest.
const INBOX_DEPTH: usize = 64;

/// Receive rounds `poll_recv` spends on a burst of punch datagrams before it
/// yields to the runtime.
const FILTER_ROUNDS: usize = 32;

/// How long `send_punch` waits for a writable socket.
const SEND_PATIENCE: Duration = Duration::from_millis(20);

/// Where the endpoint's UDP socket comes from.
pub enum SocketSource {
    /// A real OS socket: `[::]:0` dual-stack, or `0.0.0.0:0` where the host
    /// cannot make an IPv6 socket. Must be used inside a tokio runtime.
    Os,
    /// A simulated socket (`qsh_testkit::netsim`). Not part of the stable
    /// surface; the same escape-hatch status as `Connection::quinn`.
    #[doc(hidden)]
    Virtual(Arc<dyn AsyncUdpSocket>),
}

impl std::fmt::Debug for SocketSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketSource::Os => f.write_str("SocketSource::Os"),
            SocketSource::Virtual(_) => f.write_str("SocketSource::Virtual"),
        }
    }
}

/// A punch datagram that arrived for a registered attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PunchArrival {
    /// Where it came from (IPv4-mapped addresses unmapped).
    pub from: SocketAddr,
    /// The tag it carried, which is the one the inbox registered.
    pub tag: PunchTag,
}

/// Counters of one endpoint's socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PunchStats {
    /// Punch datagrams sent.
    pub punch_sent: u64,
    /// Punch datagrams delivered to an inbox.
    pub punch_received: u64,
    /// Punch-shaped datagrams whose tag no inbox expected (dropped).
    pub punch_rejected: u64,
    /// Every datagram the endpoint's QUIC side sent (excludes punches).
    pub quic_sent: u64,
    /// Every datagram handed to quinn.
    pub quic_received: u64,
}

#[derive(Default)]
struct Counters {
    punch_sent: AtomicU64,
    punch_received: AtomicU64,
    punch_rejected: AtomicU64,
    quic_sent: AtomicU64,
    quic_received: AtomicU64,
}

type InboxList = Vec<(PunchTag, mpsc::Sender<PunchArrival>)>;

/// The wrapped socket quinn runs on.
struct PunchSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    local_is_v6: bool,
    inboxes: Mutex<InboxList>,
    counters: Counters,
}

impl std::fmt::Debug for PunchSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchSocket")
            .field("local_is_v6", &self.local_is_v6)
            .finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl PunchSocket {
    fn new(inner: Arc<dyn AsyncUdpSocket>) -> io::Result<Self> {
        let local_is_v6 = inner.local_addr()?.is_ipv6();
        Ok(Self {
            inner,
            local_is_v6,
            inboxes: Mutex::new(Vec::new()),
            counters: Counters::default(),
        })
    }

    /// The destination as the inner socket wants it: a dual-stack IPv6
    /// socket addresses an IPv4 peer by its IPv4-mapped form.
    fn wire_dest(&self, dest: SocketAddr) -> SocketAddr {
        match (dest, self.local_is_v6) {
            (SocketAddr::V4(v4), true) => {
                SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            _ => dest,
        }
    }

    fn dispatch(&self, from: SocketAddr, tag: PunchTag) {
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        let sender = lock(&self.inboxes)
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, s)| s.clone());
        match sender {
            Some(tx) => {
                self.counters.punch_received.fetch_add(1, Ordering::Relaxed);
                // A full inbox drops the newest: the sender repeats.
                let _ = tx.try_send(PunchArrival { from, tag });
            }
            None => {
                self.counters.punch_rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Removes punch datagrams from the received buffers, compacting the
    /// rest to the front. Returns how many entries remain.
    fn filter(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta], n: usize) -> usize {
        let mut kept = 0;
        for i in 0..n {
            let len = meta[i].len.min(bufs[i].len());
            let stride = if meta[i].stride == 0 {
                len.max(1)
            } else {
                meta[i].stride
            };
            let mut any_punch = false;
            for seg in bufs[i][..len].chunks(stride) {
                if let Some(tag) = decode_punch_datagram(seg) {
                    any_punch = true;
                    self.dispatch(meta[i].addr, tag);
                }
            }
            if !any_punch {
                self.counters
                    .quic_received
                    .fetch_add(len.div_ceil(stride) as u64, Ordering::Relaxed);
                if kept != i {
                    let data = bufs[i][..len].to_vec();
                    bufs[kept][..len].copy_from_slice(&data);
                    meta[kept] = meta[i];
                }
                kept += 1;
                continue;
            }
            // Some segments were punches: keep the others, in order.
            let survivors: Vec<u8> = bufs[i][..len]
                .chunks(stride)
                .filter(|seg| decode_punch_datagram(seg).is_none())
                .flatten()
                .copied()
                .collect();
            if survivors.is_empty() {
                continue;
            }
            self.counters
                .quic_received
                .fetch_add(survivors.len().div_ceil(stride) as u64, Ordering::Relaxed);
            bufs[kept][..survivors.len()].copy_from_slice(&survivors);
            let mut m = meta[i];
            m.len = survivors.len();
            m.stride = stride.min(survivors.len());
            meta[kept] = m;
            kept += 1;
        }
        kept
    }
}

impl AsyncUdpSocket for PunchSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)?;
        self.counters.quic_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        for _ in 0..FILTER_ROUNDS {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            let kept = self.filter(bufs, meta, n);
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
        // A flood of punch datagrams: let the runtime run something else.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

struct Shared {
    endpoint: quinn::Endpoint,
    socket: Arc<PunchSocket>,
    identity: LocalIdentity,
    evaluator: Arc<dyn TrustEvaluator>,
    tuning: TransportTuning,
    server_config: quinn::ServerConfig,
    server_verifier: Arc<QshPeerVerifier>,
    windows: Mutex<usize>,
    /// [`PunchEndpoint::dial_trusted`]'s handshake time limit, in ms.
    dial_timeout_ms: AtomicU64,
}

/// A QUIC endpoint on a punch-aware socket. Cheap to clone; clones share the
/// endpoint.
#[derive(Clone)]
pub struct PunchEndpoint {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for PunchEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchEndpoint")
            .field("local", &self.local_addr().ok())
            .field("windows", &self.open_windows())
            .finish()
    }
}

impl PunchEndpoint {
    /// Creates the endpoint on `source`. It dials with `identity`, checks the
    /// peer through `evaluator`, and (inside a window) accepts the same way.
    /// Unlike [`Listener`](super::Listener) it carries no stateless reset key:
    /// a restarted host forgets its sessions anyway.
    pub fn new(
        source: SocketSource,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        tuning: TransportTuning,
    ) -> Result<Self, SetupError> {
        let unspecified_v6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
        let inner: Arc<dyn AsyncUdpSocket> = match source {
            SocketSource::Virtual(sock) => sock,
            SocketSource::Os => {
                let runtime = quinn::TokioRuntime;
                let (addr, std_socket) = match bind_tuned_udp_socket(unspecified_v6, true) {
                    Ok(s) => (unspecified_v6, s),
                    Err(_) => {
                        let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
                        let s = bind_tuned_udp_socket(v4, false)
                            .map_err(|source| SetupError::Bind { addr: v4, source })?;
                        (v4, s)
                    }
                };
                runtime
                    .wrap_udp_socket(std_socket)
                    .map_err(|source| SetupError::Bind { addr, source })?
            }
        };
        let bind_addr = inner.local_addr().unwrap_or(unspecified_v6);
        let socket = Arc::new(PunchSocket::new(inner).map_err(|source| SetupError::Bind {
            addr: bind_addr,
            source,
        })?);
        let server_verifier = Arc::new(QshPeerVerifier::new(evaluator.clone()));
        let server_config =
            server_config(&identity, server_verifier.clone(), transport_config(tuning))?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|source| SetupError::Bind {
            addr: bind_addr,
            source,
        })?;
        Ok(Self {
            shared: Arc::new(Shared {
                endpoint,
                socket,
                identity,
                evaluator,
                tuning,
                server_config,
                server_verifier,
                windows: Mutex::new(0),
                dial_timeout_ms: AtomicU64::new(
                    u64::try_from(super::default_dial_timeout().as_millis()).unwrap_or(u64::MAX),
                ),
            }),
        })
    }

    /// The socket's local address (`[::]:port` when dual-stack).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.endpoint.local_addr()
    }

    /// Sends one punch datagram carrying `tag` to `dest` from the endpoint's
    /// socket. Waits up to 20 ms for the socket to be writable (quinn's own
    /// send path waits the same way); past that the datagram counts as lost
    /// and the schedule repeats.
    pub async fn send_punch(&self, dest: SocketAddr, tag: &PunchTag) -> io::Result<()> {
        let sock = &self.shared.socket;
        let bytes = encode_punch_datagram(tag);
        let transmit = Transmit {
            destination: sock.wire_dest(dest),
            ecn: None,
            contents: &bytes,
            segment_size: None,
            src_ip: None,
        };
        let mut poller = sock.inner.clone().create_io_poller();
        let send = async {
            loop {
                std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)).await?;
                match sock.inner.try_send(&transmit) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    other => return other,
                }
            }
        };
        tokio::time::timeout(SEND_PATIENCE, send)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))??;
        sock.counters.punch_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Registers interest in punch datagrams carrying `tag`. Datagrams with
    /// any other tag are dropped. Dropping the inbox unregisters the tag.
    pub fn expect(&self, tag: PunchTag) -> PunchInbox {
        let (tx, rx) = mpsc::channel(INBOX_DEPTH);
        lock(&self.shared.socket.inboxes).push((tag, tx));
        PunchInbox {
            rx,
            tag,
            socket: self.shared.socket.clone(),
        }
    }

    /// Dials `addr` from the endpoint's socket. The handshake starts with
    /// `initial_rtt` as its round-trip guess (quinn then retransmits the
    /// Initial after about three of them), the peer must pass the pin or CA
    /// check, and its certificate must be `expected_peer`'s: a host that is
    /// trusted but is not the one we meant to reach is closed with
    /// `CLOSE_CODE_UNVERIFIED_PEER` and reported as
    /// [`DialError::LocalRejected`] with `observed` set.
    ///
    /// Dropping the future abandons the handshake.
    pub async fn dial(
        &self,
        addr: SocketAddr,
        server_name: &str,
        initial_rtt: Duration,
        expected_peer: &Fingerprint,
    ) -> Result<Connection, DialError> {
        let s = &self.shared;
        let verifier = Arc::new(QshPeerVerifier::new(s.evaluator.clone()));
        let tls = client_tls_config(&s.identity, verifier.clone())?;
        let quic = QuicClientConfig::try_from(tls).map_err(|e| SetupError::Quic(e.to_string()))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic));
        let mut transport = transport_config(s.tuning);
        transport.initial_rtt(initial_rtt);
        client_config.transport_config(Arc::new(transport));
        let connecting = s
            .endpoint
            .connect_with(client_config, addr, server_name)
            .map_err(ConnectError::from)?;
        let conn = match connecting.await {
            Ok(conn) => conn,
            Err(err) => return Err(classify_dial_failure(err, verifier.last_observation())),
        };
        let connection = finish_dial(conn, &verifier)?;
        let observed = connection.peer_fingerprint();
        if observed.as_ref() != Some(expected_peer) {
            connection.close(super::CLOSE_CODE_UNVERIFIED_PEER, b"unexpected peer");
            return Err(DialError::LocalRejected {
                reason: RejectReason::Untrusted,
                observed,
            });
        }
        Ok(connection)
    }

    /// Sets the time limit of [`Self::dial_trusted`] (the default dial
    /// timeout until then).
    pub fn set_dial_timeout(&self, timeout: Duration) {
        self.shared.dial_timeout_ms.store(
            u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Dials `addr` from the endpoint's socket the way `Dialer::dial` does:
    /// any peer the evaluator trusts is accepted, the handshake uses the
    /// dial timeout, and the result carries the endpoint that keeps
    /// the connection alive. This is the registration dial of
    /// `qsh serve --to`, which leaves the socket a hole-punch window later
    /// opens on (ADR-0054 decision 7).
    pub async fn dial_trusted(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Dialed, DialError> {
        self.dial_with(addr, server_name, self.shared.evaluator.clone())
            .await
    }

    /// [`Self::dial_trusted`] that accepts only the peer `binding` names
    /// (ADR-0060): the registration dial of `qsh serve --to` must reach its
    /// controller's pin, not any pinned device at that address.
    pub async fn dial_trusted_bound(
        &self,
        addr: SocketAddr,
        server_name: &str,
        binding: crate::tls::PeerBinding,
    ) -> Result<Dialed, DialError> {
        let evaluator = Arc::new(crate::tls::BoundTrust::new(
            self.shared.evaluator.clone(),
            binding,
        ));
        self.dial_with(addr, server_name, evaluator).await
    }

    async fn dial_with(
        &self,
        addr: SocketAddr,
        server_name: &str,
        evaluator: Arc<dyn TrustEvaluator>,
    ) -> Result<Dialed, DialError> {
        let s = &self.shared;
        let verifier = Arc::new(QshPeerVerifier::new(evaluator));
        let tls = client_tls_config(&s.identity, verifier.clone())?;
        let quic = QuicClientConfig::try_from(tls).map_err(|e| SetupError::Quic(e.to_string()))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic));
        client_config.transport_config(Arc::new(transport_config(s.tuning)));
        let connecting = s
            .endpoint
            .connect_with(client_config, addr, server_name)
            .map_err(ConnectError::from)?;
        let timeout = Duration::from_millis(self.shared.dial_timeout_ms.load(Ordering::Relaxed));
        let conn = match tokio::time::timeout(timeout, connecting).await {
            Err(_) => return Err(DialError::Timeout(timeout)),
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) => return Err(classify_dial_failure(err, verifier.last_observation())),
        };
        let connection = finish_dial(conn, &verifier)?;
        Ok(Dialed {
            connection,
            endpoint: self.endpoint(),
            verifier,
        })
    }

    /// Turns the server side on until the returned guard, and every other
    /// open window, is dropped. `None` when [`MAX_PUNCH_WINDOWS`] are already
    /// open. Connections accepted while a window was open outlive it.
    #[must_use]
    pub fn open_window(&self) -> Option<PunchWindow> {
        let mut n = lock(&self.shared.windows);
        if *n >= MAX_PUNCH_WINDOWS {
            return None;
        }
        if *n == 0 {
            self.shared
                .endpoint
                .set_server_config(Some(self.shared.server_config.clone()));
        }
        *n += 1;
        Some(PunchWindow {
            shared: self.shared.clone(),
        })
    }

    /// How many windows are open; the server side is on iff this is non-zero.
    pub fn open_windows(&self) -> usize {
        *lock(&self.shared.windows)
    }

    /// The next inbound connection attempt. Only produces one while a window
    /// is open. `None` once the endpoint is closed. Admission (Retry, caps)
    /// is the caller's, exactly as with [`Listener::accept`](super::Listener::accept).
    pub async fn accept(&self) -> Option<Incoming> {
        let incoming = self.shared.endpoint.accept().await?;
        Some(Incoming {
            incoming,
            verifier: self.shared.server_verifier.clone(),
        })
    }

    /// The socket's counters.
    pub fn stats(&self) -> PunchStats {
        let c = &self.shared.socket.counters;
        PunchStats {
            punch_sent: c.punch_sent.load(Ordering::Relaxed),
            punch_received: c.punch_received.load(Ordering::Relaxed),
            punch_rejected: c.punch_rejected.load(Ordering::Relaxed),
            quic_sent: c.quic_sent.load(Ordering::Relaxed),
            quic_received: c.quic_received.load(Ordering::Relaxed),
        }
    }

    /// A transport-neutral handle on the same endpoint, to keep a connection's
    /// endpoint alive the way [`Dialed::endpoint`](super::Dialed::endpoint) does.
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::from_quic(self.shared.endpoint.clone())
    }

    /// Closes every connection with `code` and refuses new ones.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.shared
            .endpoint
            .close(quinn::VarInt::from_u32(code), reason);
    }

    /// Resolves once every connection has drained.
    pub async fn wait_idle(&self) {
        self.shared.endpoint.wait_idle().await;
    }
}

/// Keeps the server side of a [`PunchEndpoint`] on. Dropping the last open
/// window removes the server configuration; connections already accepted
/// stay.
pub struct PunchWindow {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for PunchWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PunchWindow")
    }
}

impl Drop for PunchWindow {
    fn drop(&mut self) {
        let mut n = lock(&self.shared.windows);
        *n = n.saturating_sub(1);
        if *n == 0 {
            self.shared.endpoint.set_server_config(None);
        }
    }
}

/// Receives punch datagrams of one registered tag. Dropping it unregisters.
pub struct PunchInbox {
    rx: mpsc::Receiver<PunchArrival>,
    tag: PunchTag,
    socket: Arc<PunchSocket>,
}

impl std::fmt::Debug for PunchInbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchInbox").finish()
    }
}

impl PunchInbox {
    /// The next arrival.
    pub async fn recv(&mut self) -> Option<PunchArrival> {
        self.rx.recv().await
    }

    /// An arrival that is already queued.
    pub fn try_recv(&mut self) -> Option<PunchArrival> {
        self.rx.try_recv().ok()
    }
}

impl Drop for PunchInbox {
    fn drop(&mut self) {
        let tag = self.tag;
        lock(&self.socket.inboxes).retain(|(t, _)| *t != tag);
    }
}

#[cfg(test)]
mod tests;
