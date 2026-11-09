//! L3 loopback for the intermediate peer J of a jump chain (ADR-0056
//! decisions 3, 4, 7 to 9 and 24; DoD 25.7, 25.8 and 25.11 host half).
//!
//! The parties are all real:
//!
//! ```text
//!   test (raw client C) ==QUIC== J (Server) --UDP-- T (Server)  or  a test UDP socket
//! ```
//!
//! C is the test. It opens a `JUMP` stream on a real qsh connection to J and
//! either speaks hand-made QUIC-shaped packets to a plain UDP socket that
//! stands for T, or runs a real inner dial (`Dialer::dial_over_pipe` on a
//! `PacketPipe`, its [`PipePeer`] pumped over the `JUMP` stream and the kind
//! 14 datagrams) to a second qsh host. The client chain is a later step;
//! the pump here is the smallest thing that does what it will do.
//!
//! J's host-local filter is on in every test that checks it. The tests that
//! need a loopback target turn it off with the same test hook that shortens
//! the timers ([`Server::set_jump_options`]).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::acl::{AllowAllPinned, Authorizer, Role, load_or_deny};
use qsh_core::audit::{AuditError, AuditRecord, AuditSink};
use qsh_core::client::Session;
use qsh_core::config::Paths;
use qsh_core::datagram::DatagramHub;
use qsh_core::jump::{CloseReason, JumpOptions};
use qsh_core::trust::SharedTrustStore;
use qsh_proto::ErrorCode;
use qsh_proto::datagram::{ChannelId, DatagramFrame, DatagramKind};
use qsh_proto::jump::{JUMP_PACKET_MAX, JumpStreamDecoder, encode_packet};
use qsh_proto::wire::{
    self, CAP_DATAGRAM_V1, ConnectResult, PRIORITY_TUNNEL, StreamHeader, StreamKind,
};
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_identity};
use qsh_testkit::tunnel::EchoServer;
use qsh_transport::{
    Connection, Dialer, FramedRecv, FramedSend, FramedStream, PacketPipe, PipePeer, Principal,
    RecvStream, SendStream, StaticTrust,
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const LOOPBACK: &str = "127.0.0.1";

fn channel(n: u8) -> [u8; 16] {
    [n; 16]
}

/// A client Initial-shaped packet: long header, version 1, type Initial,
/// DCID of eight bytes, the given SCID, padded to `total` bytes.
fn initial(scid: &[u8], total: usize) -> Vec<u8> {
    let mut p = vec![0xC0, 0, 0, 0, 1, 8];
    p.extend_from_slice(&[9; 8]);
    p.push(scid.len() as u8);
    p.extend_from_slice(scid);
    p.resize(total.max(p.len()), 0xAB);
    p
}

/// A target's answer: a long header (type Handshake) whose DCID is `to`.
fn answer(to: &[u8]) -> Vec<u8> {
    let mut p = vec![0xE0, 0, 0, 0, 1, to.len() as u8];
    p.extend_from_slice(to);
    p.push(8);
    p.extend_from_slice(&[7; 8]);
    p.resize(1200, 0xCD);
    p
}

/// A short-header packet of `total` bytes.
fn short(total: usize) -> Vec<u8> {
    let mut p = vec![0x40; total];
    p[1] = 0x99;
    p
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// `trust.toml` pinning the client as `laptop` with `role`, and the host's
/// production authorizer built over it.
struct Roles {
    _dir: tempfile::TempDir,
    authorizer: Arc<dyn Authorizer>,
}

fn roles(client: &TestIdentity, role: &str) -> Roles {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    std::fs::create_dir_all(&paths.config_dir).expect("config dir");
    std::fs::write(
        paths.trust_file(),
        format!(
            "[[peer]]\nname = \"laptop\"\nfingerprint = \"{}\"\naddress = \"\"\n\
             added_at = \"2026-11-09T00:00:00Z\"\nrole = \"{role}\"\n",
            client.fingerprint
        ),
    )
    .expect("write trust.toml");
    let trust = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
    let (authorizer, _diagnostic) = load_or_deny(&paths, Role::Serve, trust);
    Roles {
        _dir: dir,
        authorizer,
    }
}

fn pinned(client: &TestIdentity) -> StaticTrust {
    StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()))
}

fn loopback_options() -> JumpOptions {
    JumpOptions {
        allow_host_local: true,
        ..JumpOptions::default()
    }
}

/// C, J and (optionally) T.
struct Rig {
    j: LoopbackHarness,
    outer: Connection,
    _ctl: FramedStream,
    _roles: Roles,
    client: TestIdentity,
}

impl Rig {
    /// J pins the client with `role`; `options` are J's; `hide_datagram`
    /// makes J behave as a build without `datagram.v1`.
    async fn start(role: &str, options: JumpOptions, hide_datagram: bool) -> Self {
        let client = make_identity();
        let roles = roles(&client, role);
        let j = LoopbackHarness::start_custom(
            Arc::clone(&roles.authorizer),
            client.clone(),
            pinned(&client),
        )
        .await;
        j.server.set_jump_options(options);
        if hide_datagram {
            j.server.hide_capabilities(&[CAP_DATAGRAM_V1]);
        }
        let (outer, ctl) = j.raw_session().await;
        Self {
            j,
            outer,
            _ctl: ctl,
            _roles: roles,
            client,
        }
    }

    /// The common case: a `full` pin, a loopback-friendly J.
    async fn full() -> Self {
        Self::start("full", loopback_options(), false).await
    }

    fn stats(&self) -> &qsh_core::jump::JumpStats {
        self.j.server.jump_stats()
    }

    fn jump_audit(&self) -> Vec<AuditRecord> {
        self.j
            .audit
            .records()
            .into_iter()
            .filter(|r| r.action == "forward.jump")
            .collect()
    }

    /// A host T that pins the same client, plus an echo behind it.
    async fn target_host(&self) -> (LoopbackHarness, EchoServer, Dialer) {
        let t = LoopbackHarness::start_custom(
            Arc::new(AllowAllPinned),
            self.client.clone(),
            pinned(&self.client),
        )
        .await;
        let echo = EchoServer::start().await.expect("echo");
        let dialer = Dialer::new(
            self.client.local.clone(),
            Arc::new(StaticTrust::empty().with_pin(
                t.server_identity.fingerprint,
                Principal::Device("box".into()),
            )),
        )
        .with_timeout(Duration::from_secs(10));
        (t, echo, dialer)
    }

    async fn open(&self, id: [u8; 16], host: &str, port: u16) -> Result<Channel, ConnectResult> {
        open_jump(&self.outer, id, host, port).await
    }

    async fn shutdown(self) {
        self.outer.close(0, b"done");
        self.j.shutdown().await;
    }
}

/// An open `JUMP` stream, past `ConnectResult{ok}`.
struct Channel {
    id: [u8; 16],
    send: SendStream,
    reader: Reader,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Channel")
    }
}

/// What reading the stream carrier gave.
#[derive(Debug, PartialEq, Eq)]
enum Got {
    Packet(Vec<u8>),
    Silence,
    /// The stream ended: a reset with this code, or `None` for a FIN.
    Ended(Option<u64>),
}

struct Reader {
    recv: RecvStream,
    decoder: JumpStreamDecoder,
    /// Kind 14 datagrams for the channel: J carries the target's packets on
    /// either carrier, so a client reads both.
    datagrams: qsh_core::datagram::DatagramRx,
}

impl Reader {
    async fn next(&mut self, within: Duration) -> Got {
        let deadline = tokio::time::Instant::now() + within;
        let mut buf = vec![0u8; 4096];
        loop {
            match self.decoder.next_packet() {
                Ok(Some(p)) => return Got::Packet(p),
                Ok(None) => {}
                Err(e) => panic!("the host sent a bad frame: {e}"),
            }
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => return Got::Silence,
                frame = self.datagrams.recv() => {
                    if let Some(f) = frame
                        && f.kind == DatagramKind::JumpPacket
                    {
                        return Got::Packet(f.payload);
                    }
                }
                read = self.recv.read(&mut buf) => match read {
                    Ok(Some(n)) => self.decoder.push(&buf[..n]),
                    Ok(None) => return Got::Ended(None),
                    Err(err) => return Got::Ended(Some(reset_code(&err))),
                },
            }
        }
    }
}

fn reset_code(err: &qsh_transport::ReadError) -> u64 {
    match err {
        qsh_transport::ReadError::Reset(code) => u64::from(*code),
        other => panic!("not a stream reset: {other:?}"),
    }
}

impl Channel {
    async fn send_packet(&mut self, packet: &[u8]) {
        let frame = encode_packet(packet).expect("a carrier-sized packet");
        self.send.write_all(&frame).await.expect("write a packet");
    }
}

fn jump_header(id: &[u8], host: &str, port: u16) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::Jump as i32,
        ticket: id.to_vec(),
        host: host.to_string(),
        port: u32::from(port),
        deny_host_local: false,
    }
}

async fn open_jump_header(
    outer: &Connection,
    header: &StreamHeader,
) -> Result<Channel, ConnectResult> {
    let (send, recv) = outer.open_bi().await.expect("open a JUMP stream");
    let mut send = FramedSend::data(send);
    send.set_priority(PRIORITY_TUNNEL);
    send.send(header).await.expect("send the JUMP header");
    let mut recv = FramedRecv::data(recv);
    let result: ConnectResult = recv
        .recv()
        .await
        .expect("read the ConnectResult")
        .expect("§7 requires a ConnectResult either way");
    if !result.ok {
        return Err(result);
    }
    let (recv, residue) = recv.into_raw();
    let mut decoder = JumpStreamDecoder::new();
    decoder.push(&residue);
    let mut id = [0u8; 16];
    if header.ticket.len() == 16 {
        id.copy_from_slice(&header.ticket);
    }
    Ok(Channel {
        id,
        send: send.into_raw(),
        reader: Reader {
            recv,
            decoder,
            datagrams: DatagramHub::of(outer).register(ChannelId(id)),
        },
    })
}

async fn open_jump(
    outer: &Connection,
    id: [u8; 16],
    host: &str,
    port: u16,
) -> Result<Channel, ConnectResult> {
    open_jump_header(outer, &jump_header(&id, host, port)).await
}

fn code_of(result: &ConnectResult) -> ErrorCode {
    result.code.parse().expect("a known error code")
}

/// A UDP socket standing for T.
async fn udp_target() -> (UdpSocket, u16) {
    let socket = UdpSocket::bind((LOOPBACK, 0)).await.expect("bind a target");
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

async fn recv_within(socket: &UdpSocket, within: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(within, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => Some((buf[..n].to_vec(), from)),
        _ => None,
    }
}

// ----------------------------------------------------------------------
// the real thing: an inner QUIC connection through J to a second qsh host
// ----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Via {
    /// Every client-to-J packet on the stream carrier.
    Stream,
    /// A datagram whenever the outer connection has room for it, the stream
    /// otherwise.
    DatagramWhenItFits,
}

struct Pump {
    stop: oneshot::Sender<()>,
    task: JoinHandle<PipePeer>,
}

/// Moves the packets of `peer` over the channel, as the client chain will.
fn spawn_pump(outer: &Connection, mut ch: Channel, mut peer: PipePeer, via: Via) -> Pump {
    let hub = DatagramHub::of(outer);
    let id = ChannelId(ch.id);
    let (stop, mut stop_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                packet = peer.recv() => {
                    let Some(packet) = packet else { break };
                    let fits = hub
                        .max_datagram_size()
                        .is_some_and(|room| room >= DatagramFrame::HEADER_LEN + packet.len());
                    if via == Via::DatagramWhenItFits && fits {
                        let _ = hub.send(&DatagramFrame {
                            channel: id,
                            kind: DatagramKind::JumpPacket,
                            payload: packet,
                        });
                    } else if let Some(frame) = encode_packet(&packet)
                        && ch.send.write_all(&frame).await.is_err()
                    {
                        break;
                    }
                }
                got = ch.reader.next(Duration::from_secs(3600)) => match got {
                    Got::Packet(p) => { peer.send(p); }
                    _ => break,
                },
            }
        }
        peer
    });
    Pump { stop, task }
}

impl Pump {
    async fn finish(self) -> PipePeer {
        let _ = self.stop.send(());
        self.task.await.expect("pump task")
    }
}

/// An echo through the inner connection: a `TCP_CONNECT` to `port` on T.
async fn echo_through(conn: &Connection, port: u16, payload: &[u8]) -> Vec<u8> {
    let (send, recv) = conn.open_bi().await.expect("open a tunnel stream");
    let mut send = FramedSend::data(send);
    send.send(&StreamHeader {
        kind: StreamKind::TcpConnect as i32,
        ticket: Vec::new(),
        host: LOOPBACK.to_string(),
        port: u32::from(port),
        deny_host_local: false,
    })
    .await
    .expect("send the TCP_CONNECT header");
    let mut recv = FramedRecv::data(recv);
    let result: ConnectResult = recv.recv().await.expect("result").expect("a result");
    assert!(result.ok, "{result:?}");
    let (mut recv, residue) = recv.into_raw();
    assert!(residue.is_empty());
    let mut send = send.into_raw();
    let payload = payload.to_vec();
    let writer = tokio::spawn(async move {
        send.write_all(&payload).await.expect("write the payload");
        send.finish().expect("finish");
    });
    let back = recv.read_to_end(8 << 20).await.expect("read the echo");
    writer.await.expect("writer");
    back
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Dial T through J: open the channel, start the pump, run the inner dial.
async fn inner_dial(
    rig: &Rig,
    id: [u8; 16],
    t: &LoopbackHarness,
    dialer: &Dialer,
    via: Via,
) -> (qsh_transport::Dialed, Pump) {
    let ch = rig
        .open(id, LOOPBACK, t.host_addr.port())
        .await
        .expect("J admits the jump");
    let (pipe, peer) = PacketPipe::new(256);
    let pump = spawn_pump(&rig.outer, ch, peer, via);
    let dialed = dialer
        .dial_over_pipe(pipe, LOOPBACK)
        .await
        .expect("the inner connection comes up through J");
    (dialed, pump)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_inner_dial_through_j_reaches_t_over_the_stream_carrier() {
    // J without `datagram.v1`: every packet in both directions is a stream
    // frame.
    let rig = Rig::start("full", loopback_options(), true).await;
    let (t, echo, dialer) = rig.target_host().await;
    let (dialed, pump) = inner_dial(&rig, channel(1), &t, &dialer, Via::Stream).await;

    // The inner connection is T's: the peer T sees is J's socket, not C.
    assert_eq!(
        dialed.connection.remote_address(),
        qsh_transport::PIPE_REMOTE_ADDR
    );
    let session = Session::negotiate(dialed.connection.clone(), "laptop")
        .await
        .expect("Hello through J");
    let payload = pattern(300_000);
    let back = echo_through(session.connection(), echo.port(), &payload).await;
    assert_eq!(back, payload);

    let stats = rig.stats();
    assert!(stats.to_target_packets.load(rel()) > 100);
    assert!(stats.to_client_packets.load(rel()) > 100);
    assert_eq!(stats.to_client_datagrams.load(rel()), 0);
    assert_eq!(stats.to_target_datagrams.load(rel()), 0);
    // J allowed the jump once and wrote one record naming the requested
    // target.
    let audit = rig.jump_audit();
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].decision, "allow");
    assert_eq!(audit[0].principal, "device:laptop");
    assert_eq!(
        audit[0].resource,
        format!("{LOOPBACK}:{}", t.host_addr.port())
    );
    // T sees the same principal, from J's socket.
    let t_records = t.audit.records();
    assert!(t_records.iter().any(|r| r.principal == "device:laptop"));

    dialed.connection.close(0, b"done");
    let peer = pump.finish().await;
    drop(peer);
    t.shutdown().await;
    rig.shutdown().await;
}

fn rel() -> std::sync::atomic::Ordering {
    std::sync::atomic::Ordering::Relaxed
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_inner_dial_through_j_reaches_t_over_the_datagram_carrier() {
    let rig = Rig::full().await;
    let (t, echo, dialer) = rig.target_host().await;
    // The outer connection starts at the 1200-byte MTU, whose datagram room
    // (1162) cannot carry a minimum-size inner packet. The first packets of
    // the handshake go over the stream; once PLPMTUD opens the room, both
    // directions switch (ADR-0056 decision 4).
    let (dialed, pump) = inner_dial(&rig, channel(2), &t, &dialer, Via::DatagramWhenItFits).await;
    let session = Session::negotiate(dialed.connection.clone(), "laptop")
        .await
        .expect("Hello through J");

    // Drive both directions of the outer connection until J's room opens,
    // by echoing through the inner connection.
    let payload = pattern(400_000);
    let started = Instant::now();
    loop {
        let back = echo_through(session.connection(), echo.port(), &payload).await;
        assert_eq!(back, payload);
        let stats = rig.stats();
        if stats.to_client_datagrams.load(rel()) > 0 && stats.to_target_datagrams.load(rel()) > 0 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(40),
            "the datagram carrier never opened: to client {}, to target {}, outer room {:?}",
            stats.to_client_datagrams.load(rel()),
            stats.to_target_datagrams.load(rel()),
            rig.outer.max_datagram_size(),
        );
    }
    // And the channel still carries the inner connection intact.
    let back = echo_through(session.connection(), echo.port(), &payload).await;
    assert_eq!(back, payload);

    dialed.connection.close(0, b"done");
    drop(pump.finish().await);
    t.shutdown().await;
    rig.shutdown().await;
}

// ----------------------------------------------------------------------
// authorization comes before the socket
// ----------------------------------------------------------------------

/// Threat model B49: a pin without `forward.jump` gets `PERMISSION_DENIED`
/// from the inline decision, the decision is audited, and no socket or
/// channel ever exists.
#[tokio::test(flavor = "multi_thread")]
async fn jump_without_forward_jump_opens_no_socket() {
    let (target, port) = udp_target().await;
    for role in ["exec", "read-only", "reverse", "none"] {
        let rig = Rig::start(role, loopback_options(), false).await;
        let refused = rig
            .open(channel(1), LOOPBACK, port)
            .await
            .expect_err("the role has no forward.jump");
        assert_eq!(code_of(&refused), ErrorCode::PermissionDenied, "{role}");
        assert_eq!(
            refused.message,
            qsh_core::acl::PERMISSION_DENIED_MESSAGE,
            "{role}: the uniform message"
        );
        let audit = rig.jump_audit();
        assert_eq!(audit.len(), 1, "{role}: {audit:?}");
        assert_eq!(audit[0].decision, "deny", "{role}");
        assert_eq!(audit[0].resource, format!("{LOOPBACK}:{port}"));
        assert_eq!(rig.stats().opened.load(rel()), 0, "{role}");
        assert_eq!(rig.stats().live(), 0, "{role}");
        assert_eq!(rig.j.server.activity().jump_channels, 0, "{role}");
        // Nothing was ever sent toward the target.
        assert!(
            recv_within(&target, Duration::from_millis(150))
                .await
                .is_none()
        );
        rig.shutdown().await;
    }
    // The roles that have it open the channel.
    for role in ["full", "tunnel"] {
        let rig = Rig::start(role, loopback_options(), false).await;
        let ch = rig.open(channel(1), LOOPBACK, port).await;
        assert!(ch.is_ok(), "{role}");
        let audit = rig.jump_audit();
        assert_eq!(audit.len(), 1, "{role}");
        assert_eq!(audit[0].decision, "allow", "{role}");
        drop(ch);
        rig.shutdown().await;
    }
}

/// An audit sink that accepts records until told to fail.
#[derive(Default)]
struct FailingSink(std::sync::atomic::AtomicBool);

impl FailingSink {
    fn fail(&self) {
        self.0.store(true, rel());
    }
}

impl AuditSink for FailingSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        if self.0.load(rel()) {
            Err(AuditError::Degraded)
        } else {
            Ok(())
        }
    }
}

/// A failed audit write is a refusal, not a channel.
#[tokio::test(flavor = "multi_thread")]
async fn a_jump_the_audit_cannot_record_is_refused() {
    let client = make_identity();
    let sink = Arc::new(FailingSink::default());
    let j = LoopbackHarness::start_custom_with_audit_sink(
        Arc::new(AllowAllPinned),
        client.clone(),
        pinned(&client),
        sink.clone(),
    )
    .await;
    j.server.set_jump_options(loopback_options());
    let (outer, _ctl) = j.raw_session().await;
    let (_target, port) = udp_target().await;
    sink.fail();
    let refused = open_jump(&outer, channel(1), LOOPBACK, port)
        .await
        .expect_err("no durable record, no channel");
    assert_eq!(code_of(&refused), ErrorCode::PermissionDenied);
    assert_eq!(j.server.jump_stats().opened.load(rel()), 0);
    outer.close(0, b"done");
    j.shutdown().await;
}

/// Threat model B50: loopback, "this network", link-local, multicast and
/// the IPv4-mapped forms are never a jump target, whatever the role grants.
/// Each refusal is audited twice: the allow, then the filter's deny.
#[tokio::test(flavor = "multi_thread")]
async fn jump_refuses_host_local_targets() {
    // The filter is on: the default options.
    let rig = Rig::start("full", JumpOptions::default(), false).await;
    let hosts = [
        "127.0.0.1",
        "127.1.2.3",
        "0.0.0.0",
        "169.254.10.10",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "localhost",
    ];
    for (n, host) in hosts.iter().enumerate() {
        let refused = rig
            .open(channel(n as u8 + 1), host, 4433)
            .await
            .expect_err(host);
        assert_eq!(code_of(&refused), ErrorCode::PermissionDenied, "{host}");
        assert_eq!(
            refused.message,
            qsh_core::acl::PERMISSION_DENIED_MESSAGE,
            "{host}"
        );
    }
    let audit = rig.jump_audit();
    assert_eq!(audit.len(), hosts.len() * 2, "{audit:?}");
    for pair in audit.chunks(2) {
        assert_eq!(pair[0].decision, "allow");
        assert_eq!(pair[1].decision, "deny");
        assert_eq!(pair[1].rule, None, "no acl row decided the filter's deny");
        assert_eq!(pair[0].resource, pair[1].resource);
    }
    // Neither the audit nor the refusal text ever names a resolved address.
    let text = serde_json::to_string(&audit).unwrap();
    assert!(!text.contains("::ffff:7f"), "{text}");
    assert_eq!(rig.stats().opened.load(rel()), 0);
    assert_eq!(rig.stats().live(), 0);
    rig.shutdown().await;
}

/// Threat model D26: a name that resolves to an address the filter allows or
/// refuses leaves only the requested string in the audit.
#[tokio::test(flavor = "multi_thread")]
async fn jump_audit_and_logs_carry_no_payload() {
    let rig = Rig::start("full", loopback_options(), false).await;
    // `localhost` resolves to a loopback address; the filter is off, so the
    // channel opens. The audit holds the name, never the address.
    let ch = rig
        .open(channel(1), "localhost", 4433)
        .await
        .expect("localhost resolves");
    let audit = rig.jump_audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].resource, "localhost:4433");
    let text = serde_json::to_string(&audit).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    // `peer_addr` is the requester's own address, which is on loopback too;
    // every other field must be free of the resolved target.
    for record in value.as_array().unwrap() {
        let mut fields = record.as_object().unwrap().clone();
        fields.remove("peer_addr");
        let rest = serde_json::to_string(&fields).unwrap();
        for needle in ["127.0.0.1", "::1"] {
            assert!(!rest.contains(needle), "{needle} in {rest}");
        }
    }
    for record in value.as_array().unwrap() {
        for key in record.as_object().unwrap().keys() {
            assert!(
                [
                    "ts",
                    "request_id",
                    "principal",
                    "action",
                    "resource",
                    "decision",
                    "rule",
                    "auth_path",
                    "peer_addr",
                    "role",
                    "grant",
                    "count"
                ]
                .contains(&key.as_str()),
                "unexpected audit field {key}"
            );
        }
    }
    drop(ch);
    rig.shutdown().await;
}

// ----------------------------------------------------------------------
// shape
// ----------------------------------------------------------------------

/// A channel value that is not 16 bytes, one already in use, and a bad
/// destination are `INVALID_ARGUMENT` before the ACL: no audit line.
#[tokio::test(flavor = "multi_thread")]
async fn a_duplicate_jump_channel_is_invalid_argument_without_audit() {
    let rig = Rig::full().await;
    let (_target, port) = udp_target().await;
    let first = rig
        .open(channel(1), LOOPBACK, port)
        .await
        .expect("the first use");
    assert_eq!(rig.jump_audit().len(), 1);

    let again = rig
        .open(channel(1), LOOPBACK, port)
        .await
        .expect_err("a second use of the value");
    assert_eq!(code_of(&again), ErrorCode::InvalidArgument);
    assert_eq!(
        rig.jump_audit().len(),
        1,
        "the shape check runs before the ACL and writes nothing"
    );

    for (what, header) in [
        ("15 bytes", jump_header(&[3; 15], LOOPBACK, port)),
        ("17 bytes", jump_header(&[3; 17], LOOPBACK, port)),
        ("no channel", jump_header(&[], LOOPBACK, port)),
        ("port 0", jump_header(&[4; 16], LOOPBACK, 0)),
        ("empty host", jump_header(&[5; 16], "", port)),
        ("a space in the host", jump_header(&[6; 16], "a b", port)),
        ("a long host", jump_header(&[7; 16], &"a".repeat(256), port)),
    ] {
        let refused = open_jump_header(&rig.outer, &header).await.expect_err(what);
        assert_eq!(code_of(&refused), ErrorCode::InvalidArgument, "{what}");
    }
    assert_eq!(rig.jump_audit().len(), 1, "no shape failure was audited");
    assert_eq!(rig.stats().opened.load(rel()), 1);

    // The value is free again once its channel is gone.
    drop(first);
    until("the first channel to end", || rig.stats().live() == 0).await;
    let reused = rig.open(channel(1), LOOPBACK, port).await;
    assert!(reused.is_ok(), "{:?}", reused.err());
    drop(reused);
    rig.shutdown().await;
}

/// A connection that did not negotiate `jump.v1` gets no channel: the stream
/// is refused like any kind the host does not serve.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_without_jump_v1_gets_no_jump_stream() {
    let client = make_identity();
    let j =
        LoopbackHarness::start_custom(Arc::new(AllowAllPinned), client.clone(), pinned(&client))
            .await;
    j.server.set_jump_options(loopback_options());
    j.server.hide_capabilities(&[wire::CAP_JUMP_V1]);
    let (outer, _ctl) = j.raw_session().await;
    let (_target, port) = udp_target().await;
    let (send, recv) = outer.open_bi().await.unwrap();
    let mut send = FramedSend::data(send);
    send.send(&jump_header(&channel(1), LOOPBACK, port))
        .await
        .unwrap();
    let mut recv = FramedRecv::data(recv);
    let got = tokio::time::timeout(Duration::from_secs(5), recv.recv::<ConnectResult>())
        .await
        .expect("an answer");
    assert!(got.is_err() || matches!(got, Ok(None)), "{got:?}");
    assert!(j.audit.records().iter().all(|r| r.action != "forward.jump"));
    assert_eq!(j.server.jump_stats().opened.load(rel()), 0);
    outer.close(0, b"done");
    j.shutdown().await;
}

// ----------------------------------------------------------------------
// the QUIC gate and the connected socket
// ----------------------------------------------------------------------

/// ADR-0056 decision 8, B50: until the target answers like QUIC only
/// Initial-shaped packets go out, and a target that never does is cut off.
#[tokio::test(flavor = "multi_thread")]
async fn a_jump_forwards_only_quic_until_the_target_answers_like_quic() {
    let rig = Rig::full().await;
    let (target, port) = udp_target().await;
    let mut ch = rig.open(channel(1), LOOPBACK, port).await.unwrap();

    // Not QUIC: short header, garbage, a Handshake-type long header, an
    // Initial under 1200 bytes. None reaches the target.
    let mut handshake_type = initial(&[1; 4], 1300);
    handshake_type[0] = 0xE0;
    for packet in [
        short(1300),
        vec![0xFF; 40],
        handshake_type,
        initial(&[1; 4], 1100),
    ] {
        ch.send_packet(&packet).await;
    }
    assert!(
        recv_within(&target, Duration::from_millis(300))
            .await
            .is_none(),
        "a non-Initial packet reached the target"
    );
    until("the gate to drop four packets", || {
        rig.stats().gate_dropped.load(rel()) == 4
    })
    .await;

    // An Initial passes.
    let scid = [0x11, 0x22, 0x33, 0x44];
    let first = initial(&scid, 1200);
    ch.send_packet(&first).await;
    let (got, from) = recv_within(&target, Duration::from_secs(2))
        .await
        .expect("the Initial reached the target");
    assert_eq!(got, first);

    // The target speaks without answering like QUIC: nothing comes back.
    for junk in [short(200), vec![0xC0; 30], answer(&[9; 4])] {
        target.send_to(&junk, from).await.unwrap();
    }
    assert_eq!(
        ch.reader.next(Duration::from_millis(300)).await,
        Got::Silence,
        "a packet that does not answer the client's SCID opened the gate"
    );

    // The real answer opens it, and from then on everything flows both ways.
    let reply = answer(&scid);
    target.send_to(&reply, from).await.unwrap();
    assert_eq!(
        ch.reader.next(Duration::from_secs(2)).await,
        Got::Packet(reply)
    );
    let data = short(700);
    ch.send_packet(&data).await;
    assert_eq!(
        recv_within(&target, Duration::from_secs(2))
            .await
            .map(|r| r.0),
        Some(data.clone())
    );
    target.send_to(&data, from).await.unwrap();
    assert_eq!(
        ch.reader.next(Duration::from_secs(2)).await,
        Got::Packet(data)
    );
    drop(ch);
    rig.shutdown().await;
}

/// The pregate caps: eight Initial-shaped packets, then nothing more until
/// the target answers.
#[tokio::test(flavor = "multi_thread")]
async fn the_pregate_caps_hold_on_a_real_channel() {
    let rig = Rig::full().await;
    let (target, port) = udp_target().await;
    let mut ch = rig.open(channel(1), LOOPBACK, port).await.unwrap();
    for n in 0..12u8 {
        ch.send_packet(&initial(&[n; 4], 1452)).await;
    }
    let mut arrived = 0;
    while recv_within(&target, Duration::from_millis(300))
        .await
        .is_some()
    {
        arrived += 1;
    }
    assert_eq!(arrived, qsh_proto::jump::JUMP_PREGATE_PACKETS);
    assert_eq!(rig.stats().gate_dropped.load(rel()), 4);
    assert_eq!(rig.stats().to_target_packets.load(rel()), 8);
    drop(ch);
    rig.shutdown().await;
}

/// Threat model C28: J sends toward T no more than C sent it, and what it
/// sends back is only what T sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_jump_never_sends_more_than_it_received() {
    let rig = Rig::full().await;
    let (target, port) = udp_target().await;
    let mut ch = rig.open(channel(1), LOOPBACK, port).await.unwrap();
    let scid = [5; 4];
    let mut sent_by_client = 0usize;
    let mut seen_by_target = 0usize;
    let mut from = None;
    // Eleven Initials: the gate passes eight.
    for n in 0..11u8 {
        let p = initial(&[n.max(5); 4], 1300 + usize::from(n));
        sent_by_client += p.len();
        ch.send_packet(&p).await;
    }
    while let Some((p, f)) = recv_within(&target, Duration::from_millis(250)).await {
        seen_by_target += p.len();
        from = Some(f);
    }
    let from = from.expect("some Initials passed");
    assert!(seen_by_target <= sent_by_client);
    assert_eq!(
        rig.stats().to_target_bytes.load(rel()) as usize,
        seen_by_target
    );
    // The target answers; the client sends short packets; nothing is added.
    target.send_to(&answer(&[5; 4]), from).await.unwrap();
    let _ = scid;
    assert!(matches!(
        ch.reader.next(Duration::from_secs(2)).await,
        Got::Packet(_)
    ));
    for _ in 0..20 {
        let p = short(100);
        sent_by_client += p.len();
        ch.send_packet(&p).await;
    }
    while let Some((p, _)) = recv_within(&target, Duration::from_millis(250)).await {
        seen_by_target += p.len();
    }
    assert!(seen_by_target <= sent_by_client);
    assert_eq!(
        rig.stats().to_target_bytes.load(rel()) as usize,
        seen_by_target,
        "J's count equals what the target saw"
    );
    drop(ch);
    rig.shutdown().await;
}

/// Threat model B51: the socket is `connect`ed, so a datagram from any other
/// source on the channel's port is dropped by the kernel.
#[tokio::test(flavor = "multi_thread")]
async fn a_jump_socket_drops_datagrams_from_other_sources() {
    let rig = Rig::full().await;
    let (target, port) = udp_target().await;
    let mut ch = rig.open(channel(1), LOOPBACK, port).await.unwrap();
    let scid = [0x21; 4];
    ch.send_packet(&initial(&scid, 1200)).await;
    let (_, j_socket) = recv_within(&target, Duration::from_secs(2)).await.unwrap();
    // Open the gate with the real target.
    target.send_to(&answer(&scid), j_socket).await.unwrap();
    assert!(matches!(
        ch.reader.next(Duration::from_secs(2)).await,
        Got::Packet(_)
    ));
    // A stranger sends to J's socket, QUIC-shaped and not.
    let stranger = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    for p in [answer(&scid), short(300), initial(&scid, 1200)] {
        stranger.send_to(&p, j_socket).await.unwrap();
    }
    assert_eq!(
        ch.reader.next(Duration::from_millis(400)).await,
        Got::Silence,
        "a packet from another source reached the client"
    );
    assert_eq!(rig.stats().to_client_packets.load(rel()), 1);
    // The real target still gets through.
    target.send_to(&short(64), j_socket).await.unwrap();
    assert!(matches!(
        ch.reader.next(Duration::from_secs(2)).await,
        Got::Packet(_)
    ));
    drop(ch);
    rig.shutdown().await;
}

/// DoD 25.11, `unreachable`: a closed UDP port answers the first Initial with
/// an ICMP refusal, and the stream is reset in well under a second (Linux
/// `ECONNREFUSED`, Windows `WSAECONNRESET`) instead of waiting for the gate.
#[tokio::test(flavor = "multi_thread")]
async fn jump_target_refusal_is_reported_fast() {
    let rig = Rig::full().await;
    // A port nothing holds: bind, note, close.
    let (socket, port) = udp_target().await;
    drop(socket);
    let mut ch = rig.open(channel(1), LOOPBACK, port).await.unwrap();
    let started = Instant::now();
    ch.send_packet(&initial(&[1; 4], 1200)).await;
    let got = ch.reader.next(Duration::from_secs(5)).await;
    let took = started.elapsed();
    assert_eq!(got, Got::Ended(Some(0x2007)), "after {took:?}");
    assert!(took < Duration::from_secs(1), "reported after {took:?}");
    until("the channel to be torn down", || rig.stats().live() == 0).await;
    assert_eq!(rig.stats().close_reasons(), [CloseReason::Unreachable]);
    drop(ch);
    rig.shutdown().await;
}

// ----------------------------------------------------------------------
// bounds and lifetime
// ----------------------------------------------------------------------

/// Threat model C27: sixteen channels per connection, the tunnel-stream
/// quota, the gate's ten seconds (shortened here).
#[tokio::test(flavor = "multi_thread")]
async fn jump_bounds() {
    let rig = Rig::full().await;
    let (_target, port) = udp_target().await;
    let mut open = Vec::new();
    for n in 0..qsh_core::jump::MAX_JUMP_CHANNELS_PER_CONN {
        open.push(
            rig.open(channel(n as u8 + 1), LOOPBACK, port)
                .await
                .unwrap_or_else(|e| panic!("channel {n}: {e:?}")),
        );
    }
    assert_eq!(rig.stats().live(), 16);
    assert_eq!(rig.j.server.activity().jump_channels, 16);
    let over = rig
        .open(channel(100), LOOPBACK, port)
        .await
        .expect_err("the 17th");
    assert_eq!(code_of(&over), ErrorCode::ResourceExhausted);
    assert_eq!(rig.stats().live(), 16, "a refused channel holds no slot");
    // The refusal came after the decision: it was audited as an allow.
    let audit = rig.jump_audit();
    assert_eq!(audit.len(), 17);
    assert_eq!(audit[16].decision, "allow");
    // A slot frees when its stream ends.
    open.pop();
    until("a slot to free", || rig.stats().live() == 15).await;
    let again = rig.open(channel(100), LOOPBACK, port).await;
    assert!(again.is_ok(), "{:?}", again.err());
    drop((open, again));
    rig.shutdown().await;
}

/// A `JUMP` stream is a tunnel stream for the quota (ADR-0056 decision 9,
/// ADR-0010): the per-forward cap counts jump channels to one target.
#[tokio::test(flavor = "multi_thread")]
async fn jump_streams_count_against_the_tunnel_stream_quota() {
    let client = make_identity();
    let roles = roles(&client, "full");
    let limits = qsh_core::quota::QuotaLimits {
        max_tunnel_streams_per_forward: 2,
        ..Default::default()
    };
    let j = LoopbackHarness::start_custom_with_quotas(
        Arc::clone(&roles.authorizer),
        client.clone(),
        pinned(&client),
        limits,
    )
    .await;
    j.server.set_jump_options(loopback_options());
    let (outer, _ctl) = j.raw_session().await;
    let (_target, port) = udp_target().await;
    let a = open_jump(&outer, channel(1), LOOPBACK, port).await.unwrap();
    let b = open_jump(&outer, channel(2), LOOPBACK, port).await.unwrap();
    let c = open_jump(&outer, channel(3), LOOPBACK, port)
        .await
        .expect_err("the third stream to one target");
    assert_eq!(code_of(&c), ErrorCode::ResourceExhausted);
    // Another target is a different forward.
    let (_other, other_port) = udp_target().await;
    let d = open_jump(&outer, channel(4), LOOPBACK, other_port).await;
    assert!(d.is_ok());
    drop((a, b, d));
    outer.close(0, b"done");
    j.shutdown().await;
}

/// A gate that never opens closes the channel (ten seconds in production).
#[tokio::test(flavor = "multi_thread")]
async fn a_channel_whose_gate_never_opens_is_closed() {
    let options = JumpOptions {
        gate_timeout: Duration::from_millis(400),
        ..loopback_options()
    };
    let rig = Rig::start("full", options, false).await;
    let (target, port) = udp_target().await;
    let mut ch = rig.open(channel(1), LOOPBACK, port).await.unwrap();
    ch.send_packet(&initial(&[1; 4], 1200)).await;
    assert!(recv_within(&target, Duration::from_secs(1)).await.is_some());
    // The target is silent.
    let started = Instant::now();
    let got = ch.reader.next(Duration::from_secs(5)).await;
    assert_eq!(got, Got::Ended(Some(0x2007)));
    assert!(started.elapsed() < Duration::from_secs(3));
    until("the channel to close", || rig.stats().live() == 0).await;
    assert_eq!(rig.stats().close_reasons(), [CloseReason::GateTimeout]);
    drop(ch);
    rig.shutdown().await;
}

/// DoD 25.8: a channel with no forwarded packet for the idle time closes
/// with its socket; the channel value is free again.
#[tokio::test(flavor = "multi_thread")]
async fn jump_idle_closes_the_channel_and_the_socket() {
    let options = JumpOptions {
        idle: Duration::from_millis(500),
        ..loopback_options()
    };
    let rig = Rig::start("full", options, false).await;
    let (target, port) = udp_target().await;
    let mut ch = rig.open(channel(1), LOOPBACK, port).await.unwrap();
    let scid = [3; 4];
    ch.send_packet(&initial(&scid, 1200)).await;
    let (_, from) = recv_within(&target, Duration::from_secs(2)).await.unwrap();
    target.send_to(&answer(&scid), from).await.unwrap();
    assert!(matches!(
        ch.reader.next(Duration::from_secs(2)).await,
        Got::Packet(_)
    ));
    // Activity keeps it alive past one idle period.
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        ch.send_packet(&short(100)).await;
    }
    assert_eq!(rig.stats().live(), 1);
    // Then silence.
    let started = Instant::now();
    let got = ch.reader.next(Duration::from_secs(5)).await;
    assert_eq!(got, Got::Ended(Some(0x2007)));
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "{:?}",
        started.elapsed()
    );
    until("the table to empty", || rig.stats().live() == 0).await;
    assert_eq!(rig.stats().close_reasons(), [CloseReason::Idle]);
    assert_eq!(rig.j.server.activity().jump_channels, 0);
    // The socket is gone: a packet to J's old port finds nobody (and the
    // value can be claimed again).
    let again = rig.open(channel(1), LOOPBACK, port).await;
    assert!(again.is_ok());
    drop((ch, again));
    rig.shutdown().await;
}

/// Cleanup: the client's reset, the client's FIN and a closed connection each
/// end the channel and release its slot.
#[tokio::test(flavor = "multi_thread")]
async fn a_jump_channel_ends_with_its_stream_and_with_its_connection() {
    let rig = Rig::full().await;
    let (_target, port) = udp_target().await;

    let mut by_reset = rig.open(channel(1), LOOPBACK, port).await.unwrap();
    by_reset
        .send
        .reset(qsh_transport::StreamCode::from_u32(0x2007))
        .unwrap();
    until("the reset to end the channel", || rig.stats().live() == 0).await;

    let mut by_fin = rig.open(channel(2), LOOPBACK, port).await.unwrap();
    by_fin.send.finish().unwrap();
    until("the FIN to end the channel", || rig.stats().live() == 0).await;
    assert_eq!(
        by_fin.reader.next(Duration::from_secs(2)).await,
        Got::Ended(None),
        "a FIN is answered with a FIN"
    );

    let _third = rig.open(channel(3), LOOPBACK, port).await.unwrap();
    assert_eq!(rig.stats().live(), 1);
    rig.outer.close(0, b"gone");
    until("the connection close to end the channel", || {
        rig.stats().live() == 0
    })
    .await;
    assert_eq!(rig.j.server.activity().jump_channels, 0);
    assert_eq!(rig.stats().opened.load(rel()), 3);
    assert_eq!(rig.stats().closed.load(rel()), 3);
    drop((by_reset, by_fin));
    rig.shutdown().await;
}

/// A stream carrier frame with a bad length ends the channel with
/// `BAD_HEADER` (`0x2001`).
#[tokio::test(flavor = "multi_thread")]
async fn a_bad_frame_length_resets_the_channel_with_bad_header() {
    let rig = Rig::full().await;
    let (_target, port) = udp_target().await;
    let mut ch = rig.open(channel(1), LOOPBACK, port).await.unwrap();
    let too_long = u16::try_from(JUMP_PACKET_MAX + 1).unwrap();
    ch.send.write_all(&too_long.to_be_bytes()).await.unwrap();
    let got = ch.reader.next(Duration::from_secs(3)).await;
    assert_eq!(got, Got::Ended(Some(0x2001)));
    until("the channel to close", || rig.stats().live() == 0).await;
    assert_eq!(rig.stats().close_reasons(), [CloseReason::BadFrame]);
    drop(ch);
    rig.shutdown().await;
}

// ----------------------------------------------------------------------
// ADR-0051 decision 2: the on-demand serve counts live jump channels
// ----------------------------------------------------------------------

/// A real `qsh serve --on-demand` (the production `run_serve_with`), a client
/// that holds a jump channel, and an idle limit far shorter than the test:
/// the serve stays up while the channel lives and drains after it ends.
#[tokio::test(flavor = "multi_thread")]
async fn on_demand_serve_stays_up_while_a_jump_channel_lives() {
    use qsh_core::config::Config;
    use qsh_core::identity;
    use qsh_core::serve::{OnDemandOptions, run_serve_with};
    use qsh_proto::KeyStoreMode;

    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    identity::init(&paths, KeyStoreMode::File).unwrap();
    let host_identity = identity::load(&paths).unwrap().unwrap();
    let host_fp = host_identity.identity.fingerprint;
    let client = make_identity();
    std::fs::write(
        paths.trust_file(),
        format!(
            "[[peer]]\nname = \"laptop\"\nfingerprint = \"{}\"\naddress = \"\"\n\
             added_at = \"2026-11-09T00:00:00Z\"\nrole = \"full\"\n",
            client.fingerprint
        ),
    )
    .unwrap();
    let mut config = Config::default();
    config.serve.on_demand_idle_ms = Some(400);
    let options = OnDemandOptions {
        fallback_ports: 0..=0,
        ..OnDemandOptions::from_config(&config).unwrap()
    };
    let (bound_tx, bound_rx) = oneshot::channel();
    let server_slot = Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&server_slot);
    let serve_paths = paths.clone();
    let mut serve = tokio::spawn(async move {
        run_serve_with(
            &serve_paths,
            &config,
            host_identity,
            "127.0.0.1:0".parse().unwrap(),
            Some(options),
            move |addr| {
                let _ = bound_tx.send(addr);
            },
            move |runtime| {
                runtime.server.set_jump_options(loopback_options());
                *slot.lock().unwrap() = Some(Arc::clone(&runtime.server));
            },
            |_| {},
            std::future::pending(),
        )
        .await
    });
    let addr = tokio::time::timeout(Duration::from_secs(10), bound_rx)
        .await
        .expect("bound")
        .expect("address");
    let server = server_slot.lock().unwrap().clone().expect("the server");

    let dialer = Dialer::new(
        client.local.clone(),
        Arc::new(StaticTrust::empty().with_pin(host_fp, Principal::Device("box".into()))),
    );
    let dialed = dialer.dial(addr, LOOPBACK).await.expect("dial the serve");
    let (_ctl_session, ch) = {
        let session = Session::negotiate(dialed.connection.clone(), "laptop")
            .await
            .expect("Hello");
        let (_target, port) = udp_target().await;
        let ch = open_jump(&dialed.connection, channel(1), LOOPBACK, port)
            .await
            .expect("the serve admits the jump");
        std::mem::forget(_target);
        (session, ch)
    };
    assert_eq!(server.activity().jump_channels, 1);

    // Several idle limits pass; the serve is still there.
    assert!(
        tokio::time::timeout(Duration::from_millis(1600), &mut serve)
            .await
            .is_err(),
        "the serve exited while a jump channel was live"
    );
    assert_eq!(server.activity().jump_channels, 1);

    // The channel and the connection end; then the idle limit applies.
    drop(ch);
    dialed.connection.close(0, b"done");
    let exited = tokio::time::timeout(Duration::from_secs(10), &mut serve).await;
    assert!(
        exited.is_ok(),
        "the serve never drained after the channel ended"
    );
}
