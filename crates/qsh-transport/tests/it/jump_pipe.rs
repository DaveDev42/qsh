//! `PacketPipe` + `Dialer::dial_over_pipe` against a real `Listener`
//! (ADR-0056 decisions 2, 5 and 6; ADR-0057). A small relay task stands in for
//! the jump hop: it carries the pipe's packets to the server's UDP socket and
//! back. The packet limit is set on the pipe, which is what a smaller outer
//! datagram size would do.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_transport::{
    CertificateDer, DialError, Dialed, Dialer, Fingerprint, JUMP_PACKET_MAX, JUMP_PACKET_MIN,
    Listener, LocalIdentity, PIPE_REMOTE_ADDR, PacketPipe, PipePeer, Principal, RejectReason,
    StaticTrust,
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

fn make_identity() -> (LocalIdentity, Fingerprint) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let fp = Fingerprint::of_cert_der(&der).unwrap();
    (
        LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        },
        fp,
    )
}

/// Carries the pipe's packets to `server` and the replies back, until told
/// to stop. Returns the peer so the test can read its counters.
fn spawn_relay(
    mut peer: PipePeer,
    server: SocketAddr,
) -> (oneshot::Sender<()>, JoinHandle<PipePeer>) {
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(server).await.unwrap();
        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                pkt = peer.recv() => match pkt {
                    Some(p) => { let _ = udp.send(&p).await; }
                    None => break,
                },
                n = udp.recv(&mut buf) => {
                    if let Ok(n) = n {
                        peer.send(buf[..n].to_vec());
                    }
                }
            }
        }
        peer
    });
    (stop_tx, handle)
}

struct Rig {
    dialed: Dialed,
    stop: oneshot::Sender<()>,
    relay: JoinHandle<PipePeer>,
    server: JoinHandle<()>,
}

/// A server that echoes the first bidi stream it is given, a client dialed
/// over a pipe with `limit`, and the relay between them.
async fn rig(limit: usize) -> Rig {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("box".into()));
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_id,
        Arc::new(server_trust),
    )
    .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let conn = listener
            .accept()
            .await
            .expect("one connection")
            .accept()
            .await
            .expect("handshake");
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(Some(n)) = recv.read(&mut buf).await {
            if send.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
        let _ = send.finish();
        let _ = conn.closed().await;
    });

    let (pipe, peer) = PacketPipe::new(256);
    peer.set_packet_limit(limit);
    let (stop, relay) = spawn_relay(peer, addr);
    let dialed = Dialer::new(client_id, Arc::new(client_trust))
        .with_timeout(Duration::from_secs(10))
        .dial_over_pipe(pipe, "jump-inner")
        .await
        .expect("dial over pipe");
    Rig {
        dialed,
        stop,
        relay,
        server,
    }
}

impl Rig {
    async fn finish(self) -> qsh_transport::PipeStats {
        self.dialed.connection.close(0, b"done");
        let _ = self.stop.send(());
        let peer = self.relay.await.unwrap();
        self.server.abort();
        peer.stats()
    }
}

/// Runs echo round trips until the path MTU exceeds the floor or `budget`
/// passes. Returns `(path_mtu, elapsed)`.
async fn drive_until_mtu_rises(
    rig: &Rig,
    send: &mut qsh_transport::SendStream,
    recv: &mut qsh_transport::RecvStream,
    budget: Duration,
) -> (u16, Duration) {
    let chunk = vec![0x5au8; 16 * 1024];
    let mut back = vec![0u8; chunk.len()];
    let start = Instant::now();
    loop {
        send.write_all(&chunk).await.unwrap();
        recv.read_exact(&mut back).await.unwrap();
        let mtu = rig.dialed.connection.stats().path_mtu;
        if mtu > JUMP_PACKET_MIN || start.elapsed() >= budget {
            return (mtu, start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_over_a_pipe_reaches_a_real_server_and_echoes() {
    let rig = rig(usize::from(JUMP_PACKET_MAX)).await;
    assert_eq!(rig.dialed.connection.remote_address(), PIPE_REMOTE_ADDR);
    let (mut send, mut recv) = rig.dialed.connection.open_bi().await.unwrap();
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    send.write_all(&payload).await.unwrap();
    send.finish().unwrap();
    let back = recv.read_to_end(1 << 20).await.unwrap();
    assert_eq!(back, payload);
    let stats = rig.finish().await;
    assert!(stats.out_queued > 100 && stats.in_queued > 100, "{stats:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn plpmtud_rises_over_a_pipe_with_a_1452_limit() {
    let rig = rig(usize::from(JUMP_PACKET_MAX)).await;
    // No equality with the floor here: PLPMTUD's first probe leaves right
    // after the handshake, so on a slow runner (ubuntu CI run 42610470096
    // read 1389) it has already risen by the time the dial returns.
    assert!(rig.dialed.connection.stats().path_mtu >= JUMP_PACKET_MIN);
    let (mut send, mut recv) = rig.dialed.connection.open_bi().await.unwrap();
    let (mtu, took) =
        drive_until_mtu_rises(&rig, &mut send, &mut recv, Duration::from_secs(20)).await;
    // Keep traffic going so any follow-up probe can settle, then read the final value.
    for _ in 0..50 {
        let (_, _) = drive_until_mtu_rises(&rig, &mut send, &mut recv, Duration::ZERO).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let settled = rig.dialed.connection.stats().path_mtu;
    eprintln!("pipe limit 1452: first rise to {mtu} after {took:?}, settled at {settled}");
    assert!(mtu > JUMP_PACKET_MIN, "PLPMTUD never rose: {mtu}");
    assert!(
        (1400..=JUMP_PACKET_MAX).contains(&settled),
        "settled at {settled}"
    );
    let stats = rig.finish().await;
    eprintln!("pipe limit 1452 stats: {stats:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn plpmtud_stays_at_1200_over_a_pipe_with_a_1200_limit() {
    let rig = rig(usize::from(JUMP_PACKET_MIN)).await;
    let (mut send, mut recv) = rig.dialed.connection.open_bi().await.unwrap();
    let (mtu, took) =
        drive_until_mtu_rises(&rig, &mut send, &mut recv, Duration::from_secs(8)).await;
    eprintln!("pipe limit 1200: path_mtu {mtu} after {took:?}");
    assert_eq!(mtu, JUMP_PACKET_MIN);
    let stats = rig.finish().await;
    eprintln!("pipe limit 1200 stats: {stats:?}");
    assert!(
        stats.out_dropped_oversize > 0,
        "the probes above the limit must have been dropped (and so learned from): {stats:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pin_mismatch_over_a_pipe_fails_like_a_normal_dial() {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let (_, decoy_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_id,
        Arc::new(server_trust),
    )
    .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // Never delivers an application connection; keep accepting.
        while let Some(incoming) = listener.accept().await {
            let _ = incoming.accept().await;
        }
    });
    let wrong = || StaticTrust::empty().with_pin(decoy_fp, Principal::Device("box".into()));

    let normal = Dialer::new(client_id.clone(), Arc::new(wrong()))
        .dial(addr, "127.0.0.1")
        .await;
    let (pipe, peer) = PacketPipe::new(256);
    let (stop, relay) = spawn_relay(peer, addr);
    let piped = Dialer::new(client_id, Arc::new(wrong()))
        .dial_over_pipe(pipe, "jump-inner")
        .await;
    let _ = stop.send(());
    let _ = relay.await;
    server.abort();

    for (label, result) in [("normal", normal), ("pipe", piped)] {
        match result {
            Err(DialError::LocalRejected { reason, observed }) => {
                assert_eq!(reason, RejectReason::Untrusted, "{label}");
                assert_eq!(observed, Some(server_fp), "{label}");
            }
            other => panic!("{label}: expected LocalRejected{{Untrusted}}, got {other:?}"),
        }
    }
}
