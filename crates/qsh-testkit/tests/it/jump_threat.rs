//! The tests ADR-0056 decisions 24 and 25 name for the threat model rows E27
//! (integrity of the inner packets) and F7 (who went through where), and for
//! the client chain's refusal to open a `JUMP` stream on a hop without
//! `jump.v1`. The bootstrap one lives in `qsh-cli`
//! (`bootstrap_records_proxyjump_as_the_pin_jump`).
//!
//! The tampering relay is test-side only: it stands where the target is, so
//! it sees and rewrites exactly the datagrams the middle peer's connected
//! socket sends and receives. No product hook is involved.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use qsh_core::client::Session;
use qsh_core::jump::{HopPin, JumpPlan, Stage};
use qsh_proto::ErrorCode;
use qsh_proto::wire::{CAP_JUMP_V1, ConnectResult, StreamHeader, StreamKind};
use qsh_testkit::tunnel::EchoServer;
use qsh_transport::{Connection, FramedRecv, FramedSend};
use tokio::net::UdpSocket;

use super::jump_chain::{Direct, Net, blocking, expect_failure, nothing_ran_on};

const LOOPBACK: &str = "127.0.0.1";

// ----------------------------------------------------------------------
// E27: a middle peer that alters inner packets
// ----------------------------------------------------------------------

/// Which packets the relay damages.
#[derive(Clone, Copy)]
enum Damage {
    /// Every `n`th packet, in each direction.
    EveryNth(u64),
    /// Every packet.
    All,
}

/// A UDP relay between J's socket and the real target that flips one bit in
/// the middle of the datagrams it chooses, in both directions.
struct Tamper {
    port: u16,
    flipped: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl Tamper {
    async fn start(target: SocketAddr, damage: Damage) -> Self {
        let near = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let far = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        far.connect(target).await.expect("connect");
        let port = near.local_addr().expect("addr").port();
        let flipped = Arc::new(AtomicU64::new(0));
        let task = {
            let flipped = Arc::clone(&flipped);
            tokio::spawn(async move {
                let mut j: Option<SocketAddr> = None;
                let mut a = vec![0u8; 4096];
                let mut b = vec![0u8; 4096];
                let (mut up, mut down) = (0u64, 0u64);
                let hit = |count: &mut u64, packet: &mut [u8]| {
                    *count += 1;
                    let take = match damage {
                        Damage::All => true,
                        Damage::EveryNth(n) => (*count).is_multiple_of(n),
                    };
                    if take && !packet.is_empty() {
                        let at = packet.len() / 2;
                        packet[at] ^= 0x01;
                        flipped.fetch_add(1, Ordering::Relaxed);
                    }
                };
                loop {
                    tokio::select! {
                        got = near.recv_from(&mut a) => {
                            let Ok((n, from)) = got else { return };
                            j = Some(from);
                            hit(&mut up, &mut a[..n]);
                            let _ = far.send(&a[..n]).await;
                        }
                        got = far.recv(&mut b) => {
                            let Ok(n) = got else { continue };
                            hit(&mut down, &mut b[..n]);
                            if let Some(j) = j {
                                let _ = near.send_to(&b[..n], j).await;
                            }
                        }
                    }
                }
            })
        };
        Self {
            port,
            flipped,
            task,
        }
    }
}

/// A `TCP_CONNECT` echo to `port` on the end host through `conn`; `Err` is a
/// failed connection or stream, `Ok` is whatever bytes came back.
async fn echo_through(conn: &Connection, port: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
    let (send, recv) = conn.open_bi().await.map_err(|e| format!("open: {e}"))?;
    let mut send = FramedSend::data(send);
    send.send(&StreamHeader {
        kind: StreamKind::TcpConnect as i32,
        ticket: Vec::new(),
        host: LOOPBACK.to_string(),
        port: u32::from(port),
        deny_host_local: false,
    })
    .await
    .map_err(|e| format!("header: {e}"))?;
    let mut recv = FramedRecv::data(recv);
    let result: ConnectResult = recv
        .recv()
        .await
        .map_err(|e| format!("result: {e}"))?
        .ok_or("no result")?;
    if !result.ok {
        return Err(format!("refused: {result:?}"));
    }
    let (mut recv, _residue) = recv.into_raw();
    let mut send = send.into_raw();
    let payload = payload.to_vec();
    let writer = tokio::spawn(async move {
        send.write_all(&payload).await.map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())
    });
    let back = recv
        .read_to_end(8 << 20)
        .await
        .map_err(|e| format!("read: {e}"))?;
    writer.await.map_err(|e| e.to_string())??;
    Ok(back)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A plan `j -> t` whose end is reached at `address` (the relay) instead of
/// its own socket.
fn plan_via(d: &Direct, address: String) -> JumpPlan {
    let j = d.host("j").pin();
    let t = d.host("t").pin();
    JumpPlan::new(
        vec![j],
        HopPin {
            name: t.name.clone(),
            address,
            fingerprint: t.fingerprint,
        },
        None,
        "laptop".into(),
    )
    .expect("a valid plan")
}

/// ADR-0056 decision 2 and 24, E27: J forwards inner packets without reading
/// them, so one that J (or the path behind it) alters is dropped by the end's
/// own QUIC AEAD. Part one damages a fifth of the packets in both directions:
/// the session still works and carries exactly the bytes sent. Part two
/// damages every packet: the inner connection never comes up and the end
/// runs nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inner_packets_altered_by_a_jump_are_dropped_by_the_end() {
    // Part one: some packets damaged.
    {
        let d = Direct::start(&["j", "t"]).await;
        let tamper = Tamper::start(d.host("t").h.host_addr, Damage::EveryNth(5)).await;
        let plan = plan_via(&d, format!("127.0.0.1:{}", tamper.port));
        let chain = d
            .dial(&plan, Duration::from_secs(30))
            .await
            .expect("a damaged fifth is retransmitted, the chain comes up");
        let session = Session::negotiate(chain.connection.clone(), "laptop")
            .await
            .expect("Hello through the damaged path");
        let echo = EchoServer::start().await.expect("echo");
        let payload = pattern(200_000);
        let back = echo_through(session.connection(), echo.port(), &payload)
            .await
            .expect("the stream survives dropped packets");
        assert_eq!(back.len(), payload.len(), "truncated or padded");
        assert!(back == payload, "corrupted data reached the application");
        let flipped = tamper.flipped.load(Ordering::Relaxed);
        assert!(flipped > 20, "the relay damaged only {flipped} packets");
        // The end is intact: the one session is still its own.
        drop(session);
        chain.connection.close(0, b"done");
        tamper.task.abort();
        d.shutdown().await;
    }

    // Part two: every packet damaged.
    {
        let d = Direct::start(&["j", "t"]).await;
        let tamper = Tamper::start(d.host("t").h.host_addr, Damage::All).await;
        let plan = plan_via(&d, format!("127.0.0.1:{}", tamper.port));
        let started = std::time::Instant::now();
        let err = d
            .dial(&plan, Duration::from_secs(4))
            .await
            .expect_err("no inner connection can form when every packet is altered");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "failed late: {:?}",
            started.elapsed()
        );
        assert!(!err.message.is_empty());
        assert!(tamper.flipped.load(Ordering::Relaxed) > 0);
        nothing_ran_on(d.host("t"));
        tamper.task.abort();
        d.shutdown().await;
    }
}

// ----------------------------------------------------------------------
// F7: the audit on both hops
// ----------------------------------------------------------------------

/// ADR-0056 decision 19 and 25, F7: on `c -> a -> b -> t` each middle peer
/// writes a `forward.jump` record naming the requester, `device:laptop`, and
/// the target it was asked for (`a`: b, `b`: t). The inner connections are
/// end to end, so `b` and `t` see the client's own principal, never `a`'s or
/// `b`'s; `t` writes no `forward.jump`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_audit_names_the_requester_on_both_hops() {
    let net = Net::start(&["a", "b", "t"]).await;
    let ops = net.via(&["a", "b"]);
    let req = qsh_proto::ExecRunReq {
        host: "t".into(),
        argv: vec!["sh".into(), "-c".into(), "echo f7".into()],
        env: vec![],
        timeout_ms: Some(30_000),
    };
    let out = blocking(move || ops.exec_run(req, qsh_core::ExecStdin::Closed))
        .await
        .expect("exec through two hops");
    assert_eq!(out.data.remote_exit_code, 0);

    let jumps = |name: &str| {
        net.host(name)
            .h
            .audit
            .records()
            .into_iter()
            .filter(|r| r.action == "forward.jump")
            .collect::<Vec<_>>()
    };
    for (hop, next) in [("a", "b"), ("b", "t")] {
        let records = jumps(hop);
        assert!(!records.is_empty(), "{hop} wrote no forward.jump record");
        let port = net.host(next).h.addr.port();
        for r in &records {
            assert_eq!(r.decision, "allow", "{hop}: {r:?}");
            assert_eq!(r.principal, "device:laptop", "{hop}: {r:?}");
            assert!(
                r.resource.ends_with(&format!(":{port}")),
                "{hop} should name {next}'s port {port}: {r:?}"
            );
        }
    }
    // The end sees the same requester on what it ran, and no jump of its own.
    let t_records = net.host("t").h.audit.records();
    assert!(t_records.iter().all(|r| r.action != "forward.jump"));
    let ran: Vec<_> = t_records
        .iter()
        .filter(|r| r.action.starts_with("exec"))
        .collect();
    assert!(!ran.is_empty(), "t audited no exec: {t_records:?}");
    assert!(
        ran.iter().all(|r| r.principal == "device:laptop"),
        "{ran:?}"
    );
    // The middle peers never mistake each other for the requester.
    for r in net.host("b").h.audit.records() {
        assert_ne!(r.principal, "device:a", "{r:?}");
    }
    net.shutdown().await;
}

// ----------------------------------------------------------------------
// decision 12: a hop without jump.v1
// ----------------------------------------------------------------------

/// ADR-0056 decision 12: a hop that does not advertise `jump.v1` is stage
/// `unsupported` and the chain never opens a `JUMP` stream on it, whether it
/// is the first hop or a later one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hop_without_jump_v1_gets_no_jump_stream() {
    // The only hop lacks it.
    {
        let d = Direct::start(&["j", "t"]).await;
        d.host("j").h.server.hide_capabilities(&[CAP_JUMP_V1]);
        let err = d
            .dial(&d.plan(&["j", "t"]), Duration::from_secs(5))
            .await
            .expect_err("no jump.v1");
        expect_failure(&err, 2, 2, "t", Stage::Unsupported, ErrorCode::Unsupported);
        let j = d.host("j");
        assert_eq!(j.h.server.jump_stats().opened.load(Ordering::Relaxed), 0);
        assert!(
            j.h.audit
                .records()
                .iter()
                .all(|r| r.action != "forward.jump")
        );
        nothing_ran_on(d.host("t"));
        d.shutdown().await;
    }
    // The second of two hops lacks it: the first carries one channel, to it.
    {
        let d = Direct::start(&["a", "b", "t"]).await;
        d.host("b").h.server.hide_capabilities(&[CAP_JUMP_V1]);
        let err = d
            .dial(&d.plan(&["a", "b", "t"]), Duration::from_secs(5))
            .await
            .expect_err("no jump.v1 on b");
        expect_failure(&err, 3, 3, "t", Stage::Unsupported, ErrorCode::Unsupported);
        assert_eq!(
            d.host("a")
                .h
                .server
                .jump_stats()
                .opened
                .load(Ordering::Relaxed),
            1
        );
        let b = d.host("b");
        assert_eq!(b.h.server.jump_stats().opened.load(Ordering::Relaxed), 0);
        assert!(
            b.h.audit
                .records()
                .iter()
                .all(|r| r.action != "forward.jump")
        );
        nothing_ran_on(d.host("t"));
        d.shutdown().await;
    }
}
