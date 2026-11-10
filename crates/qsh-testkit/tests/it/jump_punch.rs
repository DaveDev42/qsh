//! A jump chain whose first hop is a punched connection (ADR-0056 decision
//! 13, DoD 25.10), in netsim.
//!
//! A sits behind a NAT, B (the first hop, a real `qsh serve --to` host) behind
//! another one, and the direct path to B is closed, so the only way A reaches
//! B is the punch through R. T is a loopback host that B's own UDP socket
//! reaches. The `JUMP` channel and the inner QUIC connection to T then ride
//! the punched connection:
//!
//! ```text
//!   A ==punched QUIC (netsim)== B --UDP (loopback)-- T
//! ```

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::Engine as _;
use qsh_core::acl::AllowAllPinned;
use qsh_core::jump::JumpOptions;
use qsh_proto::{SessionOpenReq, SessionReadReq, SessionWriteReq};
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_transport::{Principal, StaticTrust};

use super::punch_route::{WorldOptions, blocking, exec, pin, punched, world};

/// A hang is a failure, not a flake.
const LIMIT: Duration = Duration::from_secs(90);

/// The first hop B is punched to, J-style: a session and an exec on T end
/// through the chain, R heard exactly one punch request, and B carried the
/// channels.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_first_hop_over_a_punched_connection() {
    let w = world(WorldOptions::default()).await;
    let b = w.b_server.clone().expect("B registered with R");
    b.set_jump_options(JumpOptions {
        allow_host_local: true,
        ..JumpOptions::default()
    });
    let t = LoopbackHarness::start_custom(
        Arc::new(AllowAllPinned),
        make_identity(),
        StaticTrust::empty().with_pin(w.a.fp, Principal::Device("a".into())),
    )
    .await;
    pin(
        &w.a.ops,
        "t",
        Some(t.addr.to_string()),
        &t.server_identity.fingerprint,
    )
    .await;
    let ops = w.a.ops.clone().with_jump(vec!["b".into()]);

    let scene = async {
        // exec on T through the punched first hop
        let out = exec(&ops, "t").await.expect("exec through the chain");
        assert!(punched(&out), "exit {}", out.data.remote_exit_code);

        // a PTY session on T: the output T's side produces reaches A, the
        // input A writes reaches T's side
        let opened = blocking(&ops, |ops| {
            ops.session_open(SessionOpenReq {
                host: "t".into(),
                argv: vec!["sh".into()],
                env: vec![],
                term: Some("xterm-256color".into()),
                cols: Some(80),
                rows: Some(24),
                user: None,
                shell_command: None,
            })
        })
        .await
        .expect("session.open through the chain");
        let mut pipe = t.pipes.take().expect("T's side of the session");
        pipe.write_output(b"hello-punched").await.expect("output");
        let session_ref = opened.session_ref.clone();
        let read = blocking(&ops, move |ops| {
            ops.session_read(SessionReadReq {
                session_ref,
                after_sequence: 0,
                wait_ms: Some(10_000),
                limit_bytes: None,
                ctl_after: None,
            })
        })
        .await
        .expect("session.read through the chain");
        assert_eq!(String::from_utf8_lossy(&read.output), "hello-punched");
        let session_ref = opened.session_ref.clone();
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"typed-punched");
        blocking(&ops, move |ops| {
            ops.session_write(SessionWriteReq {
                session_ref,
                data_b64: b64,
            })
        })
        .await
        .expect("session.write through the chain");
        let got = pipe.read_input(64).await.expect("input");
        assert_eq!(got, b"typed-punched");
    };
    tokio::time::timeout(LIMIT, scene)
        .await
        .expect("the scenario finished");

    // The first hop of each of the two connections was a punch, and B
    // carried both channels.
    let opened = b.jump_stats().opened.load(Ordering::Relaxed);
    assert!(opened >= 2);
    assert_eq!(
        w.punch_requests() as u64,
        opened,
        "every connection of A is one punch and one JUMP channel on B"
    );
    assert!(b.jump_stats().to_target_packets.load(Ordering::Relaxed) > 0);
    t.shutdown().await;
    w.shutdown().await;
}

/// The first hop B is pinned without an address, so the only way to it is
/// the punch through R (ADR-0056 decision 13, ADR-0054 decision 16.3). The
/// chain must not stop at the `address` stage for it: B's address is never
/// dialed or named in a header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_first_hop_with_no_address_is_reached_by_punching_alone() {
    let w = world(WorldOptions {
        pin_b_address: false,
        direct_listener: false,
        ..WorldOptions::default()
    })
    .await;
    let b = w.b_server.clone().expect("B registered with R");
    b.set_jump_options(JumpOptions {
        allow_host_local: true,
        ..JumpOptions::default()
    });
    let t = LoopbackHarness::start_custom(
        Arc::new(AllowAllPinned),
        make_identity(),
        StaticTrust::empty().with_pin(w.a.fp, Principal::Device("a".into())),
    )
    .await;
    pin(
        &w.a.ops,
        "t",
        Some(t.addr.to_string()),
        &t.server_identity.fingerprint,
    )
    .await;
    let ops = w.a.ops.clone().with_jump(vec!["b".into()]);

    let out = tokio::time::timeout(LIMIT, exec(&ops, "t"))
        .await
        .expect("the exec finished")
        .expect("exec through a first hop that is only punchable");
    assert!(punched(&out), "exit {}", out.data.remote_exit_code);
    let opened = b.jump_stats().opened.load(Ordering::Relaxed);
    assert_eq!(opened, 1, "B carried the one channel to T");
    assert_eq!(
        w.punch_requests() as u64,
        opened,
        "the first hop was one punch and no direct dial reached B"
    );
    t.shutdown().await;
    w.shutdown().await;
}

/// A first hop with no address and a rendezvous that names nobody usable is
/// still the `address` stage: punching alone needs a usable rendezvous.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_first_hop_with_no_address_and_no_rendezvous_is_the_address_stage() {
    let w = world(WorldOptions {
        pin_b_address: false,
        direct_listener: false,
        ..WorldOptions::default()
    })
    .await;
    let t = LoopbackHarness::start_custom(
        Arc::new(AllowAllPinned),
        make_identity(),
        StaticTrust::empty().with_pin(w.a.fp, Principal::Device("a".into())),
    )
    .await;
    pin(
        &w.a.ops,
        "t",
        Some(t.addr.to_string()),
        &t.server_identity.fingerprint,
    )
    .await;
    // `quiet` is pinned with no address and nobody lists a rendezvous for it
    // (a hint-less pin, and `--rendezvous` names the punch target's own
    // rendezvous only through `world`'s A).
    pin(&w.a.ops, "quiet", None, &make_identity().fingerprint).await;
    let ops = qsh_core::Ops::clone(&w.a.ops)
        .with_punch(qsh_core::punch::ClientPunch::default())
        .with_jump(vec!["quiet".into()]);
    let err = exec(&ops, "t").await.expect_err("no way to the first hop");
    assert_eq!(err.code, qsh_proto::ErrorCode::HostNotFound, "{err:?}");
    assert_eq!(err.details["jump"]["stage"], "address", "{err:?}");
    assert_eq!(err.details["jump"]["hop"], 1);
    t.shutdown().await;
    w.shutdown().await;
}
