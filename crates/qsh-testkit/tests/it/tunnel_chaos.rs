//! L4: tunnel behavior under chaos (`docs/design/testing.md` L4, the M4 plan (8237375)
//! M4 Step 8 (a)/(c)).
//!
//! Two scenarios, each locking down a claim M4 plan Step 8 (a) (8237375) makes
//! about what a tunnel owes across a fault, using the same chaos
//! primitives (`qsh_testkit::chaos::ChaosProxy`) `resume_chaos.rs` already
//! uses for the session-only case:
//!
//! - [`a_repath_mid_transfer_survives_as_a_migration_with_zero_byte_loss`]:
//!   a `-L` transfer rides a path change (same connection, new UDP path)
//!   with no tunnel-specific resume code involved — quinn's migration is
//!   transparent to the splice, exactly as it is to a PTY attach stream.
//! - [`a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`]:
//!   one connection carrying both an attached PTY session and a live `-L`
//!   tunnel loses its path for good. What "for good" means here is a
//!   `sever()` plus a test-simulated watchdog verdict (`close()`), not
//!   real silent-path detection — that end-to-end claim is
//!   `qsh-cli/tests/it/attach_recovery.rs`'s job, driven through a real
//!   `Ops::session_attach`. Given that a path is already dead: the PTY
//!   resumes per §10; the tunnel does not — its in-flight TCP connection
//!   must end cleanly and promptly, and must not block the session's own
//!   resume.

use std::time::Duration;

use qsh_core::client::reconnect::{REDIAL_DEADLINE, Recovered, recover};
use qsh_core::client::{ClientError, Session};
use qsh_core::telemetry::Recovery;
use qsh_core::tunnel::LocalForwardHandle;
use qsh_proto::wire::{self, StreamHeader, session_frame};
use qsh_testkit::chaos::ChaosPolicy;
use qsh_testkit::loopback::LoopbackHarness;
use qsh_testkit::tunnel::{EchoServer, TunnelHarness, ephemeral_local_spec};
use qsh_transport::FramedStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Wall-clock bound on any single chaotic round trip that is not itself
/// the thing under test — mirrors `resume_chaos.rs`'s own `OP_DEADLINE`.
const OP_DEADLINE: Duration = Duration::from_secs(30);

/// Generous ceiling on "this must end/complete promptly once the fault
/// lands, not hang" — reused across every such wait in this file (tunnel
/// teardown). It is
/// deliberately not itself a promptness gate: it exists only to turn a
/// wedged test into a failure instead of a hang, and is far looser than
/// the budgets it wraps ([`REDIAL_DEADLINE`] for resume,
/// [`POST_RESUME_RESET_BOUND`] for the post-resume reset below). A
/// scenario that needs to assert promptness, not just termination, gets
/// its own tighter constant rather than reusing this one for that.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Sub-second bound on how promptly the post-resume probe's reset (the
/// `ForwardCarrier::Direct` stale-carrier gap documented at that probe) must
/// surface once the probe's connection is actually talking to the
/// forward. Generous against the measured 23-85µs the reset itself takes
/// under an unloaded run, but two orders of magnitude tighter than
/// [`TIMEOUT`] — this is the "즉시" (promptly) half of that probe's claim,
/// not the "does the listener still accept at all" half, which the
/// probe's own connect-retry loop bounds against [`TIMEOUT`] instead.
const POST_RESUME_RESET_BOUND: Duration = Duration::from_secs(1);

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// Open the `SESSION_DATA` stream for `ticket` on `s`'s connection —
/// identical to `resume_chaos.rs`'s own helper of the same name (each
/// test binary is its own crate; there is no shared support module for
/// these to live in).
async fn redeem(s: &Session, ticket: Vec<u8>) -> FramedStream {
    let (send, recv) = s.connection().open_bi().await.expect("open_bi");
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::session_data(ticket))
        .await
        .expect("stream header");
    data
}

/// Read output frames until `want` bytes have arrived; returns the bytes
/// and the cumulative offset of the last one.
async fn read_output(data: &mut FramedStream, want: usize) -> (Vec<u8>, u64) {
    let mut bytes = Vec::new();
    let mut last_seq = 0;
    while bytes.len() < want {
        let frame = data
            .recv
            .recv::<wire::SessionFrame>()
            .await
            .expect("frame")
            .expect("stream ended early");
        if let Some(session_frame::Body::Output(o)) = frame.body {
            bytes.extend_from_slice(&o.data);
            last_seq = o.sequence;
        }
    }
    (bytes, last_seq)
}

/// A deterministic, non-repeating byte sequence (xorshift64*, seeded).
/// Constant-byte payloads would let a dropped, duplicated, or reordered
/// middle section still hash-compare equal by accident; this pattern
/// makes any such corruption visible in a plain `assert_eq!` on the whole
/// buffer.
fn deterministic_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state & 0xff) as u8);
    }
    out
}

// ------------------------------------------------------------------
// (1) migration survival: a repath mid-transfer is quinn's problem, not
//     the tunnel's.
// ------------------------------------------------------------------

const TEST1_SEED: u64 = 0x7E5_EED1;
const TRANSFER_BYTES: usize = 16 * 1024 * 1024;
/// Trigger the repath once at least this many bytes have round-tripped —
/// proof the transfer is genuinely mid-flight, not just starting or
/// already finished when the path moves.
const REPATH_TRIGGER_BYTES: usize = 3 * 1024 * 1024;

/// M4 plan Step 8 (a) (8237375): a `-L` transfer survives a path rebind (same
/// connection, new UDP socket/port) with zero byte loss and unmodified
/// content, and the host never sees a second connection — i.e. quinn's
/// migration is transparent to the splice, exactly as `resume_chaos.rs`'s
/// `a_repath_survives_as_a_migration_with_nothing_to_resume` proves it is
/// to a PTY attach stream. No tunnel-specific resume code is exercised
/// here because none exists, or needs to.
#[tokio::test(flavor = "multi_thread")]
async fn a_repath_mid_transfer_survives_as_a_migration_with_zero_byte_loss() {
    let harness = TunnelHarness::start_chaotic(ChaosPolicy::seeded(TEST1_SEED)).await;
    let ctx = harness.chaos_context();

    let host_conn = harness
        .host
        .server_connections()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("the host has no connection yet — {ctx}"));
    let stable_id = host_conn.stable_id();
    let old_up = harness
        .chaos()
        .upstream_addr()
        .await
        .expect("upstream bound");

    let forward = harness
        .local_forward("127.0.0.1", harness.echo.port())
        .await;
    let payload = deterministic_payload(TEST1_SEED, TRANSFER_BYTES);

    let conn = TcpStream::connect(forward.local_addr())
        .await
        .unwrap_or_else(|err| panic!("connect the -L listener: {err} — {ctx}"));
    conn.set_nodelay(true).ok();
    let (mut read_half, mut write_half) = conn.into_split();

    let payload_for_writer = payload.clone();
    let writer = tokio::spawn(async move {
        write_half.write_all(&payload_for_writer).await?;
        // Half-close so the echo server's own reply reaches EOF: it
        // streams bytes back as they arrive (`EchoServer`'s own doc,
        // `tokio::io::copy` under the hood) and only shuts *its* write
        // side down once ours reaches EOF too.
        write_half.shutdown().await
    });

    let mut received = Vec::with_capacity(payload.len());
    let mut buf = vec![0u8; 64 * 1024];
    let repath_result = tokio::time::timeout(OP_DEADLINE, async {
        let mut new_up = None;
        loop {
            let n = read_half.read(&mut buf).await.expect("read echoed bytes");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
            if new_up.is_none() && received.len() >= REPATH_TRIGGER_BYTES {
                new_up = Some(harness.chaos().repath().await.expect("repath"));
            }
        }
        new_up
    })
    .await
    .unwrap_or_else(|_| panic!("transfer stalled — {}", harness.chaos_detail()));
    let new_up = repath_result.unwrap_or_else(|| {
        panic!(
            "transfer finished before crossing the {REPATH_TRIGGER_BYTES}-byte repath trigger — {ctx}"
        )
    });

    writer
        .await
        .expect("writer task")
        .unwrap_or_else(|err| panic!("write side failed: {err} — {ctx}"));

    assert_ne!(
        new_up, old_up,
        "a repath must move the upstream port — {ctx}"
    );
    assert_eq!(
        received.len(),
        payload.len(),
        "byte count must match exactly (zero loss) — {}",
        harness.chaos_detail()
    );
    assert_eq!(
        received,
        payload,
        "content must match byte-for-byte — {}",
        harness.chaos_detail()
    );

    assert_eq!(
        harness.host.server_connections().len(),
        1,
        "a repath must not create a second connection — {}",
        harness.chaos_detail()
    );
    assert_eq!(
        harness.host.server_connections()[0].stable_id(),
        stable_id,
        "the host must still be talking to the same connection — {}",
        harness.chaos_detail()
    );
    assert_eq!(
        harness.host.server_connections()[0].remote_address(),
        new_up,
        "the host must observe the peer's address move too, not just the \
         proxy's own upstream-port bookkeeping — {}",
        harness.chaos_detail()
    );

    let stats = harness.chaos().stats();
    assert_eq!(stats.repaths, 1, "{}", harness.chaos_detail());
    assert!(stats.is_balanced(), "{}", harness.chaos_detail());

    drop(forward);
    harness.shutdown().await;
}

// ------------------------------------------------------------------
// (2) sever cleanup + PTY coexistence: one connection, two riders, one
//     fault — the PTY resumes, the tunnel does not, and neither blocks
//     the other.
// ------------------------------------------------------------------

const TEST2_SEED: u64 = 0x7E5_EED2;
const IN_FLIGHT_BYTES: usize = 1024 * 1024;

/// M4 plan Step 8 (a) (8237375): on one connection carrying both an attached
/// PTY session and a live `-L` tunnel with an in-flight transfer, a
/// connection the client has judged dead must resolve into exactly the
/// split the plan promises — not "the whole connection recovers" or "the
/// whole connection is lost":
///
/// - the in-flight tunnel TCP connection ends cleanly and promptly (no
///   hang, no panic) — the plan's "sever() 아래에서는 깨끗이 teardown돼야
///   한다";
/// - the PTY session resumes per §10 and is provably usable afterward (a
///   real input→output round trip through the mock child, not just a
///   successful attach);
/// - the two are concurrent, not sequential — the tunnel's teardown must
///   not gate the session's resume, checked not just by running them
///   concurrently but by pinning resume's own reported latency to
///   [`REDIAL_DEADLINE`] independent of whatever the tunnel's cleanup took;
/// - the forward's listener (the holder, M4 plan §4.1 #1 (8237375)) survives the
///   fault: it still accepts a new TCP connection after resume.
///
/// **What "judged dead" means here.** This harness drives the raw
/// `qsh_core::client::Session`/`recover()` API directly rather than a real
/// `Ops::session_attach`, so there is no live `qsh_core::client::pathwatch`
/// watchdog to observe the sever and declare the path dead on its own —
/// `close()` right after `sever()` stands in for that verdict (see the
/// comment at the fault site). Real end-to-end detection latency is
/// `qsh-cli/tests/it/attach_recovery.rs`'s claim, not this one's; this test's
/// claim is narrower and still real: *given* a connection already judged
/// dead, this is the split the tunnel and the session owe.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(TEST2_SEED)).await;
    let ctx = h.context();

    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let opened = s
        .session_open(open_req())
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");
    let mut data = redeem(&s, opened.ticket.clone()).await;

    // Baseline: the PTY works before anything goes wrong.
    pipe.write_output(b"before\r\n")
        .await
        .expect("child output");
    let (before, _) = tokio::time::timeout(OP_DEADLINE, read_output(&mut data, 8))
        .await
        .unwrap_or_else(|_| panic!("first output stalled — {ctx}"));
    assert_eq!(before, b"before\r\n", "{ctx}");

    // A `-L` tunnel on the *same* connection, riding a real production
    // entry point (`LocalForwardHandle::start`), with a genuinely
    // in-flight transfer.
    let echo = EchoServer::start().await.expect("bind echo server");
    let forward = LocalForwardHandle::start(
        &ephemeral_local_spec("127.0.0.1", echo.port()),
        s.connection().clone(),
    )
    .await
    .expect("bind local forward");
    let forward_addr = forward.local_addr();

    let tunnel_conn = TcpStream::connect(forward_addr)
        .await
        .unwrap_or_else(|err| panic!("connect the -L listener: {err} — {ctx}"));
    tunnel_conn.set_nodelay(true).ok();
    let (mut tunnel_read, mut tunnel_write) = tunnel_conn.into_split();
    let in_flight = vec![0xa5u8; IN_FLIGHT_BYTES];
    tunnel_write
        .write_all(&in_flight)
        .await
        .unwrap_or_else(|err| panic!("write through the tunnel: {err} — {ctx}"));
    // Deliberately never shut down or read to EOF here: the tunnel must
    // be genuinely open and mid-transfer when the path dies below, not
    // already finished.

    let old = s.connection().clone();
    let session_ref = format!("box/{}", opened.session_id);

    // ---- the fault: sever the path, then declare it dead the way the
    // real client watchdog (`qsh_core::client::pathwatch`, wired only into
    // `ops::session`'s attach driver behind a real `Ops::session_attach` —
    // `qsh-cli/tests/it/attach_recovery.rs`) would before ever redialing. A
    // bare `sever()` alone leaves the QUIC connection believing it is
    // merely quiet until quinn's 45 s idle timeout — not a bound either
    // this test or the product promises — and this harness's raw
    // `Session`/`recover()` API has no watchdog of its own to notice on
    // its own (`resume_chaos.rs`'s own module doc makes the same call for
    // the session-only case, and its own sever test never even closes the
    // old connection — resume there does not depend on the old
    // connection's fate at all, only on a fresh dial). This test's tunnel
    // half is different: an in-flight `-L` stream only ends once *this*
    // connection is actually gone, so `close()` here is not optional
    // set-up dressing — it is what makes "declared dead" real for the
    // tunnel side, standing in for the verdict a live watchdog would
    // eventually reach. What it is deliberately not standing in for is
    // *how long* that verdict takes to arrive: this test measures what the
    // tunnel and the session owe once a path has been judged dead, not the
    // judging itself (see this test's own name and module doc).
    h.chaos().sever().await;
    old.close(0, b"path dead (test-simulated watchdog)");

    // Two independent futures over the same fault, run concurrently so the
    // tunnel's teardown cannot serialize ahead of resume starting. `join!`
    // alone would not prove much here, though: it only shows both finished
    // before it returned, and a hypothetically serialized implementation
    // (tear the tunnel all the way down, only then redial) would still
    // satisfy a bare `join!` inside generous timeouts, since this tunnel's
    // teardown is itself microseconds (a bare RST), nowhere near either
    // timeout below. What actually pins "resume is not blocked by tunnel
    // cleanup" is asserting resume's own reported latency against its own
    // bound ([`REDIAL_DEADLINE`]) further down — a resume gated on the
    // tunnel's cleanup finishing would show up there even when the wall
    // clock this `join!` measures could not tell the two apart.
    let tunnel_cleanup = async {
        let mut buf = [0u8; 4096];
        loop {
            match tunnel_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    };

    let resume = recover(
        &session_ref,
        None,
        REDIAL_DEADLINE,
        || async { false },
        || async {
            let mut fresh = h.session().await;
            let attached = fresh
                .attach_request(wire::SessionAttach {
                    session_id: opened.session_id.clone(),
                    resume_token: opened.resume_token.clone(),
                    last_output_seq: 8,
                    mode: wire::AttachMode::Rw as i32,
                    no_steal: false,
                    screen: None,
                    agent_channel: Vec::new(),
                })
                .await?;
            let stream = redeem(&fresh, attached.ticket.clone()).await;
            Ok::<_, ClientError>((fresh, attached, stream))
        },
        || 0,
    );

    let (cleanup_result, resume_result) =
        tokio::join!(tokio::time::timeout(TIMEOUT, tunnel_cleanup), resume,);

    cleanup_result.unwrap_or_else(|_| {
        panic!("the in-flight tunnel connection must end within {TIMEOUT:?}, not hang — {ctx}")
    });

    let (fresh, attached, mut stream) = match resume_result.outcome {
        Ok(Recovered::Resumed(parts)) => parts,
        Ok(Recovered::Migrated) => panic!("a severed path cannot migrate — {ctx}"),
        Err(err) => panic!("resume did not complete: {err} — {ctx}"),
    };
    assert_eq!(resume_result.report.recovery, Recovery::Resumed, "{ctx}");
    // The load-bearing half of "resume is not blocked by tunnel cleanup"
    // (see the comment at the fault site above): `recover` already
    // enforced this bound with its own internal timeout, so this is a
    // consistency check that the *reported* number matches — mirroring
    // `resume_chaos.rs`'s identical assertion on the session-only case.
    assert!(
        u128::from(resume_result.report.time_to_recovery_ms) <= REDIAL_DEADLINE.as_millis(),
        "the report contradicts the deadline `recover` enforced: {} ms — {ctx}",
        resume_result.report.time_to_recovery_ms
    );
    assert_eq!(attached.replay_from, 8, "{ctx}");

    // Usable after resume: a real input → output round trip through the
    // mock child, not just a successful attach.
    stream
        .send
        .send(&wire::SessionFrame::input(4, b"ping".to_vec()))
        .await
        .expect("send input on the resumed stream");
    let got_input = tokio::time::timeout(OP_DEADLINE, pipe.read_input(64))
        .await
        .unwrap_or_else(|_| panic!("the child never saw the resumed input — {ctx}"))
        .expect("read_input");
    assert_eq!(got_input, b"ping", "{ctx}");
    pipe.write_output(b"ping")
        .await
        .expect("child echoes the input back");
    let (echoed, _) = tokio::time::timeout(OP_DEADLINE, read_output(&mut stream, 4))
        .await
        .unwrap_or_else(|_| panic!("echoed output stalled — {ctx}"));
    assert_eq!(
        echoed, b"ping",
        "the resumed session must be fully usable — {ctx}"
    );

    // The forward's listener (the holder) survives the fault: proven
    // structurally, separate from the round trip's own racy outcome below,
    // by a bounded retry loop that tolerates only `ConnectionRefused`
    // (nobody listening yet — a scheduling gap right after resume, not
    // evidence the listener died). Any other answer — a completed
    // connect, or an *immediate* reset/broken pipe — means a process on
    // the other end reacted to the SYN, which is what an accept loop
    // being alive means; under CPU load a connect can itself surface
    // `ConnectionReset` this way (a TCP handshake that completed in the
    // kernel and was reset before userspace ever saw it), so that is
    // folded into "answered", not "refused".
    let connected = tokio::time::timeout(TIMEOUT, async {
        loop {
            match TcpStream::connect(forward_addr).await {
                Ok(sock) => return Ok(sock),
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(err) => return Err(err),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the forward listener must still accept — {ctx}"));

    // KNOWN GAP against M4 plan Step 8 (a) (8237375)'s literal listener-survival
    // claim ("재연결 후 새 TCP 연결이 새 스트림을 연다" — a new TCP
    // connection after reconnect opens a new stream): it does not, today.
    //
    // `LocalForwardHandle::start`'s own doc on `ForwardCarrier::Direct`
    // (`crates/qsh-core/src/tunnel/local.rs`) says the carrier is a
    // **snapshot** of the connection the forward was started on, not a
    // view of whichever connection the owning attach currently holds — a
    // forward-route recovery replaces the attach's connection
    // (`ops::session`'s `Link::replace`), and this listener's accept
    // loop never learns about it. So half of the claim holds: the
    // listener itself survives the fault and keeps accepting — proven by
    // the retry loop above, which tolerates a refusal but nothing else —
    // but every stream it opens after the resume still tries to ride the
    // now-dead pre-resume connection, and `open_stream` on a dead
    // connection fails immediately, so `forward_connection`'s error path
    // resets the new client socket. Empirically that reset is a race
    // against the pre-resume connection's own teardown, not a fixed
    // point: it has been observed landing at `connect()` itself (folded
    // into `connected` above), at the first `write_all` below, and at the
    // read that follows a write that did land — always `ConnectionReset`
    // or `BrokenPipe`, delivered within low tens of microseconds under an
    // unloaded run, never a hang. All three sites are accepted as the
    // same outcome below; only a wrong echo or a hang are not.
    let round_trip = match connected {
        Err(err) => Err(err),
        Ok(mut sock) => {
            sock.set_nodelay(true).ok();
            let attempt = async {
                sock.write_all(b"post-resume").await?;
                // Half-close so a *working* forward would reach EOF on its
                // own, the same as `EchoServer`'s real requesters do — see
                // the fix to the comment at test (1)'s writer above.
                sock.shutdown().await?;
                let mut answer = Vec::new();
                let mut buf = [0u8; 64];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => return Ok(answer),
                        Ok(n) => answer.extend_from_slice(&buf[..n]),
                        Err(err) => return Err(err),
                    }
                }
            };
            match tokio::time::timeout(POST_RESUME_RESET_BOUND, attempt).await {
                Ok(result) => result,
                Err(_) => panic!(
                    "the post-resume connection neither completed nor errored \
                     within {POST_RESUME_RESET_BOUND:?} of connecting — it hung, \
                     which the known gap does not predict — {ctx}"
                ),
            }
        }
    };

    match round_trip {
        Ok(answer) if answer == b"post-resume" => panic!(
            "the post-resume connection completed a full, correct round trip \
             (echoed {answer:?} back) — the `ForwardCarrier::Direct` snapshot \
             gap this test documents appears to be fixed; update this \
             assertion to require success instead — {ctx}"
        ),
        Ok(answer) => panic!(
            "the post-resume connection completed but echoed the wrong bytes \
             ({answer:?}, wanted b\"post-resume\") — {ctx}"
        ),
        Err(err) => assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ),
            "the post-resume connection failed, but not the way the known \
             stale-carrier gap predicts: {err} — {ctx}"
        ),
    }

    let stats = h.chaos().stats();
    assert_eq!(stats.severs, 1, "{ctx} stats={stats:?}");
    assert!(stats.is_balanced(), "{ctx} stats={stats:?}");

    drop(forward);
    fresh.close();
    s.close();
    h.shutdown().await;
}
