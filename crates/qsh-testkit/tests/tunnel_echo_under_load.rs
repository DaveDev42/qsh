//! DoD 4 (M4 perf gate, `PLAN.md` M4 Step 7 (b), `docs/design/testing.md`
//! L9/L10, `docs/design/protocol.md` §12, `docs/ROADMAP.md` M4 DoD 4,
//! `docs/PRD.md` §13/§15): a saturating `-L` tunnel transfer runs
//! *concurrently*, on the **same QUIC connection**, with repeated PTY-echo
//! round trips over a `SESSION_DATA` attach stream — proving that
//! `PRIORITY_SESSION_DATA`/`PRIORITY_TUNNEL` (Step 2) actually keep PTY
//! output off the tunnel's queue, not just that the constants exist.
//!
//! **Why one connection.** Priority and the receive window are
//! per-connection scheduling knobs (`docs/design/protocol.md` §12) — a
//! saturating transfer on a *different* connection would prove nothing
//! about backpressure at all. Both streams here ride
//! [`Session::connection`]'s one dialed connection: the attach stream via
//! the production [`Session::attach`] (what actually sets
//! `PRIORITY_SESSION_DATA` — `open_data_link`), the local forward via the
//! same [`LocalForwardHandle::start`] the CLI's `-L` uses.
//!
//! **Saturation direction — host→client, not client→host.** An earlier
//! version of this test pointed the saturating `-L` forward at a
//! `DiscardServer`: the test process wrote bulk bytes into the forward's
//! local port, the client relayed them onto the tunnel stream toward the
//! host, and the host wrote them out to the sink. That saturates the
//! **client's** own QUIC send scheduler — but the client has nothing else
//! competing with it there (the 4-byte echo input is tiny and rare next
//! to a saturating forward). The party whose send scheduler actually has
//! to arbitrate `PRIORITY_TUNNEL` bulk against `PRIORITY_SESSION_DATA` PTY
//! output is the **host**, because PTY output always originates there.
//! This version points the forward at a [`FloodServer`] instead: the host
//! dials it (as any `-L` destination), and the bulk bytes it emits ride
//! the tunnel stream *back toward the client*, landing squarely on the
//! host's own send scheduler where they compete with the PTY echo's
//! output frames. The client side of the forward now just reads and
//! discards ([`drain_flood`]).
//!
//! **The metric — a genuine client-originated round trip.** An earlier
//! version originated the timing on the *host*: it timestamped
//! [`PipeHandle::write_output`] (the PTY stand-in's echo write) and
//! subtracted a full round-trip RTT from `write_at → client recv` — a
//! **one-way** leg, so the subtraction was dimensionally wrong. Its
//! fingerprint was a suspicious `min=0.000ms`: `saturating_sub` clamped
//! the (frequently negative) result to zero every time the one-way leg
//! came in under a full RTT, which on loopback it nearly always did. This
//! version originates each round on the **client**: it stamps `send_at`
//! immediately before `attached.send_input`, waits for its own echoed
//! `Output` event, stamps `recv_at` there, and computes
//! `elapsed = recv_at − send_at` — a genuine full round trip (client→host
//! input, host echo, host→client output), the same dimension as
//! `connection.quinn().stats().path.rtt`. `margin = elapsed − rtt` is now
//! full-RTT-minus-full-RTT, dimensionally sound. A `checked_sub` (not
//! `saturating_sub`) counts every round where the live RTT estimate
//! (queried fresh each round, same as before) outran the round's own
//! measured elapsed time instead of silently zeroing the margin; that
//! count is printed with the summary. The host-side echo loop
//! ([`echo_loop`]) is otherwise unchanged as the PTY stand-in —
//! [`PipeHandle`] standing in for a real PTY/child-process pipe
//! (`docs/design/testing.md`'s headless-PTY convention) — it just no
//! longer timestamps anything itself, since the metric no longer needs a
//! host-side clock reading.
//!
//! **Ping-pong, not a fire-hose.** Each round sends one 4-byte input chunk
//! and waits for its own echoed output before the next, so there is never
//! more than one round in flight — no sequence-number bookkeeping needed
//! to tell which `Output` event answers which `send_input`. An interleaved
//! `InputAck` frame (`session_stream.rs` emits one per applied input,
//! independent of the echo) is skipped, not mistaken for the echo.
//!
//! **Saturation shape — time-bounded, not round-count-bounded.** An
//! earlier round-count-bounded design (stop the saturating writer once a
//! *fixed number* of echo rounds finished) turned out to be
//! self-defeating: on a healthy connection each round is sub-millisecond,
//! so a small fixed round count let the saturating writer barely get
//! going (a few chunks) before the measurement ended — never reaching a
//! genuinely saturated queue depth. Raising the round count to force more
//! overlap instead let the saturating writer run **unbounded**, which
//! surfaced the real bug this gate exists to catch (see "Measured
//! evidence" below) but also grew past a 1 GiB-class transfer with no
//! ceiling — unacceptable for a CI job's time budget. The fix is to bound
//! by **wall clock** instead: [`FloodServer`] keeps writing 4 MiB chunks
//! for as long as its one accepted connection stays open, while the round
//! loop runs echo rounds back-to-back for [`MEASUREMENT_DURATION`] (a
//! shared stop flag the round loop sets once the deadline passes, checked
//! by [`drain_flood`] after each read). This is the sanctioned wall-clock
//! exception to `docs/design/testing.md`'s no-`sleep()` rule (the same one
//! `reverse_blackout.rs`'s 60s blackout uses) — an active measurement
//! loop, not a passive wait. `MEASUREMENT_DURATION` (15s) is this step's
//! "1GB을 시간-유계 등가로 대체" answer (`PLAN.md` §4.2): at this
//! same-process harness's own measured tunnel throughput
//! (`tunnel_throughput.rs`), 15s moves several hundred MB — the same
//! order of magnitude as the literal 1 GiB DoD wording — while stopping
//! well short of M3's 60s blackout precedent's own budget.
//!
//! **Measured evidence (`PLAN.md` M4 Step 7(a)'s "measure-then-fix"
//! obligation on [`qsh_transport::endpoint::TUNNEL_STREAM_RECEIVE_WINDOW`]).**
//! The round-count-bounded prototype above, pushed to 5,000 rounds, grew
//! the saturating transfer to 3.3 GiB over 62s and produced p95=18.1ms,
//! max=80.8ms — a real DoD 4 miss under sustained, deep saturation, though
//! that number was measured under the client→host direction and the
//! dimensionally-wrong metric this revision replaces. **This revision's
//! own numbers**, host→client with the genuine round-trip metric, at the
//! 2 MiB window: with only the Step 2 priority band and no send-side depth
//! cap, p95=30.579ms (min=0.132ms, max=74.883ms) — still a clear miss, so
//! `qsh_core::tunnel::splice`'s `SEND_DEPTH_CAP_BYTES` was added (see that
//! constant's own doc for the cap-size trials). With the 128 KiB cap in
//! place, five repeated runs all passed: p95 ∈ {7.919, 7.621, 7.672,
//! 7.766, 7.146} ms, all under the 10ms bar, alongside
//! `tunnel_throughput.rs`'s DoD 3 ratio holding at 0.899–0.945 across the
//! same runs — the cap does not trade one DoD for the other. See
//! `crates/qsh-transport/src/endpoint.rs`'s `TUNNEL_STREAM_RECEIVE_WINDOW`
//! doc comment and `docs/design/protocol.md` §12 for the window-side half
//! of this record.
//!
//! Gated identically to `tunnel_throughput.rs`
//! (`QSH_ACCEPTANCE_SLOW`/`QSH_ACCEPTANCE_STRICT`), but with a single
//! threshold rather than a strict/smoke split: `PLAN.md` §4.2's draft
//! margin only carves out a lenient smoke tier for DoD 3's *ratio*. DoD 4's
//! own threshold (measured RTT + 10ms) is already the "관대한 임계치"
//! `testing.md` L10 describes for the acceptance job's DoD 4 gate, so a
//! second, looser tier on top of it would just be redundant slack.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use qsh_core::broker::PipeHandle;
use qsh_core::client::AttachEvent;
use qsh_core::tunnel::LocalForwardHandle;
use qsh_proto::wire;
use qsh_testkit::loopback::LoopbackHarness;
use qsh_testkit::tunnel::{FloodServer, ephemeral_local_spec};
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpStream;

/// Wall-clock length of the concurrent saturate+echo measurement — see
/// the module doc's "Saturation shape".
const MEASUREMENT_DURATION: Duration = Duration::from_secs(15);

/// Floor on samples collected: below this, the p95 is statistically
/// meaningless (too few rounds fit in [`MEASUREMENT_DURATION`], which on
/// any plausible CI runner means the round loop itself is badly starved —
/// worth failing loudly on rather than reporting a p95 over a handful of
/// points).
const MIN_SAMPLES: usize = 200;

/// Hang guard on one round: on a healthy prioritized connection this is
/// never approached (loopback RTT is sub-millisecond) — it exists only so
/// a genuinely broken priority/backpressure path fails the test with a
/// clear panic message instead of holding the acceptance job hostage.
const ROUND_TIMEOUT: Duration = Duration::from_secs(2);

/// Bytes in one echo round's marker (a big-endian round index).
const MARKER_BYTES: usize = 4;

/// Read buffer for [`drain_flood`]'s client-side drain of the reverse
/// saturating flood.
const SATURATE_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// `testing.md` L10's literal bound.
const MAX_MARGIN_MS: f64 = 10.0;

fn env_flag(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim().to_string();
    !(value.is_empty() || value == "0")
}

/// Unlike DoD 3's ratio, DoD 4 has no strict/smoke split (see the module
/// doc) — either acceptance-job env var simply turns the gate on.
fn gate_requested() -> bool {
    env_flag("QSH_ACCEPTANCE_STRICT") || env_flag("QSH_ACCEPTANCE_SLOW")
}

fn skip() {
    eprintln!(
        "SKIP: the M4 DoD 4 echo-under-load p95 gate requires QSH_ACCEPTANCE_SLOW=1 or \
         QSH_ACCEPTANCE_STRICT=1 (neither set on this run) — `.github/workflows/ci.yml`'s \
         acceptance job sets QSH_ACCEPTANCE_STRICT (the certifying tier); QSH_ACCEPTANCE_SLOW \
         alone is a lenient local smoke tier"
    );
}

/// Nearest-rank percentile (`p` in `[0, 1]`) over `samples`.
fn percentile(mut samples: Vec<f64>, p: f64) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let n = samples.len();
    let idx = ((n as f64) * p).ceil() as usize;
    samples[idx.saturating_sub(1).min(n - 1)]
}

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// Host-side "PTY" stand-in: echo every input chunk straight back as
/// output. [`PipeHandle`] stands in for a real PTY/child-process pipe
/// (`docs/design/testing.md`'s headless-PTY convention) — see the module
/// doc's "The metric" for why this loop no longer timestamps its own
/// write.
async fn echo_loop(mut pipe: PipeHandle) {
    loop {
        let mut chunk = match pipe.read_input(MARKER_BYTES).await {
            Ok(bytes) if !bytes.is_empty() => bytes,
            _ => return,
        };
        // A duplex read is not guaranteed to return everything one
        // `send_input` call wrote in a single poll — accumulate until this
        // round's whole marker has arrived.
        while chunk.len() < MARKER_BYTES {
            match pipe.read_input(MARKER_BYTES - chunk.len()).await {
                Ok(more) if !more.is_empty() => chunk.extend_from_slice(&more),
                _ => return,
            }
        }
        if pipe.write_output(&chunk).await.is_err() {
            return;
        }
    }
}

/// Client side of the reverse-saturating forward: connect once, then read
/// and discard until `stop` is set (checked after each read) — see the
/// module doc's "Saturation direction". The writer lives on the host side
/// ([`FloodServer`], reached as the forward's destination), so this side's
/// only job is to keep draining what the tunnel delivers and, on `stop`,
/// to drop the connection — ending the flood by propagating a close back
/// through the splice to the host's own outbound connection to
/// [`FloodServer`].
async fn drain_flood(addr: SocketAddr, stop: Arc<AtomicBool>) -> u64 {
    let mut conn = TcpStream::connect(addr)
        .await
        .expect("connect the saturating -L listener");
    conn.set_nodelay(true).ok();
    let mut buf = vec![0u8; SATURATE_CHUNK_BYTES];
    let mut received: u64 = 0;
    loop {
        let n = conn.read(&mut buf).await.expect("read a saturating chunk");
        if n == 0 {
            break;
        }
        received += n as u64;
        if stop.load(Ordering::Relaxed) {
            break;
        }
    }
    received
}

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms() {
    if !gate_requested() {
        skip();
        return;
    }

    let h = LoopbackHarness::start().await;
    let mut session = h.session().await;
    let connection = session.connection().clone();

    // The saturating -L forward's destination: a source that floods the
    // *host's* send scheduler with tunnel bulk (see the module doc's
    // "Saturation direction" — this is the direction that actually
    // exercises PRIORITY_TUNNEL vs. PRIORITY_SESSION_DATA arbitration).
    let (flood, flood_done) = FloodServer::start().await.expect("bind flood source");
    let forward = LocalForwardHandle::start(
        &ephemeral_local_spec("127.0.0.1", flood.addr().port()),
        connection.clone(),
    )
    .await
    .expect("bind saturating local forward");

    let stop = Arc::new(AtomicBool::new(false));
    let drain_task = tokio::spawn(drain_flood(forward.local_addr(), Arc::clone(&stop)));

    // The PTY-echo stand-in, opened the production way — `Session::attach`
    // is what applies `PRIORITY_SESSION_DATA` (`open_data_link`), same as
    // a real `qsh` attach.
    let opened = session
        .session_open(open_req())
        .await
        .expect("session.open");
    let pipe = h.pipes.take().expect("pipe handle for the opened session");
    let mut attached = session
        .attach(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            // Even a first attach right after `session.open` redeems a
            // credential — `session.open` mints one for exactly this
            // (`SessionOpened.resume_token`, `server::mod.rs::
            // handle_session_attach`'s step 1, ADR-0007's rotation
            // scheme). An empty token is refused unconditionally, not
            // treated as "no resume requested".
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
        })
        .await
        .expect("attach the PTY-echo session");

    tokio::spawn(echo_loop(pipe));

    let mut margins_ms = Vec::new();
    let mut clamped_zero = 0usize;
    let deadline = Instant::now() + MEASUREMENT_DURATION;
    let mut next_round: u32 = 0;
    while Instant::now() < deadline {
        let round = next_round;
        next_round = next_round.wrapping_add(1);
        let marker = round.to_be_bytes().to_vec();

        // The round originates here, on the client — see the module
        // doc's "The metric".
        let send_at = Instant::now();
        attached
            .send_input(&marker)
            .await
            .expect("send one echo round's input");

        let (echoed, recv_at) = loop {
            let event = tokio::time::timeout(ROUND_TIMEOUT, attached.next())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "round {round}: no attach-stream event within {ROUND_TIMEOUT:?} — the \
                         saturating tunnel is starving PTY-echo delivery"
                    )
                })
                .expect("attach stream read")
                .expect("attach stream ended before this round's echo");
            match event {
                AttachEvent::Output { data, .. } => break (data, Instant::now()),
                // One per applied input (`session_stream.rs`), unrelated
                // to the echo itself — keep waiting for the Output.
                AttachEvent::InputAck { .. } => continue,
                other => panic!("round {round}: unexpected attach event {other:?}"),
            }
        };
        assert_eq!(
            echoed, marker,
            "round {round}: echoed bytes must match what this round sent"
        );

        let rtt = connection.quinn().stats().path.rtt;
        let elapsed = recv_at.saturating_duration_since(send_at);
        let margin = match elapsed.checked_sub(rtt) {
            Some(margin) => margin,
            None => {
                // The live RTT estimate outran this round's own measured
                // elapsed time — dimensionally still a full-RTT-minus-
                // full-RTT subtraction, just one where the estimate was
                // momentarily stale. Counted, not silently zeroed (the
                // module doc's "The metric").
                clamped_zero += 1;
                Duration::ZERO
            }
        };
        margins_ms.push(margin.as_secs_f64() * 1000.0);
    }

    stop.store(true, Ordering::Relaxed);
    let drained_bytes = drain_task.await.expect("drain task");
    let flood_bytes = flood_done.await.unwrap_or(0);

    attached.finish();
    session.close();
    drop(forward);
    h.shutdown().await;

    let rounds = margins_ms.len();
    let p95 = percentile(margins_ms.clone(), 0.95);
    let max = margins_ms.iter().cloned().fold(f64::MIN, f64::max);
    let min = margins_ms.iter().cloned().fold(f64::MAX, f64::min);
    let report = format!(
        "p95={p95:.3}ms (required < {MAX_MARGIN_MS}ms), min={min:.3}ms max={max:.3}ms, \
         rounds={rounds} (min {MIN_SAMPLES}), clamped_zero={clamped_zero}, \
         duration={MEASUREMENT_DURATION:?}, flood_bytes={flood_bytes} drained_bytes={drained_bytes}"
    );
    // DoD 4's acceptance-job log is the record of the criterion
    // (`PLAN.md` M4 Step 7 (d)) — print on success too, not just failure.
    eprintln!("tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms: {report}");
    assert!(
        rounds >= MIN_SAMPLES,
        "M4 DoD 4 harness fault: only {rounds} echo rounds fit in {MEASUREMENT_DURATION:?} (need \
         ≥{MIN_SAMPLES} for a meaningful p95) — {report}"
    );
    assert!(
        p95 < MAX_MARGIN_MS,
        "M4 DoD 4 (PTY-echo p95 < measured RTT + 10ms) missed: {report}"
    );
}
