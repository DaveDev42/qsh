//! M13 (b): the slow-stream half of `docs/PRD.md` §13's "느린 파일·터널
//! stream이 PTY stream을 block하지 않아야 함" (`docs/design/testing.md`
//! L9/L10, `docs/design/protocol.md` §12). `tunnel_echo_under_load.rs`
//! covers the saturation axis (a peer that reads at line rate); this file
//! covers the starvation axis: tunnel peers that **never read**.
//!
//! **Hypothesis.** Each tunnel stream is allowed
//! `TUNNEL_STREAM_RECEIVE_WINDOW` (2 MiB) of unread data, and the whole
//! connection `CONNECTION_RECEIVE_WINDOW` (8 MiB). Four stalled tunnel
//! streams hold 4 x 2 MiB = 8 MiB, which is the entire connection window,
//! so the host has no connection-level credit left for `SESSION_DATA`
//! bytes: PTY output stops until a tunnel consumer reads. Three stalled
//! streams hold 6 MiB and leave 2 MiB, so PTY output must keep flowing
//! (the boundary test). Eight stalled streams are the same failure with
//! margin. Commit `209e764` measured the progress and latency tests at N=4
//! red under `QSH_ACCEPTANCE_STRICT`, which is the input ADR-0037 decided
//! on.
//!
//! **The fix.** ADR-0037's per-connection stall ledger
//! (`qsh_core::tunnel::stall`) stops the oldest stalled tunnel stream as
//! soon as more than `CONNECTION_RECEIVE_WINDOW /
//! TUNNEL_STREAM_RECEIVE_WINDOW - 1` (3) are stalled, or one is stalled
//! while the peer reports `DATA_BLOCKED`. quinn returns a stopped stream's
//! unread bytes to the connection's credit, so all four tests are green
//! under `QSH_ACCEPTANCE_STRICT`, and the stalled consumers see an RST.
//!
//! **Shape.** Everything rides one QUIC connection. N host-side
//! [`FloodServer`]s write forever; each is the destination of its own `-L`
//! forward; the client-side consumer opens a TCP connection to the forward
//! with a tiny `SO_RCVBUF` and then never reads. The kernel buffers fill,
//! the client splice stops reading its QUIC receive stream, and the stream
//! window fills. The PTY stand-in is a [`PipeHandle`] (the headless-PTY
//! convention): a numbered-lines producer for the progress test, an echo
//! loop for the latency test.
//!
//! **Stall observation criterion** (`PLAN.md` §4.1 #1). Time is never the
//! criterion. The client's `Connection::stats().frame_rx` counts the
//! frames the host sent. The stall is considered established when
//! `data_blocked > 0` (the host ran out of connection-level credit), or
//! when `stream_data_blocked >= N` (the host reported at least one blocked
//! frame per stalled stream). quinn exposes only counters, not per-stream
//! attribution, so the second arm is an approximation; it is the only one
//! that can fire at N=3, where the connection window is never exhausted.
//! Measurement starts only after this holds, and
//! `stalled_stream_harness_observes_data_blocked_before_measuring` asserts
//! it unconditionally so a harness that never stalls cannot pass green.
//!
//! **Gating.** Like the other perf gates, without `QSH_ACCEPTANCE_STRICT`
//! the tests print their measurements and pass; with it they assert. The
//! observation test always asserts, since its only job is to catch a
//! harness that measured nothing. `ci.yml`'s `acceptance` job runs this
//! file with `QSH_ACCEPTANCE_STRICT=1`, next to `tunnel_echo_under_load`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use qsh_core::broker::PipeHandle;
use qsh_core::client::AttachEvent;
use qsh_core::tunnel::LocalForwardHandle;
use qsh_proto::wire;
use qsh_testkit::loopback::LoopbackHarness;
use qsh_testkit::tunnel::{FloodServer, ephemeral_local_spec};
use tokio::net::{TcpSocket, TcpStream};

/// Upper bound on waiting for the stall to establish. Generous: it is a
/// hang guard on an observable condition, not a pacing interval.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Poll interval while waiting for an observable condition.
const POLL: Duration = Duration::from_millis(10);

/// Client-side consumer `SO_RCVBUF`: as small as the OS allows so the
/// kernel buffers fill almost immediately.
const CONSUMER_RCVBUF: u32 = 4 * 1024;

/// One progress line is `LINE_BYTES` long, so `sequence / LINE_BYTES` is
/// the line number the client has seen.
const LINE_BYTES: u64 = 16;

/// Lines the client must see after the stall is established.
const PROGRESS_LINES: u64 = 200;

/// Generous bound on seeing [`PROGRESS_LINES`] more lines. At the
/// producer's pace this takes about a second when PTY output flows.
const PROGRESS_TIMEOUT: Duration = Duration::from_secs(10);

/// Producer pacing: one line per tick keeps the PTY stand-in far from
/// saturating anything itself.
const PRODUCER_TICK: Duration = Duration::from_millis(1);

/// Echo rounds collected for the latency percentile.
const ECHO_ROUNDS: usize = 300;

/// Hang guard on one echo round.
const ROUND_TIMEOUT: Duration = Duration::from_secs(2);

const MARKER_BYTES: usize = 4;

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

fn strict() -> bool {
    env_flag("QSH_ACCEPTANCE_STRICT")
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

/// What the client saw of the host's blocked frames once the wait ended.
#[derive(Debug, Clone, Copy)]
struct StallObservation {
    established: bool,
    data_blocked: u64,
    stream_data_blocked: u64,
    waited: Duration,
}

impl StallObservation {
    fn describe(&self) -> String {
        format!(
            "established={} DATA_BLOCKED={} STREAM_DATA_BLOCKED={} waited={:?}",
            self.established, self.data_blocked, self.stream_data_blocked, self.waited
        )
    }
}

/// The N stalled tunnel streams. Dropping it tears the stall down.
struct Stall {
    _floods: Vec<FloodServer>,
    _forwards: Vec<LocalForwardHandle>,
    /// Client-side consumers: connected, never read.
    _consumers: Vec<TcpStream>,
}

/// Open `n` flooded tunnel streams whose client-side consumers never read.
async fn open_stall(connection: &qsh_transport::Connection, n: usize) -> Stall {
    let mut floods = Vec::new();
    let mut forwards = Vec::new();
    let mut consumers = Vec::new();
    for _ in 0..n {
        let (flood, _done) = FloodServer::start().await.expect("bind flood source");
        let forward = LocalForwardHandle::start(
            &ephemeral_local_spec("127.0.0.1", flood.addr().port()),
            connection.clone(),
        )
        .await
        .expect("bind stalled local forward");
        let addr: SocketAddr = forward.local_addr();
        let socket = TcpSocket::new_v4().expect("consumer socket");
        socket
            .set_recv_buffer_size(CONSUMER_RCVBUF)
            .expect("shrink the consumer's SO_RCVBUF");
        // Connected and then never read: this is the slow consumer.
        let consumer = socket.connect(addr).await.expect("connect the forward");
        floods.push(flood);
        forwards.push(forward);
        consumers.push(consumer);
    }
    Stall {
        _floods: floods,
        _forwards: forwards,
        _consumers: consumers,
    }
}

/// Wait until the client has seen the host report itself blocked (see the
/// module doc's observation criterion), or `STALL_TIMEOUT` passes.
async fn wait_for_stall(connection: &qsh_transport::Connection, n: usize) -> StallObservation {
    let started = Instant::now();
    loop {
        let frames = connection.quinn().stats().frame_rx;
        let established = frames.data_blocked > 0 || frames.stream_data_blocked >= n as u64;
        let waited = started.elapsed();
        if established || waited >= STALL_TIMEOUT {
            return StallObservation {
                established,
                data_blocked: frames.data_blocked,
                stream_data_blocked: frames.stream_data_blocked,
                waited,
            };
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Host-side PTY stand-in that prints one fixed-width numbered line per
/// tick until `stop` is set or the session goes away.
async fn number_lines(mut pipe: PipeHandle, stop: Arc<AtomicBool>) {
    let mut n: u64 = 0;
    let mut tick = tokio::time::interval(PRODUCER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    while !stop.load(Ordering::Relaxed) {
        tick.tick().await;
        let line = format!("{n:015}\n");
        debug_assert_eq!(line.len() as u64, LINE_BYTES);
        if pipe.write_output(line.as_bytes()).await.is_err() {
            return;
        }
        n += 1;
    }
}

/// Host-side PTY stand-in that echoes every input marker back.
async fn echo_loop(mut pipe: PipeHandle) {
    loop {
        let mut chunk = match pipe.read_input(MARKER_BYTES).await {
            Ok(bytes) if !bytes.is_empty() => bytes,
            _ => return,
        };
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

struct Progress {
    stall: StallObservation,
    lines_before: u64,
    lines_after: u64,
    progressed: bool,
    waited: Duration,
}

/// Run the progress scenario with `n` stalled streams.
async fn run_progress(n: usize) -> Progress {
    let h = LoopbackHarness::start().await;
    let mut session = h.session().await;
    let connection = session.connection().clone();

    let opened = session
        .session_open(open_req())
        .await
        .expect("session.open");
    let pipe = h.pipes.take().expect("pipe handle for the opened session");
    let mut attached = session
        .attach(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
        })
        .await
        .expect("attach the numbered-lines session");

    let stop = Arc::new(AtomicBool::new(false));
    let producer = tokio::spawn(number_lines(pipe, Arc::clone(&stop)));

    // The client-side reader keeps draining the attach stream, so a stall
    // shows up as the byte offset standing still, not as an unread stream.
    let seen_bytes = Arc::new(AtomicU64::new(0));
    let reader_seen = Arc::clone(&seen_bytes);
    let reader = tokio::spawn(async move {
        while let Ok(Some(event)) = attached.next().await {
            if let AttachEvent::Output { sequence, .. } = event {
                reader_seen.fetch_max(sequence, Ordering::Relaxed);
            }
        }
        attached
    });

    // Output must be flowing before the stall starts, so "no progress"
    // afterwards cannot be a producer that never started.
    let flowing_deadline = Instant::now() + PROGRESS_TIMEOUT;
    while seen_bytes.load(Ordering::Relaxed) < LINE_BYTES * 10 {
        assert!(
            Instant::now() < flowing_deadline,
            "harness fault: no PTY output before any tunnel stall"
        );
        tokio::time::sleep(POLL).await;
    }

    let stall_streams = open_stall(&connection, n).await;
    let stall = wait_for_stall(&connection, n).await;

    let lines_before = seen_bytes.load(Ordering::Relaxed) / LINE_BYTES;
    let started = Instant::now();
    let deadline = started + PROGRESS_TIMEOUT;
    let progressed = loop {
        let now_lines = seen_bytes.load(Ordering::Relaxed) / LINE_BYTES;
        if now_lines >= lines_before + PROGRESS_LINES {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        tokio::time::sleep(POLL).await;
    };
    let waited = started.elapsed();
    let lines_after = seen_bytes.load(Ordering::Relaxed) / LINE_BYTES;

    stop.store(true, Ordering::Relaxed);
    drop(stall_streams);
    reader.abort();
    producer.abort();
    session.close();
    h.shutdown().await;

    Progress {
        stall,
        lines_before,
        lines_after,
        progressed,
        waited,
    }
}

fn report_progress(label: &str, n: usize, p: &Progress) -> String {
    let report = format!(
        "N={n}: {} lines_before={} lines_after={} (need +{PROGRESS_LINES}) progressed={} \
         waited={:?} (limit {PROGRESS_TIMEOUT:?})",
        p.stall.describe(),
        p.lines_before,
        p.lines_after,
        p.progressed,
        p.waited
    );
    eprintln!("{label}: {report}");
    report
}

fn assert_progress(n: usize, p: &Progress, report: &str) {
    if !strict() {
        return;
    }
    assert!(
        p.stall.established,
        "harness fault: the stall was never observed with N={n} — {report}"
    );
    assert!(
        p.progressed,
        "PTY output stopped progressing while {n} tunnel streams were unread — {report}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pty_output_keeps_progressing_while_four_unread_tunnel_streams_stall() {
    // Table: four streams exhaust the 8 MiB connection window exactly,
    // eight exhaust it with margin. Every row runs before any assertion
    // fires, so one strict run records both measurements.
    let mut rows = Vec::new();
    for n in [4usize, 8] {
        let p = run_progress(n).await;
        let report = report_progress(
            "pty_output_keeps_progressing_while_four_unread_tunnel_streams_stall",
            n,
            &p,
        );
        rows.push((n, p, report));
    }
    for (n, p, report) in &rows {
        assert_progress(*n, p, report);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pty_output_keeps_progressing_with_three_unread_tunnel_streams() {
    // 3 x 2 MiB = 6 MiB leaves 2 MiB of connection window: green today.
    let p = run_progress(3).await;
    let report = report_progress(
        "pty_output_keeps_progressing_with_three_unread_tunnel_streams",
        3,
        &p,
    );
    assert_progress(3, &p, &report);
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_stream_harness_observes_data_blocked_before_measuring() {
    let h = LoopbackHarness::start().await;
    let session = h.session().await;
    let connection = session.connection().clone();

    let before = connection.quinn().stats().frame_rx;
    assert_eq!(
        before.data_blocked, 0,
        "the counter must start at zero, else it proves nothing"
    );

    let stall_streams = open_stall(&connection, 4).await;
    let stall = wait_for_stall(&connection, 4).await;
    eprintln!(
        "stalled_stream_harness_observes_data_blocked_before_measuring: N=4 {}",
        stall.describe()
    );
    drop(stall_streams);
    session.close();
    h.shutdown().await;

    assert!(
        stall.established,
        "the harness never stalled four unread tunnel streams: {}",
        stall.describe()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pty_echo_p95_stays_within_measured_rtt_plus_10ms_while_four_unread_tunnel_streams_stall() {
    let label =
        "pty_echo_p95_stays_within_measured_rtt_plus_10ms_while_four_unread_tunnel_streams_stall";
    let h = LoopbackHarness::start().await;
    let mut session = h.session().await;
    let connection = session.connection().clone();

    let opened = session
        .session_open(open_req())
        .await
        .expect("session.open");
    let pipe = h.pipes.take().expect("pipe handle for the opened session");
    let mut attached = session
        .attach(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
        })
        .await
        .expect("attach the echo session");
    tokio::spawn(echo_loop(pipe));

    let stall_streams = open_stall(&connection, 4).await;
    let stall = wait_for_stall(&connection, 4).await;

    let mut margins_ms = Vec::new();
    let mut timeouts = 0usize;
    'rounds: for round in 0..ECHO_ROUNDS as u32 {
        let marker = round.to_be_bytes().to_vec();
        let send_at = Instant::now();
        if attached.send_input(&marker).await.is_err() {
            timeouts += 1;
            break;
        }
        let recv_at = loop {
            match tokio::time::timeout(ROUND_TIMEOUT, attached.next()).await {
                Err(_) | Ok(Ok(None)) | Ok(Err(_)) => {
                    // A starved PTY: count it and stop, later rounds would
                    // only queue behind this one.
                    timeouts += 1;
                    break 'rounds;
                }
                Ok(Ok(Some(AttachEvent::Output { data, .. }))) => {
                    assert_eq!(data, marker, "round {round}: echoed bytes differ");
                    break Instant::now();
                }
                Ok(Ok(Some(_))) => continue,
            }
        };
        let rtt = connection.quinn().stats().path.rtt;
        let margin = recv_at
            .saturating_duration_since(send_at)
            .saturating_sub(rtt);
        margins_ms.push(margin.as_secs_f64() * 1000.0);
    }

    drop(stall_streams);
    attached.finish();
    session.close();
    h.shutdown().await;

    let report = if margins_ms.is_empty() {
        format!("{} rounds=0 timeouts={timeouts}", stall.describe())
    } else {
        let p95 = percentile(margins_ms.clone(), 0.95);
        let max = margins_ms.iter().cloned().fold(f64::MIN, f64::max);
        format!(
            "{} p95={p95:.3}ms (required < {MAX_MARGIN_MS}ms) max={max:.3}ms rounds={} \
             (of {ECHO_ROUNDS}) timeouts={timeouts}",
            stall.describe(),
            margins_ms.len()
        )
    };
    eprintln!("{label}: {report}");

    if !strict() {
        return;
    }
    assert!(
        stall.established,
        "harness fault: the stall was never observed — {report}"
    );
    assert_eq!(
        timeouts, 0,
        "an echo round starved behind four unread tunnel streams — {report}"
    );
    assert_eq!(margins_ms.len(), ECHO_ROUNDS, "{report}");
    let p95 = percentile(margins_ms, 0.95);
    assert!(
        p95 < MAX_MARGIN_MS,
        "PTY echo p95 >= measured RTT + {MAX_MARGIN_MS}ms under four unread tunnel streams — {report}"
    );
}
