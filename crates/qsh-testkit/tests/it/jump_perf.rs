//! Jump chain performance (ADR-0056 decision 25, DoD 13), over real loopback
//! UDP. Both tests are gated by `QSH_ACCEPTANCE_SLOW` (skipped, at no cost,
//! when it is unset) and append one JSON line to `QSH_PERF_OUT` before they
//! assert, so a red run is still recorded.
//!
//! - [`jump_echo_overhead_per_hop`]: the PTY echo round trip over a direct
//!   connection, through one hop and through two. The p95 may grow by at most
//!   2 ms per hop.
//! - [`jump_tunnel_throughput`]: a `-L` transfer through one hop moves at
//!   least 50% of the bytes per second the same transfer moves over the
//!   direct connection. Three machines share one CPU here and the client
//!   encrypts two layers, which is why the bar is under PRD §13's 80%. The
//!   ratio on a bandwidth-bound path is measured by `scripts/jumpbench`.
//!
//! The channel counters are printed with the throughput line: a healthy
//! loopback chain shows no switches (ADR-0058 gave the silence rule its
//! 50 ms floor; before it the bulk upload flapped between the carriers
//! hundreds of times and the ratio swung from 0.37 to 0.56).
//!
//! The direct run and the chain runs alternate in passes and each leg is the
//! median of its passes, so drift in the machine lands on all legs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::broker::PipeHandle;
use qsh_core::client::{AttachEvent, Session};
use qsh_core::jump::ChainConn;
use qsh_core::jump::carrier::Carrier;
use qsh_core::tunnel::LocalForwardHandle;
use qsh_proto::wire;
use qsh_testkit::perf;
use qsh_testkit::tunnel::{DiscardServer, ephemeral_local_spec};
use qsh_transport::Connection;
use tokio::net::TcpStream;

use super::jump_chain::{Direct, close};

/// The extra echo p95 each hop may cost (DoD 25.13).
const MAX_HOP_OVERHEAD_MS: f64 = 2.0;
/// The share of the direct throughput one hop must keep (DoD 25.13).
const MIN_THROUGHPUT_RATIO: f64 = 0.50;
/// Echo rounds measured per leg and pass, after the warm-up.
const ROUNDS: usize = 600;
const WARMUP_ROUNDS: usize = 100;
/// Passes of the echo test; the leg's p95 is the median over them.
const ECHO_PASSES: usize = 3;
/// Bytes moved per throughput trial and trials per leg.
const TRIAL_BYTES: usize = 32 * 1024 * 1024;
const TRIALS: usize = 5;

pub(super) fn slow_requested() -> bool {
    let Some(value) = std::env::var_os("QSH_ACCEPTANCE_SLOW") else {
        return false;
    };
    let value = value.to_string_lossy().trim().to_lowercase();
    !(value.is_empty() || value == "0")
}

pub(super) fn skip() {
    eprintln!("SKIP: the jump perf gates need QSH_ACCEPTANCE_SLOW=1 (not set on this run)");
}

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    samples[samples.len() / 2]
}

/// Nearest-rank percentile (`p` in `[0, 1]`).
pub(super) fn percentile(mut samples: Vec<f64>, p: f64) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let idx = ((samples.len() as f64) * p).ceil() as usize;
    samples[idx.saturating_sub(1).min(samples.len() - 1)]
}

/// The host side of the PTY: every input chunk comes straight back.
async fn echo_loop(mut pipe: PipeHandle) {
    while let Ok(chunk) = pipe.read_input(64).await {
        if chunk.is_empty() || pipe.write_output(&chunk).await.is_err() {
            return;
        }
    }
}

/// The echo round trips (ms) of a PTY session on `connection`, whose end
/// is `d`'s host `end`.
pub(super) async fn echo_samples(
    d: &Direct,
    end: &str,
    session: &mut Session,
    warmup: usize,
    rounds: usize,
) -> Vec<f64> {
    let opened = session
        .session_open(wire::SessionOpen {
            argv: vec!["sh".into()],
            cols: 80,
            rows: 24,
            term: "xterm-256color".into(),
            ..Default::default()
        })
        .await
        .expect("session.open");
    let pipe = d.host(end).h.pipes.take().expect("the host's side");
    let mut attached = session
        .attach(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
            screen: None,
            agent_channel: Vec::new(),
        })
        .await
        .expect("attach");
    tokio::spawn(echo_loop(pipe));

    let mut samples = Vec::with_capacity(rounds);
    for round in 0..warmup + rounds {
        let marker = (round as u32).to_be_bytes().to_vec();
        let sent = Instant::now();
        attached.send_input(&marker).await.expect("input");
        let echoed = loop {
            let event = tokio::time::timeout(Duration::from_secs(10), attached.next())
                .await
                .expect("an echo within 10 s")
                .expect("attach stream read")
                .expect("attach stream still open");
            match event {
                AttachEvent::Output { data, .. } => break data,
                AttachEvent::InputAck { .. } => continue,
                other => panic!("unexpected attach event {other:?}"),
            }
        };
        assert_eq!(echoed, marker, "round {round}");
        if round >= warmup {
            samples.push(sent.elapsed().as_secs_f64() * 1000.0);
        }
    }
    attached.finish();
    samples
}

/// [`echo_samples`] over [`ROUNDS`] rounds, as the p95.
async fn echo_p95(d: &Direct, end: &str, session: &mut Session) -> f64 {
    percentile(
        echo_samples(d, end, session, WARMUP_ROUNDS, ROUNDS).await,
        0.95,
    )
}

/// Moves `payload` through a `-L` forward on `connection`; bytes per second.
async fn tunnel_bps(connection: Connection, payload: Arc<Vec<u8>>) -> f64 {
    let (sink, done) = DiscardServer::start().await.expect("sink");
    let forward = LocalForwardHandle::start(
        &ephemeral_local_spec("127.0.0.1", sink.addr().port()),
        connection,
    )
    .await
    .expect("bind the -L listener");
    let start = Instant::now();
    let mut conn = TcpStream::connect(forward.local_addr())
        .await
        .expect("connect the -L listener");
    conn.set_nodelay(true).ok();
    tokio::io::AsyncWriteExt::write_all(&mut conn, &payload)
        .await
        .expect("write through the tunnel");
    tokio::io::AsyncWriteExt::shutdown(&mut conn)
        .await
        .expect("half-close");
    let total = done.await.expect("the sink saw EOF");
    let elapsed = start.elapsed();
    assert_eq!(total, payload.len() as u64);
    drop(conn);
    drop(forward);
    payload.len() as f64 / elapsed.as_secs_f64().max(f64::EPSILON)
}

/// Lets the outer connections grow their room so every layer carries
/// datagrams, as a chain does in steady state.
async fn settle(chain: &ChainConn, session: &mut Session) {
    let infos = chain.info.channels.clone();
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end && !infos.iter().all(|i| i.carrier() == Carrier::Datagram) {
        let _ = session.session_list().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(super) async fn hello(connection: &Connection) -> Session {
    Session::negotiate(connection.clone(), "laptop")
        .await
        .expect("hello with the end")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_echo_overhead_per_hop() {
    if !slow_requested() {
        skip();
        return;
    }
    let d = Direct::start(&["a", "b", "t"]).await;
    let within = Duration::from_secs(20);
    let (mut direct, mut one, mut two) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..ECHO_PASSES {
        let (conn, endpoint) = d.dial_direct("t", within).await;
        let mut session = hello(&conn).await;
        direct.push(echo_p95(&d, "t", &mut session).await);
        drop(session);
        conn.close(0, b"done");
        endpoint.wait_idle_for(Duration::from_millis(500)).await;

        let chain = d.dial(&d.plan(&["a", "t"]), within).await.expect("one hop");
        let mut session = hello(&chain.connection).await;
        settle(&chain, &mut session).await;
        one.push(echo_p95(&d, "t", &mut session).await);
        drop(session);
        close(chain).await;

        let chain = d
            .dial(&d.plan(&["a", "b", "t"]), within)
            .await
            .expect("two hops");
        let mut session = hello(&chain.connection).await;
        settle(&chain, &mut session).await;
        two.push(echo_p95(&d, "t", &mut session).await);
        drop(session);
        close(chain).await;
    }
    d.shutdown().await;

    let direct_p95 = median(direct.clone());
    let one_p95 = median(one.clone());
    let two_p95 = median(two.clone());
    let report = format!(
        "echo p95: direct {direct_p95:.3} ms {direct:?}, 1 hop {one_p95:.3} ms {one:?}, \
         2 hops {two_p95:.3} ms {two:?} (budget {MAX_HOP_OVERHEAD_MS} ms per hop, {ROUNDS} \
         rounds, {ECHO_PASSES} passes)"
    );
    eprintln!("jump_echo_overhead_per_hop: {report}");
    perf::record(&serde_json::json!({
        "test": "jump_echo_overhead_per_hop",
        "direct_p95_ms": direct_p95,
        "hop1_p95_ms": one_p95,
        "hop2_p95_ms": two_p95,
    }));
    assert!(
        one_p95 - direct_p95 <= MAX_HOP_OVERHEAD_MS,
        "one hop costs more than {MAX_HOP_OVERHEAD_MS} ms at p95: {report}"
    );
    assert!(
        two_p95 - direct_p95 <= 2.0 * MAX_HOP_OVERHEAD_MS,
        "two hops cost more than {} ms at p95: {report}",
        2.0 * MAX_HOP_OVERHEAD_MS
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_tunnel_throughput() {
    if !slow_requested() {
        skip();
        return;
    }
    let d = Direct::start(&["a", "t"]).await;
    let within = Duration::from_secs(20);
    let payload = Arc::new(vec![0xab_u8; TRIAL_BYTES]);
    let (conn, endpoint) = d.dial_direct("t", within).await;
    let chain = d.dial(&d.plan(&["a", "t"]), within).await.expect("one hop");
    let direct_session = hello(&conn).await;
    let mut chain_session = hello(&chain.connection).await;
    settle(&chain, &mut chain_session).await;

    let (mut direct, mut hop) = (Vec::new(), Vec::new());
    for _ in 0..TRIALS {
        direct.push(tunnel_bps(conn.clone(), Arc::clone(&payload)).await);
        hop.push(tunnel_bps(chain.connection.clone(), Arc::clone(&payload)).await);
    }
    // How the channel carried it: a datagram carrier that the silence rule
    // moved to the stream, or packets dropped over the room, would show here.
    let channel = format!("{:?}", chain.info.channels[0]);
    drop((direct_session, chain_session));
    conn.close(0, b"done");
    endpoint.wait_idle_for(Duration::from_millis(500)).await;
    close(chain).await;
    d.shutdown().await;

    let direct_median = median(direct.clone());
    let hop_median = median(hop.clone());
    let ratio = hop_median / direct_median;
    let report = format!(
        "direct {:.1} MB/s {direct:?}, 1 hop {:.1} MB/s {hop:?}, ratio {ratio:.3} \
         (required >= {MIN_THROUGHPUT_RATIO}, {TRIAL_BYTES} bytes x {TRIALS}); channel {channel}",
        direct_median / 1e6,
        hop_median / 1e6,
    );
    eprintln!("jump_tunnel_throughput: {report}");
    perf::record(&serde_json::json!({
        "test": "jump_tunnel_throughput",
        "direct_mbps": direct_median * 8.0 / 1e6,
        "hop1_mbps": hop_median * 8.0 / 1e6,
        "ratio": ratio,
    }));
    assert!(
        ratio >= MIN_THROUGHPUT_RATIO,
        "one hop is too slow: {report}"
    );
}
