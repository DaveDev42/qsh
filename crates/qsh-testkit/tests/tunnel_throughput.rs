//! DoD 3 (M4 perf gate, `PLAN.md` M4 Step 7 (b), `docs/design/testing.md`
//! L9/L10, `docs/design/protocol.md` §12, `docs/ROADMAP.md` M4 DoD 3,
//! `docs/PRD.md` §13/§15): same process, same run — (i) a raw-quinn bidi
//! stream transfers N bytes over a connection built with quinn's own
//! **stock** `TransportConfig::default()`, (ii) the production `-L`
//! tunnel path (real inline `forward.local` ACL, real dial, real
//! `qsh_core::tunnel::splice`) transfers the same N bytes over a
//! connection built with qsh's tuned `transport_config()` — and the
//! tunnel's throughput must be at least a fraction of raw-quinn's.
//!
//! **Why the baseline is stock quinn, not qsh's tuned config.** An
//! earlier version of this file built *both* legs through
//! `qsh_transport::Dialer::dial`/`Listener::bind` — i.e. both sides ran
//! the identical `transport_config()` (BBR, `send_fairness`, the
//! tunnel-sized `stream_receive_window`). That made the ratio
//! self-normalizing: it could only ever measure `qsh-core`'s own
//! tunnel-path overhead (inline ACL, dial, `copy_bidirectional`, two
//! extra TCP hops through the local + host sockets) relative to a raw
//! stream on the *same* tuning, never whether the tuning itself is
//! earning its keep, and — more importantly — it meant a window
//! regression could never show up in this gate at all (both legs would
//! regress together and the ratio would stay flat). The baseline here
//! instead dials/binds through [`qsh_transport::Dialer::dial_stock_transport`]/
//! [`qsh_transport::Listener::bind_stock_transport`], which are identical
//! to `dial`/`bind` in every other respect (TLS, identity, verifier,
//! socket tuning) but hand quinn a bare `TransportConfig::default()`. So
//! the ratio now measures qsh's tuning-plus-splice against untuned QUIC,
//! which is what a "does our tuning help" gate should measure.
//!
//! **Why "raw-quinn" is a second connection pair, not a second stream on
//! the tunnel's own connection.** The host's app-level dispatch loop
//! (`qsh_core::server::Server::serve_control`) expects every stream a
//! peer opens to start with a wire `StreamHeader` frame; a stream that
//! doesn't isn't "raw", it's a protocol violation the host resets. A
//! second, independent connection sidesteps `qsh-core` entirely — no
//! `Hello`, no dispatch loop, no framing, just `Connection::open_bi`/
//! `accept_bi` moving bytes.
//!
//! **Interleaved trials (review finding F6).** Trials alternate
//! raw, tunnel, raw, tunnel, … with both the raw pair and the
//! [`TunnelHarness`] alive across the whole run, rather than running all
//! raw trials first and only then standing up the tunnel harness. A
//! sequential run lets any runner-wide drift over the run's lifetime
//! (thermal throttling, a GC pause in some unrelated background task, a
//! scheduler hiccup) land entirely on whichever leg ran later — biasing
//! the ratio in whichever direction that leg was measured. Interleaving
//! means drift is shared roughly evenly between the two legs and mostly
//! cancels out of the ratio instead.
//!
//! Gated by `QSH_ACCEPTANCE_SLOW`/`QSH_ACCEPTANCE_STRICT`
//! (`crates/qsh-cli/tests/reverse_blackout.rs`'s own gating idiom,
//! `PLAN.md` §4.1 #7's "M3's 60초 blackout 선례"): skipped — zero cost —
//! in the ordinary PR unit suite when neither is set. Under
//! `QSH_ACCEPTANCE_SLOW` alone this is a lenient smoke check (ratio ≥
//! 0.5, `PLAN.md` §4.2's draft margin); under `QSH_ACCEPTANCE_STRICT` it
//! asserts the literal DoD (ratio ≥ 0.8). `.github/workflows/ci.yml`'s
//! `acceptance` job sets `QSH_ACCEPTANCE_STRICT` on this test — that is
//! the certifying tier; `QSH_ACCEPTANCE_SLOW` alone is a lenient local
//! smoke tier a developer can run without CI. `docs/design/testing.md`'s
//! CI 규율 macOS-runner note ("작은 UDP 소켓 버퍼") is handled once,
//! upstream of this file: `qsh_transport::bind_tuned_udp_socket` (called
//! by every `Dialer`/`Listener` constructor, stock-transport variants
//! included) tunes `SO_RCVBUF`/`SO_SNDBUF` on every socket it binds, so
//! both paths this file measures — the raw-quinn pair below and
//! [`TunnelHarness`]'s own connection — get identical socket-level
//! treatment regardless of which `TransportConfig` rides on top.

use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::tunnel::{DiscardServer, TunnelHarness};
use qsh_transport::{Dialer, Endpoint, Listener, Principal, StaticTrust};
use tokio::net::TcpStream;

/// Bytes moved per trial. Large enough that one-time setup (TCP connect,
/// the `TCP_CONNECT`/`ConnectResult` round trip, the destination dial) is
/// noise next to the transfer itself; small enough that the whole file
/// finishes in a few seconds even under `QSH_ACCEPTANCE_STRICT` on a
/// modest shared runner.
const TRIAL_BYTES: usize = 48 * 1024 * 1024;

/// Trials per path. The ratio is computed from the *median* of each, so
/// one scheduling stall on a shared runner cannot flip strict vs. smoke —
/// the repetition-based flake defense `docs/design/testing.md`'s CI 규율
/// asks a perf gate to have, standing in for seeded retries (there is no
/// randomness here to seed).
const TRIALS: usize = 3;

/// `PLAN.md` §4.2's draft margin, adopted as final by this step's own
/// measurement (see the module's report for the numbers): the literal
/// DoD 3 ratio, enforced under `QSH_ACCEPTANCE_STRICT`.
const STRICT_RATIO: f64 = 0.80;

/// `PLAN.md` §4.2's draft smoke margin: a much more lenient bound for a
/// developer running just `QSH_ACCEPTANCE_SLOW=1` locally, wide enough to
/// absorb a slow/loaded laptop without being a no-op check.
const SMOKE_RATIO: f64 = 0.50;

fn env_flag(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim().to_string();
    !(value.is_empty() || value == "0")
}

/// The ratio this run must meet, or `None` to skip entirely — mirrors
/// `reverse_blackout.rs`'s `slow_acceptance_requested`/`skip` idiom, with
/// `QSH_ACCEPTANCE_STRICT` upgrading the smoke margin to the literal DoD.
fn required_ratio() -> Option<f64> {
    if env_flag("QSH_ACCEPTANCE_STRICT") {
        Some(STRICT_RATIO)
    } else if env_flag("QSH_ACCEPTANCE_SLOW") {
        Some(SMOKE_RATIO)
    } else {
        None
    }
}

fn skip() {
    eprintln!(
        "SKIP: the M4 DoD 3 throughput-ratio gate requires QSH_ACCEPTANCE_SLOW=1 or \
         QSH_ACCEPTANCE_STRICT=1 (neither set on this run) — `.github/workflows/ci.yml`'s \
         acceptance job sets QSH_ACCEPTANCE_STRICT (the certifying tier); QSH_ACCEPTANCE_SLOW \
         alone is a lenient local smoke tier"
    );
}

/// A raw (non-`qsh`) QUIC connection pair built on quinn's own **stock**
/// `TransportConfig::default()` (`Listener::bind_stock_transport`/
/// `Dialer::dial_stock_transport` — see this module's doc for why), but
/// nothing above transport ever runs — no `Hello`, no `qsh_core::server`
/// dispatch.
struct RawPair {
    client: qsh_transport::Connection,
    server: qsh_transport::Connection,
    _client_endpoint: Endpoint,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for RawPair {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn raw_quinn_pair() -> RawPair {
    let server_identity: TestIdentity = make_identity();
    let client_identity: TestIdentity = make_identity();
    let client_trust =
        StaticTrust::empty().with_pin(server_identity.fingerprint, Principal::Device("box".into()));
    let server_trust = StaticTrust::empty().with_pin(
        client_identity.fingerprint,
        Principal::Device("laptop".into()),
    );

    let listener = Listener::bind_stock_transport(
        "127.0.0.1:0".parse().expect("addr"),
        server_identity.local.clone(),
        Arc::new(server_trust),
    )
    .expect("bind raw listener");
    let host_addr = listener.local_addr().expect("raw listener local_addr");

    let (tx, rx) = tokio::sync::oneshot::channel();
    let accept_task = tokio::spawn(async move {
        let Some(incoming) = listener.accept().await else {
            return;
        };
        let conn = incoming.accept().await.expect("raw accept handshake");
        if tx.send(conn).is_err() {
            return;
        }
        // Park forever, holding `listener` (and its endpoint/socket)
        // alive for as long as the connection handed off above is in
        // use — dropping it would tear the endpoint down under a live
        // connection.
        std::future::pending::<()>().await;
    });

    let dialer = Dialer::new(client_identity.local, Arc::new(client_trust));
    let dialed = dialer
        .dial_stock_transport(host_addr, "127.0.0.1")
        .await
        .expect("raw dial");
    let server = rx.await.expect("raw accept completed");

    RawPair {
        client: dialed.connection,
        server,
        _client_endpoint: dialed.endpoint,
        accept_task,
    }
}

/// Send `payload` over a fresh raw bidi stream on `pair.client` and drain
/// it on `pair.server`; returns the wall-clock elapsed from the first
/// write to the receiver observing EOF.
async fn raw_quinn_transfer(pair: &RawPair, payload: Arc<Vec<u8>>) -> Duration {
    let server_conn = pair.server.clone();
    let server_task = tokio::spawn(async move {
        let (_send, mut recv) = server_conn.accept_bi().await.expect("raw accept_bi");
        let mut buf = vec![0u8; 256 * 1024];
        while let Some(_n) = recv.read(&mut buf).await.expect("raw recv") {}
    });

    let start = Instant::now();
    let (mut send, _recv) = pair.client.open_bi().await.expect("raw open_bi");
    send.write_all(&payload).await.expect("raw write_all");
    send.finish().expect("raw finish");
    server_task.await.expect("raw server task");
    start.elapsed()
}

/// Drive `payload` through a fresh `-L` local forward on `harness`,
/// pointed at a fresh [`DiscardServer`]; returns the wall-clock elapsed
/// from the first write to the sink observing EOF (the splice's
/// half-close propagated all the way through).
async fn tunnel_transfer(harness: &TunnelHarness, payload: Arc<Vec<u8>>) -> Duration {
    let (sink, done_rx) = DiscardServer::start().await.expect("bind discard sink");
    let forward = harness.local_forward("127.0.0.1", sink.addr().port()).await;
    let local_addr = forward.local_addr();

    let start = Instant::now();
    let mut conn = TcpStream::connect(local_addr)
        .await
        .expect("connect the -L listener");
    conn.set_nodelay(true).ok();
    tokio::io::AsyncWriteExt::write_all(&mut conn, &payload)
        .await
        .expect("write through the tunnel");
    tokio::io::AsyncWriteExt::shutdown(&mut conn)
        .await
        .expect("half-close the tunnel write side");
    // Keep the socket around until the sink confirms EOF so the kernel
    // doesn't RST a still-draining connection out from under the splice.
    let total = done_rx.await.expect("sink observed EOF");
    let elapsed = start.elapsed();
    assert_eq!(
        total,
        payload.len() as u64,
        "the sink must see every byte the tunnel forwarded"
    );
    drop(conn);
    elapsed
}

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    samples[samples.len() / 2]
}

fn bytes_per_sec(bytes: usize, elapsed: Duration) -> f64 {
    bytes as f64 / elapsed.as_secs_f64().max(f64::EPSILON)
}

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_throughput_meets_raw_quinn_ratio() {
    let Some(required) = required_ratio() else {
        skip();
        return;
    };

    let payload = Arc::new(vec![0xab_u8; TRIAL_BYTES]);

    // Both harnesses are stood up before either is measured, and neither
    // is torn down until every trial of both has run — the interleaving
    // this module's doc describes (review finding F6) needs both alive
    // across the whole loop, not just during their own trials.
    let raw_pair = raw_quinn_pair().await;
    let harness = TunnelHarness::start().await;

    let mut raw_bps = Vec::with_capacity(TRIALS);
    let mut tunnel_bps = Vec::with_capacity(TRIALS);
    for _ in 0..TRIALS {
        let raw_elapsed = raw_quinn_transfer(&raw_pair, Arc::clone(&payload)).await;
        raw_bps.push(bytes_per_sec(TRIAL_BYTES, raw_elapsed));

        let tunnel_elapsed = tunnel_transfer(&harness, Arc::clone(&payload)).await;
        tunnel_bps.push(bytes_per_sec(TRIAL_BYTES, tunnel_elapsed));
    }

    drop(raw_pair);
    harness.shutdown().await;

    let raw_median = median(raw_bps.clone());
    let tunnel_median = median(tunnel_bps.clone());
    let ratio = tunnel_median / raw_median;

    let report = format!(
        "raw-quinn median={raw_median:.0} B/s {raw_bps:?}, tunnel median={tunnel_median:.0} B/s \
         {tunnel_bps:?}, ratio={ratio:.3} (required ≥ {required:.2}, TRIAL_BYTES={TRIAL_BYTES}, \
         TRIALS={TRIALS})"
    );
    // DoD 3's acceptance-job log is the record of the criterion
    // (`PLAN.md` M4 Step 7 (d)) — print on success too, not just failure.
    eprintln!("tunnel_throughput_meets_raw_quinn_ratio: {report}");
    assert!(
        ratio >= required,
        "M4 DoD 3 (tunnel throughput ≥ raw-quinn × {required}) missed: {report}"
    );
}
