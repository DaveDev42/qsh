//! A jump chain on lossy, slow links (ADR-0056 decision 25, DoD 25.3).
//!
//! Every link of `C - J - T` and `C - a - b - T` is a [`ChaosProxy`] with
//! 25 ms one way and 3% loss (a fixed seed per link). The product's middle
//! peers open real UDP sockets, which netsim cannot stand in for, so the
//! proxies sit where the client's pins say each hop is:
//!
//! ```text
//!   C ==QUIC== [proxy] == a ==UDP== [proxy] == b ==UDP== [proxy] == T
//! ```
//!
//! Gated by `QSH_ACCEPTANCE_SLOW` (about a minute). It checks that the PTY
//! session, `-L` echo, exec and `qsh cp` finish with the bytes they sent,
//! that a connection that carries the echo rounds is never closed, and
//! prints the echo p95 of the datagram carrier next to the stream carrier's.
//! The two p95s are printed, not compared: with 80 rounds at a 100 to 150 ms
//! round trip the p95 is the fourth-worst round, a handful of loss events.
//! Since ADR-0058 the datagram carrier was the smaller in both shapes in
//! every run (349.8 vs 390.9 ms and 587.7 vs 769.4 ms; 349.7 vs 369.9 ms and
//! 531.7 vs 692.2 ms); before it the silence rule flipped the 3-link result.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use qsh_core::jump::carrier::Carrier;
use qsh_core::jump::{HopPin, JumpPlan};
use qsh_proto::wire::CAP_DATAGRAM_V1;
use qsh_testkit::chaos::{ChaosPolicy, ChaosProxy, DelayDist};

use super::jump_chain::{Direct, Net, close, every_feature, loopback_options};
use super::jump_perf::{echo_samples, hello, percentile, skip, slow_requested};

const ONE_WAY: Duration = Duration::from_millis(25);
const LOSS: f64 = 0.03;
const WARMUP_ROUNDS: usize = 10;
const ROUNDS: usize = 80;

fn policy(seed: u64) -> ChaosPolicy {
    ChaosPolicy::seeded(seed)
        .delay(DelayDist::fixed(ONE_WAY))
        .drop(LOSS)
}

/// One proxy per host, in front of it; `seed` is mixed with the position.
async fn proxies(addrs: &[SocketAddr], seed: u64) -> Vec<ChaosProxy> {
    let mut out = Vec::new();
    for (i, addr) in addrs.iter().enumerate() {
        out.push(
            ChaosProxy::start(*addr, policy(seed + i as u64))
                .await
                .expect("chaos proxy"),
        );
    }
    out
}

/// The features of DoD 25.1 over the lossy chain.
async fn features(names: &[&str], seed: u64) {
    let net = Net::start_unpinned(names, |_| "*", loopback_options()).await;
    let addrs: Vec<SocketAddr> = names.iter().map(|n| net.host(n).h.addr).collect();
    let proxies = proxies(&addrs, seed).await;
    for (name, proxy) in names.iter().zip(&proxies) {
        net.pin(
            name,
            Some(proxy.addr().to_string()),
            net.host(name).h.server_identity.fingerprint,
        )
        .await;
    }
    let (end, hops) = names.split_last().expect("an end");
    let ops = net.via(hops);
    every_feature(&net, &ops, end, "loss").await;
    for proxy in &proxies {
        let stats = proxy.stats();
        assert!(stats.dropped > 0, "the link dropped nothing: {stats:?}");
    }
    net.shutdown().await;
}

/// Echo p95 (ms) over the lossy chain, on the datagram carrier or, with
/// `stream_only`, on the stream; and how often the silence rule fired.
async fn lossy_echo(names: &[&str], seed: u64, stream_only: bool) -> (f64, u64) {
    let d = Direct::start(names).await;
    if stream_only {
        for name in names {
            d.host(name).h.server.hide_capabilities(&[CAP_DATAGRAM_V1]);
        }
    }
    let addrs: Vec<SocketAddr> = names.iter().map(|n| d.host(n).h.addr).collect();
    let proxies = proxies(&addrs, seed).await;
    let pins: Vec<HopPin> = names
        .iter()
        .zip(&proxies)
        .map(|(name, proxy)| HopPin {
            name: (*name).to_string(),
            address: proxy.addr().to_string(),
            fingerprint: d.host(name).h.server_identity.fingerprint,
        })
        .collect();
    let (end, hops) = pins.split_last().expect("an end");
    let plan = JumpPlan::new(hops.to_vec(), end.clone(), None, "laptop".into()).expect("a plan");
    let chain = d
        .dial(&plan, Duration::from_secs(60))
        .await
        .expect("the chain through the lossy links");
    let mut session = hello(&chain.connection).await;
    if !stream_only {
        // Let PLPMTUD open the room on every link first.
        let infos = chain.info.channels.clone();
        let end = Instant::now() + Duration::from_secs(60);
        while Instant::now() < end && !infos.iter().all(|i| i.carrier() == Carrier::Datagram) {
            let _ = session.session_list().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let samples = echo_samples(
        &d,
        names.last().expect("an end"),
        &mut session,
        WARMUP_ROUNDS,
        ROUNDS,
    )
    .await;
    assert!(
        chain.connection.close_reason().is_none(),
        "the connection did not survive the lossy run"
    );
    let fallbacks: u64 = chain
        .info
        .channels
        .iter()
        .map(|i| {
            i.silence_fallbacks
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .sum();
    drop(session);
    close(chain).await;
    d.shutdown().await;
    (percentile(samples, 0.95), fallbacks)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_chain_under_loss_on_every_link() {
    if !slow_requested() {
        skip();
        return;
    }
    for (label, names, seed) in [
        ("C-J-T", &["j", "t"][..], 0x26_0001_u64),
        ("C-a-b-T", &["a", "b", "t"][..], 0x26_0101_u64),
    ] {
        features(names, seed).await;
        let (datagram, fell_back) = lossy_echo(names, seed + 0x10, false).await;
        let (stream, _) = lossy_echo(names, seed + 0x20, true).await;
        eprintln!(
            "jump_chain_under_loss_on_every_link {label}: echo p95 datagram {datagram:.1} ms \
             (silence fallbacks {fell_back}), stream {stream:.1} ms"
        );
    }
}
