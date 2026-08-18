//! What the chaos proxy actually does to the wire (`docs/design/testing.md`
//! L4, PLAN M2 Step 8).
//!
//! `chaos_proxy.rs` asserts that qsh survives the faults; this file asserts
//! that the faults happen at all. There is no QUIC here — a plain
//! `UdpSocket` stands in for the host and another for the client — so every
//! effect is observed directly on the wire: a dropped datagram never
//! arrives, a duplicated one arrives twice, a reordered one arrives after
//! its successor, a delayed one arrives late, a blackholed one never
//! arrives even if it was already staged.
//!
//! This is the negative-control half of the L4 gate. Without it, "the fault
//! fired" rests on a counter incremented by the code under test, and a
//! refactor that short-circuits the fault pipeline leaves a green suite
//! testing a plain UDP relay. Together with [`ChaosStats::is_balanced`],
//! which ties the fault counters to the counters bumped at the `send_to`
//! itself, a fault that only bumps its counter cannot survive.
//!
//! Every wait here is a deadline, never a `sleep()` to let things settle;
//! the only durations are the injected delays themselves.

use std::net::SocketAddr;
use std::time::Duration;

use qsh_testkit::chaos::{ChaosPolicy, ChaosProxy, ChaosStats, DelayDist};
use tokio::net::UdpSocket;

/// How long a datagram that *should* arrive is given. Generous: loopback
/// needs microseconds, and a slow CI box must not turn into a flake.
const ARRIVE: Duration = Duration::from_secs(5);

/// How long a datagram that must *not* arrive is watched for. Short by
/// design — it is pure waiting, and the proof it backs is a negative.
const NEVER: Duration = Duration::from_millis(200);

/// A host stand-in plus the proxy in front of it.
struct Wire {
    host: UdpSocket,
    proxy: ChaosProxy,
}

impl Wire {
    async fn start(policy: ChaosPolicy) -> Self {
        let host = UdpSocket::bind("127.0.0.1:0").await.expect("bind host");
        let proxy = ChaosProxy::start(host.local_addr().expect("host addr"), policy)
            .await
            .expect("start proxy");
        Self { host, proxy }
    }

    fn front(&self) -> SocketAddr {
        self.proxy.addr()
    }

    fn ctx(&self) -> String {
        self.proxy.detail()
    }
}

async fn client() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.expect("bind client")
}

/// Receive one datagram, or `None` if none arrives inside `within`.
async fn recv(sock: &UdpSocket, within: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; 2048];
    tokio::time::timeout(within, sock.recv_from(&mut buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|(n, peer)| (buf[..n].to_vec(), peer))
}

/// Wait until the proxy's counters satisfy `done`, so a test never asserts
/// on a snapshot taken before the relay task has caught up.
async fn until_stats(proxy: &ChaosProxy, done: impl Fn(&ChaosStats) -> bool) -> ChaosStats {
    tokio::time::timeout(ARRIVE, async {
        loop {
            let stats = proxy.stats();
            if done(&stats) {
                return stats;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("counters never settled — {}", proxy.detail()))
}

/// Control arm: no faults, so the wire is a wire.
#[tokio::test(flavor = "multi_thread")]
async fn a_fault_free_proxy_relays_both_ways_unchanged() {
    let w = Wire::start(ChaosPolicy::seeded(0)).await;
    let c = client().await;
    c.send_to(b"ping", w.front()).await.expect("send");

    let (got, from) = recv(&w.host, ARRIVE).await.expect("host got nothing");
    assert_eq!(got, b"ping", "{}", w.ctx());
    assert_eq!(
        Some(from),
        w.proxy.upstream_addr().await,
        "the host's peer is the proxy's upstream socket — {}",
        w.ctx()
    );

    w.host.send_to(b"pong", from).await.expect("reply");
    let (back, _) = recv(&c, ARRIVE).await.expect("client got nothing");
    assert_eq!(back, b"pong", "{}", w.ctx());

    let stats = until_stats(&w.proxy, |s| s.to_client > 0).await;
    assert_eq!((stats.from_client, stats.to_server), (1, 1), "{stats:?}");
    assert_eq!((stats.from_server, stats.to_client), (1, 1), "{stats:?}");
    assert!(stats.is_balanced(), "{stats:?}");
}

/// `drop` takes the datagram off the wire — it is not merely counted.
#[tokio::test(flavor = "multi_thread")]
async fn drop_takes_the_datagram_off_the_wire() {
    let w = Wire::start(ChaosPolicy::seeded(1).drop(1.0)).await;
    let c = client().await;
    for _ in 0..5 {
        c.send_to(b"gone", w.front()).await.expect("send");
    }
    let stats = until_stats(&w.proxy, |s| s.dropped >= 5).await;
    assert!(
        recv(&w.host, NEVER).await.is_none(),
        "a dropped datagram reached the host — {}",
        w.proxy.detail()
    );
    assert_eq!(stats.to_server, 0, "{stats:?}");
    assert!(stats.is_balanced(), "{stats:?}");
}

/// `duplicate` really puts a second copy on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_puts_the_datagram_on_the_wire_twice() {
    let w = Wire::start(ChaosPolicy::seeded(2).duplicate(1.0)).await;
    let c = client().await;
    c.send_to(b"echo", w.front()).await.expect("send");

    let first = recv(&w.host, ARRIVE).await.expect("no first copy");
    let second = recv(&w.host, ARRIVE).await.expect("no second copy");
    assert_eq!(first.0, b"echo", "{}", w.ctx());
    assert_eq!(second.0, b"echo", "{}", w.ctx());
    assert!(
        recv(&w.host, NEVER).await.is_none(),
        "duplicate must mean twice, not thrice — {}",
        w.proxy.detail()
    );

    let stats = until_stats(&w.proxy, |s| s.to_server >= 2).await;
    assert_eq!((stats.from_client, stats.duplicated), (1, 1), "{stats:?}");
    assert!(stats.is_balanced(), "{stats:?}");
}

/// `reorder` really swaps two datagrams: the successor arrives first.
#[tokio::test(flavor = "multi_thread")]
async fn reorder_lets_the_successor_arrive_first() {
    let w = Wire::start(ChaosPolicy::seeded(3).reorder(1.0)).await;
    let c = client().await;
    c.send_to(b"first", w.front()).await.expect("send");
    // The held datagram must be parked before its successor arrives,
    // otherwise there is nothing to overtake.
    until_stats(&w.proxy, |s| s.inflight == 1).await;
    c.send_to(b"second", w.front()).await.expect("send");

    let a = recv(&w.host, ARRIVE).await.expect("no first arrival").0;
    let b = recv(&w.host, ARRIVE).await.expect("no second arrival").0;
    assert_eq!(
        (a.as_slice(), b.as_slice()),
        (b"second".as_slice(), b"first".as_slice()),
        "the successor did not overtake — {}",
        w.proxy.detail()
    );

    let stats = until_stats(&w.proxy, |s| s.to_server >= 2).await;
    assert_eq!(stats.reordered, 1, "{stats:?}");
    assert!(stats.is_balanced(), "{stats:?}");
}

/// A hold that no successor overtakes is released unchanged, and is *not*
/// counted as a reordering.
#[tokio::test(flavor = "multi_thread")]
async fn an_unovertaken_hold_is_released_and_not_counted() {
    let w = Wire::start(ChaosPolicy::seeded(4).reorder(1.0)).await;
    let c = client().await;
    c.send_to(b"lonely", w.front()).await.expect("send");

    let got = recv(&w.host, ARRIVE).await.expect("never released").0;
    assert_eq!(got, b"lonely", "{}", w.ctx());
    let stats = until_stats(&w.proxy, |s| s.to_server >= 1).await;
    assert_eq!(
        stats.reordered, 0,
        "nothing overtook it, so nothing was reordered — {stats:?}"
    );
    assert!(stats.is_balanced(), "{stats:?}");
}

/// `delay` really holds the datagram back.
#[tokio::test(flavor = "multi_thread")]
async fn delay_holds_the_datagram_back_for_the_drawn_time() {
    const HOLD: Duration = Duration::from_millis(300);
    let w = Wire::start(ChaosPolicy::seeded(5).delay(DelayDist::fixed(HOLD))).await;
    let c = client().await;
    let sent = tokio::time::Instant::now();
    c.send_to(b"late", w.front()).await.expect("send");

    assert!(
        recv(&w.host, HOLD / 3).await.is_none(),
        "a delayed datagram arrived early — {}",
        w.proxy.detail()
    );
    let got = recv(&w.host, ARRIVE).await.expect("never arrived").0;
    assert_eq!(got, b"late", "{}", w.ctx());
    assert!(
        sent.elapsed() >= HOLD,
        "arrived after {:?}, less than the injected {HOLD:?} — {}",
        sent.elapsed(),
        w.proxy.detail()
    );
    let stats = until_stats(&w.proxy, |s| s.to_server >= 1).await;
    assert_eq!(stats.delayed, 1, "{stats:?}");
    assert!(stats.is_balanced(), "{stats:?}");
}

/// A blackhole swallows what is already staged, not only what arrives during
/// the window. The gate is at egress precisely so that a policy which also
/// delays or reorders cannot leak a staged datagram through a dead path.
#[tokio::test(flavor = "multi_thread")]
async fn blackhole_swallows_datagrams_that_were_already_staged() {
    let w = Wire::start(ChaosPolicy::seeded(6).delay(DelayDist::fixed(Duration::from_millis(100))))
        .await;
    let c = client().await;
    c.send_to(b"staged", w.front()).await.expect("send");
    // Staged (delayed) but not yet sent, and now the path dies.
    until_stats(&w.proxy, |s| s.inflight == 1).await;
    w.proxy.blackhole(Duration::from_secs(30)).await;

    assert!(
        recv(&w.host, Duration::from_millis(400)).await.is_none(),
        "a staged datagram leaked through a blackhole — {}",
        w.proxy.detail()
    );
    let during = until_stats(&w.proxy, |s| s.blackholed >= 1).await;
    assert_eq!(during.to_server, 0, "{during:?}");

    // …and the path comes back.
    w.proxy.recover().await;
    c.send_to(b"after", w.front()).await.expect("send");
    let got = recv(&w.host, ARRIVE).await.expect("never recovered").0;
    assert_eq!(got, b"after", "{}", w.ctx());
    let stats = until_stats(&w.proxy, |s| s.to_server >= 1).await;
    assert!(stats.is_balanced(), "{stats:?}");
}

/// Two clients through one proxy are two independent flows: each gets its
/// own upstream socket, and the host's reply comes back to the client that
/// earned it. A single-flow relay would cross-deliver here — which is
/// exactly the shape of a lease-steal or re-dial-before-teardown test.
#[tokio::test(flavor = "multi_thread")]
async fn two_client_flows_never_cross_deliver() {
    let w = Wire::start(ChaosPolicy::seeded(7)).await;
    let (a, b) = (client().await, client().await);
    a.send_to(b"from-a", w.front()).await.expect("send a");
    let (ga, up_a) = recv(&w.host, ARRIVE).await.expect("nothing from a");
    b.send_to(b"from-b", w.front()).await.expect("send b");
    let (gb, up_b) = recv(&w.host, ARRIVE).await.expect("nothing from b");
    assert_eq!(ga, b"from-a", "{}", w.ctx());
    assert_eq!(gb, b"from-b", "{}", w.ctx());
    assert_ne!(
        up_a,
        up_b,
        "each flow needs its own upstream socket — {}",
        w.proxy.detail()
    );
    assert_eq!(w.proxy.flows().await.len(), 2, "{}", w.proxy.detail());

    // Reply to each, out of order, and check nobody got the other's mail.
    w.host.send_to(b"for-b", up_b).await.expect("reply b");
    w.host.send_to(b"for-a", up_a).await.expect("reply a");
    assert_eq!(
        recv(&b, ARRIVE).await.expect("b got nothing").0,
        b"for-b",
        "{}",
        w.ctx()
    );
    assert_eq!(
        recv(&a, ARRIVE).await.expect("a got nothing").0,
        b"for-a",
        "{}",
        w.ctx()
    );
}

/// Severing one flow leaves the other alive, and the severed source stays
/// severed.
#[tokio::test(flavor = "multi_thread")]
async fn severing_one_flow_leaves_the_others_alive() {
    let w = Wire::start(ChaosPolicy::seeded(8)).await;
    let (a, b) = (client().await, client().await);
    a.send_to(b"a1", w.front()).await.expect("send a");
    recv(&w.host, ARRIVE).await.expect("nothing from a");
    b.send_to(b"b1", w.front()).await.expect("send b");
    recv(&w.host, ARRIVE).await.expect("nothing from b");

    let a_addr = a.local_addr().expect("a addr");
    w.proxy.sever_client(a_addr).await;
    assert_eq!(w.proxy.severed_clients().await, vec![a_addr], "{}", w.ctx());
    assert_eq!(w.proxy.flows().await.len(), 1, "{}", w.proxy.detail());

    a.send_to(b"a2", w.front()).await.expect("send a");
    b.send_to(b"b2", w.front()).await.expect("send b");
    let got = recv(&w.host, ARRIVE).await.expect("b was cut off too").0;
    assert_eq!(
        got,
        b"b2",
        "the severed client's datagram crossed — {}",
        w.ctx()
    );
    assert!(
        recv(&w.host, NEVER).await.is_none(),
        "a severed client is severed for good — {}",
        w.proxy.detail()
    );

    let stats = until_stats(&w.proxy, |s| s.refused >= 1).await;
    assert_eq!(stats.severs, 1, "{stats:?}");
    assert!(stats.is_balanced(), "{stats:?}");
}

/// The proxy's own doorway: what it received, it either relayed, dropped,
/// blackholed, staged, or could not deliver. Nothing evaporates.
#[tokio::test(flavor = "multi_thread")]
async fn the_accounting_identity_holds_under_every_fault_at_once() {
    let w = Wire::start(
        ChaosPolicy::seeded(0xBA1_A0CE)
            .drop(0.2)
            .corrupt(0.1)
            .duplicate(0.2)
            .reorder(0.2)
            .delay(DelayDist::uniform(Duration::ZERO, Duration::from_millis(2))),
    )
    .await;
    let c = client().await;
    for i in 0..200u16 {
        c.send_to(&i.to_be_bytes(), w.front()).await.expect("send");
    }
    let stats = until_stats(&w.proxy, |s| s.from_client >= 200 && s.inflight == 0).await;
    assert!(stats.dropped > 0, "{stats:?}");
    assert!(stats.duplicated > 0, "{stats:?}");
    assert!(stats.delayed > 0, "{stats:?}");
    assert!(stats.reordered > 0, "{stats:?}");
    assert!(stats.corrupted > 0, "{stats:?}");
    assert!(stats.is_balanced(), "{stats:?}");
}
