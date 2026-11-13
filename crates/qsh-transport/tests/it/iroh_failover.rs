//! Relay candidates and automatic failover (ADR-0062).
//!
//! An endpoint is given several relays. A daemon homes on the best of them
//! and moves home when that one dies; a dial offers every candidate, so it
//! reaches the daemon wherever it is homed. Discovery stays off throughout:
//! the candidates come from the caller, nothing is published or looked up.
//!
//! Everything runs on loopback against in-process relays (and, for the hung
//! case, a TCP listener that never answers); no test contacts a public relay,
//! and none binds UDP 4433, 4434 or 443.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_transport::{
    Connection, IrohConfig, IrohEndpoint, IrohPeer, IrohRelay, IrohRelayTrust, LocalIdentity,
    Principal, StaticTrust,
};

use crate::iroh_support::{TestRelay, make_identity};

/// How long a re-home may take in these tests: the grace the daemon gives a
/// home relay before it asks iroh for a net report (3 s), plus a report whose
/// HTTPS probe of the dead relay has to give up (3 s), plus slack for a loaded
/// machine.
const REHOME_BOUND: Duration = Duration::from_secs(20);

/// A dial that has to wait for the daemon to re-home.
const REDIAL_BOUND: Duration = Duration::from_secs(30);

/// A dial with a dead candidate in the set, once the daemon is homed.
const DEAD_CANDIDATE_DIAL_BOUND: Duration = Duration::from_secs(8);

struct Pair {
    daemon: IrohEndpoint,
    daemon_key: [u8; 32],
    client_id: LocalIdentity,
    client_trust: StaticTrust,
}

impl Pair {
    /// A daemon endpoint homed on the best of `daemon_relays`, accepting in
    /// the background, and what a client needs to dial it.
    async fn start(daemon_relays: IrohConfig) -> Self {
        let (server_id, server_fp) = make_identity();
        let (client_id, client_fp) = make_identity();
        let server_trust =
            StaticTrust::empty().with_pin(client_fp, Principal::Device("client".into()));
        let client_trust =
            StaticTrust::empty().with_pin(server_fp, Principal::Device("server".into()));
        let daemon = IrohEndpoint::bind(&server_id, Arc::new(server_trust), daemon_relays)
            .await
            .expect("bind the daemon endpoint");
        let accepting = daemon.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                tokio::spawn(async move {
                    // Keep each accepted connection alive for the test.
                    if let Ok(conn) = incoming.accept().await {
                        let _held: Connection = conn;
                        std::future::pending::<()>().await;
                    }
                });
            }
        });
        let daemon_key = daemon.public_key();
        Self {
            daemon,
            daemon_key,
            client_id,
            client_trust,
        }
    }

    /// Dial the daemon from a fresh client endpoint given `relays`, with the
    /// dial limited to `limit`. The client endpoint is returned so the
    /// connection keeps its endpoint.
    async fn dial(
        &self,
        relays: IrohConfig,
        limit: Duration,
    ) -> Result<(Connection, IrohEndpoint), qsh_transport::DialError> {
        let client =
            IrohEndpoint::bind_client(&self.client_id, Arc::new(self.client_trust.clone()), relays)
                .await
                .expect("bind the client endpoint")
                .with_timeout(limit);
        let conn = client.dial(&IrohPeer::new(self.daemon_key)).await?;
        Ok((conn, client))
    }

    /// Wait until the daemon is homed on a relay, and say which.
    async fn homed(&self, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            if let Some(url) = self.daemon.home_relay() {
                return norm(&url);
            }
            assert!(
                Instant::now() < deadline,
                "the daemon never picked a home relay"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait until the daemon is homed on `url`.
    async fn homed_on(&self, url: &str, within: Duration) {
        let deadline = Instant::now() + within;
        let url = norm(url);
        while self.daemon.home_relay().map(|u| norm(&u)) != Some(url.clone()) {
            assert!(
                Instant::now() < deadline,
                "the daemon is homed on {:?}, not on {url} after {within:?}",
                self.daemon.home_relay()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

fn norm(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// A dial through the set reaches a daemon homed on either candidate: the
/// client does not need to know which one it picked.
#[tokio::test]
async fn a_dial_through_the_candidate_set_reaches_the_daemon_wherever_it_is_homed() {
    let a = TestRelay::spawn().await;
    let b = TestRelay::spawn().await;
    let pair = Pair::start(TestRelay::candidates_config(&[&a, &b])).await;
    let home = pair.homed(Duration::from_secs(15)).await;
    assert!(home == norm(&a.url) || home == norm(&b.url), "{home}");
    assert_eq!(pair.daemon.relay_urls().len(), 2);

    let started = Instant::now();
    let (conn, _client) = pair
        .dial(
            TestRelay::candidates_config(&[&a, &b]),
            Duration::from_secs(15),
        )
        .await
        .expect("dial through both candidates");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    drop(conn);
}

/// The dialer's set does not have to be in the daemon's order, or even the
/// same size: it only has to contain the relay the daemon is on.
#[tokio::test]
async fn a_dialers_set_needs_only_the_relay_the_daemon_is_on() {
    let a = TestRelay::spawn().await;
    let b = TestRelay::spawn().await;
    let pair = Pair::start(TestRelay::candidates_config(&[&a, &b])).await;
    let home = pair.homed(Duration::from_secs(15)).await;
    let on = if home == norm(&a.url) { &a } else { &b };
    let (conn, _client) = pair
        .dial(on.config(), Duration::from_secs(15))
        .await
        .expect("dial through the one relay");
    drop(conn);
    // The reversed order dials the same.
    let (conn, _client) = pair
        .dial(
            TestRelay::candidates_config(&[&b, &a]),
            Duration::from_secs(15),
        )
        .await
        .expect("dial with the candidates reversed");
    drop(conn);
}

/// The failover itself: the relay the daemon is homed on dies, the daemon
/// moves to the other candidate on its own, and a fresh dial gets through.
#[tokio::test]
async fn a_daemon_rehomes_when_its_home_relay_dies_and_a_fresh_dial_succeeds() {
    let mut a = TestRelay::spawn().await;
    let mut b = TestRelay::spawn().await;
    let pair = Pair::start(TestRelay::candidates_config(&[&a, &b])).await;
    let home = pair.homed(Duration::from_secs(15)).await;

    // An established link first, so the dead relay carried something.
    let (first, first_client) = pair
        .dial(
            TestRelay::candidates_config(&[&a, &b]),
            Duration::from_secs(15),
        )
        .await
        .expect("the first dial");

    let (dead, other) = if home == norm(&a.url) {
        (&mut a, &b)
    } else {
        (&mut b, &a)
    };
    let (dead_url, other_url) = (dead.url.clone(), other.url.clone());
    let killed = Instant::now();
    dead.kill().await;

    pair.homed_on(&other_url, REHOME_BOUND).await;
    let rehomed = killed.elapsed();
    assert!(rehomed < REHOME_BOUND, "re-homing took {rehomed:?}");

    // A fresh client whose set still lists the dead relay.
    let started = Instant::now();
    let (second, second_client) = pair
        .dial(
            IrohConfig {
                relay: IrohRelay::Urls(vec![dead_url, other_url]),
                relay_trust: IrohRelayTrust::OnlyRoots(vec![a.cert.clone(), b.cert.clone()]),
                bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
                proxy_from_env: false,
                relay_quic_port: None,
            },
            Duration::from_secs(15),
        )
        .await
        .expect("a fresh dial after the failover");
    assert!(
        started.elapsed() < DEAD_CANDIDATE_DIAL_BOUND,
        "a dead candidate must not eat the dial: {:?}",
        started.elapsed()
    );
    drop((first, first_client, second, second_client));
}

/// A recovery re-dial does not wait for the daemon to re-home before it
/// starts: it begins right after the relay dies and succeeds when the daemon
/// has moved, inside one bound. This is what a supervised link does after the
/// relay under it goes away.
#[tokio::test]
async fn a_redial_started_at_the_moment_the_relay_dies_succeeds_once_the_daemon_has_moved() {
    let mut a = TestRelay::spawn().await;
    let mut b = TestRelay::spawn().await;
    let pair = Pair::start(TestRelay::candidates_config(&[&a, &b])).await;
    let home = pair.homed(Duration::from_secs(15)).await;
    let (established, established_client) = pair
        .dial(
            TestRelay::candidates_config(&[&a, &b]),
            Duration::from_secs(15),
        )
        .await
        .expect("the first dial");

    let dead = if home == norm(&a.url) { &mut a } else { &mut b };
    let started = Instant::now();
    dead.kill().await;
    drop((established, established_client));

    let config = TestRelay::candidates_config(&[&a, &b]);
    let (conn, _client) = pair
        .dial(config, REDIAL_BOUND)
        .await
        .expect("the re-dial succeeds once the daemon has moved");
    assert!(
        started.elapsed() < REDIAL_BOUND,
        "recovery took {:?}",
        started.elapsed()
    );
    drop(conn);
}

/// A relay that is down before anything starts: the daemon homes on the live
/// one and a dial with the dead one in its set is not slowed by it.
#[tokio::test]
async fn a_candidate_that_is_down_from_the_start_costs_a_dial_nothing() {
    let mut dead = TestRelay::spawn().await;
    let live = TestRelay::spawn().await;
    dead.kill().await;
    let pair = Pair::start(TestRelay::candidates_config(&[&dead, &live])).await;
    pair.homed_on(&live.url, REHOME_BOUND).await;

    let started = Instant::now();
    let (conn, _client) = pair
        .dial(
            TestRelay::candidates_config(&[&dead, &live]),
            Duration::from_secs(15),
        )
        .await
        .expect("dial with a dead candidate first in the set");
    assert!(
        started.elapsed() < DEAD_CANDIDATE_DIAL_BOUND,
        "{:?}",
        started.elapsed()
    );
    drop(conn);
}

/// A candidate that accepts the TCP connection and never says a word (a
/// blackholed relay) does not stall the dial either: its probe gives up on its
/// own clock and the live candidate carries the connection.
#[tokio::test]
async fn a_candidate_that_never_answers_does_not_stall_the_dial() {
    let hung_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the hung relay");
    let hung_url = format!("https://{}", hung_listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = hung_listener.accept().await {
            held.push(stream);
        }
    });
    let live = TestRelay::spawn().await;
    let set = |live: &TestRelay| IrohConfig {
        relay: IrohRelay::Urls(vec![hung_url.clone(), live.url.clone()]),
        relay_trust: IrohRelayTrust::OnlyRoots(vec![live.cert.clone()]),
        bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
        proxy_from_env: false,
        relay_quic_port: None,
    };
    let pair = Pair::start(set(&live)).await;
    pair.homed_on(&live.url, REHOME_BOUND).await;

    let started = Instant::now();
    let (conn, _client) = pair
        .dial(set(&live), Duration::from_secs(15))
        .await
        .expect("dial with a hung candidate in the set");
    assert!(
        started.elapsed() < DEAD_CANDIDATE_DIAL_BOUND,
        "{:?}",
        started.elapsed()
    );
    drop(conn);
}

/// With every candidate down, the dial fails (it does not hang past its own
/// timeout) and the daemon reports no home relay.
#[tokio::test]
async fn with_every_candidate_down_the_dial_fails_within_its_timeout() {
    let mut a = TestRelay::spawn().await;
    let mut b = TestRelay::spawn().await;
    let pair = Pair::start(TestRelay::candidates_config(&[&a, &b])).await;
    pair.homed(Duration::from_secs(15)).await;
    let config = TestRelay::candidates_config(&[&a, &b]);
    a.kill().await;
    b.kill().await;

    let started = Instant::now();
    let result = pair.dial(config, Duration::from_secs(4)).await;
    assert!(result.is_err(), "no relay is up");
    assert!(
        started.elapsed() < Duration::from_secs(7),
        "the dial gave up late: {:?}",
        started.elapsed()
    );
}

/// The candidate list is bounded and every URL must parse: a bad set is a
/// setup error before any socket opens.
#[tokio::test]
async fn a_bad_candidate_set_is_refused_before_binding() {
    let (id, _) = make_identity();
    let too_many: Vec<String> = (0..=qsh_transport::MAX_RELAY_CANDIDATES)
        .map(|i| format!("https://relay{i}.invalid"))
        .collect();
    for relay in [
        IrohRelay::Urls(too_many),
        IrohRelay::Urls(vec!["https://ok.invalid".into(), "not a url".into()]),
    ] {
        let config = IrohConfig {
            relay,
            relay_trust: IrohRelayTrust::System,
            bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
            proxy_from_env: false,
            relay_quic_port: None,
        };
        assert!(
            IrohEndpoint::bind(&id, Arc::new(StaticTrust::empty()), config)
                .await
                .is_err()
        );
    }
}
