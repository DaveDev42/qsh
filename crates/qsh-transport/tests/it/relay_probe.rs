//! The relay check (`qsh_transport::probe_relay`) against the in-process
//! relay and against loopback sockets that answer wrongly or not at all.
//! Nothing here leaves loopback or contacts a public relay.

use std::net::Ipv4Addr;
use std::time::Duration;

use qsh_transport::{CertificateDer, IrohRelayTrust, RelayProbeStage, probe_relay};

use super::iroh_support::TestRelay;

const LIMIT: Duration = Duration::from_secs(5);

fn only(cert: &CertificateDer) -> IrohRelayTrust {
    IrohRelayTrust::OnlyRoots(vec![cert.clone()])
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_answers_ping_and_upgrades_passes() {
    let relay = TestRelay::spawn().await;
    probe_relay(&relay.url, &only(&relay.cert), LIMIT)
        .await
        .expect("ping 200 and upgrade 101");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_the_trust_does_not_accept_stops_at_tls() {
    let relay = TestRelay::spawn().await;
    let other = TestRelay::spawn().await;
    let failure = probe_relay(&relay.url, &only(&other.cert), LIMIT)
        .await
        .expect_err("the relay's certificate is not in the trust");
    assert_eq!(failure.stage, RelayProbeStage::Tls, "{failure}");
    // Nothing but the stage and a short reason: no URL beyond what the
    // caller passed in.
    assert!(!failure.detail.contains("https://"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_port_stops_at_connect() {
    // Bind and drop to find a port nothing listens on.
    let port = {
        let socket = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.local_addr().unwrap().port()
    };
    let failure = probe_relay(
        &format!("https://127.0.0.1:{port}"),
        &IrohRelayTrust::System,
        LIMIT,
    )
    .await
    .expect_err("nothing listens there");
    assert_eq!(failure.stage, RelayProbeStage::Connect, "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_socket_that_never_answers_runs_out_of_time() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let accepting = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let started = std::time::Instant::now();
    let failure = probe_relay(&url, &IrohRelayTrust::System, Duration::from_millis(700))
        .await
        .expect_err("a relay that says nothing");
    assert_eq!(failure.stage, RelayProbeStage::Timeout, "{failure}");
    assert!(started.elapsed() < Duration::from_secs(3));
    accepting.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_socket_that_speaks_something_other_than_tls_stops_at_tls() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let answering = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        }
    });
    let failure = probe_relay(&url, &IrohRelayTrust::System, LIMIT)
        .await
        .expect_err("plain HTTP on an https port");
    assert_eq!(failure.stage, RelayProbeStage::Tls, "{failure}");
    answering.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_url_that_is_not_https_stops_at_resolve() {
    for url in [
        "http://relay.example",
        "relay.example",
        "https://",
        "https://u:p@relay.example",
    ] {
        let failure = probe_relay(url, &IrohRelayTrust::System, LIMIT)
            .await
            .expect_err("not a relay URL");
        assert_eq!(failure.stage, RelayProbeStage::Resolve, "{url}: {failure}");
    }
}
