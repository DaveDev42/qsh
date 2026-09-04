//! Pairing-connection quota audit pins (`PLAN.md` M8 Step 4,
//! ARBITRATION-4.md J11, ruling R2): the ninth pre-identity
//! (`Principal::Pairing`) connection against a host already holding
//! [`MAX_CONCURRENT_PAIRING_CONNECTIONS`] slots is refused with an
//! immediate [`CLOSE_CODE_RESOURCE_EXHAUSTED`] close — no stream accepted,
//! no frame written — and the `quota_connections_pairing` audit line that
//! rejection leaves behind carries the *real* observed peer address (not a
//! placeholder) and `request_id == "-"` (a connection-level decision, made
//! before any request could exist).
//!
//! Uses [`qsh_testkit::pairing::PairingHarness::open_pending_pairing_
//! connections`] to hold eight real, unauthenticated-past-TLS pairing
//! connections open — `Server::quotas` is private, so there is no way to
//! reserve a slot without a live connection behind it.

use qsh_core::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS;
use qsh_core::server::CLOSE_CODE_RESOURCE_EXHAUSTED;
use qsh_testkit::loopback::make_identity;
use qsh_testkit::pairing::{PairingHarness, pairing_dialer};

/// Dial the ninth pairing connection against a host whose eight pairing
/// slots are already held, and assert the connection is refused with the
/// resource-exhausted close (no frame ever written — the same
/// non-distinguishing discipline the in-crate twin
/// `a_pairing_connection_past_its_fixed_cap_is_refused_without_naming_the_
/// reason` pins for a hand-seeded cap).
async fn dial_the_ninth_and_expect_resource_exhausted(host: &PairingHarness) -> u16 {
    let identity = make_identity();
    let dialed = pairing_dialer(identity.local)
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("the ninth connection must still complete its TLS handshake");
    // `Dialed::endpoint.local_addr()` reports the client socket's *bind*
    // address, which is the unspecified `0.0.0.0` wildcard, not the
    // `127.0.0.1` the server actually observes it dial in from — only the
    // ephemeral port is comparable across the two.
    let client_port = dialed
        .endpoint
        .local_addr()
        .expect("the dialing endpoint's own local address")
        .port();

    match dialed.connection.closed().await {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                u64::from(close.error_code),
                u64::from(CLOSE_CODE_RESOURCE_EXHAUSTED),
                "the ninth pairing connection must be closed with the resource-exhausted code, \
                 not some other reason"
            );
            assert_eq!(
                &close.reason[..],
                b"at capacity",
                "the same non-distinguishing reason the pairing cap always closes with"
            );
        }
        other => panic!(
            "expected the ninth connection to be closed by the server, got {other:?} instead \
             (it must never be admitted far enough to open a stream)"
        ),
    }

    client_port
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_connection_quota_rejection_records_the_real_peer_addr() {
    let host = PairingHarness::start().await;
    let _pending = host
        .open_pending_pairing_connections(MAX_CONCURRENT_PAIRING_CONNECTIONS)
        .await;

    let client_port = dial_the_ninth_and_expect_resource_exhausted(&host).await;

    let records = host.audit.records();
    let first = records
        .iter()
        .find(|r| r.resource == "quota_connections_pairing")
        .expect("the refusal must have written a quota_connections_pairing audit line");
    assert_eq!(
        first.peer_addr,
        format!("127.0.0.1:{client_port}"),
        "the audit line's peer_addr must be the refused connection's own observed address, \
         not a placeholder"
    );

    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_connection_quota_rejection_records_the_dash_request_id() {
    let host = PairingHarness::start().await;
    let _pending = host
        .open_pending_pairing_connections(MAX_CONCURRENT_PAIRING_CONNECTIONS)
        .await;

    dial_the_ninth_and_expect_resource_exhausted(&host).await;

    let records = host.audit.records();
    let first = records
        .iter()
        .find(|r| r.resource == "quota_connections_pairing")
        .expect("the refusal must have written a quota_connections_pairing audit line");
    assert_eq!(
        first.request_id, "-",
        "a pairing connection refused before any request exists is a connection-level \
         decision — request_id must be the \"-\" placeholder, never a stale or fabricated id"
    );

    host.shutdown().await;
}
