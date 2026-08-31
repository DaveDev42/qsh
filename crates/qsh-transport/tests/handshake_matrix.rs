//! L1/L3: the handshake matrix (`docs/design/testing.md` L1,
//! `docs/ROADMAP.md` M1 DoD item 3, `PLAN.md` Step 7) — 16 named
//! (client cert, server cert, client trust store, server trust store)
//! combinations, each run over a real loopback QUIC handshake
//! (`Listener`/`Dialer`, in-process, `127.0.0.1:0`, no subprocess, no
//! sleeps).
//!
//! Each case is its own `#[tokio::test]` for a clear failure name; the
//! table below is the case index this file implements.
//!
//! | # | name                                                    | outcome |
//! |---|----------------------------------------------------------|---------|
//! | 1 | pin/pin, both valid                                       | OK |
//! | 2 | client's pin for the server is the wrong fingerprint      | client `LocalRejected{Untrusted}` |
//! | 3 | server's pin for the client is the wrong fingerprint      | remote rejected |
//! | 4 | server cert expired, pinned                               | client `LocalRejected{Expired}` |
//! | 5 | client cert expired, pinned                               | remote rejected |
//! | 6 | server cert not-yet-valid, pinned                         | client `LocalRejected{Expired}` |
//! | 7 | client trust store empty                                  | client `LocalRejected{Untrusted}` |
//! | 8 | server trust store empty                                  | remote rejected |
//! | 9 | CA mode both ways (CA1)                                   | OK |
//! | 10 | client CA1-signed, server trusts CA2 only                | remote rejected |
//! | 11 | server CA1-signed, client trusts CA2 only                | client `LocalRejected{Untrusted}` |
//! | 12 | pin-only client store vs. CA-signed server                | client `LocalRejected{Untrusted}` |
//! | 13 | CA-only server store vs. self-signed client               | remote rejected |
//! | 14 | CA-signed server leaf with no qsh SAN URI                 | client `LocalRejected{NoPrincipal}` |
//! | 15 | mixed: client by pin, server by CA                        | OK |
//! | 16 | client presents no certificate at all                     | handshake fails, no `Connection` |
//! | 17 | server `pairing_open()==true`, client cert pinned nowhere | OK, `Principal::Pairing`/`AuthPath::Pairing` |
//!
//! Case 17 is the M7 Step 4 (ADR-0002) addition: the pairing fallback only
//! ever applies *after* both the pin and CA paths have already failed
//! (`docs/design/protocol.md` §15) — it must never downgrade a peer that
//! pin/CA would otherwise have accepted, so the table above (cases 1-16)
//! is exercised unchanged with `pairing_open()` at its default `false`.
//!
//! **`PLAN.md` M3 Step 3 (c)'s "reverse dial, 비신뢰 target" row is
//! deliberately not case 17 here.** At this layer a `qsh listen` accepting
//! an untrusted `qsh reverse` target is mechanically identical to cases
//! 2/3/7/8 above (an untrusted peer's cert fails verification against the
//! listener's trust store) — bind direction is irrelevant to `Listener`.
//! What the PLAN row actually needs asserted is that this failure is
//! recorded as a handshake-level deny (`AuditRecord::handshake_rejected`,
//! `action == "connect"`) and *never* reaches a `host.reverse` audit line
//! — a claim about `qsh_core::audit`, which this crate cannot depend on
//! (`CLAUDE.md`'s dependency matrix: `qsh-transport` → `qsh-proto` only,
//! enforced by `xtask arch`). Adding a 17th case here would only
//! duplicate an already-covered rejection shape, not the thing the row is
//! actually for. The real assertion lives in
//! `crates/qsh-testkit/tests/reverse_loopback.rs`'s
//! `reverse_dial_untrusted_target_fails_handshake_before_registration` —
//! the one place a real `Listen` controller and `qsh_core::audit` are
//! both available together.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rcgen::string::Ia5String;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ED25519, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use time::{Duration as TimeDuration, OffsetDateTime};

use qsh_transport::{
    AcceptError, AuthPath, CertificateDer, DialError, Dialed, Dialer, Fingerprint, Listener,
    LocalIdentity, Principal, RejectReason, StaticTrust,
};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn gen_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ED25519).unwrap()
}

/// A generated leaf identity plus its SPKI fingerprint.
struct Cert {
    identity: LocalIdentity,
    fingerprint: Fingerprint,
}

fn self_signed_window(not_before: OffsetDateTime, not_after: OffsetDateTime) -> Cert {
    let key = gen_key();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let fingerprint = Fingerprint::of_cert_der(&der).unwrap();
    Cert {
        identity: LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: key.serialize_der(),
        },
        fingerprint,
    }
}

/// Self-signed, valid from yesterday for 10 years.
fn self_signed_valid() -> Cert {
    let now = OffsetDateTime::now_utc();
    self_signed_window(now - TimeDuration::days(1), now + TimeDuration::days(3650))
}

/// Self-signed, expired a year ago.
fn self_signed_expired() -> Cert {
    let now = OffsetDateTime::now_utc();
    self_signed_window(now - TimeDuration::days(730), now - TimeDuration::days(365))
}

/// Self-signed, not valid until a year from now.
fn self_signed_not_yet_valid() -> Cert {
    let now = OffsetDateTime::now_utc();
    self_signed_window(now + TimeDuration::days(365), now + TimeDuration::days(730))
}

/// A private CA: its own self-signed root plus the params/key needed to
/// sign leaves under it.
struct Ca {
    key: KeyPair,
    params: CertificateParams,
    der: CertificateDer<'static>,
}

fn make_ca() -> Ca {
    let key = gen_key();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    Ca { key, params, der }
}

/// A leaf signed by `ca`, optionally carrying a `qsh://...` SAN URI.
fn ca_signed(ca: &Ca, san_uri: Option<&str>) -> Cert {
    let key = gen_key();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    if let Some(uri) = san_uri {
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri).unwrap())];
    }
    let issuer = Issuer::new(ca.params.clone(), &ca.key);
    let cert = params.signed_by(&key, &issuer).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let fingerprint = Fingerprint::of_cert_der(&der).unwrap();
    Cert {
        identity: LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: key.serialize_der(),
        },
        fingerprint,
    }
}

/// What the server-side accept resolved to.
#[derive(Debug)]
enum ServerAccept {
    /// Handshake succeeded; carries the verified peer principal and the
    /// trust path that admitted it.
    Ok(Principal, AuthPath),
    /// The handshake itself failed (bad/missing/untrusted client cert).
    HandshakeErr,
    /// Handshake nominally completed but principal re-derivation failed.
    /// Not expected to occur (the verifier already ran) but handled so the
    /// match is exhaustive. The reason is kept only for `Debug` output on
    /// test failure.
    Unverified(#[allow(dead_code)] RejectReason),
    /// The listener was closed before a connection arrived.
    NoConnection,
}

impl ServerAccept {
    fn principal(&self) -> Option<&Principal> {
        match self {
            ServerAccept::Ok(p, _) => Some(p),
            _ => None,
        }
    }

    fn auth_path(&self) -> Option<AuthPath> {
        match self {
            ServerAccept::Ok(_, path) => Some(*path),
            _ => None,
        }
    }

    fn is_rejected(&self) -> bool {
        !matches!(self, ServerAccept::Ok(..))
    }
}

/// Bind a listener + spawn its accept loop, then dial it. Returns the dial
/// result and an **unjoined** handle for the server's outcome: callers must
/// decide whether to close the connection from the client side (only
/// meaningful for the OK cases — a premature close on a case that is
/// expected to die from a remote rejection would race the genuine
/// crypto-failure close and corrupt the assertion) before joining it via
/// [`join_server`].
async fn run(
    server_identity: LocalIdentity,
    server_trust: StaticTrust,
    client_identity: LocalIdentity,
    client_trust: StaticTrust,
) -> (
    Result<Dialed, DialError>,
    tokio::task::JoinHandle<ServerAccept>,
) {
    let listener = Listener::bind(loopback(), server_identity, Arc::new(server_trust)).unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let Some(incoming) = listener.accept().await else {
            return ServerAccept::NoConnection;
        };
        match incoming.accept().await {
            Ok(conn) => {
                let principal = conn.principal().clone();
                let auth_path = conn.auth_path();
                // Keep the connection open until the peer closes it (only
                // reachable when the handshake genuinely succeeded).
                let _ = conn.closed().await;
                ServerAccept::Ok(principal, auth_path)
            }
            Err(AcceptError::Unverified(reason)) => ServerAccept::Unverified(reason),
            Err(_) => ServerAccept::HandshakeErr,
        }
    });

    let dialer = Dialer::new(client_identity, Arc::new(client_trust));
    let dial_result = dialer.dial(addr, "127.0.0.1").await;

    (dial_result, server)
}

/// Join the server task. Bounded (not a sleep — a deterministic upper
/// bound) so a genuine hang fails loudly instead of wedging the suite.
async fn join_server(handle: tokio::task::JoinHandle<ServerAccept>) -> ServerAccept {
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("server task did not finish (possible hang)")
        .expect("server task panicked")
}

/// Handles both ways a server-side rejection can surface on the client:
/// either the dial fails outright with `RemoteRejected`, or it completes
/// locally and the failure only surfaces when the connection dies with a
/// crypto-class error (matches `loopback.rs`'s
/// `unpinned_client_is_rejected_by_server`, `docs/design/protocol.md` §3).
/// Must be called **without** the caller having closed the connection
/// first, or the local close would race the genuine rejection.
async fn expect_remote_rejected(result: Result<Dialed, DialError>) {
    match result {
        Err(DialError::RemoteRejected) => {}
        Ok(dialed) => {
            let err = dialed.connection.closed().await;
            assert!(
                qsh_transport::endpoint::is_crypto_failure(&err),
                "expected a crypto-class connection failure, got {err:?}"
            );
        }
        Err(other) => panic!("expected RemoteRejected (or Ok + crypto failure), got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// 1. pin/pin, both valid -> OK
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case01_pin_pin_both_valid_ok() {
    let server = self_signed_valid();
    let client = self_signed_valid();
    let server_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
    let client_trust =
        StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    let dialed = dial_result.expect("dial must succeed");
    assert_eq!(
        dialed.connection.principal(),
        &Principal::Device("box".into())
    );
    let obs = dialed
        .observation()
        .expect("client verifier recorded an observation");
    assert_eq!(obs.outcome, Ok(Principal::Device("box".into())));
    assert_eq!(dialed.connection.auth_path(), AuthPath::Pin);

    dialed.connection.close(0, b"case01 done");
    let server_outcome = join_server(server_handle).await;
    assert_eq!(
        server_outcome.principal(),
        Some(&Principal::Device("laptop".into()))
    );
    assert_eq!(server_outcome.auth_path(), Some(AuthPath::Pin));
}

// ---------------------------------------------------------------------
// 2. client's pin for the server is the wrong fingerprint -> client
//    LocalRejected{Untrusted, observed: Some(actual server fp)}
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case02_client_pin_mismatch_local_rejected() {
    let server = self_signed_valid();
    let client = self_signed_valid();
    let decoy = self_signed_valid();
    let server_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
    // The client pins a fingerprint that is not the server's.
    let client_trust =
        StaticTrust::empty().with_pin(decoy.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    match dial_result {
        Err(DialError::LocalRejected { reason, observed }) => {
            assert_eq!(reason, RejectReason::Untrusted);
            assert_eq!(observed, Some(server.fingerprint));
        }
        other => panic!("expected LocalRejected{{Untrusted}}, got {other:?}"),
    }
    let server_outcome = join_server(server_handle).await;
    assert!(
        server_outcome.is_rejected(),
        "server must never see application data from a client that rejected it: {server_outcome:?}"
    );
}

// ---------------------------------------------------------------------
// 3. server's pin for the client is the wrong fingerprint -> remote
//    rejected; server Incoming::accept() returns Err.
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case03_server_pin_mismatch_remote_rejected() {
    let server = self_signed_valid();
    let client = self_signed_valid();
    let decoy = self_signed_valid();
    // The server pins a fingerprint that is not the client's.
    let server_trust =
        StaticTrust::empty().with_pin(decoy.fingerprint, Principal::Device("someone-else".into()));
    let client_trust =
        StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    expect_remote_rejected(dial_result).await;
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 4. server cert expired, pinned -> client LocalRejected{Expired}
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case04_server_cert_expired_local_rejected() {
    let server = self_signed_expired();
    let client = self_signed_valid();
    let server_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
    let client_trust =
        StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    match dial_result {
        Err(DialError::LocalRejected { reason, observed }) => {
            assert_eq!(reason, RejectReason::Expired);
            assert_eq!(observed, Some(server.fingerprint));
        }
        other => panic!("expected LocalRejected{{Expired}}, got {other:?}"),
    }
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 5. client cert expired, pinned -> remote rejected (from the client's
//    view).
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case05_client_cert_expired_remote_rejected() {
    let server = self_signed_valid();
    let client = self_signed_expired();
    let server_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
    let client_trust =
        StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    expect_remote_rejected(dial_result).await;
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 6. server cert not-yet-valid, pinned -> client LocalRejected{Expired}
//    (RejectReason::Expired covers both edges of the validity window).
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case06_server_cert_not_yet_valid_local_rejected() {
    let server = self_signed_not_yet_valid();
    let client = self_signed_valid();
    let server_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
    let client_trust =
        StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    match dial_result {
        Err(DialError::LocalRejected { reason, observed }) => {
            assert_eq!(reason, RejectReason::Expired);
            assert_eq!(observed, Some(server.fingerprint));
        }
        other => panic!("expected LocalRejected{{Expired}}, got {other:?}"),
    }
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 7. client trust store empty (server unknown) -> client
//    LocalRejected{Untrusted, observed: Some(server fp)}
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case07_client_trust_store_empty_local_rejected() {
    let server = self_signed_valid();
    let client = self_signed_valid();
    let server_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
    let client_trust = StaticTrust::empty();

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    match dial_result {
        Err(DialError::LocalRejected { reason, observed }) => {
            assert_eq!(reason, RejectReason::Untrusted);
            assert_eq!(observed, Some(server.fingerprint));
        }
        other => panic!("expected LocalRejected{{Untrusted}}, got {other:?}"),
    }
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 8. server trust store empty (client unknown) -> remote rejected
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case08_server_trust_store_empty_remote_rejected() {
    let server = self_signed_valid();
    let client = self_signed_valid();
    let server_trust = StaticTrust::empty();
    let client_trust =
        StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    expect_remote_rejected(dial_result).await;
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 9. CA mode both ways (CA1): server SAN qsh://device/box, client SAN
//    qsh://user/dave, both trust CA1 only -> OK.
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case09_ca_mode_both_ways_ok() {
    let ca1 = make_ca();
    let server = ca_signed(&ca1, Some("qsh://device/box"));
    let client = ca_signed(&ca1, Some("qsh://user/dave"));
    let server_trust = StaticTrust::empty().with_ca(ca1.der.clone());
    let client_trust = StaticTrust::empty().with_ca(ca1.der.clone());

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    let dialed = dial_result.expect("dial must succeed");
    assert_eq!(
        dialed.connection.principal(),
        &Principal::Device("box".into())
    );
    let obs = dialed
        .observation()
        .expect("client verifier recorded an observation");
    assert_eq!(obs.outcome, Ok(Principal::Device("box".into())));
    // Both sides authenticated via the CA chain, not a pin — even though the
    // server's principal is a `Device`, which a pin would also produce.
    assert_eq!(dialed.connection.auth_path(), AuthPath::Ca);

    dialed.connection.close(0, b"case09 done");
    let server_outcome = join_server(server_handle).await;
    assert_eq!(
        server_outcome.principal(),
        Some(&Principal::User("dave".into()))
    );
    assert_eq!(server_outcome.auth_path(), Some(AuthPath::Ca));
}

// ---------------------------------------------------------------------
// 10. client CA1-signed, server trusts CA2 only -> remote rejected
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case10_client_ca1_server_trusts_ca2_only_remote_rejected() {
    let ca1 = make_ca();
    let ca2 = make_ca();
    // Server's own cert is CA2-signed so the client (which only trusts
    // CA2 here) can get far enough to observe the server's rejection of
    // its CA1-signed client cert, isolating the variable under test.
    let server = ca_signed(&ca2, Some("qsh://device/srv"));
    let client = ca_signed(&ca1, Some("qsh://user/dave"));
    let server_trust = StaticTrust::empty().with_ca(ca2.der.clone());
    let client_trust = StaticTrust::empty().with_ca(ca2.der.clone());

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    expect_remote_rejected(dial_result).await;
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 11. server CA1-signed, client trusts CA2 only -> client
//     LocalRejected{Untrusted}
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case11_server_ca1_client_trusts_ca2_only_local_rejected() {
    let ca1 = make_ca();
    let ca2 = make_ca();
    // Client's own cert is CA2-signed so the server (which only trusts
    // CA2 here) accepts it, isolating the variable under test to the
    // client's decision about the server's CA1-signed cert.
    let server = ca_signed(&ca1, Some("qsh://device/srv"));
    let client = ca_signed(&ca2, Some("qsh://user/dave"));
    let server_trust = StaticTrust::empty().with_ca(ca2.der.clone());
    let client_trust = StaticTrust::empty().with_ca(ca2.der.clone());

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    match dial_result {
        Err(DialError::LocalRejected { reason, observed }) => {
            assert_eq!(reason, RejectReason::Untrusted);
            assert_eq!(observed, Some(server.fingerprint));
        }
        other => panic!("expected LocalRejected{{Untrusted}}, got {other:?}"),
    }
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 12. pin-only client trust store, server presents a CA1-signed (not
//     pinned) leaf -> client LocalRejected{Untrusted}
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case12_pin_only_client_store_vs_ca_signed_server_local_rejected() {
    let ca1 = make_ca();
    let server = ca_signed(&ca1, Some("qsh://device/srv"));
    let client = self_signed_valid();
    let decoy = self_signed_valid();
    // Server accepts the client by pin; irrelevant to the case under test.
    let server_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
    // Pure pin-only mode: a pin exists (for an unrelated fingerprint) and
    // no CA is configured, so a CA-signed peer cert can never be trusted.
    let client_trust =
        StaticTrust::empty().with_pin(decoy.fingerprint, Principal::Device("someone-else".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    match dial_result {
        Err(DialError::LocalRejected { reason, observed }) => {
            assert_eq!(reason, RejectReason::Untrusted);
            assert_eq!(observed, Some(server.fingerprint));
        }
        other => panic!("expected LocalRejected{{Untrusted}}, got {other:?}"),
    }
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 13. CA-only server trust store, client presents a self-signed leaf ->
//     remote rejected
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case13_ca_only_server_store_vs_self_signed_client_remote_rejected() {
    let ca1 = make_ca();
    let server = ca_signed(&ca1, Some("qsh://device/srv"));
    let client = self_signed_valid();
    // Pure CA-only mode on the server: only CA1 is trusted, no pins — a
    // self-signed (non-CA1-issued) client cert can never be trusted.
    let server_trust = StaticTrust::empty().with_ca(ca1.der.clone());
    let client_trust = StaticTrust::empty().with_ca(ca1.der.clone());

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    expect_remote_rejected(dial_result).await;
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 14. CA1-signed leaf without any qsh SAN URI, peer trusts CA1 ->
//     rejected with RejectReason::NoPrincipal (as server cert -> client
//     LocalRejected{NoPrincipal}).
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case14_ca_signed_leaf_without_san_local_rejected_no_principal() {
    let ca1 = make_ca();
    let server = ca_signed(&ca1, None);
    let client = ca_signed(&ca1, Some("qsh://user/dave"));
    let server_trust = StaticTrust::empty().with_ca(ca1.der.clone());
    let client_trust = StaticTrust::empty().with_ca(ca1.der.clone());

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    match dial_result {
        Err(DialError::LocalRejected { reason, observed }) => {
            assert_eq!(reason, RejectReason::NoPrincipal);
            assert_eq!(observed, Some(server.fingerprint));
        }
        other => panic!("expected LocalRejected{{NoPrincipal}}, got {other:?}"),
    }
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}

// ---------------------------------------------------------------------
// 15. mixed: client authenticated by pin, server by CA -> OK
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case15_mixed_pin_client_ca_server_ok() {
    let ca1 = make_ca();
    let server = ca_signed(&ca1, Some("qsh://device/box"));
    let client = self_signed_valid();
    let server_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
    let client_trust = StaticTrust::empty().with_ca(ca1.der.clone());

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    let dialed = dial_result.expect("dial must succeed");
    assert_eq!(
        dialed.connection.principal(),
        &Principal::Device("box".into())
    );
    let obs = dialed
        .observation()
        .expect("client verifier recorded an observation");
    assert_eq!(obs.outcome, Ok(Principal::Device("box".into())));
    assert_eq!(dialed.connection.auth_path(), AuthPath::Ca);

    dialed.connection.close(0, b"case15 done");
    let server_outcome = join_server(server_handle).await;
    assert_eq!(
        server_outcome.principal(),
        Some(&Principal::Device("laptop".into()))
    );
    assert_eq!(server_outcome.auth_path(), Some(AuthPath::Pin));
}

// ---------------------------------------------------------------------
// 16. no client certificate at all -> handshake fails on both sides, no
//     `Connection` is ever produced.
// ---------------------------------------------------------------------

/// Accept-all server-cert verifier for the bare rustls client used only in
/// case 16 (bypassing `Dialer`, which always presents a client cert, to
/// exercise the "peer sent no cert" path).
#[derive(Debug)]
struct AcceptAllServerCerts;

impl ServerCertVerifier for AcceptAllServerCerts {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn case16_no_client_certificate_handshake_fails() {
    let server = self_signed_valid();
    // Irrelevant: no client certificate ever arrives for the server to
    // evaluate against this trust store.
    let server_trust = StaticTrust::empty();
    let listener = Listener::bind(loopback(), server.identity, Arc::new(server_trust)).unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let Some(incoming) = listener.accept().await else {
            return ServerAccept::NoConnection;
        };
        match incoming.accept().await {
            Ok(conn) => ServerAccept::Ok(conn.principal().clone(), conn.auth_path()),
            Err(AcceptError::Unverified(reason)) => ServerAccept::Unverified(reason),
            Err(_) => ServerAccept::HandshakeErr,
        }
    });

    // A bare rustls/quinn client — not built through `Dialer` — configured
    // with `with_no_client_auth()` so it never presents a certificate.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllServerCerts))
        .with_no_client_auth();
    tls.alpn_protocols = vec![qsh_proto::wire::ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(quic));
    let mut endpoint = quinn::Endpoint::client(loopback()).unwrap();
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint.connect(addr, "127.0.0.1").unwrap();
    match connecting.await {
        Err(err) => {
            assert!(
                qsh_transport::endpoint::is_crypto_failure(&err),
                "expected a crypto-class failure, got {err:?}"
            );
        }
        Ok(conn) => {
            // No `qsh_transport::Connection` is ever produced on this path
            // (we never wrapped `conn` in one) — only a bare `quinn::Connection`
            // that must die with a crypto-class error.
            let err = conn.closed().await;
            assert!(
                qsh_transport::endpoint::is_crypto_failure(&err),
                "expected a crypto-class failure, got {err:?}"
            );
        }
    }

    let server_outcome = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server task did not finish (possible hang)")
        .expect("server task panicked");
    assert!(
        server_outcome.is_rejected(),
        "server must reject a client with no certificate: {server_outcome:?}"
    );
}

// ---------------------------------------------------------------------
// 17. server pairing_open()==true, client unpinned/uncertified by any CA
//     -> OK, both sides land on Principal::Pairing / AuthPath::Pairing
//     (ADR-0002, docs/design/protocol.md §15).
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case17_pairing_open_admits_unpinned_peer_as_pairing_principal() {
    let server = self_signed_valid();
    let client = self_signed_valid();
    // Neither side pins or CA-trusts the other at all — only the server's
    // pairing fallback is open. The client accepts the server on trust for
    // this test the same way `qsh trust accept`'s dial-time evaluator does
    // (a separate, deliberately permissive evaluator — see
    // `AcceptAnyForPairing` in `qsh-core`); here that is modeled directly
    // with a pin, since what this test is actually proving is the
    // *server*-side fallback in `verify_core`, not the client's.
    let server_trust = StaticTrust::empty().with_pairing_open(true);
    let client_trust =
        StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    let dialed = dial_result
        .expect("dial must succeed even though the server has no pin/CA for this client");
    assert_eq!(
        dialed.connection.principal(),
        &Principal::Device("box".into())
    );
    assert_eq!(dialed.connection.auth_path(), AuthPath::Pin);

    dialed.connection.close(0, b"case17 done");
    let server_outcome = join_server(server_handle).await;
    assert_eq!(server_outcome.principal(), Some(&Principal::Pairing));
    assert_eq!(server_outcome.auth_path(), Some(AuthPath::Pairing));
}

// ---------------------------------------------------------------------
// 17b. pairing_open()==false (the default) still rejects an unpinned peer
//      exactly as today -- explicit regression companion to case17, even
//      though this shape is already covered by case07/case08 above.
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn case17b_pairing_closed_still_rejects_unpinned_peer() {
    let server = self_signed_valid();
    let client = self_signed_valid();
    let server_trust = StaticTrust::empty(); // pairing_open defaults to false
    let client_trust =
        StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into()));

    let (dial_result, server_handle) =
        run(server.identity, server_trust, client.identity, client_trust).await;

    expect_remote_rejected(dial_result).await;
    let server_outcome = join_server(server_handle).await;
    assert!(server_outcome.is_rejected());
}
