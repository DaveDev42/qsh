//! L3 loopback end-to-end: the pairing exchange (ADR-0002, `PLAN.md` M7
//! Step 4) — `qsh trust invite` → dial with `AcceptAnyForPairing` →
//! `PairingProof`/`PairingAccepted` → bidirectional pin, all over a real
//! QUIC connection through `Server::run`'s own accept loop (so these tests
//! exercise `Server::serve_pairing_connection` exactly as `qsh serve` would
//! run it, not a hand-rolled stand-in).
//!
//! Covers all 4 DoD quadrants (success / TTL-expiry / reuse-rejection /
//! proof-mismatch), the local-pin collision case (report §B14's ordering
//! fix: a collision must leave the invite unconsumed), and the
//! bidirectional-proof regression (report §B13): a rogue responder that
//! does not hold the secret cannot trick the initiator into pinning it.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use qsh_core::pairing::PairingError;
use qsh_core::trust::pairing::INVITE_TTL;
use qsh_proto::ErrorCode;
use qsh_proto::pairing::INVITE_SECRET_LEN;
use qsh_proto::wire::{self, ControlMessage, control_message};
use qsh_testkit::loopback::make_identity;
use qsh_testkit::pairing::{PairingHarness, pairing_dialer};
use qsh_transport::{FramedStream, Listener, StaticTrust};

fn remote_error(
    result: &Result<qsh_core::pairing::PairingSuccess, PairingError>,
) -> (ErrorCode, &str) {
    match result {
        Err(PairingError::Remote { code, message, .. }) => (code.clone(), message.as_str()),
        other => panic!("expected PairingError::Remote, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_dod_success_pins_both_sides_of_the_wire_exchange() {
    let host = PairingHarness::start().await;
    let secret = host.invite();
    let laptop = make_identity();

    let dialed = pairing_dialer(laptop.local.clone())
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial");
    let success = qsh_core::pairing::accept(&dialed.connection, "laptop", &secret)
        .await
        .expect("pairing exchange succeeds");
    assert_eq!(success.peer_device_name, "host");

    // Server-side effect: `Server::serve_pairing_connection` pinned the
    // initiator using this connection's own observed fingerprint.
    let pinned = host
        .trust_snapshot()
        .find("laptop")
        .cloned()
        .expect("laptop pinned on the host");
    assert_eq!(pinned.fingerprint, laptop.fingerprint.to_string());

    dialed.connection.close(0, b"done");
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_dod_ttl_expiry_is_trust_required_not_a_bare_rejection() {
    let host = PairingHarness::start().await;
    // Backdated past INVITE_TTL, but still within INVITE_RETENTION — so
    // `pairing_open()` is still true and this reaches the application-layer
    // exchange instead of failing the TLS handshake outright (report §B6).
    let secret = host.invite_at(SystemTime::now() - INVITE_TTL - Duration::from_secs(1));
    let laptop = make_identity();

    let dialed = pairing_dialer(laptop.local)
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial");
    let result = qsh_core::pairing::accept(&dialed.connection, "laptop", &secret).await;
    let (code, _) = remote_error(&result);
    assert_eq!(code, ErrorCode::TrustRequired);
    assert!(
        host.trust_snapshot().find("laptop").is_none(),
        "an expired invite must not pin anything"
    );

    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_dod_reuse_after_success_is_session_conflict() {
    let host = PairingHarness::start().await;
    let secret = host.invite();

    let first = make_identity();
    let dialed1 = pairing_dialer(first.local)
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial 1");
    qsh_core::pairing::accept(&dialed1.connection, "laptop", &secret)
        .await
        .expect("first redemption succeeds");
    dialed1.connection.close(0, b"done");

    // Same invite, a second (different) initiator: the invite is already
    // consumed, regardless of who is asking.
    let second = make_identity();
    let dialed2 = pairing_dialer(second.local)
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial 2");
    let result = qsh_core::pairing::accept(&dialed2.connection, "laptop2", &secret).await;
    let (code, _) = remote_error(&result);
    assert_eq!(code, ErrorCode::SessionConflict);
    assert!(
        host.trust_snapshot().find("laptop2").is_none(),
        "a reused invite must not pin the second attempt"
    );

    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_dod_wrong_secret_is_auth_failed() {
    let host = PairingHarness::start().await;
    let _live_but_unused = host.invite();
    let laptop = make_identity();

    let dialed = pairing_dialer(laptop.local)
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial");
    let wrong_secret = [0xEEu8; INVITE_SECRET_LEN];
    let result = qsh_core::pairing::accept(&dialed.connection, "laptop", &wrong_secret).await;
    let (code, _) = remote_error(&result);
    assert_eq!(code, ErrorCode::AuthFailed);
    assert!(host.trust_snapshot().find("laptop").is_none());

    host.shutdown().await;
}

/// Report §B14's ordering fix: a local-pin name collision must fail loudly
/// (`SESSION_CONFLICT`, unlike `trust add`'s own silent no-op on the same
/// underlying case) **and** must leave the matched invite unconsumed — a
/// third attempt against the very same invite, under a name that does not
/// collide, must still succeed.
#[tokio::test(flavor = "multi_thread")]
async fn pairing_collision_fails_loudly_and_leaves_the_invite_unconsumed() {
    let host = PairingHarness::start().await;

    // Pin "laptop" once, ordinarily, via a first successful pairing.
    let first_secret = host.invite();
    let original = make_identity();
    let dialed0 = pairing_dialer(original.local.clone())
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial 0");
    qsh_core::pairing::accept(&dialed0.connection, "laptop", &first_secret)
        .await
        .expect("first pairing succeeds");
    dialed0.connection.close(0, b"done");

    // A second, unrelated device pairs and claims the *same* name "laptop"
    // with a *different* identity: must collide, loudly.
    let second_secret = host.invite();
    let impostor = make_identity();
    let dialed1 = pairing_dialer(impostor.local.clone())
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial 1");
    let result = qsh_core::pairing::accept(&dialed1.connection, "laptop", &second_secret).await;
    let (code, _) = remote_error(&result);
    assert_eq!(code, ErrorCode::SessionConflict);
    assert_eq!(
        host.trust_snapshot().find("laptop").unwrap().fingerprint,
        original.fingerprint.to_string(),
        "the original pin must survive a colliding pairing attempt untouched"
    );
    dialed1.connection.close(0, b"done");

    // The invite `second_secret` came from must still be live: retrying it
    // under a name that does *not* collide succeeds.
    let dialed2 = pairing_dialer(impostor.local)
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial 2");
    let retried = qsh_core::pairing::accept(&dialed2.connection, "laptop-2", &second_secret)
        .await
        .expect("the same invite is still redeemable after a collision");
    assert_eq!(retried.peer_device_name, "host");
    assert_eq!(
        host.trust_snapshot().find("laptop-2").unwrap().fingerprint,
        impostor.fingerprint.to_string()
    );

    host.shutdown().await;
}

/// Fix A2 (responder side): the initiator's self-reported device name
/// (`PairingProof.device_name`) is validated before it ever reaches
/// `try_pin`, the invite store, or a `tracing` line — a control character
/// (here `\x1b[K`, a terminal escape) must be rejected with
/// `INVALID_ARGUMENT` over the wire, and the host's own trust store must
/// come out of the attempt exactly as empty as it went in (not just "no
/// error" — the store itself, per this fix's own instruction).
#[tokio::test(flavor = "multi_thread")]
async fn pairing_rejects_a_control_character_initiator_device_name() {
    let host = PairingHarness::start().await;
    assert!(
        host.trust_snapshot().peers().is_empty(),
        "sanity: nothing pinned before the attempt"
    );
    let secret = host.invite();
    let laptop = make_identity();

    let dialed = pairing_dialer(laptop.local)
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial");
    let result = qsh_core::pairing::accept(&dialed.connection, "laptop\u{1b}[Kname", &secret).await;
    let (code, _) = remote_error(&result);
    assert_eq!(code, ErrorCode::InvalidArgument);
    assert!(
        host.trust_snapshot().peers().is_empty(),
        "a rejected device name must leave the trust store exactly as it was"
    );

    // The invite itself must be left untouched by the rejection — a retry
    // with an ordinary name against the very same invite still succeeds
    // (the positive control: this guard is not over-broad, and rejection
    // does not burn the invite the way a successful redemption would).
    let retry_identity = make_identity();
    let dialed2 = pairing_dialer(retry_identity.local)
        .dial(host.addr, "127.0.0.1")
        .await
        .expect("dial 2");
    let retried = qsh_core::pairing::accept(&dialed2.connection, "laptop", &secret)
        .await
        .expect("the same invite is still redeemable after a rejected device name");
    assert_eq!(retried.peer_device_name, "host");
    assert_eq!(
        host.trust_snapshot().find("laptop").unwrap().fingerprint,
        retry_identity.fingerprint.to_string()
    );

    host.shutdown().await;
}

/// Report §B13's security fix, tested directly: a rogue responder with *no
/// knowledge of the secret at all* answers `PairingAccepted` unconditionally
/// (as the original, vulnerable wire shape would have let it get away
/// with). [`qsh_core::pairing::accept`] must reject it — never pin on the
/// strength of a reply merely arriving.
#[tokio::test(flavor = "multi_thread")]
async fn accept_rejects_a_rogue_responder_that_does_not_know_the_secret() {
    let responder_identity = make_identity();
    let initiator_identity = make_identity();

    let listener = Listener::bind(
        "127.0.0.1:0".parse().expect("addr"),
        responder_identity.local.clone(),
        Arc::new(StaticTrust::empty().with_pairing_open(true)),
    )
    .expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let rogue = tokio::spawn(async move {
        let incoming = listener.accept().await.expect("incoming");
        let conn = incoming.accept().await.expect("accept");
        let (send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut ctl = FramedStream::control(send, recv);
        let _proof: ControlMessage = ctl.recv.recv().await.expect("recv").expect("some message");
        // No secret was ever consulted — this is exactly the "bare accept"
        // shape report §B13 found exploitable before the fix.
        ctl.send
            .send(&ControlMessage::new(
                0,
                control_message::Body::PairingAccepted(wire::PairingAccepted {
                    device_name: "rogue".to_string(),
                    proof: vec![0u8; 32],
                }),
            ))
            .await
            .expect("send bogus PairingAccepted");
        // Give the reply a bounded chance to actually reach the initiator
        // before `conn`/`incoming` drop and tear the connection down —
        // same race `crate::pairing::respond`'s own success path had to
        // guard against (report §B14's fix, right above this file).
        if ctl.send.finish().is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(2), ctl.send.stopped()).await;
        }
    });

    let dialed = pairing_dialer(initiator_identity.local)
        .dial(addr, "127.0.0.1")
        .await
        .expect("dial the rogue responder");
    let secret = [0x11u8; INVITE_SECRET_LEN];
    let result = qsh_core::pairing::accept(&dialed.connection, "laptop", &secret).await;
    assert!(
        matches!(result, Err(PairingError::ResponderProofMismatch)),
        "expected ResponderProofMismatch, got {result:?}"
    );

    rogue.await.expect("rogue responder task");
}
