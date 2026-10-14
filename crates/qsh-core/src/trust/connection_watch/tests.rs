//! Unit tests for the pure judgment of the connection watch (ADR-0031
//! 결정 5 and 6). The watch loop, the close and the audit are pinned over
//! real QUIC connections in `crates/qsh-testkit/tests/it/trust_withdrawal.rs`.

use super::*;
use crate::trust::TrustRole;

fn device(name: &str) -> Principal {
    Principal::Device(name.to_string())
}

fn established(role: Option<TrustRole>) -> Established {
    Established {
        principal: device("laptop"),
        auth_path: AuthPath::Pin,
        fingerprint: None,
        role_grants: Some(RoleGrants::of_role(role)),
    }
}

fn pin_ok() -> Result<VerifiedPeer, RejectReason> {
    Ok(VerifiedPeer {
        principal: device("laptop"),
        auth_path: AuthPath::Pin,
    })
}

fn grants(role: TrustRole) -> Option<RoleGrants> {
    Some(RoleGrants::of_role(Some(role)))
}

#[test]
fn every_reject_reason_closes_as_trust_withdrawn() {
    for reason in [
        RejectReason::Malformed,
        RejectReason::Expired,
        RejectReason::Untrusted,
        RejectReason::NoPrincipal,
    ] {
        assert_eq!(
            judge(
                &established(Some(TrustRole::Full)),
                Err(reason),
                grants(TrustRole::Full)
            ),
            Judgment::Close(WithdrawalReason::TrustWithdrawn),
            "{reason:?}"
        );
    }
}

#[test]
fn an_auth_path_change_or_pairing_closes_as_trust_withdrawn() {
    let ca = Ok(VerifiedPeer {
        principal: Principal::User("ops".into()),
        auth_path: AuthPath::Ca,
    });
    assert_eq!(
        judge(
            &established(Some(TrustRole::Full)),
            ca,
            grants(TrustRole::Full)
        ),
        Judgment::Close(WithdrawalReason::TrustWithdrawn)
    );
    let pairing = Ok(VerifiedPeer {
        principal: Principal::Pairing,
        auth_path: AuthPath::Pairing,
    });
    assert_eq!(
        judge(&established(None), pairing, None),
        Judgment::Close(WithdrawalReason::TrustWithdrawn)
    );
    // A CA-path connection whose chain now verifies through a pin is the
    // same change seen from the other side.
    let mut ca_established = established(None);
    ca_established.auth_path = AuthPath::Ca;
    assert_eq!(
        judge(&ca_established, pin_ok(), grants(TrustRole::Full)),
        Judgment::Close(WithdrawalReason::TrustWithdrawn)
    );
}

#[test]
fn a_narrower_role_closes_as_grants_reduced_and_a_wider_one_replaces_the_record() {
    let est = established(Some(TrustRole::Full));
    for narrower in [
        TrustRole::Exec,
        TrustRole::Tunnel,
        TrustRole::ReadOnly,
        TrustRole::Reverse,
        TrustRole::None,
    ] {
        assert_eq!(
            judge(&est, pin_ok(), grants(narrower)),
            Judgment::Close(WithdrawalReason::GrantsReduced),
            "full -> {narrower}"
        );
    }
    // Widening keeps the connection and moves the record, so a later
    // narrowing is measured against the widened set.
    let exec = established(Some(TrustRole::Exec));
    let Judgment::Keep {
        role_grants,
        deferred,
    } = judge(&exec, pin_ok(), grants(TrustRole::Full))
    else {
        panic!("a widening must keep the connection");
    };
    assert!(!deferred);
    assert_eq!(role_grants, grants(TrustRole::Full));
    let widened = Established {
        role_grants,
        ..exec
    };
    assert_eq!(
        judge(&widened, pin_ok(), grants(TrustRole::Exec)),
        Judgment::Close(WithdrawalReason::GrantsReduced),
        "widen then narrow back is a reduction of the widened record"
    );
}

#[test]
fn an_unchanged_role_keeps_the_connection() {
    for role in TrustRole::ALL {
        assert_eq!(
            judge(&established(Some(role)), pin_ok(), grants(role)),
            Judgment::Keep {
                role_grants: grants(role),
                deferred: false
            },
            "{role}"
        );
    }
}

#[test]
fn a_connection_that_never_had_a_role_is_never_reduced() {
    for now in TrustRole::ALL {
        assert!(matches!(
            judge(&established(None), pin_ok(), grants(now)),
            Judgment::Keep { .. }
        ));
    }
}

/// ADR-0031 결정 6 and the Step 2 carry-over: while role grants are
/// suspended the connection stays, the recorded set stays, and the watch is
/// told to ask again on the poll cadence.
#[test]
fn a_suspended_store_keeps_the_connection_and_defers_the_comparison() {
    let est = established(Some(TrustRole::Full));
    assert_eq!(
        judge(&est, pin_ok(), None),
        Judgment::Keep {
            role_grants: est.role_grants.clone(),
            deferred: true
        }
    );
    // Trust-level checks still run during a suspension.
    assert_eq!(
        judge(&est, Err(RejectReason::Untrusted), None),
        Judgment::Close(WithdrawalReason::TrustWithdrawn)
    );
}

#[test]
fn a_baseline_that_started_unknown_is_adopted_by_the_first_readable_judgment() {
    let mut est = established(None);
    est.role_grants = None;
    assert_eq!(
        judge(&est, pin_ok(), None),
        Judgment::Keep {
            role_grants: None,
            deferred: true
        }
    );
    assert_eq!(
        judge(&est, pin_ok(), grants(TrustRole::Exec)),
        Judgment::Keep {
            role_grants: grants(TrustRole::Exec),
            deferred: false
        },
        "the first judgment that sees roles records them instead of comparing"
    );
}

#[test]
fn recovery_from_a_suspension_compares_against_the_recorded_set() {
    // Recorded `full`, suspended for a while, back with `exec`: a reduction
    // that happened during the suspension is still found.
    let est = established(Some(TrustRole::Full));
    assert_eq!(
        judge(&est, pin_ok(), grants(TrustRole::Exec)),
        Judgment::Close(WithdrawalReason::GrantsReduced)
    );
}

#[test]
fn reason_words_are_the_audit_resource_values() {
    assert_eq!(WithdrawalReason::TrustWithdrawn.as_str(), "trust_withdrawn");
    assert_eq!(WithdrawalReason::GrantsReduced.as_str(), "grants_reduced");
}

// ---------------------------------------------------------------------------
// The watch over a real QUIC connection (the three-process wiring is pinned
// in `crates/qsh-testkit/tests/it/trust_withdrawal.rs`; these two need the
// crate-private `ConnectionWatch` and the `cfg(test)` audit double).
// ---------------------------------------------------------------------------

use std::time::Duration;

use crate::audit::{FailingAuditSink, MemoryAuditSink};
use crate::tunnel::testutil::loopback_pair;

/// A `trust.toml` in a tempdir pinning `connection`'s peer as `laptop` with
/// `role`, opened as a [`SharedTrustStore`].
fn store_pinning(
    connection: &Connection,
    role: &str,
) -> (tempfile::TempDir, Arc<SharedTrustStore>, PeerFingerprint) {
    let fingerprint = connection.peer_fingerprint().expect("peer fingerprint");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("trust.toml");
    std::fs::write(
        &path,
        format!(
            "[[peer]]\nname = \"laptop\"\nfingerprint = \"{fingerprint}\"\naddress = \"\"\n\
             added_at = \"2026-10-14T00:00:00Z\"\nrole = \"{role}\"\n"
        ),
    )
    .expect("write trust.toml");
    let store = SharedTrustStore::open(&path).expect("open trust.toml");
    (dir, store, PeerFingerprint::new(*fingerprint.as_bytes()))
}

/// ADR-0031 결정 5, first bullet: a connection `reverify` cannot judge (its
/// chain is empty) is closed as `trust_withdrawn` on the watch's first
/// judgment, with the close code a peer can read.
#[tokio::test]
async fn an_unverifiable_connection_is_closed() {
    let (client, server) = loopback_pair().await;
    let (_dir, store, fingerprint) = store_pinning(&server, "full");
    let unverifiable = server.with_peer_chain_dropped();
    let audit = Arc::new(MemoryAuditSink::new());

    let watch = ConnectionWatch::begin(
        store,
        &unverifiable,
        &device("laptop"),
        AuthPath::Pin,
        Some(fingerprint),
        None,
    );
    tokio::time::timeout(Duration::from_secs(5), watch.run(audit.as_ref()))
        .await
        .expect("the watch withdraws an unverifiable connection at once");

    tokio::time::timeout(Duration::from_secs(5), client.closed())
        .await
        .expect("the peer sees the close");
    assert!(client.closed_by_trust_withdrawal());
    let records = audit.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].resource, "trust_withdrawn");
    assert_eq!(records[0].action, "connect");
    assert_eq!(records[0].decision, "deny");
    assert_eq!(records[0].principal, "device:laptop");
}

/// ADR-0031 결정 6: the close comes first, so an audit writer that fails
/// closed cannot keep a withdrawn connection open. The failure is a log
/// line and the record is simply absent.
#[tokio::test]
async fn audit_failure_does_not_keep_a_withdrawn_connection_open() {
    let (client, server) = loopback_pair().await;
    let (dir, store, fingerprint) = store_pinning(&server, "full");
    let audit = FailingAuditSink::new();
    audit.fail();

    let watch = ConnectionWatch::begin(
        Arc::clone(&store),
        &server,
        &device("laptop"),
        AuthPath::Pin,
        Some(fingerprint),
        None,
    );
    let run = tokio::spawn(async move { watch.run(&audit).await });
    // Still trusted: the watch stays pending and the connection stays open.
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), client.closed())
            .await
            .is_err(),
        "a trusted connection must stay open"
    );

    std::fs::remove_file(dir.path().join("trust.toml")).expect("delete trust.toml");
    tokio::time::timeout(Duration::from_secs(5), client.closed())
        .await
        .expect("the connection is closed although the audit record cannot be written");
    assert!(client.closed_by_trust_withdrawal());
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("the watch ends after it withdrew")
        .expect("the watch task does not panic");
}
