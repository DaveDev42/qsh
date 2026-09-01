//! `PLAN.md` M5 Step 8 (SC6, DoD 2), continued from `crates/qsh-core/tests/
//! acl_registry.rs`: the three `qsh_core::acl::OP_REGISTRY` rows that file
//! cannot drive with a bare `Server::dispatch` call —
//! `"forward.local"`/`"forward.remote"`/`"host.reverse"` — because each
//! one's real choke point sits behind machinery `crates/qsh-core/tests/`
//! (an external integration test, pub-API-only) cannot reach:
//!
//! - `forward.local`'s gate (`Server::authorize_and_dial_tunnel`) and
//!   `forward.remote`'s (`Server::authorize_and_bind_remote_forward`,
//!   reached through `Server::handle_rfwd_open`) are both `pub(crate)` —
//!   a bare `Server::dispatch` call for `RemoteForwardOpen` answers
//!   `UNSUPPORTED` with no real `Connection` to hang the forward's future
//!   `TCP_ACCEPTED` streams on (`server::mod`'s own
//!   `dispatch_rfwd_open_with_no_connection_is_unsupported` test), and
//!   `forward.local` has no `Body` variant at all (protocol.md §7's inline
//!   `TCP_CONNECT` gate, not a control-stream op).
//! - `host.reverse`'s gate (`reverse::admit::admit`) is `pub`, but
//!   reaching it for real needs a live `Listen` controller accepting a
//!   real `Hello.reverse` dial-in — the connection-time check this crate's
//!   `ReverseHarness` exists to drive.
//!
//! This file adds no new coverage on its own: `tunnel_loopback.rs`/
//! `tunnel_remote_loopback.rs`/`reverse_loopback.rs` already exercise
//! `forward.local`/`forward.remote`/`host.reverse` allow *and* deny with
//! real audit assertions (`forward_local`/`forward_remote` helpers in the
//! first two, `deny_all_creates_no_registry_entry_no_connection_and_no_session`
//! in the third). What this file adds is the **registry-consuming**
//! re-statement `PLAN.md` M5 Step 8 (c) asks for: driving each of these
//! three rows once more, by name, straight off `OP_REGISTRY` — so a row
//! renamed or removed here fails a *compile-adjacent* test (a hardcoded
//! name in `TESTKIT_ONLY_OPS` that no longer matches the registry) instead
//! of only ever being caught by prose review of the loopback suites' doc
//! comments. `crates/qsh-core/tests/acl_registry.rs`'s
//! `single_source::every_op_registry_row_is_driven_somewhere` is the other
//! half of that guard.

use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::{
    Action, ActionPattern, AllowAllPinned, DenyAll, OP_REGISTRY, Op, Policy, Rule, Scope,
};
use qsh_proto::ErrorCode;
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{ReverseHarness, wait_for_audit_records};
use qsh_testkit::tunnel::TunnelHarness;
use qsh_transport::{AuthPath, Principal, StaticTrust};

/// The three `OP_REGISTRY` rows this file is the single driver for. Kept
/// as a named list (not merely implied by the test functions below) so
/// `crates/qsh-core/tests/acl_registry.rs`'s single-source guard has
/// something concrete to name.
const TESTKIT_ONLY_OPS: &[&str] = &["forward.local", "forward.remote", "host.reverse"];

const TIMEOUT: Duration = Duration::from_secs(5);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

#[test]
fn testkit_only_ops_are_exactly_three_real_registry_rows() {
    assert_eq!(TESTKIT_ONLY_OPS.len(), 3);
    for op in TESTKIT_ONLY_OPS {
        assert!(
            OP_REGISTRY.iter().any(|spec| spec.op.as_str() == *op),
            "{op} is in TESTKIT_ONLY_OPS but not in OP_REGISTRY"
        );
    }
}

// ---------------------------------------------------------------------
// forward.local — the `-L` inline TCP_CONNECT gate.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn forward_local_is_audited_allow_and_deny() {
    let action = Op::ForwardLocal.action();

    let allow = TunnelHarness::start().await;
    let result = allow.tcp_connect("127.0.0.1", allow.echo.port()).await;
    assert!(result.ok, "{result:?}");
    let records = allow.audit().records();
    let mine: Vec<_> = records
        .iter()
        .filter(|r| r.action.as_str() == action.as_str())
        .collect();
    assert_eq!(mine.len(), 1, "{records:?}");
    assert_eq!(mine[0].decision, "allow");
    allow.shutdown().await;

    let deny = TunnelHarness::start_with(Arc::new(DenyAll)).await;
    let result = deny.tcp_connect("db.internal", 5432).await;
    assert!(!result.ok, "{result:?}");
    assert_eq!(result.code, ErrorCode::PermissionDenied.as_str());
    let records = deny.audit().records();
    let mine: Vec<_> = records
        .iter()
        .filter(|r| r.action.as_str() == action.as_str())
        .collect();
    assert_eq!(mine.len(), 1, "{records:?}");
    assert_eq!(mine[0].decision, "deny");
    deny.shutdown().await;
}

// ---------------------------------------------------------------------
// forward.remote — the `-R` `RemoteForwardOpen` choke point.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn forward_remote_is_audited_allow_and_deny() {
    let action = Op::ForwardRemote.action();

    let allow = TunnelHarness::start().await;
    let forward = allow.remote_forward("127.0.0.1", allow.echo.port()).await;
    assert!(!forward.forward_id().is_empty());
    let records = allow.audit().records();
    let mine: Vec<_> = records
        .iter()
        .filter(|r| r.action.as_str() == action.as_str())
        .collect();
    assert_eq!(mine.len(), 1, "{records:?}");
    assert_eq!(mine[0].decision, "allow");
    allow.shutdown().await;

    // `RemoteForwardOpen` needs a real `Connection` to hang a future
    // accept loop on (module doc), so the deny leg goes through
    // `TunnelHarness::host`'s own `Session` directly, the same way
    // `crates/qsh-testkit/tests/tunnel_remote_loopback.rs`'s
    // `a_denied_remote_forward_open_binds_nothing_and_is_audited` does.
    let deny = TunnelHarness::start_with(Arc::new(DenyAll)).await;
    let mut session = deny.host.session().await;
    let result = session
        .rfwd_open(qsh_proto::wire::RemoteForwardOpen {
            bind_host: String::new(),
            bind_port: 0,
            forward_host: "127.0.0.1".to_string(),
            forward_port: u32::from(deny.echo.port()),
            claim_token: Vec::new(),
        })
        .await;
    match result {
        Err(qsh_core::client::ClientError::Remote { code, .. }) => {
            assert_eq!(code, ErrorCode::PermissionDenied);
        }
        other => panic!("expected a Remote/PERMISSION_DENIED error, got {other:?}"),
    }
    let records = deny.audit().records();
    let mine: Vec<_> = records
        .iter()
        .filter(|r| r.action.as_str() == action.as_str())
        .collect();
    assert_eq!(mine.len(), 1, "{records:?}");
    assert_eq!(mine[0].decision, "deny");
    deny.shutdown().await;
}

// ---------------------------------------------------------------------
// F2 (P2-1, M5 Step 8 adversarial review) — forward.remote.close is the
// one `owned: true` `OP_REGISTRY` row `crates/qsh-core/tests/
// acl_registry.rs`'s `dod2_audit::owned_flag_matches_the_observed_
// ownership_gate_for_dispatch_drivable_rows` cannot reach: closing a
// forward that does not exist never touches ownership (`owner: None` is
// never filtered by `scope`), and a *real*, owned forward needs a live
// QUIC connection to register — this file's own reason for existing.
// This is `tunnel_remote_loopback.rs`'s `remote_forward_close_denies_a_
// different_principal_and_leaves_it_alive` scenario, but driven under an
// explicit `Policy` with `scope = "owned"` (not `AllowAllPinned`, whose
// ownership check is hardcoded independently of any policy `scope`) and
// checked against `OP_REGISTRY`'s own declared `owned` value rather than
// a hardcoded expectation, so a mutation that flips the row's declared
// `owned` without changing `Server::handle_rfwd_close`'s real behavior
// fails here.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn forward_remote_close_owned_flag_matches_the_observed_ownership_gate() {
    let spec = OP_REGISTRY
        .iter()
        .find(|s| s.op == Op::ForwardRemoteClose)
        .expect("forward.remote.close is an OP_REGISTRY row");

    let owner = make_identity();
    let other = make_identity();
    let server_trust = StaticTrust::empty()
        .with_pin(owner.fingerprint, Principal::Device("laptop".into()))
        .with_pin(other.fingerprint, Principal::Device("desktop".into()));

    // Both principals get forward.remote(.close) at the default scope =
    // "owned" so a deny (if one happens) is attributable to ownership,
    // not to a missing grant.
    let policy = Policy {
        rules: vec![
            Rule {
                principal: Principal::Device("laptop".into()).to_string(),
                auth_path: AuthPath::Pin,
                allow: vec![ActionPattern::Exact(Action::ForwardRemote)],
                scope: Scope::Owned,
            },
            Rule {
                principal: Principal::Device("desktop".into()).to_string(),
                auth_path: AuthPath::Pin,
                allow: vec![ActionPattern::Exact(Action::ForwardRemote)],
                scope: Scope::Owned,
            },
        ],
    };

    let h = TunnelHarness::start_custom(Arc::new(policy), owner, server_trust).await;
    let forward = h.remote_forward("127.0.0.1", h.echo.port()).await;
    let forward_id = forward.forward_id().to_string();

    let client_trust = StaticTrust::empty().with_pin(
        h.host.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    let dialer = qsh_transport::Dialer::new(other.local.clone(), Arc::new(client_trust));
    let dialed = dialer
        .dial(h.host.addr, "127.0.0.1")
        .await
        .expect("the second device is pinned");
    let mut desktop = qsh_core::client::Session::negotiate(dialed.connection, "desktop")
        .await
        .expect("negotiate");

    let result = desktop
        .rfwd_close(qsh_proto::wire::RemoteForwardClose {
            forward_id: forward_id.clone(),
        })
        .await;

    if spec.owned {
        let err = result.expect_err("owned: true — a non-owner must be denied");
        match err {
            qsh_core::client::ClientError::Remote { code, .. } => {
                assert_eq!(code, ErrorCode::PermissionDenied);
            }
            other => panic!("expected remote PERMISSION_DENIED, got {other:?}"),
        }
    } else {
        result.expect("owned: false — ownership must not gate this op");
    }

    h.shutdown().await;
}

// ---------------------------------------------------------------------
// host.reverse — the `Hello.reverse` connection-time registration check.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn host_reverse_is_audited_allow_and_deny() {
    let action = Op::HostReverse.action();
    assert_eq!(action, Action::HostReverse);

    let allow_target = make_identity();
    let allow_harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&allow_target, "widget"),
    )
    .await;
    allow_harness
        .register(&allow_target, "")
        .await
        .expect("AllowAllPinned admits a pinned, correctly-aliased target");
    let records = wait_for_audit_records(&allow_harness.audit, 1, TIMEOUT).await;
    let mine: Vec<_> = records
        .iter()
        .filter(|r| r.action.as_str() == action.as_str())
        .collect();
    assert_eq!(mine.len(), 1, "{records:?}");
    assert_eq!(mine[0].decision, "allow");
    allow_harness.shutdown().await;

    let deny_target = make_identity();
    let deny_harness =
        ReverseHarness::start_with(Arc::new(DenyAll), false, pin(&deny_target, "widget")).await;
    // Not `.expect_err(...)`: the `Ok` type `(Dialed, FramedStream,
    // wire::Hello)` doesn't implement `Debug` (`FramedStream` owns live
    // QUIC stream halves), the same reason `reverse_loopback.rs`'s own
    // `expect_hello_err` helper exists.
    let err = match deny_harness.register(&deny_target, "").await {
        Ok(_) => panic!("DenyAll denies everything"),
        Err(err) => err,
    };
    match err {
        qsh_core::handshake::HelloError::Remote { code, .. } => {
            assert_eq!(code, ErrorCode::PermissionDenied);
        }
        other => panic!("expected a Remote/PERMISSION_DENIED error, got {other:?}"),
    }
    let records = wait_for_audit_records(&deny_harness.audit, 1, TIMEOUT).await;
    let mine: Vec<_> = records
        .iter()
        .filter(|r| r.action.as_str() == action.as_str())
        .collect();
    assert_eq!(mine.len(), 1, "{records:?}");
    assert_eq!(mine[0].decision, "deny");
    deny_harness.shutdown().await;
}
