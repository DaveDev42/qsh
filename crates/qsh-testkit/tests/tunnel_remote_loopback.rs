//! L3: remote forward (`-R`) over a forward QUIC connection, end to end in
//! one process (`PLAN.md` M4 Step 4 (c), `docs/design/testing.md` L3).
//!
//! `-R`'s two legs are host and requester, and `crates/qsh-core`'s own
//! unit tests already cover each in isolation — `server::mod`'s
//! `authorize_and_bind_remote_forward`/`handle_rfwd_open` tests prove the
//! host binds nothing before authorizing and loopback-checking, and
//! `tunnel::remote`'s `RemoteForwardAcceptor` tests prove the requester
//! dispatches (or refuses) a `TCP_ACCEPTED` in isolation. What is missing
//! until here is the two run *against* each other: a byte written on the
//! host's bound loopback port has to survive a real `RemoteForwardOpen`
//! round trip, a real bind, a real accepted TCP connection turning into a
//! real `TCP_ACCEPTED` stream, a real dial on the requester's own
//! `RemoteForwardAcceptor`, and a real splice — and come back from the
//! echo server sitting behind the requester leg. That is DoD 2's forward
//! leg, end to end.
//!
//! No hardcoded ports and no timing assumptions, the same discipline
//! `tunnel_loopback.rs` documents: `-R`'s `bind_port` is always requested
//! as `0` here (`TunnelHarness::remote_forward`), and the echo
//! destination binds `0` too — every port in this file comes from a
//! `RemoteForwardOpened.actual_port` or a kernel bind, never a literal.
//! The one *named* port ([`dead_port`]) is reserved-then-released on
//! purpose, exactly as `tunnel_loopback.rs` uses it: a `-R` forward's
//! destination is fixed at open time, so proving one forward survives a
//! refusal and then serves successfully needs a destination that comes up
//! *after* the forward already points at it.

use qsh_core::acl::DenyAll;
use qsh_proto::ErrorCode;
use qsh_testkit::tunnel::{EchoServer, TunnelHarness, dead_port};
use tokio::net::TcpListener;

/// The audit records for `forward.remote`, in order.
fn forward_remote(h: &TunnelHarness) -> Vec<qsh_core::audit::AuditRecord> {
    h.audit()
        .records()
        .into_iter()
        .filter(|r| r.action == "forward.remote")
        .collect()
}

/// DoD 2 (forward leg): a byte written to the host's `-R` listener comes
/// back from the echo server sitting behind the requester leg, and the
/// host recorded exactly one `forward.remote` allow for the address it
/// actually bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_remote_forward_round_trips_through_the_requesters_echo() {
    let h = TunnelHarness::start().await;
    let forward = h.remote_forward("127.0.0.1", h.echo.port()).await;

    // Loopback, and kernel-assigned — the same two properties
    // `tunnel_loopback.rs` asserts for `-L`'s local port, mirrored here
    // for the host's bound one.
    assert!(forward.host_addr().ip().is_loopback());
    assert_ne!(forward.host_addr().port(), 0);
    assert!(!forward.forward_id().is_empty());

    let sent = b"hello back through the remote forward".to_vec();
    let got = TunnelHarness::round_trip(forward.host_addr(), sent.clone())
        .await
        .expect("round trip");
    assert_eq!(got, sent);

    let audit = forward_remote(&h);
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].decision, "allow");
    // The choke point audits **before** binding (`PLAN.md` M4 §155's own
    // ordering), so it names what was actually requested and authorized —
    // `TunnelHarness::remote_forward` always asks for `bind_port: 0`, and
    // the kernel has not assigned a real port yet at authorize time. The
    // *request's* `bind_host` default (empty ⇒ loopback) is still
    // substituted for display (`Server::authorize_and_bind_remote_forward`'s
    // own doc), which is why this is `"127.0.0.1:0"` and not `":0"`.
    assert_eq!(
        audit[0].resource, "127.0.0.1:0",
        "the audited resource is what was requested/authorized, before the kernel assigns \
         the real port — the bound port only exists after this decision"
    );
    assert_eq!(audit[0].principal, "device:laptop");

    forward.close().await;
    h.shutdown().await;
}

/// The splice is a byte pipe on this leg too: a payload far larger than
/// its 64 KiB copy buffer arrives whole, in order, with the half-close
/// still terminating the read — `tunnel_loopback.rs`'s own large-payload
/// case, mirrored for the opposite direction.
#[tokio::test(flavor = "multi_thread")]
async fn a_remote_forward_carries_a_payload_larger_than_one_splice_buffer() {
    let h = TunnelHarness::start().await;
    let forward = h.remote_forward("127.0.0.1", h.echo.port()).await;

    const LEN: usize = 1024 * 1024;
    let sent: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();

    let got = TunnelHarness::round_trip(forward.host_addr(), sent.clone())
        .await
        .expect("round trip");
    assert_eq!(got.len(), sent.len(), "truncated or padded");
    assert_eq!(got, sent, "reordered or corrupted");

    forward.close().await;
    h.shutdown().await;
}

/// One forward serves many accepted connections, each becoming its own
/// `TCP_ACCEPTED` stream and its own dial on the requester leg.
#[tokio::test(flavor = "multi_thread")]
async fn one_remote_forward_serves_several_connections() {
    let h = TunnelHarness::start().await;
    let forward = h.remote_forward("127.0.0.1", h.echo.port()).await;

    for n in 0..3u8 {
        let payload = vec![b'a' + n; 16];
        let got = TunnelHarness::round_trip(forward.host_addr(), payload.clone())
            .await
            .expect("round trip");
        assert_eq!(got, payload, "connection {n}");
    }

    // `RemoteForwardOpen` is authorized once, at open — not once per
    // accepted connection (unlike `-L`'s inline per-`TCP_CONNECT` gate):
    // the choke point is the control round trip, and every accept after
    // that rides the listener the open already earned.
    let audit = forward_remote(&h);
    assert_eq!(
        audit.len(),
        1,
        "one decision per forward, not per connection: {audit:?}"
    );
    assert_eq!(audit[0].decision, "allow");

    forward.close().await;
    h.shutdown().await;
}

/// `RemoteForwardClose` tears the host's listener down: after it, the
/// bound port is released, not merely unresponsive — the same "prove it
/// by rebinding" discipline `tunnel_loopback.rs`'s drop test uses, because
/// a wedged listener that accepts and hangs would pass a "connect fails"
/// assertion just as wrongly as it fails this one.
#[tokio::test(flavor = "multi_thread")]
async fn remote_forward_close_releases_the_hosts_listener() {
    let h = TunnelHarness::start().await;
    let forward = h.remote_forward("127.0.0.1", h.echo.port()).await;
    let addr = forward.host_addr();
    // Works first, so the failure below is about the close, not about the
    // address never having been live.
    assert_eq!(
        TunnelHarness::round_trip(addr, b"alive".to_vec())
            .await
            .expect("round trip"),
        b"alive"
    );

    forward.close().await;

    let rebound = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match TcpListener::bind(addr).await {
                Ok(listener) => return listener,
                Err(_still_held) => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
        }
    })
    .await
    .expect("RemoteForwardClose must release the host's bound port, not hold it");
    assert_eq!(rebound.local_addr().expect("rebound addr"), addr);
    drop(rebound);

    h.shutdown().await;
}

/// The requester's own connection dying — without ever sending
/// `RemoteForwardClose` — tears the host's listener down too: the
/// connection-bound lifecycle `docs/design/protocol.md` §3 promises,
/// exercised through a real dead connection rather than
/// `Server::purge_connection` called by hand (`server::mod`'s own unit
/// test already covers that half; this is "does a real connection death
/// actually reach it").
#[tokio::test(flavor = "multi_thread")]
async fn abandoning_the_connection_closes_the_hosts_listener() {
    let h = TunnelHarness::start().await;
    let forward = h.remote_forward("127.0.0.1", h.echo.port()).await;
    let addr = forward.host_addr();
    assert_eq!(
        TunnelHarness::round_trip(addr, b"alive".to_vec())
            .await
            .expect("round trip"),
        b"alive"
    );

    forward.abandon();

    let rebound = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match TcpListener::bind(addr).await {
                Ok(listener) => return listener,
                Err(_still_held) => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
        }
    })
    .await
    .expect(
        "a dead requester connection must release the host's bound port \
         (Server::purge_connection), not leave it wedged open",
    );
    assert_eq!(rebound.local_addr().expect("rebound addr"), addr);
    drop(rebound);

    h.shutdown().await;
}

/// A connection the requester leg cannot dial — the destination it
/// registered is a reserved-but-empty port — does not kill the forward:
/// the accepted TCP connection on the host side just sees its
/// `TCP_ACCEPTED` stream reset (`RESET_CODE_LOCAL_DIAL_FAILED`,
/// `tunnel::remote`'s own doc), and the *next* accept on the same
/// listener is served normally once the destination comes up behind it.
///
/// One forward, two connections through it, on purpose — the same reason
/// `tunnel_loopback.rs`'s mirror-image test gives: asserting survival
/// with a second, freshly opened forward would prove nothing about
/// whether the first one actually kept running.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_requester_side_dial_does_not_kill_the_forward() {
    let h = TunnelHarness::start().await;
    let port = dead_port().await.expect("reserve a dead port");
    let forward = h.remote_forward("127.0.0.1", port).await;
    let addr = forward.host_addr();

    // The requester leg's dial to `port` fails — nothing is listening —
    // so the accepted TCP connection on the host side gets no payload,
    // just a reset. `round_trip` reads to EOF either way, so an empty
    // answer (reset) is exactly what proves the refusal without hanging.
    let got = TunnelHarness::round_trip(addr, b"nobody home".to_vec())
        .await
        .unwrap_or_default();
    assert!(got.is_empty(), "a refused dial delivered payload: {got:?}");

    // The destination this forward's requester leg already points at
    // comes up. Same forward, same registered destination — only the
    // refusal is behind us.
    let _echo = EchoServer::start_on(port)
        .await
        .expect("bind the destination this forward already names");
    let got = TunnelHarness::round_trip(addr, b"still serving".to_vec())
        .await
        .expect("the forward stopped serving after one refused dial");
    assert_eq!(got, b"still serving");

    // One `RemoteForwardOpen`, one allow — the ACL choke point is at
    // open, not per accepted connection (this file's own
    // `one_remote_forward_serves_several_connections` established that).
    let audit = forward_remote(&h);
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].decision, "allow");

    forward.close().await;
    h.shutdown().await;
}

/// Choke-point ACL, through a real connection: a policy that denies
/// everything answers the `RemoteForwardOpen` with
/// `PERMISSION_DENIED` and binds **nothing**. The "bind 0" half of this
/// invariant already has an instrumented-binder unit test in
/// `qsh-core` (`server::mod`'s `rfwd_open_denied_binds_nothing_...`);
/// what this adds is that the wired path really reaches that gate: the
/// port a deny would have bound stays free.
#[tokio::test(flavor = "multi_thread")]
async fn a_denied_remote_forward_open_binds_nothing_and_is_audited() {
    let h = TunnelHarness::start_with(std::sync::Arc::new(DenyAll)).await;

    let mut session = h.host.session().await;
    let result = session
        .rfwd_open(qsh_proto::wire::RemoteForwardOpen {
            bind_host: String::new(),
            bind_port: 0,
            forward_host: "127.0.0.1".to_string(),
            forward_port: u32::from(h.echo.port()),
            claim_token: Vec::new(),
        })
        .await;
    let err = result.expect_err("DenyAll must refuse RemoteForwardOpen");
    match err {
        qsh_core::client::ClientError::Remote { code, .. } => {
            assert_eq!(code, ErrorCode::PermissionDenied);
        }
        other => panic!("expected a Remote/PERMISSION_DENIED error, got {other:?}"),
    }

    let audit = forward_remote(&h);
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].decision, "deny");

    h.shutdown().await;
}

/// The host's loopback-only enforcement, through a real connection: a
/// non-loopback `bind_host` is refused with `INVALID_ARGUMENT` — a
/// request constraint every principal hits alike, never `PERMISSION_DENIED`
/// (`crate::acl::Action::ForwardRemote`'s own doc) — and binds nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_loopback_bind_host_is_refused_and_binds_nothing() {
    let h = TunnelHarness::start().await;
    let mut session = h.host.session().await;

    let result = session
        .rfwd_open(qsh_proto::wire::RemoteForwardOpen {
            bind_host: "0.0.0.0".to_string(),
            bind_port: 0,
            forward_host: "127.0.0.1".to_string(),
            forward_port: u32::from(h.echo.port()),
            claim_token: Vec::new(),
        })
        .await;
    let err = result.expect_err("non-loopback bind_host must be refused");
    match err {
        qsh_core::client::ClientError::Remote { code, .. } => {
            assert_eq!(code, ErrorCode::InvalidArgument);
        }
        other => panic!("expected a Remote/INVALID_ARGUMENT error, got {other:?}"),
    }

    h.shutdown().await;
}
