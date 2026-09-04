//! L3: local forward (`-L`) over a forward QUIC connection, end to end in
//! one process (`PLAN.md` M4 Step 3 (c), `docs/design/testing.md` L3).
//!
//! What these tests are for: the requester leg and the host leg each have
//! in-crate unit tests, but until here they had never been run *against
//! each other*. A byte written to the local port has to traverse the real
//! `-L` listener, a real `TCP_CONNECT` stream on a real QUIC connection,
//! the host's real inline `forward.local` gate, a real dial and the real
//! splice, and come back. That is DoD 1's local leg.
//!
//! No hardcoded ports and no timing assumptions: the local listener binds
//! `0`, so does the echo destination, and every wait is on something the
//! protocol actually produces — an EOF, or a port coming back
//! (`docs/design/testing.md`, CI 규율). DoD 1's `8080` is illustrative —
//! nothing here names a port. Two tests need a *named* loopback port
//! (one destination that goes from dead to alive under a forward that
//! already points at it; one port that must be reclaimable after a
//! teardown) and both get it from the kernel first, never from a literal.
//! The only sleeping anywhere is a bounded retry poll, which fails the
//! test when it runs out rather than passing on a timeout.

use std::io;
use std::sync::Arc;

use qsh_core::acl::DenyAll;
use qsh_proto::ErrorCode;
use qsh_testkit::tunnel::{EchoServer, TunnelHarness, dead_port};
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};

/// The audit records for `forward.local`, in order.
fn forward_local(h: &TunnelHarness) -> Vec<qsh_core::audit::AuditRecord> {
    h.audit()
        .records()
        .into_iter()
        .filter(|r| r.action == "forward.local")
        .collect()
}

/// DoD 1 (local leg): a byte written to the `-L` port comes back from the
/// destination on the other side of the QUIC connection, and the host
/// recorded exactly one `forward.local` allow for the destination the
/// requester named.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_forward_round_trips_through_the_remote_echo() {
    let h = TunnelHarness::start().await;
    let forward = h.local_forward("127.0.0.1", h.echo.port()).await;

    let sent = b"hello through the tunnel".to_vec();
    let got = TunnelHarness::round_trip(forward.local_addr(), sent.clone())
        .await
        .expect("round trip");
    assert_eq!(got, sent);

    // The listener is on loopback and on a kernel-assigned port — the two
    // properties `PLAN.md` M4 §4.1 #3 and the CI port rule ask for.
    assert!(forward.local_addr().ip().is_loopback());
    assert_ne!(forward.local_addr().port(), 0);

    let audit = forward_local(&h);
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].decision, "allow");
    assert_eq!(audit[0].resource, format!("127.0.0.1:{}", h.echo.port()));
    assert_eq!(audit[0].principal, "device:laptop");

    h.shutdown().await;
}

/// The splice is a byte pipe, not a message channel: a payload far larger
/// than its 64 KiB copy buffer (and than any single QUIC frame) arrives
/// whole, in order, and the half-close at the end still terminates the
/// read. A five-byte echo would exercise none of that.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_forward_carries_a_payload_larger_than_one_splice_buffer() {
    let h = TunnelHarness::start().await;
    let forward = h.local_forward("127.0.0.1", h.echo.port()).await;

    // 1 MiB of a non-repeating-per-64-KiB pattern: a chunking bug that
    // dropped, duplicated or reordered one buffer's worth cannot cancel
    // out, and a truncation shows up as a length mismatch.
    const LEN: usize = 1024 * 1024;
    let sent: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();

    let got = TunnelHarness::round_trip(forward.local_addr(), sent.clone())
        .await
        .expect("round trip");
    assert_eq!(got.len(), sent.len(), "truncated or padded");
    assert_eq!(got, sent, "reordered or corrupted");

    h.shutdown().await;
}

/// One forward serves many connections, and each gets its own authorized
/// stream — so the second connection is a fresh `forward.local` decision,
/// not a cached one.
#[tokio::test(flavor = "multi_thread")]
async fn each_connection_on_one_forward_is_authorized_again() {
    let h = TunnelHarness::start().await;
    let forward = h.local_forward("127.0.0.1", h.echo.port()).await;

    for n in 0..3u8 {
        let payload = vec![b'a' + n; 16];
        let got = TunnelHarness::round_trip(forward.local_addr(), payload.clone())
            .await
            .expect("round trip");
        assert_eq!(got, payload, "connection {n}");
    }

    let audit = forward_local(&h);
    assert_eq!(audit.len(), 3, "one decision per connection: {audit:?}");
    assert!(audit.iter().all(|r| r.decision == "allow"));

    h.shutdown().await;
}

/// A destination nothing is listening on: the host answers
/// `ConnectResult{ok:false, code:"CONNECTION_FAILED"}` on the stream
/// (`docs/design/protocol.md` §7) — and it does so *after* authorizing,
/// which is why the audit line is there.
#[tokio::test(flavor = "multi_thread")]
async fn a_forward_to_a_dead_destination_answers_connection_failed() {
    let h = TunnelHarness::start().await;
    let port = dead_port().await.expect("reserve a dead port");

    let result = h.tcp_connect("127.0.0.1", port).await;
    assert!(!result.ok, "{result:?}");
    assert_eq!(result.code, ErrorCode::ConnectionFailed.as_str());

    let audit = forward_local(&h);
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].decision, "allow");
    assert_eq!(audit[0].resource, format!("127.0.0.1:{port}"));

    h.shutdown().await;
}

/// The same refusal seen from the local socket: the application gets a
/// connection error or an empty stream — never a clean, silent "connected,
/// no data" — and **that same forward** keeps serving afterwards.
///
/// One forward, two connections through it, on purpose. Asserting the
/// survival with a *second* forward would prove nothing: a forward that
/// died on its own refusal would still leave a freshly bound one working,
/// so the assertion would hold with the defect present. A `-L` forward's
/// destination is fixed at bind time, so the way to make one forward see
/// a refusal and then a success is to point it at a reserved-but-empty
/// port and bring the destination up behind it.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_connection_yields_no_payload_and_does_not_kill_the_forward() {
    let h = TunnelHarness::start().await;
    let port = dead_port().await.expect("reserve a dead port");
    let forward = h.local_forward("127.0.0.1", port).await;
    let addr = forward.local_addr();

    // The refusal can arrive as an RST before `connect` itself returns —
    // `abort_local`'s `set_zero_linger` (`qsh-core/src/tunnel/local.rs`)
    // means the requester leg's own socket teardown sends RST, not FIN,
    // and a macOS `connect()` that observes `SO_ERROR = ECONNRESET`
    // before the socket goes writable surfaces that as `Err` here rather
    // than a connected socket that then reads EOF/reset (CI run
    // 33801780928). Either shape is "refused, no payload" — none is.
    match TcpStream::connect(addr).await {
        Ok(mut sock) => {
            let mut got = Vec::new();
            // `Err` is the RST the requester leg sends on a refusal; `Ok`
            // is an orderly close. Either is fine — payload is not.
            let _ = sock.read_to_end(&mut got).await;
            assert!(
                got.is_empty(),
                "a refused forward delivered payload: {got:?}"
            );
            drop(sock);
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) => {}
        Err(e) => panic!("connect to the local forward: {e}"),
    }

    // The destination the forward was already pointing at comes up. Same
    // listener, same forward, same destination — only the refusal is
    // behind us.
    let _echo = EchoServer::start_on(port)
        .await
        .expect("bind the destination this forward already names");
    let got = TunnelHarness::round_trip(addr, b"still serving".to_vec())
        .await
        .expect("the forward stopped serving after one refused connection");
    assert_eq!(got, b"still serving");

    // Two connections, two inline decisions, one forward.
    let audit = forward_local(&h);
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert!(
        audit
            .iter()
            .all(|r| r.decision == "allow" && r.resource == format!("127.0.0.1:{port}")),
        "{audit:?}"
    );

    h.shutdown().await;
}

/// Inline ACL, through a real connection: a policy that denies everything
/// answers `PERMISSION_DENIED` on the stream and records the denial. The
/// "zero dials" half of this invariant is asserted with an instrumented
/// dialer in `qsh-core`'s own unit tests (there is no dial to count from
/// out here); what this adds is that the wired path really reaches that
/// gate rather than only the unit-tested function.
#[tokio::test(flavor = "multi_thread")]
async fn a_denied_forward_is_refused_on_the_stream_and_audited() {
    let h = TunnelHarness::start_with(Arc::new(DenyAll)).await;

    let result = h.tcp_connect("db.internal", 5432).await;
    assert!(!result.ok, "{result:?}");
    assert_eq!(result.code, ErrorCode::PermissionDenied.as_str());

    let audit = forward_local(&h);
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].decision, "deny");
    assert_eq!(audit[0].resource, "db.internal:5432");

    h.shutdown().await;
}

/// Dropping the handle is the whole teardown (`PLAN.md` M4 §4.1 #1): the
/// listener goes away, so the port stops accepting.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_forward_closes_the_local_listener() {
    let h = TunnelHarness::start().await;
    let forward = h.local_forward("127.0.0.1", h.echo.port()).await;
    let addr = forward.local_addr();
    // It works first, so the failure below is about the drop and not about
    // the address never having been live.
    assert_eq!(
        TunnelHarness::round_trip(addr, b"alive".to_vec())
            .await
            .expect("round trip"),
        b"alive"
    );

    drop(forward);

    // Assert the port is **released**, by taking it. Only a closed
    // listener gives it up: a wedged one still owns the address, so this
    // bind keeps failing until the bound below runs out and the test
    // fails. ("The round trip must not succeed" cannot do this job — a
    // wedged listener that accepts and never answers makes that assertion
    // hang, and a hang scored as a pass is exactly the wedge it was meant
    // to catch.)
    //
    // Bounded retry rather than one shot because the close is
    // asynchronous: `LocalForwardHandle::drop` aborts the accept task and
    // the runtime drops the listener a moment later.
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
    .expect("a dropped forward must release its local port, not hold it");
    assert_eq!(
        rebound.local_addr().expect("rebound addr"),
        addr,
        "the released port is the one the forward held"
    );
    drop(rebound);

    h.shutdown().await;
}
