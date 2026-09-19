use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::tunnel::testutil::{ScriptedResolver, addr, loopback_pair};

// ---- timeout_needs_backoff: the busy-loop guard (adversarial-review
// finding — `qsh tunnel close` on a still-claimed reverse forward left
// its claim loop spinning with no backoff at all) ------------------

/// The regression this whole function exists for: a `Timeout` that
/// came back in well under the ~60s wait budget cannot have genuinely
/// waited it out — `claim_tcp_accepted` only returns that fast when
/// `admits_claim` was already `false` before the first `.await`
/// (registration removed out from under this loop, e.g. by
/// `ControlHub::admin_close_forward`). Before this fix, every
/// `Timeout` retried instantly regardless — this is the exact
/// condition (`elapsed` near zero) that turned into an unbounded hot
/// spin.
#[cfg(unix)]
#[test]
fn a_near_instant_timeout_needs_backoff() {
    assert!(
        timeout_needs_backoff(Duration::from_millis(0)),
        "a Timeout with ~0 elapsed is the fast-path (unregistered) case and must back off"
    );
    assert!(timeout_needs_backoff(Duration::from_millis(5)));
    assert!(timeout_needs_backoff(Duration::from_millis(500)));
}

/// The ordinary case must be left alone: a `Timeout` that actually
/// spent close to the real ~60s wait budget is the long-poll draining
/// normally, and retrying at once *is* the wait — backing it off too
/// would silently slow down every healthy `-R`'s throughput.
#[cfg(unix)]
#[test]
fn a_genuine_long_poll_timeout_does_not_need_backoff() {
    assert!(!timeout_needs_backoff(FAST_TIMEOUT_THRESHOLD));
    assert!(!timeout_needs_backoff(Duration::from_secs(60)));
}

// ---- all_loopback: the pure fold, network-free -------------------

#[test]
fn all_loopback_requires_every_address_not_just_one() {
    // The bypass vector this module's doc names: one loopback answer
    // among several must not be enough.
    assert!(!all_loopback([
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), // TEST-NET-3, public-shaped
    ]));
    // ...but the mirror image is loopback-safe: several addresses,
    // all of them loopback (mixed v4/v6, and 127/8 beyond .1).
    assert!(all_loopback([
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]));
}

#[test]
fn all_loopback_of_nothing_is_not_loopback() {
    // No addresses means nothing was certified loopback — must not
    // default to permissive.
    assert!(!all_loopback(std::iter::empty()));
}

#[test]
fn all_loopback_single_address_cases() {
    assert!(all_loopback([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]));
    assert!(all_loopback([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))]));
    assert!(all_loopback([IpAddr::V6(Ipv6Addr::LOCALHOST)]));
    assert!(!all_loopback([IpAddr::V4(Ipv4Addr::UNSPECIFIED)])); // 0.0.0.0
    assert!(!all_loopback([IpAddr::V6(Ipv6Addr::UNSPECIFIED)])); // ::
    assert!(!all_loopback([IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]));
}

// ---- resolve_loopback_bind_addr: the table this stage owes --------
// (`PLAN.md` M4 Step 4 (c) "loopback 강제 표")

#[tokio::test]
async fn loopback_bind_host_table() {
    let loopback_cases = [
        "127.0.0.1",
        "127.0.0.53", // whole 127.0.0.0/8, not just .1
        "::1",
    ];
    for host in loopback_cases {
        let bound = resolve_loopback_bind_addr(&SystemResolver, host, 4321)
            .await
            .unwrap_or_else(|err| panic!("{host} must classify as loopback: {err}"));
        assert!(bound.ip().is_loopback(), "{host}");
        assert_eq!(bound.port(), 4321, "{host}");
    }

    let non_loopback_cases = [
        "0.0.0.0",
        "::",
        "203.0.113.9", // TEST-NET-3: public-shaped literal
    ];
    for host in non_loopback_cases {
        assert!(
            resolve_loopback_bind_addr(&SystemResolver, host, 4321)
                .await
                .is_err(),
            "{host} must NOT classify as loopback"
        );
    }
}

#[tokio::test]
async fn empty_bind_host_is_the_loopback_default() {
    // The wire default for "no `bind:` prefix" — must not resolve, and
    // must not be mistaken for "unspecified".
    let resolver = ScriptedResolver::new(vec![vec![addr("203.0.113.9:4321")]]);
    assert_eq!(
        resolve_loopback_bind_addr(&resolver, "", 4321)
            .await
            .unwrap(),
        addr("127.0.0.1:4321")
    );
    assert_eq!(resolver.calls(), 0, "the wire default never resolves");
}

#[tokio::test]
async fn an_ip_literal_never_reaches_the_resolver() {
    // Classification by address, not by string — and no lookup at
    // all, so a resolver cannot influence a literal either way.
    let resolver = ScriptedResolver::new(vec![vec![addr("203.0.113.9:4321")]]);
    assert_eq!(
        resolve_loopback_bind_addr(&resolver, "127.0.0.53", 4321)
            .await
            .unwrap(),
        addr("127.0.0.53:4321")
    );
    assert!(
        resolve_loopback_bind_addr(&resolver, "0.0.0.0", 4321)
            .await
            .is_err()
    );
    assert_eq!(resolver.calls(), 0, "an IP literal never resolves");
}

/// **The check-then-use regression guard.** A resolver that answers
/// loopback to the first lookup and a routable address to the second
/// — a peer-controlled zone with a one-second TTL, no host compromise
/// needed — must never yield a routable bind address. The whole
/// defense is that there *is* no second lookup: exactly one call, and
/// the address returned is one of the addresses that call produced.
///
/// Mutation-checked: reintroducing a second `resolver.lookup` after
/// the `all_loopback` check makes this fail on both assertions.
#[tokio::test]
async fn the_address_returned_is_the_address_validated_never_a_second_answer() {
    let resolver = ScriptedResolver::new(vec![
        vec![addr("127.0.0.1:4321")],
        vec![addr("203.0.113.9:4321")],
    ]);

    let bound = resolve_loopback_bind_addr(&resolver, "evil.example", 4321)
        .await
        .expect("the validated answer was loopback");

    assert_eq!(
        resolver.calls(),
        1,
        "a bind_host is resolved exactly once — a second lookup is the bug"
    );
    assert_eq!(
        bound,
        addr("127.0.0.1:4321"),
        "the address bound must come out of the answer set that was validated"
    );
    assert!(bound.ip().is_loopback());
}

#[tokio::test]
async fn a_mixed_answer_set_is_rejected_whole() {
    // "Some resolved address is loopback" is not a safety property.
    let resolver =
        ScriptedResolver::new(vec![vec![addr("127.0.0.1:4321"), addr("203.0.113.9:4321")]]);
    assert!(
        resolve_loopback_bind_addr(&resolver, "split.example", 4321)
            .await
            .is_err(),
        "a name that also answers with a routable address must be refused"
    );
    assert_eq!(resolver.calls(), 1);
}

#[tokio::test]
async fn a_name_that_resolves_to_nothing_is_refused() {
    let resolver = ScriptedResolver::new(vec![vec![]]);
    assert!(
        resolve_loopback_bind_addr(&resolver, "nothing.example", 4321)
            .await
            .is_err(),
        "an empty answer set certifies nothing as loopback"
    );
}

#[tokio::test]
async fn a_resolver_failure_is_refused_as_not_loopback() {
    struct FailingResolver;
    impl BindHostResolver for FailingResolver {
        fn lookup<'a>(&'a self, _host: &'a str, _port: u16) -> LookupFuture<'a> {
            Box::pin(async { Err(io::Error::other("resolver is down")) })
        }
    }
    // Including a `bind_host` carrying terminal escapes: the debug log
    // line this path emits sanitizes it, and nothing is bound either
    // way.
    assert!(
        resolve_loopback_bind_addr(&FailingResolver, "a\u{1b}[31mb.example", 4321)
            .await
            .is_err()
    );
}

/// A resolver that never answers must not park the caller forever —
/// `RemoteForwardOpen` is handled inline on the connection's single
/// serialized control loop, so an unbounded resolve here stalls every
/// other message on that connection, on a name the peer chose
/// (`BIND_HOST_RESOLVE_TIMEOUT`'s own doc). The bound is injected so
/// this test does not wait out the production ten seconds.
#[tokio::test]
async fn a_resolver_that_never_answers_is_bounded_not_parked_forever() {
    struct HangingResolver;
    impl BindHostResolver for HangingResolver {
        fn lookup<'a>(&'a self, _host: &'a str, _port: u16) -> LookupFuture<'a> {
            Box::pin(std::future::pending())
        }
    }
    let started = std::time::Instant::now();
    let err = resolve_loopback_bind_addr_bounded(
        &HangingResolver,
        "evil.example",
        4321,
        Duration::from_millis(50),
    )
    .await
    .expect_err("a resolver that never answers must not classify as loopback");
    let _ = err; // `NotLoopback` carries nothing to inspect beyond its `Display`
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the injected bound must have applied, not some much longer default: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn localhost_resolves_to_loopback() {
    // Goes through the real resolver (not hardcoded — this module's
    // own doc explains why), so this asserts the *classification*
    // holds for whatever the system resolver answers `localhost`
    // with, which is loopback on every CI/dev environment this crate
    // targets.
    let bound = resolve_loopback_bind_addr(&SystemResolver, "localhost", 4321)
        .await
        .expect("localhost must resolve to loopback");
    assert!(bound.ip().is_loopback());
}

#[tokio::test]
async fn a_real_non_loopback_interface_address_is_not_loopback() {
    // A real, routable interface address on this host — obtained by
    // opening a UDP socket "connected" to a public address, which
    // populates the local address with whatever interface the kernel
    // would actually route through, no traffic sent
    // (`crate::tunnel` has no simpler way to name "an address that is
    // genuinely this host's LAN/interface address" than asking the
    // kernel). Skips rather than fails on a sandboxed runner with no
    // route to the outside — the point is proving the classifier
    // rejects a real interface address, not proving one exists here.
    let Ok(probe) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return;
    };
    if probe.connect("203.0.113.9:9").await.is_err() {
        return;
    }
    let Ok(local_addr) = probe.local_addr() else {
        return;
    };
    let ip = local_addr.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        // No real outbound route on this runner; nothing to assert.
        return;
    }
    assert!(
        resolve_loopback_bind_addr(&SystemResolver, &ip.to_string(), 4321)
            .await
            .is_err(),
        "a real interface address ({ip}) must not classify as loopback"
    );
}

/// `NotLoopback`'s wire text is the three-part
/// notice, not some other literal — pins `Display` to
/// [`REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE`] the same way the doc-fixture
/// tests pin `docs/CLI.md`/`README.md` to it.
#[test]
fn not_loopback_displays_the_three_part_notice() {
    assert_eq!(
        NotLoopback.to_string(),
        REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE,
        "NotLoopback::Display must stay defined in terms of the shared constant"
    );
}

// ---- claim_remote_forward_reverse cancel-safety (finding C) -------

/// **The primitive [`claim_remote_forward_reverse`]'s `select!` relies
/// on for cancel-safety, pinned directly.** Its loop races
/// `&mut claim_handle` (a [`tokio::task::JoinHandle`] naming a
/// *detached* [`spawn_claim_attempt`] task) against
/// `tasks.0.join_next()`; when a splice finishes at the same moment a
/// claim is in flight and the `join_next()` branch wins, `select!`
/// only stops polling `claim_handle` for that iteration — it does not
/// drop the task the handle names, because that task was already
/// spawned onto the runtime independently of whether anything ever
/// polls its handle again.
///
/// This test reproduces exactly that shape without any real daemon or
/// QUIC connection: a task is spawned (the fix's shape) and its
/// handle is raced, every iteration, against an *already-ready*
/// sibling future — the sibling always wins, so the handle's branch
/// never completes inside the loop, mirroring a claim that keeps
/// losing to a splice's `join_next()` resolving first. The spawned
/// task must still deliver its result afterward regardless.
///
/// **Mutation-check target:** replace the `tokio::spawn(...)` below
/// with the bare, un-spawned future awaited directly as the `select!`
/// arm — the exact shape `claim_remote_forward_reverse` used before
/// `spawn_claim_attempt` existed. Polled directly rather than merely
/// referenced, that future is what `select!` actually drops when the
/// sibling branch wins, so `tx.send(())` never runs and the
/// `timeout(...)` below fires instead of returning the sent value —
/// this is precisely the finding: an in-flight, already-granted claim
/// destroyed with no trace by an unrelated branch completing.
#[tokio::test]
async fn a_detached_claim_task_survives_losing_its_select_branch_every_time() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut handle = tokio::spawn(async move {
        // Stands in for the real claim's `open_stream_with_wait`
        // eventually resolving with a granted arrival — long enough
        // that every iteration of the loop below observes it as not
        // yet ready, so the already-ready sibling wins every single
        // race, never once by chance yielding to `handle` instead.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(());
    });
    for _ in 0..20 {
        tokio::select! {
            _joined = &mut handle => {
                panic!(
                    "the already-ready sibling must win every iteration of this loop; \
                     the claim handle becoming ready here defeats the scenario"
                );
            }
            _ = std::future::ready(()) => {
                // The unrelated branch — standing in for a splice's
                // `tasks.join_next()` resolving — always wins. Under
                // the fix, this must not disturb the detached task
                // `handle` names at all.
            }
        }
    }
    let delivered = tokio::time::timeout(Duration::from_secs(2), rx).await;
    assert!(
        delivered.is_ok(),
        "the detached claim task must still complete even though its select! branch lost \
         every race — a timeout here means the task was effectively cancelled"
    );
    assert!(
        delivered.unwrap().is_ok(),
        "the task must have actually sent its result, not merely been dropped without a panic"
    );
}

// ---- RemoteForwardAcceptor: the requester leg (Stage C) -----------

/// Send a `TCP_ACCEPTED{ticket}` header on a fresh bidi stream opened
/// from `conn` — the same handshake `serve_remote_forward`'s
/// `accept_one` writes for real, played back by hand so a test can be
/// the "host" side without standing up a whole listener.
async fn open_fake_tcp_accepted(
    conn: &qsh_transport::Connection,
    forward_id: &[u8],
) -> (quinn::SendStream, (quinn::RecvStream, Vec<u8>)) {
    let (send, recv) = conn.open_bi().await.unwrap();
    let mut framed = qsh_transport::FramedStream::data(send, recv);
    framed
        .send
        .send(&StreamHeader {
            kind: StreamKind::TcpAccepted as i32,
            ticket: forward_id.to_vec(),
            host: String::new(),
            port: 0,
            deny_host_local: false,
        })
        .await
        .unwrap();
    let (send, recv) = framed.split();
    let residue = recv.into_raw();
    (send.into_raw(), residue)
}

/// A `TCP_ACCEPTED` naming a `forward_id` this side registered is
/// dialed at the registered `host:port` and spliced — both directions,
/// proving the dispatcher does not merely accept the stream but
/// actually forwards the bytes.
#[tokio::test]
async fn registered_forward_id_is_dialed_at_its_destination_and_spliced() {
    let (requester_conn, peer_conn) = loopback_pair().await;

    // Stand in for the `-R` spec's local destination: an echo server
    // on loopback, port 0 (`docs/design/testing.md`'s CI rule).
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut sock, _peer) = echo.accept().await.unwrap();
        let mut buf = [0u8; 16];
        let n = sock.read(&mut buf).await.unwrap();
        sock.write_all(&buf[..n]).await.unwrap();
    });

    let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;
    acceptor.register(
        "fwd-1".to_string(),
        "127.0.0.1".to_string(),
        echo_addr.port(),
    );

    let (mut raw_send, (mut raw_recv, residue)) =
        open_fake_tcp_accepted(&peer_conn, b"fwd-1").await;
    assert!(
        residue.is_empty(),
        "nothing was pipelined behind the header in this test"
    );
    raw_send.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 16];
    let n = match raw_recv.read(&mut buf).await.unwrap() {
        Some(n) => n,
        None => panic!("registered forward_id must be spliced, not reset"),
    };
    assert_eq!(&buf[..n], b"ping", "the destination must echo what it got");

    echo_task.await.unwrap();
    drop(acceptor);
    drop(peer_conn);
}

/// A `TCP_ACCEPTED` naming a `forward_id` that was never registered —
/// never opened, or already closed — is rejected without dialing
/// anything: the peer sees the stream reset, not an echo
/// (`PLAN.md` M4 Step 4's requester-leg requirement).
#[tokio::test]
async fn unregistered_forward_id_is_rejected_without_dialing() {
    let (requester_conn, peer_conn) = loopback_pair().await;
    // Spawned, but nothing is ever registered on it.
    let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;

    let (mut raw_send, (mut raw_recv, _residue)) =
        open_fake_tcp_accepted(&peer_conn, b"never-registered").await;

    // The dispatcher must reset the stream immediately, before ever
    // reaching a dial — so reading back gets a reset error, not a
    // hang and not an echo of anything this test never sent.
    let read_err = raw_recv.read(&mut [0u8; 8]).await;
    assert!(
        read_err.is_err(),
        "an unregistered forward_id must reset the stream, not stay open: {read_err:?}"
    );

    drop(acceptor);
    drop(peer_conn);
    let _ = raw_send.finish();
}

/// [`RemoteForwardAcceptor::unregister`] takes a `forward_id` back out
/// of dispatch: a `TCP_ACCEPTED` for it arriving *after* unregister is
/// treated exactly like one that was never registered at all — the
/// `-R` teardown path ([`crate::ops::TunnelHold::close`]) depends on
/// this to stop dispatching before it sends `RemoteForwardClose`.
/// A `forward_id` ticket that does not satisfy
/// [`qsh_proto::wire::valid_forward_id`] never reaches the dispatch
/// table, never causes a dial, and never reaches a log line verbatim.
/// The escape-sequence case is the sharp one: the requester leg logs
/// its rejections, and a raw ticket there would let the peer drive the
/// operator's terminal.
///
/// Registering the malformed id first is deliberate — it proves the
/// shape check runs *before* the lookup, so a peer cannot smuggle a
/// malformed id into service even if one somehow got registered.
#[tokio::test]
async fn malformed_forward_id_ticket_is_rejected_without_dialing() {
    let malformed: [&[u8]; 6] = [
        b"",                      // empty
        b"a\x1b[31mb",            // ANSI escape run
        b"fwd\nqsh: forged line", // forged log/terminal line
        b"fwd\x00-1",             // NUL
        b"fwd.1",                 // `.` is not in the alphabet
        &[b'x'; 65],              // one byte over the 64-byte cap
    ];

    for ticket in malformed {
        let (requester_conn, peer_conn) = loopback_pair().await;
        let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;
        // A destination that would be dialed if the check were missing.
        if let Ok(id) = std::str::from_utf8(ticket) {
            acceptor.register(id.to_string(), "127.0.0.1".to_string(), 9);
        }

        let (mut raw_send, (mut raw_recv, _residue)) =
            open_fake_tcp_accepted(&peer_conn, ticket).await;

        let read_err = raw_recv.read(&mut [0u8; 8]).await;
        assert!(
            read_err.is_err(),
            "a malformed forward_id ({ticket:?}) must reset the stream: {read_err:?}"
        );

        drop(acceptor);
        drop(peer_conn);
        let _ = raw_send.finish();
    }
}

/// Invalid UTF-8 is the same rejection, one layer earlier.
#[tokio::test]
async fn non_utf8_forward_id_ticket_is_rejected_without_dialing() {
    let (requester_conn, peer_conn) = loopback_pair().await;
    let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;

    let (mut raw_send, (mut raw_recv, _residue)) =
        open_fake_tcp_accepted(&peer_conn, &[0xff, 0xfe]).await;

    let read_err = raw_recv.read(&mut [0u8; 8]).await;
    assert!(read_err.is_err(), "{read_err:?}");

    drop(acceptor);
    drop(peer_conn);
    let _ = raw_send.finish();
}

/// **Not just "the stream got reset for some reason."** The earlier
/// version of this test pointed `fwd-2` at port 1 — a port nothing
/// listens on — so it passed even with `unregister` gutted into a
/// no-op: a still-registered `fwd-2` would have been dialed, the dial
/// to port 1 would have failed on its own, and the stream would have
/// been reset for *that* unrelated reason, indistinguishable from a
/// correct rejection. This version points `fwd-2` at a real,
/// listening echo server, so the only way the stream can come back
/// reset instead of carrying an echo is that `unregister` actually
/// took the id out of dispatch.
///
/// Mutation-checked: gutting `unregister`'s body (so it no longer
/// removes anything) makes this test fail — `read_err` comes back
/// `Ok(Some(4))` carrying the echoed `"ping"` instead of an error,
/// because the dispatcher happily dials the still-registered
/// destination and splices it — while
/// `unregistered_forward_id_is_rejected_without_dialing` alone would
/// still have passed, which is exactly the blind spot this version
/// closes.
#[tokio::test]
async fn unregister_stops_dispatching_a_previously_registered_forward_id() {
    let (requester_conn, peer_conn) = loopback_pair().await;

    // A real destination that would happily answer if dialed — so a
    // gutted `unregister` shows up as an echo, not a coincidental
    // reset.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        // Never actually reached on a correct `unregister` — this
        // task is dropped, unjoined, when the test ends.
        let (mut sock, _peer) = echo.accept().await.unwrap();
        let mut buf = [0u8; 16];
        let n = sock.read(&mut buf).await.unwrap();
        sock.write_all(&buf[..n]).await.unwrap();
    });

    let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;
    acceptor.register(
        "fwd-2".to_string(),
        "127.0.0.1".to_string(),
        echo_addr.port(),
    );
    acceptor.unregister("fwd-2");

    let (mut raw_send, (mut raw_recv, _residue)) =
        open_fake_tcp_accepted(&peer_conn, b"fwd-2").await;
    raw_send.write_all(b"ping").await.unwrap();
    let read_err = raw_recv.read(&mut [0u8; 8]).await;
    assert!(
        read_err.is_err(),
        "an unregistered forward_id must reset the stream, not dial and splice \
         the destination it used to name: {read_err:?}"
    );

    drop(acceptor);
    drop(peer_conn);
    let _ = raw_send.finish();
    echo_task.abort();
}

// ---- Finding B: `RemoteForwardAcceptor::drop` must drain in-flight
// splices on the forward route exactly like it already does on the
// reverse route (`unregister`'s own doc), never abort them — a
// headline-claim-breaking behavioral difference across the role axis
// otherwise. ----

/// A splice already dialed and running when `RemoteForwardAcceptor`
/// itself is dropped (not merely `unregister`d) must still run to
/// completion — the forward-route mirror of the reverse route's
/// `unregister`-mid-splice guarantee, now proven for `Drop` too and
/// on the route `Drop` used to get wrong.
///
/// Determinism, not a race: the destination task signals
/// `dial_done_tx` the instant its `accept()` returns, which cannot
/// happen before `handle_accepted_stream` has already spawned this
/// splice into `dispatch_remote_forwards`'s own `tasks` (the dial is
/// issued *from inside* that already-spawned task) — so by the time
/// this test drops `acceptor`, the splice is unconditionally already
/// live inside the very `JoinSet` `RemoteForwardAcceptor::drop`'s
/// `task.abort()` tears down.
#[tokio::test]
async fn drop_drains_an_in_flight_forward_route_splice_instead_of_aborting_it() {
    let (requester_conn, peer_conn) = loopback_pair().await;

    let (dial_done_tx, dial_done_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut sock, _peer) = echo.accept().await.unwrap();
        let _ = dial_done_tx.send(());
        // Hold the connection open — and thus the splice genuinely
        // in flight — until the test has dropped `acceptor`.
        let _ = release_rx.await;
        let mut buf = [0u8; 32];
        let n = sock.read(&mut buf).await.unwrap();
        sock.write_all(&buf[..n]).await.unwrap();
    });

    let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;
    acceptor.register(
        "fwd-drop".to_string(),
        "127.0.0.1".to_string(),
        echo_addr.port(),
    );

    let (mut raw_send, (mut raw_recv, _residue)) =
        open_fake_tcp_accepted(&peer_conn, b"fwd-drop").await;
    raw_send.write_all(b"ping-after-drop").await.unwrap();

    dial_done_rx
        .await
        .expect("the destination must be dialed before this test proceeds");

    // The splice is now unconditionally live inside
    // `dispatch_remote_forwards`'s `tasks`. Drop the acceptor while
    // it is — under the bug this test catches (a bare `JoinSet<()>`
    // instead of `DrainSplicesOnDrop`), this `task.abort()` cascades
    // into aborting the splice with it.
    drop(acceptor);

    let _ = release_tx.send(());

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(5), raw_recv.read(&mut buf))
        .await
        .expect("must not hang")
        .expect("read must not error")
        .expect(
            "a splice already dialed and running when `RemoteForwardAcceptor` is dropped \
             must drain to completion, not be reset — the same guarantee `unregister` \
             already gives the reverse route",
        );
    assert_eq!(
        &buf[..n],
        b"ping-after-drop",
        "the destination must still echo what it got after the acceptor that dispatched \
         to it was dropped"
    );

    echo_task.await.unwrap();
    drop(peer_conn);
}

// ---- serve_remote_forward: the `-R` accept-time tunnel-stream permit
// (M8 Step 4b, J13) ---------------------------------------------

/// The cap this suite uses is 4, not the production default 64
/// (`ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_FORWARD`) — opening
/// 64 real loopback TCP connections and driving 64 real QUIC streams
/// through one `tokio::test` just to exercise the same comparison
/// `reserve_tunnel_stream` already has dedicated unit coverage for
/// (`quotas.rs`'s own `reserve_exec_refuses_past_the_cap_and_release_
/// frees_the_slot`-shaped tests) buys nothing this test doesn't
/// already prove at 4; `max_tunnel_streams_per_principal` is left at
/// its production default (256) so this stays a *forward*-axis test,
/// not a principal-axis one.
const TEST_FORWARD_CAP: usize = 4;

/// Accepts every incoming QUIC bidi stream on `conn` and holds it —
/// `-R`'s requester leg, standing in for `RemoteForwardAcceptor`'s
/// full claim-loop machinery (this test needs a peer that keeps every
/// `TCP_ACCEPTED` stream open, not one that dispatches it anywhere).
/// Streams are pushed into `held` rather than dropped so each
/// `accept_one` splice this test admits stays genuinely alive (a
/// dropped stream would tear the splice down and free its permit,
/// defeating the whole "N are alive at once" premise).
async fn hold_every_incoming_stream(
    conn: qsh_transport::Connection,
    held: Arc<Mutex<Vec<(quinn::SendStream, quinn::RecvStream)>>>,
) {
    loop {
        match conn.accept_bi().await {
            Ok(pair) => held.lock().unwrap_or_else(|e| e.into_inner()).push(pair),
            Err(_) => return,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_forward_accept_past_the_per_forward_stream_cap_is_closed_before_any_quic_stream_opens()
 {
    use crate::audit::{AuditSink, MemoryAuditSink};
    use crate::broker::clock::SystemClock;
    use crate::quota::{QuotaLimits, Quotas};

    let (requester_conn, host_conn) = loopback_pair().await;
    let held: Arc<Mutex<Vec<(quinn::SendStream, quinn::RecvStream)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let accept_task = tokio::spawn(hold_every_incoming_stream(
        requester_conn,
        Arc::clone(&held),
    ));

    let quotas = Quotas::new(
        QuotaLimits {
            max_tunnel_streams_per_forward: TEST_FORWARD_CAP,
            ..QuotaLimits::default()
        },
        Arc::new(SystemClock),
    );
    let audit = Arc::new(MemoryAuditSink::new());
    let owner = crate::acl::opener_key(host_conn.principal(), host_conn.auth_path());
    let forward_id = b"fwd-cap-unit-test".to_vec();
    // The production key exactly — same helper `serve_remote_forward`
    // calls, so a change to the key shape cannot silently desync the
    // observation from the reservation.
    let forward_key = remote_forward_quota_key(&forward_id);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_task = tokio::spawn(serve_remote_forward(
        listener,
        host_conn,
        forward_id,
        Arc::clone(&quotas),
        Arc::clone(&audit) as Arc<dyn AuditSink>,
    ));

    // Fill the cap and wait for the permits to actually land — no
    // fixed sleep (`docs/design/testing.md`'s own poll-not-sleep
    // discipline, the same reasoning F3's `wait_for` swap-in used).
    let mut live = Vec::with_capacity(TEST_FORWARD_CAP);
    for _ in 0..TEST_FORWARD_CAP {
        live.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if quotas.tunnel_streams_per_forward_in_use(&owner, &forward_key) == TEST_FORWARD_CAP {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the cap's worth of splices must all report live within 5s");

    // The (CAP+1)-th TCP connection must be refused: closed with no
    // payload, and — the whole point of "before `open_bi`" — no QUIC
    // stream for it ever reaches `requester_conn`'s accept loop, so
    // `held`'s length never exceeds the cap either.
    let mut over_cap = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .expect("connect must not hang")
        .unwrap();
    let mut buf = [0u8; 1];
    // A refusal is a *termination with no payload*. This socket wrote
    // nothing, so the ordinary observation is EOF; a client that had
    // already written would leave unread bytes in the host's receive
    // buffer and see the kernel's RST instead. Both are the same
    // refusal, so both are accepted — the 4a F3 shape
    // `tunnel_loopback.rs` and `tunnel/local.rs` already use.
    match tokio::time::timeout(Duration::from_secs(2), over_cap.read(&mut buf))
        .await
        .expect("the refused connection must close promptly, not hang")
    {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!(
            "the (cap+1)-th accept must end with no payload — no QUIC stream, hence no \
             splice, was ever opened for it: {other:?}"
        ),
    }
    assert_eq!(
        quotas.tunnel_streams_per_forward_in_use(&owner, &forward_key),
        TEST_FORWARD_CAP,
        "the refused connection must not have taken a permit slot"
    );
    // Two directions, two kinds of assertion. The *upper bound* holds
    // at every instant, so it is read immediately; "all `CAP` have
    // arrived" is a reachability property (the permit is taken before
    // `open_bi`, so `in_use == CAP` can be observed while the
    // requester's `accept_bi` has returned fewer), so it is polled.
    assert!(
        held.lock().unwrap_or_else(|e| e.into_inner()).len() <= TEST_FORWARD_CAP,
        "the requester side must never see more streams than the cap admits"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if held.lock().unwrap_or_else(|e| e.into_inner()).len() == TEST_FORWARD_CAP {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every admitted splice must reach the requester as a QUIC stream within 5s");
    assert_eq!(
        held.lock().unwrap_or_else(|e| e.into_inner()).len(),
        TEST_FORWARD_CAP,
        "the requester side must never see a QUIC stream for the refused connection"
    );

    // Audit: exactly the `quota_tunnels_forward` shape `-L`'s own
    // `authorize_and_dial_tunnel` refusal writes — `request_id` "-"
    // (no control-stream request to attribute a data-plane accept
    // to), `peer_addr` the actual TCP peer (the refused socket's own
    // local address, as observed from the accept side).
    let records = audit.records();
    let quota_record = records
        .iter()
        .find(|r| r.resource == "quota_tunnels_forward")
        .expect("a quota_tunnels_forward audit record must be written on refusal");
    assert_eq!(quota_record.request_id, "-");
    assert_eq!(
        quota_record.peer_addr,
        over_cap.local_addr().unwrap().to_string()
    );
    assert_eq!(quota_record.decision, "deny");

    // Draining every held splice must release every permit back to
    // zero. Dropping the live TCP sockets alone only half-closes each
    // splice (`splice::tests::pump_half_closes_only_its_own_
    // direction_at_eof`'s own point — one direction ending does not
    // end a full-duplex splice on its own), so the QUIC side this
    // test's `hold_every_incoming_stream` is holding open must be
    // dropped too before `accept_one` can actually return.
    drop(live);
    drop(over_cap);
    held.lock().unwrap_or_else(|e| e.into_inner()).clear();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if quotas.tunnel_streams_per_forward_in_use(&owner, &forward_key) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every permit must release once its splice ends");

    serve_task.abort();
    accept_task.abort();
}

/// The *order* the test above only names: a refused accept opens no
/// QUIC stream at all, not one that is opened and then reset.
///
/// Isolating the order needs every accept refused, so the forward cap
/// is 0 — the same "forced refusal" construction `server/mod.rs`'s own
/// `a_tunnel_dial_past_the_quota_never_reaches_the_dialer` uses for
/// `-L`. Under the correct implementation (reserve, *then*
/// `open_stream`) the requester's `accept_bi` never returns, so the
/// 500 ms probe below is deterministic: nothing can ever arrive.
/// Under an implementation that opened the stream first and reset it
/// on refusal, 20 dials would deliver up to 20 streams and the probe
/// would return one.
///
/// The probe is also the stream-count observation — a concurrent
/// `hold_every_incoming_stream` task cannot be used here, since it and
/// the probe would be two consumers racing over one `accept_bi`.
#[tokio::test(flavor = "multi_thread")]
async fn refused_remote_forward_accepts_never_open_a_quic_stream() {
    use crate::audit::{AuditSink, MemoryAuditSink};
    use crate::broker::clock::SystemClock;
    use crate::quota::{QuotaLimits, Quotas};

    const DIALS: usize = 20;

    let (requester_conn, host_conn) = loopback_pair().await;

    let quotas = Quotas::new(
        QuotaLimits {
            max_tunnel_streams_per_forward: 0,
            ..QuotaLimits::default()
        },
        Arc::new(SystemClock),
    );
    let audit = Arc::new(MemoryAuditSink::new());
    let forward_id = b"fwd-order-unit-test".to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_task = tokio::spawn(serve_remote_forward(
        listener,
        host_conn,
        forward_id,
        Arc::clone(&quotas),
        Arc::clone(&audit) as Arc<dyn AuditSink>,
    ));

    for i in 0..DIALS {
        let mut sock = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
            .await
            .unwrap_or_else(|_| panic!("connect {i} must not hang"))
            .unwrap_or_else(|e| panic!("connect {i}: the TCP accept itself must succeed: {e}"));
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("refused connection {i} must close promptly, not hang"))
        {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("refusal {i} must end with no payload: {other:?}"),
        }
    }

    // The order itself: with every accept refused, the requester leg
    // must never be handed a stream.
    let probe = tokio::time::timeout(Duration::from_millis(500), requester_conn.accept_bi()).await;
    assert!(
        probe.is_err(),
        "a refused accept must open no QUIC stream at all — the requester's accept_bi \
         returned {:?} instead of timing out",
        probe.map(|r| r.is_ok())
    );

    // Audit: the aggregation window (10 s) is far longer than this
    // test, so the burst leaves exactly the first rejection's row and
    // no summary — the flood shape `Quotas::record_rejection` promises.
    let records = audit.records();
    let forward_rows: Vec<_> = records
        .iter()
        .filter(|r| r.resource == "quota_tunnels_forward")
        .collect();
    assert_eq!(
        forward_rows.len(),
        1,
        "{DIALS} refusals inside one aggregation window must leave the first row only, \
         got {forward_rows:?}"
    );
    assert_eq!(forward_rows[0].decision, "deny");
    assert_eq!(forward_rows[0].request_id, "-");
    assert_eq!(
        forward_rows[0].count, None,
        "the first row of a window is a plain rejection, not a summary"
    );

    serve_task.abort();
    drop(requester_conn);
}

/// The principal axis of the same gate (`max_tunnel_streams_per_
/// principal`), which the forward-axis tests above leave at its
/// production default and so never reach: at a cap of 2 with the
/// forward axis wide open, the third accept is refused and the audit
/// row carries the *principal* category, not the forward one.
///
/// This is the axis ADR-0010's addendum names as the intended
/// consequence of gating `-R` at accept time — an unauthenticated TCP
/// flood can exhaust the registering principal's own tunnel-stream
/// budget — so it needs its own pin.
#[tokio::test(flavor = "multi_thread")]
async fn remote_forward_accept_past_the_per_principal_stream_cap_is_refused_on_that_axis() {
    use crate::audit::{AuditSink, MemoryAuditSink};
    use crate::broker::clock::SystemClock;
    use crate::quota::{QuotaLimits, Quotas};

    const PRINCIPAL_CAP: usize = 2;

    let (requester_conn, host_conn) = loopback_pair().await;
    let held: Arc<Mutex<Vec<(quinn::SendStream, quinn::RecvStream)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let accept_task = tokio::spawn(hold_every_incoming_stream(
        requester_conn,
        Arc::clone(&held),
    ));

    let quotas = Quotas::new(
        QuotaLimits {
            max_tunnel_streams_per_principal: PRINCIPAL_CAP,
            max_tunnel_streams_per_forward: 64,
            ..QuotaLimits::default()
        },
        Arc::new(SystemClock),
    );
    let audit = Arc::new(MemoryAuditSink::new());
    let owner = crate::acl::opener_key(host_conn.principal(), host_conn.auth_path());
    let forward_id = b"fwd-principal-unit-test".to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_task = tokio::spawn(serve_remote_forward(
        listener,
        host_conn,
        forward_id,
        Arc::clone(&quotas),
        Arc::clone(&audit) as Arc<dyn AuditSink>,
    ));

    let mut live = Vec::with_capacity(PRINCIPAL_CAP);
    for _ in 0..PRINCIPAL_CAP {
        live.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if quotas.tunnel_streams_per_principal_in_use(&owner) == PRINCIPAL_CAP {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the principal cap's worth of splices must all report live within 5s");

    let mut over_cap = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .expect("connect must not hang")
        .unwrap();
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), over_cap.read(&mut buf))
        .await
        .expect("the refused connection must close promptly, not hang")
    {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("the (cap+1)-th accept must end with no payload: {other:?}"),
    }
    assert_eq!(
        quotas.tunnel_streams_per_principal_in_use(&owner),
        PRINCIPAL_CAP,
        "the refused connection must not have taken a permit slot"
    );

    let records = audit.records();
    let quota_record = records
        .iter()
        .find(|r| r.resource == "quota_tunnels_principal")
        .unwrap_or_else(|| {
            panic!(
                "the refusal must be audited under the principal axis, got {:?}",
                records.iter().map(|r| &r.resource).collect::<Vec<_>>()
            )
        });
    assert_eq!(quota_record.decision, "deny");
    assert_eq!(quota_record.request_id, "-");
    assert_eq!(
        quota_record.peer_addr,
        over_cap.local_addr().unwrap().to_string()
    );
    assert!(
        !records
            .iter()
            .any(|r| r.resource == "quota_tunnels_forward"),
        "the forward axis is wide open here — nothing may be refused on it"
    );

    drop(live);
    drop(over_cap);
    held.lock().unwrap_or_else(|e| e.into_inner()).clear();
    serve_task.abort();
    accept_task.abort();
}
