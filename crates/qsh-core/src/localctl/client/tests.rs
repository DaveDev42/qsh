use std::time::Instant;

use qsh_proto::local::LocalHelloAck;
use tokio::net::UnixListener;

use super::*;

fn sample_host(name: &str) -> LocalHost {
    LocalHost {
        name: name.to_string(),
        address: "203.0.113.5:51820".to_string(),
        state: "reachable".to_string(),
        fingerprint: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        capabilities: vec!["pty".to_string()],
        generation: 1,
        registered_at: "2026-08-22T00:00:00Z".to_string(),
        lost_at: None,
    }
}

/// Spawn a one-shot fake daemon on `path`: reads a `LocalHello` +
/// `LocalAdminRequest` off `LOCAL_ADMIN`, and answers with whatever
/// `LocalResponse` body the caller supplies — whichever request arm
/// arrives (`HostList`/`TunnelList`/`TunnelClose`), since this probes
/// the shared envelope/framing contract, not one specific request's
/// content. No real `qsh listen` process anywhere in these tests —
/// this is `docs/design/testing.md` L2 "no real daemon needed" for the
/// discovery/framing contract, not an L3 harness.
fn spawn_fake_admin_daemon(
    listener: UnixListener,
    body: local_response::Body,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut conduit = LocalConduit::new(stream);
        let hello: LocalHello = conduit.recv().await.unwrap().unwrap();
        assert_eq!(hello.kind, LocalStreamKind::LocalAdmin as i32);
        let _req: LocalAdminRequest = conduit.recv().await.unwrap().unwrap();
        conduit
            .send(&LocalResponse { body: Some(body) })
            .await
            .unwrap();
    })
}

#[tokio::test]
async fn admin_host_list_round_trips_through_a_fake_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("100.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let expected = vec![sample_host("personal-mac")];
    let daemon = spawn_fake_admin_daemon(
        listener,
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: expected.clone(),
        }),
    );

    let hosts = admin_host_list(&sock).await.unwrap();
    assert_eq!(hosts, expected);
    daemon.await.unwrap();
}

#[tokio::test]
async fn admin_host_list_surfaces_a_remote_error_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("101.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = spawn_fake_admin_daemon(
        listener,
        local_response::Body::Error(LocalError::from_code(
            ErrorCode::HostNotFound,
            "no such registration",
        )),
    );

    let err = admin_host_list(&sock).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(err.message, "no such registration");
    daemon.await.unwrap();
}

/// Same fake-daemon harness, but asserting the request arm the daemon
/// actually received — proving [`admin_host_list`]/[`admin_tunnel_list`]/
/// [`admin_tunnel_close`] each put their request in the *matching*
/// `LocalAdminRequest` oneof arm, not just that some frame arrived
/// (`qsh/local/v1.proto`'s own doc on why this envelope exists at
/// all).
fn spawn_fake_admin_daemon_asserting(
    listener: UnixListener,
    expect: fn(&local_admin_request::Body) -> bool,
    body: local_response::Body,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut conduit = LocalConduit::new(stream);
        let _hello: LocalHello = conduit.recv().await.unwrap().unwrap();
        let req: LocalAdminRequest = conduit.recv().await.unwrap().unwrap();
        assert!(
            req.body.as_ref().is_some_and(expect),
            "unexpected LocalAdminRequest body: {req:?}"
        );
        conduit
            .send(&LocalResponse { body: Some(body) })
            .await
            .unwrap();
    })
}

#[tokio::test]
async fn admin_tunnel_list_round_trips_through_a_fake_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("110.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let expected = vec![LocalTunnel {
        tunnel_id: "01ABCDEF".to_string(),
        mode: "remote".to_string(),
        bind: "127.0.0.1:5432".to_string(),
        forward_to: "localhost:5432".to_string(),
        actual_port: 5432,
        host: "box".to_string(),
    }];
    let daemon = spawn_fake_admin_daemon_asserting(
        listener,
        |body| matches!(body, local_admin_request::Body::TunnelList(_)),
        local_response::Body::TunnelListResult(LocalTunnelListResult {
            tunnels: expected.clone(),
        }),
    );

    let tunnels = admin_tunnel_list(&sock).await.unwrap();
    assert_eq!(tunnels, expected);
    daemon.await.unwrap();
}

#[tokio::test]
async fn admin_tunnel_close_round_trips_through_a_fake_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("111.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = spawn_fake_admin_daemon_asserting(
        listener,
        |body| {
            matches!(
                body,
                local_admin_request::Body::TunnelClose(LocalTunnelClose { tunnel_id })
                    if tunnel_id == "01ABCDEF"
            )
        },
        local_response::Body::TunnelCloseResult(LocalTunnelCloseResult { closed: true }),
    );

    let closed = admin_tunnel_close(&sock, "01ABCDEF").await.unwrap();
    assert!(closed);
    daemon.await.unwrap();
}

#[tokio::test]
async fn admin_tunnel_close_surfaces_a_remote_error_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("112.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = spawn_fake_admin_daemon(
        listener,
        local_response::Body::Error(LocalError::from_code(
            ErrorCode::PermissionDenied,
            "not the owning peer",
        )),
    );

    let err = admin_tunnel_close(&sock, "01ABCDEF").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    daemon.await.unwrap();
}

// ---- `open_control` / `ControlConduit` (M3 Step 6) ----

/// Spawn a one-shot fake daemon: reads one `LOCAL_CONTROL` `LocalHello`
/// off `listener`, asserts it against `expect_host`, and answers with
/// whatever `LocalResponse` body the caller supplies — the
/// `LOCAL_CONTROL` sibling of [`spawn_fake_admin_daemon`].
fn spawn_fake_control_daemon(
    listener: UnixListener,
    expect_host: &'static str,
    body: local_response::Body,
) -> tokio::task::JoinHandle<LocalConduit<UnixStream>> {
    tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut conduit = LocalConduit::new(stream);
        let hello: LocalHello = conduit.recv().await.unwrap().unwrap();
        assert_eq!(hello.kind, LocalStreamKind::LocalControl as i32);
        assert_eq!(hello.host, expect_host);
        conduit
            .send(&LocalResponse { body: Some(body) })
            .await
            .unwrap();
        conduit
    })
}

#[tokio::test]
async fn open_control_ack_happy_path_carries_the_ack_fields_and_the_conduit_relays_after() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("200.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = spawn_fake_control_daemon(
        listener,
        "personal-mac",
        local_response::Body::HelloAck(LocalHelloAck {
            host: "personal-mac".to_string(),
            peer_fingerprint: "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            generation: 3,
            capabilities: vec!["pty".to_string()],
        }),
    );

    let handshake = open_control(&sock, "personal-mac", 0, None).await.unwrap();
    assert_eq!(handshake.host, "personal-mac");
    assert_eq!(
        handshake.peer_fingerprint,
        "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    );
    assert_eq!(handshake.capabilities, vec!["pty".to_string()]);
    let mut daemon_conduit = daemon.await.unwrap();

    // Past the ack, the conduit carries `wire::ControlMessage` verbatim
    // in both directions (`qsh/local/v1.proto`'s file doc) — prove it
    // round-trips one, the way a real `session.get` request/response
    // pair would.
    let mut conduit = handshake.conduit;
    let ping = qsh_proto::wire::ControlMessage::new(
        7,
        qsh_proto::wire::control_message::Body::Ping(qsh_proto::wire::Ping {}),
    );
    conduit.send(&ping).await.unwrap();
    let received: qsh_proto::wire::ControlMessage = daemon_conduit.recv().await.unwrap().unwrap();
    assert_eq!(received, ping);
}

#[tokio::test]
async fn open_control_maps_a_local_error_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("201.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = spawn_fake_control_daemon(
        listener,
        "phone",
        local_response::Body::Error(LocalError::from_code(
            ErrorCode::HostNotFound,
            "phone is not a currently reachable registered host",
        )),
    );

    let err = open_control(&sock, "phone", 0, None).await.err().unwrap();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(
        err.message,
        "phone is not a currently reachable registered host"
    );
    daemon.await.unwrap();
}

#[tokio::test]
async fn open_control_maps_a_version_or_kind_rejection_the_same_way_as_any_local_error() {
    // The daemon rejects a `LocalHello` it cannot serve (bad version,
    // or a `kind` it does not support) with the same `LocalError`
    // envelope as any other refusal — `open_control` has no special
    // case for these, they are just another remote error to map
    // verbatim (`crate::localctl::client::remote_error`).
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("202.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = spawn_fake_control_daemon(
        listener,
        "phone",
        local_response::Body::Error(LocalError::from_code(
            ErrorCode::Unsupported,
            "unsupported LocalHello version",
        )),
    );

    let err = open_control(&sock, "phone", 0, None).await.err().unwrap();
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert_eq!(err.message, "unsupported LocalHello version");
    daemon.await.unwrap();
}

#[tokio::test]
async fn open_control_treats_an_unexpected_response_body_as_connection_failed() {
    // A `LOCAL_ADMIN`-shaped reply (`HostListResult`) on a
    // `LOCAL_CONTROL` conduit is not a `LocalError` — it's a
    // protocol-shape violation, not a "the daemon refused" answer, so
    // it maps to `ConnectionFailed` rather than being misread as
    // success.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("203.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = spawn_fake_control_daemon(
        listener,
        "phone",
        local_response::Body::HostListResult(LocalHostListResult { hosts: Vec::new() }),
    );

    let err = open_control(&sock, "phone", 0, None).await.err().unwrap();
    assert_eq!(err.code, ErrorCode::ConnectionFailed);
    daemon.await.unwrap();
}

#[tokio::test]
async fn admin_host_list_over_a_socket_nothing_is_listening_on_fails_connection() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("102.sock");
    // Never bound at all — plain ENOENT, not ECONNREFUSED, but either
    // way `admin_host_list` (unlike `discover`) surfaces the failure
    // rather than silently treating it as "not found".
    let err = admin_host_list(&sock).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ConnectionFailed);
}

#[test]
fn candidate_sockets_are_sorted_ascending_by_pid_and_skip_non_matching_names() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "20.sock",
        "3.sock",
        "100.sock",
        "notasocket.txt",
        "abc.sock",
    ] {
        std::fs::write(dir.path().join(name), b"").unwrap();
    }

    let found = candidate_sockets(dir.path()).unwrap();
    let pids: Vec<u32> = found.iter().map(|(pid, _)| *pid).collect();
    assert_eq!(pids, vec![3, 20, 100]);
    assert_eq!(found[0].1, dir.path().join("3.sock"));
}

// ---- liveness check backing the `ECONNREFUSED` unlink decision ----

#[test]
fn process_is_verifiably_dead_distinguishes_a_live_pid_from_a_reaped_one() {
    assert!(
        !process_is_verifiably_dead(std::process::id()),
        "this test's own process must never be reported dead"
    );
    assert!(
        process_is_verifiably_dead(a_definitely_dead_pid()),
        "a spawned-and-reaped child's pid must be reported dead"
    );
}

// ---- bounded waits (`discover`/`admin_host_list_over` must never hang
// forever on one misbehaving daemon) ----

#[tokio::test(start_paused = true)]
async fn admin_host_list_over_a_daemon_that_never_answers_times_out_instead_of_hanging() {
    let (client_end, _daemon_end) = UnixStream::pair().unwrap();
    // `_daemon_end` is held open (accepted the conduit) but never read
    // or written to — the "daemon wedged after accept" shape a
    // deadline must catch, since it is neither a connect failure nor a
    // clean close. `start_paused` auto-advances virtual time past the
    // timeout the instant nothing else is runnable, so this proves the
    // deadline fires without an real wall-clock wait.
    let err = admin_host_list_over(client_end).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ConnectionFailed);
}

#[tokio::test(start_paused = true)]
async fn discover_moves_past_a_silent_daemon_instead_of_hanging_on_it_forever() {
    let dir = tempfile::tempdir().unwrap();
    let silent = dir.path().join("7.sock");
    let healthy = dir.path().join("8.sock");

    let silent_listener = UnixListener::bind(&silent).unwrap();
    let silent_daemon = tokio::spawn(async move {
        let (_stream, _addr) = silent_listener.accept().await.unwrap();
        // Accept the conduit, then never read or write anything —
        // exactly the daemon-wedged-after-accept scenario `discover`'s
        // own doc promises "one misbehaving daemon must not hide the
        // others" against.
        std::future::pending::<()>().await
    });

    let healthy_listener = UnixListener::bind(&healthy).unwrap();
    let expected = vec![sample_host("found-on-healthy")];
    let healthy_daemon = spawn_fake_admin_daemon(
        healthy_listener,
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: expected.clone(),
        }),
    );

    // pid-ascending order visits the silent "7.sock" before the
    // healthy "8.sock"; without a deadline this call never returns.
    let hosts = discover(dir.path(), probe_via_admin_host_list)
        .await
        .unwrap();
    assert_eq!(hosts, expected);

    silent_daemon.abort();
    healthy_daemon.await.unwrap();
}

// ---- `discover` must never unlink a live daemon's socket ----

#[tokio::test]
async fn discover_does_not_unlink_a_refused_socket_whose_pid_is_still_alive() {
    let dir = tempfile::tempdir().unwrap();
    // Named after *this test process's own pid* — by construction
    // alive for the whole test — to prove `discover` consults
    // liveness rather than treating every `ECONNREFUSED` as proof of
    // death (adversarial review finding: a live daemon whose accept
    // backlog is full, or that is caught between `bind` and `listen`,
    // answers `ECONNREFUSED` too).
    let live_pid = std::process::id();
    let refused = dir.path().join(format!("{live_pid}.sock"));
    {
        // Bind then immediately drop the listener: the socket file
        // stays on disk, but nothing is listening any more, so a
        // connect to it now fails `ECONNREFUSED` — the same wire
        // symptom a full accept backlog on a genuinely live daemon
        // would produce, deliberately reused here for a
        // process-inspection-only assertion (this test cannot
        // actually fill an OS accept backlog deterministically).
        let _listener = UnixListener::bind(&refused).unwrap();
    }
    assert!(refused.exists());

    let err = discover(dir.path(), probe_via_admin_host_list)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        refused.exists(),
        "a socket named after a still-alive pid must never be unlinked on ECONNREFUSED alone"
    );
}

#[test]
fn candidate_sockets_on_a_missing_runtime_dir_is_an_empty_list_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    assert_eq!(candidate_sockets(&missing).unwrap(), Vec::new());
}

/// Turn `admin_host_list_over`'s result into a [`DiscoverOutcome`] the
/// way a real host-routing probe eventually will: a clean answer is
/// `Found`, the daemon's own `HOST_NOT_FOUND` is `NotFound`, anything
/// else propagates as an error `discover` will skip past.
async fn probe_via_admin_host_list(
    stream: UnixStream,
) -> Result<DiscoverOutcome<Vec<LocalHost>>, OpError> {
    match admin_host_list_over(stream).await {
        Ok(hosts) => Ok(DiscoverOutcome::Found(hosts)),
        Err(err) if err.code == ErrorCode::HostNotFound => Ok(DiscoverOutcome::NotFound),
        Err(err) => Err(err),
    }
}

/// A pid this test can prove is dead right now (spawn a trivial child,
/// wait for it to exit) — the one thing `discover`'s liveness check
/// actually trusts before unlinking an `ECONNREFUSED` candidate. A
/// hardcoded low pid like `1` (`init`/`launchd`, always alive) is not
/// safe to use for a "stale" candidate any more now that `discover`
/// verifies liveness rather than unlinking on `ECONNREFUSED` alone
/// (adversarial review finding).
fn a_definitely_dead_pid() -> u32 {
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn a short-lived helper process");
    let status = child.wait().expect("wait for the helper process to exit");
    assert!(status.success(), "helper process must exit cleanly");
    child.id()
}

#[tokio::test]
async fn discover_unlinks_a_refused_stale_socket_and_finds_the_next_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let dead_pid = a_definitely_dead_pid();
    let stale = dir.path().join(format!("{dead_pid}.sock"));
    // `dead_pid + 1` sorts immediately after it by construction, so
    // pid-ascending discovery is guaranteed to visit the stale
    // candidate first regardless of what `dead_pid` actually is.
    let live = dir.path().join(format!("{}.sock", dead_pid + 1));

    // A socket file with no listener behind it: bind, then drop the
    // listener immediately. The special file stays on disk; connecting
    // to it now fails ECONNREFUSED — exactly a crashed daemon's leftover.
    {
        let _listener = UnixListener::bind(&stale).unwrap();
    }
    assert!(stale.exists(), "the stale socket file must still exist");

    let listener = UnixListener::bind(&live).unwrap();
    let expected = vec![sample_host("phone")];
    let daemon = spawn_fake_admin_daemon(
        listener,
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: expected.clone(),
        }),
    );

    let hosts = discover(dir.path(), probe_via_admin_host_list)
        .await
        .unwrap();
    assert_eq!(hosts, expected);
    assert!(
        !stale.exists(),
        "the refused stale socket must be unlinked during discovery"
    );
    daemon.await.unwrap();
}

#[tokio::test]
async fn discover_tries_candidates_in_pid_ascending_order() {
    let dir = tempfile::tempdir().unwrap();
    let lower = dir.path().join("5.sock");
    let higher = dir.path().join("50.sock");

    let lower_hosts = vec![sample_host("lower-answered")];
    let higher_hosts = vec![sample_host("higher-answered")];

    let lower_listener = UnixListener::bind(&lower).unwrap();
    let higher_listener = UnixListener::bind(&higher).unwrap();
    let lower_daemon = spawn_fake_admin_daemon(
        lower_listener,
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: lower_hosts.clone(),
        }),
    );
    let higher_daemon = spawn_fake_admin_daemon(
        higher_listener,
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: higher_hosts,
        }),
    );

    // Both candidates would answer `Found` — if discovery visited
    // pid-descending (or arbitrary directory order) it could just as
    // easily return the higher-pid daemon's answer. Getting the
    // lower-pid one back is the only outcome consistent with
    // pid-ascending order and "stop at the first `Found`".
    let hosts = discover(dir.path(), probe_via_admin_host_list)
        .await
        .unwrap();
    assert_eq!(hosts, lower_hosts);

    lower_daemon.await.unwrap();
    // The higher-pid daemon is never dialed once the lower one answers
    // `Found` — nothing to await there but its accept() never completes,
    // which is exactly the point; drop it without joining.
    higher_daemon.abort();
}

#[tokio::test]
async fn discover_moves_past_daemons_that_say_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("10.sock");
    let second = dir.path().join("11.sock");

    let first_listener = UnixListener::bind(&first).unwrap();
    let second_listener = UnixListener::bind(&second).unwrap();
    let first_daemon = spawn_fake_admin_daemon(
        first_listener,
        local_response::Body::Error(LocalError::from_code(
            ErrorCode::HostNotFound,
            "unknown host",
        )),
    );
    let expected = vec![sample_host("found-on-second")];
    let second_daemon = spawn_fake_admin_daemon(
        second_listener,
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: expected.clone(),
        }),
    );

    let hosts = discover(dir.path(), probe_via_admin_host_list)
        .await
        .unwrap();
    assert_eq!(hosts, expected);
    first_daemon.await.unwrap();
    second_daemon.await.unwrap();
}

#[tokio::test]
async fn discover_exhausted_is_host_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let only = dir.path().join("42.sock");
    let listener = UnixListener::bind(&only).unwrap();
    let daemon = spawn_fake_admin_daemon(
        listener,
        local_response::Body::Error(LocalError::from_code(
            ErrorCode::HostNotFound,
            "unknown host",
        )),
    );

    let err = discover(dir.path(), probe_via_admin_host_list)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    daemon.await.unwrap();
}

#[tokio::test]
async fn discover_with_no_candidates_at_all_is_host_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let err = discover(dir.path(), probe_via_admin_host_list)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

// ---- `admin_host_list_all` — union across every daemon, bounded ----
// (adversarial review: this had zero direct coverage, and its own
// timeout stalled 60 s per wedged socket, serially)

#[tokio::test]
async fn admin_host_list_all_unions_across_two_live_daemons() {
    let dir = tempfile::tempdir().unwrap();
    let low = dir.path().join("10.sock");
    let high = dir.path().join("20.sock");

    let low_hosts = vec![sample_host("from-low-pid")];
    let high_hosts = vec![sample_host("from-high-pid")];
    let low_daemon = spawn_fake_admin_daemon(
        UnixListener::bind(&low).unwrap(),
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: low_hosts.clone(),
        }),
    );
    let high_daemon = spawn_fake_admin_daemon(
        UnixListener::bind(&high).unwrap(),
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: high_hosts.clone(),
        }),
    );

    let mut result = admin_host_list_all(dir.path()).await;
    result.sort_by_key(|d| d.pid);
    assert_eq!(result.len(), 2, "both live daemons must contribute");
    assert_eq!(result[0].pid, 10);
    assert_eq!(result[0].hosts, low_hosts);
    assert_eq!(result[1].pid, 20);
    assert_eq!(result[1].hosts, high_hosts);

    low_daemon.await.unwrap();
    high_daemon.await.unwrap();
}

#[tokio::test]
async fn admin_host_list_all_skips_a_daemon_that_answers_with_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("30.sock");
    let good = dir.path().join("40.sock");

    let bad_daemon = spawn_fake_admin_daemon(
        UnixListener::bind(&bad).unwrap(),
        local_response::Body::Error(LocalError::from_code(
            ErrorCode::PermissionDenied,
            "not allowed",
        )),
    );
    let expected = vec![sample_host("still-listed")];
    let good_daemon = spawn_fake_admin_daemon(
        UnixListener::bind(&good).unwrap(),
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: expected.clone(),
        }),
    );

    let result = admin_host_list_all(dir.path()).await;
    assert_eq!(
        result.len(),
        1,
        "a daemon answering with an error must be dropped, not turned into a failure"
    );
    assert_eq!(result[0].pid, 40);
    assert_eq!(result[0].hosts, expected);

    bad_daemon.await.unwrap();
    good_daemon.await.unwrap();
}

#[tokio::test]
async fn admin_host_list_all_with_no_candidates_is_an_empty_list() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(admin_host_list_all(dir.path()).await, Vec::new());
}

/// The regression this whole group of tests exists for: a socket that
/// accepts the conduit and then never answers must not be able to
/// stall the listing anywhere near [`PROBE_TIMEOUT`] (60 s) — measured
/// wall-clock, not virtual time, because the defect under test was a
/// real per-candidate wall-clock cost (adversarial review: 60.015 s
/// with one wedged socket before `ADMIN_LIST_CANDIDATE_TIMEOUT`
/// existed).
#[tokio::test]
async fn admin_host_list_all_does_not_stall_on_a_silent_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let silent = dir.path().join("50.sock");
    let silent_listener = UnixListener::bind(&silent).unwrap();
    let silent_daemon = tokio::spawn(async move {
        let (_stream, _addr) = silent_listener.accept().await.unwrap();
        // Accept the conduit, then never read or write — exactly the
        // "daemon wedged after accept" shape the adversarial review
        // reproduced against a real `qsh hosts` invocation.
        std::future::pending::<()>().await
    });

    let start = Instant::now();
    let result = admin_host_list_all(dir.path()).await;
    let elapsed = start.elapsed();

    assert_eq!(result, Vec::new(), "a silent daemon contributes nothing");
    assert!(
        elapsed < ADMIN_LIST_CANDIDATE_TIMEOUT * 2,
        "admin_host_list_all took {elapsed:?} against one silent daemon — \
         ADMIN_LIST_CANDIDATE_TIMEOUT is {ADMIN_LIST_CANDIDATE_TIMEOUT:?}"
    );

    silent_daemon.abort();
}

/// Two silent daemons must cost roughly the same as one — proving the
/// candidates are probed concurrently rather than serially (a serial
/// loop would cost ~2×[`ADMIN_LIST_CANDIDATE_TIMEOUT`] here, and the
/// pre-fix code cost ~2×`PROBE_TIMEOUT`, i.e. two full minutes).
#[tokio::test]
async fn admin_host_list_all_probes_multiple_silent_daemons_concurrently() {
    let dir = tempfile::tempdir().unwrap();
    let mut daemons = Vec::new();
    for pid in [60, 61] {
        let sock = dir.path().join(format!("{pid}.sock"));
        let listener = UnixListener::bind(&sock).unwrap();
        daemons.push(tokio::spawn(async move {
            let (_stream, _addr) = listener.accept().await.unwrap();
            std::future::pending::<()>().await
        }));
    }

    let start = Instant::now();
    let result = admin_host_list_all(dir.path()).await;
    let elapsed = start.elapsed();

    assert_eq!(result, Vec::new());
    assert!(
        elapsed < ADMIN_LIST_CANDIDATE_TIMEOUT * 2,
        "two silent daemons took {elapsed:?} — candidates are not being probed \
         concurrently (serial cost would be ~2×{ADMIN_LIST_CANDIDATE_TIMEOUT:?})"
    );

    for daemon in daemons {
        daemon.abort();
    }
}

/// The same silent-daemon-does-not-hide-others discipline `discover`
/// already proves, on `admin_host_list_all`'s union path instead of
/// `discover`'s stop-at-first-match path.
#[tokio::test]
async fn admin_host_list_all_returns_the_healthy_daemon_despite_a_silent_one() {
    let dir = tempfile::tempdir().unwrap();
    let silent = dir.path().join("70.sock");
    let healthy = dir.path().join("71.sock");

    let silent_listener = UnixListener::bind(&silent).unwrap();
    let silent_daemon = tokio::spawn(async move {
        let (_stream, _addr) = silent_listener.accept().await.unwrap();
        std::future::pending::<()>().await
    });

    let expected = vec![sample_host("healthy-answered")];
    let healthy_daemon = spawn_fake_admin_daemon(
        UnixListener::bind(&healthy).unwrap(),
        local_response::Body::HostListResult(LocalHostListResult {
            hosts: expected.clone(),
        }),
    );

    let start = Instant::now();
    let result = admin_host_list_all(dir.path()).await;
    let elapsed = start.elapsed();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].pid, 71);
    assert_eq!(result[0].hosts, expected);
    assert!(
        elapsed < ADMIN_LIST_CANDIDATE_TIMEOUT * 2,
        "took {elapsed:?} with one silent daemon present"
    );

    silent_daemon.abort();
    healthy_daemon.await.unwrap();
}
