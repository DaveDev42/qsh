use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use super::*;
use crate::acl::AllowAllPinned;
use crate::audit::NullAuditSink;
use crate::broker::SystemClock;
use crate::localctl::client;
use crate::reverse::registry::{AdmittedEntry, Registry};
use tokio::io::AsyncReadExt as _;

/// A `Paths` fully sandboxed inside `dir`, `runtime_dir` included —
/// `.with_runtime_dir` pins the localctl socket location independent
/// of `$XDG_RUNTIME_DIR`, so these tests never touch the real runtime
/// directory regardless of what the host process's environment
/// happens to export (adversarial review finding: without this, every
/// test below raced other tests and a real `qsh listen` for sockets in
/// the ambient `$XDG_RUNTIME_DIR/qsh`, deleting some of them).
fn tmp_paths(dir: &tempfile::TempDir) -> Paths {
    Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"))
}

fn addr() -> SocketAddr {
    "127.0.0.1:4433".parse().unwrap()
}

fn test_listen() -> Arc<Listen> {
    let registry = Registry::new(Arc::new(SystemClock), false);
    Listen::new(
        registry,
        Arc::new(AllowAllPinned),
        Arc::new(NullAuditSink),
        "controller-device",
        Arc::new(SystemClock),
        Duration::from_secs(120),
    )
}

// ---- socket lifetime and permissions (`docs/design/testing.md` L2) ----

#[tokio::test]
async fn bind_creates_the_runtime_dir_0700_and_the_socket_0600() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9001).unwrap();

    let dir_mode = std::fs::metadata(paths.runtime_dir())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "runtime dir must be 0700");

    let sock_mode = std::fs::metadata(&bound.socket_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(sock_mode, 0o600, "socket file must be 0600");
}

#[tokio::test]
async fn bind_with_narrow_umask_creates_the_socket_node_at_0600_before_any_explicit_chmod() {
    // Calls `bind_with_narrow_umask` directly — with no subsequent
    // `tighten_socket_mode` call at all — to pin the atomicity
    // property itself: the node must already be 0600 the instant
    // `bind(2)` returns, not merely by the time `LocalctlListener::bind`
    // gets around to chmod-ing it (adversarial review finding: the
    // un-narrowed umask left a window where the node was world-
    // readable/connectable in mode terms).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("umask-atomicity.sock");
    let _listener = bind_with_narrow_umask(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "the socket node itself must be 0600 the instant bind(2) returns"
    );
}

#[tokio::test]
async fn bind_removes_a_stale_socket_file_at_the_exact_same_path() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    // A leftover regular file (not even a real socket) at the exact
    // path a pid-reused daemon would bind — `bind` must clear it
    // rather than failing `AddrInUse`.
    std::fs::create_dir_all(paths.runtime_dir()).unwrap();
    std::fs::write(paths.localctl_socket(9002), b"stale").unwrap();

    let bound = LocalctlListener::bind(&paths, 9002).unwrap();
    assert_eq!(bound.socket_path, paths.localctl_socket(9002));
}

// ---- peer credential check (`docs/design/protocol.md` §11-3) ----

#[test]
fn peer_is_authorized_only_when_the_uid_matches() {
    assert!(peer_is_authorized(1000, 1000));
    assert!(!peer_is_authorized(1000, 1001));
    assert!(!peer_is_authorized(0, 1000));
}

/// Exercises the *real* `SO_PEERCRED`/`getpeereid` syscall path via
/// [`tokio::net::UnixStream::peer_cred`] — both ends of this pair are
/// this same test process, so the peer uid this returns must equal
/// this process's own euid, proving the accept-time check actually
/// runs the OS lookup and not just [`peer_is_authorized`]'s pure logic
/// (`docs/history/m3-plan.md` Step 5 (c): "peer-cred 코드 경로를 단언" — the same-euid
/// half of that requirement; a genuinely different euid is not
/// obtainable without a second OS user, which CI does not provide).
#[tokio::test]
async fn same_euid_peer_is_authorized_via_the_real_peer_cred_syscall() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9003).unwrap();
    let socket_path = bound.socket_path.clone();

    let accept = tokio::spawn(async move { bound.listener.accept().await.unwrap().0 });
    let _client = UnixStream::connect(&socket_path).await.unwrap();
    let server_side = accept.await.unwrap();

    assert!(
        LocalctlDaemon::authorized_peer(&server_side).unwrap(),
        "this process connecting to its own socket must be authorized"
    );
}

// ---- LOCAL_ADMIN / LocalHostList (`docs/CLI.md` §6.13) ----

#[tokio::test]
async fn local_host_list_returns_the_registrys_current_entries_including_stale() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let listen = test_listen();
    listen
        .registry()
        .admit(
            "phone".to_string(),
            AdmittedEntry {
                fingerprint: "sha256:aaaa",
                principal: "device:phone",
                address: addr(),
                capabilities: vec!["pty".to_string()],
            },
        )
        .unwrap();
    let stale = listen
        .registry()
        .admit(
            "old-laptop".to_string(),
            AdmittedEntry {
                fingerprint: "sha256:bbbb",
                principal: "device:old-laptop",
                address: addr(),
                capabilities: vec![],
            },
        )
        .unwrap();
    listen
        .registry()
        .mark_stale("old-laptop", stale.entry.generation)
        .unwrap();

    let bound = LocalctlListener::bind(&paths, 9004).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::new(listen);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    let hosts = client::admin_host_list(&socket_path).await.unwrap();
    let mut by_name: Vec<(String, String)> = hosts.into_iter().map(|h| (h.name, h.state)).collect();
    by_name.sort();
    assert_eq!(
        by_name,
        vec![
            ("old-laptop".to_string(), "stale".to_string()),
            ("phone".to_string(), "reachable".to_string()),
        ]
    );

    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

#[tokio::test]
async fn local_host_list_on_an_empty_registry_is_an_empty_list_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9005).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::new(test_listen());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    let hosts = client::admin_host_list(&socket_path).await.unwrap();
    assert!(hosts.is_empty());

    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

/// A real daemon (this Stage's `LocalctlDaemon`, not a fake in-test
/// stub) whose registry has no entry at all for the name a caller
/// wants: `client::discover`'s own exhaustion rule
/// (`docs/design/architecture.md` §7: "전부 실패하면 HOST_NOT_FOUND다")
/// still surfaces `HOST_NOT_FOUND`, now proven end to end through the
/// real UDS/peer-credential/`LOCAL_ADMIN` path this PR builds — Stage
/// A's own `discover_exhausted_is_host_not_found` proved the same rule
/// only against a synthetic fake daemon.
#[tokio::test]
async fn discover_against_a_real_daemon_with_no_matching_host_is_host_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let listen = test_listen();
    listen
        .registry()
        .admit(
            "some-other-host".to_string(),
            AdmittedEntry {
                fingerprint: "sha256:cccc",
                principal: "device:some-other-host",
                address: addr(),
                capabilities: vec![],
            },
        )
        .unwrap();

    let bound = LocalctlListener::bind(&paths, 9006).unwrap();
    let daemon = LocalctlDaemon::new(listen);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    let wanted = "nobody-registered-this-name";
    let err = client::discover(&paths.runtime_dir(), |stream| async move {
        match client::admin_host_list_over(stream).await {
            Ok(hosts) if hosts.iter().any(|h| h.name == wanted) => {
                Ok(client::DiscoverOutcome::Found(()))
            }
            Ok(_) => Ok(client::DiscoverOutcome::NotFound),
            Err(err) => Err(err),
        }
    })
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);

    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

// ---- unknown / unsupported conduit kind ----

#[tokio::test]
async fn an_unspecified_kind_answers_invalid_argument_not_a_hang() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9007).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::new(test_listen());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalUnspecified as i32,
            host: String::new(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .unwrap();
    let response: LocalResponse = conduit.recv().await.unwrap().unwrap();
    match response.body {
        Some(local_response::Body::Error(err)) => {
            assert_eq!(err.error_code(), ErrorCode::InvalidArgument);
        }
        other => panic!("expected LocalError, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

/// `M3 Step 6` gave `LOCAL_CONTROL` a real serve path
/// ([`LocalctlDaemon::serve_control`]) — an unregistered/unknown host
/// now answers `HOST_NOT_FOUND`, not the pre-Step-6 blanket
/// `UNSUPPORTED` this test used to assert (it predates that landing;
/// updated here rather than left to bit-rot green on a wrong
/// assertion). `LOCAL_STREAM` is the kind still genuinely unserved —
/// see the sibling test right below.
#[tokio::test]
async fn local_control_for_an_unknown_host_is_host_not_found_not_forwarded_or_hung() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9008).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::new(test_listen());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalControl as i32,
            host: "some-host".to_string(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .unwrap();
    let response: LocalResponse = conduit.recv().await.unwrap().unwrap();
    match response.body {
        Some(local_response::Body::Error(err)) => {
            assert_eq!(err.error_code(), ErrorCode::HostNotFound);
        }
        other => panic!("expected LocalError, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

/// `LOCAL_STREAM` (`M3 Step 7`) is served, so an unregistered host now
/// gets the same `HOST_NOT_FOUND` `LOCAL_CONTROL` already answers —
/// never a hang, never `UNSUPPORTED` (the pre-Step-7 contract the
/// test this replaces used to cover), and never anything opened on
/// QUIC.
#[tokio::test]
async fn local_stream_for_an_unknown_host_is_host_not_found_not_forwarded_or_hung() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9009).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::new(test_listen());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalStream as i32,
            host: "some-host".to_string(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .unwrap();
    let response: LocalResponse = conduit.recv().await.unwrap().unwrap();
    match response.body {
        Some(local_response::Body::Error(err)) => {
            assert_eq!(err.error_code(), ErrorCode::HostNotFound);
        }
        other => panic!("expected LocalError, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

/// [`serve_stream`](LocalctlDaemon::serve_stream)'s header-shape
/// decision reduces entirely to [`local_stream_relay_kind`] — the
/// *same* function `serve_stream` itself calls, not a hand-mirrored
/// twin (an earlier version of this test drove a test-only
/// `is_session_data_header` that only mirrored `serve_stream`'s own
/// inline match; an adversarial-review finding showed mutating the
/// production match away left that twin's test green). A table over
/// every `StreamKind` this build knows, plus one it does not, so an
/// unlisted kind cannot silently start being accepted or a listed one
/// silently start being refused. `crates/qsh-testkit`'s
/// `local_stream_reverse.rs` proves the full end-to-end contract
/// against a genuine connection; this pins the decision in isolation.
#[test]
fn local_stream_relay_kind_accepts_exactly_the_documented_kinds() {
    assert_eq!(
        local_stream_relay_kind(&wire::StreamHeader::session_data(vec![1, 2, 3])),
        Some(LocalStreamRelay::OpenBidiAndSplice {
            priority: wire::PRIORITY_SESSION_DATA,
            tunnel_permit: false,
            reset_on_uds_eof: false,
            ack_before_splice: false,
        }),
    );
    assert_eq!(
        local_stream_relay_kind(&wire::StreamHeader::exec_data(vec![1, 2, 3])),
        Some(LocalStreamRelay::OpenBidiAndSplice {
            priority: wire::PRIORITY_EXEC_DATA,
            tunnel_permit: false,
            reset_on_uds_eof: true,
            ack_before_splice: true,
        }),
        "EXEC_DATA must relay at PRIORITY_EXEC_DATA, take no tunnel permit, reset (not \
         finish) the QUIC send side on a clean UDS EOF, and get an explicit ack before the \
         splice (issue #5)",
    );
    assert_eq!(
        local_stream_relay_kind(&wire::StreamHeader {
            kind: wire::StreamKind::TcpConnect as i32,
            ticket: Vec::new(),
            host: "widget".to_string(),
            port: 22,
            deny_host_local: false,
        }),
        Some(LocalStreamRelay::OpenBidiAndSplice {
            priority: wire::PRIORITY_TUNNEL,
            tunnel_permit: true,
            reset_on_uds_eof: false,
            ack_before_splice: false,
        }),
    );
    assert_eq!(
        local_stream_relay_kind(&wire::StreamHeader {
            kind: wire::StreamKind::TcpAccepted as i32,
            ticket: Vec::new(),
            host: String::new(),
            port: 0,
            deny_host_local: false,
        }),
        Some(LocalStreamRelay::ClaimTcpAccepted),
    );
    assert_eq!(
        local_stream_relay_kind(&wire::StreamHeader {
            kind: wire::StreamKind::Unspecified as i32,
            ticket: Vec::new(),
            host: String::new(),
            port: 0,
            deny_host_local: false,
        }),
        None,
    );
    // A kind value this build does not recognize at all — `stream_kind()`
    // returns `None` (`StreamKind::try_from` fails), which must be
    // rejected exactly like a recognized-but-wrong kind, never treated
    // as acceptable by default.
    assert_eq!(
        local_stream_relay_kind(&wire::StreamHeader {
            kind: 99,
            ticket: Vec::new(),
            host: String::new(),
            port: 0,
            deny_host_local: false,
        }),
        None,
    );
}

// ---- the peer-credential gate must actually stop the conduit
// (adversarial review finding: deleting the gate left every localctl
// test green — this drives the negative outcome directly, since a
// genuinely different euid needs a second OS user CI does not have) ----

#[tokio::test]
async fn an_unauthorized_peer_is_closed_before_any_frame_is_read_or_answered() {
    let (server_side, mut client_side) = UnixStream::pair().unwrap();
    let daemon = LocalctlDaemon::new(test_listen());

    // A literal `Ok(false)` stands in for the OS-level check reporting
    // a mismatched euid — see `serve_authorized_conduit`'s doc for why
    // this is the seam that makes the negative case testable at all.
    let handshake_permits = Arc::new(Semaphore::new(1));
    let handshake_permit = handshake_permits.try_acquire_owned().unwrap();
    let task =
        tokio::spawn(daemon.serve_authorized_conduit(server_side, Ok(false), handshake_permit));

    // The client side never sends a `LocalHello` — if the gate were
    // deleted (as the adversarial mutation check did), the daemon
    // would instead sit waiting for one, and this bounded read would
    // time out rather than observe a close.
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(500), client_side.read(&mut buf))
        .await
        .expect("an unauthorized peer must be closed promptly, not left waiting for a frame")
        .expect("the close must be a clean EOF, not a read error");
    assert_eq!(
        read, 0,
        "an unauthorized peer must see the conduit close, never a protocol reply"
    );

    task.await.unwrap();
}

// ---- LocalHello.version (`qsh listen` is resident, so version skew
// against an older daemon is the normal case this exists to catch) ----

#[tokio::test]
async fn a_hello_with_a_version_this_daemon_does_not_speak_is_answered_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9009).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::new(test_listen());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION + 1,
            kind: LocalStreamKind::LocalAdmin as i32,
            host: String::new(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .unwrap();
    let response: LocalResponse = conduit.recv().await.unwrap().unwrap();
    match response.body {
        Some(local_response::Body::Error(err)) => {
            assert_eq!(err.error_code(), ErrorCode::Unsupported);
        }
        other => panic!("expected LocalError, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

// ---- bounded handshake wait (`docs/history/m3-plan.md` Step 5: "never a panic or
// a hang", `LOCAL_WAIT_MAX`'s own "no caller pins a daemon slot open
// indefinitely" discipline applied to the handshake itself) ----

#[tokio::test(start_paused = true)]
async fn a_peer_that_never_sends_a_hello_is_closed_after_the_wait_ceiling_not_held_open_forever() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9010).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::new(test_listen());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();
    // Never send a `LocalHello`. `start_paused` auto-advances virtual
    // time past `LOCAL_WAIT_MAX` the instant every other task is idle,
    // so this proves the deadline actually closes the peer rather than
    // relying on a real 60s wall-clock wait.
    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(
        n, 0,
        "a peer that never sends a LocalHello must be closed after LOCAL_WAIT_MAX, not held \
         open indefinitely"
    );

    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

// ---- LOCAL_ADMIN/LOCAL_CONTROL/LOCAL_STREAM draw from independent
// permit pools (adversarial review finding: before the first split,
// long-lived LOCAL_CONTROL conduits shared the same accept-time pool
// as brief LOCAL_ADMIN discovery round trips, so enough concurrent
// sessions silently starved routing discovery of a connection at
// all; LOCAL_STREAM (`M3 Step 7`) gets the same treatment) ----

/// Structural pin, independent of any real conduit traffic: the three
/// pools never share capacity in any direction.
#[test]
fn admin_control_and_stream_pools_are_independent_semaphores() {
    let daemon = LocalctlDaemon::with_pool_sizes(test_listen(), 3, 5, 7);
    assert_eq!(daemon.admin_permits.available_permits(), 3);
    assert_eq!(daemon.control_permits.available_permits(), 5);
    assert_eq!(daemon.stream_permits.available_permits(), 7);

    // Exhaust the admin pool entirely.
    let held: Vec<_> = (0..3)
        .map(|_| daemon.admin_permits.clone().try_acquire_owned().unwrap())
        .collect();
    assert_eq!(daemon.admin_permits.available_permits(), 0);
    // The other two pools must be completely unaffected.
    assert_eq!(
        daemon.control_permits.available_permits(),
        5,
        "exhausting the admin pool must never touch the control pool's capacity"
    );
    assert_eq!(
        daemon.stream_permits.available_permits(),
        7,
        "exhausting the admin pool must never touch the stream pool's capacity"
    );

    drop(held);
    // Symmetrically, exhausting control must never touch admin or
    // stream.
    let held_control: Vec<_> = (0..5)
        .map(|_| daemon.control_permits.clone().try_acquire_owned().unwrap())
        .collect();
    assert_eq!(daemon.admin_permits.available_permits(), 3);
    assert_eq!(daemon.control_permits.available_permits(), 0);
    assert_eq!(daemon.stream_permits.available_permits(), 7);

    drop(held_control);
    // And exhausting stream must never touch admin or control.
    let _held_stream: Vec<_> = (0..7)
        .map(|_| daemon.stream_permits.clone().try_acquire_owned().unwrap())
        .collect();
    assert_eq!(daemon.admin_permits.available_permits(), 3);
    assert_eq!(daemon.control_permits.available_permits(), 5);
    assert_eq!(daemon.stream_permits.available_permits(), 0);
}

/// At the `LOCAL_ADMIN` pool's own cap, a new connection now gets an
/// explicit `LocalError{RESOURCE_EXHAUSTED}` envelope rather than
/// being silently closed before ever being read — the distinction
/// `admin_host_list_all`/`resolve_host_route` need to tell "daemon
/// saturated" apart from "no such host" (`docs/CLI.md` §6.2).
/// Held-open connections are real `LOCAL_ADMIN` conduits parked
/// mid-handshake (hello sent, `LocalAdminRequest` body deliberately
/// withheld) rather than a live `LOCAL_CONTROL` host, which needs a
/// real reverse QUIC registration this crate's own unit tests cannot
/// stand up — `crates/qsh-testkit/tests/local_control_reverse.rs`
/// covers the same pool end to end over a real reverse connection.
#[tokio::test]
async fn local_admin_at_the_admin_pools_cap_answers_resource_exhausted_not_a_silent_drop() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9011).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::with_pool_sizes(
        test_listen(),
        1,
        MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS,
        MAX_CONCURRENT_LOCAL_STREAM_CONDUITS,
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    // Occupy the single admin permit: send `LocalHello` and then never
    // send the follow-up `LocalAdminRequest` — `serve_admin` blocks
    // forever on that read, holding the permit for as long as this
    // stream stays open.
    let holder = UnixStream::connect(&socket_path).await.unwrap();
    let mut holder = LocalConduit::new(holder);
    holder
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalAdmin as i32,
            host: String::new(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .unwrap();

    // Give the accept loop a moment to actually acquire the admin
    // permit before this connection races it.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalAdmin as i32,
            host: String::new(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .unwrap();
    let response: LocalResponse = tokio::time::timeout(Duration::from_secs(5), conduit.recv())
        .await
        .expect("the daemon must answer promptly, not hang")
        .unwrap()
        .expect("a real envelope, not a silent close");
    match response.body {
        Some(local_response::Body::Error(err)) => {
            assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
        }
        other => panic!("expected LocalError(RESOURCE_EXHAUSTED), got {other:?}"),
    }

    drop(holder);
    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

/// [`LOCAL_STREAM`]'s own pool answers the same explicit
/// `LocalError{RESOURCE_EXHAUSTED}` at its cap, not a silent close —
/// the `LOCAL_STREAM` twin of
/// `local_admin_at_the_admin_pools_cap_answers_resource_exhausted_not_a_silent_drop`
/// above (adversarial review finding: this arm — `serve_authorized_conduit`'s
/// `LocalStreamKind::LocalStream => ... Err(_) => ...ResourceExhausted`
/// — had no test of its own; only the pools' *capacity independence*
/// was pinned, never this specific dispatch arm firing). The one
/// stream permit is held directly rather than via a live parked
/// `LOCAL_STREAM` conduit (unlike the admin test's holder): holding a
/// `LOCAL_STREAM` permit open via the wire would mean parking inside
/// `serve_stream`'s `connection_for_wait` — a real wait loop this
/// crate's unit tests have no live reverse registration to eventually
/// resolve, so it would hang for `LOCAL_WAIT_MAX` instead of exiting
/// promptly. Grabbing the permit straight from the semaphore proves
/// exactly the same dispatch-arm behavior without that wait.
#[tokio::test]
async fn local_stream_at_the_stream_pools_cap_answers_resource_exhausted_not_a_silent_drop() {
    let dir = tempfile::tempdir().unwrap();
    let paths = tmp_paths(&dir);
    let bound = LocalctlListener::bind(&paths, 9012).unwrap();
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::with_pool_sizes(
        test_listen(),
        MAX_CONCURRENT_LOCAL_ADMIN_QUERIES,
        MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS,
        1,
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.clone().run(bound, async move {
        let _ = shutdown_rx.await;
    }));

    // Hold the daemon's one `LOCAL_STREAM` permit directly — this is
    // the same `Arc<Semaphore>` `serve_authorized_conduit`'s
    // `LocalStreamKind::LocalStream` arm acquires from, so a second
    // connection's `try_acquire_owned` there is guaranteed to fail
    // exactly as it would with a real held conduit.
    let _held = daemon.stream_permits.clone().try_acquire_owned().unwrap();

    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalStream as i32,
            host: "irrelevant-host".to_string(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .unwrap();
    let response: LocalResponse = tokio::time::timeout(Duration::from_secs(5), conduit.recv())
        .await
        .expect("the daemon must answer promptly, not hang")
        .unwrap()
        .expect("a real envelope, not a silent close");
    match response.body {
        Some(local_response::Body::Error(err)) => {
            assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
        }
        other => panic!("expected LocalError(RESOURCE_EXHAUSTED), got {other:?}"),
    }

    drop(_held);
    let _ = shutdown_tx.send(());
    task.await.unwrap();
}

// Issue #4 items 4/3a: `to_local_host` must pass `ReverseEntry.lost_at`
// straight through to `LocalHost.lost_at`, `Some` exactly when the
// registry set it (only ever true for a `Stale` entry —
// `Registry::mark_stale`'s own doc) and `None` for a `Live` one, never
// invented or dropped on the way across this hop.
#[test]
fn to_local_host_passes_lost_at_through_for_a_stale_entry() {
    let entry = sample_reverse_entry(EntryState::Stale, Some("2026-08-22T00:00:07Z".to_string()));
    let local = to_local_host(entry);
    assert_eq!(local.state, "stale");
    assert_eq!(local.lost_at.as_deref(), Some("2026-08-22T00:00:07Z"));
}

#[test]
fn to_local_host_omits_lost_at_for_a_live_entry() {
    let entry = sample_reverse_entry(EntryState::Live, None);
    let local = to_local_host(entry);
    assert_eq!(local.state, "reachable");
    assert_eq!(local.lost_at, None);
}

/// CI run 36800800530's flake (`reverse_exec`'s
/// `exec_run_prefers_a_live_reverse_registration_over_a_dead_forward_pin`,
/// "exec stream ended without ExecExit"): the target answers `ExecExit`
/// and stops reading the moment its command exits, so the CLI's late
/// `StdinEof` fails `pump_uds_to_quic`'s QUIC write. That failure must
/// not cancel `pump_quic_to_uds` while `ExecExit` still sits unread:
/// the CLI must still receive it, then a clean EOF.
#[tokio::test]
async fn a_dead_quic_send_leg_does_not_discard_the_targets_pending_final_frame() {
    use tokio::io::AsyncWriteExt as _;

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut a_send, a_recv) = client.quinn().open_bi().await.unwrap();
    a_send.write_all(b"hdr").await.unwrap();
    let (mut b_send, mut b_recv) = server.quinn().accept_bi().await.unwrap();
    let mut hdr = [0u8; 3];
    b_recv.read_exact(&mut hdr).await.unwrap();
    // Target: final frame out and finished, then the recv half goes away.
    b_send.write_all(b"EXITFRAME").await.unwrap();
    b_send.finish().unwrap();
    b_recv.stop(quinn::VarInt::from_u32(0)).unwrap();
    // The daemon side learns the send half is dead before its pumps run.
    a_send.stopped().await.unwrap();

    let (cli, daemon_uds) = tokio::net::UnixStream::pair().unwrap();
    let (mut cli_read, mut cli_write) = cli.into_split();
    cli_write.write_all(b"late StdinEof").await.unwrap();
    let (uds_read, uds_write) = daemon_uds.into_split();
    // Let the reactor mark the UDS readable, so the first poll of
    // `pump_uds_to_quic` reads at once and hits the dead QUIC send leg
    // while `EXITFRAME` is still unread (the CI interleaving).
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (uds_gone_tx, uds_gone_rx) = tokio::sync::oneshot::channel();
    let (quic_gone_tx, quic_gone_rx) = tokio::sync::oneshot::channel();
    let pumps = async {
        tokio::join!(
            pump_uds_to_quic(uds_read, a_send, true, uds_gone_tx, quic_gone_rx),
            pump_quic_to_uds(a_recv, uds_write, quic_gone_tx, uds_gone_rx),
        )
    };
    let reader = async {
        let mut got = Vec::new();
        cli_read.read_to_end(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(pumps, reader)
    })
    .await
    .expect("pumps and reader must finish");
    assert_eq!(got, b"EXITFRAME");
}

/// The CLI half-closes its write side (`DataSendHalf::finish`, what an
/// attach does once its stdin is done or a detach is flushing) and is
/// still owed whatever the target answers after it sees the FIN — a
/// trailing frame, the `InputAck` a detach waits for. The UDS EOF must
/// finish the QUIC send half only; it must not cancel the QUIC→UDS leg
/// while that answer is still on its way.
#[tokio::test]
async fn a_cli_half_close_does_not_discard_the_targets_trailing_answer() {
    use tokio::io::AsyncWriteExt as _;

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut a_send, a_recv) = client.quinn().open_bi().await.unwrap();
    a_send.write_all(b"hdr").await.unwrap();
    let (mut b_send, mut b_recv) = server.quinn().accept_bi().await.unwrap();
    let mut hdr = [0u8; 3];
    b_recv.read_exact(&mut hdr).await.unwrap();
    // Target: answers only once it has seen the CLI's FIN, i.e. strictly
    // after the daemon has relayed the half-close.
    let target = tokio::spawn(async move {
        let rest = b_recv.read_to_end(1024).await.unwrap();
        assert_eq!(rest, b"in");
        b_send.write_all(b"TRAILING").await.unwrap();
        b_send.finish().unwrap();
        // Keep both halves alive until the stream is fully delivered.
        let _ = b_send.stopped().await;
    });

    let (cli, daemon_uds) = tokio::net::UnixStream::pair().unwrap();
    let (mut cli_read, mut cli_write) = cli.into_split();
    cli_write.write_all(b"in").await.unwrap();
    cli_write.shutdown().await.unwrap();
    let (uds_read, uds_write) = daemon_uds.into_split();

    let (uds_gone_tx, uds_gone_rx) = tokio::sync::oneshot::channel();
    let (quic_gone_tx, quic_gone_rx) = tokio::sync::oneshot::channel();
    let pumps = async {
        tokio::join!(
            pump_uds_to_quic(uds_read, a_send, false, uds_gone_tx, quic_gone_rx),
            pump_quic_to_uds(a_recv, uds_write, quic_gone_tx, uds_gone_rx),
        )
    };
    let reader = async {
        let mut got = Vec::new();
        cli_read.read_to_end(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(pumps, reader)
    })
    .await
    .expect("pumps and reader must finish");
    assert_eq!(got, b"TRAILING");
    target.await.unwrap();
}

/// The other side of the half-close rule: once the CLI half-closes and
/// then goes away entirely, a silent target must still be released
/// (`STOP_SENDING` on its stream), or every idle detach would pin a
/// conduit permit for ever.
#[tokio::test]
async fn a_cli_that_half_closes_and_then_hangs_up_still_releases_an_idle_target() {
    use tokio::io::AsyncWriteExt as _;

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut a_send, a_recv) = client.quinn().open_bi().await.unwrap();
    a_send.write_all(b"hdr").await.unwrap();
    let (b_send, mut b_recv) = server.quinn().accept_bi().await.unwrap();
    let mut hdr = [0u8; 3];
    b_recv.read_exact(&mut hdr).await.unwrap();
    // Target stays silent and keeps its send half open.

    let (cli, daemon_uds) = tokio::net::UnixStream::pair().unwrap();
    let (cli_read, mut cli_write) = cli.into_split();
    cli_write.shutdown().await.unwrap();
    let (uds_read, uds_write) = daemon_uds.into_split();

    let (uds_gone_tx, uds_gone_rx) = tokio::sync::oneshot::channel();
    let (quic_gone_tx, quic_gone_rx) = tokio::sync::oneshot::channel();
    let pumps = async {
        tokio::join!(
            pump_uds_to_quic(uds_read, a_send, false, uds_gone_tx, quic_gone_rx),
            pump_quic_to_uds(a_recv, uds_write, quic_gone_tx, uds_gone_rx),
        )
    };
    let hang_up = async {
        // The CLI process goes away: both halves closed.
        drop(cli_read);
        drop(cli_write);
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(pumps, hang_up)
    })
    .await
    .expect("a hung-up CLI must end both pumps");
    let stopped = tokio::time::timeout(Duration::from_secs(10), b_send.stopped())
        .await
        .expect("the idle target must see STOP_SENDING")
        .unwrap();
    assert_eq!(
        stopped,
        Some(quinn::VarInt::from_u32(RESET_CODE_LOCAL_PEER_GONE))
    );
}
