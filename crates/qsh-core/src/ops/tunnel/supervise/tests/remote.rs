//! `-R` re-issue against a scripted peer (ADR-0023 decisions 7-4, 9, 11).
//!
//! The peer here answers `RemoteForwardOpen` and `RemoteForwardClose` from
//! switches the test flips: a bind that keeps failing the way a listener
//! that is still closing does, a policy that allows only port zero. A real
//! `qsh serve` cannot be told to do either.

use super::*;

struct RemoteRig {
    peer: ScriptedPeer,
    _peer_runtime: tokio::runtime::Runtime,
    /// The connection the tunnel was opened on.
    first: Connection,
    first_id: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    /// What the tunnel ended with: `None` for a deliberate stop.
    ended: std::sync::mpsc::Receiver<Option<crate::ops::OpError>>,
    _dir: tempfile::TempDir,
}

fn open_remote(bind_failures: usize) -> RemoteRig {
    capture_supervise_lines();
    let dir = tempfile::tempdir().unwrap();
    let ops = Ops::new(Paths::new(
        dir.path().join("config"),
        dir.path().join("state"),
    ));
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    let peer_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut peer = peer_runtime.block_on(scripted_peer());
    peer.rfwd
        .bind_failures
        .store(bind_failures, Ordering::SeqCst);
    ops.trust_add(TrustAddReq {
        name: "box".into(),
        address: Some(peer.addr.to_string()),
        fingerprint: Some(peer.fingerprint.clone()),
        cert_pem: None,
    })
    .unwrap();
    let hold = ops
        .tunnel_open(qsh_proto::TunnelOpenReq {
            host: "box".to_string(),
            mode: "remote".to_string(),
            bind: None,
            listen_port: u32::from(free_port()),
            forward_host: "127.0.0.1".to_string(),
            forward_port: 9,
            wait_ms: None,
            supervise_ms: Some(60_000),
            accept_hold_ms: None,
        })
        .expect("the supervised -R open over the scripted peer");
    let first_id = hold.tunnel().tunnel_id.clone();
    let first = peer_runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), peer.accepted.recv()).await
        })
        .expect("the first connection was accepted")
        .expect("the channel is open");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let (ended_tx, ended) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = ended_tx.send(hold.hold_until(async move {
            let _ = stopped.await;
        }));
    });
    RemoteRig {
        peer,
        _peer_runtime: peer_runtime,
        first,
        first_id,
        stop: Some(stop),
        ended,
        _dir: dir,
    }
}

impl RemoteRig {
    /// End the connection the tunnel is on, as a dropped path would.
    fn lose_the_connection(&self) {
        self.first.close(0, b"gone");
    }

    fn stop(&mut self) -> Option<crate::ops::OpError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.ended
            .recv_timeout(Duration::from_secs(30))
            .expect("the tunnel ends")
    }
}

fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Decision 7-4: the close was answered, the bind still fails, so the open
/// alone is sent again, three times at most.
#[test]
fn supervised_remote_reissue_survives_a_delayed_listener_drop_via_bounded_open_retries() {
    let mut rig = open_remote(2);
    assert_eq!(rig.first_id, "fwd-1");
    rig.lose_the_connection();
    wait_until(
        || !lines_of("reestablished").is_empty(),
        "the `reestablished` line",
    );
    let opens = rig.peer.rfwd.opens.lock().unwrap().clone();
    // The first open, then the re-issue: two failures and the open that
    // finally bound.
    assert_eq!(opens.len(), 4, "{opens:?}");
    assert!(
        opens[1..].iter().all(|open| open.bind_port == 43_210),
        "{opens:?}"
    );
    assert_eq!(*rig.peer.rfwd.closes.lock().unwrap(), vec!["fwd-1"]);
    let line = &lines_of("reestablished")[0];
    assert_eq!(line["mode"], "remote");
    assert_eq!(line["previous_tunnel_id"], "fwd-1");
    assert_eq!(line["tunnel_id"], "fwd-2");
    assert!(rig.stop().is_none());
}

/// Decision 7-4: once the three re-sends are spent the port is someone
/// else's; the attempt does not go on sending opens.
#[test]
fn supervised_remote_reissue_sends_at_most_three_open_retries_per_attempt() {
    let mut rig = open_remote(1_000);
    rig.lose_the_connection();
    // The first attempt fails and is reported before the next one starts.
    wait_until(|| !lines_of("retry").is_empty(), "the first `retry` line");
    // One open for the tunnel itself, then 1 + 3 in the failed attempt.
    assert_eq!(rig.peer.rfwd.opens.lock().unwrap().len(), 5);
    rig.peer.rfwd.bind_failures.store(0, Ordering::SeqCst);
    assert!(rig.stop().is_none());
}

/// Decisions 8 and 9: the re-issue goes through the peer's policy like the
/// first open did. A tunnel opened on port zero asks for the port it got,
/// which a policy that allows only port zero refuses, and a refusal by
/// policy ends the tunnel.
#[test]
fn supervised_ephemeral_remote_reissue_is_permission_denied_when_the_policy_allows_only_port_zero()
{
    let mut rig = open_remote(0);
    rig.peer
        .rfwd
        .deny_concrete_port
        .store(true, Ordering::SeqCst);
    rig.lose_the_connection();
    let err = rig
        .ended
        .recv_timeout(Duration::from_secs(30))
        .expect("the tunnel ends")
        .expect("a policy refusal is a failure, not a deliberate stop");
    assert_eq!(err.code, ErrorCode::PermissionDenied, "{err:?}");
    let gave_up = lines_of("gave_up");
    assert_eq!(gave_up.len(), 1, "{gave_up:?}");
    assert_eq!(gave_up[0]["code"], "PERMISSION_DENIED");
    rig.stop = None;
}

/// Decision 11: a supervised `-R` with a live carrier says goodbye to the
/// peer on a shutdown, and the peer receives it.
#[test]
fn supervised_remote_sigterm_sends_a_best_effort_close_the_peer_receives() {
    let mut rig = open_remote(0);
    assert!(rig.peer.rfwd.closes.lock().unwrap().is_empty());
    assert!(rig.stop().is_none(), "a signal is not a failure");
    assert_eq!(*rig.peer.rfwd.closes.lock().unwrap(), vec!["fwd-1"]);
}
