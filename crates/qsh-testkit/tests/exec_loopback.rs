//! L3 loopback end-to-end: the full `exec.run` spine in one process —
//! pinned mTLS handshake → `Hello` → `ExecStart` → ACL + audit → ticket →
//! `EXEC_DATA` stream → spawn → stdio → `ExecExit` (`docs/design/testing.md`
//! §3, PLAN.md step 6).

use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::{AllowAllPinned, DenyAll};
use qsh_core::client::ClientError;
use qsh_core::exec::ExecSpec;
use qsh_proto::ErrorCode;
use qsh_proto::wire::{ExecFrame, StreamHeader};
use qsh_testkit::loopback::{LoopbackHarness, make_ca};
use qsh_transport::{FramedStream, Principal, StaticTrust};

fn spec(argv: &[&str]) -> ExecSpec {
    ExecSpec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: vec![],
        timeout: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_dod_case_stdout_stderr_and_exit_code() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    assert_eq!(s.capabilities, vec!["exec", "session", "resume.v1"]);

    let r = s
        .exec(&spec(&["sh", "-c", "echo out; echo err >&2; exit 7"]), None)
        .await
        .unwrap();
    assert_eq!(r.stdout, b"out\n");
    assert_eq!(r.stderr, b"err\n");
    assert_eq!(r.exit_code, 7);
    assert_eq!(r.signal, None);

    // A second exec on the same connection gets a fresh ticket.
    let r2 = s
        .exec(&spec(&["sh", "-c", "printf %s hi"]), None)
        .await
        .unwrap();
    assert_eq!(r2.stdout, b"hi");
    assert_eq!(r2.exit_code, 0);
    s.close();

    let records = h.audit.records();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.decision == "allow"));
    assert!(records.iter().all(|r| r.action == "exec.run"));
    assert!(records.iter().all(|r| r.principal == "device:laptop"));
    assert_eq!(h.server.pending_tickets(), 0);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_env_is_passed_to_the_remote_command() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let mut sp = spec(&["sh", "-c", "printf %s \"$QSH_TEST_VAR\""]);
    sp.env = vec![("QSH_TEST_VAR".into(), "hello env".into())];
    let r = s.exec(&sp, None).await.unwrap();
    assert_eq!(r.stdout, b"hello env");
    assert_eq!(r.exit_code, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_stdin_forwarding_and_large_output() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;

    let input = vec![b'x'; 100_000];
    let stdin: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(input.clone()));
    let r = s.exec(&spec(&["cat"]), Some(stdin)).await.unwrap();
    assert_eq!(r.stdout, input);
    assert_eq!(r.exit_code, 0);

    // 1 MiB of output, chunked into EXEC_CHUNK_MAX frames.
    let r = s
        .exec(
            &spec(&["sh", "-c", "head -c 1048576 /dev/zero | tr '\\0' 'a'"]),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r.stdout.len(), 1_048_576);
    assert!(r.stdout.iter().all(|&b| b == b'a'));
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_not_found_and_timeout() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;

    let r = s.exec(&spec(&["/nonexistent/binary"]), None).await.unwrap();
    assert_eq!(r.exit_code, 127);
    assert!(String::from_utf8_lossy(&r.stderr).contains("cannot execute"));

    // The command itself must be the thing that sleeps: on Windows there is
    // no process-group kill, so a shell wrapper's grandchild would keep the
    // pipes open past the deadline.
    let mut sp = spec(&["sleep", "30"]);
    sp.timeout = Some(Duration::from_millis(300));
    let started = std::time::Instant::now();
    let r = s.exec(&sp, None).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "timeout must kill"
    );
    assert!(r.timed_out, "host must flag the kill as a timeout");
    assert_ne!(r.exit_code, 0);
    #[cfg(unix)]
    assert_eq!(r.signal.as_deref(), Some("SIGKILL"));
}

/// POSIX signal semantics: a signaled exit is `128 + signo` with the signal
/// named, output produced before a timeout kill is still delivered, and a
/// plain signal death is *not* flagged as a timeout.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_signal_exit_and_timeout_kill_report_sigkill() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;

    let r = s
        .exec(&spec(&["sh", "-c", "kill -9 $$"]), None)
        .await
        .unwrap();
    assert_eq!(r.exit_code, 137);
    assert_eq!(r.signal.as_deref(), Some("SIGKILL"));
    assert!(!r.timed_out, "a plain signal exit is not a timeout");

    let mut sp = spec(&["sh", "-c", "echo before; sleep 30; echo after"]);
    sp.timeout = Some(Duration::from_millis(300));
    let started = std::time::Instant::now();
    let r = s.exec(&sp, None).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "timeout must kill the whole process group"
    );
    assert_eq!(r.stdout, b"before\n");
    assert_eq!(r.signal.as_deref(), Some("SIGKILL"));
    assert!(r.timed_out, "host must flag the kill as a timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_exec_returns_permission_denied_and_creates_nothing() {
    let h = LoopbackHarness::start_with(Arc::new(DenyAll)).await;
    let mut s = h.session().await;
    let err = s.exec(&spec(&["true"]), None).await.unwrap_err();
    match err {
        ClientError::Remote { code, .. } => assert_eq!(code, ErrorCode::PermissionDenied),
        other => panic!("expected remote PERMISSION_DENIED, got {other:?}"),
    }
    let records = h.audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, "deny");
    assert_eq!(h.server.pending_tickets(), 0);
}

/// The interim policy is allow-all-**pinned**. A client whose leaf is
/// CA-issued with a `qsh://device/laptop` SAN authenticates fine (the host
/// trusts the CA) and even yields the same `device:laptop` principal a pin
/// would — but it was never pinned, so `exec.run` must be denied and
/// audited as such. Nothing is created.
#[tokio::test(flavor = "multi_thread")]
async fn ca_issued_device_principal_is_denied_under_allow_all_pinned() {
    let ca = make_ca();
    let client = ca.issue("qsh://device/laptop");
    let server_trust = StaticTrust::empty().with_ca(ca.root_der.clone());
    let h = LoopbackHarness::start_custom(Arc::new(AllowAllPinned), client, server_trust).await;
    let dialed = h.dial().await;
    assert_eq!(
        dialed.connection.principal(),
        &Principal::Device("box".into())
    );
    let mut s = qsh_core::client::Session::negotiate(dialed.connection, "laptop")
        .await
        .expect("negotiate");
    let err = s.exec(&spec(&["true"]), None).await.unwrap_err();
    match err {
        ClientError::Remote { code, .. } => assert_eq!(code, ErrorCode::PermissionDenied),
        other => panic!("expected remote PERMISSION_DENIED, got {other:?}"),
    }
    let records = h.audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, "deny");
    assert_eq!(records[0].principal, "device:laptop");
    assert_eq!(h.server.pending_tickets(), 0);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bogus_ticket_stream_is_reset_without_spawn_or_audit() {
    let h = LoopbackHarness::start().await;
    let s = h.session().await;
    let (send, recv) = s.connection().open_bi().await.unwrap();
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::exec_data(vec![0u8; 16]))
        .await
        .unwrap();
    let res = data.recv.recv::<ExecFrame>().await;
    assert!(res.is_err(), "stream must be reset, got {res:?}");
    assert!(h.audit.records().is_empty());
    assert_eq!(h.server.pending_tickets(), 0);
}

/// A peer that redeems its ticket and then never reads the data stream
/// must not be able to wedge the host: once the deadline kills the child,
/// the host waits at most `DRAIN_GRACE` for the tail to drain, then resets
/// the stream and reaps. The child is gone well before that.
#[cfg(unix)] // pid files via `$$`, `kill -0`, process-group kill
#[tokio::test(flavor = "multi_thread")]
async fn peer_that_stops_reading_is_reset_after_the_drain_grace() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    // Enough output to overrun any flow-control window, then keep going.
    let script = format!(
        "echo $$ > {}; yes | head -c 40000000; sleep 30",
        pid_file.display()
    );
    let mut sp = spec(&["sh", "-c", &script]);
    sp.timeout = Some(Duration::from_millis(500));
    let started_msg = s.exec_start(&sp).await.unwrap();
    let (send, recv) = s.connection().open_bi().await.unwrap();
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::exec_data(started_msg.ticket))
        .await
        .unwrap();
    // ...and now sit on the stream without reading a byte.
    let alive = |pid: i32| {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|st| st.success())
            .unwrap_or(false)
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Ok(text) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = text.trim().parse::<i32>()
        {
            break pid;
        }
        assert!(std::time::Instant::now() < deadline, "child never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // The deadline kills the child regardless of the wedged stream.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while alive(pid) {
        assert!(
            std::time::Instant::now() < deadline,
            "child {pid} still alive well past its 500 ms timeout"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Keep *not* reading past the drain grace. Reading would open our
    // flow-control window and let the host finish normally — the point is
    // that it must not need us to.
    tokio::time::sleep(qsh_core::exec::DRAIN_GRACE + Duration::from_secs(1)).await;
    // The host has given up on us by now: the stream is reset, not left
    // hanging, and the reset wins over whatever was buffered.
    let res = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match data.recv.recv::<ExecFrame>().await {
                Ok(Some(_)) => continue,
                other => break other,
            }
        }
    })
    .await
    .expect("stream must have been reset by the host");
    match res {
        Err(qsh_transport::StreamError::Read(qsh_transport::ReadError::Reset(code))) => {
            assert_eq!(code.into_inner(), 1, "exec stream reset code");
        }
        other => panic!("expected the host to reset the wedged stream, got {other:?}"),
    }
    h.shutdown().await;
}

/// When the client vanishes mid-exec (connection dropped, no clean
/// `StdinEof`/close), the host must not leave the child running as an
/// orphan: nobody is listening, so it is killed with its process group.
#[cfg(unix)] // pid files via `$$`, `kill -0`, process-group kill
#[tokio::test(flavor = "multi_thread")]
async fn peer_disappearing_mid_exec_kills_the_child() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let script = format!("echo $$ > {}; exec sleep 30", pid_file.display());
    // Keep the connection alive only as long as this task runs.
    let conn = s.connection().clone();
    let exec_task = tokio::spawn(async move { s.exec(&spec(&["sh", "-c", &script]), None).await });

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Ok(text) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = text.trim().parse::<i32>()
        {
            break pid;
        }
        assert!(std::time::Instant::now() < deadline, "child never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let alive = |pid: i32| {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|st| st.success())
            .unwrap_or(false)
    };
    assert!(alive(pid), "child should be running before the drop");

    // Simulate the client dying: abrupt connection close, no protocol goodbye.
    conn.close(0x7777, b"gone");
    exec_task.abort();
    let _ = exec_task.await;

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while alive(pid) {
        assert!(
            std::time::Instant::now() < deadline,
            "orphaned child {pid} still alive 5s after the peer vanished"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
