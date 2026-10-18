//! The Windows host's graceful stop: `qsh serve` and `qsh serve --to` that
//! are told to stop close every session and leave no process behind
//! (`docs/CLI.md` §6.12, ADR-0003, ADR-0035 decision 22).
//!
//! This is the Windows counterpart of `serve_sigterm_drain.rs`, which is unix
//! only because its stop is `SIGTERM` and its orphan check is `kill -0` on a
//! pid the session's shell printed with `$$`. Here the stop is `CTRL_BREAK`
//! sent to the host's own process group (`common::send_stop`, the event a
//! console close or a service stop turns into), and the orphan check is
//! `qsh_testkit::shell::Runaway`: the session's process tree holds a marker
//! file open, and the file can be deleted only after the whole tree is gone,
//! so the Job Object that ties the tree to the host is what the test waits
//! on.
//!
//! Three things are checked against one run of each host: it exits `0`
//! within a bound, an attached consumer sees `session.closed` with reason
//! `closed` as its last word, and no process of any session survives. The
//! `drained` lifecycle line counts both sessions (one attached, one
//! detached) and nothing else.

#![cfg(windows)]

use crate::common;

use std::sync::mpsc;
use std::time::Duration;

use common::{Fleet, HOST_ALIAS, Sandbox, poll_until};
use qsh_core::{Ops, Paths, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{EnvVar, SessionAttachReq, SessionOpenReq};
use qsh_testkit::shell::Runaway;

use crate::route_cases::{ReverseRoute, Route};

/// Wall-clock bound for the whole scenario. Every wait inside is a real round
/// trip or a real process exit; this is only the "declare it broken"
/// backstop.
const DEADLINE: Duration = Duration::from_secs(120);

/// Bound on the drain itself: the stop event to the host's exit.
const DRAIN_BOUND: Duration = Duration::from_secs(30);

/// How long a session's command may take to start or to be gone.
const PROCESS_BOUND: Duration = Duration::from_secs(30);

/// `Ops` bound to a sandbox's config/state pair, called in-process.
fn ops_for(sandbox: &Sandbox) -> Ops {
    Ops::new(Paths::new(sandbox.config_dir(), sandbox.state_dir()))
}

/// Run `scenario` on a worker thread and fail if it has not finished within
/// [`DEADLINE`]: `Ops`'s attach API blocks the calling thread with no timeout
/// of its own.
fn with_deadline<T: Send + 'static>(
    what: &'static str,
    scenario: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(scenario());
    });
    match rx.recv_timeout(DEADLINE) {
        Ok(value) => {
            worker.join().expect("scenario thread panicked");
            value
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("{what} produced no result"),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{what} did not finish within {DEADLINE:?}")
        }
    }
}

/// Read events off `stream` until `session.closed` arrives, and return its
/// `reason`. A `session.exit` for the command's own death legitimately comes
/// first (`docs/CLI.md` §6.4, §6.7).
fn read_closed_reason(stream: &mut SessionAttachStream) -> String {
    loop {
        match stream.next_event() {
            Some(Ok(SessionEvent::Closed { reason, .. })) => return reason,
            Some(Ok(_)) => {}
            Some(Err(err)) => panic!("attach stream failed before session.closed: {err}"),
            None => panic!("the attach stream ended without ever delivering session.closed"),
        }
    }
}

fn open(ops: &Ops, host: &str, argv: Vec<String>) -> String {
    ops.session_open(SessionOpenReq {
        host: host.to_string(),
        argv,
        env: vec![EnvVar {
            name: "LANG".into(),
            value: "C".into(),
        }],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
    })
    .expect("session.open")
    .session_ref
}

const DRAINED_PREFIX: &str = "{\"lifecycle\":\"drained\"";

/// What one drained host did: its exit, the consumer's last word, and the
/// `drained` line it wrote.
struct Drained {
    status_success: bool,
    closed_reason: String,
    drained: Vec<String>,
    session_refs: Vec<String>,
    marker_dirs: Vec<String>,
}

/// Open two sessions through `client` to `host`, each running a command that
/// outlives the test, keep the first attached and leave the second detached,
/// then run `stop` (which stops the host and returns its exit status and a
/// reader of its stderr) and check what is left.
fn drain_two_sessions(
    client: &Sandbox,
    host: &str,
    stop: impl FnOnce() -> (bool, Box<dyn Fn() -> Vec<String>>),
) -> Drained {
    let ops = ops_for(client);
    let dirs = [
        tempfile::tempdir().expect("a marker directory"),
        tempfile::tempdir().expect("a marker directory"),
    ];
    let runaways = [Runaway::new(dirs[0].path()), Runaway::new(dirs[1].path())];
    let attached_ref = open(&ops, host, runaways[0].silent_argv());
    let detached_ref = open(&ops, host, runaways[1].silent_argv());

    let mut stream = ops
        .session_attach(
            SessionAttachReq {
                session_ref: attached_ref.clone(),
                no_steal: false,
            },
            &[],
        )
        .expect("session.attach");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime for the waits");
    for runaway in &runaways {
        rt.block_on(runaway.wait_running(PROCESS_BOUND));
    }

    // The attach is registered on the host once it holds the writer lease.
    // Nothing is printed on a silent session to wait for, and a drain that
    // came first would count the session as detached.
    poll_until("the attach to hold the writer lease", PROCESS_BOUND, || {
        let (code, got) = client.json(&["session", "get", &attached_ref, "--json"]);
        (code == 0 && !got["data"]["writer"].is_null()).then_some(())
    });

    let (status_success, stderr) = stop();
    let closed_reason = read_closed_reason(&mut stream);
    for runaway in &runaways {
        rt.block_on(runaway.wait_gone(PROCESS_BOUND));
    }
    // The host's stderr is read on a thread: wait for the line instead of
    // assuming it has been copied by the time the process is gone.
    let drained = poll_until("the drained lifecycle line", PROCESS_BOUND, || {
        let lines: Vec<String> = stderr()
            .into_iter()
            .filter(|line| line.starts_with(DRAINED_PREFIX))
            .collect();
        (!lines.is_empty()).then_some(lines)
    });
    stream.close();
    Drained {
        status_success,
        closed_reason,
        drained,
        session_refs: vec![attached_ref, detached_ref],
        marker_dirs: dirs
            .iter()
            .map(|dir| dir.path().display().to_string())
            .collect(),
    }
}

/// The `drained` line counts both sessions and carries nothing that names a
/// session, a command or a path (`docs/CLI.md` §6.12).
fn assert_drained(run: &Drained) {
    assert!(run.status_success, "the host did not exit 0 on the stop");
    assert_eq!(
        run.closed_reason, "closed",
        "docs/CLI.md §6.4: a drain closes with reason \"closed\""
    );
    assert_eq!(run.drained.len(), 1, "{:?}", run.drained);
    let line = &run.drained[0];
    let value: serde_json::Value = serde_json::from_str(line).expect("a JSON line");
    assert_eq!(value["sessions_closed"], 2, "{value}");
    assert_eq!(value["detached_closed"], 1, "{value}");
    assert_eq!(value["timed_out"], false, "{value}");
    let mut needles: Vec<&str> = run.session_refs.iter().map(String::as_str).collect();
    needles.extend(run.marker_dirs.iter().map(String::as_str));
    needles.extend(["ping", "cmd", "127.0.0.1"]);
    for needle in needles {
        assert!(!line.contains(needle), "`{needle}` leaked into: {line}");
    }
}

/// `qsh serve` told to stop with a live attached session and a live detached
/// one: it exits `0`, the attached consumer sees `session.closed`, nothing of
/// either session survives, and stdout stays empty.
#[test]
fn serve_stop_drains_sessions_and_leaves_no_orphan_on_windows() {
    let run = with_deadline("serve stop drain", || {
        let mut fleet = Fleet::start();
        drain_two_sessions(&fleet.client, HOST_ALIAS, || {
            fleet.serve.terminate();
            let status = fleet
                .serve
                .wait_timeout(DRAIN_BOUND)
                .unwrap_or_else(|| panic!("qsh serve did not exit within {DRAIN_BOUND:?}"));
            let output = fleet.serve.captured();
            assert!(
                output.stdout.is_empty(),
                "qsh serve wrote to stdout: {:?}",
                String::from_utf8_lossy(&output.stdout)
            );
            let stderr = output.stderr;
            (status.success(), Box::new(move || stderr.clone()))
        })
    });
    assert_drained(&run);
}

/// `qsh serve --to` told to stop with the same two sessions, reached through
/// the controller's daemon: the same exit, the same last word on the
/// consumer's stream, and no process left behind.
#[test]
fn serve_to_stop_drains_sessions_and_leaves_no_orphan_on_windows() {
    let run = with_deadline("serve --to stop drain", || {
        let mut route = ReverseRoute::start();
        let host = route.host().to_string();
        drain_two_sessions(&route.controller, &host, || {
            route.reverse.terminate();
            let status = route
                .reverse
                .wait_timeout(DRAIN_BOUND)
                .unwrap_or_else(|| panic!("qsh serve --to did not exit within {DRAIN_BOUND:?}"));
            // The live capture, not a copy: the reader thread may still be
            // draining the pipe, and the caller polls for the last line.
            let stderr = route.reverse.stderr_sink();
            (
                status.success(),
                Box::new(move || stderr.lock().unwrap_or_else(|e| e.into_inner()).clone()),
            )
        })
    });
    assert_drained(&run);
}
