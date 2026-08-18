//! `Ops::session_attach` driven for real, against a live `qsh serve`
//! (`docs/CLI.md` §7.1 — the one stream operation).
//!
//! The interactive TUI is a thin consumer of this object, so the driver
//! underneath it (three tasks, bounded queues, the control-stream drain)
//! needs coverage that does not go through a terminal: everything here is
//! plain `Ops`, no pty, no raw mode. `tui_expect.rs` covers the terminal
//! half.
//!
//! Sessions are PTY-backed, so this file only exists on POSIX hosts.

#![cfg(unix)]

mod common;

use std::sync::mpsc;
use std::time::Duration;

use common::{Fleet, HOST_ALIAS, Sandbox};
use qsh_core::{OpError, Ops, Paths, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{EnvVar, SessionAttachReq, SessionGetReq, SessionOpenReq};

/// Wall-clock bound for one attach scenario. Every wait inside is a real
/// round trip against `qsh serve`; nothing sleeps.
const DEADLINE: Duration = Duration::from_secs(60);

/// Pause between pulls of a poll loop. Not a wait for correctness — every
/// assertion is on the value pulled — just enough to keep a regression from
/// turning a deadline into an RPC flood.
const POLL_BACKOFF: Duration = Duration::from_millis(20);

/// `Ops` bound to a sandbox's config/state pair — the same directories the
/// `qsh` binary would resolve from `QSH_CONFIG_DIR`/`QSH_STATE_DIR`, but
/// called in-process so the stream object itself is under test.
fn ops_for(sandbox: &Sandbox) -> Ops {
    Ops::new(Paths::new(sandbox.config_dir(), sandbox.state_dir()))
}

/// Run `scenario` on a worker thread and fail — loudly, with the scenario
/// named — if it has not finished within [`DEADLINE`]. The blocking `Ops`
/// API has no timeout of its own, so this is what keeps a wedged attach
/// from hanging the suite instead of failing it.
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
        // Disconnected means the scenario panicked: re-raise its panic
        // rather than reporting a timeout that did not happen.
        Err(mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("{what} produced no result"),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{what} did not finish within {DEADLINE:?}")
        }
    }
}

/// Open a session running `argv` on the fleet's host.
fn open(ops: &Ops, argv: &[&str]) -> String {
    ops.session_open(SessionOpenReq {
        host: HOST_ALIAS.to_string(),
        argv: argv.iter().map(|a| (*a).to_string()).collect(),
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

/// Attach to `session_ref`, stealing the writer lease if one is held (what
/// the interactive client does).
fn attach(ops: &Ops, session_ref: &str) -> Result<SessionAttachStream, OpError> {
    ops.session_attach(SessionAttachReq {
        session_ref: session_ref.to_string(),
        no_steal: false,
    })
}

/// Drain events until the accumulated output contains `needle`, returning
/// everything read so far. A terminal event before then is a failure: the
/// session died without saying what we asked it to.
fn read_until(stream: &mut SessionAttachStream, needle: &str) -> String {
    let mut seen = String::new();
    while let Some(event) = stream.next_event() {
        match event.expect("attach stream failed") {
            SessionEvent::Output { data_b64, .. } => {
                seen.push_str(&decode(&data_b64));
                if seen.contains(needle) {
                    return seen;
                }
            }
            SessionEvent::Exit { .. } | SessionEvent::Closed { .. } => {
                panic!("session ended before {needle:?} arrived; saw {seen:?}")
            }
            _ => {}
        }
    }
    panic!("the attach stream ended before {needle:?} arrived; saw {seen:?}")
}

/// Base64 output as (lossy) text — the terminal's own bytes, only ever
/// inspected inside a test.
fn decode(data_b64: &str) -> String {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_b64.as_bytes())
        .expect("session output is Base64");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The whole round trip the TUI depends on: attach, type, see the shell's
/// answer, and get the remote exit status.
#[test]
fn attach_round_trips_input_and_reports_the_remote_exit_code() {
    let fleet = Fleet::start();
    let ops = ops_for(&fleet.client);
    let session_ref = open(
        &ops,
        &[
            "sh",
            "-c",
            "read line; printf 'GOT:%s\\n' \"$line\"; exit 7",
        ],
    );

    let (code, signal) = with_deadline("attach round trip", move || {
        let mut stream = attach(&ops, &session_ref).expect("session.attach");
        assert_eq!(stream.session_ref(), session_ref);
        assert!(
            stream.writer_lease(),
            "an attach with no other writer holds the lease"
        );
        assert_eq!(stream.replay_from(), 0, "a fresh session replays from 0");
        assert!(
            !stream.expires_at().is_empty(),
            "the resume window has to be dated"
        );

        stream.write(b"hello\n".to_vec()).expect("write");
        let seen = read_until(&mut stream, "GOT:hello");
        // The PTY echoes what we typed *and* the shell answers, which is
        // exactly the interactive experience the TUI renders — so the echo
        // has to be there ahead of the answer, not just the answer.
        let echo = seen.find("hello").expect("the PTY echo of the input");
        let answer = seen.find("GOT:hello").expect("the shell's answer");
        assert!(echo < answer, "the PTY did not echo the input: {seen:?}");

        let status = loop {
            match stream.next_event() {
                Some(Ok(SessionEvent::Exit {
                    exit_code, signal, ..
                })) => break (exit_code, signal),
                Some(Ok(_)) => continue,
                Some(Err(err)) => panic!("attach failed: {err}"),
                None => panic!("the stream ended without an exit event"),
            }
        };
        stream.close();
        status
    });
    assert_eq!(code, Some(7), "the remote exit code reaches the client");
    assert_eq!(signal, None);
}

/// `~d` in terminal terms: `AttachHandle::detach` ends this client and
/// nothing else. The session must still be `running` and attachable again
/// — the property the whole product is built on (`docs/PRD.md` §8).
#[test]
fn detaching_leaves_the_session_running_and_re_attachable() {
    let fleet = Fleet::start();
    let ops = ops_for(&fleet.client);
    let session_ref = open(
        &ops,
        &[
            "sh",
            "-c",
            "while IFS= read -r line; do printf 'ECHO:%s\\n' \"$line\"; done",
        ],
    );

    let reattached = with_deadline("detach and re-attach", {
        let session_ref = session_ref.clone();
        move || {
            let mut stream = attach(&ops, &session_ref).expect("first attach");
            stream.write(b"one\n".to_vec()).expect("write");
            read_until(&mut stream, "ECHO:one");

            // Detach from another thread's point of view: the handle is
            // what the TUI's input pump holds.
            let handle = stream.handle();
            handle.detach();
            // The event side ends promptly — that is what unblocks the
            // TUI's main loop — and never with an exit event, because the
            // child is still alive.
            while let Some(event) = stream.next_event() {
                assert!(
                    !matches!(event, Ok(SessionEvent::Exit { .. })),
                    "detach killed the child"
                );
            }
            stream.close();

            // The session survived its client. Poll rather than sleep: the
            // host purges the connection when it sees the close frame.
            let deadline = std::time::Instant::now() + DEADLINE;
            loop {
                let session = ops
                    .session_get(SessionGetReq {
                        session_ref: session_ref.clone(),
                    })
                    .expect("session.get after detach");
                assert_eq!(session.state, "running", "detach must not end the session");
                if session.writer.is_none() {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the writer lease was never released after the detach"
                );
                // Converges on the first or second pull today (the host
                // releases the lease when it sees the connection close);
                // the pause keeps a regression a slow failure rather than
                // a minute-long RPC flood.
                std::thread::sleep(POLL_BACKOFF);
            }

            let mut stream = attach(&ops, &session_ref).expect("re-attach");
            // Resume from a saved cursor is Step 7; today a re-attach
            // replays the session from the start, which is what puts the
            // scrollback back on a reconnecting terminal.
            assert_eq!(stream.replay_from(), 0);
            // The replay is what happened *before* this attach existed:
            // both the echo of the input and the answer to it.
            let replayed = read_until(&mut stream, "ECHO:one");
            let echo = replayed
                .find("one\r\n")
                .expect("the pre-detach input echo is missing from the replay");
            let answer = replayed.find("ECHO:one").expect("the shell's answer");
            assert!(
                echo < answer,
                "the replay starts after the pre-detach input: {replayed:?}"
            );
            stream.write(b"two\n".to_vec()).expect("write");
            let seen = read_until(&mut stream, "ECHO:two");
            stream.close();
            seen
        }
    });
    assert!(reattached.contains("ECHO:two"), "{reattached:?}");
}
