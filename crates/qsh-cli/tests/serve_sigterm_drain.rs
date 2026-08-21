//! **L5 real-process** — `qsh serve`'s SIGTERM graceful drain (`docs/CLI.md`
//! §6.12 "(M2, ADR-0003)", `PLAN.md` Step 3.5 PR ①).
//!
//! The audit this step repays (`docs/ROADMAP.md` M2 사후 감사, 2026-08-21)
//! found the opposite of this file's name: `qsh serve` killed by `SIGTERM`
//! left its PTY children running — real orphans, empirically confirmed. The
//! fix lives in `Server::drain`/`Broker::close_all`; this is the one test in
//! the tree that proves it against a **real OS process**, the same reason
//! `session_kill9.rs` has to be here rather than in `qsh-testkit`:
//! `CARGO_BIN_EXE_qsh` only exists in the tests of the crate that builds it,
//! and a signal delivered to an in-process `tokio::signal` future is not the
//! same fact as a signal delivered to a process this test does not own.
//!
//! Three things `docs/CLI.md` promises about the same `SIGTERM`, checked
//! against the same run:
//!
//! 1. `qsh serve` exits `0` within a bound (§6.12: it drains, it does not
//!    hang or crash).
//! 2. Nothing answers for the session's child once it has (the audit's own
//!    orphan check — SC5's mirror image: here the process must **not**
//!    survive its host).
//! 3. An attached consumer sees `session.closed{reason:"closed"}` as the
//!    last event on its stream (§6.4) — the drain does not just kill
//!    children, it says so on the wire first.

#![cfg(unix)]

mod common;

use std::sync::mpsc;
use std::time::Duration;

use common::{Fleet, HOST_ALIAS, Sandbox};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use qsh_core::{Ops, Paths, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{EnvVar, SessionAttachReq, SessionOpenReq};

/// Wall-clock bound for the whole scenario (spawn, attach, signal, drain,
/// teardown). Every wait inside is a real round trip or a real process
/// exit, never a sleep standing in for one — this is only the "declare it
/// broken" backstop, mirroring `attach_ops.rs`'s `DEADLINE`.
const DEADLINE: Duration = Duration::from_secs(60);

/// Bound on the drain itself: SIGTERM to process exit. The default
/// `[serve].close_grace_ms` (5000) only matters if the child ignores a
/// signal partway up the SIGHUP→TERM→KILL ladder (`docs/CLI.md` §6.7); this
/// session's child does not, so the real drain is fast. Generous margin
/// over the worst case (two grace periods, ~10 s) rather than a tight bound,
/// so scheduler contention on a loaded CI box cannot turn a real pass into a
/// flake.
const DRAIN_BOUND: Duration = Duration::from_secs(30);

/// Prefix the session's child prints, carrying its own pid, so this test
/// can ask the operating system — not the broker — whether it is still
/// there.
const PID_PREFIX: &str = "QSHPID=";

/// The session's child: announce its pid, then sit on something that would
/// still be running if nobody cleaned it up. `exec` keeps the announced pid
/// (no fork), matching `session_kill9.rs`'s own producer.
fn child_script() -> String {
    format!("printf '{PID_PREFIX}%s\\n' $$\nexec sleep 600\n")
}

/// `Ops` bound to a sandbox's config/state pair, called in-process —
/// exactly `attach_ops.rs`'s helper of the same name.
fn ops_for(sandbox: &Sandbox) -> Ops {
    Ops::new(Paths::new(sandbox.config_dir(), sandbox.state_dir()))
}

/// Run `scenario` on a worker thread and fail — loudly — if it has not
/// finished within [`DEADLINE`]. `Ops`'s attach API blocks the calling
/// thread with no timeout of its own, so this is what keeps a wedged drain
/// from hanging the suite instead of failing it (`attach_ops.rs` precedent).
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

/// Base64-decode one `session.output` chunk.
fn decode(data_b64: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(data_b64.as_bytes())
        .expect("session output is Base64")
}

/// Read events off `stream` until the child's pid line has arrived, and
/// return the pid. The replay always starts at offset 0 (`Ops::session_attach`
/// sends `last_output_seq: 0`), so this also exercises the ordinary
/// attach-then-replay path, not a special case for this test.
fn read_pid(stream: &mut SessionAttachStream) -> i32 {
    let mut rendered = Vec::new();
    loop {
        let event = stream
            .next_event()
            .expect("attach stream ended before the child announced its pid")
            .expect("attach stream failed before the child announced its pid");
        if let SessionEvent::Output { data_b64, .. } = event {
            rendered.extend_from_slice(&decode(&data_b64));
        }
        if let Some(line) = std::str::from_utf8(&rendered)
            .ok()
            .and_then(|text| text.lines().find(|line| line.starts_with(PID_PREFIX)))
        {
            return line
                .trim_start_matches(PID_PREFIX)
                .trim()
                .parse()
                .unwrap_or_else(|err| panic!("child pid line {line:?} did not parse: {err}"));
        }
    }
}

/// Read events off `stream` until `session.closed` arrives, and return its
/// `reason`. The drain signals the child (SIGHUP) before removing the
/// session, so a `session.exit` for the child's own death legitimately
/// precedes it (`docs/CLI.md` §6.7/§6.4) — expected, and skipped here. The
/// stream ending without ever delivering `session.closed` is the one
/// failure this exists to catch.
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

/// **PLAN.md Step 3.5 PR ①.** `SIGTERM` a real `qsh serve` with a live PTY
/// child and an attached consumer: the process exits `0`, the consumer sees
/// `session.closed{reason:"closed"}`, and — the audit's own check — nothing
/// answers for the child afterwards.
#[test]
fn sigterm_drains_the_session_and_leaves_no_orphan() {
    with_deadline("sigterm drain", || {
        let mut fleet = Fleet::start();
        let ops = ops_for(&fleet.client);

        let session_ref = ops
            .session_open(SessionOpenReq {
                host: HOST_ALIAS.to_string(),
                argv: vec!["sh".to_string(), "-c".to_string(), child_script()],
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
            .session_ref;

        let mut stream = ops
            .session_attach(SessionAttachReq {
                session_ref: session_ref.clone(),
                no_steal: false,
            })
            .expect("session.attach");

        // ---- a real child, whose pid we can ask the OS about ----
        let child_pid = read_pid(&mut stream);
        let child = Pid::from_raw(child_pid);
        assert!(
            kill(child, None).is_ok(),
            "the session's child must be alive before SIGTERM"
        );

        // ---- SIGTERM the real `qsh serve` process ----
        fleet.serve.signal(Signal::SIGTERM);

        // (a) it exits 0 within a bound — drained, not crashed, not hung.
        let status = fleet
            .serve
            .wait_timeout(DRAIN_BOUND)
            .unwrap_or_else(|| panic!("qsh serve did not exit within {DRAIN_BOUND:?} of SIGTERM"));
        assert!(
            status.success(),
            "qsh serve exited {status:?} on SIGTERM, not 0"
        );

        // (c) the attached consumer saw session.closed{reason:"closed"}
        // (§6.4) — sent, per `Server::run`'s ordering, before the listener
        // (and so this connection) closes.
        assert_eq!(
            read_closed_reason(&mut stream),
            "closed",
            "docs/CLI.md §6.4: SIGTERM drain closes are reason \"closed\""
        );

        // (b) — the audit's own check — zero processes remain in the
        // session's process group once the drained serve has exited. The
        // child is a process-group leader (`setsid`, architecture.md §4)
        // with no forked children of its own, so its own liveness *is* the
        // group's.
        assert!(
            kill(child, None).is_err(),
            "the session's child outlived the drained `qsh serve` — orphan (audit A1)"
        );

        // stdout purity holds even through this exit path (`docs/CLI.md`
        // §2.2/§6.12: `qsh serve` writes zero bytes to stdout, ever).
        let output = fleet.serve.captured();
        assert!(
            output.stdout.is_empty(),
            "qsh serve wrote to stdout: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );

        stream.close();
    });
}
