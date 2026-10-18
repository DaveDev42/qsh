//! The interactive client on Windows: the real `qsh` binary in a ConPTY,
//! attached through both routes to a host whose sessions are the broker's
//! headless echo (ADR-0035 decisions 1, 2 and 5 to 8, `docs/CLI.md` §7).
//!
//! Two kinds of host stand behind the client. The `echo_*` and `console_close_*`
//! cases run against `qsh_testkit::echo_host` (`echo_host.rs`), so the bytes
//! the console shows are exactly the bytes sent, with no ConPTY rendering of
//! a real shell in between: the forward route is a QUIC listener that pins
//! the client, the reverse route is a real `qsh listen` daemon with the echo
//! host registered on it. The `pty_*` and `killed_client_*` cases run against
//! a real `qsh serve` (forward) and a real `qsh serve --to` registered on a
//! real `qsh listen` (reverse), so the client's ConPTY is attached to a
//! `cmd.exe` in the host's own ConPTY: a typed `echo` is answered by the
//! shell, `mode con` reports the size the client set, `~d` leaves the shell
//! running and `qsh attach` picks it up again. The client, its console
//! layer, the wire, the daemon and the broker's detach and resume are the
//! production ones in both kinds. The session ops against the same hosts are
//! driven in `windows_forward_e2e.rs` and `windows_reverse_e2e.rs`.
//!
//! This module is the Windows counterpart of `tui_expect.rs` (the
//! interactive client under `expectrl`) and `session_kill9.rs` (the client
//! killed with `SIGKILL`), which are unix only because `expectrl` and the
//! POSIX signal are.
//!
//! Every wait is on observable state with a deadline: the console's text, the
//! host's session counts, the process's exit.

#![cfg(windows)]

use std::ffi::OsString;
use std::time::{Duration, Instant};

use qsh_testkit::conpty::ConPtyProbe;

use crate::common::{Sandbox, poll_until};
use crate::console_probe::qsh_bin;
use crate::echo_host::{EchoForward, EchoReverse, EchoRoute};
use crate::route_cases::{
    self as cases, ForwardRoute, ReverseRoute, Route, sessions_on, strip_vt, write_to_session,
};

/// What an echo session prints first (`qsh_core::broker::ECHO_BANNER`).
const BANNER: &str = "headless echo session";

/// How long the host may take to show a session as detached or attached.
const SETTLE: Duration = Duration::from_secs(30);

/// `qsh` with `args` in a ConPTY, in `sandbox`'s environment.
pub(crate) fn spawn_qsh(sandbox: &Sandbox, args: &[&str]) -> ConPtyProbe {
    spawn_qsh_sized(sandbox, args, 120, 30)
}

/// [`spawn_qsh`] in a console of `cols` x `rows`.
pub(crate) fn spawn_qsh_sized(
    sandbox: &Sandbox,
    args: &[&str],
    cols: u16,
    rows: u16,
) -> ConPtyProbe {
    spawn_bin_sized(&qsh_bin(), sandbox, args, cols, rows)
}

/// [`spawn_qsh_sized`] for an explicit `qsh` binary: the one a release smoke
/// certifies instead of the one the tests were built with.
pub(crate) fn spawn_bin_sized(
    bin: &std::path::Path,
    sandbox: &Sandbox,
    args: &[&str],
    cols: u16,
    rows: u16,
) -> ConPtyProbe {
    let envs: Vec<(OsString, OsString)> = sandbox
        .command(&[])
        .get_envs()
        .filter_map(|(k, v)| v.map(|v| (k.to_os_string(), v.to_os_string())))
        .collect();
    let envs: Vec<(&str, &std::ffi::OsStr)> = envs
        .iter()
        .map(|(k, v)| (k.to_str().expect("env names are UTF-8"), v.as_os_str()))
        .chain([("NO_COLOR", std::ffi::OsStr::new("1"))])
        .collect();
    ConPtyProbe::spawn_with(bin, args, &envs, cols, rows)
}

/// Wait until the echo host holds `live` sessions of which `detached` have
/// no client.
fn wait_counts(route: &impl EchoRoute, live: usize, detached: usize) {
    poll_until(
        &format!("{live} live session(s), {detached} detached"),
        SETTLE,
        || {
            let counts = route.host().live_counts();
            (counts.live == live && counts.detached == detached).then_some(())
        },
    );
}

/// Attach a fresh session through `route`, send `marker`, and see the host
/// echo it back.
fn open_and_echo(route: &impl EchoRoute, marker: &str) -> ConPtyProbe {
    let mut qsh = spawn_qsh(route.client(), &[route.name()]);
    qsh.wait_text(BANNER);
    wait_counts(route, 1, 0);
    qsh.send(format!("{marker}\r").as_bytes());
    qsh.wait_text(marker);
    qsh
}

/// The one session the host holds, by the ref `qsh sessions` lists it under.
fn the_session_ref(route: &impl EchoRoute) -> String {
    let (code, listed) = route.client().json(&["sessions", route.name(), "--json"]);
    assert_eq!(code, 0, "{listed}");
    let sessions = listed["data"]["sessions"].as_array().expect("sessions");
    assert_eq!(
        sessions.len(),
        1,
        "a detach must not remove the session: {listed}"
    );
    assert_eq!(sessions[0]["state"], "running", "{listed}");
    sessions[0]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string()
}

/// Bytes typed into the console reach the host and come back as output.
fn echo_round_trip(route: &impl EchoRoute) {
    let mut qsh = open_and_echo(route, "QSH-ATTACH-ONE");
    // A second line on the same attach: the loop keeps pumping both ways.
    qsh.send(b"QSH-ATTACH-TWO\r");
    qsh.wait_text("QSH-ATTACH-TWO");

    // `~d` at the start of a line detaches; the session stays.
    qsh.send(b"~d");
    qsh.wait_text("detached");
    assert_eq!(qsh.wait_exit(), 0, "a detach exits with status 0");
    wait_counts(route, 1, 1);
}

/// Detach, then attach again from a second console: the earlier output is
/// replayed and the same session keeps echoing.
fn detach_then_attach_resumes(route: &impl EchoRoute) {
    let mut first = open_and_echo(route, "QSH-RESUME-BEFORE");
    first.send(b"~d");
    first.wait_text("detached");
    assert_eq!(first.wait_exit(), 0);
    wait_counts(route, 1, 1);

    let session_ref = the_session_ref(route);
    let mut second = spawn_qsh(route.client(), &["attach", &session_ref]);
    // Continuity, not just a session that answers: what was typed before
    // the detach comes back from the session's retained output before
    // anything new is typed.
    second.wait_text("QSH-RESUME-BEFORE");
    wait_counts(route, 1, 0);
    second.send(b"QSH-RESUME-AFTER\r");
    second.wait_text("QSH-RESUME-AFTER");

    second.send(b"~d");
    second.wait_text("detached");
    assert_eq!(second.wait_exit(), 0);
    wait_counts(route, 1, 1);
    // Still the one session: nothing opened a second.
    the_session_ref(route);
}

/// Closing the console is a hang-up: the client detaches and the session
/// stays on the host, to be attached again.
fn console_close_detaches(route: &impl EchoRoute) {
    let mut qsh = open_and_echo(route, "QSH-CLOSE-BEFORE");
    qsh.close_console();

    // The host sees a detach well inside the connection's idle timeout, so
    // the client said so on its way out instead of just vanishing.
    let started = Instant::now();
    wait_counts(route, 1, 1);
    let seen = started.elapsed();
    assert!(
        seen < Duration::from_secs(20),
        "the host learned of the detach only after {seen:?}"
    );
    qsh.wait_exit();

    let session_ref = the_session_ref(route);
    let mut again = spawn_qsh(route.client(), &["attach", &session_ref]);
    again.wait_text("QSH-CLOSE-BEFORE");
    again.send(b"QSH-CLOSE-AFTER\r");
    again.wait_text("QSH-CLOSE-AFTER");
    again.send(b"~d");
    again.wait_text("detached");
    assert_eq!(again.wait_exit(), 0);
}

#[test]
fn echo_round_trip_forward() {
    echo_round_trip(&EchoForward::start());
}

#[test]
fn echo_round_trip_reverse() {
    echo_round_trip(&EchoReverse::start());
}

#[test]
fn detach_then_attach_resumes_forward() {
    detach_then_attach_resumes(&EchoForward::start());
}

#[test]
fn detach_then_attach_resumes_reverse() {
    detach_then_attach_resumes(&EchoReverse::start());
}

#[test]
fn console_close_detaches_and_keeps_the_session() {
    console_close_detaches(&EchoForward::start());
}

#[test]
fn console_close_detaches_and_keeps_the_session_reverse() {
    console_close_detaches(&EchoReverse::start());
}

/// `user@` is an assertion, not a choice: a name that is not the serve
/// account's is refused with `UNSUPPORTED` and no session is created
/// (`docs/CLI.md` §7, fail closed). The user gate lives in the server, so
/// the echo host enforces it exactly like a real `qsh serve`.
#[test]
fn a_foreign_user_hint_is_refused_without_creating_a_session() {
    let route = EchoForward::start();
    let target = format!("qsh-no-such-user@{}", route.name());
    let mut qsh = spawn_qsh(route.client(), &[&target]);
    qsh.wait_text("user switching is not supported");
    assert_eq!(
        qsh.wait_exit(),
        255,
        "a refused hint is a qsh runtime failure (`docs/CLI.md` §4)"
    );
    let text = qsh.text();
    assert!(
        text.contains("UNSUPPORTED"),
        "the error code must reach the user: {text:?}"
    );
    assert_eq!(
        route.host().live_counts().live,
        0,
        "a refused `user@` must not leave a session behind"
    );
    let (code, listed) = route.client().json(&["sessions", route.name(), "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert!(
        listed["data"]["sessions"]
            .as_array()
            .expect("sessions")
            .is_empty(),
        "{listed}"
    );
}

// ---------------------------------------------------------------------------
// A real PTY host behind the client
// ---------------------------------------------------------------------------

/// Wait until the host holds `running` running sessions.
fn wait_running(route: &impl Route, running: usize) {
    poll_until(&format!("{running} running session(s)"), SETTLE, || {
        let sessions = sessions_on(route);
        (sessions
            .iter()
            .filter(|session| session["state"] == "running")
            .count()
            == running)
            .then_some(())
    });
}

/// The one session the host holds, by its ref. It must be running.
fn the_running_session(route: &impl Route) -> String {
    let sessions = sessions_on(route);
    assert_eq!(sessions.len(), 1, "exactly one session: {sessions:?}");
    assert_eq!(sessions[0]["state"], "running", "{sessions:?}");
    sessions[0]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string()
}

/// Filler in front of an answer. The client's own diagnostics (`qsh: the
/// writer lease moved to …`, `docs/CLI.md` §2.2) share the console with the
/// host's output, and when one lands between the host's absolute-positioned
/// frames the host's idea of the cursor row drifts from the console's, so the
/// prompt it draws next can overwrite the start of the line above. The filler
/// takes that overwrite; the tag after it stays whole.
const PAD: &str = "..............................";

/// The line that makes the shell print `tag` followed by a value it computes
/// itself, so the echo of the typed line is never taken for the answer.
pub(crate) fn say(tag: &str) -> String {
    format!("echo {PAD}{tag}%OS%\r")
}

/// What the shell prints in answer to [`say`].
pub(crate) fn said(tag: &str) -> String {
    format!("{tag}Windows_NT")
}

/// `qsh <host>` in a ConPTY of `cols` x `rows`, with the host's shell running.
fn attach_new_shell(route: &impl Route, cols: u16, rows: u16) -> ConPtyProbe {
    let qsh = spawn_qsh_sized(route.client(), &[route.host()], cols, rows);
    wait_running(route, 1);
    qsh
}

/// Leave with `~d` at the start of a line and see the client say so and
/// exit `0`. The Enter before it makes the line start certain. This relies
/// on the client keeping its own console input plain: the host's console
/// asks for win32 input mode, and a client that passed the request on would
/// receive key records instead of `~` and `d`.
pub(crate) fn detach(qsh: &mut ConPtyProbe) {
    qsh.send(b"\r~d");
    qsh.wait_text("detached");
    assert_eq!(qsh.wait_exit(), 0, "a detach exits with status 0");
}

/// Typed input reaches the host's shell and its answer comes back; ending
/// the shell ends the client with the shell's exit code.
fn pty_attach_round_trip(route: &impl Route) {
    let mut qsh = attach_new_shell(route, 120, 30);
    qsh.send(say("QSHPTYONE").as_bytes());
    qsh.wait_text(&said("QSHPTYONE"));
    // A second line on the same attach: the loop keeps pumping both ways.
    qsh.send(say("QSHPTYTWO").as_bytes());
    qsh.wait_text(&said("QSHPTYTWO"));

    qsh.send(b"exit 7\r");
    assert_eq!(
        qsh.wait_exit(),
        7,
        "the shell's exit code is the client's (`docs/CLI.md` §4)"
    );
    let text = strip_vt(&qsh.text());
    assert!(
        text.contains(&said("QSHPTYONE")),
        "the first answer stayed on the console: {text:?}"
    );
}

/// `~d` leaves the shell running; `qsh attach` from a second console replays
/// what the first one saw, and the same shell keeps answering.
fn pty_detach_then_attach_resumes(route: &impl Route) {
    let mut first = attach_new_shell(route, 120, 30);
    first.send(say("QSHBEFORE").as_bytes());
    first.wait_text(&said("QSHBEFORE"));
    detach(&mut first);
    // Detached, not ended: the shell is still running on the host.
    let session_ref = the_running_session(route);

    let mut second = spawn_qsh(route.client(), &["attach", &session_ref]);
    // Continuity, not just a shell that answers: what the first console saw
    // comes back from the session's retained output.
    second.wait_text(&said("QSHBEFORE"));
    second.send(say("QSHAFTER").as_bytes());
    second.wait_text(&said("QSHAFTER"));
    detach(&mut second);
    assert_eq!(
        the_running_session(route),
        session_ref,
        "nothing opened a second session"
    );

    // The detached shell is still the one that answers: end it from outside.
    write_to_session(route, &session_ref, "exit 0\r\n");
    let (_, exit) = cases::read_until_exit(route, &session_ref);
    assert_eq!(exit["exit_code"], 0, "{exit}");
}

/// Closing the console is a hang-up against the real shell too: the client
/// detaches on its way out, the shell keeps running, and a fresh attach
/// reaches it with what the first console saw replayed.
///
/// `lease_released` asks for the host to report the writer lease free. A
/// reverse session reached through the controller does not: its lease is
/// bound to the resident `qsh listen` daemon's reverse connection, not to
/// the CLI process (`docs/CLI.md` §6.13, "Controller 측 writer lease 결합"),
/// so the host keeps reporting the controller as writer while that
/// connection lives. There the check is that the session survives and a
/// fresh attach takes the lease over.
fn pty_console_close_detaches(route: &impl Route, lease_released: bool) {
    let mut qsh = attach_new_shell(route, 120, 30);
    // Wait for output the shell printed itself: a process that is running is
    // not necessarily attached to its console yet.
    qsh.send(say("QSHCLOSEBEFORE").as_bytes());
    qsh.wait_text(&said("QSHCLOSEBEFORE"));
    let session_ref = the_running_session(route);

    qsh.close_console();
    qsh.wait_exit();

    if lease_released {
        // The client said goodbye: the host drops the writer lease well
        // inside the connection's idle timeout.
        let started = Instant::now();
        poll_until("the host to see the detach", SETTLE, || {
            let (code, got) = route
                .client()
                .json(&["session", "get", &session_ref, "--json"]);
            (code == 0 && got["data"]["writer"].is_null()).then_some(())
        });
        let seen = started.elapsed();
        assert!(
            seen < Duration::from_secs(20),
            "the host learned of the detach only after {seen:?}"
        );
    }
    assert_eq!(the_running_session(route), session_ref);

    let mut again = spawn_qsh(route.client(), &["attach", &session_ref]);
    again.wait_text(&said("QSHCLOSEBEFORE"));
    again.send(say("QSHCLOSEAFTER").as_bytes());
    again.wait_text(&said("QSHCLOSEAFTER"));
    again.send(b"exit 0\r");
    assert_eq!(again.wait_exit(), 0);
}

/// What `mode con` reports as `[lines, columns]`, taken after `marker` has
/// printed twice: the console the host's shell sees is the one the client
/// asked for.
fn console_size(qsh: &mut ConPtyProbe, marker: &str) -> Vec<u32> {
    let end = format!("{marker}END");
    qsh.send(format!("echo {PAD}{marker}%OS%&mode con&echo {PAD}{end}%OS%\r").as_bytes());
    let text = strip_vt(&qsh.wait_text(&said(&end)));
    // The echoed command line holds the marker without the value; the
    // answer starts at the first marker that has one.
    let (_, answer) = text
        .split_once(&said(marker))
        .expect("the marker was answered");
    // The labels are localised and the order is not: `mode con` prints the
    // buffer's lines, then its columns.
    answer
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.rsplit_once([':', '\u{ff1a}'])?;
            rest.trim().parse().ok()
        })
        .take(2)
        .collect()
}

/// The client's console size reaches the host's pseudo-console at attach and
/// again when the client's console is resized.
fn pty_resize_propagates(route: &impl Route) {
    let mut qsh = attach_new_shell(route, 100, 30);
    assert_eq!(
        console_size(&mut qsh, "QSHSIZEA"),
        [30, 100],
        "the attach's size"
    );
    qsh.resize(90, 25);
    // The resize travels asynchronously: ask until the host's console agrees
    // or the deadline passes.
    let mut round = 0;
    poll_until("the host console to take the resized size", SETTLE, || {
        round += 1;
        (console_size(&mut qsh, &format!("QSHSIZEB{round}")) == [25, 90]).then_some(())
    });
    qsh.send(b"exit 0\r");
    assert_eq!(qsh.wait_exit(), 0);
}

/// SC5 (`docs/PRD.md` §15): the client dies the way clients die, with
/// `TerminateProcess` and no goodbye. The session stays on the host, keeps
/// its shell and its retained output, and another console attaches to it.
fn killed_client_leaves_the_session_running(route: &impl Route) {
    let mut doomed = attach_new_shell(route, 120, 30);
    doomed.send(say("QSHKILLED").as_bytes());
    doomed.wait_text(&said("QSHKILLED"));
    doomed.kill();
    doomed.wait_exit();

    // The host learns of the death only by timeout, and the shell does not
    // care: it is running now and answers a writer that is not the client.
    let session_ref = the_running_session(route);
    write_to_session(route, &session_ref, &format!("{}\n", say("QSHALIVE")));
    let seen = cases::read_until_output(route, &session_ref, &said("QSHALIVE"));
    assert!(
        seen.contains(&said("QSHKILLED")),
        "the retained output has what the dead client had seen: {seen:?}"
    );

    // Another console takes the session over, replay included.
    let mut again = spawn_qsh(route.client(), &["attach", &session_ref]);
    again.wait_text(&said("QSHALIVE"));
    again.send(say("QSHAGAIN").as_bytes());
    again.wait_text(&said("QSHAGAIN"));
    again.send(b"exit 0\r");
    assert_eq!(again.wait_exit(), 0);
}

#[test]
fn pty_attach_round_trip_forward() {
    pty_attach_round_trip(&ForwardRoute::start());
}

#[test]
fn pty_attach_round_trip_reverse() {
    pty_attach_round_trip(&ReverseRoute::start());
}

#[test]
fn pty_detach_then_attach_resumes_forward() {
    pty_detach_then_attach_resumes(&ForwardRoute::start());
}

#[test]
fn pty_detach_then_attach_resumes_reverse() {
    pty_detach_then_attach_resumes(&ReverseRoute::start());
}

#[test]
fn pty_resize_propagates_forward() {
    pty_resize_propagates(&ForwardRoute::start());
}

#[test]
fn pty_resize_propagates_reverse() {
    pty_resize_propagates(&ReverseRoute::start());
}

#[test]
fn killed_client_leaves_the_session_running_forward() {
    killed_client_leaves_the_session_running(&ForwardRoute::start());
}

#[test]
fn killed_client_leaves_the_session_running_reverse() {
    killed_client_leaves_the_session_running(&ReverseRoute::start());
}

#[test]
fn pty_console_close_detaches_and_keeps_the_session_forward() {
    pty_console_close_detaches(&ForwardRoute::start(), true);
}

#[test]
fn pty_console_close_detaches_and_keeps_the_session_reverse() {
    pty_console_close_detaches(&ReverseRoute::start(), false);
}
