//! The interactive client on Windows: the real `qsh` binary in a ConPTY,
//! attached through both routes to a host whose sessions are the broker's
//! headless echo (ADR-0035 decisions 1, 2 and 5 to 8, `docs/CLI.md` §7).
//!
//! A Windows host answers `UNSUPPORTED` to PTY sessions until the Windows host
//! role lands, so the host behind the client is `qsh_testkit::echo_host`
//! (`echo_host.rs`): the forward route is a QUIC listener that pins the
//! client, the reverse route is a real `qsh listen` daemon with the echo host
//! registered on it. The client, its console layer, the wire, the daemon and
//! the broker's detach and resume are the production ones. The same cases
//! then run against a real `qsh serve` once the host has a PTY.
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

/// What an echo session prints first (`qsh_core::broker::ECHO_BANNER`).
const BANNER: &str = "headless echo session";

/// How long the host may take to show a session as detached or attached.
const SETTLE: Duration = Duration::from_secs(30);

/// `qsh` with `args` in a ConPTY, in `sandbox`'s environment.
pub(crate) fn spawn_qsh(sandbox: &Sandbox, args: &[&str]) -> ConPtyProbe {
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
    ConPtyProbe::spawn_with(&qsh_bin(), args, &envs, 120, 30)
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
