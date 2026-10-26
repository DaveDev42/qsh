//! The Windows console layer and the invite-code prompt, driven for real in a
//! ConPTY (ADR-0035 decisions 4-8 and 11).
//!
//! `qsh-console-probe` (`crates/qsh-testkit/src/bin/qsh-console-probe/`) runs
//! the client's own `tui/windows.rs` inside a pseudo-console and reports
//! what the console did; `qsh` itself is run for the prompt tests. Every
//! test waits on observable state with a deadline (the harness in
//! `qsh_testkit::conpty`), never on a fixed sleep.
//!
//! The pure parts (mode arithmetic, restore idempotence, the resize poller's
//! clock) are unit-tested on every platform in `tui/windows/tests.rs`; the
//! VT-floor refusal before `session.open` is
//! `tui::session_loop::tests::vt_unavailable_is_unsupported_before_session_open`,
//! and the `TERM` default is `tui::tests::session_open_term_defaults_to_xterm_256color_when_term_is_unset`.
//! What only a real console can show is here.
#![cfg(windows)]

use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use qsh_testkit::conpty::{ConPtyProbe, Record, parse_records, probe_bin};

use crate::common::Sandbox;

const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
const ENABLE_LINE_INPUT: u32 = 0x0002;
const ENABLE_ECHO_INPUT: u32 = 0x0004;
const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;

/// A code the parser accepts character by character but rejects as too
/// short, so `qsh trust accept` fails right after the prompt without a
/// network round trip, and with a message that does not repeat the code.
const CODE: &str = "abcdefgh-jkmnpqrs";
/// Pieces of [`CODE`] that must never reach the console output.
const CODE_PIECES: [&str; 2] = ["abcdefgh", "jkmnpqrs"];

/// The `qsh` under test: the cargo-built one, or `qsh.exe` next to the test
/// executable when the tests were built elsewhere and run natively (the
/// cross-compiled run under WSL, where `CARGO_BIN_EXE_qsh` is a Linux path).
pub(crate) fn qsh_bin() -> PathBuf {
    let built = PathBuf::from(env!("CARGO_BIN_EXE_qsh"));
    if built.is_file() {
        return built;
    }
    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().expect("test executable directory");
    [dir.join("qsh.exe"), dir.join("..").join("qsh.exe")]
        .into_iter()
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("no qsh.exe next to {}", exe.display()))
}

fn field(record: &Record, index: usize) -> &str {
    record
        .fields
        .get(index)
        .unwrap_or_else(|| panic!("record {record:?} has no field {index}"))
}

/// `(input, output)` modes of a `mode-*` record.
fn modes(record: &Record) -> (String, String) {
    let value = |name: &str| {
        record
            .fields
            .iter()
            .find_map(|f| f.strip_prefix(name))
            .unwrap_or_else(|| panic!("record {record:?} has no {name}"))
            .to_string()
    };
    (value("in="), value("out="))
}

fn parse_mode(text: &str) -> u32 {
    u32::from_str_radix(text.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("{text:?} is not a console mode"))
}

/// Run the probe's `raw` scenario (with `args`) in a 100x30 ConPTY.
fn spawn_raw(args: &[&str], env: &[(&str, &std::ffi::OsStr)]) -> ConPtyProbe {
    let mut argv = vec!["raw"];
    argv.extend_from_slice(args);
    ConPtyProbe::spawn_with(&probe_bin(), &argv, env, 100, 30)
}

/// The hex of every byte the probe reads until it has read `0x04`.
fn read_until_eot(probe: &mut ConPtyProbe) -> String {
    let mut seen = String::new();
    while !seen.ends_with("04") {
        let record = probe.wait_record("bytes");
        seen.push_str(field(&record, 0));
    }
    seen
}

#[test]
fn conpty_raw_mode_reads_input_bytes_unprocessed() {
    let mut probe = spawn_raw(&[], &[]);
    let initial = modes(&probe.wait_record("mode-initial"));
    let raw = modes(&probe.wait_record("mode-raw"));
    assert_eq!(field(&probe.wait_record("raw"), 0), "true");
    probe.wait_record("ready");

    // Input side of decision 5.
    let input = parse_mode(&raw.0);
    assert_eq!(
        input & (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT),
        0,
        "line, echo and processed input are off: {raw:?}"
    );
    assert_ne!(input & ENABLE_VIRTUAL_TERMINAL_INPUT, 0, "VT input is on");
    // Output side of decision 5.
    let output = parse_mode(&raw.1);
    assert_eq!(
        output & (ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN),
        ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
    );
    assert_ne!(initial, raw, "raw mode changed something");

    // `h`, `i`, Ctrl-C, Enter, Ctrl-D: Ctrl-C is a byte, not a signal, and
    // nothing is translated.
    probe.send(b"hi\x03\r\x04");
    assert_eq!(read_until_eot(&mut probe), "6869030d04");
    probe.wait_record("done");
    assert_eq!(probe.wait_exit(), 0);
}

/// A non-BMP character typed into a raw console reaches the reader as its
/// UTF-8 bytes (campaign W3a: `ReadFile` under code page 65001 turned each
/// half of the surrogate pair into U+FFFD).
#[test]
fn conpty_raw_mode_reads_non_bmp_text_as_utf8() {
    let mut probe = spawn_raw(&[], &[]);
    probe.wait_record("ready");

    probe.send("한글 😀\x04".as_bytes());
    let expected: String = "한글 😀\x04".bytes().map(|b| format!("{b:02x}")).collect();
    assert!(
        expected.contains("f09f9880"),
        "the expectation holds the emoji bytes"
    );
    assert_eq!(read_until_eot(&mut probe), expected);
    probe.wait_record("done");
    assert_eq!(probe.wait_exit(), 0);
}

#[test]
fn conpty_resize_poll_fires_once_per_size_change() {
    let mut probe = spawn_raw(&[], &[]);
    let size = probe.wait_record("size");
    assert_eq!((field(&size, 0), field(&size, 1)), ("100", "30"));
    probe.wait_record("ready");

    probe.resize(120, 40);
    let first = probe.wait_record("resize");
    assert_eq!(
        (field(&first, 0), field(&first, 1), field(&first, 2)),
        ("120", "40", "1")
    );

    // The same size again is not a change; a different one is. ConPTY
    // repaints the screen on a resize, so the first record can come through
    // the stream again: skip copies of it by its callback count, which a
    // callback for the repeated size would have advanced.
    probe.resize(120, 40);
    probe.resize(90, 25);
    let second = loop {
        let record = probe.wait_record("resize");
        if field(&record, 2) != "1" {
            break record;
        }
    };
    assert_eq!(
        (field(&second, 0), field(&second, 1), field(&second, 2)),
        ("90", "25", "2"),
        "the repeated size produced no callback"
    );

    probe.send(b"\x04");
    let done = probe.wait_record("done");
    assert_eq!(field(&done, 0), "resizes=2");
    assert_eq!(probe.wait_exit(), 0);
}

#[test]
fn conpty_console_modes_are_restored_after_normal_exit() {
    let mut probe = spawn_raw(&[], &[]);
    let initial = modes(&probe.wait_record("mode-initial"));
    probe.wait_record("ready");
    probe.send(b"\x04");
    let last = modes(&probe.wait_record("mode-final"));
    assert_eq!(last, initial, "the guard put every bit back");
    assert_eq!(probe.wait_exit(), 0);
}

#[test]
fn conpty_console_modes_are_restored_after_panic() {
    let mut probe = spawn_raw(&["--panic"], &[]);
    let initial = modes(&probe.wait_record("mode-initial"));
    let raw = modes(&probe.wait_record("mode-raw"));
    assert_ne!(raw, initial);
    // Reported while the guard is still alive: the panic hook did this.
    let after = modes(&probe.wait_record("mode-after-panic"));
    assert_eq!(after, initial, "the panic hook restored the console");
    let pages_initial = probe.wait_record("cp-initial");
    let pages_after = probe.wait_record("cp-after-panic");
    assert_eq!(pages_after.fields, pages_initial.fields);
    assert_eq!(probe.wait_exit(), 0);
}

// ConPTY cannot deliver a real `CTRL_CLOSE_EVENT` (closing the pseudoconsole
// ends the client without a handler round trip), so the probe calls the
// handler body, `on_console_event`, itself. What this pins is the restore
// and hang-up path for the close family. The registered
// `SetConsoleCtrlHandler` itself is exercised by the real `CTRL_BREAK` in
// `conpty_console_modes_are_restored_after_a_break_event`.
#[test]
fn conpty_console_modes_are_restored_after_a_close_event() {
    let mut probe = spawn_raw(&["--close"], &[]);
    let initial = modes(&probe.wait_record("mode-initial"));
    let raw = modes(&probe.wait_record("mode-raw"));
    assert_ne!(raw, initial);
    probe.wait_record("hangup");
    let after = modes(&probe.wait_record("mode-after-event"));
    assert_eq!(after, initial, "the control handler restored the console");
    let pages_initial = probe.wait_record("cp-initial");
    let pages_after = probe.wait_record("cp-after-event");
    assert_eq!(pages_after.fields, pages_initial.fields);
    assert_eq!(probe.wait_exit(), 0);
}

#[test]
fn conpty_console_modes_are_restored_after_a_break_event() {
    let mut probe = spawn_raw(&["--break"], &[]);
    let initial = modes(&probe.wait_record("mode-initial"));
    probe.wait_record("ready");
    probe.wait_record("hangup");
    let after = modes(&probe.wait_record("mode-after-event"));
    assert_eq!(after, initial, "a real CTRL_BREAK restored the console");
    assert_eq!(probe.wait_exit(), 0);
}

#[test]
fn conpty_code_page_is_restored_on_exit() {
    // Start from a code page that is not UTF-8.
    let mut probe = spawn_raw(&[], &[("QSH_PROBE_INITIAL_CP", "850".as_ref())]);
    let initial = probe.wait_record("cp-initial");
    assert_eq!(initial.fields, ["in=850", "out=850"]);
    let raw = probe.wait_record("cp-raw");
    assert_eq!(raw.fields, ["in=65001", "out=65001"], "raw mode is UTF-8");
    probe.wait_record("ready");
    probe.send(b"\x04");
    let last = probe.wait_record("cp-final");
    assert_eq!(last.fields, initial.fields);
    assert_eq!(probe.wait_exit(), 0);
}

#[test]
fn non_console_stdin_passes_bytes_verbatim_on_windows() {
    let mut child = Command::new(probe_bin())
        .arg("raw")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the probe");
    // Control bytes and an escape sequence: nothing is interpreted, nothing
    // is added.
    let input: &[u8] = b"a\x03\x1b[A\r\nz\x04";
    child
        .stdin
        .take()
        .expect("probe stdin")
        .write_all(input)
        .expect("write to the probe");
    let output = child.wait_with_output().expect("probe output");
    assert!(output.status.success(), "{output:?}");

    let records = parse_records(&output.stdout);
    let first = |key: &str| {
        records
            .iter()
            .find(|r| r.key == key)
            .unwrap_or_else(|| panic!("no {key} record in {records:?}"))
    };
    assert_eq!(field(first("console"), 0), "in=false");
    assert_eq!(
        field(first("raw"), 0),
        "false",
        "no raw mode without a console"
    );
    let hex: String = records
        .iter()
        .filter(|r| r.key == "bytes")
        .map(|r| field(r, 0))
        .collect();
    assert_eq!(hex, "61031b5b410d0a7a04");
}

/// Spawn `qsh` in a ConPTY with the sandbox's environment.
fn spawn_qsh(sandbox: &Sandbox, args: &[&str]) -> ConPtyProbe {
    let envs: Vec<(&str, OsString)> = vec![
        ("QSH_CONFIG_DIR", sandbox.config_dir().into()),
        ("QSH_STATE_DIR", sandbox.state_dir().into()),
        ("USERPROFILE", sandbox.home_dir().into()),
        ("HOME", sandbox.home_dir().into()),
        ("NO_COLOR", "1".into()),
    ];
    let envs: Vec<(&str, &std::ffi::OsStr)> =
        envs.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
    ConPtyProbe::spawn_with(&qsh_bin(), args, &envs, 120, 30)
}

fn assert_code_never_shown(text: &str) {
    for piece in CODE_PIECES {
        assert!(
            !text.contains(piece),
            "the typed invite code reached the console: {text:?}"
        );
    }
}

/// The control for the tests below: with echo on, the harness does see what
/// is typed, so its absence there means something.
#[test]
fn conpty_harness_sees_typed_text_when_echo_is_on() {
    let mut probe = ConPtyProbe::spawn_with(&probe_bin(), &["line"], &[], 100, 30);
    probe.send(b"visible-text\r");
    probe.wait_text("visible-text");
    probe.wait_record("line-done");
    assert_eq!(probe.wait_exit(), 0);
}

#[test]
fn invite_code_prompt_never_echoes_under_conpty() {
    let sandbox = Sandbox::with_bin(&qsh_bin());
    let mut qsh = spawn_qsh(&sandbox, &["trust", "accept", "127.0.0.1:1"]);
    qsh.wait_text(qsh_core::ops::INVITE_CODE_PROMPT);
    qsh.send(format!("{CODE}\r").as_bytes());
    // The failure text comes after the typed line was handled, so the
    // stream has passed the place where an echo would be.
    let text = qsh.wait_text("symbols, expected");
    assert_code_never_shown(&text);
    assert_ne!(qsh.wait_exit(), 0, "a malformed code is refused");
    assert_code_never_shown(&qsh.text());
}

#[test]
fn code_stdin_from_a_console_suppresses_echo() {
    let sandbox = Sandbox::with_bin(&qsh_bin());
    let mut qsh = spawn_qsh(
        &sandbox,
        &["trust", "accept", "127.0.0.1:1", "--code-stdin"],
    );
    // `--code-stdin` reads to end of input; on a console that is Ctrl-Z at
    // the start of a line, then Enter.
    qsh.send(format!("{CODE}\r").as_bytes());
    qsh.send(b"\x1a\r");
    let text = qsh.wait_text("symbols, expected");
    assert_code_never_shown(&text);
    assert_ne!(qsh.wait_exit(), 0);
    assert_code_never_shown(&qsh.text());
}

#[test]
fn invite_code_prompt_restores_the_console_mode() {
    let sandbox = Sandbox::with_bin(&qsh_bin());
    let qsh = qsh_bin();
    let envs: Vec<(&str, OsString)> = vec![
        ("QSH_CONFIG_DIR", sandbox.config_dir().into()),
        ("QSH_STATE_DIR", sandbox.state_dir().into()),
        ("USERPROFILE", sandbox.home_dir().into()),
        ("HOME", sandbox.home_dir().into()),
        ("NO_COLOR", "1".into()),
    ];
    let envs: Vec<(&str, &std::ffi::OsStr)> =
        envs.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
    let qsh_path = qsh.to_string_lossy().into_owned();
    let mut probe = ConPtyProbe::spawn_with(
        &probe_bin(),
        &["wrap", &qsh_path, "trust", "accept", "127.0.0.1:1"],
        &envs,
        120,
        30,
    );
    let initial = modes(&probe.wait_record("mode-initial"));
    probe.wait_text(qsh_core::ops::INVITE_CODE_PROMPT);
    probe.send(format!("{CODE}\r").as_bytes());
    probe.wait_record("child-exit");
    let last = modes(&probe.wait_record("mode-final"));
    assert_eq!(last, initial, "echo input is back as it was");
    assert_code_never_shown(&probe.text());
    // The echo bit is on again (the cooked console starts with it on).
    assert_ne!(parse_mode(&last.0) & ENABLE_ECHO_INPUT, 0);
}
