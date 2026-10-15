//! The Windows console contract, observed from inside a ConPTY.
//!
//! Each test runs `qsh-console-probe` in a pseudo-console (`conpty.rs`) and
//! reads back what the console did. Nothing here is Windows-specific logic
//! of qsh; it pins the console behavior the interactive client's raw mode
//! relies on (`docs/design/testing.md`): which mode bits stick, that
//! control bytes and UTF-8 arrive untouched, that a size change is seen,
//! and that the original modes come back.

#![cfg(windows)]

use super::conpty::{ConPtyProbe, probe_bin};

const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
const ENABLE_LINE_INPUT: u32 = 0x0002;
const ENABLE_ECHO_INPUT: u32 = 0x0004;
const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;

/// `in=0x.. out=0x..` fields as numbers.
fn modes(fields: &[String]) -> (u32, u32) {
    let value = |prefix: &str| {
        let field = fields
            .iter()
            .find_map(|f| f.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("no {prefix} field in {fields:?}"));
        u32::from_str_radix(field.trim_start_matches("0x"), 16).expect("a hex mode")
    };
    (value("in="), value("out="))
}

fn start(cols: u16, rows: u16) -> ConPtyProbe {
    ConPtyProbe::spawn(&probe_bin(), cols, rows)
}

#[test]
fn probe_reports_its_initial_size_under_conpty() {
    let mut probe = start(100, 30);
    let size = probe.wait_record("size");
    assert_eq!(size.fields, ["100", "30"]);
}

/// The raw modes the console accepted are the ones the pure functions ask
/// for: the three input bits off, VT input on, VT output on and newline
/// auto-return off.
#[test]
fn probe_raw_mode_sticks_in_the_console() {
    let mut probe = start(100, 30);
    let (in0, _) = modes(&probe.wait_record("mode-initial").fields);
    let (raw_in, raw_out) = modes(&probe.wait_record("mode-raw").fields);
    assert_eq!(
        raw_in & (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT),
        0,
        "initial input mode {in0:#x}, raw {raw_in:#x}"
    );
    assert_eq!(
        raw_in & ENABLE_VIRTUAL_TERMINAL_INPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT
    );
    assert_eq!(
        raw_out & (ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN),
        ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
    );
}

/// In raw mode a typed `^C` is the byte `0x03`, not a console signal, and
/// UTF-8 input arrives as its bytes.
#[test]
fn probe_raw_input_arrives_verbatim() {
    let mut probe = start(100, 30);
    probe.wait_record("ready");
    probe.send(b"ab\x03\xc3\xa9\r\x04");
    // The console may deliver the bytes in more than one read.
    let mut got = String::new();
    while !got.ends_with("04") {
        got.push_str(&probe.wait_record("bytes").fields.concat());
    }
    assert_eq!(got, "616203c3a90d04");
}

/// One change of the console size is one `resize` callback, and the probe
/// restores the modes it found.
#[test]
fn probe_sees_one_resize_and_restores_the_modes() {
    let mut probe = start(100, 30);
    let initial = modes(&probe.wait_record("mode-initial").fields);
    probe.wait_record("ready");
    probe.resize(120, 40);
    let resize = probe.wait_record("resize");
    assert_eq!(resize.fields, ["120", "40", "1"]);

    probe.send(b"\x04");
    let end = probe.wait_record("done");
    assert_eq!(end.fields, ["resizes=1"]);
    assert_eq!(modes(&probe.wait_record("mode-final").fields), initial);
    assert_eq!(probe.wait_exit(), 0);
}
