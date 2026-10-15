//! The ConPTY harness and the console probe, end to end.
//!
//! One test: it shows the harness starts the probe in a pseudo-console of
//! the size it asked for and reads the probe's records back. What the
//! console layer does with raw input, resize, restore and the
//! invitation-code prompt is in `qsh-cli`'s `tests/it/console_probe.rs`.

#![cfg(windows)]

use qsh_testkit::conpty::{ConPtyProbe, probe_bin};

#[test]
fn probe_reports_its_initial_size_under_conpty() {
    let mut probe = ConPtyProbe::spawn(&probe_bin(), 100, 30);
    let size = probe.wait_record("size");
    assert_eq!(size.fields, ["100", "30"]);
}
