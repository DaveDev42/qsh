//! `qsh-signal-probe`: a console program that reports which Windows event a
//! session signal turned into (ADR-0035 decision 22), and what a test needs
//! to read its reports.
//!
//! The probe runs inside a session's pseudo-console. It waits for the first
//! console control event or session signal event, writes one record for it
//! (`<<QSH-SIGNAL event NAME>>`, and a line `NAME` in the `--report` file
//! when one is given), and ends with the exit code that stands for the event.
//! A test asserts on that exit code in `session.exit`, so the evidence is
//! what the program received and not what the host says it sent. The modes
//! and the exact records are in the binary's own documentation
//! (`src/bin/qsh-signal-probe.rs`).
//!
//! The probe only builds for Windows; elsewhere the binary is a stub, and the
//! constants below stay available so the tables are checked on every leg.

use std::path::PathBuf;

/// The probe executable (`QSH_SIGNAL_PROBE_BIN`, next to the test executable,
/// or one `cargo build`).
pub fn bin() -> PathBuf {
    crate::testbin::locate("qsh-signal-probe", "QSH_SIGNAL_PROBE_BIN")
}

/// The record the probe prints once its handlers are installed and its
/// events are open. A test sends a signal only after it has seen this: a
/// process that is listed but has not yet attached to the console or
/// installed its handlers would miss the event.
pub const READY: &str = "<<QSH-SIGNAL ready>>";

/// The record for an event the probe received.
pub fn event_record(name: &str) -> String {
    format!("<<QSH-SIGNAL event {name}>>")
}

/// One event the probe can receive, the name it reports and the exit code
/// that stands for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeEvent {
    pub name: &'static str,
    pub exit_code: i32,
}

/// `CTRL_C_EVENT`.
pub const CTRL_C: ProbeEvent = ProbeEvent {
    name: "ctrl-c",
    exit_code: 10,
};
/// `CTRL_BREAK_EVENT`.
pub const CTRL_BREAK: ProbeEvent = ProbeEvent {
    name: "ctrl-break",
    exit_code: 11,
};
/// `CTRL_CLOSE_EVENT`, which `ClosePseudoConsole` sends.
pub const CTRL_CLOSE: ProbeEvent = ProbeEvent {
    name: "ctrl-close",
    exit_code: 12,
};
/// `CTRL_LOGOFF_EVENT`.
pub const CTRL_LOGOFF: ProbeEvent = ProbeEvent {
    name: "ctrl-logoff",
    exit_code: 13,
};
/// `CTRL_SHUTDOWN_EVENT`.
pub const CTRL_SHUTDOWN: ProbeEvent = ProbeEvent {
    name: "ctrl-shutdown",
    exit_code: 14,
};
/// The session's `Usr1` event (`QSH_SIGNAL_EVENT_USR1`).
pub const USR1: ProbeEvent = ProbeEvent {
    name: "usr1",
    exit_code: 21,
};
/// The session's `Usr2` event (`QSH_SIGNAL_EVENT_USR2`).
pub const USR2: ProbeEvent = ProbeEvent {
    name: "usr2",
    exit_code: 22,
};
/// The exit code when no event arrived within the probe's own deadline.
pub const NO_EVENT_EXIT_CODE: i32 = 99;

/// Every event the probe can report.
pub const ALL: [ProbeEvent; 7] = [
    CTRL_C,
    CTRL_BREAK,
    CTRL_CLOSE,
    CTRL_LOGOFF,
    CTRL_SHUTDOWN,
    USR1,
    USR2,
];

/// The event ADR-0035 decision 22 says `signal` (`HUP`, `INT`, `QUIT`,
/// `TERM`, `USR1`, `USR2`, `KILL`, with or without `SIG`, any case) is
/// delivered as. `KILL` is `None`: it ends the processes and no program
/// receives it.
pub fn event_for_signal(signal: &str) -> Option<ProbeEvent> {
    let upper = signal.to_ascii_uppercase();
    match upper.strip_prefix("SIG").unwrap_or(&upper) {
        "HUP" | "TERM" => Some(CTRL_CLOSE),
        "INT" => Some(CTRL_C),
        "QUIT" => Some(CTRL_BREAK),
        "USR1" => Some(USR1),
        "USR2" => Some(USR2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signal_but_kill_has_one_event_with_its_own_exit_code() {
        let signals = ["HUP", "INT", "QUIT", "TERM", "USR1", "USR2"];
        for signal in signals {
            let event = event_for_signal(signal).expect(signal);
            assert!(ALL.contains(&event), "{signal}");
            assert_eq!(event_for_signal(&format!("sig{signal}")), Some(event));
        }
        assert_eq!(event_for_signal("KILL"), None);
        assert_eq!(event_for_signal("STOP"), None);
        // Distinct events have distinct names and exit codes, and none of
        // the codes is the "no event" code or an ordinary success.
        for (i, a) in ALL.iter().enumerate() {
            assert!(a.exit_code > 0 && a.exit_code != NO_EVENT_EXIT_CODE);
            for b in &ALL[i + 1..] {
                assert_ne!(a.name, b.name);
                assert_ne!(a.exit_code, b.exit_code);
            }
        }
    }
}
