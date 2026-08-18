//! The closed set of signals a caller may name (`docs/CLI.md` §6.7).
//!
//! `session close --signal <SIG>` accepts `HUP|INT|QUIT|TERM|USR1|USR2|KILL`
//! only, case-insensitively and with or without the `SIG` prefix; anything
//! else (numbers, stop-class signals, unknown names) is `INVALID_ARGUMENT`.
//! Names are normalised to the `SIGTERM` form — the same form `session.exit`
//! reports in its `signal` field. Parsing lives in the broker so every
//! frontend and the dispatch edge share one rule and no arbitrary string
//! ever reaches [`crate::broker::SourceControl::signal`].

use std::fmt;

/// A signal the broker may deliver to a session's process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// `SIGHUP` — the default first step of the close escalation.
    Hup,
    /// `SIGINT`.
    Int,
    /// `SIGQUIT`.
    Quit,
    /// `SIGTERM` — the second escalation step.
    Term,
    /// `SIGUSR1`.
    Usr1,
    /// `SIGUSR2`.
    Usr2,
    /// `SIGKILL` — the last escalation step; as a first signal it skips
    /// escalation entirely (CLI.md §6.7).
    Kill,
}

impl Signal {
    /// Every accepted signal, in a stable order.
    pub const ALL: [Signal; 7] = [
        Signal::Hup,
        Signal::Int,
        Signal::Quit,
        Signal::Term,
        Signal::Usr1,
        Signal::Usr2,
        Signal::Kill,
    ];

    /// Parse a caller-supplied name (`HUP`, `sighup`, `SIGHUP`, …).
    /// `None` ⇒ the caller must answer `INVALID_ARGUMENT`.
    pub fn parse(name: &str) -> Option<Signal> {
        let upper = name.trim().to_ascii_uppercase();
        let bare = upper.strip_prefix("SIG").unwrap_or(&upper);
        Some(match bare {
            "HUP" => Signal::Hup,
            "INT" => Signal::Int,
            "QUIT" => Signal::Quit,
            "TERM" => Signal::Term,
            "USR1" => Signal::Usr1,
            "USR2" => Signal::Usr2,
            "KILL" => Signal::Kill,
            _ => return None,
        })
    }

    /// The canonical `SIGTERM`-form name.
    pub fn as_str(self) -> &'static str {
        match self {
            Signal::Hup => "SIGHUP",
            Signal::Int => "SIGINT",
            Signal::Quit => "SIGQUIT",
            Signal::Term => "SIGTERM",
            Signal::Usr1 => "SIGUSR1",
            Signal::Usr2 => "SIGUSR2",
            Signal::Kill => "SIGKILL",
        }
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_documented_set_case_and_prefix_insensitively() {
        for (input, want) in [
            ("HUP", Signal::Hup),
            ("hup", Signal::Hup),
            ("SIGHUP", Signal::Hup),
            ("sigterm", Signal::Term),
            (" Term ", Signal::Term),
            ("Int", Signal::Int),
            ("QUIT", Signal::Quit),
            ("usr1", Signal::Usr1),
            ("SIGUSR2", Signal::Usr2),
            ("kill", Signal::Kill),
        ] {
            assert_eq!(Signal::parse(input), Some(want), "{input}");
        }
        for s in Signal::ALL {
            assert_eq!(Signal::parse(s.as_str()), Some(s));
            assert!(s.as_str().starts_with("SIG"));
        }
    }

    #[test]
    fn rejects_numbers_stop_class_and_unknown_names() {
        for bad in [
            "9",
            "15",
            "STOP",
            "SIGSTOP",
            "TSTP",
            "CONT",
            "WINCH",
            "",
            "SIG",
            "TERMINATE",
        ] {
            assert_eq!(Signal::parse(bad), None, "{bad}");
        }
    }
}
