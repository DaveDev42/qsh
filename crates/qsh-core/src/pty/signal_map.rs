//! What each of the seven session signals does on a Windows host
//! (ADR-0035 decision 22, `docs/CLI.md` §6.7). The table is a plain function
//! without `cfg`, so every platform's test leg checks it; only the code that
//! performs a step is Windows-only.
//!
//! `session close --signal <SIG>` means "make this signal the first step of
//! the close". Windows has no signals, so each name stands for the event
//! that plays its part there:
//!
//! | signal | first step |
//! |---|---|
//! | `Int` | `CTRL_C_EVENT` to everything on the session's console |
//! | `Quit` | `CTRL_BREAK_EVENT` to the same |
//! | `Hup`, `Term` | `ClosePseudoConsole` (`CTRL_CLOSE_EVENT`) |
//! | `Usr1`, `Usr2` | `SetEvent` on the session's named event |
//! | `Kill` | `TerminateJobObject` |
//!
//! `Hup` and `Term` are one event, so a `Term` that follows a `Hup` (the
//! escalation's second step) sends nothing and only lets the grace pass.
//! Whatever the first step is, the escalation after it (`Term`, then `Kill`)
//! ends the session.

// The Windows backend is the only non-test user.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::broker::Signal;

/// Which of the session's two named events a step sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserEvent {
    Usr1,
    Usr2,
}

/// One thing the host does to a session on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// `CTRL_C_EVENT` to every process on the session's console, through the
    /// `qsh internal console-ctrl` helper.
    CtrlC,
    /// `CTRL_BREAK_EVENT`, the same way.
    CtrlBreak,
    /// `ClosePseudoConsole`: `CTRL_CLOSE_EVENT` to everything on the console.
    CloseConsole,
    /// `SetEvent` on the session's `Usr1` or `Usr2` event.
    SetEvent(UserEvent),
    /// `TerminateJobObject`.
    TerminateJob,
}

/// The step `signal` stands for on Windows.
pub(crate) const fn first_step(signal: Signal) -> Step {
    match signal {
        Signal::Int => Step::CtrlC,
        Signal::Quit => Step::CtrlBreak,
        Signal::Hup | Signal::Term => Step::CloseConsole,
        Signal::Usr1 => Step::SetEvent(UserEvent::Usr1),
        Signal::Usr2 => Step::SetEvent(UserEvent::Usr2),
        Signal::Kill => Step::TerminateJob,
    }
}

/// Whether a session that ends right after `signal` was the last step sent
/// carries that signal's name in its exit. `Usr1` and `Usr2` only `SetEvent`
/// and cannot end a process by themselves, so a program that exits after one
/// exited on its own and reports its own status, as a unix child that handled
/// `SIGUSR1` does (ADR-0047, ADR-0035 decision 22). The other steps end the
/// program themselves and keep their signal.
pub(crate) const fn reported_at_exit(signal: Signal) -> bool {
    !matches!(first_step(signal), Step::SetEvent(_))
}

/// What to do for `signal` when the steps in `taken` were already done in
/// this session: the step to perform, or `None` when there is nothing left
/// to send. `Hup` and `Term` stand for one `ClosePseudoConsole`, so once
/// `CloseConsole` is in `taken` neither of them does anything (the
/// escalation's `Term` after a `Hup` only lets the grace pass, and a `Term`
/// first makes a later `Hup` a no-op). Every other step may be repeated.
pub(crate) fn next_step(taken: &[Step], signal: Signal) -> Option<Step> {
    let step = first_step(signal);
    if step == Step::CloseConsole && taken.contains(&Step::CloseConsole) {
        return None;
    }
    Some(step)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_map_matches_adr_0035_decision_22() {
        let expected = [
            (Signal::Hup, Step::CloseConsole),
            (Signal::Int, Step::CtrlC),
            (Signal::Quit, Step::CtrlBreak),
            (Signal::Term, Step::CloseConsole),
            (Signal::Usr1, Step::SetEvent(UserEvent::Usr1)),
            (Signal::Usr2, Step::SetEvent(UserEvent::Usr2)),
            (Signal::Kill, Step::TerminateJob),
        ];
        // Every accepted signal has exactly one row, in the order of
        // `Signal::ALL`, so a new signal cannot be left without a mapping.
        assert_eq!(expected.len(), Signal::ALL.len());
        for ((signal, step), listed) in expected.iter().zip(Signal::ALL) {
            assert_eq!(*signal, listed);
            assert_eq!(first_step(*signal), *step, "{signal}");
        }
        // Quit is Ctrl-Break and not Ctrl-C; Hup and Term are one event.
        assert_ne!(first_step(Signal::Quit), first_step(Signal::Int));
        assert_eq!(first_step(Signal::Hup), first_step(Signal::Term));
        assert_ne!(
            first_step(Signal::Usr1),
            first_step(Signal::Usr2),
            "the two user events are different events"
        );
    }

    #[test]
    fn only_steps_that_end_a_program_are_reported_at_exit() {
        for signal in Signal::ALL {
            let user_event = matches!(signal, Signal::Usr1 | Signal::Usr2);
            assert_eq!(reported_at_exit(signal), !user_event, "{signal}");
        }
    }

    #[test]
    fn hup_and_term_share_one_console_close_step() {
        // Hup then Term, Term then Hup: the second sends nothing.
        for (first, second) in [
            (Signal::Hup, Signal::Term),
            (Signal::Term, Signal::Hup),
            (Signal::Hup, Signal::Hup),
            (Signal::Term, Signal::Term),
        ] {
            let mut taken = Vec::new();
            let step = next_step(&taken, first).expect("the first close is performed");
            assert_eq!(step, Step::CloseConsole, "{first}");
            taken.push(step);
            assert_eq!(next_step(&taken, second), None, "{first} then {second}");
            // And any repeat after the console is gone.
            assert_eq!(next_step(&taken, first), None, "{first} repeated");
        }
        // The close is the only once-only step.
        let taken = [Step::CloseConsole];
        for signal in [
            Signal::Int,
            Signal::Quit,
            Signal::Usr1,
            Signal::Usr2,
            Signal::Kill,
        ] {
            assert_eq!(
                next_step(&taken, signal),
                Some(first_step(signal)),
                "{signal}"
            );
        }
        let taken = [Step::CtrlC, Step::SetEvent(UserEvent::Usr1)];
        assert_eq!(next_step(&taken, Signal::Int), Some(Step::CtrlC));
        assert_eq!(
            next_step(&taken, Signal::Usr1),
            Some(Step::SetEvent(UserEvent::Usr1))
        );
        assert_eq!(next_step(&taken, Signal::Hup), Some(Step::CloseConsole));
    }
}
