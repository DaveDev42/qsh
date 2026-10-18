//! What the interactive driver needs from a terminal, and nothing else.
//!
//! The driver in `super::session_loop` is the same on every platform: it
//! forwards stdin bytes through the line-start escape machine, turns size
//! changes into `session.resize`, and maps the end of the session onto an
//! exit code. The four things below are the part that is not: switching
//! the terminal to raw mode and back, asking for its size, reading what the
//! operator types, and hearing that the terminal is gone or changed. Two
//! small hooks run before a session exists: whether the terminal can be
//! driven at all, and which `TERM` to announce when the environment has
//! none.
//! Writing session output to stdout is deliberately not here — both
//! platforms write to `std::io::Stdout`.

use std::io;

use qsh_core::OpError;

/// A terminal the interactive client can drive.
///
/// Shared by the three threads of an attach (`super`'s module doc), hence
/// `Send + Sync`.
pub(crate) trait Terminal: Send + Sync + 'static {
    /// Whether this terminal can be driven, answered before the first
    /// `session.open` so a refusal never leaves an orphan session on the
    /// host. The POSIX terminal has no requirement; the Windows console
    /// refuses with `UNSUPPORTED` when it cannot interpret VT sequences
    /// (`docs/CLI.md` §7).
    fn preflight(&self) -> Result<(), OpError> {
        Ok(())
    }

    /// The `TERM` to send in `session.open` when the environment has none.
    /// `None` leaves the choice to the host. Only meaningful after a
    /// successful [`preflight`](Terminal::preflight).
    fn fallback_term(&self) -> Option<&'static str> {
        None
    }

    /// The window size in columns and rows, or `None` when stdin is not a
    /// terminal (then the host picks: `cols`/`rows` of `0` normalise to
    /// 80x24, `docs/design/architecture.md` §4).
    fn window_size(&self) -> Option<(u16, u16)>;

    /// Put the terminal in raw mode for as long as the returned guard
    /// lives, and restore it when the guard drops. When stdin is not a
    /// terminal the guard is a no-op and reports `is_raw() == false`.
    fn enter_raw(&self) -> io::Result<Box<dyn RawGuard>>;

    /// One blocking read of stdin into `buf`. `Ok(0)` is end of input.
    fn read_stdin(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Start listening for [`TermEvent`]s. Called on the signal thread, so
    /// an implementation that needs a runtime or a message loop can keep it
    /// in the returned source; a failure leaves the client running without
    /// event handling.
    fn open_events(&self) -> io::Result<Box<dyn EventSource>>;

    /// Whether a hang-up is a detach the client finishes itself, instead of
    /// a [`Self::leave_on_hangup`]. The POSIX terminal dies of the signal and
    /// the host notices when the connection idles out. A terminal whose
    /// process is ended the moment its hang-up handler returns asks for the
    /// detach: the driver detaches as `~d` does, so the host sees the client
    /// go and the client exits `0` through its ordinary path.
    fn detaches_on_hangup(&self) -> bool {
        false
    }

    /// Whether the session output must lose its win32-input-mode requests
    /// (`CSI ? 9001 h/l`) before it reaches this terminal. A console that
    /// obeys them hands the client key records instead of the bytes typed,
    /// which the escape machine cannot read. The POSIX terminal forwards
    /// the output untouched.
    fn strips_win32_input_mode(&self) -> bool {
        false
    }

    /// The terminal is gone (hang-up, termination, console closed): put it
    /// back the way it was and leave. The session stays on the host
    /// (`docs/CLI.md` §7). The POSIX terminal dies of the signal and never
    /// returns; a stand-in may.
    fn leave_on_hangup(&self, cause: HangupCause);
}

/// The raw-mode guard. Dropping it restores the terminal.
pub(crate) trait RawGuard {
    /// Whether the terminal is actually in raw mode (`false` for a piped
    /// stdin). Escape processing is on only for a terminal
    /// (`docs/CLI.md` §7), and raw mode has no output post-processing, so
    /// diagnostics have to carry their own CR.
    fn is_raw(&self) -> bool;
}

/// What a terminal reports to the signal thread.
pub(crate) trait EventSource {
    /// Block for the next event, or `None` when no more can come.
    fn next_event(&mut self) -> Option<TermEvent>;
}

/// An event the driver acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TermEvent {
    /// The window size may have changed: ask [`Terminal::window_size`].
    Resize,
    /// An interrupt that did not arrive as a keystroke (`kill -INT`, or a
    /// non-terminal stdin): forwarded as the `^C` byte.
    Interrupt,
    /// The terminal is going away; see [`Terminal::leave_on_hangup`].
    Hangup(HangupCause),
}

/// Which hang-up it was, as the terminal implementation numbers it (the
/// signal number on POSIX). Opaque to the driver, which hands it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HangupCause(pub(crate) i32);
