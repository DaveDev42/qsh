//! POSIX terminal control for the interactive client: raw mode, window
//! size, and a restore that survives every exit path.
//!
//! Direct `termios` + `TIOCGWINSZ` through `nix`, deliberately not
//! crossterm (`docs/design/architecture.md` §8): the TUI forwards raw
//! stdin bytes to the remote PTY and must not parse keys, so a key-event
//! loop and an alternate-screen manager are the wrong shape — and would
//! drag a Windows API surface into a client that is POSIX-only in M2.
//!
//! The saved settings live in a process-global slot, not only in the
//! guard, because two other exit paths have to restore them without owning
//! it: the panic hook (a panic on *any* thread) and the signal thread
//! (SIGTERM/SIGHUP). [`restore`] is idempotent, so all three can race.

use std::io::{self, IsTerminal};
use std::os::fd::AsFd;
use std::sync::{Mutex, Once};

use nix::sys::termios::{self, SetArg, Termios};

/// The terminal settings to put back, taken by whoever restores first.
static SAVED: Mutex<Option<Termios>> = Mutex::new(None);

/// Installs the panic hook exactly once, however many attaches a process
/// makes.
static HOOK: Once = Once::new();

nix::ioctl_read_bad!(tiocgwinsz, nix::libc::TIOCGWINSZ, nix::libc::winsize);

/// Whether this process's stdin is a terminal. Escape processing and raw
/// mode are both conditional on it (`docs/CLI.md` §7: with a pipe or a
/// file on stdin every byte is forwarded verbatim).
pub fn stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// The local window size, or `None` when stdin is not a terminal (then the
/// host picks: `cols`/`rows` of `0` normalise to 80x24,
/// `docs/design/architecture.md` §4).
pub fn window_size() -> Option<(u16, u16)> {
    if !stdin_is_tty() {
        return None;
    }
    let mut size: nix::libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `size` is a live, correctly typed `winsize`; the fd is this
    // process's stdin, borrowed for the duration of the call.
    let ok = unsafe { tiocgwinsz(nix::libc::STDIN_FILENO, &mut size) }.is_ok();
    (ok && size.ws_col > 0 && size.ws_row > 0).then_some((size.ws_col, size.ws_row))
}

/// The local terminal in raw mode for as long as this value lives.
///
/// `cfmakeraw` is what an interactive attach needs: no line discipline
/// (the remote PTY has one), no echo (the remote echoes), no `ISIG` (so
/// `^C` reaches the remote as a byte — `docs/CLI.md` §9) and no `OPOST`
/// (the remote already emits CR-LF).
#[derive(Debug)]
pub struct RawMode {
    /// `false` when stdin is not a terminal — then this guard is a no-op
    /// and the client is a plain byte pipe.
    active: bool,
}

impl RawMode {
    /// Enter raw mode if stdin is a terminal; otherwise a no-op guard.
    pub fn enter() -> io::Result<Self> {
        if !stdin_is_tty() {
            return Ok(Self { active: false });
        }
        let stdin = io::stdin();
        let saved = termios::tcgetattr(stdin.as_fd()).map_err(io::Error::from)?;
        let mut raw = saved.clone();
        termios::cfmakeraw(&mut raw);
        // Restore before anything can leave the terminal unusable, and
        // publish the saved settings *before* switching, so a panic inside
        // `tcsetattr` still has something to put back.
        *SAVED.lock().unwrap_or_else(|e| e.into_inner()) = Some(saved);
        install_panic_hook();
        termios::tcsetattr(stdin.as_fd(), SetArg::TCSADRAIN, &raw).map_err(|err| {
            restore();
            io::Error::from(err)
        })?;
        Ok(Self { active: true })
    }

    /// Whether the terminal is actually in raw mode (`false` for a piped
    /// stdin). Two things follow from it: escape processing is on only for
    /// a terminal (`docs/CLI.md` §7), and raw mode has no output
    /// post-processing, so diagnostics have to carry their own CR.
    pub fn is_raw(&self) -> bool {
        self.active
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        restore();
    }
}

/// Put the terminal back. Idempotent and safe to call from any thread:
/// the first caller takes the saved settings, the rest do nothing.
pub fn restore() {
    let saved = SAVED.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(saved) = saved {
        let _ = termios::tcsetattr(io::stdin().as_fd(), SetArg::TCSADRAIN, &saved);
    }
}

/// Restore the terminal before the default panic message is printed —
/// a panic on the input or signal thread would otherwise leave the
/// operator with a raw terminal and a stair-stepped backtrace.
fn install_panic_hook() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            previous(info);
        }));
    });
}

/// Die of `signal` the way the process would have without our handler:
/// restore the terminal, put the default disposition back, and re-raise.
///
/// The exit *status* then correctly says "killed by SIGTERM" instead of
/// inventing an exit code for something the caller signalled.
pub fn restore_and_die(signal: nix::sys::signal::Signal) -> ! {
    restore();
    // SAFETY: resetting a signal to its default disposition and raising it
    // is async-signal-safe; we are on a plain thread, not in a handler.
    unsafe {
        let _ = nix::sys::signal::signal(signal, nix::sys::signal::SigHandler::SigDfl);
    }
    let _ = nix::sys::signal::raise(signal);
    // Only reachable if the signal was blocked by our caller's mask.
    std::process::exit(128 + signal as i32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, OwnedFd};

    /// A pty pair we own, so the test never touches the real terminal (and
    /// still runs when the suite is started from a pipe).
    fn pty() -> (OwnedFd, OwnedFd) {
        let pty = nix::pty::openpty(None, None).expect("openpty");
        (pty.master, pty.slave)
    }

    /// The raw-mode transformation itself, applied to a pty we own: the
    /// same `cfmakeraw` the guard applies to stdin.
    #[test]
    fn cfmakeraw_disables_echo_and_signal_generation() {
        let (_master, slave) = pty();
        let cooked = termios::tcgetattr(&slave).expect("tcgetattr");
        assert!(
            cooked
                .local_flags
                .contains(termios::LocalFlags::ECHO | termios::LocalFlags::ISIG),
            "a fresh pty should start cooked"
        );
        let mut raw = cooked.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&slave, SetArg::TCSANOW, &raw).expect("tcsetattr");

        let now = termios::tcgetattr(&slave).expect("tcgetattr");
        assert!(!now.local_flags.contains(termios::LocalFlags::ECHO));
        assert!(!now.local_flags.contains(termios::LocalFlags::ISIG));
        assert!(!now.local_flags.contains(termios::LocalFlags::ICANON));
        assert!(!now.output_flags.contains(termios::OutputFlags::OPOST));

        // ...and restoring the saved copy puts the flags back. `PENDIN` is
        // kernel bookkeeping (input awaiting reprint), not a setting, so it
        // is masked out of the comparison.
        termios::tcsetattr(&slave, SetArg::TCSANOW, &cooked).expect("restore");
        let back = termios::tcgetattr(&slave).expect("tcgetattr");
        let settings = |flags: termios::LocalFlags| flags - termios::LocalFlags::PENDIN;
        assert_eq!(settings(back.local_flags), settings(cooked.local_flags));
        assert_eq!(back.output_flags, cooked.output_flags);
        assert_eq!(back.input_flags, cooked.input_flags);
    }

    /// `restore()` is what the panic hook, the guard's `Drop` and the
    /// signal thread all call; it must be safe to call twice and safe to
    /// call when nothing was saved.
    ///
    /// Asserts on the process-global [`SAVED`], so it holds only while no
    /// unit test in this binary calls [`RawMode::enter`] — a second one
    /// that did would be stealing this one's slot. Add such a test and
    /// these two need a shared lock.
    #[test]
    fn restore_is_idempotent_and_harmless_without_a_saved_state() {
        restore();
        restore();
        assert!(SAVED.lock().unwrap().is_none());
    }

    /// The window-size ioctl reads what was set on the pty. This is the
    /// call `SIGWINCH` handling depends on; a wrong ioctl number here would
    /// silently stop resize propagation.
    #[test]
    fn tiocgwinsz_reads_the_size_that_was_set() {
        let (master, slave) = pty();
        let want = nix::libc::winsize {
            ws_row: 41,
            ws_col: 133,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        nix::ioctl_write_ptr_bad!(tiocswinsz, nix::libc::TIOCSWINSZ, nix::libc::winsize);
        // SAFETY: a live `winsize` and a pty fd we own.
        unsafe { tiocswinsz(master.as_raw_fd(), &want) }.expect("TIOCSWINSZ");

        let mut got: nix::libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: same, reading this time.
        unsafe { tiocgwinsz(slave.as_raw_fd(), &mut got) }.expect("TIOCGWINSZ");
        assert_eq!((got.ws_col, got.ws_row), (133, 41));
    }
}
