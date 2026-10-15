//! The POSIX [`Terminal`] for the interactive client: termios raw mode,
//! `TIOCGWINSZ`, and the signals an attach cares about.
//!
//! The driver itself — the open/attach sequence, the threads, the escape
//! machine, the exit code — is [`super::session_loop`]; this file is only
//! what differs between platforms (`super`'s module doc has the thread
//! layout).

use std::io::{self, Read as _};

use super::term::{self, RawMode};
use super::terminal::{EventSource, HangupCause, RawGuard, TermEvent, Terminal};

/// The terminal of this process: its stdin, its controlling tty.
pub(super) struct UnixTerminal;

impl Terminal for UnixTerminal {
    fn window_size(&self) -> Option<(u16, u16)> {
        term::window_size()
    }

    fn enter_raw(&self) -> io::Result<Box<dyn RawGuard>> {
        Ok(Box::new(RawMode::enter()?))
    }

    fn read_stdin(&self, buf: &mut [u8]) -> io::Result<usize> {
        io::stdin().lock().read(buf)
    }

    /// `SIGWINCH`, `SIGINT` and the fatal signals, on a runtime that lives
    /// in the returned source. Called on the signal thread.
    fn open_events(&self) -> io::Result<Box<dyn EventSource>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        match runtime.block_on(async { Signals::install() }) {
            Ok(signals) => Ok(Box::new(UnixEvents { runtime, signals })),
            Err(err) => {
                // A partial install would leave some of these caught but
                // never polled — i.e. ignored. Put the defaults back so the
                // client stays killable.
                Signals::disarm();
                Err(err)
            }
        }
    }

    fn leave_on_hangup(&self, cause: HangupCause) {
        match nix::sys::signal::Signal::try_from(cause.0) {
            Ok(signal) => term::restore_and_die(signal),
            Err(_) => {
                term::restore();
                std::process::exit(128 + cause.0);
            }
        }
    }
}

impl RawGuard for RawMode {
    fn is_raw(&self) -> bool {
        RawMode::is_raw(self)
    }
}

/// The runtime and signal streams of one attach.
struct UnixEvents {
    runtime: tokio::runtime::Runtime,
    signals: Signals,
}

impl EventSource for UnixEvents {
    fn next_event(&mut self) -> Option<TermEvent> {
        // Note the `block_on` boundary: the runtime context ends when this
        // returns, which is what makes the `AttachHandle` calls the caller
        // makes next legal.
        Some(match self.runtime.block_on(self.signals.next())? {
            Caught::Winch => TermEvent::Resize,
            Caught::Int => TermEvent::Interrupt,
            Caught::Fatal(signal) => TermEvent::Hangup(HangupCause(signal as i32)),
        })
    }
}

/// What the signal streams saw.
enum Caught {
    /// The window changed size.
    Winch,
    /// SIGINT, to be forwarded to the remote PTY.
    Int,
    /// A signal whose default action is to end this process.
    Fatal(nix::sys::signal::Signal),
}

/// The signals whose default action ends this process and which therefore
/// have to restore the terminal on the way out.
const FATAL: [nix::sys::signal::Signal; 3] = [
    nix::sys::signal::Signal::SIGTERM,
    nix::sys::signal::Signal::SIGHUP,
    nix::sys::signal::Signal::SIGQUIT,
];

/// The signal streams an interactive attach listens on.
struct Signals {
    winch: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
}

impl Signals {
    /// Install the handlers. Must be called from inside the runtime that
    /// will poll them.
    fn install() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            winch: signal(SignalKind::window_change())?,
            int: signal(SignalKind::interrupt())?,
            term: signal(SignalKind::terminate())?,
            hup: signal(SignalKind::hangup())?,
            quit: signal(SignalKind::quit())?,
        })
    }

    /// Put the default disposition back for every fatal signal, for the
    /// case where the install failed halfway: a signal tokio caught but
    /// nobody polls is a signal that has been silently *ignored*.
    fn disarm() {
        for signal in FATAL {
            // SAFETY: restoring a signal's default disposition takes only
            // plain integers and is done from a plain thread.
            unsafe {
                let _ = nix::sys::signal::signal(signal, nix::sys::signal::SigHandler::SigDfl);
            }
        }
    }

    /// The next signal, or `None` if every stream ended.
    async fn next(&mut self) -> Option<Caught> {
        tokio::select! {
            signal = self.winch.recv() => signal.map(|()| Caught::Winch),
            signal = self.int.recv() => signal.map(|()| Caught::Int),
            signal = self.term.recv() => {
                signal.map(|()| Caught::Fatal(nix::sys::signal::Signal::SIGTERM))
            }
            signal = self.hup.recv() => {
                signal.map(|()| Caught::Fatal(nix::sys::signal::Signal::SIGHUP))
            }
            signal = self.quit.recv() => {
                signal.map(|()| Caught::Fatal(nix::sys::signal::Signal::SIGQUIT))
            }
        }
    }
}
