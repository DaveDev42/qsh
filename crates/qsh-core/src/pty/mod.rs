//! PTY backends for the session broker (`docs/design/architecture.md` §4):
//! the POSIX one below and the Windows ConPTY one after it. M2 plan Step 4
//! (2473c88) built the POSIX one.
//!
//! `PtySource` is the production [`crate::broker::SessionSource`]: it opens a pty pair
//! with `portable-pty` 0.9, spawns the child as a **session leader with the
//! slave as its controlling tty** (`setsid` + `TIOCSCTTY`, so it is also the
//! process-group leader and job control works), wraps the master fd in a
//! `tokio::io::unix::AsyncFd` for async read/write, applies `TIOCSWINSZ`
//! on resize, delivers signals with **`killpg` to the whole process group**
//! (never just the leader), and reaps the child with `waitpid` on
//! `SIGCHLD` (no zombies, no blocking thread per session).
//!
//! Login-shell environment (architecture.md §4): the child does **not**
//! inherit the `qsh serve` process environment. It gets `HOME`/`USER`/
//! `LOGNAME` from the password database, `SHELL` (the account's login
//! shell), a platform baseline `PATH`, `TERM` (client hint, default
//! `xterm-256color`), locale/timezone pass-through (`LANG`, `LANGUAGE`,
//! `LC_*`, `TZ`) and the client's extra `env`. The client overlay may not
//! override `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH` (pinned; `PATH` because
//! it decides which binary `argv[0]` resolves to). An empty `argv` runs the
//! login shell with `argv[0] = "-<basename>"` (e.g. `-zsh`), so the shell's
//! own login files run — on macOS that is where `/usr/libexec/path_helper`
//! (via `/etc/zprofile` / `/etc/profile`) builds the real `PATH` from
//! `/etc/paths*`; the baseline we hand it is what `sshd` hands a login shell.
//!
//! **Decisions (documented, not implemented):** utmp/wtmp/lastlog are not
//! written in the MVP (`docs/design/testing.md` L5) — `who`/`last` do not
//! show qsh sessions. There is no user switching: the child always runs as
//! the `qsh serve` account; a `user` hint that names anyone else fails
//! before `openpty` with [`user_switching_unsupported`] (`UNSUPPORTED`,
//! message `user switching is not supported`, CLI.md §7), which the broker
//! surfaces as `BrokerError::Unsupported`. The dispatch edge checks the hint
//! after authorization (never before — no account-name oracle for
//! unauthorized peers); the check here is defence in depth.
//!
//! `spawn` is synchronous and runs on the caller's task: `openpty`, a
//! `fork`+`exec` (portable-pty sets `pre_exec`, so std cannot use
//! `posix_spawn`) and a `stat` of the home directory. The password lookup
//! is cached after the first call. Known upstream hazard, accepted for M2:
//! portable-pty's `pre_exec` closes stray fds by reading `/dev/fd`, which
//! allocates between `fork` and `exec` in a multi-threaded process (a
//! child could deadlock on the allocator lock and present as a session
//! that never produces output). See architecture.md §4.
//!
//! Windows has its own backend, `ConPtySource` (`conpty.rs`, ADR-0035
//! decision 20): a pseudo-console and a Job Object per session, created by
//! one `CreateProcessW`. It implements the same [`crate::broker::SessionSource`]
//! seam, so everything above it (sequence tagging, replay, quotas, detach and
//! resume, the close escalation) is the same code on both platforms.
//!
//! Signals on Windows are events, not signals (ADR-0035 decision 22): `Int`
//! is `CTRL_C_EVENT` and `Quit` is `CTRL_BREAK_EVENT` (sent by the hidden
//! `qsh internal console-ctrl` helper, [`console_ctrl`]), `Hup` and `Term` close
//! the pseudo-console, `Usr1` and `Usr2` set the session's named events, and
//! `Kill` ends the job. The table is in `signal_map`, a plain function that
//! every platform tests.
//!
//! The environment follows the same policy on both (`env_policy`): the
//! child gets the account's environment, not the `qsh serve` one, and the
//! client may not override the pinned keys. On Windows the account's
//! environment is the user environment block (`CreateEnvironmentBlock` for the
//! process token), the pinned set adds the Windows identity variables and the
//! names compare ignoring case, an empty `argv` runs `COMSPEC` (or
//! `%SystemRoot%\System32\cmd.exe`) from the user's profile directory, and the
//! `user` hint is compared with the token's account name (`user` or
//! `DOMAIN\user`) ignoring case. There is no user switching and no
//! utmp/wtmp-like record on either platform.

use std::io;
use std::sync::Arc;

use crate::broker::SourceFactory;

#[cfg(unix)]
mod posix;

#[cfg(windows)]
mod conpty;

#[cfg(windows)]
pub use conpty::{ConPtyFactory, ConPtySource, login_name};

pub mod console_ctrl;
pub(crate) mod env_policy;
pub(crate) mod signal_map;

#[cfg(unix)]
pub use posix::{PtyFactory, PtySource, login_name};

/// Host-pinned identity env, reused by `crate::exec` so `exec.run` pins
/// `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH` the same way this PTY spawn path
/// does (`docs/CLI.md`: pinned "어느 경로에서도").
#[cfg(unix)]
pub(crate) use posix::{PINNED_ENV, pinned_identity_env};

/// L5 PTY end-to-end tests (`docs/design/testing.md`), unix only.
#[cfg(all(test, unix))]
mod tests;

/// The error for a `user` hint that names anyone but the serve account
/// (CLI.md §7: `UNSUPPORTED`, message `user switching is not supported`).
pub fn user_switching_unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "user switching is not supported",
    )
}

/// The production [`SourceFactory`] for `Broker::new`: PTY-backed on unix,
/// ConPTY-backed on Windows.
pub fn factory() -> Arc<dyn SourceFactory> {
    #[cfg(unix)]
    {
        Arc::new(PtyFactory)
    }
    #[cfg(windows)]
    {
        Arc::new(ConPtyFactory::default())
    }
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn user_switching_error_maps_to_the_unsupported_kind() {
        let e = user_switching_unsupported();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert_eq!(e.to_string(), "user switching is not supported");
    }
}
