//! POSIX PTY backend for the session broker (`docs/design/architecture.md`
//! §4, PLAN Step 4).
//!
//! [`PtySource`] is the production [`SessionSource`]: it opens a pty pair
//! with `portable-pty` 0.9, spawns the child as a **session leader with the
//! slave as its controlling tty** (`setsid` + `TIOCSCTTY`, so it is also the
//! process-group leader and job control works), wraps the master fd in a
//! [`tokio::io::unix::AsyncFd`] for async read/write, applies `TIOCSWINSZ`
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
//! The whole implementation is unix-only. On other targets [`factory`]
//! returns a factory whose `create` fails with
//! [`io::ErrorKind::Unsupported`], so the crate builds everywhere and a
//! non-POSIX host answers `UNSUPPORTED` instead of not compiling
//! (`docs/ROADMAP.md` §3: no Windows host in P0).

use std::io;
use std::sync::Arc;

use crate::broker::SourceFactory;

#[cfg(unix)]
mod posix;

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

/// The error a non-POSIX host reports for any PTY request.
pub fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "PTY sessions are only supported on POSIX hosts",
    )
}

/// The error for a `user` hint that names anyone but the serve account
/// (CLI.md §7: `UNSUPPORTED`, message `user switching is not supported`).
pub fn user_switching_unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "user switching is not supported",
    )
}

/// The production [`SourceFactory`] for `Broker::new` — PTY-backed on unix,
/// always-`Unsupported` elsewhere.
pub fn factory() -> Arc<dyn SourceFactory> {
    #[cfg(unix)]
    {
        Arc::new(PtyFactory)
    }
    #[cfg(not(unix))]
    {
        Arc::new(UnsupportedFactory)
    }
}

/// Login name of the account `qsh serve` runs as, on hosts without a PTY
/// backend. Always [`io::ErrorKind::Unsupported`].
#[cfg(not(unix))]
pub fn login_name() -> io::Result<String> {
    Err(unsupported())
}

/// [`SourceFactory`] for hosts without a PTY backend.
#[cfg(not(unix))]
#[derive(Debug, Default, Clone, Copy)]
struct UnsupportedFactory;

#[cfg(not(unix))]
impl SourceFactory for UnsupportedFactory {
    fn create(
        &self,
        _spec: &crate::broker::SessionSpec,
    ) -> io::Result<Box<dyn crate::broker::SessionSource>> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn unsupported_error_maps_to_the_unsupported_kind() {
        assert_eq!(unsupported().kind(), io::ErrorKind::Unsupported);
        let e = user_switching_unsupported();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert_eq!(e.to_string(), "user switching is not supported");
    }

    #[cfg(not(unix))]
    #[test]
    fn non_posix_factory_fails_closed_with_unsupported() {
        let err = factory()
            .create(&crate::broker::SessionSpec::default())
            .err()
            .expect("no PTY on this platform");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert_eq!(login_name().unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}
