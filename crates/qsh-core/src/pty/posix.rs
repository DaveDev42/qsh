//! The POSIX implementation behind [`crate::pty`] (unix only; see the parent
//! module docs for the design and the documented non-decisions).

#![cfg(unix)]

use std::ffi::{CStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::task::{Context, Poll};

use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::signal::unix::{SignalKind, signal};

use crate::broker::{
    SessionSource, SessionSpec, Signal, SourceControl, SourceExit, SourceFactory, SpawnedSource,
};

/// `TERM` when the client sent no hint.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// The baseline `PATH` handed to the child — the same value `sshd` uses
/// (`_PATH_STDPATH`). The login shell's own profile extends it (macOS:
/// `/usr/libexec/path_helper` from `/etc/zprofile`/`/etc/profile`).
#[cfg(target_os = "macos")]
pub const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// See the macOS definition.
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Window size used when the spec carries `0` for either dimension.
const FALLBACK_SIZE: (u16, u16) = (80, 24);

/// Environment keys copied from the `qsh serve` process into the child (in
/// addition to anything the client sends). Locale and timezone only —
/// never `PATH`, never secrets.
const PASSTHROUGH_ENV: &[&str] = &["LANG", "LANGUAGE", "TZ"];

/// Keys the client's `env` may not override: they are the identity of the
/// login, fixed by the password database.
const PINNED_ENV: &[&str] = &["HOME", "USER", "LOGNAME", "SHELL"];

/// The production [`SourceFactory`]: one [`PtySource`] per session.
#[derive(Debug, Default, Clone, Copy)]
pub struct PtyFactory;

impl SourceFactory for PtyFactory {
    fn create(&self, _spec: &SessionSpec) -> io::Result<Box<dyn SessionSource>> {
        Ok(Box::new(PtySource::new()))
    }
}

/// A [`SessionSource`] that spawns the session's program in a fresh pty.
#[derive(Debug, Default)]
pub struct PtySource {
    /// Test hook: run this program as "the login shell" instead of the
    /// account's password-database shell.
    shell_override: Option<PathBuf>,
    /// Test hook: where to publish the child's pid once spawned.
    pid_observer: Option<Arc<AtomicI32>>,
}

impl PtySource {
    /// A source that spawns per the [`SessionSpec`] it is given.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use `shell` as the login shell (tests: run `/bin/sh` as `-sh` instead
    /// of whatever the developer's account uses).
    #[cfg(test)]
    pub(crate) fn with_login_shell(mut self, shell: impl Into<PathBuf>) -> Self {
        self.shell_override = Some(shell.into());
        self
    }

    /// Publish the child's pid into `slot` right after spawn (tests: zombie
    /// and process-group assertions).
    #[cfg(test)]
    pub(crate) fn observe_pid(mut self, slot: Arc<AtomicI32>) -> Self {
        self.pid_observer = Some(slot);
        self
    }
}

impl SessionSource for PtySource {
    fn spawn(self: Box<Self>, spec: &SessionSpec) -> io::Result<SpawnedSource> {
        // Must be inside a runtime: the master fd is registered with the
        // reactor here (`AsyncFd::new`).
        let _rt = tokio::runtime::Handle::try_current().map_err(|_| {
            io::Error::other("PtySource::spawn must be called from within a tokio runtime")
        })?;

        let account = current_account()?;
        // Defence in depth for architecture.md §4: no user switching, and
        // the dispatch edge has already turned a foreign hint into
        // UNSUPPORTED after the ACL check. Fail closed if it did not.
        if let Some(user) = &spec.user
            && user != &account.name
        {
            return Err(super::unsupported());
        }
        let shell = self
            .shell_override
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| account.login_shell());

        let (cols, rows) = if spec.cols == 0 || spec.rows == 0 {
            FALLBACK_SIZE
        } else {
            (spec.cols, spec.rows)
        };
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| io::Error::other(format!("openpty: {e:#}")))?;

        let mut cmd = if spec.argv.is_empty() {
            CommandBuilder::new_default_prog()
        } else {
            CommandBuilder::from_argv(spec.argv.iter().map(OsString::from).collect())
        };
        cmd.env_clear();
        for (k, v) in build_env(spec, &account, &shell) {
            cmd.env(k, v);
        }
        cmd.cwd(if Path::new(&account.home).is_dir() {
            account.home.as_str()
        } else {
            "/"
        });
        // `set_controlling_tty(true)` is the default: setsid + TIOCSCTTY in
        // the child, which also makes it the process-group leader.

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| io::Error::other(format!("spawn: {e:#}")))?;
        // The slave must be closed on our side or the master never sees EOF
        // once the child (and everyone it forked) is gone.
        drop(pair.slave);

        let pid = child
            .process_id()
            .ok_or_else(|| io::Error::other("spawned child has no pid"))?
            as libc::pid_t;
        if let Some(slot) = &self.pid_observer {
            slot.store(pid, Ordering::SeqCst);
        }

        // Own the master ourselves: dup it (CLOEXEC), make it non-blocking,
        // hand it to the reactor, and let portable-pty's wrapper close its
        // copy. One `AsyncFd` is shared by the reader, the writer and the
        // resize path.
        let master_raw = pair
            .master
            .as_raw_fd()
            .ok_or_else(|| io::Error::other("pty master has no fd"))?;
        let master = dup_cloexec_nonblocking(master_raw)?;
        drop(pair.master);
        let fd = Arc::new(AsyncFd::new(master)?);

        Ok(SpawnedSource {
            output: Box::new(MasterReader {
                fd: Arc::clone(&fd),
            }),
            input: Box::new(MasterWriter {
                fd: Arc::clone(&fd),
            }),
            control: Box::new(PtyControl { fd, pgid: pid }),
            wait: Box::pin(wait_for_exit(pid, child)),
        })
    }
}

// ---------------------------------------------------------------------------
// Account / environment
// ---------------------------------------------------------------------------

/// The `qsh serve` account, from the password database (never `$USER`).
#[derive(Debug, Clone)]
struct Account {
    name: String,
    home: String,
    shell: String,
}

impl Account {
    /// The login shell to run: the account's `pw_shell` if it is
    /// executable, else `/bin/sh` (same fallback as `sshd`/portable-pty).
    fn login_shell(&self) -> String {
        if !self.shell.is_empty() && is_executable(&self.shell) {
            self.shell.clone()
        } else {
            "/bin/sh".to_string()
        }
    }
}

fn is_executable(path: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(path) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated string for the call's duration.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

/// `getpwuid_r(geteuid())` (architecture.md §4: the login name comes from
/// the password database, not `$USER`/`$LOGNAME`).
fn current_account() -> io::Result<Account> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        // SAFETY: all pointers are valid for the call; `buf` outlives the
        // strings we copy out of it below.
        let rc = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                &mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1024 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        if result.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no password-database entry for the effective uid",
            ));
        }
        // SAFETY: `result` points at `pwd`, whose string fields point into
        // `buf`, all still alive.
        let field = |p: *const libc::c_char| -> String {
            if p.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
            }
        };
        return Ok(Account {
            name: field(pwd.pw_name),
            home: field(pwd.pw_dir),
            shell: field(pwd.pw_shell),
        });
    }
}

/// Login name of the account `qsh serve` runs as (`getpwuid(geteuid())`).
/// The dispatch edge compares the `user` hint of `session.open` against
/// this after authorization (architecture.md §4).
pub fn login_name() -> io::Result<String> {
    current_account().map(|a| a.name)
}

/// The child's full environment, in application order (later wins in
/// `CommandBuilder`, and the pinned identity keys are re-asserted last).
fn build_env(spec: &SessionSpec, account: &Account, shell: &str) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = vec![
        ("HOME".into(), account.home.clone()),
        ("USER".into(), account.name.clone()),
        ("LOGNAME".into(), account.name.clone()),
        ("SHELL".into(), shell.to_string()),
        ("PATH".into(), DEFAULT_PATH.into()),
        (
            "TERM".into(),
            spec.term
                .clone()
                .unwrap_or_else(|| DEFAULT_TERM.to_string()),
        ),
    ];
    for (k, v) in std::env::vars() {
        if PASSTHROUGH_ENV.contains(&k.as_str()) || k.starts_with("LC_") {
            env.push((k, v));
        }
    }
    for (k, v) in &spec.env {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            continue; // not a valid environment entry; drop silently
        }
        env.push((k.clone(), v.clone()));
    }
    // Re-pin the login identity after the client overlay.
    env.retain(|(k, _)| !PINNED_ENV.contains(&k.as_str()));
    env.push(("HOME".into(), account.home.clone()));
    env.push(("USER".into(), account.name.clone()));
    env.push(("LOGNAME".into(), account.name.clone()));
    env.push(("SHELL".into(), shell.to_string()));
    env
}

// ---------------------------------------------------------------------------
// Master fd plumbing
// ---------------------------------------------------------------------------

/// `F_DUPFD_CLOEXEC` + `O_NONBLOCK` on the copy (the file description is
/// shared, but the original is dropped right after anyway).
fn dup_cloexec_nonblocking(raw: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: plain fcntl calls on a descriptor we own; the returned fd is
    // fresh and becomes owned by `OwnedFd` immediately.
    let dup = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    let flags = unsafe { libc::fcntl(dup, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(dup, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Read half of the master. EOF is delivered the same way on both
/// platforms: Linux answers `EIO` once the last slave is closed, macOS
/// returns `0`; either becomes `Ok(0)` here — but only *after* every byte
/// the child wrote has been returned (`docs/design/testing.md` L5).
struct MasterReader {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl AsyncRead for MasterReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let dst = buf.initialize_unfilled();
            let raw = self.fd.as_raw_fd();
            let res = guard.try_io(|_| {
                // SAFETY: `dst` is a valid, initialised, writable buffer of
                // `dst.len()` bytes for the duration of the call.
                let n = unsafe { libc::read(raw, dst.as_mut_ptr().cast(), dst.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => {
                    return Poll::Ready(match e.raw_os_error() {
                        // Linux: last slave closed ⇒ EOF.
                        Some(libc::EIO) => Ok(()),
                        Some(libc::EINTR) => continue,
                        _ => Err(e),
                    });
                }
                Err(_would_block) => continue,
            }
        }
    }
}

/// Write half of the master (client input → child).
struct MasterWriter {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl AsyncWrite for MasterWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.fd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let raw = self.fd.as_raw_fd();
            let res = guard.try_io(|_| {
                // SAFETY: `data` is a valid readable buffer for the call.
                let n = unsafe { libc::write(raw, data.as_ptr().cast(), data.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Resize (`TIOCSWINSZ`) and signal (`killpg`) control.
struct PtyControl {
    fd: Arc<AsyncFd<OwnedFd>>,
    /// The child's pid == its pgid (session leader after `setsid`).
    pgid: libc::pid_t,
}

impl SourceControl for PtyControl {
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads a `winsize` from the pointer for the
        // duration of the call; the fd is a live pty master.
        let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn signal(&mut self, signal: Signal) -> io::Result<()> {
        // SAFETY: killpg only takes integers. The broker never calls this
        // once the child was reaped (pgid reuse), see session.rs.
        let rc = unsafe { libc::killpg(self.pgid, signo(signal)) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// The broker's closed signal set → `libc` numbers.
fn signo(signal: Signal) -> libc::c_int {
    match signal {
        Signal::Hup => libc::SIGHUP,
        Signal::Int => libc::SIGINT,
        Signal::Quit => libc::SIGQUIT,
        Signal::Term => libc::SIGTERM,
        Signal::Usr1 => libc::SIGUSR1,
        Signal::Usr2 => libc::SIGUSR2,
        Signal::Kill => libc::SIGKILL,
    }
}

// ---------------------------------------------------------------------------
// Reaping
// ---------------------------------------------------------------------------

/// Resolve when the child exits. Reaps with `waitpid(pid, WNOHANG)` on
/// each `SIGCHLD` (tokio's signal stream is per-runtime and shared with
/// `tokio::process`, which also reaps only its own pids), so there is no
/// blocking thread per session and no zombie is left behind. If the
/// `SIGCHLD` stream cannot be registered, falls back to a blocking `waitpid`
/// on the blocking pool.
///
/// If the future is dropped before the child is reaped (the actor gave up
/// after `SIGKILL` + grace on an unkillable child, or the runtime is going
/// away), a detached [`orphan_reaper`] task keeps waiting so the child does
/// not linger as a zombie once it finally dies.
async fn wait_for_exit(pid: libc::pid_t, child: Box<dyn Child + Send + Sync>) -> SourceExit {
    let mut guard = ReapGuard { pid, reaped: false };
    // Register before the first `try_wait` so a `SIGCHLD` that lands in
    // between is not lost (the stream latches pending signals).
    let mut sigchld = signal(SignalKind::child()).ok();
    let exit = loop {
        if let Some(exit) = try_reap(pid) {
            break exit;
        }
        match sigchld.as_mut() {
            Some(stream) => {
                if stream.recv().await.is_none() {
                    // Stream closed (runtime shutting down): last resort.
                    sigchld = None;
                }
            }
            None => {
                break tokio::task::spawn_blocking(move || blocking_reap(pid))
                    .await
                    .unwrap_or_default();
            }
        }
    };
    guard.reaped = true;
    // Keep the portable-pty handle alive until here (it holds nothing that
    // needs the pid, but its lifetime should not outlive the reap).
    drop(child);
    exit
}

/// Spawns [`orphan_reaper`] if the wait future is dropped unreaped.
struct ReapGuard {
    pid: libc::pid_t,
    reaped: bool,
}

impl Drop for ReapGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let pid = self.pid;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(orphan_reaper(pid));
        }
    }
}

/// Reap `pid` whenever it eventually exits (see [`wait_for_exit`]).
async fn orphan_reaper(pid: libc::pid_t) {
    let Ok(mut sigchld) = signal(SignalKind::child()) else {
        return;
    };
    loop {
        if try_reap(pid).is_some() {
            return;
        }
        if sigchld.recv().await.is_none() {
            return;
        }
    }
}

/// `waitpid(pid, WNOHANG)`: `Some(exit)` once reaped, `None` while running.
fn try_reap(pid: libc::pid_t) -> Option<SourceExit> {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: plain syscall with a valid out-pointer.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            return Some(exit_from_status(status));
        }
        if rc == 0 {
            return None;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        // ECHILD: nothing of ours to reap — the child is gone but its
        // status is unknowable (someone else reaped it).
        return Some(SourceExit::default());
    }
}

fn blocking_reap(pid: libc::pid_t) -> SourceExit {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: plain syscall with a valid out-pointer.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return exit_from_status(status);
        }
        if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return SourceExit::default();
    }
}

fn exit_from_status(status: libc::c_int) -> SourceExit {
    if libc::WIFEXITED(status) {
        SourceExit {
            exit_code: Some(libc::WEXITSTATUS(status)),
            signal: None,
        }
    } else if libc::WIFSIGNALED(status) {
        SourceExit {
            exit_code: None,
            signal: Some(crate::exec::signal_name(libc::WTERMSIG(status))),
        }
    } else {
        SourceExit::default()
    }
}
