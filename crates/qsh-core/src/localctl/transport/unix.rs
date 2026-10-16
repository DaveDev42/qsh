//! The unix transport: a Unix domain socket per daemon at
//! `<runtime_dir>/<pid>.sock` (`docs/design/architecture.md` §7).
//!
//! The trust boundary is the one `crate::localctl`'s module docs describe:
//! the socket node is 0600 inside a 0700 directory, and the daemon rejects
//! any peer whose euid is not its own (`SO_PEERCRED` on Linux, `getpeereid`
//! on macOS) before it reads a frame.

use std::io;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

/// A connected localctl conduit. On unix it is the socket itself, so every
/// readiness-based method the shared code uses (`readable`, `try_write`,
/// `poll_read_ready`, …) is `UnixStream`'s own.
pub type LocalStream = UnixStream;

/// Open the socket at `endpoint`.
pub(crate) async fn connect(endpoint: &Path) -> io::Result<LocalStream> {
    UnixStream::connect(endpoint).await
}

/// Half-close: shut the write direction of `stream` down. Synchronous, no
/// runtime needed; every clone of an `Arc`-shared stream sees the same
/// socket, and the peer's read sees a clean EOF.
pub(crate) fn shutdown_write(stream: &LocalStream) {
    shutdown(stream, libc::SHUT_WR);
}

/// Hard stop: shut both directions of `stream` down, from any thread.
pub(crate) fn shutdown_both(stream: &LocalStream) {
    shutdown(stream, libc::SHUT_RDWR);
}

fn shutdown(stream: &LocalStream, how: libc::c_int) {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `shutdown(2)` only reads the descriptor number; the fd stays
    // allocated for as long as `stream` is borrowed, so it cannot name a
    // reused descriptor.
    unsafe {
        libc::shutdown(stream.as_raw_fd(), how);
    }
}

/// This machine's localctl sockets, named `<pid>.sock`
/// (`docs/design/architecture.md` §7), in pid-ascending order. A missing
/// runtime directory (no daemon has ever bound a socket here) yields an
/// empty list, not an error — that is the normal "no `qsh listen` running"
/// state. Entries that are not `<digits>.sock` are silently skipped: the
/// runtime directory is not exclusively ours to police.
pub fn candidate_endpoints(runtime_dir: &Path) -> io::Result<Vec<(u32, PathBuf)>> {
    let entries = match std::fs::read_dir(runtime_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if let Some(pid) = socket_pid(&path) {
            out.push((pid, path));
        }
    }
    out.sort_by_key(|(pid, _)| *pid);
    Ok(out)
}

fn socket_pid(path: &Path) -> Option<u32> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("sock") {
        return None;
    }
    path.file_stem()?.to_str()?.parse().ok()
}

/// A discovery candidate refused the connection. `ECONNREFUSED` is *not*
/// proof the daemon is dead: on macOS/BSD a live listener whose accept
/// backlog is full reports it exactly this way, and even on Linux a
/// just-`bind`-not-yet-`listen`ing socket can produce it for an instant.
/// The socket is unlinked only when the pid its own filename names
/// (`<pid>.sock`, `docs/design/architecture.md` §7) is actually gone —
/// `kill(pid, 0)` returning `ESRCH` is the one thing that proves that
/// (adversarial review finding: unconditional unlink here could delete a
/// live, merely-busy daemon's socket, permanently orphaning it from `qsh
/// hosts` and routing until a manual restart).
pub(crate) fn forget_refused_endpoint(pid: u32, endpoint: &Path) {
    if process_is_verifiably_dead(pid) {
        let _ = std::fs::remove_file(endpoint);
    } else {
        tracing::debug!(
            pid,
            "localctl: connection refused but pid {pid} is still alive; leaving its \
             socket in place"
        );
    }
}

/// Whether the process named by `pid` — the pid `<pid>.sock`'s own
/// filename already carries — is provably gone, via `kill(pid, 0)`
/// (`man 2 kill`: signal `0` performs no signal delivery, only the
/// existence/permission check). Only `ESRCH` ("no such process") counts as
/// proof of death; a permission error (`EPERM`, a different uid holding
/// that pid — impossible for a genuine same-user daemon, but not this
/// function's job to assume) or success (the process exists) both leave
/// the socket alone, because unlinking a live daemon's socket is
/// unrecoverable for that process's lifetime while leaving a truly stale
/// one costs nothing but a retry on the next discovery pass.
pub(crate) fn process_is_verifiably_dead(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        // A pid that doesn't fit `pid_t` can't name a live process on this
        // machine either way; treat it as dead so a garbage filename
        // doesn't linger forever.
        return true;
    };
    // SAFETY: `kill` with signal `0` sends no signal; it only performs the
    // existence/permission check documented above, and touches no memory
    // this function does not own.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return false; // the signal would have been delivered: pid exists.
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// Serializes the brief window [`bind_with_narrow_umask`] narrows this
/// process's umask for. `umask(2)` is process-global, not per-thread, so
/// two concurrent binds — the daemon's test suite runs several binds in
/// parallel `#[tokio::test]`s — must not interleave their save/restore
/// (which could otherwise leave the process's umask permanently wrong for
/// the rest of its lifetime).
static UMASK_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Bind `path` with this process's umask narrowed to `0o177` (owner
/// read/write kept, everything else stripped) for the `bind(2)` syscall
/// alone, restored immediately after regardless of outcome — so the socket
/// node `bind(2)` creates (which has no mode parameter for `AF_UNIX`,
/// unlike `open(2)`) is never observable at a mode looser than 0600, not
/// even for the instant between `bind(2)` and an explicit `chmod`
/// (adversarial review finding: without this, the node briefly existed at
/// `0666 & ~umask` — typically 0644/0755-shaped — before
/// [`tighten_socket_mode`] ran).
pub(crate) fn bind_with_narrow_umask(path: &Path) -> io::Result<UnixListener> {
    let _guard = UMASK_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: `umask(2)` reads and writes only this process's umask; it
    // touches no memory and cannot fail. The lock above is what makes the
    // save/restore pair race-free against another thread's call to this
    // same function — `umask` itself has no thread-local variant to lean
    // on instead.
    let previous = unsafe { libc::umask(0o177) };
    let result = UnixListener::bind(path);
    unsafe { libc::umask(previous) };
    result
}

pub(crate) fn tighten_socket_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Whether `stream`'s connecting peer is this process's own euid — the
/// only fact localctl ever authorizes on (`crate::localctl` module docs).
/// Runs before any frame is read.
pub(crate) fn authorized_peer(stream: &UnixStream) -> io::Result<bool> {
    let cred = stream.peer_cred()?;
    Ok(peer_is_authorized(cred.uid(), daemon_euid()))
}

/// The pure comparison [`authorized_peer`] reduces to, once the OS-level
/// lookup (`SO_PEERCRED`/`getpeereid`, via [`UnixStream::peer_cred`]) has
/// produced a peer uid — split out so the "different euid is denied" rule
/// is unit-testable without a second real OS user
/// (`docs/design/testing.md` L2).
pub(crate) fn peer_is_authorized(peer_uid: u32, daemon_euid: u32) -> bool {
    peer_uid == daemon_euid
}

/// This process's effective user id.
fn daemon_euid() -> u32 {
    // SAFETY: `geteuid(2)` takes no arguments, touches no memory, and
    // cannot fail.
    unsafe { libc::geteuid() }
}
