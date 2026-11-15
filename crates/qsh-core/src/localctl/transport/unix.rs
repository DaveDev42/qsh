//! The unix half of the local-socket transport agent forwarding uses: a
//! Unix domain socket whose node is 0600, and a peer-credential check
//! (`SO_PEERCRED` on Linux, `getpeereid` on macOS) that accepts only this
//! process's own euid.

use std::io;
use std::path::Path;

use tokio::net::{UnixListener, UnixStream};

/// A connected local stream. On unix it is the socket itself, so every
/// readiness-based method the shared code uses (`readable`, `try_write`,
/// `poll_read_ready`, …) is `UnixStream`'s own.
pub type LocalStream = UnixStream;

/// Serializes the brief window [`bind_with_narrow_umask`] narrows this
/// process's umask for. `umask(2)` is process-global, not per-thread, so
/// two concurrent binds — a test suite runs several binds in
/// parallel `#[tokio::test]`s — must not interleave their save/restore
/// (which could otherwise leave the process's umask permanently wrong for
/// the rest of its lifetime).
static UMASK_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The umask held during [`bind_with_narrow_umask`]: group and other bits
/// stripped, the owner's three bits left alone. It must not strip the
/// owner's execute bit (`0o177` did): `umask(2)` is process-wide, so a
/// directory another thread creates with mode 0700 inside the window would
/// come out 0600, which its owner cannot enter. The audit writer's lazily
/// created state directory hit exactly that (`PermissionDenied` on
/// `audit.log`, which fails every authorization closed). With these bits a
/// concurrent create can only lose group/other permissions, never the
/// owner's.
const NARROW_UMASK: libc::mode_t = 0o077;

/// Bind `path` with this process's umask narrowed to [`NARROW_UMASK`] for
/// the `bind(2)` syscall alone, restored immediately after regardless of
/// outcome. The socket node `bind(2)` creates has no mode parameter for
/// `AF_UNIX` (unlike `open(2)`), and `0777 & !0o077` is owner-only (0700), so it
/// is never observable with group or other access, not even for the instant
/// between `bind(2)` and any later `chmod`.
pub(crate) fn bind_with_narrow_umask(path: &Path) -> io::Result<UnixListener> {
    let _guard = UMASK_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: `umask(2)` reads and writes only this process's umask; it
    // touches no memory and cannot fail. The lock above is what makes the
    // save/restore pair race-free against another thread's call to this
    // same function — `umask` itself has no thread-local variant to lean
    // on instead.
    let previous = unsafe { libc::umask(NARROW_UMASK) };
    let result = UnixListener::bind(path);
    unsafe { libc::umask(previous) };
    result
}

/// Whether `stream`'s connecting peer is this process's own euid — the
/// only fact this transport ever authorizes on. Runs before anything is
/// read from the peer.
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

#[cfg(test)]
mod umask_tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

    /// A directory another thread creates with mode 0700 while sockets are
    /// being bound must stay enterable by its owner. With a narrowed umask
    /// that stripped the owner's execute bit, some of these came out 0600.
    #[tokio::test]
    async fn a_bind_never_makes_a_concurrent_private_directory_unenterable() {
        let root = tempfile::tempdir().expect("tempdir");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let maker = {
            let (root, stop) = (root.path().to_path_buf(), stop.clone());
            std::thread::spawn(move || {
                let mut bad = Vec::new();
                let mut n = 0u64;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let dir = root.join(format!("d{n}"));
                    n += 1;
                    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
                    let mode = std::fs::metadata(&dir).unwrap().mode() & 0o777;
                    if mode != 0o700 {
                        bad.push((dir, mode));
                    }
                }
                bad
            })
        };
        let sock_dir = tempfile::tempdir().expect("tempdir");
        for i in 0..300 {
            let path = sock_dir.path().join(format!("s{i}.sock"));
            let _listener = bind_with_narrow_umask(&path).expect("bind");
            let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
            assert_eq!(
                mode & 0o077,
                0,
                "the socket node is owner-only at bind time"
            );
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let bad = maker.join().expect("directory maker");
        assert!(bad.is_empty(), "directories lost owner access: {bad:?}");
    }
}
