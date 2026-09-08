//! Shared filesystem helpers for every private-file writer in this crate
//! (`PLAN.md` M7 Step 7-2 carryover (iv)): one atomic-write implementation
//! instead of the pid+ticket temp-file dance living twice
//! (`config::write_private_file_io` and `resume`'s durable session-file
//! writer used to each hand-roll it), and the stale-temp-file sweep that
//! cleans up whichever of those two ever gets orphaned by a crash between
//! the temp write and the rename.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Ticket source for [`write_atomically`]'s temp file name — unique per
/// *writer*, not just per process. Two writers in the same process
/// (`qsh serve` spawns a `tokio::spawn` task per inbound connection, and
/// two pairing responses can land at once) racing the same `path` with a
/// pid-only temp name would truncate/interleave each other's bytes — not
/// a lost update but a **corrupt file**, which is a strictly worse
/// failure for a TOML store than either writer's update going missing.
///
/// One counter shared by every caller (plain `write_private_file` and
/// `resume`'s durable variant alike): the two used to keep separate
/// statics, which meant nothing about the name space was actually shared
/// except the string format. A single source is simpler and loses
/// nothing — the tests that predict a ticket
/// (`ca::init`/`identity::promote_to_ca_issued`'s
/// `*_recovers_from_an_interrupted_*_write`) only ever run one writer at
/// a time under `cargo nextest run`'s process isolation.
static WRITE_TICKET: AtomicU64 = AtomicU64::new(0);

/// The ticket [`write_atomically`]'s *next* call will consume. Lets a
/// crash-safety test predict the exact temp path a write will use without
/// racing the write itself (`ca::init`'s and
/// `identity::promote_to_ca_issued`'s `*_recovers_from_an_interrupted_*_write`
/// tests block a specific temp path with a directory to force that write
/// to fail).
///
/// Sound only under a **process-isolated test runner** (`cargo nextest
/// run`, this repo's required one — `.github/workflows/ci.yml`): under
/// plain `cargo test`'s in-process, thread-parallel execution, a sibling
/// test that also calls [`write_atomically`] can consume a ticket between
/// this read and the write it's predicting for.
#[cfg(test)]
pub(crate) fn next_write_ticket_for_test() -> u64 {
    WRITE_TICKET.load(Ordering::Relaxed)
}

/// Write `contents` to `path` with mode 0600, atomically (temp file in the
/// same directory + rename) so a crash never leaves a half-written key,
/// certificate or store.
///
/// `durable`: when true, `fsync`s the temp file before the rename (same
/// as the non-durable path) **and**, on unix, `fsync`s the containing
/// directory after the rename too, so the rename itself survives a crash
/// — `resume`'s session credentials need that; the rest of this crate's
/// private files stop one step short of it, same as before this helper
/// existed.
pub(crate) fn write_atomically(path: &Path, contents: &[u8], durable: bool) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let ticket = WRITE_TICKET.fetch_add(1, Ordering::Relaxed);
    let tmp = temp_path(dir, file_name, std::process::id(), ticket);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let result = (|| -> io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        // `OpenOptions::mode` is ignored for a pre-existing file; re-assert.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if durable {
            // Durability of the rename itself: fsync the directory entry,
            // not just the file's own contents. Never propagated (REVIEW-5-A
            // A1) — a filesystem that refuses directory fsync (some network
            // filesystems) must not break the write that already landed;
            // the only thing lost is "retry instead of an orphaned session"
            // (`resume.rs`'s own doc on `durable`), not the write itself.
            // `tracing::warn!` is the visible trail for whoever is
            // debugging a host that hits this.
            match std::fs::File::open(dir) {
                Ok(dir_handle) => {
                    if let Err(e) = dir_handle.sync_all() {
                        tracing::warn!(
                            target: "qsh_core::fsutil",
                            error = %e,
                            dir = %dir.display(),
                            "fsync of the containing directory failed after a durable rename"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "qsh_core::fsutil",
                        error = %e,
                        dir = %dir.display(),
                        "could not open the containing directory to fsync after a durable rename"
                    );
                }
            }
        }
        // On non-unix there is no directory-fsync step to gate on `durable`
        // at all (the rename itself is the only durability primitive
        // available), so the parameter is intentionally unused there.
        #[cfg(not(unix))]
        let _ = durable;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Build the exact temp-file name [`write_atomically`] writes to:
/// `{file_name}.tmp{pid}-{ticket}` — the pattern predates this module
/// (`PLAN.md` M7 Step 7-1) and stays byte-identical so nothing downstream
/// (the crash-safety tests above, this module's own sweep) has to learn a
/// second format.
fn temp_path(dir: &Path, file_name: &std::ffi::OsStr, pid: u32, ticket: u64) -> std::path::PathBuf {
    let mut tmp = dir.join(file_name);
    tmp.as_mut_os_string().push(format!(".tmp{pid}-{ticket}"));
    tmp
}

/// Parse a directory entry's file name as a [`write_atomically`] temp
/// file's `{pid}-{ticket}` suffix, if it has one. `None` for anything
/// that doesn't look like one of ours — a real config file, a `.corrupt`
/// aside (`resume.rs`), or garbage — so the sweep below only ever touches
/// what it created.
fn parse_temp_suffix(file_name: &str) -> Option<u32> {
    let idx = file_name.rfind(".tmp")?;
    let rest = &file_name[idx + 4..];
    let (pid_str, ticket_str) = rest.split_once('-')?;
    if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if ticket_str.is_empty() || !ticket_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid_str.parse::<u32>().ok()
}

/// How old a `write_atomically` temp file must be before the sweep will
/// even consider it — a live writer's own in-flight temp file (between
/// `open` and `rename`, normally microseconds) must never be a sweep
/// target just because another process's stale one shares the directory.
const STALE_AGE: Duration = Duration::from_secs(60 * 60);

/// The second, unconditional threshold (REVIEW-5-A A6/A7, ARBITRATION-5
/// 적대 검토 A 판정: 채택). A crash is normally followed by a restart, and
/// often a reboot — after a reboot the crashed writer's pid is drawn from
/// a fresh pid space and can be alive again as a completely unrelated
/// process, at which point [`process_is_dead`]'s `ESRCH` check never
/// fires again and the orphan would sit forever under [`STALE_AGE`]
/// alone. Past this age the sweep deletes regardless of what
/// [`process_is_dead`] reports: `write_atomically`'s open→rename window
/// is microseconds, so no genuine live writer ever holds an unrenamed
/// temp file this long. Applies on every platform, including non-unix,
/// where [`process_is_dead`] can never prove death at all.
const STALE_AGE_ANY_WRITER: Duration = Duration::from_secs(24 * 60 * 60);

/// Remove orphaned [`write_atomically`] temp files from `dir`: a file
/// matching the `{name}.tmp{pid}-{ticket}` pattern is deleted when
/// **either** holds — its mtime is older than
/// [`STALE_AGE_ANY_WRITER`] (24h, no liveness proof required), or its
/// mtime is older than [`STALE_AGE`] (1h) **and** its writer's pid is
/// provably dead (unix: `kill(pid, 0)` reports `ESRCH`; non-unix has no
/// such check, so this half can never be satisfied there — see
/// [`process_is_dead`]). A crash mid-write leaves exactly this kind of
/// file behind (`ca::init`'s and `identity::promote_to_ca_issued`'s own
/// tests simulate the same shape); a live writer's own temp file under
/// 24h old fails both halves and is left alone.
///
/// Called from each private directory's own init path (`ca::init`,
/// `identity::init`, `resume`'s session-store `update`), so it runs
/// wherever [`super::config::ensure_private_dir`] already runs for that
/// directory — not on a timer, and not a second directory walk on top of
/// what those call sites do already.
///
/// Best-effort: an unreadable directory or a file that vanishes between
/// listing and delete is silently skipped, never an error — the sweep is
/// housekeeping, not a precondition for the write that follows it.
pub(crate) fn sweep_stale_temp_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(pid) = parse_temp_suffix(name) else {
            continue;
        };
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Ok(age) = now.duration_since(modified) else {
            continue; // mtime in the future (clock skew) — not stale.
        };
        let sweepable = age >= STALE_AGE_ANY_WRITER || (age >= STALE_AGE && process_is_dead(pid));
        if !sweepable {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::debug!(
            target: "qsh_core::fsutil",
            removed,
            dir = %dir.display(),
            "swept stale temp files"
        );
    }
    removed
}

/// Whether `pid` is provably not a live process any more. Unix only:
/// signal `0` (`man 2 kill`) delivers nothing, only performs the
/// existence/permission check, so this touches no other process' state.
/// `ESRCH` ("no such process") is the only outcome that counts as proof
/// of death — a permission error (a different uid holding that pid) or
/// success both leave the file alone, because deleting a live writer's
/// in-flight temp file is a worse failure than leaving a truly stale one
/// for the next sweep. This proof is not forever-reachable: after a
/// reboot the dead writer's pid can be reused by an unrelated live
/// process, and `ESRCH` never fires again for that file — [`STALE_AGE_ANY_WRITER`]
/// is what eventually reclaims an orphan this check can no longer clear
/// (REVIEW-5-A A6).
///
/// Non-unix has no equivalent liveness check available here, so this
/// always reports "not proven dead" (REVIEW-5-A A7) — on that platform
/// only [`STALE_AGE_ANY_WRITER`] ever sweeps a temp file;
/// [`sweep_stale_temp_files`]'s `STALE_AGE`-plus-liveness branch is
/// unreachable there.
#[cfg(unix)]
fn process_is_dead(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return true;
    };
    // SAFETY: signal 0 sends no signal; it only performs the
    // existence/permission check documented above.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return false;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(not(unix))]
fn process_is_dead(_pid: u32) -> bool {
    // No proof of death is available on this platform at all (REVIEW-5-A
    // A7) — the old `true` here made every temp file older than
    // `STALE_AGE` (1h) sweepable regardless of whether its writer was
    // still running, which is exactly backwards: "no evidence either way"
    // must not be treated as "proven dead". `STALE_AGE_ANY_WRITER` (24h,
    // unconditional) is the only threshold that reclaims an orphan here.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_stale(dir: &Path, base: &str, pid: u32, ticket: u64) -> std::path::PathBuf {
        let path = temp_path(dir, std::ffi::OsStr::new(base), pid, ticket);
        std::fs::write(&path, b"leftover").unwrap();
        path
    }

    fn age_by(path: &Path, age: Duration) {
        let modified = SystemTime::now() - age;
        // `File::open` only requests read access (`GENERIC_READ` on
        // Windows), and `set_modified` calls `SetFileTime` on that same
        // handle without reopening it — which needs `FILE_WRITE_ATTRIBUTES`,
        // a bit `GENERIC_READ` does not carry. `std`'s own path-based
        // `fs::set_times` reopens with `FILE_WRITE_ATTRIBUTES` for exactly
        // this reason; do the same here or Windows CI fails every test that
        // calls this helper with `ERROR_ACCESS_DENIED` (REVIEW-5-C C1).
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }

    #[test]
    fn write_atomically_round_trips_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.toml");
        write_atomically(&path, b"hello", false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file must survive a successful write"
        );
    }

    #[test]
    #[cfg(unix)]
    fn sweep_removes_a_dead_pid_old_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        // A pid essentially guaranteed not to be alive on any real machine.
        let dead_pid = u32::MAX - 1;
        let path = write_stale(dir.path(), "config.toml", dead_pid, 7);
        age_by(&path, STALE_AGE + Duration::from_secs(60));

        let removed = sweep_stale_temp_files(dir.path());

        assert_eq!(removed, 1);
        assert!(
            !path.exists(),
            "a dead writer's stale temp file must be swept"
        );
    }

    /// REVIEW-5-A A6/A7: past [`STALE_AGE_ANY_WRITER`] the sweep no longer
    /// asks `process_is_dead` at all — even a live (this test's own) pid's
    /// temp file is deleted once it is old enough, on every platform (not
    /// `#[cfg(unix)]`: non-unix's `process_is_dead` always answers "not
    /// proven dead", so this is the *only* path that ever sweeps there).
    /// The 2h leg pins that the pre-existing 1h/ESRCH behavior is
    /// untouched below the new threshold.
    #[test]
    fn sweep_ignores_a_live_pids_temp_file_under_24h_but_removes_it_past_24h() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_stale(dir.path(), "config.toml", std::process::id(), 100);

        age_by(&path, Duration::from_secs(2 * 60 * 60));
        assert_eq!(
            sweep_stale_temp_files(dir.path()),
            0,
            "a live writer's 2h-old temp file must survive"
        );
        assert!(path.exists());

        age_by(&path, STALE_AGE_ANY_WRITER + Duration::from_secs(60));
        let removed = sweep_stale_temp_files(dir.path());
        assert_eq!(
            removed, 1,
            "STALE_AGE_ANY_WRITER must delete even a live pid's temp file"
        );
        assert!(!path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn sweep_leaves_a_live_pids_old_temp_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_stale(dir.path(), "config.toml", std::process::id(), 7);
        age_by(&path, STALE_AGE + Duration::from_secs(60));

        let removed = sweep_stale_temp_files(dir.path());

        assert_eq!(removed, 0);
        assert!(
            path.exists(),
            "a live writer's temp file must survive even when old"
        );
    }

    #[test]
    fn sweep_leaves_a_recent_dead_pid_temp_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let dead_pid = u32::MAX - 1;
        let path = write_stale(dir.path(), "config.toml", dead_pid, 7);
        // No `age_by` call: mtime stays "now", well under `STALE_AGE`.

        let removed = sweep_stale_temp_files(dir.path());

        assert_eq!(removed, 0);
        assert!(
            path.exists(),
            "a fresh temp file must survive regardless of pid liveness"
        );
    }

    #[test]
    fn sweep_ignores_files_that_do_not_match_the_temp_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let ordinary = dir.path().join("config.toml");
        std::fs::write(&ordinary, b"data").unwrap();
        age_by(&ordinary, STALE_AGE + Duration::from_secs(60));
        let corrupt_aside = dir.path().join("resume.json.corrupt");
        std::fs::write(&corrupt_aside, b"data").unwrap();
        age_by(&corrupt_aside, STALE_AGE + Duration::from_secs(60));

        let removed = sweep_stale_temp_files(dir.path());

        assert_eq!(removed, 0);
        assert!(ordinary.exists());
        assert!(corrupt_aside.exists());
    }

    #[test]
    fn parse_temp_suffix_accepts_only_the_pid_ticket_shape() {
        assert_eq!(parse_temp_suffix("config.toml.tmp1234-7"), Some(1234));
        assert_eq!(parse_temp_suffix("config.toml"), None);
        assert_eq!(parse_temp_suffix("config.toml.tmp-7"), None);
        assert_eq!(parse_temp_suffix("config.toml.tmp1234-"), None);
        assert_eq!(parse_temp_suffix("config.toml.tmpabc-7"), None);
        assert_eq!(parse_temp_suffix("resume.json.corrupt"), None);
    }

    /// REVIEW-5-A A1: `durable` is the only behavioral difference between
    /// the two writers this module merged (`config::write_private_file_io`
    /// and `resume`'s durable session-file writer), and fsync itself is not
    /// observable in-process (no crash-injection harness here). A
    /// source-text pin — the same precedent
    /// `tests/acl_registry.rs::authorize_stream_has_exactly_two_production_call_sites`
    /// uses for an unobservable property — turns a future edit that
    /// silently flips `resume.rs`'s `true` to `false`, or drops the call
    /// entirely, into a failing test instead of a silent durability
    /// regression in the resume credential store.
    #[test]
    fn resume_and_config_pin_opposite_durable_arguments_in_their_source() {
        let resume_src = include_str!("resume.rs");
        let config_src = include_str!("config.rs");
        assert_eq!(
            resume_src
                .matches("write_atomically(path, body, true)")
                .count(),
            1,
            "resume.rs must call write_atomically with durable = true exactly once"
        );
        assert_eq!(
            config_src
                .matches("write_atomically(path, contents, false)")
                .count(),
            1,
            "config.rs must call write_atomically with durable = false exactly once"
        );
    }

    /// REVIEW-5-A A1: the `durable` branch (mutation m5) had zero coverage
    /// — nothing exercised it at all. This does not (cannot, without crash
    /// injection) prove the fsyncs happen; it proves the branch runs and
    /// still produces a correct file, so the source pin above is the thing
    /// actually closing the mutation-survival gap, and this is what keeps
    /// the `durable = true` path from being merely uncompiled dead code.
    #[test]
    fn write_atomically_round_trips_when_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resume.json");
        write_atomically(&path, b"x", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }

    /// REVIEW-5-A A2 (mutation m9, survived): `OpenOptions::mode(0o600)` is
    /// ignored when the temp file already exists, so the `set_permissions`
    /// re-assertion is the only thing that closes that hole — reachable on
    /// a pid-reuse restart, where `WRITE_TICKET` restarts at 0 and
    /// regenerates the identical temp path a prior process left behind.
    /// Pre-creates the exact path `write_atomically`'s next call will use
    /// (via [`next_write_ticket_for_test`], same predicted-path trick
    /// `ca::init`'s own crash-safety tests use) with a wrong (0o644) mode,
    /// then asserts the final file lands at 0o600 regardless.
    #[test]
    #[cfg(unix)]
    fn write_atomically_reasserts_0600_on_a_pre_existing_temp_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.toml");
        let ticket = next_write_ticket_for_test();
        let tmp = temp_path(
            dir.path(),
            std::ffi::OsStr::new("thing.toml"),
            std::process::id(),
            ticket,
        );
        std::fs::write(&tmp, b"leftover").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_atomically(&path, b"final", false).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a pre-existing temp file's mode must be re-asserted to 0600"
        );
    }
}
