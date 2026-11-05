//! `state_dir/serve.json`: the runtime record of the `qsh serve` running for
//! this user (ADR-0051 decision 2). A serve writes it once it holds its
//! socket and removes it on a clean exit; a reader that finds a pid which is
//! no longer running treats the record as absent, so a crash leaves nothing
//! behind that anyone has to clean up.
//!
//! The file is 0600 (an owner-only DACL on Windows), replaced atomically
//! under a `FileLock` sidecar (`serve.json.lock`). It holds no secret, but
//! it names the port an unauthenticated peer could probe, and every other
//! file in the state directory is private too.

use serde::{Deserialize, Serialize};

use crate::config::{
    FileLock, Paths, ensure_private_dir, lock_path_for, now_rfc3339, write_private_file,
};
use crate::ops::OpError;

/// How the recorded serve was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServeRecordMode {
    /// A foreground or service-managed `qsh serve` that runs until stopped.
    Persistent,
    /// `qsh serve --on-demand`: exits after its idle limit.
    OnDemand,
}

/// The content of `serve.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeRecord {
    /// The serve process.
    pub pid: u32,
    /// The address it actually bound (`[::]:4433`, `0.0.0.0:60001`, ...).
    pub addr: String,
    /// How it was started.
    pub mode: ServeRecordMode,
    /// When it started, RFC 3339 UTC.
    pub started_at: String,
}

impl ServeRecord {
    /// A record for this process.
    pub fn for_current_process(addr: std::net::SocketAddr, mode: ServeRecordMode) -> Self {
        Self {
            pid: std::process::id(),
            addr: addr.to_string(),
            mode,
            started_at: now_rfc3339(),
        }
    }

    /// The recorded address as a socket address, when it parses.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        self.addr.parse().ok()
    }
}

/// Replace `serve.json` with `record`, under the file lock.
pub fn write(paths: &Paths, record: &ServeRecord) -> Result<(), OpError> {
    ensure_private_dir(&paths.state_dir)?;
    let file = paths.serve_record_file();
    let _lock = FileLock::acquire(&lock_path_for(&file))?;
    let body = serde_json::to_vec_pretty(record).map_err(|err| {
        OpError::new(
            qsh_proto::ErrorCode::Internal,
            format!("serialize serve.json: {err}"),
        )
    })?;
    write_private_file(&file, &body)
}

/// The record on disk, whether or not its process is still running. A
/// missing or unparseable file is `None`.
pub fn read(paths: &Paths) -> Option<ServeRecord> {
    let bytes = std::fs::read(paths.serve_record_file()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The `qsh serve` that is running for this user, if any: the record on disk
/// when its pid is a live process. This is what the SSH bootstrap asks before
/// it starts an on-demand serve of its own.
///
/// A recycled pid can make a dead serve's record look live. The caller then
/// finds nothing listening at the address, which is the same outcome as the
/// serve dying right after this call.
pub fn live_serve(paths: &Paths) -> Option<ServeRecord> {
    read(paths).filter(|record| process_is_alive(record.pid))
}

/// Remove `serve.json` if it still names `pid`, under the file lock. A serve
/// whose record a newer serve rewrote leaves the newer record alone.
pub fn remove_if_owned_by(paths: &Paths, pid: u32) {
    let file = paths.serve_record_file();
    let Ok(_lock) = FileLock::acquire(&lock_path_for(&file)) else {
        return;
    };
    if read(paths).is_some_and(|record| record.pid == pid) {
        let _ = std::fs::remove_file(&file);
    }
}

/// Removes this process's record when dropped, so every exit path of a serve
/// that wrote one (success, error, panic unwinding) cleans up.
pub(crate) struct RecordGuard<'a> {
    paths: &'a Paths,
    pid: u32,
}

impl<'a> RecordGuard<'a> {
    pub(crate) fn new(paths: &'a Paths, pid: u32) -> Self {
        Self { paths, pid }
    }
}

impl Drop for RecordGuard<'_> {
    fn drop(&mut self) {
        remove_if_owned_by(self.paths, self.pid);
    }
}

/// Whether `pid` names a running process. Errors that do not say "no such
/// process" (a permission error from another user's pid) count as running.
#[cfg(unix)]
pub(crate) fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 sends nothing; it only checks that the pid exists.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(windows)]
pub(crate) fn process_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    /// `STILL_ACTIVE`, the exit code of a process that has not exited.
    const STILL_ACTIVE: u32 = 259;
    if pid == 0 {
        return false;
    }
    // SAFETY: a plain handle open; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // SAFETY: reads the thread's last error right after the failed call.
        return unsafe { GetLastError() } == ERROR_ACCESS_DENIED;
    }
    let mut code = 0u32;
    // SAFETY: `handle` is a live process handle and `code` a valid out slot.
    let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
    // SAFETY: `handle` was opened above and is not used again.
    unsafe { CloseHandle(handle) };
    ok == 0 || code == STILL_ACTIVE
}
