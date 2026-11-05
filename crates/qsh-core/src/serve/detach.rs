//! Starting `qsh serve --on-demand` detached from the caller's session
//! (ADR-0051 decision 2), so it outlives the ssh login that asked for it.
//!
//! * unix: `fork`, `setsid`, a second `fork` (the intermediate process exits
//!   and the serve is reparented), standard input/output/error on
//!   `/dev/null`, then `execv`.
//! * Windows: `CreateProcessW` with `CREATE_BREAKAWAY_FROM_JOB |
//!   DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`. Win32-OpenSSH puts a
//!   session's processes in a kill-on-close Job Object that allows breakaway
//!   (measured, ADR-0051 revision of 2026-11-05). When the job refuses
//!   breakaway the serve is started without the flag and
//!   [`DetachedSpawn::breakaway_refused`] says so: it then ends with the ssh
//!   session.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use qsh_proto::ErrorCode;

use super::record::{self, ServeRecord};
use crate::config::{FileLock, Paths, ensure_private_dir, lock_path_for};
use crate::ops::OpError;

/// What [`spawn_detached`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachedSpawn {
    /// Windows only: the Job Object refused `CREATE_BREAKAWAY_FROM_JOB`, so
    /// the child is still inside the caller's job and dies with it. Always
    /// `false` on unix.
    pub breakaway_refused: bool,
}

/// Start `program args...` as a process that has left the caller's session
/// and stays alive when the caller exits. Does not wait for it. Standard
/// input, output and error are the null device.
pub fn spawn_detached(program: &Path, args: &[&OsStr]) -> io::Result<DetachedSpawn> {
    imp::spawn_detached(program, args)
}

#[cfg(unix)]
mod imp {
    use super::DetachedSpawn;
    use std::ffi::{CString, OsStr};
    use std::io;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    fn cstring(value: &OsStr) -> io::Result<CString> {
        CString::new(value.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains a NUL"))
    }

    pub(super) fn spawn_detached(program: &Path, args: &[&OsStr]) -> io::Result<DetachedSpawn> {
        // Everything that allocates happens before the first fork: between
        // `fork` and `execv` this process may only call async-signal-safe
        // functions, because other threads of a multi-threaded caller may
        // have held the allocator's lock at the moment of the fork.
        let program_c = cstring(program.as_os_str())?;
        let mut argv_c = vec![program_c.clone()];
        for arg in args {
            argv_c.push(cstring(arg)?);
        }
        let mut argv: Vec<*const libc::c_char> = argv_c.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        let dev_null = c"/dev/null";

        // SAFETY: the child branch below only calls async-signal-safe
        // functions (`setsid`, `fork`, `_exit`, `open`, `dup2`, `close`,
        // `execv`) on memory prepared above, and never returns.
        let first = unsafe { libc::fork() };
        if first < 0 {
            return Err(io::Error::last_os_error());
        }
        if first == 0 {
            // SAFETY: see above.
            unsafe {
                if libc::setsid() < 0 {
                    libc::_exit(126);
                }
                let second = libc::fork();
                if second != 0 {
                    // The intermediate process (or a failed second fork).
                    libc::_exit(if second < 0 { 125 } else { 0 });
                }
                let fd = libc::open(dev_null.as_ptr(), libc::O_RDWR);
                if fd >= 0 {
                    libc::dup2(fd, 0);
                    libc::dup2(fd, 1);
                    libc::dup2(fd, 2);
                    if fd > 2 {
                        libc::close(fd);
                    }
                }
                libc::execv(program_c.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
        }
        // Reap the intermediate process; the serve is its orphan.
        let mut status: libc::c_int = 0;
        loop {
            // SAFETY: `first` is this process's own child.
            let rc = unsafe { libc::waitpid(first, &mut status, 0) };
            if rc >= 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 0 {
            return Err(io::Error::other(format!(
                "detaching the child failed (status {})",
                libc::WEXITSTATUS(status)
            )));
        }
        Ok(DetachedSpawn {
            breakaway_refused: false,
        })
    }
}

#[cfg(windows)]
mod imp {
    use super::DetachedSpawn;
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED};
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    /// `CREATE_BREAKAWAY_FROM_JOB`.
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

    pub(super) fn spawn_detached(program: &Path, args: &[&OsStr]) -> io::Result<DetachedSpawn> {
        let mut argv = vec![program.to_string_lossy().into_owned()];
        argv.extend(args.iter().map(|a| a.to_string_lossy().into_owned()));
        let command_line = crate::winproc::launch::command_line(&argv);
        let mut wide: Vec<u16> = command_line.encode_wide().collect();
        wide.push(0);
        let application: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();

        let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT;
        match create(&application, &mut wide, base | CREATE_BREAKAWAY_FROM_JOB) {
            Ok(()) => Ok(DetachedSpawn {
                breakaway_refused: false,
            }),
            // A Job Object without `JOB_OBJECT_LIMIT_BREAKAWAY_OK` makes
            // `CreateProcessW` fail with access denied for this flag.
            Err(err) if err.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                create(&application, &mut wide, base)?;
                Ok(DetachedSpawn {
                    breakaway_refused: true,
                })
            }
            Err(err) => Err(err),
        }
    }

    fn create(application: &[u16], command_line: &mut [u16], flags: u32) -> io::Result<()> {
        // SAFETY: both structs are plain C structs for which all-zero is a
        // valid initial value.
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `application` and `command_line` are NUL-terminated UTF-16
        // buffers that outlive the call; no handles are inherited
        // (`bInheritHandles` is FALSE), so the child shares nothing with
        // this process's pipes (`winproc`'s handle-inheritance rule).
        let ok = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                flags,
                std::ptr::null(),
                std::ptr::null(),
                &startup,
                &mut info,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both handles were just returned by `CreateProcessW`.
        unsafe {
            CloseHandle(info.hProcess);
            CloseHandle(info.hThread);
        }
        Ok(())
    }
}

/// A live serve for this user, found or started by [`ensure_on_demand_serve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnDemandServe {
    /// The serve's `serve.json` record.
    pub record: ServeRecord,
    /// `true` when this call started the serve, `false` when one was
    /// already running.
    pub spawned: bool,
    /// Windows only, and only when `spawned`: the serve could not leave the
    /// caller's Job Object and ends with the ssh session.
    pub breakaway_refused: bool,
}

/// How long [`ensure_on_demand_serve`] waits for a new serve to publish
/// `serve.json`.
pub const ON_DEMAND_START_TIMEOUT: Duration = Duration::from_secs(15);

const START_POLL: Duration = Duration::from_millis(50);

/// The live serve for this user, starting `program serve --on-demand`
/// detached when there is none (ADR-0051 decision 2). Blocking: it polls
/// `serve.json` until the new serve has bound a port and published its
/// record, or `timeout` passes (`ErrorCode::Timeout`). Run it from a
/// blocking context.
///
/// Callers are serialised by a lock file next to `serve.json`, so two
/// concurrent bootstraps start one serve, not two.
pub fn ensure_on_demand_serve(
    paths: &Paths,
    program: &Path,
    timeout: Duration,
) -> Result<OnDemandServe, OpError> {
    if let Some(record) = record::live_serve(paths) {
        return Ok(OnDemandServe {
            record,
            spawned: false,
            breakaway_refused: false,
        });
    }
    ensure_private_dir(&paths.state_dir)?;
    let _spawn_lock = FileLock::acquire(&lock_path_for(&paths.state_dir.join("serve.spawn")))?;
    // Another caller may have started one while this one waited for the lock.
    if let Some(record) = record::live_serve(paths) {
        return Ok(OnDemandServe {
            record,
            spawned: false,
            breakaway_refused: false,
        });
    }
    let spawn = spawn_detached(program, &[OsStr::new("serve"), OsStr::new("--on-demand")])
        .map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!(
                    "cannot start `{} serve --on-demand`: {err}",
                    program.display()
                ),
            )
        })?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(record) = record::live_serve(paths) {
            return Ok(OnDemandServe {
                record,
                spawned: true,
                breakaway_refused: spawn.breakaway_refused,
            });
        }
        if Instant::now() >= deadline {
            return Err(OpError::new(
                ErrorCode::Timeout,
                format!(
                    "`qsh serve --on-demand` did not publish {} within {} s",
                    paths.serve_record_file().display(),
                    timeout.as_secs()
                ),
            ));
        }
        std::thread::sleep(START_POLL);
    }
}
