//! Windows process plumbing: a Job Object that ends a whole process tree,
//! and `CreateProcessW` with an attribute list that puts the child inside
//! that job from the moment it exists (ADR-0035 decision 20). Both the
//! ConPTY backend and host `exec` build on it.
//!
//! Creating the child and assigning it to a job in two steps leaves a window
//! in which it can already have started a grandchild that is not in the job.
//! `PROC_THREAD_ATTRIBUTE_JOB_LIST` closes that window: the process is
//! created inside the job. It is the Windows counterpart of `setsid` +
//! `killpg` on unix. The job carries `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so
//! the tree also ends when this process dies and the last handle to the job
//! closes with it.

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::sync::Arc;

use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::HPCON;
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_JOB_LIST,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, RegisterWaitForSingleObject,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, UnregisterWaitEx, UpdateProcThreadAttribute,
    WT_EXECUTEONLYONCE,
};

/// `io::Error::last_os_error` with the failing call named.
pub(crate) fn os_error(what: &str) -> io::Error {
    let err = io::Error::last_os_error();
    io::Error::new(err.kind(), format!("{what}: {err}"))
}

/// A Job Object that kills every process in it when the last handle to it
/// closes. Cloning is by `Arc`; the tree ends when the last owner drops.
#[derive(Debug)]
pub(crate) struct JobObject {
    handle: OwnedHandle,
}

impl JobObject {
    /// A new anonymous job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    pub(crate) fn new_kill_on_close() -> io::Result<Self> {
        // SAFETY: both arguments are null (default security, no name).
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(os_error("CreateJobObjectW"));
        }
        // SAFETY: `raw` is a fresh handle this function owns.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `info` is a live struct of the size the class expects.
        let ok = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const info).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(os_error("SetInformationJobObject"));
        }
        Ok(Self { handle })
    }

    /// End every process in the job now (`TerminateJobObject`), with
    /// `exit_code` as their exit status.
    pub(crate) fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: the handle is a live job handle owned by `self`.
        if unsafe { TerminateJobObject(self.handle.as_raw_handle(), exit_code) } == 0 {
            return Err(os_error("TerminateJobObject"));
        }
        Ok(())
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }
}

/// What to start. The command line is the full, already quoted string
/// `CreateProcessW` parses. The child inherits this process's environment and
/// working directory.
pub(crate) struct ProcessSpec<'a> {
    pub(crate) command_line: &'a OsStr,
    /// The pseudo-console the child is attached to, if any.
    pub(crate) pseudo_console: Option<HPCON>,
}

/// A started process: its handle and id. The primary thread's handle is
/// closed.
#[derive(Debug)]
pub(crate) struct Process {
    pub(crate) handle: OwnedHandle,
    pub(crate) pid: u32,
}

/// Start `spec` inside `job` with one `CreateProcessW` call.
pub(crate) fn spawn_in_job(job: &JobObject, spec: &ProcessSpec<'_>) -> io::Result<Process> {
    let mut command_line = wide_nul(spec.command_line);
    let job_handles = [job.raw()];

    let attribute_count = 1 + u32::from(spec.pseudo_console.is_some());
    let mut size = 0usize;
    // SAFETY: the sizing call takes a null list and writes only `size`; it
    // reports failure (`ERROR_INSUFFICIENT_BUFFER`) by design.
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), attribute_count, 0, &mut size);
    }
    if size == 0 {
        return Err(os_error("InitializeProcThreadAttributeList (size)"));
    }
    // `u64` elements keep the buffer 8-byte aligned, as the list requires.
    let mut storage = vec![0u64; size.div_ceil(8)];
    let list = storage.as_mut_ptr().cast::<c_void>();
    // SAFETY: `list` points at `size` writable bytes.
    if unsafe { InitializeProcThreadAttributeList(list, attribute_count, 0, &mut size) } == 0 {
        return Err(os_error("InitializeProcThreadAttributeList"));
    }
    let _delete = DeleteList(list);

    // SAFETY: `job_handles` outlives the `CreateProcessW` call below, which
    // is the last use of the attribute list.
    let ok = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            job_handles.as_ptr().cast::<c_void>(),
            size_of_val(&job_handles),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    if ok == 0 {
        return Err(os_error("UpdateProcThreadAttribute(JOB_LIST)"));
    }
    if let Some(console) = spec.pseudo_console {
        // The attribute value is the pseudo-console handle itself, not a
        // pointer to it.
        // SAFETY: `console` is a live pseudo-console handle.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                console as *const c_void,
                size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(os_error("UpdateProcThreadAttribute(PSEUDOCONSOLE)"));
        }
    }

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    if spec.pseudo_console.is_some() {
        // A child attached to a pseudo-console takes its standard handles
        // from it only when the startup info says it has none of its own.
        // Without this it keeps this process's redirected handles (a service
        // or a test runner has pipes there) and writes past the console.
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
        startup.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
        startup.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    }
    startup.lpAttributeList = list;
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: the command line is a writable NUL-terminated buffer; `startup`
    // and `info` are live; the attribute list is initialised and holds the
    // job and console.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            std::ptr::null(),
            (&raw const startup).cast(),
            &mut info,
        )
    };
    if ok == 0 {
        return Err(os_error("CreateProcessW"));
    }
    // SAFETY: both handles are fresh and owned here; the thread handle is
    // not needed and closes on drop.
    let (handle, _thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };
    Ok(Process {
        handle,
        pid: info.dwProcessId,
    })
}

/// Deletes an initialised attribute list on drop.
struct DeleteList(*mut c_void);

impl Drop for DeleteList {
    fn drop(&mut self) {
        // SAFETY: the list was initialised and its storage is still alive:
        // the guard is declared after the storage in `spawn_in_job`.
        unsafe { DeleteProcThreadAttributeList(self.0) };
    }
}

fn wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// The exit status of a process that has ended.
pub(crate) fn exit_code(process: &OwnedHandle) -> io::Result<u32> {
    let mut code = 0u32;
    // SAFETY: a live process handle and a local out-pointer.
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
        return Err(os_error("GetExitCodeProcess"));
    }
    Ok(code)
}

/// Resolves when a process handle becomes signalled (the process ended),
/// without a thread parked on it: the wait is registered with the system
/// thread pool and its callback sends on a channel.
pub(crate) struct ExitWatch {
    rx: oneshot::Receiver<()>,
    registration: Registration,
}

struct Registration {
    wait: HANDLE,
    /// Heap cell the callback takes the sender out of. Freed only after the
    /// blocking unregistration, when no callback can be running.
    cell: *mut Option<oneshot::Sender<()>>,
    /// Keeps the watched handle open until the wait is unregistered.
    _process: Arc<OwnedHandle>,
}

// SAFETY: `wait` and `cell` are only touched by the owner (`Drop`) and by
// the callback through `cell`, which is a plain `Option` the callback takes
// once; the registration APIs are thread-safe.
unsafe impl Send for Registration {}

unsafe extern "system" fn on_exit(context: *mut c_void, _timed_out: bool) {
    let cell = context.cast::<Option<oneshot::Sender<()>>>();
    // SAFETY: `cell` stays allocated until `Registration::drop` has
    // unregistered the wait and so waited for this callback to return.
    if let Some(tx) = unsafe { (*cell).take() } {
        let _ = tx.send(());
    }
}

impl ExitWatch {
    /// Watch `process` for its end.
    pub(crate) fn new(process: Arc<OwnedHandle>) -> io::Result<Self> {
        let (tx, rx) = oneshot::channel();
        let cell = Box::into_raw(Box::new(Some(tx)));
        let mut wait: HANDLE = std::ptr::null_mut();
        // SAFETY: `process` is a live handle kept open by the registration;
        // `cell` is a valid heap pointer for the callback's lifetime.
        let ok = unsafe {
            RegisterWaitForSingleObject(
                &mut wait,
                process.as_raw_handle(),
                Some(on_exit),
                cell.cast::<c_void>(),
                u32::MAX,
                WT_EXECUTEONLYONCE,
            )
        };
        if ok == 0 {
            let err = os_error("RegisterWaitForSingleObject");
            // SAFETY: registration failed, so no callback can hold `cell`.
            drop(unsafe { Box::from_raw(cell) });
            return Err(err);
        }
        Ok(Self {
            rx,
            registration: Registration {
                wait,
                cell,
                _process: process,
            },
        })
    }

    /// Wait for the process to end.
    pub(crate) async fn exited(self) {
        let Self { rx, registration } = self;
        // The sender is only dropped unsent when the registration is gone,
        // which cannot happen while `registration` is alive here.
        let _ = rx.await;
        drop(registration);
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // SAFETY: `INVALID_HANDLE_VALUE` makes the call wait for a running
        // callback to finish; afterwards nothing references `cell`.
        unsafe {
            UnregisterWaitEx(self.wait, INVALID_HANDLE_VALUE);
            drop(Box::from_raw(self.cell));
        }
    }
}
