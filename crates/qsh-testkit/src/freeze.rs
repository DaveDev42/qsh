//! Stop a process without ending it: the Windows counterpart of `SIGSTOP`
//! and `SIGCONT`.
//!
//! A test that wants a peer to go silent, not to go away (a host that
//! acknowledges nothing, a SOCKS proxy that stalls mid-handshake), freezes
//! the peer's process. Windows has no signal for it, so every thread of the
//! process is suspended with `SuspendThread` and resumed when the
//! [`Frozen`] guard is dropped (`docs/design/testing.md`).

use std::collections::HashSet;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
};

/// A process whose threads are all suspended. Dropping the guard resumes
/// them.
pub struct Frozen {
    threads: Vec<HANDLE>,
}

// SAFETY: a thread handle is a kernel object reference and may be used from
// any thread of this process.
unsafe impl Send for Frozen {}

/// The ids of the threads `pid` has right now.
fn thread_ids(pid: u32) -> Vec<u32> {
    let mut ids = Vec::new();
    // SAFETY: a snapshot handle is checked before use and closed after it;
    // `entry` is a plain struct with `dwSize` set as the API requires.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return ids;
        }
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut more = Thread32First(snapshot, &mut entry) != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                ids.push(entry.th32ThreadID);
            }
            more = Thread32Next(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    ids
}

/// Suspend every thread of `pid`, including the ones it starts while this
/// runs, and return only when a full pass finds no thread left to suspend.
/// Panics if the process has no thread to suspend.
pub fn freeze(pid: u32) -> Frozen {
    let mut frozen = Frozen {
        threads: Vec::new(),
    };
    let mut seen: HashSet<u32> = HashSet::new();
    loop {
        let fresh: Vec<u32> = thread_ids(pid)
            .into_iter()
            .filter(|id| seen.insert(*id))
            .collect();
        if fresh.is_empty() {
            break;
        }
        for id in fresh {
            // SAFETY: the handle is checked, kept in `frozen` and closed in
            // its `Drop`.
            unsafe {
                let handle = OpenThread(THREAD_SUSPEND_RESUME, 0, id);
                if handle.is_null() {
                    // The thread ended between the snapshot and the open.
                    continue;
                }
                if SuspendThread(handle) == u32::MAX {
                    CloseHandle(handle);
                    continue;
                }
                frozen.threads.push(handle);
            }
        }
    }
    assert!(
        !frozen.threads.is_empty(),
        "process {pid} has no thread to suspend"
    );
    frozen
}

impl Drop for Frozen {
    fn drop(&mut self) {
        for handle in self.threads.drain(..) {
            // SAFETY: each handle came from `OpenThread` and is released
            // exactly once.
            unsafe {
                ResumeThread(handle);
                CloseHandle(handle);
            }
        }
    }
}
