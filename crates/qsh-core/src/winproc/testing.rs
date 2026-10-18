//! Helpers for the Windows process tests: what the kernel says is in a job,
//! and whether a set of processes has ended. They observe the job object
//! itself, which lists a process from the moment it is created in the job,
//! so unlike a Toolhelp snapshot they do not race a child that has not
//! finished starting.

use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::JobObjects::{
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JobObjectBasicProcessIdList, QueryInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

use super::JobObject;

/// The pids in `job`, as the kernel lists them.
pub(crate) fn job_pids(job: &JobObject) -> Vec<u32> {
    // The list header is two u32 counts, then one pointer-sized id each.
    let mut buf = vec![0usize; 1 + 64];
    let mut returned = 0u32;
    // SAFETY: `buf` is a writable buffer of the length passed.
    let ok = unsafe {
        QueryInformationJobObject(
            job.raw(),
            JobObjectBasicProcessIdList,
            buf.as_mut_ptr().cast(),
            (buf.len() * size_of::<usize>()) as u32,
            &mut returned,
        )
    };
    assert_ne!(ok, 0, "QueryInformationJobObject failed");
    // SAFETY: the kernel filled the header it is reinterpreted as.
    let header = unsafe { &*buf.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
    let n = header.NumberOfProcessIdsInList as usize;
    buf[1..].iter().take(n).map(|&id| id as u32).collect()
}

/// A handle to each of `pids`, so a pid cannot be reused while a test waits
/// on it.
pub(crate) fn open_members(pids: &[u32]) -> Vec<OwnedHandle> {
    pids.iter()
        .map(|&pid| {
            // SAFETY: `OpenProcess` returns a fresh handle or null.
            let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert!(!h.is_null(), "OpenProcess({pid}) failed");
            // SAFETY: the handle is fresh and owned here.
            unsafe { OwnedHandle::from_raw_handle(h) }
        })
        .collect()
}

/// Every process in `members` has ended (within the hard bound).
pub(crate) fn assert_all_ended(members: &[OwnedHandle], pids: &[u32], what: &str) {
    for (pid, member) in pids.iter().zip(members) {
        // SAFETY: a live handle.
        let state = unsafe { WaitForSingleObject(member.as_raw_handle(), 30_000) };
        assert_eq!(state, WAIT_OBJECT_0, "process {pid} survived {what}");
    }
}
