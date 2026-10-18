//! Pipes between this process and a child it starts: the host's end is an
//! overlapped named pipe read and written through tokio, the child's end is
//! a plain synchronous handle (`conhost`'s or a program's standard handle),
//! because those do blocking I/O on it. An anonymous pipe has no overlapped
//! mode, which is why the host's end is a named pipe: no thread is parked on
//! a read per child.
//!
//! The name carries 128 random bits and the DACL lets only the account that
//! runs this process open it, so no other local user can attach to a
//! session's or an exec's I/O.

use std::fs::OpenOptions;
use std::future::Future as _;
use std::io;
use std::os::windows::io::OwnedHandle;
use std::task::{Context, Poll, Waker};

use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};

use crate::fsutil::dacl::{CurrentUser, DaclSource as _, ObjectKind};

/// Buffer size of both directions of a host pipe.
const PIPE_BUFFER: u32 = 64 * 1024;

/// A pipe between this process and a child: the host's overlapped end, and
/// the synchronous end the child gets.
pub(crate) struct HostPipe {
    pub(crate) host: NamedPipeServer,
    pub(crate) child: OwnedHandle,
}

/// Create an owner-only pipe under an unguessable name. `host_reads` is the
/// direction: the child writes and the host reads (output), or the host
/// writes (input).
pub(crate) fn host_pipe(host_reads: bool) -> io::Result<HostPipe> {
    let name = format!(r"\\.\pipe\qsh-host-{:032x}", rand::random::<u128>());
    let descriptor = CurrentUser.owner_only(ObjectKind::Pipe)?;
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte)
        .max_instances(1)
        .access_inbound(host_reads)
        .access_outbound(!host_reads)
        .in_buffer_size(PIPE_BUFFER)
        .out_buffer_size(PIPE_BUFFER);
    // SAFETY: the attributes point at a descriptor owned by `descriptor`,
    // which outlives the call; the kernel copies it.
    let host =
        unsafe { options.create_with_security_attributes_raw(&name, descriptor.attributes_ptr()) }?;
    // Synchronous open (no overlapped flag): the child does blocking I/O on
    // it. Not inheritable until a caller asks.
    let child = OpenOptions::new()
        .read(!host_reads)
        .write(host_reads)
        .open(&name)?;
    mark_connected(&host)?;
    Ok(HostPipe {
        host,
        child: OwnedHandle::from(child),
    })
}

/// Tell the reactor the host end is connected, so it starts servicing reads
/// and writes. The client is already attached (we opened it above), so
/// `ConnectNamedPipe` completes at once with `ERROR_PIPE_CONNECTED` and
/// `connect()` is ready on its first poll; polling it once here keeps the
/// callers synchronous.
fn mark_connected(host: &NamedPipeServer) -> io::Result<()> {
    let mut cx = Context::from_waker(Waker::noop());
    match std::pin::pin!(host.connect()).poll(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(io::Error::other(
            "the host pipe did not report its client as connected",
        )),
    }
}

/// Set or clear the inheritable flag of `handle`, so it can be named in the
/// handle list of a `CreateProcessW` call. Only `winproc::spawn_in_job` calls
/// this, under the spawn lock (see the `winproc` module doc); tests set a
/// flag on a handle of their own.
pub(crate) fn set_inheritable(handle: HANDLE, on: bool) -> io::Result<()> {
    // SAFETY: a live handle owned by the caller.
    let ok = unsafe {
        SetHandleInformation(
            handle,
            HANDLE_FLAG_INHERIT,
            if on { HANDLE_FLAG_INHERIT } else { 0 },
        )
    };
    if ok == 0 {
        return Err(super::os_error("SetHandleInformation"));
    }
    Ok(())
}
