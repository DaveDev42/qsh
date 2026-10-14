//! The `FILE_DATA` data plane of the remote file ops (`docs/adr/0029-file-copy.md`
//! decisions 7, 9, 10, 11, 13 and 15), unix only. The control plane
//! (`file_host.rs`) already authorized the request, opened and rechecked the
//! handle and issued a ticket; this file runs the stream that redeems it.
//!
//! Nothing here decides policy and nothing here writes an audit line: the
//! authorization was the control request's, and audit records are decisions,
//! never transfers (decision 14). What this file owns is the transfer's state
//! machine and its cleanup.
//!
//! **`file.read`.** The host sends `data` chunks of at most `FILE_CHUNK_MAX`
//! and then one `end{size, blake3}` carrying what it actually sent, then
//! finishes. The file is read on a blocking thread one chunk ahead of the
//! network, the send runs in band 0 and yields every `SEND_DEPTH_CAP_BYTES`
//! (the tunnel splice's discipline, decision 15).
//!
//! **`file.write`.** The requester sends `data` chunks, `end`, and finishes
//! its send half. The host writes them to a temp file `.<name>.qsh-<16
//! hex>.part` created through the destination directory fd (never visible
//! under the final name), hashes what it wrote, and only when the size and
//! the BLAKE3-256 agree with `end` (and with the size announced in
//! `FileWriteOpen`) does it `fsync`, set the final mode and time, and replace
//! the destination with `renameat` (or `linkat` + `unlinkat` for
//! `--no-clobber`, so a destination that appeared in the meantime is never
//! overwritten), then `fsync` the directory and answer one `result` frame.
//! Whatever else happens (a mismatch, a cancelled or lost stream, a protocol
//! violation, the stall ledger stopping the stream, a task dropped mid-flight)
//! the temp file is removed ([`TempGuard`]) and the destination is exactly as
//! it was.
//!
//! **Stall ledger.** The receiving side of a `file.write` is the local write
//! (the hand-off to the disk writer), which is what ADR-0037's ledger watches
//! on a tunnel: a stream whose hand-off makes no progress for `STALL_AGE`
//! holds its receive window and, with enough such streams, the connection's.
//! The pump registers one [`StallWatch`] per write and ends with
//! `RESET_CODE_TUNNEL_STALLED` when the ledger picks it. A `file.read` registers
//! too, only so its bytes count as traffic; its send side never enters a
//! local write, so the ledger cannot pick it.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};

use qsh_proto::wire::{FILE_CHUNK_MAX, FileEnd, FileFrame, file_frame};
use qsh_transport::{FramedRecv, FramedSend, FramedStream, StreamError};
use tokio::sync::mpsc;

use super::file_host::file_io_error;
use super::*;
use crate::file::host::{self, FsKind, StatInfo, WriteGate};
use crate::quota::FilePermit;
use crate::tunnel::splice::{RESET_CODE_TUNNEL_ABORT, SEND_DEPTH_CAP_BYTES};
use crate::tunnel::stall::{RESET_CODE_TUNNEL_STALLED, StallWatch, StreamTrack};

/// Chunks queued between the stream and the disk. Small on purpose: a disk
/// that stops taking chunks must back up into the stream's receive window
/// quickly (where the stall ledger can see it), not into memory.
const DISK_QUEUE_CHUNKS: usize = 4;

/// How long the host waits, after `end`, for the requester to finish its send
/// half. A requester that sends `end` and then neither finishes nor sends
/// anything else is not a conforming one (decision 9), and its temp file and
/// transfer slot are not held for it.
const END_FINISH_GRACE: Duration = Duration::from_secs(10);

/// What a redeemed `file.write` ticket carries (the fields of
/// [`PendingFileOp::Write`]).
struct WriteJob {
    dir: File,
    name: OsString,
    size: u64,
    mode: u32,
    overwrite: bool,
    preserve: bool,
    mtime: i64,
}

impl Server {
    /// Run the `FILE_DATA` stream a ticket was redeemed by. Consumes the
    /// stream: on return its send half has been finished or reset and
    /// everything the ticket held (the opened handle, the transfer slot) is
    /// released.
    pub(super) async fn run_file_data(
        &self,
        conn: &Connection,
        stream: FramedStream,
        pending: PendingFile,
    ) {
        let PendingFile { op, permit } = pending;
        let (send, recv) = stream.split();
        // Band 0 (`docs/design/protocol.md` §12): a file transfer must not
        // outrank the PTY in this host's own send queue.
        send.set_priority(wire::PRIORITY_TUNNEL);
        match op {
            PendingFileOp::Read { file, .. } => serve_read(conn, send, recv, file, permit).await,
            PendingFileOp::Write {
                dir,
                name,
                size,
                mode,
                overwrite,
                preserve,
                mtime,
                existed: _,
            } => {
                let job = WriteJob {
                    dir,
                    name,
                    size,
                    mode,
                    overwrite,
                    preserve,
                    mtime,
                };
                let gate = self.file_write_gate.get().cloned();
                serve_write(gate, conn, send, recv, job, permit).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// file.read
// ---------------------------------------------------------------------------

/// Why the send loop of a read ended early.
enum ReadStop {
    /// Reading the file failed.
    Disk,
    /// The stream could not take more (the requester went away or stopped
    /// it).
    Stream,
}

fn read_loop(mut file: File, tx: mpsc::Sender<io::Result<Vec<u8>>>) {
    loop {
        let mut chunk = vec![0u8; FILE_CHUNK_MAX];
        match file.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => {
                chunk.truncate(n);
                if tx.blocking_send(Ok(chunk)).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                let _ = tx.blocking_send(Err(e));
                return;
            }
        }
    }
}

async fn serve_read(
    conn: &Connection,
    mut send: FramedSend,
    mut recv: FramedRecv,
    file: File,
    permit: FilePermit,
) {
    // A read requester sends nothing after its header (decision 9); the
    // receive half is only ever stopped on the failure paths below.
    // Registered so the bytes it sends are reported as traffic (a reverse
    // registration's path watch counts them); a send never enters a local
    // write, so the ledger can never pick this stream.
    let watch = StallWatch::on(conn, "file.read");
    let (tx, mut rx) = mpsc::channel(DISK_QUEUE_CHUNKS);
    let reader = tokio::task::spawn_blocking(move || read_loop(file, tx));

    let mut hasher = blake3::Hasher::new();
    let mut total = 0u64;
    let mut since_yield = 0u64;
    let sent: Result<(), ReadStop> = async {
        while let Some(item) = rx.recv().await {
            let chunk = item.map_err(|_| ReadStop::Disk)?;
            let n = chunk.len() as u64;
            hasher.update(&chunk);
            total += n;
            send.send(&FileFrame::data(chunk))
                .await
                .map_err(|_| ReadStop::Stream)?;
            watch.track().count_sent(n as usize);
            // The send-side depth cap of the tunnel splice
            // (`SEND_DEPTH_CAP_BYTES`'s own doc): a fast source must not run
            // many chunks back to back with no scheduling opportunity.
            since_yield += n;
            if since_yield >= SEND_DEPTH_CAP_BYTES {
                since_yield = 0;
                tokio::task::yield_now().await;
            }
        }
        Ok(())
    }
    .await;
    drop(rx);
    let _ = reader.await;
    // The file is read to its end (or the transfer is over): the slot is
    // free before the requester sees the end frame, so a client that has
    // finished a transfer is never refused by the quota it still held.
    drop(permit);
    match sent {
        Ok(()) => {
            let end = FileFrame::end(total, hasher.finalize().as_bytes().to_vec());
            if send.send(&end).await.is_ok() {
                let _ = send.finish();
            } else {
                send.reset(RESET_CODE_TUNNEL_ABORT);
            }
        }
        // A truncated transfer must never look like a clean end: reset.
        Err(ReadStop::Disk | ReadStop::Stream) => {
            send.reset(RESET_CODE_TUNNEL_ABORT);
            recv.stop(RESET_CODE_TUNNEL_ABORT);
        }
    }
}

// ---------------------------------------------------------------------------
// file.write
// ---------------------------------------------------------------------------

/// Removes the temp file when it goes out of scope still armed, so every way
/// out of a write (an early return, a panic, the task being dropped) leaves
/// no temp file behind. The removal is one `unlinkat` through the directory
/// fd the temp file was created through.
struct TempGuard {
    dir: Arc<File>,
    name: Option<OsString>,
}

impl TempGuard {
    fn new(dir: Arc<File>, name: OsString) -> Self {
        Self {
            dir,
            name: Some(name),
        }
    }

    /// Remove the temp file now (idempotent).
    fn clean(&mut self) {
        if let Some(name) = self.name.take() {
            let _ = host::unlink_at(&self.dir, &name);
        }
    }

    /// The temp file is gone (renamed into place): nothing to remove.
    fn disarm(&mut self) {
        self.name = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        self.clean();
    }
}

/// What the blocking writer reports once its channel closes.
struct Written {
    file: File,
    bytes: u64,
    hash: blake3::Hash,
    error: Option<io::Error>,
}

fn write_loop(
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut file: File,
    gate: Option<Arc<dyn WriteGate>>,
) -> Written {
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0u64;
    while let Some(chunk) = rx.blocking_recv() {
        if let Some(gate) = &gate {
            gate.before_write(bytes);
        }
        if let Err(error) = file.write_all(&chunk) {
            // Returning drops the receiver: the pump's next hand-off fails
            // and it stops reading.
            return Written {
                file,
                bytes,
                hash: hasher.finalize(),
                error: Some(error),
            };
        }
        hasher.update(&chunk);
        bytes += chunk.len() as u64;
    }
    Written {
        file,
        bytes,
        hash: hasher.finalize(),
        error: None,
    }
}

/// Why the receive loop of a write ended without a verified-able `end`.
enum UploadStop {
    /// The requester broke the stream contract (an over-cap chunk, a frame
    /// after `end`, a `result` frame, more bytes than announced, an `end`
    /// that never came, a frame that does not decode).
    Violation,
    /// The stream was reset or the connection was lost.
    Gone,
    /// The disk writer gave up (the write failed).
    WriterClosed,
}

/// Read frames until the requester finishes its send half. Returns the `end`
/// frame. The local write the stall ledger watches is the hand-off of each
/// chunk to the disk writer.
async fn receive_upload(
    recv: &mut FramedRecv,
    tx: mpsc::Sender<Vec<u8>>,
    announced: u64,
    track: &StreamTrack,
) -> Result<FileEnd, UploadStop> {
    let mut received = 0u64;
    let mut end: Option<FileEnd> = None;
    loop {
        let next = if end.is_some() {
            match tokio::time::timeout(END_FINISH_GRACE, recv.recv::<FileFrame>()).await {
                Ok(next) => next,
                Err(_) => return Err(UploadStop::Violation),
            }
        } else {
            recv.recv::<FileFrame>().await
        };
        let frame = match next {
            Ok(Some(frame)) => frame,
            // The requester finished its send half.
            Ok(None) => break,
            Err(StreamError::Read(_)) => return Err(UploadStop::Gone),
            Err(_) => return Err(UploadStop::Violation),
        };
        if frame.validate().is_err() {
            return Err(UploadStop::Violation);
        }
        match frame.body {
            Some(file_frame::Body::Data(chunk)) if end.is_none() => {
                let n = chunk.len() as u64;
                received = received.saturating_add(n);
                // More than `FileWriteOpen.size`: cut right here (decision
                // 10), before the excess touches the disk.
                if received > announced {
                    return Err(UploadStop::Violation);
                }
                if chunk.is_empty() {
                    continue;
                }
                track.enter_write();
                let handed = tx.send(chunk).await;
                track.leave_write(if handed.is_ok() { n as usize } else { 0 });
                if handed.is_err() {
                    return Err(UploadStop::WriterClosed);
                }
            }
            Some(file_frame::Body::End(e)) if end.is_none() => end = Some(e),
            // `data` or `end` after `end`, a requester-sent `result`, a frame
            // with no body.
            _ => return Err(UploadStop::Violation),
        }
    }
    end.ok_or(UploadStop::Violation)
}

/// What the receive loop and the ledger decided.
enum Pumped {
    Done(Result<FileEnd, UploadStop>),
    /// The ledger stopped the stream (ADR-0037).
    Stalled,
}

fn failure_frame(error: &wire::Error) -> FileFrame {
    FileFrame::result(false, error.code.clone(), error.message.clone(), false)
}

fn mismatch() -> wire::Error {
    wire::Error::new(ErrorCode::InvalidArgument, "size or hash mismatch", false)
}

/// What a finished commit tells the caller.
struct Committed {
    overwritten: bool,
    /// The temp name no longer exists (it was renamed into place, or its
    /// extra link was removed).
    temp_gone: bool,
}

/// The blocking tail of a write: make the data durable, set the final
/// attributes, put the file in place, make the directory entry durable
/// (decision 7).
fn commit(dir: &File, temp: &OsString, written: &File, job: &WriteJob) -> io::Result<Committed> {
    written.sync_all()?;
    host::apply_final_attrs(written, job.mode, job.preserve, job.mtime)?;
    let committed = if job.overwrite {
        let overwritten = matches!(
            host::stat_at(dir, &job.name)?,
            Some(StatInfo {
                kind: FsKind::Regular,
                ..
            })
        );
        host::replace_at(dir, temp, &job.name)?;
        Committed {
            overwritten,
            temp_gone: true,
        }
    } else {
        // `linkat` fails with `EEXIST` when the name appeared since the
        // control request checked: an existing file is never replaced.
        host::link_new_at(dir, temp, &job.name)?;
        Committed {
            overwritten: false,
            temp_gone: host::unlink_at(dir, temp).is_ok(),
        }
    };
    dir.sync_all()?;
    Ok(committed)
}

async fn serve_write(
    gate: Option<Arc<dyn WriteGate>>,
    conn: &Connection,
    mut send: FramedSend,
    mut recv: FramedRecv,
    job: WriteJob,
    permit: FilePermit,
) {
    // Out of descriptors: answer with the mapped I/O error instead of panicking
    // the stream task (the permit drops with `permit`, the ticket is spent).
    let dir = match job.dir.try_clone() {
        Ok(dir) => Arc::new(dir),
        Err(e) => {
            drop(permit);
            let error = if matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) {
                wire::Error::new(ErrorCode::ResourceExhausted, "too many open files", true)
            } else {
                file_io_error(&e)
            };
            return finish_with(send, failure_frame(&error)).await;
        }
    };
    let created = {
        let dir = Arc::clone(&dir);
        let name = job.name.clone();
        tokio::task::spawn_blocking(move || host::create_temp(&dir, &name)).await
    };
    let temp = match created {
        Ok(Ok(temp)) => temp,
        Ok(Err(e)) => {
            drop(permit);
            return finish_with(send, failure_frame(&file_io_error(&e))).await;
        }
        Err(_) => {
            drop(permit);
            return finish_with(send, failure_frame(&internal())).await;
        }
    };
    let mut guard = TempGuard::new(Arc::clone(&dir), temp.name.clone());

    // The label names the kind of stream, never the path (the ledger's
    // eviction line is a log line; paths live in the audit record only).
    let watch = StallWatch::on(conn, "file.write");
    let (tx, rx) = mpsc::channel(DISK_QUEUE_CHUNKS);
    let writer = tokio::task::spawn_blocking(move || write_loop(rx, temp.file, gate));

    // Scoped so the receive future, which borrows `recv`, is gone before
    // `recv` is touched again below.
    let pumped = {
        let pump = receive_upload(&mut recv, tx, job.size, watch.track());
        tokio::pin!(pump);
        tokio::select! {
            result = &mut pump => Pumped::Done(result),
            () = watch.evicted() => Pumped::Stalled,
        }
    };

    let end = match pumped {
        Pumped::Stalled => {
            send.reset(RESET_CODE_TUNNEL_STALLED);
            recv.stop(RESET_CODE_TUNNEL_STALLED);
            guard.clean();
            return;
        }
        Pumped::Done(Ok(end)) => end,
        Pumped::Done(Err(UploadStop::Violation)) => {
            send.reset(RESET_CODE_BAD_HEADER);
            recv.stop(RESET_CODE_BAD_HEADER);
            guard.clean();
            return;
        }
        Pumped::Done(Err(UploadStop::Gone)) => {
            send.reset(RESET_CODE_TUNNEL_ABORT);
            guard.clean();
            return;
        }
        Pumped::Done(Err(UploadStop::WriterClosed)) => {
            let error = match writer.await {
                Ok(Written {
                    error: Some(error), ..
                }) => file_io_error(&error),
                _ => internal(),
            };
            guard.clean();
            drop(permit);
            return finish_with(send, failure_frame(&error)).await;
        }
    };

    // The requester finished: the writer's channel is closed, so it ends.
    let written = match writer.await {
        Ok(written) => written,
        Err(_) => {
            guard.clean();
            drop(permit);
            return finish_with(send, failure_frame(&internal())).await;
        }
    };
    if let Some(error) = &written.error {
        guard.clean();
        drop(permit);
        return finish_with(send, failure_frame(&file_io_error(error))).await;
    }
    if end.size != written.bytes
        || written.bytes != job.size
        || end.blake3.as_slice() != written.hash.as_bytes().as_slice()
    {
        guard.clean();
        drop(permit);
        return finish_with(send, failure_frame(&mismatch())).await;
    }

    let temp_name = guard.name.clone().expect("armed until here");
    let committed = {
        let dir = Arc::clone(&dir);
        tokio::task::spawn_blocking(move || commit(&dir, &temp_name, &written.file, &job)).await
    };
    let reply = match committed {
        Ok(Ok(committed)) => {
            if committed.temp_gone {
                guard.disarm();
            } else {
                guard.clean();
            }
            FileFrame::result(true, "", "", committed.overwritten)
        }
        Ok(Err(e)) => {
            guard.clean();
            failure_frame(&file_io_error(&e))
        }
        Err(_) => {
            guard.clean();
            failure_frame(&internal())
        }
    };
    // The slot is free before the requester sees the result.
    drop(permit);
    finish_with(send, reply).await;
}

fn internal() -> wire::Error {
    wire::Error::new(ErrorCode::Internal, "file operation failed", false)
}

/// Send the one `result` frame and finish. The destination is settled
/// before this is called.
async fn finish_with(mut send: FramedSend, result: FileFrame) {
    if send.send(&result).await.is_ok() {
        let _ = send.finish();
    } else {
        send.reset(RESET_CODE_TUNNEL_ABORT);
    }
}
