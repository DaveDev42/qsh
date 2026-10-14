//! Requester side of the remote file ops (`docs/adr/0029-file-copy.md`),
//! unix only: the control requests that mint a ticket and the two
//! `FILE_DATA` pumps, [`download`] (`file.read`) and [`upload`]
//! (`file.write`).
//!
//! The pumps are the mirror of `server/file_data.rs`, and share its blocking
//! pieces through `file::xfer` (the temp file's cleanup guard, the disk
//! writer and the commit), so a get writes its destination with the same
//! temp, `linkat` or `renameat`, `fsync` discipline a host applies to a put
//! (decision 7).
//!
//! **Stall ledger.** A download's local write, the hand-off of each chunk to
//! the disk writer, is registered in the connection's ADR-0037 ledger on the
//! forward route, with the same definition and reset code (`0x200E`) a host's
//! `file.write` uses (decision 15). On the reverse route this process holds
//! no QUIC connection: the `qsh listen` daemon's relay registers its own
//! write into this process's socket in the daemon's ledger, which is the
//! write that backs up when this process stops reading. An upload's local
//! work is a read from disk, which cannot hold a receive window, so it
//! registers nothing.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::wire::{
    self, FILE_CHUNK_MAX, FileEnd, FileFrame, StreamHeader, control_message, file_frame, response,
};
use qsh_transport::{ReadError, StreamError};
use tokio::sync::{mpsc, watch};

use super::link::{DataKillSwitch, DataRecv, DataSend};
use super::{ClientError, Session, unexpected};
use crate::file::host::{self, WriteGate};
use crate::file::xfer::{self, DISK_QUEUE_CHUNKS, TempGuard, Written, write_loop};
use crate::tunnel::splice::{RESET_CODE_TUNNEL_ABORT, SEND_DEPTH_CAP_BYTES};
use crate::tunnel::stall::{RESET_CODE_TUNNEL_STALLED, StallWatch};

/// How long a download waits, after `end`, for the host to finish its send
/// half (the host does it right after `end`; a longer silence is not a
/// conforming host).
const END_FINISH_GRACE: Duration = Duration::from_secs(10);

/// How long an upload that failed to send waits for the `result` frame the
/// host may already have queued.
const RESULT_GRACE: Duration = Duration::from_secs(5);

impl Session {
    /// Whether the negotiated capability set has `file.v1`.
    pub(crate) fn has_file_capability(&self) -> bool {
        self.has_capability(wire::CAP_FILE_V1)
    }

    /// One file control request and its response body, with a wire `Error`
    /// mapped to [`ClientError::Remote`]. The caller gated on `file.v1`.
    async fn file_request(
        &mut self,
        body: control_message::Body,
    ) -> Result<response::Body, ClientError> {
        let resp = self.request(body).await?;
        match resp.body {
            Some(response::Body::Error(e)) => Err(ClientError::Remote {
                code: e.error_code(),
                message: e.message,
                retryable: e.retryable,
            }),
            Some(body) => Ok(body),
            None => Err(ClientError::Protocol("empty response body".into())),
        }
    }

    /// `file.read`: ask the host to open `path` for reading.
    pub(crate) async fn file_read_open(
        &mut self,
        path: &str,
        user: &str,
    ) -> Result<wire::FileReadOpened, ClientError> {
        let req = wire::FileReadOpen {
            path: path.to_string(),
            user: user.to_string(),
        };
        match self
            .file_request(control_message::Body::FileReadOpen(req))
            .await?
        {
            response::Body::FileReadOpened(opened) => Ok(opened),
            other => Err(unexpected("FileReadOpen", &other)),
        }
    }

    /// `file.write`: ask the host to open a destination for writing.
    pub(crate) async fn file_write_open(
        &mut self,
        req: wire::FileWriteOpen,
    ) -> Result<wire::FileWriteOpened, ClientError> {
        match self
            .file_request(control_message::Body::FileWriteOpen(req))
            .await?
        {
            response::Body::FileWriteOpened(opened) => Ok(opened),
            other => Err(unexpected("FileWriteOpen", &other)),
        }
    }

    /// Open the `FILE_DATA` stream that redeems `ticket`, in band 0
    /// (decision 15). `label` names the kind of stream in the stall ledger's
    /// diagnostic (never a path); `None` registers nothing.
    pub(crate) async fn file_conduit(
        &self,
        ticket: Vec<u8>,
        label: Option<&'static str>,
    ) -> Result<FileConduit, ClientError> {
        let header = StreamHeader::file_data(ticket);
        let (send, recv, kill) = self.open_data_link(&header, wire::PRIORITY_TUNNEL).await?;
        let watch = match (self.conn.as_ref(), label) {
            (Some(conn), Some(label)) => Some(StallWatch::on(conn, label)),
            _ => None,
        };
        Ok(FileConduit {
            send,
            recv,
            kill,
            watch,
        })
    }
}

/// An open `FILE_DATA` stream, header sent, ticket redeemed by the host.
pub(crate) struct FileConduit {
    send: DataSend,
    recv: DataRecv,
    kill: DataKillSwitch,
    watch: Option<StallWatch>,
}

/// Why one item of a copy did not finish.
#[derive(Debug)]
pub(crate) enum XferFailure {
    /// The host refused or failed the item.
    Remote(ErrorCode, String),
    /// This machine failed the item.
    Local(ErrorCode, String),
    /// `--no-clobber` and the destination exists (before or after the
    /// bytes moved): a skip, not a failure (decision 7).
    Exists,
    /// The connection or the carrier failed: the copy cannot go on.
    Link(ClientError),
    /// The caller canceled the copy.
    Canceled,
}

fn internal_local(message: impl Into<String>) -> XferFailure {
    XferFailure::Local(ErrorCode::Internal, message.into())
}

/// A local I/O error as an item failure.
pub(crate) fn local_io_failure(err: &io::Error) -> XferFailure {
    match err.raw_os_error() {
        Some(libc::EEXIST) => XferFailure::Exists,
        Some(libc::ENOENT) => XferFailure::Local(
            ErrorCode::InvalidArgument,
            "no such file or directory".to_string(),
        ),
        Some(libc::EACCES | libc::EPERM | libc::EROFS) => {
            XferFailure::Local(ErrorCode::PermissionDenied, "permission denied".to_string())
        }
        Some(libc::ENOTDIR) => {
            XferFailure::Local(ErrorCode::InvalidArgument, "not a directory".to_string())
        }
        Some(libc::EISDIR) => {
            XferFailure::Local(ErrorCode::InvalidArgument, "is a directory".to_string())
        }
        Some(libc::ELOOP) => XferFailure::Local(
            ErrorCode::InvalidArgument,
            "too many levels of symbolic links".to_string(),
        ),
        Some(libc::ENOSPC | libc::EDQUOT) => XferFailure::Local(
            ErrorCode::ResourceExhausted,
            "no space left on device".to_string(),
        ),
        Some(libc::EMFILE | libc::ENFILE) => XferFailure::Local(
            ErrorCode::ResourceExhausted,
            "too many open files".to_string(),
        ),
        _ => XferFailure::Local(ErrorCode::Internal, format!("local I/O error: {err}")),
    }
}

/// What a `file.write` `result` frame that says `ok = false` means.
fn result_failure(result: wire::FileWriteResult) -> XferFailure {
    let code: ErrorCode = result.code.parse().unwrap_or(ErrorCode::Internal);
    if code == ErrorCode::InvalidArgument && result.message == "destination exists" {
        return XferFailure::Exists;
    }
    XferFailure::Remote(code, result.message)
}

/// A reset the host sent, as an item failure.
fn reset_failure(code: u32) -> XferFailure {
    if code == RESET_CODE_TUNNEL_STALLED {
        XferFailure::Remote(
            ErrorCode::ResourceExhausted,
            "the host stopped the transfer: its disk write made no progress".to_string(),
        )
    } else {
        XferFailure::Remote(
            ErrorCode::RemoteError,
            format!("the host aborted the transfer (stream error {code:#x})"),
        )
    }
}

/// Classify a failed receive on a data stream: a reset or a malformed frame
/// is the host's doing and ends the item, anything else (a lost connection,
/// a failed carrier) ends the copy.
fn recv_failure(err: ClientError) -> XferFailure {
    match err {
        ClientError::Stream(StreamError::Read(ReadError::Reset(code))) => {
            reset_failure(code.as_u32().unwrap_or(0))
        }
        ClientError::Stream(
            inner
            @ (StreamError::Frame(_) | StreamError::Decode(_) | StreamError::Truncated { .. }),
        ) => XferFailure::Remote(
            ErrorCode::RemoteError,
            format!("peer protocol violation: {inner}"),
        ),
        other => XferFailure::Link(other),
    }
}

/// Resolves once `rx` says canceled; pends forever when its sender is gone
/// without ever canceling.
async fn canceled(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn evicted(watch: &Option<StallWatch>) {
    match watch {
        Some(watch) => watch.evicted().await,
        None => std::future::pending::<()>().await,
    }
}

// ---------------------------------------------------------------------------
// file.read (download)
// ---------------------------------------------------------------------------

/// Where a download goes: a name inside an open directory.
pub(crate) struct DownloadDest {
    /// The destination directory, opened by the caller.
    pub(crate) dir: Arc<File>,
    /// The final name inside it (one validated component).
    pub(crate) name: OsString,
    /// Replace an existing file (`false` is `--no-clobber`).
    pub(crate) overwrite: bool,
    /// `-p`.
    pub(crate) preserve: bool,
}

/// What a finished download tells the caller.
#[derive(Debug)]
pub(crate) struct Downloaded {
    pub(crate) bytes: u64,
    pub(crate) blake3: String,
    pub(crate) mode: u32,
    pub(crate) overwritten: bool,
}

enum DownloadStop {
    /// The host broke the stream contract.
    Violation(String),
    /// The stream failed or ended early.
    Failed(XferFailure),
    /// The disk writer gave up.
    WriterClosed,
}

async fn receive_download(
    recv: &mut DataRecv,
    tx: mpsc::Sender<Vec<u8>>,
    watch: &Option<StallWatch>,
    progress: &(dyn Fn(u64) + Send + Sync),
) -> Result<FileEnd, DownloadStop> {
    let mut received = 0u64;
    let mut end: Option<FileEnd> = None;
    loop {
        let next = if end.is_some() {
            match tokio::time::timeout(END_FINISH_GRACE, recv.recv::<FileFrame>()).await {
                Ok(next) => next,
                Err(_) => {
                    return Err(DownloadStop::Violation(
                        "the host did not finish the stream after its end frame".to_string(),
                    ));
                }
            }
        } else {
            recv.recv::<FileFrame>().await
        };
        let frame = match next {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(err) => return Err(DownloadStop::Failed(recv_failure(err))),
        };
        if frame.validate().is_err() {
            return Err(DownloadStop::Violation(
                "data chunk over the cap".to_string(),
            ));
        }
        match frame.body {
            Some(file_frame::Body::Data(chunk)) if end.is_none() => {
                let n = chunk.len();
                if n == 0 {
                    continue;
                }
                received += n as u64;
                if let Some(watch) = watch {
                    watch.track().enter_write();
                }
                let handed = tx.send(chunk).await;
                if let Some(watch) = watch {
                    watch
                        .track()
                        .leave_write(if handed.is_ok() { n } else { 0 });
                }
                if handed.is_err() {
                    return Err(DownloadStop::WriterClosed);
                }
                progress(received);
            }
            Some(file_frame::Body::End(e)) if end.is_none() => end = Some(e),
            _ => {
                return Err(DownloadStop::Violation(
                    "unexpected frame on a file.read stream".to_string(),
                ));
            }
        }
    }
    end.ok_or_else(|| {
        DownloadStop::Failed(XferFailure::Remote(
            ErrorCode::RemoteError,
            "the host closed the stream before its end frame".to_string(),
        ))
    })
}

enum DownloadPumped {
    Done(Result<FileEnd, DownloadStop>),
    Stalled,
    Canceled,
}

/// Run a `file.read` `FILE_DATA` stream to completion: write the bytes to a
/// temp file next to the destination, verify size and BLAKE3 against the
/// host's `end` frame, and put the file in place. Every way out removes the
/// temp file and leaves the destination as it was.
pub(crate) async fn download(
    conduit: FileConduit,
    opened: &wire::FileReadOpened,
    dest: DownloadDest,
    gate: Option<Arc<dyn WriteGate>>,
    progress: &(dyn Fn(u64) + Send + Sync),
    mut cancel: watch::Receiver<bool>,
) -> Result<Downloaded, XferFailure> {
    let FileConduit {
        mut send,
        mut recv,
        kill,
        watch,
    } = conduit;
    let created = {
        let dir = Arc::clone(&dest.dir);
        let name = dest.name.clone();
        tokio::task::spawn_blocking(move || host::create_temp(&dir, &name)).await
    };
    let temp = match created {
        Ok(Ok(temp)) => temp,
        Ok(Err(e)) => {
            send.abort(RESET_CODE_TUNNEL_ABORT, &kill);
            recv.abort(RESET_CODE_TUNNEL_ABORT, &kill);
            return Err(local_io_failure(&e));
        }
        Err(_) => return Err(internal_local("file operation failed")),
    };
    let mut guard = TempGuard::new(Arc::clone(&dest.dir), temp.name.clone());
    // A read requester sends nothing after its header (decision 9).
    send.finish();

    let (tx, rx) = mpsc::channel(DISK_QUEUE_CHUNKS);
    let writer = tokio::task::spawn_blocking(move || write_loop(rx, temp.file, gate));
    let pumped = {
        let pump = receive_download(&mut recv, tx, &watch, progress);
        tokio::pin!(pump);
        tokio::select! {
            result = &mut pump => DownloadPumped::Done(result),
            () = evicted(&watch) => DownloadPumped::Stalled,
            () = canceled(&mut cancel) => DownloadPumped::Canceled,
        }
    };

    let end = match pumped {
        DownloadPumped::Stalled => {
            recv.abort(RESET_CODE_TUNNEL_STALLED, &kill);
            guard.clean();
            return Err(XferFailure::Local(
                ErrorCode::ResourceExhausted,
                "stopped: the local disk write made no progress".to_string(),
            ));
        }
        DownloadPumped::Canceled => {
            recv.abort(RESET_CODE_TUNNEL_ABORT, &kill);
            guard.clean();
            return Err(XferFailure::Canceled);
        }
        DownloadPumped::Done(Ok(end)) => end,
        DownloadPumped::Done(Err(DownloadStop::Violation(message))) => {
            recv.abort(RESET_CODE_TUNNEL_ABORT, &kill);
            guard.clean();
            return Err(XferFailure::Remote(
                ErrorCode::RemoteError,
                format!("peer protocol violation: {message}"),
            ));
        }
        DownloadPumped::Done(Err(DownloadStop::Failed(failure))) => {
            recv.abort(RESET_CODE_TUNNEL_ABORT, &kill);
            guard.clean();
            return Err(failure);
        }
        DownloadPumped::Done(Err(DownloadStop::WriterClosed)) => {
            recv.abort(RESET_CODE_TUNNEL_ABORT, &kill);
            let failure = match writer.await {
                Ok(Written {
                    error: Some(error), ..
                }) => local_io_failure(&error),
                _ => internal_local("file operation failed"),
            };
            guard.clean();
            return Err(failure);
        }
    };

    // The host finished: the writer's channel is closed, so it ends.
    let written = match writer.await {
        Ok(written) => written,
        Err(_) => {
            guard.clean();
            return Err(internal_local("file operation failed"));
        }
    };
    if let Some(error) = &written.error {
        guard.clean();
        return Err(local_io_failure(error));
    }
    if end.size != written.bytes || end.blake3.as_slice() != written.hash.as_bytes().as_slice() {
        guard.clean();
        return Err(XferFailure::Remote(
            ErrorCode::RemoteError,
            "size or hash mismatch against the host's end frame".to_string(),
        ));
    }

    let bytes = written.bytes;
    let hash = written.hash;
    let temp_name = guard.name().expect("armed until here");
    let mode = opened.mode & 0o777;
    let committed = {
        let dir = Arc::clone(&dest.dir);
        let name = dest.name.clone();
        let (overwrite, preserve, mtime) = (dest.overwrite, dest.preserve, opened.mtime);
        tokio::task::spawn_blocking(move || {
            xfer::commit_temp(
                &dir,
                &temp_name,
                &written.file,
                &xfer::Placement {
                    name: &name,
                    mode,
                    overwrite,
                    preserve,
                    mtime,
                },
            )
        })
        .await
    };
    match committed {
        Ok(Ok(committed)) => {
            if committed.temp_gone {
                guard.disarm();
            } else {
                guard.clean();
            }
            Ok(Downloaded {
                bytes,
                blake3: hash.to_hex().to_string(),
                mode,
                overwritten: committed.overwritten,
            })
        }
        Ok(Err(e)) => {
            guard.clean();
            Err(local_io_failure(&e))
        }
        Err(_) => {
            guard.clean();
            Err(internal_local("file operation failed"))
        }
    }
}

// ---------------------------------------------------------------------------
// file.write (upload)
// ---------------------------------------------------------------------------

/// A local file to send, opened and measured by the caller.
pub(crate) struct UploadSource {
    pub(crate) file: File,
    /// `fstat` size at open: the size announced in `FileWriteOpen`.
    pub(crate) size: u64,
}

/// What a finished upload tells the caller.
#[derive(Debug)]
pub(crate) struct Uploaded {
    pub(crate) bytes: u64,
    pub(crate) blake3: String,
    pub(crate) overwritten: bool,
}

/// Read the source on a blocking thread and hash every chunk there, so the
/// hashing never occupies an async worker that the connection's other
/// streams (a PTY attach) need. Returns the hash state over what was sent.
fn read_loop(mut file: File, size: u64, tx: mpsc::Sender<io::Result<Vec<u8>>>) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    let mut remaining = size;
    while remaining > 0 {
        let want = remaining.min(FILE_CHUNK_MAX as u64) as usize;
        let mut chunk = vec![0u8; want];
        match file.read(&mut chunk) {
            Ok(0) => {
                let _ = tx.blocking_send(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                return hasher;
            }
            Ok(n) => {
                chunk.truncate(n);
                remaining -= n as u64;
                hasher.update(&chunk);
                if tx.blocking_send(Ok(chunk)).is_err() {
                    return hasher;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = tx.blocking_send(Err(e));
                return hasher;
            }
        }
    }
    hasher
}

/// Read the host's `result` frame.
async fn read_result(recv: &mut DataRecv) -> Result<wire::FileWriteResult, XferFailure> {
    match recv.recv::<FileFrame>().await {
        Ok(Some(FileFrame {
            body: Some(file_frame::Body::Result(result)),
        })) => Ok(result),
        Ok(Some(_)) => Err(XferFailure::Remote(
            ErrorCode::RemoteError,
            "peer protocol violation: unexpected frame on a file.write stream".to_string(),
        )),
        Ok(None) => Err(XferFailure::Remote(
            ErrorCode::RemoteError,
            "the host closed the stream without a result".to_string(),
        )),
        Err(err) => Err(recv_failure(err)),
    }
}

async fn run_upload(
    send: &mut DataSend,
    recv: &mut DataRecv,
    kill: &DataKillSwitch,
    source: UploadSource,
    progress: &(dyn Fn(u64) + Send + Sync),
) -> Result<Uploaded, XferFailure> {
    let size = source.size;
    let (tx, mut rx) = mpsc::channel(DISK_QUEUE_CHUNKS);
    let reader = tokio::task::spawn_blocking(move || read_loop(source.file, size, tx));

    let mut total = 0u64;
    let mut since_yield = 0u64;
    let sent: Result<(), XferFailure> = async {
        while let Some(item) = rx.recv().await {
            let chunk = item.map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => XferFailure::Local(
                    ErrorCode::InvalidArgument,
                    "the source file changed while it was copied".to_string(),
                ),
                _ => local_io_failure(&e),
            })?;
            let n = chunk.len() as u64;
            total += n;
            send.send(&FileFrame::data(chunk))
                .await
                .map_err(XferFailure::Link)?;
            progress(total);
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
    let hasher = reader.await.ok();

    match sent {
        Ok(()) => {}
        Err(XferFailure::Link(err)) => {
            // The host may have refused the upload with a result before it
            // read everything (a full disk, a failed temp file): that
            // answer, not the broken pipe, is the item's outcome.
            return match tokio::time::timeout(RESULT_GRACE, read_result(recv)).await {
                Ok(Ok(result)) if !result.ok => Err(result_failure(result)),
                Ok(Err(failure @ XferFailure::Remote(..))) => Err(failure),
                _ => Err(XferFailure::Link(err)),
            };
        }
        Err(other) => {
            send.abort(RESET_CODE_TUNNEL_ABORT, kill);
            return Err(other);
        }
    }

    let Some(hasher) = hasher else {
        send.abort(RESET_CODE_TUNNEL_ABORT, kill);
        return Err(XferFailure::Local(
            ErrorCode::Internal,
            "the source reader stopped unexpectedly".to_string(),
        ));
    };
    let hash = hasher.finalize();
    send.send(&FileFrame::end(total, hash.as_bytes().to_vec()))
        .await
        .map_err(XferFailure::Link)?;
    send.finish();
    let result = read_result(recv).await?;
    if !result.ok {
        return Err(result_failure(result));
    }
    Ok(Uploaded {
        bytes: total,
        blake3: hash.to_hex().to_string(),
        overwritten: result.overwritten,
    })
}

/// Run a `file.write` `FILE_DATA` stream to completion: send the file as
/// `data` frames and an `end` frame, then wait for the host's verdict. A
/// truncated stream is never a clean end to the host (it requires `end`),
/// so abandoning one by dropping or resetting is safe.
pub(crate) async fn upload(
    conduit: FileConduit,
    source: UploadSource,
    progress: &(dyn Fn(u64) + Send + Sync),
    mut cancel: watch::Receiver<bool>,
) -> Result<Uploaded, XferFailure> {
    let FileConduit {
        mut send,
        mut recv,
        kill,
        watch: _,
    } = conduit;
    let outcome = tokio::select! {
        result = run_upload(&mut send, &mut recv, &kill, source, progress) => Some(result),
        () = canceled(&mut cancel) => None,
    };
    match outcome {
        Some(result) => result,
        None => {
            send.abort(RESET_CODE_TUNNEL_ABORT, &kill);
            recv.abort(RESET_CODE_TUNNEL_ABORT, &kill);
            Err(XferFailure::Canceled)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Condvar, Mutex};

    use qsh_transport::{FramedSend, FramedStream, StreamCode, StreamError, WriteError};

    use super::*;
    use crate::tunnel::stall::{StallLedger, StallParams};

    /// Holds the disk writer inside its first write until released: a local
    /// disk that stopped taking bytes.
    #[derive(Default)]
    struct Hold {
        open: Mutex<bool>,
        cv: Condvar,
    }

    impl Hold {
        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.cv.notify_all();
        }
    }

    impl WriteGate for Hold {
        fn before_write(&self, _written: u64) {
            let mut open = self.open.lock().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !*open {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return;
                }
                open = self.cv.wait_timeout(open, left).unwrap().0;
            }
        }
    }

    /// A client-side `file.read` whose local disk write stalls is stopped by
    /// the connection's ADR-0037 ledger: the download fails
    /// `RESOURCE_EXHAUSTED`, resets its receive half with `0x200E` (the peer's
    /// writes see `Stopped(0x200E)`, never a clean end) and leaves neither a
    /// temp file nor the destination behind (ADR-0029 decision 15).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_download_whose_local_write_stalls_is_stopped_by_the_ledger_with_the_stall_code() {
        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        // A limit of zero: the first stall is already one too many.
        let ledger = StallLedger::unstarted_for_test(
            client.clone(),
            StallParams {
                max_stalled: 0,
                ..StallParams::PRODUCTION
            },
        );

        // The host: after the header, flood `data` frames until stopped.
        let (csend, crecv) = client.open_bi().await.expect("open_bi");
        let (mut csend, crecv) = FramedStream::data(csend, crecv).split();
        csend
            .send(&StreamHeader::file_data(vec![7; 16]))
            .await
            .expect("send header");
        let host = tokio::spawn(async move {
            let (ssend, _srecv) = server.accept_bi().await.expect("accept_bi");
            let mut ssend = FramedSend::data(ssend);
            let chunk = vec![0xAB; FILE_CHUNK_MAX];
            loop {
                if let Err(err) = ssend.send(&FileFrame::data(chunk.clone())).await {
                    return err;
                }
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let dest_dir = Arc::new(File::open(dir.path()).expect("open dir"));
        let watch = ledger.watch("file.data");
        let id = watch.id();
        let conduit = FileConduit {
            send: DataSend::Direct(csend),
            recv: DataRecv::Direct(crecv),
            kill: DataKillSwitch::default(),
            watch: Some(watch),
        };
        let hold = Arc::new(Hold::default());
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let download = tokio::spawn({
            let hold: Arc<dyn WriteGate> = hold.clone();
            async move {
                download(
                    conduit,
                    &wire::FileReadOpened::default(),
                    DownloadDest {
                        dir: dest_dir,
                        name: OsString::from("out.bin"),
                        overwrite: true,
                        preserve: false,
                    },
                    Some(hold),
                    &|_| {},
                    cancel_rx,
                )
                .await
            }
        });

        // Wait until the pump sits inside the hand-off to the stuck writer,
        // then age that write past the stall limit.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while ledger.writing_since(id).is_none() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the download never blocked on the disk writer"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let now = tokio::time::Instant::now().into_std() + Duration::from_secs(10);
        ledger.force_writing_since(id, now - Duration::from_secs(5));
        ledger.tick_for_test(now);

        let result = tokio::time::timeout(Duration::from_secs(20), download)
            .await
            .expect("the download ended")
            .expect("the download task did not panic");
        hold.release();
        match result {
            Err(XferFailure::Local(ErrorCode::ResourceExhausted, message)) => {
                assert!(message.contains("no progress"), "{message}");
            }
            other => panic!("expected a stalled-write failure, got {other:?}"),
        }

        let host_err = tokio::time::timeout(Duration::from_secs(20), host)
            .await
            .expect("the host's writes ended")
            .expect("the host task did not panic");
        match host_err {
            StreamError::Write(WriteError::Stopped(code)) => {
                assert_eq!(code, StreamCode::from_u32(RESET_CODE_TUNNEL_STALLED));
            }
            other => panic!("the host's writes should be stopped with 0x200E, got {other:?}"),
        }
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert!(
            left.is_empty(),
            "the destination dir must be empty: {left:?}"
        );
    }
}
