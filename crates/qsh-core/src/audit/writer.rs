//! The async, bounded-queue, rotating audit writer (`PLAN.md` M5 Step 3,
//! `docs/design/architecture.md` §6/§7). [`RotatingAuditSink::record`] is a
//! non-blocking bounded-queue enqueue; a single dedicated `std::thread`
//! owns the active file handle across every append (no per-record open,
//! unlike [`super::FileAuditSink`]), rotates at `[audit].max_bytes`,
//! retains `[audit].retain` rotated files, and latches "degraded" on a
//! fatal write failure until an automatic background retry clears it.
//!
//! **Why `std::thread` + `std::sync::mpsc`, not a tokio task.** The choke
//! points that call `record()` (`server::Server::authorize` and its
//! siblings) are themselves synchronous functions called from `async`
//! handlers *before* their first `.await` — `record()` must stay a plain
//! function, never itself an `.await` point, or every caller's signature
//! changes. A bounded `std::sync::mpsc::sync_channel` gives `try_send`
//! (truly non-blocking, no runtime involved) on the producer side and a
//! plain blocking `recv`/iterator loop on a real OS thread for the writer —
//! exactly where synchronous, sequential file I/O belongs.
//!
//! **Failure has exactly two shapes** ([`super::AuditError`]): the queue is
//! full (`try_send` found no room — the writer is behind), or the writer is
//! latched degraded (its last write failed and none has succeeded since).
//! A record that *was* successfully enqueued before the latch trips — its
//! op was already **allowed**, so the record must eventually land — is
//! never dropped on the trip itself: [`run_writer`] moves it into an
//! in-memory `pending` queue and retries flushing it, in order, on a fixed
//! cadence ([`RETRY_TICK`]) until the write actually lands, at which point
//! the latch clears automatically and a caller needs to take no action
//! (`PLAN.md` M5 Step 3, F1). `record()` itself is unchanged by any of
//! this: the latch check still runs *before* the enqueue, so an op that is
//! actually denied while degraded produces zero audit lines, never a
//! pending one. Only records still `pending` when the process exits
//! without a clean shutdown (`RotatingAuditSink`'s `Drop`, F2) are ever
//! actually lost — the trip diagnostic is what an operator has to go on
//! for those, not a replay of the lines themselves.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use super::{AuditError, AuditRecord, AuditSink, create_private_dir};

/// Production retry cadence for [`run_writer`]'s degraded-mode flush loop
/// (`PLAN.md` M5 Step 3, F1): once a write has failed, the writer wakes up
/// this often to retry flushing whatever is `pending`, without waiting for
/// another record to arrive. A `#[cfg(test)]` caller injects a much
/// shorter tick (`RotatingAuditSink::spawn_joinable_with_retry_tick`) so a
/// test observes automatic recovery without paying this wall-clock cost.
const RETRY_TICK: Duration = Duration::from_secs(1);

/// The production audit sink: [`RotatingAuditSink::spawn`] wires
/// `[audit]`'s `max_bytes`/`retain`/`queue_depth`
/// (`crate::config::AuditConfig`) straight into the writer thread.
/// `crate::serve::host_runtime` is the one production call site.
pub struct RotatingAuditSink {
    /// `None` only after `Drop` has taken it (`PLAN.md` M5 Step 3 F2) — a
    /// live `RotatingAuditSink` always has one, so `record()` unwraps it.
    sender: Option<SyncSender<AuditRecord>>,
    degraded: Arc<AtomicBool>,
    path: PathBuf,
    /// The writer thread's `JoinHandle`, owned here only for
    /// [`RotatingAuditSink::spawn`]'s production sink — `Drop` takes and
    /// joins it (F2). The `#[cfg(test)]` constructors hand their handle
    /// back to the caller instead and leave this `None`, so `Drop` there
    /// only drops the sender (unblocking the writer) and does not also try
    /// to join a handle the test already owns.
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RotatingAuditSink {
    /// Spawn the writer thread and return the sink. `path` is the active
    /// log file; rotated files live alongside it as `<path>.1`, `<path>.2`,
    /// … up to `retain`.
    pub fn spawn(path: impl Into<PathBuf>, max_bytes: u64, retain: u32, queue_depth: u32) -> Self {
        let (mut sink, handle) = Self::spawn_inner(
            path.into(),
            max_bytes,
            retain,
            queue_depth,
            None,
            RETRY_TICK,
        );
        sink.handle = Some(handle);
        sink
    }

    /// The active log file path (diagnostics/tests).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the writer is currently latched degraded — its last write
    /// failed and automatic retry (`RETRY_TICK`) has not yet succeeded
    /// (`PLAN.md` M5 Step 3, F9). Operator visibility only: `record()`
    /// already consults the same flag on its own fail-closed path, this
    /// just lets a caller (a doctor probe, a status line) observe it
    /// without provoking a call.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::SeqCst)
    }

    /// Test-only: like [`Self::spawn`], but also hands back the writer
    /// thread's `JoinHandle` so a test can deterministically wait for it to
    /// finish draining — drop the sink, then `handle.join()` — instead of
    /// racing a background thread with a `sleep()`.
    #[cfg(test)]
    fn spawn_joinable(
        path: impl Into<PathBuf>,
        max_bytes: u64,
        retain: u32,
        queue_depth: u32,
    ) -> (Self, std::thread::JoinHandle<()>) {
        Self::spawn_inner(
            path.into(),
            max_bytes,
            retain,
            queue_depth,
            None,
            RETRY_TICK,
        )
    }

    /// Test-only: [`Self::spawn_joinable`] with a caller-chosen degraded-mode
    /// retry cadence — the F1/F4 recovery tests inject a millisecond-scale
    /// tick so they observe the writer's *production* retry path clear the
    /// latch on its own, deterministically, without paying [`RETRY_TICK`]'s
    /// real one-second cost.
    #[cfg(test)]
    fn spawn_joinable_with_retry_tick(
        path: impl Into<PathBuf>,
        max_bytes: u64,
        retain: u32,
        queue_depth: u32,
        retry_tick: Duration,
    ) -> (Self, std::thread::JoinHandle<()>) {
        Self::spawn_inner(
            path.into(),
            max_bytes,
            retain,
            queue_depth,
            None,
            retry_tick,
        )
    }

    /// Test-only: the writer thread blocks on `gate.recv()` before it ever
    /// touches the record channel, so a test can hold it "stalled"
    /// deterministically (queue-saturation / non-blocking assertions)
    /// without `sleep()` — release it by sending on the returned
    /// `SyncSender`.
    #[cfg(test)]
    fn spawn_stalled(
        path: impl Into<PathBuf>,
        max_bytes: u64,
        retain: u32,
        queue_depth: u32,
    ) -> (Self, SyncSender<()>, std::thread::JoinHandle<()>) {
        let (gate_tx, gate_rx) = mpsc::sync_channel::<()>(0);
        let (sink, handle) = Self::spawn_inner(
            path.into(),
            max_bytes,
            retain,
            queue_depth,
            Some(gate_rx),
            RETRY_TICK,
        );
        (sink, gate_tx, handle)
    }

    fn spawn_inner(
        path: PathBuf,
        max_bytes: u64,
        retain: u32,
        queue_depth: u32,
        gate: Option<Receiver<()>>,
        retry_tick: Duration,
    ) -> (Self, std::thread::JoinHandle<()>) {
        let depth = (queue_depth as usize).max(1);
        let (sender, receiver) = mpsc::sync_channel::<AuditRecord>(depth);
        let degraded = Arc::new(AtomicBool::new(false));
        let writer_degraded = Arc::clone(&degraded);
        let writer_path = path.clone();
        let handle = std::thread::Builder::new()
            .name("qsh-audit-writer".to_string())
            .spawn(move || {
                run_writer(
                    writer_path,
                    max_bytes,
                    retain,
                    receiver,
                    writer_degraded,
                    gate,
                    retry_tick,
                )
            })
            .expect("spawn qsh-audit-writer thread");
        (
            Self {
                sender: Some(sender),
                degraded,
                path,
                handle: None,
            },
            handle,
        )
    }
}

impl AuditSink for RotatingAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        // Latch-check first: if the writer is known degraded, fail fast
        // rather than growing the queue with a record it will likely just
        // fail to write too. `record()` "never blocks the caller" —
        // `try_send` below is the only other operation it performs. This
        // is exactly what keeps a denied-while-degraded op producing zero
        // audit lines even though `pending` (below) exists: nothing for a
        // refused call is ever enqueued in the first place.
        if self.degraded.load(Ordering::SeqCst) {
            return Err(AuditError::Degraded);
        }
        let sender = self.sender.as_ref().expect("sender is only taken by Drop");
        match sender.try_send(record.clone()) {
            Ok(()) => Ok(()),
            Err(_) => Err(AuditError::QueueFull),
        }
    }
}

impl Drop for RotatingAuditSink {
    /// `PLAN.md` M5 Step 3, F2: drop the sender first so the writer
    /// thread's blocking `recv`/`recv_timeout` observes a disconnect,
    /// performs its own one-shot bounded final flush of whatever is still
    /// `pending`, and exits — then join it, so a caller that drops the
    /// *last* `Arc` (every production caller holds theirs behind one, per
    /// `crate::serve::HostRuntime`/`reverse::listen::Listen`) knows the
    /// writer has actually stopped and flushed, not just been asked to.
    ///
    /// `handle` is only `Some` for [`RotatingAuditSink::spawn`]'s
    /// production sink; the `#[cfg(test)]` constructors hand their
    /// `JoinHandle` back to the caller instead, so there is nothing to
    /// join here for those — the sender-drop still runs and still
    /// unblocks the writer, the test just joins on its own handle.
    fn drop(&mut self) {
        self.sender = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The writer thread body: owns the active file handle across every
/// append, rotates at `max_bytes`, retains `retain` rotated files, and
/// flips `degraded` on the trip into and the automatic recovery out of a
/// write failure — each transition gets exactly one diagnostic line, not
/// one per record or one per retry attempt.
fn run_writer(
    active_path: PathBuf,
    max_bytes: u64,
    retain: u32,
    receiver: Receiver<AuditRecord>,
    degraded: Arc<AtomicBool>,
    gate: Option<Receiver<()>>,
    retry_tick: Duration,
) {
    if let Some(gate) = gate {
        // Disconnected (a test dropped the sender without ever signaling)
        // just proceeds — this never hangs the thread forever on a leaked
        // test fixture.
        let _ = gate.recv();
    }
    let mut file = RotatingFile::new(active_path, max_bytes, retain);
    // F1: records that were already durably enqueued (their op was
    // ALLOWED) before a write failure latches `degraded` must not be
    // dropped just because the disk was briefly unwritable — they wait
    // here until a retry actually lands them. Bounded by `queue_depth`
    // plus a small race margin: `record()`'s latch check runs before its
    // `try_send`, so at most a handful of producers can be mid-race
    // between reading the (not-yet-visible) flag and enqueueing at the
    // instant it flips, on top of whatever was already sitting in the
    // channel at that moment.
    let mut pending: VecDeque<AuditRecord> = VecDeque::new();

    loop {
        if pending.is_empty() {
            // Normal mode: block for the next record.
            let record = match receiver.recv() {
                Ok(record) => record,
                Err(_) => return, // disconnected, nothing pending: done.
            };
            handle_normal(&mut file, &degraded, &mut pending, record);
        } else {
            // Degraded mode. `recv_timeout` doubles as the drain for
            // records that were already queued (or race in) before the
            // latch became visible to producers — each arrives here as
            // `Ok` immediately (no real waiting, since the channel already
            // has data) and is appended to `pending` in order, exactly
            // like an explicit `try_recv` drain would, just without a
            // second code path for it. Only once the channel actually
            // goes quiet for a full `retry_tick` does `Timeout` fire and
            // trigger a flush attempt.
            match receiver.recv_timeout(retry_tick) {
                Ok(record) => pending.push_back(record),
                Err(RecvTimeoutError::Timeout) => {
                    try_flush_pending(&mut file, &degraded, &mut pending);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    // F2: one final bounded attempt, never a retry loop —
                    // this must never hang shutdown on a dead disk.
                    try_flush_pending(&mut file, &degraded, &mut pending);
                    return;
                }
            }
        }
    }
}

/// Encode and write one record while not degraded (normal mode). A write
/// failure trips the latch (exactly one diagnostic — never re-emitted by
/// later retries), repairs the file (F3's truncate-on-failure), and moves
/// the record into `pending` rather than dropping it (F1).
fn handle_normal(
    file: &mut RotatingFile,
    degraded: &Arc<AtomicBool>,
    pending: &mut VecDeque<AuditRecord>,
    record: AuditRecord,
) {
    let Some(line) = encode(&record) else {
        return; // unencodable: dropped, not a write failure.
    };
    if let Err(err) = file.write_line(&line) {
        if !degraded.swap(true, Ordering::SeqCst) {
            tracing::error!(
                target: "qsh::audit",
                %err,
                path = %file.active_path.display(),
                "audit writer degraded: a write failed; authorization \
                 decisions are denied until it recovers automatically \
                 (retried in the background — no operator action needed)"
            );
        }
        pending.push_back(record);
    }
}

/// Attempt to flush `pending` in order, stopping at the first failure —
/// never re-emits the trip diagnostic (F1: "not one per retry attempt").
/// Clears the latch and emits exactly one recovery diagnostic once
/// `pending` is fully flushed.
fn try_flush_pending(
    file: &mut RotatingFile,
    degraded: &Arc<AtomicBool>,
    pending: &mut VecDeque<AuditRecord>,
) {
    while let Some(record) = pending.front() {
        let Some(line) = encode(record) else {
            // Unencodable: same as the normal-mode path — drop it and
            // move on rather than wedging every future retry on a record
            // that can never succeed.
            pending.pop_front();
            continue;
        };
        match file.write_line(&line) {
            Ok(()) => {
                pending.pop_front();
            }
            Err(_) => return, // still failing: stay degraded, retry next tick.
        }
    }
    if degraded.swap(false, Ordering::SeqCst) {
        tracing::info!(
            target: "qsh::audit",
            path = %file.active_path.display(),
            "audit writer recovered; writes are durable again"
        );
    }
}

/// One JSON line, payload plus trailing `\n`, built into a single buffer —
/// `None` (with its own diagnostic) if the record itself cannot encode.
fn encode(record: &AuditRecord) -> Option<Vec<u8>> {
    match serde_json::to_vec(record) {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            Some(bytes)
        }
        Err(err) => {
            // Not an I/O failure — doesn't move the degraded latch either
            // way, just drops this one unencodable record.
            tracing::error!(
                target: "qsh::audit",
                %err,
                "audit writer: a record failed to encode; dropping it"
            );
            None
        }
    }
}

/// The active file handle plus enough bookkeeping to rotate it at a line
/// boundary. Never panics on I/O failure — every method returns
/// `io::Result` and [`run_writer`] turns an `Err` into the degraded latch,
/// never a crashed thread.
struct RotatingFile {
    dir: PathBuf,
    active_path: PathBuf,
    /// F6: sidecar advisory-lock path (`<active>.lock`), held around the
    /// revalidate → maybe-rotate → reopen critical section so two
    /// `RotatingAuditSink`s on the same path never race each other's
    /// renames. Unix-only — see [`RotatingFile::with_lock`].
    #[cfg(unix)]
    lock_path: PathBuf,
    max_bytes: u64,
    retain: u32,
    file: Option<File>,
    bytes_written: u64,
    /// F6: whether the *previous* rotation attempt failed (rename blocked
    /// by a co-writer — Windows file-sharing semantics, or losing the unix
    /// flock race to another rotator). Gates the warning to once per
    /// failure streak rather than once per record.
    rotation_degraded: bool,
}

impl RotatingFile {
    fn new(active_path: PathBuf, max_bytes: u64, retain: u32) -> Self {
        let dir = active_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        #[cfg(unix)]
        let lock_path = lock_path_for(&active_path);
        Self {
            dir,
            active_path,
            #[cfg(unix)]
            lock_path,
            max_bytes,
            retain,
            file: None,
            bytes_written: 0,
            rotation_degraded: false,
        }
    }

    fn open_fresh(&self) -> io::Result<(File, u64)> {
        create_private_dir(&self.dir)?;
        // F5: reclaim whatever an operator-lowered `retain` left behind —
        // cheapest to do it exactly when a fresh handle is about to be
        // opened (startup, and after every rotation).
        sweep_stale_rotated(&self.active_path, self.retain);
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&self.active_path)?;
        let size = file.metadata()?.len();
        Ok((file, size))
    }

    fn ensure_open(&mut self) -> io::Result<()> {
        if self.file.is_none() {
            let (file, size) = self.open_fresh()?;
            self.file = Some(file);
            self.bytes_written = size;
        }
        Ok(())
    }

    /// F6: if this handle no longer refers to what is actually at
    /// `active_path` — a co-writer rotated it out from under us — reopen
    /// and reseed `bytes_written` from the real file's metadata, rather
    /// than keep appending to an orphaned inode that a later `unlink`
    /// (past `retain`) will silently make unrecoverable. A no-op on
    /// non-unix, where Windows file-sharing semantics instead make a
    /// co-writer's rotation attempt fail outright ([`Self::rotate`]).
    #[cfg(unix)]
    fn revalidate(&mut self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let Some(file) = self.file.as_ref() else {
            return Ok(());
        };
        let fh_meta = file.metadata()?;
        let stale = match fs::metadata(&self.active_path) {
            Ok(path_meta) => path_meta.dev() != fh_meta.dev() || path_meta.ino() != fh_meta.ino(),
            Err(_) => true, // path gone (mid-rotation elsewhere): reopen.
        };
        if stale {
            self.file = None;
            self.ensure_open()?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn revalidate(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// F6: hold an advisory `flock` on the sidecar `<active>.lock` file
    /// across `revalidate` → maybe-`rotate` → reopen, so two
    /// `RotatingAuditSink`s on the same path (`qsh serve` and `qsh
    /// reverse` both default to `<state>/audit.log`; F7 puts `qsh
    /// listen`'s controller on it too) never race each other's renames.
    /// The byte-level append itself happens *outside* the lock: once this
    /// returns `Ok`, `self.file` is a live, current handle opened
    /// `O_APPEND`, and the OS placing those bytes at the file's true
    /// current end is safe to interleave with a co-writer doing the same —
    /// `revalidate`'s job is only to guarantee this handle is not stale
    /// when that happens. A no-op on non-unix.
    #[cfg(unix)]
    fn with_lock<R>(&mut self, f: impl FnOnce(&mut Self) -> io::Result<R>) -> io::Result<R> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        // The lock sidecar lives next to `active_path`; on a brand-new
        // `dir` (nothing has been opened yet) that directory does not
        // exist until `ensure_open` creates it — but `ensure_open` only
        // runs *inside* this lock. Create it here too (idempotent:
        // `create_private_dir` is a no-op once it exists) so acquiring the
        // lock never itself depends on housekeeping that only happens
        // after the lock is held.
        create_private_dir(&self.dir)?;
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).mode(0o600);
        let lock_file = opts.open(&self.lock_path)?;
        // SAFETY: `lock_file` stays open (its fd valid) for the whole
        // call; `flock`/`LOCK_UN` are plain syscalls taking that fd and a
        // plain integer operation — no pointers, nothing to uphold beyond
        // the fd being valid, which it is until `lock_file` drops below.
        if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let result = f(self);
        // SAFETY: same fd, still open; unlocking a lock this call itself
        // just took.
        let _ = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) };
        result
    }

    #[cfg(not(unix))]
    fn with_lock<R>(&mut self, f: impl FnOnce(&mut Self) -> io::Result<R>) -> io::Result<R> {
        f(self)
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.with_lock(|this| {
            this.revalidate()?;
            this.ensure_open()?;
            if this.bytes_written > 0 && this.bytes_written + line.len() as u64 > this.max_bytes {
                this.rotate()?;
            }
            Ok(())
        })?;
        // F8: a single record whose encoded line already exceeds
        // `max_bytes` never gets split or endlessly re-rotated — the
        // `bytes_written > 0` guard above only rotates a *non-empty* file,
        // so an oversized line either (a) triggers one rotation and then
        // lands alone in the fresh, now-empty file, or (b) if the file was
        // already empty, is written directly with no rotation at all.
        // Either way it ends up alone in its own file, which may itself
        // exceed `max_bytes` — the real per-file bound this writer
        // provides is `max(max_bytes, one record's size)`, not a strict
        // `max_bytes` (`docs/design/architecture.md` §6).
        let file = self.file.as_mut().expect("just ensured open");
        match file.write_all(line) {
            Ok(()) => {
                self.bytes_written += line.len() as u64;
                Ok(())
            }
            Err(err) => {
                self.repair_partial_write();
                Err(err)
            }
        }
    }

    /// F3: best-effort truncate the active file back to the last
    /// known-good offset — undoes whatever a failed
    /// [`std::io::Write::write_all`] left half-appended, so a subsequent
    /// read never finds a torn, unparseable line. The file is opened
    /// `O_APPEND`, so no seek is needed: the next successful write still
    /// lands at the (now shortened) true end. Best-effort: a `set_len`
    /// failure here is not escalated — there is nothing further to fail
    /// closed *toward*, the caller already has the original write error to
    /// act on.
    fn repair_partial_write(&self) {
        if let Some(file) = self.file.as_ref() {
            let _ = file.set_len(self.bytes_written);
        }
    }

    /// Rotate at a line boundary: close the handle **before** any rename
    /// touches its path — on Windows a rename while the file is open
    /// fails, and dropping the handle first works on every platform, so
    /// this is the one code path this needs (`PLAN.md` M5 Step 3).
    ///
    /// F6: a rename blocked by a co-writer (Windows file-sharing
    /// semantics, or losing the unix flock race to another rotator) is
    /// **non-fatal** — this skips rotation for this round and keeps
    /// appending to whatever is actually at `active_path` rather than
    /// treat housekeeping as a precondition for writing. Only a genuine
    /// inability to open a destination file trips the caller's degraded
    /// latch; this is also what makes Windows co-writers safe without any
    /// locking of their own — the blocked rename degrades to append-only
    /// instead of failing the write.
    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        if let Err(err) = rotate_files(&self.active_path, self.retain) {
            if !self.rotation_degraded {
                tracing::warn!(
                    target: "qsh::audit",
                    %err,
                    path = %self.active_path.display(),
                    "audit writer: rotation failed (likely a co-writer \
                     holding this file open); continuing to append \
                     without rotating until it clears on its own"
                );
                self.rotation_degraded = true;
            }
            // The failing rename never moved `active_path` — reopen
            // whatever is really there and reseed from its true size.
            return self.ensure_open();
        }
        self.rotation_degraded = false;
        let (file, _size) = self.open_fresh()?; // a fresh file: size is 0
        self.file = Some(file);
        self.bytes_written = 0;
        Ok(())
    }
}

/// `<active>.<n>` — the rotated-file naming scheme.
fn rotated_path(active: &Path, n: u32) -> PathBuf {
    let mut name = active.as_os_str().to_os_string();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

/// `<active>.lock` — F6's sidecar advisory-lock path. Never holds audit
/// content; distinct from every `rotated_path` (`n` is always numeric,
/// never the literal `lock`).
#[cfg(unix)]
fn lock_path_for(active: &Path) -> PathBuf {
    let mut name = active.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// F5: unlink rotated files above `retain` — `.{retain+1}`, `.{retain+2}`,
/// … — stopping at the first missing slot. Reclaims whatever an
/// operator-lowered `retain` left behind: nothing else in this writer ever
/// looks past `retain`, so without this sweep those files live forever.
/// Best-effort: an unlink failure here is skipped, not fatal — this is
/// housekeeping, not the write path.
fn sweep_stale_rotated(active: &Path, retain: u32) {
    let mut n = retain.saturating_add(1);
    while rotated_path(active, n).exists() {
        let _ = fs::remove_file(rotated_path(active, n));
        n += 1;
    }
}

/// Shift rotated files up by one slot, unlink whatever falls off the end of
/// `retain`, then move the active file into `.1`. Pure filesystem
/// operations — the caller has already closed any handle on `active`.
fn rotate_files(active: &Path, retain: u32) -> io::Result<()> {
    if retain == 0 {
        let _ = fs::remove_file(active);
        return Ok(());
    }
    // The oldest slot is about to be pushed out — clear it first so the
    // shift below never collides with a leftover file in the last slot.
    let _ = fs::remove_file(rotated_path(active, retain));
    for n in (1..retain).rev() {
        let src = rotated_path(active, n);
        if src.exists() {
            fs::rename(&src, rotated_path(active, n + 1))?;
        }
    }
    if active.exists() {
        fs::rename(active, rotated_path(active, 1))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use qsh_transport::Principal;

    use super::*;
    use crate::acl::{Action, Decision};

    /// A record whose JSON encoding is a small, near-constant size
    /// regardless of `i` (single/double-digit request ids), so rotation
    /// math in the tests below stays predictable without hardcoding
    /// `serde_json`'s exact byte count.
    fn record_for(i: u64) -> AuditRecord {
        AuditRecord::now(
            i,
            &Principal::Device("laptop".into()),
            qsh_transport::AuthPath::Pin,
            Action::ExecRun,
            "exec",
            Decision::Allow,
            None,
            "127.0.0.1:4433".parse().unwrap(),
        )
    }

    fn read_all_lines(dir: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "lock") {
                continue; // F6's sidecar lock file: never audit content.
            }
            let text = fs::read_to_string(&path).unwrap();
            lines.extend(text.lines().map(str::to_string));
        }
        lines
    }

    #[test]
    fn rotation_triggers_with_no_line_truncated_or_lost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // Small enough to force several rotations; `retain` generous
        // enough that nothing this test writes is ever evicted (that's
        // the separate retention test below).
        let (sink, handle) = RotatingAuditSink::spawn_joinable(&path, 500, 50, 64);
        let total = 20u64;
        for i in 0..total {
            sink.record(&record_for(i)).unwrap();
        }
        drop(sink);
        handle.join().unwrap();

        assert!(path.exists(), "audit.log restarted after rotating");
        assert!(
            rotated_path(&path, 1).exists(),
            "at least one rotation happened"
        );

        let lines = read_all_lines(dir.path());
        assert_eq!(
            lines.len() as u64,
            total,
            "zero record loss across rotation"
        );
        for line in &lines {
            let record: AuditRecord =
                serde_json::from_str(line).expect("every line is valid, untruncated JSON");
            assert_eq!(record.decision, "allow");
        }
    }

    #[test]
    fn retention_keeps_exactly_retain_plus_active_and_bounds_directory_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let max_bytes = 200u64;
        let retain = 2u32;
        let (sink, handle) = RotatingAuditSink::spawn_joinable(&path, max_bytes, retain, 64);
        // Comfortably more than enough rotations to reach steady state.
        for i in 0..15u64 {
            sink.record(&record_for(i)).unwrap();
        }
        drop(sink);
        handle.join().unwrap();

        let mut names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| !name.ends_with(".lock"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["audit.log", "audit.log.1", "audit.log.2"],
            "older rotated files are unlinked beyond retain"
        );

        let total_bytes: u64 = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| !p.extension().is_some_and(|ext| ext == "lock"))
            .map(|p| fs::metadata(p).unwrap().len())
            .sum();
        // One line's worth of slack per file: a write that pushes a file
        // past `max_bytes` still lands in *that* file (rotation happens
        // before the next line, not the one that triggered it).
        let slack = 512u64;
        assert!(
            total_bytes <= max_bytes * u64::from(retain + 1) + slack,
            "directory bytes {total_bytes} exceed the max_bytes*(retain+1) budget"
        );
    }

    #[test]
    fn queue_saturation_denies_the_second_decision_while_the_writer_is_stalled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let (sink, gate, handle) = RotatingAuditSink::spawn_stalled(&path, 64 * 1024, 2, 1);

        // queue_depth=1: the first record fills the only slot; the second
        // is refused outright — the writer never touches the channel
        // before this point (it is parked on `gate.recv()`), so this is
        // deterministic, not a race against the writer draining.
        assert_eq!(sink.record(&record_for(0)), Ok(()));
        assert_eq!(sink.record(&record_for(1)), Err(AuditError::QueueFull));

        drop(sink);
        gate.send(()).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn record_returns_immediately_while_the_writer_is_stalled_and_the_queue_has_room() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let (sink, gate, handle) = RotatingAuditSink::spawn_stalled(&path, 64 * 1024, 2, 4);

        // If `record()` ever blocked on the writer (e.g. a regression to a
        // blocking `send()` instead of `try_send()`), these calls would
        // hang here and the test would time out rather than reach the
        // asserts — that hang *is* the failure mode this test guards
        // against, no timing measurement needed.
        assert_eq!(sink.record(&record_for(0)), Ok(()));
        assert_eq!(sink.record(&record_for(1)), Ok(()));

        drop(sink);
        gate.send(()).unwrap();
        handle.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rotated_files_and_directory_keep_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("state");
        let path = sub.join("audit.log");
        let (sink, handle) = RotatingAuditSink::spawn_joinable(&path, 200, 3, 64);
        for i in 0..10u64 {
            sink.record(&record_for(i)).unwrap();
        }
        drop(sink);
        handle.join().unwrap();

        let dmode = fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700);
        for name in ["audit.log", "audit.log.1"] {
            let p = sub.join(name);
            assert!(p.exists(), "{name} should exist");
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} mode");
        }
    }

    #[test]
    fn path_reports_the_active_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = RotatingAuditSink::spawn(&path, 64 * 1024, 5, 16);
        assert_eq!(sink.path(), path);
    }

    // ---- F2: shutdown drain -------------------------------------------

    /// The mandatory F2 test: `RotatingAuditSink::spawn`'s `Drop` now joins
    /// the writer thread, so the instant it returns every accepted record
    /// must already be durable — no polling, no `sleep()`. Without F2 the
    /// verifier measured 229/1000 records on disk at this point.
    #[test]
    fn dropping_the_last_arc_flushes_every_enqueued_record_before_the_writer_exits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = RotatingAuditSink::spawn(&path, 64 * 1024 * 1024, 5, 1024);
        let n = 1000u64;
        for i in 0..n {
            sink.record(&record_for(i))
                .expect("queue has room for 1000");
        }
        drop(sink); // last (only) owner: Drop joins the writer synchronously.

        let on_disk = fs::read_to_string(&path)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        assert_eq!(
            on_disk as u64, n,
            "every accepted record must be durable once the last Arc drops"
        );
    }

    // ---- F3: partial-line repair ---------------------------------------

    /// Direct unit coverage of the truncate mechanism itself: forcing a
    /// genuine, byte-partial `write_all` failure deterministically on a
    /// real file (without an actual disk-full condition) is impractical —
    /// `O_APPEND` writes on a local filesystem either fully succeed or
    /// fail outright, so this instead manufactures exactly the on-disk
    /// state a partial write would leave (a torn, newline-less fragment
    /// past the last confirmed-good offset) and asserts `repair_partial_write`
    /// removes it. The end-to-end pipeline (genuine failure → repair →
    /// automatic recovery → every surviving line still valid JSON) is
    /// covered by the F4 test below.
    #[test]
    fn repair_partial_write_truncates_a_torn_fragment_back_to_the_last_known_good_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut file = RotatingFile::new(path.clone(), 64 * 1024, 5);
        file.write_line(b"{\"a\":1}\n").unwrap();
        file.write_line(b"{\"a\":2}\n").unwrap();
        let good_len = file.bytes_written;

        // Model exactly what a `write_all` that failed partway through a
        // third line would leave behind: `bytes_written` itself is
        // untouched (the real writer only advances it after success), but
        // extra, torn bytes are now on disk past that offset.
        {
            let mut raw = OpenOptions::new().append(true).open(&path).unwrap();
            raw.write_all(b"{\"a\":3, \"unterminat").unwrap();
        }
        assert!(fs::metadata(&path).unwrap().len() > good_len);

        file.repair_partial_write();

        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            good_len,
            "the torn fragment must be truncated off"
        );
        let text = fs::read_to_string(&path).unwrap();
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("no torn line survives repair");
        }
        assert!(text.ends_with('\n'));

        // And the handle is still perfectly usable afterward — O_APPEND
        // means no seek was needed.
        file.write_line(b"{\"a\":4}\n").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3);
    }

    // ---- F1 / F4: real-latch trip and automatic recovery ---------------

    // A minimal hand-rolled `tracing::Subscriber` that captures every
    // event's target and rendered fields — same precedent as
    // `acl/load.rs`'s `capture` module. Installed via
    // `set_global_default` rather than the (thread-local) `with_default`:
    // the writer thread is a real, separately spawned OS thread, and only
    // a *global* default is visible from a thread that never called
    // `with_default`/`set_default` itself.
    mod capture {
        use std::sync::{Arc, Mutex};

        use tracing::field::{Field, Visit};

        #[derive(Default)]
        pub(super) struct Sink {
            pub(super) events: Mutex<Vec<(String, String)>>, // (target, rendered fields)
        }

        struct Rec(String);
        impl Visit for Rec {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={:?} ", field.name(), value));
            }
        }

        pub(super) struct Sub(pub(super) Arc<Sink>);
        impl tracing::Subscriber for Sub {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::Id {
                tracing::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::Id, _: &tracing::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut rec = Rec(String::new());
                event.record(&mut rec);
                self.0
                    .events
                    .lock()
                    .unwrap()
                    .push((event.metadata().target().to_string(), rec.0));
            }
            fn enter(&self, _: &tracing::Id) {}
            fn exit(&self, _: &tracing::Id) {}
        }
    }

    /// The mandatory F1/F4 test: trip the latch with a **genuine** I/O
    /// failure (a 0o500 directory — deterministic, no test double), repair
    /// it, and prove the *production* retry path (not the test) clears the
    /// latch on its own: `record()` starts succeeding again, the trip and
    /// recovery diagnostics each fire exactly once, every record that was
    /// allowed before the trip eventually lands, and no record that was
    /// ever refused (`Err(Degraded)`) produces a line on disk.
    #[cfg(unix)]
    #[test]
    fn genuine_io_failure_latches_and_recovers_automatically_through_the_retry_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        let path = state.join("audit.log");

        // `create_private_dir` no-ops when the directory already exists,
        // so it never chmods this back — `OpenOptions::create` then fails
        // EACCES inside a 0o500 directory. Deterministic, no disk-full
        // simulation needed (precedent: the adversarial-verification
        // harness's own L1 experiment).
        fs::set_permissions(&state, fs::Permissions::from_mode(0o500)).unwrap();

        let sink = Arc::new(capture::Sink::default());
        let sub = capture::Sub(sink.clone());
        tracing::subscriber::set_global_default(sub)
            .expect("no other test in this process sets a global subscriber");

        let retry_tick = Duration::from_millis(15);
        let (audit, handle) =
            RotatingAuditSink::spawn_joinable_with_retry_tick(&path, 64 * 1024, 5, 8, retry_tick);

        // Drive calls until the latch trips. Bounded busy-poll on the
        // observable `record()` result, never a `sleep()` — same shape as
        // the adversarial-verification harness's L1 experiment.
        let mut allowed_before_trip = 0u64;
        let mut trip_seen = false;
        for i in 0..200_000u64 {
            match audit.record(&record_for(i)) {
                Ok(()) => allowed_before_trip += 1,
                Err(AuditError::QueueFull) => {}
                Err(AuditError::Degraded) => {
                    trip_seen = true;
                    break;
                }
            }
            std::thread::yield_now();
        }
        assert!(trip_seen, "a real EACCES must latch the writer degraded");

        // Every call while still degraded is refused at the door — none
        // of these denied ops may ever reach the file.
        const DENIED_BASE: u64 = 1_000_000;
        for i in 0..1000u64 {
            assert_eq!(
                audit.record(&record_for(DENIED_BASE + i)),
                Err(AuditError::Degraded)
            );
        }

        // Repair: the directory is writable again. The *production* retry
        // path clears the latch on its own — poll the observable
        // `is_degraded()` flag, bounded, never a fixed sleep.
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let mut spins = 0u64;
        while audit.is_degraded() && spins < 50_000_000 {
            std::thread::yield_now();
            spins += 1;
        }
        assert!(
            !audit.is_degraded(),
            "the latch must clear through the automatic retry path"
        );

        // A fresh record() now succeeds.
        assert_eq!(audit.record(&record_for(999)), Ok(()));

        drop(audit);
        handle.join().unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(text.ends_with('\n'));
        for line in &lines {
            let record: AuditRecord =
                serde_json::from_str(line).expect("every surviving line is valid JSON");
            let id: u64 = record.request_id.parse().unwrap();
            assert!(
                id < DENIED_BASE,
                "a denied op must never produce an audit line: {record:?}"
            );
        }
        assert_eq!(
            lines.len() as u64,
            allowed_before_trip + 1,
            "every pending (pre-trip allowed) record must land, plus the one post-recovery record"
        );

        let events = sink.events.lock().unwrap();
        let audit_events: Vec<&(String, String)> =
            events.iter().filter(|(t, _)| t == "qsh::audit").collect();
        let trips = audit_events
            .iter()
            .filter(|(_, fields)| fields.contains("degraded"))
            .count();
        let recoveries = audit_events
            .iter()
            .filter(|(_, fields)| fields.contains("recovered"))
            .count();
        assert_eq!(
            trips, 1,
            "the trip diagnostic must fire exactly once: {audit_events:?}"
        );
        assert_eq!(
            recoveries, 1,
            "the recovery diagnostic must fire exactly once: {audit_events:?}"
        );
    }

    // ---- F5: stale rotated files ---------------------------------------

    #[test]
    fn stale_rotated_files_above_retain_are_swept_on_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // Simulate a host that previously ran with a larger `retain`.
        for n in 1..=4u32 {
            fs::write(rotated_path(&path, n), "x".repeat(50)).unwrap();
        }
        let (sink, handle) = RotatingAuditSink::spawn_joinable(&path, 100, 2, 64);
        for i in 0..30u64 {
            sink.record(&record_for(i)).unwrap();
        }
        drop(sink);
        handle.join().unwrap();

        let mut names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| !name.ends_with(".lock"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["audit.log", "audit.log.1", "audit.log.2"],
            "files above retain must be reclaimed"
        );
    }

    // ---- F6: multi-process (multi-writer) safety of rotation -----------

    /// Two `RotatingAuditSink`s on the same path, writing concurrently from
    /// two threads with a small `max_bytes` (forcing frequent rotation
    /// contention) and a large `retain` (so retention itself never evicts
    /// anything — any missing line is loss, not policy). Without F6's
    /// flock + revalidate, the verifier measured 129/600 lines lost.
    #[cfg(unix)]
    #[test]
    fn two_sinks_on_one_path_interleave_without_losing_or_corrupting_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let n = 150u64;
        let (sink_a, handle_a) = RotatingAuditSink::spawn_joinable(&path, 400, 500, 64);
        let (sink_b, handle_b) = RotatingAuditSink::spawn_joinable(&path, 400, 500, 64);

        fn record_retrying(sink: &RotatingAuditSink, record: &AuditRecord) {
            loop {
                match sink.record(record) {
                    Ok(()) => return,
                    Err(AuditError::QueueFull) => std::thread::yield_now(),
                    Err(AuditError::Degraded) => {
                        panic!("this test must never see a real write failure")
                    }
                }
            }
        }

        std::thread::scope(|scope| {
            scope.spawn(|| {
                for i in 0..n {
                    record_retrying(&sink_a, &record_for(i));
                }
            });
            scope.spawn(|| {
                for i in 0..n {
                    record_retrying(&sink_b, &record_for(1_000_000 + i));
                }
            });
        });

        drop(sink_a);
        drop(sink_b);
        handle_a.join().unwrap();
        handle_b.join().unwrap();

        let mut total_lines = 0usize;
        let mut bad = 0usize;
        for entry in fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "lock") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap_or_default();
            for line in text.lines() {
                total_lines += 1;
                if serde_json::from_str::<serde_json::Value>(line).is_err() {
                    bad += 1;
                }
            }
        }
        assert_eq!(
            total_lines,
            (2 * n) as usize,
            "no record may be lost to a concurrent co-writer"
        );
        assert_eq!(bad, 0, "no interleaved writer may corrupt a line");
    }
}
