//! The blocking pieces of a `FILE_DATA` transfer that both ends share
//! (`docs/adr/0029-file-copy.md` decisions 7 and 10), unix only.
//!
//! The host (`server/file_data.rs`) writes an upload into a temporary file
//! next to its destination and puts it in place once the bytes verified; the
//! client (`client/file.rs`) does the same for a download. The temporary
//! file's cleanup guard, the disk writer thread and the final commit are the
//! same code on both sides, so a fix to one reaches the other.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::sync::Arc;

use tokio::sync::mpsc;

use super::host::{self, FsKind, StatInfo, WriteGate};

/// Chunks queued between the stream and the disk. Small on purpose: a disk
/// that stops taking chunks must back up into the stream's receive window
/// quickly (where the stall ledger can see it), not into memory.
pub(crate) const DISK_QUEUE_CHUNKS: usize = 4;

/// Removes the temp file when it goes out of scope still armed, so every way
/// out of a transfer (an early return, a panic, the task being dropped)
/// leaves no temp file behind. The removal is one `unlinkat` through the
/// directory fd the temp file was created through.
pub(crate) struct TempGuard {
    dir: Arc<File>,
    name: Option<OsString>,
}

impl TempGuard {
    pub(crate) fn new(dir: Arc<File>, name: OsString) -> Self {
        Self {
            dir,
            name: Some(name),
        }
    }

    /// The temp file's name while the guard is armed.
    pub(crate) fn name(&self) -> Option<OsString> {
        self.name.clone()
    }

    /// Remove the temp file now (idempotent).
    pub(crate) fn clean(&mut self) {
        if let Some(name) = self.name.take() {
            let _ = host::unlink_at(&self.dir, &name);
        }
    }

    /// The temp file is gone (renamed into place): nothing to remove.
    pub(crate) fn disarm(&mut self) {
        self.name = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        self.clean();
    }
}

/// Create the temp file and arm its guard in one blocking step. The guard is
/// built on the blocking thread, before the result travels back, so a caller
/// that is dropped while it awaits the `spawn_blocking` handle (a connection
/// closing, a cancel) still has the finished result dropped, and the guard
/// removes the file. Creating the file on the thread and the guard in the
/// awaiting task leaves a window in which the file exists and nothing owns it.
pub(crate) fn create_guarded_temp(
    dir: &Arc<File>,
    name: &std::ffi::OsStr,
) -> io::Result<(File, TempGuard)> {
    let temp = host::create_temp(dir, name)?;
    let guard = TempGuard::new(Arc::clone(dir), temp.name);
    Ok((temp.file, guard))
}

/// What the blocking writer reports once its channel closes.
pub(crate) struct Written {
    pub(crate) file: File,
    pub(crate) bytes: u64,
    pub(crate) hash: blake3::Hash,
    pub(crate) error: Option<io::Error>,
}

/// The disk writer: write every chunk the channel carries to `file`, hashing
/// what was written. Runs on a blocking thread; `gate` is the test seam that
/// can hold a write still.
pub(crate) fn write_loop(
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

/// What a finished commit tells the caller.
pub(crate) struct Committed {
    pub(crate) overwritten: bool,
    /// The temp name no longer exists (it was renamed into place, or its
    /// extra link was removed).
    pub(crate) temp_gone: bool,
}

/// Where a finished temp file goes and with which attributes.
pub(crate) struct Placement<'a> {
    /// The final name inside the directory.
    pub(crate) name: &'a OsStr,
    /// Permission bits of the source.
    pub(crate) mode: u32,
    /// Replace an existing file (`renameat`); `false` is `--no-clobber`
    /// (`linkat`, which never replaces).
    pub(crate) overwrite: bool,
    /// Carry the mode and modification time over (`-p`).
    pub(crate) preserve: bool,
    /// The source's modification time, used when `preserve` is set.
    pub(crate) mtime: i64,
}

/// The blocking tail of a transfer: make the data durable, set the final
/// attributes, put the file in place, make the directory entry durable
/// (decision 7).
pub(crate) fn commit_temp(
    dir: &File,
    temp: &OsStr,
    written: &File,
    place: &Placement<'_>,
) -> io::Result<Committed> {
    written.sync_all()?;
    host::apply_final_attrs(written, place.mode, place.preserve, place.mtime)?;
    let committed = if place.overwrite {
        let overwritten = matches!(
            host::stat_at(dir, place.name)?,
            Some(StatInfo {
                kind: FsKind::Regular,
                ..
            })
        );
        host::replace_at(dir, temp, place.name)?;
        Committed {
            overwritten,
            temp_gone: true,
        }
    } else {
        // `linkat` fails with `EEXIST` when the name appeared since the
        // caller checked: an existing file is never replaced.
        host::link_new_at(dir, temp, place.name)?;
        Committed {
            overwritten: false,
            temp_gone: host::unlink_at(dir, temp).is_ok(),
        }
    };
    dir.sync_all()?;
    Ok(committed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_guarded_temp_is_removed_when_the_awaiting_task_never_collects_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Arc::new(crate::file::guard::open_dir_nofollow(tmp.path()).unwrap());
        let created = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = {
            let dir = Arc::clone(&dir);
            let created = Arc::clone(&created);
            tokio::task::spawn_blocking(move || {
                let made = create_guarded_temp(&dir, std::ffi::OsStr::new("data.bin"));
                created.store(true, std::sync::atomic::Ordering::SeqCst);
                made
            })
        };
        // The awaiting task goes away (a closed connection, a cancel) without
        // collecting the result: the finished output is dropped with its
        // armed guard, which removes the file.
        drop(handle);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let empty = std::fs::read_dir(tmp.path()).unwrap().next().is_none();
                if created.load(std::sync::atomic::Ordering::SeqCst) && empty {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the temp file is removed with the dropped result");
    }
}
