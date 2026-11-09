//! The Windows half of the agent endpoint (ADR-0055 decision 7): a named
//! pipe `\\.\pipe\qsh-agent-<32 hex>`. The pipe construction is localctl's
//! (`crate::localctl::transport::windows::PipeListener`): a protected
//! owner-only DACL on every instance, `FILE_FLAG_FIRST_PIPE_INSTANCE` on the
//! first, `PIPE_REJECT_REMOTE_CLIENTS`, the next instance created before a
//! connection is handed out (a client that races it gets `ERROR_PIPE_BUSY`
//! and retries), and the peer process's user SID compared with this
//! process's before the caller can read a byte.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{
    AgentConn, AgentStats, Counters, MAX_AGENT_STREAMS_PER_SOCKET, RefusalReason, StreamBudget,
    random_hex_name,
};
use crate::localctl::transport::windows::{PIPE_NAMESPACE, PipeListener};

/// A listening agent pipe. The pipe goes away with its last handle.
pub struct AgentListener {
    pipe: PipeListener,
    slots: StreamBudget,
    counters: Arc<Counters>,
}

impl AgentListener {
    /// Create a pipe with the default per-socket cap. `runtime_dir` is unused
    /// on Windows; it keeps the signature the same on every platform.
    pub fn create(runtime_dir: &Path) -> io::Result<Self> {
        Self::create_with_cap(runtime_dir, MAX_AGENT_STREAMS_PER_SOCKET)
    }

    /// [`Self::create`] with an explicit per-socket cap.
    pub fn create_with_cap(_runtime_dir: &Path, cap: usize) -> io::Result<Self> {
        let name = PathBuf::from(format!("{PIPE_NAMESPACE}qsh-agent-{}", random_hex_name()));
        Self::bind_at(&name, cap)
    }

    /// Bind exactly `name`. Fails when any pipe of that name exists.
    pub(crate) fn bind_at(name: &Path, cap: usize) -> io::Result<Self> {
        let pipe = PipeListener::bind_at(name)?;
        tracing::info!(target: "qsh::agent", event = "socket_created");
        Ok(Self {
            pipe,
            slots: StreamBudget::new(cap),
            counters: Arc::new(Counters::default()),
        })
    }

    /// The value for `SSH_AUTH_SOCK`.
    pub fn auth_sock(&self) -> &Path {
        self.pipe.name()
    }

    /// Always false: there is no path-length fallback for a pipe.
    pub fn uses_fallback_dir(&self) -> bool {
        false
    }

    /// Connections handled so far. Another user's connection is dropped
    /// inside the pipe listener and is not counted here.
    pub fn stats(&self) -> AgentStats {
        self.counters.snapshot()
    }

    /// Slots of the per-socket budget currently taken.
    pub fn connections_open(&self) -> usize {
        self.slots.in_use()
    }

    /// Wait for the next usable connection; one over the per-socket cap is
    /// closed and the wait goes on.
    pub async fn accept(&mut self) -> io::Result<AgentConn> {
        loop {
            let stream = self.pipe.accept().await?;
            let Some(slot) = self.slots.try_acquire() else {
                self.counters.refused(RefusalReason::Cap);
                continue;
            };
            self.counters.accepted();
            return Ok(AgentConn::new(stream, slot));
        }
    }

    /// Stop accepting; the pipe disappears with its handles.
    pub fn close(self) {}
}

impl Drop for AgentListener {
    fn drop(&mut self) {
        tracing::info!(target: "qsh::agent", event = "socket_removed");
    }
}

/// A pipe cannot outlive its process, so there is nothing stale to sweep.
pub async fn sweep_stale(_runtime_dir: &Path) -> io::Result<usize> {
    Ok(0)
}

/// See [`sweep_stale`].
pub async fn sweep_stale_older_than(_runtime_dir: &Path, _min_age: Duration) -> io::Result<usize> {
    Ok(0)
}
