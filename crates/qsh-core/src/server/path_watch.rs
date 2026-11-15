//! The per-connection path observer (ADR-0067).
//!
//! A keyed (iroh) connection starts on a relay and may move to a direct path
//! (or back) without a new handshake, so the admission record cannot say which
//! path the connection used afterwards. [`observe`] samples the connection's
//! path kind once a second and writes one `connect` / `path` audit record
//! when the kind (`direct` or `relay`) has changed and stayed changed for two
//! consecutive samples. Address or port changes inside one kind, and moves
//! between relays, write nothing.
//!
//! The observer also writes one record for the path it starts on (not counted
//! toward the cap). The record is an observation, not a decision: a failed write is a log line
//! and never closes or blocks the connection. At most [`MAX_PATH_RECORDS`]
//! records are attempted per connection; the observer then stops. No lock is
//! held across an await.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use qsh_transport::{AuthPath, Connection, PeerAddr, PeerPath, Principal};

use crate::audit::{AuditRecord, AuditSink};

/// How often the path kind is sampled.
pub(crate) const PATH_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// The most path records one connection may write (ADR-0067 decision 3).
pub(crate) const MAX_PATH_RECORDS: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Direct,
    Relay,
}

/// The kind of a keyed peer's path; `None` for a socket-address peer.
fn kind_of(peer: &PeerAddr) -> Option<Kind> {
    match peer {
        PeerAddr::Socket(_) => None,
        PeerAddr::Keyed { path, .. } => Some(match path {
            PeerPath::Direct(_) => Kind::Direct,
            PeerPath::Relay(_) => Kind::Relay,
        }),
    }
}

/// Sample `source` every `interval` until `closed` resolves, writing a path
/// record per confirmed kind change. Returns at once for a socket-address
/// peer. `source` is the connection's current remote address.
pub(crate) async fn observe(
    source: impl Fn() -> PeerAddr,
    closed: impl Future<Output = ()>,
    interval: Duration,
    audit: &dyn AuditSink,
    principal: &Principal,
    auth_path: AuthPath,
) {
    let start = source();
    let Some(mut recorded) = kind_of(&start) else {
        return;
    };
    // The start record: connections are not otherwise recorded when they are
    // accepted, so the path the observation begins on is written once. It does
    // not count toward `MAX_PATH_RECORDS`.
    write(audit, principal, auth_path, &start);
    let mut pending: Option<Kind> = None;
    let mut written = 0u32;
    tokio::pin!(closed);
    loop {
        tokio::select! {
            () = &mut closed => return,
            () = tokio::time::sleep(interval) => {}
        }
        let peer = source();
        let Some(seen) = kind_of(&peer) else { continue };
        if seen == recorded {
            pending = None;
            continue;
        }
        if pending != Some(seen) {
            pending = Some(seen);
            continue;
        }
        pending = None;
        recorded = seen;
        written += 1;
        write(audit, principal, auth_path, &peer);
        if written >= MAX_PATH_RECORDS {
            return;
        }
    }
}

/// Write one path record; a failure is a log line and nothing else.
fn write(audit: &dyn AuditSink, principal: &Principal, auth_path: AuthPath, peer: &PeerAddr) {
    let record = AuditRecord::path_changed(principal, auth_path, peer);
    if let Err(err) = audit.record(&record) {
        tracing::warn!(%err, "failed to record a connection path; the connection is unaffected");
    }
}

/// The guard of a spawned observer; dropping it aborts the task.
pub(crate) struct PathWatchTask(tokio::task::JoinHandle<()>);

impl Drop for PathWatchTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spawn the observer for `conn` when it is a keyed connection; `None` for a
/// socket-address one.
pub(crate) fn spawn(
    conn: &Connection,
    audit: Arc<dyn AuditSink>,
    principal: Principal,
    auth_path: AuthPath,
) -> Option<PathWatchTask> {
    kind_of(&conn.remote_address())?;
    let conn = conn.clone();
    Some(PathWatchTask(tokio::spawn(async move {
        let waiter = conn.clone();
        observe(
            || conn.remote_address(),
            async move {
                waiter.closed().await;
            },
            PATH_SAMPLE_INTERVAL,
            audit.as_ref(),
            &principal,
            auth_path,
        )
        .await;
    })))
}

#[cfg(test)]
mod tests;
