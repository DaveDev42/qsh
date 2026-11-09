//! Learning rendezvous hints (ADR-0054 decision 5).
//!
//! After a forward connection stands and `punch.v1` is negotiated, the client
//! sends one `RendezvousQuery` to the host (once per host per process). The
//! host answers with the fingerprints of the controllers it is registered
//! with. Only the ones this device already pins *with an address* are kept,
//! and they are written to the host's pin as its `rendezvous` list. The list
//! never names a peer the device did not already trust, so a false answer
//! can only change whom to ask first.
//!
//! Nothing here may slow the command: the query is written and not waited
//! for ([`Session::learn_rendezvous`]), the answer is picked up by whichever
//! control-stream read sees it, and the write to `trust.toml` runs on the
//! blocking pool. Every failure is silent, apart from a `qsh::punch` debug
//! line that carries counts and no addresses.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use qsh_transport::{Connection, Fingerprint};

use crate::client::{RendezvousSink, Session};
use crate::ops::OpError;
use crate::trust::{SharedTrustStore, TrustStore};

/// Asks a host for hints, at most once. One per resolved route target.
pub struct HintLearner {
    trust_path: PathBuf,
    asked: AtomicBool,
}

impl std::fmt::Debug for HintLearner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HintLearner")
            .field("asked", &self.asked.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl HintLearner {
    /// A learner that writes into the store `trust` was opened on.
    pub fn new(trust: &SharedTrustStore) -> Arc<Self> {
        Arc::new(Self {
            trust_path: trust.path().to_path_buf(),
            asked: AtomicBool::new(false),
        })
    }

    /// Sends the query on `session` (a forward session over `connection`)
    /// unless this learner already asked. Never fails and never waits for
    /// the answer.
    pub(crate) async fn ask(&self, session: &mut Session, connection: &Connection) {
        if self.asked.swap(true, Ordering::Relaxed) {
            return;
        }
        let Some(host) = connection.peer_fingerprint() else {
            return;
        };
        let path = self.trust_path.clone();
        let sink: RendezvousSink = Arc::new(move |listed: Vec<Vec<u8>>| {
            let path = path.clone();
            let write = move || match record(&path, &host, &listed) {
                Ok(kept) => {
                    tracing::debug!(
                        target: "qsh::punch",
                        event = "hint_learned",
                        listed = listed.len(),
                        kept
                    );
                }
                Err(_) => {
                    tracing::debug!(target: "qsh::punch", event = "hint_failed");
                }
            };
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    drop(handle.spawn_blocking(write));
                }
                Err(_) => {
                    drop(std::thread::spawn(write));
                }
            }
        });
        session.learn_rendezvous(sink).await;
    }
}

/// Writes what `listed` teaches about `host` into the trust file at `path`,
/// under its lock. Returns how many hints the pin holds afterwards.
fn record(
    path: &std::path::Path,
    host: &Fingerprint,
    listed: &[Vec<u8>],
) -> Result<usize, OpError> {
    let _lock = TrustStore::lock(path)?;
    let mut store = TrustStore::load(path)?;
    let (count, changed) = store.learn_rendezvous(host, listed);
    if changed {
        store.save(path)?;
    }
    Ok(count)
}
