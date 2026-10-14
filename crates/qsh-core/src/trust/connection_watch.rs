//! The per-connection trust watch (ADR-0031 결정 2~8).
//!
//! A long-lived process (`qsh serve`, `qsh serve --to`, `qsh listen`) holds
//! connections that were admitted under the `trust.toml` of their time. Each
//! such connection gets one [`ConnectionWatch`], run in a task of its own
//! ([`ConnectionWatch::spawn`]) that lives exactly as long as the connection's
//! serving loop. It must not share that loop's `select!`: a withdrawn peer
//! that stops reading would block the loop in a flow-controlled send, and a
//! watch that is only polled between loop iterations would never run. The
//! watch sleeps on the
//! store's generation channel ([`SharedTrustStore::subscribe`]); every change
//! runs one judgment, and a connection the store no longer vouches for is
//! closed with `CLOSE_CODE_TRUST_WITHDRAWN` before anything is audited.
//!
//! The judgment ([`judge`]) is a pure function of three inputs: what the
//! connection was established with ([`Established`]), what
//! [`qsh_transport::Connection::reverify`] says now, and the role grants the
//! store gives the connection now. It reads the cached snapshot only
//! ([`SharedTrustStore::snapshot_view`]); the process's one poll task is what
//! reads the file.

use std::sync::Arc;

use qsh_transport::{AuthPath, Connection, Principal, RejectReason, VerifiedPeer};
use tokio::sync::watch;

use crate::acl::{Action, RoleGrants};
use crate::audit::{AuditRecord, AuditSink};
use crate::broker::PeerFingerprint;
use crate::trust::{SharedTrustStore, TRUST_POLL_INTERVAL};

/// The coarse reason a connection was closed (ADR-0031 결정 8). It is the
/// audit `resource` and nothing finer: which pin changed how is for the
/// operator to read from `trust.toml` and the local trust audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalReason {
    /// The trust credential itself is gone or changed: `reverify` rejected,
    /// the `auth_path` changed, `Pairing` came back, or the connection could
    /// not be judged.
    TrustWithdrawn,
    /// Still trusted, but the role grants it was admitted with shrank.
    GrantsReduced,
}

impl WithdrawalReason {
    /// The audit `resource` value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::TrustWithdrawn => "trust_withdrawn",
            Self::GrantsReduced => "grants_reduced",
        }
    }
}

/// What a connection was established with (ADR-0031 결정 4): the values every
/// later judgment is compared against.
#[derive(Debug, Clone)]
pub(crate) struct Established {
    /// The principal of the certificate, as `ConnCtx::principal` holds it.
    pub(crate) principal: Principal,
    /// How the peer authenticated.
    pub(crate) auth_path: AuthPath,
    /// The verified leaf fingerprint, the role lookup's other input.
    pub(crate) fingerprint: Option<PeerFingerprint>,
    /// The role grants of the establishment. `None` while they are not known
    /// yet: the watch started while the store's role grants were suspended
    /// (a `trust.toml` that did not parse), so the first judgment that can
    /// see roles adopts what it sees as the baseline instead of comparing.
    pub(crate) role_grants: Option<RoleGrants>,
}

/// The outcome of one [`judge`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Judgment {
    /// The connection stays. `role_grants` replaces the recorded set (the
    /// same, or a wider one: a widening is never a reason to close, and a
    /// later narrowing is measured against the widened record). `deferred`
    /// is set when the role comparison could not run because role grants
    /// were suspended; the watch must ask again without waiting for a
    /// generation change, since the end of a suspension caused by a failed
    /// read over identical bytes does not bump the generation.
    Keep {
        role_grants: Option<RoleGrants>,
        deferred: bool,
    },
    /// The connection is closed for this reason.
    Close(WithdrawalReason),
}

/// ADR-0031 결정 5, in its order. `reverified` is the outcome of
/// `Connection::reverify` against the current snapshot, `now` the role
/// grants the snapshot gives the connection's recorded principal and
/// fingerprint (`None` while role grants are suspended, 결정 6), already cut
/// to the actions the connection exercises.
pub(crate) fn judge(
    established: &Established,
    reverified: Result<VerifiedPeer, RejectReason>,
    now: Option<RoleGrants>,
) -> Judgment {
    // 1. `reverify` rejects. A connection that cannot be judged at all (an
    //    empty chain, an unparseable leaf) is a rejection too: not being
    //    able to judge is not trusting.
    let Ok(verified) = reverified else {
        return Judgment::Close(WithdrawalReason::TrustWithdrawn);
    };
    // 2. The trust basis itself changed (pin to CA, ...).
    // 3. Only the pairing window would let the peer in now.
    if verified.auth_path != established.auth_path || verified.principal == Principal::Pairing {
        return Judgment::Close(WithdrawalReason::TrustWithdrawn);
    }
    // 4. The role grants shrank. A suspended store (결정 6) keeps the
    //    connection and the recorded set; role requests are refused at the
    //    request level meanwhile.
    let Some(now) = now else {
        return Judgment::Keep {
            role_grants: established.role_grants.clone(),
            deferred: true,
        };
    };
    match &established.role_grants {
        Some(recorded) if !now.covers(recorded) => Judgment::Close(WithdrawalReason::GrantsReduced),
        _ => Judgment::Keep {
            role_grants: Some(now),
            deferred: false,
        },
    }
}

/// One connection's watch. See the module docs.
pub(crate) struct ConnectionWatch {
    trust: Arc<SharedTrustStore>,
    conn: Connection,
    generation: watch::Receiver<u64>,
    established: Established,
    /// The actions whose grants are compared, or every action for `None`.
    /// `qsh listen` passes `host.reverse` alone (결정 2).
    compared: Option<&'static [Action]>,
    /// The last judgment could not compare role grants (suspended store).
    deferred: bool,
}

impl ConnectionWatch {
    /// Start watching `conn`, which was established as `principal` over
    /// `auth_path` with leaf `fingerprint`.
    ///
    /// Subscribes to the store **before** it records anything, then starts
    /// the process's poll task, then records the role grants: a change
    /// landing after the subscription is delivered as a notification, one
    /// landing before it is already in the recorded values, so none is lost
    /// between the handshake and the first wait. [`Self::run`] also judges
    /// once before it first waits, which closes a connection whose trust was
    /// withdrawn between the handshake and this call.
    pub(crate) fn begin(
        trust: Arc<SharedTrustStore>,
        conn: &Connection,
        principal: &Principal,
        auth_path: AuthPath,
        fingerprint: Option<PeerFingerprint>,
        compared: Option<&'static [Action]>,
    ) -> Self {
        let generation = trust.subscribe();
        trust.start_poll();
        let role_grants = trust
            .snapshot_view()
            .role_grants_unless_suspended(principal, auth_path, fingerprint)
            .map(|grants| Self::cut(grants, compared));
        Self {
            trust,
            conn: conn.clone(),
            generation,
            established: Established {
                principal: principal.clone(),
                auth_path,
                fingerprint,
                role_grants,
            },
            compared,
            deferred: false,
        }
    }

    fn cut(grants: RoleGrants, compared: Option<&'static [Action]>) -> RoleGrants {
        match compared {
            Some(actions) => grants.restricted_to(actions),
            None => grants,
        }
    }

    /// Run one judgment against the current snapshot and apply a `Keep`.
    fn judge_now(&mut self) -> Option<WithdrawalReason> {
        let view = self.trust.snapshot_view();
        let reverified = self.conn.reverify(&view);
        let now = view
            .role_grants_unless_suspended(
                &self.established.principal,
                self.established.auth_path,
                self.established.fingerprint,
            )
            .map(|grants| Self::cut(grants, self.compared));
        match judge(&self.established, reverified, now) {
            Judgment::Keep {
                role_grants,
                deferred,
            } => {
                self.established.role_grants = role_grants;
                self.deferred = deferred;
                None
            }
            Judgment::Close(reason) => Some(reason),
        }
    }

    /// Watch until the connection is withdrawn, then close it, audit it and
    /// return. Never returns otherwise: the caller races it against the task
    /// that serves the connection and drops it when that task ends.
    ///
    /// The close comes first and the audit record second (ADR-0031 결정 6):
    /// narrowing is the safe direction, so an audit writer that fails closed
    /// must not keep a withdrawn connection open. Its failure is a log line.
    pub(crate) async fn run(mut self, audit: &dyn AuditSink) {
        loop {
            if let Some(reason) = self.judge_now() {
                self.withdraw(reason, audit);
                return;
            }
            let deferred = self.deferred;
            tokio::select! {
                changed = self.generation.changed() => {
                    if changed.is_err() {
                        // The store went away; nothing can change any more.
                        std::future::pending::<()>().await;
                    }
                }
                // A suspension that ends without a generation bump (a read
                // failure over identical bytes) is only visible to the poll
                // task's refresh, so while a comparison is owed, ask again
                // on the poll cadence.
                () = tokio::time::sleep(TRUST_POLL_INTERVAL), if deferred => {}
            }
        }
    }

    /// Run the watch in its own task and hand back the guard that owns it.
    /// The task closes the connection itself, so closure never depends on the
    /// serving loop being polled; dropping the guard aborts the task, which
    /// ties the watch to the connection's serving lifetime.
    pub(crate) fn spawn(self, audit: Arc<dyn AuditSink>) -> WatchTask {
        WatchTask {
            handle: tokio::spawn(async move { self.run(audit.as_ref()).await }),
        }
    }

    fn withdraw(&self, reason: WithdrawalReason, audit: &dyn AuditSink) {
        self.conn.close_trust_withdrawn();
        tracing::info!(
            principal = %self.established.principal,
            peer = %self.conn.remote_address(),
            reason = reason.as_str(),
            "closed a connection the trust store no longer vouches for"
        );
        let record = AuditRecord::connection_withdrawn(
            &self.established.principal,
            self.established.auth_path,
            self.conn.remote_address(),
            reason.as_str(),
        );
        if let Err(err) = audit.record(&record) {
            tracing::warn!(
                peer = %self.conn.remote_address(),
                %err,
                "failed to record a withdrawn connection; it is closed regardless"
            );
        }
    }
}

/// The guard of a spawned [`ConnectionWatch`]. Dropping it aborts the task.
pub(crate) struct WatchTask {
    handle: tokio::task::JoinHandle<()>,
}

impl WatchTask {
    /// Resolves once the watch closed the connection and audited it. Never
    /// resolves if the task ended any other way (it cannot, short of a panic).
    /// Call it at most until it resolves once.
    pub(crate) async fn withdrawn(&mut self) {
        if (&mut self.handle).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

impl Drop for WatchTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// [`WatchTask::withdrawn`] for an optional guard: pending without one.
pub(crate) async fn withdrawn(task: &mut Option<WatchTask>) {
    match task {
        Some(task) => task.withdrawn().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
