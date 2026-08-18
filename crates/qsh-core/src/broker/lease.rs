//! Writer lease: at most one writer per session
//! (`docs/design/architecture.md` §3 "Writer lease", `docs/design/protocol.md`
//! §10 "Writer lease").
//!
//! Rules implemented here (the actor applies them under its own single
//! lock — the inbox — so every handover is decided in one place):
//!
//! - **steal by default:** a new taker displaces a live holder; the
//!   displaced holder is reported so the actor can broadcast
//!   `session.writer_changed` and the old connection is demoted to
//!   read-only.
//! - **`no_steal`:** if a **different principal** holds a live lease the
//!   request fails with [`TakeOutcome::Conflict`] (→ `SESSION_CONFLICT`) —
//!   architecture.md §3 (b): "타 principal이 살아 있는 lease를 쥐고 있으면
//!   `SESSION_CONFLICT`". The same principal on another connection (the
//!   same device's headless `session write` next to its own interactive
//!   attach) takes the lease over — that is its own session to steer.
//!   protocol.md §10 is silent on the principal; architecture.md is the
//!   explicit rule and is what this implements.
//! - re-taking on the connection that already holds it is a no-op (no
//!   `writer_changed`).
//! - **release on connection death:** [`WriterLease::release_connection`]
//!   drops the lease when its owning connection goes away; the session and
//!   its child are untouched (that is the actor's business).
//! - reads never need a lease (nothing here is consulted on the read path).

/// Broker-local identity of a connection. Assigned by the transport layer
/// (`Connection::stable_id()`) but only ever an opaque number in here — the
/// broker never imports transport types (ADR-0003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub u64);

/// The current lease holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseHolder {
    /// Principal string of the holder (`device:…` / `user:…` / `fp:…`,
    /// `docs/CLI.md` §5 `Session.writer`).
    pub principal: String,
    /// Connection the lease is bound to.
    pub conn: ConnectionId,
}

/// Result of [`WriterLease::take`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakeOutcome {
    /// The requester now holds the lease. `displaced` is the previous
    /// holder if the lease changed hands (`Some` ⇒ broadcast
    /// `writer_changed`); `None` when it was free or already ours.
    Acquired {
        /// Previous holder, if one was displaced.
        displaced: Option<LeaseHolder>,
        /// Whether the holder actually changed (false for a re-take on the
        /// same connection).
        changed: bool,
    },
    /// `no_steal` was set and another principal holds the lease.
    Conflict {
        /// Who holds it.
        holder: LeaseHolder,
    },
}

/// A session's writer lease slot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WriterLease {
    holder: Option<LeaseHolder>,
}

impl WriterLease {
    /// A free lease.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current holder, if any.
    pub fn holder(&self) -> Option<&LeaseHolder> {
        self.holder.as_ref()
    }

    /// Whether `conn` currently holds the lease (the write-path check).
    pub fn is_held_by(&self, conn: ConnectionId) -> bool {
        self.holder.as_ref().is_some_and(|h| h.conn == conn)
    }

    /// Try to take the lease for `principal` on `conn`. See module docs.
    pub fn take(&mut self, principal: &str, conn: ConnectionId, no_steal: bool) -> TakeOutcome {
        match &self.holder {
            Some(h) if h.conn == conn => TakeOutcome::Acquired {
                displaced: None,
                changed: false,
            },
            Some(h) if no_steal && h.principal != principal => {
                TakeOutcome::Conflict { holder: h.clone() }
            }
            _ => {
                let displaced = self.holder.replace(LeaseHolder {
                    principal: principal.to_string(),
                    conn,
                });
                TakeOutcome::Acquired {
                    displaced,
                    changed: true,
                }
            }
        }
    }

    /// Release the lease if `conn` holds it. Returns the released holder
    /// (⇒ broadcast `writer_changed{writer: null}`).
    pub fn release_connection(&mut self, conn: ConnectionId) -> Option<LeaseHolder> {
        if self.is_held_by(conn) {
            self.holder.take()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ConnectionId = ConnectionId(1);
    const B: ConnectionId = ConnectionId(2);

    #[test]
    fn free_lease_is_acquired_without_displacement() {
        let mut lease = WriterLease::new();
        assert_eq!(
            lease.take("device:a", A, false),
            TakeOutcome::Acquired {
                displaced: None,
                changed: true
            }
        );
        assert!(lease.is_held_by(A));
        assert_eq!(
            lease.holder().map(|h| h.principal.as_str()),
            Some("device:a")
        );
    }

    #[test]
    fn steal_is_the_default_and_reports_the_displaced_holder() {
        let mut lease = WriterLease::new();
        lease.take("device:a", A, false);
        assert_eq!(
            lease.take("device:b", B, false),
            TakeOutcome::Acquired {
                displaced: Some(LeaseHolder {
                    principal: "device:a".into(),
                    conn: A
                }),
                changed: true
            }
        );
        assert!(lease.is_held_by(B));
        assert!(!lease.is_held_by(A));
    }

    #[test]
    fn no_steal_conflicts_with_a_live_holder_of_another_principal() {
        let mut lease = WriterLease::new();
        lease.take("device:a", A, false);
        assert_eq!(
            lease.take("device:b", B, true),
            TakeOutcome::Conflict {
                holder: LeaseHolder {
                    principal: "device:a".into(),
                    conn: A
                }
            }
        );
        assert!(lease.is_held_by(A), "conflict must not change the holder");
        // no_steal on a free lease is a plain acquire.
        let mut free = WriterLease::new();
        assert!(matches!(
            free.take("device:b", B, true),
            TakeOutcome::Acquired { changed: true, .. }
        ));
    }

    #[test]
    fn no_steal_lets_the_same_principal_take_over_from_another_connection() {
        // architecture.md §3 (b): only *another* principal conflicts.
        let mut lease = WriterLease::new();
        lease.take("device:a", A, false);
        assert_eq!(
            lease.take("device:a", B, true),
            TakeOutcome::Acquired {
                displaced: Some(LeaseHolder {
                    principal: "device:a".into(),
                    conn: A
                }),
                changed: true
            }
        );
        assert!(lease.is_held_by(B));
    }

    #[test]
    fn retake_on_the_holding_connection_is_a_noop() {
        let mut lease = WriterLease::new();
        lease.take("device:a", A, false);
        assert_eq!(
            lease.take("device:a", A, true),
            TakeOutcome::Acquired {
                displaced: None,
                changed: false
            }
        );
    }

    #[test]
    fn release_on_connection_death_only_affects_the_holder() {
        let mut lease = WriterLease::new();
        lease.take("device:a", A, false);
        assert_eq!(lease.release_connection(B), None);
        assert!(lease.is_held_by(A));
        assert_eq!(
            lease.release_connection(A),
            Some(LeaseHolder {
                principal: "device:a".into(),
                conn: A
            })
        );
        assert!(lease.holder().is_none());
        assert_eq!(lease.release_connection(A), None);
    }
}
