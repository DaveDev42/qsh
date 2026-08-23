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
    /// **Identity** the holder is compared against for "is this the same
    /// taker re-acquiring" / "does this asker hold the lease" (`take`'s own
    /// first-arm check, [`WriterLease::is_held_by`]). For a forward attach
    /// or a `session write` value op this is the same value as `physical`
    /// below — one physical connection is one asker there. It differs only
    /// for a reverse-route `SESSION_DATA` stream ([`WriterLease::take_owned`]'s
    /// own doc): every local CLI process routed through one `qsh listen`
    /// daemon redeems its ticket on that daemon's *one* shared physical
    /// registration connection, so `physical` alone cannot tell two
    /// concurrent reverse attaches apart — without a finer identity here,
    /// the second attach's `take` would hit this struct's own `conn ==
    /// conn` short-circuit meant for "the same asker again" and silently
    /// co-hold the lease with the first, `no_steal` included (both
    /// findings this field exists to close).
    pub conn: ConnectionId,
    /// **Physical** connection the lease is released on when it dies
    /// ([`WriterLease::release_connection`], driven only by
    /// `Server::purge_connection` at whole-connection teardown). Always
    /// the real transport connection, even when `conn` above is a finer,
    /// synthetic per-attach identity layered on top of it — a dead
    /// physical connection must release every lease it is behind, however
    /// many synthetic identities were multiplexed over it.
    pub physical: ConnectionId,
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
    /// Identity and release-on-death connection are the same value here —
    /// the ordinary case, where one physical connection is one asker. See
    /// [`Self::take_owned`] for the reverse-route case where they differ.
    pub fn take(&mut self, principal: &str, conn: ConnectionId, no_steal: bool) -> TakeOutcome {
        self.take_owned(principal, conn, conn, no_steal)
    }

    /// [`Self::take`], with the comparison identity (`owner`) and the
    /// release-on-death connection (`physical`) given separately.
    ///
    /// Exists for one reason: a reverse-route `SESSION_DATA` stream's
    /// `physical` connection is the `qsh listen` daemon's one shared
    /// registration to the target, identical for every local CLI process
    /// currently attached through it (`docs/CLI.md` §6.13's "writer lease는
    /// 데몬의 connection에 묶인다" — true of *release*, not of *identity*).
    /// Passing that shared value as `owner` too would make every such
    /// attach hit this lease's own "same asker re-acquiring" short-circuit
    /// against every other one, so no `no_steal` conflict and no
    /// `displaced`/`changed` demotion could ever fire between two
    /// concurrent reverse attaches — both would silently believe they hold
    /// the lease and write into the same PTY. The caller
    /// (`Server::handle_data_stream`) instead derives `owner` from the
    /// single-use ticket the stream redeemed, which is unique per
    /// `session.open`/`session.attach` call and therefore per attach, while
    /// still passing the true `physical` connection so a dead registration
    /// releases whichever attach currently holds the lease.
    pub fn take_owned(
        &mut self,
        principal: &str,
        owner: ConnectionId,
        physical: ConnectionId,
        no_steal: bool,
    ) -> TakeOutcome {
        match &self.holder {
            Some(h) if h.conn == owner => TakeOutcome::Acquired {
                displaced: None,
                changed: false,
            },
            Some(h) if no_steal && h.principal != principal => {
                TakeOutcome::Conflict { holder: h.clone() }
            }
            _ => {
                let displaced = self.holder.replace(LeaseHolder {
                    principal: principal.to_string(),
                    conn: owner,
                    physical,
                });
                TakeOutcome::Acquired {
                    displaced,
                    changed: true,
                }
            }
        }
    }

    /// Release the lease if `physical` holds it — the real transport
    /// connection, never the finer `conn`/owner identity
    /// ([`LeaseHolder::physical`]'s own doc). Returns the released holder
    /// (⇒ broadcast `writer_changed{writer: null}`).
    pub fn release_connection(&mut self, physical: ConnectionId) -> Option<LeaseHolder> {
        if self.holder.as_ref().is_some_and(|h| h.physical == physical) {
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
                    conn: A,
                    physical: A
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
                    conn: A,
                    physical: A
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
                    conn: A,
                    physical: A
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
                conn: A,
                physical: A
            })
        );
        assert!(lease.holder().is_none());
        assert_eq!(lease.release_connection(A), None);
    }
}
