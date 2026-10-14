//! The role-to-action table (ADR-0045 결정 2).
//!
//! One closed constant. The evaluator, `acl show`, doctor and the renderers
//! read [`ROLE_GRANTS`] and nothing else, so no second copy of the table can
//! drift. `crates/qsh-core/tests/it/acl_docs.rs` pins it to `docs/CLI.md` §6.11
//! and `docs/PRD.md` §9.

use crate::trust::TrustRole;

use super::Action;

/// Which resources a role's grant reaches (ADR-0045 결정 2, "소유 축").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleScope {
    /// Any resource, whoever opened it.
    Any,
    /// Only resources the principal itself created (the same rule `scope =
    /// "owned"` applies to an `[[acl]]` row).
    Owned,
    /// The role grants no resource-bound action, so the axis does not apply.
    NotApplicable,
}

impl RoleScope {
    /// The word `docs/CLI.md` §6.11 uses in the role table.
    pub fn as_str(self) -> &'static str {
        match self {
            RoleScope::Any => "any",
            RoleScope::Owned => "owned",
            RoleScope::NotApplicable => "해당 없음",
        }
    }
}

/// One row of the role table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleGrant {
    /// The role this row describes.
    pub role: TrustRole,
    /// The actions the role grants, in the order `docs/CLI.md` §6.11 lists
    /// them. `forward.socks` is in no row: the always-deny gate runs before
    /// any role (ADR-0045 결정 2).
    pub actions: &'static [Action],
    /// The ownership axis the grant is filtered by.
    pub scope: RoleScope,
}

/// ADR-0045 결정 2's table, in the order the ADR lists the roles. Adding a
/// role or changing a row needs a new ADR.
pub const ROLE_GRANTS: [RoleGrant; 6] = [
    RoleGrant {
        role: TrustRole::Full,
        actions: &[
            Action::ExecRun,
            Action::SessionOpen,
            Action::SessionList,
            Action::SessionAttach,
            Action::SessionControl,
            Action::ForwardLocal,
            Action::ForwardRemote,
            Action::FileRead,
            Action::FileWrite,
            Action::HostReverse,
        ],
        scope: RoleScope::Any,
    },
    RoleGrant {
        role: TrustRole::Exec,
        actions: &[
            Action::ExecRun,
            Action::SessionOpen,
            Action::SessionList,
            Action::SessionAttach,
            Action::SessionControl,
        ],
        scope: RoleScope::Any,
    },
    RoleGrant {
        role: TrustRole::Tunnel,
        actions: &[Action::ForwardLocal, Action::ForwardRemote],
        scope: RoleScope::Owned,
    },
    RoleGrant {
        role: TrustRole::ReadOnly,
        actions: &[Action::SessionList, Action::SessionAttach],
        scope: RoleScope::Any,
    },
    RoleGrant {
        role: TrustRole::Reverse,
        actions: &[Action::HostReverse],
        scope: RoleScope::NotApplicable,
    },
    RoleGrant {
        role: TrustRole::None,
        actions: &[],
        scope: RoleScope::NotApplicable,
    },
];

/// The table row for `role`.
pub fn role_grant(role: TrustRole) -> &'static RoleGrant {
    ROLE_GRANTS
        .iter()
        .find(|grant| grant.role == role)
        .expect("ROLE_GRANTS has one row per TrustRole (role_grants_cover_every_role)")
}

/// The `(action, ownership axis)` pairs a connection's trust role grants:
/// what a role stage ⓡ allow rests on, as one value (ADR-0031 결정 4).
///
/// Built only from [`ROLE_GRANTS`] by [`RoleGrants::of_role`]. The
/// authorizer reads the role from [`SharedTrustStore::resolve_role`] and
/// asks the table; the connection watch reads the same role through
/// [`SharedTrustStore::role_grants_for`] and gets the set this type derives
/// from the same row, so the two cannot disagree about what a pin grants.
/// An empty set is "no role" (no pin, a `none` role, a suspended store).
///
/// [`SharedTrustStore::resolve_role`]: crate::trust::SharedTrustStore::resolve_role
/// [`SharedTrustStore::role_grants_for`]: crate::trust::SharedTrustStore::role_grants_for
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoleGrants {
    entries: Vec<(Action, RoleScope)>,
}

impl RoleGrants {
    /// No grant at all.
    pub fn empty() -> Self {
        Self::default()
    }

    /// What `role` grants, per its [`ROLE_GRANTS`] row; nothing for `None`.
    pub fn of_role(role: Option<TrustRole>) -> Self {
        let Some(role) = role else {
            return Self::empty();
        };
        let row = role_grant(role);
        Self {
            entries: row.actions.iter().map(|&a| (a, row.scope)).collect(),
        }
    }

    /// Whether the set grants nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The pairs, in [`ROLE_GRANTS`] row order.
    pub fn entries(&self) -> &[(Action, RoleScope)] {
        &self.entries
    }

    /// Whether `self` grants `action`, on any ownership axis.
    pub fn contains(&self, action: Action) -> bool {
        self.entries.iter().any(|&(a, _)| a == action)
    }

    /// Whether `self` is at least as wide as `recorded` (ADR-0031 결정 5's
    /// last condition, read from the new set's side): for every
    /// `(action, axis)` in `recorded`, `self` has the same action and its
    /// axis is not narrower. `any` covers `owned`, so the set `full` grants
    /// covers the one `tunnel` grants, while the reverse does not; an
    /// action present in `recorded` and absent here, or an `any` that
    /// became `owned`, is a reduction. The empty set is covered by every
    /// set.
    pub fn covers(&self, recorded: &RoleGrants) -> bool {
        recorded.entries.iter().all(|&(action, old)| {
            self.entries
                .iter()
                .any(|&(a, new)| a == action && scope_covers(new, old))
        })
    }
}

/// `new` reaches everything `old` reached: the same axis, or `any`.
fn scope_covers(new: RoleScope, old: RoleScope) -> bool {
    new == RoleScope::Any || new == old
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_grants_cover_every_role_once_in_all_order() {
        let roles: Vec<TrustRole> = ROLE_GRANTS.iter().map(|g| g.role).collect();
        assert_eq!(roles, TrustRole::ALL);
    }

    #[test]
    fn no_role_grants_forward_socks() {
        for grant in ROLE_GRANTS {
            assert!(
                !grant.actions.contains(&Action::ForwardSocks),
                "{} must not grant forward.socks (always-deny gate)",
                grant.role
            );
        }
    }

    #[test]
    fn role_grant_actions_are_distinct_and_all_known() {
        for grant in ROLE_GRANTS {
            let mut seen = std::collections::BTreeSet::new();
            for action in grant.actions {
                assert!(Action::ALL.contains(action));
                assert!(
                    seen.insert(action.as_str()),
                    "{} repeats {action}",
                    grant.role
                );
            }
        }
    }

    /// ADR-0031 결정 5's "덮음" relation. `any` covers `owned`, so a set can
    /// narrow in two ways (an action dropped, an `any` that became `owned`)
    /// and widen or stay equal in the rest. Every ordered pair of the six
    /// roles is checked against an independent per-action oracle.
    #[test]
    fn role_grants_cover_relation_treats_any_as_covering_owned() {
        let any_exec = RoleGrants::of_role(Some(TrustRole::Exec));
        let owned_tunnel = RoleGrants::of_role(Some(TrustRole::Tunnel));
        let any_full = RoleGrants::of_role(Some(TrustRole::Full));

        // `full` grants forward.local on `any`, `tunnel` on `owned`.
        assert!(any_full.covers(&owned_tunnel), "any covers owned");
        assert!(
            !owned_tunnel.covers(&any_full),
            "owned does not cover any (and drops the other actions)"
        );
        // `full` -> `tunnel` is a reduction even for the shared actions,
        // because their axis narrows from `any` to `owned`.
        let local_full = RoleGrants {
            entries: vec![(Action::ForwardLocal, RoleScope::Any)],
        };
        let local_tunnel = RoleGrants {
            entries: vec![(Action::ForwardLocal, RoleScope::Owned)],
        };
        assert!(!local_tunnel.covers(&local_full));
        assert!(local_full.covers(&local_tunnel));
        // Equal sets cover each other; every set covers the empty one, and
        // the empty one covers only itself.
        assert!(any_exec.covers(&any_exec.clone()));
        assert!(any_exec.covers(&RoleGrants::empty()));
        assert!(RoleGrants::empty().covers(&RoleGrants::empty()));
        assert!(!RoleGrants::empty().covers(&any_exec));
        // `read-only` is a subset of `exec` on the same axis.
        let read_only = RoleGrants::of_role(Some(TrustRole::ReadOnly));
        assert!(any_exec.covers(&read_only));
        assert!(!read_only.covers(&any_exec));
        // Disjoint action sets cover neither way: `exec` vs `reverse`.
        let reverse = RoleGrants::of_role(Some(TrustRole::Reverse));
        assert!(!any_exec.covers(&reverse));
        assert!(!reverse.covers(&any_exec));

        // Oracle: new covers old iff every old action is in new and no
        // `any` became `owned`.
        let roles: Vec<Option<TrustRole>> = std::iter::once(None)
            .chain(TrustRole::ALL.into_iter().map(Some))
            .collect();
        for &new in &roles {
            for &old in &roles {
                let (n, o) = (RoleGrants::of_role(new), RoleGrants::of_role(old));
                let expected = o.entries().iter().all(|&(action, old_scope)| {
                    n.entries().iter().any(|&(a, new_scope)| {
                        a == action
                            && !(old_scope == RoleScope::Any && new_scope == RoleScope::Owned)
                    })
                });
                assert_eq!(n.covers(&o), expected, "{new:?} covers {old:?}");
            }
        }
    }
}
