//! The role-to-action table (ADR-0045 결정 2).
//!
//! One closed constant. The evaluator, `acl show`, doctor and the renderers
//! read [`ROLE_GRANTS`] and nothing else, so no second copy of the table can
//! drift. `crates/qsh-core/tests/acl_docs.rs` pins it to `docs/CLI.md` §6.11
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
}
