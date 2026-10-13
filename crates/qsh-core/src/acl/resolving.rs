//! The production [`Authorizer`] (ADR-0045 결정 4·6, PLAN M15 Step 3·4).
//!
//! [`RoleResolvingAuthorizer`] pairs the [`Policy`] `acl::load` built from
//! `acl.toml` (rows; an empty policy when the file is absent) with the
//! process's [`SharedTrustStore`]. Every decision first resolves the
//! requester's trust role against the *current* `trust.toml` (a pin's
//! `role` key, matched on the connection's verified fingerprint), then
//! runs the one evaluator, [`Policy::decide`], with that role as input:
//! the role stage ⓡ and the rows form a union.
//!
//! An unusable `acl.toml` never gets here. `load_or_deny` builds the plain
//! [`super::DenyAll`] for it, which refuses role grants too: a policy the
//! operator meant to write but that cannot be read is an ambiguous
//! authorization state, and ambiguity closes (ADR-0045 결정 6).
//!
//! The per-decision `trust.toml` refresh was wired and measured without a
//! change in meaning first (PLAN M15 Step 3,
//! `crates/qsh-testkit/tests/role_resolution_cost.rs`); this is the step
//! that makes the resolved role count.

use std::sync::Arc;

use crate::trust::SharedTrustStore;

use super::{Action, Authorizer, Policy, Requester, ResourceRef, Verdict};

/// An [`Authorizer`] that resolves the requester's trust role on every
/// call. See the module doc.
pub struct RoleResolvingAuthorizer {
    policy: Policy,
    trust: Arc<SharedTrustStore>,
}

impl RoleResolvingAuthorizer {
    /// Authorize with `policy`'s rows plus the roles `trust` resolves.
    /// `Policy::default()` (no rows) is the "no `acl.toml`" state: only
    /// roles grant.
    pub fn new(policy: Policy, trust: Arc<SharedTrustStore>) -> Self {
        Self { policy, trust }
    }
}

impl std::fmt::Debug for RoleResolvingAuthorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleResolvingAuthorizer")
            .field("rules", &self.policy.rules.len())
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl Authorizer for RoleResolvingAuthorizer {
    fn check(
        &self,
        requester: &Requester<'_>,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict {
        // `None` covers every "no role" case: not a pinned `device:`
        // principal, no connection fingerprint, no such pin, a pin
        // re-registered under another fingerprint, a pin with no `role`
        // key, and a trust store whose last reload failed.
        let role = self.trust.resolve_role(
            requester.principal,
            requester.auth_path,
            requester.fingerprint,
        );
        self.policy
            .check_with_role(requester, role, action, resource)
    }
}

#[cfg(test)]
mod tests {
    use qsh_transport::{AuthPath, Fingerprint, Principal};

    use super::*;
    use crate::acl::{Decision, GrantBasis};
    use crate::broker::PeerFingerprint;
    use crate::trust::TrustRole;

    fn store_with(role_line: &str, fingerprint: &Fingerprint) -> Arc<SharedTrustStore> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        std::fs::write(
            &path,
            format!(
                "[[peer]]\nname = \"phone\"\nfingerprint = \"{fingerprint}\"\n\
                 address = \"\"\nadded_at = \"t\"\n{role_line}"
            ),
        )
        .unwrap();
        let store = SharedTrustStore::open(&path).unwrap();
        // Keep the directory alive for the store's lifetime (refresh reads
        // the path on every call).
        std::mem::forget(dir);
        store
    }

    /// The role counts: a `full` pin whose fingerprint matches the
    /// connection gets what the table says, and the verdict names the role
    /// and no rule. A mismatched fingerprint gets nothing from an empty
    /// policy.
    #[test]
    fn a_matching_role_allows_and_names_itself_as_the_basis() {
        let fingerprint = Fingerprint::of_spki_der(b"phone");
        let trust = store_with("role = \"full\"\n", &fingerprint);
        let principal = Principal::Device("phone".into());
        let matching = Requester::new(
            &principal,
            AuthPath::Pin,
            Some(PeerFingerprint::new(*fingerprint.as_bytes())),
        );
        let stranger = Requester::new(
            &principal,
            AuthPath::Pin,
            Some(PeerFingerprint::new([7; 32])),
        );
        let authorizer = RoleResolvingAuthorizer::new(Policy::default(), trust);

        let verdict = authorizer.check(&matching, Action::ExecRun, ResourceRef::unowned("exec"));
        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.rule, None);
        assert_eq!(
            verdict.granted_by(),
            Some(GrantBasis::Role(TrustRole::Full))
        );

        let verdict = authorizer.check(&stranger, Action::ExecRun, ResourceRef::unowned("exec"));
        assert_eq!(verdict, Verdict::DENY);
        // `forward.socks` stays behind the always-deny gate even for `full`.
        let verdict =
            authorizer.check(&matching, Action::ForwardSocks, ResourceRef::unowned("h:1"));
        assert_eq!(verdict, Verdict::DENY);
    }
}
