//! The production [`Authorizer`]'s trust-store half (ADR-0045 결정 6,
//! PLAN M15 Step 3).
//!
//! [`RoleResolvingAuthorizer`] wraps the authorizer `acl::load` built from
//! `acl.toml` (a [`super::Policy`], or [`super::DenyAll`] when the file
//! cannot be used) together with the process's [`SharedTrustStore`]. Every
//! decision first resolves the requester's trust role against the current
//! `trust.toml`, then delegates.
//!
//! **This step does not change any decision.** The resolved role is traced
//! and dropped; the delegate's verdict is returned untouched. The role stage
//! ⓡ that turns the role into an allow lands in `Policy::decide` with the
//! next step. Wiring the per-decision `trust.toml` refresh first is what
//! lets its cost be measured apart from the change in meaning
//! (`crates/qsh-testkit/tests/role_resolution_cost.rs`).

use std::sync::Arc;

use crate::trust::SharedTrustStore;

use super::{Action, Authorizer, Requester, ResourceRef, Verdict};

/// An [`Authorizer`] that resolves the requester's trust role on every
/// call. See the module doc.
pub struct RoleResolvingAuthorizer {
    inner: Arc<dyn Authorizer>,
    trust: Arc<SharedTrustStore>,
}

impl RoleResolvingAuthorizer {
    /// Wrap `inner`, resolving roles against `trust`.
    pub fn new(inner: Arc<dyn Authorizer>, trust: Arc<SharedTrustStore>) -> Self {
        Self { inner, trust }
    }
}

impl std::fmt::Debug for RoleResolvingAuthorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleResolvingAuthorizer")
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
        let role = self.trust.resolve_role(
            requester.principal,
            requester.auth_path,
            requester.fingerprint,
        );
        // Not an input to the verdict yet (module doc). Logged at trace so
        // the lookup is observable and cannot be optimised away; the role
        // name is not secret and no key material is involved.
        tracing::trace!(?role, %action, "resolved the requester's trust role");
        self.inner.check(requester, action, resource)
    }
}

#[cfg(test)]
mod tests {
    use qsh_transport::{AuthPath, Fingerprint, Principal};

    use super::*;
    use crate::acl::{AllowAllPinned, Decision, DenyAll};
    use crate::broker::PeerFingerprint;

    /// Step 3 changes no decision: a pin whose role is `full` and whose
    /// fingerprint matches the connection still gets exactly what the
    /// wrapped authorizer says. The role only starts to count in Step 4.
    #[test]
    fn the_resolved_role_does_not_change_the_wrapped_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let fingerprint = Fingerprint::of_spki_der(b"phone");
        std::fs::write(
            &path,
            format!(
                "[[peer]]\nname = \"phone\"\nfingerprint = \"{fingerprint}\"\n\
                 address = \"\"\nadded_at = \"t\"\nrole = \"full\"\n"
            ),
        )
        .unwrap();
        let trust = SharedTrustStore::open(&path).unwrap();
        let principal = Principal::Device("phone".into());
        let requester = Requester::new(
            &principal,
            AuthPath::Pin,
            Some(PeerFingerprint::new(*fingerprint.as_bytes())),
        );
        // Both a matching and a mismatching fingerprint: same verdicts.
        let stranger = Requester::new(
            &principal,
            AuthPath::Pin,
            Some(PeerFingerprint::new([7; 32])),
        );

        let deny = RoleResolvingAuthorizer::new(Arc::new(DenyAll), Arc::clone(&trust));
        let allow = RoleResolvingAuthorizer::new(Arc::new(AllowAllPinned), trust);
        for r in [&requester, &stranger] {
            let unowned = ResourceRef::unowned("exec");
            assert_eq!(
                deny.check(r, Action::ExecRun, unowned).decision,
                Decision::Deny
            );
            assert_eq!(
                allow.check(r, Action::ExecRun, unowned).decision,
                Decision::Allow
            );
        }
    }
}
