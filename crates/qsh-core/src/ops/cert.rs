//! `cert.init`/`cert.issue` — the private CA frontend
//! (`docs/adr/0008-private-ca-cert-issuance.md`, `PLAN.md` M7 Step 5).
//!
//! Both operations are local-only: `cert.init` never touches the network,
//! and `cert.issue` only ever promotes *this* device's own identity (ADR
//! §5) — there is no dial, no remote `device_id` argument, and no new ACL
//! surface (`qsh cert` is unauthenticated local config work, exactly like
//! `identity.init`). All cryptography lives in [`crate::ca`]; this module
//! only sequences it and reports the result.

use qsh_proto::{
    CaRegistration, CertInitData, CertInitReq, CertIssueData, CertIssueReq, ErrorCode,
};

use crate::ca;
use crate::ops::{OpError, Operation, Ops};
use crate::trust::TrustStore;

/// The `cert.init` operation (`qsh cert init`).
pub struct CertInitOp;

impl Operation for CertInitOp {
    const COMMAND: &'static str = "cert.init";
}

/// The `cert.issue` operation (`qsh cert issue`).
pub struct CertIssueOp;

impl Operation for CertIssueOp {
    const COMMAND: &'static str = "cert.issue";
}

/// Name this device registers its own CA root under in `trust.toml
/// [[ca]]`. Fixed rather than operator-chosen: ADR-0008 §5 keeps `qsh
/// cert` scoped to a single local device/CA pair in M7, and
/// `TrustStore::add_ca`'s update-in-place semantics mean a CA re-init
/// still lands correctly under this one name on the next `cert issue`.
const LOCAL_CA_NAME: &str = "local";

fn config_error(message: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::ConfigError, message).with_retryable(false)
}

impl Ops {
    /// `cert.init` — create the local private CA root if it does not
    /// exist yet (idempotent: an existing root comes back with `created:
    /// false`, mirroring `identity.init`).
    pub fn cert_init(&self, _req: CertInitReq) -> Result<CertInitData, OpError> {
        let outcome = ca::init(&self.paths)?;
        let config_dir = std::fs::canonicalize(&self.paths.config_dir)
            .unwrap_or_else(|_| self.paths.config_dir.clone())
            .display()
            .to_string();
        Ok(CertInitData {
            fingerprint: outcome.root.fingerprint.to_string(),
            config_dir,
            created: outcome.created,
        })
    }

    /// `cert.issue` — CA-sign this device's existing identity
    /// (`qsh://device/<device_id>` SAN, ADR-0008 §2 — the SAN body never
    /// changes, only its signer) and register the CA root in `trust.toml
    /// [[ca]]`.
    ///
    /// Idempotent in two independent ways: re-issuing a leaf already
    /// signed by *this* local CA is a no-op (`issued: false`) rather than
    /// a silent rotation, and re-registering the same root under
    /// [`LOCAL_CA_NAME`] follows `TrustStore::add_ca`'s own no-op/update
    /// rule.
    ///
    /// Requires `qsh init` (an identity to promote) and `qsh cert init`
    /// (a CA to promote it with) to have already run; both missing
    /// prerequisites report `CONFIG_ERROR` with a remedy in the message,
    /// never a bespoke code (mirrors `identity::load`'s own precedent).
    pub fn cert_issue(&self, _req: CertIssueReq) -> Result<CertIssueData, OpError> {
        let identity = crate::identity::read_identity(&self.paths)?
            .ok_or_else(|| config_error("no local identity; run `qsh init` first"))?;
        let root = ca::read_root(&self.paths)?
            .ok_or_else(|| config_error("no local CA; run `qsh cert init` first"))?;
        let root_fingerprint = root.fingerprint.to_string();

        let already_issued = identity.issued_by_ca.as_deref() == Some(root_fingerprint.as_str());
        let (fingerprint, issued) = if already_issued {
            (identity.fingerprint.to_string(), false)
        } else {
            let loaded = self
                .load_identity()?
                .ok_or_else(|| config_error("no local identity; run `qsh init` first"))?;
            let leaf = ca::issue_device_leaf(
                &self.paths,
                &identity.device_id,
                &loaded.local.key_pkcs8_der,
            )?;
            let promoted = crate::identity::promote_to_ca_issued(
                &self.paths,
                &leaf.cert_pem,
                &leaf.cert_der,
                &root_fingerprint,
            )?;
            (promoted.fingerprint.to_string(), true)
        };

        let path = self.paths.trust_file();
        // Whole load→mutate→save under lock, not just the write — same
        // discipline as `Ops::trust_add`/`trust_remove`/`trust_accept`
        // (`TrustStore::lock`'s own doc, `PLAN.md` M7 Step 7-1). Acquired
        // only now, after the local crypto work above (no network I/O
        // under this lock).
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let (entry, created, updated) = store.add_ca(LOCAL_CA_NAME, root.cert_pem.clone());
        if created || updated {
            store.save(&path)?;
        }

        Ok(CertIssueData {
            device_id: identity.device_id,
            fingerprint,
            issued,
            ca: CaRegistration {
                name: entry.name,
                fingerprint: root_fingerprint,
                created,
                updated: (!created).then_some(updated),
            },
        })
    }
}
