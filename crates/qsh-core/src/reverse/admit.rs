//! The `host.reverse` authorization choke point (`docs/design/protocol.md`
//! §11-2, `PLAN.md` Step 3, PR 3a) — the "인가" half of Step 3's file list
//! that [`super::registry::Registry`] deliberately does not hold, so that
//! file stays transport-free ahead of the `PLAN.md` Step 5 arch-lint (see
//! `registry`'s module docs).
//!
//! [`admit`] is the whole authorization/insert pipeline as one pure-logic
//! function: PR 3b's `reverse/listen.rs` calls it once per accepted,
//! `Hello.reverse`-carrying connection and does nothing else with ACL — the
//! same shape `server::Server::handle_exec_start` established for the
//! forward choke point (`docs/design/architecture.md` §6).

use std::net::SocketAddr;

use qsh_proto::ErrorCode;
use qsh_transport::{AuthPath, Principal};

use crate::acl::{Action, Authorizer, Decision, ResourceRef};
use crate::audit::{AuditRecord, AuditSink};
use crate::ops::OpError;

use super::registry::{AdmittedEntry, RegisterOutcome, Registry, host_reverse_denied};

/// Everything [`admit`] needs about one connection's `Hello` — gathered by
/// 3b's `listen.rs` from the already-authenticated connection and its
/// `ReverseRegistration`.
pub struct AdmitRequest<'a> {
    /// The connection's authenticated principal — from the certificate,
    /// never from `offered_name` (`docs/design/protocol.md` §3).
    pub principal: &'a Principal,
    /// How the peer authenticated: the other ACL input, and what gates
    /// trust-store alias eligibility (see [`admit`]).
    pub auth_path: AuthPath,
    /// SPKI SHA-256 fingerprint of the peer's verified leaf certificate.
    pub fingerprint: qsh_transport::Fingerprint,
    /// Peer socket address at connection time.
    pub address: SocketAddr,
    /// `ReverseRegistration.offered_name`, verbatim off the wire — **never**
    /// an authentication or authorization input by itself (name-squatting
    /// prevention, `docs/design/protocol.md` §11-2).
    pub offered_name: &'a str,
    /// `Hello.capabilities` (the negotiated intersection).
    pub capabilities: Vec<String>,
}

/// Register a reverse target as a host, or refuse to
/// (`docs/design/protocol.md` §11-2). In order:
///
/// 1. **Shape** — `offered_name` must be empty or a valid host name.
///    Violation is `INVALID_ARGUMENT`, **never audited**: this runs before
///    the choke point and doesn't depend on who the peer is
///    (protocol.md §9's "check shape first" discipline).
/// 2. **Name resolution** — the peer's trust-store alias if it has one
///    (only possible when `auth_path == Pin`: pinned-ness is a property of
///    *how* the peer authenticated, never of what its `principal` looks
///    like — `acl` module docs) **and** it satisfies the same shape rule as
///    `offered_name` (`Ops::trust_add` doesn't enforce this at pin time, so
///    a malformed operator alias is reachable here), else `offered_name`
///    but only when `allow_advertised_names` was set, else
///    `PERMISSION_DENIED`. This step only reads the trust-store-derived
///    alias (nothing is created), and like the shape check runs before the
///    choke point — but unlike the shape check it **is** audited on refusal
///    (see below): by this point the peer is fully authenticated and the
///    refusal is exactly the kind of connection-level decision
///    `docs/design/architecture.md` §6 wants visible, even though there is
///    no resolved name to use as `resource`. Every `PERMISSION_DENIED` this
///    function returns — this step's two failure modes and the choke-point
///    deny below — carries the identical opaque
///    [`super::registry::host_reverse_denied`] message, so a peer cannot
///    distinguish them from one another.
/// 3. **The `host.reverse` choke point** — [`Authorizer::check`] on the
///    now-resolved name as `resource`, audited unconditionally (allow *or*
///    deny) before any entry exists. A deny creates nothing.
/// 4. **Insert** — only on a pass, via [`Registry::admit`].
///
/// Every early return leaves the registry exactly as it was — no partial
/// entry is ever visible.
pub fn admit(
    registry: &Registry,
    authorizer: &dyn Authorizer,
    audit: &dyn AuditSink,
    req: AdmitRequest<'_>,
) -> Result<RegisterOutcome, OpError> {
    let alias = trust_alias(req.principal, req.auth_path);

    let name = match registry.resolve_name(alias, req.offered_name) {
        Ok(name) => name,
        Err(err) if err.code == ErrorCode::PermissionDenied => {
            // Two `Registry::resolve_name` failure modes land here, both
            // fully authenticated and both `host_reverse_denied()`
            // (identical message either way — see that function's docs):
            // (ii) the trust-store alias failed shape validation, or (iii)
            // there is no alias and advertised names aren't allowed. There
            // is no resolved name to use as `resource` — unlike the shape
            // check, this refusal is still audited, because the peer *is*
            // authenticated and a silent deny here would leave zero trace
            // of repeated registration attempts from a trusted-cert-holding
            // peer (`docs/design/architecture.md` §6: every authorization
            // decision on an authenticated peer is observable).
            // `offered_name` — never the alias, which must not appear in an
            // audit `resource` field either (case (ii) would otherwise
            // disclose exactly the alias content the opaque error message
            // is withholding) — is already shape-validated at this point
            // (bounded `[A-Za-z0-9._-]{1,64}` or empty), so it is safe to
            // use verbatim as `resource`; empty becomes `"-"`.
            let resource = if req.offered_name.is_empty() {
                "-"
            } else {
                req.offered_name
            };
            // Already denying (pre-choke-point failure): a failure to
            // record this deny doesn't change the outcome, only the
            // diagnostic.
            let _ = audit.record(&AuditRecord::connection_level(
                req.principal,
                req.auth_path,
                Action::HostReverse,
                resource,
                Decision::Deny,
                // Pre-choke-point: name resolution failed, never reached
                // `Authorizer::check`, so no rule index applies.
                None,
                req.address,
            ));
            return Err(err);
        }
        Err(err) => return Err(err), // shape violation: not audited
    };

    // ---- ACL choke point: decide + audit BEFORE any resource. ----
    let verdict = authorizer.check(
        req.principal,
        req.auth_path,
        Action::HostReverse,
        ResourceRef::unowned(&name),
    );
    // A connection-level decision, not a reply to a control-stream
    // request — `AuditRecord::connection_level` records `request_id: "-"`
    // (mirroring `AuditRecord::handshake_rejected`'s convention) so it can
    // never be confused with a peer-chosen wire request `0`.
    let recorded = audit.record(&AuditRecord::connection_level(
        req.principal,
        req.auth_path,
        Action::HostReverse,
        &name,
        verdict.decision,
        verdict.rule,
        req.address,
    ));
    // Fail-closed: an allow verdict that failed to make it into the audit
    // log is denied — never register the reverse listener without a
    // durable record of having authorized it.
    if !verdict.is_allow() || recorded.is_err() {
        // Identical opaque message to both `resolve_name` denial cases
        // above — see `host_reverse_denied`'s docs.
        return Err(host_reverse_denied());
    }

    // ---- Allowed: insert, honoring the conflict rule. ----
    registry.admit(
        name,
        AdmittedEntry {
            fingerprint: &req.fingerprint.to_string(),
            principal: &req.principal.to_string(),
            address: req.address,
            capabilities: req.capabilities,
        },
    )
}

/// The trust-store alias this peer would register under, if any.
///
/// A pin always resolves to `Principal::Device(<peer.name>)`
/// (`trust::TrustStore::parsed_pins`), and pinned-ness is a property of
/// *how* the peer authenticated ([`AuthPath::Pin`]), never of what its
/// `Principal` looks like (`acl` module docs: a CA-issued leaf can legally
/// assert a `Device` principal too). So this only ever returns `Some` for
/// `AuthPath::Pin`, regardless of principal shape.
fn trust_alias(principal: &Principal, auth_path: AuthPath) -> Option<&str> {
    match (auth_path, principal) {
        (AuthPath::Pin, Principal::Device(name)) => Some(name.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use qsh_transport::Fingerprint;

    use super::*;
    use crate::acl::{AllowAllPinned, DenyAll};
    use crate::audit::{FailingAuditSink, MemoryAuditSink};
    use crate::broker::TestClock;

    fn addr() -> SocketAddr {
        "127.0.0.1:4433".parse().unwrap()
    }

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_spki_der(seed)
    }

    struct Fixture {
        registry: Registry,
        audit: Arc<MemoryAuditSink>,
    }

    fn fixture(allow_advertised_names: bool) -> Fixture {
        let audit = Arc::new(MemoryAuditSink::new());
        let registry = Registry::new(Arc::new(TestClock::new()), allow_advertised_names);
        Fixture { registry, audit }
    }

    fn req<'a>(
        principal: &'a Principal,
        auth_path: AuthPath,
        fingerprint: Fingerprint,
        offered_name: &'a str,
    ) -> AdmitRequest<'a> {
        AdmitRequest {
            principal,
            auth_path,
            fingerprint,
            address: addr(),
            offered_name,
            capabilities: vec!["exec".to_string()],
        }
    }

    #[test]
    fn alias_wins_and_registers_under_it() {
        let f = fixture(true);
        let authorizer = AllowAllPinned;
        let principal = Principal::Device("personal-mac".into());
        let outcome = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"a"), "attacker-chosen-name"),
        )
        .expect("alias registration succeeds");
        assert_eq!(outcome.entry.name, "personal-mac");
        assert_eq!(outcome.entry.generation, 0);
        assert!(outcome.replaced_generation.is_none());
        assert_eq!(outcome.entry.principal, "device:personal-mac");
        assert_eq!(outcome.entry.fingerprint, fp(b"a").to_string());
    }

    /// A fully authenticated peer that can't resolve to any name (no
    /// alias, advertised names off) is refused, but — unlike the shape
    /// check — the refusal **is** audited: this peer already passed mTLS,
    /// so its repeated attempts must leave a trace (the fix for the
    /// "authenticated peer denied at name resolution produces zero audit
    /// records" gap).
    #[test]
    fn no_alias_and_advertised_names_disallowed_denies_and_is_audited() {
        let f = fixture(false);
        let authorizer = AllowAllPinned;
        let principal = Principal::User("dave".into());
        let err = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Ca, fp(b"a"), "some-name"),
        )
        .expect_err("no alias, advertised names off");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(f.registry.snapshot().is_empty());

        let records = f.audit.records();
        assert_eq!(records.len(), 1, "the refusal itself is audited");
        assert_eq!(records[0].action, "host.reverse");
        assert_eq!(records[0].decision, "deny");
        assert_eq!(records[0].resource, "some-name");
        assert_eq!(records[0].principal, "user:dave");
        assert_eq!(
            records[0].request_id, "-",
            "connection-level decision, never a wire request id"
        );
    }

    #[test]
    fn no_alias_no_offered_name_audits_with_dash_resource() {
        let f = fixture(false);
        let authorizer = AllowAllPinned;
        let principal = Principal::User("dave".into());
        let err = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Ca, fp(b"a"), ""),
        )
        .expect_err("nothing to resolve to");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        let records = f.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].resource, "-");
    }

    /// A pinned peer whose trust-store alias doesn't satisfy
    /// `wire::valid_host_name` (reachable because `Ops::trust_add` doesn't
    /// enforce this at pin time) is denied and audited exactly like the
    /// no-alias case, and — critically — the alias itself never appears in
    /// the audit `resource` field (only `offered_name`/`"-"` may).
    #[test]
    fn malformed_alias_denies_and_never_leaks_the_alias_into_the_audit_record() {
        let f = fixture(true);
        let authorizer = AllowAllPinned;
        let principal = Principal::Device("mac/work".into());
        let err = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"a"), "harmless-offered-name"),
        )
        .expect_err("alias contains '/', not a valid host name");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(f.registry.snapshot().is_empty());

        let records = f.audit.records();
        assert_eq!(records.len(), 1, "the refusal itself is audited");
        assert_eq!(records[0].action, "host.reverse");
        assert_eq!(records[0].decision, "deny");
        assert_eq!(
            records[0].resource, "harmless-offered-name",
            "resource is offered_name, never the malformed alias"
        );
    }

    /// The three `PERMISSION_DENIED` refusals this seam can produce — no
    /// alias, malformed alias, and choke-point deny — must be textually
    /// identical, so a peer probing the seam learns nothing about which
    /// check failed (finding 2 / adversarial review).
    #[test]
    fn every_permission_denied_refusal_carries_the_identical_message() {
        let no_alias_f = fixture(false);
        let no_alias = admit(
            &no_alias_f.registry,
            &AllowAllPinned,
            no_alias_f.audit.as_ref(),
            req(&Principal::User("dave".into()), AuthPath::Ca, fp(b"a"), ""),
        )
        .expect_err("no alias");

        let bad_alias_f = fixture(true);
        let bad_alias = admit(
            &bad_alias_f.registry,
            &AllowAllPinned,
            bad_alias_f.audit.as_ref(),
            req(
                &Principal::Device("mac/work".into()),
                AuthPath::Pin,
                fp(b"a"),
                "",
            ),
        )
        .expect_err("malformed alias");

        let choke_point_f = fixture(true);
        let choke_point = admit(
            &choke_point_f.registry,
            &DenyAll,
            choke_point_f.audit.as_ref(),
            req(
                &Principal::Device("personal-mac".into()),
                AuthPath::Pin,
                fp(b"a"),
                "",
            ),
        )
        .expect_err("choke-point deny");

        assert_eq!(no_alias.message, bad_alias.message);
        assert_eq!(no_alias.message, choke_point.message);
    }

    /// A policy that allows everything, regardless of `auth_path` — used
    /// only to isolate *name resolution* from the (separately tested)
    /// `AllowAllPinned` ACL outcome for non-`Pin` peers.
    struct AllowEverything;
    impl Authorizer for AllowEverything {
        fn check(
            &self,
            _: &Principal,
            _: AuthPath,
            _: Action,
            _: ResourceRef<'_>,
        ) -> crate::acl::Verdict {
            crate::acl::Verdict {
                decision: Decision::Allow,
                rule: None,
            }
        }
    }

    #[test]
    fn no_alias_and_advertised_names_allowed_uses_offered_name() {
        let f = fixture(true);
        let authorizer = AllowEverything;
        let principal = Principal::User("dave".into());
        let outcome = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Ca, fp(b"a"), "advertised-name"),
        )
        .expect("advertised name accepted");
        assert_eq!(outcome.entry.name, "advertised-name");
    }

    #[test]
    fn shape_violation_is_invalid_argument_with_zero_audit_lines() {
        let f = fixture(true);
        let authorizer = AllowAllPinned;
        let principal = Principal::Device("personal-mac".into());
        // Contains a space: not `valid_host_name` and not empty.
        let err = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"a"), "not a valid name"),
        )
        .expect_err("malformed offered_name");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(
            f.audit.records().is_empty(),
            "shape check runs before the choke point"
        );
        assert!(f.registry.snapshot().is_empty());
    }

    // ---- DenyAll: zero entries, zero connections, one audit deny line ----
    //
    // This test only discharges the registry-entry third of PLAN.md Step
    // 3's "DenyAll 하에서 registry entry·연결·ticket이 하나도 생성되지 않음"
    // row (`f.registry.snapshot().is_empty()` below). The connection and
    // ticket thirds are structurally out of PR 3a's reach — `admit` never
    // opens a connection or issues a ticket, only PR 3b's `listen.rs` does
    // — and are owed by that PR's `reverse_loopback.rs` integration test.

    #[test]
    fn deny_all_creates_nothing_and_audits_the_denial() {
        let f = fixture(false);
        let authorizer = DenyAll;
        let principal = Principal::Device("personal-mac".into());
        let err = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"a"), ""),
        )
        .expect_err("DenyAll denies everything");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(f.registry.snapshot().is_empty());

        let records = f.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "host.reverse");
        assert_eq!(records[0].decision, "deny");
        assert_eq!(records[0].resource, "personal-mac");
        assert_eq!(
            records[0].request_id, "-",
            "connection-level decision, never a wire request id"
        );
    }

    // ---- disk-full fail-closed: `PLAN.md` M5 Step 3(c), the fourth of the
    // "four authorization points" (`PLAN.md` §1) alongside `Server::
    // authorize`/`authorize_stream`/`authorize_session_control`. ----

    #[test]
    fn allowed_registration_fails_closed_when_the_audit_sink_cannot_record_it() {
        let f = fixture(true);
        let authorizer = AllowAllPinned;
        let principal = Principal::Device("personal-mac".into());
        let audit = FailingAuditSink::new();

        // Policy would allow this peer, but the audit sink cannot durably
        // record the decision — fail-closed: denied, and no entry is
        // created (`Registry::admit` never runs).
        audit.fail();
        let err = admit(
            &f.registry,
            &authorizer,
            &audit,
            req(&principal, AuthPath::Pin, fp(b"a"), ""),
        )
        .expect_err("audit failure denies even a policy-allowed registration");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(
            f.registry.snapshot().is_empty(),
            "no entry created while the audit sink is degraded"
        );

        // The writer recovers: the same policy-allowed request now
        // succeeds, and only now does an entry exist.
        audit.clear();
        let outcome = admit(
            &f.registry,
            &authorizer,
            &audit,
            req(&principal, AuthPath::Pin, fp(b"a"), ""),
        )
        .expect("registration succeeds once the audit sink recovers");
        assert_eq!(outcome.entry.name, "personal-mac");
        assert_eq!(f.registry.snapshot().len(), 1);
    }

    // ---- audit lines carry action="host.reverse" on both outcomes ----

    #[test]
    fn allow_and_deny_are_each_audited_as_host_reverse() {
        let allow_f = fixture(false);
        let allow_authorizer = AllowAllPinned;
        let principal = Principal::Device("personal-mac".into());
        admit(
            &allow_f.registry,
            &allow_authorizer,
            allow_f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"a"), ""),
        )
        .expect("pinned peer is allowed");
        let allow_records = allow_f.audit.records();
        assert_eq!(allow_records.len(), 1);
        assert_eq!(allow_records[0].action, "host.reverse");
        assert_eq!(allow_records[0].decision, "allow");

        // Unpinned (CA-asserted) principal: reaches the choke point (name
        // resolution succeeds via the advertised-name path) but is denied
        // by the interim allow-all-**pinned** policy — this is a distinct
        // failure mode from "no alias and advertised names disallowed"
        // above: here a `resource` name *does* exist, so it *is* audited.
        let deny_f = fixture(true);
        let deny_authorizer = AllowAllPinned;
        let unpinned = Principal::User("dave".into());
        let err = admit(
            &deny_f.registry,
            &deny_authorizer,
            deny_f.audit.as_ref(),
            req(&unpinned, AuthPath::Ca, fp(b"a"), "dave-laptop"),
        )
        .expect_err("CA path is not pinned under the interim policy");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        let deny_records = deny_f.audit.records();
        assert_eq!(deny_records.len(), 1);
        assert_eq!(deny_records[0].action, "host.reverse");
        assert_eq!(deny_records[0].decision, "deny");
        assert_eq!(deny_records[0].resource, "dave-laptop");
        assert!(deny_f.registry.snapshot().is_empty());
    }

    #[test]
    fn conflicting_fingerprint_is_invalid_argument_and_creates_nothing() {
        let f = fixture(false);
        let authorizer = AllowAllPinned;
        let principal = Principal::Device("shared".into());
        let first = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"a"), ""),
        )
        .expect("first registration");
        assert_eq!(first.entry.generation, 0);

        let err = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"b"), ""),
        )
        .expect_err("different fingerprint, same name");
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        let still = f.registry.get("shared").expect("original entry remains");
        assert_eq!(still.fingerprint, fp(b"a").to_string());
        assert_eq!(still.generation, 0);
    }

    #[test]
    fn same_fingerprint_reregistering_replaces_and_advances_generation() {
        let f = fixture(false);
        let authorizer = AllowAllPinned;
        let principal = Principal::Device("shared".into());
        let first = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"a"), ""),
        )
        .expect("first registration");
        assert_eq!(first.entry.generation, 0);
        assert!(first.replaced_generation.is_none());

        let second = admit(
            &f.registry,
            &authorizer,
            f.audit.as_ref(),
            req(&principal, AuthPath::Pin, fp(b"a"), ""),
        )
        .expect("reconnect from the same peer replaces the entry");
        assert_eq!(second.entry.generation, 1);
        assert_eq!(second.replaced_generation, Some(0));
        assert_eq!(f.registry.snapshot().len(), 1, "replaced, not duplicated");
    }
}
