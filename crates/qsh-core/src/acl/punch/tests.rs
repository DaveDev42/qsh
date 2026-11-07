use std::sync::Arc;

use qsh_transport::{AuthPath, Fingerprint, Principal};

use super::*;
use crate::acl::{GrantBasis, ROLE_GRANTS, Role, load_or_deny};
use crate::audit::{AuditRecord, FailingAuditSink, MemoryAuditSink};
use crate::broker::PeerFingerprint;
use crate::config::Paths;
use crate::trust::{SharedTrustStore, TrustRole};

/// A sandbox config dir with a `trust.toml` pinning `phone` and an optional
/// `acl.toml`, and the production authorizer built over it.
struct Sandbox {
    _dir: tempfile::TempDir,
    fingerprint: Fingerprint,
    authorizer: Arc<dyn Authorizer>,
}

fn sandbox(extra_pin_keys: &str, acl: Option<&str>) -> Sandbox {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    let fingerprint = Fingerprint::of_spki_der(b"phone");
    std::fs::write(
        paths.trust_file(),
        format!(
            "[[peer]]\nname = \"phone\"\nfingerprint = \"{fingerprint}\"\n\
             address = \"\"\nadded_at = \"t\"\n{extra_pin_keys}"
        ),
    )
    .unwrap();
    if let Some(text) = acl {
        let path = dir.path().join("acl.toml");
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        crate::config::write_private_file(&path, text.as_bytes()).unwrap();
    }
    let trust = SharedTrustStore::open(paths.trust_file()).unwrap();
    let (authorizer, _diagnostic) = load_or_deny(&paths, Role::Serve, trust);
    Sandbox {
        _dir: dir,
        fingerprint,
        authorizer,
    }
}

fn phone() -> Principal {
    Principal::Device("phone".into())
}

fn check(sb: &Sandbox, audit: &dyn AuditSink, op: PunchOp) -> Result<(), OpError> {
    let principal = phone();
    let requester = Requester::new(
        &principal,
        AuthPath::Pin,
        Some(PeerFingerprint::new(*sb.fingerprint.as_bytes())),
    );
    check_punch(sb.authorizer.as_ref(), audit, op, &requester)
}

fn allowed(sb: &Sandbox) -> bool {
    check(sb, &MemoryAuditSink::new(), PunchOp::Request).is_ok()
}

#[test]
fn op_names_and_action_are_pinned() {
    let names: Vec<&str> = PUNCH_OPS.iter().map(|op| op.as_str()).collect();
    assert_eq!(names, ["punch.request", "punch.offer", "punch.rendezvous"]);
    for op in PUNCH_OPS {
        assert_eq!(op.action(), Action::HostPunch);
    }
    assert_eq!(Action::HostPunch.as_str(), "host.punch");
    assert_eq!("host.punch".parse::<Action>(), Ok(Action::HostPunch));
    assert!(!Action::HostPunch.is_always_denied());
}

/// ADR-0054 결정 6: every role but `none` grants `host.punch`.
#[test]
fn role_grants_table_has_host_punch_for_every_role_but_none() {
    for grant in ROLE_GRANTS {
        let has = grant.actions.contains(&Action::HostPunch);
        assert_eq!(
            has,
            grant.role != TrustRole::None,
            "{}: host.punch in the role table",
            grant.role
        );
    }
}

/// The same table, observed through the production authorizer and the audit
/// record rather than read off the constant.
#[test]
fn each_role_decides_host_punch_through_the_choke_point() {
    for role in TrustRole::ALL {
        let sb = sandbox(&format!("role = \"{role}\"\n"), None);
        let audit = MemoryAuditSink::new();
        let result = check(&sb, &audit, PunchOp::Request);
        let records = audit.records();
        assert_eq!(records.len(), 1, "{role}: one record per decision");
        if role == TrustRole::None {
            assert!(result.is_err(), "{role} must be denied");
            assert_eq!(records[0].decision, "deny");
            assert_eq!(records[0].role, None);
        } else {
            assert!(result.is_ok(), "{role} must be allowed");
            assert_eq!(records[0].decision, "allow");
            assert_eq!(records[0].role.as_deref(), Some(role.as_str()));
        }
    }
}

#[test]
fn a_pin_without_a_role_or_row_is_default_deny() {
    let sb = sandbox("", None);
    assert!(!allowed(&sb));
}

#[test]
fn a_row_grants_host_punch_to_a_peer_without_a_role() {
    let sb = sandbox(
        "role = \"none\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"host.punch\"]\n"),
    );
    let audit = MemoryAuditSink::new();
    assert!(check(&sb, &audit, PunchOp::Offer).is_ok());
    let record = &audit.records()[0];
    assert_eq!(record.decision, "allow");
    assert_eq!(record.rule, Some(0));
    assert_eq!(record.role, None);
}

#[test]
fn a_host_family_row_covers_host_punch() {
    let sb = sandbox(
        "role = \"none\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"host.*\"]\n"),
    );
    assert!(allowed(&sb));
}

#[test]
fn a_row_for_another_action_or_peer_does_not_grant_host_punch() {
    let other_action = sandbox(
        "role = \"none\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"host.reverse\"]\n"),
    );
    assert!(!allowed(&other_action));
    let other_peer = sandbox(
        "role = \"none\"\n",
        Some("[[acl]]\nprincipal = \"device:tablet\"\nallow = [\"host.punch\"]\n"),
    );
    assert!(!allowed(&other_peer));
}

/// Role wins as the recorded basis when role and row would both allow
/// (ADR-0045 결정 4); a row cannot take a role grant away, because the
/// grammar is allow-only.
#[test]
fn role_and_row_union_with_the_role_as_basis() {
    let sb = sandbox(
        "role = \"reverse\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"host.punch\"]\n"),
    );
    let principal = phone();
    let requester = Requester::new(
        &principal,
        AuthPath::Pin,
        Some(PeerFingerprint::new(*sb.fingerprint.as_bytes())),
    );
    let verdict = sb.authorizer.check(
        &requester,
        Action::HostPunch,
        ResourceRef::unowned("punch.request"),
    );
    assert_eq!(
        verdict.granted_by(),
        Some(GrantBasis::Role(TrustRole::Reverse))
    );
}

/// `qsh trust allow <peer> host.punch` writes a pin grant; `deny` removes it.
#[test]
fn a_pin_grant_allows_host_punch_and_records_its_basis() {
    let sb = sandbox("role = \"none\"\ngrants = [\"host.punch\"]\n", None);
    let audit = MemoryAuditSink::new();
    assert!(check(&sb, &audit, PunchOp::Rendezvous).is_ok());
    let record = &audit.records()[0];
    assert_eq!(record.grant.as_deref(), Some("pin"));
    assert_eq!(record.resource, "punch.rendezvous");
}

#[test]
fn an_unparseable_acl_toml_denies_host_punch_even_for_a_role_free_row() {
    let sb = sandbox(
        "role = \"none\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"host.punch\"\n"),
    );
    assert!(!allowed(&sb));
}

/// The always-deny gate and an unreadable acl.toml are the only things that
/// outrank a role, and `host.punch` is not behind the always-deny gate.
#[test]
fn an_unparseable_acl_toml_denies_every_peer_roles_included() {
    let sb = sandbox(
        "role = \"full\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"host.punch\"\n"),
    );
    // Roles still work when only acl.toml is missing; a broken file denies
    // all (CLAUDE.md, security defaults).
    assert!(!allowed(&sb));
}

#[test]
fn a_stranger_fingerprint_gets_no_role_grant() {
    let sb = sandbox("role = \"full\"\n", None);
    let principal = phone();
    let requester = Requester::new(
        &principal,
        AuthPath::Pin,
        Some(PeerFingerprint::new([7; 32])),
    );
    let audit = MemoryAuditSink::new();
    assert!(check_punch(sb.authorizer.as_ref(), &audit, PunchOp::Offer, &requester).is_err());
    assert_eq!(audit.records()[0].decision, "deny");
}

#[test]
fn a_failed_audit_write_turns_an_allow_into_the_same_denial() {
    let sb = sandbox("role = \"full\"\n", None);
    let audit = FailingAuditSink::new();
    audit.fail();
    let err = check(&sb, &audit, PunchOp::Request).unwrap_err();
    let denied = check(
        &sandbox("", None),
        &MemoryAuditSink::new(),
        PunchOp::Request,
    )
    .unwrap_err();
    assert_eq!(err.code, qsh_proto::ErrorCode::PermissionDenied);
    assert_eq!(err.message, PERMISSION_DENIED_MESSAGE);
    assert_eq!(err.message, denied.message);
    assert_eq!(err.code, denied.code);
}

/// ADR-0054 결정 20: no address field exists on the record, and nothing in
/// the serialized line looks like one.
#[test]
fn the_audit_record_is_structural_and_carries_no_address() {
    let record = AuditRecord::punch_signal(
        &phone(),
        AuthPath::Pin,
        "punch.offer",
        Decision::Allow,
        None,
    );
    assert_eq!(record.action, "host.punch");
    assert_eq!(record.resource, "punch.offer");
    assert_eq!(record.request_id, "-");
    assert_eq!(record.peer_addr, "-");
    let line = serde_json::to_string(&record).unwrap();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    let keys: std::collections::BTreeSet<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    // The same key set every other record has; no candidate, endpoint or
    // address-bearing key joins it.
    for key in keys {
        assert!(
            [
                "ts",
                "request_id",
                "principal",
                "action",
                "resource",
                "decision",
                "rule",
                "auth_path",
                "peer_addr",
                "count",
                "role",
                "grant"
            ]
            .contains(&key),
            "unexpected audit key {key}"
        );
    }
    assert!(!line.contains("127.0.0.1") && !line.contains("[::"));
}

#[test]
fn every_decision_is_recorded_once_with_the_op_name_as_resource() {
    let sb = sandbox("role = \"exec\"\n", None);
    let audit = MemoryAuditSink::new();
    for op in PUNCH_OPS {
        check(&sb, &audit, op).unwrap();
    }
    let resources: Vec<String> = audit.records().into_iter().map(|r| r.resource).collect();
    assert_eq!(
        resources,
        ["punch.request", "punch.offer", "punch.rendezvous"]
    );
}
