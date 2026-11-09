use std::net::SocketAddr;
use std::sync::Arc;

use qsh_transport::{AuthPath, Fingerprint, Principal};

use super::*;
use crate::acl::{ROLE_GRANTS, Role, load_or_deny};
use crate::audit::{FailingAuditSink, MemoryAuditSink};
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

fn peer() -> SocketAddr {
    "127.0.0.1:9".parse().unwrap()
}

fn check(sb: &Sandbox, audit: &dyn AuditSink, op: AgentOp) -> AgentVerdict {
    let principal = phone();
    let requester = Requester::new(
        &principal,
        AuthPath::Pin,
        Some(PeerFingerprint::new(*sb.fingerprint.as_bytes())),
    );
    check_agent(sb.authorizer.as_ref(), audit, 7, op, &requester, peer())
}

#[test]
fn op_names_and_action_are_pinned() {
    let names: Vec<&str> = AGENT_OPS.iter().map(|op| op.as_str()).collect();
    assert_eq!(names, ["session.open", "session.attach", "exec.run"]);
    for op in AGENT_OPS {
        assert_eq!(op.action(), Action::ForwardAgent);
    }
    assert_eq!(Action::ForwardAgent.as_str(), "forward.agent");
    assert_eq!("forward.agent".parse::<Action>(), Ok(Action::ForwardAgent));
    // Not behind the always-deny gate (ADR-0055 decision 16).
    assert!(!Action::ForwardAgent.is_always_denied());
}

/// ADR-0055 decision 16: `full` and `exec` grant `forward.agent`; no other
/// role does.
#[test]
fn role_grants_table_has_forward_agent_for_full_and_exec_only() {
    for grant in ROLE_GRANTS {
        let has = grant.actions.contains(&Action::ForwardAgent);
        assert_eq!(
            has,
            matches!(grant.role, TrustRole::Full | TrustRole::Exec),
            "{}: forward.agent in the role table",
            grant.role
        );
    }
}

/// The same table observed through the production authorizer and the audit
/// record: one record per decision, and the roles without the grant (and a
/// pin with no role at all) are `Denied`.
#[test]
fn each_role_decides_forward_agent_through_the_choke_point() {
    for role in TrustRole::ALL {
        let sb = sandbox(&format!("role = \"{role}\"\n"), None);
        let audit = MemoryAuditSink::new();
        let verdict = check(&sb, &audit, AgentOp::SessionOpen);
        let records = audit.records();
        assert_eq!(records.len(), 1, "{role}: one record per decision");
        if matches!(role, TrustRole::Full | TrustRole::Exec) {
            assert_eq!(verdict, AgentVerdict::Allowed, "{role}");
            assert_eq!(records[0].decision, "allow");
            assert_eq!(records[0].role.as_deref(), Some(role.as_str()));
        } else {
            assert_eq!(verdict, AgentVerdict::Denied, "{role}");
            assert_eq!(records[0].decision, "deny");
        }
    }
    let unroled = sandbox("", None);
    assert_eq!(
        check(&unroled, &MemoryAuditSink::new(), AgentOp::ExecRun),
        AgentVerdict::Denied
    );
}

#[test]
fn a_row_or_a_pin_grant_gives_forward_agent_to_a_peer_whose_role_does_not() {
    let by_row = sandbox(
        "role = \"tunnel\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"forward.agent\"]\n"),
    );
    assert_eq!(
        check(&by_row, &MemoryAuditSink::new(), AgentOp::SessionAttach),
        AgentVerdict::Allowed
    );
    let by_pin = sandbox("role = \"tunnel\"\ngrants = [\"forward.agent\"]\n", None);
    let audit = MemoryAuditSink::new();
    assert_eq!(
        check(&by_pin, &audit, AgentOp::SessionOpen),
        AgentVerdict::Allowed
    );
    assert_eq!(audit.records()[0].grant.as_deref(), Some("pin"));
}

/// ADR-0055 decision 16: a `forward.*` row picks the action up.
#[test]
fn a_forward_family_row_covers_forward_agent() {
    let sb = sandbox(
        "role = \"none\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"forward.*\"]\n"),
    );
    assert_eq!(
        check(&sb, &MemoryAuditSink::new(), AgentOp::ExecRun),
        AgentVerdict::Allowed
    );
}

#[test]
fn an_unparseable_acl_toml_denies_forward_agent_roles_included() {
    let sb = sandbox(
        "role = \"full\"\n",
        Some("[[acl]]\nprincipal = \"device:phone\"\nallow = [\"forward.agent\"\n"),
    );
    assert_eq!(
        check(&sb, &MemoryAuditSink::new(), AgentOp::SessionOpen),
        AgentVerdict::Denied
    );
}

/// An allow that could not be recorded is not an allow, and it is told apart
/// from a policy denial (`UNAVAILABLE`, not `DENIED`).
#[test]
fn a_failed_audit_write_is_audit_failed_not_allowed() {
    let sb = sandbox("role = \"full\"\n", None);
    let audit = FailingAuditSink::new();
    audit.fail();
    assert_eq!(
        check(&sb, &audit, AgentOp::SessionOpen),
        AgentVerdict::AuditFailed
    );
    // A policy denial stays a denial even when the audit also fails.
    let denied = sandbox("role = \"tunnel\"\n", None);
    assert_eq!(
        check(&denied, &audit, AgentOp::SessionOpen),
        AgentVerdict::Denied
    );
}

/// ADR-0055 decision 17: the record names the request and the op, and holds
/// nothing that could be a socket path, a channel or an agent message.
#[test]
fn the_audit_record_is_structural() {
    let sb = sandbox("role = \"exec\"\n", None);
    let audit = MemoryAuditSink::new();
    for op in AGENT_OPS {
        assert_eq!(check(&sb, &audit, op), AgentVerdict::Allowed);
    }
    let records = audit.records();
    let resources: Vec<&str> = records.iter().map(|r| r.resource.as_str()).collect();
    assert_eq!(resources, ["session.open", "session.attach", "exec.run"]);
    for record in &records {
        assert_eq!(record.action, "forward.agent");
        assert_eq!(record.request_id, "7");
        assert_eq!(record.principal, "device:phone");
        let line = serde_json::to_string(record).unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        for key in value.as_object().unwrap().keys() {
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
                .contains(&key.as_str()),
                "unexpected audit key {key}"
            );
        }
        assert!(!line.contains(".sock") && !line.contains("agent/"));
    }
}
