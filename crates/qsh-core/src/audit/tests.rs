use super::*;
use qsh_transport::Principal;

fn sample() -> AuditRecord {
    AuditRecord::now(
        7,
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
        Action::ExecRun,
        "exec",
        Decision::Allow,
        None,
        "127.0.0.1:4433".parse().unwrap(),
    )
}

#[test]
fn record_has_only_structural_fields() {
    // Type-level guarantee, checked by enumerating the JSON keys: no
    // argv / payload / key field can appear.
    let value = serde_json::to_value(sample()).unwrap();
    let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "action",
            "auth_path",
            "decision",
            "peer_addr",
            "principal",
            "request_id",
            "resource",
            "rule",
            "ts"
        ]
    );
    // ADR-0045 결정 16: `role` is optional and omitted when `None`, so the
    // nine keys above are what every record written today carries.
    let mut with_role = sample();
    with_role.role = Some("full".into());
    let value_with_role = serde_json::to_value(&with_role).unwrap();
    let mut keys_with_role: Vec<_> = value_with_role
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys_with_role.sort();
    assert_eq!(
        keys_with_role,
        [
            "action",
            "auth_path",
            "decision",
            "peer_addr",
            "principal",
            "request_id",
            "resource",
            "role",
            "rule",
            "ts"
        ]
    );
    assert_eq!(value_with_role["role"], "full");
    assert_eq!(value["principal"], "device:laptop");
    assert_eq!(value["action"], "exec.run");
    assert_eq!(value["decision"], "allow");
    assert_eq!(value["request_id"], "7");
    assert_eq!(value["auth_path"], "pin");
    assert!(value["rule"].is_null());
    // ADR-0031 결정 8: the withdrawn-connection constructor adds no key
    // either (the separate test below pins its values).
    let withdrawn = AuditRecord::connection_withdrawn(
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
        "192.0.2.7:4433".parse().unwrap(),
        "trust_withdrawn",
    );
    let withdrawn = serde_json::to_value(&withdrawn).unwrap();
    let mut withdrawn_keys: Vec<_> = withdrawn.as_object().unwrap().keys().cloned().collect();
    withdrawn_keys.sort();
    assert_eq!(
        withdrawn_keys,
        [
            "action",
            "auth_path",
            "decision",
            "peer_addr",
            "principal",
            "request_id",
            "resource",
            "rule",
            "ts"
        ]
    );
    // ADR-0032 결정 15: a local `identity.move_key` record is the same nine
    // keys — nothing in the struct could carry the key being moved.
    let moved = AuditRecord::local_op(
        "identity.move_key",
        "-".to_string(),
        "platform->file".to_string(),
    );
    let moved = serde_json::to_value(&moved).unwrap();
    let mut moved_keys: Vec<_> = moved.as_object().unwrap().keys().cloned().collect();
    moved_keys.sort();
    assert_eq!(
        moved_keys,
        [
            "action",
            "auth_path",
            "decision",
            "peer_addr",
            "principal",
            "request_id",
            "resource",
            "rule",
            "ts"
        ]
    );
    assert_eq!(moved["action"], "identity.move_key");
    assert_eq!(moved["auth_path"], "local");
}

/// ADR-0031 결정 8: the record of a withdrawn connection adds no key. It is
/// the nine of every record, with `request_id` `"-"`, action `connect`, a
/// deny without a rule, and the established principal and path.
#[test]
fn connection_withdrawn_record_keeps_the_structural_key_set() {
    let addr: std::net::SocketAddr = "192.0.2.7:4433".parse().unwrap();
    for (reason, path) in [
        ("trust_withdrawn", AuthPath::Pin),
        ("grants_reduced", AuthPath::Ca),
    ] {
        let record = AuditRecord::connection_withdrawn(
            &qsh_transport::Principal::Device("laptop".into()),
            path,
            addr,
            reason,
        );
        let value = serde_json::to_value(&record).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "action",
                "auth_path",
                "decision",
                "peer_addr",
                "principal",
                "request_id",
                "resource",
                "rule",
                "ts"
            ]
        );
        assert_eq!(value["action"], "connect");
        assert_eq!(value["decision"], "deny");
        assert_eq!(value["request_id"], "-");
        assert_eq!(value["resource"], reason);
        assert_eq!(value["principal"], "device:laptop");
        assert_eq!(value["auth_path"], auth_path_str(path));
        assert_eq!(value["peer_addr"], "192.0.2.7:4433");
        assert!(value["rule"].is_null());
    }
}

#[test]
fn file_sink_appends_jsonl_with_private_perms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state").join("audit.log");
    let sink = FileAuditSink::new(&path);
    sink.record(&sample()).unwrap();
    sink.record(&sample()).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let back: AuditRecord = serde_json::from_str(line).unwrap();
        assert_eq!(back.decision, "allow");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);
    }
}

/// `FileAuditSink` is fail-closed too, not just `RotatingAuditSink`
/// (M5 plan Step 3 (2473c88)): a write it cannot perform is `Err`, never a
/// swallowed `tracing::error!` with the call site none the wiser. Kept
/// as the simplest-possible sink for callers that want one (tests)
/// even though `reverse::listen`'s controller itself moved onto
/// `RotatingAuditSink` (F7). A directory at the log path makes
/// `OpenOptions::open` fail deterministically (EISDIR), no real
/// disk-full condition required.
#[test]
fn file_sink_returns_err_when_the_path_cannot_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    fs::create_dir(&path).unwrap();
    let sink = FileAuditSink::new(&path);
    assert_eq!(sink.record(&sample()), Err(AuditError::Degraded));
}

#[test]
fn now_rfc3339_has_second_precision_and_z_suffix() {
    let ts = now_rfc3339();
    assert!(ts.ends_with('Z'), "{ts}");
    assert_eq!(ts.len(), "2026-08-17T00:00:00Z".len(), "{ts}");
}

// ---- F2: wait_for_sole_owner ---------------------------------------

#[tokio::test]
async fn wait_for_sole_owner_returns_immediately_when_already_sole_owner() {
    let arc = Arc::new(NullAuditSink);
    // No other clone exists: the loop's own condition is false on the
    // very first check, so this returns without ever sleeping.
    wait_for_sole_owner(&arc, Duration::from_secs(10)).await;
}

#[tokio::test]
async fn wait_for_sole_owner_gives_up_after_grace_when_a_clone_is_still_held() {
    let arc = Arc::new(NullAuditSink);
    let _still_held = arc.clone();
    let grace = Duration::from_millis(30);
    let start = std::time::Instant::now();
    wait_for_sole_owner(&arc, grace).await;
    assert!(
        start.elapsed() >= grace,
        "must wait out the full grace period while a clone is held"
    );
    assert_eq!(
        Arc::strong_count(&arc),
        2,
        "gives up rather than blocking forever"
    );
}
