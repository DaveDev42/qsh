use qsh_proto::SetupStepId::{Acl, Doctor, Identity, Invite, ModeConfig, Pair, PinCert, Service};
use qsh_proto::{SetupRole, SetupStatus, SetupStepId};

use super::*;

#[test]
fn setup_step_order_matches_adr_0024_for_each_role() {
    assert_eq!(
        step_order(SetupRole::Host, false),
        [Identity, ModeConfig, Acl, Service, Invite, Doctor]
    );
    assert_eq!(
        step_order(SetupRole::Host, true),
        [Identity, ModeConfig, Acl, Service, PinCert, Doctor]
    );
    assert_eq!(
        step_order(SetupRole::HostTo, true),
        [Identity, PinCert, ModeConfig, Acl, Service, Doctor]
    );
    assert_eq!(
        step_order(SetupRole::Client, false),
        [Identity, Pair, Doctor]
    );
    assert_eq!(
        step_order(SetupRole::Client, true),
        [Identity, PinCert, Doctor]
    );
    assert_eq!(
        step_order(SetupRole::Listener, true),
        [Identity, PinCert, ModeConfig, Acl, Service, Doctor]
    );
}

#[test]
fn setup_acl_step_always_precedes_the_invite_and_service_steps() {
    for with_cert in [false, true] {
        for role in [SetupRole::Host, SetupRole::HostTo, SetupRole::Listener] {
            let order = step_order(role, with_cert);
            let acl = order.iter().position(|id| *id == Acl).expect("acl step");
            let mode = order
                .iter()
                .position(|id| *id == ModeConfig)
                .expect("mode_config step");
            assert!(mode < acl, "{role:?}: mode_config must precede acl");
            for later in [Service, Invite] {
                if let Some(at) = order.iter().position(|id| *id == later) {
                    assert!(acl < at, "{role:?}: acl must precede {later:?}");
                }
            }
        }
    }
    assert!(is_read_only_step(Acl) && is_read_only_step(ModeConfig));
    assert!(!is_read_only_step(Service) && !is_read_only_step(Identity));
}

#[test]
fn setup_vocabularies_serialize_as_the_closed_snake_case_lists() {
    let ids = [
        (Identity, "identity"),
        (ModeConfig, "mode_config"),
        (Acl, "acl"),
        (PinCert, "pin_cert"),
        (Pair, "pair"),
        (Invite, "invite"),
        (Service, "service"),
        (Doctor, "doctor"),
    ];
    for (id, text) in ids {
        assert_eq!(serde_json::to_value(id).unwrap(), text);
    }
    let statuses = [
        (SetupStatus::Done, "done"),
        (SetupStatus::Already, "already"),
        (SetupStatus::Pending, "pending"),
        (SetupStatus::Blocked, "blocked"),
        (SetupStatus::Skipped, "skipped"),
    ];
    for (status, text) in statuses {
        assert_eq!(serde_json::to_value(status).unwrap(), text);
    }
    assert_eq!(serde_json::to_value(SetupRole::HostTo).unwrap(), "host_to");
    let _: SetupStepId = serde_json::from_value("mode_config".into()).unwrap();
}

fn temp_ops() -> (tempfile::TempDir, crate::ops::Ops) {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, crate::ops::Ops::new(paths))
}

fn pin_by_fingerprint(ops: &crate::ops::Ops, name: &str, fingerprint: &str) {
    ops.trust_add(qsh_proto::TrustAddReq {
        name: name.to_string(),
        address: None,
        fingerprint: Some(fingerprint.to_string()),
        cert_pem: None,
    })
    .unwrap();
}

#[test]
fn setup_pair_pending_on_duplicate_fingerprint() {
    let (_guard, ops) = temp_ops();
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"the host").to_string();
    pin_by_fingerprint(&ops, "macmini", &fingerprint);
    // `trust.accept` then pinned the same host as "macmini-ctl" too.
    pin_by_fingerprint(&ops, "macmini-ctl", &fingerprint);

    let outcome = ops.setup_pair_after_accept("macmini-ctl", &fingerprint);
    assert_eq!(outcome.status, SetupStatus::Pending);
    let detail = outcome.detail.unwrap();
    assert!(detail.contains("macmini"), "{detail}");
    // The person's earlier pin is left alone.
    assert_eq!(ops.trust_list().unwrap().peers.len(), 2);

    let other = qsh_transport::Fingerprint::of_spki_der(b"another host").to_string();
    pin_by_fingerprint(&ops, "box", &other);
    let clean = ops.setup_pair_after_accept("box", &other);
    assert_eq!(clean.status, SetupStatus::Done);
}

#[test]
fn setup_rejects_bad_input_before_any_write() {
    let (guard, ops) = temp_ops();
    let env = SetupEnv {
        now: std::time::SystemTime::now(),
        home: Some(guard.path().join("home")),
    };
    let base = qsh_proto::SetupRunReq {
        role: SetupRole::Client,
        name: Some("box".to_string()),
        address: Some("box.local:4433".to_string()),
        peer_cert_pem: None,
        code: None,
        forward: false,
        service: false,
    };
    let bad = [
        // Neither pin method.
        base.clone(),
        // Both pin methods.
        qsh_proto::SetupRunReq {
            code: Some("x".to_string()),
            peer_cert_pem: Some("y".to_string()),
            ..base.clone()
        },
        // A name that is not a valid label.
        qsh_proto::SetupRunReq {
            name: Some("has space".to_string()),
            code: Some("x".to_string()),
            ..base.clone()
        },
        // A certificate that is not one.
        qsh_proto::SetupRunReq {
            peer_cert_pem: Some("not a pem".to_string()),
            ..base.clone()
        },
        // A flag that does not apply to the role.
        qsh_proto::SetupRunReq {
            service: true,
            peer_cert_pem: Some("not a pem".to_string()),
            ..base.clone()
        },
        // No name at all.
        qsh_proto::SetupRunReq { name: None, ..base },
    ];
    for request in bad {
        let err = ops.setup_run(&request, &env).unwrap_err();
        assert_eq!(
            err.code,
            qsh_proto::ErrorCode::InvalidArgument,
            "{request:?}"
        );
        assert!(err.details.is_null(), "validation runs before any step");
    }
    assert!(
        std::fs::read_dir(guard.path()).unwrap().next().is_none(),
        "a rejected request created files"
    );
}
