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
