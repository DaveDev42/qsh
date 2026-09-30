//! `setup.run` behavior (ADR-0024 결과 절). Fixtures are built here, outside
//! `crates/qsh-core/src/setup/`, because `cargo xtask arch` bans file-writing
//! primitives under that directory, `tests.rs` included.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use qsh_core::{OpError, Ops, Paths, SetupEnv};
use qsh_proto::{
    IdentityExportReq, IdentityInitReq, KeyStoreMode, SetupRole, SetupRunData, SetupRunReq,
    SetupStatus, SetupStep, SetupStepId, TrustAddReq, TrustInviteReq,
};

struct Sandbox {
    dir: tempfile::TempDir,
    ops: Ops,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::create_dir_all(&config).unwrap();
        // File key store: never the OS keychain from a test.
        std::fs::write(
            config.join("config.toml"),
            "[identity]\nkey_store = \"file\"\n",
        )
        .unwrap();
        let paths = Paths::new(config, dir.path().join("state"));
        Self {
            ops: Ops::new(paths),
            dir,
        }
    }

    fn config_dir(&self) -> PathBuf {
        self.dir.path().join("config")
    }

    fn write_config(&self, text: &str) {
        std::fs::write(
            self.config_dir().join("config.toml"),
            format!("[identity]\nkey_store = \"file\"\n{text}"),
        )
        .unwrap();
    }

    fn acl_path(&self) -> PathBuf {
        self.config_dir().join("acl.toml")
    }

    fn env(&self) -> SetupEnv {
        SetupEnv {
            now: SystemTime::now(),
            home: Some(self.dir.path().join("home")),
        }
    }

    /// Every file under `root` with its bytes.
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.insert(path.clone(), std::fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(root, &mut out);
        out
    }
}

/// A certificate PEM from a throwaway device, distinct per call.
fn peer_pem() -> String {
    let other = Sandbox::new();
    other
        .ops
        .identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
            ..Default::default()
        })
        .unwrap();
    other
        .ops
        .identity_export(IdentityExportReq { out: None })
        .unwrap()
        .cert_pem
        .unwrap()
}

fn req(role: SetupRole, name: &str) -> SetupRunReq {
    SetupRunReq {
        role,
        name: Some(name.to_string()),
        address: None,
        peer_cert_pem: None,
        code: None,
        forward: false,
        service: false,
    }
}

fn host(name: &str) -> SetupRunReq {
    req(SetupRole::Host, name)
}

fn host_to(name: &str, pem: &str) -> SetupRunReq {
    SetupRunReq {
        address: Some("127.0.0.1:1".to_string()),
        peer_cert_pem: Some(pem.to_string()),
        ..req(SetupRole::HostTo, name)
    }
}

fn listener(name: &str, pem: &str) -> SetupRunReq {
    SetupRunReq {
        peer_cert_pem: Some(pem.to_string()),
        ..req(SetupRole::Listener, name)
    }
}

fn client(name: &str, pem: &str) -> SetupRunReq {
    SetupRunReq {
        address: Some("127.0.0.1:1".to_string()),
        peer_cert_pem: Some(pem.to_string()),
        ..req(SetupRole::Client, name)
    }
}

fn step_of(data: &SetupRunData, id: SetupStepId) -> &SetupStep {
    data.steps
        .iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("no {id:?} step in {:?}", data.steps))
}

fn all_roles(pem: &str) -> Vec<SetupRunReq> {
    vec![
        host("laptop"),
        host_to("macmini", pem),
        client("box", pem),
        listener("ctl", pem),
    ]
}

#[test]
fn setup_never_writes_acl_toml_in_any_role() {
    let pem = peer_pem();
    for request in all_roles(&pem) {
        // No acl.toml before: none after.
        let sandbox = Sandbox::new();
        if request.role == SetupRole::HostTo {
            sandbox.write_config("[serve]\nto = \"macmini\"\n");
        } else if request.role == SetupRole::Listener {
            sandbox.write_config("[listen]\nbind = \"[::]:4433\"\n");
        }
        sandbox.ops.setup_run(&request, &sandbox.env()).unwrap();
        assert!(
            !sandbox.acl_path().exists(),
            "{:?} created acl.toml",
            request.role
        );

        // An acl.toml before: the same bytes after.
        let before =
            b"# hand written\n[[acl]]\nprincipal = \"device:someone\"\nallow = [\"exec.run\"]\n";
        std::fs::write(sandbox.acl_path(), before).unwrap();
        sandbox.ops.setup_run(&request, &sandbox.env()).unwrap();
        assert_eq!(
            std::fs::read(sandbox.acl_path()).unwrap(),
            before,
            "{:?} changed acl.toml",
            request.role
        );
    }
}

#[test]
fn setup_printed_rows_pasted_verbatim_make_acl_check_allow_every_intended_action() {
    let pem = peer_pem();
    let mut with_forward = host("laptop");
    with_forward.forward = true;
    let mut to_forward = host_to("macmini", &pem);
    to_forward.forward = true;
    let requests = vec![
        host("laptop"),
        with_forward,
        host_to("macmini", &pem),
        to_forward,
        listener("ctl", &pem),
    ];
    for request in requests {
        let sandbox = Sandbox::new();
        let plan = sandbox.ops.setup_plan(&request, &sandbox.env()).unwrap();
        let rows = plan.acl_rows.clone().expect("acl_rows");
        assert!(
            step_of(&plan, SetupStepId::Acl).status == SetupStatus::Pending,
            "no policy yet"
        );
        if request.forward {
            assert!(rows.contains("forward.local"), "{rows}");
        } else {
            assert!(!rows.contains("forward.local"), "{rows}");
        }
        std::fs::write(sandbox.acl_path(), &rows).unwrap();
        let plan = sandbox.ops.setup_plan(&request, &sandbox.env()).unwrap();
        assert_eq!(
            step_of(&plan, SetupStepId::Acl).status,
            SetupStatus::Already,
            "{:?}: {:?}",
            request.role,
            step_of(&plan, SetupStepId::Acl)
        );
    }
    let sandbox = Sandbox::new();
    let plan = sandbox
        .ops
        .setup_plan(&client("box", &pem), &sandbox.env())
        .unwrap();
    assert!(plan.acl_rows.is_none(), "a client has no acl step");
}

#[test]
fn setup_acl_step_appends_the_acl_restart_notice_byte_for_byte() {
    let sandbox = Sandbox::new();
    let request = host("laptop");
    let rows = sandbox
        .ops
        .setup_plan(&request, &sandbox.env())
        .unwrap()
        .acl_rows
        .unwrap();
    std::fs::write(sandbox.acl_path(), rows).unwrap();
    let plan = sandbox.ops.setup_plan(&request, &sandbox.env()).unwrap();
    let acl = step_of(&plan, SetupStepId::Acl);
    assert_eq!(acl.status, SetupStatus::Already);
    assert_eq!(
        acl.detail.as_deref(),
        Some(qsh_core::acl::ACL_RESTART_NOTICE)
    );
}

#[test]
fn setup_invite_always_carries_assigned_name() {
    let sandbox = Sandbox::new();
    let request = host("laptop");
    let rows = sandbox
        .ops
        .setup_plan(&request, &sandbox.env())
        .unwrap()
        .acl_rows
        .unwrap();
    std::fs::write(sandbox.acl_path(), rows).unwrap();

    let data = sandbox.ops.setup_run(&request, &sandbox.env()).unwrap();
    let invite = step_of(&data, SetupStepId::Invite);
    assert_eq!(invite.status, SetupStatus::Done);
    let result = invite.result.as_ref().unwrap();
    assert_eq!(result["assigned_name"], "laptop");
    assert!(result["code"].as_str().is_some_and(|c| !c.is_empty()));

    let counts = qsh_core::trust::live_invite_counts(
        &sandbox.config_dir().join("invites.toml"),
        SystemTime::now(),
    )
    .unwrap();
    assert_eq!(counts.unassigned, 0);
    assert_eq!(counts.assigned_to("laptop"), 1);
}

#[test]
fn setup_acl_step_pending_while_unassigned_invite_is_live() {
    let sandbox = Sandbox::new();
    let request = host("laptop");
    let rows = sandbox
        .ops
        .setup_plan(&request, &sandbox.env())
        .unwrap()
        .acl_rows
        .unwrap();
    std::fs::write(sandbox.acl_path(), rows).unwrap();
    // Someone minted an invite outside `qsh setup`, without --as.
    sandbox.ops.trust_invite(TrustInviteReq::default()).unwrap();

    let data = sandbox.ops.setup_run(&request, &sandbox.env()).unwrap();
    let acl = step_of(&data, SetupStepId::Acl);
    assert_eq!(acl.status, SetupStatus::Pending);
    assert!(
        acl.detail.as_deref().unwrap().contains("10 minutes"),
        "{acl:?}"
    );
    assert_eq!(
        step_of(&data, SetupStepId::Invite).status,
        SetupStatus::Blocked,
        "no invite is minted while the acl step is pending"
    );
    assert!(!data.complete);

    // Past the TTL the unassigned invite no longer counts.
    let later = SetupEnv {
        now: SystemTime::now() + Duration::from_secs(11 * 60),
        ..sandbox.env()
    };
    let plan = sandbox.ops.setup_plan(&request, &later).unwrap();
    assert_eq!(
        step_of(&plan, SetupStepId::Acl).status,
        SetupStatus::Already
    );
}

#[test]
fn setup_refuses_second_name_for_pinned_fingerprint() {
    let sandbox = Sandbox::new();
    let pem = peer_pem();
    sandbox
        .ops
        .trust_add(TrustAddReq {
            name: "first".to_string(),
            address: None,
            fingerprint: None,
            cert_pem: Some(pem.clone()),
        })
        .unwrap();
    let data = sandbox
        .ops
        .setup_run(&listener("second", &pem), &sandbox.env())
        .unwrap();
    let pin = step_of(&data, SetupStepId::PinCert);
    assert_eq!(pin.status, SetupStatus::Pending);
    assert!(pin.detail.as_deref().unwrap().contains("first"), "{pin:?}");
    let peers = sandbox.ops.trust_list().unwrap().peers;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].name, "first");
}

#[test]
fn setup_pin_cert_pending_on_fingerprint_mismatch() {
    let sandbox = Sandbox::new();
    let pinned = peer_pem();
    let other = peer_pem();
    sandbox
        .ops
        .trust_add(TrustAddReq {
            name: "ctl".to_string(),
            address: None,
            fingerprint: None,
            cert_pem: Some(pinned),
        })
        .unwrap();
    let before = sandbox.ops.trust_list().unwrap().peers;
    let data = sandbox
        .ops
        .setup_run(&listener("ctl", &other), &sandbox.env())
        .unwrap();
    assert_eq!(
        step_of(&data, SetupStepId::PinCert).status,
        SetupStatus::Pending
    );
    assert_eq!(sandbox.ops.trust_list().unwrap().peers, before);
}

#[test]
fn setup_trust_add_always_carries_cert_pem() {
    // An address nothing listens on: had `trust add` been asked to observe a
    // fingerprint it would dial it and fail with TRUST_REQUIRED or a
    // connection error. It pins from the certificate alone.
    let sandbox = Sandbox::new();
    let pem = peer_pem();
    sandbox.write_config("[serve]\nto = \"macmini\"\n");
    let request = host_to("macmini", &pem);
    let data = sandbox.ops.setup_run(&request, &sandbox.env()).unwrap();
    let pin = step_of(&data, SetupStepId::PinCert);
    assert_eq!(pin.status, SetupStatus::Done, "{pin:?}");
    let peers = sandbox.ops.trust_list().unwrap().peers;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].name, "macmini");
    assert_eq!(peers[0].address, "127.0.0.1:1");
}

#[test]
fn setup_mode_config_pending_on_wrong_run_mode() {
    let pem = peer_pem();
    let status = |text: &str, request: &SetupRunReq| {
        let sandbox = Sandbox::new();
        sandbox.write_config(text);
        let plan = sandbox.ops.setup_plan(request, &sandbox.env()).unwrap();
        step_of(&plan, SetupStepId::ModeConfig).status
    };
    // host runs `qsh serve`.
    assert_eq!(status("", &host("a")), SetupStatus::Already);
    assert_eq!(
        status("[listen]\nbind = \"[::]:1\"\n", &host("a")),
        SetupStatus::Pending
    );
    assert_eq!(
        status("[serve]\nto = \"x\"\n", &host("a")),
        SetupStatus::Pending
    );
    // listener runs `qsh listen`.
    assert_eq!(status("", &listener("a", &pem)), SetupStatus::Pending);
    assert_eq!(
        status("[listen]\nbind = \"[::]:4433\"\n", &listener("a", &pem)),
        SetupStatus::Already
    );
    // host --to dials the outbound target named by --to.
    assert_eq!(status("", &host_to("a", &pem)), SetupStatus::Pending);
    assert_eq!(
        status("[serve]\nto = \"a\"\n", &host_to("a", &pem)),
        SetupStatus::Already
    );
    assert_eq!(
        status("[serve]\nto = \"other\"\n", &host_to("a", &pem)),
        SetupStatus::Pending,
        "[serve].to disagreeing with --to"
    );
    assert_eq!(
        status("[reverse]\ncontroller = \"a\"\n", &host_to("a", &pem)),
        SetupStatus::Already,
        "the legacy key counts"
    );
}

#[test]
fn setup_rerun_after_completion_changes_no_file() {
    let sandbox = Sandbox::new();
    let pem = peer_pem();
    let request = SetupRunReq {
        service: true,
        ..listener("ctl", &pem)
    };
    sandbox.write_config("[listen]\nbind = \"[::]:4433\"\n");
    let rows = sandbox
        .ops
        .setup_plan(&request, &sandbox.env())
        .unwrap()
        .acl_rows
        .unwrap();
    std::fs::write(sandbox.acl_path(), rows).unwrap();

    let first = sandbox.ops.setup_run(&request, &sandbox.env()).unwrap();
    assert!(
        first
            .steps
            .iter()
            .all(|s| s.status != SetupStatus::Pending && s.status != SetupStatus::Blocked),
        "{:?}",
        first.steps
    );
    let config_before = Sandbox::snapshot(&sandbox.config_dir());
    let home_before = Sandbox::snapshot(&sandbox.dir.path().join("home"));

    let second = sandbox.ops.setup_run(&request, &sandbox.env()).unwrap();
    for id in [
        SetupStepId::Identity,
        SetupStepId::PinCert,
        SetupStepId::Service,
    ] {
        let status = step_of(&second, id).status;
        assert!(
            matches!(status, SetupStatus::Already | SetupStatus::Skipped),
            "{id:?}: {status:?}"
        );
    }
    assert_eq!(Sandbox::snapshot(&sandbox.config_dir()), config_before);
    assert_eq!(
        Sandbox::snapshot(&sandbox.dir.path().join("home")),
        home_before
    );
}

#[test]
fn setup_service_unsupported_is_skipped() {
    let sandbox = Sandbox::new();
    let pem = peer_pem();
    sandbox.write_config("[listen]\nbind = \"[::]:4433\"\n");
    let request = SetupRunReq {
        service: true,
        ..listener("ctl", &pem)
    };
    let rows = sandbox
        .ops
        .setup_plan(&request, &sandbox.env())
        .unwrap()
        .acl_rows
        .unwrap();
    std::fs::write(sandbox.acl_path(), rows).unwrap();
    let data = sandbox.ops.setup_run(&request, &sandbox.env()).unwrap();
    let service = step_of(&data, SetupStepId::Service);
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        // A service manager exists: the unit is written, and the request
        // without `--service` skips the step instead.
        assert_eq!(service.status, SetupStatus::Done, "{service:?}");
    } else {
        assert_eq!(service.status, SetupStatus::Skipped, "{service:?}");
    }
    let without = sandbox
        .ops
        .setup_run(
            &SetupRunReq {
                service: false,
                ..request
            },
            &sandbox.env(),
        )
        .unwrap();
    assert_eq!(
        step_of(&without, SetupStepId::Service).status,
        SetupStatus::Skipped
    );
}

#[test]
fn setup_op_failure_keeps_code_and_retryable_and_adds_step_ids_without_results() {
    let sandbox = Sandbox::new();
    let pem = peer_pem();
    sandbox.write_config("[listen]\nbind = \"[::]:4433\"\n");
    // A trust store that does not parse: `pin_cert` fails after `identity`.
    std::fs::write(sandbox.config_dir().join("trust.toml"), "not = [valid").unwrap();
    let direct: OpError = sandbox.ops.trust_list().unwrap_err();

    let err = sandbox
        .ops
        .setup_run(&listener("ctl", &pem), &sandbox.env())
        .unwrap_err();
    assert_eq!(err.code, direct.code);
    assert_eq!(err.retryable, direct.retryable);
    assert_eq!(err.details["step"], "pin_cert");
    let steps = err.details["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["id"], "identity");
    assert_eq!(steps[0]["status"], "done");
    for entry in steps {
        let keys: Vec<&String> = entry.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["id", "status"], "no result on an error step");
    }
}
