//! Unit tests of the automatic-bootstrap decision (ADR-0044 decision 2).
//! No ssh runs here; the end-to-end behavior against a fake `ssh` is in
//! `qsh-cli`'s `ssh_bootstrap_*` and `auto_bootstrap_*` tests. These run on
//! Windows too: the decision needs no localctl socket.

use super::*;
use crate::ops::host::{
    not_in_trust_store_host_not_found, pinned_without_address_host_not_found,
    unconfigured_host_not_found, user_prefix_not_accepted_host_not_found,
};
use crate::ssh_bootstrap::AUTO_BOOTSTRAP_NOTICE;

const FP: &str = "sha256:Uu0LCCmjUIKNZ4TCDBcp4Q4lJtAmx7iF0rnU9z4pbsE=";

fn ops_in(dir: &std::path::Path) -> Ops {
    let paths = Paths::new(dir.join("config"), dir.join("state")).with_runtime_dir(dir.join("run"));
    std::fs::create_dir_all(dir.join("config")).unwrap();
    Ops::new(paths)
}

fn write_config(dir: &std::path::Path, text: &str) {
    std::fs::write(dir.join("config").join("config.toml"), text).unwrap();
}

fn pin(ops: &Ops, name: &str, address: Option<&str>) {
    let path = ops.paths().trust_file();
    let mut store = TrustStore::load(&path).unwrap();
    store.add_peer(
        name,
        address.map(str::to_string),
        FP.parse().unwrap(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    store.save(&path).unwrap();
}

fn decide(ops: &Ops, host: &str) -> Option<AutoBootstrap> {
    ops.should_auto_bootstrap(host, None, false).unwrap()
}

#[test]
fn an_unregistered_name_starts_the_bootstrap_with_the_typed_operand() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());

    let plain = decide(&ops, "box").expect("an unregistered name triggers");
    assert_eq!(plain.host(), "box");
    assert_eq!(plain.dest(), "box");

    let with_user = ops
        .should_auto_bootstrap("box", Some("dave"), false)
        .unwrap()
        .expect("the user hint rides along to ssh");
    assert_eq!(with_user.host(), "box");
    assert_eq!(with_user.dest(), "dave@box");
}

#[test]
fn machine_mode_never_starts_the_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());
    assert_eq!(ops.should_auto_bootstrap("box", None, true).unwrap(), None);
    let req = FileCopyReq {
        sources: vec!["a.txt".into()],
        destination: "box:/tmp/a.txt".into(),
        recursive: false,
        preserve: false,
        no_clobber: false,
    };
    assert_eq!(ops.should_auto_bootstrap_cp(&req, true).unwrap(), None);
    // The same operands do trigger in human mode.
    assert!(ops.should_auto_bootstrap_cp(&req, false).unwrap().is_some());
}

#[test]
fn a_name_this_machine_already_knows_never_starts_the_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());

    pin(&ops, "pinned", Some("203.0.113.5:4433"));
    pin(&ops, "inbound", None);
    std::fs::write(
        dir.path().join("config").join("hosts.toml"),
        "[[host]]\nname = \"book\"\naddress = \"203.0.113.6:4433\"\n\n\
         [[host]]\nname = \"empty\"\naddress = \"\"\n",
    )
    .unwrap();

    for known in ["pinned", "inbound", "book", "empty"] {
        assert_eq!(decide(&ops, known), None, "{known}");
    }
    assert!(decide(&ops, "other").is_some());
}

#[test]
fn bootstrap_off_in_config_never_starts_it() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());
    write_config(dir.path(), "[ssh]\nbootstrap = \"off\"\n");
    assert_eq!(decide(&ops, "box"), None);

    write_config(dir.path(), "[ssh]\nbootstrap = \"auto\"\n");
    assert!(decide(&ops, "box").is_some());
}

#[test]
fn a_broken_config_is_reported_only_for_a_name_that_would_have_triggered() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());
    write_config(dir.path(), "[ssh]\nbootstrap = \"maybe\"\n");
    pin(&ops, "known", Some("203.0.113.5:4433"));

    assert_eq!(decide(&ops, "known"), None);
    let err = ops.should_auto_bootstrap("box", None, false).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
}

#[test]
fn a_name_that_cannot_be_an_ssh_destination_or_a_pin_name_is_not_a_trigger() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());
    for bad in [
        "",
        "-oProxyCommand=x",
        "web/prod",
        "with space",
        "ssh://box",
    ] {
        assert_eq!(decide(&ops, bad), None, "{bad:?}");
    }
}

#[test]
fn cp_reads_the_host_and_user_from_the_operands() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());
    let req = |sources: &[&str], destination: &str| FileCopyReq {
        sources: sources.iter().map(|s| s.to_string()).collect(),
        destination: destination.into(),
        recursive: false,
        preserve: false,
        no_clobber: false,
    };

    let put = ops
        .should_auto_bootstrap_cp(&req(&["a.txt"], "dave@box:/tmp/a.txt"), false)
        .unwrap()
        .expect("a put to an unregistered host triggers");
    assert_eq!((put.host(), put.dest()), ("box", "dave@box"));

    let get = ops
        .should_auto_bootstrap_cp(&req(&["box:/tmp/a.txt"], "."), false)
        .unwrap()
        .expect("a get from an unregistered host triggers");
    assert_eq!((get.host(), get.dest()), ("box", "box"));

    // Operand mistakes are the copy's own usage errors, not a trigger.
    for bad in [
        req(&["a.txt"], "b.txt"),
        req(&["one:/a"], "two:/b"),
        req(&[], "box:/b"),
    ] {
        assert_eq!(ops.should_auto_bootstrap_cp(&bad, false).unwrap(), None);
    }

    pin(&ops, "box", Some("203.0.113.5:4433"));
    assert_eq!(
        ops.should_auto_bootstrap_cp(&req(&["a.txt"], "box:/tmp/a.txt"), false)
            .unwrap(),
        None
    );
}

#[test]
fn the_notice_is_one_line_naming_the_host_the_ssh_operand_and_the_off_switch() {
    let decision = AutoBootstrap {
        dest: "dave@box".into(),
        host: "box".into(),
    };
    let notice = decision.notice();
    assert_eq!(
        notice,
        "no qsh pin for \"box\"; setting one up over ssh (ssh dave@box); \
         set [ssh].bootstrap = \"off\" to disable"
    );
    assert!(!notice.contains('\n'));
    assert!(AUTO_BOOTSTRAP_NOTICE.contains("{host}") && AUTO_BOOTSTRAP_NOTICE.contains("{dest}"));
}

#[test]
fn only_the_wholly_unconfigured_branch_has_an_unconfigured_name() {
    for err in [
        unconfigured_host_not_found("box"),
        not_in_trust_store_host_not_found("box"),
    ] {
        assert_eq!(unconfigured_host_name(&err), Some("box"), "{err}");
    }
    for err in [
        pinned_without_address_host_not_found("box"),
        user_prefix_not_accepted_host_not_found("box"),
        OpError::new(
            ErrorCode::ConnectionFailed,
            "host \"box\" is not in the trust store;",
        ),
        OpError::new(ErrorCode::HostNotFound, "something else entirely"),
        unconfigured_host_not_found("box").with_details(serde_json::json!({ "reason": "x" })),
        unconfigured_host_not_found("box").with_retryable(true),
    ] {
        assert_eq!(unconfigured_host_name(&err), None, "{err}");
    }
}
