//! `qsh identity move-key` (`docs/CLI.md` §6.11, ADR-0032 결정 15).
//!
//! The spawned binary can only reach the file key store: the `platform`
//! store is the OS credential store, which no test may touch. So the
//! cases that actually move a key run in-process, through
//! [`Ops::identity_move_key_with_platform_store`] with a fake platform
//! store, against the same sandbox directories the real `qsh` processes of
//! the route test then use.

use crate::common;

use common::{Sandbox, exit_code};

use {
    common::{HOST_ALIAS, ServeGuard},
    qsh_core::identity::MemoryKeyStore,
    qsh_core::{Ops, Paths},
    qsh_proto::{IdentityMoveKeyReq, KeyStoreKind},
    serde_json::Value,
};

/// `<config>/identity/<name>` as bytes, if the file exists.
fn identity_file(sandbox: &Sandbox, name: &str) -> Option<Vec<u8>> {
    std::fs::read(sandbox.config_dir().join("identity").join(name)).ok()
}

/// `qsh identity move-key` before `qsh init` is the `CONFIG_ERROR` every
/// identity-reading op gives, with `identity export`'s exact message, and
/// it creates nothing.
#[test]
fn move_key_before_init_is_config_error_through_the_binary() {
    let sandbox = Sandbox::new();
    let (code, envelope) = sandbox.json(&["identity", "move-key", "--to", "file", "--json"]);
    assert_eq!(code, 255, "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["command"], "identity.move_key", "{envelope}");
    assert_eq!(envelope["error"]["code"], "CONFIG_ERROR", "{envelope}");
    assert_eq!(
        envelope["error"]["message"], "no local identity; run `qsh init` first",
        "{envelope}"
    );
    assert!(!sandbox.config_dir().join("identity").exists());
}

/// The key is in the file store already, so asking for `file` changes
/// nothing: `moved: false`, no audit record, files byte for byte the same,
/// and neither output stream carries any of the key.
#[test]
fn move_key_to_the_current_store_is_a_no_op_through_the_binary() {
    let sandbox = Sandbox::initialized();
    let record = identity_file(&sandbox, "identity.toml");
    let key = identity_file(&sandbox, "device.key").expect("file store key");
    let audit_before = sandbox.audit_records().len();

    let (code, envelope) = sandbox.json(&["identity", "move-key", "--to", "file", "--json"]);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["from"], "file", "{envelope}");
    assert_eq!(envelope["data"]["to"], "file", "{envelope}");
    assert_eq!(envelope["data"]["moved"], false, "{envelope}");
    assert_eq!(envelope["data"]["stale_entry_left"], false, "{envelope}");
    assert_eq!(identity_file(&sandbox, "identity.toml"), record);
    assert_eq!(identity_file(&sandbox, "device.key"), Some(key.clone()));
    assert_eq!(sandbox.audit_records().len(), audit_before);

    let human = sandbox.qsh(&["identity", "move-key", "--to", "file"]);
    assert_eq!(exit_code(&human), 0);
    let stdout = String::from_utf8_lossy(&human.stdout).into_owned();
    assert!(
        stdout.contains("already in the file key store"),
        "unexpected human output: {stdout}"
    );

    // The key's base64 body, line by line, is in neither stream of either
    // run.
    let pem = String::from_utf8(key).expect("PEM key file");
    let body: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    assert!(!body.is_empty());
    let streams = [
        envelope.to_string(),
        stdout,
        String::from_utf8_lossy(&human.stderr).into_owned(),
    ];
    for stream in &streams {
        for line in &body {
            assert!(!stream.contains(line), "key bytes in output: {stream}");
        }
    }
}

/// `--to` takes `file` or `platform`, nothing else: clap rejects the rest
/// (exit 2, nothing on stdout).
#[test]
fn move_key_rejects_auto_and_unknown_stores_as_usage_errors() {
    let sandbox = Sandbox::initialized();
    for args in [
        &["identity", "move-key"][..],
        &["identity", "move-key", "--to", "auto"],
        &["identity", "move-key", "--to", "usb"],
    ] {
        let output = sandbox.qsh(args);
        assert_eq!(exit_code(&output), 2, "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

/// Move this sandbox's key `file -> platform -> file` through a fake
/// platform store, in-process, and return `(device_id, fingerprint)`
/// before and after. The two moves are the whole operator story: the key
/// leaves the file, sits only in the fake store, and comes back. The spawned
/// binary cannot do this on any OS: its `platform` store is the real OS
/// credential store, which no test here touches.
fn round_trip_through_a_fake_platform_store(
    sandbox: &Sandbox,
) -> ((String, String), (String, String)) {
    let identity = |sandbox: &Sandbox| -> (String, String) {
        let (code, envelope) = sandbox.json(&["identity", "export", "--json"]);
        assert_eq!(code, 0, "{envelope}");
        (
            envelope["data"]["name"].as_str().unwrap().to_string(),
            envelope["data"]["fingerprint"]
                .as_str()
                .unwrap()
                .to_string(),
        )
    };
    let before = identity(sandbox);

    let ops = Ops::new(Paths::new(sandbox.config_dir(), sandbox.state_dir()));
    let platform = MemoryKeyStore::new();
    let down = ops
        .identity_move_key_with_platform_store(
            IdentityMoveKeyReq {
                to: KeyStoreKind::Platform,
            },
            &platform,
        )
        .expect("file -> platform");
    assert!(down.moved && !down.stale_entry_left, "{down:?}");
    assert_eq!(identity_file(sandbox, "device.key"), None);

    let up = ops
        .identity_move_key_with_platform_store(
            IdentityMoveKeyReq {
                to: KeyStoreKind::File,
            },
            &platform,
        )
        .expect("platform -> file");
    assert!(up.moved && !up.stale_entry_left, "{up:?}");
    assert!(identity_file(sandbox, "device.key").is_some());
    let record = String::from_utf8(identity_file(sandbox, "identity.toml").unwrap()).unwrap();
    assert!(record.contains("key_store = \"file\""), "{record}");

    (before, identity(sandbox))
}

/// `trust.toml` as bytes: what a peer's pin of this device is stored in, minus
/// the `key = ` lines. The first dial that passes the pin check fills in a
/// pin's missing `key` (ADR-0061 decision 3) and changes nothing else, so
/// the comparison leaves that one line out and the pin's fingerprint, name,
/// address and role must still be byte-identical.
fn trust_file(sandbox: &Sandbox) -> Vec<u8> {
    let text =
        std::fs::read_to_string(sandbox.config_dir().join("trust.toml")).expect("trust.toml");
    text.lines()
        .filter(|line| !line.starts_with("key = "))
        .flat_map(|line| [line, "\n"])
        .collect::<String>()
        .into_bytes()
}

/// PRD §4 route equivalence, real processes and real QUIC: after the key
/// has been moved platform -> file, this device still handshakes as the
/// forward host (`qsh serve`) with the peer's `trust.toml` untouched. The
/// peer pinned the fingerprint from before the move, so a changed
/// fingerprint would be a failed handshake here, not a silent repin. (The
/// reverse listener and reverse target roles retired with ADR-0068.)
#[test]
fn move_key_then_serve_handshakes_with_unchanged_pins() {
    let device = Sandbox::initialized();
    let device_fp = device.fingerprint();

    // The peer pins this device by the fingerprint it had before the move.
    let client = Sandbox::initialized(); // execs on this device
    let client_fp = client.fingerprint();

    // Nothing starts until the key has moved.
    let (before, after) = round_trip_through_a_fake_platform_store(&device);
    assert_eq!(before, after, "device id and fingerprint survive the move");
    assert_eq!(after.1, device_fp);
    let audited: Vec<Value> = device
        .audit_records()
        .into_iter()
        .filter(|record| record["action"] == "identity.move_key")
        .collect();
    assert_eq!(audited.len(), 2, "{audited:?}");
    assert_eq!(audited[0]["resource"], "file->platform");
    assert_eq!(audited[1]["resource"], "platform->file");

    device.trust_add_with_role("laptop", None, &client_fp, "full");
    let serve = ServeGuard::start(&device);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &device_fp);
    let client_trust = trust_file(&client);
    let (code, envelope) = client.json(&common::exec_true_args(HOST_ALIAS));
    assert_eq!(code, 0, "forward host after move-key: {envelope}");
    assert_eq!(trust_file(&client), client_trust, "client trust.toml");
    drop(serve);
}
