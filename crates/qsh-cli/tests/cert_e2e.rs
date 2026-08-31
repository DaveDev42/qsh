//! `qsh cert` — private CA E2E
//! (`docs/adr/0008-private-ca-cert-issuance.md`, `PLAN.md` M7 Step 5).
//!
//! `crates/qsh-core/src/ca.rs`'s own unit tests cover the pure
//! generation/idempotency logic; `crates/qsh-transport/tests/
//! handshake_matrix.rs` case09/case10/case15 already prove the CA-chain
//! verification path itself at the transport layer. What only a real
//! subprocess boundary can prove — the completion criterion this file
//! exists for — is that the real `qsh cert init`/`qsh cert issue`
//! commands' **on-disk artifacts** (`ca.pem`, `device.pem`, `trust.toml
//! [[ca]]`) actually flow into a real QUIC handshake end to end, and that
//! the load-bearing distinction ADR-0008 §6 draws — `AuthPath`, never
//! principal shape — holds for a genuinely CA-issued peer, not just a
//! testkit-synthesized one.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{HOST_ALIAS, Sandbox, ServeGuard, wait_for_audit};
use serde_json::Value;

/// `qsh cert init --json`, asserted to succeed. Returns the CA root's
/// fingerprint.
fn cert_init(sandbox: &Sandbox) -> String {
    let (code, value) = sandbox.json(&["cert", "init", "--json"]);
    assert_eq!(code, 0, "cert init failed: {value}");
    value["data"]["fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string()
}

/// `qsh cert issue --json`, asserted to succeed. Returns the full
/// envelope so callers can inspect `data.issued`/`data.ca`.
fn cert_issue(sandbox: &Sandbox) -> Value {
    let (code, value) = sandbox.json(&["cert", "issue", "--json"]);
    assert_eq!(code, 0, "cert issue failed: {value}");
    value
}

/// Write `contents` to `host`'s `acl.toml`, owner-only permissions (mirrors
/// `common::plant_allow_all_acl`'s own umask fix, F8/F7 — a group-writable
/// planted `acl.toml` spuriously trips the startup warning under a `022`/
/// `002` umask).
fn write_acl_toml(host: &Sandbox, contents: &str) {
    let acl_path = host.config_dir().join("acl.toml");
    std::fs::write(&acl_path, contents).expect("write acl.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&acl_path, std::fs::Permissions::from_mode(0o600));
    }
}

/// `cert init` is idempotent: a second call reports the same root,
/// `created: false`.
#[test]
fn cert_init_is_idempotent() {
    let sandbox = Sandbox::new();
    let first = cert_init(&sandbox);

    let (code, second) = sandbox.json(&["cert", "init", "--json"]);
    assert_eq!(code, 0, "{second}");
    assert_eq!(second["data"]["created"], false, "{second}");
    assert_eq!(second["data"]["fingerprint"], first, "{second}");
}

/// `cert issue` refuses with `CONFIG_ERROR` before `qsh init`, and again
/// before `qsh cert init` — never silently creates either prerequisite
/// (`docs/adr/0008-private-ca-cert-issuance.md` §5's "발급 대상은 로컬
/// device identity로 한정", `ops/mod.rs`'s no-resource-before-prerequisite
/// invariant).
#[test]
fn cert_issue_requires_identity_and_ca_first() {
    let sandbox = Sandbox::new();

    let (code, value) = sandbox.json(&["cert", "issue", "--json"]);
    assert_ne!(code, 0, "{value}");
    assert_eq!(value["error"]["code"], "CONFIG_ERROR", "{value}");

    sandbox.init();
    let (code2, value2) = sandbox.json(&["cert", "issue", "--json"]);
    assert_ne!(code2, 0, "{value2}");
    assert_eq!(value2["error"]["code"], "CONFIG_ERROR", "{value2}");
}

/// `cert issue` is idempotent along both of its independent axes — the
/// leaf re-signature and the `trust.toml [[ca]]` registration — and
/// actually writes a `[[ca]]` entry (verified by reading `trust.toml`
/// directly: there is no `qsh cert list`/`trust list` surface for CA
/// entries, `docs/adr/0008-private-ca-cert-issuance.md`'s scope).
#[test]
fn cert_issue_is_idempotent_and_registers_the_ca_root() {
    let sandbox = Sandbox::initialized();
    cert_init(&sandbox);

    let first = cert_issue(&sandbox);
    assert_eq!(first["data"]["issued"], true, "{first}");
    assert_eq!(first["data"]["ca"]["created"], true, "{first}");
    assert_eq!(first["data"]["ca"]["updated"], Value::Null, "{first}");

    let second = cert_issue(&sandbox);
    assert_eq!(second["data"]["issued"], false, "{second}");
    assert_eq!(
        second["data"]["fingerprint"], first["data"]["fingerprint"],
        "re-running cert issue must never rotate the leaf: {second}"
    );
    assert_eq!(second["data"]["ca"]["created"], false, "{second}");
    // Mirrors `TrustAddData::updated`'s own shape (`(!created).then_some
    // (updated)`): `Some(false)` for a pure no-op re-registration, `None`
    // only alongside `created: true`.
    assert_eq!(second["data"]["ca"]["updated"], false, "{second}");

    let trust_toml =
        std::fs::read_to_string(sandbox.config_dir().join("trust.toml")).expect("trust.toml");
    assert!(
        trust_toml.contains("[[ca]]"),
        "cert issue must register a [[ca]] entry: {trust_toml}"
    );
    assert!(std::fs::metadata(sandbox.config_dir().join("ca").join("ca.pem")).is_ok());
    assert!(std::fs::metadata(sandbox.config_dir().join("ca").join("ca.key")).is_ok());
}

/// **Completion criterion (d):** a CA-issued cert completes a real QUIC
/// handshake through the pin-free CA-chain path, driven entirely by real
/// `qsh cert init`/`qsh cert issue` on-disk artifacts flowing into
/// `trust.toml` — and the resulting audit record's `auth_path` is `"ca"`,
/// never `"pin"`, while the principal is still an ordinary `device:`
/// string (ADR-0008 §6: the load-bearing distinction is `AuthPath`, never
/// principal shape — a pin device and a CA device can both be
/// `device:<id>`).
///
/// The client is the CA-issued side (its own local CA signs its own
/// identity, `qsh cert init` + `qsh cert issue` — a real "promotion", not
/// a hand-built test identity). The host trusts the client purely via
/// that CA chain: no pin for the client's fingerprint exists anywhere on
/// the host. The client still pins the host directly to know where to
/// dial — an ordinary, already-well-tested path unrelated to what this
/// test is proving (the host's authentication of the client).
#[test]
fn ca_issued_client_authenticates_with_auth_path_ca_not_pin() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();

    // Real promotion: the client becomes its own CA and CA-signs its own
    // identity, exactly `qsh cert init` + `qsh cert issue`.
    cert_init(&client);
    let issued = cert_issue(&client);
    let client_device_id = issued["data"]["device_id"]
        .as_str()
        .expect("device_id")
        .to_string();
    let client_principal = format!("device:{client_device_id}");

    // The one step no `qsh cert` command performs: registering a
    // *partner's* CA root (ADR §5 keeps issuance single-device-scoped).
    // This is the manual "operator pastes in a partner's PEM" step
    // `trust/mod.rs`'s own module doc describes — done here via the same
    // `TrustStore::add_ca` production code `cert issue` itself calls, not
    // a hand-rolled TOML string, so this test exercises the real
    // dedup/update semantics too.
    let ca_pem = std::fs::read_to_string(client.config_dir().join("ca").join("ca.pem"))
        .expect("client ca.pem");
    let host_trust_path = host.config_dir().join("trust.toml");
    let mut host_trust = qsh_core::TrustStore::load(&host_trust_path).expect("load host trust");
    host_trust.add_ca("client-ca", ca_pem);
    host_trust.save(&host_trust_path).expect("save host trust");

    // Default-deny (`PLAN.md` M5 Step 6): `plant_allow_all_acl` only
    // covers *pinned* principals, so a CA-only principal needs its own
    // `acl.toml`, written before `qsh serve` starts. A rule's `auth_path`
    // defaults to `Pin` when omitted (`acl::policy::Rule::auth_path`'s own
    // doc, `PLAN.md` M5 §4.1 #2) — this rule must say `"ca"` explicitly,
    // or it would silently never match this CA-authenticated principal.
    write_acl_toml(
        &host,
        &format!(
            "[[acl]]\nprincipal = \"{client_principal}\"\nauth_path = \"ca\"\nallow = [\"exec.run\"]\n"
        ),
    );

    let serve = ServeGuard::start_without_policy(&host, &[]);
    let host_fingerprint = host.fingerprint();
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fingerprint);

    // No pin for the client exists anywhere on the host — if the CA-chain
    // path did not work, this would be `PERMISSION_DENIED` at best (no
    // handshake at all is the more likely failure).
    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "echo", "ca-ok"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(
        value["data"]["stdout_b64"],
        BASE64.encode("ca-ok\n"),
        "{value}"
    );

    let records = wait_for_audit(&host, "an exec.run allow for the CA-issued client", |r| {
        r["principal"] == client_principal && r["action"] == "exec.run"
    });
    let record = records
        .iter()
        .find(|r| r["principal"] == client_principal && r["action"] == "exec.run")
        .expect("exec.run record for the CA-issued client");
    assert_eq!(
        record["auth_path"], "ca",
        "a CA-issued peer with no pin must authenticate over the CA path, not pin: {record}"
    );
    assert_eq!(record["decision"], "allow", "{record}");
}

/// The same-shape counterpart to the CA test above, for contrast in one
/// file: an ordinary pinned peer authenticates as `AuthPath::Pin` — the
/// same `device:` principal shape as the CA-issued peer, distinguished
/// only by `auth_path` (ADR-0008 §6's load-bearing-axis claim, made
/// concrete on both sides in this file rather than asserted in prose).
#[test]
fn pinned_client_authenticates_with_auth_path_pin() {
    let fleet = common::Fleet::start();

    let (code, value) = fleet.exec_json(&["--", "echo", "pin-ok"]);
    assert_eq!(code, 0, "{value}");

    let records = wait_for_audit(
        &fleet.host,
        "an exec.run allow for the pinned client",
        |r| r["principal"] == common::CLIENT_PRINCIPAL && r["action"] == "exec.run",
    );
    let record = records
        .iter()
        .find(|r| r["principal"] == common::CLIENT_PRINCIPAL && r["action"] == "exec.run")
        .expect("exec.run record for the pinned client");
    assert_eq!(record["auth_path"], "pin", "{record}");
}
