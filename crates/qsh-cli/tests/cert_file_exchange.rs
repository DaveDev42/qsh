//! `qsh identity export` / `qsh trust add --cert-file` — cert-file exchange
//! E2E (ADR-0013). The pure-core PEM-validation matrix and the CLI/exit-code
//! face of the negative table live in `crates/qsh-core/src/ops/tests.rs` and
//! `crates/qsh-cli/tests/init_trust.rs`; what only a real subprocess-plus-QUIC
//! boundary can prove — the completion criterion this file exists for — is
//! that a peer pinned purely by an exported PEM (no pairing code, no
//! `trust invite`/`trust accept` round trip) actually authenticates a real
//! handshake exactly like a pin taken from a fingerprint string.
//!
//! `docs/CLI.md` §6.11 (ADR-0013): the fourth pinning method, for the peers
//! that have no pairing-code exchange to begin with (`qsh listen`/`qsh serve
//! --to`).

mod common;

use common::{
    CLIENT_ALIAS, CLIENT_PRINCIPAL, HOST_ALIAS, Sandbox, ServeGuard, plant_allow_all_acl,
    wait_for_audit,
};

/// `qsh identity export --json`'s `data.cert_pem`, asserted present (no
/// `--out`).
fn exported_cert_pem(sandbox: &Sandbox) -> String {
    let (code, value) = sandbox.json(&["identity", "export", "--json"]);
    assert_eq!(code, 0, "identity export failed: {value}");
    value["data"]["cert_pem"]
        .as_str()
        .expect("data.cert_pem")
        .to_string()
}

/// Pin `name` from a real `--cert-file <path>` argument (a temp file on
/// disk, mirroring an operator's `scp`'d PEM), returning the derived
/// fingerprint.
fn trust_add_cert_file_path(sandbox: &Sandbox, name: &str, cert_pem: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{name}.pem"));
    std::fs::write(&path, cert_pem).expect("write cert file");
    let (code, value) = sandbox.json(&[
        "trust",
        "add",
        name,
        "--cert-file",
        path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 0, "trust add --cert-file {name} failed: {value}");
    value["data"]["peer"]["fingerprint"]
        .as_str()
        .expect("peer.fingerprint")
        .to_string()
}

/// Pin `name` by piping the PEM on stdin (`--cert-file -`), returning the
/// derived fingerprint.
fn trust_add_cert_file_stdin(sandbox: &Sandbox, name: &str, cert_pem: &str) -> String {
    let (code, value) = sandbox.json_with_stdin(
        &["trust", "add", name, "--cert-file", "-", "--json"],
        cert_pem.as_bytes(),
    );
    assert_eq!(code, 0, "trust add --cert-file - {name} failed: {value}");
    value["data"]["peer"]["fingerprint"]
        .as_str()
        .expect("peer.fingerprint")
        .to_string()
}

/// **Completion criterion**: both directions of a cert-file exchange — one
/// side pinned from a file path, the other from stdin — authenticate a real
/// QUIC handshake exactly like an ordinary fingerprint pin, with
/// `auth_path: "pin"` on the resulting audit record (no CA, no pairing
/// code anywhere in this test).
#[test]
fn cert_file_exchange_authenticates_a_real_handshake_in_both_directions() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();

    let host_cert_pem = exported_cert_pem(&host);
    let client_cert_pem = exported_cert_pem(&client);

    // Host pins the client via a real `--cert-file <path>` argument.
    let client_fingerprint_as_pinned_by_host =
        trust_add_cert_file_path(&host, CLIENT_ALIAS, &client_cert_pem);

    // Client pins the host via `--cert-file -` (stdin) instead.
    let host_fingerprint_as_pinned_by_client =
        trust_add_cert_file_stdin(&client, HOST_ALIAS, &host_cert_pem);

    // Cross-check: the fingerprint each side derived from the other's
    // exported PEM must match what `identity export --json` itself reports
    // (`data.fingerprint`) for that same identity — proving the derivation
    // is the real SPKI fingerprint, not some other hash of the PEM text.
    let (code, host_export_envelope) = host.json(&["identity", "export", "--json"]);
    assert_eq!(code, 0, "{host_export_envelope}");
    assert_eq!(
        host_export_envelope["data"]["fingerprint"], host_fingerprint_as_pinned_by_client,
        "the client's derived fingerprint must match the host's own reported fingerprint"
    );
    let (code, client_export_envelope) = client.json(&["identity", "export", "--json"]);
    assert_eq!(code, 0, "{client_export_envelope}");
    assert_eq!(
        client_export_envelope["data"]["fingerprint"], client_fingerprint_as_pinned_by_host,
        "the host's derived fingerprint must match the client's own reported fingerprint"
    );

    // Default-deny ACL: the host must explicitly allow the client's
    // fingerprint-pinned principal (`plant_allow_all_acl` reads the same
    // `trust.toml` this test just populated via `--cert-file`, so it
    // covers the cert-file-pinned name exactly like any other pin).
    plant_allow_all_acl(&host);

    let serve = ServeGuard::start_without_policy(&host, &[]);
    // `ServeGuard::start_without_policy` skips `plant_allow_all_acl`
    // itself, since it must also support the default-deny-posture tests —
    // this test already planted its own ACL above, before the listener
    // started, so re-planting here would be a no-op (`plant_allow_all_acl`
    // is a no-op once `acl.toml` exists) but the ordering (ACL before
    // listener) is what the invariant actually requires.

    // The address `ServeGuard` bound is only known after boot, so the
    // client's pin needs a second `trust add` with `--address` — an
    // ordinary re-add under the same name and fingerprint (address-refresh
    // path, ADR-0014 결정 5), never a fresh cert-file re-validation.
    let (code, rebind) = client.json(&[
        "trust",
        "add",
        HOST_ALIAS,
        "--address",
        serve.addr(),
        "--fingerprint",
        &host_fingerprint_as_pinned_by_client,
        "--json",
    ]);
    assert_eq!(code, 0, "{rebind}");

    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "echo", "cert-file-ok"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], true, "{value}");

    let records = wait_for_audit(
        &host,
        "an exec.run allow for the cert-file-pinned client",
        |r| r["action"] == "exec.run",
    );
    let record = records
        .iter()
        .find(|r| r["action"] == "exec.run")
        .expect("exec.run record for the cert-file-pinned client");
    assert_eq!(
        record["auth_path"], "pin",
        "a cert-file pin must authenticate over the ordinary pin path, never ca: {record}"
    );
    assert_eq!(record["decision"], "allow", "{record}");
    // A pin authenticates as its *stored name* (`TrustStore::parsed_pins`),
    // not the client's own device id — the principal is `device:laptop`,
    // the alias the host pinned it under, exactly like every other
    // `--fingerprint`-pinned peer's principal.
    assert_eq!(record["principal"], CLIENT_PRINCIPAL, "{record}");
}
