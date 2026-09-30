//! Two `trust.toml` names for one fingerprint ("One machine, two aliases",
//! README "Reverse connections"): `SharedTrustStore::lookup_pin` returns the
//! first entry whose fingerprint matches and re-reads the file on every
//! handshake, so the inbound principal is the name that comes first, and
//! reordering the file re-points it without a restart. This drives that
//! through a real `qsh serve` process: the observable behavior the README
//! section describes, not the lookup function in isolation
//! (`lookup_pin_returns_the_first_name_pinned_for_a_shared_fingerprint` and
//! `lookup_pin_follows_a_reordered_trust_toml_without_a_restart` in
//! `qsh-core`'s trust tests pin the unit).

mod common;

use std::time::Duration;

use common::{HOST_ALIAS, Sandbox, ServeGuard};
use qsh_core::{Fingerprint, TrustStore};

const FIRST: &str = "laptop";
const SECOND: &str = "laptop-lan";

/// Rewrite the host's `trust.toml` with both names for `fingerprint`, in the
/// given order.
fn write_trust(host: &Sandbox, fingerprint: &str, order: [&str; 2]) {
    let fingerprint: Fingerprint = fingerprint.parse().expect("fingerprint parses");
    let mut store = TrustStore::default();
    for name in order {
        store.add_peer(name, None, fingerprint, "2026-01-01T00:00:00Z".to_string());
    }
    store
        .save(&host.config_dir().join("trust.toml"))
        .expect("write trust.toml");
}

#[test]
fn an_acl_row_on_the_second_alias_denies_inbound_until_trust_toml_is_reordered() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();

    // Only the second name has an `[[acl]]` row.
    write_trust(&host, &client_fp, [FIRST, SECOND]);
    let acl_path = host.config_dir().join("acl.toml");
    std::fs::write(
        &acl_path,
        format!("[[acl]]\nprincipal = \"device:{SECOND}\"\nallow = [\"exec.run\"]\n"),
    )
    .expect("write acl.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&acl_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod acl.toml");
    }

    let serve = ServeGuard::start_without_policy(&host, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    // The first name is the inbound principal, so the request is denied and
    // the audit record names it, not the second alias.
    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");
    let records = common::wait_for_audit(&host, "an exec.run deny", |record| {
        record["action"] == "exec.run" && record["decision"] == "deny"
    });
    let deny = records
        .iter()
        .find(|r| r["action"] == "exec.run" && r["decision"] == "deny")
        .expect("deny record");
    assert_eq!(deny["principal"], format!("device:{FIRST}"), "{records:#?}");

    // Swap the order. The running `qsh serve` picks it up on the next
    // handshake, and the same request is now allowed as the second name.
    write_trust(&host, &client_fp, [SECOND, FIRST]);
    let value = common::poll_until(
        "the reordered trust.toml to take effect on a new handshake",
        Duration::from_secs(10),
        || {
            let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
            (code == 0).then_some(value)
        },
    );
    assert_eq!(value["ok"], true, "{value}");
    let records = common::wait_for_audit(&host, "an exec.run allow", |record| {
        record["action"] == "exec.run" && record["decision"] == "allow"
    });
    let allow = records
        .iter()
        .find(|r| r["action"] == "exec.run" && r["decision"] == "allow")
        .expect("allow record");
    assert_eq!(
        allow["principal"],
        format!("device:{SECOND}"),
        "{records:#?}"
    );
}
