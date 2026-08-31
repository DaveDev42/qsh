//! `PLAN.md` M5 Step 7 — DoD 1's table-based equivalence proof.
//!
//! `Ops::acl_check` (`crates/qsh-core/src/ops/acl.rs`) and
//! `Server::authorize`/`authorize_owned` (`crates/qsh-core/src/server/
//! mod.rs`) call the exact same `pub(crate) fn decide`
//! (`crates/qsh-core/src/acl/policy.rs`) — that narrowing is DoD 1's
//! *structural* half (only `impl Authorizer for Policy::check` and
//! `Ops::acl_check` remain as call sites, both inside `qsh-core`; a second,
//! explaining-only evaluator has nowhere left to live without showing up
//! next to them in a workspace-wide grep). This file is the *table* half
//! `docs/ROADMAP.md` M5's own wording asks for: for each row, (i) `qsh acl
//! check --json`'s `decision`/`rule`, (ii) a real op's outcome (success vs.
//! `PERMISSION_DENIED`) against a `qsh serve` host running the identical
//! policy, and (iii) the audit record that op left behind, must all three
//! agree. (iii) matters on its own — `acl check` and enforcement could
//! still call the same evaluator while the *audit write* diverged, which
//! would make SC6 (`docs/design/testing.md`) false even with DoD 1 green.
//!
//! Required row kinds (`PLAN.md` M5 Step 7 (c)): allow / deny / wildcard
//! match / always-denied action / `auth_path` mismatch / `scope = "owned"`
//! owner and non-owner / policy file absent. The owner/non-owner pair is
//! two separate `#[test]` rows below, for eight rows total — plus a ninth,
//! `policy file invalid` (adversarial addition, not itself PLAN.md-
//! required): `PolicySource::load` returns a distinct `PolicyLoad::Invalid`
//! for a present-but-corrupt `acl.toml`, and only `Missing` had a row
//! before this, leaving that loader axis half-closed.
//!
//! **One row is not end-to-end, flagged rather than silently substituted**:
//! `forward.socks`/`file.read`/`file.write` (`Action::is_always_denied`)
//! have no CLI-reachable producer anywhere in the tree — they are P1,
//! unimplemented (`fixtures.rs`'s own `DEFERRED` list documents the same
//! kind of gap for other actions/codes). There is no live network op to
//! run for them and so no audit record a real request would leave;
//! [`row_always_denied_action_overrides_an_explicit_allow_rule`] proves
//! (ii)/(iii) instead by calling the exact same `Authorizer::check`
//! `Server::authorize` calls, loaded from the same `acl.toml` a running
//! host would read, directly rather than through a network round trip that
//! does not exist yet. Every other row here is fully end-to-end: a real
//! `qsh serve` subprocess, a real client subprocess, and a real audit log
//! on disk.

mod common;

use std::str::FromStr;

use common::{CLIENT_ALIAS, CLIENT_PRINCIPAL, HOST_ALIAS, Sandbox, ServeGuard, wait_for_audit};
use qsh_core::acl::{
    Action as CoreAction, Authorizer, PERMISSION_DENIED_MESSAGE, PolicyLoad, PolicySource,
    ResourceRef,
};
use qsh_core::{Paths, Principal};
// F5 (`PLAN.md` M5 Step 7 adversarial ⑥): `Principal` comes from `qsh-core`
// (re-exported at `qsh-core/src/lib.rs:61`), not `qsh_transport` — this is
// a `qsh-core` test suite, and `qsh-core` re-exports the type its own
// public `Ops`/`acl` surface already traffics in. `qsh_transport` stays
// imported only for `AuthPath`, which `qsh-core` does not re-export.
use qsh_transport::AuthPath;
use serde_json::Value;

/// Write `contents` to `host`'s `acl.toml` and pin its permissions to
/// owner-only (F7, `PLAN.md` M5 Step 7 adversarial ⑦) — one helper instead
/// of repeating the chmod at every row's own write. `fs::write` inherits
/// the process umask (0o664 under the common `022`/`002` umask), and a
/// group-writable planted `acl.toml` would spuriously trip the group-/
/// world-writable startup warning on a runner with that umask (mirrors
/// `common::plant_allow_all_acl`'s own F8, M5 Step 6 PR 6a adversarial ④).
fn write_acl_toml(host: &Sandbox, contents: &str) {
    let acl_path = host.config_dir().join("acl.toml");
    std::fs::write(&acl_path, contents).expect("write acl.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&acl_path, std::fs::Permissions::from_mode(0o600));
    }
}

/// Run `qsh acl check --json` against `host`'s own `acl.toml` and return the
/// envelope's `data` object. `acl check` itself never fails for a
/// well-formed principal/action (`docs/CLI.md` §6.15), so a non-zero exit
/// here is always this helper's own misuse, not a row outcome to assert on.
#[allow(clippy::too_many_arguments)]
fn acl_check(
    host: &Sandbox,
    principal: &str,
    action: &str,
    resource: Option<&str>,
    auth_path: Option<&str>,
    owner: Option<&str>,
    owner_auth_path: Option<&str>,
) -> Value {
    let mut args = vec!["acl", "check", "--principal", principal, "--action", action];
    if let Some(r) = resource {
        args.push("--resource");
        args.push(r);
    }
    if let Some(a) = auth_path {
        args.push("--auth-path");
        args.push(a);
    }
    if let Some(o) = owner {
        args.push("--owner");
        args.push(o);
    }
    if let Some(oa) = owner_auth_path {
        args.push("--owner-auth-path");
        args.push(oa);
    }
    args.push("--json");
    let (code, value) = host.json(&args);
    assert_eq!(code, 0, "acl check itself must not fail: {value}");
    value["data"].clone()
}

/// Row: allow, an exact principal + `auth_path` + action match.
#[test]
fn row_allow_exact_match() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    write_acl_toml(
        &host,
        &format!("[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"exec.run\"]\n"),
    );
    let serve = ServeGuard::start(&host);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 0, "{value}");

    let records = wait_for_audit(&host, "an exec.run allow", |r| {
        r["action"] == "exec.run" && r["decision"] == "allow"
    });
    let record = records
        .iter()
        .find(|r| r["action"] == "exec.run" && r["decision"] == "allow")
        .expect("exec.run allow record");

    let data = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "exec.run",
        Some("exec"),
        Some("pin"),
        None,
        None,
    );
    assert_eq!(data["decision"], "allow", "{data}");
    assert_eq!(data["rule"], 0, "{data}");
    assert_eq!(data["decision"], record["decision"], "{data} vs {record}");
    assert_eq!(data["rule"], record["rule"], "{data} vs {record}");

    // F1b (`PLAN.md` M5 Step 7 adversarial ①): the documented default for
    // an omitted `--auth-path` is `"pin"` (`docs/CLI.md` §6.15) — before
    // this assertion, that default fold (`ops/acl.rs`'s `req.auth_path`
    // match) was mutation-unguarded: flipping its `None => AuthPath::Pin`
    // arm to `AuthPath::Ca` left every existing row green, since no row
    // compared the omitted-flag path against the explicit-`pin` path.
    let default_auth_path = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "exec.run",
        Some("exec"),
        None,
        None,
        None,
    );
    assert_eq!(
        default_auth_path, data,
        "omitting --auth-path must evaluate identically to --auth-path pin: {default_auth_path} vs {data}"
    );
}

/// Row: deny, no rule matches the action at all.
#[test]
fn row_deny_no_matching_rule() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    write_acl_toml(
        &host,
        &format!("[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"exec.run\"]\n"),
    );
    let serve = ServeGuard::start(&host);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, value) = client.json(&["session", "open", HOST_ALIAS, "--json"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");

    let records = wait_for_audit(&host, "a session.open deny", |r| {
        r["action"] == "session.open" && r["decision"] == "deny"
    });
    let record = records
        .iter()
        .find(|r| r["action"] == "session.open" && r["decision"] == "deny")
        .expect("session.open deny record");

    let data = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "session.open",
        Some("session"),
        Some("pin"),
        None,
        None,
    );
    assert_eq!(data["decision"], "deny", "{data}");
    assert!(data["rule"].is_null(), "{data}");
    assert_eq!(data["decision"], record["decision"], "{data} vs {record}");
    assert!(record["rule"].is_null(), "{record}");
}

/// Row: a trailing-wildcard family (`"session.*"`) matches an action it
/// never names exactly.
#[test]
fn row_wildcard_match() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    write_acl_toml(
        &host,
        &format!("[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"session.*\"]\n"),
    );
    let serve = ServeGuard::start(&host);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, value) = client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{value}");

    let records = wait_for_audit(&host, "a session.list allow", |r| {
        r["action"] == "session.list" && r["decision"] == "allow"
    });
    let record = records
        .iter()
        .find(|r| r["action"] == "session.list" && r["decision"] == "allow")
        .expect("session.list allow record");
    assert_eq!(record["rule"], 0, "{record}");

    let data = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "session.list",
        Some("session"),
        Some("pin"),
        None,
        None,
    );
    assert_eq!(data["decision"], "allow", "{data}");
    assert_eq!(data["rule"], 0, "{data}");
    assert_eq!(data["decision"], record["decision"], "{data} vs {record}");
    assert_eq!(data["rule"], record["rule"], "{data} vs {record}");
}

/// Row: an always-denied action (`Action::is_always_denied`) is denied
/// before any rule is even consulted — even a rule that names it
/// explicitly (`Policy::decide`'s own "① always-deny gate" doc,
/// `crates/qsh-core/src/acl/policy.rs`).
///
/// **Deviation, flagged (module doc)**: `forward.socks` has no
/// CLI-reachable producer, so there is no live op to run and no audit
/// record it would leave. (ii)/(iii) are proven here by loading the same
/// `acl.toml` the same way `Ops::acl_check` does and calling the exact
/// same `Authorizer::check` `Server::authorize` calls — the same
/// evaluator, invoked directly rather than through a network round trip
/// this action's implementation does not have yet.
#[test]
fn row_always_denied_action_overrides_an_explicit_allow_rule() {
    let host = Sandbox::new();
    write_acl_toml(
        &host,
        &format!("[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"forward.socks\"]\n"),
    );

    let data = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "forward.socks",
        Some("socks"),
        Some("pin"),
        None,
        None,
    );
    assert_eq!(data["decision"], "deny", "{data}");
    assert!(data["rule"].is_null(), "{data}");

    let paths = Paths::new(host.config_dir(), host.state_dir());
    let policy = match PolicySource::load(&paths) {
        PolicyLoad::Loaded(policy) => policy,
        other => panic!("expected a loaded policy: {other:?}"),
    };
    let principal = Principal::from_str(CLIENT_PRINCIPAL).expect("principal parses");
    let verdict = policy.check(
        &principal,
        AuthPath::Pin,
        CoreAction::ForwardSocks,
        ResourceRef::unowned("socks"),
    );
    assert!(!verdict.is_allow(), "{verdict:?}");
    assert!(verdict.rule.is_none(), "{verdict:?}");
}

/// Row: a rule scoped to `auth_path = "ca"` never matches a pin-
/// authenticated request, even for the identical principal string — no CA
/// issuance harness is needed to prove this, since the mismatch is the
/// point: the ordinary pinned client below authenticates over pin, same as
/// every other row, and the rule simply does not apply to it.
#[test]
fn row_auth_path_mismatch() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    write_acl_toml(
        &host,
        &format!(
            "[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nauth_path = \"ca\"\nallow = [\"exec.run\"]\n"
        ),
    );
    let serve = ServeGuard::start(&host);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");

    let records = wait_for_audit(&host, "an exec.run deny", |r| {
        r["action"] == "exec.run" && r["decision"] == "deny"
    });
    let record = records
        .iter()
        .find(|r| r["action"] == "exec.run" && r["decision"] == "deny")
        .expect("exec.run deny record");
    assert_eq!(record["auth_path"], "pin", "{record}");
    // F3 (`PLAN.md` M5 Step 7 adversarial ②): every other deny row in this
    // file asserts `rule` on both compared legs; this audit leg was the one
    // gap where only the `acl check` leg was checked.
    assert!(record["rule"].is_null(), "{record}");

    let data = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "exec.run",
        Some("exec"),
        Some("pin"),
        None,
        None,
    );
    assert_eq!(data["decision"], "deny", "{data}");
    assert!(data["rule"].is_null(), "{data}");
    assert_eq!(data["decision"], record["decision"], "{data} vs {record}");

    // The same evaluator also proves the *other* half of the mismatch: the
    // identical inputs with `--auth-path ca` do match this rule.
    let ca_data = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "exec.run",
        Some("exec"),
        Some("ca"),
        None,
        None,
    );
    assert_eq!(ca_data["decision"], "allow", "{ca_data}");
    assert_eq!(ca_data["rule"], 0, "{ca_data}");
}

/// Build a host with two pinned principals — `device:owner-device`
/// (`allow = ["session.open", "session.control"]`) and
/// `device:rival-device` (`allow = ["session.control"]` only, no
/// `session.open`) — bring up `qsh serve`, and have the owner open a
/// long-lived PTY session. Returns `(host, owner client, rival client,
/// serve guard, bare session id, session_ref)`; both clients pin the host
/// under the same alias ([`HOST_ALIAS`]), so `session_ref` (which embeds
/// that alias) resolves identically through either client's own trust
/// store — this is what lets the rival reference a session it never opened
/// (`docs/CLI.md` §6.2's opaque-handle shape).
///
/// Unix-only: PTY-backed sessions are a unix-host feature today (Windows
/// host is P2, `session_follow.rs`'s own file doc states the same
/// constraint for the same reason) — both rows built on this fixture are
/// `#[cfg(unix)]`.
#[cfg(unix)]
fn owned_session_fixture() -> (Sandbox, Sandbox, Sandbox, ServeGuard, String, String) {
    const OWNER_PRINCIPAL: &str = "device:owner-device";
    const RIVAL_PRINCIPAL: &str = "device:rival-device";

    let host = Sandbox::new();
    let owner = Sandbox::new();
    let rival = Sandbox::new();
    let host_fp = host.fingerprint();
    let owner_fp = owner.fingerprint();
    let rival_fp = rival.fingerprint();
    host.trust_add("owner-device", None, &owner_fp);
    host.trust_add("rival-device", None, &rival_fp);
    write_acl_toml(
        &host,
        &format!(
            "[[acl]]\nprincipal = \"{OWNER_PRINCIPAL}\"\nallow = [\"session.open\", \"session.control\"]\n\n\
             [[acl]]\nprincipal = \"{RIVAL_PRINCIPAL}\"\nallow = [\"session.control\"]\n"
        ),
    );
    let serve = ServeGuard::start(&host);
    owner.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);
    rival.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, opened) = owner.json(&[
        "session", "open", HOST_ALIAS, "--json", "--", "sh", "-c", "sleep 30",
    ]);
    assert_eq!(code, 0, "{opened}");
    let session_ref = opened["data"]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string();
    let session_id = session_ref
        .rsplit_once('/')
        .expect("session_ref has a host/id shape")
        .1
        .to_string();

    (host, owner, rival, serve, session_id, session_ref)
}

/// Row: `scope = "owned"` (the default), the requester **is** the
/// resource's recorded opener — allowed.
#[test]
#[cfg(unix)]
fn row_scope_owned_owner_is_allowed() {
    const OWNER_PRINCIPAL: &str = "device:owner-device";
    let (host, owner, _rival, _serve, session_id, session_ref) = owned_session_fixture();

    let (code, value) = owner.json(&[
        "session",
        "resize",
        &session_ref,
        "--cols",
        "80",
        "--rows",
        "24",
        "--json",
    ]);
    assert_eq!(code, 0, "{value}");

    let records = wait_for_audit(&host, "a session.control allow", |r| {
        r["action"] == "session.control" && r["decision"] == "allow"
    });
    let record = records
        .iter()
        .find(|r| r["action"] == "session.control" && r["decision"] == "allow")
        .expect("session.control allow record");
    assert_eq!(record["resource"], session_id, "{record}");
    assert_eq!(record["rule"], 0, "{record}");

    let data = acl_check(
        &host,
        OWNER_PRINCIPAL,
        "session.control",
        Some(&session_id),
        Some("pin"),
        Some(OWNER_PRINCIPAL),
        Some("pin"),
    );
    assert_eq!(data["decision"], "allow", "{data}");
    assert_eq!(data["rule"], 0, "{data}");
    assert_eq!(data["decision"], record["decision"], "{data} vs {record}");
    assert_eq!(data["rule"], record["rule"], "{data} vs {record}");

    // F1a (`PLAN.md` M5 Step 7 adversarial ①): the documented default for
    // an omitted `--owner-auth-path` is `"pin"` (`docs/CLI.md` §6.15) — a
    // CA leaf must not silently inherit a pinned owner's identity just
    // because the caller left the flag off. Before this assertion, that
    // default fold (`ops/acl.rs`'s `owner_ap` match) was mutation-
    // unguarded: flipping its `None => AuthPath::Pin` arm to `AuthPath::Ca`
    // left every existing row green.
    let default_owner_ap = acl_check(
        &host,
        OWNER_PRINCIPAL,
        "session.control",
        Some(&session_id),
        Some("pin"),
        Some(OWNER_PRINCIPAL),
        None,
    );
    assert_eq!(
        default_owner_ap, data,
        "omitting --owner-auth-path must evaluate identically to --owner-auth-path pin: {default_owner_ap} vs {data}"
    );
}

/// Row: `scope = "owned"` (the default), the requester is **not** the
/// resource's recorded opener — denied, even though the rival has its own
/// `allow = ["session.control"]` rule (`scope` filters *after* the action
/// pattern matches, `Policy::decide`'s own "④ scope judgment" doc).
#[test]
#[cfg(unix)]
fn row_scope_owned_non_owner_is_denied() {
    const OWNER_PRINCIPAL: &str = "device:owner-device";
    const RIVAL_PRINCIPAL: &str = "device:rival-device";
    let (host, _owner, rival, _serve, session_id, session_ref) = owned_session_fixture();

    let (code, value) = rival.json(&[
        "session",
        "resize",
        &session_ref,
        "--cols",
        "80",
        "--rows",
        "24",
        "--json",
    ]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");

    let records = wait_for_audit(&host, "a session.control deny", |r| {
        r["action"] == "session.control" && r["decision"] == "deny"
    });
    let record = records
        .iter()
        .find(|r| r["action"] == "session.control" && r["decision"] == "deny")
        .expect("session.control deny record");
    assert_eq!(record["resource"], session_id, "{record}");
    assert!(record["rule"].is_null(), "{record}");

    let data = acl_check(
        &host,
        RIVAL_PRINCIPAL,
        "session.control",
        Some(&session_id),
        Some("pin"),
        Some(OWNER_PRINCIPAL),
        Some("pin"),
    );
    assert_eq!(data["decision"], "deny", "{data}");
    assert!(data["rule"].is_null(), "{data}");
    assert_eq!(data["decision"], record["decision"], "{data} vs {record}");
}

/// Row: no `acl.toml` at all — `DenyAll`, every decision `"deny"`, no rule,
/// `policy.loaded: false`.
#[test]
fn row_policy_file_absent() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    let serve = ServeGuard::start_without_policy(&host, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");

    let records = wait_for_audit(&host, "an exec.run deny", |r| {
        r["action"] == "exec.run" && r["decision"] == "deny"
    });
    let record = records
        .iter()
        .find(|r| r["action"] == "exec.run" && r["decision"] == "deny")
        .expect("exec.run deny record");
    assert!(record["rule"].is_null(), "{record}");

    let data = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "exec.run",
        Some("exec"),
        Some("pin"),
        None,
        None,
    );
    assert_eq!(data["decision"], "deny", "{data}");
    assert!(data["rule"].is_null(), "{data}");
    assert_eq!(data["policy"]["loaded"], false, "{data}");
    assert_eq!(data["decision"], record["decision"], "{data} vs {record}");
}

/// Row (adversarial addition, `PLAN.md` M5 Step 7 adversarial ③): a
/// *present but corrupt* `acl.toml` — `PolicySource::load` returns
/// `PolicyLoad::Invalid`, a distinct loader outcome from
/// [`row_policy_file_absent`]'s `PolicyLoad::Missing`, but both fold into
/// the same `DenyAll` posture in `Ops::acl_check` and `Server::authorize`
/// (`policy.loaded: false`, `decision: "deny"`, no rule, same
/// `PERMISSION_DENIED` on the wire). Before this row, only the `Missing`
/// half of that loader match arm (`crates/qsh-core/src/ops/acl.rs`'s
/// `PolicyLoad::Missing | PolicyLoad::Invalid(_) => ...`) had table
/// coverage — a mutation that split the two arms apart (e.g. treating
/// `Invalid` as `loaded: true` with zero rules) would have gone unnoticed.
#[test]
fn row_policy_file_invalid() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    write_acl_toml(&host, "not toml {{{");
    let serve = ServeGuard::start_without_policy(&host, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");
    assert_eq!(
        value["error"]["message"], PERMISSION_DENIED_MESSAGE,
        "{value}"
    );

    let records = wait_for_audit(&host, "an exec.run deny", |r| {
        r["action"] == "exec.run" && r["decision"] == "deny"
    });
    let record = records
        .iter()
        .find(|r| r["action"] == "exec.run" && r["decision"] == "deny")
        .expect("exec.run deny record");
    assert!(record["rule"].is_null(), "{record}");

    let data = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "exec.run",
        Some("exec"),
        Some("pin"),
        None,
        None,
    );
    assert_eq!(data["decision"], "deny", "{data}");
    assert!(data["rule"].is_null(), "{data}");
    assert_eq!(data["policy"]["loaded"], false, "{data}");
    assert_eq!(data["decision"], record["decision"], "{data} vs {record}");
}

/// Owed test (`PLAN.md` M5 Step 7 (c)): `qsh acl check` never mutates
/// `acl.toml` — same content, same mtime, before and after a run.
#[test]
fn acl_check_does_not_modify_acl_toml() {
    let host = Sandbox::new();
    let acl_path = host.config_dir().join("acl.toml");
    write_acl_toml(
        &host,
        &format!("[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"exec.run\"]\n"),
    );
    let before_content = std::fs::read_to_string(&acl_path).expect("read acl.toml");
    let before_mtime = std::fs::metadata(&acl_path)
        .expect("stat acl.toml")
        .modified()
        .expect("mtime");

    let (code, _) = host.json(&[
        "acl",
        "check",
        "--principal",
        CLIENT_PRINCIPAL,
        "--action",
        "exec.run",
        "--json",
    ]);
    assert_eq!(code, 0);

    let after_content = std::fs::read_to_string(&acl_path).expect("read acl.toml");
    let after_mtime = std::fs::metadata(&acl_path)
        .expect("stat acl.toml")
        .modified()
        .expect("mtime");
    assert_eq!(
        before_content, after_content,
        "acl.toml content must be unchanged by qsh acl check"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "acl.toml mtime must be unchanged by qsh acl check"
    );
}

/// Owed test (`PLAN.md` M5 Step 7 (c)): `acl.check` never reaches the wire
/// — it is a local operation only (`docs/CLI.md` §2.5's "인가 불요" row,
/// ROADMAP M5 감사 개정 ③: a remote-visible policy query would itself be a
/// capability-enumeration oracle).
///
/// An exhaustive match with no `_` arm on the prost-generated oneof is a
/// compile-time guarantee, not a text search: the moment a tenth wire
/// message is added — named `AclCheck` or anything else — this function
/// fails to *compile* until the match is updated to say so explicitly,
/// where a `.contains("acl_check")` grep could rot silently alongside a
/// renamed variant.
#[test]
fn acl_check_never_appears_as_a_control_message_wire_variant() {
    #[allow(dead_code)]
    fn assert_every_variant_is_accounted_for(body: qsh_proto::wire::control_message::Body) {
        use qsh_proto::wire::control_message::Body;
        match body {
            Body::Hello(_) => {}
            Body::Response(_) => {}
            Body::SessionOpen(_) => {}
            Body::SessionAttach(_) => {}
            Body::SessionList(_) => {}
            Body::SessionGet(_) => {}
            Body::SessionResize(_) => {}
            Body::SessionClose(_) => {}
            Body::SessionRead(_) => {}
            Body::SessionWrite(_) => {}
            Body::ExecStart(_) => {}
            Body::RfwdOpen(_) => {}
            Body::RfwdClose(_) => {}
            Body::Ping(_) => {}
            Body::Pong(_) => {}
            Body::SessionEvent(_) => {}
            Body::PairingProof(_) => {}
            Body::PairingAccepted(_) => {}
        }
    }
    // The function above never runs — its only job is to fail to compile
    // the instant the oneof gains (or loses) a variant this match does not
    // name. This assertion just proves the test itself is not vacuous.
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../qsh-proto/proto/qsh/wire/v1.proto"
    ))
    .expect("read v1.proto");
    assert!(
        !source.to_lowercase().contains("aclcheck") && !source.to_lowercase().contains("acl_check"),
        "the wire proto must never gain an acl.check message"
    );
}
