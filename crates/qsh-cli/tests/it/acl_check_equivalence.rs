//! M5 plan Step 7 (2473c88) — DoD 1's table-based equivalence proof.
//!
//! `Ops::acl_check` (`crates/qsh-core/src/ops/acl.rs`) and
//! `Server::authorize`/`authorize_owned` (`crates/qsh-core/src/server/
//! mod.rs`) call the exact same `pub(crate) fn decide`
//! (`crates/qsh-core/src/acl/policy.rs`) — that narrowing is DoD 1's
//! *structural* half (exactly three call sites remain: `Policy::check_with_role`
//! (what the `Authorizer` impls reach), `Ops::acl_check` and
//! `Policy::effective_actions`, which `acl show` uses, all inside `qsh-core`; a second, explaining-only
//! evaluator has nowhere left to live without showing up next to them in
//! `grep -rn 'policy\.decide(\|self\.decide(' crates/qsh-core/src/acl
//! crates/qsh-core/src/ops --exclude=tests.rs`, which prints three lines;
//! a workspace-wide grep would also count the unrelated `Admission::decide`
//! calls). This file is the *table* half
//! `docs/ROADMAP.md` M5's own wording asks for: for each row, (i) `qsh acl
//! check --json`'s `decision`/`rule`, (ii) a real op's outcome (success vs.
//! `PERMISSION_DENIED`) against a `qsh serve` host running the identical
//! policy, and (iii) the audit record that op left behind, must all three
//! agree. (iii) matters on its own — `acl check` and enforcement could
//! still call the same evaluator while the *audit write* diverged, which
//! would make SC6 (`docs/design/testing.md`) false even with DoD 1 green.
//!
//! Required row kinds (M5 plan Step 7 (c) (2473c88)): allow / deny / wildcard
//! match / always-denied action / `auth_path` mismatch / `scope = "owned"`
//! owner and non-owner / policy file absent. The owner/non-owner pair is
//! two separate `#[test]` rows below, for eight rows total — plus a ninth,
//! `policy file invalid` (adversarial addition, not itself
//! plan-required): `PolicySource::load` returns a distinct `PolicyLoad::Invalid`
//! for a present-but-corrupt `acl.toml`, and only `Missing` had a row
//! before this, leaving that loader axis half-closed.
//!
//! **One row is not end-to-end, flagged rather than silently substituted**:
//! `forward.socks` (`Action::is_always_denied`) has no CLI-reachable
//! producer anywhere in the tree. It is not pending an implementation at
//! all: ADR-0019 결정 6 means no op will *ever* drive it, since a
//! client-attached label cannot carry authorization. There is no CLI command
//! to run for it and so no audit record a real request would leave;
//! [`row_always_denied_action_overrides_an_explicit_allow_rule`] proves
//! (ii)/(iii) instead by calling the exact same `Authorizer::check`
//! `Server::authorize` calls, loaded from the same `acl.toml` a running
//! host would read, directly rather than through a network round trip.
//! Every other row here is fully end-to-end: a real `qsh serve`
//! subprocess, a real client subprocess, and a real audit log on disk.

use crate::common;

use std::str::FromStr;

use common::{CLIENT_ALIAS, CLIENT_PRINCIPAL, HOST_ALIAS, Sandbox, ServeGuard, wait_for_audit};
use qsh_core::acl::{
    ACL_RESTART_NOTICE, Action as CoreAction, Authorizer, PERMISSION_DENIED_MESSAGE, PolicyLoad,
    PolicySource, Requester, ResourceRef,
};
use qsh_core::{Paths, Principal};
// F5 (M5 plan Step 7 (2473c88) adversarial ⑥): `Principal` comes from `qsh-core`
// (re-exported at `qsh-core/src/lib.rs`), not `qsh_transport` — this is
// a `qsh-core` test suite, and `qsh-core` re-exports the type its own
// public `Ops`/`acl` surface already traffics in. `qsh_transport` stays
// imported only for `AuthPath`, which `qsh-core` does not re-export.
use qsh_transport::AuthPath;
use serde_json::Value;

/// Write `contents` to `host`'s `acl.toml` and pin its permissions to
/// owner-only (F7, M5 plan Step 7 (2473c88) adversarial ⑦) — one helper instead
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

/// One shared policy table: every `row_*` test below reads its `acl.toml`
/// from here, and the `acl show` agreement test walks the whole table.
/// `{P}` stands for [`CLIENT_PRINCIPAL`]. `principals` lists whom the
/// agreement test evaluates for each row (the two-principal row names its
/// own).
struct TableRow {
    name: &'static str,
    toml: &'static str,
    principals: &'static [&'static str],
}

const OWNER_RIVAL_PRINCIPALS: &[&str] = &["device:owner-device", "device:rival-device"];

const POLICY_TABLE: &[TableRow] = &[
    TableRow {
        name: "exact",
        toml: "[[acl]]\nprincipal = \"{P}\"\nallow = [\"exec.run\"]\n",
        principals: &[CLIENT_PRINCIPAL],
    },
    TableRow {
        name: "wildcard",
        toml: "[[acl]]\nprincipal = \"{P}\"\nallow = [\"session.*\"]\n",
        principals: &[CLIENT_PRINCIPAL],
    },
    TableRow {
        name: "always_denied",
        toml: "[[acl]]\nprincipal = \"{P}\"\nallow = [\"forward.socks\"]\n",
        principals: &[CLIENT_PRINCIPAL],
    },
    TableRow {
        name: "auth_path_ca",
        toml: "[[acl]]\nprincipal = \"{P}\"\nauth_path = \"ca\"\nallow = [\"exec.run\"]\n",
        principals: &[CLIENT_PRINCIPAL],
    },
    TableRow {
        name: "owner_and_rival",
        toml: "[[acl]]\nprincipal = \"device:owner-device\"\nallow = [\"session.open\", \"session.control\"]\n\n\
               [[acl]]\nprincipal = \"device:rival-device\"\nallow = [\"session.control\"]\n",
        principals: OWNER_RIVAL_PRINCIPALS,
    },
    TableRow {
        name: "family_wildcards",
        toml: "[[acl]]\nprincipal = \"{P}\"\nallow = [\"forward.*\", \"file.*\"]\n",
        principals: &[CLIENT_PRINCIPAL],
    },
    TableRow {
        name: "mixed_rows_scope_any",
        toml: "[[acl]]\nprincipal = \"{P}\"\nallow = [\"exec.run\"]\n\n\
               [[acl]]\nprincipal = \"{P}\"\nauth_path = \"ca\"\nscope = \"any\"\nallow = [\"session.*\", \"host.reverse\"]\n",
        principals: &[CLIENT_PRINCIPAL],
    },
];

/// The `acl.toml` text of the table row called `name`.
fn table_toml(name: &str) -> String {
    let row = POLICY_TABLE
        .iter()
        .find(|row| row.name == name)
        .unwrap_or_else(|| panic!("no policy table row named {name}"));
    row.toml.replace("{P}", CLIENT_PRINCIPAL)
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
    // A file action is decided per path (ADR-0029 결정 19); these tables
    // ask about the root, which no table row's `paths` covers.
    if action.starts_with("file.") {
        args.push("--path");
        args.push("/");
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
    write_acl_toml(&host, &table_toml("exact"));
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

    // F1b (M5 plan Step 7 (2473c88) adversarial ①): the documented default for
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
    write_acl_toml(&host, &table_toml("exact"));
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
    write_acl_toml(&host, &table_toml("wildcard"));
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
/// record it would leave — by design, permanently (ADR-0019 결정 6), not
/// pending one. (ii)/(iii) are proven here by loading the same `acl.toml`
/// the same way `Ops::acl_check` does and calling the exact same
/// `Authorizer::check` `Server::authorize` calls — the same evaluator,
/// invoked directly rather than through a network round trip this action
/// will never have.
#[test]
fn row_always_denied_action_overrides_an_explicit_allow_rule() {
    let host = Sandbox::new();
    write_acl_toml(&host, &table_toml("always_denied"));

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
        &Requester::new(&principal, AuthPath::Pin, None),
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
    write_acl_toml(&host, &table_toml("auth_path_ca"));
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
    // F3 (M5 plan Step 7 (2473c88) adversarial ②): every other deny row in this
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
    let host = Sandbox::new();
    let owner = Sandbox::new();
    let rival = Sandbox::new();
    let host_fp = host.fingerprint();
    let owner_fp = owner.fingerprint();
    let rival_fp = rival.fingerprint();
    host.trust_add("owner-device", None, &owner_fp);
    host.trust_add("rival-device", None, &rival_fp);
    write_acl_toml(&host, &table_toml("owner_and_rival"));
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

    // F1a (M5 plan Step 7 (2473c88) adversarial ①): the documented default for
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

/// Row (adversarial addition, M5 plan Step 7 (2473c88) adversarial ③): a
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

/// Owed test (M5 plan Step 7 (c) (2473c88)): `qsh acl check` never mutates
/// `acl.toml` — same content, same mtime, before and after a run.
#[test]
fn acl_check_does_not_modify_acl_toml() {
    let host = Sandbox::new();
    let acl_path = host.config_dir().join("acl.toml");
    write_acl_toml(&host, &table_toml("exact"));
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

/// Owed test (M5 plan Step 7 (c) (2473c88)): `acl.check` never reaches the wire
/// — it is a local operation only (`docs/CLI.md` §2.5's "인가 불요" row,
/// ROADMAP M5 감사 개정 ③: a remote-visible policy query would itself be a
/// capability-enumeration oracle).
///
/// An exhaustive match with no `_` arm on the prost-generated oneof is a
/// compile-time guarantee, not a text search: the moment a further wire
/// message is added — named `AclCheck` or anything else — this function
/// fails to *compile* until the match is updated to say so explicitly,
/// where a `.contains("acl_check")` grep could rot silently alongside a
/// renamed variant.
#[test]
fn acl_check_never_appears_as_a_control_message_wire_variant() {
    // The helper at the bottom of this file never runs — its only job is to fail to compile
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

/// Compile-time anchor shared by the `acl.check` and `acl.show` wire
/// tests: an exhaustive match with no `_` arm on the prost-generated oneof.
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
        Body::FileReadOpen(_) => {}
        Body::FileWriteOpen(_) => {}
        Body::FileListOpen(_) => {}
        Body::FileMkdirOpen(_) => {}
        Body::Ping(_) => {}
        Body::Pong(_) => {}
        Body::SessionEvent(_) => {}
        Body::PairingProof(_) => {}
        Body::PairingAccepted(_) => {}
    }
}

// ---------------------------------------------------------------------------
// `acl show` (`docs/CLI.md` §6.19, ADR-0025)
// ---------------------------------------------------------------------------

/// Run `qsh acl show --json` and return the envelope's `data` object.
fn acl_show(host: &Sandbox, principal: &str, auth_path: Option<&str>) -> Value {
    let mut args = vec!["acl", "show", "--principal", principal];
    if let Some(a) = auth_path {
        args.push("--auth-path");
        args.push(a);
    }
    args.push("--json");
    let (code, value) = host.json(&args);
    assert_eq!(code, 0, "acl show itself must not fail: {value}");
    value["data"].clone()
}

fn effective(data: &Value) -> Vec<String> {
    data["effective_actions"]
        .as_array()
        .expect("effective_actions array")
        .iter()
        .map(|v| v.as_str().expect("action string").to_string())
        .collect()
}

/// Three-way discipline (ADR-0025 decision 3): for every shared table row,
/// principal and auth path, membership in `acl show`'s effective set equals
/// `acl check`'s verdict for each of the 11 actions on an unowned resource.
#[test]
fn acl_show_effective_set_agrees_with_acl_check_for_every_action_in_every_table_row() {
    for row in POLICY_TABLE {
        let host = Sandbox::new();
        write_acl_toml(&host, &table_toml(row.name));
        for principal in row.principals {
            for auth_path in ["pin", "ca"] {
                let shown = effective(&acl_show(&host, principal, Some(auth_path)));
                for action in CoreAction::ALL {
                    let checked = acl_check(
                        &host,
                        principal,
                        action.as_str(),
                        None,
                        Some(auth_path),
                        None,
                        None,
                    );
                    let allowed = checked["decision"] == "allow";
                    assert_eq!(
                        shown.iter().any(|a| a == action.as_str()),
                        allowed,
                        "row {} principal {principal} auth_path {auth_path} action {}: \
                         show {shown:?} vs check {checked}",
                        row.name,
                        action.as_str()
                    );
                }
            }
        }
    }
}

#[test]
fn acl_show_reports_an_empty_set_and_no_policy_for_a_missing_or_invalid_acl_toml() {
    let missing = Sandbox::new();
    let data = acl_show(&missing, CLIENT_PRINCIPAL, None);
    assert_eq!(data["policy"]["loaded"], false, "{data}");
    assert_eq!(data["policy"]["rules"], 0, "{data}");
    assert!(effective(&data).is_empty(), "{data}");
    assert_eq!(data["matching_rules"], serde_json::json!([]), "{data}");

    let invalid = Sandbox::new();
    write_acl_toml(&invalid, "not toml {{{");
    let data = acl_show(&invalid, CLIENT_PRINCIPAL, None);
    assert_eq!(data["policy"]["loaded"], false, "{data}");
    assert!(effective(&data).is_empty(), "{data}");
    assert_eq!(data["matching_rules"], serde_json::json!([]), "{data}");
}

/// A permission-unreadable `acl.toml` folds into the same "no policy" state
/// (`PolicySource::load_path` maps a read error to `Invalid`) and leaks no
/// rule content.
#[test]
#[cfg(unix)]
fn acl_show_on_an_unreadable_acl_toml_reports_no_policy_and_no_rule_content() {
    use std::os::unix::fs::PermissionsExt;

    let host = Sandbox::new();
    write_acl_toml(
        &host,
        "[[acl]]\nprincipal = \"device:laptop\"\nallow = [\"host.reverse\"]\n",
    );
    let acl_path = host.config_dir().join("acl.toml");
    std::fs::set_permissions(&acl_path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    if std::fs::read(&acl_path).is_ok() {
        // Running as root: permission bits do not apply, nothing to test.
        return;
    }
    let (code, value) = host.json(&["acl", "show", "--principal", CLIENT_PRINCIPAL, "--json"]);
    // Restore before asserting so the sandbox can be cleaned up.
    let _ = std::fs::set_permissions(&acl_path, std::fs::Permissions::from_mode(0o600));
    assert_eq!(code, 0, "{value}");
    let data = &value["data"];
    assert_eq!(data["policy"]["loaded"], false, "{value}");
    assert!(effective(data).is_empty(), "{value}");
    assert_eq!(data["matching_rules"], serde_json::json!([]), "{value}");
    assert!(
        !value.to_string().contains("host.reverse"),
        "no rule content may appear: {value}"
    );
}

#[test]
fn acl_show_distinguishes_a_loaded_policy_with_no_matching_row_from_no_policy() {
    let host = Sandbox::new();
    write_acl_toml(&host, &table_toml("exact"));
    let data = acl_show(&host, "device:somebody-else", None);
    assert_eq!(data["policy"]["loaded"], true, "{data}");
    assert_eq!(data["policy"]["rules"], 1, "{data}");
    assert!(effective(&data).is_empty(), "{data}");
    assert_eq!(data["matching_rules"], serde_json::json!([]), "{data}");
}

#[test]
fn acl_show_never_lists_forward_socks_and_lists_no_file_action_for_a_row_without_paths() {
    let host = Sandbox::new();
    write_acl_toml(&host, &table_toml("family_wildcards"));
    let data = acl_show(&host, CLIENT_PRINCIPAL, None);
    let set = effective(&data);
    assert_eq!(set, ["forward.local", "forward.remote"], "{data}");
    // `forward.socks` is refused by the always-deny gate whatever the row
    // says. The file actions are absent only because the row has no `paths`
    // (ADR-0029 decision 4); a row with `paths` lists them (see
    // `file_rows_agree_between_acl_check_path_and_acl_show`).
    for absent in ["forward.socks", "file.read", "file.write"] {
        assert!(!set.iter().any(|a| a == absent), "{absent} in {data}");
    }
    // The row is still reported as matching, with its patterns as written;
    // it names `file.*` without `paths`, which the host flags.
    assert_eq!(
        data["matching_rules"],
        serde_json::json!([{
            "index": 0,
            "allow": ["forward.*", "file.*"],
            "auth_path": "pin",
            "scope": "owned",
            "file_paths_missing": true
        }]),
        "{data}"
    );
}

/// `acl check --path` against one path, returning the exit code and the
/// whole envelope (the argument-contract rows are errors, not decisions).
#[cfg(unix)]
fn acl_check_path(host: &Sandbox, action: &str, path: Option<&str>) -> (i32, Value) {
    let mut args = vec![
        "acl",
        "check",
        "--principal",
        CLIENT_PRINCIPAL,
        "--action",
        action,
    ];
    if let Some(path) = path {
        args.push("--path");
        args.push(path);
    }
    args.push("--json");
    host.json(&args)
}

/// The file rows of the three-way discipline (ADR-0029 결정 4·19): for
/// `file.read` and `file.write`, `acl check --path` decides per path and
/// `acl show` lists the action exactly when the principal has a ground for
/// it (a row with `paths`, or the role). Enforcement is the third voice:
/// `file_host.rs` (`acl_check_path_agrees_with_enforcement_*`) drives the
/// same rows through a running host, and asserts the same expectations
/// spelled out here. Rows: inside `paths`, a sibling, a symlink out, a `..`
/// escape, a row without `paths`, role `full` on any path, `--path` missing,
/// and `--path` on a non-file action.
#[cfg(unix)]
#[test]
fn file_rows_agree_between_acl_check_path_and_acl_show() {
    fn expect_invalid(host: &Sandbox, action: &str, path: Option<&str>) {
        let (code, out) = acl_check_path(host, action, path);
        assert_eq!(code, 255, "{action} {path:?}: {out}");
        assert_eq!(out["error"]["code"], "INVALID_ARGUMENT", "{out}");
    }

    let paths_row = Sandbox::new();
    let share = paths_row.home_dir().join("share");
    let outside = paths_row.home_dir().join("outside");
    std::fs::create_dir_all(share.join("sub")).expect("create share");
    std::fs::create_dir_all(&outside).expect("create outside");
    std::fs::write(share.join("a.txt"), b"alpha").expect("write a.txt");
    std::fs::write(outside.join("secret.txt"), b"x").expect("write secret");
    std::os::unix::fs::symlink(outside.join("secret.txt"), share.join("out")).expect("symlink");
    let share = std::fs::canonicalize(&share).expect("canonical share");
    let outside = std::fs::canonicalize(&outside).expect("canonical outside");
    let share_path = |rel: &str| format!("{}/{rel}", share.display());
    let rows: Vec<(String, bool)> = vec![
        (share_path("a.txt"), true),
        (share_path("sub/../a.txt"), true),
        (share_path("new.txt"), true),
        (outside.join("secret.txt").display().to_string(), false),
        (share_path("out"), false),
        (share_path("../outside/secret.txt"), false),
    ];
    let acl = |paths: Option<&str>| {
        let paths = paths.map_or(String::new(), |p| format!("paths = [\"{p}\"]\n"));
        format!(
            "[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"file.read\", \"file.write\"]\n{paths}"
        )
    };

    // A row with `paths`.
    write_acl_toml(&paths_row, &acl(Some(&share.display().to_string())));
    let shown = effective(&acl_show(&paths_row, CLIENT_PRINCIPAL, None));
    for action in ["file.read", "file.write"] {
        assert!(shown.iter().any(|a| a == action), "{action} in {shown:?}");
        for (path, expected) in &rows {
            let (code, out) = acl_check_path(&paths_row, action, Some(path));
            assert_eq!(code, 0, "{action} {path}: {out}");
            assert_eq!(
                out["data"]["decision"] == "allow",
                *expected,
                "{action} {path}: {out}"
            );
        }
        expect_invalid(&paths_row, action, None);
    }
    expect_invalid(&paths_row, "exec.run", Some(&share_path("a.txt")));

    // A row without `paths` grants no file access and is not listed.
    let nopaths = Sandbox::new();
    write_acl_toml(&nopaths, &acl(None));
    let shown = effective(&acl_show(&nopaths, CLIENT_PRINCIPAL, None));
    for action in ["file.read", "file.write"] {
        assert!(!shown.iter().any(|a| a == action), "{action} in {shown:?}");
        for (path, _) in &rows {
            let (code, out) = acl_check_path(&nopaths, action, Some(path));
            assert_eq!(code, 0, "{action} {path}: {out}");
            assert_eq!(out["data"]["decision"], "deny", "{action} {path}: {out}");
        }
        expect_invalid(&nopaths, action, None);
    }

    // Role `full` reaches every path and `acl show` lists both actions.
    let full = Sandbox::new();
    let client = Sandbox::new();
    pin_with_role(&full, &client.fingerprint(), "full");
    let shown = effective(&acl_show(&full, CLIENT_PRINCIPAL, None));
    for action in ["file.read", "file.write"] {
        assert!(shown.iter().any(|a| a == action), "{action} in {shown:?}");
        for (path, _) in &rows {
            let (code, out) = acl_check_path(&full, action, Some(path));
            assert_eq!(code, 0, "{action} {path}: {out}");
            assert_eq!(out["data"]["decision"], "allow", "{action} {path}: {out}");
            assert_eq!(out["data"]["role"], "full", "{action} {path}: {out}");
        }
        expect_invalid(&full, action, None);
    }
}

#[test]
fn acl_show_evaluates_the_ca_auth_path_when_asked() {
    let host = Sandbox::new();
    write_acl_toml(&host, &table_toml("auth_path_ca"));

    let defaulted = acl_show(&host, CLIENT_PRINCIPAL, None);
    assert_eq!(defaulted["auth_path"], "pin", "{defaulted}");
    assert!(effective(&defaulted).is_empty(), "{defaulted}");
    assert_eq!(defaulted["matching_rules"], serde_json::json!([]));

    let ca = acl_show(&host, CLIENT_PRINCIPAL, Some("ca"));
    assert_eq!(ca["auth_path"], "ca", "{ca}");
    assert_eq!(ca["auth_path_defaulted"], false, "{ca}");
    assert_eq!(effective(&ca), ["exec.run"], "{ca}");
    assert_eq!(ca["matching_rules"][0]["auth_path"], "ca", "{ca}");
}

#[test]
fn acl_show_rejects_a_malformed_principal_or_auth_path_as_invalid_argument() {
    let host = Sandbox::new();
    write_acl_toml(&host, &table_toml("exact"));
    for args in [
        &["acl", "show", "--principal", "nobody", "--json"][..],
        &[
            "acl",
            "show",
            "--principal",
            CLIENT_PRINCIPAL,
            "--auth-path",
            "pairing",
            "--json",
        ][..],
    ] {
        let (code, value) = host.json(args);
        assert_eq!(code, 255, "{value}");
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{value}");
    }
}

#[test]
fn acl_show_does_not_modify_acl_toml() {
    let host = Sandbox::new();
    let acl_path = host.config_dir().join("acl.toml");
    write_acl_toml(&host, &table_toml("exact"));
    let before_content = std::fs::read_to_string(&acl_path).expect("read acl.toml");
    let before_mtime = std::fs::metadata(&acl_path)
        .expect("stat acl.toml")
        .modified()
        .expect("mtime");

    let _ = acl_show(&host, CLIENT_PRINCIPAL, None);

    let after_content = std::fs::read_to_string(&acl_path).expect("read acl.toml");
    let after_mtime = std::fs::metadata(&acl_path)
        .expect("stat acl.toml")
        .modified()
        .expect("mtime");
    assert_eq!(before_content, after_content);
    assert_eq!(before_mtime, after_mtime);
}

/// Twin of [`acl_check_never_appears_as_a_control_message_wire_variant`]:
/// `acl.show` is local only (ADR-0025 decision 4). The compile-time anchor
/// is the shared exhaustive match above; the proto text check is the same
/// non-vacuity assertion.
#[test]
fn acl_show_never_appears_as_a_control_message_wire_variant() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../qsh-proto/proto/qsh/wire/v1.proto"
    ))
    .expect("read v1.proto");
    let lower = source.to_lowercase();
    assert!(
        !lower.contains("aclshow") && !lower.contains("acl_show"),
        "the wire proto must never gain an acl.show message"
    );
}

/// L6: with `--auth-path` omitted the human output carries the pin-default
/// notice and the JSON says `auth_path_defaulted: true`; naming the path
/// removes both.
#[test]
fn acl_show_notes_the_pin_default_when_auth_path_is_omitted() {
    let host = Sandbox::new();
    write_acl_toml(&host, &table_toml("exact"));

    let output = host.qsh(&["acl", "show", "--principal", CLIENT_PRINCIPAL]);
    assert_eq!(common::exit_code(&output), 0);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("--auth-path was omitted, so \"pin\" was evaluated"),
        "{stdout}"
    );

    let explicit = host.qsh(&[
        "acl",
        "show",
        "--principal",
        CLIENT_PRINCIPAL,
        "--auth-path",
        "pin",
    ]);
    let stdout = String::from_utf8(explicit.stdout).expect("utf8 stdout");
    assert!(!stdout.contains("--auth-path was omitted"), "{stdout}");

    let data = acl_show(&host, CLIENT_PRINCIPAL, None);
    assert_eq!(data["auth_path_defaulted"], true, "{data}");
    assert_eq!(data["auth_path"], "pin", "{data}");
    let data = acl_show(&host, CLIENT_PRINCIPAL, Some("pin"));
    assert_eq!(data["auth_path_defaulted"], false, "{data}");
}

/// L6: the human output prints `ACL_RESTART_NOTICE` as its own line, byte
/// for byte, and the JSON carries no notice prose.
#[test]
fn acl_show_human_output_carries_the_acl_restart_notice_byte_for_byte() {
    let host = Sandbox::new();
    write_acl_toml(&host, &table_toml("exact"));
    let output = host.qsh(&["acl", "show", "--principal", CLIENT_PRINCIPAL]);
    assert_eq!(common::exit_code(&output), 0);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.lines().any(|line| line == ACL_RESTART_NOTICE),
        "{stdout}"
    );

    let (_, value) = host.json(&["acl", "show", "--principal", CLIENT_PRINCIPAL, "--json"]);
    assert!(
        !value.to_string().contains(ACL_RESTART_NOTICE),
        "the restart notice is prose and stays out of the JSON: {value}"
    );
}

// ---------------------------------------------------------------------------
// The role dimension (M15 plan Step 6 (1a4af3b), ADR-0045 결정 10·11)
//
// ADR-0025 결정 3's three-way discipline, widened by the pin role: for a
// pin carrying each role (and for a legacy pin with no `role` key), `acl
// check`, `acl show`, the real op and the audit record must agree, with no
// `acl.toml` (rows empty, only the role can grant) and with a row that adds
// `session.list`.
//
// The real op column covers `exec.run`, `session.open` and `session.list`.
// `forward.*` and `host.reverse` have no short-lived CLI producer (`qsh
// tunnel open` runs until killed; `host.reverse` is a registration loop), so
// those actions are covered by `acl check` against `acl show` and the
// literal role table below, and by the enforcement tests in
// `acl_enforcement.rs` and `qsh-core`'s `decide_agrees_with_naive_coverage_oracle`.
// ---------------------------------------------------------------------------

/// The role table of ADR-0045 결정 2, spelled out again here on purpose:
/// never read from `qsh_core::acl::ROLE_GRANTS`, so a wrong row in the
/// constant disagrees with this copy. `forward.socks` is left out because
/// the always-deny gate answers it before any role; `file.read` and
/// `file.write` ride on `full` alone (ADR-0029 decision 4).
fn role_grants_literal(role: &str, action: &str) -> bool {
    let granted: &[&str] = match role {
        "full" => &[
            "exec.run",
            "session.open",
            "session.list",
            "session.attach",
            "session.control",
            "forward.local",
            "forward.remote",
            "host.reverse",
            "file.read",
            "file.write",
        ],
        "exec" => &[
            "exec.run",
            "session.open",
            "session.list",
            "session.attach",
            "session.control",
        ],
        "tunnel" => &["forward.local", "forward.remote"],
        "read-only" => &["session.list", "session.attach"],
        "reverse" => &["host.reverse"],
        "none" | "legacy" => &[],
        other => panic!("unknown role row {other}"),
    };
    granted.contains(&action)
}

/// Pin `client_fp` on `host` as `CLIENT_ALIAS` with `role`. `"legacy"` is a
/// pin written before ADR-0045: the `role` key is cut out of the file.
fn pin_with_role(host: &Sandbox, client_fp: &str, role: &str) {
    if role == "legacy" {
        host.trust_add_with_role(CLIENT_ALIAS, None, client_fp, "none");
        let path = host.config_dir().join("trust.toml");
        let text = std::fs::read_to_string(&path).expect("read trust.toml");
        let stripped: String = text
            .lines()
            .filter(|line| !line.starts_with("role = "))
            .map(|line| format!("{line}\n"))
            .collect();
        assert!(!stripped.contains("role"), "{stripped}");
        std::fs::write(&path, stripped).expect("write trust.toml");
    } else {
        host.trust_add_with_role(CLIENT_ALIAS, None, client_fp, role);
    }
}

/// One row of the role table: a host whose pin of the client carries `role`,
/// started once with no `acl.toml` and once with a row granting only
/// `session.list`.
fn role_row_agrees(role: &str) {
    let expected_role = if role == "legacy" { "none" } else { role };
    let ops: [(&str, &[&str]); 3] = [
        ("exec.run", &["exec", HOST_ALIAS, "--json", "--", "true"]),
        ("session.open", &["session", "open", HOST_ALIAS, "--json"]),
        ("session.list", &["sessions", HOST_ALIAS, "--json"]),
    ];
    for with_row in [false, true] {
        let host = Sandbox::new();
        let client = Sandbox::new();
        let host_fp = host.fingerprint();
        let client_fp = client.fingerprint();
        pin_with_role(&host, &client_fp, role);
        if with_row {
            write_acl_toml(
                &host,
                &format!(
                    "[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"session.list\"]\n"
                ),
            );
        }
        let serve = ServeGuard::start_without_policy(&host, &[]);
        client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);
        let label = format!("role {role}, row {with_row}");

        for (action, args) in ops {
            let (code, value) = client.json(args);
            let data = acl_check(
                &host,
                CLIENT_PRINCIPAL,
                action,
                None,
                Some("pin"),
                None,
                None,
            );

            // `acl check` against the literal table: the role grants it, or
            // the one row does.
            let by_role = role_grants_literal(role, action);
            let by_row = with_row && action == "session.list";
            let allowed = data["decision"] == "allow";
            assert_eq!(allowed, by_role || by_row, "{label} {action}: {data}");
            assert_eq!(data["role"], expected_role, "{label} {action}: {data}");
            assert_eq!(
                data["policy"]["state"],
                if with_row { "loaded" } else { "missing" },
                "{label} {action}: {data}"
            );

            // A Windows host has no PTY sessions yet (M20): `session.open`
            // answers UNSUPPORTED there, so only the `acl check` columns
            // above apply to it. `exec.run` and `session.list` run for real.
            if cfg!(windows) && action == "session.open" {
                continue;
            }

            // The real op agrees.
            if allowed {
                assert_eq!(code, 0, "{label} {action}: {value}");
            } else {
                assert_eq!(code, 255, "{label} {action}: {value}");
                assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");
            }

            // The audit record agrees on decision, rule and role. When a role
            // and the row would both allow, the basis is the role.
            let decision = if allowed { "allow" } else { "deny" };
            let records = wait_for_audit(&host, &format!("{label}: {action} {decision}"), |r| {
                r["action"] == action && r["decision"] == decision
            });
            let record = records
                .iter()
                .find(|r| r["action"] == action && r["decision"] == decision)
                .expect("audit record");
            if allowed {
                let basis = if by_role { "role" } else { "acl" };
                assert_eq!(data["granted_by"], basis, "{label} {action}: {data}");
                if by_role {
                    assert!(data.get("rule").is_none(), "{label} {action}: {data}");
                    assert!(record["rule"].is_null(), "{label} {action}: {record}");
                    assert_eq!(record["role"], expected_role, "{label} {action}: {record}");
                } else {
                    assert_eq!(data["rule"], 0, "{label} {action}: {data}");
                    assert_eq!(record["rule"], 0, "{label} {action}: {record}");
                    assert!(record.get("role").is_none(), "{label} {action}: {record}");
                }
            } else {
                assert!(data.get("granted_by").is_none(), "{label} {action}: {data}");
                assert!(record["rule"].is_null(), "{label} {action}: {record}");
                assert!(record.get("role").is_none(), "{label} {action}: {record}");
            }
        }

        // `acl show` against `acl check` for all eleven actions, and against
        // the role table.
        let shown = acl_show(&host, CLIENT_PRINCIPAL, Some("pin"));
        assert_eq!(shown["role"], expected_role, "{label}: {shown}");
        let table = qsh_core::acl::role_grant(expected_role.parse().expect("role name"));
        let table: Vec<&str> = table.actions.iter().map(|a| a.as_str()).collect();
        let role_actions: Vec<&str> = shown["role_actions"]
            .as_array()
            .expect("role_actions")
            .iter()
            .map(|v| v.as_str().expect("action string"))
            .collect();
        assert_eq!(role_actions, table, "{label}: {shown}");
        let effective_set = effective(&shown);
        for action in CoreAction::ALL {
            let checked = acl_check(
                &host,
                CLIENT_PRINCIPAL,
                action.as_str(),
                None,
                Some("pin"),
                None,
                None,
            );
            let allowed = checked["decision"] == "allow";
            assert_eq!(
                effective_set.iter().any(|a| a == action.as_str()),
                allowed,
                "{label} {}: show {effective_set:?} vs check {checked}",
                action.as_str()
            );
            let literal = role_grants_literal(role, action.as_str())
                || (with_row && action.as_str() == "session.list");
            assert_eq!(allowed, literal, "{label} {}: {checked}", action.as_str());
        }
    }
}

macro_rules! role_row_tests {
    ($($name:ident => $role:literal),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                role_row_agrees($role);
            }
        )*
    };
}

role_row_tests! {
    role_full_agrees_across_check_show_op_and_audit => "full",
    role_exec_agrees_across_check_show_op_and_audit => "exec",
    role_tunnel_agrees_across_check_show_op_and_audit => "tunnel",
    role_read_only_agrees_across_check_show_op_and_audit => "read-only",
    role_reverse_agrees_across_check_show_op_and_audit => "reverse",
    role_none_agrees_across_check_show_op_and_audit => "none",
    role_legacy_pin_agrees_across_check_show_op_and_audit => "legacy",
}

/// A `missing` policy is a policy with no rows: the role still grants, and
/// `policy.loaded` stays `false`. An `invalid` one refuses role grants too,
/// but the role is still reported so the operator sees what is being
/// refused. `acl show` follows (ADR-0045 결정 6, 10, 11).
#[test]
fn missing_policy_keeps_role_grants_and_invalid_policy_refuses_them() {
    let host = Sandbox::new();
    pin_with_role(&host, &Sandbox::new().fingerprint(), "full");

    let missing = acl_check(&host, CLIENT_PRINCIPAL, "exec.run", None, None, None, None);
    assert_eq!(missing["decision"], "allow", "{missing}");
    assert_eq!(missing["granted_by"], "role", "{missing}");
    assert_eq!(missing["policy"]["loaded"], false, "{missing}");
    assert_eq!(missing["policy"]["state"], "missing", "{missing}");
    assert_eq!(missing["policy"]["rules"], 0, "{missing}");
    let shown = acl_show(&host, CLIENT_PRINCIPAL, None);
    assert_eq!(shown["policy"]["state"], "missing", "{shown}");
    assert_eq!(shown["matching_rules"], serde_json::json!([]), "{shown}");
    assert!(effective(&shown).iter().any(|a| a == "exec.run"), "{shown}");

    write_acl_toml(&host, "not toml {{{");
    let invalid = acl_check(&host, CLIENT_PRINCIPAL, "exec.run", None, None, None, None);
    assert_eq!(invalid["decision"], "deny", "{invalid}");
    assert!(invalid.get("granted_by").is_none(), "{invalid}");
    assert_eq!(invalid["policy"]["loaded"], false, "{invalid}");
    assert_eq!(invalid["policy"]["state"], "invalid", "{invalid}");
    assert_eq!(invalid["role"], "full", "{invalid}");
    let shown = acl_show(&host, CLIENT_PRINCIPAL, None);
    assert_eq!(shown["policy"]["state"], "invalid", "{shown}");
    assert!(effective(&shown).is_empty(), "{shown}");
}

/// The role is omitted whenever no pin role applies: a CA-path question, a
/// `user:` or `fp:` principal, a name with no pin, and a `trust.toml` that
/// does not parse (the state in which a running `qsh serve` grants no role).
/// The rows alone then decide, with `granted_by: "acl"` when they allow.
#[test]
fn role_is_omitted_when_no_pin_role_applies() {
    let host = Sandbox::new();
    pin_with_role(&host, &Sandbox::new().fingerprint(), "full");
    write_acl_toml(
        &host,
        "[[acl]]\nprincipal = \"device:laptop\"\nauth_path = \"ca\"\nallow = [\"exec.run\"]\n\n\
         [[acl]]\nprincipal = \"user:dave\"\nallow = [\"exec.run\"]\n",
    );

    // A CA-path question never reaches the role, even for a pinned name.
    let ca = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "exec.run",
        None,
        Some("ca"),
        None,
        None,
    );
    assert!(ca.get("role").is_none(), "{ca}");
    assert_eq!(ca["granted_by"], "acl", "{ca}");
    let ca_denied = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "session.open",
        None,
        Some("ca"),
        None,
        None,
    );
    assert_eq!(ca_denied["decision"], "deny", "{ca_denied}");
    let shown = acl_show(&host, CLIENT_PRINCIPAL, Some("ca"));
    assert!(
        shown.get("role").is_none() && shown.get("role_actions").is_none(),
        "{shown}"
    );
    assert_eq!(effective(&shown), ["exec.run"], "{shown}");

    // `user:` principals and unpinned names carry no role.
    for principal in ["user:dave", "device:stranger"] {
        let data = acl_check(&host, principal, "exec.run", None, None, None, None);
        assert!(data.get("role").is_none(), "{principal}: {data}");
    }
    let stranger = acl_check(&host, "device:stranger", "exec.run", None, None, None, None);
    assert_eq!(stranger["decision"], "deny", "{stranger}");
    let user = acl_check(&host, "user:dave", "exec.run", None, None, None, None);
    assert_eq!(user["granted_by"], "acl", "{user}");

    // An unparseable trust.toml: no role, rows unaffected.
    std::fs::write(
        host.config_dir().join("trust.toml"),
        "[[peer]]\nname = \"laptop\"\nfingerprint = \"sha256:AAAA\"\naddress = \"\"\n\
         added_at = \"t\"\nrole = \"no-such-role\"\n",
    )
    .expect("write trust.toml");
    let broken = acl_check(&host, CLIENT_PRINCIPAL, "exec.run", None, None, None, None);
    assert!(broken.get("role").is_none(), "{broken}");
    assert_eq!(broken["decision"], "deny", "{broken}");
}

/// A tunnel-role pin is `owned`-axis: `acl check` with an owner that is
/// someone else denies `forward.remote`, with the pin's own principal as
/// owner allows it (the same rule `decide` applies to enforcement).
#[test]
fn tunnel_role_honors_the_owner_axis_in_acl_check() {
    let host = Sandbox::new();
    pin_with_role(&host, &Sandbox::new().fingerprint(), "tunnel");
    let own = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "forward.remote",
        Some("127.0.0.1:1"),
        None,
        Some(CLIENT_PRINCIPAL),
        None,
    );
    assert_eq!(own["decision"], "allow", "{own}");
    assert_eq!(own["granted_by"], "role", "{own}");
    let other = acl_check(
        &host,
        CLIENT_PRINCIPAL,
        "forward.remote",
        Some("127.0.0.1:1"),
        None,
        Some("device:someone-else"),
        None,
    );
    assert_eq!(other["decision"], "deny", "{other}");
}

/// Human output (ADR-0045 결정 11): `acl check` names a role basis, and
/// `acl show` leads with the role and states the asymmetry between roles
/// (next request) and rows (restart), the latter as `ACL_RESTART_NOTICE`.
#[test]
fn human_output_names_the_role_and_the_role_versus_row_asymmetry() {
    let host = Sandbox::new();
    pin_with_role(&host, &Sandbox::new().fingerprint(), "exec");

    let output = host.qsh(&[
        "acl",
        "check",
        "--principal",
        CLIENT_PRINCIPAL,
        "--action",
        "exec.run",
    ]);
    assert_eq!(common::exit_code(&output), 0);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert_eq!(stdout.trim_end(), "allow (role exec)", "{stdout}");

    let output = host.qsh(&["acl", "show", "--principal", CLIENT_PRINCIPAL]);
    assert_eq!(common::exit_code(&output), 0);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines[0].starts_with("principal: device:laptop"), "{stdout}");
    assert!(
        lines[1].starts_with("role: exec (exec.run, session.open"),
        "the role line comes first: {stdout}"
    );
    let role_note = lines
        .iter()
        .position(|line| line.contains("a role change takes effect on the next request"))
        .unwrap_or_else(|| panic!("no role-reload line: {stdout}"));
    let row_note = lines
        .iter()
        .position(|line| *line == ACL_RESTART_NOTICE)
        .unwrap_or_else(|| panic!("no restart notice line: {stdout}"));
    assert!(role_note < row_note, "{stdout}");
}
