use super::*;

/// A `use qsh_transport::…` under the broker directory is flagged.
#[test]
fn module_ban_flags_a_transport_import_under_broker() {
    let root = tempfile::tempdir().unwrap();
    let broker = root.path().join("crates/qsh-core/src/broker");
    fs::create_dir_all(&broker).unwrap();
    fs::write(
        broker.join("session.rs"),
        "use qsh_transport::Connection;\nfn f() {}\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();
    let hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("session.rs"))
        .collect();
    assert_eq!(hits.len(), 1, "{violations:?}");
    assert!(hits[0].contains("session.rs:1"));
    assert!(hits[0].contains("qsh_transport"));
}

/// Prose mentioning the crate in a doc comment must NOT trip the ban —
/// only real code references do.
#[test]
fn module_ban_ignores_comments() {
    let root = tempfile::tempdir().unwrap();
    let broker = root.path().join("crates/qsh-core/src/broker");
    fs::create_dir_all(&broker).unwrap();
    fs::write(
        broker.join("mod.rs"),
        "//! never names a `qsh_transport` type (ADR-0003).\n\
         /// nothing under here imports qsh_transport.\n\
         pub fn ok() {}\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();
    let hits: Vec<_> = violations.iter().filter(|v| v.contains("mod.rs")).collect();
    assert!(hits.is_empty(), "{violations:?}");
}

/// Smoke check: a CRLF-line-ended source file (the Windows-checkout
/// shape `acl_registry.rs`'s `source_scan` module calls out) must still
/// get its violation caught (restoring the coverage the M8 Step 6 MCP-ban
/// removal dropped along with `MCP_DIR`) — the deleted test's own doc
/// said as much: this is a demonstration, not a discriminator, and
/// cannot be turned into one. Swapping
/// `text.lines()` for `text.split('\n')` in `check_module_bans` still
/// passes this (and every other) xtask test, because the scan matches
/// `ban.forbidden` as a substring anywhere within a line, and a
/// trailing `\r` only ever sits at the very end of that line — after
/// the token has already matched or not — so its presence or absence
/// cannot flip the `.contains()` result either way. There is no line
/// content this scan could be given that would tell `lines()` and
/// `split('\n')` apart here.
///
/// This is why this test needs no separate `.replace("\r\n", "\n")`
/// step: the M5 precedent in `acl_registry.rs`'s `source_scan` needed
/// that replace only because *that* scan does a whole-file, multi-line
/// marker substring search (a match can straddle a line boundary), a
/// shape where a stray `\r` immediately before the match point could
/// matter. This scan is strictly per-line and position-independent
/// within the line, so no such step is needed here.
#[test]
fn module_ban_catches_a_violation_in_a_crlf_line_ended_file_under_cli_src() {
    let root = tempfile::tempdir().unwrap();
    let cli_src = root.path().join("crates/qsh-cli/src");
    fs::create_dir_all(&cli_src).unwrap();
    fs::write(
        cli_src.join("crlf.rs"),
        "// a comment first\r\nfn f() { let _ = UnixStream::connect(\"x\"); }\r\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();
    let hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("crlf.rs"))
        .collect();
    assert_eq!(hits.len(), 1, "{violations:?}");
    assert!(hits[0].contains("crlf.rs:2"));
    assert!(hits[0].contains("UnixStream"));
}

/// The crate-root re-export of a transport type (`crate::Principal`)
/// and the transport's own dependencies are banned too — the seam
/// cannot be evaded by going through `qsh-core`'s own paths.
#[test]
fn module_ban_flags_reexported_transport_types_and_underlying_crates() {
    let root = tempfile::tempdir().unwrap();
    let broker = root.path().join("crates/qsh-core/src/broker");
    fs::create_dir_all(&broker).unwrap();
    fs::write(
        broker.join("lease.rs"),
        "use crate::Principal;\nuse crate::client::Session;\nfn f() { let _ = quinn::Endpoint::client; }\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();
    let hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("lease.rs"))
        .collect();
    assert_eq!(hits.len(), 3, "{violations:?}");
    assert!(hits.iter().any(|v| v.contains("crate::Principal")));
    assert!(hits.iter().any(|v| v.contains("crate::client")));
    assert!(hits.iter().any(|v| v.contains("quinn")));
}

/// A nested module file is scanned too.
#[test]
fn module_ban_recurses_into_subdirectories() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("crates/qsh-core/src/broker/sub");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("inner.rs"), "let _ = qsh_transport::foo();\n").unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();
    let hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("inner.rs"))
        .collect();
    assert_eq!(hits.len(), 1, "{violations:?}");
}

/// Every configured module-ban target that doesn't exist is flagged
/// once — not once per token bound to it (the ban targets must exist
/// once their consumers land: `BROKER_DIR`, the two `localctl` files,
/// `REGISTRY_FILE`, `CLI_SRC_DIR`, `INVITE_ADDRESS_FILE`, and the
/// `SETUP_DIR` directory, and the `INVITE_ADDRESS_DIR` directory that two
/// separate bans share — a shared target is still one entry in `reported_missing`, not two).
#[test]
fn module_ban_flags_each_missing_target_exactly_once() {
    let root = tempfile::tempdir().unwrap();
    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();
    assert_eq!(violations.len(), 8, "{violations:?}");
    assert!(
        violations.iter().all(|v| v.contains("does not exist")),
        "{violations:?}"
    );
}

/// `localctl/frame.rs` and `client.rs` ban `qsh_transport`/`quinn`/
/// `rustls` — but `daemon.rs`, the transport bridge, is deliberately
/// exempt because the ban is file-scoped, not directory-scoped.
#[test]
fn module_ban_flags_transport_in_localctl_frame_and_client_but_daemon_is_exempt() {
    let root = tempfile::tempdir().unwrap();
    let localctl = root.path().join("crates/qsh-core/src/localctl");
    fs::create_dir_all(&localctl).unwrap();
    fs::write(
        localctl.join("frame.rs"),
        "use qsh_transport::Connection;\n",
    )
    .unwrap();
    fs::write(
        localctl.join("client.rs"),
        "fn f() { let _ = quinn::Endpoint::client; }\n",
    )
    .unwrap();
    fs::write(
        localctl.join("daemon.rs"),
        "use qsh_transport::Connection;\nuse quinn::Endpoint;\nuse rustls::ClientConfig;\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();

    // Match on `<file>:<line>` (the violation's location prefix), not a
    // bare filename — the shared reason string itself mentions
    // `daemon.rs` in prose, which would otherwise false-positive here.
    let frame_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("frame.rs:"))
        .collect();
    let client_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("client.rs:"))
        .collect();
    let daemon_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("daemon.rs:"))
        .collect();

    assert_eq!(frame_hits.len(), 1, "{violations:?}");
    assert!(frame_hits[0].contains("qsh_transport"));
    assert_eq!(client_hits.len(), 1, "{violations:?}");
    assert!(client_hits[0].contains("quinn"));
    assert!(
        daemon_hits.is_empty(),
        "daemon.rs is the transport bridge and must stay exempt: {violations:?}"
    );
}

/// `trust/invite_address/` bans `.send`/`.recv` and the serde tokens by
/// *directory* (`INVITE_ADDRESS_DIR`), not only on `route.rs` by name: a
/// file-scoped-only ban would let a later sibling added next to `route.rs`
/// escape it, exactly the trap CLAUDE.md's arch-lint note warns about.
/// The parent `invite_address.rs`
/// *file*, one level up, is deliberately outside the directory scope —
/// covered instead by the separate `Scope::File(INVITE_ADDRESS_FILE)`
/// entry the serde tokens also carry.
#[test]
fn module_ban_flags_send_and_json_schema_in_a_new_sibling_under_invite_address() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("crates/qsh-core/src/trust/invite_address");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("route.rs"),
        "fn f(s: &std::net::UdpSocket) { let _ = s.send(&[]); }\n",
    )
    .unwrap();
    // Not `route.rs` — a brand-new sibling, to prove the ban reaches a
    // file that did not exist when the rule was written.
    fs::write(
        dir.join("extra.rs"),
        "#[derive(schemars::JsonSchema)]\nstruct Sibling;\n",
    )
    .unwrap();
    // The parent file, one level up: outside `INVITE_ADDRESS_DIR`'s
    // scope, so it must stay clean even though it shares the "serde
    // tokens" rule via its own separate `Scope::File` entry.
    fs::write(
        root.path()
            .join("crates/qsh-core/src/trust/invite_address.rs"),
        "pub(crate) mod route;\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();

    let route_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("invite_address/route.rs"))
        .collect();
    let extra_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("extra.rs"))
        .collect();
    let parent_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("invite_address.rs:"))
        .collect();

    assert_eq!(route_hits.len(), 1, "{violations:?}");
    assert!(route_hits[0].contains(".send"));
    assert_eq!(extra_hits.len(), 1, "{violations:?}");
    assert!(extra_hits[0].contains("JsonSchema"));
    assert!(
        parent_hits.is_empty(),
        "invite_address.rs's own clean content must not be flagged: {violations:?}"
    );
}

/// `crates/qsh-core/src/setup/` bans all eight write and probe tokens by
/// directory, so a nested module or a later sibling is covered, and a
/// `tests.rs` under it is scanned like any other file. The `//` comment
/// strip is naive, so this is also where that assumption was re-checked
/// for the new scope: no line in the scope embeds `//` in a string
/// before a banned token (a URL in a string literal would hide one).
#[test]
fn module_ban_flags_every_forbidden_token_under_setup_including_nested_directories() {
    let root = tempfile::tempdir().unwrap();
    let setup = root.path().join("crates/qsh-core/src/setup");
    let nested = setup.join("plan/deep");
    fs::create_dir_all(&nested).unwrap();
    let tokens = [
        "acl_file",
        "fs::write",
        "File::create",
        "OpenOptions",
        "write_private_file",
        "write_atomically",
        ".save(",
        "probe_fingerprint",
    ];
    // One token per line, alternating between the directory itself and a
    // nested directory two levels down.
    let mut top = String::new();
    let mut deep = String::new();
    for (i, token) in tokens.iter().enumerate() {
        let line = format!("fn f{i}() {{ let _ = {token}; }}\n");
        if i % 2 == 0 {
            top.push_str(&line);
        } else {
            deep.push_str(&line);
        }
    }
    fs::write(setup.join("mod.rs"), top).unwrap();
    fs::write(nested.join("inner.rs"), deep).unwrap();
    fs::write(setup.join("tests.rs"), "fn t() { let _ = fs::write; }\n").unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();
    let setup_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("src/setup/"))
        .collect();
    for token in tokens {
        assert!(
            setup_hits
                .iter()
                .any(|v| v.contains(&format!("names `{token}`"))),
            "{token} was not flagged: {violations:?}"
        );
    }
    assert!(
        setup_hits.iter().any(|v| v.contains("setup/mod.rs:")),
        "{violations:?}"
    );
    assert!(
        setup_hits
            .iter()
            .any(|v| v.contains("setup/plan/deep/inner.rs:")),
        "{violations:?}"
    );
    assert!(
        setup_hits.iter().any(|v| v.contains("setup/tests.rs:")),
        "{violations:?}"
    );
    // Nothing under `setup/` trips any other scope's ban.
    assert_eq!(setup_hits.len(), 9, "{setup_hits:?}");
}

/// Prose and doc comments under `setup/` may name the banned tokens, the
/// way the module's own docs name `write_private_file` when they explain
/// the ban; only code trips it.
#[test]
fn module_ban_ignores_forbidden_tokens_in_setup_comments() {
    let root = tempfile::tempdir().unwrap();
    let setup = root.path().join("crates/qsh-core/src/setup");
    fs::create_dir_all(&setup).unwrap();
    fs::write(
        setup.join("mod.rs"),
        "//! never calls write_private_file or probe_fingerprint, and never opens acl_file.\n\
         /// no fs::write, File::create, OpenOptions or write_atomically here.\n\
         pub fn ok() {} // and no .save( either\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();
    let hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("src/setup/"))
        .collect();
    assert!(hits.is_empty(), "{violations:?}");
}

/// The directory-qualified filter the test above uses only means what it
/// says if a violation spells its path the same way on every platform.
/// It does not by default: a Windows CI run flagged
/// `trust/invite_address\route.rs`, and every other ban test matches a
/// bare file name, so that test is the first one the mixed spelling
/// could reach. [`repo_relative_display`] is what makes it uniform.
#[test]
fn a_violation_path_is_spelled_with_forward_slashes_on_every_platform() {
    let native: PathBuf = [
        "crates",
        "qsh-core",
        "src",
        "trust",
        "invite_address",
        "route.rs",
    ]
    .iter()
    .collect();
    assert_eq!(
        repo_relative_display(&native),
        "crates/qsh-core/src/trust/invite_address/route.rs"
    );
}

/// `reverse/registry.rs` bans the same six-token set as `BROKER_DIR` —
/// a sibling file in the same directory (e.g. `listen.rs`, the live
/// bridge) is not in scope for this rule.
#[test]
fn module_ban_flags_a_leak_in_reverse_registry_but_not_its_sibling_listen_rs() {
    let root = tempfile::tempdir().unwrap();
    let reverse = root.path().join("crates/qsh-core/src/reverse");
    fs::create_dir_all(&reverse).unwrap();
    fs::write(
        reverse.join("registry.rs"),
        "use crate::client::Session;\nfn f() { let _ = quinn::Endpoint::client; }\n",
    )
    .unwrap();
    fs::write(
        reverse.join("listen.rs"),
        "use qsh_transport::Connection; // legitimate: listen.rs is the live bridge\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();

    let registry_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("registry.rs"))
        .collect();
    let listen_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("listen.rs"))
        .collect();

    assert_eq!(registry_hits.len(), 2, "{violations:?}");
    assert!(registry_hits.iter().any(|v| v.contains("crate::client")));
    assert!(registry_hits.iter().any(|v| v.contains("quinn")));
    assert!(
        listen_hits.is_empty(),
        "listen.rs is not in scope for the registry rule: {violations:?}"
    );
}

/// `qsh-cli/src` bans `UnixStream`/`UnixListener` — but the ban is
/// scoped to `src/` only, so `crates/qsh-cli/tests/localctl_perms.rs`
/// (which legitimately needs `UnixStream` to probe UDS permissions) is
/// unaffected.
#[test]
fn module_ban_flags_uds_apis_under_cli_src_but_tests_are_exempt() {
    let root = tempfile::tempdir().unwrap();
    let cli_src = root.path().join("crates/qsh-cli/src");
    fs::create_dir_all(&cli_src).unwrap();
    fs::write(cli_src.join("main.rs"), "use tokio::net::UnixStream;\n").unwrap();

    let cli_tests = root.path().join("crates/qsh-cli/tests");
    fs::create_dir_all(&cli_tests).unwrap();
    fs::write(
        cli_tests.join("localctl_perms.rs"),
        "use tokio::net::UnixStream;\nuse tokio::net::UnixListener;\n",
    )
    .unwrap();

    let mut violations = Vec::new();
    check_module_bans(root.path(), &mut violations).unwrap();

    let src_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("main.rs"))
        .collect();
    let test_hits: Vec<_> = violations
        .iter()
        .filter(|v| v.contains("localctl_perms.rs"))
        .collect();

    assert_eq!(src_hits.len(), 1, "{violations:?}");
    assert!(src_hits[0].contains("UnixStream"));
    assert!(
        test_hits.is_empty(),
        "crates/qsh-cli/tests is out of scope for this rule: {violations:?}"
    );
}

/// The real workspace tree must respect every module ban: the broker,
/// `localctl/{frame,client}.rs` (with `daemon.rs` exempt),
/// `reverse/registry.rs`, and `qsh-cli/src`.
#[test]
fn real_tree_respects_all_module_bans() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut violations = Vec::new();
    check_module_bans(workspace_root, &mut violations).unwrap();
    assert!(violations.is_empty(), "{violations:?}");
}
