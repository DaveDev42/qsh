//! `qsh acl check --path` and the `paths` echo of `qsh acl show` (ADR-0029
//! 결정 4·19, `docs/CLI.md` §6.15·§6.19). Both are local operations over a
//! hand-written `acl.toml`, so each test gets its own sandbox.
//!
//! The always-deny gate still stands in front of `file.read`/`file.write`,
//! so every decision here is `deny`; what the tests pin is the argument
//! contract, the request echo, and when normalization runs. Which paths a
//! row covers is pinned at the evaluator (`acl::policy` tests).

mod common;

#[cfg(unix)]
use common::CLIENT_ALIAS;
use common::{CLIENT_PRINCIPAL, Sandbox};
use serde_json::Value;

#[cfg(unix)]
fn write_acl(host: &Sandbox, text: &str) {
    std::fs::write(host.config_dir().join("acl.toml"), text).expect("write acl.toml");
}

fn check(host: &Sandbox, action: &str, path: Option<&str>) -> (i32, Value) {
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

#[test]
fn file_action_without_path_is_invalid_argument() {
    let host = Sandbox::new();
    for action in ["file.read", "file.write"] {
        let (code, out) = check(&host, action, None);
        assert_eq!(code, 255, "{out}");
        assert_eq!(out["error"]["code"], "INVALID_ARGUMENT", "{out}");
        assert!(
            out["error"]["message"].as_str().unwrap().contains("--path"),
            "{out}"
        );
    }
}

#[test]
fn path_on_a_non_file_action_is_invalid_argument() {
    let host = Sandbox::new();
    let (code, out) = check(&host, "exec.run", Some("/srv"));
    assert_eq!(code, 255, "{out}");
    assert_eq!(out["error"]["code"], "INVALID_ARGUMENT", "{out}");
    assert!(!out.to_string().contains("/srv"), "{out}");
}

#[cfg(unix)]
#[test]
fn malformed_path_is_invalid_argument_and_never_echoed() {
    let host = Sandbox::new();
    let too_long = format!("/{}", "a".repeat(5000));
    for bad in ["~someone/SENTINEL", "", too_long.as_str()] {
        let (code, out) = check(&host, "file.read", Some(bad));
        assert_eq!(code, 255, "{out}");
        assert_eq!(out["error"]["code"], "INVALID_ARGUMENT", "{out}");
        assert!(!out.to_string().contains("SENTINEL"), "{out}");
        assert!(!out.to_string().contains("aaaaaaaa"), "{out}");
    }
}

#[cfg(unix)]
#[test]
fn path_argument_is_checked_before_acl_toml_is_read() {
    let host = Sandbox::new();
    write_acl(&host, "not valid toml {{{");
    let (code, out) = check(&host, "file.read", None);
    assert_eq!(code, 255, "{out}");
    assert_eq!(out["error"]["code"], "INVALID_ARGUMENT", "{out}");
}

#[cfg(unix)]
#[test]
fn principal_without_a_file_grant_never_gets_a_canonical_path() {
    let host = Sandbox::new();
    write_acl(
        &host,
        &format!("[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"exec.run\"]\n"),
    );
    let (code, out) = check(&host, "file.read", Some("/srv/share/a.txt"));
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["data"]["decision"], "deny", "{out}");
    assert_eq!(out["data"]["path"], "/srv/share/a.txt", "{out}");
    assert!(out["data"].get("canonical_path").is_none(), "{out}");
}

#[cfg(unix)]
#[test]
fn row_with_paths_makes_the_query_normalize_the_request_path() {
    let host = Sandbox::new();
    let share = host.home_dir().join("share");
    std::fs::create_dir_all(&share).expect("create share dir");
    let canonical_share = std::fs::canonicalize(&share).expect("canonicalize share dir");
    write_acl(
        &host,
        &format!(
            "[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"file.read\"]\npaths = [\"{}\"]\n",
            canonical_share.display()
        ),
    );
    // A `..` that climbs out and back in resolves to the same file.
    let asked = format!("{}/sub/../a.txt", share.display());
    let (code, out) = check(&host, "file.read", Some(&asked));
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["data"]["path"], asked.as_str(), "{out}");
    assert_eq!(
        out["data"]["canonical_path"],
        canonical_share.join("a.txt").to_string_lossy().as_ref(),
        "{out}"
    );
}

#[cfg(unix)]
#[test]
fn role_that_grants_files_makes_the_query_normalize_without_any_row() {
    let host = Sandbox::new();
    host.trust_add_with_role(CLIENT_ALIAS, None, &Sandbox::new().fingerprint(), "full");
    let (code, out) = check(&host, "file.read", Some("/"));
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["data"]["canonical_path"], "/", "{out}");
    // `full` grants `file.read` whatever the path; enforcement adds the
    // state-path check on top, which `acl check` does not run (ADR-0029
    // decision 4-6 and CLI.md section 6.15).
    assert_eq!(out["data"]["decision"], "allow", "{out}");
}

#[cfg(unix)]
#[test]
fn acl_show_echoes_paths_and_flags_a_file_row_without_them() {
    let host = Sandbox::new();
    write_acl(
        &host,
        &format!(
            "[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"file.read\"]\n\
             paths = [\"/srv/share\", \"/var/log\"]\n\n\
             [[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"file.write\"]\n\n\
             [[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"exec.run\"]\n"
        ),
    );
    let (code, out) = host.json(&["acl", "show", "--principal", CLIENT_PRINCIPAL, "--json"]);
    assert_eq!(code, 0, "{out}");
    let rules = &out["data"]["matching_rules"];
    assert_eq!(
        rules[0]["paths"],
        serde_json::json!(["/srv/share", "/var/log"]),
        "{out}"
    );
    assert!(rules[0].get("file_paths_missing").is_none(), "{out}");
    assert!(rules[1].get("paths").is_none(), "{out}");
    assert_eq!(rules[1]["file_paths_missing"], true, "{out}");
    assert!(rules[2].get("paths").is_none(), "{out}");
    assert!(rules[2].get("file_paths_missing").is_none(), "{out}");

    let output = host.qsh(&["acl", "show", "--principal", CLIENT_PRINCIPAL]);
    assert_eq!(common::exit_code(&output), 0);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("paths: /srv/share, /var/log"), "{stdout}");
    assert_eq!(
        stdout
            .matches("grants no file access: the row has no paths")
            .count(),
        1,
        "{stdout}"
    );
}
