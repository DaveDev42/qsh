//! `cargo xtask arch`: enforce the workspace-crate dependency direction
//! documented in the project architecture (`qsh(bin) → qsh-core →
//! qsh-transport → qsh-proto`, with `qsh-cli` allowed to reach `qsh-proto`
//! directly for contract types). This is primarily a static manifest check:
//! it reads each crate's `[dependencies]` table and flags any dependency on
//! another workspace crate that isn't allowed.
//!
//! It also enforces **module-path import bans** the manifest matrix cannot
//! express, because they live *inside* a crate. The session broker sits
//! behind the `SessionBackend` seam (ADR-0003) and must not name a
//! `qsh_transport` type so a future out-of-process supervisor can implement
//! the same trait across a process boundary; `qsh-core` as a whole is
//! allowed to depend on `qsh-transport`, so only a source-level check under
//! `crates/qsh-core/src/broker/` can catch a regression (architecture.md
//! §9-2 named this an "arch-lint 확장 후보").

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// One crate's allowed set of workspace-crate dependencies.
struct Rule {
    /// `None` means "unrestricted" (currently only `qsh-testkit`).
    allowed: Option<BTreeSet<&'static str>>,
}

fn matrix() -> Vec<(&'static str, Rule)> {
    vec![
        (
            "qsh-proto",
            Rule {
                allowed: Some(BTreeSet::new()),
            },
        ),
        (
            "qsh-transport",
            Rule {
                allowed: Some(BTreeSet::from(["qsh-proto"])),
            },
        ),
        (
            "qsh-core",
            Rule {
                allowed: Some(BTreeSet::from(["qsh-proto", "qsh-transport"])),
            },
        ),
        (
            "qsh-cli",
            Rule {
                allowed: Some(BTreeSet::from(["qsh-core", "qsh-proto"])),
            },
        ),
        ("qsh-testkit", Rule { allowed: None }),
    ]
}

/// Run the arch-lint check against `workspace_root/crates/*/Cargo.toml`.
///
/// Returns `Err` (with every violation listed in the message) if any crate
/// declares a workspace-crate dependency outside its allowed set, or if a
/// crate under `crates/` isn't in the matrix at all.
pub fn run(workspace_root: &Path) -> Result<()> {
    let crates_dir = workspace_root.join("crates");
    let matrix = matrix();

    let mut entries: Vec<_> = fs::read_dir(&crates_dir)
        .with_context(|| format!("reading {}", crates_dir.display()))?
        .collect::<Result<Vec<_>, std::io::Error>>()
        .with_context(|| format!("listing {}", crates_dir.display()))?;
    entries.sort_by_key(|e| e.file_name());

    let mut violations = Vec::new();

    for entry in entries {
        let manifest_path = entry.path().join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let (name, deps) = read_manifest(&manifest_path)?;

        let Some((_, rule)) = matrix.iter().find(|(n, _)| *n == name) else {
            violations.push(format!(
                "{name}: not present in xtask's arch matrix (xtask/src/arch.rs) — add a rule for it"
            ));
            continue;
        };

        let Some(allowed) = &rule.allowed else {
            continue; // unrestricted
        };

        for dep in &deps {
            if !allowed.contains(dep.as_str()) {
                let allowed_desc = if allowed.is_empty() {
                    "none".to_string()
                } else {
                    allowed.iter().copied().collect::<Vec<_>>().join(", ")
                };
                violations.push(format!(
                    "{name} depends on {dep}, which is not allowed (allowed: {allowed_desc})"
                ));
            }
        }
    }

    check_module_bans(workspace_root, &mut violations)?;

    if violations.is_empty() {
        Ok(())
    } else {
        bail!("architecture violations:\n  {}", violations.join("\n  "));
    }
}

/// Where a [`ModuleBan`] applies.
enum Scope {
    /// Every `.rs` file under this workspace-relative directory, recursively.
    Dir(&'static str),
    /// Exactly this one workspace-relative file — not its whole directory,
    /// so a sibling file in the same module (e.g. the transport bridge) can
    /// stay exempt.
    File(&'static str),
}

impl Scope {
    /// The workspace-relative path string, for lookup/dedup keys.
    fn path(&self) -> &'static str {
        match self {
            Scope::Dir(p) | Scope::File(p) => p,
        }
    }
}

/// A ban on naming `forbidden` anywhere within `scope` (relative to the
/// workspace root). Enforced at source granularity, unlike the manifest
/// matrix.
struct ModuleBan {
    /// Where the ban applies: a whole directory (recursively) or one file.
    scope: Scope,
    /// The token (a crate name in Rust path form, or a `crate::` path) that
    /// must not appear in any in-scope `.rs` file, comments excluded.
    forbidden: &'static str,
    /// Why, for the failure message.
    reason: &'static str,
}

/// The broker must not name a transport type — directly, through the
/// crates behind `qsh_transport`, or through `qsh-core`'s own crate-root
/// re-exports of transport types (`crate::Principal` / `crate::Fingerprint`)
/// and the connection-level `crate::client` module. Note the lint is
/// directory-scoped: transport-free code that lives elsewhere and is merely
/// used by the broker is not checked here (keep PTY/source code that the
/// broker consumes under `broker/` or equally transport-free).
const BROKER_DIR: &str = "crates/qsh-core/src/broker";
const BROKER_REASON: &str = "the SessionBackend seam must not name a transport type (ADR-0003); \
     keep the broker transport-free so a supervisor can implement it over IPC";

/// The six-token set PLAN.md M3 Step 5(a) reuses verbatim from `BROKER_DIR`
/// for `localctl`'s other transport-free surfaces.
const BROKER_TOKEN_SET: [&str; 6] = [
    "qsh_transport",
    "quinn",
    "rustls",
    "crate::Principal",
    "crate::Fingerprint",
    "crate::client",
];

/// `localctl/client.rs` (CLI-process side) is pure UDS + `qsh-proto`
/// framing and must never reach for a transport type; `localctl/frame.rs`
/// is the shared conduit codec underneath it and is bound by the same rule.
/// `localctl/daemon.rs` is the bridge to QUIC and is deliberately *not*
/// listed here — file scope, not the directory, is what lets it stay
/// exempt (PLAN.md M3 Step 5(a)).
const LOCALCTL_FRAME_FILE: &str = "crates/qsh-core/src/localctl/frame.rs";
const LOCALCTL_CLIENT_FILE: &str = "crates/qsh-core/src/localctl/client.rs";
const LOCALCTL_TRANSPORT_REASON: &str = "localctl/{frame,client}.rs are pure UDS + qsh-proto framing on the CLI-process side; \
     localctl/daemon.rs is the transport bridge and is deliberately exempt (PLAN.md M3 Step 5(a))";

/// `reverse/registry.rs` holds `ReverseEntry` metadata only (Step 3 already
/// narrowed it — the live `client::Session` stays in `reverse/listen.rs`),
/// so it can carry the same six-token ban as the broker: `crate::client`
/// staying clean here is the mechanical proof that a `ReverseEntry` never
/// holds a live session.
const REGISTRY_FILE: &str = "crates/qsh-core/src/reverse/registry.rs";
const REGISTRY_REASON: &str = "reverse/registry.rs is metadata-only (Step 3); it must not hold a live client::Session or \
     name a transport type — same token set as BROKER_DIR (PLAN.md M3 Step 5(a))";

/// `qsh-cli/src` never opens a UDS socket directly — it goes through
/// `qsh-core`'s `localctl::client`. Scope is `src/` only, not the crate
/// root: `crates/qsh-cli/tests/localctl_perms.rs` pokes UDS permissions
/// directly and legitimately needs `UnixStream` (PLAN.md M3 Step 5(a)).
const CLI_SRC_DIR: &str = "crates/qsh-cli/src";
const CLI_SRC_REASON: &str = "qsh-cli talks to a daemon only through qsh-core's localctl client, never by opening a UDS \
     socket itself (PLAN.md M3 Step 5(a)); crates/qsh-cli/tests is out of scope for this rule";

/// The MCP adapter (`docs/CLI.md` §8.2's own prose: "MCP adapter가 command
/// string을 만들거나 CLI output을 다시 parse해서는 안 된다. 두 adapter
/// 모두 같은 Rust operation layer를 직접 호출한다.", `PLAN.md` M6 DoD 4)
/// must call `Ops` in-process, never shell out to the `qsh` binary and
/// re-parse its output. Three literal surfaces are banned: the
/// subprocess-spawning module (`std::process`, so a `use std::process::…`
/// import is caught at the import line even before any call site);
/// the constructor call site (`Command::new`, which — being a bare type
/// name, not a full path — catches `tokio::process::Command::new` the
/// same way it catches `std::process::Command::new`, so switching to the
/// async twin does not evade this); and the API a spawned child's stdout
/// has to go through before its text could be re-parsed (`Stdio::piped`,
/// shared by both `std::process::Stdio` and `tokio::process::Stdio`).
/// Scope is the whole `mcp/` directory, tests inline in it (`#[cfg(test)]`
/// modules) included — unlike `CLI_SRC_DIR`, there is no sibling
/// `crates/qsh-cli/tests/mcp_conformance.rs`-style carve-out needed here
/// because that conformance harness lives under `crates/qsh-cli/tests/`,
/// outside this directory entirely, and *is* allowed a real
/// `std::process::Command` (`PLAN.md` §4.1 #5 — it spawns the real `qsh
/// mcp` binary to observe the wire, which is a different concern from the
/// adapter shelling out to itself).
const MCP_DIR: &str = "crates/qsh-cli/src/mcp";
const MCP_REASON: &str = "the MCP adapter must call Ops directly, in-process — never shell out to \
     `qsh` and re-parse its CLI output (docs/CLI.md §8.2, PLAN.md M6 DoD 4)";

fn module_bans() -> Vec<ModuleBan> {
    let mut bans: Vec<ModuleBan> = BROKER_TOKEN_SET
        .into_iter()
        .map(|forbidden| ModuleBan {
            scope: Scope::Dir(BROKER_DIR),
            forbidden,
            reason: BROKER_REASON,
        })
        .collect();

    for file in [LOCALCTL_FRAME_FILE, LOCALCTL_CLIENT_FILE] {
        for forbidden in ["qsh_transport", "quinn", "rustls"] {
            bans.push(ModuleBan {
                scope: Scope::File(file),
                forbidden,
                reason: LOCALCTL_TRANSPORT_REASON,
            });
        }
    }

    for forbidden in BROKER_TOKEN_SET {
        bans.push(ModuleBan {
            scope: Scope::File(REGISTRY_FILE),
            forbidden,
            reason: REGISTRY_REASON,
        });
    }

    for forbidden in ["UnixStream", "UnixListener"] {
        bans.push(ModuleBan {
            scope: Scope::Dir(CLI_SRC_DIR),
            forbidden,
            reason: CLI_SRC_REASON,
        });
    }

    for forbidden in ["std::process", "Command::new", "Stdio::piped"] {
        bans.push(ModuleBan {
            scope: Scope::Dir(MCP_DIR),
            forbidden,
            reason: MCP_REASON,
        });
    }

    bans
}

/// Enforce every [`ModuleBan`], appending a violation line per offending
/// occurrence.
fn check_module_bans(workspace_root: &Path, violations: &mut Vec<String>) -> Result<()> {
    let mut reported_missing = std::collections::BTreeSet::new();
    for ban in module_bans() {
        let target = workspace_root.join(ban.scope.path());
        let files: Vec<PathBuf> = match ban.scope {
            Scope::Dir(dir) => {
                if !target.is_dir() {
                    if reported_missing.insert(dir) {
                        // The directory is expected to exist once its
                        // consumer lands; a missing directory is itself a
                        // regression worth flagging.
                        violations.push(format!(
                            "module-ban target {} does not exist (xtask/src/arch.rs)",
                            target.display()
                        ));
                    }
                    continue;
                }
                let mut files = Vec::new();
                collect_rs_files(&target, &mut files)
                    .with_context(|| format!("scanning {}", target.display()))?;
                files.sort();
                files
            }
            Scope::File(file) => {
                if !target.is_file() {
                    if reported_missing.insert(file) {
                        violations.push(format!(
                            "module-ban target {} does not exist (xtask/src/arch.rs)",
                            target.display()
                        ));
                    }
                    continue;
                }
                vec![target.clone()]
            }
        };
        for file in files {
            let text =
                fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            for (lineno, raw) in text.lines().enumerate() {
                let code = strip_line_comment(raw);
                if code.contains(ban.forbidden) {
                    let rel = file.strip_prefix(workspace_root).unwrap_or(&file);
                    violations.push(format!(
                        "{}:{} names `{}` — {}",
                        rel.display(),
                        lineno + 1,
                        ban.forbidden,
                        ban.reason
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Everything before a `//` line comment (doc comments included). Naive but
/// sufficient for this lint: this assumption — no string literal embeds `//`
/// before a banned token, and no block comments (`/* … */`) are used — has
/// been re-verified for every scope this lint currently scans (`BROKER_DIR`,
/// the `localctl` files, `REGISTRY_FILE`, `CLI_SRC_DIR`, and `MCP_DIR`). For
/// `MCP_DIR` specifically: the only banned-token occurrence anywhere under
/// `crates/qsh-cli/src/mcp/` is the `///` line comment at
/// `crates/qsh-cli/src/mcp/mod.rs:805` (`` `std::process::Command` `` in
/// prose) — no block comments and no token-bearing string literals exist in
/// that tree. **Adding a new scanned scope requires re-checking this
/// assumption against that scope's actual source** before trusting this
/// naive strip on it.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// Recursively collect `.rs` files under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Read a crate's `[package].name` and the set of workspace-crate
/// (`qsh-*`) names it lists under `[dependencies]`.
fn read_manifest(path: &Path) -> Result<(String, BTreeSet<String>)> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: toml::Value = text
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;

    let name = value
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .with_context(|| format!("{}: missing [package].name", path.display()))?
        .to_string();

    let mut deps = BTreeSet::new();
    if let Some(table) = value.get("dependencies").and_then(|d| d.as_table()) {
        for key in table.keys() {
            if key.starts_with("qsh-") {
                deps.insert(key.clone());
            }
        }
    }
    Ok((name, deps))
}

#[cfg(test)]
mod tests {
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
    /// `REGISTRY_FILE`, `CLI_SRC_DIR`, and `MCP_DIR`).
    #[test]
    fn module_ban_flags_each_missing_target_exactly_once() {
        let root = tempfile::tempdir().unwrap();
        let mut violations = Vec::new();
        check_module_bans(root.path(), &mut violations).unwrap();
        assert_eq!(violations.len(), 6, "{violations:?}");
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

    /// `crates/qsh-cli/src/mcp` bans `std::process`/`Command::new`/
    /// `Stdio::piped` (M6 DoD 4, `MCP_DIR`) — a synthetic adapter file that
    /// shells out to the `qsh` binary and pipes its stdout for re-parsing
    /// is flagged on all three tokens, each on the line it actually
    /// appears on.
    #[test]
    fn module_ban_flags_a_subprocess_shell_out_under_mcp() {
        let root = tempfile::tempdir().unwrap();
        let mcp = root.path().join("crates/qsh-cli/src/mcp");
        fs::create_dir_all(&mcp).unwrap();
        fs::write(
            mcp.join("evil.rs"),
            "use std::process::{Command, Stdio};\n\
             fn shell_out_and_reparse() {\n    \
             let out = Command::new(\"qsh\").stdout(Stdio::piped()).output().unwrap();\n\
             }\n",
        )
        .unwrap();

        let mut violations = Vec::new();
        check_module_bans(root.path(), &mut violations).unwrap();
        let hits: Vec<_> = violations
            .iter()
            .filter(|v| v.contains("evil.rs"))
            .collect();
        // Line 1 names `std::process` (the `use` path); line 3 names both
        // `Command::new` and `Stdio::piped`.
        assert_eq!(hits.len(), 3, "{violations:?}");
        assert!(
            hits.iter()
                .any(|v| v.contains("evil.rs:1") && v.contains("std::process"))
        );
        assert!(
            hits.iter()
                .any(|v| v.contains("evil.rs:3") && v.contains("Command::new"))
        );
        assert!(
            hits.iter()
                .any(|v| v.contains("evil.rs:3") && v.contains("Stdio::piped"))
        );
    }

    /// Smoke check: a CRLF-line-ended source file (the Windows-checkout
    /// shape `acl_registry.rs`'s `source_scan` module calls out) must still
    /// get its violation caught. This is a demonstration, not a
    /// discriminator — it does **not** pin `text.lines()` as the specific
    /// choice, and it cannot be turned into one. Swapping `text.lines()`
    /// for `text.split('\n')` in `check_module_bans` still passes this
    /// (and every other) xtask test, because the scan matches `ban.forbidden`
    /// as a substring anywhere within a line, and a trailing `\r` only ever
    /// sits at the very end of that line — after the token has already
    /// matched or not — so its presence or absence cannot flip the
    /// `.contains()` result either way. There is no line content this scan
    /// could be given that would tell `lines()` and `split('\n')` apart
    /// here.
    ///
    /// This is why this test needs no separate `.replace("\r\n", "\n")`
    /// step: the M5 precedent in `acl_registry.rs`'s `source_scan` needed
    /// that replace only because *that* scan does a whole-file, multi-line
    /// marker substring search (a match can straddle a line boundary), a
    /// shape where a stray `\r` immediately before the match point could
    /// matter. This scan is strictly per-line and position-independent
    /// within the line, so no such step is needed here — not because
    /// `lines()` was proven necessary, but because the hazard the replace
    /// step guards against does not exist in this scan's shape.
    #[test]
    fn module_ban_catches_a_violation_in_a_crlf_line_ended_file_under_mcp() {
        let root = tempfile::tempdir().unwrap();
        let mcp = root.path().join("crates/qsh-cli/src/mcp");
        fs::create_dir_all(&mcp).unwrap();
        fs::write(
            mcp.join("crlf.rs"),
            "// a comment first\r\nfn f() { let _ = Command::new(\"qsh\"); }\r\n",
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
        assert!(hits[0].contains("Command::new"));
    }

    /// Doc-comment prose that merely *mentions* `std::process::Command` or
    /// `Stdio::piped` — explaining why a *different* file (the conformance
    /// harness under `crates/qsh-cli/tests/`, out of `MCP_DIR`'s scope) is
    /// allowed a real one — must not trip this ban; only real code does
    /// (mirrors `module_ban_ignores_comments`, MCP axis). This is the
    /// actual shape `crates/qsh-cli/src/mcp/mod.rs` carries today, so this
    /// test is also the guarantee that adding the MCP ban did not force an
    /// unwanted comment-wording change there.
    #[test]
    fn module_ban_ignores_comments_mentioning_process_apis_under_mcp() {
        let root = tempfile::tempdir().unwrap();
        let mcp = root.path().join("crates/qsh-cli/src/mcp");
        fs::create_dir_all(&mcp).unwrap();
        fs::write(
            mcp.join("mod.rs"),
            "//! A conformance harness can therefore be a bare\n\
             //! `std::process::Command` with piped stdio (`Stdio::piped`),\n\
             //! writing/reading newline-delimited JSON-RPC directly — nothing\n\
             //! this module itself does; `Command::new` never appears in real\n\
             //! code here.\n\
             pub fn ok() {}\n",
        )
        .unwrap();

        let mut violations = Vec::new();
        check_module_bans(root.path(), &mut violations).unwrap();
        let hits: Vec<_> = violations.iter().filter(|v| v.contains("mod.rs")).collect();
        assert!(hits.is_empty(), "{violations:?}");
    }

    /// The real workspace tree must respect every module ban: the broker,
    /// `localctl/{frame,client}.rs` (with `daemon.rs` exempt),
    /// `reverse/registry.rs`, `qsh-cli/src`, and `qsh-cli/src/mcp`.
    #[test]
    fn real_tree_respects_all_module_bans() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut violations = Vec::new();
        check_module_bans(workspace_root, &mut violations).unwrap();
        assert!(violations.is_empty(), "{violations:?}");
    }
}
