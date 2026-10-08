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

/// The six-token set reused verbatim from `BROKER_DIR` for `localctl`'s other transport-free surfaces.
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
/// exempt (`docs/design/architecture.md` §1).
const LOCALCTL_FRAME_FILE: &str = "crates/qsh-core/src/localctl/frame.rs";
const LOCALCTL_CLIENT_FILE: &str = "crates/qsh-core/src/localctl/client.rs";
const LOCALCTL_TRANSPORT_REASON: &str = "localctl/{frame,client}.rs are pure UDS + qsh-proto framing on the CLI-process side; \
     localctl/daemon.rs is the transport bridge and is deliberately exempt (docs/design/architecture.md §1)";

/// `reverse/registry.rs` holds `ReverseEntry` metadata only (already narrowed — the live `client::Session` stays in `reverse/listen.rs`),
/// so it can carry the same six-token ban as the broker: `crate::client`
/// staying clean here is the mechanical proof that a `ReverseEntry` never
/// holds a live session.
const REGISTRY_FILE: &str = "crates/qsh-core/src/reverse/registry.rs";
const REGISTRY_REASON: &str = "reverse/registry.rs is metadata-only; it must not hold a live client::Session or \
     name a transport type — same token set as BROKER_DIR (docs/design/architecture.md §1)";

/// `qsh-cli/src` never opens a UDS socket directly — it goes through
/// `qsh-core`'s `localctl::client`. Scope is `src/` only, not the crate
/// root: `crates/qsh-cli/tests/localctl_perms.rs` pokes UDS permissions
/// directly and legitimately needs `UnixStream` (`docs/design/architecture.md` §1).
const CLI_SRC_DIR: &str = "crates/qsh-cli/src";
const CLI_SRC_REASON: &str = "qsh-cli talks to a daemon only through qsh-core's localctl client, never by opening a UDS \
     socket itself (docs/design/architecture.md §1); crates/qsh-cli/tests is out of scope for this rule";

/// `trust/invite_address/route.rs` (and any future sibling under the same
/// directory) asks the kernel which source address a route off this host
/// would use and must never transmit: zero bytes on the wire is the
/// premise the whole candidate block rests on (`docs/design/
/// threat-model.md` §3's `qsh trust invite` row), and it is also what
/// makes the call bounded — `connect(2)` on a datagram socket resolves a
/// route synchronously, while a transmit or receive call would introduce
/// the one wait an interactive command must not have. Directory-scoped,
/// not file-scoped: a file-scoped ban on `route.rs` alone would not cover
/// a later sibling added to this module (adversarial review).
const INVITE_ADDRESS_DIR: &str = "crates/qsh-core/src/trust/invite_address";
const INVITE_ROUTE_REASON: &str = "crates/qsh-core/src/trust/invite_address/ performs a connect-only route lookup and \
     must never transmit or wait: zero bytes on the wire is what keeps `qsh trust invite` from becoming an \
     active probe, and what keeps an interactive command from blocking (docs/design/threat-model.md §3)";

/// `trust::invite_address::InviteAddressAdvice` must stay structurally
/// incapable of reaching the `qsh.cli/v1` envelope: no serde derive, no
/// hand-written impl, no schema. `qsh-cli`'s `finish` is bound on
/// `Serialize`, so with no such impl anywhere in this module the type
/// cannot be serialized into an envelope even by accident. Two scopes,
/// not one: `Scope::Dir(INVITE_ADDRESS_DIR)` covers `route.rs` and any
/// future sibling, but not the parent `invite_address.rs` file itself
/// (a directory scope never reaches its own parent), so a
/// `Scope::File(INVITE_ADDRESS_FILE)` entry stays alongside it — trait
/// coherence lets an `impl Serialize` for a `qsh-core` type live in any
/// file of the crate, not only the one that declares the type
/// (adversarial review).
const INVITE_ADDRESS_FILE: &str = "crates/qsh-core/src/trust/invite_address.rs";
const INVITE_ADDRESS_REASON: &str = "trust/invite_address holds a human-channel-only type; this module must not itself \
     name serde or a schema derive for it — trait coherence still lets an impl live in another qsh-core file, so this \
     ban is one input to keeping the type out of a qsh.cli/v1 envelope, not a crate-wide guarantee by itself \
     (docs/CLI.md §10 compatibility policy)";

/// `qsh setup`'s planning module writes nothing and dials nothing of its
/// own (ADR-0024 결정 3). Its only writes are the ones the existing `Ops`
/// methods it calls already perform, so it must not name `acl.toml`'s path,
/// any file-writing primitive, the trust store's `save`, or the fingerprint
/// probe that would turn `trust.add` into trust-on-first-use. Directory-
/// scoped so a sibling added later is covered too; the `tests.rs` files
/// under it are scanned as well, so they build fixtures through helpers
/// that live outside this directory.
const SETUP_DIR: &str = "crates/qsh-core/src/setup";
const SETUP_REASON: &str = "crates/qsh-core/src/setup/ orchestrates existing ops and never writes acl.toml, config.toml \
     or hosts.toml, nor probes a peer for a fingerprint to pin (ADR-0024 결정 3, 6); its only writes are the ones the \
     Ops methods it calls already perform";
const SETUP_TOKEN_SET: [&str; 8] = [
    "acl_file",
    "fs::write",
    "File::create",
    "OpenOptions",
    "write_private_file",
    "write_atomically",
    ".save(",
    "probe_fingerprint",
];

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

    for forbidden in [".send", ".recv"] {
        bans.push(ModuleBan {
            scope: Scope::Dir(INVITE_ADDRESS_DIR),
            forbidden,
            reason: INVITE_ROUTE_REASON,
        });
    }

    for forbidden in SETUP_TOKEN_SET {
        bans.push(ModuleBan {
            scope: Scope::Dir(SETUP_DIR),
            forbidden,
            reason: SETUP_REASON,
        });
    }

    for forbidden in ["Serialize", "serde", "JsonSchema"] {
        bans.push(ModuleBan {
            scope: Scope::File(INVITE_ADDRESS_FILE),
            forbidden,
            reason: INVITE_ADDRESS_REASON,
        });
        bans.push(ModuleBan {
            scope: Scope::Dir(INVITE_ADDRESS_DIR),
            forbidden,
            reason: INVITE_ADDRESS_REASON,
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
                        repo_relative_display(rel),
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

/// A repo-relative path spelled with `/` on every platform.
///
/// `Path::display` uses the host separator, so a directory-scoped ban on
/// Windows renders `trust/invite_address\route.rs` — a mixed spelling,
/// because the scope constant's own slashes survive `Path::join` while
/// [`collect_rs_files`] appends each entry with the native one. A violation
/// string is a repo-relative path a person pastes into an editor or a grep,
/// so it must read the same everywhere. Built from `components()` rather
/// than a `\` → `/` replacement: a backslash is a legal filename byte on
/// Unix, and replacing it there would rewrite a real file name.
fn repo_relative_display(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Everything before a `//` line comment (doc comments included). Naive but
/// sufficient for this lint: this assumption — no string literal embeds `//`
/// before a banned token, and no block comments (`/* … */`) are used — has
/// been re-verified for every scope this lint currently scans (`BROKER_DIR`,
/// the `localctl` files, `REGISTRY_FILE`, `CLI_SRC_DIR`, `INVITE_ADDRESS_DIR`,
/// `INVITE_ADDRESS_FILE` and `SETUP_DIR`). **Adding a new scanned scope requires
/// re-checking this assumption against that scope's actual source** before
/// trusting this naive strip on it.
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
    let value = text
        .parse::<toml::Table>()
        .map(toml::Value::Table)
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
mod tests;
