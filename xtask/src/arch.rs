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

/// A ban on naming `forbidden_crate` anywhere under `dir` (relative to the
/// workspace root). Enforced at source granularity, unlike the manifest
/// matrix.
struct ModuleBan {
    /// Directory (workspace-relative) the ban applies to, recursively.
    dir: &'static str,
    /// The crate name (Rust path form, i.e. underscores) that must not
    /// appear in any `.rs` file under `dir`.
    forbidden_crate: &'static str,
    /// Why, for the failure message.
    reason: &'static str,
}

fn module_bans() -> Vec<ModuleBan> {
    vec![ModuleBan {
        dir: "crates/qsh-core/src/broker",
        forbidden_crate: "qsh_transport",
        reason: "the SessionBackend seam must not import qsh_transport (ADR-0003); \
                 keep the broker transport-free so a supervisor can implement it over IPC",
    }]
}

/// Enforce every [`ModuleBan`], appending a violation line per offending
/// occurrence.
fn check_module_bans(workspace_root: &Path, violations: &mut Vec<String>) -> Result<()> {
    for ban in module_bans() {
        let dir = workspace_root.join(ban.dir);
        if !dir.is_dir() {
            // The directory is expected to exist once the broker lands; a
            // missing directory is itself a regression worth flagging.
            violations.push(format!(
                "module-ban target {} does not exist (xtask/src/arch.rs)",
                dir.display()
            ));
            continue;
        }
        let mut files = Vec::new();
        collect_rs_files(&dir, &mut files)
            .with_context(|| format!("scanning {}", dir.display()))?;
        files.sort();
        for file in files {
            let text =
                fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            for (lineno, raw) in text.lines().enumerate() {
                let code = strip_line_comment(raw);
                if code.contains(ban.forbidden_crate) {
                    let rel = file.strip_prefix(workspace_root).unwrap_or(&file);
                    violations.push(format!(
                        "{}:{} names `{}` — {}",
                        rel.display(),
                        lineno + 1,
                        ban.forbidden_crate,
                        ban.reason
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Everything before a `//` line comment (doc comments included). Naive but
/// sufficient for this lint: broker source has no string literal that embeds
/// `//` before a banned token, and block comments are not used there.
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
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("session.rs:1"));
        assert!(violations[0].contains("qsh_transport"));
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
        assert!(violations.is_empty(), "{violations:?}");
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
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("inner.rs"));
    }

    /// A missing broker directory is itself flagged (the ban target must
    /// exist once the broker lands).
    #[test]
    fn module_ban_flags_a_missing_target() {
        let root = tempfile::tempdir().unwrap();
        let mut violations = Vec::new();
        check_module_bans(root.path(), &mut violations).unwrap();
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("does not exist"));
    }

    /// The real workspace broker must be transport-free.
    #[test]
    fn real_broker_is_transport_free() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut violations = Vec::new();
        check_module_bans(workspace_root, &mut violations).unwrap();
        assert!(violations.is_empty(), "{violations:?}");
    }
}
