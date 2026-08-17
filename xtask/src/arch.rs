//! `cargo xtask arch`: enforce the workspace-crate dependency direction
//! documented in the project architecture (`qsh(bin) → qsh-core →
//! qsh-transport → qsh-proto`, with `qsh-cli` allowed to reach `qsh-proto`
//! directly for contract types). This is a static manifest check, not a
//! symbol-level check: it reads each crate's `[dependencies]` table and
//! flags any dependency on another workspace crate that isn't allowed.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

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

    if violations.is_empty() {
        Ok(())
    } else {
        bail!("architecture violations:\n  {}", violations.join("\n  "));
    }
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
