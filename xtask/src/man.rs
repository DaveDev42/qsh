//! `cargo xtask man`: regenerate the checked-in man pages under
//! `docs/man/` from this build's real `qsh` `clap::Command` tree
//! (`qsh_cli::cli::Cli`) — see `crates/qsh-cli/src/lib.rs`'s own doc for
//! why that crate exposes a library target at all, and why depending on
//! it from here does not widen `arch.rs`'s dependency matrix.
//!
//! **One page per node, not one page for the whole tree.** `Cli`'s
//! `Command` enum has ~25 leaves and several of those (`trust`, `cert`,
//! `tunnel`, `session`, `acl`, `host`) are themselves `#[command(subcommand)]`
//! enums — a single `qsh.1` flattening all of it would itself become a
//! second, hand-scale copy of `docs/CLI.md`'s command table, the exact
//! duplication man-page generation exists to avoid. `clap_mangen::generate_to`
//! already renders one page per `Command` node, recursively, named by its
//! clap-computed display name (`qsh-trust-add.1`, and so on) — the
//! standard shape `cargo`/`git`'s own man pages use for the same reason.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::CommandFactory;

/// `docs/man/`, workspace-relative.
fn man_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join("docs").join("man")
}

/// Every `*.1` filename directly under `dir` (non-recursive — `docs/man/`
/// is flat).
fn existing_man_pages(dir: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|ext| ext == "1") {
            names.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(names)
}

/// Render every man page (root command + every subcommand, recursively)
/// into `out_dir` — must already exist and, for a clean result, be empty
/// of stale `*.1` files first (`generate_to` only ever writes, never
/// deletes). Returns the set of filenames written.
fn render_into(out_dir: &Path) -> Result<BTreeSet<String>> {
    let cmd = qsh_cli::cli::Cli::command();
    clap_mangen::generate_to(cmd, out_dir)
        .with_context(|| format!("generating man pages into {}", out_dir.display()))?;
    existing_man_pages(out_dir)
}

/// `cargo xtask man`: regenerate `docs/man/` in place. Deletes every
/// checked-in `*.1` page first, so a subcommand rename or removal doesn't
/// leave an orphaned page behind — `docs/man/` holds nothing but generated
/// output, so wiping it clean before regenerating is safe.
pub fn run(workspace_root: &Path) -> Result<()> {
    let dir = man_dir(workspace_root);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    for stale in existing_man_pages(&dir)? {
        fs::remove_file(dir.join(&stale))
            .with_context(|| format!("removing stale {}", dir.join(&stale).display()))?;
    }
    let written = render_into(&dir)?;
    println!("wrote {} man page(s) to {}", written.len(), dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has a parent directory")
            .to_path_buf()
    }

    /// The `docs/CLI.md`-style anti-drift gate for the man pages: whatever
    /// `cargo xtask man` would produce right now must be exactly what is
    /// checked into `docs/man/`, filename set and byte content both. A
    /// clap `about`/`long_about` edit, or a subcommand added, renamed, or
    /// removed, without re-running `cargo xtask man` fails here — the
    /// same "regenerate and commit the diff" discipline
    /// `crates/qsh-cli/tests/fixtures.rs`'s `QSH_UPDATE_FIXTURES` flow
    /// uses for golden JSON fixtures.
    #[test]
    fn checked_in_man_pages_match_the_generator() {
        let root = workspace_root();
        let checked_in_dir = man_dir(&root);
        let checked_in = existing_man_pages(&checked_in_dir).unwrap_or_else(|err| {
            panic!(
                "reading {}: {err} — run `cargo xtask man` and commit its output first",
                checked_in_dir.display()
            )
        });

        let tmp = tempfile::tempdir().expect("temp dir for a fresh render");
        let fresh = render_into(tmp.path()).expect("render the current Command tree");

        assert_eq!(
            checked_in, fresh,
            "docs/man/ does not have the same *.1 file set `cargo xtask man` produces \
             right now — a subcommand was added, removed, or renamed without \
             regenerating. Run `cargo xtask man` and commit the diff."
        );

        for name in &fresh {
            let checked_in_bytes = fs::read(checked_in_dir.join(name))
                .unwrap_or_else(|err| panic!("reading docs/man/{name}: {err}"));
            let fresh_bytes = fs::read(tmp.path().join(name))
                .unwrap_or_else(|err| panic!("reading generated {name}: {err}"));
            assert_eq!(
                checked_in_bytes, fresh_bytes,
                "docs/man/{name} is stale — its content no longer matches what \
                 `cargo xtask man` generates right now. Run it and commit the diff."
            );
        }
    }
}
