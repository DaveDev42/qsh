//! Derives `QSH_BUILD_COMMIT` for `cargo install --git` builds so
//! `qsh version` reports `build.commit` (`docs/CLI.md` §6.10).
//!
//! CI injects `QSH_BUILD_COMMIT` itself and that value wins untouched. A
//! developer working tree emits nothing (no commit, no rebuild churn). Only a
//! cargo git checkout (the workspace root holds both `.cargo-ok`, which cargo
//! writes into checkouts, and `.git`) is asked for `git rev-parse HEAD`. Any
//! failure emits nothing.

use std::path::Path;
use std::process::Command;

/// A full lowercase-or-uppercase hex SHA-1 (40 chars), nothing else.
fn is_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=QSH_BUILD_COMMIT");
    if std::env::var_os("QSH_BUILD_COMMIT").is_some() {
        return;
    }
    let Some(manifest_dir) = std::env::var_os("CARGO_MANIFEST_DIR") else {
        return;
    };
    let root = Path::new(&manifest_dir).join("../..");
    if !root.join(".cargo-ok").is_file() || !root.join(".git").exists() {
        return;
    }
    let Ok(out) = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&root)
        .output()
    else {
        return;
    };
    if !out.status.success() {
        return;
    }
    let Ok(text) = String::from_utf8(out.stdout) else {
        return;
    };
    let sha = text.trim();
    if is_sha(sha) {
        println!("cargo:rustc-env=QSH_BUILD_COMMIT={sha}");
    }
}
