//! `qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS` bidirectional completeness
//! gate (`PLAN.md` M7 Step 1 검증 라운드 판정 P2-2, `docs/design/testing.md`
//! L6).
//!
//! `crates/qsh-proto/src/schema.rs`'s own `every_registered_command_has_a_schema`
//! only proves the *const → match arm* direction: every name in
//! `CLI_V1_SCHEMA_COMMANDS` has a `cli_v1_data_schema` arm. It says nothing
//! about the other direction — a real, implemented operation whose name was
//! never added to `CLI_V1_SCHEMA_COMMANDS` is invisible to that test, so
//! `qsh schema --json` silently omits it and nothing fails
//! (mutation-demonstrated: removing a row from `CLI_V1_SCHEMA_COMMANDS`
//! passes every existing test in the crate). Concretely, this is the gap
//! `PLAN.md` M7 Step 6 will walk into: the day `doctor.run` gets a real
//! `Operation` impl, forgetting to also add `"doctor.run"` to
//! `CLI_V1_SCHEMA_COMMANDS` has no test that catches it — until this file.
//!
//! **Why a source scan instead of reusing `qsh_core::acl::OP_REGISTRY`**
//! (`PLAN.md` M5 Step 8's own bidirectional set-equality precedent,
//! `crates/qsh-core/tests/acl_registry.rs`): `OP_REGISTRY` enumerates only
//! operations that need *authorization* (13 rows) — it deliberately
//! excludes every local-only operation (`version.get`, `schema.get`,
//! `capabilities.get`, `identity.init`, `trust.*`, `host.list`, `host.get`,
//! `acl.check`, `docs/CLI.md` §2.5's own "인가 불요" row), which is most of
//! what `CLI_V1_SCHEMA_COMMANDS` actually lists. It is the wrong universe
//! for this gate.
//!
//! The universe this file *does* use is every `impl Operation for` block
//! under `crates/qsh-core/src/ops/` (`qsh_core::ops::Operation`'s own
//! `COMMAND` associated const, `docs/CLI.md` §2.4's own dotted-name
//! source) — a plain text scan (the `acl_registry.rs`
//! `mod source_scan` precedent, CRLF-normalized the same way that file's
//! `server_mod_production_source` is, for the same Windows-checkout
//! reason) rather than a second hand-maintained Rust-level list, so this
//! file cannot itself drift from the operations that actually exist.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// `crates/qsh-core/src/ops/`.
fn ops_dir() -> PathBuf {
    repo_root()
        .join("crates")
        .join("qsh-core")
        .join("src")
        .join("ops")
}

/// Every `.rs` file directly under `dir`, sorted for deterministic
/// diagnostics — no recursion needed today (`ops/` is a flat module), but
/// this still walks one level of subdirectory so a future `ops/<mod>/`
/// split does not silently drop out of the scan.
fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = std::fs::read_dir(&current)
            .unwrap_or_else(|e| panic!("listing {}: {e}", current.display()));
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Every `const COMMAND: &'static str = "<dotted.name>";` value in `text`,
/// outside comments. The `Operation` trait's own declaration
/// (`const COMMAND: &'static str;`, no `= "..."`) never matches — it has
/// no `= "` at all — so scanning for the marker is unambiguous with no
/// need to first locate `impl Operation for` blocks.
fn command_consts(text: &str) -> Vec<String> {
    const MARKER: &str = "const COMMAND: &'static str = \"";
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .filter_map(|line| {
            let after = line.find(MARKER).map(|i| &line[i + MARKER.len()..])?;
            let end = after.find('"')?;
            Some(after[..end].to_string())
        })
        .collect()
}

/// Every dotted operation name with a real `Operation` impl under
/// `crates/qsh-core/src/ops/` — the universe this gate checks
/// `CLI_V1_SCHEMA_COMMANDS` against.
fn implemented_operations() -> HashSet<String> {
    let mut seen = HashSet::new();
    for path in rust_files_under(&ops_dir()) {
        // CRLF-normalized (`acl_registry.rs`'s `server_mod_production_source`
        // precedent): irrelevant to this scan's line-based matching in
        // practice (`str::lines()` already treats `\r\n` as one
        // terminator), kept for the same "make the on-disk line ending
        // provably irrelevant, not merely believed irrelevant" discipline.
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
            .replace("\r\n", "\n");
        for command in command_consts(&text) {
            assert!(
                seen.insert(command.clone()),
                "{command:?} has more than one `const COMMAND` definition under ops/ \
                 (last seen in {})",
                path.display()
            );
        }
    }
    seen
}

/// Dotted operation names with a real `Operation` impl but deliberately no
/// `qsh schema --json` entry, each with its reason. Symmetric with
/// `qsh-cli/tests/fixtures.rs`'s `DEFERRED` (`ErrorCode` coverage) and
/// `crates/qsh-core/src/acl/registry.rs`'s exclusion lists: an exclusion
/// is a documented decision, not a silent gap.
const EXCLUDED: &[(&str, &str)] = &[(
    "session.attach",
    "stream op — no data envelope to generate a schema for \
     (`docs/CLI.md` §2.4: \"session.attach는 value operation이 아니라 stream \
     operation이다\"; `SchemaData`/`qsh schema --json` only ever describes \
     value-op `data` payloads)",
)];

/// The bidirectional L6 gate: every implemented operation is named by
/// exactly one of `CLI_V1_SCHEMA_COMMANDS` or `EXCLUDED`, and the two
/// never overlap. A row present on neither side (an implemented op with
/// no schema and no documented reason) fails, a row present on both
/// (registered *and* excluded) fails, and a name in `EXCLUDED` that no
/// longer has an `Operation` impl fails too — `EXCLUDED` cannot go stale
/// silently either.
#[test]
fn every_implemented_operation_has_a_schema_or_a_documented_exclusion() {
    let implemented = implemented_operations();
    assert!(
        implemented.len() >= 20,
        "implemented_operations() found suspiciously few operations ({}) — the source \
         scan likely broke: {implemented:?}",
        implemented.len()
    );

    let schema_commands: HashSet<String> = qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let excluded: HashSet<String> = EXCLUDED.iter().map(|(op, _)| op.to_string()).collect();

    let overlap: Vec<&String> = schema_commands.intersection(&excluded).collect();
    assert!(
        overlap.is_empty(),
        "these commands are both registered in CLI_V1_SCHEMA_COMMANDS and listed in \
         EXCLUDED — a command cannot be both served and deliberately unserved: {overlap:?}"
    );

    let mut covered: HashSet<String> = schema_commands.clone();
    covered.extend(excluded.iter().cloned());

    let unaccounted: Vec<&String> = implemented.difference(&covered).collect();
    assert!(
        unaccounted.is_empty(),
        "these operations have a real Operation impl under crates/qsh-core/src/ops/ but \
         are neither in qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS nor in this file's \
         EXCLUDED list — qsh schema --json silently omits them: {unaccounted:?}"
    );

    let stale_registrations: Vec<&String> = schema_commands.difference(&implemented).collect();
    assert!(
        stale_registrations.is_empty(),
        "CLI_V1_SCHEMA_COMMANDS names these commands, but no Operation impl under \
         crates/qsh-core/src/ops/ defines a matching const COMMAND — a schema with no \
         implementation behind it (or a scan/naming drift): {stale_registrations:?}"
    );

    let stale_exclusions: Vec<&String> = excluded.difference(&implemented).collect();
    assert!(
        stale_exclusions.is_empty(),
        "EXCLUDED names these commands, but no Operation impl under \
         crates/qsh-core/src/ops/ defines a matching const COMMAND anymore — remove the \
         stale exclusion: {stale_exclusions:?}"
    );
}

#[cfg(test)]
mod source_scan_unit {
    use super::command_consts;

    #[test]
    fn extracts_the_command_literal_and_skips_the_trait_declaration() {
        let source = "pub trait Operation {\n    const COMMAND: &'static str;\n}\n\nimpl Operation for VersionOp {\n    const COMMAND: &'static str = \"version.get\";\n}\n";
        assert_eq!(command_consts(source), vec!["version.get".to_string()]);
    }

    #[test]
    fn ignores_a_commented_out_definition() {
        let source = "    // const COMMAND: &'static str = \"not.real\";\n    const COMMAND: &'static str = \"real.op\";\n";
        assert_eq!(command_consts(source), vec!["real.op".to_string()]);
    }
}
