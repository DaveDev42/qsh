//! Op registration completeness (`docs/ROADMAP.md` M9 (c)/(e) DoD 5,
//! ADR-0013) — the `crates/qsh-core/tests/acl_registry.rs` /
//! `schema_commands_registry.rs` precedent applied to a new axis neither
//! of those files walks: `docs/CLI.md` §2.4's dotted-name fence itself,
//! and the full set of faces a *served* operation (one in
//! `qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS`) is supposed to show up on
//! — schema, dispatch, renderer, docs, man page.
//!
//! Three layers:
//!
//! 1. [`layer_1_cli_md_fence`]: bidirectional set equality between §2.4's
//!    fenced list and every real `impl Operation for` block under
//!    `crates/qsh-core/src/ops/` — nothing parses §2.4 today, so a name
//!    added to one side and not the other has no test catching it.
//! 2. [`layer_2_six_faces`]: an explicit `(op, marker, man file, CLI
//!    spelling, renderer)` table covering every `CLI_V1_SCHEMA_COMMANDS`
//!    entry, gated for totality both ways, then five per-op faces
//!    checked against the live sources.
//! 3. [`layer_3_acl_registry_exclusions`]... lives in `acl_registry.rs`
//!    itself (the `trust.*` expansion fix) — that edit stays in the file
//!    that already owns the `no_authz_ops`/`excluded` logic rather than
//!    forking a second copy of it here.
//!
//! **Why a source scan instead of reusing `qsh_core::acl::OP_REGISTRY`**:
//! same reasoning as `schema_commands_registry.rs`'s own module doc —
//! `OP_REGISTRY` only enumerates operations that need authorization, and
//! most of what this file checks (`identity.export`, `trust.add_ca`,
//! every local-only op) is deliberately outside that set.
//!
//! **Deliberate scope reduction from the brief's "docs/CLI.md §6.11 row"
//! face**: §6.11 (and the sibling sections other ops document under,
//! §6.1–§6.17) is prose with fenced `bash`/`json` examples, not a literal
//! Markdown table with one row per op — there is no single parseable
//! "row" to key off mechanically the way §2.5's table has. This file
//! checks instead that each op's canonical CLI spelling (e.g. `qsh trust
//! add-ca`) appears **somewhere** in `docs/CLI.md`, which still catches
//! the named mutation (deleting the doc paragraph that mentions a new
//! command) without a bespoke per-section prose parser.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[path = "support/docs.rs"]
mod docs;
use docs::{read_doc, repo_root};

// ---------------------------------------------------------------------
// Shared source-scan primitives, duplicated from
// `schema_commands_registry.rs` rather than imported (do not make that
// file a module of this one) — that file's own
// `every_implemented_operation_has_a_schema_or_a_documented_exclusion`
// already gates the const/arm faces this file must not re-litigate; only
// `implemented_operations()` itself is needed again here, as the
// universe both new layers check against.
// ---------------------------------------------------------------------

/// `crates/qsh-core/src/ops/`.
fn ops_dir() -> PathBuf {
    repo_root()
        .join("crates")
        .join("qsh-core")
        .join("src")
        .join("ops")
}

/// Every `.rs` file directly under `dir`, recursing one level so an
/// `ops/<mod>/` split (like `ops/session/attach.rs`) is not silently
/// dropped from the scan.
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

/// Every `const COMMAND: &'static str = "<dotted.name>";` value in
/// `text`, outside comments. The `Operation` trait's own declaration
/// (`const COMMAND: &'static str;`, no `= "..."`) never matches.
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
/// `crates/qsh-core/src/ops/`.
fn implemented_operations() -> HashSet<String> {
    let mut seen = HashSet::new();
    for path in rust_files_under(&ops_dir()) {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
            .replace("\r\n", "\n");
        for command in command_consts(&text) {
            seen.insert(command);
        }
    }
    seen
}

// ---------------------------------------------------------------------
// Layer 1 — the §2.4 fence, genuinely new: nothing parses it today
// (only §2.5's table is parsed, by `acl_registry.rs`).
// ---------------------------------------------------------------------

/// `docs/CLI.md` §2.4's fenced `text` block, one dotted name per line.
fn cli_md_section_2_4_fence(cli_md: &str) -> HashSet<String> {
    let heading = "### 2.4 Operation 이름";
    let start = cli_md
        .find(heading)
        .unwrap_or_else(|| panic!("docs/CLI.md must have a {heading:?} heading"));
    let after_heading = &cli_md[start..];
    let fence_open = after_heading
        .find("```text\n")
        .expect("§2.4 must open a ```text fence");
    let body_start = fence_open + "```text\n".len();
    let body_end = after_heading[body_start..]
        .find("```")
        .map(|i| body_start + i)
        .expect("§2.4's ```text fence must close");
    after_heading[body_start..body_end]
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

#[test]
fn section_2_4_fence_matches_every_implemented_operation_bidirectionally() {
    let cli_md = read_doc("docs/CLI.md");
    let fence = cli_md_section_2_4_fence(&cli_md);
    let implemented = implemented_operations();

    assert!(
        fence.len() >= 20,
        "docs/CLI.md §2.4's fence parsed suspiciously few operations ({}) — the fence \
         parser likely broke: {fence:?}",
        fence.len()
    );

    let documented_but_not_implemented: Vec<&String> = fence.difference(&implemented).collect();
    assert!(
        documented_but_not_implemented.is_empty(),
        "docs/CLI.md §2.4 names these operations, but no `impl Operation for` block under \
         crates/qsh-core/src/ops/ defines a matching const COMMAND: \
         {documented_but_not_implemented:?}"
    );

    let implemented_but_not_documented: Vec<&String> = implemented.difference(&fence).collect();
    assert!(
        implemented_but_not_documented.is_empty(),
        "these operations have a real `impl Operation for` block under \
         crates/qsh-core/src/ops/, but docs/CLI.md §2.4's fence never names them — a real \
         op with no dotted-name documentation: {implemented_but_not_documented:?}"
    );
}

// ---------------------------------------------------------------------
// Layer 2 — six faces per `CLI_V1_SCHEMA_COMMANDS` entry.
// ---------------------------------------------------------------------

/// One served operation's faces, hand-written because none of them is
/// mechanically derivable from the dotted name alone (`identity.init` →
/// `qsh-init.1`, `host.list` → `qsh-hosts.1`; `capabilities.get` →
/// `CapabilitiesOp`, not `CapabilitiesGetOp`) — the brief's own finding,
/// re-verified against the tree at this commit.
struct OpFace {
    /// Dotted `docs/CLI.md` §2.4 name, matching a
    /// `CLI_V1_SCHEMA_COMMANDS` entry exactly.
    op: &'static str,
    /// The zero-sized `Operation` marker struct's name in `qsh-core`
    /// (`ops/mod.rs`'s or a submodule's `impl Operation for <marker>`).
    marker: &'static str,
    /// `crates/qsh-cli/src/render/human.rs` function `main.rs`'s
    /// dispatch calls for this op's human-mode output.
    renderer: &'static str,
    /// A substring that names this op's CLI invocation, expected to
    /// appear somewhere in `docs/CLI.md` (see this file's module doc for
    /// why "somewhere" rather than a specific section/row).
    cli_spelling: &'static str,
    /// The generated man page under `docs/man/` for this op's CLI
    /// command.
    man_file: &'static str,
}

const OP_FACES: &[OpFace] = &[
    OpFace {
        op: "acl.check",
        marker: "AclCheckOp",
        renderer: "print_acl_check",
        cli_spelling: "qsh acl check",
        man_file: "qsh-acl-check.1",
    },
    OpFace {
        op: "capabilities.get",
        marker: "CapabilitiesOp",
        renderer: "print_capabilities",
        cli_spelling: "qsh capabilities",
        man_file: "qsh-capabilities.1",
    },
    OpFace {
        op: "cert.init",
        marker: "CertInitOp",
        renderer: "print_cert_init",
        cli_spelling: "qsh cert init",
        man_file: "qsh-cert-init.1",
    },
    OpFace {
        op: "cert.issue",
        marker: "CertIssueOp",
        renderer: "print_cert_issue",
        cli_spelling: "qsh cert issue",
        man_file: "qsh-cert-issue.1",
    },
    OpFace {
        op: "doctor.run",
        marker: "DoctorOp",
        renderer: "print_doctor",
        cli_spelling: "qsh doctor",
        man_file: "qsh-doctor.1",
    },
    OpFace {
        op: "exec.run",
        marker: "ExecRunOp",
        renderer: "print_exec",
        cli_spelling: "qsh exec",
        man_file: "qsh-exec.1",
    },
    OpFace {
        op: "host.get",
        marker: "HostGetOp",
        renderer: "print_host",
        cli_spelling: "qsh host get",
        man_file: "qsh-host-get.1",
    },
    OpFace {
        op: "host.list",
        marker: "HostListOp",
        renderer: "print_hosts",
        cli_spelling: "qsh hosts",
        man_file: "qsh-hosts.1",
    },
    OpFace {
        op: "identity.export",
        marker: "IdentityExportOp",
        renderer: "print_identity_export",
        cli_spelling: "qsh identity export",
        man_file: "qsh-identity-export.1",
    },
    OpFace {
        op: "identity.init",
        marker: "IdentityInitOp",
        renderer: "print_init",
        cli_spelling: "qsh init",
        man_file: "qsh-init.1",
    },
    OpFace {
        op: "schema.get",
        marker: "SchemaOp",
        renderer: "print_schema",
        cli_spelling: "qsh schema",
        man_file: "qsh-schema.1",
    },
    OpFace {
        op: "session.close",
        marker: "SessionCloseOp",
        renderer: "print_session_close",
        cli_spelling: "qsh session close",
        man_file: "qsh-session-close.1",
    },
    OpFace {
        op: "session.get",
        marker: "SessionGetOp",
        renderer: "print_session",
        cli_spelling: "qsh session get",
        man_file: "qsh-session-get.1",
    },
    OpFace {
        op: "session.list",
        marker: "SessionListOp",
        renderer: "print_session_list",
        cli_spelling: "qsh sessions",
        man_file: "qsh-sessions.1",
    },
    OpFace {
        op: "session.open",
        marker: "SessionOpenOp",
        renderer: "print_session_open",
        cli_spelling: "qsh session open",
        man_file: "qsh-session-open.1",
    },
    OpFace {
        op: "session.read",
        marker: "SessionReadOp",
        renderer: "print_session_read",
        cli_spelling: "qsh session read",
        man_file: "qsh-session-read.1",
    },
    OpFace {
        op: "session.resize",
        marker: "SessionResizeOp",
        renderer: "print_session_resize",
        cli_spelling: "qsh session resize",
        man_file: "qsh-session-resize.1",
    },
    OpFace {
        op: "session.write",
        marker: "SessionWriteOp",
        renderer: "print_session_write",
        cli_spelling: "qsh session write",
        man_file: "qsh-session-write.1",
    },
    OpFace {
        op: "trust.accept",
        marker: "TrustAcceptOp",
        renderer: "print_trust_accept",
        cli_spelling: "qsh pair accept",
        man_file: "qsh-pair-accept.1",
    },
    OpFace {
        op: "trust.add",
        marker: "TrustAddOp",
        renderer: "print_trust_add",
        cli_spelling: "qsh trust add ",
        man_file: "qsh-trust-add.1",
    },
    OpFace {
        op: "trust.add_ca",
        marker: "TrustAddCaOp",
        renderer: "print_trust_add_ca",
        cli_spelling: "qsh trust add-ca",
        man_file: "qsh-trust-add-ca.1",
    },
    OpFace {
        op: "trust.invite",
        marker: "TrustInviteOp",
        renderer: "print_trust_invite",
        cli_spelling: "qsh pair invite",
        man_file: "qsh-pair-invite.1",
    },
    OpFace {
        op: "trust.list",
        marker: "TrustListOp",
        renderer: "print_trust_list",
        cli_spelling: "qsh trust list",
        man_file: "qsh-trust-list.1",
    },
    OpFace {
        op: "trust.remove",
        marker: "TrustRemoveOp",
        renderer: "print_trust_remove",
        cli_spelling: "qsh trust remove",
        man_file: "qsh-trust-remove.1",
    },
    OpFace {
        op: "trust.rename",
        marker: "TrustRenameOp",
        renderer: "print_trust_rename",
        cli_spelling: "qsh trust rename",
        man_file: "qsh-trust-rename.1",
    },
    OpFace {
        op: "tunnel.close",
        marker: "TunnelCloseOp",
        renderer: "print_tunnel_close",
        cli_spelling: "qsh tunnel close",
        man_file: "qsh-tunnel-close.1",
    },
    OpFace {
        op: "tunnel.dynamic",
        marker: "TunnelDynamicOp",
        renderer: "print_dynamic_tunnel_open",
        cli_spelling: "--dynamic",
        man_file: "qsh-tunnel-open.1",
    },
    OpFace {
        op: "tunnel.list",
        marker: "TunnelListOp",
        renderer: "print_tunnels",
        cli_spelling: "qsh tunnels",
        man_file: "qsh-tunnels.1",
    },
    OpFace {
        op: "tunnel.open",
        marker: "TunnelOpenOp",
        renderer: "print_tunnel_open",
        cli_spelling: "qsh tunnel open",
        man_file: "qsh-tunnel-open.1",
    },
    OpFace {
        op: "version.get",
        marker: "VersionOp",
        renderer: "print_version",
        cli_spelling: "qsh version",
        man_file: "qsh-version.1",
    },
];

#[test]
fn layer_2_every_schema_command_has_all_six_faces() {
    let schema_commands: HashSet<&str> = qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS
        .iter()
        .copied()
        .collect();
    let table: HashMap<&str, &OpFace> = OP_FACES.iter().map(|f| (f.op, f)).collect();
    assert_eq!(
        table.len(),
        OP_FACES.len(),
        "OP_FACES has a duplicate `op` entry"
    );

    // Totality, both ways: every schema command has a table row, and
    // every table row names a real schema command.
    let table_ops: HashSet<&str> = table.keys().copied().collect();
    let missing_rows: Vec<&&str> = schema_commands.difference(&table_ops).collect();
    assert!(
        missing_rows.is_empty(),
        "these commands are in qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS but have no \
         OP_FACES row in this file: {missing_rows:?}"
    );
    let stale_rows: Vec<&&str> = table_ops.difference(&schema_commands).collect();
    assert!(
        stale_rows.is_empty(),
        "these OP_FACES rows name a command that is no longer in \
         qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS: {stale_rows:?}"
    );

    let main_rs = read_doc("crates/qsh-cli/src/main.rs");
    let cli_md = read_doc("docs/CLI.md");
    let man_dir = repo_root().join("docs").join("man");

    for face in OP_FACES {
        // Face 1: schemars arm.
        assert!(
            qsh_proto::schema::cli_v1_data_schema(face.op).is_some(),
            "{}: qsh_proto::schema::cli_v1_data_schema returns None — no schemars arm",
            face.op
        );

        // Face 2: CLI_V1_SCHEMA_COMMANDS membership (already proven by
        // the totality check above; asserted again per-row so a failure
        // names the specific op instead of only a set diff).
        assert!(
            schema_commands.contains(face.op),
            "{}: missing from qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS",
            face.op
        );

        // Face 3: main.rs dispatch source-scan. Every dispatch arm in
        // this codebase passes `<Marker>::COMMAND` as a literal argument
        // to `finish`/`report_error`/`Envelope::success` (never behind a
        // variable it constructs itself), so the marker's own
        // `::COMMAND` literal is a reliable proxy for "this op has a
        // dispatch arm" without needing to parse the match expression.
        let marker_literal = format!("{}::COMMAND", face.marker);
        assert!(
            main_rs.contains(&marker_literal),
            "{}: {marker_literal:?} does not appear in crates/qsh-cli/src/main.rs — no \
             dispatch arm reachable for this op",
            face.op
        );

        // Face 4: human renderer call.
        let renderer_literal = format!("human::{}", face.renderer);
        assert!(
            main_rs.contains(&renderer_literal),
            "{}: {renderer_literal:?} is not called from crates/qsh-cli/src/main.rs",
            face.op
        );

        // Face 5: docs/CLI.md mentions the CLI spelling somewhere (see
        // module doc for why this is whole-document, not per-section).
        assert!(
            cli_md.contains(face.cli_spelling),
            "{}: {:?} does not appear anywhere in docs/CLI.md",
            face.op,
            face.cli_spelling
        );

        // Face 6: the generated man page exists.
        let man_path = man_dir.join(face.man_file);
        assert!(
            man_path.is_file(),
            "{}: {} does not exist under docs/man/ — run `cargo xtask man`",
            face.op,
            face.man_file
        );
    }
}
