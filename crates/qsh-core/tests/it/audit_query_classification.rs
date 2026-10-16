//! `audit.query` is a local, read-only operation (ADR-0033 결정 4, 7, 10,
//! `docs/CLI.md` §2.4/§2.5/§6.22). These tests pin the three facts that keep
//! it from becoming an enumeration oracle or a way to shorten the audit log:
//!
//! - nothing a remote peer can send names it: no wire message, and no
//!   localctl request either (the scan walks the whole localctl source tree,
//!   which includes the Unix socket and the Windows named-pipe transport,
//!   ADR-0035 결정 14);
//! - it has no ACL action or `OP_REGISTRY` row of its own;
//! - under `crates/qsh-core/src/ops/` it is the only op that reads the audit
//!   log back, and no op can delete, truncate or rewrite it (SC6).
//!
//! The tests read sources and `docs/CLI.md`, so they run on every CI leg
//! with the same names.

use std::path::{Path, PathBuf};

use qsh_core::acl::{Action, OP_REGISTRY};

use crate::docs;
use docs::{read_doc, repo_root};

/// Spellings under which a wire message, request variant or ACL action for
/// the audit query could appear (lower case, compared against lower-cased
/// text).
const AUDIT_QUERY_SPELLINGS: &[&str] = &[
    "auditquery",
    "audit_query",
    "audit.query",
    "auditrecordview",
    "audit_record_view",
];

fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = std::fs::read_dir(&current)
            .unwrap_or_else(|e| panic!("listing {}: {e}", current.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
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

fn assert_no_audit_query_spelling(label: &str, text: &str) {
    let lower = text.to_lowercase();
    for spelling in AUDIT_QUERY_SPELLINGS {
        assert!(
            !lower.contains(spelling),
            "{label} must never name the audit query ({spelling:?} found): the op is local only \
             (ADR-0033 결정 4)"
        );
    }
}

/// The wire protocol, the frame layer and the localctl request surface
/// (`proto/qsh/local/v1.proto`, `qsh-proto/src/local.rs`, the localctl
/// modules of `qsh-core`) carry no audit-query message, and the ACL has no
/// action or registry row for it.
#[test]
fn audit_query_has_no_wire_message_and_no_localctl_request() {
    let root = repo_root();
    for relative in [
        "crates/qsh-proto/proto/qsh/wire/v1.proto",
        "crates/qsh-proto/proto/qsh/local/v1.proto",
        "crates/qsh-proto/src/wire.rs",
        "crates/qsh-proto/src/frame.rs",
        "crates/qsh-proto/src/local.rs",
    ] {
        let text = read_doc(relative);
        assert!(!text.trim().is_empty(), "{relative} looks empty");
        assert_no_audit_query_spelling(relative, &text);
    }

    // Every localctl module of qsh-core: the daemon's request dispatch and
    // the client that builds requests.
    let localctl = root.join("crates/qsh-core/src/localctl");
    let files = rust_files_under(&localctl);
    assert!(!files.is_empty(), "localctl sources not found");
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read localctl source");
        assert_no_audit_query_spelling(&path.display().to_string(), &text);
    }

    // No ACL action and no OP_REGISTRY row: the op needs no authorization
    // because no peer can reach it, not because a row grants it.
    for action in Action::ALL {
        assert!(
            !action.as_str().contains("audit"),
            "ACL action {:?} names audit; `audit.query` needs no ACL action",
            action.as_str()
        );
    }
    for spec in OP_REGISTRY {
        assert!(
            !spec.op.as_str().contains("audit"),
            "OP_REGISTRY row {:?} names audit; `audit.query` is local only",
            spec.op.as_str()
        );
    }
}

/// The localctl request enum is closed over the three admin requests on every
/// platform. The exhaustive match stops compiling when a variant is added, so
/// an `audit.query` request cannot arrive without this test being read; the
/// source scan above then covers both transports, the Windows named pipe
/// included.
#[test]
fn localctl_request_enum_has_no_audit_variant_on_any_platform() {
    use qsh_proto::local::{LocalAdminRequest, local_admin_request};

    fn name(request: &LocalAdminRequest) -> &'static str {
        match request.body.as_ref() {
            Some(local_admin_request::Body::HostList(_)) => "host_list",
            Some(local_admin_request::Body::TunnelList(_)) => "tunnel_list",
            Some(local_admin_request::Body::TunnelClose(_)) => "tunnel_close",
            None => "none",
        }
    }
    let request = LocalAdminRequest {
        body: Some(local_admin_request::Body::HostList(Default::default())),
    };
    assert_eq!(name(&request), "host_list");

    for transport in ["unix.rs", "windows.rs"] {
        let path = repo_root()
            .join("crates/qsh-core/src/localctl/transport")
            .join(transport);
        assert!(
            path.is_file(),
            "{} is part of the scanned localctl tree",
            path.display()
        );
    }
}

/// Same shape as `pair_ssh_never_appears_as_a_control_message_wire_variant`:
/// the wire proto never gains a message for the audit query.
#[test]
fn audit_query_never_appears_as_a_control_message_wire_variant() {
    let source = read_doc("crates/qsh-proto/proto/qsh/wire/v1.proto");
    assert!(source.contains("message "), "v1.proto looks empty");
    let lower = source.to_lowercase();
    assert!(
        !lower.contains("auditquery")
            && !lower.contains("audit_query")
            && !lower.contains("audit.query"),
        "the wire proto must never gain an audit.query message"
    );
}

/// Tokens that open, delete, truncate or rewrite a file. `OpenOptions` is
/// on the list so even a read-mode open has to go through the reader module.
const FILE_MUTATION_TOKENS: &[&str] = &[
    "remove_file",
    "remove_dir",
    "set_len",
    ".truncate(",
    "fs::rename",
    "fs::write",
    "fs::copy",
    "File::create",
    "OpenOptions",
    ".append(",
    ".write(true)",
];

/// Strip `//` comment lines so a doc sentence that names a forbidden token
/// does not trip a source scan.
fn code_lines(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `path` is matched relative to `ops_dir`, so a checkout that itself sits
/// under a directory named `tests` does not skip every op file.
fn is_test_source(ops_dir: &Path, path: &Path) -> bool {
    path.strip_prefix(ops_dir)
        .unwrap_or(path)
        .components()
        .any(|c| c.as_os_str() == "tests")
        || path
            .file_name()
            .is_some_and(|name| name == "tests.rs" || name == "test_support.rs")
}

/// SC6 traceability (ADR-0033 결정 10): of everything under `ops/`, only
/// `ops/audit.rs` reads the audit log back and it does so through the reader
/// module, which has no write path; no op source names the writer's
/// rotation and recovery module or a file-mutation call next to the audit
/// path (the other op files get a windowed line scan for a mutation call that mentions the audit log). The remaining audit users in `ops/` are append-only
/// [`FileAuditSink`](qsh_core::audit::FileAuditSink) constructions, whose
/// only operation is `record`.
#[test]
fn no_op_other_than_audit_query_reads_the_audit_log_and_none_writes_it() {
    let ops_dir = repo_root().join("crates/qsh-core/src/ops");
    let audit_op = ops_dir.join("audit.rs");
    let mut saw_audit_op = false;
    for path in rust_files_under(&ops_dir) {
        if is_test_source(&ops_dir, &path) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read ops source");
        let code = code_lines(&text.replace("\r\n", "\n"));
        let label = path.display().to_string();

        // Reading the log back: the reader module and the view type.
        let reads_back = code.contains("audit::reader")
            || code.contains("reader::query")
            || code.contains("AuditRecordView");
        if path == audit_op {
            saw_audit_op = true;
            assert!(
                code.contains("reader::query"),
                "{label} must read the log through audit::reader::query"
            );
            // The op itself opens no file at all: every open lives in the
            // reader module, whose own source scan forbids write modes.
            for token in FILE_MUTATION_TOKENS {
                assert!(
                    !code.contains(token),
                    "{label} is the read-only audit.query op but contains {token:?}"
                );
            }
        } else {
            assert!(
                !reads_back,
                "{label} reads the audit log back; only ops/audit.rs (audit.query) may"
            );
            // Other ops legitimately delete and rewrite their own files
            // (unit files, trust.toml), so the blanket token ban above does
            // not apply. A mutation call whose own line or next two lines
            // mention the audit log is the shape of an op reaching for it.
            let lines: Vec<&str> = code.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                if !FILE_MUTATION_TOKENS
                    .iter()
                    .any(|token| line.contains(token))
                {
                    continue;
                }
                let window = lines[idx..lines.len().min(idx + 3)]
                    .join("\n")
                    .to_lowercase();
                assert!(
                    !window.contains("audit"),
                    "{label} calls a file-mutation API next to the audit log: {line:?}"
                );
            }
        }

        // Rotation, torn-tail repair and every other file-level operation on
        // the log belong to the writer; no op source may reach for them.
        assert!(
            !code.contains("audit::writer") && !code.contains("RotatingAuditSink"),
            "{label} names the audit writer's rotation and recovery module; no op may \
             delete, truncate or rewrite the audit log"
        );
    }
    assert!(saw_audit_op, "ops/audit.rs not found");

    // The reader module has no deletion, truncation or write API: no public
    // function whose name says so, and no write-mode open.
    let reader = std::fs::read_to_string(repo_root().join("crates/qsh-core/src/audit/reader.rs"))
        .expect("read audit/reader.rs");
    let reader_code = code_lines(&reader.replace("\r\n", "\n"));
    for token in [
        "remove_file",
        "set_len",
        ".truncate(",
        "fs::rename",
        "fs::write",
        "File::create",
        ".write(true)",
        ".append(",
        ".create(",
    ] {
        assert!(
            !reader_code.contains(token),
            "audit/reader.rs must stay read-only but contains {token:?}"
        );
    }
}

/// `docs/CLI.md` agrees with the classification: §2.4 lists the op, the
/// §2.5 "인가 불요" row names it, and the same row's paragraph says why a
/// remote caller would be an enumeration oracle.
#[test]
fn cli_md_lists_audit_query_as_a_local_op_with_no_authorization() {
    let cli_md = read_doc("docs/CLI.md");
    let section_2_5 = cli_md
        .split("### 2.5")
        .nth(1)
        .expect("docs/CLI.md has a §2.5")
        .split("\n### ")
        .next()
        .expect("§2.5 body");
    let row = section_2_5
        .lines()
        .find(|line| line.contains("인가 불요"))
        .expect("§2.5 has the no-authorization row");
    assert!(
        row.contains("`audit.query`"),
        "§2.5's 인가 불요 row must name audit.query: {row:?}"
    );
    assert!(
        section_2_5.contains("열거 oracle"),
        "§2.5 must give the enumeration-oracle reason for keeping audit.query local"
    );
}
