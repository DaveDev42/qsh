//! Doc-prose == code-constant anti-drift gate for `qsh_core::admission`'s
//! vocabulary (`PLAN.md` M8 Step 2 verification round, H3): before this,
//! nothing cross-checked `docs/CLI.md` §6.12's admission prose — the
//! category strings, the config key names, their defaults — against the
//! actual `qsh_core::admission::RejectReason::category()`/
//! `qsh_core::config::ServeConfig` constants it describes, unlike the
//! established `doctor_docs.rs`/`acl_docs.rs`/`tunnel_docs.rs` pattern
//! this file follows (`read_doc` helper included). A rename on either
//! side would have left the doc silently stale.
//!
//! Every assertion below reads the real constant/function rather than a
//! literal, so a rename breaks this test instead of leaving CLI.md wrong.

use std::path::PathBuf;

use qsh_core::admission::RejectReason;
use qsh_core::config::ServeConfig;

/// The repo root, reached from `CARGO_MANIFEST_DIR`
/// (`crates/qsh-core`) the same way every other doc-reading integration
/// test in this workspace does.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read_doc(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn cli_md_names_both_admission_rejection_categories() {
    let cli_md = read_doc("docs/CLI.md");
    assert!(
        cli_md.contains(RejectReason::RateLimited.category()),
        "docs/CLI.md §6.12 must name the \"{}\" category word \
         (RejectReason::RateLimited::category())",
        RejectReason::RateLimited.category()
    );
    assert!(
        cli_md.contains(RejectReason::AtCapacity.category()),
        "docs/CLI.md §6.12 must name the \"{}\" category word \
         (RejectReason::AtCapacity::category())",
        RejectReason::AtCapacity.category()
    );
}

#[test]
fn cli_md_names_both_admission_config_keys_and_their_defaults() {
    let cli_md = read_doc("docs/CLI.md");

    assert!(
        cli_md.contains("max_concurrent_handshakes"),
        "docs/CLI.md §6.12 must name the [serve].max_concurrent_handshakes config key"
    );
    assert!(
        cli_md.contains(&ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES.to_string()),
        "docs/CLI.md §6.12 must quote max_concurrent_handshakes's default \
         ({})",
        ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES
    );

    assert!(
        cli_md.contains("handshake_rate_per_source"),
        "docs/CLI.md §6.12 must name the [serve].handshake_rate_per_source config key"
    );
    assert!(
        cli_md.contains(&ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE.to_string()),
        "docs/CLI.md §6.12 must quote handshake_rate_per_source's default \
         ({})",
        ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE
    );
}
