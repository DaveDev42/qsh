//! An M8 soak adversarial-review finding (docs/campaigns/m8-soak.md §3) had a
//! wrong premise: it assumed `Quotas::reserve_connection` has exactly one
//! production call site, when there are really two, one per accept path
//! that reserves a connection slot before authorizing anything else —
//! `Server::serve_connection` (`qsh serve`'s own accept loop,
//! `crates/qsh-core/src/server/mod.rs`) and `Listen::
//! accept_and_register_permitted` (the reverse-target controller's accept
//! loop, `crates/qsh-core/src/reverse/listen.rs`).
//!
//! `live_conns` (the accept-loop heartbeat) and the per-connection quota
//! itself both depend on every accepted connection actually reaching one
//! of these two calls — there is no exhaustive-match anchor for "every
//! accept path" the way `qsh_proto::wire::control_message::Body` gives
//! layer 2 of `tests/acl_registry.rs`, so this pins the fact by source
//! text instead, the same precedent `tests/acl_registry.rs::source_scan::
//! authorize_stream_has_exactly_two_production_call_sites` uses for a
//! property with the identical shape: a third call site anywhere (or the
//! loss of either of these two) fails here instead of silently changing
//! which accept path actually reserves the slot the heartbeat and the
//! quota believe every live connection holds.

#[path = "support/docs.rs"]
mod docs;
use docs::{read_doc, repo_root};

/// `relative`'s source, which is production code only: both scanned files
/// keep their tests in sibling files (`server/tests.rs`, `reverse/listen/
/// *_tests.rs` and `listen/tests.rs`), so a `#[cfg(test)]` call site never
/// counts. Same shape as `tests/acl_registry.rs::source_scan::
/// server_mod_production_source`.
fn production_source(relative: &str) -> String {
    read_doc(relative)
}

/// `reverse/listen.rs` plus every production `.rs` file in the
/// `reverse/listen/` directory beside it (`conn_table.rs`, `hub.rs`,
/// `registration.rs`, and whatever is added later), concatenated. The
/// test files are the ones named `tests.rs` or ending in `_tests.rs`.
fn reverse_listen_production_source() -> String {
    let dir = repo_root().join("crates/qsh-core/src/reverse/listen");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()))
        .map(|entry| entry.expect("read_dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name != "tests.rs" && !name.ends_with("_tests.rs")
        })
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no production files under {}",
        dir.display()
    );
    let mut source = production_source("crates/qsh-core/src/reverse/listen.rs");
    for path in paths {
        source.push('\n');
        source.push_str(&production_source(
            &path.strip_prefix(repo_root()).unwrap().to_string_lossy(),
        ));
    }
    source
}

/// Every line of `source`, blanking any line that is itself a comment
/// (`//`, `///`, or `//!`, after leading whitespace) — so a doc comment
/// that merely *mentions* `reserve_connection(` in prose (this module's
/// own doc does, several times) never counts as a real call site.
fn non_comment_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect()
}

/// Real `Quotas::reserve_connection` call sites in `relative`'s
/// production code: lines containing `.reserve_connection(`, which
/// excludes the method's own `pub fn reserve_connection(` definition line
/// in `crates/qsh-core/src/quota.rs` (a method call is always written
/// `receiver.method(`; a definition never is) as well as anything in a
/// `#[cfg(test)]` module or a comment.
fn reserve_connection_call_sites(relative: &str) -> Vec<String> {
    reserve_connection_call_sites_in(&production_source(relative))
}

/// [`reserve_connection_call_sites`] over an already-read source string.
fn reserve_connection_call_sites_in(source: &str) -> Vec<String> {
    non_comment_lines(source)
        .into_iter()
        .filter(|line| line.contains(".reserve_connection("))
        .map(|line| line.trim().to_string())
        .collect()
}

/// `Server::serve_connection` must be the sole
/// `reserve_connection` call site in `server/mod.rs` — a second one
/// (an accept path that reserves a slot outside this choke point) or a
/// zero count (the reservation moved or was dropped) both change what the
/// heartbeat's `live_conns` and the connection quota actually measure.
#[test]
fn reserve_connection_has_exactly_one_production_call_site_in_server_mod() {
    let sites = reserve_connection_call_sites("crates/qsh-core/src/server/mod.rs");
    assert_eq!(
        sites.len(),
        1,
        "Server::serve_connection must be the sole reserve_connection call site in \
         server/mod.rs, not {}: {sites:?}",
        sites.len()
    );
}

/// The other half of the same check: `Listen::accept_and_register_permitted`
/// must be the sole `reserve_connection` call site under `reverse/listen.rs`
/// and `reverse/listen/` — the reverse-target controller's own accept path,
/// independent of `qsh serve`'s.
#[test]
fn reserve_connection_has_exactly_one_production_call_site_in_reverse_listen() {
    let sites = reserve_connection_call_sites_in(&reverse_listen_production_source());
    assert_eq!(
        sites.len(),
        1,
        "Listen::accept_and_register_permitted must be the sole reserve_connection call \
         site under reverse/listen.rs and reverse/listen/, not {}: {sites:?}",
        sites.len()
    );
}
