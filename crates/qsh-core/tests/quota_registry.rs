//! ARBITRATION-5 (적대 검토 A 판정, F3) — REVIEW-5-A A4's own premise was
//! wrong: it assumed `Quotas::reserve_connection` has exactly one
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

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read_doc(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// `relative`'s production code only: a prefix slice on the file's sole
/// `"\n#[cfg(test)]\nmod tests {"` marker (this crate's clippy/fmt
/// discipline keeps exactly one such block per file) — not a parser,
/// deliberately, same as `tests/acl_registry.rs::source_scan::
/// server_mod_production_source`, whose own doc explains why a
/// byte-offset slice on a literal marker is the cheapest way to guarantee
/// a `#[cfg(test)]` call site never counts. CRLF-normalized for the same
/// reason that function documents: the Windows CI runner checks sources
/// out with `\r\n`, which would keep the `\n`-joined marker from ever
/// matching.
fn production_source(relative: &str) -> String {
    let full = read_doc(relative).replace("\r\n", "\n");
    let marker = "\n#[cfg(test)]\nmod tests {";
    let end = full
        .find(marker)
        .unwrap_or_else(|| panic!("{relative} must still have a #[cfg(test)] mod tests block"));
    full[..end].to_string()
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
    non_comment_lines(&production_source(relative))
        .into_iter()
        .filter(|line| line.contains(".reserve_connection("))
        .map(|line| line.trim().to_string())
        .collect()
}

/// REVIEW-5-A A4: `Server::serve_connection` must be the sole
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

/// REVIEW-5-A A4's other half: `Listen::accept_and_register_permitted`
/// must be the sole `reserve_connection` call site in
/// `reverse/listen.rs` — the reverse-target controller's own accept path,
/// independent of `qsh serve`'s.
#[test]
fn reserve_connection_has_exactly_one_production_call_site_in_reverse_listen() {
    let sites = reserve_connection_call_sites("crates/qsh-core/src/reverse/listen.rs");
    assert_eq!(
        sites.len(),
        1,
        "Listen::accept_and_register_permitted must be the sole reserve_connection call \
         site in reverse/listen.rs, not {}: {sites:?}",
        sites.len()
    );
}
