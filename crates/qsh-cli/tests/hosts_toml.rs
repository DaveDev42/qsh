//! `hosts.toml` CLI-boundary integration tests (`docs/CLI.md` §6.1's
//! "`hosts.toml` 파일 계약", `PLAN.md` M7 Step 3 (d) 완료 판정).
//!
//! `crates/qsh-core/src/ops/host.rs`'s `mod tests` already covers
//! `resolve_forward`'s merge/priority rules exhaustively at the pure-
//! function level, and `crates/qsh-cli/tests/fixtures.rs`'s
//! `golden_host_fixtures_with_hosts_toml` covers the additive JSON-contract
//! shape. What's left, and what only a real subprocess boundary (or a real
//! dial) can prove, is here:
//!
//! - a malformed `hosts.toml` surfaces as `CONFIG_ERROR` through the
//!   actual `qsh.cli/v1` envelope, at both places that load it
//!   (`host.list` and the peer-address resolution `exec`/session-open
//!   share);
//! - `hosts.toml`'s address genuinely wins a **live** QUIC dial over a
//!   stale `trust.toml` pin, not just the pure merge function;
//! - a `hosts.toml`-sourced default `user` still hits the exact same
//!   fail-closed `UNSUPPORTED` check an explicit `user@` mismatch already
//!   hits (`tui_expect.rs`'s
//!   `a_foreign_user_hint_is_refused_without_creating_a_session`), proving
//!   the default-fill path (`ops/session.rs`'s `resolve_user_hint`) is
//!   never a bypass.

mod common;

use common::{CLIENT_ALIAS, Fleet, HOST_ALIAS, Sandbox, ServeGuard};

/// A malformed `hosts.toml` is a `CONFIG_ERROR`, not a silent empty
/// directory (`docs/CLI.md`'s `hosts.toml` file contract paragraph). `qsh
/// hosts` is the cheapest command that exercises `Ops::host_list`'s
/// `HostsFile::load` call: no peer, no trust store entry, just `qsh init`.
#[test]
fn a_malformed_hosts_toml_is_a_config_error_not_a_silent_empty_directory() {
    let sandbox = Sandbox::initialized();
    std::fs::write(
        sandbox.config_dir().join("hosts.toml"),
        "this is not [ valid toml",
    )
    .expect("write malformed hosts.toml");

    let (code, envelope) = sandbox.json(&["hosts", "--json"]);
    assert_eq!(code, 255, "{envelope}");
    assert_eq!(envelope["error"]["code"], "CONFIG_ERROR", "{envelope}");
}

/// The same failure through the other choke point: `Ops::resolve_peer`
/// (the address resolution `exec`/session-open share), proving the
/// malformed-file failure mode isn't specific to `host.list`'s own code
/// path.
#[test]
fn a_malformed_hosts_toml_also_fails_closed_on_exec() {
    let fleet = Fleet::start();
    std::fs::write(
        fleet.client.config_dir().join("hosts.toml"),
        "[[host]\nmissing-bracket",
    )
    .expect("write malformed hosts.toml");

    let (code, envelope) = fleet
        .client
        .json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{envelope}");
    assert_eq!(envelope["error"]["code"], "CONFIG_ERROR", "{envelope}");
}

/// The real-connection priority test: the client's `trust.toml` pins `box`
/// at a deliberately unreachable address; `hosts.toml` overrides it with
/// the fleet's actual bound address. If `hosts.toml`'s address didn't win
/// this dial, it would time out or be refused — it succeeds, which is the
/// proof that `resolve_forward`'s priority rule holds at the real-dial
/// level, not just in the pure-function unit tests.
#[test]
fn hosts_toml_address_actually_wins_a_live_dial_over_a_stale_trust_toml_pin() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    let serve = ServeGuard::start(&host);

    // Port 1 is a reserved TCP port nothing on loopback will ever answer;
    // a dial that actually used this address would fail closed, never
    // succeed.
    client.trust_add(HOST_ALIAS, Some("127.0.0.1:1"), &host_fp);
    std::fs::write(
        client.config_dir().join("hosts.toml"),
        format!(
            "[[host]]\nname = \"{HOST_ALIAS}\"\naddress = \"{}\"\n",
            serve.addr()
        ),
    )
    .expect("write hosts.toml");

    let (code, envelope) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(
        code, 0,
        "hosts.toml's address must win the dial: {envelope}"
    );
}

/// The `user`-hint mismatch test: a `hosts.toml`-sourced default `user`
/// that doesn't match the account actually running `qsh serve` is refused
/// exactly like an explicit `user@host` mismatch is
/// (`tui_expect.rs`'s `a_foreign_user_hint_is_refused_without_creating_a_session`),
/// with no session left behind.
#[test]
fn a_hosts_toml_default_user_mismatch_is_refused_the_same_as_an_explicit_one() {
    let fleet = Fleet::start();
    let before = session_count(&fleet.client);

    std::fs::write(
        fleet.client.config_dir().join("hosts.toml"),
        format!(
            "[[host]]\nname = \"{HOST_ALIAS}\"\naddress = \"{}\"\nuser = \"qsh-no-such-user\"\n",
            fleet.addr()
        ),
    )
    .expect("write hosts.toml");

    // No `user@` prefix: the request's `user` is `None` until
    // `Ops::session_open`'s `resolve_user_hint` fills it in from
    // `hosts.toml`.
    let output = fleet.client.qsh(&[HOST_ALIAS]);
    assert_eq!(
        common::exit_code(&output),
        255,
        "a refused hosts.toml default is a qsh runtime failure (`docs/CLI.md` §4)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("user switching is not supported"),
        "stderr was {stderr:?}"
    );
    assert!(
        stderr.contains("UNSUPPORTED"),
        "the error code must reach the user: {stderr:?}"
    );
    assert_eq!(
        session_count(&fleet.client),
        before,
        "a refused hosts.toml default must not leave a session behind"
    );
}

/// How many sessions the host is holding.
fn session_count(client: &Sandbox) -> usize {
    let (code, listed) = client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{listed}");
    listed["data"]["sessions"]
        .as_array()
        .expect("sessions")
        .len()
}
