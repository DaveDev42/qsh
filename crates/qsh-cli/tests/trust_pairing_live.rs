//! `trust invite` / `trust accept` live pairing (ADR-0002, `PLAN.md` M7 Step
//! 4), driven through the product path against a **running** `qsh serve`
//! daemon — the CLI-facing counterpart to the lower-level wire-protocol
//! coverage in `qsh-testkit/tests/pairing_loopback.rs`.
//!
//! Every scenario here mints the invite *after* `qsh serve` is already
//! running (never before), because the interesting claim is `docs/CLI.md`
//! §6.11's "no restart needed": `SharedInviteStore` re-reads `invites.toml`
//! on every redeem attempt the same way `SharedTrustStore` re-reads
//! `trust.toml` (`trust_lifecycle_live.rs`'s own module doc) — a separate
//! `qsh trust invite` process writes the file, and the already-running
//! daemon must pick the new invite up with no signal, no restart, nothing
//! but the next connection.

use common::{Sandbox, ServeGuard};

mod common;

/// Mint an invite on `host` via a real `qsh trust invite --json` process and
/// return `(code, accept_command)`.
fn invite(host: &Sandbox) -> (String, String) {
    let (code, envelope) = host.json(&["trust", "invite", "--json"]);
    assert_eq!(code, 0, "{envelope}");
    let invite_code = envelope["data"]["code"]
        .as_str()
        .expect("data.code")
        .to_string();
    let accept_command = envelope["data"]["accept_command"]
        .as_str()
        .expect("data.accept_command")
        .to_string();
    assert!(
        accept_command.contains(&invite_code),
        "accept_command must embed the real code verbatim: {accept_command:?} / {invite_code:?}"
    );
    assert!(
        accept_command.starts_with("qsh trust accept <address> "),
        "accept_command must be the copy-pasteable command line: {accept_command:?}"
    );
    (invite_code, accept_command)
}

/// **DoD quadrant: happy path.** A fresh invite, redeemed once, pins both
/// sides — the host learns the client's device id (via the client's own
/// `qsh init`-generated identity), and the client learns the host's.
#[test]
fn trust_accept_pairs_both_sides_via_a_live_invite() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    let (code, _cmd) = invite(&host);

    let (exit, accepted) = client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit, 0, "{accepted}");
    assert_eq!(accepted["data"]["created"], true, "{accepted}");
    assert!(
        accepted["data"]["peer"]["fingerprint"].as_str().is_some(),
        "{accepted}"
    );

    // Report F-6: the address just dialed successfully must not be
    // discarded — otherwise `qsh exec <peer>` right after pairing would be
    // `HOST_NOT_FOUND` (§6.1/§6.8: an address-less pin is never a dial
    // candidate), undercutting ADR-0002's SC1 (5-minute pairing to first
    // connection).
    assert_eq!(
        accepted["data"]["peer"]["address"],
        serve.addr(),
        "{accepted}"
    );

    // The client is now pinned locally, same shape `trust add` would have
    // produced.
    let (list_exit, listed) = client.json(&["trust", "list", "--json"]);
    assert_eq!(list_exit, 0, "{listed}");
    let peers = listed["data"]["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 1, "{listed}");
    assert_eq!(peers[0]["address"], serve.addr(), "{listed}");

    // The host side pinned the client back, bidirectionally, in the same
    // exchange (invariant #5) — no separate `trust add` on the host.
    let (host_list_exit, host_listed) = host.json(&["trust", "list", "--json"]);
    assert_eq!(host_list_exit, 0, "{host_listed}");
    let host_peers = host_listed["data"]["peers"]
        .as_array()
        .expect("host peers array");
    assert_eq!(host_peers.len(), 1, "{host_listed}");
}

/// **DoD quadrant: single-use.** A second redemption of the same code, after
/// a first success, is rejected — the invite is consumed, not reusable.
#[test]
fn a_consumed_invite_cannot_be_redeemed_twice() {
    let host = Sandbox::initialized();
    let first_client = Sandbox::initialized();
    let second_client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    let (code, _cmd) = invite(&host);

    let (exit, accepted) = first_client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit, 0, "{accepted}");

    let (exit2, rejected) = second_client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_ne!(exit2, 0, "a second redemption must fail: {rejected}");
    assert_eq!(rejected["error"]["code"], "SESSION_CONFLICT", "{rejected}");
}

/// **DoD quadrant: unknown code.** A syntactically valid but never-issued
/// code is rejected distinguishably from "already consumed" / "expired".
#[test]
fn an_unknown_invite_code_is_rejected_as_auth_failed() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    // Mint and immediately discard a real invite so the daemon has a live
    // `invites.toml` to consult — the code below is a different, made-up
    // one of the same shape, never issued by this host.
    let _ = invite(&host);
    let bogus = "0000-0000-0000-0000-0000-0000-0000-0000";

    let (exit, rejected) = client.json(&["trust", "accept", serve.addr(), bogus, "--json"]);
    assert_ne!(exit, 0, "{rejected}");
    assert_eq!(rejected["error"]["code"], "AUTH_FAILED", "{rejected}");
}

/// **Invariant #5 regression, server side.** The host already has a peer
/// pinned locally under the exact name the pairing client will offer as its
/// own device id (`Server::serve_pairing_connection`'s `try_pin` closure —
/// `crates/qsh-core/src/server/mod.rs`), but under a *different*
/// fingerprint. Pairing must fail loudly (`SESSION_CONFLICT`), never the
/// silent no-op `trust add` itself would give the same underlying case
/// (`TrustStore::add_peer`'s own doc, left deliberately untouched — report
/// §F). Because this is a *server*-side collision, the ordering fix
/// (report §B9/§B14: `SharedInviteStore::redeem`'s `on_matched` hook runs
/// before consume) applies: the invite must be left redeemable for anyone
/// else afterward.
#[test]
fn trust_accept_fails_loudly_on_a_server_side_device_id_collision() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    // Pin some other identity on the *host* under the exact name the
    // client's own `qsh init`-generated device id is — but with a
    // fingerprint that cannot possibly match the client's real one.
    let client_device_id = client.init()["data"]["device_id"]
        .as_str()
        .expect("device_id")
        .to_string();
    let bogus_fingerprint = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    host.trust_add(&client_device_id, None, bogus_fingerprint);

    let (code, _cmd) = invite(&host);
    let (exit, rejected) = client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_ne!(
        exit, 0,
        "a server-side device-id collision must not be a silent no-op: {rejected}"
    );
    assert_eq!(rejected["error"]["code"], "SESSION_CONFLICT", "{rejected}");

    // The invite itself must be left untouched by the rejected collision —
    // a fresh client (one whose device id does not collide with anything
    // already pinned on the host) can still redeem the very same code
    // afterward.
    let other_client = Sandbox::initialized();
    let (exit2, accepted) = other_client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(
        exit2, 0,
        "a collision on one redeemer must not burn the invite for anyone else: {accepted}"
    );
}

/// **Report F-2 regression.** The *same* client, already pinned by the
/// host from a first successful pairing, retries `trust accept` (here with
/// the same, now-consumed code — the most common real-world case: someone
/// runs the accept command twice). `verify_core`'s pin priority
/// (`qsh-transport::tls`) means this connection never routes through
/// `Principal::Pairing` at all on the second attempt — it lands in the
/// ordinary `handshake::respond` path, which must answer with a clean,
/// non-retryable `SESSION_CONFLICT`, never the old silent-connection-drop
/// behavior that surfaced as `CONNECTION_FAILED`/`retryable: true` (an
/// unrecoverable retry loop: no amount of retrying — not even a fresh
/// invite — changes the host's existing pin).
#[test]
fn same_client_retrying_a_consumed_code_gets_a_non_retryable_session_conflict() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    let (code, _cmd) = invite(&host);

    let (exit, accepted) = client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit, 0, "{accepted}");

    // The SAME client, now pinned on the host, retries with the same
    // (already-consumed) code.
    let (exit2, rejected) = client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_ne!(exit2, 0, "{rejected}");
    assert_eq!(
        rejected["error"]["code"], "SESSION_CONFLICT",
        "must not be CONNECTION_FAILED (the old silent-drop bug): {rejected}"
    );
    assert_eq!(
        rejected["error"]["retryable"], false,
        "a same-client retry can never succeed — no fresh invite fixes an \
         already-pinned peer, only the host's own `trust remove` does: {rejected}"
    );
}

/// **Invariant #8.** `--json` mode never opens an interactive prompt, even
/// on the one CLI command family (`trust`) that has an established
/// interactive path elsewhere (`trust add`'s TOFU confirmation). A bogus
/// code with stdin closed (`Sandbox::qsh`'s default) must return a clean
/// machine-mode error, not hang.
#[test]
fn trust_accept_in_json_mode_never_prompts_on_a_bad_code() {
    let client = Sandbox::initialized();
    // No host needed: an invite code that fails to parse at all is
    // rejected locally, before any dial — still must be pure JSON on
    // stdout with no prompt.
    let output = client.qsh(&[
        "trust",
        "accept",
        "127.0.0.1:1",
        "not-a-valid-invite-code",
        "--json",
    ]);
    let value = common::sole_envelope(
        &output.stdout,
        &["trust", "accept", "127.0.0.1:1", "not-a-valid-invite-code"],
    );
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{value}");
    assert_ne!(common::exit_code(&output), 0);
}

/// **Regression: `trust add --fingerprint` is unaffected by pairing.** The
/// pre-existing non-interactive pin-by-fingerprint path still works
/// unchanged alongside the new `trust invite`/`trust accept` pair.
#[test]
fn trust_add_with_an_explicit_fingerprint_is_unaffected_by_pairing() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let host_fp = host.fingerprint();
    let serve = ServeGuard::start(&host);

    client.trust_add("box", Some(serve.addr()), &host_fp);
    let (exit, listed) = client.json(&["trust", "list", "--json"]);
    assert_eq!(exit, 0, "{listed}");
    let peers = listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(peers.len(), 1, "{listed}");
    assert_eq!(peers[0]["fingerprint"], host_fp, "{listed}");
}
