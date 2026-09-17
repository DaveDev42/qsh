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

use common::{Sandbox, ServeGuard, poll_until};
use std::time::Duration;

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
///
/// ADR-0017 결정 4: the replay also owes a host-
/// local diagnostic on top of the wire reply. Both halves are asserted —
/// the host's own stderr must carry `PAIRING_INVITE_REPLAY_NOTICE`
/// exactly once, **and** the second redeemer's `SESSION_CONFLICT`
/// envelope (`error.code`/`error.message`) must stay byte-unchanged,
/// which is the proof that decision 4's exempted wire/tracing axes were
/// not touched by adding the third, host-local line.
#[test]
fn a_consumed_invite_cannot_be_redeemed_twice() {
    let host = Sandbox::initialized();
    let first_client = Sandbox::initialized();
    let second_client = Sandbox::initialized();
    let mut serve = ServeGuard::start(&host);

    let (code, _cmd) = invite(&host);

    let (exit, accepted) = first_client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit, 0, "{accepted}");

    let (exit2, rejected) = second_client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_ne!(exit2, 0, "a second redemption must fail: {rejected}");
    assert_eq!(rejected["error"]["code"], "SESSION_CONFLICT", "{rejected}");
    assert_eq!(
        rejected["error"]["message"], "invite already used",
        "the wire message `PairingError::as_wire_error` sends must stay byte-unchanged: {rejected}"
    );

    // The rejected client already has its `SESSION_CONFLICT` reply (and
    // has exited) by the time the host's own follow-on `self.notify(...)`
    // (`server/mod.rs`'s `serve_pairing_connection`) runs — that write is
    // asynchronous to the wire exchange, so poll for it rather than racing
    // `finish()`'s immediate kill against it (`ServeGuard::stderr_snapshot`'s
    // own doc).
    poll_until(
        "the invite-replay notice on host stderr",
        Duration::from_secs(5),
        || {
            serve
                .stderr_snapshot()
                .iter()
                .any(|line| line.contains(qsh_core::pairing::PAIRING_INVITE_REPLAY_NOTICE))
                .then_some(())
        },
    );

    let output = serve.finish();
    let notice_count = output
        .stderr
        .iter()
        .filter(|line| line.contains(qsh_core::pairing::PAIRING_INVITE_REPLAY_NOTICE))
        .count();
    assert_eq!(
        notice_count, 1,
        "host stderr must note the invite replay exactly once: {:?}",
        output.stderr
    );
}

/// ADR-0017 결정 3: pairing with no `acl.toml` on
/// disk at all. `ServeGuard::start_without_policy` skips
/// `plant_allow_all_acl`, so the host enforces `DenyAll` — pairing itself
/// is not ACL-gated (`Server::serve_pairing_connection`'s `try_pin`
/// closure runs before any `Authorizer::check`), so the accept still
/// succeeds, and the host's own stderr must carry `PAIRING_ACL_ROW_ABSENT`
/// exactly once: pinned, but every action is still denied.
#[test]
fn pairing_with_no_acl_toml_notes_the_row_absent_on_the_host() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let mut serve = ServeGuard::start_without_policy(&host, &[]);

    let (code, _cmd) = invite(&host);
    let (exit, accepted) = client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit, 0, "{accepted}");

    // See the `poll_until` note in `a_consumed_invite_cannot_be_redeemed_twice`
    // — the pin notice is a host-side follow-on write, asynchronous to the
    // client's own already-completed exchange.
    poll_until(
        "the absent-acl-row pin notice on host stderr",
        Duration::from_secs(5),
        || {
            serve
                .stderr_snapshot()
                .iter()
                .any(|line| line.contains(qsh_core::pairing::PAIRING_ACL_ROW_ABSENT))
                .then_some(())
        },
    );

    let output = serve.finish();
    let notice_count = output
        .stderr
        .iter()
        .filter(|line| line.contains(qsh_core::pairing::PAIRING_ACL_ROW_ABSENT))
        .count();
    assert_eq!(
        notice_count, 1,
        "host stderr must note the absent acl row exactly once: {:?}",
        output.stderr
    );
}

/// The mirror of `pairing_with_no_acl_toml_notes_the_row_absent_on_the_host`
/// above: an `[[acl]]` row already names the initiator's device id, so the
/// host's stderr must carry `PAIRING_ACL_ROW_PRESENT` instead.
///
/// **Startup order is the test contract, not an accident.**
/// `PinnedPrincipalIndex` (`acl/load.rs`) is computed exactly once, at
/// `qsh serve` startup, from the `Policy` this process is actually
/// enforcing — a fresh re-read at pairing time would misreport a row
/// added *after* startup as already applied (the same startup-vs-runtime
/// hazard ADR-0017 결정 2 already guards against). So the `acl.toml` row
/// below must exist on disk **before** `ServeGuard::start` spawns the
/// host; starting the host first and writing the row afterward would
/// still make the assertion below pass, but for the wrong reason (it
/// would only prove a fresh read, not the startup-computed index this
/// step actually commits to). Do not reorder this.
#[test]
fn pairing_with_an_existing_acl_row_notes_the_row_present_on_the_host() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let client_device_id = client.init()["data"]["device_id"]
        .as_str()
        .expect("device_id")
        .to_string();

    // Written BEFORE `ServeGuard::start` below — see the doc comment
    // above.
    let acl_path = host.config_dir().join("acl.toml");
    std::fs::write(
        &acl_path,
        format!("[[acl]]\nprincipal = \"device:{client_device_id}\"\nallow = [\"exec.run\"]\n"),
    )
    .expect("write acl.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&acl_path, std::fs::Permissions::from_mode(0o600));
    }

    // `ServeGuard::start`'s `plant_allow_all_acl` is a no-op here — the
    // file above already exists — so the policy actually loaded and
    // enforced is exactly the one-row file just written.
    let mut serve = ServeGuard::start(&host);

    let (code, _cmd) = invite(&host);
    let (exit, accepted) = client.json(&["trust", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit, 0, "{accepted}");

    // See the `poll_until` note in `a_consumed_invite_cannot_be_redeemed_twice`
    // — the pin notice is a host-side follow-on write, asynchronous to the
    // client's own already-completed exchange.
    poll_until(
        "the present-acl-row pin notice on host stderr",
        Duration::from_secs(5),
        || {
            serve
                .stderr_snapshot()
                .iter()
                .any(|line| line.contains(qsh_core::pairing::PAIRING_ACL_ROW_PRESENT))
                .then_some(())
        },
    );

    let output = serve.finish();
    let notice_count = output
        .stderr
        .iter()
        .filter(|line| line.contains(qsh_core::pairing::PAIRING_ACL_ROW_PRESENT))
        .count();
    assert_eq!(
        notice_count, 1,
        "host stderr must note the present acl row exactly once: {:?}",
        output.stderr
    );
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

/// `PLAN.md` M9 Step 2, ADR-0013 decision 8: a code piped on stdin
/// redeems a real invite, same as the positional-argument path.
#[test]
fn trust_accept_reads_the_code_from_stdin_in_json_mode() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);
    let (code, _cmd) = invite(&host);

    let args = ["trust", "accept", serve.addr(), "--code-stdin", "--json"];
    let output = client.qsh_with_stdin(&args, code.as_bytes());
    let envelope = common::sole_envelope(&output.stdout, &args);
    assert_eq!(common::exit_code(&output), 0, "{envelope}");
    assert_eq!(envelope["data"]["created"], true, "{envelope}");
    assert_eq!(
        envelope["data"]["peer"]["address"],
        serve.addr(),
        "{envelope}"
    );
}

/// Trim regression 1 (`PLAN.md` M9 Step 2 (c)): a trailing newline, as a
/// real `printf '%s\n' "$code" | qsh trust accept … --code-stdin` pipeline
/// would produce, must not be rejected.
#[test]
fn trust_accept_from_stdin_tolerates_a_trailing_newline() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);
    let (code, _cmd) = invite(&host);

    let args = ["trust", "accept", serve.addr(), "--code-stdin", "--json"];
    let output = client.qsh_with_stdin(&args, format!("{code}\n").as_bytes());
    let envelope = common::sole_envelope(&output.stdout, &args);
    assert_eq!(common::exit_code(&output), 0, "{envelope}");
    assert_eq!(envelope["data"]["created"], true, "{envelope}");
}

/// Trim regression 2 (`PLAN.md` M9 Step 2 (c)): surrounding spaces must
/// not be rejected either.
#[test]
fn trust_accept_from_stdin_tolerates_surrounding_whitespace() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);
    let (code, _cmd) = invite(&host);

    let args = ["trust", "accept", serve.addr(), "--code-stdin", "--json"];
    let output = client.qsh_with_stdin(&args, format!("  {code}  ").as_bytes());
    let envelope = common::sole_envelope(&output.stdout, &args);
    assert_eq!(common::exit_code(&output), 0, "{envelope}");
    assert_eq!(envelope["data"]["created"], true, "{envelope}");
}

/// A `trust accept` call with neither a positional code nor
/// `--code-stdin` in machine mode is rejected without ever opening a
/// prompt. No host needed: the resolver refuses before any dial.
#[test]
fn trust_accept_with_no_code_in_json_mode_is_invalid_argument() {
    let client = Sandbox::initialized();
    let args = ["trust", "accept", "127.0.0.1:1", "--json"];
    let output = client.qsh(&args);

    let envelope = common::sole_envelope(&output.stdout, &args);
    assert_eq!(common::exit_code(&output), 255, "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");
    // This is the resolver's own wording for *this* refusal — the
    // machine-mode arm wins before the tty check, so even though stdin is
    // not a terminal here either, the sibling "no terminal" wording must
    // not appear (both mention `--code-stdin`, so a substring match alone
    // would not tell the two apart — see
    // `ops::tests::resolve_invite_code_source_decision_table`). It is also
    // not `parse_invite_code`'s `WrongLength`, which is what a prompt
    // opening and reading an empty value would have produced instead.
    assert_eq!(
        envelope["error"]["message"].as_str().expect("message"),
        "no invite code: --json/--jsonl mode never prompts, so pass the code as an argument or \
         read it from stdin with --code-stdin",
        "{envelope}"
    );
    // machine mode never opens a prompt: its wording never reaches stderr.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(qsh_core::ops::INVITE_CODE_PROMPT),
        "no prompt in machine mode: {stderr:?}"
    );
}

/// `PLAN.md` M9 Step 2 (d): `INVITE_CODE_STDIN_MAX` really bounds the
/// read — a valid code preceded by more than the cap's worth of padding
/// is truncated away entirely (nothing but padding survives into the
/// buffer), not merely trimmed. Raising the constant, or reading stdin
/// unbounded, would turn this into a real accept instead of a rejection.
#[test]
fn trust_accept_from_stdin_is_bounded_by_invite_code_stdin_max() {
    let client = Sandbox::initialized();
    let padding = " ".repeat(qsh_core::ops::INVITE_CODE_STDIN_MAX + 10);
    let code = "abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab";
    let input = format!("{padding}{code}");

    let args = ["trust", "accept", "127.0.0.1:1", "--code-stdin", "--json"];
    let output = client.qsh_with_stdin(&args, input.as_bytes());
    let envelope = common::sole_envelope(&output.stdout, &args);
    assert_eq!(common::exit_code(&output), 255, "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .expect("message")
            .contains("0 symbols"),
        "the cap must have discarded the whole code, not merely trimmed whitespace: {envelope}"
    );
}

/// `--code-stdin` input that is not valid UTF-8 fails with a distinct,
/// readable message rather than silently truncating or panicking.
#[test]
fn trust_accept_from_stdin_rejects_non_utf8_input() {
    let client = Sandbox::initialized();
    let args = ["trust", "accept", "127.0.0.1:1", "--code-stdin", "--json"];
    let output = client.qsh_with_stdin(&args, &[0xFF, 0xFE, 0xFD]);
    let envelope = common::sole_envelope(&output.stdout, &args);
    assert_eq!(common::exit_code(&output), 255, "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .expect("message")
            .contains("valid UTF-8"),
        "{envelope}"
    );
}

/// ADR-0014 결정 5: the port-assumed notice fires from the very top of
/// `run_trust_accept`, before the invite code is even resolved — so a
/// call with no code at all (machine mode refuses to prompt) still notes
/// the assumed port exactly once, with no network and no server needed.
#[test]
fn trust_accept_with_a_port_less_address_notes_the_assumed_port_once_and_keeps_stdout_pure() {
    let client = Sandbox::initialized();
    let args = ["trust", "accept", "127.0.0.1", "--json"];
    let output = client.qsh(&args);
    let envelope = common::sole_envelope(&output.stdout, &args);
    assert_eq!(common::exit_code(&output), 255, "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr.matches("assuming port 4433").count(),
        1,
        "stderr must note the assumed port exactly once: {stderr:?}"
    );

    // The `stderr_note!` call in `run_trust_accept`
    // fires unconditionally, before `--json`/human mode is decided
    // (`main.rs`'s `run_trust_accept`), so the human-mode half must see
    // it too. Deleting that call site must turn this whole test red.
    let human_client = Sandbox::initialized();
    let human_output = human_client.qsh(&["trust", "accept", "127.0.0.1"]);
    assert_eq!(common::exit_code(&human_output), 255, "{human_output:?}");
    let human_stderr = String::from_utf8(human_output.stderr).unwrap();
    assert_eq!(
        human_stderr.matches("assuming port 4433").count(),
        1,
        "human mode stderr must note the assumed port exactly once: {human_stderr:?}"
    );
}

/// The symmetric case: an address that already names a port notes nothing.
#[test]
fn trust_accept_with_a_port_notes_nothing() {
    let client = Sandbox::initialized();
    let args = ["trust", "accept", "127.0.0.1:4433", "--json"];
    let output = client.qsh(&args);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("assuming port"),
        "an address with an explicit port must not be noted: {stderr:?}"
    );
}
