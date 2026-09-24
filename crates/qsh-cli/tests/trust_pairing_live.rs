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
        accept_command.starts_with("qsh pair accept <address> "),
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

/// Mint an invite with `--as <assigned_name>` and return `(code, assigned_name)`.
fn invite_as(host: &Sandbox, assigned_name: &str) -> String {
    let (code, envelope) = host.json(&["trust", "invite", "--as", assigned_name, "--json"]);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(
        envelope["data"]["assigned_name"], assigned_name,
        "{envelope}"
    );
    envelope["data"]["code"]
        .as_str()
        .expect("data.code")
        .to_string()
}

/// ADR-0012 결정 6: the host pins the redeeming peer under the name the
/// invite assigned with `--as`, never the peer's self-asserted device id.
#[test]
fn pair_invite_as_pins_the_invite_chosen_name_on_the_host() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    let code = invite_as(&host, "workbench");
    let (exit, accepted) = client.json(&["pair", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit, 0, "{accepted}");

    let (list_exit, host_listed) = host.json(&["trust", "list", "--json"]);
    assert_eq!(list_exit, 0, "{host_listed}");
    let host_peers = host_listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(host_peers.len(), 1, "{host_listed}");
    assert_eq!(
        host_peers[0]["name"], "workbench",
        "the host must pin under the invite-assigned name, not the \
         client's self-asserted device id: {host_listed}"
    );
}

/// The accept-side counterpart, and the wire-invariance canary in one
/// (mutation #5/#6's target): `pair accept --as` only ever renames the
/// entry in the *accepting* client's own store — the host, which never
/// sees `--as` at all (it is not on the wire), still pins the client
/// under its real, self-asserted device id.
#[test]
fn pair_accept_as_pins_the_client_chosen_name_locally() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let client_device_id = client.init()["data"]["device_id"]
        .as_str()
        .expect("device_id")
        .to_string();
    let serve = ServeGuard::start(&host);

    let (code, _cmd) = invite(&host);
    let (exit, accepted) = client.json(&[
        "pair",
        "accept",
        serve.addr(),
        &code,
        "--as",
        "chosen-name",
        "--json",
    ]);
    assert_eq!(exit, 0, "{accepted}");

    let (client_list_exit, client_listed) = client.json(&["trust", "list", "--json"]);
    assert_eq!(client_list_exit, 0, "{client_listed}");
    let client_peers = client_listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(client_peers.len(), 1, "{client_listed}");
    assert_eq!(client_peers[0]["name"], "chosen-name", "{client_listed}");

    let (host_list_exit, host_listed) = host.json(&["trust", "list", "--json"]);
    assert_eq!(host_list_exit, 0, "{host_listed}");
    let host_peers = host_listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(host_peers.len(), 1, "{host_listed}");
    assert_eq!(
        host_peers[0]["name"], client_device_id,
        "the host must never see the accept side's --as value at all — \
         it pins the client's real device id, exactly as it would with no \
         --as given: {host_listed}"
    );
}

/// Both `--as` values in the same exchange, deliberately swapped from what
/// either side's real identity is — each store must hold only its own
/// axis's chosen name, proving the two are independent and neither
/// crosses over the wire (`docs/design/protocol.md` §15.6).
#[test]
fn invite_side_and_accept_side_as_names_are_independent() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    let code = invite_as(&host, "host-picks-this");
    let (exit, accepted) = client.json(&[
        "pair",
        "accept",
        serve.addr(),
        &code,
        "--as",
        "client-picks-this",
        "--json",
    ]);
    assert_eq!(exit, 0, "{accepted}");

    let (_e, host_listed) = host.json(&["trust", "list", "--json"]);
    let host_peers = host_listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(host_peers[0]["name"], "host-picks-this", "{host_listed}");

    let (_e, client_listed) = client.json(&["trust", "list", "--json"]);
    let client_peers = client_listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(
        client_peers[0]["name"], "client-picks-this",
        "{client_listed}"
    );
}

/// ADR-0012 결정 6's backward-compatible fallback: an invite minted with no
/// `--as` still pins the redeeming peer under its self-asserted device id,
/// exactly as `trust invite`/`trust accept` always did.
#[test]
fn pair_invite_without_as_still_pins_the_self_asserted_name() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let client_device_id = client.init()["data"]["device_id"]
        .as_str()
        .expect("device_id")
        .to_string();
    let serve = ServeGuard::start(&host);

    let (_code, envelope) = host.json(&["pair", "invite", "--json"]);
    assert!(
        envelope["data"]["assigned_name"].is_null(),
        "no --as: assigned_name must be absent, not null-but-present: {envelope}"
    );
    let code = envelope["data"]["code"].as_str().expect("code").to_string();

    let (exit, accepted) = client.json(&["pair", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit, 0, "{accepted}");

    let (_e, host_listed) = host.json(&["trust", "list", "--json"]);
    let host_peers = host_listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(host_peers[0]["name"], client_device_id, "{host_listed}");
}

/// The accept-side half of the wire-invariance claim (`docs/design/
/// protocol.md` §15.6): if `Ops::trust_accept` ever put `--as` on the
/// wire as `PairingProof.device_name` instead of the real device id, the
/// host would pin the client under the `--as` value even with no
/// invite-side `assigned_name` at all. This asserts the same property
/// `pair_accept_as_pins_the_client_chosen_name_locally` above does,
/// through the CLI/JSON layer rather than a raw wire frame, with a
/// deliberately identity-shaped `--as` value that would be trivially
/// distinguishable from a real device id if it leaked onto the wire. The
/// invite-side half — that an invite's `assigned_name` never reaches
/// `PairingProof` either — is pinned directly at the frame level by
/// `qsh-testkit`'s `invite_assigned_name_never_reaches_the_wire_proof`.
#[test]
fn pairing_frames_still_carry_the_device_id_not_the_assigned_name() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let client_device_id = client.init()["data"]["device_id"]
        .as_str()
        .expect("device_id")
        .to_string();
    let serve = ServeGuard::start(&host);

    let (code, _cmd) = invite(&host);
    let (exit, accepted) = client.json(&[
        "pair",
        "accept",
        serve.addr(),
        &code,
        "--as",
        "definitely-not-a-device-id",
        "--json",
    ]);
    assert_eq!(exit, 0, "{accepted}");

    let (_e, host_listed) = host.json(&["trust", "list", "--json"]);
    let host_peers = host_listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(
        host_peers[0]["name"], client_device_id,
        "PairingProof.device_name must carry this client's real device id, \
         never the accept side's --as value: {host_listed}"
    );
    assert_ne!(host_peers[0]["name"], "definitely-not-a-device-id");
}

/// `--as` collision on the accept side is judged against the effective
/// (chosen) name, not the self-asserted device id — a name already pinned
/// on the client from something unrelated blocks the pairing even though
/// the client's own device id is fine.
#[test]
fn pair_accept_as_collides_on_the_chosen_name_not_the_self_asserted_one() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    client.trust_add(
        "already-taken",
        None,
        "sha256:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=",
    );

    let (code, _cmd) = invite(&host);
    let (exit, rejected) = client.json(&[
        "pair",
        "accept",
        serve.addr(),
        &code,
        "--as",
        "already-taken",
        "--json",
    ]);
    assert_ne!(
        exit, 0,
        "a chosen-name collision must not be a silent no-op: {rejected}"
    );
    assert_eq!(rejected["error"]["code"], "SESSION_CONFLICT", "{rejected}");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .expect("message")
            .contains("already-taken"),
        "the message must name the effective (chosen) name, not the \
         self-asserted device id: {rejected}"
    );

    // Unlike a host-side collision, this check runs only after the wire
    // exchange with the host has already succeeded (`Ops::trust_accept`
    // pins locally under lock, strictly after `crate::pairing::accept`
    // returns `Ok`) — the host has no visibility into the accept side's
    // local naming at all, so it already pinned the client under its real
    // device id, and the invite is already spent. There is no host-side
    // rollback to prove here; `pair_invite_assigned_name_collision_
    // declines_without_burning_the_invite` covers the one collision shape
    // (host-side, pre-consumption) that does leave the invite untouched.
    let (_e, host_listed) = host.json(&["trust", "list", "--json"]);
    let host_peers = host_listed["data"]["peers"].as_array().expect("peers");
    assert_eq!(host_peers.len(), 1, "{host_listed}");
}

/// The invite-side counterpart: the invite's `--as` name collides with
/// something already pinned on the *host*. Declines through the same
/// non-distinguishing path a self-asserted collision does, and — because
/// this is a rejection inside `on_matched`, before the invite is marked
/// consumed — the code must still be redeemable afterward, and
/// `invites.toml` must be byte-identical (`docs/design/protocol.md` §15.6).
#[test]
fn pair_invite_assigned_name_collision_declines_without_burning_the_invite() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    host.trust_add(
        "collision-name",
        None,
        "sha256:Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=",
    );
    let code = invite_as(&host, "collision-name");
    let invites_path = host.config_dir().join("invites.toml");
    let raw_before = std::fs::read_to_string(&invites_path).unwrap();

    let (exit, rejected) = client.json(&["pair", "accept", serve.addr(), &code, "--json"]);
    assert_ne!(exit, 0, "{rejected}");
    assert_eq!(rejected["error"]["code"], "SESSION_CONFLICT", "{rejected}");

    let raw_after = std::fs::read_to_string(&invites_path).unwrap();
    assert_eq!(
        raw_after, raw_before,
        "a declined assigned-name collision must leave invites.toml \
         byte-identical — the invite is not consumed"
    );

    // Fix the collision on the host, then the very same code still works.
    host.json(&["trust", "remove", "collision-name", "--json"]);
    let other_client = Sandbox::initialized();
    let (exit2, accepted) = other_client.json(&["pair", "accept", serve.addr(), &code, "--json"]);
    assert_eq!(exit2, 0, "{accepted}");
}

/// Human mode with `--as` omitted prints the pinned self-asserted name on
/// **stderr only** — never stdout, so a script piping stdout sees nothing
/// extra (`docs/CLI.md` §6.11, ADR-0012 decision 6) — and the whole line
/// is suppressed once `--as` picks the name explicitly. Both cases dial
/// `serve.addr()` (an IP literal), the one address this harness can dial
/// with zero risk of an environment-dependent resolver outcome deciding
/// whether the connection even succeeds, so this also doubles as the
/// "no suggested label for an IP-literal address" case.
///
/// The complementary claim — that a *hostname* address does produce a
/// suggested label — is pinned separately and without a live dial at all:
/// `crate::trust::tests::suggested_peer_label_takes_the_first_dns_label_
/// and_skips_ip_literals` (`qsh-core`) proves `suggested_peer_label`
/// itself returns `Some` for a hostname and `None` for an IP literal: a
/// live test that actually dialed a hostname here would depend on which
/// of `127.0.0.1`/`::1` this machine's resolver hands back first for
/// `localhost`, which is not this harness's to control and differs across
/// the three CI legs.
#[test]
fn pair_accept_suggested_name_notice_is_stderr_only_and_conditional() {
    let host = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    // `--as` omitted: the self-asserted pin line prints on stderr, never
    // stdout, and (IP literal, so no hostname to derive a label from)
    // carries no suggested-rename clause.
    let client = Sandbox::initialized();
    let (code, _cmd) = invite(&host);
    let output = client.qsh(&["pair", "accept", serve.addr(), &code]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pinned as"),
        "expected the self-asserted pin line on stderr: {stderr:?}"
    );
    assert!(
        !stdout.contains("pinned as"),
        "the pin notice must never reach stdout: {stdout:?}"
    );
    assert!(
        !stderr.contains("consider `qsh trust rename"),
        "an IP-literal address must not produce a suggested label: {stderr:?}"
    );

    // `--as` given: no notice at all, not even the self-asserted line.
    let client_as = Sandbox::initialized();
    let (code2, _cmd2) = invite(&host);
    let output2 = client_as.qsh(&[
        "pair",
        "accept",
        serve.addr(),
        &code2,
        "--as",
        "chosen-name",
    ]);
    assert!(output2.status.success(), "{output2:?}");
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        !stderr2.contains("pinned as"),
        "no suggested-name notice belongs here when --as was given: {stderr2:?}"
    );
}
