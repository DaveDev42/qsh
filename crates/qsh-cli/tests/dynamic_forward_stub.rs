//! `-D` (SOCKS5 dynamic forwarding) P0 stub (`docs/CLI.md` §6.9,
//! `docs/ROADMAP.md` M4 "명시적 out", `PLAN.md` M4 Step 6, DoD 5).
//!
//! Both places `-D` can be spelled — the interactive form's `qsh host -D
//! …` (`cli.rs`'s `InteractiveArgs::dynamic_forward`) and `qsh tunnel open
//! … --dynamic` (`TunnelOpenArgs::dynamic`) — always answer `UNSUPPORTED`
//! with a message that discloses the P1 deferral, and never create
//! anything: no local listener bind, no connection attempt, no session.
//! The interactive form has one exception to "always `UNSUPPORTED`":
//! with `--json`/`--jsonl` present, `docs/CLI.md` §7's machine-mode gate
//! answers `INVALID_ARGUMENT` before `-D`'s own refusal ever gets a turn
//! (`main.rs`'s `run_interactive` checks `wants_json` before `-D`) — the
//! interactive form has no JSON output mode at all, so that check
//! outranks every other refusal on the same command line. `-D`'s own
//! `UNSUPPORTED` is therefore only observable there in human mode;
//! `qsh tunnel open --dynamic` has a real JSON mode, so its `-D` answers
//! `UNSUPPORTED` in both output modes, and both spellings are repeatable
//! (`PLAN.md:223`) without changing that answer.
//! Unlike `tunnel_e2e.rs` (this file's nearest sibling in spirit), this
//! file carries **no** `cfg(unix)` gate anywhere — the `-D` stub is
//! refused entirely inside `qsh-cli`'s argument handling, before the
//! platform-specific tunnel/session machinery is reached at all, so it
//! has to run (and pass) on the Windows leg too (`PLAN.md` M4 Step 6
//! scope).

mod common;

use std::net::TcpListener;

use common::{Fleet, HOST_ALIAS};

/// A port nothing is listening on, released back to the kernel so a
/// successful re-bind after the refusal is proof nothing claimed it in
/// between (same technique as `tunnel_e2e.rs`'s own `free_port`,
/// duplicated rather than shared for the same self-containment reason
/// `fixtures.rs`'s copy gives).
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

/// Assert the shared shape every `-D` refusal owes: exit `255`, `ok:
/// false`, `error.code: UNSUPPORTED`, and a message that names "P1"
/// (`docs/CLI.md` §6.9: "message가 P1으로 미뤄졌음을 밝힌다"). This
/// substring check is `docs/design/testing.md` L6's own bar, not the
/// whole story: `fixtures.rs`'s `error.UNSUPPORTED.json` golden fixture
/// additionally exact-pins `qsh-core`'s `DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE`
/// verbatim (`fixtures.rs`'s `check()` does a full-envelope `assert_eq!`),
/// the same way every sibling error fixture freezes its own P0 wording —
/// so a rewording of that constant is a golden-surface change, not
/// something this substring assertion alone gives you for free.
fn assert_dynamic_forward_refusal(label: &str, envelope: &serde_json::Value, exit: i32) {
    assert_eq!(exit, 255, "{label}: {envelope}");
    assert_eq!(envelope["ok"], false, "{label}: {envelope}");
    assert_eq!(
        envelope["error"]["code"], "UNSUPPORTED",
        "{label}: {envelope}"
    );
    let message = envelope["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: error.message missing: {envelope}"));
    assert!(
        message.contains("P1"),
        "{label}: message must disclose the P1 deferral, got {message:?}"
    );
}

/// `-D` on `qsh tunnel open --dynamic` refuses before `Ops::tunnel_open`
/// is ever called (`main.rs`'s `run_tunnel_open`) — against a real, live,
/// trusted host (`HOST_ALIAS`), so the refusal is not merely "there was
/// nothing to connect to" but "this never tried", and the port it named
/// stays bindable afterward. Also pins repeatability (`PLAN.md:223`,
/// `cli.rs`'s `TunnelOpenArgs::dynamic` is `Vec<String>`): giving
/// `--dynamic` twice still collapses to one refusal, not a usage error.
#[test]
fn dynamic_forward_on_tunnel_open_is_unsupported_and_binds_nothing() {
    let fleet = Fleet::start();
    let port = free_port();

    let (code, envelope) = fleet.client.json(&[
        "tunnel",
        "open",
        HOST_ALIAS,
        "--dynamic",
        &port.to_string(),
        "--json",
    ]);
    assert_dynamic_forward_refusal("tunnel open --dynamic", &envelope, code);

    TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| {
        panic!(
            "port {port} was not re-bindable after the refusal (either --dynamic bound it \
             — a zero-resource violation — or an unrelated process took the ephemeral port \
             in between; the UNSUPPORTED envelope above already proves Ops::tunnel_open was \
             never reached, which is the stronger guarantee this test has): {e}"
        )
    });

    // Human mode agrees on the exit code and names the code on stderr
    // (`docs/CLI.md` §4: exit code must not depend on output mode).
    let human = fleet
        .client
        .qsh(&["tunnel", "open", HOST_ALIAS, "--dynamic", &port.to_string()]);
    assert_eq!(common::exit_code(&human), 255, "{human:?}");
    assert!(
        human.stdout.is_empty(),
        "human mode wrote to stdout: {:?}",
        String::from_utf8_lossy(&human.stdout)
    );
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(
        stderr.contains("(UNSUPPORTED)"),
        "human stderr must name the error code: {stderr:?}"
    );
    assert!(
        stderr.contains("P1"),
        "human stderr must disclose P1: {stderr:?}"
    );

    // Repeatability (`PLAN.md:223`): `--dynamic` given twice must still
    // collapse to a single `UNSUPPORTED` refusal, not a clap usage error
    // and not two envelopes — `fleet.client.json` already asserts
    // exactly one JSON stdout line (`common::sole_envelope`).
    let (code, envelope) = fleet.client.json(&[
        "tunnel",
        "open",
        HOST_ALIAS,
        "--dynamic",
        "18081",
        "--dynamic",
        "18082",
        "--json",
    ]);
    assert_dynamic_forward_refusal("tunnel open --dynamic (given twice)", &envelope, code);
}

/// The interactive form's `-D` (`qsh host -D <port>`) refuses before
/// `SessionOpen` is ever sent — before `-L`/`-R` on the same command line
/// are even looked at (`main.rs`'s `run_interactive`, right after the
/// `wants_json` gate) — so combining `-D` with a live `-L` still creates
/// nothing: no session on the host, no local listener bound.
///
/// This is also where the `docs/CLI.md` §7 precedence lives: `-D`'s own
/// `UNSUPPORTED` only shows up in human mode. With `--json`/`--jsonl`
/// present, §7's machine-mode gate answers `INVALID_ARGUMENT` first,
/// because the interactive form has no JSON output mode at all — `-D`
/// never gets a turn to report anything. Both outcomes are pinned here,
/// against the same fleet.
#[test]
fn dynamic_forward_on_the_interactive_form_creates_no_session_even_combined_with_local_forward() {
    let fleet = Fleet::start();
    let dynamic_port = free_port();
    let local_port = free_port();
    let dynamic_port_str = dynamic_port.to_string();
    let local_spec = format!("{local_port}:localhost:1");

    // Human mode: nothing outranks `-D` here, so its own `UNSUPPORTED`
    // (`docs/CLI.md` §6.9) is what stderr names.
    let human = fleet
        .client
        .qsh(&[HOST_ALIAS, "-D", &dynamic_port_str, "-L", &local_spec]);
    assert_eq!(common::exit_code(&human), 255, "{human:?}");
    assert!(
        human.stdout.is_empty(),
        "human mode wrote to stdout: {:?}",
        String::from_utf8_lossy(&human.stdout)
    );
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(
        stderr.contains("(UNSUPPORTED)"),
        "human stderr must name the error code: {stderr:?}"
    );
    assert!(
        stderr.contains("P1"),
        "human stderr must disclose P1: {stderr:?}"
    );

    TcpListener::bind(("127.0.0.1", dynamic_port)).unwrap_or_else(|e| {
        panic!(
            "port {dynamic_port} was not re-bindable after the refusal (either -D bound it \
             — a zero-resource violation — or an unrelated process took the ephemeral port; \
             the sessions check below is the authoritative proof that nothing was created): {e}"
        )
    });
    TcpListener::bind(("127.0.0.1", local_port)).unwrap_or_else(|e| {
        panic!(
            "port {local_port} was not re-bindable after the refusal (either the accompanying \
             -L bound its listener anyway — a fail-closed-ordering violation — or an unrelated \
             process took the ephemeral port; the sessions check below is the authoritative \
             proof that nothing was created): {e}"
        )
    });

    // Nothing was opened on the host — the refusal happened before
    // `SessionOpen` (`docs/PRD.md` §9, "no resource before
    // authorization"). Unlike the port re-bind checks above (which a
    // racing, unrelated process could in principle also fail), this is
    // the authoritative proof: it asks the host directly.
    let (code, listed) = fleet.client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert_eq!(
        listed["data"]["sessions"].as_array().map(Vec::len),
        Some(0),
        "-D (with an accompanying -L) still opened a session: {listed}"
    );

    // Machine mode: `docs/CLI.md` §7's json-mode gate answers first, so
    // the envelope names `INVALID_ARGUMENT`, not `-D`'s own
    // `UNSUPPORTED` — no `UNSUPPORTED` envelope exists for the
    // interactive form at all any more, so there is nothing here to
    // check an `error.command` field on.
    let args = [HOST_ALIAS, "-D", &dynamic_port_str, "--json"];
    let (json_code, json_envelope) = fleet.client.json(&args);
    assert_eq!(json_code, 255, "{json_envelope}");
    assert_eq!(json_envelope["ok"], false, "{json_envelope}");
    assert_eq!(
        json_envelope["error"]["code"], "INVALID_ARGUMENT",
        "§7 must win over §6.9's -D refusal when --json is present: {json_envelope}"
    );
}
