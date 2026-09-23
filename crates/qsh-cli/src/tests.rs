use std::sync::{Arc, Mutex};

use qsh_core::telemetry::{Recovery, RecoveryReport, TARGET};
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;

use super::*;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

impl LineSink for Captured {
    fn write_line(&self, line: &str) {
        self.0.lock().expect("not poisoned").push(line.to_string());
    }
}

/// Run `body` with only the recovery layer installed, exactly as
/// `init_tracing` composes it, and return the lines it wrote.
fn capture(spec: Option<&str>, quiet: bool, body: impl FnOnce()) -> Vec<String> {
    let sink = Captured::default();
    let default = if quiet { "error" } else { "warn" };
    let recovery_default = format!("{default},{TARGET}=info");
    let enabled = !quiet;
    let layer = RecoveryLayer(sink.clone())
        .with_filter(env_filter(spec, &recovery_default))
        .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
            enabled && meta.target() == TARGET
        }));
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, body);
    let lines = sink.0.lock().expect("not poisoned");
    lines.clone()
}

/// `docs/CLI.md` §6.4: at default verbosity a recovery is one line of
/// pure JSON on stderr — no level, no timestamp, no target prefix.
#[test]
fn a_recovery_is_one_pure_json_line_at_default_verbosity() {
    let report = RecoveryReport::new(
        Recovery::Resumed,
        std::time::Duration::from_millis(412),
        "mac/01K0ABCD",
        0,
    );
    let expected = report.to_json_line();
    let lines = capture(None, false, || report.emit());
    assert_eq!(lines, vec![expected.clone()], "expected exactly one line");
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).expect("the line is pure JSON");
    assert_eq!(parsed["recovery"], "resumed");
    assert_eq!(parsed["time_to_recovery_ms"], 412);
    assert_eq!(parsed["session_ref"], "mac/01K0ABCD");
}

/// An ordinary diagnostic on another target never reaches this layer,
/// so the stream stays parseable line by line.
#[test]
fn only_the_recovery_target_reaches_the_layer() {
    let lines = capture(None, false, || {
        tracing::info!("an ordinary diagnostic");
        tracing::warn!(target: "qsh::something", "another one");
    });
    assert!(lines.is_empty(), "{lines:?}");
}

/// `-q` means no diagnostics, and an explicit `QSH_LOG` governs the
/// recovery stream like every other one.
#[test]
fn quiet_and_an_explicit_log_level_both_silence_it() {
    let report = RecoveryReport::new(Recovery::Failed, std::time::Duration::ZERO, "mac/01K0", 0);
    assert!(capture(None, true, || report.emit()).is_empty(), "-q");
    assert!(
        capture(Some("off"), false, || report.emit()).is_empty(),
        "off"
    );
    assert!(
        capture(Some("error"), false, || report.emit()).is_empty(),
        "error"
    );
    // …and asking for it explicitly still works.
    assert_eq!(
        capture(Some("qsh::recovery=info"), false, || report.emit()).len(),
        1
    );
}

/// `docs/CLI.md` §6.13: a `qsh listen` registration event
/// (`RegistrationEvent`, `qsh_core::reverse::listen::TARGET`) is one
/// line of pure JSON on stderr **at default verbosity** — exactly the
/// same promise §6.4 makes for a recovery record, and `init_tracing`
/// now wires a dedicated layer for it (mirroring `recovery`) instead of
/// leaving it to fall through the `warn`-default human layer, which
/// would either drop it entirely or wrap it in a timestamp/level prefix
/// (adversarial review finding). This test pins the *composition* —
/// the same `EnvFilter`/`filter_fn` shape `init_tracing` builds — not
/// `RegistrationEvent` itself, which is private to `qsh-core` and
/// already pins its own JSON shape in `reverse::listen`'s unit tests.
#[test]
fn a_reverse_registration_event_is_one_pure_json_line_at_default_verbosity() {
    let target = qsh_core::reverse::listen::TARGET;
    let sink = Captured::default();
    let default = "warn"; // `cli.verbose == 0`, `cli.quiet == false`
    let reverse_default = format!("{default},{target}=info");
    let layer = RecoveryLayer(sink.clone())
        .with_filter(env_filter(None, &reverse_default))
        .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
            meta.target() == target
        }));
    let subscriber = tracing_subscriber::registry().with(layer);
    let line =
        r#"{"event":"registered","host":"widget","fingerprint":"sha256:abc","generation":0}"#;
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: qsh_core::reverse::listen::TARGET, "{}", line);
    });
    let lines = sink.0.lock().expect("not poisoned");
    assert_eq!(
        *lines,
        vec![line.to_string()],
        "visible at default verbosity, byte-identical, no prefix"
    );
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).expect("the line is pure JSON");
    assert_eq!(parsed["event"], "registered");
    assert_eq!(parsed["host"], "widget");
}

/// `docs/CLI.md` §2.2/§6.12/§6.13: `qsh serve`/`qsh listen`/`qsh
/// reverse` write zero bytes to stdout on every path, envelope
/// included — even a setup failure this early (`Ops::from_env()`,
/// before `run_serve`/`run_listen`/`run_reverse` exist to apply their
/// own stderr-only error path). `run`'s dispatch on an
/// `Ops::from_env()` failure must therefore route all three to
/// [`report_long_running_setup_error`] (stderr only) rather than
/// [`report_error`] (which prints a `qsh.cli/v1` envelope to stdout
/// whenever `--json`/`--jsonl` was passed — `qsh serve` did exactly
/// this until the PLAN.md Step 3.5 audit follow-up caught it). This
/// pins the routing decision itself; `report_long_running_setup_error`'s
/// own body is `human::print_error` verbatim, already proven
/// stderr-only.
#[test]
fn ops_from_env_failure_routes_serve_listen_and_reverse_off_the_envelope_path() {
    assert_eq!(
        long_running_setup_mode(&Some(Command::Serve { bind: None })),
        Some(SERVE_MODE)
    );
    assert_eq!(
        long_running_setup_mode(&Some(Command::Listen { bind: None })),
        Some(LISTEN_MODE)
    );
    assert_eq!(
        long_running_setup_mode(&Some(Command::Reverse {
            controller: "widget".to_string(),
            offered_name: None,
        })),
        Some(REVERSE_MODE)
    );
    // Every ordinary operation keeps using `report_error`'s envelope
    // path.
    assert_eq!(long_running_setup_mode(&Some(Command::Version)), None);
    assert_eq!(long_running_setup_mode(&None), None);
}

#[test]
fn remote_exit_code_passes_through_except_255() {
    assert_eq!(remote_exit_code_to_process_exit(0), 0);
    assert_eq!(remote_exit_code_to_process_exit(7), 7);
    assert_eq!(remote_exit_code_to_process_exit(254), 254);
    assert_eq!(remote_exit_code_to_process_exit(255), 254);
    assert_eq!(remote_exit_code_to_process_exit(-1), 254);
    assert_eq!(remote_exit_code_to_process_exit(300), 254);
}

/// `finish`'s laziness is the structural half of D3
/// (`docs/CLI.md` §2.2): in machine mode it must never call the human
/// closure at all, which is what keeps `qsh trust invite --json` from
/// making a route query it will not print. This does not go through
/// `qsh trust invite`'s own dispatch arm (that needs a live `Ops` and
/// real config paths) — it exercises `finish` directly with a fixed
/// `Ok` result and a closure that records whether it ran, which is
/// exactly the seam `run`'s dispatch arm calls through.
#[test]
fn finish_never_calls_the_human_closure_in_machine_mode() {
    let cli = Cli::parse_from(["qsh", "--json", "trust", "invite"]);
    assert!(cli.wants_json());

    let called = std::cell::Cell::new(false);
    let data = qsh_proto::TrustInviteData {
        code: "abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab".to_string(),
        expires_at: "2026-08-31T00:10:00Z".to_string(),
        accept_command: "qsh trust accept <address> abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab"
            .to_string(),
    };
    let exit = finish(&cli, TrustInviteOp::COMMAND, Ok(data), |_data| {
        called.set(true);
        Ok(())
    });
    assert_eq!(exit, 0);
    assert!(
        !called.get(),
        "the human closure must not run when --json is set"
    );
}

/// The mechanical guard the test above cannot provide.
/// `finish_never_calls_the_human_closure_in_machine_mode` exercises
/// `finish` with a hand-built closure, not `qsh trust invite`'s real
/// one, so it never runs the real dispatch arm end to end and would
/// not fail if `ops.invite_address_advice()` were called
/// unconditionally instead of only inside the human closure. That
/// mutation still compiles, still keeps `dead_code` quiet (the call
/// site still exists), and still prints nothing extra in machine
/// mode, since a discarded return value writes no stdout line either
/// way. `jsonl_purity.rs`'s
/// `trust_invite_keeps_stdout_pure_json_and_free_of_the_address_block_at_every_verbosity`
/// is blind to it for the same reason: it reads stdout, and the hoist
/// changes no byte of stdout.
///
/// This drives [`dispatch`] itself — the exact function `run` calls
/// in production — against a real `Ops` over a temporary,
/// test-owned config/state directory pair standing in for
/// `Ops::from_env()`'s environment lookup, and checks the one effect
/// that *does* tell the two shapes apart:
/// `qsh_core::trust::invite_address::route_query_count()`, an
/// `AtomicUsize` `qsh-core`'s `observe_source_addresses` increments
/// on every call. An **integration** test spawning the built `qsh`
/// binary as a subprocess (the `Sandbox`/`sandbox.qsh(..)` pattern
/// `crates/qsh-cli/tests/*.rs` uses) cannot observe this counter at
/// all — it lives in the child process's own address space, gone the
/// moment that process exits, and unreadable from the parent test
/// process even while it runs. Only a test compiled into the same
/// binary as the code under test, calling `dispatch` in-process
/// exactly as `run` does, can read it — which is why this test lives
/// here, in `qsh-cli`'s own `#[cfg(test)]` module, rather than under
/// `crates/qsh-cli/tests/`.
#[test]
fn trust_invite_json_mode_makes_no_route_query_while_human_mode_does() {
    use qsh_core::Paths;
    use qsh_core::trust::invite_address::route_query_count;

    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(tmp.path().join("config"), tmp.path().join("state"));
    std::fs::create_dir_all(&paths.config_dir).expect("create config dir");
    std::fs::create_dir_all(&paths.state_dir).expect("create state dir");

    let before = route_query_count();

    let json_cli = Cli::parse_from(["qsh", "--json", "trust", "invite"]);
    let exit = dispatch(&json_cli, Ops::new(paths.clone()));
    assert_eq!(
        exit, 0,
        "trust invite --json must succeed on a fresh config dir"
    );
    assert_eq!(
        route_query_count(),
        before,
        "machine mode must make no route query at all"
    );

    let human_cli = Cli::parse_from(["qsh", "trust", "invite"]);
    let exit = dispatch(&human_cli, Ops::new(paths));
    assert_eq!(
        exit, 0,
        "trust invite (human mode) must succeed on a fresh config dir"
    );
    assert_eq!(
        route_query_count(),
        before + 1,
        "human mode must make exactly one route query"
    );
}

/// [`TunnelOpenArgs`] with `--local` and every other field at its
/// clap default, for the `--wait` wiring tests below — mirrors what
/// `Cli::parse_from` would produce for `qsh tunnel open host -L
/// 8080:localhost:3000` before any `--wait` is applied.
fn local_tunnel_open_args() -> TunnelOpenArgs {
    TunnelOpenArgs {
        host: "box".to_string(),
        local: Some("8080:localhost:3000".to_string()),
        remote: None,
        dynamic: Vec::new(),
        wait: 0,
    }
}

/// issue #4 item 5a review finding: nothing previously drove `--wait`
/// through [`build_tunnel_open_request`], so a mutation that dropped
/// `wait_ms` from the built request entirely (or hardcoded `None`)
/// passed the whole suite (`crates/qsh-cli/tests/` never constructs a
/// `TunnelOpenReq`, and `cli.rs`'s own `tunnel_open_wait_defaults_to_
/// zero_and_parses_when_given` only asserts the clap field, never
/// builds a request). Pins both directions: a given `--wait` reaches
/// `wait_ms` as `Some`, and the clap default `0` maps to `None` —
/// the byte-identical-to-before-this-flag guarantee (`docs/CLI.md`
/// §6.9).
#[test]
fn build_tunnel_open_request_wires_wait_into_wait_ms() {
    let mut args = local_tunnel_open_args();
    args.wait = 30_000;
    let request = build_tunnel_open_request(&args).expect("valid -L spec");
    assert_eq!(request.wait_ms, Some(30_000));

    let bare = local_tunnel_open_args();
    let request = build_tunnel_open_request(&bare).expect("valid -L spec");
    assert_eq!(
        request.wait_ms, None,
        "the clap default (0) must map to None, not Some(0)"
    );
}
