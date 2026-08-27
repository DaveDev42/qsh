//! Exit-code matrix (`docs/design/testing.md` L6): a table of
//! scenario → (exit code, `ok`, `error.code`), executed in **both** output
//! modes to make `docs/CLI.md` §4 ("output mode에 따라 exit code 의미가
//! 달라져서는 안 된다") a literal test.
//!
//! One `qsh serve` host is shared by the whole table — the scenarios differ
//! in what the *client* does, not in how the host is configured.
//!
//! **`tunnel.close` on a nonexistent id is idempotent, not a failure.**
//! `qsh-core`'s `Ops::tunnel_close` (`ops/tunnel.rs`) never returns `Err`,
//! and `docs/CLI.md` §6.9 now states this explicitly: closing an id
//! nothing holds is idempotent — `ok: true`, `data.closed: false` — the
//! same pattern §6.11 states for `trust.remove` ("존재하지 않는 이름을
//! 제거하는 것도 오류가 아니라 멱등이다"). `qsh-proto`'s
//! `TunnelCloseData::closed` doc (`types.rs:~665`) says the same thing at
//! the wire-type level. This file encodes that as the idempotent
//! `Succeeds(0)` + `data.closed == false` row below, not a `Fails` row.
//! `PLAN.md:220`'s Step 6(a) draft table once listed a failure row here
//! ("존재하지 않는 `tunnel close <id>` → 255/적절 코드"); that line has
//! been amended in this same change to match the contract instead of
//! needing a follow-up edit.

mod common;

use common::{CLIENT_ALIAS, Fleet, HOST_ALIAS, Sandbox, ServeGuard, exit_code, sole_envelope};
#[cfg(unix)]
use common::{ListenGuard, ReverseGuard, hosts_array, poll_until};

/// What a scenario produces, independent of output mode.
enum Outcome {
    /// clap rejected the command line: exit 2, nothing on stdout, no
    /// envelope in either mode (`docs/CLI.md` §4).
    Usage,
    /// The operation succeeded and the process exits with `code` (which is
    /// the remote's exit code for `qsh exec`).
    Succeeds(i32),
    /// The operation failed: exit 255, `ok:false` and this `error.code`.
    Fails(&'static str),
}

/// One row of the matrix.
struct Case<'a> {
    name: &'static str,
    sandbox: &'a Sandbox,
    args: &'a [&'a str],
    outcome: Outcome,
}

/// QSH runtime failures always exit 255 (`docs/CLI.md` §4).
const EXIT_RUNTIME_FAILURE: i32 = 255;

/// clap usage errors exit 2.
const EXIT_USAGE: i32 = 2;

/// Insert `--json` before the `--` separator (appending it after would make
/// it an argument of the *remote* command, not of `qsh`).
fn with_json<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut out = Vec::with_capacity(args.len() + 1);
    match args.iter().position(|arg| *arg == "--") {
        Some(at) => {
            out.extend_from_slice(&args[..at]);
            out.push("--json");
            out.extend_from_slice(&args[at..]);
        }
        None => {
            out.extend_from_slice(args);
            out.push("--json");
        }
    }
    out
}

#[test]
fn exit_codes_and_error_codes_are_identical_in_both_output_modes() {
    let fleet = Fleet::start();
    let rogue = fleet.rogue();
    let uninitialized = Sandbox::new();
    let fresh = Sandbox::new();
    // An address nothing can be dialed at, refused without waiting out the
    // dial timeout (the timeout path has its own fixture test).
    fleet
        .client
        .trust_add("deadport", Some("127.0.0.1:0"), &fleet.host_fingerprint);
    // A client whose *only* pinned host with an address is unreachable:
    // the `qsh sessions` fan-out is best-effort per host, but when no host
    // answers at all that is the call failing (`docs/CLI.md` §6.2).
    let all_dead = Sandbox::new();
    all_dead.init();
    all_dead.trust_add("deadport", Some("127.0.0.1:0"), &fleet.host_fingerprint);

    // `PLAN.md` M5 Step 6 PR 6b: `PERMISSION_DENIED`'s own row. A host
    // with no `acl.toml` at all (`ServeGuard::start_without_policy`,
    // `common/mod.rs`) loads `DenyAll` and refuses `forward.remote` at its
    // ACL gate before any reply goes out — the same shape `fixtures.rs`'s
    // `golden_permission_denied_fixture` uses to capture the envelope;
    // this row instead proves the exit code this file exists to pin: the
    // same 255 in both human and `--json` mode.
    let denied_host = Sandbox::new();
    let denied_client = Sandbox::new();
    let denied_host_fp = denied_host.fingerprint();
    let denied_client_fp = denied_client.fingerprint();
    denied_host.trust_add(CLIENT_ALIAS, None, &denied_client_fp);
    let denied_serve = ServeGuard::start_without_policy(&denied_host, &[]);
    denied_client.trust_add(HOST_ALIAS, Some(denied_serve.addr()), &denied_host_fp);

    // A real duplicate-name routing conflict (`PLAN.md` M3 Step 7 DoD 1,
    // `Ops::host.host.get`'s `resolve_route`): the *same* controller
    // machine — one `QSH_CONFIG_DIR`/`QSH_STATE_DIR`, so one trust store
    // and one `runtime_dir` — runs **two** independent `qsh listen`
    // daemons (`hosts_reverse.rs`'s own `dup` rig proves the merge-by-name
    // rule with one daemon `+` one forward pin; this is Step 7's new
    // case, two *live reverse* holders of the same name at once). Both
    // daemons resolve the same pinned fingerprint to the same name
    // ("dup"), so once the one target dials into both, `host.list`'s
    // reverse source (`admin_host_list_all`, unioned across every socket
    // under `runtime_dir`) sees two live, independent claims on "dup" —
    // exactly `ops::host`'s own
    // `resolve_host_route_async_is_invalid_argument_when_two_daemons_both_hold_it_live`
    // unit test, reproduced here against two real OS processes instead of
    // two fake admin daemons.
    #[cfg(unix)]
    let dup_controller = Sandbox::initialized();
    #[cfg(unix)]
    let dup_target = Sandbox::initialized();
    // Bound to `_` in each guard's own binding (not a block) so normal
    // end-of-function `Drop` order kills every child — no `mem::forget`,
    // no leaked processes; these just need to outlive the `host get dup`
    // case below, exactly like `fleet`/`rogue`/`all_dead` above.
    #[cfg(unix)]
    let (_listen_a, _listen_b, _reverse_a, _reverse_b) = {
        let target_fp = dup_target.fingerprint();
        let controller_fp = dup_controller.fingerprint();
        dup_controller.trust_add("dup", None, &target_fp);
        let listen_a = ListenGuard::start(&dup_controller);
        let listen_b = ListenGuard::start(&dup_controller);
        dup_target.trust_add("hub-a", Some(listen_a.addr()), &controller_fp);
        dup_target.trust_add("hub-b", Some(listen_b.addr()), &controller_fp);
        let reverse_a = ReverseGuard::start(&dup_target, "hub-a");
        let reverse_b = ReverseGuard::start(&dup_target, "hub-b");
        poll_until(
            "both live reverse registrations of \"dup\" to appear",
            std::time::Duration::from_secs(15),
            || {
                let hosts = hosts_array(&dup_controller);
                let live_dups = hosts
                    .iter()
                    .filter(|h| h["name"] == "dup" && h["connection_mode"] == "reverse")
                    .count();
                (live_dups == 2).then_some(())
            },
        );
        (listen_a, listen_b, reverse_a, reverse_b)
    };

    // `mut` is only needed for the `#[cfg(unix)] cases.push(..)` below —
    // unused (and clippy-denied) on the Windows leg, where that push is
    // compiled out entirely.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut cases = vec![
        Case {
            name: "usage: exec with no command after `--`",
            sandbox: &fleet.client,
            args: &["exec", HOST_ALIAS],
            outcome: Outcome::Usage,
        },
        Case {
            // No subcommand and no target. `qsh` alone is clap's
            // `arg_required_else_help`; `qsh --json` is our own branch, and
            // both owe the same answer — exit 2 with **nothing on stdout**,
            // because help text on stdout would break machine mode
            // (`docs/CLI.md` §2.2).
            name: "usage: global flags with no target and no subcommand",
            sandbox: &fleet.client,
            args: &[],
            outcome: Outcome::Usage,
        },
        Case {
            name: "version",
            sandbox: &fleet.client,
            args: &["version"],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            name: "init",
            sandbox: &fresh,
            args: &["init", "--key-store", "file"],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            name: "exec: remote exits 7",
            sandbox: &fleet.client,
            args: &["exec", HOST_ALIAS, "--", "sh", "-c", "exit 7"],
            outcome: Outcome::Succeeds(7),
        },
        Case {
            name: "exec: remote exits 255 (clamped to 254)",
            sandbox: &fleet.client,
            args: &["exec", HOST_ALIAS, "--", "sh", "-c", "exit 255"],
            outcome: Outcome::Succeeds(254),
        },
        Case {
            name: "exec: unpinned host name",
            sandbox: &fleet.client,
            args: &["exec", "nowhere", "--", "true"],
            outcome: Outcome::Fails("HOST_NOT_FOUND"),
        },
        Case {
            name: "exec: peer the host does not pin",
            sandbox: &rogue,
            args: &["exec", HOST_ALIAS, "--", "true"],
            outcome: Outcome::Fails("AUTH_FAILED"),
        },
        Case {
            name: "exec: nothing listening at the pinned address",
            sandbox: &fleet.client,
            args: &["exec", "deadport", "--", "true"],
            outcome: Outcome::Fails("CONNECTION_FAILED"),
        },
        Case {
            name: "exec: --timeout expires",
            sandbox: &fleet.client,
            args: &["exec", HOST_ALIAS, "--timeout", "300", "--", "sleep", "5"],
            outcome: Outcome::Fails("TIMEOUT"),
        },
        Case {
            name: "exec: no device identity",
            sandbox: &uninitialized,
            args: &["exec", HOST_ALIAS, "--", "true"],
            outcome: Outcome::Fails("CONFIG_ERROR"),
        },
        Case {
            name: "trust add: malformed fingerprint",
            sandbox: &fleet.client,
            args: &["trust", "add", "bad", "--fingerprint", "not-a-fingerprint"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // `PLAN.md` M5 Step 7 (c): a name outside `Action::ALL`'s
            // vocabulary is `INVALID_ARGUMENT` in both output modes — the
            // deliberate deviation from the Step 7 draft's literal "exit
            // `2`" text is that this is an `OpError` (exit `255`, this
            // file's `EXIT_RUNTIME_FAILURE`), not a clap usage error (exit
            // `2`): `--action`'s value is syntactically well-formed (a
            // plain string), just outside the runtime vocabulary, the same
            // "`INVALID_ARGUMENT` op error, not a clap usage error"
            // precedent `cli.rs`'s own `-L`/`-R` flag docs already state.
            // The rejection happens before any `acl.toml` load (`ops/
            // acl.rs`), so which sandbox runs this is irrelevant to the
            // outcome — `fleet.client` is reused rather than adding a new
            // one.
            name: "acl check: action name outside the vocabulary",
            sandbox: &fleet.client,
            args: &[
                "acl",
                "check",
                "--principal",
                "device:laptop",
                "--action",
                "not.a.real.action",
            ],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // §6.15's other vocabulary edge: a principal matching none of
            // the three shapes (`device:`/`user:`/`fp:sha256:`). Pinned
            // here at the op level, not only by `qsh-transport`'s
            // `FromStr` unit test — `Ops::acl_check` mapping the parse
            // error to `INVALID_ARGUMENT` (rather than, say, falling back
            // to a raw device principal) is exactly the kind of seam a
            // unit test one layer down cannot see.
            name: "acl check: principal outside the vocabulary",
            sandbox: &fleet.client,
            args: &[
                "acl",
                "check",
                "--principal",
                "not-a-principal",
                "--action",
                "exec.run",
            ],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            name: "usage: session close with an unknown signal",
            sandbox: &fleet.client,
            args: &["session", "close", "box/01K0SESSION", "--signal", "STOP"],
            outcome: Outcome::Usage,
        },
        Case {
            name: "usage: session write without --stdin or --data-b64",
            sandbox: &fleet.client,
            args: &["session", "write", "box/01K0SESSION"],
            outcome: Outcome::Usage,
        },
        Case {
            name: "usage: session resize with cols 0",
            sandbox: &fleet.client,
            args: &[
                "session",
                "resize",
                "box/01K0SESSION",
                "--cols",
                "0",
                "--rows",
                "1",
            ],
            outcome: Outcome::Usage,
        },
        Case {
            name: "session open",
            sandbox: &fleet.client,
            // Sessions are PTY-backed; a host without a PTY backend
            // answers UNSUPPORTED without creating anything (Windows host
            // is P2 — README "Known limitations", CLI.md §7).
            args: &["session", "open", HOST_ALIAS],
            #[cfg(unix)]
            outcome: Outcome::Succeeds(0),
            #[cfg(not(unix))]
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            name: "sessions",
            sandbox: &fleet.client,
            args: &["sessions", HOST_ALIAS],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            name: "sessions: every pinned host unreachable",
            sandbox: &all_dead,
            args: &["sessions"],
            outcome: Outcome::Fails("CONNECTION_FAILED"),
        },
        Case {
            name: "session get: unknown session id",
            sandbox: &fleet.client,
            args: &["session", "get", "box/01K0NOSUCHSESSION"],
            outcome: Outcome::Fails("SESSION_NOT_FOUND"),
        },
        Case {
            name: "session get: malformed session_ref",
            sandbox: &fleet.client,
            args: &["session", "get", "not-a-session-ref"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            name: "session get: unknown host alias",
            sandbox: &fleet.client,
            args: &["session", "get", "nowhere/01K0SESSION"],
            outcome: Outcome::Fails("HOST_NOT_FOUND"),
        },
        Case {
            // `--follow` is a pull loop on the same cursor primitive as
            // `--wait`, so its first pull fails exactly like a single read.
            name: "session read --follow: unknown session id",
            sandbox: &fleet.client,
            args: &["session", "read", "box/01K0SESSION", "--follow"],
            outcome: Outcome::Fails("SESSION_NOT_FOUND"),
        },
        Case {
            name: "session open: unpinned peer",
            sandbox: &rogue,
            args: &["session", "open", HOST_ALIAS],
            outcome: Outcome::Fails("AUTH_FAILED"),
        },
        Case {
            // `Ops::tunnel_open`'s pre-flight is `spec_from_request` then
            // `self.connect(&req.host)` — the same `HOST_NOT_FOUND`
            // resolution every other unpinned-host row in this table
            // exercises, just reached through `tunnel.open` instead
            // (`docs/CLI.md` §6.9, `PLAN.md` M4 Step 6).
            name: "tunnel open: unresolved host",
            sandbox: &fleet.client,
            args: &[
                "tunnel",
                "open",
                "nowhere",
                "--local",
                "18080:localhost:3000",
            ],
            outcome: Outcome::Fails("HOST_NOT_FOUND"),
        },
        Case {
            // Loopback-only for `-R` is host-side, not a client
            // pre-flight (`qsh_core::parse_remote_forwards`'s own doc:
            // "a non-loopback `-R` therefore parses `Ok` here and fails
            // later, on the peer's `RemoteForwardOpened`/`Error` reply").
            // This row drives that real round trip against `fleet`'s
            // live host — a genuine CLI-binary-reachable producer, not a
            // host-side-only path the harness cannot exercise
            // (`docs/design/protocol.md` §7, `docs/PRD.md` §9).
            name: "tunnel open: non-loopback -R bind rejected by the peer",
            sandbox: &fleet.client,
            args: &[
                "tunnel",
                "open",
                HOST_ALIAS,
                "--remote",
                "0.0.0.0:19000:localhost:9",
            ],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // `PLAN.md` M5 Step 6 PR 6b: `forward.remote`'s ACL gate
            // (`Server::authorize_and_bind_remote_forward`) runs *before*
            // the loopback-only check above and before any reply goes
            // out, so a denying host (`denied_host`/`denied_client`, no
            // `acl.toml` at all — `DenyAll`) answers `PERMISSION_DENIED`
            // on `tunnel.open`'s own top-level envelope, not a mid-tunnel
            // side channel.
            name: "tunnel open --remote: denied by policy (no acl.toml)",
            sandbox: &denied_client,
            args: &[
                "tunnel",
                "open",
                HOST_ALIAS,
                "--remote",
                "9000:localhost:9000",
            ],
            outcome: Outcome::Fails("PERMISSION_DENIED"),
        },
        Case {
            // `-D` refuses before `Ops::tunnel_open` is even called
            // (`main.rs`'s `run_tunnel_open`), so no peer round trip
            // happens here at all — included in this table anyway
            // because it is exactly the kind of envelope-producing
            // failure this matrix exists to pin (`docs/CLI.md` §6.9,
            // `PLAN.md` M4 Step 6, DoD 5).
            name: "tunnel open: -D is UNSUPPORTED",
            sandbox: &fleet.client,
            args: &["tunnel", "open", HOST_ALIAS, "--dynamic", "1080"],
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            // `tunnel.close` is idempotent by contract (`docs/CLI.md`
            // §6.9's `data.closed` shape, mirroring `trust.remove`'s own
            // idempotent-delete precedent at §6.11) — closing an id
            // nothing holds is `ok:true`/`data.closed:false`/exit `0`,
            // never an error (`qsh-core`'s `Ops::tunnel_close` never
            // returns `Err`). `PLAN.md`'s Step 6 draft table expected a
            // failure row here; `docs/CLI.md` wins the conflict
            // (`CLAUDE.md` "when PLAN.md and CLI.md conflict, CLI.md
            // wins") — see this file's module doc; `PLAN.md:220` was
            // amended in this same change.
            name: "tunnel close: nonexistent id is a no-op, not a failure",
            sandbox: &fleet.client,
            args: &["tunnel", "close", "01K0NOSUCHTUNNEL"],
            outcome: Outcome::Succeeds(0),
        },
    ];

    #[cfg(unix)]
    cases.push(Case {
        name: "host get: duplicate name held live by two reverse daemons at once",
        sandbox: &dup_controller,
        args: &["host", "get", "dup"],
        outcome: Outcome::Fails("INVALID_ARGUMENT"),
    });

    for case in &cases {
        check(case);
    }

    // The generic `Succeeds(0)` check above only asserts `ok:true`; the
    // idempotent-delete shape (`docs/CLI.md` §6.9, this file's own module
    // doc on the `PLAN.md` conflict) needs its own look at `data.closed`.
    let args = ["tunnel", "close", "01K0NOSUCHTUNNEL", "--json"];
    let out = fleet.client.qsh(&args);
    assert_eq!(exit_code(&out), 0, "tunnel close nonexistent id: {out:?}");
    let envelope = sole_envelope(&out.stdout, &args);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(
        envelope["data"]["closed"], false,
        "tunnel close on an id nothing holds must report closed:false, not an error: {envelope}"
    );

    // `qsh sessions` with no host fans out over every pinned host that has
    // an address (here: the live host plus the unreachable `deadport`).
    // Best-effort: an unreachable host is reported in `data.unreachable`
    // and must not hide the sessions the live host reported, nor turn the
    // call into a failure (`docs/CLI.md` §6.2). The `session open` rows
    // above left live sessions behind, so the list is non-empty.
    let args = ["sessions", "--json"];
    let out = fleet.client.qsh(&args);
    assert_eq!(
        exit_code(&out),
        0,
        "sessions fan-out: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let envelope = sole_envelope(&out.stdout, &args);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let sessions = envelope["data"]["sessions"]
        .as_array()
        .expect("sessions array");
    // Only a PTY host actually has sessions to report; elsewhere the list
    // is legitimately empty and what matters is that the dead peer did not
    // turn the fan-out into a failure.
    #[cfg(unix)]
    assert!(
        sessions.iter().any(|s| s["host"] == HOST_ALIAS),
        "the reachable host's sessions survive a peer being down: {envelope}"
    );
    #[cfg(not(unix))]
    assert!(
        sessions.iter().all(|s| s["host"] == HOST_ALIAS),
        "no foreign hosts in the list: {envelope}"
    );
    let unreachable = envelope["data"]["unreachable"]
        .as_array()
        .expect("unreachable array");
    assert_eq!(unreachable.len(), 1, "{envelope}");
    assert_eq!(unreachable[0]["host"], "deadport", "{envelope}");
    assert_eq!(unreachable[0]["code"], "CONNECTION_FAILED", "{envelope}");

    // Human mode: the same warning is a stderr diagnostic, never a table
    // row, and stdout still lists the reachable host's sessions (§2.2).
    let human = fleet.client.qsh(&["sessions"]);
    assert_eq!(exit_code(&human), 0);
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(stderr.contains("deadport"), "human stderr was {stderr:?}");
    assert!(
        !String::from_utf8_lossy(&human.stdout).contains("deadport"),
        "unreachable hosts are not table rows"
    );
}

fn check(case: &Case<'_>) {
    let name = case.name;
    let json_args = with_json(case.args);
    let json = case.sandbox.qsh(&json_args);
    let human = case.sandbox.qsh(case.args);
    let (json_code, human_code) = (exit_code(&json), exit_code(&human));

    assert_eq!(
        json_code,
        human_code,
        "{name}: exit code must not depend on the output mode (docs/CLI.md §4); \
         json stderr: {}",
        String::from_utf8_lossy(&json.stderr)
    );

    match case.outcome {
        Outcome::Usage => {
            assert_eq!(json_code, EXIT_USAGE, "{name}");
            assert!(
                json.stdout.is_empty(),
                "{name}: usage errors write no stdout"
            );
            assert!(human.stdout.is_empty(), "{name}");
        }
        Outcome::Succeeds(expected) => {
            assert_eq!(json_code, expected, "{name}");
            let envelope = sole_envelope(&json.stdout, &json_args);
            assert_eq!(envelope["ok"], true, "{name}: {envelope}");
            assert!(envelope.get("error").is_none(), "{name}: {envelope}");
        }
        Outcome::Fails(code) => {
            assert_eq!(json_code, EXIT_RUNTIME_FAILURE, "{name}");
            let envelope = sole_envelope(&json.stdout, &json_args);
            assert_eq!(envelope["ok"], false, "{name}: {envelope}");
            assert_eq!(envelope["error"]["code"], code, "{name}: {envelope}");

            // Human mode reports the same failure on stderr and keeps
            // stdout clean (`docs/CLI.md` §2.2).
            assert!(
                human.stdout.is_empty(),
                "{name}: human-mode errors belong on stderr, stdout was {:?}",
                String::from_utf8_lossy(&human.stdout)
            );
            let stderr = String::from_utf8_lossy(&human.stderr);
            assert!(
                stderr.contains(&format!("({code})")),
                "{name}: human stderr must name the error code, was {stderr:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// `qsh attach` on an unregistered host — deliberately **not** a `Case`
// row above. `run_interactive` (`main.rs`) answers `--json` with a
// hard-coded `UNSUPPORTED` (`tui::json_mode_unsupported`) *before* it ever
// calls `Ops::connect`/`resolve_route` — a pre-existing, Step-7-unrelated
// design fact (`docs/CLI.md` §7: interactive commands have no JSON form
// at all). `check`'s machinery requires the json-mode envelope's
// `error.code` to equal the human-mode one, which this command structurally
// cannot satisfy (json mode never reaches host resolution to report
// `HOST_NOT_FOUND` in the first place) — so this is its own human-mode-
// only assertion, the same "separate assertion, not a matrix row" shape
// `PLAN.md` already prescribes for the reverse-refusal/listen-conflict
// cases below.
// ---------------------------------------------------------------------

#[test]
fn attach_on_an_unregistered_host_is_host_not_found_and_stdout_stays_empty() {
    let sandbox = Sandbox::initialized();
    let output = sandbox.qsh(&["attach", "nowhere/01K0SESSION"]);

    assert_eq!(exit_code(&output), EXIT_RUNTIME_FAILURE, "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "attach's routing failure must never write to stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one stderr line: {stderr:?}"
    );
    // The error the single stderr line names is the one platform-difference
    // in this command: on unix, interactive attach reaches route
    // resolution and reports `HOST_NOT_FOUND` for the missing registration;
    // on Windows the PTY/TTY path is `cfg(unix)`, so `run_interactive`
    // answers `UNSUPPORTED` ("needs a POSIX terminal") *before* it ever
    // reaches host resolution — interactive mode is the PTY/TTY path, which
    // is `cfg(unix)` (`docs/CLI.md` §7 human interactive mode) — a
    // pre-existing platform fact, not a Step-7 regression. Everything else
    // this test pins (exit 255, empty stdout, exactly one stderr line) is
    // identical on both, so the assertion branches only on the code name.
    let expected_code = if cfg!(unix) {
        "(HOST_NOT_FOUND)"
    } else {
        "(UNSUPPORTED)"
    };
    assert!(
        lines[0].contains(expected_code),
        "stderr must name {expected_code}: {stderr:?}"
    );
}

// ---------------------------------------------------------------------
// Interactive `-D` — deliberately **not** a `Case` row above, for the
// same reason as the attach test just above: the two output modes
// disagree *on purpose*. `docs/CLI.md` §7 (~line 662) states that
// `--json`/`--jsonl` on either interactive form is refused with
// `INVALID_ARGUMENT` **before a session is even opened**, because the
// interactive form has no machine mode at all; §6.9 separately states
// that `-D` itself is always `UNSUPPORTED`. `run_interactive` (`main.rs`)
// checks `wants_json` first and the `-D` refusal second, so with
// `--json`/`--jsonl` present the §7 gate answers `INVALID_ARGUMENT` and
// `-D`'s own `UNSUPPORTED` never gets a turn — human mode is the only
// place `-D`'s `UNSUPPORTED` is observable. `check`'s machinery asserts
// the *same* `error.code` in both modes, which this command structurally
// cannot satisfy, so it gets its own two-part assertion instead of a
// matrix row.
// ---------------------------------------------------------------------

#[test]
fn interactive_dash_d_is_unsupported_in_human_mode_but_json_mode_wins_on_precedence() {
    let sandbox = Sandbox::initialized();

    // Human mode: nothing outranks `-D` here, so its own `UNSUPPORTED`
    // (`docs/CLI.md` §6.9) is what stderr names.
    let human = sandbox.qsh(&[HOST_ALIAS, "-D", "1080"]);
    assert_eq!(exit_code(&human), EXIT_RUNTIME_FAILURE, "{human:?}");
    assert!(
        human.stdout.is_empty(),
        "interactive -D refusal must never write to stdout: {:?}",
        String::from_utf8_lossy(&human.stdout)
    );
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(
        stderr.contains("(UNSUPPORTED)"),
        "stderr must name UNSUPPORTED: {stderr:?}"
    );
    assert!(
        stderr.contains("P1"),
        "stderr must carry the -D P1 message: {stderr:?}"
    );

    // Machine mode: §7's json-mode gate answers first, so the envelope
    // names `INVALID_ARGUMENT`, not `-D`'s own `UNSUPPORTED`.
    let args = [HOST_ALIAS, "-D", "1080", "--json"];
    let json = sandbox.qsh(&args);
    assert_eq!(exit_code(&json), EXIT_RUNTIME_FAILURE, "{json:?}");
    let envelope = sole_envelope(&json.stdout, &args);
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "INVALID_ARGUMENT",
        "§7 must win over §6.9's -D refusal when --json is present: {envelope}"
    );
}

// ---------------------------------------------------------------------
// `qsh listen` bind conflict and `qsh reverse` registration refusal:
// separate assertions, not matrix rows — neither `Command::Listen` nor
// `Command::Reverse` produces a `qsh.cli/v1` envelope at all
// (`report_long_running_setup_error`'s own module docs), so they cannot
// be expressed as an `Outcome` the shared `check()` machinery understands.
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn qsh_listen_bind_conflict_is_one_stderr_line_exit_255_and_zero_stdout() {
    let sandbox = Sandbox::initialized();
    let holder = ListenGuard::start(&sandbox);

    let output = ListenGuard::run_to_completion(&sandbox, holder.addr(), &[]);

    assert_eq!(exit_code(&output), EXIT_RUNTIME_FAILURE, "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "a bind conflict must never write to stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one stderr line: {stderr:?}"
    );
    assert!(
        lines[0].starts_with("qsh: cannot listen on"),
        "stderr: {stderr:?}"
    );
    assert!(lines[0].contains("(CONFIG_ERROR)"), "stderr: {stderr:?}");

    drop(holder);
}

/// A running `qsh -v reverse <controller>` child with both streams fully
/// captured — deliberately not `common::ReverseGuard` (which discards its
/// child's output), since this scenario's entire point is inspecting
/// stdout/stderr while the process is still alive and retrying.
#[cfg(unix)]
struct CapturedReverse {
    child: std::process::Child,
    stdout: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    stderr: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

#[cfg(unix)]
impl CapturedReverse {
    fn start(sandbox: &Sandbox, controller: &str) -> Self {
        // Incremental line reads, not `read_to_end` — the whole point of
        // this struct is inspecting output *while the process is still
        // running*, and `read_to_end` would block on the pipe until the
        // child closes it (i.e. exits), which this scenario's process
        // deliberately never does on its own.
        use std::io::BufRead as _;
        let mut child = sandbox
            .command(&["-v", "reverse", controller])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn qsh reverse");
        let stdout = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let out_pipe = child.stdout.take().expect("stdout pipe");
        let err_pipe = child.stderr.take().expect("stderr pipe");
        {
            let sink = std::sync::Arc::clone(&stdout);
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(out_pipe)
                    .lines()
                    .map_while(Result::ok)
                {
                    let mut buf = sink.lock().unwrap_or_else(|e| e.into_inner());
                    buf.extend_from_slice(line.as_bytes());
                    buf.push(b'\n');
                }
            });
        }
        {
            let sink = std::sync::Arc::clone(&stderr);
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(err_pipe)
                    .lines()
                    .map_while(Result::ok)
                {
                    let mut buf = sink.lock().unwrap_or_else(|e| e.into_inner());
                    buf.extend_from_slice(line.as_bytes());
                    buf.push(b'\n');
                }
            });
        }
        Self {
            child,
            stdout,
            stderr,
        }
    }

    fn stdout_so_far(&self) -> Vec<u8> {
        self.stdout
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn stderr_so_far(&self) -> Vec<u8> {
        self.stderr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// `SIGTERM`, bounded wait for the graceful-shutdown line, same
    /// discipline as `hosts_reverse.rs::ReverseGuard::shut_down`.
    fn shut_down(mut self) {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[cfg(unix)]
impl Drop for CapturedReverse {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A controller the target does **not** pin — `qsh reverse`'s registration
/// attempt is refused (`AUTH_FAILED`, unpinned peer) on every attempt. Per
/// `reverse/target.rs`'s own module docs ("Registration is the target's
/// only reachability path, so it is never fatal"), this is **not** a
/// one-shot setup failure: the process retries forever with backoff and
/// never exits on its own — the opposite shape from `qsh listen`'s bind
/// conflict above. What this test actually pins down (deviating from the
/// task brief's literal "exit 255" framing, which does not hold for this
/// scenario as landed in Step 4 — see this stage's own reported
/// deviations) is the two guarantees that *do* hold unconditionally for a
/// long-running setup mode: stdout stays byte-for-byte empty no matter how
/// many attempts fail, and the process is still alive (retrying, not
/// crashed, not hung on the first attempt) well past the time a single
/// dial could plausibly take.
#[cfg(unix)]
#[test]
fn qsh_reverse_registration_refusal_retries_forever_and_never_writes_stdout() {
    let controller = Sandbox::initialized();
    let target = Sandbox::initialized();
    let controller_fp = controller.fingerprint();
    // Deliberately no `controller.trust_add` for the target's fingerprint
    // — every attempt is refused.
    let listen = ListenGuard::start(&controller);
    target.trust_add("hub", Some(listen.addr()), &controller_fp);

    let mut reverse = CapturedReverse::start(&target, "hub");

    // Deadline-polled, not a fixed sleep (no `sleep()`-as-synchronization
    // — this suite spawns many real `qsh listen`/`qsh reverse`/`qsh serve`
    // children concurrently, so a fixed short sleep is a flake on a loaded
    // box on the way in and wasted wall-clock time on a fast one): wait
    // until at least one refused attempt and one structured retry event
    // have actually been logged, bounded well past what a single dial +
    // refusal + backoff should ever take.
    poll_until(
        "a refused registration attempt and a retry event to be logged",
        std::time::Duration::from_secs(15),
        || {
            let stderr_bytes = reverse.stderr_so_far();
            let stderr = String::from_utf8_lossy(&stderr_bytes);
            (stderr.contains("AUTH_FAILED") && stderr.contains("\"event\":\"retry\"")).then_some(())
        },
    );

    assert!(
        matches!(reverse.child.try_wait(), Ok(None)),
        "a refused registration must not end the process — it retries forever"
    );
    assert!(
        reverse.stdout_so_far().is_empty(),
        "qsh reverse must never write to stdout, refused or not: {:?}",
        String::from_utf8_lossy(&reverse.stdout_so_far())
    );

    reverse.shut_down();
    drop(listen);
}
