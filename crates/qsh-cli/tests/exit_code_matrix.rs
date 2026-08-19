//! Exit-code matrix (`docs/design/testing.md` L6): a table of
//! scenario → (exit code, `ok`, `error.code`), executed in **both** output
//! modes to make `docs/CLI.md` §4 ("output mode에 따라 exit code 의미가
//! 달라져서는 안 된다") a literal test.
//!
//! One `qsh serve` host is shared by the whole table — the scenarios differ
//! in what the *client* does, not in how the host is configured.

mod common;

use common::{Fleet, HOST_ALIAS, Sandbox, exit_code, sole_envelope};

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

    let cases = [
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
    ];

    for case in &cases {
        check(case);
    }

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
