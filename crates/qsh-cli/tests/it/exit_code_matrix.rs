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
//! M4 plan Step 6(a) (2473c88)'s draft table once listed a failure row here
//! ("존재하지 않는 `tunnel close <id>` → 255/적절 코드"); that line has
//! been amended in this same change to match the contract instead of
//! needing a follow-up edit.

use crate::common;
use crate::ssh_golden;

use common::{CLIENT_ALIAS, Fleet, HOST_ALIAS, Sandbox, ServeGuard, exit_code, sole_envelope};

/// What a scenario produces, independent of output mode.
enum Outcome {
    /// clap rejected the command line: exit 2, nothing on stdout, no
    /// envelope in either mode (`docs/CLI.md` §4).
    Usage,
    /// A mistake in the root ssh form (`qsh [ssh options] host [command]`):
    /// exit 255 like ssh, nothing on stdout, no envelope in either mode
    /// (`docs/CLI.md` §4, ADR-0051 decision 9). A subcommand's own mistake
    /// is [`Outcome::Usage`], exit 2.
    RootUsage,
    /// The operation succeeded and the process exits with `code` (which is
    /// the remote's exit code for `qsh exec`).
    Succeeds(i32),
    /// The operation failed: exit 255, `ok:false` and this `error.code`.
    Fails(&'static str),
    /// Exit 255, this code named in the stderr line — but, unlike
    /// `Fails`, **no `qsh.cli/v1` envelope at all, in either output
    /// mode**: `qsh serve`/`qsh listen`/`qsh reverse` are long-running
    /// setup modes (`long_running_setup_mode`) whose every failure path
    /// goes through `report_long_running_setup_error`, never
    /// `report_error` — `--json` changes nothing for them (`docs/CLI.md`
    /// §2.2/§6.12/§6.13, ROADMAP M9 (b)). This variant is for
    /// the subset of those failures that *do* run to completion (a
    /// synchronous input-validation refusal like `--to`/`--bind`
    /// together) rather than retrying forever, which is why
    /// `qsh_reverse_registration_refusal_retries_forever_and_never_writes_stdout`
    /// below stays a separate assertion instead of a row using this
    /// variant.
    RefusedWithoutEnvelope(&'static str),
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

    // M5 plan Step 6 (2473c88) PR 6b: `PERMISSION_DENIED`'s own row. A host
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

    // ADR-0013: a chain of two certificates on disk, for the
    // `trust add --cert-file` `INVALID_ARGUMENT` row below. Built from two
    // real `identity export`s rather than a hand-written fixture, so this
    // exercises the exact same `single_certificate` validator the pure-core
    // negative table (`ops/tests.rs`) and the CLI-face table
    // (`init_trust.rs`) both pin.
    let cert_chain_owner_a = Sandbox::new();
    cert_chain_owner_a.init();
    let cert_chain_owner_b = Sandbox::new();
    cert_chain_owner_b.init();
    let cert_chain_dir = tempfile::tempdir().expect("tempdir");
    let cert_chain_path = cert_chain_dir.path().join("chain.pem");
    let (code, pem_a) = cert_chain_owner_a.json(&["identity", "export", "--json"]);
    assert_eq!(code, 0, "{pem_a}");
    let (code, pem_b) = cert_chain_owner_b.json(&["identity", "export", "--json"]);
    assert_eq!(code, 0, "{pem_b}");
    std::fs::write(
        &cert_chain_path,
        format!(
            "{}{}",
            pem_a["data"]["cert_pem"].as_str().expect("cert_pem a"),
            pem_b["data"]["cert_pem"].as_str().expect("cert_pem b")
        ),
    )
    .expect("write chain.pem");
    let cert_chain_path_str = cert_chain_path.to_str().unwrap().to_string();
    let trust_add_cert_file_chain_args = [
        "trust",
        "add",
        "chain-peer",
        "--cert-file",
        cert_chain_path_str.as_str(),
    ];

    // ADR-0026: key files for the `init --import-ssh-key` refusal rows,
    // synthesized at run time (no real key, no PEM text in the repository).
    let ssh_key_dir = tempfile::tempdir().expect("tempdir");
    let ssh_encrypted = ssh_golden::write(
        ssh_key_dir.path(),
        "encrypted",
        &ssh_golden::encrypted_key_file(),
    );
    let ssh_rsa = ssh_golden::write(ssh_key_dir.path(), "rsa", &ssh_golden::rsa_key_file());
    let ssh_garbage = ssh_golden::write(ssh_key_dir.path(), "garbage", b"not a key\n");
    let ssh_encrypted = ssh_encrypted.to_str().unwrap().to_string();
    let ssh_rsa = ssh_rsa.to_str().unwrap().to_string();
    let ssh_garbage = ssh_garbage.to_str().unwrap().to_string();
    let import_encrypted_args = [
        "init",
        "--key-store",
        "file",
        "--import-ssh-key",
        &ssh_encrypted,
    ];
    let import_rsa_args = ["init", "--key-store", "file", "--import-ssh-key", &ssh_rsa];
    let import_garbage_args = [
        "init",
        "--key-store",
        "file",
        "--import-ssh-key",
        &ssh_garbage,
    ];

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
            // both owe the same answer — the root form's usage code, 255,
            // with **nothing on stdout**, because help text on stdout would
            // break machine mode (`docs/CLI.md` §2.2).
            name: "root usage: global flags with no target and no subcommand",
            sandbox: &fleet.client,
            args: &[],
            outcome: Outcome::RootUsage,
        },
        Case {
            name: "root usage: an option ssh does not have",
            sandbox: &fleet.client,
            args: &["--no-such-option", HOST_ALIAS],
            outcome: Outcome::RootUsage,
        },
        Case {
            name: "root usage: an ssh option without its value",
            sandbox: &fleet.client,
            args: &["-p"],
            outcome: Outcome::RootUsage,
        },
        Case {
            name: "version",
            sandbox: &fleet.client,
            args: &["version"],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            // `docs/CLI.md` §6.17: `doctor.run` exit code is always `0` —
            // findings are data, never a failure (verify round P3-8: no
            // `qsh-cli` integration test pinned doctor's exit code/JSON
            // purity at all before this row).
            name: "doctor",
            sandbox: &fleet.client,
            args: &["doctor"],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            // ADR-0027: a doctor that cannot start keeps exit 255 under
            // `--fail-on`; the threshold is judged only after a
            // successful run. The exit-1 rows need a known severity mix
            // and live in `doctor_fail_on.rs`.
            name: "doctor --fail-on warn, no identity",
            sandbox: &uninitialized,
            args: &["doctor", "--fail-on", "warn"],
            outcome: Outcome::Fails("CONFIG_ERROR"),
        },
        Case {
            // ADR-0027 decision 2: `info` is outside the vocabulary.
            name: "doctor --fail-on info",
            sandbox: &fleet.client,
            args: &["doctor", "--fail-on", "info"],
            outcome: Outcome::Usage,
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
            // ADR-0013: `identity export` before `qsh init` is
            // the same `CONFIG_ERROR` every other identity-reading op gives
            // (`identity_export_is_a_config_error_before_qsh_init` in
            // `ops/tests.rs` and `init_trust.rs` pin this at the pure-core
            // and CLI layers; this row is only the exit-code/output-mode
            // face of the same guarantee).
            name: "identity export: no device identity",
            sandbox: &uninitialized,
            args: &["identity", "export"],
            outcome: Outcome::Fails("CONFIG_ERROR"),
        },
        Case {
            // ADR-0032 결정 15: the same `CONFIG_ERROR` as `identity export`
            // before `qsh init` (`identity_move_key.rs` pins the message).
            name: "identity move-key: no device identity",
            sandbox: &uninitialized,
            args: &["identity", "move-key", "--to", "file"],
            outcome: Outcome::Fails("CONFIG_ERROR"),
        },
        Case {
            // The key already lives in the file store, so this is the
            // no-op success (`moved: false`) and touches no key store.
            name: "identity move-key: already in the requested store",
            sandbox: &fleet.client,
            args: &["identity", "move-key", "--to", "file"],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            // `auto` is a policy for `init`, not a store to move a key to.
            name: "usage: identity move-key --to auto",
            sandbox: &fleet.client,
            args: &["identity", "move-key", "--to", "auto"],
            outcome: Outcome::Usage,
        },
        Case {
            name: "usage: identity move-key without --to",
            sandbox: &fleet.client,
            args: &["identity", "move-key"],
            outcome: Outcome::Usage,
        },
        Case {
            // ADR-0033 결정 4: local-only and authorization-free, so even a
            // machine with no log yet answers with an empty success.
            name: "audit: empty log",
            sandbox: &fleet.client,
            args: &["audit"],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            // ADR-0033 결정 9: the limit range is checked by the core, so a
            // bad value is a runtime failure (255), not a clap usage error.
            name: "audit: --limit 0",
            sandbox: &fleet.client,
            args: &["audit", "--limit", "0"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            name: "audit: --limit above 1000",
            sandbox: &fleet.client,
            args: &["audit", "--limit", "5000"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            name: "audit: unknown --decision",
            sandbox: &fleet.client,
            args: &["audit", "--decision", "maybe"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // There is no remote form: a host operand is not accepted.
            name: "usage: audit with a host operand",
            sandbox: &fleet.client,
            args: &["audit", HOST_ALIAS],
            outcome: Outcome::Usage,
        },
        Case {
            name: "init --import-ssh-key: passphrase-protected key",
            sandbox: &uninitialized,
            args: &import_encrypted_args,
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            name: "init --import-ssh-key: non-Ed25519 key",
            sandbox: &uninitialized,
            args: &import_rsa_args,
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            name: "init --import-ssh-key: malformed key file",
            sandbox: &uninitialized,
            args: &import_garbage_args,
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // The identity-exists refusal (ADR-0026) needs no valid key
            // file: the existence check runs before the file is opened.
            name: "init --import-ssh-key: identity already exists",
            sandbox: &fleet.client,
            args: &import_garbage_args,
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            name: "trust add: malformed fingerprint",
            sandbox: &fleet.client,
            args: &["trust", "add", "bad", "--fingerprint", "not-a-fingerprint"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // ADR-0013 결정 4: a chain of two certificates is a structural
            // PEM rejection, `INVALID_ARGUMENT` in both output modes —
            // never a clap usage error, since clap has no opinion on the
            // *contents* of the file `--cert-file` names.
            name: "trust add: --cert-file names a chain of two certificates",
            sandbox: &fleet.client,
            args: &trust_add_cert_file_chain_args,
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // No positional code and no `--code-stdin`. `check()` also
            // runs this in human mode, whose stdin is `Stdio::null()`
            // (non-a-terminal) too, so both modes must fall to the same
            // `INVALID_ARGUMENT` for "exit code does not depend on output
            // mode" (`docs/CLI.md` §4) to hold (M9 plan Step 2 (a) (b9a621b),
            // ADR-0013 decision 8).
            name: "trust accept: no code and no --code-stdin",
            sandbox: &fleet.client,
            args: &["trust", "accept", "127.0.0.1:1"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // `docs/CLI.md` §6.11: the positional code and `--code-stdin`
            // together is a clap usage error (exit 2, no envelope), not an
            // `Ops`-level `INVALID_ARGUMENT` — `cli.rs`'s
            // `conflicts_with = "code"` is what makes
            // `resolve_invite_code_source`'s own `(Some(_), true)` arm
            // unreachable through the CLI; removing the attribute would
            // make this row fall through to that arm's `INVALID_ARGUMENT`
            // (exit 255) instead, which this pins against.
            name: "trust accept: code and --code-stdin together",
            sandbox: &fleet.client,
            args: &[
                "trust",
                "accept",
                "127.0.0.1:1",
                "abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab",
                "--code-stdin",
            ],
            outcome: Outcome::Usage,
        },
        Case {
            // `docs/CLI.md` §6.20, ADR-0024 decision 2: an invite code and
            // `--peer-cert` are two different pin means, so giving both is
            // a clap usage error, not an `INVALID_ARGUMENT` op error.
            name: "setup client: code and --peer-cert together",
            sandbox: &fleet.client,
            args: &[
                "setup",
                "client",
                "laptop",
                "abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab",
                "--peer-cert",
                "peer.pem",
            ],
            outcome: Outcome::Usage,
        },
        Case {
            // `docs/CLI.md` §6.20: `--forward` is a host-side flag, so the
            // listener role does not define it and clap refuses it before
            // any step runs. The listener role runs on every platform, so
            // this row has no `cfg`.
            name: "setup listener: a flag the role does not define",
            sandbox: &fleet.client,
            args: &["setup", "listener", "--peer", "m", "--forward"],
            outcome: Outcome::Usage,
        },
        Case {
            // The same refusal for `--to`, which names a target-side slot.
            name: "setup listener: --to is not a listener flag",
            sandbox: &fleet.client,
            args: &["setup", "listener", "--to", "m"],
            outcome: Outcome::Usage,
        },
        Case {
            // ADR-0044 decision 7: a destination that looks like an ssh
            // option is refused by `Ops` before the identity or any ssh
            // process exists, so it is an `INVALID_ARGUMENT` op error
            // (exit 255), not a clap usage error.
            name: "pair ssh: destination that looks like an ssh option",
            sandbox: &fleet.client,
            args: &["pair", "ssh", "--", "-oProxyCommand=touch /tmp/pwned"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // ADR-0044 decision 7: a host part that is not a valid pin name
            // needs `--as`; the refusal comes before any ssh process.
            name: "pair ssh: host part is not a pin name and no --as",
            sandbox: &fleet.client,
            args: &["pair", "ssh", "box/alias"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // The destination is a required operand: clap usage error.
            name: "pair ssh: no destination",
            sandbox: &fleet.client,
            args: &["pair", "ssh"],
            outcome: Outcome::Usage,
        },
        Case {
            // ADR-0024 decision 7: a missing required input is not a clap
            // error. No role given in machine mode, and in human mode the
            // matrix runs without a terminal, so both are
            // `INVALID_ARGUMENT` before any step runs.
            name: "setup: no role",
            sandbox: &fleet.client,
            args: &["setup"],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // M5 plan Step 7 (c) (2473c88): a name outside `Action::ALL`'s
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
            // The default shell on both platforms: the login shell on unix,
            // `COMSPEC` on a ConPTY host (ADR-0035 decision 20).
            args: &["session", "open", HOST_ALIAS],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            name: "sessions",
            sandbox: &fleet.client,
            args: &["sessions", HOST_ALIAS],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            name: "sessions: filtered",
            sandbox: &fleet.client,
            args: &[
                "sessions",
                HOST_ALIAS,
                "--state",
                "running",
                "--writer",
                "none",
                "--attachable",
            ],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            name: "sessions: unknown state filter is empty, not an error",
            sandbox: &fleet.client,
            args: &["sessions", HOST_ALIAS, "--state", "no-such-state"],
            outcome: Outcome::Succeeds(0),
        },
        Case {
            name: "sessions: a filter flag without its value",
            sandbox: &fleet.client,
            args: &["sessions", HOST_ALIAS, "--writer"],
            outcome: Outcome::Usage,
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
            // (`docs/CLI.md` §6.9, M4 plan Step 6 (2473c88)).
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
            // M5 plan Step 6 (2473c88) PR 6b: `forward.remote`'s ACL gate
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
            // `-D` is implemented (ADR-0019); this row used to pin the P0
            // stub's unconditional `UNSUPPORTED`. What still refuses
            // before `Ops::tunnel_open`/`Ops::tunnel_dynamic` is even
            // called (`main.rs`'s `run_tunnel_open_dynamic`) is giving
            // `--dynamic` more than once — no peer round trip happens
            // here either, for the same reason: included in this table
            // anyway because it is exactly the kind of envelope-producing
            // failure this matrix exists to pin (`docs/CLI.md` §6.9,
            // M4 plan Step 6 (2473c88), DoD 5).
            name: "tunnel open: --dynamic given twice is INVALID_ARGUMENT",
            sandbox: &fleet.client,
            args: &[
                "tunnel",
                "open",
                HOST_ALIAS,
                "--dynamic",
                "1080",
                "--dynamic",
                "1081",
            ],
            outcome: Outcome::Fails("INVALID_ARGUMENT"),
        },
        Case {
            // `tunnel.close` is idempotent by contract (`docs/CLI.md`
            // §6.9's `data.closed` shape, mirroring `trust.remove`'s own
            // idempotent-delete precedent at §6.11) — closing an id
            // nothing holds is `ok:true`/`data.closed:false`/exit `0`,
            // never an error (`qsh-core`'s `Ops::tunnel_close` never
            // returns `Err`). the Step 6 draft table in
            // The M4 plan (2473c88) expected a failure row here;
            // `docs/CLI.md` wins the conflict (the contract docs are
            // binding over a plan) — see this file's module doc; the
            // plan's draft line was amended in the same change.
            name: "tunnel close: nonexistent id is a no-op, not a failure",
            sandbox: &fleet.client,
            args: &["tunnel", "close", "01K0NOSUCHTUNNEL"],
            outcome: Outcome::Succeeds(0),
        },
        // ADR-0068: every retired reverse entry point parses and answers
        // `UNSUPPORTED`, exit 255. The long-running ones write no envelope
        // even under `--json` (`long_running_setup_mode`); the operations
        // answer with one.
        Case {
            name: "listen: retired, refused with no envelope",
            sandbox: &fleet.client,
            args: &["listen"],
            outcome: Outcome::RefusedWithoutEnvelope("UNSUPPORTED"),
        },
        Case {
            name: "listen --serve: retired, refused with no envelope",
            sandbox: &fleet.client,
            args: &["listen", "--serve"],
            outcome: Outcome::RefusedWithoutEnvelope("UNSUPPORTED"),
        },
        Case {
            name: "reverse: retired, refused with no envelope",
            sandbox: &fleet.client,
            args: &["reverse", "hub"],
            outcome: Outcome::RefusedWithoutEnvelope("UNSUPPORTED"),
        },
        Case {
            name: "serve --to: retired, refused with no envelope",
            sandbox: &fleet.client,
            args: &["serve", "--to", "box", "--bind", "127.0.0.1:0"],
            outcome: Outcome::RefusedWithoutEnvelope("UNSUPPORTED"),
        },
        Case {
            name: "serve --name: retired, refused with no envelope",
            sandbox: &fleet.client,
            args: &["serve", "--name", "laptop"],
            outcome: Outcome::RefusedWithoutEnvelope("UNSUPPORTED"),
        },
        Case {
            name: "setup listener: retired",
            sandbox: &fleet.client,
            args: &["setup", "listener", "--peer", "m"],
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            name: "setup host --to: retired",
            sandbox: &fleet.client,
            args: &["setup", "host", "--to", "m"],
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            name: "pair ssh --reverse: retired",
            sandbox: &fleet.client,
            args: &["pair", "ssh", "--reverse", "--to", "hub:4433", "box"],
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            name: "service install --to: retired",
            sandbox: &fleet.client,
            args: &["service", "install", "--to", "hub"],
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            name: "config set on a retired reverse key",
            sandbox: &fleet.client,
            args: &["config", "set", "listen.bind", "127.0.0.1:0"],
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
        Case {
            name: "--rendezvous: retired",
            sandbox: &fleet.client,
            args: &["version", "--rendezvous", "hub"],
            outcome: Outcome::Fails("UNSUPPORTED"),
        },
    ];

    // `qsh cp` (ADR-0029, `docs/CLI.md` §6.21). A scp transport flag is a
    // clap-level refusal (exit 2, nothing on stdout, in both modes). The
    // runtime rows run on every client against every host: the fleet host
    // advertises `file.v1` on every platform (ADR-0035 decision 26), so the
    // same rows end the same way on a Windows fleet.
    cases.push(Case {
        name: "usage: cp with an scp transport flag",
        sandbox: &fleet.client,
        args: &["cp", "-P", "22", "a.txt", "box:/tmp/qsh-cp-never"],
        outcome: Outcome::Usage,
    });
    cases.push(Case {
        name: "cp: put of a local file that does not exist",
        sandbox: &fleet.client,
        args: &["cp", "/nonexistent/qsh-cp-source", "box:/tmp/qsh-cp-never"],
        outcome: Outcome::Fails("INVALID_ARGUMENT"),
    });
    // The fleet host pins its client with role `none` and its `acl.toml` has
    // no file row: default-deny, the uniform refusal (ADR-0029 decision 8).
    // The remote operand is a home-relative name, the one spelling that is a
    // well-formed path on every host (a `/tmp/...` path is not one on a
    // Windows host, where the shape check refuses it before the ACL). The
    // destination is `.`, a directory that exists on every client, so the
    // client-side destination check cannot answer first (`/tmp` is not
    // a directory on a Windows runner).
    cases.push(Case {
        name: "cp: get from a host that grants this client no file access",
        sandbox: &fleet.client,
        args: &["cp", "box:qsh-cp-never", "."],
        outcome: Outcome::Fails("PERMISSION_DENIED"),
    });

    // ADR-0032 decision 1: each flag belongs to exactly one subcommand, and
    // clap refuses a flag on the wrong one before any op (or manager) runs.
    // No row here runs a real manager; the success faces of the three flags
    // live in `fixtures::golden_service_activation_fixtures` over a fake.
    cases.push(Case {
        name: "usage: service install takes --activate, not --deactivate",
        sandbox: &fleet.client,
        args: &["service", "install", "--deactivate"],
        outcome: Outcome::Usage,
    });
    cases.push(Case {
        name: "usage: service uninstall takes --deactivate, not --live",
        sandbox: &fleet.client,
        args: &["service", "uninstall", "--live"],
        outcome: Outcome::Usage,
    });
    cases.push(Case {
        name: "usage: service status takes --live, not --activate",
        sandbox: &fleet.client,
        args: &["service", "status", "--activate"],
        outcome: Outcome::Usage,
    });
    // `status --live` is the one flag no row may leave to a real manager
    // elsewhere: with no unit file in the sandbox it answers `active: false`
    // without asking launchd, systemd or the Task Scheduler, so it succeeds on
    // every platform. The Windows `--activate` and `--deactivate` rows would
    // register or delete a real task, and are covered over a recording runner
    // in `qsh-core`.
    cases.push(Case {
        name: "service status --live: no unit file, no manager is asked",
        sandbox: &fleet.client,
        args: &["service", "status", "--live"],
        outcome: Outcome::Succeeds(0),
    });

    for case in &cases {
        check(case);
    }

    // `session close --signal` on a Windows host (ADR-0035 decision 3, 22):
    // each of the seven accepted values answers `0` and removes a session of
    // its own. A row cannot name the session it closes, so these are opened
    // here. The default shell keeps running after `INT`, `QUIT`, `USR1` and
    // `USR2` reach it, which is the escalation's job to end; what each signal
    // delivers to a program is pinned in `windows_forward_e2e` and
    // `windows_reverse_e2e` (`session_close_with_each_signal_ends_the_session`).
    // Human mode runs for `KILL` alone, which ends the session at once; the
    // exit code does not depend on the output mode (`docs/CLI.md` §4).
    #[cfg(windows)]
    for (signal, human) in [
        ("HUP", false),
        ("INT", false),
        ("QUIT", false),
        ("TERM", false),
        ("KILL", true),
        ("USR1", false),
        ("USR2", false),
    ] {
        let modes: &[bool] = if human { &[false, true] } else { &[false] };
        for &human_mode in modes {
            let (code, opened) = fleet
                .client
                .json(&["session", "open", HOST_ALIAS, "--json"]);
            assert_eq!(code, 0, "session open for --signal {signal}: {opened}");
            let session_ref = opened["data"]["session_ref"]
                .as_str()
                .expect("session_ref")
                .to_string();
            let mut args = vec!["session", "close", session_ref.as_str(), "--signal", signal];
            if !human_mode {
                args.push("--json");
            }
            let out = fleet.client.qsh(&args);
            assert_eq!(
                exit_code(&out),
                0,
                "session close --signal {signal} (human: {human_mode}): {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // The generic `Succeeds(0)` check above only asserts `ok:true`; the
    // idempotent-delete shape (`docs/CLI.md` §6.9, this file's own module
    // doc on the plan conflict) needs its own look at `data.closed`.
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
    assert!(
        sessions.iter().any(|s| s["host"] == HOST_ALIAS),
        "the reachable host's sessions survive a peer being down: {envelope}"
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
        Outcome::RootUsage => {
            assert_eq!(json_code, EXIT_RUNTIME_FAILURE, "{name}");
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
        Outcome::RefusedWithoutEnvelope(code) => {
            assert_eq!(json_code, EXIT_RUNTIME_FAILURE, "{name}");
            // Unlike `Fails`, `--json` produces no envelope at all here —
            // both modes write the same stderr line and zero stdout.
            assert!(
                json.stdout.is_empty(),
                "{name}: a long-running setup mode must write no stdout even \
                 under --json, was {:?}",
                String::from_utf8_lossy(&json.stdout)
            );
            assert!(human.stdout.is_empty(), "{name}");
            for (label, output) in [("json", &json), ("human", &human)] {
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains(&format!("({code})")),
                    "{name} ({label}): stderr must name the error code, was {stderr:?}"
                );
            }
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
// The M4 plan (2473c88) already prescribes for the reverse-refusal/listen-conflict
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
    // The interactive client has one code path on every platform, so the
    // routing failure is the same `HOST_NOT_FOUND` on unix and on Windows.
    let expected_code = "(HOST_NOT_FOUND)";
    assert!(
        lines[0].contains(expected_code),
        "stderr must name {expected_code}: {stderr:?}"
    );
}

// ---------------------------------------------------------------------
// Interactive `-D` — deliberately **not** a `Case` row above, for the
// same reason as the attach test just above: the two output modes
// disagree *on purpose*. `docs/CLI.md` §7 states that
// `--json`/`--jsonl` on either interactive form is refused with
// `INVALID_ARGUMENT` **before a session is even opened**, because the
// interactive form has no machine mode at all. `run_interactive`
// (`main.rs`) checks `wants_json` first, so with `--json`/`--jsonl`
// present the §7 gate answers `INVALID_ARGUMENT` before `-D`'s own specs
// are even parsed. `check`'s machinery asserts the *same* `error.code` in
// both modes, which this command structurally cannot satisfy, so it gets
// its own two-part assertion instead of a matrix row.
// ---------------------------------------------------------------------

#[test]
fn interactive_dash_d_is_host_not_found_but_json_mode_wins_on_precedence() {
    let sandbox = Sandbox::initialized();
    // An unregistered alias in human mode would start the ssh bootstrap on
    // unix (ADR-0044 decision 2); this test is about the routing failure
    // behind it, so the bootstrap is off and no ssh is ever run.
    std::fs::write(
        sandbox.config_dir().join("config.toml"),
        "[ssh]\nbootstrap = \"off\"\n",
    )
    .unwrap();

    // Human mode: nothing outranks host resolution here, so a valid `-D`
    // spec against an alias this sandbox never registered reaches
    // `Ops::session_open` and reports `HOST_NOT_FOUND`, exactly like a bare
    // interactive attach with no `-D` at all, on every platform.
    let human = sandbox.qsh(&[HOST_ALIAS, "-D", "1080"]);
    assert_eq!(exit_code(&human), EXIT_RUNTIME_FAILURE, "{human:?}");
    assert!(
        human.stdout.is_empty(),
        "interactive -D's routing failure must never write to stdout: {:?}",
        String::from_utf8_lossy(&human.stdout)
    );
    let stderr = String::from_utf8_lossy(&human.stderr);
    let expected_code = "(HOST_NOT_FOUND)";
    assert!(
        stderr.contains(expected_code),
        "stderr must name {expected_code}: {stderr:?}"
    );

    // Machine mode: §7's json-mode gate answers first, before host
    // resolution or any `-D` parsing, on both platforms alike.
    let args = [HOST_ALIAS, "-D", "1080", "--json"];
    let json = sandbox.qsh(&args);
    assert_eq!(exit_code(&json), EXIT_RUNTIME_FAILURE, "{json:?}");
    let envelope = sole_envelope(&json.stdout, &args);
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "INVALID_ARGUMENT",
        "§7 must win over host resolution when --json is present: {envelope}"
    );
}

// ---------------------------------------------------------------------
// The retired reverse entry points (ADR-0068) are matrix rows above. These
// two tests pin what a row cannot: the message names the alternative, and
// `details.reason` is `reverse_retired` in the envelope.
// ---------------------------------------------------------------------

/// The long-running retired commands put one line on stderr and nothing on
/// stdout; the line names the retirement, its ADR and one alternative.
#[test]
fn retired_long_running_commands_say_the_alternative_on_one_stderr_line() {
    let sandbox = Sandbox::initialized();
    for (args, alternative) in [
        (&["listen"][..], "qsh serve"),
        (
            &["listen", "--serve"][..],
            "`[listen].bind`는 `[serve].bind`로 옮긴다",
        ),
        (&["reverse", "hub"][..], "qsh serve"),
        (&["serve", "--to", "hub"][..], "qsh serve"),
    ] {
        let output = sandbox.qsh(args);
        assert_eq!(exit_code(&output), EXIT_RUNTIME_FAILURE, "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stderr.lines().count(), 1, "{args:?}: {stderr:?}");
        assert!(stderr.contains("ADR-0068"), "{args:?}: {stderr:?}");
        assert!(stderr.contains(alternative), "{args:?}: {stderr:?}");
        assert!(stderr.contains("(UNSUPPORTED)"), "{args:?}: {stderr:?}");
    }
}

/// An operation answers with the envelope: `UNSUPPORTED`, not retryable,
/// `details.reason` `reverse_retired`.
#[test]
fn retired_operations_carry_the_reason_in_the_envelope() {
    let sandbox = Sandbox::initialized();
    for args in [
        &["setup", "listener", "--peer", "m", "--json"][..],
        &["setup", "host", "--to", "m", "--json"][..],
        &["service", "install", "--to", "hub", "--json"][..],
        &["config", "set", "serve.to", "hub", "--json"][..],
        &["version", "--rendezvous", "hub", "--json"][..],
    ] {
        let (code, envelope) = sandbox.json(args);
        assert_eq!(code, EXIT_RUNTIME_FAILURE, "{args:?}: {envelope}");
        assert_eq!(envelope["ok"], false, "{args:?}: {envelope}");
        assert_eq!(envelope["error"]["code"], "UNSUPPORTED", "{args:?}");
        assert_eq!(envelope["error"]["retryable"], false, "{args:?}");
        assert_eq!(
            envelope["error"]["details"]["reason"], "reverse_retired",
            "{args:?}: {envelope}"
        );
    }
}

/// `qsh serve`'s bind failure carries the remedy on one stderr line with
/// exit 255, through `serve.rs`'s own `Listener::bind` call site.
#[test]
fn qsh_serve_bind_conflict_is_one_stderr_line_exit_255_and_zero_stdout() {
    let sandbox = Sandbox::initialized();
    let holder = ServeGuard::start(&sandbox);

    let output = sandbox.qsh(&["serve", "--bind", holder.addr()]);

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
    assert!(
        lines[0].contains(qsh_core::serve::BIND_UNAVAILABLE_REMEDY),
        "stderr must carry the bind-conflict remedy: {stderr:?}"
    );

    drop(holder);
}
