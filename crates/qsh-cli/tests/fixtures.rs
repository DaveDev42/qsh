//! Golden `qsh.cli/v1` fixtures and their schema validation
//! (`docs/design/testing.md` L6, `PLAN.md` Step 7).
//!
//! Three things happen here:
//!
//! 1. **Golden fixtures.** Each `golden_*` test reproduces one real
//!    (command, outcome) with the actual binary, normalizes the volatile
//!    fields away (`qsh_testkit::fixtures::normalize`) and compares the
//!    result to a checked-in file. Fixtures are **append-only**
//!    (`docs/CLI.md` §10): add new ones, never edit or delete an existing
//!    one. Re-run with `QSH_UPDATE_FIXTURES=1` only when adding a fixture.
//! 2. **Schema validation.** `schemars` derives the JSON Schema straight
//!    from the contract types in `qsh-proto`, and every fixture is
//!    validated against it — one source for the envelope shape.
//! 3. **`ErrorCode` reachability.** Every code in `ErrorCode::KNOWN` is
//!    either produced by a fixture or listed in [`DEFERRED`] with the
//!    milestone that will first produce it. The two lists must be
//!    disjoint, so adding a fixture for a code forces removing it here.
//!
//! `qsh schema --json` (`PLAN.md` M7 Step 1) serves exactly the schemas
//! this file validates fixtures against — both sides call
//! `qsh_proto::schema::{cli_v1_data_schema, cli_v1_envelope_schema}`
//! (`data_schema` below is a thin wrapper over the former), so there is
//! only ever one generator, never two hand-maintained copies of the same
//! table. `schema_command_output_matches_the_single_source_generator`
//! (below) is the mechanical proof of that, not just a doc claim.

mod common;

use std::collections::BTreeSet;
use std::io::BufRead as _;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;

use common::{CLIENT_ALIAS, Fleet, HOST_ALIAS, Sandbox, ServeGuard};
use qsh_proto::ErrorCode;
use qsh_testkit::fixtures;
use serde_json::Value;

/// A deterministic, valid fingerprint (32 bytes, standard Base64) so the
/// `trust.*` fixtures never depend on a generated key.
const SAMPLE_FINGERPRINT: &str = "sha256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// Set this to regenerate every fixture this file owns instead of asserting
/// against it.
const UPDATE_ENV: &str = "QSH_UPDATE_FIXTURES";

/// `ErrorCode`s no fixture covers yet, each with the reason it has none.
/// Move a code out of this list the moment a fixture covers it — the
/// reachability test asserts the two sets are disjoint.
///
/// "No fixture" is not the same as "unreachable": several of these are
/// produced today on a path that has no `qsh.cli/v1` envelope to capture
/// (the interactive form has no machine mode, `docs/CLI.md` §7) or no
/// deterministic way to force one. The reason string has to say which,
/// because a stale "the next milestone will do it" hides a code that
/// quietly became reachable (`docs/design/testing.md` L6).
const DEFERRED: &[(&str, &str)] = &[
    (
        "RESUME_GAP",
        "event-only by contract (`docs/CLI.md` §3.3): leaving the replay \
         range is always delivered as a `session.gap` event, never as an \
         error envelope. Stays deferred until the P1 strict-read option",
    ),
    (
        "CANCELED",
        "no producer anywhere in the tree yet — reserved for caller-side \
         cancellation, which no M2 op offers",
    ),
    ("REMOTE_ERROR", "no deterministic producer"),
    ("INTERNAL", "no deterministic producer"),
];

/// Every fixture this milestone owes, so a silently-missing file fails
/// loudly instead of shrinking the covered surface.
const REQUIRED_FIXTURES: &[&str] = &[
    "version.json",
    "capabilities.json",
    "identity.init.created.json",
    "identity.init.existing.json",
    "cert.init.json",
    "cert.issue.json",
    "trust.add.json",
    "trust.add.updated.json",
    "trust.list.json",
    "trust.remove.json",
    "trust.remove.absent.json",
    "trust.invite.json",
    "trust.accept.json",
    "host.list.json",
    "host.get.json",
    "host.list.with_hosts_toml.json",
    "host.get.with_hosts_toml.json",
    "exec.run.json",
    "exec.run.signal.json",
    "error.INVALID_ARGUMENT.json",
    "error.CONFIG_ERROR.json",
    "error.HOST_NOT_FOUND.json",
    "error.CONNECTION_FAILED.json",
    "error.AUTH_FAILED.json",
    "error.TRUST_REQUIRED.json",
    "error.TIMEOUT.json",
    "session.open.json",
    "session.get.json",
    "session.list.json",
    "session.read.json",
    "session.write.json",
    "session.resize.json",
    "session.close.json",
    "error.SESSION_NOT_FOUND.json",
    "error.SESSION_CONFLICT.json",
    "error.UNSUPPORTED.json",
    "tunnel.open.json",
    "tunnel.list.json",
    "tunnel.close.json",
    "error.PERMISSION_DENIED.json",
    "acl.check.allow.json",
    "acl.check.deny.json",
    "error.RESOURCE_EXHAUSTED.json",
];

// ---------------------------------------------------------------------------
// Fixture plumbing
// ---------------------------------------------------------------------------

fn updating() -> bool {
    match std::env::var(UPDATE_ENV) {
        Ok(value) => !value.is_empty() && value != "0",
        Err(_) => false,
    }
}

fn fixture_path(name: &str) -> PathBuf {
    fixtures::cli_v1_dir().join(name)
}

/// Compare one freshly-produced envelope to its fixture — or write it, when
/// running with `QSH_UPDATE_FIXTURES=1`.
fn check(name: &str, envelope: Value) {
    let actual = fixtures::normalize(envelope);
    if updating() {
        let path = fixture_path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture dir");
        }
        let mut text = serde_json::to_string_pretty(&actual).expect("encode fixture");
        text.push('\n');
        std::fs::write(&path, text).expect("write fixture");
        eprintln!("regenerated {}", path.display());
        return;
    }
    let expected = fixtures::load_cli_v1(name);
    assert_eq!(
        pretty(&actual),
        pretty(&expected),
        "fixture {name} no longer matches the binary's output.\n\
         Fixtures are append-only: if this is an intentional contract change \
         it needs a new /v2 (docs/CLI.md §10). If you are adding a new \
         fixture, regenerate with {UPDATE_ENV}=1."
    );
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("encode json")
}

/// Fixture-reading tests are meaningless mid-regeneration; skip them then.
fn skip_while_regenerating() -> bool {
    if updating() {
        eprintln!("{UPDATE_ENV} is set: skipping fixture validation");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Golden fixtures produced by real runs
// ---------------------------------------------------------------------------

/// Everything that needs neither a peer nor a network round trip.
#[test]
fn golden_local_fixtures() {
    let sandbox = Sandbox::new();

    let (code, version) = sandbox.json(&["version", "--json"]);
    assert_eq!(code, 0, "{version}");
    check("version.json", version);

    // `qsh capabilities` (no host): this build's own advertised set,
    // unprocessed (`docs/ROADMAP.md` M7 DoD 3's scope-creep tripwire,
    // `PLAN.md` M7 §4.1 #2). Unlike every other fixture in this function,
    // this one is **not** append-only in the strict "never touches again"
    // sense — its whole purpose is to fail loudly the moment
    // `wire::LOCAL_CAPABILITIES` changes, the same "diff review required"
    // discipline `docs/design/testing.md` L7 already documents for MCP's
    // `tools_list.json`. A deliberate capability change updates this file
    // with `QSH_UPDATE_FIXTURES=1` and the diff gets reviewed like any
    // other contract change; it does not get a second, parallel file the
    // way an ordinary CLI fixture would.
    let (code, capabilities) = sandbox.json(&["capabilities", "--json"]);
    assert_eq!(code, 0, "{capabilities}");
    check("capabilities.json", capabilities);

    let (code, created) = sandbox.json(&["init", "--json", "--key-store", "file"]);
    assert_eq!(code, 0, "{created}");
    check("identity.init.created.json", created);

    let (code, existing) = sandbox.json(&["init", "--json", "--key-store", "file"]);
    assert_eq!(code, 0, "{existing}");
    check("identity.init.existing.json", existing);

    // `qsh cert init`/`qsh cert issue` (`docs/adr/0008-private-ca-cert-issuance.md`,
    // `PLAN.md` M7 Step 5): local-only, no peer — a private CA root, then
    // the promotion of this sandbox's own identity to CA-issued.
    // `device_id`/`fingerprint`/`config_dir` are all masked by
    // `fixtures::normalize` (fresh key material every run); `ca.name` is
    // the fixed `"local"` constant, so it stays in the fixture verbatim.
    let (code, cert_init) = sandbox.json(&["cert", "init", "--json"]);
    assert_eq!(code, 0, "{cert_init}");
    check("cert.init.json", cert_init);

    let (code, cert_issue) = sandbox.json(&["cert", "issue", "--json"]);
    assert_eq!(code, 0, "{cert_issue}");
    check("cert.issue.json", cert_issue);

    let (code, added) = sandbox.json(&[
        "trust",
        "add",
        "personal-mac",
        "--address",
        "personal-mac.example.com:4433",
        "--fingerprint",
        SAMPLE_FINGERPRINT,
        "--json",
    ]);
    assert_eq!(code, 0, "{added}");
    check("trust.add.json", added);

    let (code, listed) = sandbox.json(&["trust", "list", "--json"]);
    assert_eq!(code, 0, "{listed}");
    check("trust.list.json", listed);

    // `trust invite` (ADR-0002, `PLAN.md` M7 Step 4, `docs/CLI.md` §6.11) is
    // pure local generation — no dial, no peer — so it belongs here rather
    // than in `golden_remote_fixtures`. `code`/`expires_at`/`accept_command`
    // are all volatile (fresh 160-bit secret + creation time every run) and
    // masked by `fixtures::normalize`.
    let (code, invited) = sandbox.json(&["trust", "invite", "--json"]);
    assert_eq!(code, 0, "{invited}");
    check("trust.invite.json", invited);

    // `host.list`/`host.get` (`docs/CLI.md` §6.1) forward-only: no
    // localctl daemon runs in this sandbox (`Sandbox::command` scrubs
    // `XDG_RUNTIME_DIR` and no `<state_dir>/run` directory exists), so the
    // reverse source is empty and this is a pure local read — no dial, no
    // network round trip, which is exactly why it lives in this
    // `sandbox`-only test rather than `golden_remote_fixtures`.
    let (code, hosts) = sandbox.json(&["hosts", "--json"]);
    assert_eq!(code, 0, "{hosts}");
    check("host.list.json", hosts);

    let (code, host) = sandbox.json(&["host", "get", "personal-mac", "--json"]);
    assert_eq!(code, 0, "{host}");
    check("host.get.json", host);

    let (code, removed) = sandbox.json(&["trust", "remove", "personal-mac", "--json"]);
    assert_eq!(code, 0, "{removed}");
    check("trust.remove.json", removed);

    let (code, absent) = sandbox.json(&["trust", "remove", "personal-mac", "--json"]);
    assert_eq!(code, 0, "{absent}");
    check("trust.remove.absent.json", absent);

    let (code, invalid) = sandbox.json(&[
        "trust",
        "add",
        "personal-mac",
        "--fingerprint",
        "not-a-fingerprint",
        "--json",
    ]);
    assert_eq!(code, 255, "{invalid}");
    check("error.INVALID_ARGUMENT.json", invalid);

    let (code, missing_host) = sandbox.json(&["exec", "nowhere", "--json", "--", "true"]);
    assert_eq!(code, 255, "{missing_host}");
    check("error.HOST_NOT_FOUND.json", missing_host);

    // A sandbox that never ran `qsh init` has no identity to dial with.
    let uninitialized = Sandbox::new();
    let (code, config_error) = uninitialized.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{config_error}");
    check("error.CONFIG_ERROR.json", config_error);

    // `-D`'s stub refusal (`docs/CLI.md` §6.9, `PLAN.md` M4 Step 6, DoD 5)
    // is `UNSUPPORTED`'s first CLI-binary envelope producer (`fixtures.rs`
    // module doc, `DEFERRED`'s former `UNSUPPORTED` entry). It needs no
    // identity or peer at all — `main.rs`'s `run_tunnel_open` refuses `-D`
    // before ever calling `Ops::tunnel_open`, so a brand-new, uninitialized
    // sandbox proves the same thing `a_non_loopback_bind_is_refused_before…`
    // proves for `-L` in `tunnel_e2e.rs`: nothing downstream ran.
    let no_identity = Sandbox::new();
    let (code, dynamic_forward) = no_identity.json(&[
        "tunnel",
        "open",
        "irrelevant-host",
        "--dynamic",
        "1080",
        "--json",
    ]);
    assert_eq!(code, 255, "{dynamic_forward}");
    assert_eq!(
        dynamic_forward["error"]["code"], "UNSUPPORTED",
        "{dynamic_forward}"
    );
    check("error.UNSUPPORTED.json", dynamic_forward);

    // `acl check` (`docs/CLI.md` §6.15, `PLAN.md` M5 Step 7) is local and
    // needs no identity (`Ops::from_env` only resolves paths), so a fresh,
    // uninitialized sandbox works — it gets its own hand-written
    // `acl.toml`: one rule for `device:laptop` that allows `session.open`
    // only, so the same policy file produces both an "allow (rule 0)" and
    // a "no rule matched" deny fixture.
    let acl_sandbox = Sandbox::new();
    std::fs::write(
        acl_sandbox.config_dir().join("acl.toml"),
        "[[acl]]\nprincipal = \"device:laptop\"\nallow = [\"session.open\"]\n",
    )
    .expect("write acl.toml fixture policy");

    let (code, allow) = acl_sandbox.json(&[
        "acl",
        "check",
        "--principal",
        "device:laptop",
        "--action",
        "session.open",
        "--resource",
        "exec",
        "--json",
    ]);
    assert_eq!(code, 0, "{allow}");
    assert_eq!(allow["data"]["decision"], "allow", "{allow}");
    check("acl.check.allow.json", allow);

    let (code, deny) = acl_sandbox.json(&[
        "acl",
        "check",
        "--principal",
        "device:laptop",
        "--action",
        "exec.run",
        "--resource",
        "exec",
        "--json",
    ]);
    assert_eq!(code, 0, "{deny}");
    assert_eq!(deny["data"]["decision"], "deny", "{deny}");
    check("acl.check.deny.json", deny);
}

/// `host.list`/`host.get`'s two new additive fields, `source` and `user`
/// (`docs/CLI.md` §5, `PLAN.md` M7 Step 3): a `hosts.toml` alongside
/// `trust.toml` exercises all three `source` values in one sandbox —
/// `"trust"` (pinned but absent from `hosts.toml`), `"hosts"` (named only
/// by `hosts.toml`, so unroutable at the trust/TLS layer — same code for
/// the "named by both, addresses disagree" case, since `source` reports
/// which side's *address* won, not which side merely names the host,
/// `PLAN.md` Step 3 (a)-추기 ②), and `"both"` (named by both, addresses
/// *agree*). `hosts-wins` below exercises the disagreeing-address shape
/// deliberately — it is the same shape the P2-0 redirect-detection fix
/// depends on (`docs/CLI.md` §5's threat note), so this golden fixture
/// doubles as its CLI/JSON-envelope-level proof. Its own sandbox —
/// `golden_local_fixtures` never writes a `hosts.toml`, which is exactly
/// the byte-identical-when-absent case
/// `absent_hosts_toml_is_byte_identical_to_pre_m7_step_3_forward_hosts`
/// (`ops/host.rs`) already pins at the `qsh-core` level; this is the same
/// guarantee proven at the CLI/JSON-envelope boundary.
#[test]
fn golden_host_fixtures_with_hosts_toml() {
    let sandbox = Sandbox::new();
    sandbox.init();

    // Named by `trust.toml` alone -> source: "trust".
    sandbox.trust_add(
        "trust-only",
        Some("trust-only.example.com:4433"),
        SAMPLE_FINGERPRINT,
    );
    // Named by both, addresses *disagree* -> `hosts.toml`'s address wins
    // and `source` reports "hosts". `trust.toml`'s address here is
    // deliberately wrong (never dialed by this fixture-only test) to make
    // the override visible in intent, not just in the normalized-away
    // `<address>` field.
    sandbox.trust_add(
        "hosts-wins",
        Some("trust-address.example.com:4433"),
        SAMPLE_FINGERPRINT,
    );
    // Named by both, addresses *agree* -> source: "both".
    sandbox.trust_add(
        "agree",
        Some("agree-address.example.com:4433"),
        SAMPLE_FINGERPRINT,
    );

    // hosts.toml: `hosts-only` (trust.toml has never heard of this name),
    // `hosts-wins` (its address here differs from the trust.toml pin
    // above, and its `user` has no `trust.toml` counterpart to conflict
    // with since `hosts.toml` is the only source of `user`), and `agree`
    // (its address here matches the trust.toml pin above exactly).
    std::fs::write(
        sandbox.config_dir().join("hosts.toml"),
        "[[host]]\n\
         name = \"hosts-wins\"\n\
         address = \"hosts-address.example.com:4433\"\n\
         user = \"dave\"\n\
         \n\
         [[host]]\n\
         name = \"hosts-only\"\n\
         address = \"hosts-only.example.com:4433\"\n\
         \n\
         [[host]]\n\
         name = \"agree\"\n\
         address = \"agree-address.example.com:4433\"\n",
    )
    .expect("write hosts.toml fixture");

    let (code, hosts) = sandbox.json(&["hosts", "--json"]);
    assert_eq!(code, 0, "{hosts}");
    check("host.list.with_hosts_toml.json", hosts);

    let (code, host) = sandbox.json(&["host", "get", "hosts-wins", "--json"]);
    assert_eq!(code, 0, "{host}");
    check("host.get.with_hosts_toml.json", host);
}

/// `trust add` re-run for a name already pinned under the *same*
/// fingerprint, but with a *new* `--address` (decision B, `PLAN.md` M7 Step
/// 2, `docs/CLI.md` §6.11's address-refresh path): `data.created` stays
/// `false`, and the new additive `data.updated` field is `true`. Its own
/// sandbox — `golden_local_fixtures` reuses `personal-mac` at a fixed
/// address for `trust.list.json`/`host.get.json`, and this scenario would
/// perturb both if it shared that sandbox.
#[test]
fn golden_trust_add_update_fixture() {
    let sandbox = Sandbox::new();

    let (code, added) = sandbox.json(&[
        "trust",
        "add",
        "personal-mac",
        "--address",
        "personal-mac.example.com:4433",
        "--fingerprint",
        SAMPLE_FINGERPRINT,
        "--json",
    ]);
    assert_eq!(code, 0, "{added}");
    assert_eq!(added["data"]["created"], true, "{added}");

    let (code, updated) = sandbox.json(&[
        "trust",
        "add",
        "personal-mac",
        "--address",
        "personal-mac.example.com:5544",
        "--fingerprint",
        SAMPLE_FINGERPRINT,
        "--json",
    ]);
    assert_eq!(code, 0, "{updated}");
    assert_eq!(updated["data"]["created"], false, "{updated}");
    assert_eq!(updated["data"]["updated"], true, "{updated}");
    check("trust.add.updated.json", updated);
}

/// `trust accept` (ADR-0002, `PLAN.md` M7 Step 4, `docs/CLI.md` §6.11): a
/// live pairing round trip against a real `qsh serve`, redeemed with a real
/// `qsh trust invite --json` code. Own host + client — never `Fleet::start`,
/// which pre-pins both sides via `--fingerprint` and would defeat pairing's
/// own premise of two peers that do not already trust each other.
#[test]
fn golden_trust_accept_fixture() {
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let serve = ServeGuard::start(&host);

    let (code, invited) = host.json(&["trust", "invite", "--json"]);
    assert_eq!(code, 0, "{invited}");
    let invite_code = invited["data"]["code"].as_str().expect("data.code");

    let (code, accepted) = client.json(&["trust", "accept", serve.addr(), invite_code, "--json"]);
    assert_eq!(code, 0, "{accepted}");
    check("trust.accept.json", accepted);
}

/// The dial-timeout path. Split out because it is the one scenario that
/// costs the full `CONNECTION_FAILED` dial timeout (~10s) — the exit-code
/// matrix uses the instant `:0` variant instead of paying it twice.
#[test]
fn golden_connection_failed_fixture() {
    let sandbox = Sandbox::initialized();
    // Port 9 (discard) with nothing bound: the dial simply gets no answer.
    sandbox.trust_add("unreachable", Some("127.0.0.1:9"), SAMPLE_FINGERPRINT);

    let (code, value) = sandbox.json(&["exec", "unreachable", "--json", "--", "true"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "CONNECTION_FAILED");
    check("error.CONNECTION_FAILED.json", value);
}

/// `PERMISSION_DENIED`'s first CLI-binary envelope producer (`PLAN.md` M5
/// Step 6 PR 6b) — the former `DEFERRED` entry's own self-discharge
/// condition: "the moment `Fleet`/an equivalent gains a way to run the real
/// binary under a denying policy". `ServeGuard::start_without_policy`
/// (`common/mod.rs`, landed by PR 6a) is exactly that — a host with no
/// `acl.toml` at all loads `DenyAll` (`docs/design/architecture.md` §6),
/// which denies every action including ones no rule ever names.
///
/// `tunnel open --remote` is the producer named in that entry's item (3):
/// the peer's `forward.remote` ACL gate
/// (`Server::authorize_and_bind_remote_forward`) runs *before* any reply
/// goes out, so the deny is `tunnel.open`'s own top-level envelope, not a
/// mid-tunnel side channel the way `-L`'s per-connection refusal is (item
/// (2), still envelope-less). The spec is `docs/CLI.md` §6.9's own canonical
/// `-R` example (`qsh tunnel open server --remote 9000:localhost:9000
/// --json`) — loopback, so nothing about the bind itself is in question;
/// only the ACL gate that runs ahead of it is.
#[test]
fn golden_permission_denied_fixture() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    let serve = ServeGuard::start_without_policy(&host, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, denied) = client.json(&[
        "tunnel",
        "open",
        HOST_ALIAS,
        "--remote",
        "9000:localhost:9000",
        "--json",
    ]);
    assert_eq!(code, 255, "{denied}");
    assert_eq!(denied["ok"], false, "{denied}");
    assert_eq!(denied["error"]["code"], "PERMISSION_DENIED", "{denied}");
    assert!(
        denied["data"].is_null(),
        "a denied op must carry no data: {denied}"
    );
    check("error.PERMISSION_DENIED.json", denied);
}

/// `RESOURCE_EXHAUSTED`'s first CLI-binary envelope producer (`PLAN.md` M8
/// Step 3, `docs/adr/0010-resource-quotas.md`) — the former `DEFERRED`
/// entry's own listed producers (`EXEC_OUTPUT_MAX`, broker backpressure, a
/// `LOCAL_CONTROL` conduit's in-flight cap) were each too expensive or too
/// deep in `qsh-testkit`/`qsh-core` machinery to stage behind a real
/// `CARGO_BIN_EXE_qsh` envelope; a saturated `[serve].
/// max_sessions_per_principal` is neither: one extra `config.toml` line on
/// an ordinary two-`session open`-calls scenario.
///
/// `max_sessions_per_principal = 1` (mirroring
/// `golden_permission_denied_fixture`'s hand-built host/client pair, not
/// `Fleet::start`, which has no seam for a caller-written `config.toml`
/// before `qsh serve` starts): the first `session open` succeeds and is
/// left running (`ServeGuard` kills the child on drop); the second is
/// refused before any PTY is spawned for it.
#[cfg(unix)]
#[test]
fn golden_resource_exhausted_fixture() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    std::fs::write(
        host.config_dir().join("config.toml"),
        "[serve]\nmax_sessions_per_principal = 1\n",
    )
    .expect("write config.toml");
    let serve = ServeGuard::start(&host);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, opened) = client.json(&["session", "open", HOST_ALIAS, "--json", "--", "sh"]);
    assert_eq!(code, 0, "{opened}");

    let (code, refused) = client.json(&["session", "open", HOST_ALIAS, "--json", "--", "sh"]);
    assert_eq!(code, 255, "{refused}");
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(refused["error"]["code"], "RESOURCE_EXHAUSTED", "{refused}");
    assert_eq!(refused["error"]["retryable"], true, "{refused}");
    assert!(
        refused["data"].is_null(),
        "a refused op must carry no data: {refused}"
    );
    check("error.RESOURCE_EXHAUSTED.json", refused);
}

/// Everything that needs a live peer on the other end.
#[test]
fn golden_remote_fixtures() {
    let fleet = Fleet::start();

    let (code, exec) = fleet.exec_json(&["--", "sh", "-c", "echo out; echo err >&2; exit 7"]);
    assert_eq!(code, 7, "{exec}");
    check("exec.run.json", exec);

    // Signal exits are POSIX semantics; the fixture is asserted where a
    // signal can actually happen.
    #[cfg(unix)]
    {
        let (code, killed) = fleet.exec_json(&["--", "sh", "-c", "kill -9 $$"]);
        assert_eq!(code, 137, "{killed}");
        assert_eq!(killed["data"]["signal"], "SIGKILL");
        check("exec.run.signal.json", killed);
    }

    let (code, timeout) = fleet.exec_json(&["--timeout", "300", "--", "sleep", "5"]);
    assert_eq!(code, 255, "{timeout}");
    check("error.TIMEOUT.json", timeout);

    let rogue = fleet.rogue();
    let (code, auth_failed) = rogue.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{auth_failed}");
    check("error.AUTH_FAILED.json", auth_failed);

    // `trust add` without `--fingerprint` observes the peer instead of
    // prompting, because machine mode never prompts (`docs/CLI.md` §2.1).
    let stranger = Sandbox::initialized();
    let (code, trust_required) = stranger.json(&[
        "trust",
        "add",
        HOST_ALIAS,
        "--address",
        fleet.addr(),
        "--json",
    ]);
    assert_eq!(code, 255, "{trust_required}");
    check("error.TRUST_REQUIRED.json", trust_required);
}

/// `tunnel.open`/`tunnel.list`/`tunnel.close` (`docs/CLI.md` §6.9, `PLAN.md`
/// M4 Step 5 PR 5b).
///
/// `tunnel.open` needs a real peer (`Fleet`) — the `Tunnel` envelope it
/// prints is the DoD 1 shape (`docs/CLI.md` §6.9's own example), captured
/// from the standalone `qsh tunnel open --json` machine-mode form (not the
/// interactive `-L`/PTY one `tunnel_e2e.rs` covers). The forward
/// destination is never dialed at open time (only per accepted
/// connection), so it does not need to exist for this fixture — `--local`
/// only has to bind.
///
/// `tunnel.list`/`tunnel.close` need no peer at all here: both are pure
/// local reads/asks against this machine's localctl daemons
/// (`Ops::tunnel_list`/`Ops::tunnel_close`'s own docs), and
/// `Sandbox::command` scrubs `XDG_RUNTIME_DIR` exactly as it does for
/// `host.list` (`golden_local_fixtures`'s own comment) — no daemon exists
/// in this sandbox, so `tunnels` is the ordinary empty-list state and
/// `tunnel close` on a made-up id is the ordinary `closed: false` state.
/// Both are real, deterministic outcomes, not placeholders — the
/// daemon-held non-empty case is `crates/qsh-testkit/tests/reverse_tunnel.rs`'s
/// L3 job, which drives an actual resident daemon.
#[test]
fn golden_tunnel_fixtures() {
    let fleet = Fleet::start();
    let port = free_port();

    let mut command = fleet.client.command(&[
        "tunnel",
        "open",
        HOST_ALIAS,
        "--local",
        &format!("{port}:localhost:1"),
        "--json",
    ]);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qsh tunnel open");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("tunnel open stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read the envelope line");
    assert!(!line.trim().is_empty(), "qsh tunnel open printed nothing");
    let opened: Value =
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("not JSON: {e}: {line:?}"));
    assert_eq!(opened["ok"], true, "{opened}");
    assert_eq!(opened["data"]["mode"], "local", "{opened}");
    check("tunnel.open.json", opened);

    let _ = child.kill();
    let _ = child.wait();

    let (code, listed) = fleet.client.json(&["tunnels", "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert_eq!(listed["data"]["tunnels"].as_array().map(Vec::len), Some(0));
    check("tunnel.list.json", listed);

    let (code, closed) = fleet
        .client
        .json(&["tunnel", "close", "01NOSUCHTUNNEL", "--json"]);
    assert_eq!(code, 0, "{closed}");
    assert_eq!(closed["data"]["closed"], false, "{closed}");
    check("tunnel.close.json", closed);
}

/// Pick a free TCP port on loopback by binding `:0` and reading it back —
/// same technique `tunnel_e2e.rs`'s own `free_port` uses, duplicated here
/// (fixture generation is deliberately self-contained, `fixtures.rs`'s own
/// module doc) rather than shared through `common`.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

/// The `session.*` value ops against a real `qsh serve` (PTY-backed
/// sessions, M2 Step 4): open → read → write → get → resize → list →
/// close → get (gone). A real PTY's byte stream is not reproducible
/// (prompt text differs per shell and platform), so the asserts here pin
/// invariants — cursor monotonicity and the shape of each envelope — while
/// the fixtures themselves mask payload and offsets.
// Sessions are PTY-backed, so this whole path only exists on POSIX hosts
// (Windows host is P2). The fixtures it writes are checked in and are
// still validated everywhere by the whole-directory contract tests below.
#[cfg(unix)]
#[test]
fn golden_session_fixtures() {
    let fleet = Fleet::start();
    let client = &fleet.client;

    let (code, opened) = client.json(&["session", "open", HOST_ALIAS, "--json", "--", "sh"]);
    assert_eq!(code, 0, "{opened}");
    let session_ref = opened["data"]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string();
    assert!(session_ref.starts_with(&format!("{HOST_ALIAS}/")));
    check("session.open.json", opened);

    // The shell writes its prompt as soon as the PTY is up; a long-poll
    // read from 0 returns it (no lease has been taken yet, so no control
    // events can interleave).
    let (code, read) = client.json(&[
        "session",
        "read",
        &session_ref,
        "--after",
        "0",
        "--wait",
        "5000",
        "--json",
    ]);
    assert_eq!(code, 0, "{read}");
    let events = read["data"]["events"].as_array().expect("events");
    assert!(!events.is_empty(), "{read}");
    assert!(
        events.iter().all(|e| e["type"] == "session.output"),
        "{read}"
    );
    // The reply carries the resume cursor a poller must feed back
    // (`--after`/`--ctl-after`, CLI.md §6.4): it is exactly the last
    // delivered output offset, and reading from 0 must have advanced it.
    let prompt_end = read["data"]["next_after"].as_u64().expect("next_after");
    assert!(prompt_end > 0, "{read}");
    assert_eq!(
        events.last().unwrap()["sequence"].as_u64(),
        Some(prompt_end),
        "{read}"
    );
    assert!(read["data"]["next_ctl_after"].is_u64(), "{read}");
    // One event in the fixture: the pull may split the banner in theory,
    // so keep the fixture to the first event only (shape is what it pins).
    let mut read_fixture = read.clone();
    read_fixture["data"]["events"] = Value::Array(vec![events[0].clone()]);
    check("session.read.json", read_fixture);

    // "hi\n" — the tty echoes it back, and the shell then reacts to it, so
    // the ring grows by *at least* the three bytes written.
    let (code, written) = client.json(&[
        "session",
        "write",
        &session_ref,
        "--data-b64",
        "aGkK",
        "--json",
    ]);
    assert_eq!(code, 0, "{written}");
    assert_eq!(written["data"]["bytes_written"], 3);
    check("session.write.json", written);

    // Bounded poll (no sleeps: each iteration is a real round trip) until
    // the echoed input has landed in the ring and the write's connection
    // has released its lease, so the snapshots below are stable.
    // Wall-clock bounded rather than iteration-bounded so a loaded box
    // does not fail spuriously.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let session = loop {
        let (code, session) = client.json(&["session", "get", &session_ref, "--json"]);
        assert_eq!(code, 0, "{session}");
        let last = session["data"]["last_sequence"]
            .as_u64()
            .expect("last_sequence");
        if last >= prompt_end + 3 && session["data"]["writer"].is_null() {
            break session;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "echoed output never reached the replay ring / lease never released: {session}"
        );
    };
    assert_eq!(session["data"]["state"], "running");
    check("session.get.json", session);

    let (code, resized) = client.json(&[
        "session",
        "resize",
        &session_ref,
        "--cols",
        "120",
        "--rows",
        "40",
        "--json",
    ]);
    assert_eq!(code, 0, "{resized}");
    check("session.resize.json", resized);

    let (code, listed) = client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert_eq!(listed["data"]["sessions"].as_array().map(Vec::len), Some(1));
    check("session.list.json", listed);

    let (code, closed) = client.json(&["session", "close", &session_ref, "--json"]);
    assert_eq!(code, 0, "{closed}");
    // A live shell keeps producing output, so the final offset is only
    // bounded from below by what we have already observed.
    assert!(
        closed["data"]["final_sequence"]
            .as_u64()
            .expect("final_sequence")
            >= prompt_end + 3,
        "{closed}"
    );
    check("session.close.json", closed);

    let (code, gone) = client.json(&["session", "get", &session_ref, "--json"]);
    assert_eq!(code, 255, "{gone}");
    assert_eq!(gone["error"]["code"], "SESSION_NOT_FOUND");
    check("error.SESSION_NOT_FOUND.json", gone);
}

/// `SESSION_CONFLICT` from the one producer the CLI reaches
/// deterministically: a write to a session whose child has already exited.
///
/// The code covers three broker refusals (`server/mod.rs`):
/// `BrokerError::Conflict` (a `no_steal` attach against a foreign lease,
/// which M2's CLI cannot ask for — `qsh attach` always sends
/// `no_steal: false` and there is no `--no-steal` flag), `NotWriter`, and
/// `NotRunning`. The last one needs nothing but a child that returned:
/// `session.write` checks the session's state before it checks the lease,
/// so an exited session refuses the write outright (`broker/session.rs`).
#[cfg(unix)]
#[test]
fn golden_session_conflict_fixture() {
    let fleet = Fleet::start();
    let client = &fleet.client;

    let (code, opened) = client.json(&[
        "session", "open", HOST_ALIAS, "--json", "--", "sh", "-c", "exit 0",
    ]);
    assert_eq!(code, 0, "{opened}");
    let session_ref = opened["data"]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string();

    // Bounded poll (each iteration is a real round trip, never a sleep)
    // until the host has reaped the child and the session has left
    // `running`. Wall-clock bounded so a loaded box does not fail
    // spuriously.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let (code, session) = client.json(&["session", "get", &session_ref, "--json"]);
        assert_eq!(code, 0, "{session}");
        if session["data"]["state"] == "exited" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the session never reached `exited`: {session}"
        );
    }

    // "x" — the byte never reaches a pty; the state check refuses it first.
    let (code, conflict) = client.json(&[
        "session",
        "write",
        &session_ref,
        "--data-b64",
        "eA==",
        "--json",
    ]);
    assert_eq!(code, 255, "{conflict}");
    assert_eq!(conflict["error"]["code"], "SESSION_CONFLICT", "{conflict}");
    check("error.SESSION_CONFLICT.json", conflict);
}

// ---------------------------------------------------------------------------
// Contract checks over the whole fixture directory
// ---------------------------------------------------------------------------

#[test]
fn every_required_fixture_exists() {
    if skip_while_regenerating() {
        return;
    }
    let present: BTreeSet<String> = fixtures::all_cli_v1()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for required in REQUIRED_FIXTURES {
        assert!(
            present.contains(*required),
            "missing fixture {required} (regenerate with {UPDATE_ENV}=1); have {present:?}"
        );
    }
}

#[test]
fn every_fixture_is_a_wellformed_v1_envelope() {
    if skip_while_regenerating() {
        return;
    }
    let known: BTreeSet<&str> = ErrorCode::KNOWN.iter().map(ErrorCode::as_str).collect();
    for (name, fixture) in fixtures::all_cli_v1() {
        assert_eq!(fixture["schema"], "qsh.cli/v1", "{name}");
        assert!(
            fixture["command"].as_str().is_some_and(|c| !c.is_empty()),
            "{name}: missing command"
        );
        assert!(fixture["request_id"].as_str().is_some(), "{name}");
        let ok = fixture["ok"]
            .as_bool()
            .unwrap_or_else(|| panic!("{name}: ok"));
        let has_data = fixture.get("data").is_some();
        let has_error = fixture.get("error").is_some();
        assert_eq!(
            has_data, ok,
            "{name}: `data` is present iff `ok` (docs/CLI.md §3)"
        );
        assert_eq!(has_error, !ok, "{name}: `error` is present iff `!ok`");
        if let Some(error) = fixture.get("error") {
            let code = error["code"].as_str().unwrap_or_else(|| panic!("{name}"));
            assert!(
                known.contains(code),
                "{name}: {code} is not in ErrorCode::KNOWN — error codes come from the \
                 single enum in qsh-proto, never an ad hoc string"
            );
            assert!(error["message"].as_str().is_some(), "{name}");
            assert!(error["retryable"].as_bool().is_some(), "{name}");
        }
    }
}

/// ADR-0007 (결과 절): the resume token is never a property of any JSON
/// contract type (`qsh-proto` pins the schemas) **and never appears in a
/// fixture** — this is the fixture half. Checked structurally on every
/// object key at any depth, and textually so a token smuggled inside a
/// string value would trip it too.
#[test]
fn no_fixture_carries_a_resume_token() {
    if skip_while_regenerating() {
        return;
    }
    fn keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                out.extend(map.keys().cloned());
                map.values().for_each(|c| keys(c, out));
            }
            Value::Array(items) => items.iter().for_each(|c| keys(c, out)),
            _ => {}
        }
    }
    for (name, fixture) in fixtures::all_cli_v1() {
        let mut names = Vec::new();
        keys(&fixture, &mut names);
        assert!(
            !names
                .iter()
                .any(|k| k.contains("resume_token") || k == "token"),
            "{name}: exposes a token field ({names:?}) — ADR-0007"
        );
        let text = serde_json::to_string(&fixture).expect("encode");
        assert!(
            !text.contains("resume_token"),
            "{name}: mentions resume_token"
        );
    }
}

#[test]
fn every_fixture_validates_against_the_envelope_schema() {
    if skip_while_regenerating() {
        return;
    }
    let schema = qsh_proto::schema::cli_v1_envelope_schema().to_value();
    let validator = jsonschema::validator_for(&schema).expect("envelope schema is valid");
    for (name, fixture) in fixtures::all_cli_v1() {
        if !validator.is_valid(&fixture) {
            let errors: Vec<String> = validator
                .iter_errors(&fixture)
                .map(|e| e.to_string())
                .collect();
            panic!("{name} does not match the CliEnvelope schema: {errors:#?}");
        }
    }
}

#[test]
fn every_fixture_payload_validates_against_its_command_schema() {
    if skip_while_regenerating() {
        return;
    }
    for (name, fixture) in fixtures::all_cli_v1() {
        let Some(data) = fixture.get("data") else {
            continue;
        };
        let command = fixture["command"].as_str().expect("command");
        let schema = data_schema(command)
            .unwrap_or_else(|| panic!("{name}: no data schema registered for command {command}"));
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|e| panic!("{command} data schema is invalid: {e}"));
        if !validator.is_valid(data) {
            let errors: Vec<String> = validator.iter_errors(data).map(|e| e.to_string()).collect();
            panic!("{name}: data does not match the {command} schema: {errors:#?}");
        }
    }
}

/// The JSON Schema of the `data` payload of one command — a thin wrapper
/// over [`qsh_proto::schema::cli_v1_data_schema`], the single source
/// `Ops::schema` (`qsh schema --json`) also reads from
/// (`crates/qsh-proto/src/schema.rs`, `PLAN.md` M7 Step 1 (b)). Kept as a
/// local `-> Option<Value>` helper only so every call site below stays
/// unchanged.
fn data_schema(command: &str) -> Option<Value> {
    qsh_proto::schema::cli_v1_data_schema(command).map(|s| s.to_value())
}

/// `docs/design/testing.md` L6: every `ErrorCode` variant is either covered
/// by a fixture or explicitly deferred to a named milestone. A code that is
/// in neither list is a code nothing can ever produce.
#[test]
fn every_error_code_is_covered_by_a_fixture_or_explicitly_deferred() {
    if skip_while_regenerating() {
        return;
    }
    let known: BTreeSet<String> = ErrorCode::KNOWN
        .iter()
        .map(|code| code.as_str().to_string())
        .collect();
    let covered: BTreeSet<String> = fixtures::all_cli_v1()
        .into_iter()
        .filter_map(|(_, fixture)| {
            fixture
                .get("error")
                .and_then(|e| e["code"].as_str().map(str::to_string))
        })
        .collect();
    let deferred: BTreeSet<String> = DEFERRED
        .iter()
        .map(|(code, _)| (*code).to_string())
        .collect();

    let both: Vec<&String> = covered.intersection(&deferred).collect();
    assert!(
        both.is_empty(),
        "these codes now have a fixture and must be removed from DEFERRED: {both:?}"
    );

    let union: BTreeSet<String> = covered.union(&deferred).cloned().collect();
    let unreachable: Vec<&String> = known.difference(&union).collect();
    assert!(
        unreachable.is_empty(),
        "no fixture and no DEFERRED entry for: {unreachable:?}"
    );
    let stale: Vec<&String> = union.difference(&known).collect();
    assert!(
        stale.is_empty(),
        "these are not ErrorCode::KNOWN codes: {stale:?}"
    );
}

/// Guards the two tests above against passing vacuously: a schemars type
/// that generated a permissive `true` schema would validate anything.
#[test]
fn the_generated_schemas_actually_reject_wrong_shapes() {
    let envelope = qsh_proto::schema::cli_v1_envelope_schema().to_value();
    let validator = jsonschema::validator_for(&envelope).expect("envelope schema is valid");
    for bad in [
        serde_json::json!({}),
        serde_json::json!({"schema": 1, "request_id": "r", "command": "c", "ok": true}),
        serde_json::json!({"schema": "qsh.cli/v1", "request_id": "r", "command": "c"}),
        serde_json::json!({
            "schema": "qsh.cli/v1", "request_id": "r", "command": "c", "ok": false,
            "error": {"code": "INTERNAL", "message": "m"}
        }),
    ] {
        assert!(
            !validator.is_valid(&bad),
            "the CliEnvelope schema accepted {bad}"
        );
    }

    let exec = data_schema("exec.run").expect("exec.run schema");
    let validator = jsonschema::validator_for(&exec).expect("exec.run schema is valid");
    for bad in [
        serde_json::json!({}),
        serde_json::json!({
            "stdout_b64": "", "stderr_b64": "", "remote_exit_code": "7",
            "signal": null, "duration_ms": 0
        }),
    ] {
        assert!(
            !validator.is_valid(&bad),
            "the ExecRunData schema accepted {bad}"
        );
    }
}

// ---------------------------------------------------------------------------
// `qsh schema --json` / `qsh capabilities [host]` (`PLAN.md` M7 Step 1)
// ---------------------------------------------------------------------------

/// `qsh schema --json`'s own output has no checked-in golden fixture in
/// this file (deliberately — see this test's own doc for why), so its
/// contract is pinned structurally instead: the binary's `data` must equal
/// what calling `qsh_proto::schema` directly produces, command by command
/// and for the envelope. That is the actual "one source" claim
/// (`docs/design/testing.md` L6, `PLAN.md` M7 Step 1 (b)) — not "the two
/// happen to agree today" but "there is only one generator function and
/// this command calls it".
///
/// No golden `schema.json` fixture: unlike every other command in
/// `REQUIRED_FIXTURES`, `schema.get`'s payload is a full registry dump
/// (envelope schema + one schema per known command) that grows every time
/// a later milestone step adds a new op/type — freezing it byte-for-byte
/// under the strict append-only rule (`docs/CLI.md` §10, this file's own
/// module doc) would make the very next PLAN.md step that adds an op a
/// forced fixture edit. `capabilities.json` above is the opposite case on
/// purpose: it must stay pinned so an *accidental* surface change is
/// caught (DoD 3's scope-creep tripwire); `schema.get`'s surface is
/// *expected* to grow, so this file proves it structurally instead of by
/// diffing bytes.
#[test]
fn schema_command_output_matches_the_single_source_generator() {
    let sandbox = Sandbox::new();
    let (code, response) = sandbox.json(&["schema", "--json"]);
    assert_eq!(code, 0, "{response}");

    let expected_envelope = qsh_proto::schema::cli_v1_envelope_schema().to_value();
    assert_eq!(response["data"]["envelope"], expected_envelope);

    let commands = response["data"]["commands"]
        .as_object()
        .expect("commands is an object");
    let expected_commands: BTreeSet<&str> = qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS
        .iter()
        .copied()
        .collect();
    let actual_commands: BTreeSet<String> = commands.keys().cloned().collect();
    assert_eq!(
        actual_commands,
        expected_commands.iter().map(|s| s.to_string()).collect(),
        "qsh schema --json's commands map must name exactly \
         qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS"
    );
    for command in qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS {
        let expected = qsh_proto::schema::cli_v1_data_schema(command)
            .expect("registered command has a schema")
            .to_value();
        assert_eq!(
            commands[*command], expected,
            "schema.get's schema for {command} does not match \
             qsh_proto::schema::cli_v1_data_schema({command:?})"
        );
    }
}

/// `qsh capabilities <host>`: no dedicated wire op exists for this
/// (`crates/qsh-core/src/ops/session.rs`'s `Ops::capabilities` own doc) —
/// it dials, negotiates `Hello` exactly like every other value op, and
/// reports the intersection that connection's own handshake settled on.
/// Both peers in `Fleet` run the exact same build, so the negotiated set
/// equals `wire::LOCAL_CAPABILITIES` (a proper subset would also be a
/// valid negotiation outcome against a peer advertising less, but nothing
/// in this harness constructs one, so equality is the correct assertion
/// here).
#[test]
fn capabilities_host_form_reports_the_negotiated_set() {
    let fleet = Fleet::start();
    let (code, response) = fleet.client.json(&["capabilities", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{response}");
    assert_eq!(response["command"], "capabilities.get", "{response}");
    assert_eq!(response["data"]["host"], HOST_ALIAS, "{response}");

    let local: Vec<String> = qsh_proto::wire::LOCAL_CAPABILITIES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let reported: Vec<String> = response["data"]["capabilities"]
        .as_array()
        .expect("capabilities is an array")
        .iter()
        .map(|v| v.as_str().expect("capability is a string").to_string())
        .collect();
    assert_eq!(reported, local, "{response}");
}
