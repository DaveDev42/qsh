//! L6 CLI: `qsh sessions --state / --writer / --attachable` against real
//! `qsh serve`, `qsh listen` and `qsh serve --to` processes (`docs/CLI.md`
//! §6.2, ADR-0033 decisions 1-3 and 13).
//!
//! The filters run in the client after the host answered, so what these
//! tests pin is the part only a real binary can show: the host cannot tell a
//! filtered call from an unfiltered one, `data.unreachable` survives a
//! filter, the resume credential never reaches an output, and the same
//! filter picks the same sessions whether the host is a forward `qsh serve`
//! or a reverse target behind the local `qsh listen` daemon.
//!
//! The tests seed live sessions with a POSIX shell script, and Windows has no
//! `sh`, so every test that needs a live session seeds it under `cfg(unix)`;
//! on Windows the same tests run over a host with zero sessions, which still drives the filter and the forward route on the
//! Windows client. The route-equivalence test has a Windows twin of the same
//! name that runs both routes (a `qsh serve` host and a `qsh serve --to`
//! target behind the local `qsh listen` daemon) over zero sessions: the
//! filters, `data.unreachable` and the host-less fan-out reaching the reverse
//! target through the daemon's named pipe are all observable without a
//! session.

use crate::common;

use common::{Fleet, HOST_ALIAS, Sandbox, exit_code, sole_envelope};
use serde_json::Value;

/// Wall-clock bound for every observable state this file waits for.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// The name the controller gives the reverse target.
const TARGET: &str = "nat-target";

/// The alias the target uses for the controller it dials.
const CONTROLLER_ALIAS: &str = "hub";

/// A `qsh listen` daemon on `controller` and a `qsh serve --to` target that
/// registered with it, once `qsh hosts` shows the registration reachable.
/// The target's own sandbox is returned to keep it alive.
fn reverse_target(controller: &Sandbox) -> (Sandbox, common::ListenGuard, common::ReverseGuard) {
    let target = Sandbox::initialized();
    let target_fp = target.fingerprint();
    let controller_fp = controller.fingerprint();

    // The target pin carries an address so the host-less fan-out visits it
    // (it only asks pins that have one). The address is never dialed: a
    // live reverse registration wins the route (`docs/CLI.md` §6.1).
    controller.trust_add(TARGET, Some("127.0.0.1:0"), &target_fp);
    let listen = common::ListenGuard::start(controller);
    target.trust_add(CONTROLLER_ALIAS, Some(listen.addr()), &controller_fp);
    let reverse = common::ReverseGuard::start_serve_to(&target, CONTROLLER_ALIAS);

    common::poll_until("the reverse registration to be reachable", DEADLINE, || {
        common::hosts_array(controller)
            .iter()
            .any(|h| {
                h["name"] == TARGET
                    && h["connection_mode"] == "reverse"
                    && h["state"] == "reachable"
            })
            .then_some(())
    });
    (target, listen, reverse)
}

/// A listing in `--json` mode: the whole envelope after asserting success.
fn list_json(client: &Sandbox, args: &[&str]) -> Value {
    let mut argv = vec!["sessions"];
    argv.extend_from_slice(args);
    argv.push("--json");
    let (code, envelope) = client.json(&argv);
    assert_eq!(code, 0, "qsh {argv:?}: {envelope}");
    assert_eq!(envelope["ok"], true, "{envelope}");
    envelope
}

/// The `session_ref`s of a listing envelope, in the order given.
#[cfg(unix)]
fn refs(envelope: &Value) -> Vec<String> {
    envelope["data"]["sessions"]
        .as_array()
        .expect("data.sessions")
        .iter()
        .map(|s| s["session_ref"].as_str().expect("session_ref").to_string())
        .collect()
}

#[cfg(unix)]
mod seeded {
    //! One host's worth of sessions in four known shapes, plus the pty
    //! client that holds the writer lease of one of them.

    use super::*;
    use std::collections::BTreeSet;

    use common::poll_until;
    use expectrl::Session;
    use expectrl::session::OsSession;

    /// What a seeded session is, as the filters see it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Role {
        /// `running`, a pty client holds the writer lease, attachable.
        Writer,
        /// `running`, no writer, attachable.
        Plain,
        /// `running`, no writer, no credential on this device.
        Foreign,
        /// `exited`, no writer, attachable.
        Exited,
    }

    /// The four sessions on one host and the guard that keeps the writer
    /// lease of [`Role::Writer`] held for as long as it lives.
    pub struct Seeded {
        pub host: String,
        pub writer_ref: String,
        pub plain_ref: String,
        pub foreign_ref: String,
        pub exited_ref: String,
        /// The principal string the host reports as the writer.
        pub writer_principal: String,
        _attached: OsSession,
    }

    impl Seeded {
        pub fn role_of(&self, session_ref: &str) -> Role {
            if session_ref == self.writer_ref {
                Role::Writer
            } else if session_ref == self.plain_ref {
                Role::Plain
            } else if session_ref == self.foreign_ref {
                Role::Foreign
            } else if session_ref == self.exited_ref {
                Role::Exited
            } else {
                panic!(
                    "{session_ref} is not one of {}'s seeded sessions",
                    self.host
                )
            }
        }
    }

    /// `session open <host> -- <argv>`; the new `session_ref`.
    pub fn open(client: &Sandbox, host: &str, argv: &[&str]) -> String {
        let mut args = vec!["session", "open", host, "--json", "--"];
        args.extend_from_slice(argv);
        let (code, opened) = client.json(&args);
        assert_eq!(code, 0, "{opened}");
        opened["data"]["session_ref"]
            .as_str()
            .expect("session_ref")
            .to_string()
    }

    /// Wait until the host reports `session_ref` as `exited`.
    pub fn wait_exited(client: &Sandbox, session_ref: &str) {
        poll_until("a short-lived session to exit", DEADLINE, || {
            let (code, got) = client.json(&["session", "get", session_ref, "--json"]);
            assert_eq!(code, 0, "{got}");
            (got["data"]["state"] == "exited").then_some(())
        });
    }

    /// Drop `session_ref`'s entry from this device's `resume.json`, which
    /// is what a session opened from another device looks like here:
    /// listed, but not attachable. The token itself is never read into a
    /// string.
    pub fn forget_credential(client: &Sandbox, session_ref: &str) {
        let path = client.state_dir().join("resume.json");
        let raw = std::fs::read(&path).expect("resume.json exists after session open");
        let mut doc: Value = serde_json::from_slice(&raw).expect("resume.json is JSON");
        let removed = doc["sessions"]
            .as_object_mut()
            .expect("resume.json has a sessions map")
            .remove(session_ref);
        assert!(removed.is_some(), "no credential for {session_ref}");
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).expect("encode")).expect("rewrite");
    }

    /// The four sessions on one host before anything holds a lease.
    pub struct Opened {
        pub host: String,
        pub writer_ref: String,
        pub plain_ref: String,
        pub foreign_ref: String,
        pub exited_ref: String,
    }

    /// Open the four sessions on `host`, make one of them non-attachable
    /// and let one exit. `resume.json` is rewritten here, so this runs for
    /// every host before any [`hold_writer`] starts an attach that renews
    /// entries in the same file.
    pub fn open_all(client: &Sandbox, host: &str) -> Opened {
        let writer_ref = open(client, host, &["cat"]);
        let plain_ref = open(client, host, &["cat"]);
        let foreign_ref = open(client, host, &["cat"]);
        let exited_ref = open(client, host, &["sh", "-c", "exit 0"]);
        forget_credential(client, &foreign_ref);
        wait_exited(client, &exited_ref);
        Opened {
            host: host.to_string(),
            writer_ref,
            plain_ref,
            foreign_ref,
            exited_ref,
        }
    }

    /// Hold the writer lease of [`Role::Writer`] with a real pty attach and
    /// return once the host reports the writer.
    pub fn hold_writer(client: &Sandbox, opened: Opened) -> Seeded {
        let mut command = client.command(&["attach", &opened.writer_ref]);
        command.env("TERM", "xterm-256color");
        let attached = Session::spawn(command).expect("spawn qsh attach under a pty");

        let host = opened.host.as_str();
        let writer_ref = opened.writer_ref.as_str();
        let writer_principal = poll_until("the attach to take the writer lease", DEADLINE, || {
            let listing = list_json(client, &[host]);
            listing["data"]["sessions"]
                .as_array()?
                .iter()
                .find(|s| s["session_ref"] == writer_ref)
                .and_then(|s| s["writer"].as_str())
                .map(str::to_string)
        });
        Seeded {
            host: opened.host,
            writer_ref: opened.writer_ref,
            plain_ref: opened.plain_ref,
            foreign_ref: opened.foreign_ref,
            exited_ref: opened.exited_ref,
            writer_principal,
            _attached: attached,
        }
    }

    /// [`open_all`] then [`hold_writer`] for a single host.
    pub fn seed(client: &Sandbox, host: &str) -> Seeded {
        hold_writer(client, open_all(client, host))
    }

    /// The `(role)` set of a listing for one seeded host. Panics on a
    /// session that is not one of its four.
    pub fn roles(envelope: &Value, seeded: &Seeded) -> BTreeSet<Role> {
        refs(envelope)
            .iter()
            .filter(|r| r.starts_with(&format!("{}/", seeded.host)))
            .map(|r| seeded.role_of(r))
            .collect()
    }

    /// Every filter combination the tests run, with the roles it must keep
    /// (`writer` stands for the principal the host reported).
    pub fn cases(seeded: &Seeded) -> Vec<(Vec<String>, BTreeSet<Role>)> {
        use Role::{Exited, Foreign, Plain, Writer};
        let args = |items: &[&str]| items.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let set = |items: &[Role]| items.iter().copied().collect::<BTreeSet<_>>();
        let p = seeded.writer_principal.as_str();
        vec![
            (args(&[]), set(&[Writer, Plain, Foreign, Exited])),
            (
                args(&["--state", "running"]),
                set(&[Writer, Plain, Foreign]),
            ),
            (args(&["--state", "exited"]), set(&[Exited])),
            (args(&["--writer", "none"]), set(&[Plain, Foreign, Exited])),
            (args(&["--writer", p]), set(&[Writer])),
            (args(&["--attachable"]), set(&[Writer, Plain, Exited])),
            (
                args(&["--state", "running", "--writer", "none", "--attachable"]),
                set(&[Plain]),
            ),
            (args(&["--state", "exited", "--attachable"]), set(&[Exited])),
            (
                args(&["--state", "running", "--writer", p, "--attachable"]),
                set(&[Writer]),
            ),
            (args(&["--state", "exited", "--writer", p]), set(&[])),
            (args(&["--state", "no-such-state"]), set(&[])),
        ]
    }
}

#[cfg(unix)]
#[test]
fn sessions_filter_state_writer_attachable_and_combined() {
    let fleet = Fleet::start();
    let client = &fleet.client;
    let seeded = seeded::seed(client, HOST_ALIAS);

    let unfiltered = list_json(client, &[HOST_ALIAS]);
    let unfiltered_refs = refs(&unfiltered);
    assert_eq!(unfiltered_refs.len(), 4, "{unfiltered}");

    for (filter, expected) in seeded::cases(&seeded) {
        let args: Vec<&str> = std::iter::once(HOST_ALIAS)
            .chain(filter.iter().map(String::as_str))
            .collect();
        let listing = list_json(client, &args);
        assert_eq!(
            seeded::roles(&listing, &seeded),
            expected,
            "qsh sessions {filter:?}: {listing}"
        );
        // A filter keeps the host's order and invents nothing.
        let kept = refs(&listing);
        let in_host_order: Vec<String> = unfiltered_refs
            .iter()
            .filter(|r| kept.contains(r))
            .cloned()
            .collect();
        assert_eq!(kept, in_host_order, "qsh sessions {filter:?}");
        // The JSON shape is the unfiltered shape: one `sessions` array and
        // no filter echo, no count, no new key.
        let data = listing["data"].as_object().expect("data object");
        assert_eq!(
            data.keys().collect::<Vec<_>>(),
            ["sessions"],
            "qsh sessions {filter:?}: {listing}"
        );
        for session in listing["data"]["sessions"].as_array().expect("sessions") {
            let same_ref = session["session_ref"].as_str().expect("session_ref");
            let original = unfiltered["data"]["sessions"]
                .as_array()
                .expect("sessions")
                .iter()
                .find(|s| s["session_ref"] == same_ref)
                .expect("a kept session was in the unfiltered listing");
            assert_eq!(
                session.as_object().map(|o| o.keys().collect::<Vec<_>>()),
                original.as_object().map(|o| o.keys().collect::<Vec<_>>()),
                "qsh sessions {filter:?} changed a session's keys"
            );
        }
    }

    // Without a host the call fans out over every pinned host; with only
    // one pinned host the answer is the same set.
    let fan_out = list_json(client, &["--state", "running", "--attachable"]);
    assert_eq!(
        seeded::roles(&fan_out, &seeded),
        [seeded::Role::Writer, seeded::Role::Plain]
            .into_iter()
            .collect()
    );
}

#[cfg(unix)]
#[test]
fn sessions_filter_does_not_change_the_wire_request() {
    let fleet = Fleet::start();
    let client = &fleet.client;
    let _open = seeded::open(client, HOST_ALIAS, &["cat"]);

    // The request type carries a host and nothing else. Were a filter
    // field added, this would be the first place to notice.
    assert_eq!(
        serde_json::to_value(qsh_proto::SessionListReq::default()).expect("encode"),
        serde_json::json!({})
    );
    assert_eq!(
        serde_json::to_value(qsh_proto::SessionListReq {
            host: Some(HOST_ALIAS.into())
        })
        .expect("encode"),
        serde_json::json!({ "host": HOST_ALIAS })
    );

    let before = fleet.host.audit_records().len();
    for args in [
        &[HOST_ALIAS][..],
        &[HOST_ALIAS, "--state", "running"],
        &[HOST_ALIAS, "--state", "no-such-state", "--attachable"],
        &[HOST_ALIAS, "--writer", "none", "--state", "running"],
    ] {
        list_json(client, args);
    }

    // What the host recorded for each call. A host that could tell the
    // calls apart would have a field, a resource or a decision that
    // differs; only the timestamp and request id may.
    let records: Vec<Value> = fleet.host.audit_records()[before..]
        .iter()
        .filter(|r| r["action"] == "session.list")
        .cloned()
        .map(|mut r| {
            let object = r.as_object_mut().expect("audit record");
            // Per-call values: the timestamp, the request id and the
            // client's ephemeral source port.
            object.remove("ts");
            object.remove("request_id");
            object.remove("peer_addr");
            r
        })
        .collect();
    assert_eq!(records.len(), 4, "one session.list per call: {records:?}");
    assert!(
        records.iter().all(|r| r == &records[0]),
        "the host saw different session.list requests: {records:?}"
    );
}

#[test]
fn sessions_filter_keeps_unreachable_in_fan_out() {
    let fleet = Fleet::start();
    let client = &fleet.client;
    // A pinned host with an address nothing listens on, as
    // `exit_code_matrix` uses for the unfiltered fan-out.
    client.trust_add("deadport", Some("127.0.0.1:0"), &fleet.host_fingerprint);
    #[cfg(unix)]
    let _open = seeded::open(client, HOST_ALIAS, &["cat"]);

    for filter in [
        &["--state", "running"][..],
        &["--state", "no-such-state"],
        &["--writer", "none", "--attachable"],
    ] {
        let listing = list_json(client, filter);
        let unreachable = listing["data"]["unreachable"]
            .as_array()
            .unwrap_or_else(|| panic!("a filter hid data.unreachable: {listing}"));
        assert_eq!(unreachable.len(), 1, "{listing}");
        assert_eq!(unreachable[0]["host"], "deadport", "{listing}");
        assert_eq!(unreachable[0]["code"], "CONNECTION_FAILED", "{listing}");
    }

    // The filter that removes everything leaves the failure visible, in
    // human mode too: stderr names the host, stdout stays a table.
    let human = client.qsh(&["sessions", "--state", "no-such-state"]);
    assert_eq!(exit_code(&human), 0);
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(stderr.contains("deadport"), "human stderr was {stderr:?}");
    assert!(
        !String::from_utf8_lossy(&human.stdout).contains("deadport"),
        "an unreachable host is not a table row"
    );
}

#[test]
fn sessions_filter_unknown_state_is_empty_not_an_error() {
    let fleet = Fleet::start();
    let client = &fleet.client;
    #[cfg(unix)]
    let _open = seeded::open(client, HOST_ALIAS, &["cat"]);

    for state in ["no-such-state", "Running", "", "run"] {
        let args = ["sessions", HOST_ALIAS, "--state", state, "--json"];
        let output = client.qsh(&args);
        assert_eq!(exit_code(&output), 0, "state {state:?}: {output:?}");
        let envelope = sole_envelope(&output.stdout, &args);
        assert_eq!(envelope["ok"], true, "state {state:?}: {envelope}");
        assert_eq!(
            envelope["data"]["sessions"],
            serde_json::json!([]),
            "state {state:?}: {envelope}"
        );
    }
}

#[test]
fn sessions_filter_human_count_line_goes_to_stderr_only() {
    let fleet = Fleet::start();
    let client = &fleet.client;
    #[cfg(unix)]
    let total = {
        let _running = seeded::open(client, HOST_ALIAS, &["cat"]);
        let exited = seeded::open(client, HOST_ALIAS, &["sh", "-c", "exit 0"]);
        seeded::wait_exited(client, &exited);
        (2usize, 1usize)
    };
    #[cfg(not(unix))]
    let total = (0usize, 0usize);
    let (all, running) = total;

    let filtered = client.qsh(&["sessions", HOST_ALIAS, "--state", "running"]);
    assert_eq!(exit_code(&filtered), 0, "{filtered:?}");
    let stderr = String::from_utf8_lossy(&filtered.stderr);
    let stdout = String::from_utf8_lossy(&filtered.stdout);
    let line = format!("qsh: showing {running} of {all} sessions");
    assert_eq!(
        stderr.lines().filter(|l| l.contains("showing")).count(),
        1,
        "stderr was {stderr:?}"
    );
    assert!(stderr.contains(&line), "stderr was {stderr:?}");
    assert!(
        !stdout.contains("showing"),
        "the count line must not reach stdout: {stdout:?}"
    );

    // No filter, no line.
    let plain = client.qsh(&["sessions", HOST_ALIAS]);
    assert_eq!(exit_code(&plain), 0, "{plain:?}");
    assert!(
        !String::from_utf8_lossy(&plain.stderr).contains("showing"),
        "an unfiltered call has no count line: {plain:?}"
    );

    // Machine mode: stdout is one envelope, stderr carries no count line.
    let args = ["sessions", HOST_ALIAS, "--state", "running", "--json"];
    let json = client.qsh(&args);
    assert_eq!(exit_code(&json), 0, "{json:?}");
    let envelope = sole_envelope(&json.stdout, &args);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert!(
        !String::from_utf8_lossy(&json.stderr).contains("showing"),
        "--json has no count line: {json:?}"
    );
    assert!(
        envelope["data"].get("total").is_none() && envelope["data"].get("filtered").is_none(),
        "the count is not part of the JSON data: {envelope}"
    );
}

#[cfg(unix)]
#[test]
fn sessions_attachable_never_prints_the_resume_token() {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    let fleet = Fleet::start();
    let client = &fleet.client;
    let session_ref = seeded::open(client, HOST_ALIAS, &["cat"]);

    // The credential this device stores for the session. The test reads it
    // only to look for it in the outputs below.
    let doc: Value = serde_json::from_slice(
        &std::fs::read(client.state_dir().join("resume.json")).expect("resume.json"),
    )
    .expect("resume.json is JSON");
    let token = doc["sessions"][&session_ref]["token"]
        .as_str()
        .expect("a stored token")
        .to_string();
    assert!(token.len() >= 32, "unexpectedly short stored token");
    let raw = STANDARD.decode(&token).expect("stored token is Base64");
    let needles = [
        token.clone(),
        STANDARD.encode(&raw),
        URL_SAFE_NO_PAD.encode(&raw),
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    ];

    let runs: [&[&str]; 4] = [
        &["sessions", HOST_ALIAS, "--attachable", "--json"],
        &["sessions", "--attachable", "--json"],
        &["sessions", HOST_ALIAS, "--attachable"],
        &["-vv", "sessions", HOST_ALIAS, "--attachable"],
    ];
    for args in runs {
        let output = client.qsh(args);
        assert_eq!(exit_code(&output), 0, "qsh {args:?}: {output:?}");
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            text.contains(&session_ref),
            "the attachable session is listed: {text}"
        );
        for needle in &needles {
            assert!(
                !text.contains(needle.as_str()),
                "qsh {args:?} printed the resume token"
            );
        }
    }
}

/// The reverse half of ADR-0033 decision 13. One machine (the
/// "controller") runs `qsh listen`, pins a forward host it dials and a
/// reverse target that dialed it. The same four sessions are seeded on
/// both, and every filter has to pick the same roles on both, with the
/// host-less fan-out returning exactly the union of the two.
#[cfg(unix)]
#[test]
fn sessions_filter_applies_identically_to_forward_and_reverse_hosts() {
    use std::collections::BTreeSet;

    // `fleet.host` is the forward host (`qsh serve`); `fleet.client` is the
    // controller that pins it and also runs `qsh listen`.
    let fleet = Fleet::start();
    let controller = &fleet.client;
    let (_target, listen, reverse) = reverse_target(controller);

    // Both hosts' sessions are opened (and `resume.json` rewritten) before
    // either attach starts renewing entries in that file.
    let forward_opened = seeded::open_all(controller, HOST_ALIAS);
    let reversed_opened = seeded::open_all(controller, TARGET);
    let forward = seeded::hold_writer(controller, forward_opened);
    let reversed = seeded::hold_writer(controller, reversed_opened);

    // Same roles per filter on both hosts, and per host-less fan-out the
    // union of the two.
    let forward_cases = seeded::cases(&forward);
    let reverse_cases = seeded::cases(&reversed);
    for ((filter, expected), (reverse_filter, reverse_expected)) in
        forward_cases.iter().zip(&reverse_cases)
    {
        assert_eq!(
            expected, reverse_expected,
            "the expectation table differs between hosts for {filter:?}"
        );
        let on = |host: &str, filter: &[String]| {
            let args: Vec<&str> = std::iter::once(host)
                .chain(filter.iter().map(String::as_str))
                .collect();
            list_json(controller, &args)
        };
        let via_forward = on(HOST_ALIAS, filter);
        let via_reverse = on(TARGET, reverse_filter);
        assert_eq!(
            &seeded::roles(&via_forward, &forward),
            expected,
            "forward host, qsh sessions {filter:?}: {via_forward}"
        );
        assert_eq!(
            &seeded::roles(&via_reverse, &reversed),
            reverse_expected,
            "reverse host, qsh sessions {reverse_filter:?}: {via_reverse}"
        );

        let fan_args: Vec<&str> = filter.iter().map(String::as_str).collect();
        let fan_out = list_json(controller, &fan_args);
        assert!(
            fan_out["data"].get("unreachable").is_none(),
            "both hosts answered the fan-out: {fan_out}"
        );
        // A writer principal is host-relative: the reverse target knows the
        // controller by the identity it pinned, not by the name the forward
        // host uses. The host-less call carries the forward spelling, so
        // the reverse host contributes to it only when the two agree.
        let by_principal = filter
            .windows(2)
            .any(|w| w[0] == "--writer" && w[1] != "none");
        let same_principal = forward.writer_principal == reversed.writer_principal;
        let expected_refs: BTreeSet<String> = if by_principal && !same_principal {
            refs(&via_forward).into_iter().collect()
        } else {
            refs(&via_forward)
                .into_iter()
                .chain(refs(&via_reverse))
                .collect()
        };
        let fanned: BTreeSet<String> = refs(&fan_out).into_iter().collect();
        assert_eq!(
            fanned, expected_refs,
            "fan-out for {filter:?} is not the union of the per-host results"
        );
        assert_eq!(
            refs(&fan_out).len(),
            fanned.len(),
            "fan-out repeated a session: {fan_out}"
        );
    }

    drop(forward);
    drop(reversed);
    reverse.shut_down();
    drop(listen);
}

/// The Windows twin of the test above, over hosts with no sessions (seeding
/// is a POSIX shell script). What it pins is the route part: every filter
/// returns the same empty listing from the forward host and from the reverse
/// target, and the host-less fan-out reaches the reverse target through the
/// local daemon's named pipe. The target's pin carries an address nothing
/// listens on, so a fan-out that came back without `data.unreachable` did get
/// its answer over the registration, not a forward dial. With the
/// registration gone the same fan-out reports the target unreachable and
/// keeps the filter.
#[cfg(windows)]
#[test]
fn sessions_filter_applies_identically_to_forward_and_reverse_hosts() {
    let fleet = Fleet::start();
    let controller = &fleet.client;
    let (target, listen, reverse) = reverse_target(controller);

    let filters: [&[&str]; 4] = [
        &[],
        &["--state", "running"],
        &["--writer", "none", "--attachable"],
        &["--state", "no-such-state"],
    ];
    for filter in filters {
        let on = |host: Option<&str>| {
            let args: Vec<&str> = host.into_iter().chain(filter.iter().copied()).collect();
            list_json(controller, &args)
        };
        for (what, listing) in [
            ("forward host", on(Some(HOST_ALIAS))),
            ("reverse host", on(Some(TARGET))),
            ("fan-out", on(None)),
        ] {
            assert_eq!(
                listing["data"]["sessions"],
                serde_json::json!([]),
                "{what}, qsh sessions {filter:?}: {listing}"
            );
            assert!(
                listing["data"].get("unreachable").is_none(),
                "{what} reached both hosts, qsh sessions {filter:?}: {listing}"
            );
        }
    }

    // Lose the registration: the host-less call now cannot reach the target
    // (its pinned address is undialable), says so, and a filter does not hide
    // that.
    reverse.shut_down();
    common::poll_until(
        "the lost target to show as unreachable in the fan-out",
        DEADLINE,
        || {
            let listing = list_json(controller, &["--state", "running"]);
            let unreachable = listing["data"]["unreachable"].as_array()?;
            unreachable
                .iter()
                .any(|u| u["host"] == TARGET)
                .then_some(())
        },
    );
    drop(target);
    drop(listen);
}
