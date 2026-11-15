//! L6 CLI: `qsh sessions --state / --writer / --attachable` against a real
//! `qsh serve` process (`docs/CLI.md` §6.2, ADR-0033 decisions 1-3; the
//! reverse-host route equivalence of decision 13 retired with ADR-0068).
//!
//! The filters run in the client after the host answered, so what these
//! tests pin is the part only a real binary can show: the host cannot tell a
//! filtered call from an unfiltered one, `data.unreachable` survives a
//! filter, the resume credential never reaches an output, and the same
//! filter picks the same sessions whether the host is a forward `qsh serve`
//! or a reverse target behind the local `qsh listen` daemon.
//!
//! The sessions are live ones on both platforms. A session is a program in a
//! pseudo-terminal (`cat` and `true` on unix, `findstr "^"` and `cmd /c exit
//! 0` on Windows, `qsh_testkit::shell`), and the writer lease of one of them
//! is held by a real `qsh attach` under a pty: `expectrl` on unix, a ConPTY
//! (`windows_attach::spawn_qsh`) on Windows. The route-equivalence test runs
//! both routes (a `qsh serve` host and a `qsh serve --to` target behind the
//! local `qsh listen` daemon, which on Windows is reached through its named
//! pipe). A Windows-only test adds the part that needs no session: the
//! host-less fan-out reaching the reverse target through the daemon, and
//! reporting it unreachable once the registration is gone.

use crate::common;

use common::{Fleet, HOST_ALIAS, Sandbox, exit_code, sole_envelope};
use qsh_testkit::shell::{cat_argv, true_argv};
use serde_json::Value;

/// Wall-clock bound for every observable state this file waits for.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

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
fn refs(envelope: &Value) -> Vec<String> {
    envelope["data"]["sessions"]
        .as_array()
        .expect("data.sessions")
        .iter()
        .map(|s| s["session_ref"].as_str().expect("session_ref").to_string())
        .collect()
}

mod seeded {
    //! One host's worth of sessions in four known shapes, plus the pty
    //! client that holds the writer lease of one of them.

    use super::*;
    use std::collections::BTreeSet;

    use common::poll_until;
    use qsh_testkit::shell::{cat_argv, true_argv};

    /// The client that holds a writer lease: a `qsh attach` in a pty.
    #[cfg(unix)]
    pub struct Holder {
        _session: expectrl::session::OsSession,
    }

    /// See the unix definition.
    #[cfg(windows)]
    pub struct Holder {
        _console: qsh_testkit::conpty::ConPtyProbe,
    }

    impl Holder {
        #[cfg(unix)]
        fn attach(client: &Sandbox, session_ref: &str) -> Self {
            let mut command = client.command(&["attach", session_ref]);
            command.env("TERM", "xterm-256color");
            Self {
                _session: expectrl::Session::spawn(command).expect("spawn qsh attach under a pty"),
            }
        }

        #[cfg(windows)]
        fn attach(client: &Sandbox, session_ref: &str) -> Self {
            Self {
                _console: crate::windows_attach::spawn_qsh(client, &["attach", session_ref]),
            }
        }
    }

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
        _attached: Holder,
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
    pub fn open(client: &Sandbox, host: &str, argv: &[String]) -> String {
        let mut args = vec!["session", "open", host, "--json", "--"];
        args.extend(argv.iter().map(String::as_str));
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
        let writer_ref = open(client, host, &cat_argv());
        let plain_ref = open(client, host, &cat_argv());
        let foreign_ref = open(client, host, &cat_argv());
        let exited_ref = open(client, host, &true_argv());
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
        let attached = Holder::attach(client, &opened.writer_ref);

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

#[test]
fn sessions_filter_does_not_change_the_wire_request() {
    let fleet = Fleet::start();
    let client = &fleet.client;
    let _open = seeded::open(client, HOST_ALIAS, &cat_argv());

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
    let _open = seeded::open(client, HOST_ALIAS, &cat_argv());

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
    let _open = seeded::open(client, HOST_ALIAS, &cat_argv());

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
    let _running = seeded::open(client, HOST_ALIAS, &cat_argv());
    let exited = seeded::open(client, HOST_ALIAS, &true_argv());
    seeded::wait_exited(client, &exited);
    let (all, running) = (2usize, 1usize);

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

#[test]
fn sessions_attachable_never_prints_the_resume_token() {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    let fleet = Fleet::start();
    let client = &fleet.client;
    let session_ref = seeded::open(client, HOST_ALIAS, &cat_argv());

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
