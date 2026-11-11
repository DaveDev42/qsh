//! **L5 real-process** — the lifecycle of `qsh listen` with `[listen].serve =
//! true` (ADR-0059 decisions 17 and 19): the SIGTERM order and the restart
//! banner, and the `serve.json` record the SSH bootstrap finds.
//!
//! The in-process halves of the same decisions are in `qsh-testkit`
//! (`combined::combined_shutdown_closes_registrations_before_the_drain`,
//! `combined_lifecycle::*`); this file proves them against real children:
//! `qsh listen` with the key in its `config.toml`, `qsh serve --to` as the
//! registered target, and a client with a session of its own.

#![cfg(unix)]

use crate::common;
use crate::serve_sigterm_drain::{
    DRAIN_BOUND, child_script, ops_for, read_closed_reason, read_pid, with_deadline,
};

use std::path::Path;
use std::time::Duration;

use common::{
    CLIENT_ALIAS, HOST_ALIAS, ListenGuard, ReverseGuard, Sandbox, exit_code, hosts_array,
    poll_until,
};
use nix::sys::signal::kill;
use nix::unistd::Pid;
use qsh_proto::{EnvVar, SessionAttachReq, SessionOpenReq};
use qsh_testkit::fake_ssh::FakeSsh;
use serde_json::Value;

const QSH: &str = env!("CARGO_BIN_EXE_qsh");

/// The key that turns a listen into the combined endpoint.
const COMBINED: &str = "[listen]\nserve = true\n";

fn serve_record(sandbox: &Sandbox) -> Option<Value> {
    let text = std::fs::read(sandbox.state_dir().join("serve.json")).ok()?;
    serde_json::from_slice(&text).ok()
}

/// SIGTERM on a combined `qsh listen` with a registered target, a session and
/// an attached consumer: the process exits `0`, the target hears its
/// registration close at once (a `lost` event with cause `peer_closed`, not
/// an idle timeout), the consumer sees `session.closed{reason:"closed"}`,
/// nothing answers for the session's child, `serve.json` is gone, and the
/// banner that says sessions live in this process was printed. The `drained`
/// line carries counts only.
#[test]
fn combined_sigterm_drains_sessions_and_closes_registrations() {
    with_deadline("combined sigterm", || {
        let host = Sandbox::initialized();
        std::fs::write(host.config_dir().join("config.toml"), COMBINED).unwrap();
        let target = Sandbox::initialized();
        let client = Sandbox::initialized();
        let (host_fp, target_fp, client_fp) = (
            host.fingerprint(),
            target.fingerprint(),
            client.fingerprint(),
        );
        host.trust_add("widget", None, &target_fp);
        host.trust_add_with_role(CLIENT_ALIAS, None, &client_fp, "none");

        let mut listen = ListenGuard::start_with(&host, "127.0.0.1:0");
        let addr = listen.addr().to_string();
        client.trust_add(HOST_ALIAS, Some(&addr), &host_fp);
        target.trust_add("ctl", Some(&addr), &host_fp);
        let target_proc = ReverseGuard::start_serve_to(&target, "ctl");

        // Both roles are up: the target is registered with the endpoint and
        // the client has a session on its host side.
        poll_until("the target's registration", Duration::from_secs(20), || {
            hosts_array(&host)
                .iter()
                .any(|h| h["connection_mode"] == "reverse" && h["state"] == "reachable")
                .then_some(())
        });
        let ops = ops_for(&client);
        let session_ref = ops
            .session_open(SessionOpenReq {
                host: HOST_ALIAS.to_string(),
                argv: vec!["sh".to_string(), "-c".to_string(), child_script()],
                env: vec![EnvVar {
                    name: "LANG".into(),
                    value: "C".into(),
                }],
                term: Some("xterm-256color".into()),
                cols: Some(80),
                rows: Some(24),
                user: None,
                shell_command: None,
            })
            .expect("session.open on the combined endpoint")
            .session_ref;
        let mut stream = ops
            .session_attach(
                SessionAttachReq {
                    session_ref,
                    no_steal: false,
                },
                &[],
            )
            .expect("session.attach");
        let child = Pid::from_raw(read_pid(&mut stream));
        assert!(
            kill(child, None).is_ok(),
            "the child is alive before SIGTERM"
        );

        // The startup lines: listen's, then serve's on the same stderr, and
        // the restart banner.
        let lines = listen.stderr_lines();
        let at = |prefix: &str| {
            lines
                .iter()
                .position(|l| l.starts_with(prefix))
                .unwrap_or_else(|| panic!("no `{prefix}` line in {lines:?}"))
        };
        assert!(
            at("qsh listen: listening on ") < at("qsh serve: listening on "),
            "serve's address line follows listen's: {lines:?}"
        );
        at("qsh serve: sessions live inside this process");
        let record = serve_record(&host).expect("serve.json while running");
        assert_eq!(record["mode"], "persistent", "{record}");
        assert_eq!(record["pid"].as_u64(), Some(u64::from(listen.pid())));
        assert_eq!(record["addr"], addr.as_str(), "{record}");

        // ---- SIGTERM ----
        listen.terminate();
        let status = listen
            .wait_timeout(DRAIN_BOUND)
            .unwrap_or_else(|| panic!("the combined listen did not exit within {DRAIN_BOUND:?}"));
        assert!(status.success(), "exited {status:?} on SIGTERM, not 0");

        assert_eq!(read_closed_reason(&mut stream), "closed");
        assert!(
            kill(child, None).is_err(),
            "the session's child outlived the drained endpoint"
        );
        poll_until(
            "the target to hear its registration close",
            Duration::from_secs(10),
            || {
                target_proc
                    .stderr_snapshot()
                    .iter()
                    .any(|l| l.contains("\"event\":\"lost\"") && l.contains("peer_closed"))
                    .then_some(())
            },
        );
        assert!(
            serve_record(&host).is_none(),
            "a clean exit removes serve.json"
        );

        let lines = listen.stderr_lines();
        let drained: Vec<&String> = lines
            .iter()
            .filter(|l| l.starts_with("{\"lifecycle\":\"drained\""))
            .collect();
        assert_eq!(drained.len(), 1, "one drained line: {lines:?}");
        assert!(
            drained[0].contains("\"sessions_closed\":1"),
            "{}",
            drained[0]
        );
        assert!(
            lines.iter().any(|l| l == "qsh listen: shutting down"),
            "{lines:?}"
        );
        stream.close();
        target_proc.shut_down();
    });
}

/// A client and a remote account whose combined endpoint is already running.
struct Remote {
    client: Sandbox,
    remote: Sandbox,
    fake: FakeSsh,
    listen: ListenGuard,
}

impl Remote {
    fn new() -> Self {
        let client = Sandbox::initialized();
        let remote = Sandbox::initialized();
        std::fs::write(remote.config_dir().join("config.toml"), COMBINED).unwrap();
        let mut fake = FakeSsh::new();
        fake.run_local_responder(Path::new(QSH), remote.config_dir(), remote.state_dir());
        std::fs::write(
            client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
        )
        .unwrap();
        let listen = ListenGuard::start_with(&remote, "127.0.0.1:0");
        Self {
            client,
            remote,
            fake,
            listen,
        }
    }
}

/// ADR-0059 DoD 27.8: a combined endpoint publishes `serve.json` as a
/// persistent serve, and an SSH bootstrap to its account finds it, starts no
/// on-demand serve beside it and connects to its address. The copy that is
/// the first connection goes through the combined endpoint.
#[test]
fn combined_endpoint_writes_serve_json_and_bootstrap_uses_it() {
    let r = Remote::new();
    let before = serve_record(&r.remote).expect("the combined endpoint publishes serve.json");
    assert_eq!(before["mode"], "persistent", "{before}");
    assert_eq!(before["pid"].as_u64(), Some(u64::from(r.listen.pid())));
    assert_eq!(before["addr"], r.listen.addr(), "{before}");

    // `qsh cp` of one small file to `box:`: the unknown name sets itself up
    // over ssh first (ADR-0044 decision 2), which is the "first connection".
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    std::fs::write(&src, b"first connection\n").unwrap();
    let out = r.client.qsh(&[
        "cp",
        &src.display().to_string(),
        &format!("box:{}", dst.display()),
    ]);
    assert_eq!(
        exit_code(&out),
        0,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&dst).unwrap(), b"first connection\n");

    let after = serve_record(&r.remote).expect("serve.json is still there");
    assert_eq!(
        after, before,
        "no on-demand serve was started and replaced the combined endpoint's record"
    );
    let store = qsh_core::TrustStore::load(&r.client.config_dir().join("trust.toml")).unwrap();
    let pin = store.find("box").expect("the client pinned box");
    assert_eq!(
        pin.address,
        r.listen.addr(),
        "the pin holds the combined endpoint's address"
    );
    assert_eq!(pin.source.as_deref(), Some("ssh_bootstrap"));
    assert!(!r.fake.calls().is_empty());

    // A clean stop takes the record with it.
    let Remote {
        mut listen, remote, ..
    } = r;
    listen.terminate();
    listen.wait_timeout(DRAIN_BOUND).expect("exits");
    assert!(serve_record(&remote).is_none());
}
