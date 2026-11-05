//! The bootstrap starts the remote serve and revives it (ADR-0051 decisions
//! 1, 2 and 4, `docs/design/protocol.md` §17.2/§17.3).
//!
//! The remote account is a second sandbox whose `pair ssh-respond` is run by
//! `qsh_testkit::fake_ssh::FakeSsh` (a real qsh responder, a fake `ssh`). Its
//! `qsh serve --on-demand` is a real detached process, so nothing is started
//! before the first connection and the idle limit
//! (`serve.on_demand_idle_ms`, a second or two here) really ends it.

use std::path::Path;
use std::time::Duration;

use qsh_proto::ssh_bootstrap::{BootstrapLine, BootstrapResult, Hello, HelloStatus, ResultStatus};
use qsh_testkit::fake_ssh::FakeSsh;
use serde_json::Value;

use crate::common::{Sandbox, exec_true_args, exit_code, poll_until, steady_bind};

const QSH: &str = env!("CARGO_BIN_EXE_qsh");

/// How long the on-demand serve may sit idle before it drains.
const IDLE_MS: u64 = 1500;

/// A client and a remote account with nothing running on the remote.
struct Cold {
    client: Sandbox,
    remote: Sandbox,
    fake: FakeSsh,
}

impl Cold {
    fn new() -> Self {
        let client = Sandbox::initialized();
        let remote = Sandbox::initialized();
        let mut cold = Self {
            client,
            remote,
            fake: FakeSsh::new(),
        };
        cold.set_remote_bind(&steady_bind());
        cold.fake.run_local_responder(
            Path::new(QSH),
            cold.remote.config_dir(),
            cold.remote.state_dir(),
        );
        cold.write_client_config("");
        cold
    }

    /// The remote's `[serve].bind`, and the short idle limit.
    fn set_remote_bind(&self, bind: &str) {
        std::fs::write(
            self.remote.config_dir().join("config.toml"),
            format!("[serve]\nbind = \"{bind}\"\non_demand_idle_ms = {IDLE_MS}\n"),
        )
        .unwrap();
    }

    fn write_client_config(&self, ssh_extra: &str) {
        std::fs::write(
            self.client.config_dir().join("config.toml"),
            format!(
                "[ssh]\nprogram = '{}'\n{ssh_extra}",
                self.fake.program().display()
            ),
        )
        .unwrap();
    }

    /// The remote's `serve.json`: a serve removes it when it drains, so its
    /// presence is the serve running.
    fn serve_record(&self) -> Option<Value> {
        let text = std::fs::read(self.remote.state_dir().join("serve.json")).ok()?;
        serde_json::from_slice(&text).ok()
    }

    fn wait_for_serve(&self) -> Value {
        poll_until("the remote serve record", Duration::from_secs(20), || {
            self.serve_record()
        })
    }

    fn wait_for_serve_to_idle_out(&self) {
        poll_until(
            "the on-demand serve to drain",
            Duration::from_secs(30),
            || self.serve_record().is_none().then_some(()),
        );
    }

    fn pin(&self) -> qsh_proto::TrustPeer {
        let store =
            qsh_core::TrustStore::load(&self.client.config_dir().join("trust.toml")).unwrap();
        store.find("box").expect("the client pinned box").clone()
    }

    /// `qsh exec box -- true --json` in the client.
    fn exec_true(&self) -> (std::process::Output, Value) {
        let args = exec_true_args("box");
        let out = self.client.qsh(&args);
        let json = crate::common::sole_envelope(&out.stdout, &args);
        (out, json)
    }
}

impl Drop for Cold {
    fn drop(&mut self) {
        // The serve would drain by itself; do not leave it for the next test.
        #[cfg(unix)]
        if let Some(pid) = self
            .serve_record()
            .and_then(|record| record["pid"].as_u64())
        {
            crate::common::send_stop(pid as u32);
        }
    }
}

/// `qsh cp` of one small file to `box:`: the unknown name sets itself up over
/// ssh first (ADR-0044 decision 2), which is the "first connection".
fn first_connection(cold: &Cold) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    std::fs::write(&src, b"first connection\n").unwrap();
    let out = cold.client.qsh(&[
        "cp",
        &src.display().to_string(),
        &format!("box:{}", dst.display()),
    ]);
    if exit_code(&out) == 0 {
        assert_eq!(std::fs::read(&dst).unwrap(), b"first connection\n");
    }
    out
}

/// Nothing is running on the remote: the first `qsh cp box:...` pins both
/// sides, starts an on-demand serve there, and the copy goes through it. The
/// pin holds the address the responder reported and is marked as made by the
/// bootstrap.
#[test]
fn first_connection_starts_an_on_demand_serve_and_connects() {
    let cold = Cold::new();
    assert!(cold.serve_record().is_none());

    let out = first_connection(&cold);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(exit_code(&out), 0, "{stderr}");

    let record = cold.wait_for_serve();
    assert_eq!(record["mode"], "on_demand", "{record}");
    let pin = cold.pin();
    assert_eq!(pin.address, record["addr"].as_str().unwrap());
    assert_eq!(pin.source.as_deref(), Some("ssh_bootstrap"));
    assert_eq!(cold.fake.calls().len(), 2, "{:?}", cold.fake.calls());
    assert!(
        !stderr.contains("ends with the ssh session"),
        "an ordinary account gets no scoped-serve warning: {stderr}"
    );

    // `trust list` shows where the pin came from; `source` is additive.
    let (code, list) = cold.client.json(&["trust", "list", "--json"]);
    assert_eq!(code, 0, "{list}");
    assert_eq!(
        list["data"]["peers"][0]["source"], "ssh_bootstrap",
        "{list}"
    );
}

/// Once the on-demand serve has drained, the next command to the name fails
/// to connect, restarts the serve over ssh without a question, and runs. The
/// run is `--json`, so ssh is in `BatchMode`, and stdout stays one envelope.
#[test]
fn a_command_revives_the_serve_after_it_idled_out() {
    let cold = Cold::new();
    let out = first_connection(&cold);
    assert_eq!(
        exit_code(&out),
        0,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let first = cold.wait_for_serve();
    cold.wait_for_serve_to_idle_out();
    let calls_before = cold.fake.calls().len();

    let (out, json) = cold.exec_true();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(exit_code(&out), 0, "{json}\n{stderr}");
    assert_eq!(json["ok"], true, "{json}");
    assert!(stderr.contains("starting its serve over ssh"), "{stderr}");

    let calls = cold.fake.calls();
    assert_eq!(
        calls.len(),
        calls_before + 2,
        "ssh -G and the responder: {calls:?}"
    );
    assert!(
        calls
            .last()
            .unwrap()
            .windows(2)
            .any(|w| w == ["-o", "BatchMode=yes"]),
        "{calls:?}"
    );
    let second = cold.wait_for_serve();
    assert_ne!(second["pid"], first["pid"], "a new serve process");
    assert_eq!(cold.pin().address, second["addr"].as_str().unwrap());
}

/// The revival is verify-only: the pin keeps its fingerprint and role, and the
/// remote's pin of this machine is not written twice.
#[test]
fn revival_does_not_re_pair() {
    let cold = Cold::new();
    let out = first_connection(&cold);
    assert_eq!(
        exit_code(&out),
        0,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    cold.wait_for_serve();
    cold.wait_for_serve_to_idle_out();
    let before = cold.pin();
    let remote_trust = std::fs::read(cold.remote.config_dir().join("trust.toml")).unwrap();

    let (out, json) = cold.exec_true();
    assert_eq!(exit_code(&out), 0, "{json}");
    assert_eq!(cold.pin(), before);
    assert_eq!(
        std::fs::read(cold.remote.config_dir().join("trust.toml")).unwrap(),
        remote_trust
    );
}

/// The serve comes back on a different port: the pin address follows it.
#[test]
fn a_changed_port_updates_the_pin() {
    let cold = Cold::new();
    let out = first_connection(&cold);
    assert_eq!(
        exit_code(&out),
        0,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let first = cold.wait_for_serve();
    cold.wait_for_serve_to_idle_out();

    let moved = steady_bind();
    assert_ne!(moved, first["addr"].as_str().unwrap());
    cold.set_remote_bind(&moved);

    let (out, json) = cold.exec_true();
    assert_eq!(
        exit_code(&out),
        0,
        "{json}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(cold.pin().address, moved);
}

/// `--no-ssh` and `[ssh].bootstrap = "off"` leave the dead serve dead: the
/// command ends with the connection error it had and ssh never runs.
#[test]
fn no_ssh_and_bootstrap_off_disable_the_revival() {
    let cold = Cold::new();
    let out = first_connection(&cold);
    assert_eq!(
        exit_code(&out),
        0,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    cold.wait_for_serve();
    cold.wait_for_serve_to_idle_out();
    let calls_before = cold.fake.calls().len();

    let mut args = exec_true_args("box");
    args.insert(1, "--no-ssh");
    let out = cold.client.qsh(&args);
    assert_eq!(
        exit_code(&out),
        255,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = crate::common::sole_envelope(&out.stdout, &args);
    assert_eq!(json["error"]["code"], "CONNECTION_FAILED", "{json}");
    assert_eq!(cold.fake.calls().len(), calls_before, "ssh must not run");
    assert!(cold.serve_record().is_none());

    cold.write_client_config("bootstrap = \"off\"\n");
    let args = exec_true_args("box");
    let out = cold.client.qsh(&args);
    assert_eq!(
        exit_code(&out),
        255,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(cold.fake.calls().len(), calls_before, "ssh must not run");

    // Without either, the same command revives it.
    cold.write_client_config("");
    let (out, json) = cold.exec_true();
    assert_eq!(exit_code(&out), 0, "{json}");
}

/// A pin that did not come from the bootstrap (`trust add`) is never revived,
/// even when the connection to it fails.
#[test]
fn a_pin_made_by_hand_is_not_revived() {
    let cold = Cold::new();
    let free = steady_bind();
    cold.client
        .trust_add("box", Some(&free), &cold.remote.fingerprint());
    let args = exec_true_args("box");
    let out = cold.client.qsh(&args);
    assert_eq!(
        exit_code(&out),
        255,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(cold.fake.calls().is_empty(), "{:?}", cold.fake.calls());
}

/// A responder from before ADR-0051 says nothing about `on_demand`, so it is
/// sent no `ensure_serve`, starts nothing and the client reports what it
/// always reported: no serve is listening (`verified: false`).
#[test]
fn an_old_responder_gets_the_commit_it_always_got() {
    let mut cold = Cold::new();
    cold.fake.respond_as_old_qsh();

    let (code, got) = cold
        .client
        .json(&["pair", "ssh", "box", "--remote-as", "laptop", "--json"]);
    assert_eq!(code, 0, "{got}");
    assert_eq!(got["data"]["verified"], false, "{got}");
    assert_eq!(
        got["data"]["verify_error"]["details"]["reason"], "remote_serve_not_listening",
        "{got}"
    );
    assert!(cold.serve_record().is_none(), "nothing was started");
    // The address is the one the hello implies: the ssh host and the
    // configured port.
    let configured = std::fs::read_to_string(cold.remote.config_dir().join("config.toml")).unwrap();
    let port = configured
        .split("127.0.0.1:")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap();
    assert_eq!(got["data"]["peer"]["address"], format!("127.0.0.1:{port}"));
}

/// A responder that reports a session-scoped serve gets the one stderr
/// warning of decision 2, and the command still goes on.
#[test]
fn a_session_scoped_serve_prints_the_warning_once_and_still_connects() {
    let mut fake = FakeSsh::new();
    let remote_fp = crate::ssh_bootstrap::pair::other_fingerprint(7);
    let bound = steady_bind();
    let mut script = BootstrapLine::Hello(Hello {
        versions: vec![1],
        qsh_version: "9.9.9".into(),
        status: HelloStatus::Ready,
        fingerprint: Some(remote_fp),
        serve_bind: Some("[::]:4433".into()),
        serve_listening: Some(false),
        on_demand: Some(true),
    })
    .encode_line()
    .unwrap()
    .into_bytes();
    script.extend(
        BootstrapLine::Result(BootstrapResult {
            status: ResultStatus::Pinned,
            name: "laptop".into(),
            role: Some("full".into()),
            created: true,
            code: None,
            message: None,
            serve_bind: Some(bound.clone()),
            serve_started: Some(true),
            serve_session_scoped: Some(true),
        })
        .encode_line()
        .unwrap()
        .into_bytes(),
    );
    fake.script(&script).record_stdin();
    let client = Sandbox::initialized();
    std::fs::write(
        client.config_dir().join("config.toml"),
        format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
    )
    .unwrap();

    let out = client.qsh(&["pair", "ssh", "box"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Nothing answers at `bound`, so the confirming dial reports that, and
    // the pins stand: exit 0.
    assert_eq!(exit_code(&out), 0, "{stderr}");
    assert_eq!(
        stderr.matches("ends with the ssh session").count(),
        1,
        "{stderr}"
    );
    assert!(
        stderr.contains("qsh service install --always-on"),
        "{stderr}"
    );
    let store = qsh_core::TrustStore::load(&client.config_dir().join("trust.toml")).unwrap();
    assert_eq!(store.find("box").unwrap().address, bound);
}

/// The other dialing commands revive too: `qsh cp` and the root form with a
/// command (the latter keeps the `user@` it was given for ssh).
#[test]
fn cp_and_the_root_form_revive_the_serve_as_well() {
    let cold = Cold::new();
    let out = first_connection(&cold);
    assert_eq!(
        exit_code(&out),
        0,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    cold.wait_for_serve();
    cold.wait_for_serve_to_idle_out();

    let out = first_connection(&cold);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(exit_code(&out), 0, "{stderr}");
    assert!(stderr.contains("starting its serve over ssh"), "{stderr}");
    assert!(
        !stderr.contains("setting one up"),
        "the pin exists: {stderr}"
    );
    cold.wait_for_serve();
    cold.wait_for_serve_to_idle_out();

    #[cfg(unix)]
    {
        let out = cold.client.qsh(&["fake@box", "true"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 0, "{stderr}");
        assert!(
            stderr.contains("starting its serve over ssh (ssh fake@box)"),
            "{stderr}"
        );
    }
}
