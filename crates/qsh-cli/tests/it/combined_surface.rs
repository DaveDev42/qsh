//! **L5 real-process** — the user surface of the combined endpoint (ADR-0059
//! decision 20): the `[listen].serve` key, the `--serve` flag, and the two
//! together. The runtime halves (what the combined endpoint does) are in
//! `combined_lifecycle.rs` and `qsh-testkit`.

use crate::common;

use std::time::Duration;

use common::{ListenGuard, Sandbox, poll_until};
use serde_json::Value;

const SERVE_LINE: &str = "qsh serve: listening on ";
/// The last line `qsh listen` prints before a combined endpoint's own.
const LAST_LISTEN_LINE: &str = "qsh listen: ";

fn serve_record(sandbox: &Sandbox) -> Option<Value> {
    let text = std::fs::read(sandbox.state_dir().join("serve.json")).ok()?;
    serde_json::from_slice(&text).ok()
}

/// The four cells of `[listen].serve` (off/on) by `--serve` (absent/given).
/// A cell is the combined endpoint when either is on: it prints serve's
/// `listening on` line after listen's and writes `serve.json` for its own
/// pid. Both off is the plain `qsh listen`, which prints no serve line and
/// writes no record.
#[test]
fn listen_serve_flag_and_config_key() {
    for (key, flag, combined) in [
        (false, false, false),
        (false, true, true),
        (true, false, true),
        (true, true, true),
    ] {
        let sandbox = Sandbox::initialized();
        if key {
            std::fs::write(
                sandbox.config_dir().join("config.toml"),
                "[listen]\nserve = true\n",
            )
            .unwrap();
        }
        let extra: &[&str] = if flag { &["--serve"] } else { &[] };
        let listen = ListenGuard::start_with_args(&sandbox, "127.0.0.1:0", extra);
        let case = format!("key={key} flag={flag}");

        if combined {
            let lines = poll_until(
                &format!("serve's line ({case})"),
                Duration::from_secs(20),
                || {
                    let lines = listen.stderr_lines();
                    lines
                        .iter()
                        .any(|l| l.starts_with(SERVE_LINE))
                        .then_some(lines)
                },
            );
            let at = |prefix: &str| lines.iter().position(|l| l.starts_with(prefix)).unwrap();
            assert!(
                at("qsh listen: listening on ") < at(SERVE_LINE),
                "{case}: {lines:?}"
            );
            let record = poll_until(
                &format!("serve.json ({case})"),
                Duration::from_secs(20),
                || serve_record(&sandbox),
            );
            assert_eq!(
                record["pid"].as_u64(),
                Some(u64::from(listen.pid())),
                "{case}"
            );
            assert_eq!(record["mode"], "persistent", "{case}");
            assert_eq!(record["addr"], listen.addr(), "{case}");
        } else {
            // listen's own lines are all out once the controller reminder is
            // there; serve's would follow it at once.
            poll_until(
                &format!("listen's lines ({case})"),
                Duration::from_secs(20),
                || {
                    listen
                        .stderr_lines()
                        .iter()
                        .any(|l| {
                            l.starts_with(LAST_LISTEN_LINE) && l.contains("must be able to reach")
                        })
                        .then_some(())
                },
            );
            std::thread::sleep(Duration::from_millis(300));
            let lines = listen.stderr_lines();
            assert!(
                lines.iter().all(|l| !l.starts_with("qsh serve: ")),
                "{case}: a plain listen printed a serve line: {lines:?}"
            );
            assert!(
                serve_record(&sandbox).is_none(),
                "{case}: plain listen wrote serve.json"
            );
        }
        listen.shut_down();
    }
}

/// `qsh config` knows the key: a bool that applies from the next start, and a
/// value that is not a bool is refused before anything is written.
#[test]
fn listen_serve_is_a_startup_bool_config_key() {
    let sandbox = Sandbox::initialized();

    let (code, set) = sandbox.json(&["config", "set", "listen.serve", "true", "--json"]);
    assert_eq!(code, 0, "{set}");
    assert_eq!(set["data"]["applies_from"], "next_start", "{set}");
    let (code, got) = sandbox.json(&["config", "get", "listen.serve", "--json"]);
    assert_eq!(code, 0, "{got}");
    assert_eq!(got["data"]["value"], true, "{got}");
    let (code, listed) = sandbox.json(&["config", "list", "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert!(listed.to_string().contains("listen.serve"), "{listed}");

    let (code, bad) = sandbox.json(&["config", "set", "listen.serve", "maybe", "--json"]);
    assert_ne!(code, 0, "{bad}");
    assert_eq!(bad["error"]["code"], "INVALID_ARGUMENT", "{bad}");
    let (_, again) = sandbox.json(&["config", "get", "listen.serve", "--json"]);
    assert_eq!(again["data"]["value"], true, "{again}");
}

/// The install text says that a combined `listen` unit also hosts sessions
/// (ADR-0059 decision 21), and only then; machine output is unchanged.
#[test]
fn service_install_notes_that_a_combined_listen_hosts_sessions() {
    const NOTE: &str = "also hosts sessions";
    for (config, noted) in [
        ("[listen]\nserve = true\n", true),
        ("[listen]\nallow_advertised_names = true\n", false),
        ("", false),
    ] {
        let sandbox = Sandbox::new();
        if !config.is_empty() {
            std::fs::create_dir_all(sandbox.config_dir()).unwrap();
            std::fs::write(sandbox.config_dir().join("config.toml"), config).unwrap();
        }
        let output = sandbox.qsh(&["service", "install", "--no-activate"]);
        assert_eq!(common::exit_code(&output), 0, "{config:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.contains(NOTE), noted, "{config:?}: {stdout}");

        let (code, json) = sandbox.json(&["service", "install", "--no-activate", "--json"]);
        assert_eq!(code, 0, "{json}");
        assert!(!json.to_string().contains(NOTE), "{json}");
    }
}
