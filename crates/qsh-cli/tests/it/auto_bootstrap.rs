//! The automatic bootstrap (ADR-0044 decisions 2, 3, 13, 16): `qsh
//! [user@]host` and `qsh cp` set a pin up over ssh themselves when the name
//! resolves nowhere, then carry on with the original command.
//!
//! The ssh side is `qsh_testkit::fake_ssh::FakeSsh`, which records every call
//! and runs the real `qsh pair ssh-respond` against a second sandbox. The
//! interactive form under a pty is `tui_expect.rs`
//! (`auto_bootstrap_then_interactive_attach_enters_raw_mode_only_after_ssh_exits`).
//! The pure decision (which names start it) is unit-tested in `qsh-core`
//! (`ops::auto_bootstrap::tests`).

use crate::common::Sandbox;

/// `HOST_NOT_FOUND` in human mode names the next command, and only there:
/// the envelope's message and details are what the append-only fixtures pin
/// (ADR-0044 decision 2).
#[test]
fn host_not_found_human_message_names_qsh_pair_ssh() {
    let sandbox = Sandbox::initialized();

    for args in [
        &["host", "get", "nowhere-at-all"][..],
        &["exec", "nowhere", "--", "true"][..],
    ] {
        let out = sandbox.qsh(args);
        assert_eq!(crate::common::exit_code(&out), 255, "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        let name = args[args.len() - if args[0] == "exec" { 3 } else { 1 }];
        assert!(
            stderr.contains(&format!("`qsh pair ssh {name}`")),
            "{args:?}: {stderr}"
        );
        assert!(stderr.trim_end().ends_with("(HOST_NOT_FOUND)"), "{stderr}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }

    // The envelope is untouched.
    let (code, got) = sandbox.json(&["host", "get", "nowhere-at-all", "--json"]);
    assert_eq!(code, 255, "{got}");
    let message = got["error"]["message"].as_str().unwrap();
    assert!(!message.contains("pair ssh"), "{message}");
    assert!(got["error"]["details"].is_null(), "{got}");
}

#[cfg(unix)]
mod world {
    use super::*;
    use crate::common::{ReverseGuard, exit_code, hosts_array, poll_until};
    use crate::ssh_bootstrap::pair::{World, other_fingerprint, store};
    use qsh_testkit::fake_ssh::FakeSsh;
    use std::path::PathBuf;

    /// The line `qsh` writes before it starts ssh, for the name `box`.
    const NOTICE: &str = "qsh: no qsh pin for \"box\"; setting one up over ssh (ssh box); \
                          set [ssh].bootstrap = \"off\" to disable";

    /// One local file, and where `qsh cp` should put it on the "remote"
    /// (which shares this machine's filesystem).
    struct Payload {
        _dir: tempfile::TempDir,
        src: PathBuf,
        dst: PathBuf,
    }

    impl Payload {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let src = dir.path().join("src.txt");
            std::fs::write(&src, b"through the automatic bootstrap\n").unwrap();
            let dst = dir.path().join("dst.txt");
            Self {
                _dir: dir,
                src,
                dst,
            }
        }

        fn args(&self, host: &str) -> Vec<String> {
            vec![
                "cp".into(),
                self.src.display().to_string(),
                format!("{host}:{}", self.dst.display()),
            ]
        }
    }

    fn run_cp(
        client: &Sandbox,
        payload: &Payload,
        host: &str,
        extra: &[&str],
    ) -> std::process::Output {
        let mut args = payload.args(host);
        for flag in extra.iter().rev() {
            args.insert(1, (*flag).to_string());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        client.qsh(&refs)
    }

    fn set_client_config(w: &World, extra: &str) {
        std::fs::write(
            w.client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n{extra}", w.fake.program().display()),
        )
        .unwrap();
    }

    /// An unregistered name in a `qsh cp` pins both machines over ssh and
    /// the copy then runs as typed (decision 2). The original connection is
    /// the confirmation, so ssh runs exactly twice (`-G`, then the
    /// responder) and a second copy does not run it again (decision 3).
    #[test]
    fn auto_bootstrap_then_cp_completes_the_original_command() {
        let w = World::new();
        let payload = Payload::new();

        let out = run_cp(&w.client, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 0, "{stderr}");
        assert_eq!(
            std::fs::read(&payload.dst).unwrap(),
            std::fs::read(&payload.src).unwrap()
        );
        assert!(stderr.contains(NOTICE), "{stderr}");
        // The pins the explicit command writes: this machine's has the
        // address ssh -G and the remote's hello gave, role none.
        let pinned = store(&w.client);
        let peer = pinned.find("box").expect("this machine pinned box");
        assert_eq!(peer.address, w.serve.addr());
        assert_eq!(peer.role.as_deref(), Some("none"));
        assert_eq!(w.fake.calls().len(), 2, "{:?}", w.fake.calls());
        // Nothing the machine-readable surface would carry reaches stdout.
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("verified"), "{stdout}");

        // The pin stands, so the next copy is plain QUIC.
        std::fs::remove_file(&payload.dst).unwrap();
        let again = run_cp(&w.client, &payload, "box", &[]);
        assert_eq!(exit_code(&again), 0);
        assert!(!String::from_utf8_lossy(&again.stderr).contains("setting one up"));
        assert_eq!(w.fake.calls().len(), 2, "no ssh once the pin exists");
    }

    /// The person learns ssh is about to run before ssh does anything: the
    /// notice precedes the first thing the fake writes, which it does on the
    /// `-G` call (decision 2).
    #[test]
    fn auto_bootstrap_prints_the_notice_before_ssh_runs() {
        let mut w = World::new();
        w.fake.g_stderr("FAKE-SSH-FIRST-CALL");
        let payload = Payload::new();

        let out = run_cp(&w.client, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 0, "{stderr}");
        let notice = stderr.find(NOTICE).unwrap_or_else(|| panic!("{stderr}"));
        let ssh = stderr
            .find("FAKE-SSH-FIRST-CALL")
            .unwrap_or_else(|| panic!("{stderr}"));
        assert!(notice < ssh, "the notice must come first:\n{stderr}");
        assert_eq!(stderr.matches("setting one up over ssh").count(), 1);
    }

    /// `--quiet` keeps the notice (it is the warning that ssh will run) and
    /// drops the pin lines.
    #[test]
    fn auto_bootstrap_quiet_keeps_the_notice_and_drops_the_pin_lines() {
        let w = World::new();
        let payload = Payload::new();
        let out = run_cp(&w.client, &payload, "box", &["--quiet"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 0, "{stderr}");
        assert!(stderr.contains(NOTICE), "{stderr}");
        assert!(!stderr.contains("pinned"), "{stderr}");
    }

    /// A `user@` on the operand rides along to ssh and is the assertion the
    /// copy keeps making afterwards.
    #[test]
    fn auto_bootstrap_hands_the_typed_user_hint_to_ssh() {
        let w = World::new();
        let payload = Payload::new();
        let out = run_cp(&w.client, &payload, "dave@box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        // The remote runs as whoever runs this test, so the assertion may
        // fail; what matters here is what ssh was given.
        assert!(stderr.contains("(ssh dave@box)"), "{stderr}");
        let calls = w.fake.calls();
        assert!(calls.len() >= 2, "{calls:?}");
        assert!(
            calls[0].ends_with(&["--".into(), "dave@box".into()]),
            "{calls:?}"
        );
        assert!(calls[1].iter().any(|arg| arg == "dave@box"), "{calls:?}");
        assert!(store(&w.client).find("box").is_some());
    }

    /// A remote that reported nothing listening on its serve port: the pins
    /// are written and the original command ends with `CONNECTION_FAILED`
    /// (`remote_serve_not_listening`) without dialing (decision 13).
    #[test]
    fn auto_bootstrap_ends_with_connection_failed_when_the_remote_serve_is_not_listening() {
        let w = World::new();
        let free = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let spec = free.local_addr().unwrap().to_string();
        drop(free);
        std::fs::write(
            w.remote.config_dir().join("config.toml"),
            format!("[serve]\nbind = \"{spec}\"\n"),
        )
        .unwrap();
        let payload = Payload::new();

        let out = run_cp(&w.client, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{stderr}");
        assert!(stderr.contains("CONNECTION_FAILED"), "{stderr}");
        assert!(stderr.contains("no `qsh serve` is listening"), "{stderr}");
        assert!(!payload.dst.exists());
        // The pins stay: `qsh box` works as soon as serve is up.
        assert_eq!(store(&w.client).find("box").unwrap().address, spec);
        assert!(!store(&w.remote).peers().is_empty());
    }

    /// A failing ssh stops the command before it connects, and writes
    /// nothing.
    #[test]
    fn auto_bootstrap_stops_the_original_command_when_ssh_fails() {
        let w = World::new();
        // A fake that answers `-G` and then dies like an ssh that failed to
        // authenticate (exit 255, no hello).
        let mut failing = FakeSsh::new();
        failing.exit(255);
        std::fs::write(
            w.client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n", failing.program().display()),
        )
        .unwrap();
        let payload = Payload::new();

        let out = run_cp(&w.client, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{stderr}");
        assert!(stderr.contains("CONNECTION_FAILED"), "{stderr}");
        assert!(!payload.dst.exists());
        assert!(store(&w.client).find("box").is_none());
        assert_eq!(failing.calls().len(), 2, "{:?}", failing.calls());
        assert_eq!(w.fake.calls().len(), 0);
    }

    /// Machine mode never starts ssh: `qsh cp --json` on an unregistered name
    /// is the same `HOST_NOT_FOUND` as before and the fake records nothing
    /// (decision 2).
    #[test]
    fn ssh_bootstrap_is_never_implicit_in_machine_mode() {
        let w = World::new();
        let payload = Payload::new();

        for flag in ["--json", "--jsonl"] {
            let out = run_cp(&w.client, &payload, "box", &[flag]);
            assert_eq!(exit_code(&out), 255, "{flag}");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            assert_eq!(lines.len(), 1, "{flag}: {stdout}");
            let envelope: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
            assert_eq!(
                envelope["error"]["code"], "HOST_NOT_FOUND",
                "{flag}: {stdout}"
            );
            assert!(envelope["error"]["details"].is_null(), "{stdout}");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(!stderr.contains("setting one up"), "{flag}: {stderr}");
        }
        assert_eq!(w.fake.calls().len(), 0, "machine mode ran ssh");
        assert!(store(&w.client).find("box").is_none());
    }

    /// `[ssh].bootstrap = "off"` turns the automatic path off; the explicit
    /// command still works (decision 2).
    #[test]
    fn ssh_bootstrap_off_in_config_is_respected() {
        let w = World::new();
        set_client_config(&w, "bootstrap = \"off\"\n");
        let payload = Payload::new();

        let out = run_cp(&w.client, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{stderr}");
        assert!(stderr.contains("HOST_NOT_FOUND"), "{stderr}");
        assert!(stderr.contains("`qsh pair ssh box`"), "{stderr}");
        assert!(!stderr.contains("setting one up"), "{stderr}");
        assert_eq!(w.fake.calls().len(), 0);

        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(w.fake.calls().len(), 2, "the explicit command ignores it");
    }

    /// A name qsh already knows something about is qsh's to resolve: a
    /// `hosts.toml` entry, a pin (with or without an address), a reverse
    /// registration (live, or stale after the target went away). None of
    /// them runs ssh (decision 2).
    #[test]
    fn ssh_bootstrap_is_not_triggered_for_hosts_toml_or_reverse_names() {
        use crate::ssh_bootstrap::pair_reverse::World as Reverse;

        let w = World::new();
        let payload = Payload::new();
        std::fs::write(
            w.client.config_dir().join("hosts.toml"),
            format!(
                "[[host]]\nname = \"book\"\naddress = \"{}\"\n",
                w.serve.addr()
            ),
        )
        .unwrap();
        w.client
            .trust_add("pinned", Some(w.serve.addr()), &w.remote.fingerprint());
        w.client.trust_add("inbound", None, &other_fingerprint(7));

        for host in ["book", "pinned", "inbound"] {
            let out = run_cp(&w.client, &payload, host, &[]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_ne!(
                exit_code(&out),
                0,
                "{host}: the remote does not know this client"
            );
            assert!(!stderr.contains("setting one up"), "{host}: {stderr}");
        }
        assert_eq!(w.fake.calls().len(), 0, "ssh ran for a known name");

        // The reverse half, on the reverse fixture: after a `--reverse --to`
        // bootstrap the target's name is pinned without an address. It is
        // known while nothing is registered yet, while the registration is
        // live (the copy goes through the relay), and once it has gone
        // stale; ssh runs for none of the three.
        let r = Reverse::new();
        let (code, got) = r.pair(&[]);
        assert_eq!(code, 0, "{got}");
        let before = r.fake.calls().len();

        let out = run_cp(&r.controller, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "pinned, not registered: {stderr}");
        assert!(stderr.contains("HOST_NOT_FOUND"), "{stderr}");
        assert!(!stderr.contains("setting one up"), "{stderr}");

        let reverse = ReverseGuard::start_serve_to(&r.target, "hub");
        poll_until(
            "the reverse registration to appear reachable",
            std::time::Duration::from_secs(20),
            || {
                hosts_array(&r.controller)
                    .iter()
                    .any(|h| h["name"] == "box" && h["state"] == "reachable")
                    .then_some(())
            },
        );
        let out = run_cp(&r.controller, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 0, "live: {stderr}");
        assert!(!stderr.contains("setting one up"), "{stderr}");

        reverse.shut_down();
        poll_until(
            "the reverse registration to go stale",
            std::time::Duration::from_secs(20),
            || {
                hosts_array(&r.controller)
                    .iter()
                    .any(|h| h["name"] == "box" && h["state"] == "stale")
                    .then_some(())
            },
        );
        std::fs::remove_file(&payload.dst).unwrap();
        let out = run_cp(&r.controller, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "stale: {stderr}");
        assert!(stderr.contains("HOST_NOT_FOUND"), "{stderr}");
        assert!(!stderr.contains("setting one up"), "{stderr}");
        assert!(!payload.dst.exists());
        assert_eq!(r.fake.calls().len(), before, "ssh ran for a reverse name");
    }

    /// Ctrl-C while ssh runs (a password prompt, say) ends the call with
    /// `CANCELED`, ends ssh, writes no pin on either side, and never starts
    /// the original command (`docs/CLI.md` §7, decision 16).
    #[test]
    fn ctrl_c_during_the_bootstrap_ends_canceled_and_does_not_start_the_command() {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        use std::process::Stdio;

        let mut w = World::new();
        // The responder call stays at its "prompt" until a signal ends it.
        w.fake.hang();
        let payload = Payload::new();
        let args = payload.args("box");
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut child = w
            .client
            .command(&refs)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qsh cp");

        // `-G`, then the responder: ssh is now sitting at its prompt.
        poll_until(
            "the responder ssh call to start",
            std::time::Duration::from_secs(30),
            || (w.fake.calls().len() == 2).then_some(()),
        );
        let pid = w
            .fake
            .wait_for_pid(std::time::Duration::from_secs(30))
            .expect("the fake started");
        kill(Pid::from_raw(child.id() as i32), Signal::SIGINT).expect("send SIGINT");

        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while child.try_wait().expect("try_wait").is_none() {
            if std::time::Instant::now() >= until {
                let _ = child.kill();
                panic!("qsh cp did not end within 30 s of the interrupt");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let out = child.wait_with_output().expect("collect output");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{stderr}");
        assert!(stderr.contains("CANCELED"), "{stderr}");
        assert!(out.stdout.is_empty(), "{:?}", out.stdout);
        assert!(!payload.dst.exists(), "the original command ran");
        assert!(store(&w.client).find("box").is_none());
        assert!(
            store(&w.remote).peers().is_empty(),
            "the remote was written"
        );
        assert_eq!(w.fake.calls().len(), 2, "{:?}", w.fake.calls());
        poll_until(
            "the interrupted ssh to be gone",
            std::time::Duration::from_secs(10),
            || crate::ssh_bootstrap::process_is_gone(pid).then_some(()),
        );
    }

    /// `qsh exec`, `qsh session open`, `qsh tunnel open` and `qsh sessions`
    /// are machine-oriented surfaces, not the place of ssh: they keep
    /// reporting `HOST_NOT_FOUND`, in human mode too (decision 2).
    #[test]
    fn ssh_bootstrap_is_not_triggered_for_exec_session_tunnel_or_sessions() {
        let w = World::new();
        let invocations: [&[&str]; 4] = [
            &["exec", "box", "--", "true"],
            &["session", "open", "box", "--", "true"],
            &["tunnel", "open", "box", "-L", "127.0.0.1:8081:127.0.0.1:1"],
            &["sessions", "box"],
        ];
        for args in invocations {
            let out = w.client.qsh(args);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(exit_code(&out), 255, "{args:?}: {stderr}");
            assert!(stderr.contains("HOST_NOT_FOUND"), "{args:?}: {stderr}");
            assert!(!stderr.contains("setting one up"), "{args:?}: {stderr}");
        }
        assert_eq!(
            w.fake.calls().len(),
            0,
            "a machine-oriented surface ran ssh"
        );
        assert!(store(&w.client).find("box").is_none());
    }
}
