//! The automatic bootstrap (ADR-0044 decisions 2, 3, 13, 16): `qsh
//! [user@]host` and `qsh cp` set a pin up over ssh themselves when the name
//! resolves nowhere, then carry on with the original command.
//!
//! The ssh side is `qsh_testkit::fake_ssh::FakeSsh`, which records every call
//! runs the real `qsh pair ssh-respond` against a second sandbox (`world`),
//! on every platform. The cases that need no responder (`bare`) run on every
//! platform too. On Windows `console` drives the interactive form in a
//! ConPTY, up to the end of the bootstrap with no responder and through the
//! original command with the Windows responder. The interactive form under a
//! unix pty is `tui_expect.rs`
//! (`auto_bootstrap_then_interactive_attach_enters_raw_mode_only_after_ssh_exits`).
//! The pure decision (which names start it) is unit-tested in `qsh-core`
//! (`ops::auto_bootstrap::tests`).

use std::path::PathBuf;

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

fn run_cp(client: &Sandbox, payload: &Payload, host: &str, extra: &[&str]) -> std::process::Output {
    let mut args = payload.args(host);
    for flag in extra.iter().rev() {
        args.insert(1, (*flag).to_string());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    client.qsh(&refs)
}

mod world {
    use super::*;
    use crate::common::{ReverseGuard, exit_code, hosts_array, poll_until};
    use crate::ssh_bootstrap::pair::{World, other_fingerprint, store};

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
    ///
    /// Unix only: the interrupt is `SIGINT` sent to a child process. Windows
    /// has no signal to send to another process, so its meaning is the byte
    /// `0x03` typed into a ConPTY, which `console::
    /// ctrl_c_during_the_bootstrap_ends_canceled_on_windows` does with the
    /// same assertions.
    #[cfg(unix)]
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
}

/// The cases that need no responder on the other end of ssh: the fake `ssh`
/// reports nothing, or fails, and the client alone is under test.
mod bare {
    use super::*;
    use crate::common::exit_code;
    use qsh_testkit::fake_ssh::FakeSsh;

    /// Whether `client` holds a pin named `box`. No `trust.toml` is none.
    pub(super) fn pinned_box(client: &Sandbox) -> bool {
        let path = client.config_dir().join("trust.toml");
        path.exists()
            && qsh_core::TrustStore::load(&path)
                .unwrap()
                .find("box")
                .is_some()
    }

    /// A client whose `[ssh].program` is a fake ssh that answers `-G` and
    /// then prints nothing.
    pub(super) struct Bare {
        pub client: Sandbox,
        pub fake: FakeSsh,
    }

    impl Bare {
        pub(super) fn new() -> Self {
            Self::with(FakeSsh::new())
        }

        pub(super) fn with(fake: FakeSsh) -> Self {
            let client = Sandbox::initialized();
            std::fs::write(
                client.config_dir().join("config.toml"),
                format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
            )
            .unwrap();
            Self { client, fake }
        }
    }

    /// A failing ssh stops the command before it connects, and writes
    /// nothing.
    #[test]
    fn auto_bootstrap_stops_the_original_command_when_ssh_fails() {
        // A fake that answers `-G` and then dies like an ssh that failed to
        // authenticate (exit 255, no hello).
        let mut failing = FakeSsh::new();
        failing.exit(255);
        let w = Bare::with(failing);
        let payload = Payload::new();

        let out = run_cp(&w.client, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{stderr}");
        assert!(stderr.contains(NOTICE), "{stderr}");
        assert!(stderr.contains("CONNECTION_FAILED"), "{stderr}");
        assert!(!payload.dst.exists());
        assert!(!pinned_box(&w.client));
        assert_eq!(w.fake.calls().len(), 2, "{:?}", w.fake.calls());
    }

    /// The person learns ssh is about to run before ssh does anything: the
    /// notice precedes the first thing the fake writes, which it does on the
    /// `-G` call (decision 2). A fake that reports nothing ends the call
    /// without a pin.
    #[test]
    fn auto_bootstrap_prints_the_notice_before_ssh_runs_without_a_responder() {
        let mut w = Bare::new();
        w.fake.g_stderr("FAKE-SSH-FIRST-CALL");
        let payload = Payload::new();

        let out = run_cp(&w.client, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{stderr}");
        let notice = stderr.find(NOTICE).unwrap_or_else(|| panic!("{stderr}"));
        let ssh = stderr
            .find("FAKE-SSH-FIRST-CALL")
            .unwrap_or_else(|| panic!("{stderr}"));
        assert!(notice < ssh, "the notice must come first:\n{stderr}");
        assert_eq!(stderr.matches("setting one up over ssh").count(), 1);
        assert!(!payload.dst.exists());
        assert!(!pinned_box(&w.client));
    }

    /// A `user@` on the operand rides along to ssh.
    #[test]
    fn auto_bootstrap_hands_the_typed_user_hint_to_ssh_without_a_responder() {
        let w = Bare::new();
        let payload = Payload::new();
        let out = run_cp(&w.client, &payload, "dave@box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("(ssh dave@box)"), "{stderr}");
        let calls = w.fake.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(
            calls[0].ends_with(&["--".into(), "dave@box".into()]),
            "{calls:?}"
        );
        assert!(calls[1].iter().any(|arg| arg == "dave@box"), "{calls:?}");
        assert!(!payload.dst.exists());
    }

    /// Machine mode never starts ssh: `qsh cp --json` on an unregistered name
    /// is the same `HOST_NOT_FOUND` as before and the fake records nothing
    /// (decision 2).
    #[test]
    fn ssh_bootstrap_is_never_implicit_in_machine_mode() {
        let w = Bare::new();
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
        assert!(!pinned_box(&w.client));
    }

    /// `[ssh].bootstrap = "off"` turns the automatic path off (decision 2).
    #[test]
    fn ssh_bootstrap_off_in_config_runs_no_ssh_without_a_responder() {
        let w = Bare::new();
        std::fs::write(
            w.client.config_dir().join("config.toml"),
            format!(
                "[ssh]\nprogram = '{}'\nbootstrap = \"off\"\n",
                w.fake.program().display()
            ),
        )
        .unwrap();
        let payload = Payload::new();

        let out = run_cp(&w.client, &payload, "box", &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{stderr}");
        assert!(stderr.contains("HOST_NOT_FOUND"), "{stderr}");
        assert!(stderr.contains("`qsh pair ssh box`"), "{stderr}");
        assert!(!stderr.contains("setting one up"), "{stderr}");
        assert_eq!(w.fake.calls().len(), 0);
    }

    /// `qsh exec`, `qsh session open`, `qsh tunnel open` and `qsh sessions`
    /// are machine-oriented surfaces, not the place of ssh: they keep
    /// reporting `HOST_NOT_FOUND`, in human mode too (decision 2).
    #[test]
    fn ssh_bootstrap_is_not_triggered_for_exec_session_tunnel_or_sessions() {
        let w = Bare::new();
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
        assert!(!pinned_box(&w.client));
    }
}

/// The interactive form on Windows: the real `qsh` in a ConPTY, ssh being the
/// fake `ssh.exe` (ADR-0044 decision 16, ADR-0035 decision 1). The cases with
/// no responder end at the bootstrap; the ones with the Windows responder
/// carry on into the original command, a `qsh cp` and an attach to the
/// host's own ConPTY session.
#[cfg(windows)]
mod console {
    use super::bare::{Bare, pinned_box};
    use super::*;
    use crate::ssh_bootstrap::pair::{World, store};
    use crate::windows_attach::spawn_qsh;

    const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
    const ENABLE_LINE_INPUT: u32 = 0x0002;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;

    /// While ssh runs the console is the cooked one it needs: the fake, held
    /// at its "prompt" like an ssh waiting for a password, reads the console's
    /// input mode and finds the line editor, echo and the system's Ctrl-C
    /// handling on and VT input off. The client has not taken the console raw
    /// (ADR-0044 decision 16); it does only after ssh has exited.
    #[test]
    fn auto_bootstrap_keeps_the_console_cooked_until_ssh_exits_on_windows() {
        let mut w = Bare::new();
        let gate_dir = tempfile::tempdir().expect("gate dir");
        let gate = gate_dir.path().join("release-ssh");
        w.fake.record_console_mode().gate_file(&gate);

        let mut qsh = spawn_qsh(&w.client, &["box"]);
        qsh.wait_text("setting one up over ssh (ssh box)");
        let mode = crate::common::poll_until(
            "ssh to read its console's mode",
            std::time::Duration::from_secs(30),
            || w.fake.console_mode(),
        )
        .expect("ssh has a console under a ConPTY");
        let cooked = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
        assert_eq!(
            mode & cooked,
            cooked,
            "console mode {mode:#x} is not cooked"
        );
        assert_eq!(
            mode & ENABLE_VIRTUAL_TERMINAL_INPUT,
            0,
            "console mode {mode:#x} is in VT input mode"
        );
        assert!(!pinned_box(&w.client));

        // ssh ends without an answer; the bootstrap ends the command.
        std::fs::write(&gate, b"").expect("release ssh");
        qsh.wait_text("(REMOTE_ERROR)");
        assert_eq!(qsh.wait_exit(), 255);
        assert!(!pinned_box(&w.client));
        assert_eq!(w.fake.calls().len(), 2, "{:?}", w.fake.calls());
    }

    /// Ctrl-C at the console while ssh sits at its prompt ends the call with
    /// `CANCELED`, ends ssh, writes no pin and never starts the command.
    #[test]
    fn ctrl_c_during_the_bootstrap_ends_canceled_on_windows() {
        let mut w = Bare::new();
        // The responder call stays at its "prompt" until it is ended.
        w.fake.hang();
        let payload = Payload::new();
        let args = payload.args("box");
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();

        let mut qsh = spawn_qsh(&w.client, &refs);
        qsh.wait_text("setting one up over ssh (ssh box)");
        crate::common::poll_until(
            "the responder ssh call to start",
            std::time::Duration::from_secs(30),
            || (w.fake.calls().len() == 2).then_some(()),
        );
        let pid = w
            .fake
            .wait_for_pid(std::time::Duration::from_secs(30))
            .expect("the fake started");
        qsh.send(b"\x03");
        qsh.wait_text("CANCELED");
        assert_eq!(qsh.wait_exit(), 255);
        assert!(!payload.dst.exists(), "the original command ran");
        assert!(!pinned_box(&w.client));
        assert_eq!(w.fake.calls().len(), 2, "{:?}", w.fake.calls());
        crate::common::poll_until(
            "the interrupted ssh to be gone",
            std::time::Duration::from_secs(10),
            || crate::ssh_bootstrap::process_is_gone(pid).then_some(()),
        );
    }

    /// With the Windows responder behind ssh, the bootstrap pins both sides
    /// from a console and the original `qsh cp` then runs as typed
    /// (decision 2). The console is cooked while ssh runs, so the same
    /// console reads the client's output afterwards.
    #[test]
    fn auto_bootstrap_then_cp_completes_in_a_console_on_windows() {
        let w = World::new();
        let payload = Payload::new();
        let args = payload.args("box");
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();

        let mut qsh = spawn_qsh(&w.client, &refs);
        qsh.wait_text("setting one up over ssh (ssh box)");
        assert_eq!(qsh.wait_exit(), 0, "{}", qsh.text());
        assert_eq!(
            std::fs::read(&payload.dst).unwrap(),
            std::fs::read(&payload.src).unwrap()
        );
        let pinned = store(&w.client);
        let peer = pinned.find("box").expect("this machine pinned box");
        assert_eq!(peer.address, w.serve.addr());
        assert_eq!(w.fake.calls().len(), 2, "{:?}", w.fake.calls());
    }

    /// The bare `qsh box` form: the bootstrap pins both sides, then the
    /// client attaches to a ConPTY session of the host and a command typed
    /// into it runs there. The proof is a file the host's shell writes, not
    /// the text the test console renders, which a pseudo-console repaints.
    /// The line is typed again until the file exists: keystrokes sent before
    /// the attach has the writer lease are dropped, and writing the same
    /// file twice is harmless.
    #[test]
    fn auto_bootstrap_then_interactive_attach_reaches_the_host_shell_on_windows() {
        let w = World::new();
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("attached.txt");
        let mut qsh = spawn_qsh(&w.client, &["box"]);
        qsh.wait_text("setting one up over ssh (ssh box)");
        // The host's shell prints its banner once the attach is up.
        qsh.wait_text("Microsoft Windows");
        let line = format!("echo attached> \"{}\"\r", marker.display());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !marker.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the host shell never ran the typed line; console: {:?}",
                qsh.text()
            );
            qsh.send(line.as_bytes());
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
        qsh.send(b"exit\r");
        assert_eq!(qsh.wait_exit(), 0, "{}", qsh.text());
        assert!(store(&w.client).find("box").is_some());
        assert_eq!(w.fake.calls().len(), 2, "{:?}", w.fake.calls());
    }
}
