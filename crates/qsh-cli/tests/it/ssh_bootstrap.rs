//! The ssh-side machinery of `qsh pair ssh` against a fake `ssh`
//! (ADR-0044; `docs/design/testing.md`).
//!
//! `qsh_testkit::fake_ssh::FakeSsh` stands in for the system `ssh`: it
//! records its argv and prints what the test scripts. There is no sshd, no
//! OpenSSH configuration and no remote qsh. These tests drive
//! `qsh_core::ssh_bootstrap` directly, because no command uses it yet; the
//! `pair.ssh` operation and its CLI surface come with the steps that need
//! them.
//!
//! The remote half is covered here too: the hidden `qsh pair ssh-respond`
//! is started as a real process against a sandbox (the `ssh_respond_*`
//! tests write a `commit` on its stdin), and the fake `ssh` can run it as
//! the remote end of the ssh child (`ssh_bootstrap_local_responder_*`).
//!
//! The same file runs on Windows, where the fake is a copied `ssh.exe` and
//! the recorded argv shows what `ssh.exe` receives after the Windows
//! command-line round trip. The responder tests are Unix-only: the Windows
//! responder is M20 (ADR-0044 decision 10), and until then the Windows
//! build does not know the command.

use std::time::Duration;

use qsh_core::CancelToken;
use qsh_core::ssh_bootstrap::{
    BootstrapTimeouts, Dest, ResponderOptions, SSH_G_OUTPUT_MAX, SshRunner, batch_mode,
};
use qsh_proto::ErrorCode;
use qsh_proto::ssh_bootstrap::{BootstrapLine, Commit, Hello, HelloStatus};
use qsh_testkit::fake_ssh::FakeSsh;

const GENEROUS: Duration = Duration::from_secs(30);

fn runner(fake: &FakeSsh) -> SshRunner {
    SshRunner::new(fake.program())
}

fn dest(raw: &str) -> Dest {
    Dest::parse(raw).unwrap()
}

fn hello_line(status: HelloStatus) -> Vec<u8> {
    BootstrapLine::Hello(Hello {
        versions: vec![1],
        qsh_version: "0.0.0".into(),
        status,
        fingerprint: None,
        serve_bind: None,
        serve_listening: None,
    })
    .encode_line()
    .unwrap()
    .into_bytes()
}

fn commit() -> BootstrapLine {
    BootstrapLine::Commit(Commit {
        version: 1,
        fingerprint: "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".into(),
        name: "laptop".into(),
        role: "full".into(),
        address: None,
    })
}

fn options(batch: bool) -> ResponderOptions {
    ResponderOptions::new(batch, CancelToken::new())
}

/// Spawn the responder call with `BatchMode` and wait for it to fail.
async fn responder_error(fake: &FakeSsh, remote_qsh: &str) -> qsh_core::ops::OpError {
    responder_error_with(fake, remote_qsh, true).await
}

/// Spawn the responder call for `dave@box` and wait for it to fail.
async fn responder_error_with(
    fake: &FakeSsh,
    remote_qsh: &str,
    batch: bool,
) -> qsh_core::ops::OpError {
    let mut child = runner(fake)
        .spawn_responder(&dest("dave@box"), remote_qsh, options(batch))
        .unwrap();
    tokio::time::timeout(GENEROUS, child.recv())
        .await
        .expect("the fake ssh ends")
        .unwrap_err()
}

fn reason(err: &qsh_core::ops::OpError) -> &str {
    err.details["reason"].as_str().unwrap_or("")
}

#[cfg(unix)]
fn process_is_gone(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid as i32), None) == Err(Errno::ESRCH)
}

// ---------------------------------------------------------------------
// argv
// ---------------------------------------------------------------------

#[tokio::test]
async fn ssh_bootstrap_ssh_argv_is_fixed() {
    // (machine mode, stdin is a terminal) -> BatchMode
    for (machine, tty, batch) in [
        (false, true, false),
        (true, true, true),
        (false, false, true),
        (true, false, true),
    ] {
        assert_eq!(batch_mode(machine, tty), batch);
        let fake = FakeSsh::new();
        let _ = responder_error_with(&fake, "qsh", batch_mode(machine, tty)).await;

        let mut expected: Vec<&str> = vec![
            "-T",
            "-a",
            "-x",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "RemoteCommand=none",
            "-o",
            "RequestTTY=no",
            "-o",
            "PermitLocalCommand=no",
        ];
        if batch {
            expected.extend(["-o", "BatchMode=yes"]);
        }
        expected.extend(["--", "dave@box", "qsh", "pair", "ssh-respond"]);
        assert_eq!(fake.calls(), vec![expected], "machine={machine} tty={tty}");
        let flat = fake.calls().concat().join(" ");
        assert!(!flat.contains("StrictHostKeyChecking"), "{flat}");
        assert!(!flat.contains("UserKnownHostsFile"), "{flat}");
    }
}

#[tokio::test]
async fn ssh_bootstrap_rejects_a_dest_that_looks_like_an_option() {
    let fake = FakeSsh::new();
    for bad in [
        "-oProxyCommand=touch /tmp/pwned",
        "-F/etc/passwd",
        "-",
        "ssh://dave@box",
    ] {
        let err = Dest::parse(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad}");
    }
    assert_eq!(fake.calls().len(), 0, "ssh must not run for a refused dest");
}

#[tokio::test]
async fn ssh_bootstrap_remote_qsh_quoting_is_bare_for_safe_chars_and_single_quoted_otherwise() {
    for (word, sent) in [
        ("qsh", "qsh"),
        ("/usr/local/bin/qsh", "/usr/local/bin/qsh"),
        ("~/.cargo/bin/qsh", "~/.cargo/bin/qsh"),
        ("C:/Qsh/qsh.exe", "C:/Qsh/qsh.exe"),
        (r"C:\Qsh\qsh.exe", r"C:\Qsh\qsh.exe"),
        (
            "C:/Program Files/qsh/qsh.exe",
            "'C:/Program Files/qsh/qsh.exe'",
        ),
        ("/opt/my qsh/qsh", "'/opt/my qsh/qsh'"),
        ("it's", r"'it'\''s'"),
        ("$(id)", "'$(id)'"),
    ] {
        let fake = FakeSsh::new();
        let _ = responder_error(&fake, word).await;
        let calls = fake.calls();
        assert_eq!(calls.len(), 1, "{word}");
        let args = &calls[0];
        let after = args
            .iter()
            .position(|a| a == "dave@box")
            .expect("dest in argv");
        // `<dest> <remote_qsh> pair ssh-respond`, each its own argument.
        assert_eq!(args[after + 1], sent, "{word}");
        assert_eq!(&args[after + 2..], ["pair", "ssh-respond"], "{word}");
    }
}

// ---------------------------------------------------------------------
// ssh -G
// ---------------------------------------------------------------------

#[tokio::test]
async fn ssh_g_output_is_capped_and_only_four_keys_are_read() {
    let mut fake = FakeSsh::new();
    fake.g_output(
        b"host box\nhostname box.example.com\nport 2222\nuser dave\n\
          identityfile ~/.ssh/id_ed25519\nproxyjump none\nstricthostkeychecking ask\n",
    );
    let got = runner(&fake)
        .resolve(&dest("box"), &CancelToken::new())
        .await
        .unwrap();
    assert_eq!(got.hostname, "box.example.com");
    assert_eq!(got.user.as_deref(), Some("dave"));
    assert!(!got.proxied);
    assert_eq!(fake.calls(), vec![vec!["-G", "--", "box"]]);

    // Exactly the cap is read; one byte more is refused.
    let mut at_cap = b"hostname box\n".to_vec();
    at_cap.resize(SSH_G_OUTPUT_MAX, b'\n');
    fake.g_output(&at_cap);
    let got = runner(&fake)
        .resolve(&dest("box"), &CancelToken::new())
        .await
        .unwrap();
    assert_eq!(got.hostname, "box");

    let mut over = at_cap.clone();
    over.extend_from_slice(&vec![b'x'; 70_000]);
    fake.g_output(&over);
    let err = runner(&fake)
        .resolve(&dest("box"), &CancelToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert_eq!(reason(&err), "ssh_g_too_large");
}

#[tokio::test]
async fn ssh_g_proxyjump_marks_the_bootstrap_as_proxied() {
    for line in ["proxyjump bastion.example.com\n", "proxycommand nc %h %p\n"] {
        let mut fake = FakeSsh::new();
        fake.g_output(format!("hostname box\n{line}").as_bytes());
        let got = runner(&fake)
            .resolve(&dest("box"), &CancelToken::new())
            .await
            .unwrap();
        assert!(got.proxied, "{line}");
        assert_eq!(got.hostname, "box");
    }
}

#[tokio::test]
async fn ssh_g_failure_is_a_config_error_with_the_exit_status() {
    let mut fake = FakeSsh::new();
    fake.g_output(b"").g_exit(255);
    let err = runner(&fake)
        .resolve(&dest("box"), &CancelToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert_eq!(reason(&err), "ssh_g_failed");
    assert_eq!(err.details["ssh_exit"], 255);
}

// ---------------------------------------------------------------------
// Exit status mapping
// ---------------------------------------------------------------------

#[tokio::test]
async fn ssh_exit_codes_map_to_the_adr_reasons() {
    // 9009 (cmd.exe) cannot be a Unix exit status: it is checked here only
    // where a process can return it, and for every platform in qsh-core's
    // `ssh_exit_codes_map_to_the_adr_reasons_before_the_hello`.
    let mut table: Vec<(i32, ErrorCode, &str)> = vec![
        (127, ErrorCode::RemoteError, "remote_qsh_missing"),
        (2, ErrorCode::Unsupported, "remote_qsh_too_old"),
        (1, ErrorCode::RemoteError, "remote_command_failed"),
        (255, ErrorCode::ConnectionFailed, "ssh_failed"),
        (0, ErrorCode::RemoteError, "bootstrap_protocol"),
    ];
    if cfg!(windows) {
        table.push((9009, ErrorCode::RemoteError, "remote_qsh_missing"));
    }
    for (exit, code, expected) in table {
        let mut fake = FakeSsh::new();
        fake.exit(exit);
        let err = responder_error(&fake, "qsh").await;
        assert_eq!(err.code, code, "exit {exit}");
        assert_eq!(reason(&err), expected, "exit {exit}");
    }

    // The remote status is reported, never the remote's words.
    let mut fake = FakeSsh::new();
    fake.exit(1).stderr("bash: qsh: command not found");
    let err = responder_error(&fake, "qsh").await;
    assert_eq!(err.details["remote_exit"], 1);
    assert!(!err.message.contains("command not found"));
}

#[tokio::test]
async fn ssh_exit_after_the_hello_is_ssh_failed_for_255_and_a_protocol_error_otherwise() {
    for (exit, code, expected) in [
        (255, ErrorCode::ConnectionFailed, "ssh_failed"),
        (1, ErrorCode::RemoteError, "bootstrap_protocol"),
    ] {
        let mut fake = FakeSsh::new();
        fake.script(&hello_line(HelloStatus::Ready)).exit(exit);
        let mut child = runner(&fake)
            .spawn_responder(&dest("box"), "qsh", options(true))
            .unwrap();
        assert!(matches!(
            child.recv().await.unwrap(),
            BootstrapLine::Hello(_)
        ));
        assert!(child.hello_seen());
        let err = child.recv().await.unwrap_err();
        assert_eq!(err.code, code, "exit {exit}");
        assert_eq!(reason(&err), expected, "exit {exit}");
    }
}

#[tokio::test]
async fn ssh_not_found_is_a_config_error_for_both_calls() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-ssh");
    let runner = SshRunner::new(&missing);
    let err = runner
        .resolve(&dest("box"), &CancelToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert_eq!(reason(&err), "ssh_not_found");
    let err = runner
        .spawn_responder(&dest("box"), "qsh", options(true))
        .err()
        .expect("spawn fails");
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert_eq!(reason(&err), "ssh_not_found");
    assert!(!err.retryable);
}

// ---------------------------------------------------------------------
// The stream through the child
// ---------------------------------------------------------------------

#[tokio::test]
async fn ssh_child_counts_rc_output_before_the_hello_and_carries_both_directions() {
    let mut fake = FakeSsh::new();
    let mut script = b"Welcome to box\nexport TOKEN=hunter2\n".to_vec();
    script.extend(hello_line(HelloStatus::Ready));
    fake.script(&script).record_stdin();

    let mut child = runner(&fake)
        .spawn_responder(&dest("box"), "qsh", options(true))
        .unwrap();
    let first = child.recv().await.unwrap();
    assert!(matches!(first, BootstrapLine::Hello(_)));
    assert_eq!(child.skipped_lines(), 2);
    assert_eq!(
        child.skipped_bytes(),
        "Welcome to box\nexport TOKEN=hunter2\n".len()
    );

    child.send(&commit()).await.unwrap();
    let exit = tokio::time::timeout(GENEROUS, child.finish())
        .await
        .expect("the fake exits at the end of its stdin");
    assert_eq!(exit, qsh_core::ssh_bootstrap::SshExit::Code(0));
    assert_eq!(
        fake.stdin_log(),
        commit_text().into_bytes(),
        "the responder received the commit line unchanged"
    );
}

fn commit_text() -> String {
    match commit() {
        BootstrapLine::Commit(c) => BootstrapLine::Commit(c).encode_line().unwrap(),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn ssh_child_refuses_a_hello_buried_under_more_than_64_kib_of_rc_output() {
    let mut fake = FakeSsh::new();
    let mut script = vec![b'x'; 70_000];
    script.push(b'\n');
    script.extend(hello_line(HelloStatus::Ready));
    fake.script(&script);
    let err = responder_error(&fake, "qsh").await;
    assert_eq!(err.code, ErrorCode::RemoteError);
    assert_eq!(reason(&err), "bootstrap_protocol");
}

// ---------------------------------------------------------------------
// Deadlines and cancellation
// ---------------------------------------------------------------------

#[tokio::test]
async fn ssh_child_hello_and_message_deadlines_are_timeout_errors() {
    // A hello that never comes.
    let mut fake = FakeSsh::new();
    fake.hang();
    let mut child = runner(&fake)
        .spawn_responder(&dest("box"), "qsh", {
            let mut o = options(true);
            o.timeouts = BootstrapTimeouts {
                hello: Some(Duration::from_millis(300)),
                message: GENEROUS,
            };
            o
        })
        .unwrap();
    // Wait for the fake to have started before the clock runs out, so a
    // loaded machine cannot kill it before it records its pid. The hello
    // deadline starts at the first `recv`.
    let pid = fake.wait_for_pid(GENEROUS).expect("the fake started");
    let err = child.recv().await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout);
    assert_eq!(reason(&err), "bootstrap_timeout");
    assert_eq!(err.details["stage"], "hello");
    #[cfg(unix)]
    assert!(
        process_is_gone(pid),
        "the timed out ssh is ended and reaped"
    );
    let _ = pid;

    // A result that never comes after the hello.
    let mut fake = FakeSsh::new();
    fake.script(&hello_line(HelloStatus::Ready)).hang();
    let mut child = runner(&fake)
        .spawn_responder(&dest("box"), "qsh", {
            let mut o = options(true);
            o.timeouts = BootstrapTimeouts {
                hello: Some(GENEROUS),
                message: Duration::from_millis(300),
            };
            o
        })
        .unwrap();
    assert!(matches!(
        child.recv().await.unwrap(),
        BootstrapLine::Hello(_)
    ));
    let err = child.recv().await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout);
    assert_eq!(err.details["stage"], "message");
}

#[tokio::test]
async fn ssh_child_is_reaped_when_the_cancel_token_fires() {
    let mut fake = FakeSsh::new();
    fake.hang();
    let cancel = CancelToken::new();
    let mut child = runner(&fake)
        .spawn_responder(
            &dest("box"),
            "qsh",
            ResponderOptions::new(false, cancel.clone()),
        )
        .unwrap();
    let pid = fake.wait_for_pid(GENEROUS).expect("the fake started");
    let waiting = tokio::spawn(async move { child.recv().await });
    cancel.cancel();
    let err = tokio::time::timeout(GENEROUS, waiting)
        .await
        .expect("cancel ends the wait")
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Canceled);
    #[cfg(unix)]
    assert!(process_is_gone(pid), "the canceled ssh is ended and reaped");
    let _ = pid;
}

/// A Ctrl-C in the terminal reaches ssh in the same foreground process group.
/// Here the signal goes to the fake alone, as it would to a real ssh sitting at
/// a password prompt: the call must end `CANCELED`, with nothing left running.
#[cfg(unix)]
#[tokio::test]
async fn ssh_child_is_reaped_on_cancel() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let mut fake = FakeSsh::new();
    fake.hang();
    let mut child = runner(&fake)
        .spawn_responder(&dest("box"), "qsh", options(false))
        .unwrap();
    let pid = fake.wait_for_pid(GENEROUS).expect("the fake started");
    let waiting = tokio::spawn(async move { child.recv().await });
    kill(Pid::from_raw(pid as i32), Signal::SIGINT).unwrap();
    let err = tokio::time::timeout(GENEROUS, waiting)
        .await
        .expect("SIGINT ends the ssh child")
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Canceled);
    assert!(!err.retryable);
    assert!(process_is_gone(pid), "the interrupted ssh is reaped");
}

/// The Windows twin: a console Ctrl-C ends `ssh.exe` with
/// `STATUS_CONTROL_C_EXIT`, which the call reports as `CANCELED`.
#[cfg(windows)]
#[tokio::test]
async fn ssh_child_is_reaped_on_cancel() {
    let mut fake = FakeSsh::new();
    fake.exit(0xC000_013Au32 as i32);
    let err = responder_error(&fake, "qsh").await;
    assert_eq!(err.code, ErrorCode::Canceled);
    assert!(!err.retryable);
}

/// The remote responder as a process (ADR-0044 decisions 9, 10, 12). Unix
/// only until M20 (decision 10): a Windows build does not register the
/// command, see `pair_ssh_respond_is_unknown_on_windows_before_m20`.
#[cfg(unix)]
mod responder {
    use super::*;
    use crate::common::Sandbox;
    use qsh_proto::ssh_bootstrap::{BootstrapReader, ResultStatus};

    /// A well-formed fingerprint made of one repeated byte, for a pin nobody
    /// owns the key of.
    fn fp(byte: u8) -> String {
        use base64::Engine as _;
        format!(
            "sha256:{}",
            base64::engine::general_purpose::STANDARD.encode([byte; 32])
        )
    }

    fn commit_for(name: &str, fingerprint: &str, role: &str, address: Option<&str>) -> Vec<u8> {
        BootstrapLine::Commit(Commit {
            version: 1,
            fingerprint: fingerprint.into(),
            name: name.into(),
            role: role.into(),
            address: address.map(str::to_string),
        })
        .encode_line()
        .unwrap()
        .into_bytes()
    }

    /// What one `qsh pair ssh-respond` run said.
    struct Responded {
        code: i32,
        stdout: Vec<u8>,
        stderr: String,
        lines: Vec<BootstrapLine>,
    }

    impl Responded {
        fn hello(&self) -> &Hello {
            match self.lines.first() {
                Some(BootstrapLine::Hello(hello)) => hello,
                other => panic!("expected a hello first, got {other:?}"),
            }
        }

        fn result(&self) -> &qsh_proto::ssh_bootstrap::BootstrapResult {
            match self.lines.as_slice() {
                [BootstrapLine::Hello(_), BootstrapLine::Result(result)] => result,
                other => panic!("expected a hello and a result, got {other:?}"),
            }
        }
    }

    /// Start `qsh pair ssh-respond` in `remote`, write `input` to its stdin,
    /// close it, and wait. `log` becomes `QSH_LOG` when given.
    fn respond(remote: &Sandbox, input: &[u8], log: Option<&str>) -> Responded {
        use std::io::Write as _;
        use std::process::Stdio;
        let mut command = remote.command(&["pair", "ssh-respond"]);
        if let Some(log) = log {
            command.env("QSH_LOG", log).env("NO_COLOR", "1");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qsh pair ssh-respond");
        let mut stdin = child.stdin.take().expect("stdin pipe");
        // The responder may answer and exit before it reads everything.
        let _ = stdin.write_all(input);
        drop(stdin);
        let output = child.wait_with_output().expect("wait for the responder");
        let lines = BootstrapReader::new()
            .push(&output.stdout)
            .unwrap_or_else(|e| {
                panic!(
                    "stdout is not a bootstrap stream ({e}): {:?}",
                    output.stdout
                )
            });
        Responded {
            code: crate::common::exit_code(&output),
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            lines,
        }
    }

    fn trust_file(sandbox: &Sandbox) -> std::path::PathBuf {
        sandbox.config_dir().join("trust.toml")
    }

    fn trust_bytes(sandbox: &Sandbox) -> Vec<u8> {
        std::fs::read(trust_file(sandbox)).unwrap_or_default()
    }

    fn write_config(sandbox: &Sandbox, text: &str) {
        std::fs::write(sandbox.config_dir().join("config.toml"), text).unwrap();
    }

    /// The audit records the responder wrote (the pins a test planted itself
    /// leave `trust.add` records that are not the subject).
    fn respond_audits(sandbox: &Sandbox) -> Vec<serde_json::Value> {
        sandbox
            .audit_records()
            .into_iter()
            .filter(|record| record["action"] == "pair.ssh_respond")
            .collect()
    }

    /// A free loopback UDP port, released again.
    fn free_udp_addr() -> String {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().to_string()
    }

    #[test]
    fn ssh_respond_reports_not_initialized_without_writing() {
        let remote = Sandbox::new();
        let got = respond(&remote, &commit_for("laptop", &fp(1), "full", None), None);
        assert_eq!(got.code, 0, "{}", got.stderr);
        assert_eq!(
            got.lines.len(),
            1,
            "a hello and nothing else: {:?}",
            got.lines
        );
        let hello = got.hello();
        assert_eq!(hello.status, HelloStatus::NotInitialized);
        assert_eq!(hello.fingerprint, None);
        assert_eq!(hello.versions, vec![1]);
        // No identity was created and no trust file was started.
        assert!(!remote.config_dir().join("identity").exists());
        assert!(!trust_file(&remote).exists());
    }

    #[test]
    fn ssh_respond_stdout_is_only_bootstrap_lines() {
        let remote = Sandbox::initialized();
        let got = respond(&remote, &commit_for("laptop", &fp(1), "full", None), None);
        assert_eq!(got.code, 0, "{}", got.stderr);
        let text = String::from_utf8(got.stdout).unwrap();
        assert_eq!(text.lines().count(), 2, "{text:?}");
        for line in text.lines() {
            assert!(line.starts_with("qsh-bootstrap {"), "{line:?}");
        }
        assert!(!text.contains('\r'), "no CR from the responder itself");
    }

    #[test]
    fn ssh_respond_serve_listening_reflects_a_bound_udp_port() {
        // A row with a real `qsh serve` holding the configured port.
        let remote = Sandbox::initialized();
        let serve = crate::common::ServeGuard::start(&remote);
        write_config(&remote, &format!("[serve]\nbind = \"{}\"\n", serve.addr()));
        let got = respond(&remote, b"", None);
        assert_eq!(got.code, 0, "{}", got.stderr);
        assert_eq!(got.hello().status, HelloStatus::Ready);
        assert_eq!(got.hello().serve_bind.as_deref(), Some(serve.addr()));
        assert_eq!(got.hello().serve_listening, Some(true));
        drop(serve);

        // A row with nothing on the port.
        let remote = Sandbox::initialized();
        let spec = free_udp_addr();
        write_config(&remote, &format!("[serve]\nbind = \"{spec}\"\n"));
        let got = respond(&remote, b"", None);
        assert_eq!(got.hello().serve_bind.as_deref(), Some(spec.as_str()));
        assert_eq!(got.hello().serve_listening, Some(false));
        // The probe did not keep the port.
        std::net::UdpSocket::bind(&spec).expect("the port is free after the probe");

        // No config at all: the default bind, reported as such.
        let remote = Sandbox::initialized();
        let got = respond(&remote, b"", None);
        assert_eq!(got.hello().serve_bind.as_deref(), Some("[::]:4433"));
    }

    #[test]
    fn ssh_respond_hello_carries_this_devices_fingerprint() {
        let remote = Sandbox::initialized();
        let got = respond(&remote, b"", None);
        assert_eq!(
            got.hello().fingerprint.as_deref(),
            Some(remote.fingerprint().as_str())
        );
    }

    #[test]
    fn ssh_respond_writes_an_inbound_only_pin_with_the_committed_role() {
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        let got = respond(
            &remote,
            &commit_for("laptop", &client.fingerprint(), "exec", None),
            None,
        );
        assert_eq!(got.code, 0, "{}", got.stderr);
        let result = got.result();
        assert_eq!(result.status, ResultStatus::Pinned);
        assert_eq!(result.name, "laptop");
        assert_eq!(result.role.as_deref(), Some("exec"));
        assert!(result.created);

        let store = qsh_core::TrustStore::load(&trust_file(&remote)).unwrap();
        let peer = store.find("laptop").expect("the pin exists");
        assert_eq!(peer.fingerprint, client.fingerprint());
        assert_eq!(peer.address, "", "an inbound-only pin has no address");
        assert_eq!(peer.role.as_deref(), Some("exec"));

        // The pin is the one `trust list` shows.
        let (code, listed) = remote.json(&["trust", "list", "--json"]);
        assert_eq!(code, 0, "{listed}");
        assert_eq!(listed["data"]["peers"][0]["name"], "laptop");
    }

    #[test]
    fn ssh_respond_a_commit_address_makes_an_addressed_pin() {
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        let got = respond(
            &remote,
            &commit_for(
                "ctl",
                &client.fingerprint(),
                "full",
                Some("ctl.example:4500"),
            ),
            None,
        );
        assert_eq!(got.result().status, ResultStatus::Pinned);
        let store = qsh_core::TrustStore::load(&trust_file(&remote)).unwrap();
        assert_eq!(store.find("ctl").unwrap().address, "ctl.example:4500");
    }

    #[test]
    fn ssh_respond_returns_exists_and_keeps_the_role_for_a_known_fingerprint() {
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        remote.trust_add_with_role("known", None, &client.fingerprint(), "read-only");
        let before = trust_bytes(&remote);
        let got = respond(
            &remote,
            &commit_for("laptop", &client.fingerprint(), "full", None),
            None,
        );
        let result = got.result();
        assert_eq!(result.status, ResultStatus::Exists);
        assert_eq!(result.name, "known");
        assert_eq!(result.role.as_deref(), Some("read-only"));
        assert!(!result.created);
        assert_eq!(trust_bytes(&remote), before, "trust.toml is untouched");
        assert!(
            respond_audits(&remote).is_empty(),
            "nothing was written, so nothing is audited"
        );
    }

    #[test]
    fn ssh_respond_returns_conflict_for_the_same_name_with_another_fingerprint() {
        let remote = Sandbox::initialized();
        remote.trust_add_with_role("laptop", None, &fp(7), "full");
        let before = trust_bytes(&remote);
        let got = respond(&remote, &commit_for("laptop", &fp(8), "full", None), None);
        let result = got.result();
        assert_eq!(result.status, ResultStatus::Conflict);
        assert_eq!(result.code, Some(ErrorCode::SessionConflict));
        assert!(!result.created);
        assert_eq!(trust_bytes(&remote), before, "trust.toml is byte-identical");
    }

    #[test]
    fn ssh_respond_writes_nothing_when_the_client_closes_its_end_first() {
        // The client found its own conflict and never sent a commit.
        let remote = Sandbox::initialized();
        let got = respond(&remote, b"", None);
        assert_eq!(got.code, 0, "{}", got.stderr);
        assert_eq!(got.lines.len(), 1);
        assert!(!trust_file(&remote).exists());
        assert!(respond_audits(&remote).is_empty());
    }

    #[test]
    fn ssh_respond_refuses_to_pin_when_audit_is_unwritable() {
        let remote = Sandbox::initialized();
        // An audit "file" that is a directory cannot be appended to, on any OS.
        let blocked = remote.state_dir().join("audit-is-a-directory");
        std::fs::create_dir_all(&blocked).unwrap();
        write_config(
            &remote,
            &format!("[audit]\npath = '{}'\n", blocked.display()),
        );
        let got = respond(&remote, &commit_for("laptop", &fp(3), "full", None), None);
        assert_eq!(got.code, 0, "{}", got.stderr);
        let result = got.result();
        assert_eq!(result.status, ResultStatus::Error);
        assert_eq!(result.code, Some(ErrorCode::Internal));
        assert!(!result.created);
        assert!(
            !trust_file(&remote).exists(),
            "no audit record, no pin: {}",
            result.message.as_deref().unwrap_or("")
        );
    }

    #[test]
    fn ssh_respond_audit_record_has_only_structural_fields() {
        let remote = Sandbox::initialized();
        let got = respond(&remote, &commit_for("laptop", &fp(4), "tunnel", None), None);
        assert_eq!(got.result().status, ResultStatus::Pinned);
        let records = respond_audits(&remote);
        assert_eq!(records.len(), 1, "{records:?}");
        let record = &records[0];
        assert_eq!(record["action"], "pair.ssh_respond");
        assert_eq!(record["principal"], "device:laptop");
        assert_eq!(record["resource"], "laptop");
        assert_eq!(record["role"], "tunnel");
        assert_eq!(record["auth_path"], "local");
        let mut keys: Vec<&str> = record
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "action",
                "auth_path",
                "decision",
                "peer_addr",
                "principal",
                "request_id",
                "resource",
                "role",
                "rule",
                "ts"
            ]
        );
    }

    #[test]
    fn ssh_respond_never_logs_the_commit() {
        let remote = Sandbox::initialized();
        let name = "sentinel-name-7f3a";
        let fingerprint = fp(0x5A);
        let got = respond(
            &remote,
            &commit_for(name, &fingerprint, "full", None),
            Some("trace"),
        );
        assert_eq!(got.result().status, ResultStatus::Pinned);
        assert!(!got.stderr.contains(name), "{}", got.stderr);
        assert!(!got.stderr.contains(&fingerprint), "{}", got.stderr);
        assert!(!got.stderr.contains("qsh-bootstrap"), "{}", got.stderr);
    }

    #[test]
    fn ssh_respond_rejects_a_malformed_commit_with_an_error_result() {
        let remote = Sandbox::initialized();
        let got = respond(&remote, b"not a bootstrap line\n", None);
        assert_eq!(got.code, 0, "{}", got.stderr);
        let result = got.result();
        assert_eq!(result.status, ResultStatus::Error);
        assert_eq!(result.code, Some(ErrorCode::InvalidArgument));
        assert!(!trust_file(&remote).exists());
    }

    #[test]
    fn ssh_respond_is_hidden_from_help() {
        let sandbox = Sandbox::new();
        for args in [&["--help"][..], &["pair", "--help"][..]] {
            let out = sandbox.qsh(args);
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(text.contains("invite"), "{args:?}: sanity: {text}");
            assert!(!text.contains("ssh-respond"), "{args:?}: {text}");
        }
        // Hidden is not removed: the command parses and has its own help.
        let out = sandbox.qsh(&["pair", "ssh-respond", "--help"]);
        assert_eq!(crate::common::exit_code(&out), 0);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("bootstrap"),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        // And it gets no man page: the generator skips hidden subcommands, the
        // way it skips `qsh reverse` and `qsh trust invite` (ADR-0044 decision
        // 9; the user-facing `pair ssh` gets its own page).
        let man = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/man");
        assert!(!man.join("qsh-pair-ssh-respond.1").exists());
    }

    // ---------------------------------------------------------------------
    // The responder behind the fake ssh
    // ---------------------------------------------------------------------

    /// Drive a whole bootstrap conversation through `fake`'s local responder:
    /// recv the hello, send a commit for `client`, recv the result, and let the
    /// child finish. Returns the hello and the result.
    async fn converse_through(
        fake: &FakeSsh,
        remote_qsh: &str,
        client: &Sandbox,
        name: &str,
    ) -> (Hello, qsh_proto::ssh_bootstrap::BootstrapResult) {
        let mut child = runner(fake)
            .spawn_responder(&dest("dave@box"), remote_qsh, options(true))
            .unwrap();
        let hello = match tokio::time::timeout(GENEROUS, child.recv())
            .await
            .expect("hello in time")
            .expect("hello")
        {
            BootstrapLine::Hello(hello) => hello,
            other => panic!("expected the hello, got {other:?}"),
        };
        child
            .send(&BootstrapLine::Commit(Commit {
                version: 1,
                fingerprint: client.fingerprint(),
                name: name.into(),
                role: "full".into(),
                address: None,
            }))
            .await
            .unwrap();
        let result = match tokio::time::timeout(GENEROUS, child.recv())
            .await
            .expect("result in time")
            .expect("result")
        {
            BootstrapLine::Result(result) => result,
            other => panic!("expected the result, got {other:?}"),
        };
        let exit = tokio::time::timeout(GENEROUS, child.finish())
            .await
            .expect("the responder ends at the end of its stdin");
        assert_eq!(exit, qsh_core::ssh_bootstrap::SshExit::Code(0));
        (hello, result)
    }

    fn fake_with_responder(remote: &Sandbox) -> FakeSsh {
        let mut fake = FakeSsh::new();
        fake.run_local_responder(
            std::path::Path::new(env!("CARGO_BIN_EXE_qsh")),
            remote.config_dir(),
            remote.state_dir(),
        );
        fake
    }

    #[tokio::test]
    async fn ssh_bootstrap_local_responder_pins_the_client_through_the_fake_ssh() {
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        let fake = fake_with_responder(&remote);
        let (hello, result) = converse_through(&fake, "qsh", &client, "laptop").await;
        assert_eq!(hello.status, HelloStatus::Ready);
        assert_eq!(
            hello.fingerprint.as_deref(),
            Some(remote.fingerprint().as_str())
        );
        assert_eq!(result.status, ResultStatus::Pinned);
        let store = qsh_core::TrustStore::load(&trust_file(&remote)).unwrap();
        assert_eq!(
            store.find("laptop").unwrap().fingerprint,
            client.fingerprint()
        );
        // The client's own tree was never touched by the remote half.
        assert!(!trust_file(&client).exists());
        // The fake recorded the fixed responder argv.
        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0][calls[0].len() - 3..],
            ["qsh", "pair", "ssh-respond"]
        );
    }

    #[tokio::test]
    async fn ssh_bootstrap_local_responder_survives_rc_output_and_crlf_line_ends() {
        // A remote shell that prints a banner first and whose console turns
        // every line end into CR LF (a Windows host).
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        let mut fake = fake_with_responder(&remote);
        fake.script(b"Welcome to box\r\nexport TOKEN=hunter2\r\n")
            .respond_with_crlf();
        let (hello, result) = converse_through(&fake, "qsh", &client, "laptop").await;
        assert_eq!(hello.status, HelloStatus::Ready);
        assert_eq!(result.status, ResultStatus::Pinned);
    }

    #[tokio::test]
    async fn ssh_bootstrap_local_responder_reports_exists_on_the_second_run() {
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        let fake = fake_with_responder(&remote);
        let (_hello, first) = converse_through(&fake, "qsh", &client, "laptop").await;
        assert_eq!(first.status, ResultStatus::Pinned);
        let before = trust_bytes(&remote);
        let (_hello, second) = converse_through(&fake, "qsh", &client, "laptop").await;
        assert_eq!(second.status, ResultStatus::Exists);
        assert_eq!(second.name, "laptop");
        assert_eq!(second.role.as_deref(), Some("full"));
        assert_eq!(trust_bytes(&remote), before);
    }

    /// The remote command goes through a shell, as sshd does it: the word the
    /// client sends for `<remote_qsh>` must reach the shell as one program.
    #[tokio::test]
    async fn ssh_bootstrap_local_responder_runs_the_remote_qsh_word_through_a_shell() {
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        let qsh = env!("CARGO_BIN_EXE_qsh");
        let mut fake = fake_with_responder(&remote);
        fake.respond_through_shell();

        // The bare form works only where every character is shell-safe, the
        // rule of ADR-0044 decision 9; a build directory that is not safe
        // is single-quoted.
        let quoted = qsh_core::ssh_bootstrap::quote_remote_program(qsh).unwrap();
        if quoted == qsh {
            let (hello, result) = converse_through(&fake, qsh, &client, "laptop").await;
            assert_eq!(hello.status, HelloStatus::Ready);
            assert_eq!(result.status, ResultStatus::Pinned);
        } else {
            assert!(quoted.starts_with('\''), "unexpected quoting {quoted}");
        }
    }

    /// A path with a space is single-quoted for a POSIX remote shell, and the
    /// shell hands the responder one program.
    #[tokio::test]
    async fn ssh_bootstrap_local_responder_runs_a_single_quoted_remote_qsh() {
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        let dir = tempfile::tempdir().unwrap();
        let spaced = dir.path().join("my qsh");
        std::fs::create_dir(&spaced).unwrap();
        let copy = spaced.join("qsh");
        std::fs::copy(env!("CARGO_BIN_EXE_qsh"), &copy).unwrap();
        let mut fake = fake_with_responder(&remote);
        fake.respond_through_shell();
        let word = copy.to_str().unwrap();
        assert_ne!(
            qsh_core::ssh_bootstrap::quote_remote_program(word).unwrap(),
            word,
            "the path needs quoting"
        );
        let (_hello, result) = converse_through(&fake, word, &client, "laptop").await;
        assert_eq!(result.status, ResultStatus::Pinned);
    }

    #[tokio::test]
    async fn ssh_bootstrap_local_responder_without_an_identity_says_not_initialized() {
        let remote = Sandbox::new();
        let fake = fake_with_responder(&remote);
        let mut child = runner(&fake)
            .spawn_responder(&dest("dave@box"), "qsh", options(true))
            .unwrap();
        let hello = tokio::time::timeout(GENEROUS, child.recv())
            .await
            .expect("hello in time")
            .expect("hello");
        assert!(matches!(
            hello,
            BootstrapLine::Hello(Hello {
                status: HelloStatus::NotInitialized,
                ..
            })
        ));
        let exit = tokio::time::timeout(GENEROUS, child.finish())
            .await
            .expect("the responder ends");
        assert_eq!(exit, qsh_core::ssh_bootstrap::SshExit::Code(0));
        assert!(!trust_file(&remote).exists());
    }
}

/// A Windows build has no `qsh pair ssh-respond` before M20 (ADR-0044
/// decision 10): clap exits 2, which the client reads as
/// `remote_qsh_too_old` (`ssh_exit_codes_map_to_the_adr_reasons`).
#[cfg(windows)]
#[test]
fn pair_ssh_respond_is_unknown_on_windows_before_m20() {
    let sandbox = crate::common::Sandbox::new();
    let out = sandbox.qsh(&["pair", "ssh-respond"]);
    assert_eq!(crate::common::exit_code(&out), 2);
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
