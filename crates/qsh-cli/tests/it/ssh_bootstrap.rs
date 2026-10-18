//! The ssh-side machinery of `qsh pair ssh` against a fake `ssh`
//! (ADR-0044; `docs/design/testing.md`).
//!
//! `qsh_testkit::fake_ssh::FakeSsh` stands in for the system `ssh`: it
//! records its argv and prints what the test scripts. There is no sshd, no
//! OpenSSH configuration and no remote qsh. The first half drives
//! `qsh_core::ssh_bootstrap` directly (the ssh child layer); the `pair`
//! module runs `qsh pair ssh` itself against the fake.
//!
//! The remote half is covered here too: the hidden `qsh pair ssh-respond`
//! is started as a real process against a sandbox (the `ssh_respond_*`
//! tests write a `commit` on its stdin), and the fake `ssh` can run it as
//! the remote end of the ssh child (`ssh_bootstrap_local_responder_*`).
//!
//! The same file runs on Windows, where the fake is a copied `ssh.exe` and
//! the recorded argv shows what `ssh.exe` receives after the Windows
//! command-line round trip. The responder tests run there too, against the
//! Windows `qsh pair ssh-respond` (ADR-0044 decision 10): the fake `ssh.exe`
//! starts the real responder as the remote end of its pipes.

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
pub(crate) fn process_is_gone(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid as i32), None) == Err(Errno::ESRCH)
}

/// `tasklist` lists a process by its quoted pid in CSV mode; an empty match
/// prints an INFO line instead.
#[cfg(windows)]
pub(crate) fn process_is_gone(pid: u32) -> bool {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .expect("run tasklist");
    !String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\""))
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
    assert!(
        process_is_gone(pid),
        "the timed out ssh is ended and reaped"
    );

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
    assert!(process_is_gone(pid), "the canceled ssh is ended and reaped");
}

/// `ssh -G` can sit on a slow resolver or a hanging `Match exec`; cancel must
/// end that child too, on Windows as on Unix (ADR-0044 decision 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_g_child_is_reaped_when_the_cancel_token_fires() {
    let mut fake = FakeSsh::new();
    fake.g_hang();
    let cancel = CancelToken::new();
    let program = fake.program().to_path_buf();
    let target = dest("box");
    let waiting = tokio::spawn({
        let cancel = cancel.clone();
        async move { SshRunner::new(&program).resolve(&target, &cancel).await }
    });
    let pid = fake.wait_for_pid(GENEROUS).expect("the fake started");
    cancel.cancel();
    let err = tokio::time::timeout(GENEROUS, waiting)
        .await
        .expect("cancel ends the wait")
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Canceled);
    assert!(!err.retryable);
    assert!(
        process_is_gone(pid),
        "the canceled ssh -G is ended and reaped"
    );
}

/// A real OpenSSH can outlive the connection's SIGINT and report 255 ("Killed
/// by signal 2") after closing its stdout. The cancel token is what knows the
/// user pressed Ctrl-C, so the call is `CANCELED`, not `ssh_failed`.
///
/// Unix only: the fake ssh is a `#!/bin/sh` script that closes its stdout and
/// exits 255. Windows has no such exit code for an interrupted ssh; the
/// console Ctrl-C there is `STATUS_CONTROL_C_EXIT`, which
/// `ssh_child_is_reaped_on_cancel` (its Windows twin) maps to `CANCELED`, and
/// the cancel-token path is `ssh_child_is_reaped_when_the_cancel_token_fires` in this file.
#[cfg(unix)]
#[tokio::test]
async fn ssh_child_exit_255_after_a_cancel_is_canceled_not_ssh_failed() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("ssh");
    std::fs::write(&script, "#!/bin/sh\nexec 1>&-\nsleep 1\nexit 255\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Control: with no cancel the same child is an ordinary ssh failure.
    let mut child = SshRunner::new(&script)
        .spawn_responder(&dest("box"), "qsh", options(true))
        .unwrap();
    let err = tokio::time::timeout(GENEROUS, child.recv())
        .await
        .expect("the script ends")
        .unwrap_err();
    assert_eq!(reason(&err), "ssh_failed", "{err:?}");

    let cancel = CancelToken::new();
    let mut child = SshRunner::new(&script)
        .spawn_responder(
            &dest("box"),
            "qsh",
            ResponderOptions::new(true, cancel.clone()),
        )
        .unwrap();
    let waiting = tokio::spawn(async move { child.recv().await });
    // After the script closed stdout and while it is still in its sleep.
    tokio::time::sleep(Duration::from_millis(400)).await;
    cancel.cancel();
    let err = tokio::time::timeout(GENEROUS, waiting)
        .await
        .expect("the script ends")
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Canceled, "{err:?}");
    assert!(!err.retryable);
}

/// A Ctrl-C in the terminal reaches ssh in the same foreground process group.
/// Here the signal goes to the fake alone, as it would to a real ssh sitting at
/// a password prompt: the call must end `CANCELED`, with nothing left running.
/// Unix only because the signal is `SIGINT` sent to one process; the Windows
/// twin of the same name follows.
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

/// The remote responder as a process (ADR-0044 decisions 9, 10, 12), on every
/// platform: the same cases run against the Windows responder.
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

    /// One run that does both halves of the responder's job: it reports the
    /// busy serve port in its hello and then writes the committed pin. Runs on
    /// every platform, so on Windows it is the Windows responder doing both.
    #[test]
    fn windows_responder_pins_and_reports_serve_listening() {
        let remote = Sandbox::initialized();
        let client = Sandbox::initialized();
        let serve = crate::common::ServeGuard::start(&remote);
        write_config(&remote, &format!("[serve]\nbind = \"{}\"\n", serve.addr()));
        let got = respond(
            &remote,
            &commit_for("laptop", &client.fingerprint(), "exec", None),
            None,
        );
        assert_eq!(got.code, 0, "{}", got.stderr);
        assert_eq!(got.hello().serve_bind.as_deref(), Some(serve.addr()));
        assert_eq!(got.hello().serve_listening, Some(true));
        let result = got.result();
        assert_eq!(result.status, ResultStatus::Pinned);
        assert_eq!(result.name, "laptop");
        let store = qsh_core::TrustStore::load(&trust_file(&remote)).unwrap();
        let peer = store.find("laptop").expect("the pin exists");
        assert_eq!(peer.fingerprint, client.fingerprint());
        assert_eq!(peer.address, "", "an inbound-only pin has no address");
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
    /// shell hands the responder one program. Unix only: the quoting is for a
    /// POSIX shell, and a Windows remote whose default shell is `cmd.exe` or
    /// PowerShell does not read single quotes (ADR-0044 decision 9 fails that
    /// case with an instruction instead; `quote_remote_program`'s unit tests
    /// pin the rule on every platform).
    #[cfg(unix)]
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

// ---------------------------------------------------------------------
// qsh pair ssh, the client half, on every platform
// ---------------------------------------------------------------------

/// The parts of `qsh pair ssh` that run on this machine alone: argument
/// checks, the ssh program lookup, and the mapping of an ssh failure. They
/// need a `Sandbox` and the fake, not a remote qsh, so the Windows leg runs
/// them too.
mod pair_client {
    use super::*;
    use crate::common::{Sandbox, exit_code};
    use serde_json::Value;

    /// A client whose `[ssh].program` is `fake`. A TOML literal string, so
    /// a Windows path needs no escaping.
    fn client_for(fake: &FakeSsh) -> Sandbox {
        let client = Sandbox::initialized();
        std::fs::write(
            client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
        )
        .unwrap();
        client
    }

    fn pair_json(client: &Sandbox, args: &[&str]) -> (i32, Value) {
        let mut argv = vec!["pair", "ssh"];
        argv.extend_from_slice(args);
        argv.push("--json");
        client.json(&argv)
    }

    fn trust_file_exists(client: &Sandbox) -> bool {
        client.config_dir().join("trust.toml").exists()
    }

    #[test]
    fn ssh_bootstrap_an_old_remote_is_unsupported_and_writes_nothing() {
        // A remote that does not know `pair ssh-respond` (an older qsh: clap
        // exits 2).
        let mut fake = FakeSsh::new();
        fake.exit(2);
        let client = client_for(&fake);
        let (code, got) = pair_json(&client, &["box"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["command"], "pair.ssh", "{got}");
        assert_eq!(got["ok"], false, "{got}");
        assert_eq!(got["error"]["code"], "UNSUPPORTED", "{got}");
        assert_eq!(
            got["error"]["details"]["reason"], "remote_qsh_too_old",
            "{got}"
        );
        assert!(!trust_file_exists(&client));
        // `ssh -G`, then the responder: two calls, in that order.
        let calls = fake.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[0], ["-G", "--", "box"]);
    }

    /// cmd.exe answers 9009 for a program it cannot find; only a Windows
    /// process can exit with that value (a Unix status is one byte).
    #[cfg(windows)]
    #[test]
    fn ssh_bootstrap_a_remote_cmd_exe_9009_is_a_missing_qsh_and_writes_nothing() {
        let mut fake = FakeSsh::new();
        fake.exit(9009);
        let client = client_for(&fake);
        let (code, got) = pair_json(&client, &["box"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["code"], "REMOTE_ERROR", "{got}");
        assert_eq!(
            got["error"]["details"]["reason"], "remote_qsh_missing",
            "{got}"
        );
        assert_eq!(got["error"]["details"]["remote_exit"], 9009, "{got}");
        assert!(!trust_file_exists(&client));
    }

    #[test]
    fn ssh_bootstrap_a_missing_ssh_program_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-ssh");
        let client = Sandbox::initialized();
        std::fs::write(
            client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n", missing.display()),
        )
        .unwrap();
        let (code, got) = pair_json(&client, &["box"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["code"], "CONFIG_ERROR", "{got}");
        assert_eq!(got["error"]["details"]["reason"], "ssh_not_found", "{got}");
        assert!(!trust_file_exists(&client));
    }

    /// Validation happens before the identity is made and before ssh runs
    /// (ADR-0044 decisions 7 and 18): a dest that looks like an ssh option
    /// reaches no process at all.
    #[test]
    fn ssh_bootstrap_an_option_like_dest_runs_no_ssh_and_creates_no_identity() {
        let fake = FakeSsh::new();
        let client = Sandbox::new();
        std::fs::write(
            client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
        )
        .unwrap();
        for bad in [
            "-oProxyCommand=touch /tmp/pwned",
            "-F/etc/passwd",
            "ssh://dave@box",
        ] {
            let (code, got) = client.json(&["pair", "ssh", "--json", "--", bad]);
            assert_eq!(code, 255, "{bad}: {got}");
            assert_eq!(got["error"]["code"], "INVALID_ARGUMENT", "{bad}: {got}");
        }
        assert_eq!(fake.calls().len(), 0, "ssh must not run for a refused dest");
        assert!(
            !client.config_dir().join("identity").exists(),
            "an invalid command line must not create the identity"
        );
        assert!(!trust_file_exists(&client));
    }

    #[test]
    fn ssh_bootstrap_other_invalid_arguments_run_no_ssh() {
        let fake = FakeSsh::new();
        let client = client_for(&fake);
        for args in [
            vec!["box", "--role", "root"],
            vec!["box", "--as", "a/b"],
            vec!["box", "--remote-as", "a/b"],
            vec!["box", "--address", ""],
            vec!["box", "--remote-qsh", "bad\u{7}word"],
        ] {
            let (code, got) = pair_json(&client, &args);
            assert_eq!(code, 255, "{args:?}: {got}");
            assert_eq!(got["error"]["code"], "INVALID_ARGUMENT", "{args:?}: {got}");
        }
        assert_eq!(fake.calls().len(), 0);
    }

    /// `--reverse` and `--to` go together, and `--address` is the forward
    /// direction's dial address (ADR-0044 decision 1): every misuse is
    /// refused before the identity is made and before ssh runs.
    #[test]
    fn ssh_bootstrap_reverse_flag_misuse_runs_no_ssh() {
        let fake = FakeSsh::new();
        let client = Sandbox::new();
        std::fs::write(
            client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
        )
        .unwrap();
        for args in [
            vec!["box", "--reverse"],
            vec!["box", "--to", "hub.example:4433"],
            vec!["box", "--reverse", "--to", ""],
            vec![
                "box",
                "--reverse",
                "--to",
                "hub.example:4433",
                "--address",
                "10.0.0.2:4433",
            ],
        ] {
            let (code, got) = pair_json(&client, &args);
            assert_eq!(code, 255, "{args:?}: {got}");
            assert_eq!(got["error"]["code"], "INVALID_ARGUMENT", "{args:?}: {got}");
        }
        assert_eq!(
            fake.calls().len(),
            0,
            "ssh must not run for a refused flag set"
        );
        assert!(
            !client.config_dir().join("identity").exists(),
            "an invalid command line must not create the identity"
        );
        assert!(!trust_file_exists(&client));
    }

    /// `--as` names the pin, so a `Host` alias that is not a valid pin name
    /// is fine as the ssh operand once `--as` is given.
    #[test]
    fn ssh_bootstrap_as_makes_a_non_label_host_alias_usable() {
        let mut fake = FakeSsh::new();
        fake.exit(2);
        let client = client_for(&fake);
        let (_, got) = pair_json(&client, &["box/alias"]);
        assert_eq!(got["error"]["code"], "INVALID_ARGUMENT", "{got}");
        assert_eq!(
            fake.calls().len(),
            0,
            "the default pin name is checked first"
        );
        let (_, got) = pair_json(&client, &["box/alias", "--as", "prod"]);
        // Past validation: it reached the (failing) ssh call.
        assert_eq!(
            got["error"]["details"]["reason"], "remote_qsh_too_old",
            "{got}"
        );
        assert_eq!(fake.calls().len(), 2);
    }

    #[test]
    fn ssh_bootstrap_the_real_caller_passes_batch_mode_in_machine_mode() {
        let mut fake = FakeSsh::new();
        fake.exit(2);
        let client = client_for(&fake);
        let _ = pair_json(&client, &["dave@box"]);
        let calls = fake.calls();
        let responder = calls.last().expect("the responder call");
        assert!(
            responder.windows(2).any(|w| w == ["-o", "BatchMode=yes"]),
            "{responder:?}"
        );
        // The tests run without a terminal on stdin, so human mode is batch too.
        let fake2 = {
            let mut f = FakeSsh::new();
            f.exit(2);
            f
        };
        let client = client_for(&fake2);
        let out = client.qsh(&["pair", "ssh", "dave@box"]);
        assert_eq!(exit_code(&out), 255);
        let calls = fake2.calls();
        assert!(
            calls
                .last()
                .unwrap()
                .windows(2)
                .any(|w| w == ["-o", "BatchMode=yes"]),
            "{calls:?}"
        );
        // The human renderer writes the failure to stderr and nothing to stdout.
        assert!(out.stdout.is_empty(), "{:?}", out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("UNSUPPORTED"), "{stderr}");
    }
}

// ---------------------------------------------------------------------
// qsh pair ssh end to end (the remote half is `pair ssh-respond`)
// ---------------------------------------------------------------------

/// Two sandboxes, a real `qsh serve` on the remote one, and a fake `ssh`
/// that runs the remote's `qsh pair ssh-respond` against the remote tree.
/// This is everything `qsh pair ssh` touches except OpenSSH itself.
pub(crate) mod pair {
    use super::*;
    use crate::common::{Sandbox, ServeGuard, exit_code};
    use serde_json::Value;
    use std::path::{Path, PathBuf};

    const QSH: &str = env!("CARGO_BIN_EXE_qsh");

    pub(crate) struct World {
        pub client: Sandbox,
        pub remote: Sandbox,
        pub serve: ServeGuard,
        pub fake: FakeSsh,
    }

    impl World {
        pub fn new() -> Self {
            Self::with_client(Sandbox::initialized())
        }

        pub fn with_client(client: Sandbox) -> Self {
            let remote = Sandbox::initialized();
            let serve = ServeGuard::start(&remote);
            // What the responder reports as the serve bind.
            std::fs::write(
                remote.config_dir().join("config.toml"),
                format!("[serve]\nbind = \"{}\"\n", serve.addr()),
            )
            .unwrap();
            let mut fake = FakeSsh::new();
            fake.run_local_responder(Path::new(QSH), remote.config_dir(), remote.state_dir());
            std::fs::write(
                client.config_dir().join("config.toml"),
                format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
            )
            .unwrap();
            Self {
                client,
                remote,
                serve,
                fake,
            }
        }

        /// `qsh pair ssh <args> --json` on the client.
        pub fn pair(&self, args: &[&str]) -> (i32, Value) {
            let mut argv = vec!["pair", "ssh"];
            argv.extend_from_slice(args);
            argv.push("--json");
            self.client.json(&argv)
        }
    }

    pub(crate) fn trust_file(sandbox: &Sandbox) -> PathBuf {
        sandbox.config_dir().join("trust.toml")
    }

    pub(crate) fn trust_bytes(sandbox: &Sandbox) -> Vec<u8> {
        std::fs::read(trust_file(sandbox)).unwrap_or_default()
    }

    pub(crate) fn store(sandbox: &Sandbox) -> qsh_core::TrustStore {
        qsh_core::TrustStore::load(&trust_file(sandbox)).unwrap()
    }

    /// A well-formed fingerprint nobody owns the key of.
    pub(crate) fn other_fingerprint(byte: u8) -> String {
        use base64::Engine as _;
        format!(
            "sha256:{}",
            base64::engine::general_purpose::STANDARD.encode([byte; 32])
        )
    }

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap().flatten() {
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_dir(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    /// Every file under `dir`, relative, with its bytes.
    fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    let rel = path.strip_prefix(root).unwrap().display().to_string();
                    out.insert(rel, std::fs::read(&path).unwrap_or_default());
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(dir, dir, &mut out);
        out
    }

    #[test]
    fn ssh_bootstrap_pins_both_sides_and_connects() {
        let w = World::new();
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{got}");
        let data = &got["data"];
        assert_eq!(got["command"], "pair.ssh");
        assert_eq!(data["direction"], "forward");
        assert_eq!(data["verified"], true, "{got}");
        assert!(data.get("verify_error").is_none(), "{got}");
        assert_eq!(data["created"], true);
        assert_eq!(data["identity_created"], false);
        assert_eq!(data["ssh_proxied"], false);
        assert_eq!(data["peer"]["name"], "box");
        assert_eq!(data["peer"]["address"], w.serve.addr());
        assert_eq!(data["peer"]["fingerprint"], w.remote.fingerprint());
        assert_eq!(data["remote"]["name"], "laptop");
        assert_eq!(data["remote"]["created"], true);
        assert_eq!(data["remote"]["role"], "full");

        // This machine pins the remote by address; the remote pins this
        // machine inbound-only under the name it was asked to use.
        let local = store(&w.client);
        let pin = local.find("box").expect("the local pin");
        assert_eq!(pin.fingerprint, w.remote.fingerprint());
        assert_eq!(pin.address, w.serve.addr());
        let remote_pin = store(&w.remote)
            .find("laptop")
            .cloned()
            .expect("the remote pin");
        assert_eq!(remote_pin.fingerprint, w.client.fingerprint());
        assert_eq!(remote_pin.address, "");
        assert_eq!(remote_pin.role.as_deref(), Some("full"));

        // The pin works: `qsh exec box` reaches the remote serve.
        let (program, expected) = if cfg!(windows) {
            (["cmd", "/c", "echo paired"], "cGFpcmVkDQo=")
        } else {
            (["sh", "-c", "echo paired"], "cGFpcmVkCg==")
        };
        let mut argv = vec!["exec", "box", "--json", "--"];
        argv.extend(program);
        let (code, exec) = w.client.json(&argv);
        assert_eq!(code, 0, "{exec}");
        assert_eq!(exec["data"]["stdout_b64"], expected, "{exec}");
    }

    #[test]
    fn ssh_bootstrap_role_flag_sets_the_remote_role() {
        let w = World::new();
        let (code, got) = w.pair(&["box", "--remote-as", "laptop", "--role", "exec"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["remote"]["role"], "exec");
        assert_eq!(
            store(&w.remote).find("laptop").unwrap().role.as_deref(),
            Some("exec")
        );
        // The remote audit record names the role it wrote.
        let audits: Vec<_> = w
            .remote
            .audit_records()
            .into_iter()
            .filter(|r| r["action"] == "pair.ssh_respond")
            .collect();
        assert_eq!(audits.len(), 1, "{audits:?}");
        assert_eq!(audits[0]["role"], "exec");
    }

    #[test]
    fn ssh_bootstrap_local_pin_has_explicit_role_none() {
        let w = World::new();
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["peer"]["role"], "none", "{got}");
        assert_eq!(
            store(&w.client).find("box").unwrap().role.as_deref(),
            Some("none")
        );
        // The `none` pin grants nothing: this machine's own serve would deny
        // the remote every action (default-deny, ADR-0045 decision 8).
        let (code, checked) = w.client.json(&[
            "acl",
            "check",
            "--principal",
            "device:box",
            "--action",
            "exec.run",
            "--json",
        ]);
        assert_eq!(code, 0, "{checked}");
        assert_eq!(checked["data"]["decision"], "deny", "{checked}");
        // A `none` pin writes no audit record (ADR-0045 decision 8).
        assert!(
            w.client
                .audit_records()
                .iter()
                .all(|r| r["action"] != "trust.add"),
            "{:?}",
            w.client.audit_records()
        );
    }

    #[test]
    fn ssh_bootstrap_does_not_widen_an_existing_roleless_pin() {
        let w = World::new();
        // A pin written before roles existed: no `role` key.
        {
            let path = trust_file(&w.remote);
            let mut store = qsh_core::TrustStore::load(&path).unwrap();
            let fp: qsh_core::Fingerprint = w.client.fingerprint().parse().unwrap();
            store.add_peer("laptop", None, fp, "2026-01-01T00:00:00Z".into());
            store.save(&path).unwrap();
        }
        let before = trust_bytes(&w.remote);
        let (code, got) = w.pair(&["box", "--remote-as", "laptop", "--role", "full"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["remote"]["created"], false, "{got}");
        assert!(got["data"]["remote"].get("role").is_none(), "{got}");
        assert_eq!(
            trust_bytes(&w.remote),
            before,
            "an existing pin is never widened"
        );
    }

    #[test]
    fn ssh_bootstrap_never_overwrites_a_pin_with_a_different_fingerprint() {
        // Local side: `box` is pinned here under another identity.
        let w = World::new();
        w.client
            .trust_add("box", Some("10.0.0.9:4433"), &other_fingerprint(7));
        let local_before = trust_bytes(&w.client);
        let remote_before = snapshot(w.remote.config_dir());
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["code"], "SESSION_CONFLICT", "{got}");
        assert_eq!(got["error"]["details"]["reason"], "pin_conflict");
        assert_eq!(got["error"]["details"]["side"], "local");
        assert_eq!(trust_bytes(&w.client), local_before);
        assert_eq!(
            snapshot(w.remote.config_dir()),
            remote_before,
            "nothing on the remote"
        );

        // Remote side: `laptop` is pinned there under another identity.
        let w = World::new();
        w.remote.trust_add("laptop", None, &other_fingerprint(9));
        let remote_before = trust_bytes(&w.remote);
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["code"], "SESSION_CONFLICT", "{got}");
        assert_eq!(got["error"]["details"]["side"], "remote");
        assert_eq!(
            got["error"]["details"]["pinned_fingerprint"],
            other_fingerprint(9)
        );
        assert_eq!(trust_bytes(&w.remote), remote_before);
        assert!(!trust_file(&w.client).exists(), "nothing on this machine");

        // The remote identity already pinned here under another name.
        let w = World::new();
        w.client
            .trust_add("old-box", Some("10.0.0.9:4433"), &w.remote.fingerprint());
        let local_before = trust_bytes(&w.client);
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["details"]["pinned_name"], "old-box", "{got}");
        assert_eq!(trust_bytes(&w.client), local_before);
        assert!(!trust_file(&w.remote).exists());
    }

    #[test]
    fn ssh_bootstrap_writes_nothing_when_the_remote_cannot_respond() {
        // (what the fake does, error code, reason)
        let hello_versions = |versions: Vec<u32>| {
            BootstrapLine::Hello(Hello {
                versions,
                qsh_version: "9.9.9".into(),
                status: HelloStatus::Ready,
                fingerprint: Some(other_fingerprint(3)),
                serve_bind: Some("127.0.0.1:4433".into()),
                serve_listening: Some(true),
            })
            .encode_line()
            .unwrap()
            .into_bytes()
        };
        type Setup = Box<dyn Fn(&mut FakeSsh)>;
        let cases: Vec<(&str, Setup, &[&str], &str, &str)> = vec![
            (
                // A shell that cannot find the program answers 127.
                "127",
                Box::new(|f| {
                    f.respond_through_shell();
                }),
                &["--remote-qsh", "/nonexistent/qsh"],
                "REMOTE_ERROR",
                "remote_qsh_missing",
            ),
            (
                "exit 2",
                Box::new(|f| {
                    f.exit(2);
                }),
                &[],
                "UNSUPPORTED",
                "remote_qsh_too_old",
            ),
            (
                "no common version",
                Box::new(move |f| {
                    f.script(&hello_versions(vec![99])).exit(0);
                }),
                &[],
                "UNSUPPORTED",
                "bootstrap_version",
            ),
        ];
        for (label, setup, extra, code_name, reason) in cases {
            // The process exit status of `cmd.exe /C <unknown program>` is 1
            // (the 9009 is the ERRORLEVEL inside the shell), so a real
            // `cmd.exe` cannot stand in for the remote shell here. The 9009
            // mapping is pinned by
            // `ssh_bootstrap_a_remote_cmd_exe_9009_is_a_missing_qsh_and_writes_nothing`.
            if cfg!(windows) && label == "127" {
                continue;
            }
            let mut w = World::new();
            // The 127 row keeps the fake that runs the real responder; the
            // others use one that only prints what the row scripts.
            if label != "127" {
                w.fake = FakeSsh::new();
                std::fs::write(
                    w.client.config_dir().join("config.toml"),
                    format!("[ssh]\nprogram = '{}'\n", w.fake.program().display()),
                )
                .unwrap();
            }
            setup(&mut w.fake);
            let mut args = vec!["box", "--remote-as", "laptop"];
            args.extend_from_slice(extra);
            let (code, got) = w.pair(&args);
            assert_eq!(code, 255, "{label}: {got}");
            assert_eq!(got["error"]["code"], code_name, "{label}: {got}");
            assert_eq!(got["error"]["details"]["reason"], reason, "{label}: {got}");
            assert!(!trust_file(&w.client).exists(), "{label}");
            assert!(!trust_file(&w.remote).exists(), "{label}");
        }

        // The remote has no identity: reported, and not created.
        let mut w = World::new();
        let bare = Sandbox::new();
        w.fake
            .run_local_responder(Path::new(QSH), bare.config_dir(), bare.state_dir());
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["code"], "REMOTE_ERROR", "{got}");
        assert_eq!(got["error"]["details"]["reason"], "remote_not_initialized");
        assert!(!bare.config_dir().join("identity").exists());
        assert!(!trust_file(&bare).exists());
        assert!(!trust_file(&w.client).exists());
    }

    /// The remote says `hello` and then never answers the `commit`: the
    /// client gives up after the message deadline and neither side has a
    /// pin. Runs the real 30 s deadline, so it is a test of its own.
    #[test]
    fn ssh_bootstrap_writes_nothing_when_the_commit_is_never_answered() {
        let mut w = World::new();
        w.fake = FakeSsh::new();
        std::fs::write(
            w.client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n", w.fake.program().display()),
        )
        .unwrap();
        let hello = BootstrapLine::Hello(Hello {
            versions: vec![1],
            qsh_version: "9.9.9".into(),
            status: HelloStatus::Ready,
            fingerprint: Some(other_fingerprint(3)),
            serve_bind: Some("127.0.0.1:4433".into()),
            serve_listening: Some(true),
        })
        .encode_line()
        .unwrap()
        .into_bytes();
        w.fake.script(&hello).hang();
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["code"], "TIMEOUT", "{got}");
        assert_eq!(
            got["error"]["details"]["reason"], "bootstrap_timeout",
            "{got}"
        );
        assert!(!trust_file(&w.client).exists());
        assert!(!trust_file(&w.remote).exists());
    }

    #[test]
    fn ssh_bootstrap_reports_the_actual_remote_role_when_an_existing_pin_differs() {
        let w = World::new();
        w.remote
            .trust_add_with_role("laptop", None, &w.client.fingerprint(), "read-only");
        let before = trust_bytes(&w.remote);
        let (code, got) = w.pair(&["box", "--remote-as", "laptop", "--role", "full"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["remote"]["created"], false);
        assert_eq!(got["data"]["remote"]["role"], "read-only", "{got}");
        assert_eq!(trust_bytes(&w.remote), before, "the role is not changed");

        // Human mode says so on stderr.
        let w2 = World::new();
        w2.remote
            .trust_add_with_role("laptop", None, &w2.client.fingerprint(), "read-only");
        let out = w2.client.qsh(&[
            "pair",
            "ssh",
            "box",
            "--remote-as",
            "laptop",
            "--role",
            "full",
        ]);
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("read-only"), "{stderr}");
    }

    #[test]
    fn ssh_bootstrap_skips_untagged_stdout_and_never_logs_it() {
        let mut w = World::new();
        w.fake
            .run_local_responder(Path::new(QSH), w.remote.config_dir(), w.remote.state_dir())
            .script(b"Welcome to box\nexport TOKEN=hunter2-secret\n");
        let mut command =
            w.client
                .command(&["pair", "ssh", "box", "--remote-as", "laptop", "--json"]);
        let output = command
            .env("QSH_LOG", "trace")
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert_eq!(
            exit_code(&output),
            0,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!all.contains("hunter2-secret"), "rc output leaked: {all}");
        assert!(!all.contains("Welcome to box"), "rc output leaked: {all}");

        // More than 64 KiB of such lines before any hello: a protocol error,
        // with nothing written.
        let mut w = World::new();
        let noise: Vec<u8> = (0..2000)
            .flat_map(|n| format!("noise line {n} {}\n", "x".repeat(60)).into_bytes())
            .collect();
        assert!(noise.len() > 64 * 1024);
        w.fake
            .run_local_responder(Path::new(QSH), w.remote.config_dir(), w.remote.state_dir())
            .script(&noise);
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(
            got["error"]["details"]["reason"], "bootstrap_protocol",
            "{got}"
        );
        assert!(!trust_file(&w.client).exists());
        assert!(!trust_file(&w.remote).exists());
    }

    #[test]
    fn ssh_bootstrap_reports_identity_mismatch_when_serve_runs_another_identity() {
        let w = World::new();
        // Another machine answers on the address ssh's remote reported.
        let other = Sandbox::initialized();
        let other_serve = ServeGuard::start(&other);
        let (code, got) = w.pair(&[
            "box",
            "--remote-as",
            "laptop",
            "--address",
            other_serve.addr(),
        ]);
        assert_eq!(code, 0, "the pins stand: {got}");
        assert_eq!(got["data"]["verified"], false, "{got}");
        assert_eq!(
            got["data"]["verify_error"]["details"]["reason"], "remote_serve_identity_mismatch",
            "{got}"
        );
        // Both pins were written, with the address the user asked for.
        assert_eq!(
            store(&w.client).find("box").unwrap().address,
            other_serve.addr()
        );
        assert!(store(&w.remote).find("laptop").is_some());
    }

    /// The serve at the address runs with the ssh account's identity but
    /// another trust store (another config directory in a real deployment
    /// would change the identity too; here only the trust differs), so it
    /// does not know this device and closes right after the handshake.
    #[test]
    fn ssh_bootstrap_reports_a_serve_that_does_not_know_this_device() {
        let mut w = World::new();
        // The account the responder runs as: the same identity files, its own
        // trust store.
        let account = Sandbox::new();
        copy_dir(
            &w.remote.config_dir().join("identity"),
            &account.config_dir().join("identity"),
        );
        std::fs::write(
            account.config_dir().join("config.toml"),
            format!("[serve]\nbind = \"{}\"\n", w.serve.addr()),
        )
        .unwrap();
        w.fake
            .run_local_responder(Path::new(QSH), account.config_dir(), account.state_dir());
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "the pins stand: {got}");
        assert_eq!(got["data"]["verified"], false, "{got}");
        assert_eq!(
            got["data"]["verify_error"]["details"]["reason"], "remote_serve_rejected_this_device",
            "{got}"
        );
        assert!(store(&account).find("laptop").is_some());
        assert!(!trust_file(&w.remote).exists() || store(&w.remote).find("laptop").is_none());
    }

    #[test]
    fn ssh_bootstrap_unverified_when_remote_serve_is_not_listening() {
        let w = World::new();
        let free = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let spec = free.local_addr().unwrap().to_string();
        drop(free);
        std::fs::write(
            w.remote.config_dir().join("config.toml"),
            format!("[serve]\nbind = \"{spec}\"\n"),
        )
        .unwrap();
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["verified"], false, "{got}");
        assert_eq!(
            got["data"]["verify_error"]["details"]["reason"], "remote_serve_not_listening",
            "{got}"
        );
        assert_eq!(got["data"]["peer"]["address"], spec);
        assert!(store(&w.client).find("box").is_some());
        assert!(store(&w.remote).find("laptop").is_some());
    }

    #[test]
    fn ssh_bootstrap_initializes_a_missing_local_identity_once() {
        let w = World::with_client(Sandbox::new());
        assert!(!w.client.config_dir().join("identity").exists());
        let (code, first) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{first}");
        assert_eq!(first["data"]["identity_created"], true, "{first}");
        let fingerprint = w.client.fingerprint();
        assert_eq!(
            store(&w.remote).find("laptop").unwrap().fingerprint,
            fingerprint
        );

        // A rerun converges: same identity, nothing new.
        let local_before = trust_bytes(&w.client);
        let remote_before = trust_bytes(&w.remote);
        let (code, second) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{second}");
        assert_eq!(second["data"]["identity_created"], false);
        assert_eq!(second["data"]["created"], false);
        assert_eq!(second["data"]["remote"]["created"], false);
        assert_eq!(w.client.fingerprint(), fingerprint);
        assert_eq!(trust_bytes(&w.client), local_before);
        assert_eq!(trust_bytes(&w.remote), remote_before);
    }

    #[test]
    fn ssh_bootstrap_never_writes_hosts_config_or_acl_files() {
        let w = World::new();
        let client_before = snapshot(w.client.config_dir());
        let remote_before = snapshot(w.remote.config_dir());
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{got}");
        for (label, dir, before) in [
            ("client", w.client.config_dir(), client_before),
            ("remote", w.remote.config_dir(), remote_before),
        ] {
            let after = snapshot(dir);
            let changed: Vec<&String> = after
                .iter()
                .filter(|(name, bytes)| before.get(*name) != Some(*bytes))
                .map(|(name, _)| name)
                // The advisory lock file next to the trust store.
                .filter(|name| !name.ends_with(".lock"))
                .collect();
            assert_eq!(
                changed,
                ["trust.toml"],
                "{label}: only the trust store changes"
            );
            for forbidden in ["hosts.toml", "acl.toml", "config.toml"] {
                assert_eq!(
                    after.get(forbidden),
                    before.get(forbidden),
                    "{label}: {forbidden}"
                );
            }
        }
    }

    #[test]
    fn ssh_bootstrap_envelope_is_the_only_stdout_line() {
        let w = World::new();
        for mode in ["--json", "--jsonl"] {
            // At the loudest verbosity: diagnostics stay on stderr.
            let out = w
                .client
                .qsh(&["pair", "ssh", "box", "--remote-as", "laptop", "-vvv", mode]);
            assert_eq!(
                exit_code(&out),
                0,
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let text = String::from_utf8(out.stdout).unwrap();
            assert_eq!(text.lines().count(), 1, "{mode}: {text:?}");
            let value: Value = serde_json::from_str(text.trim()).unwrap();
            assert_eq!(value["command"], "pair.ssh");
            assert_eq!(value["ok"], true);
        }
    }

    #[test]
    fn ssh_bootstrap_human_mode_prints_both_pins_and_the_verified_line() {
        let w = World::new();
        let out = w
            .client
            .qsh(&["pair", "ssh", "box", "--remote-as", "laptop"]);
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 3, "{stdout}");
        // This machine's pin names the remote identity, fingerprint included.
        assert!(
            lines[0].starts_with(&format!("pinned box ({}) [", w.remote.fingerprint())),
            "{stdout}"
        );
        assert_eq!(lines[1], "remote: pinned laptop role full", "{stdout}");
        assert_eq!(lines[2], "verified", "{stdout}");
    }

    #[test]
    fn pair_ssh_never_appears_as_a_control_message_wire_variant() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../qsh-proto/proto/qsh/wire/v1.proto"
        ))
        .expect("read v1.proto");
        assert!(source.contains("message "), "v1.proto looks empty");
        let lower = source.to_lowercase();
        assert!(
            !lower.contains("pairssh")
                && !lower.contains("pair_ssh")
                && !lower.contains("pair.ssh"),
            "the wire proto must never gain a pair.ssh message"
        );
    }

    /// The bootstrapped pin is an ordinary forward route: exec, a file
    /// round trip and a session all work through it. Unix only because the
    /// commands are `sh -c`; the Windows twin below runs the same three
    /// operations with `cmd` programs.
    #[cfg(unix)]
    #[test]
    fn bootstrapped_forward_route_passes_the_attach_exec_cp_suite() {
        let w = World::new();
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{got}");

        let (code, exec) = w.client.json(&[
            "exec",
            "box",
            "--json",
            "--",
            "sh",
            "-c",
            "echo out; exit 3",
        ]);
        assert_eq!(code, 3, "{exec}");

        let work = tempfile::tempdir().unwrap();
        let src = work.path().join("src.txt");
        std::fs::write(&src, b"through the bootstrapped pin\n").unwrap();
        let dst = work.path().join("dst.txt");
        let remote_dst = format!("box:{}", dst.display());
        let (code, put) = w
            .client
            .json(&["cp", "--json", src.to_str().unwrap(), &remote_dst]);
        assert_eq!(code, 0, "{put}");
        assert_eq!(std::fs::read(&dst).unwrap(), std::fs::read(&src).unwrap());
        let back = work.path().join("back.txt");
        let (code, get) = w
            .client
            .json(&["cp", "--json", &remote_dst, back.to_str().unwrap()]);
        assert_eq!(code, 0, "{get}");
        assert_eq!(std::fs::read(&back).unwrap(), std::fs::read(&src).unwrap());

        let (code, opened) = w.client.json(&[
            "session",
            "open",
            "box",
            "--json",
            "--",
            "sh",
            "-c",
            "echo attached",
        ]);
        assert_eq!(code, 0, "{opened}");
        let session = opened["data"]["session_ref"].as_str().unwrap().to_string();
        let (code, listed) = w.client.json(&["session", "get", &session, "--json"]);
        assert_eq!(code, 0, "{listed}");
    }

    /// The route the pair command just wrote, as the shared Windows cases see
    /// it: the client's sandbox, the name it pinned, the remote's own tree.
    #[cfg(windows)]
    struct Bootstrapped<'a>(&'a World);

    #[cfg(windows)]
    impl crate::route_cases::Route for Bootstrapped<'_> {
        fn client(&self) -> &Sandbox {
            &self.0.client
        }

        fn host(&self) -> &str {
            "box"
        }

        fn host_sandbox(&self) -> &Sandbox {
            &self.0.remote
        }
    }

    /// The Windows twin of the suite above, with the Windows responder on the
    /// remote: the pins the explicit command wrote are all the forward route
    /// needs, and the shared exec and `qsh cp` cases pass through them. The
    /// interactive attach over a real console is `windows_attach.rs`.
    #[cfg(windows)]
    #[test]
    fn bootstrapped_forward_route_passes_the_exec_cp_suite_on_windows() {
        let w = World::new();
        let (code, got) = w.pair(&["box", "--remote-as", "laptop"]);
        assert_eq!(code, 0, "{got}");

        let route = Bootstrapped(&w);
        crate::route_cases::exec_round_trip(&route);
        crate::route_cases::cp_round_trip(&route);
        crate::route_cases::pty_session_runs_a_command(&route);
    }
}

// ---------------------------------------------------------------------
// qsh pair ssh --reverse --to, this machine's side (ADR-0044 decision 22)
// ---------------------------------------------------------------------

/// The controller's half of the reverse pairing against a scripted remote,
/// so it runs wherever the client does: the fake `ssh` prints the remote's
/// `hello` and its `pinned` answer, and records what the client sent. The
/// remote's own half is `pair_reverse` below.
mod pair_reverse_local {
    use super::*;
    use crate::common::{ListenGuard, Sandbox, exit_code};
    use qsh_proto::ssh_bootstrap::{BootstrapResult, ResultStatus, parse_ssh_bootstrap_line};

    const HUB: &str = "hub";
    const BOX: &str = "box";

    fn remote_fingerprint() -> String {
        use base64::Engine as _;
        format!(
            "sha256:{}",
            base64::engine::general_purpose::STANDARD.encode([7u8; 32])
        )
    }

    /// What a ready remote prints and answers: its `hello`, then a `pinned`
    /// result for the name the controller asked it to use.
    fn scripted_remote() -> Vec<u8> {
        let mut bytes = BootstrapLine::Hello(Hello {
            versions: vec![1],
            qsh_version: "0.0.0".into(),
            status: HelloStatus::Ready,
            fingerprint: Some(remote_fingerprint()),
            serve_bind: None,
            serve_listening: None,
        })
        .encode_line()
        .unwrap()
        .into_bytes();
        bytes.extend(
            BootstrapLine::Result(BootstrapResult {
                status: ResultStatus::Pinned,
                name: HUB.into(),
                role: Some("full".into()),
                created: true,
                code: None,
                message: None,
            })
            .encode_line()
            .unwrap()
            .into_bytes(),
        );
        bytes
    }

    #[test]
    fn pair_ssh_reverse_local_side_runs_on_windows_and_names_serve_to_as_the_next_command() {
        let controller = Sandbox::initialized();
        let listen = ListenGuard::start(&controller);
        let mut fake = FakeSsh::new();
        fake.script(&scripted_remote()).record_stdin();
        std::fs::write(
            controller.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
        )
        .unwrap();

        let out = controller.qsh(&[
            "pair",
            "ssh",
            BOX,
            "--remote-as",
            HUB,
            "--reverse",
            "--to",
            listen.addr(),
        ]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 0, "{stderr}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 3, "{stdout}");
        assert_eq!(
            lines[0],
            format!("pinned {BOX} ({}) role reverse", remote_fingerprint()),
            "{stdout}"
        );
        assert_eq!(lines[1], "remote: pinned hub role full", "{stdout}");
        assert_eq!(
            lines[2], "next, on the remote: qsh serve --to hub",
            "{stdout}"
        );
        assert!(stderr.contains("qsh serve --to hub"), "{stderr}");
        assert!(stderr.contains("qsh service install"), "{stderr}");

        // The controller's pin of the remote has no address and role
        // `reverse`; the remote was asked to dial the `--to` address.
        let trust = std::fs::read_to_string(controller.config_dir().join("trust.toml")).unwrap();
        let store =
            qsh_core::TrustStore::load(&controller.config_dir().join("trust.toml")).unwrap();
        let pin = store.find(BOX).unwrap_or_else(|| panic!("{trust}"));
        assert_eq!(pin.role.as_deref(), Some("reverse"), "{trust}");
        assert!(pin.address.is_empty(), "{trust}");
        crate::common::poll_until("ssh to record the commit", GENEROUS, || {
            (!fake.stdin_log().is_empty()).then_some(())
        });
        let log = String::from_utf8(fake.stdin_log()).unwrap();
        let BootstrapLine::Commit(sent) =
            parse_ssh_bootstrap_line(log.lines().next().unwrap().as_bytes()).unwrap()
        else {
            panic!("the client sent something other than a commit: {log}");
        };
        assert_eq!(sent.name, HUB, "{log}");
        assert_eq!(sent.role, "full", "{log}");
        assert_eq!(sent.address.as_deref(), Some(listen.addr()), "{log}");
        assert_eq!(sent.fingerprint, controller.fingerprint(), "{log}");
        assert_eq!(fake.calls().len(), 2, "{:?}", fake.calls());
    }
}

// ---------------------------------------------------------------------
// qsh pair ssh --reverse --to end to end (ADR-0044 decision 22)
// ---------------------------------------------------------------------

/// The reverse direction: the remote is the target behind NAT, this machine
/// is the controller whose `qsh listen` it registers with. The fake `ssh`
/// runs the real responder against the target's tree; nothing is pre-pinned.
pub(crate) mod pair_reverse {
    use super::pair::{other_fingerprint, store, trust_bytes, trust_file};
    use super::*;
    use crate::common::{ListenGuard, ReverseGuard, Sandbox, exit_code, hosts_array, poll_until};
    use serde_json::Value;
    use std::path::Path;

    const QSH: &str = env!("CARGO_BIN_EXE_qsh");

    /// The name the target pins the controller under, and the name
    /// `qsh serve --to` takes there.
    const HUB: &str = "hub";
    /// The name the controller pins the target under (the ssh alias).
    const BOX: &str = "box";

    pub(crate) struct World {
        pub controller: Sandbox,
        pub target: Sandbox,
        pub listen: ListenGuard,
        pub fake: FakeSsh,
    }

    impl World {
        pub fn new() -> Self {
            let controller = Sandbox::initialized();
            let target = Sandbox::initialized();
            let listen = ListenGuard::start(&controller);
            let mut fake = FakeSsh::new();
            fake.run_local_responder(Path::new(QSH), target.config_dir(), target.state_dir());
            write_client_config(&controller, &fake, "");
            Self {
                controller,
                target,
                listen,
                fake,
            }
        }

        /// `qsh pair ssh box --remote-as hub <extra> --reverse --to <listen> --json`.
        pub fn pair(&self, extra: &[&str]) -> (i32, Value) {
            let mut argv = vec!["pair", "ssh", BOX, "--remote-as", HUB];
            argv.extend_from_slice(extra);
            argv.extend_from_slice(&["--reverse", "--to", self.listen.addr(), "--json"]);
            self.controller.json(&argv)
        }
    }

    fn write_client_config(client: &Sandbox, fake: &FakeSsh, extra: &str) {
        std::fs::write(
            client.config_dir().join("config.toml"),
            format!("[ssh]\nprogram = '{}'\n{extra}", fake.program().display()),
        )
        .unwrap();
    }

    fn pair_audits(sandbox: &Sandbox) -> Vec<Value> {
        sandbox
            .audit_records()
            .into_iter()
            .filter(|record| record["action"] == "pair.ssh")
            .collect()
    }

    #[test]
    fn ssh_bootstrap_reverse_pins_listener_full_with_address_and_target_reverse_without() {
        let w = World::new();
        let (code, got) = w.pair(&[]);
        assert_eq!(code, 0, "{got}");
        let data = &got["data"];
        assert_eq!(got["command"], "pair.ssh");
        assert_eq!(data["direction"], "reverse", "{got}");
        // No dial was made and none was skipped: unverified, and no reason.
        assert_eq!(data["verified"], false, "{got}");
        assert!(data.get("verify_error").is_none(), "{got}");
        assert_eq!(data["next_command"], "qsh serve --to hub", "{got}");
        assert_eq!(data["created"], true);
        assert_eq!(data["identity_created"], false);
        assert_eq!(data["peer"]["name"], BOX);
        assert_eq!(data["peer"]["address"], "", "{got}");
        assert_eq!(data["peer"]["role"], "reverse", "{got}");
        assert_eq!(data["peer"]["fingerprint"], w.target.fingerprint());
        assert_eq!(data["remote"]["name"], HUB);
        assert_eq!(data["remote"]["created"], true);
        assert_eq!(data["remote"]["role"], "full");

        // The target pins this machine by the --to address with `full`; this
        // machine pins the target without an address and with `reverse`.
        let target_pin = store(&w.target).find(HUB).cloned().expect("target pin");
        assert_eq!(target_pin.fingerprint, w.controller.fingerprint());
        assert_eq!(target_pin.address, w.listen.addr());
        assert_eq!(target_pin.role.as_deref(), Some("full"));
        let local_pin = store(&w.controller).find(BOX).cloned().expect("local pin");
        assert_eq!(local_pin.fingerprint, w.target.fingerprint());
        assert_eq!(local_pin.address, "");
        assert_eq!(local_pin.role.as_deref(), Some("reverse"));

        // ssh ran twice (`-G` and the responder), and the target runs
        // nothing: no `[serve].to` and no config file written there.
        assert_eq!(w.fake.calls().len(), 2, "{:?}", w.fake.calls());
        assert!(
            !w.target.config_dir().join("config.toml").exists(),
            "nothing is written to the target's config"
        );

        // `--role` still chooses the target's pin; this machine's stays `reverse`.
        let w = World::new();
        let (code, got) = w.pair(&["--role", "exec"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["remote"]["role"], "exec", "{got}");
        assert_eq!(got["data"]["peer"]["role"], "reverse", "{got}");

        // The port is filled in like `trust add --address` does.
        let w = World::new();
        let host = w.listen.addr().rsplit_once(':').unwrap().0.to_string();
        let (code, got) = w.controller.json(&[
            "pair",
            "ssh",
            BOX,
            "--remote-as",
            HUB,
            "--reverse",
            "--to",
            &host,
            "--json",
        ]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(
            store(&w.target).find(HUB).unwrap().address,
            format!("{host}:4433")
        );
    }

    #[test]
    fn ssh_bootstrap_reverse_flag_misuse_runs_no_ssh_here_too() {
        let w = World::new();
        let to = w.listen.addr();
        for args in [
            vec!["pair", "ssh", BOX, "--reverse"],
            vec!["pair", "ssh", BOX, "--to", to],
            vec!["pair", "ssh", BOX, "--reverse", "--to", to, "--address", to],
        ] {
            let mut argv = args.clone();
            argv.push("--json");
            let (code, got) = w.controller.json(&argv);
            assert_eq!(code, 255, "{args:?}: {got}");
            assert_eq!(got["error"]["code"], "INVALID_ARGUMENT", "{args:?}: {got}");
        }
        assert_eq!(w.fake.calls().len(), 0);
        assert!(!trust_file(&w.controller).exists());
        assert!(!trust_file(&w.target).exists());
    }

    #[test]
    fn ssh_bootstrap_reverse_local_reverse_role_leaves_an_audit_record_and_needs_it() {
        let w = World::new();
        let (code, got) = w.pair(&[]);
        assert_eq!(code, 0, "{got}");
        let records = pair_audits(&w.controller);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0]["principal"], "device:box");
        assert_eq!(records[0]["resource"], BOX);
        assert_eq!(records[0]["role"], "reverse");
        // The target's audit record is the responder's, under its own action.
        assert_eq!(
            w.target
                .audit_records()
                .iter()
                .filter(|r| r["action"] == "pair.ssh_respond")
                .count(),
            1
        );

        // An audit log that cannot be appended to: no record, no local pin.
        // The target's pin already stands, so the message says to run again.
        let w = World::new();
        let blocked = w.controller.state_dir().join("audit-is-a-directory");
        std::fs::create_dir_all(&blocked).unwrap();
        write_client_config(
            &w.controller,
            &w.fake,
            &format!("[audit]\npath = '{}'\n", blocked.display()),
        );
        let (code, got) = w.pair(&[]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["code"], "INTERNAL", "{got}");
        assert!(
            got["error"]["message"]
                .as_str()
                .unwrap()
                .contains("run this command again"),
            "{got}"
        );
        assert!(
            !trust_file(&w.controller).exists(),
            "no audit record, no local pin"
        );
        assert!(
            store(&w.target).find(HUB).is_some(),
            "the remote pin stands"
        );

        // Once the log works, the same command converges.
        write_client_config(&w.controller, &w.fake, "");
        let (code, got) = w.pair(&[]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["created"], true, "{got}");
        assert_eq!(got["data"]["remote"]["created"], false, "{got}");
        assert_eq!(pair_audits(&w.controller).len(), 1);
    }

    #[test]
    fn ssh_bootstrap_reverse_updates_only_the_address_of_an_existing_remote_pin() {
        let w = World::new();
        // The target already pins this machine: inbound only, `exec`.
        w.target
            .trust_add_with_role("old-hub", None, &w.controller.fingerprint(), "exec");
        let (code, got) = w.pair(&["--role", "full"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["remote"]["created"], false, "{got}");
        assert_eq!(got["data"]["remote"]["name"], "old-hub", "{got}");
        assert_eq!(got["data"]["remote"]["role"], "exec", "{got}");
        let target_store = store(&w.target);
        assert_eq!(target_store.peers().len(), 1, "no second pin");
        let pin = target_store.find("old-hub").unwrap();
        assert_eq!(pin.address, w.listen.addr(), "the address was filled in");
        assert_eq!(pin.role.as_deref(), Some("exec"), "the role was kept");
        assert_eq!(got["data"]["next_command"], "qsh serve --to old-hub");
        assert!(
            w.target
                .audit_records()
                .iter()
                .all(|r| r["action"] != "pair.ssh_respond"),
            "an address refresh writes no pin and no record"
        );

        // A rerun changes nothing on either side.
        let controller_before = trust_bytes(&w.controller);
        let target_before = trust_bytes(&w.target);
        let (code, got) = w.pair(&["--role", "full"]);
        assert_eq!(code, 0, "{got}");
        assert_eq!(got["data"]["created"], false, "{got}");
        assert_eq!(trust_bytes(&w.controller), controller_before);
        assert_eq!(trust_bytes(&w.target), target_before);
        assert_eq!(pair_audits(&w.controller).len(), 1, "no second record");
    }

    #[test]
    fn ssh_bootstrap_reverse_never_overwrites_a_pin_with_a_different_fingerprint() {
        // Local: `box` is pinned here under another identity.
        let w = World::new();
        w.controller
            .trust_add(BOX, Some("10.0.0.9:4433"), &other_fingerprint(7));
        let before = trust_bytes(&w.controller);
        let (code, got) = w.pair(&[]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["details"]["reason"], "pin_conflict");
        assert_eq!(got["error"]["details"]["side"], "local");
        assert_eq!(trust_bytes(&w.controller), before);
        assert!(!trust_file(&w.target).exists());

        // Remote: `hub` is pinned there under another identity.
        let w = World::new();
        w.target.trust_add(HUB, None, &other_fingerprint(9));
        let before = trust_bytes(&w.target);
        let (code, got) = w.pair(&[]);
        assert_eq!(code, 255, "{got}");
        assert_eq!(got["error"]["details"]["side"], "remote");
        assert_eq!(trust_bytes(&w.target), before);
        assert!(!trust_file(&w.controller).exists());
    }

    #[test]
    fn ssh_bootstrap_reverse_says_so_when_a_local_pin_keeps_another_role() {
        let w = World::new();
        // A forward bootstrap came first: this machine's pin is `none`.
        w.controller.trust_add_with_role(
            BOX,
            Some("10.0.0.9:4433"),
            &w.target.fingerprint(),
            "none",
        );
        let out = w.controller.qsh(&[
            "pair",
            "ssh",
            BOX,
            "--remote-as",
            HUB,
            "--reverse",
            "--to",
            w.listen.addr(),
        ]);
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("qsh trust set-role box reverse"),
            "{stderr}"
        );
        // The pin was not changed, and no audit record was written for it.
        assert_eq!(
            store(&w.controller).find(BOX).unwrap().role.as_deref(),
            Some("none")
        );
        assert!(pair_audits(&w.controller).is_empty());
    }

    #[test]
    fn ssh_bootstrap_reverse_human_mode_names_the_command_to_run_on_the_remote() {
        let w = World::new();
        let out = w.controller.qsh(&[
            "pair",
            "ssh",
            BOX,
            "--remote-as",
            HUB,
            "--reverse",
            "--to",
            w.listen.addr(),
        ]);
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 3, "{stdout}");
        // No address on this side: nothing in brackets, and the role shows.
        assert_eq!(
            lines[0],
            format!("pinned box ({}) role reverse", w.target.fingerprint()),
            "{stdout}"
        );
        assert_eq!(lines[1], "remote: pinned hub role full", "{stdout}");
        assert_eq!(
            lines[2], "next, on the remote: qsh serve --to hub",
            "{stdout}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("qsh serve --to hub"), "{stderr}");
        assert!(stderr.contains("qsh service install"), "{stderr}");
    }

    /// The pins `qsh pair ssh --reverse --to` wrote are all the reverse
    /// route has: the target registers with `qsh serve --to hub`, and the
    /// existing reverse acceptance suite (a real pty attach, detach and
    /// reattach; `qsh cp` put and get through the controller's relay;
    /// exec) passes against it unchanged. Unix only because the attach leg
    /// uses `expectrl`; the Windows twin below runs the shared exec, cp and
    /// PTY session cases, and the console attach is `windows_attach.rs`.
    #[cfg(unix)]
    #[test]
    fn bootstrapped_reverse_route_passes_the_forward_attach_exec_cp_suite() {
        let w = World::new();
        let (code, got) = w.pair(&[]);
        assert_eq!(code, 0, "{got}");

        // The target's config is exactly what a person has after the
        // bootstrap: `qsh serve --to <name>` is the only thing run there.
        let reverse = ReverseGuard::start_serve_to(&w.target, HUB);
        let merged = poll_until(
            "the reverse registration to appear reachable",
            std::time::Duration::from_secs(20),
            || {
                let hosts = hosts_array(&w.controller);
                hosts
                    .iter()
                    .any(|h| {
                        h["name"] == BOX
                            && h["connection_mode"] == "reverse"
                            && h["state"] == "reachable"
                    })
                    .then_some(hosts)
            },
        );
        assert_eq!(merged.len(), 1, "reverse-only pin: one entry, {merged:?}");

        let (code, exec) =
            w.controller
                .json(&["exec", BOX, "--json", "--", "sh", "-c", "echo out; exit 3"]);
        assert_eq!(code, 3, "{exec}");

        // `qsh cp` put and get through the controller's relay.
        let work = tempfile::tempdir().unwrap();
        let dst = format!("{BOX}:{}", work.path().join("stored.bin").display());
        crate::cp_e2e::round_trip(work.path(), &dst, &dst, |args| {
            let mut argv = vec!["cp", "--json"];
            argv.extend_from_slice(args);
            w.controller.json(&argv)
        });

        crate::reverse_e2e::attach_detach_reattach_suite(&w.controller, BOX, &reverse);
        reverse.shut_down();
    }

    /// The reverse route the pair command just wrote, as the shared Windows
    /// cases see it: the controller's sandbox, the name it pinned the target
    /// under, the target's own tree.
    #[cfg(windows)]
    struct Bootstrapped<'a>(&'a World);

    #[cfg(windows)]
    impl crate::route_cases::Route for Bootstrapped<'_> {
        fn client(&self) -> &Sandbox {
            &self.0.controller
        }

        fn host(&self) -> &str {
            BOX
        }

        fn host_sandbox(&self) -> &Sandbox {
            &self.0.target
        }
    }

    /// The Windows twin of the suite above, with the Windows responder on the
    /// target: `qsh serve --to hub` is the only thing run there after the
    /// bootstrap, and the shared exec and `qsh cp` cases pass through the
    /// controller's relay. The interactive attach over a real console is
    /// `windows_attach.rs`.
    #[cfg(windows)]
    #[test]
    fn bootstrapped_reverse_route_passes_the_exec_cp_suite_on_windows() {
        let w = World::new();
        let (code, got) = w.pair(&[]);
        assert_eq!(code, 0, "{got}");

        let reverse = ReverseGuard::start_serve_to(&w.target, HUB);
        let merged = poll_until(
            "the reverse registration to appear reachable",
            std::time::Duration::from_secs(30),
            || {
                let hosts = hosts_array(&w.controller);
                hosts
                    .iter()
                    .any(|h| {
                        h["name"] == BOX
                            && h["connection_mode"] == "reverse"
                            && h["state"] == "reachable"
                    })
                    .then_some(hosts)
            },
        );
        assert_eq!(merged.len(), 1, "reverse-only pin: one entry, {merged:?}");

        let route = Bootstrapped(&w);
        crate::route_cases::exec_round_trip(&route);
        crate::route_cases::cp_round_trip(&route);
        crate::route_cases::pty_session_runs_a_command(&route);
        reverse.shut_down();
    }
}
