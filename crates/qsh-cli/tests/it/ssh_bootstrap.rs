//! The ssh-side machinery of `qsh pair ssh` against a fake `ssh`
//! (ADR-0044; `docs/design/testing.md`).
//!
//! `qsh_testkit::fake_ssh::FakeSsh` stands in for the system `ssh`: it
//! records its argv and prints what the test scripts. There is no sshd, no
//! OpenSSH configuration and no remote qsh. These tests drive
//! `qsh_core::ssh_bootstrap` directly, because no command uses it yet; the
//! responder, the pin writes and the CLI surface come with the steps that
//! need them. The same file runs on Windows, where the fake is a copied
//! `ssh.exe` and the recorded argv shows what `ssh.exe` receives after the
//! Windows command-line round trip.

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
