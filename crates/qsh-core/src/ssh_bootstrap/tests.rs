use std::io::Cursor;
use std::sync::{Arc, Mutex};

use qsh_proto::ErrorCode;
use qsh_proto::ssh_bootstrap::{BootstrapLine, Hello, HelloStatus};
use tracing_subscriber::fmt::MakeWriter;

use super::ssh::MessageStream;
use super::*;

fn dest(raw: &str) -> Dest {
    Dest::parse(raw).unwrap()
}

// ---------------------------------------------------------------------
// `<dest>` (ADR-0044 decision 7)
// ---------------------------------------------------------------------

#[test]
fn dest_keeps_the_text_for_ssh_and_names_the_pin_after_the_host_half() {
    let d = dest("dave@box");
    assert_eq!(d.as_ssh_arg(), "dave@box");
    assert_eq!(d.user(), Some("dave"));
    assert_eq!(d.host(), "box");
    assert_eq!(d.pin_name(None).unwrap(), "box");

    // Split at the last `@`, like ssh and the `qsh [user@]host` positional.
    let d = dest("dave@corp@box.example");
    assert_eq!(d.user(), Some("dave@corp"));
    assert_eq!(d.host(), "box.example");
    assert_eq!(d.pin_name(None).unwrap(), "box.example");

    let d = dest("box");
    assert_eq!(d.user(), None);
    assert_eq!(d.as_ssh_arg(), "box");
}

#[test]
fn dest_rejects_option_lookalikes_uris_and_unusable_operands() {
    for bad in [
        "-oProxyCommand=touch /tmp/x",
        "-",
        "--",
        "-G",
        "ssh://box",
        "ssh://dave@box:22",
        "",
        "@box",
        "dave@",
        "box\n",
        "bo\u{0}x",
        "bo x",
        "dave@bo\tx",
    ] {
        let err = Dest::parse(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad:?}");
        assert!(!err.retryable, "{bad:?}");
    }
}

#[test]
fn dest_errors_do_not_echo_the_operand() {
    for bad in [
        "-oSecretToken123",
        "ssh://SecretToken123",
        "Secret Token123",
    ] {
        let err = Dest::parse(bad).unwrap_err();
        assert!(!err.message.contains("SecretToken123"), "{}", err.message);
    }
    let err = Dest::parse("SecretToken123/x")
        .unwrap()
        .pin_name(None)
        .unwrap_err();
    assert!(!err.message.contains("SecretToken123"), "{}", err.message);
    let err = dest("box").pin_name(Some("Secret/Token123")).unwrap_err();
    assert!(!err.message.contains("Token123"), "{}", err.message);
}

#[test]
fn a_host_alias_that_breaks_the_pin_name_rule_works_with_as() {
    // ssh accepts the alias; only the default pin name is unusable.
    for alias in ["web/prod", "dave@web/prod"] {
        let d = dest(alias);
        assert_eq!(d.as_ssh_arg(), alias);
        let err = d.pin_name(None).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{alias}");
        assert!(err.message.contains("--as"), "{}", err.message);
        assert_eq!(d.pin_name(Some("web-prod")).unwrap(), "web-prod");
    }
    // `--as` itself is held to the rule.
    for bad in ["", "a/b", "a\nb"] {
        let err = dest("box").pin_name(Some(bad)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad:?}");
    }
}

#[test]
fn split_user_host_matches_the_cli_positional_rules() {
    assert_eq!(split_user_host("dave@box"), Ok((Some("dave"), "box")));
    assert_eq!(split_user_host("box"), Ok((None, "box")));
    assert_eq!(
        split_user_host("dave@corp@box"),
        Ok((Some("dave@corp"), "box"))
    );
    assert!(split_user_host("").is_err());
    assert!(split_user_host("dave@").is_err());
    assert!(split_user_host("@box").is_err());
}

// ---------------------------------------------------------------------
// Argument building and quoting (decision 9)
// ---------------------------------------------------------------------

#[test]
fn remote_qsh_is_bare_for_safe_characters_and_single_quoted_otherwise() {
    for bare in [
        "qsh",
        "/usr/local/bin/qsh",
        "~/.cargo/bin/qsh",
        "C:/Qsh/bin/qsh.exe",
        r"C:\Qsh\bin\qsh.exe",
        "qsh+nightly:1",
        "a-b_c.d",
    ] {
        assert_eq!(quote_remote_program(bare).unwrap(), bare);
    }
    for (word, quoted) in [
        (
            "C:/Program Files/qsh/qsh.exe",
            "'C:/Program Files/qsh/qsh.exe'",
        ),
        ("/opt/my qsh/qsh", "'/opt/my qsh/qsh'"),
        ("qsh;id", "'qsh;id'"),
        ("$(id)", "'$(id)'"),
        ("a'b", r"'a'\''b'"),
        ("'", r"''\'''"),
        ("qsh\"x", "'qsh\"x'"),
        ("é", "'é'"),
    ] {
        assert_eq!(quote_remote_program(word).unwrap(), quoted, "{word}");
    }
}

#[test]
fn remote_qsh_rejects_empty_control_and_oversized_words() {
    for bad in ["", "a\nb", "a\u{0}b", "a\rb", "\u{7f}"] {
        let err = quote_remote_program(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad:?}");
    }
    assert!(quote_remote_program(&"a".repeat(4096)).is_ok());
    assert!(quote_remote_program(&"a".repeat(4097)).is_err());
}

#[test]
fn responder_args_are_the_fixed_adr_list() {
    let d = dest("dave@box");
    let args = responder_args(&d, "qsh", false).unwrap();
    assert_eq!(
        args,
        [
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
            "--",
            "dave@box",
            "qsh",
            "pair",
            "ssh-respond",
        ]
    );
    let batch = responder_args(&d, "qsh", true).unwrap();
    let at = batch.iter().position(|a| a == "BatchMode=yes").unwrap();
    assert_eq!(batch[at - 1], "-o");
    assert_eq!(batch[at + 1], "--", "BatchMode sits before the --");
    assert_eq!(batch.len(), args.len() + 2);
    assert!(
        !batch
            .iter()
            .any(|a| a.contains("StrictHostKeyChecking") || a.contains("UserKnownHostsFile")),
        "host key policy is the user's (decision 20): {batch:?}"
    );
}

#[test]
fn ssh_g_args_pass_the_dest_after_the_double_dash() {
    assert_eq!(ssh_g_args(&dest("box")), ["-G", "--", "box"]);
}

#[test]
fn batch_mode_is_machine_mode_or_a_non_terminal_stdin() {
    assert!(batch_mode(true, true));
    assert!(batch_mode(true, false));
    assert!(batch_mode(false, false));
    assert!(!batch_mode(false, true));
}

#[test]
fn bootstrap_timeouts_are_unbounded_for_the_hello_only_without_batch_mode() {
    let human = BootstrapTimeouts::for_batch_mode(false);
    assert_eq!(human.hello, None);
    assert_eq!(human.message, MESSAGE_TIMEOUT);
    let batch = BootstrapTimeouts::for_batch_mode(true);
    assert_eq!(batch.hello, Some(BATCH_HELLO_TIMEOUT));
    assert_eq!(MESSAGE_TIMEOUT.as_secs(), 30);
    assert_eq!(BATCH_HELLO_TIMEOUT.as_secs(), 60);
}

// ---------------------------------------------------------------------
// `ssh -G` (decision 4, 6, 26)
// ---------------------------------------------------------------------

#[test]
fn ssh_g_reads_the_four_keys_and_skips_the_rest() {
    let output = b"host box\nhostname box.example.com\nport 2222\nuser dave\n\
                   identityfile ~/.ssh/id_ed25519\nidentityfile ~/.ssh/id_rsa\n\
                   proxyjump none\nforwardagent no\nhostkeyalgorithms ssh-ed25519\n";
    let got = parse_ssh_g(output).unwrap();
    assert_eq!(
        got,
        SshResolved {
            hostname: "box.example.com".into(),
            user: Some("dave".into()),
            proxied: false,
        }
    );
}

#[test]
fn ssh_g_first_occurrence_wins_and_keys_are_case_insensitive() {
    let got = parse_ssh_g(b"HostName first\r\nhostname second\r\n").unwrap();
    assert_eq!(got.hostname, "first");
}

#[test]
fn ssh_g_proxyjump_or_proxycommand_marks_the_bootstrap_as_proxied() {
    for extra in [
        "proxyjump bastion.example.com\n",
        "proxycommand ssh -W %h:%p gw\n",
        "proxyjump none\nproxycommand nc %h %p\n",
    ] {
        let got = parse_ssh_g(format!("hostname box\n{extra}").as_bytes()).unwrap();
        assert!(got.proxied, "{extra:?}");
    }
    for extra in ["proxyjump none\n", "proxycommand none\n", "proxyjump\n", ""] {
        let got = parse_ssh_g(format!("hostname box\n{extra}").as_bytes()).unwrap();
        assert!(!got.proxied, "{extra:?}");
    }
}

#[test]
fn ssh_g_keeps_an_ipv6_literal_unbracketed() {
    assert_eq!(
        parse_ssh_g(b"hostname fe80::1\n").unwrap().hostname,
        "fe80::1"
    );
}

#[test]
fn ssh_g_output_over_64_kib_is_a_config_error_and_exactly_64_kib_is_read() {
    let mut at_cap = b"hostname box\n".to_vec();
    at_cap.resize(SSH_G_OUTPUT_MAX, b'\n');
    assert_eq!(parse_ssh_g(&at_cap).unwrap().hostname, "box");

    let mut over = at_cap.clone();
    over.push(b'\n');
    let err = parse_ssh_g(&over).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert_eq!(err.details["reason"], "ssh_g_too_large");
}

#[test]
fn ssh_g_without_a_usable_hostname_is_a_config_error() {
    for bad in [
        &b""[..],
        b"user dave\n",
        b"hostname\n",
        b"hostname two words\n",
        b"hostname \xff\xfe\n",
        b"hostname bad\x07host\n",
    ] {
        let err = parse_ssh_g(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError, "{bad:?}");
        assert_eq!(err.details["reason"], "ssh_g_unreadable", "{bad:?}");
    }
}

#[test]
fn ssh_g_errors_never_echo_the_output() {
    let err =
        parse_ssh_g(b"identityfile /home/SecretUser/.ssh/key\nhostname two words\n").unwrap_err();
    assert!(!err.message.contains("SecretUser"));
    assert!(!err.details.to_string().contains("SecretUser"));
}

// ---------------------------------------------------------------------
// Exit status mapping (decision 14)
// ---------------------------------------------------------------------

fn reason(err: &crate::ops::OpError) -> &str {
    err.details["reason"].as_str().unwrap_or("")
}

#[test]
fn ssh_exit_codes_map_to_the_adr_reasons_before_the_hello() {
    let missing_127 = map_ssh_exit(SshExit::Code(127), false);
    assert_eq!(missing_127.code, ErrorCode::RemoteError);
    assert_eq!(reason(&missing_127), "remote_qsh_missing");
    assert!(missing_127.message.contains("--remote-qsh"));
    assert!(missing_127.message.contains("[ssh].remote_qsh"));

    let missing_9009 = map_ssh_exit(SshExit::Code(9009), false);
    assert_eq!(missing_9009.code, ErrorCode::RemoteError);
    assert_eq!(reason(&missing_9009), "remote_qsh_missing");
    assert_eq!(missing_9009.details["remote_exit"], 9009);

    let old = map_ssh_exit(SshExit::Code(2), false);
    assert_eq!(old.code, ErrorCode::Unsupported);
    assert_eq!(reason(&old), "remote_qsh_too_old");

    let failed = map_ssh_exit(SshExit::Code(1), false);
    assert_eq!(failed.code, ErrorCode::RemoteError);
    assert_eq!(reason(&failed), "remote_command_failed");
    assert_eq!(failed.details["remote_exit"], 1);
    assert!(failed.message.contains("PowerShell"));

    let ssh = map_ssh_exit(SshExit::Code(255), false);
    assert_eq!(ssh.code, ErrorCode::ConnectionFailed);
    assert_eq!(reason(&ssh), "ssh_failed");
    assert_eq!(ssh.details["ssh_exit"], 255);

    let other = map_ssh_exit(SshExit::Code(77), false);
    assert_eq!(reason(&other), "remote_command_failed");
    assert_eq!(other.details["remote_exit"], 77);

    let silent = map_ssh_exit(SshExit::Code(0), false);
    assert_eq!(silent.code, ErrorCode::RemoteError);
    assert_eq!(reason(&silent), "bootstrap_protocol");
}

const CMD_EN: &[u8] = b"'qsh' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n";
const CMD_KO: &str = "'qsh'\u{c740}(\u{b294}) \u{b0b4}\u{bd80} \u{b610}\u{b294} \u{c678}\u{bd80} \u{bc84}\u{ba85}\u{b839}, \u{c2e4}\u{d589}\u{d560} \u{c218} \u{c788}\u{b294} \u{d504}\u{b85c}\u{adf8}\u{b7a8}, \u{b610}\u{b294} \u{bc30}\u{ce58} \u{d30c}\u{c77c}\u{c774} \u{c544}\u{b2d9}\u{b2c8}\u{b2e4}.\r\n";
const POWERSHELL: &[u8] = b"qsh: The term 'qsh' is not recognized as a name of a cmdlet, function, script file, or executable program.\n";

#[test]
fn exit_1_with_the_cmd_exe_text_is_a_missing_qsh() {
    for tail in [CMD_EN, CMD_KO.as_bytes()] {
        let err = map_ssh_exit_with_stderr(SshExit::Code(1), false, "qsh", tail);
        assert_eq!(err.code, ErrorCode::RemoteError);
        assert_eq!(reason(&err), "remote_qsh_missing");
        assert_eq!(err.details["remote_exit"], 1);
        assert!(err.message.contains("--remote-qsh"));
        assert!(err.message.contains("[ssh].remote_qsh"));
    }
    // Other lines before it, an ANSI-colored line and leading blanks do not hide it.
    let tail = b"Warning: noise\r\n  \x1b[31m'qsh' is not recognized as an internal\x1b[0m\r\n";
    let err = map_ssh_exit_with_stderr(SshExit::Code(1), false, "qsh", tail);
    assert_eq!(reason(&err), "remote_qsh_missing");
}

#[test]
fn a_custom_remote_qsh_is_matched_by_its_value_or_basename() {
    let path = r"C:\Tools\qsh\qsh.exe";
    let full = format!("'{path}' is not recognized as an internal or external command,\r\n");
    let err = map_ssh_exit_with_stderr(SshExit::Code(1), false, path, full.as_bytes());
    assert_eq!(reason(&err), "remote_qsh_missing");
    let base = b"'qsh.exe' is not recognized as an internal or external command,\r\n";
    let err = map_ssh_exit_with_stderr(SshExit::Code(1), false, path, base);
    assert_eq!(reason(&err), "remote_qsh_missing");
    // The default name does not match a different custom program.
    let err = map_ssh_exit_with_stderr(SshExit::Code(1), false, path, CMD_EN);
    assert_eq!(reason(&err), "remote_command_failed");
}

#[test]
fn exit_1_with_powershell_or_unrelated_text_stays_a_failed_command() {
    let colored = b"\x1b[31;1mqsh: \x1b[0m\x1b[31;1mThe term 'qsh' is not recognized as a name of a cmdlet\x1b[0m\n";
    for tail in [
        POWERSHELL,
        &colored[..],
        b"bash: qsh: command not found\n",
        b"",
        b"it's 'qsh' time\n",
    ] {
        let err = map_ssh_exit_with_stderr(SshExit::Code(1), false, "qsh", tail);
        assert_eq!(reason(&err), "remote_command_failed", "{tail:?}");
        assert_eq!(err.details["remote_exit"], 1);
        assert!(err.message.contains("PowerShell"));
    }
}

#[test]
fn the_cmd_exe_text_changes_only_exit_1_and_only_before_the_hello() {
    for (code, expected) in [
        (127, "remote_qsh_missing"),
        (9009, "remote_qsh_missing"),
        (2, "remote_qsh_too_old"),
        (77, "remote_command_failed"),
        (0, "bootstrap_protocol"),
    ] {
        let err = map_ssh_exit_with_stderr(SshExit::Code(code), false, "qsh", CMD_EN);
        assert_eq!(reason(&err), expected, "{code}");
    }
    let err = map_ssh_exit_with_stderr(SshExit::Code(1), true, "qsh", CMD_EN);
    assert_eq!(reason(&err), "bootstrap_protocol");
    let err = map_ssh_exit_with_stderr(SshExit::Code(255), false, "qsh", CMD_EN);
    assert_eq!(reason(&err), "ssh_failed");
}

#[test]
fn ssh_exit_after_the_hello_is_ssh_failed_or_a_protocol_error() {
    let dropped = map_ssh_exit(SshExit::Code(255), true);
    assert_eq!(dropped.code, ErrorCode::ConnectionFailed);
    assert_eq!(reason(&dropped), "ssh_failed");
    for code in [0, 1, 2, 127] {
        let err = map_ssh_exit(SshExit::Code(code), true);
        assert_eq!(err.code, ErrorCode::RemoteError, "{code}");
        assert_eq!(reason(&err), "bootstrap_protocol", "{code}");
    }
}

#[test]
fn an_interrupt_is_canceled_at_every_point() {
    for hello_seen in [false, true] {
        let err = map_ssh_exit(SshExit::Interrupted, hello_seen);
        assert_eq!(err.code, ErrorCode::Canceled);
        assert!(!err.retryable);
    }
    let by_signal = map_ssh_exit(SshExit::Signal(9), false);
    assert_eq!(by_signal.code, ErrorCode::ConnectionFailed);
    assert_eq!(reason(&by_signal), "ssh_failed");
}

#[test]
fn the_windows_ctrl_c_status_is_an_interrupt_on_every_platform() {
    assert_eq!(
        SshExit::from_code(0xC000_013Au32 as i32),
        SshExit::Interrupted
    );
    assert_eq!(SshExit::from_code(255), SshExit::Code(255));
    assert_eq!(SshExit::from_code(9009), SshExit::Code(9009));
    assert_eq!(SshExit::from_code(-1), SshExit::Code(-1));
}

#[test]
fn ssh_not_found_names_the_windows_feature_only_on_windows() {
    let unix = ssh_not_found("ssh", false);
    assert_eq!(unix.code, ErrorCode::ConfigError);
    assert_eq!(reason(&unix), "ssh_not_found");
    assert!(!unix.message.contains("OpenSSH Client"));
    assert!(unix.message.contains("[ssh].program"));

    let windows = ssh_not_found("ssh.exe", true);
    assert_eq!(reason(&windows), "ssh_not_found");
    assert!(windows.message.contains("OpenSSH Client"));
}

// ---------------------------------------------------------------------
// Log discipline (decision 19)
// ---------------------------------------------------------------------

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

fn capturing() -> (Capture, tracing::subscriber::DefaultGuard) {
    let capture = Capture::default();
    let guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    (capture, guard)
}

fn hello_line() -> String {
    BootstrapLine::Hello(Hello {
        versions: vec![1],
        qsh_version: "0.0.0".into(),
        status: HelloStatus::NotInitialized,
        fingerprint: None,
        serve_bind: None,
        serve_listening: None,
    })
    .encode_line()
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_bootstrap_rc_output_is_counted_not_logged() {
    let (capture, _guard) = capturing();
    let rc = "RC-SECRET-TOKEN-4711 welcome back dave\nexport API_KEY=RC-SECRET-TOKEN-4712\n";
    let stream = format!("{rc}{rc}{}", hello_line());
    let mut messages = MessageStream::new(Cursor::new(stream.into_bytes()));

    let first = messages.next().await.unwrap();
    assert!(matches!(first, Some(BootstrapLine::Hello(_))));
    assert_eq!(messages.skipped_lines(), 4);
    assert_eq!(messages.skipped_bytes(), rc.len() * 2);

    let logged = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logged.contains("skipped_lines=4"),
        "the count is logged: {logged:?}"
    );
    assert!(!logged.contains("RC-SECRET"), "{logged:?}");
    assert!(!logged.contains("API_KEY"), "{logged:?}");
    assert!(!logged.contains("welcome"), "{logged:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_protocol_error_logs_counts_and_maps_to_bootstrap_protocol() {
    use tokio::io::AsyncWriteExt;

    let (capture, _guard) = capturing();
    let (mut tx, rx) = tokio::io::duplex(4096);
    let mut messages = MessageStream::new(rx);
    tx.write_all(format!("RC-SECRET-TOKEN-4713\n{}", hello_line()).as_bytes())
        .await
        .unwrap();
    assert!(messages.next().await.unwrap().is_some());
    tx.write_all(b"untagged after hello\n").await.unwrap();
    let err = messages.next().await.unwrap_err();
    assert_eq!(err.code, ErrorCode::RemoteError);
    assert_eq!(reason(&err), "bootstrap_protocol");
    assert!(!err.message.contains("untagged after hello"));
    let logged = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!logged.contains("RC-SECRET"), "{logged:?}");
    assert!(!logged.contains("untagged after hello"), "{logged:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn message_stream_ends_at_eof_and_after_the_result() {
    let mut empty = MessageStream::new(Cursor::new(Vec::new()));
    assert!(empty.next().await.unwrap().is_none());
    assert!(!empty.hello_seen());
}

// ---------------------------------------------------------------------
// `*_POSIX_FD_STATE` is not passed to the ssh child (Windows OpenSSH Server)
// ---------------------------------------------------------------------

#[test]
fn posix_fd_state_names_picks_only_names_ending_in_the_suffix_ignoring_case() {
    use super::ssh::posix_fd_state_names;
    let guid = "c28fc6f98a2c44abbbd89d6a3037d0d9_POSIX_FD_STATE";
    let picked = posix_fd_state_names([
        guid,
        "c28fc6f98a2c44abbbd89d6a3037d0d9_posix_fd_state",
        "OTHER_Posix_Fd_State",
        "PATH",
        "SSH_TTY",
        "POSIX_FD_STATE",
        "X_POSIX_FD_STATE_EXTRA",
        "MY_POSIX_FD_STATE_DIR",
        "é_POSIX_FD_STATE",
        "",
    ]);
    let picked: Vec<_> = picked.iter().map(|n| n.to_string_lossy()).collect();
    assert_eq!(
        picked,
        [
            guid,
            "c28fc6f98a2c44abbbd89d6a3037d0d9_posix_fd_state",
            "OTHER_Posix_Fd_State",
            "é_POSIX_FD_STATE",
        ]
    );
}

#[cfg(windows)]
#[tokio::test]
async fn the_ssh_spawn_path_strips_the_posix_fd_state_variable_on_windows() {
    use super::ssh::strip_posix_fd_state;
    // The stub exits 1 when the variable is defined. The variable is set on
    // the command (no process-wide `set_var`), which `env_remove` also clears.
    let name = "0123456789abcdef0123456789abcdef_POSIX_FD_STATE";
    let run = |strip: bool| async move {
        let mut cmd = tokio::process::Command::new("cmd.exe");
        cmd.args(["/c", &format!("if defined {name} (exit 1) else (exit 0)")])
            .env(name, "AAAAAAICAgA=");
        if strip {
            strip_posix_fd_state(&mut cmd, [name]);
        }
        cmd.status().await.unwrap().code()
    };
    assert_eq!(run(false).await, Some(1), "the stub sees the variable");
    assert_eq!(run(true).await, Some(0), "the stripped child does not");
}

/// Only a `BatchMode` responder call gets `SSH_ASKPASS_REQUIRE=never`; in
/// human mode the person's own environment stands (ADR-0044 decision 16).
#[test]
fn batch_child_env_sets_askpass_never_only_in_batch_mode() {
    use super::ssh::batch_child_env;

    assert_eq!(
        batch_child_env(true),
        &[("SSH_ASKPASS_REQUIRE", "never")][..]
    );
    assert!(batch_child_env(false).is_empty());
}
