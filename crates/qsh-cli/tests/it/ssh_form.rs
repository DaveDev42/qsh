//! The root ssh form, `qsh [ssh options] [user@]host [command...]`
//! (ADR-0051 decisions 6 to 9): one row per decision-7 row, as
//! argv -> the ssh command lines -> QUIC behavior -> exit code.
//!
//! The ssh side is `qsh_testkit::fake_ssh::FakeSsh`, which records every
//! call's argv. The table rows give it no responder: the second call exits
//! `255`, so the bootstrap ends with `CONNECTION_FAILED` right after both
//! command lines exist. The rows that go through to a command or a forward
//! use the same `World` the automatic-bootstrap tests use (a real
//! `qsh pair ssh-respond` and a real `qsh serve`).
//!
//! The pure parts (option validation, mode planning, argument
//! normalization) are unit tests in `qsh-core` and `src/cli/tests.rs`.

use qsh_testkit::fake_ssh::FakeSsh;

use crate::common::{Sandbox, exit_code};

/// The responder call's fixed head (ADR-0044 decision 9) with `BatchMode`,
/// which the tests get because their stdin is not a terminal.
const RESPONDER_HEAD: &[&str] = &[
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
    "-o",
    "BatchMode=yes",
];

/// A client whose `[ssh].program` is the fake, whose responder exits 255.
fn client_with_failing_ssh() -> (Sandbox, FakeSsh) {
    let mut fake = FakeSsh::new();
    fake.exit(255);
    let client = Sandbox::initialized();
    std::fs::write(
        client.config_dir().join("config.toml"),
        format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
    )
    .unwrap();
    (client, fake)
}

/// One row: what the ssh calls look like for an argv.
struct SshRow {
    name: &'static str,
    args: &'static [&'static str],
    /// The words `ssh -G` gets between `-G` and `--`, then the destination.
    forwarded: &'static [&'static str],
    dest: &'static str,
}

/// `ssh -G` and the responder call both carry the forwarded options, the
/// destination is `user@host` when `-l` or `user@` named the account, and a
/// trailing command, `-t`, `-T`, `-N` and `-L` change nothing about either.
#[test]
fn ssh_option_table_argv_to_ssh_command_lines() {
    let rows = [
        SshRow {
            name: "bare host",
            args: &["box"],
            forwarded: &[],
            dest: "box",
        },
        SshRow {
            name: "-p is sshd's port",
            args: &["-p", "2222", "box"],
            forwarded: &["-p", "2222"],
            dest: "box",
        },
        SshRow {
            name: "-l selects the account like user@",
            args: &["-l", "bob", "box"],
            forwarded: &[],
            dest: "bob@box",
        },
        SshRow {
            name: "user@host",
            args: &["bob@box"],
            forwarded: &[],
            dest: "bob@box",
        },
        SshRow {
            name: "user@ wins over -l, like ssh",
            args: &["-l", "eve", "bob@box"],
            forwarded: &[],
            dest: "bob@box",
        },
        SshRow {
            name: "-i -F -C in the fixed order",
            args: &["-C", "-i", "k1", "-i", "k2", "-F", "cfg", "box"],
            forwarded: &["-F", "cfg", "-i", "k1", "-i", "k2", "-C"],
            dest: "box",
        },
        SshRow {
            name: "-o is forwarded as typed",
            args: &["-o", "StrictHostKeyChecking=no", "box"],
            forwarded: &["-o", "StrictHostKeyChecking=no"],
            dest: "box",
        },
        SshRow {
            name: "-4 reaches ssh",
            args: &["-4", "box"],
            forwarded: &["-4"],
            dest: "box",
        },
        SshRow {
            name: "-6 reaches ssh",
            args: &["-6", "box"],
            forwarded: &["-6"],
            dest: "box",
        },
        SshRow {
            name: "-J reaches the bootstrap ssh",
            args: &["-J", "hop", "box"],
            forwarded: &["-J", "hop"],
            dest: "box",
        },
        SshRow {
            name: "-o ProxyJump reaches the bootstrap ssh",
            args: &["-o", "ProxyJump=hop", "box"],
            forwarded: &["-o", "ProxyJump=hop"],
            dest: "box",
        },
        SshRow {
            name: "the four QUIC-side -o keys are forwarded too",
            args: &[
                "-o",
                "ConnectTimeout=5",
                "-o",
                "ServerAliveInterval=7",
                "-o",
                "ServerAliveCountMax=2",
                "box",
            ],
            forwarded: &[
                "-o",
                "ConnectTimeout=5",
                "-o",
                "ServerAliveInterval=7",
                "-o",
                "ServerAliveCountMax=2",
            ],
            dest: "box",
        },
        SshRow {
            name: "a trailing command does not change the ssh lines",
            args: &["box", "ls", "-l", "/tmp"],
            forwarded: &[],
            dest: "box",
        },
        SshRow {
            name: "options between the host and the command stay options",
            args: &["box", "-p", "2200", "uname"],
            forwarded: &["-p", "2200"],
            dest: "box",
        },
        SshRow {
            name: "-t with a command",
            args: &["-t", "box", "top"],
            forwarded: &[],
            dest: "box",
        },
        SshRow {
            name: "-tt with a command",
            args: &["-tt", "box", "top"],
            forwarded: &[],
            dest: "box",
        },
        SshRow {
            name: "-T without a command",
            args: &["-T", "box"],
            forwarded: &[],
            dest: "box",
        },
        SshRow {
            name: "-N with a forward",
            args: &["-N", "-L", "18080:localhost:80", "box"],
            forwarded: &[],
            dest: "box",
        },
        SshRow {
            name: "-e is the escape character, not an ssh option",
            args: &["-e", "^", "box"],
            forwarded: &[],
            dest: "box",
        },
    ];
    for row in rows {
        let (client, fake) = client_with_failing_ssh();
        let out = client.qsh(row.args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{}: {stderr}", row.name);
        assert!(
            stderr.contains("(CONNECTION_FAILED)"),
            "{}: {stderr}",
            row.name
        );
        assert!(out.stdout.is_empty(), "{}", row.name);

        let mut g = vec!["-G".to_string()];
        g.extend(row.forwarded.iter().map(|w| (*w).to_string()));
        g.push("--".into());
        g.push(row.dest.into());
        let mut responder: Vec<String> = RESPONDER_HEAD.iter().map(|w| (*w).to_string()).collect();
        responder.extend(row.forwarded.iter().map(|w| (*w).to_string()));
        responder.extend(
            ["--", row.dest, "qsh", "pair", "ssh-respond"]
                .iter()
                .map(|w| (*w).to_string()),
        );
        assert_eq!(fake.calls(), vec![g, responder], "{}", row.name);
    }
}

/// The reject list (`-A` left it in M25, ADR-0055): named, `UNSUPPORTED`, exit 255, ssh never runs.
#[test]
fn rejected_ssh_options_name_themselves_and_run_nothing() {
    let rows: &[(&[&str], &str)] = &[
        (&["-X", "box"], "-X"),
        (&["-Y", "box"], "-Y"),
        (&["-W", "h:1", "box"], "-W"),
        (&["-M", "box"], "-M"),
        (&["-S", "/tmp/s", "box"], "-S"),
        (&["-O", "check", "box"], "-O"),
        (&["-w", "0:0", "box"], "-w"),
        (&["-b", "10.0.0.1", "box"], "-b"),
        (&["-B", "eth0", "box"], "-B"),
        (&["-c", "aes256-ctr", "box"], "-c"),
        (&["-m", "hmac-sha2-256", "box"], "-m"),
        (&["-Q", "cipher", "box"], "-Q"),
    ];
    for (args, name) in rows {
        let (client, fake) = client_with_failing_ssh();
        let out = client.qsh(args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{args:?}: {stderr}");
        assert!(stderr.contains("(UNSUPPORTED)"), "{args:?}: {stderr}");
        assert!(stderr.contains(name), "{args:?}: {stderr}");
        assert!(fake.calls().is_empty(), "{args:?}: ssh must not run");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

/// `-J` with a name that needs no bootstrap would have to jump on the QUIC
/// path: `UNSUPPORTED` until M26, and no ssh.
#[test]
fn jump_on_a_pinned_host_is_unsupported_without_running_ssh() {
    let (client, fake) = client_with_failing_ssh();
    client.trust_add(
        "pinned",
        Some("127.0.0.1:1"),
        &Sandbox::initialized().fingerprint(),
    );
    for args in [
        &["-J", "hop", "pinned", "true"][..],
        &["-o", "ProxyJump=hop", "pinned", "true"][..],
    ] {
        let out = client.qsh(args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 255, "{args:?}: {stderr}");
        assert!(stderr.contains("(UNSUPPORTED)"), "{args:?}: {stderr}");
        assert!(stderr.contains("M26"), "{args:?}: {stderr}");
    }
    assert!(fake.calls().is_empty());
}

/// `-4` / `-6` also filter the QUIC dial: a pin at an IPv4 address is
/// refused by `-6` before any packet, and `-4` dials as usual.
#[test]
fn address_family_filters_the_quic_dial() {
    let client = Sandbox::initialized();
    client.trust_add(
        "pinned",
        Some("127.0.0.1:1"),
        &Sandbox::initialized().fingerprint(),
    );
    let v6 = client.qsh(&["-6", "pinned", "true"]);
    let stderr = String::from_utf8_lossy(&v6.stderr);
    assert_eq!(exit_code(&v6), 255, "{stderr}");
    assert!(stderr.contains("requested family"), "{stderr}");
    let v4 = client.qsh(&["-4", "-o", "ConnectTimeout=1", "pinned", "true"]);
    let stderr = String::from_utf8_lossy(&v4.stderr);
    assert_eq!(exit_code(&v4), 255, "{stderr}");
    assert!(!stderr.contains("requested family"), "{stderr}");
}

/// `-o ConnectTimeout` bounds the QUIC dial. A pin at a blackhole address
/// with a one-second deadline returns well before the ten-second default.
#[test]
fn connect_timeout_bounds_the_quic_dial() {
    let client = Sandbox::initialized();
    // 192.0.2.0/24 is TEST-NET-1: nothing answers.
    client.trust_add(
        "hole",
        Some("192.0.2.1:4433"),
        &Sandbox::initialized().fingerprint(),
    );
    let started = std::time::Instant::now();
    let out = client.qsh(&["-o", "ConnectTimeout=1", "hole", "true"]);
    assert_eq!(exit_code(&out), 255);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(8),
        "took {:?}: {}",
        started.elapsed(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `-E file` takes the diagnostics, the stderr of the process stays empty.
#[test]
fn log_file_takes_the_diagnostics() {
    let (client, _fake) = client_with_failing_ssh();
    let log = client.home_dir().join("qsh.log");
    let out = client.qsh(&["-E", log.to_str().unwrap(), "box"]);
    assert_eq!(exit_code(&out), 255);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("no qsh pin for \"box\""), "{text}");
    assert!(text.contains("(CONNECTION_FAILED)"), "{text}");
}

/// Root-form mistakes exit 255 like ssh, subcommand mistakes stay 2, and a
/// subcommand name as the first word is the subcommand unless `--` says host.
#[test]
fn usage_errors_exit_255_in_the_root_form_and_2_in_a_subcommand() {
    let (client, fake) = client_with_failing_ssh();
    for args in [
        &["--bogus"][..],
        &["-p"][..],
        &["-Z", "box"][..],
        &["-e", "toolong", "box"][..],
    ] {
        let out = client.qsh(args);
        assert_eq!(exit_code(&out), 255, "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    for args in [
        &["exec"][..],
        &["exec", "--bogus"][..],
        &["trust", "nope"][..],
    ] {
        let out = client.qsh(args);
        assert_eq!(exit_code(&out), 2, "{args:?}");
    }
    assert!(fake.calls().is_empty());

    // `qsh -- version` is a host called "version"; `qsh version` is the
    // subcommand; `qsh box version` runs the command "version" on box.
    let out = client.qsh(&["version"]);
    assert_eq!(exit_code(&out), 0);
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("qsh "));
    let out = client.qsh(&["--", "version"]);
    assert_eq!(exit_code(&out), 255);
    assert_eq!(fake.calls()[0], ["-G", "--", "version"]);
    let out = client.qsh(&["box", "version"]);
    assert_eq!(exit_code(&out), 255);
    assert!(out.stdout.is_empty());
    assert_eq!(fake.calls()[2], ["-G", "--", "box"]);
}

/// `--json` on the root form is refused first, before any other check.
#[test]
fn json_on_the_root_form_is_refused_before_option_checks() {
    let (client, fake) = client_with_failing_ssh();
    let (code, got) = client.json(&["-W", "h:1", "box", "--json"]);
    assert_eq!(code, 255, "{got}");
    assert_eq!(got["error"]["code"], "INVALID_ARGUMENT", "{got}");
    assert!(fake.calls().is_empty());
}

// Every test here needs a unix host shell (`sh -c` until the
// `shell_command` step lands), so the module is unix-only.
#[cfg(unix)]
mod world {
    use super::*;
    use crate::ssh_bootstrap::pair::World;

    /// A trailing command runs through the exec path with the arguments
    /// joined by spaces, so the remote shell sees one string (shell syntax
    /// works), and the remote exit status is the process status.
    #[cfg(unix)]
    #[test]
    fn trailing_command_runs_joined_and_passes_the_exit_status() {
        let w = World::new();
        let out = w
            .client
            .qsh(&["box", "echo", "a", "b", "&&", "echo", "$((1+2))"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 0, "{stderr}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "a b\n3\n");
        // The first run bootstrapped; the second is plain QUIC.
        let calls = w.fake.calls().len();
        let out = w.client.qsh(&["box", "exit", "7"]);
        assert_eq!(
            exit_code(&out),
            7,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(w.fake.calls().len(), calls, "no ssh once the pin exists");
    }

    /// `-T` with no command runs the login shell without a PTY: it reads
    /// the commands from a piped stdin.
    #[cfg(unix)]
    #[test]
    fn t_without_a_command_runs_a_shell_without_a_pty() {
        let w = World::new();
        let out = w
            .client
            .qsh_with_stdin(&["-T", "box"], b"echo from-stdin\nexit 4\n");
        assert_eq!(
            exit_code(&out),
            4,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "from-stdin\n");
    }

    /// `-f -N -L`: the foreground process exits `0` once the listener
    /// stands, and the background process keeps it.
    #[cfg(target_os = "linux")]
    #[test]
    fn f_with_n_returns_once_the_forward_stands_and_leaves_it_running() {
        let w = World::new();
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let spec = format!("{port}:127.0.0.1:9");
        let out = w.client.qsh(&["-f", "-N", "-L", &spec, "box"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(exit_code(&out), 0, "{stderr}");
        let child = find_process(&spec);
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("the forward listens");
        if let Some(pid) = child {
            let _ = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status();
        }
        assert!(
            child.is_some(),
            "the background process outlives the foreground one"
        );
    }

    /// The pid of a process whose command line holds `needle`, other than
    /// this one.
    #[cfg(target_os = "linux")]
    fn find_process(needle: &str) -> Option<u32> {
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if pid == std::process::id() {
                continue;
            }
            let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            if String::from_utf8_lossy(&cmdline).contains(needle) {
                return Some(pid);
            }
        }
        None
    }

    /// `-f` that cannot get its forwards up relays the child's failure.
    #[test]
    fn f_relays_a_failed_background_start() {
        let (client, _fake) = client_with_failing_ssh();
        let out = client.qsh(&["-f", "-N", "-L", "18081:127.0.0.1:9", "box"]);
        assert_eq!(exit_code(&out), 255);
        assert!(String::from_utf8_lossy(&out.stderr).contains("(CONNECTION_FAILED)"));
    }
}
