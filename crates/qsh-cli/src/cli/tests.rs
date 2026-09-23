use super::*;
use clap::CommandFactory as _;

#[test]
fn cli_definition_is_valid() {
    Cli::command().debug_assert();
}

/// `qsh schema` takes no arguments; `qsh capabilities [host]` takes an
/// optional positional (`docs/CLI.md` §6.10) — same shape as
/// `qsh sessions [host]`.
#[test]
fn schema_and_capabilities_parse_per_cli_md() {
    assert!(matches!(
        Cli::try_parse_from(["qsh", "schema"]).unwrap().command,
        Some(Command::Schema)
    ));
    assert!(Cli::try_parse_from(["qsh", "schema", "extra"]).is_err());

    assert!(matches!(
        Cli::try_parse_from(["qsh", "capabilities"])
            .unwrap()
            .command,
        Some(Command::Capabilities { host: None })
    ));
    let cli = Cli::try_parse_from(["qsh", "capabilities", "personal-mac"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Capabilities { host: Some(ref h) }) if h == "personal-mac"
    ));
}

#[test]
fn key_store_flag_parses_and_rejects_unknown_modes() {
    let cli = Cli::try_parse_from(["qsh", "init", "--key-store", "file"]).unwrap();
    match cli.command.unwrap() {
        Command::Init { key_store } => assert_eq!(key_store, Some(KeyStoreMode::File)),
        other => panic!("expected init, got {other:?}"),
    }
    assert!(Cli::try_parse_from(["qsh", "init", "--key-store", "keychain"]).is_err());
}

/// `-L` is repeatable, scoped to the interactive form, and left
/// **unparsed** by clap so a malformed spec is an `INVALID_ARGUMENT`
/// operation error (exit 255) rather than a clap usage error (exit 2)
/// — `docs/CLI.md` §6.9, and this flag's own doc.
#[test]
fn local_forward_is_repeatable_and_scoped_to_the_interactive_form() {
    let cli = Cli::try_parse_from([
        "qsh",
        "dave@box",
        "-L",
        "8080:localhost:3000",
        "-L",
        "127.0.0.1:9090:db.internal:5432",
    ])
    .unwrap();
    assert!(cli.command.is_none());
    assert_eq!(
        cli.interactive.local_forward,
        vec![
            "8080:localhost:3000".to_string(),
            "127.0.0.1:9090:db.internal:5432".to_string(),
        ]
    );

    // Garbage is accepted by clap and refused later, with a code.
    assert_eq!(
        Cli::try_parse_from(["qsh", "box", "-L", "nonsense"])
            .unwrap()
            .interactive
            .local_forward,
        vec!["nonsense".to_string()]
    );
    // …but only on the form that has a target: `-L` is not a global
    // flag, and `qsh attach` takes none (`docs/CLI.md` §7).
    assert!(Cli::try_parse_from(["qsh", "-L", "8080:localhost:3000"]).is_err());
    assert!(
        Cli::try_parse_from(["qsh", "attach", "box/01K0", "-L", "8080:localhost:3000"]).is_err()
    );
    assert!(Cli::try_parse_from(["qsh", "hosts", "-L", "8080:localhost:3000"]).is_err());
}

/// `-R` is `-L`'s twin: repeatable, scoped to the interactive form,
/// unparsed by clap for the same reason (`docs/CLI.md` §6.9), and free
/// to coexist with `-L` on the same invocation — `docs/CLI.md` §6.9
/// treats them as companion flags of the interactive form, not mutually
/// exclusive.
#[test]
fn remote_forward_is_repeatable_scoped_to_the_interactive_form_and_coexists_with_local() {
    let cli = Cli::try_parse_from([
        "qsh",
        "dave@box",
        "-R",
        "9000:127.0.0.1:22",
        "-L",
        "8080:localhost:3000",
        "-R",
        "127.0.0.1:9001:127.0.0.1:23",
    ])
    .unwrap();
    assert_eq!(
        cli.interactive.remote_forward,
        vec![
            "9000:127.0.0.1:22".to_string(),
            "127.0.0.1:9001:127.0.0.1:23".to_string(),
        ]
    );
    assert_eq!(
        cli.interactive.local_forward,
        vec!["8080:localhost:3000".to_string()]
    );

    assert!(Cli::try_parse_from(["qsh", "-R", "9000:127.0.0.1:22"]).is_err());
    assert!(Cli::try_parse_from(["qsh", "attach", "box/01K0", "-R", "9000:127.0.0.1:22"]).is_err());
}

/// `qsh tunnel open` takes a bare host and exactly one of
/// `--local`/`-L`, `--remote`/`-R`, or `--dynamic`/`-D`
/// (`docs/CLI.md` §6.9) — none, or more than one, is a clap usage
/// error (exit 2), because a tunnel with no forward — or two
/// contradictory ones — is nothing. `--dynamic` given twice is a
/// separate `INVALID_ARGUMENT` refusal built in `main.rs`'s
/// `run_tunnel_open_dynamic` (not clap, and not `Ops`: `Ops::tunnel_dynamic`
/// never sees `args.dynamic`'s length), not a clap usage error — clap's
/// own conflict machinery only rejects *different* flags colliding, so
/// this test does not cover that case.
#[test]
fn tunnel_open_takes_a_bare_host_and_exactly_one_of_local_or_remote() {
    let cli = Cli::try_parse_from([
        "qsh",
        "tunnel",
        "open",
        "box",
        "--local",
        "8080:localhost:3000",
    ])
    .unwrap();
    match cli.command.unwrap() {
        Command::Tunnel(TunnelCmd::Open(args)) => {
            assert_eq!(args.host, "box");
            assert_eq!(args.local.as_deref(), Some("8080:localhost:3000"));
            assert_eq!(args.remote, None);
        }
        other => panic!("expected tunnel open, got {other:?}"),
    }
    // `-L` is the short form of the same flag.
    let cli =
        Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-L", "1:h:2", "--json"]).unwrap();
    assert!(cli.wants_json());

    let cli = Cli::try_parse_from([
        "qsh",
        "tunnel",
        "open",
        "box",
        "--remote",
        "9000:127.0.0.1:22",
    ])
    .unwrap();
    match cli.command.unwrap() {
        Command::Tunnel(TunnelCmd::Open(args)) => {
            assert_eq!(args.local, None);
            assert_eq!(args.remote.as_deref(), Some("9000:127.0.0.1:22"));
        }
        other => panic!("expected tunnel open, got {other:?}"),
    }
    // `-R` is the short form of the same flag.
    assert!(Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-R", "1:h:2"]).is_ok());

    assert!(Cli::try_parse_from(["qsh", "tunnel", "open", "box"]).is_err());
    assert!(Cli::try_parse_from(["qsh", "tunnel", "open", "-L", "1:h:2"]).is_err());
    // Both at once is a usage error, not a "last one wins".
    assert!(
        Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-L", "1:h:2", "-R", "3:h:4",])
            .is_err()
    );

    // `-D` is a third, mutually exclusive mode.
    let cli = Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-D", "1080"]).unwrap();
    match cli.command.unwrap() {
        Command::Tunnel(TunnelCmd::Open(args)) => {
            assert_eq!(args.local, None);
            assert_eq!(args.remote, None);
            assert_eq!(args.dynamic, vec!["1080".to_string()]);
        }
        other => panic!("expected tunnel open, got {other:?}"),
    }
    // `--dynamic` conflicts with `--local` and `--remote` alike, in
    // either flag order.
    assert!(
        Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-D", "1080", "-L", "1:h:2",])
            .is_err()
    );
    assert!(
        Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-L", "1:h:2", "-D", "1080",])
            .is_err()
    );
    assert!(
        Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-D", "1080", "-R", "3:h:4",])
            .is_err()
    );
    // `--dynamic` given twice parses fine at the clap layer
    // (`main.rs`'s `run_tunnel_open_dynamic` refuses it downstream,
    // before `Ops::tunnel_dynamic` is ever called) — this is not a
    // usage error.
    assert!(
        Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-D", "1080", "-D", "1081",]).is_ok()
    );
}

/// `--wait` (`docs/CLI.md` §6.9, issue #4 item 5a): defaults to `0`
/// when absent, parses as a plain millisecond count when given, and
/// conflicts with `--dynamic` (it builds a separate request this flag
/// never reaches) but not with `--local`/`--remote`. The bound
/// (`0..=600_000`) is enforced in `qsh-core` (`Ops::tunnel_open`'s
/// `wait_budget_ms`), not by clap here, so an out-of-range value
/// still parses at this layer and only fails once the request
/// reaches `Ops`.
#[test]
fn tunnel_open_wait_defaults_to_zero_and_parses_when_given() {
    let cli = Cli::try_parse_from(["qsh", "tunnel", "open", "box", "-L", "1:h:2"]).unwrap();
    match cli.command.unwrap() {
        Command::Tunnel(TunnelCmd::Open(args)) => assert_eq!(args.wait, 0),
        other => panic!("expected tunnel open, got {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "qsh", "tunnel", "open", "box", "-L", "1:h:2", "--wait", "30000",
    ])
    .unwrap();
    match cli.command.unwrap() {
        Command::Tunnel(TunnelCmd::Open(args)) => assert_eq!(args.wait, 30_000),
        other => panic!("expected tunnel open, got {other:?}"),
    }

    // Parses fine at this layer even out of `Ops`'s bound — clap does
    // not enforce `0..=600_000` here (this file's own doc on `wait`).
    assert!(
        Cli::try_parse_from([
            "qsh", "tunnel", "open", "box", "-L", "1:h:2", "--wait", "700000",
        ])
        .is_ok()
    );
}

/// `--wait` together with `--dynamic` (`-D`) is a clap usage error,
/// not a silent no-op — `-D` builds `TunnelDynamicReq`, which has no
/// `wait_ms` field, so before this `conflicts_with` existed the value
/// simply vanished (issue #4 item 5a review finding).
#[test]
fn tunnel_open_wait_conflicts_with_dynamic() {
    assert!(
        Cli::try_parse_from([
            "qsh", "tunnel", "open", "box", "-D", "1080", "--wait", "30000",
        ])
        .is_err()
    );
}

#[test]
fn global_flags_work_before_and_after_the_subcommand() {
    for args in [
        ["qsh", "--json", "-vv", "trust", "list"],
        ["qsh", "trust", "list", "--json", "-vv"],
    ] {
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(cli.wants_json());
        assert_eq!(cli.verbose, 2);
    }
}

#[test]
fn quiet_and_verbose_are_mutually_exclusive() {
    assert!(Cli::try_parse_from(["qsh", "-q", "-v", "version"]).is_err());
}

#[test]
fn exec_takes_argv_after_double_dash_and_global_flags_before_it() {
    let cli = Cli::try_parse_from([
        "qsh",
        "exec",
        "box",
        "--json",
        "--timeout",
        "5000",
        "--env",
        "A=1",
        "--",
        "sh",
        "-c",
        "echo -n hi --json",
    ])
    .unwrap();
    assert!(cli.wants_json());
    match cli.command.unwrap() {
        Command::Exec(args) => {
            assert_eq!(args.host, "box");
            assert_eq!(args.timeout, Some(5000));
            assert_eq!(args.env.len(), 1);
            assert_eq!(args.env[0].name, "A");
            assert_eq!(args.env[0].value, "1");
            assert_eq!(args.argv, ["sh", "-c", "echo -n hi --json"]);
        }
        other => panic!("expected exec, got {other:?}"),
    }
    // No command after `--` is a usage error (exit 2), not a runtime one.
    assert!(Cli::try_parse_from(["qsh", "exec", "box"]).is_err());
    assert!(Cli::try_parse_from(["qsh", "exec", "box", "--"]).is_err());
    assert!(Cli::try_parse_from(["qsh", "exec", "box", "--env", "novalue", "--", "true"]).is_err());
}

#[test]
fn serve_bind_is_optional() {
    let cli = Cli::try_parse_from(["qsh", "serve"]).unwrap();
    assert!(matches!(
        cli.command.unwrap(),
        Command::Serve { bind: None }
    ));
    let cli = Cli::try_parse_from(["qsh", "serve", "--bind", "127.0.0.1:0"]).unwrap();
    match cli.command.unwrap() {
        Command::Serve { bind } => assert_eq!(bind.as_deref(), Some("127.0.0.1:0")),
        other => panic!("expected serve, got {other:?}"),
    }
}

#[test]
fn listen_bind_is_optional() {
    let cli = Cli::try_parse_from(["qsh", "listen"]).unwrap();
    assert!(matches!(
        cli.command.unwrap(),
        Command::Listen { bind: None }
    ));
    let cli = Cli::try_parse_from(["qsh", "listen", "--bind", "127.0.0.1:0"]).unwrap();
    match cli.command.unwrap() {
        Command::Listen { bind } => assert_eq!(bind.as_deref(), Some("127.0.0.1:0")),
        other => panic!("expected listen, got {other:?}"),
    }
}

#[test]
fn reverse_requires_controller_and_offered_name_is_optional() {
    let cli = Cli::try_parse_from(["qsh", "reverse", "personal-mac"]).unwrap();
    match cli.command.unwrap() {
        Command::Reverse {
            controller,
            offered_name,
        } => {
            assert_eq!(controller, "personal-mac");
            assert!(offered_name.is_none());
        }
        other => panic!("expected reverse, got {other:?}"),
    }
    let cli =
        Cli::try_parse_from(["qsh", "reverse", "personal-mac", "--offered-name", "phone"]).unwrap();
    match cli.command.unwrap() {
        Command::Reverse {
            controller,
            offered_name,
        } => {
            assert_eq!(controller, "personal-mac");
            assert_eq!(offered_name.as_deref(), Some("phone"));
        }
        other => panic!("expected reverse, got {other:?}"),
    }
    assert!(Cli::try_parse_from(["qsh", "reverse"]).is_err());
}

#[test]
fn session_subcommands_parse_per_cli_md() {
    let cli = Cli::try_parse_from([
        "qsh", "session", "open", "box", "--env", "A=1", "--term", "xterm", "--cols", "80",
        "--rows", "24", "--json", "--", "claude", "--json",
    ])
    .unwrap();
    assert!(cli.wants_json());
    match cli.command.unwrap() {
        Command::Session(SessionCmd::Open(args)) => {
            assert_eq!(args.host, "box");
            assert_eq!(args.env[0].name, "A");
            assert_eq!(args.term.as_deref(), Some("xterm"));
            assert_eq!((args.cols, args.rows), (Some(80), Some(24)));
            assert_eq!(args.argv, ["claude", "--json"]);
        }
        other => panic!("expected session open, got {other:?}"),
    }
    // No `--` ⇒ login shell (empty argv), unlike exec.
    let cli = Cli::try_parse_from(["qsh", "session", "open", "box"]).unwrap();
    assert!(matches!(cli.command.unwrap(),
        Command::Session(SessionCmd::Open(SessionOpenArgs { ref argv, .. })) if argv.is_empty()
    ));
    assert!(Cli::try_parse_from(["qsh", "session", "open", "box", "--cols", "0"]).is_err());

    let cli = Cli::try_parse_from([
        "qsh",
        "session",
        "read",
        "box/01K0",
        "--after",
        "42",
        "--wait",
        "30000",
        "--limit-bytes",
        "1024",
    ])
    .unwrap();
    match cli.command.unwrap() {
        Command::Session(SessionCmd::Read(args)) => {
            assert_eq!(args.session_ref, "box/01K0");
            assert_eq!(args.after, 42);
            assert_eq!(args.wait, Some(30000));
            assert_eq!(args.limit_bytes, Some(1024));
            assert!(!args.follow);
        }
        other => panic!("expected session read, got {other:?}"),
    }
    let cli = Cli::try_parse_from(["qsh", "session", "read", "box/01K0"]).unwrap();
    assert!(matches!(
        cli.command.unwrap(),
        Command::Session(SessionCmd::Read(SessionReadArgs {
            after: 0,
            wait: None,
            ..
        }))
    ));

    // write: exactly one source.
    assert!(Cli::try_parse_from(["qsh", "session", "write", "box/01K0"]).is_err());
    assert!(
        Cli::try_parse_from([
            "qsh",
            "session",
            "write",
            "box/01K0",
            "--stdin",
            "--data-b64",
            "Yw=="
        ])
        .is_err()
    );
    let cli =
        Cli::try_parse_from(["qsh", "session", "write", "box/01K0", "--data-b64", "Yw=="]).unwrap();
    assert!(matches!(cli.command.unwrap(),
        Command::Session(SessionCmd::Write(SessionWriteArgs { stdin: false, ref data_b64, .. }))
            if data_b64.as_deref() == Some("Yw==")
    ));
    let cli = Cli::try_parse_from(["qsh", "session", "write", "box/01K0", "--stdin"]).unwrap();
    assert!(matches!(
        cli.command.unwrap(),
        Command::Session(SessionCmd::Write(SessionWriteArgs {
            stdin: true,
            data_b64: None,
            ..
        }))
    ));

    // resize: both dimensions, 1..=65535.
    let cli = Cli::try_parse_from([
        "qsh", "session", "resize", "box/01K0", "--cols", "120", "--rows", "40",
    ])
    .unwrap();
    assert!(matches!(
        cli.command.unwrap(),
        Command::Session(SessionCmd::Resize {
            cols: 120,
            rows: 40,
            ..
        })
    ));
    assert!(
        Cli::try_parse_from(["qsh", "session", "resize", "box/01K0", "--cols", "120"]).is_err()
    );
    assert!(
        Cli::try_parse_from([
            "qsh", "session", "resize", "box/01K0", "--cols", "70000", "--rows", "1"
        ])
        .is_err()
    );

    // close: --signal is normalized to the canonical form or rejected
    // as a usage error (exit 2).
    for (given, canonical) in [
        ("term", "SIGTERM"),
        ("SIGKILL", "SIGKILL"),
        ("Hup", "SIGHUP"),
    ] {
        let cli = Cli::try_parse_from(["qsh", "session", "close", "box/01K0", "--signal", given])
            .unwrap();
        match cli.command.unwrap() {
            Command::Session(SessionCmd::Close { signal, .. }) => {
                assert_eq!(signal.as_deref(), Some(canonical), "{given}");
            }
            other => panic!("expected session close, got {other:?}"),
        }
    }
    for bad in ["STOP", "TSTP", "9", "nope"] {
        assert!(
            Cli::try_parse_from(["qsh", "session", "close", "box/01K0", "--signal", bad]).is_err(),
            "{bad}"
        );
    }

    // sessions [host]
    let cli = Cli::try_parse_from(["qsh", "sessions"]).unwrap();
    assert!(matches!(
        cli.command.unwrap(),
        Command::Sessions { host: None }
    ));
    let cli = Cli::try_parse_from(["qsh", "sessions", "box", "--json"]).unwrap();
    assert!(matches!(cli.command.unwrap(), Command::Sessions { host: Some(ref h) } if h == "box"));
}

/// The bare `qsh [user@]host` form and `qsh attach` (`docs/CLI.md` §7).
#[test]
fn the_interactive_forms_parse_per_cli_md() {
    // `qsh host` and `qsh user@host`, with the subcommand slot empty.
    let cli = Cli::try_parse_from(["qsh", "personal-mac"]).unwrap();
    assert!(cli.command.is_none());
    assert_eq!(
        cli.interactive.target,
        Some(Target {
            user: None,
            host: "personal-mac".into()
        })
    );
    assert_eq!(cli.interactive.escape_char, None);

    let cli = Cli::try_parse_from(["qsh", "dave@personal-mac", "-vv"]).unwrap();
    assert_eq!(
        cli.interactive.target,
        Some(Target {
            user: Some("dave".into()),
            host: "personal-mac".into()
        })
    );
    assert_eq!(cli.verbose, 2);

    // A subcommand name still wins over the positional.
    let cli = Cli::try_parse_from(["qsh", "sessions"]).unwrap();
    assert!(cli.interactive.target.is_none());
    assert!(matches!(cli.command, Some(Command::Sessions { .. })));

    // `--escape-char <c>|none`, on both interactive forms only.
    let cli = Cli::try_parse_from(["qsh", "box", "--escape-char", "none"]).unwrap();
    assert_eq!(cli.interactive.escape_char, Some(EscapeChar(None)));
    let cli = Cli::try_parse_from(["qsh", "box", "--escape-char", "^"]).unwrap();
    assert_eq!(cli.interactive.escape_char, Some(EscapeChar(Some(b'^'))));
    for bad in ["", "~~", "tilde", "é", " "] {
        assert!(
            Cli::try_parse_from(["qsh", "box", "--escape-char", bad]).is_err(),
            "{bad:?}"
        );
    }
    // Scoped to the interactive forms: a usage error anywhere else.
    assert!(Cli::try_parse_from(["qsh", "--escape-char", "none", "sessions"]).is_err());
    assert!(Cli::try_parse_from(["qsh", "--escape-char", "none"]).is_err());

    // `qsh attach <session-ref>` takes the same flag.
    let cli = Cli::try_parse_from(["qsh", "attach", "box/01K0", "--escape-char", "none"]).unwrap();
    match cli.command.unwrap() {
        Command::Attach(args) => {
            assert_eq!(args.session_ref, "box/01K0");
            assert_eq!(args.escape_char, Some(EscapeChar(None)));
        }
        other => panic!("expected attach, got {other:?}"),
    }
    assert!(Cli::try_parse_from(["qsh", "attach"]).is_err());
}

/// `[user@]host` splitting (`docs/CLI.md` §7): `user@` is a hint, and
/// the host half is what has to be there.
#[test]
fn target_parsing_splits_at_the_last_at_sign() {
    assert_eq!(
        parse_target("dave@box").unwrap(),
        Target {
            user: Some("dave".into()),
            host: "box".into()
        }
    );
    assert_eq!(
        parse_target("dave@corp@box").unwrap(),
        Target {
            user: Some("dave@corp".into()),
            host: "box".into()
        }
    );
    assert_eq!(
        parse_target("box").unwrap(),
        Target {
            user: None,
            host: "box".into()
        }
    );
    for bad in ["", "@box", "dave@", "@"] {
        assert!(parse_target(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn trust_add_requires_a_name_only() {
    let cli = Cli::try_parse_from(["qsh", "trust", "add", "mac"]).unwrap();
    match cli.command.unwrap() {
        Command::Trust(TrustCmd::Add(args)) => {
            assert_eq!(args.name, "mac");
            assert!(args.address.is_none() && args.fingerprint.is_none());
        }
        other => panic!("expected trust add, got {other:?}"),
    }
    assert!(Cli::try_parse_from(["qsh", "trust", "add"]).is_err());
}
