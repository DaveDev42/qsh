//! Argument parsing only. No business logic lives here — see `docs/CLI.md`
//! §11: this module's job ends at producing a [`Cli`] value for `main` to
//! dispatch on `qsh_core::Ops`.

use clap::{ArgAction, Args, Parser, Subcommand};
use qsh_proto::{EnvVar, KeyStoreMode};

/// QSH: a QUIC-based direct-connect remote shell.
#[derive(Debug, Parser)]
#[command(name = "qsh", version, about, propagate_version = true)]
pub struct Cli {
    /// Emit a single `qsh.cli/v1` JSON envelope on stdout instead of
    /// human-readable text.
    #[arg(long, global = true, conflicts_with = "jsonl")]
    pub json: bool,

    /// Emit newline-delimited JSON on stdout (reserved for streaming
    /// commands; non-streaming commands emit a single line, same as
    /// `--json`).
    #[arg(long, global = true, conflicts_with = "json")]
    pub jsonl: bool,

    /// Increase diagnostic verbosity on stderr (`-v` info, `-vv` debug,
    /// `-vvv` trace). Never affects stdout (`docs/CLI.md` §2.2).
    #[arg(short, long, global = true, action = ArgAction::Count, conflicts_with = "quiet")]
    pub verbose: u8,

    /// Suppress diagnostic output on stderr.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Whether either JSON output mode was requested.
    pub fn wants_json(&self) -> bool {
        self.json || self.jsonl
    }
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print qsh's version and the wire/CLI schemas it understands.
    Version,

    /// Create this device's identity (keypair + self-signed certificate).
    /// Idempotent: re-running reports the existing identity.
    Init {
        /// Where to keep the private key: `auto` (platform store, falling
        /// back to a 0600 file), `platform` or `file`. Defaults to
        /// `config.toml`'s `[identity].key_store`, then `auto`.
        #[arg(long, value_name = "MODE", value_parser = parse_key_store_mode)]
        key_store: Option<KeyStoreMode>,
    },

    /// Manage the trust store (pinned peers).
    #[command(subcommand)]
    Trust(TrustCmd),

    /// Run a command on a pinned host and return its output.
    ///
    /// The remote exit code becomes qsh's exit code (255 is clamped to
    /// 254); qsh's own failures exit 255. With `--json`, stdout/stderr are
    /// returned Base64-encoded in the envelope; otherwise they are passed
    /// through verbatim.
    Exec(ExecArgs),

    /// Manage sessions: shells that outlive the connection that opened them.
    #[command(subcommand)]
    Session(SessionCmd),

    /// List sessions on one pinned host, or on every pinned host.
    Sessions {
        /// Host alias from the trust store; omit for every host with an
        /// address.
        host: Option<String>,
    },

    /// Run the host: accept connections from pinned peers. Foreground only;
    /// the bound address is printed to stderr.
    Serve {
        /// Listen address (`ip:port`). Overrides `[serve].bind` in
        /// `config.toml`; defaults to `[::]:4433`.
        #[arg(long, value_name = "IP:PORT")]
        bind: Option<String>,
    },
}

/// Arguments of `qsh exec`.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Host alias from the trust store (`qsh trust list`).
    pub host: String,

    /// Give up with `TIMEOUT` if the command has not finished within this
    /// many milliseconds. The remote process is killed.
    #[arg(long, value_name = "MILLISECONDS")]
    pub timeout: Option<u64>,

    /// Extra environment variable for the remote command (`NAME=VALUE`).
    /// Repeatable.
    #[arg(long = "env", value_name = "NAME=VALUE", value_parser = parse_env_var)]
    pub env: Vec<EnvVar>,

    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub argv: Vec<String>,
}

/// clap value parser for `--env NAME=VALUE`.
fn parse_env_var(value: &str) -> Result<EnvVar, String> {
    match value.split_once('=') {
        Some((name, val)) if !name.is_empty() && !name.contains(char::is_whitespace) => {
            Ok(EnvVar {
                name: name.to_string(),
                value: val.to_string(),
            })
        }
        _ => Err(format!("expected NAME=VALUE, got {value:?}")),
    }
}

/// `qsh trust …` subcommands.
#[derive(Debug, Subcommand)]
pub enum TrustCmd {
    /// Pin a peer by name.
    Add(TrustAddArgs),
    /// List pinned peers.
    List,
    /// Remove a pinned peer. Idempotent.
    Remove {
        /// The peer alias to unpin.
        name: String,
    },
}

/// Arguments of `qsh trust add`.
#[derive(Debug, Args)]
pub struct TrustAddArgs {
    /// Local alias for the peer (also the `device:<name>` principal it
    /// authenticates as).
    pub name: String,

    /// `host:port` used to dial this peer. Required when `--fingerprint`
    /// is absent, since the fingerprint has to be observed from somewhere.
    #[arg(long, value_name = "HOST:PORT")]
    pub address: Option<String>,

    /// `sha256:BASE64` fingerprint. When given, the peer is pinned without
    /// connecting.
    #[arg(long, value_name = "FINGERPRINT")]
    pub fingerprint: Option<String>,
}

/// clap value parser for `--key-store`.
fn parse_key_store_mode(value: &str) -> Result<KeyStoreMode, String> {
    value.parse()
}

/// `qsh session …` subcommands (`docs/CLI.md` §6.2–6.7). Every command
/// takes the opaque `session_ref` returned by `session open` /
/// `sessions`; the CLI never takes it apart.
#[derive(Debug, Subcommand)]
pub enum SessionCmd {
    /// Create a session on a pinned host. Without a command after `--` the
    /// remote login shell is started.
    Open(SessionOpenArgs),
    /// Show one session.
    Get {
        /// Opaque session handle (`<host>/<session_id>`).
        session_ref: String,
    },
    /// Read session output after a cumulative byte offset.
    Read(SessionReadArgs),
    /// Inject input into a session.
    Write(SessionWriteArgs),
    /// Change a session's terminal size.
    Resize {
        /// Opaque session handle.
        session_ref: String,
        /// New terminal width (1..=65535).
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
        cols: u16,
        /// New terminal height (1..=65535).
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
        rows: u16,
    },
    /// Terminate a session's process group and remove the session.
    Close {
        /// Opaque session handle.
        session_ref: String,
        /// First signal of the HUP -> TERM -> KILL escalation
        /// (HUP|INT|QUIT|TERM|USR1|USR2|KILL, case-insensitive, `SIG`
        /// prefix optional).
        #[arg(long, value_name = "SIG", value_parser = parse_signal)]
        signal: Option<String>,
    },
}

/// Arguments of `qsh session open`.
#[derive(Debug, Args)]
pub struct SessionOpenArgs {
    /// Host alias from the trust store (`qsh trust list`).
    pub host: String,

    /// Extra environment variable for the session (`NAME=VALUE`).
    /// Repeatable.
    #[arg(long = "env", value_name = "NAME=VALUE", value_parser = parse_env_var)]
    pub env: Vec<EnvVar>,

    /// `TERM` to export in the session; defaults to the remote's choice.
    #[arg(long, value_name = "TERM")]
    pub term: Option<String>,

    /// Initial terminal width; defaults to the remote's choice.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
    pub cols: Option<u16>,

    /// Initial terminal height; defaults to the remote's choice.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
    pub rows: Option<u16>,

    /// The program and its arguments, after `--`. Omit for the login shell.
    #[arg(last = true, value_name = "COMMAND")]
    pub argv: Vec<String>,
}

/// Arguments of `qsh session read`.
#[derive(Debug, Args)]
pub struct SessionReadArgs {
    /// Opaque session handle.
    pub session_ref: String,

    /// Cumulative output byte offset already received; the reply starts
    /// right after it.
    #[arg(long, value_name = "SEQUENCE", default_value_t = 0)]
    pub after: u64,

    /// Long-poll: wait up to this many milliseconds for new output.
    #[arg(long, value_name = "MILLISECONDS")]
    pub wait: Option<u64>,

    /// Maximum output payload bytes in one reply (the host clamps to its
    /// own cap).
    #[arg(long, value_name = "BYTES")]
    pub limit_bytes: Option<u64>,

    /// Keep printing events until the session exits or is closed.
    #[arg(long)]
    pub follow: bool,
}

/// Arguments of `qsh session write`.
#[derive(Debug, Args)]
pub struct SessionWriteArgs {
    /// Opaque session handle.
    pub session_ref: String,

    /// Send this process's stdin, verbatim, until EOF.
    #[arg(
        long,
        conflicts_with = "data_b64",
        required_unless_present = "data_b64"
    )]
    pub stdin: bool,

    /// Send these bytes (standard Base64).
    #[arg(long, value_name = "BASE64")]
    pub data_b64: Option<String>,
}

/// clap value parser for `--signal`: canonical `SIGTERM` form, or a usage
/// error (exit 2, `docs/CLI.md` §6.7). The vocabulary lives in `qsh-core`
/// so the CLI never has its own list.
fn parse_signal(value: &str) -> Result<String, String> {
    qsh_core::broker::Signal::parse(value)
        .map(|s| s.as_str().to_string())
        .ok_or_else(|| {
            format!("unknown signal {value:?}; expected one of HUP|INT|QUIT|TERM|USR1|USR2|KILL")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn key_store_flag_parses_and_rejects_unknown_modes() {
        let cli = Cli::try_parse_from(["qsh", "init", "--key-store", "file"]).unwrap();
        match cli.command {
            Command::Init { key_store } => assert_eq!(key_store, Some(KeyStoreMode::File)),
            other => panic!("expected init, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["qsh", "init", "--key-store", "keychain"]).is_err());
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
        match cli.command {
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
        assert!(
            Cli::try_parse_from(["qsh", "exec", "box", "--env", "novalue", "--", "true"]).is_err()
        );
    }

    #[test]
    fn serve_bind_is_optional() {
        let cli = Cli::try_parse_from(["qsh", "serve"]).unwrap();
        assert!(matches!(cli.command, Command::Serve { bind: None }));
        let cli = Cli::try_parse_from(["qsh", "serve", "--bind", "127.0.0.1:0"]).unwrap();
        match cli.command {
            Command::Serve { bind } => assert_eq!(bind.as_deref(), Some("127.0.0.1:0")),
            other => panic!("expected serve, got {other:?}"),
        }
    }

    #[test]
    fn session_subcommands_parse_per_cli_md() {
        let cli = Cli::try_parse_from([
            "qsh", "session", "open", "box", "--env", "A=1", "--term", "xterm", "--cols", "80",
            "--rows", "24", "--json", "--", "claude", "--json",
        ])
        .unwrap();
        assert!(cli.wants_json());
        match cli.command {
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
        assert!(matches!(
            cli.command,
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
        match cli.command {
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
            cli.command,
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
            Cli::try_parse_from(["qsh", "session", "write", "box/01K0", "--data-b64", "Yw=="])
                .unwrap();
        assert!(matches!(
            cli.command,
            Command::Session(SessionCmd::Write(SessionWriteArgs { stdin: false, ref data_b64, .. }))
                if data_b64.as_deref() == Some("Yw==")
        ));
        let cli = Cli::try_parse_from(["qsh", "session", "write", "box/01K0", "--stdin"]).unwrap();
        assert!(matches!(
            cli.command,
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
            cli.command,
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
            let cli =
                Cli::try_parse_from(["qsh", "session", "close", "box/01K0", "--signal", given])
                    .unwrap();
            match cli.command {
                Command::Session(SessionCmd::Close { signal, .. }) => {
                    assert_eq!(signal.as_deref(), Some(canonical), "{given}");
                }
                other => panic!("expected session close, got {other:?}"),
            }
        }
        for bad in ["STOP", "TSTP", "9", "nope"] {
            assert!(
                Cli::try_parse_from(["qsh", "session", "close", "box/01K0", "--signal", bad])
                    .is_err(),
                "{bad}"
            );
        }

        // sessions [host]
        let cli = Cli::try_parse_from(["qsh", "sessions"]).unwrap();
        assert!(matches!(cli.command, Command::Sessions { host: None }));
        let cli = Cli::try_parse_from(["qsh", "sessions", "box", "--json"]).unwrap();
        assert!(matches!(cli.command, Command::Sessions { host: Some(ref h) } if h == "box"));
    }

    #[test]
    fn trust_add_requires_a_name_only() {
        let cli = Cli::try_parse_from(["qsh", "trust", "add", "mac"]).unwrap();
        match cli.command {
            Command::Trust(TrustCmd::Add(args)) => {
                assert_eq!(args.name, "mac");
                assert!(args.address.is_none() && args.fingerprint.is_none());
            }
            other => panic!("expected trust add, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["qsh", "trust", "add"]).is_err());
    }
}
