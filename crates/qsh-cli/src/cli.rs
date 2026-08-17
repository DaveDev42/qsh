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
