//! Argument parsing only. No business logic lives here — see `docs/CLI.md`
//! §11: this module's job ends at producing a [`Cli`] value for `main` to
//! dispatch on `qsh_core::Ops`.

use clap::{ArgAction, Args, Parser, Subcommand};
use qsh_proto::{EnvVar, KeyStoreMode};

/// QSH: a QUIC-based direct-connect remote shell.
#[derive(Debug, Parser)]
#[command(
    name = "qsh",
    version,
    about,
    propagate_version = true,
    arg_required_else_help = true
)]
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
    pub command: Option<Command>,

    /// The bare `qsh [user@]host` form (`docs/CLI.md` §7): open a session
    /// on a pinned host and attach to it interactively.
    #[command(flatten)]
    pub interactive: InteractiveArgs,
}

impl Cli {
    /// Whether either JSON output mode was requested.
    pub fn wants_json(&self) -> bool {
        self.json || self.jsonl
    }
}

/// The root-level arguments of the interactive form, `qsh [user@]host`.
///
/// `--escape-char` and `-L` both `requires` the target, so either is a
/// clap usage error (exit `2`) on any other command — `docs/CLI.md` §7
/// scopes `--escape-char` to `qsh [user@]host` and `qsh attach`, and `-L`
/// to `qsh [user@]host` alone (the standalone tunnel form is
/// `qsh tunnel open`, §6.9).
#[derive(Debug, Args)]
pub struct InteractiveArgs {
    /// Pinned host to open an interactive session on, optionally prefixed
    /// with the expected remote login name (`dave@personal-mac`).
    #[arg(value_name = "[USER@]HOST", value_parser = parse_target)]
    pub target: Option<Target>,

    /// Escape character for the line-start detach sequences (`~d`, `~.`,
    /// `~~`, `~?`), or `none` to disable them. Default `~`; only active
    /// when stdin is a terminal.
    #[arg(long, value_name = "CHAR", value_parser = parse_escape_char, requires = "target")]
    pub escape_char: Option<EscapeChar>,

    /// Local forward `[bind:]listen_port:host:host_port`, repeatable:
    /// open `listen_port` on this machine and forward each connection to
    /// `host:host_port` as seen from the peer. `bind` defaults to (and is
    /// restricted to) loopback.
    ///
    /// The listener lives exactly as long as this interactive session and
    /// dies with the process (`docs/CLI.md` §6.14) — there is no daemon
    /// and nothing to close.
    ///
    /// Deliberately **not** parsed by a clap `value_parser`: a malformed
    /// spec is an `INVALID_ARGUMENT` operation error (exit `255`, with a
    /// `qsh.cli/v1` envelope in machine mode), not a clap usage error
    /// (exit `2`), and `qsh_core::parse_local_forwards` is the single
    /// place that decides which code a spec earns (`docs/CLI.md` §6.9).
    #[arg(
        short = 'L',
        value_name = "SPEC",
        action = ArgAction::Append,
        requires = "target"
    )]
    pub local_forward: Vec<String>,

    /// Remote forward `[bind:]rport:host:hport`, repeatable: ask the peer
    /// to bind `rport` (loopback-only — `docs/PRD.md` §9) and forward each
    /// connection it accepts back to `host:hport` **on this machine**
    /// (`docs/CLI.md` §6.9). The two legs are swapped relative to `-L`;
    /// see [`Self::local_forward`]'s own doc for the lifecycle this shares
    /// with it — same holder, same teardown, no daemon.
    ///
    /// Same reasoning as [`Self::local_forward`] for not being a clap
    /// `value_parser`: `qsh_core::parse_remote_forwards` decides the
    /// `docs/CLI.md` §3.3 code, not clap's usage-error path.
    #[arg(
        short = 'R',
        value_name = "SPEC",
        action = ArgAction::Append,
        requires = "target"
    )]
    pub remote_forward: Vec<String>,

    /// SOCKS5 dynamic forwarding `[bind:]port`, repeatable: open a SOCKS5
    /// proxy on this machine and, for every CONNECT a SOCKS client sends
    /// it, forward to whatever destination that CONNECT names, as seen
    /// from the peer (ADR-0019). `bind` defaults to (and is restricted
    /// to) loopback, same as `-L`/`-R`.
    ///
    /// Every listener this flag opens lives exactly as long as this
    /// interactive session and dies with the process, same lifecycle as
    /// `-L` (`docs/CLI.md` §6.14) — there is no daemon and nothing to
    /// close.
    ///
    /// There is no ACL check at open time: each CONNECT is authorized on
    /// the peer as `forward.local`, the same action `-L` uses.
    /// `DYNAMIC_FORWARD_ACL_NOTE` — "`-D` runs SOCKS5 on this machine and
    /// authorizes every CONNECT on the peer as `forward.local`;
    /// `forward.socks` is never consulted." Works over both forward and
    /// reverse routes (ADR-0020 decisions 1–3) — a reverse route relays
    /// each CONNECT through this machine's resident `qsh listen` daemon,
    /// with the same host-local address filter a forward route enforces.
    /// The one refusal left is `UNSUPPORTED` before anything binds when
    /// the connected route never negotiated `dial-filter.v1`; on a
    /// reverse route the message names both possible causes (the
    /// target's qsh may predate the capability, or this machine's own
    /// `qsh listen` daemon may have started before this machine's own
    /// upgrade) (`docs/CLI.md` §6.9).
    ///
    /// With `--json`/`--jsonl` also given, §7's machine-mode gate answers
    /// `INVALID_ARGUMENT` before this flag is looked at at all — the
    /// interactive form has no JSON output mode of its own.
    ///
    /// Not shape-checked here for the same reason as
    /// [`Self::local_forward`]/[`Self::remote_forward`]:
    /// `qsh_core::parse_dynamic_forwards` is the single place that decides
    /// which `docs/CLI.md` §3.3 code a malformed spec earns.
    #[arg(
        short = 'D',
        value_name = "SPEC",
        action = ArgAction::Append,
        requires = "target"
    )]
    pub dynamic_forward: Vec<String>,
}

/// A parsed `[user@]host` target (`docs/CLI.md` §7).
///
/// `user` is a *hint*, never an identity: the remote shell always runs as
/// the account that runs `qsh serve`, and the host answers `UNSUPPORTED`
/// when the hint names a different login (PRD §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The `user@` half, if given.
    pub user: Option<String>,
    /// Host alias from the trust store.
    pub host: String,
}

/// clap value parser for the `[user@]host` positional.
fn parse_target(value: &str) -> Result<Target, String> {
    // Split at the *last* `@`, like ssh: an alias may not contain one, but
    // a user name conceivably does.
    let (user, host) = match value.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, value),
    };
    if host.is_empty() {
        return Err(format!("expected [user@]host, got {value:?}"));
    }
    if user.is_some_and(str::is_empty) {
        return Err(format!("empty user in {value:?}"));
    }
    Ok(Target {
        user: user.map(str::to_string),
        host: host.to_string(),
    })
}

/// The escape character of an interactive session, or `None` when escape
/// processing is off (`--escape-char none`, `docs/CLI.md` §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscapeChar(pub Option<u8>);

/// The default escape character (`~`), matching ssh.
pub const DEFAULT_ESCAPE_CHAR: EscapeChar = EscapeChar(Some(b'~'));

/// clap value parser for `--escape-char <c>|none`: a single printable
/// ASCII character, or `none`. Anything else is a usage error (exit `2`,
/// `docs/CLI.md` §7).
fn parse_escape_char(value: &str) -> Result<EscapeChar, String> {
    if value == "none" {
        return Ok(EscapeChar(None));
    }
    let mut bytes = value.bytes();
    match (bytes.next(), bytes.next()) {
        (Some(c), None) if c.is_ascii_graphic() => Ok(EscapeChar(Some(c))),
        _ => Err(format!(
            "expected a single printable ASCII character or \"none\", got {value:?}"
        )),
    }
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print qsh's version and the wire/CLI schemas it understands.
    Version,

    /// Print the JSON Schema of the `qsh.cli/v1` envelope and every
    /// command's `data` payload (`docs/CLI.md` §6.10) — the same schemas
    /// golden fixtures are validated against.
    Schema,

    /// Print this build's supported capabilities, or (with a host) the
    /// capabilities actually negotiated with that pinned peer
    /// (`docs/CLI.md` §6.10).
    Capabilities {
        /// Pinned host to dial and negotiate with; omit for this build's
        /// own local/static supported set.
        host: Option<String>,
    },

    /// Diagnose this deployment: identity, ACL policy, audit log, trust
    /// store, clock and (best-effort) network reachability
    /// (`docs/CLI.md` §6.17). Always exits `0` on a successful run —
    /// findings are reported as data, not exit status (`overall` field);
    /// only doctor's own inability to run at all (e.g. no identity yet)
    /// fails the command.
    Doctor {
        /// Additional pinned host to probe connectivity for, beyond
        /// whatever `[reverse].controller` names.
        host: Option<String>,
    },

    /// Create this device's identity (keypair + self-signed certificate).
    /// Idempotent: re-running reports the existing identity.
    Init {
        /// Where to keep the private key: `auto` (platform store, falling
        /// back to a 0600 file), `platform` or `file`. Defaults to
        /// `config.toml`'s `[identity].key_store`, then `auto`.
        #[arg(long, value_name = "MODE", value_parser = parse_key_store_mode)]
        key_store: Option<KeyStoreMode>,
    },

    /// Manage this device's own identity (`docs/CLI.md` §6.11).
    #[command(subcommand)]
    Identity(IdentityCmd),

    /// Manage the trust store (pinned peers).
    #[command(subcommand)]
    Trust(TrustCmd),

    /// Pair with another device: mint an invite on one side, redeem it on
    /// the other (ADR-0002, ADR-0012 decision 3, `docs/CLI.md` §6.11). This is
    /// the documented spelling for creating a new trust entry by pairing;
    /// `trust …` stays the vocabulary for manipulating entries that already
    /// exist.
    #[command(subcommand)]
    Pair(PairCmd),

    /// Manage the private CA (`docs/adr/0008-private-ca-cert-issuance.md`).
    #[command(subcommand)]
    Cert(CertCmd),

    /// Inspect the ACL policy (`docs/CLI.md` §6.15).
    #[command(subcommand)]
    Acl(AclCmd),

    /// List every host visible to this machine: trust-store-pinned forward
    /// hosts and this machine's live reverse registrations, together
    /// (`docs/CLI.md` §6.1). Never dials.
    Hosts,

    /// Look up one host.
    #[command(subcommand)]
    Host(HostCmd),

    /// Run a command on a pinned host and return its output.
    ///
    /// The remote exit code becomes qsh's exit code (255 is clamped to
    /// 254); qsh's own failures exit 255. With `--json`, stdout/stderr are
    /// returned Base64-encoded in the envelope; otherwise they are passed
    /// through verbatim.
    Exec(ExecArgs),

    /// Re-attach this terminal to a session that is already running.
    ///
    /// Only possible from the device that opened the session, whose resume
    /// credential is bound to it (`docs/CLI.md` §6.2, §7). Detach with the
    /// escape sequence `~d`; the session keeps running.
    Attach(AttachArgs),

    /// Manage sessions: shells that outlive the connection that opened them.
    #[command(subcommand)]
    Session(SessionCmd),

    /// List sessions on one pinned host, or on every pinned host.
    Sessions {
        /// Host alias from the trust store; omit for every host with an
        /// address.
        host: Option<String>,
    },

    /// Run the host: accept connections from pinned peers, or (with
    /// `--to`) dial out and register as a reverse target instead
    /// (`docs/CLI.md` §6.12/§6.13, ADR-0012 decision 2/4). Foreground
    /// only; the bound address, or the dial/registration events, go to
    /// stderr.
    Serve {
        // Precedent for not using a clap `value_parser`/`conflicts_with`
        // here: `crate::serve::resolve_serve_mode` decides the
        // outbound-vs-inbound choice in `qsh-core`, not clap — same shape
        // as this struct's `-L` doc a few lines up.
        /// Listen address (`ip:port`). Overrides `[serve].bind` in
        /// `config.toml`; defaults to `[::]:4433`. Mutually exclusive with
        /// `--to` — both given is `INVALID_ARGUMENT` (exit `255`, not a
        /// clap usage error).
        #[arg(long, value_name = "IP:PORT")]
        bind: Option<String>,

        /// Dial this controller and register as a reverse target instead
        /// of listening inbound — the same role `qsh reverse <controller>`
        /// plays, reached under its new name (ADR-0012 decision 2/4). A
        /// trust-store alias, same as `qsh reverse`'s positional, or a
        /// bare `host[:port]` address that resolves against pinned peers
        /// by normalized address when no name matches (ADR-0014 decision
        /// 7). Wins over `[serve].to` and the legacy
        /// `[reverse].controller` config keys, which are not read at all
        /// when this is given. The former `qsh reverse <controller>`
        /// spelling still works as a hidden alias — no deprecation
        /// warning, no scheduled removal.
        #[arg(long, value_name = "LISTENER|HOST:PORT")]
        to: Option<String>,

        /// Name to register under when `--to` is given. Only takes effect
        /// when the controller has no trust-store alias for this peer and
        /// its `[listen].allow_advertised_names` is set; otherwise the
        /// controller assigns the name from its own trust store, ignoring
        /// this (same rule as `qsh reverse --offered-name`). Given without
        /// `--to` is `INVALID_ARGUMENT` — a name is only meaningful
        /// outbound, so this fails closed rather than silently ignoring
        /// it.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },

    /// Run the reverse-mode controller: accept dial-in registrations from
    /// `qsh serve --to` (the hidden `qsh reverse` alias dials the same
    /// way) and serve them as hosts (`docs/CLI.md` §6.13). Foreground
    /// only; the bound address and registration events go to stderr.
    Listen {
        /// Listen address (`ip:port`). Overrides `[listen].bind` in
        /// `config.toml`; defaults to `[::]:4433` — the same default as
        /// `qsh serve`, so running both roles on one host needs an
        /// explicit `--bind` on at least one of them.
        #[arg(long, value_name = "IP:PORT")]
        bind: Option<String>,
    },

    /// Manage tunnels (`docs/CLI.md` §6.9).
    #[command(subcommand)]
    Tunnel(TunnelCmd),

    /// List every tunnel this machine's resident `qsh listen` daemon(s)
    /// currently hold (`docs/CLI.md` §6.9, `tunnel.list`). Never dials.
    /// A forward-route tunnel opened by a standalone `qsh tunnel open`
    /// process is not visible here — it has no resident holder to be
    /// listed by (`Ops::tunnel_list`'s own doc).
    Tunnels,

    /// Dial `<controller>` and register this device as a reverse target,
    /// and keep it registered, redialing with backoff when the link drops
    /// (`docs/CLI.md` §6.13). On success this process serves the connection
    /// as a host, the same broker/writer-lease discipline as `qsh serve`.
    ///
    /// Hidden from `qsh --help`'s `Commands:` block (ADR-0012 decision 2/4):
    /// `qsh serve --to <controller>` is the spelling documented from this
    /// rename on (ROADMAP M9 (b)). This form still parses and still works, silently, with
    /// no deprecation warning — `hide` only removes it from the parent's
    /// listing, not from the CLI (`qsh reverse --help` still renders this
    /// subcommand's own help in full).
    #[command(hide = true)]
    Reverse {
        /// Trust-store alias of the controller to dial (`qsh trust list`).
        controller: String,

        /// Name to register under. Only takes effect when the controller
        /// has no trust-store alias for this peer and its
        /// `[listen].allow_advertised_names` is set; otherwise the
        /// controller assigns the name from its own trust store, ignoring
        /// this. Defaults to `[reverse].offered_name`, then this device's
        /// identity.
        #[arg(long, value_name = "NAME")]
        offered_name: Option<String>,
    },
}

/// `qsh tunnel …` subcommands (`docs/CLI.md` §6.9).
#[derive(Debug, Subcommand)]
pub enum TunnelCmd {
    /// Open a tunnel to a pinned host and hold it open.
    ///
    /// This is a *value* operation that then blocks: the `Tunnel` envelope
    /// is emitted once, and the tunnel lives for as long as this
    /// foreground process does (`docs/CLI.md` §6.14). Ctrl-C ends it.
    Open(TunnelOpenArgs),

    /// Close a tunnel by id (`docs/CLI.md` §6.9, `tunnel.close`).
    ///
    /// Only ever reaches a daemon-held reverse-route (`-R over reverse`)
    /// forward — a forward-route tunnel's only "close" is its holding
    /// process exiting (`docs/CLI.md` §6.14). Idempotent: closing an id
    /// nothing currently holds answers `closed: false`, not an error.
    Close {
        /// The `tunnel_id` from that tunnel's `tunnel.open`/`tunnels`
        /// entry.
        tunnel_id: String,
    },
}

/// Arguments of `qsh tunnel open`.
///
/// Bare host only — no `user@` (`docs/CLI.md` §7: this form sends no
/// `SessionOpen`, so there is no login hint to carry).
#[derive(Debug, Args)]
pub struct TunnelOpenArgs {
    /// Host alias from the trust store (`qsh trust list`).
    pub host: String,

    /// Local forward `[bind:]listen_port:host:host_port` — same grammar
    /// as the interactive `-L` (`docs/CLI.md` §6.9). Exactly one of
    /// `--local`/`--remote`/`--dynamic` is required.
    #[arg(
        short = 'L',
        long,
        value_name = "SPEC",
        conflicts_with = "remote",
        required_unless_present_any = ["remote", "dynamic"]
    )]
    pub local: Option<String>,

    /// Remote forward `[bind:]rport:host:hport` — same grammar as the
    /// interactive `-R` (`docs/CLI.md` §6.9). Exactly one of
    /// `--local`/`--remote`/`--dynamic` is required.
    #[arg(
        short = 'R',
        long,
        value_name = "SPEC",
        conflicts_with = "local",
        required_unless_present_any = ["local", "dynamic"]
    )]
    pub remote: Option<String>,

    /// SOCKS5 dynamic forwarding `[bind:]port`: open a SOCKS5 proxy on
    /// this machine and, for every CONNECT a SOCKS client sends it,
    /// forward to whatever destination that CONNECT names, as seen from
    /// the peer (ADR-0019). Exactly one of `--local`/`--remote`/`--dynamic`
    /// is required, and `--dynamic` conflicts with the other two — a
    /// single `tunnel open` call opens exactly one listener.
    ///
    /// Still `Vec<String>`/`ArgAction::Append` so the value can be given
    /// more than once on the command line, but only ever one listener is
    /// meant to result: giving `--dynamic` twice is refused with
    /// `INVALID_ARGUMENT` ("one listener per `tunnel open`"), not silently
    /// collapsed to the first or last value.
    ///
    /// There is no ACL check at open time: each CONNECT is authorized on
    /// the peer as `forward.local`, the same action `--local` uses.
    /// `DYNAMIC_FORWARD_ACL_NOTE` — "`-D` runs SOCKS5 on this machine and
    /// authorizes every CONNECT on the peer as `forward.local`;
    /// `forward.socks` is never consulted." Works over both forward and
    /// reverse routes (ADR-0020 decisions 1–3) — a reverse route relays
    /// each CONNECT through this machine's resident `qsh listen` daemon,
    /// with the same host-local address filter a forward route enforces.
    /// The one refusal left is `UNSUPPORTED` before anything binds when
    /// the connected route never negotiated `dial-filter.v1`; on a
    /// reverse route the message names both possible causes (the
    /// target's qsh may predate the capability, or this machine's own
    /// `qsh listen` daemon may have started before this machine's own
    /// upgrade) (`docs/CLI.md` §6.9).
    #[arg(
        short = 'D',
        long,
        value_name = "SPEC",
        action = ArgAction::Append,
        conflicts_with_all = ["local", "remote"]
    )]
    pub dynamic: Vec<String>,

    /// Milliseconds to keep retrying the initial route resolution while
    /// it answers the reverse-registration-stale branch. `0` (the
    /// default) is one attempt, unchanged from before this flag existed.
    /// Applies to `--local`/`--remote` only — combining it with
    /// `--dynamic` is a clap usage error. Bound `0..=600000`; above it is
    /// `INVALID_ARGUMENT`. Full semantics: `docs/CLI.md` §6.9.
    #[arg(
        long,
        value_name = "MS",
        default_value_t = 0,
        conflicts_with = "dynamic"
    )]
    pub wait: u32,
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

/// Arguments of `qsh attach`.
#[derive(Debug, Args)]
pub struct AttachArgs {
    /// Opaque session handle (`<host>/<session_id>`) from `session open`
    /// or `sessions`.
    pub session_ref: String,

    /// Escape character for the line-start detach sequences, or `none`.
    /// Default `~`; only active when stdin is a terminal.
    #[arg(long, value_name = "CHAR", value_parser = parse_escape_char)]
    pub escape_char: Option<EscapeChar>,
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

/// `qsh cert …` subcommands (`docs/adr/0008-private-ca-cert-issuance.md`).
/// Both are local-only and idempotent — neither dials, and neither takes a
/// `device_id`: `cert issue` always promotes this device's own identity
/// (ADR §5).
#[derive(Debug, Subcommand)]
pub enum CertCmd {
    /// Create the local private CA root (self-signed, `is_ca`). Idempotent:
    /// re-running reports the existing root.
    Init,
    /// CA-sign this device's existing identity and register the CA root in
    /// `trust.toml`. Idempotent: re-running after this device is already
    /// CA-issued reports `issued: false` rather than rotating the leaf.
    Issue,
}

/// `qsh identity …` subcommands.
#[derive(Debug, Subcommand)]
pub enum IdentityCmd {
    /// Print this device's certificate as PEM, never its private key
    /// (`docs/CLI.md` §6.11, ADR-0013). Without `--out`, the PEM is the
    /// only thing this command writes to stdout, so it pipes directly
    /// into `qsh trust add --cert-file -` on another host.
    Export(IdentityExportArgs),
}

/// Arguments of `qsh identity export`.
#[derive(Debug, Args)]
pub struct IdentityExportArgs {
    /// Write the certificate to this path instead of stdout. Refuses to
    /// overwrite an existing file.
    #[arg(long, value_name = "PATH")]
    pub out: Option<String>,
}

/// `qsh trust …` subcommands.
#[derive(Debug, Subcommand)]
pub enum TrustCmd {
    /// Pin a peer by name.
    Add(TrustAddArgs),
    /// Register a foreign CA root supplied as a certificate file
    /// (`docs/CLI.md` §6.11, ADR-0013). Append-only: an existing name
    /// under a different certificate is refused rather than overwritten.
    AddCa(TrustAddCaArgs),
    /// List pinned peers.
    List,
    /// Remove a pinned peer. Idempotent.
    Remove {
        /// The peer alias to unpin.
        name: String,
    },
    /// Mint a one-time invite code for another device to pair with this one
    /// (ADR-0002, `docs/CLI.md` §6.11).
    ///
    /// Kept for v1 as the pre-rename spelling of `qsh pair invite`; hidden
    /// from `qsh trust --help`'s listing but still parses and still works,
    /// silently, with no deprecation warning (`qsh trust invite --help`
    /// still renders this subcommand's own help in full).
    #[command(hide = true)]
    Invite {
        /// Assign the redeeming peer's trust-store name up front, instead
        /// of letting it self-assert one at pairing time (`docs/CLI.md`
        /// §6.11, ADR-0012 decision 6).
        #[arg(long = "as", value_name = "NAME")]
        as_name: Option<String>,
    },
    /// Dial `address`, redeem `code` against its invite, and — on a
    /// successful mutual proof — pin the peer exactly as `trust add` would
    /// (ADR-0002, `docs/CLI.md` §6.11).
    ///
    /// Kept for v1 as the pre-rename spelling of `qsh pair accept`; hidden
    /// from `qsh trust --help`'s listing but still parses and still works,
    /// silently, with no deprecation warning (`qsh trust accept --help`
    /// still renders this subcommand's own help in full).
    #[command(hide = true)]
    Accept {
        /// `host:port` of the device that printed `code` via `pair invite`.
        /// With no `:port`, port 4433 is assumed.
        address: String,
        /// The invite code, as printed (case-insensitive, hyphens ignored).
        ///
        /// Optional. With no code here and no `--code-stdin`, a terminal is
        /// prompted for it with echo off, and `--json`/`--jsonl` returns
        /// INVALID_ARGUMENT instead of prompting.
        ///
        /// A fingerprint is a public value, so `trust add --fingerprint` left
        /// in shell history is not a risk. A code left in history has no
        /// reuse value either: an invite is single-use and stops being
        /// redeemable 10 minutes after `pair invite` mints it.
        code: Option<String>,
        /// Read the invite code from standard input, to end of input,
        /// ignoring leading and trailing whitespace. Use this instead of the
        /// positional code to keep it out of shell history.
        ///
        /// If standard input is a terminal, echo is suppressed the same way
        /// it is for the prompt, and `--json`/`--jsonl` still refuses
        /// rather than waiting on it: pipe or redirect the code in for
        /// machine mode.
        #[arg(long, conflicts_with = "code")]
        code_stdin: bool,
        /// Pin the redeemed peer under this name instead of its self-
        /// asserted one (`docs/CLI.md` §6.11, ADR-0012 decision 6).
        #[arg(long = "as", value_name = "NAME")]
        as_name: Option<String>,
    },
    /// Rename a pinned peer (`docs/CLI.md` §6.11). Takes effect at the next
    /// handshake with no restart required. `acl.toml` is not reloaded: until
    /// `qsh serve`/`qsh listen` restarts with a row for the new name, the
    /// renamed peer matches no row and is denied (default-deny); rows naming
    /// the old principal no longer apply to it.
    Rename {
        /// The peer's current trust-store name.
        old: String,
        /// The name to rename it to.
        new: String,
    },
}

/// `qsh pair …` subcommands — creating a new trust entry by pairing
/// (`docs/CLI.md` §6.11, ADR-0012 decision 3). The pre-rename spellings
/// (`qsh trust invite`/`qsh trust accept`) are kept, hidden, as strict
/// equivalents.
#[derive(Debug, Subcommand)]
pub enum PairCmd {
    /// Mint a one-time invite code for another device to pair with this one
    /// (ADR-0002, `docs/CLI.md` §6.11). Human mode also lists the source
    /// addresses this host's own routing table picks, as candidates for the
    /// `<address>` placeholder in the printed `qsh pair accept` line — a
    /// routing observation, never a reachability check, and the operator
    /// still relays the chosen one out of band. `--json`/`--jsonl` makes no
    /// such observation and the envelope carries no address.
    Invite {
        /// Assign the redeeming peer's trust-store name up front, instead
        /// of letting it self-assert one at pairing time (`docs/CLI.md`
        /// §6.11, ADR-0012 decision 6).
        #[arg(long = "as", value_name = "NAME")]
        as_name: Option<String>,
    },
    /// Dial `address`, redeem `code` against its invite, and — on a
    /// successful mutual proof — pin the peer exactly as `trust add` would
    /// (ADR-0002, `docs/CLI.md` §6.11).
    Accept {
        /// `host:port` of the device that printed `code` via `pair invite`.
        /// With no `:port`, port 4433 is assumed.
        address: String,
        /// The invite code, as printed (case-insensitive, hyphens ignored).
        ///
        /// Optional. With no code here and no `--code-stdin`, a terminal is
        /// prompted for it with echo off, and `--json`/`--jsonl` returns
        /// INVALID_ARGUMENT instead of prompting.
        ///
        /// A fingerprint is a public value, so `trust add --fingerprint` left
        /// in shell history is not a risk. A code left in history has no
        /// reuse value either: an invite is single-use and stops being
        /// redeemable 10 minutes after `pair invite` mints it.
        code: Option<String>,
        /// Read the invite code from standard input, to end of input,
        /// ignoring leading and trailing whitespace. Use this instead of the
        /// positional code to keep it out of shell history.
        ///
        /// If standard input is a terminal, echo is suppressed the same way
        /// it is for the prompt, and `--json`/`--jsonl` still refuses
        /// rather than waiting on it: pipe or redirect the code in for
        /// machine mode.
        #[arg(long, conflicts_with = "code")]
        code_stdin: bool,
        /// Pin the redeemed peer under this name instead of its self-
        /// asserted one (`docs/CLI.md` §6.11, ADR-0012 decision 6). When
        /// omitted in human mode, the pinned self-asserted name is printed
        /// after the pin succeeds, along with a suggested label derived
        /// from `address` when it has a hostname (never for an IP literal).
        #[arg(long = "as", value_name = "NAME")]
        as_name: Option<String>,
    },
}

/// `qsh acl …` subcommands (`docs/CLI.md` §6.15).
#[derive(Debug, Subcommand)]
pub enum AclCmd {
    /// Evaluate this machine's own `acl.toml` against a hypothetical
    /// request, using the exact same evaluator `qsh serve`/`qsh listen`/
    /// `qsh reverse` enforce with — a reliable prediction of what
    /// enforcement would decide, without a restart.
    /// Local only: never reaches a remote peer (`docs/CLI.md` §6.15).
    Check(AclCheckArgs),
}

/// Arguments of `qsh acl check` (`docs/CLI.md` §6.15).
#[derive(Debug, Args)]
pub struct AclCheckArgs {
    /// Principal string to evaluate: `device:<name>` | `user:<name>` |
    /// `fp:sha256:<base64>` (`docs/PRD.md` §9). A shape outside this
    /// vocabulary is `INVALID_ARGUMENT`.
    #[arg(long, value_name = "PRINCIPAL")]
    pub principal: String,

    /// Dotted action, one of the 11 PRD §9 actions (e.g. `session.open`).
    /// A name outside the vocabulary is `INVALID_ARGUMENT`.
    #[arg(long, value_name = "ACTION")]
    pub action: String,

    /// Resource identifier the action would target. Omit to evaluate an
    /// unowned resource.
    #[arg(long, value_name = "RESOURCE")]
    pub resource: Option<String>,

    /// Auth path the principal is assumed to have authenticated over.
    /// Omit to use `acl.toml`'s own default (`"pin"`).
    #[arg(long = "auth-path", value_name = "pin|ca")]
    pub auth_path: Option<String>,

    /// Principal that owns `--resource`, so `scope = "owned"` rows can be
    /// evaluated too (`docs/CLI.md` §6.15). Omit to evaluate `--resource` as
    /// unowned.
    #[arg(long, value_name = "PRINCIPAL")]
    pub owner: Option<String>,

    /// Auth path `--owner` is assumed to have authenticated over. Only
    /// meaningful together with `--owner`; omit to default to `"pin"`.
    /// `requires = "owner"` mirrors [`InteractiveArgs::escape_char`]'s own
    /// `requires = "target"` (`docs/CLI.md` §6.15): giving this alone is a
    /// clap usage error (exit `2`), not a silently-ignored no-op.
    #[arg(long = "owner-auth-path", value_name = "pin|ca", requires = "owner")]
    pub owner_auth_path: Option<String>,
}

/// `qsh host …` subcommands (`docs/CLI.md` §6.1).
#[derive(Debug, Subcommand)]
pub enum HostCmd {
    /// Resolve one host name to the route this machine would actually use
    /// for it — live reverse registration if there is one, else the
    /// forward pin, else `HOST_NOT_FOUND` (`docs/CLI.md` §6.1).
    Get {
        /// Host alias.
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
    /// With no `:port`, port 4433 is assumed and the pin is stored with it.
    #[arg(long, value_name = "HOST[:PORT]")]
    pub address: Option<String>,

    /// `sha256:BASE64` fingerprint. When given, the peer is pinned without
    /// connecting. Mutually exclusive with `--cert-file`.
    #[arg(long, value_name = "FINGERPRINT")]
    pub fingerprint: Option<String>,

    /// Path to a PEM file holding exactly one `CERTIFICATE` block (as
    /// `qsh identity export` prints), or `-` to read it from standard
    /// input. The peer's fingerprint is derived from it and the peer is
    /// pinned without connecting. Mutually exclusive with `--fingerprint`
    /// (`docs/CLI.md` §6.11, ADR-0013).
    #[arg(long, value_name = "PEM|-")]
    pub cert_file: Option<String>,
}

/// Arguments of `qsh trust add-ca`.
#[derive(Debug, Args)]
pub struct TrustAddCaArgs {
    /// Local name for the CA root.
    pub name: String,

    /// Path to a PEM file holding exactly one `CERTIFICATE` block, or `-`
    /// to read it from standard input.
    #[arg(long, value_name = "PEM|-")]
    pub cert_file: String,
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

    /// Control-entry cursor: the `next_ctl_after` of the previous reply.
    /// Control events do not advance `--after`, so a poller that omits this
    /// is handed the control event sitting at `--after` on every pull.
    #[arg(long, value_name = "ID", default_value_t = 0)]
    pub ctl_after: u64,

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
mod tests;
