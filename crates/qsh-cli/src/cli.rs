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

    /// SOCKS5 dynamic forwarding `[bind:]port`, repeatable. Parses, but
    /// P0 always refuses it with `UNSUPPORTED` before this session (or
    /// anything else on the command line) is opened — implementation is
    /// P1 (`docs/CLI.md` §6.9, `docs/ROADMAP.md` M4 "명시적 out").
    ///
    /// Not shape-checked here for the same reason as
    /// [`Self::local_forward`]/[`Self::remote_forward`]: the refusal is
    /// unconditional, so there is nothing a `value_parser` could reject
    /// that this flag's own handling would not refuse anyway.
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

    /// Run the host: accept connections from pinned peers. Foreground only;
    /// the bound address is printed to stderr.
    Serve {
        /// Listen address (`ip:port`). Overrides `[serve].bind` in
        /// `config.toml`; defaults to `[::]:4433`.
        #[arg(long, value_name = "IP:PORT")]
        bind: Option<String>,
    },

    /// Run the reverse-mode controller: accept dial-in registrations from
    /// `qsh reverse` and serve them as hosts (`docs/CLI.md` §6.13).
    /// Foreground only; the bound address and registration events go to
    /// stderr.
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
    /// once — no reconnect loop yet (`docs/CLI.md` §6.13). On success this
    /// process serves the connection as a host, the same broker/writer-lease
    /// discipline as `qsh serve`.
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

    /// Serve MCP tools over stdio (`docs/CLI.md` §8). Not an operation: no
    /// envelope, nothing on stdout but JSON-RPC frames — every diagnostic
    /// goes to stderr, exactly like `qsh serve`/`qsh listen`/`qsh reverse`
    /// (`docs/CLI.md` §8.1, §2.2). No flags: MVP is stdio-only.
    Mcp,
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

    /// SOCKS5 dynamic forwarding `[bind:]port`, repeatable — a third,
    /// independent mode: it does not fold into `--local`/`--remote`'s
    /// mutual exclusion (`PLAN.md` M4 Step 6). Parses, but always answers
    /// `UNSUPPORTED` before opening a connection to `host` or doing
    /// anything `--local`/`--remote` would have — implementation is P1
    /// (`docs/CLI.md` §6.9).
    #[arg(short = 'D', long, value_name = "SPEC", action = ArgAction::Append)]
    pub dynamic: Vec<String>,
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

/// `qsh cert …` subcommands (`docs/adr/0008-private-ca-cert-issuance.md`,
/// `PLAN.md` M7 Step 5). Both are local-only and idempotent — neither
/// dials, and neither takes a `device_id`: `cert issue` always promotes
/// this device's own identity (ADR §5).
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
    /// Mint a one-time invite code for another device to pair with this one
    /// (ADR-0002, `docs/CLI.md` §6.11). No address to reach *this* device is
    /// known here — the operator supplies one out of band when relaying the
    /// printed `qsh trust accept` command line.
    Invite,
    /// Dial `address`, redeem `code` against its invite, and — on a
    /// successful mutual proof — pin the peer exactly as `trust add` would
    /// (ADR-0002, `docs/CLI.md` §6.11).
    Accept {
        /// `host:port` of the device that printed `code` via `trust invite`.
        address: String,
        /// The invite code, as printed (case-insensitive, hyphens ignored).
        code: String,
    },
}

/// `qsh acl …` subcommands (`docs/CLI.md` §6.15).
#[derive(Debug, Subcommand)]
pub enum AclCmd {
    /// Evaluate this machine's own `acl.toml` against a hypothetical
    /// request, using the exact same evaluator `qsh serve`/`qsh listen`/
    /// `qsh reverse` enforce with (`PLAN.md` M5 DoD 1) — a reliable
    /// prediction of what enforcement would decide, without a restart.
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
    /// evaluated too (`PLAN.md` M5 §4.2). Omit to evaluate `--resource` as
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
mod tests {
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
            Cli::try_parse_from(["qsh", "attach", "box/01K0", "-L", "8080:localhost:3000"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["qsh", "hosts", "-L", "8080:localhost:3000"]).is_err());
    }

    /// `-R` is `-L`'s twin: repeatable, scoped to the interactive form,
    /// unparsed by clap for the same reason (`docs/CLI.md` §6.9), and free
    /// to coexist with `-L` on the same invocation — `PLAN.md` M4 Step 4
    /// calls them "companion flags" of the interactive form, not mutually
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
        assert!(
            Cli::try_parse_from(["qsh", "attach", "box/01K0", "-R", "9000:127.0.0.1:22"]).is_err()
        );
    }

    /// `qsh tunnel open` takes a bare host and exactly one of
    /// `--local`/`-L` or `--remote`/`-R` (`docs/CLI.md` §6.9) — neither,
    /// or both, is a clap usage error (exit 2), because a tunnel with no
    /// forward — or two contradictory ones — is nothing.
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
        assert!(
            Cli::try_parse_from(["qsh", "exec", "box", "--env", "novalue", "--", "true"]).is_err()
        );
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
            Cli::try_parse_from(["qsh", "reverse", "personal-mac", "--offered-name", "phone"])
                .unwrap();
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

    /// `qsh mcp` (`docs/CLI.md` §8.1) takes no arguments.
    #[test]
    fn mcp_takes_no_arguments() {
        let cli = Cli::try_parse_from(["qsh", "mcp"]).unwrap();
        assert!(matches!(cli.command.unwrap(), Command::Mcp));
        assert!(Cli::try_parse_from(["qsh", "mcp", "extra"]).is_err());
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
            Cli::try_parse_from(["qsh", "session", "write", "box/01K0", "--data-b64", "Yw=="])
                .unwrap();
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
            let cli =
                Cli::try_parse_from(["qsh", "session", "close", "box/01K0", "--signal", given])
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
                Cli::try_parse_from(["qsh", "session", "close", "box/01K0", "--signal", bad])
                    .is_err(),
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
        assert!(
            matches!(cli.command.unwrap(), Command::Sessions { host: Some(ref h) } if h == "box")
        );
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
        let cli =
            Cli::try_parse_from(["qsh", "attach", "box/01K0", "--escape-char", "none"]).unwrap();
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
}
