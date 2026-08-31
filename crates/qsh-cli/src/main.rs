//! `qsh`: thin frontend binary. All business logic lives in `qsh-core`;
//! this crate only parses arguments, calls `qsh_core::Ops`, and renders the
//! result (`docs/CLI.md` §11).

mod cli;
mod mcp;
mod render;
mod tui;

use std::io::{self, IsTerminal, Read, Write};
use std::time::SystemTime;

use clap::{CommandFactory as _, Parser};
use qsh_core::{
    AclCheckOp, CapabilitiesOp, CertInitOp, CertIssueOp, DoctorOp, ExecRunOp, ExecStdin, HostGetOp,
    HostListOp, IdentityInitOp, OpError, Operation, Ops, SchemaOp, SessionAttachOp, SessionCloseOp,
    SessionGetOp, SessionListOp, SessionOpenOp, SessionReadOp, SessionResizeOp, SessionWriteOp,
    TrustAcceptOp, TrustAddOp, TrustInviteOp, TrustListOp, TrustRemoveOp, TunnelCloseOp,
    TunnelListOp, TunnelOpenOp, VersionOp, dynamic_forward_unsupported,
};
use qsh_proto::{
    AclCheckReq, CapabilitiesReq, CertInitReq, CertIssueReq, DoctorReq, ErrorCode, ExecRunReq,
    HostGetReq, IdentityInitReq, SessionCloseReq, SessionGetReq, SessionListReq, SessionOpenReq,
    SessionReadReq, SessionResizeReq, SessionWriteReq, TrustAcceptReq, TrustAddReq, TrustInviteReq,
    TunnelCloseReq, TunnelListReq, TunnelOpenReq,
};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

use cli::{
    AclCmd, AttachArgs, CertCmd, Cli, Command, DEFAULT_ESCAPE_CHAR, EscapeChar, ExecArgs, HostCmd,
    SessionCmd, SessionReadArgs, SessionWriteArgs, TrustAddArgs, TrustCmd, TunnelCmd,
    TunnelOpenArgs,
};
use render::{human, json, json::Envelope};

/// QSH runtime failure exit code (`docs/CLI.md` §4): connection, auth,
/// policy or any other `OpError`.
const EXIT_RUNTIME_FAILURE: i32 = 255;

/// I/O failure writing our own output. Not a documented exit code by
/// itself, but reuses the runtime-failure code since it is just as fatal.
const EXIT_IO_FAILURE: i32 = 255;

/// `qsh exec` passes the remote exit code through, except that a remote
/// `255` is clamped to this so it stays distinguishable from qsh's own
/// [`EXIT_RUNTIME_FAILURE`] (`docs/CLI.md` §4). The JSON `remote_exit_code`
/// keeps the real value.
const EXIT_REMOTE_CLAMPED: i32 = 254;

/// The name `qsh serve` reports in diagnostics. Not an operation — it has
/// no envelope (`docs/CLI.md` §6.12).
const SERVE_MODE: &str = "serve";

/// The name `qsh listen` reports in diagnostics. Not an operation — it has
/// no envelope (`docs/CLI.md` §6.13).
const LISTEN_MODE: &str = "listen";

/// The name `qsh reverse` reports in diagnostics. Not an operation — it has
/// no envelope (`docs/CLI.md` §6.13).
const REVERSE_MODE: &str = "reverse";

/// The name `qsh mcp` reports in diagnostics. Not an operation — it has no
/// envelope; stdout carries only JSON-RPC frames for as long as the
/// process runs (`docs/CLI.md` §8.1, §2.2).
const MCP_MODE: &str = "mcp";

/// Usage error exit code (`docs/CLI.md` §4), matching clap's own.
const EXIT_USAGE: i32 = 2;

/// `eprintln!`, minus the abort: `eprintln!` panics the process when
/// stderr is gone — EPIPE once whatever spawned us drops the pipe, a
/// closed terminal, logrotate — and a long-lived `qsh listen`/`qsh serve`
/// must never die over a diagnostic line (latent since M3: the listen
/// daemon exited 101 whenever its stderr reader went away between two
/// startup lines). Diagnostics are best-effort everywhere in this crate:
/// loss is acceptable, death is not.
macro_rules! stderr_note {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = writeln!(::std::io::stderr(), $($arg)*);
    }};
}
pub(crate) use stderr_note;

/// stderr for the tracing `human` layer, with write errors swallowed.
///
/// `tracing_subscriber`'s fmt layer reports a writer failure through
/// `eprintln!`, which itself panics when stderr is closed — the same
/// daemon-killing class as a raw `eprintln!` (see [`stderr_note`]).
/// Swallowing the error here means that fallback can never fire.
struct LossyStderr;

impl Write for LossyStderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Claim the full buffer even on failure: a partial-write retry
        // loop against a dead stderr is only more chances to fail.
        let _ = io::stderr().write_all(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = io::stderr().flush();
        Ok(())
    }
}

fn main() {
    // `Cli::parse()` exits with code 2 on usage errors and 0 on
    // `--help`/`--version`, per clap's default behavior.
    let cli = Cli::parse();
    init_tracing(&cli);
    let exit_code = run(&cli);
    std::process::exit(exit_code);
}

/// Diagnostics go to **stderr only**, at a level set by `-q`/`-v`/`-vv`
/// and overridable with `QSH_LOG` (or `RUST_LOG`). stdout stays reserved
/// for the JSON envelope / human result (`docs/CLI.md` §2.2).
///
/// Recovery telemetry ([`qsh_core::telemetry`]) gets its own layer.
/// `docs/CLI.md` §6.4 fixes it as a **one-line JSON** record emitted at
/// *default* verbosity — a campaign script (`docs/design/testing.md` L4)
/// parses those lines whole — so a `warn` default level must not swallow
/// it and the human formatter's timestamp/level prefix must not be wrapped
/// around it. It obeys `--quiet`, which means "no diagnostics", and it
/// obeys an explicit `QSH_LOG`/`RUST_LOG` like every other diagnostic: a
/// level control that cannot silence one of the two streams is a trap for
/// anything scripting around it.
fn init_tracing(cli: &Cli) {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let default = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    // One spec, two filters: `EnvFilter` is not `Clone`, and both layers
    // have to read the same environment. An unparseable spec falls back to
    // the flag-derived default, exactly as before.
    let spec = std::env::var("QSH_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .ok()
        .filter(|spec| EnvFilter::try_new(spec).is_ok());
    // `rmcp`'s own `debug!(?request, …)`/`debug!(?result, …)` spans
    // (`rmcp-3.1.4/src/service.rs`'s `serve_inner`) `Debug`-format the
    // *entire* JSON-RPC message — a `tools/call` request's `arguments`
    // (PTY input b64, `exec` argv) or a response's `structuredContent`
    // (PTY output b64) — at plain `debug` level, so `-vv` (`default ==
    // "trace"`) would otherwise put PTY/command content on stderr as
    // `Debug`, violating this crate's "PTY/command 내용 로그 금지" rule
    // just as much as putting it on stdout would (`docs/CLI.md` §8.1's
    // *stream* promise says nothing about *content*; `PLAN.md` M6 Step
    // 2+3 검증 라운드 판정 ①/F1). `rmcp`'s crate-prefixed target (every
    // span/event above resolves to `rmcp::…`) is clamped to `warn` here,
    // unconditionally — appended to *both* the flag-derived `default` and
    // any explicit `QSH_LOG`/`RUST_LOG`, the same "always append a
    // target-scoped directive so it wins over the coarse level, however
    // that level was chosen" shape `recovery_default` below uses (for the
    // opposite reason: making sure a target is *always shown*, not always
    // hidden) — so neither `-vv` nor a blanket `RUST_LOG=debug` can
    // surface it. A caller who explicitly names `rmcp=` at a lower level
    // in their own spec still wins (`EnvFilter`'s per-target directives
    // are resolved by specificity, not by append order), which is the
    // deliberate opt-in escape hatch, not a hole in this clamp.
    const RMCP_TARGET_CLAMP: &str = "rmcp=warn";
    let default = format!("{default},{RMCP_TARGET_CLAMP}");
    let default = default.as_str();
    let spec = spec.map(|spec| format!("{spec},{RMCP_TARGET_CLAMP}"));
    let spec = spec.as_deref();
    // With no explicit spec, the recovery target sits at `info` whatever
    // `-v` says, because §6.4 fixes the record as visible at *default*
    // verbosity. An explicit spec governs it like anything else.
    let recovery_default = format!("{default},{}=info", qsh_core::telemetry::TARGET);
    // `qsh listen`'s registration diagnostics (`registered`/`denied`/
    // `replaced`/`lost`, `docs/CLI.md` §6.13) are the exact same shape of
    // promise as the recovery record above — a one-line JSON record an
    // operator/campaign script must see at *default* verbosity, never
    // wrapped in the human formatter's timestamp/level prefix (adversarial
    // review: at `warn` default the line was invisible outright; at `-v`
    // it came out doubled and non-JSON, because both layers reused the
    // same `human` filter/formatter that this constant now special-cases).
    let reverse_target = qsh_core::reverse::listen::TARGET;
    let reverse_default = format!("{default},{reverse_target}=info");
    let human = tracing_subscriber::fmt::layer()
        .with_writer(|| LossyStderr)
        .with_target(false)
        .with_filter(env_filter(spec, default))
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            meta.target() != qsh_core::telemetry::TARGET
                && meta.target() != qsh_core::reverse::listen::TARGET
        }));
    let recovery_enabled = !cli.quiet;
    let recovery = RecoveryLayer(StderrLines)
        .with_filter(env_filter(spec, &recovery_default))
        .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
            recovery_enabled && meta.target() == qsh_core::telemetry::TARGET
        }));
    let reverse_enabled = !cli.quiet;
    let reverse = RecoveryLayer(StderrLines)
        .with_filter(env_filter(spec, &reverse_default))
        .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
            reverse_enabled && meta.target() == reverse_target
        }));
    tracing_subscriber::registry()
        .with(human)
        .with(recovery)
        .with(reverse)
        .init();
}

/// `spec` if it parses, otherwise `fallback`.
fn env_filter(spec: Option<&str>, fallback: &str) -> EnvFilter {
    spec.and_then(|spec| EnvFilter::try_new(spec).ok())
        .unwrap_or_else(|| EnvFilter::new(fallback))
}

/// Where a recovery line goes. A trait so the layer can be exercised
/// without a global subscriber and without capturing the process's stderr.
trait LineSink: Send + Sync + 'static {
    /// Write one already-complete line, terminator included.
    fn write_line(&self, line: &str);
}

/// The production sink.
struct StderrLines;

impl LineSink for StderrLines {
    fn write_line(&self, line: &str) {
        // A recovery record is emitted at default verbosity (CLI.md §6.4)
        // and, by definition, mid-session — which for `qsh attach` means
        // the local terminal is in raw mode, where a bare LF moves down a
        // row without returning the carriage and the record stair-steps
        // across the screen. Only when stderr is a terminal: a redirected
        // log stays plain LF so the M8 campaign's `grep` still reads one
        // record per line.
        let crlf = io::stderr().is_terminal();
        let mut err = io::stderr().lock();
        // Best effort: telemetry must never be able to fail a command.
        let _ = if crlf {
            write!(err, "{line}\r\n")
        } else {
            writeln!(err, "{line}")
        };
    }
}

/// Writes a recovery record as exactly the line
/// [`qsh_core::telemetry::RecoveryReport::to_json_line`] produced —
/// nothing before it, nothing after it.
struct RecoveryLayer<W>(W);

impl<S: tracing::Subscriber, W: LineSink> tracing_subscriber::Layer<S> for RecoveryLayer<W> {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut line = String::new();
        event.record(&mut MessageOnly(&mut line));
        if line.is_empty() {
            return;
        }
        self.0.write_line(&line);
    }
}

/// Pulls just the event's message out, which for a recovery record is the
/// whole JSON object.
struct MessageOnly<'a>(&'a mut String);

impl tracing::field::Visit for MessageOnly<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

fn run(cli: &Cli) -> i32 {
    let ops = match Ops::from_env() {
        Ok(ops) => ops,
        Err(err) => {
            // `qsh listen`/`qsh reverse` are long-running modes with no
            // envelope at all (`docs/CLI.md` §2.4, §6.13): stdout gets zero
            // bytes on every path, including a setup failure this early —
            // before `run_listen`/`run_reverse` even exist to apply their
            // own stderr-only error path. `report_error` would otherwise
            // print a `qsh.cli/v1` envelope to stdout here whenever
            // `--json`/`--jsonl` was passed, exactly the leak `run_listen`/
            // `run_reverse`'s own `Err` arms are already careful to avoid
            // (adversarial review finding; `docs/design/testing.md` L6:
            // "every machine-mode stdout line must be pure JSON" applies
            // just as much to producing *no* line at all here).
            return match long_running_setup_mode(&cli.command) {
                Some(mode) => report_long_running_setup_error(mode, &err),
                None => report_error(cli, command_name(cli), &err),
            };
        }
    };

    let Some(command) = &cli.command else {
        // No subcommand: the bare interactive form, `qsh [user@]host`.
        let Some(target) = &cli.interactive.target else {
            // Reachable with global flags and nothing else:
            // `arg_required_else_help` only fires on a *completely* empty
            // command line, so `qsh --json` lands here. clap prints an
            // error to stderr, which is what keeps stdout pure JSON in
            // machine mode (`docs/CLI.md` §2.2, §4: usage errors write
            // nothing to stdout in either mode).
            let _ = Cli::command()
                .error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "no target and no subcommand: expected `qsh [user@]host` \
                     or one of the subcommands below",
                )
                .print();
            return EXIT_USAGE;
        };
        return run_interactive(
            cli,
            &ops,
            tui::Attach::Open {
                host: target.host.clone(),
                user: target.user.clone(),
                forwards: cli.interactive.local_forward.clone(),
                remote_forwards: cli.interactive.remote_forward.clone(),
            },
            cli.interactive.escape_char,
        );
    };

    match command {
        Command::Version => finish(cli, VersionOp::COMMAND, ops.version(), human::print_version),
        Command::Schema => finish(cli, SchemaOp::COMMAND, ops.schema(), human::print_schema),
        Command::Capabilities { host } => finish(
            cli,
            CapabilitiesOp::COMMAND,
            ops.capabilities(CapabilitiesReq { host: host.clone() }),
            human::print_capabilities,
        ),
        Command::Doctor { host } => finish(
            cli,
            DoctorOp::COMMAND,
            ops.doctor(DoctorReq { host: host.clone() }, SystemTime::now()),
            human::print_doctor,
        ),
        Command::Init { key_store } => finish(
            cli,
            IdentityInitOp::COMMAND,
            ops.identity_init(IdentityInitReq {
                key_store: *key_store,
            }),
            human::print_init,
        ),
        Command::Trust(TrustCmd::Add(args)) => run_trust_add(cli, &ops, args),
        Command::Trust(TrustCmd::List) => finish(
            cli,
            TrustListOp::COMMAND,
            ops.trust_list(),
            human::print_trust_list,
        ),
        Command::Trust(TrustCmd::Remove { name }) => finish(
            cli,
            TrustRemoveOp::COMMAND,
            ops.trust_remove(name),
            human::print_trust_remove,
        ),
        Command::Trust(TrustCmd::Invite) => finish(
            cli,
            TrustInviteOp::COMMAND,
            ops.trust_invite(TrustInviteReq {}),
            human::print_trust_invite,
        ),
        Command::Trust(TrustCmd::Accept { address, code }) => finish(
            cli,
            TrustAcceptOp::COMMAND,
            ops.trust_accept(TrustAcceptReq {
                address: address.clone(),
                code: code.clone(),
            }),
            human::print_trust_accept,
        ),
        Command::Cert(CertCmd::Init) => finish(
            cli,
            CertInitOp::COMMAND,
            ops.cert_init(CertInitReq {}),
            human::print_cert_init,
        ),
        Command::Cert(CertCmd::Issue) => finish(
            cli,
            CertIssueOp::COMMAND,
            ops.cert_issue(CertIssueReq {}),
            human::print_cert_issue,
        ),
        Command::Hosts => finish(
            cli,
            HostListOp::COMMAND,
            ops.host_list(),
            human::print_hosts,
        ),
        Command::Host(HostCmd::Get { name }) => finish(
            cli,
            HostGetOp::COMMAND,
            ops.host_get(HostGetReq { name: name.clone() }),
            human::print_host,
        ),
        Command::Acl(AclCmd::Check(args)) => finish(
            cli,
            AclCheckOp::COMMAND,
            ops.acl_check(AclCheckReq {
                principal: args.principal.clone(),
                action: args.action.clone(),
                resource: args.resource.clone(),
                auth_path: args.auth_path.clone(),
                owner: args.owner.clone(),
                owner_auth_path: args.owner_auth_path.clone(),
            }),
            human::print_acl_check,
        ),
        Command::Exec(args) => run_exec(cli, &ops, args),
        Command::Attach(AttachArgs {
            session_ref,
            escape_char,
        }) => run_interactive(
            cli,
            &ops,
            tui::Attach::Existing {
                session_ref: session_ref.clone(),
            },
            *escape_char,
        ),
        Command::Session(cmd) => run_session(cli, &ops, cmd),
        Command::Sessions { host } => finish(
            cli,
            SessionListOp::COMMAND,
            ops.session_list(SessionListReq { host: host.clone() }),
            human::print_session_list,
        ),
        Command::Tunnel(TunnelCmd::Open(args)) => run_tunnel_open(cli, &ops, args),
        Command::Tunnel(TunnelCmd::Close { tunnel_id }) => finish(
            cli,
            TunnelCloseOp::COMMAND,
            ops.tunnel_close(TunnelCloseReq {
                tunnel_id: tunnel_id.clone(),
            }),
            human::print_tunnel_close,
        ),
        Command::Tunnels => finish(
            cli,
            TunnelListOp::COMMAND,
            ops.tunnel_list(TunnelListReq {}),
            human::print_tunnels,
        ),
        Command::Serve { bind } => run_serve(&ops, bind.as_deref()),
        Command::Listen { bind } => run_listen(&ops, bind.as_deref()),
        Command::Reverse {
            controller,
            offered_name,
        } => run_reverse(&ops, controller, offered_name.as_deref()),
        Command::Mcp => run_mcp(&ops),
    }
}

/// `qsh [user@]host` and `qsh attach <session-ref>` — the interactive
/// forms (`docs/CLI.md` §7).
///
/// The only command with **no envelope at all**: stdout carries the remote
/// terminal's bytes, so every diagnostic goes to stderr (`docs/CLI.md`
/// §2.2) and the exit code is the remote shell's (§4). Failures before the
/// terminal is touched still report through the shared [`report_error`]
/// path, which is what keeps `--json` honest about *why* it refuses.
fn run_interactive(cli: &Cli, ops: &Ops, what: tui::Attach, escape: Option<EscapeChar>) -> i32 {
    let command = what.command();
    if cli.wants_json() {
        return report_error(cli, command, &tui::json_mode_unsupported());
    }
    // `-D` is refused before anything else on this command line — before
    // `SessionOpen`, before `-L`/`-R` are even looked at (`docs/CLI.md`
    // §6.9, `PLAN.md` M4 Step 6, DoD 5): fail-closed ordering means a
    // `-D` alongside a session/`-L`/`-R` request must not let any of the
    // rest through first, so this has to happen before `tui::run` ever
    // touches a session or a target — the zero-resource property holds
    // just as it did when this check lived in `run`. It sits *after* the
    // `wants_json` gate above, though: `docs/CLI.md` §7 wins over §6.9's
    // `-D` refusal when `--json`/`--jsonl` is present, because the
    // interactive form has no machine mode at all — that has to be the
    // first thing reported no matter what else is wrong with the command
    // line. Only the bare `qsh [user@]host` form ever populates
    // `dynamic_forward` (`qsh attach` has no `-D`), so this is a no-op on
    // the `Attach::Existing` path.
    if !cli.interactive.dynamic_forward.is_empty() {
        return report_error(cli, command, &dynamic_forward_unsupported());
    }
    let EscapeChar(escape) = escape.unwrap_or(DEFAULT_ESCAPE_CHAR);
    match tui::run(ops, what, escape) {
        Ok(code) => code,
        Err(err) => report_error(cli, command, &err),
    }
}

/// `qsh session …` — value operations on one session (`docs/CLI.md`
/// §6.2–6.7). Each is a plain `Ops` call plus a renderer; the CLI never
/// looks inside a `session_ref`.
fn run_session(cli: &Cli, ops: &Ops, cmd: &SessionCmd) -> i32 {
    match cmd {
        SessionCmd::Open(args) => finish(
            cli,
            SessionOpenOp::COMMAND,
            ops.session_open(SessionOpenReq {
                host: args.host.clone(),
                argv: args.argv.clone(),
                env: args.env.clone(),
                term: args.term.clone(),
                cols: args.cols.map(u32::from),
                rows: args.rows.map(u32::from),
                user: None,
            }),
            human::print_session_open,
        ),
        SessionCmd::Get { session_ref } => finish(
            cli,
            SessionGetOp::COMMAND,
            ops.session_get(SessionGetReq {
                session_ref: session_ref.clone(),
            }),
            human::print_session,
        ),
        SessionCmd::Read(args) => run_session_read(cli, ops, args),
        SessionCmd::Write(args) => run_session_write(cli, ops, args),
        SessionCmd::Resize {
            session_ref,
            cols,
            rows,
        } => finish(
            cli,
            SessionResizeOp::COMMAND,
            ops.session_resize(SessionResizeReq {
                session_ref: session_ref.clone(),
                cols: u32::from(*cols),
                rows: u32::from(*rows),
            }),
            human::print_session_resize,
        ),
        SessionCmd::Close {
            session_ref,
            signal,
        } => finish(
            cli,
            SessionCloseOp::COMMAND,
            ops.session_close(SessionCloseReq {
                session_ref: session_ref.clone(),
                signal: signal.clone(),
            }),
            human::print_session_close,
        ),
    }
}

/// How long one `--follow` pull long-polls, and the *floor* under an
/// explicit `--wait`. The host only clamps `wait_ms` from above
/// (`SESSION_READ_MAX_WAIT`), so a follower given `--wait 0` for a single
/// pull would otherwise turn into a tight round-trip loop against `serve`
/// for as long as the session stays idle. A follower parks; it never
/// spins.
const FOLLOW_WAIT_MS: u64 = 30_000;

/// `qsh session read`: one pull, or — with `--follow` — a loop of them
/// (`docs/CLI.md` §6.4). Both forms go through the same
/// [`Ops::session_reader`] cursor-pull primitive; `--wait` is exactly one
/// `pull()` and `--follow` is that same call in a loop, so the two cannot
/// drift apart.
fn run_session_read(cli: &Cli, ops: &Ops, args: &SessionReadArgs) -> i32 {
    if args.follow {
        return run_session_follow(cli, ops, args);
    }
    let output = match ops.session_read(SessionReadReq {
        session_ref: args.session_ref.clone(),
        after_sequence: args.after,
        wait_ms: args.wait,
        limit_bytes: args.limit_bytes,
        ctl_after: Some(args.ctl_after),
    }) {
        Ok(output) => output,
        Err(err) => return report_error(cli, SessionReadOp::COMMAND, &err),
    };
    if cli.wants_json() {
        finish(
            cli,
            SessionReadOp::COMMAND,
            Ok::<_, OpError>(output.data),
            |_| Ok(()),
        )
    } else {
        emit(human::print_session_read(&output))
    }
}

/// `qsh session read --follow`: pull, render, repeat until the session
/// ends. Terminates on `session.exit` (exit `0`, without waiting for the
/// TTL cleanup) or on `session.closed` — `docs/CLI.md` §6.4.
///
/// In either JSON mode this is the `--jsonl` streaming form: one bare
/// `qsh.event/v1` event per stdout line, never an envelope (§6.4). A
/// follower is a stream, so `--json`'s one-envelope-per-invocation shape
/// does not apply to it; error reporting is unchanged, which is what keeps
/// the exit-code/error-code matrix identical in both modes.
fn run_session_follow(cli: &Cli, ops: &Ops, args: &SessionReadArgs) -> i32 {
    let mut reader = match ops.session_reader(SessionReadReq {
        session_ref: args.session_ref.clone(),
        after_sequence: args.after,
        // `--wait` may only make a follower park *longer*: see
        // `FOLLOW_WAIT_MS`.
        wait_ms: Some(args.wait.unwrap_or(FOLLOW_WAIT_MS).max(FOLLOW_WAIT_MS)),
        limit_bytes: args.limit_bytes,
        ctl_after: Some(args.ctl_after),
    }) {
        Ok(reader) => reader,
        Err(err) => return report_error(cli, SessionReadOp::COMMAND, &err),
    };
    let code = loop {
        let output = match reader.pull() {
            Ok(output) => output,
            Err(err) => break report_error(cli, SessionReadOp::COMMAND, &err),
        };
        let rendered = if cli.wants_json() {
            output.data.events.iter().try_for_each(json::print_event)
        } else {
            human::print_session_read(&output)
        };
        if let Err(err) = rendered {
            break emit(Err(err));
        }
        if reader.is_done() {
            break 0;
        }
    };
    reader.close();
    code
}

/// `qsh session write`: `--data-b64` goes straight to `Ops`; `--stdin`
/// reads this process's stdin to EOF first (raw bytes, no re-encoding on
/// this side).
fn run_session_write(cli: &Cli, ops: &Ops, args: &SessionWriteArgs) -> i32 {
    let result = match &args.data_b64 {
        Some(data_b64) => ops.session_write(SessionWriteReq {
            session_ref: args.session_ref.clone(),
            data_b64: data_b64.clone(),
        }),
        None => {
            // Read at most one byte past the cap: `Ops` rejects the
            // oversize write, and stdin is never buffered unbounded.
            let mut data = Vec::new();
            let cap = qsh_core::ops::SESSION_WRITE_MAX as u64 + 1;
            match io::stdin().lock().take(cap).read_to_end(&mut data) {
                Ok(_) => ops.session_write_bytes(&args.session_ref, data),
                Err(err) => Err(OpError::new(
                    ErrorCode::InvalidArgument,
                    format!("cannot read stdin: {err}"),
                )),
            }
        }
    };
    finish(
        cli,
        SessionWriteOp::COMMAND,
        result,
        human::print_session_write,
    )
}

/// `qsh exec` — the one command whose exit code is not ours to choose.
///
/// The remote process's exit code is passed through like `ssh` does
/// (`255` clamped to `254`, `docs/CLI.md` §4); qsh's own failures exit
/// `255` through the shared [`report_error`] path. Local stdin is
/// forwarded to the remote command only when it is not a terminal, so an
/// interactive `qsh exec host -- cat` does not sit waiting on the keyboard.
fn run_exec(cli: &Cli, ops: &Ops, args: &ExecArgs) -> i32 {
    let stdin = if io::stdin().is_terminal() {
        ExecStdin::Closed
    } else {
        ExecStdin::Inherit
    };
    let request = ExecRunReq {
        host: args.host.clone(),
        argv: args.argv.clone(),
        env: args.env.clone(),
        timeout_ms: args.timeout,
    };
    let output = match ops.exec_run(request, stdin) {
        Ok(output) => output,
        Err(err) => return report_error(cli, ExecRunOp::COMMAND, &err),
    };

    let rendered = if cli.wants_json() {
        match serde_json::to_value(&output.data) {
            Ok(value) => Envelope::success(ExecRunOp::COMMAND, value).print(),
            Err(err) => {
                stderr_note!("qsh: failed to encode result: {err}");
                return EXIT_IO_FAILURE;
            }
        }
    } else {
        human::print_exec(&output)
    };
    if let Err(err) = rendered {
        stderr_note!("qsh: failed to write output: {err}");
        return EXIT_IO_FAILURE;
    }
    remote_exit_code_to_process_exit(output.data.remote_exit_code)
}

/// `docs/CLI.md` §4: remote `0..=254` verbatim, remote `255` → `254`.
/// Anything outside `0..=255` cannot come from a Unix exit status but is
/// clamped defensively rather than trusted.
fn remote_exit_code_to_process_exit(remote: i32) -> i32 {
    match remote {
        code @ 0..=254 => code,
        _ => EXIT_REMOTE_CLAMPED,
    }
}

/// `qsh tunnel open <host> --local <spec>` — open one tunnel and hold it
/// (`docs/CLI.md` §6.9, §6.14).
///
/// Two-phase on purpose, and the only command shaped like this: the
/// `Tunnel` envelope is emitted **once**, up front, exactly like any value
/// operation — and then this process blocks, because the foreground
/// process *is* the tunnel's holder (`PLAN.md` M4 §4.1 #1: no client
/// daemon). Consequences this function is careful about:
///
/// - stdout is **flushed** before blocking. It is block-buffered when it
///   is a pipe, and a caller reading the envelope to learn the bound port
///   would otherwise wait for a flush that only happens at exit.
/// - the end of the tunnel is reported on **stderr**, never as a second
///   envelope: machine mode is one JSON line per command (`docs/CLI.md`
///   §2.2), and a success line followed by a failure line would break
///   every parser of it.
fn run_tunnel_open(cli: &Cli, ops: &Ops, args: &TunnelOpenArgs) -> i32 {
    // `-D` is checked before anything else here, same fail-closed
    // ordering as the interactive form's own check above: whichever of
    // `--local`/`--remote` also happens to be given, `-D` wins and
    // nothing gets as far as `Ops::tunnel_open` (`docs/CLI.md` §6.9,
    // `PLAN.md` M4 Step 6, DoD 5). That is "whichever", not "both": `-L`
    // and `-R` together never reach this function at all — clap's
    // `conflicts_with` on both flags (`cli.rs`'s `TunnelOpenArgs`)
    // rejects that combination as a usage error (exit `2`) during
    // argument parsing, before `-D` or anything else here runs.
    if !args.dynamic.is_empty() {
        return report_error(cli, TunnelOpenOp::COMMAND, &dynamic_forward_unsupported());
    }
    // Exactly one of `--local`/`--remote` is expected here: clap's
    // `conflicts_with`/`required_unless_present_any` on both flags
    // (`cli.rs`'s `TunnelOpenArgs`) already rule out both `None` and
    // both `Some` as usage errors before argument parsing even finishes
    // (the third option, `--dynamic`, was just ruled out above). The `_`
    // arm below is a fail-closed backstop rather than a trusted
    // invariant: if that guarantee ever slips — a future flag change, a
    // clap upgrade that loosens a constraint — this refuses the command
    // with `INVALID_ARGUMENT` instead of panicking or guessing a mode.
    let (mode, spec_str) = match (&args.local, &args.remote) {
        (Some(spec), None) => ("local", spec),
        (None, Some(spec)) => ("remote", spec),
        _ => {
            return report_error(
                cli,
                TunnelOpenOp::COMMAND,
                &OpError::new(
                    ErrorCode::InvalidArgument,
                    "exactly one of --local/--remote is required",
                ),
            );
        }
    };
    // Parsing (and, for `"local"`, the loopback-bind rule) lives in
    // `qsh-core`: this frontend only shuttles the already-parsed halves
    // into the request the contract defines (`docs/CLI.md` §6.9).
    let parsed = if mode == "local" {
        qsh_core::parse_local_forwards(std::slice::from_ref(spec_str))
    } else {
        qsh_core::parse_remote_forwards(std::slice::from_ref(spec_str))
    };
    let specs = match parsed {
        Ok(specs) => specs,
        Err(err) => return report_error(cli, TunnelOpenOp::COMMAND, &err),
    };
    let Some(spec) = specs.first() else {
        return report_error(
            cli,
            TunnelOpenOp::COMMAND,
            &OpError::new(ErrorCode::InvalidArgument, "no forward spec"),
        );
    };
    let request = TunnelOpenReq {
        host: args.host.clone(),
        mode: mode.to_string(),
        bind: spec.bind.clone(),
        listen_port: u32::from(spec.listen_port),
        forward_host: spec.host.clone(),
        forward_port: u32::from(spec.host_port),
    };
    let hold = match ops.tunnel_open(request) {
        Ok(hold) => hold,
        Err(err) => return report_error(cli, TunnelOpenOp::COMMAND, &err),
    };
    let rendered = if cli.wants_json() {
        match serde_json::to_value(hold.tunnel()) {
            Ok(value) => emit(Envelope::success(TunnelOpenOp::COMMAND, value).print()),
            Err(err) => {
                stderr_note!("qsh: failed to encode result: {err}");
                EXIT_IO_FAILURE
            }
        }
    } else {
        emit(human::print_tunnel_open(hold.tunnel()))
    };
    if rendered != 0 {
        // Could not even report the tunnel; do not go on to hold one
        // nobody was told about. Dropping `hold` closes it.
        return rendered;
    }
    if let Err(err) = io::stdout().flush() {
        stderr_note!("qsh: failed to write output: {err}");
        return EXIT_IO_FAILURE;
    }
    stderr_note!("qsh tunnel open: holding; press Ctrl-C to close");
    let err = hold.hold();
    if let Err(io_err) = human::print_error(&err) {
        stderr_note!("qsh tunnel open: failed to write output: {io_err}");
    }
    EXIT_RUNTIME_FAILURE
}

/// `qsh serve` — long-running host mode. Not an operation: no envelope,
/// nothing on stdout at all; the bound address goes to stderr and the
/// process runs until SIGINT/SIGTERM (`docs/CLI.md` §6.12).
fn run_serve(ops: &Ops, bind: Option<&str>) -> i32 {
    let result = (|| -> Result<(), OpError> {
        let config = ops.config()?;
        // Identity is loaded synchronously, before any runtime exists: the
        // credential store may block (and prompt) — keep that off the
        // runtime's workers.
        let identity = ops.load_identity()?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
        })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?;
        let device_id = identity.identity.device_id.clone();
        let fingerprint = identity.identity.fingerprint.to_string();
        runtime.block_on(qsh_core::serve::run_serve(
            ops.paths(),
            &config,
            identity,
            bind,
            |addr| {
                stderr_note!("qsh serve: listening on {addr}");
                stderr_note!("qsh serve: identity {device_id} fingerprint {fingerprint}");
            },
            // `PLAN.md` M5 Step 6: `acl.toml` policy loads once, here, at
            // startup — `qsh_core::acl::StartupDiagnostic::render` is the
            // single source of truth for the wording; this closure only
            // prints it, holding no ACL logic of its own (`CLAUDE.md`'s
            // crate boundary).
            |runtime| {
                if let Some(diag) = &runtime.policy_diagnostic {
                    stderr_note!("qsh serve: {}", diag.render());
                }
            },
            shutdown_signal(),
        ))
    })();
    match result {
        Ok(()) => {
            stderr_note!("qsh serve: shutting down");
            0
        }
        Err(err) => report_long_running_setup_error(SERVE_MODE, &err),
    }
}

/// Whether `command` is one of the long-running modes whose setup failures
/// must stay off stdout entirely (`docs/CLI.md` §2.2, §6.12, §6.13), and if
/// so, which mode name to report under. `None` for every ordinary
/// operation, which keeps using [`report_error`]'s JSON-envelope path. A
/// pure function so the routing decision itself is unit-testable without a
/// real `Ops::from_env()` failure (which would need process-global
/// environment mutation to provoke).
fn long_running_setup_mode(command: &Option<Command>) -> Option<&'static str> {
    match command {
        Some(Command::Serve { .. }) => Some(SERVE_MODE),
        Some(Command::Listen { .. }) => Some(LISTEN_MODE),
        Some(Command::Reverse { .. }) => Some(REVERSE_MODE),
        Some(Command::Mcp) => Some(MCP_MODE),
        _ => None,
    }
}

/// Report an [`OpError`] for `qsh serve`/`qsh listen`/`qsh reverse` —
/// stderr only, never `report_error`'s JSON-envelope path, because these
/// three long-running modes have no envelope at all and stdout must see
/// zero bytes on every path (`docs/CLI.md` §2.2, §6.12, §6.13). Shared by
/// [`run_serve`]/[`run_listen`]/[`run_reverse`]'s own runtime-failure arms
/// and by [`run`]'s pre-dispatch `Ops::from_env()` failure, so the paths
/// cannot drift apart.
fn report_long_running_setup_error(mode: &'static str, err: &OpError) -> i32 {
    if let Err(io_err) = human::print_error(err) {
        stderr_note!("qsh {mode}: failed to write output: {io_err}");
    }
    EXIT_RUNTIME_FAILURE
}

/// `qsh listen` — the reverse-mode controller (`docs/CLI.md` §6.13). Not an
/// operation: no envelope, nothing on stdout at all; the bound address and
/// registration events go to stderr and the process runs until
/// SIGINT/SIGTERM, exactly like [`run_serve`].
fn run_listen(ops: &Ops, bind: Option<&str>) -> i32 {
    let result = (|| -> Result<(), OpError> {
        let config = ops.config()?;
        // Identity is loaded synchronously, before any runtime exists: the
        // credential store may block (and prompt) — keep that off the
        // runtime's workers.
        let identity = ops.load_identity()?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
        })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?;
        runtime.block_on(qsh_core::reverse::listen::run_listen(
            ops.paths(),
            &config,
            identity,
            bind,
            |addr| {
                stderr_note!("qsh listen: listening on {addr}");
                // `docs/CLI.md` §6.13's "Controller reachability 요구":
                // reverse only makes the *target* reachable through NAT —
                // this controller must still be dialable at `addr` by
                // every target. `qsh_core::doctor::CONTROLLER_UNREACHABLE`
                // is the single source of truth for that reminder's
                // wording (doctor.rs's own docs, docs/CLI.md §6.13's "같은
                // 상수를 qsh listen 시작 배너 ... 함께 소비한다") — this
                // banner renders it verbatim rather than forking its own
                // paraphrase, same as the target's connection-failure path
                // below (adversarial review finding, M3 Step 9: a second
                // hardcoded copy here could silently drift from the
                // constant with no test catching it).
                stderr_note!("qsh listen: targets must be able to reach {addr} directly over UDP");
                let diag = qsh_core::doctor::CONTROLLER_UNREACHABLE;
                stderr_note!("qsh listen: {}", diag.message);
                stderr_note!("qsh listen: {}", diag.remedy);
            },
            // `PLAN.md` M5 Step 6: fires at most once, only when `acl.toml`
            // did not produce a usable policy — `rendered` is already the
            // complete banner (`qsh_core::acl::StartupDiagnostic::render`);
            // this closure prints it verbatim, no ACL logic here.
            |rendered| {
                stderr_note!("qsh listen: {rendered}");
            },
            shutdown_signal(),
        ))
    })();
    match result {
        Ok(()) => {
            stderr_note!("qsh listen: shutting down");
            0
        }
        Err(err) => report_long_running_setup_error(LISTEN_MODE, &err),
    }
}

/// `qsh reverse <controller>` — the reverse-mode target (`docs/CLI.md`
/// §6.13). Not an operation: no envelope, nothing on stdout at all.
/// Registers and reconnects forever with backoff whenever the connection to
/// the controller dies (`docs/design/protocol.md` §11-4, `PLAN.md` M3 Step
/// 4) — registration is this target's only reachability path, so it is
/// never abandoned; a clean SIGINT/SIGTERM is the only way this returns.
fn run_reverse(ops: &Ops, controller: &str, offered_name: Option<&str>) -> i32 {
    let result = (|| -> Result<(), OpError> {
        let config = ops.config()?;
        let identity = ops.load_identity()?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
        })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?;
        runtime.block_on(qsh_core::reverse::target::run_reverse_observed(
            ops.paths(),
            &config,
            identity,
            controller,
            offered_name,
            // `PLAN.md` M5 Step 6: a reverse target is a host
            // (`crate::serve::host_runtime`) — its own `acl.toml` gates the
            // sessions it serves the controller, loaded once here, not per
            // reconnect (`on_runtime` fires exactly once, before the first
            // dial, `run_reverse_observed`'s own docs).
            |runtime| {
                if let Some(diag) = &runtime.policy_diagnostic {
                    stderr_note!("qsh reverse: {}", diag.render());
                }
            },
            // `qsh_core::doctor::CONTROLLER_UNREACHABLE` fires at most
            // once per process (`run_reverse_observed`'s own docs — the
            // once-only guard lives in qsh-core, this closure only
            // renders it): the first failed dial/registration attempt,
            // never once per backoff retry (`docs/CLI.md` §6.13,
            // `PLAN.md` M3 Step 9).
            || {
                let diag = qsh_core::doctor::CONTROLLER_UNREACHABLE;
                stderr_note!("qsh reverse: {}", diag.message);
                stderr_note!("qsh reverse: {}", diag.remedy);
            },
            shutdown_signal(),
        ))
    })();
    match result {
        Ok(()) => {
            stderr_note!("qsh reverse: shutting down");
            0
        }
        Err(err) => report_long_running_setup_error(REVERSE_MODE, &err),
    }
}

/// `qsh mcp` — serve MCP tools over stdio (`docs/CLI.md` §8, `PLAN.md` M6
/// Step 2/3). Not an operation: no envelope, nothing on stdout but JSON-RPC
/// frames, same shape as [`run_serve`]/[`run_listen`]/[`run_reverse`].
///
/// No identity/config load *here* — unlike `serve`/`listen`/`reverse`, `qsh
/// mcp` is not a host runtime (it never accepts a peer connection or
/// enforces `acl.toml`; `docs/design/architecture.md` §6's ACL choke point
/// stays on the host-dispatch side). `ops` (Step 3's [`mcp::QshMcpServer`]
/// field) is the **same** `Ops` every other command in [`run`] already
/// dialed with (`Ops::from_env()`, this function's caller) — the MCP
/// adapter's tool calls reach out through it exactly the way the CLI
/// frontend's own commands do (`docs/CLI.md` §11), so there is no
/// `qsh_core::acl::StartupDiagnostic` for this process to print — nothing
/// here is silently skipping one.
///
/// Diagnostics: [`stderr_note!`] only, and [`init_tracing`]'s subscriber is
/// already stderr-only regardless of `-v`/`-vv`/`-q` (`LossyStderr`), which
/// is what keeps stdout pure JSON-RPC even at `-vv` (`docs/CLI.md` §8.1,
/// DoD 5) — nothing MCP-specific was needed to get that.
fn run_mcp(ops: &Ops) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            return report_long_running_setup_error(
                MCP_MODE,
                &OpError::new(ErrorCode::Internal, format!("runtime: {err}")),
            );
        }
    };
    stderr_note!("qsh mcp: serving tools over stdio");
    let result = runtime.block_on(mcp::serve_stdio(ops.clone()));
    // `runtime.shutdown_timeout` — not a plain `drop(runtime)` — on the way
    // out (`PLAN.md` M6 Step 4 item ①/③(iii), proved by a real binary: a
    // `qsh mcp` process with a still-in-flight `read_session` long-poll
    // (`run_tool`'s `spawn_blocking`, `crate::mcp`'s own doc on why every
    // `Ops` call needs one) hung well past `mcp::serve_stdio`'s own return
    // when stdin closed with the default `Drop for Runtime`). The reason:
    // `Ops::session_read`'s blocking network wait has no cancellation hook
    // of its own (`Connected::run`'s `runtime.block_on` on its own private,
    // per-connection runtime — a genuinely new interrupt plumbing into
    // `qsh-core`'s pull primitive is out of this adapter's scope, `PLAN.md`
    // M6 Step 4 (a)'s "새 스트리밍 경로를 만들지 않는다"), so once
    // `spawn_blocking` has started that thread, nothing this crate does can
    // make it return early — it keeps running until the host's own
    // `SESSION_READ_MAX_WAIT` clamp (60s) or the requested `wait_ms`,
    // whichever is sooner. Plain `Runtime::drop` (`tokio-1.53.1`
    // `src/runtime/blocking/pool.rs`'s `BlockingPool::drop` →
    // `shutdown(None)`) blocks the *caller* — this function, and therefore
    // `main`'s `std::process::exit` — for that same span, so a client that
    // cancels a long-poll and then simply disconnects (`docs/CLI.md` §9's
    // "MCP cancellation은 local wait 또는 request를 취소하고 session
    // lifecycle을 변경하지 않는다" — it says nothing about *this* process's
    // own exit latency) would leave `qsh mcp` visibly hung for up to a
    // minute. `shutdown_timeout` gives outstanding work `MCP_SHUTDOWN_DRAIN`
    // to finish — on top of `rmcp`'s own up-to-5s internal drain
    // (`rmcp-3.1.4/src/service.rs`'s `serve_inner`, already run inside
    // `mcp::serve_stdio`'s `service.waiting()` before this line), so a tool
    // call that is genuinely about to finish still gets to send its
    // response — and then returns regardless, abandoning (not aborting) any
    // thread still running; the abandoned thread's own result was already
    // unobservable to any peer (a cancelled request's response is dropped
    // by `rmcp` itself — `crate::mcp::QshMcpServer::call_tool`'s doc
    // comment, `read_session` paragraph, has the `local_ct_pool` source
    // citation; an uncancelled one simply never gets read once this process
    // has exited), and the OS reclaims the thread the instant
    // `std::process::exit` tears the process down.
    const MCP_SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_millis(500);
    runtime.shutdown_timeout(MCP_SHUTDOWN_DRAIN);
    match result {
        Ok(()) => {
            stderr_note!("qsh mcp: shutting down");
            0
        }
        Err(err) => report_long_running_setup_error(
            MCP_MODE,
            &OpError::new(ErrorCode::Internal, format!("mcp: {err}")),
        ),
    }
}

/// Resolves on SIGINT (Ctrl-C) or, on Unix, SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(term) => term,
            Err(err) => {
                tracing::warn!(%err, "cannot install SIGTERM handler; Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `qsh trust add` — the one command with an interactive path.
///
/// Without `--fingerprint` the ops layer observes the peer's fingerprint and
/// returns `TRUST_REQUIRED`. In human mode that becomes an ssh-style
/// confirmation prompt; in `--json`/`--jsonl` mode the error is returned
/// verbatim, because machine mode never prompts (`docs/CLI.md` §2.1).
fn run_trust_add(cli: &Cli, ops: &Ops, args: &TrustAddArgs) -> i32 {
    let request = |fingerprint: Option<String>| TrustAddReq {
        name: args.name.clone(),
        address: args.address.clone(),
        fingerprint,
    };

    let mut result = ops.trust_add(request(args.fingerprint.clone()));

    if let Err(err) = &result
        && !cli.wants_json()
        && err.code == ErrorCode::TrustRequired
    {
        match prompt_for_pin(&args.name, err) {
            Prompt::Accepted(fingerprint) => result = ops.trust_add(request(Some(fingerprint))),
            Prompt::Declined => {
                stderr_note!("aborted");
                return EXIT_RUNTIME_FAILURE;
            }
            // Not a terminal, or the error carried no observation: fall
            // through and report the original error.
            Prompt::Unavailable => {}
        }
    }

    finish(cli, TrustAddOp::COMMAND, result, human::print_trust_add)
}

/// Outcome of the interactive pin confirmation.
enum Prompt {
    /// The operator accepted the observed fingerprint.
    Accepted(String),
    /// The operator declined.
    Declined,
    /// No prompt was possible (not a terminal, or nothing to confirm).
    Unavailable,
}

fn prompt_for_pin(name: &str, err: &OpError) -> Prompt {
    let (Some(fingerprint), Some(address)) = (
        err.details
            .get("observed_fingerprint")
            .and_then(|v| v.as_str()),
        err.details.get("address").and_then(|v| v.as_str()),
    ) else {
        return Prompt::Unavailable;
    };
    if !io::stdin().is_terminal() {
        return Prompt::Unavailable;
    }

    let mut stderr = io::stderr().lock();
    let written = (|| -> io::Result<()> {
        writeln!(
            stderr,
            "The authenticity of peer {address} can't be established."
        )?;
        writeln!(stderr, "Fingerprint: {fingerprint}")?;
        write!(stderr, "Pin this peer as '{name}'? [y/N] ")?;
        stderr.flush()
    })();
    drop(stderr);
    if written.is_err() {
        return Prompt::Unavailable;
    }

    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return Prompt::Unavailable;
    }
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Prompt::Accepted(fingerprint.to_string()),
        _ => Prompt::Declined,
    }
}

/// Render one op result in whichever output mode was requested and return
/// the process exit code. Every command funnels through here so the
/// envelope/exit-code contract has exactly one implementation.
fn finish<T: Serialize>(
    cli: &Cli,
    command: &'static str,
    result: Result<T, OpError>,
    human: impl FnOnce(&T) -> io::Result<()>,
) -> i32 {
    match result {
        Ok(data) => {
            if cli.wants_json() {
                match serde_json::to_value(&data) {
                    Ok(value) => emit(Envelope::success(command, value).print()),
                    Err(err) => {
                        stderr_note!("qsh: failed to encode result: {err}");
                        EXIT_IO_FAILURE
                    }
                }
            } else {
                emit(human(&data))
            }
        }
        Err(err) => report_error(cli, command, &err),
    }
}

/// The dotted operation name a command reports in its envelope. The bare
/// interactive form (`qsh [user@]host`) has no subcommand; it reports the
/// first operation it performs, `session.open`.
fn command_name(cli: &Cli) -> &'static str {
    let Some(command) = &cli.command else {
        return SessionOpenOp::COMMAND;
    };
    match command {
        Command::Version => VersionOp::COMMAND,
        Command::Schema => SchemaOp::COMMAND,
        Command::Capabilities { .. } => CapabilitiesOp::COMMAND,
        Command::Doctor { .. } => DoctorOp::COMMAND,
        Command::Init { .. } => IdentityInitOp::COMMAND,
        Command::Trust(TrustCmd::Add(_)) => TrustAddOp::COMMAND,
        Command::Trust(TrustCmd::List) => TrustListOp::COMMAND,
        Command::Trust(TrustCmd::Remove { .. }) => TrustRemoveOp::COMMAND,
        Command::Trust(TrustCmd::Invite) => TrustInviteOp::COMMAND,
        Command::Trust(TrustCmd::Accept { .. }) => TrustAcceptOp::COMMAND,
        Command::Cert(CertCmd::Init) => CertInitOp::COMMAND,
        Command::Cert(CertCmd::Issue) => CertIssueOp::COMMAND,
        Command::Hosts => HostListOp::COMMAND,
        Command::Host(HostCmd::Get { .. }) => HostGetOp::COMMAND,
        Command::Acl(AclCmd::Check(_)) => AclCheckOp::COMMAND,
        Command::Exec(_) => ExecRunOp::COMMAND,
        Command::Attach(_) => SessionAttachOp::COMMAND,
        Command::Session(SessionCmd::Open(_)) => SessionOpenOp::COMMAND,
        Command::Session(SessionCmd::Get { .. }) => SessionGetOp::COMMAND,
        Command::Session(SessionCmd::Read(_)) => SessionReadOp::COMMAND,
        Command::Session(SessionCmd::Write(_)) => SessionWriteOp::COMMAND,
        Command::Session(SessionCmd::Resize { .. }) => SessionResizeOp::COMMAND,
        Command::Session(SessionCmd::Close { .. }) => SessionCloseOp::COMMAND,
        Command::Sessions { .. } => SessionListOp::COMMAND,
        Command::Tunnel(TunnelCmd::Open(_)) => TunnelOpenOp::COMMAND,
        Command::Tunnel(TunnelCmd::Close { .. }) => TunnelCloseOp::COMMAND,
        Command::Tunnels => TunnelListOp::COMMAND,
        Command::Serve { .. } => SERVE_MODE,
        Command::Listen { .. } => LISTEN_MODE,
        Command::Reverse { .. } => REVERSE_MODE,
        Command::Mcp => MCP_MODE,
    }
}

/// Render an [`OpError`] in whichever mode was requested and return the
/// process exit code for it.
fn report_error(cli: &Cli, command: &'static str, err: &OpError) -> i32 {
    let result = if cli.wants_json() {
        Envelope::failure(command, err).print()
    } else {
        human::print_error(err)
    };
    if let Err(io_err) = result {
        stderr_note!("qsh: failed to write output: {io_err}");
    }
    EXIT_RUNTIME_FAILURE
}

/// Turn a render `io::Result` into an exit code: `0` on success, the
/// runtime-failure code if we couldn't even write our own output.
fn emit(result: std::io::Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => {
            stderr_note!("qsh: failed to write output: {err}");
            EXIT_IO_FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use qsh_core::telemetry::{Recovery, RecoveryReport, TARGET};
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<String>>>);

    impl LineSink for Captured {
        fn write_line(&self, line: &str) {
            self.0.lock().expect("not poisoned").push(line.to_string());
        }
    }

    /// Run `body` with only the recovery layer installed, exactly as
    /// `init_tracing` composes it, and return the lines it wrote.
    fn capture(spec: Option<&str>, quiet: bool, body: impl FnOnce()) -> Vec<String> {
        let sink = Captured::default();
        let default = if quiet { "error" } else { "warn" };
        let recovery_default = format!("{default},{TARGET}=info");
        let enabled = !quiet;
        let layer = RecoveryLayer(sink.clone())
            .with_filter(env_filter(spec, &recovery_default))
            .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
                enabled && meta.target() == TARGET
            }));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, body);
        let lines = sink.0.lock().expect("not poisoned");
        lines.clone()
    }

    /// `docs/CLI.md` §6.4: at default verbosity a recovery is one line of
    /// pure JSON on stderr — no level, no timestamp, no target prefix.
    #[test]
    fn a_recovery_is_one_pure_json_line_at_default_verbosity() {
        let report = RecoveryReport::new(
            Recovery::Resumed,
            std::time::Duration::from_millis(412),
            "mac/01K0ABCD",
            0,
        );
        let expected = report.to_json_line();
        let lines = capture(None, false, || report.emit());
        assert_eq!(lines, vec![expected.clone()], "expected exactly one line");
        let parsed: serde_json::Value =
            serde_json::from_str(&lines[0]).expect("the line is pure JSON");
        assert_eq!(parsed["recovery"], "resumed");
        assert_eq!(parsed["time_to_recovery_ms"], 412);
        assert_eq!(parsed["session_ref"], "mac/01K0ABCD");
    }

    /// An ordinary diagnostic on another target never reaches this layer,
    /// so the stream stays parseable line by line.
    #[test]
    fn only_the_recovery_target_reaches_the_layer() {
        let lines = capture(None, false, || {
            tracing::info!("an ordinary diagnostic");
            tracing::warn!(target: "qsh::something", "another one");
        });
        assert!(lines.is_empty(), "{lines:?}");
    }

    /// `-q` means no diagnostics, and an explicit `QSH_LOG` governs the
    /// recovery stream like every other one.
    #[test]
    fn quiet_and_an_explicit_log_level_both_silence_it() {
        let report =
            RecoveryReport::new(Recovery::Failed, std::time::Duration::ZERO, "mac/01K0", 0);
        assert!(capture(None, true, || report.emit()).is_empty(), "-q");
        assert!(
            capture(Some("off"), false, || report.emit()).is_empty(),
            "off"
        );
        assert!(
            capture(Some("error"), false, || report.emit()).is_empty(),
            "error"
        );
        // …and asking for it explicitly still works.
        assert_eq!(
            capture(Some("qsh::recovery=info"), false, || report.emit()).len(),
            1
        );
    }

    /// `docs/CLI.md` §6.13: a `qsh listen` registration event
    /// (`RegistrationEvent`, `qsh_core::reverse::listen::TARGET`) is one
    /// line of pure JSON on stderr **at default verbosity** — exactly the
    /// same promise §6.4 makes for a recovery record, and `init_tracing`
    /// now wires a dedicated layer for it (mirroring `recovery`) instead of
    /// leaving it to fall through the `warn`-default human layer, which
    /// would either drop it entirely or wrap it in a timestamp/level prefix
    /// (adversarial review finding). This test pins the *composition* —
    /// the same `EnvFilter`/`filter_fn` shape `init_tracing` builds — not
    /// `RegistrationEvent` itself, which is private to `qsh-core` and
    /// already pins its own JSON shape in `reverse::listen`'s unit tests.
    #[test]
    fn a_reverse_registration_event_is_one_pure_json_line_at_default_verbosity() {
        let target = qsh_core::reverse::listen::TARGET;
        let sink = Captured::default();
        let default = "warn"; // `cli.verbose == 0`, `cli.quiet == false`
        let reverse_default = format!("{default},{target}=info");
        let layer = RecoveryLayer(sink.clone())
            .with_filter(env_filter(None, &reverse_default))
            .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
                meta.target() == target
            }));
        let subscriber = tracing_subscriber::registry().with(layer);
        let line =
            r#"{"event":"registered","host":"widget","fingerprint":"sha256:abc","generation":0}"#;
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: qsh_core::reverse::listen::TARGET, "{}", line);
        });
        let lines = sink.0.lock().expect("not poisoned");
        assert_eq!(
            *lines,
            vec![line.to_string()],
            "visible at default verbosity, byte-identical, no prefix"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&lines[0]).expect("the line is pure JSON");
        assert_eq!(parsed["event"], "registered");
        assert_eq!(parsed["host"], "widget");
    }

    /// `docs/CLI.md` §2.2/§6.12/§6.13: `qsh serve`/`qsh listen`/`qsh
    /// reverse` write zero bytes to stdout on every path, envelope
    /// included — even a setup failure this early (`Ops::from_env()`,
    /// before `run_serve`/`run_listen`/`run_reverse` exist to apply their
    /// own stderr-only error path). `run`'s dispatch on an
    /// `Ops::from_env()` failure must therefore route all three to
    /// [`report_long_running_setup_error`] (stderr only) rather than
    /// [`report_error`] (which prints a `qsh.cli/v1` envelope to stdout
    /// whenever `--json`/`--jsonl` was passed — `qsh serve` did exactly
    /// this until the PLAN.md Step 3.5 audit follow-up caught it). This
    /// pins the routing decision itself; `report_long_running_setup_error`'s
    /// own body is `human::print_error` verbatim, already proven
    /// stderr-only.
    #[test]
    fn ops_from_env_failure_routes_serve_listen_and_reverse_off_the_envelope_path() {
        assert_eq!(
            long_running_setup_mode(&Some(Command::Serve { bind: None })),
            Some(SERVE_MODE)
        );
        assert_eq!(
            long_running_setup_mode(&Some(Command::Listen { bind: None })),
            Some(LISTEN_MODE)
        );
        assert_eq!(
            long_running_setup_mode(&Some(Command::Reverse {
                controller: "widget".to_string(),
                offered_name: None,
            })),
            Some(REVERSE_MODE)
        );
        assert_eq!(long_running_setup_mode(&Some(Command::Mcp)), Some(MCP_MODE));
        // Every ordinary operation keeps using `report_error`'s envelope
        // path.
        assert_eq!(long_running_setup_mode(&Some(Command::Version)), None);
        assert_eq!(long_running_setup_mode(&None), None);
    }

    #[test]
    fn remote_exit_code_passes_through_except_255() {
        assert_eq!(remote_exit_code_to_process_exit(0), 0);
        assert_eq!(remote_exit_code_to_process_exit(7), 7);
        assert_eq!(remote_exit_code_to_process_exit(254), 254);
        assert_eq!(remote_exit_code_to_process_exit(255), 254);
        assert_eq!(remote_exit_code_to_process_exit(-1), 254);
        assert_eq!(remote_exit_code_to_process_exit(300), 254);
    }
}
