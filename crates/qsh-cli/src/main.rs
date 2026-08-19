//! `qsh`: thin frontend binary. All business logic lives in `qsh-core`;
//! this crate only parses arguments, calls `qsh_core::Ops`, and renders the
//! result (`docs/CLI.md` §11).

mod cli;
mod render;
mod tui;

use std::io::{self, IsTerminal, Read, Write};

use clap::{CommandFactory as _, Parser};
use qsh_core::{
    ExecRunOp, ExecStdin, IdentityInitOp, OpError, Operation, Ops, SessionAttachOp, SessionCloseOp,
    SessionGetOp, SessionListOp, SessionOpenOp, SessionReadOp, SessionResizeOp, SessionWriteOp,
    TrustAddOp, TrustListOp, TrustRemoveOp, VersionOp,
};
use qsh_proto::{
    ErrorCode, ExecRunReq, IdentityInitReq, SessionCloseReq, SessionGetReq, SessionListReq,
    SessionOpenReq, SessionReadReq, SessionResizeReq, SessionWriteReq, TrustAddReq,
};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

use cli::{
    AttachArgs, Cli, Command, DEFAULT_ESCAPE_CHAR, EscapeChar, ExecArgs, SessionCmd,
    SessionReadArgs, SessionWriteArgs, TrustAddArgs, TrustCmd,
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

/// Usage error exit code (`docs/CLI.md` §4), matching clap's own.
const EXIT_USAGE: i32 = 2;

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
    // With no explicit spec, the recovery target sits at `info` whatever
    // `-v` says, because §6.4 fixes the record as visible at *default*
    // verbosity. An explicit spec governs it like anything else.
    let recovery_default = format!("{default},{}=info", qsh_core::telemetry::TARGET);
    let human = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_target(false)
        .with_filter(env_filter(spec.as_deref(), default))
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            meta.target() != qsh_core::telemetry::TARGET
        }));
    let recovery_enabled = !cli.quiet;
    let recovery = RecoveryLayer(StderrLines)
        .with_filter(env_filter(spec.as_deref(), &recovery_default))
        .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
            recovery_enabled && meta.target() == qsh_core::telemetry::TARGET
        }));
    tracing_subscriber::registry()
        .with(human)
        .with(recovery)
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
        Err(err) => return report_error(cli, command_name(cli), &err),
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
            },
            cli.interactive.escape_char,
        );
    };

    match command {
        Command::Version => finish(cli, VersionOp::COMMAND, ops.version(), human::print_version),
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
        Command::Serve { bind } => run_serve(&ops, bind.as_deref()),
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
                eprintln!("qsh: failed to encode result: {err}");
                return EXIT_IO_FAILURE;
            }
        }
    } else {
        human::print_exec(&output)
    };
    if let Err(err) = rendered {
        eprintln!("qsh: failed to write output: {err}");
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
                eprintln!("qsh serve: listening on {addr}");
                eprintln!("qsh serve: identity {device_id} fingerprint {fingerprint}");
            },
            shutdown_signal(),
        ))
    })();
    match result {
        Ok(()) => {
            eprintln!("qsh serve: shutting down");
            0
        }
        Err(err) => {
            if let Err(io_err) = human::print_error(&err) {
                eprintln!("qsh {SERVE_MODE}: failed to write output: {io_err}");
            }
            EXIT_RUNTIME_FAILURE
        }
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
                eprintln!("aborted");
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
                        eprintln!("qsh: failed to encode result: {err}");
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
        Command::Init { .. } => IdentityInitOp::COMMAND,
        Command::Trust(TrustCmd::Add(_)) => TrustAddOp::COMMAND,
        Command::Trust(TrustCmd::List) => TrustListOp::COMMAND,
        Command::Trust(TrustCmd::Remove { .. }) => TrustRemoveOp::COMMAND,
        Command::Exec(_) => ExecRunOp::COMMAND,
        Command::Attach(_) => SessionAttachOp::COMMAND,
        Command::Session(SessionCmd::Open(_)) => SessionOpenOp::COMMAND,
        Command::Session(SessionCmd::Get { .. }) => SessionGetOp::COMMAND,
        Command::Session(SessionCmd::Read(_)) => SessionReadOp::COMMAND,
        Command::Session(SessionCmd::Write(_)) => SessionWriteOp::COMMAND,
        Command::Session(SessionCmd::Resize { .. }) => SessionResizeOp::COMMAND,
        Command::Session(SessionCmd::Close { .. }) => SessionCloseOp::COMMAND,
        Command::Sessions { .. } => SessionListOp::COMMAND,
        Command::Serve { .. } => SERVE_MODE,
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
        eprintln!("qsh: failed to write output: {io_err}");
    }
    EXIT_RUNTIME_FAILURE
}

/// Turn a render `io::Result` into an exit code: `0` on success, the
/// runtime-failure code if we couldn't even write our own output.
fn emit(result: std::io::Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("qsh: failed to write output: {err}");
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
        let report = RecoveryReport::new(Recovery::Failed, std::time::Duration::ZERO, "mac/01K0");
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
