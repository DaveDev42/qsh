//! `qsh`: thin frontend binary. All business logic lives in `qsh-core`;
//! this crate only parses arguments, calls `qsh_core::Ops`, and renders the
//! result (`docs/CLI.md` §11).

mod cli;
mod render;

use std::io::{self, IsTerminal, Write};

use clap::Parser;
use qsh_core::{
    ExecRunOp, ExecStdin, IdentityInitOp, OpError, Operation, Ops, TrustAddOp, TrustListOp,
    TrustRemoveOp, VersionOp,
};
use qsh_proto::{ErrorCode, ExecRunReq, IdentityInitReq, TrustAddReq};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command, ExecArgs, TrustAddArgs, TrustCmd};
use render::{human, json::Envelope};

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
fn init_tracing(cli: &Cli) {
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
    let filter = EnvFilter::try_from_env("QSH_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn run(cli: &Cli) -> i32 {
    let ops = match Ops::from_env() {
        Ok(ops) => ops,
        Err(err) => return report_error(cli, command_name(&cli.command), &err),
    };

    match &cli.command {
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
        Command::Serve { bind } => run_serve(&ops, bind.as_deref()),
    }
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

/// The dotted operation name a subcommand reports in its envelope.
fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Version => VersionOp::COMMAND,
        Command::Init { .. } => IdentityInitOp::COMMAND,
        Command::Trust(TrustCmd::Add(_)) => TrustAddOp::COMMAND,
        Command::Trust(TrustCmd::List) => TrustListOp::COMMAND,
        Command::Trust(TrustCmd::Remove { .. }) => TrustRemoveOp::COMMAND,
        Command::Exec(_) => ExecRunOp::COMMAND,
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
    use super::*;

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
