//! `qsh`: thin frontend binary. All business logic lives in `qsh-core`;
//! this crate only parses arguments, calls `qsh_core::Ops`, and renders the
//! result (`docs/CLI.md` §11).

mod cli;
mod render;

use clap::Parser;
use qsh_core::{OpError, Operation, Ops, VersionOp};

use cli::{Cli, Command};
use render::{human, json::Envelope};

/// QSH runtime failure exit code (`docs/CLI.md` §4): connection, auth,
/// policy or any other `OpError`.
const EXIT_RUNTIME_FAILURE: i32 = 255;

/// I/O failure writing our own output. Not a documented exit code by
/// itself, but reuses the runtime-failure code since it is just as fatal.
const EXIT_IO_FAILURE: i32 = 255;

fn main() {
    // `Cli::parse()` exits with code 2 on usage errors and 0 on
    // `--help`/`--version`, per clap's default behavior.
    let cli = Cli::parse();
    let exit_code = run(&cli);
    std::process::exit(exit_code);
}

fn run(cli: &Cli) -> i32 {
    match &cli.command {
        Command::Version => run_version(cli),
    }
}

fn run_version(cli: &Cli) -> i32 {
    match Ops::version() {
        Ok(data) => {
            if cli.wants_json() {
                match serde_json::to_value(&data) {
                    Ok(value) => emit(Envelope::success(VersionOp::COMMAND, value).print()),
                    Err(err) => {
                        eprintln!("qsh: failed to encode result: {err}");
                        EXIT_IO_FAILURE
                    }
                }
            } else {
                emit(human::print_version(&data))
            }
        }
        Err(err) => report_error(cli, VersionOp::COMMAND, &err),
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
