//! Workspace-internal developer tasks. Not published, not part of the
//! product. Run via `cargo xtask <subcommand>` (see `.cargo/config.toml`).

mod arch;
mod man;
mod perf;

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let workspace_root = match Path::new(env!("CARGO_MANIFEST_DIR")).parent() {
        Some(root) => root,
        None => {
            eprintln!("xtask: could not determine workspace root from CARGO_MANIFEST_DIR");
            return ExitCode::FAILURE;
        }
    };

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("arch") => match arch::run(workspace_root) {
            Ok(()) => {
                println!("xtask arch: OK");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("xtask arch: {err:#}");
                ExitCode::FAILURE
            }
        },
        Some("man") => match man::run(workspace_root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask man: {err:#}");
                ExitCode::FAILURE
            }
        },
        Some("perf-judge") => match perf::run(args) {
            Ok(verdict) => {
                println!("{verdict}");
                if verdict.is_red() {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(err) => {
                eprintln!("xtask perf-judge: {err:#}");
                // Exit 2 keeps a judge failure apart from a red verdict (1).
                ExitCode::from(2)
            }
        },
        Some(other) => {
            eprintln!("xtask: unknown subcommand '{other}'");
            eprintln!("usage: cargo xtask arch|man|perf-judge");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("usage: cargo xtask arch|man|perf-judge");
            ExitCode::FAILURE
        }
    }
}
