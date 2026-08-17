//! Workspace-internal developer tasks. Not published, not part of the
//! product. Run via `cargo xtask <subcommand>` (see `.cargo/config.toml`).

mod arch;

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
        Some(other) => {
            eprintln!("xtask: unknown subcommand '{other}'");
            eprintln!("usage: cargo xtask arch");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("usage: cargo xtask arch");
            ExitCode::FAILURE
        }
    }
}
