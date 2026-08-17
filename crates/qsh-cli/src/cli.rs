//! Argument parsing only. No business logic lives here — see `docs/CLI.md`
//! §11: this module's job ends at producing a [`Cli`] value for `main` to
//! dispatch on `qsh_core::Ops`.

use clap::{Parser, Subcommand};

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
}
