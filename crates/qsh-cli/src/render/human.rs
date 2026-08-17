//! Human-readable text output. Kept deliberately dumb: it only formats
//! already-computed op results, never calls back into `qsh-core` logic.

use std::io::{self, Write};

use qsh_core::OpError;
use qsh_proto::VersionData;

/// Print `qsh <version>` to stdout.
pub fn print_version(data: &VersionData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "qsh {}", data.version)
}

/// Print a human-readable error line to stderr.
pub fn print_error(err: &OpError) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "qsh: {} ({})", err.message, err.code)
}
