//! Human-readable text output. Kept deliberately dumb: it only formats
//! already-computed op results, never calls back into `qsh-core` logic.
//!
//! Results go to stdout, diagnostics and errors to stderr
//! (`docs/CLI.md` §2.2).

use std::io::{self, Write};

use qsh_core::{ExecRunOutput, OpError};
use qsh_proto::{
    IdentityInitData, TrustAddData, TrustListData, TrustPeer, TrustRemoveData, VersionData,
};

/// Print `qsh <version>` to stdout.
pub fn print_version(data: &VersionData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "qsh {}", data.version)
}

/// Print the device identity `qsh init` created (or found).
pub fn print_init(data: &IdentityInitData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "device_id:   {}", data.device_id)?;
    writeln!(stdout, "fingerprint: {}", data.fingerprint)?;
    writeln!(stdout, "key_store:   {}", data.key_store.as_str())?;
    writeln!(stdout, "config_dir:  {}", data.config_dir)?;
    writeln!(
        stdout,
        "{}",
        if data.created {
            "created"
        } else {
            "already initialized"
        }
    )
}

/// Print the outcome of `qsh trust add`.
pub fn print_trust_add(data: &TrustAddData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    let verb = if data.created {
        "pinned"
    } else {
        "already pinned"
    };
    let peer = &data.peer;
    if peer.address.is_empty() {
        writeln!(stdout, "{verb} {} ({})", peer.name, peer.fingerprint)
    } else {
        writeln!(
            stdout,
            "{verb} {} ({}) [{}]",
            peer.name, peer.fingerprint, peer.address
        )
    }
}

/// Print the pinned-peer table.
pub fn print_trust_list(data: &TrustListData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    if data.peers.is_empty() {
        return writeln!(stdout, "no trusted peers");
    }

    let width = |header: &str, field: fn(&TrustPeer) -> &str| {
        data.peers
            .iter()
            .map(|p| field(p).chars().count())
            .chain(std::iter::once(header.chars().count()))
            .max()
            .unwrap_or(0)
    };
    let name_w = width("NAME", |p| &p.name);
    let fp_w = width("FINGERPRINT", |p| &p.fingerprint);
    let addr_w = width("ADDRESS", |p| &p.address);

    writeln!(
        stdout,
        "{:name_w$}  {:fp_w$}  {:addr_w$}  ADDED",
        "NAME", "FINGERPRINT", "ADDRESS"
    )?;
    for peer in &data.peers {
        writeln!(
            stdout,
            "{:name_w$}  {:fp_w$}  {:addr_w$}  {}",
            peer.name, peer.fingerprint, peer.address, peer.added_at
        )?;
    }
    Ok(())
}

/// Print the outcome of `qsh trust remove`.
pub fn print_trust_remove(data: &TrustRemoveData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    if data.removed {
        writeln!(stdout, "removed {}", data.name)
    } else {
        writeln!(stdout, "{} not found (nothing to do)", data.name)
    }
}

/// `qsh exec` in human mode is a passthrough: the remote command's stdout
/// and stderr bytes go to ours, verbatim, and its exit code becomes ours
/// (the caller applies the `255 → 254` clamp, `docs/CLI.md` §4).
pub fn print_exec(output: &ExecRunOutput) -> io::Result<()> {
    if !output.stderr.is_empty() {
        let mut stderr = io::stderr().lock();
        stderr.write_all(&output.stderr)?;
        stderr.flush()?;
    }
    if !output.stdout.is_empty() {
        let mut stdout = io::stdout().lock();
        stdout.write_all(&output.stdout)?;
        stdout.flush()?;
    }
    if let Some(signal) = &output.data.signal {
        eprintln!("qsh: remote command terminated by {}", sanitize(signal));
    }
    Ok(())
}

/// Strip control characters (except `\t`) from text that may have been
/// influenced by a remote peer — error messages, signal names — so a
/// hostile host cannot smuggle terminal escape sequences or fake extra
/// lines into *our* diagnostics. Command output itself is passed through
/// verbatim on purpose (that is what the user asked to see).
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\t' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Print a human-readable error line to stderr.
pub fn print_error(err: &OpError) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "qsh: {} ({})",
        sanitize(&err.message),
        sanitize(err.code.as_str())
    )
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn sanitize_strips_escapes_and_newlines_but_keeps_tabs() {
        assert_eq!(sanitize("plain text"), "plain text");
        assert_eq!(
            sanitize("a\u{1b}[31mred\u{1b}[0m\nfake line\ttab"),
            "a\u{FFFD}[31mred\u{FFFD}[0m\u{FFFD}fake line\ttab"
        );
    }
}
