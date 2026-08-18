//! Human-readable text output. Kept deliberately dumb: it only formats
//! already-computed op results, never calls back into `qsh-core` logic.
//!
//! Results go to stdout, diagnostics and errors to stderr
//! (`docs/CLI.md` §2.2).

use std::io::{self, Write};

use qsh_core::{ExecRunOutput, OpError, SessionReadOutput};
use qsh_proto::{
    IdentityInitData, Session, SessionCloseData, SessionEvent, SessionListData, SessionOpenData,
    SessionResizeData, SessionWriteData, TrustAddData, TrustListData, TrustPeer, TrustRemoveData,
    VersionData,
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

/// Print the outcome of `qsh session open`.
pub fn print_session_open(data: &SessionOpenData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{}", sanitize(&data.session_ref))
}

/// Print one session (`qsh session get`).
pub fn print_session(session: &Session) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "session_ref:   {}", sanitize(&session.session_ref))?;
    writeln!(stdout, "host:          {}", sanitize(&session.host))?;
    writeln!(stdout, "state:         {}", sanitize(&session.state))?;
    writeln!(
        stdout,
        "writer:        {}",
        session
            .writer
            .as_deref()
            .map_or_else(|| "-".to_string(), sanitize)
    )?;
    writeln!(stdout, "created_at:    {}", sanitize(&session.created_at))?;
    writeln!(stdout, "last_sequence: {}", session.last_sequence)
}

/// Print the session table (`qsh sessions`).
pub fn print_session_list(data: &SessionListData) -> io::Result<()> {
    // Hosts the fan-out could not reach are a stderr diagnostic, never a
    // table row (`docs/CLI.md` §2.2, §6.2).
    for h in &data.unreachable {
        eprintln!(
            "qsh: {}: unreachable: {} ({})",
            sanitize(&h.host),
            sanitize(&h.message),
            sanitize(&h.code)
        );
    }
    let mut stdout = io::stdout().lock();
    if data.sessions.is_empty() {
        return writeln!(stdout, "no sessions");
    }
    let rows: Vec<[String; 5]> = data
        .sessions
        .iter()
        .map(|s| {
            [
                sanitize(&s.session_ref),
                sanitize(&s.state),
                s.writer
                    .as_deref()
                    .map_or_else(|| "-".to_string(), sanitize),
                s.last_sequence.to_string(),
                sanitize(&s.created_at),
            ]
        })
        .collect();
    let headers = ["SESSION", "STATE", "WRITER", "SEQ", "CREATED"];
    let widths: Vec<usize> = (0..headers.len())
        .map(|i| {
            rows.iter()
                .map(|r| r[i].chars().count())
                .chain(std::iter::once(headers[i].len()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cells: [&str; 5]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i + 1 == cells.len() {
                    c.to_string()
                } else {
                    format!("{:w$}", c, w = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    writeln!(stdout, "{}", line(headers))?;
    for row in &rows {
        writeln!(
            stdout,
            "{}",
            line([&row[0], &row[1], &row[2], &row[3], &row[4]])
        )?;
    }
    Ok(())
}

/// `qsh session read` in human mode: the raw session output goes to stdout
/// verbatim; every other event (`exit`, `writer_changed`, `closed`, `gap`)
/// is a one-line structural note on stderr so it never mixes into the
/// output stream.
pub fn print_session_read(output: &SessionReadOutput) -> io::Result<()> {
    if !output.output.is_empty() {
        let mut stdout = io::stdout().lock();
        stdout.write_all(&output.output)?;
        stdout.flush()?;
    }
    let mut stderr = io::stderr().lock();
    for event in &output.data.events {
        match event {
            SessionEvent::Output { .. } | SessionEvent::Unknown(_) => {}
            SessionEvent::Gap {
                requested_after,
                available_from,
                ..
            } => writeln!(
                stderr,
                "qsh: session output gap: requested after {requested_after}, available from {available_from}"
            )?,
            SessionEvent::Exit {
                sequence,
                exit_code,
                signal,
                ..
            } => match (exit_code, signal) {
                (_, Some(signal)) => writeln!(
                    stderr,
                    "qsh: session exited (terminated by {}) at sequence {sequence}",
                    sanitize(signal)
                )?,
                (Some(code), None) => writeln!(
                    stderr,
                    "qsh: session exited with code {code} at sequence {sequence}"
                )?,
                (None, None) => writeln!(stderr, "qsh: session exited at sequence {sequence}")?,
            },
            SessionEvent::WriterChanged {
                sequence, writer, ..
            } => writeln!(
                stderr,
                "qsh: session writer is now {} (sequence {sequence})",
                writer.as_deref().map_or_else(|| "-".to_string(), sanitize)
            )?,
            SessionEvent::Closed {
                sequence, reason, ..
            } => writeln!(
                stderr,
                "qsh: session closed ({}) at sequence {sequence}",
                sanitize(reason)
            )?,
        }
    }
    stderr.flush()
}

/// Print the outcome of `qsh session write`.
pub fn print_session_write(data: &SessionWriteData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "wrote {} bytes", data.bytes_written)
}

/// Print the outcome of `qsh session resize`.
pub fn print_session_resize(data: &SessionResizeData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "resized to {}x{}", data.cols, data.rows)
}

/// Print the outcome of `qsh session close`.
pub fn print_session_close(data: &SessionCloseData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "closed {} (final sequence {})",
        sanitize(&data.session_ref),
        data.final_sequence
    )
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
