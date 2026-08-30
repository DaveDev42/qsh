//! Human-readable text output. Kept deliberately dumb: it only formats
//! already-computed op results, never calls back into `qsh-core` logic.
//!
//! Results go to stdout, diagnostics and errors to stderr
//! (`docs/CLI.md` §2.2).

use std::io::{self, Write};

use qsh_core::{ExecRunOutput, OpError, SessionReadOutput};
use qsh_proto::{
    AclCheckData, CapabilitiesData, Host, HostListData, IdentityInitData, SchemaData, Session,
    SessionCloseData, SessionEvent, SessionListData, SessionOpenData, SessionResizeData,
    SessionWriteData, TrustAddData, TrustListData, TrustPeer, TrustRemoveData, Tunnel,
    TunnelCloseData, TunnelListData, VersionData,
};

use crate::stderr_note;

/// Print `qsh <version>` to stdout, plus the build commit when this binary
/// was compiled with one (`VersionData::build`, `docs/ROADMAP.md` M7 감사
/// 개정 ③).
pub fn print_version(data: &VersionData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    match &data.build {
        Some(build) => writeln!(stdout, "qsh {} ({})", data.version, build.commit),
        None => writeln!(stdout, "qsh {}", data.version),
    }
}

/// Print a short summary of `qsh schema` — the supported schema versions
/// and the commands a schema was generated for. The full JSON Schema
/// documents are what `--json` returns; human mode is a pointer, not a
/// dump (`docs/CLI.md` §6.10).
pub fn print_schema(data: &SchemaData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "schemas: {}", data.schemas.join(", "))?;
    writeln!(stdout, "commands ({}):", data.commands.len())?;
    for command in data.commands.keys() {
        writeln!(stdout, "  {command}")?;
    }
    Ok(())
}

/// Print `qsh capabilities [host]`: the capability list, and which host
/// (if any) it was negotiated with.
pub fn print_capabilities(data: &CapabilitiesData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    match &data.host {
        Some(host) => writeln!(stdout, "capabilities negotiated with {host}:")?,
        None => writeln!(stdout, "capabilities (local):")?,
    }
    if data.capabilities.is_empty() {
        return writeln!(stdout, "  (none)");
    }
    for capability in &data.capabilities {
        writeln!(stdout, "  {capability}")?;
    }
    Ok(())
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

/// Print the host table (`qsh hosts`, `docs/CLI.md` §6.1). The same name
/// appearing once per `connection_mode` is expected, not deduplicated —
/// `Ops::host_list` never merges forward and reverse entries.
pub fn print_hosts(data: &HostListData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    if data.hosts.is_empty() {
        return writeln!(stdout, "no hosts");
    }

    let width = |header: &str, field: fn(&Host) -> &str| {
        data.hosts
            .iter()
            .map(|h| field(h).chars().count())
            .chain(std::iter::once(header.chars().count()))
            .max()
            .unwrap_or(0)
    };
    let name_w = width("NAME", |h| &h.name);
    let mode_w = width("MODE", |h| &h.connection_mode);
    let state_w = width("STATE", |h| &h.state);

    writeln!(
        stdout,
        "{:name_w$}  {:mode_w$}  {:state_w$}  ADDRESS",
        "NAME", "MODE", "STATE"
    )?;
    for host in &data.hosts {
        writeln!(
            stdout,
            "{:name_w$}  {:mode_w$}  {:state_w$}  {}",
            sanitize(&host.name),
            sanitize(&host.connection_mode),
            sanitize(&host.state),
            sanitize(&host.address),
        )?;
    }
    Ok(())
}

/// Print one host (`qsh host get <name>`) — the route
/// [`qsh_core::Ops::resolve_host_route`] would actually use.
pub fn print_host(data: &Host) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "name:            {}", sanitize(&data.name))?;
    writeln!(
        stdout,
        "connection_mode: {}",
        sanitize(&data.connection_mode)
    )?;
    writeln!(stdout, "state:           {}", sanitize(&data.state))?;
    writeln!(stdout, "address:         {}", sanitize(&data.address))?;
    writeln!(stdout, "device_id:       {}", sanitize(&data.device_id))
}

/// Print `qsh acl check`'s verdict (`docs/CLI.md` §6.15) — one line to
/// stdout, exactly the shape (a)/§4 asks for: `"allow (rule 0)"` when a
/// rule matched, bare `"deny"`/`"allow"` when the decision stands without
/// one (always the case for `"deny"`), or `"deny (no policy loaded)"` when
/// `acl.toml` is missing or failed to parse. Zero authorization logic
/// here — every field is already decided by `Ops::acl_check`; this only
/// formats it. The policy file path is a separate stderr hint, not part
/// of the one-line stdout summary.
pub fn print_acl_check(data: &AclCheckData) -> io::Result<()> {
    let decision = sanitize(&data.decision);
    let line = if !data.policy.loaded {
        format!("{decision} (no policy loaded)")
    } else if let Some(rule) = data.rule {
        format!("{decision} (rule {rule})")
    } else {
        decision
    };
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{line}")?;
    stderr_note!("qsh: acl.toml path: {}", sanitize(&data.policy.path));
    Ok(())
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
        stderr_note!("qsh: remote command terminated by {}", sanitize(signal));
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
        stderr_note!(
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
/// verbatim on purpose (that is what the user asked to see). Also used by
/// the interactive TUI, which prints peer-supplied signal names and close
/// reasons onto a terminal it has just restored.
pub(crate) fn sanitize(text: &str) -> String {
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

/// Print one opened tunnel (`qsh tunnel open`, `docs/CLI.md` §6.9).
///
/// One line, the bound address first, because that is the thing the
/// operator has to point a client at — and with a `0` listen port it is
/// the only place the kernel-assigned port appears.
pub fn print_tunnel_open(tunnel: &Tunnel) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "{} -> {} on {} ({})",
        sanitize(&tunnel.bind),
        sanitize(&tunnel.forward_to),
        sanitize(&tunnel.host),
        sanitize(&tunnel.tunnel_id)
    )
}

/// Print the tunnel table (`qsh tunnels`, `docs/CLI.md` §6.9). Only ever
/// daemon-held reverse-route tunnels — `Ops::tunnel_list`'s own doc on why
/// a forward-route `qsh tunnel open` is never listed here.
pub fn print_tunnels(data: &TunnelListData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    if data.tunnels.is_empty() {
        return writeln!(stdout, "no tunnels");
    }

    let width = |header: &str, field: fn(&Tunnel) -> &str| {
        data.tunnels
            .iter()
            .map(|t| field(t).chars().count())
            .chain(std::iter::once(header.chars().count()))
            .max()
            .unwrap_or(0)
    };
    let id_w = width("TUNNEL_ID", |t| &t.tunnel_id);
    let mode_w = width("MODE", |t| &t.mode);
    let bind_w = width("BIND", |t| &t.bind);
    let fwd_w = width("FORWARD_TO", |t| &t.forward_to);

    writeln!(
        stdout,
        "{:id_w$}  {:mode_w$}  {:bind_w$}  {:fwd_w$}  HOST",
        "TUNNEL_ID", "MODE", "BIND", "FORWARD_TO"
    )?;
    for tunnel in &data.tunnels {
        writeln!(
            stdout,
            "{:id_w$}  {:mode_w$}  {:bind_w$}  {:fwd_w$}  {}",
            sanitize(&tunnel.tunnel_id),
            sanitize(&tunnel.mode),
            sanitize(&tunnel.bind),
            sanitize(&tunnel.forward_to),
            sanitize(&tunnel.host),
        )?;
    }
    Ok(())
}

/// Print the outcome of `qsh tunnel close`.
pub fn print_tunnel_close(data: &TunnelCloseData) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    if data.closed {
        writeln!(stdout, "closed {}", sanitize(&data.tunnel_id))
    } else {
        writeln!(
            stdout,
            "{} not found (nothing to do)",
            sanitize(&data.tunnel_id)
        )
    }
}

/// Announce a started `-L` forward on **stderr** (`qsh [user@]host -L …`).
///
/// stderr, not stdout: on the interactive form stdout is the remote
/// terminal's (`docs/CLI.md` §2.2). Structural only — a destination and a
/// bound address, never a byte of what the tunnel carries.
// Called only from `crate::tui::unix`, the `#[cfg(unix)]` interactive
// driver (`tui::run` is `UNSUPPORTED` on Windows, so no `-L` listener is
// ever started there) — dead, not absent, on Windows. `print_tunnel_open`
// above stays live everywhere: `run_tunnel_open` in `main.rs` is not gated.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn print_forward_started(tunnel: &Tunnel) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "qsh: forwarding {} -> {} on {}",
        sanitize(&tunnel.bind),
        sanitize(&tunnel.forward_to),
        sanitize(&tunnel.host)
    )
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
