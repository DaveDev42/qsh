//! `qsh::lifecycle`: one-line JSON records for the moments a long-running
//! process starts serving and stops (`docs/CLI.md` §6.12, §6.13, §6.14,
//! ADR-0023 decision 21).
//!
//! The human lines (`qsh serve: listening on {addr}` and friends) keep their
//! bytes, because outside parsers read an address after the prefix. These
//! records sit beside them and carry what those lines cannot: a timestamp
//! and a machine-readable process kind. They go through `tracing` under
//! [`TARGET`]; `qsh-cli` routes that target to stderr as a bare JSON line
//! and never to stdout (`docs/CLI.md` §2.2).
//!
//! A record never carries an address, a bind address, a token or an error
//! body. The address is already on the human line.

use serde::Serialize;

/// The tracing target the records are emitted under.
pub const TARGET: &str = "qsh::lifecycle";

/// Which kind of process a record is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Process {
    /// `qsh serve` accepting inbound connections.
    Serve,
    /// `qsh listen`, the reverse-route controller side.
    Listen,
    /// `qsh serve --to` (and the hidden `qsh reverse`), the reverse target.
    ServeTo,
    /// `qsh tunnel open`.
    Tunnel,
}

/// What a record says happened. Serialized as the first key, `lifecycle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Event {
    Listening,
    ShuttingDown,
    Drained,
    TunnelOpened,
    TunnelEnded,
}

/// The tunnel a `tunnel_*` record is about.
#[derive(Debug, Clone, Copy)]
pub struct TunnelFacts<'a> {
    /// The tunnel's id, as the envelope reported it.
    pub tunnel_id: &'a str,
    /// `local`, `remote` or `dynamic`.
    pub mode: &'a str,
    /// Whether the tunnel runs under `--supervise`.
    pub supervise: bool,
}

/// Field order is the wire order: `lifecycle` is first.
#[derive(Serialize)]
struct Line<'a> {
    lifecycle: Event,
    at: String,
    process: Process,
    #[serde(skip_serializing_if = "Option::is_none")]
    sessions_closed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detached_closed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timed_out: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tunnel_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supervise: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<&'a str>,
}

fn line(event: Event, process: Process) -> Line<'static> {
    Line {
        lifecycle: event,
        at: crate::config::now_rfc3339(),
        process,
        sessions_closed: None,
        detached_closed: None,
        timed_out: None,
        tunnel_id: None,
        mode: None,
        supervise: None,
        code: None,
        cause: None,
    }
}

fn emit(line: &Line<'_>) {
    let json = serde_json::to_string(line).unwrap_or_else(|_| "{}".to_string());
    tracing::info!(target: TARGET, "{}", json);
}

/// The process is ready to serve. For `serve` and `listen` this sits next to
/// the human `listening on` line; `serve --to` has no such line, so here it
/// means the runtime is up and the first dial is about to start.
pub fn listening(process: Process) {
    emit(&line(Event::Listening, process));
}

/// The process was told to stop and is exiting on purpose.
pub fn shutting_down(process: Process) {
    emit(&line(Event::ShuttingDown, process));
}

/// What a SIGTERM drain did, in counts only: no session id, command, PTY
/// content or address (`docs/CLI.md` §6.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainSummary {
    /// Sessions that were live when the drain started and are closed now.
    pub sessions_closed: usize,
    /// The subset of [`Self::sessions_closed`] that had no attached consumer.
    pub detached_closed: usize,
    /// The drain hit `DRAIN_TIMEOUT` and gave up on the rest.
    pub timed_out: bool,
}

/// The drain finished (or gave up). Emitted by `Server::drain`, before the
/// process exits, so a restart leaves a record of what it erased.
pub fn drained(process: Process, summary: DrainSummary) {
    let mut record = line(Event::Drained, process);
    record.sessions_closed = Some(summary.sessions_closed);
    record.detached_closed = Some(summary.detached_closed);
    record.timed_out = Some(summary.timed_out);
    emit(&record);
}

/// The one human line `qsh serve` and `qsh serve --to` print after their
/// listening lines (without the `qsh serve: ` style prefix, which the caller
/// adds): sessions live inside this process, so a restart erases every
/// detached one. `qsh-cli` prints it unless `--quiet`.
pub const RESTART_BANNER: &str =
    "sessions live inside this process; a restart drops every detached session";

/// A tunnel is open and the envelope has been reported.
pub fn tunnel_opened(tunnel: TunnelFacts<'_>) {
    let mut record = line(Event::TunnelOpened, Process::Tunnel);
    record.tunnel_id = Some(tunnel.tunnel_id);
    record.mode = Some(tunnel.mode);
    record.supervise = Some(tunnel.supervise);
    emit(&record);
}

/// A tunnel ended on its own. `code` is the `ErrorCode` string and `cause`
/// the connection-level reason when it is known.
pub fn tunnel_ended(tunnel: TunnelFacts<'_>, code: &str, cause: Option<&str>) {
    let mut record = line(Event::TunnelEnded, Process::Tunnel);
    record.tunnel_id = Some(tunnel.tunnel_id);
    record.mode = Some(tunnel.mode);
    record.supervise = Some(tunnel.supervise);
    record.code = Some(code);
    record.cause = cause;
    emit(&record);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_starts_with_the_lifecycle_key_and_omits_absent_fields() {
        let json = serde_json::to_string(&line(Event::Listening, Process::ServeTo)).unwrap();
        assert!(
            json.starts_with(r#"{"lifecycle":"listening","at":""#),
            "{json}"
        );
        assert!(json.contains(r#""process":"serve_to""#), "{json}");
        assert!(
            !json.contains("tunnel_id") && !json.contains("cause"),
            "{json}"
        );
    }

    #[test]
    fn a_drained_line_carries_counts_and_the_timeout_verdict_only() {
        let mut record = line(Event::Drained, Process::Serve);
        record.sessions_closed = Some(3);
        record.detached_closed = Some(2);
        record.timed_out = Some(false);
        let json = serde_json::to_string(&record).unwrap();
        assert!(
            json.starts_with(r#"{"lifecycle":"drained","at":""#),
            "{json}"
        );
        assert!(
            json.ends_with(
                r#""process":"serve","sessions_closed":3,"detached_closed":2,"timed_out":false}"#
            ),
            "{json}"
        );
    }

    #[test]
    fn a_tunnel_line_carries_the_tunnel_facts_and_the_end_its_code() {
        let mut record = line(Event::TunnelEnded, Process::Tunnel);
        record.tunnel_id = Some("t1");
        record.mode = Some("dynamic");
        record.supervise = Some(false);
        record.code = Some("CONNECTION_FAILED");
        record.cause = Some("idle_timeout");
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains(r#""tunnel_id":"t1","mode":"dynamic","supervise":false,"code":"CONNECTION_FAILED","cause":"idle_timeout""#), "{json}");
    }
}
