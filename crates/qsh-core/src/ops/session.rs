//! `session.*` value operations — client side (`docs/CLI.md` §6.2–6.7):
//! resolve the host through the trust store, dial with mutual TLS,
//! negotiate, send one control request, and assemble the `qsh.cli/v1`
//! payload. Every session is addressed by its opaque `session_ref`
//! (`<host-alias>/<session_id>`, ADR-0007), which only this module
//! assembles and parses.
//!
//! The stream operations (`session.attach`, `session.read --follow`) are
//! not here: they land with PLAN M2 Steps 5 and 7.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_proto::event::{EVENT_SCHEMA, SessionEvent};
use qsh_proto::wire::{self, session_read_event};
use qsh_proto::{
    ErrorCode, Session as SessionJson, SessionCloseData, SessionCloseReq, SessionGetReq,
    SessionListData, SessionListReq, SessionOpenData, SessionOpenReq, SessionReadData,
    SessionReadReq, SessionResizeData, SessionResizeReq, SessionWriteData, SessionWriteReq,
    UnreachableHost,
};
use qsh_transport::Dialer;

use crate::client::{ClientError, Session};
use crate::ops::exec::{map_client_error, map_dial_error};
use crate::ops::{OpError, Operation, Ops, PeerTarget};

/// Upper bound on the input one `session.write` accepts (`--stdin` or
/// `--data-b64`), 16 MiB. Keeps a single value op — and its stdin buffer —
/// bounded, the way `EXEC_OUTPUT_MAX` bounds one `exec.run` envelope.
pub const SESSION_WRITE_MAX: usize = 16 * 1024 * 1024;

/// The `session.open` operation.
pub struct SessionOpenOp;
impl Operation for SessionOpenOp {
    const COMMAND: &'static str = "session.open";
}

/// The `session.get` operation.
pub struct SessionGetOp;
impl Operation for SessionGetOp {
    const COMMAND: &'static str = "session.get";
}

/// The `session.list` operation.
pub struct SessionListOp;
impl Operation for SessionListOp {
    const COMMAND: &'static str = "session.list";
}

/// The `session.read` operation.
pub struct SessionReadOp;
impl Operation for SessionReadOp {
    const COMMAND: &'static str = "session.read";
}

/// The `session.write` operation.
pub struct SessionWriteOp;
impl Operation for SessionWriteOp {
    const COMMAND: &'static str = "session.write";
}

/// The `session.resize` operation.
pub struct SessionResizeOp;
impl Operation for SessionResizeOp {
    const COMMAND: &'static str = "session.resize";
}

/// The `session.close` operation.
pub struct SessionCloseOp;
impl Operation for SessionCloseOp {
    const COMMAND: &'static str = "session.close";
}

/// Result of [`Ops::session_read`]: the JSON payload plus the raw output
/// bytes of this pull concatenated in order, so a human-mode frontend can
/// pass them through verbatim without re-decoding the Base64.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionReadOutput {
    /// The `session.read` envelope payload (`docs/CLI.md` §6.4).
    pub data: SessionReadData,
    /// Raw session output of every `session.output` event, in order.
    pub output: Vec<u8>,
}

/// A parsed `session_ref`: the host alias and the host-issued session id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRef {
    /// Host alias (trust-store peer name).
    pub host: String,
    /// Host-issued opaque session id.
    pub session_id: String,
}

impl SessionRef {
    /// Assemble the opaque handle (`<host-alias>/<session_id>`).
    pub fn to_ref(&self) -> String {
        make_session_ref(&self.host, &self.session_id)
    }
}

/// Assemble a `session_ref` from its parts (ADR-0007).
pub fn make_session_ref(host: &str, session_id: &str) -> String {
    format!("{host}/{session_id}")
}

/// Parse a `session_ref` at its **last** `/` (host aliases may contain
/// `/`; session ids never do). Structural problems are `INVALID_ARGUMENT`;
/// whether the alias is known is checked by the caller (`HOST_NOT_FOUND`).
pub fn parse_session_ref(session_ref: &str) -> Result<SessionRef, OpError> {
    let invalid = |why: &str| {
        OpError::new(
            ErrorCode::InvalidArgument,
            format!("invalid session_ref {session_ref:?}: {why}"),
        )
    };
    let Some((host, session_id)) = session_ref.rsplit_once('/') else {
        return Err(invalid("expected <host>/<session_id>"));
    };
    if host.is_empty() {
        return Err(invalid("host alias is empty"));
    }
    if session_id.is_empty() {
        return Err(invalid("session id is empty"));
    }
    if !session_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(invalid(
            "session id must be URL-safe (alphanumeric, - or _)",
        ));
    }
    Ok(SessionRef {
        host: host.to_string(),
        session_id: session_id.to_string(),
    })
}

/// A wire `SessionInfo` as the `qsh.cli/v1` `Session` object on `host`.
fn session_json(host: &str, info: wire::SessionInfo) -> SessionJson {
    SessionJson {
        session_ref: make_session_ref(host, &info.session_id),
        host: host.to_string(),
        session_id: info.session_id,
        state: info.state,
        writer: info.writer,
        created_at: info.created_at,
        last_sequence: info.last_sequence,
    }
}

/// One wire read event as a `qsh.event/v1` event. Bodies this build does
/// not know are dropped (forward compatibility, `docs/CLI.md` §5.3).
fn event_json(session_ref: &str, event: wire::SessionReadEvent) -> Option<SessionEvent> {
    let schema = EVENT_SCHEMA.to_string();
    let session_ref = session_ref.to_string();
    Some(match event.body? {
        session_read_event::Body::Output(o) => SessionEvent::Output {
            schema,
            session_ref,
            sequence: o.sequence,
            data_b64: BASE64.encode(&o.data),
        },
        session_read_event::Body::Gap(g) => SessionEvent::Gap {
            schema,
            session_ref,
            requested_after: g.requested_after,
            available_from: g.available_from,
        },
        session_read_event::Body::Exit(x) => SessionEvent::Exit {
            schema,
            session_ref,
            sequence: x.final_seq,
            // A signal-terminated child has no exit code (CLI.md §6.4).
            exit_code: if x.signal.is_some() {
                None
            } else {
                Some(x.exit_code)
            },
            signal: x.signal,
        },
        session_read_event::Body::WriterChanged(w) => SessionEvent::WriterChanged {
            schema,
            session_ref,
            sequence: w.seq,
            writer: w.new_writer,
        },
        session_read_event::Body::Closed(c) => SessionEvent::Closed {
            schema,
            session_ref,
            sequence: c.seq,
            reason: c.reason,
        },
    })
}

impl Ops {
    /// `session.open` — create a session on `req.host` (`docs/CLI.md`
    /// §6.3). Value op: no attach, no PTY on this side; the returned
    /// `session_ref` is the handle for every later call.
    pub fn session_open(&self, req: SessionOpenReq) -> Result<SessionOpenData, OpError> {
        let host = req.host.clone();
        let msg = wire::SessionOpen {
            argv: req.argv,
            env: req.env.into_iter().map(|e| (e.name, e.value)).collect(),
            term: req.term.unwrap_or_default(),
            cols: req.cols.unwrap_or(0),
            rows: req.rows.unwrap_or(0),
            user: req.user,
        };
        let opened = self.call(&host, |s| Box::pin(s.session_open(msg)))?;
        Ok(SessionOpenData {
            session_ref: make_session_ref(&host, &opened.session_id),
            initial_sequence: opened.initial_seq,
        })
    }

    /// `session.get` — one session's snapshot (`docs/CLI.md` §6.2).
    pub fn session_get(&self, req: SessionGetReq) -> Result<SessionJson, OpError> {
        let r = parse_session_ref(&req.session_ref)?;
        let sid = r.session_id.clone();
        let info = self.call(&r.host, move |s| {
            Box::pin(async move { s.session_get(&sid).await })
        })?;
        Ok(session_json(&r.host, info))
    }

    /// `session.list` — sessions on one host, or on every pinned host with
    /// an address when `req.host` is `None` (`docs/CLI.md` §6.2). Hosts are
    /// visited in trust-store order. A single-host request fails as that
    /// host fails; the fan-out is best-effort per host — one sleeping
    /// laptop must not hide every other host's sessions — so unreachable
    /// hosts are reported in `unreachable` (additive) and the call only
    /// fails when *no* host answered.
    pub fn session_list(&self, req: SessionListReq) -> Result<SessionListData, OpError> {
        let (hosts, fan_out) = match req.host {
            Some(host) => (vec![host], false),
            None => (
                self.open_trust()?
                    .snapshot()
                    .peers()
                    .iter()
                    .filter(|p| !p.address.is_empty())
                    .map(|p| p.name.clone())
                    .collect(),
                true,
            ),
        };
        let mut sessions = Vec::new();
        let mut unreachable = Vec::new();
        let mut last_error = None;
        let mut answered = 0usize;
        for host in hosts {
            match self.call(&host, |s| Box::pin(s.session_list())) {
                Ok(infos) => {
                    answered += 1;
                    sessions.extend(infos.into_iter().map(|i| session_json(&host, i)));
                }
                Err(err) if fan_out => {
                    tracing::warn!(%host, code = %err.code, %err.message, "session.list: host unreachable");
                    unreachable.push(UnreachableHost {
                        host,
                        code: err.code.to_string(),
                        message: err.message.clone(),
                    });
                    last_error = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        if answered == 0
            && !unreachable.is_empty()
            && let Some(err) = last_error
        {
            // *No* host answered: that is the call failing, not a partial
            // answer. A host that answered with an empty list is an answer,
            // so it keeps the call successful. `unreachable` is on the
            // error too.
            let details = serde_json::json!({ "unreachable": unreachable });
            return Err(OpError {
                code: err.code,
                message: format!("no host answered session.list (last: {})", err.message),
                retryable: err.retryable,
                details,
            });
        }
        Ok(SessionListData {
            sessions,
            unreachable,
        })
    }

    /// `session.read` — one pull of the replay ring from the
    /// (`after_sequence`, `ctl_after`) cursor (`docs/CLI.md` §6.4),
    /// long-polling up to `wait_ms`. The reply carries the next cursor:
    /// a poller must feed `next_after`/`next_ctl_after` back, otherwise a
    /// control event positioned exactly at `after_sequence` is re-delivered
    /// on every pull and a `--wait` loop never parks.
    pub fn session_read(&self, req: SessionReadReq) -> Result<SessionReadOutput, OpError> {
        let r = parse_session_ref(&req.session_ref)?;
        let msg = wire::SessionRead {
            session_id: r.session_id.clone(),
            after: req.after_sequence,
            max_bytes: req.limit_bytes.unwrap_or(0),
            wait_ms: req.wait_ms.unwrap_or(0),
            ctl_after: req.ctl_after.unwrap_or(0),
        };
        let result = self.call(&r.host, |s| Box::pin(s.session_read(msg)))?;
        let mut output = Vec::new();
        let mut json_events = Vec::with_capacity(result.events.len());
        for event in result.events {
            if let Some(session_read_event::Body::Output(o)) = &event.body {
                output.extend_from_slice(&o.data);
            }
            if let Some(json) = event_json(&req.session_ref, event) {
                json_events.push(json);
            }
        }
        Ok(SessionReadOutput {
            data: SessionReadData {
                session_ref: req.session_ref,
                events: json_events,
                next_after: result.next_after,
                next_ctl_after: result.next_ctl_after,
            },
            output,
        })
    }

    /// `session.write` — inject Base64 input (`docs/CLI.md` §6.5).
    pub fn session_write(&self, req: SessionWriteReq) -> Result<SessionWriteData, OpError> {
        let data = BASE64.decode(req.data_b64.as_bytes()).map_err(|err| {
            OpError::new(
                ErrorCode::InvalidArgument,
                format!("data_b64 is not valid standard Base64: {err}"),
            )
        })?;
        self.session_write_bytes(&req.session_ref, data)
    }

    /// `session.write` with raw bytes (the CLI's `--stdin` path). Input
    /// longer than one wire chunk is sent as consecutive chunks on the same
    /// connection; `bytes_written` is the total the host accepted. One
    /// write is bounded by [`SESSION_WRITE_MAX`] (`INVALID_ARGUMENT`
    /// beyond it — a single envelope must stay bounded, `docs/CLI.md`
    /// §6.5); stream larger input through repeated writes or an attach.
    pub fn session_write_bytes(
        &self,
        session_ref: &str,
        data: Vec<u8>,
    ) -> Result<SessionWriteData, OpError> {
        let r = parse_session_ref(session_ref)?;
        if data.len() > SESSION_WRITE_MAX {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "session write input is {} bytes; one write is limited to {SESSION_WRITE_MAX} bytes",
                    data.len()
                ),
            ));
        }
        let bytes_written = self.call(&r.host, |s| {
            Box::pin(async move {
                let mut total = 0u64;
                let mut chunks = data.chunks(wire::SESSION_CHUNK_MAX).peekable();
                if chunks.peek().is_none() {
                    // An empty write still goes through the ACL path (and
                    // existence check) but takes no lease on the host.
                    return s.session_write(&r.session_id, Vec::new()).await;
                }
                for chunk in chunks {
                    total += s.session_write(&r.session_id, chunk.to_vec()).await?;
                }
                Ok(total)
            })
        })?;
        Ok(SessionWriteData {
            session_ref: session_ref.to_string(),
            bytes_written,
        })
    }

    /// `session.resize` (`docs/CLI.md` §6.6).
    pub fn session_resize(&self, req: SessionResizeReq) -> Result<SessionResizeData, OpError> {
        let r = parse_session_ref(&req.session_ref)?;
        let (Ok(cols), Ok(rows)) = (u16::try_from(req.cols), u16::try_from(req.rows)) else {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "cols and rows must be between 1 and 65535",
            ));
        };
        if cols == 0 || rows == 0 {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "cols and rows must be between 1 and 65535",
            ));
        }
        let sid = r.session_id.clone();
        let (cols, rows) = self.call(&r.host, move |s| {
            Box::pin(async move { s.session_resize(&sid, cols, rows).await })
        })?;
        Ok(SessionResizeData {
            session_ref: req.session_ref,
            cols: u32::from(cols),
            rows: u32::from(rows),
        })
    }

    /// `session.close` (`docs/CLI.md` §6.7). `signal` is validated here so
    /// a typo never reaches the wire.
    pub fn session_close(&self, req: SessionCloseReq) -> Result<SessionCloseData, OpError> {
        let r = parse_session_ref(&req.session_ref)?;
        let signal = match req.signal.as_deref() {
            None => None,
            Some(name) => Some(
                crate::broker::Signal::parse(name)
                    .ok_or_else(|| {
                        OpError::new(
                            ErrorCode::InvalidArgument,
                            format!(
                                "unknown signal {name:?}; expected one of HUP|INT|QUIT|TERM|USR1|USR2|KILL"
                            ),
                        )
                    })?
                    .as_str()
                    .to_string(),
            ),
        };
        let sid = r.session_id.clone();
        let final_sequence = self.call(&r.host, move |s| {
            Box::pin(async move { s.session_close(&sid, signal).await })
        })?;
        Ok(SessionCloseData {
            session_ref: req.session_ref,
            final_sequence,
        })
    }

    /// Dial `host`, negotiate, run one request closure on the session, and
    /// tear the connection down. Blocking: builds a runtime internally so
    /// frontends stay synchronous; the identity is loaded before entering
    /// it (platform key stores must not be touched from within one).
    fn call<T, F>(&self, host: &str, f: F) -> Result<T, OpError>
    where
        F: for<'a> FnOnce(
            &'a mut Session,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, ClientError>> + Send + 'a>,
        >,
    {
        let PeerTarget {
            identity,
            trust,
            address,
            server_name,
        } = self.resolve_peer(host)?;
        let device_name = identity.identity.device_id.clone();
        let dialer = Dialer::new(
            identity.local,
            trust as Arc<dyn qsh_transport::TrustEvaluator>,
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?;
        let result = runtime.block_on(async {
            let addr = tokio::net::lookup_host(&address)
                .await
                .ok()
                .and_then(|mut it| it.next())
                .ok_or_else(|| {
                    OpError::new(
                        ErrorCode::ConnectionFailed,
                        format!("cannot resolve {address:?}"),
                    )
                })?;
            let dialed = dialer
                .dial(addr, &server_name)
                .await
                .map_err(|err| map_dial_error(err, &address))?;
            let endpoint = dialed.endpoint.clone();
            let connection = dialed.connection.clone();
            let result = match Session::negotiate(dialed.connection, &device_name).await {
                Ok(mut session) => {
                    let result = f(&mut session).await;
                    session.close();
                    result
                }
                Err(err) => Err(err),
            };
            connection.close(0, b"done");
            drop(connection);
            endpoint.wait_idle().await;
            result.map_err(map_client_error)
        });
        // Let in-flight QUIC close frames drain (bounded).
        runtime.shutdown_timeout(Duration::from_millis(200));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ref_round_trips_and_splits_at_the_last_slash() {
        let r = parse_session_ref("box/01K0ABC").unwrap();
        assert_eq!(r.host, "box");
        assert_eq!(r.session_id, "01K0ABC");
        assert_eq!(r.to_ref(), "box/01K0ABC");
        let r = parse_session_ref("team/box/01K0ABC").unwrap();
        assert_eq!(r.host, "team/box");
        assert_eq!(r.session_id, "01K0ABC");
    }

    #[test]
    fn malformed_session_refs_are_invalid_argument() {
        for bad in ["", "box", "/01K0ABC", "box/", "box/has space", "box/a/b?"] {
            let err = parse_session_ref(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad:?}");
        }
    }

    #[test]
    fn exit_events_drop_the_code_when_signaled() {
        let signaled = event_json(
            "box/01K0",
            wire::SessionReadEvent::from_body(session_read_event::Body::Exit(wire::Exit {
                final_seq: 9,
                exit_code: -1,
                signal: Some("SIGKILL".into()),
            })),
        )
        .unwrap();
        assert!(matches!(
            signaled,
            SessionEvent::Exit {
                exit_code: None,
                sequence: 9,
                ..
            }
        ));
        let clean = event_json(
            "box/01K0",
            wire::SessionReadEvent::from_body(session_read_event::Body::Exit(wire::Exit {
                final_seq: 9,
                exit_code: 3,
                signal: None,
            })),
        )
        .unwrap();
        assert!(matches!(
            clean,
            SessionEvent::Exit {
                exit_code: Some(3),
                ..
            }
        ));
        // Unknown bodies are dropped, not an error.
        assert!(event_json("box/01K0", wire::SessionReadEvent { body: None }).is_none());
    }

    #[test]
    fn operation_commands_match_cli_md() {
        assert_eq!(SessionOpenOp::COMMAND, "session.open");
        assert_eq!(SessionGetOp::COMMAND, "session.get");
        assert_eq!(SessionListOp::COMMAND, "session.list");
        assert_eq!(SessionReadOp::COMMAND, "session.read");
        assert_eq!(SessionWriteOp::COMMAND, "session.write");
        assert_eq!(SessionResizeOp::COMMAND, "session.resize");
        assert_eq!(SessionCloseOp::COMMAND, "session.close");
    }
}
