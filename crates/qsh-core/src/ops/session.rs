//! `session.*` value operations — client side (`docs/CLI.md` §6.2–6.7):
//! resolve the host through the trust store, dial with mutual TLS,
//! negotiate, send one control request, and assemble the `qsh.cli/v1`
//! payload. Every session is addressed by its opaque `session_ref`
//! (`<host-alias>/<session_id>`, ADR-0007), which only this module
//! assembles and parses.
//!
//! The stream operations live here too: [`Ops::session_reader`] is the
//! single cursor-pull primitive (`--wait`, `--follow`, and M6's MCP
//! long-poll all go through it) and [`Ops::session_attach`] is the one
//! stream op, a live `SESSION_DATA` stream as a typed event stream.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_proto::event::{EVENT_SCHEMA, SessionEvent};
use qsh_proto::wire::{self, session_read_event};
use qsh_proto::{
    ErrorCode, Session as SessionJson, SessionAttachReq, SessionCloseData, SessionCloseReq,
    SessionGetReq, SessionListData, SessionListReq, SessionOpenData, SessionOpenReq,
    SessionReadData, SessionReadReq, SessionResizeData, SessionResizeReq, SessionWriteData,
    SessionWriteReq, UnreachableHost,
};
use qsh_transport::Dialer;

use crate::client::{ClientError, Session};
use crate::ops::exec::{map_client_error, map_dial_error};
use crate::ops::{OpError, Operation, Ops, PeerTarget};
use crate::resume::{NoToken, ResumeStore, StoredToken};

/// Upper bound on the input one `session.write` accepts (`--stdin` or
/// `--data-b64`), 16 MiB. Keeps a single value op — and its stdin buffer —
/// bounded, the way `EXEC_OUTPUT_MAX` bounds one `exec.run` envelope.
pub const SESSION_WRITE_MAX: usize = 16 * 1024 * 1024;

/// Depth of the two queues between a frontend and its attach driver — the
/// same bound the host puts on its own side of the stream. Bounded on
/// purpose: an unbounded event queue would let a slow renderer grow client
/// memory without limit *and* remove QUIC flow control from the session
/// stream (protocol.md §12, architecture.md §9-5).
pub const SESSION_ATTACH_QUEUE: usize = 64;

/// How long the control stream gets to deliver a `session.closed` that was
/// queued just before the data stream's FIN. Not a synchronisation sleep:
/// the drain ends as soon as the control stream closes or an event lands.
const ATTACH_CONTROL_DRAIN: Duration = Duration::from_millis(250);

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
        // Not `call`: the resume credential is bound to the peer that
        // issued it (protocol.md §10-2), so the fingerprint of *this*
        // connection has to be read before the connection is torn down.
        let mut conn = self.connect(&host)?;
        let peer = conn.peer_fingerprint();
        let opened = conn.run(move |s| Box::pin(s.session_open(msg)));
        conn.close();
        let opened = opened?;
        let session_ref = make_session_ref(&host, &opened.session_id);
        self.remember_resume(
            &session_ref,
            &host,
            &opened.session_id,
            &opened.resume_token,
            peer.as_deref(),
            &opened.expires_at,
        );
        Ok(SessionOpenData {
            session_ref,
            initial_sequence: opened.initial_seq,
        })
    }

    /// Persist a freshly issued resume credential, if there is one to
    /// persist and a peer to bind it to.
    ///
    /// Deliberately best-effort and silent about the token itself: a
    /// `session.open` that succeeded on the host has created a session,
    /// and failing the operation because a local state file could not be
    /// written would leave the caller with no handle to a session that
    /// exists. What is lost is the ability to resume it across a
    /// connection — which is reported as a warning (never the token).
    fn remember_resume(
        &self,
        session_ref: &str,
        host: &str,
        session_id: &str,
        token: &[u8],
        peer: Option<&str>,
        expires_at: &str,
    ) {
        if token.is_empty() {
            return;
        }
        let (Some(peer), Some(token)) = (peer, StoredToken::from_slice(token)) else {
            tracing::warn!(
                %session_ref,
                "host issued a resume credential this client cannot bind; \
                 the session will not survive a reconnect"
            );
            return;
        };
        if let Err(err) = ResumeStore::new(&self.paths).put(
            session_ref,
            host,
            session_id,
            token,
            peer,
            expires_at,
        ) {
            tracing::warn!(
                %session_ref,
                error = %err.message,
                "could not store the resume credential; the session will \
                 not survive a reconnect"
            );
        }
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
        // One pull of the same primitive `--follow` loops on, so the two
        // cannot drift: there is only one implementation of a pull.
        let mut reader = self.session_reader(req)?;
        let result = reader.pull();
        reader.close();
        result
    }

    /// The cursor-pull primitive `session read` sits on: a live connection
    /// plus a cursor that advances with every [`SessionReader::pull`].
    ///
    /// `session read --wait` is exactly one `pull`, `--follow` is a loop of
    /// them, and M6's MCP long-poll will be a third caller — all of them
    /// the same code path, so a fix or a cap applies to every consumer at
    /// once. `req`'s cursor and `wait_ms`/`limit_bytes` seed the reader;
    /// each pull then feeds `next_after`/`next_ctl_after` back, which is
    /// what keeps a control event positioned exactly at `after_sequence`
    /// from being re-delivered for ever.
    pub fn session_reader(&self, req: SessionReadReq) -> Result<SessionReader, OpError> {
        let r = parse_session_ref(&req.session_ref)?;
        let conn = self.connect(&r.host)?;
        Ok(SessionReader {
            conn,
            store: ResumeStore::new(&self.paths),
            session_ref: req.session_ref,
            session_id: r.session_id,
            after: req.after_sequence,
            ctl_after: req.ctl_after.unwrap_or(0),
            wait_ms: req.wait_ms.unwrap_or(0),
            max_bytes: req.limit_bytes.unwrap_or(0),
            done: false,
        })
    }

    /// `session.attach` — the one **stream** operation (`docs/CLI.md` §6.1):
    /// authorize the attach, open the `SESSION_DATA` stream, and hand back
    /// a live [`SessionAttachStream`] of `qsh.event/v1` events with an
    /// input/resize channel going the other way.
    ///
    /// Attach carries the session's **resume credential** (protocol.md
    /// §10, ADR-0007). The token is looked up from `resume.json` by
    /// `session_ref` and presented only to the peer it was issued to, so
    /// an attach is possible from the device that opened the session and
    /// nowhere else — a session visible in `qsh sessions` from another
    /// device still fails here, locally and before any request is sent
    /// (`docs/CLI.md` §6.3). The successor token the host returns is made
    /// durable **before** the stream is used, because it is
    /// single-generation: losing it orphans the session.
    pub fn session_attach(&self, req: SessionAttachReq) -> Result<SessionAttachStream, OpError> {
        let r = parse_session_ref(&req.session_ref)?;
        let store = ResumeStore::new(&self.paths);
        let mut conn = self.connect(&r.host)?;
        // No verified fingerprint means nothing to bind a credential to.
        // Fail closed rather than present a token to an unidentified peer.
        let Some(peer) = conn.peer_fingerprint() else {
            conn.close();
            return Err(NoToken::PeerMismatch.into_error(&req.session_ref));
        };
        let token = match store.take_for(&req.session_ref, &peer) {
            Ok(token) => token,
            Err(why) => {
                conn.close();
                return Err(why.into_error(&req.session_ref));
            }
        };
        let msg = wire::SessionAttach {
            session_id: r.session_id.clone(),
            resume_token: token.expose().to_vec(),
            // A fresh attach has delivered nothing, so it asks for the
            // whole retained ring. The reconnect path
            // ([`crate::client::reconnect`]) is the caller that has a real
            // `L` to continue from.
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: req.no_steal,
        };
        let attached = match conn.run(move |s| Box::pin(s.attach_request(msg))) {
            Ok(attached) => attached,
            Err(err) => {
                // The host refused the credential. Whether the session is
                // gone or the token is stale is deliberately not
                // distinguishable (protocol.md §10-2) and the answer is
                // the same either way: this entry is dead weight.
                if matches!(err.code, ErrorCode::AuthFailed | ErrorCode::SessionNotFound) {
                    let _ = store.forget(&req.session_ref);
                }
                conn.close();
                return Err(err);
            }
        };
        // Durable before the stream is touched (ADR-0007): the presented
        // token is already invalid on the host, so a successor that only
        // exists in memory is one crash away from an unreachable session.
        if let Some(successor) = StoredToken::from_slice(&attached.new_resume_token)
            && let Err(err) = store.put(
                &req.session_ref,
                &r.host,
                &r.session_id,
                successor,
                &peer,
                &attached.expires_at,
            )
        {
            // The presented token is already spent on the host and its
            // successor did not reach the disk, so the entry we still
            // hold is dead weight that would earn an `AUTH_FAILED` on
            // the next try. Drop it and let go of the connection rather
            // than leaving the host holding a ticket and a lease for an
            // attach that is not going to happen.
            let _ = store.forget(&req.session_ref);
            conn.close();
            return Err(err);
        }
        let replay_from = attached.replay_from;
        let writer_lease = attached.writer_lease;
        let expires_at = attached.expires_at.clone();
        // How long the host says the credential lives. The stored
        // `expires_at` is a snapshot, and a session's own TTL does not run
        // while it is attached, so an attach outliving this window has to
        // push its entry forward or the next disconnect finds no credential
        // to resume with (ADR-0007 "정리").
        let resume_ttl = crate::resume::ttl_until(&expires_at);
        // Only now, with the successor on disk, is the data stream opened.
        let attached = match conn.run(move |s| Box::pin(s.open_attach_stream(attached))) {
            Ok(attached) => attached,
            Err(err) => {
                conn.close();
                return Err(err);
            }
        };
        let session = conn
            .take_session()
            .ok_or_else(|| OpError::new(ErrorCode::Internal, "attach lost its control stream"))?;

        let (events_tx, events_rx) = tokio::sync::mpsc::channel(SESSION_ATTACH_QUEUE);
        let (commands, command_rx) = tokio::sync::mpsc::channel(SESSION_ATTACH_QUEUE);
        let session_ref = req.session_ref.clone();
        let driver = conn.runtime().spawn(drive_attach(
            session,
            attached,
            session_ref.clone(),
            command_rx,
            events_tx,
        ));
        Ok(SessionAttachStream {
            conn,
            store: ResumeStore::new(&self.paths),
            driver,
            events: events_rx,
            commands,
            session_ref,
            replay_from,
            writer_lease,
            resume_ttl,
            renew_at: resume_ttl.map(|ttl| std::time::Instant::now() + ttl / 2),
            expires_at,
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
        // The session is gone on the host, so its credential is now a
        // token that can only ever earn an `AUTH_FAILED` (ADR-0007
        // "정리").
        let _ = ResumeStore::new(&self.paths).forget(&req.session_ref);
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
        let mut connected = self.connect(host)?;
        let result = connected.run(f);
        connected.close();
        result
    }

    /// Dial `host` and negotiate, keeping the connection open for the
    /// caller. Blocking, for the same reason [`Ops::call`] is: the identity
    /// is loaded before the runtime exists, because platform key stores
    /// must not be touched from inside one.
    ///
    /// This is what the streaming ops (`session read --follow`,
    /// `session.attach`) sit on — they need many round trips on one
    /// connection, where a value op needs exactly one.
    fn connect(&self, host: &str) -> Result<Connected, OpError> {
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
        let dialed = runtime.block_on(async {
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
            match Session::negotiate(dialed.connection, &device_name).await {
                Ok(session) => Ok((endpoint, connection, session)),
                Err(err) => {
                    connection.close(0, b"done");
                    endpoint.wait_idle().await;
                    Err(map_client_error(err))
                }
            }
        });
        match dialed {
            Ok((endpoint, connection, session)) => Ok(Connected {
                runtime: Some(runtime),
                endpoint,
                connection,
                session: Some(session),
            }),
            Err(err) => {
                runtime.shutdown_timeout(CLOSE_DRAIN);
                Err(err)
            }
        }
    }
}

/// How long a torn-down connection's QUIC close frames get to drain.
const CLOSE_DRAIN: Duration = Duration::from_millis(200);

/// A live cursor on one session's replay ring — the single pull primitive
/// behind `session read --wait`, `session read --follow` and (M6) the MCP
/// long-poll. See [`Ops::session_reader`].
pub struct SessionReader {
    conn: Connected,
    /// Where this session's resume credential lives, so a `session.closed`
    /// seen while reading takes the dead entry with it (CLI.md §6.4).
    store: ResumeStore,
    session_ref: String,
    session_id: String,
    after: u64,
    ctl_after: u64,
    wait_ms: u64,
    max_bytes: u64,
    done: bool,
}

impl SessionReader {
    /// The session being read.
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }

    /// The cursor the next pull will use, as `(after, ctl_after)`.
    pub fn cursor(&self) -> (u64, u64) {
        (self.after, self.ctl_after)
    }

    /// Whether a terminal event (`session.exit`, `session.closed`) has been
    /// delivered — a follower stops here instead of polling a dead session.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// One pull. Advances the cursor by the reply's
    /// `next_after`/`next_ctl_after`, so consecutive pulls neither skip nor
    /// repeat.
    pub fn pull(&mut self) -> Result<SessionReadOutput, OpError> {
        let msg = wire::SessionRead {
            session_id: self.session_id.clone(),
            after: self.after,
            max_bytes: self.max_bytes,
            wait_ms: self.wait_ms,
            ctl_after: self.ctl_after,
        };
        let result = self.conn.run(move |s| Box::pin(s.session_read(msg)))?;
        self.after = result.next_after;
        self.ctl_after = result.next_ctl_after;
        let mut output = Vec::new();
        let mut json_events = Vec::with_capacity(result.events.len());
        for event in result.events {
            if let Some(session_read_event::Body::Output(o)) = &event.body {
                output.extend_from_slice(&o.data);
            }
            if let Some(json) = event_json(&self.session_ref, event) {
                self.done |= is_terminal(&json);
                forget_if_closed(&self.store, &self.session_ref, &json);
                json_events.push(json);
            }
        }
        Ok(SessionReadOutput {
            data: SessionReadData {
                session_ref: self.session_ref.clone(),
                events: json_events,
                next_after: self.after,
                next_ctl_after: self.ctl_after,
            },
            output,
        })
    }

    /// Close the connection this reader holds.
    pub fn close(self) {
        self.conn.close();
    }
}

/// Drop the stored resume credential once the host says the session is
/// gone (`docs/CLI.md` §6.4).
///
/// Only `session.closed` — not `session.exit`. An exited session is still
/// in the broker until the reaper takes it, and its output is still
/// attachable; a session that has been *removed* can only answer an attach
/// with the non-distinguishing `AUTH_FAILED`, and keeping the credential
/// around would turn "this session is over" into that opaque refusal.
fn forget_if_closed(store: &ResumeStore, session_ref: &str, event: &SessionEvent) {
    if matches!(event, SessionEvent::Closed { .. }) {
        let _ = store.forget(session_ref);
    }
}

/// Whether an event ends the stream: nothing follows an exit or a close.
fn is_terminal(event: &SessionEvent) -> bool {
    matches!(
        event,
        SessionEvent::Exit { .. } | SessionEvent::Closed { .. }
    )
}

/// The `session.attach` operation — the only stream op.
pub struct SessionAttachOp;
impl Operation for SessionAttachOp {
    const COMMAND: &'static str = "session.attach";
}

/// What a frontend sends into a live attach.
enum AttachCommand {
    /// Session input, split into wire chunks by the writer.
    Input(Vec<u8>),
    /// A window-size change.
    Resize {
        /// New column count.
        cols: u16,
        /// New row count.
        rows: u16,
    },
}

/// A live attach: a blocking `qsh.event/v1` event stream out, an
/// input/resize channel in. See [`Ops::session_attach`].
///
/// The connection, its runtime and the driver task are owned here, so
/// dropping this ends the attach.
pub struct SessionAttachStream {
    conn: Connected,
    /// See [`SessionReader::store`].
    store: ResumeStore,
    driver: tokio::task::JoinHandle<()>,
    events: tokio::sync::mpsc::Receiver<Result<SessionEvent, OpError>>,
    commands: tokio::sync::mpsc::Sender<AttachCommand>,
    session_ref: String,
    replay_from: u64,
    writer_lease: bool,
    /// The credential window the host reported, if it parsed.
    resume_ttl: Option<std::time::Duration>,
    /// When to push the stored entry's expiry forward; `None` disables it.
    renew_at: Option<std::time::Instant>,
    expires_at: String,
}

impl SessionAttachStream {
    /// The session being attached.
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }

    /// Cumulative output offset replay started from.
    pub fn replay_from(&self) -> u64 {
        self.replay_from
    }

    /// Whether this attach holds the writer lease.
    pub fn writer_lease(&self) -> bool {
        self.writer_lease
    }

    /// When the session's resume window ends (RFC 3339).
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    /// Block until the next event. `None` once the stream has ended — the
    /// child exited, the session closed, or the connection went away.
    ///
    /// Call from a plain thread, never from inside an async runtime: like
    /// every other `Ops` entry point this is the blocking face of the
    /// driver that owns the connection.
    pub fn next_event(&mut self) -> Option<Result<SessionEvent, OpError>> {
        let event = self.events.blocking_recv()?;
        if let Ok(event) = &event {
            forget_if_closed(&self.store, &self.session_ref, event);
        }
        self.renew_credential();
        Some(event)
    }

    /// Keep the stored credential's expiry ahead of the clock while this
    /// attach is alive. Runs at most once per half-window (a disk write
    /// every twelve hours at the default TTL), and a failure is not fatal:
    /// the host is the authority, and the worst case is the stale stamp
    /// this is trying to avoid.
    fn renew_credential(&mut self) {
        let (Some(ttl), Some(due)) = (self.resume_ttl, self.renew_at) else {
            return;
        };
        if std::time::Instant::now() < due {
            return;
        }
        if let Err(err) = self.store.renew(&self.session_ref, ttl) {
            tracing::debug!(session_ref = %self.session_ref, %err, "resume entry renewal failed");
        }
        self.renew_at = Some(std::time::Instant::now() + ttl / 2);
    }

    /// Queue session input; the driver writes it in order. Blocks only
    /// while the driver's bounded queue is full — that backpressure is
    /// what keeps a fast producer from growing the queue without limit.
    pub fn write(&self, data: Vec<u8>) -> Result<(), OpError> {
        self.commands
            .blocking_send(AttachCommand::Input(data))
            .map_err(|_| attach_gone())
    }

    /// Queue a window-size change. Same backpressure as [`write`](Self::write).
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), OpError> {
        self.commands
            .blocking_send(AttachCommand::Resize { cols, rows })
            .map_err(|_| attach_gone())
    }

    /// Stop the attach and close the connection.
    pub fn close(self) {
        self.driver.abort();
        self.conn.close();
    }
}

fn attach_gone() -> OpError {
    OpError::new(ErrorCode::ConnectionFailed, "the attach stream has ended")
}

/// A spawned task aborted when its handle is dropped, so tearing the
/// driver down takes its helpers with it.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Drive one attach: data-stream frames and control-stream `SessionEvent`s
/// out as `qsh.event/v1` events, queued input and resizes in. Ends when the
/// host finishes the stream, the peer goes away, or the frontend drops its
/// command sender.
///
/// Three tasks, never one `select!` over all three, for two reasons that
/// both bit the first cut:
///
/// - a `select!` arm that awaits `AttachWriter::send_input` stops polling
///   the read arm while it is parked on QUIC flow control, and the host
///   parks its own input reader when *its* frame queue fills — a large
///   paste on a chatty session deadlocks both ends until the idle timeout;
/// - `Session::next_event` answers a `Ping` with a `write_all`, which is
///   **not** cancel-safe: losing a `select!` race mid-write leaves half a
///   control frame on the wire and desynchronises the peer's decoder.
///
/// Giving the send halves their own tasks means nothing that writes is
/// ever cancelled, and the reads (which *are* cancel-safe) are the only
/// things racing.
async fn drive_attach(
    session: Session,
    attached: crate::client::Attached,
    session_ref: String,
    commands: tokio::sync::mpsc::Receiver<AttachCommand>,
    events: tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
) {
    let (writer, mut reader) = attached.split();
    let _input = AbortOnDrop(tokio::spawn(pump_attach_input(writer, commands)));
    let mut control = AbortOnDrop(tokio::spawn(pump_attach_control(
        session,
        session_ref.clone(),
        events.clone(),
    )));

    loop {
        match reader.next().await {
            Ok(Some(event)) => {
                if let Some(json) = attach_event_json(&session_ref, event)
                    && events.send(Ok(json)).await.is_err()
                {
                    break;
                }
            }
            Ok(None) => {
                // The data stream ended. `session.closed` has no
                // `SessionFrame` form, so a close that the host queued just
                // before the FIN is still in flight on the control stream —
                // give it a bounded moment to arrive rather than racing it
                // to the exit (CLI.md §6.4 makes it the last event).
                let _ = tokio::time::timeout(ATTACH_CONTROL_DRAIN, &mut control.0).await;
                break;
            }
            Err(err) => {
                let _ = events.send(Err(map_client_error(err))).await;
                break;
            }
        }
    }
}

/// Sole owner of the attach's send half: queued input and resizes, in
/// order. A write that fails does not end the attach — a stolen writer
/// lease demotes this peer to read-only (protocol.md §10) and it is still
/// owed its output.
async fn pump_attach_input(
    mut writer: crate::client::AttachWriter,
    mut commands: tokio::sync::mpsc::Receiver<AttachCommand>,
) {
    while let Some(command) = commands.recv().await {
        let sent = match command {
            AttachCommand::Input(data) => writer.send_input(&data).await.map(|_| ()),
            AttachCommand::Resize { cols, rows } => writer.resize(cols, rows).await,
        };
        if sent.is_err() {
            return;
        }
    }
    // The frontend dropped its handle: finish our send half so the host
    // drains what is left and finishes the stream.
    writer.finish();
}

/// Sole owner of the control stream for the lifetime of an attach: the
/// asynchronous `SessionEvent`s (`writer_changed`, `closed`) an attached
/// peer is owed, plus the ping answers `Session::next_event` sends.
async fn pump_attach_control(
    mut session: Session,
    session_ref: String,
    events: tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
) {
    loop {
        match session.next_event().await {
            // `Exited` also arrives as a data frame, which is the
            // authoritative copy; emitting both would duplicate a terminal
            // event in the JSONL stream.
            Ok(Some(event)) => {
                if let Some(json) = control_event_json(&session_ref, event)
                    && events.send(Ok(json)).await.is_err()
                {
                    return;
                }
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// One attach data frame as a `qsh.event/v1` event. `InputAck` is flow
/// control, not an event, and has no `qsh.event/v1` type.
fn attach_event_json(session_ref: &str, event: crate::client::AttachEvent) -> Option<SessionEvent> {
    let schema = EVENT_SCHEMA.to_string();
    let session_ref = session_ref.to_string();
    Some(match event {
        crate::client::AttachEvent::Output { sequence, data } => SessionEvent::Output {
            schema,
            session_ref,
            sequence,
            data_b64: BASE64.encode(&data),
        },
        crate::client::AttachEvent::Gap {
            requested_after,
            available_from,
        } => SessionEvent::Gap {
            schema,
            session_ref,
            requested_after,
            available_from,
        },
        crate::client::AttachEvent::Exit {
            final_seq,
            exit_code,
            signal,
        } => SessionEvent::Exit {
            schema,
            session_ref,
            sequence: final_seq,
            // A signal-terminated child has no exit code (CLI.md §6.4).
            exit_code: if signal.is_some() {
                None
            } else {
                Some(exit_code)
            },
            signal,
        },
        crate::client::AttachEvent::InputAck { .. } => return None,
    })
}

/// One asynchronous control-stream `SessionEvent` as a `qsh.event/v1`
/// event; the exit is dropped because the data stream already carries it.
fn control_event_json(session_ref: &str, event: wire::SessionEvent) -> Option<SessionEvent> {
    let schema = EVENT_SCHEMA.to_string();
    let session_ref = session_ref.to_string();
    Some(match event.body? {
        wire::session_event::Body::WriterChanged(w) => SessionEvent::WriterChanged {
            schema,
            session_ref,
            sequence: w.seq,
            writer: w.new_writer,
        },
        wire::session_event::Body::Closed(c) => SessionEvent::Closed {
            schema,
            session_ref,
            sequence: c.seq,
            reason: c.reason,
        },
        wire::session_event::Body::Exited(_) => return None,
    })
}

/// A dialed, negotiated peer connection held open across calls, with its
/// own runtime — the backbone of both the value ops (one call, then
/// [`close`](Connected::close)) and the streaming ops (many calls).
struct Connected {
    /// `None` only between [`Connected::close`] and the drop.
    runtime: Option<tokio::runtime::Runtime>,
    endpoint: qsh_transport::Endpoint,
    connection: qsh_transport::Connection,
    /// `None` only after the session was consumed by the teardown.
    session: Option<Session>,
}

impl Connected {
    /// Run one request closure on the live session.
    fn run<T, F>(&mut self, f: F) -> Result<T, OpError>
    where
        F: for<'a> FnOnce(
            &'a mut Session,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, ClientError>> + Send + 'a>,
        >,
    {
        let (Some(runtime), Some(session)) = (self.runtime.as_ref(), self.session.as_mut()) else {
            return Err(OpError::new(
                ErrorCode::Internal,
                "connection already closed",
            ));
        };
        runtime.block_on(f(session)).map_err(map_client_error)
    }

    /// The runtime this connection lives on, for callers that drive their
    /// own tasks on it (the attach driver).
    fn runtime(&self) -> &tokio::runtime::Runtime {
        self.runtime
            .as_ref()
            .expect("runtime is only taken by close()")
    }

    /// Take the negotiated session out, leaving the connection and runtime
    /// in place (the attach driver owns the session for its lifetime).
    fn take_session(&mut self) -> Option<Session> {
        self.session.take()
    }

    /// `sha256:…` fingerprint of the peer this connection verified — the
    /// identity a resume credential is bound to (protocol.md §10-2). Not
    /// an authorization input: the host authorizes on the mTLS principal.
    fn peer_fingerprint(&self) -> Option<String> {
        self.connection.peer_fingerprint().map(|fp| fp.to_string())
    }

    /// Close the control stream and the connection, then let the QUIC close
    /// frames drain.
    fn close(mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let session = self.session.take();
        let connection = self.connection.clone();
        let endpoint = self.endpoint.clone();
        runtime.block_on(async move {
            if let Some(session) = session {
                session.close();
            }
            connection.close(0, b"done");
            drop(connection);
            endpoint.wait_idle().await;
        });
        runtime.shutdown_timeout(CLOSE_DRAIN);
    }
}

impl Drop for Connected {
    fn drop(&mut self) {
        // `close()` already took the runtime on the normal path; this is the
        // panic / early-return path.
        if let Some(runtime) = self.runtime.take() {
            self.session.take();
            self.connection.close(0, b"done");
            runtime.shutdown_timeout(CLOSE_DRAIN);
        }
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
