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

use crate::client::pathwatch::{PathWatch, PathWatchConfig, watch_path};
use crate::client::reconnect::{
    OutputCursor, PathBinder, PendingInput, REDIAL_DEADLINE, Recovered, recover,
};
use crate::client::{AttachEvent, ClientError, ControlIn, Session};
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

/// How long the driver waits for the host to acknowledge the input it
/// wrote before a detach, once the send half is finished. Long enough for
/// a round trip on a bad link, short enough that `~d` still feels instant.
const DETACH_FLUSH: Duration = Duration::from_millis(750);

/// How long [`AttachHandle::detach`] waits for the driver's acknowledgement
/// before closing anyway. Strictly longer than [`DETACH_FLUSH`], so the
/// normal path is bounded by the driver, not by this fallback.
const DETACH_FLUSH_GRACE: Duration = Duration::from_millis(1_000);

/// How long a migration probe waits for *any* answer from the host before
/// it is called a failure.
///
/// Deliberately small: it is spent out of the same
/// [`REDIAL_DEADLINE`] budget the re-dial needs, and migration is only ever
/// a latency optimization (`docs/design/protocol.md` §2). A probe that has
/// to wait longer than this has already cost more than it can save.
const MIGRATION_PROBE: Duration = Duration::from_millis(300);

/// How long the supervisor gives a leg's pumps to stop of their own accord
/// before aborting them. They stop between commands, so this is only ever
/// spent on a pump parked mid-write on a dead connection — which has
/// already recorded its bytes as un-acked and loses nothing to an abort.
const PUMP_STOP_GRACE: Duration = Duration::from_millis(250);

/// How a live attach survives a dead path (`PLAN.md` M2 Step 7 (a)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryConfig {
    /// How the path-death detector behaves.
    pub watch: PathWatchConfig,
    /// Whether to try `Endpoint::rebind()` active migration before
    /// re-dialing.
    ///
    /// On by default because it is much cheaper than a resume when it
    /// works. **Nothing depends on it**: turning it off must change how
    /// long a recovery takes and nothing else, which is what the recovery
    /// gate asserts by running with it off.
    pub migration: bool,
    /// How many times a detected death is recovered from before the attach
    /// gives up and reports the error. Each attempt is separately bounded
    /// by [`REDIAL_DEADLINE`] and separately recorded in the recovery
    /// telemetry, so a campaign counts attempts, not outcomes.
    pub attempts: u32,
    /// Whether to recover at all. Off makes a dead path end the attach the
    /// way it did before recovery existed.
    pub enabled: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            watch: PathWatchConfig::default(),
            migration: true,
            attempts: 3,
            enabled: true,
        }
    }
}

impl RecoveryConfig {
    /// Backoff before attempt `n` (zero-based). The first retry is
    /// immediate — a path that just died is most often a path that came
    /// straight back on another interface.
    fn backoff(attempt: u32) -> Duration {
        match attempt {
            0 => Duration::ZERO,
            1 => Duration::from_millis(200),
            _ => Duration::from_millis(800),
        }
    }
}

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
        // Resolved once and kept: resolution loads the device key, which a
        // platform key store will not hand over from inside a runtime, and
        // a recovery re-dials from inside one.
        let target = self.resolve_peer(&r.host)?;
        let mut conn = self.connect_target(&target)?;
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
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ctx = Arc::new(AttachContext {
            target,
            host: r.host.clone(),
            session_id: r.session_id.clone(),
            session_ref: session_ref.clone(),
            paths: self.paths.clone(),
            no_steal: req.no_steal,
            link: conn.link.clone(),
            recovery: self.recovery,
            finished: finished.clone(),
        });
        let driver = conn
            .runtime()
            .spawn(drive_attach(ctx, session, attached, command_rx, events_tx));
        Ok(SessionAttachStream {
            conn,
            store: ResumeStore::new(&self.paths),
            driver,
            events: events_rx,
            commands,
            session_ref,
            replay_from,
            writer_lease,
            renewal: resume_ttl.map(|ttl| RenewalSchedule::new(ttl, std::time::Instant::now())),
            expires_at,
            finished,
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
        let target = self.resolve_peer(host)?;
        self.connect_target(&target)
    }

    /// [`connect`](Self::connect) for a peer already resolved.
    ///
    /// An attach resolves its peer once and keeps the result, because the
    /// resolution loads the device key — which must not happen inside a
    /// runtime — and a recovery re-dials from inside one.
    fn connect_target(&self, target: &PeerTarget) -> Result<Connected, OpError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?;
        match runtime.block_on(dial_peer(target)) {
            Ok((endpoint, connection, session)) => Ok(Connected {
                runtime: Some(runtime),
                link: Link::new(endpoint, connection),
                session: Some(session),
            }),
            Err(err) => {
                runtime.shutdown_timeout(CLOSE_DRAIN);
                Err(err)
            }
        }
    }
}

/// Dial a resolved peer and exchange `Hello`. The async half of
/// [`Ops::connect`], split out because a recovery re-dials from inside a
/// runtime that already exists.
async fn dial_peer(
    target: &PeerTarget,
) -> Result<(qsh_transport::Endpoint, qsh_transport::Connection, Session), OpError> {
    let device_name = target.identity.identity.device_id.clone();
    let dialer = Dialer::new(
        target.identity.local.clone(),
        target.trust.clone() as Arc<dyn qsh_transport::TrustEvaluator>,
    );
    let address = target.address.clone();
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
        .dial(addr, &target.server_name)
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
    /// Finish the send half and report back once the host has it. Travels
    /// the same ordered queue as the input so a detach cannot overtake the
    /// bytes typed just before it (`docs/CLI.md` §7).
    Detach(std::sync::mpsc::SyncSender<()>),
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
    /// When to push the stored entry's expiry forward; `None` when the
    /// host's window did not parse and there is nothing to schedule from.
    renewal: Option<RenewalSchedule>,
    expires_at: String,
    /// Shared with the driver: set once this attach is deliberately over,
    /// so a connection the frontend closed is never recovered from.
    finished: Arc<std::sync::atomic::AtomicBool>,
}

/// When a live attach owes its stored resume entry a fresh `expires_at`.
///
/// Split out as a pure schedule with an injected `now` for one reason: the
/// bug it replaces was not in the arithmetic but in what drove it. Renewal
/// used to happen only as a side effect of an event arriving, so an attach
/// that produced no output — the all-day-idle shell the resume feature
/// exists to protect — never renewed, and the client-side "drop an entry
/// whose `expires_at` has passed" rule then deleted a credential the host
/// would still have honoured. A schedule that can be asked "how long until
/// the next one is due?" is what lets the waiting loop wake for the
/// renewal instead of for an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RenewalSchedule {
    ttl: std::time::Duration,
    due: std::time::Instant,
}

impl RenewalSchedule {
    /// Renew every half-window: at the default 24 h TTL that is one small
    /// disk write every twelve hours, and it leaves a full half-window of
    /// slack for a renewal that fails.
    fn new(ttl: std::time::Duration, now: std::time::Instant) -> Self {
        Self {
            ttl,
            due: now + Self::period(ttl),
        }
    }

    fn period(ttl: std::time::Duration) -> std::time::Duration {
        // Never zero: a degenerate TTL must not turn the waiting loop into
        // a spin.
        (ttl / 2).max(std::time::Duration::from_millis(1))
    }

    /// The window the host granted, which is also what a renewal writes.
    fn ttl(&self) -> std::time::Duration {
        self.ttl
    }

    /// How long until the next renewal is due — what the event wait is
    /// bounded by, so a silent attach still wakes up in time.
    fn due_in(&self, now: std::time::Instant) -> std::time::Duration {
        self.due.saturating_duration_since(now)
    }

    /// Claim a due renewal and arm the next one. `false` if it is not due
    /// yet, so the caller does not write the file on every wakeup.
    fn take_if_due(&mut self, now: std::time::Instant) -> bool {
        if now < self.due {
            return false;
        }
        self.due = now + Self::period(self.ttl);
        true
    }
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
        loop {
            self.renew_credential();
            // The wait is bounded by the next renewal, never by the next
            // event: a shell nobody is typing into can go a whole day
            // without producing a byte, and that is precisely the session
            // whose credential must not be allowed to go stale.
            let event = match self.renewal.map(|r| r.due_in(std::time::Instant::now())) {
                Some(wait) => {
                    let runtime = self.conn.runtime();
                    let events = &mut self.events;
                    // The timer is created *inside* `block_on`: `timeout`
                    // arms its sleep eagerly, and there is no reactor on
                    // this thread until the runtime is entered.
                    match runtime
                        .block_on(async { tokio::time::timeout(wait, events.recv()).await })
                    {
                        Ok(Some(event)) => event,
                        Ok(None) => return None,
                        // The renewal came due first. Round the loop, write
                        // it, and go back to waiting.
                        Err(_) => continue,
                    }
                }
                None => self.events.blocking_recv()?,
            };
            if let Ok(event) = &event {
                forget_if_closed(&self.store, &self.session_ref, event);
            }
            return Some(event);
        }
    }

    /// Keep the stored credential's expiry ahead of the clock while this
    /// attach is alive. Runs at most once per half-window (a disk write
    /// every twelve hours at the default TTL), and a failure is not fatal:
    /// the host is the authority, and the worst case is the stale stamp
    /// this is trying to avoid.
    fn renew_credential(&mut self) {
        let Some(schedule) = self.renewal.as_mut() else {
            return;
        };
        if !schedule.take_if_due(std::time::Instant::now()) {
            return;
        }
        let ttl = schedule.ttl();
        if let Err(err) = self.store.renew(&self.session_ref, ttl) {
            tracing::debug!(session_ref = %self.session_ref, %err, "resume entry renewal failed");
        }
    }

    /// Queue session input; the driver writes it in order. Blocks only
    /// while the driver's bounded queue is full — that backpressure is
    /// what keeps a fast producer from growing the queue without limit.
    pub fn write(&self, data: Vec<u8>) -> Result<(), OpError> {
        self.handle().write(data)
    }

    /// Queue a window-size change. Same backpressure as [`write`](Self::write).
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), OpError> {
        self.handle().resize(cols, rows)
    }

    /// A cloneable handle on the input side of this attach.
    ///
    /// [`next_event`](Self::next_event) blocks the thread that owns the
    /// stream, so anything that has to reach the session while output is
    /// flowing — a terminal's input pump, a `SIGWINCH` watcher, a detach
    /// key — runs on another thread and needs its own handle. The stream
    /// stays the sole owner of the event side.
    pub fn handle(&self) -> AttachHandle {
        AttachHandle {
            commands: self.commands.clone(),
            link: self.conn.link.clone(),
            finished: self.finished.clone(),
        }
    }

    /// Stop the attach and close the connection.
    pub fn close(self) {
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        self.driver.abort();
        self.conn.close();
    }
}

/// The input side of a live attach: cloneable, `Send`, and usable from any
/// thread — session input, window-size changes, and a detach that leaves
/// the session running. See [`SessionAttachStream::handle`].
#[derive(Clone)]
pub struct AttachHandle {
    commands: tokio::sync::mpsc::Sender<AttachCommand>,
    link: Link,
    finished: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for AttachHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachHandle").finish_non_exhaustive()
    }
}

impl AttachHandle {
    /// Queue session input; the driver writes it in order. Blocks only
    /// while the driver's bounded queue is full.
    ///
    /// Call from a plain thread, never from inside an async runtime — the
    /// same rule every blocking `Ops` entry point follows.
    pub fn write(&self, data: Vec<u8>) -> Result<(), OpError> {
        self.commands
            .blocking_send(AttachCommand::Input(data))
            .map_err(|_| attach_gone())
    }

    /// Queue session input without ever blocking. `Ok(false)` means the
    /// driver's queue was full and the bytes were **not** taken — the
    /// caller has to say so rather than pretend they were sent.
    ///
    /// For callers that must stay responsive under backpressure: the host
    /// parks its own input reader when its frame queue fills, so a
    /// blocking [`write`](Self::write) can park indefinitely.
    pub fn try_write(&self, data: Vec<u8>) -> Result<bool, OpError> {
        match self.commands.try_send(AttachCommand::Input(data)) {
            Ok(()) => Ok(true),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(attach_gone()),
        }
    }

    /// Queue a window-size change. Same backpressure as [`write`](Self::write).
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), OpError> {
        self.commands
            .blocking_send(AttachCommand::Resize { cols, rows })
            .map_err(|_| attach_gone())
    }

    /// Queue a window-size change without ever blocking; see
    /// [`try_write`](Self::try_write). A dropped resize is self-healing —
    /// the next `SIGWINCH` sends the current size again.
    pub fn try_resize(&self, cols: u16, rows: u16) -> Result<bool, OpError> {
        match self.commands.try_send(AttachCommand::Resize { cols, rows }) {
            Ok(()) => Ok(true),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(attach_gone()),
        }
    }

    /// Detach: end this client's attach **without touching the session**
    /// (`docs/CLI.md` §7 — a session outlives its client by design).
    ///
    /// Closing the QUIC connection is what makes a detach prompt and
    /// complete: the host purges the connection, releases the writer lease
    /// it held and keeps the session running, and the
    /// [`next_event`](SessionAttachStream::next_event) blocking the owning
    /// thread returns. Idempotent, and callable from any thread — closing
    /// a connection needs no runtime.
    pub fn detach(&self) {
        // Ordering first: hand the driver a detach marker so everything
        // already queued is written and the send half finished before the
        // connection goes away — a QUIC close discards unsent stream data,
        // which would silently eat a command typed just before `~d`.
        //
        // Bounded on both sides. A full queue (the host stopped reading)
        // means the bytes were never going to land anyway, and a driver
        // parked on flow control never answers; neither may keep the user
        // attached, so the close happens regardless.
        //
        // Marked deliberate *first*: closing the connection is
        // indistinguishable, from the driver's side, from the path dying,
        // and a detach that raced the flag would be answered with a
        // re-dial and a resume of the session the user just left.
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        let (ack, flushed) = std::sync::mpsc::sync_channel(1);
        if self.commands.try_send(AttachCommand::Detach(ack)).is_ok() {
            let _ = flushed.recv_timeout(DETACH_FLUSH_GRACE);
        }
        self.link.connection().close(0, b"detach");
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

/// Everything a recovery needs to rebuild a dead attach without going back
/// through the blocking `Ops` layer.
///
/// The peer is resolved **once**, when the attach is created: resolution
/// loads the device key, which platform key stores refuse to hand over from
/// inside a runtime, and a recovery re-dials from inside one.
struct AttachContext {
    target: PeerTarget,
    host: String,
    session_id: String,
    session_ref: String,
    paths: crate::config::Paths,
    no_steal: bool,
    /// The connection the attach is riding; a resume swaps it in place.
    link: Link,
    recovery: RecoveryConfig,
    /// Set once the frontend deliberately ended the attach, so a connection
    /// **we** closed is never mistaken for a path that died and recovered
    /// from.
    finished: Arc<std::sync::atomic::AtomicBool>,
}

impl AttachContext {
    fn finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// How one leg of an attach ended.
enum LegEnd {
    /// The host finished the data stream: the session is over.
    Ended,
    /// The frontend is gone; there is nobody to deliver to.
    Gone,
    /// The path was declared dead by the watchdog.
    PathDead,
    /// The data stream itself failed.
    Broken(ClientError),
}

/// A leg's helper tasks, stoppable without losing queued input.
///
/// Stopping is a signal and a bounded wait, not an abort: a pump aborted
/// between taking a command off the queue and recording it would silently
/// eat a keystroke the user believes they typed. The abort is the fallback
/// for a pump parked mid-write on a connection that is already dead — by
/// then its bytes are recorded as un-acked and the resume retransmits them.
struct LegPumps {
    input: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    )>,
    control: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    )>,
}

impl LegPumps {
    async fn stop(&mut self) {
        for slot in [&mut self.input, &mut self.control] {
            let Some((stop, mut handle)) = slot.take() else {
                continue;
            };
            let _ = stop.send(());
            if tokio::time::timeout(PUMP_STOP_GRACE, &mut handle)
                .await
                .is_err()
            {
                handle.abort();
            }
        }
    }
}

impl Drop for LegPumps {
    fn drop(&mut self) {
        for slot in [&mut self.input, &mut self.control] {
            if let Some((_, handle)) = slot.take() {
                handle.abort();
            }
        }
    }
}

/// Drive one attach for its whole life, across as many connections as it
/// takes (`docs/design/protocol.md` §2, §10; `PLAN.md` M2 Step 7 (a)).
///
/// Each *leg* is one connection's worth of attach: a data stream, a control
/// stream, and a watchdog asking whether the path still carries packets. A
/// leg ends when the session does, when the frontend goes away, or when the
/// watchdog says the path is dead — and only the last of those is
/// recoverable. Recovery either revives the leg (the connection migrated:
/// nothing to rebuild, nothing to replay) or builds a new one and stitches
/// it to the old with [`OutputCursor`] and [`PendingInput`], so the byte
/// stream the frontend sees has no seam in it.
///
/// Three tasks per leg, never one `select!` over all of them, for two
/// reasons that both bit the first cut:
///
/// - a `select!` arm that awaits `AttachWriter::send_input` stops polling
///   the read arm while it is parked on QUIC flow control, and the host
///   parks its own input reader when *its* frame queue fills — a large
///   paste on a chatty session deadlocks both ends until the idle timeout;
/// - `Session::next_event` answers a `Ping` with a `write_all`, which is
///   **not** cancel-safe: losing a `select!` race mid-write leaves half a
///   control frame on the wire and desynchronises the peer's decoder. The
///   control pump uses [`Session::next_control`], which only reads, and
///   does its writing in the branch body where nothing can cancel it.
async fn drive_attach(
    ctx: Arc<AttachContext>,
    session: Session,
    attached: crate::client::Attached,
    commands: tokio::sync::mpsc::Receiver<AttachCommand>,
    events: tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
) {
    // Shared across legs: the command queue survives a recovery (input
    // typed while the path was dying is still input), and so do the two
    // cursors that make the stitch invisible.
    let commands = Arc::new(tokio::sync::Mutex::new(commands));
    let pending = Arc::new(std::sync::Mutex::new(PendingInput::new(
        attached.input_from,
    )));
    let cursor = Arc::new(std::sync::Mutex::new(OutputCursor::new(0)));

    let mut session = session;
    let mut attached = attached;

    'leg: loop {
        let watch = PathWatch::new(ctx.recovery.watch);
        let probes = Arc::new(tokio::sync::Notify::new());
        let (writer, mut reader) = attached.split();

        let (input_stop, input_stop_rx) = tokio::sync::oneshot::channel();
        let (ctl_stop, ctl_stop_rx) = tokio::sync::oneshot::channel();
        let mut pumps = LegPumps {
            input: Some((
                input_stop,
                tokio::spawn(pump_attach_input(
                    writer,
                    commands.clone(),
                    pending.clone(),
                    watch.clone(),
                    ctx.finished.clone(),
                    input_stop_rx,
                )),
            )),
            control: Some((
                ctl_stop,
                tokio::spawn(pump_attach_control(
                    session,
                    ctx.session_ref.clone(),
                    events.clone(),
                    watch.clone(),
                    probes.clone(),
                    ctl_stop_rx,
                )),
            )),
        };
        let mut watchdog = AbortOnDrop(tokio::spawn(watch_path(
            ctx.link.connection(),
            watch.clone(),
            probes.clone(),
        )));

        loop {
            let end = read_leg(&mut reader, &cursor, &pending, &watch, &ctx, &events).await;
            let recoverable = match end {
                LegEnd::Ended => {
                    // The data stream ended. `session.closed` has no
                    // `SessionFrame` form, so a close the host queued just
                    // before the FIN is still in flight on the control
                    // stream — give it a bounded moment to arrive rather
                    // than racing it to the exit (CLI.md §6.4 makes it the
                    // last event).
                    if let Some((_, handle)) = pumps.control.as_mut() {
                        let _ = tokio::time::timeout(ATTACH_CONTROL_DRAIN, handle).await;
                    }
                    return;
                }
                LegEnd::Gone => return,
                LegEnd::PathDead => None,
                LegEnd::Broken(err) => Some(err),
            };
            // A connection the frontend closed on purpose (a detach) is not
            // a path that died, and recovering from it would resurrect an
            // attach the user just ended.
            if ctx.finished() || !ctx.recovery.enabled {
                if let Some(err) = recoverable {
                    let _ = events.send(Err(map_client_error(err))).await;
                }
                return;
            }
            drop(watchdog);

            match recover_attach(&ctx, &watch, &probes, &pending, &cursor, &mut pumps).await {
                Recovery::SameLeg => {
                    // Migrated: the connection, both streams and every
                    // cursor are exactly as they were. Re-arm the watchdog
                    // and keep reading the same stream.
                    watch.revive();
                    watchdog = AbortOnDrop(tokio::spawn(watch_path(
                        ctx.link.connection(),
                        watch.clone(),
                        probes.clone(),
                    )));
                    continue;
                }
                Recovery::NewLeg(new_session, new_attached) => {
                    session = new_session;
                    attached = new_attached;
                    continue 'leg;
                }
                Recovery::Failed(err) => {
                    let _ = events.send(Err(err)).await;
                    return;
                }
            }
        }
    }
}

/// Read one leg's data stream until it ends, breaks, or the path dies.
async fn read_leg(
    reader: &mut crate::client::AttachReader,
    cursor: &Arc<std::sync::Mutex<OutputCursor>>,
    pending: &Arc<std::sync::Mutex<PendingInput>>,
    watch: &PathWatch,
    ctx: &AttachContext,
    events: &tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
) -> LegEnd {
    loop {
        let next = tokio::select! {
            biased;
            // Checked first: once the path is dead the frames still
            // arriving are from a connection that cannot answer, and every
            // millisecond spent on them comes out of the recovery budget.
            () = watch.dead() => return LegEnd::PathDead,
            // Cancel-safe: `FramedRecv` keeps its partial frame in the
            // decoder, so losing this race loses nothing.
            next = reader.next() => next,
        };
        let event = match next {
            Ok(Some(event)) => event,
            Ok(None) => return LegEnd::Ended,
            Err(err) => return LegEnd::Broken(err),
        };
        // Anything at all from the host proves the path carries packets.
        watch.inbound();
        if let AttachEvent::InputAck { acked_input_seq } = &event {
            lock(pending).ack(*acked_input_seq);
        }
        // Defence in depth against a doubled terminal (protocol.md §10-3):
        // the host is asked to replay from exactly where we stopped, but a
        // frame still in flight on the connection that just died, or a host
        // replaying from a conservative earlier offset, must not redraw
        // what is already on screen.
        let Some(event) = lock(cursor).accept(event) else {
            continue;
        };
        if let Some(json) = attach_event_json(&ctx.session_ref, event) {
            // A frontend that stopped draining looks exactly like a path
            // that stopped answering; say which it is rather than let the
            // watchdog guess.
            let _stalled = watch.stalled();
            if events.send(Ok(json)).await.is_err() {
                return LegEnd::Gone;
            }
        }
    }
}

/// What one recovery produced.
#[allow(clippy::large_enum_variant, reason = "short-lived, moved once")]
enum Recovery {
    /// The connection survived; carry on with the leg that is already
    /// running.
    SameLeg,
    /// A new connection and a resumed attach.
    NewLeg(Session, crate::client::Attached),
    /// Nothing worked inside the budget.
    Failed(OpError),
}

/// Recover one detected path death: migrate if that is enough, otherwise
/// re-dial and resume, retrying up to [`RecoveryConfig::attempts`] times.
///
/// Every attempt is bounded by [`REDIAL_DEADLINE`] and recorded on
/// `qsh::recovery` by [`recover`] itself, so a failed attempt is a campaign
/// datapoint rather than a silence.
async fn recover_attach(
    ctx: &Arc<AttachContext>,
    watch: &PathWatch,
    probes: &Arc<tokio::sync::Notify>,
    pending: &Arc<std::sync::Mutex<PendingInput>>,
    cursor: &Arc<std::sync::Mutex<OutputCursor>>,
    pumps: &mut LegPumps,
) -> Recovery {
    let mut last: Option<OpError> = None;
    for attempt in 0..ctx.recovery.attempts.max(1) {
        let backoff = RecoveryConfig::backoff(attempt);
        if !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }
        // Only the first attempt still has a live leg behind it, so only
        // the first can migrate: after a re-dial has been attempted the
        // old connection and its control stream are gone.
        let live_leg = attempt == 0;
        let binder = ctx.link.endpoint();
        let migration = live_leg && ctx.recovery.migration;
        let last_output_seq = lock(cursor).last_seq();

        let outcome = recover(
            &ctx.session_ref,
            migration.then_some(&binder as &dyn PathBinder),
            || {
                let watch = watch.clone();
                let probes = probes.clone();
                async move { live_leg && probe_alive(&watch, &probes).await }
            },
            || async {
                // Past the point of no return for this leg: stop the pumps
                // (which is what releases the command queue and the
                // `Session`) before building a replacement.
                pumps.stop().await;
                reattach(ctx, pending, last_output_seq).await
            },
        )
        .await;

        match outcome.outcome {
            Ok(Recovered::Migrated) => return Recovery::SameLeg,
            Ok(Recovered::Resumed(leg)) => return Recovery::NewLeg(leg.0, leg.1),
            Err(err) => last = Some(map_resume_error(err)),
        }
    }
    Recovery::Failed(last.unwrap_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            "the session's path died and could not be recovered",
        )
    }))
}

/// Ask the host, on the connection we already have, whether it is still
/// there — and take any answer at all as a yes.
///
/// The `Ping` goes out through the control pump, which owns the stream;
/// the answer is whatever the watchdog next sees as inbound traffic, which
/// may be the `Pong`, a session event, or a frame of output.
async fn probe_alive(watch: &PathWatch, probes: &Arc<tokio::sync::Notify>) -> bool {
    probes.notify_one();
    tokio::time::timeout(MIGRATION_PROBE, watch.next_inbound())
        .await
        .is_ok()
}

/// Rebuild a dead attach on a fresh connection: dial, redeem the resume
/// credential, persist its successor, open the data stream, and retransmit
/// the input the host never acknowledged (`docs/design/protocol.md` §10).
async fn reattach(
    ctx: &Arc<AttachContext>,
    pending: &Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> Result<(Session, crate::client::Attached), crate::client::reconnect::ResumeError> {
    let (endpoint, connection, mut session) = dial_peer(&ctx.target).await?;
    let store = ResumeStore::new(&ctx.paths);
    let Some(peer) = connection.peer_fingerprint().map(|fp| fp.to_string()) else {
        connection.close(0, b"unverified");
        endpoint.wait_idle().await;
        return Err(NoToken::PeerMismatch.into_error(&ctx.session_ref).into());
    };
    let token = match store.take_for(&ctx.session_ref, &peer) {
        Ok(token) => token,
        Err(why) => {
            connection.close(0, b"no credential");
            endpoint.wait_idle().await;
            return Err(why.into_error(&ctx.session_ref).into());
        }
    };
    let attached = session
        .attach_request(wire::SessionAttach {
            session_id: ctx.session_id.clone(),
            resume_token: token.expose().to_vec(),
            // Exactly where the frontend's terminal stopped, so the host
            // replays from there and nothing is redrawn or lost.
            last_output_seq,
            mode: wire::AttachMode::Rw as i32,
            no_steal: ctx.no_steal,
        })
        .await
        .inspect_err(|err| {
            // Same reasoning as a first attach: whether the session is gone
            // or the credential is stale is deliberately indistinguishable,
            // and the answer is the same either way.
            if let ClientError::Remote { code, .. } = err
                && matches!(code, ErrorCode::AuthFailed | ErrorCode::SessionNotFound)
            {
                let _ = store.forget(&ctx.session_ref);
            }
        })?;
    // Durable before the stream is touched (ADR-0007).
    if let Some(successor) = StoredToken::from_slice(&attached.new_resume_token)
        && let Err(err) = store.put(
            &ctx.session_ref,
            &ctx.host,
            &ctx.session_id,
            successor,
            &peer,
            &attached.expires_at,
        )
    {
        let _ = store.forget(&ctx.session_ref);
        connection.close(0, b"credential not durable");
        endpoint.wait_idle().await;
        return Err(err.into());
    }
    let mut attached = session.open_attach_stream(attached).await?;
    // The host's axis for this attach starts at what it actually applied on
    // the stream we lost, so the tail it never saw is retransmitted — and
    // nothing it *did* see is sent twice (protocol.md §10-5).
    let replay = lock(pending).rebase(attached.input_from)?.to_vec();
    if !replay.is_empty() {
        attached.send_input(&replay).await?;
    }
    // Only now, with the new leg working, is the old connection let go.
    let (old_endpoint, old_connection) = ctx.link.replace(endpoint, connection);
    old_connection.close(0, b"superseded");
    drop(old_endpoint);
    Ok((session, attached))
}

fn map_resume_error(err: crate::client::reconnect::ResumeError) -> OpError {
    use crate::client::reconnect::ResumeError;
    match err {
        ResumeError::Local(err) => err,
        ResumeError::Client(err) => map_client_error(err),
        ResumeError::Deadline => OpError::new(
            ErrorCode::ConnectionFailed,
            format!(
                "the session's path died and was not recovered within {} ms",
                REDIAL_DEADLINE.as_millis()
            ),
        ),
        other @ (ResumeError::UnackedInputOverflow { .. }
        | ResumeError::InputUnrecoverable { .. }) => {
            OpError::new(ErrorCode::ResourceExhausted, other.to_string())
        }
    }
}

/// Lock a mutex, ignoring poisoning: every critical section here is a few
/// field updates, so a poisoned lock means a panic elsewhere and the state
/// is still coherent.
fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Sole owner of one leg's send half: queued input and resizes, in order. A
/// write that fails does not end the attach — a stolen writer lease demotes
/// this peer to read-only (protocol.md §10) and it is still owed its
/// output.
///
/// Every accepted command is recorded in `pending` **before** it is
/// written, so a leg that dies mid-write leaves the bytes retransmittable
/// rather than lost.
async fn pump_attach_input(
    mut writer: crate::client::AttachWriter,
    commands: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<AttachCommand>>>,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    watch: PathWatch,
    finished: Arc<std::sync::atomic::AtomicBool>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    let mut commands = commands.lock().await;
    loop {
        let command = tokio::select! {
            biased;
            _ = &mut stop => return,
            // Cancel-safe, and the only await that can lose the race: the
            // handling below runs to completion once a command is taken.
            command = commands.recv() => match command {
                Some(command) => command,
                None => break,
            },
        };
        // Somebody is waiting for an answer, so the watchdog runs at its
        // fast cadence from here.
        watch.activity();
        let sent = match command {
            AttachCommand::Input(data) => {
                // Recorded first: bytes accepted from the frontend are the
                // client's responsibility from this moment, and a leg that
                // dies before the write lands must retransmit them.
                if let Err(err) = lock(&pending).push(&data) {
                    tracing::warn!(%err, "input dropped: the un-acked buffer is full");
                    continue;
                }
                writer.send_input(&data).await.map(|_| ())
            }
            AttachCommand::Resize { cols, rows } => writer.resize(cols, rows).await,
            AttachCommand::Detach(ack) => {
                // Everything queued ahead of the detach has been written by
                // the time we get here. Finish, wait for the host to
                // acknowledge it, and mark the attach deliberately over so
                // the supervisor does not try to recover it.
                finished.store(true, std::sync::atomic::Ordering::Release);
                let _ = tokio::time::timeout(DETACH_FLUSH, writer.finish_flushed()).await;
                let _ = ack.send(());
                return;
            }
        };
        if sent.is_err() {
            return;
        }
    }
    // The frontend dropped its handle: finish our send half so the host
    // drains what is left and finishes the stream.
    finished.store(true, std::sync::atomic::Ordering::Release);
    writer.finish();
}

/// Sole owner of one leg's control stream: the asynchronous `SessionEvent`s
/// (`writer_changed`, `closed`) an attached peer is owed, the `Pong` a host
/// `Ping` is owed, and the liveness `Ping`s the watchdog asks for.
///
/// The `select!` races exactly one future that touches the session
/// ([`Session::next_control`], which only reads), so nothing that writes is
/// ever cancelled.
async fn pump_attach_control(
    mut session: Session,
    session_ref: String,
    events: tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
    watch: PathWatch,
    probes: Arc<tokio::sync::Notify>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return,
            () = probes.notified() => {
                if session.send_ping().await.is_err() {
                    return;
                }
            }
            message = session.next_control() => {
                let message = match message {
                    Ok(Some(message)) => message,
                    Ok(None) | Err(_) => return,
                };
                // Any inbound control message answers the watchdog, not
                // just the `Pong`: the question is whether the path carries
                // packets.
                watch.inbound();
                match message {
                    ControlIn::Pong => {}
                    ControlIn::Ping { request_id } => {
                        if session.send_pong(request_id).await.is_err() {
                            return;
                        }
                    }
                    // `Exited` also arrives as a data frame, which is the
                    // authoritative copy; emitting both would duplicate a
                    // terminal event in the JSONL stream.
                    ControlIn::Event(event) => {
                        if let Some(json) = control_event_json(&session_ref, event) {
                            let _stalled = watch.stalled();
                            if events.send(Ok(json)).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
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
    /// The endpoint and connection currently carrying this attach. Shared
    /// and swappable because a recovery replaces both underneath handles
    /// that were taken before it happened.
    link: Link,
    /// `None` only after the session was consumed by the teardown.
    session: Option<Session>,
}

/// The endpoint/connection pair an attach is riding right now.
///
/// A recovery builds a new QUIC connection on a new endpoint, but every
/// [`AttachHandle`] a frontend already took — and the teardown path — must
/// keep reaching the live one. So the pair lives behind one shared cell
/// that the recovery swaps, rather than being copied out at construction.
#[derive(Clone, Debug)]
struct Link {
    inner: Arc<std::sync::Mutex<(qsh_transport::Endpoint, qsh_transport::Connection)>>,
}

impl Link {
    fn new(endpoint: qsh_transport::Endpoint, connection: qsh_transport::Connection) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new((endpoint, connection))),
        }
    }

    fn get(&self) -> (qsh_transport::Endpoint, qsh_transport::Connection) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn connection(&self) -> qsh_transport::Connection {
        self.get().1
    }

    fn endpoint(&self) -> qsh_transport::Endpoint {
        self.get().0
    }

    /// Install a new pair, returning the one it replaced so the caller can
    /// tear it down.
    fn replace(
        &self,
        endpoint: qsh_transport::Endpoint,
        connection: qsh_transport::Connection,
    ) -> (qsh_transport::Endpoint, qsh_transport::Connection) {
        let mut slot = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::replace(&mut *slot, (endpoint, connection))
    }
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
        self.link
            .connection()
            .peer_fingerprint()
            .map(|fp| fp.to_string())
    }

    /// Close the control stream and the connection, then let the QUIC close
    /// frames drain.
    fn close(mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let session = self.session.take();
        let (endpoint, connection) = self.link.get();
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
            self.link.connection().close(0, b"done");
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

    /// The renewal schedule with an injected clock: nothing here sleeps,
    /// and nothing here depends on an event arriving — which is the whole
    /// point, because the schedule replaces a renewal that only ran when
    /// the host happened to send something.
    #[test]
    fn a_renewal_comes_due_on_the_clock_and_not_on_an_event() {
        let ttl = Duration::from_secs(24 * 60 * 60);
        let t0 = std::time::Instant::now();
        let mut schedule = RenewalSchedule::new(ttl, t0);

        // Half a window out, and the wait a silent attach is bounded by is
        // exactly that — not "forever, until the host speaks".
        assert_eq!(schedule.due_in(t0), ttl / 2);
        assert!(!schedule.take_if_due(t0));
        assert!(!schedule.take_if_due(t0 + ttl / 2 - Duration::from_secs(1)));

        // Due, claimed once, and re-armed for the next half-window.
        let due_at = t0 + ttl / 2;
        assert!(schedule.take_if_due(due_at));
        assert!(
            !schedule.take_if_due(due_at),
            "a claimed renewal must not fire again on the same instant"
        );
        assert_eq!(schedule.due_in(due_at), ttl / 2);
        assert_eq!(schedule.ttl(), ttl, "a renewal writes the host's window");

        // A wake-up long after the deadline claims exactly one renewal and
        // schedules the next from *now*, not from the missed deadline.
        let late = due_at + ttl * 3;
        assert!(schedule.take_if_due(late));
        assert_eq!(schedule.due_in(late), ttl / 2);
    }

    /// A degenerate window must not turn the event wait into a spin.
    #[test]
    fn a_zero_length_window_still_yields_a_nonzero_wait() {
        let now = std::time::Instant::now();
        let schedule = RenewalSchedule::new(Duration::ZERO, now);
        assert!(schedule.due_in(now) > Duration::ZERO);
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
