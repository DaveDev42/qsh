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
    CapabilitiesData, CapabilitiesReq, ErrorCode, Session as SessionJson, SessionAttachReq,
    SessionCloseData, SessionCloseReq, SessionGetReq, SessionListData, SessionListReq,
    SessionOpenData, SessionOpenReq, SessionReadData, SessionReadReq, SessionResizeData,
    SessionResizeReq, SessionWriteData, SessionWriteReq, UnreachableHost,
};
use qsh_transport::Dialer;

use crate::client::link::DataKillSwitch;
use crate::client::pathwatch::{PathWatch, PathWatchConfig, watch_path};
use crate::client::reconnect::{
    OutputCursor, PathBinder, PendingInput, REDIAL_DEADLINE, Reconnect, ReconnectFuture, Recovered,
    ResumeError, recover,
};
use crate::client::{AttachEvent, ClientError, ControlIn, Session};
use crate::ops::exec::{map_client_error, map_dial_error};
use crate::ops::{LocalRoute, OpError, Operation, Ops, PeerRoute, PeerTarget};
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

/// How long the driver waits for the host to confirm it *applied* the
/// input written before a detach (`InputAck`, protocol.md §10-5).
///
/// Only reached when the host is answering slowly or not at all: the wait
/// ends the moment the ack lands, which on a live session is one round trip
/// plus a PTY write. The bound is what a user is made to wait for a host
/// that has gone quiet, so it is generous rather than snappy — the
/// alternative to waiting is throwing the bytes away.
const DETACH_FLUSH: Duration = Duration::from_secs(2);

/// How long [`AttachHandle::detach`] waits for the driver's answer before
/// closing anyway. Strictly longer than [`DETACH_FLUSH`], so the normal
/// path is bounded by the driver, not by this fallback.
const DETACH_FLUSH_GRACE: Duration = Duration::from_millis(2_500);

/// Ceiling on how long a migration probe waits for *any* answer from the
/// host before it is called a failure.
///
/// Deliberately small: it is spent out of the same [`REDIAL_DEADLINE`]
/// budget the re-dial needs, and migration is only ever a latency
/// optimization (`docs/design/protocol.md` §2). A probe that has to wait
/// longer than this has already cost more than it can save.
const MIGRATION_PROBE_MAX: Duration = Duration::from_millis(300);

/// Floor on the same, so a fast path still tolerates a scheduling hiccup.
const MIGRATION_PROBE_MIN: Duration = Duration::from_millis(100);

/// What a migration probe on a path with this smoothed RTT is worth
/// waiting.
///
/// The question is "did one frame get there and back", so the honest
/// budget is a round trip with slack — not a constant. Fixing it at
/// [`MIGRATION_PROBE_MAX`] spent 600 ms of a 2 s budget on a LAN, where
/// the answer arrives in under a millisecond or not at all; scaling it
/// gives that time back to the re-dial, which is the part that actually
/// needs it (`docs/design/testing.md` L4).
fn migration_probe_budget(rtt: Duration) -> Duration {
    rtt.saturating_mul(2)
        .clamp(MIGRATION_PROBE_MIN, MIGRATION_PROBE_MAX)
}

/// How long the supervisor gives a leg's pumps to stop of their own accord
/// before aborting them.
///
/// Short on purpose, because it is spent inside the recovery deadline. The
/// window it protects is not a network round trip: a pump parked
/// mid-`send_input` on a dead connection is never going to return, and
/// aborting it loses nothing (its bytes were recorded as un-acked *before*
/// the write). The only thing worth waiting for is the handful of
/// microseconds between taking a command off the queue and recording it,
/// plus enough slack for the task to be scheduled at all.
const PUMP_STOP_GRACE: Duration = Duration::from_millis(50);

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
    /// by its route's [`Reconnect::attempt_deadline`] — [`REDIAL_DEADLINE`]
    /// on the forward route, `registration_wait` + [`REDIAL_DEADLINE`] on
    /// the reverse route (`LocalReconnect::attempt_deadline`) so a single
    /// attempt can legitimately cover the whole wait for a new
    /// registration — and separately recorded in the recovery telemetry,
    /// so a campaign counts attempts, not outcomes.
    pub attempts: u32,
    /// Whether to recover at all. Off makes a dead path end the attach the
    /// way it did before recovery existed.
    pub enabled: bool,
    /// Reverse-route only (`LocalReconnect`, `PLAN.md` M3 Step 8): the
    /// ceiling on how long a single reconnect wait asks the daemon to
    /// block for a new-generation live registration
    /// (`LocalHello.wait_ms`, clamped again on the daemon side to
    /// `qsh_proto::local::LOCAL_WAIT_MAX` regardless of what is sent
    /// here — this is this *client's* budget, not a second copy of that
    /// clamp). Unread on the forward route: [`DialReconnect`] never
    /// looks at it. Deliberately **not** [`REDIAL_DEADLINE`] — that 2 s
    /// budget covers the resume *after* a registration is observed
    /// (`docs/design/protocol.md` §11-4's "재등록 시점부터 resume 완료까지
    /// 2초"), while this covers the wait *for* one, which can legitimately
    /// run for as long as the target's own reconnect backoff
    /// (`backoff_max_ms`, default 30 s) takes.
    pub registration_wait: Duration,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            watch: PathWatchConfig::default(),
            migration: true,
            attempts: 3,
            enabled: true,
            registration_wait: qsh_proto::local::LOCAL_WAIT_MAX,
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
    ///
    /// `remote_forward_specs` (`PLAN.md` M4 Step 4's interactive `-R`) is
    /// processed **inside** this call, before the attach driver is
    /// spawned — not left to a later method on the returned
    /// [`SessionAttachStream`] the way [`SessionAttachStream::
    /// open_local_forwards`] is. The reason is [`Connected::run`]: each
    /// `-R` spec costs a real `RemoteForwardOpen` control round trip, and
    /// that needs the connection's [`Session`], but a few lines below
    /// this point `Connected::take_session` moves that `Session` into the
    /// spawned `drive_attach` task for the rest of the attach's life —
    /// after which `Connected::run` can only ever answer `Internal`
    /// ("connection already closed"), because there is no session left to
    /// run a request on. `-L` never hits this because
    /// [`SessionAttachStream::open_local_forwards`] only needs the raw
    /// [`Connected::connection`], which the driver never takes. Pass an
    /// empty slice for a plain attach or `-L`-only one; the resulting
    /// [`qsh_proto::Tunnel`] DTOs come back through
    /// [`SessionAttachStream::take_remote_forward_tunnels`].
    pub fn session_attach(
        &self,
        req: SessionAttachReq,
        remote_forward_specs: &[wire::ForwardSpec],
    ) -> Result<SessionAttachStream, OpError> {
        let r = parse_session_ref(&req.session_ref)?;
        let store = ResumeStore::new(&self.paths);
        // Route-aware (`PLAN.md` M3 Step 7): a live reverse registration
        // relays through this machine's `qsh listen` daemon, exactly like
        // every other `Ops::connect` caller since Step 6 — this was the
        // one holdout still pinned to `resolve_peer`/`connect_target`
        // (forward-only). `target` is kept only on the forward branch:
        // resolution loads the device key, which a platform key store
        // will not hand over from inside a runtime, and a recovery
        // re-dials from inside one — there is no equivalent re-dial on
        // the reverse branch (`RecoveryLink`'s own doc), so nothing there
        // ever needs it back.
        let (mut conn, target, reverse_route) = match self.resolve_route(&r.host)? {
            PeerRoute::Forward(target) => {
                let conn = self.connect_target(&target)?;
                (conn, Some(target), None)
            }
            PeerRoute::Reverse(route) => {
                let (conn, generation) = self.connect_reverse(&route)?;
                let reverse_route = ReverseRoute {
                    host: route.host.clone(),
                    socket: route.socket,
                    generation: std::sync::atomic::AtomicU64::new(generation),
                    registration_wait_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
                };
                (conn, None, Some(reverse_route))
            }
        };
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
        // `-R`: send each `RemoteForwardOpen` now, while `conn` still owns
        // its `Session` — this method's own doc explains why this cannot
        // wait until after the attach driver is spawned below. All-or-
        // nothing, the same discipline `SessionAttachStream::
        // open_local_forwards` uses for `-L`: a spec that fails after
        // earlier ones in this same call already opened a listener on the
        // peer sends `RemoteForwardClose` for each of them (best-effort —
        // their teardown is not this call's failure to report), because
        // dropping this side's bookkeeping alone would leave the peer's
        // listener bound with nobody left to dial its `TCP_ACCEPTED`
        // streams.
        let (remote_acceptor, remote_tunnels) = if remote_forward_specs.is_empty() {
            (None, Vec::new())
        } else {
            // Same reverse-route refusal as `open_local_forwards`, and for
            // the same reason: this leg needs a raw QUIC connection of its
            // own to spawn the `TCP_ACCEPTED` acceptor on (`PLAN.md` M4
            // Step 5).
            let Some(connection) = conn.connection() else {
                conn.close();
                return Err(OpError::new(
                    ErrorCode::Unsupported,
                    "remote forwards over a reverse connection are not implemented yet",
                ));
            };
            let acceptor =
                conn.runtime()
                    .block_on(crate::tunnel::remote::RemoteForwardAcceptor::spawn(
                        connection,
                    ));
            let mut opened_ids: Vec<String> = Vec::with_capacity(remote_forward_specs.len());
            let mut tunnels = Vec::with_capacity(remote_forward_specs.len());
            let mut open_err = None;
            for spec in remote_forward_specs {
                let open_req = crate::ops::tunnel::remote_forward_open_from_spec(spec);
                match conn.run(move |s| Box::pin(s.rfwd_open(open_req))) {
                    Ok(opened) => {
                        acceptor.register(
                            opened.forward_id.clone(),
                            spec.host.clone(),
                            spec.host_port,
                        );
                        opened_ids.push(opened.forward_id.clone());
                        tunnels.push(crate::ops::tunnel::remote_tunnel_dto(
                            spec, &opened, &r.host,
                        ));
                    }
                    Err(err) => {
                        open_err = Some(err);
                        break;
                    }
                }
            }
            if let Some(err) = open_err {
                for forward_id in opened_ids {
                    acceptor.unregister(&forward_id);
                    let close_req = wire::RemoteForwardClose { forward_id };
                    let _ = conn.run(move |s| Box::pin(s.rfwd_close(close_req)));
                }
                conn.close();
                return Err(err);
            }
            (Some(acceptor), tunnels)
        };

        let session = conn
            .take_session()
            .ok_or_else(|| OpError::new(ErrorCode::Internal, "attach lost its control stream"))?;

        let (events_tx, events_rx) = tokio::sync::mpsc::channel(SESSION_ATTACH_QUEUE);
        let (commands, command_rx) = tokio::sync::mpsc::channel(SESSION_ATTACH_QUEUE);
        let session_ref = req.session_ref.clone();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let detaching = Arc::new(std::sync::Mutex::new(()));
        // Seeded with the offset this attach continues from: everything at
        // or below it is already the host's, so a detach with nothing typed
        // since has nothing to wait for.
        let (applied_input, _) = tokio::sync::watch::channel(attached.input_from);
        // What `AttachHandle::detach`/the recovery loop actually hold onto
        // to end or rebuild this attach's transport (`RecoveryLink`'s own
        // doc): the forward route's swappable `Link` on the forward
        // branch, or a hard-stop for this attach's own `LOCAL_STREAM`
        // conduit on the reverse branch — `attached.kill`, set by
        // `Session::open_attach_stream` moments ago, never `conn.link`
        // (which on the reverse route carries nothing usable here; see
        // `ConnectedLink::Reverse`'s own doc).
        let link = match &conn.link {
            ConnectedLink::Forward(fwd) => RecoveryLink::Forward(fwd.clone()),
            ConnectedLink::Reverse { .. } => {
                RecoveryLink::Reverse(ReverseKill::new(attached.kill.clone()))
            }
        };
        let ctx = Arc::new(AttachContext {
            target,
            host: r.host.clone(),
            session_id: r.session_id.clone(),
            session_ref: session_ref.clone(),
            paths: self.paths.clone(),
            no_steal: req.no_steal,
            link: link.clone(),
            window: Arc::new(std::sync::Mutex::new(None)),
            recovery: self.recovery,
            finished: finished.clone(),
            applied_input,
            reverse_route,
        });
        let driver = conn
            .runtime()
            .spawn(drive_attach(ctx, session, attached, command_rx, events_tx));
        Ok(SessionAttachStream {
            stop: AttachStop {
                finished,
                detaching,
                driver,
            },
            forwards: Vec::new(),
            remote_acceptor,
            remote_tunnels,
            conn,
            store: ResumeStore::new(&self.paths),
            events: events_rx,
            commands,
            session_ref,
            replay_from,
            writer_lease,
            renewal: resume_ttl.map(|ttl| RenewalSchedule::new(ttl, std::time::Instant::now())),
            expires_at,
            link,
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

    /// `capabilities.get` (`docs/CLI.md` §6.10, `docs/CLI.md` §2.5 —
    /// unauthorized, local-only operation, same row as `version.get`).
    ///
    /// No `req.host`: this build's own advertised set
    /// ([`wire::LOCAL_CAPABILITIES`]), unprocessed — deterministic and
    /// side-effect-free, the fixture-able form `docs/ROADMAP.md` M7's DoD 3
    /// scope-creep tripwire pins.
    ///
    /// With `req.host`: dials and negotiates exactly like every other
    /// value op ([`Self::call`]) and reports the intersection that
    /// specific connection's own `Hello` exchange settled on
    /// ([`Session::capabilities`], computed by
    /// `crate::handshake::negotiated_capabilities`). There is **no
    /// dedicated wire request** for this — the negotiated set is a
    /// byproduct of the handshake every connection already performs
    /// before any privileged op runs, not a privileged operation of its
    /// own that a peer's ACL would ever see (`docs/CLI.md` §2.5's "인가
    /// 불요" row already lists `capabilities.get`, and `OP_REGISTRY`
    /// — `crate::acl::registry` — has no row for it, on purpose).
    pub fn capabilities(&self, req: CapabilitiesReq) -> Result<CapabilitiesData, OpError> {
        match req.host {
            None => Ok(CapabilitiesData {
                capabilities: wire::LOCAL_CAPABILITIES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                host: None,
            }),
            Some(host) => {
                let capabilities = self.call(&host, |s| {
                    Box::pin(async move { Ok(s.capabilities.clone()) })
                })?;
                Ok(CapabilitiesData {
                    capabilities,
                    host: Some(host),
                })
            }
        }
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
    ///
    /// Routes via [`Ops::resolve_route`] (`PLAN.md` M3 Step 6): a live
    /// reverse registration relays through this machine's `qsh listen`
    /// daemon ([`Self::connect_reverse`]); otherwise this is exactly the
    /// forward dial it always was, via [`Self::connect_target`]. Every
    /// caller of `connect` — the six value ops and [`Ops::session_reader`]
    /// — gets this transparently; `session.attach`'s own
    /// [`Self::connect_target`] call stays forward-only (M3 Step 7 adds
    /// its reverse leg).
    pub(crate) fn connect(&self, host: &str) -> Result<Connected, OpError> {
        match self.resolve_route(host)? {
            PeerRoute::Forward(target) => self.connect_target(&target),
            // Generation is only ever needed to seed a `session.attach`'s
            // recovery baseline (`Self::connect_reverse`'s own doc) — none
            // of this method's six value-op callers attach anything.
            PeerRoute::Reverse(route) => {
                self.connect_reverse(&route).map(|(conn, _generation)| conn)
            }
        }
    }

    /// [`connect`](Self::connect) for a peer already resolved, forward
    /// route only.
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
                link: ConnectedLink::Forward(Link::new(endpoint, connection)),
                session: Some(session),
            }),
            Err(err) => {
                runtime.shutdown_timeout(CLOSE_DRAIN);
                Err(err)
            }
        }
    }

    /// [`connect`](Self::connect)'s reverse-route branch: relay through
    /// this machine's resident `qsh listen` daemon over a `LOCAL_CONTROL`
    /// conduit instead of dialing the peer directly (`PLAN.md` M3 Step 6).
    /// No identity load here — the CLI process presents no certificate of
    /// its own on this leg, the daemon already holds the live mTLS
    /// connection to the peer — so, unlike [`Self::connect_target`],
    /// there is nothing that must happen before this method's own runtime
    /// exists.
    /// Returns the registration `generation` observed at connect time
    /// alongside [`Connected`] — [`Self::session_attach`]'s reverse arm
    /// needs it to seed [`AttachContext`]'s reverse-route baseline (Step
    /// 8's `LocalReconnect` input); every other caller of
    /// [`Self::connect`] discards it.
    #[cfg(unix)]
    fn connect_reverse(&self, route: &LocalRoute) -> Result<(Connected, u64), OpError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?;
        match runtime.block_on(dial_reverse(route)) {
            Ok((session, peer_fingerprint, generation)) => Ok((
                Connected {
                    runtime: Some(runtime),
                    link: ConnectedLink::Reverse {
                        peer_fingerprint,
                        socket: route.socket.clone(),
                        host: route.host.clone(),
                    },
                    session: Some(session),
                },
                generation,
            )),
            Err(err) => {
                runtime.shutdown_timeout(CLOSE_DRAIN);
                Err(err)
            }
        }
    }

    /// Windows twin of [`Self::connect_reverse`]: localctl (UDS) has no
    /// meaning there, and [`Ops::resolve_route`] never actually produces
    /// [`PeerRoute::Reverse`] on that platform (`Ops::host::reverse_host_entries_async`
    /// always returns empty), so this exists only so `connect`'s match
    /// compiles — it is unreachable in practice.
    #[cfg(not(unix))]
    fn connect_reverse(&self, _route: &LocalRoute) -> Result<(Connected, u64), OpError> {
        Err(OpError::new(
            ErrorCode::Unsupported,
            "reverse routing (localctl) is not available on this platform",
        ))
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

/// Open a `LOCAL_CONTROL` conduit to `route`'s daemon and build a
/// [`Session`] over it — the async half of [`Ops::connect_reverse`], split
/// out the same way [`dial_peer`] is. `wait_ms: 0`, `known_generation:
/// None`: [`Ops::resolve_route`] already observed a *live* registration
/// before this is ever called (`crate::localctl::client::open_control`'s
/// own doc), so there is nothing to wait for and no prior generation to
/// gate on here — [`dial_reverse_wait`] is the Step 8 sibling that does
/// both.
///
/// Returns the ack's `peer_fingerprint` and `generation` alongside the
/// session — [`Connected::peer_fingerprint`] on the reverse leg is exactly
/// this `peer_fingerprint` value (`docs/adr/`'s ADR-0007 presentation
/// condition, `PLAN.md` M3 Step 6), never re-derived from a QUIC
/// connection this process does not itself hold; `generation` seeds
/// [`AttachContext`]'s reverse-route baseline that Step 8's
/// `LocalReconnect` waits past.
#[cfg(unix)]
async fn dial_reverse(route: &LocalRoute) -> Result<(Session, Option<String>, u64), OpError> {
    dial_reverse_wait(route, 0, None).await
}

/// [`dial_reverse`], generalized with the two inputs Step 8's
/// `LocalReconnect` needs on top of a first attach's `wait_ms: 0,
/// known_generation: None`: how long to wait for a *live* registration
/// (`LOCAL_WAIT_MAX`-clamped by the daemon, `crate::localctl::client::open_control`'s
/// own doc) and which generation it must be strictly newer than
/// (`qsh/local/v1.proto`'s `LocalHello.known_generation` doc). Opens both
/// the `LOCAL_CONTROL` conduit this returns *and* nothing else — the data
/// conduit is a separate `open_stream` call the caller makes once it has
/// something to attach.
#[cfg(unix)]
async fn dial_reverse_wait(
    route: &LocalRoute,
    wait_ms: u32,
    known_generation: Option<u64>,
) -> Result<(Session, Option<String>, u64), OpError> {
    let handshake = crate::localctl::client::open_control(
        &route.socket,
        &route.host,
        wait_ms,
        known_generation,
    )
    .await?;
    let peer_fingerprint = Some(handshake.peer_fingerprint.clone());
    let generation = handshake.generation;
    let session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        route.socket.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );
    Ok((session, peer_fingerprint, generation))
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
    /// Finish the send half and report back once the host has acknowledged
    /// applying everything written before it. Travels the same ordered
    /// queue as the input so a detach cannot overtake the bytes typed just
    /// before it (`docs/CLI.md` §7).
    Detach(std::sync::mpsc::SyncSender<DetachFlush>),
}

/// What a detach could establish about the input queued ahead of it.
///
/// A detach closes the connection, and a QUIC close throws away anything
/// the peer has not taken, so "did the shell get it?" has to be answered
/// *before* the close rather than assumed after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachFlush {
    /// The host acknowledged applying every byte written before the detach:
    /// a command typed immediately ahead of `~d` reached the child.
    Applied,
    /// The bound elapsed with bytes still unacknowledged, so they may never
    /// have reached the child. The caller has to say so — silently dropped
    /// input is what `docs/PRD.md` §8 forbids.
    Unconfirmed,
}

/// A live attach: a blocking `qsh.event/v1` event stream out, an
/// input/resize channel in. See [`Ops::session_attach`].
///
/// The connection, its runtime and the driver task are owned here, so
/// dropping this ends the attach.
pub struct SessionAttachStream {
    /// **Declared first on purpose**: fields drop in declaration order, so
    /// this marks the attach deliberately over and stops the driver before
    /// the connection underneath it goes away. Without it, dropping a
    /// stream without calling [`close`](Self::close) closes the connection
    /// with `finished` still false, and the driver reads its own teardown
    /// as a path death and starts re-dialing.
    stop: AttachStop,
    /// The `-L` local forwards opened on this attach, if any
    /// ([`Self::open_local_forwards`]). Declared **before** `conn`
    /// deliberately: each handle's drop aborts its accept loop on `conn`'s
    /// runtime, so they must go while that runtime is still there. That
    /// ordering is also the whole `-L` teardown story — the listeners die
    /// with the attach, no daemon and no close RPC (`PLAN.md` M4 §4.1 #1).
    forwards: Vec<crate::tunnel::LocalForwardHandle>,
    /// The `-R` remote forwards opened on this attach, if any — one shared
    /// [`crate::tunnel::remote::RemoteForwardAcceptor`] for every `-R` spec
    /// on this attach (`PLAN.md` M4 Step 4): a single `TCP_ACCEPTED`
    /// dispatcher per connection is not an optimization, it is the only
    /// correct shape once more than one `-R` shares a connection (that
    /// type's own doc explains why two independent accept loops would
    /// misroute each other's streams). Declared **before** `conn` for the
    /// same reason `forwards` is: its accept task runs on `conn`'s runtime.
    /// Set by [`Ops::session_attach`] itself, not by a method on this
    /// type — see that method's own doc for why the `RemoteForwardOpen`
    /// round trips cannot wait until after this value exists.
    ///
    /// Never read again after this: it is held purely for its `Drop`
    /// (aborts the `TCP_ACCEPTED` dispatcher task, same one-drop teardown
    /// `forwards`'s handles use) — `rustc`'s `dead_code` lint cannot see a
    /// field kept alive only for its destructor, hence the `allow` below.
    #[allow(dead_code)]
    remote_acceptor: Option<crate::tunnel::remote::RemoteForwardAcceptor>,
    /// The `qsh.cli/v1` [`Tunnel`](qsh_proto::Tunnel) DTO for each `-R`
    /// spec [`Ops::session_attach`] already opened, waiting for
    /// [`Self::take_remote_forward_tunnels`] to hand them to the frontend
    /// to render — the same information `-L`'s [`Self::open_local_forwards`]
    /// returns directly, split out here only because `-R`'s RPCs cannot
    /// run this late (this struct's own doc on `remote_acceptor`).
    remote_tunnels: Vec<qsh_proto::Tunnel>,
    conn: Connected,
    /// See [`SessionReader::store`].
    store: ResumeStore,
    events: tokio::sync::mpsc::Receiver<Result<SessionEvent, OpError>>,
    commands: tokio::sync::mpsc::Sender<AttachCommand>,
    session_ref: String,
    replay_from: u64,
    writer_lease: bool,
    /// When to push the stored entry's expiry forward; `None` when the
    /// host's window did not parse and there is nothing to schedule from.
    renewal: Option<RenewalSchedule>,
    expires_at: String,
    /// What [`Self::handle`] hands each [`AttachHandle`] — computed once
    /// at `session_attach` and kept here rather than re-derived from
    /// `conn` on every call, because the reverse route's half
    /// (`attached.kill`) only ever exists for the instant right after
    /// `open_attach_stream` returns (`crate::ops::session::RecoveryLink`'s
    /// own doc).
    link: RecoveryLink,
}

/// Ends an attach the same way whether it was closed or merely dropped:
/// mark it deliberately over, then stop the driver. See
/// [`SessionAttachStream::stop`].
struct AttachStop {
    /// Shared with the driver: set once this attach is deliberately over,
    /// so a connection the frontend closed is never recovered from.
    finished: Arc<std::sync::atomic::AtomicBool>,
    /// See [`AttachHandle::detaching`].
    detaching: Arc<std::sync::Mutex<()>>,
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for AttachStop {
    fn drop(&mut self) {
        // A `~d` runs on the frontend's input thread while the thread that
        // owns the stream is still in `next_event`, so the two race: the
        // detach is announced before it has flushed, and the owner can
        // reach this teardown while the driver is still writing the bytes
        // typed just before the escape. Aborting there loses them for
        // good. The gate makes the teardown wait out a detach that is
        // already in flight — which is bounded by
        // [`DETACH_FLUSH_GRACE`], not by the host.
        let _flushing = lock(&self.detaching);
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        self.driver.abort();
    }
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
    /// Bind and start this attach's `-L` local forwards (`PLAN.md` M4
    /// Step 3; `docs/CLI.md` §7 "`-L`/`-R`은 이 대화형 form의 companion
    /// flag이지 별도 명령이 아니다").
    ///
    /// The forwards ride **this attach's** connection and are owned by
    /// this stream, so they live exactly as long as the interactive
    /// session and die with it — the foreground holder model (§4.1 #1),
    /// with no daemon and no orphaned bound port. Nothing here is
    /// authorized locally: each forwarded TCP connection is authorized by
    /// the peer, inline at stream open, before the peer dials anything
    /// (`docs/design/protocol.md` §7).
    ///
    /// Binding is all-or-nothing: a spec that fails drops every listener
    /// this call already bound, so a partially-established `-L` set never
    /// survives into the session. Call it **before** the frontend takes
    /// the terminal — a bind failure is an ordinary typed error, and the
    /// caller should report it rather than half-start a session.
    ///
    /// Returns the [`qsh_proto::Tunnel`] DTO of each forward, in `specs`
    /// order, for
    /// the frontend to render.
    pub fn open_local_forwards(
        &mut self,
        specs: &[qsh_proto::wire::ForwardSpec],
    ) -> Result<Vec<qsh_proto::Tunnel>, OpError> {
        if specs.is_empty() {
            return Ok(Vec::new());
        }
        let host = parse_session_ref(&self.session_ref)?.host;
        // A `-L` needs a raw QUIC stream of its own; the reverse route has
        // no connection here to open one on (`Connected::connection`).
        // Fail closed rather than pretend (`PLAN.md` M4 Step 5).
        let Some(connection) = self.conn.connection() else {
            return Err(OpError::new(
                ErrorCode::Unsupported,
                "local forwards over a reverse connection are not implemented yet",
            ));
        };
        let started = {
            let runtime = self.conn.runtime();
            let mut started = Vec::with_capacity(specs.len());
            for spec in specs {
                // On `Err` the loop returns, dropping every handle in
                // `started` — each drop closes its listener.
                let handle = runtime
                    .block_on(crate::tunnel::LocalForwardHandle::start(
                        spec,
                        connection.clone(),
                    ))
                    .map_err(crate::ops::tunnel::map_local_forward_error)?;
                started.push(handle);
            }
            started
        };
        let tunnels = started.iter().map(|f| f.tunnel(&host)).collect();
        self.forwards.extend(started);
        Ok(tunnels)
    }

    /// This attach's `-R` remote forward [`Tunnel`](qsh_proto::Tunnel)
    /// DTOs, for the frontend to render — one per spec, in the order
    /// passed to [`Ops::session_attach`], which is where the actual
    /// `RemoteForwardOpen` round trips already happened (this method's own
    /// struct field doc, [`SessionAttachStream::remote_acceptor`], says
    /// why they cannot happen here instead). Takes the vec, so a second
    /// call sees nothing left — there is exactly one batch to hand over,
    /// same as `-L`'s single [`Self::open_local_forwards`] call.
    pub fn take_remote_forward_tunnels(&mut self) -> Vec<qsh_proto::Tunnel> {
        std::mem::take(&mut self.remote_tunnels)
    }

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

    /// When the session's resume window ends (RFC 3339), as the host
    /// reported it when this attach was **first** established.
    ///
    /// A snapshot, not a live value: a resume underneath this stream gets a
    /// fresh `expires_at` from the host and writes it straight to the
    /// stored credential (`reattach`), which is the copy that decides
    /// whether a later attach can resume. This one is not re-read, because
    /// the TTL the host grants is a constant of its configuration; if that
    /// ever stops being true, the driver has to publish the new window back
    /// here and into [`RenewalSchedule::ttl`] together.
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
            link: self.link.clone(),
            finished: self.stop.finished.clone(),
            detaching: self.stop.detaching.clone(),
        }
    }

    /// Stop the attach and close the connection.
    pub fn close(self) {
        // Destructured rather than dropped whole so the ordering is
        // explicit: `stop` marks the attach finished and aborts the driver
        // *before* `close` drains and tears down the connection, which is
        // the same order the drop glue produces.
        let Self { stop, conn, .. } = self;
        drop(stop);
        conn.close();
    }
}

/// The input side of a live attach: cloneable, `Send`, and usable from any
/// thread — session input, window-size changes, and a detach that leaves
/// the session running. See [`SessionAttachStream::handle`].
#[derive(Clone)]
pub struct AttachHandle {
    commands: tokio::sync::mpsc::Sender<AttachCommand>,
    link: RecoveryLink,
    finished: Arc<std::sync::atomic::AtomicBool>,
    /// Held for as long as a detach is flushing, so the thread that owns
    /// the stream cannot tear the driver down mid-flush. See
    /// [`AttachStop::drop`].
    detaching: Arc<std::sync::Mutex<()>>,
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
    ///
    /// The answer says whether the input typed ahead of the detach is known
    /// to have reached the child; a caller that gets
    /// [`DetachFlush::Unconfirmed`] owes the user a word about it.
    pub fn detach(&self) -> DetachFlush {
        // Held across the whole detach: the thread that owns the stream is
        // free to tear the attach down the moment it notices, and the
        // teardown aborts the very driver this flush is waiting on.
        let _flushing = lock(&self.detaching);
        // Marked deliberate *first*: closing the connection is
        // indistinguishable, from the driver's side, from the path dying,
        // and a detach that raced the flag would be answered with a
        // re-dial and a resume of the session the user just left.
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        // Ordering next: hand the driver a detach marker down the same
        // queue as the input, so everything already typed is written — and
        // acknowledged by the host — before the connection goes away. A
        // QUIC close discards unsent stream data, and a host that has not
        // read a frame yet loses it with the stream, so only the host's own
        // `InputAck` can say the bytes made it (protocol.md §10-5).
        //
        // Bounded on both sides. A full queue (the host stopped reading)
        // means the bytes were never going to land anyway, and a driver
        // parked on flow control never answers; neither may keep the user
        // attached, so the close happens regardless — and says so.
        let (ack, flushed) = std::sync::mpsc::sync_channel(1);
        let outcome = if self.commands.try_send(AttachCommand::Detach(ack)).is_ok() {
            flushed
                .recv_timeout(DETACH_FLUSH_GRACE)
                .unwrap_or(DetachFlush::Unconfirmed)
        } else {
            DetachFlush::Unconfirmed
        };
        // Forward: closing the connection is what makes `next_event`
        // return and the host release the writer lease (this doc's own
        // opening paragraph). Reverse: there is no connection this attach
        // owns alone to close (`RecoveryLink`'s own doc) — the hard-stop
        // is this attach's own `LOCAL_STREAM` conduit going away locally,
        // which needs no cooperation from the daemon or the peer either.
        match &self.link {
            RecoveryLink::Forward(link) => link.connection().close(0, b"detach"),
            RecoveryLink::Reverse(kill) => kill.kill(),
        }
        outcome
    }

    /// Whether a detach is flushing **right now** — the state the
    /// teardown gate in [`SessionAttachStream::close`] waits out.
    ///
    /// A snapshot, with one asymmetry that makes it useful: `false` can be
    /// stale the instant it returns (a detach may begin right after), but
    /// `true` means the detach currently holding the gate keeps it until
    /// that detach completes — so a teardown started while this reports
    /// `true` is guaranteed to wait the flush out. An owner that knows a
    /// detach was *requested* on another thread cannot get the same
    /// guarantee from the request alone: thread start order says nothing
    /// about who reaches the gate first.
    pub fn is_detaching(&self) -> bool {
        match self.detaching.try_lock() {
            Ok(_guard) => false,
            Err(std::sync::TryLockError::WouldBlock) => true,
            // Poisoned: the flushing thread panicked, so whatever detach
            // held the gate is over — nothing left to wait out.
            Err(std::sync::TryLockError::Poisoned(_)) => false,
        }
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
    /// `Some` only on the forward route — `session_attach`'s own doc on
    /// why the reverse route never resolves one of these at all.
    /// [`reattach`] (the only reader) is reachable only when
    /// [`Self::link`] is [`RecoveryLink::Forward`] (`drive_attach`'s "no
    /// recovery on the reverse leg" gate), so this being `None` there is
    /// never actually observed.
    target: Option<PeerTarget>,
    host: String,
    session_id: String,
    session_ref: String,
    paths: crate::config::Paths,
    no_steal: bool,
    /// The transport this attach's hard-stop and recovery ride —
    /// [`RecoveryLink`]'s own doc.
    link: RecoveryLink,
    /// The last window size the frontend asked for, if it ever did.
    ///
    /// A `Resize` is written straight through and is not part of the
    /// un-acked input axis, so one that lands while the path is dead is
    /// written to a stream nobody is reading. Remembering it lets the
    /// resume re-assert the geometry instead of leaving the remote PTY on
    /// a stale size until the user happens to resize again.
    window: Arc<std::sync::Mutex<Option<(u16, u16)>>>,
    recovery: RecoveryConfig,
    /// Set once the frontend deliberately ended the attach, so a connection
    /// **we** closed is never mistaken for a path that died and recovered
    /// from.
    finished: Arc<std::sync::atomic::AtomicBool>,
    /// Highest cumulative input offset the host has confirmed *applying*
    /// (`InputAck`), published by whichever leg is reading.
    ///
    /// Separate from the un-acked buffer next to it, which the same acks
    /// drain, because this one has a waiter: the detach flush. A transport
    /// acknowledgement is not enough there — it says the bytes arrived,
    /// while the host only sends an `InputAck` once the child has actually
    /// been handed them (`crate::session_stream`), and a connection closed
    /// in between drops whatever the host had not read yet.
    applied_input: tokio::sync::watch::Sender<u64>,
    /// `Some` only on the reverse route — the mirror image of
    /// [`Self::target`]'s "`Some` only on forward". Step 8's
    /// [`LocalReconnect`] input: which daemon to ask, and the highest
    /// registration generation this attach has ridden so far. Seeded at
    /// connect time by [`Ops::session_attach`]'s reverse arm from
    /// `LocalHelloAck.generation`, then advanced by every successful
    /// `LocalReconnect` landing — so a *second* leg death after a
    /// recovery waits past the generation the recovery itself landed on,
    /// never the original one again.
    reverse_route: Option<ReverseRoute>,
}

impl AttachContext {
    fn finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// [`AttachContext::reverse_route`]'s payload: which daemon socket and
/// host alias to reconnect to (`LocalHello.host`, `LocalRoute`'s own
/// fields — kept here as an owned copy rather than a borrow because this
/// outlives the `session_attach` call that resolved them), and the
/// generation baseline [`LocalReconnect`] must wait past. The generation
/// is interior-mutable (not just `u64`) because it is shared, through the
/// one `Arc<AttachContext>` every leg of this attach holds, between
/// whichever `LocalReconnect` is currently running and the next one
/// `drive_attach`'s gate builds after a *subsequent* leg death — see the
/// field's own doc on `AttachContext` for why the value must survive
/// across that boundary rather than being reset per-`LocalReconnect`.
struct ReverseRoute {
    // `host`/`socket`/`generation` are read only by the `#[cfg(unix)]`
    // `local_reattach`/`LocalReconnect` dial path; the struct is still
    // constructed on every platform, so they are dead — not absent — on
    // Windows. (`registration_wait_ms` below stays live everywhere: the
    // recovery-report getter that reads it is not gated.)
    #[cfg_attr(not(unix), allow(dead_code))]
    host: String,
    #[cfg_attr(not(unix), allow(dead_code))]
    socket: std::path::PathBuf,
    #[cfg_attr(not(unix), allow(dead_code))]
    generation: std::sync::atomic::AtomicU64,
    /// Milliseconds the most recently *completed* [`LocalReconnect`] wait
    /// spent blocked on the daemon's new-generation registration before it
    /// could redeem the resume credential — measured across the wait
    /// only, not the redemption that follows it. This is Step 8's
    /// `registration_wait_ms` telemetry *input*: `docs/CLI.md` §6.4 names
    /// the field, and wiring it into the emitted `qsh::recovery` record is
    /// a later step's job, not this one's — this field only has to make
    /// the number available to whatever reads it next.
    /// `u64::MAX` means "no `LocalReconnect` wait has completed yet on
    /// this route" (the field's zero value would be indistinguishable
    /// from a wait that resolved instantly, which the daemon's own
    /// immediate-hit branch can genuinely do).
    registration_wait_ms: std::sync::atomic::AtomicU64,
}

/// The reverse route's swappable hard-stop — the [`DataKillSwitch`]
/// counterpart to [`Link`]'s swappable endpoint/connection pair, and for
/// exactly the same reason ([`Link`]'s own doc: "every `AttachHandle` a
/// frontend already took — and the teardown path — must keep reaching the
/// live one"). Before Step 8 the reverse route never rebuilt a leg, so a
/// bare, un-swappable `DataKillSwitch` was enough; Step 8's
/// [`LocalReconnect`] lands a *new* `LOCAL_STREAM` conduit with its own
/// kill switch on every successful recovery, and every clone of
/// [`RecoveryLink::Reverse`] — [`AttachContext::link`]'s and
/// [`AttachHandle::link`]'s alike — has to observe that swap, not go on
/// killing the conduit that already died. One shared cell, exactly the
/// shape [`Link`] already uses.
#[derive(Clone, Default)]
struct ReverseKill(Arc<std::sync::Mutex<DataKillSwitch>>);

impl ReverseKill {
    fn new(kill: DataKillSwitch) -> Self {
        Self(Arc::new(std::sync::Mutex::new(kill)))
    }

    /// Shut the *current* conduit down — see [`DataKillSwitch::kill`].
    fn kill(&self) {
        lock(&self.0).kill();
    }

    /// Install a new kill switch, handing back the one it replaced so the
    /// caller can decide whether it is still worth killing explicitly
    /// (mirrors [`Link::replace`]).
    // Only the `#[cfg(unix)]` `LocalReconnect` recovery swap calls this;
    // `kill`/`new` above are used cross-platform, `replace` is not.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn replace(&self, new: DataKillSwitch) -> DataKillSwitch {
        std::mem::replace(&mut *lock(&self.0), new)
    }
}

/// What an attach's [`AttachContext::link`]/[`AttachHandle::link`] rides —
/// the forward route's swappable [`Link`], or, on the reverse route
/// (`PLAN.md` M3 Step 7), this attach's own `LOCAL_STREAM` hard-stop,
/// swappable since Step 8 ([`ReverseKill`]'s own doc).
///
/// **Recovery on the reverse leg since Step 8** rides a different seam
/// than the forward route's, because the underlying transport really is
/// different: the forward route's migrate-or-resume machinery
/// ([`recover_attach`], [`reattach`], [`watch_path`]) is built on a QUIC
/// `Connection` this one attach owns exclusively — probeable for
/// liveness, swappable for a fresh dial, and safe to hand a full
/// `close()` to because nothing else is riding it. None of that holds on
/// the reverse route: the `Connection` a target sees is its *one*
/// long-lived registration to the controller, shared by every attach
/// every daemon-relayed CLI process has open to it, so there is nothing
/// attach-scoped to probe or migrate — only [`LocalReconnect`]'s wait-
/// then-reattach applies (`recover_attach`'s `link: None` branch, its own
/// doc). `drive_attach`'s gate still reads `&ctx.link` to decide *which*
/// [`Reconnect`] to build, but both branches now reach [`recover_attach`]
/// when `ctx.recovery.enabled` — a link death that recovery cannot use
/// (disabled, or `LocalReconnect` exhausted, `PLAN.md` M3 Step 8) still
/// ends the attach with a typed error (`LegEnd::Broken`'s existing path),
/// never a panic, an `unreachable!`, or a hang.
#[derive(Clone)]
enum RecoveryLink {
    /// The forward route: a real, swappable QUIC endpoint/connection pair
    /// (recovery-capable — [`Link`]'s own doc).
    Forward(Link),
    /// The reverse route: this attach's own `LOCAL_STREAM` conduit,
    /// killable synchronously from any thread and swappable across a
    /// recovery ([`ReverseKill`]'s own doc) — no `Connection`, no
    /// `Endpoint`, nothing [`recover_attach`]'s migration half could
    /// probe (it never tries to on this route — its own doc).
    Reverse(ReverseKill),
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

impl LegEnd {
    /// Whether the leg's streams are still usable if the connection under
    /// them turns out to be alive.
    ///
    /// Only [`LegEnd::PathDead`] is: the watchdog suspects the *path*, and
    /// the streams on top of it are untouched, so a connection that
    /// answers a probe (or one a rebind rescues) can simply be read on.
    /// [`LegEnd::Broken`] is not — a reset or malformed `SESSION_DATA`
    /// stream stays broken however healthy the connection is (a host-side
    /// `RESET_CODE_SESSION_CONFLICT`/`RESET_CODE_BAD_HEADER` arrives on a
    /// perfectly live connection), so answering it with a migration would
    /// hand back the same failing reader for the driver to fail on again,
    /// immediately and forever. It has to be rebuilt.
    fn leg_survived(&self) -> bool {
        matches!(self, LegEnd::PathDead)
    }
}

/// A leg's helper tasks, stoppable without losing queued input.
///
/// Stopping is a signal and a bounded wait, not an abort: a pump aborted
/// between taking a command off the queue and recording it would silently
/// eat a keystroke the user believes they typed. The abort is the fallback
/// for a pump parked mid-write on a connection that is already dead — by
/// then its bytes are recorded as un-acked and the resume retransmits them.
struct LegPumps {
    input: Option<Pump>,
    control: Option<Pump>,
}

/// One pump: the signal that asks it to stop, and its handle.
struct Pump {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl LegPumps {
    async fn stop(&mut self) {
        for slot in [&mut self.input, &mut self.control] {
            {
                let Some(pump) = slot.as_mut() else {
                    continue;
                };
                if let Some(stop) = pump.stop.take() {
                    let _ = stop.send(());
                }
                // Awaited **in place**, with the handle still in the slot.
                // This future runs inside the recovery deadline and can be
                // cancelled here, and a dropped `JoinHandle` *detaches* its
                // task rather than aborting it — a pump left parked
                // mid-write on the dead connection would keep the shared
                // command queue locked, so the next leg's input pump could
                // not start. Leaving it in the slot means the retry, and
                // `Drop`, can still abort it.
                if tokio::time::timeout(PUMP_STOP_GRACE, &mut pump.handle)
                    .await
                    .is_err()
                {
                    pump.handle.abort();
                }
            }
            *slot = None;
        }
    }
}

impl Drop for LegPumps {
    fn drop(&mut self) {
        for slot in [&mut self.input, &mut self.control] {
            if let Some(pump) = slot.take() {
                pump.handle.abort();
            }
        }
    }
}

/// Start (or, on the reverse route, deliberately not start) the path
/// watchdog for one leg.
///
/// Forward: [`watch_path`] polls the real QUIC `Connection` this attach's
/// [`RecoveryLink::Forward`] holds, exactly as before Step 7. Reverse:
/// there is no connection this attach owns alone to probe (`RecoveryLink`'s
/// own doc) — the returned task simply never completes, so `watch.dead()`
/// never fires and [`read_leg`]'s `select!` is decided purely by the
/// `LOCAL_STREAM` conduit's own reader (a clean end is [`LegEnd::Ended`],
/// an error is [`LegEnd::Broken`] — both already handled with no recovery
/// attempted, since `drive_attach`'s gate only ever calls [`recover_attach`]
/// on a `Forward` link).
fn spawn_watchdog(
    link: &RecoveryLink,
    watch: PathWatch,
    probes: Arc<tokio::sync::Notify>,
) -> AbortOnDrop {
    match link {
        RecoveryLink::Forward(link) => {
            AbortOnDrop(tokio::spawn(watch_path(link.connection(), watch, probes)))
        }
        RecoveryLink::Reverse(_) => AbortOnDrop(tokio::spawn(async move {
            let _ = (watch, probes);
            std::future::pending::<()>().await;
        })),
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
            input: Some(Pump {
                stop: Some(input_stop),
                handle: tokio::spawn(pump_attach_input(
                    writer,
                    commands.clone(),
                    pending.clone(),
                    watch.clone(),
                    ctx.clone(),
                    events.clone(),
                    input_stop_rx,
                )),
            }),
            control: Some(Pump {
                stop: Some(ctl_stop),
                handle: tokio::spawn(pump_attach_control(
                    session,
                    ctx.session_id.clone(),
                    ctx.session_ref.clone(),
                    events.clone(),
                    watch.clone(),
                    probes.clone(),
                    ctl_stop_rx,
                )),
            }),
        };
        let mut watchdog = spawn_watchdog(&ctx.link, watch.clone(), probes.clone());

        loop {
            let end = read_leg(&mut reader, &cursor, &pending, &watch, &ctx, &events).await;
            // Decided here, before `end` is consumed: a recovery may only
            // be answered with "keep reading the same leg" if the leg
            // itself survived. See [`LegEnd::leg_survived`].
            let leg_survived = end.leg_survived();
            let recoverable = match end {
                LegEnd::Ended => {
                    // The data stream ended. `session.closed` has no
                    // `SessionFrame` form, so a close the host queued just
                    // before the FIN is still in flight on the control
                    // stream — give it a bounded moment to arrive rather
                    // than racing it to the exit (CLI.md §6.4 makes it the
                    // last event).
                    if let Some(pump) = pumps.control.as_mut() {
                        let _ = tokio::time::timeout(ATTACH_CONTROL_DRAIN, &mut pump.handle).await;
                    }
                    return;
                }
                LegEnd::Gone => return,
                LegEnd::PathDead => None,
                LegEnd::Broken(err) => Some(err),
            };
            // A connection the frontend closed on purpose (a detach) is not
            // a path that died, and recovering from it would resurrect an
            // attach the user just ended — checked identically on both
            // routes. Which `Reconnect` `recover_attach` gets built with is
            // the one thing that still depends on the route (`RecoveryLink`'s
            // own doc): the forward route redials itself (`DialReconnect`),
            // the reverse route waits for the target's own re-dial to land
            // as a new registration generation (`LocalReconnect`, Step 8).
            let recovery = if let RecoveryLink::Forward(link) = &ctx.link
                && ctx.recovery.enabled
                && !ctx.finished()
            {
                let forward_link = link.clone();
                drop(watchdog);
                let reconnector =
                    DialReconnect::new(ctx.clone(), forward_link.clone(), pending.clone());
                let recovery = recover_attach(
                    &ctx,
                    Some(&forward_link),
                    leg_survived,
                    &watch,
                    &probes,
                    &cursor,
                    &mut pumps,
                    &reconnector,
                )
                .await;
                if matches!(recovery, Recovery::SameLeg) {
                    // Migrated: the connection, both streams and every
                    // cursor are exactly as they were. Re-arm the watchdog
                    // and keep reading the same stream. Only the forward
                    // route can ever produce this (`recover_attach`'s own
                    // doc on its `link: None` branch), so it is handled
                    // here rather than in the route-agnostic match below.
                    watch.revive();
                    watchdog = AbortOnDrop(tokio::spawn(watch_path(
                        forward_link.connection(),
                        watch.clone(),
                        probes.clone(),
                    )));
                    continue;
                }
                recovery
            } else if let RecoveryLink::Reverse(_) = &ctx.link
                && ctx.recovery.enabled
                && !ctx.finished()
            {
                drop(watchdog);
                let reconnector = LocalReconnect::new(ctx.clone(), pending.clone());
                recover_attach(
                    &ctx,
                    None,
                    leg_survived,
                    &watch,
                    &probes,
                    &cursor,
                    &mut pumps,
                    &reconnector,
                )
                .await
            } else {
                if let Some(err) = recoverable {
                    let _ = events.send(Err(map_client_error(err))).await;
                }
                return;
            };

            match recovery {
                Recovery::SameLeg => {
                    // Structurally reachable only from the forward branch
                    // above, which already `continue`d before getting
                    // here — a typed error rather than `unreachable!()` so
                    // a future `Reconnect` implementation that breaks that
                    // invariant fails closed instead of panicking
                    // (`docs/design/testing.md`; `PLAN.md` M3 Step 8's
                    // "recovery == migrated must be impossible on the
                    // reverse leg").
                    let _ = events
                        .send(Err(OpError::new(
                            ErrorCode::Internal,
                            "recovery reported a migrated connection on a route with no \
                             migration",
                        )))
                        .await;
                    return;
                }
                Recovery::NewLeg(new_session, new_attached) => {
                    // Last check before the new leg is installed: a detach
                    // that raced the rebuild must not be answered with a
                    // fresh leg on a session the user has already left.
                    if ctx.finished() {
                        return;
                    }
                    session = new_session;
                    attached = new_attached;
                    continue 'leg;
                }
                // The frontend ended the attach while we were recovering
                // it. Nothing to report: this is the user's own doing.
                Recovery::Abandoned => return,
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
        // Anything at all from the host proves the path carries packets —
        // and a session that is producing output is a session in use, so
        // this is traffic rather than bare liveness.
        watch.traffic();
        if let AttachEvent::InputAck { acked_input_seq } = &event {
            lock(pending).ack(*acked_input_seq);
            // Monotonic: a resumed leg re-acks from the offset the host
            // applied, and a stale ack from the leg that just died must not
            // walk the mark backwards under a waiting detach.
            ctx.applied_input.send_if_modified(|applied| {
                let ahead = *acked_input_seq > *applied;
                if ahead {
                    *applied = *acked_input_seq;
                }
                ahead
            });
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

/// The forward route's [`Reconnect`]: re-dial the peer directly.
///
/// Owns exactly what the forward route's reconnect step needs — the
/// [`Link`] to redial on and, through `ctx.target`, the [`PeerTarget`] to
/// dial — plus the one piece of state that has to survive a cancelled
/// attempt: a redemption [`spawn_reattach`] started that a timed-out
/// caller walked away from. That adoption logic used to live inline in
/// [`recover_attach`]'s loop as a bare `&mut Option<ReattachTask>`; it is
/// moved here verbatim, not rewritten, so the behaviour — a second
/// attempt finds and awaits the *same* in-flight task rather than starting
/// a second redemption of the same single-use resume token
/// (`spawn_reattach`'s own doc) — is unchanged.
struct DialReconnect {
    ctx: Arc<AttachContext>,
    link: Link,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    /// The in-flight redemption, if a previous attempt's deadline stopped
    /// waiting on it without stopping it. A `tokio::sync::Mutex` because
    /// [`Reconnect::reconnect`] has to hold the guard across the `.await`
    /// on the task handle: that is what lets the *outer* `recover()`
    /// timeout cancel this future while leaving the handle in the slot for
    /// the next attempt to pick back up, exactly as the bare `&mut`
    /// binding it replaces did.
    in_flight: tokio::sync::Mutex<Option<ReattachTask>>,
}

impl DialReconnect {
    fn new(
        ctx: Arc<AttachContext>,
        link: Link,
        pending: Arc<std::sync::Mutex<PendingInput>>,
    ) -> Self {
        Self {
            ctx,
            link,
            pending,
            in_flight: tokio::sync::Mutex::new(None),
        }
    }
}

impl Reconnect for DialReconnect {
    fn has_pending(&self) -> bool {
        // Never contended at the point `recover_attach` calls this: it
        // asks at the top of a loop iteration, after any previous
        // `reconnect()` future has either run to completion (which clears
        // the slot below) or been dropped by the outer deadline (which
        // drops this guard along with it). A `try_lock` failure here would
        // itself be the bug, not a legitimate "still pending" answer.
        self.in_flight
            .try_lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn reconnect(&self, last_output_seq: u64) -> ReconnectFuture<'_> {
        Box::pin(async move {
            let mut in_flight = self.in_flight.lock().await;
            let handle = in_flight.get_or_insert_with(|| {
                spawn_reattach(
                    self.ctx.clone(),
                    self.link.clone(),
                    self.pending.clone(),
                    last_output_seq,
                )
            });
            let joined = handle.await;
            // Reached only when the redemption finished, so a
            // cancellation above (the recovery deadline firing while this
            // `.await` was pending) leaves the handle in the slot for the
            // next attempt to adopt.
            *in_flight = None;
            match joined {
                Ok(result) => result,
                Err(err) => Err(ResumeError::Local(OpError::new(
                    ErrorCode::Internal,
                    format!("the resume task did not finish: {err}"),
                ))),
            }
        })
    }
}

/// The reverse route's [`Reconnect`] (`PLAN.md` M3 Step 8,
/// `docs/design/protocol.md` §11-4's Reattach mapping): no dial of its own
/// to make — [`RecoveryLink`]'s own doc explains why there is no
/// `Connection` here to redial — instead it waits for *the target's own*
/// re-dial to land as a new registration `generation` on the daemon
/// (`Listen::control_hub_wait`, via [`dial_reverse_wait`]), then performs
/// §10 Reattach steps 2–5 on the fresh `LOCAL_CONTROL`/`LOCAL_STREAM`
/// conduit pair that registration's handshake hands back.
///
/// Mirrors [`DialReconnect`]'s in-flight adoption (`Self::in_flight`) for
/// the same reason: the wait for a new generation can legitimately run
/// well past a single [`REDIAL_DEADLINE`] window (the target's own
/// backoff climbs to `backoff_max_ms`, default 30 s), so a caller whose
/// attempt deadline fires must only stop *waiting* on the underlying
/// task, never cancel it outright — cancelling it mid-redemption would
/// either orphan a resume token this device can no longer reach (the same
/// "credential critical section" `docs/design/protocol.md` §10 names for
/// the forward route) or, worse, let the *next* attempt spawn a second,
/// concurrent wait racing the first for the same single-use token.
struct LocalReconnect {
    ctx: Arc<AttachContext>,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    /// Same shape and purpose as [`DialReconnect::in_flight`] — see that
    /// field's doc for why a `tokio::sync::Mutex` held across the
    /// `.await` is what lets the outer deadline stop waiting without
    /// stopping the work.
    in_flight: tokio::sync::Mutex<Option<LocalReattachTask>>,
}

impl LocalReconnect {
    fn new(ctx: Arc<AttachContext>, pending: Arc<std::sync::Mutex<PendingInput>>) -> Self {
        Self {
            ctx,
            pending,
            in_flight: tokio::sync::Mutex::new(None),
        }
    }
}

impl Reconnect for LocalReconnect {
    fn has_pending(&self) -> bool {
        // Same reasoning as `DialReconnect::has_pending`: never contended
        // at the point `recover_attach` asks.
        self.in_flight
            .try_lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn reconnect(&self, last_output_seq: u64) -> ReconnectFuture<'_> {
        Box::pin(async move {
            let mut in_flight = self.in_flight.lock().await;
            let handle = in_flight.get_or_insert_with(|| {
                spawn_local_reattach(self.ctx.clone(), self.pending.clone(), last_output_seq)
            });
            let joined = handle.await;
            *in_flight = None;
            match joined {
                Ok(result) => result,
                Err(err) => Err(ResumeError::Local(OpError::new(
                    ErrorCode::Internal,
                    format!("the reverse resume task did not finish: {err}"),
                ))),
            }
        })
    }

    /// The wait [`local_reattach`] measured and stored on
    /// [`ReverseRoute::registration_wait_ms`] before this call's
    /// `reconnect` future resolved — `local_reattach` records it
    /// unconditionally, on both the success and the error path, so by
    /// the time `reconnect` above has returned either way the value is
    /// already there to read. The `u64::MAX` sentinel (no
    /// [`LocalReconnect`] wait has landed on this route yet — the case
    /// where the outer [`REDIAL_DEADLINE`] fired before this attempt's
    /// `local_reattach` got as far as its own store, which can only
    /// happen on the very first attempt) folds to `0` here rather than
    /// leaking a nonsense millisecond count into the telemetry line.
    fn registration_wait_ms(&self) -> u64 {
        let Some(route) = self.ctx.reverse_route.as_ref() else {
            return 0;
        };
        match route
            .registration_wait_ms
            .load(std::sync::atomic::Ordering::Acquire)
        {
            u64::MAX => 0,
            ms => ms,
        }
    }

    /// `ctx.recovery.registration_wait` (the ceiling `local_reattach` asks
    /// the daemon to block for, `RecoveryConfig::registration_wait`'s own
    /// doc) plus [`REDIAL_DEADLINE`] for the resume steps that follow a
    /// registration — exactly the budget split `RecoveryConfig::registration_wait`
    /// promises ("that 2 s budget covers the resume *after* a registration
    /// is observed … while this covers the wait *for* one"). Without this
    /// override `recover`'s default [`REDIAL_DEADLINE`] would cut the wait
    /// itself off after 2 s regardless of `registration_wait`, silently
    /// breaking that promise (`Reconnect::attempt_deadline`'s own doc).
    fn attempt_deadline(&self) -> Duration {
        self.ctx
            .recovery
            .registration_wait
            .saturating_add(REDIAL_DEADLINE)
    }
}

/// A reverse redemption in flight: the [`local_reattach`] the recovery is
/// waiting on — the reverse-route twin of [`ReattachTask`].
type LocalReattachTask =
    tokio::task::JoinHandle<Result<(Session, crate::client::Attached), ResumeError>>;

/// Run [`local_reattach`] on a task of its own — the reverse-route twin of
/// [`spawn_reattach`], for the identical reason: the recovery deadline may
/// stop *waiting* for it without stopping it, so the redemption inside it
/// always runs to `store.put`.
fn spawn_local_reattach(
    ctx: Arc<AttachContext>,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> LocalReattachTask {
    tokio::spawn(async move { local_reattach(&ctx, &pending, last_output_seq).await })
}

/// [`reattach`]'s reverse-route twin: wait for the target's re-registration
/// instead of redialing, then redeem the resume credential, persist its
/// successor, open the data stream and retransmit unacked input — exactly
/// §10 Reattach steps 2–5, unchanged (`PLAN.md` M3 Step 8's "새 resume
/// 로직을 만들지 않는다").
///
/// Only ever invoked through [`spawn_local_reattach`], on a
/// [`RecoveryLink::Reverse`] attach (`recover_attach`'s reverse call site
/// builds a [`LocalReconnect`] only when `ctx.link` already is one) — the
/// `ctx.reverse_route`/`ctx.link` mismatches this function bails out on
/// below are defence in depth against a future call site breaking that
/// pairing, not a path this function's only caller can currently reach.
#[cfg(unix)]
async fn local_reattach(
    ctx: &Arc<AttachContext>,
    pending: &Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> Result<(Session, crate::client::Attached), ResumeError> {
    // Same cheapest-first check `reattach` opens with: a detach that raced
    // the recovery must not spend a wait, a redemption, and a durable
    // write on a session the user already left.
    if ctx.finished() {
        return Err(abandoned());
    }
    let Some(route) = ctx.reverse_route.as_ref() else {
        // `AttachContext::reverse_route` and `ctx.link`'s
        // `RecoveryLink::Reverse` variant are seeded together, from the
        // same `session_attach` reverse arm (`ReverseRoute`'s own doc on
        // `AttachContext`) — never one without the other. Fail closed
        // instead of panicking if that invariant is ever broken.
        return Err(ResumeError::Local(OpError::new(
            ErrorCode::Internal,
            "reverse recovery attempted with no reverse route recorded on this attach",
        )));
    };
    let RecoveryLink::Reverse(kill) = &ctx.link else {
        return Err(ResumeError::Local(OpError::new(
            ErrorCode::Internal,
            "reverse recovery attempted on an attach whose link is not the reverse route",
        )));
    };
    // The generation baseline this wait must land strictly past —
    // `Listen::control_hub_wait`'s own doc on why "still sitting at
    // exactly this generation" is the dead registration, not a live one.
    let known_generation = route.generation.load(std::sync::atomic::Ordering::Acquire);
    let local_route = LocalRoute {
        host: route.host.clone(),
        socket: route.socket.clone(),
    };
    let wait_ms = u32::try_from(ctx.recovery.registration_wait.as_millis()).unwrap_or(u32::MAX);
    let wait_started = std::time::Instant::now();
    let dialed = dial_reverse_wait(&local_route, wait_ms, Some(known_generation)).await;
    // Recorded regardless of outcome: a failed wait still spent this long
    // finding that out, and a campaign that only ever sees successes
    // cannot tell a fast target from a slow one it happened to catch
    // failing for an unrelated reason.
    let waited_ms = u64::try_from(wait_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    route
        .registration_wait_ms
        .store(waited_ms, std::sync::atomic::Ordering::Release);
    let (mut session, peer_fingerprint, generation) = dialed?;
    // Never proceed on the old generation. `control_hub_wait`'s own
    // strictly-greater gate already guarantees this on the daemon side;
    // this is defence in depth on the client side against a future daemon
    // regression silently handing back the very connection whose death
    // this recovery exists to repair.
    if generation <= known_generation {
        return Err(ResumeError::Local(OpError::new(
            ErrorCode::Internal,
            "daemon handed back a registration generation that did not advance past the one \
             this attach already rode",
        )));
    }
    let store = ResumeStore::new(&ctx.paths);
    // `dial_reverse_wait` always reports `Some` (`LocalHelloAck.peer_fingerprint`
    // is not optional on the wire) — handled as fail-closed `None` here
    // anyway rather than unwrapped, exactly as the first-attach path
    // (`Ops::session_attach`) already treats an absent fingerprint: no
    // verified peer means nothing to bind a credential to.
    let Some(peer) = peer_fingerprint else {
        return Err(NoToken::PeerMismatch.into_error(&ctx.session_ref).into());
    };
    let token = match store.take_for(&ctx.session_ref, &peer) {
        Ok(token) => token,
        Err(why) => return Err(why.into_error(&ctx.session_ref).into()),
    };
    let attached = session
        .attach_request(wire::SessionAttach {
            session_id: ctx.session_id.clone(),
            resume_token: token.expose().to_vec(),
            last_output_seq,
            mode: wire::AttachMode::Rw as i32,
            no_steal: ctx.no_steal,
        })
        .await
        .inspect_err(|err| {
            // Same non-distinguishing treatment as every other resume
            // path: whether the session is gone or the credential is
            // stale is deliberately indistinguishable to the peer.
            if let ClientError::Remote { code, .. } = err
                && matches!(code, ErrorCode::AuthFailed | ErrorCode::SessionNotFound)
            {
                let _ = store.forget(&ctx.session_ref);
            }
        })?;
    // Durable before the stream is touched (ADR-0007) — identical to
    // `reattach`'s ordering.
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
        return Err(err.into());
    }
    let mut attached = session.open_attach_stream(attached).await?;
    // Re-assert the last geometry the frontend asked for — identical
    // reasoning to `reattach`.
    let window = *lock(&ctx.window);
    if let Some((cols, rows)) = window {
        attached.resize(cols, rows).await?;
    }
    let replay = lock(pending).rebase(attached.input_from)?.to_vec();
    if !replay.is_empty() {
        attached.send_input(&replay).await?;
    }
    // Last gate before this leg becomes *the* leg: a detach that landed
    // while this was being built must not have its freshly built
    // replacement installed behind it. The successor credential is
    // already durable, so the session stays attachable — only this leg is
    // dropped, exactly as `reattach`'s own closing gate does.
    if ctx.finished() {
        return Err(abandoned());
    }
    // Advance the generation baseline before the old kill switch is
    // silenced, so a concurrent read of `route.generation` (there is
    // none today — only this one `LocalReconnect` ever runs at a time,
    // Step 8's own single-flight design — but this ordering costs
    // nothing and keeps the invariant true even if that ever changes)
    // never observes the new leg installed under the old generation.
    route
        .generation
        .store(generation, std::sync::atomic::Ordering::Release);
    // Only now, with the new leg working, is the old conduit let go —
    // `reattach`'s "only now is the old connection let go" ordering,
    // ported to the reverse route's hard-stop primitive.
    let old_kill = kill.replace(attached.kill.clone());
    old_kill.kill();
    Ok((session, attached))
}

/// Windows twin of [`local_reattach`]: unreachable in practice (no
/// `RecoveryLink::Reverse` attach exists off unix — `Ops::connect_reverse`'s
/// non-unix arm always fails first), kept only so `LocalReconnect`'s
/// `Reconnect` impl compiles on every platform.
#[cfg(not(unix))]
async fn local_reattach(
    ctx: &Arc<AttachContext>,
    _pending: &Arc<std::sync::Mutex<PendingInput>>,
    _last_output_seq: u64,
) -> Result<(Session, crate::client::Attached), ResumeError> {
    let _ = ctx;
    Err(ResumeError::Local(OpError::new(
        ErrorCode::Unsupported,
        "reverse routing (localctl) is not available on this platform",
    )))
}

/// What one recovery produced.
#[allow(clippy::large_enum_variant, reason = "short-lived, moved once")]
enum Recovery {
    /// The connection survived; carry on with the leg that is already
    /// running. Only ever a valid answer to [`LegEnd::PathDead`], because
    /// it hands the caller back the very reader and writer it came in
    /// with.
    SameLeg,
    /// A new connection and a resumed attach.
    NewLeg(Session, crate::client::Attached),
    /// The frontend ended the attach while the recovery was running, so
    /// there is nothing left to recover *to*. Not a failure: nobody is
    /// owed an error for a detach they asked for.
    Abandoned,
    /// Nothing worked inside the budget.
    Failed(OpError),
}

/// Recover one detected path death: migrate if that is enough, otherwise
/// re-dial and resume, retrying up to [`RecoveryConfig::attempts`] times.
///
/// Every attempt is bounded by `reconnect.attempt_deadline()` ([`REDIAL_DEADLINE`]
/// on the forward route, wider on the reverse route — see
/// [`Reconnect::attempt_deadline`]) and recorded on `qsh::recovery` by
/// [`recover`] itself, so a failed attempt is a campaign datapoint rather
/// than a silence.
///
/// `leg_survived` says whether the old leg's streams are still worth
/// keeping ([`LegEnd::leg_survived`]). When they are not, the migration
/// half is skipped outright: probing the connection would answer "alive"
/// and return [`Recovery::SameLeg`], which is a broken reader handed back
/// to a caller that will fail on it again with no backoff.
///
/// `link` is `Some` only on the forward route (`Step 8`: this function is
/// now shared with the reverse route too, unlike before Step 8, when it
/// was forward-only and took a bare `&Link`). `None` disables migration
/// unconditionally, regardless of `leg_survived`/`ctx.recovery.migration`
/// — there is no `Connection` to probe or rebind on the reverse route
/// (`RecoveryLink`'s own doc), so every attempt falls straight through to
/// `reconnect`. In practice `leg_survived` is already always `false` on
/// that route (reverse's [`spawn_watchdog`] never produces
/// [`LegEnd::PathDead`], the only end [`LegEnd::leg_survived`] answers
/// `true` for), so this is defence in depth, not the only thing standing
/// between a reverse leg and a migration attempt.
#[allow(
    clippy::too_many_arguments,
    reason = "one more than before Step 8 (`reconnect`, the `Reconnect` seam the forward call \
              site builds a `DialReconnect` for — bundling it into `ctx` would put a route- \
              specific reconnect step back where `RecoveryLink` already keeps the routes apart)"
)]
async fn recover_attach(
    ctx: &Arc<AttachContext>,
    link: Option<&Link>,
    leg_survived: bool,
    watch: &PathWatch,
    probes: &Arc<tokio::sync::Notify>,
    cursor: &Arc<std::sync::Mutex<OutputCursor>>,
    pumps: &mut LegPumps,
    reconnect: &dyn Reconnect,
) -> Recovery {
    let mut last: Option<OpError> = None;
    for attempt in 0..ctx.recovery.attempts.max(1) {
        // Re-checked on every attempt, not once before the loop: a `~d`
        // that lands mid-recovery must end the attach, not be answered
        // with a fresh connection to the session the user just left.
        if ctx.finished() {
            return Recovery::Abandoned;
        }
        let backoff = RecoveryConfig::backoff(attempt);
        if !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }
        if ctx.finished() {
            return Recovery::Abandoned;
        }
        // Only the first attempt still has a live leg behind it, so only
        // the first can migrate: after a re-dial has been attempted the
        // old connection and its control stream are gone. And only a leg
        // whose streams outlived the failure can be kept at all. `link`
        // being `None` (the reverse route) forces this `false` too — see
        // this function's own doc.
        let live_leg = link.is_some() && leg_survived && attempt == 0 && !reconnect.has_pending();
        let binder = link.map(Link::endpoint);
        let migration = live_leg && ctx.recovery.migration;
        let path_binder: Option<&dyn PathBinder> = if migration {
            binder.as_ref().map(|b| b as &dyn PathBinder)
        } else {
            None
        };
        let last_output_seq = lock(cursor).last_seq();

        let outcome = recover(
            &ctx.session_ref,
            path_binder,
            reconnect.attempt_deadline(),
            || {
                let watch = watch.clone();
                let probes = probes.clone();
                // `None` only when `link` is `None` (the reverse route),
                // in which case `live_leg` is already forced `false`
                // above — so `rtt.is_none()` short-circuits the `&&`
                // below before `probe_alive` would ever need a value.
                let rtt = link.map(|link| link.connection().quinn().stats().path.rtt);
                async move {
                    match rtt {
                        Some(rtt) => live_leg && probe_alive(&watch, &probes, rtt).await,
                        None => false,
                    }
                }
            },
            || async {
                // Past the point of no return for this leg: stop the pumps
                // (which is what releases the command queue and the
                // `Session`) before building a replacement.
                pumps.stop().await;
                reconnect.reconnect(last_output_seq).await
            },
            // Read only after the attempt above has resolved (`recover`'s
            // own doc) — `0` on the forward route, the reverse route's
            // measured re-registration wait on the other
            // (`Reconnect::registration_wait_ms`'s own doc).
            || reconnect.registration_wait_ms(),
        )
        .await;

        match outcome.outcome {
            Ok(Recovered::Migrated) => return Recovery::SameLeg,
            Ok(Recovered::Resumed(leg)) => return Recovery::NewLeg(leg.0, leg.1),
            Err(err) => {
                if ctx.finished() {
                    return Recovery::Abandoned;
                }
                last = Some(map_resume_error(err));
            }
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
async fn probe_alive(watch: &PathWatch, probes: &Arc<tokio::sync::Notify>, rtt: Duration) -> bool {
    // Subscribed **before** the question is asked. The answer can land on
    // a runtime worker before this task is polled again, and a
    // notification edge issued in that window is delivered to nobody — a
    // connection that genuinely survived would then be written off as
    // unmigratable and pay for a full resume it did not need.
    let mut answered = watch.inbound_signal();
    probes.notify_one();
    tokio::time::timeout(migration_probe_budget(rtt), answered.changed())
        .await
        .is_ok()
}

/// A redemption in flight: the [`reattach`] the recovery is waiting on.
type ReattachTask =
    tokio::task::JoinHandle<Result<(Session, crate::client::Attached), ResumeError>>;

/// Run [`reattach`] on a task of its own, so the recovery deadline can stop
/// *waiting* for it without stopping it.
///
/// This is not an optimization, it is the difference between a recovered
/// session and one nobody can ever reach again. The host kills the
/// presented resume token the instant it mints the successor
/// (protocol.md §10 "Rotation"), so there is a window — from "the request
/// is on the wire" to "the successor is on disk" — in which cancelling the
/// client leaves this device holding a credential the host has already
/// retired, for a session that is alive and, because attach is
/// device-bound (`docs/CLI.md` §6.2), that no other device can rescue.
/// A cancelled `.await` on a `JoinHandle` merely detaches the task, so the
/// redemption always runs to `store.put`.
fn spawn_reattach(
    ctx: Arc<AttachContext>,
    link: Link,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> ReattachTask {
    tokio::spawn(async move { reattach(&ctx, &link, &pending, last_output_seq).await })
}

/// Rebuild a dead attach on a fresh connection: dial, redeem the resume
/// credential, persist its successor, open the data stream, and retransmit
/// the input the host never acknowledged (`docs/design/protocol.md` §10).
///
/// `link` is the same forward [`Link`] `drive_attach`'s gate already pulled
/// out of `ctx.link` — never re-derived here, and never itself the reverse
/// route's kind, because [`recover_attach`] (this function's only caller,
/// via [`spawn_reattach`]) is never invoked with one (`RecoveryLink`'s own
/// doc).
async fn reattach(
    ctx: &Arc<AttachContext>,
    link: &Link,
    pending: &Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> Result<(Session, crate::client::Attached), ResumeError> {
    // Cheapest place to notice a detach that raced the recovery: before a
    // socket, a handshake or a `session.attach` the host would audit and
    // answer by moving the writer lease back to a client that has left.
    if ctx.finished() {
        return Err(abandoned());
    }
    // `ctx.target` is `Some` on every forward-route attach (the only kind
    // that ever reaches `reattach` — this fn's own doc), and `None` only
    // on the reverse route, which never resolves one at all
    // (`session_attach`'s own doc). `AttachContext::target`'s doc names
    // this same invariant.
    let target = ctx
        .target
        .as_ref()
        .expect("reattach only runs on the forward route, which always resolves a PeerTarget");
    let (endpoint, connection, mut session) = dial_peer(target).await?;
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
    // A `SIGWINCH` that landed while the path was dead wrote to a stream
    // nobody was reading, and a resize is not part of the un-acked input
    // axis, so nothing else would ever retransmit it. Re-assert the
    // geometry the frontend last asked for before the input replay, so the
    // shell redraws at the size the terminal is actually at.
    let window = *lock(&ctx.window);
    if let Some((cols, rows)) = window {
        attached.resize(cols, rows).await?;
    }
    // The host's axis for this attach starts at what it actually applied on
    // the stream we lost, so the tail it never saw is retransmitted — and
    // nothing it *did* see is sent twice (protocol.md §10-5).
    let replay = lock(pending).rebase(attached.input_from)?.to_vec();
    if !replay.is_empty() {
        attached.send_input(&replay).await?;
    }
    // Last gate before the new connection becomes *the* connection: a
    // detach that landed while this was being built must not have its
    // freshly dialed replacement installed behind it. The successor
    // credential is already durable, so the session stays attachable — it
    // is only this leg that is dropped.
    if ctx.finished() {
        connection.close(0, b"detached");
        endpoint.wait_idle().await;
        return Err(abandoned());
    }
    // Only now, with the new leg working, is the old connection let go.
    let (old_endpoint, old_connection) = link.replace(endpoint, connection);
    old_connection.close(0, b"superseded");
    drop(old_endpoint);
    Ok((session, attached))
}

/// The attach ended under a recovery that was still running.
fn abandoned() -> ResumeError {
    ResumeError::Local(OpError::new(
        ErrorCode::ConnectionFailed,
        "the attach was ended while its path was being recovered",
    ))
}

fn map_resume_error(err: ResumeError) -> OpError {
    match err {
        ResumeError::Local(err) => err,
        ResumeError::Client(err) => map_client_error(err),
        ResumeError::Deadline(deadline) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!(
                "the session's path died and was not recovered within {} ms",
                deadline.as_millis()
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
    ctx: Arc<AttachContext>,
    events: tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    let finished = &ctx.finished;
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
                // Bound the guard to this statement: the refusal below
                // awaits, and a `std` guard held across an await is not
                // `Send`.
                let refused = lock(&pending).push(&data).err();
                if let Some(err) = refused {
                    // protocol.md §10-5 is explicit that overrunning the
                    // 64 KiB cap is an **error**, not silent buffering.
                    // These bytes cannot be replayed across a break, so a
                    // `warn` on stderr would be the user believing they
                    // typed something the shell will never see — under a
                    // raw-mode TUI, invisibly. Say so on the event stream
                    // and stop writing.
                    //
                    // Only this leg's send half stops: the output the user
                    // is owed keeps arriving, and a recovery — which is
                    // what an unacking host usually means — spawns a fresh
                    // pump against a host that is acking again.
                    tracing::warn!(%err, "the un-acked input buffer is full");
                    let _ = events.send(Err(map_resume_error(err))).await;
                    return;
                }
                writer.send_input(&data).await.map(|_| ())
            }
            AttachCommand::Resize { cols, rows } => {
                // Remembered before it is written: a resize is not on the
                // input axis, so a resume has nothing to retransmit it
                // from unless the last size was kept somewhere.
                *lock(&ctx.window) = Some((cols, rows));
                writer.resize(cols, rows).await
            }
            AttachCommand::Detach(ack) => {
                // Everything queued ahead of the detach has been written by
                // the time we get here, so this offset covers every byte
                // the frontend handed us. Mark the attach deliberately over
                // (the supervisor must not recover it), FIN the send half,
                // and wait for the host to say the child ran them.
                finished.store(true, std::sync::atomic::Ordering::Release);
                let target = writer.input_seq();
                writer.finish();
                let _ = ack.send(await_applied(&ctx.applied_input, target).await);
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

/// Wait until the host has acknowledged applying every byte up to `target`,
/// or [`DETACH_FLUSH`] passes.
///
/// Returns immediately when the mark is already there, which is the usual
/// case for a `~d` typed on its own line: the escape follows a CR the host
/// acked while the user was still reading the prompt.
async fn await_applied(applied: &tokio::sync::watch::Sender<u64>, target: u64) -> DetachFlush {
    let mut mark = applied.subscribe();
    let reached = tokio::time::timeout(DETACH_FLUSH, mark.wait_for(|applied| *applied >= target));
    match reached.await {
        Ok(Ok(_)) => DetachFlush::Applied,
        // The sender lives in the attach context this task holds, so a
        // closed channel is not reachable; a timeout is, and both mean the
        // same thing to the user.
        Ok(Err(_)) | Err(_) => DetachFlush::Unconfirmed,
    }
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
    session_id: String,
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
                match message {
                    // The answer to our own liveness probe. Proof the path
                    // carries packets, and nothing more — counting it as
                    // activity would let the watchdog hold itself inside
                    // the active window forever and the idle cadence would
                    // never be reached on a healthy path.
                    ControlIn::Pong => watch.inbound(),
                    ControlIn::Ping { request_id } => {
                        watch.traffic();
                        if session.send_pong(request_id).await.is_err() {
                            return;
                        }
                    }
                    // Unreachable in practice on a forward attach (the
                    // host never sends a request back to its client), but
                    // must still be answered rather than dropped — the
                    // same `UNSUPPORTED`/zero-resource contract
                    // `reverse/listen.rs` relies on for the reverse
                    // direction (`ControlIn::Request`'s docs).
                    ControlIn::Request { request_id } => {
                        watch.traffic();
                        if session.reject_unsupported(request_id).await.is_err() {
                            return;
                        }
                    }
                    // `Exited` also arrives as a data frame, which is the
                    // authoritative copy; emitting both would duplicate a
                    // terminal event in the JSONL stream.
                    ControlIn::Event(event) => {
                        watch.traffic();
                        // Defensive on a forward attach today (one
                        // connection per session, so the peer only ever
                        // has this session's events to send) and load-bearing
                        // the moment this pump runs over a shared
                        // `ControlLink::Local` control stream, where a
                        // `session.writer_changed` is broadcast to every
                        // conduit of the host regardless of which session
                        // it names (`crate::localctl::mux::ControlMux::route_event`).
                        // `docs/design/protocol.md` §11-3's own rule:
                        // "구독자 쪽 클라이언트도 낯선 session_id의 event는
                        // 방어적으로 무시한다" — without this, an event for
                        // a different session would be re-stamped with
                        // *this* session's `session_ref` and emitted as a
                        // fabricated `qsh.event/v1` line (adversarial
                        // review finding).
                        if event.session_id != session_id {
                            continue;
                        }
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
///
/// `pub(crate)` only so the sibling `crate::ops::tunnel` module can hold
/// one for a foreground tunnel (`PLAN.md` M4 Step 3); nothing outside
/// `crate::ops` can name it.
pub(crate) struct Connected {
    /// `None` only between [`Connected::close`] and the drop.
    runtime: Option<tokio::runtime::Runtime>,
    /// The endpoint and connection currently carrying this attach — the
    /// forward route's swappable pair — or, on the reverse route, the
    /// facts a `LOCAL_CONTROL` handshake produced instead of one
    /// (`PLAN.md` M3 Step 6).
    link: ConnectedLink,
    /// `None` only after the session was consumed by the teardown.
    session: Option<Session>,
}

/// Which of [`PeerRoute`](crate::ops::PeerRoute)'s two carriers this
/// [`Connected`] rides.
enum ConnectedLink {
    /// The forward route: a real, swappable QUIC endpoint/connection pair
    /// (recovery-capable — see [`Link`]'s own doc).
    Forward(Link),
    /// The reverse route: relayed through this machine's `qsh listen`
    /// daemon over a `LOCAL_CONTROL` conduit. There is no separate
    /// endpoint/connection for this leg to hold — [`Connected::close`]'s
    /// `session.close()` alone tears the conduit down — so this variant
    /// carries only what [`Connected::peer_fingerprint`] needs: the
    /// `LocalHelloAck.peer_fingerprint` this connection's own handshake
    /// reported (`None` only if the daemon's ack omitted it, which never
    /// happens on a live registration but is not this type's job to
    /// assume).
    // Only ever constructed by `connect_reverse`'s `#[cfg(unix)]` body
    // (localctl/UDS is unix-only) in the non-test lib build — the
    // Windows twin returns `Err` before ever reaching a `Connected`, so
    // this variant is genuinely unconstructed there outside `#[cfg(test)]`
    // (where a unit test builds it directly to pin
    // `Connected::peer_fingerprint`'s reverse-leg behavior).
    #[cfg_attr(not(unix), allow(dead_code))]
    Reverse {
        peer_fingerprint: Option<String>,
        /// This machine's resident `qsh listen` daemon's localctl socket
        /// and the registered host alias this leg is for — exactly
        /// [`LocalRoute`]'s two fields, carried forward from
        /// [`Ops::connect_reverse`] rather than re-resolved, because
        /// re-resolving could name a *different* daemon/registration than
        /// the one this specific `Connected`'s `LOCAL_CONTROL` conduit is
        /// actually talking to. [`Connected::reverse_route`] is the only
        /// reader — `crate::ops::tunnel`'s route-aware `tunnel_open`
        /// (`PLAN.md` M4 Step 5 PR 5b), which needs both to open the
        /// per-connection `LOCAL_STREAM` conduits
        /// [`crate::tunnel::LocalForwardHandle::start_reverse`] and
        /// [`crate::tunnel::remote::RemoteForwardAcceptor::spawn_reverse`]
        /// take.
        socket: std::path::PathBuf,
        host: String,
    },
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
    ///
    /// `pub(crate)`, not private: `crate::ops::tunnel`'s `-R` requester leg
    /// (`PLAN.md` M4 Step 4) needs the same one-request-closure shape
    /// `session_open`/`attach_request`/etc. already use here, for
    /// `Session::rfwd_open`/`rfwd_close` — a sibling `ops` module, not a
    /// descendant of this one, so plain module-private is not enough.
    pub(crate) fn run<T, F>(&mut self, f: F) -> Result<T, OpError>
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
    /// own tasks on it (the attach driver, and a `-L` forward's accept
    /// loop).
    pub(crate) fn runtime(&self) -> &tokio::runtime::Runtime {
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
    ///
    /// Forward: read straight off this connection's own TLS-verified peer.
    /// Reverse: the `LocalHelloAck.peer_fingerprint` this leg's own
    /// handshake reported — the daemon's TLS-verified peer for *this*
    /// registration, which is the ADR-0007 presentation-condition input on
    /// that leg since the CLI process is not itself a TLS endpoint on the
    /// underlying connection (`PLAN.md` M3 Step 6).
    fn peer_fingerprint(&self) -> Option<String> {
        match &self.link {
            ConnectedLink::Forward(link) => link
                .connection()
                .peer_fingerprint()
                .map(|fp| fp.to_string()),
            ConnectedLink::Reverse {
                peer_fingerprint, ..
            } => peer_fingerprint.clone(),
        }
    }

    /// The QUIC connection underneath, on the forward route only.
    ///
    /// `None` on the reverse route, where this process is not a QUIC
    /// endpoint at all — its peer traffic is relayed by the resident `qsh
    /// listen` daemon over a `LOCAL_STREAM` conduit
    /// ([`ConnectedLink::Reverse`]). A caller that needs a raw byte pipe
    /// of its own (a tunnel splice) has to refuse there rather than
    /// improvise, which is what `PLAN.md` M4 Step 5 exists to fix.
    pub(crate) fn connection(&self) -> Option<qsh_transport::Connection> {
        match &self.link {
            ConnectedLink::Forward(link) => Some(link.connection()),
            ConnectedLink::Reverse { .. } => None,
        }
    }

    /// The reverse-route carrier [`crate::ops::tunnel`]'s route-aware
    /// `tunnel_open` needs to open its own `LOCAL_STREAM` conduits
    /// (`PLAN.md` M4 Step 5 PR 5b) — this machine's resident `qsh listen`
    /// daemon socket and the registered host alias, i.e. exactly
    /// [`ConnectedLink::Reverse`]'s two extra fields. `None` on the
    /// forward route (the mirror image of [`Self::connection`] being
    /// `None` on the reverse route) — a caller branches on one or the
    /// other, never both.
    #[cfg(unix)]
    pub(crate) fn reverse_route(&self) -> Option<(&std::path::Path, &str)> {
        match &self.link {
            ConnectedLink::Forward(_) => None,
            ConnectedLink::Reverse { socket, host, .. } => Some((socket.as_path(), host.as_str())),
        }
    }

    /// Wait until this connection ends, and say why — the one signal
    /// [`crate::ops::tunnel::TunnelHold::hold`] blocks on for as long as
    /// the tunnel it holds is alive (`docs/CLI.md` §6.14).
    ///
    /// Forward route: [`qsh_transport::Connection::closed`], the QUIC
    /// connection's own close future. Reverse route: there is no such
    /// object on this side ([`Self::connection`]'s own doc), so this
    /// drives [`Session::next_control`] in a loop instead — `Ok(None)` is
    /// the daemon ending the `LOCAL_CONTROL` conduit, which is also how
    /// this side learns its reverse registration died
    /// (`crate::client::link::ControlLink::recv`'s own doc,
    /// `docs/design/protocol.md` §11-3), and any `Err` is the conduit
    /// itself failing. `next_control` performs no write (unlike
    /// [`Session::next_event`], which answers a peer `Ping` inline), so
    /// this is safe to run with nothing else touching the session — which
    /// is exactly `tunnel_open`'s reverse-route `Connected`, since it is
    /// never attached to any session and issues only the occasional
    /// `RfwdOpen`/`RfwdClose` request on it. A message that is not a
    /// clean end or an error (there should never legitimately be one on
    /// this bare value-op connection) is simply discarded and the loop
    /// keeps waiting — the same "nothing here to answer" posture every
    /// other bare value-op `Connected` already has, forward or reverse.
    pub(crate) async fn wait_dead(&mut self) -> OpError {
        match &self.link {
            ConnectedLink::Forward(link) => {
                let err = link.connection().closed().await;
                OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("the connection carrying this tunnel closed: {err}"),
                )
            }
            ConnectedLink::Reverse { .. } => {
                let Some(session) = self.session.as_mut() else {
                    return OpError::new(
                        ErrorCode::ConnectionFailed,
                        "the reverse connection carrying this tunnel is already closed",
                    );
                };
                loop {
                    match session.next_control().await {
                        Ok(None) => {
                            return OpError::new(
                                ErrorCode::ConnectionFailed,
                                "the reverse connection carrying this tunnel closed",
                            );
                        }
                        Ok(Some(_)) => continue,
                        Err(err) => {
                            return OpError::new(
                                ErrorCode::ConnectionFailed,
                                format!(
                                    "the reverse connection carrying this tunnel failed: {err}"
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    /// Close the control stream and the connection, then let the QUIC close
    /// frames drain (forward route) — or just the control stream (reverse
    /// route: there is no separate connection here to close, and no QUIC
    /// close frame of this process's own to drain).
    pub(crate) fn close(mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let session = self.session.take();
        match &self.link {
            ConnectedLink::Forward(link) => {
                let (endpoint, connection) = link.get();
                runtime.block_on(async move {
                    if let Some(session) = session {
                        session.close();
                    }
                    connection.close(0, b"done");
                    drop(connection);
                    endpoint.wait_idle().await;
                });
            }
            ConnectedLink::Reverse { .. } => {
                runtime.block_on(async move {
                    if let Some(session) = session {
                        session.close();
                    }
                });
            }
        }
        runtime.shutdown_timeout(CLOSE_DRAIN);
    }
}

impl Drop for Connected {
    fn drop(&mut self) {
        // `close()` already took the runtime on the normal path; this is the
        // panic / early-return path.
        if let Some(runtime) = self.runtime.take() {
            self.session.take();
            if let ConnectedLink::Forward(link) = &self.link {
                link.connection().close(0, b"done");
            }
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

    /// The un-acked cap is a *contract* (`protocol.md` §10-5: "초과 시
    /// 조용히 쌓지 않고 오류"), and the driver now surfaces it on the event
    /// stream instead of logging it away. This pins the code the frontend
    /// sees, because a `warn` and a `RESOURCE_EXHAUSTED` are the same
    /// number of lines of source and very different products.
    #[test]
    fn a_full_un_acked_buffer_is_resource_exhausted_not_a_log_line() {
        let mut pending = PendingInput::new(0);
        pending
            .push(&vec![b'x'; crate::client::reconnect::UNACKED_INPUT_MAX])
            .expect("the cap itself fits");
        let err = pending
            .push(b"one byte too many")
            .expect_err("over the cap");
        assert!(matches!(err, ResumeError::UnackedInputOverflow { .. }));
        let mapped = map_resume_error(err);
        assert_eq!(mapped.code, ErrorCode::ResourceExhausted);
        // The message names the limit, so a user who pasted too much can
        // tell this from a host that ran out of memory.
        assert!(mapped.message.contains("un-acked"), "{:?}", mapped.message);
    }

    /// Migration is an answer to a *path* that died, never to a stream
    /// that broke. The distinction is load-bearing: `probe_alive` asks the
    /// connection, and a host that resets `SESSION_DATA` on a live
    /// connection (`RESET_CODE_SESSION_CONFLICT`, `RESET_CODE_BAD_HEADER`)
    /// still answers `Ping`. Classifying that as migratable returns
    /// `Recovery::SameLeg` with the same broken reader, which the driver
    /// re-reads with zero backoff — a hot loop that emits a `migrated`
    /// record per turn and never tells the frontend anything.
    #[test]
    fn a_broken_stream_is_never_migratable_however_healthy_the_connection() {
        assert!(
            LegEnd::PathDead.leg_survived(),
            "a dead path leaves usable streams behind; that is what migration rescues"
        );
        assert!(
            !LegEnd::Broken(ClientError::Protocol("reset".into())).leg_survived(),
            "a broken data stream must be rebuilt, not migrated onto"
        );
        // The two endings that never reach recovery at all are still
        // classified conservatively, so a future caller cannot read a
        // survival out of them.
        assert!(!LegEnd::Ended.leg_survived());
        assert!(!LegEnd::Gone.leg_survived());
    }

    /// A detach that lands mid-recovery is the user's own doing, so it ends
    /// the attach rather than producing an error the frontend has to
    /// render — and it must not look like a failed recovery either.
    #[test]
    fn an_abandoned_recovery_is_not_a_wire_failure() {
        assert_eq!(
            map_resume_error(abandoned()).code,
            ErrorCode::ConnectionFailed
        );
    }

    /// The migration probe is worth one round trip, not a constant: on a
    /// LAN a fixed 300 ms was 600 ms of a 2 s budget spent learning
    /// nothing.
    #[test]
    fn the_migration_probe_scales_with_the_path() {
        assert_eq!(
            migration_probe_budget(Duration::from_micros(200)),
            MIGRATION_PROBE_MIN,
            "a fast path still gets a floor, for scheduling"
        );
        assert_eq!(
            migration_probe_budget(Duration::from_millis(100)),
            Duration::from_millis(200)
        );
        assert_eq!(
            migration_probe_budget(Duration::from_secs(5)),
            MIGRATION_PROBE_MAX,
            "and it is capped: the deadline it is spent from is 2 s"
        );
    }

    /// `Connected::peer_fingerprint` on the reverse leg must be exactly
    /// the value that leg's own `LOCAL_CONTROL` handshake reported —
    /// never re-derived from a QUIC connection this process does not
    /// itself hold (ADR-0007's presentation condition, `PLAN.md` M3
    /// Step 6). `dial_reverse` is what actually produces that value from
    /// a live `LocalHelloAck` (exercised end-to-end by
    /// `crate::client::link`'s and `crate::localctl::client`'s own
    /// handshake tests); this pins the narrower claim that
    /// `ConnectedLink::Reverse`'s carried value round-trips through
    /// `peer_fingerprint()` unchanged, with no runtime/session needed to
    /// observe it.
    #[test]
    fn connected_peer_fingerprint_on_the_reverse_leg_is_exactly_the_acks_value() {
        let connected = Connected {
            runtime: None,
            link: ConnectedLink::Reverse {
                peer_fingerprint: Some("sha256:deadbeefdeadbeefdeadbeefdeadbeef".to_string()),
                socket: std::path::PathBuf::from("/tmp/qsh-test.sock"),
                host: "box".to_string(),
            },
            session: None,
        };
        assert_eq!(
            connected.peer_fingerprint(),
            Some("sha256:deadbeefdeadbeefdeadbeefdeadbeef".to_string())
        );

        let no_fingerprint = Connected {
            runtime: None,
            link: ConnectedLink::Reverse {
                peer_fingerprint: None,
                socket: std::path::PathBuf::from("/tmp/qsh-test.sock"),
                host: "box".to_string(),
            },
            session: None,
        };
        assert_eq!(no_fingerprint.peer_fingerprint(), None);
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

    /// `drive_attach`'s reverse gate with recovery turned **off**
    /// (`RecoveryLink`'s own doc): a real reverse `Session`/`Attached`
    /// pair whose `LOCAL_STREAM` data conduit breaks (not a clean close —
    /// a mid-frame EOF, so `read_leg` reports [`LegEnd::Broken`]) must end
    /// the attach with one typed [`OpError`] on the events channel and
    /// *return*, never call [`recover_attach`], never hang. Before Step 8
    /// this was true unconditionally — the reverse route had no
    /// `Reconnect` at all — so this test used to leave
    /// `ctx.recovery.enabled` at its default `true` on purpose (nothing
    /// consumed it). Since Step 8 wired `RecoveryLink::Reverse` through
    /// the same [`recover_attach`] the forward route uses (via
    /// [`LocalReconnect`]), that default would now attempt a real
    /// recovery instead of ending the attach immediately, so this test
    /// sets `enabled: false` explicitly to keep testing exactly what its
    /// name says: the immediate, no-recovery fail-closed path. The
    /// recovery-**enabled** counterpart —
    /// [`reverse_leg_link_death_with_recovery_exhausted_ends_the_attach_with_a_typed_error_never_a_panic_or_hang`]
    /// — proves the same typed-error/never-hang property once a real
    /// `LocalReconnect` attempt is in play and exhausts its budget.
    #[cfg(unix)]
    #[tokio::test]
    async fn reverse_leg_link_death_with_recovery_disabled_ends_the_attach_with_a_typed_error_never_a_panic_or_hang()
     {
        use qsh_proto::local::{LocalHello, LocalHelloAck, LocalResponse, local_response};
        use tokio::net::UnixListener;

        use crate::localctl::frame::LocalConduit;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("drive-attach-reverse-death.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut control = LocalConduit::new(stream);
            let _hello: LocalHello = control.recv().await.unwrap().unwrap();
            control
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();

            let (stream, _addr) = listener.accept().await.unwrap();
            let mut data = LocalConduit::new(stream);
            let _hello: LocalHello = data.recv().await.unwrap().unwrap();
            data.send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();
            let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
            let (mut raw, _prefetched) = data.into_raw();
            // A declared frame length with no payload behind it at
            // all — a broken conduit, not a clean end: `DataRecvHalf`
            // reports this as `ConnectionFailed`, never `Ok(None)`.
            use tokio::io::AsyncWriteExt as _;
            raw.write_all(&[0, 0, 0, 50]).await.unwrap();
            drop(raw);
            // Keep the control conduit's peer alive for the rest of the
            // test — nothing on it is expected to arrive, but dropping it
            // early would end the control leg too and confound which leg
            // `drive_attach` actually reported the error for.
            std::future::pending::<()>().await
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let mut session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            sock.clone(),
            handshake.peer_fingerprint,
            handshake.generation,
        );
        let attached = session
            .open_attach_stream(wire::SessionAttached {
                ticket: vec![1],
                new_resume_token: Vec::new(),
                replay_from: 0,
                writer_lease: true,
                expires_at: String::new(),
                input_seq: 0,
            })
            .await
            .unwrap();

        let link = RecoveryLink::Reverse(ReverseKill::new(attached.kill.clone()));
        let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
        let (applied_input, _) = tokio::sync::watch::channel(0u64);
        let ctx = Arc::new(AttachContext {
            target: None,
            host: "phone".to_string(),
            session_id: "01REVERSEDEATH".to_string(),
            session_ref: "phone/01REVERSEDEATH".to_string(),
            paths,
            no_steal: false,
            link,
            window: Arc::new(std::sync::Mutex::new(None)),
            // Recovery off — this test proves the immediate fail-closed
            // path, not `LocalReconnect` (this fn's own doc).
            recovery: RecoveryConfig {
                enabled: false,
                ..RecoveryConfig::default()
            },
            finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            applied_input,
            reverse_route: None,
        });
        let (_commands_tx, commands_rx) = tokio::sync::mpsc::channel(4);
        let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(4);

        tokio::time::timeout(
            Duration::from_secs(10),
            drive_attach(ctx, session, attached, commands_rx, events_tx),
        )
        .await
        .expect("drive_attach must return promptly on a broken reverse leg, not hang");

        let reported = events_rx
            .recv()
            .await
            .expect("drive_attach must report the broken leg on the events channel");
        assert!(
            reported.is_err(),
            "a broken reverse-leg link must be reported as an error, got {reported:?}"
        );

        daemon.abort();
    }

    /// `drive_attach`'s reverse gate with recovery turned **on** (Step 8):
    /// the counterpart to
    /// [`reverse_leg_link_death_with_recovery_disabled_ends_the_attach_with_a_typed_error_never_a_panic_or_hang`].
    /// Same broken `LOCAL_STREAM` data conduit, but this time
    /// `ctx.recovery.enabled` is `true`, so `drive_attach` now builds a
    /// [`LocalReconnect`] and drives it through [`recover_attach`]. The
    /// fake daemon in this test never accepts a third UDS connection (it
    /// blocks in `std::future::pending()` after handing out the first
    /// attach's control/data conduits), so the wait for a new-generation
    /// registration never resolves — with `attempts: 1` this exhausts
    /// [`recover_attach`]'s single attempt inside one [`REDIAL_DEADLINE`]
    /// window (~2 s of real wall-clock time, the same bound the forward
    /// route's own unit tests already accept — `docs/design/testing.md`'s
    /// `sleep()`-free discipline binds the PR-gate chaos/acceptance
    /// suites, not this crate's internal unit tests) and the attach still
    /// ends with exactly one typed [`OpError`] on the events channel,
    /// never a panic, never `recovery == "migrated"` (`RecoveryLink`'s own
    /// doc — there is no `Link` on this route for `recover_attach` to
    /// reach for), never a hang past the outer 10 s test timeout.
    #[cfg(unix)]
    #[tokio::test]
    async fn reverse_leg_link_death_with_recovery_exhausted_ends_the_attach_with_a_typed_error_never_a_panic_or_hang()
     {
        use qsh_proto::local::{LocalHello, LocalHelloAck, LocalResponse, local_response};
        use tokio::net::UnixListener;

        use crate::localctl::frame::LocalConduit;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("drive-attach-reverse-recovery.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut control = LocalConduit::new(stream);
            let _hello: LocalHello = control.recv().await.unwrap().unwrap();
            control
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();

            let (stream, _addr) = listener.accept().await.unwrap();
            let mut data = LocalConduit::new(stream);
            let _hello: LocalHello = data.recv().await.unwrap().unwrap();
            data.send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();
            let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
            let (mut raw, _prefetched) = data.into_raw();
            use tokio::io::AsyncWriteExt as _;
            raw.write_all(&[0, 0, 0, 50]).await.unwrap();
            drop(raw);
            // No third accept, ever — a `LocalReconnect` wait against this
            // socket blocks until this test's own deadline cancels it.
            std::future::pending::<()>().await
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
            .await
            .unwrap();
        let mut session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            sock.clone(),
            handshake.peer_fingerprint,
            handshake.generation,
        );
        let attached = session
            .open_attach_stream(wire::SessionAttached {
                ticket: vec![1],
                new_resume_token: Vec::new(),
                replay_from: 0,
                writer_lease: true,
                expires_at: String::new(),
                input_seq: 0,
            })
            .await
            .unwrap();

        let link = RecoveryLink::Reverse(ReverseKill::new(attached.kill.clone()));
        let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
        let (applied_input, _) = tokio::sync::watch::channel(0u64);
        let ctx = Arc::new(AttachContext {
            target: None,
            host: "phone".to_string(),
            session_id: "01REVERSERECOVERY".to_string(),
            session_ref: "phone/01REVERSERECOVERY".to_string(),
            paths,
            no_steal: false,
            link,
            window: Arc::new(std::sync::Mutex::new(None)),
            // A single attempt is enough to prove "exhausted -> typed
            // error, never a hang" without the test paying for
            // `RecoveryConfig::default()`'s three attempts' worth of
            // `REDIAL_DEADLINE` windows.
            recovery: RecoveryConfig {
                enabled: true,
                attempts: 1,
                migration: false,
                registration_wait: Duration::from_millis(50),
                ..RecoveryConfig::default()
            },
            finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            applied_input,
            reverse_route: Some(ReverseRoute {
                host: "phone".to_string(),
                socket: sock.clone(),
                // Matches the ack's `generation: 1` above: `LocalReconnect`
                // must wait for something strictly greater, which this
                // fake daemon never produces.
                generation: std::sync::atomic::AtomicU64::new(1),
                registration_wait_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
            }),
        });
        let (_commands_tx, commands_rx) = tokio::sync::mpsc::channel(4);
        let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(4);

        tokio::time::timeout(
            Duration::from_secs(10),
            drive_attach(ctx, session, attached, commands_rx, events_tx),
        )
        .await
        .expect(
            "drive_attach must return once LocalReconnect exhausts its attempts, not hang \
             forever",
        );

        let reported = events_rx
            .recv()
            .await
            .expect("drive_attach must report the exhausted recovery on the events channel");
        assert!(
            reported.is_err(),
            "an exhausted reverse recovery must be reported as an error, got {reported:?}"
        );

        daemon.abort();
    }
}
