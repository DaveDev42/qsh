//! `session.*` value operations — client side (`docs/CLI.md` §6.2–6.7):
//! resolve the host through the trust store, dial with mutual TLS,
//! negotiate, send one control request, and assemble the `qsh.cli/v1`
//! payload. Every session is addressed by its opaque `session_ref`
//! (`<host-alias>/<session_id>`, ADR-0007), which only this module
//! assembles and parses.
//!
//! The stream operations live here too: [`Ops::session_reader`] is the
//! single cursor-pull primitive (`--wait`, `--follow`, and a long-running
//! external process's, e.g. an agent tool, long-poll all go through it)
//! and [`Ops::session_attach`] is the one
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
use crate::hosts::HostsFile;
use crate::ops::exec::{map_client_error, map_dial_error};
use crate::ops::{LocalRoute, OpError, Operation, Ops, PeerRoute, PeerTarget};
use crate::resume::{NoToken, ResumeStore, StoredToken};

mod attach;
mod context;
mod drive;
mod link;
mod pump;
mod reader;
mod reconnect;
mod recovery;

pub use attach::{AttachHandle, DetachFlush, SessionAttachOp, SessionAttachStream};
pub(crate) use link::Connected;
pub use reader::SessionReader;

use attach::{AttachCommand, AttachStop, RenewalSchedule};
use context::{
    AbortOnDrop, AttachContext, LegEnd, LegPumps, Pump, RecoveryLink, ReverseKill, ReverseRoute,
};
use drive::drive_attach;
use link::{ConnectedLink, Link};
use pump::{attach_event_json, pump_attach_control, pump_attach_input};
use reader::{dial_peer, forget_if_closed};
#[cfg(unix)]
use reader::{dial_reverse, dial_reverse_wait};
use reconnect::{DialReconnect, LocalReconnect};
#[cfg(any(unix, test))]
use recovery::abandoned;
use recovery::{ReattachTask, Recovery, lock, map_resume_error, recover_attach, spawn_reattach};

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
    /// clamp). Unread on the forward route: `DialReconnect` never
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
        self.session_open_gated(req, false)
    }

    /// [`Self::session_open`]'s twin for the interactive `qsh [user@]host
    /// -D spec` form (ADR-0020 decisions 2–3): the same `session.open`, but
    /// gated on the connected route's `dial-filter.v1` capability *before*
    /// `SessionOpen` is sent, on both routes. Exists so `-D`'s connect-
    /// side entry point (`crate::tui`'s interactive driver, outside this
    /// crate) never opens a session on the target and then discovers the
    /// capability is missing — the ordering
    /// [`crate::ops::session::SessionAttachStream::open_dynamic_forwards`]
    /// cannot give it, since that call only runs *after* the attach that
    /// created the session already exists. `-L`-only and plain interactive
    /// sessions are unaffected: they call [`Self::session_open`] instead,
    /// which requires nothing extra.
    pub fn session_open_for_dynamic(
        &self,
        req: SessionOpenReq,
    ) -> Result<SessionOpenData, OpError> {
        self.session_open_gated(req, true)
    }

    /// The shared body of [`Self::session_open`]/
    /// [`Self::session_open_for_dynamic`]: connect, optionally require
    /// `dial-filter.v1` on whichever route connected, and only then send
    /// `SessionOpen` — the capability gate strictly precedes the one
    /// resource this op creates (`docs/PRD.md` §9), exactly the same
    /// "connect, gate, only then act" order `crate::ops::tunnel::Ops::
    /// tunnel_dynamic_with_connected` uses for the standalone `-D` form.
    fn session_open_gated(
        &self,
        req: SessionOpenReq,
        require_dial_filter: bool,
    ) -> Result<SessionOpenData, OpError> {
        let host = req.host.clone();
        let user = self.resolve_user_hint(&host, req.user)?;
        let msg = wire::SessionOpen {
            argv: req.argv,
            env: req.env.into_iter().map(|e| (e.name, e.value)).collect(),
            term: req.term.unwrap_or_default(),
            cols: req.cols.unwrap_or(0),
            rows: req.rows.unwrap_or(0),
            user,
        };
        // Not `call`: the resume credential is bound to the peer that
        // issued it (protocol.md §10-2), so the fingerprint of *this*
        // connection has to be read before the connection is torn down.
        let conn = self.connect(&host)?;
        self.session_open_gated_with_connected(conn, msg, &host, require_dial_filter)
    }

    /// The post-connect half of [`Self::session_open_gated`], split out as
    /// a test seam mirroring [`crate::ops::tunnel::Ops::
    /// tunnel_dynamic_with_connected`]'s own doc: a test can hand this a
    /// [`Connected`] built directly ([`Connected::for_test_forward`]/
    /// [`Connected::for_test_reverse`]) carrying a fabricated negotiated
    /// capability set, to exercise the capability gate — and confirm no
    /// `SessionOpen` is ever sent when it fails closed — without a real
    /// peer `Hello`/`LocalHelloAck` answering a dial.
    fn session_open_gated_with_connected(
        &self,
        mut conn: Connected,
        msg: wire::SessionOpen,
        host: &str,
        require_dial_filter: bool,
    ) -> Result<SessionOpenData, OpError> {
        if require_dial_filter {
            let is_reverse = conn.connection().is_none();
            if let Err(err) =
                crate::ops::tunnel::require_dial_filter_capability(conn.capabilities(), is_reverse)
            {
                conn.close();
                return Err(err);
            }
        }
        let peer = conn.peer_fingerprint();
        let opened = conn.run(move |s| Box::pin(s.session_open(msg)));
        conn.close();
        let opened = opened?;
        let session_ref = make_session_ref(host, &opened.session_id);
        self.remember_resume(
            &session_ref,
            host,
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

    /// Fill in `SessionOpen.user` (`docs/CLI.md` §7): an explicit hint from
    /// the caller — `user@host`/a long-running external process's (e.g. an
    /// agent tool) `user` argument — always wins;
    /// otherwise `hosts.toml`'s `user` entry for `host` fills in as a
    /// default, if it set a non-empty one (`PLAN.md` M7 Step 3, ssh_config
    /// `User`-directive-like: a per-name default a caller can still
    /// override on the command line).
    ///
    /// **Still never an identity or an account selector** — exactly the
    /// same assertion hint `docs/CLI.md` §7 already documents, just with a
    /// second possible source now. The server-side check this value feeds
    /// (`SessionOpen.user` against the `qsh serve` OS account's login
    /// name, mismatch -> `UNSUPPORTED`) is completely unchanged: a
    /// `hosts.toml`-sourced default that mismatches is rejected exactly
    /// like an explicit one would be — this only changes what "requested
    /// user" defaults to before that check ever runs.
    ///
    /// Applied uniformly at this single choke point — every
    /// `session.open` caller (interactive attach, `session open`, and a
    /// long-running external process, e.g. an agent tool) gets the same
    /// default-fill, rather than only the
    /// interactive command growing it, so the three frontends can't drift
    /// into different behavior for the same host name.
    fn resolve_user_hint(
        &self,
        host: &str,
        explicit: Option<String>,
    ) -> Result<Option<String>, OpError> {
        if explicit.is_some() {
            return Ok(explicit);
        }
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        Ok(hosts
            .find(host)
            .and_then(|entry| entry.user.clone())
            .filter(|user| !user.trim().is_empty()))
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
    /// them, and a long-running external process's (e.g. an agent tool)
    /// long-poll is a third caller — all of them
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
    /// open_local_forwards`] is. The reason is `Connected::run`: each
    /// `-R` spec costs a real `RemoteForwardOpen` control round trip, and
    /// that needs the connection's [`Session`], but a few lines below
    /// this point `Connected::take_session` moves that `Session` into the
    /// spawned `drive_attach` task for the rest of the attach's life —
    /// after which `Connected::run` can only ever answer `Internal`
    /// ("connection already closed"), because there is no session left to
    /// run a request on. `-L` never hits this because
    /// [`SessionAttachStream::open_local_forwards`] only needs the raw
    /// `Connected::connection`, which the driver never takes. Pass an
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

        // Captured before `take_session()` below empties it out — see
        // `SessionAttachStream::capabilities`'s own doc for why
        // `open_dynamic_forwards` cannot read `conn.capabilities()` itself.
        let capabilities = conn.capabilities().to_vec();
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
            dynamic_forwards: Vec::new(),
            remote_acceptor,
            remote_tunnels,
            capabilities,
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
    /// value op (`Self::call`) and reports the intersection that
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
        let runtime = self.connect_runtime()?;
        let (endpoint, connection, session) = runtime.block_on(dial_peer(target))?;
        Ok(Connected {
            runtime: Some(runtime),
            link: ConnectedLink::Forward(Link::new(endpoint, connection)),
            session: Some(session),
        })
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
        let runtime = self.connect_runtime()?;
        let (session, peer_fingerprint, generation) = runtime.block_on(dial_reverse(route))?;
        Ok((
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
        ))
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

#[cfg(test)]
mod tests;
