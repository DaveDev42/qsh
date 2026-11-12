//! The host side of agent forwarding (ADR-0055 decisions 5 to 10, 16, 17).
//!
//! A request that carries an `agent_channel` from an `agent.v1` peer makes
//! this host create a socket (a named pipe on Windows) for the session or
//! exec, set `SSH_AUTH_SOCK` to it, and answer an `AgentGrant`. Every program
//! that connects to the socket gets an `AGENT` stream opened toward whichever
//! connection backs the socket at that moment, and the host copies bytes
//! between the two without reading them. The host is not the owner of that
//! data: filtering what reaches the local agent is the client's job
//! (decision 12).
//!
//! The order inside a request is fixed. The request's own action was allowed
//! first, then [`check_agent`] decides `forward.agent` and writes its audit
//! record, and only an allowed and recorded decision creates a socket. A
//! denial, a failed audit write or a socket that cannot be created never
//! fails the request: the session or exec opens without an agent and the
//! reply says why.
//!
//! # Lifetime
//!
//! A session's socket belongs to the session (decision 9): it stays at its
//! fixed path while the session lives and goes when the session ends (child
//! exit, `session close`, resume TTL). What stands behind it is the
//! [`Backing`], the connection and channel of the attach that holds the
//! writer lease and asked for `-A`. With no backing a connection to the
//! socket is closed at once. An exec's socket belongs to its pending ticket
//! and then to the exec's data-stream handler, so it goes with the exec or
//! with the connection.
//!
//! Logs and audit carry counts and closed words only. No path, channel or
//! agent byte is ever written.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use qsh_proto::wire::AGENT_CHANNEL_LEN;
use qsh_proto::wire::{self, StreamHeader, StreamKind};
use qsh_transport::{Connection, FramedSend, RecvStream, SendStream, StreamCode};
use rand::Rng as _;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use super::{ConnCtx, Server};
use crate::acl::{AgentOp, AgentVerdict, check_agent};
use crate::agent::{AgentConn, AgentListener, MAX_AGENT_STREAMS_PER_CONN, StreamBudget};
use crate::broker::{SessionBackend, SessionId, SessionState};
use crate::client::link::DataLink;
use crate::tunnel::splice::{RESET_CODE_TUNNEL_ABORT, pump};

/// How often a session socket asks whether its session is still running.
const SESSION_POLL: Duration = Duration::from_millis(200);

/// How long a local connection waits for the backing connection to prove the
/// path carries packets, at least ([`probe_wait`] scales it with the RTT).
const PROBE_FLOOR: Duration = Duration::from_millis(300);

/// The longest a probe waits, however slow the path.
const PROBE_CEIL: Duration = Duration::from_secs(2);

/// What the host knows about whether a backing connection's path works, kept
/// per connection and shared by every socket it backs.
///
/// A path that died without a close leaves the QUIC connection looking
/// healthy for the whole idle timeout, and a stream opened on it just waits.
/// The first local connection after that finds out with a probe
/// ([`probe_path`]); this remembers the verdict so the connections after it
/// close at once. The verdict is lifted only by a later probe that is
/// answered ([`Self::mark_silent`] keeps probing in the background), never by
/// the peer's frames moving: datagrams that left the peer before the path
/// died can still be queued here and arrive after the verdict, and would
/// make a dead path look alive again.
#[derive(Default)]
struct PathHealth {
    /// A probe went unanswered and none has been answered since.
    silent: AtomicBool,
    /// The last `rx_frames` a local connection saw and when it saw that
    /// value change.
    heard: Mutex<Option<(u64, std::time::Instant)>>,
}

impl PathHealth {
    /// Whether the connection is still known to be silent.
    fn still_silent(&self) -> bool {
        self.silent.load(Ordering::Acquire)
    }

    /// Whether the peer's authenticated frames moved within `wait` of the
    /// last time this was asked, which makes a probe needless. Records
    /// `rx_frames` for the next call.
    fn heard_recently(&self, rx_frames: u64, wait: Duration) -> bool {
        let now = std::time::Instant::now();
        let mut heard = self.heard.lock().unwrap_or_else(|e| e.into_inner());
        match *heard {
            Some((at, since)) if at != rx_frames => {
                *heard = Some((rx_frames, now));
                now.duration_since(since) <= wait
            }
            Some(_) => false,
            None => {
                *heard = Some((rx_frames, now));
                false
            }
        }
    }

    /// Remember that `conn` is silent, and keep probing it (one probe at a
    /// time, `wait` apart) until one is answered or the connection ends, so
    /// the sockets it backs work again once the path does.
    fn mark_silent(self: &Arc<Self>, conn: &Connection, wait: Duration) {
        if self.silent.swap(true, Ordering::AcqRel) {
            return;
        }
        let health = Arc::clone(self);
        let conn = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(wait).await;
                if conn.close_reason().is_some() {
                    return;
                }
                if probe_path(&conn, wait).await {
                    health.silent.store(false, Ordering::Release);
                    return;
                }
            }
        });
    }
}

/// The connection and channel that stand behind a socket right now.
#[derive(Clone)]
struct Backing {
    conn: Connection,
    conn_id: usize,
    channel: Vec<u8>,
    /// The `AGENT` streams of `conn` (decision 10), shared by every socket
    /// that connection backs.
    budget: StreamBudget,
    health: Arc<PathHealth>,
}

/// A running accept loop, stopped (and its socket removed) when this is
/// dropped.
pub(crate) struct AgentTask(JoinHandle<()>);

impl Drop for AgentTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl std::fmt::Debug for AgentTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AgentTask")
    }
}

/// One session's socket: the task that owns the listener and the handle that
/// swaps what stands behind it.
struct SessionSocket {
    /// The `SSH_AUTH_SOCK` value this socket was announced with.
    endpoint: String,
    backing: watch::Sender<Option<Backing>>,
    _task: AgentTask,
}

/// Every agent socket this host has, plus the per-connection stream budgets.
pub(super) struct AgentTable {
    /// Where sockets are made. Unset means this host cannot make any, which
    /// answers `UNAVAILABLE` (tests that never wired a runtime directory).
    runtime_dir: OnceLock<PathBuf>,
    sockets: Mutex<HashMap<String, SessionSocket>>,
    budgets: Mutex<HashMap<usize, StreamBudget>>,
    health: Mutex<HashMap<usize, Arc<PathHealth>>>,
}

impl AgentTable {
    pub(super) fn new() -> Self {
        Self {
            runtime_dir: OnceLock::new(),
            sockets: Mutex::new(HashMap::new()),
            budgets: Mutex::new(HashMap::new()),
            health: Mutex::new(HashMap::new()),
        }
    }

    fn health(&self, conn_id: usize) -> Arc<PathHealth> {
        Arc::clone(
            self.health
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(conn_id)
                .or_default(),
        )
    }

    fn budget(&self, conn_id: usize) -> StreamBudget {
        self.budgets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(conn_id)
            .or_insert_with(|| StreamBudget::new(MAX_AGENT_STREAMS_PER_CONN))
            .clone()
    }

    fn has_socket(&self, session: &str) -> bool {
        self.sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(session)
    }

    /// Put `backing` behind `session`'s socket. `false` when the session has
    /// no socket.
    fn set_backing(&self, session: &str, backing: Option<Backing>) -> bool {
        match self
            .sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session)
        {
            Some(socket) => {
                socket.backing.send_replace(backing);
                true
            }
            None => false,
        }
    }

    /// A connection is gone: it backs nothing any more, and its budget goes.
    pub(super) fn forget_connection(&self, conn_id: usize) {
        let sockets = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
        for socket in sockets.values() {
            socket.backing.send_if_modified(|current| {
                if current.as_ref().is_some_and(|b| b.conn_id == conn_id) {
                    *current = None;
                    true
                } else {
                    false
                }
            });
        }
        drop(sockets);
        self.budgets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&conn_id);
        self.health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&conn_id);
    }
}

/// What [`Server::prepare_agent`] decided: the grant to answer and, when it
/// is `FORWARDED`, the socket that exists but is not accepting yet.
pub(super) struct PreparedAgent {
    pub(super) grant: wire::AgentGrant,
    listener: Option<AgentListener>,
    backing: Option<Backing>,
}

impl PreparedAgent {
    fn without_socket(grant: wire::AgentGrant) -> Self {
        Self {
            grant,
            listener: None,
            backing: None,
        }
    }

    /// The value for `SSH_AUTH_SOCK`, when there is a socket.
    pub(super) fn sock(&self) -> Option<String> {
        self.listener
            .as_ref()
            .map(|l| l.auth_sock().to_string_lossy().into_owned())
    }
}

/// Interpret an `agent_channel` field (ADR-0055 decision 3). `Ok(None)` is
/// "nothing requested": the field is empty, or the peer did not advertise
/// `agent.v1` (ignored, like `screen_params`). A channel that is not exactly
/// 16 bytes is an error and the request is `INVALID_ARGUMENT`.
pub(super) fn requested_channel<'a>(
    ctx: &ConnCtx,
    agent_channel: &'a [u8],
) -> Result<Option<&'a [u8]>, &'static str> {
    if agent_channel.is_empty() || !ctx.has_capability(wire::CAP_AGENT_V1) {
        return Ok(None);
    }
    if agent_channel.len() != wire::AGENT_CHANNEL_LEN {
        return Err("agent_channel must be exactly 16 bytes");
    }
    Ok(Some(agent_channel))
}

impl Server {
    /// Tell this host where agent sockets are made: the runtime directory
    /// (`Paths::runtime_dir`). `crate::serve::host_runtime` calls it; a host
    /// without it answers `UNAVAILABLE` to every agent request. First call
    /// wins.
    pub fn set_agent_runtime_dir(&self, dir: PathBuf) {
        let _ = self.agents.runtime_dir.set(dir);
    }

    /// The `SSH_AUTH_SOCK` value (socket path, or pipe name on Windows) of
    /// every live session socket. A test seam: a named pipe has no directory
    /// to list, so a test that must find the socket a session announced asks
    /// the host. Exec sockets are not included; they live as long as one
    /// exec and are announced to the program itself.
    pub fn agent_session_endpoints(&self) -> Vec<String> {
        self.agents
            .sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|s| s.endpoint.clone())
            .collect()
    }

    /// Decide `forward.agent` for a request that asked for an agent and, when
    /// allowed and recorded, create its socket (not yet accepting). Call this
    /// after the request's own authorization and before the session or exec
    /// exists. `channel` is `None` when the request asked for nothing.
    ///
    /// `conn` is the connection that will back the socket. It is `None` only
    /// for a direct [`Server::dispatch`], which has no connection to open
    /// streams on; that answers `UNAVAILABLE` without a decision.
    pub(super) fn prepare_agent(
        &self,
        ctx: &ConnCtx,
        conn: Option<&Connection>,
        request_id: u64,
        op: AgentOp,
        channel: Option<&[u8]>,
    ) -> PreparedAgent {
        let Some(channel) = channel else {
            return PreparedAgent::without_socket(wire::AgentGrant::Unspecified);
        };
        let Some(conn) = conn else {
            return PreparedAgent::without_socket(wire::AgentGrant::Unavailable);
        };
        match check_agent(
            self.authorizer.as_ref(),
            self.audit.as_ref(),
            request_id,
            op,
            &ctx.requester(),
            &ctx.peer_addr,
        ) {
            AgentVerdict::Denied => {
                return PreparedAgent::without_socket(wire::AgentGrant::Denied);
            }
            AgentVerdict::AuditFailed => {
                return PreparedAgent::without_socket(wire::AgentGrant::Unavailable);
            }
            AgentVerdict::Allowed => {}
        }
        let Some(dir) = self.agents.runtime_dir.get() else {
            return PreparedAgent::without_socket(wire::AgentGrant::Unavailable);
        };
        match AgentListener::create(dir) {
            Ok(listener) => PreparedAgent {
                grant: wire::AgentGrant::Forwarded,
                listener: Some(listener),
                backing: Some(Backing {
                    conn: conn.clone(),
                    conn_id: ctx.conn_id,
                    channel: channel.to_vec(),
                    budget: self.agents.budget(ctx.conn_id),
                    health: self.agents.health(ctx.conn_id),
                }),
            },
            Err(err) => {
                tracing::warn!(
                    target: "qsh::agent",
                    event = "socket_unavailable",
                    kind = ?err.kind(),
                );
                PreparedAgent::without_socket(wire::AgentGrant::Unavailable)
            }
        }
    }

    /// The session exists: start accepting on its socket, backed by the
    /// connection that asked. A no-op when `prepared` has no socket.
    pub(super) fn start_session_agent(&self, id: &SessionId, prepared: PreparedAgent) {
        let (Some(listener), backing) = (prepared.listener, prepared.backing) else {
            return;
        };
        let table = &self.agents;
        let endpoint = listener.auth_sock().to_string_lossy().into_owned();
        let (tx, rx) = watch::channel(backing);
        let key = id.0.clone();
        let weak = Arc::downgrade(table);
        let remove_key = key.clone();
        // Held across the spawn and the insert so a socket whose session
        // already ended cannot remove its entry before it exists.
        let mut sockets = table.sockets.lock().unwrap_or_else(|e| e.into_inner());
        let task = tokio::spawn(run_socket(
            listener,
            rx,
            session_ended(Arc::clone(&self.sessions), id.clone()),
            move || {
                if let Some(table) = weak.upgrade() {
                    table
                        .sockets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&remove_key);
                }
            },
        ));
        sockets.insert(
            key,
            SessionSocket {
                endpoint,
                backing: tx,
                _task: AgentTask(task),
            },
        );
    }

    /// The exec is authorized: start accepting on its socket. The returned
    /// task goes in the pending ticket; dropping it removes the socket.
    pub(super) fn start_exec_agent(&self, prepared: PreparedAgent) -> Option<AgentTask> {
        let listener = prepared.listener?;
        let (tx, rx) = watch::channel(prepared.backing);
        let task = tokio::spawn(async move {
            // The exec's backing never changes (decision 9), so the sender
            // lives exactly as long as the loop does.
            let _tx = tx;
            run_socket(listener, rx, std::future::pending(), || {}).await;
        });
        Some(AgentTask(task))
    }

    /// An attach finished authorization: put the right connection behind the
    /// session's socket and answer the `AgentGrant` (decision 9).
    ///
    /// The attach takes the writer lease, so what stands behind the socket
    /// follows it: this attach's connection when it asked for `-A` and
    /// `forward.agent` allows, nothing otherwise. A session opened without
    /// `-A` has no socket and answers `NO_SOCKET`; one is never made later.
    pub(super) fn attach_agent(
        &self,
        ctx: &ConnCtx,
        conn: Option<&Connection>,
        request_id: u64,
        session: &SessionId,
        channel: Option<&[u8]>,
    ) -> wire::AgentGrant {
        let Some(channel) = channel else {
            self.agents.set_backing(&session.0, None);
            return wire::AgentGrant::Unspecified;
        };
        let Some(conn) = conn else {
            self.agents.set_backing(&session.0, None);
            return wire::AgentGrant::Unavailable;
        };
        match check_agent(
            self.authorizer.as_ref(),
            self.audit.as_ref(),
            request_id,
            AgentOp::SessionAttach,
            &ctx.requester(),
            &ctx.peer_addr,
        ) {
            AgentVerdict::Denied => {
                self.agents.set_backing(&session.0, None);
                wire::AgentGrant::Denied
            }
            AgentVerdict::AuditFailed => {
                self.agents.set_backing(&session.0, None);
                wire::AgentGrant::Unavailable
            }
            AgentVerdict::Allowed => {
                if !self.agents.has_socket(&session.0) {
                    return wire::AgentGrant::NoSocket;
                }
                let backing = Backing {
                    conn: conn.clone(),
                    conn_id: ctx.conn_id,
                    channel: channel.to_vec(),
                    budget: self.agents.budget(ctx.conn_id),
                    health: self.agents.health(ctx.conn_id),
                };
                if self.agents.set_backing(&session.0, Some(backing)) {
                    wire::AgentGrant::Forwarded
                } else {
                    wire::AgentGrant::NoSocket
                }
            }
        }
    }
}

/// Completes when the session is no longer running: closed, expired or its
/// child exited.
async fn session_ended(sessions: Arc<dyn SessionBackend>, id: SessionId) {
    loop {
        tokio::time::sleep(SESSION_POLL).await;
        match sessions.get(&id) {
            Ok(info) if info.state == SessionState::Running => {}
            _ => return,
        }
    }
}

/// Accept on `listener` until `ended` completes or the listener fails, then
/// remove the socket and call `on_end`. Dropping the future (the owning
/// [`AgentTask`] going away) tears down the same way: the in-flight
/// connections are aborted, which resets their streams, and the listener
/// removes its socket.
async fn run_socket(
    mut listener: AgentListener,
    backing: watch::Receiver<Option<Backing>>,
    ended: impl Future<Output = ()>,
    on_end: impl FnOnce(),
) {
    let mut streams: JoinSet<()> = JoinSet::new();
    tokio::pin!(ended);
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => admit(conn, &backing, &mut streams),
                Err(_) => break,
            },
            () = &mut ended => break,
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
        }
    }
    streams.shutdown().await;
    drop(listener);
    on_end();
}

/// A program connected to the socket: bridge it, or close it at once.
fn admit(
    mut conn: AgentConn,
    backing: &watch::Receiver<Option<Backing>>,
    streams: &mut JoinSet<()>,
) {
    let Some(backing) = backing.borrow().clone() else {
        tracing::info!(target: "qsh::agent", event = "accept_closed", reason = "no_backing");
        return;
    };
    if !conn.hold(&backing.budget) {
        tracing::info!(target: "qsh::agent", event = "accept_closed", reason = "cap");
        return;
    }
    streams.spawn(bridge(conn, backing));
}

/// The two QUIC halves of one `AGENT` stream, reset unless the copy ended
/// cleanly. Dropping a bare quinn stream would finish it, which the other
/// side reads as a normal end.
struct StreamGuard {
    send: Option<SendStream>,
    recv: Option<RecvStream>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let code = StreamCode::from_u32(RESET_CODE_TUNNEL_ABORT);
        if let Some(mut send) = self.send.take() {
            let _ = send.reset(code);
        }
        if let Some(mut recv) = self.recv.take() {
            let _ = recv.stop(code);
        }
    }
}

/// Open an `AGENT` stream on the backing connection and copy bytes between
/// it and the local connection, each direction half-closed as it ends.
///
/// The copy starts at once. Unless the connection was heard from a moment ago,
/// a liveness probe ([`probe_path`]) runs beside it, so a healthy path costs
/// no extra round trip. A path that died silently must not leave the program
/// waiting (decision 9): when the probe finds no sign of life the local
/// connection is closed and tries again once the attach has resumed. The
/// real stream's own silence proves nothing, since the local agent may take
/// long to answer (`ssh-add -c`).
async fn bridge(conn: AgentConn, backing: Backing) {
    let (local, _slots) = conn.into_parts();
    let frames = backing.conn.rx_frames();
    let wait = probe_wait(backing.conn.rtt());
    if backing.health.still_silent() {
        tracing::info!(target: "qsh::agent", event = "accept_closed", reason = "path_silent");
        return;
    }
    let probing = !backing.health.heard_recently(frames, wait);
    let header = StreamHeader {
        kind: StreamKind::Agent as i32,
        ticket: backing.channel.clone(),
        host: String::new(),
        port: 0,
        deny_host_local: false,
    };
    let link = DataLink::Direct(&backing.conn);
    let Ok((send, recv, kill)) = crate::tunnel::open_stream(&link, &header).await else {
        return;
    };
    let (Ok(send), Ok((recv, residue))) = (send.into_raw_direct(), recv.into_raw_direct()) else {
        kill.kill();
        return;
    };
    let copy = async move {
        let mut guard = StreamGuard {
            send: Some(send),
            recv: Some(recv),
        };
        let (mut local_read, mut local_write) = tokio::io::split(local);
        let (Some(send), Some(recv)) = (guard.send.as_mut(), guard.recv.as_mut()) else {
            return;
        };
        let up = pump(&mut local_read, send, &[]);
        let down = pump(recv, &mut local_write, &residue);
        if tokio::try_join!(up, down).is_ok() {
            // Both directions ended cleanly: each already said so to its peer.
            guard.send.take();
            guard.recv.take();
        }
    };
    tokio::pin!(copy);
    // A connection heard from within `wait` gets its probe only if the copy
    // is still going after another `wait` with nothing heard since: the path
    // may have died right after that traffic, and a connection that is
    // answered in time never starts a probe stream.
    let grace = if probing { Duration::ZERO } else { wait };
    let probe = async {
        tokio::time::sleep(grace).await;
        let seen = backing.conn.rx_frames();
        if probe_path(&backing.conn, wait).await {
            return true;
        }
        // Frames that arrived while the probe waited prove nothing about the
        // path now (they may have been queued before it died), but they show
        // a peer that was alive a moment ago and may only be slow to answer
        // under load: it gets one more probe. A path with no sign of life at
        // all is judged silent after the first.
        backing.conn.rx_frames() != seen && probe_path(&backing.conn, wait).await
    };
    tokio::pin!(probe);
    tokio::select! {
        () = &mut copy => {}
        alive = &mut probe => {
            if alive {
                copy.await;
            } else {
                // Dropping `copy` closes the local connection and resets the
                // stream.
                backing.health.mark_silent(&backing.conn, wait);
                tracing::info!(
                    target: "qsh::agent",
                    event = "accept_closed",
                    reason = "path_silent"
                );
            }
        }
    }
}

/// How long a probe waits for a connection with this RTT estimate.
fn probe_wait(rtt: Duration) -> Duration {
    rtt.saturating_mul(4).clamp(PROBE_FLOOR, PROBE_CEIL)
}

/// Whether the backing connection's peer answers within `wait`. The proof is
/// an `AGENT` stream whose channel no client has registered, opened and
/// finished just now: the peer acknowledges its bytes (transport level, so a
/// busy program on the other side cannot delay it) or resets it at once
/// (ADR-0055 decision 13). Either is a round trip that began after this
/// call. The peer's authenticated frames moving is not enough: datagrams
/// that left the peer before the path died can still be queued here and
/// would pass for a live path. Nothing reaches a local agent, and the
/// channel is random, so it never collides with a real one.
async fn probe_path(conn: &Connection, wait: Duration) -> bool {
    let stream = async {
        let (send, mut recv) = conn.open_bi().await.ok()?;
        let mut channel = [0u8; AGENT_CHANNEL_LEN];
        rand::rng().fill_bytes(&mut channel);
        let mut framed = FramedSend::data(send);
        framed
            .send(&StreamHeader {
                kind: StreamKind::Agent as i32,
                ticket: channel.to_vec(),
                ..Default::default()
            })
            .await
            .ok()?;
        let mut send = framed.into_raw();
        send.finish().ok()?;
        let stopped = send.stopped();
        let mut byte = [0u8; 1];
        // Any answer proves the path: an acknowledgement, a reset, a stop or
        // an end.
        tokio::select! {
            _ = recv.read(&mut byte) => {}
            _ = stopped => {}
        }
        let _ = send.reset(StreamCode::from_u32(RESET_CODE_TUNNEL_ABORT));
        Some(())
    };
    let answered = tokio::time::timeout(wait, stream).await;
    matches!(answered, Ok(Some(()))) && conn.close_reason().is_none()
}
