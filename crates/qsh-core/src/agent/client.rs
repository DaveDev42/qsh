//! The client side of agent forwarding (ADR-0055 decisions 11 to 13): find
//! the local ssh-agent, keep the table of `agent_channel`s this process
//! asked for, and serve each `AGENT` stream the host opens by filtering it
//! message by message.
//!
//! The host is not trusted with the local agent. Three rules keep it away:
//!
//! - A stream reaches the local agent only if its ticket is a channel this
//!   process registered ([`ClientAgent::register`]) and has not yet
//!   released. Anything else is reset before a local connection exists.
//! - Of the requests that follow, only [`qsh_proto::agent::ALLOWED_REQUESTS`] are written to
//!   the local agent. Every other one is answered by this module with
//!   [`FAILURE_REPLY`]; the agent never sees it.
//! - A zero or oversized frame resets the stream and closes the local
//!   connection.
//!
//! Nothing here logs a key, a signature or a socket path. The `qsh::agent`
//! lines carry counts, message type numbers and durations only.

use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use qsh_proto::agent::{
    AgentDecoder, AgentFrameError, FAILURE_REPLY, RequestDisposition, request_disposition,
};
use qsh_proto::wire::AGENT_CHANNEL_LEN;
use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{MAX_AGENT_STREAMS_PER_CONN, StreamBudget};
use crate::ops::OpError;
use qsh_proto::ErrorCode;

/// The Win32-OpenSSH agent's pipe, used on Windows when `SSH_AUTH_SOCK` is
/// not set (ADR-0055 decision 11).
pub const WINDOWS_DEFAULT_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// `ERROR_PIPE_BUSY`: the agent's pipe exists but its next instance is not
/// up yet.
#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;

/// Reset code for a framing violation or an unregistered channel (`0x2001`).
const RESET_BAD_HEADER: u32 = crate::server::RESET_CODE_BAD_HEADER;
/// Reset code for a local agent that broke framing or went away mid-request
/// (`0x2007`, the splice abort code of `docs/design/protocol.md` §7).
const RESET_ABORT: u32 = 0x2007;
/// Reset code for a stream over the per-connection cap (`0x200D`).
const RESET_EXHAUSTED: u32 = crate::server::RESET_CODE_RESOURCE_EXHAUSTED;

/// A byte stream to a local agent.
pub trait AgentIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AgentIo for T {}

/// One connection to the local agent.
pub type LocalAgentStream = Box<dyn AgentIo>;

/// Where the local agent listens, as resolved from `-o ForwardAgent`, the
/// environment and the platform default (decision 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEndpoint {
    target: String,
}

/// Why no endpoint could be named. The text is what the stderr line shows
/// after `no ssh-agent at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoEndpoint {
    /// Where the lookup ended: a variable name, a path, or a pipe name.
    pub shown: String,
}

impl AgentEndpoint {
    /// Resolve the agent location.
    ///
    /// - `spec` is the value of `-o ForwardAgent=` when it named a place: a
    ///   path, or `$VAR` to read the path from the environment.
    /// - Without one, `SSH_AUTH_SOCK` is read through `env`. On Windows an
    ///   unset variable means [`WINDOWS_DEFAULT_AGENT_PIPE`]; on unix it
    ///   means there is no agent.
    /// - On Windows only a `\\.\pipe\` name can be connected to, so any
    ///   other value is reported as having no endpoint.
    ///
    /// `env` is passed in so a test names the variable's value without
    /// touching the process environment.
    pub fn resolve(
        spec: Option<&str>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, NoEndpoint> {
        let from_env = |name: &str| env(name).filter(|v| !v.is_empty());
        let value = match spec {
            Some(spec) => match spec.strip_prefix('$') {
                Some(var) => from_env(var).ok_or_else(|| NoEndpoint {
                    shown: format!("${var} (not set)"),
                })?,
                None => spec.to_string(),
            },
            None => match from_env("SSH_AUTH_SOCK") {
                Some(value) => value,
                None if cfg!(windows) => WINDOWS_DEFAULT_AGENT_PIPE.to_string(),
                None => {
                    return Err(NoEndpoint {
                        shown: "$SSH_AUTH_SOCK (not set)".to_string(),
                    });
                }
            },
        };
        if cfg!(windows) && !value.to_ascii_lowercase().starts_with(r"\\.\pipe\") {
            return Err(NoEndpoint { shown: value });
        }
        Ok(Self { target: value })
    }

    /// The path or pipe name, for the one stderr line. Never logged.
    pub fn shown(&self) -> &str {
        &self.target
    }

    /// Open one connection to the agent.
    #[cfg(unix)]
    pub async fn connect(&self) -> io::Result<LocalAgentStream> {
        let stream = tokio::net::UnixStream::connect(std::path::Path::new(&self.target)).await?;
        Ok(Box::new(stream))
    }

    /// Open one connection to the agent. The server creates the next pipe
    /// instance only after a client has connected to the current one, so a
    /// second client in between sees `ERROR_PIPE_BUSY`; retry briefly.
    #[cfg(windows)]
    pub async fn connect(&self) -> io::Result<LocalAgentStream> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(&self.target) {
                Err(err)
                    if err.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Ok(client) => return Ok(Box::new(client)),
                Err(err) => return Err(err),
            }
        }
    }
}

/// What `-o ForwardAgent=` said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardAgentOption {
    /// `yes`.
    Yes,
    /// `no`.
    No,
    /// A path or `$VAR`: forward, and use this place for the local agent.
    Location(String),
}

impl ForwardAgentOption {
    /// Parse the value of `-o ForwardAgent=<value>`.
    pub fn parse(value: &str) -> Result<Self, OpError> {
        if value.eq_ignore_ascii_case("yes") || value.eq_ignore_ascii_case("true") {
            Ok(Self::Yes)
        } else if value.eq_ignore_ascii_case("no") || value.eq_ignore_ascii_case("false") {
            Ok(Self::No)
        } else if value.is_empty() || value.contains('\0') {
            Err(OpError::new(
                ErrorCode::InvalidArgument,
                "ForwardAgent expects yes, no, a socket path or $VAR",
            ))
        } else {
            Ok(Self::Location(value.to_string()))
        }
    }
}

/// The decision of decision 18's precedence: `-A`/`-a`, then `-o
/// ForwardAgent`, then `[agent].forward`, then off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentChoice {
    /// Do not forward.
    Off,
    /// Forward. `location` is the place named by `-o ForwardAgent=<path>`,
    /// `None` for the default discovery.
    Forward {
        /// Explicit path or `$VAR`.
        location: Option<String>,
    },
}

impl AgentChoice {
    /// Apply the precedence. `flag` is the last of `-A` (`Some(true)`) and
    /// `-a` (`Some(false)`); `option` is the first `-o ForwardAgent`;
    /// `config` is `[agent].forward`. `-A` still takes its place from a
    /// `-o ForwardAgent=<path>`: the flag says whether, the option says
    /// where.
    pub fn decide(
        flag: Option<bool>,
        option: Option<&ForwardAgentOption>,
        config: bool,
    ) -> AgentChoice {
        let location = match option {
            Some(ForwardAgentOption::Location(l)) => Some(l.clone()),
            _ => None,
        };
        let on = match (flag, option) {
            (Some(flag), _) => flag,
            (None, Some(ForwardAgentOption::No)) => false,
            (None, Some(_)) => true,
            (None, None) => config,
        };
        if on {
            AgentChoice::Forward { location }
        } else {
            AgentChoice::Off
        }
    }
}

/// The word the JSON `agent` field and the stderr note use for a host's
/// answer (ADR-0055 decision 19), or `None` when `-A` was not asked.
///
/// `host_supports` is whether the connection can carry agent forwarding at
/// all: the peer advertised `agent.v1` and this is a forward connection.
/// When it cannot, the request field was never sent and the word is
/// `"unsupported"`, whatever the (absent) reply says.
pub fn grant_label(requested: bool, host_supports: bool, grant: i32) -> Option<&'static str> {
    use qsh_proto::wire::AgentGrant;
    if !requested {
        return None;
    }
    if !host_supports {
        return Some("unsupported");
    }
    Some(
        match AgentGrant::try_from(grant).unwrap_or(AgentGrant::Unspecified) {
            AgentGrant::Forwarded => "forwarded",
            AgentGrant::Denied => "denied",
            AgentGrant::Unavailable => "unavailable",
            AgentGrant::NoSocket => "no_socket",
            AgentGrant::Unspecified => "unsupported",
        },
    )
}

/// A registered `agent_channel`. Dropping it removes the channel from the
/// table, so a stream naming it is refused from then on (decision 13).
#[derive(Debug)]
pub struct AgentChannel {
    id: [u8; AGENT_CHANNEL_LEN],
    agent: Arc<ClientAgent>,
    /// The claim loop of the reverse route, stopped with the channel.
    claims: Mutex<Option<ReverseClaims>>,
}

impl AgentChannel {
    /// The 16 bytes to put in the request.
    pub fn bytes(&self) -> Vec<u8> {
        self.id.to_vec()
    }

    /// On the reverse route, start claiming this channel's `AGENT` streams
    /// from the `qsh listen` daemon at `socket` (ADR-0055 decision 14). It
    /// can start before the request carrying the channel has left: a claim
    /// the daemon does not recognize yet comes back at once and is retried.
    /// The loop stops when the channel is dropped. Must run inside a Tokio
    /// runtime.
    pub fn serve_over_daemon(&self, socket: std::path::PathBuf, host: String) {
        let task = tokio::spawn(claim_loop(Arc::clone(&self.agent), self.id, socket, host));
        *self.claims.lock().unwrap_or_else(|e| e.into_inner()) = Some(ReverseClaims(task));
    }
}

impl Drop for AgentChannel {
    fn drop(&mut self) {
        self.agent
            .channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

/// Everything one client process holds for agent forwarding: where the
/// local agent is and which channels are live.
#[derive(Debug)]
pub struct ClientAgent {
    endpoint: Result<AgentEndpoint, NoEndpoint>,
    channels: Mutex<HashSet<[u8; AGENT_CHANNEL_LEN]>>,
}

impl ClientAgent {
    /// A client agent that reaches `endpoint`, or reports it cannot.
    pub fn new(endpoint: Result<AgentEndpoint, NoEndpoint>) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            channels: Mutex::new(HashSet::new()),
        })
    }

    /// Resolve the endpoint from `location` (the `-o ForwardAgent=` place)
    /// and the process environment.
    pub fn from_env(location: Option<&str>) -> Arc<Self> {
        Self::new(AgentEndpoint::resolve(location, &|name| {
            std::env::var(name).ok()
        }))
    }

    /// Draw a fresh channel and add it to the table. Done before the request
    /// is sent, so the host can open the stream before the reply arrives.
    pub fn register(self: &Arc<Self>) -> AgentChannel {
        let mut id = [0u8; AGENT_CHANNEL_LEN];
        rand::rng().fill_bytes(&mut id);
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id);
        AgentChannel {
            id,
            agent: Arc::clone(self),
            claims: Mutex::new(None),
        }
    }

    /// Whether `ticket` is a live channel. A ticket of any other length is
    /// not.
    pub fn is_registered(&self, ticket: &[u8]) -> bool {
        let Ok(id) = <[u8; AGENT_CHANNEL_LEN]>::try_from(ticket) else {
            return false;
        };
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&id)
    }

    /// Channels currently registered.
    pub fn channel_count(&self) -> usize {
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// The text of the stderr line (the frontend adds `qsh: `) when the agent
    /// cannot be reached, or `None` when
    /// a connection works (decision 11). One probe connection is opened and
    /// closed without sending anything. The request goes out either way.
    pub async fn unreachable_note(&self) -> Option<String> {
        let shown = match &self.endpoint {
            Err(no) => no.shown.clone(),
            Ok(endpoint) => match endpoint.connect().await {
                Ok(_probe) => return None,
                Err(_) => endpoint.shown().to_string(),
            },
        };
        Some(format!("-A: no ssh-agent at {shown}; forwarding anyway"))
    }

    /// Dispatch state for one connection: a fresh per-connection stream
    /// budget in front of this agent.
    pub fn dispatcher(self: &Arc<Self>) -> AgentDispatch {
        AgentDispatch {
            agent: Arc::clone(self),
            budget: StreamBudget::new(MAX_AGENT_STREAMS_PER_CONN),
        }
    }

    async fn connect_local(&self) -> io::Result<LocalAgentStream> {
        match &self.endpoint {
            Ok(endpoint) => endpoint.connect().await,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no local agent endpoint",
            )),
        }
    }
}

/// The per-connection half the stream dispatcher consults: the channel
/// table plus the 64-stream budget of one QUIC connection (decision 10).
#[derive(Debug, Clone)]
pub struct AgentDispatch {
    agent: Arc<ClientAgent>,
    budget: StreamBudget,
}

impl AgentDispatch {
    /// Streams currently being served on this connection.
    pub fn in_use(&self) -> usize {
        self.budget.in_use()
    }
}

/// Serve one `AGENT` stream whose header the dispatcher already read.
///
/// `ticket` is the header's ticket, `residue` the bytes the framed reader
/// consumed past the header. The stream's end is decided here: a registered
/// channel under the budget gets a local agent connection; anything else is
/// reset before one exists.
pub(crate) async fn serve_agent_stream(
    mut send: qsh_transport::SendStream,
    mut recv: qsh_transport::RecvStream,
    residue: Vec<u8>,
    ticket: &[u8],
    dispatch: &AgentDispatch,
) {
    let reset =
        |send: &mut qsh_transport::SendStream, recv: &mut qsh_transport::RecvStream, code: u32| {
            let _ = send.reset(qsh_transport::StreamCode::from_u32(code));
            let _ = recv.stop(qsh_transport::StreamCode::from_u32(code));
        };
    if !dispatch.agent.is_registered(ticket) {
        tracing::warn!(
            target: "qsh::agent",
            event = "refused",
            reason = "unregistered_channel",
            ticket_len = ticket.len(),
        );
        reset(&mut send, &mut recv, RESET_BAD_HEADER);
        return;
    }
    let Some(_permit) = dispatch.budget.try_acquire() else {
        tracing::warn!(
            target: "qsh::agent",
            event = "refused",
            reason = "cap",
        );
        reset(&mut send, &mut recv, RESET_EXHAUSTED);
        return;
    };
    match run_against_local(&mut send, &mut recv, residue, &dispatch.agent).await {
        Served::NoLocalAgent => {
            let _ = send.finish();
            let _ = recv.stop(qsh_transport::StreamCode::from_u32(0));
        }
        Served::Done(Outcome::HostClosed | Outcome::LocalClosed) => {
            let _ = send.finish();
        }
        Served::Done(Outcome::BadFrame) => reset(&mut send, &mut recv, RESET_BAD_HEADER),
        Served::Done(Outcome::Abort) => reset(&mut send, &mut recv, RESET_ABORT),
    }
}

/// How one stream ended against the local agent.
enum Served {
    /// No connection to the local agent could be made. The host sees an
    /// agent failure; the session itself is fine.
    NoLocalAgent,
    Done(Outcome),
}

/// Connect to the local agent and run the filter loop between it and the
/// stream halves `send`/`recv`, whatever carries them (a QUIC stream on the
/// forward route, the daemon's conduit on the reverse route). Logs the
/// `qsh::agent` lines; the caller turns the outcome into the carrier's own
/// way of ending a stream.
async fn run_against_local<R, W>(
    send: &mut W,
    recv: &mut R,
    residue: Vec<u8>,
    agent: &ClientAgent,
) -> Served
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let local = match agent.connect_local().await {
        Ok(local) => local,
        Err(_) => {
            tracing::info!(
                target: "qsh::agent",
                event = "refused",
                reason = "no_local_agent",
            );
            return Served::NoLocalAgent;
        }
    };
    tracing::info!(target: "qsh::agent", event = "opened");
    let started = Instant::now();
    let mut stats = FilterStats::default();
    let outcome = filter_loop(send, recv, residue, local, &mut stats).await;
    tracing::info!(
        target: "qsh::agent",
        event = "closed",
        requests = stats.requests,
        filtered = stats.filtered,
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
    Served::Done(outcome)
}

// ---- the reverse route (ADR-0055 decision 14) ----------------------------

/// How long one claim long-polls the daemon, the most the daemon honors.
const CLAIM_WAIT_MS: u32 = qsh_proto::local::LOCAL_WAIT_MAX.as_millis() as u32;
/// Shortest and longest pause before the next claim after one that failed
/// or came back at once (a channel the daemon has not seen yet, a daemon
/// restarting). It doubles from the first to the second.
const CLAIM_BACKOFF_MIN: std::time::Duration = std::time::Duration::from_millis(25);
const CLAIM_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_millis(400);
/// A `Timeout` faster than this did not wait out the budget: the channel is
/// not registered (yet) or the seat is someone else's.
const FAST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// The claim loop of one channel on the reverse route. Dropping it stops
/// new claims; a stream already claimed runs to its own end.
pub(crate) struct ReverseClaims(tokio::task::JoinHandle<()>);

impl Drop for ReverseClaims {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl std::fmt::Debug for ReverseClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReverseClaims")
    }
}

/// Claim `AGENT` streams for `channel` from the `qsh listen` daemon at
/// `socket` for `host`, one long poll at a time, and serve each through the
/// local agent exactly as the forward route's dispatcher does: this
/// process, not the daemon, connects to the agent and filters.
///
/// Must run inside a Tokio runtime.
async fn claim_loop(
    agent: Arc<ClientAgent>,
    channel: [u8; AGENT_CHANNEL_LEN],
    socket: std::path::PathBuf,
    host: String,
) {
    use qsh_proto::wire::{StreamHeader, StreamKind};
    // The claim token. The first claim seats it, so a later claim from any
    // other process (which cannot know it) is refused by the daemon.
    let mut token = [0u8; AGENT_CHANNEL_LEN];
    rand::rng().fill_bytes(&mut token);
    let mut ticket = channel.to_vec();
    ticket.extend_from_slice(&token);
    let header = StreamHeader {
        kind: StreamKind::Agent as i32,
        ticket,
        host: String::new(),
        port: 0,
        deny_host_local: false,
    };
    let dispatch = agent.dispatcher();
    let mut backoff = CLAIM_BACKOFF_MIN;
    loop {
        let started = Instant::now();
        let link = crate::client::link::DataLink::Local {
            socket: &socket,
            host: &host,
        };
        match crate::tunnel::open_stream_with_wait(&link, &header, CLAIM_WAIT_MS).await {
            Ok((send, recv, kill)) => {
                backoff = CLAIM_BACKOFF_MIN;
                tokio::spawn(serve_relayed(send, recv, kill, channel, dispatch.clone()));
            }
            Err(crate::client::ClientError::Remote {
                code: ErrorCode::Timeout,
                ..
            }) if started.elapsed() >= FAST_TIMEOUT => {
                // Nothing arrived for the whole budget: claim again.
                backoff = CLAIM_BACKOFF_MIN;
            }
            Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(CLAIM_BACKOFF_MAX);
            }
        }
    }
}

/// Serve one claimed `AGENT` stream: the daemon already matched it to this
/// channel and this process, so only the budget and the filter remain.
async fn serve_relayed(
    send: crate::client::link::DataSend,
    recv: crate::client::link::DataRecv,
    kill: crate::client::link::DataKillSwitch,
    channel: [u8; AGENT_CHANNEL_LEN],
    dispatch: AgentDispatch,
) {
    let (Ok(mut raw_send), Ok((mut raw_recv, residue))) =
        (send.into_raw_local(), recv.into_raw_local())
    else {
        kill.kill();
        return;
    };
    if !dispatch.agent.is_registered(&channel) {
        tracing::warn!(
            target: "qsh::agent",
            event = "refused",
            reason = "unregistered_channel",
        );
        kill.kill();
        return;
    }
    let Some(_permit) = dispatch.budget.try_acquire() else {
        tracing::warn!(target: "qsh::agent", event = "refused", reason = "cap");
        kill.kill();
        return;
    };
    match run_against_local(&mut raw_send, &mut raw_recv, residue, &dispatch.agent).await {
        Served::NoLocalAgent | Served::Done(Outcome::HostClosed | Outcome::LocalClosed) => {
            let _ = raw_send.shutdown().await;
        }
        // The conduit has no per-stream reset. Closing it whole makes the
        // daemon end the QUIC stream, and the host sees an agent failure.
        Served::Done(Outcome::BadFrame | Outcome::Abort) => kill.kill(),
    }
}

#[derive(Default)]
struct FilterStats {
    requests: u64,
    filtered: u64,
}

enum Outcome {
    /// The host half-closed after a whole message.
    HostClosed,
    /// The local agent closed its connection.
    LocalClosed,
    /// The host sent a zero-length or oversized frame.
    BadFrame,
    /// The stream broke, or the local agent broke framing.
    Abort,
}

/// The request loop: one request in, one response out, never a second
/// request read before the response is written (decision 4).
async fn filter_loop<R, W>(
    send: &mut W,
    recv: &mut R,
    residue: Vec<u8>,
    mut local: LocalAgentStream,
    stats: &mut FilterStats,
) -> Outcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut from_host = AgentDecoder::new();
    from_host.push(&residue);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let request = loop {
            match from_host.next_message() {
                Ok(Some(message)) => break message,
                Ok(None) => {}
                Err(AgentFrameError::ZeroLength | AgentFrameError::Oversize { .. }) => {
                    return Outcome::BadFrame;
                }
            }
            match recv.read(&mut buf).await {
                Ok(0) => return Outcome::HostClosed,
                Ok(n) => from_host.push(&buf[..n]),
                Err(_) => return Outcome::Abort,
            }
        };
        stats.requests += 1;
        match request_disposition(request.kind) {
            RequestDisposition::Fail => {
                stats.filtered += 1;
                tracing::info!(
                    target: "qsh::agent",
                    event = "refused",
                    kind = request.kind,
                );
                if send.write_all(&FAILURE_REPLY).await.is_err() {
                    return Outcome::Abort;
                }
            }
            RequestDisposition::Forward => {
                if local.write_all(&request.bytes).await.is_err() {
                    return Outcome::LocalClosed;
                }
                let reply = match read_reply(&mut local, &mut buf).await {
                    Ok(reply) => reply,
                    Err(outcome) => return outcome,
                };
                if send.write_all(&reply).await.is_err() {
                    return Outcome::Abort;
                }
            }
        }
    }
}

/// Read exactly one whole message from the local agent. The reply is not
/// filtered, only framed, so a broken agent cannot make this side buffer
/// more than [`qsh_proto::agent::AGENT_MESSAGE_MAX`] bytes.
async fn read_reply(local: &mut LocalAgentStream, buf: &mut [u8]) -> Result<Vec<u8>, Outcome> {
    let mut decoder = AgentDecoder::new();
    loop {
        match decoder.next_message() {
            Ok(Some(message)) => return Ok(message.bytes),
            Ok(None) => {}
            Err(_) => return Err(Outcome::Abort),
        }
        match local.read(buf).await {
            Ok(0) => return Err(Outcome::LocalClosed),
            Ok(n) => decoder.push(&buf[..n]),
            Err(_) => return Err(Outcome::LocalClosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[cfg(unix)]
    #[test]
    fn discovery_prefers_the_option_then_the_environment() {
        let env = env_of(&[
            ("SSH_AUTH_SOCK", "/run/agent.sock"),
            ("MYSOCK", "/tmp/my.sock"),
        ]);
        let from_env = AgentEndpoint::resolve(None, &env).unwrap();
        assert_eq!(from_env.shown(), "/run/agent.sock");
        let literal = AgentEndpoint::resolve(Some("/x/y.sock"), &env).unwrap();
        assert_eq!(literal.shown(), "/x/y.sock");
        let var = AgentEndpoint::resolve(Some("$MYSOCK"), &env).unwrap();
        assert_eq!(var.shown(), "/tmp/my.sock");
        let missing = AgentEndpoint::resolve(Some("$NOPE"), &env).unwrap_err();
        assert_eq!(missing.shown, "$NOPE (not set)");
        let none = AgentEndpoint::resolve(None, &env_of(&[])).unwrap_err();
        assert_eq!(none.shown, "$SSH_AUTH_SOCK (not set)");
        // An empty value is the same as unset.
        let empty = AgentEndpoint::resolve(None, &env_of(&[("SSH_AUTH_SOCK", "")])).unwrap_err();
        assert_eq!(empty.shown, "$SSH_AUTH_SOCK (not set)");
    }

    #[cfg(windows)]
    #[test]
    fn discovery_defaults_to_the_openssh_pipe_on_windows() {
        let none = AgentEndpoint::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(none.shown(), WINDOWS_DEFAULT_AGENT_PIPE);
        let pipe = AgentEndpoint::resolve(
            None,
            &env_of(&[("SSH_AUTH_SOCK", r"\\.\pipe\custom-agent")]),
        )
        .unwrap();
        assert_eq!(pipe.shown(), r"\\.\pipe\custom-agent");
        // An AF_UNIX path or a msys socket file cannot be connected to.
        let path = AgentEndpoint::resolve(None, &env_of(&[("SSH_AUTH_SOCK", "C:/tmp/agent")]));
        assert!(path.is_err());
    }

    /// Decision 18's table: the flag, then `-o`, then the config key, then
    /// off. `-A` keeps the place that `-o ForwardAgent=<path>` names.
    #[test]
    fn forward_agent_precedence_table() {
        use ForwardAgentOption::{Location, No, Yes};
        let loc = || Location("/s/a.sock".to_string());
        let fwd = |l: Option<&str>| AgentChoice::Forward {
            location: l.map(str::to_string),
        };
        #[allow(clippy::type_complexity)]
        let rows: Vec<(Option<bool>, Option<ForwardAgentOption>, bool, AgentChoice)> = vec![
            // Nothing given: the config key decides.
            (None, None, false, AgentChoice::Off),
            (None, None, true, fwd(None)),
            // -o beats the config key, both ways.
            (None, Some(Yes), false, fwd(None)),
            (None, Some(No), true, AgentChoice::Off),
            (None, Some(loc()), false, fwd(Some("/s/a.sock"))),
            // -A / -a beat -o and the config key.
            (Some(true), None, false, fwd(None)),
            (Some(true), Some(No), false, fwd(None)),
            (Some(true), Some(loc()), false, fwd(Some("/s/a.sock"))),
            (Some(false), None, true, AgentChoice::Off),
            (Some(false), Some(Yes), true, AgentChoice::Off),
            (Some(false), Some(loc()), true, AgentChoice::Off),
        ];
        for (flag, option, config, want) in rows {
            let got = AgentChoice::decide(flag, option.as_ref(), config);
            assert_eq!(got, want, "flag={flag:?} option={option:?} config={config}");
        }
    }

    #[test]
    fn the_option_value_parses() {
        assert_eq!(
            ForwardAgentOption::parse("yes").unwrap(),
            ForwardAgentOption::Yes
        );
        assert_eq!(
            ForwardAgentOption::parse("No").unwrap(),
            ForwardAgentOption::No
        );
        assert_eq!(
            ForwardAgentOption::parse("$SOCK").unwrap(),
            ForwardAgentOption::Location("$SOCK".into())
        );
        assert!(ForwardAgentOption::parse("").is_err());
    }

    #[test]
    fn a_channel_leaves_the_table_when_dropped() {
        let agent = ClientAgent::new(Err(NoEndpoint { shown: "x".into() }));
        let channel = agent.register();
        assert!(agent.is_registered(&channel.bytes()));
        assert!(!agent.is_registered(&channel.bytes()[..15]));
        assert!(!agent.is_registered(&[0u8; 16]));
        assert_eq!(agent.channel_count(), 1);
        let bytes = channel.bytes();
        drop(channel);
        assert!(!agent.is_registered(&bytes));
        assert_eq!(agent.channel_count(), 0);
    }
}
