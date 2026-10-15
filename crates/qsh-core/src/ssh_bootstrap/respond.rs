//! The remote half of `qsh pair ssh`: the hidden `qsh pair ssh-respond`
//! command (ADR-0044 decisions 9, 10, 12).
//!
//! The command is not an operation. Its stdout is the bootstrap stream
//! (`docs/design/protocol.md` §17) and its stdin is the client's `commit`;
//! no `qsh.cli/v1` envelope is written. The code here is generic over the
//! two streams so the same function serves the process's own stdin/stdout
//! and the in-memory pipes of the tests.
//!
//! One responder run is one conversation, in this order:
//!
//! 1. Read this device's identity (`identity/device.pem`). With none, say
//!    `not_initialized` and stop; the responder never creates an identity
//!    (decision 10).
//! 2. Probe the serve port with one UDP bind and close it again (decision
//!    10), then send the `hello`.
//! 3. Wait for the `commit` for [`MESSAGE_TIMEOUT`]. Nothing is written if
//!    it does not come, or if the client closes its end instead.
//! 4. Under the `trust.toml` lock: load, check, mutate, audit, save, in that
//!    order (decision 12). A pin is never written unless its audit record
//!    was.
//!
//! The streams carry public values only (fingerprints, pin names, roles).
//! Nothing read from the peer is logged: `tracing` gets stages and result
//! statuses, never a line or a field of one (decision 19).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::ssh_bootstrap::{
    BOOTSTRAP_LINE_MAX, BOOTSTRAP_VERSIONS, BootstrapLine, BootstrapResult, Commit, Hello,
    HelloStatus, ResultStatus, parse_ssh_bootstrap_line,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use super::MESSAGE_TIMEOUT;
use crate::audit::{AuditRecord, AuditSink};
use crate::config::{Config, Paths, now_rfc3339};
use crate::ops::{OpError, Ops};
use crate::trust::{TrustRole, TrustStore, normalize_peer_address, validate_peer_label};
use crate::{Fingerprint, Principal};

/// The audit `action` of a pin the responder wrote (ADR-0044 decision 9).
/// It names no operation: `qsh pair ssh-respond` is not one.
pub const AUDIT_ACTION: &str = "pair.ssh_respond";

/// How a responder run ended. The process exits 0 for every variant; only
/// an I/O failure on the streams is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespondEnd {
    /// No identity here. The `hello` said so and nothing was written.
    NotInitialized,
    /// No complete `commit` arrived within the deadline. Nothing was
    /// written.
    CommitTimedOut,
    /// The client closed its end without a `commit` (it found a conflict
    /// of its own, or gave up). Nothing was written.
    ClientClosed,
    /// A `result` was sent with this status.
    Answered(ResultStatus),
}

/// The responder, bound to one config tree and one audit sink.
pub struct Responder {
    paths: Paths,
    config: Config,
    audit: Arc<dyn AuditSink>,
    commit_timeout: Duration,
}

impl Responder {
    /// A responder over `paths` and `config`, recording to `audit`.
    pub fn new(paths: Paths, config: Config, audit: Arc<dyn AuditSink>) -> Self {
        Self {
            paths,
            config,
            audit,
            commit_timeout: MESSAGE_TIMEOUT,
        }
    }

    /// Replace the 30 s wait for the `commit` (ADR-0044 decision 16). The
    /// wait runs on tokio's clock, so a test pauses time instead of
    /// sleeping.
    pub fn with_commit_timeout(mut self, timeout: Duration) -> Self {
        self.commit_timeout = timeout;
        self
    }

    /// Run one conversation over `input` (the client's stream) and `output`
    /// (the responder's stream).
    ///
    /// The identity is read with [`crate::identity::read_identity`], which
    /// never opens the key store: the responder only needs the public
    /// fingerprint, and a prompt on the remote account's credential store
    /// has no terminal to answer it.
    pub async fn run<R, W>(&self, input: R, mut output: W) -> Result<RespondEnd, OpError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let identity = crate::identity::read_identity(&self.paths)?;
        let serve_spec = self
            .config
            .serve
            .bind
            .clone()
            .unwrap_or_else(|| crate::serve::DEFAULT_BIND.to_string());
        let hello = match &identity {
            None => Hello {
                versions: BOOTSTRAP_VERSIONS.to_vec(),
                qsh_version: env!("CARGO_PKG_VERSION").to_string(),
                status: HelloStatus::NotInitialized,
                fingerprint: None,
                serve_bind: None,
                serve_listening: None,
            },
            Some(identity) => Hello {
                versions: BOOTSTRAP_VERSIONS.to_vec(),
                qsh_version: env!("CARGO_PKG_VERSION").to_string(),
                status: HelloStatus::Ready,
                fingerprint: Some(identity.fingerprint.to_string()),
                serve_listening: serve_listening(&serve_spec),
                serve_bind: Some(serve_spec),
            },
        };
        send(&mut output, &BootstrapLine::Hello(hello)).await?;
        if identity.is_none() {
            tracing::info!(stage = "hello", status = "not_initialized", "ssh-respond");
            return Ok(RespondEnd::NotInitialized);
        }

        let line = match tokio::time::timeout(self.commit_timeout, read_line(input)).await {
            Err(_elapsed) => {
                tracing::info!(stage = "commit", outcome = "timed_out", "ssh-respond");
                return Ok(RespondEnd::CommitTimedOut);
            }
            Ok(line) => line?,
        };
        let result = match line {
            Line::Closed => {
                tracing::info!(stage = "commit", outcome = "client_closed", "ssh-respond");
                return Ok(RespondEnd::ClientClosed);
            }
            Line::TooLong => reject(
                "",
                ErrorCode::InvalidArgument,
                "the commit line is too long",
            ),
            Line::Complete(bytes) => match parse_ssh_bootstrap_line(&bytes) {
                Ok(BootstrapLine::Commit(commit)) => self.apply(&commit),
                Ok(_) => reject("", ErrorCode::InvalidArgument, "expected a commit message"),
                Err(_) => reject("", ErrorCode::InvalidArgument, "the commit is not valid"),
            },
        };
        let status = result.status.clone();
        tracing::info!(stage = "result", status = status.as_str(), "ssh-respond");
        send(&mut output, &BootstrapLine::Result(result)).await?;
        Ok(RespondEnd::Answered(status))
    }

    /// Validate a `commit` and, if it is new, write the pin. Every failure
    /// is a `result` of status `error`; nothing here returns an `Err`.
    fn apply(&self, commit: &Commit) -> BootstrapResult {
        if !BOOTSTRAP_VERSIONS.contains(&commit.version) {
            return reject(
                "",
                ErrorCode::Unsupported,
                "the commit names a bootstrap version this qsh does not speak",
            );
        }
        let fingerprint = match commit.fingerprint.parse::<Fingerprint>() {
            Ok(fingerprint) => fingerprint,
            Err(_) => {
                return reject(
                    "",
                    ErrorCode::InvalidArgument,
                    "the commit's fingerprint is not a sha256 fingerprint",
                );
            }
        };
        // The validators' messages name the rule that failed and never echo
        // the value.
        if let Err(err) = validate_peer_label(&commit.name) {
            return reject("", ErrorCode::InvalidArgument, &err.to_string());
        }
        let name = commit.name.as_str();
        let Ok(role) = commit.role.parse::<TrustRole>() else {
            return reject(
                name,
                ErrorCode::InvalidArgument,
                "the commit's role is not a trust role",
            );
        };
        let address = match commit.address.as_deref() {
            None => None,
            Some("") => {
                return reject(
                    name,
                    ErrorCode::InvalidArgument,
                    "the commit's address is empty",
                );
            }
            Some(address) => Some(normalize_peer_address(address).address),
        };

        match self.write_pin(name, address, fingerprint, role) {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(stage = "write", code = ?err.code, "ssh-respond");
                reject(name, err.code, &err.message)
            }
        }
    }

    /// lock, load, mutate, audit, save (ADR-0044 decision 12). The audit
    /// record is written after the in-memory change and before the save, so
    /// a failed audit leaves `trust.toml` untouched.
    fn write_pin(
        &self,
        name: &str,
        address: Option<String>,
        fingerprint: Fingerprint,
        role: TrustRole,
    ) -> Result<BootstrapResult, OpError> {
        let path = self.paths.trust_file();
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;

        let fingerprint_text = fingerprint.to_string();
        if let Some(existing) = store
            .peers()
            .iter()
            .find(|peer| peer.fingerprint == fingerprint_text)
        {
            return Ok(BootstrapResult {
                status: ResultStatus::Exists,
                name: existing.name.clone(),
                role: existing.role.clone(),
                created: false,
                code: None,
                message: None,
            });
        }
        if let Some(existing) = store.find(name) {
            return Ok(BootstrapResult {
                status: ResultStatus::Conflict,
                name: name.to_string(),
                role: None,
                created: false,
                code: Some(ErrorCode::SessionConflict),
                message: Some(format!(
                    "the name {name} is already pinned on this host with fingerprint {}",
                    existing.fingerprint
                )),
            });
        }

        let (peer, created, _updated) =
            store.add_peer_with_role(name, address, fingerprint, now_rfc3339(), role);
        debug_assert!(created, "the checks above leave only a new pin");
        let mut record = AuditRecord::local_op(
            AUDIT_ACTION,
            Principal::Device(peer.name.clone()).to_string(),
            peer.name.clone(),
        );
        record.role = Some(role.as_str().to_string());
        self.audit.record(&record).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("audit record could not be written; trust.toml left unchanged: {err}"),
            )
            .with_retryable(true)
        })?;
        store.save(&path)?;
        Ok(BootstrapResult {
            status: ResultStatus::Pinned,
            name: peer.name,
            role: Some(role.as_str().to_string()),
            created: true,
            code: None,
            message: None,
        })
    }
}

impl Ops {
    /// The responder for this tree's config, config file and audit sink
    /// (`qsh pair ssh-respond`, ADR-0044 decision 9). It is not an
    /// operation: no envelope, no `COMMAND` name.
    pub fn ssh_responder(&self) -> Result<Responder, OpError> {
        Ok(Responder::new(
            self.paths().clone(),
            self.config()?,
            self.audit_sink()?,
        ))
    }
}

/// A `result` of status `error`. `name` is empty unless the commit's name
/// already passed validation, so a peer-chosen string is never echoed.
fn reject(name: &str, code: ErrorCode, message: &str) -> BootstrapResult {
    BootstrapResult {
        status: ResultStatus::Error,
        name: name.to_string(),
        role: None,
        created: false,
        code: Some(code),
        message: Some(message.to_string()),
    }
}

async fn send<W: AsyncWrite + Unpin>(output: &mut W, line: &BootstrapLine) -> Result<(), OpError> {
    let text = line.encode_line().map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("cannot encode a bootstrap message: {err}"),
        )
    })?;
    let io_err = |err: io::Error| {
        OpError::new(
            ErrorCode::Internal,
            format!("cannot write the bootstrap stream: {err}"),
        )
    };
    output.write_all(text.as_bytes()).await.map_err(io_err)?;
    output.flush().await.map_err(io_err)
}

enum Line {
    /// One line without its `\n`; a trailing `\r` is left for the parser,
    /// which tolerates it.
    Complete(Vec<u8>),
    /// More than [`BOOTSTRAP_LINE_MAX`] bytes (plus the CR and LF) before a
    /// newline.
    TooLong,
    /// End of input before a full line.
    Closed,
}

/// Read one newline-terminated line, never buffering more than
/// [`BOOTSTRAP_LINE_MAX`] + 2 bytes of it.
async fn read_line<R: AsyncRead + Unpin>(input: R) -> Result<Line, OpError> {
    let limit = BOOTSTRAP_LINE_MAX as u64 + 2;
    let mut reader = BufReader::new(input).take(limit);
    let mut buf = Vec::new();
    let n = reader.read_until(b'\n', &mut buf).await.map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("cannot read the bootstrap stream: {err}"),
        )
    })?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(Line::Complete(buf));
    }
    if n as u64 >= limit {
        return Ok(Line::TooLong);
    }
    Ok(Line::Closed)
}

/// Whether something already holds the serve port (ADR-0044 decision 10):
/// `Some(true)` for "address in use", `Some(false)` for a bind that worked,
/// `None` for anything else, including a `spec` that does not resolve.
fn serve_listening(spec: &str) -> Option<bool> {
    let addr = resolve_spec(spec)?;
    probe_udp_bind(addr)
}

fn resolve_spec(spec: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs as _;
    spec.parse::<SocketAddr>()
        .ok()
        .or_else(|| spec.to_socket_addrs().ok()?.next())
}

/// Bind a UDP socket at `addr` and close it at once. The socket is shaped
/// like the serve listener's (dual-stack on an IPv6 wildcard), so the two
/// conflict exactly when `qsh serve` would fail to bind.
///
/// Unix only: the Windows probe needs `SO_EXCLUSIVEADDRUSE`, which comes
/// with the Windows responder in M20 (ADR-0044 decision 10).
pub(crate) fn probe_udp_bind(addr: SocketAddr) -> Option<bool> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    match socket.bind(&addr.into()) {
        Ok(()) => Some(false),
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => Some(true),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests;
