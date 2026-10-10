//! `exec.run` — client side of the walking skeleton (`docs/CLI.md` §6.8):
//! resolve `host` the same route-aware way `host.get`/attach do (issue #5:
//! a live reverse registration wins over a forward pin), dial or relay,
//! negotiate, run, and assemble the `ExecRunData` payload.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_proto::{ErrorCode, ExecRunData, ExecRunReq};
use qsh_transport::{ConnectionError, DialError, Dialer, StreamError};

use crate::client::{ClientError, Session};
use crate::exec::ExecSpec;
use crate::identity::LoadedIdentity;
use crate::ops::host::{self, HostRoute};
use crate::ops::{LocalRoute, OpError, Operation, Ops, PeerRoute, PeerTarget, server_name_for};

/// The `exec.run` operation.
pub struct ExecRunOp;

impl Operation for ExecRunOp {
    const COMMAND: &'static str = "exec.run";
}

/// Result of [`Ops::exec_run`]: the JSON payload plus the raw output
/// bytes, so a human-mode frontend can pass them through verbatim without
/// re-decoding the Base64 it never asked for.
#[derive(Debug, Clone)]
pub struct ExecRunOutput {
    /// The `exec.run` envelope payload (`docs/CLI.md` §6.8).
    pub data: ExecRunData,
    /// Raw remote stdout.
    pub stdout: Vec<u8>,
    /// Raw remote stderr.
    pub stderr: Vec<u8>,
}

/// Where the remote command's stdin comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStdin {
    /// Send EOF immediately (e.g. stdin is a terminal).
    Closed,
    /// Stream this process's stdin to the remote command until EOF.
    Inherit,
}

impl Ops {
    /// Run a command on `req.host` and collect its output — route-aware
    /// since issue #5: a live reverse registration held by this machine's
    /// `qsh listen` daemon wins over a forward (`hosts.toml`/trust-store)
    /// pin, the same [`Ops::resolve_host_route`] priority `host.get` and
    /// attach already apply (`docs/CLI.md` §6.1).
    ///
    /// Blocking: runs on `Ops`' shared dial runtime
    /// (`Ops::connect_runtime`) so frontends stay synchronous. The
    /// identity is loaded **before** routing, not just before entering the
    /// runtime: `qsh exec` on an uninitialized device must fail
    /// `CONFIG_ERROR`, never `HOST_NOT_FOUND`, for an unconfigured name —
    /// the frozen `error.CONFIG_ERROR.json` fixture and
    /// `exit_code_matrix.rs`'s "exec: no device identity" row both pin
    /// this order (a platform key store must not be touched from within
    /// a runtime either way, which is the other reason this happens
    /// up front). The forward branch below reuses this one loaded
    /// identity to build its `PeerTarget` rather than loading it a
    /// second time through `Ops::resolve_peer`.
    pub fn exec_run(&self, req: ExecRunReq, stdin: ExecStdin) -> Result<ExecRunOutput, OpError> {
        if req.argv.is_empty() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "exec requires a command after `--`",
            ));
        }
        let identity = self.load_identity()?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
        })?;

        let spec = ExecSpec {
            argv: req.argv.clone(),
            env: req
                .env
                .iter()
                .map(|e| (e.name.clone(), e.value.clone()))
                .collect(),
            timeout: req.timeout_ms.map(Duration::from_millis),
        };
        let timeout = req.timeout_ms.map(Duration::from_millis);

        // Shared with every other dial op (`ops/mod.rs::connect_runtime`,
        // M7 plan Step 7-2 (69dd788) carryover (ii)) instead of a fresh
        // `Builder::new_multi_thread()` per call — one exec after another
        // (or an exec alongside a live pull) no longer pays for a second
        // multi-thread runtime it never needed.
        let runtime = self.connect_runtime()?;
        match self.resolve_exec_route(&req.host, identity)? {
            PeerRoute::Forward(target) => {
                let device_name = target.identity.identity.device_id.clone();
                let dialer = Dialer::new(
                    target.identity.local,
                    target.trust as Arc<dyn qsh_transport::TrustEvaluator>,
                );
                runtime.block_on(exec_async(
                    &dialer,
                    &target.address,
                    &target.server_name,
                    &device_name,
                    &spec,
                    stdin,
                    timeout,
                ))
            }
            #[cfg(unix)]
            PeerRoute::Reverse(route) => {
                runtime.block_on(exec_async_reverse(&route, &spec, stdin, timeout))
            }
            // Windows twin of `Ops::connect_reverse` (`ops/session.rs`):
            // `Ops::resolve_host_route` never actually produces
            // `HostRoute::Reverse` there (`host::reverse_host_entries_async`
            // always returns empty), so this is unreachable in practice —
            // kept only so the match compiles on every platform.
            #[cfg(not(unix))]
            PeerRoute::Reverse(_route) => Err(OpError::new(
                ErrorCode::Unsupported,
                "reverse routing (localctl) is not available on this platform",
            )),
        }
    }

    /// [`Ops::resolve_route`] (`ops/mod.rs`), specialized for `exec_run`:
    /// same routing decision (`Ops::resolve_host_route`'s live-reverse-
    /// first priority), but built from an **already-loaded** `identity`
    /// instead of calling [`Ops::resolve_peer`] a second time on the
    /// forward branch (which would reload it, touching the platform key
    /// store twice for one call) — and with `host::not_in_trust_store_host_not_found`
    /// as the "wholly unconfigured" branch's wording, `qsh exec`'s own
    /// frozen legacy text (`error.HOST_NOT_FOUND.json`), rather than
    /// [`Ops::resolve_host_route`]'s newer, longer wording every other
    /// caller of that routing gets.
    fn resolve_exec_route(
        &self,
        host: &str,
        identity: LoadedIdentity,
    ) -> Result<PeerRoute, OpError> {
        match self.resolve_host_route_with(host, host::not_in_trust_store_host_not_found)? {
            HostRoute::Forward { address, .. } => {
                let trust = self.open_trust()?;
                let server_name = server_name_for(&address);
                Ok(PeerRoute::Forward(PeerTarget {
                    identity,
                    trust,
                    address,
                    server_name,
                }))
            }
            HostRoute::Reverse { socket, .. } => Ok(PeerRoute::Reverse(LocalRoute {
                host: host.to_string(),
                socket,
            })),
        }
    }
}

/// `TIMEOUT` as the contract words it (`docs/CLI.md` §6.8, §9): the remote
/// process (group) has been killed — by the host on its own copy of the
/// deadline, or as a consequence of this client dropping the connection.
fn timeout_error(timeout: Duration) -> OpError {
    OpError::new(
        ErrorCode::Timeout,
        format!(
            "exec did not complete within {} ms; the remote command was killed",
            timeout.as_millis()
        ),
    )
    .with_retryable(true)
    .with_details(serde_json::json!({ "timeout_ms": timeout.as_millis() as u64 }))
}

/// Await `fut` with an optional wall-clock deadline (absolute, so several
/// phases can share one budget).
async fn until<T>(
    deadline: Option<tokio::time::Instant>,
    fut: impl std::future::Future<Output = T>,
) -> Option<T> {
    match deadline {
        Some(d) => tokio::time::timeout_at(d, fut).await.ok(),
        None => Some(fut.await),
    }
}

async fn exec_async(
    dialer: &Dialer,
    address: &str,
    server_name: &str,
    device_name: &str,
    spec: &ExecSpec,
    stdin: ExecStdin,
    timeout: Option<Duration>,
) -> Result<ExecRunOutput, OpError> {
    exec_async_resolving(
        dialer,
        address,
        server_name,
        device_name,
        spec,
        stdin,
        timeout,
        &crate::ops::SystemResolver,
    )
    .await
}

/// [`exec_async`], with the resolve step seamed out behind `resolver` —
/// issue #4 item 2's stub-resolver seam
/// ([`crate::ops::AddressResolver`], modeled on
/// `crates/qsh-core/src/tunnel/dial.rs`'s `Resolver`). Production always
/// calls [`exec_async`], which passes [`crate::ops::SystemResolver`]; a
/// test can pass a synthetic resolver instead and prove this function
/// itself — not a hand-rolled copy of
/// [`crate::ops::dial_first_reachable`] — tries every resolved address,
/// not only the first
/// (`exec_async_tries_every_resolved_address_not_only_the_first`).
#[allow(clippy::too_many_arguments)]
async fn exec_async_resolving(
    dialer: &Dialer,
    address: &str,
    server_name: &str,
    device_name: &str,
    spec: &ExecSpec,
    stdin: ExecStdin,
    timeout: Option<Duration>,
    resolver: &dyn crate::ops::AddressResolver,
) -> Result<ExecRunOutput, OpError> {
    // One budget for everything the user is waiting on: resolve, dial,
    // negotiate, run. The connection teardown afterwards is *not* under it —
    // a command that finished in time must not be reported as TIMEOUT
    // because the close handshake was slow.
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t);
    let timed_out = || timeout_error(timeout.unwrap_or_default());

    let addrs = until(deadline, crate::ops::resolve_all_with(resolver, address))
        .await
        .ok_or_else(timed_out)??;
    let dialed = until(
        deadline,
        crate::ops::dial_first_reachable(&addrs, |addr| dialer.dial(addr, server_name)),
    )
    .await
    .ok_or_else(timed_out)?
    .map_err(|(err, attempted)| map_dial_error(err, address, attempted))?;
    let endpoint = dialed.endpoint.clone();
    let connection = dialed.connection.clone();

    let stdin_reader: Option<Box<dyn tokio::io::AsyncRead + Send + Unpin>> = match stdin {
        ExecStdin::Closed => None,
        ExecStdin::Inherit => Some(Box::new(tokio::io::stdin())),
    };
    let run = async {
        match Session::negotiate(dialed.connection, device_name).await {
            Ok(mut session) => {
                // No kill-switch out-param on the forward route: a timeout
                // here is handled below by closing the whole `connection`
                // instead (unlike the reverse route, this connection is
                // this one exec's alone, and closing it reaches through to
                // its stdin-pump task's held stream regardless of which
                // task currently owns it).
                let result = session.exec(spec, stdin_reader, None).await;
                session.close();
                result
            }
            Err(err) => Err(err),
        }
    };
    let result = match until(deadline, run).await {
        Some(result) => result.map_err(map_client_error),
        None => {
            // Deadline hit mid-flight: `run` (and with it the session) was
            // dropped. Close explicitly so the host sees the peer go away
            // now — it kills the command on that signal — rather than at
            // its idle timeout.
            connection.close(0, b"timeout");
            Err(timed_out())
        }
    };
    // Idempotent: covers the negotiate-failed path (no session to close)
    // and drops our own handle so `wait_idle` cannot wait on us.
    connection.close(0, b"done");
    drop(connection);
    endpoint.wait_idle().await;
    let result = result?;
    if result.timed_out {
        // The host enforced the same deadline first and told us so.
        return Err(timed_out());
    }
    let data = ExecRunData {
        stdout_b64: BASE64.encode(&result.stdout),
        stderr_b64: BASE64.encode(&result.stderr),
        remote_exit_code: result.exit_code,
        signal: result.signal,
        duration_ms: u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
    };
    Ok(ExecRunOutput {
        data,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

/// [`exec_async`]'s reverse-route twin (issue #5): relay through this
/// machine's resident `qsh listen` daemon instead of dialing the peer
/// directly, under the same single `--timeout` deadline `exec_async`
/// itself uses for resolve+dial+negotiate+run. `dial_reverse` opens a
/// fresh `LOCAL_CONTROL` conduit to `route`'s daemon/host (the same one
/// `Ops::connect_reverse` uses, `ops/session.rs`), and `Session::exec`
/// then relays `EXEC_DATA` over a fresh `LOCAL_STREAM` conduit to the
/// same daemon (`Session::open_data_link`, issue #5's daemon `EXEC_DATA`
/// relay, `crate::localctl::daemon::local_stream_relay_kind`).
///
/// Unlike the forward route, there is no QUIC `Connection` here for a
/// timeout to force-close: the CLI process is not itself a QUIC endpoint
/// on the reverse route. `exec`'s `kill_tx` out-parameter is exactly the
/// substitute — a [`crate::client::link::DataKillSwitch`] shuts the
/// `LOCAL_STREAM` conduit's raw fd down at the OS level the instant the
/// deadline hits, regardless of which task (`Session::exec`'s own stdin
/// pump, `crate::client::pump_stdin`, moves the send half into a detached
/// `tokio::spawn`) currently holds the async wrapper around it — dropping
/// the cancelled `run` future alone would not reach that fd promptly. The
/// daemon's own EXEC_DATA UDS-EOF→reset rule then resets the target's
/// stream, and the host kills the command, exactly like the forward
/// route's `connection.close(0, b"timeout")` does over QUIC.
#[cfg(unix)]
async fn exec_async_reverse(
    route: &LocalRoute,
    spec: &ExecSpec,
    stdin: ExecStdin,
    timeout: Option<Duration>,
) -> Result<ExecRunOutput, OpError> {
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t);
    let timed_out = || timeout_error(timeout.unwrap_or_default());

    let mut session = match until(deadline, crate::ops::session::dial_reverse(route)).await {
        Some(dialed) => dialed?.0,
        None => return Err(timed_out()),
    };

    let stdin_reader: Option<Box<dyn tokio::io::AsyncRead + Send + Unpin>> = match stdin {
        ExecStdin::Closed => None,
        ExecStdin::Inherit => Some(Box::new(tokio::io::stdin())),
    };

    let (kill_tx, kill_rx) = tokio::sync::oneshot::channel();
    let result = match until(deadline, session.exec(spec, stdin_reader, Some(kill_tx))).await {
        Some(result) => result.map_err(map_client_error),
        None => {
            // Deadline hit mid-flight: shut the data conduit down right
            // now (see this function's own doc on why dropping `run`
            // alone would not) so the host notices and kills the command
            // rather than running on as a silent orphan. `kill_rx` closes
            // with no value when the deadline hit before the data link
            // even opened (still inside `exec_start`'s control round
            // trip) — nothing was relaying yet, so there is nothing to
            // kill.
            if let Ok(kill) = kill_rx.await {
                kill.kill();
            }
            Err(timed_out())
        }
    };
    // Idempotent-in-effect (a no-op `ControlLink::Local::finish`, then
    // drop): covers the exec-failed path too, and there is no connection
    // to `wait_idle` on for this route (this function's own doc).
    session.close();
    let result = result?;
    if result.timed_out {
        // The host enforced the same deadline first and told us so.
        return Err(timed_out());
    }
    let data = ExecRunData {
        stdout_b64: BASE64.encode(&result.stdout),
        stderr_b64: BASE64.encode(&result.stderr),
        remote_exit_code: result.exit_code,
        signal: result.signal,
        duration_ms: u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
    };
    Ok(ExecRunOutput {
        data,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

fn auth_failed(category: &str) -> OpError {
    OpError::new(
        ErrorCode::AuthFailed,
        "peer authentication failed (mutual TLS)",
    )
    .with_retryable(false)
    .with_details(serde_json::json!({ "category": category }))
}

/// Map a dial failure to the CLI vocabulary (`docs/CLI.md` §6.11 error
/// paths). `attempted` is how many resolved addresses
/// [`crate::ops::dial_first_reachable`] tried before `err` (its last
/// failure) gave up; when more than one address was tried *and* `err` is
/// a reachability-class failure (`Refused`/`Timeout`/`Connect`, or
/// `Failed` that is not itself a crypto failure), the count is appended
/// to the message so an operator sees this was not a single-address
/// failure. A `Setup` failure or an auth-class rejection
/// (`LocalRejected`/`RemoteRejected`, or a crypto-class `Failed`) never
/// gets the suffix: those are local/identity problems that have nothing
/// to do with how many *addresses* were tried, so naming an attempt
/// count next to them would misleadingly imply a reachability issue —
/// the single-address case (`attempted == 1`, every existing caller
/// before issue #4 item 2) stays byte-identical to the pinned
/// `crates/qsh-cli/tests/fixtures/cli-v1/error.CONNECTION_FAILED.json`
/// either way.
pub(crate) fn map_dial_error(err: DialError, address: &str, attempted: usize) -> OpError {
    let reachability_class = match &err {
        DialError::Refused | DialError::Timeout(_) | DialError::Connect(_) => true,
        DialError::Failed(inner) => !inner.is_crypto_failure(),
        DialError::LocalRejected { .. } | DialError::RemoteRejected | DialError::Setup(_) => false,
    };
    let mut op_err = map_dial_error_inner(err, address);
    if attempted > 1 && reachability_class {
        op_err.message = format!("{} (tried {attempted} addresses)", op_err.message);
    }
    op_err
}

fn map_dial_error_inner(err: DialError, address: &str) -> OpError {
    match err {
        // `address` no longer implies a trust store pin for this host
        // (M7 plan Step 3 (a)-추기 ③ (69dd788)): it can come from `hosts.toml`
        // alone, naming a host trust.toml has never heard of. So a
        // locally-rejected certificate here can be either a *mismatch*
        // (the peer answering doesn't match a pin that does exist) or a
        // *missing pin* (no pin exists at all for whatever fingerprint
        // answered) — this function can't tell which from `DialError`
        // alone, and doesn't need to: both map to the same coarse
        // AUTH_FAILED category (`docs/CLI.md` §6.11 documents this
        // uniformly, verifier-confirmed no contract change needed here).
        DialError::LocalRejected { reason, .. } => {
            auth_failed(&format!("{reason:?}").to_lowercase())
        }
        DialError::RemoteRejected => auth_failed("remote_rejected"),
        // M8 plan Step 2 (52639fc): the peer's `admission::Gate` refused an
        // already address-validated attempt at its concurrency cap.
        // *Same* `ErrorCode::ConnectionFailed`/`retryable: true` as
        // `DialError::Failed` below — only the human message differs
        // (`qsh_transport::DialError::Refused`'s own doc) — so
        // `qsh.cli/v1`'s `code`/`retryable` are unchanged by this arm
        // existing.
        // `DialError::Refused` carries no fields, so a fresh value's own
        // `Display` (its `#[error(...)]` text) is used rather than
        // `err.to_string()` — `err` is already consumed by this `match`,
        // and this way the message can never drift from the transport
        // crate's own wording without a compile-visible edit right here.
        DialError::Refused => {
            OpError::new(ErrorCode::ConnectionFailed, DialError::Refused.to_string())
        }
        DialError::Timeout(t) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("no response from {address} within {t:?}"),
        ),
        DialError::Failed(inner) => {
            if inner.is_crypto_failure() {
                auth_failed("remote_rejected")
            } else {
                OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("connection to {address} failed: {inner}"),
                )
            }
        }
        DialError::Connect(inner) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot connect to {address}: {inner}"),
        ),
        DialError::Setup(inner) => {
            OpError::new(ErrorCode::Internal, format!("transport setup: {inner}"))
        }
    }
}

fn connection_error_to_op(err: &ConnectionError) -> OpError {
    if err.is_crypto_failure() {
        auth_failed("remote_rejected")
    } else {
        OpError::new(
            ErrorCode::ConnectionFailed,
            format!("connection lost: {err}"),
        )
    }
}

/// Map a client protocol error to the CLI vocabulary. Remote codes pass
/// through verbatim (one vocabulary, no translation table).
/// A code string a peer sent that this build does not know is passed
/// through (`docs/CLI.md` §5.3: unknown codes are handled as generic QSH
/// errors) — but only if it *looks like* a code. Anything else is
/// peer-controlled garbage and must not land verbatim in our `error.code`.
fn well_formed_unknown_code(raw: &str) -> bool {
    let mut chars = raw.chars();
    raw.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// `pub` (not `pub(crate)`) so `qsh-testkit`'s integration tests can chain
/// it onto [`crate::client::map_hello_error`] and assert what a denied
/// `qsh reverse` registration actually maps to — the exact chain
/// `reverse::target::dial_and_register` applies — without re-deriving the
/// mapping table in test code.
pub fn map_client_error(err: ClientError) -> OpError {
    match err {
        ClientError::Remote {
            code: ErrorCode::Unknown(raw),
            message,
            retryable,
        } if !well_formed_unknown_code(&raw) => OpError::new(
            ErrorCode::RemoteError,
            format!("peer reported a malformed error code: {message}"),
        )
        .with_retryable(retryable)
        .with_details(serde_json::json!({ "raw_code": raw })),
        ClientError::Remote {
            code,
            message,
            retryable,
        } => OpError::new(code, message).with_retryable(retryable),
        ClientError::Unsupported(msg) => OpError::new(ErrorCode::Unsupported, msg),
        ClientError::Protocol(msg) => OpError::new(
            ErrorCode::RemoteError,
            format!("peer protocol violation: {msg}"),
        ),
        ClientError::HelloTimeout => OpError::new(
            ErrorCode::ConnectionFailed,
            "peer did not complete the handshake in time",
        ),
        ClientError::OutputTooLarge { limit } => OpError::new(
            ErrorCode::ResourceExhausted,
            format!(
                "remote command produced more than {limit} bytes of output; \
                 exec.run buffers the whole output — use a session (M2) for streaming"
            ),
        )
        .with_details(serde_json::json!({ "limit_bytes": limit })),
        ClientError::Connection(inner) => connection_error_to_op(&inner),
        ClientError::Stream(inner) => match &inner {
            StreamError::Read(read) => match read {
                qsh_transport::ReadError::ConnectionLost(c) => connection_error_to_op(c),
                other => OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("stream read failed: {other}"),
                ),
            },
            StreamError::Write(write) => match write {
                qsh_transport::WriteError::ConnectionLost(c) => connection_error_to_op(c),
                other => OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("stream write failed: {other}"),
                ),
            },
            StreamError::Frame(_) | StreamError::Decode(_) | StreamError::Truncated { .. } => {
                OpError::new(
                    ErrorCode::RemoteError,
                    format!("peer protocol violation: {inner}"),
                )
            }
            StreamError::Encode(_) | StreamError::Close(_) => {
                OpError::new(ErrorCode::Internal, inner.to_string())
            }
        },
    }
}

#[cfg(test)]
mod tests;
