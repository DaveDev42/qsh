//! `exec.run` — client side of the walking skeleton (`docs/CLI.md` §6.8):
//! resolve `host` the same route-aware way `host.get`/attach do (issue #5:
//! a live reverse registration wins over a forward pin), dial or relay,
//! negotiate, run, and assemble the `ExecRunData` payload.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_proto::{ErrorCode, ExecRunData, ExecRunReq};
use qsh_transport::endpoint::is_crypto_failure;
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
        // `PLAN.md` M7 Step 7-2 carryover (ii)) instead of a fresh
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

    let addrs = until(deadline, resolver.resolve_all(address))
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
        DialError::Failed(inner) => !is_crypto_failure(inner),
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
        // (`PLAN.md` M7 Step 3 (a)-추기 ③): it can come from `hosts.toml`
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
        // `PLAN.md` M8 Step 2: the peer's `admission::Gate` refused an
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
            if is_crypto_failure(&inner) {
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
    if is_crypto_failure(err) {
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
            StreamError::Read(quinn_read) => match quinn_read {
                qsh_transport::ReadError::ConnectionLost(c) => connection_error_to_op(c),
                other => OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("stream read failed: {other}"),
                ),
            },
            StreamError::Write(quinn_write) => match quinn_write {
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
mod tests {
    use super::*;
    use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq};

    fn temp_ops() -> (tempfile::TempDir, Ops) {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::ops::Paths::new(dir.path().join("config"), dir.path().join("state"));
        (dir, Ops::new(paths))
    }

    /// M7 Step 7-2 carryover (ii), `PLAN.md`: `exec_run` must dial on
    /// `Ops`' shared [`crate::ops::Ops::connect_runtime`], not build a
    /// fresh `Builder::new_multi_thread()` per call — modeled on
    /// `ops/mod.rs`'s
    /// `connect_runtime_is_the_same_instance_across_calls_and_clones`,
    /// but pinned at `exec_run`'s own call site rather than at
    /// `connect_runtime()` directly, since a regression here would look
    /// identical from that test's point of view (both build *a* runtime,
    /// just not the *same* one).
    ///
    /// The dial itself is expected to fail — nothing listens on
    /// `127.0.0.1:1` — the point is only that `exec_run` reaches into
    /// `Ops::connect_runtime` on its way there, twice, and gets the same
    /// `Arc` both times.
    #[test]
    fn exec_run_shares_the_connect_runtime_across_calls() {
        let (_dir, ops) = temp_ops();
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        })
        .unwrap();
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"exec-run-shared-runtime-peer");
        ops.trust_add(TrustAddReq {
            name: "peer".into(),
            address: Some("127.0.0.1:1".into()),
            fingerprint: Some(fingerprint.to_string()),
            cert_pem: None,
        })
        .unwrap();

        assert!(
            ops.connect_runtime.get().is_none(),
            "constructing Ops must not build the dial runtime eagerly"
        );

        let req = || ExecRunReq {
            host: "peer".into(),
            argv: vec!["true".into()],
            env: vec![],
            timeout_ms: Some(500),
        };
        let _ = ops.exec_run(req(), ExecStdin::Closed);
        let first = ops
            .connect_runtime
            .get()
            .cloned()
            .expect("exec_run must build (and reuse) Ops' shared connect_runtime");

        let _ = ops.exec_run(req(), ExecStdin::Closed);
        let second = ops
            .connect_runtime
            .get()
            .cloned()
            .expect("the shared runtime must still be installed after a second exec_run");

        assert!(
            Arc::ptr_eq(&first, &second),
            "exec_run must share one Runtime across calls, not build a second one"
        );
    }

    /// Issue #4 item 2, end to end: `exec_async` itself — not
    /// `dial_first_reachable` driven directly (`ops::tests` already
    /// covers that in isolation) — must try every resolved address, not
    /// only the first. Drives `exec_async_resolving` (`exec_async`'s own
    /// production body, with only the resolve step swapped for a
    /// synthetic one, its `Resolver`-pattern seam) with two real,
    /// unreachable loopback UDP ports — bind-then-drop, the same
    /// technique `crates/qsh-cli/tests/reverse_unreachable_diagnostic.rs`
    /// uses — so this is a real `Dialer::dial` attempt against each, not
    /// a canned `DialError`. `with_timeout` keeps each attempt to well
    /// under a second instead of the production 10s default. A mutation
    /// that truncates the resolver's answer before the
    /// `dial_first_reachable` call inside `exec_async_resolving` reds
    /// this test: `attempted` would read 1 and the "(tried 2 addresses)"
    /// suffix `map_dial_error` appends would be absent from the message.
    #[tokio::test]
    async fn exec_async_tries_every_resolved_address_not_only_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::ops::Paths::new(dir.path().join("config"), dir.path().join("state"));
        let trust = crate::trust::SharedTrustStore::open(paths.trust_file()).unwrap();

        // A real generated identity (not an empty `LocalIdentity`): the
        // dial below must actually reach `Dialer::dial`'s socket
        // bind/connect, not fail earlier at TLS config construction —
        // that would report `DialError::Setup`, which
        // `map_dial_error`'s own doc comment excludes from the "(tried N
        // addresses)" suffix this test asserts on.
        crate::identity::init(&paths, qsh_proto::KeyStoreMode::File).unwrap();
        let local = crate::identity::load(&paths).unwrap().unwrap().local;
        let dialer = Dialer::new(local, trust as Arc<dyn qsh_transport::TrustEvaluator>)
            .with_timeout(Duration::from_millis(300));

        // Two real, unreachable loopback UDP ports: bind each to claim a
        // real, otherwise unused port, then drop the socket immediately
        // so nothing ever answers there.
        let unreachable_addr = || {
            let socket =
                std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a throwaway UDP port");
            socket.local_addr().expect("local addr")
        };
        let addrs = vec![unreachable_addr(), unreachable_addr()];

        struct StubResolver(Vec<std::net::SocketAddr>);
        impl crate::ops::AddressResolver for StubResolver {
            fn resolve_all<'a>(&'a self, _address: &'a str) -> crate::ops::ResolveFuture<'a> {
                let addrs = self.0.clone();
                Box::pin(async move { Ok(addrs) })
            }
        }

        let spec = ExecSpec {
            argv: vec!["true".into()],
            env: vec![],
            timeout: None,
        };

        let err = exec_async_resolving(
            &dialer,
            "does-not-matter:4433",
            "widget",
            "device",
            &spec,
            ExecStdin::Closed,
            None,
            &StubResolver(addrs),
        )
        .await
        .expect_err("two unreachable loopback ports must never dial successfully");

        assert!(
            err.message.contains("tried 2 addresses"),
            "message must name both attempts, not just the first (i.e. exec_async_resolving \
             must not have been reverted to trying only `addrs[0]`): {}",
            err.message
        );
    }

    #[test]
    fn well_formed_unknown_codes_pass_through_malformed_ones_do_not() {
        let ok = map_client_error(ClientError::Remote {
            code: ErrorCode::Unknown("SOME_FUTURE_CODE".into()),
            message: "m".into(),
            retryable: true,
        });
        assert_eq!(ok.code, ErrorCode::Unknown("SOME_FUTURE_CODE".into()));
        assert!(ok.retryable);

        for raw in [
            "",
            "lowercase",
            "HAS SPACE",
            "ESC\u{1b}[31mRED",
            "한글",
            "9STARTS_WITH_DIGIT",
            &"X".repeat(65),
        ] {
            let bad = map_client_error(ClientError::Remote {
                code: ErrorCode::Unknown(raw.into()),
                message: "m".into(),
                retryable: false,
            });
            assert_eq!(bad.code, ErrorCode::RemoteError, "raw={raw:?}");
            assert_eq!(bad.details["raw_code"], raw);
        }
    }

    #[test]
    fn timeout_error_is_retryable_and_carries_the_budget() {
        let err = timeout_error(Duration::from_millis(1500));
        assert_eq!(err.code, ErrorCode::Timeout);
        assert!(err.retryable);
        assert_eq!(err.details["timeout_ms"], 1500);
    }

    /// Issue #5's routing change (`resolve_exec_route`/
    /// `resolve_host_route_with`) moved where `exec_run` learns a name has
    /// no configuration at all, at the exact seam that decides it:
    /// `exec_run` must answer `CONFIG_ERROR` before it ever routes, even
    /// for a name that is configured nowhere at all — proving the order is
    /// "identity, then routing" rather than "routing, then identity for
    /// whichever branch happens to need it". A device that never ran `qsh
    /// init` has no identity to build either the forward `PeerTarget` or
    /// the reverse `LocalRoute` with, and the frozen `error.CONFIG_ERROR.json`
    /// fixture (`qsh exec HOST_ALIAS`, `crates/qsh-cli/tests/fixtures.rs`)
    /// and `exit_code_matrix.rs`'s "exec: no device identity" row both pin
    /// this same order for a *configured* name; this pins it independently
    /// for one that is not, so a regression that moved identity-loading
    /// behind `resolve_host_route_with` (which would answer `HOST_NOT_FOUND`
    /// for this name well before any identity check) cannot hide behind
    /// "only the configured-name fixture is checked".
    #[test]
    fn exec_run_answers_config_error_before_routing_even_for_an_unconfigured_name() {
        let (_dir, ops) = temp_ops(); // never `identity_init`'d.
        let err = ops
            .exec_run(
                ExecRunReq {
                    host: "nowhere-at-all".into(),
                    argv: vec!["true".into()],
                    env: vec![],
                    timeout_ms: None,
                },
                ExecStdin::Closed,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError, "{err:?}");
    }

    /// `resolve_exec_route`'s "wholly unconfigured" branch must keep
    /// `qsh exec`'s own frozen legacy wording
    /// (`host::not_in_trust_store_host_not_found`, extracted verbatim from
    /// the pre-issue-#5 `resolve_peer_address` this replaces) rather than
    /// the longer, newer wording `Ops::resolve_host_route` gives every
    /// other caller (`host::unconfigured_host_not_found`) — the
    /// append-only `error.HOST_NOT_FOUND.json` fixture (`qsh exec nowhere`)
    /// compares this message byte for byte.
    #[test]
    fn exec_host_not_found_keeps_the_frozen_text_for_a_wholly_unconfigured_name() {
        let (_dir, ops) = temp_ops();
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        })
        .unwrap();
        let identity = ops.load_identity().unwrap().expect("just initialized");

        // `PeerRoute` (the `Ok` side) has no `Debug` impl, so this matches
        // by hand rather than `.unwrap_err()`.
        let err = match ops.resolve_exec_route("nowhere", identity) {
            Err(err) => err,
            Ok(_) => panic!("an unconfigured name must not route anywhere"),
        };
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert_eq!(
            err.message,
            host::not_in_trust_store_host_not_found("nowhere").message,
            "exec's own frozen wording must be used, not resolve_host_route's newer one"
        );
    }

    /// The other exec-specific branch `resolve_exec_route` must get right:
    /// a trust-store pin with no address and no reverse registration is
    /// `pinned_without_address_host_not_found` — the truthful wording
    /// issue #5 gives every caller of `Ops::resolve_host_route`'s shared
    /// routing, replacing the pre-#5 `resolve_peer_address`'s false "is
    /// not in the trust store" for this exact shape (the host *is* pinned;
    /// see issue #5's reverse-only counterpart,
    /// `exec_run_reaches_a_reverse_only_host_pinned_without_address` in
    /// `crates/qsh-testkit/tests/reverse_exec.rs`).
    #[test]
    fn exec_host_not_found_names_a_pinned_host_without_address_truthfully() {
        let (_dir, ops) = temp_ops();
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        })
        .unwrap();
        let identity = ops.load_identity().unwrap().expect("just initialized");
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"exec-pinned-no-address-peer");
        ops.trust_add(TrustAddReq {
            name: "phone".into(),
            address: None,
            fingerprint: Some(fingerprint.to_string()),
            cert_pem: None,
        })
        .unwrap();

        let err = match ops.resolve_exec_route("phone", identity) {
            Err(err) => err,
            Ok(_) => panic!("a pinned-but-addressless host must not route anywhere"),
        };
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert_eq!(
            err.message,
            host::pinned_without_address_host_not_found("phone").message,
            "a pinned-but-addressless host must not be told it is unpinned"
        );
    }

    /// The `user@`-prefix branch, exercised through `exec_run`'s own
    /// `resolve_exec_route` rather than the shared `host::resolve_route`
    /// unit tests (`ops/host/tests.rs`) — this file's module doc in
    /// `qsh-testkit/tests/reverse_exec.rs` used to claim this split was
    /// unit tested against `Ops::resolve_exec_route` when no such test
    /// existed. `"dave@phone"` with `phone` pinned must give the same
    /// `user_prefix_not_accepted_host_not_found` wording every other
    /// caller of `Ops::resolve_host_route`'s routing gets — that branch
    /// is shared, unlike the "wholly unconfigured" wording above.
    #[test]
    fn exec_host_not_found_names_a_pinned_alias_behind_a_user_prefix() {
        let (_dir, ops) = temp_ops();
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        })
        .unwrap();
        let identity = ops.load_identity().unwrap().expect("just initialized");
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"exec-user-prefix-peer");
        ops.trust_add(TrustAddReq {
            name: "phone".into(),
            address: None,
            fingerprint: Some(fingerprint.to_string()),
            cert_pem: None,
        })
        .unwrap();

        let err = match ops.resolve_exec_route("dave@phone", identity) {
            Err(err) => err,
            Ok(_) => panic!("a user@-prefixed positional must not route anywhere"),
        };
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert_eq!(
            err.message,
            host::user_prefix_not_accepted_host_not_found("phone").message,
            "a configured alias behind a user@ prefix must name the prefix problem, not \
             pretend the alias itself is unconfigured"
        );
    }

    /// The `user@`-prefix branch's other side: `"dave@nowhere"` where
    /// `nowhere` is configured nowhere at all still falls through to
    /// exec's own frozen legacy text (same wording as the bare-alias case
    /// above), because the prefix check only fires once `display_name` is
    /// found in the trust store or `hosts.toml` (`host::resolve_route`'s
    /// own doc) — an unconfigured name behind a prefix is exactly as
    /// unconfigured as one without it.
    #[test]
    fn exec_host_not_found_keeps_the_frozen_text_for_a_user_prefixed_unconfigured_name() {
        let (_dir, ops) = temp_ops();
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        })
        .unwrap();
        let identity = ops.load_identity().unwrap().expect("just initialized");

        let err = match ops.resolve_exec_route("dave@nowhere", identity) {
            Err(err) => err,
            Ok(_) => panic!("a user@-prefixed unconfigured name must not route anywhere"),
        };
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert_eq!(
            err.message,
            host::not_in_trust_store_host_not_found("nowhere").message,
            "an unconfigured name behind a user@ prefix keeps exec's frozen bare-alias wording"
        );
    }
}
