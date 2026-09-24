//! `exec.run` — client side of the walking skeleton (`docs/CLI.md` §6.8):
//! resolve host through the trust store, dial with mutual TLS, negotiate,
//! run, and assemble the `ExecRunData` payload.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_proto::{ErrorCode, ExecRunData, ExecRunReq};
use qsh_transport::endpoint::is_crypto_failure;
use qsh_transport::{ConnectionError, DialError, Dialer, StreamError};

use crate::client::{ClientError, Session};
use crate::exec::ExecSpec;
use crate::ops::{OpError, Operation, Ops, PeerTarget};

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
    /// Run a command on a pinned host and collect its output.
    ///
    /// Blocking: runs on `Ops`' shared dial runtime
    /// (`Ops::connect_runtime`) so frontends stay synchronous. The
    /// identity is loaded before entering the runtime (platform key
    /// stores must not be touched from within one).
    pub fn exec_run(&self, req: ExecRunReq, stdin: ExecStdin) -> Result<ExecRunOutput, OpError> {
        if req.argv.is_empty() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "exec requires a command after `--`",
            ));
        }
        let PeerTarget {
            identity,
            trust,
            address,
            server_name,
        } = self.resolve_peer(&req.host)?;

        let spec = ExecSpec {
            argv: req.argv.clone(),
            env: req
                .env
                .iter()
                .map(|e| (e.name.clone(), e.value.clone()))
                .collect(),
            timeout: req.timeout_ms.map(Duration::from_millis),
        };
        let device_name = identity.identity.device_id.clone();
        let dialer = Dialer::new(
            identity.local,
            trust as Arc<dyn qsh_transport::TrustEvaluator>,
        );
        // Shared with every other dial op (`ops/mod.rs::connect_runtime`,
        // `PLAN.md` M7 Step 7-2 carryover (ii)) instead of a fresh
        // `Builder::new_multi_thread()` per call — one exec after another
        // (or an exec alongside a live pull) no longer pays for a second
        // multi-thread runtime it never needed.
        let runtime = self.connect_runtime()?;
        let timeout = req.timeout_ms.map(Duration::from_millis);
        runtime.block_on(exec_async(
            &dialer,
            &address,
            &server_name,
            &device_name,
            &spec,
            stdin,
            timeout,
        ))
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
                let result = session.exec(spec, stdin_reader).await;
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
}
