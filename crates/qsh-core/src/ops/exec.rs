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
    /// Blocking: builds a runtime internally so frontends stay synchronous.
    /// The identity is loaded before entering the runtime (platform key
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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?;
        let timeout = req.timeout_ms.map(Duration::from_millis);
        let result = runtime.block_on(exec_async(
            &dialer,
            &address,
            &server_name,
            &device_name,
            &spec,
            stdin,
            timeout,
        ));
        // Let in-flight QUIC close frames drain (bounded).
        runtime.shutdown_timeout(Duration::from_millis(200));
        result
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
    // One budget for everything the user is waiting on: resolve, dial,
    // negotiate, run. The connection teardown afterwards is *not* under it —
    // a command that finished in time must not be reported as TIMEOUT
    // because the close handshake was slow.
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t);
    let timed_out = || timeout_error(timeout.unwrap_or_default());

    let addr = until(deadline, tokio::net::lookup_host(address))
        .await
        .ok_or_else(timed_out)?
        .ok()
        .and_then(|mut it| it.next())
        .ok_or_else(|| {
            OpError::new(
                ErrorCode::ConnectionFailed,
                format!("cannot resolve {address:?}"),
            )
        })?;
    let dialed = until(deadline, dialer.dial(addr, server_name))
        .await
        .ok_or_else(timed_out)?
        .map_err(|err| map_dial_error(err, address))?;
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

/// Map a dial failure to the CLI vocabulary (`docs/CLI.md` §6.11 error paths).
pub(crate) fn map_dial_error(err: DialError, address: &str) -> OpError {
    match err {
        // The host is in our trust store (that is how we got its address),
        // so a locally-rejected certificate is a *mismatch*, not a missing
        // pin: AUTH_FAILED with a coarse category only.
        DialError::LocalRejected { reason, .. } => {
            auth_failed(&format!("{reason:?}").to_lowercase())
        }
        DialError::RemoteRejected => auth_failed("remote_rejected"),
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
