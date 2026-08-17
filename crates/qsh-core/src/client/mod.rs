//! Requester side of the protocol: `Hello` negotiation over a dialed
//! connection and the client half of `exec.run` (control request → ticket
//! → `EXEC_DATA` stream → assemble stdout/stderr/exit).
//!
//! This module speaks in wire terms and typed errors; the `Ops` façade maps
//! [`ClientError`] to `OpError`/`ErrorCode` for the CLI.

use std::time::{Duration, Instant};

use qsh_proto::ErrorCode;
use qsh_proto::wire::{
    self, ControlMessage, ExecFrame, ExecStart, ExecStarted, Hello, StreamHeader, control_message,
    exec_frame, response,
};
use qsh_transport::{Connection, FramedStream, StreamError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::exec::ExecSpec;

/// How long to wait for the peer's `Hello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Client-side protocol errors.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The peer answered a request with a wire error. `code` is the peer's
    /// error code verbatim (e.g. `PERMISSION_DENIED`).
    #[error("{code}: {message}")]
    Remote {
        /// Peer-reported code.
        code: ErrorCode,
        /// Peer-reported message.
        message: String,
        /// Peer-reported retryability.
        retryable: bool,
    },
    /// The peer does not offer what we need (no common version/capability).
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The peer violated the protocol.
    #[error("protocol: {0}")]
    Protocol(String),
    /// A stream failed.
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// The connection failed.
    #[error("connection: {0}")]
    Connection(#[from] qsh_transport::ConnectionError),
    /// The peer's `Hello` did not arrive in time.
    #[error("timed out waiting for peer Hello")]
    HelloTimeout,
    /// The remote command produced more output than this client is willing
    /// to buffer ([`EXEC_OUTPUT_MAX`]).
    #[error("remote command output exceeded {limit} bytes")]
    OutputTooLarge {
        /// The cap that was hit.
        limit: usize,
    },
}

/// Upper bound on the bytes of stdout + stderr an `exec` buffers before it
/// gives up with [`ClientError::OutputTooLarge`]. `exec.run` returns the
/// whole output in one JSON envelope, so it must be bounded; streaming
/// output belongs to sessions (M2).
pub const EXEC_OUTPUT_MAX: usize = 64 * 1024 * 1024;

/// A negotiated connection: control stream open, `Hello` exchanged.
pub struct Session {
    conn: Connection,
    ctl: FramedStream,
    next_request_id: u64,
    /// Capabilities both sides support.
    pub capabilities: Vec<String>,
    /// The peer's display name from its `Hello` (informational only —
    /// never an identity).
    pub peer_device_name: String,
}

impl Session {
    /// Open the control stream and exchange `Hello` on a fresh connection.
    pub async fn negotiate(conn: Connection, device_name: &str) -> Result<Self, ClientError> {
        let (send, recv) = conn.open_bi().await?;
        let mut ctl = FramedStream::control(send, recv);
        ctl.send
            .send(&ControlMessage::new(
                0,
                control_message::Body::Hello(Hello {
                    versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
                    device_name: device_name.to_string(),
                    capabilities: wire::LOCAL_CAPABILITIES
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                }),
            ))
            .await?;

        let reply = tokio::time::timeout(HELLO_TIMEOUT, ctl.recv.recv::<ControlMessage>())
            .await
            .map_err(|_| ClientError::HelloTimeout)??
            .ok_or_else(|| {
                ClientError::Protocol("peer closed control stream before Hello".into())
            })?;
        let peer_hello = match reply.body {
            Some(control_message::Body::Hello(h)) => h,
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => {
                return Err(ClientError::Remote {
                    code: e.error_code(),
                    message: e.message,
                    retryable: e.retryable,
                });
            }
            _ => {
                return Err(ClientError::Protocol(
                    "first control message was not Hello".into(),
                ));
            }
        };
        if !wire::WIRE_MINOR_VERSIONS
            .iter()
            .any(|v| peer_hello.versions.contains(v))
        {
            return Err(ClientError::Unsupported(
                "no common wire minor version".into(),
            ));
        }
        let capabilities = wire::LOCAL_CAPABILITIES
            .iter()
            .filter(|c| peer_hello.capabilities.iter().any(|p| p == *c))
            .map(|c| c.to_string())
            .collect();
        Ok(Self {
            conn,
            ctl,
            next_request_id: 1,
            capabilities,
            peer_device_name: peer_hello.device_name,
        })
    }

    /// The underlying connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }

    /// Send one request and wait for its correlated response.
    async fn request(
        &mut self,
        body: control_message::Body,
    ) -> Result<wire::Response, ClientError> {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.ctl
            .send
            .send(&ControlMessage::new(request_id, body))
            .await?;
        loop {
            let msg = self
                .ctl
                .recv
                .recv::<ControlMessage>()
                .await?
                .ok_or_else(|| {
                    ClientError::Protocol("peer closed control stream mid-request".into())
                })?;
            match msg.body {
                Some(control_message::Body::Response(resp)) if msg.request_id == request_id => {
                    return Ok(resp);
                }
                Some(control_message::Body::Ping(_)) => {
                    self.ctl
                        .send
                        .send(&ControlMessage::new(
                            msg.request_id,
                            control_message::Body::Pong(wire::Pong {}),
                        ))
                        .await?;
                }
                // Responses to other requests / events: none exist in M1;
                // ignore rather than fail.
                _ => {}
            }
        }
    }

    /// Phase one of an exec: ask the peer to authorize `spec` and issue a
    /// data-stream ticket. Nothing runs until the ticket is redeemed by
    /// opening an `EXEC_DATA` stream (see [`exec`](Self::exec), which does
    /// both).
    pub async fn exec_start(&mut self, spec: &ExecSpec) -> Result<ExecStarted, ClientError> {
        if !self.has_capability(wire::CAP_EXEC) {
            return Err(ClientError::Unsupported(
                "peer does not support exec".into(),
            ));
        }
        let resp = self
            .request(control_message::Body::ExecStart(ExecStart {
                argv: spec.argv.clone(),
                env: spec.env.iter().cloned().collect(),
                timeout_ms: spec
                    .timeout
                    .map_or(0, |t| t.as_millis().min(u64::MAX as u128) as u64),
            }))
            .await?;
        match resp.body {
            Some(response::Body::ExecStarted(s)) => Ok(s),
            Some(response::Body::Error(e)) => Err(ClientError::Remote {
                code: e.error_code(),
                message: e.message,
                retryable: e.retryable,
            }),
            _ => Err(ClientError::Protocol(
                "unexpected response to ExecStart".into(),
            )),
        }
    }

    /// Run `spec` on the peer. `stdin`, if given, is streamed to the remote
    /// process until EOF; `None` sends an immediate EOF.
    pub async fn exec(
        &mut self,
        spec: &ExecSpec,
        stdin: Option<Box<dyn AsyncRead + Send + Unpin>>,
    ) -> Result<ExecResult, ClientError> {
        let started = Instant::now();
        let started_msg = self.exec_start(spec).await?;

        // Data stream: header first, then pump.
        let (send, recv) = self.conn.open_bi().await?;
        let mut data = FramedStream::data(send, recv);
        data.send
            .send(&StreamHeader::exec_data(started_msg.ticket))
            .await?;

        // stdin pump runs concurrently with output collection.
        let (mut send_half, mut recv_half) = data.split();
        let stdin_task = tokio::spawn(async move {
            let result = pump_stdin(stdin, &mut send_half).await;
            (send_half, result)
        });

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let outcome = loop {
            let frame = match recv_half.recv::<ExecFrame>().await {
                Ok(frame) => frame,
                Err(err) => {
                    stdin_task.abort();
                    return Err(err.into());
                }
            };
            match frame {
                Some(ExecFrame {
                    body: Some(exec_frame::Body::Stdout(chunk)),
                }) => stdout.extend_from_slice(&chunk.data),
                Some(ExecFrame {
                    body: Some(exec_frame::Body::Stderr(chunk)),
                }) => stderr.extend_from_slice(&chunk.data),
                Some(ExecFrame {
                    body: Some(exec_frame::Body::ExecExit(exit)),
                }) => break Some(exit),
                Some(_) => {} // stdin frames from the peer would be a slip; ignore
                None => break None,
            }
            if stdout.len() + stderr.len() > EXEC_OUTPUT_MAX {
                // Stop reading; the host notices the reset and kills the
                // command instead of streaming into the void.
                stdin_task.abort();
                recv_half.stop(1);
                return Err(ClientError::OutputTooLarge {
                    limit: EXEC_OUTPUT_MAX,
                });
            }
        };
        stdin_task.abort();
        let _ = stdin_task.await;

        let exit = outcome
            .ok_or_else(|| ClientError::Protocol("exec stream ended without ExecExit".into()))?;
        Ok(ExecResult {
            exec_id: started_msg.exec_id,
            stdout,
            stderr,
            exit_code: exit.exit_code,
            signal: exit.signal,
            timed_out: exit.timed_out,
            duration: started.elapsed(),
        })
    }

    /// Finish the control stream and close the connection cleanly.
    pub fn close(mut self) {
        let _ = self.ctl.send.finish();
        self.conn.close(0, b"done");
    }
}

/// Assembled result of a remote exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// Peer-assigned exec id.
    pub exec_id: String,
    /// Remote stdout bytes.
    pub stdout: Vec<u8>,
    /// Remote stderr bytes.
    pub stderr: Vec<u8>,
    /// Remote exit code (`128 + signo` if signaled).
    pub exit_code: i32,
    /// Terminating signal name, if any.
    pub signal: Option<String>,
    /// The host killed the command because the requested timeout elapsed.
    pub timed_out: bool,
    /// Wall-clock time from request to exit.
    pub duration: Duration,
}

async fn pump_stdin(
    stdin: Option<Box<dyn AsyncRead + Send + Unpin>>,
    send: &mut qsh_transport::FramedSend,
) -> Result<(), StreamError> {
    if let Some(mut stdin) = stdin {
        let mut buf = vec![0u8; wire::EXEC_CHUNK_MAX];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => send.send(&ExecFrame::stdin(buf[..n].to_vec())).await?,
            }
        }
    }
    send.send(&ExecFrame::stdin_eof()).await
}
