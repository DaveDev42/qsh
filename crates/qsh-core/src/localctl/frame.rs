//! Length-prefixed `qsh.local.v1` message I/O over a localctl conduit —
//! the transport-free analogue of `qsh-transport::control`'s framed QUIC
//! stream helpers (`docs/design/protocol.md` §5, §11-3). Deliberately
//! reimplemented rather than reused: this file must never import
//! `qsh_transport` (`crate::localctl` module docs, `PLAN.md` M3 Step 5).
//!
//! What *is* reused is the frame **parser** — exactly the discipline
//! `docs/design/protocol.md` §11-3 requires ("§5와 동일한 frame layer"):
//! [`qsh_proto::frame::FrameDecoder`] (u32-BE length prefix, checked
//! against [`CONTROL_FRAME_MAX`] *before* any payload-sized buffer is
//! allocated) via [`qsh_proto::local::encode_local`]/[`decode_local`],
//! running over whatever `AsyncRead + AsyncWrite` the caller hands in. In
//! production that is always a `tokio::net::UnixStream`, but keeping
//! [`LocalConduit`] generic lets tests drive the exact same code over an
//! in-memory `tokio::io::duplex` pipe with no real socket at all.

use prost::Message;
use qsh_proto::ErrorCode;
use qsh_proto::frame::{CONTROL_FRAME_MAX, FrameDecoder};
use qsh_proto::local::{decode_local, encode_local};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::ops::OpError;

/// One localctl conduit: a length-prefixed `qsh.local.v1` message stream
/// over any `AsyncRead + AsyncWrite` byte stream, capped at
/// [`CONTROL_FRAME_MAX`] in both directions — the same cap the wire
/// control stream uses (`docs/design/protocol.md` §5).
pub struct LocalConduit<S> {
    stream: S,
    dec: FrameDecoder,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> LocalConduit<S> {
    /// Wrap an already-connected stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            dec: FrameDecoder::new(CONTROL_FRAME_MAX),
            buf: vec![0u8; 16 * 1024],
        }
    }

    /// Encode + frame + write one `qsh.local.v1` message.
    pub async fn send<M: Message>(&mut self, msg: &M) -> Result<(), OpError> {
        let wire = encode_local(msg).map_err(|err| conduit_error("encode", err))?;
        self.stream
            .write_all(&wire)
            .await
            .map_err(|err| conduit_error("write", err))?;
        Ok(())
    }

    /// Read the next message. `Ok(None)` on a clean end-of-conduit (the
    /// peer closed exactly at a frame boundary, with nothing pending).
    ///
    /// An oversize declared length or a conduit that ends mid-frame are
    /// both reported as [`ErrorCode::ConnectionFailed`] — past either
    /// point framing sync is lost and the conduit cannot be trusted
    /// further; the oversize case is caught from the 4-byte header alone,
    /// before any payload-sized buffer is allocated
    /// (`docs/design/protocol.md` §5).
    pub async fn recv<M: Message + Default>(&mut self) -> Result<Option<M>, OpError> {
        loop {
            if let Some(payload) = self
                .dec
                .next_frame()
                .map_err(|err| conduit_error("frame", err))?
            {
                let msg = decode_local(&payload).map_err(|err| conduit_error("decode", err))?;
                return Ok(Some(msg));
            }
            let n = self
                .stream
                .read(&mut self.buf)
                .await
                .map_err(|err| conduit_error("read", err))?;
            if n == 0 {
                let buffered = self.dec.buffered();
                return if buffered == 0 {
                    Ok(None)
                } else {
                    Err(conduit_error(
                        "read",
                        format!("conduit ended mid-frame ({buffered} bytes buffered)"),
                    ))
                };
            }
            self.dec.push(&self.buf[..n]);
        }
    }

    /// Consume this conduit once framed `qsh.local.v1` I/O on it is done,
    /// handing back the still-open underlying stream plus any bytes
    /// already read off it but not yet resolved into a frame.
    ///
    /// `LOCAL_STREAM`'s serve path (`crate::localctl::daemon`) is the one
    /// caller: after reading exactly one wire `StreamHeader` frame via
    /// [`Self::recv`], the conduit stops speaking framed messages
    /// entirely and becomes a raw byte splice onto a QUIC data stream
    /// (`docs/design/protocol.md` §11-3). The splice must start with
    /// whatever [`qsh_proto::frame::FrameDecoder`] already buffered past
    /// that header — one `read()` routinely returns more than one
    /// frame's worth of bytes — or however much of the caller's next
    /// write landed in that same read is silently dropped.
    pub fn into_raw(self) -> (S, Vec<u8>) {
        let LocalConduit {
            stream, mut dec, ..
        } = self;
        (stream, dec.take_remaining())
    }
}

/// Wrap any localctl framing failure as [`ErrorCode::ConnectionFailed`] —
/// the same code `PLAN.md` M3's fixed vocabulary uses for "controller 도달
/// 실패" (`docs/CLI.md` §3.3). A broken local IPC conduit to this
/// machine's own daemon plays the same role for the CLI process that an
/// unreachable controller plays for a reverse target, so it is classified
/// the same way rather than minting a new code (M3 mints none —
/// `CLAUDE.md` "never invent an ad hoc error string").
fn conduit_error(step: &str, err: impl std::fmt::Display) -> OpError {
    OpError::new(
        ErrorCode::ConnectionFailed,
        format!("localctl conduit {step} failed: {err}"),
    )
}

#[cfg(test)]
mod tests {
    use qsh_proto::local::{LocalHello, LocalStreamKind};

    use super::*;

    #[tokio::test]
    async fn round_trips_a_message_over_an_in_memory_pipe() {
        // `tokio::io::duplex` proves the conduit is genuinely transport-
        // agnostic: no real socket exists anywhere in this test.
        let (client_end, daemon_end) = tokio::io::duplex(4096);
        let mut client = LocalConduit::new(client_end);
        let mut daemon = LocalConduit::new(daemon_end);

        let hello = LocalHello {
            version: 1,
            kind: LocalStreamKind::LocalAdmin as i32,
            host: String::new(),
            wait_ms: 0,
        };
        client.send(&hello).await.unwrap();

        let received: LocalHello = daemon.recv().await.unwrap().unwrap();
        assert_eq!(received, hello);
    }

    #[tokio::test]
    async fn split_across_many_small_reads_still_round_trips() {
        // The frame decoder buffers across partial reads; a duplex with a
        // tiny channel capacity forces exactly that.
        let (client_end, daemon_end) = tokio::io::duplex(3);
        let mut client = LocalConduit::new(client_end);
        let mut daemon = LocalConduit::new(daemon_end);

        let hello = LocalHello {
            version: 1,
            kind: LocalStreamKind::LocalControl as i32,
            host: "personal-mac".to_string(),
            wait_ms: 250,
        };
        let write = tokio::spawn(async move {
            client.send(&hello).await.unwrap();
            hello
        });
        let received: LocalHello = daemon.recv().await.unwrap().unwrap();
        let sent = write.await.unwrap();
        assert_eq!(received, sent);
    }

    #[tokio::test]
    async fn into_raw_hands_back_bytes_already_read_past_the_last_frame() {
        // A single `write_all` on the client side, sized so both the
        // header frame and the start of the next (raw, unframed) payload
        // land in the daemon's one `read()` call — exactly the situation
        // `into_raw` exists for.
        let (mut client_end, daemon_end) = tokio::io::duplex(4096);
        let mut daemon = LocalConduit::new(daemon_end);

        let hello = LocalHello {
            version: 1,
            kind: LocalStreamKind::LocalStream as i32,
            host: "some-host".to_string(),
            wait_ms: 0,
        };
        let mut wire = encode_local(&hello).unwrap();
        wire.extend_from_slice(b"raw bytes after the frame");
        client_end.write_all(&wire).await.unwrap();

        let received: LocalHello = daemon.recv().await.unwrap().unwrap();
        assert_eq!(received, hello);

        let (_stream, leftover) = daemon.into_raw();
        assert_eq!(leftover, b"raw bytes after the frame".to_vec());
    }

    #[tokio::test]
    async fn into_raw_with_nothing_buffered_past_the_frame_is_empty() {
        let (mut client_end, daemon_end) = tokio::io::duplex(4096);
        let mut daemon = LocalConduit::new(daemon_end);

        let hello = LocalHello {
            version: 1,
            kind: LocalStreamKind::LocalStream as i32,
            host: "some-host".to_string(),
            wait_ms: 0,
        };
        client_end
            .write_all(&encode_local(&hello).unwrap())
            .await
            .unwrap();

        let received: LocalHello = daemon.recv().await.unwrap().unwrap();
        assert_eq!(received, hello);

        let (_stream, leftover) = daemon.into_raw();
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn clean_close_at_a_frame_boundary_is_none() {
        let (client_end, daemon_end) = tokio::io::duplex(4096);
        drop(client_end); // close immediately, nothing ever written
        let mut daemon = LocalConduit::new(daemon_end);

        let received = daemon.recv::<LocalHello>().await.unwrap();
        assert!(received.is_none());
    }

    #[tokio::test]
    async fn oversize_declared_length_is_rejected_as_connection_failed() {
        let (mut client_end, daemon_end) = tokio::io::duplex(4096);
        let mut daemon = LocalConduit::new(daemon_end);

        // Only the 4-byte header is ever written: if the decoder tried to
        // allocate a buffer sized by the (huge) declared length before
        // checking the cap, this would try to OOM instead of erroring
        // cleanly.
        let huge_len: u32 = u32::MAX;
        client_end.write_all(&huge_len.to_be_bytes()).await.unwrap();

        let err = daemon.recv::<LocalHello>().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::ConnectionFailed);
    }

    #[tokio::test]
    async fn truncated_mid_frame_close_is_an_error_not_none() {
        let (mut client_end, daemon_end) = tokio::io::duplex(4096);
        let mut daemon = LocalConduit::new(daemon_end);

        // A length prefix declaring 10 bytes, followed by only 3, then the
        // peer hangs up — sync is lost past the header, so this must never
        // be reported the same way as a clean `Ok(None)` close.
        client_end.write_all(&10u32.to_be_bytes()).await.unwrap();
        client_end.write_all(b"abc").await.unwrap();
        drop(client_end);

        let err = daemon.recv::<LocalHello>().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::ConnectionFailed);
        assert!(
            err.message.contains("mid-frame"),
            "message: {}",
            err.message
        );
    }
}
