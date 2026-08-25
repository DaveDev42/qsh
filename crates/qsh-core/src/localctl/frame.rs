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
        let Some(payload) = self.recv_payload().await? else {
            return Ok(None);
        };
        let msg = decode_local(&payload).map_err(|err| conduit_error("decode", err))?;
        Ok(Some(msg))
    }

    /// [`Self::recv`], stopping one layer short of decoding: hands back
    /// the de-framed payload bytes exactly as they arrived, still
    /// unparsed.
    ///
    /// `LOCAL_STREAM`'s `SESSION_DATA` header is the one caller
    /// (`crate::localctl::daemon::LocalctlDaemon::serve_stream`): it needs
    /// the decoded [`wire::StreamHeader`](qsh_proto::wire::StreamHeader)
    /// to run its own checks (`kind`, `ticket`), but what it *forwards*
    /// onto the QUIC data stream has to be relayed verbatim, not
    /// decode-then-re-encode — prost drops any field this build's
    /// `StreamHeader` does not know about, which would silently strip an
    /// additive field a newer `qsh` client set (`docs/CLI.md`'s
    /// additive-only wire contract is only meaningful if an intermediary
    /// that does not understand a field still forwards it byte-exact).
    /// This method is how the same bytes end up in both places: decoded
    /// once from this return value for the daemon's own checks, and
    /// re-framed unchanged (never re-encoded from the decoded struct) for
    /// the QUIC side.
    pub(crate) async fn recv_payload(&mut self) -> Result<Option<Vec<u8>>, OpError> {
        loop {
            if let Some(payload) = self
                .dec
                .next_frame()
                .map_err(|err| conduit_error("frame", err))?
            {
                return Ok(Some(payload));
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
    use qsh_proto::local::{
        LocalClaimGranted, LocalHello, LocalResponse, LocalStreamKind, local_response,
    };

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
            known_generation: None,
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
            known_generation: None,
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
            known_generation: None,
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
            known_generation: None,
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

    // ---- the TCP_ACCEPTED claim leg's frame -> raw boundary -----------
    //
    // `docs/design/protocol.md` §11-3 ("TCP_ACCEPTED claim leg의 요청/응답")
    // makes the daemon answer every claim with exactly one framed
    // `LocalResponse` and start raw tunnel payload immediately after it.
    // The reader's whole job is therefore: read one frame, then hand the
    // rest to the splice **in order**. These pin that down against the two
    // ways it can go wrong — losing residue that shared a `read()` with the
    // frame, and reordering it.

    fn claim_granted() -> LocalResponse {
        LocalResponse {
            body: Some(local_response::Body::ClaimGranted(LocalClaimGranted {})),
        }
    }

    #[tokio::test]
    async fn one_frame_then_raw_preserves_order_across_read_boundaries() {
        // The write is deliberately torn in the middle of the frame's own
        // 4-byte length prefix, and the second chunk then carries the rest
        // of the frame *plus the entire payload*. That shape forces both
        // properties at once:
        //   - a `read()` that resolves a frame only after an earlier,
        //     incomplete one (the decoder must carry state across reads);
        //   - a `read()` that straddles the frame/raw boundary and leaves
        //     a large, order-sensitive residue behind it.
        // A residue of one or two bytes would pass even if the residue
        // were handed back reversed, so it is sized to make that
        // detectable.
        let (mut client_end, daemon_end) = tokio::io::duplex(4096);
        let mut reader = LocalConduit::new(daemon_end);

        let payload: Vec<u8> = (0u8..=255).cycle().take(700).collect();
        let mut wire = encode_local(&claim_granted()).unwrap();
        wire.extend_from_slice(&payload);

        let feeder = tokio::spawn(async move {
            client_end.write_all(&wire[..3]).await.unwrap();
            tokio::task::yield_now().await;
            client_end.write_all(&wire[3..]).await.unwrap();
            client_end
        });

        let resp: LocalResponse = reader.recv().await.unwrap().unwrap();
        assert!(matches!(
            resp.body,
            Some(local_response::Body::ClaimGranted(_))
        ));

        // Drain the rest exactly as the real caller does: residue first,
        // then whatever is still on the socket.
        let (mut stream, mut got) = reader.into_raw();
        assert!(
            got.len() > 64,
            "the test is only meaningful if a substantial residue crossed the boundary with the \
             frame; got {}",
            got.len()
        );
        while got.len() < payload.len() {
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "peer closed before the whole payload arrived");
            got.extend_from_slice(&buf[..n]);
        }
        let _client_end = feeder.await.unwrap();

        assert_eq!(
            got, payload,
            "every raw byte after the claim frame must arrive once, in order"
        );
    }

    #[tokio::test]
    async fn raw_payload_that_looks_like_a_frame_flows_through_untouched() {
        // Leading zero bytes: read as a BE u32 this is a small, in-cap
        // declared length, and the "payload" after it is a zero tag, which
        // prost rejects — the exact shape the deleted content-classifying
        // claim race mistook for a frame and then re-ordered while trying
        // to put back. Nothing here may look at these bytes at all: the
        // one frame was already consumed, so all of this is residue.
        let (mut client_end, daemon_end) = tokio::io::duplex(4096);
        let mut reader = LocalConduit::new(daemon_end);

        let payload = vec![0x00u8, 0x00, 0x00, 0x01, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x09];
        let mut wire = encode_local(&claim_granted()).unwrap();
        wire.extend_from_slice(&payload);
        client_end.write_all(&wire).await.unwrap();

        let resp: LocalResponse = reader.recv().await.unwrap().unwrap();
        assert!(matches!(
            resp.body,
            Some(local_response::Body::ClaimGranted(_))
        ));

        let (_stream, residue) = reader.into_raw();
        assert_eq!(
            residue, payload,
            "raw payload is never parsed, never re-framed, never reordered"
        );
    }
}
