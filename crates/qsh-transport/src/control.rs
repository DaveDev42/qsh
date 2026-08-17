//! Framed message I/O over QUIC streams: the frame layer from
//! `qsh-proto::frame` on top of quinn `SendStream`/`RecvStream`, generic over
//! any prost message. Used for the control stream (256 KiB cap) and for
//! data streams such as `EXEC_DATA` (64 KiB cap).

use prost::Message;
use qsh_proto::frame::{CONTROL_FRAME_MAX, DATA_FRAME_MAX, FrameDecoder, FrameError};
use qsh_proto::wire::{WireEncodeError, encode_framed};
use quinn::{RecvStream, SendStream};
use thiserror::Error;

/// Errors from framed stream I/O.
#[derive(Debug, Error)]
pub enum StreamError {
    /// Peer declared a frame larger than this stream's cap (fatal — the
    /// stream is unsynchronized past this point).
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Payload did not decode as the expected message.
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
    /// Our own message did not fit the frame cap.
    #[error(transparent)]
    Encode(#[from] WireEncodeError),
    /// The stream ended in the middle of a frame.
    #[error("stream ended mid-frame ({buffered} bytes buffered)")]
    Truncated {
        /// Bytes received past the last complete frame.
        buffered: usize,
    },
    /// QUIC read failure (reset, connection lost, …).
    #[error("read: {0}")]
    Read(#[from] quinn::ReadError),
    /// QUIC write failure.
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
    /// Finishing the send side failed (already closed).
    #[error("close: {0}")]
    Close(#[from] quinn::ClosedStream),
}

/// Sending half of a framed stream.
pub struct FramedSend {
    send: SendStream,
    max: usize,
}

impl FramedSend {
    /// Wrap a send stream with the given frame cap.
    pub fn new(send: SendStream, max: usize) -> Self {
        Self { send, max }
    }

    /// Control-stream sender (256 KiB frames).
    pub fn control(send: SendStream) -> Self {
        Self::new(send, CONTROL_FRAME_MAX)
    }

    /// Data-stream sender (64 KiB frames).
    pub fn data(send: SendStream) -> Self {
        Self::new(send, DATA_FRAME_MAX)
    }

    /// Encode + frame + write one message.
    pub async fn send<M: Message>(&mut self, msg: &M) -> Result<(), StreamError> {
        let wire = encode_framed(msg, self.max)?;
        self.send.write_all(&wire).await?;
        Ok(())
    }

    /// Signal end-of-stream to the peer (FIN). Idempotent-ish: a second call
    /// errors with `ClosedStream`, which callers may ignore.
    pub fn finish(&mut self) -> Result<(), StreamError> {
        self.send.finish()?;
        Ok(())
    }

    /// Abruptly reset the stream with an application error code.
    pub fn reset(&mut self, code: u32) {
        let _ = self.send.reset(quinn::VarInt::from_u32(code));
    }

    /// Set the QUIC send priority (`docs/design/protocol.md` §12).
    pub fn set_priority(&self, priority: i32) {
        let _ = self.send.set_priority(priority);
    }
}

/// Receiving half of a framed stream.
pub struct FramedRecv {
    recv: RecvStream,
    dec: FrameDecoder,
    buf: Vec<u8>,
}

impl FramedRecv {
    /// Wrap a receive stream with the given frame cap.
    pub fn new(recv: RecvStream, max: usize) -> Self {
        Self {
            recv,
            dec: FrameDecoder::new(max),
            buf: vec![0u8; 16 * 1024],
        }
    }

    /// Control-stream receiver (256 KiB frames).
    pub fn control(recv: RecvStream) -> Self {
        Self::new(recv, CONTROL_FRAME_MAX)
    }

    /// Data-stream receiver (64 KiB frames).
    pub fn data(recv: RecvStream) -> Self {
        Self::new(recv, DATA_FRAME_MAX)
    }

    /// Read the next message. `Ok(None)` on a clean end-of-stream (FIN at a
    /// frame boundary); [`StreamError::Truncated`] if the peer finished
    /// mid-frame.
    pub async fn recv<M: Message + Default>(&mut self) -> Result<Option<M>, StreamError> {
        loop {
            if let Some(payload) = self.dec.next_frame()? {
                return Ok(Some(M::decode(payload.as_slice())?));
            }
            match self.recv.read(&mut self.buf).await? {
                Some(n) => self.dec.push(&self.buf[..n]),
                None => {
                    let buffered = self.dec.buffered();
                    return if buffered == 0 {
                        Ok(None)
                    } else {
                        Err(StreamError::Truncated { buffered })
                    };
                }
            }
        }
    }

    /// Stop reading and tell the peer we are not interested in more data.
    pub fn stop(&mut self, code: u32) {
        let _ = self.recv.stop(quinn::VarInt::from_u32(code));
    }
}

/// A bidirectional framed stream (the control stream, or a data stream
/// after its header). Both halves can be split for concurrent use.
pub struct FramedStream {
    /// Sending half.
    pub send: FramedSend,
    /// Receiving half.
    pub recv: FramedRecv,
}

impl FramedStream {
    /// Control stream over a bidi pair.
    pub fn control(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: FramedSend::control(send),
            recv: FramedRecv::control(recv),
        }
    }

    /// Data stream over a bidi pair.
    pub fn data(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: FramedSend::data(send),
            recv: FramedRecv::data(recv),
        }
    }

    /// Split into independently-owned halves.
    pub fn split(self) -> (FramedSend, FramedRecv) {
        (self.send, self.recv)
    }
}
