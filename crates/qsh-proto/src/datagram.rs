//! The QUIC DATAGRAM frame header (ADR-0052 decision 7).
//!
//! A datagram is its own boundary, so the frame has no length prefix: a
//! 16-byte channel id, a one-byte body kind, then the body. The channel id
//! is the 128-bit random value the host issues after the ACL admits an
//! attach; a datagram naming an unknown channel is dropped and counted by
//! the receiver. The kind numbers are the `DatagramFrame.body` field numbers
//! of decision 9. The payload of each kind is the protobuf message of the
//! same name from [`crate::wire`]. The `datagram.v1` capability carries
//! these frames (`docs/design/protocol.md` §18.9); the decoder is a fuzz
//! surface.

use thiserror::Error;

/// Bytes in a channel id.
pub const CHANNEL_ID_LEN: usize = 16;
/// Largest accepted frame. Datagrams are far smaller (PMTU), this only
/// bounds what a decoder looks at.
pub const MAX_DATAGRAM_FRAME: usize = 64 * 1024;

/// The per-connection datagram channel id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(pub [u8; CHANNEL_ID_LEN]);

/// What the payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DatagramKind {
    /// An encoded [`crate::screen::ScreenUpdate`] (or one fragment of it).
    ScreenUpdate = 10,
    /// A `ScreenAck`.
    ScreenAck = 11,
    /// A copy of a session `Input`.
    Input = 12,
    /// A `ScreenEcho` (ADR-0053 decision 3, capability `screen-echo.v1`).
    ScreenEcho = 13,
    /// One inner QUIC packet of a jump channel (ADR-0056 decision 4,
    /// capability `jump.v1`). The channel is the `jump_channel` of the `JUMP`
    /// stream, looked up in the jump table only; the payload is the packet
    /// bytes as they are, not a protobuf.
    JumpPacket = 14,
}

impl DatagramKind {
    /// From the wire value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            10 => Some(Self::ScreenUpdate),
            11 => Some(Self::ScreenAck),
            12 => Some(Self::Input),
            13 => Some(Self::ScreenEcho),
            14 => Some(Self::JumpPacket),
            _ => None,
        }
    }
}

/// Why a datagram does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DatagramError {
    /// Shorter than the channel id and kind byte.
    #[error("datagram is shorter than its header")]
    Truncated,
    /// Longer than [`MAX_DATAGRAM_FRAME`].
    #[error("datagram is longer than the cap")]
    TooLong,
    /// The kind byte names no known body.
    #[error("unknown datagram kind {0}")]
    UnknownKind(u8),
}

/// One datagram: channel id, kind, payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramFrame {
    /// Channel the datagram belongs to.
    pub channel: ChannelId,
    /// Payload kind.
    pub kind: DatagramKind,
    /// The payload, possibly empty.
    pub payload: Vec<u8>,
}

impl DatagramFrame {
    /// Header bytes before the payload.
    pub const HEADER_LEN: usize = CHANNEL_ID_LEN + 1;

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.channel.0);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode one datagram. Total over arbitrary bytes; accepted input
    /// re-encodes to itself.
    pub fn decode(bytes: &[u8]) -> Result<Self, DatagramError> {
        if bytes.len() > MAX_DATAGRAM_FRAME {
            return Err(DatagramError::TooLong);
        }
        if bytes.len() < Self::HEADER_LEN {
            return Err(DatagramError::Truncated);
        }
        let mut channel = [0u8; CHANNEL_ID_LEN];
        channel.copy_from_slice(&bytes[..CHANNEL_ID_LEN]);
        let k = bytes[CHANNEL_ID_LEN];
        let kind = DatagramKind::from_u8(k).ok_or(DatagramError::UnknownKind(k))?;
        Ok(Self {
            channel: ChannelId(channel),
            kind,
            payload: bytes[Self::HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_bad_headers() {
        let f = DatagramFrame {
            channel: ChannelId([7; CHANNEL_ID_LEN]),
            kind: DatagramKind::ScreenAck,
            payload: vec![1, 2, 3],
        };
        assert_eq!(DatagramFrame::decode(&f.encode()), Ok(f.clone()));
        let empty = DatagramFrame {
            payload: vec![],
            ..f
        };
        assert_eq!(DatagramFrame::decode(&empty.encode()), Ok(empty));
        assert_eq!(
            DatagramFrame::decode(&[0; CHANNEL_ID_LEN]),
            Err(DatagramError::Truncated)
        );
        let mut bad = vec![0; CHANNEL_ID_LEN];
        bad.push(99);
        assert_eq!(
            DatagramFrame::decode(&bad),
            Err(DatagramError::UnknownKind(99))
        );
        assert_eq!(
            DatagramFrame::decode(&vec![0; MAX_DATAGRAM_FRAME + 1]),
            Err(DatagramError::TooLong)
        );
    }

    #[test]
    fn jump_packet_round_trips_with_an_opaque_body() {
        // Kind 14 (ADR-0056 decision 4): the body is packet bytes, never
        // interpreted here, so even a body that is no valid protobuf is kept.
        let body = vec![0xc0, 0, 0, 0, 1, 0xff, 0xff];
        let f = DatagramFrame {
            channel: ChannelId([9; CHANNEL_ID_LEN]),
            kind: DatagramKind::JumpPacket,
            payload: body.clone(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[CHANNEL_ID_LEN], 14);
        assert_eq!(DatagramKind::from_u8(14), Some(DatagramKind::JumpPacket));
        assert_eq!(DatagramFrame::decode(&bytes), Ok(f));
        assert_eq!(&bytes[DatagramFrame::HEADER_LEN..], body.as_slice());
        let mut unknown = vec![0; CHANNEL_ID_LEN];
        unknown.push(15);
        assert_eq!(
            DatagramFrame::decode(&unknown),
            Err(DatagramError::UnknownKind(15))
        );
    }
}
