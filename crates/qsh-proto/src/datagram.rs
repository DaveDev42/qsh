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
}

impl DatagramKind {
    /// From the wire value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            10 => Some(Self::ScreenUpdate),
            11 => Some(Self::ScreenAck),
            12 => Some(Self::Input),
            13 => Some(Self::ScreenEcho),
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
}
