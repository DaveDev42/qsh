//! Jump packet framing and the QUIC long-header reader behind the "QUIC
//! gate" (ADR-0056 decisions 2, 4, 7 and 8; the MTU figures are ADR-0057's).
//!
//! Two sans-IO pieces, no wire change yet:
//!
//! - the stream carrier: a `u16` big-endian length followed by that many
//!   packet bytes, repeated ([`JumpStreamDecoder`], [`encode_packet`]);
//! - a reader for the invariant fields of a QUIC long header (RFC 8999) and
//!   the predicates the intermediate peer's gate uses ([`read_long_header`],
//!   [`is_v1_initial_shaped`], [`answers_gate`]).
//!
//! The gate looks only at fields QUIC sends in the clear. Nothing here
//! touches ciphertext, builds a packet or allocates from a declared length.

use thiserror::Error;

/// Smallest inner packet. QUIC's floor for a datagram, and the inner
/// endpoint's `initial_mtu`/`min_mtu`.
pub const JUMP_PACKET_MIN: usize = 1200;
/// Largest inner packet (the PLPMTUD ceiling, ADR-0056 decision 5).
pub const JUMP_PACKET_MAX: usize = 1452;
/// Bytes not yet sent that a stream carrier may hold; past this the sender
/// drops new packets and counts them (decision 4).
pub const JUMP_STREAM_QUEUE: usize = 64 * 1024;
/// Length of `jump_channel`.
pub const JUMP_CHANNEL_LEN: usize = 16;

/// Length of the stream carrier's length prefix.
const PREFIX_LEN: usize = 2;
/// QUIC version 1 (RFC 9000).
pub const QUIC_V1: u32 = 1;
/// Longest connection ID a v1 packet may carry (RFC 9000 section 17.2).
const V1_CID_MAX: usize = 20;

/// A stream-carrier framing violation. The caller resets the stream with
/// `BAD_HEADER` (`0x2001`). The decoder stays failed after returning one.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum JumpFrameError {
    /// The declared length is 0.
    #[error("jump packet with length 0")]
    ZeroLength,
    /// The declared length exceeds [`JUMP_PACKET_MAX`].
    #[error("jump packet length {len} exceeds max {max}")]
    Oversize {
        /// The length the peer declared.
        len: u16,
        /// The cap, [`JUMP_PACKET_MAX`].
        max: usize,
    },
}

/// Incremental decoder for the stream carrier: [`push`](Self::push) bytes as
/// they arrive, then call [`next_packet`](Self::next_packet) until it returns
/// `Ok(None)`.
#[derive(Debug, Default)]
pub struct JumpStreamDecoder {
    buf: Vec<u8>,
    failed: Option<JumpFrameError>,
}

impl JumpStreamDecoder {
    /// An empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed received bytes. After a framing error the bytes are dropped.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            self.buf.extend_from_slice(bytes);
        }
    }

    /// Bytes buffered but not yet returned. Non-zero at end of stream means
    /// the peer cut a packet short.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Cut one packet (without its length prefix) off the front.
    ///
    /// - `Ok(None)`: more bytes are needed.
    /// - `Err(_)`: the prefix is invalid; the same error is returned from
    ///   then on and nothing stays buffered.
    ///
    /// The buffer holds only bytes that arrived, so the declared length never
    /// drives an allocation.
    pub fn next_packet(&mut self) -> Result<Option<Vec<u8>>, JumpFrameError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let Some(head) = self.buf.first_chunk::<PREFIX_LEN>() else {
            return Ok(None);
        };
        let len = u16::from_be_bytes(*head);
        let fail = if len == 0 {
            Some(JumpFrameError::ZeroLength)
        } else if usize::from(len) > JUMP_PACKET_MAX {
            Some(JumpFrameError::Oversize {
                len,
                max: JUMP_PACKET_MAX,
            })
        } else {
            None
        };
        if let Some(e) = fail {
            self.failed = Some(e);
            self.buf = Vec::new();
            return Err(e);
        }
        let total = PREFIX_LEN + usize::from(len);
        if self.buf.len() < total {
            return Ok(None);
        }
        let rest = self.buf.split_off(total);
        let mut packet = std::mem::replace(&mut self.buf, rest);
        packet.drain(..PREFIX_LEN);
        Ok(Some(packet))
    }
}

/// Encode one packet for the stream carrier. `None` when the packet is empty
/// or longer than [`JUMP_PACKET_MAX`] (the sender drops it).
pub fn encode_packet(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.is_empty() || packet.len() > JUMP_PACKET_MAX {
        return None;
    }
    let len = u16::try_from(packet.len()).ok()?;
    let mut out = Vec::with_capacity(PREFIX_LEN + packet.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(packet);
    Some(out)
}

/// The invariant fields of a QUIC long header (RFC 8999 section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongHeader<'a> {
    /// The first byte. Only the form bit (0x80) is invariant; the rest is
    /// version-specific.
    pub first: u8,
    /// The version field. 0 is Version Negotiation.
    pub version: u32,
    /// Destination connection ID, 0..=255 bytes.
    pub dcid: &'a [u8],
    /// Source connection ID, 0..=255 bytes.
    pub scid: &'a [u8],
}

/// Read the invariant long-header fields. `None` for an empty packet, a short
/// header (form bit clear) or a truncated header. Never panics.
pub fn read_long_header(packet: &[u8]) -> Option<LongHeader<'_>> {
    let (&first, rest) = packet.split_first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let (version, rest) = rest.split_first_chunk::<4>()?;
    let (&dlen, rest) = rest.split_first()?;
    let (dcid, rest) = rest.split_at_checked(usize::from(dlen))?;
    let (&slen, rest) = rest.split_first()?;
    let (scid, _) = rest.split_at_checked(usize::from(slen))?;
    Some(LongHeader {
        first,
        version: u32::from_be_bytes(*version),
        dcid,
        scid,
    })
}

/// True for a short-header packet: non-empty with the form bit clear.
pub fn is_short_header(packet: &[u8]) -> bool {
    packet.first().is_some_and(|b| b & 0x80 == 0)
}

/// The gate's test on a packet from the client before the target has
/// answered: a QUIC v1 Initial-shaped datagram. That is a long header (top
/// two bits `11`, so the fixed bit is set too), version 1, packet type
/// Initial (bits 0x30 clear), connection IDs within v1's 20 bytes, and a
/// datagram length of [`JUMP_PACKET_MIN`] or more, which RFC 9000 section
/// 14.1 requires of a client Initial. A packet over [`JUMP_PACKET_MAX`] is
/// not Initial-shaped either, since no carrier moves it.
pub fn is_v1_initial_shaped(packet: &[u8]) -> bool {
    if !(JUMP_PACKET_MIN..=JUMP_PACKET_MAX).contains(&packet.len()) {
        return false;
    }
    let Some(h) = read_long_header(packet) else {
        return false;
    };
    h.first & 0xC0 == 0xC0
        && h.first & 0x30 == 0
        && h.version == QUIC_V1
        && h.dcid.len() <= V1_CID_MAX
        && h.scid.len() <= V1_CID_MAX
}

/// Whether `packet`, arriving from the target, opens the gate: a long header
/// of any version and type (Retry, Initial, Version Negotiation) whose DCID
/// equals `client_scid`, an SCID the client used in a packet the gate
/// passed. A short header never opens it (ADR-0056 decision 8). The caller
/// tries each SCID it recorded from [`is_v1_initial_shaped`] packets.
pub fn answers_gate(packet: &[u8], client_scid: &[u8]) -> bool {
    read_long_header(packet).is_some_and(|h| h.dcid == client_scid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn long(first: u8, version: u32, dcid: &[u8], scid: &[u8], total: usize) -> Vec<u8> {
        let mut p = vec![first];
        p.extend_from_slice(&version.to_be_bytes());
        p.push(dcid.len() as u8);
        p.extend_from_slice(dcid);
        p.push(scid.len() as u8);
        p.extend_from_slice(scid);
        p.resize(total.max(p.len()), 0xAB);
        p
    }

    type Drained = Result<Vec<Vec<u8>>, JumpFrameError>;

    fn drain(d: &mut JumpStreamDecoder) -> Result<Vec<Vec<u8>>, JumpFrameError> {
        let mut out = Vec::new();
        while let Some(p) = d.next_packet()? {
            out.push(p);
        }
        Ok(out)
    }

    #[test]
    fn constants_match_the_adr() {
        assert_eq!(JUMP_PACKET_MIN, 1200);
        assert_eq!(JUMP_PACKET_MAX, 1452);
        assert_eq!(JUMP_STREAM_QUEUE, 65_536);
        assert_eq!(JUMP_CHANNEL_LEN, 16);
    }

    #[test]
    fn decoder_table() {
        let cases: Vec<(&str, Vec<u8>, Drained)> = vec![
            ("empty", vec![], Ok(vec![])),
            ("one byte of prefix", vec![0], Ok(vec![])),
            ("one packet", vec![0, 3, 1, 2, 3], Ok(vec![vec![1, 2, 3]])),
            (
                "two packets",
                vec![0, 1, 9, 0, 2, 7, 8],
                Ok(vec![vec![9], vec![7, 8]]),
            ),
            ("short body", vec![0, 3, 1, 2], Ok(vec![])),
            ("zero length", vec![0, 0], Err(JumpFrameError::ZeroLength)),
            (
                "zero after a good one",
                vec![0, 1, 5, 0, 0],
                Err(JumpFrameError::ZeroLength),
            ),
            (
                "one over the max",
                vec![0x05, 0xAD],
                Err(JumpFrameError::Oversize {
                    len: 1453,
                    max: JUMP_PACKET_MAX,
                }),
            ),
            (
                "u16 max",
                vec![0xFF, 0xFF],
                Err(JumpFrameError::Oversize {
                    len: 0xFFFF,
                    max: JUMP_PACKET_MAX,
                }),
            ),
        ];
        for (name, bytes, want) in cases {
            let mut d = JumpStreamDecoder::new();
            d.push(&bytes);
            let got = drain(&mut d);
            // A good packet before the error is returned first in the
            // sequence, so compare the error only when one is expected.
            match want {
                Ok(w) => assert_eq!(got, Ok(w), "{name}"),
                Err(e) => assert_eq!(got, Err(e), "{name}"),
            }
        }
    }

    #[test]
    fn the_max_itself_is_accepted() {
        let pkt = vec![7u8; JUMP_PACKET_MAX];
        let enc = encode_packet(&pkt).unwrap();
        let mut d = JumpStreamDecoder::new();
        d.push(&enc);
        assert_eq!(d.next_packet(), Ok(Some(pkt)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn encode_rejects_empty_and_oversize() {
        assert_eq!(encode_packet(&[]), None);
        assert_eq!(encode_packet(&vec![0; JUMP_PACKET_MAX + 1]), None);
        assert_eq!(encode_packet(&[1]), Some(vec![0, 1, 1]));
    }

    #[test]
    fn a_split_read_gives_the_same_packets() {
        let a = vec![1u8; 1200];
        let b = vec![2u8; 5];
        let mut wire = encode_packet(&a).unwrap();
        wire.extend(encode_packet(&b).unwrap());
        for chunk in [1, 2, 3, 7, 1201, 4096] {
            let mut d = JumpStreamDecoder::new();
            let mut got = Vec::new();
            for piece in wire.chunks(chunk) {
                d.push(piece);
                got.extend(drain(&mut d).unwrap());
            }
            assert_eq!(got, vec![a.clone(), b.clone()], "chunk {chunk}");
            assert_eq!(d.buffered(), 0);
        }
    }

    #[test]
    fn many_packets_in_one_chunk() {
        let mut wire = Vec::new();
        for i in 1..=200u8 {
            wire.extend(encode_packet(&vec![i; usize::from(i)]).unwrap());
        }
        let mut d = JumpStreamDecoder::new();
        d.push(&wire);
        let got = drain(&mut d).unwrap();
        assert_eq!(got.len(), 200);
        assert_eq!(got[199], vec![200u8; 200]);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn an_error_is_sticky_and_leaves_nothing_buffered() {
        let mut d = JumpStreamDecoder::new();
        d.push(&[0, 0, 1, 2, 3]);
        assert_eq!(d.next_packet(), Err(JumpFrameError::ZeroLength));
        assert_eq!(d.buffered(), 0);
        d.push(&[0, 1, 9]);
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.next_packet(), Err(JumpFrameError::ZeroLength));
    }

    #[test]
    fn the_declared_length_is_not_allocated_up_front() {
        let mut d = JumpStreamDecoder::new();
        d.push(&[0x05, 0xAC, 1]); // declares 1452, only 1 byte arrived
        assert_eq!(d.next_packet(), Ok(None));
        assert!(d.buf.capacity() < 64, "capacity {}", d.buf.capacity());
        assert_eq!(d.buffered(), 3);
    }

    #[test]
    fn long_header_reader_table() {
        let h = long(0xC0, 1, &[1, 2, 3], &[9, 8], 20);
        let r = read_long_header(&h).unwrap();
        assert_eq!(
            (r.version, r.dcid, r.scid),
            (1, &[1, 2, 3][..], &[9, 8][..])
        );
        let empty_cids = long(0x80, 0, &[], &[], 7);
        let r = read_long_header(&empty_cids).unwrap();
        assert_eq!((r.version, r.dcid.len(), r.scid.len()), (0, 0, 0));
        let big = long(0xC0, 7, &[3; 255], &[4; 255], 0);
        let r = read_long_header(&big).unwrap();
        assert_eq!((r.dcid.len(), r.scid.len()), (255, 255));
        assert_eq!(read_long_header(&[]), None);
        assert_eq!(read_long_header(&[0x40, 0, 0, 0, 1, 0, 0]), None);
        // every strict prefix of a header is truncated
        let full = long(0xC0, 1, &[1, 2, 3], &[9, 8], 0);
        for n in 0..full.len() {
            assert_eq!(read_long_header(&full[..n]), None, "prefix {n}");
        }
        assert!(read_long_header(&full).is_some());
    }

    #[test]
    fn short_header_predicate() {
        assert!(is_short_header(&[0x40, 1, 2]));
        assert!(is_short_header(&[0x00]));
        assert!(!is_short_header(&[0xC0]));
        assert!(!is_short_header(&[]));
    }

    #[test]
    fn initial_gate_table() {
        let cid = [1u8; 8];
        let ok = |first, version, dcid: &[u8], total| long(first, version, dcid, &cid, total);
        let cases: Vec<(&str, Vec<u8>, bool)> = vec![
            ("initial v1 at 1200", ok(0xC0, 1, &cid, 1200), true),
            (
                "initial v1 with packet number bits",
                ok(0xC3, 1, &cid, 1252),
                true,
            ),
            (
                "initial v1 at max",
                ok(0xC0, 1, &cid, JUMP_PACKET_MAX),
                true,
            ),
            ("initial v1 empty dcid", ok(0xC0, 1, &[], 1200), true),
            ("short initial", ok(0xC0, 1, &cid, 1199), false),
            (
                "over the carrier max",
                ok(0xC0, 1, &cid, JUMP_PACKET_MAX + 1),
                false,
            ),
            ("version 2", ok(0xC0, 0x6b33_43cf, &cid, 1200), false),
            ("version 0 (negotiation)", ok(0xC0, 0, &cid, 1200), false),
            ("0-RTT", ok(0xD0, 1, &cid, 1200), false),
            ("handshake", ok(0xE0, 1, &cid, 1200), false),
            ("retry", ok(0xF0, 1, &cid, 1200), false),
            ("fixed bit clear", ok(0x80, 1, &cid, 1200), false),
            ("dcid over 20", ok(0xC0, 1, &[1; 21], 1200), false),
            ("short header", vec![0x40; 1300], false),
            ("zeros", vec![0; 1300], false),
            ("garbage", vec![0xFF; 1300], false),
            ("empty", vec![], false),
        ];
        for (name, pkt, want) in cases {
            assert_eq!(is_v1_initial_shaped(&pkt), want, "{name}");
        }
        // truncated header inside a long enough datagram cannot pass
        let mut cut = vec![0xC0, 0, 0, 0, 1, 200];
        cut.resize(1300, 0);
        assert!(!is_v1_initial_shaped(&cut));
    }

    #[test]
    fn answer_gate_table() {
        let scid = [7u8; 8];
        let reply = |first, version| long(first, version, &scid, &[5; 8], 100);
        assert!(answers_gate(&reply(0xC0, 1), &scid), "initial");
        assert!(answers_gate(&reply(0xF0, 1), &scid), "retry");
        assert!(answers_gate(&reply(0x80, 0), &scid), "version negotiation");
        assert!(!answers_gate(&reply(0xC0, 1), &[6; 8]), "other scid");
        assert!(!answers_gate(&reply(0xC0, 1), &[7; 7]), "prefix of scid");
        let mut short = vec![0x40];
        short.extend_from_slice(&scid);
        short.resize(100, 0);
        assert!(!answers_gate(&short, &scid), "short header");
        assert!(!answers_gate(&[], &scid));
        assert!(!answers_gate(&[0xC0, 0, 0], &scid));
    }

    proptest! {
        #[test]
        fn round_trip_under_any_chunking(
            packets in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 1..=JUMP_PACKET_MAX), 0..8),
            chunk in 1usize..2000,
        ) {
            let mut wire = Vec::new();
            for p in &packets {
                wire.extend(encode_packet(p).unwrap());
            }
            let mut d = JumpStreamDecoder::new();
            let mut got = Vec::new();
            for piece in wire.chunks(chunk) {
                d.push(piece);
                got.extend(drain(&mut d).unwrap());
            }
            prop_assert_eq!(got, packets);
            prop_assert_eq!(d.buffered(), 0);
        }

        #[test]
        fn readers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1600),
                               scid in proptest::collection::vec(any::<u8>(), 0..24)) {
            let _ = read_long_header(&data);
            let _ = is_short_header(&data);
            let _ = is_v1_initial_shaped(&data);
            let _ = answers_gate(&data, &scid);
            let mut d = JumpStreamDecoder::new();
            d.push(&data);
            let _ = drain(&mut d);
        }
    }
}
