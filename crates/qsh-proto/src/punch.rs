//! The hole-punch datagram (ADR-0054 decision 13): a fixed 16-byte UDP
//! payload, a 4-byte head and a 12-byte tag, sent from the same socket the
//! QUIC endpoint uses so the sender's NAT opens a mapping towards the peer.
//!
//! Sans-IO and total over arbitrary bytes. This is not a `qsh/1` message:
//! nothing negotiates it yet (`punch.v1` is a later step), and the datagram
//! travels beside QUIC on the punching socket only, so it sits outside the
//! wire freeze until that capability lands.
//!
//! The tag is a keyed BLAKE3 hash of a direction label. The key is derived
//! from the 16-byte `attempt_id` (BLAKE3 wants 32 bytes), so only the two
//! ends of one attempt, and the rendezvous that relayed the id, can produce
//! a tag that the other end accepts. The head's first byte is `0x00`, so the
//! QUIC fixed bit is clear and the datagram is no QUIC packet; at 16 bytes
//! it is also below the 21 bytes under which quinn never answers an unknown
//! datagram, so one that slips past an interceptor still draws no reply.

/// Length of a punch datagram.
pub const PUNCH_DATAGRAM_LEN: usize = 16;

/// The 4-byte head. The first byte is zero: the QUIC fixed bit is clear.
pub const PUNCH_HEAD: [u8; 4] = [0x00, 0x71, 0x70, 0x01];

/// Length of the tag.
pub const PUNCH_TAG_LEN: usize = PUNCH_DATAGRAM_LEN - PUNCH_HEAD.len();

/// Length of an attempt id.
pub const ATTEMPT_ID_LEN: usize = 16;

/// The tag carried by a punch datagram.
pub type PunchTag = [u8; PUNCH_TAG_LEN];

/// The 16 random bytes that name one punching attempt.
pub type AttemptId = [u8; ATTEMPT_ID_LEN];

const KEY_CONTEXT: &str = "qsh punch attempt key v1";

/// Which way a punch datagram travels. A is the end that dials (TLS
/// client); B is the target that opens a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PunchDirection {
    /// From A towards B.
    AToB,
    /// From B towards A.
    BToA,
}

impl PunchDirection {
    /// The label hashed into the tag.
    pub const fn label(self) -> &'static [u8] {
        match self {
            PunchDirection::AToB => b"qsh punch a->b",
            PunchDirection::BToA => b"qsh punch b->a",
        }
    }

    /// The opposite direction: what the receiver of this direction sends.
    pub const fn reverse(self) -> Self {
        match self {
            PunchDirection::AToB => PunchDirection::BToA,
            PunchDirection::BToA => PunchDirection::AToB,
        }
    }
}

/// The tag a sender puts on a punch datagram of `attempt_id` going
/// `direction`.
pub fn punch_tag(attempt_id: &AttemptId, direction: PunchDirection) -> PunchTag {
    let key = blake3::derive_key(KEY_CONTEXT, attempt_id);
    let hash = blake3::keyed_hash(&key, direction.label());
    let mut tag = [0u8; PUNCH_TAG_LEN];
    tag.copy_from_slice(&hash.as_bytes()[..PUNCH_TAG_LEN]);
    tag
}

/// Builds the datagram for `tag`.
pub fn encode_punch_datagram(tag: &PunchTag) -> [u8; PUNCH_DATAGRAM_LEN] {
    let mut out = [0u8; PUNCH_DATAGRAM_LEN];
    out[..PUNCH_HEAD.len()].copy_from_slice(&PUNCH_HEAD);
    out[PUNCH_HEAD.len()..].copy_from_slice(tag);
    out
}

/// Reads a punch datagram. `None` unless `bytes` is exactly
/// [`PUNCH_DATAGRAM_LEN`] long and starts with [`PUNCH_HEAD`]; the tag is not
/// checked here (the receiver compares it with the tags it expects).
pub fn decode_punch_datagram(bytes: &[u8]) -> Option<PunchTag> {
    if bytes.len() != PUNCH_DATAGRAM_LEN || bytes[..PUNCH_HEAD.len()] != PUNCH_HEAD {
        return None;
    }
    let mut tag = [0u8; PUNCH_TAG_LEN];
    tag.copy_from_slice(&bytes[PUNCH_HEAD.len()..]);
    Some(tag)
}

/// Whether `bytes` is a punch datagram of `attempt_id` going `direction`.
/// The tag comparison runs over every byte.
pub fn verify_punch_datagram(
    bytes: &[u8],
    attempt_id: &AttemptId,
    direction: PunchDirection,
) -> bool {
    let Some(got) = decode_punch_datagram(bytes) else {
        return false;
    };
    let want = punch_tag(attempt_id, direction);
    got.iter()
        .zip(want.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: AttemptId = [7; ATTEMPT_ID_LEN];

    #[test]
    fn a_datagram_round_trips_and_verifies_in_its_own_direction_only() {
        for dir in [PunchDirection::AToB, PunchDirection::BToA] {
            let bytes = encode_punch_datagram(&punch_tag(&ID, dir));
            assert_eq!(bytes.len(), PUNCH_DATAGRAM_LEN);
            assert_eq!(bytes[..4], PUNCH_HEAD);
            assert!(verify_punch_datagram(&bytes, &ID, dir));
            assert!(
                !verify_punch_datagram(&bytes, &ID, dir.reverse()),
                "{dir:?} accepted in the other direction"
            );
        }
    }

    #[test]
    fn the_two_directions_and_two_attempts_have_distinct_tags() {
        let other: AttemptId = [8; ATTEMPT_ID_LEN];
        let tags = [
            punch_tag(&ID, PunchDirection::AToB),
            punch_tag(&ID, PunchDirection::BToA),
            punch_tag(&other, PunchDirection::AToB),
            punch_tag(&other, PunchDirection::BToA),
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "tags {i} and {j} collide");
            }
        }
    }

    #[test]
    fn a_wrong_attempt_id_is_rejected() {
        let bytes = encode_punch_datagram(&punch_tag(&ID, PunchDirection::AToB));
        assert!(!verify_punch_datagram(
            &bytes,
            &[9; ATTEMPT_ID_LEN],
            PunchDirection::AToB
        ));
    }

    #[test]
    fn truncated_padded_and_mis_headed_datagrams_are_rejected() {
        let good = encode_punch_datagram(&punch_tag(&ID, PunchDirection::AToB));
        for len in 0..PUNCH_DATAGRAM_LEN {
            assert!(decode_punch_datagram(&good[..len]).is_none(), "len {len}");
        }
        let mut longer = good.to_vec();
        longer.push(0);
        assert!(decode_punch_datagram(&longer).is_none());
        for i in 0..PUNCH_HEAD.len() {
            let mut bad = good;
            bad[i] ^= 0x80;
            assert!(decode_punch_datagram(&bad).is_none(), "head byte {i}");
        }
    }

    #[test]
    fn every_flipped_tag_bit_is_rejected() {
        let good = encode_punch_datagram(&punch_tag(&ID, PunchDirection::BToA));
        for byte in PUNCH_HEAD.len()..PUNCH_DATAGRAM_LEN {
            for bit in 0..8 {
                let mut bad = good;
                bad[byte] ^= 1 << bit;
                assert!(!verify_punch_datagram(&bad, &ID, PunchDirection::BToA));
            }
        }
    }

    #[test]
    fn the_head_leaves_the_quic_fixed_bit_clear_and_fits_under_the_reset_floor() {
        assert_eq!(PUNCH_HEAD[0] & 0x40, 0);
        const { assert!(PUNCH_DATAGRAM_LEN <= 21) };
    }

    #[test]
    fn the_tag_derivation_is_pinned() {
        // Both ends must compute the same bytes, so a change here is a change
        // on the wire.
        let hex: String = punch_tag(&ID, PunchDirection::AToB)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, "45da71c4406fcd1b978ad876");
    }
}
