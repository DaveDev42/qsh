//! The hole-punch datagram (ADR-0054 decision 13): a fixed 16-byte UDP
//! payload, a 4-byte head and a 12-byte tag, sent from the same socket the
//! QUIC endpoint uses so the sender's NAT opens a mapping towards the peer.
//!
//! Sans-IO and total over arbitrary bytes. The datagram is not a `qsh/1`
//! message: it travels beside QUIC on the punching socket only. The
//! signalling messages (`PunchRequest` and friends, capability `punch.v1`,
//! `docs/design/protocol.md` §19) are protobuf in [`crate::wire`]; this module
//! holds their shape checks and the candidate validator.
//!
//! The tag is a keyed BLAKE3 hash of a direction label. The key is derived
//! from the 16-byte `attempt_id` (BLAKE3 wants 32 bytes), so only the two
//! ends of one attempt, and the rendezvous that relayed the id, can produce
//! a tag that the other end accepts. The head's first byte is `0x00`, so the
//! QUIC fixed bit is clear and the datagram is no QUIC packet; at 16 bytes
//! it is also below the 21 bytes under which quinn never answers an unknown
//! datagram, so one that slips past an interceptor still draws no reply.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use prost::Message;
use thiserror::Error;

use crate::wire::{
    PunchAnswer, PunchCandidate, PunchCandidateKind, PunchOffer, PunchReply, PunchRequest,
    RendezvousList,
};

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

/// Most candidates one message carries (ADR-0054 decision 8).
pub const MAX_PUNCH_CANDIDATES: usize = 8;

/// Most peer-reflexive candidates the dialing end learns in one attempt
/// (ADR-0054 decision 8).
pub const MAX_PEER_REFLEXIVE: usize = 4;

/// Most fingerprints one `RendezvousList` carries (ADR-0054 decision 11).
pub const MAX_RENDEZVOUS_FINGERPRINTS: usize = 4;

/// Length of a certificate fingerprint on the wire.
pub const PUNCH_FINGERPRINT_LEN: usize = 32;

/// Largest encoded length of any hole-punching message, 1 KiB (ADR-0054
/// decision 11). One request therefore costs a third party at most 1 KiB.
pub const PUNCH_MESSAGE_MAX: usize = 1024;

/// Rendezvous attempts one initiator may start per window (ADR-0054
/// decision 11).
pub const PUNCH_RATE: usize = 6;

/// The window `PUNCH_RATE` counts over, in seconds.
pub const PUNCH_RATE_WINDOW_SECS: u64 = 60;

/// Punching connections a rendezvous holds at once (ADR-0054 decision 10).
pub const RENDEZVOUS_MAX_CLIENTS: usize = 16;

/// Which shape rule a hole-punching message broke. It names the rule and
/// never repeats a value.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum PunchMessageError {
    /// `attempt_id` is not exactly 16 bytes.
    #[error("attempt_id must be exactly 16 bytes")]
    AttemptId,
    /// A fingerprint is not exactly 32 bytes.
    #[error("fingerprint must be exactly 32 bytes")]
    Fingerprint,
    /// More candidates than [`MAX_PUNCH_CANDIDATES`].
    #[error("more than 8 candidates")]
    TooManyCandidates,
    /// More fingerprints than [`MAX_RENDEZVOUS_FINGERPRINTS`].
    #[error("more than 4 fingerprints")]
    TooManyFingerprints,
    /// The encoded message is longer than [`PUNCH_MESSAGE_MAX`].
    #[error("message longer than 1024 bytes")]
    TooLarge,
}

/// Whether `ip`/`port` name an address a peer may be asked to send a punch
/// datagram to (ADR-0054 decision 8). `ip` is 4 or 16 bytes in network order
/// and `port` is `1..=65535`. Rejected: unspecified, loopback, link-local
/// (`169.254.0.0/16`, `fe80::/10`), multicast, `255.255.255.255`,
/// `0.0.0.0/8`, `240.0.0.0/4` and IPv4-mapped IPv6. Private and CGNAT
/// addresses pass: a same-LAN or inner-CGNAT path is a real path.
pub fn valid_punch_candidate(ip: &[u8], port: u32) -> Option<SocketAddr> {
    let port = u16::try_from(port).ok().filter(|p| *p != 0)?;
    let ip = match ip.len() {
        4 => {
            let v4 = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
            if v4.octets()[0] == 0
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.octets()[0] >= 240
            {
                return None;
            }
            IpAddr::V4(v4)
        }
        16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(ip);
            let v6 = Ipv6Addr::from(b);
            if v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some()
            {
                return None;
            }
            IpAddr::V6(v6)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

impl PunchCandidate {
    /// This candidate as an address, or `None` when
    /// [`valid_punch_candidate`] refuses it.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        valid_punch_candidate(&self.ip, self.port)
    }

    /// A candidate for `addr` of `kind`.
    pub fn from_addr(addr: SocketAddr, kind: PunchCandidateKind) -> Self {
        let ip = match addr.ip() {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        Self {
            ip,
            port: u32::from(addr.port()),
            kind: kind as i32,
        }
    }
}

/// The result of re-checking a received candidate list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CheckedCandidates {
    /// The accepted addresses, in the order received, duplicates removed.
    pub accepted: Vec<SocketAddr>,
    /// How many entries [`valid_punch_candidate`] refused (a duplicate is
    /// dropped but not counted here).
    pub dropped: usize,
}

/// Re-checks a received list: refuses more than [`MAX_PUNCH_CANDIDATES`],
/// drops and counts the entries [`valid_punch_candidate`] refuses, and
/// removes duplicates (ADR-0054 decision 8).
pub fn check_candidates(
    candidates: &[PunchCandidate],
) -> Result<CheckedCandidates, PunchMessageError> {
    check_count(candidates)?;
    let mut out = CheckedCandidates::default();
    for c in candidates {
        match c.socket_addr() {
            Some(a) if out.accepted.contains(&a) => {}
            Some(a) => out.accepted.push(a),
            None => out.dropped += 1,
        }
    }
    Ok(out)
}

fn check_size<M: Message>(m: &M) -> Result<(), PunchMessageError> {
    if m.encoded_len() > PUNCH_MESSAGE_MAX {
        return Err(PunchMessageError::TooLarge);
    }
    Ok(())
}

fn check_id(id: &[u8]) -> Result<(), PunchMessageError> {
    if id.len() == ATTEMPT_ID_LEN {
        Ok(())
    } else {
        Err(PunchMessageError::AttemptId)
    }
}

fn check_fingerprint(fp: &[u8]) -> Result<(), PunchMessageError> {
    if fp.len() == PUNCH_FINGERPRINT_LEN {
        Ok(())
    } else {
        Err(PunchMessageError::Fingerprint)
    }
}

fn check_count(candidates: &[PunchCandidate]) -> Result<(), PunchMessageError> {
    if candidates.len() > MAX_PUNCH_CANDIDATES {
        Err(PunchMessageError::TooManyCandidates)
    } else {
        Ok(())
    }
}

impl PunchRequest {
    /// Shape rules of ADR-0054 decision 11: `attempt_id` 16 bytes, a
    /// 32-byte fingerprint, at most eight candidates, at most 1 KiB encoded.
    /// Candidate values are checked by [`check_candidates`], which drops
    /// rather than refuses.
    pub fn validate(&self) -> Result<(), PunchMessageError> {
        check_size(self)?;
        check_id(&self.attempt_id)?;
        check_fingerprint(&self.target_fingerprint)?;
        check_count(&self.candidates)
    }

    /// The attempt id as an array; `None` unless it is 16 bytes.
    pub fn attempt(&self) -> Option<AttemptId> {
        self.attempt_id.as_slice().try_into().ok()
    }
}

impl PunchOffer {
    /// Same rules as [`PunchRequest::validate`], for the initiator's
    /// fingerprint.
    pub fn validate(&self) -> Result<(), PunchMessageError> {
        check_size(self)?;
        check_id(&self.attempt_id)?;
        check_fingerprint(&self.initiator_fingerprint)?;
        check_count(&self.candidates)
    }

    /// The attempt id as an array; `None` unless it is 16 bytes.
    pub fn attempt(&self) -> Option<AttemptId> {
        self.attempt_id.as_slice().try_into().ok()
    }
}

impl PunchAnswer {
    /// At most eight candidates and 1 KiB.
    pub fn validate(&self) -> Result<(), PunchMessageError> {
        check_size(self)?;
        check_count(&self.candidates)
    }
}

impl PunchReply {
    /// At most eight candidates and 1 KiB. An unknown `refusal` number reads
    /// as `None` through `refusal()`; a reply with no usable candidate and no
    /// refusal is the caller's failure to handle.
    pub fn validate(&self) -> Result<(), PunchMessageError> {
        check_size(self)?;
        check_count(&self.candidates)
    }
}

impl RendezvousList {
    /// At most four fingerprints of exactly 32 bytes each, 1 KiB.
    pub fn validate(&self) -> Result<(), PunchMessageError> {
        check_size(self)?;
        if self.fingerprints.len() > MAX_RENDEZVOUS_FINGERPRINTS {
            return Err(PunchMessageError::TooManyFingerprints);
        }
        self.fingerprints
            .iter()
            .try_for_each(|f| check_fingerprint(f))
    }
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

    use crate::wire::{
        ControlMessage, Response, control_message, decode_msg, encode_control, response,
    };
    use proptest::prelude::*;

    fn cand(ip: &[u8], port: u32) -> PunchCandidate {
        PunchCandidate {
            ip: ip.to_vec(),
            port,
            kind: PunchCandidateKind::Host as i32,
        }
    }

    fn good(n: u8) -> PunchCandidate {
        cand(&[203, 0, 113, n.max(1)], 4000 + u32::from(n))
    }

    #[test]
    fn punch_candidate_validation_table() {
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap().octets().to_vec();
        let accepted: &[(&[u8], u32)] = &[
            (&[203, 0, 113, 7], 1),
            (&[203, 0, 113, 7], 65535),
            (&[192, 168, 1, 10], 4433), // private
            (&[10, 0, 0, 1], 4433),
            (&[100, 64, 0, 1], 4433), // CGNAT
            (&[172, 16, 0, 1], 4433),
            (&[223, 255, 255, 255], 4433), // last unicast below 224/4
        ];
        for (ip, port) in accepted {
            assert!(valid_punch_candidate(ip, *port).is_some(), "{ip:?}:{port}");
        }
        for ip6 in ["2001:db8::1", "fd00::1", "2a00:1450::1", "fec0::1"] {
            assert!(valid_punch_candidate(&v6(ip6), 4433).is_some(), "{ip6}");
        }
        let refused: &[(&[u8], u32)] = &[
            (&[], 4433),
            (&[1, 2, 3], 4433),
            (&[1, 2, 3, 4, 5], 4433),
            (&[203, 0, 113, 7], 0),
            (&[203, 0, 113, 7], 65536),
            (&[203, 0, 113, 7], u32::MAX),
            (&[0, 0, 0, 0], 4433),
            (&[0, 1, 2, 3], 4433), // 0.0.0.0/8
            (&[127, 0, 0, 1], 4433),
            (&[127, 255, 255, 254], 4433),
            (&[169, 254, 1, 1], 4433),
            (&[224, 0, 0, 1], 4433),
            (&[239, 255, 255, 250], 4433),
            (&[255, 255, 255, 255], 4433),
            (&[240, 0, 0, 1], 4433), // 240.0.0.0/4
            (&[254, 1, 1, 1], 4433),
        ];
        for (ip, port) in refused {
            assert!(valid_punch_candidate(ip, *port).is_none(), "{ip:?}:{port}");
        }
        for ip6 in [
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "ff0e::1",
            "::ffff:203.0.113.7",
            "::ffff:127.0.0.1",
        ] {
            assert!(valid_punch_candidate(&v6(ip6), 4433).is_none(), "{ip6}");
        }
        assert!(valid_punch_candidate(&[0u8; 15], 4433).is_none());
        assert!(valid_punch_candidate(&[1u8; 17], 4433).is_none());
    }

    #[test]
    fn a_checked_list_drops_bad_entries_counts_them_and_removes_duplicates() {
        let list = vec![
            good(1),
            cand(&[127, 0, 0, 1], 4433),
            good(1),
            good(2),
            cand(&[1], 1),
        ];
        let got = check_candidates(&list).unwrap();
        assert_eq!(got.accepted.len(), 2);
        assert_eq!(got.dropped, 2);
        let nine: Vec<_> = (1..=9).map(good).collect();
        assert_eq!(
            check_candidates(&nine),
            Err(PunchMessageError::TooManyCandidates)
        );
        assert!(check_candidates(&nine[..8]).is_ok());
    }

    fn request() -> PunchRequest {
        PunchRequest {
            attempt_id: vec![9; 16],
            target_fingerprint: vec![1; 32],
            candidates: (1..=8).map(good).collect(),
        }
    }

    #[test]
    fn message_shape_rules_are_enforced() {
        assert!(request().validate().is_ok());
        let mut r = request();
        r.attempt_id = vec![9; 15];
        assert_eq!(r.validate(), Err(PunchMessageError::AttemptId));
        let mut r = request();
        r.attempt_id = vec![9; 17];
        assert_eq!(r.validate(), Err(PunchMessageError::AttemptId));
        let mut r = request();
        r.target_fingerprint = vec![1; 31];
        assert_eq!(r.validate(), Err(PunchMessageError::Fingerprint));
        let mut r = request();
        r.candidates.push(good(9));
        assert_eq!(r.validate(), Err(PunchMessageError::TooManyCandidates));
        // A long ip field is what pushes a message over 1 KiB.
        let mut r = request();
        r.candidates[0].ip = vec![1; 2000];
        assert_eq!(r.validate(), Err(PunchMessageError::TooLarge));

        let o = PunchOffer {
            attempt_id: vec![9; 16],
            initiator_fingerprint: vec![1; 33],
            candidates: vec![],
        };
        assert_eq!(o.validate(), Err(PunchMessageError::Fingerprint));
        let a = PunchAnswer {
            candidates: (1..=9).map(good).collect(),
        };
        assert_eq!(a.validate(), Err(PunchMessageError::TooManyCandidates));
        let l = RendezvousList {
            fingerprints: vec![vec![0; 32]; 5],
        };
        assert_eq!(l.validate(), Err(PunchMessageError::TooManyFingerprints));
        let l = RendezvousList {
            fingerprints: vec![vec![0; 32], vec![0; 31]],
        };
        assert_eq!(l.validate(), Err(PunchMessageError::Fingerprint));
        let l = RendezvousList {
            fingerprints: vec![vec![0; 32]; 4],
        };
        assert!(l.validate().is_ok());
    }

    #[test]
    fn the_encoder_refuses_a_malformed_punch_message() {
        let mut r = request();
        r.attempt_id = vec![];
        let m = ControlMessage::new(1, control_message::Body::PunchRequest(r));
        assert!(encode_control(&m).is_err());
        let m = ControlMessage::response(
            1,
            response::Body::RendezvousList(RendezvousList {
                fingerprints: vec![vec![0; 32]; 5],
            }),
        );
        assert!(encode_control(&m).is_err());
        let m = ControlMessage::new(1, control_message::Body::PunchRequest(request()));
        assert!(encode_control(&m).is_ok());
    }

    /// The field number of the first field after an optional `request_id`.
    fn body_number(bytes: &[u8]) -> u32 {
        let mut i = 0;
        if bytes[0] == 0x08 {
            i = 1;
            while bytes[i] & 0x80 != 0 {
                i += 1;
            }
            i += 1;
        }
        let mut v = 0u32;
        let mut shift = 0;
        loop {
            let b = bytes[i];
            v |= u32::from(b & 0x7f) << shift;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        v >> 3
    }

    #[test]
    fn the_punch_messages_keep_their_pinned_numbers() {
        // ControlMessage 90, 91, 92 and Response 16, 17, 18 are wire
        // (protocol.md section 9).
        let enc =
            |b: control_message::Body| prost::Message::encode_to_vec(&ControlMessage::new(1, b));
        assert_eq!(
            body_number(&enc(
                control_message::Body::PunchRequest(Default::default())
            )),
            90
        );
        assert_eq!(
            body_number(&enc(control_message::Body::PunchOffer(Default::default()))),
            91
        );
        assert_eq!(
            body_number(&enc(control_message::Body::RendezvousQuery(
                Default::default()
            ))),
            92
        );
        let tag = |b: response::Body| {
            body_number(&prost::Message::encode_to_vec(&Response { body: Some(b) }))
        };
        assert_eq!(tag(response::Body::PunchReply(Default::default())), 16);
        assert_eq!(tag(response::Body::PunchAnswer(Default::default())), 17);
        assert_eq!(tag(response::Body::RendezvousList(Default::default())), 18);
    }

    #[test]
    fn the_capability_is_advertised() {
        assert_eq!(crate::wire::CAP_PUNCH_V1, "punch.v1");
        assert!(crate::wire::LOCAL_CAPABILITIES.contains(&"punch.v1"));
    }

    #[test]
    fn a_maximal_message_fits_the_cap_with_room() {
        let r = PunchRequest {
            attempt_id: vec![0xff; 16],
            target_fingerprint: vec![0xff; 32],
            candidates: (0..8)
                .map(|_| PunchCandidate {
                    ip: vec![0x20; 16],
                    port: 65535,
                    kind: PunchCandidateKind::Reflexive as i32,
                })
                .collect(),
        };
        assert!(prost::Message::encoded_len(&r) < PUNCH_MESSAGE_MAX / 2);
        assert!(r.validate().is_ok());
    }

    proptest! {
        #[test]
        fn candidates_round_trip_and_the_validator_is_total(
            ip in proptest::collection::vec(any::<u8>(), 0..20),
            port in any::<u32>(),
            kind in 0i32..4,
        ) {
            let c = PunchCandidate { ip, port, kind };
            let bytes = prost::Message::encode_to_vec(&c);
            let back: PunchCandidate = decode_msg(&bytes).unwrap();
            prop_assert_eq!(&back, &c);
            if let Some(a) = back.socket_addr() {
                let again = PunchCandidate::from_addr(a, PunchCandidateKind::Host);
                prop_assert_eq!(again.ip, c.ip);
                prop_assert_eq!(again.port, c.port);
                prop_assert!(a.port() != 0);
            }
        }

        #[test]
        fn decode_then_validate_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..1500)
        ) {
            if let Ok(m) = decode_msg::<ControlMessage>(&data) {
                match m.body {
                    Some(control_message::Body::PunchRequest(r)) => {
                        let _ = r.validate();
                        let _ = check_candidates(&r.candidates);
                    }
                    Some(control_message::Body::PunchOffer(o)) => {
                        let _ = o.validate();
                        let _ = check_candidates(&o.candidates);
                    }
                    _ => {}
                }
            }
        }
    }
}
