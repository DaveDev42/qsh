//! Fuzzes the hole-punching surface of `qsh-proto` (ADR-0054 decisions 8, 11
//! and 13): the candidate validator `valid_punch_candidate`, the shape checks
//! on the six signalling messages after a peer-controlled decode, and the
//! 16-byte punch datagram with its tag comparison.
//!
//! The first byte picks the entry point, the rest is the input:
//! - 0: the bytes are a `PunchCandidate`; the validator must be total and a
//!   valid address must re-encode to the same ip and port.
//! - 1..=5: the bytes are a `PunchRequest` / `PunchOffer` / `PunchAnswer` /
//!   `PunchReply` / `RendezvousList`; `validate()` and `check_candidates()`
//!   must not panic, and a checked list holds at most eight distinct,
//!   non-forbidden addresses with `accepted + dropped <= len`.
//! - 6: the bytes are a datagram; decode and verify must be total, and a
//!   datagram built from a tag verifies in its own direction only.
//!
//! The wrapped socket's receive filter (GRO segment boundaries) lives in
//! `qsh-transport` and is covered by its unit tests, not here.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::punch::{
    ATTEMPT_ID_LEN, MAX_PUNCH_CANDIDATES, PunchDirection, check_candidates, decode_punch_datagram,
    encode_punch_datagram, punch_tag, valid_punch_candidate, verify_punch_datagram,
};
use qsh_proto::wire::{
    PunchAnswer, PunchCandidate, PunchCandidateKind, PunchOffer, PunchReply, PunchRequest,
    RendezvousList, decode_msg,
};

fn check_list(candidates: &[PunchCandidate]) {
    let Ok(checked) = check_candidates(candidates) else {
        assert!(candidates.len() > MAX_PUNCH_CANDIDATES);
        return;
    };
    assert!(candidates.len() <= MAX_PUNCH_CANDIDATES);
    assert!(checked.accepted.len() + checked.dropped <= candidates.len());
    for (i, a) in checked.accepted.iter().enumerate() {
        assert!(a.port() != 0);
        assert!(!a.ip().is_loopback() && !a.ip().is_unspecified() && !a.ip().is_multicast());
        assert!(!checked.accepted[..i].contains(a));
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, body)) = data.split_first() else {
        return;
    };
    match which % 7 {
        0 => {
            if let Ok(c) = decode_msg::<PunchCandidate>(body) {
                if let Some(addr) = c.socket_addr() {
                    let again = PunchCandidate::from_addr(addr, PunchCandidateKind::Host);
                    assert_eq!(again.ip, c.ip);
                    assert_eq!(again.port, c.port);
                }
                let _ = valid_punch_candidate(&c.ip, c.port);
            }
        }
        1 => {
            if let Ok(m) = decode_msg::<PunchRequest>(body) {
                let _ = m.validate();
                let _ = m.attempt();
                check_list(&m.candidates);
            }
        }
        2 => {
            if let Ok(m) = decode_msg::<PunchOffer>(body) {
                let _ = m.validate();
                let _ = m.attempt();
                check_list(&m.candidates);
            }
        }
        3 => {
            if let Ok(m) = decode_msg::<PunchAnswer>(body) {
                let _ = m.validate();
                check_list(&m.candidates);
            }
        }
        4 => {
            if let Ok(m) = decode_msg::<PunchReply>(body) {
                let _ = m.validate();
                let _ = m.refusal();
                check_list(&m.candidates);
                if let Some(c) = &m.initiator_reflexive {
                    let _ = c.socket_addr();
                }
            }
        }
        5 => {
            if let Ok(m) = decode_msg::<RendezvousList>(body) {
                let _ = m.validate();
            }
        }
        _ => {
            let _ = decode_punch_datagram(body);
            if body.len() >= ATTEMPT_ID_LEN {
                let mut id = [0u8; ATTEMPT_ID_LEN];
                id.copy_from_slice(&body[..ATTEMPT_ID_LEN]);
                let _ = verify_punch_datagram(&body[ATTEMPT_ID_LEN..], &id, PunchDirection::AToB);
                let tag = punch_tag(&id, PunchDirection::AToB);
                let dgram = encode_punch_datagram(&tag);
                assert!(verify_punch_datagram(&dgram, &id, PunchDirection::AToB));
                assert!(!verify_punch_datagram(&dgram, &id, PunchDirection::BToA));
            }
        }
    }
});
