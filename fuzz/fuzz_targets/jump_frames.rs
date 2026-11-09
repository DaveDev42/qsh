//! Fuzzes the jump stream-carrier decoder and the QUIC long-header reader of
//! `qsh-proto` (ADR-0056 decisions 4 and 8).
//!
//! The first byte picks the chunk size (1..=64), the rest is the stream.
//! The decoder must not panic; every packet it returns is 1..=
//! `JUMP_PACKET_MAX` long and re-encodes to the bytes it consumed; an error
//! is sticky and leaves nothing buffered; chunking changes neither the
//! packets nor the error. The long-header reader and the gate predicates are
//! run on the raw input and on each packet and must agree with each other.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::jump::{
    JUMP_PACKET_MAX, JUMP_PACKET_MIN, JumpFrameError, JumpStreamDecoder, QUIC_V1, answers_gate,
    encode_packet, is_short_header, is_v1_initial_shaped, read_long_header,
};

fn run(data: &[u8], chunk: usize) -> (Vec<Vec<u8>>, Option<JumpFrameError>, usize) {
    let mut d = JumpStreamDecoder::new();
    let mut out = Vec::new();
    let mut err = None;
    'feed: for piece in data.chunks(chunk) {
        d.push(piece);
        loop {
            match d.next_packet() {
                Ok(Some(p)) => out.push(p),
                Ok(None) => break,
                Err(e) => {
                    err = Some(e);
                    assert_eq!(d.next_packet(), Err(e));
                    assert_eq!(d.buffered(), 0);
                    break 'feed;
                }
            }
        }
    }
    (out, err, d.buffered())
}

fn check_header(p: &[u8]) {
    let long = read_long_header(p);
    if is_short_header(p) {
        assert!(long.is_none());
    }
    if is_v1_initial_shaped(p) {
        let h = long.expect("initial-shaped implies a long header");
        assert_eq!(h.version, QUIC_V1);
        assert!((JUMP_PACKET_MIN..=JUMP_PACKET_MAX).contains(&p.len()));
    }
    match long {
        Some(h) => {
            assert!(answers_gate(p, h.dcid));
            let mut other = h.dcid.to_vec();
            other.push(0);
            assert!(!answers_gate(p, &other));
        }
        None => assert!(!answers_gate(p, &[])),
    }
}

fuzz_target!(|data: &[u8]| {
    check_header(data);
    let Some((&pick, body)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(pick % 64) + 1;
    let (pkts, err, left) = run(body, chunk);
    let mut consumed = 0;
    for p in &pkts {
        assert!((1..=JUMP_PACKET_MAX).contains(&p.len()));
        let enc = encode_packet(p).expect("returned packets re-encode");
        assert_eq!(&body[consumed..consumed + enc.len()], &enc[..]);
        consumed += enc.len();
        check_header(p);
    }
    if err.is_none() {
        assert_eq!(consumed + left, body.len());
    }
    let (pkts2, err2, left2) = run(body, body.len().max(1));
    assert_eq!(pkts, pkts2);
    assert_eq!(err, err2);
    assert_eq!(left, left2);
});
