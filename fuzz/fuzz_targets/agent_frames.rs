//! Fuzzes the ssh-agent framing decoder of `qsh-proto` (ADR-0055 decisions 4
//! and 12): `AgentDecoder` fed in data-chosen chunks, and the request filter
//! table.
//!
//! The first byte picks the chunk size (1..=64), the rest is the stream.
//! The decoder must not panic; every message it returns is whole (length
//! prefix consistent with the bytes, type byte equal to `kind`, at most
//! `AGENT_MESSAGE_MAX` long); an error is sticky and leaves nothing
//! buffered; chunking does not change the messages or the error; the filter
//! passes exactly types 11 and 13.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::agent::{
    AGENT_MESSAGE_MAX, AgentDecoder, AgentFrameError, AgentMessage, RequestDisposition,
    request_disposition,
};

fn run(data: &[u8], chunk: usize) -> (Vec<AgentMessage>, Option<AgentFrameError>, usize) {
    let mut d = AgentDecoder::new();
    let mut out = Vec::new();
    let mut err = None;
    'feed: for piece in data.chunks(chunk) {
        d.push(piece);
        loop {
            match d.next_message() {
                Ok(Some(m)) => out.push(m),
                Ok(None) => break,
                Err(e) => {
                    err = Some(e);
                    assert_eq!(d.next_message(), Err(e));
                    assert_eq!(d.buffered(), 0);
                    break 'feed;
                }
            }
        }
    }
    (out, err, d.buffered())
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(pick % 64) + 1;
    let (msgs, err, left) = run(body, chunk);
    for m in &msgs {
        let len = u32::from_be_bytes([m.bytes[0], m.bytes[1], m.bytes[2], m.bytes[3]]) as usize;
        assert!((1..=AGENT_MESSAGE_MAX).contains(&len));
        assert_eq!(m.bytes.len(), 4 + len);
        assert_eq!(m.bytes[4], m.kind);
        let pass = request_disposition(m.kind) == RequestDisposition::Forward;
        assert_eq!(pass, m.kind == 11 || m.kind == 13);
    }
    let (msgs2, err2, left2) = run(body, body.len().max(1));
    assert_eq!(msgs, msgs2);
    assert_eq!(err, err2);
    assert_eq!(left, left2);
});
