//! ssh-agent message framing and the request filter table (ADR-0055
//! decisions 4 and 12).
//!
//! An ssh-agent message is a 4-byte big-endian length, a 1-byte type and the
//! rest; the length counts the type byte and the body. The `AGENT` stream
//! carries those bytes unchanged. This module is sans-IO and reads only the
//! length and the type: it never interprets a body. The client side of the
//! stream uses it to cut the host's bytes into whole messages, to pass on
//! only the requests in [`ALLOWED_REQUESTS`], and to answer everything else
//! itself with [`FAILURE_REPLY`] so the local agent never sees it.
//!
//! The decoder does not allocate for a declared length: it rejects a zero or
//! over-cap length from the 4 header bytes alone, and buffers only bytes
//! that actually arrived.

use thiserror::Error;

/// Longest message the decoder accepts, counted the way the wire counts it
/// (type byte plus body). Same value as OpenSSH's `AGENT_MAX_LEN`.
pub const AGENT_MESSAGE_MAX: usize = 262_144;

/// Length of the length prefix.
const HEADER_LEN: usize = 4;

/// `SSH_AGENT_FAILURE`.
pub const SSH_AGENT_FAILURE: u8 = 5;
/// `SSH2_AGENTC_REQUEST_IDENTITIES`.
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// `SSH2_AGENT_IDENTITIES_ANSWER`.
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// `SSH2_AGENTC_SIGN_REQUEST`.
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
/// `SSH2_AGENT_SIGN_RESPONSE`.
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

/// The request types the client passes to the local agent. Every other type
/// is answered with [`FAILURE_REPLY`] by the client (ADR-0055 decision 12).
/// Widening this table needs a new ADR.
pub const ALLOWED_REQUESTS: [u8; 2] = [SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST];

/// The complete `FAILURE` message: length 1, type 5.
pub const FAILURE_REPLY: [u8; 5] = [0, 0, 0, 1, SSH_AGENT_FAILURE];

/// What the client does with a request of a given type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDisposition {
    /// Send the message to the local agent.
    Forward,
    /// Do not send it; write [`FAILURE_REPLY`] to the stream.
    Fail,
}

/// Look a request type up in [`ALLOWED_REQUESTS`].
pub fn request_disposition(kind: u8) -> RequestDisposition {
    if ALLOWED_REQUESTS.contains(&kind) {
        RequestDisposition::Forward
    } else {
        RequestDisposition::Fail
    }
}

/// A framing violation. The caller resets the stream with `BAD_HEADER` and
/// closes the local agent connection (ADR-0055 decision 4). The decoder
/// stays failed after returning one.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentFrameError {
    /// The declared length is 0, so there is no type byte.
    #[error("agent message with length 0")]
    ZeroLength,
    /// The declared length exceeds [`AGENT_MESSAGE_MAX`].
    #[error("agent message length {len} exceeds max {max}")]
    Oversize {
        /// The length the peer declared.
        len: u32,
        /// The cap, [`AGENT_MESSAGE_MAX`].
        max: usize,
    },
}

/// One whole message cut from the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMessage {
    /// The type byte.
    pub kind: u8,
    /// The message exactly as it arrived, length prefix included, so it can
    /// be written to the local agent unchanged.
    pub bytes: Vec<u8>,
}

/// Incremental decoder: [`push`](Self::push) bytes as they arrive, then call
/// [`next_message`](Self::next_message) until it returns `Ok(None)`.
#[derive(Debug, Default)]
pub struct AgentDecoder {
    buf: Vec<u8>,
    failed: Option<AgentFrameError>,
}

impl AgentDecoder {
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
    /// the peer cut a message short.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Cut one whole message off the front of the buffer.
    ///
    /// - `Ok(None)`: more bytes are needed.
    /// - `Err(_)`: the header is invalid; the same error is returned from
    ///   then on.
    pub fn next_message(&mut self) -> Result<Option<AgentMessage>, AgentFrameError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let Some(head) = self.buf.first_chunk::<HEADER_LEN>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*head);
        let fail = if len == 0 {
            Some(AgentFrameError::ZeroLength)
        } else if len as usize > AGENT_MESSAGE_MAX {
            Some(AgentFrameError::Oversize {
                len,
                max: AGENT_MESSAGE_MAX,
            })
        } else {
            None
        };
        if let Some(e) = fail {
            self.failed = Some(e);
            self.buf = Vec::new();
            return Err(e);
        }
        let total = HEADER_LEN + len as usize;
        if self.buf.len() < total {
            return Ok(None);
        }
        let rest = self.buf.split_off(total);
        let bytes = std::mem::replace(&mut self.buf, rest);
        Ok(Some(AgentMessage {
            kind: bytes[HEADER_LEN],
            bytes,
        }))
    }
}

/// Encode one message: `kind` and `body` behind the length prefix. For tests
/// and the fake agent; `None` when the message would exceed
/// [`AGENT_MESSAGE_MAX`].
pub fn encode_message(kind: u8, body: &[u8]) -> Option<Vec<u8>> {
    let len = body.len() + 1;
    if len > AGENT_MESSAGE_MAX {
        return None;
    }
    let mut out = Vec::with_capacity(HEADER_LEN + len);
    out.extend_from_slice(&u32::try_from(len).ok()?.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn msg(kind: u8, body: &[u8]) -> Vec<u8> {
        encode_message(kind, body).unwrap()
    }

    #[test]
    fn failure_reply_is_a_well_formed_message() {
        let mut d = AgentDecoder::new();
        d.push(&FAILURE_REPLY);
        let m = d.next_message().unwrap().unwrap();
        assert_eq!(m.kind, SSH_AGENT_FAILURE);
        assert_eq!(m.bytes, FAILURE_REPLY);
        assert_eq!(msg(SSH_AGENT_FAILURE, &[]), FAILURE_REPLY);
    }

    /// One row per message type: only 11 and 13 are passed on; every other
    /// byte value, named or not, is answered with FAILURE by the client.
    #[test]
    fn agent_filter_table() {
        use RequestDisposition::{Fail, Forward};
        let named: &[(u8, &str, RequestDisposition)] = &[
            (1, "SSH_AGENTC_REQUEST_RSA_IDENTITIES", Fail),
            (3, "SSH_AGENTC_RSA_CHALLENGE", Fail),
            (5, "SSH_AGENT_FAILURE", Fail),
            (6, "SSH_AGENT_SUCCESS", Fail),
            (7, "SSH_AGENTC_ADD_RSA_IDENTITY", Fail),
            (8, "SSH_AGENTC_REMOVE_RSA_IDENTITY", Fail),
            (9, "SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES", Fail),
            (11, "SSH2_AGENTC_REQUEST_IDENTITIES", Forward),
            (12, "SSH2_AGENT_IDENTITIES_ANSWER", Fail),
            (13, "SSH2_AGENTC_SIGN_REQUEST", Forward),
            (14, "SSH2_AGENT_SIGN_RESPONSE", Fail),
            (17, "SSH2_AGENTC_ADD_IDENTITY", Fail),
            (18, "SSH2_AGENTC_REMOVE_IDENTITY", Fail),
            (19, "SSH2_AGENTC_REMOVE_ALL_IDENTITIES", Fail),
            (20, "SSH_AGENTC_ADD_SMARTCARD_KEY", Fail),
            (21, "SSH_AGENTC_REMOVE_SMARTCARD_KEY", Fail),
            (22, "SSH_AGENTC_LOCK", Fail),
            (23, "SSH_AGENTC_UNLOCK", Fail),
            (25, "SSH2_AGENTC_ADD_ID_CONSTRAINED", Fail),
            (26, "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED", Fail),
            (27, "SSH_AGENTC_EXTENSION", Fail),
            (0, "zero", Fail),
            (255, "unknown", Fail),
        ];
        for (kind, name, want) in named {
            assert_eq!(request_disposition(*kind), *want, "{name} ({kind})");
        }
        for kind in 0..=u8::MAX {
            let want = if kind == 11 || kind == 13 {
                Forward
            } else {
                Fail
            };
            assert_eq!(request_disposition(kind), want, "type {kind}");
        }
        assert_eq!(ALLOWED_REQUESTS, [11, 13]);
    }

    /// Decoder level only: the oversize error is what the caller turns into
    /// a `BAD_HEADER` stream reset.
    // The stream-level version (reset, local agent connection closed, nothing
    // written to the agent) comes with the client dispatcher step.
    #[test]
    fn an_oversized_agent_frame_resets_the_stream() {
        let mut d = AgentDecoder::new();
        let over = (AGENT_MESSAGE_MAX as u32 + 1).to_be_bytes();
        d.push(&over);
        let want = AgentFrameError::Oversize {
            len: AGENT_MESSAGE_MAX as u32 + 1,
            max: AGENT_MESSAGE_MAX,
        };
        assert_eq!(d.next_message(), Err(want));
        // Failed for good, and later bytes are not kept.
        d.push(&FAILURE_REPLY);
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.next_message(), Err(want));
        // u32::MAX is refused from the header alone, with nothing allocated.
        let mut d = AgentDecoder::new();
        d.push(&u32::MAX.to_be_bytes());
        assert!(matches!(
            d.next_message(),
            Err(AgentFrameError::Oversize { .. })
        ));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn the_cap_itself_is_accepted() {
        let mut d = AgentDecoder::new();
        let body = vec![7u8; AGENT_MESSAGE_MAX - 1];
        d.push(&msg(13, &body));
        let m = d.next_message().unwrap().unwrap();
        assert_eq!(m.bytes.len(), HEADER_LEN + AGENT_MESSAGE_MAX);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn a_zero_length_message_is_an_error() {
        let mut d = AgentDecoder::new();
        d.push(&[0, 0, 0, 0, 11]);
        assert_eq!(d.next_message(), Err(AgentFrameError::ZeroLength));
        assert_eq!(d.next_message(), Err(AgentFrameError::ZeroLength));
    }

    #[test]
    fn a_short_header_or_body_waits_for_more() {
        let mut d = AgentDecoder::new();
        d.push(&[0, 0, 0]);
        assert_eq!(d.next_message(), Ok(None));
        d.push(&[2, 13]);
        assert_eq!(d.next_message(), Ok(None));
        d.push(&[9]);
        let m = d.next_message().unwrap().unwrap();
        assert_eq!(m.kind, 13);
        assert_eq!(m.bytes, vec![0, 0, 0, 2, 13, 9]);
        assert_eq!(d.next_message(), Ok(None));
    }

    #[test]
    fn two_messages_in_one_push_come_out_in_order() {
        let mut d = AgentDecoder::new();
        let mut both = msg(11, &[]);
        both.extend(msg(13, b"abc"));
        d.push(&both);
        assert_eq!(d.next_message().unwrap().unwrap().kind, 11);
        assert_eq!(d.next_message().unwrap().unwrap().kind, 13);
        assert_eq!(d.next_message(), Ok(None));
    }

    #[test]
    fn the_declared_length_is_not_allocated_up_front() {
        let mut d = AgentDecoder::new();
        d.push(&(AGENT_MESSAGE_MAX as u32).to_be_bytes());
        d.push(&[13]);
        assert_eq!(d.next_message(), Ok(None));
        assert!(d.buf.capacity() < 1024);
    }

    #[test]
    fn encode_message_refuses_an_oversize_body() {
        assert!(encode_message(13, &vec![0; AGENT_MESSAGE_MAX]).is_none());
        assert!(encode_message(13, &vec![0; AGENT_MESSAGE_MAX - 1]).is_some());
    }

    proptest! {
        /// Chunking never changes what comes out.
        #[test]
        fn chunking_is_invisible(
            bodies in proptest::collection::vec(
                (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..64)), 0..8),
            cuts in proptest::collection::vec(1usize..16, 1..32),
        ) {
            let mut stream = Vec::new();
            for (k, b) in &bodies {
                stream.extend(encode_message(*k, b).unwrap());
            }
            let mut d = AgentDecoder::new();
            let mut got = Vec::new();
            let mut at = 0;
            let mut i = 0;
            while at < stream.len() {
                let n = cuts[i % cuts.len()].min(stream.len() - at);
                d.push(&stream[at..at + n]);
                at += n;
                i += 1;
                while let Some(m) = d.next_message().unwrap() {
                    got.push((m.kind, m.bytes));
                }
            }
            prop_assert_eq!(got.len(), bodies.len());
            for ((k, b), (gk, gb)) in bodies.iter().zip(got) {
                prop_assert_eq!(*k, gk);
                prop_assert_eq!(encode_message(*k, b).unwrap(), gb);
            }
            prop_assert_eq!(d.buffered(), 0);
        }

        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut d = AgentDecoder::new();
            d.push(&data);
            while let Ok(Some(_)) = d.next_message() {}
        }
    }
}
