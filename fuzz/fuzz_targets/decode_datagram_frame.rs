//! Fuzzes `qsh_proto::datagram::DatagramFrame::decode` — the header of a
//! QUIC DATAGRAM (ADR-0052 decision 7): 16-byte channel id, one kind byte,
//! then the payload. Datagrams are unauthenticated at this layer until the
//! channel id is looked up, so this is the first thing a peer's (or an
//! on-path replayer's) datagram touches.
//!
//! Invariants: no panic; an accepted datagram re-encodes to the same
//! bytes; the kind is one of the four known bodies; the payload is
//! exactly the input minus the 17-byte header. When the payload is a
//! `ScreenUpdate`, decoding it is also total (it is what the receiver does
//! next, once the channel is known).

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::datagram::{DatagramFrame, DatagramKind};
use qsh_proto::screen::ScreenUpdate;
use qsh_proto::wire::{ScreenEcho, decode_msg};

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = DatagramFrame::decode(data) {
        assert_eq!(frame.encode(), data);
        assert_eq!(frame.payload.len(), data.len() - DatagramFrame::HEADER_LEN);
        assert!(matches!(
            frame.kind,
            DatagramKind::ScreenUpdate
                | DatagramKind::ScreenAck
                | DatagramKind::Input
                | DatagramKind::ScreenEcho
        ));
        if frame.kind == DatagramKind::ScreenUpdate {
            let _ = ScreenUpdate::decode(&frame.payload);
        }
        // Kind 13 (ADR-0053): decoding is total, and the tty value never
        // fails a decode.
        if frame.kind == DatagramKind::ScreenEcho
            && let Ok(echo) = decode_msg::<ScreenEcho>(&frame.payload)
        {
            let _ = echo.tty_echo();
            let _ = echo.validate_against_sent(0);
        }
    }
});
