//! Size guards for the facade types.
//!
//! `SendStream`, `RecvStream` and `Connection` are held by value in `qsh-core`
//! types that sit in `Result::Err` positions and enum variants, where clippy's
//! `result_large_err` and `large_enum_variant` thresholds are only a few bytes
//! away. A second backend variant must not grow them: the iroh stream halves
//! are boxed so the enums keep the QUIC layout (the tag sits in a niche).

use crate::{Connection, RecvStream, SendStream};

#[test]
fn the_stream_facades_are_no_larger_than_the_quic_streams() {
    assert_eq!(
        std::mem::size_of::<SendStream>(),
        std::mem::size_of::<quinn::SendStream>()
    );
    assert_eq!(
        std::mem::size_of::<RecvStream>(),
        std::mem::size_of::<quinn::RecvStream>()
    );
}

/// The iroh variant of `Connection` is an `Arc` handle (iroh's own connection
/// is 80 bytes inline plus the endpoint handle), so it adds at most a tag.
/// This pins that it does not grow further.
#[test]
fn the_connection_facade_stays_within_its_size() {
    assert!(std::mem::size_of::<Connection>() <= 128);
}
