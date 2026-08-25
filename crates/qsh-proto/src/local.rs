//! Prost-generated `qsh.local.v1` messages (localctl — the IPC a CLI
//! process speaks to this machine's resident `qsh listen` daemon over a
//! Unix domain socket), plus the small amount of glue that binds them to
//! the frame layer ([`crate::frame`]) and the shared error vocabulary
//! ([`crate::ErrorCode`]).
//!
//! The grammar lives in `proto/qsh/local/v1.proto` (compiled by `build.rs`
//! alongside `qsh.wire.v1`; see that file's header for why the two are
//! separate packages). See `docs/design/protocol.md` §11-3,
//! `docs/design/architecture.md` §3.
//!
//! Like [`crate::wire`], everything here is sans-IO: `&[u8] → Result<Message>`
//! and back. The `tokio::net::UnixStream` plumbing that actually runs a
//! localctl connection is a later milestone step's concern, not this
//! crate's.

use std::time::Duration;

use crate::ErrorCode;
use crate::frame::CONTROL_FRAME_MAX;
use crate::wire::{WireEncodeError, decode_msg, encode_framed};

#[allow(
    missing_docs,
    clippy::doc_markdown,
    clippy::derive_partial_eq_without_eq,
    clippy::large_enum_variant
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/qsh.local.v1.rs"));
}

pub use generated::*;

/// Upper bound `LocalHello.wait_ms` is clamped to: 60 s. Same clamp
/// discipline as the wire control message `SessionRead.wait_ms` /
/// `SESSION_READ_MAX_WAIT` (`crates/qsh-core/src/server/mod.rs`) — a
/// *ceiling*, not a rejection, so a caller cannot pin a daemon slot open
/// indefinitely by asking for an unbounded wait. The whole-command
/// `--timeout` (`docs/CLI.md` §9) is enforced separately by the CLI on top
/// of this.
pub const LOCAL_WAIT_MAX: Duration = Duration::from_secs(60);

/// The only `LocalHello.version` this build speaks, on both ends of a
/// localctl conduit. Centralized here (rather than duplicated as a
/// private constant in the CLI-process client and re-derived by the daemon)
/// so the two ends cannot silently drift, and so the daemon has a single
/// canonical value to check `LocalHello.version` against: `qsh listen` is a
/// resident daemon that can genuinely outlive a CLI upgrade, so a future
/// version bump on one end while the other is still running is the normal
/// case this field exists to fail closed on, not an edge case.
///
/// **2 (M4 Step 5 PR 5b, bumped from 1).** `LOCAL_ADMIN`'s second frame
/// changed shape — a bare, fieldless `LocalHostList{}` (which encodes to
/// zero bytes, `tests::local_host_list_and_tunnel_list_are_wire_identical_which_is_exactly_why_local_admin_request_exists`'s
/// own proof) became a `LocalAdminRequest{oneof body}` envelope so the
/// same conduit kind could also carry `TunnelList`/`TunnelClose`. Zero
/// bytes is not a valid `LocalAdminRequest` (`body: None`), so an old CLI
/// talking to a new resident daemon would otherwise get a confusing
/// `INVALID_ARGUMENT` ("LocalAdminRequest has no body set") instead of
/// the clean, actionable version-mismatch `UNSUPPORTED` this field exists
/// to produce (adversarial-review finding — a wire-shape change on a
/// conduit kind with no other version signal must bump this).
pub const LOCAL_HELLO_VERSION: u32 = 2;

/// Encode a `qsh.local.v1` message as one length-prefixed frame, under the
/// same [`CONTROL_FRAME_MAX`] cap the wire control stream uses — "§5와
/// 동일한 frame layer" (`docs/design/protocol.md` §11-3): the *parser* is
/// shared with the wire control stream, not merely similar to it.
pub fn encode_local<M: prost::Message>(msg: &M) -> Result<Vec<u8>, WireEncodeError> {
    encode_framed(msg, CONTROL_FRAME_MAX)
}

/// Decode one already-de-framed `qsh.local.v1` message
/// (post-[`crate::frame::FrameDecoder`]). Never panics on malformed input.
pub fn decode_local<M: prost::Message + Default>(payload: &[u8]) -> Result<M, prost::DecodeError> {
    decode_msg(payload)
}

/// Classify a raw `LocalHello.kind` value.
///
/// The unset/default value (`LOCAL_UNSPECIFIED`, proto3 field default) and
/// any value this build does not recognize are both refused as
/// [`ErrorCode::InvalidArgument`] — a conduit's identity must be an
/// explicit, known kind before the daemon does anything with the
/// connection (exactly the discipline `wire::SessionAttach::attach_mode`
/// applies to `AttachMode`: unset/unknown never default to a meaningful
/// variant). This function only classifies; turning the error into an
/// actual `LocalError` envelope on a live socket is the daemon's job
/// (PLAN M3 Step 5), not this sans-IO crate's.
pub fn classify_stream_kind(kind: i32) -> Result<LocalStreamKind, ErrorCode> {
    match LocalStreamKind::try_from(kind) {
        Ok(LocalStreamKind::LocalUnspecified) => Err(ErrorCode::InvalidArgument),
        Ok(known) => Ok(known),
        Err(_) => Err(ErrorCode::InvalidArgument),
    }
}

impl LocalError {
    /// Build a local IPC error from the shared vocabulary — the same
    /// pattern as [`crate::wire::Error::from_code`], so `qsh.local.v1` and
    /// `qsh.wire.v1` errors are always constructed the same way.
    pub fn from_code(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.as_str().to_string(),
            message: message.into(),
        }
    }

    /// The error code, parsed through the shared vocabulary. Unknown
    /// strings pass through as [`ErrorCode::Unknown`] (never fails).
    pub fn error_code(&self) -> ErrorCode {
        match self.code.parse::<ErrorCode>() {
            Ok(code) => code,
            Err(never) => match never {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameDecoder;
    use proptest::prelude::*;

    // ---- strategies -------------------------------------------------

    fn arb_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..=max)
    }

    fn arb_rfc3339() -> impl Strategy<Value = String> {
        "20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z"
    }

    fn arb_fingerprint() -> impl Strategy<Value = String> {
        "sha256:[A-Za-z0-9+/]{1,44}"
    }

    fn arb_local_hello() -> impl Strategy<Value = LocalHello> {
        (
            any::<u32>(),
            // Deliberately any i32, not just the four known values: prost
            // keeps unknown enum values in the raw field, and an
            // out-of-range `kind` must round-trip on the wire even though
            // `classify_stream_kind` rejects it.
            any::<i32>(),
            "[a-zA-Z0-9._-]{0,64}",
            any::<u32>(),
            proptest::option::of(any::<u64>()),
        )
            .prop_map(
                |(version, kind, host, wait_ms, known_generation)| LocalHello {
                    version,
                    kind,
                    host,
                    wait_ms,
                    known_generation,
                },
            )
    }

    fn arb_local_hello_ack() -> impl Strategy<Value = LocalHelloAck> {
        (
            "[a-zA-Z0-9._-]{0,64}",
            arb_fingerprint(),
            any::<u64>(),
            proptest::collection::vec("[a-z.0-9]{1,16}", 0..4),
        )
            .prop_map(
                |(host, peer_fingerprint, generation, capabilities)| LocalHelloAck {
                    host,
                    peer_fingerprint,
                    generation,
                    capabilities,
                },
            )
    }

    fn arb_local_error() -> impl Strategy<Value = LocalError> {
        (
            proptest::sample::select(ErrorCode::KNOWN.to_vec()),
            ".{0,64}",
        )
            .prop_map(|(code, message)| LocalError::from_code(code, message))
    }

    fn arb_local_host() -> impl Strategy<Value = LocalHost> {
        (
            "[a-zA-Z0-9._-]{1,64}",
            ".{0,64}",
            "(reachable|stale|unknown)",
            arb_fingerprint(),
            proptest::collection::vec("[a-z.0-9]{1,16}", 0..4),
            any::<u64>(),
            arb_rfc3339(),
        )
            .prop_map(
                |(name, address, state, fingerprint, capabilities, generation, registered_at)| {
                    LocalHost {
                        name,
                        address,
                        state,
                        fingerprint,
                        capabilities,
                        generation,
                        registered_at,
                    }
                },
            )
    }

    fn arb_local_host_list_result() -> impl Strategy<Value = LocalHostListResult> {
        proptest::collection::vec(arb_local_host(), 0..4)
            .prop_map(|hosts| LocalHostListResult { hosts })
    }

    fn arb_local_tunnel() -> impl Strategy<Value = LocalTunnel> {
        (
            "[a-zA-Z0-9_-]{1,64}",
            "(local|remote)",
            ".{0,64}",
            ".{0,64}",
            any::<u32>(),
            "[a-zA-Z0-9._-]{0,64}",
        )
            .prop_map(|(tunnel_id, mode, bind, forward_to, actual_port, host)| {
                LocalTunnel {
                    tunnel_id,
                    mode,
                    bind,
                    forward_to,
                    actual_port,
                    host,
                }
            })
    }

    fn arb_local_tunnel_list_result() -> impl Strategy<Value = LocalTunnelListResult> {
        proptest::collection::vec(arb_local_tunnel(), 0..4)
            .prop_map(|tunnels| LocalTunnelListResult { tunnels })
    }

    fn arb_local_tunnel_close() -> impl Strategy<Value = LocalTunnelClose> {
        "[a-zA-Z0-9_-]{1,64}".prop_map(|tunnel_id| LocalTunnelClose { tunnel_id })
    }

    fn arb_local_tunnel_close_result() -> impl Strategy<Value = LocalTunnelCloseResult> {
        any::<bool>().prop_map(|closed| LocalTunnelCloseResult { closed })
    }

    fn arb_local_admin_request() -> impl Strategy<Value = LocalAdminRequest> {
        prop_oneof![
            Just(LocalAdminRequest {
                body: Some(local_admin_request::Body::HostList(LocalHostList {})),
            }),
            Just(LocalAdminRequest {
                body: Some(local_admin_request::Body::TunnelList(LocalTunnelList {})),
            }),
            arb_local_tunnel_close().prop_map(|m| LocalAdminRequest {
                body: Some(local_admin_request::Body::TunnelClose(m)),
            }),
        ]
    }

    fn arb_local_response() -> impl Strategy<Value = LocalResponse> {
        prop_oneof![
            arb_local_hello_ack().prop_map(|m| LocalResponse {
                body: Some(local_response::Body::HelloAck(m)),
            }),
            arb_local_host_list_result().prop_map(|m| LocalResponse {
                body: Some(local_response::Body::HostListResult(m)),
            }),
            arb_local_tunnel_list_result().prop_map(|m| LocalResponse {
                body: Some(local_response::Body::TunnelListResult(m)),
            }),
            // Empty message, but the *envelope* around it still has to
            // round-trip byte-canonically — `LocalClaimGranted` carries its
            // whole meaning in which oneof arm is set
            // (`qsh/local/v1.proto`'s own doc).
            Just(LocalResponse {
                body: Some(local_response::Body::ClaimGranted(LocalClaimGranted {})),
            }),
            arb_local_tunnel_close_result().prop_map(|m| LocalResponse {
                body: Some(local_response::Body::TunnelCloseResult(m)),
            }),
            arb_local_error().prop_map(|m| LocalResponse {
                body: Some(local_response::Body::Error(m)),
            }),
        ]
    }

    // ---- roundtrip / canonical encoding ------------------------------

    /// `decode(encode(m)) == m` (roundtrip) and, on the resulting bytes,
    /// `encode(decode(b)) == b` (canonical encoding) — re-encoding what we
    /// just decoded reproduces the exact bytes, not merely an equivalent
    /// message.
    fn roundtrip_and_canonical<M>(m: &M)
    where
        M: prost::Message + Default + PartialEq + std::fmt::Debug,
    {
        let wire = encode_local(m).unwrap();
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let payload = dec.next_frame().unwrap().expect("one complete frame");
        assert_eq!(dec.next_frame().unwrap(), None, "no trailing bytes");

        let back: M = decode_local(&payload).unwrap();
        assert_eq!(&back, m, "roundtrip: decode(encode(m)) == m");

        let re_wire = encode_local(&back).unwrap();
        assert_eq!(re_wire, wire, "canonical: encode(decode(b)) == b");
    }

    /// Every strict prefix of a framed encoding is "incomplete" at the
    /// frame layer: never a frame, never a panic.
    fn prefixes_are_incomplete<M: prost::Message>(m: &M) {
        let wire = encode_local(m).unwrap();
        for cut in 0..wire.len() {
            let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
            dec.push(&wire[..cut]);
            assert_eq!(dec.next_frame().unwrap(), None, "prefix len {cut}");
        }
    }

    proptest! {
        #[test]
        fn local_hello_roundtrips(m in arb_local_hello()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_hello_ack_roundtrips(m in arb_local_hello_ack()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_error_roundtrips(m in arb_local_error()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_host_list_result_roundtrips(m in arb_local_host_list_result()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_tunnel_list_result_roundtrips(m in arb_local_tunnel_list_result()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_tunnel_close_roundtrips(m in arb_local_tunnel_close()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_tunnel_close_result_roundtrips(m in arb_local_tunnel_close_result()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_admin_request_roundtrips(m in arb_local_admin_request()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_response_roundtrips(m in arb_local_response()) {
            roundtrip_and_canonical(&m);
        }

        #[test]
        fn local_hello_prefixes_are_incomplete(m in arb_local_hello()) {
            prefixes_are_incomplete(&m);
        }

        #[test]
        fn local_host_list_result_prefixes_are_incomplete(m in arb_local_host_list_result()) {
            prefixes_are_incomplete(&m);
        }

        #[test]
        fn local_tunnel_list_result_prefixes_are_incomplete(m in arb_local_tunnel_list_result()) {
            prefixes_are_incomplete(&m);
        }

        #[test]
        fn local_admin_request_prefixes_are_incomplete(m in arb_local_admin_request()) {
            prefixes_are_incomplete(&m);
        }

        #[test]
        fn local_response_prefixes_are_incomplete(m in arb_local_response()) {
            prefixes_are_incomplete(&m);
        }

        /// Arbitrary bytes never panic the decoder for any local message
        /// type.
        #[test]
        fn garbage_never_panics(bytes in arb_bytes(256)) {
            let _ = decode_local::<LocalHello>(&bytes);
            let _ = decode_local::<LocalHelloAck>(&bytes);
            let _ = decode_local::<LocalError>(&bytes);
            let _ = decode_local::<LocalHostList>(&bytes);
            let _ = decode_local::<LocalHostListResult>(&bytes);
            let _ = decode_local::<LocalTunnelList>(&bytes);
            let _ = decode_local::<LocalTunnelListResult>(&bytes);
            let _ = decode_local::<LocalTunnelClose>(&bytes);
            let _ = decode_local::<LocalTunnelCloseResult>(&bytes);
            let _ = decode_local::<LocalAdminRequest>(&bytes);
            let _ = decode_local::<LocalResponse>(&bytes);
        }

        /// Bit-flipped valid encodings never panic and, when they still
        /// decode, re-encode without panicking.
        #[test]
        fn bit_flips_never_panic(
            m in arb_local_hello_ack(),
            idx in any::<prop::sample::Index>(),
            bit in 0u8..8,
        ) {
            use prost::Message;
            let mut body = m.encode_to_vec();
            if body.is_empty() { return Ok(()); }
            let i = idx.index(body.len());
            body[i] ^= 1 << bit;
            if let Ok(decoded) = decode_local::<LocalHelloAck>(&body) {
                let _ = decoded.encode_to_vec();
            }
        }
    }

    // ---- allocation bound --------------------------------------------

    #[test]
    fn oversize_local_frame_rejected_before_allocation() {
        // A peer (or a confused local caller) claiming a 4 GiB `LocalHello`
        // frame is rejected from the 4-byte header alone, on the exact same
        // decoder cap the wire control stream uses — no message-sized
        // buffer is ever allocated.
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&u32::MAX.to_be_bytes());
        assert_eq!(
            dec.next_frame().unwrap_err(),
            crate::frame::FrameError::Oversize {
                len: u32::MAX,
                max: CONTROL_FRAME_MAX,
            }
        );
    }

    #[test]
    fn encode_local_refuses_messages_over_frame_cap() {
        // Local IPC messages share the wire control stream's
        // CONTROL_FRAME_MAX cap (256 KiB), not the smaller DATA_FRAME_MAX —
        // this exercises the actual cap `encode_local` enforces.
        let big = LocalHost {
            name: "x".repeat(CONTROL_FRAME_MAX),
            ..Default::default()
        };
        assert!(matches!(
            encode_local(&big),
            Err(WireEncodeError::TooLarge { .. })
        ));
    }

    // ---- LocalStreamKind classification -------------------------------

    #[test]
    fn classify_stream_kind_rejects_unspecified_and_unknown() {
        assert_eq!(
            classify_stream_kind(LocalStreamKind::LocalUnspecified as i32),
            Err(ErrorCode::InvalidArgument)
        );
        // Never-defined values.
        for unknown in [4, 5, -1, i32::MAX, i32::MIN] {
            assert_eq!(
                classify_stream_kind(unknown),
                Err(ErrorCode::InvalidArgument),
                "kind {unknown}"
            );
        }
    }

    #[test]
    fn classify_stream_kind_accepts_known_kinds() {
        for kind in [
            LocalStreamKind::LocalControl,
            LocalStreamKind::LocalStream,
            LocalStreamKind::LocalAdmin,
        ] {
            assert_eq!(classify_stream_kind(kind as i32), Ok(kind));
        }
    }

    // ---- error vocabulary ----------------------------------------------

    #[test]
    fn local_error_code_uses_error_code_vocabulary_verbatim() {
        for code in ErrorCode::KNOWN {
            let err = LocalError::from_code(code.clone(), "x");
            assert_eq!(err.code, code.as_str());
            assert_eq!(&err.error_code(), code);
        }
        let unknown = LocalError {
            code: "SOME_FUTURE_CODE".into(),
            message: String::new(),
        };
        assert_eq!(
            unknown.error_code(),
            ErrorCode::Unknown("SOME_FUTURE_CODE".into())
        );
    }

    // ---- misc -----------------------------------------------------------

    #[test]
    fn local_wait_max_is_sixty_seconds() {
        // Same numeric ceiling as `SESSION_READ_MAX_WAIT`
        // (crates/qsh-core/src/server/mod.rs) — pinned here so a future
        // edit to one does not silently drift from the other's documented
        // rationale.
        assert_eq!(LOCAL_WAIT_MAX, Duration::from_secs(60));
    }

    #[test]
    fn local_hello_version_is_two() {
        // Bumped from 1 in M4 Step 5 PR 5b (adversarial-review finding):
        // `LOCAL_ADMIN`'s second frame changed shape (bare `LocalHostList{}`
        // -> `LocalAdminRequest{oneof body}`), and this field exists
        // precisely so that a version skew across a resident daemon and a
        // just-upgraded (or just-downgraded) CLI fails closed with a clear
        // `UNSUPPORTED` instead of a confusing `INVALID_ARGUMENT` decoded
        // from the old, now-incompatible empty-frame shape.
        assert_eq!(LOCAL_HELLO_VERSION, 2);
    }

    #[test]
    fn local_host_list_request_has_no_fields() {
        // LocalHostList{} carries no data; round-trip through the frame
        // layer still holds for the empty message.
        roundtrip_and_canonical(&LocalHostList {});
    }

    #[test]
    fn local_tunnel_list_request_has_no_fields() {
        // LocalTunnelList{} (M4, `qsh tunnels`) carries no data, same as
        // LocalHostList{} above.
        roundtrip_and_canonical(&LocalTunnelList {});
    }

    #[test]
    fn local_host_list_and_tunnel_list_are_wire_identical_which_is_exactly_why_local_admin_request_exists()
     {
        // The discriminator problem `LocalAdminRequest`'s own doc states:
        // two different fieldless message *types* encode to the exact
        // same (empty) bytes, so a bare top-level request would be
        // ambiguous the instant a `LOCAL_ADMIN` conduit could be asked
        // more than one kind of question.
        use prost::Message;
        assert_eq!(LocalHostList {}.encode_to_vec(), Vec::<u8>::new());
        assert_eq!(LocalTunnelList {}.encode_to_vec(), Vec::<u8>::new());
        assert_eq!(
            LocalHostList {}.encode_to_vec(),
            LocalTunnelList {}.encode_to_vec()
        );
    }
}
