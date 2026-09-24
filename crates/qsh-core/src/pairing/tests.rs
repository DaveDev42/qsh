use super::*;

/// **Report F-1 regression.** Zero test in this crate directly pinned
/// down channel binding at the exact layer that provides it: this
/// module's own [`export_keying_material`] wrapper. Before this test,
/// replacing its body with `Ok([0u8; EKM_LEN])` (i.e. deriving both
/// proofs from a constant instead of the TLS session) left every
/// existing test green — the wire-level DoD-quadrant tests in
/// `qsh-testkit/tests/pairing_loopback.rs` only ever exercise a single
/// live connection at a time, so they cannot distinguish "bound to
/// this session's TLS key material" from "bound to nothing at all".
///
/// Two independent loopback connections must export different keying
/// material, and neither may be the degenerate all-zero value a
/// stubbed-out exporter would produce — the exact property
/// `docs/design/protocol.md` §15.3 claims defeats a MITM that
/// terminates two separate TLS sessions.
#[tokio::test(flavor = "multi_thread")]
async fn export_keying_material_differs_across_separate_connections() {
    let (client1, _server1) = crate::tunnel::testutil::loopback_pair().await;
    let (client2, _server2) = crate::tunnel::testutil::loopback_pair().await;

    let e1 = export_keying_material(&client1).expect("export 1");
    let e2 = export_keying_material(&client2).expect("export 2");

    assert_ne!(
        e1, e2,
        "two separate TLS sessions must export different keying material \
             (channel binding, protocol.md §15.3) — a MITM terminating two \
             legs would otherwise see the same value on both"
    );
    assert_ne!(
        e1, [0u8; EKM_LEN],
        "the exporter must not degenerate to an all-zero constant"
    );
    assert_ne!(
        e2, [0u8; EKM_LEN],
        "the exporter must not degenerate to an all-zero constant"
    );
}

/// Fix A2's ingest guard, at the pure-predicate level: an ordinary
/// device name (letters, digits, hyphens, spaces — the shapes every
/// existing pairing test in `qsh-testkit/tests/pairing_loopback.rs`
/// already uses, e.g. `"laptop"`) must pass, so the guard is not
/// over-broad.
#[test]
fn reject_control_chars_allows_an_ordinary_device_name() {
    assert!(reject_control_chars("laptop", "PairingProof.device_name").is_ok());
    assert!(reject_control_chars("Dave's MacBook Pro", "PairingProof.device_name").is_ok());
}

/// The notice advertises its tail as a command to paste, and the name
/// in it is the peer's self-asserted `device_name`, so the principal
/// has to survive a shell as one word. An apostrophe is the case bare
/// single-quoting gets wrong — it closes the quote early — and
/// `reject_control_chars_allows_an_ordinary_device_name` above pins
/// `"Dave's MacBook Pro"` as a name a peer may legitimately assert.
#[test]
fn the_pin_notice_shell_quotes_a_device_name_containing_an_apostrophe() {
    let notice = pairing_pin_notice("Dave's MacBook Pro", false, false);
    assert!(
        notice.contains(r"--principal 'device:Dave'\''s MacBook Pro' --action session.open"),
        "an apostrophe must be POSIX-escaped, not left to close the quote: {notice}"
    );
}

/// The complement: a name with no apostrophe is wrapped and nothing
/// else, which is the form `failure_text_discipline.rs`'s three-part
/// table pins as T3's next-command slice. Escaping must not reach a
/// name that does not need it.
#[test]
fn the_pin_notice_wraps_an_apostrophe_free_name_without_escaping_it() {
    let notice = pairing_pin_notice("probe-device", false, false);
    assert!(
        notice.ends_with("qsh acl check --principal 'device:probe-device' --action session.open"),
        "{notice}"
    );
    assert!(!notice.contains(r"\'"), "no escape belongs here: {notice}");
}

/// The actual threat this guard closes (report background: `human.rs`'s
/// `print_trust_accept` prints `{name} ({fingerprint})` on one line —
/// an escape sequence or bare `\r` in `name` can overwrite or hide the
/// fingerprint printed right after it). Tab is control too (a device
/// name is a label, not formatted text), unlike `human::sanitize`'s own
/// tab exemption for free-form diagnostic text.
#[test]
fn reject_control_chars_rejects_escape_sequences_cr_and_tab() {
    for bad in ["evil\u{1b}[Kname", "evil\rname", "evil\tname", "evil\0name"] {
        let err = reject_control_chars(bad, "PairingProof.device_name")
            .expect_err(&format!("{bad:?} must be rejected"));
        assert!(
            matches!(
                err,
                PairingError::InvalidDeviceName {
                    field: "PairingProof.device_name",
                    reason: wire::DeviceNameError::Control,
                }
            ),
            "unexpected error for {bad:?}: {err:?}"
        );
        // The rejected value itself must never appear in the error's
        // own `Display` — only the field name (fail-closed logging
        // rule: `PairingError::InvalidDeviceName`'s own doc).
        assert!(
            !err.to_string().contains("evil"),
            "the rejected device name must not be echoed: {err}"
        );
    }
}

/// [`PairingError::InvalidDeviceName`] must map to `INVALID_ARGUMENT`
/// on the wire, not fall through the catch-all `_ => Internal` arm in
/// [`PairingError::as_wire_error`].
#[test]
fn invalid_device_name_maps_to_invalid_argument_on_the_wire() {
    let err = PairingError::InvalidDeviceName {
        field: "PairingProof.device_name",
        reason: wire::DeviceNameError::Control,
    };
    assert_eq!(err.as_wire_error().error_code(), ErrorCode::InvalidArgument);
}

/// [`PairingError::InvalidAssignedName`]'s own doc claims the initiator
/// cannot use the wire reply to distinguish it from an ordinary
/// [`PairingError::PinCollision`]. Pin that mechanically: not just the
/// `ErrorCode` (both `SESSION_CONFLICT`) but the `message` bytes too, so
/// the two variants' distinct `Display` text (used only for the
/// host-local `tracing::warn!` and audit category) never leaks onto the
/// wire.
#[test]
fn invalid_assigned_name_and_pin_collision_produce_the_same_wire_error() {
    let a = PairingError::InvalidAssignedName.as_wire_error();
    let b = PairingError::PinCollision.as_wire_error();
    assert_eq!(
        a, b,
        "the wire error must be byte-identical, not just same-coded"
    );
}

/// The boundary this guard now enforces (`docs/design/protocol.md`
/// §15.5's length row): exactly 64 bytes passes, 65 bytes fails —
/// checked once in ASCII (byte count == char count) and once in a
/// multi-byte script (Korean, 3 bytes/char) so the boundary is proven
/// on the UTF-8 *byte* length, not the char count.
#[test]
fn reject_control_chars_enforces_the_64_byte_boundary() {
    let ascii_64 = "a".repeat(64);
    let ascii_65 = "a".repeat(65);
    assert!(reject_control_chars(&ascii_64, "PairingProof.device_name").is_ok());
    assert!(matches!(
        reject_control_chars(&ascii_65, "PairingProof.device_name"),
        Err(PairingError::InvalidDeviceName {
            reason: wire::DeviceNameError::Length,
            ..
        })
    ));

    // "가" is 3 bytes in UTF-8: 21 chars = 63 bytes (fits), 22 chars =
    // 66 bytes (a multi-byte overshoot past 64, not just an off-by-one).
    let hangul_63_bytes = "가".repeat(21);
    let hangul_66_bytes = "가".repeat(22);
    assert_eq!(hangul_63_bytes.len(), 63);
    assert_eq!(hangul_66_bytes.len(), 66);
    assert!(reject_control_chars(&hangul_63_bytes, "PairingProof.device_name").is_ok());
    assert!(matches!(
        reject_control_chars(&hangul_66_bytes, "PairingProof.device_name"),
        Err(PairingError::InvalidDeviceName {
            reason: wire::DeviceNameError::Length,
            ..
        })
    ));
}

/// An empty name is rejected the same way an oversized one is (the
/// length row covers both ends of `1..=64`).
#[test]
fn reject_control_chars_rejects_an_empty_name() {
    assert!(matches!(
        reject_control_chars("", "PairingProof.device_name"),
        Err(PairingError::InvalidDeviceName {
            reason: wire::DeviceNameError::Length,
            ..
        })
    ));
}

/// Bidi-override and zero-width characters are neither of them
/// `char::is_control()` (the RLO trick this closes: a name that
/// visually rewrites its own or a neighboring fingerprint line without
/// tripping the older control-character guard — `docs/design/
/// protocol.md` §15.5).
#[test]
fn reject_control_chars_rejects_bidi_and_zero_width() {
    assert!(matches!(
        reject_control_chars("evil\u{202e}name", "PairingProof.device_name"),
        Err(PairingError::InvalidDeviceName {
            reason: wire::DeviceNameError::Bidi,
            ..
        })
    ));
    assert!(matches!(
        reject_control_chars("evil\u{200b}name", "PairingProof.device_name"),
        Err(PairingError::InvalidDeviceName {
            reason: wire::DeviceNameError::ZeroWidth,
            ..
        })
    ));
    assert!(matches!(
        reject_control_chars("evil\u{feff}name", "PairingProof.device_name"),
        Err(PairingError::InvalidDeviceName {
            reason: wire::DeviceNameError::ZeroWidth,
            ..
        })
    ));
}

/// A name built from ordinary multi-byte characters — Korean text, an
/// emoji — is not itself a rejection reason; only the specific
/// code-point classes in `wire::validate_device_name`'s table are.
#[test]
fn reject_control_chars_allows_hangul_and_emoji_names() {
    assert!(reject_control_chars("데이브의 맥북", "PairingProof.device_name").is_ok());
    assert!(reject_control_chars("laptop 💻", "PairingProof.device_name").is_ok());
}
