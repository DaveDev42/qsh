use super::*;

// ---- parse_greeting -----------------------------------------------

#[test]
fn greeting_rejects_http_tls_and_socks4_first_bytes() {
    // HTTP verbs, a TLS ClientHello's content-type byte, SOCKS4's
    // version byte, and the two all-bits boundary values — none of
    // them is `0x05`, so all are `Invalid` off a single byte, never
    // `Incomplete`.
    for &first in &[b'G', b'P', b'H', b'C', b'O', 0x16u8, 0x04u8, 0x00u8, 0xFFu8] {
        let err = parse_greeting(&[first]).unwrap_err();
        assert_eq!(err, GreetingError::Invalid, "first byte {first:#04x}");
    }
}

#[test]
fn greeting_incomplete_before_first_byte() {
    assert_eq!(parse_greeting(&[]).unwrap_err(), GreetingError::Incomplete);
}

#[test]
fn greeting_without_no_auth_selects_ff() {
    // Offers only GSSAPI (0x01) and username/password (0x02) — no
    // no-auth, so the reply is `05 FF`.
    let input = [0x05, 0x02, 0x01, 0x02];
    let parsed = parse_greeting(&input).unwrap();
    assert_eq!(parsed.consumed, 4);
    assert_eq!(parsed.value.methods, vec![0x01, 0x02]);
    assert_eq!(encode_method_select(&parsed.value), [0x05, 0xFF]);
}

#[test]
fn greeting_with_no_auth_selects_it() {
    let input = [0x05, 0x02, 0x01, 0x00];
    let parsed = parse_greeting(&input).unwrap();
    assert_eq!(encode_method_select(&parsed.value), [0x05, 0x00]);
}

#[test]
fn greeting_with_zero_methods_selects_ff() {
    // `NMETHODS = 0` is a structurally valid greeting (parses `Ok`,
    // never `GreetingError::Invalid` — that variant is reserved for a
    // bad first byte), but offers nothing — same `05 FF` outcome as
    // no-auth being absent from a nonempty list (ADR-0019 decision 7).
    let input = [0x05, 0x00];
    let parsed = parse_greeting(&input).unwrap();
    assert_eq!(parsed.consumed, 2);
    assert!(parsed.value.methods.is_empty());
    assert_eq!(encode_method_select(&parsed.value), [0x05, 0xFF]);
}

#[test]
fn greeting_at_max_len_still_parses() {
    let mut input = vec![0x05, 0xFF];
    input.extend(std::iter::repeat_n(0x00, 255));
    assert_eq!(input.len(), GREETING_MAX_LEN);
    let parsed = parse_greeting(&input).unwrap();
    assert_eq!(parsed.consumed, GREETING_MAX_LEN);
    assert_eq!(parsed.value.methods.len(), 255);
}

// ---- parse_request: CMD/ATYP tables --------------------------------

fn ipv4_request(cmd: u8, atyp: u8) -> Vec<u8> {
    vec![0x05, cmd, 0x00, atyp, 127, 0, 0, 1, 0x1F, 0x90]
}

#[test]
fn request_command_table() {
    // CMD 1 (CONNECT) passes; every other value is `CommandNotSupported`,
    // checked before ATYP is even looked at.
    let parsed = parse_request(&ipv4_request(0x01, ATYP_IPV4)).unwrap();
    assert_eq!(parsed.value.port, 8080);

    for cmd in [0x02u8, 0x03, 0x00, 0xFF] {
        let err = parse_request(&ipv4_request(cmd, ATYP_IPV4)).unwrap_err();
        assert_eq!(
            err,
            RequestError::Rejected(Rep::CommandNotSupported),
            "cmd {cmd:#04x}"
        );
    }
}

#[test]
fn request_atyp_table() {
    for atyp in [ATYP_IPV4, ATYP_IPV6] {
        let bytes = match atyp {
            ATYP_IPV4 => ipv4_request(CMD_CONNECT, atyp),
            _ => {
                let mut v = vec![0x05, CMD_CONNECT, 0x00, atyp];
                v.extend_from_slice(&[0u8; 15]);
                v.push(1);
                v.extend_from_slice(&[0x1F, 0x90]);
                v
            }
        };
        assert!(parse_request(&bytes).is_ok(), "atyp {atyp:#04x}");
    }
    // Domain (0x03) with a trivially valid one-byte hostname "a".
    let domain = [0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, 1, b'a', 0x1F, 0x90];
    assert!(parse_request(&domain).is_ok());

    for atyp in [0x00u8, 0x02, 0x05, 0x7F, 0xFF] {
        let err = parse_request(&ipv4_request(CMD_CONNECT, atyp)).unwrap_err();
        assert_eq!(
            err,
            RequestError::Rejected(Rep::AddressTypeNotSupported),
            "atyp {atyp:#04x}"
        );
    }
}

#[test]
fn request_rsv_nonzero_and_port_zero_are_general_failure() {
    let mut rsv_bad = ipv4_request(CMD_CONNECT, ATYP_IPV4);
    rsv_bad[2] = 0x01;
    assert_eq!(
        parse_request(&rsv_bad).unwrap_err(),
        RequestError::Rejected(Rep::GeneralFailure)
    );

    let mut port_zero = ipv4_request(CMD_CONNECT, ATYP_IPV4);
    let len = port_zero.len();
    port_zero[len - 2] = 0;
    port_zero[len - 1] = 0;
    assert_eq!(
        parse_request(&port_zero).unwrap_err(),
        RequestError::Rejected(Rep::GeneralFailure)
    );
}

#[test]
fn request_ver_mismatch_is_general_failure_not_silent_close() {
    // Unlike `parse_greeting`'s first byte, a bad VER on the request
    // line still owes the client a reply (SOCKS5 is already
    // negotiated) — never a bare `Invalid`.
    let mut bad_ver = ipv4_request(CMD_CONNECT, ATYP_IPV4);
    bad_ver[0] = 0x04;
    assert_eq!(
        parse_request(&bad_ver).unwrap_err(),
        RequestError::Rejected(Rep::GeneralFailure)
    );
}

// ---- parse_request: IPv4/IPv6 host rendering -----------------------

#[test]
fn ipv4_request_renders_dotted_quad() {
    let parsed = parse_request(&ipv4_request(CMD_CONNECT, ATYP_IPV4)).unwrap();
    assert_eq!(parsed.value.host, "127.0.0.1");
    assert_eq!(parsed.value.port, 8080);
}

#[test]
fn ipv6_request_renders_unbracketed() {
    let mut bytes = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV6];
    bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    bytes.extend_from_slice(&[0x00, 0x50]);
    let parsed = parse_request(&bytes).unwrap();
    assert_eq!(parsed.value.host, "::1");
    assert_eq!(parsed.value.port, 80);
}

// ---- domain shape table --------------------------------------------

fn domain_request(name: &[u8]) -> Vec<u8> {
    let mut v = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, name.len() as u8];
    v.extend_from_slice(name);
    v.extend_from_slice(&[0x1F, 0x90]);
    v
}

#[test]
fn socks5_domain_shape_table() {
    // Length boundaries: 0 invalid (REP pinned, not just `is_err`), 253
    // valid, 254 invalid.
    assert_eq!(
        parse_request(&domain_request(b"")).unwrap_err(),
        RequestError::Rejected(Rep::AddressTypeNotSupported)
    );
    let at_253 = vec![b'a'; 253];
    assert_eq!(
        parse_request(&domain_request(&at_253)).unwrap().value.host,
        String::from_utf8(at_253).unwrap()
    );
    let at_254 = vec![b'a'; 254];
    assert_eq!(
        parse_request(&domain_request(&at_254)).unwrap_err(),
        RequestError::Rejected(Rep::AddressTypeNotSupported)
    );

    // Disallowed characters.
    for bad in [
        &b"exa:mple"[..],
        b"[example]",
        b"exa%mple",
        b"exa mple",
        b"exa\x01mple",
        b"exa\rmple",
    ] {
        assert_eq!(
            parse_request(&domain_request(bad)).unwrap_err(),
            RequestError::Rejected(Rep::AddressTypeNotSupported),
            "{bad:?}"
        );
    }

    // Non-UTF-8 bytes.
    assert_eq!(
        parse_request(&domain_request(&[0xFF, 0xFE])).unwrap_err(),
        RequestError::Rejected(Rep::AddressTypeNotSupported)
    );

    // Uppercase and one trailing dot normalize away.
    assert_eq!(
        parse_request(&domain_request(b"Example.COM."))
            .unwrap()
            .value
            .host,
        "example.com"
    );

    // A strict dotted-quad normalizes to the literal.
    assert_eq!(
        parse_request(&domain_request(b"127.0.0.1"))
            .unwrap()
            .value
            .host,
        "127.0.0.1"
    );

    // A strict IPv6 literal normalizes to unbracketed canonical text.
    assert_eq!(
        parse_request(&domain_request(b"::1")).unwrap().value.host,
        "::1"
    );

    // inet_aton-style numeric forms are rejected, not silently
    // accepted as an odd-looking hostname. The `0x` rule is checked
    // against the *last* label specifically — `127.0x1`, `127.0.0.0x1`
    // and `a.0x7f` are only caught if the check looks past the first
    // label.
    for numeric in [
        &b"127.1"[..],
        b"0x7f.1",
        b"2130706433",
        b"127.0x1",
        b"127.0.0.0x1",
        b"a.0x7f",
    ] {
        assert_eq!(
            parse_request(&domain_request(numeric)).unwrap_err(),
            RequestError::Rejected(Rep::AddressTypeNotSupported),
            "{numeric:?}"
        );
    }

    // An ordinary hostname is unaffected by the numeric-label rule.
    assert_eq!(
        parse_request(&domain_request(b"host1.example"))
            .unwrap()
            .value
            .host,
        "host1.example"
    );

    // The `0x` rule looks only at the last label, so a hostname whose
    // *first* label starts with `0x`, or whose last label merely
    // contains `0x` without starting with it, is an ordinary hostname,
    // not an inet_aton form.
    assert_eq!(
        parse_request(&domain_request(b"0xproject.com"))
            .unwrap()
            .value
            .host,
        "0xproject.com"
    );
    assert_eq!(
        parse_request(&domain_request(b"a.b0x1"))
            .unwrap()
            .value
            .host,
        "a.b0x1"
    );

    // One trailing dot is stripped *before* the literal parse, so a
    // dotted-quad written with a trailing dot still normalizes; a
    // second trailing dot (or a bare `..`) leaves an empty label and
    // is rejected rather than accepted as a strange hostname.
    assert_eq!(
        parse_request(&domain_request(b"127.0.0.1."))
            .unwrap()
            .value
            .host,
        "127.0.0.1"
    );
    for empty_label in [&b"127.0.0.1.."[..], b".."] {
        assert_eq!(
            parse_request(&domain_request(empty_label)).unwrap_err(),
            RequestError::Rejected(Rep::AddressTypeNotSupported),
            "{empty_label:?}"
        );
    }
}

// ---- Incomplete vs. Rejected invariant -----------------------------

#[test]
fn strict_prefix_of_valid_message_is_incomplete_never_invalid() {
    let greeting_full = {
        let mut v = vec![0x05, 0x02];
        v.extend_from_slice(&[0x00, 0x01]);
        v
    };
    for len in 0..greeting_full.len() {
        assert_eq!(
            parse_greeting(&greeting_full[..len]).unwrap_err(),
            GreetingError::Incomplete,
            "greeting prefix len {len}"
        );
    }

    let requests = [
        ipv4_request(CMD_CONNECT, ATYP_IPV4),
        domain_request(b"example.com"),
        {
            let mut v = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV6];
            v.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            v.extend_from_slice(&[0x00, 0x50]);
            v
        },
    ];
    for full in requests {
        for len in 0..full.len() {
            assert_eq!(
                parse_request(&full[..len]),
                Err(RequestError::Incomplete),
                "request prefix len {len} of {full:?}"
            );
        }
    }
}

#[test]
fn consumed_count_stops_at_request_end() {
    let mut bytes = ipv4_request(CMD_CONNECT, ATYP_IPV4);
    let request_len = bytes.len();
    bytes.extend_from_slice(b"GET / HTTP/1.1\r\n");
    let parsed = parse_request(&bytes).unwrap();
    assert_eq!(parsed.consumed, request_len);
    assert_eq!(&bytes[parsed.consumed..], b"GET / HTTP/1.1\r\n");
}

// ---- encode_reply / Rep::from_error_code ---------------------------

#[test]
fn reply_bytes_are_pinned_verbatim() {
    assert_eq!(
        encode_reply(Rep::Succeeded),
        [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        encode_reply(Rep::GeneralFailure),
        [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        encode_reply(Rep::NotAllowedByRuleset),
        [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        encode_reply(Rep::HostUnreachable),
        [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        encode_reply(Rep::ConnectionRefused),
        [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        encode_reply(Rep::CommandNotSupported),
        [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        encode_reply(Rep::AddressTypeNotSupported),
        [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn rep_mapping_table_is_pinned_verbatim() {
    // Exhaustive over every *known* code (`ErrorCode::KNOWN`) plus
    // `Unknown`, matching ADR-0019 decision 8's table.
    for code in ErrorCode::KNOWN {
        let expected = match code {
            ErrorCode::PermissionDenied => Rep::NotAllowedByRuleset,
            ErrorCode::HostNotFound => Rep::HostUnreachable,
            ErrorCode::ConnectionFailed => Rep::ConnectionRefused,
            _ => Rep::GeneralFailure,
        };
        assert_eq!(Rep::from_error_code(code), expected, "code {code:?}");
    }
    assert_eq!(
        Rep::from_error_code(&ErrorCode::Unknown("SOME_FUTURE_CODE".to_string())),
        Rep::GeneralFailure
    );
}

// ---- proptest round trip --------------------------------------------

proptest::proptest! {
    #[test]
    fn encode_then_parse_round_trips(
        methods in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=255),
        host_octets in proptest::prelude::any::<[u8; 4]>(),
        port in 1u16..=u16::MAX,
    ) {
        // Greeting round trip.
        let mut greeting_bytes = vec![0x05, methods.len() as u8];
        greeting_bytes.extend_from_slice(&methods);
        let parsed = parse_greeting(&greeting_bytes).unwrap();
        proptest::prop_assert_eq!(parsed.consumed, greeting_bytes.len());
        proptest::prop_assert_eq!(&parsed.value.methods, &methods);

        // IPv4 CONNECT request round trip (a fixed, always-in-range
        // ATYP so this proptest exercises the address/port encoding,
        // not the ATYP/CMD tables the table tests above already pin).
        let mut req = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV4];
        req.extend_from_slice(&host_octets);
        req.extend_from_slice(&port.to_be_bytes());
        let parsed = parse_request(&req).unwrap();
        proptest::prop_assert_eq!(parsed.consumed, req.len());
        proptest::prop_assert_eq!(parsed.value.port, port);
        proptest::prop_assert_eq!(
            parsed.value.host,
            Ipv4Addr::from(host_octets).to_string()
        );
    }
}
