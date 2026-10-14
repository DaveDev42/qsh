use proptest::prelude::*;

use super::*;

fn hello() -> Hello {
    Hello {
        versions: vec![1],
        qsh_version: "0.5.0".to_string(),
        status: HelloStatus::Ready,
        fingerprint: Some("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
        serve_bind: Some("[::]:4433".to_string()),
        serve_listening: Some(false),
    }
}

fn commit() -> Commit {
    Commit {
        version: 1,
        fingerprint: "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
        name: "laptop".to_string(),
        role: "full".to_string(),
        address: None,
    }
}

fn result() -> BootstrapResult {
    BootstrapResult {
        status: ResultStatus::Pinned,
        name: "laptop".to_string(),
        role: Some("full".to_string()),
        created: true,
        code: None,
        message: None,
    }
}

fn every_message() -> Vec<BootstrapLine> {
    vec![
        BootstrapLine::Hello(hello()),
        BootstrapLine::Hello(Hello {
            versions: vec![1, 2, 7],
            qsh_version: "9.9.9".to_string(),
            status: HelloStatus::NotInitialized,
            fingerprint: None,
            serve_bind: None,
            serve_listening: None,
        }),
        BootstrapLine::Hello(Hello {
            serve_listening: None,
            ..hello()
        }),
        BootstrapLine::Commit(commit()),
        BootstrapLine::Commit(Commit {
            address: Some("laptop.example:4433".to_string()),
            ..commit()
        }),
        BootstrapLine::Result(result()),
        BootstrapLine::Result(BootstrapResult {
            status: ResultStatus::Exists,
            role: None,
            created: false,
            ..result()
        }),
        BootstrapLine::Result(BootstrapResult {
            status: ResultStatus::Conflict,
            role: None,
            created: false,
            code: Some(ErrorCode::SessionConflict),
            message: Some("name \"laptop\" is pinned with another fingerprint".to_string()),
            ..result()
        }),
        BootstrapLine::Result(BootstrapResult {
            status: ResultStatus::Error,
            role: None,
            created: false,
            code: Some(ErrorCode::Internal),
            message: Some("line one\nline two\r\n\u{2028}\u{0}".to_string()),
            ..result()
        }),
    ]
}

fn tagged(json: &str) -> Vec<u8> {
    format!("{BOOTSTRAP_LINE_PREFIX}{json}").into_bytes()
}

fn hello_line() -> String {
    BootstrapLine::Hello(hello()).encode_line().unwrap()
}

fn result_line() -> String {
    BootstrapLine::Result(result()).encode_line().unwrap()
}

#[test]
fn bootstrap_line_round_trips_every_message() {
    for msg in every_message() {
        let line = msg.encode_line().unwrap();
        assert!(line.starts_with(BOOTSTRAP_LINE_PREFIX));
        assert!(line.ends_with('\n'));
        assert_eq!(
            line.matches('\n').count(),
            1,
            "an encoded message is exactly one line: {line:?}"
        );
        assert!(!line.contains('\r'));
        let parsed = parse_ssh_bootstrap_line(line.trim_end_matches('\n').as_bytes()).unwrap();
        assert_eq!(parsed, msg);
        // A CRLF-translating remote still parses.
        let with_cr = format!("{}\r", line.trim_end_matches('\n'));
        assert_eq!(parse_ssh_bootstrap_line(with_cr.as_bytes()).unwrap(), msg);
    }
}

#[test]
fn bootstrap_line_rejects_lines_over_8_kib() {
    // Exactly at the cap parses; one byte over is refused whatever follows.
    let head = format!(
        r#"{BOOTSTRAP_LINE_PREFIX}{{"type":"commit","version":1,"fingerprint":"f","name":""#
    );
    let tail = r#"","role":"full"}"#;
    let pad = BOOTSTRAP_LINE_MAX - head.len() - tail.len();
    let at_cap = format!("{head}{}{tail}", "n".repeat(pad));
    assert_eq!(at_cap.len(), BOOTSTRAP_LINE_MAX);
    assert!(matches!(
        parse_ssh_bootstrap_line(at_cap.as_bytes()),
        Ok(BootstrapLine::Commit(_))
    ));

    let over = format!("{head}{}{tail}", "n".repeat(pad + 1));
    assert_eq!(
        parse_ssh_bootstrap_line(over.as_bytes()),
        Err(BootstrapLineError::LineTooLong)
    );
    // The size check runs before the prefix check, so garbage that long is
    // `LineTooLong`, not scanned.
    assert_eq!(
        parse_ssh_bootstrap_line(&vec![b'x'; BOOTSTRAP_LINE_MAX + 1]),
        Err(BootstrapLineError::LineTooLong)
    );

    // The encoder refuses to emit what a peer would refuse.
    let huge = BootstrapLine::Result(BootstrapResult {
        message: Some("m".repeat(BOOTSTRAP_LINE_MAX)),
        ..result()
    });
    assert_eq!(huge.encode_line(), Err(BootstrapLineError::LineTooLong));

    // A reader refuses an over-long line without buffering it all.
    let mut reader = BootstrapReader::new();
    let mut stream = hello_line().into_bytes();
    stream.extend_from_slice(&over.into_bytes());
    stream.push(b'\n');
    assert_eq!(reader.push(&stream), Err(BootstrapLineError::LineTooLong));
    let mut reader = BootstrapReader::new();
    let endless = vec![b'x'; BOOTSTRAP_LINE_MAX * 4];
    let mut tagged_endless = BOOTSTRAP_LINE_PREFIX.as_bytes().to_vec();
    tagged_endless.extend_from_slice(&endless);
    assert_eq!(
        reader.push(&tagged_endless),
        Err(BootstrapLineError::LineTooLong)
    );
    assert!(reader.line.capacity() <= BOOTSTRAP_LINE_MAX * 2 + 2);
}

#[test]
fn bootstrap_line_rejects_missing_prefix_and_malformed_json() {
    assert_eq!(
        parse_ssh_bootstrap_line(b""),
        Err(BootstrapLineError::MissingPrefix)
    );
    assert_eq!(
        parse_ssh_bootstrap_line(b"qsh-bootstrap{}"),
        Err(BootstrapLineError::MissingPrefix)
    );
    assert_eq!(
        parse_ssh_bootstrap_line(br#" qsh-bootstrap {"type":"hello"}"#),
        Err(BootstrapLineError::MissingPrefix)
    );
    for body in [
        "",
        "{",
        "[]",
        "null",
        r#"{"type":"nope"}"#,
        r#"{"versions":[1]}"#,
        // Required fields missing or mistyped.
        r#"{"type":"hello","versions":[1],"qsh_version":"x"}"#,
        r#"{"type":"hello","versions":"1","qsh_version":"x","status":"ready"}"#,
        r#"{"type":"hello","versions":[-1],"qsh_version":"x","status":"ready"}"#,
        r#"{"type":"commit","version":1,"fingerprint":"f","name":"n"}"#,
        r#"{"type":"result","status":"pinned","name":"n"}"#,
    ] {
        assert_eq!(
            parse_ssh_bootstrap_line(&tagged(body)),
            Err(BootstrapLineError::Malformed),
            "{body}"
        );
    }
    // Deeply nested JSON that fits the line cap is refused by the JSON
    // depth limit, without exhausting the stack.
    let nested = "[".repeat(BOOTSTRAP_LINE_MAX - BOOTSTRAP_LINE_PREFIX.len());
    assert_eq!(
        parse_ssh_bootstrap_line(&tagged(&nested)),
        Err(BootstrapLineError::Malformed)
    );
    let nested_value = format!(r#"{{"type":"hello","versions":{}"#, "[".repeat(4000));
    assert_eq!(
        parse_ssh_bootstrap_line(&tagged(&nested_value)),
        Err(BootstrapLineError::Malformed)
    );
    // Invalid UTF-8 inside the JSON is malformed, not a panic.
    let mut bad = tagged(r#"{"type":"commit","version":1,"fingerprint":"f","name":""#);
    bad.extend_from_slice(&[0xFF, 0xFE]);
    bad.extend_from_slice(br#"","role":"r"}"#);
    assert_eq!(
        parse_ssh_bootstrap_line(&bad),
        Err(BootstrapLineError::Malformed)
    );
}

#[test]
fn bootstrap_unknown_fields_are_ignored() {
    let hello = parse_ssh_bootstrap_line(&tagged(
        r#"{"type":"hello","versions":[1,2],"qsh_version":"9","status":"ready","fingerprint":"sha256:x","serve_bind":"[::]:4433","serve_listening":true,"future":{"a":[1,2,3]},"extra":null}"#,
    ))
    .unwrap();
    let BootstrapLine::Hello(h) = hello else {
        panic!("not a hello");
    };
    assert_eq!(h.versions, vec![1, 2]);
    assert_eq!(h.serve_listening, Some(true));

    let commit = parse_ssh_bootstrap_line(&tagged(
        r#"{"type":"commit","version":1,"fingerprint":"f","name":"n","role":"full","nonce":"z"}"#,
    ));
    assert!(matches!(commit, Ok(BootstrapLine::Commit(_))));

    let result = parse_ssh_bootstrap_line(&tagged(
        r#"{"type":"result","status":"exists","name":"n","role":null,"created":false,"hint":1}"#,
    ));
    assert!(matches!(result, Ok(BootstrapLine::Result(_))));

    // `serve_listening: null` and its absence both mean unknown.
    let null = parse_ssh_bootstrap_line(&tagged(
        r#"{"type":"hello","versions":[1],"qsh_version":"9","status":"ready","serve_listening":null}"#,
    ));
    let Ok(BootstrapLine::Hello(h)) = null else {
        panic!("not a hello");
    };
    assert_eq!(h.serve_listening, None);
}

#[test]
fn bootstrap_unknown_status_is_preserved_as_unknown() {
    let parsed = parse_ssh_bootstrap_line(&tagged(
        r#"{"type":"hello","versions":[1],"qsh_version":"9","status":"busy"}"#,
    ))
    .unwrap();
    let BootstrapLine::Hello(h) = parsed else {
        panic!("not a hello");
    };
    assert_eq!(h.status, HelloStatus::Unknown("busy".to_string()));
    assert_eq!(h.status.as_str(), "busy");

    let result = parse_ssh_bootstrap_line(&tagged(
        r#"{"type":"result","status":"quota","name":"n","role":null,"created":false}"#,
    ))
    .unwrap();
    let BootstrapLine::Result(r) = result else {
        panic!("not a result");
    };
    assert_eq!(r.status, ResultStatus::Unknown("quota".to_string()));

    // The known spellings still map to their variants, and an unknown one
    // survives a round trip as the same string.
    for s in ["ready", "not_initialized"] {
        let line = format!(r#"{{"type":"hello","versions":[1],"qsh_version":"9","status":"{s}"}}"#);
        let Ok(BootstrapLine::Hello(h)) = parse_ssh_bootstrap_line(&tagged(&line)) else {
            panic!("not a hello");
        };
        assert!(!matches!(h.status, HelloStatus::Unknown(_)), "{s}");
    }
    let round = BootstrapLine::Hello(Hello {
        status: HelloStatus::Unknown("Ready".to_string()),
        ..hello()
    });
    let line = round.encode_line().unwrap();
    assert_eq!(
        parse_ssh_bootstrap_line(line.trim_end().as_bytes()).unwrap(),
        round
    );
}

#[test]
fn negotiate_version_picks_the_largest_common_and_none_when_disjoint() {
    assert_eq!(negotiate_version(&[1], &[1]), Some(1));
    assert_eq!(negotiate_version(&[1, 2, 3], &[2, 3, 4]), Some(3));
    assert_eq!(negotiate_version(&[3, 1, 2], &[1, 2, 9, 3]), Some(3));
    assert_eq!(negotiate_version(&[1], &[2, 3]), None);
    assert_eq!(negotiate_version(&[1], &[]), None);
    assert_eq!(negotiate_version(&[], &[1]), None);
    assert_eq!(negotiate_version(BOOTSTRAP_VERSIONS, &[7, 1, 1]), Some(1));
    assert_eq!(BOOTSTRAP_VERSIONS, &[1]);
}

#[test]
fn bootstrap_reader_skips_untagged_preamble_up_to_64_kib_and_keeps_only_a_count() {
    // Exactly 64 KiB of rc output, in 1 KiB lines (newline included), then
    // the hello and the result.
    let mut reader = BootstrapReader::new();
    let line = format!("{}\n", "x".repeat(1023));
    let mut stream = Vec::new();
    for _ in 0..(BOOTSTRAP_PREAMBLE_MAX / line.len()) {
        stream.extend_from_slice(line.as_bytes());
    }
    assert_eq!(stream.len(), BOOTSTRAP_PREAMBLE_MAX);
    let out = reader.push(&stream).unwrap();
    assert!(out.is_empty());
    assert_eq!(reader.skipped_lines(), 64);
    assert_eq!(reader.skipped_bytes(), BOOTSTRAP_PREAMBLE_MAX);
    // Only a count survives: nothing buffered, nothing retained.
    assert!(reader.line.is_empty());
    assert!(reader.line.capacity() <= BOOTSTRAP_LINE_PREFIX.len() + 2);
    assert!(!reader.hello_seen());

    let out = reader.push(hello_line().as_bytes()).unwrap();
    assert_eq!(out, vec![BootstrapLine::Hello(hello())]);
    assert!(reader.hello_seen());
    let out = reader.push(result_line().as_bytes()).unwrap();
    assert_eq!(out, vec![BootstrapLine::Result(result())]);
    assert!(reader.is_done());

    // One byte more is a protocol error, at the byte that crosses the cap,
    // and the reader stays failed.
    let mut reader = BootstrapReader::new();
    stream.push(b'y');
    assert_eq!(
        reader.push(&stream),
        Err(BootstrapLineError::PreambleTooLarge)
    );
    assert_eq!(
        reader.push(hello_line().as_bytes()),
        Err(BootstrapLineError::PreambleTooLarge)
    );

    // One endless unterminated line is bounded the same way, in constant
    // memory.
    let mut reader = BootstrapReader::new();
    let endless = vec![b'z'; BOOTSTRAP_PREAMBLE_MAX + 1];
    assert_eq!(
        reader.push(&endless),
        Err(BootstrapLineError::PreambleTooLarge)
    );

    // Lines that start like the prefix but are not it are preamble too, as
    // are empty and CRLF-only lines.
    let mut reader = BootstrapReader::new();
    reader.push(b"qsh-boot\n\nqsh-bootstrap\r\n\r\n").unwrap();
    assert_eq!(reader.skipped_lines(), 4);
    assert_eq!(reader.skipped_bytes(), 9 + 1 + 15 + 2);
    assert!(!reader.hello_seen());
}

#[test]
fn bootstrap_reader_rejects_untagged_lines_after_hello() {
    // Between hello and result.
    let mut reader = BootstrapReader::new();
    reader.push(hello_line().as_bytes()).unwrap();
    assert_eq!(
        reader.push(b"Welcome back\n"),
        Err(BootstrapLineError::UntaggedAfterHello)
    );

    // The very first byte that cannot be the prefix is enough: no need to
    // wait for the newline.
    let mut reader = BootstrapReader::new();
    reader.push(hello_line().as_bytes()).unwrap();
    assert_eq!(
        reader.push(b"x"),
        Err(BootstrapLineError::UntaggedAfterHello)
    );

    // An empty line is untagged too.
    let mut reader = BootstrapReader::new();
    reader.push(hello_line().as_bytes()).unwrap();
    assert_eq!(
        reader.push(b"\n"),
        Err(BootstrapLineError::UntaggedAfterHello)
    );

    // After the result.
    let mut reader = BootstrapReader::new();
    reader.push(hello_line().as_bytes()).unwrap();
    reader.push(result_line().as_bytes()).unwrap();
    assert_eq!(
        reader.push(b"logout\n"),
        Err(BootstrapLineError::UntaggedAfterHello)
    );
}

#[test]
fn bootstrap_reader_rejects_out_of_order_messages() {
    let commit_line = BootstrapLine::Commit(commit()).encode_line().unwrap();
    // A result or a commit where the hello belongs.
    for first in [result_line(), commit_line.clone()] {
        let mut reader = BootstrapReader::new();
        assert_eq!(
            reader.push(first.as_bytes()),
            Err(BootstrapLineError::OutOfOrder)
        );
    }
    // A second hello, a commit from the responder side, anything after the
    // result.
    for second in [hello_line(), commit_line.clone()] {
        let mut reader = BootstrapReader::new();
        reader.push(hello_line().as_bytes()).unwrap();
        assert_eq!(
            reader.push(second.as_bytes()),
            Err(BootstrapLineError::OutOfOrder)
        );
    }
    let mut reader = BootstrapReader::new();
    reader.push(hello_line().as_bytes()).unwrap();
    reader.push(result_line().as_bytes()).unwrap();
    assert_eq!(
        reader.push(result_line().as_bytes()),
        Err(BootstrapLineError::OutOfOrder)
    );
}

#[test]
fn bootstrap_reader_tolerates_rc_output_before_hello_and_crlf() {
    let mut stream = Vec::new();
    stream.extend_from_slice(b"Last login: Mon Jan  1 00:00:00 2026\n");
    stream.extend_from_slice(b"\xff\xfe not even utf-8 \x00\x1b[2J\r\n");
    stream.extend_from_slice(hello_line().trim_end().as_bytes());
    stream.extend_from_slice(b"\r\n");
    stream.extend_from_slice(result_line().trim_end().as_bytes());
    stream.extend_from_slice(b"\r\n");
    let mut reader = BootstrapReader::new();
    let out = reader.push(&stream).unwrap();
    assert_eq!(
        out,
        vec![
            BootstrapLine::Hello(hello()),
            BootstrapLine::Result(result())
        ]
    );
    assert_eq!(reader.skipped_lines(), 2);
    assert!(reader.is_done());
}

#[test]
fn bootstrap_reader_errors_never_echo_input() {
    let secret = "hunter2-do-not-log";
    let mut reader = BootstrapReader::new();
    let err = reader
        .push(format!("{BOOTSTRAP_LINE_PREFIX}{{\"type\":\"{secret}\"}}\n").as_bytes())
        .unwrap_err();
    assert!(!format!("{err} {err:?}").contains(secret));
    assert!(!format!("{reader:?}").contains(secret));

    let mut reader = BootstrapReader::new();
    reader.push(format!("{secret}\n").as_bytes()).unwrap();
    assert!(!format!("{reader:?}").contains(secret));
}

fn run_whole(data: &[u8]) -> Result<(Vec<BootstrapLine>, u32, usize), BootstrapLineError> {
    let mut reader = BootstrapReader::new();
    let out = reader.push(data)?;
    Ok((out, reader.skipped_lines(), reader.skipped_bytes()))
}

fn run_chunked(
    data: &[u8],
    chunk: usize,
) -> Result<(Vec<BootstrapLine>, u32, usize), BootstrapLineError> {
    let mut reader = BootstrapReader::new();
    let mut out = Vec::new();
    for piece in data.chunks(chunk.max(1)) {
        out.extend(reader.push(piece)?);
    }
    Ok((out, reader.skipped_lines(), reader.skipped_bytes()))
}

fn stream_strategy() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        Just(hello_line().into_bytes()),
        Just(result_line().into_bytes()),
        Just(
            BootstrapLine::Commit(commit())
                .encode_line()
                .unwrap()
                .into_bytes()
        ),
        Just(b"rc output\n".to_vec()),
        Just(b"qsh-boot\n".to_vec()),
        Just(b"\r\n".to_vec()),
        Just(b"qsh-bootstrap {\n".to_vec()),
        proptest::collection::vec(any::<u8>(), 0..64),
    ];
    proptest::collection::vec(piece, 0..8).prop_map(|v| v.concat())
}

proptest! {
    #[test]
    fn bootstrap_reader_result_is_independent_of_chunking(
        data in stream_strategy(),
        chunk in 1usize..40,
    ) {
        prop_assert_eq!(run_whole(&data), run_chunked(&data, chunk));
        prop_assert_eq!(run_whole(&data), run_chunked(&data, 1));
    }

    #[test]
    fn parse_ssh_bootstrap_line_is_total(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_ssh_bootstrap_line(&data);
        let mut reader = BootstrapReader::new();
        let _ = reader.push(&data);
    }

    #[test]
    fn encoded_lines_are_single_lines(
        name in ".{0,64}",
        message in ".{0,256}",
    ) {
        let msg = BootstrapLine::Result(BootstrapResult {
            name,
            message: Some(message),
            ..result()
        });
        let line = msg.encode_line().unwrap();
        prop_assert_eq!(line.matches('\n').count(), 1);
        prop_assert!(line.ends_with('\n'));
        prop_assert!(!line.contains('\r'));
        prop_assert_eq!(
            parse_ssh_bootstrap_line(line.trim_end_matches('\n').as_bytes()).unwrap(),
            msg
        );
    }
}
