use super::*;
use crate::frame::FrameDecoder;
use proptest::prelude::*;
use std::collections::HashMap;

// ---- strategies -----------------------------------------------------

fn arb_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=max)
}

fn arb_reverse_registration() -> impl Strategy<Value = ReverseRegistration> {
    (
        "[a-zA-Z0-9._-]{0,64}",
        proptest::collection::vec("[a-z.0-9]{1,16}", 0..4),
    )
        .prop_map(|(offered_name, capabilities)| ReverseRegistration {
            offered_name,
            capabilities,
        })
}

fn arb_hello() -> impl Strategy<Value = Hello> {
    (
        proptest::collection::vec(any::<u32>(), 0..4),
        ".{0,32}",
        proptest::collection::vec("[a-z.0-9]{1,16}", 0..4),
        proptest::option::of(arb_reverse_registration()),
    )
        .prop_map(|(versions, device_name, capabilities, reverse)| Hello {
            versions,
            device_name,
            capabilities,
            reverse,
        })
}

fn arb_error() -> impl Strategy<Value = Error> {
    (
        proptest::sample::select(ErrorCode::KNOWN.to_vec()),
        ".{0,64}",
        any::<bool>(),
    )
        .prop_map(|(code, message, retryable)| Error::new(code, message, retryable))
}

fn arb_exec_start() -> impl Strategy<Value = ExecStart> {
    (
        proptest::collection::vec(".{0,16}", 0..5),
        proptest::collection::hash_map("[A-Z_]{1,8}", ".{0,16}", 0..4),
        any::<u64>(),
        proptest::option::of(".{0,32}"),
        any::<bool>(),
        arb_agent_channel(),
    )
        .prop_map(
            |(argv, env, timeout_ms, shell_command, login_shell, agent_channel)| ExecStart {
                argv,
                env,
                timeout_ms,
                shell_command,
                login_shell,
                agent_channel,
            },
        )
}

fn arb_exec_started() -> impl Strategy<Value = ExecStarted> {
    (".{0,26}", arb_bytes(16), any::<i32>()).prop_map(|(exec_id, ticket, agent)| ExecStarted {
        exec_id,
        ticket,
        agent,
    })
}

/// Empty (not requested) or the 16 bytes a client draws (ADR-0055 decision 3).
fn arb_agent_channel() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![Just(Vec::new()), arb_bytes(16)]
}

// -- tunnel control (M4) --

fn arb_forward_id() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{1,64}"
}

fn arb_remote_forward_open() -> impl Strategy<Value = RemoteForwardOpen> {
    (
        ".{0,64}",
        any::<u32>(),
        ".{0,64}",
        any::<u32>(),
        proptest::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(
            |(bind_host, bind_port, forward_host, forward_port, claim_token)| RemoteForwardOpen {
                bind_host,
                bind_port,
                forward_host,
                forward_port,
                claim_token,
            },
        )
}

fn arb_remote_forward_opened() -> impl Strategy<Value = RemoteForwardOpened> {
    (arb_forward_id(), any::<u32>()).prop_map(|(forward_id, actual_port)| RemoteForwardOpened {
        forward_id,
        actual_port,
    })
}

fn arb_remote_forward_close() -> impl Strategy<Value = RemoteForwardClose> {
    arb_forward_id().prop_map(|forward_id| RemoteForwardClose { forward_id })
}

fn arb_connect_result() -> impl Strategy<Value = ConnectResult> {
    (
        any::<bool>(),
        "(|CONNECTION_FAILED|PERMISSION_DENIED)",
        ".{0,64}",
    )
        .prop_map(|(ok, code, message)| ConnectResult { ok, code, message })
}

// -- session control (M2) --

fn arb_session_id() -> impl Strategy<Value = String> {
    "[0-9A-HJKMNP-TV-Z]{26}"
}

fn arb_rfc3339() -> impl Strategy<Value = String> {
    "20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z"
}

fn arb_principal() -> impl Strategy<Value = String> {
    "(device|user|fp):[a-z0-9]{1,12}"
}

fn arb_screen_request() -> impl Strategy<Value = Option<ScreenRequest>> {
    proptest::option::of(
        (
            any::<u32>(),
            any::<u32>(),
            proptest::option::of(any::<u32>()),
            proptest::option::of(any::<u32>()),
        )
            .prop_map(|(cols, rows, fg, bg)| ScreenRequest { cols, rows, fg, bg }),
    )
}

fn arb_session_open() -> impl Strategy<Value = SessionOpen> {
    (
        proptest::collection::vec(".{0,16}", 0..5),
        proptest::collection::hash_map("[A-Z_]{1,8}", ".{0,16}", 0..4),
        "[a-z0-9-]{0,16}",
        any::<u32>(),
        any::<u32>(),
        proptest::option::of("[a-z]{1,8}"),
        proptest::option::of(".{0,32}"),
        arb_screen_request(),
        arb_agent_channel(),
    )
        .prop_map(
            |(argv, env, term, cols, rows, user, shell_command, screen, agent_channel)| {
                SessionOpen {
                    argv,
                    env,
                    term,
                    cols,
                    rows,
                    user,
                    shell_command,
                    screen,
                    agent_channel,
                }
            },
        )
}

fn arb_session_opened() -> impl Strategy<Value = SessionOpened> {
    (
        arb_session_id(),
        arb_bytes(32),
        arb_bytes(16),
        any::<u64>(),
        arb_rfc3339(),
        arb_bytes(16),
        any::<i32>(),
    )
        .prop_map(
            |(session_id, resume_token, ticket, initial_seq, expires_at, screen_channel, agent)| {
                SessionOpened {
                    session_id,
                    resume_token,
                    ticket,
                    initial_seq,
                    expires_at,
                    screen_channel,
                    agent,
                }
            },
        )
}

fn arb_session_attach() -> impl Strategy<Value = SessionAttach> {
    (
        arb_session_id(),
        arb_bytes(32),
        any::<u64>(),
        // Any i32: prost keeps unknown enum values in the raw field, so
        // out-of-range modes must round-trip too.
        any::<i32>(),
        any::<bool>(),
        arb_screen_request(),
        arb_agent_channel(),
    )
        .prop_map(
            |(session_id, resume_token, last_output_seq, mode, no_steal, screen, agent_channel)| {
                SessionAttach {
                    session_id,
                    resume_token,
                    last_output_seq,
                    mode,
                    no_steal,
                    screen,
                    agent_channel,
                }
            },
        )
}

fn arb_session_attached() -> impl Strategy<Value = SessionAttached> {
    (
        arb_bytes(16),
        arb_bytes(32),
        any::<u64>(),
        any::<bool>(),
        arb_rfc3339(),
        any::<u64>(),
        arb_bytes(16),
        any::<i32>(),
    )
        .prop_map(
            |(
                ticket,
                new_resume_token,
                replay_from,
                writer_lease,
                expires_at,
                input_seq,
                screen_channel,
                agent,
            )| {
                SessionAttached {
                    ticket,
                    new_resume_token,
                    replay_from,
                    writer_lease,
                    expires_at,
                    input_seq,
                    output_end: 0,
                    screen_channel,
                    agent,
                }
            },
        )
}

fn arb_session_info() -> impl Strategy<Value = SessionInfo> {
    (
        arb_session_id(),
        "(running|exited)",
        proptest::option::of(arb_principal()),
        arb_rfc3339(),
        any::<u64>(),
    )
        .prop_map(
            |(session_id, state, writer, created_at, last_sequence)| SessionInfo {
                session_id,
                state,
                writer,
                created_at,
                last_sequence,
            },
        )
}

fn arb_output() -> impl Strategy<Value = Output> {
    (any::<u64>(), arb_bytes(64)).prop_map(|(sequence, data)| Output { sequence, data })
}

fn arb_gap() -> impl Strategy<Value = Gap> {
    (any::<u64>(), any::<u64>()).prop_map(|(requested_after, available_from)| Gap {
        requested_after,
        available_from,
    })
}

fn arb_exit() -> impl Strategy<Value = Exit> {
    (
        any::<u64>(),
        any::<i32>(),
        proptest::option::of("SIG[A-Z]{3,4}"),
    )
        .prop_map(|(final_seq, exit_code, signal)| Exit {
            final_seq,
            exit_code,
            signal,
        })
}

fn arb_writer_changed() -> impl Strategy<Value = WriterChanged> {
    (proptest::option::of(arb_principal()), any::<u64>())
        .prop_map(|(new_writer, seq)| WriterChanged { new_writer, seq })
}

fn arb_closed() -> impl Strategy<Value = Closed> {
    ("(closed|exit|ttl_expired|future_reason)", any::<u64>())
        .prop_map(|(reason, seq)| Closed { reason, seq })
}

fn arb_session_read_event() -> impl Strategy<Value = SessionReadEvent> {
    use session_read_event::Body;
    prop_oneof![
        arb_output().prop_map(|o| SessionReadEvent::from_body(Body::Output(o))),
        arb_gap().prop_map(|g| SessionReadEvent::from_body(Body::Gap(g))),
        arb_exit().prop_map(|e| SessionReadEvent::from_body(Body::Exit(e))),
        arb_writer_changed().prop_map(|w| SessionReadEvent::from_body(Body::WriterChanged(w))),
        arb_closed().prop_map(|c| SessionReadEvent::from_body(Body::Closed(c))),
        Just(SessionReadEvent { body: None }),
    ]
}

fn arb_session_event() -> impl Strategy<Value = SessionEvent> {
    (
        arb_session_id(),
        prop_oneof![
            arb_exit().prop_map(session_event::Body::Exited),
            arb_writer_changed().prop_map(session_event::Body::WriterChanged),
            arb_closed().prop_map(session_event::Body::Closed),
        ],
    )
        .prop_map(|(session_id, body)| SessionEvent::from_body(session_id, body))
}

fn arb_response() -> impl Strategy<Value = Response> {
    let body = prop_oneof![
        arb_session_opened().prop_map(response::Body::SessionOpened),
        arb_session_attached().prop_map(response::Body::SessionAttached),
        arb_exec_started().prop_map(response::Body::ExecStarted),
        (
            proptest::collection::vec(arb_session_read_event(), 0..4),
            any::<u64>(),
            any::<u64>(),
        )
            .prop_map(|(events, next_after, next_ctl_after)| {
                response::Body::SessionReadResult(SessionReadResult {
                    events,
                    next_after,
                    next_ctl_after,
                })
            }),
        proptest::collection::vec(arb_session_info(), 0..4).prop_map(|sessions| {
            response::Body::SessionListResult(SessionListResult { sessions })
        }),
        arb_session_info().prop_map(response::Body::SessionInfo),
        any::<u64>().prop_map(|bytes_written| {
            response::Body::SessionWritten(SessionWritten { bytes_written })
        }),
        (any::<u32>(), any::<u32>())
            .prop_map(|(cols, rows)| response::Body::SessionResized(SessionResized { cols, rows })),
        any::<u64>()
            .prop_map(|final_seq| response::Body::SessionClosed(SessionClosed { final_seq })),
        arb_remote_forward_opened().prop_map(response::Body::RfwdOpened),
        arb_error().prop_map(response::Body::Error),
    ];
    proptest::option::of(body).prop_map(|body| Response { body })
}

fn arb_control_body() -> impl Strategy<Value = control_message::Body> {
    use control_message::Body;
    prop_oneof![
        arb_hello().prop_map(Body::Hello),
        arb_response().prop_map(Body::Response),
        arb_session_open().prop_map(Body::SessionOpen),
        arb_session_attach().prop_map(Body::SessionAttach),
        Just(Body::SessionList(SessionList {})),
        arb_session_id().prop_map(|session_id| Body::SessionGet(SessionGet { session_id })),
        (arb_session_id(), any::<u32>(), any::<u32>()).prop_map(|(session_id, cols, rows)| {
            Body::SessionResize(SessionResize {
                session_id,
                cols,
                rows,
            })
        }),
        (
            arb_session_id(),
            proptest::option::of("SIG(HUP|INT|QUIT|TERM|USR1|USR2|KILL)")
        )
            .prop_map(|(session_id, signal)| Body::SessionClose(SessionClose {
                session_id,
                signal
            })),
        (
            arb_session_id(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
        )
            .prop_map(|(session_id, after, max_bytes, wait_ms, ctl_after)| {
                Body::SessionRead(SessionRead {
                    session_id,
                    after,
                    max_bytes,
                    wait_ms,
                    ctl_after,
                })
            }),
        (arb_session_id(), arb_bytes(64))
            .prop_map(|(session_id, data)| Body::SessionWrite(SessionWrite { session_id, data })),
        arb_exec_start().prop_map(Body::ExecStart),
        arb_remote_forward_open().prop_map(Body::RfwdOpen),
        arb_remote_forward_close().prop_map(Body::RfwdClose),
        Just(Body::Ping(Ping {})),
        Just(Body::Pong(Pong {})),
        arb_session_event().prop_map(Body::SessionEvent),
    ]
}

fn arb_control() -> impl Strategy<Value = ControlMessage> {
    (any::<u64>(), proptest::option::of(arb_control_body()))
        .prop_map(|(request_id, body)| ControlMessage { request_id, body })
}

fn arb_stream_header() -> impl Strategy<Value = StreamHeader> {
    (
        0i32..=5,
        arb_bytes(16),
        ".{0,32}",
        any::<u32>(),
        any::<bool>(),
    )
        .prop_map(|(kind, ticket, host, port, deny_host_local)| StreamHeader {
            kind,
            ticket,
            host,
            port,
            deny_host_local,
        })
}

fn arb_session_frame() -> impl Strategy<Value = SessionFrame> {
    prop_oneof![
        (any::<u64>(), arb_bytes(64)).prop_map(|(seq, data)| SessionFrame::output(seq, data)),
        (any::<u64>(), arb_bytes(64)).prop_map(|(seq, data)| SessionFrame::input(seq, data)),
        any::<u64>().prop_map(SessionFrame::input_ack),
        (any::<u64>(), any::<u64>()).prop_map(|(a, b)| SessionFrame::gap(a, b)),
        (any::<u32>(), any::<u32>()).prop_map(|(c, r)| SessionFrame::resize(c, r)),
        (
            any::<u64>(),
            any::<i32>(),
            proptest::option::of("SIG[A-Z]{3,4}")
        )
            .prop_map(|(seq, code, sig)| SessionFrame::exit(seq, code, sig)),
        (any::<u64>(), any::<u32>(), any::<u32>(), arb_bytes(64)).prop_map(
            |(new_num, part, parts, data)| {
                SessionFrame::screen_update(ScreenUpdate {
                    new_num,
                    part,
                    parts,
                    data,
                })
            }
        ),
        any::<u64>().prop_map(SessionFrame::screen_ack),
        (proptest::collection::vec(arb_bytes(32), 0..4), any::<u64>()).prop_map(
            |(lines, skipped)| SessionFrame::screen_history(ScreenHistory { lines, skipped })
        ),
        Just(SessionFrame { body: None }),
    ]
}

fn arb_exec_frame() -> impl Strategy<Value = ExecFrame> {
    prop_oneof![
        arb_bytes(64).prop_map(ExecFrame::stdin),
        Just(ExecFrame::stdin_eof()),
        arb_bytes(64).prop_map(ExecFrame::stdout),
        arb_bytes(64).prop_map(ExecFrame::stderr),
        (any::<i32>(), proptest::option::of("[A-Z]{3,7}"))
            .prop_map(|(code, sig)| ExecFrame::exec_exit(code, sig)),
        (any::<i32>(), proptest::option::of("[A-Z]{3,7}"))
            .prop_map(|(code, sig)| ExecFrame::exec_exit_timed_out(code, sig)),
        Just(ExecFrame { body: None }),
    ]
}

fn arb_file_kind() -> impl Strategy<Value = i32> {
    0i32..=4
}

fn arb_file_entry() -> impl Strategy<Value = FileEntry> {
    (
        ".{0,32}",
        arb_file_kind(),
        any::<u64>(),
        any::<u32>(),
        any::<i64>(),
    )
        .prop_map(|(name, kind, size, mode, mtime)| FileEntry {
            name,
            kind,
            size,
            mode,
            mtime,
        })
}

fn arb_file_listed() -> impl Strategy<Value = FileListed> {
    (
        arb_file_kind(),
        any::<u64>(),
        any::<u32>(),
        any::<i64>(),
        proptest::collection::vec(arb_file_entry(), 0..4),
        any::<bool>(),
        any::<u32>(),
    )
        .prop_map(
            |(kind, size, mode, mtime, entries, more, unlistable)| FileListed {
                kind,
                size,
                mode,
                mtime,
                entries,
                more,
                unlistable,
            },
        )
}

fn arb_file_write_open() -> impl Strategy<Value = FileWriteOpen> {
    (
        ".{0,32}",
        any::<u64>(),
        any::<u32>(),
        any::<bool>(),
        ".{0,16}",
        any::<bool>(),
        any::<i64>(),
        ".{0,16}",
    )
        .prop_map(
            |(path, size, mode, overwrite, name_if_dir, preserve, mtime, user)| FileWriteOpen {
                path,
                size,
                mode,
                overwrite,
                name_if_dir,
                preserve,
                mtime,
                user,
            },
        )
}

fn arb_file_mkdir_open() -> impl Strategy<Value = FileMkdirOpen> {
    (".{0,32}", any::<u32>(), ".{0,16}", any::<bool>(), ".{0,16}").prop_map(
        |(path, mode, name_if_dir, preserve, user)| FileMkdirOpen {
            path,
            mode,
            name_if_dir,
            preserve,
            user,
        },
    )
}

fn arb_file_response() -> impl Strategy<Value = response::Body> {
    prop_oneof![
        (arb_bytes(16), any::<u64>(), any::<u32>(), any::<i64>()).prop_map(
            |(ticket, size, mode, mtime)| response::Body::FileReadOpened(FileReadOpened {
                ticket,
                size,
                mode,
                mtime
            })
        ),
        (arb_bytes(16), any::<bool>()).prop_map(|(ticket, into_dir)| {
            response::Body::FileWriteOpened(FileWriteOpened { ticket, into_dir })
        }),
        arb_file_listed().prop_map(response::Body::FileListed),
        (any::<bool>(), any::<bool>()).prop_map(|(created, into_dir)| {
            response::Body::FileMkdirDone(FileMkdirDone { created, into_dir })
        }),
    ]
}

fn arb_file_control_body() -> impl Strategy<Value = control_message::Body> {
    use control_message::Body;
    prop_oneof![
        (".{0,32}", ".{0,16}")
            .prop_map(|(path, user)| Body::FileReadOpen(FileReadOpen { path, user })),
        arb_file_write_open().prop_map(Body::FileWriteOpen),
        (".{0,32}", ".{0,16}", ".{0,16}").prop_map(|(path, after, user)| {
            Body::FileListOpen(FileListOpen { path, after, user })
        }),
        arb_file_mkdir_open().prop_map(Body::FileMkdirOpen),
        arb_file_response().prop_map(|r| Body::Response(Response { body: Some(r) })),
    ]
}

fn arb_file_frame() -> impl Strategy<Value = FileFrame> {
    prop_oneof![
        arb_bytes(64).prop_map(FileFrame::data),
        (any::<u64>(), arb_bytes(32)).prop_map(|(size, hash)| FileFrame::end(size, hash)),
        (any::<bool>(), "[A-Z_]{0,16}", ".{0,32}", any::<bool>())
            .prop_map(|(ok, code, msg, over)| FileFrame::result(ok, code, msg, over)),
        Just(FileFrame { body: None }),
    ]
}

// ---- roundtrip ------------------------------------------------------

/// `decode(encode(m)) == m`: the frame round-trips to an equal message.
///
/// This does *not* also assert `encode(decode(b)) == b` (canonical
/// encoding) the way `local::tests::roundtrip_and_canonical` does — some
/// `qsh.wire.v1` messages carry a `map<string, string>` field
/// (`SessionOpen.env`, `ExecStart.env`), and prost's `HashMap` field
/// encoding order is a function of the map's internal bucket layout, not
/// wire order, so two maps with identical contents but different
/// insertion histories can legitimately re-encode to different (but
/// semantically equal) bytes. Canonical encoding is asserted separately,
/// scoped to the map-free messages that actually need it — see
/// `hello_encoding_is_canonical` below.
fn roundtrip_via_frame<M: Message + Default + PartialEq + std::fmt::Debug>(m: &M, max: usize) {
    let wire = encode_framed(m, max).unwrap();
    let mut dec = FrameDecoder::new(max);
    dec.push(&wire);
    let payload = dec.next_frame().unwrap().expect("one complete frame");
    assert_eq!(dec.next_frame().unwrap(), None, "no trailing bytes");
    let back: M = decode_msg(&payload).unwrap();
    assert_eq!(&back, m, "roundtrip: decode(encode(m)) == m");
}

/// `encode(decode(b)) == b` for a valid `b`: re-encoding what we just
/// decoded reproduces the exact bytes, not merely an equivalent message.
/// `Hello`/`ReverseRegistration` carry no map field, so this holds
/// (unlike `ControlMessage` in general — see `roundtrip_via_frame`).
fn assert_canonical_via_frame<M: Message + Default + PartialEq + std::fmt::Debug>(
    m: &M,
    max: usize,
) {
    let wire = encode_framed(m, max).unwrap();
    let mut dec = FrameDecoder::new(max);
    dec.push(&wire);
    let payload = dec.next_frame().unwrap().expect("one complete frame");
    let back: M = decode_msg(&payload).unwrap();
    let re = encode_framed(&back, max).unwrap();
    assert_eq!(re, wire, "canonical: encode(decode(b)) == b");
}

proptest! {
    #[test]
    fn control_message_roundtrips(m in arb_control()) {
        roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
    }

    /// `Hello` (including the M3 `reverse` field) is map-free, so unlike
    /// `ControlMessage` in general it owes canonical encoding too
    /// (`docs/design/testing.md` L0).
    #[test]
    fn hello_encoding_is_canonical(m in arb_hello()) {
        let ctl = ControlMessage::new(0, control_message::Body::Hello(m));
        assert_canonical_via_frame(&ctl, CONTROL_FRAME_MAX);
    }

    #[test]
    fn stream_header_roundtrips(m in arb_stream_header()) {
        roundtrip_via_frame(&m, DATA_FRAME_MAX);
    }

    // -- M4 tunnel messages (`docs/design/testing.md` L0): `decode(encode(m))
    // == m` plus canonical encoding for each — none of the four carry a
    // map field, so (unlike `ControlMessage` in general) canonical
    // encoding holds directly, the same reasoning as
    // `hello_encoding_is_canonical` above. --

    #[test]
    fn remote_forward_open_roundtrips_and_is_canonical(m in arb_remote_forward_open()) {
        roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
        assert_canonical_via_frame(&m, CONTROL_FRAME_MAX);
    }

    #[test]
    fn remote_forward_opened_roundtrips_and_is_canonical(m in arb_remote_forward_opened()) {
        roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
        assert_canonical_via_frame(&m, CONTROL_FRAME_MAX);
    }

    #[test]
    fn remote_forward_close_roundtrips_and_is_canonical(m in arb_remote_forward_close()) {
        roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
        assert_canonical_via_frame(&m, CONTROL_FRAME_MAX);
    }

    #[test]
    fn connect_result_roundtrips_and_is_canonical(m in arb_connect_result()) {
        roundtrip_via_frame(&m, DATA_FRAME_MAX);
        assert_canonical_via_frame(&m, DATA_FRAME_MAX);
    }

    #[test]
    fn exec_frame_roundtrips(m in arb_exec_frame()) {
        roundtrip_via_frame(&m, DATA_FRAME_MAX);
    }

    #[test]
    fn session_frame_roundtrips(m in arb_session_frame()) {
        roundtrip_via_frame(&m, DATA_FRAME_MAX);
        // The dedicated encoder agrees with the generic one for
        // in-cap chunks.
        let via_helper = encode_session_frame(&m).unwrap();
        prop_assert_eq!(via_helper, encode_framed(&m, DATA_FRAME_MAX).unwrap());
    }

    #[test]
    fn file_control_messages_roundtrip_and_are_canonical(
        id in any::<u64>(),
        body in arb_file_control_body(),
    ) {
        let m = ControlMessage { request_id: id, body: Some(body) };
        roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
        assert_canonical_via_frame(&m, CONTROL_FRAME_MAX);
        // The control encoder accepts them unchanged.
        prop_assert_eq!(encode_control(&m).unwrap(), encode_framed(&m, CONTROL_FRAME_MAX).unwrap());
    }

    #[test]
    fn file_frame_roundtrips(m in arb_file_frame()) {
        roundtrip_via_frame(&m, DATA_FRAME_MAX);
        let via_helper = encode_file_frame(&m).unwrap();
        prop_assert_eq!(via_helper, encode_framed(&m, DATA_FRAME_MAX).unwrap());
    }

    #[test]
    fn framed_file_frame_prefixes_are_incomplete(m in arb_file_frame()) {
        let wire = encode_file_frame(&m).unwrap();
        for cut in 0..wire.len() {
            let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
            dec.push(&wire[..cut]);
            prop_assert_eq!(dec.next_frame().unwrap(), None, "prefix len {}", cut);
        }
    }

    /// Every strict prefix of a framed encoding is "incomplete" at the
    /// frame layer (`Ok(None)`): never a frame, never a panic. The
    /// protobuf body itself is prefix-tolerant by design, so the
    /// truncation guarantee lives in the frame layer.
    #[test]
    fn framed_prefixes_are_incomplete(m in arb_control()) {
        let wire = encode_control(&m).unwrap();
        for cut in 0..wire.len() {
            let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
            dec.push(&wire[..cut]);
            prop_assert_eq!(dec.next_frame().unwrap(), None, "prefix len {}", cut);
        }
    }

    /// Same truncation guarantee for the data-stream frame types.
    #[test]
    fn framed_session_frame_prefixes_are_incomplete(m in arb_session_frame()) {
        let wire = encode_session_frame(&m).unwrap();
        for cut in 0..wire.len() {
            let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
            dec.push(&wire[..cut]);
            prop_assert_eq!(dec.next_frame().unwrap(), None, "prefix len {}", cut);
        }
    }

    #[test]
    fn framed_stream_header_prefixes_are_incomplete(m in arb_stream_header()) {
        let wire = encode_stream_header(&m).unwrap();
        for cut in 0..wire.len() {
            let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
            dec.push(&wire[..cut]);
            prop_assert_eq!(dec.next_frame().unwrap(), None, "prefix len {}", cut);
        }
    }

    /// Arbitrary bytes never panic the decoder.
    #[test]
    fn garbage_never_panics(bytes in arb_bytes(256)) {
        let _ = decode_msg::<ControlMessage>(&bytes);
        let _ = decode_msg::<StreamHeader>(&bytes);
        let _ = decode_msg::<ExecFrame>(&bytes);
        let _ = decode_msg::<SessionFrame>(&bytes);
        let _ = decode_msg::<FileFrame>(&bytes);
        let _ = decode_msg::<RemoteForwardOpen>(&bytes);
        let _ = decode_msg::<RemoteForwardOpened>(&bytes);
        let _ = decode_msg::<RemoteForwardClose>(&bytes);
        let _ = decode_msg::<ConnectResult>(&bytes);
    }

    /// Bit-flipped valid encodings never panic and, when they decode,
    /// re-encode without panicking.
    #[test]
    fn bit_flips_never_panic(m in arb_control(), idx in any::<prop::sample::Index>(), bit in 0u8..8) {
        let mut body = m.encode_to_vec();
        if body.is_empty() { return Ok(()); }
        let i = idx.index(body.len());
        body[i] ^= 1 << bit;
        if let Ok(decoded) = decode_msg::<ControlMessage>(&body) {
            let _ = decoded.encode_to_vec();
        }
    }
}

// ---- allocation bound ----------------------------------------------

#[test]
fn oversize_control_frame_rejected_before_allocation() {
    // A peer claiming a 4 GiB frame is rejected from the 4-byte header
    // alone; the frame layer never allocates `attacker_length` bytes.
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&u32::MAX.to_be_bytes());
    assert_eq!(
        dec.next_frame().unwrap_err(),
        FrameError::Oversize {
            len: u32::MAX,
            max: CONTROL_FRAME_MAX
        }
    );
}

#[test]
fn encode_refuses_messages_over_frame_cap() {
    let big = ExecFrame::stdout(vec![0u8; DATA_FRAME_MAX + 1]);
    assert!(matches!(
        encode_exec_frame(&big),
        Err(WireEncodeError::TooLarge { .. })
    ));
}

/// The allocation-bound guarantee extends to the new M3 message: a
/// `Hello.reverse` carrying an oversize `ReverseRegistration` is
/// refused by the same `CONTROL_FRAME_MAX` cap `encode_control` already
/// enforces for every other control message — no new bypass was opened
/// by adding the field.
#[test]
fn hello_with_oversize_reverse_registration_rejected_over_frame_cap() {
    let msg = ControlMessage::new(
        1,
        control_message::Body::Hello(Hello {
            versions: vec![0],
            device_name: "hermes".into(),
            capabilities: vec![],
            reverse: Some(ReverseRegistration {
                offered_name: "x".into(),
                capabilities: vec!["x".repeat(CONTROL_FRAME_MAX)],
            }),
        }),
    );
    assert!(matches!(
        encode_control(&msg),
        Err(WireEncodeError::TooLarge { .. })
    ));
}

// ---- chunk cap ------------------------------------------------------

#[test]
fn session_frame_chunk_over_cap_is_rejected_at_encode() {
    // Exactly the cap is fine …
    assert!(encode_session_frame(&SessionFrame::output(0, vec![0u8; SESSION_CHUNK_MAX])).is_ok());
    assert!(encode_session_frame(&SessionFrame::input(0, vec![0u8; SESSION_CHUNK_MAX])).is_ok());
    // … one byte more is refused *before* framing, even though it would
    // still fit the 64 KiB data-frame cap.
    const { assert!(SESSION_CHUNK_MAX + 1 < DATA_FRAME_MAX) };
    for frame in [
        SessionFrame::output(0, vec![0u8; SESSION_CHUNK_MAX + 1]),
        SessionFrame::input(0, vec![0u8; SESSION_CHUNK_MAX + 1]),
    ] {
        let expected = ChunkTooLarge {
            len: SESSION_CHUNK_MAX + 1,
            max: SESSION_CHUNK_MAX,
        };
        assert_eq!(
            encode_session_frame(&frame),
            Err(WireEncodeError::ChunkTooLarge(expected))
        );
        // The receiver-side check reports the same violation on a
        // frame that arrived without passing through our encoder.
        assert_eq!(frame.validate(), Err(expected));
    }
}

#[test]
fn decoded_over_cap_chunks_are_rejected_by_validate() {
    // A peer that bypasses our encoder can put up to DATA_FRAME_MAX /
    // CONTROL_FRAME_MAX in a chunk; `validate()` is what bounds it.
    let frame = SessionFrame::output(0, vec![0u8; SESSION_CHUNK_MAX + 1]);
    let raw = encode_framed(&frame, DATA_FRAME_MAX).unwrap();
    let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
    dec.push(&raw);
    let payload = dec.next_frame().unwrap().unwrap();
    let back: SessionFrame = decode_msg(&payload).unwrap();
    assert!(back.validate().is_err());

    let write = SessionWrite {
        session_id: "01K0SESSION".into(),
        data: vec![0u8; SESSION_CHUNK_MAX + 1],
    };
    let raw = encode_framed(&write, CONTROL_FRAME_MAX).unwrap();
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&raw);
    let payload = dec.next_frame().unwrap().unwrap();
    let back: SessionWrite = decode_msg(&payload).unwrap();
    assert!(back.validate().is_err());
    assert!(
        SessionWrite {
            data: vec![0u8; SESSION_CHUNK_MAX],
            ..write
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn session_read_result_over_cap_output_is_rejected_at_encode() {
    let m = ControlMessage::response(
        1,
        response::Body::SessionReadResult(SessionReadResult {
            events: vec![SessionReadEvent::from_body(
                session_read_event::Body::Output(Output {
                    sequence: 0,
                    data: vec![0u8; SESSION_CHUNK_MAX + 1],
                }),
            )],
            ..Default::default()
        }),
    );
    assert!(matches!(
        encode_control(&m),
        Err(WireEncodeError::ChunkTooLarge(_))
    ));
}

#[test]
fn full_limit_session_read_result_fits_one_control_frame() {
    // SESSION_READ_MAX_BYTES of Output payload, split into max-size
    // chunks, plus interleaved control entries, must encode under
    // CONTROL_FRAME_MAX — otherwise a legal `limit_bytes` could make the
    // host unable to form a reply.
    const { assert!(SESSION_READ_MAX_BYTES.is_multiple_of(SESSION_CHUNK_MAX)) };
    let mut events = Vec::new();
    for i in 0..(SESSION_READ_MAX_BYTES / SESSION_CHUNK_MAX) {
        events.push(SessionReadEvent::from_body(
            session_read_event::Body::Output(Output {
                sequence: u64::MAX - i as u64,
                data: vec![0xffu8; SESSION_CHUNK_MAX],
            }),
        ));
        events.push(SessionReadEvent::from_body(
            session_read_event::Body::WriterChanged(WriterChanged {
                new_writer: Some("device:".to_string() + &"x".repeat(200)),
                seq: u64::MAX,
            }),
        ));
    }
    events.push(SessionReadEvent::from_body(session_read_event::Body::Exit(
        Exit {
            final_seq: u64::MAX,
            exit_code: i32::MIN,
            signal: Some("SIGKILL".into()),
        },
    )));
    let m = ControlMessage::response(
        u64::MAX,
        response::Body::SessionReadResult(SessionReadResult {
            events,
            ..Default::default()
        }),
    );
    assert!(encode_control(&m).is_ok());
}

#[test]
fn session_write_chunk_over_cap_is_rejected_at_encode() {
    let m = ControlMessage::new(
        5,
        control_message::Body::SessionWrite(SessionWrite {
            session_id: "01K0SESSION".into(),
            data: vec![0u8; SESSION_CHUNK_MAX + 1],
        }),
    );
    assert!(matches!(
        encode_control(&m),
        Err(WireEncodeError::ChunkTooLarge { .. })
    ));
}

#[test]
fn stream_header_session_data_constructor() {
    let h = StreamHeader::session_data(vec![1, 2, 3]);
    assert_eq!(h.stream_kind(), Some(StreamKind::SessionData));
    assert_eq!(h.ticket, vec![1, 2, 3]);
    assert!(h.host.is_empty());
    assert_eq!(h.port, 0);
}

#[test]
fn attach_mode_unknown_or_unset_is_none_not_rw() {
    // Unknown value.
    let a = SessionAttach {
        mode: 42,
        ..Default::default()
    };
    assert_eq!(a.attach_mode(), None);
    assert!(!a.wants_write());
    // Unset field (proto3 default 0 = ATTACH_MODE_UNSPECIFIED): a client
    // that forgets `mode` must not be granted the writer lease.
    let a = SessionAttach::default();
    assert_eq!(a.mode, 0);
    assert_eq!(a.attach_mode(), None);
    assert!(!a.wants_write());
    // Only an explicit RW asks for the lease.
    let a = SessionAttach {
        mode: AttachMode::Rw as i32,
        ..Default::default()
    };
    assert_eq!(a.attach_mode(), Some(AttachMode::Rw));
    assert!(a.wants_write());
    let a = SessionAttach {
        mode: AttachMode::Ro as i32,
        ..Default::default()
    };
    assert_eq!(a.attach_mode(), Some(AttachMode::Ro));
    assert!(!a.wants_write());
}

#[test]
fn local_capabilities_advertise_exactly_what_is_implemented() {
    assert!(LOCAL_CAPABILITIES.contains(&CAP_EXEC));
    assert!(LOCAL_CAPABILITIES.contains(&CAP_SESSION));
    // Resume is implemented (M2 plan Step 7 (2473c88)): credential redemption,
    // replay from `last_output_seq` with a `Gap` when the ring has
    // moved past it, and input dedup across the reattach. This
    // assertion is the lockstep — flipping it back means the
    // implementation went away.
    assert!(LOCAL_CAPABILITIES.contains(&CAP_RESUME_V1));
    // The host-local dial filter is implemented (ADR-0019 decision 3):
    // `authorize_and_dial_tunnel` honors `StreamHeader.deny_host_local`.
    assert!(LOCAL_CAPABILITIES.contains(&CAP_DIAL_FILTER_V1));
    // The host emulator and its stream carrier exist (ADR-0052 decision 9).
    assert!(LOCAL_CAPABILITIES.contains(&CAP_SCREEN_V1));
    // The datagram carrier and the input copy exist (ADR-0052 decisions 6
    // to 9).
    assert!(LOCAL_CAPABILITIES.contains(&CAP_DATAGRAM_V1));
}

/// A `StreamHeader` encoded by a peer that predates field 5 (no bytes
/// on the wire for it) must decode with `deny_host_local == false` —
/// proto3's own default, and the "unfiltered = today's behavior"
/// meaning ADR-0019 decision 3 relies on (`docs/design/protocol.md`
/// §16.4's additive rule for a new field number on an existing
/// message).
#[test]
fn stream_header_without_field_5_decodes_as_false() {
    // Hand-encoded, not `StreamHeader { deny_host_local: false, .. }.
    // encode_to_vec()`: encoding the new struct and trusting prost to
    // omit a default-valued field is a round-trip of prost's own
    // encoder, not a decode of bytes a pre-ADR-0019 peer actually
    // sends. Building the bytes by hand and asserting no field-5 tag
    // appears in them is the only form this test cannot pass
    // vacuously if a future encoder starts writing field 5 explicitly
    // even for `false`.
    let host = b"example.com";
    let mut old_peer_bytes = vec![
        0x08,
        0x03, // field 1 (kind), varint: TCP_CONNECT = 3
        0x1A,
        host.len() as u8, // field 3 (host), length-delimited
    ];
    old_peer_bytes.extend_from_slice(host);
    old_peer_bytes.extend_from_slice(&[0x20, 0xBB, 0x03]); // field 4 (port) = 443

    const FIELD_5_TAG: u8 = 0x28; // (5 << 3) | 0 (varint wire type)
    assert!(
        !old_peer_bytes.contains(&FIELD_5_TAG),
        "these hand-encoded bytes must carry no field-5 tag at all: {old_peer_bytes:02x?}"
    );

    let decoded = StreamHeader::decode(old_peer_bytes.as_slice())
        .expect("a header with no field 5 bytes must still decode");
    assert_eq!(decoded.kind, StreamKind::TcpConnect as i32);
    assert_eq!(decoded.host, "example.com");
    assert_eq!(decoded.port, 443);
    assert!(!decoded.deny_host_local);
}

/// The shell-command fields (ADR-0051 decision 6, `docs/design/protocol.md`
/// §7.1) are the numbers the `.proto` gives them, and the empty string stays
/// distinct from "no shell command" (`ssh host ''`).
#[test]
fn shell_command_fields_use_their_numbers_and_keep_the_empty_string() {
    // ExecStart.shell_command = 4 (length-delimited): tag 0x22.
    let empty = ExecStart {
        shell_command: Some(String::new()),
        ..ExecStart::default()
    };
    assert_eq!(empty.encode_to_vec(), [0x22, 0x00]);
    assert_eq!(
        ExecStart::decode(&[0x22, 0x00][..]).unwrap().shell_command,
        Some(String::new())
    );
    assert_eq!(ExecStart::default().encode_to_vec(), Vec::<u8>::new());
    // ExecStart.login_shell = 5 (varint): tag 0x28.
    let login = ExecStart {
        login_shell: true,
        ..ExecStart::default()
    };
    assert_eq!(login.encode_to_vec(), [0x28, 0x01]);
    // SessionOpen.shell_command = 7 (length-delimited): tag 0x3A.
    let open = SessionOpen {
        shell_command: Some("ls".into()),
        ..SessionOpen::default()
    };
    assert_eq!(open.encode_to_vec(), [0x3A, 0x02, b'l', b's']);
}

/// A peer that predates field 4/5 of `ExecStart` (and field 7 of
/// `SessionOpen`) skips them as unknown and sees an empty `argv`: that is
/// why a sender must check `shell-command.v1` before setting them, and why
/// the host rejects them from a peer that did not negotiate it
/// (`docs/design/protocol.md` §16.4, ADR-0019 decision 4). `OldExecStart` is
/// the message as the previous release declared it.
#[test]
fn an_old_peer_skips_the_shell_fields_and_sees_an_empty_argv() {
    #[derive(Clone, PartialEq, prost::Message)]
    struct OldExecStart {
        #[prost(string, repeated, tag = "1")]
        argv: Vec<String>,
        #[prost(uint64, tag = "3")]
        timeout_ms: u64,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    struct OldSessionOpen {
        #[prost(string, repeated, tag = "1")]
        argv: Vec<String>,
        #[prost(string, tag = "3")]
        term: String,
    }

    let new = ExecStart {
        shell_command: Some("rm -rf build && make".into()),
        login_shell: true,
        ..ExecStart::default()
    };
    let old = OldExecStart::decode(new.encode_to_vec().as_slice())
        .expect("unknown fields 4 and 5 must not fail the decode");
    assert!(old.argv.is_empty(), "the old host sees no program at all");

    let new = SessionOpen {
        term: "xterm".into(),
        shell_command: Some("top".into()),
        ..SessionOpen::default()
    };
    let old = OldSessionOpen::decode(new.encode_to_vec().as_slice()).unwrap();
    assert!(old.argv.is_empty(), "the old host opens the login shell");
    assert_eq!(old.term, "xterm");

    // The other direction: bytes an old client sends decode with the new
    // fields at their defaults.
    let from_old = OldExecStart {
        argv: vec!["true".into()],
        timeout_ms: 5,
    }
    .encode_to_vec();
    let decoded = ExecStart::decode(from_old.as_slice()).unwrap();
    assert_eq!(decoded.argv, ["true"]);
    assert_eq!((decoded.shell_command, decoded.login_shell), (None, false));
}

#[test]
fn send_priority_band_matches_protocol_md_12() {
    // control 200 > session data 100 > exec 50 > tunnel 0.
    assert_eq!(
        (
            PRIORITY_CONTROL,
            PRIORITY_SESSION_DATA,
            PRIORITY_EXEC_DATA,
            PRIORITY_TUNNEL
        ),
        (200, 100, 50, 0)
    );
    // The ordering itself, not just the values: a later re-tune must
    // keep control above session data above exec above bulk.
    let band = [
        PRIORITY_CONTROL,
        PRIORITY_SESSION_DATA,
        PRIORITY_EXEC_DATA,
        PRIORITY_TUNNEL,
    ];
    assert!(band.windows(2).all(|w| w[0] > w[1]), "band: {band:?}");
}

// ---- error vocabulary ----------------------------------------------

#[test]
fn wire_error_code_uses_error_code_vocabulary_verbatim() {
    for code in ErrorCode::KNOWN {
        let err = Error::from_code(code.clone(), "x");
        assert_eq!(err.code, code.as_str());
        assert_eq!(&err.error_code(), code);
    }
    // The session codes M2 starts producing are part of the shared
    // vocabulary (never ad hoc strings anywhere in the session path).
    for (code, s) in [
        (ErrorCode::SessionNotFound, "SESSION_NOT_FOUND"),
        (ErrorCode::SessionConflict, "SESSION_CONFLICT"),
        (ErrorCode::ResumeGap, "RESUME_GAP"),
    ] {
        assert!(ErrorCode::KNOWN.contains(&code));
        assert_eq!(Error::from_code(code.clone(), "x").code, s);
        assert_eq!(s.parse::<ErrorCode>().unwrap(), code);
    }
    let unknown = Error {
        code: "SOME_FUTURE_CODE".into(),
        message: String::new(),
        retryable: false,
    };
    assert_eq!(
        unknown.error_code(),
        ErrorCode::Unknown("SOME_FUTURE_CODE".into())
    );
}

// ---- golden vectors -------------------------------------------------

/// Checked-in hex frames. Breaking these means the wire format changed:
/// that requires a deliberate `qsh/2` decision, not a test edit.
#[test]
fn golden_hello_frame() {
    // No `reverse` field set: encoding is byte-for-byte identical to
    // the pre-M3 wire format. This is the mechanical proof that adding
    // `Hello.reverse` (M3, filling the tag `Hello` reserved for it) is
    // additive — an old Hello re-encodes to exactly these bytes, field
    // 4 simply never appears when unset. If this assertion ever needs
    // to change, the wire format changed and that requires a
    // deliberate `qsh/2` decision, not a test edit (M3 plan Step 1 (2473c88)).
    let msg = ControlMessage::new(
        1,
        control_message::Body::Hello(Hello {
            versions: vec![0],
            device_name: "hermes".into(),
            capabilities: vec!["exec".into()],
            reverse: None,
        }),
    );
    let wire = encode_control(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "0000001508015211" // frame len 21 | request_id=1 | field 10 (Hello) len 17
            .to_owned()
            + "0a0100" // versions: packed [0]
            + "12066865726d6573" // device_name "hermes"
            + "1a0465786563" // capabilities ["exec"]
    );
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_hello_with_reverse_frame() {
    // New M3 golden: a Hello carrying `reverse` (a target registering
    // itself). Paired with `golden_hello_frame` above — that one pins
    // the additive *absence* of the field, this one pins its
    // *presence*, both as checked-in bytes.
    let msg = ControlMessage::new(
        1,
        control_message::Body::Hello(Hello {
            versions: vec![0],
            device_name: "hermes".into(),
            capabilities: vec!["exec".into()],
            reverse: Some(ReverseRegistration {
                offered_name: "personal-mac".into(),
                capabilities: vec![],
            }),
        }),
    );
    let wire = encode_control(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "0000002508015221" // frame len 37 | request_id=1 | field 10 (Hello) len 33
            .to_owned()
            + "0a0100" // versions: packed [0]
            + "12066865726d6573" // device_name "hermes"
            + "1a0465786563" // capabilities ["exec"]
            + "220e" // field 4 (ReverseRegistration) len 14
            + "0a0c706572736f6e616c2d6d6163" // offered_name "personal-mac" (capabilities empty, omitted)
    );
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

// ---- valid_host_name --------------------------------------------

#[test]
fn valid_host_name_boundary_table() {
    // Empty string: too short.
    assert!(!valid_host_name(""));
    // Exactly 64 bytes: allowed; 65 bytes: refused.
    assert!(valid_host_name(&"a".repeat(64)));
    assert!(!valid_host_name(&"a".repeat(65)));
    // Path-traversal-shaped input: `/` is not in the allowed alphabet,
    // so any name containing it is refused regardless of the dots.
    assert!(!valid_host_name("../"));
    assert!(!valid_host_name("/"));
    // Two bare dots *are* in-alphabet on their own (`.` is allowed) —
    // shape validity does not imply the name is semantically sensible,
    // only that its bytes are in the allowed set and length range.
    assert!(valid_host_name(".."));
    // Unicode: multi-byte characters fall outside the ASCII alphabet.
    assert!(!valid_host_name("café"));
    assert!(!valid_host_name("主机"));
    // Other disallowed separators.
    assert!(!valid_host_name("host/name"));
    assert!(!valid_host_name("host name"));
    assert!(!valid_host_name("host@name"));
    // Every allowed byte, exhaustively.
    for b in (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9') {
        let s = (b as char).to_string();
        assert!(valid_host_name(&s), "byte {b} ({s:?}) should be allowed");
    }
    for c in ['.', '_', '-'] {
        assert!(valid_host_name(&c.to_string()));
    }
}

// ---- valid_forward_id ------------------------------------------------

#[test]
fn valid_forward_id_boundary_table() {
    // Empty: too short.
    assert!(!valid_forward_id(""));
    // Exactly 64 bytes: allowed; 65 bytes: refused.
    assert!(valid_forward_id(&"a".repeat(64)));
    assert!(!valid_forward_id(&"a".repeat(65)));
    // Unlike `valid_host_name`, `.` is *not* in the alphabet — a
    // `forward_id` is an opaque URL-safe token, not a display name.
    assert!(!valid_forward_id("."));
    assert!(!valid_forward_id("fwd.01"));
    // Path-traversal-shaped / separator input stays refused.
    assert!(!valid_forward_id("../"));
    assert!(!valid_forward_id("/"));
    assert!(!valid_forward_id("fwd/id"));
    assert!(!valid_forward_id("fwd id"));
    // Unicode falls outside the ASCII alphabet.
    assert!(!valid_forward_id("café"));
    // Every allowed byte, exhaustively.
    for b in (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9') {
        let s = (b as char).to_string();
        assert!(valid_forward_id(&s), "byte {b} ({s:?}) should be allowed");
    }
    for c in ['_', '-'] {
        assert!(valid_forward_id(&c.to_string()));
    }
    // A realistic-shaped id.
    assert!(valid_forward_id("fwd_01K0EXAMPLE-token"));
    // Control characters and terminal escapes: refused outright, so a
    // caller that shape-checks a peer's `forward_id` at ingress never
    // has to sanitize it afterwards (this check is strictly stronger
    // than `sanitize_peer_text`). These are the shapes that would
    // otherwise reach an operator's terminal through a log line —
    // `crate::wire::sanitize_peer_text`'s own doc names them.
    assert!(!valid_forward_id("a\u{1b}[31mb"));
    assert!(!valid_forward_id("\u{1b}]0;pwned\u{7}"));
    assert!(!valid_forward_id("fwd\nqsh: forged line"));
    assert!(!valid_forward_id("fwd\r-1"));
    assert!(!valid_forward_id("fwd\u{0}-1"));
    assert!(!valid_forward_id("fwd\t1"));
    // A ULID — the shape the host actually mints
    // (`qsh_core::server::Server::handle_rfwd_open`).
    assert!(valid_forward_id("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
}

// ---- validate_device_name ----------------------------------------------

#[test]
fn validate_device_name_boundary_table() {
    // Empty: too short.
    assert_eq!(validate_device_name(""), Err(DeviceNameError::Length));
    // Exactly 64 bytes: allowed; 65 bytes: refused — checked in ASCII
    // (byte count == char count) and in a 3-bytes-per-char script, so
    // the boundary is proven on UTF-8 *byte* length, not char count.
    assert_eq!(validate_device_name(&"a".repeat(64)), Ok(()));
    assert_eq!(
        validate_device_name(&"a".repeat(65)),
        Err(DeviceNameError::Length)
    );
    let hangul_63_bytes = "가".repeat(21);
    let hangul_66_bytes = "가".repeat(22);
    assert_eq!(hangul_63_bytes.len(), 63);
    assert_eq!(hangul_66_bytes.len(), 66);
    assert_eq!(validate_device_name(&hangul_63_bytes), Ok(()));
    assert_eq!(
        validate_device_name(&hangul_66_bytes),
        Err(DeviceNameError::Length)
    );
    // Existing control-character rule (`char::is_control()`, tab
    // included).
    assert_eq!(
        validate_device_name("evil\u{1b}[Kname"),
        Err(DeviceNameError::Control)
    );
    assert_eq!(
        validate_device_name("evil\tname"),
        Err(DeviceNameError::Control)
    );
    // Bidi override/isolate controls — not `char::is_control()`, so
    // they need their own arm.
    assert_eq!(
        validate_device_name("evil\u{202e}name"),
        Err(DeviceNameError::Bidi)
    );
    // Zero-width characters — invisible in a terminal.
    assert_eq!(
        validate_device_name("evil\u{200b}name"),
        Err(DeviceNameError::ZeroWidth)
    );
    assert_eq!(
        validate_device_name("evil\u{feff}name"),
        Err(DeviceNameError::ZeroWidth)
    );
    // Ordinary multi-byte names — Korean, emoji — pass; only the
    // specific code-point classes above are rejected, not
    // "non-ASCII" wholesale (unlike `valid_host_name`).
    assert_eq!(validate_device_name("데이브의 맥북"), Ok(()));
    assert_eq!(validate_device_name("laptop 💻"), Ok(()));
    assert_eq!(validate_device_name("Dave's MacBook Pro"), Ok(()));
}

// ---- sanitize_peer_text ------------------------------------------------

/// A peer's free-form prose must not be able to drive the terminal it
/// is displayed on: escapes, newlines and carriage returns all become
/// `U+FFFD`, tabs and ordinary (including non-ASCII) text survive.
#[test]
fn sanitize_peer_text_neutralizes_terminal_escapes() {
    assert_eq!(sanitize_peer_text(""), "");
    assert_eq!(
        sanitize_peer_text("peer is not allowed"),
        "peer is not allowed"
    );
    assert_eq!(sanitize_peer_text("한글 ok\tkept"), "한글 ok\tkept");
    // A CSI colour run, a forged extra `qsh:` line, and an OSC window
    // retitle — the three shapes a hostile `ConnectResult.message`
    // would reach for.
    assert_eq!(
        sanitize_peer_text("a\u{1b}[31mred\u{1b}[0m\nqsh: forged\r\u{7}"),
        "a\u{FFFD}[31mred\u{FFFD}[0m\u{FFFD}qsh: forged\u{FFFD}\u{FFFD}"
    );
    assert_eq!(
        sanitize_peer_text("\u{1b}]0;pwned\u{7}"),
        "\u{FFFD}]0;pwned\u{FFFD}"
    );
    // Replacement, not deletion: the length in chars is preserved, so
    // the operator can see that something was removed.
    assert_eq!(sanitize_peer_text("\u{1b}\u{1b}\u{1b}").chars().count(), 3);
}

// ---- format_host_port --------------------------------------------------

/// The inverse of the parser's bracket stripping: an IPv6 destination
/// round-trips back to an unambiguous `[addr]:port`, and everything
/// else is left alone.
#[test]
fn format_host_port_brackets_only_ipv6_literals() {
    assert_eq!(format_host_port("db.internal", 5432), "db.internal:5432");
    assert_eq!(format_host_port("127.0.0.1", 5432), "127.0.0.1:5432");
    assert_eq!(format_host_port("localhost", 3000), "localhost:3000");
    assert_eq!(format_host_port("*", 80), "*:80");
    // The whole point: `::1:5432` cannot be split back, `[::1]:5432`
    // can.
    assert_eq!(format_host_port("::1", 5432), "[::1]:5432");
    assert_eq!(format_host_port("::", 80), "[::]:80");
    assert_eq!(format_host_port("2001:db8::1", 443), "[2001:db8::1]:443");
    // IPv4-mapped IPv6 still classifies as IPv6, and must not be
    // confused with the bare IPv4 address.
    assert_eq!(
        format_host_port("::ffff:127.0.0.1", 22),
        "[::ffff:127.0.0.1]:22"
    );
    assert_ne!(
        format_host_port("::ffff:127.0.0.1", 22),
        format_host_port("127.0.0.1", 22)
    );
    // Already bracketed input is not double-bracketed.
    assert_eq!(format_host_port("[::1]", 5432), "[::1]:5432");
    // What a parsed spec's host actually looks like, end to end.
    let spec = parse_forward_spec("8080:[::1]:5432").unwrap();
    assert_eq!(spec.host, "::1");
    assert_eq!(format_host_port(&spec.host, spec.host_port), "[::1]:5432");
}

// ---- parse_forward_spec -----------------------------------------------

#[test]
fn parse_forward_spec_three_part_has_no_bind() {
    let spec = parse_forward_spec("8080:localhost:3000").unwrap();
    assert_eq!(spec.direction, ForwardDirection::Local);
    assert_eq!(spec.bind, None);
    assert_eq!(spec.listen_port, 8080);
    assert_eq!(spec.host, "localhost");
    assert_eq!(spec.host_port, 3000);
}

#[test]
fn parse_forward_spec_four_part_has_bind() {
    let spec = parse_forward_spec("0.0.0.0:8080:localhost:3000").unwrap();
    assert_eq!(spec.bind.as_deref(), Some("0.0.0.0"));
    assert_eq!(spec.listen_port, 8080);
    assert_eq!(spec.host, "localhost");
    assert_eq!(spec.host_port, 3000);
}

#[test]
fn parse_forward_spec_ipv6_bind_brackets() {
    let spec = parse_forward_spec("[::1]:8080:localhost:3000").unwrap();
    assert_eq!(spec.bind.as_deref(), Some("::1"));
    assert_eq!(spec.listen_port, 8080);
    assert_eq!(spec.host, "localhost");
    assert_eq!(spec.host_port, 3000);
}

#[test]
fn parse_forward_spec_ipv6_host_brackets_without_bind() {
    // Three logical parts even though the host segment is bracketed:
    // token *count* (not bracket presence) decides bind-vs-no-bind.
    let spec = parse_forward_spec("8080:[::1]:3000").unwrap();
    assert_eq!(spec.bind, None);
    assert_eq!(spec.listen_port, 8080);
    assert_eq!(spec.host, "::1");
    assert_eq!(spec.host_port, 3000);
}

#[test]
fn parse_forward_spec_ipv6_bind_and_host_brackets() {
    let spec = parse_forward_spec("[::1]:8080:[::2]:3000").unwrap();
    assert_eq!(spec.bind.as_deref(), Some("::1"));
    assert_eq!(spec.host, "::2");
}

#[test]
fn parse_forward_spec_rejects_port_zero_and_65536() {
    for spec in ["0:localhost:3000", "8080:localhost:0"] {
        assert_eq!(
            parse_forward_spec(spec).unwrap_err().error_code(),
            ErrorCode::InvalidArgument,
            "spec {spec:?}"
        );
    }
    for spec in ["65536:localhost:3000", "8080:localhost:65536"] {
        assert_eq!(
            parse_forward_spec(spec).unwrap_err().error_code(),
            ErrorCode::InvalidArgument,
            "spec {spec:?}"
        );
    }
    // The boundary values immediately on either side of the rejected
    // ones are accepted.
    assert!(parse_forward_spec("1:localhost:65535").is_ok());
}

#[test]
fn parse_forward_spec_rejects_empty_host() {
    for spec in ["8080::3000", "8080:[]:3000", ":8080:localhost:3000"] {
        assert_eq!(
            parse_forward_spec(spec).unwrap_err().error_code(),
            ErrorCode::InvalidArgument,
            "spec {spec:?}"
        );
    }
}

#[test]
fn parse_forward_spec_accepts_non_loopback_bind_shape_only() {
    // The parser knows no policy: a non-loopback bind is shape-valid.
    // Loopback-only enforcement is host-side (M4 plan §4.1 #5 (2473c88),
    // implemented in a later milestone step, not here).
    let spec = parse_forward_spec("0.0.0.0:8080:localhost:3000").unwrap();
    assert_eq!(spec.bind.as_deref(), Some("0.0.0.0"));
    let spec = parse_forward_spec("203.0.113.5:8080:localhost:3000").unwrap();
    assert_eq!(spec.bind.as_deref(), Some("203.0.113.5"));
}

#[test]
fn parse_forward_spec_rejects_garbage() {
    for spec in [
        "",
        "garbage",
        "8080",
        "8080:localhost",
        "a:b:8080:localhost:3000",
        "8080:localhost:3000:extra",
        "8080:localhost:3000:",
        ":",
        "[::1:8080:localhost:3000",
        "[]:8080:localhost:3000",
        "8080:localhost:abc",
        "abc:localhost:3000",
        "[8080]:localhost:3000",
        "8080:local host:3000",
    ] {
        assert_eq!(
            parse_forward_spec(spec).unwrap_err().error_code(),
            ErrorCode::InvalidArgument,
            "spec {spec:?} should be rejected"
        );
    }
}

#[test]
fn parse_forward_spec_direction_defaults_local_caller_sets_remote() {
    let spec = parse_forward_spec("8080:localhost:3000").unwrap();
    assert_eq!(spec.direction, ForwardDirection::Local);
    let spec = ForwardSpec {
        direction: ForwardDirection::Remote,
        ..spec
    };
    assert_eq!(spec.direction, ForwardDirection::Remote);
}

// ---- parse_dynamic_spec (ADR-0019 decision 11) -------------------------

#[test]
fn parse_dynamic_spec_table() {
    // (spec, expected bind, expected port) for the accepted cases.
    let ok_cases: &[(&str, Option<&str>, u16)] = &[
        ("1080", None, 1080),
        ("127.0.0.1:1080", Some("127.0.0.1"), 1080),
        ("[::1]:1080", Some("::1"), 1080),
        ("localhost:1080", Some("localhost"), 1080),
        ("1", None, 1),
        ("65535", None, 65535),
    ];
    for (spec, bind, port) in ok_cases {
        let parsed = parse_dynamic_spec(spec)
            .unwrap_or_else(|e| panic!("spec {spec:?} should parse, got {e:?}"));
        assert_eq!(parsed.bind.as_deref(), *bind, "spec {spec:?}");
        assert_eq!(parsed.listen_port, *port, "spec {spec:?}");
    }

    let err_cases = [
        "",
        "0",
        "65536",
        "garbage",
        "127.0.0.1:8080:1080",
        "[1080]",
        "8080:",
        ":8080",
        "[::1:1080",
    ];
    for spec in err_cases {
        assert_eq!(
            parse_dynamic_spec(spec).unwrap_err().error_code(),
            ErrorCode::InvalidArgument,
            "spec {spec:?} should be rejected"
        );
    }
}

#[test]
fn golden_exec_exit_frame() {
    let msg = ExecFrame::exec_exit(7, None);
    let wire = encode_exec_frame(&msg).unwrap();
    assert_eq!(hex(&wire), "000000042a020807");
    let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
    dec.push(&wire);
    let back: ExecFrame = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_error_response_frame() {
    let msg = ControlMessage::error(2, Error::new(ErrorCode::PermissionDenied, "no", false));
    let wire = encode_control(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "0000001d08025a197a17" // frame len 29 | request_id=2 | Response(len 25) | Error(len 23)
            .to_owned()
            + "0a115045524d495353494f4e5f44454e494544" // code
            + "12026e6f" // message "no"
    );
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_session_open_frame() {
    let msg = ControlMessage::new(
        3,
        control_message::Body::SessionOpen(SessionOpen {
            argv: vec!["claude".into()],
            env: Default::default(),
            term: "xterm-256color".into(),
            cols: 120,
            rows: 40,
            user: Some("dave".into()),
            shell_command: None,
            screen: None,
            agent_channel: Vec::new(),
        }),
    );
    let wire = encode_control(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "000000270803a20122" // frame len 39 | request_id=3 | field 20 (SessionOpen) len 34
            .to_owned()
            + "0a06636c61756465" // argv ["claude"]
            + "1a0e787465726d2d323536636f6c6f72" // term "xterm-256color"
            + "2078" // cols 120
            + "2828" // rows 40
            + "320464617665" // user "dave"
    );
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_session_output_frame() {
    // Output{sequence: 49, data: "Hello\r\n"} — the CLI.md §6.4 example
    // (7 bytes after `--after 42` → cumulative offset 49).
    let msg = SessionFrame::output(49, b"Hello\r\n".to_vec());
    let wire = encode_session_frame(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "0000000d0a0b" // frame len 13 | field 1 (Output) len 11
            .to_owned()
            + "0831" // sequence 49
            + "120748656c6c6f0d0a" // data "Hello\r\n"
    );
    let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
    dec.push(&wire);
    let back: SessionFrame = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_session_closed_event_frame() {
    let msg = ControlMessage::new(
        0,
        control_message::Body::SessionEvent(SessionEvent::closed("01K0SESSION", "closed", 180)),
    );
    let wire = encode_control(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "0000001de2031a" // frame len 29 | (request_id 0 omitted) | field 60 (SessionEvent) len 26
            .to_owned()
            + "0a0b30314b3053455353494f4e" // session_id "01K0SESSION"
            + "220b" // field 4 (Closed) len 11
            + "0a06636c6f736564" // reason "closed"
            + "10b401" // seq 180
    );
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn exec_start_env_map_roundtrips() {
    let mut env = HashMap::new();
    env.insert("A".to_string(), "1".to_string());
    env.insert("B".to_string(), "2".to_string());
    let msg = ControlMessage::new(
        9,
        control_message::Body::ExecStart(ExecStart {
            argv: vec!["sh".into(), "-c".into(), "true".into()],
            env,
            timeout_ms: 1500,
            login_shell: false,
            shell_command: None,
            agent_channel: Vec::new(),
        }),
    );
    roundtrip_via_frame(&msg, CONTROL_FRAME_MAX);
}

// ---- golden vectors: M4 tags 40/41/4 realized (mechanical proof the
// realization is additive — the golden tests above for Hello, the
// plain error Response, SessionOpen and the SessionEvent-carrying
// ControlMessage are unchanged by this file's edits and still pass
// byte-for-byte, since none of them touch tags 40/41/4; these four are
// the new tags' own golden vectors) --------------------------------

#[test]
fn golden_remote_forward_open_frame() {
    let msg = ControlMessage::new(
        4,
        control_message::Body::RfwdOpen(RemoteForwardOpen {
            bind_host: "0.0.0.0".into(),
            bind_port: 8080,
            forward_host: "localhost".into(),
            forward_port: 3000,
            claim_token: Vec::new(),
        }),
    );
    let wire = encode_control(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "0000001f0804c2021a" // frame len 31 | request_id=4 | field 40 (rfwd_open) len 26
            .to_owned()
            + "0a07302e302e302e30" // bind_host "0.0.0.0"
            + "10903f" // bind_port 8080
            + "1a096c6f63616c686f7374" // forward_host "localhost"
            + "20b817" // forward_port 3000
    );
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_remote_forward_close_frame() {
    let msg = ControlMessage::new(
        5,
        control_message::Body::RfwdClose(RemoteForwardClose {
            forward_id: "fwd_01K0EXAMPLE".into(),
        }),
    );
    let wire = encode_control(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "000000160805ca0211" // frame len 22 | request_id=5 | field 41 (rfwd_close) len 17
            .to_owned()
            + "0a0f6677645f30314b304558414d504c45" // forward_id "fwd_01K0EXAMPLE"
    );
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_remote_forward_opened_response_frame() {
    let msg = ControlMessage::response(
        6,
        response::Body::RfwdOpened(RemoteForwardOpened {
            forward_id: "fwd_01K0EXAMPLE".into(),
            actual_port: 8080,
        }),
    );
    let wire = encode_control(&msg).unwrap();
    assert_eq!(
        hex(&wire),
        "0000001a08065a16" // frame len 26 | request_id=6 | field 11 (Response) len 22
            .to_owned()
            + "2214" // field 4 (rfwd_opened) len 20
            + "0a0f6677645f30314b304558414d504c45" // forward_id "fwd_01K0EXAMPLE"
            + "10903f" // actual_port 8080
    );
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_connect_result_ok_frame() {
    let msg = ConnectResult {
        ok: true,
        code: String::new(),
        message: String::new(),
    };
    let wire = encode_framed(&msg, DATA_FRAME_MAX).unwrap();
    assert_eq!(
        hex(&wire),
        "00000002" // frame len 2
            .to_owned()
            + "0801" // ok = true
    );
    let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
    dec.push(&wire);
    let back: ConnectResult = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn golden_connect_result_err_frame() {
    let msg = ConnectResult {
        ok: false,
        code: "CONNECTION_FAILED".into(),
        message: "dial refused".into(),
    };
    let wire = encode_framed(&msg, DATA_FRAME_MAX).unwrap();
    assert_eq!(
        hex(&wire),
        "00000021" // frame len 33 | `ok` omitted (proto3 default false)
            .to_owned()
            + "1211434f4e4e454354494f4e5f4641494c4544" // code "CONNECTION_FAILED"
            + "1a0c6469616c2072656675736564" // message "dial refused"
    );
    let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
    dec.push(&wire);
    let back: ConnectResult = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back, msg);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn file_constants_match_adr_0029() {
    assert_eq!(FILE_CHUNK_MAX, 32 * 1024);
    assert_eq!(FILE_LIST_PAGE_MAX, 512);
    assert_eq!(FILE_LIST_DIR_MAX, 65536);
    assert_eq!(FILE_WRITE_FREE_RESERVE, 256 * 1024 * 1024);
    // A chunk plus its frame overhead fits one data frame.
    const { assert!(FILE_CHUNK_MAX + 64 <= DATA_FRAME_MAX) };
}

/// `file.v1` is advertised by every build: the host data plane exists on unix
/// and on Windows (ADR-0029 decision 23, ADR-0035 decision 26), and the set
/// is the same on both, so a Windows build's `Hello` carries it too.
#[test]
fn windows_build_advertises_file_v1() {
    assert_eq!(CAP_FILE_V1, "file.v1");
    assert!(LOCAL_CAPABILITIES.contains(&CAP_FILE_V1));
    // Appended after the four that predate it, so the golden list only grows.
    assert_eq!(LOCAL_CAPABILITIES[4], CAP_FILE_V1);
    // `shell-command.v1` joined after it (ADR-0051 decision 6).
    assert_eq!(
        LOCAL_CAPABILITIES,
        [
            CAP_EXEC,
            CAP_SESSION,
            CAP_RESUME_V1,
            CAP_DIAL_FILTER_V1,
            CAP_FILE_V1,
            CAP_SHELL_COMMAND_V1,
            CAP_SCREEN_V1,
            CAP_DATAGRAM_V1,
            CAP_SCREEN_ECHO_V1,
            CAP_PUNCH_V1,
            CAP_AGENT_V1,
            CAP_JUMP_V1,
        ]
    );
}

#[test]
fn file_op_numbers_are_the_adr_numbers() {
    use control_message::Body;
    let tag = |m: &ControlMessage| {
        // Field 1 is request_id (varint), the oneof body follows as a
        // length-delimited field; read its field number from the first
        // tag after request_id.
        let bytes = m.encode_to_vec();
        let mut i = 0;
        // request_id key + value (request_id < 128 in these samples)
        assert_eq!(bytes[i] >> 3, 1);
        i += 2;
        let mut key = 0u64;
        let mut shift = 0;
        loop {
            let b = bytes[i];
            i += 1;
            key |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        key >> 3
    };
    let sample = |body| ControlMessage::new(1, body);
    assert_eq!(
        tag(&sample(Body::FileReadOpen(FileReadOpen::default()))),
        80
    );
    assert_eq!(
        tag(&sample(Body::FileWriteOpen(FileWriteOpen::default()))),
        81
    );
    assert_eq!(
        tag(&sample(Body::FileListOpen(FileListOpen::default()))),
        82
    );
    assert_eq!(
        tag(&sample(Body::FileMkdirOpen(FileMkdirOpen::default()))),
        83
    );
    assert_eq!(StreamKind::FileData as i32, 5);
}

#[test]
fn file_stream_header_constructor_sets_the_kind() {
    let h = StreamHeader::file_data(vec![1, 2, 3]);
    assert_eq!(h.stream_kind(), Some(StreamKind::FileData));
    assert_eq!(h.ticket, vec![1, 2, 3]);
    assert!(h.host.is_empty() && h.port == 0 && !h.deny_host_local);
}

#[test]
fn file_frame_data_at_the_cap_encodes_and_over_the_cap_is_refused() {
    let at_cap = FileFrame::data(vec![0u8; FILE_CHUNK_MAX]);
    assert!(at_cap.validate().is_ok());
    encode_file_frame(&at_cap).unwrap();

    let over = FileFrame::data(vec![0u8; FILE_CHUNK_MAX + 1]);
    assert_eq!(
        over.validate(),
        Err(ChunkTooLarge {
            len: FILE_CHUNK_MAX + 1,
            max: FILE_CHUNK_MAX
        })
    );
    // The chunk cap is tighter than the frame cap: this frame would fit
    // DATA_FRAME_MAX and is still refused.
    const { assert!(FILE_CHUNK_MAX + 1 < DATA_FRAME_MAX) };
    assert!(matches!(
        encode_file_frame(&over),
        Err(WireEncodeError::ChunkTooLarge(_))
    ));
    // Non-data frames carry no chunk.
    assert!(FileFrame::end(1, vec![0; 32]).validate().is_ok());
    assert!(FileFrame::result(true, "", "", false).validate().is_ok());
    assert!(FileFrame { body: None }.validate().is_ok());
}

/// A full `file.list` page of maximum-length names plus the response
/// envelope fits one control frame (ADR-0029 decision 9).
#[test]
fn a_full_file_list_page_of_255_byte_names_fits_a_control_frame() {
    let entries = (0..FILE_LIST_PAGE_MAX)
        .map(|i| FileEntry {
            name: format!("{i:0>255}"),
            kind: FileKind::File as i32,
            size: u64::MAX,
            mode: u32::MAX,
            mtime: i64::MIN,
        })
        .collect();
    let msg = ControlMessage::response(
        u64::MAX,
        response::Body::FileListed(FileListed {
            kind: FileKind::Dir as i32,
            size: u64::MAX,
            mode: u32::MAX,
            mtime: i64::MIN,
            entries,
            more: true,
            unlistable: u32::MAX,
        }),
    );
    let wire = encode_control(&msg).unwrap();
    assert!(wire.len() <= CONTROL_FRAME_MAX + 4);
}

/// Every `FileWriteOpen` field survives encode and decode.
#[test]
fn file_write_open_survives_a_frame_roundtrip_field_by_field() {
    let open = FileWriteOpen {
        path: "~/in/x".into(),
        size: 7,
        mode: 0o640,
        overwrite: true,
        name_if_dir: "x".into(),
        preserve: true,
        mtime: -5,
        user: "dave".into(),
    };
    let wire = encode_control(&ControlMessage::new(
        9,
        control_message::Body::FileWriteOpen(open.clone()),
    ))
    .unwrap();
    let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
    dec.push(&wire);
    let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(back.request_id, 9);
    assert_eq!(back.body, Some(control_message::Body::FileWriteOpen(open)));
}

#[test]
fn screen_history_batches_keep_order_fit_the_cap_and_carry_skipped_last() {
    let lines: Vec<String> = (0..2000)
        .map(|i| format!("line {i:05} {}", "x".repeat(60)))
        .collect();
    let (batches, oversize) = ScreenHistory::batches(&lines, 7);
    assert_eq!(oversize, 0);
    assert!(batches.len() > 1);
    let mut seen = Vec::new();
    for (i, b) in batches.iter().enumerate() {
        b.validate().unwrap();
        SessionFrame::screen_history(b.clone()).validate().unwrap();
        assert_eq!(b.skipped != 0, i + 1 == batches.len());
        seen.extend(
            b.lines
                .iter()
                .map(|l| String::from_utf8(l.clone()).unwrap()),
        );
    }
    assert_eq!(seen, lines);
    assert_eq!(batches.last().unwrap().skipped, 7);
}

#[test]
fn screen_history_batches_count_a_line_too_big_for_a_frame() {
    let lines = vec![
        "a".to_string(),
        "b".repeat(SESSION_CHUNK_MAX),
        "c".to_string(),
    ];
    let (batches, oversize) = ScreenHistory::batches(&lines, 2);
    assert_eq!(oversize, 1);
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].lines, vec![b"a".to_vec(), b"c".to_vec()]);
    assert_eq!(batches[0].skipped, 3);
    assert!(ScreenHistory::batches(&[], 0).0.is_empty());
}

#[test]
fn a_screen_history_frame_over_the_chunk_cap_is_rejected() {
    let h = ScreenHistory {
        lines: vec![vec![b'x'; SESSION_CHUNK_MAX + 1]],
        skipped: 0,
    };
    assert!(SessionFrame::screen_history(h).validate().is_err());
}

#[test]
fn screen_echo_round_trips_on_session_frame_10_and_datagram_kind_13() {
    use prost::Message;
    for tty in [
        TtyEcho::Unknown,
        TtyEcho::Kernel,
        TtyEcho::App,
        TtyEcho::Secret,
    ] {
        let echo = ScreenEcho {
            state_num: 7,
            input_seq: 1 << 40,
            tty: tty as i32,
        };
        let frame = SessionFrame::screen_echo(echo);
        assert_eq!(frame.validate(), Ok(()));
        let bytes = frame.encode_to_vec();
        // field 10, length-delimited: tag 0x52.
        assert_eq!(bytes[0], 0x52);
        let back = SessionFrame::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, frame);
        assert_eq!(echo.tty_echo(), tty);
    }
    assert_eq!(TtyEcho::Unknown as i32, 0);
    assert_eq!(TtyEcho::Kernel as i32, 1);
    assert_eq!(TtyEcho::App as i32, 2);
    assert_eq!(TtyEcho::Secret as i32, 3);
    let dg = crate::datagram::DatagramFrame {
        channel: crate::datagram::ChannelId([3; 16]),
        kind: crate::datagram::DatagramKind::ScreenEcho,
        payload: ScreenEcho::default().encode_to_vec(),
    };
    assert_eq!(dg.encode()[crate::datagram::CHANNEL_ID_LEN], 13);
    assert_eq!(crate::datagram::DatagramFrame::decode(&dg.encode()), Ok(dg));
}

#[test]
fn screen_echo_validation_and_order() {
    let e = |state_num, input_seq| ScreenEcho {
        state_num,
        input_seq,
        tty: 0,
    };
    assert_eq!(e(1, 10).validate_against_sent(10), Ok(()));
    assert_eq!(
        e(1, 11).validate_against_sent(10),
        Err(EchoBeyondSent {
            input_seq: 11,
            sent: 10
        })
    );
    // An unknown tty value reads as UNKNOWN rather than failing the decode.
    assert_eq!(
        ScreenEcho { tty: 99, ..e(0, 0) }.tty_echo(),
        TtyEcho::Unknown
    );
    assert!(e(2, 0).is_newer_than(&e(1, 99)));
    assert!(e(2, 5).is_newer_than(&e(2, 4)));
    assert!(!e(2, 5).is_newer_than(&e(2, 5)));
    assert!(!e(1, 9).is_newer_than(&e(2, 0)));
}

#[test]
fn screen_echo_is_advertised_by_every_build() {
    assert!(LOCAL_CAPABILITIES.contains(&CAP_SCREEN_ECHO_V1));
    assert_eq!(CAP_SCREEN_ECHO_V1, "screen-echo.v1");
}

// -- agent.v1 (ADR-0055 decision 3) --

#[test]
fn agent_v1_numbers_are_the_adr_numbers() {
    assert_eq!(CAP_AGENT_V1, "agent.v1");
    assert!(LOCAL_CAPABILITIES.contains(&CAP_AGENT_V1));
    assert_eq!(AGENT_CHANNEL_LEN, 16);
    assert_eq!(StreamKind::Agent as i32, 6);
    assert_eq!(AgentGrant::Unspecified as i32, 0);
    assert_eq!(AgentGrant::Forwarded as i32, 1);
    assert_eq!(AgentGrant::Denied as i32, 2);
    assert_eq!(AgentGrant::Unavailable as i32, 3);
    assert_eq!(AgentGrant::NoSocket as i32, 4);

    // Field numbers: the tag byte is `number << 3 | wire type` and the value
    // follows. A 16-byte channel is `tag 0x10 <16 bytes>`.
    let ch = vec![0xab; AGENT_CHANNEL_LEN];
    let tail = |bytes: Vec<u8>| bytes[bytes.len() - 18..].to_vec();
    let want = |tag: u8| [vec![tag, 0x10], ch.clone()].concat();
    let open = SessionOpen {
        agent_channel: ch.clone(),
        ..Default::default()
    };
    assert_eq!(tail(open.encode_to_vec()), want(0x4a)); // field 9
    let attach = SessionAttach {
        agent_channel: ch.clone(),
        ..Default::default()
    };
    assert_eq!(tail(attach.encode_to_vec()), want(0x3a)); // field 7
    let exec = ExecStart {
        agent_channel: ch.clone(),
        ..Default::default()
    };
    assert_eq!(tail(exec.encode_to_vec()), want(0x32)); // field 6
    // Grants are varints: field 7, 9 and 3, value 3 (`UNAVAILABLE`).
    let g = AgentGrant::Unavailable as i32;
    let opened = SessionOpened {
        agent: g,
        ..Default::default()
    };
    assert_eq!(opened.encode_to_vec(), [0x38, 3]);
    let attached = SessionAttached {
        agent: g,
        ..Default::default()
    };
    assert_eq!(attached.encode_to_vec(), [0x48, 3]);
    let started = ExecStarted {
        agent: g,
        ..Default::default()
    };
    assert_eq!(started.encode_to_vec(), [0x18, 3]);
    // The header ticket of an `AGENT` stream is the channel itself.
    let header = StreamHeader {
        kind: StreamKind::Agent as i32,
        ticket: ch.clone(),
        ..Default::default()
    };
    assert_eq!(header.stream_kind(), Some(StreamKind::Agent));
    assert_eq!(
        decode_msg::<StreamHeader>(&header.encode_to_vec()).unwrap(),
        header
    );
}

/// DoD 13: a request that does not ask for agent forwarding encodes to the
/// bytes it had before `agent.v1` existed. Pinned against golden bytes
/// written from the pre-`agent.v1` schema.
#[test]
fn no_agent_field_without_dash_a() {
    let open = SessionOpen {
        argv: vec!["sh".into()],
        term: "xterm".into(),
        cols: 80,
        rows: 24,
        ..Default::default()
    };
    assert_eq!(hex(&open.encode_to_vec()), "0a0273681a05787465726d20502818");
    let attach = SessionAttach {
        session_id: "S".into(),
        resume_token: vec![1, 2],
        mode: AttachMode::Rw as i32,
        ..Default::default()
    };
    assert_eq!(hex(&attach.encode_to_vec()), "0a0153120201022001");
    let exec = ExecStart {
        argv: vec!["id".into()],
        timeout_ms: 5,
        ..Default::default()
    };
    assert_eq!(hex(&exec.encode_to_vec()), "0a0269641805");
    // The same holds for the responses of a request that asked for nothing.
    let opened = SessionOpened {
        session_id: "S".into(),
        ..Default::default()
    };
    assert_eq!(hex(&opened.encode_to_vec()), "0a0153");
    let started = ExecStarted {
        exec_id: "E".into(),
        ..Default::default()
    };
    assert_eq!(hex(&started.encode_to_vec()), "0a0145");
}

#[test]
fn agent_grant_unknown_values_are_kept_raw_and_read_as_unspecified() {
    let started = ExecStarted {
        agent: 99,
        ..Default::default()
    };
    let back = decode_msg::<ExecStarted>(&started.encode_to_vec()).unwrap();
    assert_eq!(back.agent, 99);
    assert_eq!(
        AgentGrant::try_from(back.agent).unwrap_or(AgentGrant::Unspecified),
        AgentGrant::Unspecified
    );
}

/// The checked-in fuzz seeds for the new fields decode to what their names
/// say (DoD 12), so a schema edit that breaks them fails here and not only
/// in the nightly fuzz run.
#[test]
fn agent_fuzz_seeds_decode_to_the_new_fields() {
    use control_message::Body;
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/corpus");
    let read = |target: &str, name: &str| {
        std::fs::read(format!("{root}/{target}/{name}")).expect("fuzz seed")
    };
    let control = |name: &str| decode_msg::<ControlMessage>(&read("decode_control", name)).unwrap();
    let response = |name: &str| match control(name).body {
        Some(Body::Response(Response { body: Some(b) })) => b,
        other => panic!("{name}: {other:?}"),
    };

    let Some(Body::SessionOpen(o)) = control("session_open_agent").body else {
        panic!("session_open_agent")
    };
    assert_eq!(o.agent_channel.len(), AGENT_CHANNEL_LEN);
    let Some(Body::SessionOpen(o)) = control("session_open_agent_bad_len").body else {
        panic!("session_open_agent_bad_len")
    };
    assert_ne!(o.agent_channel.len(), AGENT_CHANNEL_LEN);
    let Some(Body::SessionAttach(a)) = control("session_attach_agent").body else {
        panic!("session_attach_agent")
    };
    assert_eq!(a.agent_channel.len(), AGENT_CHANNEL_LEN);
    let Some(Body::ExecStart(e)) = control("exec_start_agent").body else {
        panic!("exec_start_agent")
    };
    assert_eq!(e.agent_channel.len(), AGENT_CHANNEL_LEN);

    let response::Body::SessionOpened(o) = response("session_opened_agent_grant") else {
        panic!()
    };
    assert_eq!(o.agent, AgentGrant::Unavailable as i32);
    let response::Body::SessionAttached(a) = response("session_attached_agent_grant") else {
        panic!()
    };
    assert_eq!(a.agent, AgentGrant::NoSocket as i32);
    let response::Body::ExecStarted(e) = response("exec_started_agent_grant") else {
        panic!()
    };
    assert_eq!(e.agent, AgentGrant::Denied as i32);
    let response::Body::ExecStarted(e) = response("exec_started_agent_grant_unknown") else {
        panic!()
    };
    assert_eq!(e.agent, 99);

    let header = decode_msg::<StreamHeader>(&read("decode_stream_header", "agent")).unwrap();
    assert_eq!(header.stream_kind(), Some(StreamKind::Agent));
    assert_eq!(header.ticket.len(), AGENT_CHANNEL_LEN);
    let short =
        decode_msg::<StreamHeader>(&read("decode_stream_header", "agent_short_ticket")).unwrap();
    assert_eq!(short.stream_kind(), Some(StreamKind::Agent));
    assert_ne!(short.ticket.len(), AGENT_CHANNEL_LEN);
}

/// Without `-J` the bytes of every request that exists today are what they
/// were before `jump.v1`: the new `StreamKind` value and datagram kind are
/// opt-in, and no existing message gained a field (ADR-0056 decision 3,
/// DoD 25.17). Golden bytes written from the pre-`jump.v1` schema.
#[test]
fn no_jump_stream_without_dash_j() {
    let open = SessionOpen {
        argv: vec!["sh".into()],
        term: "xterm".into(),
        cols: 80,
        rows: 24,
        ..Default::default()
    };
    assert_eq!(hex(&open.encode_to_vec()), "0a0273681a05787465726d20502818");
    let exec = ExecStart {
        argv: vec!["id".into()],
        timeout_ms: 5,
        ..Default::default()
    };
    assert_eq!(hex(&exec.encode_to_vec()), "0a0269641805");
    assert_eq!(
        hex(&StreamHeader::session_data(vec![1, 2]).encode_to_vec()),
        "080112020102"
    );
    assert_eq!(
        hex(&StreamHeader::exec_data(vec![9]).encode_to_vec()),
        "0802120109"
    );
    assert_eq!(
        hex(&StreamHeader {
            kind: StreamKind::TcpConnect as i32,
            ticket: vec![],
            host: "h".into(),
            port: 80,
            deny_host_local: false,
        }
        .encode_to_vec()),
        "08031a01682050"
    );
    assert_eq!(StreamKind::Jump as i32, 7);
}

#[test]
fn jump_stream_header_round_trips_with_golden_bytes() {
    let channel = [0xb0u8; crate::jump::JUMP_CHANNEL_LEN];
    let header = StreamHeader::jump(channel, "h".into(), 80);
    let bytes = header.encode_to_vec();
    assert_eq!(
        hex(&bytes),
        format!("08071210{}1a01682050", "b0".repeat(16))
    );
    let back = decode_msg::<StreamHeader>(&bytes).unwrap();
    assert_eq!(back, header);
    assert_eq!(back.stream_kind(), Some(StreamKind::Jump));
    assert_eq!(back.jump_channel(), Some(channel));
    assert_eq!((back.host.as_str(), back.port), ("h", 80));
}

/// The ticket of a `JUMP` header is exactly 16 bytes (ADR-0056 decision 3);
/// anything else, and any other kind, reads no channel.
#[test]
fn jump_ticket_must_be_exactly_sixteen_bytes() {
    for len in [0usize, 1, 15, 17, 32, 64] {
        let header = StreamHeader {
            kind: StreamKind::Jump as i32,
            ticket: vec![7; len],
            host: "h".into(),
            port: 80,
            deny_host_local: false,
        };
        assert_eq!(header.jump_channel(), None, "len {len}");
    }
    let header = StreamHeader {
        kind: StreamKind::Jump as i32,
        ticket: vec![7; 16],
        ..Default::default()
    };
    assert_eq!(header.jump_channel(), Some([7; 16]));
    let agent = StreamHeader {
        kind: StreamKind::Agent as i32,
        ticket: vec![7; 16],
        ..Default::default()
    };
    assert_eq!(agent.jump_channel(), None);
}

#[test]
fn jump_fuzz_seeds_decode_to_what_their_names_say() {
    use crate::datagram::{DatagramError, DatagramFrame, DatagramKind};
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/corpus");
    let read = |target: &str, name: &str| {
        std::fs::read(format!("{root}/{target}/{name}")).expect("fuzz seed")
    };
    let header =
        |name: &str| decode_msg::<StreamHeader>(&read("decode_stream_header", name)).unwrap();
    let ok = header("jump");
    assert_eq!(ok.stream_kind(), Some(StreamKind::Jump));
    assert!(ok.jump_channel().is_some());
    assert_eq!((ok.host.as_str(), ok.port), ("10.0.0.7", 4433));
    let short = header("jump_short_ticket");
    assert_eq!(short.stream_kind(), Some(StreamKind::Jump));
    assert_eq!(short.jump_channel(), None);
    assert_eq!(header("jump_port_zero").port, 0);

    let frame = |name: &str| read("decode_datagram_frame", name);
    let packet = DatagramFrame::decode(&frame("jump_packet")).unwrap();
    assert_eq!(packet.kind, DatagramKind::JumpPacket);
    assert_eq!(packet.payload.len(), 14);
    let empty = DatagramFrame::decode(&frame("jump_packet_empty")).unwrap();
    assert_eq!(empty.kind, DatagramKind::JumpPacket);
    assert!(empty.payload.is_empty());
    assert_eq!(
        DatagramFrame::decode(&frame("unknown_kind_15")),
        Err(DatagramError::UnknownKind(15))
    );
}

/// `jump.v1` is advertised by every build, as the last entry (ADR-0056
/// decision 3): the intermediate peer exists, and a capability string is a
/// promise about behaviour.
#[test]
fn jump_v1_is_advertised_last() {
    assert_eq!(CAP_JUMP_V1, "jump.v1");
    assert_eq!(LOCAL_CAPABILITIES.last(), Some(&CAP_JUMP_V1));
    assert_eq!(
        LOCAL_CAPABILITIES
            .iter()
            .filter(|c| **c == CAP_JUMP_V1)
            .count(),
        1
    );
}
