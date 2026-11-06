//! L3 loopback tests for screen state sync on the stream carrier (ADR-0052
//! decisions 1, 6, 9 and 11; M22 DoD 18-3, 18-4, 18-9, 18-12). Pipe-backed
//! sessions, so the same tests run on Linux, macOS and Windows (the host
//! emulator is fed from the pipe exactly as it is fed from a PTY or ConPTY).
//!
//! The real `qsh` CLI does not request screen sync yet; these tests drive
//! the client plumbing (`Session::screen_request`, `ClientScreen`,
//! `Attached::send_screen_ack`) directly.

use std::time::Duration;

use qsh_core::broker::{PipeHandle, SessionBackend, SessionId};
use qsh_core::client::screen::{ClientScreen, ScreenOutcome};
use qsh_core::client::{AttachEvent, Attached, Session};
use qsh_proto::wire::{self, ControlMessage, control_message, response};
use qsh_testkit::loopback::LoopbackHarness;

pub(crate) const DEADLINE: Duration = Duration::from_secs(60);

pub(crate) fn open_req(session: &Session) -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        screen: session.screen_request(80, 24, Some(0xdddddd), Some(0x101010)),
        ..Default::default()
    }
}

/// Open a session (asking for screen sync when the peer allows it) and
/// redeem its first data stream.
pub(crate) async fn open_attached(
    h: &LoopbackHarness,
    s: &mut Session,
    req: wire::SessionOpen,
) -> (wire::SessionOpened, PipeHandle, Attached) {
    let opened = s.session_open(req).await.expect("session.open");
    let pipe = h.pipes.take().expect("pipe handle");
    let attached = s
        .open_attach_stream(wire::SessionAttached {
            ticket: opened.ticket.clone(),
            screen_channel: opened.screen_channel.clone(),
            ..Default::default()
        })
        .await
        .expect("data stream");
    (opened, pipe, attached)
}

/// The host emulator's current state hash and number (`None` without one).
pub(crate) fn host_state(h: &LoopbackHarness, id: &str) -> Option<([u8; 8], u64)> {
    let u = SessionBackend::screen_update_since(&*h.broker, &SessionId(id.to_string()), 0)?;
    Some((u.state_hash, u.new_num))
}

pub(crate) async fn wait_ring_end(h: &LoopbackHarness, id: &str, end: u64) {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let info = SessionBackend::get(&*h.broker, &SessionId(id.to_string())).unwrap();
            if info.last_sequence >= end {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("host consumed the output");
}

/// Read events, applying screen updates and acking them, until the client
/// holds the host's current state. Returns the count of `Output` events seen.
pub(crate) async fn converge(
    h: &LoopbackHarness,
    id: &str,
    att: &mut Attached,
    screen: &mut ClientScreen,
) -> usize {
    let mut outputs = 0;
    tokio::time::timeout(DEADLINE, async {
        loop {
            if let Some((hash, num)) = host_state(h, id)
                && screen.num() == num
                && screen.hash() == Some(hash)
            {
                return;
            }
            match att.next().await.expect("event").expect("stream open") {
                AttachEvent::Screen(part) => {
                    let outcome = screen.on_part(&part).expect("part");
                    if let Some(n) = outcome.ack() {
                        att.send_screen_ack(n).await.expect("ack");
                    }
                }
                AttachEvent::ScreenDatagram(part) => {
                    let outcome = screen.on_datagram_part(&part);
                    if let Some(n) = outcome.ack() {
                        att.send_screen_ack(n).await.expect("ack");
                    }
                }
                AttachEvent::Output { .. } => outputs += 1,
                _ => {}
            }
        }
    })
    .await
    .expect("client converges on the host's state");
    outputs
}

#[tokio::test(flavor = "multi_thread")]
async fn screen_sync_on_stream_carrier_converges_without_datagram() {
    let h = LoopbackHarness::start().await;
    h.server.hide_capabilities(&[wire::CAP_DATAGRAM_V1]);
    let mut s = h.session().await;
    assert!(s.screen_supported());
    assert!(
        !s.capabilities.iter().any(|c| c == "datagram.v1"),
        "a host without datagram.v1 negotiates none"
    );
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    assert_eq!(opened.screen_channel.len(), 16, "host accepted screen sync");

    let text = b"\x1b[2J\x1b[Hhello \x1b[1;31mworld\x1b[0m\r\nline two";
    pipe.write_output(text).await.unwrap();
    wait_ring_end(&h, &opened.session_id, text.len() as u64).await;
    let mut screen = ClientScreen::new();
    let outputs = converge(&h, &opened.session_id, &mut att, &mut screen).await;
    assert_eq!(outputs, 0, "a screen-sync attach carries no Output");
    let state = screen.state().unwrap();
    assert_eq!(&*state.grid[0].cells[0].text, "h");
    assert_eq!(&*state.grid[1].cells[0].text, "l");
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn new_client_with_old_host_stays_on_the_byte_path() {
    let h = LoopbackHarness::start().await;
    h.server.hide_capabilities(&[wire::CAP_SCREEN_V1]);
    let mut s = h.session().await;
    assert!(!s.screen_supported());
    assert!(s.screen_request(80, 24, None, None).is_none());
    // Even a caller that builds the field itself cannot send it.
    let mut req = open_req(&s);
    req.screen = Some(wire::ScreenRequest {
        cols: 80,
        rows: 24,
        fg: None,
        bg: None,
    });
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    assert!(opened.screen_channel.is_empty());

    let payload: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
    pipe.write_output(&payload).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(DEADLINE, async {
        while got.len() < payload.len() {
            match att.next().await.unwrap().unwrap() {
                AttachEvent::Output { data, .. } => got.extend_from_slice(&data),
                AttachEvent::Screen(_) => panic!("old host sent a ScreenUpdate"),
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(got, payload, "Output bytes are the bytes written");
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn old_client_with_new_host_never_gets_a_screen_update() {
    let h = LoopbackHarness::start().await;
    let dialed = h.dialer.dial(h.addr, "127.0.0.1").await.expect("dial");
    let mut s = Session::negotiate_hiding(dialed.connection, "laptop", &[wire::CAP_SCREEN_V1])
        .await
        .expect("negotiate");
    assert!(!s.screen_supported());
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    assert!(opened.screen_channel.is_empty());
    pipe.write_output(b"plain bytes").await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(DEADLINE, async {
        while got.len() < 11 {
            match att.next().await.unwrap().unwrap() {
                AttachEvent::Output { data, .. } => got.extend_from_slice(&data),
                AttachEvent::Screen(_) => panic!("host sent a ScreenUpdate to an old client"),
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(got, b"plain bytes");
    s.close();
    h.shutdown().await;
}

/// A peer that did not advertise `screen.v1` but sends the request field
/// anyway is ignored: the session is a plain one and the reply says so.
#[tokio::test(flavor = "multi_thread")]
async fn host_ignores_a_screen_request_from_a_peer_without_the_capability() {
    let h = LoopbackHarness::start().await;
    let dialed = h.dialer.dial(h.addr, "127.0.0.1").await.expect("dial");
    let hello = wire::Hello {
        versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
        device_name: "laptop".into(),
        capabilities: wire::LOCAL_CAPABILITIES
            .iter()
            .filter(|c| **c != wire::CAP_SCREEN_V1)
            .map(|c| c.to_string())
            .collect(),
        reverse: None,
    };
    let (_ctl_conn, mut ctl) = {
        let (ctl, _peer) = qsh_core::handshake::initiate(&dialed.connection, hello)
            .await
            .expect("hello");
        (dialed.connection.clone(), ctl)
    };
    let req = wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        screen: Some(wire::ScreenRequest {
            cols: 80,
            rows: 24,
            fg: None,
            bg: None,
        }),
        ..Default::default()
    };
    ctl.send
        .send(&ControlMessage::new(
            1,
            control_message::Body::SessionOpen(req),
        ))
        .await
        .unwrap();
    let reply = ctl.recv.recv::<ControlMessage>().await.unwrap().unwrap();
    let Some(control_message::Body::Response(resp)) = reply.body else {
        panic!("expected a response");
    };
    let Some(response::Body::SessionOpened(opened)) = resp.body else {
        panic!("expected SessionOpened, got {resp:?}");
    };
    assert!(opened.screen_channel.is_empty());
    let _pipe = h.pipes.take().unwrap();
    assert!(
        host_state(&h, &opened.session_id).is_none(),
        "no emulator was started for the session"
    );
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reattach_sends_one_screen_not_the_backlog() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, mut pipe, att) = open_attached(&h, &mut s, req).await;
    // Detach.
    drop(att);

    // 10 MB of scrolling output while nobody is attached, ending with a
    // distinctive screen. Queries inside it must never reach the client
    // (ADR-0048): the host emulator answers them, the client never sees
    // the bytes.
    let mut chunk = Vec::new();
    for i in 0..200 {
        chunk.extend_from_slice(format!("backlog line {i:04} 0123456789abcdef\r\n").as_bytes());
    }
    let total: usize = 10 * 1024 * 1024;
    let mut written = 0usize;
    while written < total {
        pipe.write_output(&chunk).await.unwrap();
        written += chunk.len();
    }
    let tail = b"\x1b[c\x1b[6n\x1b]11;?\x07\x1b[2J\x1b[Hfinal screen";
    pipe.write_output(tail).await.unwrap();
    written += tail.len();
    wait_ring_end(&h, &opened.session_id, written as u64).await;

    let attached = s
        .attach_request(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
            screen: s.screen_request(80, 24, None, None),
        })
        .await
        .expect("session.attach");
    assert_eq!(attached.screen_channel.len(), 16);
    assert_eq!(
        attached.replay_from, attached.output_end,
        "a screen attach replays nothing"
    );
    let mut att = s.open_attach_stream(attached).await.expect("data stream");

    // Bytes up to the first applied update: every frame is a screen part,
    // never Output.
    let mut screen = ClientScreen::new();
    let mut first_update_bytes = 0usize;
    tokio::time::timeout(DEADLINE, async {
        loop {
            match att.next().await.unwrap().unwrap() {
                AttachEvent::Screen(part) => {
                    first_update_bytes += part.data.len();
                    let outcome = screen.on_part(&part).unwrap();
                    if matches!(outcome, ScreenOutcome::Applied { .. }) {
                        return;
                    }
                }
                AttachEvent::Output { .. } => {
                    panic!("Output (the backlog or a replayed query) reached the client")
                }
                AttachEvent::ScreenHistory(_) => {
                    panic!("history that scrolled off while detached was replayed")
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    // One screen of 24x80 is far below this bound; the backlog is 10 MB.
    let one_screen_bound = 24 * 80 * 40;
    assert!(
        first_update_bytes <= one_screen_bound,
        "{first_update_bytes} bytes to the first update"
    );
    // The screen the client holds is the host's state, with the final text.
    let (hash, num) = host_state(&h, &opened.session_id).unwrap();
    assert_eq!(screen.hash(), Some(hash));
    assert_eq!(screen.num(), num);
    let first_row: String = screen.state().unwrap().grid[0]
        .cells
        .iter()
        .map(|c| if c.text.is_empty() { " " } else { &*c.text })
        .collect();
    assert!(first_row.starts_with("final screen"), "{first_row:?}");

    // The host emulator answered the replayed queries into the PTY input.
    let answers = tokio::time::timeout(DEADLINE, pipe.read_input(64))
        .await
        .unwrap()
        .unwrap();
    assert!(
        answers.starts_with(b"\x1b["),
        "the host answered the terminal queries: {answers:?}"
    );
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_carrier_skips_intermediate_states_under_a_slow_reader() {
    let h = LoopbackHarness::start().await;
    h.server.hide_capabilities(&[wire::CAP_DATAGRAM_V1]);
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;

    // Each write is one complete, distinct screen.
    const FRAMES: usize = 2000;
    let producer = tokio::spawn(async move {
        for k in 0..FRAMES {
            let frame = format!("\x1b[H\x1b[2Jframe {k:05} {}", "x".repeat(200));
            pipe.write_output(frame.as_bytes()).await.unwrap();
        }
        pipe
    });
    let mut screen = ClientScreen::new();
    // A slow reader: it applies and acks, but lags behind the producer.
    let mut seen = 0usize;
    tokio::time::timeout(DEADLINE, async {
        while seen < 3 || !producer.is_finished() {
            if let AttachEvent::Screen(part) = att.next().await.unwrap().unwrap()
                && let Some(n) = screen.on_part(&part).unwrap().ack()
            {
                seen += 1;
                att.send_screen_ack(n).await.unwrap();
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
        }
    })
    .await
    .unwrap();
    let _pipe = producer.await.unwrap();
    converge(&h, &opened.session_id, &mut att, &mut screen).await;
    assert!(
        (screen.applied_updates() as usize) < FRAMES,
        "applied {} updates for {FRAMES} screens produced",
        screen.applied_updates()
    );
    let first_row: String = screen.state().unwrap().grid[0]
        .cells
        .iter()
        .map(|c| if c.text.is_empty() { " " } else { &*c.text })
        .collect();
    assert!(
        first_row.starts_with(&format!("frame {:05}", FRAMES - 1)),
        "the final screen is the last one produced: {first_row:?}"
    );
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_screen_request_gets_a_base_zero_update() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    pipe.write_output(b"first").await.unwrap();
    wait_ring_end(&h, &opened.session_id, 5).await;
    let mut screen = ClientScreen::new();
    converge(&h, &opened.session_id, &mut att, &mut screen).await;
    let applied_before = screen.applied_updates();

    // The client lost faith in its copy: it asks for the full screen, then
    // output continues.
    att.send_screen_ack(0).await.unwrap();
    pipe.write_output(b" second").await.unwrap();
    wait_ring_end(&h, &opened.session_id, 12).await;
    let mut saw_base_zero = false;
    tokio::time::timeout(DEADLINE, async {
        loop {
            let (part, datagram) = match att.next().await.unwrap().unwrap() {
                AttachEvent::Screen(part) => (part, false),
                AttachEvent::ScreenDatagram(part) => (part, true),
                _ => continue,
            };
            // `base_num` is the first varint of the encoded update; 0 is a
            // single zero byte.
            let is_base_zero = part.part == 0 && part.data.first() == Some(&0);
            let outcome = if datagram {
                screen.on_datagram_part(&part)
            } else {
                screen.on_part(&part).unwrap()
            };
            if let Some(n) = outcome.ack() {
                att.send_screen_ack(n).await.unwrap();
            }
            // A full screen applies even though the client was far ahead of 0.
            if matches!(outcome, ScreenOutcome::Applied { .. }) && is_base_zero {
                saw_base_zero = true;
            }
            let (hash, num) = host_state(&h, &opened.session_id).unwrap();
            if screen.num() == num && screen.hash() == Some(hash) && saw_base_zero {
                return;
            }
        }
    })
    .await
    .unwrap();
    assert!(screen.applied_updates() > applied_before);
    s.close();
    h.shutdown().await;
}

// ---------------------------------------------------------------------
// History (ADR-0052 decision 10, protocol.md §18.10)
// ---------------------------------------------------------------------

/// What `ScreenHistory` frames delivered so far.
#[derive(Default)]
struct Collected {
    lines: Vec<String>,
    /// The `skipped` count of every frame, in arrival order, with the
    /// number of lines already collected when it arrived.
    skipped: Vec<(usize, u64)>,
}

impl Collected {
    fn skipped_total(&self) -> u64 {
        self.skipped.iter().map(|(_, n)| *n).sum()
    }
}

/// Read events (acking screen updates) until `done` holds for what the
/// stream delivered.
async fn collect_history(
    att: &mut Attached,
    screen: &mut ClientScreen,
    done: impl Fn(&Collected) -> bool,
) -> Collected {
    let mut got = Collected::default();
    tokio::time::timeout(DEADLINE, async {
        while !done(&got) {
            match att.next().await.expect("event").expect("stream open") {
                AttachEvent::Screen(part) => {
                    if let Some(n) = screen.on_part(&part).expect("part").ack() {
                        att.send_screen_ack(n).await.expect("ack");
                    }
                }
                AttachEvent::ScreenHistory(h) => {
                    for l in &h.lines {
                        got.lines
                            .push(String::from_utf8(l.clone()).expect("utf-8 line"));
                    }
                    if h.skipped > 0 {
                        got.skipped.push((got.lines.len(), h.skipped));
                    }
                }
                AttachEvent::Output { .. } => panic!("a screen-sync attach carries no Output"),
                _ => {}
            }
        }
    })
    .await
    .expect("history arrives");
    got
}

/// `n` numbered lines, each ended by CR LF.
fn numbered(prefix: &str, n: usize) -> Vec<u8> {
    (0..n)
        .flat_map(|i| format!("{prefix}{i:04}\r\n").into_bytes())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn rows_that_scroll_off_arrive_once_and_in_order() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (_opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    // 80 lines through a 24-row screen: the cursor ends on row 23 after
    // 23 of them fit, so 80 - 23 = 57 rows scrolled off, the first being
    // line 0.
    pipe.write_output(&numbered("H", 80)).await.unwrap();
    let got = collect_history(&mut att, &mut screen, |g| g.lines.len() >= 57).await;
    let want: Vec<String> = (0..57).map(|i| format!("H{i:04}")).collect();
    assert_eq!(
        got.lines
            .iter()
            .map(|l| l.trim_end().to_string())
            .collect::<Vec<_>>(),
        want
    );
    assert!(got.skipped.is_empty(), "nothing was behind");

    // Nothing more arrives while the screen only changes in place.
    pipe.write_output(b"\x1b[Hno scroll").await.unwrap();
    let more = tokio::time::timeout(
        Duration::from_millis(300),
        collect_history(&mut att, &mut screen, |g| !g.lines.is_empty()),
    )
    .await;
    assert!(more.is_err(), "rows are sent once");
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_alternate_screen_adds_no_history() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (_opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    let mut out = b"\x1b[?1049h".to_vec();
    out.extend(numbered("ALT", 100));
    out.extend_from_slice(b"\x1b[?1049l\x1b[2J\x1b[H");
    out.extend(numbered("P", 30));
    pipe.write_output(&out).await.unwrap();
    // 30 lines on the restored screen: 30 - 23 = 7 rows scrolled off.
    let got = collect_history(&mut att, &mut screen, |g| g.lines.len() >= 7).await;
    let texts: Vec<_> = got.lines.iter().map(|l| l.trim_end().to_string()).collect();
    assert_eq!(
        texts,
        (0..7).map(|i| format!("P{i:04}")).collect::<Vec<_>>()
    );
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flood_is_reported_as_a_skipped_count_not_dropped_silently() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (_opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    // Far more rows than the history keeps (5000) in a few big writes.
    const ROWS: usize = 40_000;
    let chunk = vec![b'\n'; 16 * 1024];
    let mut written = 0;
    while written < ROWS {
        pipe.write_output(&chunk).await.unwrap();
        written += chunk.len();
    }
    // The cursor is on the last row after 23 line feeds; every one after
    // that scrolls a row off.
    let scrolled = (written - 23) as u64;
    let got = collect_history(&mut att, &mut screen, |g| {
        g.lines.len() as u64 + g.skipped_total() >= scrolled
    })
    .await;
    assert_eq!(
        got.lines.len() as u64 + got.skipped_total(),
        scrolled,
        "every row is either delivered or counted"
    );
    assert!(got.skipped_total() > 0, "a flood is reported as skipped");
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reattach_does_not_replay_history_that_was_already_sent() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    pipe.write_output(&numbered("H", 40)).await.unwrap();
    let first = collect_history(&mut att, &mut screen, |g| g.lines.len() >= 17).await;
    assert_eq!(first.lines.len(), 17);
    drop(att);

    // Rows that scroll off while nobody is attached are not queued for the
    // next attach either; only the screen is.
    pipe.write_output(&numbered("D", 40)).await.unwrap();
    wait_ring_end(&h, &opened.session_id, 40 * 7 * 2).await;
    let attached = s
        .attach_request(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
            screen: s.screen_request(80, 24, None, None),
        })
        .await
        .expect("session.attach");
    let mut att = s.open_attach_stream(attached).await.expect("data stream");
    let mut screen = ClientScreen::new();
    let replayed = tokio::time::timeout(
        Duration::from_millis(500),
        collect_history(&mut att, &mut screen, |g| {
            !g.lines.is_empty() || !g.skipped.is_empty()
        }),
    )
    .await;
    assert!(replayed.is_err(), "reattach sent history");
    assert!(screen.state().is_some(), "the screen did arrive");

    // New rows after the attach flow again.
    pipe.write_output(&numbered("N", 30)).await.unwrap();
    let got = collect_history(&mut att, &mut screen, |g| g.lines.len() >= 7).await;
    assert!(got.lines[0].starts_with('N') || got.lines[0].starts_with('D'));
    s.close();
    h.shutdown().await;
}

/// Follow-up to the stream carrier step (ADR-0052 decision 6): the host
/// holds updates back while more than 128 KiB of screen data sit unwritten.
///
/// Host flow-control simulation: the client attaches and then reads nothing,
/// so QUIC flow control (the 2 MiB stream window) stops the host's writer
/// and the send queue behind it fills. A producer paints hundreds of
/// distinct, large screens meanwhile. With the gate the host stops queueing
/// at its 128 KiB cap, so what reaches the client in the end is the window
/// plus about the cap plus the catch-up screen (measured: 23 updates, 2.37
/// MB). With `has_room` forced true the same run sends 125 updates and 3.14
/// MB, because the pump then queues behind the writer up to the frame
/// queue's 64 parts of 16 KiB.
#[tokio::test(flavor = "multi_thread")]
async fn the_send_depth_gate_defers_updates_while_the_client_does_not_read() {
    /// The stream's receive window (`TUNNEL_STREAM_RECEIVE_WINDOW`).
    const STREAM_WINDOW: usize = 2 * 1024 * 1024;
    const SEND_DEPTH_CAP: usize = 128 * 1024;
    const FRAMES: usize = 300;
    const COLS: usize = 300;
    const ROWS: usize = 100;

    let h = LoopbackHarness::start().await;
    h.server.hide_capabilities(&[wire::CAP_DATAGRAM_V1]);
    let mut s = h.session().await;
    // A large screen makes each full-screen update about 100 KiB, so the
    // window fills after a couple of dozen of them.
    let mut req = open_req(&s);
    req.cols = COLS as u32;
    req.rows = ROWS as u32;
    req.screen = s.screen_request(COLS as u16, ROWS as u16, Some(0xdddddd), Some(0x101010));
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;

    // Every cell of a screen differs from the same cell of the previous
    // screen, in colour and in character, so each diff is a full screen.
    let screens: Vec<Vec<u8>> = (0..FRAMES)
        .map(|k| {
            let mut out = b"\x1b[H".to_vec();
            for row in 0..ROWS {
                for col in 0..COLS {
                    let colour = 16 + (k * 7 + row * 3 + col) % 200;
                    let ch = char::from(b'!' + ((k + row + col) % 90) as u8);
                    out.extend_from_slice(format!("\x1b[38;5;{colour}m{ch}").as_bytes());
                }
            }
            out
        })
        .collect();
    let total_output: usize = screens.iter().map(Vec::len).sum();
    for screen in &screens {
        pipe.write_output(screen).await.unwrap();
    }
    wait_ring_end(&h, &opened.session_id, total_output as u64).await;

    // Now read everything the host sends until the client holds its state.
    let mut screen = ClientScreen::new();
    let mut part_bytes = 0usize;
    tokio::time::timeout(DEADLINE, async {
        loop {
            if let Some((hash, num)) = host_state(&h, &opened.session_id)
                && screen.num() == num
                && screen.hash() == Some(hash)
            {
                return;
            }
            if let AttachEvent::Screen(part) = att.next().await.unwrap().unwrap() {
                part_bytes += part.data.len();
                if let Some(n) = screen.on_part(&part).unwrap().ack() {
                    att.send_screen_ack(n).await.unwrap();
                }
            }
        }
    })
    .await
    .expect("client converges on the host's state");

    // One full-screen update is about 100 KiB; allow the initial screen, the
    // catch-up and the one that was being queued when the gate shut.
    let bound = STREAM_WINDOW + SEND_DEPTH_CAP + 4 * 128 * 1024;
    eprintln!(
        "send-depth gate: {part_bytes} bytes in {} updates for {FRAMES} screens",
        screen.applied_updates()
    );
    assert!(
        part_bytes <= bound,
        "{part_bytes} screen bytes reached the client, more than window + gate ({bound}): \
         the host kept queueing while the writer was blocked"
    );
    assert!(
        (screen.applied_updates() as usize) < FRAMES / 4,
        "applied {} updates for {FRAMES} screens produced",
        screen.applied_updates()
    );
    s.close();
    h.shutdown().await;
}
