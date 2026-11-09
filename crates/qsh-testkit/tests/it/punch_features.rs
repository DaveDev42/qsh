//! ADR-0054 DoD 9: the features work over a punched connection, in netsim.
//!
//! Every test uses `punch_route::world` with a pin of B that carries no
//! address and no direct listener, so the only way A reaches B is the punch
//! through R. Each one asserts that a punch really happened (R recorded the
//! `punch.request`) before it looks at the feature itself:
//!
//! - an interactive screen-sync attach with local echo prediction (M23,
//!   ADR-0053) over a 200 ms round trip: the keys appear on the local
//!   terminal long before the host could have echoed them, underlined, and
//!   the screen ends up exactly the host's;
//! - `exec`;
//! - a plain `-L` tunnel carrying a payload through to an echo server on B's
//!   machine;
//! - `qsh cp` of one file.
//!
//! The clocks are real (R and B use `std` time), so the bounds are real
//! time. Nothing here prints PTY contents; a failure reports lengths and
//! the screen rows of the shell this test itself started.

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use qsh_core::screen::{HostScreen, ScreenOptions};
use qsh_core::{CancelToken, Ops, Predict, ScreenAttach, ScreenSync, SilentObserver, StatusLine};
use qsh_proto::event::SessionEvent;
use qsh_proto::screen::cell_flags;
use qsh_proto::{EnvVar, FileCopyReq, SessionAttachReq, SessionOpenReq, TunnelOpenReq};
use qsh_testkit::net_probe::free_port;
use qsh_testkit::shell::pty_shell;
use qsh_testkit::tunnel::EchoServer;

use super::punch_route::{World, WorldOptions, exec, punched, world};

const COLS: u16 = 80;
const ROWS: u16 = 24;
const PROMPT: &str = "PRM>";

/// A hang is a failure, not a flake.
const LIMIT: Duration = Duration::from_secs(60);

/// B reachable only by a punch.
fn punch_only() -> WorldOptions {
    WorldOptions {
        direct_listener: false,
        pin_b_address: false,
        ..WorldOptions::default()
    }
}

async fn blocking_scenario<T: Send + 'static>(
    what: &'static str,
    body: impl FnOnce() -> T + Send + 'static,
) -> T {
    match tokio::time::timeout(LIMIT, tokio::task::spawn_blocking(body)).await {
        Ok(joined) => joined.expect("scenario thread panicked"),
        Err(_) => panic!("{what} did not finish within {LIMIT:?}"),
    }
}

/// R recorded `dials` punch requests: one per connection the command made.
fn assert_punched(w: &World, dials: usize) {
    assert_eq!(
        w.punch_requests(),
        dials,
        "each connection came from a punch through R"
    );
}

// ---------------------------------------------------------------------------
// exec
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn exec_runs_over_a_punched_connection() {
    let w = world(punch_only()).await;
    let out = exec(&w.a.ops, "b").await.expect("exec over the punch");
    assert!(punched(&out), "exit {}", out.data.remote_exit_code);
    assert_punched(&w, 1);
    w.shutdown().await;
}

// ---------------------------------------------------------------------------
// -L
// ---------------------------------------------------------------------------

/// One round trip through the `-L` listener: write `payload`, half-close,
/// read the echo to the end.
fn echo_through(listen_port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], listen_port)),
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut writer = stream.try_clone()?;
    let data = payload.to_vec();
    let writing = std::thread::spawn(move || {
        writer.write_all(&data)?;
        writer.shutdown(Shutdown::Write)
    });
    let mut got = Vec::new();
    stream.read_to_end(&mut got)?;
    writing.join().expect("writer thread")?;
    Ok(got)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_forward_carries_bytes_over_a_punched_connection() {
    let echo = EchoServer::start().await.expect("echo server");
    let echo_port = echo.port();
    let w = world(punch_only()).await;
    let ops = w.a.ops.clone();
    let listen_port = free_port();
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let got = blocking_scenario("the -L tunnel", move || {
        let hold = ops
            .tunnel_open(TunnelOpenReq {
                host: "b".into(),
                mode: "local".into(),
                bind: None,
                listen_port: u32::from(listen_port),
                forward_host: "127.0.0.1".into(),
                forward_port: u32::from(echo_port),
                wait_ms: None,
                supervise_ms: None,
                accept_hold_ms: None,
            })
            .expect("open the -L tunnel over the punch");
        let got = echo_through(listen_port, &payload).expect("a round trip through -L");
        hold.close();
        got
    })
    .await;
    assert_eq!(got.len(), expected.len(), "truncated or padded");
    assert!(got == expected, "the echo came back different");
    assert_punched(&w, 1);
    w.shutdown().await;
}

// ---------------------------------------------------------------------------
// qsh cp
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cp_copies_a_file_over_a_punched_connection() {
    let w = world(punch_only()).await;
    let ops = w.a.ops.clone();
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.bin");
    let target = dir.path().join("target.bin");
    let bytes: Vec<u8> = (0..300 * 1024).map(|i| (i % 253) as u8).collect();
    std::fs::write(&source, &bytes).expect("write the source");
    let req = FileCopyReq {
        sources: vec![source.to_string_lossy().into_owned()],
        // Bracketed, because on a Windows client a bare `b:` is a drive.
        destination: format!("[b]:{}", target.display()),
        recursive: false,
        preserve: false,
        no_clobber: false,
    };
    let data = blocking_scenario("qsh cp", move || {
        ops.file_copy(req, Arc::new(SilentObserver), &CancelToken::new())
    })
    .await
    .unwrap_or_else(|err| panic!("cp over the punch: {err:?}"));
    assert_eq!(data.direction, "put");
    assert_eq!(data.files, 1, "{data:?}");
    assert_eq!(data.bytes, bytes.len() as u64);
    assert!(
        std::fs::read(&target).expect("the copy") == bytes,
        "the copy differs from the source"
    );
    assert_punched(&w, 1);
    w.shutdown().await;
}

// ---------------------------------------------------------------------------
// screen sync with prediction
// ---------------------------------------------------------------------------

/// The local terminal: whatever the attach writes to it lands here.
struct LocalTerminal {
    screen: HostScreen,
    bytes: u64,
}

impl LocalTerminal {
    fn new() -> Self {
        Self {
            screen: HostScreen::new(ScreenOptions {
                rows: ROWS,
                cols: COLS,
                ..ScreenOptions::default()
            }),
            bytes: 0,
        }
    }

    fn feed(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::Output { data_b64, .. } => {
                let data = base64::engine::general_purpose::STANDARD
                    .decode(data_b64.as_bytes())
                    .expect("output is Base64");
                self.bytes += data.len() as u64;
                self.screen.feed(&data, self.bytes);
            }
            end @ (SessionEvent::Exit { .. } | SessionEvent::Closed { .. }) => {
                panic!("the session ended: {end:?}")
            }
            _ => {}
        }
    }

    fn rows(&self) -> Vec<String> {
        self.screen
            .snapshot()
            .grid
            .iter()
            .map(|row| {
                row.cells
                    .iter()
                    .map(|c| if c.text.is_empty() { " " } else { &*c.text })
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn shows_bare_prompt(&self) -> bool {
        self.rows().iter().any(|row| row == PROMPT)
    }

    /// The index of the row that is the prompt followed by `typed`.
    fn typed_row(&self, typed: &str) -> Option<usize> {
        let want = format!("{PROMPT} {typed}");
        self.rows().iter().position(|r| *r == want)
    }

    fn flags_at(&self, row: usize, col: usize) -> u8 {
        self.screen.snapshot().grid[row].cells[col].flags
    }

    fn any_underline(&self) -> bool {
        self.screen
            .snapshot()
            .grid
            .iter()
            .flat_map(|r| &r.cells)
            .any(|c| c.flags & cell_flags::UNDERLINE != 0 && !c.text.is_empty() && &*c.text != " ")
    }
}

fn shell_request() -> SessionOpenReq {
    SessionOpenReq {
        host: "b".to_string(),
        argv: pty_shell(),
        env: vec![
            EnvVar {
                name: "LANG".into(),
                value: "C".into(),
            },
            EnvVar {
                name: "PS1".into(),
                value: format!("{PROMPT} "),
            },
            EnvVar {
                name: "PROMPT".into(),
                value: format!("{PROMPT}$S"),
            },
        ],
        term: Some("xterm-256color".into()),
        cols: Some(u32::from(COLS)),
        rows: Some(u32::from(ROWS)),
        user: None,
        shell_command: None,
    }
}

/// Feeds events from the attach's thread until `done` holds or `timeout`
/// passes.
fn until(
    events: &mpsc::Receiver<Result<SessionEvent, String>>,
    term: &mut LocalTerminal,
    timeout: Duration,
    done: impl Fn(&LocalTerminal) -> bool,
) -> bool {
    let limit = Instant::now() + timeout;
    loop {
        if done(term) {
            return true;
        }
        let left = limit.saturating_duration_since(Instant::now());
        match events.recv_timeout(left) {
            Ok(event) => term.feed(event.unwrap_or_else(|err| panic!("the attach failed: {err}"))),
            Err(mpsc::RecvTimeoutError::Timeout) => return done(term),
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("the attach ended"),
        }
    }
}

/// What the typing measured.
struct Typing {
    latencies: Vec<Duration>,
    underlined_on_sight: usize,
}

fn type_with_prediction(ops: &Ops) -> Typing {
    let attach = Some(ScreenAttach {
        mode: ScreenSync::On,
        cols: COLS,
        rows: ROWS,
        predict: Predict::Always,
        status_line: StatusLine::Off,
        escape: None,
    });
    let opened = ops
        .session_open_interactive(shell_request(), false, attach)
        .expect("open the screen-sync session over the punch");
    let mut stream = ops
        .session_attach_screen(
            SessionAttachReq {
                session_ref: opened.session_ref,
                no_steal: false,
            },
            &[],
            attach,
        )
        .expect("attach over the punch");
    assert!(stream.screen_sync(), "the host granted screen sync");
    assert_eq!(stream.predict_unavailable(), None, "the attach can predict");
    let handle = stream.handle();
    let (tx, events) = mpsc::channel();
    std::thread::spawn(move || {
        while let Some(event) = stream.next_event() {
            if tx.send(event.map_err(|e| e.to_string())).is_err() {
                break;
            }
        }
    });

    let mut term = LocalTerminal::new();
    let wait = Duration::from_secs(30);
    assert!(
        until(&events, &mut term, wait, LocalTerminal::shows_bare_prompt),
        "no prompt on the local terminal: {:?}",
        term.rows()
    );
    // The first key is typed alone: its confirmation opens the epoch, so
    // every key after it is drawn at once.
    handle.write(b"q".to_vec()).expect("write");
    assert!(
        until(&events, &mut term, wait, |t| t.typed_row("q").is_some()),
        "the first key never showed: {:?}",
        term.rows()
    );
    until(&events, &mut term, Duration::from_millis(600), |_| false);

    let mut typed = String::from("q");
    let mut out = Typing {
        latencies: Vec::new(),
        underlined_on_sight: 0,
    };
    for i in 0..10u8 {
        let key = char::from(b'a' + i);
        typed.push(key);
        let sent = Instant::now();
        handle.write(vec![key as u8]).expect("write");
        let shown = until(&events, &mut term, wait, |t| t.typed_row(&typed).is_some());
        assert!(shown, "key {i} never showed: {:?}", term.rows());
        out.latencies.push(sent.elapsed());
        if let Some(row) = term.typed_row(&typed) {
            let col = PROMPT.len() + 1 + typed.len() - 1;
            if term.flags_at(row, col) & cell_flags::UNDERLINE != 0 {
                out.underlined_on_sight += 1;
            }
        }
        until(&events, &mut term, Duration::from_millis(25), |_| false);
    }
    // Everything is judged: the local terminal is the host's screen.
    assert!(
        until(&events, &mut term, wait, |t| {
            t.typed_row(&typed).is_some() && !t.any_underline()
        }),
        "the screen never settled to the host's: {:?}",
        term.rows()
    );
    let _ = handle.detach();
    out
}

/// 100 ms each way between A and B: a key the host echoes takes at least
/// 200 ms to come back, so a glyph on the local terminal sooner is the
/// prediction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_screen_sync_attach_predicts_keys_over_a_punched_connection() {
    let w = world(WorldOptions {
        a_b_delay: Duration::from_millis(100),
        ..punch_only()
    })
    .await;
    let ops = w.a.ops.clone();
    let typing =
        blocking_scenario("the predicted typing", move || type_with_prediction(&ops)).await;
    let mut sorted = typing.latencies.clone();
    sorted.sort();
    eprintln!(
        "RTT 200 ms over a punch, 10 keys: min {:?} median {:?} max {:?}, underlined on sight {}",
        sorted[0],
        sorted[sorted.len() / 2],
        sorted[sorted.len() - 1],
        typing.underlined_on_sight
    );
    assert!(
        sorted[sorted.len() - 1] < Duration::from_millis(150),
        "a key took {:?}, as long as a round trip: {:?}",
        sorted[sorted.len() - 1],
        typing.latencies
    );
    assert_eq!(
        typing.underlined_on_sight,
        typing.latencies.len(),
        "a prediction the host has not confirmed is underlined"
    );
    assert_punched(&w, 2);
    w.shutdown().await;
}

/// The session does not need a prediction to be right: with prediction off
/// the same typing waits for the host, and the attach is still screen sync.
/// (A control for the test above: its bound is a real prediction, not a fast
/// link.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_prediction_a_key_waits_for_the_host_over_the_same_punch() {
    let w = world(WorldOptions {
        a_b_delay: Duration::from_millis(100),
        ..punch_only()
    })
    .await;
    let ops = w.a.ops.clone();
    let slowest_first = blocking_scenario("the unpredicted typing", move || {
        let attach = Some(ScreenAttach {
            mode: ScreenSync::On,
            cols: COLS,
            rows: ROWS,
            predict: Predict::Never,
            status_line: StatusLine::Off,
            escape: None,
        });
        let opened = ops
            .session_open_interactive(shell_request(), false, attach)
            .expect("open");
        let mut stream = ops
            .session_attach_screen(
                SessionAttachReq {
                    session_ref: opened.session_ref,
                    no_steal: false,
                },
                &[],
                attach,
            )
            .expect("attach");
        assert!(stream.screen_sync());
        let handle = stream.handle();
        let (tx, events) = mpsc::channel();
        std::thread::spawn(move || {
            while let Some(event) = stream.next_event() {
                if tx.send(event.map_err(|e| e.to_string())).is_err() {
                    break;
                }
            }
        });
        let mut term = LocalTerminal::new();
        let wait = Duration::from_secs(30);
        assert!(until(
            &events,
            &mut term,
            wait,
            LocalTerminal::shows_bare_prompt
        ));
        let sent = Instant::now();
        handle.write(b"q".to_vec()).expect("write");
        assert!(until(&events, &mut term, wait, |t| t
            .typed_row("q")
            .is_some()));
        let took = sent.elapsed();
        let _ = handle.detach();
        took
    })
    .await;
    assert!(
        slowest_first >= Duration::from_millis(180),
        "with prediction off the key took {slowest_first:?}, under the 200 ms round trip"
    );
    assert_punched(&w, 2);
    w.shutdown().await;
}
