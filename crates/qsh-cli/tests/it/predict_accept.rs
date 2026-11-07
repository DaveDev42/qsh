//! L8 acceptance for local echo prediction (ADR-0053 decision 16, items 1, 3,
//! 4, 7 and 12; `docs/design/testing.md` L8).
//!
//! Every test drives the client through `Ops` against a real host behind a
//! chaos proxy (or the echo host with one capability hidden). The local
//! terminal is a second emulator ([`LocalTerminal`]) fed the `Output` bytes
//! the attach hands a frontend, and the same bytes are kept raw (`drawn`) so
//! a test can assert what the client wrote to the terminal, byte for byte.
//! Nothing here prints PTY contents: the strings typed into the secret
//! tests are fixed test constants, and a failure reports counts.
//!
//! The wall-clock gates (display latency p95 behind 300 ms of round trip,
//! with loss and reorder, the old host) run under `QSH_ACCEPTANCE_SLOW`. The
//! functional ones (a rollback, a secret, a tentative epoch, a Windows host)
//! run on every platform in the ordinary test job.

use crate::common;

use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::{HOST_ALIAS, Sandbox};
use qsh_core::{
    AttachHandle, OpError, Ops, Paths, Predict, RecoveryConfig, ScreenAttach, ScreenSync,
    StatusLine,
};
use qsh_proto::event::SessionEvent;
use qsh_proto::screen::cell_flags;
use qsh_proto::wire;
use qsh_proto::{SessionAttachReq, SessionOpenReq};
use qsh_testkit::chaos::{ChaosPolicy, ChaosProxy, DelayDist};
use qsh_testkit::echo_host::EchoHost;
use qsh_testkit::shell::said;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use super::attach_recovery::{ProxiedFleet, with_deadline};
use super::screen_sync::{COLS, LocalTerminal, PROMPT, ROWS, open_req};

fn slow_enabled() -> bool {
    std::env::var_os("QSH_ACCEPTANCE_SLOW").is_some_and(|v| {
        let v = v.to_string_lossy().trim().to_lowercase();
        !(v.is_empty() || v == "0")
    })
}

/// One way 150 ms: a round trip of 300 ms.
fn rtt_300() -> ChaosPolicy {
    ChaosPolicy::seeded(0xFEED).delay(DelayDist::fixed(Duration::from_millis(150)))
}

/// Block waits for the local terminal to show something. Generous: a hang
/// is a failure, but a slow runner is not.
const WAIT: Duration = Duration::from_secs(40);

// ---------------------------------------------------------------------
// `qsh::predict` lines
// ---------------------------------------------------------------------

fn predict_lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

struct PredictLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PredictLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != "qsh::predict" {
            return;
        }
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        predict_lines()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message.0);
    }
}

/// Capture this process's `qsh::predict` lines (once; one test per process
/// under nextest, so a line belongs to the test that reads it).
fn capture_predict_lines() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::registry()
            .with(PredictLayer)
            .try_init()
            .ok();
    });
}

fn predict_log() -> Vec<String> {
    predict_lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

// ---------------------------------------------------------------------
// the client under test
// ---------------------------------------------------------------------

/// An attach whose events are read on a thread, so a test can wait with a
/// timeout and type from the same thread that looks at the screen.
struct Client {
    handle: AttachHandle,
    events: mpsc::Receiver<Result<SessionEvent, String>>,
    term: LocalTerminal,
    /// Every byte the client wrote to the local terminal, in order.
    drawn: Vec<u8>,
    /// Whether a failure may print the screen (never for a secret).
    show_rows: bool,
    unavailable: Option<&'static str>,
}

fn screen(predict: Predict, status_line: StatusLine) -> Option<ScreenAttach> {
    Some(ScreenAttach {
        mode: ScreenSync::On,
        cols: COLS,
        rows: ROWS,
        predict,
        status_line,
        escape: Some(b'~'),
    })
}

impl Client {
    fn attach(
        ops: &Ops,
        req: SessionOpenReq,
        predict: Predict,
        status_line: StatusLine,
        ctx: &str,
    ) -> Self {
        let attach = screen(predict, status_line);
        let opened = ops
            .session_open_interactive(req, false, attach)
            .unwrap_or_else(|e: OpError| panic!("open: {e} — {ctx}"));
        let mut stream = ops
            .session_attach_screen(
                SessionAttachReq {
                    session_ref: opened.session_ref,
                    no_steal: false,
                },
                &[],
                attach,
            )
            .unwrap_or_else(|e| panic!("attach: {e} — {ctx}"));
        let handle = stream.handle();
        let unavailable = stream.predict_unavailable();
        let (tx, events) = mpsc::channel();
        std::thread::spawn(move || {
            while let Some(event) = stream.next_event() {
                let event = event.map_err(|e| e.to_string());
                if tx.send(event).is_err() {
                    break;
                }
            }
        });
        Self {
            handle,
            events,
            term: LocalTerminal::new(),
            drawn: Vec::new(),
            show_rows: true,
            unavailable,
        }
    }

    fn apply(&mut self, event: Result<SessionEvent, String>) {
        let event = event.unwrap_or_else(|e| panic!("the attach failed: {e}"));
        if let SessionEvent::Output { data_b64, .. } = &event {
            let data = base64::engine::general_purpose::STANDARD
                .decode(data_b64.as_bytes())
                .expect("output is Base64");
            self.drawn.extend_from_slice(&data);
        }
        if let Some(end) = self.term.feed(event) {
            panic!("the session ended: {end:?}");
        }
    }

    /// Feed events until `done` holds; `false` at `timeout`.
    fn until(&mut self, timeout: Duration, done: impl Fn(&LocalTerminal) -> bool) -> bool {
        let limit = Instant::now() + timeout;
        loop {
            if done(&self.term) {
                return true;
            }
            let left = limit.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok(event) => self.apply(event),
                Err(mpsc::RecvTimeoutError::Timeout) => return done(&self.term),
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!("the attach ended"),
            }
        }
    }

    fn wait(&mut self, what: &str, done: impl Fn(&LocalTerminal) -> bool) {
        if !self.until(WAIT, done) {
            let rows = if self.show_rows {
                format!("{:?}", self.term.rows())
            } else {
                "(not shown)".into()
            };
            panic!("timed out waiting for {what}; screen: {rows}");
        }
    }

    /// Feed whatever arrives for `dur`.
    fn settle(&mut self, dur: Duration) {
        self.until(dur, |_| false);
    }

    fn type_bytes(&self, bytes: &[u8]) {
        self.handle.write(bytes.to_vec()).expect("write");
    }

    fn finish(self) {
        let _ = self.handle.detach();
    }
}

// ---------------------------------------------------------------------
// reading the local terminal
// ---------------------------------------------------------------------

/// The index of the row that is the prompt followed by `typed`.
fn typed_row(term: &LocalTerminal, typed: &str) -> Option<usize> {
    let want = format!("{PROMPT} {typed}");
    // PSReadLine draws a history suggestion after the cursor, which is not
    // the typed text; on a Windows host the row is judged up to the cursor.
    term.rows().iter().position(|r| {
        if cfg!(windows) {
            r.starts_with(&want)
        } else {
            *r == want
        }
    })
}

fn cell_flags_at(term: &LocalTerminal, row: usize, col: usize) -> u8 {
    term.screen.snapshot().grid[row].cells[col].flags
}

fn any_underline(term: &LocalTerminal) -> bool {
    term.screen
        .snapshot()
        .grid
        .iter()
        .flat_map(|r| &r.cells)
        .any(|c| c.flags & cell_flags::UNDERLINE != 0 && !c.text.is_empty() && &*c.text != " ")
}

fn cursor(term: &LocalTerminal) -> (u16, u16) {
    let s = term.screen.snapshot();
    (s.cursor_row, s.cursor_col)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let rank = (p * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Whether the bytes hold any of `needles`.
#[cfg(unix)]
fn holds_any(bytes: &[u8], needles: &[u8]) -> bool {
    bytes.iter().any(|b| needles.contains(b))
}

// ---------------------------------------------------------------------
// item 1: the display latency
// ---------------------------------------------------------------------

/// What typing at a shell prompt measured.
struct Typing {
    /// Time from handing a key to `Ops` to its glyph on the local terminal.
    latencies: Vec<Duration>,
    /// Keys whose glyph was underlined the moment it appeared.
    underlined: usize,
    /// The last `qsh::predict` line.
    last_log: String,
}

impl Typing {
    fn sorted(&self) -> Vec<Duration> {
        let mut v = self.latencies.clone();
        v.sort();
        v
    }

    fn summary(&self) -> String {
        let v = self.sorted();
        format!(
            "n={} p50={:?} p95={:?} max={:?} underlined_on_sight={}",
            v.len(),
            percentile(&v, 0.5),
            percentile(&v, 0.95),
            v[v.len() - 1],
            self.underlined
        )
    }
}

/// Type `keys` letters at the shell's prompt, `gap` apart, and time each
/// from `Ops` to the local terminal. The first key is typed alone and waited
/// for: it is the one that confirms the epoch (decision 5), so every key
/// after it is a confirmed-epoch key (decision 16, item 1). With
/// `settle_policy` the policy gets the time to see the round trip first.
/// After the last key the local terminal must settle to exactly the host's
/// screen: the typed row, the cursor after it, no underline anywhere.
fn type_at_the_prompt(
    policy: ChaosPolicy,
    predict: Predict,
    keys: usize,
    gap: Duration,
    settle_policy: bool,
) -> Typing {
    capture_predict_lines();
    let fleet = ProxiedFleet::start(policy);
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    with_deadline("typing at the prompt", move || {
        let mut c = Client::attach(&ops, open_req(), predict, StatusLine::On, &ctx);
        c.wait("the first prompt", LocalTerminal::shows_bare_prompt);
        if settle_policy {
            // The policy samples once a second: give it two to see the RTT.
            c.settle(Duration::from_millis(2500));
        }
        c.type_bytes(b"q");
        c.wait("the first key", |t| typed_row(t, "q").is_some());
        // The host's judgment of that key follows its screen by a few ms.
        c.settle(Duration::from_millis(300));

        let mut typed = String::from("q");
        let mut out = Typing {
            latencies: Vec::new(),
            underlined: 0,
            last_log: String::new(),
        };
        for i in 0..keys {
            let key = char::from(b'a' + (i % 25) as u8);
            typed.push(key);
            let row_text = typed.clone();
            c.type_bytes(&[key as u8]);
            let sent = Instant::now();
            c.wait("the key on the local terminal", |t| {
                typed_row(t, &row_text).is_some()
            });
            out.latencies.push(sent.elapsed());
            if let Some(row) = typed_row(&c.term, &typed) {
                let col = PROMPT.len() + 1 + typed.len() - 1;
                if cell_flags_at(&c.term, row, col) & cell_flags::UNDERLINE != 0 {
                    out.underlined += 1;
                }
            }
            c.settle(gap);
        }
        // Everything is judged: the local terminal is the host's screen.
        let want = typed.clone();
        c.wait("every key confirmed and no underline left", |t| {
            typed_row(t, &want).is_some() && !any_underline(t)
        });
        let row = typed_row(&c.term, &typed).expect("the typed row");
        assert_eq!(
            cursor(&c.term),
            (row as u16, (PROMPT.len() + 1 + typed.len()) as u16),
            "the cursor sits after the typed text — {ctx}"
        );
        out.last_log = predict_log().last().cloned().unwrap_or_default();
        c.finish();
        out
    })
}

/// ADR-0053 decision 16, item 1.
///
/// Behind 150 ms each way, fifty keys of a confirmed epoch are on the local
/// terminal within 20 ms at p95, every one underlined while the host has not
/// answered, and the screen ends up exactly the host's. With prediction off
/// the same keys take a round trip.
#[test]
fn a_predicted_keystroke_is_drawn_before_the_echo_arrives() {
    if !slow_enabled() {
        eprintln!("skipped: needs QSH_ACCEPTANCE_SLOW");
        return;
    }
    let predicted = type_at_the_prompt(
        rtt_300(),
        Predict::Auto,
        50,
        Duration::from_millis(25),
        true,
    );
    let plain = type_at_the_prompt(rtt_300(), Predict::Never, 10, Duration::ZERO, false);
    let p95 = percentile(&predicted.sorted(), 0.95);
    let fastest_plain = plain.sorted()[0];
    eprintln!("RTT 300 ms, 50 keys: predicted {}", predicted.summary());
    eprintln!("RTT 300 ms, 10 keys: never     {}", plain.summary());
    assert!(
        fastest_plain >= Duration::from_millis(250),
        "control: {}",
        plain.summary()
    );
    assert!(
        p95 <= Duration::from_millis(20),
        "predicted p95 {p95:?} over 20 ms: {}",
        predicted.summary()
    );
    assert_eq!(
        predicted.underlined,
        predicted.latencies.len(),
        "a prediction the host has not confirmed is underlined: {}",
        predicted.summary()
    );
}

/// The same fifty keys behind 300 ms of round trip with 3% loss and 5%
/// reorder (the chaos proxy holds a datagram back so the next overtakes it).
/// Display is local, so the p95 bound is the same; loss and reorder bear on
/// the judgment, so the end state must still be exactly the host's screen
/// (the helper waits for it and checks the cursor).
#[test]
fn predicted_display_holds_under_loss_and_reorder() {
    if !slow_enabled() {
        eprintln!("skipped: needs QSH_ACCEPTANCE_SLOW");
        return;
    }
    let policy = rtt_300().drop(0.03).reorder(0.05);
    let typing = type_at_the_prompt(policy, Predict::Auto, 50, Duration::from_millis(25), true);
    eprintln!(
        "RTT 300 ms, loss 3%, reorder 5%, 50 keys: {}",
        typing.summary()
    );
    let p95 = percentile(&typing.sorted(), 0.95);
    assert!(
        p95 <= Duration::from_millis(20),
        "p95 {p95:?} over 20 ms under loss and reorder: {}",
        typing.summary()
    );
}

// ---------------------------------------------------------------------
// item 3: a wrong prediction is taken back
// ---------------------------------------------------------------------

/// A raw-mode program that echoes the first byte as typed and every byte
/// after it as `*`: with the first key confirmed, the keys after it are
/// predicted as themselves and are all wrong.
#[cfg(unix)]
#[test]
fn a_misprediction_is_rolled_back_to_the_host_screen() {
    let fleet = ProxiedFleet::start(rtt_300());
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    with_deadline("a misprediction", move || {
        let mut req = open_req();
        req.argv = vec![
            "sh".into(),
            "-c".into(),
            "/bin/stty raw -echo; printf 'READY>'; n=0; while :; do \
             c=$(/bin/dd bs=1 count=1 2>/dev/null); \
             if [ $n = 0 ]; then printf %s \"$c\"; else printf '*'; fi; n=1; done"
                .into(),
        ];
        let mut c = Client::attach(&ops, req, Predict::Always, StatusLine::On, &ctx);
        c.wait("the program's banner", |t| t.shows("READY>"));
        // The first key is judged, not drawn; wait for the host's echo of it.
        c.type_bytes(b"a");
        c.wait("the first key", |t| t.shows("READY>a"));
        c.settle(Duration::from_millis(300));
        // Three keys the program answers with `*`.
        let sent = Instant::now();
        c.type_bytes(b"bcd");
        c.wait("the predicted keys", |t| t.shows("READY>abcd"));
        let drawn_in = sent.elapsed();
        let before = c.drawn.len();
        assert!(
            drawn_in < Duration::from_millis(150),
            "the wrong prediction was drawn after {drawn_in:?}, a round trip is 300 ms — {ctx}"
        );
        // One judgment later the wrong glyphs are gone and the host's are
        // there; nothing underlined is left, the cursor is after them.
        c.wait("the host's cells", |t| t.shows("READY>a***"));
        c.settle(Duration::from_millis(400));
        assert!(c.term.shows("READY>a***"), "{:?}", c.term.rows());
        assert!(!c.term.shows("abcd"), "a rolled-back glyph is left");
        assert!(!any_underline(&c.term), "an underline is left");
        let row = c
            .term
            .rows()
            .iter()
            .position(|r| r == "READY>a***")
            .unwrap();
        assert_eq!(cursor(&c.term), (row as u16, 10), "cursor — {ctx}");
        // The rollback is a cell write, not a repaint of the window.
        let after = &c.drawn[before..];
        assert!(
            !String::from_utf8_lossy(after).contains("\x1b[2J"),
            "a rollback cleared the window"
        );
        c.finish();
    });
}

// ---------------------------------------------------------------------
// item 4: a secret is never drawn
// ---------------------------------------------------------------------

/// Characters that appear nowhere else on the screen (not in the prompt, the
/// commands, or their output), so a byte of them in what the client drew can
/// only be a typed secret.
const SECRET: &[u8] = b"Q7Z9J3X";

/// `stty -echo; read` (ECHO off, ICANON on): the secret typed at it is in
/// none of the bytes the client writes to the local terminal, and the host
/// tells the client the tty is secret. The shell session is the production
/// path: the secret follows an Enter, and the tty hint (decision 3) is the
/// second guard behind the epoch rule (decision 5).
#[cfg(unix)]
#[test]
fn secret_input_is_never_drawn() {
    capture_predict_lines();
    let policy = ChaosPolicy::seeded(0x5EC2E7).delay(DelayDist::fixed(Duration::from_millis(60)));
    let fleet = ProxiedFleet::start(policy);
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    with_deadline("a secret", move || {
        let mut c = Client::attach(&ops, open_req(), Predict::Always, StatusLine::On, &ctx);
        c.show_rows = false;
        c.wait("the first prompt", LocalTerminal::shows_bare_prompt);
        // A confirmed epoch first, as after any ordinary typing.
        c.type_bytes(b"e");
        c.wait("an echoed key", |t| typed_row(t, "e").is_some());
        c.settle(Duration::from_millis(300));
        c.type_bytes(b"\x7f");
        c.wait("the erased key", |t| t.shows_bare_prompt());
        c.settle(Duration::from_millis(300));
        // Echo off, then read: the program is waiting for the secret.
        let cmd =
            "/bin/stty -echo; printf 'RDY%s\\n' 1; read -r pw; /bin/stty echo; printf 'FIN%s\\n' 1";
        c.type_bytes(format!("{cmd}\n").as_bytes());
        c.wait("the program waiting", |t| t.shows("RDY1"));
        c.settle(Duration::from_millis(300));

        let mark = c.drawn.len();
        for b in SECRET {
            c.type_bytes(&[*b]);
            c.settle(Duration::from_millis(40));
        }
        // Past two round trips: the host has judged every one of them.
        c.settle(Duration::from_millis(800));
        let leaked = c.drawn[mark..]
            .iter()
            .filter(|b| SECRET.contains(b))
            .count();
        assert_eq!(
            leaked, 0,
            "{leaked} secret byte(s) reached the local terminal — {ctx}"
        );
        assert!(
            predict_log()
                .iter()
                .any(|l| l.contains("\"blocked\":\"secret\"")),
            "the host never reported a secret tty: {:?}",
            predict_log()
        );
        // End the read; the shell is back and the secret is still nowhere.
        c.type_bytes(b"\n");
        c.wait("the program done", |t| t.shows("FIN1"));
        c.settle(Duration::from_millis(300));
        assert!(
            !holds_any(&c.drawn[mark..], SECRET),
            "a secret byte reached the local terminal after the read — {ctx}"
        );
        assert!(
            c.term
                .rows()
                .iter()
                .all(|r| !r.bytes().any(|b| SECRET.contains(&b))),
            "a secret byte is on the local screen — {ctx}"
        );
        c.finish();
    });
}

/// A program that echoes nothing and reads input (a raw-mode program on a
/// unix host, a console program that never reads on Windows): after an
/// Enter, nothing typed is ever drawn, whatever `--predict=always` says,
/// because no prediction of the new epoch is ever confirmed (decision 5).
/// Unix hosts also have the tty hint; this program is raw (`tty = APP`) so
/// the epoch rule is the only guard left. The control types at a shell
/// first, where the same keys are drawn.
#[test]
fn a_tentative_epoch_is_never_drawn() {
    capture_predict_lines();
    let policy = ChaosPolicy::seeded(0x7E47).delay(DelayDist::fixed(Duration::from_millis(80)));
    let fleet = ProxiedFleet::start(policy);
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    with_deadline("a tentative epoch", move || {
        // Control: at a shell the second key of a confirmed epoch is drawn
        // long before the host could echo it (RTT 160 ms).
        let mut c = Client::attach(&ops, open_req(), Predict::Always, StatusLine::On, &ctx);
        c.wait("the first prompt", LocalTerminal::shows_bare_prompt);
        c.type_bytes(b"q");
        c.wait("the first key", |t| typed_row(t, "q").is_some());
        c.settle(Duration::from_millis(250));
        let sent = Instant::now();
        c.type_bytes(b"z");
        c.wait("the second key", |t| typed_row(t, "qz").is_some());
        let drawn_in = sent.elapsed();
        assert!(
            drawn_in < Duration::from_millis(100),
            "control: a confirmed-epoch key took {drawn_in:?} (RTT 160 ms) — {ctx}"
        );
        c.finish();

        // The program that never echoes.
        let mut req = open_req();
        #[cfg(unix)]
        {
            req.argv = vec![
                "sh".into(),
                "-c".into(),
                "/bin/stty raw -echo; printf 'RDY%s\\n' 1; exec /bin/sleep 30".into(),
            ];
        }
        #[cfg(windows)]
        {
            req.argv = ["cmd", "/c", "echo RDY%OS%& ping -n 30 127.0.0.1 >nul"]
                .map(String::from)
                .to_vec();
        }
        let mut c = Client::attach(&ops, req, Predict::Always, StatusLine::On, &ctx);
        c.show_rows = false;
        c.wait("the program", |t| t.shows(&said("RDY")));
        let mark = c.drawn.len();
        // An Enter first (it ends any epoch), then the typing.
        c.type_bytes(b"x\r");
        c.settle(Duration::from_millis(100));
        for b in SECRET {
            c.type_bytes(&[*b]);
            c.settle(Duration::from_millis(30));
        }
        // Two round trips and a half for the host's judgments.
        c.settle(Duration::from_millis(600));
        let leaked = c.drawn[mark..]
            .iter()
            .filter(|b| SECRET.contains(b))
            .count();
        assert_eq!(
            leaked, 0,
            "{leaked} typed byte(s) were drawn in a tentative epoch — {ctx}"
        );
        assert!(
            c.term
                .rows()
                .iter()
                .all(|r| !r.bytes().any(|b| SECRET.contains(&b))),
            "a typed byte is on the local screen — {ctx}"
        );
        c.finish();
    });
}

// ---------------------------------------------------------------------
// item 7: an old host
// ---------------------------------------------------------------------

/// A host that predates `screen-echo.v1` gives the client nothing to judge
/// a prediction by, so it predicts nothing, even for `--predict=always`
/// (which says so); the connection status line is client-only and still
/// comes up in a blackhole (decision 16, item 7).
#[test]
fn a_host_without_screen_echo_gets_no_predictions() {
    if !slow_enabled() {
        eprintln!("skipped: needs QSH_ACCEPTANCE_SLOW");
        return;
    }
    let client = Sandbox::initialized();
    let host = EchoHost::new();
    host.hide_capabilities(&[wire::CAP_SCREEN_ECHO_V1]);
    let addr = host.serve_forward(&client.fingerprint());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("proxy runtime");
    let proxy = std::sync::Arc::new(
        runtime
            .block_on(ChaosProxy::start(addr, rtt_300()))
            .expect("chaos proxy"),
    );
    client.trust_add(
        HOST_ALIAS,
        Some(&proxy.addr().to_string()),
        &host.fingerprint(),
    );
    let ops = Ops::new(Paths::new(
        client.config_dir().to_path_buf(),
        client.state_dir().to_path_buf(),
    ))
    .with_recovery(RecoveryConfig::default());
    let ctx = proxy.context();
    let blackhole = proxy.clone();
    let blackhole_runtime = runtime.handle().clone();
    with_deadline("an old host", move || {
        let mut c = Client::attach(&ops, open_req(), Predict::Always, StatusLine::On, &ctx);
        assert_eq!(
            c.unavailable,
            Some("the host does not offer screen-echo.v1"),
            "--predict=always on an old host says why it has no effect — {ctx}"
        );
        c.wait("the banner", |t| t.shows("headless echo session"));
        c.settle(Duration::from_millis(500));
        let mut latencies = Vec::new();
        let mut typed = String::new();
        for key in ['z', 'x', 'j'] {
            typed.push(key);
            c.type_bytes(&[key as u8]);
            let sent = Instant::now();
            let want = typed.clone();
            c.wait("the host's echo", |t| t.shows(&want));
            latencies.push(sent.elapsed());
            assert!(!any_underline(&c.term), "a prediction was drawn — {ctx}");
        }
        eprintln!("old host, RTT 300 ms: echo after {latencies:?}");
        assert!(
            latencies.iter().all(|l| *l >= Duration::from_millis(250)),
            "a key appeared before the host's echo: {latencies:?} — {ctx}"
        );
        // The status line is the client's own and still comes up.
        blackhole_runtime.block_on(blackhole.blackhole(Duration::from_secs(5)));
        c.type_bytes(b"x");
        let up = c.until(Duration::from_secs(5), |t| {
            t.rows()
                .first()
                .is_some_and(|r| r.starts_with("qsh: last reply"))
        });
        assert!(up, "no status line behind a blackhole — {ctx}");
        assert!(!any_underline(&c.term), "a prediction was drawn — {ctx}");
        c.finish();
    });
    drop(runtime);
}

// ---------------------------------------------------------------------
// item 12: a Windows host
// ---------------------------------------------------------------------

/// The shells a Windows host is asked to run for the prediction test.
#[cfg(windows)]
fn windows_shells() -> Vec<(&'static str, Vec<String>)> {
    let mut shells = vec![("cmd", vec!["cmd".to_string()])];
    if std::process::Command::new("pwsh")
        .args(["-NoLogo", "-NoProfile", "-Command", "exit 0"])
        .status()
        .is_ok_and(|s| s.success())
    {
        shells.push((
            "pwsh",
            [
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-NoExit",
                "-Command",
                "function prompt { 'PRM> ' }",
            ]
            .map(String::from)
            .to_vec(),
        ));
    } else {
        // CI Windows images carry pwsh; a box without it is a failure there.
        assert!(
            std::env::var_os("CI").is_none(),
            "pwsh is not installed on this runner"
        );
        eprintln!("SKIP pwsh: not installed");
    }
    shells
}

/// ConPTY reports no echo mode (`tty = UNKNOWN`), so on a Windows host only
/// the epoch rule guards a secret. This types at a cmd.exe and a PowerShell
/// (PSReadLine) prompt behind 300 ms of round trip with `--predict=always`
/// and asserts items 1 and 3 there: the confirmed-epoch keys appear well
/// before the host's echo, and when every key is judged the local terminal
/// is exactly the host's screen (the typed row, the cursor after it, no
/// underline), whatever the shell redrew on the way. Under
/// `QSH_ACCEPTANCE_SLOW` the p95 is held to the 20 ms bound.
#[cfg(windows)]
#[test]
fn windows_host_predictions_confirm_in_cmd_and_pwsh() {
    capture_predict_lines();
    for (name, argv) in windows_shells() {
        let fleet = ProxiedFleet::start(rtt_300());
        let ctx = fleet.context();
        let ops = fleet.ops(RecoveryConfig::default());
        let strict = slow_enabled();
        let summary = with_deadline("a Windows shell", move || {
            let mut req = open_req();
            req.argv = argv;
            let mut c = Client::attach(&ops, req, Predict::Always, StatusLine::On, &ctx);
            c.wait("the first prompt", LocalTerminal::shows_bare_prompt);
            c.type_bytes(b"q");
            c.wait("the first key", |t| typed_row(t, "q").is_some());
            c.settle(Duration::from_millis(500));
            let mut typed = String::from("q");
            let mut latencies = Vec::new();
            for i in 0..30 {
                let key = char::from(b'a' + (i % 25) as u8);
                typed.push(key);
                c.type_bytes(&[key as u8]);
                let sent = Instant::now();
                let want = typed.clone();
                c.wait("the key", |t| typed_row(t, &want).is_some());
                latencies.push(sent.elapsed());
                c.settle(Duration::from_millis(25));
            }
            let want = typed.clone();
            c.wait("every key judged and no underline left", |t| {
                typed_row(t, &want).is_some() && !any_underline(t)
            });
            let row = typed_row(&c.term, &typed).expect("the typed row");
            assert_eq!(
                cursor(&c.term),
                (row as u16, (PROMPT.len() + 1 + typed.len()) as u16),
                "the cursor sits after the typed text — {ctx}"
            );
            latencies.sort();
            let p95 = percentile(&latencies, 0.95);
            let worst = latencies[latencies.len() - 1];
            // ConPTY has no termios: nothing may say `secret` here.
            assert!(
                !predict_log().iter().any(|l| l.contains("\"secret\"")),
                "a Windows host reported a secret tty: {:?}",
                predict_log()
            );
            c.finish();
            if strict {
                assert!(p95 <= Duration::from_millis(20), "p95 {p95:?} — {ctx}");
            }
            // Not a round trip (300 ms) even on a loaded runner: nine keys in
            // ten are on the screen in under half of it. (A shell that
            // redraws its line can cost one key a frame or two.)
            let p90 = percentile(&latencies, 0.9);
            assert!(
                p90 < Duration::from_millis(150),
                "p90 {p90:?}, a round trip is 300 ms — {ctx}"
            );
            format!("p90={p90:?} p95={p95:?} max={worst:?}")
        });
        eprintln!("windows host {name}: {summary}");
    }
}
