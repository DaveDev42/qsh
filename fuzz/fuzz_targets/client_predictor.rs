//! Fuzzes the client's local echo prediction engine (ADR-0053 decisions 4 to
//! 8 and 15, DoD 10): `qsh_core::client::predict::Predictor` together with
//! the renderer that composes its overlay (`ScreenRenderer`).
//!
//! Every input the engine sees is attacker-influenced: the host screen is
//! built from arbitrary program output (a hostile `cat`, a hostile server),
//! the `ScreenEcho` reports come straight off the wire with any state
//! number, input offset and tty value, and the typed bytes can be anything a
//! paste or a terminal sends. The data is read as an op sequence: typed text
//! (ASCII, wide, combining, ambiguous-width, control, raw bytes), host
//! output fed to a `HostScreen` and applied as a new state, host echo of the
//! typed text, arbitrary `EchoReport`s, ticks on a synthetic monotonic
//! clock, policy / writer / status-line / leg changes and host resizes.
//!
//! Invariants checked after every op: no panic; `pending_len() <= 256`;
//! overlay cells lie inside the screen of the last applied state, in strict
//! row-major order, a wide cell never reaching past the last column; no
//! overlay while `blocked()` says so, while the last applied state shows the
//! alternate screen or mouse reporting, on a read-only attach, or after a
//! fresh report said `Secret` (which must also make `blocked()` say so); the
//! renderer, given a state it has already drawn, never emits an erase of the
//! screen (`CSI J`, `CSI 1J`, `CSI 2J`, `CSI 3J`) when an overlay or the
//! status line appears, changes or goes away.
//!
//! After the ops, the engine is brought to a quiet end (writer, a fresh
//! state with the cursor shown, one report covering every byte sent, tty
//! `Kernel`); then nothing is
//! pending and the overlay is empty.

#![no_main]

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use qsh_core::adapt::Prediction;
use qsh_core::client::predict::{EchoReport, MAX_PENDING, Overlay, Predictor, TtyEcho};
use qsh_core::client::render::ScreenRenderer;
use qsh_core::screen::{HostScreen, ScreenOptions};
use qsh_proto::screen::{Modes, ScreenState, cell_flags};

/// Typed text: ASCII, wide, ambiguous width, combining, zero width, emoji,
/// control characters.
const TEXT: &[&str] = &[
    "a", "b", "Z", " ", "0", "~", "가", "나", "漢", "±", "é", "e\u{301}", "\u{200d}", "\u{fe0f}",
    "🙂", "\u{7f}", "\r", "\n", "\t", "\u{1b}", "\u{0}", "\u{3a3}", "ｱ",
];
/// Keys: Backspace, Left, Right, Up, Home, Delete, bracketed paste, Ctrl-U.
const KEYS: &[&[u8]] = &[
    b"\x7f",
    b"\x08",
    b"\x1b[D",
    b"\x1b[C",
    b"\x1b[A",
    b"\x1bOD",
    b"\x1b[H",
    b"\x1b[3~",
    b"\x1b[200~hello\x1b[201~",
    b"\x1b[200~",
    b"\x1b[201~",
    b"\x1b[",
    b"\x1b",
    b"\x15",
    b"\r",
    b"hello world",
];
/// Host output that changes modes or the screen shape.
const HOST: &[&[u8]] = &[
    b"\x1b[?1049h",
    b"\x1b[?1049l",
    b"\x1b[?25l",
    b"\x1b[?25h",
    b"\x1b[?1000h",
    b"\x1b[?1000l",
    b"\x1b[?2004h",
    b"\x1b[2J\x1b[H",
    b"\x1b[1;1H",
    b"\x1b[K",
    b"\r\n$ ",
    b"\x08 \x08",
    b"\x1b[D",
    b"\x1b[C",
    b"\x1b[10P",
    b"\x1b[2@",
];

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from(self.u16()?) | u32::from(self.u16()?) << 16)
    }
    fn bytes(&mut self, max: usize) -> Option<Vec<u8>> {
        let n = usize::from(self.u8()?) % (max + 1);
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head.to_vec())
    }
}

fn tty_of(b: u8) -> TtyEcho {
    match b % 4 {
        0 => TtyEcho::Unknown,
        1 => TtyEcho::Kernel,
        2 => TtyEcho::App,
        _ => TtyEcho::Secret,
    }
}

/// Whether `out` holds `CSI J` or `CSI Ps J`, an erase of the display.
fn has_erase(out: &[u8]) -> bool {
    out.windows(3).any(|w| w == b"\x1b[J")
        || out
            .windows(4)
            .any(|w| w[0] == 0x1b && w[1] == b'[' && w[3] == b'J' && w[2].is_ascii_digit())
}

struct Run {
    host: HostScreen,
    p: Predictor,
    r: ScreenRenderer,
    now: Instant,
    /// Cumulative bytes typed (the input offset).
    sent: u64,
    /// Typed since the host last echoed, for the echo op.
    typed: Vec<u8>,
    /// The state the predictor was last given.
    state: Option<ScreenState>,
    n: u64,
    window: (u16, u16),
    status: bool,
    writer: bool,
    // A model of which reports the engine must accept.
    last_key: Option<(u64, u64)>,
    fresh_secret: bool,
    max_num: u64,
}

impl Run {
    fn check(&mut self) {
        assert!(self.p.pending_len() <= MAX_PENDING);
        let overlay = self.p.overlay();
        if let Some(s) = &self.state {
            let mut prev: Option<(u16, u16)> = None;
            for c in &overlay.cells {
                assert!(c.row < s.rows && c.col < s.cols, "overlay cell off screen");
                if c.cell.flags & cell_flags::WIDE != 0 {
                    assert!(c.col + 1 < s.cols, "wide overlay cell in the last column");
                }
                assert!(
                    prev.is_none_or(|p| p < (c.row, c.col)),
                    "overlay not ordered"
                );
                prev = Some((c.row, c.col));
            }
            if let Some((r, c)) = overlay.cursor {
                assert!(r < s.rows && c <= s.cols, "overlay cursor off screen");
            }
            let m = s.modes;
            if m.flags & Modes::ALT_SCREEN != 0 || m.mouse_mode != 0 {
                assert!(overlay.is_empty(), "overlay on a full-screen app");
            }
        }
        if self.p.blocked().is_some() {
            assert!(overlay.is_empty(), "overlay while blocked");
        }
        if !self.writer {
            assert!(overlay.is_empty(), "overlay on a read-only attach");
        }
        if self.fresh_secret {
            assert!(self.p.blocked().is_some(), "secret report did not block");
            assert!(overlay.is_empty(), "overlay under a secret tty");
        }
        self.render(&overlay);
    }

    fn render(&mut self, overlay: &Overlay) {
        let Some(s) = self.state.clone() else { return };
        let w = self.window;
        // Settle the renderer on the bare host state, then change only the
        // overlay and the status line: none of that may erase the screen.
        let _ = self.r.draw_composed(&s, None, None, &[], w);
        let bare = self.r.draw_composed(&s, None, None, &[], w);
        assert!(bare.is_empty(), "redrawing an unchanged state wrote bytes");
        let status = self.status.then_some("qsh: last reply 3s ago");
        let with = self.r.draw_composed(&s, Some(overlay), status, &[], w);
        assert!(!has_erase(&with), "overlay change erased the screen");
        let back = self.r.draw_composed(&s, None, None, &[], w);
        assert!(!has_erase(&back), "overlay removal erased the screen");
        let _ = self.r.draw_with_overlay(&s, overlay, &[], w);
    }

    /// Feed the host emulator. U+FE0F reaches `HostScreen::feed` like any
    /// other byte: `vt100` 0.18.1 panics in `text_cleanup` when a variation
    /// selector widens the previous cell, and `HostScreen` turns the selector
    /// into a NUL before the emulator sees it (threat model C23).
    fn feed(&mut self, bytes: &[u8], end: u64) {
        self.host.feed(bytes, end);
    }

    fn apply_state(&mut self, num: u64) {
        let s = self.host.snapshot();
        self.p.on_state(&s, num, self.now);
        self.max_num = self.max_num.max(num);
        self.state = Some(s);
    }

    fn input(&mut self, bytes: &[u8]) {
        self.sent += bytes.len() as u64;
        self.p.on_input(bytes, self.sent, self.now);
        self.typed.extend_from_slice(bytes);
        self.typed.truncate(256);
    }

    fn echo(&mut self, report: EchoReport) {
        self.p.on_echo(report, self.now);
        if report.input_seq <= self.sent
            && self
                .last_key
                .is_none_or(|k| (report.state_num, report.input_seq) > k)
        {
            self.last_key = Some((report.state_num, report.input_seq));
            self.fresh_secret = report.tty == TtyEcho::Secret;
        }
        self.max_num = self.max_num.max(report.state_num);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut rd = Reader(data);
    let (Some(rows), Some(cols), Some(wc), Some(wr)) = (rd.u8(), rd.u8(), rd.u8(), rd.u8()) else {
        return;
    };
    let rows = u16::from(rows % 12) + 1;
    let cols = u16::from(cols % 48) + 1;
    let mut run = Run {
        host: HostScreen::new(ScreenOptions {
            rows,
            cols,
            history_rows: 16,
            history_bytes: 2048,
        }),
        p: Predictor::new(true),
        r: ScreenRenderer::new(),
        now: Instant::now(),
        sent: 0,
        typed: Vec::new(),
        state: None,
        n: 1,
        window: (u16::from(wc % 60) + 1, u16::from(wr % 16) + 1),
        status: false,
        writer: true,
        last_key: None,
        fresh_secret: false,
        max_num: 0,
    };
    run.p.on_policy(Prediction::Underline);
    run.apply_state(1);

    while let Some(op) = rd.u8() {
        match op % 16 {
            0..=3 => {
                let Some(i) = rd.u8() else { break };
                let mut s = String::new();
                for k in 0..=(op / 16 % 3) {
                    s.push_str(TEXT[(usize::from(i) + usize::from(k) * 7) % TEXT.len()]);
                }
                run.input(s.as_bytes());
            }
            4 => {
                let Some(i) = rd.u8() else { break };
                run.input(KEYS[usize::from(i) % KEYS.len()]);
            }
            5 => {
                let Some(b) = rd.bytes(12) else { break };
                run.input(&b);
            }
            6 => {
                // The host echoes what was typed, then maybe more output.
                let typed = std::mem::take(&mut run.typed);
                run.feed(&typed, run.sent);
                if let Some(i) = rd.u8() {
                    run.feed(HOST[usize::from(i) % HOST.len()], run.sent);
                }
                run.n += 1;
                run.apply_state(run.n);
            }
            7 => {
                let Some(b) = rd.bytes(40) else { break };
                run.feed(&b, run.sent);
                run.n += 1;
                run.apply_state(run.n);
            }
            8 => {
                let Some(i) = rd.u8() else { break };
                run.feed(HOST[usize::from(i) % HOST.len()], run.sent);
                run.n += 1;
                run.apply_state(run.n);
            }
            9 => {
                // A well-formed report: the newest state.
                let Some(t) = rd.u8() else { break };
                let seq = rd.u16().map_or(0, |v| u64::from(v) % (run.sent + 1));
                let report = EchoReport {
                    state_num: run.n,
                    input_seq: if t & 0x80 != 0 { run.sent } else { seq },
                    tty: tty_of(t),
                };
                run.echo(report);
            }
            10 => {
                // Any report at all.
                let (Some(t), Some(a), Some(b)) = (rd.u8(), rd.u32(), rd.u32()) else {
                    break;
                };
                let state_num = match t >> 4 & 3 {
                    0 => u64::from(a),
                    1 => run.n + u64::from(a % 3),
                    2 => u64::MAX - u64::from(a % 2),
                    _ => u64::from(a % 8),
                };
                let input_seq = match t >> 6 {
                    0 => u64::from(b),
                    1 => run.sent + u64::from(b % 3),
                    2 => u64::MAX,
                    _ => u64::from(b) % (run.sent + 1),
                };
                run.echo(EchoReport {
                    state_num,
                    input_seq,
                    tty: tty_of(t),
                });
            }
            11 => {
                let Some(ms) = rd.u16() else { break };
                run.now += Duration::from_millis(u64::from(ms) % 3000);
                run.p.on_tick(run.now);
            }
            12 => {
                let Some(b) = rd.u8() else { break };
                run.p.on_policy(match b % 3 {
                    0 => Prediction::Off,
                    1 => Prediction::Display,
                    _ => Prediction::Underline,
                });
                if b & 0x40 != 0 {
                    run.writer = !run.writer;
                    run.p.on_writer(run.writer);
                }
                run.status = b & 0x20 != 0;
                run.p.on_status_line(run.status);
            }
            13 => {
                // A new leg: state numbers and reports start again.
                run.p.on_leg_change();
                run.last_key = None;
                run.fresh_secret = false;
                run.max_num = 0;
                run.n = 1;
                run.apply_state(1);
            }
            14 => {
                let (Some(r), Some(c)) = (rd.u8(), rd.u8()) else {
                    break;
                };
                run.host
                    .resize(u16::from(r % 12) + 1, u16::from(c % 48) + 1);
                run.n += 1;
                run.apply_state(run.n);
            }
            _ => {
                let (Some(c), Some(r)) = (rd.u8(), rd.u8()) else {
                    break;
                };
                run.window = (u16::from(c % 60) + 1, u16::from(r % 16) + 1);
            }
        }
        run.now += Duration::from_millis(1);
        run.check();
    }

    // A quiet end: writer, a fresh leg and state, one report covering every
    // byte.
    if !run.writer {
        run.writer = true;
        run.p.on_writer(true);
    }
    run.p.on_policy(Prediction::Underline);
    run.p.on_status_line(false);
    run.status = false;
    // A new leg numbers its states again, so any report numbers seen so far
    // (up to `u64::MAX`) cannot make the closing report look stale.
    run.p.on_leg_change();
    run.last_key = None;
    // Show the host cursor: while it is hidden the predictor gives no verdict
    // on a key whose cell is not painted yet (a shell in the middle of
    // redrawing its line, ADR-0053 decision 6 amendments), so a state with
    // the cursor hidden may legitimately leave predictions pending.
    run.feed(b"\x1b[?25h", run.sent);
    run.apply_state(1);
    run.echo(EchoReport {
        state_num: 1,
        input_seq: run.sent,
        tty: TtyEcho::Kernel,
    });
    assert_eq!(
        run.p.pending_len(),
        0,
        "predictions left after every input was judged"
    );
    assert!(
        run.p.overlay().is_empty(),
        "overlay left after every input was judged"
    );
});
