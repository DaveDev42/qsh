//! The `vt100` callbacks: terminal query answers (ADR-0052 decision 3),
//! off-screen effects (decision 4) and lines scrolled off the top
//! (decision 10).

use std::collections::VecDeque;
use std::fmt::Write as _;

use qsh_proto::screen::{
    Effect, MAX_CLIPBOARD_BYTES, MAX_EFFECTS, MAX_HYPERLINK_PARAMS, MAX_HYPERLINK_URI,
    MAX_TITLE_BYTES,
};
use vt100::capture::{BasicFormattedCaptureState, RowContents};

/// Answers kept per fed chunk. A program that floods queries gets the
/// first few answered and the rest dropped.
pub(super) const MAX_ANSWER_BYTES: usize = 4096;

/// A colour the client reported at attach (`ScreenRequest.fg` / `bg`).
pub type Rgb = [u8; 3];

/// Everything the emulator collects while it is fed.
pub(super) struct Collector {
    pub(super) answers: Vec<u8>,
    pub(super) effects: Vec<Effect>,
    /// Effects dropped because the list was full or a payload was over its
    /// cap.
    pub(super) effects_dropped: u64,
    pub(super) history: VecDeque<String>,
    pub(super) history_bytes: usize,
    pub(super) history_max_rows: usize,
    pub(super) history_max_bytes: usize,
    /// Lines that scrolled off while `history` was full and were counted,
    /// not formatted, since the last drain.
    pub(super) history_skipped: u64,
    /// `history` has hit its row or byte cap: later rows are only counted
    /// until the next drain. Formatting a row costs more than the emulator
    /// spends on the bytes that produced it, so under a flood a full history
    /// must not format rows it would throw away.
    pub(super) history_full: bool,
    pub(super) fg: Option<Rgb>,
    pub(super) bg: Option<Rgb>,
}

impl Collector {
    pub(super) fn new(history_max_rows: usize, history_max_bytes: usize) -> Self {
        Self {
            answers: Vec::new(),
            effects: Vec::new(),
            effects_dropped: 0,
            history: VecDeque::new(),
            history_bytes: 0,
            history_max_rows,
            history_max_bytes,
            history_skipped: 0,
            history_full: false,
            fg: None,
            bg: None,
        }
    }

    fn answer(&mut self, bytes: &[u8]) {
        if self.answers.len() + bytes.len() <= MAX_ANSWER_BYTES {
            self.answers.extend_from_slice(bytes);
        }
    }

    fn effect(&mut self, e: Effect) {
        if !e.is_valid() {
            self.effects_dropped += 1;
        } else if matches!(e, Effect::Bell) && matches!(self.effects.last(), Some(Effect::Bell)) {
            // Consecutive bells are one bell.
        } else if self.effects.len() >= MAX_EFFECTS {
            self.effects_dropped += 1;
        } else {
            self.effects.push(e);
        }
    }

    fn push_history(&mut self, line: String) {
        if self.history_bytes + line.len() > self.history_max_bytes {
            self.history_full = true;
            self.history_skipped += 1;
            return;
        }
        self.history_bytes += line.len();
        self.history.push_back(line);
        if self.history.len() >= self.history_max_rows {
            self.history_full = true;
        }
    }

    fn color_answer(&mut self, ps: u8, color: Option<Rgb>) {
        if let Some([r, g, b]) = color {
            let mut s = String::new();
            let _ = write!(
                s,
                "\x1b]{ps};rgb:{r:02x}{r:02x}/{g:02x}{g:02x}/{b:02x}{b:02x}\x1b\\"
            );
            self.answer(s.as_bytes());
        }
    }
}

/// Drop control characters and cut to `max` bytes on a character boundary.
fn clean_text(bytes: &[u8], max: usize) -> String {
    let mut out = String::new();
    for c in String::from_utf8_lossy(bytes).chars() {
        if c.is_control() {
            continue;
        }
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

/// DECRQM answer for the private modes the emulator implements.
fn private_mode_state(screen: &vt100::Screen, mode: u16) -> Option<bool> {
    use vt100::{MouseProtocolEncoding as Enc, MouseProtocolMode as Mouse};
    Some(match mode {
        1 => screen.application_cursor(),
        9 => screen.mouse_protocol_mode() == Mouse::Press,
        25 => !screen.hide_cursor(),
        47 | 1049 => screen.alternate_screen(),
        1000 => screen.mouse_protocol_mode() == Mouse::PressRelease,
        1002 => screen.mouse_protocol_mode() == Mouse::ButtonMotion,
        1003 => screen.mouse_protocol_mode() == Mouse::AnyMotion,
        1005 => screen.mouse_protocol_encoding() == Enc::Utf8,
        1006 => screen.mouse_protocol_encoding() == Enc::Sgr,
        2004 => screen.bracketed_paste(),
        _ => return None,
    })
}

fn first_param(params: &[&[u16]]) -> Option<u16> {
    params.first().and_then(|p| p.first()).copied()
}

impl vt100::Callbacks for Collector {
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.effect(Effect::Bell);
    }

    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        self.effect(Effect::Title(clean_text(title, MAX_TITLE_BYTES)));
    }

    fn copy_to_clipboard(&mut self, _: &mut vt100::Screen, ty: &[u8], data: &[u8]) {
        // vt100 has checked both against the OSC 52 alphabets. A selection
        // list and a payload over the caps are dropped whole.
        let (Ok(selection), Ok(data)) = (std::str::from_utf8(ty), std::str::from_utf8(data)) else {
            self.effects_dropped += 1;
            return;
        };
        if data.len() > MAX_CLIPBOARD_BYTES {
            self.effects_dropped += 1;
            return;
        }
        self.effect(Effect::Clipboard {
            selection: selection.to_owned(),
            data: data.to_owned(),
        });
    }

    fn unhandled_osc(&mut self, _: &mut vt100::Screen, params: &[&[u8]]) {
        match params {
            [b"8", link_params, uri @ ..] if !uri.is_empty() => {
                // The URI may itself contain ';', which the parser split.
                let uri = uri.join(&b';');
                if link_params.len() > MAX_HYPERLINK_PARAMS || uri.len() > MAX_HYPERLINK_URI {
                    self.effects_dropped += 1;
                    return;
                }
                let (Ok(p), Ok(u)) = (std::str::from_utf8(link_params), std::str::from_utf8(&uri))
                else {
                    self.effects_dropped += 1;
                    return;
                };
                self.effect(Effect::Hyperlink {
                    params: p.to_owned(),
                    uri: u.to_owned(),
                });
            }
            // Colour queries are answered only with what the client
            // reported at attach.
            [b"10", b"?"] => self.color_answer(10, self.fg),
            [b"11", b"?"] => self.color_answer(11, self.bg),
            _ => {}
        }
    }

    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        let first = first_param(params);
        match (i1, i2, c) {
            // DA1.
            (None, None, 'c') if matches!(first, None | Some(0)) => self.answer(b"\x1b[?62;22c"),
            // DA2.
            (Some(b'>'), None, 'c') if matches!(first, None | Some(0)) => {
                self.answer(b"\x1b[>0;0;0c");
            }
            // DSR: status, cursor position.
            (None, None, 'n') if first == Some(5) => self.answer(b"\x1b[0n"),
            (None, None, 'n') | (Some(b'?'), None, 'n') if first == Some(6) => {
                let (rows, cols) = screen.size();
                let (row, col) = screen.cursor_position();
                let (row, col) = (row.min(rows.get() - 1) + 1, col.min(cols.get() - 1) + 1);
                let private = if i1.is_some() { "?" } else { "" };
                self.answer(format!("\x1b[{private}{row};{col}R").as_bytes());
            }
            // DECRQM for a private mode the emulator implements.
            (Some(b'?'), Some(b'$'), 'p') if params.len() == 1 => {
                if let Some(mode) = first
                    && let Some(set) = private_mode_state(screen, mode)
                {
                    let pm = if set { 1 } else { 2 };
                    self.answer(format!("\x1b[?{mode};{pm}$y").as_bytes());
                }
            }
            _ => {}
        }
    }

    fn on_scroll(&mut self, contents: RowContents<'_>, alternate_screen: bool) {
        if alternate_screen {
            return;
        }
        if self.history_full || self.history_max_rows == 0 {
            // Counted, not formatted: this is the flood path and it must
            // stay a few instructions.
            self.history_skipped += 1;
            return;
        }
        let mut line = String::new();
        let mut state = BasicFormattedCaptureState::new();
        if contents
            .write_formatted_basic(&mut line, &mut state)
            .is_ok()
        {
            self.push_history(line);
        }
    }
}
