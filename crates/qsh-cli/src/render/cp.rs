//! What `qsh cp` shows while it runs (`docs/CLI.md` §6.21): the human
//! progress line on stderr, or the `--jsonl` `file.entry` events on stdout.
//! It only formats what the copy reports; it decides nothing.

use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use qsh_core::{FileCopyObserver, FileProgress};
use qsh_proto::{FileCopyEntry, FileEntryEvent};

use super::human::sanitize;

/// How `qsh cp` reports while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpMode {
    /// Human text: failures and skips on stderr, plus a progress line when
    /// stderr is a terminal.
    Human { progress: bool, quiet: bool },
    /// `--jsonl`: one `file.entry` event per finished item on stdout.
    Jsonl,
    /// `--json`: nothing until the envelope.
    Silent,
}

/// The [`FileCopyObserver`] `qsh cp` hands to the copy.
pub struct CpObserver {
    mode: CpMode,
    /// When the progress line was last drawn.
    drawn: Mutex<Option<Instant>>,
}

/// The progress line is redrawn at most this often.
const REDRAW: Duration = Duration::from_millis(100);

impl CpObserver {
    pub fn new(mode: CpMode) -> Self {
        Self {
            mode,
            drawn: Mutex::new(None),
        }
    }

    fn clear_line(&self) {
        if matches!(self.mode, CpMode::Human { progress: true, .. }) {
            let mut stderr = io::stderr().lock();
            let _ = write!(stderr, "\r\x1b[K");
            let _ = stderr.flush();
        }
    }
}

impl FileCopyObserver for CpObserver {
    fn progress(&self, progress: &FileProgress) {
        let CpMode::Human {
            progress: true,
            quiet: false,
        } = self.mode
        else {
            return;
        };
        let mut drawn = self.drawn.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if drawn.is_some_and(|last| now.duration_since(last) < REDRAW) {
            return;
        }
        *drawn = Some(now);
        let percent = (progress.bytes.min(progress.total) * 100)
            .checked_div(progress.total)
            .unwrap_or(100)
            .min(100);
        let mut stderr = io::stderr().lock();
        let _ = write!(
            stderr,
            "\r\x1b[K{} {:>3}% {}",
            sanitize(&progress.name),
            percent,
            human_bytes(progress.bytes)
        );
        let _ = stderr.flush();
    }

    fn entry(&self, entry: &FileCopyEntry) {
        match self.mode {
            CpMode::Jsonl => {
                let event = FileEntryEvent::new(entry.clone());
                if let Ok(line) = serde_json::to_string(&event) {
                    let mut stdout = io::stdout().lock();
                    let _ = writeln!(stdout, "{line}");
                    let _ = stdout.flush();
                }
            }
            CpMode::Human { quiet, .. } => {
                let note = match entry.status.as_str() {
                    "failed" => Some(format!(
                        "qsh: {}: {} ({})",
                        sanitize(&item_path(entry)),
                        sanitize(entry.message.as_deref().unwrap_or("failed")),
                        entry.code.as_ref().map_or("INTERNAL", |c| c.as_str())
                    )),
                    "skipped" if !quiet => Some(format!(
                        "qsh: {}: skipped ({})",
                        sanitize(&item_path(entry)),
                        sanitize(entry.reason.as_deref().unwrap_or("skipped"))
                    )),
                    _ => None,
                };
                if let Some(note) = note {
                    self.clear_line();
                    let mut stderr = io::stderr().lock();
                    let _ = writeln!(stderr, "{note}");
                } else if entry.status == "copied" {
                    self.clear_line();
                }
            }
            CpMode::Silent => {}
        }
    }
}

fn item_path(entry: &FileCopyEntry) -> String {
    if entry.remote_path.is_empty() {
        entry.local_path.clone()
    } else {
        format!("{} -> {}", entry.remote_path, entry.local_path)
    }
}

/// `1.5 MiB`-style size.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
