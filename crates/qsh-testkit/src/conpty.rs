//! A ConPTY harness for the Windows console tests.
//!
//! [`ConPtyProbe`] opens a pseudo-console with `portable-pty`, runs a
//! program in it (usually `qsh-console-probe`, or `qsh` itself), and exposes
//! what the probe reports as parsed records and everything the program
//! printed as text. The pseudo-console's output is a VT stream: the
//! harness strips the escape sequences, finds the probe's
//! `<<QSH-PROBE key fields>>` tokens, and answers the cursor-position query
//! (`ESC [ 6 n`) that a pseudo-console may send at start-up and wait on.
//!
//! Waiting is on observable state with a deadline, never on a fixed sleep.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

/// How long any single wait may take before the test fails. Generous on
/// purpose: a loaded CI runner starts a ConPTY child slowly.
pub const WAIT: Duration = Duration::from_secs(60);

/// The probe executable (`QSH_CONSOLE_PROBE_BIN`, next to the test
/// executable, or one `cargo build`).
pub fn probe_bin() -> PathBuf {
    crate::testbin::locate("qsh-console-probe", "QSH_CONSOLE_PROBE_BIN")
}

/// One probe report: its key and the whitespace-separated fields after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub key: String,
    pub fields: Vec<String>,
}

/// A program running in a ConPTY, with its reports.
pub struct ConPtyProbe {
    /// `None` once [`Self::close_console`] has closed the pseudo-console.
    master: Option<Box<dyn MasterPty + Send>>,
    writer: Arc<Mutex<Box<dyn std::io::Write + Send>>>,
    child: Box<dyn Child + Send + Sync>,
    output: Receiver<Vec<u8>>,
    raw: Vec<u8>,
    /// How many records of each key earlier waits have handed out.
    taken: HashMap<String, usize>,
}

impl ConPtyProbe {
    /// Start `program` in a pseudo-console of `cols` x `rows`.
    pub fn spawn(program: &std::path::Path, cols: u16, rows: u16) -> Self {
        Self::spawn_with(program, &[], &[], cols, rows)
    }

    /// Start `program` with `args` and the extra environment `env` in a
    /// pseudo-console of `cols` x `rows`.
    pub fn spawn_with(
        program: &std::path::Path,
        args: &[&str],
        env: &[(&str, &std::ffi::OsStr)],
        cols: u16,
        rows: u16,
    ) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open a ConPTY");
        let mut command = CommandBuilder::new(program);
        command.args(args);
        for (name, value) in env {
            command.env(name, value);
        }
        let child = pair
            .slave
            .spawn_command(command)
            .expect("start the program in the ConPTY");
        let mut reader = pair.master.try_clone_reader().expect("ConPTY reader");
        let writer: Arc<Mutex<Box<dyn std::io::Write + Send>>> = Arc::new(Mutex::new(
            pair.master.take_writer().expect("ConPTY writer"),
        ));

        let (tx, output) = channel();
        let reply = Arc::clone(&writer);
        std::thread::spawn(move || {
            const QUERY: &[u8] = b"\x1b[6n";
            let mut buf = [0u8; 4096];
            let mut tail: Vec<u8> = Vec::new();
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                // The query can straddle two reads: look through the end of
                // the last one as well.
                tail.extend_from_slice(&buf[..n]);
                if tail.windows(QUERY.len()).any(|w| w == QUERY) {
                    let mut writer = reply.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writer.write_all(b"\x1b[1;1R");
                    let _ = writer.flush();
                }
                let keep = tail.len().saturating_sub(QUERY.len() - 1);
                tail.drain(..keep);
                if tx.send(buf[..n].to_vec()).is_err() {
                    return;
                }
            }
        });

        // The slave end stays owned by the pseudo-console; the master is
        // kept for `resize`.
        drop(pair.slave);
        Self {
            master: Some(pair.master),
            writer,
            child,
            output,
            raw: Vec::new(),
            taken: HashMap::new(),
        }
    }

    /// Type `bytes` into the pseudo-console's input.
    pub fn send(&self, bytes: &[u8]) {
        let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        writer.write_all(bytes).expect("write to the ConPTY");
        writer.flush().expect("flush the ConPTY");
    }

    /// Change the pseudo-console's size.
    pub fn resize(&self, cols: u16, rows: u16) {
        self.master
            .as_ref()
            .expect("the console is open")
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("resize the ConPTY");
    }

    /// Close the pseudo-console the way closing its window does: the console
    /// host sends `CTRL_CLOSE_EVENT` to the processes attached to it and
    /// ends them if they linger. The program is not killed from here, so
    /// what it does with the event is what a test observes. [`Self::wait_exit`]
    /// still works afterwards; the output so far stays readable.
    pub fn close_console(&mut self) {
        drop(self.master.take());
    }

    /// End the program the way a crash would: `TerminateProcess`, with no
    /// chance to restore the console or to say goodbye to a peer. The
    /// pseudo-console stays open, so [`Self::wait_exit`] still returns the
    /// status.
    pub fn kill(&mut self) {
        self.child.kill().expect("terminate the program");
    }

    /// The next record of `key` that no earlier wait returned, waiting up to
    /// [`WAIT`] for it. Panics with what was seen if it never comes.
    pub fn wait_record(&mut self, key: &str) -> Record {
        let deadline = Instant::now() + WAIT;
        loop {
            let seen = self.taken.get(key).copied().unwrap_or(0);
            if let Some(record) = parse_records(&self.raw)
                .into_iter()
                .filter(|r| r.key == key)
                .nth(seen)
            {
                *self.taken.entry(key.to_string()).or_default() += 1;
                return record;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(left) {
                Ok(chunk) => self.raw.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => panic!(
                    "no `{key}` record within {WAIT:?}; the console stream so far:\n{:?}",
                    String::from_utf8_lossy(&self.raw)
                ),
            }
        }
    }

    /// Everything the program has printed so far, as text with the escape
    /// sequences removed. Only what earlier waits drained is in it, so wait
    /// for a record that comes after the output of interest first.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&strip_vt(&self.raw)).into_owned()
    }

    /// Wait until the program's output contains `needle`, up to [`WAIT`],
    /// and return all the text so far. Panics with what was seen if it
    /// never comes.
    pub fn wait_text(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            let text = self.text();
            if text.contains(needle) {
                return text;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(left) {
                Ok(chunk) => self.raw.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    panic!("no {needle:?} within {WAIT:?}; the console text so far:\n{text:?}")
                }
            }
        }
    }

    /// Wait until the program has printed a whole line that is a JSON
    /// document (an envelope), up to [`WAIT`], and return the last one seen.
    /// The pseudo-console wraps a line at its width, so a caller that reads
    /// one asks for a console wide enough to hold it.
    pub fn wait_json(&mut self) -> serde_json::Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let text = self.text();
            if let Some(value) = text
                .lines()
                .rev()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())
                .find(serde_json::Value::is_object)
            {
                return value;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(left) {
                Ok(chunk) => self.raw.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    panic!("no JSON line within {WAIT:?}; the console text so far:\n{text:?}")
                }
            }
        }
    }

    /// The program's status if it has already exited, without waiting. The
    /// output that has arrived is taken in either way.
    pub fn try_exit(&mut self) -> Option<u32> {
        while let Ok(chunk) = self.output.try_recv() {
            self.raw.extend_from_slice(&chunk);
        }
        self.child
            .try_wait()
            .expect("poll the program")
            .map(|status| status.exit_code())
    }

    /// Wait for the probe to exit and return its status.
    pub fn wait_exit(&mut self) -> u32 {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the probe") {
                return status.exit_code();
            }
            assert!(Instant::now() < deadline, "the program did not exit");
            // Keep draining so the pseudo-console never blocks on a full
            // pipe; a short receive timeout doubles as the poll interval.
            match self.output.recv_timeout(Duration::from_millis(50)) {
                Ok(chunk) => self.raw.extend_from_slice(&chunk),
                // The reader is gone (the console closed), so the receive
                // no longer paces the loop.
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

impl Drop for ConPtyProbe {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Every `<<QSH-PROBE key fields>>` token in a pseudo-console stream, in
/// order, after the escape sequences are removed.
pub fn parse_records(stream: &[u8]) -> Vec<Record> {
    const OPEN: &str = "<<QSH-PROBE ";
    let text = String::from_utf8_lossy(&strip_vt(stream)).into_owned();
    let mut records = Vec::new();
    let mut rest = text.as_str();
    while let Some(start) = rest.find(OPEN) {
        let after = &rest[start + OPEN.len()..];
        let Some(end) = after.find(">>") else { break };
        let mut words = after[..end].split_whitespace().map(str::to_string);
        if let Some(key) = words.next() {
            records.push(Record {
                key,
                fields: words.collect(),
            });
        }
        rest = &after[end + 2..];
    }
    records
}

/// Remove CSI and OSC escape sequences (and bare ESC-prefixed pairs) from a
/// VT stream, keeping the text.
fn strip_vt(stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(stream.len());
    let mut i = 0;
    while i < stream.len() {
        if stream[i] != 0x1b {
            out.push(stream[i]);
            i += 1;
            continue;
        }
        i += 1;
        match stream.get(i) {
            // CSI: parameters and intermediates, then one final byte.
            Some(b'[') => {
                i += 1;
                while i < stream.len() && !(0x40..=0x7e).contains(&stream[i]) {
                    i += 1;
                }
                i += 1;
            }
            // OSC: up to BEL or ST (ESC \).
            Some(b']') => {
                i += 1;
                while i < stream.len() {
                    if stream[i] == 0x07 {
                        i += 1;
                        break;
                    }
                    if stream[i] == 0x1b && stream.get(i + 1) == Some(&b'\\') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            // Two-byte escape (`ESC =`, `ESC >`, charset selection, ...).
            Some(_) => i += 1,
            None => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_found_through_escape_sequences() {
        let stream = b"\x1b[?9001h\x1b[2J\x1b]0;title\x07<<QSH-PROBE size 100 \x1b[1;5H30>>\r\n\
                       \x1b[3;1H<<QSH-PROBE ready >>";
        assert_eq!(
            parse_records(stream),
            vec![
                Record {
                    key: "size".into(),
                    fields: vec!["100".into(), "30".into()]
                },
                Record {
                    key: "ready".into(),
                    fields: vec![]
                },
            ]
        );
    }
}
