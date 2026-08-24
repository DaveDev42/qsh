//! **SC4/SC5** — the client dies the way clients actually die
//! (`docs/PRD.md` §15 SC4·SC5, `docs/ROADMAP.md` M2 수용 기준 3,
//! `PLAN.md` Step 8 (a)).
//!
//! Every other resume test in the tree tears down a *path*: the client
//! process stays alive and its driver notices. This one kills the client
//! itself with `SIGKILL`, which is the case no amount of in-process
//! cleverness can help with — no unwind, no `Drop`, no detach frame, no
//! QUIC `CONNECTION_CLOSE`. The host only ever learns about it by
//! timeout.
//!
//! It therefore has to be a **real OS process**, which is why this file
//! lives in `qsh-cli/tests/` rather than in `qsh-testkit/tests/` where
//! `PLAN.md` Step 8 (b) first put it: `CARGO_BIN_EXE_qsh` — the only way
//! to get a `qsh` binary to kill — exists only in the tests of the crate
//! that builds it. `attach_recovery.rs` is here for the same reason.
//!
//! ## What is asserted, and against what
//!
//! The session runs a deterministic producer: numbered markers separated
//! by fixed-size bursts of `yes`. `yes` makes corruption loud, but nothing
//! here pattern-matches on `y`s — the ground truth is the **replay ring
//! itself**, pulled twice through the cursor-pull primitive
//! (`docs/CLI.md` §6.4):
//!
//! * `full` — the whole canonical stream, read from offset `0`;
//! * `tail` — the same stream read from `L`, the offset the killed client
//!   had provably rendered (its pty output is captured, and `full[..L]`
//!   is located inside it byte for byte).
//!
//! SC4 is then `tail == full[L..]` **as byte ranges**, plus the first
//! recovered frame starting at exactly `L` — no loss, no duplication —
//! plus no `session.gap` anywhere, which is the precondition the DoD
//! states ("gap 이벤트가 없는 한").
//!
//! Both halves come out of the same ring, so on their own they can only
//! show that the *resume offset* is honest — a byte the broker dropped on
//! the way in would be missing from both, identically, and every offset
//! would still tile. [`assert_producer_corpus`] is the check whose oracle
//! is **not** the ring: the producer's script fixes the number of markers,
//! their order, and every byte between them, so a chunk lost at append
//! time changes a round's contents and fails.
//!
//! ## Why the kill is mid-stream, and not by luck
//!
//! The DoD condition is "`yes` 실행 중" — the producer must still be
//! writing when the signal lands. That is a race unless something orders
//! it, so the producer's burst loop is **gated**: it blocks on `read`
//! until the test types [`GO_TOKEN`] into the attached client. The
//! producer therefore cannot have finished — cannot have started — before
//! a live client was watching, and the client is killed three markers in.
//! It is then *asserted*, not assumed: the ring's cursor taken off the
//! corpse (`session.get`'s `last_sequence`) is still short of the offset
//! `QSHDONE` ends up at — and that sample is taken a round trip *after*
//! the kill, so it over-states how far the stream had got, never the
//! reverse. Megabytes are still to come when the client dies, and `L` (the
//! offset it had rendered) is measured, so "it had already seen
//! everything" cannot pass either.
//!
//! ## Which mechanism proves which half
//!
//! `SessionAttachReq` carries no resume offset — a user-initiated
//! reattach deliberately replays the whole retained ring (`PLAN.md` Step 6
//! invariant, asserted here too). The offset-resume half of SC4 is
//! therefore proven on the `session.read` cursor-pull (`docs/CLI.md`
//! §6.4), which is the primitive a caller with an `L` actually has. The
//! *wire* `SessionAttach{last_output_seq: L}` seam belongs to the driver's
//! reconnect path and is proven in `attach_recovery.rs`, where the client
//! is alive to remember `L`; a SIGKILLed process has no cursor to bring
//! back, which is exactly why this file measures `L` from the pty.
//!
//! SC5 is three independent facts about the same corpse: the producer's
//! own pid (it prints `$$` as its first line) still answers `kill -0`, the
//! host still reports the session `running`, and the pty is still wired up
//! — input written while no client is attached comes back out of the ring
//! (see [`ALIVE_MARKER`] for what that leg does and does not prove).
//!
//! ## Termination discipline
//!
//! `qsh serve` spawns session children in their own process group
//! (`setsid`, `docs/design/architecture.md` §4), so killing the listener
//! does **not** reap them. Every process this test creates is therefore
//! owned by a guard that fires on any exit path: [`ClientGuard`] for the
//! `qsh` client, [`ChildGroupGuard`] for the remote `sh`/`yes` group, and
//! `ServeGuard` for the listener. Nothing sleeps for synchronisation —
//! every wait is a bounded `expect` or a deadline-bounded pull loop.

#![cfg(unix)]

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use common::{Fleet, HOST_ALIAS, Sandbox};
use expectrl::process::unix::{Signal, WaitStatus};
use expectrl::session::OsSession;
use expectrl::{Expect as _, Regex, Session};
use nix::sys::signal::{Signal as NixSignal, kill, killpg};
use nix::unistd::Pid;
use qsh_core::{Ops, Paths, SessionReader};
use qsh_proto::event::SessionEvent;
use qsh_proto::{
    EnvVar, SessionAttachReq, SessionCloseReq, SessionGetReq, SessionOpenReq, SessionReadReq,
};

/// How long any single `expect` on the client's pty waits.
const EXPECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on every pull loop in this file. Generous — the failure worth
/// reporting is "never arrived", not "arrived late" — but finite, so a
/// wedged broker fails the suite instead of hanging it.
const PULL_DEADLINE: Duration = Duration::from_secs(90);

/// Long-poll per pull. Small enough that the deadline above stays
/// responsive, non-zero so the loop parks in the broker instead of
/// spinning.
const PULL_WAIT_MS: u64 = 250;

/// How many marker/burst rounds the producer emits.
///
/// Two ceilings meet here. The whole stream must stay comfortably inside
/// the replay ring's 8 MiB budget (`docs/PRD.md` §13): eviction would
/// produce a `session.gap`, and a gap is the one condition under which the
/// DoD does *not* promise byte-identity. At [`MARKER_STRIDE`] bytes per
/// round that is ≈ 2.1 MiB — a quarter of the budget. It also has to take
/// long enough that the *sampling* round trip after the kill (a fresh dial
/// while the host is blasting a megabyte a second — one lost handshake
/// packet costs a QUIC PTO, ~0.7 s) stays a small part of it, because that
/// sample is the upper bound the mid-stream assertion rests on.
const ROUNDS: usize = 360;

/// Bytes of `yes` between two markers, measured on the pipe (the pty's
/// `ONLCR` turns each `y\n` into `y\r\n`, so the stream carries 1.5×).
const BURST: usize = 4096;

/// The same burst as the stream carries it: `head -c BURST` cuts `yes` on
/// a `y\n` boundary, and the pty's `ONLCR` makes every pair three bytes.
const BURST_ON_PTY: usize = BURST + BURST / 2;

/// `printf 'QSHMARK-%04d\n'` is 13 bytes on the pipe, 14 on the pty.
const MARKER_LINE: usize = 14;

/// Width of a `QSHMARK-\d{4}` regex match itself, terminator excluded:
/// the 8-byte literal prefix plus the fixed 4-digit index. Used to slice
/// consecutive occurrences apart when one `expect()` scan turns up more
/// than one (see `ClientGuard::next_marker`).
const MARKER_MATCH_LEN: usize = 8 + 4;

/// Nominal distance between the starts of two consecutive markers — the
/// floor, since the tty may emit an extra `\r` (see
/// [`assert_producer_corpus`]), never fewer bytes.
const MARKER_STRIDE: usize = MARKER_LINE + BURST_ON_PTY;

/// The client is killed once it has *rendered* this many markers. Early
/// on purpose: everything after `L` is what the reattach has to recover,
/// so a small `L` makes the recovered range large.
const KILL_AFTER_MARKERS: usize = 3;

/// Bytes of the canonical stream used to locate it inside what the client
/// painted. Long enough to be unique (it spans the pid line, the echoed
/// go token and the start of the first marker), short enough to be there
/// however little the client rendered.
const PROBE: usize = 32;

/// First line of the producer, carrying its own pid so SC5 can be checked
/// against the operating system rather than against the broker's opinion.
const PID_PREFIX: &str = "QSHPID=";

/// Printed once the producer has emitted every round.
const DONE_MARKER: &str = "QSHDONE";

/// Typed into the attached client to release the producer's burst loop.
/// Nothing else in the corpus looks like it, so the `read` cannot be
/// satisfied by anything but this test.
const GO_TOKEN: &str = "QSHGO";

/// Written to the session while nothing is attached, and read back out of
/// the ring. Both the pty's own line discipline and the `cat` the producer
/// exec'd into will emit it, so what this proves is that the pty and the
/// broker's write path are still live without a client — not that the
/// child is scheduling. (Once the child is *gone* the write fails outright
/// with `SESSION_CONFLICT`; that path has its own fixture.)
const ALIVE_MARKER: &str = "QSHALIVE";

/// The deterministic producer.
///
/// Numbered markers make any byte offset in the stream nameable; the
/// `yes` bursts between them are the high-throughput part `PLAN.md` Step 8
/// asks for. The `read` between the pid line and the loop is the gate that
/// turns "the kill was mid-stream" from a race into a fact: no burst
/// exists until a live client types [`GO_TOKEN`]. It ends in `exec cat`
/// rather than exiting so that the pty's child is still there to be
/// interrogated after the client is gone — `exec` keeps the pid it
/// announced.
fn producer_script() -> String {
    format!(
        "printf '{PID_PREFIX}%s\\n' $$\n\
         read go\n\
         i=0\n\
         while [ $i -lt {ROUNDS} ]; do\n\
         printf 'QSHMARK-%04d\\n' $i\n\
         yes | head -c {BURST}\n\
         i=$((i + 1))\n\
         done\n\
         printf '{DONE_MARKER}\\n'\n\
         exec cat\n"
    )
}

// ---------------------------------------------------------------------------
// guards
// ---------------------------------------------------------------------------

/// Owns the remote pty child's **process group**.
///
/// The session's child is a process-group leader in its own session
/// (`setsid`), so it survives `qsh serve` being killed. Without this
/// guard a failing assertion would leave an `sh` (and possibly a `yes`)
/// running on the developer's machine for ever.
struct ChildGroupGuard(Pid);

impl ChildGroupGuard {
    /// Whether the group leader still exists (signal 0).
    fn alive(&self) -> bool {
        kill(self.0, None).is_ok()
    }
}

impl Drop for ChildGroupGuard {
    fn drop(&mut self) {
        let _ = killpg(self.0, NixSignal::SIGKILL);
        let _ = kill(self.0, NixSignal::SIGKILL);
    }
}

/// A `qsh` client running under its own pty, killed and reaped on drop.
struct ClientGuard {
    session: OsSession,
    reaped: bool,
    /// Markers a single `expect()` scan turned up beyond the one it
    /// reported, queued in stream order and drained before the next scan.
    /// See [`ClientGuard::next_marker`] for why this exists instead of
    /// `Session::set_expect_lazy`.
    pending_markers: std::collections::VecDeque<(Vec<u8>, usize)>,
}

impl ClientGuard {
    /// Spawn `qsh <args>` under a pty with the sandbox's isolated dirs.
    fn spawn(sandbox: &Sandbox, args: &[&str]) -> Self {
        let mut command: Command = sandbox.command(args);
        command.env("TERM", "xterm-256color");
        let mut session = Session::spawn(command).expect("spawn qsh under a pty");
        session.set_expect_timeout(Some(EXPECT_TIMEOUT));
        Self {
            session,
            reaped: false,
            pending_markers: std::collections::VecDeque::new(),
        }
    }

    /// Consume the client's output up to and including the producer's pid
    /// line, returning the bytes consumed and the pid.
    ///
    /// The line terminator is part of the pattern: a bare `\d+` would
    /// happily match the first three digits of a five-digit pid that is
    /// still arriving, and the group this test kills is chosen from it.
    fn next_pid(&mut self) -> (Vec<u8>, i32) {
        let pattern = format!(r"{PID_PREFIX}\d+\r?\n");
        let found = self
            .session
            .expect(Regex(pattern.as_str()))
            .unwrap_or_else(|err| panic!("the producer never announced its pid: {err}"));
        let matched = found.get(0).expect("a match has group 0").to_vec();
        let pid: i32 = std::str::from_utf8(&matched)
            .expect("the producer's prologue is ASCII")
            .trim()
            .trim_start_matches(PID_PREFIX)
            .parse()
            .expect("the producer's pid");
        let mut bytes = found.before().to_vec();
        bytes.extend_from_slice(&matched);
        (bytes, pid)
    }

    /// Type at the client the way a person does — into its pty, so the
    /// bytes travel the client's own input path and the writer lease stays
    /// where it is. (An `Ops`-side write would steal the lease and print a
    /// diagnostic into the very capture `L` is measured from.) Enter is
    /// CR, exactly what a terminal sends.
    fn type_line(&mut self, text: &str) {
        self.session
            .send(format!("{text}\r"))
            .expect("type at the client's pty");
    }

    /// Consume the client's output up to and including the next
    /// `QSHMARK-NNNN`, returning the bytes consumed and the marker's
    /// index.
    ///
    /// A single non-blocking `expect()` scan can turn up more than one
    /// occurrence: the producer's burst loop free-runs once the read gate
    /// opens (`producer_script`'s doc comment), so a test-thread poll that
    /// lands a round or more behind can find two markers already sitting in
    /// the buffer. `expectrl`'s greedy `expect()` (`sync_session.rs`,
    /// `expect_gready`) reports only the first such occurrence
    /// (`Captures::get(0)`) but consumes the stream through the *last* one
    /// it saw (`Captures::right_most_index`) — trusting `get(0)` alone
    /// would silently drop every marker strictly in between, which is
    /// exactly the byte this file's round-order assertion would need back.
    /// (Forcing single-occurrence scans via `Session::set_expect_lazy` was
    /// tried and rejected: it reads one byte per non-blocking syscall with
    /// no batching, and consuming just the ~6 KiB burst between two markers
    /// that way outlasts the producer's entire unthrottled run, turning
    /// "killed mid-stream" into "killed after the producer finished" on any
    /// reasonably fast machine.) Instead, every occurrence the scan
    /// reports is sliced out of `Captures::as_bytes()` — the same span
    /// `expect()` already consumed, so no extra pty reads — and queued in
    /// stream order; only the first is returned here, and the rest are
    /// served from the queue, without another scan, before the next call
    /// touches the pty again.
    fn next_marker(&mut self) -> (Vec<u8>, usize) {
        if let Some(pending) = self.pending_markers.pop_front() {
            return pending;
        }
        let found = self
            .session
            .expect(Regex(r"QSHMARK-\d{4}"))
            .unwrap_or_else(|err| panic!("the client never rendered another marker: {err}"));
        // Everything the scan consumed, from where the previous call (or
        // `next_pid`) left off through the end of the last occurrence —
        // exactly `Captures::before()` generalised to more than one match.
        let consumed = found.as_bytes();
        let mut at = 0usize;
        while let Some(hit) = find(&consumed[at..], b"QSHMARK-") {
            let start = at + hit;
            let end = start + MARKER_MATCH_LEN;
            let index: usize = std::str::from_utf8(&consumed[start + "QSHMARK-".len()..end])
                .expect("markers are ASCII")
                .parse()
                .expect("marker index");
            let mut bytes = consumed[at..start].to_vec();
            bytes.extend_from_slice(&consumed[start..end]);
            self.pending_markers.push_back((bytes, index));
            at = end;
        }
        self.pending_markers
            .pop_front()
            .expect("the regex matched, so the scan queued at least one marker")
    }

    /// `kill -9` the client — no grace, no unwind, no goodbye on the
    /// wire — and reap it, asserting that is really how it died.
    fn sigkill_and_reap(&mut self) {
        self.session
            .get_process_mut()
            .signal(Signal::SIGKILL)
            .expect("SIGKILL the client");
        let status = self
            .session
            .get_process()
            .wait()
            .expect("wait for the killed client");
        self.reaped = true;
        assert!(
            matches!(status, WaitStatus::Signaled(_, Signal::SIGKILL, _)),
            "the client was supposed to die of SIGKILL, not {status:?}"
        );
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.session.get_process_mut().signal(Signal::SIGKILL);
        let _ = self.session.get_process().wait();
    }
}

// ---------------------------------------------------------------------------
// reading the ring
// ---------------------------------------------------------------------------

/// One deadline-bounded sweep of the cursor-pull primitive.
struct Sweep {
    /// Output bytes, concatenated in delivery order.
    bytes: Vec<u8>,
    /// `(start_offset, len)` of every `session.output` event.
    frames: Vec<(u64, usize)>,
    /// Any `session.gap` seen: `(requested_after, available_from)`.
    gaps: Vec<(u64, u64)>,
    /// The cursor the sweep stopped at.
    end: u64,
}

impl Sweep {
    /// The frames must tile `[start, end)` exactly: each one begins where
    /// the previous ended. That is what "no loss, no duplication" means
    /// when the cursor is a cumulative byte offset (`docs/CLI.md` §2.3).
    fn assert_tiles_from(&self, start: u64, what: &str) {
        assert!(
            self.gaps.is_empty(),
            "{what}: unexpected gap(s) {:?}",
            self.gaps
        );
        let mut expected = start;
        for (index, (offset, len)) in self.frames.iter().enumerate() {
            assert_eq!(
                *offset,
                expected,
                "{what}: frame {index} starts at {offset} but the stream had reached \
                 {expected} — {}",
                if *offset > expected {
                    "bytes were lost"
                } else {
                    "bytes were redelivered"
                }
            );
            expected += *len as u64;
        }
        assert_eq!(expected, self.end, "{what}: frames do not reach the cursor");
    }
}

/// Pull from `reader` until `stop` says the sweep is complete, or fail
/// after [`PULL_DEADLINE`].
///
/// `stop` is handed the bytes accumulated so far and the current cursor.
fn sweep(reader: &mut SessionReader, what: &str, stop: impl Fn(&[u8], u64) -> bool) -> Sweep {
    let start = reader.cursor().0;
    let mut out = Sweep {
        bytes: Vec::new(),
        frames: Vec::new(),
        gaps: Vec::new(),
        end: start,
    };
    let deadline = Instant::now() + PULL_DEADLINE;
    loop {
        if stop(&out.bytes, out.end) {
            return out;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: not complete within {PULL_DEADLINE:?} \
             (cursor {}, {} bytes, gaps {:?})",
            out.end,
            out.bytes.len(),
            out.gaps
        );
        let pull = reader
            .pull()
            .unwrap_or_else(|err| panic!("{what}: session.read failed: {err}"));
        for event in &pull.data.events {
            match event {
                SessionEvent::Output {
                    sequence, data_b64, ..
                } => {
                    use base64::Engine as _;
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(data_b64.as_bytes())
                        .expect("session output is Base64");
                    out.frames.push((sequence - data.len() as u64, data.len()));
                    out.bytes.extend_from_slice(&data);
                }
                SessionEvent::Gap {
                    requested_after,
                    available_from,
                    ..
                } => out.gaps.push((*requested_after, *available_from)),
                _ => {}
            }
        }
        out.end = pull.data.next_after;
    }
}

/// A reader positioned at `after` on a fresh connection — the shape a
/// client that just came back from the dead has: nothing but the session
/// handle and the offset it last saw.
fn reader_from(ops: &Ops, session_ref: &str, after: u64) -> SessionReader {
    ops.session_reader(SessionReadReq {
        session_ref: session_ref.to_string(),
        after_sequence: after,
        wait_ms: Some(PULL_WAIT_MS),
        limit_bytes: None,
        ctl_after: None,
    })
    .expect("session.read")
}

/// Byte-level `find`, because the corpus is a byte stream and `str` would
/// have to be lossy about it.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The one check in this file whose oracle is not the ring.
///
/// `full` and `tail` are both pulled from the same `ReplayRing` through
/// the same primitive, so between them a byte the broker never appended is
/// invisible: it is missing from both, identically, and every sequence
/// still tiles. The producer's script, however, fixes the corpus: `ROUNDS`
/// markers, numbered in order, each followed by exactly `BURST / 2` `y`s
/// on their own lines. Every byte of every round is accounted for here, so
/// a chunk lost on the way *into* the ring fails, naming the round it went
/// missing in.
///
/// Every byte, but not every *stride*: the pty's `ONLCR` is applied inside
/// the tty write path, and a write that is only partially accepted (the
/// line discipline's buffer filling under load is enough) can re-emit the
/// `\r` of a `\r\n` it had already started. That adds a byte and moves the
/// nominal [`MARKER_STRIDE`] without losing anything, which is why the
/// accounting below tolerates *extra* CRs and nothing else: the `y` and
/// `\n` counts are exact, and no byte outside the marker text, `y`, `\r`
/// and `\n` is allowed to exist at all.
fn assert_producer_corpus(bytes: &[u8]) {
    /// `QSHMARK-NNNN`, without its line terminator.
    const MARKER_TEXT: usize = 12;

    let mut markers: Vec<(usize, usize)> = Vec::new(); // (offset, index)
    let mut at = 0usize;
    while let Some(hit) = find(&bytes[at..], b"QSHMARK-") {
        let offset = at + hit;
        let digits = &bytes[offset + "QSHMARK-".len()..];
        let index: usize = std::str::from_utf8(&digits[..4.min(digits.len())])
            .expect("markers are ASCII")
            .parse()
            .expect("marker index");
        markers.push((offset, index));
        at = offset + "QSHMARK-".len();
    }

    assert_eq!(
        markers.len(),
        ROUNDS,
        "the stream carries {} of the {ROUNDS} markers the producer printed — \
         bytes went missing before the ring ever saw them",
        markers.len()
    );
    for (round, (offset, index)) in markers.iter().enumerate() {
        assert_eq!(
            *index, round,
            "marker {round} of the stream reads QSHMARK-{index:04} (at byte {offset}) — \
             the corpus is out of order or a marker is duplicated"
        );
    }
    for pair in markers.windows(2) {
        let (from, round) = pair[0];
        let (to, _) = pair[1];
        let round_bytes = &bytes[from..to];
        let count = |b: u8| round_bytes.iter().filter(|got| **got == b).count();
        let (ys, newlines, crs) = (count(b'y'), count(b'\n'), count(b'\r'));
        assert_eq!(
            ys,
            BURST / 2,
            "round {round} carries {ys} `y`s, not the {} `yes | head -c {BURST}` writes — \
             bytes were lost before the ring saw them",
            BURST / 2
        );
        assert_eq!(
            newlines,
            BURST / 2 + 1,
            "round {round} carries {newlines} line ends, not the {} its marker plus burst \
             produce",
            BURST / 2 + 1
        );
        assert!(
            crs >= newlines,
            "round {round} carries {crs} CRs for {newlines} line ends — the pty's ONLCR \
             cannot drop one"
        );
        assert!(
            round_bytes.len() >= MARKER_STRIDE,
            "round {round} is {} bytes, below the {MARKER_STRIDE} its marker line and \
             burst occupy at the nominal `ONLCR` expansion",
            round_bytes.len()
        );
        assert_eq!(
            round_bytes.len(),
            MARKER_TEXT + ys + newlines + crs,
            "round {round} carries {} bytes that are neither its marker text nor `y`, \
             `\\r`, `\\n`",
            round_bytes.len() - (MARKER_TEXT + ys + newlines + crs).min(round_bytes.len())
        );
    }
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

/// **DoD 3 (SC4 + SC5).** `kill -9` the attached client mid-stream; the
/// session and its child survive it, and the bytes the dead client never
/// got are still there, exactly once each, starting exactly where it
/// stopped.
#[test]
fn a_sigkilled_client_loses_no_bytes_and_the_session_survives_it() {
    let fleet = Fleet::start();
    let ops = Ops::new(Paths::new(
        fleet.client.config_dir().to_path_buf(),
        fleet.client.state_dir().to_path_buf(),
    ));

    let session_ref = ops
        .session_open(SessionOpenReq {
            host: HOST_ALIAS.to_string(),
            argv: vec!["sh".to_string(), "-c".to_string(), producer_script()],
            env: vec![EnvVar {
                name: "LANG".into(),
                value: "C".into(),
            }],
            term: Some("xterm-256color".into()),
            cols: Some(80),
            rows: Some(24),
            user: None,
        })
        .expect("session.open")
        .session_ref;

    // ---- a real client, under a real pty, watching a real stream ----
    let mut client = ClientGuard::spawn(&fleet.client, &["attach", &session_ref]);
    let mut rendered: Vec<u8> = Vec::new();

    // The producer announced its own pid on its first line and is now
    // parked on `read`: take ownership of its process group before a
    // single burst exists, and before anything else can fail.
    let (prologue, child_pid) = client.next_pid();
    rendered.extend_from_slice(&prologue);
    let child = ChildGroupGuard(Pid::from_raw(child_pid));

    // ---- release the producer; the stream starts here, live ----
    // Everything the client renders from now on is output it is *tailing*,
    // not replay backlog it is catching up on.
    client.type_line(GO_TOKEN);
    for round in 0..KILL_AFTER_MARKERS {
        let (bytes, index) = client.next_marker();
        rendered.extend_from_slice(&bytes);
        assert_eq!(
            index, round,
            "the client rendered QSHMARK-{index:04} where round {round} belongs"
        );
    }

    // ---- the client dies here, and nothing is told ----
    client.sigkill_and_reap();

    // ---- SC5: the remote pty and its child outlive the client ----
    assert!(
        child.alive(),
        "the session's child died with the client — SC5"
    );
    let after_kill = ops
        .session_get(SessionGetReq {
            session_ref: session_ref.clone(),
        })
        .expect("session.get");
    assert_eq!(
        after_kill.state, "running",
        "the session did not survive its client — SC5"
    );
    // Where the stream had got to when the corpse was examined — an upper
    // bound on where it was when the signal landed, one round trip
    // earlier. Checked against the producer's own finish line below.
    let at_kill = after_kill.last_sequence;

    // ---- the canonical stream, from the ring, once the producer is done ----
    let mut whole = reader_from(&ops, &session_ref, 0);
    let full = sweep(&mut whole, "canonical sweep", |bytes, _| {
        find(bytes, DONE_MARKER.as_bytes()).is_some()
    });
    // No gap anywhere in the canonical sweep is what makes the byte
    // comparison below meaningful: the DoD promises byte-identity only
    // while the ring has not evicted (`docs/CLI.md` §6.4).
    full.assert_tiles_from(0, "canonical sweep");
    let end = full.end;
    // …and that the ring holds what the child wrote, judged against the
    // producer's script rather than against the ring itself.
    assert_producer_corpus(&full.bytes);

    // ---- the kill really was mid-stream ----
    //
    // The DoD condition is "`yes` 실행 중". The `read` gate makes the
    // client a *tail* of a live stream by construction — the producer
    // cannot have filled the ring before a client existed, because it had
    // not started. What remains to rule out is the other end: that the
    // producer had already run to completion when the signal landed. The
    // ring's cursor taken off the corpse answers it, and answers it
    // conservatively — the sample costs a round trip the producer keeps
    // writing through, so `at_kill` is an over-estimate of where the
    // stream was when the client actually died. A test that degraded into
    // "replay a finished ring" fails here.
    let done_at = find(&full.bytes, DONE_MARKER.as_bytes())
        .expect("the producer's finish line is in the canonical stream") as u64;
    assert!(
        at_kill < done_at,
        "the producer had already written its finish line (offset {done_at}) by the time \
         the dead client was examined at {at_kill} — nothing was in flight, so this is a \
         replay test, not a mid-stream kill"
    );

    // ---- L: the offset the dead client had provably rendered ----
    //
    // Measured, not assumed: the canonical stream is located inside what
    // the client painted and then followed byte for byte, and `L` is where
    // the two stop agreeing. Deriving it this way is what makes the SC4
    // comparison below a *byte-range* comparison on both halves of the
    // seam rather than a claim about the half nobody checked.
    //
    // The anchor is the echo of the go token, not offset `0`, because the
    // client's terminal also carries the client's own diagnostics (`qsh:
    // the writer lease moved to …` — stderr shares the pty, `docs/CLI.md`
    // §2.2), and the lease it takes at attach lands one such line between
    // the replayed prologue and the live stream. Anchoring at the token
    // starts the comparison at the first canonical byte the client can
    // only have rendered *live*, and a diagnostic anywhere after it would
    // cut `L` short — never lengthen it.
    let anchor = find(&full.bytes, GO_TOKEN.as_bytes())
        .expect("the go token's echo belongs to the canonical stream");
    let probe = &full.bytes[anchor..(anchor + PROBE).min(full.bytes.len())];
    let start = find(&rendered, probe).unwrap_or_else(|| {
        panic!(
            "the killed client never rendered the live stream; it showed {:?}",
            String::from_utf8_lossy(&rendered[..400.min(rendered.len())])
        )
    });
    let l = anchor as u64
        + rendered[start..]
            .iter()
            .zip(full.bytes[anchor..].iter())
            .take_while(|(painted, canonical)| painted == canonical)
            .count() as u64;
    // A floor on the half of the seam the ring did not produce: below a
    // full burst the pty capture is too short to be following the stream
    // rather than agreeing with it by accident.
    assert!(
        l - anchor as u64 >= BURST as u64,
        "the client only rendered {} contiguous bytes of the live stream before dying, \
         which is too little to anchor the seam against",
        l - anchor as u64
    );
    assert!(
        end - l >= (ROUNDS * BURST) as u64,
        "the client consumed all but {} bytes before it was killed, so almost nothing \
         was left to recover — raise ROUNDS or lower KILL_AFTER_MARKERS",
        end - l
    );

    // ---- SC4: reattach at L and compare byte ranges ----
    let mut resumed = reader_from(&ops, &session_ref, l);
    let tail = sweep(&mut resumed, "resumed sweep", |_, cursor| cursor >= end);
    tail.assert_tiles_from(l, "resumed sweep");
    assert_eq!(
        tail.frames.first().map(|(offset, _)| *offset),
        Some(l),
        "the resumed stream did not restart at the offset the dead client stopped at"
    );
    assert_eq!(
        tail.bytes.len(),
        (end - l) as usize,
        "the resumed stream is {} bytes for a {} byte range",
        tail.bytes.len(),
        end - l
    );
    assert!(
        tail.bytes == full.bytes[l as usize..end as usize],
        "the bytes after {l} are not byte-identical to the canonical stream"
    );
    // Said the way the DoD says it: what the dead client had, plus what
    // the reattach delivered, *is* the stream.
    let mut rejoined = full.bytes[..l as usize].to_vec();
    rejoined.extend_from_slice(&tail.bytes);
    assert!(
        rejoined == full.bytes[..end as usize],
        "concatenating at the seam did not reproduce the canonical stream"
    );

    // ---- SC5, behavioural: the pty still carries input with no client ----
    ops.session_write_bytes(&session_ref, format!("{ALIVE_MARKER}\n").into_bytes())
        .expect("session.write");
    let mut after = reader_from(&ops, &session_ref, end);
    let echoed = sweep(&mut after, "liveness sweep", |bytes, _| {
        find(bytes, ALIVE_MARKER.as_bytes()).is_some()
    });
    assert!(echoed.gaps.is_empty(), "{:?}", echoed.gaps);

    // ---- and a real reattach still authenticates ----
    // The SIGKILL happened after the client had made its successor resume
    // token durable, so the credential is still good (ADR-0007). This is
    // the half of SC4 the cursor-pull cannot show: the session is not
    // merely readable, it is *attachable* again.
    //
    // It replays from `0`, and that is the contract, not a shortcut:
    // `SessionAttachReq` carries no offset because a user-initiated
    // reattach hands the terminal its scrollback back (`PLAN.md` Step 6
    // invariant; `Ops::session_attach` sends `last_output_seq: 0`). The
    // wire seam that resumes at a real `L` is the driver's reconnect path,
    // and `attach_recovery.rs` is where it is byte-checked — a process
    // that died of SIGKILL has no cursor left to present, which is the
    // whole reason `L` is recovered from the pty here.
    let mut stream = ops
        .session_attach(
            SessionAttachReq {
                session_ref: session_ref.clone(),
                no_steal: false,
            },
            &[],
        )
        .expect("a reattach after the client was killed");
    assert_eq!(
        stream.replay_from(),
        0,
        "nothing was evicted, so a fresh attach replays the whole ring"
    );
    assert!(
        stream.next_event().is_some(),
        "the reattached stream delivered nothing"
    );
    stream.close();

    // ---- teardown: close the session and prove the group is gone ----
    whole.close();
    resumed.close();
    after.close();
    ops.session_close(SessionCloseReq {
        session_ref: session_ref.clone(),
        signal: Some("KILL".to_string()),
    })
    .expect("session.close");
    // Reaping happens in another process, so there is no in-process event
    // to await; this polls an operating-system fact under a hard deadline
    // (the same shape as `common::wait_for_audit`), never a fixed sleep
    // standing in for synchronisation.
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.alive() {
        assert!(
            Instant::now() < deadline,
            "session.close left the child process group running"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
