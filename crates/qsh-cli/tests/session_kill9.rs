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
//! SC5 is three independent facts about the same corpse: the producer's
//! own pid (it prints `$$` as its first line) still answers `kill -0`, the
//! host still reports the session `running`, and the child *answers* —
//! input written while no client is attached comes back out of the ring.
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
/// The whole stream must stay comfortably inside the replay ring's 8 MiB
/// budget (`docs/PRD.md` §13): eviction would produce a `session.gap`,
/// and a gap is the one condition under which the DoD does *not* promise
/// byte-identity. At [`BURST`] bytes per round plus the pty's `\r\n`
/// expansion this is ≈ 1.5 MiB — a fifth of the budget.
const ROUNDS: usize = 240;

/// Bytes of `yes` between two markers, measured on the pipe (the pty's
/// `ONLCR` turns each `y\n` into `y\r\n`, so the stream carries 1.5×).
const BURST: usize = 4096;

/// The client is killed once it has *rendered* this many markers. Early
/// on purpose: everything after `L` is what the reattach has to recover,
/// so a small `L` makes the recovered range large.
const KILL_AFTER_MARKERS: usize = 3;

/// Bytes of the canonical stream used to locate it inside what the client
/// painted. Long enough to be unique (it spans the pid line and the first
/// marker), short enough to be there however little the client rendered.
const PROBE: usize = 32;

/// First line of the producer, carrying its own pid so SC5 can be checked
/// against the operating system rather than against the broker's opinion.
const PID_PREFIX: &str = "QSHPID=";

/// Printed once the producer has emitted every round.
const DONE_MARKER: &str = "QSHDONE";

/// Echoed back by the producer's final `cat` when input is written to a
/// session no client is attached to.
const ALIVE_MARKER: &str = "QSHALIVE";

/// The deterministic producer.
///
/// Numbered markers make any byte offset in the stream nameable; the
/// `yes` bursts between them are the high-throughput part `PLAN.md` Step 8
/// asks for. It ends in `exec cat` rather than exiting so that the pty's
/// child is still there to be interrogated after the client is gone —
/// `exec` keeps the pid it announced.
fn producer_script() -> String {
    format!(
        "printf '{PID_PREFIX}%s\\n' $$\n\
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
        }
    }

    /// Consume the client's output up to and including the next
    /// `QSHMARK-NNNN`, returning the bytes consumed and the marker's
    /// index.
    fn next_marker(&mut self) -> (Vec<u8>, usize) {
        let found = self
            .session
            .expect(Regex(r"QSHMARK-\d{4}"))
            .unwrap_or_else(|err| panic!("the client never rendered another marker: {err}"));
        let matched = found.get(0).expect("a match has group 0").to_vec();
        let index: usize = std::str::from_utf8(&matched)
            .expect("markers are ASCII")
            .trim_start_matches("QSHMARK-")
            .parse()
            .expect("marker index");
        let mut bytes = found.before().to_vec();
        bytes.extend_from_slice(&matched);
        (bytes, index)
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
    let mut last_marker = 0usize;
    for _ in 0..KILL_AFTER_MARKERS {
        let (bytes, index) = client.next_marker();
        rendered.extend_from_slice(&bytes);
        last_marker = index;
    }

    // The producer announced its own pid on its first line; take
    // ownership of its process group before anything can fail.
    let pid_line = std::str::from_utf8(&rendered)
        .expect("the producer's prologue is ASCII")
        .lines()
        .find_map(|line| line.trim().strip_prefix(PID_PREFIX).map(str::to_string))
        .unwrap_or_else(|| panic!("the producer never announced its pid: {rendered:?}"));
    let child = ChildGroupGuard(Pid::from_raw(
        pid_line.parse::<i32>().expect("the producer's pid"),
    ));

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

    // ---- L: the offset the dead client had provably rendered ----
    //
    // Measured, not assumed. The client's terminal also carries its own
    // diagnostics (`qsh: the writer lease moved to …` — stderr shares the
    // pty, `docs/CLI.md` §2.2), so the stream is located inside what was
    // painted and then followed byte for byte; `L` is where the two stop
    // agreeing. Deriving it this way is what makes the SC4 comparison
    // below a *byte-range* comparison on both halves of the seam rather
    // than a claim about the half nobody checked.
    let probe = &full.bytes[..PROBE.min(full.bytes.len())];
    let start = find(&rendered, probe).unwrap_or_else(|| {
        panic!(
            "the killed client never rendered the start of the stream; it showed {:?}",
            String::from_utf8_lossy(&rendered[..200.min(rendered.len())])
        )
    });
    let l = rendered[start..]
        .iter()
        .zip(full.bytes.iter())
        .take_while(|(painted, canonical)| painted == canonical)
        .count() as u64;
    assert!(
        l >= BURST as u64,
        "the client only rendered {l} contiguous bytes of the stream before dying, \
         which is too little to call this a mid-stream kill"
    );
    assert!(
        last_marker < ROUNDS / 4,
        "the client was killed at round {last_marker} of {ROUNDS} — that is not \
         mid-stream any more"
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

    // ---- SC5, behavioural: the child answers with no client attached ----
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
    let mut stream = ops
        .session_attach(SessionAttachReq {
            session_ref: session_ref.clone(),
            no_steal: false,
        })
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
