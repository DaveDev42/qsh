//! L5 — Ctrl-C on `qsh cp` (ADR-0029 decision 11, `docs/CLI.md` §6.21),
//! PLAN M15 Step 15 (the review findings of Step 14).
//!
//! The first SIGINT cancels the copy wherever it is: mid-transfer, or still
//! dialing. The second ends the process at once. A canceled copy exits 255
//! with `CANCELED` and leaves no temp file behind.

#![cfg(unix)]

use crate::common::{Sandbox, poll_until};
use crate::cp_e2e::{Forward, Reverse, assert_no_part_files};

use std::net::UdpSocket;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;

/// A sparse file big enough that a loopback transfer takes seconds, so the
/// signal always lands mid-transfer.
const BIG: u64 = 1 << 30;

fn spawn(sandbox: &Sandbox, args: &[&str]) -> Child {
    let mut command: Command = sandbox.command(args);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qsh cp")
}

fn interrupt(child: &Child) {
    kill(Pid::from_raw(child.id() as i32), Signal::SIGINT).expect("send SIGINT");
}

/// Wait for `child` to end within `limit`, killing it (and failing) if not.
fn finish(mut child: Child, limit: Duration) -> (i32, Value, String) {
    let until = Instant::now() + limit;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None if Instant::now() >= until => {
                let _ = child.kill();
                let out = child.wait_with_output().expect("reap");
                panic!(
                    "qsh cp did not end within {limit:?} of the interrupt; stderr: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let out = child.wait_with_output().expect("collect output");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let text = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let line = text
        .lines()
        .last()
        .unwrap_or_else(|| panic!("no envelope on stdout; stderr: {stderr}"));
    let envelope: Value = serde_json::from_str(line).expect("envelope is JSON");
    (
        out.status.code().unwrap_or_else(|| {
            panic!("qsh cp died of a signal instead of canceling cleanly; stderr: {stderr}")
        }),
        envelope,
        stderr,
    )
}

/// Whether `dir` holds a `.part` temp file.
fn has_part_file(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|read| {
        read.flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(".part"))
    })
}

fn sparse_file(path: &Path) {
    let file = std::fs::File::create(path).expect("create sparse file");
    file.set_len(BIG).expect("size sparse file");
}

/// Start `args`, wait until a temp file shows up in `watch` (the transfer
/// is under way), interrupt, and check the whole story: exit 255,
/// `CANCELED`, and every temp file gone from both `dirs`.
fn cancel_mid_transfer(sandbox: &Sandbox, args: &[&str], watch: &Path, dirs: &[&Path]) {
    let child = spawn(sandbox, args);
    poll_until(
        "the transfer to create its temp file",
        Duration::from_secs(30),
        || has_part_file(watch).then_some(()),
    );
    interrupt(&child);
    let (code, envelope, stderr) = finish(child, Duration::from_secs(20));
    assert_eq!(code, 255, "{envelope} / {stderr}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["error"]["code"], "CANCELED", "{envelope}");
    assert_eq!(envelope["error"]["details"]["copied"], 0, "{envelope}");
    // The host removes its temp file when the stream dies, which is a beat
    // after the client is gone. A client that closed without the host
    // hearing of it would leave the file until the 45 s idle timeout, so
    // this bound is what pins `Connected::settle_before_close`.
    poll_until(
        "every temp file to be removed",
        Duration::from_secs(15),
        || dirs.iter().all(|d| !has_part_file(d)).then_some(()),
    );
    for dir in dirs {
        assert_no_part_files(dir);
    }
}

#[test]
fn cp_canceled_mid_transfer_exits_255_and_leaves_no_temp_file() {
    let rig = Forward::start();
    let work = rig.work.path();
    let big = work.join("big.bin");
    sparse_file(&big);
    let outbound = work.join("outbound");
    let inbound = work.join("inbound");
    std::fs::create_dir(&outbound).unwrap();
    std::fs::create_dir(&inbound).unwrap();

    // put: the temp file is on the host.
    let remote = rig.remote("outbound/big.bin");
    cancel_mid_transfer(
        &rig.client,
        &["cp", "--json", big.to_str().unwrap(), &remote],
        &outbound,
        &[&outbound, &inbound],
    );
    assert!(
        !outbound.join("big.bin").exists(),
        "a canceled put kept a file"
    );

    // get: the temp file is on this machine.
    let source = rig.remote("big.bin");
    cancel_mid_transfer(
        &rig.client,
        &["cp", "--json", &source, inbound.to_str().unwrap()],
        &inbound,
        &[&outbound, &inbound],
    );
    assert!(
        !inbound.join("big.bin").exists(),
        "a canceled get kept a file"
    );
}

#[test]
fn cp_canceled_mid_transfer_exits_255_and_leaves_no_temp_file_reverse() {
    let rig = Reverse::start();
    let work = rig.work.path();
    let big = work.join("big.bin");
    sparse_file(&big);
    let outbound = work.join("outbound");
    let inbound = work.join("inbound");
    std::fs::create_dir(&outbound).unwrap();
    std::fs::create_dir(&inbound).unwrap();

    let remote = rig.remote("outbound/big.bin");
    cancel_mid_transfer(
        &rig.controller,
        &["cp", "--json", big.to_str().unwrap(), &remote],
        &outbound,
        &[&outbound, &inbound],
    );
    let source = rig.remote("big.bin");
    cancel_mid_transfer(
        &rig.controller,
        &["cp", "--json", &source, inbound.to_str().unwrap()],
        &inbound,
        &[&outbound, &inbound],
    );
}

/// A client whose host is a UDP socket that swallows every datagram: the
/// QUIC handshake can never finish, so the copy is stuck dialing.
fn blackholed_client() -> (UdpSocket, Sandbox, tempfile::TempDir) {
    let hole = UdpSocket::bind("127.0.0.1:0").expect("bind blackhole");
    hole.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    let addr = hole.local_addr().expect("blackhole addr").to_string();
    client.trust_add(crate::common::HOST_ALIAS, Some(&addr), &host.fingerprint());
    (hole, client, tempfile::tempdir().expect("work dir"))
}

#[test]
fn cp_canceled_during_the_dial_ends_canceled_promptly() {
    let (hole, client, work) = blackholed_client();
    let src = work.path().join("src.txt");
    std::fs::write(&src, b"x").unwrap();
    let dst = format!("{}:/tmp/never", crate::common::HOST_ALIAS);
    let child = spawn(&client, &["cp", "--json", src.to_str().unwrap(), &dst]);

    // The first QUIC Initial proves the client is dialing, and that the
    // interrupt handler (armed before the dial) is in place.
    let mut buf = [0u8; 2048];
    hole.recv_from(&mut buf)
        .expect("the client's first datagram");
    let sent = Instant::now();
    interrupt(&child);
    let (code, envelope, stderr) = finish(child, Duration::from_secs(5));
    assert_eq!(code, 255, "{envelope} / {stderr}");
    assert_eq!(envelope["error"]["code"], "CANCELED", "{envelope}");
    assert!(
        sent.elapsed() < Duration::from_secs(5),
        "the dial took {:?} to give up",
        sent.elapsed()
    );
}

/// Two interrupts in a row end the process with 255 and no hang. Whether the
/// first one already wound the dial down or the second one cut it short is
/// a race the test cannot (and need not) pin: the contract is the exit
/// value and the bound on time. The second-interrupt branch itself is three
/// lines in `arm_cancel_on_interrupt`.
#[test]
fn cp_second_interrupt_exits_255_without_waiting() {
    let (hole, client, work) = blackholed_client();
    let src = work.path().join("src.txt");
    std::fs::write(&src, b"x").unwrap();
    let dst = format!("{}:/tmp/never", crate::common::HOST_ALIAS);
    // Human mode: the process must end by itself, with no envelope to read.
    let mut child = spawn(&client, &["cp", src.to_str().unwrap(), &dst]);
    let mut buf = [0u8; 2048];
    hole.recv_from(&mut buf)
        .expect("the client's first datagram");
    interrupt(&child);
    interrupt(&child);
    let until = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            panic!("two interrupts did not end qsh cp within 5s");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(255), "{status:?}");
}
