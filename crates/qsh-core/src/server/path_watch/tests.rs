//! ADR-0067: the path observer, over a fake path source and virtual time.

use super::*;
use crate::audit::{FailingAuditSink, MemoryAuditSink};
use qsh_transport::{PEER_KEY_LEN, PeerKey};
use std::sync::Mutex;

fn keyed(path: PeerPath) -> PeerAddr {
    PeerAddr::Keyed {
        key: PeerKey([7; PEER_KEY_LEN]),
        path,
    }
}

fn relay() -> PeerAddr {
    keyed(PeerPath::Relay("https://relay.example.test/".into()))
}

fn direct(port: u16) -> PeerAddr {
    keyed(PeerPath::Direct(
        format!("192.0.2.9:{port}").parse().unwrap(),
    ))
}

/// A path source that plays `script` one entry per sample and then repeats
/// the last.
struct Script {
    script: Vec<PeerAddr>,
    next: Mutex<usize>,
}

impl Script {
    fn new(script: Vec<PeerAddr>) -> Self {
        Self {
            script,
            next: Mutex::new(0),
        }
    }
    fn sample(&self) -> PeerAddr {
        let mut next = self.next.lock().unwrap();
        let i = (*next).min(self.script.len() - 1);
        *next += 1;
        self.script[i].clone()
    }
}

const TICK: Duration = Duration::from_secs(1);

/// Run the observer over `script` (the first entry is the baseline sampled at
/// start) for `ticks` samples, then close.
async fn run(script: Vec<PeerAddr>, ticks: u64, audit: &dyn AuditSink) {
    let script = Script::new(script);
    let closed = async {
        tokio::time::sleep(TICK * ticks as u32 + TICK / 2).await;
    };
    observe(
        || script.sample(),
        closed,
        TICK,
        audit,
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn relay_direct_relay_leaves_two_path_records() {
    let sink = MemoryAuditSink::new();
    run(
        vec![
            relay(), // baseline
            relay(),
            direct(1),
            direct(2), // second consecutive direct sample (other port)
            direct(2),
            relay(),
            relay(),
        ],
        6,
        &sink,
    )
    .await;
    let records = sink.records();
    assert_eq!(records.len(), 2, "{records:?}");
    let (up, down) = (&records[0], &records[1]);
    for r in &records {
        assert_eq!(r.action, "connect");
        assert_eq!(r.resource, "path");
        assert_eq!(r.decision, "allow");
        assert_eq!(r.rule, None);
        assert_eq!(r.request_id, "-");
        assert_eq!(r.principal, "device:laptop");
        assert_eq!(r.auth_path, "pin");
        assert!(r.peer_addr.starts_with("iroh:"), "{}", r.peer_addr);
    }
    assert_eq!(up.peer_path.as_deref(), Some("direct"));
    assert_eq!(up.relay, None);
    assert_eq!(down.peer_path.as_deref(), Some("relay"));
    assert_eq!(down.relay.as_deref(), Some("https://relay.example.test"));
}

#[tokio::test(start_paused = true)]
async fn a_one_sample_blip_leaves_no_record() {
    let sink = MemoryAuditSink::new();
    run(
        vec![relay(), relay(), direct(1), relay(), relay(), relay()],
        5,
        &sink,
    )
    .await;
    assert!(sink.records().is_empty(), "{:?}", sink.records());
}

#[tokio::test(start_paused = true)]
async fn an_address_change_inside_one_kind_leaves_no_record() {
    let sink = MemoryAuditSink::new();
    run(
        vec![direct(1), direct(2), direct(3), direct(4), direct(5)],
        4,
        &sink,
    )
    .await;
    assert!(sink.records().is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_seventeenth_change_is_not_written() {
    let sink = MemoryAuditSink::new();
    // Baseline relay, then 17 settled flips, each held for two samples.
    let mut script = vec![relay()];
    for i in 0..17 {
        let p = if i % 2 == 0 { direct(1) } else { relay() };
        script.push(p.clone());
        script.push(p);
    }
    let ticks = script.len() as u64 + 2;
    run(script, ticks, &sink).await;
    assert_eq!(sink.records().len(), MAX_PATH_RECORDS as usize);
}

#[tokio::test(start_paused = true)]
async fn a_failing_writer_does_not_stop_the_observer() {
    let sink = FailingAuditSink::new();
    sink.fail();
    let script = Script::new(vec![
        relay(),
        direct(1),
        direct(1),
        direct(1),
        relay(),
        relay(),
    ]);
    let closed = async {
        tokio::time::sleep(TICK * 20).await;
    };
    // The first change fails to write; the observer lives on and the later
    // one lands once the writer recovers.
    let recover = async {
        while *script.next.lock().unwrap() < 4 {
            tokio::time::sleep(TICK).await;
        }
        sink.clear();
    };
    let principal = Principal::Device("laptop".into());
    let obs = observe(
        || script.sample(),
        closed,
        TICK,
        &sink,
        &principal,
        AuthPath::Pin,
    );
    tokio::join!(obs, recover);
    let records = sink.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].peer_path.as_deref(), Some("relay"));
}

#[tokio::test(start_paused = true)]
async fn a_socket_connection_never_gets_a_path_record() {
    let sink = MemoryAuditSink::new();
    let sock: PeerAddr = "192.0.2.7:4433".parse().unwrap();
    // Returns at once, without waiting for the close.
    let script = Script::new(vec![sock]);
    observe(
        || script.sample(),
        std::future::pending::<()>(),
        TICK,
        &sink,
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
    )
    .await;
    assert!(sink.records().is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_observer_ends_when_the_connection_closes() {
    let sink = MemoryAuditSink::new();
    let script = Script::new(vec![relay()]);
    observe(
        || script.sample(),
        async {
            tokio::time::sleep(Duration::from_millis(2500)).await;
        },
        TICK,
        &sink,
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
    )
    .await;
    assert!(sink.records().is_empty());
}
