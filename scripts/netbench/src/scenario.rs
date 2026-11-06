//! Workloads. The host (server) sends screen states and bulk and echoes keys;
//! the client sends keys and measures everything.

use crate::net::now_ns;
use crate::profile::{Carrier, Isolation, Kind, Profile};
use crate::result::{Metrics, percentiles, round3};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout_at};

/// How long the client keeps listening after the host stops producing.
const GRACE: Duration = Duration::from_secs(3);
const BULK_CHUNK: usize = 64 * 1024;
const KEY_RECORD: usize = 16;
/// Priority of the echo stream when `isolation = "priority"`.
const ECHO_PRIORITY: i32 = 10;

pub fn states_total(p: &Profile) -> u64 {
    u64::from(p.workload.duration_s) * 1000 / u64::from(p.workload.frame_interval_ms)
}

pub fn keys_total(p: &Profile) -> u64 {
    u64::from(p.workload.duration_s) * 1000 / u64::from(p.workload.key_interval_ms)
}

// ---------------------------------------------------------------- staleness

pub struct Staleness {
    /// One sample per counted state, milliseconds.
    pub samples_ms: Vec<f64>,
    /// Counted states with no applied state at or after them.
    pub unresolved: u64,
}

/// Staleness of every state produced at or after `warmup_ns`.
///
/// State `k` is produced at `t0 + k * interval_ns`. Its staleness is the time
/// from that instant until the receiver first applied state `k` or any newer
/// state, minus the one-way propagation delay `owd_ns` of the link.
/// `applied` holds `(seq, rx_ns)` for every state the receiver applied.
pub fn staleness(
    t0: u64,
    interval_ns: u64,
    n: u64,
    warmup_ns: u64,
    applied: &[(u64, u64)],
    owd_ns: u64,
) -> Staleness {
    let mut rx: Vec<Option<u64>> = vec![None; n as usize];
    for &(seq, t) in applied {
        if let Some(slot) = rx.get_mut(seq as usize) {
            *slot = Some(slot.map_or(t, |old| old.min(t)));
        }
    }
    // earliest[k] = earliest time any state >= k was applied
    let mut earliest: Vec<Option<u64>> = vec![None; n as usize];
    let mut m: Option<u64> = None;
    for k in (0..n as usize).rev() {
        m = match (m, rx[k]) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        earliest[k] = m;
    }
    let mut out = Staleness {
        samples_ms: Vec::new(),
        unresolved: 0,
    };
    for k in 0..n {
        let produced = t0 + k * interval_ns;
        if produced < t0 + warmup_ns {
            continue;
        }
        match earliest[k as usize] {
            None => out.unresolved += 1,
            Some(t) => {
                let ns = t.saturating_sub(produced).saturating_sub(owd_ns);
                out.samples_ms.push(ns as f64 / 1e6);
            }
        }
    }
    out
}

// ------------------------------------------------------------------ screen

/// State record: `seq u64 | produced_ns u64 | t0_ns u64 | padding`, all LE.
fn state_record(seq: u64, t0: u64, interval_ns: u64, size: usize) -> Vec<u8> {
    let mut b = vec![0u8; size];
    b[0..8].copy_from_slice(&seq.to_le_bytes());
    b[8..16].copy_from_slice(&(t0 + seq * interval_ns).to_le_bytes());
    b[16..24].copy_from_slice(&t0.to_le_bytes());
    b
}

fn parse_state(b: &[u8]) -> Option<(u64, u64)> {
    if b.len() < 24 {
        return None;
    }
    let seq = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let t0 = u64::from_le_bytes(b[16..24].try_into().ok()?);
    Some((seq, t0))
}

pub async fn screen_server(conn: &quinn::Connection, p: &Profile) -> Result<()> {
    let w = &p.workload;
    let interval_ns = u64::from(w.frame_interval_ms) * 1_000_000;
    let size = w.state_bytes as usize;
    let mut stream = match w.carrier {
        Carrier::Stream => Some(conn.open_uni().await?),
        Carrier::Datagram => None,
    };
    let mut tick = interval(Duration::from_millis(u64::from(w.frame_interval_ms)));
    tick.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let t0 = now_ns();
    for seq in 0..states_total(p) {
        tick.tick().await;
        let rec = state_record(seq, t0, interval_ns, size);
        match &mut stream {
            Some(s) => s.write_all(&rec).await?,
            None => conn
                .send_datagram(Bytes::from(rec))
                .context("send_datagram")?,
        }
    }
    if let Some(mut s) = stream {
        s.finish()?;
    }
    Ok(())
}

pub struct ScreenOutcome {
    pub applied: Vec<(u64, u64)>,
    pub received_frames: u64,
    pub t0: Option<u64>,
}

pub async fn screen_client(conn: &quinn::Connection, p: &Profile, m: &mut Metrics) -> Result<()> {
    let w = &p.workload;
    let size = w.state_bytes as usize;
    let deadline = Instant::now() + Duration::from_secs(u64::from(w.duration_s)) + GRACE;
    let mut out = ScreenOutcome {
        applied: Vec::new(),
        received_frames: 0,
        t0: None,
    };
    let mut max_applied: Option<u64> = None;
    let mut apply = |out: &mut ScreenOutcome, seq: u64, t0: u64, rx: u64| {
        out.received_frames += 1;
        out.t0.get_or_insert(t0);
        // A state older than one already applied is dropped, not applied.
        if max_applied.is_none_or(|m| seq > m) {
            max_applied = Some(seq);
            out.applied.push((seq, rx));
        }
    };
    match w.carrier {
        Carrier::Datagram => {
            while let Ok(Ok(d)) = timeout_at(deadline, conn.read_datagram()).await {
                let rx = now_ns();
                if let Some((seq, t0)) = parse_state(&d) {
                    apply(&mut out, seq, t0, rx);
                }
            }
        }
        Carrier::Stream => {
            let mut rs = timeout_at(deadline, conn.accept_uni())
                .await
                .context("no screen stream")??;
            let mut buf = vec![0u8; size];
            while let Ok(Ok(())) = timeout_at(deadline, rs.read_exact(&mut buf)).await {
                let rx = now_ns();
                if let Some((seq, t0)) = parse_state(&buf) {
                    apply(&mut out, seq, t0, rx);
                }
            }
        }
    }
    let n = states_total(p);
    let Some(t0) = out.t0 else {
        bail!("no screen state arrived");
    };
    let st = staleness(
        t0,
        u64::from(w.frame_interval_ms) * 1_000_000,
        n,
        u64::from(w.warmup_s) * 1_000_000_000,
        &out.applied,
        p.one_way_ns(),
    );
    m.staleness_ms = percentiles(&st.samples_ms);
    m.states_produced = Some(n);
    m.states_applied = Some(out.applied.len() as u64);
    m.states_unresolved = Some(st.unresolved);
    if w.carrier == Carrier::Datagram {
        let lost = n.saturating_sub(out.received_frames);
        m.datagram_loss_pct = Some(round3(lost as f64 * 100.0 / n as f64));
    }
    Ok(())
}

// -------------------------------------------------------------------- echo

pub async fn echo_server(conn: &quinn::Connection, p: &Profile) -> Result<()> {
    let (mut tx, mut rx) = conn.accept_bi().await?;
    if p.workload.kind == Kind::BulkEcho && p.workload.isolation == Isolation::Priority {
        tx.set_priority(ECHO_PRIORITY)?;
    }
    let mut rec = [0u8; KEY_RECORD];
    while rx.read_exact(&mut rec).await.is_ok() {
        tx.write_all(&rec).await?;
    }
    let _ = tx.finish();
    Ok(())
}

pub async fn echo_client(conn: &quinn::Connection, p: &Profile, m: &mut Metrics) -> Result<()> {
    let w = &p.workload;
    let n = keys_total(p);
    let (mut tx, mut rx) = conn.open_bi().await?;
    let lat: Arc<Mutex<Vec<Option<u64>>>> = Arc::new(Mutex::new(vec![None; n as usize]));
    let reader = {
        let lat = lat.clone();
        tokio::spawn(async move {
            let mut rec = [0u8; KEY_RECORD];
            while rx.read_exact(&mut rec).await.is_ok() {
                let now = now_ns();
                let seq = u64::from_le_bytes(rec[0..8].try_into().expect("8 bytes")) as usize;
                let sent = u64::from_le_bytes(rec[8..16].try_into().expect("8 bytes"));
                if let Some(slot) = lat.lock().expect("lat").get_mut(seq) {
                    *slot = Some(now.saturating_sub(sent));
                }
            }
        })
    };
    let mut tick = interval(Duration::from_millis(u64::from(w.key_interval_ms)));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    for seq in 0..n {
        tick.tick().await;
        let mut rec = [0u8; KEY_RECORD];
        rec[0..8].copy_from_slice(&seq.to_le_bytes());
        rec[8..16].copy_from_slice(&now_ns().to_le_bytes());
        tx.write_all(&rec).await?;
    }
    // Wait for stragglers: until every key is back or the grace runs out.
    let wait_until = Instant::now() + GRACE;
    while Instant::now() < wait_until && lat.lock().expect("lat").iter().any(Option::is_none) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    reader.abort();
    let _ = tx.finish();
    let lat = lat.lock().expect("lat");
    let first = (u64::from(w.warmup_s) * 1000 / u64::from(w.key_interval_ms)) as usize;
    let counted = &lat[first.min(lat.len())..];
    let samples: Vec<f64> = counted
        .iter()
        .flatten()
        .map(|&ns| ns as f64 / 1e6)
        .collect();
    m.echo_ms = percentiles(&samples);
    m.echo_missing = Some(counted.iter().filter(|x| x.is_none()).count() as u64);
    Ok(())
}

// -------------------------------------------------------------------- bulk

pub async fn bulk_server(conn: &quinn::Connection, p: &Profile) -> Result<()> {
    let mut tx = conn.open_uni().await?;
    tx.set_priority(0)?;
    let deadline = Instant::now() + Duration::from_secs(u64::from(p.workload.duration_s));
    let chunk = vec![0xA5u8; BULK_CHUNK];
    while Instant::now() < deadline {
        match timeout_at(deadline, tx.write_all(&chunk)).await {
            Ok(r) => r?,
            Err(_) => break,
        }
    }
    let _ = tx.finish();
    Ok(())
}

/// Receives the bulk stream until the run's deadline; returns bytes received.
pub async fn bulk_client(conn: &quinn::Connection, p: &Profile) -> Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(u64::from(p.workload.duration_s));
    let mut rs = timeout_at(deadline, conn.accept_uni())
        .await
        .context("no bulk stream")??;
    let mut buf = vec![0u8; BULK_CHUNK];
    let mut total = 0u64;
    while let Ok(Ok(Some(n))) = timeout_at(deadline, rs.read(&mut buf)).await {
        total += n as u64;
    }
    Ok(total)
}

pub fn goodput_mb_s(bytes: u64, duration_s: u32) -> f64 {
    round3(bytes as f64 / 1e6 / f64::from(duration_s))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn staleness_counts_time_to_the_first_state_at_or_after() {
        // 5 states 20 ms apart from t0 = 1000 ms. State 1 is lost; state 2
        // arrives at +55 ms, which also satisfies state 1.
        let t0 = 1000 * MS;
        let applied = vec![
            (0, t0 + 10 * MS),
            (2, t0 + 55 * MS),
            (3, t0 + 70 * MS),
            (4, t0 + 90 * MS),
        ];
        let s = staleness(t0, 20 * MS, 5, 0, &applied, 0);
        assert_eq!(s.unresolved, 0);
        let want = [10.0, 35.0, 15.0, 10.0, 10.0];
        for (g, w) in s.samples_ms.iter().zip(want) {
            assert!((g - w).abs() < 1e-9, "{:?}", s.samples_ms);
        }
    }

    #[test]
    fn staleness_subtracts_one_way_delay_and_skips_warmup() {
        let t0 = 0;
        let applied: Vec<(u64, u64)> = (0..10).map(|k| (k, k * 20 * MS + 85 * MS)).collect();
        let s = staleness(t0, 20 * MS, 10, 60 * MS, &applied, 75 * MS);
        // states 0..=2 are warm-up; 7 counted, each 85 - 75 = 10 ms
        assert_eq!(s.samples_ms.len(), 7);
        assert!(s.samples_ms.iter().all(|x| (x - 10.0).abs() < 1e-9));
    }

    #[test]
    fn trailing_states_with_nothing_newer_are_unresolved() {
        let applied = vec![(0, 5 * MS), (1, 25 * MS)];
        let s = staleness(0, 20 * MS, 4, 0, &applied, 0);
        assert_eq!(s.samples_ms.len(), 2);
        assert_eq!(s.unresolved, 2);
    }

    #[test]
    fn state_record_round_trips() {
        let r = state_record(7, 1234, 20 * MS, 800);
        assert_eq!(r.len(), 800);
        assert_eq!(parse_state(&r), Some((7, 1234)));
        assert_eq!(
            u64::from_le_bytes(r[8..16].try_into().unwrap()),
            1234 + 7 * 20 * MS
        );
        assert_eq!(parse_state(&r[..10]), None);
    }

    #[test]
    fn goodput_is_decimal_megabytes_per_second() {
        assert_eq!(goodput_mb_s(50_000_000, 20), 2.5);
    }
}
