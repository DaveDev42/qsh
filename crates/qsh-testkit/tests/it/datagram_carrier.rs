//! L3/L4 tests for the DATAGRAM carrier of screen state sync and the input
//! copy (ADR-0052 decisions 6 to 9 and 12 (c); M22 DoD 18-1 and 18-4;
//! `docs/design/protocol.md` §18.9). Pipe-backed sessions, so the same tests
//! run on every platform.
//!
//! `screen_sync_staleness_under_loss` is the acceptance gate: it runs only
//! with `QSH_ACCEPTANCE_SLOW` set (the `acceptance` job in
//! `.github/workflows/ci.yml` sets it); a plain run prints SKIP. Its numbers
//! (p95 staleness, convergence time) go to stderr.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use qsh_core::broker::PipeHandle;
use qsh_core::client::screen::ClientScreen;
use qsh_core::client::{AttachEvent, Attached, Session};
use qsh_core::datagram::{DatagramHub, input_copy};
use qsh_proto::datagram::ChannelId;
use qsh_proto::wire;
use qsh_testkit::chaos::{ChaosPolicy, DelayDist};
use qsh_testkit::loopback::LoopbackHarness;

use super::screen_sync::{DEADLINE, host_state, open_attached, open_req};

/// Which carrier a screen event came on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Via {
    Stream,
    Datagram,
}

/// Apply one attach event to `screen`, ack what needs acking, and say which
/// carrier a screen update used (`None` for any other event).
async fn feed(
    att: &mut Attached,
    screen: &mut ClientScreen,
    event: AttachEvent,
    spoke: &mut bool,
) -> Option<Via> {
    let (outcome, via) = match event {
        AttachEvent::Screen(part) => (screen.on_part(&part).expect("part"), Via::Stream),
        AttachEvent::ScreenDatagram(part) => (screen.on_datagram_part(&part), Via::Datagram),
        _ => return None,
    };
    if let Some(n) = outcome.ack() {
        att.send_screen_ack(n).await.expect("ack");
        *spoke = true;
    }
    Some(via)
}

fn converged(h: &LoopbackHarness, id: &str, screen: &ClientScreen) -> bool {
    host_state(h, id).is_some_and(|(hash, num)| screen.num() == num && screen.hash() == Some(hash))
}

/// Read events until the client holds the host's state, counting updates per
/// carrier.
async fn run_until_converged(
    h: &LoopbackHarness,
    id: &str,
    att: &mut Attached,
    screen: &mut ClientScreen,
) -> (usize, usize) {
    let (mut stream, mut datagram) = (0, 0);
    // Datagram updates count only while the client has sent nothing yet. After
    // its first ack the host may legitimately send a further state as a
    // datagram (the output can land in more than one state, and when the host
    // gets there depends on timing), so counting those would make the
    // take-over check race the host (ADR-0052 decision 6, protocol §18.9).
    let mut spoke = false;
    tokio::time::timeout(DEADLINE, async {
        while !converged(h, id, screen) {
            let event = att.next().await.expect("event").expect("stream open");
            let before = spoke;
            match feed(att, screen, event, &mut spoke).await {
                Some(Via::Stream) => stream += 1,
                Some(Via::Datagram) if !before => datagram += 1,
                Some(Via::Datagram) | None => {}
            }
        }
    })
    .await
    .expect("client converges on the host's state");
    (stream, datagram)
}

/// The text of the first row.
fn first_row(screen: &ClientScreen) -> String {
    screen.state().unwrap().grid[0]
        .cells
        .iter()
        .map(|c| if c.text.is_empty() { " " } else { &*c.text })
        .collect()
}

/// Read exactly `n` forwarded input bytes from the session pipe.
async fn read_input_exact(pipe: &mut PipeHandle, n: usize) -> Vec<u8> {
    let mut got = Vec::new();
    tokio::time::timeout(DEADLINE, async {
        while got.len() < n {
            got.extend(pipe.read_input(4096).await.expect("pipe input"));
        }
    })
    .await
    .expect("the host forwarded the input");
    got
}

/// Whether more input arrives within `wait` (it must not).
async fn input_arrives(pipe: &mut PipeHandle, wait: Duration) -> bool {
    matches!(
        tokio::time::timeout(wait, pipe.read_input(4096)).await,
        Ok(Ok(bytes)) if !bytes.is_empty()
    )
}

fn host_hub(h: &LoopbackHarness) -> Arc<DatagramHub> {
    let conn = h.server_connections().into_iter().next().expect("conn");
    DatagramHub::of(&conn)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_datagram_carrier_takes_over_once_the_client_sends_a_datagram() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(7)).await;
    let mut s = h.session().await;
    assert!(s.capabilities.iter().any(|c| c == wire::CAP_DATAGRAM_V1));
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    pipe.write_output(b"\x1b[2J\x1b[Hone").await.unwrap();
    let mut screen = ClientScreen::new();
    // The first screen has to come on the stream: the host does not know yet
    // that this client reads datagrams.
    let (stream, datagram) =
        run_until_converged(&h, &opened.session_id, &mut att, &mut screen).await;
    assert!(stream >= 1, "the first update rides the stream");
    assert_eq!(
        datagram, 0,
        "no datagram before the client spoke on the channel"
    );

    // The client's ack went out as a datagram too; from here updates ride
    // datagrams.
    let mut datagrams = 0;
    for k in 0..40 {
        pipe.write_output(format!("\x1b[2J\x1b[Hframe {k:03}").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let (_, d) = run_until_converged(&h, &opened.session_id, &mut att, &mut screen).await;
        datagrams += d;
    }
    assert!(datagrams > 0, "updates arrived as datagrams");
    assert!(
        first_row(&screen).starts_with("frame 039"),
        "{}",
        first_row(&screen)
    );
    let host_conn = h.server_connections().into_iter().next().unwrap();
    assert!(host_conn.stats().tx_datagram_frames > 0);
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_without_datagram_v1_gets_the_stream_carrier() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(7)).await;
    let dialed = h.dial().await;
    let mut s = Session::negotiate_hiding(dialed.connection, "laptop", &[wire::CAP_DATAGRAM_V1])
        .await
        .expect("negotiate");
    assert!(s.screen_supported());
    assert!(!s.capabilities.iter().any(|c| c == wire::CAP_DATAGRAM_V1));
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    let mut datagrams = 0;
    for k in 0..20 {
        pipe.write_output(format!("\x1b[2J\x1b[Hframe {k:03}").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let (_, d) = run_until_converged(&h, &opened.session_id, &mut att, &mut screen).await;
        datagrams += d;
    }
    assert_eq!(datagrams, 0);
    let host_conn = h.server_connections().into_iter().next().unwrap();
    assert_eq!(
        host_conn.stats().tx_datagram_frames,
        0,
        "the host sent no datagram"
    );
    assert!(first_row(&screen).starts_with("frame 019"));
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_without_datagram_v1_gets_the_stream_carrier_from_a_new_client() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(7)).await;
    h.server.hide_capabilities(&[wire::CAP_DATAGRAM_V1]);
    let mut s = h.session().await;
    assert!(s.screen_supported());
    assert!(!s.capabilities.iter().any(|c| c == wire::CAP_DATAGRAM_V1));
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    let mut datagrams = 0;
    for k in 0..10 {
        pipe.write_output(format!("\x1b[2J\x1b[Hframe {k:03}").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let (_, d) = run_until_converged(&h, &opened.session_id, &mut att, &mut screen).await;
        datagrams += d;
    }
    assert_eq!(datagrams, 0);
    // The input copy needs the capability too.
    att.send_input(b"abc").await.unwrap();
    assert_eq!(read_input_exact(&mut pipe, 3).await, b"abc");
    let client_conn = h.server_connections().into_iter().next().unwrap();
    assert_eq!(client_conn.stats().rx_datagram_frames, 0);
    s.close();
    h.shutdown().await;
}

/// Lossless and without duplicates while the path loses, reorders and
/// duplicates the datagram copies (and the stream's packets too).
#[tokio::test(flavor = "multi_thread")]
async fn input_copies_are_lossless_and_duplicate_free_under_loss_and_reordering() {
    let policy = ChaosPolicy::seeded(0x1A9_07C0)
        .drop(0.15)
        .reorder(0.2)
        .duplicate(0.2)
        .delay(DelayDist::uniform(Duration::ZERO, Duration::from_millis(4)));
    let h = LoopbackHarness::start_chaotic(policy).await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    run_until_converged(&h, &opened.session_id, &mut att, &mut screen).await;

    let mut expect = Vec::new();
    let (mut writer, mut reader) = att.split();
    let sender = tokio::spawn(async move {
        let mut sent = Vec::new();
        for k in 0..300u32 {
            let chunk = format!("<{k:04}>");
            writer.send_input(chunk.as_bytes()).await.expect("send");
            sent.extend_from_slice(chunk.as_bytes());
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        (writer, sent)
    });
    // Keep reading so the stream's acks and updates flow.
    let drain = tokio::spawn(async move {
        loop {
            match reader.next().await {
                Ok(Some(_)) => {}
                _ => return,
            }
        }
    });
    let (_writer, sent) = sender.await.unwrap();
    expect.extend_from_slice(&sent);
    let got = read_input_exact(&mut pipe, expect.len()).await;
    assert_eq!(got, expect, "every byte, once, in order — {}", h.context());
    assert!(
        !input_arrives(&mut pipe, Duration::from_millis(500)).await,
        "no duplicate arrives later — {}",
        h.context()
    );
    let delivered = host_hub(&h).counters().delivered.load(Ordering::Relaxed);
    assert!(delivered > 0, "datagram copies reached the host");
    drain.abort();
    s.close();
    h.shutdown().await;
}

/// A datagram copy applies only if it starts at the attach's applied offset.
/// Copies from the future and replays of old bytes are dropped; the stream
/// copy is the one that counts.
#[tokio::test(flavor = "multi_thread")]
async fn a_datagram_input_copy_at_the_wrong_offset_is_dropped() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(7)).await;
    let dialed = h.dial().await;
    let conn = dialed.connection.clone();
    let mut s = Session::negotiate(dialed.connection, "laptop")
        .await
        .expect("negotiate");
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;
    let channel = ChannelId(opened.screen_channel.clone().try_into().expect("16 bytes"));
    let client_hub = DatagramHub::of(&conn);

    // From the future: the bytes before it never arrived.
    client_hub
        .send(&input_copy(channel, 105, b"future"))
        .unwrap();
    // A copy that starts exactly at the applied offset (0) is applied.
    client_hub.send(&input_copy(channel, 3, b"abc")).unwrap();
    assert_eq!(read_input_exact(&mut pipe, 3).await, b"abc");
    // A replay of what was applied, and an overlapping one, are dropped.
    client_hub.send(&input_copy(channel, 3, b"abc")).unwrap();
    client_hub.send(&input_copy(channel, 5, b"bcde")).unwrap();
    // The stream copy of the same bytes the copy already applied is
    // de-duplicated, and new bytes still flow after all of the above.
    // (`send_input` continues the axis the host told us: 0.)
    att.send_input(b"abcXY").await.unwrap();
    assert_eq!(
        read_input_exact(&mut pipe, 2).await,
        b"XY",
        "only the bytes after the applied offset are new"
    );
    assert!(!input_arrives(&mut pipe, Duration::from_millis(300)).await);
    s.close();
    h.shutdown().await;
}

/// A datagram for a channel nobody registered is dropped and counted, and
/// creates nothing (ADR-0052 decision 7).
#[tokio::test(flavor = "multi_thread")]
async fn a_datagram_for_an_unknown_channel_is_dropped_and_counted() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(7)).await;
    let dialed = h.dial().await;
    let conn = dialed.connection.clone();
    let mut s = Session::negotiate(dialed.connection, "laptop")
        .await
        .expect("negotiate");
    let req = open_req(&s);
    let (_opened, mut pipe, _att) = open_attached(&h, &mut s, req).await;
    let hub = host_hub(&h);
    let before = hub.counters().unknown_channel.load(Ordering::Relaxed);
    DatagramHub::of(&conn)
        .send(&input_copy(ChannelId([0xEE; 16]), 4, b"evil"))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while hub.counters().unknown_channel.load(Ordering::Relaxed) == before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the unknown channel was counted");
    assert!(
        !input_arrives(&mut pipe, Duration::from_millis(300)).await,
        "a forged channel id reaches no session"
    );
    s.close();
    h.shutdown().await;
}

/// A path that drops only datagrams: the host notices that its datagram
/// updates go unacked while the connection lives, falls back to the stream,
/// and the screen still converges (ADR-0052 decision 12 (c), DoD 18-4).
#[tokio::test(flavor = "multi_thread")]
async fn a_path_that_eats_datagrams_falls_back_to_the_stream_and_converges() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(7)).await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, pipe, mut att) = open_attached(&h, &mut s, req).await;
    let stop = Arc::new(AtomicBool::new(false));
    let producer = {
        let stop = Arc::clone(&stop);
        let mut pipe = pipe;
        tokio::spawn(async move {
            let mut k = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let frame = format!("\x1b[2J\x1b[Hframe {k:05}");
                pipe.write_output(frame.as_bytes()).await.unwrap();
                k += 1;
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            (pipe, k)
        })
    };
    let mut screen = ClientScreen::new();
    let mut black_at = None::<Instant>;
    let mut fell_back_after = None::<Duration>;
    let mut datagrams_before = 0;
    tokio::time::timeout(DEADLINE, async {
        loop {
            let event = att.next().await.expect("event").expect("open");
            let Some(via) = feed(&mut att, &mut screen, event, &mut false).await else {
                continue;
            };
            match (black_at, via) {
                (None, Via::Datagram) => {
                    datagrams_before += 1;
                    if datagrams_before >= 5 {
                        h.server.blackhole_datagrams(true);
                        black_at = Some(Instant::now());
                    }
                }
                (Some(t), Via::Stream) => {
                    fell_back_after = Some(t.elapsed());
                    return;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the host fell back to the stream");
    eprintln!(
        "datagram blackhole detected after {:?} (carrier fell back to the stream)",
        fell_back_after.unwrap()
    );
    assert!(
        fell_back_after.unwrap() < Duration::from_secs(5),
        "{fell_back_after:?}"
    );
    stop.store(true, Ordering::Relaxed);
    let (_pipe, produced) = producer.await.unwrap();
    assert!(produced > 5);
    // Output stopped; the stream carrier brings the client to the end state.
    run_until_converged(&h, &opened.session_id, &mut att, &mut screen).await;
    assert!(
        first_row(&screen).starts_with(&format!("frame {:05}", produced - 1)),
        "{}",
        first_row(&screen)
    );
    s.close();
    h.shutdown().await;
}

// ---------------------------------------------------------------------
// screen_sync_staleness_under_loss
// ---------------------------------------------------------------------

const ONE_WAY: Duration = Duration::from_millis(75);

fn slow_enabled() -> bool {
    std::env::var_os("QSH_ACCEPTANCE_SLOW")
        .or_else(|| std::env::var_os("QSH_ACCEPTANCE_STRICT"))
        .is_some_and(|v| !v.is_empty() && v != "0")
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let idx = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[idx]
}

/// The frame number in row 0 (`frame NNNNN`), if the screen shows one.
fn frame_number(screen: &ClientScreen) -> Option<usize> {
    first_row(screen)
        .strip_prefix("frame ")
        .and_then(|rest| rest.get(..5))
        .and_then(|n| n.parse().ok())
}

/// One full-screen frame whose first row names it.
fn full_frame(k: usize) -> Vec<u8> {
    let mut out = format!("\x1b[H\x1b[2Jframe {k:05}\r\n");
    for row in 1..22 {
        out.push_str(&format!("{k:05}:{row:02} {}\r\n", "abcdefghij".repeat(6)));
    }
    out.into_bytes()
}

struct Measured {
    /// Staleness of every frame: when the client first showed that frame or
    /// a later one, minus when it was produced, minus the one-way delay.
    staleness: Vec<Duration>,
    applied: u64,
    produced: usize,
    /// From the last frame produced until the client holds the host's state.
    settle: Duration,
}

/// Produce `frames` frames (one per `gap`, no sleep when `gap` is zero),
/// follow them on the client and measure.
async fn measure(h: &LoopbackHarness, frames: usize, gap: Duration) -> Measured {
    let mut s = h.session().await;
    let req = open_req(&s);
    let (opened, mut pipe, mut att) = open_attached(h, &mut s, req).await;
    let mut screen = ClientScreen::new();
    // Warm up: the first screen, and the datagram channel if there is one.
    pipe.write_output(&full_frame(0)).await.unwrap();
    run_until_converged(h, &opened.session_id, &mut att, &mut screen).await;
    let wrote = Arc::new(Mutex::new(vec![Instant::now(); frames + 1]));
    let finished = Arc::new(Mutex::new(None::<Instant>));
    let producer = {
        let wrote = Arc::clone(&wrote);
        let finished = Arc::clone(&finished);
        tokio::spawn(async move {
            for k in 1..=frames {
                wrote.lock().unwrap()[k] = Instant::now();
                pipe.write_output(&full_frame(k)).await.unwrap();
                if !gap.is_zero() {
                    tokio::time::sleep(gap).await;
                }
            }
            *finished.lock().unwrap() = Some(Instant::now());
            pipe
        })
    };
    let mut shown = vec![None::<Instant>; frames + 1];
    let mut highest = 0usize;
    let applied_before = screen.applied_updates();
    let settle_at = tokio::time::timeout(DEADLINE, async {
        loop {
            let event = att.next().await.expect("event").expect("open");
            feed(&mut att, &mut screen, event, &mut false).await;
            let now = Instant::now();
            if let Some(n) = frame_number(&screen)
                && n > highest
            {
                for slot in shown.iter_mut().take(n.min(frames) + 1).skip(highest + 1) {
                    *slot = Some(now);
                }
                highest = n;
            }
            let done = finished.lock().unwrap().is_some();
            if done && converged(h, &opened.session_id, &screen) {
                return now;
            }
        }
    })
    .await
    .expect("the client settles on the last frame");
    let _pipe = producer.await.unwrap();
    let wrote = wrote.lock().unwrap().clone();
    let last_write = finished.lock().unwrap().unwrap();
    let staleness = (1..=frames)
        .filter_map(|k| shown[k].map(|t| t.duration_since(wrote[k]).saturating_sub(ONE_WAY)))
        .collect();
    let measured = Measured {
        staleness,
        applied: screen.applied_updates() - applied_before,
        produced: frames,
        settle: settle_at.duration_since(last_write),
    };
    s.close();
    measured
}

/// QUIC's probe timeout shape: `srtt + 4 * rttvar + max_ack_delay`, with
/// `rttvar` taken at its initial bound of `srtt / 2`.
fn rto_of(h: &LoopbackHarness) -> Duration {
    let rtt = h
        .server_connections()
        .iter()
        .map(|c| c.stats().rtt)
        .max()
        .unwrap_or_default()
        .max(ONE_WAY * 2);
    rtt + rtt * 2 + Duration::from_millis(25)
}

#[tokio::test(flavor = "multi_thread")]
async fn screen_sync_staleness_under_loss() {
    if !slow_enabled() {
        eprintln!("SKIP: the screen_sync_staleness_under_loss gate requires QSH_ACCEPTANCE_SLOW=1");
        return;
    }
    let policy = || {
        ChaosPolicy::seeded(0x57A1E)
            .drop(0.05)
            .delay(DelayDist::fixed(ONE_WAY))
    };

    // Datagram carrier: one frame every 30 ms, so a lost update is replaced
    // by the next one.
    let h = LoopbackHarness::start_chaotic(policy()).await;
    let datagram = measure(&h, 400, Duration::from_millis(30)).await;
    let rto = rto_of(&h);
    let host_datagrams = h
        .server_connections()
        .iter()
        .map(|c| c.stats().tx_datagram_frames)
        .sum::<u64>();
    let mut sorted = datagram.staleness.clone();
    sorted.sort();
    let (p50, p95, p99) = (
        percentile(&sorted, 0.50),
        percentile(&sorted, 0.95),
        percentile(&sorted, 0.99),
    );
    eprintln!(
        "datagram carrier: staleness p50 {p50:?} p95 {p95:?} p99 {p99:?} over {} frames, \
         {} updates applied, {host_datagrams} datagram frames sent, settle {:?}, rto {rto:?} — {}",
        sorted.len(),
        datagram.applied,
        datagram.settle,
        h.context()
    );
    assert!(host_datagrams > 100, "the datagram carrier was in use");
    assert!(
        p95 <= Duration::from_millis(50),
        "datagram staleness p95 {p95:?} > 50 ms — {}",
        h.context()
    );
    assert!(
        datagram.settle <= ONE_WAY + rto * 2,
        "datagram settle {:?} — {}",
        datagram.settle,
        h.context()
    );
    h.shutdown().await;

    // Stream carrier under the same conditions: a burst of frames, far
    // faster than the path delivers. Intermediate states are skipped and the
    // last one arrives within 2 x RTO of the burst ending.
    let h = LoopbackHarness::start_chaotic(policy()).await;
    h.server.hide_capabilities(&[wire::CAP_DATAGRAM_V1]);
    let stream = measure(&h, 600, Duration::ZERO).await;
    let rto = rto_of(&h);
    let mut sorted = stream.staleness.clone();
    sorted.sort();
    eprintln!(
        "stream carrier: {} updates applied for {} frames produced, staleness p95 {:?}, \
         settle {:?}, rto {rto:?} — {}",
        stream.applied,
        stream.produced,
        percentile(&sorted, 0.95),
        stream.settle,
        h.context()
    );
    assert!(
        (stream.applied as usize) < stream.produced,
        "the stream carrier skipped intermediate states: {} applied for {} produced",
        stream.applied,
        stream.produced
    );
    assert!(
        stream.settle <= ONE_WAY + rto * 2,
        "stream settle {:?} > 2 x RTO {:?} — {}",
        stream.settle,
        rto,
        h.context()
    );
    h.shutdown().await;
}
