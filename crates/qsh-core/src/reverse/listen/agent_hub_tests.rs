//! The `AGENT` relay of [`ControlHub`] (ADR-0055 decision 14): which
//! conduit's channels the hub knows, who may claim a channel's streams, and
//! the per-hub cap. Wire-level behavior through a real daemon is in
//! `crates/qsh-testkit/tests/it/agent_reverse.rs`.

use std::time::Duration;

use qsh_proto::wire::control_message::Body;

use super::hub::*;
use super::*;

const CHANNEL: [u8; wire::AGENT_CHANNEL_LEN] = [0x7a; wire::AGENT_CHANNEL_LEN];
const TOKEN_A: &[u8] = b"claim-token-of-a";
const TOKEN_B: &[u8] = b"claim-token-of-b";
const SHORT: Duration = Duration::from_millis(40);
const LONG: Duration = Duration::from_secs(5);

fn hub() -> Arc<ControlHub> {
    ControlHub::new("widget".into(), "sha256:deadbeef".into(), 1, Vec::new())
}

fn exec_start(channel: &[u8]) -> Body {
    Body::ExecStart(wire::ExecStart {
        argv: vec!["true".into()],
        agent_channel: channel.to_vec(),
        ..Default::default()
    })
}

/// One bidi stream on `conn` with a byte written, so the peer's
/// `accept_bi` sees it.
async fn stream_on(conn: &Connection) -> (SendStream, RecvStream) {
    let (mut send, recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"x").await.expect("write");
    (send, recv)
}

/// Queue one stream for `channel` the way the accept loop does.
async fn deliver(hub: &ControlHub, conn: &Connection, channel: &[u8]) -> Result<(), ()> {
    let permit = hub.try_acquire_agent_permit().ok_or(())?;
    let (send, recv) = stream_on(conn).await;
    hub.deliver_agent(channel, send, recv, Vec::new(), permit)
        .map_err(|rejected| rejected.reset(RESET_CODE_AGENT_UNKNOWN_CHANNEL))
}

/// ADR-0055 decision 22 B47: a stream for a channel is handed to the claim
/// seat and nobody else, whichever conduit asks and however it asks.
#[tokio::test]
async fn a_reverse_agent_channel_is_claimed_only_by_its_conduit() {
    let hub = hub();
    let (_client, target) = crate::tunnel::testutil::loopback_pair().await;
    let (a, _inbox_a) = hub.register_conduit();
    let (b, _inbox_b) = hub.register_conduit();

    hub.send_request(a, 1, exec_start(&CHANNEL)).unwrap();
    assert_eq!(hub.agent_channel_owner(&CHANNEL), Some(a));

    // The first claim seats its token, even with nothing to take yet.
    assert!(hub.claim_agent(&CHANNEL, TOKEN_A, SHORT).await.is_none());

    deliver(&hub, &target, &CHANNEL).await.unwrap();
    assert_eq!(hub.queued_agent_count(&CHANNEL), 1);

    // Another claimant of the same uid, knowing the channel, gets nothing:
    // a different token, an empty one, and one over the length cap.
    assert!(hub.claim_agent(&CHANNEL, TOKEN_B, SHORT).await.is_none());
    assert!(hub.claim_agent(&CHANNEL, b"", SHORT).await.is_none());
    let long = vec![9u8; MAX_AGENT_CLAIM_TOKEN_LEN + 1];
    assert!(hub.claim_agent(&CHANNEL, &long, SHORT).await.is_none());
    assert_eq!(
        hub.queued_agent_count(&CHANNEL),
        1,
        "a refused claim must leave the stream where it was"
    );

    // Another conduit sending a request with the same channel does not take
    // the registration over.
    hub.send_request(b, 1, exec_start(&CHANNEL)).unwrap();
    assert_eq!(hub.agent_channel_owner(&CHANNEL), Some(a));
    assert!(hub.claim_agent(&CHANNEL, TOKEN_B, SHORT).await.is_none());

    // The seat holder gets it.
    let claimed = hub.claim_agent(&CHANNEL, TOKEN_A, LONG).await;
    assert!(claimed.is_some());
    assert_eq!(hub.queued_agent_count(&CHANNEL), 0);
}

/// A claim parked before the stream exists is woken by it, and is checked
/// against the seat on every wake.
#[tokio::test]
async fn a_parked_agent_claim_is_woken_by_the_stream() {
    let hub = hub();
    let (_client, target) = crate::tunnel::testutil::loopback_pair().await;
    let (a, _inbox) = hub.register_conduit();
    hub.send_request(a, 1, exec_start(&CHANNEL)).unwrap();

    let waiting = {
        let hub = Arc::clone(&hub);
        tokio::spawn(async move { hub.claim_agent(&CHANNEL, TOKEN_A, LONG).await.is_some() })
    };
    // Let the claim park (and seat) first.
    tokio::time::sleep(Duration::from_millis(50)).await;
    deliver(&hub, &target, &CHANNEL).await.unwrap();
    assert!(waiting.await.unwrap());
}

/// A stream for a channel nobody registered is handed back to be reset, and
/// nothing is queued or kept.
#[tokio::test]
async fn an_unregistered_agent_channel_is_refused_and_queues_nothing() {
    let hub = hub();
    let (_client, target) = crate::tunnel::testutil::loopback_pair().await;
    let (a, _inbox) = hub.register_conduit();
    hub.send_request(a, 1, exec_start(&CHANNEL)).unwrap();

    let stranger = [0x11u8; wire::AGENT_CHANNEL_LEN];
    assert!(deliver(&hub, &target, &stranger).await.is_err());
    assert_eq!(hub.queued_agent_count(&stranger), 0);
    assert_eq!(
        hub.agent_streams_in_use(),
        0,
        "a refused stream gives its slot back"
    );
    assert!(hub.claim_agent(&stranger, TOKEN_A, SHORT).await.is_none());
}

/// Only a request that carries a whole 16-byte channel registers one; a
/// request without `-A`, or with a malformed field, leaves the table alone.
#[tokio::test]
async fn only_a_well_formed_agent_channel_is_registered() {
    let hub = hub();
    let (a, _inbox) = hub.register_conduit();
    hub.send_request(a, 1, exec_start(&[])).unwrap();
    hub.send_request(a, 2, exec_start(&CHANNEL[..15])).unwrap();
    hub.send_request(a, 3, exec_start(&[0u8; 17])).unwrap();
    assert_eq!(hub.agent_channel_owner(&CHANNEL), None);
    assert_eq!(hub.agent_channel_owner(&CHANNEL[..15]), None);

    // `session.open` and `session.attach` register too.
    let open = Body::SessionOpen(wire::SessionOpen {
        agent_channel: CHANNEL.to_vec(),
        ..Default::default()
    });
    hub.send_request(a, 4, open).unwrap();
    assert_eq!(hub.agent_channel_owner(&CHANNEL), Some(a));
    let other = [0x22u8; wire::AGENT_CHANNEL_LEN];
    let attach = Body::SessionAttach(wire::SessionAttach {
        agent_channel: other.to_vec(),
        ..Default::default()
    });
    hub.send_request(a, 5, attach).unwrap();
    assert_eq!(hub.agent_channel_owner(&other), Some(a));
}

/// ADR-0055 decision 10: the hub holds 32 `AGENT` streams at once, queued or
/// being spliced, and the 33rd is refused until one ends. The count is
/// apart from the tunnel streams.
#[tokio::test]
async fn the_agent_stream_cap_is_32_per_hub() {
    let hub = hub();
    let (_client, target) = crate::tunnel::testutil::loopback_pair().await;
    let (a, _inbox) = hub.register_conduit();
    hub.send_request(a, 1, exec_start(&CHANNEL)).unwrap();
    assert_eq!(MAX_AGENT_STREAMS_PER_HUB, 32);

    for n in 0..MAX_AGENT_STREAMS_PER_HUB {
        deliver(&hub, &target, &CHANNEL)
            .await
            .unwrap_or_else(|()| panic!("stream {n} is under the cap"));
    }
    assert_eq!(hub.agent_streams_in_use(), 32);
    assert!(
        hub.try_acquire_agent_permit().is_none(),
        "the 33rd stream is refused"
    );
    // Tunnels have their own pool and are not touched.
    assert!(hub.try_acquire_tunnel_permit().is_some());

    // One stream ends: its slot is free again, whether it was spliced...
    let claimed = hub.claim_agent(&CHANNEL, TOKEN_A, LONG).await.unwrap();
    assert!(
        hub.try_acquire_agent_permit().is_none(),
        "a claimed stream keeps its slot for the whole splice"
    );
    drop(claimed);
    let again = hub.try_acquire_agent_permit();
    assert!(again.is_some());
    drop(again);
    assert_eq!(hub.agent_streams_in_use(), 31);
}

/// A conduit's channels leave with it, the streams queued for them are
/// reset, and their slots come back (decision 14: "등록한 conduit이 죽으면 항목을
/// 내리고 대기 중인 스트림을 reset한다").
#[tokio::test]
async fn a_dead_conduits_agent_channels_and_queued_streams_go_with_it() {
    let hub = hub();
    let (client, target) = crate::tunnel::testutil::loopback_pair().await;
    let (a, _inbox_a) = hub.register_conduit();
    let (b, _inbox_b) = hub.register_conduit();
    let other = [0x33u8; wire::AGENT_CHANNEL_LEN];
    hub.send_request(a, 1, exec_start(&CHANNEL)).unwrap();
    hub.send_request(b, 1, exec_start(&other)).unwrap();
    deliver(&hub, &target, &CHANNEL).await.unwrap();
    deliver(&hub, &target, &other).await.unwrap();
    assert_eq!(hub.agent_streams_in_use(), 2);

    hub.unregister_conduit(a);
    assert_eq!(hub.agent_channel_owner(&CHANNEL), None);
    assert_eq!(hub.queued_agent_count(&CHANNEL), 0);
    assert_eq!(hub.agent_channel_owner(&other), Some(b), "b is untouched");
    assert_eq!(hub.queued_agent_count(&other), 1);
    assert_eq!(hub.agent_streams_in_use(), 1);
    assert!(hub.claim_agent(&CHANNEL, TOKEN_A, SHORT).await.is_none());

    // The target sees a reset, not a clean end, on the stream that was
    // queued for the dead conduit.
    let (_send, mut recv) = client.accept_bi().await.expect("the first stream");
    let mut buf = [0u8; 8];
    // The 'x' written before the reset may or may not be delivered first;
    // what matters is that the stream ends in an error.
    let outcome = loop {
        match recv.read(&mut buf).await {
            Ok(Some(_)) => continue,
            other => break other,
        }
    };
    assert!(outcome.is_err(), "expected a reset, got {outcome:?}");
}

/// A claim parked on a channel is released when the conduit that registered
/// it dies, rather than sitting out its budget.
#[tokio::test]
async fn a_parked_agent_claim_ends_when_its_conduit_dies() {
    let hub = hub();
    let (a, _inbox) = hub.register_conduit();
    hub.send_request(a, 1, exec_start(&CHANNEL)).unwrap();
    let waiting = {
        let hub = Arc::clone(&hub);
        tokio::spawn(async move { hub.claim_agent(&CHANNEL, TOKEN_A, LONG).await.is_none() })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    hub.unregister_conduit(a);
    let ended = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("the claim must not wait out its budget");
    assert!(ended.unwrap());
}
