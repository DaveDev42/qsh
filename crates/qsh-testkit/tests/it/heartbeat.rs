//! L3 loopback tests for the client heartbeat (`AttachWriter::send_heartbeat`):
//! an `Input` frame with no bytes, which the host takes for a repeat of input
//! it already ran and answers with an `InputAck`. The reverse route uses it to
//! ask the host a question the local daemon would otherwise answer itself.

use qsh_core::client::AttachEvent;
use qsh_testkit::loopback::LoopbackHarness;

use crate::screen_sync::{DEADLINE, open_attached, open_req};

/// The next `InputAck` the host sends.
async fn next_ack(att: &mut qsh_core::client::Attached) -> u64 {
    tokio::time::timeout(DEADLINE, async {
        loop {
            if let AttachEvent::InputAck { acked_input_seq } =
                att.next().await.expect("event").expect("stream open")
            {
                return acked_input_seq;
            }
        }
    })
    .await
    .expect("the host answered")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_heartbeat_is_answered_with_the_applied_offset_and_runs_no_input() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let req = open_req(&s);
    let (_opened, mut pipe, mut att) = open_attached(&h, &mut s, req).await;

    assert_eq!(att.send_input(b"abc").await.unwrap(), 3);
    assert_eq!(pipe.read_input(16).await.unwrap(), b"abc");
    assert_eq!(next_ack(&mut att).await, 3);

    // At the acknowledged offset, and below it: the answer is the host's
    // own offset either way, never a protocol error.
    for up_to in [3, 3, 1, 0] {
        att.send_heartbeat(up_to).await.unwrap();
        assert_eq!(next_ack(&mut att).await, 3, "heartbeat at {up_to}");
    }
    // Nothing reached the program, and typing goes on from where it was.
    assert_eq!(att.input_seq(), 3);
    assert_eq!(att.send_input(b"d").await.unwrap(), 4);
    assert_eq!(pipe.read_input(16).await.unwrap(), b"d");
    // Acks of the earlier heartbeats may still be queued ahead of this one.
    while next_ack(&mut att).await < 4 {}
    s.close();
    h.shutdown().await;
}
