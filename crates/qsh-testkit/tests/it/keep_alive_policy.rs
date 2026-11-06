//! L3 loopback tests for the keep-alive policy (ADR-0052 decisions 12 (e)
//! and 13). The policy is applied with the control-stream `Ping`, so the
//! tests count the `Ping`s the host writes (`Server::keep_alive_pings`) on a
//! live screen-sync attach. A NAT rebind is injected
//! (`Server::inject_nat_rebind`) since loopback never changes address; the
//! policy's thresholds themselves are pinned by the table tests in
//! `qsh-core`'s `adapt` module.

use std::time::Duration;

use qsh_core::broker::PipeHandle;
use qsh_core::client::{Attached, Session};
use qsh_testkit::loopback::LoopbackHarness;

use super::screen_sync::{open_attached, open_req};

/// Keep reading the attach (answering the host's `Ping`s) for `span`.
async fn drain_for(att: &mut Attached, span: Duration) {
    let _ = tokio::time::timeout(span, async {
        loop {
            if att.next().await.is_err() {
                return;
            }
        }
    })
    .await;
}

/// An attach with screen sync. The session and pipe are returned so they
/// outlive the test body.
async fn attach(h: &LoopbackHarness) -> (Session, PipeHandle, Attached) {
    let mut s = h.session().await;
    let req = open_req(&s);
    let (_opened, pipe, att) = open_attached(h, &mut s, req).await;
    (s, pipe, att)
}

#[tokio::test(flavor = "multi_thread")]
async fn no_policy_ping_flows_while_nothing_shortened_the_interval() {
    let h = LoopbackHarness::start().await;
    let (_s, _pipe, mut att) = attach(&h).await;
    drain_for(&mut att, Duration::from_secs(3)).await;
    assert_eq!(h.server.keep_alive_pings(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn after_a_nat_rebind_pings_flow_at_the_policy_interval() {
    let h = LoopbackHarness::start().await;
    let (_s, _pipe, mut att) = attach(&h).await;
    // g = 2 s gives clamp(g / 2, 1 s, 15 s) = 1 s.
    h.server.inject_nat_rebind(Duration::from_secs(2));
    drain_for(&mut att, Duration::from_millis(5500)).await;
    let n = h.server.keep_alive_pings();
    // One ping a second for roughly 4.5 s after the policy picked it up,
    // with the pump's one-second wake-up granularity on either side.
    assert!((2..=6).contains(&n), "{n} policy pings in 5.5 s");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_written_key_pins_the_interval_and_the_policy_stays_silent() {
    let h = LoopbackHarness::start().await;
    h.server.pin_keep_alive(Duration::from_secs(15));
    let (_s, _pipe, mut att) = attach(&h).await;
    h.server.inject_nat_rebind(Duration::from_secs(2));
    drain_for(&mut att, Duration::from_millis(4500)).await;
    assert_eq!(h.server.keep_alive_pings(), 0);
}
