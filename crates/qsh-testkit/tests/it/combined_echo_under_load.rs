//! L10 for the combined endpoint (ADR-0059 DoD 27.12, `docs/design/testing.md`
//! L9/L10): the budget of `tunnel_echo_under_load` (a saturating `-L` tunnel
//! and a PTY echo on one connection, p95 below measured RTT + 10 ms), run
//! against a `qsh listen --serve` shaped endpoint instead of a standalone
//! `qsh serve`. The endpoint also holds a registered reverse target for the
//! whole measurement, so the forward branch is judged with the registration
//! role present on the same socket, admission gate and quota tracker. The
//! measurement itself is the one `tunnel_echo_under_load` uses, unchanged.
//!
//! Gated by `QSH_ACCEPTANCE_SLOW` (or `QSH_ACCEPTANCE_STRICT`) like it.

use std::sync::Arc;

use qsh_core::acl::AllowAllPinned;
use qsh_core::client::Session;
use qsh_core::quota::QuotaLimits;
use qsh_testkit::combined::CombinedHarness;
use qsh_testkit::loopback::make_identity;

use super::combined::{keepalive, pins};
use super::tunnel_echo_under_load::{gate_requested, measure_saturated_echo, skip};

#[tokio::test(flavor = "multi_thread")]
async fn combined_tunnel_echo_under_load() {
    if !gate_requested() {
        skip();
        return;
    }
    let laptop = make_identity();
    let widget = make_identity();
    let h = CombinedHarness::start(
        Arc::new(AllowAllPinned),
        pins(&[(&laptop, "laptop"), (&widget, "widget")]),
        QuotaLimits::default(),
    )
    .await;

    // The registration role is live for the whole run.
    let (registered, ctl, _hello) = h.register(&widget, "").await.expect("widget registers");
    let _keep = keepalive(ctl);
    assert!(h.listen.registry().get("widget").is_some());

    let (dialed, ctl, hello) = h.forward(&laptop).await.expect("laptop connects");
    let mut session = Session::from_control(dialed.connection.clone(), ctl, hello);
    let measured = measure_saturated_echo(&mut session, &h.pipes).await;
    session.close();

    assert!(
        h.listen.registry().get("widget").is_some(),
        "the registration outlived the forward load"
    );
    let report = measured.report();
    eprintln!("combined_tunnel_echo_under_load: {report}");
    drop(registered);
    h.shutdown().await;
    measured.assert_gates(&report);
}
