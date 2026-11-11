//! The combined `listen` + `serve` endpoint (ADR-0059) as the rendezvous R of
//! a hole punch, over netsim: the punch branch of the connection split
//! (decision 5, DoD 27.2 and 27.4).
//!
//! The clocks that matter here are the paused ones: a quiet forward client
//! must not be closed as a punching one however long it idles
//! (`a_quiet_forward_client_on_a_combined_endpoint_is_not_closed_as_punch`),
//! and a punch through a combined R must run the same signalling as one
//! through a bare `qsh listen` (`punch_through_a_combined_rendezvous`).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::admission::Gate;
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Clock, SystemClock};
use qsh_core::handshake;
use qsh_core::quota::{QuotaLimits, Quotas};
use qsh_proto::wire::{self, ControlMessage, control_message};
use qsh_testkit::combined::build_roles;
use qsh_testkit::make_identity;
use qsh_testkit::netsim::{NatKind, Net, NetConfig};
use qsh_testkit::reverse::forward_hello;
use qsh_transport::{
    Listener, Principal, PunchEndpoint, SocketSource, StaticTrust, TransportTuning,
};

use super::punch_route::{WorldOptions, exec, punched, world};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// DoD 27.2: a client that holds a connection and sends no request (the
/// holder of a `-L`) is a forward client. With the clock stopped it idles for
/// sixty seconds, past the 3 s rendezvous window and the 45 s transport idle,
/// and the connection is still open, still answers `Ping`, and still serves a
/// request afterwards. No punching connection was ever counted.
#[tokio::test(start_paused = true)]
async fn a_quiet_forward_client_on_a_combined_endpoint_is_not_closed_as_punch() {
    let net = Net::new(NetConfig {
        seed: 11,
        ..NetConfig::default()
    });
    let r_site = net.internet().site(NatKind::None, "r", ip("203.0.113.1"));
    let c_site = net.internet().site(NatKind::None, "c", ip("198.51.100.3"));
    let (r_id, c_id) = (make_identity(), make_identity());

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let limits = QuotaLimits::default();
    let gate = Arc::new(Gate::new(
        clock.clone(),
        qsh_core::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        qsh_core::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
        qsh_core::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
    ));
    let audit = Arc::new(MemoryAuditSink::new());
    let roles = build_roles(
        Arc::new(AllowAllPinned),
        audit.clone(),
        gate,
        Quotas::new(limits, clock),
        limits,
    );
    let r_trust = StaticTrust::empty().with_pin(c_id.fingerprint, Principal::Device("c".into()));
    let listener = Listener::bind_virtual(
        Arc::new(r_site.bind_wildcard(9000).unwrap()),
        r_id.local.clone(),
        Arc::new(r_trust),
        TransportTuning::default(),
    )
    .unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let r_task = tokio::spawn(roles.server.clone().run(listener, async move {
        let _ = stop_rx.await;
    }));

    let c = PunchEndpoint::new(
        SocketSource::Virtual(Arc::new(c_site.bind_wildcard(5000).unwrap())),
        c_id.local.clone(),
        Arc::new(StaticTrust::empty().with_pin(r_id.fingerprint, Principal::Device("r".into()))),
        TransportTuning::default(),
    )
    .unwrap();
    let conn = c
        .dial(
            "203.0.113.1:9000".parse().unwrap(),
            "qsh",
            Duration::from_secs(5),
            &r_id.fingerprint,
        )
        .await
        .expect("the client dials the combined endpoint");
    let (mut ctl, _hello) = handshake::initiate(&conn, forward_hello())
        .await
        .expect("a forward hello");

    tokio::time::sleep(Duration::from_secs(60)).await;

    assert!(
        conn.close_reason().is_none(),
        "a quiet forward connection stays open: {:?}",
        conn.close_reason()
    );
    assert_eq!(roles.listen.punch_connections(), 0);
    let ask = |id, body| ControlMessage::new(id, body);
    ctl.send
        .send(&ask(1, control_message::Body::Ping(wire::Ping {})))
        .await
        .expect("send Ping after a minute");
    let pong = ctl
        .recv
        .recv::<ControlMessage>()
        .await
        .expect("no stream error")
        .expect("the stream is open");
    assert!(matches!(pong.body, Some(control_message::Body::Pong(_))));
    // And it is a forward connection still: a request is the host's.
    ctl.send
        .send(&ask(
            2,
            control_message::Body::SessionOpen(wire::SessionOpen {
                argv: vec!["sh".into()],
                cols: 80,
                rows: 24,
                term: "xterm-256color".into(),
                ..Default::default()
            }),
        ))
        .await
        .expect("send a request after a minute");
    let reply = ctl
        .recv
        .recv::<ControlMessage>()
        .await
        .expect("no stream error")
        .expect("the stream is open");
    assert!(
        matches!(
            reply.body,
            Some(control_message::Body::Response(wire::Response {
                body: Some(wire::response::Body::SessionOpened(_))
            }))
        ),
        "{reply:?}"
    );
    assert_eq!(roles.broker.live_counts().live, 1);

    c.close(0, b"done");
    let _ = stop_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(10), r_task).await;
}

/// DoD 27.4: A punches to B through a combined endpoint as R. The signalling
/// is the one a bare `qsh listen` runs: R judges `host.punch`, relays the
/// offer over B's registration, and A and B open a connection of their own.
/// R recorded one `punch.request`, and A's command ran over the punch.
#[tokio::test(flavor = "multi_thread")]
async fn punch_through_a_combined_rendezvous() {
    let w = world(WorldOptions {
        direct_listener: false,
        pin_b_address: false,
        combined_r: true,
        ..WorldOptions::default()
    })
    .await;
    let out = exec(&w.a.ops, "b")
        .await
        .expect("exec over a punch through the combined endpoint");
    assert!(punched(&out), "exit {}", out.data.remote_exit_code);
    assert_eq!(w.punch_requests(), 1, "one request reached R's choke point");
    assert_eq!(
        w.r_listen.punch_connections(),
        0,
        "the punching connection of A to R is closed after the answer"
    );
    w.shutdown().await;
}
