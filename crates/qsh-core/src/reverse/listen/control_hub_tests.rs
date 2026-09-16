use super::*;

fn hub() -> Arc<ControlHub> {
    ControlHub::new("widget".into(), "sha256:deadbeef".into(), 1, Vec::new())
}

/// The ordinary case: `tunnel_id` lives on exactly one of several
/// registered hosts' hubs.
#[test]
fn tunnel_close_target_finds_the_one_hub_that_holds_the_id() {
    let hub_a = hub();
    let hub_b = hub();
    let (conduit_a, _rx_a) = hub_a.register_conduit();
    hub_a.register_forward_for_test("fid-on-a", conduit_a);

    let hubs = vec![("host-a".to_string(), hub_a), ("host-b".to_string(), hub_b)];
    match tunnel_close_target(&hubs, "fid-on-a") {
        TunnelCloseTarget::One(hub) => assert!(Arc::ptr_eq(hub, &hubs[0].1)),
        other => panic!("expected exactly one match, got {other:?}"),
    }
}

/// An id nothing holds is `None`, not an error and not a match —
/// `LocalTunnelCloseResult::closed`'s idempotent-not-error contract
/// starts here.
#[test]
fn tunnel_close_target_of_an_unknown_id_is_none() {
    let hub_a = hub();
    let hubs = vec![("host-a".to_string(), hub_a)];
    assert!(matches!(
        tunnel_close_target(&hubs, "never-registered"),
        TunnelCloseTarget::None
    ));
}

/// **The regression this whole function exists for.** The same
/// `forward_id` string registered on two different hosts' hubs at
/// once (a colliding/adversarial peer, or — pre-fix — the astronomically
/// unlikely accidental ULID collision) must refuse to pick one rather
/// than silently closing whichever hub iteration happened to visit
/// first. Before this fix, `serve_admin_tunnel_close`'s
/// `Iterator::any` shape closed on the first match — this asserts the
/// fixed shape instead: `Ambiguous(2)`, and — mutation-checked —
/// `TunnelCloseTarget::One` would make this test fail immediately,
/// since a `HashMap`-sourced `hubs_snapshot()`'s order is not fixed
/// and either hub could be "first".
#[test]
fn tunnel_close_target_refuses_to_guess_between_two_colliding_hosts() {
    let hub_a = hub();
    let hub_b = hub();
    let (conduit_a, _rx_a) = hub_a.register_conduit();
    let (conduit_b, _rx_b) = hub_b.register_conduit();
    hub_a.register_forward_for_test("collided-id", conduit_a);
    hub_b.register_forward_for_test("collided-id", conduit_b);

    let hubs = vec![("host-a".to_string(), hub_a), ("host-b".to_string(), hub_b)];
    match tunnel_close_target(&hubs, "collided-id") {
        TunnelCloseTarget::Ambiguous(2) => {}
        other => panic!("expected Ambiguous(2), got {other:?}"),
    }
    // And neither hub's registration was touched by the decision
    // itself (`tunnel_close_target` never calls `admin_close_forward`
    // — that is the caller's job, only after seeing `One`).
    assert_eq!(hubs[0].1.forward_registry_len(), 1);
    assert_eq!(hubs[1].1.forward_registry_len(), 1);
}

fn read_body(after: u64) -> wire::control_message::Body {
    wire::control_message::Body::SessionRead(wire::SessionRead {
        session_id: "s1".into(),
        after,
        max_bytes: 0,
        wait_ms: 30_000,
        ctl_after: 0,
    })
}

fn list_body() -> wire::control_message::Body {
    wire::control_message::Body::SessionList(wire::SessionList {})
}

fn opened_response(session_id: &str) -> wire::Response {
    wire::Response {
        body: Some(wire::response::Body::SessionOpened(wire::SessionOpened {
            session_id: session_id.to_string(),
            resume_token: Vec::new(),
            ticket: Vec::new(),
            initial_seq: 0,
            expires_at: String::new(),
        })),
    }
}

/// The BLOCKER this cap exists to close (adversarial review finding):
/// a per-conduit cap of the same magnitude as the target's shared
/// per-connection long-poll budget does not bound the shared
/// resource at all — one conduit, entirely within its own allowance,
/// can occupy the whole thing. Proven directly against
/// `ControlHub::send_request`: conduit A alone hits the *hub-wide*
/// cap well below its own per-conduit cap, and — the actual
/// cross-conduit denial — a completely different conduit B is
/// refused a long-poll it never asked much of, while a non-long-poll
/// request from B still goes through (the cap is scoped to
/// `SessionRead`/`SessionClose` only).
#[test]
fn long_poll_cap_is_hub_wide_not_per_conduit() {
    let hub = hub();
    let (a, _rx_a) = hub.register_conduit();
    let (b, _rx_b) = hub.register_conduit();

    for i in 0..MAX_INFLIGHT_LONG_POLL_PER_HUB as u64 {
        hub.send_request(a, i, read_body(i))
            .expect("under the hub-wide cap");
    }
    const _: () = assert!(
        MAX_INFLIGHT_LONG_POLL_PER_HUB < crate::localctl::mux::MAX_INFLIGHT_PER_CONDUIT,
        "the whole point of this cap is to bind tighter than the per-conduit one"
    );
    assert!(
        matches!(
            hub.send_request(a, 9999, read_body(9999)),
            Err(HubSendError::Exhausted)
        ),
        "conduit a is still far under its own per-conduit cap, but the hub-wide \
         long-poll budget is spent"
    );

    // The actual DoS this finding demonstrated: a *different* conduit
    // that has sent nothing at all is refused too, because the shared
    // budget — not either conduit's own allowance — is what is
    // spent.
    assert!(
        matches!(
            hub.send_request(b, 0, read_body(0)),
            Err(HubSendError::Exhausted)
        ),
        "conduit b must be denied a long-poll while the hub-wide budget is \
         saturated, even though b itself sent nothing"
    );

    // Only long-poll-classified requests are bounded by this cap — a
    // plain request from the otherwise-blocked conduit still goes
    // through untouched.
    assert!(
        hub.send_request(b, 1, list_body()).is_ok(),
        "a non-long-poll request must never be refused by the long-poll cap"
    );
}

/// A dying conduit must not hand its share of the hub-wide long-poll
/// budget back early — the target-side permit it occupied is not
/// actually freed just because nobody is listening for the answer any
/// more (`MAX_INFLIGHT_LONG_POLL_PER_HUB`'s doc: there is no
/// wire-level cancel). The budget is only released when the `Response`
/// actually arrives, however late.
#[tokio::test]
async fn conduit_death_does_not_free_the_long_poll_budget_but_the_late_response_does() {
    let hub = hub();
    let (a, _rx_a) = hub.register_conduit();
    let (b, _rx_b) = hub.register_conduit();

    for i in 0..MAX_INFLIGHT_LONG_POLL_PER_HUB as u64 {
        hub.send_request(a, i, read_body(i)).unwrap();
    }
    let mut outbound = hub
        .take_outbound_receiver()
        .expect("hub has an outbound receiver");
    let mut sent_ids = Vec::new();
    for _ in 0..MAX_INFLIGHT_LONG_POLL_PER_HUB {
        let (daemon_request_id, _) = outbound.recv().await.expect("queued send");
        sent_ids.push(daemon_request_id);
    }

    hub.unregister_conduit(a);
    assert!(
        matches!(
            hub.send_request(b, 0, read_body(0)),
            Err(HubSendError::Exhausted)
        ),
        "a's death alone must not free target-side long-poll capacity nobody \
         actually reclaimed"
    );

    // The (late) `Response` for one of a's now-orphaned long-polls
    // arrives — this is what actually frees its slot.
    hub.deliver_response(
        sent_ids[0],
        wire::Response {
            body: Some(wire::response::Body::SessionReadResult(
                wire::SessionReadResult {
                    events: Vec::new(),
                    next_after: 0,
                    next_ctl_after: 0,
                },
            )),
        },
    );
    assert!(
        hub.send_request(b, 1, read_body(1)).is_ok(),
        "once the target's own reply actually arrives, the hub-wide budget \
         must be released"
    );
}

fn rfwd_open_body() -> wire::control_message::Body {
    wire::control_message::Body::RfwdOpen(wire::RemoteForwardOpen::default())
}

fn rfwd_opened_response(forward_id: &str) -> wire::Response {
    wire::Response {
        body: Some(wire::response::Body::RfwdOpened(
            wire::RemoteForwardOpened {
                forward_id: forward_id.to_string(),
                actual_port: 0,
            },
        )),
    }
}

/// **Finding: a duplicate `forward_id` must not silently transfer
/// ownership.** `forward_id` is target-minted (`ulid::Ulid::new()`)
/// and practically unique, but this relay must not trust that: a
/// second `RemoteForwardOpened` naming an id already registered to
/// conduit A, answering a *different* request conduit B issued, must
/// leave A as the owner — never silently hand B the registration (and
/// with it, any arrival already queued for it).
#[tokio::test]
async fn a_duplicate_forward_id_does_not_transfer_ownership_to_a_later_registrant() {
    let hub = hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    let mut outbound = hub
        .take_outbound_receiver()
        .expect("hub has an outbound receiver");

    hub.send_request(conduit_a, 0, rfwd_open_body()).unwrap();
    let (daemon_request_id_a, _) = outbound.recv().await.expect("queued send");
    hub.send_request(conduit_b, 0, rfwd_open_body()).unwrap();
    let (daemon_request_id_b, _) = outbound.recv().await.expect("queued send");

    hub.deliver_response(daemon_request_id_a, rfwd_opened_response("fid-dup"));
    assert_eq!(
        hub.forward_owner("fid-dup"),
        Some(conduit_a),
        "conduit_a's registration must seat first"
    );

    // The target (bug, or adversary) answers conduit_b's own,
    // separate request with the *same* forward_id conduit_a already
    // holds. Mutation-check target: deleting this rejection and
    // letting the `insert` run unconditionally again is exactly what
    // would make this test fail.
    hub.deliver_response(daemon_request_id_b, rfwd_opened_response("fid-dup"));
    assert_eq!(
        hub.forward_owner("fid-dup"),
        Some(conduit_a),
        "a duplicate forward_id must never move ownership away from its first registrant"
    );
}

/// The reverse relay's late-response rule, symmetric with the forward
/// route: session lifetime is decoupled from connection lifetime
/// (`docs/PRD.md`'s core premise). On the forward route, a CLI that
/// dies between sending `session.open` and receiving `SessionOpened`
/// leaves a live session on the target — discoverable via
/// `session.list`, closable via `session.close` — never leaked or
/// invisible. A late `Response` for a `daemon_request_id` whose
/// conduit already died must behave identically here: dropped, full
/// stop. The relay must not originate a `session.close` on its own
/// initiative — it carries no business logic, and the target would
/// audit a close nobody requested under the controller principal.
#[tokio::test]
async fn a_late_response_for_a_dead_conduit_is_dropped_and_sends_nothing() {
    let hub = hub();
    let (a, _rx_a) = hub.register_conduit();
    hub.send_request(
        a,
        0,
        wire::control_message::Body::SessionOpen(wire::SessionOpen {
            argv: vec!["sh".into()],
            env: Default::default(),
            term: String::new(),
            cols: 0,
            rows: 0,
            user: None,
        }),
    )
    .unwrap();

    let mut outbound = hub
        .take_outbound_receiver()
        .expect("hub has an outbound receiver");
    let (open_id, _) = outbound.recv().await.expect("the queued session.open");

    // The conduit dies before the reply arrives — its own mux table
    // entry (and, were this a long-poll body, its `long_poll_ids`
    // membership) is already gone.
    hub.unregister_conduit(a);
    assert_eq!(
        hub.total_in_flight(),
        0,
        "the dead conduit's entry must already be gone from the mux table"
    );

    // The reply arrives late — nobody is registered to receive it any
    // more.
    hub.deliver_response(open_id, opened_response("orphan-session-1"));

    // Dropped, not compensated: nothing goes out on the outbound
    // channel — no compensating `session.close`, nothing at all.
    let outcome = tokio::time::timeout(Duration::from_millis(50), outbound.recv()).await;
    assert!(
        outcome.is_err(),
        "a late response for a dead conduit must send nothing on the outbound \
         channel, got {outcome:?}"
    );

    // Still nothing under `open_id` in the mux table after the late
    // delivery.
    assert_eq!(hub.total_in_flight(), 0);
}

/// `HubState::dead` closes the race a conduit can otherwise fall into:
/// resolving this hub, then registering *after* `mark_dead` already
/// ran (the real window `crate::localctl::daemon::serve_control` has
/// — an await for the `LocalHelloAck` write sits between the two).
/// Without the sticky flag such a conduit would be handed a
/// live-looking hub and hang forever; with it, the very first thing
/// its inbox receives is `HostDead`.
#[tokio::test]
async fn registering_after_mark_dead_delivers_host_dead_immediately() {
    let hub = hub();
    hub.mark_dead();

    let (_conduit, mut inbox) = hub.register_conduit();
    assert!(
        matches!(inbox.recv().await, Some(ConduitInbound::HostDead)),
        "a conduit registering after the hub is already dead must be told \
         immediately, not left to hang"
    );
}
