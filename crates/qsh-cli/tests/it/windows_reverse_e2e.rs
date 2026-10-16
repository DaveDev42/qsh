//! The reverse route end to end on Windows: a real `qsh listen` controller and
//! a real `qsh serve --to` target in separate sandboxes, with the client
//! commands running against the controller's daemon over its named pipe
//! (ADR-0035 decisions 1, 14 and 19, `docs/CLI.md` §6.13, §6.14).
//!
//! The shared cases live in `route_cases.rs` and also run over the forward
//! route in `windows_forward_e2e.rs`. The rest are the ones only a daemon can
//! have: its listing of the registration, the registration surviving the
//! controller's restart, and its `tunnels` and `tunnel close`.
//!
//! No test-only harness stands in for either side. Attaching a pty session
//! through the route needs ConPTY and is M20's, so those cases stay in
//! `reverse_e2e.rs`.

#![cfg(windows)]

use crate::common;
use crate::route_cases::{self as cases, ReverseRoute, Route, TunnelHolder};

use std::time::Duration;

use common::{ListenGuard, poll_until, steady_bind};

/// A registration made through a controller that was just killed is noticed
/// at the idle timeout at the latest, so the waits that depend on that get
/// more than the usual deadline.
const NOTICE_DEADLINE: Duration = Duration::from_secs(90);

#[test]
fn exec_round_trip() {
    cases::exec_round_trip(&ReverseRoute::start());
}

#[test]
fn local_tunnel_echo() {
    cases::local_tunnel_echo(&ReverseRoute::start());
}

#[test]
fn remote_tunnel_echo() {
    cases::remote_tunnel_echo(&ReverseRoute::start());
}

#[test]
fn local_tunnel_delivers_the_destinations_close() {
    cases::local_tunnel_delivers_the_destinations_close(&ReverseRoute::start());
}

#[test]
fn hosts_lists_the_reverse_entry() {
    let route = ReverseRoute::start();
    cases::hosts_names_the_host(&route, "reverse");

    let entry = cases::wait_reverse_entry(&route.controller, "reachable", cases::READY_DEADLINE);
    assert_eq!(entry["name"], cases::REVERSE_NAME);
    assert!(
        entry.get("lost_at").is_none(),
        "a live reverse entry never carries lost_at: {entry}"
    );
}

#[test]
fn hosts_drops_the_reverse_entry_after_the_daemon_dies() {
    let ReverseRoute {
        controller,
        target,
        listen,
        reverse,
    } = ReverseRoute::start();
    assert_eq!(cases::reverse_entries(&controller).len(), 1);

    // The registration lives in the daemon's memory: with the daemon gone
    // nothing lists it, and `qsh hosts` still answers from the trust store.
    drop(listen);
    poll_until(
        "the dead daemon's reverse entry to disappear",
        cases::READY_DEADLINE,
        || cases::reverse_entries(&controller).is_empty().then_some(()),
    );

    drop(reverse);
    drop(target);
}

#[test]
fn target_re_registers_with_a_new_daemon() {
    let bind = steady_bind();
    let ReverseRoute {
        controller,
        target,
        listen,
        reverse,
    } = ReverseRoute::start_at(&bind);

    // A graceful stop closes the registration at once; when the test process
    // has no console to send the stop from, the daemon is killed and the
    // target finds out at the idle timeout instead.
    listen.shut_down();

    // The target keeps dialing the controller's pinned address; a new daemon
    // on it gets the registration without anything restarting on the target.
    let _listen = ListenGuard::start_with(&controller, &bind);
    let entry = cases::wait_reverse_entry(&controller, "reachable", NOTICE_DEADLINE);
    assert_eq!(entry["name"], cases::REVERSE_NAME);

    // And the route works through the new daemon.
    let (code, value) = controller.json(&[
        "exec",
        cases::REVERSE_NAME,
        "--json",
        "--",
        "cmd",
        "/c",
        "exit 3",
    ]);
    assert_eq!(code, 3, "{value}");
    drop(reverse);
    drop(target);
}

#[test]
fn tunnels_and_tunnel_close_reach_the_daemon() {
    let route = ReverseRoute::start();
    let echo = cases::start_echo();
    let remote_port = qsh_testkit::net_probe::free_port();
    let spec = format!("{remote_port}:127.0.0.1:{}", echo.port());

    // `-R` on the reverse route is the one tunnel the daemon holds, so it is
    // the one `qsh tunnels` can list (`docs/CLI.md` §6.9).
    let (_holder, envelope) = TunnelHolder::open(&route, "--remote", &spec);
    let tunnel_id = envelope["data"]["tunnel_id"]
        .as_str()
        .expect("tunnel_id")
        .to_string();

    let listed = poll_until(
        "the daemon to list the tunnel",
        cases::READY_DEADLINE,
        || {
            let (code, value) = route.client().json(&["tunnels", "--json"]);
            assert_eq!(code, 0, "{value}");
            let tunnels = value["data"]["tunnels"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            tunnels
                .iter()
                .any(|t| t["tunnel_id"] == tunnel_id.as_str())
                .then_some(tunnels)
        },
    );
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0]["mode"], "remote");

    let (code, closed) = route
        .client()
        .json(&["tunnel", "close", &tunnel_id, "--json"]);
    assert_eq!(code, 0, "{closed}");
    assert_eq!(closed["data"]["closed"], true, "{closed}");
    poll_until(
        "the closed tunnel to leave the listing",
        cases::READY_DEADLINE,
        || {
            let (_, value) = route.client().json(&["tunnels", "--json"]);
            value["data"]["tunnels"]
                .as_array()
                .is_some_and(Vec::is_empty)
                .then_some(())
        },
    );

    // Closing what is already gone is not an error.
    let (code, again) = route
        .client()
        .json(&["tunnel", "close", &tunnel_id, "--json"]);
    assert_eq!(code, 0, "{again}");
    assert_eq!(again["data"]["closed"], false, "{again}");
}
