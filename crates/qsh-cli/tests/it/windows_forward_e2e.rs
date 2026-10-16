//! The forward route end to end on Windows: a real `qsh serve` host and a real
//! `qsh` client, each in its own sandbox, driven through the shared cases in
//! `route_cases.rs` (ADR-0035 decisions 1 and 14, `docs/CLI.md` §6.8, §6.9).
//!
//! The reverse route runs the same cases in `windows_reverse_e2e.rs`, so a
//! behaviour that differs between the routes shows up as one module failing
//! where the other passes. The interactive form is `windows_attach.rs`, against
//! the in-process echo host, since a Windows host has no PTY sessions yet.

#![cfg(windows)]

use crate::route_cases::{self as cases, ForwardRoute};

#[test]
fn exec_round_trip() {
    cases::exec_round_trip(&ForwardRoute::start());
}

#[test]
fn local_tunnel_echo() {
    cases::local_tunnel_echo(&ForwardRoute::start());
}

#[test]
fn remote_tunnel_echo() {
    cases::remote_tunnel_echo(&ForwardRoute::start());
}

#[test]
fn local_tunnel_delivers_the_destinations_close() {
    cases::local_tunnel_delivers_the_destinations_close(&ForwardRoute::start());
}

#[test]
fn dynamic_forward_connect() {
    cases::dynamic_forward_connect(&ForwardRoute::start());
}

#[test]
fn hosts_lists_the_forward_host_without_a_daemon() {
    let route = ForwardRoute::start();
    cases::hosts_names_the_host(&route, "forward");

    // No daemon runs on the client's side and nothing is reverse.
    assert!(
        cases::reverse_entries(&route.fleet.client).is_empty(),
        "a forward-only machine listed a reverse entry"
    );
}

#[test]
fn cp_to_a_windows_host_is_unsupported_before_m20() {
    cases::cp_to_a_windows_host_is_unsupported_before_m20(&ForwardRoute::start(), false);
}
