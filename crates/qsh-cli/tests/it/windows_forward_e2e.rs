//! The forward route end to end on Windows: a real `qsh serve` host and a real
//! `qsh` client, each in its own sandbox, driven through the shared cases in
//! `route_cases.rs` (ADR-0035 decisions 1 and 14, `docs/CLI.md` §6.8, §6.9).
//!
//! The reverse route runs the same cases in `windows_reverse_e2e.rs`, so a
//! behaviour that differs between the routes shows up as one module failing
//! where the other passes. The session ops run here against the host's own
//! ConPTY sessions; the interactive form is `windows_attach.rs`, against the
//! in-process echo host.

#![cfg(windows)]

use crate::common::{Sandbox, ServeGuard};
use crate::route_cases::{self as cases, ForwardRoute};

#[test]
fn exec_round_trip() {
    cases::exec_round_trip(&ForwardRoute::start());
}

#[test]
fn exec_timeout_kills_the_whole_tree() {
    cases::exec_timeout_kills_the_whole_tree(&ForwardRoute::start());
}

#[test]
fn audit_record_and_lock_file_land_in_the_hosts_state_directory() {
    let route = ForwardRoute::start();
    cases::audit_record_and_lock_file_land_in_the_hosts_state_directory(&route, &route.fleet.host);
}

/// `qsh serve` starting on an `acl.toml` that `Everyone` can write to
/// warns with the DACL's structural fields and goes on to serve
/// (ADR-0035 decision 24). The reverse route's twin is in
/// `windows_reverse_e2e.rs`.
#[test]
fn acl_toml_with_an_everyone_write_ace_warns_at_startup() {
    let host = Sandbox::initialized();
    let acl_path = cases::plant_everyone_writable_acl(&host);
    let serve = ServeGuard::start(&host);
    cases::assert_acl_dacl_warning(|| serve.stderr_snapshot(), &acl_path);
}

#[test]
fn pty_session_runs_a_command() {
    cases::pty_session_runs_a_command(&ForwardRoute::start());
}

#[test]
fn pty_session_default_shell_takes_input() {
    cases::pty_session_default_shell_takes_input(&ForwardRoute::start());
}

#[test]
fn pty_session_resize_is_applied() {
    cases::pty_session_resize_is_applied(&ForwardRoute::start());
}

#[test]
fn pty_session_close_ends_a_running_session() {
    cases::pty_session_close_ends_a_running_session(&ForwardRoute::start());
}

#[test]
fn session_close_with_each_signal_ends_the_session() {
    cases::session_close_with_each_signal_ends_the_session(&ForwardRoute::start());
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
fn cp_round_trip() {
    cases::cp_round_trip(&ForwardRoute::start_full());
}

#[test]
fn cp_refuses_state_paths_and_reparse_points() {
    cases::cp_refuses_state_paths_and_reparse_points(&ForwardRoute::start_full());
}
