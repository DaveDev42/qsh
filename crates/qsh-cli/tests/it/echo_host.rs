//! The echo host behind the real `qsh` client (`qsh_testkit::echo_host`), on
//! its forward route (the reverse route retired with ADR-0068).
//!
//! The interactive client's console tests on Windows want a host whose output
//! is exactly what it was sent, not a ConPTY's rendering of it. These routes
//! put an echo-session host behind the real client instead: the forward route
//! is a QUIC listener that pins the client's fingerprint. Everything but the
//! session source is production code.
//!
//! The case in this file needs no terminal, so it runs on every platform and
//! proves the route itself; `windows_attach.rs` drives the interactive
//! client through them in a ConPTY.

use crate::common::{HOST_ALIAS, Sandbox};

use qsh_testkit::echo_host::EchoHost;

/// A route from a real `qsh` client to an echo host.
pub trait EchoRoute {
    /// The sandbox every client command runs in.
    fn client(&self) -> &Sandbox;
    /// The host's name, as the client knows it.
    fn name(&self) -> &str;
    /// The host, for what only its broker can tell.
    fn host(&self) -> &EchoHost;
}

/// Client to an echo host over QUIC.
pub struct EchoForward {
    pub client: Sandbox,
    pub host: EchoHost,
}

impl EchoForward {
    pub fn start() -> Self {
        let client = Sandbox::initialized();
        let host = EchoHost::new();
        let addr = host.serve_forward(&client.fingerprint());
        client.trust_add(HOST_ALIAS, Some(&addr.to_string()), &host.fingerprint());
        Self { client, host }
    }
}

impl EchoRoute for EchoForward {
    fn client(&self) -> &Sandbox {
        &self.client
    }

    fn name(&self) -> &str {
        HOST_ALIAS
    }

    fn host(&self) -> &EchoHost {
        &self.host
    }
}

/// `qsh session open` through the route makes one session on the echo host,
/// which `qsh sessions` then lists as running and detached (nobody attached).
fn session_open_then_list(route: &impl EchoRoute) {
    let (code, opened) = route
        .client()
        .json(&["session", "open", route.name(), "--json"]);
    assert_eq!(code, 0, "session open through the route failed: {opened}");

    let counts = route.host().live_counts();
    assert_eq!((counts.live, counts.detached), (1, 1), "{counts:?}");

    let (code, listed) = route.client().json(&["sessions", route.name(), "--json"]);
    assert_eq!(code, 0, "{listed}");
    let sessions = listed["data"]["sessions"].as_array().expect("sessions");
    assert_eq!(sessions.len(), 1, "{listed}");
    assert_eq!(sessions[0]["state"], "running", "{listed}");
}

#[test]
fn echo_host_serves_a_session_over_the_forward_route() {
    session_open_then_list(&EchoForward::start());
}
