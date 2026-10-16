//! The echo host behind the real `qsh` client (`qsh_testkit::echo_host`), on
//! both routes.
//!
//! A Windows host answers `UNSUPPORTED` to PTY sessions until the Windows host
//! role lands, so the interactive client cannot be driven against a real
//! `qsh serve` there. These routes put an echo-session host behind the real
//! client instead: the forward route is a QUIC listener that pins the
//! client's fingerprint, the reverse route is a real `qsh listen` daemon with
//! the echo host registered on it as a target. Everything but the session
//! source is production code.
//!
//! The cases in this file need no terminal, so they run on every platform and
//! prove the routes themselves; `windows_attach.rs` drives the interactive
//! client through them in a ConPTY.

use crate::common::{HOST_ALIAS, ListenGuard, Sandbox, hosts_array, poll_until};

use std::time::Duration;

use qsh_testkit::echo_host::EchoHost;

/// The name the controller's trust store gives the echo target.
pub const REVERSE_NAME: &str = "echo-target";

/// How long the daemon may take to show the registration.
const REGISTERED_DEADLINE: Duration = Duration::from_secs(30);

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

/// Client to an echo host registered on the client's own `qsh listen` daemon.
pub struct EchoReverse {
    /// The controller, and the sandbox the client commands run in.
    pub controller: Sandbox,
    pub _listen: ListenGuard,
    pub host: EchoHost,
}

impl EchoReverse {
    /// Daemon up, echo host registered and listed as reachable.
    pub fn start() -> Self {
        let controller = Sandbox::initialized();
        let host = EchoHost::new();
        // The daemon pins the target by fingerprint only, with no address:
        // the one way to reach `REVERSE_NAME` is the live registration.
        controller.trust_add(REVERSE_NAME, None, &host.fingerprint());
        let listen = ListenGuard::start(&controller);
        host.register(listen.addr(), &controller.fingerprint(), REVERSE_NAME);
        poll_until(
            "the echo target to be listed as a reachable reverse entry",
            REGISTERED_DEADLINE,
            || {
                hosts_array(&controller)
                    .into_iter()
                    .find(|h| h["name"] == REVERSE_NAME && h["connection_mode"] == "reverse")
                    .filter(|h| h["state"] == "reachable")
            },
        );
        Self {
            controller,
            _listen: listen,
            host,
        }
    }
}

impl EchoRoute for EchoReverse {
    fn client(&self) -> &Sandbox {
        &self.controller
    }

    fn name(&self) -> &str {
        REVERSE_NAME
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

#[test]
fn echo_host_serves_a_session_over_the_reverse_route() {
    session_open_then_list(&EchoReverse::start());
}
