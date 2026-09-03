//! L3 — the reverse-carrier tunnel data path end to end (`PLAN.md` M4
//! Step 5 (a), `docs/design/protocol.md` §11-3): a real
//! [`qsh_testkit::reverse::ReverseHarness`] target, a real localctl
//! daemon bound via [`ReverseHarness::attach_localctl`], and the real
//! production requester legs — [`LocalForwardHandle::start_reverse`]
//! (`-L`) and [`RemoteForwardAcceptor::spawn_reverse`] (`-R`) — driving
//! genuine TCP traffic through them.
//!
//! **Role-axis independence, proven mechanically, not asserted.** `-L`'s
//! and `-R`'s round-trip behavior is expressed as exactly one scenario
//! function each ([`scenario_local_forward_round_trips_through_a_target_echo`],
//! [`scenario_remote_forward_round_trips_through_a_controller_echo`]),
//! generic over a small [`LocalForwardCarrier`]/[`RemoteForwardCarrier`]
//! trait. [`qsh_testkit::tunnel::TunnelHarness`] (forward QUIC, M4 Step 3/4)
//! and this file's own reverse-route carriers each implement the trait;
//! the *same* scenario body then runs against both in
//! `l_over_forward_reaches_the_target_echo`/`l_over_reverse_reaches_the_target_echo`
//! and their `-R` counterparts. If the reverse carrier's implementation
//! ever diverged in observable behavior from the forward one, the shared
//! scenario body — not a second hand-copied test — would be the thing
//! that caught it, which is the actual claim "the carrier axis is
//! independent of tunnel behavior" needs to mean.
//!
//! **What `-R over reverse` is actually novel about**
//! (`PLAN.md`'s own framing): the target *dials* the controller, but once
//! registered it plays the *host* role for every op the controller sends
//! it — including `RemoteForwardOpen`, which this file drives over a raw
//! `LOCAL_CONTROL` conduit exactly like `local_stream_reverse.rs`'s own
//! helpers do (no `Ops`/CLI layer; `Session::from_local_control` and
//! `localctl::client::open_control` are `pub(crate)` on purpose — PR 5b's
//! job is to build the `Ops` layer on top of them, not this file's).
//! Once the target binds its loopback listener and a real TCP client
//! connects to it, the target opens `TCP_ACCEPTED{forward_id}` on the
//! *same* reverse QUIC connection it dialed in on; that stream has to
//! cross the controller's resident daemon to reach whichever CLI
//! conduit's [`RemoteForwardAcceptor`] registered that `forward_id` —
//! the third multiplexed state `crate::reverse::listen::ControlHub`'s own
//! module docs describe, and [`a_target_opened_tcp_accepted_reaches_only_its_own_conduit`]
//! is this file's proof that a second, independent `-R` binding on the
//! *same* target never sees a byte of the first's traffic, driven at the
//! full wire level (the registry-level version of this same claim lives
//! in `qsh_core::reverse::listen`'s own L2 unit tests).
//!
//! `#![cfg(unix)]`: localctl (UDS) and `ReverseHarness::attach_localctl`
//! are both unix-only, same as every other reverse-conduit L3 suite in
//! this crate (`local_stream_reverse.rs`, `local_control_reverse.rs`).

#![cfg(unix)]

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::localctl::frame::LocalConduit;
use qsh_core::tunnel::{LocalForwardHandle, RemoteForwardAcceptor};
use qsh_core::{Paths, Principal};
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LocalHello, LocalResponse, LocalStreamKind, local_response,
};
use qsh_proto::wire::{self, control_message, response};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_testkit::tunnel::{EchoServer, RemoteForwardBinding, TunnelHarness, ephemeral_local_spec};
use qsh_transport::StaticTrust;
use tokio::net::UnixStream;

/// Bound on every "this must have already happened" wait in this file —
/// same generosity `local_stream_reverse.rs`'s own `TIMEOUT` uses for the
/// identical reason (a real reverse registration plus one or two relay
/// hops, not a pure in-memory pipe).
const TIMEOUT: Duration = Duration::from_secs(15);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// Fresh, throwaway [`Paths`] — this file never touches `trust.toml`
/// (no `Ops`, module docs), so only `runtime_dir()` (what
/// [`ReverseHarness::attach_localctl`] binds its socket under) matters.
fn fresh_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, paths)
}

/// Connect a fresh `LOCAL_CONTROL` conduit for `host` and consume its
/// `LocalHelloAck` — identical to `local_stream_reverse.rs`'s own helper
/// of the same name (each test binary is its own crate; there is no
/// shared support module for these small wire-level helpers to live in).
async fn connect_control(socket_path: &Path, host: &str) -> LocalConduit<UnixStream> {
    let stream = UnixStream::connect(socket_path)
        .await
        .expect("connect localctl socket");
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalControl as i32,
            host: host.to_string(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .expect("send LocalHello");
    let ack: LocalResponse = conduit
        .recv()
        .await
        .expect("recv LocalHelloAck")
        .expect("conduit stayed open for the ack");
    match ack.body {
        Some(local_response::Body::HelloAck(_)) => {}
        other => panic!("expected LocalHelloAck, got {other:?}"),
    }
    conduit
}

async fn send_control(
    conduit: &mut LocalConduit<UnixStream>,
    request_id: u64,
    body: control_message::Body,
) {
    conduit
        .send(&wire::ControlMessage::new(request_id, body))
        .await
        .expect("send ControlMessage");
}

/// Read the next `ControlMessage` off `ctl`, skipping over any spontaneous
/// `SessionEvent` (`request_id = 0`) — see `local_stream_reverse.rs`'s own
/// `recv_control_response` for why one can land interleaved with a
/// request/response even though this file never opens a PTY session.
async fn recv_control_response(conduit: &mut LocalConduit<UnixStream>) -> wire::ControlMessage {
    loop {
        let msg: wire::ControlMessage = conduit
            .recv()
            .await
            .expect("recv ControlMessage")
            .expect("conduit stayed open");
        if matches!(msg.body, Some(control_message::Body::SessionEvent(_))) {
            continue;
        }
        return msg;
    }
}

// ------------------------------------------------------------------
// (i) `-L` over forward vs. reverse — one scenario, two carriers.
// ------------------------------------------------------------------

/// What a `-L` scenario needs from either carrier: bind a local forward
/// pointed at `host:port` and hand back the live handle. Implemented for
/// [`TunnelHarness`] (forward QUIC, already the production entry point
/// [`TunnelHarness::local_forward`] wraps) and for this file's
/// [`ReverseRoute`] (reverse, wrapping [`LocalForwardHandle::start_reverse`]
/// — also the real production entry point, PR 5b's `Ops` layer is just a
/// thinner caller of the same function).
trait LocalForwardCarrier {
    async fn start_local_forward(&self, host: &str, port: u16) -> LocalForwardHandle;
}

struct ForwardRoute<'a>(&'a TunnelHarness);

impl LocalForwardCarrier for ForwardRoute<'_> {
    async fn start_local_forward(&self, host: &str, port: u16) -> LocalForwardHandle {
        self.0.local_forward(host, port).await
    }
}

struct ReverseRoute<'a> {
    socket_path: &'a Path,
    host: &'a str,
}

impl LocalForwardCarrier for ReverseRoute<'_> {
    async fn start_local_forward(&self, host: &str, port: u16) -> LocalForwardHandle {
        LocalForwardHandle::start_reverse(
            &ephemeral_local_spec(host, port),
            self.socket_path.to_path_buf(),
            self.host.to_string(),
        )
        .await
        .expect("bind -L over reverse")
    }
}

/// **The role-axis-independence proof for `-L`** (`PLAN.md` M4 Step 5
/// (a)): bind a local forward at `echo`'s address through whichever
/// carrier the caller supplies, round-trip a payload through it, and
/// assert it comes back byte-for-byte. Nothing here names "forward" or
/// "reverse" — that split lives entirely in the two `#[tokio::test]`
/// functions below, each contributing only the harness setup its own
/// carrier needs.
async fn scenario_local_forward_round_trips_through_a_target_echo(
    carrier: impl LocalForwardCarrier,
    echo: &EchoServer,
) {
    let handle = carrier.start_local_forward("127.0.0.1", echo.port()).await;
    let payload = b"qsh -L round trip over the tunnel carrier under test".to_vec();
    let got = TunnelHarness::round_trip(handle.local_addr(), payload.clone())
        .await
        .expect("round trip through the local forward");
    assert_eq!(got, payload, "the echoed payload must come back unchanged");
}

#[tokio::test(flavor = "multi_thread")]
async fn l_over_forward_reaches_the_target_echo() {
    let harness = TunnelHarness::start().await;
    scenario_local_forward_round_trips_through_a_target_echo(ForwardRoute(&harness), &harness.echo)
        .await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn l_over_reverse_reaches_the_target_echo() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;
    let echo = EchoServer::start().await.expect("bind echo server");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        scenario_local_forward_round_trips_through_a_target_echo(
            ReverseRoute {
                socket_path: &localctl.socket_path,
                host: "widget",
            },
            &echo,
        )
        .await;

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

// ------------------------------------------------------------------
// (ii) `-R` over forward vs. reverse — one scenario, two carriers.
// ------------------------------------------------------------------

/// What either `-R` carrier's live binding must expose once opened —
/// implemented for [`RemoteForwardBinding`] (forward, already `pub`) and
/// [`ReverseRemoteBinding`] below. Delegates to each type's own inherent
/// `host_addr`/`close` — Rust's inherent-method-wins-over-trait-method
/// resolution means these calls are not recursive despite sharing a name.
trait Binding {
    fn host_addr(&self) -> SocketAddr;
    async fn close(self);
}

impl Binding for RemoteForwardBinding {
    fn host_addr(&self) -> SocketAddr {
        self.host_addr()
    }

    async fn close(self) {
        RemoteForwardBinding::close(self).await
    }
}

/// A live `-R` remote forward driven entirely at the raw wire level over a
/// reverse connection's `LOCAL_CONTROL`/`LOCAL_STREAM` conduits — the
/// reverse-route sibling of [`RemoteForwardBinding`], built the way
/// `local_stream_reverse.rs`'s own helpers are (raw `ControlMessage`s, no
/// `Ops`/CLI layer): a hand-driven `RemoteForwardOpen`/`RemoteForwardClose`
/// round trip for the control-plane half, and the real production
/// [`RemoteForwardAcceptor::spawn_reverse`] for the claim/splice half —
/// there is no reason to hand-roll the claim loop when the exact function
/// PR 5b's `Ops` layer will call already exists and is `pub`.
struct ReverseRemoteBinding {
    forward_id: String,
    actual_port: u16,
    ctl: LocalConduit<UnixStream>,
    acceptor: RemoteForwardAcceptor,
}

impl ReverseRemoteBinding {
    fn host_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.actual_port))
    }

    async fn close(mut self) {
        // Stop this side's own dispatch first — the same order
        // `RemoteForwardBinding::close` uses, so a `TCP_ACCEPTED` racing
        // the close can never land after this side stopped expecting one.
        self.acceptor.unregister(&self.forward_id);
        send_control(
            &mut self.ctl,
            2,
            control_message::Body::RfwdClose(wire::RemoteForwardClose {
                forward_id: self.forward_id.clone(),
            }),
        )
        .await;
        let reply = recv_control_response(&mut self.ctl).await;
        assert_eq!(reply.request_id, 2);
        // `RemoteForwardClose`'s bare success carries no payload
        // (`Session::rfwd_close`'s own doc: "a `None` response body is
        // the success case, not a protocol error").
        assert!(
            matches!(
                reply.body,
                Some(control_message::Body::Response(wire::Response {
                    body: None,
                    ..
                }))
            ),
            "RemoteForwardClose must succeed with an empty body, got {:?}",
            reply.body
        );
    }
}

impl Binding for ReverseRemoteBinding {
    fn host_addr(&self) -> SocketAddr {
        self.host_addr()
    }

    async fn close(self) {
        ReverseRemoteBinding::close(self).await
    }
}

/// What a `-R` scenario needs from either carrier: open a remote forward
/// pointed at `forward_host:forward_port` (the destination *this* side
/// dials on each accept) and hand back a live [`Binding`].
trait RemoteForwardCarrier {
    type Binding: Binding;

    async fn open_remote_forward(&self, forward_host: &str, forward_port: u16) -> Self::Binding;
}

struct ForwardRemoteRoute<'a>(&'a TunnelHarness);

impl RemoteForwardCarrier for ForwardRemoteRoute<'_> {
    type Binding = RemoteForwardBinding;

    async fn open_remote_forward(&self, forward_host: &str, forward_port: u16) -> Self::Binding {
        self.0.remote_forward(forward_host, forward_port).await
    }
}

struct ReverseRemoteRoute<'a> {
    socket_path: &'a Path,
    host: &'a str,
}

impl ReverseRemoteRoute<'_> {
    /// The raw `RemoteForwardOpen` round trip plus registering the real
    /// [`RemoteForwardAcceptor::spawn_reverse`] claim loop — shared by
    /// [`RemoteForwardCarrier::open_remote_forward`] and the
    /// two-conduits proof below, which needs the same setup twice with
    /// two independent `LOCAL_CONTROL` conduits (`PLAN.md` M4 Step 5 (a):
    /// "one conduit registers, the other tries to claim" driven for real,
    /// not just at the registry level).
    async fn open(&self, forward_host: &str, forward_port: u16) -> ReverseRemoteBinding {
        // Mint the acceptor — and with it, its one claim token
        // (`RemoteForwardAcceptor::spawn_reverse`) — *before* sending
        // `RemoteForwardOpen`, exactly as `RemoteForwardAcceptor::
        // claim_token`'s own doc requires: the request below must carry
        // this instance's token verbatim, because it is the only copy
        // that will ever reach the hub (`ControlHub`'s `claim_tokens`
        // seats whatever the request carried; there is no wire round
        // trip that echoes it back for this side to read it from later).
        let acceptor = RemoteForwardAcceptor::spawn_reverse(
            self.socket_path.to_path_buf(),
            self.host.to_string(),
        )
        .await;
        let claim_token = acceptor
            .claim_token()
            .expect("spawn_reverse's acceptor always carries a claim token")
            .to_vec();

        let mut ctl = connect_control(self.socket_path, self.host).await;
        send_control(
            &mut ctl,
            1,
            control_message::Body::RfwdOpen(wire::RemoteForwardOpen {
                bind_host: String::new(),
                bind_port: 0,
                forward_host: forward_host.to_string(),
                forward_port: u32::from(forward_port),
                claim_token,
            }),
        )
        .await;
        let reply = recv_control_response(&mut ctl).await;
        assert_eq!(reply.request_id, 1);
        let opened = match reply.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::RfwdOpened(opened)),
                ..
            })) => opened,
            other => panic!("expected RemoteForwardOpened, got {other:?}"),
        };

        acceptor.register(
            opened.forward_id.clone(),
            forward_host.to_string(),
            forward_port,
        );
        let actual_port =
            u16::try_from(opened.actual_port).expect("actual_port fits u16 on loopback");

        ReverseRemoteBinding {
            forward_id: opened.forward_id,
            actual_port,
            ctl,
            acceptor,
        }
    }
}

impl RemoteForwardCarrier for ReverseRemoteRoute<'_> {
    type Binding = ReverseRemoteBinding;

    async fn open_remote_forward(&self, forward_host: &str, forward_port: u16) -> Self::Binding {
        self.open(forward_host, forward_port).await
    }
}

/// **The role-axis-independence proof for `-R`** (`PLAN.md` M4 Step 5
/// (a)): open a remote forward pointed at `echo` through whichever
/// carrier the caller supplies, round-trip a payload through the address
/// it bound, and assert it comes back byte-for-byte. Same split as
/// [`scenario_local_forward_round_trips_through_a_target_echo`] — nothing
/// here names "forward" or "reverse".
async fn scenario_remote_forward_round_trips_through_a_controller_echo(
    carrier: impl RemoteForwardCarrier,
    echo: &EchoServer,
) {
    let binding = carrier.open_remote_forward("127.0.0.1", echo.port()).await;
    let payload = b"qsh -R round trip over the tunnel carrier under test".to_vec();
    let got = TunnelHarness::round_trip(binding.host_addr(), payload.clone())
        .await
        .expect("round trip through the remote forward");
    assert_eq!(got, payload, "the echoed payload must come back unchanged");
    binding.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn r_over_forward_reaches_the_controller_echo() {
    let harness = TunnelHarness::start().await;
    scenario_remote_forward_round_trips_through_a_controller_echo(
        ForwardRemoteRoute(&harness),
        &harness.echo,
    )
    .await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn r_over_reverse_reaches_the_controller_echo() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;
    let echo = EchoServer::start().await.expect("bind echo server");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        scenario_remote_forward_round_trips_through_a_controller_echo(
            ReverseRemoteRoute {
                socket_path: &localctl.socket_path,
                host: "widget",
            },
            &echo,
        )
        .await;

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

// ------------------------------------------------------------------
// (iii) a target-opened `TCP_ACCEPTED` reaches only its own conduit —
// the full wire-level edition of `qsh_core::reverse::listen`'s L2 proof.
// ------------------------------------------------------------------

/// Two independent `-R` bindings on the *same* target, two independent
/// controller-side destinations, driven with distinguishable payloads
/// concurrently. Each binding is its own `LOCAL_CONTROL` conduit and its
/// own [`RemoteForwardAcceptor`] — exactly two separate CLI processes
/// would be — sharing nothing but the one localctl daemon and the one
/// reverse QUIC connection underneath. If a `TCP_ACCEPTED` stream ever
/// crossed from one binding's `forward_id` to the other's claim loop, one
/// of the two round trips below would come back carrying the *other*
/// binding's payload (or the wrong destination's echo entirely) instead
/// of its own — a leak here is detectable, not merely improbable.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_opened_tcp_accepted_reaches_only_its_own_conduit() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;
    let echo_a = EchoServer::start().await.expect("bind echo a");
    let echo_b = EchoServer::start().await.expect("bind echo b");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        let route_a = ReverseRemoteRoute {
            socket_path: &localctl.socket_path,
            host: "widget",
        };
        let route_b = ReverseRemoteRoute {
            socket_path: &localctl.socket_path,
            host: "widget",
        };
        let binding_a = route_a.open("127.0.0.1", echo_a.port()).await;
        let binding_b = route_b.open("127.0.0.1", echo_b.port()).await;
        assert_ne!(
            binding_a.forward_id, binding_b.forward_id,
            "the target must mint a distinct forward_id per RemoteForwardOpen"
        );

        let addr_a = binding_a.host_addr();
        let addr_b = binding_b.host_addr();
        let payload_a = b"CONDUIT-A-OWNS-THIS-PAYLOAD-ONLY".to_vec();
        let payload_b = b"CONDUIT-B-OWNS-THIS-PAYLOAD-ONLY".to_vec();

        // Interleaved, not sequential — both target-bound ports are hit
        // concurrently so a bug that only shows up under a race has a
        // chance to fire.
        let (got_a, got_b) = tokio::join!(
            TunnelHarness::round_trip(addr_a, payload_a.clone()),
            TunnelHarness::round_trip(addr_b, payload_b.clone()),
        );
        assert_eq!(
            got_a.expect("round trip through binding a"),
            payload_a,
            "binding a's connection must reach echo_a with its own payload, never binding b's"
        );
        assert_eq!(
            got_b.expect("round trip through binding b"),
            payload_b,
            "binding b's connection must reach echo_b with its own payload, never binding a's"
        );

        binding_a.close().await;
        binding_b.close().await;
        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

// ------------------------------------------------------------------
// (iv) the claim leg always answers with exactly one frame —
// `docs/design/protocol.md` §11-3, "TCP_ACCEPTED claim leg의 요청/응답".
// ------------------------------------------------------------------
//
// The three tests below drive the `TCP_ACCEPTED` claim by hand, at the
// `qsh.local.v1` frame level, because that is the only place the
// invariant they check is observable: `RemoteForwardAcceptor` swallows
// the framed answer into its own retry loop, so a claim that succeeded
// silently and a claim that succeeded with an explicit `ClaimGranted`
// look the same from above. The invariant is that the daemon answers a
// `TCP_ACCEPTED` header with exactly one `LocalResponse` before any raw
// byte flows — success included, timeout included — so a claimer never
// has to tell payload from a frame by its content, or success from
// not-yet by silence.

/// Connect a fresh `LOCAL_STREAM` conduit for `host` and consume its
/// `LocalHelloAck`, leaving the conduit positioned exactly where the next
/// frame is the wire `StreamHeader` — the `LOCAL_STREAM` sibling of this
/// file's [`connect_control`] (same helper `local_stream_reverse.rs`
/// carries for the same reason: no shared support module exists across
/// test binaries).
async fn connect_stream(socket_path: &Path, host: &str, wait_ms: u32) -> LocalConduit<UnixStream> {
    let stream = UnixStream::connect(socket_path)
        .await
        .expect("connect localctl socket");
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalStream as i32,
            host: host.to_string(),
            wait_ms,
            known_generation: None,
        })
        .await
        .expect("send LocalHello");
    let ack: LocalResponse = conduit
        .recv()
        .await
        .expect("recv LocalHelloAck")
        .expect("conduit stayed open for the ack");
    match ack.body {
        Some(local_response::Body::HelloAck(_)) => {}
        other => panic!("expected LocalHelloAck, got {other:?}"),
    }
    conduit
}

/// `ticket = forward_id ++ 0x00 ++ claim_token` — the exact shape
/// `crate::tunnel::remote::claim_ticket` builds and
/// `LocalctlDaemon::serve_tcp_accepted` parses back apart
/// (`docs/design/protocol.md` §11-3's `TCP_ACCEPTED` claim leg
/// paragraph, adversarial-review finding A). `claim_token` is
/// deliberately a separate parameter rather than folded into
/// `forward_id`'s bytes: every call site below has to say explicitly
/// what token it is presenting, instead of a helper silently picking one
/// that happens to match (or not) whatever the test actually seated.
fn tcp_accepted_header(forward_id: &[u8], claim_token: &[u8]) -> wire::StreamHeader {
    let mut ticket = Vec::with_capacity(forward_id.len() + 1 + claim_token.len());
    ticket.extend_from_slice(forward_id);
    ticket.push(0);
    ticket.extend_from_slice(claim_token);
    wire::StreamHeader {
        kind: wire::StreamKind::TcpAccepted as i32,
        ticket,
        host: String::new(),
        port: 0,
    }
}

/// Run `body` against a live reverse registration named `widget`, with a
/// real localctl daemon attached — the setup every test in this section
/// shares, factored out so each test below is only its own claim.
async fn with_registered_widget<F, Fut>(body: F)
where
    F: FnOnce(std::path::PathBuf) -> Fut,
    Fut: Future<Output = ()>,
{
    with_registered_widget_and_quotas(
        qsh_core::config::ServeConfig::DEFAULT_MAX_REMOTE_FORWARDS_PER_PRINCIPAL,
        body,
    )
    .await;
}

/// [`with_registered_widget`] with a caller-chosen
/// `[serve].max_remote_forwards_per_principal` — for a test that
/// deliberately opens more than the default (16, M8 Step 3b) worth of
/// remote forwards from the single `"widget"` principal to exercise
/// something else entirely (the parked-claim pool), and needs the
/// per-principal quota out of its way to do so.
///
/// The quota that actually gates `RemoteForwardOpen` here lives on the
/// **target** side, not the controller's `Listen`:
/// `ReverseHarness::run_target*` builds the target's own
/// `crate::serve::host_runtime` (`crate::server::Server`) from this
/// `Config`, and it is that `Server::authorize_and_bind_remote_forward`
/// call — reached because the target "plays the host role for every op
/// the controller sends it" (this file's module docs) — that reserves
/// against `[serve].max_remote_forwards_per_principal`. Raising the
/// controller-side `Listen`'s own `Quotas` (`ReverseHarness::
/// start_with_quotas`) does not touch this path at all.
async fn with_registered_widget_and_quotas<F, Fut>(
    max_remote_forwards_per_principal: usize,
    body: F,
) where
    F: FnOnce(std::path::PathBuf) -> Fut,
    Fut: Future<Output = ()>,
{
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;

    let target_config = qsh_core::config::Config {
        serve: qsh_core::config::ServeConfig {
            max_remote_forwards_per_principal: Some(max_remote_forwards_per_principal),
            ..qsh_core::config::ServeConfig::default()
        },
        ..qsh_core::config::Config::default()
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target_with_config(
        &target,
        "device-id",
        "controller",
        None,
        &target_config,
        async {
            let _ = shutdown_rx.await;
        },
    );

    let socket_path = localctl.socket_path.clone();
    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
        body(socket_path).await;
        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

/// A claim for a `forward_id` nobody registered must come back as a
/// framed `LocalError{TIMEOUT}` once the wait budget elapses — never as
/// the daemon simply going quiet. Silence is the one answer a claimer
/// cannot interpret: it is indistinguishable from a granted claim onto a
/// connection that has not spoken yet.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_for_an_unregistered_forward_id_is_a_framed_timeout_not_silence() {
    with_registered_widget(|socket_path| async move {
        let mut claim = connect_stream(&socket_path, "widget", 300).await;
        claim
            .send(&tcp_accepted_header(
                b"fwd-00000000000000000000000000000001",
                // No registration exists for this `forward_id` at all, so
                // `claim_tcp_accepted` refuses on the ownership check
                // before it would ever compare token bytes — this value
                // is arbitrary and unchecked on this path.
                b"unused-token",
            ))
            .await
            .expect("send TCP_ACCEPTED header");

        let answer: LocalResponse = tokio::time::timeout(TIMEOUT, claim.recv())
            .await
            .expect("the claim leg must answer within its budget, never hang")
            .expect("the daemon must answer on this same framed conduit")
            .expect("the daemon must answer, not close the conduit");
        match answer.body {
            Some(local_response::Body::Error(err)) => assert_eq!(
                err.error_code(),
                qsh_proto::ErrorCode::Timeout,
                "wrong code for a claim that found nothing: {err:?}"
            ),
            other => panic!("expected a framed LocalError{{TIMEOUT}}, got {other:?}"),
        }
    })
    .await;
}

/// A ticket that is not a well-formed `forward_id` is refused as a framed
/// `INVALID_ARGUMENT` before any registry lookup happens — and, like every
/// other claim outcome, it is a *frame*, not a closed conduit.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_claim_ticket_is_a_framed_invalid_argument() {
    with_registered_widget(|socket_path| async move {
        let mut claim = connect_stream(&socket_path, "widget", 5_000).await;
        claim
            // The separator is present and well-formed — it is
            // specifically the `forward_id` half that is malformed, so
            // this exercises `valid_forward_id`'s shape check rather than
            // the separate "ticket has no NUL at all" rejection.
            .send(&tcp_accepted_header(
                b"not a forward id/../\xff",
                b"unused-token",
            ))
            .await
            .expect("send TCP_ACCEPTED header");

        let answer: LocalResponse = tokio::time::timeout(TIMEOUT, claim.recv())
            .await
            .expect("a shape rejection must be immediate, never wait out the budget")
            .expect("the daemon must answer on this same framed conduit")
            .expect("the daemon must answer, not close the conduit");
        match answer.body {
            Some(local_response::Body::Error(err)) => assert_eq!(
                err.error_code(),
                qsh_proto::ErrorCode::InvalidArgument,
                "wrong code for a malformed ticket: {err:?}"
            ),
            other => panic!("expected a framed LocalError{{INVALID_ARGUMENT}}, got {other:?}"),
        }
    })
    .await;
}

/// **The case silence-as-success could never serve.** A real target-side
/// accept whose TCP peer sends nothing at all: the claim is granted, but
/// there is no first byte to infer that from. The `LocalClaimGranted`
/// frame must arrive immediately — measured against a deliberately huge
/// `wait_ms` (30 s), so a design that resolved the claim by waiting out
/// its budget would blow the assertion rather than merely be slow.
///
/// No `RemoteForwardAcceptor` here on purpose: the acceptor's claim loop
/// would race this test for the same arrival. The `RemoteForwardOpen` is
/// driven raw, exactly as [`ReverseRemoteRoute::open`] does it, and this
/// test *is* the claimer.
#[tokio::test(flavor = "multi_thread")]
async fn a_granted_claim_is_acked_at_once_even_when_the_peer_sends_nothing() {
    with_registered_widget(|socket_path| async move {
        let mut ctl = connect_control(&socket_path, "widget").await;
        send_control(
            &mut ctl,
            1,
            control_message::Body::RfwdOpen(wire::RemoteForwardOpen {
                bind_host: String::new(),
                bind_port: 0,
                // Nothing ever dials this: the claimer under test never
                // reaches the splice's far side, it only checks that the
                // grant was announced.
                forward_host: "127.0.0.1".to_string(),
                forward_port: 9,
                // This test drives the claim by hand (no
                // `RemoteForwardAcceptor` — its own doc above explains
                // why), so it stands in as its own claimant and must
                // present this exact value back on the claim leg below.
                claim_token: b"hand-rolled-claim-token".to_vec(),
            }),
        )
        .await;
        let reply = recv_control_response(&mut ctl).await;
        let opened = match reply.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::RfwdOpened(opened)),
                ..
            })) => opened,
            other => panic!("expected RemoteForwardOpened, got {other:?}"),
        };
        let bound = SocketAddr::from((
            [127, 0, 0, 1],
            u16::try_from(opened.actual_port).expect("actual_port fits u16"),
        ));

        // A TCP peer that connects and then says nothing. The target
        // accepts it and opens `TCP_ACCEPTED` on the reverse connection;
        // not one payload byte follows it.
        let _mute = tokio::net::TcpStream::connect(bound)
            .await
            .expect("dial the target's bound remote-forward port");

        let mut claim = connect_stream(&socket_path, "widget", 30_000).await;
        claim
            .send(&tcp_accepted_header(
                opened.forward_id.as_bytes(),
                b"hand-rolled-claim-token",
            ))
            .await
            .expect("send TCP_ACCEPTED header");

        let started = std::time::Instant::now();
        let answer: LocalResponse = tokio::time::timeout(TIMEOUT, claim.recv())
            .await
            .expect("a granted claim must be announced, not inferred from silence")
            .expect("the daemon must answer on this same framed conduit")
            .expect("the daemon must answer, not close the conduit");
        assert!(
            matches!(answer.body, Some(local_response::Body::ClaimGranted(_))),
            "expected LocalClaimGranted, got {:?}",
            answer.body
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the grant must be announced at once, not after the 30s wait budget: {:?}",
            started.elapsed()
        );
    })
    .await;
}

// ------------------------------------------------------------------
// (v) Finding A — the parked-claim permit
// (`LocalctlDaemon::serve_tcp_accepted`'s `MAX_PARKED_CLAIMS_PER_HUB`-
// backed `_claim_permit`) must be scoped to the parked *wait*, not to
// the live splice a granted claim goes on to run. Held past the grant,
// it silently caps concurrent *live* reverse tunnels at the much smaller
// parked-claim bound instead of the tunnel-stream bound that actually
// governs live splices (`MAX_TUNNEL_STREAMS_PER_HUB`).
//
// The pool is also *divided*, not merely capped: `MAX_PARKED_CLAIMS_PER_HUB`
// (32 as of this writing) is the hub-wide ceiling and
// `MAX_PARKED_CLAIMS_PER_CONDUIT` (8, a quarter of it) is what any one
// owning conduit — one CLI process — may hold parked at once, because the
// steady state of a healthy `-R` is to *sit* holding a permit and a
// ceiling alone therefore lets one CLI's ordinary operation starve every
// other CLI on the host. Both live in `qsh_core::reverse::listen` as
// private `const`s, unreachable from this crate — the tests below pin
// their values as literals instead. If either constant changes, these
// literals need to move with it (same tradeoff
// `qsh_core::reverse::listen`'s own mutation-checked unit tests for the
// same constants accept, one crate over).
// ------------------------------------------------------------------

/// `CAP` claims are each granted *immediately* — every arrival is queued
/// (the raw TCP peer already connected) before its claim is even sent, so
/// none of them ever parks — and then held open as a genuinely live
/// splice for the rest of the test. A `CAP + 1`-th claim, granted the
/// same immediate way, must still succeed: nothing about it is parked
/// either, so it must never compete with the `CAP` live splices for the
/// parked-claim permit pool at all.
///
/// Under the bug this test catches — the permit bound to the whole
/// splice instead of just the parked wait — the `CAP`-th live splice
/// alone would exhaust the pool, and this `CAP + 1`-th claim would come
/// back `RESOURCE_EXHAUSTED` despite nothing being parked anywhere.
#[tokio::test(flavor = "multi_thread")]
async fn n_live_splices_beyond_the_parked_claim_cap_coexist() {
    const CAP: usize = 32;
    const LIVE_SPLICE_COUNT: usize = CAP + 1;

    // `[serve].max_remote_forwards_per_principal` defaults to 16 (M8 Step
    // 3b); this test opens `LIVE_SPLICE_COUNT` (33) from the single
    // `"widget"` principal to exercise the parked-claim cap, so it raises
    // the per-principal quota well above that count.
    with_registered_widget_and_quotas(64, |socket_path| async move {
        let mut ctl = connect_control(&socket_path, "widget").await;
        // Held for the rest of the test so every splice opened below
        // stays genuinely live (neither the TCP peer nor the claim
        // conduit is ever closed) — the whole point is that a bug would
        // show up only while `CAP` of these are simultaneously alive.
        let mut held = Vec::with_capacity(LIVE_SPLICE_COUNT);

        for i in 0..LIVE_SPLICE_COUNT {
            let claim_token = format!("live-token-{i}").into_bytes();
            send_control(
                &mut ctl,
                (i + 1) as u64,
                control_message::Body::RfwdOpen(wire::RemoteForwardOpen {
                    bind_host: String::new(),
                    bind_port: 0,
                    // Never dialed — this test claims by hand and never
                    // completes a real splice's far side, same as
                    // `a_granted_claim_is_acked_at_once_even_when_the_peer_sends_nothing`.
                    forward_host: "127.0.0.1".to_string(),
                    forward_port: 9,
                    claim_token: claim_token.clone(),
                }),
            )
            .await;
            let reply = recv_control_response(&mut ctl).await;
            let opened = match reply.body {
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::RfwdOpened(opened)),
                    ..
                })) => opened,
                other => panic!("expected RemoteForwardOpened for claim {i}, got {other:?}"),
            };
            let bound = SocketAddr::from((
                [127, 0, 0, 1],
                u16::try_from(opened.actual_port).expect("actual_port fits u16"),
            ));

            // Connecting here — before the claim below is even sent — is
            // what makes the daemon's `claim_tcp_accepted` resolve at
            // once instead of parking: the arrival is already queued.
            let peer = tokio::net::TcpStream::connect(bound)
                .await
                .unwrap_or_else(|e| panic!("dial claim {i}'s bound remote-forward port: {e}"));

            let mut claim = connect_stream(&socket_path, "widget", 5_000).await;
            claim
                .send(&tcp_accepted_header(
                    opened.forward_id.as_bytes(),
                    &claim_token,
                ))
                .await
                .unwrap_or_else(|e| panic!("send TCP_ACCEPTED header for claim {i}: {e}"));

            let started = std::time::Instant::now();
            let answer: LocalResponse = tokio::time::timeout(TIMEOUT, claim.recv())
                .await
                .unwrap_or_else(|_| panic!("claim {i} of {LIVE_SPLICE_COUNT} must not hang"))
                .expect("the daemon must answer on this same framed conduit")
                .expect("the daemon must answer, not close the conduit");
            assert!(
                matches!(answer.body, Some(local_response::Body::ClaimGranted(_))),
                "claim {i} of {LIVE_SPLICE_COUNT} (one more than the parked-claim cap of \
                 {CAP}) must be granted — a live splice must not pin the parked-claim permit \
                 for its whole life, only for the parked wait that already ended: got {:?}",
                answer.body
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "claim {i} was already queued and should never have waited at all: {:?}",
                started.elapsed()
            );

            // Keep both halves alive: dropping either would end this
            // splice and free whatever permit it does or does not still
            // hold, defeating the point of the test.
            held.push((peer, claim));
        }

        assert_eq!(held.len(), LIVE_SPLICE_COUNT);
    })
    .await;
}

/// The parked-claim pool's other half, and the fairness finding that
/// divided it: claims that are genuinely parked (no arrival ever queued
/// for any of them) must exhaust their owner's *share* — and then the
/// hub's ceiling — while a **different** CLI, which has done nothing
/// wrong, keeps claiming normally throughout.
///
/// Proven end to end through the real localctl daemon rather than the
/// bare `ControlHub`, so the whole chain the finding names is exercised:
/// `RemoteForwardOpen` on one CLI's `LOCAL_CONTROL` conduit, a
/// `LOCAL_STREAM` `TCP_ACCEPTED` claim per forward, the daemon's permit
/// acquisition before it ever parks, and the framed refusal. Three
/// separate claims are made about the pool here:
///
/// 1. one conduit is held to `SHARE` parked claims even though the hub
///    still has three quarters of its pool free — the `SHARE + 1`-th is
///    refused `RESOURCE_EXHAUSTED` *immediately*, not after waiting out
///    its own 60 s budget;
/// 2. a second CLI, arriving while the first sits at its share, parks and
///    is **granted** a real arrival — the starvation the share exists to
///    prevent, checked positively rather than by absence of an error;
/// 3. the ceiling still holds: once `CONDUITS` conduits each hold their
///    full share, the pool is spent and a fresh conduit holding none of
///    its own share is refused too.
#[tokio::test(flavor = "multi_thread")]
async fn the_parked_claim_share_bounds_one_conduit_without_starving_another() {
    const SHARE: usize = 8;
    const HUB_CAP: usize = 32;
    const CONDUITS: usize = HUB_CAP / SHARE;

    // `[serve].max_remote_forwards_per_principal` defaults to 16 (M8 Step
    // 3b); this test opens `HUB_CAP` (32) plus a handful more remote
    // forwards from the single `"widget"` principal to exercise the
    // parked-claim share/ceiling, so it raises the per-principal quota
    // well above that count.
    with_registered_widget_and_quotas(64, |socket_path| async move {
        // Every parked claim's reader task, kept alive for the whole test
        // so each one's permit stays genuinely held.
        let mut parked = Vec::with_capacity(HUB_CAP);
        // Every `LOCAL_CONTROL` conduit, likewise: dropping one would
        // unregister its forwards and release its share.
        let mut ctls = Vec::with_capacity(CONDUITS);

        for c in 0..CONDUITS {
            let mut ctl = connect_control(&socket_path, "widget").await;
            for i in 0..SHARE {
                let claim_token = format!("parked-token-{c}-{i}").into_bytes();
                let opened = open_remote_forward(&mut ctl, (i + 1) as u64, &claim_token).await;

                // No TCP peer ever connects to this forward's bound port,
                // so this claim has nothing to be granted: it genuinely
                // parks in `ControlHub::claim_tcp_accepted` for the rest
                // of its (deliberately generous) budget, holding its
                // permit the whole time.
                let mut claim = connect_stream(&socket_path, "widget", 60_000).await;
                claim
                    .send(&tcp_accepted_header(
                        opened.forward_id.as_bytes(),
                        &claim_token,
                    ))
                    .await
                    .unwrap_or_else(|e| panic!("send header for parked claim {c}/{i}: {e}"));
                parked.push(tokio::spawn(async move {
                    let _ = claim.recv::<LocalResponse>().await;
                }));

                // Give the daemon's own read/acquire a real chance to run
                // before the next iteration's connect — these are two
                // separate OS-scheduled tasks with no other
                // synchronization between "this claim's header is on the
                // wire" and "the daemon has read it and acquired its
                // permit".
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            if c == 0 {
                // (1) This conduit is at its own share while 24 of the
                // hub's 32 permits are still free — its next claim must
                // be refused anyway, and refused *now*.
                let claim_token = b"parked-token-over-share".to_vec();
                let opened = open_remote_forward(&mut ctl, (SHARE + 1) as u64, &claim_token).await;
                let (answer, elapsed) =
                    claim_once(&socket_path, &opened.forward_id, &claim_token).await;
                assert_resource_exhausted(
                    answer,
                    elapsed,
                    "one conduit must be held to its own share even with the hub pool mostly free",
                );

                // (2) A *different* CLI, arriving while the first sits at
                // its share, must be able to park and actually be
                // granted — the starvation this share exists to prevent.
                let mut other = connect_control(&socket_path, "widget").await;
                let other_token = b"other-cli-token".to_vec();
                let other_opened = open_remote_forward(&mut other, 1, &other_token).await;
                let mut other_claim = connect_stream(&socket_path, "widget", 60_000).await;
                other_claim
                    .send(&tcp_accepted_header(
                        other_opened.forward_id.as_bytes(),
                        &other_token,
                    ))
                    .await
                    .expect("send header for the second CLI's claim");
                // Parked now (nothing has arrived yet); dialing the
                // target's bound port is what queues the arrival that
                // wakes it.
                tokio::time::sleep(Duration::from_millis(20)).await;
                let bound = SocketAddr::from((
                    [127, 0, 0, 1],
                    u16::try_from(other_opened.actual_port).expect("actual_port fits u16"),
                ));
                let peer = tokio::net::TcpStream::connect(bound)
                    .await
                    .expect("dial the second CLI's bound remote-forward port");
                let answer: LocalResponse = tokio::time::timeout(TIMEOUT, other_claim.recv())
                    .await
                    .expect("the second CLI's claim must not hang")
                    .expect("the daemon must answer on this same framed conduit")
                    .expect("the daemon must answer, not close the conduit");
                assert!(
                    matches!(answer.body, Some(local_response::Body::ClaimGranted(_))),
                    "a second CLI must claim normally while the first sits at its full share — \
                     one CLI's ordinary steady state must never deny `-R` to another: got {:?}",
                    answer.body
                );
                drop(peer);
                drop(other_claim);
                ctls.push(other);
            }

            ctls.push(ctl);
        }

        assert_eq!(parked.len(), HUB_CAP);

        // (3) The ceiling still holds: every permit is now genuinely held
        // by a claim that is still waiting, spread across `CONDUITS`
        // owners, so a fresh conduit holding none of its own share is
        // refused too — the share divided the pool, it did not inflate
        // it.
        let mut late = connect_control(&socket_path, "widget").await;
        let claim_token = b"parked-token-over-ceiling".to_vec();
        let opened = open_remote_forward(&mut late, 1, &claim_token).await;
        let (answer, elapsed) = claim_once(&socket_path, &opened.forward_id, &claim_token).await;
        assert_resource_exhausted(
            answer,
            elapsed,
            "the hub-wide ceiling must still bind once every conduit's share is spent",
        );
        drop(late);
        drop(ctls);
    })
    .await;
}

/// `RemoteForwardOpen` on `ctl`, returning the `RemoteForwardOpened` the
/// target answered with — the three-line preamble every parked-claim case
/// above repeats.
async fn open_remote_forward(
    ctl: &mut LocalConduit<UnixStream>,
    request_id: u64,
    claim_token: &[u8],
) -> wire::RemoteForwardOpened {
    send_control(
        ctl,
        request_id,
        control_message::Body::RfwdOpen(wire::RemoteForwardOpen {
            bind_host: String::new(),
            bind_port: 0,
            forward_host: "127.0.0.1".to_string(),
            forward_port: 9,
            claim_token: claim_token.to_vec(),
        }),
    )
    .await;
    match recv_control_response(ctl).await.body {
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::RfwdOpened(opened)),
            ..
        })) => opened,
        other => panic!("expected RemoteForwardOpened, got {other:?}"),
    }
}

/// One `TCP_ACCEPTED` claim on its own `LOCAL_STREAM` conduit, returning
/// the daemon's single framed answer and how long it took — the shape
/// both refusal assertions above need (the *promptness* is half the
/// claim: a refusal that arrives only after the 60 s budget would mean
/// the claim parked after all).
async fn claim_once(
    socket_path: &Path,
    forward_id: &str,
    claim_token: &[u8],
) -> (LocalResponse, Duration) {
    let mut claim = connect_stream(socket_path, "widget", 60_000).await;
    claim
        .send(&tcp_accepted_header(forward_id.as_bytes(), claim_token))
        .await
        .expect("send TCP_ACCEPTED header");
    let started = std::time::Instant::now();
    let answer: LocalResponse = tokio::time::timeout(TIMEOUT, claim.recv())
        .await
        .expect("a refused claim must be answered promptly, never hang")
        .expect("the daemon must answer on this same framed conduit")
        .expect("the daemon must answer, not close the conduit");
    (answer, started.elapsed())
}

fn assert_resource_exhausted(answer: LocalResponse, elapsed: Duration, what: &str) {
    match answer.body {
        Some(local_response::Body::Error(err)) => assert_eq!(
            err.error_code(),
            qsh_proto::ErrorCode::ResourceExhausted,
            "{what}: wrong code, got {err:?}"
        ),
        other => {
            panic!("{what}: expected a framed LocalError{{RESOURCE_EXHAUSTED}}, got {other:?}")
        }
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "{what}: the refusal must come from the permit check, not from waiting out the 60s \
         budget: {elapsed:?}"
    );
}

// ------------------------------------------------------------------
// localctl `NotOwner` — a same-uid trust boundary, deliberately not
// `crate::acl::PERMISSION_DENIED_MESSAGE` (`PLAN.md` M5 Step 4 §4.2,
// `docs/design/protocol.md` §11-3's "close도 소유 conduit만 할 수 있다").
// ------------------------------------------------------------------

/// A second `LOCAL_CONTROL` conduit that does not own `forward_id` gets
/// `PERMISSION_DENIED` with the wording this path has always used, pinned
/// here so a future edit to `crate::acl::PERMISSION_DENIED_MESSAGE` can
/// never silently start being reused for this same-uid local-trust
/// refusal — the two are deliberately separate axes
/// (`crate::acl::PERMISSION_DENIED_MESSAGE`'s own doc). The owner's own
/// close still succeeds afterward: this is a non-owner guard, not a
/// blanket refusal on the id.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_owning_conduits_close_is_refused_with_the_pinned_notowner_message() {
    with_registered_widget(|socket_path| async move {
        let mut owner = connect_control(&socket_path, "widget").await;
        let opened = open_remote_forward(&mut owner, 1, b"owner-token").await;

        let mut stranger = connect_control(&socket_path, "widget").await;
        send_control(
            &mut stranger,
            1,
            control_message::Body::RfwdClose(wire::RemoteForwardClose {
                forward_id: opened.forward_id.clone(),
            }),
        )
        .await;
        let reply = recv_control_response(&mut stranger).await;
        match reply.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(err)),
                ..
            })) => {
                assert_eq!(err.error_code(), qsh_proto::ErrorCode::PermissionDenied);
                assert_eq!(
                    err.message, "this forward is owned by another client on this host",
                    "the localctl NotOwner wording must stay pinned independently of \
                     crate::acl::PERMISSION_DENIED_MESSAGE"
                );
            }
            other => panic!("expected a PERMISSION_DENIED error, got {other:?}"),
        }
        drop(stranger);

        // The owner's own close still works.
        send_control(
            &mut owner,
            2,
            control_message::Body::RfwdClose(wire::RemoteForwardClose {
                forward_id: opened.forward_id,
            }),
        )
        .await;
        let reply = recv_control_response(&mut owner).await;
        assert!(
            matches!(
                reply.body,
                Some(control_message::Body::Response(wire::Response {
                    body: None,
                    ..
                }))
            ),
            "the owner's own close must still succeed, got {reply:?}"
        );
    })
    .await;
}

// ------------------------------------------------------------------
// (vi) Finding C — a detached [`spawn_claim_attempt`] must not be
// silently lost if it is granted an arrival *after* its owning claim
// loop (`claim_remote_forward_reverse`) was already torn down by
// [`RemoteForwardAcceptor::unregister`]. This is deterministic, not a
// timing race: `unregister` fires here before any TCP peer ever connects
// to the target's bound port, so the loop's one outstanding attempt is
// unambiguously still parked — with nothing to grant it — at the exact
// moment its loop is aborted out from under it. Only afterward does a
// peer connect, so whatever gets granted can only be that same orphaned,
// still-running detached attempt.
// ------------------------------------------------------------------

/// `unregister` only stops *this* CLI's own dispatch — it never sends
/// `RemoteForwardClose`, so the target's bound listener and the hub's
/// registration for `forward_id` are both untouched by it. That is what
/// makes the arrival after teardown possible here: a real `-R over
/// reverse` registration, opened and dispatched through the production
/// [`RemoteForwardAcceptor::spawn_reverse`]/`register` path exactly as
/// `Ops::tunnel_open` would drive it (no hand-rolled claim in this test),
/// unregistered while its claim loop's first attempt is still parked, and
/// only then completed by a real TCP connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_granted_after_its_loop_is_torn_down_still_completes_the_splice() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;
    let echo = EchoServer::start().await.expect("bind echo");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        let acceptor = RemoteForwardAcceptor::spawn_reverse(
            localctl.socket_path.clone(),
            "widget".to_string(),
        )
        .await;
        let claim_token = acceptor
            .claim_token()
            .expect("a reverse acceptor always mints its own claim token")
            .to_vec();

        let mut ctl = connect_control(&localctl.socket_path, "widget").await;
        send_control(
            &mut ctl,
            1,
            control_message::Body::RfwdOpen(wire::RemoteForwardOpen {
                bind_host: String::new(),
                bind_port: 0,
                forward_host: "127.0.0.1".to_string(),
                forward_port: u32::from(echo.port()),
                claim_token: claim_token.clone(),
            }),
        )
        .await;
        let reply = recv_control_response(&mut ctl).await;
        let opened = match reply.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::RfwdOpened(opened)),
                ..
            })) => opened,
            other => panic!("expected RemoteForwardOpened, got {other:?}"),
        };
        let bound = SocketAddr::from((
            [127, 0, 0, 1],
            u16::try_from(opened.actual_port).expect("actual_port fits u16"),
        ));

        // Starts the real `claim_remote_forward_reverse` loop, production
        // code path — its first attempt parks at once, since nothing has
        // connected to `bound` yet.
        acceptor.register(
            opened.forward_id.clone(),
            "127.0.0.1".to_string(),
            echo.port(),
        );

        // Well inside `REVERSE_CLAIM_WAIT_MS` (60s) — this only needs to
        // outlast the loop's first attempt actually reaching the daemon
        // and beginning to park, which a loopback UDS round trip does in
        // well under a millisecond in practice.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Tear the loop down. Its one outstanding `spawn_claim_attempt`
        // keeps running on the runtime regardless (`spawn_claim_attempt`'s
        // own doc) — under the bug this test catches, whatever it is
        // later granted would just be dropped in silence the moment that
        // detached task completes with nothing left to hand it to.
        acceptor.unregister(&opened.forward_id);

        // Only now does a TCP peer connect. The target accepts it and
        // opens `TCP_ACCEPTED` on the reverse connection; the hub grants
        // it to whatever is parked for this `forward_id` — which, after
        // the `unregister` above, can only be the orphaned detached
        // attempt.
        let payload = b"POST-TEARDOWN-CLAIM".to_vec();
        let got = TunnelHarness::round_trip(bound, payload.clone())
            .await
            .expect(
                "a claim granted after its loop was torn down must still complete the splice \
                 (`DrainClaimAttemptOnDrop`'s reaper calling `handle_reverse_claim`), not hang \
                 or reset",
            );
        assert_eq!(
            got, payload,
            "the post-teardown arrival must actually reach the registered destination and echo \
             back, proving the splice really ran rather than the connection merely not having \
             been reset yet"
        );

        drop(acceptor);
        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

// ------------------------------------------------------------------
// (vii) Finding 4 — `serve_stream` computed `deadline = clamp_wait
// (wait_ms)` once and then spent it *twice*: first on
// `connection_for_wait`, then again in full as `serve_tcp_accepted`'s
// `claim_tcp_accepted` budget, regardless of how much of the one shared
// budget `connection_for_wait` had already used. A claim that starts
// before its target's hub has (re)published — the ordinary case right
// after a reconnect — could then park for up to *two* full `wait_ms`
// windows, while the CLI's own `wait_ms + PROBE_TIMEOUT` timeout
// (`localctl::client::open_stream_over_with_wait`) only ever bounds one:
// an orphaned daemon-side claim outliving the CLI's own timeout, free to
// race a later retry for whatever arrival shows up next.
// ------------------------------------------------------------------

/// The registry is deliberately made to know "widget" — so
/// `connection_for_wait`'s "never registered" early exit
/// (`Listen::control_hub_wait`'s own doc) does not fire — well before any
/// `ControlHub` is published for it, reproducing the real trigger for
/// this bug: a target that registered once, dropped its connection, and
/// has not yet reconnected, while a `-R` claim loop is already parked
/// waiting on it (`docs/design/protocol.md` §11-4's reconnect gap, not a
/// first-ever connection — every other test in this file has the target
/// already fully registered before any conduit connects, which is
/// exactly the case that never triggers this bug).
///
/// Under the bug, the claim's total daemon-side wait is
/// `REGISTRATION_DELAY + WAIT_MS` (`connection_for_wait` spends
/// `REGISTRATION_DELAY`, then `claim_tcp_accepted` gets handed a second,
/// full, fresh `WAIT_MS`). Fixed, it is bounded by `WAIT_MS` alone,
/// counted from the moment the conduit first connects — the same one
/// budget the CLI's own timeout wrapper is bounded by, so nothing can
/// still be parked once the CLI has given up and moved on.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_started_before_registration_gets_only_its_declared_wait_ms_not_a_second_one() {
    const REGISTRATION_DELAY: Duration = Duration::from_millis(400);
    const WAIT_MS: u32 = 700;

    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;

    // `Registry::admit` directly, the same lower-level primitive
    // `reverse::listen`'s own unit tests use for this (it "performs no
    // authorization and assumes none is needed by the time it's called" —
    // its own doc), under the target's *real* fingerprint: `run_target`'s
    // real registration below re-admits the same name, and the conflict
    // rule only takes the ordinary-reconnect branch (generation advances,
    // no error) when the fingerprint matches what is already there.
    harness
        .listen
        .registry()
        .admit(
            "widget".to_string(),
            qsh_core::reverse::registry::AdmittedEntry {
                fingerprint: &target.fingerprint.to_string(),
                principal: "device:pre-admit",
                address: "127.0.0.1:1".parse().unwrap(),
                capabilities: vec![],
            },
        )
        .expect("pre-admit widget under its real fingerprint, no hub published yet");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    // The target does not dial in — and so publishes no `ControlHub` for
    // "widget" — until well after the claim conduit below has already
    // connected and is sitting inside `connection_for_wait`.
    let run_fut = async {
        tokio::time::sleep(REGISTRATION_DELAY).await;
        harness
            .run_target(&target, "device-id", "controller", None, async {
                let _ = shutdown_rx.await;
            })
            .await
    };

    let socket_path = localctl.socket_path.clone();
    let claim_fut = async {
        let started = std::time::Instant::now();
        // Connects and sends `LocalHello` at once — `serve_stream`'s own
        // wait-budget clock starts right here, before the daemon has any
        // idea whether "widget" is even registered yet. This is the call
        // that blocks inside `connection_for_wait` for roughly
        // `REGISTRATION_DELAY`.
        let mut claim = connect_stream(&socket_path, "widget", WAIT_MS).await;

        // The hub is live now (the ack above could not have arrived
        // otherwise) — register a forward over a fresh control conduit,
        // held open for the rest of this closure so the registration
        // cannot be swept out from under the claim below.
        let claim_token = b"finding-4-claim-token".to_vec();
        let mut ctl = connect_control(&socket_path, "widget").await;
        let opened = open_remote_forward(&mut ctl, 1, &claim_token).await;

        claim
            .send(&tcp_accepted_header(
                opened.forward_id.as_bytes(),
                &claim_token,
            ))
            .await
            .expect("send TCP_ACCEPTED header");

        // Nothing ever arrives for this forward_id — the claim must wait
        // out its (now shared, already-partly-spent) budget and answer
        // `Timeout`, never hang past it.
        let answer: LocalResponse = tokio::time::timeout(Duration::from_secs(5), claim.recv())
            .await
            .expect("the claim must answer within its own declared budget, not hang past it")
            .expect("the daemon must answer on this same framed conduit")
            .expect("the daemon must answer, not close the conduit");
        let elapsed = started.elapsed();

        match answer.body {
            Some(local_response::Body::Error(err)) => assert_eq!(
                err.error_code(),
                qsh_proto::ErrorCode::Timeout,
                "wrong code for a claim that found nothing: {err:?}"
            ),
            other => panic!("expected a framed LocalError{{TIMEOUT}}, got {other:?}"),
        }

        // Fixed: total daemon-side time is bounded by `WAIT_MS` alone
        // (plus real-world slack for the reconnect and the registration
        // round trip), not by `REGISTRATION_DELAY + WAIT_MS` ≈ 1100 ms —
        // the sum the bug produced by handing `claim_tcp_accepted` a
        // second full `WAIT_MS` after `connection_for_wait` had already
        // spent `REGISTRATION_DELAY` of the one budget the CLI itself is
        // bounded by.
        assert!(
            elapsed < Duration::from_millis(950),
            "the parked claim must not get a second full wait_ms after connection_for_wait \
             already spent part of the shared {WAIT_MS}ms budget — this total ({elapsed:?}) is \
             only explained by the bug's REGISTRATION_DELAY + WAIT_MS double-spend"
        );
        // Sanity: `connection_for_wait` must have genuinely waited here,
        // not resolved instantly — otherwise the assertion above would be
        // vacuous (true regardless of the fix).
        assert!(
            elapsed >= Duration::from_millis(300),
            "the claim conduit must have actually waited on connection_for_wait, not resolved \
             the hub instantly: {elapsed:?}"
        );

        drop(ctl);
        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, claim_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

// ------------------------------------------------------------------
// (v) `Ops::tunnel_list`/`Ops::tunnel_close` (`PLAN.md` M4 Step 5 PR 5b) —
// qsh-level, against a real daemon-held `-R over reverse` forward.
// ------------------------------------------------------------------

/// Pick a free TCP port on loopback by binding `:0` and reading it back —
/// same technique `crates/qsh-cli/tests/fixtures.rs`'s own `free_port`
/// uses. `Ops::tunnel_open`'s `TunnelOpenReq::listen_port` must be
/// `1..=65535` (`crate::ops::tunnel`'s own `port` helper) — unlike the raw
/// wire `RemoteForwardOpen.bind_port`, which this file's other `-R`
/// helpers ([`ReverseRemoteRoute::open`]) can and do send as `0` to ask
/// the target for a kernel-assigned port, the `Ops`/CLI-facing grammar has
/// no such request-a-free-port spelling (`docs/CLI.md` §6.9's `-R` grammar
/// takes a concrete `rport`), so this test picks one itself instead.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

/// [`Ops::tunnel_list`] off the calling thread — same
/// `spawn_blocking` bridge `host_list_reverse.rs` uses for
/// [`Ops::host_list`], and for the identical reason (`Ops::tunnel_list`
/// builds and blocks on its own current-thread runtime internally,
/// `crate::ops::tunnel::Ops::reverse_tunnel_entries`'s own doc).
async fn tunnel_list(ops: &qsh_core::Ops) -> Result<qsh_proto::TunnelListData, qsh_core::OpError> {
    let ops = ops.clone();
    tokio::task::spawn_blocking(move || ops.tunnel_list(qsh_proto::TunnelListReq {}))
        .await
        .expect("spawn_blocking join")
}

/// [`Ops::tunnel_close`] off the calling thread — same bridge, same
/// reason.
async fn tunnel_close(
    ops: &qsh_core::Ops,
    tunnel_id: &str,
) -> Result<qsh_proto::TunnelCloseData, qsh_core::OpError> {
    let ops = ops.clone();
    let tunnel_id = tunnel_id.to_string();
    tokio::task::spawn_blocking(move || ops.tunnel_close(qsh_proto::TunnelCloseReq { tunnel_id }))
        .await
        .expect("spawn_blocking join")
}

/// The full owed PR 5b L3 scenario (`PLAN.md` M4 Step 5 PR 5b (c)):
/// `Ops::tunnel_open --remote` over the reverse route registers a forward
/// with the target's resident-daemon-adjacent hub; a *second*, independent
/// `Ops::tunnel_list` call (not the one that opened it — the same
/// process-independence `Ops::tunnel_close`'s own doc argues from) reports
/// it with the address it *actually* bound, which is live and reachable;
/// `Ops::tunnel_close` tears it down — the listing empties, a repeat close
/// is the ordinary idempotent `closed: false`, and the bound address stops
/// accepting connections once the target has processed the relayed
/// `RemoteForwardClose`.
///
/// The tunnel is held open (not `hold()`ed — nothing here waits for the
/// tunnel to end) on a dedicated blocking-pool thread for the scenario's
/// duration, released only once every assertion below is done — exactly
/// [`TunnelHold`](qsh_core::TunnelHold)'s own contract: the resource lives
/// only as long as something keeps the value alive.
#[tokio::test(flavor = "multi_thread")]
async fn tunnel_list_and_close_manage_a_daemon_held_remote_forward() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = qsh_core::Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    // `Ops::tunnel_open`'s route resolution loads `trust.toml` regardless
    // of whether the reverse source ends up winning (`resolve_route`'s own
    // "reverse wins over a forward pin" — it still reads the store to
    // check) — an empty-but-present store, same as `host_list_reverse.rs`'s
    // own `ops_with_forward_pin` always writes one.
    qsh_core::TrustStore::default()
        .save(&paths.trust_file())
        .expect("save empty trust.toml");
    let ops = qsh_core::Ops::new(paths);
    let localctl = harness.attach_localctl(ops.paths()).await;
    let echo = EchoServer::start().await.expect("bind echo server");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        // Hold the tunnel open on a blocking-pool thread — `Ops::tunnel_open`
        // is sync and spins its own runtime internally, exactly like
        // `Ops::host_list` (`tunnel_list`/`tunnel_close`'s own helpers,
        // above).
        let ops_hold = ops.clone();
        let echo_port = echo.port();
        let (tunnel_tx, tunnel_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let hold_task = tokio::task::spawn_blocking(move || {
            let hold = ops_hold
                .tunnel_open(qsh_proto::TunnelOpenReq {
                    host: "widget".to_string(),
                    mode: "remote".to_string(),
                    bind: None,
                    listen_port: u32::from(free_port()),
                    forward_host: "127.0.0.1".to_string(),
                    forward_port: u32::from(echo_port),
                })
                .expect("tunnel_open --remote over reverse");
            let _ = tunnel_tx.send(hold.tunnel().clone());
            // Block here — not `hold.hold()` — until the scenario below is
            // done with the resource: this thread's only job is to keep
            // `TunnelHold` alive (and therefore the forward registered)
            // for exactly as long as the test needs it.
            let _ = release_rx.recv();
            hold.close();
        });
        let opened = tunnel_rx.await.expect("tunnel_open reported its Tunnel");
        assert_eq!(opened.mode, "remote");
        assert_eq!(opened.host, "widget");
        assert_eq!(
            opened.forward_to,
            qsh_proto::wire::format_host_port("127.0.0.1", echo_port)
        );

        // `tunnel_list` reports the same forward, from a *second*,
        // independent `Ops::tunnel_list` call — never the one that opened
        // it — with the address that actually got bound.
        let listed = tunnel_list(&ops).await.expect("tunnel.list");
        assert_eq!(listed.tunnels.len(), 1, "{:?}", listed.tunnels);
        let entry = &listed.tunnels[0];
        assert_eq!(entry.tunnel_id, opened.tunnel_id);
        assert_eq!(entry.mode, "remote");
        assert_eq!(entry.bind, opened.bind);
        assert_eq!(entry.forward_to, opened.forward_to);
        assert_eq!(entry.host, "widget");

        // The address `tunnel_list` reported is real and live: dial it
        // and round-trip a payload through the target's echo server.
        let bind_addr: SocketAddr = entry.bind.parse().expect("bind is a real socket address");
        let payload = b"tunnel.list reports a real, live bound address".to_vec();
        let got = TunnelHarness::round_trip(bind_addr, payload.clone())
            .await
            .expect("round trip through the listed bind address");
        assert_eq!(got, payload);

        // `tunnel_close` tears it down: `closed: true` the first time, the
        // registry empties, and a second close on the same id is the
        // ordinary idempotent `closed: false` — never an error.
        let closed = tunnel_close(&ops, &opened.tunnel_id)
            .await
            .expect("tunnel.close");
        assert!(closed.closed, "{closed:?}");
        assert_eq!(closed.tunnel_id, opened.tunnel_id);

        let after = tunnel_list(&ops).await.expect("tunnel.list after close");
        assert!(after.tunnels.is_empty(), "{:?}", after.tunnels);

        let closed_again = tunnel_close(&ops, &opened.tunnel_id)
            .await
            .expect("tunnel.close again");
        assert!(
            !closed_again.closed,
            "closing twice must be idempotent, not an error"
        );

        // The target processes the relayed `RemoteForwardClose`
        // asynchronously (`ControlHub::admin_close_forward`'s own doc:
        // "best-effort... nothing here waits for or depends on that
        // notification landing") — poll until the bound address stops
        // accepting rather than asserting on the first attempt.
        tokio::time::timeout(TIMEOUT, async {
            loop {
                match tokio::time::timeout(
                    Duration::from_millis(200),
                    tokio::net::TcpStream::connect(bind_addr),
                )
                .await
                {
                    Ok(Ok(_)) => tokio::time::sleep(Duration::from_millis(20)).await,
                    _ => return,
                }
            }
        })
        .await
        .expect("the target's listener must be torn down after tunnel_close");

        release_tx
            .send(())
            .expect("tell the holder task to stop holding");
        hold_task.await.expect("hold task join");

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

/// Regression for the panic an adversarial review caught in `Ops::
/// tunnel_open`'s reverse `-R` leg: `RemoteForwardAcceptor::register`
/// starts its claim loop with a bare `tokio::spawn`
/// (`RemoteForwardAcceptor::register`'s own doc), which requires an
/// ambient Tokio runtime context on the calling thread. The scenario
/// above (and every other L3 test in this file) drives `Ops::tunnel_open`
/// from `tokio::task::spawn_blocking`, whose worker threads *do* carry
/// runtime context -- so it cannot catch this. The real `qsh` binary's
/// `fn main()` is plain synchronous with **no** `#[tokio::main]` and no
/// ambient runtime at all (`crates/qsh-cli/src/main.rs`); this test
/// reproduces that exact shape with `std::thread::spawn` instead, which
/// panicked with "there is no reactor running, must be called from the
/// context of a Tokio 1.x runtime" at
/// `crates/qsh-core/src/tunnel/remote.rs:668` before the fix wrapped the
/// `register()` call in `conn.runtime().block_on(...)`.
#[tokio::test(flavor = "multi_thread")]
async fn tunnel_open_remote_over_reverse_survives_a_thread_with_no_ambient_tokio_runtime() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = qsh_core::Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    qsh_core::TrustStore::default()
        .save(&paths.trust_file())
        .expect("save empty trust.toml");
    let ops = qsh_core::Ops::new(paths);
    let localctl = harness.attach_localctl(ops.paths()).await;
    let echo = EchoServer::start().await.expect("bind echo server");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        let ops_hold = ops.clone();
        let echo_port = echo.port();
        let (tunnel_tx, tunnel_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        // `std::thread::spawn`, deliberately not `tokio::task::spawn_blocking`
        // -- no ambient Tokio runtime on this thread at all, the same shape
        // `qsh-cli`'s synchronous `fn main()` calls `Ops::tunnel_open` from.
        let hold_thread = std::thread::spawn(move || {
            let hold = ops_hold
                .tunnel_open(qsh_proto::TunnelOpenReq {
                    host: "widget".to_string(),
                    mode: "remote".to_string(),
                    bind: None,
                    listen_port: u32::from(free_port()),
                    forward_host: "127.0.0.1".to_string(),
                    forward_port: u32::from(echo_port),
                })
                .expect("tunnel_open --remote over reverse, off any Tokio runtime");
            let _ = tunnel_tx.send(hold.tunnel().clone());
            let _ = release_rx.recv();
            hold.close();
        });
        let opened = tunnel_rx
            .await
            .expect("tunnel_open reported its Tunnel without panicking");
        assert_eq!(opened.mode, "remote");

        // The claim loop the off-runtime `register()` call started must
        // actually be running: dial the bound address and round-trip a
        // payload through the target's echo server.
        let bind_addr: SocketAddr = opened.bind.parse().expect("bind is a real socket address");
        let payload = b"off-runtime register() still claims TCP_ACCEPTED".to_vec();
        let got = TunnelHarness::round_trip(bind_addr, payload.clone())
            .await
            .expect("round trip through the tunnel opened off any Tokio runtime");
        assert_eq!(got, payload);

        release_tx
            .send(())
            .expect("tell the holder thread to stop holding");
        hold_thread
            .join()
            .expect("holder thread must not panic -- this is the regression this test guards");

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}
