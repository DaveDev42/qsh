//! L3 — `Ops::host_list`/`host_get`/`resolve_host_route` driven directly
//! (no CLI subprocess) over a real localctl daemon attached to
//! [`qsh_testkit::reverse::ReverseHarness`] (`docs/design/testing.md` L3,
//! `PLAN.md` M3 Step 5 (c): "`ReverseHarness` 위에서 `qsh hosts --json`이
//! forward+reverse를 한 배열로 반환하고, 연결을 끊으면 그 항목이 `stale`로
//! 바뀜" + "`qsh hosts`가 네트워크를 건드리지 않음").
//!
//! `#![cfg(unix)]`: localctl (UDS) and `ReverseHarness::attach_localctl`
//! are both unix-only (`qsh_core::localctl` compiles out on Windows,
//! `docs/CLI.md` §6.13). The Windows-leg guarantee that `qsh hosts` still
//! returns forward-only there is structural, not a dedicated unit test:
//! `ops/host.rs`'s `reverse_host_entries` has a `#[cfg(not(unix))]` tail
//! arm that returns `Vec::new()` unconditionally, so `merge_hosts` (this
//! file's `hosts_merge_forward_and_live_reverse_then_stale_after_severance`
//! test exercises its unix-side behavior) only ever sees an empty reverse
//! source there — verified by a full workspace `cargo clippy --all-targets`
//! cross-check against a Windows target rather than by a runnable test on
//! this file's own platform.
//!
//! `Ops::host_list`/`host_get`/`resolve_host_route` are plain *sync*
//! methods that spin up their own single-threaded Tokio runtime internally
//! (`ops/host.rs`'s `reverse_host_entries`, mirroring `ops/mod.rs`'s
//! `probe_fingerprint`) — exactly what a real, non-`#[tokio::main]` `qsh`
//! process's `main()` calls them from. Calling one directly on a
//! `#[tokio::test]` worker thread would panic ("Cannot start a runtime from
//! within a runtime"), so every call here goes through
//! `tokio::task::spawn_blocking`, which runs on a distinct OS thread that
//! has never entered any runtime context — the same bridge a real `qsh`
//! binary never needs only because its `main` isn't async at all.

#![cfg(unix)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::acl::AllowAllPinned;
use qsh_core::{Fingerprint, HostRoute, OpError, Ops, Paths, Principal, TrustStore};
use qsh_proto::{ErrorCode, HostGetReq};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{EntryState, ReverseHarness, wait_for};
use qsh_transport::StaticTrust;

/// Bound on every "this must have already happened" wait in this file —
/// same order of magnitude as `reverse_loopback.rs`'s own `TIMEOUT`.
const TIMEOUT: Duration = Duration::from_secs(5);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// A throwaway, parseable fingerprint for a forward pin that is never
/// actually dialed — `host.list`'s forward source reads it straight off
/// disk, so it need not belong to any real identity.
const FORWARD_FP: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// `Ops` bound at a fresh tempdir: `trust.toml` seeded with one forward pin
/// (`name` @ `address`), `runtime_dir()` pointed wherever a caller's
/// [`qsh_testkit::reverse::LocalctlHandle`] (or nothing at all, for the
/// no-daemons case) binds its socket.
fn ops_with_forward_pin(name: &str, address: &str) -> (tempfile::TempDir, Ops) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let mut trust = TrustStore::default();
    trust.add_peer(
        name,
        Some(address.to_string()),
        FORWARD_FP.parse::<Fingerprint>().expect("fingerprint"),
        "2026-01-01T00:00:00Z".to_string(),
    );
    trust.save(&paths.trust_file()).expect("save trust.toml");
    (dir, Ops::new(paths))
}

/// [`Ops::host_list`] off the calling thread — see module docs for why.
async fn host_list(ops: &Ops) -> Result<qsh_proto::HostListData, OpError> {
    let ops = ops.clone();
    tokio::task::spawn_blocking(move || ops.host_list())
        .await
        .expect("spawn_blocking join")
}

/// [`Ops::host_get`] off the calling thread.
async fn host_get(ops: &Ops, name: &str) -> Result<qsh_proto::Host, OpError> {
    let ops = ops.clone();
    let name = name.to_string();
    tokio::task::spawn_blocking(move || ops.host_get(HostGetReq { name }))
        .await
        .expect("spawn_blocking join")
}

/// [`Ops::resolve_host_route`] off the calling thread.
async fn resolve_route(ops: &Ops, name: &str) -> Result<HostRoute, OpError> {
    let ops = ops.clone();
    let name = name.to_string();
    tokio::task::spawn_blocking(move || ops.resolve_host_route(&name))
        .await
        .expect("spawn_blocking join")
}

/// The full owed L3 scenario: a forward pin and a live reverse
/// registration under the *same* name merge into two entries
/// (`docs/CLI.md` §6.1 — same name in both sources is never hidden), the
/// live one wins routing, and severing the connection flips it to
/// `"stale"` (never removes it) and routing falls back to the forward pin.
#[tokio::test(flavor = "multi_thread")]
async fn hosts_merge_forward_and_live_reverse_then_stale_after_severance() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "dup-host")).await;

    // Deliberately RFC 5737 TEST-NET-1 — a forward pin `host.list` must
    // never dial regardless of whether it is reachable.
    let (_dir, ops) = ops_with_forward_pin("dup-host", "192.0.2.10:4433");
    let localctl = harness.attach_localctl(ops.paths()).await;

    // Before any registration: the daemon is up (so this already exercises
    // the real UDS round trip) but has nothing to report — forward-only,
    // not an error.
    let before = host_list(&ops)
        .await
        .expect("host.list before registration");
    assert_eq!(
        before.hosts.len(),
        1,
        "forward-only before any registration"
    );
    assert_eq!(before.hosts[0].connection_mode, "forward");

    // Register the target under the trust-store alias "dup-host" (never
    // the offered name — name-squatting prevention, `reverse_loopback.rs`'s
    // own `registers_and_shows_live_with_a_registered_stderr_event`). The
    // raw `register` primitive (not `run_target`) is used so this test can
    // sever the *connection* itself afterward, not just ask a well-behaved
    // target to shut down.
    let (dialed, ctl, peer_hello) = harness
        .register(&target, "attacker-chosen-name")
        .await
        .expect("registration should succeed");
    assert!(peer_hello.reverse.is_none());
    let keepalive = spawn_ping_keepalive(ctl);
    wait_for(TIMEOUT, || harness.listen.registry().get("dup-host")).await;

    let merged = host_list(&ops).await.expect("host.list after registration");
    assert_eq!(
        merged.hosts.len(),
        2,
        "same name in both sources must yield two entries, got {:?}",
        merged.hosts
    );
    let forward = merged
        .hosts
        .iter()
        .find(|h| h.connection_mode == "forward")
        .expect("forward entry present");
    assert_eq!(forward.name, "dup-host");
    assert_eq!(forward.state, "unknown");
    let reverse = merged
        .hosts
        .iter()
        .find(|h| h.connection_mode == "reverse")
        .expect("reverse entry present");
    assert_eq!(reverse.name, "dup-host");
    assert_eq!(reverse.state, "reachable");
    assert_eq!(reverse.device_id, target.fingerprint.to_string());

    // `host.get`/`resolve_host_route` both pick the live reverse route.
    let got = host_get(&ops, "dup-host").await.expect("host.get live");
    assert_eq!(got.connection_mode, "reverse");
    assert_eq!(got.state, "reachable");
    let route = resolve_route(&ops, "dup-host")
        .await
        .expect("resolve_host_route live");
    assert!(
        matches!(route, HostRoute::Reverse { .. }),
        "live reverse must win routing, got {route:?}"
    );

    // Sever the connection — a real QUIC close, not a graceful target
    // shutdown (`reverse_loopback.rs`'s own
    // `a_dead_registration_transitions_to_stale_then_is_swept_after_retention`:
    // `watch_path`'s `ProbeSource::closed` resolves on any close).
    keepalive.abort();
    dialed.connection.close(0, b"severed");

    wait_for(TIMEOUT, || {
        let entry = harness.listen.registry().get("dup-host")?;
        (entry.state == EntryState::Stale).then_some(())
    })
    .await;

    let after_sever = host_list(&ops).await.expect("host.list after severance");
    assert_eq!(
        after_sever.hosts.len(),
        2,
        "a stale entry is included, never dropped from the listing"
    );
    let stale = after_sever
        .hosts
        .iter()
        .find(|h| h.connection_mode == "reverse")
        .expect("stale reverse entry still present");
    assert_eq!(stale.state, "stale");

    // Routing now falls back to the forward pin — a stale registration is
    // not a proven-reachable path.
    let got_after = host_get(&ops, "dup-host")
        .await
        .expect("host.get falls back to forward");
    assert_eq!(got_after.connection_mode, "forward");
    let route_after = resolve_route(&ops, "dup-host")
        .await
        .expect("resolve_host_route falls back to forward");
    assert!(
        matches!(route_after, HostRoute::Forward { .. }),
        "a stale reverse entry must not win routing, got {route_after:?}"
    );

    localctl.shutdown().await;
    harness.shutdown().await;
}

/// `host.list` never dials — proven by wall-clock, not just by code
/// inspection: a trust store whose only forward pin points at an
/// unreachable, black-holed address (RFC 5737 TEST-NET-1) must still
/// return within a bound far tighter than any real network connect
/// attempt could ever complete in, whether or not a localctl daemon is
/// even running (`docs/CLI.md` §6.2: "잠든 노트북 한 대가 목록을 느리게
/// 만들지 않는다").
#[tokio::test(flavor = "multi_thread")]
async fn hosts_list_never_dials_and_returns_well_under_a_dial_timeout() {
    // No daemons at all — the "no daemons -> forward-only, not an error"
    // path (`PLAN.md` M3 Step 5 (c)'s merge table), proven here under a
    // hard wall-clock bound rather than only asserted structurally.
    let (_dir, ops) = ops_with_forward_pin("blackhole", "192.0.2.55:4433");

    /// Far tighter than any real TCP/QUIC connect attempt to a black-holed
    /// address could complete in (those take multiple seconds at the very
    /// least) — a dial attempt hiding inside `host.list` would blow this.
    const DIAL_COULD_NOT_MEET: Duration = Duration::from_millis(1500);

    let start = Instant::now();
    let data = tokio::time::timeout(DIAL_COULD_NOT_MEET, host_list(&ops))
        .await
        .expect("host.list must return well inside the bound — it must never dial")
        .expect("host.list must not error just because a pin is unreachable");
    let elapsed = start.elapsed();
    assert_eq!(data.hosts.len(), 1);
    assert_eq!(data.hosts[0].connection_mode, "forward");
    assert!(
        elapsed < DIAL_COULD_NOT_MEET,
        "host.list took {elapsed:?}, suspiciously close to a real dial timeout"
    );
}

/// `host.get` on a name with neither a live reverse registration nor a
/// forward pin is `HOST_NOT_FOUND` — the same routing function `host.list`
/// never uses but `host.get` and (Step 6) `Ops::connect` share.
#[tokio::test(flavor = "multi_thread")]
async fn host_get_on_an_unregistered_unpinned_name_is_host_not_found() {
    let (_dir, ops) = ops_with_forward_pin("someone-else", "192.0.2.1:4433");
    let err = host_get(&ops, "nowhere")
        .await
        .expect_err("an unregistered, unpinned name must fail");
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

/// Keep answering the daemon's own liveness `Ping`s while this test holds
/// the raw registered connection past `PathWatchConfig::default()`'s
/// `min_dead_after` (1 s) — the identical hazard (and fix) every raw
/// long-held registration in `reverse_loopback.rs` guards against.
fn spawn_ping_keepalive(mut ctl: qsh_transport::FramedStream) -> tokio::task::JoinHandle<()> {
    use qsh_proto::wire::{self, ControlMessage, control_message};
    tokio::spawn(async move {
        loop {
            match ctl.recv.recv::<ControlMessage>().await {
                Ok(Some(msg)) => {
                    if let Some(control_message::Body::Ping(_)) = msg.body
                        && ctl
                            .send
                            .send(&ControlMessage::new(
                                msg.request_id,
                                control_message::Body::Pong(wire::Pong {}),
                            ))
                            .await
                            .is_err()
                    {
                        return;
                    }
                }
                _ => return,
            }
        }
    })
}
