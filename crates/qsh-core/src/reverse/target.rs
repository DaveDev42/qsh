//! `qsh reverse <controller>` — the reverse-mode target (`docs/CLI.md`
//! §6.13, `docs/design/protocol.md` §11-3/§11-4, `PLAN.md` Step 3 + Step 4).
//!
//! [`run_reverse`] resolves `<controller>` as a trust-store alias (the same
//! `Ops::resolve_peer` path `qsh <host>`/`qsh exec` use today — hosts.toml
//! directory lookup is M7), dials it, and runs
//! [`crate::handshake::initiate`] with `Hello{reverse: Some(..)}`. From the
//! wire's point of view this connection is now indistinguishable from one
//! `qsh serve` accepted: on success this process *is* a host on it, reusing
//! [`crate::serve::host_runtime`] (the exact factory `qsh serve` uses, no
//! second broker/audit/authorizer construction — `serve.rs`'s module docs)
//! and running [`crate::server::Server::serve_control`] on the connection
//! `initiate` just negotiated.
//!
//! **Step 4: the reconnect loop.** Registration is the target's only
//! reachability path, so a dead connection is never fatal — the process
//! stays up and keeps trying, forever (`docs/design/protocol.md` §11-4).
//! One connection's lifetime, inside the loop in [`run_reverse_unix`], is:
//!
//! 1. Dial + `Hello.reverse` exchange ([`dial_and_register`]). A rejection
//!    from the controller (`PERMISSION_DENIED`/`INVALID_ARGUMENT`/
//!    `UNSUPPORTED` — name-squatting shape check, the `host.reverse` choke
//!    point, or an unpinned peer) arrives as `HelloError::Remote` from
//!    `initiate`, reusing exactly the mapping `client::Session::negotiate`
//!    already applies to the same error ([`crate::client::map_hello_error`]
//!    chained into [`crate::ops::exec::map_client_error`]) — and, like
//!    every other failure at this stage, is **not** fatal: it just costs
//!    this attempt, logged and followed by backoff.
//! 2. On success, `serve_control` runs as a host on the new connection,
//!    with this connection's own outbound liveness watch
//!    ([`crate::client::pathwatch`], fed through
//!    [`crate::server::ControlPinger`] — Stage A of this step) racing
//!    `shutdown` alongside it, so a silent NAT death is noticed without
//!    waiting on QUIC's 45 s idle timeout.
//! 3. Whichever way the connection ends, [`crate::server::Server::purge_connection`]
//!    drops this connection's tickets and releases any writer lease it
//!    held — **never** the sessions themselves (`docs/design/
//!    architecture.md` §3: session lifetime is decoupled from connection
//!    lifetime, and the whole point of this loop is that the *same*
//!    broker, built once in [`run_reverse_unix`] before the loop starts,
//!    outlives every connection it dials).
//! 4. Backoff (exponential + jitter, ±%, `[reverse]` config,
//!    `docs/design/protocol.md` §11-4) via [`Backoff`], then back to step 1
//!    — unless a successful registration already reset it back to
//!    `backoff_initial_ms`.
//!
//! `shutdown` resolving at any point in that cycle — mid-backoff,
//! mid-redial, or mid-serve — is a clean exit: the host runtime drains
//! exactly once and the process returns `Ok(())`. `identity` is loaded
//! exactly once, by the caller, before any of this starts, and is never
//! reloaded on a reconnect (`PLAN.md` Step 4 (a): the macOS Keychain watch
//! item this device's key may live behind must not be re-opened per dial).

// Most of this import block is consumed only by the unix body (and this
// module's tests) — the Windows `run_reverse` refuses before touching any
// of it, so ungated these would trip `unused_imports` under the Windows
// leg's `clippy -D warnings` (same gating as `tui/mod.rs`).
#[cfg(unix)]
use std::sync::Arc;
#[cfg(any(unix, test))]
use std::time::Duration;

#[cfg(any(unix, test))]
use qsh_proto::wire;
#[cfg(unix)]
use qsh_transport::{Dialed, Dialer, FramedStream, TrustEvaluator};
// Only consumed by `run_reverse_unix`'s `StdRng::from_os_rng()` (below) —
// production's replacement for `rand::rng()`'s `!Send` `ThreadRng`
// (adversarial review finding: it made `run_reverse`'s returned future
// `!Send`, so `tokio::spawn`ing it failed to compile). `#[cfg(unix)]`
// rather than `#[cfg(any(unix, test))]`: the test module seeds its own
// `StdRng` directly via `SeedableRng::seed_from_u64`, imported locally
// inside `mod tests` (Windows leg trap (b) — an ungated import consumed
// only by unix code trips `unused_imports` under Windows clippy).
#[cfg(unix)]
use rand::SeedableRng;

#[cfg(unix)]
use crate::broker::PeerFingerprint;
#[cfg(unix)]
use crate::client::pathwatch::{PathWatch, PathWatchConfig, watch_path};
#[cfg(any(unix, test))]
use crate::config::BackoffLimits;
use crate::config::{Config, Paths};
use crate::identity::LoadedIdentity;
use crate::ops::OpError;
#[cfg(unix)]
use crate::server::ConnCtx;
#[cfg(unix)]
use crate::trust::SharedTrustStore;

/// Resolve the offered name: `--offered-name` > `[reverse].offered_name` >
/// this device's `device_id`. There is no separate "device name" concept
/// anywhere in this codebase (`Hello.device_name` and `qsh serve`/`qsh
/// listen`'s own `Hello` both already use `device_id` as their display
/// name) — this fallback matches that.
pub fn resolve_offered_name(flag: Option<&str>, config: &Config, device_id: &str) -> String {
    flag.map(str::to_owned)
        .or_else(|| config.reverse.offered_name.clone())
        .unwrap_or_else(|| device_id.to_string())
}

/// Dial `controller`, register as a reverse target, and serve as a host —
/// reconnecting with backoff, forever, whenever the connection dies —
/// until `shutdown` resolves.
///
/// `identity` must already be loaded synchronously before entering the
/// runtime, exactly like [`crate::serve::run_serve`]/
/// [`super::listen::run_listen`], and is never reloaded by the reconnect
/// loop inside (module docs). `shutdown` resolving is the only clean exit
/// (`Ok(())`) — a dead connection, cleanly closed by the controller or
/// not, is never fatal on its own (`docs/design/protocol.md` §11-4:
/// registration is this target's only reachability path, so it is never
/// abandoned).
pub async fn run_reverse(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    controller: &str,
    offered_name_flag: Option<&str>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    run_reverse_observed(
        paths,
        config,
        identity,
        controller,
        offered_name_flag,
        |_runtime| {},
        || {},
        shutdown,
    )
    .await
}

/// [`run_reverse`], plus two hooks: `on_runtime` fires exactly once —
/// synchronously, before the first dial — with the long-lived host runtime
/// (broker included, `docs/design/architecture.md` §3) the reconnect loop
/// below builds and then reuses across every attempt. `run_reverse` itself
/// is this function with no-op hooks; the CLI entry point supplies
/// `on_runtime` as a no-op (it never needs the runtime handle — only a
/// test that wants to observe session state *across* a reconnect does,
/// `crates/qsh-testkit/tests/reverse_chaos.rs`) but wires `on_unreachable`
/// up to a one-time stderr diagnostic (`PLAN.md` M3 Step 9, `docs/CLI.md`
/// §6.13). `on_unreachable` fires at most once per call, the first time an
/// attempt fails to dial/register (module docs, `run_reverse_unix`'s
/// reconnect loop) — never once per backoff retry; a doctor-item render
/// belongs to `qsh-cli`, so this only signals *that* a first failure
/// happened, never *what to print* (`qsh_core::doctor::
/// CONTROLLER_UNREACHABLE` stays the one render surface owns the text).
/// Mirrors [`super::listen::run_listen`]'s `on_bound` hook in shape.
#[allow(clippy::too_many_arguments)]
pub async fn run_reverse_observed(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    controller: &str,
    offered_name_flag: Option<&str>,
    on_runtime: impl FnOnce(&crate::serve::HostRuntime),
    on_unreachable: impl FnOnce(),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    // Twin cfg blocks as alternative tail expressions — the exact shape
    // `pty::factory` established; a `return` here instead would trip
    // clippy's `needless_return` on the Windows leg (probed empirically).
    #[cfg(not(unix))]
    {
        let _ = (
            paths,
            config,
            identity,
            controller,
            offered_name_flag,
            on_runtime,
            on_unreachable,
            shutdown,
        );
        Err(super::listen::windows_unsupported())
    }
    #[cfg(unix)]
    {
        run_reverse_unix(
            paths,
            config,
            identity,
            controller,
            offered_name_flag,
            on_runtime,
            on_unreachable,
            shutdown,
        )
        .await
    }
}

/// Close code for the connection this target's own path-death watchdog
/// (`docs/design/protocol.md` §10) condemns — a silent NAT/path death,
/// never a clean QUIC close. Local to this module, same rationale as
/// [`super::listen`]'s `CLOSE_CODE_REPLACED`: the meaning is
/// reconnect-loop-specific, not a transport concern
/// (`docs/design/architecture.md` §1). Only [`run_reverse_unix`] ever
/// closes a connection for this reason, so this stays `#[cfg(unix)]` too.
#[cfg(unix)]
const CLOSE_CODE_PATH_DEAD: u32 = 0x1004;

/// `docs/CLI.md` §6.13's Windows gate (module docs on
/// [`super::listen::windows_unsupported`]) — this is the target's half.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn run_reverse_unix(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    controller: &str,
    offered_name_flag: Option<&str>,
    on_runtime: impl FnOnce(&crate::serve::HostRuntime),
    on_unreachable: impl FnOnce(),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    let device_id = identity.identity.device_id.clone();
    let offered_name = resolve_offered_name(offered_name_flag, config, &device_id);
    // Fail closed on nonsense config before touching the network at all
    // (`ReverseConfig::backoff`'s own doc comment).
    let backoff_limits = config.reverse.backoff()?;

    // Identity (the caller's job, module docs) and the trust store are
    // both established exactly once, ahead of the loop below — never
    // re-opened per attempt (`ops::resolve_peer_address`'s own doc comment
    // is the canonical citation for why this exact split exists).
    // `SharedTrustStore` already re-reads `trust.toml` on its own whenever
    // the file's mtime moves (`trust/mod.rs`'s module docs), so this one
    // long-lived handle still picks up an operator's `qsh trust add`
    // without needing to be reopened.
    let trust = SharedTrustStore::open(paths.trust_file())?;
    let dialer = Dialer::new(identity.local, trust.clone() as Arc<dyn TrustEvaluator>);

    // The broker — and every session it ever opens — outlives every
    // connection this loop dials (`docs/design/architecture.md` §3): built
    // once, reused across every attempt below, never rebuilt on a
    // reconnect. This is what makes "sessions survive reconnection" true.
    let runtime = crate::serve::host_runtime(paths, config, device_id.clone());
    on_runtime(&runtime);
    let local_hello = runtime.server.local_hello(Some(wire::ReverseRegistration {
        offered_name: offered_name.clone(),
        // Empty means "same as Hello.capabilities" (`v1.proto`'s field
        // doc) — this target offers everything its own `Hello` does, so
        // there is nothing narrower to say here.
        capabilities: Vec::new(),
    }));

    // `StdRng::from_os_rng()`, not `rand::rng()`: `ThreadRng` wraps an
    // `Rc`, making it (and therefore this whole function's returned
    // future) `!Send` — a compile error the moment any caller tries to
    // `tokio::spawn` this loop rather than `block_on` it (adversarial
    // review finding). `Backoff<R>` is generic over `R: RngCore`
    // specifically so a `Send` RNG can be swapped in here at zero
    // behavioral cost; the reconnect sequence itself is unaffected either
    // way — its determinism guarantee (`docs/design/testing.md` L2) comes
    // from the *tests* seeding a `StdRng` explicitly, never from what
    // production seeds itself with.
    let mut backoff = Backoff::new(backoff_limits, rand::rngs::StdRng::from_os_rng());
    tokio::pin!(shutdown);

    // `Option` rather than a bare `FnOnce()` in scope: the loop below can
    // reach the `Err` arm many times across the process lifetime (every
    // backoff retry, every future redial after a connection that once
    // succeeded later dies), but `on_unreachable` must fire at most once
    // per invocation, and only for a genuine first-attempt failure
    // (`PLAN.md` M3 Step 9 — a `qsh reverse` process must not re-print the
    // controller-reachability diagnostic on every retry, and must not
    // print it at all once the controller has proven reachable by
    // accepting a registration). `Option::take` turns the `FnOnce` into
    // something callable from a loop body without changing its "called at
    // most once" contract; the `Ok` arm below additionally sets this to
    // `None` outright so a later redial failure — after the controller
    // was already reachable once — never fires it.
    let mut on_unreachable = Some(on_unreachable);

    loop {
        let attempt = tokio::select! {
            _ = &mut shutdown => {
                runtime.server.drain().await;
                return Ok(());
            }
            result = dial_and_register(&dialer, &trust, controller, &local_hello) => result,
        };

        let (dialed, ctl, peer_hello) = match attempt {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(controller, %err, "qsh reverse: registration attempt failed");
                // Gated to the FIRST failed connection attempt of a fresh
                // process, before any registration has ever succeeded:
                // `dial_and_register` collapses DNS failures,
                // refused/blackholed UDP, and TLS rejections into the same
                // `OpError` today, so there is no protocol-level signal
                // this loop could switch on to fire only for the
                // reachability-class case the diagnostic describes without
                // a wire change (`PLAN.md` M3 Step 9 documents this choice
                // explicitly). The first attempt of a fresh `qsh reverse`
                // process is the one moment a controller that is simply
                // unreachable and a controller having a bad day look
                // identical from here, and it is also the moment an
                // operator most needs the reachability reminder — so this
                // is where it fires, once, and (the `Ok` arm's `None`
                // assignment below) never once the controller has proven
                // itself reachable by accepting a registration — a later
                // redial failure after that is a benign reconnect blip
                // (mobility, sleep/wake), not a reachability problem.
                if let Some(hook) = on_unreachable.take() {
                    hook();
                }
                let delay = backoff.next_delay();
                ReconnectEvent {
                    event: "retry",
                    host: controller,
                    fingerprint: "-",
                    delay_ms: Some(delay.as_millis() as u64),
                }
                .emit();
                if !wait_backoff(delay, &mut shutdown).await {
                    runtime.server.drain().await;
                    return Ok(());
                }
                continue;
            }
        };
        // A registration the controller actually accepted: the next
        // failure (if any) starts backoff over from `backoff_initial_ms`
        // again (`docs/design/protocol.md` §11-4). Also permanently
        // disarms `on_unreachable`: it must fire only for a genuine
        // first-attempt failure (the comment above this match), never for
        // a later redial after a connection that once worked — a benign
        // reconnect blip (mobility, a sleep/wake) is exactly the case
        // `docs/design/testing.md` L2's reconnect story exists to survive,
        // and printing "controller unreachable" for it would be a false
        // alarm the controller has already disproved by having accepted
        // this same target once (adversarial review finding, M3 Step 9).
        on_unreachable = None;
        backoff.reset();

        // Must outlive the connection (`Dialer::dial`'s own docs).
        let _endpoint = dialed.endpoint;
        let conn = dialed.connection;
        let peer_fp = conn
            .peer_fingerprint()
            .map(|fp| fp.to_string())
            .unwrap_or_else(|| "-".to_string());

        ReconnectEvent {
            event: "registered",
            host: controller,
            fingerprint: &peer_fp,
            delay_ms: None,
        }
        .emit();
        tracing::info!(
            controller,
            offered_name,
            "qsh reverse: registered, serving this connection as a host"
        );

        let ctx = ConnCtx {
            principal: conn.principal().clone(),
            auth_path: conn.auth_path(),
            peer_fingerprint: conn
                .peer_fingerprint()
                .map(|fp| PeerFingerprint::new(*fp.as_bytes())),
            peer_addr: conn.remote_address(),
            conn_id: conn.stable_id(),
            capabilities: crate::handshake::negotiated_capabilities(&peer_hello),
            // This *is* a real `qsh reverse` registration — the one site
            // that sets this `true` (`ConnCtx::is_reverse_registration`'s
            // own doc).
            is_reverse_registration: true,
        };
        let conn_id = ctx.conn_id;

        // This connection's own liveness watch (`docs/design/protocol.md`
        // §10/§11-4, Stage A's `server::ControlPinger`): the target dialed
        // this connection, so nothing else ever notices a silent NAT
        // death on it — `watch.dead()` below is what turns that into a
        // reconnect instead of `serve_control` sitting parked forever on a
        // read that will never complete.
        let watch = PathWatch::new(PathWatchConfig::default());
        let probes = Arc::new(tokio::sync::Notify::new());
        let watchdog = tokio::spawn(watch_path(conn.clone(), watch.clone(), probes.clone()));

        // `serve_control` is `tokio::spawn`ed rather than raced directly
        // against `shutdown`/`watch.dead()` below, on purpose: it is the
        // sole writer of `session.closed` onto this connection's control
        // stream (`server/mod.rs`'s module docs), and `drain()` only
        // *queues* that event — delivering it needs `serve_control`'s loop
        // still running to actually flush it to the wire.
        let mut serve_control = tokio::spawn({
            let server = runtime.server.clone();
            let conn = conn.clone();
            let watch = watch.clone();
            let probes = probes.clone();
            async move {
                server
                    .serve_control(&conn, ctl, ctx, Some((watch, probes)))
                    .await
            }
        });

        tokio::select! {
            _ = &mut shutdown => {
                // SIGTERM graceful drain (`docs/CLI.md` §6.12, ADR-0003) —
                // this is the single path a shutdown signal can take out
                // of this loop, whether it lands mid-backoff, mid-redial
                // (the `select!` above `dial_and_register`) or here,
                // mid-serve, so `drain` runs exactly once regardless of
                // which. `serve_control` keeps running as its own task
                // through this, so it can still deliver `session.closed`
                // before the connection closes below.
                runtime.server.drain().await;
                conn.close(0, b"shutdown");
                let _ = serve_control.await;
                watchdog.abort();
                return Ok(());
            }
            () = watch.dead() => {
                // No clean QUIC close — the path just went silent
                // (`docs/design/protocol.md` §10). `serve_control` is
                // parked on a read that will never complete on its own,
                // but aborting the *outer* task here would not be enough:
                // `serve_control`'s own module docs single out that
                // dropping its `blocking: JoinSet` only *requests* an
                // abort of the tasks inside it, so a data-stream task
                // already mid-await on `Sessions::take_lease` could still
                // apply it after `purge_connection` below runs, pinning a
                // lease to a dead connection forever. Closing the
                // connection instead makes `ctl.recv.recv()` return an
                // error, so `serve_control`'s own loop exits normally and
                // runs its own `blocking.shutdown().await` — the join
                // actually happens, and `purge_connection` below only
                // starts once it has.
                conn.close(CLOSE_CODE_PATH_DEAD, b"path unresponsive");
                let _ = (&mut serve_control).await;
            }
            joined = &mut serve_control => {
                let detail = match joined {
                    Ok(Ok(())) => "connection closed".to_string(),
                    Ok(Err(err)) => err.to_string(),
                    Err(join_err) => format!("serve_control task failed: {join_err}"),
                };
                tracing::info!(controller, %detail, "qsh reverse: connection to the controller ended");
            }
        }
        watchdog.abort();

        // The connection is gone one way or another: drop its tickets and
        // release any writer lease it held. Sessions, PTYs and children are
        // untouched (module docs) — this is `docs/CLI.md` §6.13's own
        // documented observable difference from a forward host ("the
        // writer lease is bound to the connection the resident `qsh
        // listen` daemon holds"), and it is Step 3's race debt ② closing:
        // unlike Step 3's single-shot process, this loop keeps running and
        // re-registers, so a stale lease left behind here would actually
        // be observable by the *next* connection instead of being
        // reclaimed by process exit.
        runtime.server.purge_connection(conn_id).await;
        ReconnectEvent {
            event: "lost",
            host: controller,
            fingerprint: &peer_fp,
            delay_ms: None,
        }
        .emit();

        let delay = backoff.next_delay();
        ReconnectEvent {
            event: "retry",
            host: controller,
            fingerprint: "-",
            delay_ms: Some(delay.as_millis() as u64),
        }
        .emit();
        if !wait_backoff(delay, &mut shutdown).await {
            runtime.server.drain().await;
            return Ok(());
        }
    }
}

/// One dial+register attempt: resolve `controller`'s address fresh (it may
/// have moved since the last attempt — DNS, a dynamic IP), dial, and run
/// the `Hello.reverse` exchange. Never retries on its own — the reconnect
/// loop in [`run_reverse_unix`] owns backoff between attempts
/// (`docs/design/protocol.md` §11-4).
#[cfg(unix)]
async fn dial_and_register(
    dialer: &Dialer,
    trust: &SharedTrustStore,
    controller: &str,
    local_hello: &wire::Hello,
) -> Result<(Dialed, FramedStream, wire::Hello), OpError> {
    let (address, server_name) = crate::ops::resolve_peer_address(&trust.snapshot(), controller)?;
    let addr = crate::ops::resolve_one(&address).await?;
    let dialed = dialer
        .dial(addr, &server_name)
        .await
        .map_err(|err| crate::ops::exec::map_dial_error(err, &address))?;
    let (ctl, peer_hello) = crate::handshake::initiate(&dialed.connection, local_hello.clone())
        .await
        .map_err(|err| crate::ops::exec::map_client_error(crate::client::map_hello_error(err)))?;
    Ok((dialed, ctl, peer_hello))
}

/// Sleep out one backoff delay, unless `shutdown` resolves first. Its own
/// function (rather than inlined into the reconnect loop) so `docs/design/
/// testing.md` L2's "no CPU burn … after reaching the cap the loop waits
/// ~30s between attempts" is testable under `tokio::time::pause()` without
/// a real dial. `true` means the delay elapsed in full; `false` means
/// `shutdown` won the race and the caller must stop retrying.
#[cfg(any(unix, test))]
async fn wait_backoff(
    delay: Duration,
    shutdown: &mut (impl std::future::Future<Output = ()> + Unpin),
) -> bool {
    tokio::select! {
        _ = &mut *shutdown => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

/// Exponential backoff with jitter between reconnect attempts
/// (`docs/design/protocol.md` §11-4): starts at `limits.initial`, doubles
/// (capped at `limits.max`) on every subsequent [`Backoff::next_delay`]
/// call, and collapses back to `initial` on [`Backoff::reset`] (a
/// successful registration). The multiplier is fixed at 2 — not a config
/// knob; `docs/CLI.md`/`protocol.md` §11-4 name only initial/max/jitter as
/// tunable.
///
/// Generic over the RNG so `docs/design/testing.md` L2's property tests can
/// inject a seeded `rand::rngs::StdRng` for a fully deterministic sequence;
/// production uses `rand::rngs::StdRng::from_os_rng()` — `Send`, unlike
/// `rand::rng()`'s `ThreadRng` (`run_reverse_unix`'s own doc comment).
#[cfg(any(unix, test))]
struct Backoff<R> {
    limits: BackoffLimits,
    /// The un-jittered delay the last call returned; `None` before the
    /// first call (or right after a [`Backoff::reset`]) — either way the
    /// next call starts the sequence at `limits.initial`.
    current: Option<Duration>,
    rng: R,
}

#[cfg(any(unix, test))]
impl<R: rand::RngCore> Backoff<R> {
    /// The multiplier the un-jittered delay doubles by on each failure
    /// (`docs/design/protocol.md` §11-4 — fixed, not configurable).
    const MULTIPLIER: u32 = 2;

    fn new(limits: BackoffLimits, rng: R) -> Self {
        Self {
            limits,
            current: None,
            rng,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let raw = match self.current {
            None => self.limits.initial,
            Some(prev) => prev.saturating_mul(Self::MULTIPLIER).min(self.limits.max),
        };
        self.current = Some(raw);
        jitter(raw, self.limits.jitter_pct, &mut self.rng)
    }

    /// A successful registration: the next failure starts the sequence
    /// over from `initial` again.
    fn reset(&mut self) {
        self.current = None;
    }
}

/// Apply `±jitter_pct%` to `delay`, drawing the offset from `rng`.
/// `jitter_pct == 0` short-circuits to an exact, deterministic delay
/// (and never touches `rng`).
#[cfg(any(unix, test))]
fn jitter(delay: Duration, jitter_pct: u8, rng: &mut impl rand::RngCore) -> Duration {
    if jitter_pct == 0 {
        return delay;
    }
    let millis = delay.as_millis() as i64;
    let pct = i64::from(jitter_pct);
    let offset_pct = rand::Rng::random_range(rng, -pct..=pct);
    let jittered = millis + (millis * offset_pct) / 100;
    Duration::from_millis(jittered.max(0) as u64)
}

/// One `registered`/`lost`/`retry` line from the target's own point of view
/// — the same tracing target and one-line-JSON discipline as
/// `reverse::listen::RegistrationEvent` (`docs/CLI.md` §6.13's documented
/// vocabulary: `registered|denied|replaced|lost|expired|retry`; `denied`/
/// `replaced`/`expired` are controller-only observations and never appear
/// here). A separate, target-owned type rather than reusing
/// `RegistrationEvent` itself: the two sides observe different things at
/// different times — most notably, a `retry` fires before any TLS
/// handshake for that attempt has even started (e.g. a DNS failure during
/// backoff), so there is no fingerprint to report yet, and this target
/// never learns the `generation` number the controller's registry assigns
/// it (`Hello`'s reply never carries it back).
#[cfg(any(unix, test))]
#[derive(serde::Serialize)]
struct ReconnectEvent<'a> {
    event: &'static str,
    host: &'a str,
    fingerprint: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    delay_ms: Option<u64>,
}

#[cfg(any(unix, test))]
impl ReconnectEvent<'_> {
    /// Emit on [`super::listen::TARGET`] at `INFO` — the exact JSON line a
    /// stderr-reading campaign script parses whole, built by `serde_json`
    /// rather than hand-formatted (`docs/CLI.md` §6.13: "payload·토큰 field
    /// 없음").
    fn emit(&self) {
        let line = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        tracing::info!(
            target: super::listen::TARGET,
            event = self.event,
            host = self.host,
            fingerprint = self.fingerprint,
            delay_ms = self.delay_ms,
            "{}",
            line
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::ReverseConfig;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn offered_name_precedence_flag_then_config_then_device_id() {
        let mut config = Config::default();
        assert_eq!(
            resolve_offered_name(None, &config, "device_abc"),
            "device_abc"
        );
        config.reverse.offered_name = Some("configured".into());
        assert_eq!(
            resolve_offered_name(None, &config, "device_abc"),
            "configured"
        );
        assert_eq!(
            resolve_offered_name(Some("flagged"), &config, "device_abc"),
            "flagged"
        );
    }

    // Regression for the adversarial review finding: `rand::rng()`
    // (`ThreadRng`, `!Send`) held across every `.await` in the reconnect
    // loop made `run_reverse_observed`'s (and therefore `run_reverse`'s)
    // returned future `!Send`, so `tokio::spawn(run_reverse(..))` failed to
    // compile while the symmetric `tokio::spawn(run_listen(..))` was fine.
    // Nothing here actually runs `never_called` — the whole point is the
    // compile-time check `assert_send` performs on the future value it's
    // handed; a future `!Send` fails to *build*, not to pass an assertion.
    #[cfg(unix)]
    #[test]
    fn run_reverse_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        fn never_called(
            paths: &Paths,
            config: &Config,
            identity: LoadedIdentity,
            controller: &str,
        ) {
            let fut = run_reverse_observed(
                paths,
                config,
                identity,
                controller,
                None,
                |_runtime| {},
                || {},
                std::future::pending::<()>(),
            );
            assert_send(fut);
        }
        let _ = never_called;
    }

    // `host_runtime` spawns the broker's TTL reaper (`tokio::spawn`), so
    // this needs a runtime in context — same reason
    // `serve::tests::host_runtime_wires_device_id_and_a_shared_audit_sink`
    // is a `#[tokio::test]` rather than a plain `#[test]`.
    #[tokio::test]
    async fn reverse_hello_carries_only_offered_name_capabilities_empty() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path(), dir.path());
        let runtime = crate::serve::host_runtime(&paths, &Config::default(), "hermes");
        let hello = runtime.server.local_hello(Some(wire::ReverseRegistration {
            offered_name: "phone".into(),
            capabilities: Vec::new(),
        }));
        let reg = hello.reverse.expect("Hello.reverse is Some");
        assert_eq!(reg.offered_name, "phone");
        assert!(
            reg.capabilities.is_empty(),
            "empty means \"same as Hello.capabilities\" (v1.proto)"
        );
    }

    /// `docs/CLI.md` §6.13's Windows gate, mechanically: `run_reverse`
    /// refuses on every non-unix target before it ever touches its
    /// arguments (module docs on [`super::listen::windows_unsupported`]),
    /// so the identity/paths/config below are throwaway. This is the
    /// positive Windows-leg assertion `PLAN.md` Step 3 (d) owes ("Windows
    /// leg의 nextest green … 나머지가 컴파일·통과") — a real `#[tokio::test]`
    /// that runs and passes on the Windows CI leg, not just an absence of
    /// a compile error there.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn run_reverse_is_unsupported_on_non_unix() {
        let identity = LoadedIdentity {
            identity: crate::identity::Identity {
                device_id: "device".into(),
                fingerprint: qsh_transport::Fingerprint::of_spki_der(&[]),
                key_store: qsh_proto::KeyStoreKind::File,
                created_at: "2026-01-01T00:00:00Z".into(),
                cert_der: Vec::new(),
            },
            local: qsh_transport::LocalIdentity {
                cert_chain: Vec::new(),
                key_pkcs8_der: Vec::new(),
            },
        };
        let paths = Paths::new("unused-config", "unused-state");
        let err = run_reverse(
            &paths,
            &Config::default(),
            identity,
            "controller",
            None,
            std::future::pending::<()>(),
        )
        .await
        .expect_err("non-unix must refuse to run");
        assert_eq!(err.code, qsh_proto::ErrorCode::Unsupported);
    }

    // ------------------------------------------------------------------
    // Backoff (`docs/design/testing.md` L2 — deterministic, seeded RNG,
    // no wall clock)
    // ------------------------------------------------------------------

    fn limits(initial_ms: u64, max_ms: u64, jitter_pct: u8) -> BackoffLimits {
        BackoffLimits {
            initial: Duration::from_millis(initial_ms),
            max: Duration::from_millis(max_ms),
            jitter_pct,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The un-jittered sequence never shrinks and never exceeds the
        /// cap — checked with `jitter_pct: 0` so the observed delay *is*
        /// the raw sequence, isolating this property from jitter's own
        /// (separately tested below).
        #[test]
        fn backoff_sequence_is_monotone_nondecreasing_until_the_cap(
            initial_ms in 1u64..=5_000,
            max_ms in 1u64..=120_000,
            seed in any::<u64>(),
        ) {
            prop_assume!(max_ms >= initial_ms);
            let limits = limits(initial_ms, max_ms, 0);
            let mut backoff = Backoff::new(limits, StdRng::seed_from_u64(seed));

            let first = backoff.next_delay();
            prop_assert_eq!(first, limits.initial);

            let mut prev = first;
            for _ in 0..24 {
                let next = backoff.next_delay();
                prop_assert!(next >= prev, "backoff must never shrink before a reset");
                prop_assert!(next <= limits.max, "backoff must never exceed the cap");
                prev = next;
            }
            // log2(120_000 / 1) < 17: 24 further doublings always
            // saturate at the cap for every (initial, max) in range.
            prop_assert_eq!(prev, limits.max, "cap must actually be reached, not just respected");
        }

        /// Every jittered delay falls within `±jitter_pct%` of the raw
        /// (pre-jitter) delay the same doubling-then-cap sequence would
        /// have produced.
        #[test]
        fn jitter_stays_within_the_declared_band(
            initial_ms in 1u64..=5_000,
            max_ms in 1u64..=120_000,
            jitter_pct in 0u8..100,
            seed in any::<u64>(),
        ) {
            prop_assume!(max_ms >= initial_ms);
            let limits = limits(initial_ms, max_ms, jitter_pct);
            let mut backoff = Backoff::new(limits, StdRng::seed_from_u64(seed));

            let mut raw = limits.initial;
            for i in 0..16 {
                if i > 0 {
                    raw = raw.saturating_mul(2).min(limits.max);
                }
                let observed = backoff.next_delay();
                let raw_ms = raw.as_millis() as i64;
                let band = raw_ms * i64::from(jitter_pct) / 100;
                let lo = (raw_ms - band).max(0);
                let hi = raw_ms + band;
                let observed_ms = observed.as_millis() as i64;
                prop_assert!(
                    observed_ms >= lo && observed_ms <= hi,
                    "delay {observed_ms}ms out of band [{lo},{hi}] for raw {raw_ms}ms at {jitter_pct}%",
                );
            }
        }

        /// `jitter_stays_within_the_declared_band` above is containment-only:
        /// an implementation that applied zero jitter (or jitter only ever
        /// rounding down) would satisfy it trivially. Pin that jitter is
        /// actually applied and actually two-sided: at a fixed nonzero
        /// `jitter_pct`, repeated draws from distinct seeds must produce at
        /// least two distinct delays, with at least one strictly below the
        /// raw (pre-jitter) delay and at least one strictly above it.
        #[test]
        fn jitter_actually_varies_and_straddles_the_raw_delay(
            initial_ms in 200u64..=5_000,
            seed_base in any::<u64>(),
        ) {
            let jitter_pct = 20u8;
            let limits = limits(initial_ms, initial_ms, jitter_pct);
            let raw_ms = initial_ms as i64;

            let mut distinct = std::collections::HashSet::new();
            let mut saw_below = false;
            let mut saw_above = false;
            for offset in 0u64..64 {
                let mut backoff = Backoff::new(limits, StdRng::seed_from_u64(seed_base.wrapping_add(offset)));
                let observed_ms = backoff.next_delay().as_millis() as i64;
                distinct.insert(observed_ms);
                saw_below |= observed_ms < raw_ms;
                saw_above |= observed_ms > raw_ms;
            }
            prop_assert!(
                distinct.len() >= 2,
                "jitter_pct {jitter_pct}% must produce more than one distinct delay across seeds, got {distinct:?}",
            );
            prop_assert!(saw_below, "jitter must round down at least once across seeds, got {distinct:?}");
            prop_assert!(saw_above, "jitter must round up at least once across seeds, got {distinct:?}");
        }

        /// A reset collapses the sequence back to `initial`, regardless of
        /// how far it had already climbed.
        #[test]
        fn reset_returns_the_sequence_to_initial(
            initial_ms in 1u64..=5_000,
            max_ms in 1u64..=120_000,
            seed in any::<u64>(),
        ) {
            prop_assume!(max_ms >= initial_ms);
            let limits = limits(initial_ms, max_ms, 0);
            let mut backoff = Backoff::new(limits, StdRng::seed_from_u64(seed));

            prop_assert_eq!(backoff.next_delay(), limits.initial);
            let _ = backoff.next_delay();
            let _ = backoff.next_delay();
            backoff.reset();
            prop_assert_eq!(backoff.next_delay(), limits.initial);
        }
    }

    #[test]
    fn a_jitter_of_exactly_zero_percent_is_deterministic() {
        // jitter_pct: 0 never calls into the rng at all — proven by
        // seeding with a value that would otherwise perturb the delay.
        let mut backoff = Backoff::new(limits(500, 2_000, 0), StdRng::seed_from_u64(1));
        assert_eq!(backoff.next_delay(), Duration::from_millis(500));
        assert_eq!(backoff.next_delay(), Duration::from_millis(1_000));
        assert_eq!(backoff.next_delay(), Duration::from_millis(2_000));
        assert_eq!(backoff.next_delay(), Duration::from_millis(2_000));
    }

    // ------------------------------------------------------------------
    // wait_backoff (`docs/design/testing.md` L2 — `tokio::time::pause()`,
    // no `sleep()`-based test synchronization)
    // ------------------------------------------------------------------

    /// `docs/design/protocol.md` §11-4 / `PLAN.md` Step 4 (d): "controller
    /// 부재 상태에서 재접속 루프가 CPU를 태우지 않음(상한 도달 후 30 s
    /// 간격)". Reaching the cap and then waiting is driven by a real
    /// `tokio::time::sleep`, not a busy poll — proven by advancing a
    /// *paused* clock and asserting the elapsed virtual time is exactly
    /// the capped delay, never more (no extra spinning) and never less
    /// (no shortcut).
    #[tokio::test(start_paused = true)]
    async fn after_reaching_the_cap_the_loop_waits_the_full_default_thirty_seconds() {
        // `jitter_pct: 0` isolates this from jitter's own (separately
        // tested) band — this test is about the *wait mechanism*, not
        // about how big the delay is.
        let cap = ReverseConfig::default().backoff().unwrap().max;
        assert_eq!(cap, Duration::from_millis(30_000), "the documented default");
        let mut backoff = Backoff::new(limits(500, 30_000, 0), StdRng::seed_from_u64(7));
        let mut delay = Duration::ZERO;
        for _ in 0..12 {
            delay = backoff.next_delay();
        }
        assert_eq!(delay, cap, "must have saturated at the cap by now");

        let shutdown = std::future::pending::<()>();
        tokio::pin!(shutdown);
        let start = tokio::time::Instant::now();
        let completed = wait_backoff(delay, &mut shutdown).await;
        assert!(completed, "the delay must elapse, not be short-circuited");
        assert_eq!(
            tokio::time::Instant::now() - start,
            Duration::from_millis(30_000),
            "must wait exactly the capped delay — no busy loop, no shortcut",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_interrupts_a_backoff_wait_immediately() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tx.send(()).unwrap();
        let shutdown = async move {
            let _ = rx.await;
        };
        tokio::pin!(shutdown);

        let start = tokio::time::Instant::now();
        let completed = wait_backoff(Duration::from_secs(30), &mut shutdown).await;
        assert!(!completed, "shutdown must win the race, not the sleep");
        assert_eq!(
            tokio::time::Instant::now() - start,
            Duration::ZERO,
            "must not wait any part of the delay once shutdown has already fired",
        );
    }

    // ------------------------------------------------------------------
    // ReconnectEvent (`docs/CLI.md` §6.13 — one-line JSON, additive only)
    // ------------------------------------------------------------------

    #[test]
    fn reconnect_event_json_line_has_the_documented_field_set() {
        let retry = ReconnectEvent {
            event: "retry",
            host: "personal-mac",
            fingerprint: "-",
            delay_ms: Some(542),
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&retry).unwrap()).unwrap();
        assert_eq!(parsed["event"], "retry");
        assert_eq!(parsed["host"], "personal-mac");
        assert_eq!(parsed["fingerprint"], "-");
        assert_eq!(parsed["delay_ms"], 542);

        let registered = ReconnectEvent {
            event: "registered",
            host: "personal-mac",
            fingerprint: "sha256:abc",
            delay_ms: None,
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&registered).unwrap()).unwrap();
        assert_eq!(parsed["event"], "registered");
        assert_eq!(parsed["fingerprint"], "sha256:abc");
        assert!(
            parsed.get("delay_ms").is_none(),
            "delay_ms must be omitted, not null, when absent — additive-only field"
        );

        // `emit()`'s only production callers live inside `run_reverse_unix`,
        // which is `#[cfg(unix)]`. Under `cfg(test) && not(unix)` (the
        // windows-latest leg of `cargo clippy --workspace --all-targets`)
        // that leaves the method itself unreferenced unless a test calls it
        // too — call it here so it is exercised (and its output shape
        // covered) on every platform this module compiles under.
        retry.emit();
        registered.emit();
    }
}
