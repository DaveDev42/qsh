//! `qsh reverse <controller>` — the reverse-mode target (`docs/CLI.md`
//! §6.13, `docs/design/protocol.md` §11-3/§11-4, `PLAN.md` Step 3 + Step 4).
//!
//! [`run_reverse`] resolves `<controller>` via the same `hosts.toml`-over-
//! `trust.toml` address resolution `Ops::resolve_peer` uses for
//! `qsh <host>`/`qsh exec` (`PLAN.md` M7 Step 3, §4.1 #4), dials it, and
//! runs
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
//! One connection's lifetime, inside the loop in `run_reverse_unix`, is:
//!
//! 1. Dial + `Hello.reverse` exchange (`dial_and_register`). A rejection
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
//!    broker, built once in `run_reverse_unix` before the loop starts,
//!    outlives every connection it dials).
//! 4. Backoff (exponential + jitter, ±%, `[reverse]` config,
//!    `docs/design/protocol.md` §11-4) via `Backoff`, then back to step 1
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
// `#[cfg(any(unix, test))]`, not plain `#[cfg(unix)]`: `dial_and_register`
// itself and its own unit test both need `Arc`/`Dialed`/`Dialer`/
// `FramedStream`/`TrustEvaluator`/`SharedTrustStore` on every CI target
// (the windows-latest test leg included), not just a unix build — see
// `dial_and_register`'s own doc comment.
#[cfg(any(unix, test))]
use std::sync::Arc;
#[cfg(any(unix, test))]
use std::time::Duration;

#[cfg(any(unix, test))]
use qsh_proto::wire;
#[cfg(any(unix, test))]
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
#[cfg(any(unix, test))]
use crate::reverse::ReconnectCause;
#[cfg(unix)]
use crate::server::ConnCtx;
#[cfg(any(unix, test))]
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
            result = dial_and_register(&dialer, &trust, paths, controller, &local_hello) => result,
        };

        let (dialed, ctl, peer_hello) = match attempt {
            Ok(v) => v,
            Err((err, cause)) => {
                tracing::warn!(controller, %err, cause = cause.as_str(), "qsh reverse: registration attempt failed");
                // Gated to the FIRST failed connection attempt of a fresh
                // process, before any registration has ever succeeded.
                // `dial_and_register` does now classify DNS failures,
                // refused/blackholed UDP and TLS rejections into distinct
                // `cause`s (issue #4 item 6, `cause` above) — but
                // `on_unreachable` stays coarse on purpose: its job is the
                // *blanket* "you may not be able to reach this controller
                // at all" hint (`PLAN.md` M3 Step 9), which every one of
                // those causes equally warrants on a fresh process's first
                // attempt, not a per-cause routing decision. The first
                // attempt of a fresh `qsh reverse` process is the one
                // moment a controller that is simply unreachable and a
                // controller having a bad day look identical from here,
                // and it is also the moment an operator most needs the
                // reachability reminder — so this is where it fires, once,
                // and (the `Ok` arm's `None` assignment below) never once
                // the controller has proven itself reachable by accepting
                // a registration — a later redial failure after that is a
                // benign reconnect blip (mobility, sleep/wake), not a
                // reachability problem.
                if let Some(hook) = on_unreachable.take() {
                    hook();
                }
                let delay = backoff.next_delay();
                ReconnectEvent {
                    event: "retry",
                    host: controller,
                    fingerprint: None,
                    delay_ms: Some(delay.as_millis() as u64),
                    cause: Some(cause.as_str()),
                    at: crate::config::now_rfc3339(),
                    // A fresh dial/register failure never had a
                    // registration to time (issue #4 item 6).
                    since_registered_ms: None,
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
        // Issue #4 item 6: starts the clock this registration's eventual
        // `lost`/`retry` pair reports as `since_registered_ms` — a plain
        // local, not `Option`: the only read (below, after `'serve` ends)
        // is always reached through this exact assignment first, never
        // through an earlier loop iteration or the dial-failure `Err` arm
        // above (which never reads it).
        let registered_at = std::time::Instant::now();

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
            fingerprint: Some(&peer_fp),
            delay_ms: None,
            // Not an ended registration (issue #4 item 6).
            cause: None,
            at: crate::config::now_rfc3339(),
            since_registered_ms: None,
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

        // This connection's own periodic quota-audit flush (main-session
        // arbitration item 5, S2 deviation 2, design §2.4 path ②): the
        // forward host's accept loop (`server::Server::run`) already ticks
        // `Server::quota_housekeeping` on this exact cadence, but this
        // reconnect loop has no accept loop of its own to hang a tick off
        // — without this, a quota-rejection window on a target that stays
        // registered for a long time (no reconnect to trigger
        // `purge_connection`'s own one-shot flush, path ③) only ever
        // closes lazily, on the *next* rejection, which once a burst stops
        // may be never. Same interval, same missed-tick policy as
        // `Server::run`'s own `audit_flush`.
        let mut quota_flush = tokio::time::interval(crate::admission::AUDIT_AGGREGATION_WINDOW);
        quota_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Why this connection ended, for the `lost`/`retry` pair below
        // (issue #4 item 6, `docs/CLI.md` §6.13 bullet at :952). Deferred
        // init, no `mut`: the two arms below that `break 'serve` each
        // assign this exactly once, first — the only way to reach the
        // read after the loop.
        let loss_cause;
        'serve: loop {
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
                    // Same path-③ reasoning as `Server::run`'s own
                    // post-loop call (design §2.4): a shutdown that lands
                    // mid-window must not strand that window's summary —
                    // this connection is not reconnecting, so nothing
                    // else will ever flush it. This is the *only* arm of
                    // this loop that returns without falling through to
                    // the shared `purge_connection` call below `'serve:`,
                    // so call it here explicitly; the other two arms
                    // (`watch.dead()`, `serve_control` join) `break
                    // 'serve` into it instead, and must keep doing so —
                    // this call and that one are not both reached on any
                    // path.
                    runtime.server.purge_connection(conn_id, ()).await;
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
                    // Issue #4 item 6: `watch.dead()` resolves both for a
                    // genuinely silent path (this arm's own comment above)
                    // and for a connection that was *already* closed —
                    // `ProbeSource::closed`'s own doc: "the specific
                    // ConnectionError is diagnostic-only here", i.e. ANY
                    // close wakes it, not only silence — racing ahead of
                    // `serve_control` noticing the same close on its own
                    // read. Reading `close_reason()` *before* our own
                    // `conn.close()` call just below tells the two apart:
                    // `Some` means a real close already happened (classify
                    // it exactly like `classify_target_connection_loss`
                    // would have), `None` means the connection was still
                    // nominally open and this really was watchdog-declared
                    // silence.
                    let pre_close_reason = conn.close_reason();
                    conn.close(CLOSE_CODE_PATH_DEAD, b"path unresponsive");
                    let _ = (&mut serve_control).await;
                    loss_cause = match pre_close_reason {
                        Some(err) => super::classify_connection_error(&err),
                        None => ReconnectCause::PathDead,
                    };
                    break 'serve;
                }
                joined = &mut serve_control => {
                    let detail = match &joined {
                        Ok(Ok(())) => "connection closed".to_string(),
                        Ok(Err(err)) => err.to_string(),
                        Err(join_err) => format!("serve_control task failed: {join_err}"),
                    };
                    tracing::info!(controller, %detail, "qsh reverse: connection to the controller ended");
                    loss_cause = classify_target_connection_loss(&joined);
                    break 'serve;
                }
                _ = quota_flush.tick() => {
                    runtime.server.quota_housekeeping();
                }
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
        runtime.server.purge_connection(conn_id, ()).await;
        // Issue #4 item 6: both lines below describe the same ended
        // registration, so they share `cause`/`since_registered_ms`; a
        // later `retry` from a fresh dial failure (the `Err` arm above,
        // outside this `registered_at`'s scope) reports it absent by
        // construction — that arm never sees this variable at all.
        let since_registered_ms =
            Some(u64::try_from(registered_at.elapsed().as_millis()).unwrap_or(u64::MAX));
        let lost_at = crate::config::now_rfc3339();
        ReconnectEvent {
            event: "lost",
            host: controller,
            fingerprint: Some(&peer_fp),
            delay_ms: None,
            cause: Some(loss_cause.as_str()),
            at: lost_at,
            since_registered_ms,
        }
        .emit();

        let delay = backoff.next_delay();
        ReconnectEvent {
            event: "retry",
            host: controller,
            fingerprint: None,
            delay_ms: Some(delay.as_millis() as u64),
            cause: Some(loss_cause.as_str()),
            at: crate::config::now_rfc3339(),
            since_registered_ms,
        }
        .emit();
        if !wait_backoff(delay, &mut shutdown).await {
            runtime.server.drain().await;
            return Ok(());
        }
    }
}

/// One dial+register attempt: resolve `controller`'s address fresh (it may
/// have moved since the last attempt — DNS, a dynamic IP, or an operator
/// edit to `hosts.toml`), dial, and run the `Hello.reverse` exchange. Never
/// retries on its own — the reconnect loop in [`run_reverse_unix`] owns
/// backoff between attempts (`docs/design/protocol.md` §11-4).
///
/// Address resolution reloads `hosts.toml` fresh on every attempt (never
/// cached across retries, unlike `trust`) via the same
/// [`crate::ops::resolve_peer_address`] `qsh <host>`/`qsh exec` use
/// (`PLAN.md` M7 Step 3, §4.1 #4: `hosts.toml` first, the trust store's
/// pin as fallback) — so an operator can repoint a controller's address by
/// editing `hosts.toml` without restarting this process, the same way it
/// already tolerates DNS/IP changes.
///
/// Issue #4 item 6: the `Err` side also carries a [`ReconnectCause`],
/// classified at the point of failure — before `map_dial_error`/
/// `map_client_error` collapse it into one opaque [`OpError`] — because
/// the coarser classification is what the CLI's `error.code` needs, not
/// what a reconnect-loop operator staring at stderr does. `hosts.toml`
/// failing to load and `resolve_peer_address` finding no known address
/// for `controller` both classify `local` rather than `resolve`: neither
/// one ever reaches a DNS resolver — that classification is reserved for
/// [`crate::ops::resolve_one`]'s own failure just below, the literal
/// resolver call.
///
/// Only ever driven in production from [`run_reverse_unix`]
/// (`#[cfg(unix)]`), but gated `#[cfg(any(unix, test))]` rather than
/// plain `#[cfg(unix)]` so its own unit test
/// (`dial_and_register_maps_an_unresolvable_controller_to_resolve_cause`)
/// builds and runs on every CI target, including the windows-latest
/// clippy/test leg — that test is the only place
/// [`ReconnectCause::Resolve`] is ever constructed, so without this a
/// non-unix build has no way to exercise it and the variant is dead code
/// there.
#[cfg(any(unix, test))]
async fn dial_and_register(
    dialer: &Dialer,
    trust: &SharedTrustStore,
    paths: &Paths,
    controller: &str,
    local_hello: &wire::Hello,
) -> Result<(Dialed, FramedStream, wire::Hello), (OpError, ReconnectCause)> {
    let hosts = crate::hosts::HostsFile::load(&paths.hosts_file())
        .map_err(|err| (err, ReconnectCause::Local))?;
    let (address, server_name) =
        crate::ops::resolve_peer_address(&trust.snapshot(), &hosts, controller)
            .map_err(|err| (err, ReconnectCause::Local))?;
    let addr = crate::ops::resolve_one(&address)
        .await
        .map_err(|err| (err, ReconnectCause::Resolve))?;
    let dialed = dialer.dial(addr, &server_name).await.map_err(|err| {
        let cause = classify_dial_error(&err);
        (crate::ops::exec::map_dial_error(err, &address), cause)
    })?;
    let (ctl, peer_hello) = crate::handshake::initiate(&dialed.connection, local_hello.clone())
        .await
        .map_err(|err| {
            let cause = classify_hello_error(&err);
            (
                crate::ops::exec::map_client_error(crate::client::map_hello_error(err)),
                cause,
            )
        })?;
    Ok((dialed, ctl, peer_hello))
}

/// Classify a [`qsh_transport::DialError`] into [`ReconnectCause`]'s
/// `resolve`-adjacent slice (issue #4 item 6).
/// `DialError::Failed` mirrors `map_dial_error`'s own
/// `is_crypto_failure` check exactly — the same quinn
/// `ConnectionError` that makes that function answer `AUTH_FAILED`
/// instead of `CONNECTION_FAILED` is what makes this answer
/// `tls_rejected` instead of `refused`, so the two classifications never
/// disagree about the same failure.
#[cfg(any(unix, test))]
fn classify_dial_error(err: &qsh_transport::DialError) -> ReconnectCause {
    use qsh_transport::DialError;
    match err {
        DialError::Timeout(_) => ReconnectCause::DialTimeout,
        DialError::LocalRejected { .. } | DialError::RemoteRejected => ReconnectCause::TlsRejected,
        DialError::Refused | DialError::Connect(_) => ReconnectCause::Refused,
        DialError::Failed(inner) => {
            if qsh_transport::endpoint::is_crypto_failure(inner) {
                ReconnectCause::TlsRejected
            } else {
                ReconnectCause::Refused
            }
        }
        // Endpoint construction failed before any packet went out —
        // originates on this side.
        DialError::Setup(_) => ReconnectCause::Local,
    }
}

/// Classify a [`crate::handshake::HelloError`] reached from `dial_and_register`'s
/// initiator role into [`ReconnectCause`] (issue #4 item 6). `Remote` is
/// the controller's own `host.reverse` choke point
/// answering with a wire `Error` (name-squatting shape check, ACL denial,
/// or an unpinned peer past the version check — `dial_and_register`'s own
/// module docs) — always `registration_denied`. `Connection`/a
/// `ConnectionLost` stream error reuse [`crate::reverse::classify_connection_error`]'s
/// judgment. Every other variant (`Timeout`, `ClosedBeforeHello`,
/// `ExpectedHello`, `VersionMismatch`, a stream error with no underlying
/// `ConnectionError`; `Rejected`/`AlreadyPaired` are responder-only and
/// unreachable from this initiator call, per that enum's own doc) is a
/// protocol-shaped anomaly this fixed eight-value vocabulary has no
/// sharper bucket for, so it falls to `local`.
#[cfg(any(unix, test))]
fn classify_hello_error(err: &crate::handshake::HelloError) -> ReconnectCause {
    use crate::handshake::HelloError;
    match err {
        HelloError::Remote { .. } => ReconnectCause::RegistrationDenied,
        HelloError::Connection(e) => super::classify_connection_error(e),
        HelloError::Stream(qsh_transport::StreamError::Read(
            qsh_transport::ReadError::ConnectionLost(e),
        ))
        | HelloError::Stream(qsh_transport::StreamError::Write(
            qsh_transport::WriteError::ConnectionLost(e),
        )) => super::classify_connection_error(e),
        _ => ReconnectCause::Local,
    }
}

/// Classify why the `'serve` loop in [`run_reverse_unix`] exited via its
/// `serve_control` join arm (issue #4 item 6) — reached whenever
/// `serve_control` itself notices the connection ended first; the
/// `watch.dead()` arm races the same connection dying and classifies its
/// own arm directly from `conn.close_reason()` instead of calling this
/// (that arm's own comment: `watch.dead()` resolves for an
/// already-peer-closed connection just as readily as a genuinely silent
/// one, so it cannot assume `path_dead` either). `Ok(Ok(()))` is
/// `serve_control`'s own loop ending on a clean
/// end-of-stream — the controller closed its send side — `peer_closed`.
/// `Ok(Err(err))` extracts the underlying `ConnectionError` from
/// [`crate::server::ConnError`] where one exists (`Connection`, or a
/// `ConnectionLost` stream error) and reuses
/// [`crate::reverse::classify_connection_error`]'s judgment; every other
/// `ConnError` variant (a Hello-exchange error, unreachable here — the
/// exchange already finished before `serve_control` ever ran) falls to
/// `local`. `Err(_)` is `serve_control`'s task itself panicking/being
/// aborted — `local`, a bug on this side, never a peer/path judgment.
#[cfg(any(unix, test))]
fn classify_target_connection_loss(
    joined: &Result<Result<(), crate::server::ConnError>, tokio::task::JoinError>,
) -> ReconnectCause {
    use crate::server::ConnError;
    match joined {
        Ok(Ok(())) => ReconnectCause::PeerClosed,
        Ok(Err(ConnError::Connection(e))) => super::classify_connection_error(e),
        Ok(Err(ConnError::Stream(qsh_transport::StreamError::Read(
            qsh_transport::ReadError::ConnectionLost(e),
        )))) => super::classify_connection_error(e),
        Ok(Err(ConnError::Stream(qsh_transport::StreamError::Write(
            qsh_transport::WriteError::ConnectionLost(e),
        )))) => super::classify_connection_error(e),
        Ok(Err(_)) | Err(_) => ReconnectCause::Local,
    }
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
/// it (`Hello`'s reply never carries it back). `fingerprint` is itself
/// `Option` (issue #4 item 6): every `retry` — pre-handshake or the one
/// right after a `lost` — fires before this attempt's own TLS handshake,
/// so it is always absent there, never the `"-"` placeholder earlier
/// revisions used.
#[cfg(any(unix, test))]
#[derive(serde::Serialize)]
struct ReconnectEvent<'a> {
    event: &'static str,
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delay_ms: Option<u64>,
    /// Fixed vocabulary ([`crate::reverse::ReconnectCause`]), present only
    /// on `"lost"` and the `"retry"` that follows it, and on a `"retry"`
    /// from a failed dial/register attempt — absent, never null, on
    /// `"registered"` (`docs/CLI.md` §6.13 bullet at :952, issue #4 item
    /// 6).
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<&'static str>,
    /// RFC 3339 UTC, every line (`crate::config::now_rfc3339`).
    at: String,
    /// Milliseconds since the registration that just ended was
    /// established — only on the `"lost"`/`"retry"` pair that follows a
    /// connection dying; absent (never null) everywhere else, including a
    /// `"retry"` from a fresh dial failure that never had a registration
    /// to time.
    #[serde(skip_serializing_if = "Option::is_none")]
    since_registered_ms: Option<u64>,
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
            cause = self.cause,
            at = %self.at,
            since_registered_ms = self.since_registered_ms,
            "{}",
            line
        );
    }
}

#[cfg(test)]
mod tests;
