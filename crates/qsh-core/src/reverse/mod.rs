//! Reverse mode (`docs/design/protocol.md` §11, `docs/CLI.md` §6.13):
//! `qsh listen` (controller) accepts dial-in registrations from `qsh
//! reverse` (target) and serves them as hosts.
//!
//! M3 plan Step 3 (2473c88) lands in two PRs. **PR 3a**: [`registry`] (the
//! transport-free metadata table and name-resolution logic) and [`admit`]
//! (the `host.reverse` authorization choke point that bridges it to
//! `qsh_transport`'s typed `Principal`/`AuthPath`/`Authorizer`), factored so
//! both can be unit-tested without a transport. **PR 3b**: [`listen`] (`qsh
//! listen`'s `run_listen` — bind, accept, `handshake::respond`, `admit`,
//! the live-connection table) and [`target`] (`qsh reverse`'s `run_reverse`
//! — dial, `handshake::initiate` with `Hello.reverse`, then
//! `Server::serve_control` on the same connection). The CLI surface
//! (`Command::Listen`/`Command::Reverse`) lives in `qsh-cli`, not here.
//!
//! The `registry`/`admit` split exists so that `registry.rs` alone can
//! satisfy the transport-free arch-lint M3 plan Step 5 (2473c88) commits to adding
//! for this exact file (the same six-token `BROKER_DIR`-style ban
//! `xtask/src/arch.rs` already enforces under `broker/`) — see
//! `registry`'s module docs.

pub mod admit;
pub mod listen;
pub mod registry;
pub mod target;

#[cfg(test)]
pub(crate) mod test_harness;

/// The [`PathWatchConfig`] the target's registered-session watchdog uses
/// (`target::run_reverse_observed`). Production gets `configured`, which is the
/// validated reverse registration watch of the `[recovery]` section in this
/// process's own `config.toml` (ADR-0021 decision 4, ADR-0041;
/// [`crate::client::pathwatch::PathWatchConfig::reverse_default`] when the
/// section is absent). Under
/// `#[cfg(test)]` only, a test can wrap the target future in
/// [`TEST_PATH_WATCH_CONFIG`]`.scope(..)` to raise the judgment floor
/// (`min_dead_after`) above quinn's 45 s idle timeout, so the idle timeout,
/// not `PathWatch`, is what ends a silent connection. The override is
/// compiled out of every non-test build, which keeps it separate from the
/// `[recovery]` config surface, and it is deliberately not a cargo feature
/// (workspace feature unification could switch it on in the shipped
/// binary).
pub(crate) fn path_watch_config(
    configured: crate::client::pathwatch::PathWatchConfig,
) -> crate::client::pathwatch::PathWatchConfig {
    #[cfg(test)]
    if let Ok(config) = TEST_PATH_WATCH_CONFIG.try_with(|config| *config) {
        return config;
    }
    configured
}

/// The wake signal the target's reconnect loop listens to
/// (`target::run_reverse_observed`). Production always gets the process-wide
/// detector's subscription. Under `#[cfg(test)]` only, a test can wrap the
/// target future in [`TEST_WAKE`]`.scope(..)` to inject wakes by hand.
pub(crate) fn wake_subscription() -> tokio::sync::watch::Receiver<crate::client::wake::WakeEvent> {
    #[cfg(test)]
    if let Ok(mut rx) = TEST_WAKE.try_with(|rx| rx.clone()) {
        rx.mark_unchanged();
        return rx;
    }
    crate::client::wake::subscribe()
}

#[cfg(test)]
tokio::task_local! {
    /// Test-only override read by [`wake_subscription`]. A task-local, not a
    /// process global, so it only reaches the future it scopes.
    pub(crate) static TEST_WAKE: tokio::sync::watch::Receiver<crate::client::wake::WakeEvent>;
}

#[cfg(test)]
tokio::task_local! {
    /// Test-only override read by [`path_watch_config`]. A task-local, not
    /// a process global, so it only reaches the future it scopes.
    pub(crate) static TEST_PATH_WATCH_CONFIG: crate::client::pathwatch::PathWatchConfig;
}

/// Count the tunnel traffic on a registration `conn` as use of the
/// registration, for `watch`. Called by both ends right after they build the
/// registration's [`crate::client::pathwatch::PathWatch`]; the returned guard
/// stops the reporting when it drops, so hold it as long as the watch runs.
///
/// Without this the watch could not tell a registration that carries
/// tunnels from one that carries nothing. Its fast cadence (250 ms probes,
/// the `P×S+D` budget of ADR-0041) runs only while the registration is in
/// use, and only control messages other than `Ping`/`Pong` said so
/// (`server::ControlPinger::record`). Tunnel bytes ride their own QUIC
/// streams and never touch the control stream, so a registration busy with
/// nothing but tunnels, the topology of issue #10, fell to the idle beat
/// (`PathWatchConfig::idle_probe_interval`, 5 s) after `active_window`
/// (15 s) and took about 20 s to be ruled dead. Every tunnel splice on
/// either end reports its byte counts to a `tunnel::stall::StreamTrack`
/// (the localctl relay legs included), which is where the hook fires.
///
/// Only [`PathWatch::activity`](crate::client::pathwatch::PathWatch::activity):
/// the cadence moves, liveness does not. Bytes written locally prove nothing
/// about the path, and the datagram counter already counts what arrives.
pub(crate) fn report_tunnel_traffic(
    watch: &crate::client::pathwatch::PathWatch,
    conn: &qsh_transport::Connection,
) -> crate::tunnel::stall::TrafficGuard {
    let watch = watch.clone();
    crate::tunnel::stall::report_traffic(conn, std::sync::Arc::new(move || watch.activity()))
}

/// A duration as whole milliseconds for a diagnostic line, saturating
/// rather than wrapping.
pub(crate) fn millis(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}
