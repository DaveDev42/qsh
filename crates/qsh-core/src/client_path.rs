//! The QUIC-side meaning of the root form's ssh options (ADR-0051 decision
//! 7). `-4`/`-6`, `-o ConnectTimeout`, `ServerAliveInterval` and
//! `ServerAliveCountMax` describe the ssh path, and also apply to the QUIC
//! connection the same command makes.
//!
//! The values are process-wide and installed once, at start, by the client
//! frontend ([`install`]). A process that never installs anything (the
//! daemons, every subcommand) sees the compiled defaults. The alternative,
//! carrying the values through every `Dialer::new` and `resolve_all` call
//! site, would touch a dozen call sites for a setting that is the same for
//! the whole life of one `qsh` invocation.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use crate::config::Liveness;
use crate::ssh_bootstrap::{AddressFamily, SshOptions};

#[derive(Debug, Clone, Copy)]
struct ClientPath {
    family: AddressFamily,
    keep_alive: Option<Duration>,
    strikes: Option<u32>,
}

static CLIENT_PATH: OnceLock<ClientPath> = OnceLock::new();

/// Install the QUIC-side values of `options`. The first call wins.
pub fn install(options: &SshOptions) {
    let _ = CLIENT_PATH.set(ClientPath {
        family: options.family(),
        keep_alive: options.server_alive_interval(),
        strikes: options.server_alive_count_max(),
    });
    if let Some(timeout) = options.connect_timeout() {
        qsh_transport::set_default_dial_timeout(timeout);
    }
}

/// Keep only the addresses the installed `-4`/`-6` filter allows.
pub(crate) fn filter_addresses(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    match CLIENT_PATH.get() {
        Some(path) => addrs
            .into_iter()
            .filter(|addr| path.family.allows(addr))
            .collect(),
        None => addrs,
    }
}

/// The installed address family (for messages).
pub(crate) fn family() -> AddressFamily {
    CLIENT_PATH.get().map_or(AddressFamily::Any, |p| p.family)
}

/// Apply `ServerAliveInterval` / `ServerAliveCountMax` to a validated
/// [`Liveness`]. The interval is held inside the allowed keep-alive range
/// (a longer ssh interval would let the fixed 45 s idle timeout fire first,
/// ADR-0021 decision 1), and the count becomes the number of unanswered
/// path probes that call the path dead.
pub(crate) fn apply_liveness(liveness: &mut Liveness) {
    let Some(path) = CLIENT_PATH.get() else {
        return;
    };
    if let Some(interval) = path.keep_alive {
        let lo = Duration::from_millis(crate::config::TransportConfig::MIN_KEEP_ALIVE_MS);
        let hi = Duration::from_millis(crate::config::TransportConfig::MAX_KEEP_ALIVE_MS);
        liveness.keep_alive = interval.clamp(lo, hi);
    }
    if let Some(strikes) = path.strikes {
        liveness.watch.strikes = strikes;
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::ssh_bootstrap::SshFlags;

    fn mixed() -> Vec<SocketAddr> {
        ["192.0.2.1:4433", "[2001:db8::1]:4433", "198.51.100.7:9"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect()
    }

    fn install_flags(ipv4: bool, ipv6: bool) {
        let options = SshOptions::from_flags(&SshFlags {
            ipv4,
            ipv6,
            ..SshFlags::default()
        })
        .unwrap();
        install(&options);
    }

    /// `-4` keeps only IPv4 candidates, in order. Each test is its own
    /// process under nextest, so the process-wide install is not shared.
    #[test]
    fn dash_four_filters_punch_candidates_to_ipv4() {
        install_flags(true, false);
        let kept = filter_addresses(mixed());
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(SocketAddr::is_ipv4), "{kept:?}");
        assert_eq!(family(), AddressFamily::V4);
    }

    /// `-6` keeps only IPv6 candidates.
    #[test]
    fn dash_six_filters_punch_candidates_to_ipv6() {
        install_flags(false, true);
        let kept = filter_addresses(mixed());
        assert_eq!(kept.len(), 1);
        assert!(kept.iter().all(SocketAddr::is_ipv6), "{kept:?}");
        assert_eq!(family(), AddressFamily::V6);
    }

    /// Without either flag nothing is dropped.
    #[test]
    fn without_a_family_flag_every_candidate_stays() {
        install_flags(false, false);
        assert_eq!(filter_addresses(mixed()), mixed());
    }
}
