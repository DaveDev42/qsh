//! Host-environment self-check: can loopback UDP actually round-trip?
//!
//! A stale host firewall rule once dropped loopback UDP to ports
//! 60000-61000 (a leftover nftables table with no loopback exception).
//! About 4.3% of `bind(0)` QUIC endpoints landed in that range and every
//! test that used one waited out a 10 s timeout, which looked like a flaky
//! product bug (`docs/design/testing.md` CI discipline). This module turns
//! that failure into one immediate, explicit panic.
//!
//! The probe is the Rust twin of `scripts/soak/preflight_udp.py`: bind a
//! few UDP sockets on `127.0.0.1` across the ephemeral range plus the
//! known-bad 60000-61000 stretch, send each a datagram from another socket
//! and expect it back within [`PROBE_TIMEOUT`]. Ports already in use are
//! skipped. A healthy host answers in well under a millisecond per port, so
//! the whole check stays far below 50 ms.
//!
//! [`ensure_loopback_udp`] runs the probe once per process
//! ([`OnceLock`]) and is called from the harness constructors that open
//! QUIC endpoints. `qsh-core`'s own unit tests cannot reach it
//! (`qsh-testkit` depends on `qsh-core`, never the reverse).

use std::net::{SocketAddr, UdpSocket};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long a sent datagram may take to arrive before the port counts as
/// blocked. Loopback delivery is synchronous in practice.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(200);

/// Ports always probed: the stretch the old firewall rule dropped.
const KNOWN_BAD_RANGE_PORTS: [u16; 5] = [60000, 60250, 60500, 60750, 61000];

/// Ephemeral-range samples taken on top of [`KNOWN_BAD_RANGE_PORTS`].
const EPHEMERAL_SAMPLES: u16 = 16;

const PAYLOAD: &[u8] = b"qsh-testkit-udp-selfcheck";

/// Outcome of one probe pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// Ports whose datagram never arrived.
    pub blocked: Vec<u16>,
    /// Ports that were bound and answered.
    pub ok: usize,
    /// Ports skipped because another process held them.
    pub skipped: usize,
}

fn ephemeral_range() -> (u16, u16) {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|raw| {
            let mut it = raw.split_whitespace().map(|v| v.parse::<u16>().ok());
            match (it.next().flatten(), it.next().flatten()) {
                (Some(lo), Some(hi)) if lo > 0 && hi > lo => Some((lo, hi)),
                _ => None,
            }
        })
        .unwrap_or((32768, 60999))
}

fn sample_ports() -> Vec<u16> {
    let (lo, hi) = ephemeral_range();
    let span = u32::from(hi - lo);
    let mut ports: Vec<u16> = (0..EPHEMERAL_SAMPLES)
        .map(|i| lo + (span * u32::from(i) / u32::from(EPHEMERAL_SAMPLES - 1)) as u16)
        .collect();
    ports.extend(KNOWN_BAD_RANGE_PORTS);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Round-trip one datagram per port. `send` delivers the datagram; the
/// production path is a plain `send_to`, the unit test swaps in a sender
/// that drops one port to stand in for a firewall.
fn probe_with(
    ports: &[u16],
    timeout: Duration,
    send: impl Fn(&UdpSocket, SocketAddr),
) -> ProbeReport {
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind probe sender on 127.0.0.1");
    let mut receivers = Vec::new();
    let mut skipped = 0;
    for &port in ports {
        match UdpSocket::bind(("127.0.0.1", port)) {
            Ok(sock) => {
                sock.set_nonblocking(true)
                    .expect("nonblocking probe socket");
                send(&sender, sock.local_addr().expect("probe local addr"));
                receivers.push((port, sock));
            }
            Err(_) => skipped += 1,
        }
    }
    let deadline = Instant::now() + timeout;
    let mut pending: Vec<(u16, UdpSocket)> = receivers;
    let mut ok = 0;
    let mut buf = [0u8; 64];
    while !pending.is_empty() && Instant::now() < deadline {
        pending.retain(|(_, sock)| match sock.recv_from(&mut buf) {
            Ok((n, _)) if &buf[..n] == PAYLOAD => {
                ok += 1;
                false
            }
            _ => true,
        });
        if !pending.is_empty() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    ProbeReport {
        blocked: pending.into_iter().map(|(port, _)| port).collect(),
        ok,
        skipped,
    }
}

/// Probe the sampled ports with real sends.
pub fn probe_loopback_udp() -> ProbeReport {
    probe_with(&sample_ports(), PROBE_TIMEOUT, |sender, to| {
        let _ = sender.send_to(PAYLOAD, to);
    })
}

/// Render the panic message for a failed probe.
fn failure_message(report: &ProbeReport) -> String {
    let (lo, hi) = (
        report.blocked.iter().min().copied().unwrap_or(0),
        report.blocked.iter().max().copied().unwrap_or(0),
    );
    format!(
        "loopback UDP self-check failed: datagrams to 127.0.0.1 ports {:?} (range {lo}-{hi}) \
         were not delivered within {} ms. QUIC tests that bind an endpoint in that range would \
         wait out a 10 s timeout. Likely cause: a host firewall rule dropping loopback UDP, e.g. \
         a leftover nftables table (`sudo nft list ruleset`). Workaround: run the suite in its \
         own network namespace with scripts/test/nextest-ns.sh. See docs/design/testing.md \
         (CI discipline).",
        report.blocked,
        PROBE_TIMEOUT.as_millis(),
    )
}

/// Run the self-check once per process and panic with a clear message when
/// loopback UDP is filtered. Cheap after the first call.
pub fn ensure_loopback_udp() {
    static RESULT: OnceLock<Result<(), String>> = OnceLock::new();
    let result = RESULT.get_or_init(|| {
        let report = probe_loopback_udp();
        if report.blocked.is_empty() {
            Ok(())
        } else {
            Err(failure_message(&report))
        }
    });
    if let Err(message) = result {
        panic!("{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_healthy_loopback_reports_no_blocked_port_and_is_cheap() {
        let started = Instant::now();
        let report = probe_loopback_udp();
        let took = started.elapsed();
        assert!(report.blocked.is_empty(), "{report:?}");
        assert!(report.ok > 0, "nothing probed: {report:?}");
        assert!(took < Duration::from_millis(50), "probe took {took:?}");
        ensure_loopback_udp();
    }

    #[test]
    fn a_dropped_datagram_is_reported_as_blocked_and_named_in_the_message() {
        let sender_probe = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let victim = sender_probe.local_addr().expect("addr").port();
        drop(sender_probe);
        let report = probe_with(&[victim], Duration::from_millis(30), |_, _| {});
        assert_eq!(report.blocked, vec![victim]);
        let message = failure_message(&report);
        assert!(message.contains(&victim.to_string()), "{message}");
        assert!(message.contains("scripts/test/nextest-ns.sh"), "{message}");
        assert!(message.contains("nftables"), "{message}");
    }

    #[test]
    fn a_port_held_by_another_socket_is_skipped_not_blocked() {
        let holder = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let port = holder.local_addr().expect("addr").port();
        let report = probe_with(&[port], Duration::from_millis(30), |_, _| {});
        assert_eq!(report.skipped, 1);
        assert!(report.blocked.is_empty());
    }
}
