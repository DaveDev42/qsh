//! Platform-touching detectors for `doctor.run` (`docs/CLI.md` §6.17):
//! raw UDP egress probing, `$PATH` scanning for a shadowing `qsh`
//! executable, and a read-only platform-keystore reachability probe.
//! Deliberately split out of `crate::doctor` (the parent module's own doc,
//! `doctor.rs` L13-15's no-cfg rule): the parent stays pure text so it
//! builds identically everywhere, and every cfg branch — or platform
//! quirk in how "unreachable" surfaces from a raw socket — lives here
//! instead, in the one place a diagnostic actually has to *do* something.
//!
//! Detection (the two probes) and classification are kept apart on
//! purpose: [`classify_connectivity`] is a pure function over an already-
//! observed [`UdpProbeOutcome`], so the precedence rule between
//! `controller_unreachable`/`udp_egress_blocked`/`no_route`
//! (`PLAN.md` M7 §4.1 #5) is unit-testable with synthetic inputs, with no
//! real socket, no timing, and no flakiness — the same split
//! `crate::ops::exec::map_dial_error` uses for `DialError` → `OpError`.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use qsh_proto::DoctorFinding;

use super::Diagnostic;

// ---------------------------------------------------------------------------
// Connectivity: raw UDP egress probe + pure classification
// ---------------------------------------------------------------------------

/// What a raw UDP egress probe against one address observed. Never a QUIC
/// handshake — just enough to tell "packets can leave and something comes
/// back" from "silently dropped" from "actively refused" at the transport
/// layer below QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpProbeOutcome {
    /// Something came back within the timeout. Does not have to be a
    /// meaningful reply — even an OS-surfaced error datagram counts as
    /// "the round trip happened", which is all this probe claims.
    Responded,
    /// No response within the timeout — indistinguishable, at this layer,
    /// from "nothing is listening" and "a firewall silently drops UDP".
    /// Classified as [`crate::doctor::UDP_EGRESS_BLOCKED`] (or
    /// [`crate::doctor::CONTROLLER_UNREACHABLE`] for a controller target).
    TimedOut,
    /// The OS reported the destination actively unreachable — network/host
    /// unreachable or connection-refused class errors, the signature of an
    /// ICMP rejection rather than a silent drop. Classified as
    /// [`crate::doctor::NO_ROUTE`] (or [`crate::doctor::CONTROLLER_UNREACHABLE`]
    /// for a controller target).
    Unreachable,
    /// Some other local I/O failure setting up or using the probe socket
    /// (e.g. the ephemeral bind itself failed). Classified the same as
    /// [`UdpProbeOutcome::Unreachable`] — an operator is better served by
    /// "check routing" than a false claim that a firewall drop was
    /// observed.
    Other(io::ErrorKind),
}

/// Send one deterministic, content-free datagram to `target` and wait up
/// to `timeout` for anything at all to come back.
///
/// Blocking, synchronous `std::net::UdpSocket` — deliberately not QUIC:
/// `doctor.run` needs to tell a silent drop apart from an active refusal,
/// which `qsh_transport::DialError` already collapses together (both can
/// surface as a QUIC-layer timeout), so this probes strictly below that
/// layer instead of reusing the transport's own dialer.
pub fn probe_udp_egress(target: SocketAddr, timeout: Duration) -> UdpProbeOutcome {
    let bind_addr: SocketAddr = if target.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(socket) => socket,
        Err(err) => return classify_io_error(&err),
    };
    if let Err(err) = socket.connect(target) {
        return classify_io_error(&err);
    }
    if let Err(err) = socket.send(b"qsh-doctor-probe") {
        return classify_io_error(&err);
    }
    if let Err(err) = socket.set_read_timeout(Some(timeout)) {
        return UdpProbeOutcome::Other(err.kind());
    }
    let mut buf = [0u8; 512];
    match socket.recv(&mut buf) {
        Ok(_) => UdpProbeOutcome::Responded,
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            UdpProbeOutcome::TimedOut
        }
        Err(err) => classify_io_error(&err),
    }
}

fn classify_io_error(err: &io::Error) -> UdpProbeOutcome {
    match err.kind() {
        io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::ConnectionRefused => UdpProbeOutcome::Unreachable,
        other => UdpProbeOutcome::Other(other),
    }
}

/// Turn one already-observed probe outcome into at most one
/// [`DoctorFinding`] — the precedence rule `docs/CLI.md` §6.17 /
/// `PLAN.md` M7 §4.1 #5 locks: a `controller` target always classifies a
/// failure as `controller_unreachable`; any other target classifies a
/// silent timeout as `udp_egress_blocked` and an active refusal as
/// `no_route`. Exactly one code per failed probe, never two.
///
/// Pure: takes the outcome, never observes the network itself, which is
/// what makes the precedence rule unit-testable with synthetic inputs
/// instead of a real (and inherently OS/CI-dependent) socket.
pub fn classify_connectivity(
    outcome: UdpProbeOutcome,
    is_controller_target: bool,
    host: &str,
    address: &str,
) -> Option<DoctorFinding> {
    match outcome {
        UdpProbeOutcome::Responded => None,
        UdpProbeOutcome::TimedOut => Some(finding_from(
            if is_controller_target {
                &super::CONTROLLER_UNREACHABLE
            } else {
                &super::UDP_EGRESS_BLOCKED
            },
            host,
            address,
        )),
        UdpProbeOutcome::Unreachable | UdpProbeOutcome::Other(_) => Some(finding_from(
            if is_controller_target {
                &super::CONTROLLER_UNREACHABLE
            } else {
                &super::NO_ROUTE
            },
            host,
            address,
        )),
    }
}

fn finding_from(diag: &Diagnostic, host: &str, address: &str) -> DoctorFinding {
    DoctorFinding {
        code: diag.code.to_string(),
        status: "error".to_string(),
        detail: format!("{} (host: {host}, address: {address})", diag.message),
        remedy: Some(diag.remedy.to_string()),
    }
}

// ---------------------------------------------------------------------------
// $PATH shadow scan
// ---------------------------------------------------------------------------

/// Platform-appropriate `qsh` executable file name(s) to look for on each
/// `$PATH` entry.
#[cfg(unix)]
const QSH_EXE_NAMES: &[&str] = &["qsh"];
#[cfg(windows)]
const QSH_EXE_NAMES: &[&str] = &["qsh.exe"];

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
}

/// The first `qsh` executable `dirs` (in order) resolves to — i.e. what
/// invoking bare `qsh` would actually run right now. `None` when no `$PATH`
/// entry has one at all (e.g. this build is only ever invoked by absolute
/// path).
fn first_qsh_on_path(dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in dirs {
        for name in QSH_EXE_NAMES {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Whether some *other* `qsh` executable on `$PATH` (`dirs`, in resolution
/// order) would run instead of `current_exe` — and if so, which one.
///
/// `None` when: nothing on `$PATH` matches at all; the first match *is*
/// `current_exe` (compared after canonicalizing both, so distinct-looking
/// paths to the same file never false-positive); or either path fails to
/// canonicalize (missing/unreadable — this never guesses, only reports a
/// mismatch it could actually confirm).
///
/// Pure given its inputs (`docs/CLI.md` §6.17, `PLAN.md` M7 §4.1 #5's
/// "순수함수 우선" discipline): `crate::ops::doctor` is the only caller that
/// reads `std::env::current_exe()`/`std::env::split_paths` and hands the
/// results in, which is what makes this testable with an injected temp
/// `$PATH` instead of the real one.
pub fn detect_path_shadow(current_exe: &Path, dirs: &[PathBuf]) -> Option<PathBuf> {
    let found = first_qsh_on_path(dirs)?;
    let current_canon = std::fs::canonicalize(current_exe).ok()?;
    let found_canon = std::fs::canonicalize(&found).ok()?;
    if current_canon == found_canon {
        None
    } else {
        Some(found)
    }
}

// ---------------------------------------------------------------------------
// Platform keystore reachability (read-only probe)
// ---------------------------------------------------------------------------

/// Turn an already-performed [`crate::identity::KeyStore::load`] probe
/// result into a `keystore_unavailable` finding, or `None` when the store
/// is reachable (`Ok`) or failed for some other reason
/// (`crate::identity::KeyStoreError::Io`/`Other` — not what this
/// diagnostic is about).
///
/// Pure over its input for the same reason [`classify_connectivity`] is:
/// `crate::ops::doctor` performs the actual (platform-dependent, and on a
/// real machine often environment-dependent) probe and hands the result
/// in, so this mapping is unit-testable with a synthetic
/// [`crate::identity::KeyStoreError::Unavailable`] instead of depending on
/// whether the test machine happens to have a reachable platform store.
pub fn keystore_finding(
    probe: Result<Option<zeroize::Zeroizing<Vec<u8>>>, crate::identity::KeyStoreError>,
) -> Option<DoctorFinding> {
    match probe {
        Err(crate::identity::KeyStoreError::Unavailable(reason)) => Some(DoctorFinding {
            code: super::KEYSTORE_UNAVAILABLE.code.to_string(),
            status: "warn".to_string(),
            detail: format!("{} ({reason})", super::KEYSTORE_UNAVAILABLE.message),
            remedy: Some(super::KEYSTORE_UNAVAILABLE.remedy.to_string()),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Raw UDP probe — real sockets, `udp_egress_blocked`'s trigger (a
    // cooperative local black-hole: bound, but never read from/responded
    // to) plus the happy path. `no_route`'s real-socket trigger is OS/CI
    // dependent (E-2, brief) so it stays `#[ignore]`; `classify_connectivity`
    // below covers its logic deterministically instead.
    // -----------------------------------------------------------------

    #[test]
    fn probe_reports_responded_when_the_target_replies() {
        let responder = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let addr = responder.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = responder.recv_from(&mut buf) {
                let _ = responder.send_to(&buf[..n], from);
            }
        });
        let outcome = probe_udp_egress(addr, Duration::from_secs(2));
        assert_eq!(outcome, UdpProbeOutcome::Responded);
        handle.join().unwrap();
    }

    /// `udp_egress_blocked`'s actual trigger: a socket that binds (so the
    /// address is live) but never calls `recv`, standing in for a firewall
    /// that drops the packet silently — both look identical to a probe
    /// that only waits for *any* response.
    #[test]
    fn probe_times_out_against_a_silent_black_hole() {
        let black_hole = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let addr = black_hole.local_addr().unwrap();
        let outcome = probe_udp_egress(addr, Duration::from_millis(300));
        assert_eq!(outcome, UdpProbeOutcome::TimedOut);
        drop(black_hole);
    }

    /// OS/CI dependent (ICMP port-unreachable handling varies by sandbox),
    /// so `#[ignore]` per the brief's own E-2 guidance — `classify_connectivity`'s
    /// unit tests below cover the `no_route` *logic* deterministically;
    /// this is only a best-effort confirmation that a real refused port
    /// actually reaches that classification on a real socket.
    #[test]
    #[ignore = "ICMP port-unreachable delivery to a connected UDP socket is OS/sandbox dependent"]
    fn probe_reports_unreachable_when_nothing_listens_on_the_port() {
        let claim = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let addr = claim.local_addr().unwrap();
        drop(claim);
        let outcome = probe_udp_egress(addr, Duration::from_millis(500));
        assert_eq!(outcome, UdpProbeOutcome::Unreachable);
    }

    // -----------------------------------------------------------------
    // classify_io_error — pure, synthetic `io::Error`s, no socket
    // (verify round P3-3: nothing drove this function before, so mutation
    // `MH`, `ConnectionRefused` remapped to `TimedOut`, went undetected —
    // in production that turns an actively refused port into
    // `udp_egress_blocked` ("a firewall is silently blocking UDP")
    // instead of `no_route`, a wrong remedy handed to an operator).
    // -----------------------------------------------------------------

    #[test]
    fn classify_io_error_maps_active_refusal_kinds_to_unreachable() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
        ] {
            let outcome = classify_io_error(&io::Error::from(kind));
            assert_eq!(outcome, UdpProbeOutcome::Unreachable, "{kind:?}");
        }
    }

    #[test]
    fn classify_io_error_maps_any_other_kind_to_other() {
        let outcome = classify_io_error(&io::Error::from(io::ErrorKind::PermissionDenied));
        assert_eq!(
            outcome,
            UdpProbeOutcome::Other(io::ErrorKind::PermissionDenied)
        );
    }

    // -----------------------------------------------------------------
    // classify_connectivity — pure, synthetic inputs, no socket.
    // -----------------------------------------------------------------

    #[test]
    fn classify_connectivity_responded_has_no_finding() {
        assert!(classify_connectivity(UdpProbeOutcome::Responded, false, "h", "a:1").is_none());
        assert!(classify_connectivity(UdpProbeOutcome::Responded, true, "h", "a:1").is_none());
    }

    #[test]
    fn classify_connectivity_controller_target_always_wins() {
        for outcome in [
            UdpProbeOutcome::TimedOut,
            UdpProbeOutcome::Unreachable,
            UdpProbeOutcome::Other(io::ErrorKind::Other),
        ] {
            let finding = classify_connectivity(outcome, true, "ctrl", "203.0.113.1:4433")
                .unwrap_or_else(|| panic!("expected a finding for {outcome:?}"));
            assert_eq!(finding.code, "controller_unreachable");
        }
    }

    #[test]
    fn classify_connectivity_non_controller_timeout_is_udp_egress_blocked() {
        let finding =
            classify_connectivity(UdpProbeOutcome::TimedOut, false, "h", "203.0.113.1:4433")
                .unwrap();
        assert_eq!(finding.code, "udp_egress_blocked");
        assert_eq!(finding.status, "error");
        assert!(finding.remedy.is_some());
    }

    #[test]
    fn classify_connectivity_non_controller_unreachable_is_no_route() {
        for outcome in [
            UdpProbeOutcome::Unreachable,
            UdpProbeOutcome::Other(io::ErrorKind::Other),
        ] {
            let finding = classify_connectivity(outcome, false, "h", "203.0.113.1:4433").unwrap();
            assert_eq!(finding.code, "no_route");
        }
    }

    /// Precedence, asserted directly (E-6, brief): never two codes for one
    /// failed probe.
    #[test]
    fn classify_connectivity_never_emits_more_than_one_code_for_one_failure() {
        const CODES: [&str; 3] = ["controller_unreachable", "udp_egress_blocked", "no_route"];
        for is_controller in [true, false] {
            for outcome in [UdpProbeOutcome::TimedOut, UdpProbeOutcome::Unreachable] {
                let finding = classify_connectivity(outcome, is_controller, "h", "a:1").unwrap();
                assert_eq!(
                    CODES.iter().filter(|&&c| c == finding.code).count(),
                    1,
                    "{outcome:?}/{is_controller} produced {}",
                    finding.code
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // PATH shadow scan
    // -----------------------------------------------------------------

    #[cfg(unix)]
    fn write_fake_exe(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("qsh");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(windows)]
    fn write_fake_exe(dir: &Path) -> PathBuf {
        let path = dir.join("qsh.exe");
        std::fs::write(&path, b"MZ").unwrap();
        path
    }

    #[test]
    fn detect_path_shadow_finds_an_earlier_qsh_before_the_running_one() {
        let dir = tempfile::tempdir().unwrap();
        let shadow_dir = dir.path().join("shadow");
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&shadow_dir).unwrap();
        std::fs::create_dir(&real_dir).unwrap();
        let shadow_exe = write_fake_exe(&shadow_dir);
        let real_exe = write_fake_exe(&real_dir);

        let found = detect_path_shadow(&real_exe, &[shadow_dir, real_dir]);
        assert_eq!(found.as_deref(), Some(shadow_exe.as_path()));
    }

    #[test]
    fn detect_path_shadow_is_none_when_the_running_binary_resolves_first() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        let other_dir = dir.path().join("other");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::create_dir(&other_dir).unwrap();
        let real_exe = write_fake_exe(&real_dir);
        let _other_exe = write_fake_exe(&other_dir);

        assert!(detect_path_shadow(&real_exe, &[real_dir, other_dir]).is_none());
    }

    #[test]
    fn detect_path_shadow_is_none_with_no_qsh_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        let empty_dir = dir.path().join("empty");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::create_dir(&empty_dir).unwrap();
        let real_exe = write_fake_exe(&real_dir);

        assert!(detect_path_shadow(&real_exe, &[empty_dir]).is_none());
        assert!(detect_path_shadow(&real_exe, &[]).is_none());
    }

    // -----------------------------------------------------------------
    // keystore_finding — pure, synthetic KeyStoreError.
    // -----------------------------------------------------------------

    #[test]
    fn keystore_finding_fires_on_unavailable() {
        let finding = keystore_finding(Err(crate::identity::KeyStoreError::Unavailable(
            "no secret service".to_string(),
        )))
        .unwrap();
        assert_eq!(finding.code, "keystore_unavailable");
        assert_eq!(finding.status, "warn");
        assert!(finding.detail.contains("no secret service"));
    }

    #[test]
    fn keystore_finding_is_none_when_reachable_or_a_different_failure() {
        assert!(keystore_finding(Ok(None)).is_none());
        assert!(
            keystore_finding(Err(crate::identity::KeyStoreError::Other(
                "malformed".to_string()
            )))
            .is_none()
        );
    }
}
