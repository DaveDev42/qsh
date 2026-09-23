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

// ---------------------------------------------------------------------------
// bindv6only (ROADMAP M9 (h)) — real probe + pure classification
// ---------------------------------------------------------------------------

/// Whether `addr` is the IPv6 wildcard (`[::]:port`) — the one shape
/// [`probe_bindv6only`] is even worth running against; `dual_stack_v6=false`
/// binds fine at any other address, wildcard or not, with no IPv4-blocking
/// consequence (`crate::doctor::BINDV6ONLY_BLOCKS_IPV4`'s own doc).
pub fn is_ipv6_wildcard(addr: SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(v6) if v6.ip().is_unspecified())
}

/// Bind a throwaway UDP socket at `addr`'s IP but an **ephemeral port**
/// (`SocketAddr::new(addr.ip(), 0)`, same wildcard IP as the configured
/// listen address) via `qsh_transport::bind_tuned_udp_socket(_, false)` —
/// `dual_stack_v6=false`, `crates/qsh-transport/src/endpoint.rs` — and
/// read back whether the OS defaulted it to `IPV6_V6ONLY`. `IPV6_V6ONLY`'s
/// default is a per-socket/system default (Linux `net.ipv6.bindv6only`,
/// BSD/macOS `net.inet6.ip6.v6only`, Windows fixed to 1), never
/// port-specific, so an ephemeral-port bind answers exactly the same
/// question a bind of the configured port would — without colliding with,
/// or racing, a real listener already bound there (`qsh serve`/`qsh
/// listen` running on this machine binds the configured port for the
/// whole time doctor is probing it, which would otherwise turn every
/// `Err` here into a false "could not tell"). A real socket, real OS
/// default — this is the one probe in this module that is not a
/// synthetic classifier input, because "what does this OS default a fresh
/// dual-stack bind to" has no portable answer any other way.
///
/// `Err` (bind failure — no permission, unsupported family) means "could
/// not tell", not "blocked"; [`crate::ops::Ops::doctor`]'s own caller
/// treats that the same as "no finding" rather than guessing.
pub fn probe_bindv6only(addr: SocketAddr) -> io::Result<bool> {
    let ephemeral = SocketAddr::new(addr.ip(), 0);
    let std_socket = qsh_transport::bind_tuned_udp_socket(ephemeral, false)?;
    let socket: socket2::Socket = std_socket.into();
    socket.only_v6()
}

/// Turn an already-observed [`probe_bindv6only`] result into at most one
/// [`DoctorFinding`] — pure over `only_v6`, so the classification itself
/// (fire iff the OS actually defaulted to v6-only) is unit-testable with a
/// synthetic bool, no real socket, the same "detect vs. classify" split
/// [`classify_connectivity`] already establishes in this module.
pub fn bindv6only_finding(bind_display: &str, only_v6: bool) -> Option<DoctorFinding> {
    if !only_v6 {
        return None;
    }
    let diag = &super::BINDV6ONLY_BLOCKS_IPV4;
    Some(DoctorFinding {
        code: diag.code.to_string(),
        status: "warn".to_string(),
        detail: format!("{} (bind: {bind_display})", diag.message),
        remedy: Some(diag.remedy.to_string()),
    })
}

// ---------------------------------------------------------------------------
// Service registration (ROADMAP M9 (h)): unit-file existence,
// platform-gated. Every function below takes its root directory
// (`$HOME`, the systemd linger marker directory) as a parameter rather
// than reading the environment itself — the same "detection reads real
// state, classification/path-building stays a pure function of its
// inputs" split this module's other probes use, and the seam
// `crate::ops::doctor::DoctorEnvironment` injects a fake root through for
// hermetic tests: real unit registration and real linger state cannot be
// simulated any other way.
// ---------------------------------------------------------------------------

/// `~/Library/LaunchAgents/io.qsh.<mode>.plist` — the path `qsh service
/// install` (ROADMAP M9 (g)) will write and [`service_unit_registered`] reads,
/// on macOS.
#[cfg(target_os = "macos")]
pub fn macos_launchagent_path(home: &Path, mode: &str) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("io.qsh.{mode}.plist"))
}

/// `~/.config/systemd/user/qsh-<mode>.service` — the Linux twin of
/// [`macos_launchagent_path`].
#[cfg(target_os = "linux")]
pub fn linux_systemd_user_unit_path(home: &Path, mode: &str) -> PathBuf {
    home.join(".config")
        .join("systemd")
        .join("user")
        .join(format!("qsh-{mode}.service"))
}

/// Whether this platform's service unit for `mode` is registered —
/// `Some(true)`/`Some(false)` on macOS/Linux (existence of the path
/// `macos_launchagent_path`/`linux_systemd_user_unit_path` names),
/// `None` everywhere else (Windows included) — `docs/CLI.md` §6.17: `qsh
/// service install` is `UNSUPPORTED`/P1 off macOS/Linux, so there is
/// nothing to report there. `home` is `None` when
/// the caller could not resolve one (`crate::config::home_dir()`
/// returning `None` in the real environment) — also `None`, since no
/// unit path could even be built.
pub fn service_unit_registered(home: Option<&Path>, mode: &str) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        let home = home?;
        Some(macos_launchagent_path(home, mode).exists())
    }
    #[cfg(target_os = "linux")]
    {
        let home = home?;
        Some(linux_systemd_user_unit_path(home, mode).exists())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (home, mode);
        None
    }
}

/// `service_not_registered`'s finding, pure over an already-observed
/// [`service_unit_registered`] result — `None` when a unit is registered
/// (or this platform never reports at all, which [`service_unit_registered`]'s
/// `None` already signals to its own caller directly).
pub fn service_not_registered_finding(mode: &str) -> DoctorFinding {
    let diag = &super::SERVICE_NOT_REGISTERED;
    DoctorFinding {
        code: diag.code.to_string(),
        status: "info".to_string(),
        detail: format!("{} (inferred mode: {mode})", diag.message),
        remedy: Some(diag.remedy.to_string()),
    }
}

/// `launchagent_session_scoped`'s finding — unconditional once the
/// LaunchAgent is registered (`crate::doctor::LAUNCHAGENT_SESSION_SCOPED`'s
/// own doc: a structural fact, not a misconfiguration).
pub fn launchagent_session_scoped_finding(mode: &str) -> DoctorFinding {
    let diag = &super::LAUNCHAGENT_SESSION_SCOPED;
    DoctorFinding {
        code: diag.code.to_string(),
        status: "warn".to_string(),
        detail: format!("{} (mode: {mode})", diag.message),
        remedy: Some(diag.remedy.to_string()),
    }
}

/// The outcome of probing `/var/lib/systemd/linger/$USER` for
/// [`super::SYSTEMD_LINGER_DISABLED`]. Three states, not two — `Unknown` for an
/// unreadable probe (a sandboxed CI account) is
/// deliberately not folded into `Disabled`: a probe this process cannot
/// even perform is not evidence that linger is off, only that this
/// process cannot tell, and reporting a finding on that non-evidence
/// would be a false positive `crate::doctor::SYSTEMD_LINGER_DISABLED`'s
/// own doc explicitly declines to risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LingerProbe {
    /// The marker file exists — linger is enabled for this account.
    Enabled,
    /// The marker file's absence was confirmed (not merely unreadable).
    Disabled,
    /// Could not tell (e.g. `linger_dir` itself is unreadable in a
    /// sandbox) — no finding either way.
    Unknown,
}

/// Probe `<linger_dir>/<username>` for existence — systemd's own linger
/// marker, no subprocess (`crate::doctor::SYSTEMD_LINGER_DISABLED`'s own
/// doc: "matches the repo's no-`Command::new` bias"). `linger_dir` is a
/// parameter (production: `/var/lib/systemd/linger`) rather than a
/// literal here so a test can point it at a tempdir instead.
pub fn probe_systemd_linger(linger_dir: &Path, username: &str) -> LingerProbe {
    match linger_dir.join(username).try_exists() {
        Ok(true) => LingerProbe::Enabled,
        Ok(false) => LingerProbe::Disabled,
        Err(_) => LingerProbe::Unknown,
    }
}

/// `systemd_linger_disabled`'s finding, pure over an already-observed
/// [`LingerProbe`] — `None` for `Enabled`/`Unknown`, matching
/// [`LingerProbe::Unknown`]'s own "no finding either way" doc.
pub fn linger_finding(probe: LingerProbe, mode: &str) -> Option<DoctorFinding> {
    if probe != LingerProbe::Disabled {
        return None;
    }
    let diag = &super::SYSTEMD_LINGER_DISABLED;
    Some(DoctorFinding {
        code: diag.code.to_string(),
        status: "warn".to_string(),
        detail: format!("{} (mode: {mode})", diag.message),
        remedy: Some(diag.remedy.to_string()),
    })
}

#[cfg(test)]
mod tests;
