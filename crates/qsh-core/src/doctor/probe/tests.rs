use super::*;

// -----------------------------------------------------------------
// Raw UDP probe — real sockets, `udp_egress_blocked`'s trigger (a
// cooperative local black-hole: bound, but never read from/responded
// to) plus the happy path. `no_route`'s real-socket trigger is OS/CI
// dependent (`docs/CLI.md` §6.17's connectivity-diagnostic precedence
// rule) so it stays `#[ignore]`; `classify_connectivity`
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
/// so `#[ignore]` per `docs/CLI.md` §6.17's precedence rule — `classify_connectivity`'s
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
        classify_connectivity(UdpProbeOutcome::TimedOut, false, "h", "203.0.113.1:4433").unwrap();
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

/// Precedence, asserted directly (`docs/CLI.md` §6.17): never two codes for one
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

// -----------------------------------------------------------------
// bindv6only — is_ipv6_wildcard + classify pure, synthetic bools;
// one real-socket smoke test, `#[ignore]`d the way
// `probe_reports_unreachable_when_nothing_listens_on_the_port` is
// (CI runners may already disable v6only, or may run in an
// IPv6-less sandbox that cannot bind `[::]` at all).
// -----------------------------------------------------------------

#[test]
fn is_ipv6_wildcard_true_only_for_the_v6_unspecified_address() {
    assert!(is_ipv6_wildcard("[::]:4433".parse().unwrap()));
    assert!(!is_ipv6_wildcard("[::1]:4433".parse().unwrap()));
    assert!(!is_ipv6_wildcard("0.0.0.0:4433".parse().unwrap()));
    assert!(!is_ipv6_wildcard("127.0.0.1:4433".parse().unwrap()));
}

#[test]
fn bindv6only_finding_fires_only_when_the_probe_observed_v6_only() {
    assert!(bindv6only_finding("[::]:4433", false).is_none());
    let finding = bindv6only_finding("[::]:4433", true).expect("bindv6only_blocks_ipv4");
    assert_eq!(finding.code, "bindv6only_blocks_ipv4");
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("[::]:4433"), "{finding:?}");
    assert!(finding.remedy.is_some());
}

/// OS/sandbox dependent (a CI runner may already disable v6only
/// system-wide, or lack IPv6 entirely) — `#[ignore]` per the same
/// discipline `probe_reports_unreachable_when_nothing_listens_on_the_port`
/// already uses in this file; `bindv6only_finding`'s unit tests above
/// cover the classification logic deterministically. This only
/// confirms `probe_bindv6only` itself does not panic and returns a
/// bool for a real ephemeral-port wildcard bind.
#[test]
#[ignore = "this OS/sandbox's IPV6_V6ONLY default for a fresh dual-stack bind is environment dependent"]
fn probe_bindv6only_reports_a_bool_for_a_real_ephemeral_bind() {
    let addr: SocketAddr = "[::]:0".parse().unwrap();
    let only_v6 = probe_bindv6only(addr).expect("a throwaway ephemeral v6 bind should work");
    // No assertion on the value itself — this is a smoke test that
    // the real probe path runs to completion on this machine.
    let _ = only_v6;
}

/// Not OS/sandbox dependent, unlike the smoke test above — proves the
/// actual bug this change fixes: with `qsh serve`/`qsh listen` already
/// bound to the configured port, the old probe (bind the configured
/// address verbatim) collided with it (`EADDRINUSE`), and
/// `Ops::doctor_bindv6only_finding`'s `.ok()?` turned that collision into
/// a silent "no finding" — the diagnostic could never fire on exactly
/// the machine it is about. Binds `[::1]:0` to claim a real, currently
/// in-use port `P`, then calls `probe_bindv6only` on the wildcard IP at
/// that same port (`[::]:P`) and asserts it succeeds — proving the
/// probe never actually binds `P` itself, only an ephemeral one. Skips
/// (does not fail) when this sandbox has no IPv6 loopback at all, the
/// same "could not tell, not a failure" stance this module's other
/// probes take toward an unreadable environment.
#[test]
fn probe_bindv6only_does_not_bind_the_caller_supplied_port() {
    let holder = match UdpSocket::bind("[::1]:0") {
        Ok(socket) => socket,
        Err(_) => return, // no IPv6 loopback in this sandbox
    };
    let port = holder.local_addr().unwrap().port();
    let wildcard_same_port: SocketAddr = format!("[::]:{port}").parse().unwrap();
    let result = probe_bindv6only(wildcard_same_port);
    assert!(
        result.is_ok(),
        "probe_bindv6only should bind an ephemeral port, not the caller-supplied {port}: {result:?}"
    );
    drop(holder);
}

// -----------------------------------------------------------------
// service_unit_registered / service_not_registered_finding — pure
// over an injected `home`, no real `$HOME`.
// -----------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn service_unit_registered_reads_the_launchagent_plist_on_macos() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    assert_eq!(service_unit_registered(Some(home), "serve"), Some(false));

    let plist_dir = home.join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&plist_dir).unwrap();
    std::fs::write(plist_dir.join("io.qsh.serve.plist"), b"<plist/>").unwrap();
    assert_eq!(service_unit_registered(Some(home), "serve"), Some(true));
    // A different mode's unit does not count.
    assert_eq!(service_unit_registered(Some(home), "listen"), Some(false));
}

#[cfg(target_os = "linux")]
#[test]
fn service_unit_registered_reads_the_systemd_user_unit_on_linux() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    assert_eq!(service_unit_registered(Some(home), "serve"), Some(false));

    let unit_dir = home.join(".config").join("systemd").join("user");
    std::fs::create_dir_all(&unit_dir).unwrap();
    std::fs::write(unit_dir.join("qsh-serve.service"), b"[Unit]").unwrap();
    assert_eq!(service_unit_registered(Some(home), "serve"), Some(true));
    assert_eq!(service_unit_registered(Some(home), "listen"), Some(false));
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn service_unit_registered_is_none_off_macos_and_linux() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(service_unit_registered(Some(dir.path()), "serve"), None);
    assert_eq!(service_unit_registered(None, "serve"), None);
}

#[test]
fn service_not_registered_finding_names_the_inferred_mode() {
    let finding = service_not_registered_finding("listen");
    assert_eq!(finding.code, "service_not_registered");
    assert_eq!(finding.status, "info");
    assert!(finding.detail.contains("listen"), "{finding:?}");
}

#[test]
fn launchagent_session_scoped_finding_names_the_inferred_mode() {
    let finding = launchagent_session_scoped_finding("serve");
    assert_eq!(finding.code, "launchagent_session_scoped");
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("serve"), "{finding:?}");
}

// -----------------------------------------------------------------
// systemd linger — Linux only, injected `linger_dir`/`username`.
// -----------------------------------------------------------------

#[test]
fn probe_systemd_linger_reads_the_marker_file() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        probe_systemd_linger(dir.path(), "dave"),
        LingerProbe::Disabled
    );
    std::fs::write(dir.path().join("dave"), b"").unwrap();
    assert_eq!(
        probe_systemd_linger(dir.path(), "dave"),
        LingerProbe::Enabled
    );
    // A different account's marker does not count.
    assert_eq!(
        probe_systemd_linger(dir.path(), "carol"),
        LingerProbe::Disabled
    );
}

#[test]
fn probe_systemd_linger_is_unknown_when_the_root_is_unreadable() {
    // A path under a nonexistent multi-level parent: `try_exists`
    // surfaces this as `Ok(false)` on most platforms (ENOENT on an
    // ancestor is not itself an error for `try_exists`), so this
    // pins the *other* half of the contract instead — `Unknown` is
    // reachable at all as a distinct variant from `Disabled`, via a
    // permission-denied ancestor.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let probe = probe_systemd_linger(&locked, "dave");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(probe, LingerProbe::Unknown, "{probe:?}");
    }
}

#[test]
fn linger_finding_fires_only_when_disabled() {
    assert!(linger_finding(LingerProbe::Enabled, "serve").is_none());
    assert!(linger_finding(LingerProbe::Unknown, "serve").is_none());
    let finding = linger_finding(LingerProbe::Disabled, "serve").expect("systemd_linger_disabled");
    assert_eq!(finding.code, "systemd_linger_disabled");
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("serve"), "{finding:?}");
}

// -----------------------------------------------------------------
// Version-negotiation probe: sans-IO build/parse (issue #7)
// -----------------------------------------------------------------

const TEST_DCID: [u8; PROBE_CID_LEN] = [1, 2, 3, 4, 5, 6, 7, 8];
const TEST_SCID: [u8; PROBE_CID_LEN] = [9, 10, 11, 12, 13, 14, 15, 16];

fn version_negotiation_reply(dcid_echo: &[u8], scid_echo: &[u8], versions: &[u32]) -> Vec<u8> {
    let mut reply = vec![0xc5];
    reply.extend_from_slice(&0u32.to_be_bytes());
    reply.push(dcid_echo.len() as u8);
    reply.extend_from_slice(dcid_echo);
    reply.push(scid_echo.len() as u8);
    reply.extend_from_slice(scid_echo);
    for v in versions {
        reply.extend_from_slice(&v.to_be_bytes());
    }
    reply
}

#[test]
fn version_negotiation_probe_is_a_padded_long_header_with_a_reserved_version() {
    let probe = build_version_negotiation_probe(&TEST_DCID, &TEST_SCID);
    assert_eq!(probe.len(), PROBE_DATAGRAM_LEN);
    assert!(probe[0] & 0x80 != 0, "long header bit");
    let version = u32::from_be_bytes(probe[1..5].try_into().unwrap());
    assert_eq!(version, PROBE_UNSUPPORTED_VERSION);
    assert_eq!(
        version & 0x0f0f_0f0f,
        0x0a0a_0a0a,
        "reserved 0x?a?a?a?a form"
    );
    assert_eq!(probe[5] as usize, PROBE_CID_LEN);
    assert_eq!(&probe[6..14], &TEST_DCID);
    assert_eq!(probe[14] as usize, PROBE_CID_LEN);
    assert_eq!(&probe[15..23], &TEST_SCID);
    assert!(probe[23..].iter().all(|b| *b == 0));
}

#[test]
fn version_negotiation_reply_parser_accepts_an_echoing_reply() {
    // A real server echoes our SCID as its DCID and our DCID as its SCID.
    let reply = version_negotiation_reply(&TEST_SCID, &TEST_DCID, &[0x0a1a_2a3a, 1]);
    assert!(is_version_negotiation_reply(&reply, &TEST_SCID));
}

#[test]
fn version_negotiation_reply_parser_rejects_everything_else() {
    let good = version_negotiation_reply(&TEST_SCID, &TEST_DCID, &[1]);
    let wrong = version_negotiation_reply(&TEST_DCID, &TEST_SCID, &[1]);
    assert!(!is_version_negotiation_reply(&wrong, &TEST_SCID));
    let mut nonzero = good.clone();
    nonzero[4] = 1;
    assert!(!is_version_negotiation_reply(&nonzero, &TEST_SCID));
    let mut short = good.clone();
    short[0] &= 0x7f;
    assert!(!is_version_negotiation_reply(&short, &TEST_SCID));
    assert!(!is_version_negotiation_reply(
        &version_negotiation_reply(&TEST_SCID, &TEST_DCID, &[]),
        &TEST_SCID
    ));
    assert!(!is_version_negotiation_reply(
        &good[..good.len() - 1],
        &TEST_SCID
    ));
    assert!(!is_version_negotiation_reply(&good[..10], &TEST_SCID));
    assert!(!is_version_negotiation_reply(&[], &TEST_SCID));
    assert!(!is_version_negotiation_reply(
        &build_version_negotiation_probe(&TEST_DCID, &TEST_SCID),
        &TEST_SCID
    ));
}

/// The #7 regression at the probe level: a live quinn endpoint (the same
/// `Listener` `qsh serve` binds) answers the probe with a real Version
/// Negotiation packet, and `probe_udp_egress` reports `Responded`.
#[tokio::test]
async fn probe_gets_a_version_negotiation_reply_from_a_live_quinn_listener() {
    let (identity, _fp) = crate::tunnel::testutil::self_signed();
    let listener = qsh_transport::Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        identity,
        std::sync::Arc::new(qsh_transport::StaticTrust::empty()),
    )
    .unwrap();
    let addr = listener.local_addr().unwrap();

    // Raw exchange: the reply must parse as a VN packet echoing our CIDs.
    let raw = tokio::task::spawn_blocking(move || {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        socket.connect(addr).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .send(&build_version_negotiation_probe(&TEST_DCID, &TEST_SCID))
            .unwrap();
        let mut buf = [0u8; 512];
        let n = socket.recv(&mut buf).expect("VN reply from the listener");
        is_version_negotiation_reply(&buf[..n], &TEST_SCID)
    })
    .await
    .unwrap();
    assert!(raw, "the listener's reply is a Version Negotiation packet");

    let outcome =
        tokio::task::spawn_blocking(move || probe_udp_egress(addr, Duration::from_secs(5)))
            .await
            .unwrap();
    assert_eq!(outcome, UdpProbeOutcome::Responded);
    drop(listener);
}
