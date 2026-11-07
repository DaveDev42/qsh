//! `netsim` (ADR-0054 decision 22, `docs/design/testing.md` L4): the virtual
//! network, its RFC 4787 NAT boxes, and real quinn on top of both.
//!
//! Every test runs on tokio's paused clock, so "25 ms" and "30 s" are exact
//! and cost no wall time, and nothing here touches an OS socket, so the
//! results are the same on Linux, macOS and Windows. A failing assertion
//! names the row, and the seed is the fixed `SEED` below.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use qsh_testkit::netsim::quic::{self, SERVER_NAME};
use qsh_testkit::netsim::{
    DropReason, Filtering, Mapping, NatConfig, NatKind, Net, NetConfig, NetSocket, PathConfig,
    PortAssignment, Site,
};
use tokio::time::{Instant, advance, timeout};

const SEED: u64 = 0x5eed_0001;
const OWD: Duration = Duration::from_millis(25);

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn net() -> Net {
    Net::new(NetConfig {
        seed: SEED,
        ..NetConfig::default()
    })
}

/// The next datagram within 200 ms of virtual time, or `None`.
async fn arrives(sock: &NetSocket) -> Option<(SocketAddr, Vec<u8>)> {
    timeout(Duration::from_millis(200), sock.recv_from())
        .await
        .ok()
}

/// A public server site with two ports on one IP and a third on another IP,
/// the probes every NAT row uses.
struct Probes {
    x1: NetSocket,
    x2: NetSocket,
    x3: NetSocket,
    _sites: [Site; 2],
}

impl Probes {
    fn new(net: &Net) -> Self {
        let a = net.internet().site(NatKind::None, "x-a", ip("203.0.113.1"));
        let b = net.internet().site(NatKind::None, "x-b", ip("203.0.113.2"));
        Self {
            x1: a.bind(7000).unwrap(),
            x2: a.bind(7001).unwrap(),
            x3: b.bind(7000).unwrap(),
            _sites: [a, b],
        }
    }
}

fn nat_site(net: &Net, cfg: NatConfig) -> Site {
    net.internet().add_nat("box", cfg, ip("198.51.100.7"))
}

fn cfg(mapping: Mapping, filtering: Filtering, ports: PortAssignment) -> NatConfig {
    NatConfig {
        mapping,
        filtering,
        ports,
        hairpin: false,
        timeout: Duration::from_secs(30),
    }
}

// ---------------------------------------------------------------------------
// The network itself.
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn netsim_delivers_after_exactly_the_path_delay() {
    let net = net();
    let a = net.internet().site(NatKind::None, "a", ip("203.0.113.1"));
    let b = net.internet().site(NatKind::None, "b", ip("203.0.113.2"));
    let sa_ = a.bind(1000).unwrap();
    let sb = b.bind(2000).unwrap();
    let t0 = Instant::now();
    sa_.send_to(sb.local(), b"x");
    let (from, data) = sb.recv_from().await;
    assert_eq!(t0.elapsed(), OWD, "seed {SEED:#x}");
    assert_eq!((from, data.as_slice()), (sa_.local(), &b"x"[..]));

    // A per-pair override beats the default, in both directions.
    net.set_path(
        ip("203.0.113.1"),
        ip("203.0.113.2"),
        PathConfig::delay(Duration::from_millis(80)),
    );
    let t1 = Instant::now();
    sb.send_to(sa_.local(), b"y");
    sa_.recv_from().await;
    assert_eq!(t1.elapsed(), Duration::from_millis(80));
}

#[tokio::test(start_paused = true)]
async fn netsim_lan_hosts_behind_one_box_use_the_lan_path() {
    let net = net();
    let home = nat_site(&net, NatConfig::port_restricted());
    let other = home.add_host().unwrap();
    assert_ne!(home.ip(), other.ip());
    let a = home.bind(5000).unwrap();
    let b = other.bind(5000).unwrap();
    let t0 = Instant::now();
    a.send_to(b.local(), b"lan");
    let (from, _) = b.recv_from().await;
    assert_eq!(from, a.local(), "a LAN hop is not translated");
    assert_eq!(t0.elapsed(), Duration::from_millis(1));
}

#[tokio::test(start_paused = true)]
async fn netsim_loss_is_seeded() {
    async fn received(seed: u64) -> usize {
        let net = Net::new(NetConfig {
            seed,
            default_path: PathConfig::delay(OWD).with_loss(0.2),
            ..NetConfig::default()
        });
        let a = net.internet().site(NatKind::None, "a", ip("203.0.113.1"));
        let b = net.internet().site(NatKind::None, "b", ip("203.0.113.2"));
        let (sa_, sb) = (a.bind(1000).unwrap(), b.bind(2000).unwrap());
        for _ in 0..2000 {
            sa_.send_to(sb.local(), b"p");
        }
        advance(Duration::from_secs(1)).await;
        let mut n = 0;
        while sb.try_recv_from().is_some() {
            n += 1;
        }
        let dropped = net.stats().dropped(DropReason::Loss) as usize;
        assert_eq!(n + dropped, 2000, "every packet is delivered or counted");
        n
    }
    let first = received(7).await;
    assert!(
        (1500..=1700).contains(&first),
        "20% loss kept {first} of 2000"
    );
    assert_eq!(received(7).await, first, "same seed, same losses");
    assert_ne!(received(8).await, first, "another seed, other losses");
}

#[tokio::test(start_paused = true)]
async fn netsim_jitter_stays_inside_its_bound() {
    let net = Net::new(NetConfig {
        seed: SEED,
        default_path: PathConfig::delay(OWD).with_jitter(Duration::from_millis(10)),
        ..NetConfig::default()
    });
    let a = net.internet().site(NatKind::None, "a", ip("203.0.113.1"));
    let b = net.internet().site(NatKind::None, "b", ip("203.0.113.2"));
    let (sa_, sb) = (a.bind(1000).unwrap(), b.bind(2000).unwrap());
    for _ in 0..50 {
        let t0 = Instant::now();
        sa_.send_to(sb.local(), b"j");
        sb.recv_from().await;
        let dt = t0.elapsed();
        // tokio's timer rounds up to whole milliseconds.
        assert!(dt >= OWD && dt <= OWD + Duration::from_millis(10), "{dt:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn netsim_socket_lifecycle_and_drop_accounting() {
    let net = net();
    let site = net.internet().site(NatKind::None, "a", ip("203.0.113.1"));
    let s = site.bind(1000).unwrap();
    assert_eq!(
        site.bind(1000).unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse
    );
    let e1 = site.bind(0).unwrap();
    let e2 = site.bind(0).unwrap();
    assert!(e1.local().port() >= 49152 && e1.local().port() != e2.local().port());
    drop(s);
    let again = site.bind(1000).unwrap();

    let other = net.internet().site(NatKind::None, "b", ip("203.0.113.2"));
    let o = other.bind(2000).unwrap();
    o.send_to(sa("203.0.113.1:9"), b"x"); // host exists, port closed
    o.send_to(sa("203.0.113.99:9"), b"x"); // nobody owns the address
    o.send_to(sa("203.0.113.1:1000"), &[0u8; 1500]); // over the MTU
    o.send_to(again.local(), b"ok");
    again.recv_from().await;
    advance(Duration::from_secs(1)).await;
    let st = net.stats();
    assert_eq!(st.sent, 4);
    assert_eq!(st.delivered, 1);
    assert_eq!(st.dropped(DropReason::NoSocket), 1);
    assert_eq!(st.dropped(DropReason::NoRoute), 1);
    assert_eq!(st.dropped(DropReason::Mtu), 1);
}

// ---------------------------------------------------------------------------
// NAT boxes, one RFC 4787 behaviour per row.
// ---------------------------------------------------------------------------

/// RFC 4787 section 4.1: what the outside sees of one inside socket as it
/// talks to three destinations (same IP and port; same IP, other port; other
/// IP).
#[tokio::test(start_paused = true)]
async fn netsim_nat_mapping_follows_rfc4787() {
    // (row, mapping, same port to x2?, same port to x3?)
    let rows = [
        ("EIM", Mapping::EndpointIndependent, true, true),
        ("ADM", Mapping::AddressDependent, true, false),
        ("APDM", Mapping::AddressAndPortDependent, false, false),
    ];
    for (row, mapping, same_x2, same_x3) in rows {
        let net = net();
        let probes = Probes::new(&net);
        let site = nat_site(
            &net,
            cfg(
                mapping,
                Filtering::EndpointIndependent,
                // Sequential, so a new mapping is visible as a new port (a
                // preserving box reuses the inside port for every mapping).
                PortAssignment::Sequential,
            ),
        );
        let inside = site.bind(5000).unwrap();
        for x in [&probes.x1, &probes.x2, &probes.x3] {
            inside.send_to(x.local(), b"m");
        }
        let e1 = arrives(&probes.x1).await.expect(row).0;
        let e2 = arrives(&probes.x2).await.expect(row).0;
        let e3 = arrives(&probes.x3).await.expect(row).0;
        for e in [e1, e2, e3] {
            assert_eq!(e.ip(), site.external_ip(), "{row}: source is the box");
        }
        assert_eq!(e1 == e2, same_x2, "{row}: same IP, other port");
        assert_eq!(e1 == e3, same_x3, "{row}: other IP");
        assert_eq!(
            site.nat().unwrap().mappings().len(),
            if same_x2 && same_x3 {
                1
            } else if same_x2 {
                2
            } else {
                3
            }
        );
    }
}

/// RFC 4787 section 4.2.1: how the external port is chosen.
#[tokio::test(start_paused = true)]
async fn netsim_nat_port_assignment_follows_rfc4787() {
    let net = net();
    let probes = Probes::new(&net);

    // Preserve: the inside port, but a second host with the same port gets
    // another one rather than hijacking the first mapping.
    let site = nat_site(&net, NatConfig::port_restricted());
    let h2 = site.add_host().unwrap();
    let (a, b) = (site.bind(5000).unwrap(), h2.bind(5000).unwrap());
    a.send_to(probes.x1.local(), b"1");
    b.send_to(probes.x1.local(), b"2");
    let pa = arrives(&probes.x1).await.unwrap().0.port();
    let pb = arrives(&probes.x1).await.unwrap().0.port();
    assert_eq!(pa, 5000, "Preserve");
    assert_ne!(pb, 5000, "Preserve falls back when the port is taken");

    // Sequential: a counter, one new port per mapping.
    let seq = net.internet().add_nat(
        "seq",
        NatConfig::port_restricted().with_ports(PortAssignment::Sequential),
        ip("198.51.100.8"),
    );
    let s = seq.bind(5000).unwrap();
    let mut seen = Vec::new();
    for x in [&probes.x1, &probes.x3] {
        // EIM: one mapping, so one port...
        s.send_to(x.local(), b"s");
        seen.push(arrives(x).await.unwrap().0.port());
    }
    assert_eq!(seen[0], seen[1], "EIM reuses the mapping");
    assert_eq!(seen[0], 10_000, "Sequential starts at 10000");
    let s2 = seq.add_host().unwrap().bind(5000).unwrap();
    s2.send_to(probes.x1.local(), b"s");
    assert_eq!(arrives(&probes.x1).await.unwrap().0.port(), 10_001);

    // Random: differs from the inside port, repeats with the seed.
    async fn random_ports(seed: u64) -> Vec<u16> {
        let net = Net::new(NetConfig {
            seed,
            ..NetConfig::default()
        });
        let probes = Probes::new(&net);
        let sym = net
            .internet()
            .add_nat("sym", NatConfig::symmetric(), ip("198.51.100.9"));
        let s = sym.bind(5000).unwrap();
        let mut ports = Vec::new();
        for x in [&probes.x1, &probes.x2, &probes.x3] {
            s.send_to(x.local(), b"r");
            ports.push(arrives(x).await.unwrap().0.port());
        }
        ports
    }
    let first = random_ports(SEED).await;
    assert!(first.iter().all(|p| *p >= 1024));
    assert!(
        first.iter().all(|p| *p != 5000),
        "Random does not preserve: {first:?}"
    );
    assert_eq!(random_ports(SEED).await, first, "same seed, same ports");
    assert_ne!(random_ports(SEED + 1).await, first);
}

/// RFC 4787 section 5: who may send to a mapping. Rows are the three
/// filters; the senders are the contacted endpoint, the same IP on another
/// port, and another IP.
#[tokio::test(start_paused = true)]
async fn netsim_nat_filtering_follows_rfc4787() {
    // (row, filter, x1 passes, x2 passes, x3 passes)
    let rows = [
        ("EIF", Filtering::EndpointIndependent, true, true, true),
        ("ADF", Filtering::AddressDependent, true, true, false),
        (
            "APDF",
            Filtering::AddressAndPortDependent,
            true,
            false,
            false,
        ),
    ];
    for (row, filtering, p1, p2, p3) in rows {
        let net = net();
        let probes = Probes::new(&net);
        let site = nat_site(
            &net,
            cfg(
                Mapping::EndpointIndependent,
                filtering,
                PortAssignment::Preserve,
            ),
        );
        let inside = site.bind(5000).unwrap();
        let ext = SocketAddr::new(site.external_ip(), 5000);

        // Without a mapping nothing gets in, whatever the filter.
        probes.x1.send_to(ext, b"early");
        assert!(arrives(&inside).await.is_none(), "{row}: no mapping yet");
        assert_eq!(net.stats().dropped(DropReason::NoMapping), 1, "{row}");

        inside.send_to(probes.x1.local(), b"open");
        arrives(&probes.x1).await.expect(row);
        for (who, sock, passes) in [
            ("x1", &probes.x1, p1),
            ("x2", &probes.x2, p2),
            ("x3", &probes.x3, p3),
        ] {
            sock.send_to(ext, who.as_bytes());
            let got = arrives(&inside).await;
            assert_eq!(got.is_some(), passes, "{row}: from {who}");
            if let Some((from, data)) = got {
                assert_eq!(
                    (from, data.as_slice()),
                    (sock.local(), who.as_bytes()),
                    "{row}"
                );
            }
        }
        assert_eq!(
            net.stats().dropped(DropReason::Filtered),
            [p1, p2, p3].iter().filter(|p| !**p).count() as u64,
            "{row}"
        );
    }
}

/// RFC 4787 REQ-5/REQ-6: a mapping lives 30 s past the last *outbound*
/// packet; inbound traffic does not extend it.
#[tokio::test(start_paused = true)]
async fn netsim_nat_mapping_times_out_from_the_last_outbound_packet() {
    let net = net();
    let probes = Probes::new(&net);
    let site = nat_site(&net, NatConfig::full_cone());
    let inside = site.bind(5000).unwrap();
    let ext = SocketAddr::new(site.external_ip(), 5000);

    inside.send_to(probes.x1.local(), b"t0");
    arrives(&probes.x1).await.unwrap();
    advance(Duration::from_secs(28)).await;
    probes.x3.send_to(ext, b"29s");
    assert!(
        arrives(&inside).await.is_some(),
        "alive just before the timeout"
    );
    advance(Duration::from_secs(3)).await;
    probes.x3.send_to(ext, b"31s");
    assert!(
        arrives(&inside).await.is_none(),
        "inbound did not refresh it"
    );
    assert!(site.nat().unwrap().mappings().is_empty());

    // Outbound traffic refreshes it.
    inside.send_to(probes.x1.local(), b"again");
    arrives(&probes.x1).await.unwrap();
    advance(Duration::from_secs(20)).await;
    inside.send_to(probes.x1.local(), b"keep-alive");
    arrives(&probes.x1).await.unwrap();
    advance(Duration::from_secs(20)).await;
    probes
        .x3
        .send_to(ext, b"40s after the first, 20s after the refresh");
    assert!(arrives(&inside).await.is_some(), "refreshed by outbound");

    // The filter permission lapses on its own clock: ADF/APDF forget the
    // peer 30 s after the last send to it, even while the mapping lives.
    let restricted = net
        .internet()
        .add_nat("r", NatConfig::restricted(), ip("198.51.100.20"));
    let r_in = restricted.bind(5000).unwrap();
    let r_ext = SocketAddr::new(restricted.external_ip(), 5000);
    r_in.send_to(probes.x1.local(), b"open");
    arrives(&probes.x1).await.unwrap();
    advance(Duration::from_secs(10)).await;
    r_in.send_to(probes.x3.local(), b"keep the mapping");
    arrives(&probes.x3).await.unwrap();
    advance(Duration::from_secs(25)).await;
    probes.x1.send_to(r_ext, b"stale permission");
    assert!(
        arrives(&r_in).await.is_none(),
        "x1's permission is 35 s old"
    );
    probes.x3.send_to(r_ext, b"fresh permission");
    assert!(
        arrives(&r_in).await.is_some(),
        "x3's permission is 25 s old"
    );
}

/// RFC 4787 section 6: hairpinning.
#[tokio::test(start_paused = true)]
async fn netsim_nat_hairpin_follows_rfc4787() {
    for hairpin in [false, true] {
        let net = net();
        let probes = Probes::new(&net);
        let site = nat_site(&net, NatConfig::full_cone().with_hairpin(hairpin));
        let other = site.add_host().unwrap();
        let (h1, h2) = (site.bind(5000).unwrap(), other.bind(6000).unwrap());
        h1.send_to(probes.x1.local(), b"1");
        let e1 = arrives(&probes.x1).await.unwrap().0;
        h2.send_to(probes.x1.local(), b"2");
        let e2 = arrives(&probes.x1).await.unwrap().0;

        h1.send_to(e2, b"via the box");
        let got = arrives(&h2).await;
        if hairpin {
            let (from, data) = got.expect("hairpin on");
            assert_eq!(
                from, e1,
                "the source is h1's external endpoint, not its inside one"
            );
            assert_eq!(data, b"via the box");
        } else {
            assert!(got.is_none(), "hairpin off");
            assert_eq!(net.stats().dropped(DropReason::HairpinDisabled), 1);
        }
    }
}

/// Two inside hosts that both sent to each other's external endpoint pass a
/// port-restricted hairpin: what a same-NAT punch relies on.
#[tokio::test(start_paused = true)]
async fn netsim_nat_hairpin_passes_a_port_restricted_filter_once_both_sides_sent() {
    let net = net();
    let probes = Probes::new(&net);
    let site = nat_site(&net, NatConfig::port_restricted().with_hairpin(true));
    let other = site.add_host().unwrap();
    let (h1, h2) = (site.bind(5000).unwrap(), other.bind(6000).unwrap());
    h1.send_to(probes.x1.local(), b"1");
    let e1 = arrives(&probes.x1).await.unwrap().0;
    h2.send_to(probes.x1.local(), b"2");
    let e2 = arrives(&probes.x1).await.unwrap().0;

    h1.send_to(e2, b"first");
    assert!(arrives(&h2).await.is_none(), "h2 has not sent to e1 yet");
    h2.send_to(e1, b"second");
    assert_eq!(arrives(&h1).await.expect("h1 sent to e2 already").0, e2);
    h1.send_to(e2, b"third");
    assert_eq!(arrives(&h2).await.expect("now both are open").0, e1);
}

/// A port forward admits anyone and pins the inside socket's source port.
#[tokio::test(start_paused = true)]
async fn netsim_nat_port_forward_admits_anyone_and_pins_the_source_port() {
    for mut cfg in [NatConfig::symmetric(), NatConfig::port_restricted()] {
        cfg.hairpin = false;
        let net = net();
        let probes = Probes::new(&net);
        let site = nat_site(&net, cfg.clone());
        let server = site.bind(5000).unwrap();
        site.nat().unwrap().forward(4000, server.local());
        let ext = SocketAddr::new(site.external_ip(), 4000);

        probes.x3.send_to(ext, b"cold call");
        let (from, data) = arrives(&server).await.expect("forwarded");
        assert_eq!(
            (from, data.as_slice()),
            (probes.x3.local(), &b"cold call"[..])
        );
        server.send_to(probes.x2.local(), b"reply");
        assert_eq!(
            arrives(&probes.x2).await.unwrap().0,
            ext,
            "{cfg:?}: leaves from the forward"
        );
        server.send_to(probes.x1.local(), b"reply");
        assert_eq!(
            arrives(&probes.x1).await.unwrap().0,
            ext,
            "{cfg:?}: same for every destination"
        );
    }
}

/// `flush` is a router reboot: the old mapping is gone and, with random
/// assignment, the next one is elsewhere.
#[tokio::test(start_paused = true)]
async fn netsim_nat_flush_forgets_mappings() {
    let net = net();
    let probes = Probes::new(&net);
    let site = nat_site(&net, NatConfig::port_restricted());
    let inside = site.bind(5000).unwrap();
    inside.send_to(probes.x1.local(), b"1");
    let e = arrives(&probes.x1).await.unwrap().0;
    site.nat().unwrap().flush();
    probes.x1.send_to(e, b"after reboot");
    assert!(arrives(&inside).await.is_none());
    assert_eq!(net.stats().dropped(DropReason::NoMapping), 1);
}

/// `firewall_v6`: no translation, but the filter still applies.
#[tokio::test(start_paused = true)]
async fn netsim_firewall_filters_without_translating() {
    let net = net();
    let a = net
        .internet()
        .site(NatKind::None, "x-a", ip("2001:db8:a::1"));
    let b = net
        .internet()
        .site(NatKind::None, "x-b", ip("2001:db8:b::1"));
    let (x1, x2, x3) = (
        a.bind(7000).unwrap(),
        a.bind(7001).unwrap(),
        b.bind(7000).unwrap(),
    );
    let home = net
        .internet()
        .site(NatKind::FirewallV6, "home", ip("2001:db8:c::2"));
    assert_eq!(home.external_ip(), home.ip(), "no translation");
    let host = home.bind(5000).unwrap();

    x1.send_to(host.local(), b"unsolicited");
    assert!(arrives(&host).await.is_none());
    assert_eq!(net.stats().dropped(DropReason::Filtered), 1);

    host.send_to(x1.local(), b"open");
    assert_eq!(
        arrives(&x1).await.unwrap().0,
        host.local(),
        "source is untouched"
    );
    x1.send_to(host.local(), b"reply");
    assert!(arrives(&host).await.is_some());
    x2.send_to(host.local(), b"other port");
    assert!(arrives(&host).await.is_none(), "APDF");
    x3.send_to(host.local(), b"other address");
    assert!(arrives(&host).await.is_none(), "APDF");
}

/// A box behind a box (a carrier-grade NAT): the outside sees the outer
/// address, and both boxes' filters apply.
#[tokio::test(start_paused = true)]
async fn netsim_nat_behind_nat_translates_twice() {
    let net = net();
    let probes = Probes::new(&net);
    let cgnat = net
        .internet()
        .site(NatKind::PortRestricted, "cgnat", ip("198.51.100.1"));
    let home = cgnat.nest(NatKind::FullCone, "home").unwrap();
    let host = home.bind(5000).unwrap();

    host.send_to(probes.x1.local(), b"hi");
    let seen = arrives(&probes.x1).await.unwrap().0;
    assert_eq!(
        seen.ip(),
        cgnat.external_ip(),
        "the outside sees the outer box"
    );
    assert_eq!(
        home.nat().unwrap().mappings(),
        vec![(host.local(), SocketAddr::new(home.external_ip(), 5000))]
    );
    assert_eq!(cgnat.nat().unwrap().mappings().len(), 1);

    probes.x1.send_to(seen, b"back");
    assert_eq!(arrives(&host).await.unwrap().1, b"back");
    // The outer box is port restricted: a stranger still cannot get in even
    // though the inner box is a full cone.
    probes.x3.send_to(seen, b"stranger");
    assert!(arrives(&host).await.is_none());
    assert_eq!(net.stats().dropped(DropReason::Filtered), 1);
}

// ---------------------------------------------------------------------------
// Real quinn on the virtual network.
// ---------------------------------------------------------------------------

/// Which address family the table uses for a kind: the firewall is the IPv6
/// case, every other kind is IPv4.
fn addrs(kind: NatKind) -> (IpAddr, IpAddr) {
    if kind == NatKind::FirewallV6 {
        (ip("2001:db8:5::1"), ip("2001:db8:c::2"))
    } else {
        (ip("203.0.113.1"), ip("198.51.100.7"))
    }
}

/// Accepts connections on `ep`, echoes the first bidirectional stream of
/// each, and reports every peer address the server saw.
fn spawn_echo_server(ep: quinn::Endpoint) -> tokio::sync::mpsc::UnboundedReceiver<SocketAddr> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let _ = tx.send(conn.remote_address());
                if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let data = recv.read_to_end(1 << 20).await.unwrap_or_default();
                    let _ = send.write_all(&data).await;
                    let _ = send.finish();
                }
                conn.closed().await;
            });
        }
    });
    rx
}

/// Dials `dst`, echoes `len` bytes, and returns the virtual time the
/// handshake took. `Err` is the connect failure or the 5 s timeout.
async fn echo_through(
    client: &quinn::Endpoint,
    dst: SocketAddr,
    len: usize,
) -> Result<Duration, String> {
    let t0 = Instant::now();
    let connecting = client
        .connect(dst, SERVER_NAME)
        .map_err(|e| e.to_string())?;
    let conn = timeout(Duration::from_secs(5), connecting)
        .await
        .map_err(|_| "handshake timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    let handshake = t0.elapsed();
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(&payload).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let echoed = timeout(Duration::from_secs(10), recv.read_to_end(1 << 20))
        .await
        .map_err(|_| "echo timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    if echoed != payload {
        return Err(format!("echo differs: {} of {} bytes", echoed.len(), len));
    }
    conn.close(0u32.into(), b"done");
    Ok(handshake)
}

#[tokio::test(start_paused = true)]
async fn netsim_quic_handshake_completes_between_public_hosts() {
    let net = net();
    let s = net
        .internet()
        .site(NatKind::None, "server", ip("203.0.113.1"));
    let c = net
        .internet()
        .site(NatKind::None, "client", ip("203.0.113.9"));
    let server = quic::server_endpoint(s.bind(5000).unwrap()).unwrap();
    let mut seen = spawn_echo_server(server.clone());
    let client = quic::client_endpoint(c.bind(0).unwrap()).unwrap();

    let handshake = echo_through(&client, server.local_addr().unwrap(), 64 * 1024)
        .await
        .unwrap_or_else(|e| panic!("seed {SEED:#x}: {e}"));
    // One round trip is 50 ms; give quinn a few before calling it a bug.
    assert!(
        handshake >= 2 * OWD && handshake <= 8 * OWD,
        "{handshake:?}"
    );
    assert_eq!(seen.recv().await.unwrap().ip(), c.ip());
}

/// What a direct dial does today: the client is outside a NAT of every kind,
/// the server has a public address.
#[tokio::test(start_paused = true)]
async fn netsim_quic_handshake_completes_with_the_client_behind_each_nat_kind() {
    for kind in NatKind::ALL {
        let (server_ip, nat_ip) = addrs(kind);
        let net = net();
        let s = net.internet().site(NatKind::None, "server", server_ip);
        let c = net.internet().site(kind, "client", nat_ip);
        let server = quic::server_endpoint(s.bind(5000).unwrap()).unwrap();
        let mut seen = spawn_echo_server(server.clone());
        let client = quic::client_endpoint(c.bind(0).unwrap()).unwrap();

        echo_through(&client, server.local_addr().unwrap(), 32 * 1024)
            .await
            .unwrap_or_else(|e| panic!("client behind {kind}, seed {SEED:#x}: {e}"));
        let peer = seen.recv().await.unwrap();
        assert_eq!(
            peer.ip(),
            c.external_ip(),
            "{kind}: the server sees the box"
        );
        match kind {
            NatKind::None | NatKind::FirewallV6 => assert_eq!(peer.ip(), c.ip(), "{kind}"),
            _ => assert_ne!(peer.ip(), c.ip(), "{kind}: translated"),
        }
    }
}

/// A server behind a NAT is unreachable by a cold dial, whatever the kind,
/// and reachable through a port forward: the gap hole punching has to close,
/// and the forward is what the derived-candidate scene relies on.
#[tokio::test(start_paused = true)]
async fn netsim_quic_dial_to_a_server_behind_each_nat_kind() {
    for kind in NatKind::ALL {
        let (client_ip, nat_ip) = addrs(kind);
        let net = net();
        let c = net.internet().site(NatKind::None, "client", client_ip);
        let s = net.internet().site(kind, "server", nat_ip);
        let server = quic::server_endpoint(s.bind(5000).unwrap()).unwrap();
        let _seen = spawn_echo_server(server.clone());
        let client = quic::client_endpoint(c.bind(0).unwrap()).unwrap();
        let target = SocketAddr::new(s.external_ip(), 5000);

        let cold = echo_through(&client, target, 1024).await;
        match kind {
            NatKind::None => {
                cold.unwrap_or_else(|e| panic!("{kind}: {e}"));
            }
            _ => assert!(cold.is_err(), "{kind}: a cold dial must not connect"),
        }

        if let Some(nat) = s.nat() {
            nat.forward(4000, server.local_addr().unwrap());
            let forwarded = SocketAddr::new(s.external_ip(), 4000);
            echo_through(&client, forwarded, 1024)
                .await
                .unwrap_or_else(|e| panic!("{kind} with a forward: {e}"));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn netsim_quic_handshake_survives_packet_loss() {
    let net = Net::new(NetConfig {
        seed: SEED,
        default_path: PathConfig::delay(OWD).with_loss(0.1),
        ..NetConfig::default()
    });
    let s = net
        .internet()
        .site(NatKind::None, "server", ip("203.0.113.1"));
    let c = net
        .internet()
        .site(NatKind::PortRestricted, "client", ip("198.51.100.7"));
    let server = quic::server_endpoint(s.bind(5000).unwrap()).unwrap();
    let _seen = spawn_echo_server(server.clone());
    let client = quic::client_endpoint(c.bind(0).unwrap()).unwrap();
    echo_through(&client, server.local_addr().unwrap(), 32 * 1024)
        .await
        .unwrap_or_else(|e| panic!("seed {SEED:#x}: {e}"));
    assert!(
        net.stats().dropped(DropReason::Loss) > 0,
        "the path did lose packets"
    );
}

/// The shape the hole-punching tests need next: a quinn endpoint that both
/// accepts and dials, two endpoints each behind its own box, and an address
/// handed over by hand. With port-restricted boxes on both sides a cold dial
/// fails; once each side has sent a datagram to the other's external
/// endpoint, the same dial succeeds. (This is the manual punch the next step
/// automates; here the datagrams come from raw sockets on the same ports.)
#[tokio::test(start_paused = true)]
async fn netsim_two_endpoints_behind_two_boxes_connect_after_a_manual_punch() {
    let net = net();
    let a = net
        .internet()
        .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
    let b = net
        .internet()
        .site(NatKind::PortRestricted, "b", ip("198.51.100.2"));
    let a_sock = a.bind(5000).unwrap();
    let b_sock = b.bind(6000).unwrap();
    let (a_ext, b_ext) = (
        SocketAddr::new(a.external_ip(), 5000),
        SocketAddr::new(b.external_ip(), 6000),
    );

    // Before the endpoints take the sockets, each side opens its box towards
    // the other with a raw datagram, like a punch packet.
    a_sock.send_to(b_ext, b"punch");
    b_sock.send_to(a_ext, b"punch");
    advance(OWD * 2).await;
    // The first punch from each side was filtered or accepted depending on
    // arrival order; both boxes now hold a permission for the other.
    while a_sock.try_recv_from().is_some() {}
    while b_sock.try_recv_from().is_some() {}

    let b_ep = quic::server_endpoint(b_sock).unwrap();
    let mut seen = spawn_echo_server(b_ep.clone());
    let a_ep = quic::client_endpoint(a_sock).unwrap();
    echo_through(&a_ep, b_ext, 4096)
        .await
        .unwrap_or_else(|e| panic!("seed {SEED:#x}: {e}"));
    assert_eq!(
        seen.recv().await.unwrap(),
        a_ext,
        "B sees A's external endpoint"
    );
}
