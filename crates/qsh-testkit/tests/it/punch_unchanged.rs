//! ADR-0054 DoD 15: a host without a rendezvous dials exactly as it did
//! before M24 (`a_host_without_rendezvous_dials_exactly_as_before`).
//!
//! "Exactly as before" is checked from the outside, on a real loopback
//! server behind a pass-through UDP proxy that counts what the client sends:
//!
//! * the client uses one UDP socket (one proxy flow), the one the direct dial
//!   needs, and asks the simulated-network socket factory for none;
//! * nothing enters the simulated network at all, and a pinned peer that
//!   could have been a rendezvous (it is pinned with an address but neither
//!   named by `--rendezvous` nor listed in the host's hints) hears nothing;
//! * the datagram count from the client is that of a client with no punch
//!   settings at all (the pre-M24 `Ops`), within the jitter of ACK timing.
//!
//! Hint learning (`learn_hints`, on in the `qsh` binary) writes one
//! `RendezvousQuery` on the established connection, a different feature
//! (decision 5); it is run too, and it still opens no second socket and
//! sends nothing anywhere but to the host.

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::config::Paths;
use qsh_core::punch::{ClientPunch, FixedAddrs, PunchMode, SocketFactory};
use qsh_core::{Fingerprint, Ops};
use qsh_proto::{IdentityInitReq, KeyStoreMode};
use qsh_testkit::chaos::{ChaosPolicy, ChaosProxy};
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_testkit::netsim::{NatKind, Net, NetConfig};
use qsh_transport::{Principal, SocketSource, StaticTrust};

use super::punch_route::{blocking, exec, ip, pin, punched};

/// A client `Ops` of its own with a fresh identity.
async fn client(dir: &tempfile::TempDir) -> (Ops, Fingerprint) {
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let ops = Ops::new(paths);
    let init = blocking(&ops, |ops| {
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
            ..Default::default()
        })
    })
    .await
    .expect("identity.init");
    let fp = init.fingerprint.parse().expect("fingerprint");
    (ops, fp)
}

struct Observed {
    flows: usize,
    from_client: u64,
    virtual_sockets: usize,
    netsim_sent: u64,
    rendezvous_heard: usize,
}

#[derive(Clone, Copy, Debug)]
enum Client {
    /// `Ops::new` alone: what the code did before M24.
    NoPunchSettings,
    /// The punch settings of a client that names no rendezvous.
    PunchAuto { learn_hints: bool },
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_without_rendezvous_dials_exactly_as_before() {
    let clients = [
        Client::NoPunchSettings,
        Client::PunchAuto { learn_hints: false },
        Client::PunchAuto { learn_hints: true },
    ];
    let dirs: Vec<_> = clients
        .iter()
        .map(|_| tempfile::tempdir().unwrap())
        .collect();
    let mut made = Vec::new();
    for dir in &dirs {
        made.push(client(dir).await);
    }
    let mut trust = StaticTrust::empty();
    for (_, fp) in &made {
        trust = trust.with_pin(*fp, Principal::Device("laptop".into()));
    }
    let h = LoopbackHarness::start_custom(Arc::new(AllowAllPinned), make_identity(), trust).await;

    let mut seen = Vec::new();
    for ((kind, (ops, _)), _dir) in clients.iter().zip(&made).zip(&dirs) {
        let proxy = ChaosProxy::start(h.host_addr, ChaosPolicy::seeded(11))
            .await
            .expect("proxy");
        // A pinned peer with an address that a punch could use as its
        // rendezvous, if anything asked for it.
        let watch = UdpSocket::bind("127.0.0.1:0").unwrap();
        watch.set_nonblocking(true).unwrap();
        pin(
            ops,
            "r",
            Some(watch.local_addr().unwrap().to_string()),
            &make_identity().fingerprint,
        )
        .await;
        pin(
            ops,
            "b",
            Some(proxy.addr().to_string()),
            &h.server_identity.fingerprint,
        )
        .await;

        let net = Net::new(NetConfig::default());
        let site = net
            .internet()
            .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
        let made_sockets = Arc::new(AtomicUsize::new(0));
        let ops = match kind {
            Client::NoPunchSettings => ops.clone(),
            Client::PunchAuto { learn_hints } => {
                let (counter, factory_site) = (made_sockets.clone(), site.clone());
                let factory: SocketFactory = Arc::new(move || {
                    let port = 5000 + counter.fetch_add(1, Ordering::SeqCst) as u16;
                    SocketSource::Virtual(Arc::new(factory_site.bind_wildcard(port).unwrap()))
                });
                ops.clone().with_punch(ClientPunch {
                    mode: PunchMode::Auto,
                    rendezvous: vec![],
                    learn_hints: *learn_hints,
                    local_addrs: Arc::new(FixedAddrs(vec![site.ip()])),
                    socket: Some(factory),
                    ..ClientPunch::default()
                })
            }
        };
        let out = exec(&ops, "b")
            .await
            .unwrap_or_else(|err| panic!("{kind:?}: {err:?}"));
        assert!(punched(&out), "{kind:?}: the command did not run");
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut buf = [0u8; 64];
        let heard = usize::from(watch.recv_from(&mut buf).is_ok());
        let stats = proxy.stats();
        seen.push(Observed {
            flows: proxy.flows().await.len(),
            from_client: stats.from_client,
            virtual_sockets: made_sockets.load(Ordering::SeqCst),
            netsim_sent: net.stats().sent,
            rendezvous_heard: heard,
        });
        println!(
            "{kind:?}: {} client datagrams on {} socket(s), {} simulated sockets",
            stats.from_client,
            seen.last().unwrap().flows,
            seen.last().unwrap().virtual_sockets
        );
    }

    for (kind, o) in clients.iter().zip(&seen) {
        assert_eq!(o.flows, 1, "{kind:?}: one socket, the direct dial's");
        assert_eq!(o.virtual_sockets, 0, "{kind:?}: no extra socket");
        assert_eq!(o.netsim_sent, 0, "{kind:?}: nothing on a simulated network");
        assert_eq!(o.rendezvous_heard, 0, "{kind:?}: the pinned peer heard it");
    }
    let before = seen[0].from_client;
    let without_hints = seen[1].from_client;
    assert!(
        before.abs_diff(without_hints) <= 4,
        "{without_hints} client datagrams against {before} before M24"
    );
    h.shutdown().await;
}
