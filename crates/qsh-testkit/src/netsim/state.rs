//! The simulator's mutable core: realms, NAT boxes, sockets, and the event
//! heap. Everything here runs under one mutex, so packet order is a pure
//! function of the order of `send` calls and the seed.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::Notify;
use tokio::time::Instant;

use super::nat::{FirewallConfig, FirewallState, NatConfig, NatState, Refusal};
use super::rng::Rng;
use super::socket::SockQueue;
use super::{DropReason, NetConfig, NetStats, PathConfig};

pub(crate) type RealmId = usize;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Uplink {
    Root,
    Nat(usize),
    Firewall,
}

#[derive(Debug)]
pub(crate) struct RealmState {
    pub(crate) name: String,
    pub(crate) parent: Option<RealmId>,
    pub(crate) uplink: Uplink,
    pub(crate) lan: PathConfig,
    pub(crate) hosts: HashSet<IpAddr>,
    pub(crate) child_nats: Vec<usize>,
    pub(crate) child_firewalls: Vec<RealmId>,
    pub(crate) firewall: Option<FirewallState>,
    pub(crate) next_private: u32,
    /// Distinguishes private prefixes between realms.
    pub(crate) tag: u32,
}

#[derive(Debug)]
struct Pending {
    at: Instant,
    seq: u64,
    realm: RealmId,
    src: SocketAddr,
    dst: SocketAddr,
    data: Vec<u8>,
}

impl PartialEq for Pending {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Pending {}
impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Pending {
    // Reversed: `BinaryHeap` is a max-heap and we want the earliest first.
    fn cmp(&self, other: &Self) -> Ordering {
        (other.at, other.seq).cmp(&(self.at, self.seq))
    }
}

pub(crate) struct State {
    pub(crate) cfg: NetConfig,
    rng: Rng,
    seq: u64,
    heap: BinaryHeap<Pending>,
    pub(crate) realms: Vec<RealmState>,
    pub(crate) nats: Vec<NatState>,
    pub(crate) sockets: HashMap<(RealmId, SocketAddr), Arc<SockQueue>>,
    paths: HashMap<(IpAddr, IpAddr), PathConfig>,
    next_port: HashMap<(RealmId, IpAddr), u16>,
    pub(crate) stats: NetStats,
    notify: Arc<Notify>,
}

impl State {
    pub(crate) fn new(cfg: NetConfig, notify: Arc<Notify>) -> Self {
        let root = RealmState {
            name: "internet".to_owned(),
            parent: None,
            uplink: Uplink::Root,
            lan: cfg.lan,
            hosts: HashSet::new(),
            child_nats: Vec::new(),
            child_firewalls: Vec::new(),
            firewall: None,
            next_private: 2,
            tag: 0,
        };
        Self {
            rng: Rng::new(cfg.seed),
            cfg,
            seq: 0,
            heap: BinaryHeap::new(),
            realms: vec![root],
            nats: Vec::new(),
            sockets: HashMap::new(),
            paths: HashMap::new(),
            next_port: HashMap::new(),
            stats: NetStats::default(),
            notify,
        }
    }

    pub(crate) fn set_path(&mut self, a: IpAddr, b: IpAddr, cfg: PathConfig, both: bool) {
        self.paths.insert((a, b), cfg);
        if both {
            self.paths.insert((b, a), cfg);
        }
    }

    fn path(&self, a: IpAddr, b: IpAddr) -> PathConfig {
        self.paths
            .get(&(a, b))
            .copied()
            .unwrap_or(self.cfg.default_path)
    }

    fn drop_packet(&mut self, reason: DropReason) {
        *self.stats.dropped.entry(reason).or_insert(0) += 1;
    }

    // ---- topology ----

    pub(crate) fn add_realm(
        &mut self,
        name: &str,
        parent: RealmId,
        uplink: Uplink,
        firewall: Option<FirewallState>,
    ) -> RealmId {
        let id = self.realms.len();
        let lan = self.cfg.lan;
        self.realms.push(RealmState {
            name: name.to_owned(),
            parent: Some(parent),
            uplink,
            lan,
            hosts: HashSet::new(),
            child_nats: Vec::new(),
            child_firewalls: Vec::new(),
            firewall,
            next_private: 2,
            tag: id as u32,
        });
        id
    }

    pub(crate) fn add_nat(
        &mut self,
        name: &str,
        parent: RealmId,
        cfg: NatConfig,
        ext_ip: IpAddr,
    ) -> (RealmId, usize) {
        let nat_id = self.nats.len();
        let inner = self.add_realm(name, parent, Uplink::Nat(nat_id), None);
        self.nats.push(NatState::new(cfg, ext_ip, inner));
        self.realms[parent].child_nats.push(nat_id);
        (inner, nat_id)
    }

    pub(crate) fn add_firewall(
        &mut self,
        name: &str,
        parent: RealmId,
        cfg: FirewallConfig,
    ) -> RealmId {
        let id = self.add_realm(
            name,
            parent,
            Uplink::Firewall,
            Some(FirewallState::new(cfg)),
        );
        self.realms[parent].child_firewalls.push(id);
        id
    }

    /// The next unused private address of a translating realm, in the same
    /// family as `like`.
    pub(crate) fn alloc_private(&mut self, realm: RealmId, like: IpAddr) -> IpAddr {
        let r = &mut self.realms[realm];
        let n = r.next_private;
        r.next_private += 1;
        let ip = match like {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::new(
                192,
                168,
                (r.tag % 250) as u8,
                (n % 250) as u8,
            )),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::new(
                0xfd00,
                r.tag as u16,
                0,
                0,
                0,
                0,
                0,
                n as u16,
            )),
        };
        r.hosts.insert(ip);
        ip
    }

    pub(crate) fn bind(
        &mut self,
        realm: RealmId,
        mut addr: SocketAddr,
    ) -> std::io::Result<Arc<SockQueue>> {
        use std::io::{Error, ErrorKind};
        if addr.ip().is_unspecified() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "netsim sockets bind to a specific host address",
            ));
        }
        if addr.port() == 0 {
            let counter = self.next_port.entry((realm, addr.ip())).or_insert(49_152);
            let mut found = None;
            for _ in 0..16_384u32 {
                let p = *counter;
                *counter = if p == u16::MAX { 49_152 } else { p + 1 };
                if !self
                    .sockets
                    .contains_key(&(realm, SocketAddr::new(addr.ip(), p)))
                {
                    found = Some(p);
                    break;
                }
            }
            let Some(p) = found else {
                return Err(Error::new(ErrorKind::AddrInUse, "no free ephemeral port"));
            };
            addr.set_port(p);
        }
        if self.sockets.contains_key(&(realm, addr)) {
            return Err(Error::new(ErrorKind::AddrInUse, "address already bound"));
        }
        self.realms[realm].hosts.insert(addr.ip());
        let queue = Arc::new(SockQueue::new(addr));
        self.sockets.insert((realm, addr), queue.clone());
        Ok(queue)
    }

    pub(crate) fn unbind(&mut self, realm: RealmId, addr: SocketAddr) {
        self.sockets.remove(&(realm, addr));
    }

    // ---- packet flow ----

    /// Sends one datagram from a socket in `realm`. Outbound NAT and firewall
    /// state change now; the packet arrives after the path delay.
    pub(crate) fn send(&mut self, realm: RealmId, src: SocketAddr, dst: SocketAddr, data: &[u8]) {
        let now = Instant::now();
        self.stats.sent += 1;
        let overhead = if dst.is_ipv4() { 28 } else { 48 };
        if data.len() + overhead > self.cfg.mtu {
            self.drop_packet(DropReason::Mtu);
            return;
        }
        let mut realm = realm;
        let mut src = src;
        loop {
            let r = &self.realms[realm];
            let Some(parent) = r.parent else {
                let path = self.path(src.ip(), dst.ip());
                self.schedule(now, realm, src, dst, data, path);
                return;
            };
            let local = r.hosts.contains(&dst.ip())
                || r.child_nats
                    .iter()
                    .any(|n| self.nats[*n].ext_ip == dst.ip());
            if local {
                let lan = r.lan;
                self.schedule(now, realm, src, dst, data, lan);
                return;
            }
            match r.uplink {
                Uplink::Root => unreachable!("only the root has no parent"),
                Uplink::Firewall => {
                    if let Some(fw) = self.realms[realm].firewall.as_mut() {
                        fw.note_outbound(now, src, dst);
                    }
                }
                Uplink::Nat(n) => {
                    let nat = &mut self.nats[n];
                    let ext_src = nat.outbound(now, src, dst, &mut self.rng);
                    if dst.ip() == nat.ext_ip {
                        // Hairpin: the packet turns around inside the box.
                        if !nat.cfg.hairpin {
                            self.drop_packet(DropReason::HairpinDisabled);
                            return;
                        }
                        match nat.inbound(now, ext_src, dst.port()) {
                            Ok(internal) => {
                                let inner = nat.inner;
                                let lan = self.realms[inner].lan;
                                self.schedule(now, inner, ext_src, internal, data, lan);
                            }
                            Err(why) => self.drop_packet(refusal_reason(why)),
                        }
                        return;
                    }
                    src = ext_src;
                }
            }
            realm = parent;
        }
    }

    fn schedule(
        &mut self,
        now: Instant,
        realm: RealmId,
        src: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        path: PathConfig,
    ) {
        if path.loss > 0.0 && self.rng.unit() < path.loss {
            self.drop_packet(DropReason::Loss);
            return;
        }
        let mut delay = path.delay;
        if !path.jitter.is_zero() {
            delay += path.jitter.mul_f64(self.rng.unit());
        }
        self.seq += 1;
        self.heap.push(Pending {
            at: now + delay,
            seq: self.seq,
            realm,
            src,
            dst,
            data: data.to_vec(),
        });
        self.notify.notify_one();
    }

    /// Delivers every event due at `now`.
    pub(crate) fn run_due(&mut self, now: Instant) {
        while self.heap.peek().is_some_and(|p| p.at <= now) {
            let p = self.heap.pop().expect("peeked");
            self.arrive(now, p.realm, p.src, p.dst, p.data);
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.heap.peek().map(|p| p.at)
    }

    fn arrive(
        &mut self,
        now: Instant,
        realm: RealmId,
        src: SocketAddr,
        dst: SocketAddr,
        data: Vec<u8>,
    ) {
        if let Some(q) = self.sockets.get(&(realm, dst)).cloned() {
            let refused = self.realms[realm]
                .firewall
                .as_ref()
                .is_some_and(|fw| !fw.admit(now, dst, src));
            if refused {
                self.drop_packet(DropReason::Filtered);
                return;
            }
            if q.push(src, data) {
                self.stats.delivered += 1;
            } else {
                self.drop_packet(DropReason::QueueFull);
            }
            return;
        }
        let nat = self.realms[realm]
            .child_nats
            .iter()
            .copied()
            .find(|n| self.nats[*n].ext_ip == dst.ip());
        if let Some(n) = nat {
            match self.nats[n].inbound(now, src, dst.port()) {
                Ok(internal) => {
                    let inner = self.nats[n].inner;
                    self.arrive(now, inner, src, internal, data);
                }
                Err(why) => self.drop_packet(refusal_reason(why)),
            }
            return;
        }
        let fw_realm = self.realms[realm]
            .child_firewalls
            .iter()
            .copied()
            .find(|f| self.realms[*f].hosts.contains(&dst.ip()));
        if let Some(f) = fw_realm {
            self.arrive(now, f, src, dst, data);
            return;
        }
        if self.realms[realm].hosts.contains(&dst.ip()) {
            self.drop_packet(DropReason::NoSocket);
        } else {
            self.drop_packet(DropReason::NoRoute);
        }
    }
}

fn refusal_reason(r: Refusal) -> DropReason {
    match r {
        Refusal::NoMapping => DropReason::NoMapping,
        Refusal::Filtered => DropReason::Filtered,
    }
}

pub(crate) struct Shared {
    pub(crate) state: Mutex<State>,
    notify: Arc<Notify>,
}

impl Shared {
    pub(crate) fn new(cfg: NetConfig) -> Arc<Self> {
        let notify = Arc::new(Notify::new());
        let shared = Arc::new(Self {
            state: Mutex::new(State::new(cfg, notify.clone())),
            notify: notify.clone(),
        });
        tokio::spawn(pump(Arc::downgrade(&shared), notify));
        shared
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        // Wake the pump so it notices the network is gone and exits.
        self.notify.notify_one();
    }
}

async fn pump(weak: Weak<Shared>, notify: Arc<Notify>) {
    loop {
        let next: Option<Instant> = {
            let Some(shared) = weak.upgrade() else {
                return;
            };
            let mut st = shared.lock();
            st.run_due(Instant::now());
            st.next_deadline()
        };
        match next {
            Some(at) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(at) => {}
                    _ = notify.notified() => {}
                }
            }
            None => notify.notified().await,
        }
    }
}
