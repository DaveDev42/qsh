use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

const START: u64 = 200_000_000;

struct Manual(AtomicU64);

impl Manual {
    fn at(ms: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(ms)))
    }

    fn advance(&self, d: Duration) {
        self.0.fetch_add(duration_ms(d), Ordering::SeqCst);
    }
}

impl RouteClock for Manual {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Addrs(Mutex<Vec<IpAddr>>);

impl Addrs {
    fn new(ips: &[&str]) -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            ips.iter().map(|s| s.parse().unwrap()).collect(),
        )))
    }

    fn set(&self, ips: &[&str]) {
        *self.0.lock().unwrap() = ips.iter().map(|s| s.parse().unwrap()).collect();
    }
}

impl LocalAddrs for Addrs {
    fn observe(&self) -> Vec<IpAddr> {
        self.0.lock().unwrap().clone()
    }
}

struct Rig {
    _dir: tempfile::TempDir,
    path: PathBuf,
    clock: Arc<Manual>,
    addrs: Arc<Addrs>,
}

impl Rig {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            path: dir.path().join("state").join("route-cache.json"),
            _dir: dir,
            clock: Manual::at(START),
            addrs: Addrs::new(&["192.0.2.10"]),
        }
    }

    fn pin(&self, name: &str) -> RouteMemory {
        RouteMemory::new(
            self.path.clone(),
            name,
            self.clock.clone(),
            self.addrs.clone(),
        )
    }
}

#[test]
fn the_rest_is_ten_minutes_doubling_to_an_hour() {
    let minutes: Vec<u64> = (1..=8).map(|n| rest_after(n).as_secs() / 60).collect();
    assert_eq!(minutes, [10, 20, 40, 60, 60, 60, 60, 60]);
    assert_eq!(rest_after(0), FIRST_REST);
    assert_eq!(rest_after(u32::MAX), MAX_REST);
}

#[test]
fn a_pin_nobody_remembers_runs_the_usual_order() {
    let rig = Rig::new();
    assert_eq!(rig.pin("sha256:a").stance(), Stance::Normal);
}

#[test]
fn iroh_winning_over_a_route_that_did_not_stand_starts_a_rest() {
    let rig = Rig::new();
    let pin = rig.pin("sha256:a");
    assert_eq!(pin.stance(), Stance::Normal);
    pin.note_iroh_won(true);
    assert_eq!(pin.stance(), Stance::Skip);
    // Another pin is not affected.
    assert_eq!(rig.pin("sha256:b").stance(), Stance::Normal);

    rig.clock.advance(Duration::from_secs(9 * 60 + 59));
    assert_eq!(pin.stance(), Stance::Skip, "ten minutes have not passed");
    rig.clock.advance(Duration::from_secs(1));
    assert_eq!(pin.stance(), Stance::Retry, "the rest is over");
}

#[test]
fn each_consecutive_win_of_iroh_doubles_the_rest_up_to_an_hour() {
    let rig = Rig::new();
    let pin = rig.pin("sha256:a");
    for minutes in [10u64, 20, 40, 60, 60] {
        pin.note_iroh_won(true);
        rig.clock.advance(Duration::from_secs(minutes * 60 - 1));
        assert_eq!(
            pin.stance(),
            Stance::Skip,
            "{minutes} min rest, one second early"
        );
        rig.clock.advance(Duration::from_secs(1));
        assert_eq!(pin.stance(), Stance::Retry, "{minutes} min rest is over");
    }
}

#[test]
fn a_win_by_iroh_during_a_rest_leaves_the_rest_alone() {
    let rig = Rig::new();
    let pin = rig.pin("sha256:a");
    pin.note_iroh_won(true);
    rig.clock.advance(Duration::from_secs(5 * 60));
    // The others did not run, so there is nothing new to learn.
    pin.note_iroh_won(false);
    rig.clock.advance(Duration::from_secs(5 * 60));
    assert_eq!(
        pin.stance(),
        Stance::Retry,
        "the first rest still ended at ten minutes"
    );
}

#[test]
fn a_win_by_the_direct_dial_or_the_punch_forgets_the_pin() {
    let rig = Rig::new();
    let pin = rig.pin("sha256:a");
    pin.note_iroh_won(true);
    pin.note_iroh_won(true);
    pin.note_other_won();
    assert_eq!(pin.stance(), Stance::Normal);
    // The failures start over from one.
    pin.note_iroh_won(true);
    rig.clock.advance(FIRST_REST);
    assert_eq!(pin.stance(), Stance::Retry);
}

#[test]
fn a_change_of_network_forgets_every_pin() {
    let rig = Rig::new();
    let a = rig.pin("sha256:a");
    let b = rig.pin("sha256:b");
    a.note_iroh_won(true);
    b.note_iroh_won(true);
    assert_eq!(a.stance(), Stance::Skip);

    rig.addrs.set(&["198.51.100.7"]);
    assert_eq!(
        a.stance(),
        Stance::Normal,
        "a new source address is a new network"
    );
    assert_eq!(b.stance(), Stance::Normal);

    // Back on the first network: the memory of it is gone too.
    rig.addrs.set(&["192.0.2.10"]);
    assert_eq!(a.stance(), Stance::Normal);
}

#[test]
fn the_order_of_addresses_and_a_dual_stack_pair_are_one_network() {
    let rig = Rig::new();
    rig.addrs.set(&["192.0.2.10", "2001:db8::1"]);
    let pin = rig.pin("sha256:a");
    pin.note_iroh_won(true);
    rig.addrs.set(&["2001:db8::1", "192.0.2.10"]);
    assert_eq!(pin.stance(), Stance::Skip);
    // Losing one family is a different network.
    rig.addrs.set(&["192.0.2.10"]);
    assert_eq!(pin.stance(), Stance::Normal);
}

#[test]
fn going_offline_forgets_nothing() {
    let rig = Rig::new();
    let pin = rig.pin("sha256:a");
    pin.note_iroh_won(true);
    rig.addrs.set(&[]);
    assert_eq!(
        pin.stance(),
        Stance::Skip,
        "no observation is not a new network"
    );
    rig.addrs.set(&["192.0.2.10"]);
    assert_eq!(pin.stance(), Stance::Skip, "and the same network is back");
}

#[test]
fn a_corrupt_file_is_an_empty_memory_and_is_written_over() {
    let rig = Rig::new();
    std::fs::create_dir_all(rig.path.parent().unwrap()).unwrap();
    for junk in [
        &b"not json"[..],
        b"{\"version\":99,\"network\":\"x\",\"pins\":{}}",
        b"",
        b"\xff\xfe",
    ] {
        std::fs::write(&rig.path, junk).unwrap();
        let pin = rig.pin("sha256:a");
        assert_eq!(pin.stance(), Stance::Normal);
        pin.note_iroh_won(true);
        assert_eq!(
            pin.stance(),
            Stance::Skip,
            "the file works again after a write"
        );
    }
}

#[test]
fn a_huge_file_is_not_read() {
    let rig = Rig::new();
    std::fs::create_dir_all(rig.path.parent().unwrap()).unwrap();
    std::fs::write(&rig.path, vec![b' '; (MAX_FILE_BYTES + 1) as usize]).unwrap();
    assert_eq!(rig.pin("sha256:a").stance(), Stance::Normal);
}

#[test]
fn an_unwritable_location_is_ignored() {
    let rig = Rig::new();
    // A directory where the file should be: every write fails.
    std::fs::create_dir_all(&rig.path).unwrap();
    let pin = rig.pin("sha256:a");
    pin.note_iroh_won(true);
    assert_eq!(pin.stance(), Stance::Normal);
}

#[test]
fn a_clock_that_went_back_retries_instead_of_resting_for_days() {
    let rig = Rig::new();
    let pin = rig.pin("sha256:a");
    pin.note_iroh_won(true);
    assert_eq!(pin.stance(), Stance::Skip);
    // The wall clock steps back a day: the rest began "in the future".
    let back = Manual::at(START - 86_400_000);
    let earlier = RouteMemory::new(rig.path.clone(), "sha256:a", back, rig.addrs.clone());
    assert_eq!(earlier.stance(), Stance::Retry);
}

#[test]
fn the_file_holds_a_hash_and_fingerprints_but_no_address() {
    let rig = Rig::new();
    rig.addrs.set(&["192.0.2.10", "2001:db8::1"]);
    rig.pin("sha256:a").note_iroh_won(true);
    let text = std::fs::read_to_string(&rig.path).unwrap();
    assert!(!text.contains("192.0.2"), "{text}");
    assert!(!text.contains("2001:db8"), "{text}");
    assert!(text.contains("sha256:a"), "{text}");
}

#[test]
fn the_file_never_holds_more_than_the_cap() {
    let rig = Rig::new();
    for n in 0..(MAX_PINS + 10) {
        rig.pin(&format!("sha256:{n}")).note_iroh_won(true);
        rig.clock.advance(Duration::from_secs(1));
    }
    let state: State = serde_json::from_slice(&std::fs::read(&rig.path).unwrap()).unwrap();
    assert_eq!(state.pins.len(), MAX_PINS);
}
