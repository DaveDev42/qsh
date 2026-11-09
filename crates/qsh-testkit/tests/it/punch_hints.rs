//! Where the rendezvous comes from, over netsim (ADR-0054 decisions 4, 5, 19;
//! DoD 3 and 10): a hint learned from the host after one connection and used
//! by the next dial, the hint list never widening trust, `--rendezvous` over
//! the pin's list, and the three ways of switching punching off.
//!
//! The clocks are real (the target's services use `std` time), so the bounds
//! are real seconds.

use std::time::{Duration, Instant};

use qsh_core::punch::PUNCH_HEAD_START;
use qsh_proto::{ErrorCode, TrustPeer, TrustSetRendezvousReq};

use super::punch_route::{World, WorldOptions, blocking, exec, pin, punched, world};

/// Nothing answers here: the doc range no network routes.
const BLACKHOLE: &str = "198.51.100.200:4433";
const TIMEOUT: Duration = Duration::from_secs(20);

async fn peers(w: &World) -> Vec<TrustPeer> {
    blocking(&w.a.ops, |ops| ops.trust_list().expect("trust.list").peers).await
}

async fn peer(w: &World, name: &str) -> TrustPeer {
    peers(w)
        .await
        .into_iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("no pin {name}"))
}

async fn set_rendezvous(w: &World, name: &str, rendezvous: &[&str]) {
    let req = TrustSetRendezvousReq {
        name: name.into(),
        rendezvous: rendezvous.iter().map(|s| (*s).to_string()).collect(),
        clear: false,
    };
    blocking(&w.a.ops, move |ops| ops.trust_set_rendezvous(req))
        .await
        .expect("trust.set_rendezvous");
}

/// Points A's pin of `b` at an address nothing answers on, keeping its key.
async fn close_the_direct_path(w: &World) {
    let b = peer(w, "b").await;
    let fingerprint = b.fingerprint.parse().expect("fingerprint");
    pin(&w.a.ops, "b", Some(BLACKHOLE.to_string()), &fingerprint).await;
    assert_eq!(peer(w, "b").await.address, BLACKHOLE);
}

/// B listens for the first, direct, connection and sits on the open internet
/// so nothing needs punching yet. The first command carries `--rendezvous r`
/// only so that its direct dial uses the simulated network (a plan carries
/// the virtual socket); the pin has no hint yet.
fn learning_world() -> WorldOptions {
    WorldOptions {
        b_nat: qsh_testkit::netsim::NatKind::None,
        flag_rendezvous: true,
        learn_hints: true,
        ..WorldOptions::default()
    }
}

/// The same client with no `--rendezvous`: what the pin's hints say decides.
fn without_the_flag(w: &World) -> qsh_core::Ops {
    w.a.ops.clone().with_punch(qsh_core::punch::ClientPunch {
        rendezvous: Vec::new(),
        ..w.a.env.clone()
    })
}

/// DoD 10: after one connection over the direct path the pin of B carries the
/// rendezvous B told us about; with the direct path closed, the next command
/// punches through exactly that peer, with no flag given.
#[tokio::test(flavor = "multi_thread")]
async fn a_hint_learned_after_the_first_connection_is_used_on_the_next_dial() {
    let w = world(learning_world()).await;
    assert!(peer(&w, "b").await.rendezvous.is_empty());

    let out = exec(&w.a.ops, "b")
        .await
        .expect("exec over the direct dial");
    assert!(punched(&out));
    assert_eq!(w.punch_requests(), 0, "the direct dial stood: no punch");

    let r_fingerprint = peer(&w, "r").await.fingerprint;
    let learned = loop_until(|| async {
        let b = peer(&w, "b").await;
        (!b.rendezvous.is_empty()).then_some(b.rendezvous)
    })
    .await;
    assert_eq!(learned, vec![r_fingerprint], "B's registration is the hint");

    close_the_direct_path(&w).await;
    let started = Instant::now();
    let out = exec(&without_the_flag(&w), "b")
        .await
        .expect("exec over a punch through the learned rendezvous");
    assert!(punched(&out));
    assert!(
        started.elapsed() >= PUNCH_HEAD_START,
        "after the head start"
    );
    assert_eq!(w.punch_requests(), 1, "the hint was used, once");
    w.shutdown().await;
}

/// A fingerprint that is not pinned here (or has no address) never becomes a
/// hint, however B vouches for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rendezvous_this_device_does_not_pin_is_not_learned() {
    let w = world(learning_world()).await;
    // R is pinned on A; unpin it, so B's answer names a stranger. The flag
    // names another pin so the command still has a plan (and the simulated
    // network for its direct dial).
    let other = qsh_testkit::loopback::make_identity();
    pin(
        &w.a.ops,
        "other",
        Some(BLACKHOLE.to_string()),
        &other.fingerprint,
    )
    .await;
    blocking(&w.a.ops, |ops| ops.trust_remove("r"))
        .await
        .expect("trust.remove");
    let ops = w.a.ops.clone().with_punch(qsh_core::punch::ClientPunch {
        rendezvous: vec!["other".into()],
        ..w.a.env.clone()
    });
    let out = exec(&ops, "b").await.expect("exec over the direct dial");
    assert!(punched(&out));
    // The answer arrives with the command; give the write time to not happen.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        peer(&w, "b").await.rendezvous.is_empty(),
        "an unpinned fingerprint teaches nothing"
    );
    w.shutdown().await;
}

/// `--rendezvous` replaces the pin's list for the command: the list points at
/// a peer that cannot be reached, the flag at the real rendezvous.
#[tokio::test(flavor = "multi_thread")]
async fn the_flag_overrides_the_pins_rendezvous_list() {
    let w = world(WorldOptions {
        flag_rendezvous: true,
        learn_hints: false,
        ..WorldOptions::default()
    })
    .await;
    let dead = qsh_testkit::loopback::make_identity();
    pin(
        &w.a.ops,
        "dead-relay",
        Some(BLACKHOLE.to_string()),
        &dead.fingerprint,
    )
    .await;
    set_rendezvous(&w, "b", &["dead-relay"]).await;
    // B's NAT closes the direct path; the flag names R.
    let out = exec(&w.a.ops, "b")
        .await
        .expect("exec through --rendezvous r");
    assert!(punched(&out));
    assert_eq!(w.punch_requests(), 1);
    w.shutdown().await;
}

/// The three ways to switch punching off send no `PunchRequest`, and the
/// error is the direct dial's own.
#[tokio::test(flavor = "multi_thread")]
async fn punching_off_sends_no_punch_request() {
    qsh_transport::set_default_dial_timeout(Duration::from_secs(2));
    for how in ["config key", "no-punch flag"] {
        let w = world(WorldOptions {
            flag_rendezvous: false,
            learn_hints: true,
            // The direct path to B is closed by its NAT, and there is a hint.
            ..WorldOptions::default()
        })
        .await;
        // A hint to a working rendezvous, and a direct address that is dead.
        close_the_direct_path(&w).await;
        set_rendezvous(&w, "b", &["r"]).await;

        let ops = match how {
            "config key" => {
                let path = w.a.ops.paths().config_file();
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, "[punch]\nmode = \"off\"\n").unwrap();
                w.a.ops.clone()
            }
            _ => w.a.ops.clone().with_punch(qsh_core::punch::ClientPunch {
                mode: qsh_core::punch::PunchMode::Off,
                learn_hints: true,
                ..qsh_core::punch::ClientPunch::default()
            }),
        };
        let started = Instant::now();
        let err = exec(&ops, "b").await.expect_err(how);
        assert_eq!(err.code, ErrorCode::ConnectionFailed, "{how}: {err:?}");
        assert!(err.details.get("punch").is_none(), "{how}: {err:?}");
        assert!(!err.message.contains("hole punching"), "{how}: {err:?}");
        assert!(started.elapsed() < Duration::from_secs(8), "{how}");
        assert_eq!(w.punch_requests(), 0, "{how}: no PunchRequest was sent");
        w.shutdown().await;
    }
}

async fn loop_until<T, F, Fut>(mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `-6` leaves nothing to punch with in an IPv4 world: the rendezvous address
/// is filtered out, so the attempt ends before a `PunchRequest` exists
/// (`-4`/`-6` apply to the rendezvous dial and to the candidates alike).
/// The install is process-wide, so this test is the only one in its process
/// under nextest.
#[tokio::test(flavor = "multi_thread")]
async fn dash_six_in_an_ipv4_world_ends_before_any_punch_request() {
    let w = world(WorldOptions::default()).await;
    // After the world is up: the target's own registration dials with the
    // same process-wide filter.
    let options =
        qsh_core::ssh_bootstrap::SshOptions::from_flags(&qsh_core::ssh_bootstrap::SshFlags {
            ipv6: true,
            ..Default::default()
        })
        .unwrap();
    qsh_core::client_path::install(&options);
    qsh_transport::set_default_dial_timeout(Duration::from_secs(3));
    let err = exec(&w.a.ops, "b").await.expect_err("-6 in an IPv4 world");
    assert_eq!(err.code, ErrorCode::ConnectionFailed, "{err:?}");
    assert_eq!(
        err.details["punch"]["reason"], "rendezvous_unreachable",
        "{err:?}"
    );
    assert_eq!(w.punch_requests(), 0);
    w.shutdown().await;
}
