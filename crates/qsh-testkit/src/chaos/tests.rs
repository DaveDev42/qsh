use super::*;

#[test]
fn the_prng_is_reproducible_and_independent_of_wall_clock() {
    let mut r1 = ChaosRng::new(0xDEAD_BEEF);
    let mut r2 = ChaosRng::new(0xDEAD_BEEF);
    let s1: Vec<u64> = (0..64).map(|_| r1.next_u64()).collect();
    let s2: Vec<u64> = (0..64).map(|_| r2.next_u64()).collect();
    assert_eq!(s1, s2, "same seed, same stream");
    assert!(s1.windows(2).all(|w| w[0] != w[1]), "not a constant");
}

#[test]
fn disabled_faults_do_not_consume_the_stream() {
    let mut rng = ChaosRng::new(1);
    // p == 0 draws nothing: the next real draw is the same as if the
    // disabled fault were not in the pipeline at all.
    assert!(!rng.chance(0.0));
    assert!(!rng.chance(-1.0));
    let after_zero = rng.next_u64();
    let mut fresh = ChaosRng::new(1);
    assert_eq!(after_zero, fresh.next_u64());
    assert!(fresh.chance(1.0), "p >= 1 is unconditional");
}

#[test]
fn chance_tracks_the_requested_probability() {
    let mut rng = ChaosRng::new(0x5EED);
    let hits = (0..10_000).filter(|_| rng.chance(0.25)).count();
    assert!((2_200..2_800).contains(&hits), "{hits} of 10000 at p=0.25");
}

#[test]
fn delay_draws_stay_inside_the_distribution() {
    let mut rng = ChaosRng::new(9);
    let dist = DelayDist::uniform(Duration::from_millis(1), Duration::from_millis(5));
    for _ in 0..1_000 {
        let d = dist.draw(&mut rng);
        assert!(
            d >= Duration::from_millis(1) && d <= Duration::from_millis(5),
            "{d:?}"
        );
    }
    assert_eq!(
        DelayDist::fixed(Duration::from_millis(2)).draw(&mut rng),
        Duration::from_millis(2)
    );
    assert!(DelayDist::None.draw(&mut rng).is_zero());
    // A backwards range is clamped, not a panic.
    let flipped = DelayDist::uniform(Duration::from_millis(5), Duration::from_millis(1));
    assert_eq!(flipped.draw(&mut rng), Duration::from_millis(5));
}

#[test]
fn corruption_lands_in_the_aead_tag_and_changes_exactly_one_bit() {
    let mut rng = ChaosRng::new(42);
    for _ in 0..200 {
        let original = vec![0xA5u8; 1200];
        let mut tampered = original.clone();
        corrupt(&mut tampered, &mut rng);
        let differing: Vec<usize> = (0..original.len())
            .filter(|i| original[*i] != tampered[*i])
            .collect();
        assert_eq!(differing.len(), 1);
        assert!(
            differing[0] >= original.len() - 16,
            "corruption must hit the tag, hit {}",
            differing[0]
        );
        assert_eq!(
            (original[differing[0]] ^ tampered[differing[0]]).count_ones(),
            1
        );
    }
    // Degenerate inputs do not panic.
    corrupt(&mut [], &mut rng);
    let mut tiny = [7u8];
    corrupt(&mut tiny, &mut rng);
    assert_ne!(tiny[0], 7);
}

#[test]
fn scheduled_datagrams_order_by_time_then_arrival() {
    let base = Instant::now();
    let client: SocketAddr = "127.0.0.1:1".parse().expect("addr");
    let mk = |ms: u64, seq: u64| Scheduled {
        at: base + Duration::from_millis(ms),
        seq,
        client,
        dir: Dir::ToServer,
        data: vec![],
    };
    let mut heap = BinaryHeap::new();
    heap.push(Reverse(mk(10, 1)));
    heap.push(Reverse(mk(5, 2)));
    heap.push(Reverse(mk(5, 3)));
    let order: Vec<u64> = std::iter::from_fn(|| heap.pop().map(|Reverse(s)| s.seq)).collect();
    assert_eq!(order, vec![2, 3, 1]);
}

#[test]
fn the_accounting_identity_catches_a_fault_that_only_bumps_its_counter() {
    // Ten datagrams in, two dropped, one duplicated, one blackholed:
    // seven sends plus the extra copy.
    let honest = ChaosStats {
        from_client: 10,
        to_server: 8,
        dropped: 2,
        duplicated: 1,
        blackholed: 1,
        ..Default::default()
    };
    assert!(honest.is_balanced(), "{honest:?}");
    // A `drop` that bumps the counter and relays anyway.
    let liar = ChaosStats {
        to_server: 10,
        ..honest
    };
    assert!(!liar.is_balanced(), "{liar:?}");
    // A staged datagram is accounted for while it waits.
    let staged = ChaosStats {
        to_server: 6,
        inflight: 2,
        ..honest
    };
    assert!(staged.is_balanced(), "{staged:?}");
}
