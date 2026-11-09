use super::*;

/// A QUIC long-header packet: `first`, version, DCID, SCID, padded to
/// `total` bytes.
fn long(first: u8, version: u32, dcid: &[u8], scid: &[u8], total: usize) -> Vec<u8> {
    let mut p = vec![first];
    p.extend_from_slice(&version.to_be_bytes());
    p.push(dcid.len() as u8);
    p.extend_from_slice(dcid);
    p.push(scid.len() as u8);
    p.extend_from_slice(scid);
    p.resize(total.max(p.len()), 0xAB);
    p
}

/// A client Initial-shaped packet with SCID `scid`.
fn initial(scid: &[u8], total: usize) -> Vec<u8> {
    long(0xC0, 1, &[9; 8], scid, total)
}

/// A server reply addressed to the client SCID `to`.
fn reply(to: &[u8]) -> Vec<u8> {
    long(0xC0, 1, to, &[7; 8], 1200)
}

#[test]
fn constants_match_the_adr() {
    assert_eq!(MAX_JUMP_CHANNELS_PER_CONN, 16);
    assert_eq!(JUMP_IDLE, Duration::from_secs(60));
    assert_eq!(JUMP_GATE_TIMEOUT, Duration::from_secs(10));
    assert_eq!(JUMP_RESOLVE_TIMEOUT, Duration::from_secs(5));
    let o = JumpOptions::default();
    assert_eq!(o.idle, JUMP_IDLE);
    assert!(
        !o.allow_host_local,
        "the host-local filter is on by default"
    );
}

#[test]
fn the_gate_passes_only_initial_shaped_packets_before_the_target_answers() {
    let mut gate = Gate::new();
    let scid = [1, 2, 3, 4];
    let table: Vec<(&str, Vec<u8>, bool)> = vec![
        ("an Initial", initial(&scid, 1200), true),
        (
            "an Initial at the packet maximum",
            initial(&scid, 1452),
            true,
        ),
        ("an Initial under 1200", initial(&scid, 1199), false),
        ("an Initial over 1452", initial(&scid, 1453), false),
        (
            "a Handshake packet",
            long(0xE0, 1, &[9; 8], &scid, 1300),
            false,
        ),
        ("a 0-RTT packet", long(0xD0, 1, &[9; 8], &scid, 1300), false),
        (
            "another version",
            long(0xC0, 2, &[9; 8], &scid, 1300),
            false,
        ),
        ("a short header", vec![0x40; 1300], false),
        ("garbage", vec![0xFF; 3], false),
        ("empty", vec![], false),
    ];
    for (name, packet, want) in table {
        assert_eq!(gate.admit_client(&packet), want, "{name}");
    }
    assert!(!gate.is_open());
}

#[test]
fn the_pregate_packet_cap_holds() {
    let mut gate = Gate::new();
    for n in 0..JUMP_PREGATE_PACKETS {
        assert!(
            gate.admit_client(&initial(&[n as u8; 4], 1200)),
            "packet {n}"
        );
    }
    assert!(!gate.admit_client(&initial(&[0xEE; 4], 1200)), "the ninth");
    assert!(!gate.is_open());
}

#[test]
fn the_pregate_byte_cap_holds() {
    // Eight Initials top out at 11,616 bytes, under the 16 KiB cap, so the
    // byte cap is exercised with a smaller limit.
    let mut gate = Gate::with_limits(100, 3000);
    assert!(gate.admit_client(&initial(&[1; 4], 1452)));
    assert!(gate.admit_client(&initial(&[2; 4], 1452)));
    assert!(
        !gate.admit_client(&initial(&[3; 4], 1200)),
        "2904 + 1200 is over 3000"
    );
    let mut gate = Gate::with_limits(100, 2904);
    assert!(gate.admit_client(&initial(&[1; 4], 1452)));
    assert!(
        gate.admit_client(&initial(&[2; 4], 1452)),
        "exactly at the cap"
    );
    assert!(!gate.admit_client(&initial(&[3; 4], 1200)));
}

#[test]
fn only_a_long_header_that_answers_a_passed_scid_opens_the_gate() {
    let mut gate = Gate::new();
    let scid = [5; 8];
    // Before any client packet passed there is nothing to answer.
    assert!(!gate.admit_target(&reply(&scid)));
    assert!(gate.admit_client(&initial(&scid, 1200)));
    let table: Vec<(&str, Vec<u8>)> = vec![
        ("a short header", vec![0x40; 100]),
        ("a long header for another connection", reply(&[6; 8])),
        ("a UDP echo of the client's Initial", initial(&scid, 1200)),
        ("garbage", vec![1, 2, 3]),
    ];
    for (name, packet) in table {
        assert!(!gate.admit_target(&packet), "{name}");
        assert!(!gate.is_open(), "{name}");
    }
    // Retry, Initial and Version Negotiation all open it.
    for first in [0xF0u8, 0xC0, 0x80] {
        let mut g = Gate::new();
        assert!(g.admit_client(&initial(&scid, 1200)));
        let version = if first == 0x80 { 0 } else { 1 };
        assert!(
            g.admit_target(&long(first, version, &scid, &[7; 8], 100)),
            "{first:#x}"
        );
        assert!(g.is_open());
    }
}

#[test]
fn an_open_gate_carries_everything_both_ways() {
    let mut gate = Gate::new();
    let scid = [5; 8];
    assert!(gate.admit_client(&initial(&scid, 1200)));
    assert!(gate.admit_target(&reply(&scid)));
    assert!(gate.admit_client(&[0x40, 1, 2, 3]));
    assert!(gate.admit_target(&[0x41, 9]));
    assert!(!gate.admit_client(&[]));
    assert!(!gate.admit_target(&[]));
}

#[test]
fn carrier_choice_table() {
    use Carrier::{Datagram, Stream};
    let table: Vec<(&str, bool, Option<usize>, Carrier)> = vec![
        ("both sides, plenty of room", true, Some(1397), Datagram),
        ("both sides, exactly 1217", true, Some(1217), Datagram),
        ("both sides, one under", true, Some(1216), Stream),
        ("the 1280 IPv4 link (1214)", true, Some(1214), Stream),
        ("the IPv6 minimum link (1194)", true, Some(1194), Stream),
        ("right after the handshake (1162)", true, Some(1162), Stream),
        ("the peer has no datagram.v1", false, Some(1397), Stream),
        ("the outer connection has no datagrams", true, None, Stream),
    ];
    for (name, both, room, want) in table {
        assert_eq!(choose_carrier(both, room), want, "{name}");
    }
}

#[test]
fn the_stream_queue_refuses_what_would_pass_its_limit() {
    let (queue, rx) = StreamQueue::new(1000);
    assert!(queue.push(vec![0; 600]));
    assert!(!queue.push(vec![0; 401]), "601 + 400 + 1 is over 1000");
    assert_eq!(queue.queued(), 600);
    assert!(queue.push(vec![0; 400]), "exactly at the limit");
    assert!(!queue.push(vec![0; 1]));
    // Writing frees the room.
    rx.sent(600);
    assert_eq!(queue.queued(), 400);
    assert!(queue.push(vec![0; 600]));
}

#[test]
fn the_stream_queue_limit_is_the_adr_constant() {
    let (queue, _rx) = StreamQueue::new(JUMP_STREAM_QUEUE);
    assert!(queue.push(vec![0; JUMP_STREAM_QUEUE]));
    assert!(!queue.push(vec![0; 1]));
}

#[test]
fn a_channel_value_can_be_claimed_once_per_connection() {
    let table = Arc::new(JumpTable::new());
    let stats = Arc::new(JumpStats::default());
    let first = table.claim(1, [7; 16], &stats).expect("first claim");
    assert!(table.claim(1, [7; 16], &stats).is_none(), "same connection");
    let other = table
        .claim(2, [7; 16], &stats)
        .expect("another connection may use the value");
    let again = table.claim(1, [8; 16], &stats).expect("another value");
    drop(first);
    assert!(
        table.claim(1, [7; 16], &stats).is_some(),
        "the claim is released with the guard"
    );
    drop((other, again));
}

#[test]
fn live_slots_are_per_connection_and_released_on_drop() {
    let table = Arc::new(JumpTable::new());
    let stats = Arc::new(JumpStats::default());
    let mut guards = Vec::new();
    for n in 0..3u8 {
        let mut g = table.claim(1, [n; 16], &stats).unwrap();
        assert!(g.reserve(3), "slot {n}");
        assert!(g.reserve(3), "reserving twice does not take a second slot");
        guards.push(g);
    }
    assert_eq!(table.live_channels(), 3);
    assert_eq!(stats.live(), 3);
    let mut fourth = table.claim(1, [9; 16], &stats).unwrap();
    assert!(!fourth.reserve(3), "over the bound");
    assert_eq!(table.live_channels(), 3, "a refused reserve holds nothing");
    let mut elsewhere = table.claim(2, [9; 16], &stats).unwrap();
    assert!(elsewhere.reserve(3), "another connection has its own slots");
    assert_eq!(table.live_channels(), 4);
    guards.pop();
    assert!(fourth.reserve(3), "a freed slot is usable");
    drop((guards, fourth, elsewhere));
    assert_eq!(table.live_channels(), 0);
    assert_eq!(stats.live(), 0);
}

#[test]
fn close_reason_words_are_closed() {
    let words: Vec<&str> = [
        CloseReason::Idle,
        CloseReason::StreamEnd,
        CloseReason::ConnectionClosed,
        CloseReason::Unreachable,
        CloseReason::GateTimeout,
        CloseReason::BadFrame,
        CloseReason::SocketError,
    ]
    .into_iter()
    .map(CloseReason::as_str)
    .collect();
    assert_eq!(
        words,
        [
            "idle",
            "stream_end",
            "connection_closed",
            "unreachable",
            "gate_timeout",
            "bad_frame",
            "socket_error"
        ]
    );
}

#[test]
fn a_refusal_is_a_refusal_on_every_platform_spelling() {
    use io::ErrorKind::*;
    for kind in [
        ConnectionRefused,
        ConnectionReset,
        ConnectionAborted,
        HostUnreachable,
        NetworkUnreachable,
    ] {
        assert!(is_refusal(&io::Error::from(kind)), "{kind:?}");
    }
    for kind in [WouldBlock, InvalidInput, PermissionDenied, Other] {
        assert!(!is_refusal(&io::Error::from(kind)), "{kind:?}");
    }
}
