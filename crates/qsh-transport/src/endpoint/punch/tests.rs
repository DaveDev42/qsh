//! `PunchEndpoint` over real loopback UDP. The NAT behaviour is
//! `qsh-testkit`'s `punch` tests; these cover the socket wrapper itself:
//! what reaches quinn, what reaches an inbox, and what the window does.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::punch::{
    ATTEMPT_ID_LEN, PUNCH_DATAGRAM_LEN, PUNCH_HEAD, PunchDirection, encode_punch_datagram,
    punch_tag,
};

use super::*;
use crate::identity::{Fingerprint, Principal};
use crate::tls::StaticTrust;

struct Party {
    identity: LocalIdentity,
    fingerprint: Fingerprint,
}

fn party() -> Party {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    Party {
        fingerprint: Fingerprint::of_cert_der(&der).unwrap(),
        identity: LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        },
    }
}

fn endpoint(me: &Party, trusts: &[&Party]) -> PunchEndpoint {
    let mut trust = StaticTrust::empty();
    for (i, p) in trusts.iter().enumerate() {
        trust = trust.with_pin(p.fingerprint, Principal::Device(format!("peer{i}")));
    }
    PunchEndpoint::new(
        SocketSource::Os,
        me.identity.clone(),
        Arc::new(trust),
        TransportTuning::default(),
    )
    .unwrap()
}

fn loopback(ep: &PunchEndpoint) -> SocketAddr {
    (Ipv4Addr::LOCALHOST, ep.local_addr().unwrap().port()).into()
}

fn raw() -> UdpSocket {
    let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    s.set_nonblocking(true).unwrap();
    s
}

const ID: [u8; ATTEMPT_ID_LEN] = [3; ATTEMPT_ID_LEN];

async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn a_punch_datagram_goes_to_its_inbox_and_never_to_quinn() {
    let a = party();
    let ep = endpoint(&a, &[]);
    let tag = punch_tag(&ID, PunchDirection::AToB);
    let mut inbox = ep.expect(tag);
    let sender = raw();
    sender
        .send_to(&encode_punch_datagram(&tag), loopback(&ep))
        .unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), inbox.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.tag, tag);
    assert_eq!(
        got.from,
        sender.local_addr().unwrap(),
        "IPv4 source comes back unmapped"
    );
    let s = ep.stats();
    assert_eq!((s.punch_received, s.punch_rejected), (1, 0));
    assert_eq!(s.quic_received, 0, "quinn saw nothing");
}

#[tokio::test]
async fn a_punch_datagram_with_an_unexpected_tag_is_dropped_and_counted() {
    let a = party();
    let ep = endpoint(&a, &[]);
    let mut inbox = ep.expect(punch_tag(&ID, PunchDirection::AToB));
    let sender = raw();
    // Right head, other direction's tag.
    let wrong = encode_punch_datagram(&punch_tag(&ID, PunchDirection::BToA));
    sender.send_to(&wrong, loopback(&ep)).unwrap();
    settle().await;
    assert!(inbox.try_recv().is_none());
    let s = ep.stats();
    assert_eq!((s.punch_received, s.punch_rejected), (0, 1));
    assert_eq!(s.quic_received, 0);
}

#[tokio::test]
async fn a_dropped_inbox_stops_receiving() {
    let a = party();
    let ep = endpoint(&a, &[]);
    let tag = punch_tag(&ID, PunchDirection::AToB);
    drop(ep.expect(tag));
    raw()
        .send_to(&encode_punch_datagram(&tag), loopback(&ep))
        .unwrap();
    settle().await;
    let s = ep.stats();
    assert_eq!((s.punch_received, s.punch_rejected), (0, 1));
}

/// Anything that is not exactly a punch datagram goes to quinn, which drops
/// it: a 15-byte and a 17-byte datagram with the punch head, and a 16-byte
/// one with another head.
#[tokio::test]
async fn near_miss_datagrams_pass_through_to_quinn() {
    let a = party();
    let ep = endpoint(&a, &[]);
    let mut inbox = ep.expect(punch_tag(&ID, PunchDirection::AToB));
    let good = encode_punch_datagram(&punch_tag(&ID, PunchDirection::AToB));
    let mut other_head = good;
    other_head[1] ^= 0xff;
    let mut long = good.to_vec();
    long.push(0);
    let sender = raw();
    for bytes in [&good[..15], &long[..], &other_head[..]] {
        sender.send_to(bytes, loopback(&ep)).unwrap();
    }
    settle().await;
    assert!(inbox.try_recv().is_none());
    let s = ep.stats();
    assert_eq!((s.punch_received, s.punch_rejected), (0, 0));
    assert_eq!(s.quic_received, 3, "all three reached quinn");
}

#[tokio::test]
async fn send_punch_puts_exactly_the_sixteen_byte_datagram_on_the_wire() {
    let a = party();
    let ep = endpoint(&a, &[]);
    let sink = raw();
    let tag = punch_tag(&ID, PunchDirection::BToA);
    ep.send_punch(sink.local_addr().unwrap(), &tag)
        .await
        .unwrap();
    settle().await;
    let mut buf = [0u8; 64];
    let (n, from) = sink.recv_from(&mut buf).unwrap();
    assert_eq!(n, PUNCH_DATAGRAM_LEN);
    assert_eq!(buf[..4], PUNCH_HEAD);
    assert_eq!(buf[4..n], tag);
    assert_eq!(from.port(), ep.local_addr().unwrap().port(), "same socket");
    assert_eq!(ep.stats().punch_sent, 1);
    assert_eq!(ep.stats().quic_sent, 0);
}

/// Two endpoints punch each other on loopback: each hears the other's tag.
#[tokio::test]
async fn two_endpoints_hear_each_others_punches() {
    let (a, b) = (party(), party());
    let (ea, eb) = (endpoint(&a, &[&b]), endpoint(&b, &[&a]));
    let mut at_a = ea.expect(punch_tag(&ID, PunchDirection::BToA));
    let mut at_b = eb.expect(punch_tag(&ID, PunchDirection::AToB));
    ea.send_punch(loopback(&eb), &punch_tag(&ID, PunchDirection::AToB))
        .await
        .unwrap();
    eb.send_punch(loopback(&ea), &punch_tag(&ID, PunchDirection::BToA))
        .await
        .unwrap();
    let heard_b = tokio::time::timeout(Duration::from_secs(5), at_b.recv())
        .await
        .unwrap()
        .unwrap();
    let heard_a = tokio::time::timeout(Duration::from_secs(5), at_a.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(heard_b.from.port(), ea.local_addr().unwrap().port());
    assert_eq!(heard_a.from.port(), eb.local_addr().unwrap().port());
}

/// A real handshake over the wrapped socket: QUIC passes through, no punch
/// bookkeeping moves, the dial goes to an IPv4 address on a dual-stack
/// socket, and the connection carries a stream.
#[tokio::test]
async fn quic_passes_through_and_a_connection_carries_a_stream() {
    let (a, b) = (party(), party());
    let (ea, eb) = (endpoint(&a, &[&b]), endpoint(&b, &[&a]));
    let _window = eb.open_window().unwrap();
    let serve = {
        let eb = eb.clone();
        tokio::spawn(async move {
            let incoming = eb.accept().await.unwrap();
            let incoming = match incoming.retry() {
                Ok(()) => eb.accept().await.unwrap(),
                Err(i) => i,
            };
            incoming.accept().await.unwrap()
        })
    };
    let conn = ea
        .dial(
            loopback(&eb),
            "qsh",
            Duration::from_millis(100),
            &b.fingerprint,
        )
        .await
        .unwrap();
    let server_conn = serve.await.unwrap();
    assert_eq!(conn.peer_fingerprint(), Some(b.fingerprint));
    assert_eq!(server_conn.peer_fingerprint(), Some(a.fingerprint));
    let (mut tx, _rx) = conn.open_bi().await.unwrap();
    tx.write_all(b"hi").await.unwrap();
    let (_stx, mut srx) = server_conn.accept_bi().await.unwrap();
    let mut buf = [0u8; 2];
    srx.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
    for e in [&ea, &eb] {
        let s = e.stats();
        assert!(s.quic_sent > 0 && s.quic_received > 0);
        assert_eq!(
            (s.punch_sent, s.punch_received, s.punch_rejected),
            (0, 0, 0)
        );
    }
}

/// Decision 12: a peer that passes the trust check but is not the one we
/// meant to reach is closed.
#[tokio::test]
async fn a_trusted_stranger_is_not_adopted() {
    let (a, b, c) = (party(), party(), party());
    let ea = endpoint(&a, &[&b, &c]);
    let eb = endpoint(&b, &[&a]);
    let _window = eb.open_window().unwrap();
    tokio::spawn({
        let eb = eb.clone();
        async move {
            loop {
                let Some(i) = eb.accept().await else { return };
                match i.retry() {
                    Ok(()) => {}
                    Err(i) => {
                        let _ = i.accept().await;
                    }
                }
            }
        }
    });
    // B answers, but A was told to expect C.
    let err = ea
        .dial(
            loopback(&eb),
            "qsh",
            Duration::from_millis(100),
            &c.fingerprint,
        )
        .await
        .unwrap_err();
    match err {
        DialError::LocalRejected { observed, .. } => {
            assert_eq!(observed, Some(b.fingerprint));
        }
        other => panic!("expected LocalRejected, got {other:?}"),
    }
}

/// The server side exists only while a window is open (decision 7).
#[tokio::test]
async fn the_server_answers_only_inside_a_window() {
    let (a, b) = (party(), party());
    let (ea, eb) = (endpoint(&a, &[&b]), endpoint(&b, &[&a]));
    let dial = |ea: &PunchEndpoint| {
        let ea = ea.clone();
        let to = loopback(&eb);
        let fp = b.fingerprint;
        async move {
            tokio::time::timeout(
                Duration::from_millis(600),
                ea.dial(to, "qsh", Duration::from_millis(100), &fp),
            )
            .await
        }
    };
    assert_eq!(eb.open_windows(), 0);
    assert!(dial(&ea).await.is_err(), "no window: nothing answers");
    // quinn still sends a stateless reset (smaller than the Initial) to a
    // datagram for an unknown connection; what matters is that no handshake
    // starts and no attempt is ever produced.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), eb.accept())
            .await
            .is_err()
    );

    let w1 = eb.open_window().unwrap();
    let w2 = eb.open_window().unwrap();
    assert_eq!(eb.open_windows(), 2);
    drop(w1);
    assert_eq!(eb.open_windows(), 1, "still on while one window is open");
    drop(w2);
    assert_eq!(eb.open_windows(), 0);
    assert!(dial(&ea).await.is_err(), "closed again");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), eb.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn at_most_four_windows_are_open_at_once() {
    let a = party();
    let ep = endpoint(&a, &[]);
    let held: Vec<_> = (0..MAX_PUNCH_WINDOWS)
        .map(|_| ep.open_window().unwrap())
        .collect();
    assert!(ep.open_window().is_none());
    drop(held);
    assert!(ep.open_window().is_some());
}

/// GRO hands quinn several equal-size segments in one buffer. The filter
/// takes punch segments out and keeps the rest in order.
#[tokio::test]
async fn a_coalesced_buffer_loses_its_punch_segments_only() {
    let std_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    std_sock.set_nonblocking(true).unwrap();
    let inner = quinn::TokioRuntime.wrap_udp_socket(std_sock).unwrap();
    let sock = PunchSocket::new(inner).unwrap();
    let tag = punch_tag(&ID, PunchDirection::AToB);
    let (tx, mut rx) = mpsc::channel(8);
    lock(&sock.inboxes).push((tag, tx));
    let punch = encode_punch_datagram(&tag);
    let from: SocketAddr = "192.0.2.9:4000".parse().unwrap();
    let meta_for = |len: usize, stride: usize| RecvMeta {
        addr: from,
        len,
        stride,
        ecn: None,
        dst_ip: None,
    };

    // Three punches, stride 16: the entry disappears.
    let mut buf = [punch, punch, punch].concat();
    let mut bufs = [IoSliceMut::new(&mut buf)];
    let mut meta = [meta_for(48, 16)];
    assert_eq!(sock.filter(&mut bufs, &mut meta, 1), 0);
    for _ in 0..3 {
        assert_eq!(rx.try_recv().unwrap().from, from);
    }

    // Stride 40: one 40-byte QUIC-ish segment, then a short punch at the end.
    let quic = [0x40u8; 40];
    let mut buf = [&quic[..], &punch[..]].concat();
    buf.resize(200, 0);
    let mut bufs = [IoSliceMut::new(&mut buf)];
    let mut meta = [meta_for(56, 40)];
    assert_eq!(sock.filter(&mut bufs, &mut meta, 1), 1);
    assert_eq!(meta[0].len, 40);
    assert_eq!(&bufs[0][..40], &quic[..]);
    assert!(rx.try_recv().is_ok());

    // Two entries, the first all punch: the second moves to the front.
    let mut b0 = punch.to_vec();
    b0.resize(64, 0);
    let mut b1 = quic.to_vec();
    b1.resize(64, 0);
    let mut bufs = [IoSliceMut::new(&mut b0), IoSliceMut::new(&mut b1)];
    let mut meta = [meta_for(16, 16), meta_for(40, 40)];
    assert_eq!(sock.filter(&mut bufs, &mut meta, 2), 1);
    assert_eq!(meta[0].len, 40);
    assert_eq!(&bufs[0][..40], &quic[..]);
    assert!(rx.try_recv().is_ok());
}
