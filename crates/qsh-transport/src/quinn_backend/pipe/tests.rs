use std::future::poll_fn;

use super::*;

fn transmit(contents: &[u8]) -> Transmit<'_> {
    Transmit {
        destination: PIPE_REMOTE_ADDR,
        ecn: None,
        contents,
        segment_size: None,
        src_ip: None,
    }
}

async fn recv_one(socket: &PipeSocket) -> io::Result<(Vec<u8>, RecvMeta)> {
    poll_fn(|cx| {
        let mut buf = [0u8; 2048];
        let mut bufs = [IoSliceMut::new(&mut buf)];
        let mut meta = [RecvMeta::default()];
        socket.poll_recv(cx, &mut bufs, &mut meta).map_ok(|n| {
            assert_eq!(n, 1);
            (buf[..meta[0].len].to_vec(), meta[0])
        })
    })
    .await
}

#[test]
fn the_socket_makes_the_promises_the_probe_found_necessary() {
    let (pipe, _peer) = PacketPipe::new(4);
    let socket = pipe.socket;
    assert!(!socket.may_fragment());
    assert_eq!(socket.max_transmit_segments(), 1);
    assert_eq!(socket.max_receive_segments(), 1);
    assert_eq!(socket.local_addr().unwrap(), PIPE_LOCAL_ADDR);
}

#[tokio::test]
async fn outgoing_overflow_drops_and_counts_without_blocking() {
    let (pipe, mut peer) = PacketPipe::new(3);
    for i in 0..10u8 {
        pipe.socket.try_send(&transmit(&[i; 100])).unwrap();
    }
    let stats = peer.stats();
    assert_eq!((stats.out_queued, stats.out_dropped_full), (3, 7));
    // The first three survive, in order.
    for i in 0..3u8 {
        assert_eq!(peer.recv().await.unwrap(), vec![i; 100]);
    }
    // Room again after draining.
    pipe.socket.try_send(&transmit(&[9; 100])).unwrap();
    assert_eq!(peer.stats().out_queued, 4);
}

#[tokio::test]
async fn try_recv_drains_what_is_queued_and_never_waits() {
    let (pipe, mut peer) = PacketPipe::new(8);
    assert_eq!(peer.try_recv(), None);
    for i in 0..3u8 {
        pipe.socket.try_send(&transmit(&[i; 10])).unwrap();
    }
    for i in 0..3u8 {
        assert_eq!(peer.try_recv(), Some(vec![i; 10]));
    }
    assert_eq!(peer.try_recv(), None);
}

#[tokio::test]
async fn incoming_overflow_drops_and_counts_without_blocking() {
    let (pipe, peer) = PacketPipe::new(2);
    let accepted: Vec<bool> = (0..5u8).map(|i| peer.send(vec![i; 50])).collect();
    assert_eq!(accepted, [true, true, false, false, false]);
    let stats = peer.stats();
    assert_eq!((stats.in_queued, stats.in_dropped_full), (2, 3));
    let (p, meta) = recv_one(&pipe.socket).await.unwrap();
    assert_eq!(p, vec![0; 50]);
    assert_eq!(meta.addr, PIPE_REMOTE_ADDR);
    assert_eq!(meta.len, 50);
}

#[tokio::test]
async fn packets_over_the_limit_are_dropped_silently_in_both_directions() {
    let (pipe, peer) = PacketPipe::new(8);
    assert_eq!(peer.packet_limit(), usize::from(JUMP_PACKET_MAX));
    peer.set_packet_limit(1200);
    pipe.socket.try_send(&transmit(&[0; 1200])).unwrap();
    // Oversize is Ok to quinn (it is "lost"), not an error.
    pipe.socket.try_send(&transmit(&[0; 1201])).unwrap();
    assert!(peer.send(vec![0; 1200]));
    assert!(!peer.send(vec![0; 1201]));
    let stats = peer.stats();
    assert_eq!(stats.out_queued, 1);
    assert_eq!(stats.out_dropped_oversize, 1);
    assert_eq!(stats.in_queued, 1);
    assert_eq!(stats.in_dropped_oversize, 1);
    // Raising the limit takes effect on the next packet.
    peer.set_packet_limit(1452);
    pipe.socket.try_send(&transmit(&[0; 1452])).unwrap();
    assert_eq!(peer.stats().out_queued, 2);
}

#[tokio::test]
async fn a_dropped_peer_ends_the_socket_with_broken_pipe() {
    let (pipe, peer) = PacketPipe::new(2);
    drop(peer);
    let err = recv_one(&pipe.socket).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    // Sending into a dead pipe is still not an error for quinn.
    pipe.socket.try_send(&transmit(&[0; 10])).unwrap();
}
