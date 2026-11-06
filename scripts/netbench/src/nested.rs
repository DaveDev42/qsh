//! Nested transport: an inner QUIC connection whose UDP packets are carried by
//! an outer QUIC connection, either as DATAGRAMs or on one stream.

use crate::net::{Identity, SERVER_NAME, client_config, server_config};
use crate::profile::{Cc, Path};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskCx, Poll};
use std::time::Duration;
use tokio::sync::mpsc;

/// Inner packets are 1200 bytes at most (no inner PMTU discovery), so the
/// outer connection must be able to carry a datagram that large.
const INNER_MTU: u16 = 1200;
const QUEUE_PACKETS: usize = 256;

pub struct VirtualSocket {
    local: SocketAddr,
    peer: SocketAddr,
    out: mpsc::Sender<Vec<u8>>,
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl fmt::Debug for VirtualSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtualSocket")
            .field("local", &self.local)
            .finish()
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut TaskCx) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for VirtualSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        match self.out.try_send(transmit.contents.to_vec()) {
            // A full carrier queue drops the packet, like a full NIC queue.
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut TaskCx,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.inbound.lock().expect("inbound lock");
        match rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let n = pkt.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&pkt[..n]);
                meta[0] = RecvMeta {
                    addr: self.peer,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        true // keeps quinn from running MTU discovery on the virtual link
    }
}

struct Plumbing {
    socket: Arc<VirtualSocket>,
    /// Packets the inner endpoint wants sent.
    outbound: mpsc::Receiver<Vec<u8>>,
    /// Where the carrier delivers packets received from the peer.
    inbound: mpsc::Sender<Vec<u8>>,
}

fn plumbing(local: &str, peer: &str) -> Plumbing {
    let (out_tx, out_rx) = mpsc::channel(QUEUE_PACKETS);
    let (in_tx, in_rx) = mpsc::channel(QUEUE_PACKETS);
    Plumbing {
        socket: Arc::new(VirtualSocket {
            local: local.parse().expect("local addr"),
            peer: peer.parse().expect("peer addr"),
            out: out_tx,
            inbound: Mutex::new(in_rx),
        }),
        outbound: out_rx,
        inbound: in_tx,
    }
}

async fn wait_for_outer_datagram_room(outer: &quinn::Connection) -> Result<()> {
    let need = usize::from(INNER_MTU) + 16;
    for _ in 0..100 {
        if outer.max_datagram_size().is_some_and(|m| m >= need) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!(
        "outer max datagram size stayed below {need} (now {:?})",
        outer.max_datagram_size()
    )
}

fn spawn_carrier(
    outer: quinn::Connection,
    path: Path,
    mut p: Plumbing,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) {
    match path {
        Path::NestedDatagram => {
            let o = outer.clone();
            tokio::spawn(async move {
                while let Some(pkt) = p.outbound.recv().await {
                    let _ = o.send_datagram(Bytes::from(pkt));
                }
            });
            let inbound = p.inbound.clone();
            tokio::spawn(async move {
                while let Ok(d) = outer.read_datagram().await {
                    if inbound.try_send(d.to_vec()).is_err() {
                        // inbound queue full: drop, like a NIC would
                    }
                }
            });
        }
        Path::NestedStream => {
            let mut send = send;
            tokio::spawn(async move {
                while let Some(pkt) = p.outbound.recv().await {
                    let mut frame = (pkt.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&pkt);
                    if send.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
            let inbound = p.inbound.clone();
            let mut recv = recv;
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                while recv.read_exact(&mut len).await.is_ok() {
                    let mut pkt = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if recv.read_exact(&mut pkt).await.is_err() {
                        break;
                    }
                    let _ = inbound.try_send(pkt);
                }
            });
        }
        Path::Direct => unreachable!("direct runs have no carrier"),
    }
}

fn inner_endpoint(p: &Plumbing, server: Option<quinn::ServerConfig>) -> Result<quinn::Endpoint> {
    let rt = quinn::default_runtime().context("no tokio runtime")?;
    Ok(quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server,
        p.socket.clone(),
        rt,
    )?)
}

fn inner_transport(cfg: &mut quinn::TransportConfig) {
    cfg.initial_mtu(INNER_MTU);
    cfg.mtu_discovery_config(None);
}

/// Client side: carry packets over `outer`, then open the inner connection.
pub async fn connect_inner(
    outer: quinn::Connection,
    path: Path,
    id_cert: &rustls::pki_types::CertificateDer<'static>,
    cc: Cc,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    wait_for_outer_datagram_room(&outer).await?;
    let (mut s, r) = outer.open_bi().await?;
    s.write_all(&[0]).await?; // announce the stream to the peer
    let p = plumbing("10.77.0.2:7000", "10.77.0.1:7000");
    let mut ep = inner_endpoint(&p, None)?;
    let mut cfg = client_config(id_cert, cc, Duration::from_secs(15), None)?;
    cfg.transport_config(shared_inner_transport(cc));
    ep.set_default_client_config(cfg);
    spawn_carrier(outer, path, p, s, r);
    let conn = ep
        .connect("10.77.0.1:7000".parse()?, SERVER_NAME)?
        .await
        .context("inner handshake")?;
    Ok((ep, conn))
}

/// Server side: accept the carrier stream, then accept the inner connection.
pub async fn accept_inner(
    outer: quinn::Connection,
    path: Path,
    id: &Identity,
    cc: Cc,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    wait_for_outer_datagram_room(&outer).await?;
    let (s, mut r) = outer.accept_bi().await?;
    let mut hello = [0u8; 1];
    r.read_exact(&mut hello).await?;
    let p = plumbing("10.77.0.1:7000", "10.77.0.2:7000");
    let mut cfg = server_config(id, cc, Duration::from_secs(15), None)?;
    cfg.transport_config(shared_inner_transport(cc));
    let ep = inner_endpoint(&p, Some(cfg))?;
    spawn_carrier(outer, path, p, s, r);
    let incoming = ep.accept().await.context("inner endpoint closed")?;
    let conn = incoming.await.context("inner handshake")?;
    Ok((ep, conn))
}

fn shared_inner_transport(cc: Cc) -> Arc<quinn::TransportConfig> {
    // transport_config() returns an Arc we cannot mutate in place, so rebuild
    // it through the same constructor and apply the inner-only knobs on a
    // fresh config of the same shape.
    let mut t = quinn::TransportConfig::default();
    crate::net::apply_shared(&mut t, cc, Duration::from_secs(15));
    inner_transport(&mut t);
    Arc::new(t)
}
