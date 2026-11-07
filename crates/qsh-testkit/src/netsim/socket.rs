//! The virtual UDP socket: quinn's [`AsyncUdpSocket`] plus a small raw API
//! for tests that talk datagrams directly.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use super::state::{RealmId, Shared};

/// Datagrams a socket buffers before dropping the newest.
const QUEUE_CAP: usize = 4096;

#[derive(Default)]
struct Inner {
    queue: VecDeque<(SocketAddr, Vec<u8>)>,
    waker: Option<Waker>,
}

/// A socket's receive queue, shared with the network.
pub(crate) struct SockQueue {
    local: SocketAddr,
    inner: Mutex<Inner>,
}

impl fmt::Debug for SockQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SockQueue")
            .field("local", &self.local)
            .finish()
    }
}

impl SockQueue {
    pub(crate) fn new(local: SocketAddr) -> Self {
        Self {
            local,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queues a datagram; `false` when the queue is full.
    pub(crate) fn push(&self, src: SocketAddr, data: Vec<u8>) -> bool {
        let mut g = self.lock();
        if g.queue.len() >= QUEUE_CAP {
            return false;
        }
        g.queue.push_back((src, data));
        if let Some(w) = g.waker.take() {
            w.wake();
        }
        true
    }
}

/// A UDP socket on the simulated network. Hand it to
/// `quinn::Endpoint::new_with_abstract_socket` (it is an [`AsyncUdpSocket`]),
/// or use [`send_to`](Self::send_to) and [`recv_from`](Self::recv_from) to
/// exchange raw datagrams. Dropping the last handle unbinds the address.
pub struct NetSocket {
    shared: Arc<Shared>,
    realm: RealmId,
    queue: Arc<SockQueue>,
}

impl fmt::Debug for NetSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetSocket")
            .field("local", &self.queue.local)
            .finish()
    }
}

impl NetSocket {
    pub(crate) fn new(shared: Arc<Shared>, realm: RealmId, queue: Arc<SockQueue>) -> Self {
        Self {
            shared,
            realm,
            queue,
        }
    }

    /// The address this socket is bound to, as the host itself sees it (the
    /// private address behind a NAT).
    pub fn local(&self) -> SocketAddr {
        self.queue.local
    }

    /// Sends one datagram. Like UDP, it never blocks and never reports loss.
    pub fn send_to(&self, dst: SocketAddr, data: &[u8]) {
        self.shared
            .lock()
            .send(self.realm, self.queue.local, dst, data);
    }

    /// The next queued datagram, if any.
    pub fn try_recv_from(&self) -> Option<(SocketAddr, Vec<u8>)> {
        self.queue.lock().queue.pop_front()
    }

    /// Waits for the next datagram.
    pub async fn recv_from(&self) -> (SocketAddr, Vec<u8>) {
        std::future::poll_fn(|cx| {
            let mut g = self.queue.lock();
            match g.queue.pop_front() {
                Some(item) => Poll::Ready(item),
                None => {
                    g.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Datagrams waiting in the receive queue.
    pub fn queued(&self) -> usize {
        self.queue.lock().queue.len()
    }
}

impl Drop for NetSocket {
    fn drop(&mut self) {
        self.shared.lock().unbind(self.realm, self.queue.local);
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for NetSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // `max_transmit_segments` is 1, so `contents` is one datagram.
        self.send_to(transmit.destination, transmit.contents);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.queue.lock();
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let Some((src, data)) = g.queue.pop_front() else {
                break;
            };
            let len = data.len().min(bufs[n].len());
            bufs[n][..len].copy_from_slice(&data[..len]);
            meta[n] = RecvMeta {
                addr: src,
                len,
                stride: len,
                ecn: None,
                dst_ip: Some(self.queue.local.ip()),
            };
            n += 1;
        }
        if n > 0 {
            return Poll::Ready(Ok(n));
        }
        g.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.queue.local)
    }
}
