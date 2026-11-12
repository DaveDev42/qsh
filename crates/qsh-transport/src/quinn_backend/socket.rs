//! UDP socket creation for the QUIC backend: buffer tuning and dual-stack
//! handling (`docs/adr/0046-dual-stack-wildcard-listener.md`).

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// Descending candidate ladder for the UDP socket buffer tuning below.
/// Deliberately **decoupled** from [`TUNNEL_STREAM_RECEIVE_WINDOW`]: the
/// window is a QUIC-level flow-control ceiling tuned against the M4 perf
/// DoDs (and, per that constant's own doc, may need to come *down* to
/// protect PTY latency), while this ladder is a queue-*depth* floor one
/// layer below it (the OS socket) that must never shrink — a socket
/// buffer smaller than whatever window is in effect would itself become
/// the bottleneck a bufferbloat-sensitive stream queues behind, defeating
/// the point regardless of which window value wins. Kept independent
/// (and always ≥ the current window) rather than derived from it, so a
/// future window change can never accidentally shrink this.
pub(crate) const SOCKET_BUFFER_LADDER_BYTES: [usize; 4] = [
    8 * 1024 * 1024,
    4 * 1024 * 1024,
    2 * 1024 * 1024,
    1024 * 1024,
];

/// Try each rung of [`SOCKET_BUFFER_LADDER_BYTES`], largest first, keeping
/// the first rung whose OS-granted result beats what the OS already had
/// before this function touched it (`get`/`set` are `recv_buffer_size`/
/// `set_recv_buffer_size` or the `send_*` pair). **Never reduces the
/// buffer:** a candidate at or below the already-granted default is
/// skipped outright (never handed to `set`), and a rung whose `set`
/// either fails or is silently clamped back down to (or below) the
/// default is undone by re-asserting the default before the next
/// (smaller) rung is tried — so a clamped-low attempt can never leave the
/// socket worse off than it started, and this function is safe to call
/// even on a platform whose default already exceeds every rung.
///
/// **Why independently sized ladders per direction, not one shared call.**
/// macOS grants a default `SO_RCVBUF` of ~768 KiB but a default
/// `SO_SNDBUF` of only ~9 KiB — the two directions differ by two orders
/// of magnitude on the same platform, so a single fixed request applied
/// to both (this file's previous approach: a flat 128 KiB for both) was a
/// measured **6x reduction** of macOS's own recv default, the opposite of
/// what `docs/design/testing.md`'s CI 규율 ("GHA macOS runner는 UDP 소켓
/// 버퍼 기본값이 작다") exists to guard against. Sizing each direction
/// from its own read-back default, independently, is what keeps a
/// well-provisioned platform's default from ever being *reduced* by this
/// tuning.
pub(crate) fn tune_socket_buffer(
    socket: &Socket,
    get: impl Fn(&Socket) -> io::Result<usize>,
    set: impl Fn(&Socket, usize) -> io::Result<()>,
) {
    let Ok(default) = get(socket) else {
        // Can't read the baseline back — nothing safe to compare against,
        // so leave the socket untouched rather than risk a reduction.
        return;
    };
    for candidate in SOCKET_BUFFER_LADDER_BYTES {
        if candidate <= default {
            // Never call `set` with a value at or below the read-back
            // default — either it would be a no-op or, on a platform that
            // honors requests literally instead of clamping them up, a
            // reduction.
            continue;
        }
        if set(socket, candidate).is_err() {
            continue;
        }
        match get(socket) {
            Ok(granted) if granted > default => return,
            _ => {
                // Didn't stick, or the OS granted something at/below the
                // default — restore before trying a smaller rung.
                let _ = set(socket, default);
            }
        }
    }
}

/// Bind a UDP socket at `addr` with `tune_socket_buffer` applied
/// independently to each direction, in place of
/// `quinn::Endpoint::client`/`::server`'s own internal bind (which offers
/// no way to ask for a bigger buffer). `dual_stack_v6` mirrors
/// `quinn::Endpoint::client`'s own best-effort `IPV6_V6ONLY` handling for
/// a wildcard v6 bind. [`Dialer::dial`](crate::endpoint::Dialer::dial)'s replacement and the listener
/// (`bind_listener_socket`, `docs/adr/0046-dual-stack-wildcard-listener.md`)
/// both pass `true`, so a `[::]` listener accepts IPv4 peers on every OS
/// instead of leaving that to the OS default (Windows opens new IPv6
/// sockets `IPV6_V6ONLY`). Failing to clear the option never fails the
/// bind. Also used by
/// `qsh_core::client::reconnect`'s migration rebind (`PathBinder`), so a
/// post-migration socket keeps the same tuning and dual-stack behavior
/// the original dial got.
///
/// Every step here is best-effort except the bind itself: a platform that
/// refuses (or silently caps) the buffer request keeps its own default,
/// which only degrades *how fast* a loopback benchmark can measure, never
/// correctness (`crates/qsh-testkit/tests/it/tunnel_throughput.rs`'s own
/// module doc walks through why the M4 DoD 3 ratio gate is tolerant of
/// this either way).
pub fn bind_tuned_udp_socket(
    addr: SocketAddr,
    dual_stack_v6: bool,
) -> io::Result<std::net::UdpSocket> {
    let socket = prepare_udp_socket(addr, dual_stack_v6)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Everything [`bind_tuned_udp_socket`] does before `bind(2)`. Split out
/// because Linux forces `IPV6_V6ONLY` on once a socket binds a specific
/// (non-wildcard) IPv6 address, so only the pre-bind state can show the
/// option was cleared on a loopback address.
pub(crate) fn prepare_udp_socket(addr: SocketAddr, dual_stack_v6: bool) -> io::Result<Socket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if dual_stack_v6 && addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    tune_socket_buffer(
        &socket,
        Socket::recv_buffer_size,
        Socket::set_recv_buffer_size,
    );
    tune_socket_buffer(
        &socket,
        Socket::send_buffer_size,
        Socket::set_send_buffer_size,
    );
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// The server-side UDP bind: [`bind_tuned_udp_socket`] with
/// `dual_stack_v6=true` (`docs/adr/0046-dual-stack-wildcard-listener.md`
/// decision 1). Kept as one helper so a test can pin the flag the
/// [`Listener`] actually uses ([`LISTENER_DUAL_STACK_V6`]).
pub(crate) fn bind_listener_socket(bind: SocketAddr) -> io::Result<std::net::UdpSocket> {
    bind_tuned_udp_socket(bind, LISTENER_DUAL_STACK_V6)
}

/// The `dual_stack_v6` argument the listener binds with.
pub(crate) const LISTENER_DUAL_STACK_V6: bool = true;
