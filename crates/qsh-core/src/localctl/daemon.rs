//! Daemon side of localctl: the bridge module (`crate::localctl` module
//! docs — the one place in this tree allowed to touch `qsh_transport`
//! indirectly, through [`crate::reverse::listen::Listen`]) that binds this
//! `qsh listen` process's UDS socket, enforces the peer-credential trust
//! boundary, and answers the `LOCAL_ADMIN` conduit
//! (`docs/design/protocol.md` §11-3, M3 plan Step 5 (2473c88), PR 5a).
//!
//! Two pieces:
//!
//! - [`LocalctlListener`] — binds `paths.localctl_socket(pid)`: creates the
//!   runtime directory 0700 if absent (fails closed if that mode cannot be
//!   pinned — [`crate::config::ensure_private_dir`]), then tightens the
//!   socket file itself to 0600.
//! - [`LocalctlDaemon`] — the accept loop and per-conduit serve logic.
//!   Every accepted connection is peer-credential-checked (this process's
//!   own euid, via [`tokio::net::UnixStream::peer_cred`] — `SO_PEERCRED` on
//!   Linux, `getpeereid` on macOS) **before a single frame is read**; a
//!   mismatch (or a failed credential lookup) is rejected silently, with no
//!   attempt to speak the protocol to a peer this process does not trust
//!   (`crate::localctl` module docs: "localctl grants no new authority").
//!   All three defined conduit kinds are served (`docs/CLI.md` §6.2's "부분
//!   실패를 감추지 않는다" discipline underlies all of them):
//!
//!   | kind | served by | shape |
//!   |---|---|---|
//!   | `LOCAL_ADMIN` | `LocalctlDaemon::serve_admin` | one `LocalAdminRequest` (`HostList` / `TunnelList` / `TunnelClose`, M4 Step 5 PR 5b) → one `LocalResponse`, from [`Listen::registry`]'s current snapshot or [`Listen::hubs_snapshot`]'s live forwards, stale entries included, never dialing anything. No `LocalHelloAck` — its fields describe a specific registered host and `LOCAL_ADMIN` names none. |
//!   | `LOCAL_CONTROL` (`M3 Step 6`) | `LocalctlDaemon::serve_control` | `LocalHelloAck`, then a long-lived `qsh.wire.v1` `ControlMessage` relay for `hello.host`'s live [`ControlHub`](crate::reverse::listen::ControlHub) — one conduit per attached CLI process, for as long as it runs. |
//!   | `LOCAL_STREAM` (`M3 Step 7`) | `LocalctlDaemon::serve_stream` | `LocalHelloAck`, then exactly one wire `StreamHeader` frame — `SESSION_DATA`, `EXEC_DATA` (issue #5), `TCP_CONNECT` or `TCP_ACCEPTED` — then a raw byte-level splice onto a fresh QUIC bidi stream on `hello.host`'s live connection; for `EXEC_DATA` only, a `LocalResponse{ClaimGranted}` ack is written first, once `open_bi` has actually succeeded (`docs/design/protocol.md` §11-3's EXEC_DATA ack leg) — the daemon never parses anything past the header (module docs' own "grants no new authority": it neither redeems nor inspects the ticket, the target does). |
//!
//!   An unspecified/unrecognized `LocalHello.kind` answers
//!   `INVALID_ARGUMENT`. None of the three paths ever calls
//!   `Authorizer::check` or an audit sink for the conduit itself, and none
//!   trusts anything the CLI side sent about its own identity — only the
//!   OS-level credential this module checked at accept time
//!   (`crate::localctl` module docs).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use qsh_proto::ErrorCode;
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LOCAL_WAIT_MAX, LocalAdminRequest, LocalClaimGranted, LocalError,
    LocalHello, LocalHelloAck, LocalHost, LocalHostListResult, LocalResponse, LocalStreamKind,
    LocalTunnel, LocalTunnelCloseResult, LocalTunnelListResult, classify_stream_kind,
    local_admin_request, local_response,
};
use qsh_proto::wire;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::config::{Paths, ensure_private_dir};
use crate::localctl::mux::{MessageKind, classify};
use crate::ops::OpError;
use crate::reverse::listen::{ConduitInbound, HubSendError, Listen};
use crate::reverse::registry::{EntryState, ReverseEntry};

use super::frame::LocalConduit;

/// This daemon's bound localctl UDS socket, plus the path it owns —
/// unlinking it is the caller's job once every accept loop tied to it has
/// stopped (`reverse/listen.rs`'s `run_listen_unix`, which composes this
/// with the QUIC accept loop's own drain).
pub struct LocalctlListener {
    listener: UnixListener,
    /// Absolute path this socket was bound at
    /// (`paths.localctl_socket(pid)`).
    pub socket_path: PathBuf,
}

impl LocalctlListener {
    /// Bind `paths.localctl_socket(pid)`:
    ///
    /// 1. Create/tighten the runtime directory to 0700
    ///    ([`ensure_private_dir`]) — **fails closed** (refuses to bind at
    ///    all) if that mode cannot be pinned, rather than binding into a
    ///    directory whose permissions this process does not actually
    ///    control (M3 plan Step 5 (a) (2473c88)).
    /// 2. Remove any leftover file at the exact socket path first — `bind`
    ///    fails with `AddrInUse` on an existing path, and a `<pid>.sock`
    ///    left over from a previous process that reused this pid (or that
    ///    crashed without unlinking) is garbage, not state to preserve
    ///    (exactly the judgment `crate::localctl::client::discover` already
    ///    makes for a stale socket it finds `ECONNREFUSED` on).
    /// 3. Tighten the socket file itself to 0600.
    pub fn bind(paths: &Paths, pid: u32) -> Result<Self, OpError> {
        let runtime_dir = paths.runtime_dir();
        ensure_private_dir(&runtime_dir)?;
        let socket_path = paths.localctl_socket(pid);
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }
        let listener =
            bind_with_narrow_umask(&socket_path).map_err(|err| bind_error(&socket_path, &err))?;
        // Belt-and-suspenders: `bind_with_narrow_umask` already creates the
        // node at 0600 (`bind(2)`'s default 0666, narrowed by the 0177
        // umask it holds for the syscall alone), but tighten it again
        // explicitly so the final mode does not depend on that umask trick
        // alone — a caller relying only on the observable end state, not
        // the mechanism, still gets exactly 0600.
        tighten_socket_mode(&socket_path).map_err(|err| bind_error(&socket_path, &err))?;
        Ok(Self {
            listener,
            socket_path,
        })
    }
}

/// Serializes the brief window [`bind_with_narrow_umask`] narrows this
/// process's umask for. `umask(2)` is process-global, not per-thread, so
/// two concurrent binds — this module's own test suite runs several
/// `LocalctlListener::bind` calls in parallel `#[tokio::test]`s — must not
/// interleave their save/restore (which could otherwise leave the
/// process's umask permanently wrong for the rest of its lifetime).
static UMASK_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Bind `path` with this process's umask narrowed to `0o177` (owner
/// read/write kept, everything else stripped) for the `bind(2)` syscall
/// alone, restored immediately after regardless of outcome — so the socket
/// node `bind(2)` creates (which has no mode parameter for `AF_UNIX`,
/// unlike `open(2)`) is never observable at a mode looser than 0600, not
/// even for the instant between `bind(2)` and an explicit `chmod`
/// (adversarial review finding: without this, the node briefly existed at
/// `0666 & ~umask` — typically 0644/0755-shaped — before
/// [`tighten_socket_mode`] ran).
fn bind_with_narrow_umask(path: &Path) -> io::Result<UnixListener> {
    let _guard = UMASK_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: `umask(2)` reads and writes only this process's umask; it
    // touches no memory and cannot fail. The lock above is what makes the
    // save/restore pair race-free against another thread's call to this
    // same function — `umask` itself has no thread-local variant to lean
    // on instead.
    let previous = unsafe { libc::umask(0o177) };
    let result = UnixListener::bind(path);
    unsafe { libc::umask(previous) };
    result
}

fn tighten_socket_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn bind_error(path: &Path, err: &io::Error) -> OpError {
    OpError::new(
        ErrorCode::ConfigError,
        format!("localctl: cannot bind {}: {err}", path.display()),
    )
}

/// Upper bound on connections *still being handshaked* (peer-cred check
/// through `LocalHello`/kind classification) — not a wire contract value
/// (unlike [`LOCAL_WAIT_MAX`]), just this process's own resource-hygiene
/// ceiling on spawned tasks and fds during the brief pre-classification
/// window. Deliberately the same magnitude as
/// [`crate::server::MAX_INFLIGHT_REQUESTS_PER_CONN`] rather than an
/// unrelated number invented for this file (PR 5a's accept loop had no
/// bound at all — adversarial review finding: an unbounded burst of
/// same-uid connections that never wrote a byte pinned a task and fd per
/// connection for the daemon's lifetime).
///
/// This permit is released as soon as [`LocalctlDaemon::serve_authorized_conduit`]
/// classifies `LocalHello.kind` and hands the conduit off to its
/// kind-specific pool ([`MAX_CONCURRENT_LOCAL_ADMIN_QUERIES`]/
/// [`MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS`]) — it never bounds how long a
/// classified conduit itself runs (adversarial review finding: Step 6 made
/// `LOCAL_CONTROL` conduits long-lived, up to the whole life of a `session
/// read --follow`; sharing one pool across the brief handshake, brief
/// `LOCAL_ADMIN` round trips, and those long-lived sessions let enough
/// concurrent sessions silently starve new `LOCAL_ADMIN` discovery — the
/// very query `resolve_host_route` depends on — of a connection at all).
const MAX_CONCURRENT_LOCALCTL_HANDSHAKES: usize = 64;

/// Upper bound on concurrent `LOCAL_ADMIN` round trips (`qsh hosts`/`host
/// get`/routing discovery) — its own pool, entirely separate from
/// [`MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS`], so a daemon saturated with
/// long-lived control sessions never blocks a fresh discovery query.
const MAX_CONCURRENT_LOCAL_ADMIN_QUERIES: usize = 64;

/// Upper bound on concurrent `LOCAL_CONTROL` conduits — these are
/// long-lived (one per attached CLI process, for as long as it runs), so
/// this pool is sized generously above [`MAX_CONCURRENT_LOCAL_ADMIN_QUERIES`]
/// rather than sharing it: ordinary use (many concurrent `session read
/// --follow`/interactive attaches) must never compete with `LOCAL_ADMIN`
/// discovery for the same permit.
const MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS: usize = 256;

/// Upper bound on concurrent `LOCAL_STREAM` conduits (`M3 Step 7`) — one
/// per active attach data stream, each held open for as long as that
/// attach runs, exactly like [`MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS`]'s
/// `LOCAL_CONTROL` conduits (indeed the two grow together in practice: a
/// live attach is one of each). Its own pool for the same reason
/// [`MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS`] is its own pool — a burst of
/// long-lived data streams must never starve `LOCAL_ADMIN`/`LOCAL_CONTROL`
/// of a permit, or vice versa.
///
/// Kept comfortably under `qsh_transport`'s own
/// `max_concurrent_bidi_streams` (set well above this pool specifically so
/// this cap is always the one that bites first, `endpoint.rs`'s own doc):
/// a peer permit exhausted at the transport layer instead of here means
/// `open_bi` parks in [`OPEN_DATA_STREAM_TIMEOUT`] and then fails closed
/// with [`RESET_CODE_LOCAL_CONDUIT_FAILED`] rather than answering the
/// clean, bounded [`ErrorCode::ResourceExhausted`] this pool exists to
/// produce.
const MAX_CONCURRENT_LOCAL_STREAM_CONDUITS: usize = 256;

/// Bound on [`qsh_transport::Connection::open_bi`] in [`LocalctlDaemon::serve_stream`]
/// — opening a stream on an already-established, healthy connection is
/// normally near-instant; a wait this long only happens when the peer's
/// own concurrent-stream limit is exhausted (`MAX_CONCURRENT_LOCAL_STREAM_CONDUITS`'s
/// doc explains why that should not happen before this pool's own cap
/// does). Bounding it at all is the point: an unbounded `await` here holds
/// the stream permit acquired just before it forever, so a peer at its
/// limit would silently wedge every later `LOCAL_STREAM` attach behind
/// this one instead of the `ResourceExhausted` envelope callers can act
/// on.
const OPEN_DATA_STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Reset code the `LOCAL_STREAM` splice sends on the QUIC side when the
/// UDS side ended abnormally (a read error, not a clean EOF) — the honest
/// signal that sync with the local peer was lost, distinct from
/// [`crate::server::RESET_CODE_BAD_HEADER`] and friends (those describe
/// *why the target itself* rejected a stream; this describes a failure on
/// the daemon's own local-IPC leg, before the target is even involved in
/// the failure).
const RESET_CODE_LOCAL_CONDUIT_FAILED: u32 = 0x2005;

/// `STOP_SENDING`/reset code the `LOCAL_STREAM` splice's two pumps send
/// on the QUIC side when their *sibling* leg ends first — the local CLI
/// conduit is a single logical peer, so once either half of it is gone
/// the other half is never coming back either, and holding a QUIC bidi
/// stream half-open waiting for input/output nobody will ever supply is
/// exactly the leak `pump_uds_to_quic`/`pump_quic_to_uds`'s cross-leg
/// cancellation exists to close (a detach otherwise pins one of
/// [`MAX_CONCURRENT_LOCAL_STREAM_CONDUITS`] forever on an idle session —
/// see the two functions' own docs).
const RESET_CODE_LOCAL_PEER_GONE: u32 = 0x2006;

/// Delay the accept loop pays after a failed `accept()` before retrying —
/// long enough that a persistent failure (EMFILE/ENFILE) does not spin the
/// loop hot burning CPU and flooding stderr, short enough that a single
/// transient failure barely delays the next real connection.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// The daemon side of one `qsh listen` process's localctl surface. Reads
/// through [`Listen::registry`] only — never [`Listen`]'s live connection
/// table — so there is no lock-order interaction with the probe
/// driver/sweeper that touch `conns` (`reverse/listen.rs` module docs:
/// `Registry` and the connection table are two separate locks, never held
/// together).
pub struct LocalctlDaemon {
    listen: Arc<Listen>,
    /// Separate from the handshake pool acquired in [`Self::run`] — see
    /// [`MAX_CONCURRENT_LOCAL_ADMIN_QUERIES`]'s doc for why `LOCAL_ADMIN`
    /// must never compete with `LOCAL_CONTROL` for the same permit.
    admin_permits: Arc<Semaphore>,
    /// Separate from both the handshake pool and [`Self::admin_permits`]
    /// — see [`MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS`]'s doc.
    control_permits: Arc<Semaphore>,
    /// Separate from the handshake pool and both sibling pools — see
    /// [`MAX_CONCURRENT_LOCAL_STREAM_CONDUITS`]'s doc.
    stream_permits: Arc<Semaphore>,
}

impl LocalctlDaemon {
    /// Build a daemon answering from `listen`'s registry.
    pub fn new(listen: Arc<Listen>) -> Arc<Self> {
        Self::with_pool_sizes(
            listen,
            MAX_CONCURRENT_LOCAL_ADMIN_QUERIES,
            MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS,
            MAX_CONCURRENT_LOCAL_STREAM_CONDUITS,
        )
    }

    /// [`Self::new`] with explicitly chosen pool sizes — tests use this to
    /// saturate one of the three independent permit pools without needing
    /// hundreds of real connections.
    fn with_pool_sizes(
        listen: Arc<Listen>,
        admin: usize,
        control: usize,
        stream: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            listen,
            admin_permits: Arc::new(Semaphore::new(admin)),
            control_permits: Arc::new(Semaphore::new(control)),
            stream_permits: Arc::new(Semaphore::new(stream)),
        })
    }

    /// Accept loop: run until `shutdown` resolves, spawning one task per
    /// accepted connection, up to `MAX_CONCURRENT_LOCALCTL_HANDSHAKES`
    /// concurrently *while unclassified* — `Self::serve_authorized_conduit`
    /// releases this permit the moment it knows `LocalHello.kind` and
    /// switches to that kind's own pool, so this bound never limits how
    /// many classified conduits run at once. A single failed `accept` is
    /// logged (after a brief backoff — see `ACCEPT_ERROR_BACKOFF`'s doc)
    /// and does not end the loop — one bad connection attempt must not
    /// take the whole daemon down.
    pub async fn run(
        self: Arc<Self>,
        bound: LocalctlListener,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_LOCALCTL_HANDSHAKES));
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = bound.listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            // Never blocks the accept loop itself: at the
                            // cap, the new connection is simply dropped
                            // (closed) rather than served, so a burst of
                            // same-uid connections cannot starve the
                            // daemon's fd table or task count
                            // (adversarial review finding — previously
                            // unbounded).
                            match permits.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let this = self.clone();
                                    tokio::spawn(async move {
                                        this.serve_conduit(stream, permit).await;
                                    });
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        "localctl: at the handshake cap ({MAX_CONCURRENT_LOCALCTL_HANDSHAKES}); \
                                         dropping a new connection"
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            tracing::warn!(%err, "localctl: accept failed");
                            // A persistent accept failure (EMFILE/ENFILE)
                            // would otherwise spin this loop hot, burning
                            // CPU and flooding stderr with no chance for
                            // the fd pressure to ease; a transient one
                            // pays a single short, bounded delay.
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        }
                    }
                }
            }
        }
    }

    /// Peer-credential-check, then dispatch on `LocalHello.kind`. Every
    /// return path here is a plain function return — nothing in this
    /// module ever panics on a malformed or unexpected peer message
    /// (M3 plan Step 5 (2473c88): "never a panic or a hang").
    async fn serve_conduit(
        self: Arc<Self>,
        stream: UnixStream,
        handshake_permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let authorized = Self::authorized_peer(&stream);
        self.serve_authorized_conduit(stream, authorized, handshake_permit)
            .await;
    }

    /// The rest of [`Self::serve_conduit`], taking the peer-credential
    /// check's outcome as a parameter rather than computing it itself.
    ///
    /// This split exists purely so the enforcement wiring is
    /// unit-testable: [`Self::serve_conduit`] cannot be driven with a
    /// rejected peer without a second real OS user (`daemon_euid`'s
    /// `unsafe { libc::geteuid() }` has no injectable seam), so nothing
    /// previously asserted that a `false`/`Err` outcome from
    /// [`Self::authorized_peer`] actually stops this function from ever
    /// reading a frame — an adversarial review confirmed this by deleting
    /// the gate entirely and finding every localctl test still green. This
    /// function is what the negative-outcome test drives directly, with a
    /// literal `Ok(false)` standing in for a genuinely different euid.
    async fn serve_authorized_conduit(
        self: Arc<Self>,
        stream: UnixStream,
        authorized: io::Result<bool>,
        handshake_permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        match authorized {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    "localctl: rejected a connecting peer whose euid did not match this daemon's"
                );
                return;
            }
            Err(err) => {
                tracing::warn!(%err, "localctl: peer credential check failed; rejecting");
                return;
            }
        }

        let mut conduit = LocalConduit::new(stream);
        // Bounded by `LOCAL_WAIT_MAX` — the same ceiling
        // `LocalHello.wait_ms` itself is clamped to (`qsh/local/v1.proto`:
        // "so one caller cannot pin a daemon slot open indefinitely") —
        // applied here to the handshake itself: a same-uid peer that
        // connects and never writes a byte would otherwise pin a spawned
        // task and an fd for this daemon's entire lifetime (adversarial
        // review finding).
        let hello: LocalHello = match tokio::time::timeout(LOCAL_WAIT_MAX, conduit.recv()).await {
            Ok(Ok(Some(hello))) => hello,
            Ok(Ok(None)) | Ok(Err(_)) => return,
            Err(_elapsed) => {
                tracing::warn!(
                    "localctl: peer connected but never sent a LocalHello within {LOCAL_WAIT_MAX:?}; closing"
                );
                return;
            }
        };

        if hello.version != LOCAL_HELLO_VERSION {
            // Fail closed on a version this build does not speak, exactly
            // the discipline the sibling `kind` check applies to an
            // unset/unknown `LocalStreamKind` — `qsh listen` is resident
            // and can genuinely outlive a CLI upgrade, so serving an
            // unrecognized version as if it were `LOCAL_HELLO_VERSION` is
            // the wrong default (adversarial review finding: this check
            // did not exist at all).
            let _ = conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::Error(LocalError::from_code(
                        ErrorCode::Unsupported,
                        format!(
                            "this daemon speaks localctl protocol version {LOCAL_HELLO_VERSION}, \
                             not {}",
                            hello.version
                        ),
                    ))),
                })
                .await;
            return;
        }

        let kind = match classify_stream_kind(hello.kind) {
            Ok(kind) => kind,
            Err(code) => {
                let _ = conduit
                    .send(&LocalResponse {
                        body: Some(local_response::Body::Error(LocalError::from_code(
                            code,
                            "LocalHello.kind is unset or not a value this daemon recognizes",
                        ))),
                    })
                    .await;
                return;
            }
        };

        match kind {
            // Kind is known — hand off from the shared handshake pool to
            // this kind's own pool (`MAX_CONCURRENT_LOCAL_ADMIN_QUERIES`'s
            // doc: `LOCAL_ADMIN` must never be starved by long-lived
            // `LOCAL_CONTROL` conduits sharing one pool with it,
            // adversarial review finding). At that pool's own cap, answer
            // `RESOURCE_EXHAUSTED` explicitly rather than silently closing
            // — `admin_host_list_all`/`resolve_host_route` must be able to
            // tell "daemon saturated" apart from "no such host"
            // (`docs/CLI.md` §6.2's "부분 실패를 감추지 않는다").
            LocalStreamKind::LocalAdmin => match self.admin_permits.clone().try_acquire_owned() {
                Ok(_admin_permit) => {
                    drop(handshake_permit);
                    self.serve_admin(conduit).await;
                }
                Err(_) => {
                    let _ = conduit
                        .send(&LocalResponse {
                            body: Some(local_response::Body::Error(LocalError::from_code(
                                ErrorCode::ResourceExhausted,
                                "too many concurrent LOCAL_ADMIN queries on this daemon; retry shortly",
                            ))),
                        })
                        .await;
                }
            },
            // `M3 Step 6`: the daemon's second localctl consumer — a
            // control session for `hello.host` (module docs, the M3 plan (2473c88)
            // M3 Step 6's "localctl의 두 번째 소비자... 이것이 M3의 유일한
            // 신규 상태 기계"). Long-lived, so it gets its own pool
            // (`MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS`) rather than the
            // brief handshake pool.
            LocalStreamKind::LocalControl => {
                match self.control_permits.clone().try_acquire_owned() {
                    Ok(_control_permit) => {
                        drop(handshake_permit);
                        self.serve_control(
                            &hello.host,
                            hello.wait_ms,
                            hello.known_generation,
                            conduit,
                        )
                        .await;
                    }
                    Err(_) => {
                        let _ = conduit
                            .send(&LocalResponse {
                                body: Some(local_response::Body::Error(LocalError::from_code(
                                    ErrorCode::ResourceExhausted,
                                    "too many concurrent LOCAL_CONTROL conduits on this daemon; \
                                     retry shortly",
                                ))),
                            })
                            .await;
                    }
                }
            }
            // `LOCAL_STREAM` (`M3 Step 7`): the attach data splice, its
            // own pool for the same reason `LOCAL_CONTROL` has one
            // (`MAX_CONCURRENT_LOCAL_STREAM_CONDUITS`'s doc).
            LocalStreamKind::LocalStream => match self.stream_permits.clone().try_acquire_owned() {
                Ok(_stream_permit) => {
                    drop(handshake_permit);
                    self.serve_stream(&hello.host, hello.wait_ms, hello.known_generation, conduit)
                        .await;
                }
                Err(_) => {
                    let _ = conduit
                        .send(&LocalResponse {
                            body: Some(local_response::Body::Error(LocalError::from_code(
                                ErrorCode::ResourceExhausted,
                                "too many concurrent LOCAL_STREAM conduits on this daemon; \
                                     retry shortly",
                            ))),
                        })
                        .await;
                }
            },
            // `classify_stream_kind` only ever hands back a known,
            // non-`Unspecified` variant (its own doc/test coverage) —
            // every real kind is matched above, so this is unreachable in
            // practice; answered explicitly rather than with `unreachable!()`
            // so a future new variant this match has not been updated for
            // fails as "gets an envelope back", not a panic.
            LocalStreamKind::LocalUnspecified => {
                let _ = conduit
                    .send(&LocalResponse {
                        body: Some(local_response::Body::Error(LocalError::from_code(
                            ErrorCode::InvalidArgument,
                            "LocalHello.kind is unset or not a value this daemon recognizes",
                        ))),
                    })
                    .await;
            }
        }
    }

    /// `LOCAL_ADMIN`: read one [`LocalAdminRequest`] and answer with
    /// exactly one [`LocalResponse`] — `HostList`
    /// ([`Self::serve_admin_host_list`], M3 plan Step 5 (2473c88)) / `TunnelList`
    /// ([`Self::serve_admin_tunnel_list`], M4 plan Step 5 (2473c88) PR 5b) /
    /// `TunnelClose` ([`Self::serve_admin_tunnel_close`], same PR). The
    /// request is read through the `LocalAdminRequest` envelope, not a bare
    /// top-level message (`qsh/local/v1.proto`'s own doc on that type: two
    /// of these three request shapes are fieldless and therefore wire-
    /// identical, so a bare top-level message could never tell them
    /// apart).
    async fn serve_admin(&self, mut conduit: LocalConduit<UnixStream>) {
        let request = match conduit.recv::<LocalAdminRequest>().await {
            Ok(Some(request)) => request,
            Ok(None) | Err(_) => return,
        };
        match request.body {
            Some(local_admin_request::Body::HostList(_)) => {
                self.serve_admin_host_list(conduit).await;
            }
            Some(local_admin_request::Body::TunnelList(_)) => {
                self.serve_admin_tunnel_list(conduit).await;
            }
            Some(local_admin_request::Body::TunnelClose(close)) => {
                self.serve_admin_tunnel_close(conduit, &close.tunnel_id)
                    .await;
            }
            None => {
                let _ = conduit
                    .send(&LocalResponse {
                        body: Some(local_response::Body::Error(LocalError::from_code(
                            ErrorCode::InvalidArgument,
                            "LocalAdminRequest has no body set",
                        ))),
                    })
                    .await;
            }
        }
    }

    /// `HostList` arm of [`Self::serve_admin`]: this controller's current
    /// registry snapshot — every entry, live or stale, never filtered and
    /// never dialed (`docs/CLI.md` §6.2, module docs).
    async fn serve_admin_host_list(&self, mut conduit: LocalConduit<UnixStream>) {
        let hosts = self
            .listen
            .registry()
            .snapshot()
            .into_iter()
            .map(to_local_host)
            .collect();
        let _ = conduit
            .send(&LocalResponse {
                body: Some(local_response::Body::HostListResult(LocalHostListResult {
                    hosts,
                })),
            })
            .await;
    }

    /// `TunnelList` arm of [`Self::serve_admin`] (M4 plan Step 5 (2473c88) PR
    /// 5b, `qsh tunnels`): every forward this controller currently holds,
    /// across every registered reverse host — structural fields only
    /// ([`crate::reverse::listen::hub::ForwardSummary`]'s own doc), never a
    /// payload byte. `host` is filled in from the name each
    /// [`Listen::hubs_snapshot`] entry is keyed under, the same "this
    /// table's own key is the alias" pattern [`to_local_host`] relies on
    /// for `LocalHost.name`.
    async fn serve_admin_tunnel_list(&self, mut conduit: LocalConduit<UnixStream>) {
        let tunnels = self
            .listen
            .hubs_snapshot()
            .into_iter()
            .flat_map(|(host, hub)| {
                hub.list_forwards()
                    .into_iter()
                    .map(move |forward| LocalTunnel {
                        tunnel_id: forward.forward_id,
                        mode: forward.mode.to_string(),
                        bind: forward.bind,
                        forward_to: forward.forward_to,
                        actual_port: forward.actual_port,
                        host: host.clone(),
                    })
            })
            .collect();
        let _ = conduit
            .send(&LocalResponse {
                body: Some(local_response::Body::TunnelListResult(
                    LocalTunnelListResult { tunnels },
                )),
            })
            .await;
    }

    /// `TunnelClose` arm of [`Self::serve_admin`] (M4 plan Step 5 (2473c88) PR
    /// 5b, `qsh tunnel close <id>`): search every registered reverse
    /// host's hub for `tunnel_id` and close it via
    /// [`ControlHub::admin_close_forward`](crate::reverse::listen::ControlHub::admin_close_forward)
    /// — that method's own doc is where the "who may ask the daemon to do
    /// this" authorization decision (`docs/CLI.md` §2.5's owning-peer
    /// clause) actually lives; this arm only has to find the right hub.
    /// `closed: false` (never an error) when no hub currently holds
    /// `tunnel_id` — same idempotent-not-error shape every other
    /// `tunnel.close`-on-an-unknown-id outcome has.
    ///
    /// **Ambiguity is refused, not resolved by picking one (adversarial-
    /// review finding).** `tunnel_id` is `forward_id`, which is
    /// target-minted (`ControlHub`'s own §11-3 doc: shape-checked by
    /// [`wire::valid_forward_id`] only, never guaranteed unique *across*
    /// hosts — only within one hub's own table). `LocalTunnelClose` has
    /// no `host` to disambiguate with (unlike [`LocalTunnel::host`] on the
    /// listing side), so if the id names a live forward on **more than
    /// one** registered host's hub at once, there is no principled way to
    /// pick the intended one from this call alone. The old shape
    /// (`Iterator::any`, first match over a `HashMap`'s nondeterministic
    /// iteration order) silently closed whichever hub happened to be
    /// checked first — a real, if narrow, "closes the wrong host's
    /// tunnel" failure mode a colliding id (accidental, or a non-ULID-
    /// minting peer) could trigger. Refusing instead follows this
    /// codebase's own default (`CLAUDE.md`: "Fail closed on any ambiguous
    /// auth/ACL state") — no forward is torn down, `closed: false`, and a
    /// structural warning names the id and the match count only (never a
    /// host or any payload).
    async fn serve_admin_tunnel_close(
        &self,
        mut conduit: LocalConduit<UnixStream>,
        tunnel_id: &str,
    ) {
        let hubs = self.listen.hubs_snapshot();
        let closed = match crate::reverse::listen::tunnel_close_target(&hubs, tunnel_id) {
            crate::reverse::listen::TunnelCloseTarget::None => false,
            crate::reverse::listen::TunnelCloseTarget::One(hub) => {
                hub.admin_close_forward(tunnel_id)
            }
            crate::reverse::listen::TunnelCloseTarget::Ambiguous(count) => {
                tracing::warn!(
                    tunnel_id,
                    hosts = count,
                    "qsh::localctl: tunnel_id matched forwards on more than one registered \
                     host; refusing to guess which one — closing none (fail closed)"
                );
                false
            }
        };
        let _ = conduit
            .send(&LocalResponse {
                body: Some(local_response::Body::TunnelCloseResult(
                    LocalTunnelCloseResult { closed },
                )),
            })
            .await;
    }

    /// `LOCAL_CONTROL`: relay `qsh.wire.v1` `ControlMessage`/`Response`
    /// between this conduit and `host`'s live reverse QUIC control stream
    /// (`docs/design/protocol.md` §11-3, M3 plan Step 6 (2473c88)). Resolves
    /// `host` in [`Listen::control_hub_wait`] first — live (and, when
    /// `wait_ms > 0`, a registration that arrives within the wait window —
    /// M3 plan Step 8 (2473c88)'s daemon-side half of `LocalReconnect`) gets a
    /// `LocalHelloAck` and this conduit is registered with its
    /// [`crate::reverse::listen::ControlHub`]; nothing found by the
    /// deadline gets `HOST_NOT_FOUND` and nothing else. `known_generation`
    /// gates *which* live registration counts — see
    /// [`Listen::control_hub_wait`]'s own doc for why `None` (every pre-
    /// Step-8 caller) is unchanged from the old immediate-only behavior
    /// and `Some(g)` never accepts a hub still at generation `g` itself.
    ///
    /// After the ack, this loop is the *only* reader/writer of `conduit`'s
    /// UDS stream: every inbound `ControlMessage` is either a `Ping`
    /// (answered locally, never forwarded — `Self`'s module docs) or
    /// forwarded through the hub (`RESOURCE_EXHAUSTED` answered locally,
    /// on this conduit only, if the hub's per-conduit cap is already hit);
    /// every hub delivery ([`ConduitInbound`]) becomes exactly one
    /// outbound frame. Ends on a UDS read error/EOF (this conduit's own
    /// death — the hub's in-flight work for it is unregistered) or a
    /// [`ConduitInbound::HostDead`] delivery (the host's reverse
    /// connection died — `docs/design/protocol.md` §11-3's "그 host의 모든
    /// conduit이 명확한 typed error로 함께 끝난다": closing this UDS stream
    /// here gives the CLI-side `Session` reading it the same
    /// `ClientError::Protocol` a genuinely dead QUIC control stream would).
    async fn serve_control(
        &self,
        host: &str,
        wait_ms: u32,
        known_generation: Option<u64>,
        mut conduit: LocalConduit<UnixStream>,
    ) {
        let deadline = clamp_wait(wait_ms);
        let Some(hub) = self
            .listen
            .control_hub_wait(host, known_generation, deadline)
            .await
        else {
            let _ = conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::Error(LocalError::from_code(
                        ErrorCode::HostNotFound,
                        format!("{host} is not a currently reachable registered host"),
                    ))),
                })
                .await;
            return;
        };

        let (ack_host, peer_fingerprint, generation, capabilities) = hub.ack_fields();
        if conduit
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: ack_host,
                    peer_fingerprint,
                    generation,
                    capabilities,
                })),
            })
            .await
            .is_err()
        {
            return;
        }

        let (conduit_id, mut inbox) = hub.register_conduit();

        loop {
            tokio::select! {
                biased;
                incoming = conduit.recv::<wire::ControlMessage>() => {
                    let msg = match incoming {
                        Ok(Some(msg)) => msg,
                        Ok(None) | Err(_) => break,
                    };
                    let request_id = msg.request_id;
                    let Some(body) = msg.body else {
                        // Empty/unrecognized on this conduit — nothing to
                        // relay; answer this one request only.
                        let reply = wire::ControlMessage::new(
                            request_id,
                            wire::control_message::Body::Response(wire::Response {
                                body: Some(wire::response::Body::Error(wire::Error::new(
                                    ErrorCode::InvalidArgument,
                                    "empty ControlMessage body",
                                    false,
                                ))),
                            }),
                        );
                        if conduit.send(&reply).await.is_err() {
                            break;
                        }
                        continue;
                    };
                    match classify(&body) {
                        // Never forwarded onto the QUIC connection —
                        // liveness is the daemon's own job (module docs,
                        // `docs/design/protocol.md` §11-3).
                        MessageKind::Ping => {
                            let pong = wire::ControlMessage::new(
                                request_id,
                                wire::control_message::Body::Pong(wire::Pong {}),
                            );
                            if conduit.send(&pong).await.is_err() {
                                break;
                            }
                        }
                        MessageKind::Request => match hub.send_request(conduit_id, request_id, body) {
                            Ok(()) => {}
                            Err(HubSendError::Exhausted) => {
                                let reply = wire::ControlMessage::new(
                                    request_id,
                                    wire::control_message::Body::Response(wire::Response {
                                        body: Some(wire::response::Body::Error(wire::Error::new(
                                            ErrorCode::ResourceExhausted,
                                            "too many in-flight requests on this control conduit",
                                            true,
                                        ))),
                                    }),
                                );
                                if conduit.send(&reply).await.is_err() {
                                    break;
                                }
                            }
                            // Adversarial-review hole 3: this conduit
                            // asked to close a `forward_id` another
                            // conduit on this hub owns. Nothing was
                            // allocated and nothing reached the target
                            // (`ControlHub::send_request`'s own
                            // `NotOwner` doc — the daemon is the only
                            // component that can tell two CLI conduits
                            // apart, so refusing here is the only place
                            // it can be refused at all). Answered on this
                            // conduit only, exactly like the exhaustion
                            // case above; the owning conduit never learns
                            // the attempt happened and its registration is
                            // untouched.
                            Err(HubSendError::NotOwner) => {
                                // Deliberately NOT `crate::acl::
                                // PERMISSION_DENIED_MESSAGE`: this is the
                                // same-uid local trust boundary between two
                                // local clients of this daemon, not the
                                // remote-peer authorization layer that
                                // constant is reserved for (`docs/design/
                                // protocol.md` §11-3, M5 plan Step 4 (2473c88)
                                // §4.2 — `crate::acl::
                                // PERMISSION_DENIED_MESSAGE`'s own doc).
                                let reply = wire::ControlMessage::new(
                                    request_id,
                                    wire::control_message::Body::Response(wire::Response {
                                        body: Some(wire::response::Body::Error(wire::Error::new(
                                            ErrorCode::PermissionDenied,
                                            "this forward is owned by another client on this host",
                                            false,
                                        ))),
                                    }),
                                );
                                if conduit.send(&reply).await.is_err() {
                                    break;
                                }
                            }
                            Err(HubSendError::HostDead) => break,
                        },
                        // A conduit sent a body shape it must never send
                        // (`Pong`/`Response`/`SessionEvent`/`Hello`) —
                        // answered locally on this conduit only, exactly
                        // like the empty-body case above; never touches
                        // the hub or the shared QUIC connection
                        // (`classify`'s own doc comment, adversarial
                        // review finding).
                        MessageKind::Invalid => {
                            let reply = wire::ControlMessage::new(
                                request_id,
                                wire::control_message::Body::Response(wire::Response {
                                    body: Some(wire::response::Body::Error(wire::Error::new(
                                        ErrorCode::InvalidArgument,
                                        "this ControlMessage body is not a shape a conduit may send",
                                        false,
                                    ))),
                                }),
                            );
                            if conduit.send(&reply).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                inbound = inbox.recv() => {
                    let outgoing = match inbound {
                        Some(ConduitInbound::Response { peer_request_id, body }) => {
                            wire::ControlMessage::new(
                                peer_request_id,
                                wire::control_message::Body::Response(body),
                            )
                        }
                        Some(ConduitInbound::Event(event)) => wire::ControlMessage::new(
                            0,
                            wire::control_message::Body::SessionEvent(event),
                        ),
                        Some(ConduitInbound::HostDead) | None => break,
                    };
                    if conduit.send(&outgoing).await.is_err() {
                        break;
                    }
                }
            }
        }

        hub.unregister_conduit(conduit_id);
    }

    /// `LOCAL_STREAM` (`M3 Step 7`, `EXEC_DATA` relay added by issue #5):
    /// after the same `HOST_NOT_FOUND`/`LocalHelloAck`
    /// handshake [`Self::serve_control`] uses (including its
    /// `wait_ms`/`known_generation` wait, M3 plan Step 8 (2473c88) — the
    /// data-conduit half of `LocalReconnect`'s new leg), read exactly one
    /// wire `StreamHeader` frame ([`local_stream_relay_kind`] decides
    /// which kinds are relayable at all), open a fresh QUIC bidi stream on
    /// `host`'s live connection at that kind's own send priority, forward
    /// the header verbatim, and become a raw byte-level pump both ways
    /// (`docs/design/protocol.md` §11-3, §12). Never parses a
    /// `SessionFrame`/`ExecFrame`, never redeems or inspects `ticket` —
    /// that is the target's job; a forged or expired ticket is the
    /// target's reset, relayed to the CLI exactly as any other QUIC-side
    /// termination would be (module docs' kind table).
    async fn serve_stream(
        &self,
        host: &str,
        wait_ms: u32,
        known_generation: Option<u64>,
        mut conduit: LocalConduit<UnixStream>,
    ) {
        let deadline = clamp_wait(wait_ms);
        // `deadline` is the CLI's *one* total wait budget for this whole
        // call, not a per-phase allowance handed out fresh at each step
        // (adversarial-review finding: `serve_tcp_accepted` used to
        // receive this same `deadline` value unmodified, so a call that
        // had already spent real time parked in `connection_for_wait`
        // below — the ordinary case right after a target reconnects and
        // its hub has not republished yet — got a *second* full
        // `deadline` for its `claim_tcp_accepted` park, doubling the
        // daemon's total wait past what the CLI's own
        // `wait_ms + PROBE_TIMEOUT` timeout (`localctl::client::
        // open_stream_over_with_wait`) is actually bounded by. A claim
        // still parked after the CLI has given up and retried on a fresh
        // conduit is an orphan that can win the race for an arrival the
        // retry was waiting for. `wait_start` is measured on
        // `tokio::time`'s clock (not the injectable `Clock` trait) on
        // purpose: [`ControlHub::claim_tcp_accepted`]'s own parked wait
        // is a raw `tokio::time::timeout`, and [`Listen::connection_for_wait`]'s
        // poll sleeps through [`crate::broker::SystemClock`], which
        // itself wraps the same tokio timer in production — so this is
        // the one clock both phases already answer to, paused/advanced
        // together under `tokio::time::pause()` in a test exactly the way
        // production timing composes.
        let wait_start = tokio::time::Instant::now();
        let Some((conn, hub)) = self
            .listen
            .connection_for_wait(host, known_generation, deadline)
            .await
        else {
            let _ = conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::Error(LocalError::from_code(
                        ErrorCode::HostNotFound,
                        format!("{host} is not a currently reachable registered host"),
                    ))),
                })
                .await;
            return;
        };

        let (ack_host, peer_fingerprint, generation, capabilities) = hub.ack_fields();
        if conduit
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: ack_host,
                    peer_fingerprint,
                    generation,
                    capabilities,
                })),
            })
            .await
            .is_err()
        {
            return;
        }

        // Bounded by the same ceiling the `LocalHello` read itself is
        // bounded by (`LOCAL_WAIT_MAX`'s own doc: no caller pins a daemon
        // slot open indefinitely) — a same-uid peer that completes the
        // handshake and then never sends the follow-up header would
        // otherwise hold this conduit's permit forever.
        //
        // Read as raw, still-unparsed payload bytes
        // (`LocalConduit::recv_payload`'s own doc) — decoded once here for
        // this function's own checks, but *those bytes*, not a re-encode
        // of the decoded struct, are what get forwarded onto the QUIC data
        // stream below, so an additive `StreamHeader` field this build
        // does not know about survives the relay untouched.
        let raw_header = match tokio::time::timeout(LOCAL_WAIT_MAX, conduit.recv_payload()).await {
            Ok(Ok(Some(raw))) => raw,
            Ok(Ok(None)) | Ok(Err(_)) => return,
            Err(_elapsed) => {
                tracing::warn!(
                    "localctl: LOCAL_STREAM peer connected but never sent a StreamHeader within \
                     {LOCAL_WAIT_MAX:?}; closing"
                );
                return;
            }
        };
        let header: wire::StreamHeader = match wire::decode_msg(&raw_header) {
            Ok(header) => header,
            Err(_) => return,
        };

        // `M4 Step 5` added `TCP_CONNECT`/`TCP_ACCEPTED` alongside
        // `SESSION_DATA`; issue #5 adds `EXEC_DATA` the same way
        // — `docs/design/protocol.md` §11-3's "터널 conduit은 새
        // LocalStreamKind를 얻지 않는다" applies to it too. `TCP_ACCEPTED`
        // is different in kind, not degree — no `open_bi` at all, because
        // the QUIC stream it splices onto already exists (the target
        // opened it; `Listen::run_tunnel_accept_loop` accepted it) — so it
        // is handled by [`Self::serve_tcp_accepted`] and returns before any
        // of the `open_bi` machinery below ever runs. Every other
        // relayable kind takes the exact same open-a-fresh-QUIC-bidi-and-
        // splice path (this daemon never distinguishes a session byte from
        // a tunnel or exec byte — all three are opaque past the header);
        // [`local_stream_relay_kind`] is the one place that decides which
        // kinds are relayable at all and how, so a mutation here cannot
        // silently diverge from what this function's own unit tests
        // assert (`local_stream_relay_kind`'s own doc).
        let (priority, tunnel_permit, reset_on_uds_eof, ack_before_splice) =
            match local_stream_relay_kind(&header) {
                Some(LocalStreamRelay::ClaimTcpAccepted) => {
                    // What is left of the *one* `deadline` budget after
                    // `connection_for_wait` above (and the header read just
                    // above this match) already spent part of it —
                    // `wait_start`'s own doc on why handing `serve_tcp_accepted`
                    // a second full `deadline` here would let its parked claim
                    // outlive the CLI's own timeout. Saturating: a slow
                    // handshake that already ate the whole budget hands the
                    // claim `Duration::ZERO`, which still runs
                    // `claim_tcp_accepted`'s first, pre-`await` check (an
                    // already-queued arrival is still granted at once) but
                    // never actually parks.
                    self.serve_tcp_accepted(
                        &hub,
                        &conn,
                        &header,
                        deadline.saturating_sub(wait_start.elapsed()),
                        conduit,
                    )
                    .await;
                    return;
                }
                Some(LocalStreamRelay::OpenBidiAndSplice {
                    priority,
                    tunnel_permit,
                    reset_on_uds_eof,
                    ack_before_splice,
                }) => (priority, tunnel_permit, reset_on_uds_eof, ack_before_splice),
                None => {
                    // Nothing opened on QUIC — the whole point of checking
                    // the kind before `open_bi` (HARD RULES: "a non-
                    // SESSION_DATA/TCP_CONNECT/TCP_ACCEPTED/EXEC_DATA or
                    // missing header -> LocalError INVALID_ARGUMENT, nothing
                    // opened on QUIC").
                    let _ = conduit
                        .send(&LocalResponse {
                            body: Some(local_response::Body::Error(LocalError::from_code(
                                ErrorCode::InvalidArgument,
                                "LOCAL_STREAM's first frame must be a SESSION_DATA, TCP_CONNECT, \
                             TCP_ACCEPTED, or EXEC_DATA StreamHeader",
                            ))),
                        })
                        .await;
                    return;
                }
            };

        // The local conduit's own cap (`CONTROL_FRAME_MAX`, 256 KiB) is
        // wider than the QUIC data stream's (`DATA_FRAME_MAX`, 64 KiB) —
        // a header accepted on the way in is not automatically forward-
        // able on the way out. Checked here, against the *raw* bytes,
        // before anything is opened on QUIC (nothing here inspects why a
        // legitimate `StreamHeader` would ever be this large; it fails
        // closed either way).
        if raw_header.len() > qsh_proto::frame::DATA_FRAME_MAX {
            let _ = conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::Error(LocalError::from_code(
                        ErrorCode::InvalidArgument,
                        "LOCAL_STREAM's StreamHeader exceeds the data stream's frame cap",
                    ))),
                })
                .await;
            return;
        }

        // M4 plan Step 5 (a) (2473c88)'s hub cap: a `TCP_CONNECT` splice is
        // about to commit a fresh QUIC bidi stream on this host's shared
        // reverse connection, so it draws from the same
        // `MAX_TUNNEL_STREAMS_PER_HUB` pool `TCP_ACCEPTED` streams do
        // (`ControlHub::try_acquire_tunnel_permit`'s own doc) — never for
        // `SESSION_DATA` or `EXEC_DATA` (issue #5), neither of which this
        // cap bounds: exec concurrency is already limited by the target's
        // own `[serve].max_exec_per_principal` and ticket budget, and the
        // conduit itself by the `LOCAL_STREAM` permit acquired before this
        // task was spawned. Held for the whole splice, released only when
        // this function returns (the binding lives to the end of scope,
        // past the `tokio::join!` below).
        let _tunnel_permit = if tunnel_permit {
            match hub.try_acquire_tunnel_permit() {
                Some(permit) => Some(permit),
                None => {
                    let _ = conduit
                        .send(&LocalResponse {
                            body: Some(local_response::Body::Error(LocalError::from_code(
                                ErrorCode::ResourceExhausted,
                                "too many concurrent tunnel streams on this host's reverse \
                                 connection; retry shortly",
                            ))),
                        })
                        .await;
                    return;
                }
            }
        } else {
            None
        };

        // From here on this conduit never speaks framed `qsh.local.v1`
        // again — `into_raw` hands back the UDS stream plus whatever bytes
        // of the *next* frame the last `read()` already swallowed
        // alongside the header (`LocalConduit::into_raw`'s own doc).
        let (uds, prefetched) = conduit.into_raw();

        // Bounded ([`OPEN_DATA_STREAM_TIMEOUT`]'s own doc): this task is
        // already holding the `LOCAL_STREAM` permit acquired before
        // `serve_stream` was spawned, and an unbounded `await` here would
        // hold it — silently, with no envelope ever reaching the caller —
        // for as long as the peer connection's own concurrent-stream limit
        // stays exhausted.
        let (mut quic_send, quic_recv) = match tokio::time::timeout(
            OPEN_DATA_STREAM_TIMEOUT,
            conn.open_bi(),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => {
                tracing::warn!(
                    %err,
                    %host,
                    "localctl: LOCAL_STREAM failed to open a data stream on this host's connection"
                );
                // A sentinel byte, never a clean close: nothing on
                // QUIC ever opened, but the CLI already believes the
                // handshake succeeded and is reading for `SessionFrame`s
                // (`docs/CLI.md`'s "link death ends the attach with a
                // clear typed error" — same reasoning as
                // `pump_quic_to_uds`'s own ambiguous-boundary case).
                let mut uds = uds;
                let _ = uds.write_all(&[0u8]).await;
                return;
            }
            Err(_elapsed) => {
                tracing::warn!(
                    %host,
                    "localctl: LOCAL_STREAM's open_bi did not complete within \
                     {OPEN_DATA_STREAM_TIMEOUT:?}; the peer connection's own concurrent-\
                     stream limit is likely exhausted"
                );
                let mut uds = uds;
                let _ = uds.write_all(&[0u8]).await;
                return;
            }
        };

        // `EXEC_DATA` only (`ack_before_splice`'s own doc): a raw
        // `LocalResponse{ClaimGranted}` frame, written the same way the
        // error paths above write their sentinel byte — `conduit`'s own
        // framing is already gone (`into_raw` above), so this is a manual
        // `encode_frame`, not `conduit.send`. Written only now, after
        // `open_bi` has actually succeeded, so a failure to open the QUIC
        // stream still reaches the CLI as the sentinel-byte error above,
        // never a spurious success ack first.
        let mut uds = uds;
        if ack_before_splice {
            let ack_bytes = match qsh_proto::local::encode_local(&LocalResponse {
                body: Some(local_response::Body::ClaimGranted(LocalClaimGranted {})),
            }) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(
                        %err,
                        "localctl: LOCAL_STREAM failed to encode its own EXEC_DATA ack"
                    );
                    let _ = quic_send.reset(qsh_transport::StreamCode::from_u32(
                        RESET_CODE_LOCAL_CONDUIT_FAILED,
                    ));
                    return;
                }
            };
            if uds.write_all(&ack_bytes).await.is_err() {
                return;
            }
        }
        // M4 plan Step 5 (a) (2473c88): a relayed `TCP_CONNECT` rides at
        // `PRIORITY_TUNNEL`, same as a direct-connect tunnel stream
        // (`crate::tunnel::open_stream`) — a saturated tunnel must not
        // outrank session data in this daemon's own send queue either
        // (`docs/design/protocol.md` §12). `SESSION_DATA` keeps the
        // session-data priority this call already applied before Step 5,
        // and `EXEC_DATA` (issue #5) rides at `PRIORITY_EXEC_DATA` — all
        // three come straight from [`local_stream_relay_kind`], never
        // re-derived here.
        let _ = quic_send.set_priority(priority);

        // Re-framed from the raw payload bytes already validated above —
        // never re-encoded from the decoded `header` struct (this
        // function's own doc: that would silently drop any field this
        // build's `StreamHeader` does not know about).
        let header_bytes = match qsh_proto::frame::encode_frame(&raw_header) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(%err, "localctl: LOCAL_STREAM failed to re-frame its own header");
                let _ = quic_send.reset(qsh_transport::StreamCode::from_u32(
                    RESET_CODE_LOCAL_CONDUIT_FAILED,
                ));
                return;
            }
        };
        if quic_send.write_all(&header_bytes).await.is_err() {
            return;
        }
        if !prefetched.is_empty() && quic_send.write_all(&prefetched).await.is_err() {
            return;
        }

        let (uds_read, uds_write) = uds.into_split();

        if tunnel_permit {
            // `TCP_CONNECT`'s post-handshake body is unframed tunnel
            // payload, not `SessionFrame`s — `tunnel_splice_uds_quic`'s
            // own doc on why it cannot reuse `pump_uds_to_quic`/
            // `pump_quic_to_uds` below. The header and any UDS-side
            // prefetch were already flushed onto `quic_send` above, and
            // nothing has been read from the freshly opened `quic_recv`
            // yet, so both legs start with an empty prefix here.
            let watch = crate::tunnel::stall::StallWatch::on(
                &conn,
                format!("{}:{}", header.host, header.port),
            );
            tunnel_splice_uds_quic(
                uds_read,
                uds_write,
                quic_send,
                quic_recv,
                Vec::new(),
                Vec::new(),
                watch,
            )
            .await;
            return;
        }

        // One local UDS conduit is a single logical peer: once either
        // direction of it ends, the other is never coming back either
        // (`RESET_CODE_LOCAL_PEER_GONE`'s own doc). These two one-shot
        // channels are how each pump tells its sibling that promptly
        // instead of leaving it blocked on a `read()` that will now never
        // resolve — without this, `tokio::join!` below would only return
        // once *both* legs end on their own, and on an idle session
        // nothing ever wakes the QUIC→UDS leg once the UDS→QUIC leg sees
        // the CLI detach (this daemon task, its `_stream_permit` and the
        // QUIC bidi stream would all leak for as long as the session
        // stays idle — see the two pumps' own docs).
        let (uds_gone_tx, uds_gone_rx) = tokio::sync::oneshot::channel();
        let (quic_gone_tx, quic_gone_rx) = tokio::sync::oneshot::channel();
        tokio::join!(
            pump_uds_to_quic(
                uds_read,
                quic_send,
                reset_on_uds_eof,
                uds_gone_tx,
                quic_gone_rx
            ),
            pump_quic_to_uds(quic_recv, uds_write, quic_gone_tx, uds_gone_rx),
        );
    }

    /// `TCP_ACCEPTED`'s side of the `LOCAL_STREAM` conduit
    /// (`docs/design/protocol.md` §11-3's `-R over reverse` path,
    /// M4 plan Step 5 (a) (2473c88)): the CLI names the `forward_id` it wants
    /// to claim (`header.ticket`), this waits up to `deadline` — already
    /// [`serve_stream`](Self::serve_stream)'s original wait budget
    /// *minus* whatever `connection_for_wait` and the header read already
    /// spent, never a fresh window of its own (its call site's own doc) —
    /// for a queued [`crate::reverse::listen::ControlHub::claim_tcp_accepted`]
    /// arrival, and — once one shows up — splices it onto this conduit,
    /// forwarding the QUIC-side handshake residue the target already
    /// pipelined as that leg's prefix. Unlike `TCP_CONNECT`, this leg
    /// never calls `open_bi`: the QUIC stream it splices onto already
    /// exists (the target opened it), so there is no `open_bi` timeout,
    /// no header to forward onto QUIC (the target's own `TCP_ACCEPTED`
    /// header already made it there — `Listen::handle_tcp_accepted_stream`
    /// consumed it), and the `MAX_TUNNEL_STREAMS_PER_HUB` permit
    /// `claim_tcp_accepted` hands back travels with the arrival rather
    /// than being acquired again here.
    ///
    /// `forward_id` is shape-checked with `qsh_proto::wire::valid_forward_id`
    /// **before** the registry lookup — a malformed ticket never reaches
    /// `claim_tcp_accepted` at all, so it can never coincidentally match a
    /// live registration by some later coercion (M4 plan Step 5 (a) (2473c88)'s
    /// "shape-check before lookup" requirement, mirroring every other
    /// peer-ingress `forward_id` check in this tree).
    ///
    /// An unrecognized or never-arriving `forward_id` and a malformed one
    /// answer the *same* observable outcome to the CLI — `LocalError` —
    /// though different codes (`InvalidArgument` for shape, `Timeout` for
    /// "nothing arrived") — never a partial pipe, never a splice onto
    /// nothing (this method's only two exits before a splice starts are
    /// both a bare `LocalError` and a `return`).
    ///
    /// **Exactly one framed `LocalResponse` always leaves this method
    /// before any raw byte does** — `LocalClaimGranted` on success, a
    /// `LocalError` on every failure above, and a timeout is one of those
    /// failures rather than silence (`docs/design/protocol.md` §11-3's
    /// "TCP_ACCEPTED claim leg의 요청/응답"). That invariant is what lets the
    /// claiming CLI read a fixed one frame and then switch to raw, instead
    /// of trying to tell a frame from tunnel payload by its content or a
    /// success from a failure by how long nothing arrived — neither of
    /// which is decidable, and both of which corrupt or kill live tunnel
    /// connections when guessed wrong.
    async fn serve_tcp_accepted(
        &self,
        hub: &Arc<crate::reverse::listen::ControlHub>,
        conn: &qsh_transport::Connection,
        header: &wire::StreamHeader,
        deadline: std::time::Duration,
        mut conduit: LocalConduit<UnixStream>,
    ) {
        // `header.ticket` is `forward_id`, a NUL byte, then this
        // claimant's opaque claim token
        // (`crate::reverse::listen::ControlHub::claim_tcp_accepted`'s own
        // doc on why a token is required at all — adversarial-review
        // finding: knowing `forward_id` alone must not be enough to claim
        // it). `forward_id` can never itself contain a NUL
        // (`wire::valid_forward_id`'s charset is `[A-Za-z0-9_-]`), so
        // splitting on the *first* NUL unambiguously separates the two;
        // an absent separator is rejected the same way a malformed
        // `forward_id` is. `crate::tunnel::remote::claim_ticket` is the
        // one place that builds this exact `forward_id\0token` shape, so
        // the two sides can never drift.
        let ticket = &header.ticket;
        let Some(nul_at) = ticket.iter().position(|&b| b == 0) else {
            let _ = conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::Error(LocalError::from_code(
                        ErrorCode::InvalidArgument,
                        "TCP_ACCEPTED StreamHeader's ticket is missing its claim-token separator",
                    ))),
                })
                .await;
            return;
        };
        let (forward_id_bytes, rest) = ticket.split_at(nul_at);
        let claim_token = &rest[1..];
        let forward_id = match std::str::from_utf8(forward_id_bytes) {
            Ok(id) if wire::valid_forward_id(id) => id.to_string(),
            _ => {
                let _ = conduit
                    .send(&LocalResponse {
                        body: Some(local_response::Body::Error(LocalError::from_code(
                            ErrorCode::InvalidArgument,
                            "TCP_ACCEPTED StreamHeader's ticket is not a valid forward_id",
                        ))),
                    })
                    .await;
                return;
            }
        };

        // M4 plan Step 5 (2473c88) adversarial-review finding: a parked claim
        // holds this conduit's `MAX_CONCURRENT_LOCAL_STREAM_CONDUITS`
        // permit for its *entire* wait budget with nothing bounding how
        // many of *this hub's* claims can be parked at once — one CLI
        // opening many long-`wait_ms` claims against one host could alone
        // exhaust that daemon-wide pool. Keyed by the conduit that owns
        // `forward_id` so the pool is *divided*, not merely capped
        // (`MAX_PARKED_CLAIMS_PER_CONDUIT`'s own doc: one CLI's ordinary
        // steady state — one parked claim per registered `-R`, re-armed
        // forever — must not be able to hold every permit on this host).
        // Acquired and released around
        // exactly the parked wait below, never held any longer — a denial
        // here never touches `hub.claim_tcp_accepted` at all, so it never
        // parks in the first place. "Held any longer" is enforced by an
        // explicit `drop` right after the wait ends (below), not by
        // scope: this binding is *not* `_`-prefixed on purpose, because
        // letting it live to the end of this async fn — as it would by
        // default, since the live splice runs to completion inside this
        // same function — would silently cap concurrent *live* reverse
        // tunnels at `MAX_PARKED_CLAIMS_PER_HUB` instead of at
        // `MAX_TUNNEL_STREAMS_PER_HUB`, which is the limit that actually
        // belongs to the splice (`_permit` below, bound from
        // `hub.claim_tcp_accepted`'s return and held across the splice on
        // purpose — see its own comment near `tunnel_splice_uds_quic`).
        let Some(claim_permit) = hub.try_acquire_claim_permit(&forward_id) else {
            let _ = conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::Error(LocalError::from_code(
                        ErrorCode::ResourceExhausted,
                        "too many concurrent TCP_ACCEPTED claims on this host's reverse \
                         connection",
                    ))),
                })
                .await;
            return;
        };

        let Some((quic_send, quic_recv, residue, _permit)) = hub
            .claim_tcp_accepted(&forward_id, claim_token, deadline)
            .await
        else {
            // The wait is over (it failed), so `claim_permit`'s job is
            // done here too — this arm `return`s immediately below,
            // which drops it at scope exit. No explicit `drop` needed on
            // this arm; the success arm below is the one that needs it,
            // because that arm does *not* return next — it runs the live
            // splice, which must not be scoped by this permit.
            //
            // Covers both "this hub never registered that forward_id"
            // and "it was registered but nothing arrived before the
            // deadline" — `ControlHub::claim_tcp_accepted`'s own doc on
            // why the caller cannot and need not tell them apart. Either
            // way: no splice, nothing claimed.
            let _ = conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::Error(LocalError::from_code(
                        ErrorCode::Timeout,
                        "no TCP_ACCEPTED arrived for this forward_id within the wait budget",
                    ))),
                })
                .await;
            return;
        };

        // The parked wait is over and it succeeded — `claim_permit`'s job
        // ends here. Release it now, before the live splice below, so
        // concurrent *live* reverse tunnels are bounded only by
        // `MAX_TUNNEL_STREAMS_PER_HUB` (`_permit`, held across the splice
        // on purpose) and never by `MAX_PARKED_CLAIMS_PER_HUB` — the two
        // limits guard different resources (parked waits vs. live
        // splices) and must not be conflated by one outliving its scope.
        drop(claim_permit);

        // The claim is granted — say so, in one explicit frame, before a
        // single raw byte moves (`docs/design/protocol.md` §11-3's
        // "TCP_ACCEPTED claim leg의 요청/응답": the daemon always answers a
        // `TCP_ACCEPTED` header with exactly one `LocalResponse`, success
        // or failure, never with silence). The claimer cannot infer this
        // any other way: raw payload is not distinguishable from a frame
        // by its content, and a granted claim onto a connection that has
        // not spoken yet is not distinguishable from a slow failure by
        // silence. This frame is the discriminator.
        //
        // A write failure here means the CLI conduit is already gone. The
        // arrival was claimed out of the queue and nothing else will ever
        // pick it up, so it is reset rather than dropped — the target's
        // accepted TCP connection learns promptly that its peer went away
        // instead of hanging on a stream nobody will ever read.
        if conduit
            .send(&LocalResponse {
                body: Some(local_response::Body::ClaimGranted(LocalClaimGranted {})),
            })
            .await
            .is_err()
        {
            let mut quic_send = quic_send;
            let mut quic_recv = quic_recv;
            let _ = quic_send.reset(qsh_transport::StreamCode::from_u32(
                RESET_CODE_LOCAL_PEER_GONE,
            ));
            let _ = quic_recv.stop(qsh_transport::StreamCode::from_u32(
                RESET_CODE_LOCAL_PEER_GONE,
            ));
            return;
        }

        // From here on this conduit never speaks framed `qsh.local.v1`
        // again, same as the `TCP_CONNECT`/`SESSION_DATA` legs above.
        let (uds, prefetched) = conduit.into_raw();
        let (uds_read, uds_write) = uds.into_split();
        // `_permit` (bound above, held here) must outlive the splice — it
        // is what keeps this stream counted against
        // `MAX_TUNNEL_STREAMS_PER_HUB` for its whole life, not just its
        // time queued (`crate::reverse::listen::TunnelArrival`'s own
        // doc), so it stays alive across the `.await` below and drops
        // only once `tunnel_splice_uds_quic` returns.
        let watch = crate::tunnel::stall::StallWatch::on(conn, forward_id);
        tunnel_splice_uds_quic(
            uds_read, uds_write, quic_send, quic_recv, prefetched, residue, watch,
        )
        .await;
    }

    /// Whether `stream`'s connecting peer is this process's own euid — the
    /// only fact localctl ever authorizes on (`crate::localctl` module
    /// docs). Runs before any frame is read.
    fn authorized_peer(stream: &UnixStream) -> io::Result<bool> {
        let cred = stream.peer_cred()?;
        Ok(peer_is_authorized(cred.uid(), daemon_euid()))
    }
}

/// `LOCAL_STREAM`'s UDS → QUIC leg: relay raw bytes read off the localctl
/// conduit's read half onto the just-opened `SESSION_DATA` QUIC send
/// stream, without ever parsing them (module docs' kind table: "the
/// daemon never parses anything past that header").
///
/// A clean UDS EOF (the CLI half-closed its write side — nothing more is
/// ever coming from it) finishes the QUIC stream gracefully; a UDS read
/// error resets it abruptly instead (HARD RULES: "UDS EOF -> QUIC finish;
/// UDS error -> QUIC reset" — the daemon distinguishes only "no more
/// data" from "something went wrong", never the data itself). That finish
/// does not cancel the sibling leg: the target may still owe an answer, so
/// the sibling is told only once the CLI hangs up entirely
/// ([`wait_for_conduit_hangup`]). A QUIC
/// write failure (the target reset or stopped this stream from its own
/// end) simply ends this direction on its own.
///
/// `reset_on_uds_eof` overrides the clean-EOF case to a reset instead of a
/// finish — `EXEC_DATA` only (`local_stream_relay_kind`'s own doc): a
/// clean `EXEC_DATA` stream close has no meaning to the host's `run_exec`
/// (its stdin-EOF signal is the in-band `StdinEof` `ExecFrame`, not the
/// stream ending), so a client that drops the conduit — Ctrl-C, a
/// deadline, a crash — without ever sending `StdinEof` must still make
/// the host notice the peer is gone, or a silent remote command runs on
/// as an orphan. `SESSION_DATA`/`TCP_CONNECT` keep the plain finish: a
/// clean session/tunnel close is a real clean close there.
///
/// Either way `done_tx` fires once this leg is done, and `cancel_rx` is
/// raced against every read so the *sibling* leg ending first — the
/// local CLI conduit going away entirely, or the target ending its own
/// output — ends this one promptly too, instead of leaving it parked on
/// a `read()` that has no reason left to ever resolve (module docs'
/// cross-leg cancellation; see `serve_stream`'s call site).
async fn pump_uds_to_quic(
    mut uds_read: tokio::net::unix::OwnedReadHalf,
    mut quic_send: qsh_transport::SendStream,
    reset_on_uds_eof: bool,
    done_tx: tokio::sync::oneshot::Sender<()>,
    mut cancel_rx: tokio::sync::oneshot::Receiver<()>,
) {
    use tokio::io::AsyncReadExt as _;

    let mut buf = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            biased;
            _ = &mut cancel_rx => {
                // The QUIC→UDS leg already ended (target gone, or the
                // target ended its own output) — nothing this leg could
                // still relay would ever be read on the other end, so
                // abandon it rather than wait for a UDS read that may
                // never come (an idle CLI that is still attached but has
                // typed nothing is exactly this case).
                let _ = quic_send.reset(qsh_transport::StreamCode::from_u32(RESET_CODE_LOCAL_PEER_GONE));
                return;
            }
            r = uds_read.read(&mut buf) => match r {
                Ok(0) => {
                    if reset_on_uds_eof {
                        let _ = quic_send.reset(qsh_transport::StreamCode::from_u32(RESET_CODE_LOCAL_PEER_GONE));
                    } else {
                        let _ = quic_send.finish();
                        // A half-close is not a detach: the CLI shut only
                        // its write side (`DataSendHalf::finish`) and is
                        // still owed the target's answer to what it already
                        // sent (trailing output, the `InputAck` a detach
                        // flushes on). Cancelling the QUIC→UDS leg here
                        // would discard that, so the sibling is only told
                        // once the conduit is gone for good — the CLI hung
                        // up entirely — or it ended on its own.
                        tokio::select! {
                            biased;
                            _ = &mut cancel_rx => return,
                            () = wait_for_conduit_hangup(uds_read.as_ref()) => {}
                        }
                    }
                    let _ = done_tx.send(());
                    return;
                }
                Ok(n) => {
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        // The target stopped reading (an `EXEC_DATA` host
                        // whose command already exited drops its recv half
                        // right after `ExecExit`) — this direction is dead,
                        // but the target's output may still sit unread in
                        // the QUIC→UDS leg. Telling that leg to cancel here
                        // would discard a pending `ExecExit`, so keep the
                        // conduit open: discard what the CLI still writes
                        // until it closes or the sibling leg ends.
                        discard_until_gone(&mut uds_read, &mut cancel_rx).await;
                        let _ = done_tx.send(());
                        return;
                    }
                }
                Err(_) => {
                    let _ =
                        quic_send.reset(qsh_transport::StreamCode::from_u32(RESET_CODE_LOCAL_CONDUIT_FAILED));
                    let _ = done_tx.send(());
                    return;
                }
            },
        }
    }
}

/// Resolves once the CLI has closed its end of `conduit` entirely (both
/// directions), as opposed to merely half-closing its write side.
///
/// After a half-close the read half is at EOF for good, so reading cannot
/// tell the two apart, and an idle target writes nothing whose failure
/// would. The poller reports the write side as closed (`EPOLLHUP` /
/// kqueue `EV_EOF` on the write filter) only when the peer is gone for
/// good, never for a bare `shutdown(SHUT_WR)`. That readiness is watched on
/// a `dup` of the socket with its own registration, so clearing it here
/// cannot starve the sibling leg's writes on the shared one. This keeps the
/// idle-detach release (`RESET_CODE_LOCAL_PEER_GONE`'s own doc) without
/// cancelling a leg that is still owed data. If the watch cannot be set up
/// it resolves at once, which is the old cancel-on-EOF behavior.
async fn wait_for_conduit_hangup(conduit: &tokio::net::UnixStream) {
    use std::os::fd::AsFd as _;
    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;

    let Ok(fd) = conduit.as_fd().try_clone_to_owned() else {
        return;
    };
    let Ok(watch) = AsyncFd::with_interest(fd, Interest::WRITABLE) else {
        return;
    };
    loop {
        let Ok(mut guard) = watch.ready(Interest::WRITABLE).await else {
            return;
        };
        if guard.ready().is_write_closed() {
            return;
        }
        guard.clear_ready();
    }
}

/// Keep reading and dropping the CLI's bytes after the QUIC send half
/// died, until the CLI closes its write side (EOF or error) or the sibling
/// QUIC→UDS leg ends (`cancel_rx`). The conduit's read side must not simply
/// stop: the sibling leg may still be delivering the target's final frames.
async fn discard_until_gone(
    uds_read: &mut tokio::net::unix::OwnedReadHalf,
    cancel_rx: &mut tokio::sync::oneshot::Receiver<()>,
) {
    use tokio::io::AsyncReadExt as _;

    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            biased;
            _ = &mut *cancel_rx => return,
            r = uds_read.read(&mut buf) => match r {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            },
        }
    }
}

/// `LOCAL_STREAM`'s QUIC → UDS leg: relay raw bytes read off the target's
/// half of the data stream back onto the localctl conduit, again never
/// parsed.
///
/// A clean QUIC FIN (`Ok(None)`) and a QUIC reset/connection failure
/// (`Err`) surface through [`qsh_transport::RecvStream`]'s own inherent `read`
/// (not `AsyncReadExt`'s — it shadows the trait method) and both end this
/// pump by shutting down the UDS write half (HARD RULES: "QUIC FIN/reset
/// -> UDS shutdown"). They must not, however, become the same *observable
/// outcome* on the local reader's side of that shutdown: a reverse-leg
/// `session.attach` promises "link death ends the attach with a clear
/// typed error" (`docs/CLI.md` §6.13), and a plain UDS EOF at a frame
/// boundary is indistinguishable from a normal end from
/// [`crate::localctl::client::DataRecvHalf::recv`]'s point of view.
///
/// So the two cases are told apart the only place they safely can be: at
/// the *frame* layer, not the payload layer. `dec` is a purely mechanical
/// shadow of the same [`qsh_proto::frame`] boundary-tracking
/// `DataRecvHalf::recv` itself does on the other end of this splice —
/// pushed bytes, drained complete frames, contents never inspected past
/// that (this still never learns what the bytes mean; it only ever learns
/// where one length-prefixed record ends and the next begins, exactly
/// like `LocalConduit`'s own handshake framing already does on this same
/// conduit). On a clean FIN, `dec` is always at a frame boundary (the
/// target does not FIN mid-frame) and nothing extra is written. On an
/// `Err`, if `dec` shows a frame already truncated, the client's own
/// decoder will independently observe the same truncation and there is
/// nothing to add; but if `dec` is *also* sitting exactly on a boundary —
/// the "looks clean" case that silently ate every prior reset — one
/// sentinel byte is written before the shutdown. That byte can never
/// complete a real frame (a lone byte is never enough to satisfy a
/// pending 4-byte length header, let alone a payload), so it only ever
/// forces [`crate::localctl::client::DataRecvHalf::recv`]'s existing
/// "conduit ended mid-frame" branch — the same `LegEnd::Broken` path
/// (`crate::ops::session`) a literal truncated frame already takes,
/// never a corrupted-but-decodable payload.
///
/// Like the sibling direction, `done_tx` fires once this leg is done and
/// `cancel_rx` is raced against every read so the UDS→QUIC leg ending
/// first (the CLI detached) ends this one promptly too, instead of
/// blocking on target output that may never come on an idle session.
async fn pump_quic_to_uds(
    mut quic_recv: qsh_transport::RecvStream,
    mut uds_write: tokio::net::unix::OwnedWriteHalf,
    done_tx: tokio::sync::oneshot::Sender<()>,
    mut cancel_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let mut buf = [0u8; 16 * 1024];
    let mut dec = qsh_proto::frame::FrameDecoder::new(qsh_proto::frame::DATA_FRAME_MAX);
    loop {
        tokio::select! {
            biased;
            _ = &mut cancel_rx => {
                // The UDS→QUIC leg already ended — the local CLI conduit
                // is gone, so nothing arriving on this stream from here
                // on would ever be delivered anywhere. `stop()` tells the
                // target that directly (a real `STOP_SENDING`, not just a
                // local shutdown), which is what lets an idle target's
                // own output pump notice and release its session's
                // attach token instead of holding it open indefinitely
                // (`session_stream::write_frames`'s own doc).
                let _ = quic_recv.stop(qsh_transport::StreamCode::from_u32(RESET_CODE_LOCAL_PEER_GONE));
                let _ = done_tx.send(());
                return;
            }
            r = quic_recv.read(&mut buf) => match r {
                Ok(None) => {
                    let _ = uds_write.shutdown().await;
                    let _ = done_tx.send(());
                    return;
                }
                Ok(Some(n)) => {
                    if uds_write.write_all(&buf[..n]).await.is_err() {
                        let _ = done_tx.send(());
                        return;
                    }
                    // Mechanical bookkeeping only — drain whatever
                    // complete frames these bytes finish, never look at
                    // their content.
                    dec.push(&buf[..n]);
                    while matches!(dec.next_frame(), Ok(Some(_))) {}
                }
                Err(_) => {
                    // `Err(_)` from `next_frame` (an oversize declared
                    // length) also means "not cleanly at a boundary" for
                    // this purpose — treat it the same as leftover
                    // buffered bytes and skip the sentinel; the client's
                    // own decoder will already see the same truncation
                    // independently.
                    if dec.buffered() == 0 {
                        let _ = uds_write.write_all(&[0u8]).await;
                    }
                    let _ = uds_write.shutdown().await;
                    let _ = done_tx.send(());
                    return;
                }
            },
        }
    }
}

/// Drop-driven reset guard for the QUIC half of a tunnel splice
/// (`TunnelQuicGuard`) — the mirror of
/// `crate::tunnel::splice::SpliceGuard`'s reasoning, scoped to just the
/// QUIC side because that is the half whose peer (the real network target
/// on the other end of `hello.host`'s connection) must never mistake a
/// truncated relay for a clean end. The UDS side is a process-local relay
/// hop to this same host's CLI process with no equivalent abrupt-close
/// signal available through tokio (`SpliceGuard`'s own doc on why only a
/// real `TcpStream` gets the `SO_LINGER 0` treatment) — losing the
/// clean/abrupt distinction there does not create data loss or
/// misdelivery, only a coarser signal to a process on this same machine.
///
/// Armed for the whole splice and disarmed only once both directions have
/// finished cleanly (`tunnel_splice_uds_quic`'s own call site) — so a task
/// abort mid-transfer (daemon shutdown, this host's connection replaced)
/// resets this stream via `Drop` exactly like a hand-written error path
/// would, instead of a bare `SendStream`/`RecvStream` drop finishing it
/// cleanly.
struct TunnelQuicGuard {
    send: Option<qsh_transport::SendStream>,
    recv: Option<qsh_transport::RecvStream>,
    /// `crate::tunnel::splice::RESET_CODE_TUNNEL_ABORT`, or
    /// `crate::tunnel::stall::RESET_CODE_TUNNEL_STALLED` once the
    /// connection's stall ledger stopped this stream (ADR-0037).
    code: u32,
}

impl TunnelQuicGuard {
    /// The clean-finish path: both directions already told their peers
    /// the truth via `pump`'s own half-closes.
    fn disarm(mut self) {
        self.send.take();
        self.recv.take();
    }
}

impl Drop for TunnelQuicGuard {
    fn drop(&mut self) {
        if let Some(mut send) = self.send.take() {
            let _ = send.reset(qsh_transport::StreamCode::from_u32(self.code));
        }
        if let Some(mut recv) = self.recv.take() {
            let _ = recv.stop(qsh_transport::StreamCode::from_u32(self.code));
        }
    }
}

/// `LOCAL_STREAM`'s tunnel body (`TCP_CONNECT`'s post-handshake bytes,
/// `TCP_ACCEPTED`'s whole body) — a raw, **unframed** byte splice between
/// this conduit's UDS halves and the paired QUIC data stream halves,
/// M4 plan Step 5 (a) (2473c88).
///
/// This is deliberately *not* [`pump_uds_to_quic`]/[`pump_quic_to_uds`]
/// above: that pair is `SESSION_DATA`-specific — it layers
/// `qsh_proto::frame`-boundary bookkeeping and a disambiguating sentinel
/// byte onto the relay so a truncation is never mistaken for a clean
/// `SessionFrame` end (`pump_quic_to_uds`'s own doc), which is safe
/// *because* session data is itself a stream of length-prefixed messages.
/// Tunnel payload has no such structure — it is arbitrary application
/// bytes (someone's TCP stream) with no frame boundaries at all. Reusing
/// that pair here would not merely fail to help; the injected sentinel
/// byte would be a real, wrong byte spliced into the tunnel — corruption,
/// not disambiguation.
///
/// So this leg follows `crate::tunnel::splice`'s model instead, reusing
/// its exact `pump` primitive: each direction runs to its own end
/// independently rather than being cancelled the moment its sibling ends
/// (unlike the `SESSION_DATA` pair's cross-leg cancellation) — half-close
/// matters for a forwarded TCP connection (an HTTP request body, `nc -N`)
/// the same way `crate::tunnel::splice::splice_tcp_quic`'s own doc
/// requires for the direct-connect leg. `up_prefix`/`down_prefix` are
/// each leg's own handshake residue, if any (`TCP_CONNECT`'s UDS-side
/// prefetch was already flushed onto `quic_send` by the caller before
/// this is reached, so it always passes `Vec::new()` for both;
/// `TCP_ACCEPTED`'s QUIC-side residue is real and passed as
/// `down_prefix` — `crate::localctl::daemon::LocalctlDaemon::serve_tcp_accepted`'s
/// call site).
///
/// On any read/write error on either leg, [`TunnelQuicGuard`] resets the
/// QUIC side with `crate::tunnel::splice::RESET_CODE_TUNNEL_ABORT` — the
/// same code the direct-connect splice uses for an identical truncation —
/// so the target never mistakes a lost connection for a clean end.
///
/// `watch` is this relay's entry in the connection's stall ledger
/// (ADR-0037 decision 8): a CLI process that stops reading its UDS leaves
/// unread bytes in the QUIC receive stream exactly as a stalled local TCP
/// application does on the direct-connect leg. When the ledger picks this
/// stream, the QUIC side is reset and stopped with
/// `crate::tunnel::stall::RESET_CODE_TUNNEL_STALLED` and the UDS side is
/// dropped, the same asymmetric teardown as an error here.
async fn tunnel_splice_uds_quic(
    mut uds_read: tokio::net::unix::OwnedReadHalf,
    mut uds_write: tokio::net::unix::OwnedWriteHalf,
    quic_send: qsh_transport::SendStream,
    quic_recv: qsh_transport::RecvStream,
    up_prefix: Vec<u8>,
    down_prefix: Vec<u8>,
    watch: crate::tunnel::stall::StallWatch,
) {
    use crate::tunnel::splice::{Probe, pump_probed};

    let mut guard = TunnelQuicGuard {
        send: Some(quic_send),
        recv: Some(quic_recv),
        code: crate::tunnel::splice::RESET_CODE_TUNNEL_ABORT,
    };
    let mut stalled = false;

    // Scoped so both futures — and the borrows of the guard's two handles
    // they hold — are dropped before `guard` is touched again below,
    // mirroring `splice_tcp_quic`'s own structure exactly.
    let (up, down) = {
        let up = pump_probed(
            &mut uds_read,
            guard.send.as_mut().expect("armed"),
            &up_prefix,
            Probe::Sent(watch.track()),
        );
        let down = pump_probed(
            guard.recv.as_mut().expect("armed"),
            &mut uds_write,
            &down_prefix,
            Probe::Received(watch.track()),
        );
        tokio::pin!(up, down);

        let mut up_res: Option<io::Result<u64>> = None;
        let mut down_res: Option<io::Result<u64>> = None;
        while up_res.is_none() || down_res.is_none() {
            tokio::select! {
                r = &mut up, if up_res.is_none() => {
                    let failed = r.is_err();
                    up_res = Some(r);
                    if failed {
                        break;
                    }
                }
                r = &mut down, if down_res.is_none() => {
                    let failed = r.is_err();
                    down_res = Some(r);
                    if failed {
                        break;
                    }
                }
                () = watch.evicted() => {
                    stalled = true;
                    break;
                }
            }
        }
        (up_res, down_res)
    };

    if stalled {
        guard.code = crate::tunnel::stall::RESET_CODE_TUNNEL_STALLED;
    } else if matches!(up, Some(Ok(_))) && matches!(down, Some(Ok(_))) {
        // Clean end on both directions: nothing left to reset.
        guard.disarm();
    }
    // Otherwise `guard` falls out of scope still armed, and its `Drop`
    // resets the QUIC side — the same truncation teardown
    // `splice_tcp_quic`'s doc describes, applied to this relay hop.
}

/// Clamp a caller's `LocalHello.wait_ms` to [`LOCAL_WAIT_MAX`] — the same
/// ceiling discipline `qsh/local/v1.proto`'s own doc on the field promises
/// ("a *ceiling*, not a rejection"), applied at the one place both
/// [`LocalctlDaemon::serve_control`] and [`LocalctlDaemon::serve_stream`]
/// need it. `0` maps to [`Duration::ZERO`] — a single, immediate check,
/// exactly the behavior every pre-Step-8 caller (which never sets
/// `wait_ms`) already gets from [`Listen::control_hub_wait`]'s zero-
/// deadline branch.
fn clamp_wait(wait_ms: u32) -> std::time::Duration {
    std::time::Duration::from_millis(u64::from(wait_ms)).min(LOCAL_WAIT_MAX)
}

/// What [`LocalctlDaemon::serve_stream`] does with a relayable
/// `LOCAL_STREAM` header — never re-derived at the call site, so this is
/// the *only* place that decides which `StreamKind`s are relayable and
/// how (an earlier version of this file had a test-only
/// `is_session_data_header` twin that only *mirrored* `serve_stream`'s own
/// inline match rather than driving it — an adversarial-review finding
/// (`docs/design/testing.md`): mutating the production match away left
/// every unit test on that twin green).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalStreamRelay {
    /// Open a fresh QUIC bidi stream and become a raw byte-level pump both
    /// ways, at `priority`.
    OpenBidiAndSplice {
        /// The QUIC send stream's priority (`docs/design/protocol.md`
        /// §12).
        priority: i32,
        /// Whether this splice draws from the shared
        /// `MAX_TUNNEL_STREAMS_PER_HUB` pool (`TCP_CONNECT` only).
        tunnel_permit: bool,
        /// Whether a clean UDS EOF resets the QUIC send side instead of
        /// finishing it (`EXEC_DATA` only — `pump_uds_to_quic`'s own doc).
        reset_on_uds_eof: bool,
        /// Whether this kind gets an explicit `LocalClaimGranted` framed
        /// ack once `open_bi` succeeds, before any raw byte flows
        /// (`EXEC_DATA` only). `SESSION_DATA`/`TCP_CONNECT` stay silent on
        /// success exactly as before issue #5 — both predate any
        /// cross-version daemon/CLI skew concern, so there is nothing new
        /// for a caller to fail to decide between success and a slow
        /// failure (`LocalClaimGranted`'s own doc on why `TCP_ACCEPTED`
        /// needs this: "a granted claim onto an idle connection cannot be
        /// told apart from a slow failure by silence"). `EXEC_DATA` is the
        /// one kind new enough that an *old* daemon might not recognize it
        /// at all — without this ack, its `INVALID_ARGUMENT` rejection
        /// would race `serve_stream`'s own `into_raw` and be read as
        /// prefetched raw bytes instead of a framed `LocalResponse`, never
        /// surfacing as a decodable error to the CLI
        /// (`map_local_stream_open_error`'s own doc, `client::mod`'s
        /// `exec_data_rejected_by_an_old_daemon_names_the_stale_qsh_listen`).
        ack_before_splice: bool,
    },
    /// Claim an already-open QUIC stream the target opened
    /// (`LocalctlDaemon::serve_tcp_accepted`'s own path) instead of
    /// opening one — `TCP_ACCEPTED` only.
    ClaimTcpAccepted,
}

/// Classify a `LOCAL_STREAM` header into what [`LocalctlDaemon::serve_stream`]
/// does with it, or `None` for every kind that must be refused with
/// `INVALID_ARGUMENT` before anything is opened on QUIC (HARD RULES: "a
/// non-SESSION_DATA/TCP_CONNECT/TCP_ACCEPTED/EXEC_DATA or missing header ->
/// LocalError INVALID_ARGUMENT, nothing opened on QUIC"). `SESSION_DATA`
/// and `TCP_CONNECT`/`TCP_ACCEPTED` predate `EXEC_DATA`, which issue #5
/// adds here — the target-side ACL choke point and ticket
/// machinery are unchanged either way (`docs/design/protocol.md` §11-3:
/// "registration grants reachability, never authority").
fn local_stream_relay_kind(header: &wire::StreamHeader) -> Option<LocalStreamRelay> {
    match header.stream_kind() {
        Some(wire::StreamKind::SessionData) => Some(LocalStreamRelay::OpenBidiAndSplice {
            priority: wire::PRIORITY_SESSION_DATA,
            tunnel_permit: false,
            reset_on_uds_eof: false,
            ack_before_splice: false,
        }),
        Some(wire::StreamKind::TcpConnect) => Some(LocalStreamRelay::OpenBidiAndSplice {
            priority: wire::PRIORITY_TUNNEL,
            tunnel_permit: true,
            reset_on_uds_eof: false,
            ack_before_splice: false,
        }),
        Some(wire::StreamKind::ExecData) => Some(LocalStreamRelay::OpenBidiAndSplice {
            priority: wire::PRIORITY_EXEC_DATA,
            tunnel_permit: false,
            reset_on_uds_eof: true,
            ack_before_splice: true,
        }),
        Some(wire::StreamKind::TcpAccepted) => Some(LocalStreamRelay::ClaimTcpAccepted),
        Some(wire::StreamKind::Unspecified) | None => None,
    }
}

/// The pure comparison [`LocalctlDaemon::authorized_peer`] reduces to, once
/// the OS-level lookup (`SO_PEERCRED`/`getpeereid`, via
/// [`tokio::net::UnixStream::peer_cred`]) has produced a peer uid — split
/// out so the "different euid is denied" rule is unit-testable without a
/// second real OS user (`docs/design/testing.md` L2; M3 plan Step 5 (2473c88)
/// (c): "다른 euid의 connect 거부... 아니면... peer-cred 코드 경로를 단언").
fn peer_is_authorized(peer_uid: u32, daemon_euid: u32) -> bool {
    peer_uid == daemon_euid
}

/// This process's effective user id.
fn daemon_euid() -> u32 {
    // SAFETY: `geteuid(2)` takes no arguments, touches no memory, and
    // cannot fail.
    unsafe { libc::geteuid() }
}

/// The daemon's admin view of one registered host
/// (`crates/qsh-proto/proto/qsh/local/v1.proto`'s `LocalHost` doc comment —
/// distinct from the JSON `Host` type PR 5b builds on top of this).
fn to_local_host(entry: ReverseEntry) -> LocalHost {
    LocalHost {
        name: entry.name,
        address: entry.address.to_string(),
        state: match entry.state {
            EntryState::Live => "reachable".to_string(),
            EntryState::Stale => "stale".to_string(),
        },
        fingerprint: entry.fingerprint,
        capabilities: entry.capabilities,
        generation: entry.generation,
        registered_at: entry.registered_at,
        lost_at: entry.lost_at,
    }
}

#[cfg(test)]
fn sample_reverse_entry(state: EntryState, lost_at: Option<String>) -> ReverseEntry {
    ReverseEntry {
        name: "phone".to_string(),
        fingerprint: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        principal: "device:phone".to_string(),
        address: "203.0.113.5:51820".parse().unwrap(),
        capabilities: vec!["pty".to_string()],
        registered_at: "2026-08-22T00:00:00Z".to_string(),
        generation: 1,
        state,
        stale_since: None,
        lost_at,
    }
}

#[cfg(test)]
mod tests;
