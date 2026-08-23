//! Daemon side of localctl: the bridge module (`crate::localctl` module
//! docs — the one place in this tree allowed to touch `qsh_transport`
//! indirectly, through [`crate::reverse::listen::Listen`]) that binds this
//! `qsh listen` process's UDS socket, enforces the peer-credential trust
//! boundary, and answers the `LOCAL_ADMIN` conduit
//! (`docs/design/protocol.md` §11-3, `PLAN.md` M3 Step 5, PR 5a).
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
//!   Only `LOCAL_ADMIN` is served in this PR — `LocalHostList` answers from
//!   [`Listen::registry`]'s current snapshot, stale entries included, never
//!   dialing anything (`docs/CLI.md` §6.2's "부분 실패를 감추지 않는다"
//!   discipline: a listing never blocks on reachability). No `LocalHelloAck`
//!   is ever sent on this conduit kind — `LOCAL_ADMIN` pipelines its
//!   `LocalHello` straight into `LocalHostList` and answers with exactly
//!   one `LocalResponse` (`docs/design/protocol.md` §11-3, `qsh/local/v1.proto`
//!   header: `LocalHelloAck` is a `LOCAL_CONTROL`/`LOCAL_STREAM`-only reply,
//!   since every one of its fields is a fact about a specific registered
//!   host and `LOCAL_ADMIN` names none). `LOCAL_CONTROL`/
//!   `LOCAL_STREAM` are recognized-but-not-yet-served kinds — Step 6's job
//!   ("localctl의 두 번째 소비자... 이것이 M3의 유일한 신규 상태 기계") — and
//!   answer `UNSUPPORTED` rather than hanging or forwarding anything. An
//!   unspecified/unrecognized `LocalHello.kind` answers `INVALID_ARGUMENT`.
//!   Neither path ever calls `Authorizer::check` or an audit sink for the
//!   conduit itself, and never trusts anything the CLI side sent about its
//!   own identity — only the OS-level credential this module checked at
//!   accept time (`crate::localctl` module docs).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use qsh_proto::ErrorCode;
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LOCAL_WAIT_MAX, LocalError, LocalHello, LocalHelloAck, LocalHost,
    LocalHostList, LocalHostListResult, LocalResponse, LocalStreamKind, classify_stream_kind,
    local_response,
};
use qsh_proto::wire;
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
    ///    control (`PLAN.md` M3 Step 5 (a)).
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
}

impl LocalctlDaemon {
    /// Build a daemon answering from `listen`'s registry.
    pub fn new(listen: Arc<Listen>) -> Arc<Self> {
        Self::with_pool_sizes(
            listen,
            MAX_CONCURRENT_LOCAL_ADMIN_QUERIES,
            MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS,
        )
    }

    /// [`Self::new`] with explicitly chosen pool sizes — tests use this to
    /// saturate one of the two independent permit pools without needing
    /// hundreds of real connections.
    fn with_pool_sizes(listen: Arc<Listen>, admin: usize, control: usize) -> Arc<Self> {
        Arc::new(Self {
            listen,
            admin_permits: Arc::new(Semaphore::new(admin)),
            control_permits: Arc::new(Semaphore::new(control)),
        })
    }

    /// Accept loop: run until `shutdown` resolves, spawning one task per
    /// accepted connection, up to [`MAX_CONCURRENT_LOCALCTL_HANDSHAKES`]
    /// concurrently *while unclassified* — [`Self::serve_authorized_conduit`]
    /// releases this permit the moment it knows `LocalHello.kind` and
    /// switches to that kind's own pool, so this bound never limits how
    /// many classified conduits run at once. A single failed `accept` is
    /// logged (after a brief backoff — see [`ACCEPT_ERROR_BACKOFF`]'s doc)
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
    /// (`PLAN.md` M3 Step 5: "never a panic or a hang").
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
            // control session for `hello.host` (module docs, `PLAN.md`
            // M3 Step 6's "localctl의 두 번째 소비자... 이것이 M3의 유일한
            // 신규 상태 기계"). Long-lived, so it gets its own pool
            // (`MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS`) rather than the
            // brief handshake pool.
            LocalStreamKind::LocalControl => {
                match self.control_permits.clone().try_acquire_owned() {
                    Ok(_control_permit) => {
                        drop(handshake_permit);
                        self.serve_control(&hello.host, conduit).await;
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
            // `LOCAL_STREAM` is a real, defined kind this daemon does not
            // serve yet (Step 7 — attach data streams, deliberately not
            // bundled with Step 6's control relay, `PLAN.md`'s own split);
            // answering explicitly here, rather than falling through to a
            // bare connection close, keeps every reachable kind on the
            // "gets an envelope back" side of the module docs' contract.
            _ => {
                let _ = conduit
                    .send(&LocalResponse {
                        body: Some(local_response::Body::Error(LocalError::from_code(
                            ErrorCode::Unsupported,
                            "this daemon does not yet serve this localctl conduit kind",
                        ))),
                    })
                    .await;
            }
        }
    }

    /// `LOCAL_ADMIN`: read the (fieldless) `LocalHostList` request and
    /// answer with this controller's current registry snapshot — every
    /// entry, live or stale, never filtered and never dialed
    /// (`docs/CLI.md` §6.2, module docs).
    async fn serve_admin(&self, mut conduit: LocalConduit<UnixStream>) {
        match conduit.recv::<LocalHostList>().await {
            Ok(Some(LocalHostList {})) => {}
            Ok(None) | Err(_) => return,
        }
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

    /// `LOCAL_CONTROL`: relay `qsh.wire.v1` `ControlMessage`/`Response`
    /// between this conduit and `host`'s live reverse QUIC control stream
    /// (`docs/design/protocol.md` §11-3, `PLAN.md` M3 Step 6). Resolves
    /// `host` in [`Listen::control_hub`] first — live gets a
    /// `LocalHelloAck` and this conduit is registered with its
    /// [`crate::reverse::listen::ControlHub`]; stale or unknown gets
    /// `HOST_NOT_FOUND` and nothing else (`LocalHello.wait_ms` is not yet
    /// honored for a stale entry — Step 8 adds `LocalReconnect`).
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
    async fn serve_control(&self, host: &str, mut conduit: LocalConduit<UnixStream>) {
        let Some(hub) = self.listen.control_hub(host) else {
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

    /// Whether `stream`'s connecting peer is this process's own euid — the
    /// only fact localctl ever authorizes on (`crate::localctl` module
    /// docs). Runs before any frame is read.
    fn authorized_peer(stream: &UnixStream) -> io::Result<bool> {
        let cred = stream.peer_cred()?;
        Ok(peer_is_authorized(cred.uid(), daemon_euid()))
    }
}

/// The pure comparison [`LocalctlDaemon::authorized_peer`] reduces to, once
/// the OS-level lookup (`SO_PEERCRED`/`getpeereid`, via
/// [`tokio::net::UnixStream::peer_cred`]) has produced a peer uid — split
/// out so the "different euid is denied" rule is unit-testable without a
/// second real OS user (`docs/design/testing.md` L2; `PLAN.md` M3 Step 5
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
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use super::*;
    use crate::acl::AllowAllPinned;
    use crate::audit::NullAuditSink;
    use crate::broker::SystemClock;
    use crate::localctl::client;
    use crate::reverse::registry::{AdmittedEntry, Registry};
    use tokio::io::AsyncReadExt as _;

    /// A `Paths` fully sandboxed inside `dir`, `runtime_dir` included —
    /// `.with_runtime_dir` pins the localctl socket location independent
    /// of `$XDG_RUNTIME_DIR`, so these tests never touch the real runtime
    /// directory regardless of what the host process's environment
    /// happens to export (adversarial review finding: without this, every
    /// test below raced other tests and a real `qsh listen` for sockets in
    /// the ambient `$XDG_RUNTIME_DIR/qsh`, deleting some of them).
    fn tmp_paths(dir: &tempfile::TempDir) -> Paths {
        Paths::new(dir.path().join("config"), dir.path().join("state"))
            .with_runtime_dir(dir.path().join("run"))
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:4433".parse().unwrap()
    }

    fn test_listen() -> Arc<Listen> {
        let registry = Registry::new(Arc::new(SystemClock), false);
        Listen::new(
            registry,
            Arc::new(AllowAllPinned),
            Arc::new(NullAuditSink),
            "controller-device",
            Arc::new(SystemClock),
            Duration::from_secs(120),
        )
    }

    // ---- socket lifetime and permissions (`docs/design/testing.md` L2) ----

    #[tokio::test]
    async fn bind_creates_the_runtime_dir_0700_and_the_socket_0600() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9001).unwrap();

        let dir_mode = std::fs::metadata(paths.runtime_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "runtime dir must be 0700");

        let sock_mode = std::fs::metadata(&bound.socket_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(sock_mode, 0o600, "socket file must be 0600");
    }

    #[tokio::test]
    async fn bind_with_narrow_umask_creates_the_socket_node_at_0600_before_any_explicit_chmod() {
        // Calls `bind_with_narrow_umask` directly — with no subsequent
        // `tighten_socket_mode` call at all — to pin the atomicity
        // property itself: the node must already be 0600 the instant
        // `bind(2)` returns, not merely by the time `LocalctlListener::bind`
        // gets around to chmod-ing it (adversarial review finding: the
        // un-narrowed umask left a window where the node was world-
        // readable/connectable in mode terms).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("umask-atomicity.sock");
        let _listener = bind_with_narrow_umask(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the socket node itself must be 0600 the instant bind(2) returns"
        );
    }

    #[tokio::test]
    async fn bind_removes_a_stale_socket_file_at_the_exact_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        // A leftover regular file (not even a real socket) at the exact
        // path a pid-reused daemon would bind — `bind` must clear it
        // rather than failing `AddrInUse`.
        std::fs::create_dir_all(paths.runtime_dir()).unwrap();
        std::fs::write(paths.localctl_socket(9002), b"stale").unwrap();

        let bound = LocalctlListener::bind(&paths, 9002).unwrap();
        assert_eq!(bound.socket_path, paths.localctl_socket(9002));
    }

    // ---- peer credential check (`docs/design/protocol.md` §11-3) ----

    #[test]
    fn peer_is_authorized_only_when_the_uid_matches() {
        assert!(peer_is_authorized(1000, 1000));
        assert!(!peer_is_authorized(1000, 1001));
        assert!(!peer_is_authorized(0, 1000));
    }

    /// Exercises the *real* `SO_PEERCRED`/`getpeereid` syscall path via
    /// [`tokio::net::UnixStream::peer_cred`] — both ends of this pair are
    /// this same test process, so the peer uid this returns must equal
    /// this process's own euid, proving the accept-time check actually
    /// runs the OS lookup and not just [`peer_is_authorized`]'s pure logic
    /// (`PLAN.md` M3 Step 5 (c): "peer-cred 코드 경로를 단언" — the same-euid
    /// half of that requirement; a genuinely different euid is not
    /// obtainable without a second OS user, which CI does not provide).
    #[tokio::test]
    async fn same_euid_peer_is_authorized_via_the_real_peer_cred_syscall() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9003).unwrap();
        let socket_path = bound.socket_path.clone();

        let accept = tokio::spawn(async move { bound.listener.accept().await.unwrap().0 });
        let _client = UnixStream::connect(&socket_path).await.unwrap();
        let server_side = accept.await.unwrap();

        assert!(
            LocalctlDaemon::authorized_peer(&server_side).unwrap(),
            "this process connecting to its own socket must be authorized"
        );
    }

    // ---- LOCAL_ADMIN / LocalHostList (`docs/CLI.md` §6.13) ----

    #[tokio::test]
    async fn local_host_list_returns_the_registrys_current_entries_including_stale() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let listen = test_listen();
        listen
            .registry()
            .admit(
                "phone".to_string(),
                AdmittedEntry {
                    fingerprint: "sha256:aaaa",
                    principal: "device:phone",
                    address: addr(),
                    capabilities: vec!["pty".to_string()],
                },
            )
            .unwrap();
        let stale = listen
            .registry()
            .admit(
                "old-laptop".to_string(),
                AdmittedEntry {
                    fingerprint: "sha256:bbbb",
                    principal: "device:old-laptop",
                    address: addr(),
                    capabilities: vec![],
                },
            )
            .unwrap();
        listen
            .registry()
            .mark_stale("old-laptop", stale.entry.generation)
            .unwrap();

        let bound = LocalctlListener::bind(&paths, 9004).unwrap();
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::new(listen);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        let hosts = client::admin_host_list(&socket_path).await.unwrap();
        let mut by_name: Vec<(String, String)> =
            hosts.into_iter().map(|h| (h.name, h.state)).collect();
        by_name.sort();
        assert_eq!(
            by_name,
            vec![
                ("old-laptop".to_string(), "stale".to_string()),
                ("phone".to_string(), "reachable".to_string()),
            ]
        );

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn local_host_list_on_an_empty_registry_is_an_empty_list_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9005).unwrap();
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::new(test_listen());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        let hosts = client::admin_host_list(&socket_path).await.unwrap();
        assert!(hosts.is_empty());

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    /// A real daemon (this Stage's `LocalctlDaemon`, not a fake in-test
    /// stub) whose registry has no entry at all for the name a caller
    /// wants: `client::discover`'s own exhaustion rule
    /// (`docs/design/architecture.md` §7: "전부 실패하면 HOST_NOT_FOUND다")
    /// still surfaces `HOST_NOT_FOUND`, now proven end to end through the
    /// real UDS/peer-credential/`LOCAL_ADMIN` path this PR builds — Stage
    /// A's own `discover_exhausted_is_host_not_found` proved the same rule
    /// only against a synthetic fake daemon.
    #[tokio::test]
    async fn discover_against_a_real_daemon_with_no_matching_host_is_host_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let listen = test_listen();
        listen
            .registry()
            .admit(
                "some-other-host".to_string(),
                AdmittedEntry {
                    fingerprint: "sha256:cccc",
                    principal: "device:some-other-host",
                    address: addr(),
                    capabilities: vec![],
                },
            )
            .unwrap();

        let bound = LocalctlListener::bind(&paths, 9006).unwrap();
        let daemon = LocalctlDaemon::new(listen);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        let wanted = "nobody-registered-this-name";
        let err = client::discover(&paths.runtime_dir(), |stream| async move {
            match client::admin_host_list_over(stream).await {
                Ok(hosts) if hosts.iter().any(|h| h.name == wanted) => {
                    Ok(client::DiscoverOutcome::Found(()))
                }
                Ok(_) => Ok(client::DiscoverOutcome::NotFound),
                Err(err) => Err(err),
            }
        })
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    // ---- unknown / unsupported conduit kind ----

    #[tokio::test]
    async fn an_unspecified_kind_answers_invalid_argument_not_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9007).unwrap();
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::new(test_listen());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut conduit = LocalConduit::new(stream);
        conduit
            .send(&LocalHello {
                version: 1,
                kind: LocalStreamKind::LocalUnspecified as i32,
                host: String::new(),
                wait_ms: 0,
            })
            .await
            .unwrap();
        let response: LocalResponse = conduit.recv().await.unwrap().unwrap();
        match response.body {
            Some(local_response::Body::Error(err)) => {
                assert_eq!(err.error_code(), ErrorCode::InvalidArgument);
            }
            other => panic!("expected LocalError, got {other:?}"),
        }

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    /// `M3 Step 6` gave `LOCAL_CONTROL` a real serve path
    /// ([`LocalctlDaemon::serve_control`]) — an unregistered/unknown host
    /// now answers `HOST_NOT_FOUND`, not the pre-Step-6 blanket
    /// `UNSUPPORTED` this test used to assert (it predates that landing;
    /// updated here rather than left to bit-rot green on a wrong
    /// assertion). `LOCAL_STREAM` is the kind still genuinely unserved —
    /// see the sibling test right below.
    #[tokio::test]
    async fn local_control_for_an_unknown_host_is_host_not_found_not_forwarded_or_hung() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9008).unwrap();
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::new(test_listen());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut conduit = LocalConduit::new(stream);
        conduit
            .send(&LocalHello {
                version: 1,
                kind: LocalStreamKind::LocalControl as i32,
                host: "some-host".to_string(),
                wait_ms: 0,
            })
            .await
            .unwrap();
        let response: LocalResponse = conduit.recv().await.unwrap().unwrap();
        match response.body {
            Some(local_response::Body::Error(err)) => {
                assert_eq!(err.error_code(), ErrorCode::HostNotFound);
            }
            other => panic!("expected LocalError, got {other:?}"),
        }

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    /// `LOCAL_STREAM` is the one kind this daemon still genuinely does not
    /// serve (Step 7 — attach data streams) — it must keep answering
    /// `UNSUPPORTED` rather than hanging or being silently dropped, the
    /// exact contract the pre-Step-6 test above used to cover for both
    /// kinds at once.
    #[tokio::test]
    async fn local_stream_is_answered_unsupported_not_forwarded_or_hung() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9009).unwrap();
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::new(test_listen());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut conduit = LocalConduit::new(stream);
        conduit
            .send(&LocalHello {
                version: 1,
                kind: LocalStreamKind::LocalStream as i32,
                host: "some-host".to_string(),
                wait_ms: 0,
            })
            .await
            .unwrap();
        let response: LocalResponse = conduit.recv().await.unwrap().unwrap();
        match response.body {
            Some(local_response::Body::Error(err)) => {
                assert_eq!(err.error_code(), ErrorCode::Unsupported);
            }
            other => panic!("expected LocalError, got {other:?}"),
        }

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    // ---- the peer-credential gate must actually stop the conduit
    // (adversarial review finding: deleting the gate left every localctl
    // test green — this drives the negative outcome directly, since a
    // genuinely different euid needs a second OS user CI does not have) ----

    #[tokio::test]
    async fn an_unauthorized_peer_is_closed_before_any_frame_is_read_or_answered() {
        let (server_side, mut client_side) = UnixStream::pair().unwrap();
        let daemon = LocalctlDaemon::new(test_listen());

        // A literal `Ok(false)` stands in for the OS-level check reporting
        // a mismatched euid — see `serve_authorized_conduit`'s doc for why
        // this is the seam that makes the negative case testable at all.
        let handshake_permits = Arc::new(Semaphore::new(1));
        let handshake_permit = handshake_permits.try_acquire_owned().unwrap();
        let task =
            tokio::spawn(daemon.serve_authorized_conduit(server_side, Ok(false), handshake_permit));

        // The client side never sends a `LocalHello` — if the gate were
        // deleted (as the adversarial mutation check did), the daemon
        // would instead sit waiting for one, and this bounded read would
        // time out rather than observe a close.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_millis(500), client_side.read(&mut buf))
            .await
            .expect("an unauthorized peer must be closed promptly, not left waiting for a frame")
            .expect("the close must be a clean EOF, not a read error");
        assert_eq!(
            read, 0,
            "an unauthorized peer must see the conduit close, never a protocol reply"
        );

        task.await.unwrap();
    }

    // ---- LocalHello.version (`qsh listen` is resident, so version skew
    // against an older daemon is the normal case this exists to catch) ----

    #[tokio::test]
    async fn a_hello_with_a_version_this_daemon_does_not_speak_is_answered_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9009).unwrap();
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::new(test_listen());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut conduit = LocalConduit::new(stream);
        conduit
            .send(&LocalHello {
                version: LOCAL_HELLO_VERSION + 1,
                kind: LocalStreamKind::LocalAdmin as i32,
                host: String::new(),
                wait_ms: 0,
            })
            .await
            .unwrap();
        let response: LocalResponse = conduit.recv().await.unwrap().unwrap();
        match response.body {
            Some(local_response::Body::Error(err)) => {
                assert_eq!(err.error_code(), ErrorCode::Unsupported);
            }
            other => panic!("expected LocalError, got {other:?}"),
        }

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    // ---- bounded handshake wait (`PLAN.md` M3 Step 5: "never a panic or
    // a hang", `LOCAL_WAIT_MAX`'s own "no caller pins a daemon slot open
    // indefinitely" discipline applied to the handshake itself) ----

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_sends_a_hello_is_closed_after_the_wait_ceiling_not_held_open_forever()
     {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9010).unwrap();
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::new(test_listen());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        // Never send a `LocalHello`. `start_paused` auto-advances virtual
        // time past `LOCAL_WAIT_MAX` the instant every other task is idle,
        // so this proves the deadline actually closes the peer rather than
        // relying on a real 60s wall-clock wait.
        let mut buf = [0u8; 1];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(
            n, 0,
            "a peer that never sends a LocalHello must be closed after LOCAL_WAIT_MAX, not held \
             open indefinitely"
        );

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    // ---- LOCAL_ADMIN/LOCAL_CONTROL draw from independent permit pools
    // (adversarial review finding: before this split, long-lived
    // LOCAL_CONTROL conduits shared the same accept-time pool as brief
    // LOCAL_ADMIN discovery round trips, so enough concurrent sessions
    // silently starved routing discovery of a connection at all) ----

    /// Structural pin, independent of any real conduit traffic: the two
    /// pools never share capacity in either direction.
    #[test]
    fn admin_and_control_pools_are_independent_semaphores() {
        let daemon = LocalctlDaemon::with_pool_sizes(test_listen(), 3, 5);
        assert_eq!(daemon.admin_permits.available_permits(), 3);
        assert_eq!(daemon.control_permits.available_permits(), 5);

        // Exhaust the admin pool entirely.
        let held: Vec<_> = (0..3)
            .map(|_| daemon.admin_permits.clone().try_acquire_owned().unwrap())
            .collect();
        assert_eq!(daemon.admin_permits.available_permits(), 0);
        // The control pool must be completely unaffected.
        assert_eq!(
            daemon.control_permits.available_permits(),
            5,
            "exhausting the admin pool must never touch the control pool's capacity"
        );

        drop(held);
        // Symmetrically, exhausting control must never touch admin.
        let _held_control: Vec<_> = (0..5)
            .map(|_| daemon.control_permits.clone().try_acquire_owned().unwrap())
            .collect();
        assert_eq!(daemon.admin_permits.available_permits(), 3);
        assert_eq!(daemon.control_permits.available_permits(), 0);
    }

    /// At the `LOCAL_ADMIN` pool's own cap, a new connection now gets an
    /// explicit `LocalError{RESOURCE_EXHAUSTED}` envelope rather than
    /// being silently closed before ever being read — the distinction
    /// `admin_host_list_all`/`resolve_host_route` need to tell "daemon
    /// saturated" apart from "no such host" (`docs/CLI.md` §6.2).
    /// Held-open connections are real `LOCAL_ADMIN` conduits parked
    /// mid-handshake (hello sent, `LocalHostList` body deliberately
    /// withheld) rather than a live `LOCAL_CONTROL` host, which needs a
    /// real reverse QUIC registration this crate's own unit tests cannot
    /// stand up — `crates/qsh-testkit/tests/local_control_reverse.rs`
    /// covers the same pool end to end over a real reverse connection.
    #[tokio::test]
    async fn local_admin_at_the_admin_pools_cap_answers_resource_exhausted_not_a_silent_drop() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tmp_paths(&dir);
        let bound = LocalctlListener::bind(&paths, 9011).unwrap();
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::with_pool_sizes(
            test_listen(),
            1,
            MAX_CONCURRENT_LOCAL_CONTROL_CONDUITS,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = shutdown_rx.await;
        }));

        // Occupy the single admin permit: send `LocalHello` and then never
        // send the follow-up `LocalHostList` — `serve_admin` blocks
        // forever on that read, holding the permit for as long as this
        // stream stays open.
        let holder = UnixStream::connect(&socket_path).await.unwrap();
        let mut holder = LocalConduit::new(holder);
        holder
            .send(&LocalHello {
                version: LOCAL_HELLO_VERSION,
                kind: LocalStreamKind::LocalAdmin as i32,
                host: String::new(),
                wait_ms: 0,
            })
            .await
            .unwrap();

        // Give the accept loop a moment to actually acquire the admin
        // permit before this connection races it.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut conduit = LocalConduit::new(stream);
        conduit
            .send(&LocalHello {
                version: LOCAL_HELLO_VERSION,
                kind: LocalStreamKind::LocalAdmin as i32,
                host: String::new(),
                wait_ms: 0,
            })
            .await
            .unwrap();
        let response: LocalResponse = tokio::time::timeout(Duration::from_secs(5), conduit.recv())
            .await
            .expect("the daemon must answer promptly, not hang")
            .unwrap()
            .expect("a real envelope, not a silent close");
        match response.body {
            Some(local_response::Body::Error(err)) => {
                assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
            }
            other => panic!("expected LocalError(RESOURCE_EXHAUSTED), got {other:?}"),
        }

        drop(holder);
        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }
}
