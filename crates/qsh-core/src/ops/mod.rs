//! The typed operation layer: the single API surface the CLI, `--json`
//! renderer and any long-running external process (e.g. an agent tool)
//! all call through. See
//! `docs/CLI.md` §11 — frontends must not reimplement business logic, they
//! only translate an [`Ops`] call into their own presentation.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use qsh_proto::{
    BuildInfo, ErrorCode, IdentityInitData, IdentityInitReq, KeyStoreMode, SchemaData,
    TrustAcceptData, TrustAcceptReq, TrustAddData, TrustAddReq, TrustInviteData, TrustInviteReq,
    TrustListData, TrustRemoveData, VersionData,
};
use qsh_transport::{DialError, Dialer, Fingerprint, StaticTrust};

use crate::config::{Config, Paths, now_rfc3339};
use crate::hosts::HostsFile;
use crate::identity::LoadedIdentity;
use crate::trust::{SharedTrustStore, TrustStore};

pub mod acl;
pub mod cert;
pub mod doctor;
pub mod exec;
pub mod host;
pub mod session;
pub mod tunnel;

pub use acl::AclCheckOp;
pub use cert::{CertInitOp, CertIssueOp};
pub use doctor::DoctorOp;
pub use exec::{ExecRunOp, ExecRunOutput, ExecStdin};
pub use host::{HostGetOp, HostListOp, HostRoute};
pub use session::{
    AttachHandle, DetachFlush, RecoveryConfig, SESSION_WRITE_MAX, SessionAttachOp,
    SessionAttachStream, SessionCloseOp, SessionGetOp, SessionListOp, SessionOpenOp, SessionReadOp,
    SessionReadOutput, SessionReader, SessionRef, SessionResizeOp, SessionWriteOp,
    make_session_ref, parse_session_ref,
};
pub use tunnel::{
    TunnelCloseOp, TunnelHold, TunnelListOp, TunnelOpenOp, dynamic_forward_unsupported,
    parse_local_forwards, parse_remote_forwards,
};

/// Everything a remote call needs to reach a pinned host: our identity,
/// the trust evaluator, and where to dial.
pub(crate) struct PeerTarget {
    /// This device's identity and private key.
    pub identity: LoadedIdentity,
    /// The trust store as the transport's evaluator.
    pub trust: Arc<SharedTrustStore>,
    /// `host:port` recorded for the peer.
    pub address: String,
    /// SNI value for the dial (see [`server_name_for`]).
    pub server_name: String,
}

/// Where `Ops::connect`/`connect_target` (`crate::ops::session`) actually
/// reach `host` through — the dial-time counterpart of
/// [`host::HostRoute`], resolved by [`Ops::resolve_route`] (`PLAN.md` M3
/// Step 6). `HostRoute` is what `host.get`/the human renderer *display*;
/// `PeerRoute` is what a connection is actually built over, carrying the
/// identity/trust material `HostRoute` deliberately does not (routing and
/// display share one decision, `host::resolve_route`, but only one of
/// their two callers ever needs a private key in hand).
pub(crate) enum PeerRoute {
    /// Dial the peer directly over QUIC (forward route).
    Forward(PeerTarget),
    /// Relay through this machine's resident `qsh listen` daemon (reverse
    /// route).
    Reverse(LocalRoute),
}

/// Everything a reverse dial needs: which daemon (by its localctl socket)
/// and which of its registered hosts (by the alias name `LocalHello.host`
/// carries) to ask for.
///
/// Deliberately **not** carrying the fingerprint [`host::HostRoute::Reverse`]
/// observed at resolution time — [`crate::ops::session::Connected::peer_fingerprint`]
/// (the ADR-0007 presentation-condition input) must be the value *this*
/// connection's own `LocalHelloAck` reports, not a possibly-stale one read
/// moments earlier during routing (`docs/design/protocol.md` §11-3, `PLAN.md`
/// M3 Step 6's "Connected::peer_fingerprint() on the reverse leg returns
/// LocalHelloAck.peer_fingerprint" rule).
pub(crate) struct LocalRoute {
    /// The host alias to ask the daemon for (`LocalHello.host`).
    // Only ever read by `ops/session.rs`'s `dial_reverse`, `#[cfg(unix)]`
    // (localctl/UDS is unix-only) — `resolve_route` below still
    // *constructs* a `LocalRoute` on every platform (it mirrors
    // `HostRoute::Reverse` unconditionally), so the fields are genuinely
    // unread, not unconstructed, on Windows.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub host: String,
    /// The daemon's localctl socket path.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub socket: std::path::PathBuf,
}

/// How long the `trust.add` fingerprint probe waits for a handshake before
/// reporting `CONNECTION_FAILED`. Deliberately shorter than the transport's
/// default dial timeout: this dial is expected to fail (we trust nothing),
/// so it must not hold a human or a test hostage.
const PROBE_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Marker trait for a single typed operation.
///
/// `COMMAND` is the dotted-form command name used as the `command` field in
/// the `qsh.cli/v1` envelope and as the audit/ACL join key (e.g.
/// `"version.get"`, `"session.open"`).
pub trait Operation {
    /// Dotted-form command name, e.g. `"version.get"`.
    const COMMAND: &'static str;
}

/// Error type returned by every operation. Carries everything the
/// `qsh.cli/v1` error envelope needs (`docs/CLI.md` §3.2) plus a structured
/// `details` payload for automation.
#[derive(Debug, Clone, PartialEq)]
pub struct OpError {
    /// Shared error vocabulary code.
    pub code: ErrorCode,
    /// Human-readable explanation. Automation must not parse this.
    pub message: String,
    /// Whether retrying the same request might succeed.
    pub retryable: bool,
    /// Structured, machine-readable detail payload. `Value::Null` when
    /// there is nothing to add beyond `code`/`message`.
    pub details: serde_json::Value,
}

impl OpError {
    /// Construct an [`OpError`] with `retryable` defaulted from
    /// [`ErrorCode::default_retryable`] and empty `details`.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let retryable = code.default_retryable();
        Self {
            code,
            message: message.into(),
            retryable,
            details: serde_json::Value::Null,
        }
    }

    /// Override the default retryability.
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Attach a structured `details` payload.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

impl From<ErrorCode> for OpError {
    /// Build an [`OpError`] whose message is just the code's own display
    /// string. Callers that have a better message should use
    /// [`OpError::new`] instead; this exists for quick propagation of a
    /// bare code (e.g. from a lower layer that only has the code).
    fn from(code: ErrorCode) -> Self {
        let message = code.to_string();
        OpError::new(code, message)
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for OpError {}

/// The `version.get` operation.
pub struct VersionOp;

impl Operation for VersionOp {
    const COMMAND: &'static str = "version.get";
}

/// The `schema.get` operation.
pub struct SchemaOp;

impl Operation for SchemaOp {
    const COMMAND: &'static str = "schema.get";
}

/// The `capabilities.get` operation.
pub struct CapabilitiesOp;

impl Operation for CapabilitiesOp {
    const COMMAND: &'static str = "capabilities.get";
}

/// The `identity.init` operation (`qsh init`).
pub struct IdentityInitOp;

impl Operation for IdentityInitOp {
    const COMMAND: &'static str = "identity.init";
}

/// The `trust.add` operation.
pub struct TrustAddOp;

impl Operation for TrustAddOp {
    const COMMAND: &'static str = "trust.add";
}

/// The `trust.invite` operation (ADR-0002, `PLAN.md` M7 Step 4).
pub struct TrustInviteOp;

impl Operation for TrustInviteOp {
    const COMMAND: &'static str = "trust.invite";
}

/// The `trust.accept` operation (ADR-0002, `PLAN.md` M7 Step 4).
pub struct TrustAcceptOp;

impl Operation for TrustAcceptOp {
    const COMMAND: &'static str = "trust.accept";
}

/// The invite-code prompt's wording, in `qsh-core` because the decision to
/// prompt is `qsh-core`'s (`docs/ROADMAP.md:118` (j)) and the frontend only
/// writes what it is handed.
pub const INVITE_CODE_PROMPT: &str = "Invite code: ";

/// Upper bound on the bytes read for `--code-stdin`. The display form is 39
/// bytes (`docs/CLI.md` §6.11); the slack is for whitespace and CRLF. The
/// frontend reads one byte past it and lets
/// [`qsh_proto::pairing::parse_invite_code`] reject the oversize input by
/// symbol count — `qsh-core` only defines the number, the same way it
/// defines [`INVITE_CODE_PROMPT`] without being the one that writes it;
/// the frontend's own stdin-bounding precedent is `run_session_write`'s use
/// of [`SESSION_WRITE_MAX`] the same way.
pub const INVITE_CODE_STDIN_MAX: usize = 1024;

/// Where `trust accept` is to get its invite code from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteCodeSource {
    /// Use this value, already on the command line.
    UseCode(String),
    /// Read this process's stdin to end of input (`--code-stdin`).
    /// `suppress_echo` is set only when stdin is a terminal *and* the
    /// platform can suppress its echo — the same guard
    /// [`Prompt`](InviteCodeSource::Prompt) needs, reused here because
    /// `--code-stdin` on a terminal is just as interactive as the prompt
    /// and must not echo the code into the scrollback either.
    ReadStdin { suppress_echo: bool },
    /// Write `text` to **stderr**, then read one line from the terminal
    /// with echo suppressed.
    Prompt { text: String },
}

const NO_CODE_IN_MACHINE_MODE: &str = "no invite code: --json/--jsonl mode never prompts, so pass the code as \
     an argument or read it from stdin with --code-stdin";

const NO_CODE_WITHOUT_A_TERMINAL: &str = "no invite code: stdin is not a terminal, so pass the code as an \
     argument or read it from stdin with --code-stdin";

const BOTH_CODE_SOURCES: &str = "invite code given both as an argument and with --code-stdin; pass \
     exactly one";

/// `--code-stdin` was given explicitly, but stdin is a terminal and this is
/// machine mode: reading it would block a `--json`/`--jsonl` caller on a
/// human, which §2.1 forbids exactly as much as opening the prompt would
/// (ADR-0013 decision 8). Distinct wording from [`NO_CODE_IN_MACHINE_MODE`]
/// on purpose — that one fires when there is no way at all to get a code,
/// this one when the code-stdin path itself is what would block.
const CODE_STDIN_BLOCKS_MACHINE_MODE: &str = "invite code: --code-stdin on a terminal is interactive; \
     --json/--jsonl mode never blocks on a terminal, so redirect stdin from a pipe or file, or pass the \
     code as an argument";

/// This build cannot suppress a terminal's echo, so the interactive prompt
/// is refused rather than opened with the code landing in the scrollback —
/// the CLI's Windows-client precedent for the same reason (`tui::run`,
/// `docs/design/architecture.md` §8, client Windows is P1).
const NO_TERMINAL_ECHO_SUPPRESSION: &str = "reading an invite code from the terminal needs a POSIX \
     terminal; pass the code as an argument or read it from stdin with --code-stdin";

fn no_invite_code(message: &'static str) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message).with_retryable(false)
}

fn terminal_echo_unsupported(message: &'static str) -> OpError {
    OpError::new(ErrorCode::Unsupported, message).with_retryable(false)
}

/// Decide where `trust accept`'s invite code comes from, or refuse
/// (`docs/ROADMAP.md:118` (j), ADR-0013 decision 8,
/// `docs/adr/0013-cert-file-exchange.md:29`).
///
/// A free function, not an [`Ops`] method: it is pure (no [`Paths`], no
/// filesystem, no network), so a `&self` method would wrongly suggest it
/// touches the store — the same reasoning [`dynamic_forward_unsupported`]
/// and [`parse_local_forwards`] already follow for this crate's other
/// CLI-preflight judgments.
///
/// `echo_can_be_suppressed` is the frontend's `cfg!(unix)` at the call
/// site: whether a no-echo prompt is even possible carries the same
/// prompt-vs-refuse judgment as everything else here, so it belongs in
/// this resolver rather than as a second, untested branch in `qsh-cli`
/// (`main.rs`'s `read_invite_code_from_terminal` used to answer this on
/// its own, invisibly to this function's unit tests).
pub fn resolve_invite_code_source(
    code: Option<String>,
    code_stdin: bool,
    machine_mode: bool,
    stdin_is_tty: bool,
    echo_can_be_suppressed: bool,
) -> Result<InviteCodeSource, OpError> {
    match (code, code_stdin) {
        // Unreachable through the CLI: clap's `conflicts_with` refuses this
        // pair as a usage error first (`cli.rs`'s `TrustCmd::Accept`).
        // Answered anyway so the resolver is total on its own inputs and
        // the arm is exercised by its own unit test rather than left as
        // dead code.
        (Some(_), true) => Err(no_invite_code(BOTH_CODE_SOURCES)),
        // An explicit code wins in every mode: neither `machine_mode` nor
        // `stdin_is_tty` is consulted, because nothing has to be read.
        (Some(code), false) => Ok(InviteCodeSource::UseCode(code)),
        (None, true) => {
            // A terminal delivers EOF on Ctrl-D, so `--code-stdin` is
            // honored there too in human mode — but in machine mode a
            // terminal has no EOF coming, so this would block a
            // `--json`/`--jsonl` caller on a human exactly as a prompt
            // would.
            if stdin_is_tty && machine_mode {
                return Err(no_invite_code(CODE_STDIN_BLOCKS_MACHINE_MODE));
            }
            Ok(InviteCodeSource::ReadStdin {
                suppress_echo: stdin_is_tty && echo_can_be_suppressed,
            })
        }
        (None, false) => {
            if machine_mode {
                return Err(no_invite_code(NO_CODE_IN_MACHINE_MODE));
            }
            if !stdin_is_tty {
                return Err(no_invite_code(NO_CODE_WITHOUT_A_TERMINAL));
            }
            if !echo_can_be_suppressed {
                return Err(terminal_echo_unsupported(NO_TERMINAL_ECHO_SUPPRESSION));
            }
            Ok(InviteCodeSource::Prompt {
                text: INVITE_CODE_PROMPT.to_string(),
            })
        }
    }
}

/// The invite code as it goes on the wire: leading and trailing whitespace
/// removed.
///
/// Internal whitespace is left alone — `abcd efgh…` still fails
/// [`qsh_proto::pairing::parse_invite_code`]'s `InvalidCharacter` check, on
/// purpose: silently accepting embedded whitespace would blur the §6.11
/// grammar contract that only `-` is ignored. Every source in
/// [`InviteCodeSource`] funnels through this one function at exactly one
/// call site (`run_trust_accept`'s `invite_code` helper), so there is a
/// single named place the trim happens, mirroring how
/// [`dynamic_forward_unsupported`] centralizes its own single-site policy.
pub fn normalize_invite_code(raw: &str) -> &str {
    raw.trim()
}

/// The `trust.list` operation.
pub struct TrustListOp;

impl Operation for TrustListOp {
    const COMMAND: &'static str = "trust.list";
}

/// The `trust.remove` operation.
pub struct TrustRemoveOp;

impl Operation for TrustRemoveOp {
    const COMMAND: &'static str = "trust.remove";
}

/// Façade over every typed operation. This is the *only* entry point
/// frontends (`qsh-cli`'s human/JSON renderers, and any long-running
/// external process, e.g. an agent tool) are allowed to call into
/// `qsh-core` through.
///
/// One `Ops` is bound to one pair of config/state directories, so a test —
/// or a `QSH_CONFIG_DIR` override — redirects the whole tree at once.
#[derive(Debug, Clone)]
pub struct Ops {
    paths: Paths,
    recovery: session::RecoveryConfig,
    /// Every tunnel this process is holding via [`Ops::tunnel_open_and_hold`]
    /// (`PLAN.md` M6 Step 2+3 검증 라운드 판정 ②/F2) — `Arc`-backed so every
    /// clone of this `Ops` shares the same table (`tunnel::TunnelHoldRegistry`'s
    /// own doc).
    tunnel_holds: tunnel::TunnelHoldRegistry,
    /// The Tokio runtime [`session::Connected::connect_target`]/
    /// [`session::Connected::connect_reverse`] dial and block on, shared
    /// across every clone of this `Ops` and every pull on it instead of
    /// built-and-torn-down per call (`PLAN.md` M7 Step 7-2 ①: a single
    /// abandoned pull used to cost 11 threads — a whole `num_cpus`-sized
    /// `Builder::new_multi_thread()` plus a `lookup_host` blocking thread —
    /// on top of its own QUIC endpoint/socket; measured 11.05
    /// threads/5.00 fds per in-flight pull before this change).
    ///
    /// **Lazy by construction**: nothing builds this until the first
    /// `connect*` call reaches [`Self::connect_runtime`], so a purely local
    /// op (`qsh version`, `qsh trust list`, …) never pays for it. `Arc<
    /// OnceLock<Arc<SharedRuntime>>>`, not a bare `OnceLock`, for two
    /// reasons — the outer `Arc` lets every `Ops::clone()` share the one
    /// cell (a `static OnceLock` was considered and rejected: it would
    /// outlive `Ops` and break test isolation, since `qsh-testkit` builds
    /// and drops many `Ops` instances with different `Paths` per test), and
    /// the inner `Arc<SharedRuntime>` lets a [`session::Connected`] hold an
    /// owned handle that outlives the `&Ops` borrow which created it — a
    /// bare `&Runtime` borrowed from the cell could not be stored across
    /// `connect_target`'s return. [`SharedRuntime`] (rather than a bare
    /// `Runtime`) is what makes the last such `Arc` safe to drop from
    /// literally anywhere — see its own doc.
    ///
    /// Never reused for a long-running external process's (e.g. an agent
    /// tool) own long-lived runtime ([`crate`]'s caller wires that up
    /// separately in `qsh-cli`): sharing one runtime's blocking-thread pool
    /// between "the process accepting long-poll requests" and "every
    /// in-flight pull's blocking work" was measured to
    /// deadlock around ~256 concurrent pulls, because each pull both
    /// occupies a blocking-pool thread (the caller's `spawn_blocking`) and
    /// then asks the *same* pool for another one (`tokio::net::lookup_host`)
    /// — two independent runtimes keep the two demands on separate pools.
    connect_runtime: Arc<OnceLock<Arc<SharedRuntime>>>,
}

/// A [`tokio::runtime::Runtime`] whose `Drop` never blocks.
///
/// The plain `Runtime::drop` waits for every worker thread to park before
/// returning, and that wait **panics** — "Cannot drop a runtime in a
/// context where blocking is not allowed" — if it happens to run on a
/// thread that is, at that moment, itself executing inside some async
/// task (any runtime's, not necessarily this one's). [`Ops::connect_runtime`]
/// is shared and reference-counted, so its very last `Arc` can be dropped
/// almost anywhere — in particular, `qsh-testkit`'s loopback fixtures build
/// an `Ops` inside a `#[tokio::test]` and drop it at the end of that same
/// async test function, which is exactly such a context (found by this
/// step's own nextest run: `qsh-testkit::reverse_attach
/// detaching_leaves_the_session_running_and_a_reattach_replays_the_retained_ring`
/// failed with precisely that panic before this wrapper existed). Wrapping
/// every shared handle in this type instead and routing its `Drop` through
/// [`tokio::runtime::Runtime::shutdown_background`] — documented by tokio
/// itself as the non-blocking teardown, safe to call from inside another
/// runtime — fixes it generally, for every current and future caller,
/// rather than special-casing the one call site the test happened to
/// exercise.
#[derive(Debug)]
pub(crate) struct SharedRuntime(Option<tokio::runtime::Runtime>);

impl std::ops::Deref for SharedRuntime {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &tokio::runtime::Runtime {
        self.0.as_ref().expect("runtime is only taken by Drop")
    }
}

impl Drop for SharedRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

impl Ops {
    /// Bind operations to explicit directories.
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            recovery: session::RecoveryConfig::default(),
            tunnel_holds: tunnel::new_tunnel_hold_registry(),
            connect_runtime: Arc::new(OnceLock::new()),
        }
    }

    /// The shared dial runtime, building it on first use.
    ///
    /// `std::sync::OnceLock::get_or_try_init` is still unstable (tracking
    /// issue 109737), so a fallible build cannot use `get_or_init`
    /// directly; this hand-rolls the same double-checked shape:
    /// [`OnceLock::get`] first (the fast, already-built path every pull
    /// after the first takes), and only on a miss does it build a runtime
    /// and race [`OnceLock::set`] to install it. Losing that race is
    /// harmless — the loser's freshly built, never-used runtime is simply
    /// dropped, which [`SharedRuntime`]'s own `Drop` makes safe regardless
    /// of which context that drop happens to run in.
    pub(crate) fn connect_runtime(&self) -> Result<Arc<SharedRuntime>, OpError> {
        if let Some(runtime) = self.connect_runtime.get() {
            return Ok(Arc::clone(runtime));
        }
        let built = Arc::new(SharedRuntime(Some(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?,
        )));
        match self.connect_runtime.set(Arc::clone(&built)) {
            Ok(()) => Ok(built),
            Err(_) => Ok(Arc::clone(
                self.connect_runtime
                    .get()
                    .expect("just set by the winning thread"),
            )),
        }
    }

    /// Override how a live attach survives a dead path
    /// ([`session::RecoveryConfig`]).
    ///
    /// The defaults are what the product ships and what the M2 recovery
    /// gate measures; this exists so a caller can turn a half of it off —
    /// which is also how "nothing depends on migration succeeding"
    /// (`docs/design/protocol.md` §2) is demonstrated rather than asserted.
    #[must_use]
    pub fn with_recovery(mut self, recovery: session::RecoveryConfig) -> Self {
        self.recovery = recovery;
        self
    }

    /// Bind operations to the directories resolved from the environment
    /// ([`Paths::from_env`]).
    pub fn from_env() -> Result<Self, OpError> {
        Ok(Self::new(Paths::from_env()?))
    }

    /// The config/state directories these operations act on.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Load `config.toml` (missing = defaults).
    pub fn config(&self) -> Result<Config, OpError> {
        Config::load(&self.paths)
    }

    /// Report this build's version and the wire/CLI schemas it understands.
    ///
    /// `build.commit` (`docs/ROADMAP.md` M7 감사 개정 ③) is whatever
    /// `option_env!("QSH_BUILD_COMMIT")` captured when this binary was
    /// *compiled* — not read from the environment at call time — so a
    /// local build with no such variable set reports no `build` field at
    /// all rather than a fabricated or empty one (`PLAN.md` M7 §4.1 #1).
    pub fn version(&self) -> Result<VersionData, OpError> {
        Ok(VersionData {
            version: env!("CARGO_PKG_VERSION").to_string(),
            schemas: vec!["qsh.cli/v1".to_string(), "qsh.event/v1".to_string()],
            build: option_env!("QSH_BUILD_COMMIT").map(|commit| BuildInfo {
                commit: commit.to_string(),
            }),
        })
    }

    /// `schema.get` (`docs/CLI.md` §6.10) — the JSON Schema of the
    /// `qsh.cli/v1` envelope and every command's `data` payload, generated
    /// straight from `qsh_proto::schema`: the exact same function
    /// `crates/qsh-cli/tests/fixtures.rs` validates every golden fixture
    /// against (`docs/design/testing.md` L6), so this and the fixture
    /// validator cannot drift apart.
    pub fn schema(&self) -> Result<SchemaData, OpError> {
        let commands = qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS
            .iter()
            .map(|&command| {
                let schema = qsh_proto::schema::cli_v1_data_schema(command).unwrap_or_else(|| {
                    panic!(
                        "CLI_V1_SCHEMA_COMMANDS names {command:?} with no cli_v1_data_schema arm"
                    )
                });
                (command.to_string(), schema.to_value())
            })
            .collect();
        Ok(SchemaData {
            schemas: vec!["qsh.cli/v1".to_string(), "qsh.event/v1".to_string()],
            envelope: qsh_proto::schema::cli_v1_envelope_schema().to_value(),
            commands,
        })
    }

    // -----------------------------------------------------------------
    // identity
    // -----------------------------------------------------------------

    /// `identity.init` — create this device's identity if it does not exist
    /// (idempotent: an existing identity comes back with `created: false`).
    ///
    /// Key-store selection: the request wins over `config.toml`
    /// `[identity].key_store`, which wins over `auto`.
    pub fn identity_init(&self, req: IdentityInitReq) -> Result<IdentityInitData, OpError> {
        let mode = match req.key_store {
            Some(mode) => mode,
            None => self
                .config()?
                .identity
                .key_store
                .unwrap_or(KeyStoreMode::Auto),
        };
        crate::identity::init(&self.paths, mode)
    }

    /// This device's identity plus its private key, or `None` before
    /// `qsh init`.
    ///
    /// **Runtime caveat:** with a platform key store this blocks on the OS
    /// credential store — call it outside a tokio runtime, or from
    /// `spawn_blocking` (see [`crate::identity::load`]).
    pub fn load_identity(&self) -> Result<Option<LoadedIdentity>, OpError> {
        crate::identity::load(&self.paths)
    }

    /// The shared, reload-on-change trust store to inject into the
    /// transport as a [`qsh_transport::TrustEvaluator`].
    pub fn open_trust(&self) -> Result<Arc<SharedTrustStore>, OpError> {
        SharedTrustStore::open(self.paths.trust_file())
    }

    // -----------------------------------------------------------------
    // trust
    // -----------------------------------------------------------------

    /// `trust.add` — pin a peer.
    ///
    /// With `--fingerprint` the peer is pinned **without connecting**
    /// (provisioning-friendly, `docs/CLI.md` §6.11). Without one, the peer
    /// is dialed once to observe its fingerprint and the result is always a
    /// `TRUST_REQUIRED` error carrying `details.observed_fingerprint` and
    /// `details.address`: the caller (human prompt or automation) verifies
    /// that value out of band and re-calls with `--fingerprint`. Nothing is
    /// ever pinned on the strength of what the network said.
    ///
    /// Re-adding an already-pinned name is idempotent, with one deliberate
    /// exception (`PLAN.md` M7 Step 2 decision B, `TrustStore::add_peer`'s
    /// own doc): the *same* fingerprint with a *different* `--address`
    /// overwrites the stored address in place (`data.updated: true`,
    /// `data.created` stays `false`) instead of being a no-op — the M6
    /// mobility campaign's backlog item. A *different* fingerprint is still
    /// a hard no-op on the whole entry; re-binding an identity is `trust
    /// remove` then `trust add`, never a side effect of a repeated call.
    pub fn trust_add(&self, req: TrustAddReq) -> Result<TrustAddData, OpError> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "peer name must not be empty",
            ));
        }

        let fingerprint = match req.fingerprint.as_deref() {
            Some(text) => text
                .parse::<Fingerprint>()
                .map_err(|err| OpError::new(ErrorCode::InvalidArgument, err.to_string()))?,
            None => {
                let Some(address) = req.address.as_deref() else {
                    return Err(OpError::new(
                        ErrorCode::InvalidArgument,
                        "--address is required to observe a fingerprint",
                    ));
                };
                let observed = self.probe_fingerprint(address)?;
                return Err(OpError::new(
                    ErrorCode::TrustRequired,
                    format!(
                        "peer {address} is not trusted; verify the fingerprint and re-run with \
                         --fingerprint"
                    ),
                )
                .with_retryable(false)
                .with_details(serde_json::json!({
                    "observed_fingerprint": observed.to_string(),
                    "address": address,
                })));
            }
        };

        let path = self.paths.trust_file();
        // Whole load→mutate→save under lock, not just the write — a
        // concurrent `qsh serve` pairing response or another CLI process
        // racing this same read-modify-write must not have its change
        // silently discarded (`TrustStore::lock`'s own doc, `PLAN.md` M7
        // Step 7-1).
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let (peer, created, updated) =
            store.add_peer(name, req.address, fingerprint, now_rfc3339());
        if created || updated {
            store.save(&path)?;
        }
        Ok(TrustAddData {
            peer,
            created,
            updated: (!created).then_some(updated),
        })
    }

    /// `trust.list` — every pinned peer, in store order.
    pub fn trust_list(&self) -> Result<TrustListData, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        Ok(TrustListData {
            peers: store.peers().to_vec(),
        })
    }

    /// `trust.remove` — unpin a peer. Removing an unknown name is not an
    /// error (`removed: false`, idempotent).
    pub fn trust_remove(&self, name: &str) -> Result<TrustRemoveData, OpError> {
        let path = self.paths.trust_file();
        // See `trust_add`'s identical comment — whole cycle under lock.
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let removed = store.remove(name);
        if removed {
            store.save(&path)?;
        }
        Ok(TrustRemoveData {
            name: name.to_string(),
            removed,
        })
    }

    /// `trust.invite` — mint a one-time pairing invite (ADR-0002, `PLAN.md`
    /// M7 Step 4).
    ///
    /// The raw secret exists only for the lifetime of this call: it is
    /// generated, hashed into `invites.toml` (never the raw bytes —
    /// `crate::trust::pairing`'s own module doc), rendered as the Crockford
    /// Base32 display code, and zeroized on drop before this returns. `qsh
    /// serve`'s own `SharedInviteStore` picks up the freshly written invite
    /// on its very next check, without a restart (Step 2's content-based
    /// reload, invariant #6). `accept_command` is the exact command line to
    /// hand the other party — the code alone carries no address (`PLAN.md`
    /// M7 §4.1 #7), so this is the only place that pairing is complete.
    pub fn trust_invite(&self, _req: TrustInviteReq) -> Result<TrustInviteData, OpError> {
        let secret = crate::trust::pairing::generate_secret();
        let now = std::time::SystemTime::now();
        let path = self.paths.invites_file();
        // Whole load→mutate→save under lock, not just the write — closes
        // report F-9's residual lost-update window against a concurrent
        // `qsh serve` redeeming a different invite at the same time
        // (`InviteStore::lock`'s own doc, `PLAN.md` M7 Step 7-1).
        let _lock = crate::trust::pairing::InviteStore::lock(&path)?;
        let mut store = crate::trust::pairing::InviteStore::load(&path)?;
        store.prune(now);
        let (_created_at, expires_at) = store.add(secret.as_slice(), now);
        store.save(&path)?;

        let code = qsh_proto::pairing::encode_invite_code(&secret);
        Ok(TrustInviteData {
            accept_command: format!("qsh trust accept <address> {code}"),
            code,
            expires_at,
        })
    }

    /// `trust.accept <address> <code>` — complete a pairing exchange with
    /// `qsh trust invite`'s counterpart (ADR-0002, `PLAN.md` M7 Step 4).
    ///
    /// Dials `address` with a trust evaluator that accepts *any*
    /// certificate ([`crate::pairing::AcceptAnyForPairing`], report §B3) —
    /// pairing's real authentication is possession of `code`'s secret,
    /// proven over a TLS-exporter-bound channel
    /// ([`crate::pairing::accept`]), never the TLS identity presented. Only
    /// once the responder's own proof has verified (never on the strength
    /// of a reply merely arriving — report §B13) is the responder pinned,
    /// using this connection's own observed fingerprint, via the same
    /// [`TrustStore::add_peer`] path `qsh trust add` uses. A name collision
    /// here (the responder's self-reported name already pinned locally
    /// under a *different* fingerprint) fails loudly with `SESSION_CONFLICT`
    /// — unlike `trust add`'s own established silent no-op on the same
    /// underlying case (`TrustStore::add_peer`'s own doc; left untouched).
    ///
    /// **Runtime caveat:** loads the identity synchronously — call it
    /// outside a tokio runtime (see [`Self::load_identity`]).
    pub fn trust_accept(&self, req: TrustAcceptReq) -> Result<TrustAcceptData, OpError> {
        let secret = qsh_proto::pairing::parse_invite_code(&req.code).map_err(|err| {
            OpError::new(ErrorCode::InvalidArgument, err.to_string()).with_retryable(false)
        })?;

        let Some(loaded) = self.load_identity()? else {
            return Err(OpError::new(
                ErrorCode::ConfigError,
                format!(
                    "no device identity in {}; run qsh init first",
                    self.paths.config_dir.display()
                ),
            )
            .with_retryable(false));
        };
        let device_name = loaded.identity.device_id.clone();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                OpError::new(
                    ErrorCode::Internal,
                    format!("failed to start an async runtime: {err}"),
                )
                .with_retryable(false)
            })?;

        let dialer = Dialer::new(loaded.local, Arc::new(crate::pairing::AcceptAnyForPairing));
        let server_name = server_name_for(&req.address);
        let dial_address = req.address.clone();

        let outcome = runtime.block_on(async move {
            let socket = resolve_one(&dial_address).await?;
            let dialed = dialer
                .dial(socket, &server_name)
                .await
                .map_err(|err| classify_pairing_dial_failure(err, &dial_address))?;
            let success = crate::pairing::accept(&dialed.connection, &device_name, &secret)
                .await
                .map_err(classify_pairing_exchange_failure)?;
            let observed_fp = dialed.connection.peer_fingerprint().ok_or_else(|| {
                OpError::new(
                    ErrorCode::Internal,
                    "paired connection reported no peer certificate fingerprint",
                )
                .with_retryable(false)
            })?;
            dialed.connection.close(0, b"paired");
            Ok::<_, OpError>((success, observed_fp))
        });
        runtime.shutdown_timeout(Duration::from_millis(200));
        let (success, observed_fp) = outcome?;

        let path = self.paths.trust_file();
        // See `trust_add`'s identical comment — whole cycle under lock.
        // Acquired only now, after the network dial above has already
        // completed: the critical section stays a small local file
        // rewrite, never a network wait.
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        // Report F-6: pin with the address this exchange just dialed
        // successfully (`req.address`, the same meaning `trust add
        // --address` gives it) rather than `None` — otherwise `qsh exec
        // <peer>` right after a successful pairing would come back
        // `HOST_NOT_FOUND` (§6.1/§6.8: an address-less pin is never a
        // dial-address candidate), directly undercutting ADR-0002's SC1
        // (5-minute pairing to first connection).
        let (peer, created, updated) = store.add_peer(
            success.peer_device_name.clone(),
            Some(req.address.clone()),
            observed_fp,
            now_rfc3339(),
        );
        if !created && !updated && peer.fingerprint != observed_fp.to_string() {
            return Err(OpError::new(
                ErrorCode::SessionConflict,
                format!(
                    "paired with {}, but {:?} is already pinned locally under a different \
                     identity; rename or remove the conflicting entry and retry",
                    req.address, success.peer_device_name
                ),
            )
            .with_retryable(false));
        }
        if created || updated {
            store.save(&path)?;
        }
        Ok(TrustAcceptData {
            peer,
            created,
            updated: (!created).then_some(updated),
        })
    }

    /// Resolve `host` to a dial target: loads the identity (`CONFIG_ERROR`
    /// before `qsh init`) and resolves an address via `hosts.toml`
    /// layered over the trust store's pinned peers (`PLAN.md` M7 Step 3,
    /// §4.1 #4 — `hosts.toml` first, trust-store pin as fallback;
    /// `HOST_NOT_FOUND` when neither source has one). Identity/trust is
    /// still decided solely by the trust store: this only changes where
    /// the *address* comes from.
    ///
    /// **Runtime caveat:** loads the identity synchronously — call it
    /// outside a tokio runtime (see [`Ops::load_identity`]).
    pub(crate) fn resolve_peer(&self, host: &str) -> Result<PeerTarget, OpError> {
        let identity = self.load_identity()?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
        })?;
        let trust = self.open_trust()?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        let (address, server_name) = resolve_peer_address(&trust.snapshot(), &hosts, host)?;
        Ok(PeerTarget {
            identity,
            trust,
            address,
            server_name,
        })
    }

    /// Resolve `host` to a [`PeerRoute`] — the routing decision
    /// [`Self::resolve_host_route`] already makes (live reverse
    /// registration beats a forward pin), turned into what
    /// `Ops::connect`/`connect_target` (`crate::ops::session`) need to
    /// actually build a connection over either link (`PLAN.md` M3 Step 6).
    ///
    /// **Sync, and not callable from inside a running Tokio runtime** —
    /// same caveat as [`Self::resolve_peer`] (identity loads synchronously
    /// on the forward branch, which a platform key store will not hand
    /// over from inside one) and [`Self::resolve_host_route`] (whose own
    /// doc this delegates to). Called from `Ops::connect`/`connect_target`
    /// *before* either builds its own runtime for the dial — sequential,
    /// not nested, runtimes: [`Self::resolve_host_route`]'s throwaway
    /// probe runtime is built and torn down here, before the dial's own
    /// multi-thread runtime exists.
    pub(crate) fn resolve_route(&self, host: &str) -> Result<PeerRoute, OpError> {
        match self.resolve_host_route(host)? {
            HostRoute::Forward { .. } => Ok(PeerRoute::Forward(self.resolve_peer(host)?)),
            HostRoute::Reverse { socket, .. } => Ok(PeerRoute::Reverse(LocalRoute {
                host: host.to_string(),
                socket,
            })),
        }
    }

    /// Dial `address` once with an empty trust store and report the
    /// fingerprint the peer presented.
    ///
    /// Because nothing is trusted, the handshake always ends in a local
    /// rejection — the observation is the *point* of the dial, and no
    /// usable connection is ever established. Used by `trust.add` and by
    /// the CLI's interactive pin prompt.
    pub fn probe_fingerprint(&self, address: &str) -> Result<Fingerprint, OpError> {
        // Load the identity *before* entering the runtime: a platform key
        // store blocks on the OS credential service.
        let Some(loaded) = self.load_identity()? else {
            return Err(OpError::new(
                ErrorCode::ConfigError,
                format!(
                    "no device identity in {}; run qsh init first",
                    self.paths.config_dir.display()
                ),
            )
            .with_retryable(false));
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                OpError::new(
                    ErrorCode::Internal,
                    format!("failed to start an async runtime: {err}"),
                )
                .with_retryable(false)
            })?;

        let dialer = Dialer::new(loaded.local, Arc::new(StaticTrust::empty()))
            .with_timeout(PROBE_DIAL_TIMEOUT);
        let server_name = server_name_for(address);

        runtime.block_on(async move {
            let socket = resolve_one(address).await?;
            match dialer.dial(socket, &server_name).await {
                // Unreachable in practice (an empty trust store rejects
                // every peer), but never leave a connection open.
                Ok(dialed) => {
                    let observed = dialed.observation().and_then(|o| o.fingerprint);
                    dialed.connection.close(0, b"probe");
                    observed.ok_or_else(|| {
                        OpError::new(
                            ErrorCode::Internal,
                            "peer accepted by an empty trust store".to_string(),
                        )
                        .with_retryable(false)
                    })
                }
                // The expected outcome: our (empty) trust store rejected
                // the peer, and the verifier recorded what it presented.
                Err(DialError::LocalRejected {
                    observed: Some(fingerprint),
                    ..
                }) => Ok(fingerprint),
                Err(err) => Err(classify_probe_failure(err, address)),
            }
        })
    }
}

/// Resolve `host:port` to its first socket address. `pub(crate)` — Step 3's
/// `qsh reverse` (`crate::reverse::target::run_reverse`) reuses this exact
/// resolution instead of a second copy of it, for the same reason
/// [`resolve_peer_address`] just below is split out.
pub(crate) async fn resolve_one(address: &str) -> Result<SocketAddr, OpError> {
    let mut addrs = tokio::net::lookup_host(address).await.map_err(|err| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            format!("failed to resolve {address}: {err}"),
        )
    })?;
    addrs.next().ok_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            format!("{address} resolved to no addresses"),
        )
    })
}

/// The `(address, server_name)` half of [`Ops::resolve_peer`] that touches
/// no identity — split out so a caller that already holds its own
/// [`LoadedIdentity`] can reuse the trust-store/`hosts.toml` lookup without
/// a second synchronous identity load of its own. `qsh reverse` (`PLAN.md`
/// M3 Step 3, `crate::reverse::target::run_reverse`/`dial_and_register`) is
/// that caller: it loads identity once, outside any runtime, ahead of a
/// reconnect loop that must not reopen the keystore per dial
/// (`docs/design/protocol.md` §11-4), so it cannot go through
/// [`Ops::resolve_peer`] itself (which always loads identity synchronously
/// — safe only when called before a runtime exists, per that method's own
/// doc).
///
/// Address resolution: `hosts.toml` layered over `trust`'s pinned peers,
/// via [`host::resolve_forward`] — the exact same decision
/// [`Ops::host_list`]/[`Ops::resolve_host_route`] make (`PLAN.md` M7 Step
/// 3, §4.1 #4). Identity/trust is unaffected: the fingerprint a dial
/// actually presents is still verified solely against `trust` at the TLS
/// layer ([`qsh_transport::TrustEvaluator::lookup_pin`] is fingerprint-
/// keyed across the whole store, not scoped to `host`) — `hosts.toml`
/// supplying an address for a name with no trust peer, or a different
/// address than trust's own pin, never changes *who* is allowed to answer.
pub(crate) fn resolve_peer_address(
    trust: &TrustStore,
    hosts: &HostsFile,
    host: &str,
) -> Result<(String, String), OpError> {
    let hosts_has_any = !hosts.entries().is_empty();
    // Message text is a frozen golden fixture
    // (`crates/qsh-cli/tests/fixtures/cli-v1/error.HOST_NOT_FOUND.json`,
    // via `qsh exec nowhere`) — kept byte-identical to the pre-M7-Step-3
    // wording even though the remedy it names (`qsh trust add`) is now
    // only one of two ways to fix this (the other being a `hosts.toml`
    // entry); fixtures are append-only, this is not an editable one. The
    // fixture's own input (`"nowhere"`) has no `@`, so [`host::hint_alias`]
    // is a no-op for it and the fixture stays byte-identical; the strip
    // only changes behavior for `qsh exec <user>@<host> -- ...`
    // (`ExecArgs.host`, `docs/CLI.md` §6.9, a raw positional that — like
    // `qsh host get` — bypasses `parse_target`'s own `user@` split), which
    // used to echo the `user@` hint into this same un-runnable `qsh trust
    // add` shape `Ops::resolve_host_route` had (`PLAN.md` §3 Step 6,
    // lens-2 finding).
    let entry = host::resolve_forward(trust.find(host), hosts.find(host), hosts_has_any)
        .ok_or_else(|| match host::hint_alias(host) {
            host::HintAlias::Valid(alias) => OpError::new(
                ErrorCode::HostNotFound,
                format!(
                    "host {alias:?} is not in the trust store; pin it with `qsh trust add \
                     {alias} --address <host:port> --fingerprint sha256:...`"
                ),
            ),
            host::HintAlias::Empty => host::empty_host_name_error(),
            host::HintAlias::Invalid(alias) => host::invalid_host_alias_error(alias),
        })?;
    let server_name = server_name_for(&entry.address);
    Ok((entry.address, server_name))
}

/// SNI value for a dial. The verifier ignores it entirely
/// (`docs/design/protocol.md` §3), so this only needs to be a name rustls
/// will accept; the host part of the address is the most useful one for
/// packet captures.
fn server_name_for(address: &str) -> String {
    let host = match address.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => address,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        "qsh".to_string()
    } else {
        host.to_string()
    }
}

/// Turn a failed probe dial into the error the ops layer promises.
///
/// A *local* rejection with an observed fingerprint is the success case for
/// a probe and is handled by the caller; everything else is a genuine
/// failure. `AUTH_FAILED` details carry only a category — never a reason
/// that could leak trust-store contents (`docs/CLI.md` §6.11).
fn classify_probe_failure(err: DialError, address: &str) -> OpError {
    match err {
        DialError::LocalRejected {
            observed: Some(fingerprint),
            ..
        } => OpError::new(
            ErrorCode::TrustRequired,
            format!("peer {address} is not trusted"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({
            "observed_fingerprint": fingerprint.to_string(),
            "address": address,
        })),
        DialError::LocalRejected { observed: None, .. } => OpError::new(
            ErrorCode::AuthFailed,
            format!("could not read {address}'s certificate"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({"category": "unverifiable_certificate"})),
        DialError::RemoteRejected => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address} rejected this device's certificate"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({"category": "remote_rejected"})),
        // `PLAN.md` M8 Step 2 — same `ErrorCode::ConnectionFailed` as
        // `DialError::Failed` below, `qsh_transport::DialError::Refused`'s
        // own human message.
        DialError::Refused => {
            OpError::new(ErrorCode::ConnectionFailed, DialError::Refused.to_string())
        }
        DialError::Timeout(after) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("no response from {address} after {after:?}"),
        ),
        DialError::Connect(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot dial {address}: {err}"),
        ),
        DialError::Failed(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("connection to {address} failed: {err}"),
        ),
        DialError::Setup(err) => OpError::new(
            ErrorCode::Internal,
            format!("failed to build a client endpoint: {err}"),
        )
        .with_retryable(false),
    }
}

/// `trust.accept`'s own dial-failure classifier: unlike
/// [`classify_probe_failure`], the dialer here is
/// [`crate::pairing::AcceptAnyForPairing`] (accepts *any* fingerprint), so
/// a [`DialError::LocalRejected`] can only mean the peer's certificate
/// itself was structurally invalid (malformed, outside its validity
/// window — `qsh_transport::tls::verify_core`'s unconditional checks, which
/// run before any trust-evaluator branch), never "untrusted" — there is no
/// `observed_fingerprint` detail worth reporting since nothing was ever
/// evaluated against a fingerprint at all.
fn classify_pairing_dial_failure(err: DialError, address: &str) -> OpError {
    match err {
        DialError::LocalRejected { .. } => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address}'s certificate could not be verified"),
        )
        .with_retryable(false),
        DialError::RemoteRejected => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address} rejected this device's certificate"),
        )
        .with_retryable(false),
        // `PLAN.md` M8 Step 2 — same as `classify_probe_failure`'s arm.
        DialError::Refused => {
            OpError::new(ErrorCode::ConnectionFailed, DialError::Refused.to_string())
        }
        DialError::Timeout(after) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("no response from {address} after {after:?}"),
        ),
        DialError::Connect(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot dial {address}: {err}"),
        ),
        DialError::Failed(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("connection to {address} failed: {err}"),
        ),
        DialError::Setup(err) => OpError::new(
            ErrorCode::Internal,
            format!("failed to build a client endpoint: {err}"),
        )
        .with_retryable(false),
    }
}

/// Turn a failed [`crate::pairing::accept`] exchange into the `OpError`
/// `trust.accept` reports. `Remote { code, .. }` is the common case — the
/// responder already picked one of `AUTH_FAILED`/`TRUST_REQUIRED`/
/// `SESSION_CONFLICT`/`INTERNAL` via its own `PairingError::as_wire_error`
/// (report §B7) and this just carries that verdict through unchanged. The
/// `NoMatch`/`Expired`/`AlreadyConsumed`/`PinCollision` arms are the
/// responder's own local-matching outcomes and are never constructed by
/// [`crate::pairing::accept`] itself (only by `respond`) — present here
/// only so the match stays exhaustive, matching this codebase's existing
/// style for structurally-unreachable-but-required arms.
fn classify_pairing_exchange_failure(err: crate::pairing::PairingError) -> OpError {
    use crate::pairing::PairingError as E;
    match err {
        E::Remote {
            code,
            message,
            retryable,
        } => OpError::new(code, message).with_retryable(retryable),
        E::NoMatch => OpError::new(ErrorCode::AuthFailed, err.to_string()).with_retryable(false),
        E::Expired => OpError::new(ErrorCode::TrustRequired, err.to_string()).with_retryable(false),
        E::AlreadyConsumed | E::PinCollision => {
            OpError::new(ErrorCode::SessionConflict, err.to_string()).with_retryable(false)
        }
        E::InvalidDeviceName { .. } => {
            OpError::new(ErrorCode::InvalidArgument, err.to_string()).with_retryable(false)
        }
        E::ResponderProofMismatch => {
            OpError::new(ErrorCode::AuthFailed, err.to_string()).with_retryable(false)
        }
        E::Timeout => OpError::new(ErrorCode::Timeout, err.to_string()),
        E::ClosedEarly | E::UnexpectedMessage | E::Stream(_) | E::Connection(_) => {
            OpError::new(ErrorCode::ConnectionFailed, err.to_string())
        }
        E::ExporterUnavailable => {
            OpError::new(ErrorCode::Internal, err.to_string()).with_retryable(false)
        }
        E::Store(op_err) => op_err,
    }
}

#[cfg(test)]
mod tests;
