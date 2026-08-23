//! `localctl` — the IPC a CLI process on this machine speaks to *its own*
//! resident `qsh listen` daemon over a Unix domain socket
//! (`$XDG_RUNTIME_DIR/qsh/<pid>.sock`, `docs/design/architecture.md` §7,
//! `docs/design/protocol.md` §11-3, ADR-0003 결과 절 2026-08-18/19 추기).
//! `PLAN.md` M3 Step 5 introduces this module tree, split into two PRs: 5a
//! (this transport/security layer) and 5b (`Ops::host_list`/`host_get`,
//! `qsh hosts`, renderers — layered on top, not here).
//!
//! ## Trust model (read before touching any conduit code)
//!
//! **localctl grants no new authority.** The only thing that can connect
//! to this socket is a process running as *this machine's same OS user* —
//! the socket is mode 0600 inside a mode 0700 directory, and the daemon
//! additionally rejects any connecting peer whose euid does not match its
//! own (`SO_PEERCRED` on Linux / `getpeereid` on macOS), checked **before**
//! it reads a single frame off the connection — fail closed even if the
//! runtime directory's permission bits were somehow wrong. That same OS
//! user can already read this machine's device key, so nothing localctl
//! exposes hands out privilege the caller did not already have.
//!
//! **localctl is not an authorization layer.** The daemon never calls
//! `Authorizer::check` for a conduit — doing so would evaluate the
//! *wrong* principal (itself, not the remote peer the request is
//! ultimately headed to). Real authorization happens exactly where it
//! always has: the *target* evaluates its own ACL against the
//! *controller's* TLS-authenticated principal when a relayed
//! `SessionOpen`/`SessionAttach` arrives over the live reverse QUIC
//! connection (`docs/design/protocol.md` §11-3 — "역방향 등록은 도달성만
//! 부여하고 권한은 부여하지 않는다"). The daemon also **never trusts any
//! principal-like value the CLI side sends it**: a local socket peer can
//! put anything it likes in a frame body, and the only fact localctl is
//! allowed to act on is the OS-level peer credential it checked at accept
//! time. No ACL or audit call belongs on the conduit path.
//!
//! ## Module layout and the arch rule this seam protects
//!
//! [`frame`] and [`client`] run in the *CLI process* and are **pure UDS
//! and `qsh-proto` framing**: they must never name `qsh_transport`,
//! `quinn` or `rustls` — mechanically enforced by `xtask/src/arch.rs`'s
//! file-scoped `ModuleBan` for exactly these two files (`PLAN.md` M3 Step 5
//! names only `qsh_transport` for this pair; `quinn`/`rustls` are this
//! project's own stricter superset, since a QUIC name reaching either file
//! by any route is the same seam violation `qsh_transport` itself would
//! be). This is a narrower token set than [`crate::reverse::registry`]'s —
//! that module additionally bans `crate::client`, `crate::Principal` and
//! `crate::Fingerprint` (the full six tokens `BROKER_DIR`'s rule bans in
//! `broker/`), because `ReverseEntry` must mechanically never hold a live
//! `client::Session` (`PLAN.md` M3 Step 3). `frame`/`client` have no
//! parallel invariant to protect with those extra three tokens — they
//! never construct a `Session`/`Principal`/`Fingerprint` in the first
//! place — so PLAN.md does not ask for them here and arch-lint does not
//! enforce them here; do not assume they are covered by this seam. A CLI
//! process has no business holding a QUIC connection regardless.
//!
//! [`daemon`] is the one module allowed to import `qsh_transport` here (only
//! indirectly, through [`crate::reverse::listen::Listen`]/`Registry`, which
//! this PR does not itself add a fresh `qsh_transport` name to): it is the
//! bridge that answers this machine's `LOCAL_ADMIN` conduit from the
//! registry `qsh listen` already holds, and — from `PLAN.md` M3 Step 6
//! onward — relays a `LOCAL_CONTROL` conduit's requests onto a live reverse
//! QUIC connection and relays the answers back. Blurring that line would
//! erode exactly the seam `docs/design/architecture.md` §9 risk 2 ("in-listener session vs
//! listener restart") depends on staying sharp — a future out-of-process
//! supervisor needs `SessionBackend` (ADR-0003) and this IPC layer to
//! already be proven transport-free.
//!
//! [`mux`] (`PLAN.md` M3 Step 6, Stage A1) is the pure `request_id`
//! remapping and event-routing table [`daemon`] drives once it starts
//! multiplexing several `LOCAL_CONTROL` conduits onto one reverse QUIC
//! connection — it names no transport type at all (not even indirectly)
//! and has no async, no lock, no socket; see its own module docs for the
//! invariant it enforces.
//!
//! Every type here lives behind `#[cfg(unix)]` (see the `pub mod
//! localctl;` declaration in `lib.rs`) — localctl (UDS, peer credentials)
//! has no meaning on Windows, so this whole module tree compiles out there
//! (`docs/CLI.md` §6.13: Windows `qsh listen`/`qsh reverse` are
//! `UNSUPPORTED`, and `qsh hosts` returns forward hosts only — no daemon,
//! no socket, no localctl call at all).
//!
//! ## What must never cross a localctl frame
//!
//! Resume tokens (`docs/adr/0007-session-ref-and-resume-token-custody.md`)
//! never travel over a localctl conduit — `qsh.local.v1`'s message set
//! (`crates/qsh-proto/proto/qsh/local/v1.proto`, fixed by Step 1) has no
//! field for one, and nothing in this module tree should ever thread one
//! through it (`docs/design/testing.md` L6 `resume_secrecy` discipline
//! extends here, made mechanical by PR 5b's fixtures).

pub mod client;
pub mod daemon;
pub mod frame;
pub mod mux;
