//! The trust store (`<config_dir>/trust.toml`): pinned peers and private CA
//! roots (`docs/design/architecture.md` §5, §7).
//!
//! ```toml
//! [[peer]]
//! name = "personal-mac"
//! fingerprint = "sha256:BASE64FINGERPRINT"
//! address = "personal-mac.example.com:4433"
//! added_at = "2026-08-17T00:00:00Z"
//!
//! [[ca]]
//! name = "corp-root"
//! cert_pem = "-----BEGIN CERTIFICATE-----\n…"
//! ```
//!
//! Verification logic itself lives in `qsh-transport`
//! ([`qsh_transport::QshPeerVerifier`]); this module only *evaluates* trust
//! and injects the answer through [`qsh_transport::TrustEvaluator`], which
//! [`SharedTrustStore`] implements.
//!
//! The pinned peers here are still the sole source of *identity* for every
//! host — [`TrustStore::resolve_host`] is one input `crate::ops::host`'s
//! `resolve_forward` layers `crate::hosts::HostsFile` over for `qsh exec
//! <host>`'s host → address resolution (`PLAN.md` M7 Step 3, §4.1 #4,
//! `docs/CLI.md` §6.8): `hosts.toml` may supply or override the *address*,
//! but never the fingerprint — a peer's identity is decided here alone.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::SystemTime;

use qsh_proto::{ErrorCode, TrustPeer};
use qsh_transport::{CertificateDer, Fingerprint, Principal, TrustEvaluator};
use serde::{Deserialize, Serialize};

use crate::config::{config_io_error, ensure_private_dir, write_private_file};
use crate::identity::pem;
use crate::ops::OpError;

pub mod invite_address;
pub mod pairing;
pub use pairing::SharedInviteStore;

/// The one line an operator gets when a peer address named no port and
/// 4433 was assumed (ADR-0014 결정 5). stderr only, on the write paths
/// only (`qsh trust add`, `qsh trust accept`, and `qsh serve --to` from
/// M9 Step 5), and only when [`NormalizedAddress::port_filled`] is true.
/// Never a field of a `qsh.cli/v1` envelope and never on a read path:
/// `trust.list`/`host.list`/`host.get` stay silent (those ops each return
/// several entries, so a line per entry would be noise, and pointing out a
/// hand-written file's notation on every op does not fit "the file is the
/// operator's to manage").
///
/// The wording lives here, not in the frontend, because operator-facing
/// text has one canonical copy in `qsh-core` and the CLI only writes what
/// it is handed (`docs/design/architecture.md` §1; precedent:
/// [`crate::ops::INVITE_CODE_PROMPT`]).
///
/// Three parts (ADR-0014 결정 5, "관측·영향·다음 명령"): what happened
/// (`assuming port 4433: the peer address names no port`), what it means
/// (`so this command uses port 4433 everywhere that address goes`), and
/// what to do about it (`Re-run with an explicit \`host:port\` to use a
/// different port.`). The leading seven words are byte-identical to the
/// pre-M9 wording on purpose: `qsh-cli/tests/init_trust.rs` and
/// `qsh-cli/tests/trust_pairing_live.rs` each assert
/// `stderr.matches("assuming port 4433").count() == 1`, and this notice
/// fires from three call sites (`qsh trust add`, `qsh trust accept`, and
/// `qsh serve --to`) that share one wording rather than one
/// per site (ADR-0014 결정 5 requires a single line). "pins" was
/// deliberately left out of the impact clause — at the `serve --to` site
/// this notice also fires from, the normalized address only looks an
/// already-pinned peer up, it pins nothing (ADR-0014 결정 7) — so
/// `everywhere that address goes` is the one clause true at all three
/// sites.
pub const ADDRESS_PORT_ASSUMED_NOTICE: &str = "assuming port 4433: the peer address names no port, so this command uses port 4433 everywhere that address goes. Re-run with an explicit `host:port` to use a different port.";

/// The notice must name the one default port and nothing else — a second
/// literal here would be a second source of truth (ADR-0014 결정 1).
/// [`crate::serve::names_only_port`], not [`crate::serve::trailing_port`]:
/// this notice puts the port in the middle of a sentence, not at the end,
/// so there is no trailing digit run for `trailing_port` to scan back
/// over.
const _: () = assert!(
    crate::serve::names_only_port(ADDRESS_PORT_ASSUMED_NOTICE, crate::serve::DEFAULT_PORT),
    "ADDRESS_PORT_ASSUMED_NOTICE must name serve::DEFAULT_PORT and no other number"
);

/// Outcome of [`normalize_peer_address`]: the address every downstream
/// consumer must use, plus whether this call is what put the port there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedAddress {
    /// The normalized address. Never a rewrite of any file on disk
    /// (ADR-0014 결정 4): callers derive responses from it, they do not
    /// save it back to `trust.toml`/`hosts.toml`.
    pub address: String,
    /// `true` only when the default port was actually appended. The one
    /// input that makes the `assuming port 4433` notice
    /// ([`ADDRESS_PORT_ASSUMED_NOTICE`]) correct to print.
    pub port_filled: bool,
}

/// The single place a peer address gets its port filled in (ADR-0014 결정 2,
/// "파서 한 곳"). Pure: no I/O, no clock, no errors.
///
/// A peer address is what an operator hand-writes or hand-relays: `qsh
/// trust add --address`, `qsh trust accept <address>`, and the `address`
/// fields of `trust.toml`/`hosts.toml`. When it names no port, the one port
/// qsh uses (`crate::serve::DEFAULT_PORT`, 4433) is appended. When it
/// already names one, or is empty, the input comes back byte-identical.
///
/// Not for bind specs. `qsh serve --bind`/`qsh listen --bind` still refuse a
/// port-less spec (ADR-0014 결정 8): a bind decides where this machine
/// listens, and that is not a value to guess at.
///
/// Port *range* is not this function's business either (`PLAN.md` M9 §4.1
/// #12): `"host:0"` and `"host:99999"` come back untouched and fail later,
/// at dial time, exactly as they do today. The `1..=65535` rule belongs to
/// the `-L`/`-R` spec grammar alone (`docs/CLI.md:482`,
/// `qsh_proto::wire::parse_forward_spec`).
pub fn normalize_peer_address(address: &str) -> NormalizedAddress {
    let as_given = || NormalizedAddress {
        address: address.to_string(),
        port_filled: false,
    };
    let filled = |address: String| NormalizedAddress {
        address,
        port_filled: true,
    };

    // 1. An address-less pin stays address-less. `trust.toml`/`hosts.toml`
    //    use an empty `address` to mean "inbound-only peer, never a dial
    //    candidate" (`docs/CLI.md` §6.1·§6.11); turning it into `:4433`
    //    would invent a reachable-looking dial target out of nothing.
    //    (This filter runs strictly before rule 5 appends anything — the
    //    read path's own empty-string filter in `host::resolve_forward`
    //    duplicates it defensively, but this is the one that must hold for
    //    `trust_list`, which has no such filter of its own.)
    if address.is_empty() {
        return as_given();
    }
    // 2. A bracket-less IPv6 literal is a *host*, never host+port: its last
    //    group would otherwise read as a port (`::1` -> host `:`, port `1`).
    //    Bracketing is the contract layer's own rule, so call it rather than
    //    re-deriving it here.
    if address.parse::<std::net::Ipv6Addr>().is_ok() {
        return filled(qsh_proto::wire::format_host_port(
            address,
            crate::serve::DEFAULT_PORT,
        ));
    }
    // 3. Already carries a port — the same test `ops::server_name_for` uses
    //    to find the port it strips for SNI (`split_port`, shared so there
    //    is one rule and not two).
    if split_port(address).is_some() {
        return as_given();
    }
    // 4. Has a colon that is not a port and is not a closing bracket: the
    //    input is malformed (`"host:"`, `"host:ssh"`, `"[::1]:x"`).
    //    Appending would only add a second colon, producing a string the
    //    operator never typed and no resolver can read; hand the bytes back
    //    and let the dial report them verbatim, exactly as today.
    if address.contains(':') && !address.ends_with(']') {
        return as_given();
    }
    // 5. A name, an IPv4 literal, or a bracketed IPv6 with no port.
    filled(format!("{address}:{}", crate::serve::DEFAULT_PORT))
}

/// Where the port starts in a peer address, when it has one: the run after
/// the rightmost `:`, if that run is non-empty and all ASCII digits.
///
/// One rule, three consumers: [`normalize_peer_address`]'s "does it
/// already have a port" test, the SNI host `ops::server_name_for` extracts
/// (ADR-0014 결정 2, "이미 코드에 있는 규칙을 재사용한다"), and
/// [`invite_address::port_from_bind_spec`]'s read of the `[serve].bind`
/// port.
pub(crate) fn split_port(address: &str) -> Option<(&str, &str)> {
    match address.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            Some((host, port))
        }
        _ => None,
    }
}

/// A private CA root the verifier accepts chains against.
///
/// Written by `qsh cert issue` (`docs/adr/0008-private-ca-cert-issuance.md`,
/// `PLAN.md` M7 Step 5) via [`TrustStore::add_ca`], and equally loadable
/// from an operator-provisioned `trust.toml` that was never touched by
/// `qsh cert` at all — this store only ever *evaluates* `[[ca]]` entries,
/// it never assumes how one got here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaEntry {
    /// Operator-chosen label.
    pub name: String,
    /// PEM-encoded root certificate.
    pub cert_pem: String,
}

/// `trust.toml` as serialized.
#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustFile {
    #[serde(default, rename = "peer", skip_serializing_if = "Vec::is_empty")]
    peers: Vec<TrustPeer>,
    #[serde(default, rename = "ca", skip_serializing_if = "Vec::is_empty")]
    cas: Vec<CaEntry>,
}

/// An in-memory snapshot of the trust store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustStore {
    peers: Vec<TrustPeer>,
    cas: Vec<CaEntry>,
}

impl TrustStore {
    /// Load `path`. A missing file is an empty store (not an error); a
    /// malformed one is `CONFIG_ERROR` — QSH never guesses at trust.
    pub fn load(path: &Path) -> Result<Self, OpError> {
        match read_raw(path)? {
            Some(text) => Self::parse(path, &text),
            None => Ok(Self::default()),
        }
    }

    /// Parse `text` (already-read bytes at `path`, used only for error
    /// messages). Split out of [`TrustStore::load`] so
    /// [`SharedTrustStore::refresh`] can reuse it without re-reading a file
    /// it already has in hand — the content it just read *is* the
    /// invalidation check (`PLAN.md` M7 Step 2 P2-2), so by the time this
    /// runs the bytes are already sitting in memory.
    fn parse(path: &Path, text: &str) -> Result<Self, OpError> {
        let file: TrustFile = toml::from_str(text).map_err(|err| {
            OpError::new(
                ErrorCode::ConfigError,
                format!("invalid trust store {}: {err}", path.display()),
            )
            .with_retryable(false)
        })?;
        Ok(Self {
            peers: file.peers,
            cas: file.cas,
        })
    }

    /// Acquire the cross-process advisory lock guarding `path`'s whole
    /// read-modify-write cycle (`PLAN.md` M7 Step 7-1). Every caller must
    /// acquire this **before** [`TrustStore::load`] and hold the returned
    /// guard until after [`TrustStore::save`] — locking only around the
    /// write (the pre-Step-7-1 state) still lets two writers each load a
    /// stale copy, mutate it, and have the later `save` silently discard
    /// the earlier writer's change. Two scenarios this closes:
    ///
    /// - **S1** (lost update): a `qsh serve` pairing response loads
    ///   `trust.toml`, and while it is composing its own save a concurrent
    ///   `qsh trust remove` finishes its own load→mutate→save first — the
    ///   pairing response's save then overwrites the file with a copy
    ///   that still has the just-removed peer in it, silently resurrecting
    ///   a pin the operator just revoked.
    /// - **S3** (file corruption): two pairing responses land on the same
    ///   `qsh serve` process at once (`tokio::spawn` per connection) and
    ///   both reach `TrustStore::save` around the same time — without a
    ///   cross-writer lock, [`crate::config::write_private_file_io`]'s
    ///   writer-scoped temp ticket keeps their temp files from colliding,
    ///   but the two renames can still interleave so that whichever loses
    ///   the race clobbers the winner's just-written file with its own
    ///   stale copy.
    ///
    /// **Lock order**: any `RwLock`/`Mutex` the caller already holds must
    /// be acquired **before** this call, never after — see
    /// [`crate::config::FileLock`]'s own doc for why reversing it risks a
    /// deadlock.
    pub(crate) fn lock(path: &Path) -> Result<crate::config::FileLock, OpError> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
            // `path` (`trust.toml`, in `config_dir`) is written through
            // `write_private_file` -> `fsutil::write_atomically`, so this
            // directory does receive `.tmp{pid}-*` orphans on a crash
            // between temp-write and rename (M7 carryover (iv)).
            // `ca::init`/`identity::init` already sweep `config_dir` once
            // at `qsh init` time, but this call site runs on every trust
            // lock/save over a long-running `qsh serve`'s whole lifetime,
            // so sweeping here too bounds how long an orphan can sit
            // around between `qsh init` runs.
            crate::fsutil::sweep_stale_temp_files(parent);
        }
        crate::config::FileLock::acquire(&crate::config::lock_path_for(path))
    }

    /// Write the store to `path` (0600, in a 0700 directory, atomically).
    pub fn save(&self, path: &Path) -> Result<(), OpError> {
        if let Some(parent) = path.parent() {
            // Partial adoption (부분 채택): no sweep here any more. Every real
            // call site reaches `save` from within the same
            // lock→load→mutate→save cycle whose `Self::lock` call just
            // swept this directory microseconds earlier — a second
            // `read_dir` walk here bought nothing but a redundant
            // directory scan on the pairing response path this milestone
            // is hardening.
            ensure_private_dir(parent)?;
        }
        let file = TrustFile {
            peers: self.peers.clone(),
            cas: self.cas.clone(),
        };
        let text = toml::to_string_pretty(&file).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("failed to encode trust store {}: {err}", path.display()),
            )
            .with_retryable(false)
        })?;
        write_private_file(path, text.as_bytes())
    }

    /// All pinned peers, in store order.
    pub fn peers(&self) -> &[TrustPeer] {
        &self.peers
    }

    /// All private CA roots, in store order.
    pub fn cas(&self) -> &[CaEntry] {
        &self.cas
    }

    /// The pin named `name`, if any.
    pub fn find(&self, name: &str) -> Option<&TrustPeer> {
        self.peers.iter().find(|p| p.name == name)
    }

    /// This store's own half of host → address resolution: only peers
    /// that actually carry a dial address resolve. `crate::ops::host`'s
    /// `resolve_forward` (`PLAN.md` M7 Step 3) is what layers
    /// `hosts.toml` over this — callers that need the *actual* resolution
    /// `qsh exec <host>`/`qsh <host>` use should go through that, not
    /// this method directly, unless they deliberately want the
    /// trust-only view (e.g. `forward_hosts`' own name enumeration).
    pub fn resolve_host(&self, name: &str) -> Option<&TrustPeer> {
        self.find(name).filter(|p| !p.address.is_empty())
    }

    /// Every pinned peer whose own dial address normalizes
    /// ([`normalize_peer_address`]) to `normalized_address` (already
    /// normalized by the caller) — the address half of `qsh serve --to`'s
    /// two-step resolution (ADR-0014 결정 7, ROADMAP M9 (b)): name lookup
    /// (`crate::ops::resolve_peer_address`) runs first, and only on a
    /// miss does a caller fall back to this scan. An address-less pin
    /// (`""`, inbound-only, `docs/CLI.md` §6.1/§6.11) never matches — the
    /// same "empty means never a dial target" rule
    /// [`normalize_peer_address`]'s own doc states.
    ///
    /// Returns every match rather than picking one: more than one match is
    /// the caller's ambiguity to reject (`INVALID_ARGUMENT`, no first-wins
    /// — ADR-0014 결정 7 is explicit that address ambiguity must not be
    /// silently resolved the way `--to`'s name lookup is single-valued by
    /// construction).
    pub fn find_by_address<'a>(
        &'a self,
        normalized_address: &'a str,
    ) -> impl Iterator<Item = &'a TrustPeer> + 'a {
        self.peers.iter().filter(move |p| {
            !p.address.is_empty()
                && normalize_peer_address(&p.address).address == normalized_address
        })
    }

    /// Pin `name`, idempotently — with one deliberate exception (`PLAN.md`
    /// M7 Step 2 decision B): re-adding an already-pinned name under the
    /// *same* fingerprint but a *different* `address` overwrites the
    /// stored address in place (the M6 mobility campaign's backlog item —
    /// a host that changed its reachable address had no way to update a
    /// client's pin short of `remove` + `add`).
    ///
    /// Returns `(peer, created, updated)`:
    /// - **New name:** `created = true`, `updated = false`, `peer` is the
    ///   freshly written pin.
    /// - **Existing name, same fingerprint, address unchanged (or none
    ///   given):** a pure no-op — `created = false`, `updated = false`,
    ///   `peer` is the existing entry, untouched.
    /// - **Existing name, same fingerprint, a different address given:**
    ///   the stored address is overwritten in place — `created = false`,
    ///   `updated = true`, `peer` is the entry with its new address.
    ///   `added_at` is left as it was (it records when the *identity* was
    ///   first pinned, not when the address last changed).
    /// - **Existing name, a *different* fingerprint:** nothing changes at
    ///   all — `created = false`, `updated = false`, `peer` is the existing
    ///   entry, untouched. Re-binding an identity is a deliberate operator
    ///   action (remove, then add), never a side effect of a repeated
    ///   `trust add` (`docs/CLI.md` §6.11).
    pub fn add_peer(
        &mut self,
        name: impl Into<String>,
        address: Option<String>,
        fingerprint: Fingerprint,
        now: String,
    ) -> (TrustPeer, bool, bool) {
        let name = name.into();
        let fingerprint = fingerprint.to_string();
        if let Some(existing) = self.find(&name) {
            if existing.fingerprint != fingerprint {
                return (existing.clone(), false, false);
            }
            let Some(new_address) = address else {
                return (existing.clone(), false, false);
            };
            if existing.address == new_address {
                return (existing.clone(), false, false);
            }
            let index = self
                .peers
                .iter()
                .position(|p| p.name == name)
                .expect("just found by find()");
            self.peers[index].address = new_address;
            return (self.peers[index].clone(), false, true);
        }
        let peer = TrustPeer {
            name,
            fingerprint,
            address: address.unwrap_or_default(),
            added_at: now,
        };
        self.peers.push(peer.clone());
        (peer, true, false)
    }

    /// Register a private CA root, idempotently (`qsh cert issue`,
    /// `docs/adr/0008-private-ca-cert-issuance.md` §6 결과: "trust.toml
    /// \[\[ca\]\] 등재는 additive·append-only이며 중복 방지·갱신 semantics는
    /// trust add(Step 2) 선례를 따른다") — the same created/updated shape
    /// as [`TrustStore::add_peer`], keyed on `name` instead of
    /// fingerprint since a CA root has no principal of its own.
    ///
    /// **Scope:** this in-place-overwrite-on-mismatch behavior is only
    /// ever reached from `qsh cert issue`'s *local* re-init of a CA it
    /// already owns under that name — never from an operator-supplied
    /// root (`trust add-ca`, ADR-0013 결정 5), which instead goes through
    /// [`TrustStore::add_ca_append_only`] and refuses a name collision
    /// rather than overwrite it.
    ///
    /// Returns `(entry, created, updated)`:
    /// - **New name:** `created = true`, `updated = false`.
    /// - **Existing name, identical `cert_pem`:** a pure no-op —
    ///   `created = false`, `updated = false`. Re-running `qsh cert issue`
    ///   against the same local CA never rewrites `trust.toml`.
    /// - **Existing name, a different `cert_pem`:** the stored PEM is
    ///   overwritten in place — `created = false`, `updated = true`. This
    ///   only happens by construction from a *local* re-init of the CA
    ///   under the same name; nothing here fetches or trusts a remote
    ///   root on the strength of a name match.
    pub fn add_ca(&mut self, name: impl Into<String>, cert_pem: String) -> (CaEntry, bool, bool) {
        let name = name.into();
        if let Some(index) = self.cas.iter().position(|ca| ca.name == name) {
            if self.cas[index].cert_pem == cert_pem {
                return (self.cas[index].clone(), false, false);
            }
            self.cas[index].cert_pem = cert_pem;
            return (self.cas[index].clone(), false, true);
        }
        let entry = CaEntry { name, cert_pem };
        self.cas.push(entry.clone());
        (entry, true, false)
    }

    /// Register an *operator-supplied* CA root (`qsh trust add-ca`,
    /// ADR-0013 결정 5) — append-only, unlike [`TrustStore::add_ca`]'s
    /// local-reinit overwrite semantics: a name collision with a
    /// *different* `cert_pem` is refused rather than silently replacing
    /// a trust anchor an operator may not have intended to change.
    ///
    /// Returns `(entry, created, updated)` on success:
    /// - **New name:** `created = true`, `updated = false`.
    /// - **Existing name, identical `cert_pem`:** a pure no-op —
    ///   `created = false`, `updated = false` (idempotent re-registration).
    /// - **Existing name, a different `cert_pem`:** `Err(OpError)`,
    ///   `INVALID_ARGUMENT`, naming only the CA's `name` — never either
    ///   PEM's bytes; the message tells the operator to `trust remove`
    ///   the old entry first if replacing it is actually intended.
    pub fn add_ca_append_only(
        &mut self,
        name: &str,
        cert_pem: String,
    ) -> Result<(CaEntry, bool, bool), OpError> {
        if let Some(existing) = self.cas.iter().find(|ca| ca.name == name) {
            if existing.cert_pem == cert_pem {
                return Ok((existing.clone(), false, false));
            }
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "CA root {name:?} is already registered under a different certificate; \
                     remove it with `qsh trust remove {name}` first"
                ),
            )
            .with_retryable(false));
        }
        Ok(self.add_ca(name.to_string(), cert_pem))
    }

    /// Remove the peer pin and/or the CA root named `name`. This is the
    /// only way to replace an operator-registered root (ADR-0013 결정 5):
    /// [`TrustStore::add_ca_append_only`] refuses a name collision and
    /// tells the operator to `trust remove` the old entry first. If both
    /// a pin and a CA root share `name`, both are dropped — erring
    /// fail-closed, since removal only ever narrows trust, never widens
    /// it. Returns `true` if either list shrank, `false` if there was
    /// neither (idempotent).
    pub fn remove(&mut self, name: &str) -> bool {
        let peers_before = self.peers.len();
        self.peers.retain(|p| p.name != name);
        let cas_before = self.cas.len();
        self.cas.retain(|ca| ca.name != name);
        self.peers.len() != peers_before || self.cas.len() != cas_before
    }

    /// Pins as `(fingerprint, principal)` pairs. Entries whose fingerprint
    /// string does not parse are skipped with a `WARN` — a corrupt line
    /// must never widen trust, and must not disable the rest of the store.
    fn parsed_pins(&self) -> Vec<(Fingerprint, Principal)> {
        self.peers
            .iter()
            .filter_map(|peer| match peer.fingerprint.parse::<Fingerprint>() {
                Ok(fp) => Some((fp, Principal::Device(peer.name.clone()))),
                Err(err) => {
                    tracing::warn!(peer = %peer.name, %err, "ignoring pin with an unparsable fingerprint");
                    None
                }
            })
            .collect()
    }

    /// CA roots as DER. Unparsable PEM is skipped with a `WARN`.
    fn parsed_cas(&self) -> Vec<CertificateDer<'static>> {
        self.cas
            .iter()
            .filter_map(|ca| match pem::decode_first(pem::CERTIFICATE, &ca.cert_pem) {
                Ok(der) => Some(CertificateDer::from(der)),
                Err(err) => {
                    tracing::warn!(ca = %ca.name, %err, "ignoring CA entry with unparsable PEM");
                    None
                }
            })
            .collect()
    }
}

/// The cached, parsed view [`SharedTrustStore`] serves to the verifier.
#[derive(Debug)]
struct Cached {
    /// The exact on-disk text this snapshot was parsed from (`None` for a
    /// missing file). This — not `mtime` — is the final arbiter of whether
    /// [`SharedTrustStore::refresh`] reloads: it is compared byte-for-byte
    /// on *every* refresh call. A filesystem with 1-2s mtime resolution
    /// (HFS+, exFAT/FAT, some SMB/NFS mounts) can otherwise leave a
    /// same-tick content change invisible to an mtime-only check
    /// (`PLAN.md` M7 Step 2 P2-2) — `trust.toml` is small enough that
    /// reading it in full on every handshake costs nothing next to the TLS
    /// handshake that triggers it.
    raw: Option<String>,
    /// Last observed mtime. No longer gates a reload (`raw` does); kept
    /// only as non-load-bearing metadata.
    mtime: Option<SystemTime>,
    store: TrustStore,
    pins: Vec<(Fingerprint, Principal)>,
    cas: Vec<CertificateDer<'static>>,
}

impl Cached {
    fn new(raw: Option<String>, mtime: Option<SystemTime>, store: TrustStore) -> Self {
        Self {
            pins: store.parsed_pins(),
            cas: store.parsed_cas(),
            store,
            raw,
            mtime,
        }
    }
}

/// A process-wide, reload-on-change view of `trust.toml` that satisfies
/// [`TrustEvaluator`].
///
/// The file's full content is read and compared on every lookup, and the
/// store is re-parsed whenever that content differs from the cached
/// snapshot — not merely when `mtime` moves (`PLAN.md` M7 Step 2 P2-2: an
/// mtime-only check is fail-open on a 1-2s-resolution filesystem, where two
/// edits inside the same tick share an mtime). `trust.toml` is small, so
/// this costs nothing next to the TLS handshake that triggers it. `qsh
/// trust add`/`remove` on a *running* `qsh serve` therefore takes effect
/// without a restart, deterministically, regardless of filesystem mtime
/// resolution. A failed reload keeps the last good snapshot (a
/// half-written file must not silently un-trust every peer); it never
/// *widens* trust, because widening requires a successful parse.
pub struct SharedTrustStore {
    path: PathBuf,
    cache: RwLock<Cached>,
    /// Set once, after construction, by [`SharedTrustStore::attach_pairing`]
    /// — never at `open()` time, because the pairing store is optional
    /// (only `qsh serve` wires one; a one-shot dial like `probe_fingerprint`
    /// never does) and because `Server::new`'s existing call sites must not
    /// change shape (`PLAN.md` M7 Step 4, same `OnceLock`-after-construction
    /// pattern `crate::server::Server` uses for its own pairing store).
    /// `pairing_open()` answers `false` whenever this is unset — identical
    /// to `TrustEvaluator::pairing_open`'s own default, so an evaluator that
    /// never attaches one behaves exactly as it did before this step.
    pairing: OnceLock<Arc<SharedInviteStore>>,
}

impl std::fmt::Debug for SharedTrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedTrustStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SharedTrustStore {
    /// Open (and eagerly load) the trust store at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Result<Arc<Self>, OpError> {
        let path = path.into();
        let raw = read_raw(&path)?;
        let store = match &raw {
            Some(text) => TrustStore::parse(&path, text)?,
            None => TrustStore::default(),
        };
        Ok(Arc::new(Self {
            cache: RwLock::new(Cached::new(raw, mtime_of(&path), store)),
            path,
            pairing: OnceLock::new(),
        }))
    }

    /// The file this view is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Wire an invite store into this trust view's
    /// [`TrustEvaluator::pairing_open`] answer (`qsh serve`'s startup path,
    /// `PLAN.md` M7 Step 4). A no-op past the first call — matching every
    /// other `OnceLock`-after-construction seam in this step (`Server`'s own
    /// pairing store): a `Server`/`SharedTrustStore` is built once per
    /// process, so "attach exactly once, right after construction" is the
    /// only shape that matters in practice.
    pub fn attach_pairing(&self, store: Arc<SharedInviteStore>) {
        let _ = self.pairing.set(store);
    }

    /// A copy of the current (possibly reloaded) store contents.
    pub fn snapshot(&self) -> TrustStore {
        self.refresh();
        self.read().store.clone()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Cached> {
        self.cache.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Re-read `trust.toml` if its on-disk *content* differs from the
    /// cached snapshot. Compared in full on every call — not gated on
    /// `mtime` — because `lookup_pin`/`ca_roots` call this on every TLS
    /// handshake and a coarse-granularity filesystem's mtime can miss a
    /// same-tick edit (`PLAN.md` M7 Step 2 P2-2). A read failure other
    /// than "file does not exist" (e.g. a permissions change) keeps the
    /// last good snapshot rather than un-trusting everyone; a missing file
    /// reloads as an empty store — fail-closed, mirroring
    /// [`TrustStore::load`]'s own contract.
    fn refresh(&self) {
        let raw = match read_raw(&self.path) {
            Ok(raw) => raw,
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %err,
                    "failed to read the trust store for a refresh; keeping the last good snapshot"
                );
                return;
            }
        };
        // Double-checked: a cheap read-lock check first (the common case,
        // where nothing changed), then re-check under the write lock in
        // case another thread already applied the same reload.
        if self.read().raw == raw {
            return;
        }
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if cache.raw == raw {
            return;
        }
        let parsed = match &raw {
            Some(text) => TrustStore::parse(&self.path, text),
            None => Ok(TrustStore::default()),
        };
        match parsed {
            Ok(store) => {
                // Content changed (we would not be here otherwise) but the
                // mtime did not move: the coarse-granularity-filesystem
                // scenario P2-2 identified. Not actionable — the content
                // check already caught it — but worth a trace for whoever
                // is debugging a filesystem that behaves this way.
                let new_mtime = mtime_of(&self.path);
                if new_mtime.is_some() && new_mtime == cache.mtime {
                    tracing::debug!(
                        path = %self.path.display(),
                        "trust store content changed with no mtime movement \
                         (coarse filesystem mtime resolution?); reloaded anyway"
                    );
                }
                *cache = Cached::new(raw, new_mtime, store);
            }
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %err,
                    "failed to reload the trust store; keeping the last good snapshot"
                );
            }
        }
    }
}

fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Read `path` in full. A missing file is `Ok(None)` (an empty store, not
/// an error, mirroring [`TrustStore::load`]'s contract); any other read
/// failure is `Err`.
fn read_raw(path: &Path) -> Result<Option<String>, OpError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(config_io_error(path, "read", &err)),
    }
}

impl TrustEvaluator for SharedTrustStore {
    fn lookup_pin(&self, fingerprint: &Fingerprint) -> Option<Principal> {
        self.refresh();
        self.read()
            .pins
            .iter()
            .find(|(fp, _)| fp == fingerprint)
            .map(|(_, principal)| principal.clone())
    }

    fn ca_roots(&self) -> Vec<CertificateDer<'static>> {
        self.refresh();
        self.read().cas.clone()
    }

    /// `true` iff an invite store is attached ([`Self::attach_pairing`])
    /// and it currently reports at least one record within its retention
    /// window (`crate::trust::pairing`'s module doc) — `false` (the trait's
    /// own default) when nothing is attached at all, e.g. a one-shot dial
    /// evaluator that never calls `attach_pairing`.
    fn pairing_open(&self) -> bool {
        match self.pairing.get() {
            Some(store) => store.pairing_open(SystemTime::now()),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests;
