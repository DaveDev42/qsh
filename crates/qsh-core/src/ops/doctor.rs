//! `doctor.run` (`docs/CLI.md` §6.17, `PLAN.md` M7 Step 6) — orchestrates
//! every diagnostic in [`crate::doctor`]/[`crate::doctor::probe`] into one
//! report. Local, authorization-free operation (`docs/CLI.md` §2.5's "인가
//! 불요" row), same discipline as `acl.check` ([`crate::ops::acl`]): never
//! dispatched to a remote peer.
//!
//! **Exit-code discipline** (`PLAN.md` M7 §4.1 #6, design brief §B): every
//! finding is reported as *data*, never a nonzero exit — `finish()` always
//! yields exit 0 for a successful `doctor.run`, mirroring `acl.check`'s own
//! precedent (`docs/CLI.md` §6.15: "acl check 자체는 실패하지 않는다— deny나
//! no-policy조차 exit 0"). [`Ops::doctor`] only returns `Err` (exit 255)
//! for a precondition doctor cannot work around at all: no device identity
//! yet (`qsh init` was never run). Every other condition, however bad, is
//! reported as a [`qsh_proto::DoctorFinding`], never a hard error.
//!
//! **`now`-injection is mandatory, not optional**: three of the thirteen
//! diagnostics (`cert_expired`/`cert_expiring_soon`/`clock_skew`) are
//! unreachable in real time under normal operation — a device leaf is
//! valid for 10 years — and are only testable by supplying a synthetic
//! `now`. Not a new architectural pattern: [`crate::trust::pairing`]'s
//! `InviteStore::add`/`prune` and [`crate::config::rfc3339_of`] already
//! take `SystemTime` as a parameter rather than calling
//! `SystemTime::now()` internally.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use qsh_proto::{DoctorData, DoctorFinding, DoctorReq, ErrorCode, KeyStoreKind};

use crate::acl::load_or_deny;
use crate::config::Config;
use crate::doctor::probe::{self, UdpProbeOutcome};
use crate::doctor::{
    CERT_EXPIRED, CERT_EXPIRING_SOON, CLOCK_SKEW, CONFIG_UNKNOWN_KEY, PEER_UNTRUSTED,
    QSH_PATH_SHADOWED, TRUST_REMOVE_SCOPE, probe_audit_path_writable,
};
use crate::hosts::HostsFile;
use crate::identity::{
    CERT_BACKDATE_MINUTES, FileKeyStore, Identity, KEY_FILE, KeyStore, PlatformKeyStore,
};
use crate::ops::{OpError, Operation, Ops, resolve_peer_address};
use crate::trust::TrustStore;

/// The `doctor.run` operation (`qsh doctor [host]`).
pub struct DoctorOp;

impl Operation for DoctorOp {
    const COMMAND: &'static str = "doctor.run";
}

/// How long a single connectivity probe ([`probe::probe_udp_egress`]) waits
/// before it counts as a timeout. Reuses [`super::PROBE_DIAL_TIMEOUT`]
/// rather than a second "3s" constant — doctor's probes are exactly the
/// kind of "expected to sometimes fail, must not hold a human or CI
/// hostage" dial that constant already exists for (`trust.add`'s own
/// fingerprint probe).
const DOCTOR_PROBE_TIMEOUT: Duration = super::PROBE_DIAL_TIMEOUT;

/// Certs expiring within this many seconds of `now` are `cert_expiring_soon`
/// rather than silently `ok` (`docs/ROADMAP.md` §4 risk table L136: "만료
/// 30일 전 doctor 경고", design brief row #5).
const CERT_EXPIRING_SOON_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;

/// The two real-process inputs [`Ops::doctor_assemble`]'s
/// `keystore_unavailable`/`qsh_path_shadowed` probes depend on that are
/// not files under `self.paths` — bundled into one borrow so
/// [`Ops::doctor_assemble`] stays under clippy's argument-count lint
/// (verify round P2-2/P2-4). [`Ops::doctor`] always builds this from the
/// real environment; a test builds it from a stub `KeyStore` and/or an
/// injected temp `$PATH` to force either probe deterministically through
/// the real assembly path.
struct DoctorEnvironment<'a> {
    keystore: &'a dyn KeyStore,
    current_exe: Option<&'a Path>,
    path_dirs: &'a [PathBuf],
}

impl Ops {
    /// `doctor.run` (`qsh doctor [host]`, `docs/CLI.md` §6.17). Inspects
    /// this host's own config, identity, and (best-effort) network
    /// reachability, and assembles every finding that fired into one
    /// report — never touches a remote peer's state (§2.5).
    ///
    /// `req.host`: an additional pinned host to probe connectivity for,
    /// beyond whatever `[reverse].controller` names — same UX shape as
    /// `qsh capabilities [host]`. `now`: mandatory injection point for the
    /// three time-dependent diagnostics (module doc) — the CLI passes
    /// `SystemTime::now()`; tests pass a fixed instant.
    ///
    /// Fails outright (`Err`, exit 255 via `finish()`) only when doctor
    /// itself has no way to proceed: no device identity (`qsh init` not
    /// run), or `config.toml`/`hosts.toml`/`trust.toml` fails to parse —
    /// each loader already turns a malformed file into `CONFIG_ERROR`
    /// (`crate::config::Config::load`/`HostsFile::load`/`TrustStore::load`'s
    /// own contracts) and doctor does not re-implement a second, tolerant
    /// parse of the same file just to keep running past it. `config_
    /// unknown_key` (below) is a different kind of check on the same file
    /// and does not relax this: it only ever runs after `Config::load`
    /// has already succeeded, and compares two parses of the same
    /// well-formed TOML rather than tolerating a malformed one.
    pub fn doctor(&self, req: DoctorReq, now: SystemTime) -> Result<DoctorData, OpError> {
        let now_unix = unix_seconds(now);
        let identity = crate::identity::read_identity(&self.paths)?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
            .with_retryable(false)
        })?;
        let config = self.config()?;

        // Real environment: the key store this device's identity actually
        // records (`identity.key_store`, `crate::identity::open_store`'s
        // own match — mirrored here rather than exposed, since `open_store`
        // is private to the `identity` module) and this process's actual
        // `current_exe()`/`$PATH` — the inputs `doctor_assemble`'s
        // `keystore_unavailable`/`qsh_path_shadowed` probes depend on that
        // are not files under `self.paths` (verify round P2-2/P2-4). Read
        // here, once, and handed down as data rather than read again inside
        // `doctor_assemble` — the same "read once at the edge, pass data
        // down" shape [`unix_seconds`]'s own `now` injection already uses.
        //
        // Always probing `PlatformKeyStore` regardless of `identity.
        // key_store` used to make `keystore_unavailable` mean "the OS
        // keychain is unreachable" even for a `file`-mode identity that
        // never touches it — a probe of a store nothing reads from, and on
        // this project's own macOS dev hosts, one that can cost tens of
        // seconds per `doctor.run` (an unsigned binary's first keychain
        // access prompts for user consent; R1 판정 (g)). Probing the store
        // actually in use makes the finding mean what its name says: "the
        // key store this device relies on cannot be opened right now."
        let keystore: Box<dyn KeyStore> = match identity.key_store {
            KeyStoreKind::File => {
                Box::new(FileKeyStore::new(self.paths.identity_dir().join(KEY_FILE)))
            }
            KeyStoreKind::Platform => Box::new(PlatformKeyStore::new(identity.device_id.clone())),
        };
        let current_exe = std::env::current_exe().ok();
        let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        let env = DoctorEnvironment {
            keystore: keystore.as_ref(),
            current_exe: current_exe.as_deref(),
            path_dirs: &path_dirs,
        };

        self.doctor_assemble(req, now_unix, &identity, &config, &env)
    }

    /// The rest of `doctor.run` past reading `identity`/`config` and this
    /// real process's environment — split out from [`Ops::doctor`] purely
    /// as a test seam (verify round P2-2/P2-4, mutations `MA`/`MB`): a
    /// test can call this directly with a stub [`DoctorEnvironment`] (an
    /// always-`Unavailable` `KeyStore`, an injected temp `$PATH`) to force
    /// `keystore_unavailable`/`qsh_path_shadowed` deterministically
    /// through the *real* finding-assembly code path, not just through the
    /// pure classifiers ([`keystore_finding_of`]/[`path_shadow_finding`])
    /// one layer down — closing the exact gap the verify round's `MA`/`MB`
    /// mutations (deleting the wiring line entirely) exploited: those
    /// mutations are only observable if some test's report actually
    /// depends on the finding being present, which — for these two
    /// probes — real-environment nondeterminism otherwise prevents any
    /// test from guaranteeing.
    fn doctor_assemble(
        &self,
        req: DoctorReq,
        now_unix: i64,
        identity: &Identity,
        config: &Config,
        env: &DoctorEnvironment<'_>,
    ) -> Result<DoctorData, OpError> {
        let mut findings = Vec::new();
        findings.extend(self.doctor_audit_finding(config));
        findings.extend(self.doctor_config_unknown_key_findings(config));
        findings.extend(self.doctor_acl_finding());
        findings.extend(self.doctor_cert_findings(identity, now_unix)?);
        findings.extend(self.doctor_clock_skew_finding(identity, now_unix)?);
        findings.extend(keystore_finding_of(env.keystore));
        findings.extend(
            env.current_exe
                .and_then(|exe| path_shadow_finding(exe, env.path_dirs)),
        );
        findings.extend(self.doctor_trust_findings()?);
        findings.extend(self.doctor_connectivity_findings(config, req.host.as_deref())?);

        Ok(DoctorData {
            overall: overall_status(&findings),
            findings,
        })
    }

    /// `audit_path_unwritable` (design brief row #9) — reuses
    /// [`probe_audit_path_writable`] and [`crate::doctor::AUDIT_PATH_UNWRITABLE`]
    /// verbatim, the same detector `qsh listen`'s own startup path uses.
    fn doctor_audit_finding(&self, config: &Config) -> Option<DoctorFinding> {
        let path = config.audit.path(&self.paths);
        if probe_audit_path_writable(&path) {
            return None;
        }
        let diag = &crate::doctor::AUDIT_PATH_UNWRITABLE;
        Some(DoctorFinding {
            code: diag.code.to_string(),
            status: "error".to_string(),
            detail: format!("{} (path: {})", diag.message, path.display()),
            remedy: Some(diag.remedy.to_string()),
        })
    }

    /// `acl_policy_missing`/`acl_policy_invalid` (design brief rows
    /// #10/#11) — reuses [`load_or_deny`] and its
    /// [`crate::acl::StartupDiagnostic`] verbatim, the exact same
    /// detection `qsh serve`/`qsh listen`'s own startup banner runs; this
    /// discards the throwaway [`crate::acl::Authorizer`] it also
    /// constructs (loading `acl.toml` has no side effects worth avoiding).
    fn doctor_acl_finding(&self) -> Option<DoctorFinding> {
        let (_authorizer, diagnostic) = load_or_deny(&self.paths);
        let diagnostic = diagnostic?;
        Some(DoctorFinding {
            code: diagnostic.code.to_string(),
            status: "error".to_string(),
            detail: diagnostic.render(),
            remedy: Some(format!(
                "{}. {}",
                crate::acl::ACL_STARTUP_NO_AUTOGEN,
                crate::acl::ACL_STARTUP_CHECK_HINT
            )),
        })
    }

    /// `cert_expired`/`cert_expiring_soon` (design brief rows #4/#5) —
    /// checks both certificates this device relies on: its own device leaf
    /// (always present once `identity` exists) and the local CA root, when
    /// one has been initialized (`qsh cert init`, M7 Step 5 — its absence
    /// is not a diagnostic, per the brief's own completeness argument:
    /// "CA 미초기화는 실패가 아니라 부재").
    fn doctor_cert_findings(
        &self,
        identity: &Identity,
        now_unix: i64,
    ) -> Result<Vec<DoctorFinding>, OpError> {
        let mut out = Vec::new();
        out.extend(cert_expiry_finding(
            "this device's own leaf certificate",
            &identity.cert_der,
            now_unix,
        )?);
        if let Some(ca) = crate::ca::read_root(&self.paths)? {
            out.extend(cert_expiry_finding(
                "the local CA root certificate",
                &ca.cert_der,
                now_unix,
            )?);
        }
        Ok(out)
    }

    /// `clock_skew` (design brief row #7) — compares `now` against this
    /// device's own leaf certificate `not_before`, the same backdated
    /// timestamp [`crate::identity::init`] stamped at `qsh init` time.
    fn doctor_clock_skew_finding(
        &self,
        identity: &Identity,
        now_unix: i64,
    ) -> Result<Option<DoctorFinding>, OpError> {
        let (not_before, _not_after) = qsh_transport::identity::validity_unix(&identity.cert_der)
            .map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("failed to read this device's own certificate validity: {err}"),
            )
            .with_retryable(false)
        })?;
        Ok(clock_skew_finding(not_before, now_unix))
    }

    /// `config_unknown_key` (`PLAN.md` M8 Step 4b, J10). Reads `config.toml`
    /// a second time as a bare [`toml::Value`] (not through [`Config`]'s
    /// `#[serde(default)]` `Deserialize`, which silently drops anything it
    /// does not recognize — that silence is exactly what this finding
    /// exists to surface) and compares its leaf key paths against
    /// `config`'s own, re-serialized the same way. No hand-maintained key
    /// list: [`collect_leaf_paths`] derives the "known" set from the
    /// struct itself via `Serialize`, so a future field addition/removal
    /// to [`Config`] or any of its sections updates this finding's
    /// vocabulary for free, with nothing here to keep in sync by hand. A
    /// candidate that only `serde`'s deserializer recognizes under a
    /// different name (a `#[serde(alias = ...)]`, which never appears in
    /// `Serialize`'s output) is filtered out by
    /// [`accepted_under_another_name`] before being reported — see its
    /// own doc for the one corner it cannot see.
    ///
    /// Only reachable once [`Ops::doctor`] already holds a successfully
    /// loaded `config` — a missing file means `Config::load` returned
    /// `Config::default()` with nothing to compare against (no finding,
    /// same as every other "file absent" case in this module), and a
    /// malformed file would already have failed `Config::load` itself
    /// (module doc). This method's own re-read can still race a
    /// concurrent edit or removal after that load; either failure mode
    /// (unreadable, or fails to parse as *any* TOML) is treated the same
    /// as "nothing to compare" rather than escalated to a second
    /// `CONFIG_ERROR` — this diagnostic is best-effort, not a second
    /// source of truth for whether the file is valid.
    fn doctor_config_unknown_key_findings(&self, config: &Config) -> Vec<DoctorFinding> {
        let path = self.paths.config_file();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let Ok(raw) = text.parse::<toml::Value>() else {
            return Vec::new();
        };
        let Ok(known) = toml::Value::try_from(config) else {
            return Vec::new();
        };

        let mut present = std::collections::BTreeSet::new();
        collect_leaf_paths(&raw, String::new(), &mut present);
        let mut known_paths = std::collections::BTreeSet::new();
        collect_leaf_paths(&known, String::new(), &mut known_paths);

        present
            .difference(&known_paths)
            .filter(|key_path| !accepted_under_another_name(&raw, key_path))
            .map(|key_path| DoctorFinding {
                code: CONFIG_UNKNOWN_KEY.code.to_string(),
                status: "warn".to_string(),
                detail: format!("{} (key: {key_path})", CONFIG_UNKNOWN_KEY.message),
                remedy: Some(CONFIG_UNKNOWN_KEY.remedy.to_string()),
            })
            .collect()
    }

    /// `peer_untrusted`/`trust_remove_scope` (design brief rows #3/#13) —
    /// a static cross-reference between `hosts.toml` and `trust.toml`
    /// (`peer_untrusted`: `docs/CLI.md`'s `Host` contract guarantees
    /// `hosts.toml` only ever supplies an address, never identity, so a
    /// name with no trust pin is destined to fail `TRUST_REQUIRED` the
    /// moment anything dials it — no false positive is possible), plus an
    /// unconditional notice (`trust_remove_scope`) whenever at least one
    /// peer is pinned at all.
    fn doctor_trust_findings(&self) -> Result<Vec<DoctorFinding>, OpError> {
        let trust = TrustStore::load(&self.paths.trust_file())?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        let mut out = Vec::new();

        let peer_diag = &PEER_UNTRUSTED;
        for entry in hosts.entries() {
            if trust.find(&entry.name).is_none() {
                out.push(DoctorFinding {
                    code: peer_diag.code.to_string(),
                    status: "error".to_string(),
                    detail: format!("{} (host: {})", peer_diag.message, entry.name),
                    remedy: Some(peer_diag.remedy.to_string()),
                });
            }
        }

        if !trust.peers().is_empty() {
            let scope_diag = &TRUST_REMOVE_SCOPE;
            out.push(DoctorFinding {
                code: scope_diag.code.to_string(),
                status: "info".to_string(),
                detail: scope_diag.message.to_string(),
                remedy: Some(scope_diag.remedy.to_string()),
            });
        }

        Ok(out)
    }

    /// `udp_egress_blocked`/`no_route`/`controller_unreachable` (design
    /// brief rows #1/#2/#8) — one probe for `[reverse].controller` (when
    /// configured; this is the first code path to actually read that
    /// field — [`crate::config::ReverseConfig::controller`]'s own doc),
    /// one for `req.host` (when given). Precedence between the three codes
    /// is [`probe::classify_connectivity`]'s alone (design brief risk #6):
    /// this method never constructs a `DoctorFinding` itself, only feeds
    /// it a `(outcome, is_controller_target)` pair.
    fn doctor_connectivity_findings(
        &self,
        config: &Config,
        extra_host: Option<&str>,
    ) -> Result<Vec<DoctorFinding>, OpError> {
        let trust = TrustStore::load(&self.paths.trust_file())?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        let mut out = Vec::new();

        let controller = config.reverse.controller.as_deref();
        if let Some(controller) = controller {
            out.extend(probe_named_target(&trust, &hosts, controller, true));
        }
        if let Some(host) = extra_host {
            // An explicit `--host`/positional target: an unknown name is a
            // hard error, the same precedent `resolve_peer_address`'s own
            // `HOST_NOT_FOUND` wording sets for every other host-targeting
            // op (`qsh exec`, `qsh capabilities <host>`) — the caller named
            // a specific peer, so a typo fails loudly rather than
            // silently turning into an "unreachable" finding.
            let (address, _server_name) = resolve_peer_address(&trust, &hosts, host)?;
            // P3-4 (verify round): when `host` resolves to the very peer
            // `[reverse].controller` already names, the branch above
            // already probed it once as `controller_unreachable` — probing
            // it again here would report the *same* underlying failure a
            // second time under a *different* code
            // (`no_route`/`udp_egress_blocked`), which reads as two
            // contradictory diagnoses of one problem rather than one.
            // Matches on the alias name first (cheap, and correct even
            // when the controller alias itself does not resolve), then
            // falls back to comparing resolved addresses (the same name
            // pinned under two different aliases).
            let same_as_controller = controller.is_some_and(|controller| {
                controller == host
                    || resolve_peer_address(&trust, &hosts, controller)
                        .is_ok_and(|(controller_address, _)| controller_address == address)
            });
            if !same_as_controller {
                out.extend(probe_address(&address, host, false));
            }
        }

        Ok(out)
    }
}

/// `now` as unix seconds. `SystemTime::duration_since` only fails for a
/// `now` before `UNIX_EPOCH`, which no real clock and no test in this
/// codebase produces — handled here anyway (a negative timestamp) rather
/// than panicking, since `doctor.run`'s entire point is to stay useful
/// under a badly wrong clock.
fn unix_seconds(t: SystemTime) -> i64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(before_epoch) => -i64::try_from(before_epoch.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Walks a [`toml::Value`] tree and inserts every *leaf* key path into
/// `out`, dotted (`serve.max_sessions_per_principal`). A table array's
/// index is deliberately dropped from the path (`reverse.foo` not
/// `reverse[0].foo`) so an array-of-tables entry compares by shape, not by
/// position — [`Ops::doctor_config_unknown_key_findings`]'s own doc
/// explains why this matters for `Config`, which currently has no such
/// array field but should not silently break this comparison the day one
/// is added. An empty table contributes no leaf of its own (nothing to
/// diff against — an empty `[serve]` and an absent one look identical
/// either way) — this also means a wholly unknown *empty* section, e.g.
/// a config.toml with nothing but `[garbage]` and no keys under it, has
/// no leaf path to compare and so is not reported by
/// `config_unknown_key` either; only an unknown key (leaf) is ever
/// flagged, never an unknown but empty table.
fn collect_leaf_paths(
    value: &toml::Value,
    prefix: String,
    out: &mut std::collections::BTreeSet<String>,
) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_leaf_paths(child, path, out);
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                collect_leaf_paths(item, prefix.clone(), out);
            }
        }
        _ => {
            if !prefix.is_empty() {
                out.insert(prefix);
            }
        }
    }
}

/// Looks up the [`toml::Value`] living at a dotted `key_path` inside
/// `raw`, descending through tables only. A path that runs through an
/// array along the way (its index already dropped by
/// [`collect_leaf_paths`]) cannot be resolved to one unambiguous value
/// and yields `None` — [`accepted_under_another_name`] treats that as
/// "cannot probe this candidate", not as "this key is unknown".
fn lookup<'a>(raw: &'a toml::Value, key_path: &str) -> Option<&'a toml::Value> {
    let mut current = raw;
    for segment in key_path.split('.') {
        current = current.as_table()?.get(segment)?;
    }
    Some(current)
}

/// Wraps a single leaf `value` back up in the nested tables its dotted
/// `key_path` implies, e.g. `serve.resume_ttl_secs` + `3600` becomes the
/// document `{ serve = { resume_ttl_secs = 3600 } }` and nothing else.
fn single_key_document(key_path: &str, value: &toml::Value) -> toml::Value {
    let mut segments: Vec<&str> = key_path.split('.').collect();
    let mut doc = value.clone();
    while let Some(segment) = segments.pop() {
        let mut table = toml::value::Table::new();
        table.insert(segment.to_string(), doc);
        doc = toml::Value::Table(table);
    }
    doc
}

/// Filters a `config_unknown_key` candidate that `serde` actually
/// recognizes under a different name than the one it was written with —
/// today, only [`crate::config::ServeConfig::resume_ttl`]'s
/// `#[serde(alias = "resume_ttl_secs")]`, which `Serialize` never
/// re-emits, so a file written with the alias always looks "unknown" by
/// [`collect_leaf_paths`]'s round trip alone. Builds a single-key TOML
/// document containing nothing but this one candidate at its original
/// path and deserializes it as a [`Config`]: a genuine typo can never
/// move `Config` off [`Config::default`] (there is no field for it to
/// land on), so only a real alias — or the canonical name itself —
/// makes this `true`. A key path [`lookup`] cannot resolve (it runs
/// through an array) is left flagged rather than probed. A malformed
/// single-key document (should not happen — it is built from an
/// already-parsed [`toml::Value`]) is likewise treated as "not an
/// alias", i.e. still flagged. The one corner this cannot see: an alias
/// key written with exactly the default value is indistinguishable from
/// an unrecognized one and stays flagged — harmless, since this
/// finding's remedy (delete the key) would not change any applied cap
/// either way.
fn accepted_under_another_name(raw: &toml::Value, key_path: &str) -> bool {
    let Some(leaf) = lookup(raw, key_path) else {
        return false;
    };
    let doc = single_key_document(key_path, leaf);
    matches!(doc.try_into::<Config>(), Ok(config) if config != Config::default())
}

/// `cert_expired`/`cert_expiring_soon`, pure over an already-read
/// certificate's validity window — the two codes are mutually exclusive
/// for the same certificate (design brief row #5): expired wins outright,
/// expiring-soon only applies to a certificate that has not expired yet.
fn cert_expiry_finding(
    label: &str,
    cert_der: &[u8],
    now_unix: i64,
) -> Result<Option<DoctorFinding>, OpError> {
    let (_not_before, not_after) =
        qsh_transport::identity::validity_unix(cert_der).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("failed to read {label}'s certificate validity: {err}"),
            )
            .with_retryable(false)
        })?;

    if now_unix >= not_after {
        let diag = &CERT_EXPIRED;
        return Ok(Some(DoctorFinding {
            code: diag.code.to_string(),
            status: "error".to_string(),
            detail: format!("{} ({label}, not_after unix: {not_after})", diag.message),
            remedy: Some(diag.remedy.to_string()),
        }));
    }
    if not_after - now_unix <= CERT_EXPIRING_SOON_WINDOW_SECS {
        let diag = &CERT_EXPIRING_SOON;
        return Ok(Some(DoctorFinding {
            code: diag.code.to_string(),
            status: "warn".to_string(),
            detail: format!("{} ({label}, not_after unix: {not_after})", diag.message),
            remedy: Some(diag.remedy.to_string()),
        }));
    }
    Ok(None)
}

/// `clock_skew`, pure over an already-read `not_before` and `now`
/// (design brief row #7 / E-1): `error` once the observed skew exceeds
/// [`CERT_BACKDATE_MINUTES`] (the same 5-minute margin
/// [`crate::identity::init`] already backdates every fresh certificate
/// by, to absorb ordinary clock drift between peers), `warn` for any
/// smaller skew, `None` when the clock is not behind `not_before` at all.
fn clock_skew_finding(not_before_unix: i64, now_unix: i64) -> Option<DoctorFinding> {
    if now_unix >= not_before_unix {
        return None;
    }
    let skew_seconds = not_before_unix - now_unix;
    // Compare in whole seconds, not truncated minutes (P2 verify round
    // P3-1): a 301s skew already exceeds the 300s (5-minute) margin, but
    // `301 / 60 == 5`, which is not `> 5` — the truncated-minutes
    // comparison used to under-report that as `warn` instead of `error`.
    // `skew_minutes` still exists, for the detail string only.
    let skew_minutes = skew_seconds / 60;
    let status = if skew_seconds > CERT_BACKDATE_MINUTES * 60 {
        "error"
    } else {
        "warn"
    };
    let diag = &CLOCK_SKEW;
    Some(DoctorFinding {
        code: diag.code.to_string(),
        status: status.to_string(),
        detail: format!(
            "{} (observed skew: {skew_minutes} minute(s); backdate margin: {CERT_BACKDATE_MINUTES} minute(s))",
            diag.message
        ),
        remedy: Some(diag.remedy.to_string()),
    })
}

/// `keystore_unavailable`, pure over an already-performed
/// [`KeyStore::load`] probe (verify round P2-2). Split out of
/// [`Ops::doctor_keystore_finding`] so a test can force the
/// `Err(KeyStoreError::Unavailable(_))` branch with a stub `KeyStore`
/// rather than depending on whether this test machine happens to have a
/// reachable platform credential store — the same "detection and
/// classification kept apart" discipline
/// [`probe::classify_connectivity`]'s own doc states, one layer up: this
/// is the seam between "which store to probe" (`Ops`'s job) and "what a
/// probe result means" ([`probe::keystore_finding`]'s job, reused
/// verbatim here).
fn keystore_finding_of(store: &(impl KeyStore + ?Sized)) -> Option<DoctorFinding> {
    probe::keystore_finding(store.load())
}

/// `qsh_path_shadowed`, pure over an already-read `current_exe`/`$PATH`
/// (verify round P2-4). Split out of [`Ops::doctor_path_shadow_finding`]
/// for the same reason [`keystore_finding_of`] is: `std::env::current_exe`/
/// `std::env::var_os("PATH")` stay in the one caller that reads the real
/// environment, so a test can drive this deterministically with an
/// injected temp `$PATH` (the same pattern
/// `doctor::probe::tests::detect_path_shadow_*` already uses one layer
/// down) instead of only ever exercising it through whatever `qsh`
/// binaries happen to be on this test machine's real `$PATH`.
fn path_shadow_finding(current_exe: &Path, dirs: &[PathBuf]) -> Option<DoctorFinding> {
    let shadow = probe::detect_path_shadow(current_exe, dirs)?;
    let diag = &QSH_PATH_SHADOWED;
    Some(DoctorFinding {
        code: diag.code.to_string(),
        status: "warn".to_string(),
        detail: format!(
            "{} (shadowing: {}, running: {})",
            diag.message,
            shadow.display(),
            current_exe.display()
        ),
        remedy: Some(diag.remedy.to_string()),
    })
}

/// Resolve `name` (a trust-store/`hosts.toml` alias) to an address and
/// probe it, or — when the alias itself does not resolve — report that
/// the same way an unreachable probe would ([`UdpProbeOutcome::Unreachable`]):
/// an alias this device cannot even resolve to an address is exactly what
/// `controller_unreachable`/`no_route` already mean, so
/// [`Ops::doctor_connectivity_findings`]'s `[reverse].controller` branch
/// never aborts the whole report over a config value it did not validate
/// itself (see [`crate::config::ReverseConfig::controller`]'s own doc: a
/// dangling alias there has never been validated by any code path before
/// this one).
fn probe_named_target(
    trust: &TrustStore,
    hosts: &HostsFile,
    name: &str,
    is_controller_target: bool,
) -> Option<DoctorFinding> {
    match resolve_peer_address(trust, hosts, name) {
        Ok((address, _server_name)) => probe_address(&address, name, is_controller_target),
        Err(_) => probe::classify_connectivity(
            UdpProbeOutcome::Unreachable,
            is_controller_target,
            name,
            "<unresolved>",
        ),
    }
}

/// Resolve `address` (`host:port`) to a socket address and run the raw UDP
/// egress probe against it; a DNS/parse failure classifies the same as
/// [`UdpProbeOutcome::Unreachable`] rather than propagating as a hard
/// error, for the same reason [`probe_named_target`]'s alias-resolution
/// failure does not.
fn probe_address(address: &str, name: &str, is_controller_target: bool) -> Option<DoctorFinding> {
    let outcome = match resolve_probe_socket_addr(address) {
        Ok(socket_addr) => probe::probe_udp_egress(socket_addr, DOCTOR_PROBE_TIMEOUT),
        Err(_) => UdpProbeOutcome::Unreachable,
    };
    probe::classify_connectivity(outcome, is_controller_target, name, address)
}

/// Blocking `host:port` → `SocketAddr` resolution for the connectivity
/// probe. Deliberately not [`crate::ops::resolve_one`] (that is `async`,
/// for callers already inside a Tokio runtime) — `doctor.run` is entirely
/// synchronous end to end, so this uses the blocking
/// [`std::net::ToSocketAddrs`] resolver instead of starting a runtime just
/// for one DNS lookup.
///
/// Bounded by [`DOCTOR_PROBE_TIMEOUT`] via [`resolve_with_timeout`] — a
/// slow or silent resolver (a real risk for a real, possibly stale-network
/// `--host`/`[reverse].controller` value) no longer holds `doctor.run`
/// hostage past the same budget every other probe already respects. A
/// timeout is surfaced as a plain [`std::io::Error`] and falls through
/// [`probe_address`]'s existing `Err(_) => `[`UdpProbeOutcome::Unreachable`]
/// arm — the same path a parse failure or NXDOMAIN already took, so this
/// adds no new [`DoctorFinding`] code (`EXPECTED_DOCTOR_CODES` stays at
/// 14). This resolve budget is on top of, not shared with,
/// [`probe_address`]'s own `DOCTOR_PROBE_TIMEOUT`-bounded
/// [`probe::probe_udp_egress`] call that follows a successful resolution —
/// so one unreachable target costs at most `2 × DOCTOR_PROBE_TIMEOUT`, not
/// `DOCTOR_PROBE_TIMEOUT`.
fn resolve_probe_socket_addr(address: &str) -> std::io::Result<std::net::SocketAddr> {
    let address = address.to_string();
    resolve_with_timeout(DOCTOR_PROBE_TIMEOUT, move || blocking_resolve(&address))
}

/// The actual blocking `ToSocketAddrs` lookup, factored out of
/// [`resolve_probe_socket_addr`] so [`resolve_with_timeout`] can be tested
/// against a synthetic slow closure instead of a real DNS name.
fn blocking_resolve(address: &str) -> std::io::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    address
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved"))
}

/// Run a blocking `resolve` (in practice, [`blocking_resolve`]'s DNS
/// lookup) on its own thread and wait up to `timeout` for it to finish.
///
/// The thread is detached, not joined: if the resolver never returns —
/// genuinely hung, not merely slow — that thread stays parked past this
/// function's return, until the resolver eventually answers (its `send`
/// then silently fails, since `rx` has already been dropped) or the
/// process exits. This is a deliberate, bounded leak of at most one thread
/// per timed-out probe, not an unbounded one: `doctor.run` issues a small,
/// fixed number of probes per invocation (one per pinned `--host`/
/// `[reverse].controller` target), never a loop over untrusted input.
fn resolve_with_timeout<F>(timeout: Duration, resolve: F) -> std::io::Result<std::net::SocketAddr>
where
    F: FnOnce() -> std::io::Result<std::net::SocketAddr> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("qsh-doctor-resolve".to_string())
        .spawn(move || {
            // The receiver may already be gone (timed out and returned) by
            // the time this resolves — that's the detach: a
            // dropped-receiver send error is expected, not a bug, and is
            // deliberately discarded.
            let _ = tx.send(resolve());
        });
    if let Err(err) = spawned {
        // Thread creation itself failing (`EAGAIN`/`ENOMEM` — OS-level
        // resource exhaustion) must not panic `doctor.run` the way
        // `std::thread::spawn` would; it is the same "could not probe"
        // outcome as a timeout, just diagnosed at spawn time rather than
        // after waiting on it.
        return Err(std::io::Error::new(
            err.kind(),
            format!("could not spawn resolver thread: {err}"),
        ));
    }
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "resolver did not respond within the probe timeout",
        )),
        // `tx` was dropped without a `send` — the resolver thread died
        // (panicked) before it could report a result. Distinct from a
        // plain timeout: this is not "still working, too slow" but "will
        // never answer."
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::other(
            "resolver thread died before sending a result",
        )),
    }
}

/// Worst severity across every finding — `"error"` beats `"warn"` beats
/// (no findings, or only `"info"`) `"ok"`. `"info"` findings never affect
/// this: an unconditional notice like `trust_remove_scope` is not a
/// problem (design brief §A: `ok` never appears on an individual finding,
/// only here).
fn overall_status(findings: &[DoctorFinding]) -> String {
    if findings.iter().any(|f| f.status == "error") {
        "error".to_string()
    } else if findings.iter().any(|f| f.status == "warn") {
        "warn".to_string()
    } else {
        "ok".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq};

    use crate::config::Paths;

    fn temp_ops() -> (tempfile::TempDir, Ops) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        (dir, Ops::new(paths))
    }

    fn init_identity(ops: &Ops) {
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        })
        .unwrap();
    }

    // -----------------------------------------------------------------
    // Precondition: no identity is a hard Err, not a finding.
    // -----------------------------------------------------------------

    #[test]
    fn doctor_without_identity_is_a_config_error() {
        let (_guard, ops) = temp_ops();
        let err = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
        assert!(err.message.contains("qsh init"), "{err}");
    }

    // -----------------------------------------------------------------
    // acl_policy_missing / acl_policy_invalid — startup diagnostic reuse.
    // -----------------------------------------------------------------

    #[test]
    fn doctor_reports_acl_policy_missing_when_acl_toml_is_absent() {
        let (_guard, ops) = temp_ops();
        init_identity(&ops);

        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        assert_eq!(data.overall, "error");
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "acl_policy_missing")
            .expect("acl_policy_missing finding");
        assert_eq!(finding.status, "error");
    }

    #[test]
    fn doctor_reports_acl_policy_invalid_for_malformed_acl_toml() {
        let (_guard, ops) = temp_ops();
        init_identity(&ops);
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(ops.paths().acl_file(), "not valid toml {{{").unwrap();

        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "acl_policy_invalid")
            .expect("acl_policy_invalid finding");
        assert_eq!(finding.status, "error");
        assert!(
            data.findings.iter().all(|f| f.code != "acl_policy_missing"),
            "invalid and missing are mutually exclusive"
        );
    }

    fn minimal_acl_toml() -> &'static str {
        "[[acl]]\nprincipal = \"user:x\"\nallow = [\"exec.run\"]\n"
    }

    // -----------------------------------------------------------------
    // audit_path_unwritable
    // -----------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn doctor_reports_audit_path_unwritable_for_a_0500_directory() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, ops) = temp_ops();
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
        init_identity(&ops);

        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::write(
            ops.paths().config_file(),
            format!(
                "[audit]\npath = {:?}\n",
                locked.join("audit.log").display().to_string()
            ),
        )
        .unwrap();

        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "audit_path_unwritable")
            .expect("audit_path_unwritable finding");
        assert_eq!(finding.status, "error");

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// P3-5 (verify round): the 0o500 trigger above is `#[cfg(unix)]`
    /// only — permission bits do not port to Windows — while this
    /// module's own doc requires the diagnostic to build *and run* on
    /// the Windows CI leg too. A portable trigger instead: a regular file
    /// sitting where the audit log's parent directory needs to be created
    /// makes `std::fs::create_dir_all` fail deterministically on every
    /// platform (it is not a permission error, so no `#[cfg(unix)]` is
    /// needed at all).
    #[test]
    fn doctor_reports_audit_path_unwritable_when_the_parent_path_is_occupied_by_a_file() {
        let (dir, ops) = temp_ops();
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
        init_identity(&ops);

        let occupied = dir.path().join("occupied");
        std::fs::write(&occupied, b"not a directory").unwrap();
        std::fs::write(
            ops.paths().config_file(),
            format!(
                "[audit]\npath = {:?}\n",
                occupied.join("audit.log").display().to_string()
            ),
        )
        .unwrap();

        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "audit_path_unwritable")
            .expect("audit_path_unwritable finding");
        assert_eq!(finding.status, "error");
    }

    // -----------------------------------------------------------------
    // cert_expired / cert_expiring_soon / clock_skew — `now` injection.
    // -----------------------------------------------------------------

    fn healthy_ops() -> (tempfile::TempDir, Ops) {
        let (dir, ops) = temp_ops();
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
        init_identity(&ops);
        (dir, ops)
    }

    #[test]
    fn doctor_reports_cert_expired_when_now_is_past_not_after() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap();
        let (_not_before, not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_after + 86_400) as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        assert_eq!(data.overall, "error");
        assert!(
            data.findings.iter().any(|f| f.code == "cert_expired"),
            "{:?}",
            data.findings
        );
        assert!(
            data.findings.iter().all(|f| f.code != "cert_expiring_soon"),
            "expired and expiring-soon are mutually exclusive for one cert"
        );
    }

    #[test]
    fn doctor_reports_cert_expiring_soon_within_the_30_day_window() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap();
        let (_not_before, not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_after - 20 * 86_400) as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "cert_expiring_soon")
            .expect("cert_expiring_soon finding");
        assert_eq!(finding.status, "warn");
    }

    /// Boundary (verify round P3-2, mutation `MF`: `now_unix >= not_after`
    /// weakened to `>`): `now == not_after` must still fire `cert_expired`,
    /// not just strictly-past.
    #[test]
    fn doctor_reports_cert_expired_when_now_exactly_equals_not_after() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap();
        let (_not_before, not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(not_after as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        assert!(
            data.findings.iter().any(|f| f.code == "cert_expired"),
            "{:?}",
            data.findings
        );
    }

    /// Boundary (verify round P3-2, mutation `MI`: the 30-day window
    /// comparison weakened from `<=` to `<`): exactly 30 days out must
    /// still fire `cert_expiring_soon`.
    #[test]
    fn doctor_reports_cert_expiring_soon_at_exactly_the_30_day_window() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap();
        let (_not_before, not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        let now = SystemTime::UNIX_EPOCH
            + Duration::from_secs((not_after - CERT_EXPIRING_SOON_WINDOW_SECS) as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "cert_expiring_soon")
            .expect("cert_expiring_soon finding");
        assert_eq!(finding.status, "warn");
    }

    /// CA root half of `cert_expired` (verify round P2-3, mutation `MD`:
    /// the CA branch checking `identity.cert_der` instead of `ca.cert_der`)
    /// — `crate::ca::init` is never called anywhere else in this module's
    /// tests, so without this test the CA branch of
    /// `Ops::doctor_cert_findings` is never exercised at all. The CA root
    /// is valid for 20 years (`crate::ca::CA_VALIDITY_DAYS`) vs. the
    /// device leaf's 10 (`crate::identity::CERT_VALIDITY_DAYS`), so a
    /// `now` past the CA's own `not_after` is also past the leaf's —
    /// both fire, and `detail` must name each one distinctly.
    #[test]
    fn doctor_reports_cert_expired_for_both_leaf_and_ca_root_once_both_are_past_not_after() {
        let (_guard, ops) = healthy_ops();
        ops.cert_init(qsh_proto::CertInitReq {}).unwrap();
        let ca_root = crate::ca::read_root(ops.paths()).unwrap().unwrap();
        let (_not_before, ca_not_after) =
            qsh_transport::identity::validity_unix(&ca_root.cert_der).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs((ca_not_after + 86_400) as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        let expired: Vec<_> = data
            .findings
            .iter()
            .filter(|f| f.code == "cert_expired")
            .collect();
        assert_eq!(
            expired.len(),
            2,
            "expected both the device leaf and the CA root to report cert_expired: {:?}",
            data.findings
        );
        assert!(
            expired.iter().any(|f| f.detail.contains("own leaf")),
            "{expired:?}"
        );
        assert!(
            expired.iter().any(|f| f.detail.contains("CA root")),
            "{expired:?}"
        );
    }

    /// Distinguishes the CA-root branch from the leaf branch by actual
    /// expiry state rather than by label text alone (verify round P2-3,
    /// mutation `MD`: the CA branch reading `identity.cert_der` — the
    /// leaf's own bytes — instead of `ca.cert_der`). The leaf's 10-year
    /// validity ends well before the CA root's 20-year validity
    /// ([`crate::identity::CERT_VALIDITY_DAYS`] vs.
    /// [`crate::ca::CA_VALIDITY_DAYS`]), so `now` set just past the
    /// leaf's own `not_after` but still years before the CA root's
    /// `not_after` must report exactly one `cert_expired` (the leaf) —
    /// under `MD` the mislabeled "CA root" entry would also fire
    /// `cert_expired`, because it is secretly re-checking the
    /// already-expired leaf bytes, producing two findings instead of one.
    #[test]
    fn doctor_reports_cert_expired_only_for_the_leaf_when_only_the_leaf_is_past_not_after() {
        let (_guard, ops) = healthy_ops();
        ops.cert_init(qsh_proto::CertInitReq {}).unwrap();
        let identity = ops.load_identity().unwrap().unwrap();
        let (_not_before, leaf_not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        let ca_root = crate::ca::read_root(ops.paths()).unwrap().unwrap();
        let (_ca_not_before, ca_not_after) =
            qsh_transport::identity::validity_unix(&ca_root.cert_der).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs((leaf_not_after + 86_400) as u64);
        assert!(
            leaf_not_after + 86_400 < ca_not_after,
            "fixture assumption: leaf must expire well before the CA root"
        );

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        let expired: Vec<_> = data
            .findings
            .iter()
            .filter(|f| f.code == "cert_expired")
            .collect();
        assert_eq!(
            expired.len(),
            1,
            "expected only the device leaf to report cert_expired while the CA root is still valid: {:?}",
            data.findings
        );
        assert!(
            expired.iter().any(|f| f.detail.contains("own leaf")),
            "{expired:?}"
        );
        assert!(
            !expired.iter().any(|f| f.detail.contains("CA root")),
            "{expired:?}"
        );
    }

    #[test]
    fn doctor_reports_no_cert_findings_well_before_expiry() {
        let (_guard, ops) = healthy_ops();
        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        assert!(
            data.findings
                .iter()
                .all(|f| f.code != "cert_expired" && f.code != "cert_expiring_soon"),
            "{:?}",
            data.findings
        );
    }

    #[test]
    fn doctor_reports_clock_skew_error_past_the_backdate_margin() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap();
        let (not_before, _not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        // 10 minutes behind not_before: exceeds the 5-minute backdate margin.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_before - 10 * 60) as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "clock_skew")
            .expect("clock_skew finding");
        assert_eq!(finding.status, "error");
    }

    #[test]
    fn doctor_reports_clock_skew_warn_within_the_backdate_margin() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap();
        let (not_before, _not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        // 3 minutes behind not_before: inside the 5-minute backdate margin.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_before - 3 * 60) as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "clock_skew")
            .expect("clock_skew finding");
        assert_eq!(finding.status, "warn");
    }

    /// P3-1 regression: 301 seconds of skew already exceeds the 300s
    /// (5-minute) backdate margin, and must classify as `error`. Before
    /// the fix, `(301 / 60) == 5` truncated to exactly the margin and this
    /// reported `warn` instead — the comparison must be in whole seconds,
    /// not truncated minutes.
    #[test]
    fn doctor_reports_clock_skew_error_at_301_seconds_past_the_margin() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap();
        let (not_before, _not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_before - 301) as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "clock_skew")
            .expect("clock_skew finding");
        assert_eq!(finding.status, "error", "{finding:?}");
    }

    /// Boundary (verify round P3-2, mutation `MG`: `skew_minutes >
    /// CERT_BACKDATE_MINUTES` weakened to `>=`): skew of exactly 300
    /// seconds (5 minutes) is *at* the margin, not past it, and must stay
    /// `warn`.
    #[test]
    fn doctor_reports_clock_skew_warn_at_exactly_the_5_minute_margin() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap();
        let (not_before, _not_after) =
            qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_before - 300) as u64);

        let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "clock_skew")
            .expect("clock_skew finding");
        assert_eq!(finding.status, "warn", "{finding:?}");
    }

    // -----------------------------------------------------------------
    // peer_untrusted / trust_remove_scope
    // -----------------------------------------------------------------

    #[test]
    fn doctor_reports_peer_untrusted_for_a_hosts_toml_entry_with_no_pin() {
        let (_guard, ops) = healthy_ops();
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(
            ops.paths().hosts_file(),
            "[[host]]\nname = \"orphan\"\naddress = \"orphan.example:4433\"\n",
        )
        .unwrap();

        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "peer_untrusted")
            .expect("peer_untrusted finding");
        assert_eq!(finding.status, "error");
        assert!(finding.detail.contains("orphan"), "{finding:?}");
    }

    #[test]
    fn doctor_has_no_peer_untrusted_when_hosts_toml_is_empty() {
        let (_guard, ops) = healthy_ops();
        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        assert!(data.findings.iter().all(|f| f.code != "peer_untrusted"));
    }

    #[test]
    fn doctor_reports_trust_remove_scope_only_once_a_peer_is_pinned() {
        let (_guard, ops) = healthy_ops();
        let before = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        assert!(
            before
                .findings
                .iter()
                .all(|f| f.code != "trust_remove_scope")
        );

        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();
        ops.trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("mac.example:4433".into()),
            fingerprint: Some(fingerprint),
        })
        .unwrap();

        let after = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        let finding = after
            .findings
            .iter()
            .find(|f| f.code == "trust_remove_scope")
            .expect("trust_remove_scope finding");
        assert_eq!(finding.status, "info");
        // An `info`-only addition must not change `overall` — compared
        // against the "before" baseline rather than a hardcoded "ok"
        // defensively, in case some other finding on this test machine
        // already put the baseline at "warn"; `keystore_unavailable`
        // itself is no longer one of the ways that can happen for
        // `healthy_ops()`'s file-mode identity (below).
        assert_eq!(after.overall, before.overall);
    }

    // -----------------------------------------------------------------
    // keystore_unavailable — `Ops::doctor` now probes the key store
    // `identity.key_store` actually names (R1 판정 (g)), not
    // unconditionally `PlatformKeyStore`. `healthy_ops()` inits a
    // file-mode identity, so this probes `FileKeyStore` against the real
    // `device.key` `init_identity` already wrote — deterministic, and it
    // always finds the key, so `keystore_unavailable` does not fire in
    // this suite at all. The test below stays as a defensive shape check
    // (a broken/unreadable `device.key` on some other machine, or a
    // platform-mode identity in the field, must still only ever surface
    // as `"warn"`, never panic) — not a claim that this specific run
    // exercises the unavailable path; the deterministic trigger for that
    // path is the `AlwaysUnavailableKeyStore` stub two tests down.
    // -----------------------------------------------------------------

    #[test]
    fn doctor_keystore_probe_does_not_panic_and_only_ever_reports_warn() {
        let (_guard, ops) = healthy_ops();
        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        if let Some(finding) = data
            .findings
            .iter()
            .find(|f| f.code == "keystore_unavailable")
        {
            assert_eq!(finding.status, "warn");
        }
    }

    /// A `KeyStore` stub whose `load()` always reports
    /// `Err(KeyStoreError::Unavailable(_))` — the deterministic trigger
    /// the test above cannot force on its own (verify round P2-2,
    /// mutation `MA`: deleting `Ops::doctor`'s keystore-probe wiring
    /// entirely used to leave every test in this file green).
    struct AlwaysUnavailableKeyStore;

    impl KeyStore for AlwaysUnavailableKeyStore {
        fn kind(&self) -> qsh_proto::KeyStoreKind {
            qsh_proto::KeyStoreKind::Platform
        }

        fn store(&self, _key_pkcs8_der: &[u8]) -> Result<(), crate::identity::KeyStoreError> {
            unimplemented!("keystore_finding_of only ever calls load()")
        }

        fn load(
            &self,
        ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, crate::identity::KeyStoreError> {
            Err(crate::identity::KeyStoreError::Unavailable(
                "stub: no secret service".to_string(),
            ))
        }

        fn delete(&self) -> Result<(), crate::identity::KeyStoreError> {
            unimplemented!("keystore_finding_of only ever calls load()")
        }
    }

    #[test]
    fn keystore_finding_of_fires_deterministically_when_the_store_reports_unavailable() {
        let finding =
            keystore_finding_of(&AlwaysUnavailableKeyStore).expect("keystore_unavailable finding");
        assert_eq!(finding.code, "keystore_unavailable");
        assert_eq!(finding.status, "warn");
        assert!(finding.detail.contains("stub: no secret service"));
    }

    /// Wiring-level (verify round P2-2, mutation `MA`: deleting
    /// `Ops::doctor_assemble`'s `findings.extend(keystore_finding_of(...))`
    /// line entirely used to leave every test in this file green — the
    /// unit test above only drives the pure classifier, never `Ops`'s own
    /// finding-assembly). Goes through [`Ops::doctor_assemble`] itself
    /// with a stub [`DoctorEnvironment`], the real code path `Ops::doctor`
    /// calls, not a parallel reimplementation of it.
    #[test]
    fn doctor_wires_the_keystore_finding_into_the_full_report_deterministically() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap().identity;
        let config = ops.config().unwrap();
        let env = DoctorEnvironment {
            keystore: &AlwaysUnavailableKeyStore,
            current_exe: None,
            path_dirs: &[],
        };

        let data = ops
            .doctor_assemble(
                DoctorReq { host: None },
                unix_seconds(SystemTime::now()),
                &identity,
                &config,
                &env,
            )
            .unwrap();
        assert!(
            data.findings
                .iter()
                .any(|f| f.code == "keystore_unavailable"),
            "{:?}",
            data.findings
        );
    }

    // -----------------------------------------------------------------
    // qsh_path_shadowed — the underlying scan is already covered
    // deterministically with an injected `$PATH`
    // (`doctor::probe::tests::detect_path_shadow_*`). `Ops::doctor` itself
    // reads the *real* `$PATH` and `current_exe()` (design brief row #12:
    // this is meant to catch a real shadowing binary on this machine), so
    // whether it fires at all depends on this test machine's actual
    // environment — this only asserts the finding's shape when present,
    // never its absence.
    // -----------------------------------------------------------------

    #[test]
    fn doctor_path_shadow_probe_does_not_panic_and_only_ever_reports_warn() {
        let (_guard, ops) = healthy_ops();
        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        if let Some(finding) = data.findings.iter().find(|f| f.code == "qsh_path_shadowed") {
            assert_eq!(finding.status, "warn");
        }
    }

    /// A fake, executable `qsh` for the injected-`$PATH` test below — the
    /// same shape `doctor::probe::tests::write_fake_exe` uses one layer
    /// down, duplicated here rather than exported test-only from `probe`
    /// (verify round P2-4).
    #[cfg(unix)]
    fn write_fake_qsh_exe(dir: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("qsh");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(windows)]
    fn write_fake_qsh_exe(dir: &std::path::Path) -> PathBuf {
        let path = dir.join("qsh.exe");
        std::fs::write(&path, b"MZ").unwrap();
        path
    }

    /// Deterministic trigger for `path_shadow_finding` (verify round
    /// P2-4, mutation `MB`: deleting `Ops::doctor`'s path-shadow-probe
    /// wiring entirely used to leave every test in this file green, and
    /// on a machine with no `qsh` on `$PATH` the shape-only test above is
    /// completely vacuous). An injected temp `$PATH`, not this process's
    /// real one — the same pattern
    /// `doctor::probe::tests::detect_path_shadow_finds_an_earlier_qsh_before_the_running_one`
    /// already uses one layer down.
    #[test]
    fn path_shadow_finding_fires_deterministically_for_an_earlier_qsh_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let shadow_dir = dir.path().join("shadow");
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&shadow_dir).unwrap();
        std::fs::create_dir(&real_dir).unwrap();
        let shadow_exe = write_fake_qsh_exe(&shadow_dir);
        let real_exe = write_fake_qsh_exe(&real_dir);

        let finding = path_shadow_finding(&real_exe, &[shadow_dir, real_dir])
            .expect("qsh_path_shadowed finding");
        assert_eq!(finding.code, "qsh_path_shadowed");
        assert_eq!(finding.status, "warn");
        assert!(
            finding.detail.contains(&shadow_exe.display().to_string()),
            "{finding:?}"
        );
        assert!(
            finding.detail.contains(&real_exe.display().to_string()),
            "{finding:?}"
        );
    }

    /// Wiring-level (verify round P2-4, mutation `MB`: deleting
    /// `Ops::doctor_assemble`'s path-shadow line entirely used to leave
    /// every test in this file green — the unit test above only drives
    /// the pure classifier, never `Ops`'s own finding-assembly). Goes
    /// through [`Ops::doctor_assemble`] itself with a stub
    /// [`DoctorEnvironment`] (an injected temp `$PATH`, a `MemoryKeyStore`
    /// so `keystore_unavailable` never fires and cannot be mistaken for
    /// this finding), the real code path `Ops::doctor` calls.
    #[test]
    fn doctor_wires_the_path_shadow_finding_into_the_full_report_deterministically() {
        let (_guard, ops) = healthy_ops();
        let identity = ops.load_identity().unwrap().unwrap().identity;
        let config = ops.config().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let shadow_dir = dir.path().join("shadow");
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&shadow_dir).unwrap();
        std::fs::create_dir(&real_dir).unwrap();
        write_fake_qsh_exe(&shadow_dir);
        let real_exe = write_fake_qsh_exe(&real_dir);
        let path_dirs = vec![shadow_dir, real_dir];
        let never_unavailable = crate::identity::MemoryKeyStore::new();
        let env = DoctorEnvironment {
            keystore: &never_unavailable,
            current_exe: Some(&real_exe),
            path_dirs: &path_dirs,
        };

        let data = ops
            .doctor_assemble(
                DoctorReq { host: None },
                unix_seconds(SystemTime::now()),
                &identity,
                &config,
                &env,
            )
            .unwrap();
        assert!(
            data.findings.iter().any(|f| f.code == "qsh_path_shadowed"),
            "{:?}",
            data.findings
        );
    }

    // -----------------------------------------------------------------
    // connectivity: controller_unreachable / no_route / udp_egress_blocked
    // precedence, and an unresolvable req.host being a hard error.
    // -----------------------------------------------------------------

    /// `resolve_with_timeout` against a "slow resolver" seam — a closure
    /// that sleeps well past a 1ms timeout — rather than a real DNS name,
    /// per the brief's own steer away from depending on real DNS. Mirrors
    /// `doctor::probe`'s `probe_times_out_against_a_silent_black_hole`
    /// shape: an extreme, deterministic timeout injected directly at the
    /// seam under test.
    ///
    /// Two more checks land in this same test (R1 판정 (g), DNS-wiring
    /// minors): an elapsed-time assertion that the wait itself is actually
    /// bounded by the 1ms timeout rather than by how long the sleeping
    /// resolver takes (a regression that swapped `recv_timeout` for a
    /// plain, unbounded `recv` would still return the right `Err` above,
    /// eventually — only the clock catches that); and a source-text pin,
    /// the same shape as `fsutil.rs`'s `resume_and_config_pin_opposite_
    /// durable_arguments_in_their_source`, that `resolve_probe_socket_
    /// addr`'s production call site really does pass `DOCTOR_PROBE_
    /// TIMEOUT` — not some other duration — as the resolve budget. Built
    /// via `format!` rather than typed as one literal so the needle does
    /// not just match itself inside this test's own source once
    /// `include_str!` pulls the whole file in.
    #[test]
    fn probe_times_out_against_a_silent_black_hole_resolver() {
        let started = std::time::Instant::now();
        let result = resolve_with_timeout(Duration::from_millis(1), || {
            std::thread::sleep(Duration::from_millis(200));
            blocking_resolve("127.0.0.1:0")
        });
        let elapsed = started.elapsed();
        let err = result.expect_err("a resolver stuck past the timeout must not succeed");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_millis(50),
            "resolve_with_timeout must return close to its 1ms timeout, not wait \
             out the 200ms sleeping resolver; took {elapsed:?}"
        );

        let call_site = format!(
            "resolve_with_timeout({}, move || blocking_resolve(&address))",
            "DOCTOR_PROBE_TIMEOUT"
        );
        assert_eq!(
            include_str!("doctor.rs").matches(&call_site).count(),
            1,
            "resolve_probe_socket_addr must bound its resolve with \
             DOCTOR_PROBE_TIMEOUT, the same budget every other probe \
             already respects"
        );
    }

    #[test]
    fn doctor_reports_controller_unreachable_for_a_dangling_controller_alias() {
        let (_guard, ops) = healthy_ops();
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(
            ops.paths().config_file(),
            "[reverse]\ncontroller = \"ctrl\"\n",
        )
        .unwrap();

        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "controller_unreachable")
            .expect("controller_unreachable finding");
        assert_eq!(finding.status, "error");
        assert!(
            data.findings
                .iter()
                .all(|f| f.code != "no_route" && f.code != "udp_egress_blocked"),
            "precedence: a controller target must classify as controller_unreachable only"
        );
    }

    /// P3-4 (verify round): `req.host` naming the same peer as
    /// `[reverse].controller` used to be probed twice — once via the
    /// controller branch (`controller_unreachable`) and once via the
    /// extra-host branch (`udp_egress_blocked`, since a non-controller
    /// probe classifies differently) — reporting one failing target under
    /// two contradictory codes at once. The extra-host branch must skip
    /// its own probe once it recognizes the same target.
    #[test]
    fn doctor_probing_the_controller_alias_as_extra_host_reports_one_code_only() {
        let (_guard, ops) = healthy_ops();
        let black_hole = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let addr = black_hole.local_addr().unwrap();
        ops.trust_add(TrustAddReq {
            name: "ctrl".into(),
            address: Some(addr.to_string()),
            fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"ctrl").to_string()),
        })
        .unwrap();
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(
            ops.paths().config_file(),
            "[reverse]\ncontroller = \"ctrl\"\n",
        )
        .unwrap();

        let data = ops
            .doctor(
                DoctorReq {
                    host: Some("ctrl".to_string()),
                },
                SystemTime::now(),
            )
            .unwrap();
        let connectivity_codes: Vec<&str> = data
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.code.as_str(),
                    "controller_unreachable" | "udp_egress_blocked" | "no_route"
                )
            })
            .map(|f| f.code.as_str())
            .collect();
        assert_eq!(
            connectivity_codes,
            vec!["controller_unreachable"],
            "the same target must not be reported under two different connectivity codes: {:?}",
            data.findings
        );
        drop(black_hole);
    }

    #[test]
    fn doctor_with_an_unknown_extra_host_is_host_not_found() {
        let (_guard, ops) = healthy_ops();
        let err = ops
            .doctor(
                DoctorReq {
                    host: Some("nowhere".to_string()),
                },
                SystemTime::now(),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }

    #[test]
    fn doctor_probes_a_pinned_extra_host_and_classifies_a_black_hole_as_udp_egress_blocked() {
        let (_guard, ops) = healthy_ops();
        let black_hole = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let addr = black_hole.local_addr().unwrap();
        ops.trust_add(TrustAddReq {
            name: "quiet".into(),
            address: Some(addr.to_string()),
            fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"quiet").to_string()),
        })
        .unwrap();

        let data = ops
            .doctor(
                DoctorReq {
                    host: Some("quiet".to_string()),
                },
                SystemTime::now(),
            )
            .unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "udp_egress_blocked")
            .expect("udp_egress_blocked finding");
        assert_eq!(finding.status, "error");
        drop(black_hole);
    }

    /// `no_route` — verify round P2-1, mutation `MC`
    /// (`probe_address`'s `Err(_) => UdpProbeOutcome::Unreachable` branch
    /// weakened to `TimedOut`). Rebuts design brief §C/§E-2's premise that
    /// a real, OS-dependent socket is required to reach `no_route`: a
    /// pinned address with no port fails
    /// `resolve_probe_socket_addr`/`ToSocketAddrs::to_socket_addrs`'s
    /// parse deterministically — no socket, no DNS, no OS dependency at
    /// all.
    #[test]
    fn doctor_reports_no_route_for_a_pinned_address_with_no_port() {
        let (_guard, ops) = healthy_ops();
        ops.trust_add(TrustAddReq {
            name: "bad".into(),
            // No port: `ToSocketAddrs` for `&str` requires `host:port` and
            // fails to parse this at all, deterministically.
            address: Some("203.0.113.9".into()),
            fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"bad").to_string()),
        })
        .unwrap();

        let data = ops
            .doctor(
                DoctorReq {
                    host: Some("bad".to_string()),
                },
                SystemTime::now(),
            )
            .unwrap();
        let finding = data
            .findings
            .iter()
            .find(|f| f.code == "no_route")
            .expect("no_route finding");
        assert_eq!(finding.status, "error", "{:?}", data.findings);
    }

    // -----------------------------------------------------------------
    // status vocabulary — `DoctorFinding.status`/`DoctorData.overall` stay
    // `String` (`docs/CLI.md` §10's open-string discipline), so nothing at
    // the type level stops a stray value; this is the only thing that
    // does (verify round P3-7).
    // -----------------------------------------------------------------

    #[test]
    fn doctor_finding_status_is_always_one_of_the_locked_vocabulary() {
        let (_guard, ops) = temp_ops();
        init_identity(&ops);
        // No acl.toml at all (acl_policy_missing/error), an unpinned
        // hosts.toml entry (peer_untrusted/error), a dangling controller
        // alias (controller_unreachable/error), and one pinned peer
        // (trust_remove_scope/info) — enough findings in one report to
        // make this more than a vacuous pass.
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(
            ops.paths().hosts_file(),
            "[[host]]\nname = \"orphan\"\naddress = \"orphan.example:4433\"\n",
        )
        .unwrap();
        std::fs::write(
            ops.paths().config_file(),
            "[reverse]\ncontroller = \"ctrl\"\n",
        )
        .unwrap();
        ops.trust_add(TrustAddReq {
            name: "pinned".into(),
            address: Some("pinned.example:4433".into()),
            fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"vocab").to_string()),
        })
        .unwrap();

        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        assert!(
            !data.findings.is_empty(),
            "expected several findings to fire in this deliberately unhealthy setup"
        );
        for finding in &data.findings {
            assert!(
                matches!(finding.status.as_str(), "warn" | "error" | "info"),
                "unexpected status {:?} on finding {finding:?}",
                finding.status
            );
        }
        assert!(
            matches!(data.overall.as_str(), "ok" | "warn" | "error"),
            "unexpected overall {:?}",
            data.overall
        );
    }

    // -----------------------------------------------------------------
    // Operation::COMMAND + overall_status
    // -----------------------------------------------------------------

    #[test]
    fn doctor_op_command_is_dotted_form() {
        assert_eq!(DoctorOp::COMMAND, "doctor.run");
    }

    #[test]
    fn overall_status_is_worst_of_error_warn_ok() {
        let error = DoctorFinding {
            code: "x".into(),
            status: "error".into(),
            detail: "d".into(),
            remedy: None,
        };
        let warn = DoctorFinding {
            code: "y".into(),
            status: "warn".into(),
            detail: "d".into(),
            remedy: None,
        };
        let info = DoctorFinding {
            code: "z".into(),
            status: "info".into(),
            detail: "d".into(),
            remedy: None,
        };
        assert_eq!(overall_status(&[]), "ok");
        assert_eq!(overall_status(std::slice::from_ref(&info)), "ok");
        assert_eq!(overall_status(&[info.clone(), warn.clone()]), "warn");
        assert_eq!(overall_status(&[info, warn, error]), "error");
    }

    // -----------------------------------------------------------------
    // config_unknown_key (`PLAN.md` M8 Step 4b, J10).
    // -----------------------------------------------------------------

    fn config_unknown_key_findings(ops: &Ops) -> Vec<DoctorFinding> {
        let data = ops
            .doctor(DoctorReq { host: None }, SystemTime::now())
            .unwrap();
        data.findings
            .into_iter()
            .filter(|f| f.code == "config_unknown_key")
            .collect()
    }

    #[test]
    fn doctor_reports_config_unknown_key_for_a_typo_d_key_in_a_known_section() {
        let (_guard, ops) = healthy_ops();
        std::fs::write(ops.paths().config_file(), "[serve]\nmx_sessions = 4\n").unwrap();

        let findings = config_unknown_key_findings(&ops);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].status, "warn");
        assert!(
            findings[0].detail.contains("serve.mx_sessions"),
            "{:?}",
            findings[0]
        );
    }

    #[test]
    fn doctor_reports_config_unknown_key_for_a_typo_d_section_name() {
        let (_guard, ops) = healthy_ops();
        std::fs::write(ops.paths().config_file(), "[serv]\nbind = \"[::]:1\"\n").unwrap();

        let findings = config_unknown_key_findings(&ops);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].detail.contains("serv.bind"),
            "{:?}",
            findings[0]
        );
    }

    #[test]
    fn doctor_reports_config_unknown_key_for_a_typo_d_key_nested_in_a_known_section() {
        let (_guard, ops) = healthy_ops();
        std::fs::write(
            ops.paths().config_file(),
            "[reverse]\nbackoff_initial_m = 5\n",
        )
        .unwrap();

        let findings = config_unknown_key_findings(&ops);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].detail.contains("reverse.backoff_initial_m"),
            "{:?}",
            findings[0]
        );
    }

    #[test]
    fn doctor_reports_no_config_unknown_key_when_every_key_is_recognized() {
        let (_guard, ops) = healthy_ops();
        std::fs::write(
            ops.paths().config_file(),
            "[serve]\nmax_sessions_per_principal = 4\n\n[reverse]\ncontroller = \"ctrl\"\n",
        )
        .unwrap();

        assert!(config_unknown_key_findings(&ops).is_empty());
    }

    /// A-P1-1/B-P1-3 (4b adversarial round): `ServeConfig::resume_ttl` is
    /// documented (`config.rs`) to accept `resume_ttl_secs` as a
    /// `#[serde(alias)]`. `Serialize` never re-emits that alias — only
    /// the canonical `resume_ttl` — so a naive present/known leaf-path
    /// diff flags it as unknown even though it is fully recognized and
    /// applied. This test fixes both halves at once: no finding, and
    /// (loaded the real way, not through this probe) the alias actually
    /// set the TTL.
    #[test]
    fn doctor_reports_no_config_unknown_key_for_the_documented_resume_ttl_alias() {
        let (_guard, ops) = healthy_ops();
        std::fs::write(
            ops.paths().config_file(),
            "[serve]\nresume_ttl_secs = 3600\n",
        )
        .unwrap();

        assert!(config_unknown_key_findings(&ops).is_empty());
        let config = Config::load(ops.paths()).unwrap();
        assert_eq!(config.serve.resume_ttl(), Duration::from_secs(3600));
    }

    /// The alias filter must not swallow an unrelated typo sitting next
    /// to it in the same file — `accepted_under_another_name` is a
    /// per-candidate probe, not a blanket "this section is fine" switch.
    #[test]
    fn doctor_reports_config_unknown_key_for_a_typo_next_to_a_recognized_alias() {
        let (_guard, ops) = healthy_ops();
        std::fs::write(
            ops.paths().config_file(),
            "[serve]\nresume_ttl_secs = 3600\nmax_sesions_per_principal = 4\n",
        )
        .unwrap();

        let findings = config_unknown_key_findings(&ops);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0]
                .detail
                .contains("serve.max_sesions_per_principal"),
            "{:?}",
            findings[0]
        );
    }

    /// B-P2-4 (4b adversarial round): the module doc on
    /// [`Ops::doctor_config_unknown_key_findings`] promises that a
    /// config.toml which fails to parse as *any* TOML (e.g. clobbered by
    /// a concurrent edit after `Config::load` already succeeded) is
    /// "nothing to compare", not a second error source. Calls the
    /// private probe directly with a malformed file, bypassing
    /// `Ops::doctor`'s own `Config::load` (which would fail first on the
    /// same input and never reach this method in practice).
    #[test]
    fn doctor_config_unknown_key_findings_is_empty_for_malformed_config_toml() {
        let (_guard, ops) = healthy_ops();
        std::fs::write(ops.paths().config_file(), "[serve\nthis = = broken\n").unwrap();

        let findings = ops.doctor_config_unknown_key_findings(&Config::default());
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn doctor_reports_no_config_unknown_key_when_config_toml_is_absent() {
        let (_guard, ops) = healthy_ops();
        // `healthy_ops` never writes a config.toml — `Config::load`
        // already yields `Config::default()` for a missing file
        // (`crate::config::Config::load`'s own doc), so there is nothing
        // for this probe to compare against.
        assert!(!ops.paths().config_file().exists());

        assert!(config_unknown_key_findings(&ops).is_empty());
    }

    /// B-P2-3 (4b adversarial round): a true lockstep in both directions,
    /// not a one-way `contains` check. `ServeConfig` is built as a
    /// struct literal with every field set to `Some(..)` and no
    /// `..Default::default()` spread — if a field is ever added to
    /// `ServeConfig`, this literal fails to compile until the new field
    /// is named here too, and the expected set below is updated to
    /// match. `toml`'s `Serialize` omits an `Option::None` field
    /// entirely (no TOML `null`), which is why every field must be
    /// `Some`: a `None` silently vanishes from `serve.*` on the
    /// serialized side rather than producing a leaf to compare, and
    /// would let a renamed/removed field escape detection.
    /// [`toml::Value::try_from`] then round-trips the same way
    /// [`Ops::doctor_config_unknown_key_findings`] does, and the
    /// resulting `serve.*` leaf-path set must equal the hard-coded
    /// expectation exactly — `assert_eq!` on two `BTreeSet`s, not
    /// `contains`, so a name change (not just a field count change) also
    /// fails this test.
    #[test]
    fn known_leaf_paths_round_trip_covers_every_serve_cap_key() {
        const ALL_SERVE_KEYS: [&str; 16] = [
            "bind",
            "replay_bytes",
            "resume_ttl",
            "close_grace_ms",
            "max_concurrent_handshakes",
            "handshake_rate_per_source",
            "max_sessions",
            "max_sessions_per_principal",
            "max_exec_per_principal",
            "validated_rate_per_source",
            "max_exec",
            "max_tunnel_streams_per_principal",
            "max_tunnel_streams_per_forward",
            "max_remote_forwards_per_principal",
            "max_connections_per_principal",
            "max_connections",
        ];
        let serve = crate::config::ServeConfig {
            bind: Some("[::]:4433".to_string()),
            replay_bytes: Some(1),
            resume_ttl: Some(2),
            close_grace_ms: Some(3),
            max_concurrent_handshakes: Some(4),
            handshake_rate_per_source: Some(5),
            max_sessions: Some(6),
            max_sessions_per_principal: Some(7),
            max_exec_per_principal: Some(8),
            validated_rate_per_source: Some(9),
            max_exec: Some(10),
            max_tunnel_streams_per_principal: Some(11),
            max_tunnel_streams_per_forward: Some(12),
            max_remote_forwards_per_principal: Some(13),
            max_connections_per_principal: Some(14),
            max_connections: Some(15),
        };
        let config = Config {
            serve,
            ..Default::default()
        };
        let value = toml::Value::try_from(&config).unwrap();
        let mut known = std::collections::BTreeSet::new();
        collect_leaf_paths(&value, String::new(), &mut known);

        let serve_paths: std::collections::BTreeSet<&str> = known
            .iter()
            .filter_map(|p| p.strip_prefix("serve."))
            .collect();
        let expected: std::collections::BTreeSet<&str> = ALL_SERVE_KEYS.into_iter().collect();
        assert_eq!(serve_paths, expected);
    }
}
