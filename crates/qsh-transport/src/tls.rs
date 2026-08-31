//! `QshPeerVerifier`: the single certificate-verification core shared by the
//! client (verifying the server) and the server (verifying the client),
//! implemented as rustls `danger` verifiers (`docs/design/protocol.md` §3):
//!
//! 1. leaf SPKI SHA-256 fingerprint is pinned in the trust store → allow,
//!    principal = the pin's `device:<name>`;
//! 2. else the chain verifies against a trust-store private CA → allow,
//!    principal = leaf SAN URI (`qsh://user/<n>` / `qsh://device/<n>`);
//! 3. else reject. **No web-PKI roots are ever loaded.**
//!
//! Additionally (M1 clarification): a leaf outside its validity window is
//! rejected on both paths — expiry is the one revocation lever pinned device
//! certs have, and "fail closed on ambiguity" wins.
//!
//! Trust *evaluation* (what is pinned, which CAs exist) is injected via
//! [`TrustEvaluator`], implemented by `qsh-core::trust`; this crate only
//! owns the verification mechanics.

use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, OtherError,
    SignatureScheme,
};
use webpki::{EndEntityCert, KeyUsage};

use crate::identity::{Fingerprint, Principal, principal_from_san, validity_unix};

/// Source of trust decisions, injected by `qsh-core::trust`.
///
/// Implementations must be cheap to call: the verifier invokes them on the
/// TLS handshake path (synchronously).
pub trait TrustEvaluator: Send + Sync + 'static {
    /// If `fingerprint` is pinned, the principal it authenticates as.
    fn lookup_pin(&self, fingerprint: &Fingerprint) -> Option<Principal>;

    /// DER-encoded private CA root certificates. Empty = CA mode disabled.
    fn ca_roots(&self) -> Vec<CertificateDer<'static>>;

    /// Whether an unpinned, non-CA peer should still be admitted under
    /// [`Principal::Pairing`] (ADR-0002, one-time invite pairing,
    /// `docs/design/protocol.md` §15). Default `false` — every existing
    /// implementor (`StaticTrust`, and any test/probe evaluator) needs no
    /// change; only `qsh-core`'s `SharedTrustStore` overrides this, backed
    /// by whether it currently has a live invite record. Checked by
    /// [`QshPeerVerifier::verify_core`] only *after* both the pin and the
    /// CA-chain paths have already failed — an evaluator that pins or
    /// CA-signs a peer is never routed through this fallback.
    fn pairing_open(&self) -> bool {
        false
    }
}

/// Which side of the handshake the peer certificate is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    /// The peer is the TLS server (we dialed it).
    Server,
    /// The peer is the TLS client (it dialed us).
    Client,
}

/// Why the verifier rejected a peer. Deliberately coarse: this is what
/// eventually surfaces as `AUTH_FAILED`/`TRUST_REQUIRED` `details`, which
/// per `docs/CLI.md` §6.11 carry only a category, never a reason string
/// that could leak trust-store contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The certificate could not be parsed.
    Malformed,
    /// Outside its validity window.
    Expired,
    /// Not pinned and not issued by a trusted CA (or no CA configured).
    Untrusted,
    /// CA-signed but carries no recognized `qsh://` SAN principal.
    NoPrincipal,
}

/// How a peer was authenticated: by a trust-store pin on its exact
/// certificate, or by a chain to a trusted private CA. Policy needs the
/// distinction (the interim M1 policy admits **pinned** peers only), and it
/// cannot be recovered from the [`Principal`] alone — a CA-issued leaf may
/// legitimately assert a `qsh://device/…` principal too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthPath {
    /// The leaf's SPKI fingerprint matched a trust-store pin.
    Pin,
    /// The chain verified to a trusted CA root; principal from the SAN.
    Ca,
    /// Neither pinned nor CA-signed, admitted only because
    /// [`TrustEvaluator::pairing_open`] answered `true` (ADR-0002). Carries
    /// [`Principal::Pairing`] — see that variant's doc for why this is not
    /// a normal ACL-reachable auth path.
    Pairing,
}

/// A peer that passed the verifier: who they are and how we know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeer {
    /// The ACL principal.
    pub principal: Principal,
    /// Which trust path admitted them.
    pub auth_path: AuthPath,
}

/// What the verifier saw for the most recent handshake it processed.
///
/// Only meaningful for verifiers used by a single dial (the client side): a
/// server-side verifier is shared by every incoming connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// SPKI fingerprint of the presented leaf, if it parsed.
    pub fingerprint: Option<Fingerprint>,
    /// The decision.
    pub outcome: Result<Principal, RejectReason>,
}

/// The pin-or-CA verifier. Implements both rustls verifier traits over one
/// core so client and server can never drift.
pub struct QshPeerVerifier {
    evaluator: Arc<dyn TrustEvaluator>,
    algs: WebPkiSupportedAlgorithms,
    last: Mutex<Option<Observation>>,
}

impl fmt::Debug for QshPeerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QshPeerVerifier").finish_non_exhaustive()
    }
}

impl QshPeerVerifier {
    /// Build a verifier over `evaluator` using the aws-lc-rs signature
    /// algorithms (Ed25519, ECDSA P-256/384, RSA-PSS…).
    pub fn new(evaluator: Arc<dyn TrustEvaluator>) -> Self {
        Self {
            evaluator,
            algs: rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            last: Mutex::new(None),
        }
    }

    /// The most recent observation (see [`Observation`]).
    pub fn last_observation(&self) -> Option<Observation> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Re-derive the principal of an already-verified peer chain (as
    /// returned by `quinn::Connection::peer_identity()`), so it can be
    /// attached to the connection. Uses the same core as the handshake.
    pub fn principal_of(
        &self,
        chain: &[CertificateDer<'_>],
        role: PeerRole,
    ) -> Result<Principal, RejectReason> {
        self.verify_peer(chain, role).map(|v| v.principal)
    }

    /// Like [`principal_of`](Self::principal_of) but also reports *which*
    /// trust path admitted the peer.
    pub fn verify_peer(
        &self,
        chain: &[CertificateDer<'_>],
        role: PeerRole,
    ) -> Result<VerifiedPeer, RejectReason> {
        let (end_entity, intermediates) = match chain.split_first() {
            Some(x) => x,
            None => return Err(RejectReason::Untrusted),
        };
        self.verify_core(end_entity, intermediates, UnixTime::now(), role)
            .map_err(|(reason, _)| reason)
    }

    /// The verification core. Returns the principal or the coarse reason
    /// plus the precise rustls error to hand back to the handshake.
    fn verify_core(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        role: PeerRole,
    ) -> Result<VerifiedPeer, (RejectReason, TlsError)> {
        let fingerprint = Fingerprint::of_cert_der(end_entity).map_err(|_| {
            (
                RejectReason::Malformed,
                TlsError::InvalidCertificate(CertificateError::BadEncoding),
            )
        })?;

        // Validity window first: it applies to both paths.
        let (not_before, not_after) = validity_unix(end_entity).map_err(|_| {
            (
                RejectReason::Malformed,
                TlsError::InvalidCertificate(CertificateError::BadEncoding),
            )
        })?;
        let now_secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        if now_secs < not_before {
            return Err((
                RejectReason::Expired,
                TlsError::InvalidCertificate(CertificateError::NotValidYet),
            ));
        }
        if now_secs > not_after {
            return Err((
                RejectReason::Expired,
                TlsError::InvalidCertificate(CertificateError::Expired),
            ));
        }

        // 1. Pin.
        if let Some(principal) = self.evaluator.lookup_pin(&fingerprint) {
            return Ok(VerifiedPeer {
                principal,
                auth_path: AuthPath::Pin,
            });
        }

        // 2. Private CA chain. Wrapped in a closure so its several distinct
        // failure points share one tail check (3, below) instead of each
        // needing its own copy of it.
        let ca_result: Result<VerifiedPeer, (RejectReason, TlsError)> = (|| {
            let roots = self.evaluator.ca_roots();
            if roots.is_empty() {
                return Err((
                    RejectReason::Untrusted,
                    TlsError::InvalidCertificate(CertificateError::UnknownIssuer),
                ));
            }
            let anchors = roots
                .iter()
                .map(|der| {
                    webpki::anchor_from_trusted_cert(der)
                        .map(|anchor| anchor.to_owned())
                        .map_err(|_| {
                            (
                                RejectReason::Untrusted,
                                TlsError::InvalidCertificate(CertificateError::UnknownIssuer),
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let ee = EndEntityCert::try_from(end_entity).map_err(|_| {
                (
                    RejectReason::Malformed,
                    TlsError::InvalidCertificate(CertificateError::BadEncoding),
                )
            })?;
            let usage = match role {
                PeerRole::Server => KeyUsage::server_auth(),
                PeerRole::Client => KeyUsage::client_auth(),
            };
            ee.verify_for_usage(
                self.algs.all,
                &anchors,
                intermediates,
                now,
                usage,
                None,
                None,
            )
            .map_err(|e| (RejectReason::Untrusted, webpki_to_tls(e)))?;

            // CA path: identity comes from the leaf's SAN URI.
            match principal_from_san(end_entity) {
                Ok(Some(principal)) => Ok(VerifiedPeer {
                    principal,
                    auth_path: AuthPath::Ca,
                }),
                Ok(None) => Err((
                    RejectReason::NoPrincipal,
                    TlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
                )),
                Err(_) => Err((
                    RejectReason::Malformed,
                    TlsError::InvalidCertificate(CertificateError::BadEncoding),
                )),
            }
        })();

        // 3. Pairing fallback (ADR-0002, `docs/design/protocol.md` §15):
        // only reached once both the pin and CA paths above have failed.
        // The cert already passed the fingerprint/validity-window checks
        // above this function's pin/CA section, so this only ever admits a
        // well-formed, currently-valid cert that simply is not (yet)
        // trusted by either other path — exactly "any new device's own
        // self-signed identity", which is the case pairing exists for.
        match ca_result {
            Ok(v) => Ok(v),
            Err(err) => {
                if self.evaluator.pairing_open() {
                    Ok(VerifiedPeer {
                        principal: Principal::Pairing,
                        auth_path: AuthPath::Pairing,
                    })
                } else {
                    Err(err)
                }
            }
        }
    }

    fn verify_and_record(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        role: PeerRole,
    ) -> Result<VerifiedPeer, TlsError> {
        let fingerprint = Fingerprint::of_cert_der(end_entity).ok();
        let result = self.verify_core(end_entity, intermediates, now, role);
        let outcome = match &result {
            Ok(v) => Ok(v.principal.clone()),
            Err((reason, _)) => Err(*reason),
        };
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(Observation {
            fingerprint,
            outcome,
        });
        result.map_err(|(_, err)| err)
    }
}

fn webpki_to_tls(err: webpki::Error) -> TlsError {
    let ce = match err {
        webpki::Error::CertExpired { .. } => CertificateError::Expired,
        webpki::Error::CertNotValidYet { .. } => CertificateError::NotValidYet,
        webpki::Error::UnknownIssuer => CertificateError::UnknownIssuer,
        webpki::Error::BadDer | webpki::Error::BadDerTime => CertificateError::BadEncoding,
        webpki::Error::InvalidSignatureForPublicKey => CertificateError::BadSignature,
        other => CertificateError::Other(OtherError(Arc::new(other))),
    };
    TlsError::InvalidCertificate(ce)
}

impl ServerCertVerifier for QshPeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // The server name is deliberately ignored: identity is the pin or
        // the CA-asserted SAN principal, never a DNS name.
        self.verify_and_record(end_entity, intermediates, now, PeerRole::Server)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

impl ClientCertVerifier for QshPeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // We do not hint any CA subject; peers always send their device
        // cert regardless.
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // Mutual authentication is not optional (`protocol.md` §3).
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        self.verify_and_record(end_entity, intermediates, now, PeerRole::Client)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A fixed, in-memory [`TrustEvaluator`] — for tests and for one-shot
/// "observe the peer's fingerprint" dials (empty store: rejects everything
/// but records what it saw).
#[derive(Debug, Default, Clone)]
pub struct StaticTrust {
    pins: Vec<(Fingerprint, Principal)>,
    cas: Vec<CertificateDer<'static>>,
    pairing_open: bool,
}

impl StaticTrust {
    /// An evaluator that trusts nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Add a pin.
    #[must_use]
    pub fn with_pin(mut self, fingerprint: Fingerprint, principal: Principal) -> Self {
        self.pins.push((fingerprint, principal));
        self
    }

    /// Add a private CA root (DER).
    #[must_use]
    pub fn with_ca(mut self, root_der: CertificateDer<'static>) -> Self {
        self.cas.push(root_der);
        self
    }

    /// Toggle the pairing fallback (test-only; production evaluators wire
    /// this to a real open-invite check — see `SharedTrustStore`).
    #[must_use]
    pub fn with_pairing_open(mut self, open: bool) -> Self {
        self.pairing_open = open;
        self
    }
}

impl TrustEvaluator for StaticTrust {
    fn lookup_pin(&self, fingerprint: &Fingerprint) -> Option<Principal> {
        self.pins
            .iter()
            .find(|(fp, _)| fp == fingerprint)
            .map(|(_, p)| p.clone())
    }

    fn ca_roots(&self) -> Vec<CertificateDer<'static>> {
        self.cas.clone()
    }

    fn pairing_open(&self) -> bool {
        self.pairing_open
    }
}
