//! A one-shot check of an iroh relay (ADR-0061, `docs/CLI.md` §10
//! `iroh_relay_unreachable`): resolve the relay's host, open TLS to it with
//! the trust a relay connection uses, ask `/ping`, and ask for the relay
//! WebSocket upgrade. It sends no identity and no payload, and says which
//! stage failed.
//!
//! The same check tells `qsh-core` why a relay dial failed
//! (`details.iroh.reason`): the iroh connection itself reports only that it
//! did not stand.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::tls::CaTlsConfig;
use rustls::pki_types::{CertificateDer as TlsCertificateDer, ServerName};

use crate::iroh_backend::IrohRelayTrust;

/// The relay's path for latency queries.
const PING_PATH: &str = "/ping";
/// The relay's path for the relaying connection.
const RELAY_PATH: &str = "/relay";
/// The most of a response head the probe reads.
const HEAD_LIMIT: usize = 8192;

/// The stage of the check that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayProbeStage {
    /// The host name did not resolve, or the URL is not an `https` URL.
    Resolve,
    /// No TCP connection to any resolved address.
    Connect,
    /// The TLS handshake failed (a certificate the trust does not accept,
    /// or a peer that does not speak TLS).
    Tls,
    /// `/ping` did not answer `200`.
    Http,
    /// The WebSocket upgrade at `/relay` did not answer `101`.
    Upgrade,
    /// The whole check ran out of time.
    Timeout,
}

impl RelayProbeStage {
    /// The word `docs/CLI.md` §10 uses for the stage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Upgrade => "upgrade",
            Self::Timeout => "timeout",
        }
    }
}

/// Why the relay check failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayProbeFailure {
    /// The stage that failed.
    pub stage: RelayProbeStage,
    /// A short description for a human. Never holds more of the URL than its
    /// host.
    pub detail: String,
}

impl std::fmt::Display for RelayProbeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage.as_str(), self.detail)
    }
}

fn fail(stage: RelayProbeStage, detail: impl Into<String>) -> RelayProbeFailure {
    RelayProbeFailure {
        stage,
        detail: detail.into(),
    }
}

/// `(host, port)` of an `https://host[:port][/...]` URL.
fn split_https(url: &str) -> Option<(String, u16)> {
    let rest = url
        .get(..8)
        .filter(|s| s.eq_ignore_ascii_case("https://"))?;
    let rest = &url[rest.len()..];
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if let Some(inner) = authority.strip_prefix('[') {
        let (host, tail) = inner.split_once(']')?;
        let port = match tail {
            "" => 443,
            _ => tail.strip_prefix(':')?.parse().ok()?,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((authority.to_string(), 443)),
    }
}

fn ca_config(trust: &IrohRelayTrust) -> CaTlsConfig {
    let roots = |roots: &[crate::identity::CertificateDer]| {
        roots
            .iter()
            .map(|c| TlsCertificateDer::from(c.as_der().to_vec()))
            .collect::<Vec<_>>()
    };
    match trust {
        IrohRelayTrust::System => CaTlsConfig::system(),
        IrohRelayTrust::SystemWithRoots(r) => CaTlsConfig::system().with_extra_roots(roots(r)),
        IrohRelayTrust::OnlyRoots(r) => CaTlsConfig::custom_roots(roots(r)),
    }
}

/// How many trust anchors the operating system's store holds, as far as
/// they can be read. Only the count leaves this function
/// (`iroh.trust_roots` in `qsh doctor`, `iroh_trust_store_empty`); no
/// certificate is kept.
pub fn system_trust_root_count() -> usize {
    rustls_native_certs::load_native_certs().certs.len()
}

/// The environment variables a relay connection follows for its proxy when
/// `proxy_from_env` is on (see `IrohConfig::proxy_from_env`).
const PROXY_VARS: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];

/// Whether the process environment names an HTTP(S) proxy. The check below
/// connects straight to the relay host, so a caller whose relay connection
/// follows the environment cannot use it to say what the relay connection
/// saw.
pub fn proxy_in_environment() -> bool {
    proxy_named_by(|name| std::env::var(name).ok())
}

/// [`proxy_in_environment`] over `get`, for a test that must not touch the
/// real environment.
pub fn proxy_named_by(get: impl Fn(&str) -> Option<String>) -> bool {
    PROXY_VARS
        .iter()
        .any(|name| get(name).is_some_and(|v| !v.trim().is_empty()))
}

/// An error and its `source()` chain as one line.
fn chain_text(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !out.ends_with(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

fn remaining(deadline: Instant) -> Result<Duration, RelayProbeFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| fail(RelayProbeStage::Timeout, "the check ran out of time"))
}

fn is_timeout(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

struct Tls {
    conn: rustls::ClientConnection,
    tcp: TcpStream,
}

impl Tls {
    fn open(
        config: &Arc<rustls::ClientConfig>,
        name: &ServerName<'static>,
        addrs: &[SocketAddr],
        deadline: Instant,
    ) -> Result<Self, RelayProbeFailure> {
        let mut last = None;
        let mut tcp = None;
        for addr in addrs {
            let left = remaining(deadline)?;
            match TcpStream::connect_timeout(addr, left) {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(err) if is_timeout(&err) => {
                    return Err(fail(RelayProbeStage::Timeout, "TCP connect timed out"));
                }
                Err(err) => last = Some(err),
            }
        }
        let Some(tcp) = tcp else {
            let why = last.map_or_else(|| "no address".to_string(), |e| e.kind().to_string());
            return Err(fail(
                RelayProbeStage::Connect,
                format!("TCP connect: {why}"),
            ));
        };
        let conn = rustls::ClientConnection::new(config.clone(), name.clone())
            .map_err(|e| fail(RelayProbeStage::Tls, e.to_string()))?;
        let mut this = Self { conn, tcp };
        while this.conn.is_handshaking() {
            let left = remaining(deadline)?;
            this.tcp
                .set_read_timeout(Some(left))
                .and_then(|()| this.tcp.set_write_timeout(Some(left)))
                .map_err(|e| fail(RelayProbeStage::Tls, e.to_string()))?;
            this.conn.complete_io(&mut this.tcp).map_err(|e| {
                if is_timeout(&e) {
                    fail(RelayProbeStage::Timeout, "TLS handshake timed out")
                } else {
                    fail(RelayProbeStage::Tls, chain_text(&e))
                }
            })?;
        }
        Ok(this)
    }

    /// Send `request` and read the status code of the response head.
    fn status_of(
        &mut self,
        request: &str,
        deadline: Instant,
        stage: RelayProbeStage,
    ) -> Result<u16, RelayProbeFailure> {
        let left = remaining(deadline)?;
        self.tcp
            .set_read_timeout(Some(left))
            .and_then(|()| self.tcp.set_write_timeout(Some(left)))
            .map_err(|e| fail(stage, e.to_string()))?;
        let mut stream = rustls::Stream::new(&mut self.conn, &mut self.tcp);
        stream
            .write_all(request.as_bytes())
            .map_err(|e| io_fail(&e, stage))?;
        let mut head = Vec::new();
        let mut buf = [0u8; 512];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < HEAD_LIMIT {
            remaining(deadline)?;
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => head.extend_from_slice(&buf[..n]),
                Err(e) => return Err(io_fail(&e, stage)),
            }
        }
        let line = head.split(|b| *b == b'\r').next().unwrap_or_default();
        let line = String::from_utf8_lossy(line);
        let mut parts = line.split_whitespace();
        match (
            parts.next(),
            parts.next().and_then(|c| c.parse::<u16>().ok()),
        ) {
            (Some(version), Some(code)) if version.starts_with("HTTP/") => Ok(code),
            _ => Err(fail(stage, "the answer is not an HTTP response")),
        }
    }
}

fn io_fail(err: &std::io::Error, stage: RelayProbeStage) -> RelayProbeFailure {
    if is_timeout(err) {
        fail(RelayProbeStage::Timeout, "no answer in time")
    } else {
        fail(stage, err.kind().to_string())
    }
}

fn check(url: &str, trust: &IrohRelayTrust, deadline: Instant) -> Result<(), RelayProbeFailure> {
    let (host, port) = split_https(url).ok_or_else(|| {
        fail(
            RelayProbeStage::Resolve,
            "the relay URL is not an https URL",
        )
    })?;
    let name = ServerName::try_from(host.clone()).map_err(|_| {
        fail(
            RelayProbeStage::Resolve,
            "the relay host is not a valid name",
        )
    })?;
    let addrs: Vec<SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| fail(RelayProbeStage::Resolve, e.kind().to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(fail(RelayProbeStage::Resolve, "the host has no address"));
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ca_config(trust)
        .client_config(provider)
        .map_err(|e| fail(RelayProbeStage::Tls, e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);

    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let mut ping = Tls::open(&config, &name, &addrs, deadline)?;
    let code = ping.status_of(
        &format!("GET {PING_PATH} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"),
        deadline,
        RelayProbeStage::Http,
    )?;
    if code != 200 {
        return Err(fail(
            RelayProbeStage::Http,
            format!("{PING_PATH} answered {code}"),
        ));
    }
    drop(ping);

    let mut upgrade = Tls::open(&config, &name, &addrs, deadline)?;
    let code = upgrade.status_of(
        &format!(
            "GET {RELAY_PATH} HTTP/1.1\r\nHost: {host_header}\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: cXNoLXJlbGF5LXByb2Jl\r\n\
             Sec-WebSocket-Protocol: iroh-relay-v2, iroh-relay-v1\r\n\r\n"
        ),
        deadline,
        RelayProbeStage::Upgrade,
    )?;
    if code != 101 {
        return Err(fail(
            RelayProbeStage::Upgrade,
            format!("the upgrade answered {code}"),
        ));
    }
    Ok(())
}

/// Check the relay at `url`: resolve, TLS with `trust`, `/ping` answers 200,
/// and the WebSocket upgrade answers 101. Everything runs inside `limit`.
/// The check sends no identity key and no payload.
pub async fn probe_relay(
    url: &str,
    trust: &IrohRelayTrust,
    limit: Duration,
) -> Result<(), RelayProbeFailure> {
    let url = url.to_owned();
    let trust = trust.clone();
    let deadline = Instant::now() + limit;
    let work = tokio::task::spawn_blocking(move || check(&url, &trust, deadline));
    // The blocking work ends by its own deadline; this outer bound only
    // covers a thread that never gets to run.
    match tokio::time::timeout(limit + Duration::from_millis(500), work).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(_) => Err(fail(RelayProbeStage::Timeout, "the check did not finish")),
    }
}

#[cfg(test)]
mod tests {
    use super::proxy_named_by;

    #[test]
    fn any_of_the_four_proxy_variables_with_a_value_counts() {
        for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            assert!(
                proxy_named_by(|n| (n == name).then(|| "http://proxy.invalid:3128".to_string())),
                "{name}"
            );
        }
    }

    #[test]
    fn no_variable_or_an_empty_one_is_no_proxy() {
        assert!(!proxy_named_by(|_| None));
        assert!(!proxy_named_by(|_| Some(String::new())));
        assert!(!proxy_named_by(|_| Some("  ".to_string())));
        assert!(!proxy_named_by(
            |n| (n == "NO_PROXY").then(|| "x".to_string())
        ));
    }
}
