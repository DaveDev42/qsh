//! Clock, TLS and quinn configuration shared by both ends.
//!
//! The transport settings mirror `transport_config` in
//! `crates/qsh-transport/src/endpoint.rs` as of ADR-0052: BBR, send fairness,
//! 2 MiB stream window, 8 MiB connection window, keep-alive 15 s, idle 45 s.

use crate::profile::{Cc, Profile};
use anyhow::{Context, Result};
use quinn::congestion::{BbrConfig, CubicConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub const SERVER_NAME: &str = "netbench";
const ALPN: &[u8] = b"qsh-netbench";

/// CLOCK_MONOTONIC in nanoseconds. Both processes run on one host (in two
/// network namespaces), and time namespaces are not unshared, so the value is
/// comparable across them. `std::time::Instant` is opaque and would not be.
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out pointer and CLOCK_MONOTONIC always exists.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn apply_shared(t: &mut quinn::TransportConfig, cc: Cc, keep_alive: Duration) {
    match cc {
        Cc::Bbr => t.congestion_controller_factory(Arc::new(BbrConfig::default())),
        Cc::Cubic => t.congestion_controller_factory(Arc::new(CubicConfig::default())),
    };
    t.send_fairness(true);
    t.stream_receive_window((2u32 << 20).into());
    t.receive_window((8u32 << 20).into());
    t.keep_alive_interval(Some(keep_alive));
    t.max_idle_timeout(Some(Duration::from_secs(45).try_into().expect("idle")));
    t.max_concurrent_bidi_streams(1024u32.into());
}

pub fn transport_config(
    cc: Cc,
    keep_alive: Duration,
    dgram_buf_kib: Option<u32>,
) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    apply_shared(&mut t, cc, keep_alive);
    if let Some(k) = dgram_buf_kib {
        t.datagram_send_buffer_size(k as usize * 1024);
    }
    Arc::new(t)
}

pub struct Identity {
    pub cert: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Identity> {
        let ck = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
        Ok(Identity {
            cert: ck.cert.der().clone(),
            key: ck.signing_key.serialize_der(),
        })
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

pub fn server_config(
    id: &Identity,
    cc: Cc,
    keep_alive: Duration,
    dgram_buf_kib: Option<u32>,
) -> Result<quinn::ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone()));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    cfg.transport_config(transport_config(cc, keep_alive, dgram_buf_kib));
    Ok(cfg)
}

pub fn client_config(
    cert: &CertificateDer<'static>,
    cc: Cc,
    keep_alive: Duration,
    dgram_buf_kib: Option<u32>,
) -> Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone())?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    cfg.transport_config(transport_config(cc, keep_alive, dgram_buf_kib));
    Ok(cfg)
}

/// A UDP endpoint on an ephemeral port (port 0 in `addr`). The bench never
/// binds a fixed port, so it cannot collide with a qsh serve on UDP 4433 even
/// if it ever ran outside its own network namespace.
pub fn udp_endpoint(
    addr: SocketAddr,
    server: Option<quinn::ServerConfig>,
) -> Result<quinn::Endpoint> {
    anyhow::ensure!(
        addr.port() == 0,
        "bench endpoints must use an ephemeral port"
    );
    let sock = std::net::UdpSocket::bind(addr).with_context(|| format!("bind {addr}"))?;
    let rt = quinn::default_runtime().context("no tokio runtime")?;
    Ok(quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        server,
        sock,
        rt,
    )?)
}

/// Keep-alive for the outer connection of a nested run: short, so PMTU
/// discovery has ack-eliciting traffic before the inner connection starts.
pub fn keep_alive_for(p: &Profile) -> Duration {
    if p.workload.path == crate::profile::Path::Direct {
        Duration::from_secs(15)
    } else {
        Duration::from_millis(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_is_monotonic() {
        let a = now_ns();
        let b = now_ns();
        assert!(b >= a && a > 0);
    }

    #[test]
    fn fixed_ports_are_refused() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        assert!(udp_endpoint(addr, None).is_err());
    }
}
