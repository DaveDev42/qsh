//! `qsh-transport`: QUIC transport glue.
//!
//! Future responsibility (see the architecture note in the project plan and
//! `docs/PRD.md`'s transport section): wraps `quinn` behind `Transport`/
//! `StreamMux` traits so wire code never assumes QUIC-only primitives
//! (stream IDs, datagrams). Owns the `qsh/1` ALPN endpoint config
//! (keep-alive 15s / idle timeout 45s), the `QshPeerVerifier` (SPKI pin OR
//! private CA, no web PKI roots), and connection lifecycle (dial, accept,
//! `rebind()`-based migration, redial/backoff).
//!
//! This crate is intentionally empty in M0: it exists so the crate graph
//! and dependency direction (`qsh-core → qsh-transport → qsh-proto`) are
//! fixed before any protocol code lands.
