//! Reverse mode (`docs/design/protocol.md` §11, `docs/CLI.md` §6.13):
//! `qsh listen` (controller) accepts dial-in registrations from `qsh
//! reverse` (target) and serves them as hosts.
//!
//! **PR 3a scope** (`PLAN.md` Step 3): [`registry`] (the transport-free
//! metadata table and name-resolution logic) and [`admit`] (the
//! `host.reverse` authorization choke point that bridges it to
//! `qsh_transport`'s typed `Principal`/`AuthPath`/`Authorizer`) land here,
//! factored so both can be unit-tested without a transport. Nothing in this
//! module opens a socket, and no CLI surface changes yet (`qsh listen`/`qsh
//! reverse` themselves are PR 3b: `listen.rs`, `target.rs`).
//!
//! The `registry`/`admit` split exists so that `registry.rs` alone can
//! satisfy the transport-free arch-lint `PLAN.md` Step 5 commits to adding
//! for this exact file (the same six-token `BROKER_DIR`-style ban
//! `xtask/src/arch.rs` already enforces under `broker/`) — see
//! `registry`'s module docs.

pub mod admit;
pub mod registry;
