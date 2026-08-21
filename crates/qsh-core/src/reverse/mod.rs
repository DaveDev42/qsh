//! Reverse mode (`docs/design/protocol.md` §11, `docs/CLI.md` §6.13):
//! `qsh listen` (controller) accepts dial-in registrations from `qsh
//! reverse` (target) and serves them as hosts.
//!
//! `PLAN.md` Step 3 lands in two PRs. **PR 3a**: [`registry`] (the
//! transport-free metadata table and name-resolution logic) and [`admit`]
//! (the `host.reverse` authorization choke point that bridges it to
//! `qsh_transport`'s typed `Principal`/`AuthPath`/`Authorizer`), factored so
//! both can be unit-tested without a transport. **PR 3b**: [`listen`] (`qsh
//! listen`'s `run_listen` — bind, accept, `handshake::respond`, `admit`,
//! the live-connection table) and [`target`] (`qsh reverse`'s `run_reverse`
//! — dial, `handshake::initiate` with `Hello.reverse`, then
//! `Server::serve_control` on the same connection). The CLI surface
//! (`Command::Listen`/`Command::Reverse`) lives in `qsh-cli`, not here.
//!
//! The `registry`/`admit` split exists so that `registry.rs` alone can
//! satisfy the transport-free arch-lint `PLAN.md` Step 5 commits to adding
//! for this exact file (the same six-token `BROKER_DIR`-style ban
//! `xtask/src/arch.rs` already enforces under `broker/`) — see
//! `registry`'s module docs.

pub mod admit;
pub mod listen;
pub mod registry;
pub mod target;
