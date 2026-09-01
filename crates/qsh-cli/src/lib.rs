//! Library surface of the `qsh` binary crate. It exists for exactly one
//! consumer: `xtask`'s man-page generator (`cargo xtask man`,
//! `xtask/src/man.rs`) needs this build's real `clap::Command` tree to
//! render `docs/man/` from — the same "표 두 벌 금지" discipline the rest
//! of this repo applies to JSON fixtures and schemas (`docs/design/
//! testing.md` L6, `docs/CLI.md` §10). A hand-written man page would be a
//! second, driftable copy of `cli.rs`'s own `--help` text; generating from
//! `Cli::command()` instead means there is exactly one place that decides
//! what `qsh --help` says.
//!
//! `qsh-cli` otherwise stays a thin frontend binary in every sense
//! `docs/CLI.md` §11 and `docs/design/architecture.md` §1 already commit
//! to: `mcp`, `render`, and `tui` stay private to `main.rs`, nothing here
//! is a supported external API, and no product crate may depend on this
//! one. Worth being exact about what enforces that, now that a library
//! target makes the edge expressible at all: `xtask/src/arch.rs`'s matrix
//! has no lane for `qsh-cli` as anyone's dependency, but the thing that
//! actually stops it is cargo. `qsh-proto`, `qsh-transport`, and `qsh-core`
//! all sit *below* `qsh-cli`, so an edge back from any of them is a package
//! cycle and cargo refuses to resolve the workspace at all — checked by
//! adding `qsh-core -> qsh-cli` and watching `cargo` reject it before
//! arch-lint got a chance to run. The two crates that could take the edge
//! without a cycle are the two the matrix already exempts: `qsh-testkit`
//! (unrestricted, for test-harness reasons) and `xtask` itself, which sits
//! outside the matrix by design — the tool that enforces it, not a
//! product-layer crate bound by it (`docs/design/architecture.md` §1's own
//! line: "xtask (arch-lint — workspace 멤버, 위 매트릭스를 빌드 실패로
//! 강제)").

pub mod cli;
