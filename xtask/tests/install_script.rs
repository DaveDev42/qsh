//! Tests for the release scripts under `scripts/`: the installers
//! (`install.sh`, `install.ps1`), the all-or-none signing-secret gate, the
//! Windows zip packager, the Authenticode verdict function and the scoop and
//! winget manifest renderer, plus a few structural checks of
//! `.github/workflows/release.yml` that keep it in step with them. None of it
//! touches the network.
//!
//! One integration binary, as `CLAUDE.md` asks for the crates under
//! `crates/`: each topic is a module in `install_script/`. The shell scripts
//! run on unix. The PowerShell scripts run on Windows only, because they
//! need a real Windows PowerShell (registry, `Get-AuthenticodeSignature`),
//! and they are embedded with `include_str!` so the test never depends on
//! where the checkout lives.
//!
//! Lives in `xtask` because it is an unpublished crate: no tarball policy
//! applies to these files.

// Not `mod x;` alone: a test target's root file looks for its modules beside
// itself, and they live in `install_script/` so the directory holds the topics.
#[cfg(windows)]
#[path = "install_script/install_ps1.rs"]
mod install_ps1;
#[cfg(unix)]
#[path = "install_script/install_sh.rs"]
mod install_sh;
#[cfg(unix)]
#[path = "install_script/package_manifests.rs"]
mod package_manifests;
#[cfg(windows)]
#[path = "install_script/pwsh.rs"]
mod pwsh;
#[path = "install_script/release_yml.rs"]
mod release_yml;
#[cfg(unix)]
#[path = "install_script/secret_gate.rs"]
mod secret_gate;
#[cfg(windows)]
#[path = "install_script/signature.rs"]
mod signature;
