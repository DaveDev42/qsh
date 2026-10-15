//! Finding a helper executable this crate builds, from a test.
//!
//! `CARGO_BIN_EXE_<name>` exists only in the tests of the package that owns
//! the binary, and the tests that need `qsh-fake-ssh` live in `qsh-cli`
//! while the ones that need `qsh-console-probe` live here but run as
//! `it`, not as the bin. So the lookup is: an environment variable, then the
//! directories of the running test executable (`target/<profile>/deps/` and
//! `target/<profile>/`), which is where a workspace build puts it, then one
//! `cargo build` of it into that profile directory. The last step is what
//! makes a narrow `cargo nextest run -p qsh-cli --test it -E
//! 'test(/^ssh_bootstrap::/)'` work on a tree that has not built the whole
//! workspace.

use std::path::PathBuf;
use std::process::Command;

/// The path of the `qsh-testkit` binary `bin_name`, built if need be.
///
/// `env_var` names the override that wins over everything else (a path to
/// the executable).
///
/// # Panics
///
/// If the executable cannot be found or built.
pub fn locate(bin_name: &str, env_var: &str) -> PathBuf {
    let file = format!("{bin_name}{}", std::env::consts::EXE_SUFFIX);
    if let Some(path) = std::env::var_os(env_var) {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let exe_dir = exe.parent().expect("test executable has a directory");
    let candidates = [exe_dir.join(&file), exe_dir.join("..").join(&file)];
    if let Some(found) = candidates.iter().find(|p| p.is_file()) {
        return found.clone();
    }
    // Not built yet: build it once next to the test executables' profile
    // directory. Cargo's own lock serializes concurrent callers.
    let profile_dir = if exe_dir.file_name().is_some_and(|n| n == "deps") {
        exe_dir.parent().unwrap_or(exe_dir)
    } else {
        exe_dir
    };
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut build = Command::new(cargo);
    build.args(["build", "-p", "qsh-testkit", "--bin", bin_name]);
    if profile_dir.file_name().is_some_and(|n| n == "release") {
        build.arg("--release");
    }
    if let Some(target_dir) = profile_dir.parent() {
        build.arg("--target-dir").arg(target_dir);
    }
    let status = build
        .status()
        .unwrap_or_else(|err| panic!("run cargo to build {bin_name}: {err}"));
    assert!(status.success(), "cargo build of {bin_name} failed");
    let built = profile_dir.join(&file);
    assert!(
        built.is_file(),
        "{bin_name} is not at {}; build it with `cargo build -p qsh-testkit --bin {bin_name}` \
         or set {env_var}",
        built.display()
    );
    built
}
