//! The `setup.run` marker. The judgment lives in `crate::setup`; this file
//! only names the operation where the registration gates look for it.

use super::Operation;

/// The `setup.run` operation (`qsh setup`, `docs/CLI.md` §6.20).
pub struct SetupRunOp;

impl Operation for SetupRunOp {
    const COMMAND: &'static str = "setup.run";
}
