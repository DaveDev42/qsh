//! `qsh-cli`'s Windows console layer, included by path.
//!
//! The probe runs the real `tui/windows.rs`, not a copy, so what the
//! ConPTY tests observe is the code the client ships. That file uses
//! nothing outside its `tui` siblings, `std`, `qsh-core`, `qsh-proto` and
//! `windows-sys`, which is what keeps this inclusion possible.

#[path = "../../../../qsh-cli/src/tui/console_mode.rs"]
pub mod console_mode;
#[allow(dead_code)]
#[path = "../../../../qsh-cli/src/tui/terminal.rs"]
pub mod terminal;
#[allow(dead_code)]
#[path = "../../../../qsh-cli/src/tui/utf16_input.rs"]
pub mod utf16_input;
#[allow(dead_code)]
#[path = "../../../../qsh-cli/src/tui/windows.rs"]
pub mod windows;
