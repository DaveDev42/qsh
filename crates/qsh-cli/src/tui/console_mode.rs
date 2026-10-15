//! Windows console mode arithmetic, with no Windows API in it.
//!
//! The interactive client and the invitation-code prompt change the console
//! input and output modes with `GetConsoleMode`/`SetConsoleMode`. Which bits
//! to flip is a pure function of the mode the console already had, so it
//! lives here as plain `u32` arithmetic: the constants are the documented
//! Win32 values spelled out in this file, which lets the tests run on every
//! CI leg without `windows-sys`.
//!
//! Every function leaves the bits it was not asked to touch exactly as it
//! found them (quick-edit, insert mode, mouse input, window input and
//! whatever a later Windows release adds). The caller keeps the original
//! mode and hands it back to `SetConsoleMode` to restore.

// The console layer that calls these is Windows-only, so on a non-test Unix
// build the module is not compiled at all (`super`), and on a non-test
// Windows build nothing in this crate reads it yet.
#![cfg_attr(not(test), allow(dead_code))]

/// Input mode: Ctrl-C is handled by the system instead of being delivered
/// as input (`ENABLE_PROCESSED_INPUT`).
pub const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
/// Input mode: `ReadFile` returns whole lines (`ENABLE_LINE_INPUT`).
pub const ENABLE_LINE_INPUT: u32 = 0x0002;
/// Input mode: typed characters are echoed (`ENABLE_ECHO_INPUT`).
pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
/// Input mode: key events arrive as VT sequences
/// (`ENABLE_VIRTUAL_TERMINAL_INPUT`).
pub const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
/// Output mode: VT escape sequences are interpreted
/// (`ENABLE_VIRTUAL_TERMINAL_PROCESSING`).
pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
/// Output mode: a line feed does not imply a carriage return
/// (`DISABLE_NEWLINE_AUTO_RETURN`).
pub const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;

/// The input mode of an interactive attach: no line editing, no echo, no
/// system Ctrl-C handling, and keys delivered as VT bytes.
///
/// `Ctrl-C` then reaches the remote PTY as the byte `0x03`, which is what
/// the remote line discipline expects (`docs/CLI.md` §7, §9).
pub fn raw_input_mode(original: u32) -> u32 {
    (original & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
        | ENABLE_VIRTUAL_TERMINAL_INPUT
}

/// The output mode of an interactive attach: the remote's VT sequences are
/// interpreted by the console, and a bare line feed is not turned into a
/// carriage return plus line feed behind the remote's back.
pub fn raw_output_mode(original: u32) -> u32 {
    original | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
}

/// The input mode of the invitation-code prompt: typed characters are not
/// echoed, and line editing and Ctrl-C handling stay as the console had
/// them, so the operator can still correct a mistyped code and abort.
pub fn echo_suppressed_input_mode(original: u32) -> u32 {
    original & !ENABLE_ECHO_INPUT
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cooked console input mode as Windows hands it out, plus a few bits
    /// this module has no opinion on (`ENABLE_WINDOW_INPUT` 0x8,
    /// `ENABLE_MOUSE_INPUT` 0x10, `ENABLE_INSERT_MODE` 0x20,
    /// `ENABLE_QUICK_EDIT_MODE` 0x40, `ENABLE_EXTENDED_FLAGS` 0x80).
    const COOKED_INPUT: u32 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80;
    const UNRELATED_INPUT: u32 = 0x08 | 0x10 | 0x20 | 0x40 | 0x80;

    #[test]
    fn raw_input_mode_clears_line_echo_processed_and_sets_vt_input() {
        let raw = raw_input_mode(COOKED_INPUT);
        assert_eq!(raw & ENABLE_LINE_INPUT, 0);
        assert_eq!(raw & ENABLE_ECHO_INPUT, 0);
        assert_eq!(raw & ENABLE_PROCESSED_INPUT, 0);
        assert_eq!(
            raw & ENABLE_VIRTUAL_TERMINAL_INPUT,
            ENABLE_VIRTUAL_TERMINAL_INPUT
        );
        // A console that already had VT input on, or the three bits off,
        // comes out the same.
        assert_eq!(raw_input_mode(raw), raw);
        assert_eq!(
            raw_input_mode(0),
            ENABLE_VIRTUAL_TERMINAL_INPUT,
            "from an empty mode only VT input is set"
        );
    }

    #[test]
    fn raw_output_mode_sets_vt_processing_and_disables_newline_auto_return() {
        // `ENABLE_PROCESSED_OUTPUT` (0x1) and `ENABLE_WRAP_AT_EOL_OUTPUT`
        // (0x2) are what a console starts with.
        let original = 0x01 | 0x02;
        let raw = raw_output_mode(original);
        assert_eq!(
            raw & ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING
        );
        assert_eq!(
            raw & DISABLE_NEWLINE_AUTO_RETURN,
            DISABLE_NEWLINE_AUTO_RETURN
        );
        assert_eq!(raw, original | 0x04 | 0x08);
        assert_eq!(raw_output_mode(raw), raw, "idempotent");
    }

    #[test]
    fn echo_suppressed_mode_clears_only_echo_input() {
        let quiet = echo_suppressed_input_mode(COOKED_INPUT);
        assert_eq!(quiet, COOKED_INPUT & !ENABLE_ECHO_INPUT);
        // Line editing and Ctrl-C handling are what the prompt relies on.
        assert_eq!(quiet & ENABLE_LINE_INPUT, ENABLE_LINE_INPUT);
        assert_eq!(quiet & ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_INPUT);
        assert_eq!(echo_suppressed_input_mode(quiet), quiet, "idempotent");
    }

    #[test]
    fn mode_computation_preserves_unrelated_bits() {
        // Over a spread of sample modes (empty, all bits set, single high
        // and low bits, a dense pattern, the cooked default), the unrelated
        // part of the result equals the unrelated part of the input, for
        // all three functions, whatever the named bits were to begin with.
        let named_input = ENABLE_PROCESSED_INPUT
            | ENABLE_LINE_INPUT
            | ENABLE_ECHO_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        let named_output = ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        for original in [
            0u32,
            u32::MAX,
            0x0000_0050,
            0x8000_0000,
            0xdead_beef,
            COOKED_INPUT,
        ] {
            assert_eq!(
                raw_input_mode(original) & !named_input,
                original & !named_input,
                "raw input mode touched an unrelated bit of {original:#x}"
            );
            assert_eq!(
                echo_suppressed_input_mode(original) & !ENABLE_ECHO_INPUT,
                original & !ENABLE_ECHO_INPUT,
                "echo suppression touched an unrelated bit of {original:#x}"
            );
            assert_eq!(
                raw_output_mode(original) & !named_output,
                original & !named_output,
                "raw output mode touched an unrelated bit of {original:#x}"
            );
        }
        assert_eq!(
            raw_input_mode(COOKED_INPUT) & UNRELATED_INPUT,
            UNRELATED_INPUT
        );
    }
}
