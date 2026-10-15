//! A small console program for the Windows console tests: it enters the raw
//! console mode the interactive client uses, and reports what it sees.
//!
//! The ConPTY harness (`tests/it/conpty.rs`) runs this inside a
//! pseudo-console and reads the records from the pseudo-console's output.
//! Every record is one `<<QSH-PROBE key fields>>` token followed by CR-LF,
//! so the harness can find it in a VT stream that also carries the
//! pseudo-console's own escape sequences.
//!
//! In order:
//!
//! - `size COLS ROWS`: the console window size at start.
//! - `mode-initial in=0x.. out=0x..`: the console input and output modes at
//!   start.
//! - `mode-raw in=0x.. out=0x..`: the modes after the probe switched to raw
//!   mode with the arithmetic in `qsh-cli`'s `tui/console_mode.rs` (included
//!   below by path, so this tests the real functions) and the UTF-8 code
//!   page, as read back from the console.
//! - `ready`: raw mode is on and the size poller is running.
//! - `bytes HEX`: one record per read of stdin, the bytes as they arrived.
//!   A read containing `0x04` (`^D`) ends the loop.
//! - `resize COLS ROWS N`: the size poller (every 200 ms) saw a new size;
//!   `N` counts the callbacks so far, one per distinct change.
//! - `mode-final in=0x.. out=0x..`: the modes after the probe restored the
//!   originals.
//! - `done resizes=N`.
//!
//! On any other platform it builds as a stub that exits with status 2.

#[cfg(windows)]
#[path = "../../../qsh-cli/src/tui/console_mode.rs"]
mod console_mode;

#[cfg(not(windows))]
fn main() {
    eprintln!("qsh-console-probe needs a Windows console");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    std::process::exit(probe::run());
}

#[cfg(windows)]
mod probe {
    use std::io::Write as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleCP, GetConsoleMode, GetConsoleOutputCP,
        GetConsoleScreenBufferInfo, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        SetConsoleCP, SetConsoleMode, SetConsoleOutputCP,
    };

    use super::console_mode::{raw_input_mode, raw_output_mode};

    const UTF8: u32 = 65001;
    const POLL: Duration = Duration::from_millis(200);

    fn record(key: &str, fields: &str) {
        let mut out = std::io::stdout().lock();
        let _ = write!(out, "<<QSH-PROBE {key} {fields}>>\r\n");
        let _ = out.flush();
    }

    fn modes(hin: HANDLE, hout: HANDLE) -> (u32, u32) {
        let (mut input, mut output) = (0u32, 0u32);
        // SAFETY: the handles are this process's standard handles and the
        // out-pointers are live locals.
        unsafe {
            GetConsoleMode(hin, &mut input);
            GetConsoleMode(hout, &mut output);
        }
        (input, output)
    }

    fn window_size(hout: HANDLE) -> Option<(i32, i32)> {
        // SAFETY: a zeroed `CONSOLE_SCREEN_BUFFER_INFO` is a valid
        // out-parameter, and the handle is this process's stdout.
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        if unsafe { GetConsoleScreenBufferInfo(hout, &mut info) } == 0 {
            return None;
        }
        let w = &info.srWindow;
        Some((
            i32::from(w.Right) - i32::from(w.Left) + 1,
            i32::from(w.Bottom) - i32::from(w.Top) + 1,
        ))
    }

    fn read_stdin(hin: HANDLE, buf: &mut [u8]) -> Option<usize> {
        let mut read = 0u32;
        // SAFETY: `buf` is live for the call and the length is its own; a
        // console handle takes no OVERLAPPED.
        let ok = unsafe {
            ReadFile(
                hin,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        (ok != 0 && read > 0).then_some(read as usize)
    }

    pub fn run() -> i32 {
        // SAFETY: plain queries of this process's standard handles.
        let (hin, hout) = unsafe {
            (
                GetStdHandle(STD_INPUT_HANDLE),
                GetStdHandle(STD_OUTPUT_HANDLE),
            )
        };
        let Some((cols, rows)) = window_size(hout) else {
            eprintln!("qsh-console-probe: stdout is not a console");
            return 3;
        };
        record("size", &format!("{cols} {rows}"));

        let (in0, out0) = modes(hin, hout);
        record("mode-initial", &format!("in={in0:#x} out={out0:#x}"));

        // SAFETY: plain queries and sets on this process's console.
        let (cp_in, cp_out) = unsafe { (GetConsoleCP(), GetConsoleOutputCP()) };
        unsafe {
            SetConsoleMode(hin, raw_input_mode(in0));
            SetConsoleMode(hout, raw_output_mode(out0));
            SetConsoleCP(UTF8);
            SetConsoleOutputCP(UTF8);
        }
        let (in1, out1) = modes(hin, hout);
        record("mode-raw", &format!("in={in1:#x} out={out1:#x}"));

        let resizes = Arc::new(AtomicU32::new(0));
        {
            let resizes = Arc::clone(&resizes);
            // A `HANDLE` is a raw pointer and not `Send`; the console handle
            // is process-wide, so the poller takes its address.
            let hout_addr = hout as usize;
            std::thread::spawn(move || {
                let hout = hout_addr as HANDLE;
                let mut last = (cols, rows);
                loop {
                    std::thread::sleep(POLL);
                    let Some(now) = window_size(hout) else {
                        continue;
                    };
                    if now != last {
                        last = now;
                        let n = resizes.fetch_add(1, Ordering::SeqCst) + 1;
                        record("resize", &format!("{} {} {n}", now.0, now.1));
                    }
                }
            });
        }
        record("ready", "");

        let mut buf = [0u8; 256];
        while let Some(n) = read_stdin(hin, &mut buf) {
            let chunk = &buf[..n];
            let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
            record("bytes", &hex);
            if chunk.contains(&0x04) {
                break;
            }
        }

        // SAFETY: as above.
        unsafe {
            SetConsoleMode(hin, in0);
            SetConsoleMode(hout, out0);
            SetConsoleCP(cp_in);
            SetConsoleOutputCP(cp_out);
        }
        let (in2, out2) = modes(hin, hout);
        record("mode-final", &format!("in={in2:#x} out={out2:#x}"));
        record(
            "done",
            &format!("resizes={}", resizes.load(Ordering::SeqCst)),
        );
        0
    }
}
