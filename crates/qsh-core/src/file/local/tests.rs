//! Platform-neutral tests of the local interface: the Windows file-name rule
//! is pure, so it is checked on every leg.

use super::*;

#[test]
fn windows_names_refuse_streams_devices_and_stripped_spellings() {
    for ok in [
        "a.txt",
        "report 2026.md",
        ".hidden",
        "no_extension",
        "é.txt",
        "CONSOLE.txt",
        "COM10",
        "LPT0",
        "a b",
        "x..y",
    ] {
        assert!(windows_name_is_safe(ok), "{ok:?}");
    }
    for bad in [
        "",
        ".",
        "..",
        "a:b",
        "file.txt:stream",
        "a\\b",
        "a/b",
        "a<b",
        "a>b",
        "a\"b",
        "a|b",
        "a?b",
        "a*b",
        "tab\there",
        "nul\0byte",
        "trailing.",
        "trailing ",
        "CON",
        "con",
        "Nul.txt",
        "AUX.tar.gz",
        "COM1",
        "lpt9.log",
        "PRN ",
        "CON .txt",
        "COM\u{b9}",
        "CONIN$",
    ] {
        assert!(!windows_name_is_safe(bad), "{bad:?}");
    }
}
