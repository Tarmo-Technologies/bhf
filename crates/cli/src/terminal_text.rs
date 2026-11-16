// SPDX-License-Identifier: Apache-2.0

//! Text from a target's run, made safe to print to the operator's terminal.
//!
//! A finding's report, its exception message, a replay's output and a
//! capsule's recorded signature all carry bytes the target chose, and the fuzz
//! input is often quoted in them. Printed raw, an escape sequence in them can
//! move the cursor, retitle the window or rewrite what the operator already
//! read. Every console line that shows such text goes through this module.

use std::fmt::Write;

/// `text` safe to print as one line of a terminal: the C0 and C1 control
/// characters other than tab (an escape, a bell, NUL, a carriage return, a
/// line break), DEL, and the bidirectional marks and overrides that reorder
/// what is shown are written as escapes (`\x1b`, `\n`, `\u{9b}`, `\u{202e}`).
/// Every other character, tab included, is kept as it is.
pub(crate) fn terminal_safe(text: &str) -> String {
    escape(text, false)
}

/// [`terminal_safe`] for a block of lines, such as a harness's own output:
/// line breaks are kept.
pub(crate) fn terminal_safe_block(text: &str) -> String {
    escape(text, true)
}

fn escape(text: &str, keep_line_breaks: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\t' => out.push(c),
            '\n' if keep_line_breaks => out.push(c),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x80 && c.is_control() => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if c.is_control() || is_bidi_control(c) => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// The marks and overrides that change the direction text is shown in.
pub(crate) fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_are_escaped_and_tab_is_kept() {
        assert_eq!(
            terminal_safe("a\x1b[2Jb\x07c\0d\te\u{9b}31m\u{85}f\x7f"),
            "a\\x1b[2Jb\\x07c\\x00d\te\\u{9b}31m\\u{85}f\\x7f"
        );
        assert_eq!(terminal_safe("line\r\nnext"), "line\\r\\nnext");
        assert_eq!(terminal_safe("\u{202e}txt.exe"), "\\u{202e}txt.exe");
        assert_eq!(
            terminal_safe("plain ünïcode → text"),
            "plain ünïcode → text"
        );
    }

    #[test]
    fn a_block_keeps_its_line_breaks_only() {
        assert_eq!(
            terminal_safe_block("first\nsecond\x1b]0;title\x07\r\n"),
            "first\nsecond\\x1b]0;title\\x07\\r\n"
        );
    }
}
