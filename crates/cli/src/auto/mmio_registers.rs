// SPDX-License-Identifier: Apache-2.0

//! Device registers a target reads at fixed addresses. Firmware reaches a
//! peripheral through a pointer cast of a constant, usually inside a macro
//! (`#define UART_SR (*(volatile uint32_t *)(UART1_BASE + 0x00))`). On the host
//! nothing is mapped there, so the first read SEGVs: that is the missing device,
//! not an out-of-bounds read the input caused. [`register_fault`] finds such a
//! crash: its fault address lies on a register the crash path's sources name.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

/// The span after a register address that is the same device: one page.
const DEVICE_SPAN: u64 = 0x1000;
/// Below this a constant is a small integer or a NULL offset, not a device.
const LOWEST_DEVICE_ADDRESS: u64 = 0x1_0000;
/// Bounds on what one finding's scan reads.
const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: u64 = 1 << 20;
const MAX_INCLUDE_DEPTH: usize = 3;

/// A register address a source names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Register {
    pub(crate) address: u64,
    /// The macro the cast is in, when it is in one.
    pub(crate) name: Option<String>,
    pub(crate) file: PathBuf,
    /// 1-based.
    pub(crate) line: usize,
}

/// A crash at a fixed device-register address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisterFault {
    pub(crate) fault: u64,
    pub(crate) register: Register,
}

impl RegisterFault {
    /// One sentence for the fidelity record: what the target read, and where.
    pub(crate) fn describe(&self, root: Option<&Path>) -> String {
        let file = root
            .and_then(|root| self.register.file.strip_prefix(root).ok())
            .unwrap_or(&self.register.file);
        let name = self
            .register
            .name
            .as_deref()
            .map(|name| format!("{name} "))
            .unwrap_or_default();
        format!(
            "the target read device register {name}at {:#x} ({}:{}) through a fixed address; \
             no device is mapped there on the host, so the read faulted at {:#x}",
            self.register.address,
            file.display(),
            self.register.line,
            self.fault
        )
    }
}

/// The register a SEGV finding's fault address lies on, from the sources of
/// its crash path (the stack frames' files and the headers they include).
pub(crate) fn register_fault(raw: &serde_json::Value) -> Option<RegisterFault> {
    let fault = fault_address(raw)?;
    if fault < LOWEST_DEVICE_ADDRESS {
        return None;
    }
    let files: Vec<PathBuf> = raw
        .pointer("/exception/stack")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|frame| frame.get("file")?.as_str().map(PathBuf::from))
        .filter(|file| file.is_file())
        .collect();
    registers(&files)
        .into_iter()
        .find(|register| on_device(fault, register.address))
        .map(|register| RegisterFault { fault, register })
}

/// Whether `fault` lies on the device whose register is at `register`.
fn on_device(fault: u64, register: u64) -> bool {
    (register..register.saturating_add(DEVICE_SPAN)).contains(&fault)
        || fault & !(DEVICE_SPAN - 1) == register & !(DEVICE_SPAN - 1)
}

/// The address an ASan SEGV report names (`SEGV on unknown address 0x...`).
fn fault_address(raw: &serde_json::Value) -> Option<u64> {
    let message = raw.pointer("/exception/message")?.as_str()?;
    let rest = message.split("SEGV on unknown address ").nth(1)?;
    let hex = rest.split_whitespace().next()?.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

/// The register addresses `files` and the headers they include name.
pub(crate) fn registers(files: &[PathBuf]) -> Vec<Register> {
    let mut sources = Vec::new();
    let mut seen = HashSet::new();
    for file in files {
        collect(file, 0, &mut seen, &mut sources);
    }
    let mut defines: BTreeMap<String, Define> = BTreeMap::new();
    for source in &sources {
        for (name, define) in defines_in(source) {
            defines.entry(name).or_insert(define);
        }
    }
    let mut out = Vec::new();
    for source in &sources {
        for (line, mut text, macro_name) in logical_lines(source) {
            // A register macro taking an offset names its device's base.
            if let Some(params) = macro_name
                .as_ref()
                .and_then(|name| defines.get(name))
                .and_then(|define| define.params.as_ref())
            {
                for param in params {
                    text = replace_word(&text, param, "0");
                }
            }
            for operand in cast_operands(&text) {
                if let Some(address) = evaluate(&operand, &defines, 0)
                    .filter(|address| *address >= LOWEST_DEVICE_ADDRESS)
                {
                    out.push(Register {
                        address,
                        name: macro_name.clone(),
                        file: source.path.clone(),
                        line,
                    });
                }
            }
        }
    }
    out.dedup();
    out
}

struct Source {
    path: PathBuf,
    text: String,
}

/// Read `file` and, up to [`MAX_INCLUDE_DEPTH`] deep, the quoted headers it
/// includes that sit beside it.
fn collect(file: &Path, depth: usize, seen: &mut HashSet<PathBuf>, out: &mut Vec<Source>) {
    if out.len() >= MAX_FILES || !seen.insert(file.to_path_buf()) {
        return;
    }
    if std::fs::metadata(file).map_or(true, |meta| meta.len() > MAX_FILE_BYTES) {
        return;
    }
    let Ok(text) = std::fs::read_to_string(file) else {
        return;
    };
    let includes: Vec<PathBuf> = text
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix('#')?.trim_start();
            let quoted = rest
                .strip_prefix("include")?
                .trim_start()
                .strip_prefix('"')?;
            Some(file.parent()?.join(quoted.split('"').next()?))
        })
        .collect();
    out.push(Source {
        path: file.to_path_buf(),
        text,
    });
    if depth < MAX_INCLUDE_DEPTH {
        for include in includes {
            if include.is_file() {
                collect(&include, depth + 1, seen, out);
            }
        }
    }
}

/// A `#define`: its parameters (a function-like macro) and body.
#[derive(Debug, Clone)]
struct Define {
    params: Option<Vec<String>>,
    body: String,
}

static DEFINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*#\s*define\s+([A-Za-z_]\w*)(\(([^)]*)\))?\s*(.*)$").expect("valid regex")
});

fn defines_in(source: &Source) -> Vec<(String, Define)> {
    logical_lines(source)
        .into_iter()
        .filter_map(|(_, text, _)| {
            let captures = DEFINE.captures(&text)?;
            let params = captures.get(2).map(|_| {
                captures[3]
                    .split(',')
                    .map(|param| param.trim().to_owned())
                    .filter(|param| !param.is_empty())
                    .collect()
            });
            Some((
                captures[1].to_owned(),
                Define {
                    params,
                    body: captures[4].trim().to_owned(),
                },
            ))
        })
        .collect()
}

/// `source`'s lines with comments removed and continuations joined: the
/// 1-based number of each one's first line, its text, and the macro it
/// defines, if it is a `#define`.
fn logical_lines(source: &Source) -> Vec<(usize, String, Option<String>)> {
    let text = strip_comments(&source.text);
    let mut out = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (index, line) in text.lines().enumerate() {
        let (start, mut joined) = pending.take().unwrap_or((index + 1, String::new()));
        match line.strip_suffix('\\') {
            Some(head) => {
                joined.push_str(head);
                joined.push(' ');
                pending = Some((start, joined));
            }
            None => {
                joined.push_str(line);
                let name = DEFINE.captures(&joined).map(|c| c[1].to_owned());
                out.push((start, joined, name));
            }
        }
    }
    out
}

/// `text` with `/* */` and `//` comments blanked, keeping its newlines.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('/', Some('*')) => {
                chars.next();
                let mut last = ' ';
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                    }
                    if last == '*' && c == '/' {
                        break;
                    }
                    last = c;
                }
                out.push(' ');
            }
            ('/', Some('/')) => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// A cast to a pointer type: `(volatile uint32_t *)`, `(uint8_t volatile*)`,
/// `(UART_TypeDef *)`.
static POINTER_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\(\s*(?:(?:const|volatile|struct|unsigned|signed)\s+)*[A-Za-z_]\w*(?:\s+(?:const|volatile))*\s*\*+\s*(?:const|volatile)?\s*\)")
        .expect("valid regex")
});

/// The operand after each pointer cast in `text`: the parenthesized expression
/// or the token that follows it.
fn cast_operands(text: &str) -> Vec<String> {
    POINTER_CAST
        .find_iter(text)
        .filter_map(|cast| {
            let rest = text[cast.end()..].trim_start();
            if rest.starts_with('(') {
                let mut depth = 0usize;
                for (at, c) in rest.char_indices() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(rest[1..at].to_owned());
                            }
                        }
                        _ => {}
                    }
                }
                None
            } else {
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                (end > 0).then(|| rest[..end].to_owned())
            }
        })
        .collect()
}

/// The constant `expression` is, with the object-like macros of `defines`
/// substituted (a function-like macro's parameters read as 0), or `None` when
/// it is not one.
fn evaluate(expression: &str, defines: &BTreeMap<String, Define>, depth: usize) -> Option<u64> {
    if depth > 8 {
        return None;
    }
    let mut parser = Parser {
        tokens: tokens(expression)?,
        at: 0,
        defines,
        depth,
    };
    let value = parser.or()?;
    (parser.at == parser.tokens.len()).then_some(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Number(u64),
    Name(String),
    Op(&'static str),
    Open,
    Close,
}

fn tokens(expression: &str) -> Option<Vec<Token>> {
    let mut out = Vec::new();
    let bytes = expression.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let c = bytes[at] as char;
        if c.is_whitespace() {
            at += 1;
        } else if c.is_ascii_digit() {
            let end = expression[at..]
                .find(|c: char| !c.is_ascii_alphanumeric())
                .map_or(bytes.len(), |end| at + end);
            let literal = expression[at..end].trim_end_matches(['u', 'U', 'l', 'L']);
            let value = match literal.strip_prefix("0x").or(literal.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16).ok()?,
                None => literal.parse().ok()?,
            };
            out.push(Token::Number(value));
            at = end;
        } else if c.is_ascii_alphabetic() || c == '_' {
            let end = expression[at..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(bytes.len(), |end| at + end);
            out.push(Token::Name(expression[at..end].to_owned()));
            at = end;
        } else {
            let two = expression.get(at..at + 2);
            let (op, len) = match (two, c) {
                (Some("<<"), _) => ("<<", 2),
                (Some(">>"), _) => (">>", 2),
                (_, '+') => ("+", 1),
                (_, '-') => ("-", 1),
                (_, '*') => ("*", 1),
                (_, '|') => ("|", 1),
                (_, '(') => {
                    out.push(Token::Open);
                    at += 1;
                    continue;
                }
                (_, ')') => {
                    out.push(Token::Close);
                    at += 1;
                    continue;
                }
                _ => return None,
            };
            out.push(Token::Op(op));
            at += len;
        }
    }
    Some(out)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    at: usize,
    defines: &'a BTreeMap<String, Define>,
    depth: usize,
}

impl Parser<'_> {
    fn peek_op(&self, op: &'static str) -> bool {
        self.tokens.get(self.at) == Some(&Token::Op(op))
    }

    fn or(&mut self) -> Option<u64> {
        let mut value = self.shift()?;
        while self.peek_op("|") {
            self.at += 1;
            value |= self.shift()?;
        }
        Some(value)
    }

    fn shift(&mut self) -> Option<u64> {
        let mut value = self.sum()?;
        loop {
            if self.peek_op("<<") {
                self.at += 1;
                value = value.checked_shl(u32::try_from(self.sum()?).ok()?)?;
            } else if self.peek_op(">>") {
                self.at += 1;
                value = value.checked_shr(u32::try_from(self.sum()?).ok()?)?;
            } else {
                return Some(value);
            }
        }
    }

    fn sum(&mut self) -> Option<u64> {
        let mut value = self.product()?;
        loop {
            if self.peek_op("+") {
                self.at += 1;
                value = value.checked_add(self.product()?)?;
            } else if self.peek_op("-") {
                self.at += 1;
                value = value.checked_sub(self.product()?)?;
            } else {
                return Some(value);
            }
        }
    }

    fn product(&mut self) -> Option<u64> {
        let mut value = self.atom()?;
        while self.peek_op("*") {
            self.at += 1;
            value = value.checked_mul(self.atom()?)?;
        }
        Some(value)
    }

    fn atom(&mut self) -> Option<u64> {
        match self.tokens.get(self.at)?.clone() {
            Token::Number(value) => {
                self.at += 1;
                Some(value)
            }
            Token::Name(name) => {
                self.at += 1;
                let define = self.defines.get(&name)?;
                let body = match &define.params {
                    None => define.body.clone(),
                    // A register macro taking an offset: the device's base.
                    Some(params) => {
                        self.skip_arguments()?;
                        let mut body = define.body.clone();
                        for param in params {
                            body = replace_word(&body, param, "0");
                        }
                        body
                    }
                };
                // A body that is itself a cast of a constant (`((T *)BASE)`).
                let body = match cast_operands(&body).first() {
                    Some(operand) => operand.clone(),
                    None => body,
                };
                evaluate(&body, self.defines, self.depth + 1)
            }
            Token::Open => {
                self.at += 1;
                // `(uint32_t)` and other casts to an integer type.
                if let (Some(Token::Name(_)), Some(Token::Close)) =
                    (self.tokens.get(self.at), self.tokens.get(self.at + 1))
                {
                    let Some(Token::Name(name)) = self.tokens.get(self.at).cloned() else {
                        return None;
                    };
                    if !self.defines.contains_key(&name) {
                        self.at += 2;
                        return self.atom();
                    }
                }
                let value = self.or()?;
                (self.tokens.get(self.at) == Some(&Token::Close)).then(|| {
                    self.at += 1;
                    value
                })
            }
            _ => None,
        }
    }

    /// Step over a function-like macro's parenthesized arguments.
    fn skip_arguments(&mut self) -> Option<()> {
        if self.tokens.get(self.at) != Some(&Token::Open) {
            return Some(());
        }
        let mut depth = 0usize;
        while let Some(token) = self.tokens.get(self.at) {
            self.at += 1;
            match token {
                Token::Open => depth += 1,
                Token::Close => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(());
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// `text` with every whole-word `word` replaced by `with`.
fn replace_word(text: &str, word: &str, with: &str) -> String {
    let pattern = Regex::new(&format!(r"\b{}\b", regex::escape(word))).expect("escaped word");
    pattern.replace_all(text, with).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn source(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    const UART_H: &str = "#ifndef UART_H\n#define UART_H\n#include <stdint.h>\n\
                          #define PERIPH_BASE 0x40000000UL\n\
                          #define UART1_BASE (PERIPH_BASE + 0x11000) /* USART1 */\n\
                          #define UART_SR (*(volatile uint32_t *)(UART1_BASE + 0x00))\n\
                          #define UART_REG(off) \\\n  (*(volatile uint32_t *)(UART1_BASE + (off)))\n\
                          #endif\n";

    #[test]
    fn registers_are_read_through_macros_and_included_headers() {
        let dir = tempfile::tempdir().unwrap();
        source(dir.path(), "uart.h", UART_H);
        let c = source(
            dir.path(),
            "uart.c",
            "#include \"uart.h\"\nint ready(void) { return UART_SR & 0x80; }\n\
             int gpio(void) { return *(volatile unsigned int *)0x48000010; }\n\
             typedef struct { int x; } T;\nint cmsis(void) { return ((T *) (0x50000000u | 0x4))->x; }\n\
             int small(void) { return *(volatile char *)0x10; }\n",
        );
        let found = registers(&[c]);
        let addresses: Vec<u64> = found.iter().map(|r| r.address).collect();
        assert!(addresses.contains(&0x4001_1000), "{found:#?}");
        assert!(addresses.contains(&0x4800_0010), "{found:#?}");
        assert!(addresses.contains(&0x5000_0004), "{found:#?}");
        assert!(!addresses.contains(&0x10), "a small constant is no device");
        let sr = found
            .iter()
            .find(|r| r.name.as_deref() == Some("UART_SR"))
            .unwrap();
        assert_eq!(sr.line, 6);
        // A function-like register macro names its device's base.
        assert!(found.iter().any(|r| r.name.as_deref() == Some("UART_REG")));
    }

    fn segv(file: &Path, address: &str) -> serde_json::Value {
        json!({
            "rule_id": "BHF-223",
            "exception": {
                "message": format!("ERROR: AddressSanitizer: SEGV on unknown address {address} \
                                    (pc 0x5555 bp 0x7fff sp 0x7ffe T0)"),
                "stack": [{"function": "ready", "file": file, "line": 2}],
            },
        })
    }

    #[test]
    fn a_segv_on_a_named_register_is_a_register_fault() {
        let dir = tempfile::tempdir().unwrap();
        source(dir.path(), "uart.h", UART_H);
        let c = source(
            dir.path(),
            "uart.c",
            "#include \"uart.h\"\nint ready(void) { return UART_SR; }\n",
        );
        let fault = register_fault(&segv(&c, "0x000040011000")).expect("a register fault");
        assert_eq!(fault.register.address, 0x4001_1000);
        assert!(fault
            .describe(Some(dir.path()))
            .contains("UART_SR at 0x40011000 (uart.h:6)"));
        // Another register of the same device.
        assert!(register_fault(&segv(&c, "0x000040011004")).is_some());
        // A wild address, or NULL, is not one.
        assert!(register_fault(&segv(&c, "0x7ffd12345678")).is_none());
        assert!(register_fault(&segv(&c, "0x000000000000")).is_none());
    }

    #[test]
    fn integer_casts_and_shifts_evaluate() {
        let defines = BTreeMap::new();
        assert_eq!(
            evaluate("(uint32_t)0x40000000 + (1 << 12)", &defines, 0),
            Some(0x4000_1000)
        );
        assert_eq!(evaluate("0x4000 | 0x0010UL", &defines, 0), Some(0x4010));
        assert_eq!(evaluate("data + 1", &defines, 0), None);
    }
}
