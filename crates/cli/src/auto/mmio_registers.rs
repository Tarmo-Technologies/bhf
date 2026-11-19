// SPDX-License-Identifier: Apache-2.0

//! Device registers a target reads at fixed addresses. Firmware reaches a
//! peripheral through a pointer cast of a constant, usually inside a macro
//! (`#define UART_SR (*(volatile uint32_t *)(UART1_BASE + 0x00))`). On the host
//! nothing is mapped there, so the first read SEGVs: that is the missing device,
//! not an out-of-bounds read the input caused. [`register_fault`] finds such a
//! crash: its fault address lies on a register the crash path's sources name.

use std::collections::{BTreeMap, BTreeSet, HashSet};
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
    /// Whether the access is volatile: a `volatile` (or CMSIS `__IO`, `__I`,
    /// `__O`) qualified cast, or a cast to a struct whose members are, as a
    /// device register's always is. A plain `(void *)0x00100100` sentinel is
    /// not.
    pub(crate) volatile: bool,
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
/// Only a register access counts (#437): a volatile one, and no sentinel
/// ([`is_sentinel`]), the rule #341 maps device windows by. A fault on a
/// plain pointer constant (list.h's `LIST_POISON1`) keeps its own
/// classification.
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
        .filter(|register| {
            register.volatile && !is_sentinel(register.name.as_deref(), register.address)
        })
        .find(|register| on_device(fault, register.address))
        .map(|register| RegisterFault { fault, register })
}

/// Whether a register named `name` at `address` is a poison or sentinel
/// value rather than a device: list.h's `LIST_POISON1` and the fill patterns
/// allocators and debuggers use. Mapping one would turn the fault its
/// dereference is into a read of fuzz bytes.
pub(crate) fn is_sentinel(name: Option<&str>, address: u64) -> bool {
    const FILL_PATTERNS: &[u64] = &[
        0xdead_beef,
        0xdead_dead,
        0xdead_c0de,
        0xbaad_f00d,
        0xcafe_babe,
        0xfeed_face,
        0xfeee_feee,
        0xcccc_cccc,
        0xcdcd_cdcd,
        0xabab_abab,
        0xa5a5_a5a5,
        0x5a5a_5a5a,
    ];
    let named = name.is_some_and(|name| {
        let name = name.to_ascii_uppercase();
        ["POISON", "SENTINEL", "INVALID", "BOGUS"]
            .iter()
            .any(|word| name.contains(word))
    });
    named || FILL_PATTERNS.contains(&address)
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
    let scan = Scan::of(files);
    registers_in(&scan)
}

/// The sources one scan reads and the macros they define.
struct Scan {
    sources: Vec<Source>,
    defines: BTreeMap<String, Define>,
}

impl Scan {
    fn of(files: &[PathBuf]) -> Self {
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
        Self { sources, defines }
    }
}

fn registers_in(scan: &Scan) -> Vec<Register> {
    let Scan { sources, defines } = scan;
    let volatile = VolatileNames::of(scan);
    let mut out = Vec::new();
    for source in sources {
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
            for (cast, operand) in casts(&text) {
                if let Some(address) = evaluate(&operand, defines, 0)
                    .filter(|address| *address >= LOWEST_DEVICE_ADDRESS)
                {
                    out.push(Register {
                        address,
                        name: macro_name.clone(),
                        file: source.path.clone(),
                        line,
                        volatile: volatile.cast_is_volatile(&cast),
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
    casts(text)
        .into_iter()
        .map(|(_, operand)| operand)
        .collect()
}

/// Each pointer cast in `text` and the operand after it.
fn casts(text: &str) -> Vec<(String, String)> {
    POINTER_CAST
        .find_iter(text)
        .filter_map(|cast| {
            let operand = cast_operand(&text[cast.end()..])?;
            Some((cast.as_str().to_owned(), operand))
        })
        .collect()
}

/// The parenthesized expression or the token at the start of `rest`.
fn cast_operand(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    if !rest.starts_with('(') {
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        return (end > 0).then(|| rest[..end].to_owned());
    }
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

// ---------------------------------------------------------------------------
// What a target's code does with the registers (#341)
// ---------------------------------------------------------------------------

/// The qualifiers that make an access volatile: `volatile` and the CMSIS
/// register qualifiers. A macro the sources define as one of them counts too.
const VOLATILE_QUALIFIERS: &[&str] = &["volatile", "__IO", "__I", "__O", "__IOM", "__IM", "__OM"];

/// Cap on the functions one target's reach follows.
const MAX_REACHED_FUNCTIONS: usize = 256;
/// How deep a macro body is expanded when looking for register names.
const MAX_MACRO_DEPTH: usize = 8;

static WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").expect("valid regex"));

fn words(text: &str) -> impl Iterator<Item = &str> {
    WORD.find_iter(text).map(|word| word.as_str())
}

/// The words and type names that make a cast a volatile access.
struct VolatileNames {
    qualifiers: HashSet<String>,
    /// Typedefs and struct tags of volatile types or of structs with
    /// volatile members (a CMSIS `USART_TypeDef`).
    types: HashSet<String>,
}

static STRUCT_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(typedef\s+)?((?:[A-Za-z_]\w*\s+)*?)(?:struct|union)\s*([A-Za-z_]\w*)?\s*\{")
        .expect("valid regex")
});
static PLAIN_TYPEDEF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\btypedef\s+([^;{}]*?)\b([A-Za-z_]\w*)\s*;").expect("valid regex")
});

impl VolatileNames {
    fn of(scan: &Scan) -> Self {
        let mut qualifiers: HashSet<String> = VOLATILE_QUALIFIERS
            .iter()
            .map(|qualifier| (*qualifier).to_owned())
            .collect();
        // `#define __IO volatile`, `#define __I volatile const`.
        for (name, define) in &scan.defines {
            let body: Vec<&str> = words(&define.body).collect();
            if define.params.is_none()
                && body.iter().any(|word| qualifiers.contains(*word))
                && body
                    .iter()
                    .all(|word| *word == "const" || qualifiers.contains(*word))
            {
                qualifiers.insert(name.clone());
            }
        }
        let mut names = Self {
            qualifiers,
            types: HashSet::new(),
        };
        let texts: Vec<String> = scan
            .sources
            .iter()
            .map(|source| code_only(&source.text))
            .collect();
        // Twice, so a struct of volatile typedefs declared before them counts.
        for _ in 0..2 {
            for text in &texts {
                names.collect_types(text);
            }
        }
        names
    }

    fn is_volatile_word(&self, word: &str) -> bool {
        self.qualifiers.contains(word) || self.types.contains(word)
    }

    fn mentions_volatile(&self, text: &str) -> bool {
        words(text).any(|word| self.is_volatile_word(word))
    }

    /// Whether `cast` (`(volatile uint32_t *)`, `(UART_TypeDef *)`) is a
    /// volatile access.
    fn cast_is_volatile(&self, cast: &str) -> bool {
        self.mentions_volatile(cast)
    }

    fn collect_types(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let mut found = Vec::new();
        for open in STRUCT_OPEN.captures_iter(text) {
            let whole = open.get(0).expect("match");
            let Some(close) = matching_brace(bytes, whole.end() - 1) else {
                continue;
            };
            let body = &text[whole.end()..close];
            let qualified = open
                .get(2)
                .is_some_and(|prefix| self.mentions_volatile(prefix.as_str()));
            if !(qualified || self.mentions_volatile(body)) {
                continue;
            }
            if let Some(tag) = open.get(3) {
                found.push(tag.as_str().to_owned());
            }
            if open.get(1).is_some() {
                let rest = &text[close + 1..];
                let declarators = &rest[..rest.find(';').unwrap_or(rest.len())];
                found.extend(
                    words(declarators)
                        .filter(|word| !self.qualifiers.contains(*word) && *word != "const")
                        .map(str::to_owned),
                );
            }
        }
        for typedef in PLAIN_TYPEDEF.captures_iter(text) {
            if self.mentions_volatile(&typedef[1]) {
                found.push(typedef[2].to_owned());
            }
        }
        self.types.extend(found);
    }
}

/// `text` with comments, string and character literals and preprocessor
/// lines blanked, keeping every newline: the code a function parse reads.
fn code_only(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('/', Some('*')) => {
                chars.next();
                let mut last = ' ';
                for c in chars.by_ref() {
                    out.push(if c == '\n' { '\n' } else { ' ' });
                    if last == '*' && c == '/' {
                        break;
                    }
                    last = c;
                }
            }
            ('/', Some('/')) => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('"' | '\'', _) => {
                out.push(' ');
                let mut escaped = false;
                for inner in chars.by_ref() {
                    if inner == '\n' {
                        out.push('\n');
                        break;
                    }
                    out.push(' ');
                    if escaped {
                        escaped = false;
                    } else if inner == '\\' {
                        escaped = true;
                    } else if inner == c {
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    // Preprocessor lines, with their continuations.
    let mut blanked = String::with_capacity(out.len());
    let mut continued = false;
    for line in out.split_inclusive('\n') {
        let directive = continued || line.trim_start().starts_with('#');
        continued = directive && line.trim_end_matches('\n').ends_with('\\');
        if directive {
            blanked.extend(line.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
        } else {
            blanked.push_str(line);
        }
    }
    blanked
}

/// The index of the `}` closing the `{` at `open`.
fn matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// The index of the `(` opening the `)` at the end of `text`.
fn matching_open_paren(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (at, byte) in text.bytes().enumerate().rev() {
        match byte {
            b')' => depth += 1,
            b'(' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// The name of the function whose body opens right after `prefix`, when
/// `prefix` ends with a parameter list (`int f(int x)`, `f(void)
/// __attribute__((noinline))`).
fn function_name_before(prefix: &str) -> Option<String> {
    let mut head = prefix.trim_end();
    loop {
        if !head.ends_with(')') {
            return None;
        }
        let open = matching_open_paren(head)?;
        let before = head[..open].trim_end();
        let name_start = before
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |at| at + 1);
        let name = &before[name_start..];
        match name {
            "__attribute__" | "__declspec" => head = before[..name_start].trim_end(),
            "" | "if" | "while" | "for" | "switch" | "return" | "sizeof" | "do" | "else" => {
                return None
            }
            _ if name.starts_with(|c: char| c.is_ascii_digit()) => return None,
            _ => return Some(name.to_owned()),
        }
    }
}

/// A function definition in a scanned source.
struct Function {
    file: PathBuf,
    /// 1-based lines of its body's braces.
    first_line: usize,
    last_line: usize,
    /// Its body, as [`code_only`] leaves it.
    body: String,
}

impl Function {
    /// Whether `register` is a cast written in this function's body (not
    /// through a macro, which [`Reach::named`] finds by name).
    fn spells_out(&self, register: &Register) -> bool {
        register.name.is_none()
            && register.file == self.file
            && (self.first_line..=self.last_line).contains(&register.line)
    }
}

fn functions_in(source: &Source) -> Vec<(String, Function)> {
    let text = code_only(&source.text);
    let bytes = text.as_bytes();
    let line_of = |at: usize| 1 + bytes[..at].iter().filter(|b| **b == b'\n').count();
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'{' if depth == 0 => {
                let body_end = function_name_before(&text[..at])
                    .and_then(|name| Some((name, matching_brace(bytes, at)?)));
                if let Some((name, end)) = body_end {
                    out.push((
                        name,
                        Function {
                            file: source.path.clone(),
                            first_line: line_of(at),
                            last_line: line_of(end),
                            body: text[at..=end].to_owned(),
                        },
                    ));
                    at = end + 1;
                    continue;
                }
                depth += 1;
            }
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        at += 1;
    }
    out
}

static LOOP_HEAD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(while|for|if)\s*\(").expect("valid regex"));

/// The conditions in `body` that decide whether a loop goes round again:
/// `while (...)` (a `do ... while` too), the test of a `for (;;)`, and an
/// `if (...)` whose statement is `break`.
fn loop_conditions(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for head in LOOP_HEAD.captures_iter(body) {
        let whole = head.get(0).expect("match");
        let open = whole.end() - 1;
        let Some(condition) = cast_operand(&body[open..]) else {
            continue;
        };
        match &head[1] {
            "while" => out.push(condition),
            "for" => {
                let parts: Vec<&str> = condition.split(';').collect();
                if parts.len() == 3 {
                    out.push(parts[1].to_owned());
                }
            }
            _ => {
                let after = body[open + condition.len() + 2..].trim_start();
                let after = after.strip_prefix('{').unwrap_or(after).trim_start();
                let breaks = after.strip_prefix("break").is_some_and(|rest| {
                    !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_')
                });
                if breaks {
                    out.push(condition);
                }
            }
        }
    }
    out
}

/// The device registers a target's code accesses at fixed addresses
/// through a volatile access, and the addresses of those it polls.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DeviceAccess {
    /// The registers `function` and the functions it calls (in the scanned
    /// sources) read or write.
    pub(crate) accessed: Vec<Register>,
    /// The register addresses a loop condition there reads: a status poll
    /// (`while (!(UART_SR & 0x80)) {}`) that a register holding one value
    /// for the whole run would spin on.
    pub(crate) polled: Vec<u64>,
}

/// What `function`, defined in `files` or the quoted headers they include,
/// does with device registers. Nothing for a function the scan does not
/// find. A sentinel cast (`(void *)0x00100100`) is no register access.
pub(crate) fn device_access(files: &[PathBuf], function: &str) -> DeviceAccess {
    let scan = Scan::of(files);
    let registers: Vec<Register> = registers_in(&scan)
        .into_iter()
        .filter(|register| register.volatile)
        .collect();
    if registers.is_empty() {
        return DeviceAccess::default();
    }
    let mut functions: BTreeMap<String, Function> = BTreeMap::new();
    for source in &scan.sources {
        for (name, function) in functions_in(source) {
            functions.entry(name).or_insert(function);
        }
    }
    if !functions.contains_key(function) {
        return DeviceAccess::default();
    }
    let reach = Reach {
        scan: &scan,
        registers: &registers,
        functions: &functions,
        volatile: VolatileNames::of(&scan),
    };
    // The functions the target reaches, in call order from it.
    let mut reached = vec![function.to_owned()];
    let mut seen: HashSet<String> = reached.iter().cloned().collect();
    let mut next = 0;
    while next < reached.len() && reached.len() < MAX_REACHED_FUNCTIONS {
        let body = &functions[&reached[next]].body;
        let mut called = Vec::new();
        reach.called_functions(body, 0, &mut HashSet::new(), &mut called);
        for name in called {
            if seen.insert(name.clone()) {
                reached.push(name);
            }
        }
        next += 1;
    }
    let mut accessed = BTreeSet::new();
    let mut polled = BTreeSet::new();
    for name in &reached {
        let function = &functions[name];
        accessed.extend(reach.named(&function.body));
        accessed
            .extend((0..registers.len()).filter(|index| function.spells_out(&registers[*index])));
        for condition in loop_conditions(&function.body) {
            polled.extend(reach.polled_by(&condition));
        }
    }
    DeviceAccess {
        accessed: accessed
            .into_iter()
            .map(|index| registers[index].clone())
            .collect(),
        polled: polled.into_iter().collect(),
    }
}

struct Reach<'a> {
    scan: &'a Scan,
    /// The volatile register accesses of the scanned sources.
    registers: &'a [Register],
    functions: &'a BTreeMap<String, Function>,
    volatile: VolatileNames,
}

impl Reach<'_> {
    /// The functions `text` calls, through the macros it uses too.
    fn called_functions(
        &self,
        text: &str,
        depth: usize,
        macros: &mut HashSet<String>,
        out: &mut Vec<String>,
    ) {
        for word in words(text) {
            if self.functions.contains_key(word) {
                out.push(word.to_owned());
            }
            if let Some(define) = self.scan.defines.get(word) {
                if depth < MAX_MACRO_DEPTH && macros.insert(word.to_owned()) {
                    self.called_functions(&define.body, depth + 1, macros, out);
                }
            }
        }
    }

    /// The registers `text` names, directly or through the macros it uses.
    fn named(&self, text: &str) -> BTreeSet<usize> {
        let mut names = HashSet::new();
        self.expand(text, 0, &mut names);
        self.registers
            .iter()
            .enumerate()
            .filter(|(_, register)| {
                register
                    .name
                    .as_deref()
                    .is_some_and(|name| names.contains(name))
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// Every word `text` holds, with the bodies of the macros it uses.
    fn expand(&self, text: &str, depth: usize, out: &mut HashSet<String>) {
        for word in words(text) {
            if !out.insert(word.to_owned()) {
                continue;
            }
            if let Some(define) = self.scan.defines.get(word) {
                if depth < MAX_MACRO_DEPTH {
                    self.expand(&define.body, depth + 1, out);
                }
            }
        }
    }

    /// The register addresses `condition` reads: the registers it names,
    /// the volatile casts of constants in it, and the registers of the
    /// functions it calls.
    fn polled_by(&self, condition: &str) -> BTreeSet<u64> {
        let mut out: BTreeSet<u64> = self
            .named(condition)
            .into_iter()
            .map(|index| self.registers[index].address)
            .collect();
        for (cast, operand) in casts(condition) {
            if self.volatile.cast_is_volatile(&cast) {
                if let Some(address) = evaluate(&operand, &self.scan.defines, 0)
                    .filter(|address| *address >= LOWEST_DEVICE_ADDRESS)
                {
                    out.insert(address);
                }
            }
        }
        let mut called = Vec::new();
        self.called_functions(condition, 0, &mut HashSet::new(), &mut called);
        let mut seen = HashSet::new();
        while let Some(name) = called.pop() {
            if seen.len() >= MAX_REACHED_FUNCTIONS || !seen.insert(name.clone()) {
                continue;
            }
            let function = &self.functions[&name];
            out.extend(
                self.named(&function.body)
                    .into_iter()
                    .map(|index| self.registers[index].address),
            );
            out.extend(
                self.registers
                    .iter()
                    .filter(|register| function.spells_out(register))
                    .map(|register| register.address),
            );
            self.called_functions(&function.body, 0, &mut HashSet::new(), &mut called);
        }
        out
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

    /// #437: a fault on a constant that is no register access keeps the
    /// crash's own classification. A plain pointer cast (list.h's
    /// `LIST_POISON1`, here on a device-range address) and a named sentinel
    /// are not missing devices; a volatile register on the same page is.
    #[test]
    fn only_a_register_access_is_a_missing_device() {
        let dir = tempfile::tempdir().unwrap();
        let c = source(
            dir.path(),
            "list.c",
            "#define LIST_POISON1 ((void *) 0x40100100)\n\
             #define BAD_SLOT (*(volatile unsigned *)0x40200000u)\n\
             #define TRACE_POISON (*(volatile unsigned *)0x40300000u)\n\
             #define DEV_SR (*(volatile unsigned *)0x40400000u)\n\
             struct node { struct node *next; };\n\
             int walk(struct node *n) { n->next = LIST_POISON1; return BAD_SLOT + TRACE_POISON + DEV_SR; }\n",
        );
        assert!(
            register_fault(&segv(&c, "0x000040100100")).is_none(),
            "a plain pointer constant"
        );
        assert!(
            register_fault(&segv(&c, "0x000040300000")).is_none(),
            "a named sentinel"
        );
        let fault = register_fault(&segv(&c, "0x000040400000")).expect("a volatile register");
        assert_eq!(fault.register.name.as_deref(), Some("DEV_SR"));
    }

    /// #341: only a volatile access is a register: a volatile cast, a CMSIS
    /// qualifier, or a struct whose members are volatile. A plain pointer
    /// cast of a constant (list.h's poison values) is not.
    #[test]
    fn a_register_access_is_volatile_and_a_sentinel_cast_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let c = source(
            dir.path(),
            "dev.c",
            "#define __IO volatile\n\
             typedef struct { __IO unsigned SR; __IO unsigned DR; } USART_TypeDef;\n\
             typedef struct { unsigned a; unsigned b; } plain_t;\n\
             typedef volatile unsigned reg32_t;\n\
             #define USART1 ((USART_TypeDef *) 0x40011000u)\n\
             #define TABLE ((plain_t *) 0x40022000u)\n\
             #define CTRL (*(reg32_t *) 0x40033000u)\n\
             #define RAW (*(volatile unsigned *) 0x40044000u)\n\
             #define LIST_POISON1 ((void *) 0x00100100)\n\
             int f(void) { return (int)(USART1->SR + TABLE->a + CTRL + RAW); }\n",
        );
        let volatile: Vec<(u64, bool)> = registers(&[c])
            .into_iter()
            .map(|register| (register.address, register.volatile))
            .collect();
        assert_eq!(
            volatile,
            [
                (0x4001_1000, true),
                (0x4002_2000, false),
                (0x4003_3000, true),
                (0x4004_4000, true),
                (0x0010_0100, false),
            ]
        );
    }

    /// #341: the registers a target's code reaches (through the functions it
    /// calls and the macros it uses), and the ones a loop condition polls.
    #[test]
    fn a_targets_reach_and_its_polls_are_found() {
        let dir = tempfile::tempdir().unwrap();
        source(dir.path(), "uart.h", UART_H);
        let c = source(
            dir.path(),
            "uart.c",
            "#include \"uart.h\"\n\
             #define GPIO (*(volatile unsigned *)0x48000010u)\n\
             static const char *banner = \"while (UART_SR) { not code }\";\n\
             static void wait_ready(void) { while (!(UART_SR & 0x80)) {} }\n\
             static int level(void) { return (int)GPIO; }\n\
             int send(int c) { wait_ready(); UART_REG(4) = (unsigned)c; return level(); }\n\
             int direct(void) { return *(volatile unsigned *)0x50000004u; }\n\
             int pure(int x) { return x * 2; }\n",
        );
        let access = device_access(std::slice::from_ref(&c), "send");
        let mut names: Vec<&str> = access
            .accessed
            .iter()
            .filter_map(|register| register.name.as_deref())
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["GPIO", "UART_REG", "UART_SR"]);
        assert_eq!(access.polled, [0x4001_1000]);

        let direct = device_access(std::slice::from_ref(&c), "direct");
        let addresses: Vec<u64> = direct.accessed.iter().map(|r| r.address).collect();
        assert_eq!(addresses, [0x5000_0004]);
        assert!(direct.polled.is_empty());

        assert_eq!(
            device_access(std::slice::from_ref(&c), "pure"),
            DeviceAccess::default()
        );
        assert_eq!(
            device_access(std::slice::from_ref(&c), "missing"),
            DeviceAccess::default()
        );
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
