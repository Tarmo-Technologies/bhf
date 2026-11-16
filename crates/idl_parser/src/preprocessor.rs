// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{IdlParseError, Span};

const MAX_INCLUDE_DEPTH: usize = 32;

pub fn preprocess_idl(source: &str) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor::default();
    preprocessor.process_source(source, None)
}

pub fn preprocess_idl_with_defines(
    source: &str,
    defines: &[(String, String)],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor::with_defines(defines);
    preprocessor.process_source(source, None)
}

pub fn preprocess_idl_file(path: &Path) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor::default();
    preprocessor.process_file(path, 0)
}

pub fn preprocess_idl_file_with_defines(
    path: &Path,
    defines: &[(String, String)],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor::with_defines(defines);
    preprocessor.process_file(path, 0)
}

pub fn preprocess_idl_file_with_include_dirs(
    path: &Path,
    include_dirs: &[PathBuf],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor {
        include_dirs: include_dirs.to_vec(),
        recovery: RecoveryMode::Strict,
        ..Preprocessor::default()
    };
    preprocessor.process_file(path, 0)
}

pub fn preprocess_idl_file_recovering_with_include_dirs(
    path: &Path,
    include_dirs: &[PathBuf],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor {
        include_dirs: include_dirs.to_vec(),
        recovery: RecoveryMode::Recover,
        ..Preprocessor::default()
    };
    preprocessor.process_file(path, 0)
}

pub fn preprocess_idl_file_recovering_with_options(
    path: &Path,
    defines: &[(String, String)],
    include_dirs: &[PathBuf],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor {
        defines: defines.iter().cloned().collect(),
        include_dirs: include_dirs.to_vec(),
        recovery: RecoveryMode::Recover,
        ..Preprocessor::default()
    };
    preprocessor.process_file(path, 0)
}

/// Run the CPP-lite preprocessor over a C/C++ translation unit before tree-sitter
/// (#460): object-like `#define` expansion and `#ifdef`/`#ifndef`/`#if` guard
/// resolution, in RECOVERING mode so an unknown / function-like / unsupported
/// directive passes through rather than aborting discovery. `#include` is not
/// expanded here (no include dirs are consulted). Infallible: on a preprocessing
/// error the original source is returned unchanged, so the caller can always fall
/// back to the raw tree-sitter parse. The IDL preprocessor's directive handling is
/// language-agnostic, so the C/C++ discovery lane reuses it.
pub fn preprocess_c_like(source: &str, defines: &[(String, String)]) -> String {
    let mut preprocessor = Preprocessor {
        defines: defines.iter().cloned().collect(),
        recovery: RecoveryMode::Recover,
        ..Preprocessor::default()
    };
    preprocessor
        .process_source(source, None)
        .unwrap_or_else(|_| source.to_owned())
}

/// Maps a line number reported from a PREPROCESSED C/C++ translation unit back to
/// the line in the ORIGINAL source it came from (§27.6). [`preprocess_c_like`]
/// resolves `#ifdef` branches and expands object-like macros, which drops/folds
/// lines, so a target/finding location parsed out of the preprocessed text would be
/// shifted; this map translates it back so reported locations stay accurate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineMap {
    /// `original[i]` = 1-based original source line for preprocessed output line
    /// `i + 1` (1-based). Empty => identity (used on the raw-source fallback).
    original: Vec<usize>,
}

impl LineMap {
    /// Translate a 1-based PREPROCESSED line number to its 1-based ORIGINAL source
    /// line. Out-of-range inputs (and the identity/empty map) return the line
    /// unchanged, so a caller can always translate safely.
    pub fn to_original(&self, preprocessed_line: u32) -> u32 {
        if preprocessed_line == 0 {
            return preprocessed_line;
        }
        self.original
            .get(preprocessed_line as usize - 1)
            .map(|line| *line as u32)
            .unwrap_or(preprocessed_line)
    }

    /// An identity map (every line maps to itself) — what discovery uses when
    /// preprocessing is disabled or fell back to the raw source.
    pub fn identity() -> Self {
        Self::default()
    }
}

/// Run the recovering CPP-lite preprocessor over a C/C++ translation unit AND
/// return a [`LineMap`] translating preprocessed-line numbers back to original
/// source lines (§27.6). `#include` directives are passed through verbatim (in-tree
/// header expansion is a further increment). Infallible: on any preprocessing error
/// the original source and an identity map are returned, so the caller always has a
/// parseable text plus a correct (here, trivial) translation.
pub fn preprocess_c_like_with_line_map(
    source: &str,
    defines: &[(String, String)],
) -> (String, LineMap) {
    let mut preprocessor = Preprocessor {
        defines: defines.iter().cloned().collect(),
        recovery: RecoveryMode::Recover,
        passthrough_includes: true,
        track_lines: true,
        keep_unknown_branches: true,
        ..Preprocessor::default()
    };
    match preprocessor.process_source(source, None) {
        Ok(output) => (
            output,
            LineMap {
                original: std::mem::take(&mut preprocessor.line_map),
            },
        ),
        // Fall back to the raw source with an identity map so locations are exact.
        Err(_) => (source.to_owned(), LineMap::identity()),
    }
}

#[derive(Debug, Default)]
struct Preprocessor {
    defines: HashMap<String, String>,
    /// In recovering mode, a `#if`/`#elif` it cannot evaluate keeps every
    /// branch of the chain (C/C++ discovery: a compiled-in function must not
    /// vanish) instead of counting the branch as inactive (IDL).
    keep_unknown_branches: bool,
    frames: Vec<ConditionalFrame>,
    include_stack: Vec<PathBuf>,
    include_dirs: Vec<PathBuf>,
    recovery: RecoveryMode,
    /// C/C++ discovery mode (§27.6): keep `#include` directives verbatim instead of
    /// erroring (no `current_file` to resolve against) — expanding in-tree headers
    /// is a further increment. With this set the output stays one line per source
    /// logical line, so the line map below is exact.
    passthrough_includes: bool,
    /// Accumulate, per emitted output line, the 1-based ORIGINAL source line it came
    /// from (§27.6 line map). Only populated when `track_lines` is set, so the IDL
    /// paths pay nothing. Aligned by construction: `process_source` emits exactly one
    /// output line per source logical line and pushes one entry here per iteration.
    track_lines: bool,
    line_map: Vec<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum RecoveryMode {
    #[default]
    Strict,
    Recover,
}

#[derive(Debug, Clone, Copy)]
struct ConditionalFrame {
    parent_active: bool,
    condition_active: bool,
    seen_else: bool,
    /// A branch of this `#if`/`#elif` chain was taken, so later `#elif`s
    /// and the `#else` are not.
    taken: bool,
    /// A condition of this chain could not be evaluated (recovering mode):
    /// every later branch is kept too, since any of them may be compiled in.
    unknown: bool,
}

impl ConditionalFrame {
    fn decided(parent_active: bool, condition_active: bool) -> Self {
        Self {
            parent_active,
            condition_active,
            seen_else: false,
            taken: condition_active,
            unknown: false,
        }
    }
}

impl Preprocessor {
    fn with_defines(defines: &[(String, String)]) -> Self {
        Self {
            defines: defines.iter().cloned().collect(),
            keep_unknown_branches: false,
            frames: Vec::new(),
            include_stack: Vec::new(),
            include_dirs: Vec::new(),
            recovery: RecoveryMode::Strict,
            passthrough_includes: false,
            track_lines: false,
            line_map: Vec::new(),
        }
    }

    fn process_file(&mut self, path: &Path, depth: usize) -> Result<String, IdlParseError> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(IdlParseError::new(
                "maximum include depth exceeded",
                Span::start(),
            ));
        }

        let normalized = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if self.include_stack.iter().any(|entry| entry == &normalized) {
            return Err(IdlParseError::new(
                format!("include cycle involving {}", normalized.display()),
                Span::start(),
            ));
        }

        let source = std::fs::read_to_string(&normalized).map_err(|error| {
            IdlParseError::new(format!("read {}: {error}", path.display()), Span::start())
        })?;

        self.include_stack.push(normalized.clone());
        let result = self.process_source(&source, Some(&normalized));
        self.include_stack.pop();
        result
    }

    fn process_source(
        &mut self,
        source: &str,
        current_file: Option<&Path>,
    ) -> Result<String, IdlParseError> {
        let frame_depth_at_entry = self.frames.len();
        let mut output = String::new();
        for (line_no, line, has_newline) in logical_lines(source) {
            // §27.6 line map: each loop iteration emits exactly ONE output line
            // (content, possibly empty, then an optional '\n'), so recording the
            // original source line here, once per iteration, keeps `line_map[i]`
            // aligned with output line `i + 1`. In `passthrough_includes` mode no
            // `#include` recurses, so this stays linear (one entry per output line).
            if self.track_lines {
                self.line_map.push(line_no);
            }
            if self.is_directive(&line) {
                if let Some(expansion) =
                    self.process_directive(&line, line_no, current_file, frame_depth_at_entry)?
                {
                    output.push_str(&expansion);
                }
                if has_newline {
                    output.push('\n');
                }
            } else if self.is_active() {
                output.push_str(&self.expand_line(&line));
                if has_newline {
                    output.push('\n');
                }
            } else {
                if has_newline {
                    output.push('\n');
                }
            }
        }

        if self.frames.len() > frame_depth_at_entry {
            self.frames.truncate(frame_depth_at_entry);
            return Err(IdlParseError::new(
                "missing #endif",
                line_span(source.lines().count().max(1), 1),
            ));
        }

        Ok(output)
    }

    fn is_directive(&self, line: &str) -> bool {
        line.trim_start().starts_with('#')
    }

    fn process_directive(
        &mut self,
        line: &str,
        line_no: usize,
        current_file: Option<&Path>,
        frame_depth_at_entry: usize,
    ) -> Result<Option<String>, IdlParseError> {
        let trimmed = line.trim_start();
        let rest = trimmed.strip_prefix('#').expect("directive starts with #");
        let rest = rest.trim_start();
        let (directive, payload) = split_directive(rest).ok_or_else(|| {
            IdlParseError::new("expected preprocessor directive", line_span(line_no, 1))
        })?;

        match directive {
            "define" => {
                if self.is_active() {
                    if let Err(error) = self.define_macro(payload, line_no) {
                        if self.recovery == RecoveryMode::Recover {
                            return Ok(Some(warning_pragma(format!(
                                "unsupported macro definition ignored at line {line_no}: {}",
                                error.message
                            ))));
                        }
                        return Err(error);
                    }
                }
                Ok(None)
            }
            "undef" => {
                if self.is_active() {
                    let name = parse_directive_identifier(payload, line_no)?;
                    self.defines.remove(name);
                }
                Ok(None)
            }
            "ifdef" => {
                let name = parse_directive_identifier(payload, line_no)?;
                let parent_active = self.is_active();
                self.frames.push(ConditionalFrame::decided(
                    parent_active,
                    self.defines.contains_key(name),
                ));
                Ok(None)
            }
            "ifndef" => {
                let name = parse_directive_identifier(payload, line_no)?;
                let parent_active = self.is_active();
                self.frames.push(ConditionalFrame::decided(
                    parent_active,
                    !self.defines.contains_key(name),
                ));
                Ok(None)
            }
            "if" => {
                let parent_active = self.is_active();
                if !parent_active {
                    self.frames.push(ConditionalFrame::decided(false, false));
                    return Ok(None);
                }
                match eval_if_expression(strip_trailing_comment(payload), &self.defines) {
                    Ok(active) => {
                        self.frames
                            .push(ConditionalFrame::decided(parent_active, active));
                        Ok(None)
                    }
                    Err(error) if self.recovery == RecoveryMode::Recover => {
                        let keep = self.keep_unknown_branches;
                        self.frames.push(ConditionalFrame {
                            parent_active,
                            condition_active: keep,
                            seen_else: false,
                            taken: false,
                            unknown: keep,
                        });
                        Ok(Some(warning_pragma(if keep {
                            format!(
                                "#if expression not evaluated at line {line_no}, every branch kept: {error}"
                            )
                        } else {
                            format!(
                                "unsupported #if expression treated as inactive at line {line_no}: {error}"
                            )
                        })))
                    }
                    Err(error) => Err(IdlParseError::new(error, line_span(line_no, 1))),
                }
            }
            "elif" => {
                if self.frames.len() == frame_depth_at_entry {
                    return Err(IdlParseError::new("unmatched #elif", line_span(line_no, 1)));
                }
                let recovering = self.recovery == RecoveryMode::Recover;
                let keep = self.keep_unknown_branches;
                let defines = &self.defines;
                let frame = self
                    .frames
                    .last_mut()
                    .expect("frame exists above entry depth");
                if frame.seen_else {
                    return Err(IdlParseError::new(
                        "#elif after #else",
                        line_span(line_no, 1),
                    ));
                }
                if !frame.parent_active || (frame.taken && !frame.unknown) {
                    frame.condition_active = false;
                    return Ok(None);
                }
                if frame.unknown {
                    frame.condition_active = true;
                    return Ok(None);
                }
                match eval_if_expression(strip_trailing_comment(payload), defines) {
                    Ok(active) => {
                        frame.condition_active = active;
                        frame.taken = active;
                        Ok(None)
                    }
                    Err(error) if recovering => {
                        frame.condition_active = keep;
                        frame.unknown = keep;
                        Ok(Some(warning_pragma(if keep {
                            format!(
                                "#elif expression not evaluated at line {line_no}, every branch kept: {error}"
                            )
                        } else {
                            format!(
                                "unsupported #elif expression treated as inactive at line {line_no}: {error}"
                            )
                        })))
                    }
                    Err(error) => Err(IdlParseError::new(error, line_span(line_no, 1))),
                }
            }
            "else" => {
                if !strip_trailing_comment(payload).trim().is_empty() {
                    return Err(IdlParseError::new(
                        "#else does not take arguments",
                        line_span(line_no, 1),
                    ));
                }
                if self.frames.len() == frame_depth_at_entry {
                    return Err(IdlParseError::new("unmatched #else", line_span(line_no, 1)));
                }
                let frame = self
                    .frames
                    .last_mut()
                    .expect("frame exists above entry depth");
                if frame.seen_else {
                    return Err(IdlParseError::new("duplicate #else", line_span(line_no, 1)));
                }
                frame.seen_else = true;
                frame.condition_active = frame.unknown || !frame.taken;
                Ok(None)
            }
            "endif" => {
                if !strip_trailing_comment(payload).trim().is_empty() {
                    return Err(IdlParseError::new(
                        "#endif does not take arguments",
                        line_span(line_no, 1),
                    ));
                }
                if self.frames.len() == frame_depth_at_entry {
                    return Err(IdlParseError::new(
                        "unmatched #endif",
                        line_span(line_no, 1),
                    ));
                }
                self.frames.pop();
                Ok(None)
            }
            "include" => {
                // §27.6 C/C++ discovery: keep the directive verbatim in an active
                // region (dropped in an inactive one) rather than resolving it —
                // there is no `current_file`, and in-tree header expansion is a
                // further increment. Pass-through keeps the line map 1:1; tree-sitter
                // simply ignores the `#include` line.
                if self.passthrough_includes {
                    return Ok(self.is_active().then(|| trimmed.to_owned()));
                }
                if !self.is_active() {
                    return Ok(None);
                }
                let current_file = current_file.ok_or_else(|| {
                    IdlParseError::new("#include requires parse_idl_file", line_span(line_no, 1))
                })?;
                let include = parse_include(payload, line_no)?;
                let resolved = match self.resolve_include(current_file, &include, line_no) {
                    Ok(resolved) => resolved,
                    Err(error) if self.recovery == RecoveryMode::Recover => {
                        return Ok(Some(warning_pragma(error.to_string())));
                    }
                    Err(error) => return Err(error),
                };
                self.process_file(&resolved, self.include_stack.len())
                    .map(Some)
            }
            "pragma" => {
                if self.is_active() {
                    Ok(Some(trimmed.to_owned()))
                } else {
                    Ok(None)
                }
            }
            _ if self.recovery == RecoveryMode::Recover => Ok(Some(warning_pragma(format!(
                "unsupported directive '#{directive}' ignored at line {line_no}"
            )))),
            _ => Err(IdlParseError::new(
                format!("unsupported directive '#{directive}'"),
                line_span(line_no, 1),
            )),
        }
    }

    fn define_macro(&mut self, payload: &str, line_no: usize) -> Result<(), IdlParseError> {
        let payload = payload.trim_start();
        let (name, consumed) = read_identifier(payload).ok_or_else(|| {
            IdlParseError::new("expected macro name after #define", line_span(line_no, 1))
        })?;
        let replacement = &payload[consumed..];
        if replacement.starts_with('(') {
            return Err(IdlParseError::new(
                "function-like macros are unsupported",
                line_span(line_no, 1),
            ));
        }
        self.defines
            .insert(name.to_owned(), replacement.trim_start().to_owned());
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.frames
            .last()
            .is_none_or(|frame| frame.parent_active && frame.condition_active)
    }

    fn expand_line(&self, line: &str) -> String {
        let mut output = String::with_capacity(line.len());
        let mut chars = line.char_indices().peekable();

        while let Some((_, ch)) = chars.next() {
            if ch == '"' || ch == '\'' {
                output.push(ch);
                let quote = ch;
                let mut escaped = false;
                for (_, literal_ch) in chars.by_ref() {
                    output.push(literal_ch);
                    if escaped {
                        escaped = false;
                    } else if literal_ch == '\\' {
                        escaped = true;
                    } else if literal_ch == quote {
                        break;
                    }
                }
            } else if is_identifier_start(ch) {
                let mut ident = String::new();
                ident.push(ch);
                while let Some((_, next)) = chars.peek().copied() {
                    if is_identifier_continue(next) {
                        ident.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(replacement) = self.defines.get(&ident) {
                    output.push_str(replacement);
                } else {
                    output.push_str(&ident);
                }
            } else {
                output.push(ch);
            }
        }

        output
    }

    fn resolve_include(
        &self,
        current_file: &Path,
        include: &IncludePath,
        line_no: usize,
    ) -> Result<PathBuf, IdlParseError> {
        let mut candidates = Vec::new();
        if matches!(include.kind, IncludeKind::Quoted) {
            let include_root = current_file.parent().unwrap_or_else(|| Path::new("."));
            candidates.push(include_root.join(&include.path));
        }
        candidates.extend(self.include_dirs.iter().map(|dir| dir.join(&include.path)));

        for candidate in &candidates {
            if candidate.is_file() {
                return Ok(candidate.clone());
            }
        }

        if matches!(include.kind, IncludeKind::Angle) && self.include_dirs.is_empty() {
            return Err(IdlParseError::new(
                format!(
                    "include <{}> requires at least one configured IDL include directory",
                    include.path
                ),
                line_span(line_no, 1),
            ));
        }

        let searched = candidates
            .iter()
            .map(|candidate| candidate.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Err(IdlParseError::new(
            format!("include '{}' not found; searched {searched}", include.path),
            line_span(line_no, 1),
        ))
    }
}

fn logical_lines(source: &str) -> Vec<(usize, String, bool)> {
    let mut lines = Vec::new();
    let mut continued = String::new();
    let mut continued_start = 1;
    let mut in_continuation = false;
    let mut last_has_newline = false;

    for (index, raw_line) in source.split_inclusive('\n').enumerate() {
        let line_no = index + 1;
        let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
        let has_newline = raw_line.ends_with('\n');
        let trimmed = line.trim_end();
        let continues = trimmed.ends_with('\\');
        let segment = if continues {
            let slash = line.rfind('\\').expect("continued line has backslash");
            line[..slash].trim_end()
        } else {
            line
        };

        if in_continuation {
            continued.push_str(segment);
        } else if continues {
            continued_start = line_no;
            continued.push_str(segment);
        } else {
            lines.push((line_no, line.to_owned(), has_newline));
            continue;
        }

        last_has_newline = has_newline;
        if continues {
            continued.push(' ');
            in_continuation = true;
        } else {
            lines.push((continued_start, std::mem::take(&mut continued), has_newline));
            in_continuation = false;
        }
    }

    if in_continuation {
        lines.push((continued_start, continued, last_has_newline));
    }

    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncludeKind {
    Quoted,
    Angle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncludePath {
    kind: IncludeKind,
    path: String,
}

fn split_directive(rest: &str) -> Option<(&str, &str)> {
    let (directive, consumed) = read_identifier(rest)?;
    Some((directive, &rest[consumed..]))
}

fn parse_directive_identifier(payload: &str, line_no: usize) -> Result<&str, IdlParseError> {
    let payload = payload.trim_start();
    let (name, consumed) = read_identifier(payload).ok_or_else(|| {
        IdlParseError::new(
            "expected identifier in preprocessor directive",
            line_span(line_no, 1),
        )
    })?;
    if !strip_trailing_comment(&payload[consumed..])
        .trim()
        .is_empty()
    {
        return Err(IdlParseError::new(
            "unexpected trailing tokens in preprocessor directive",
            line_span(line_no, 1),
        ));
    }
    Ok(name)
}

fn parse_include(payload: &str, line_no: usize) -> Result<IncludePath, IdlParseError> {
    let payload = strip_trailing_comment(payload).trim();
    if let Some(path) = parse_delimited_include(payload, '"', line_no)? {
        return Ok(IncludePath {
            kind: IncludeKind::Quoted,
            path,
        });
    }
    if let Some(path) = parse_delimited_include(payload, '<', line_no)? {
        return Ok(IncludePath {
            kind: IncludeKind::Angle,
            path,
        });
    }
    Err(IdlParseError::new(
        "expected quoted or angle-bracket include path",
        line_span(line_no, 1),
    ))
}

fn parse_delimited_include(
    payload: &str,
    opener: char,
    line_no: usize,
) -> Result<Option<String>, IdlParseError> {
    let closer = if opener == '<' { '>' } else { opener };
    let Some(rest) = payload.strip_prefix(opener) else {
        return Ok(None);
    };
    let Some(end) = rest.find(closer) else {
        return Err(IdlParseError::new(
            "unterminated include path",
            line_span(line_no, 1),
        ));
    };
    let include_path = &rest[..end];
    if !strip_trailing_comment(&rest[end + closer.len_utf8()..])
        .trim()
        .is_empty()
    {
        return Err(IdlParseError::new(
            "unexpected trailing tokens after include path",
            line_span(line_no, 1),
        ));
    }
    if include_path.is_empty() {
        return Err(IdlParseError::new(
            "empty include path",
            line_span(line_no, 1),
        ));
    }
    Ok(Some(include_path.to_owned()))
}

fn strip_trailing_comment(payload: &str) -> &str {
    let mut chars = payload.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '"' | '\'' => {
                let quote = ch;
                let mut escaped = false;
                for (_, literal_ch) in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if literal_ch == '\\' {
                        escaped = true;
                    } else if literal_ch == quote {
                        break;
                    }
                }
            }
            '/' => match chars.peek().copied() {
                Some((_, '/')) | Some((_, '*')) => return &payload[..index],
                _ => {}
            },
            _ => {}
        }
    }
    payload
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExprToken {
    Number(i64),
    Ident(String),
    Defined,
    /// An operator or punctuator: `! ~ * / % + - << >> < <= > >= == != & ^ | && || ? : ( )`.
    Op(&'static str),
}

/// The value of a C `#if` expression: an integer, with `defined`, every
/// arithmetic, shift, comparison, bitwise and logical operator, `?:`,
/// integer and character constants, and object-like macros expanded (an
/// identifier no macro defines is 0, as in C). An empty macro counts as 1,
/// so `-DFLAG` and `#define FLAG` both test true. A function-like macro, or
/// anything else this evaluator cannot read, is an error the caller decides
/// about.
fn eval_if_expression(expression: &str, defines: &HashMap<String, String>) -> Result<bool, String> {
    eval_if_value(expression, defines, 0).map(|value| value != 0)
}

/// How deep object-like macros may expand into each other in one `#if`.
const MAX_MACRO_DEPTH: usize = 32;

fn eval_if_value(
    expression: &str,
    defines: &HashMap<String, String>,
    depth: usize,
) -> Result<i64, String> {
    if depth > MAX_MACRO_DEPTH {
        return Err("macro expansion too deep in #if expression".to_owned());
    }
    let tokens = lex_expr(expression)?;
    if tokens.is_empty() {
        return Err("expected expression after #if".to_owned());
    }
    let mut parser = ExprParser {
        tokens: &tokens,
        pos: 0,
        defines,
        depth,
    };
    let value = parser.parse_expr(0)?;
    if parser.pos != tokens.len() {
        return Err(format!(
            "unexpected {:?} in #if expression",
            tokens[parser.pos]
        ));
    }
    Ok(value)
}

const PUNCTUATORS: &[&str] = &[
    "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "!", "~", "*", "/", "%", "+", "-", "<", ">",
    "&", "^", "|", "?", ":", "(", ")",
    // Only so a function-like macro's arguments lex and the error names the
    // macro; no #if operator takes a comma.
    ",",
];

fn lex_expr(expression: &str) -> Result<Vec<ExprToken>, String> {
    let mut tokens = Vec::new();
    let bytes = expression.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let rest = &expression[at..];
        let ch = rest.chars().next().expect("non-empty");
        if ch.is_whitespace() {
            at += ch.len_utf8();
            continue;
        }
        if ch.is_ascii_digit() {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '\''))
                .unwrap_or(rest.len());
            tokens.push(ExprToken::Number(parse_integer(&rest[..end])?));
            at += end;
            continue;
        }
        if ch == '\'' {
            let (value, len) = parse_char_constant(rest)?;
            tokens.push(ExprToken::Number(value));
            at += len;
            continue;
        }
        if is_identifier_start(ch) {
            let end = rest
                .find(|c: char| !is_identifier_continue(c))
                .unwrap_or(rest.len());
            let ident = &rest[..end];
            tokens.push(if ident == "defined" {
                ExprToken::Defined
            } else {
                ExprToken::Ident(ident.to_owned())
            });
            at += end;
            continue;
        }
        let Some(op) = PUNCTUATORS.iter().find(|op| rest.starts_with(**op)) else {
            return Err(format!("unsupported token '{ch}' in #if expression"));
        };
        tokens.push(ExprToken::Op(op));
        at += op.len();
    }
    Ok(tokens)
}

/// A C integer constant: decimal, octal (`017`), hex (`0x1F`) or binary
/// (`0b101`), with digit separators (`1'000`) and `u`/`l`/`ll` suffixes.
fn parse_integer(text: &str) -> Result<i64, String> {
    let digits: String = text.chars().filter(|c| *c != '\'').collect();
    let trimmed = digits.trim_end_matches(['u', 'U', 'l', 'L']);
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else if let Some(bin) = trimmed
        .strip_prefix("0b")
        .or_else(|| trimmed.strip_prefix("0B"))
    {
        u64::from_str_radix(bin, 2)
    } else if trimmed.len() > 1 && trimmed.starts_with('0') {
        u64::from_str_radix(&trimmed[1..], 8)
    } else {
        trimmed.parse::<u64>()
    };
    parsed
        .map(|value| value as i64)
        .map_err(|_| format!("invalid integer constant '{text}'"))
}

/// A character constant (`'A'`, `'\n'`, `'\x41'`, `'\0'`) and its length in
/// bytes, prefix and quotes included.
fn parse_char_constant(text: &str) -> Result<(i64, usize), String> {
    let body = &text[1..];
    let close = body
        .find('\'')
        .filter(|close| *close > 0)
        .ok_or_else(|| "unterminated character constant in #if expression".to_owned())?;
    // `'\''` closes after the escaped quote.
    let close = if body.starts_with("\\'") { 2 } else { close };
    let inner = &body[..close];
    let value = match inner.strip_prefix('\\') {
        None => {
            let mut chars = inner.chars();
            let ch = chars.next().unwrap_or('\0');
            if chars.next().is_some() {
                return Err(format!(
                    "multi-character constant '{inner}' in #if expression"
                ));
            }
            ch as i64
        }
        Some(escape) => match escape {
            "n" => 10,
            "t" => 9,
            "r" => 13,
            "0" => 0,
            "a" => 7,
            "b" => 8,
            "f" => 12,
            "v" => 11,
            "\\" => 92,
            "'" => 39,
            "\"" => 34,
            "?" => 63,
            hex if hex.starts_with('x') => i64::from_str_radix(&hex[1..], 16)
                .map_err(|_| format!("invalid escape '\\{hex}' in #if expression"))?,
            oct if oct.chars().all(|c| c.is_digit(8)) => i64::from_str_radix(oct, 8)
                .map_err(|_| format!("invalid escape '\\{oct}' in #if expression"))?,
            other => return Err(format!("invalid escape '\\{other}' in #if expression")),
        },
    };
    Ok((value, close + 2))
}

struct ExprParser<'a> {
    tokens: &'a [ExprToken],
    pos: usize,
    defines: &'a HashMap<String, String>,
    depth: usize,
}

/// Binding power of a binary operator, lowest first, as C ranks them.
fn binary_precedence(op: &str) -> Option<u8> {
    Some(match op {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | "<=" | ">" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        _ => return None,
    })
}

impl ExprParser<'_> {
    /// Precedence climbing over the binary operators, with `?:` (the lowest,
    /// right-associative) at the top.
    fn parse_expr(&mut self, min_precedence: u8) -> Result<i64, String> {
        let mut lhs = self.parse_unary()?;
        loop {
            if min_precedence == 0 && self.consume_op("?") {
                let then = self.parse_expr(0)?;
                self.expect_op(":")?;
                let otherwise = self.parse_expr(0)?;
                lhs = if lhs != 0 { then } else { otherwise };
                continue;
            }
            let Some(ExprToken::Op(op)) = self.tokens.get(self.pos) else {
                break;
            };
            let Some(precedence) = binary_precedence(op) else {
                break;
            };
            if precedence < min_precedence.max(1) {
                break;
            }
            let op = *op;
            self.pos += 1;
            let rhs = self.parse_expr(precedence + 1)?;
            lhs = apply_binary(op, lhs, rhs)?;
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<i64, String> {
        for (op, apply) in [
            ("!", (|v: i64| (v == 0) as i64) as fn(i64) -> i64),
            ("~", |v: i64| !v),
            ("-", |v: i64| v.wrapping_neg()),
            ("+", |v: i64| v),
        ] {
            if self.consume_op(op) {
                return self.parse_unary().map(apply);
            }
        }
        if self.consume(&ExprToken::Defined) {
            return self.parse_defined();
        }
        self.parse_primary()
    }

    fn parse_defined(&mut self) -> Result<i64, String> {
        let name = if self.consume_op("(") {
            let name = self.expect_ident()?;
            self.expect_op(")")?;
            name
        } else {
            self.expect_ident()?
        };
        Ok(self.defines.contains_key(&name) as i64)
    }

    fn parse_primary(&mut self) -> Result<i64, String> {
        if self.consume_op("(") {
            let value = self.parse_expr(0)?;
            self.expect_op(")")?;
            return Ok(value);
        }
        match self.tokens.get(self.pos) {
            Some(ExprToken::Number(value)) => {
                self.pos += 1;
                Ok(*value)
            }
            Some(ExprToken::Ident(name)) => {
                self.pos += 1;
                if matches!(self.tokens.get(self.pos), Some(ExprToken::Op("("))) {
                    return Err(format!("function-like macro '{name}' in #if expression"));
                }
                match self.defines.get(name) {
                    None => Ok(0),
                    Some(value) if value.trim().is_empty() => Ok(1),
                    Some(value) => eval_if_value(value, self.defines, self.depth + 1),
                }
            }
            Some(token) => Err(format!("unexpected {token:?} in #if expression")),
            None => Err("expression ends early in #if".to_owned()),
        }
    }

    fn consume(&mut self, expected: &ExprToken) -> bool {
        if self.tokens.get(self.pos) == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn consume_op(&mut self, op: &str) -> bool {
        if matches!(self.tokens.get(self.pos), Some(ExprToken::Op(found)) if *found == op) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_op(&mut self, op: &str) -> Result<(), String> {
        if self.consume_op(op) {
            Ok(())
        } else {
            Err(format!("expected '{op}' in #if expression"))
        }
    }

    fn expect_ident(&mut self) -> Result<String, String> {
        match self.tokens.get(self.pos) {
            Some(ExprToken::Ident(name)) => {
                self.pos += 1;
                Ok(name.clone())
            }
            _ => Err("expected identifier in defined expression".to_owned()),
        }
    }
}

fn apply_binary(op: &str, lhs: i64, rhs: i64) -> Result<i64, String> {
    Ok(match op {
        "||" => (lhs != 0 || rhs != 0) as i64,
        "&&" => (lhs != 0 && rhs != 0) as i64,
        "|" => lhs | rhs,
        "^" => lhs ^ rhs,
        "&" => lhs & rhs,
        "==" => (lhs == rhs) as i64,
        "!=" => (lhs != rhs) as i64,
        "<" => (lhs < rhs) as i64,
        "<=" => (lhs <= rhs) as i64,
        ">" => (lhs > rhs) as i64,
        ">=" => (lhs >= rhs) as i64,
        "<<" => lhs.wrapping_shl(rhs as u32),
        ">>" => lhs.wrapping_shr(rhs as u32),
        "+" => lhs.wrapping_add(rhs),
        "-" => lhs.wrapping_sub(rhs),
        "*" => lhs.wrapping_mul(rhs),
        "/" | "%" if rhs == 0 => return Err("division by zero in #if expression".to_owned()),
        "/" => lhs.wrapping_div(rhs),
        "%" => lhs.wrapping_rem(rhs),
        other => return Err(format!("unsupported operator '{other}' in #if expression")),
    })
}

fn warning_pragma(message: impl AsRef<str>) -> String {
    let escaped = message.as_ref().replace('\\', "\\\\").replace('"', "\"\"");
    format!("#pragma bhf_warning \"{escaped}\"")
}

fn read_identifier(input: &str) -> Option<(&str, usize)> {
    let mut chars = input.char_indices();
    let (_, first) = chars.next()?;
    if !is_identifier_start(first) {
        return None;
    }
    let mut end = first.len_utf8();
    for (index, ch) in chars {
        if is_identifier_continue(ch) {
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    Some((&input[..end], end))
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn line_span(line: usize, column: usize) -> Span {
    Span {
        start: 0,
        end: 0,
        line,
        column,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocess_expands_object_like_defines_on_identifier_boundaries() {
        let output =
            preprocess_idl("#define SIZE 8\nconst long Limit = SIZE;\n").expect("preprocesses");
        assert!(output.contains("const long Limit = 8;"));
    }

    #[test]
    fn preprocess_c_like_resolves_ifdef_branches_and_object_macros() {
        // #460: a C TU with conditional compilation + an object-like macro. The
        // inactive #ifdef branch is dropped, the #else kept, and MAX expanded — so
        // tree-sitter sees the correct, single set of declarations.
        let src = "#define MAX 16\n\
                   #ifdef LINUX\n\
                   int linux_only(void);\n\
                   #else\n\
                   int other_only(void);\n\
                   #endif\n\
                   int buf[MAX];\n";

        let undefined = preprocess_c_like(src, &[]);
        assert!(undefined.contains("other_only"), "{undefined}");
        assert!(!undefined.contains("linux_only"), "{undefined}");
        assert!(undefined.contains("int buf[16]"), "{undefined}");

        let defined = preprocess_c_like(src, &[("LINUX".to_owned(), "1".to_owned())]);
        assert!(defined.contains("linux_only"), "{defined}");
        assert!(!defined.contains("other_only"), "{defined}");
    }

    #[test]
    fn line_map_translates_preprocessed_line_back_to_original() {
        // §27.6 regression guard: with an inactive `#ifdef` branch dropped and an
        // object macro expanded, a function that sits at original line 8 lands at a
        // DIFFERENT preprocessed line — the map must translate it back to 8, or
        // every reported location would be shifted.
        //
        // Original source (1-based):
        //   1: #define MAX 16
        //   2: #ifdef LINUX
        //   3: int linux_only(void);
        //   4: #else
        //   5: int other_only(void);
        //   6: #endif
        //   7: int buf[MAX];
        //   8: int real_target(const char *p) { return p[0]; }
        let src = "#define MAX 16\n\
                   #ifdef LINUX\n\
                   int linux_only(void);\n\
                   #else\n\
                   int other_only(void);\n\
                   #endif\n\
                   int buf[MAX];\n\
                   int real_target(const char *p) { return p[0]; }\n";

        let (out, map) = preprocess_c_like_with_line_map(src, &[]);
        assert!(out.contains("other_only"), "{out}");
        assert!(!out.contains("linux_only"), "{out}");
        assert!(out.contains("int buf[16]"), "{out}");

        // Find which PREPROCESSED line `real_target` ended up on, then translate.
        let pp_line = out
            .lines()
            .position(|l| l.contains("real_target"))
            .expect("real_target survives preprocessing") as u32
            + 1;
        assert_eq!(
            map.to_original(pp_line),
            8,
            "preprocessed line {pp_line} must map back to original line 8"
        );

        // `other_only` (kept #else branch) sits at original line 5.
        let other_pp = out
            .lines()
            .position(|l| l.contains("other_only"))
            .expect("other_only kept") as u32
            + 1;
        assert_eq!(map.to_original(other_pp), 5);

        // Out-of-range / zero inputs translate to themselves (safe identity).
        assert_eq!(map.to_original(0), 0);
        assert_eq!(map.to_original(9999), 9999);
    }

    #[test]
    fn line_map_passes_includes_through_and_stays_one_to_one() {
        // A real C file with an active `#include` must NOT abort preprocessing
        // (which would drop the line map's value): the include is kept verbatim and
        // every line maps to itself when there is no folding/conditional.
        let src = "#include <stdio.h>\n\
                   #include \"local.h\"\n\
                   int parse(const char *p) { return p[0]; }\n";
        let (out, map) = preprocess_c_like_with_line_map(src, &[]);
        assert!(out.contains("#include <stdio.h>"), "include kept: {out}");
        assert!(out.contains("#include \"local.h\""), "include kept: {out}");
        // No folding/conditionals -> identity map.
        for line in 1..=3u32 {
            assert_eq!(
                map.to_original(line),
                line,
                "line {line} should be identity"
            );
        }
    }

    #[test]
    fn line_map_corrects_for_backslash_continued_macro_fold() {
        // A 3-physical-line backslash-continued (object-like) macro folds to ONE
        // output line, so a function below it shifts up by 2 preprocessed lines —
        // the map must still resolve it to its ORIGINAL physical line.
        //   1: #define COMMON \
        //   2:   short s; \
        //   3:   long l;
        //   4: int after(const char *p) { return p[0]; }
        let src = "#define COMMON \\\n  short s; \\\n  long l;\n\
                   int after(const char *p) { return p[0]; }\n";
        let (out, map) = preprocess_c_like_with_line_map(src, &[]);
        let pp = out
            .lines()
            .position(|l| l.contains("int after"))
            .expect("after survives") as u32
            + 1;
        assert_eq!(
            map.to_original(pp),
            4,
            "function after a folded macro must map back to original line 4 (pp line {pp})"
        );
    }

    #[test]
    fn preprocess_folds_backslash_continued_macro_definitions() {
        let source =
            "#define COMMON_FIELDS \\\n  short s; \\\n  long l;\nstruct S {\n  COMMON_FIELDS\n};\n";
        let output = preprocess_idl(source).expect("preprocesses");

        assert!(output.contains("short s;"));
        assert!(output.contains("long l;"));
        assert!(!output.contains('\\'));
    }

    #[test]
    fn preprocess_preserves_string_literals_during_expansion() {
        let output =
            preprocess_idl("#define NAME Foo\nconst string S = \"NAME\";\ninterface NAME {};\n")
                .expect("preprocesses");
        assert!(output.contains("const string S = \"NAME\";"));
        assert!(output.contains("interface Foo {};"));
    }

    #[test]
    fn preprocess_selects_ifdef_and_ifndef_branches() {
        let source = "#define ENABLED\n#ifdef ENABLED\ninterface On {};\n#else\ninterface Off {};\n#endif\n#ifndef MISSING\ninterface Fallback {};\n#endif\n";
        let output = preprocess_idl(source).expect("preprocesses");
        assert!(output.contains("interface On {};"));
        assert!(output.contains("interface Fallback {};"));
        assert!(!output.contains("interface Off {};"));
    }

    fn if_value(expression: &str, defines: &[(&str, &str)]) -> Result<i64, String> {
        let defines = defines
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        eval_if_value(expression, &defines, 0)
    }

    #[test]
    fn if_expressions_evaluate_every_operator_class() {
        for (expression, expected) in [
            // comparison and equality
            ("3 >= 2", 1),
            ("2 >= 3", 0),
            ("1 < 2", 1),
            ("2 <= 2", 1),
            ("3 > 4", 0),
            ("4 == 4", 1),
            ("4 != 4", 0),
            // arithmetic, with C precedence
            ("1 + 2 * 3", 7),
            ("(1 + 2) * 3", 9),
            ("10 / 3", 3),
            ("10 % 3", 1),
            ("7 - 2 - 1", 4),
            ("-3 + 5", 2),
            // shifts and bitwise
            ("1 << 4", 16),
            ("256 >> 4", 16),
            ("6 & 3", 2),
            ("6 | 1", 7),
            ("6 ^ 3", 5),
            ("~0", -1),
            // logical, unary and the conditional
            ("!0", 1),
            ("1 && 0", 0),
            ("0 || 2", 1),
            ("1 ? 10 : 20", 10),
            ("0 ? 10 : 0 ? 30 : 40", 40),
            // constants
            ("0x1F", 31),
            ("017", 15),
            ("0b101", 5),
            ("201112L", 201112),
            ("1'000", 1000),
            ("'A'", 65),
            ("'\\n'", 10),
            ("'\\x41'", 65),
        ] {
            assert_eq!(if_value(expression, &[]), Ok(expected), "{expression}");
        }
    }

    #[test]
    fn if_expressions_expand_object_like_macros() {
        let defines = [
            ("API_LEVEL", "3"),
            ("MIN_LEVEL", "API_LEVEL - 1"),
            ("FLAG", ""),
            ("STDC", "201112L"),
        ];
        assert_eq!(if_value("API_LEVEL >= 2", &defines), Ok(1));
        assert_eq!(if_value("MIN_LEVEL == 2", &defines), Ok(1));
        // An empty macro (`#define FLAG`, `-DFLAG`) tests true.
        assert_eq!(if_value("FLAG", &defines), Ok(1));
        assert_eq!(if_value("STDC >= 201112L", &defines), Ok(1));
        // An identifier no macro defines is 0.
        assert_eq!(if_value("MISSING", &defines), Ok(0));
        assert_eq!(
            if_value("defined(API_LEVEL) && !defined MISSING", &defines),
            Ok(1)
        );
        // What the evaluator cannot read is an error, never a guess.
        assert!(if_value("VERSION(2)", &defines).is_err());
        assert!(if_value("1 / 0", &defines).is_err());
        assert!(if_value("1 +", &defines).is_err());
        let looping = [("A", "B"), ("B", "A")];
        assert!(if_value("A", &looping).is_err());
    }

    #[test]
    fn elif_chains_take_the_first_true_branch() {
        let source = "#define API_LEVEL 2\n\
                      #if API_LEVEL >= 3\nint v3;\n\
                      #elif API_LEVEL >= 2\nint v2;\n\
                      #elif API_LEVEL >= 1\nint v1;\n\
                      #else\nint v0;\n#endif\n";
        let (output, _) = preprocess_c_like_with_line_map(source, &[]);
        assert!(output.contains("int v2;"), "{output}");
        for dead in ["int v3;", "int v1;", "int v0;"] {
            assert!(!output.contains(dead), "{dead} in {output}");
        }
    }

    #[test]
    fn c_discovery_keeps_every_branch_of_an_unevaluated_if() {
        let source =
            "#if VERSION(2)\nint parse_v2(void);\n#else\nint parse_legacy(void);\n#endif\n\
                      int always(void);\n";
        let (output, _) = preprocess_c_like_with_line_map(source, &[]);
        assert!(output.contains("int parse_v2(void);"), "{output}");
        assert!(output.contains("int parse_legacy(void);"), "{output}");
        assert!(output.contains("int always(void);"), "{output}");
        assert!(
            output.contains("every branch kept") && output.contains("line 1"),
            "{output}"
        );
    }

    #[test]
    fn c_discovery_follows_a_comparison_gate() {
        let source = "#define API_LEVEL 3\n\
                      #if API_LEVEL >= 2\nint parse_v2(void);\n#else\nint parse_legacy(void);\n#endif\n\
                      #if API_LEVEL != 0\nint checksum(void);\n#endif\n";
        let (output, _) = preprocess_c_like_with_line_map(source, &[]);
        assert!(output.contains("int parse_v2(void);"), "{output}");
        assert!(output.contains("int checksum(void);"), "{output}");
        assert!(!output.contains("int parse_legacy(void);"), "{output}");
    }

    #[test]
    fn preprocess_rejects_unsupported_if_expression() {
        let error = preprocess_idl("#if VENDOR_FLAG(1)\ninterface I {};\n#endif\n")
            .expect_err("unsupported directive is rejected");
        assert!(
            error
                .to_string()
                .contains("function-like macro 'VENDOR_FLAG'"),
            "{error}"
        );
    }

    #[test]
    fn preprocess_if_expression_supports_defined_not_and_and() {
        let source = "#define ENABLED\n#if defined ENABLED && !defined DISABLED\ninterface Active {};\n#endif\n";
        let output = preprocess_idl(source).expect("preprocesses #if expression");

        assert!(output.contains("interface Active {};"));
    }

    #[test]
    fn preprocess_if_expression_allows_trailing_comment() {
        let source =
            "#define ENABLED\n#if defined ENABLED /* enabled */\ninterface Active {};\n#endif\n";
        let output = preprocess_idl(source).expect("preprocesses #if comment");

        assert!(output.contains("interface Active {};"));
    }

    #[test]
    fn preprocess_if_expression_treats_undefined_identifier_as_false() {
        let source = "#if MISSING\ninterface Hidden {};\n#endif\ninterface Root {};\n";
        let output = preprocess_idl(source).expect("preprocesses #if expression");

        assert!(!output.contains("interface Hidden {};"));
        assert!(output.contains("interface Root {};"));
    }

    #[test]
    fn preprocess_undef_removes_macro_definition() {
        let source = "#define ENABLED 1\n#undef ENABLED\n#if ENABLED\ninterface Hidden {};\n#endif\ninterface Root {};\n";
        let output = preprocess_idl(source).expect("preprocesses #undef");

        assert!(!output.contains("interface Hidden {};"));
        assert!(output.contains("interface Root {};"));
    }

    #[test]
    fn preprocess_allows_comments_after_conditional_directives() {
        let source = "#define ENABLED\n#ifdef ENABLED /* guard */\ninterface Root {};\n#else // disabled\ninterface Hidden {};\n#endif /* guard */\n";
        let output = preprocess_idl(source).expect("preprocesses comments after directives");

        assert!(output.contains("interface Root {};"));
        assert!(!output.contains("interface Hidden {};"));
    }

    #[test]
    fn preprocess_preserves_active_pragmas_and_drops_inactive_pragmas() {
        let source = "#define ENABLED\n#ifdef ENABLED\n#pragma prefix \"acme.example\"\n#else\n#pragma vendor disabled\n#endif\ninterface Root {};\n";

        let output = preprocess_idl(source).expect("preprocesses");

        assert!(output.contains("#pragma prefix \"acme.example\""));
        assert!(!output.contains("vendor disabled"));
        assert!(output.contains("interface Root {};"));
    }

    #[test]
    fn preprocess_file_resolves_quoted_include_relative_to_parent() {
        let (_root_guard, root) = temp_dir("include_relative");
        let _ = std::fs::remove_dir_all(&root);
        let child_dir = root.join("idl");
        std::fs::create_dir_all(&child_dir).expect("create fixture dir");
        std::fs::write(child_dir.join("common.idl"), "interface Common {};\n")
            .expect("write include");
        let root_file = child_dir.join("root.idl");
        std::fs::write(&root_file, "#include \"common.idl\"\ninterface Root {};\n")
            .expect("write root");

        let output = preprocess_idl_file(&root_file).expect("preprocesses file");

        assert!(output.contains("interface Common {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_allows_comments_after_include_path() {
        let (_root_guard, root) = temp_dir("include_comment");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        std::fs::write(root.join("common.idl"), "interface Common {};\n").expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#include \"common.idl\" /* common */\ninterface Root {};\n",
        )
        .expect("write root");

        let output = preprocess_idl_file(&root_file).expect("preprocesses file");

        assert!(output.contains("interface Common {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_resolves_quoted_include_from_include_dir() {
        let (_root_guard, root) = temp_dir("include_dir_quoted");
        let _ = std::fs::remove_dir_all(&root);
        let include_dir = root.join("shared");
        std::fs::create_dir_all(&include_dir).expect("create include dir");
        std::fs::write(include_dir.join("common.idl"), "interface Common {};\n")
            .expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(&root_file, "#include \"common.idl\"\ninterface Root {};\n")
            .expect("write root");

        let output = preprocess_idl_file_with_include_dirs(&root_file, &[include_dir])
            .expect("preprocesses file");

        assert!(output.contains("interface Common {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_resolves_angle_include_from_include_dir() {
        let (_root_guard, root) = temp_dir("include_dir_angle");
        let _ = std::fs::remove_dir_all(&root);
        let include_dir = root.join("shared");
        std::fs::create_dir_all(&include_dir).expect("create include dir");
        std::fs::write(include_dir.join("common.idl"), "interface Common {};\n")
            .expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(&root_file, "#include <common.idl>\ninterface Root {};\n")
            .expect("write root");

        let output = preprocess_idl_file_with_include_dirs(&root_file, &[include_dir])
            .expect("preprocesses file");

        assert!(output.contains("interface Common {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_recovering_skips_missing_include_with_warning_pragma() {
        let (_root_guard, root) = temp_dir("recover_missing_include");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let root_file = root.join("root.idl");
        std::fs::write(&root_file, "#include \"missing.idl\"\ninterface Root {};\n")
            .expect("write root");

        let output = preprocess_idl_file_recovering_with_include_dirs(&root_file, &[])
            .expect("preprocesses with recovery");

        assert!(output.contains("#pragma bhf_warning"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_recovering_treats_unsupported_if_expression_as_inactive() {
        let (_root_guard, root) = temp_dir("recover_unsupported_if");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#if VENDOR_FLAG(1)\ninterface Hidden {};\n#endif\ninterface Root {};\n",
        )
        .expect("write root");

        let output = preprocess_idl_file_recovering_with_include_dirs(&root_file, &[])
            .expect("preprocesses with recovery");

        assert!(output.contains("#pragma bhf_warning"));
        assert!(!output.contains("interface Hidden {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_detects_include_cycles() {
        let (_root_guard, root) = temp_dir("include_cycle");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let a = root.join("a.idl");
        let b = root.join("b.idl");
        std::fs::write(&a, "#include \"b.idl\"\n").expect("write a");
        std::fs::write(&b, "#include \"a.idl\"\n").expect("write b");

        let error = preprocess_idl_file(&a).expect_err("cycle is rejected");

        assert!(error.to_string().contains("include cycle"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_skips_include_inside_inactive_ifdef_without_reading_file() {
        let (_root_guard, root) = temp_dir("inactive_include");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#ifdef DISABLED\n#include \"missing.idl\"\n#endif\ninterface Root {};\n",
        )
        .expect("write root");

        let output = preprocess_idl_file(&root_file).expect("preprocesses file");

        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_errors_for_missing_endif_inside_include() {
        let (_root_guard, root) = temp_dir("include_missing_endif");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let included = root.join("common.idl");
        std::fs::write(&included, "#ifdef ENABLED\ninterface Common {};\n").expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#define ENABLED\n#include \"common.idl\"\ninterface Root {};\n",
        )
        .expect("write root");

        let error = preprocess_idl_file(&root_file).expect_err("missing endif is rejected");

        assert!(error.to_string().contains("missing #endif"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    /// A path under a directory that is removed when the guard is dropped.
    fn temp_dir(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let guard = tempfile::Builder::new()
            .prefix("bhf-")
            .tempdir()
            .expect("create test dir");
        let path = guard
            .path()
            .join(format!("bhf-idl-{name}-{}", std::process::id()));
        (guard, path)
    }
}
