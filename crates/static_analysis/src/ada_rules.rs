// SPDX-License-Identifier: Apache-2.0

//! Ada structural rule pack.
//!
//! The line-based Ada rules in `lib.rs` cannot see across a multi-line call or
//! tell a local object from a library-level one. This module lexes the Ada
//! source (strings, character literals and the attribute tick handled), splits it
//! into statements, and tracks the enclosing package / subprogram / task / block
//! frames with their declarations, parameters and exception handlers. The rules
//! below run over that model. Rule ids, CWEs and the known false-positive
//! patterns are listed in `docs/designs/2026-10-16-ada-static-rules.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::{static_finding, StaticEvidence, StaticFinding};

pub(crate) fn scan(root: &Path, path: &Path, source: &str, findings: &mut Vec<StaticFinding>) {
    if is_test_path(root, path) {
        return;
    }
    let model = Model::build(lex(source));
    if is_runtime_unit(&model) {
        return;
    }
    let ctx = Ctx {
        root,
        path,
        lines: source.lines().collect(),
        model: &model,
    };
    let mut out = Vec::new();
    broad_null_handler(&ctx, &mut out);
    suppressed_checks(&ctx, &mut out);
    unchecked_access_escape(&ctx, &mut out);
    address_overlay(&ctx, &mut out);
    imported_unsafe_c(&ctx, &mut out);
    new_string_leak(&ctx, &mut out);
    command_spawn(&ctx, &mut out);
    sql_concatenation(&ctx, &mut out);
    secret_logged(&ctx, &mut out);
    export_propagation(&ctx, &mut out);
    raise_in_finalize(&ctx, &mut out);
    unbounded_stream_input(&ctx, &mut out);
    predictable_random(&ctx, &mut out);
    weak_password_hash(&ctx, &mut out);
    unchecked_conversion_to_access(&ctx, &mut out);
    free_through_alias(&ctx, &mut out);
    unprotected_task_write(&ctx, &mut out);
    let mut seen = BTreeSet::new();
    for hit in out {
        if !seen.insert((hit.rule, hit.tok)) {
            continue;
        }
        let tok = &model.toks[hit.tok];
        let snippet = ctx.lines.get(tok.line).map_or("", |l| l.trim());
        findings.push(static_finding(
            root,
            path,
            tok.line,
            tok.col + 1,
            hit.rule,
            "ada",
            hit.slug,
            hit.message,
            StaticEvidence {
                kind: hit.kind.to_owned(),
                detail: hit.detail,
                snippet: snippet.to_owned(),
            },
        ));
    }
}

/// Test trees (`tests/`, `regtests/`, `testsuite/`, `*-tests.adb`) are not
/// attacker-facing code; findings there cost review time and teach nothing.
/// Only components below the scan root count, so a root named `tests` still scans.
fn is_test_path(root: &Path, path: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let mut parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    let file = parts.pop().unwrap_or_default();
    // GNAT binder output (`b__main.adb`, `b~main.adb`) is generated elaboration code.
    if file.starts_with("b__") || file.starts_with("b~") {
        return true;
    }
    let stem = file
        .rsplit_once('.')
        .map_or(file.as_str(), |(stem, _)| stem);
    parts.iter().any(|part| {
        matches!(
            part.as_str(),
            "test" | "tests" | "regtests" | "testsuite" | "testing" | "unit_tests" | "unittests"
        )
    }) || ["-tests", "_tests", "-test", "_test"]
        .iter()
        .any(|suffix| stem.ends_with(suffix))
}

/// A compilation unit of the predefined (`Ada.`, `System.`, `Interfaces.`) or
/// GNAT implementation-defined hierarchy: a language runtime implementing the
/// checks itself, not application code.
fn is_runtime_unit(m: &Model) -> bool {
    let Some(header) = m
        .stmts
        .iter()
        .find(|s| s.kind == StmtKind::Header && s.frame == 0)
    else {
        return false;
    };
    let toks = m.stmt_toks(header);
    // `separate (System.Unwind.Raising) package body Separated`: the parent decides.
    if toks.len() > 3 && toks[0].is("separate") && toks[1].sym("(") {
        return toks[3].sym(".")
            && matches!(
                toks[2].text.as_str(),
                "ada" | "system" | "interfaces" | "gnat"
            );
    }
    let Some(at) = toks
        .iter()
        .position(|t| t.is("package") || t.is("procedure") || t.is("function"))
    else {
        return false;
    };
    let mut k = at + 1;
    if toks.get(k).is_some_and(|t| t.is("body")) {
        k += 1;
    }
    let root = toks
        .get(k)
        .filter(|_| toks.get(k + 1).is_some_and(|d| d.sym(".")));
    root.is_some_and(|t| matches!(t.text.as_str(), "ada" | "system" | "interfaces" | "gnat"))
}

// ───────────────────────────── lexer ─────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ident,
    Str,
    Char,
    Num,
    Sym,
}

#[derive(Clone, Debug)]
struct Tok {
    kind: Kind,
    /// Identifiers are lowercased (Ada is case-insensitive); string literals hold
    /// their decoded contents; symbols their spelling.
    text: String,
    line: usize,
    col: usize,
}

impl Tok {
    fn is(&self, word: &str) -> bool {
        self.kind == Kind::Ident && self.text == word
    }

    fn sym(&self, s: &str) -> bool {
        self.kind == Kind::Sym && self.text == s
    }
}

const RESERVED: &[&str] = &[
    "abort",
    "abs",
    "abstract",
    "accept",
    "access",
    "aliased",
    "all",
    "and",
    "array",
    "at",
    "begin",
    "body",
    "case",
    "constant",
    "declare",
    "delay",
    "delta",
    "digits",
    "do",
    "else",
    "elsif",
    "end",
    "entry",
    "exception",
    "exit",
    "for",
    "function",
    "generic",
    "goto",
    "if",
    "in",
    "interface",
    "is",
    "limited",
    "loop",
    "mod",
    "new",
    "not",
    "null",
    "of",
    "or",
    "others",
    "out",
    "overriding",
    "package",
    "parallel",
    "pragma",
    "private",
    "procedure",
    "protected",
    "raise",
    "range",
    "record",
    "rem",
    "renames",
    "requeue",
    "return",
    "reverse",
    "select",
    "separate",
    "some",
    "subtype",
    "synchronized",
    "tagged",
    "task",
    "terminate",
    "then",
    "type",
    "until",
    "use",
    "when",
    "while",
    "with",
    "xor",
];

fn is_reserved(word: &str) -> bool {
    RESERVED.contains(&word)
}

fn lex(source: &str) -> Vec<Tok> {
    let chars: Vec<(usize, char)> = source.char_indices().collect();
    let at = |k: usize| chars.get(k).map(|(_, c)| *c);
    let mut toks: Vec<Tok> = Vec::new();
    let (mut line, mut line_start) = (0usize, 0usize);
    let mut k = 0;
    while k < chars.len() {
        let (pos, c) = chars[k];
        if c == '\n' {
            line += 1;
            line_start = pos + 1;
            k += 1;
            continue;
        }
        if c.is_whitespace() {
            k += 1;
            continue;
        }
        let col = pos - line_start;
        let push = |toks: &mut Vec<Tok>, kind, text: String| {
            toks.push(Tok {
                kind,
                text,
                line,
                col,
            })
        };
        if c == '-' && at(k + 1) == Some('-') {
            while k < chars.len() && chars[k].1 != '\n' {
                k += 1;
            }
            continue;
        }
        if c == '"' {
            let mut text = String::new();
            k += 1;
            while let Some(ch) = at(k) {
                if ch == '\n' {
                    break;
                }
                k += 1;
                if ch == '"' {
                    if at(k) == Some('"') {
                        text.push('"');
                        k += 1;
                        continue;
                    }
                    break;
                }
                text.push(ch);
            }
            push(&mut toks, Kind::Str, text);
            continue;
        }
        if c == '\'' {
            // An attribute tick follows a name or a closing paren; anywhere else a
            // quote that closes two characters later is a character literal.
            let tick = toks.last().is_some_and(|t| {
                (t.kind == Kind::Ident
                    && (!is_reserved(&t.text)
                        || matches!(
                            t.text.as_str(),
                            "all" | "range" | "access" | "delta" | "digits"
                        )))
                    || t.sym(")")
            });
            if !tick && at(k + 2) == Some('\'') {
                push(&mut toks, Kind::Char, at(k + 1).unwrap_or(' ').to_string());
                k += 3;
                continue;
            }
            push(&mut toks, Kind::Sym, "'".to_owned());
            k += 1;
            continue;
        }
        if c.is_alphabetic() {
            let mut text = String::new();
            while let Some(ch) = at(k) {
                if ch.is_alphanumeric() || ch == '_' {
                    text.extend(ch.to_lowercase());
                    k += 1;
                } else {
                    break;
                }
            }
            push(&mut toks, Kind::Ident, text);
            continue;
        }
        if c.is_ascii_digit() {
            let mut text = String::new();
            while let Some(ch) = at(k) {
                let exponent_sign = matches!(ch, '+' | '-')
                    && text.ends_with(['e', 'E'])
                    && at(k + 1).is_some_and(|d| d.is_ascii_digit());
                let fraction = ch == '.' && at(k + 1).is_some_and(|d| d.is_ascii_digit());
                if ch.is_ascii_alphanumeric()
                    || matches!(ch, '_' | '#')
                    || exponent_sign
                    || fraction
                {
                    text.push(ch);
                    k += 1;
                } else {
                    break;
                }
            }
            push(&mut toks, Kind::Num, text);
            continue;
        }
        let pair: String = [Some(c), at(k + 1)].iter().flatten().collect();
        if matches!(
            pair.as_str(),
            "=>" | ":=" | ".." | "**" | "/=" | ">=" | "<=" | "<<" | ">>" | "<>"
        ) {
            push(&mut toks, Kind::Sym, pair);
            k += 2;
            continue;
        }
        push(&mut toks, Kind::Sym, c.to_string());
        k += 1;
    }
    toks
}

// ────────────────────── statements and frames ──────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameKind {
    Unit,
    Package,
    Subprogram,
    Task,
    Protected,
    Block,
    /// if / loop / case / select / record / accept-do / extended return, and
    /// task or protected specs: no declarations or handlers of their own.
    Control,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Decl,
    Body,
    Handler,
}

#[derive(Debug)]
struct Frame {
    kind: FrameKind,
    name: String,
    parent: Option<usize>,
    /// The parent's phase when this frame opened (a block inside a handler is
    /// itself part of that handler).
    parent_phase: Phase,
    phase: Phase,
    header: Option<usize>,
    params: Vec<String>,
    /// Exception choices of this frame's own handler part (`others` included).
    handled: BTreeSet<String>,
    /// Statements and descendant frames are emitted in order, so everything
    /// nested in this frame is `stmts[stmt_lo..stmt_hi]` / `frames[..frame_hi]`.
    stmt_lo: usize,
    stmt_hi: usize,
    frame_hi: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StmtKind {
    Plain,
    Header,
    End,
    Choice,
    Scheme,
}

#[derive(Clone, Copy, Debug)]
struct Stmt {
    lo: usize,
    hi: usize,
    frame: usize,
    phase: Phase,
    kind: StmtKind,
}

#[derive(Debug)]
struct Decl {
    names: Vec<String>,
    frame: usize,
    stmt: usize,
    constant: bool,
    ty: (usize, usize),
    init: Option<(usize, usize)>,
    aspects: Option<(usize, usize)>,
}

struct Model {
    toks: Vec<Tok>,
    stmts: Vec<Stmt>,
    frames: Vec<Frame>,
    decls: Vec<Decl>,
    decls_by_frame: Vec<Vec<usize>>,
    decl_of_stmt: Vec<Option<usize>>,
}

/// What an identifier resolves to from inside a given frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Binding {
    /// An object declared inside the enclosing subprogram or task body.
    Local(usize),
    /// A formal parameter of the enclosing subprogram.
    Param,
    /// An object declared at package / library level.
    Library(usize),
    Unknown,
}

impl Model {
    fn build(toks: Vec<Tok>) -> Self {
        let mut model = Model {
            toks,
            stmts: Vec::new(),
            frames: vec![Frame {
                kind: FrameKind::Unit,
                name: String::new(),
                parent: None,
                parent_phase: Phase::Decl,
                phase: Phase::Decl,
                header: None,
                params: Vec::new(),
                handled: BTreeSet::new(),
                stmt_lo: 0,
                stmt_hi: usize::MAX,
                frame_hi: usize::MAX,
            }],
            decls: Vec::new(),
            decls_by_frame: Vec::new(),
            decl_of_stmt: Vec::new(),
        };
        let mut stack = vec![0usize];
        let (mut lo, mut depth) = (0usize, 0usize);
        let n = model.toks.len();
        let mut i = 0;
        while i < n {
            let top = *stack.last().unwrap_or(&0);
            let t = &model.toks[i];
            if t.sym("(") {
                depth += 1;
            } else if t.sym(")") {
                depth = depth.saturating_sub(1);
            } else if depth == 0 {
                let prev_is = |w: &str| i > 0 && model.toks[i - 1].is(w);
                let at_start = i == lo;
                if t.sym(";") {
                    let is_end = lo < i && model.toks[lo].is("end");
                    model.emit(
                        lo,
                        i,
                        top,
                        if is_end {
                            StmtKind::End
                        } else {
                            StmtKind::Plain
                        },
                    );
                    if is_end && stack.len() > 1 {
                        if let Some(closed) = stack.pop() {
                            model.frames[closed].stmt_hi = model.stmts.len();
                            model.frames[closed].frame_hi = model.frames.len();
                        }
                    }
                    lo = i + 1;
                } else if t.sym("=>") && lo < i && model.toks[lo].is("when") {
                    if model.frames[top].phase == Phase::Handler {
                        let choices: Vec<String> = model.toks[lo + 1..i]
                            .iter()
                            .filter(|c| c.kind == Kind::Ident)
                            .map(|c| c.text.clone())
                            .collect();
                        // `when E : Constraint_Error` names the occurrence first.
                        let named = model.toks[lo + 1..i].iter().any(|c| c.sym(":"));
                        let skip = usize::from(named);
                        model.frames[top]
                            .handled
                            .extend(choices.into_iter().skip(skip));
                    }
                    model.emit(lo, i, top, StmtKind::Choice);
                    lo = i + 1;
                } else if t.kind == Kind::Ident {
                    match t.text.as_str() {
                        "is" => {
                            if let Some((kind, name, always)) = header_kind(&model.toks[lo..i]) {
                                let next = model.toks.get(i + 1);
                                let deferred = next.is_some_and(|nx| {
                                    nx.is("new")
                                        || nx.is("separate")
                                        || nx.is("abstract")
                                        || nx.is("null")
                                        || nx.sym("(")
                                        || nx.sym("<>")
                                });
                                if always || !deferred {
                                    let header = model.emit(lo, i, top, StmtKind::Header);
                                    let params = header_params(&model.toks[lo..i]);
                                    model.push(&mut stack, kind, name, Some(header), params);
                                    lo = i + 1;
                                }
                            }
                        }
                        "begin" => {
                            let frame = &mut model.frames[top];
                            if frame.phase == Phase::Decl
                                && matches!(
                                    frame.kind,
                                    FrameKind::Package
                                        | FrameKind::Subprogram
                                        | FrameKind::Task
                                        | FrameKind::Block
                                )
                            {
                                frame.phase = Phase::Body;
                            } else {
                                model.push(
                                    &mut stack,
                                    FrameKind::Block,
                                    String::new(),
                                    None,
                                    Vec::new(),
                                );
                                let new_top = *stack.last().unwrap_or(&0);
                                model.frames[new_top].phase = Phase::Body;
                            }
                            lo = i + 1;
                        }
                        "declare" => {
                            model.push(
                                &mut stack,
                                FrameKind::Block,
                                String::new(),
                                None,
                                Vec::new(),
                            );
                            let new_top = *stack.last().unwrap_or(&0);
                            model.frames[new_top].phase = Phase::Decl;
                            lo = i + 1;
                        }
                        "exception" if at_start => {
                            model.frames[top].phase = Phase::Handler;
                            lo = i + 1;
                        }
                        "private" if at_start => {
                            let next_is_unit = model.toks.get(i + 1).is_some_and(|nx| {
                                nx.is("with")
                                    || nx.is("package")
                                    || nx.is("procedure")
                                    || nx.is("function")
                                    || nx.is("generic")
                            });
                            if !next_is_unit {
                                lo = i + 1;
                            }
                        }
                        "then" if !prev_is("and") => {
                            if lo < i && (model.toks[lo].is("if") || model.toks[lo].is("elsif")) {
                                let opens = model.toks[lo].is("if");
                                model.emit(lo, i, top, StmtKind::Scheme);
                                if opens {
                                    model.push(
                                        &mut stack,
                                        FrameKind::Control,
                                        String::new(),
                                        None,
                                        Vec::new(),
                                    );
                                }
                                lo = i + 1;
                            } else if at_start {
                                lo = i + 1;
                                if model.toks.get(i + 1).is_some_and(|nx| nx.is("abort")) {
                                    lo = i + 2;
                                }
                            }
                        }
                        "else" | "or" if at_start => lo = i + 1,
                        "select" if at_start => {
                            model.push(
                                &mut stack,
                                FrameKind::Control,
                                String::new(),
                                None,
                                Vec::new(),
                            );
                            lo = i + 1;
                        }
                        "loop" | "do" if !prev_is("end") => {
                            if lo < i {
                                model.emit(lo, i, top, StmtKind::Scheme);
                            }
                            model.push(
                                &mut stack,
                                FrameKind::Control,
                                String::new(),
                                None,
                                Vec::new(),
                            );
                            lo = i + 1;
                        }
                        "record" if !prev_is("end") && !prev_is("null") => {
                            if lo < i {
                                model.emit(lo, i, top, StmtKind::Plain);
                            }
                            model.push(
                                &mut stack,
                                FrameKind::Control,
                                String::new(),
                                None,
                                Vec::new(),
                            );
                            lo = i + 1;
                        }
                        _ => {}
                    }
                }
            }
            i += 1;
        }
        // Frames still open at end of file extend to the end.
        let (stmt_count, frame_count) = (model.stmts.len(), model.frames.len());
        for frame in &mut model.frames {
            frame.stmt_hi = frame.stmt_hi.min(stmt_count);
            frame.frame_hi = frame.frame_hi.min(frame_count);
        }
        model.decls_by_frame = vec![Vec::new(); model.frames.len()];
        model.decl_of_stmt = vec![None; model.stmts.len()];
        for index in 0..model.stmts.len() {
            if let Some(decl) = model.parse_decl(index) {
                model.decls_by_frame[decl.frame].push(model.decls.len());
                model.decl_of_stmt[index] = Some(model.decls.len());
                model.decls.push(decl);
            }
        }
        model
    }

    fn emit(&mut self, lo: usize, hi: usize, frame: usize, kind: StmtKind) -> usize {
        self.stmts.push(Stmt {
            lo,
            hi,
            frame,
            phase: self.frames[frame].phase,
            kind,
        });
        self.stmts.len() - 1
    }

    fn push(
        &mut self,
        stack: &mut Vec<usize>,
        kind: FrameKind,
        name: String,
        header: Option<usize>,
        params: Vec<String>,
    ) {
        let parent = *stack.last().unwrap_or(&0);
        let parent_phase = self.frames[parent].phase;
        let phase = if kind == FrameKind::Control {
            parent_phase
        } else {
            Phase::Decl
        };
        self.frames.push(Frame {
            kind,
            name,
            parent: Some(parent),
            parent_phase,
            phase,
            header,
            params,
            handled: BTreeSet::new(),
            stmt_lo: self.stmts.len(),
            stmt_hi: usize::MAX,
            frame_hi: usize::MAX,
        });
        stack.push(self.frames.len() - 1);
    }

    /// `A, B : [aliased] [constant] T [:= init] [with aspects];` in a declarative part.
    fn parse_decl(&self, index: usize) -> Option<Decl> {
        let stmt = self.stmts[index];
        if stmt.kind != StmtKind::Plain || stmt.phase != Phase::Decl {
            return None;
        }
        let toks = &self.toks[stmt.lo..stmt.hi];
        let mut names = Vec::new();
        let mut j = 0;
        loop {
            let t = toks.get(j)?;
            if t.kind != Kind::Ident || is_reserved(&t.text) {
                return None;
            }
            names.push(t.text.clone());
            j += 1;
            if toks.get(j)?.sym(",") {
                j += 1;
                continue;
            }
            if toks.get(j)?.sym(":") {
                j += 1;
                break;
            }
            return None;
        }
        let mut constant = false;
        while let Some(t) = toks.get(j) {
            if t.is("aliased") {
                j += 1;
            } else if t.is("constant") {
                constant = true;
                j += 1;
            } else {
                break;
            }
        }
        if toks.get(j).is_some_and(|t| t.is("exception")) {
            return None;
        }
        let ty_lo = stmt.lo + j;
        let mut depth = 0usize;
        let (mut init_at, mut with_at) = (None, None);
        for (k, t) in toks.iter().enumerate().skip(j) {
            if t.sym("(") {
                depth += 1;
            } else if t.sym(")") {
                depth = depth.saturating_sub(1);
            } else if depth == 0 {
                if t.sym(":=") && init_at.is_none() && with_at.is_none() {
                    init_at = Some(stmt.lo + k);
                } else if t.is("with") && with_at.is_none() {
                    with_at = Some(stmt.lo + k);
                } else if t.is("renames") {
                    return None;
                }
            }
        }
        let ty_hi = init_at.or(with_at).unwrap_or(stmt.hi);
        let init = init_at.map(|at| (at + 1, with_at.unwrap_or(stmt.hi)));
        let aspects = with_at.map(|at| (at + 1, stmt.hi));
        Some(Decl {
            names,
            frame: stmt.frame,
            stmt: index,
            constant,
            ty: (ty_lo, ty_hi),
            init,
            aspects,
        })
    }

    /// Nearest enclosing subprogram / task body frame (inclusive).
    fn routine_of(&self, mut frame: usize) -> Option<usize> {
        loop {
            match self.frames[frame].kind {
                FrameKind::Subprogram | FrameKind::Task => return Some(frame),
                FrameKind::Package | FrameKind::Protected | FrameKind::Unit => return None,
                _ => frame = self.frames[frame].parent?,
            }
        }
    }

    /// Whether `inner` is `outer` or nested inside it.
    fn within(&self, mut inner: usize, outer: usize) -> bool {
        loop {
            if inner == outer {
                return true;
            }
            match self.frames[inner].parent {
                Some(parent) => inner = parent,
                None => return false,
            }
        }
    }

    fn resolve(&self, frame: usize, name: &str) -> Binding {
        let mut current = Some(frame);
        let mut inside_routine = true;
        while let Some(f) = current {
            for &d in &self.decls_by_frame[f] {
                if self.decls[d].names.iter().any(|n| n == name) {
                    return if inside_routine {
                        Binding::Local(d)
                    } else {
                        Binding::Library(d)
                    };
                }
            }
            let fr = &self.frames[f];
            if matches!(fr.kind, FrameKind::Subprogram | FrameKind::Task) {
                if inside_routine && fr.params.iter().any(|p| p == name) {
                    return Binding::Param;
                }
                // Objects of an enclosing routine are still stack objects, but they
                // outlive this nested routine's frame: treat them as non-local.
                inside_routine = false;
            }
            current = fr.parent;
        }
        Binding::Unknown
    }

    /// Statements nested anywhere inside `frame`, with their indices.
    fn stmts_in(&self, frame: usize) -> impl Iterator<Item = (usize, &Stmt)> + '_ {
        let f = &self.frames[frame];
        (f.stmt_lo..f.stmt_hi.min(self.stmts.len()))
            .map(move |i| (i, &self.stmts[i]))
            .filter(move |(_, s)| self.within(s.frame, frame))
    }

    fn decl_at(&self, stmt: usize) -> Option<&Decl> {
        self.decl_of_stmt
            .get(stmt)
            .copied()
            .flatten()
            .map(|d| &self.decls[d])
    }

    fn stmt_toks(&self, stmt: &Stmt) -> &[Tok] {
        &self.toks[stmt.lo..stmt.hi]
    }

    fn text(&self, lo: usize, hi: usize) -> String {
        self.toks[lo..hi]
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Recognize a construct header ending in `is` that opens a frame. The third
/// element says the frame opens even before `new` (task/protected specs).
fn header_kind(toks: &[Tok]) -> Option<(FrameKind, String, bool)> {
    let mut j = 0;
    loop {
        match toks.get(j) {
            Some(t) if t.is("overriding") || t.is("generic") || t.is("private") => j += 1,
            Some(t) if t.is("not") && toks.get(j + 1).is_some_and(|n| n.is("overriding")) => j += 2,
            Some(t) if t.is("separate") => {
                j += 1;
                if toks.get(j).is_some_and(|n| n.sym("(")) {
                    while toks.get(j).is_some_and(|n| !n.sym(")")) {
                        j += 1;
                    }
                    j += 1;
                }
            }
            _ => break,
        }
    }
    let first = toks.get(j)?;
    let name_after = |k: usize| -> String {
        let mut name = String::new();
        let mut m = k;
        while let Some(t) = toks.get(m) {
            if matches!(t.kind, Kind::Ident | Kind::Str) && !is_reserved(&t.text) {
                name = t.text.clone();
                m += 1;
                if toks.get(m).is_some_and(|d| d.sym(".")) {
                    m += 1;
                    continue;
                }
            }
            break;
        }
        name
    };
    match first.text.as_str() {
        "procedure" | "function" | "entry" if first.kind == Kind::Ident => {
            Some((FrameKind::Subprogram, name_after(j + 1), false))
        }
        "package" if first.kind == Kind::Ident => {
            let body = toks.get(j + 1).is_some_and(|t| t.is("body"));
            Some((
                FrameKind::Package,
                name_after(j + 1 + usize::from(body)),
                false,
            ))
        }
        "task" | "protected" if first.kind == Kind::Ident => {
            let next = toks.get(j + 1);
            if next.is_some_and(|t| t.is("body")) {
                let kind = if first.is("task") {
                    FrameKind::Task
                } else {
                    FrameKind::Protected
                };
                Some((kind, name_after(j + 2), false))
            } else {
                let skip = usize::from(next.is_some_and(|t| t.is("type")));
                Some((FrameKind::Control, name_after(j + 1 + skip), true))
            }
        }
        "case" if first.kind == Kind::Ident => Some((FrameKind::Control, String::new(), true)),
        _ => None,
    }
}

/// Formal parameter names of a subprogram / entry header.
fn header_params(toks: &[Tok]) -> Vec<String> {
    let Some(open) = toks.iter().position(|t| t.sym("(")) else {
        return Vec::new();
    };
    let mut params = Vec::new();
    let mut pending = Vec::new();
    let mut depth = 0usize;
    let mut in_names = true;
    for t in &toks[open..] {
        if t.sym("(") {
            depth += 1;
            if depth == 1 {
                in_names = true;
                pending.clear();
            }
            continue;
        }
        if t.sym(")") {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                break;
            }
            continue;
        }
        if depth != 1 {
            continue;
        }
        if t.sym(";") {
            in_names = true;
            pending.clear();
        } else if t.sym(":") && in_names {
            params.append(&mut pending);
            in_names = false;
        } else if in_names && t.kind == Kind::Ident {
            pending.push(t.text.clone());
        }
    }
    params
}

// ───────────────────────── expression helpers ─────────────────────────

/// Index of the matching `)` for the `(` at `open`.
fn close_paren(toks: &[Tok], open: usize) -> Option<usize> {
    if !toks.get(open)?.sym("(") {
        return None;
    }
    let mut depth = 0usize;
    for (k, t) in toks.iter().enumerate().skip(open) {
        if t.sym("(") {
            depth += 1;
        } else if t.sym(")") {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(k);
            }
        }
    }
    None
}

/// The top-level arguments of the call whose `(` is at `open`, as token ranges,
/// each with its formal name when given in named notation.
fn call_args(toks: &[Tok], open: usize) -> Vec<(Option<String>, usize, usize)> {
    let Some(close) = close_paren(toks, open) else {
        return Vec::new();
    };
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = open + 1;
    for k in open + 1..=close {
        let t = &toks[k];
        if t.sym("(") {
            depth += 1;
        } else if t.sym(")") && depth > 0 {
            depth -= 1;
        } else if depth == 0 && (t.sym(",") || k == close) {
            if start < k {
                let named =
                    k > start + 1 && toks[start].kind == Kind::Ident && toks[start + 1].sym("=>");
                if named {
                    args.push((Some(toks[start].text.clone()), start + 2, k));
                } else {
                    args.push((None, start, k));
                }
            }
            start = k + 1;
        }
    }
    args
}

/// Pick a call argument by formal name, falling back to its position.
fn arg_by(
    args: &[(Option<String>, usize, usize)],
    names: &[&str],
    position: usize,
) -> Option<(usize, usize)> {
    if let Some((_, lo, hi)) = args
        .iter()
        .find(|(n, _, _)| n.as_deref().is_some_and(|n| names.contains(&n)))
    {
        return Some((*lo, *hi));
    }
    args.get(position)
        .filter(|(n, _, _)| n.is_none())
        .map(|(_, lo, hi)| (*lo, *hi))
}

/// The root identifier of a name at `k` (walking back over `A.B.C` and
/// `A (I).B` prefixes), as a token index.
fn name_root(toks: &[Tok], mut k: usize) -> usize {
    while k >= 2 {
        if toks[k - 1].sym(".") && toks[k - 2].kind == Kind::Ident {
            k -= 2;
        } else if toks[k - 1].sym(".") && toks[k - 2].sym(")") {
            let mut depth = 0usize;
            let mut m = k - 2;
            loop {
                if toks[m].sym(")") {
                    depth += 1;
                } else if toks[m].sym("(") {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                if m == 0 {
                    return k;
                }
                m -= 1;
            }
            if m == 0 || toks[m - 1].kind != Kind::Ident {
                return k;
            }
            k = m - 1;
        } else {
            break;
        }
    }
    k
}

/// The assignment target root of `X ... := ...`, if the statement is one.
fn assignment(toks: &[Tok], stmt: &Stmt) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    for k in stmt.lo..stmt.hi {
        let t = &toks[k];
        if t.sym("(") {
            depth += 1;
        } else if t.sym(")") {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && t.sym(":=") {
            return (toks[stmt.lo].kind == Kind::Ident && !is_reserved(&toks[stmt.lo].text))
                .then_some((stmt.lo, k));
        }
    }
    None
}

/// `word` as the whole identifier or its trailing `_`-delimited part.
fn has_word(ident: &str, word: &str) -> bool {
    ident == word
        || ident
            .strip_suffix(word)
            .is_some_and(|head| head.ends_with('_'))
        || ident
            .strip_prefix(word)
            .is_some_and(|tail| tail.starts_with('_'))
        || ident.contains(&format!("_{word}_"))
}

fn is_literal_expr(model: &Model, frame: usize, lo: usize, hi: usize) -> bool {
    lo < hi
        && model.toks[lo..hi]
            .iter()
            .enumerate()
            .all(|(off, t)| match t.kind {
                Kind::Str | Kind::Char | Kind::Num => true,
                Kind::Sym => matches!(t.text.as_str(), "&" | "(" | ")"),
                Kind::Ident => {
                    // Another constant whose own value is literal.
                    let k = lo + off;
                    let qualified = k > lo && model.toks[k - 1].sym(".");
                    !qualified && constant_literal(model, frame, &t.text, 0)
                }
            })
}

fn constant_literal(model: &Model, frame: usize, name: &str, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    let decl = match model.resolve(frame, name) {
        Binding::Local(d) | Binding::Library(d) => d,
        _ => return false,
    };
    let decl = &model.decls[decl];
    let Some((lo, hi)) = decl.init else {
        return false;
    };
    decl.constant
        && lo < hi
        && model.toks[lo..hi].iter().all(|t| match t.kind {
            Kind::Str | Kind::Char | Kind::Num => true,
            Kind::Sym => matches!(t.text.as_str(), "&" | "(" | ")"),
            Kind::Ident => constant_literal(model, decl.frame, &t.text, depth + 1),
        })
}

/// Identifier tokens of `lo..hi` that are not part of an attribute or a
/// selected-component suffix.
fn plain_idents(toks: &[Tok], lo: usize, hi: usize) -> impl Iterator<Item = usize> + '_ {
    (lo..hi).filter(move |&k| {
        toks[k].kind == Kind::Ident
            && !is_reserved(&toks[k].text)
            && !(k > 0 && (toks[k - 1].sym("'") || toks[k - 1].sym(".")))
    })
}

// ───────────────────────────── findings ─────────────────────────────

struct Ctx<'a> {
    #[allow(dead_code)]
    root: &'a Path,
    #[allow(dead_code)]
    path: &'a Path,
    lines: Vec<&'a str>,
    model: &'a Model,
}

struct Hit {
    rule: &'static str,
    slug: &'static str,
    message: &'static str,
    kind: &'static str,
    detail: String,
    tok: usize,
}

fn hit(
    out: &mut Vec<Hit>,
    tok: usize,
    rule: &'static str,
    slug: &'static str,
    message: &'static str,
    kind: &'static str,
    detail: String,
) {
    out.push(Hit {
        rule,
        slug,
        message,
        kind,
        detail,
        tok,
    });
}

/// BHF-402: an exception handler whose `others` alternative does nothing but
/// `null`. `when others => null` in a case statement is not a handler.
fn broad_null_handler(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for (i, choice) in m.stmts.iter().enumerate() {
        if choice.kind != StmtKind::Choice || choice.phase != Phase::Handler {
            continue;
        }
        if !m.stmt_toks(choice).iter().any(|t| t.is("others")) {
            continue;
        }
        let body: Vec<&Stmt> = m.stmts[i + 1..]
            .iter()
            .take_while(|s| {
                !(s.frame == choice.frame && matches!(s.kind, StmtKind::Choice | StmtKind::End))
            })
            .collect();
        let only_null = body.len() == 1 && {
            let t = m.stmt_toks(body[0]);
            t.len() == 1 && t[0].is("null")
        };
        let frame = &m.frames[choice.frame];
        // Finalize must not propagate, so swallowing there is the required
        // idiom; and a guard around nothing but cleanup/logging masks nothing.
        let in_finalize = frame.kind == FrameKind::Subprogram
            && matches!(frame.name.as_str(), "finalize" | "adjust")
            && is_controlled_signature(m, frame);
        if only_null && !in_finalize && !guards_only_cleanup(m, choice.frame) {
            hit(
                out,
                choice.lo,
                "BHF-402",
                "broad-exception-suppression",
                "Broad Ada exception handler suppresses all failures",
                "handler",
                "A when others handler immediately discards the exception.".to_owned(),
            );
        }
    }
}

const CLEANUP_WORDS: &[&str] = &[
    "close",
    "delete",
    "free",
    "remove",
    "release",
    "destroy",
    "dispose",
    "unlock",
    "finalize",
    "flush",
    "put",
    "new_line",
    "log",
    "trace",
    "kill",
    "abort",
    "set_modification_time",
    "shutdown",
];

/// Whether the statements a handler protects are only `null` or calls to
/// cleanup / logging operations (conditions and loops around them allowed;
/// a nested block with its own handlers is not).
fn guards_only_cleanup(m: &Model, frame: usize) -> bool {
    let nested_block =
        (frame + 1..m.frames[frame].frame_hi).any(|f| m.frames[f].kind != FrameKind::Control);
    if nested_block {
        return false;
    }
    m.stmts_in(frame)
        .map(|(_, s)| s)
        .filter(|s| s.phase == Phase::Body && s.kind == StmtKind::Plain)
        .all(|s| {
            let t = m.stmt_toks(s);
            if t.len() == 1 && t[0].is("null") {
                return true;
            }
            if assignment(&m.toks, s).is_some() || t.first().is_some_and(|x| is_reserved(&x.text)) {
                return false;
            }
            // The called name: last identifier before the first `(` (or the end).
            let callee = t
                .iter()
                .take_while(|x| !x.sym("("))
                .filter(|x| x.kind == Kind::Ident)
                .last();
            callee.is_some_and(|c| CLEANUP_WORDS.iter().any(|w| c.text.contains(w)))
        })
}

/// Whether the subprogram enclosing `frame` states the invariant a check
/// suppression relies on (`pragma Assert`, a `Pre` aspect), or the unit is SPARK.
fn suppression_justified(m: &Model, frame: usize) -> bool {
    let spark = m.toks.windows(3).any(|w| {
        w[0].is("spark_mode")
            && !(w[1].sym("(") && w[2].is("off"))
            && !(w[1].sym("=>") && w[2].is("off"))
    });
    if spark {
        return true;
    }
    let Some(routine) = m.routine_of(frame) else {
        return false;
    };
    let asserts = m.stmts_in(routine).any(|(_, s)| {
        let t = m.stmt_toks(s);
        t.len() > 1 && t[0].is("pragma") && (t[1].is("assert") || t[1].is("assume"))
    });
    let pre = m.frames[routine].header.is_some_and(|h| {
        let t = m.stmt_toks(&m.stmts[h]);
        t.windows(2)
            .any(|w| w[0].is("pre") && (w[1].sym("=>") || w[1].sym("'")))
    });
    asserts || pre
}

/// BHF-564 / BHF-565: `pragma Suppress` of a memory-safety or overflow check.
fn suppressed_checks(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for stmt in &m.stmts {
        let toks = m.stmt_toks(stmt);
        if toks.len() < 4 || !toks[0].is("pragma") {
            continue;
        }
        let check = if toks[1].is("suppress") && toks[2].sym("(") {
            toks[3].text.as_str()
        } else if toks[1].is("suppress_all") {
            "all_checks"
        } else {
            continue;
        };
        let (rule, slug, message) = match check {
            "index_check" | "range_check" | "length_check" | "all_checks" => (
                "BHF-564",
                "ada-runtime-check-suppressed",
                "Ada index/range checks suppressed",
            ),
            "overflow_check" => (
                "BHF-565",
                "ada-overflow-check-suppressed",
                "Ada overflow check suppressed",
            ),
            _ => continue,
        };
        if suppression_justified(m, stmt.frame) {
            continue;
        }
        hit(
            out,
            stmt.lo,
            rule,
            slug,
            message,
            "check_suppression",
            format!(
                "pragma Suppress ({}) removes the run-time check; a bad index, range or arithmetic result is no longer caught and becomes erroneous execution.",
                ctx.lines
                    .get(toks[3].line)
                    .and_then(|l| l.get(toks[3].col..toks[3].col + toks[3].text.len()))
                    .unwrap_or(&toks[3].text)
            ),
        );
    }
}

/// BHF-566: `Local'Unchecked_Access` / `'Unrestricted_Access` stored outside, or
/// returned from, the subprogram that owns the object.
fn unchecked_access_escape(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for stmt in &m.stmts {
        if stmt.phase == Phase::Decl || stmt.kind != StmtKind::Plain {
            continue;
        }
        let Some(routine) = m.routine_of(stmt.frame) else {
            continue;
        };
        let returns = m.toks[stmt.lo].is("return");
        let target = assignment(&m.toks, stmt);
        if !returns && target.is_none() {
            continue;
        }
        // The attribute must BE the stored/returned value, not a call actual.
        let (mut expr_lo, mut expr_hi) = match target {
            Some((_, eq)) => (eq + 1, stmt.hi),
            None => (stmt.lo + 1, stmt.hi),
        };
        if expr_hi > expr_lo + 2
            && m.toks[expr_lo].kind == Kind::Ident
            && m.toks[expr_lo + 1].sym("(")
            && close_paren(&m.toks, expr_lo + 1) == Some(expr_hi - 1)
        {
            // A type conversion wrapper `T (X'Unchecked_Access)`.
            expr_lo += 2;
            expr_hi -= 1;
        }
        for k in stmt.lo + 2..stmt.hi {
            let attr = &m.toks[k];
            if !(attr.is("unchecked_access") || attr.is("unrestricted_access"))
                || !m.toks[k - 1].sym("'")
                || m.toks[k - 2].kind != Kind::Ident
                || k + 1 != expr_hi
            {
                continue;
            }
            let root = name_root(&m.toks, k - 2);
            if root != expr_lo || m.toks[root..k].iter().any(|t| t.is("all")) {
                continue;
            }
            let Binding::Local(decl) = m.resolve(stmt.frame, &m.toks[root].text) else {
                continue;
            };
            if !m.within(m.decls[decl].frame, routine) {
                continue;
            }
            let escapes = returns
                || target.is_some_and(|(lhs, _)| {
                    !matches!(m.resolve(stmt.frame, &m.toks[lhs].text), Binding::Local(_))
                });
            if escapes {
                hit(
                    out,
                    root,
                    "BHF-566",
                    "ada-local-access-escape",
                    "Access to a local object escapes its subprogram",
                    "dangling_access",
                    format!(
                        "'{}' of local object {} is {}; the access value dangles once {} returns.",
                        attr.text,
                        m.toks[root].text,
                        if returns {
                            "returned"
                        } else {
                            "stored in a non-local object"
                        },
                        m.frames[routine].name
                    ),
                );
            }
        }
    }
}

/// BHF-567: an object overlaid onto another object's storage via an address
/// clause / `Address` aspect (type-breaking reinterpretation).
fn address_overlay(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for decl in &m.decls {
        let Some((lo, hi)) = decl.aspects else {
            continue;
        };
        for k in lo..hi.saturating_sub(1) {
            if m.toks[k].is("address") && m.toks[k + 1].sym("=>") {
                let expr_hi = (k + 2..hi).find(|&e| m.toks[e].sym(",")).unwrap_or(hi);
                overlay_hit(ctx, out, decl.frame, &decl.names[0], k, k + 2, expr_hi);
            }
        }
    }
    for stmt in &m.stmts {
        let toks = m.stmt_toks(stmt);
        if toks.len() > 5
            && toks[0].is("for")
            && toks[1].kind == Kind::Ident
            && toks[2].sym("'")
            && toks[3].is("address")
            && toks[4].is("use")
        {
            overlay_hit(
                ctx,
                out,
                stmt.frame,
                &toks[1].text,
                stmt.lo,
                stmt.lo + 5,
                stmt.hi,
            );
        }
    }
}

fn overlay_hit(
    ctx: &Ctx,
    out: &mut Vec<Hit>,
    frame: usize,
    overlay: &str,
    anchor: usize,
    lo: usize,
    hi: usize,
) {
    let m = ctx.model;
    // `Y'Address` or `Y (I)'Address` as the whole expression.
    if hi < lo + 3 || !m.toks[hi - 1].is("address") || !m.toks[hi - 2].sym("'") {
        return;
    }
    if m.toks[lo].kind != Kind::Ident || m.toks[lo].is("system") {
        return;
    }
    let target = m.toks[lo].text.clone();
    let type_of = |name: &str| match m.resolve(frame, name) {
        Binding::Local(d) | Binding::Library(d) => {
            let (a, b) = m.decls[d].ty;
            Some(m.text(a, b))
        }
        _ => None,
    };
    if let (Some(a), Some(b)) = (type_of(overlay), type_of(&target)) {
        if a == b {
            return;
        }
    }
    // A view whose bounds come from the target itself (`(1 .. Data'Length)`,
    // `Item'Size / 8`) is the standard byte-view idiom, sized to fit.
    let sized_from_target = match m.resolve(frame, overlay) {
        Binding::Local(d) | Binding::Library(d) => {
            let (a, b) = m.decls[d].ty;
            m.toks[a..b]
                .iter()
                .any(|t| t.kind == Kind::Ident && t.text == target)
        }
        _ => false,
    };
    if sized_from_target {
        return;
    }
    // Both objects sized by the same quantity (`(1 .. Info.Size)` on each side).
    let bound_idents = |name: &str| -> BTreeSet<String> {
        match m.resolve(frame, name) {
            Binding::Local(d) | Binding::Library(d) => {
                let (a, b) = m.decls[d].ty;
                let open = (a..b).find(|&k| m.toks[k].sym("(")).unwrap_or(b);
                m.toks[open..b]
                    .iter()
                    .filter(|t| t.kind == Kind::Ident && !is_reserved(&t.text))
                    .map(|t| t.text.clone())
                    .filter(|t| {
                        !matches!(
                            t.as_str(),
                            "natural"
                                | "positive"
                                | "integer"
                                | "stream_element_offset"
                                | "streams"
                                | "ada"
                                | "size"
                                | "length"
                                | "first"
                                | "last"
                        )
                    })
                    .collect()
            }
            _ => BTreeSet::new(),
        }
    };
    if !bound_idents(overlay).is_disjoint(&bound_idents(&target)) {
        return;
    }
    // A fixed-size view of a type with no invalid bit patterns (`Unsigned_8`,
    // `Stream_Element_Array (1 .. 16)`) cannot produce an invalid value.
    if let Binding::Local(d) | Binding::Library(d) = m.resolve(frame, overlay) {
        let (a, b) = m.decls[d].ty;
        if total_scalar_view(&m.toks[a..b]) {
            return;
        }
    }
    // A compile-time or run-time size check on the overlay states the invariant.
    let size_checked = m.stmts.iter().any(|s| {
        let t = m.stmt_toks(s);
        t.len() > 4
            && t[0].is("pragma")
            && matches!(
                t[1].text.as_str(),
                "compile_time_error" | "compile_time_warning" | "assert"
            )
            && t.windows(3)
                .any(|w| w[0].text == overlay && w[1].sym("'") && w[2].is("size"))
    });
    if size_checked {
        return;
    }
    hit(
        out,
        anchor,
        "BHF-567",
        "ada-address-overlay",
        "Ada object overlaid on another object's storage",
        "address_overlay",
        format!(
            "{overlay} is placed at {target}'Address; its bytes are reinterpreted without a validity check, and a size mismatch reads or writes past {target}."
        ),
    );
}

const TOTAL_SCALARS: &[&str] = &[
    "unsigned_8",
    "unsigned_16",
    "unsigned_32",
    "unsigned_64",
    "stream_element",
    "storage_element",
    "byte",
    "character",
    "stream_element_array",
    "storage_array",
    "byte_array",
    "string",
    "unsigned_char",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
];

/// `T` or `T (lit .. lit)` / `array (Natural range lit .. lit) of T` where `T`
/// has no invalid representations.
fn total_scalar_view(ty: &[Tok]) -> bool {
    let (mark, bounds): (Option<&Tok>, &[Tok]) = if ty.first().is_some_and(|t| t.is("array")) {
        let close = close_paren(ty, 1).unwrap_or(ty.len());
        (ty.last(), ty.get(2..close).unwrap_or(&[]))
    } else {
        let open = ty.iter().position(|t| t.sym("(")).unwrap_or(ty.len());
        let close = if open < ty.len() {
            close_paren(ty, open).unwrap_or(ty.len())
        } else {
            open
        };
        (
            ty[..open].iter().rev().find(|t| t.kind == Kind::Ident),
            ty.get(open + 1..close).unwrap_or(&[]),
        )
    };
    let literal_bounds = bounds.iter().all(|t| {
        t.kind == Kind::Num
            || t.sym("..")
            || t.sym(",")
            || t.is("range")
            || matches!(
                t.text.as_str(),
                "natural" | "positive" | "integer" | "stream_element_offset" | "storage_offset"
            )
    });
    mark.is_some_and(|m| TOTAL_SCALARS.contains(&m.text.as_str())) && literal_bounds
}

const UNSAFE_C: &[&str] = &[
    "strcpy", "strcat", "wcscpy", "wcscat", "sprintf", "vsprintf", "gets", "system", "popen",
    "_popen", "_wsystem", "_wpopen", "execl", "execlp", "execle", "execv", "execvp", "execvpe",
    "execve", "mktemp", "tmpnam", "tempnam",
];

/// BHF-568: an Ada binding to an unbounded-copy, shell or insecure-temp C function.
fn imported_unsafe_c(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for stmt in &m.stmts {
        let toks = m.stmt_toks(stmt);
        if toks.len() > 4 && toks[0].is("pragma") && toks[1].is("import") && toks[2].sym("(") {
            let args = call_args(&m.toks, stmt.lo + 2);
            let convention = arg_by(&args, &["convention"], 0).map(|(a, b)| m.text(a, b));
            if !convention.as_deref().is_some_and(is_c_convention) {
                continue;
            }
            let Some((ea, eb)) = arg_by(&args, &["entity"], 1) else {
                continue;
            };
            let external = arg_by(&args, &["external_name"], 2)
                .or_else(|| arg_by(&args, &["link_name"], 3))
                .filter(|(a, b)| b - a == 1 && m.toks[*a].kind == Kind::Str)
                .map(|(a, _)| m.toks[a].text.to_ascii_lowercase())
                .unwrap_or_else(|| m.text(ea, eb));
            if UNSAFE_C.contains(&external.as_str()) {
                imported_hit(out, stmt.lo, &external);
            }
            continue;
        }
        if !(toks
            .first()
            .is_some_and(|t| t.is("procedure") || t.is("function")))
        {
            continue;
        }
        let mut depth = 0usize;
        let Some(with_at) = (stmt.lo..stmt.hi).find(|&k| {
            let t = &m.toks[k];
            if t.sym("(") {
                depth += 1;
            } else if t.sym(")") {
                depth = depth.saturating_sub(1);
            }
            depth == 0 && t.is("with")
        }) else {
            continue;
        };
        let aspects = &m.toks[with_at + 1..stmt.hi];
        let imported = aspects.iter().enumerate().any(|(a, t)| {
            t.is("import")
                && !aspects
                    .get(a + 2)
                    .is_some_and(|v| aspects[a + 1].sym("=>") && v.is("false"))
        });
        let c = aspects
            .windows(3)
            .any(|w| w[0].is("convention") && w[1].sym("=>") && is_c_convention(&w[2].text));
        if !imported || !c {
            continue;
        }
        let named = aspects.windows(3).enumerate().find(|(_, w)| {
            (w[0].is("external_name") || w[0].is("link_name"))
                && w[1].sym("=>")
                && w[2].kind == Kind::Str
        });
        let (external, anchor) = match named {
            Some((a, w)) => (w[2].text.to_ascii_lowercase(), with_at + 1 + a + 2),
            None => (
                header_kind(toks).map(|(_, n, _)| n).unwrap_or_default(),
                stmt.lo,
            ),
        };
        if UNSAFE_C.contains(&external.as_str()) {
            imported_hit(out, anchor, &external);
        }
    }
}

fn is_c_convention(text: &str) -> bool {
    matches!(
        text,
        "c" | "c_pass_by_copy" | "cpp" | "stdcall" | "c_variadic_0" | "c_variadic_1"
    )
}

fn imported_hit(out: &mut Vec<Hit>, tok: usize, external: &str) {
    hit(
        out,
        tok,
        "BHF-568",
        "ada-imported-unsafe-c-function",
        "Ada binding imports an unsafe C function",
        "foreign_import",
        format!(
            "The C function {external} is imported; it has no bound or runs a shell, and Ada's checks do not apply across the call."
        ),
    );
}

const RELEASE_WORDS: &[&str] = &[
    "free", "release", "destroy", "dispose", "delete", "finalize",
];

/// Calls that keep the pointer they are given (a container insert, a list
/// append): ownership moves to the callee's data structure.
const STORE_WORDS: &[&str] = &[
    "insert", "add", "append", "prepend", "push", "store", "register", "attach", "take", "adopt",
    "enqueue", "include",
];

fn keeps_or_releases(name: &str) -> bool {
    RELEASE_WORDS
        .iter()
        .chain(STORE_WORDS)
        .any(|w| name.contains(w))
}

/// BHF-550 (Ada): `Interfaces.C.Strings.New_String` allocation never freed,
/// returned or stored by the subprogram that made it.
fn new_string_leak(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for (si, stmt) in m.stmts.iter().enumerate() {
        let Some(routine) = m.routine_of(stmt.frame) else {
            continue;
        };
        for k in stmt.lo..stmt.hi.saturating_sub(1) {
            if !(m.toks[k].is("new_string") && m.toks[k + 1].sym("(")) {
                continue;
            }
            if k > stmt.lo && m.toks[k - 1].sym("'") {
                continue;
            }
            let owner = if k >= stmt.lo + 2 && m.toks[k - 1].sym(":=") {
                // `V := New_String (...)` or a declaration initializer.
                let decl_name = m.decl_at(si).map(|d| d.names[0].clone());
                decl_name.or_else(|| {
                    assignment(&m.toks, stmt)
                        .filter(|(lhs, eq)| eq - lhs == 1)
                        .map(|(lhs, _)| m.toks[lhs].text.clone())
                })
            } else {
                None
            };
            match owner {
                Some(var) => {
                    let Binding::Local(_) = m.resolve(stmt.frame, &var) else {
                        continue;
                    };
                    if !released_or_escapes(m, routine, si, &var) {
                        leak_hit(out, k, Some(&var));
                    }
                }
                None => {
                    let inline_arg = k > stmt.lo
                        && (m.toks[k - 1].sym("(")
                            || m.toks[k - 1].sym(",")
                            || m.toks[k - 1].sym("=>"));
                    let call_stmt = !m.toks[stmt.lo].is("return")
                        && assignment(&m.toks, stmt).is_none()
                        && stmt.phase != Phase::Decl;
                    let into_release = (stmt.lo..k).any(|c| {
                        m.toks[c].kind == Kind::Ident && keeps_or_releases(&m.toks[c].text)
                    });
                    if inline_arg && call_stmt && !into_release {
                        leak_hit(out, k, None);
                    }
                }
            }
        }
    }
}

fn released_or_escapes(m: &Model, routine: usize, from: usize, var: &str) -> bool {
    m.stmts_in(routine).any(|(si, stmt)| {
        if si == from {
            return false;
        }
        let mentions: Vec<usize> = (stmt.lo..stmt.hi).filter(|&k| m.toks[k].is(var)).collect();
        if mentions.is_empty() {
            return false;
        }
        if m.toks[stmt.lo].is("return") {
            return true;
        }
        if let Some((lhs, eq)) = assignment(&m.toks, stmt) {
            // Stored or aliased: `X := V` / `Obj.F := V`.
            if mentions.iter().any(|&k| k > eq) {
                return true;
            }
            let _ = lhs;
        }
        // Passed to a release/ownership-taking call, or as an out/in out actual we
        // cannot see into.
        (stmt.lo..stmt.hi).any(|k| {
            m.toks[k].kind == Kind::Ident
                && m.toks.get(k + 1).is_some_and(|t| t.sym("("))
                && keeps_or_releases(&m.toks[k].text)
        })
    })
}

fn leak_hit(out: &mut Vec<Hit>, tok: usize, var: Option<&str>) {
    hit(
        out,
        tok,
        "BHF-550",
        "resource-leak",
        "C string from New_String is never freed",
        "resource_leak",
        match var {
            Some(v) => format!(
                "{v} holds a New_String allocation that is never passed to Free, returned or stored, so each call leaks it."
            ),
            None => "A New_String allocation is passed straight into a call and never freed, so each call leaks it.".to_owned(),
        },
    );
}

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "csh",
    "tcsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
];

/// BHF-412: process spawn whose program is not a constant, or a shell given a
/// non-constant command.
fn command_spawn(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for stmt in &m.stmts {
        if stmt.kind == StmtKind::Header
            || ["procedure", "function", "pragma", "overriding", "not"]
                .iter()
                .any(|w| m.toks[stmt.lo].is(w))
        {
            continue;
        }
        for k in stmt.lo..stmt.hi.saturating_sub(1) {
            let name = &m.toks[k];
            let is_spawn = matches!(
                name.text.as_str(),
                "spawn" | "non_blocking_spawn" | "get_command_output"
            ) && name.kind == Kind::Ident;
            if !is_spawn || !m.toks[k + 1].sym("(") || (k > 0 && m.toks[k - 1].sym("'")) {
                continue;
            }
            let args = call_args(&m.toks, k + 1);
            if args.is_empty() {
                continue;
            }
            // GNAT.Expect.Non_Blocking_Spawn and Util.Processes.Spawn take the
            // process object first.
            let first_is_process = args[0]
                .0
                .as_deref()
                .is_some_and(|n| matches!(n, "descriptor" | "proc" | "process" | "pd"))
                || (args[0].0.is_none() && is_process_handle(m, stmt.frame, args[0].1, args[0].2));
            let program_pos = usize::from(first_is_process);
            let Some((plo, phi)) = arg_by(&args, &["program_name", "command"], program_pos) else {
                continue;
            };
            if !program_is_text(m, stmt.frame, plo, phi) {
                continue;
            }
            // A formal parameter passed straight through: the caller chooses the
            // program, and the taint engine follows that call edge.
            if phi - plo == 1 && m.resolve(stmt.frame, &m.toks[plo].text) == Binding::Param {
                continue;
            }
            let program_fixed = fixed_program(m, stmt.frame, plo, phi);
            let detail = match program_fixed {
                None => format!(
                    "The program {} is not a constant; whoever controls it chooses what runs.",
                    m.text(plo, phi)
                ),
                Some(ref prog) if is_shell(prog) => {
                    let rest_dynamic = args.iter().any(|&(_, a, b)| {
                        a != plo && !is_literal_expr(m, stmt.frame, a, b) && {
                            // Output/status actuals are names, not command text.
                            let single = b - a == 1 && m.toks[a].kind == Kind::Ident;
                            !(single && looks_like_status(&m.toks[a].text))
                        }
                    });
                    if !rest_dynamic {
                        continue;
                    }
                    format!(
                        "{prog} is run with a non-constant argument list; a shell interprets that text as commands."
                    )
                }
                Some(_) => continue,
            };
            hit(
                out,
                k,
                "BHF-412",
                "ada-process-runtime-dependency",
                "Process spawned with a non-constant program or shell command",
                "ada_runtime_dependency",
                detail,
            );
        }
    }
}

fn type_of_name(m: &Model, frame: usize, name: &str) -> Option<String> {
    match m.resolve(frame, name) {
        Binding::Local(d) | Binding::Library(d) => {
            let (a, b) = m.decls[d].ty;
            Some(m.text(a, b))
        }
        Binding::Param => param_type(m, frame, name),
        Binding::Unknown => None,
    }
}

/// A process / descriptor object actual (`Proc`, `Stream.Proc`, `Desc`).
fn is_process_handle(m: &Model, frame: usize, lo: usize, hi: usize) -> bool {
    let toks = &m.toks[lo..hi];
    if toks
        .iter()
        .any(|t| matches!(t.kind, Kind::Str | Kind::Char) || t.sym("&") || t.sym("("))
    {
        return false;
    }
    let Some(last) = toks.iter().rev().find(|t| t.kind == Kind::Ident) else {
        return false;
    };
    let named = matches!(
        last.text.as_str(),
        "p" | "proc" | "process" | "pd" | "desc" | "descriptor"
    ) || last.text.ends_with("_proc")
        || last.text.ends_with("_process")
        || last.text.contains("descriptor");
    named
        || (toks.len() == 1
            && type_of_name(m, frame, &last.text)
                .is_some_and(|t| t.contains("process") || t.contains("descriptor")))
}

/// Whether the program actual can be command text: not an enumeration-like mode
/// literal, and not a name whose declared type is plainly not a string.
fn program_is_text(m: &Model, frame: usize, lo: usize, hi: usize) -> bool {
    let toks = &m.toks[lo..hi];
    let Some(last) = toks.last() else {
        return false;
    };
    let simple_name = toks.iter().all(|t| t.kind == Kind::Ident || t.sym("."));
    if simple_name
        && (last.text.ends_with("mode")
            || matches!(
                last.text.as_str(),
                "none"
                    | "read"
                    | "write"
                    | "read_all"
                    | "write_all"
                    | "read_write"
                    | "read_write_all"
                    | "read_error"
                    | "read_write_error"
            ))
    {
        return false;
    }
    if toks.len() == 1 && last.kind == Kind::Ident {
        if let Some(ty) = type_of_name(m, frame, &last.text) {
            return [
                "string",
                "str",
                "name",
                "path",
                "command",
                "cmd",
                "unbounded",
                "access",
            ]
            .iter()
            .any(|w| ty.contains(w));
        }
    }
    true
}

fn param_type(m: &Model, frame: usize, name: &str) -> Option<String> {
    let routine = m.routine_of(frame)?;
    let header = m.frames[routine].header?;
    let stmt = m.stmts[header];
    let toks = m.stmt_toks(&stmt);
    let at = toks.iter().position(|t| t.is(name))?;
    let colon = (at..toks.len()).find(|&k| toks[k].sym(":"))?;
    let end = (colon..toks.len())
        .find(|&k| toks[k].sym(";") || toks[k].sym(")"))
        .unwrap_or(toks.len());
    Some(
        toks[colon + 1..end]
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn looks_like_status(name: &str) -> bool {
    [
        "success", "ok", "status", "result", "code", "output", "pid", "fd", "file", "err",
    ]
    .iter()
    .any(|w| has_word(name, w))
}

fn is_shell(program: &str) -> bool {
    let base = program.rsplit(['/', '\\']).next().unwrap_or(program);
    SHELLS.contains(&base.to_ascii_lowercase().as_str())
}

/// The program text when the program actual is a constant: a literal, a literal
/// constant, or a `Locate_Exec_On_Path ("lit")` lookup (directly or through a
/// variable it initialized).
fn fixed_program(m: &Model, frame: usize, lo: usize, hi: usize) -> Option<String> {
    let toks = &m.toks[lo..hi];
    if toks.len() == 1 && toks[0].kind == Kind::Str {
        return Some(toks[0].text.clone());
    }
    let literal_of = |a: usize, b: usize| -> Option<String> {
        is_literal_expr(m, frame, a, b).then(|| {
            m.toks[a..b]
                .iter()
                .filter(|t| t.kind == Kind::Str)
                .map(|t| t.text.as_str())
                .collect()
        })
    };
    if let Some(text) = literal_of(lo, hi) {
        return Some(text);
    }
    if let Some(found) = locate_literal(m, lo, hi) {
        return Some(found);
    }
    // `Name.all` / `Name` where Name was initialized or assigned from a lookup.
    let name = toks.first().filter(|t| t.kind == Kind::Ident)?;
    let simple = toks.len() == 1 || (toks.len() == 3 && toks[1].sym(".") && toks[2].is("all"));
    if !simple {
        return None;
    }
    if let Binding::Local(d) | Binding::Library(d) = m.resolve(frame, &name.text) {
        if let Some((a, b)) = m.decls[d].init {
            if let Some(found) = locate_literal(m, a, b).or_else(|| {
                constant_literal(m, frame, &name.text, 0)
                    .then(|| literal_of(a, b))
                    .flatten()
            }) {
                return Some(found);
            }
        }
        let routine = m.routine_of(frame)?;
        return m.stmts_in(routine).find_map(|(_, s)| {
            let (lhs, eq) = assignment(&m.toks, s)?;
            (eq - lhs == 1 && m.toks[lhs].text == name.text)
                .then(|| locate_literal(m, eq + 1, s.hi))
                .flatten()
        });
    }
    None
}

fn locate_literal(m: &Model, lo: usize, hi: usize) -> Option<String> {
    let at = (lo..hi)
        .find(|&k| m.toks[k].is("locate_exec_on_path") || m.toks[k].is("locate_regular_file"))?;
    let open = at + 1;
    if !m.toks.get(open)?.sym("(") {
        return None;
    }
    let first = m.toks.get(open + 1)?;
    (first.kind == Kind::Str && m.toks.get(open + 2)?.sym(")") || m.toks.get(open + 2)?.sym(","))
        .then(|| first.text.clone())
        .filter(|_| first.kind == Kind::Str)
}

const SQL_CALLS: &[&str] = &[
    "execute",
    "fetch",
    "prepare",
    "create_statement",
    "sqlexecdirect",
    "sqlprepare",
    "exec",
    "exec_direct",
    "execute_query",
    "execute_update",
    "set_query",
    "set_sql",
    "prepare_statement",
];

fn looks_like_sql(text: &str) -> bool {
    let up = format!(" {} ", text.to_ascii_uppercase());
    (up.contains("SELECT ") && up.contains(" FROM "))
        || up.contains("INSERT INTO ")
        || (up.contains("UPDATE ") && up.contains(" SET "))
        || up.contains("DELETE FROM ")
        || up.contains(" WHERE ")
        || up.contains(" ORDER BY ")
        || up.contains(" VALUES")
}

/// An `&`-built expression with SQL text and at least one operand that is neither
/// a literal, a constant, a numeric image nor a quoting call.
fn dynamic_sql(m: &Model, frame: usize, lo: usize, hi: usize) -> bool {
    let has_sql = m.toks[lo..hi]
        .iter()
        .any(|t| t.kind == Kind::Str && looks_like_sql(&t.text));
    if !has_sql {
        return false;
    }
    let mut operands = Vec::new();
    let (mut depth, mut start) = (0usize, lo);
    for k in lo..hi {
        let t = &m.toks[k];
        if t.sym("(") {
            depth += 1;
        } else if t.sym(")") {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && t.sym("&") {
            operands.push((start, k));
            start = k + 1;
        }
    }
    operands.push((start, hi));
    if operands.len() < 2 {
        return false;
    }
    operands.iter().any(|&(a, b)| {
        if a >= b || is_literal_expr(m, frame, a, b) {
            return false;
        }
        let toks = &m.toks[a..b];
        let image = toks.windows(2).any(|w| {
            w[0].sym("'")
                && matches!(
                    w[1].text.as_str(),
                    "image" | "img" | "length" | "first" | "last"
                )
        });
        let quoted = toks.iter().any(|t| {
            t.kind == Kind::Ident && (t.text.contains("quote") || t.text.contains("escape"))
        });
        let unary_plus = toks.first().is_some_and(|t| t.sym("+"));
        !(image || quoted || unary_plus)
    })
}

/// BHF-419 (Ada): a SQL execution call whose query is built by `&` concatenation
/// of non-constant text, directly or through a local constant/variable.
fn sql_concatenation(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for stmt in &m.stmts {
        if stmt.kind == StmtKind::Header
            || m.toks[stmt.lo].is("procedure")
            || m.toks[stmt.lo].is("function")
        {
            continue;
        }
        for k in stmt.lo..stmt.hi.saturating_sub(1) {
            let name = &m.toks[k];
            if name.kind != Kind::Ident
                || !SQL_CALLS.contains(&name.text.as_str())
                || !m.toks[k + 1].sym("(")
            {
                continue;
            }
            let args = call_args(&m.toks, k + 1);
            let dynamic = args.iter().any(|&(_, a, b)| {
                if dynamic_sql(m, stmt.frame, a, b) {
                    return true;
                }
                // One hop through a local query object.
                if b - a != 1 || m.toks[a].kind != Kind::Ident {
                    return false;
                }
                let var = &m.toks[a].text;
                let Binding::Local(d) = m.resolve(stmt.frame, var) else {
                    return false;
                };
                let decl = &m.decls[d];
                if decl
                    .init
                    .is_some_and(|(x, y)| dynamic_sql(m, decl.frame, x, y))
                {
                    return true;
                }
                let Some(routine) = m.routine_of(stmt.frame) else {
                    return false;
                };
                m.stmts_in(routine).any(|(_, s)| {
                    assignment(&m.toks, s).is_some_and(|(lhs, eq)| {
                        eq - lhs == 1
                            && m.toks[lhs].text == *var
                            && dynamic_sql(m, s.frame, eq + 1, s.hi)
                    })
                })
            });
            if dynamic {
                hit(
                    out,
                    k,
                    "BHF-419",
                    "sql-injection-dynamic-query",
                    "SQL query built by string concatenation",
                    "sql",
                    format!(
                        "{} runs SQL text concatenated from non-constant values; bind them as query parameters instead.",
                        ctx.lines
                            .get(name.line)
                            .and_then(|l| l.get(name.col..name.col + name.text.len()))
                            .unwrap_or(&name.text)
                    ),
                );
            }
        }
    }
}

const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "secret_key",
    "access_token",
    "auth_token",
    "session_token",
    "refresh_token",
    "bearer_token",
    "client_secret",
];

const SECRET_EXCLUDE: &[&str] = &[
    "_file",
    "_prompt",
    "_len",
    "_length",
    "_kind",
    "_type",
    "_env",
    "_name",
    "_id",
    "_hash",
    "_digest",
    "_policy",
    "_field",
    "_label",
    "_path",
    "_size",
    "_count",
    "_min",
    "_max",
    "_required",
    "_changed",
    "_expir",
    "_valid",
    "_ok",
    "_set",
    "_mode",
    "_flag",
    "_option",
    "_param",
    "_char",
    "_entry",
    "_widget",
    "_dialog",
    "_button",
    "_salt",
    "_last",
    "_first",
];

fn is_secret_name(ident: &str) -> bool {
    SECRET_WORDS.iter().any(|w| has_word(ident, w))
        && !SECRET_EXCLUDE.iter().any(|x| ident.contains(x))
        && !ident.starts_with("is_")
        && !ident.starts_with("has_")
        && !ident.starts_with("no_")
}

const PASSTHROUGH: &[&str] = &[
    "to_string",
    "to_ada",
    "value",
    "trim",
    "to_wide_string",
    "to_unbounded_string",
    "image",
];

/// BHF-569: a password, secret key or token written to a log or the console.
fn secret_logged(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for stmt in &m.stmts {
        if stmt.phase == Phase::Decl || stmt.kind != StmtKind::Plain {
            continue;
        }
        for k in stmt.lo..stmt.hi.saturating_sub(1) {
            let name = &m.toks[k];
            if name.kind != Kind::Ident || !m.toks[k + 1].sym("(") {
                continue;
            }
            let prefix =
                (k >= stmt.lo + 2 && m.toks[k - 1].sym(".")).then(|| m.toks[k - 2].text.as_str());
            let is_log = match name.text.as_str() {
                "put_line" | "put" | "trace" | "log" => true,
                "debug" | "info" | "warn" | "warning" | "error" | "critical" | "fatal"
                | "notice" => prefix.is_some_and(|p| p.contains("log") || p.contains("trace")),
                _ => false,
            };
            if !is_log {
                continue;
            }
            let args = call_args(&m.toks, k + 1);
            if args.is_empty() {
                continue;
            }
            let mut first_arg = 0;
            if matches!(name.text.as_str(), "put_line" | "put") && args.len() >= 2 {
                let (_, a, b) = args[0];
                let file_like = m.toks[a..b]
                    .iter()
                    .all(|t| t.kind == Kind::Ident || t.sym(".") || t.sym("(") || t.sym(")"));
                if file_like {
                    let target = m.toks[b - 1].text.as_str();
                    let console = matches!(
                        target,
                        "standard_error" | "standard_output" | "current_error" | "current_output"
                    ) || m.toks[a..b]
                        .iter()
                        .any(|t| t.is("standard_error") || t.is("standard_output"));
                    if !console {
                        continue;
                    }
                    first_arg = 1;
                }
            }
            let secret = args[first_arg..].iter().find_map(|&(_, a, b)| {
                plain_idents(&m.toks, a, b).find(|&i| {
                    if !is_secret_name(&m.toks[i].text) {
                        return false;
                    }
                    if m.toks.get(i + 1).is_some_and(|t| t.sym("'")) {
                        return false;
                    }
                    if m.toks.get(i + 1).is_some_and(|t| t.sym("(")) {
                        // A call named like a secret (`Get_Password (...)`) still yields it.
                        return true;
                    }
                    // Only literal-preserving wrappers may sit between the call and
                    // the secret: `Hash (Password)` is not the password.
                    let mut depth = 0usize;
                    let mut j = i;
                    while j > a {
                        j -= 1;
                        let t = &m.toks[j];
                        if t.sym(")") {
                            depth += 1;
                        } else if t.sym("(") {
                            if depth == 0 {
                                let wrapper = m.toks.get(j.wrapping_sub(1)).filter(|_| j > a);
                                match wrapper {
                                    Some(w) if w.kind == Kind::Ident && !is_reserved(&w.text) => {
                                        if !PASSTHROUGH.contains(&w.text.as_str()) {
                                            return false;
                                        }
                                    }
                                    Some(w) if w.sym("'") => {}
                                    _ => {}
                                }
                            } else {
                                depth -= 1;
                            }
                        }
                    }
                    true
                })
            });
            if let Some(i) = secret {
                hit(
                    out,
                    k,
                    "BHF-569",
                    "ada-secret-logged",
                    "Secret value written to a log or the console",
                    "sensitive_output",
                    format!(
                        "{} is written to {}; logs and consoles are not secret storage.",
                        m.toks[i].text,
                        prefix.map_or(name.text.clone(), |p| format!("{p}.{}", name.text))
                    ),
                );
            }
        }
    }
}

/// BHF-570: a subprogram exported to C (or another foreign convention) whose
/// body has no `when others` handler, so an Ada exception unwinds through
/// foreign frames.
fn export_propagation(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    let no_propagation = m.stmts.iter().any(|s| {
        let t = m.stmt_toks(s);
        t.len() > 3
            && t[0].is("pragma")
            && (t[1].is("restrictions") || t[1].is("restriction_warnings"))
            && t.iter().any(|x| {
                x.is("no_exception_propagation")
                    || x.is("no_exceptions")
                    || x.is("no_exception_handlers")
            })
    });
    if no_propagation {
        return;
    }
    let mut exported = BTreeSet::new();
    for stmt in &m.stmts {
        let toks = m.stmt_toks(stmt);
        if toks.len() > 4 && toks[0].is("pragma") && toks[1].is("export") && toks[2].sym("(") {
            let args = call_args(&m.toks, stmt.lo + 2);
            let convention = arg_by(&args, &["convention"], 0).map(|(a, b)| m.text(a, b));
            if convention.as_deref().is_some_and(is_c_convention) {
                if let Some((a, b)) = arg_by(&args, &["entity"], 1) {
                    exported.insert(m.text(a, b));
                }
            }
        } else if toks
            .first()
            .is_some_and(|t| t.is("procedure") || t.is("function"))
            && stmt.kind != StmtKind::Header
        {
            let has = |w: &str| toks.iter().any(|t| t.is(w));
            let c = toks
                .windows(3)
                .any(|w| w[0].is("convention") && w[1].sym("=>") && is_c_convention(&w[2].text));
            if has("with") && has("export") && c {
                if let Some((_, name, _)) = header_kind(toks) {
                    exported.insert(name);
                }
            }
        }
    }
    for (fi, frame) in m.frames.iter().enumerate() {
        if frame.kind != FrameKind::Subprogram || !exported.contains(&frame.name) {
            continue;
        }
        if frame.handled.contains("others") {
            continue;
        }
        let body: Vec<&Stmt> = m
            .stmts_in(fi)
            .map(|(_, s)| s)
            .filter(|s| s.frame == fi && s.phase == Phase::Body && s.kind != StmtKind::End)
            .collect();
        let trivial = body.iter().all(|s| {
            let t = m.stmt_toks(s);
            t.len() == 1 && t[0].is("null")
        });
        let nested_any = m
            .stmts_in(fi)
            .any(|(_, s)| s.frame != fi && s.kind != StmtKind::End);
        if trivial && !nested_any {
            continue;
        }
        let Some(header) = frame.header else {
            continue;
        };
        hit(
            out,
            m.stmts[header].lo,
            "BHF-570",
            "ada-exception-propagation-from-export",
            "Exception can propagate out of a subprogram exported to C",
            "foreign_export",
            format!(
                "{} is exported with a foreign convention but has no `when others` handler; an Ada exception unwinding through C frames is undefined behavior.",
                frame.name
            ),
        );
    }
}

/// BHF-571: an exception raised (or re-raised) out of `Finalize`; the language
/// turns it into Program_Error and the remaining finalization is skipped.
fn raise_in_finalize(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for stmt in &m.stmts {
        let toks = m.stmt_toks(stmt);
        if !toks.first().is_some_and(|t| t.is("raise")) {
            continue;
        }
        let raised = toks.get(1).filter(|t| t.kind == Kind::Ident).map(|t| {
            let mut name = t.text.clone();
            let mut j = 2;
            while toks.get(j).is_some_and(|d| d.sym(".")) && toks.get(j + 1).is_some() {
                name = toks[j + 1].text.clone();
                j += 2;
            }
            name
        });
        let (mut frame, mut phase) = (stmt.frame, stmt.phase);
        let caught = loop {
            let f = &m.frames[frame];
            if phase == Phase::Body
                && (f.handled.contains("others")
                    || raised.as_ref().is_some_and(|r| f.handled.contains(r)))
            {
                break true;
            }
            if f.kind == FrameKind::Subprogram {
                break !(f.name == "finalize" && is_controlled_signature(m, f));
            }
            if matches!(
                f.kind,
                FrameKind::Package | FrameKind::Unit | FrameKind::Task | FrameKind::Protected
            ) {
                break true;
            }
            phase = f.parent_phase;
            match f.parent {
                Some(p) => frame = p,
                None => break true,
            }
        };
        if !caught {
            hit(
                out,
                stmt.lo,
                "BHF-571",
                "ada-raise-in-finalize",
                "Exception propagates out of Finalize",
                "finalization",
                "An exception leaving Finalize becomes Program_Error and skips the remaining finalization, so later cleanup (and resource release) does not run.".to_owned(),
            );
        }
    }
}

/// `procedure Finalize (Object : in out T)`: one `in out` formal, the
/// Ada.Finalization signature. A parameterless `Finalize` is just a name.
fn is_controlled_signature(m: &Model, frame: &Frame) -> bool {
    let Some(header) = frame.header else {
        return false;
    };
    let t = m.stmt_toks(&m.stmts[header]);
    frame.params.len() == 1 && t.windows(2).any(|w| w[0].is("in") && w[1].is("out"))
}

/// BHF-436 (Ada): `String'Input` and friends read the bounds from the stream,
/// so a network peer chooses the allocation size.
fn unbounded_stream_input(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    let networked = m.toks.windows(3).any(|w| {
        (w[0].is("gnat") && w[1].sym(".") && w[2].is("sockets"))
            || (w[0].is("aws") && w[1].sym(".") && w[2].is("net"))
    });
    if !networked {
        return;
    }
    for k in 0..m.toks.len().saturating_sub(3) {
        let t = &m.toks[k];
        if matches!(
            t.text.as_str(),
            "string"
                | "wide_string"
                | "wide_wide_string"
                | "unbounded_string"
                | "stream_element_array"
                | "storage_array"
        ) && t.kind == Kind::Ident
            && m.toks[k + 1].sym("'")
            && m.toks[k + 2].is("input")
            && m.toks[k + 3].sym("(")
        {
            hit(
                out,
                k,
                "BHF-436",
                "uncontrolled-allocation-size",
                "Stream 'Input of an unconstrained array sized by the peer",
                "allocation",
                format!(
                    "{}'Input reads the array bounds from a network stream and allocates them unchecked; a peer can request an arbitrarily large object.",
                    ctx.lines
                        .get(t.line)
                        .and_then(|l| l.get(t.col..t.col + t.text.len()))
                        .unwrap_or(&t.text)
                ),
            );
        }
    }
}

const RANDOM_CONTEXT: &[&str] = &[
    "token",
    "nonce",
    "salt",
    "password",
    "passwd",
    "passphrase",
    "secret",
    "session",
    "otp",
    "csrf",
    "api_key",
    "apikey",
    "private_key",
    "secret_key",
    "credential",
    "challenge",
    "cookie",
];

/// BHF-428 (Ada): Ada.Numerics.Discrete_Random / Float_Random feeding a token,
/// key, salt, nonce or password.
fn predictable_random(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    let mut generators = BTreeSet::new();
    let mut numerics = false;
    for w in m.toks.windows(3) {
        if w[0].is("numerics")
            && w[1].sym(".")
            && (w[2].is("discrete_random") || w[2].is("float_random"))
        {
            numerics = true;
        }
    }
    if !numerics {
        return;
    }
    for stmt in &m.stmts {
        let t = m.stmt_toks(stmt);
        if t.len() > 4
            && t[0].is("package")
            && t[2].is("is")
            && t[3].is("new")
            && t.iter()
                .any(|x| x.is("discrete_random") || x.is("float_random"))
        {
            generators.insert(t[1].text.clone());
        }
    }
    generators.insert("float_random".to_owned());
    generators.insert("discrete_random".to_owned());
    for stmt in &m.stmts {
        if stmt.phase == Phase::Decl && stmt.kind != StmtKind::Plain {
            continue;
        }
        for k in stmt.lo..stmt.hi.saturating_sub(1) {
            if !(m.toks[k].is("random") && m.toks[k + 1].sym("(")) {
                continue;
            }
            let qualified_ok = if k >= 2 && m.toks[k - 1].sym(".") {
                generators.contains(&m.toks[k - 2].text)
            } else {
                true
            };
            if !qualified_ok {
                continue;
            }
            let routine = m.routine_of(stmt.frame).map(|r| m.frames[r].name.clone());
            let target = assignment(&m.toks, stmt)
                .map(|(lhs, _)| m.toks[lhs].text.clone())
                .or_else(|| {
                    m.stmts
                        .iter()
                        .position(|s| s.lo == stmt.lo)
                        .and_then(|si| m.decl_at(si))
                        .map(|d| d.names[0].clone())
                });
            let context = [routine, target].into_iter().flatten().find(|n| {
                RANDOM_CONTEXT
                    .iter()
                    .any(|w| has_word(n, w) || n.contains(w))
            });
            if let Some(context) = context {
                hit(
                    out,
                    k,
                    "BHF-428",
                    "insecure-randomness",
                    "Ada.Numerics random generator used for a security value",
                    "randomness",
                    format!(
                        "{context} is derived from Ada.Numerics.*_Random, a predictable non-cryptographic generator; use a CSPRNG."
                    ),
                );
            }
        }
    }
}

const PASSWORD_WORDS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "passphrase",
    "credential",
];

/// BHF-422 (Ada): GNAT.MD5 / GNAT.SHA1 digest of a password.
fn weak_password_hash(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    for stmt in &m.stmts {
        for k in stmt.lo + 2..stmt.hi.saturating_sub(1) {
            if !(m.toks[k].is("digest") && m.toks[k + 1].sym("(") && m.toks[k - 1].sym(".")) {
                continue;
            }
            let algo = m.toks[k - 2].text.as_str();
            if !matches!(algo, "md5" | "sha1") {
                continue;
            }
            let Some(close) = close_paren(&m.toks, k + 1) else {
                continue;
            };
            let in_args = plain_idents(&m.toks, k + 2, close)
                .any(|i| PASSWORD_WORDS.iter().any(|w| has_word(&m.toks[i].text, w)));
            let routine = m
                .routine_of(stmt.frame)
                .map(|r| m.frames[r].name.clone())
                .unwrap_or_default();
            let in_name = ["password", "passwd", "credential"]
                .iter()
                .any(|w| routine.contains(w));
            if in_args || in_name {
                hit(
                    out,
                    k,
                    "BHF-422",
                    "weak-cryptography",
                    "Password hashed with MD5/SHA-1",
                    "crypto",
                    format!(
                        "GNAT.{} is a fast, broken hash; stored password hashes need a slow salted KDF (PBKDF2, scrypt, Argon2).",
                        algo.to_ascii_uppercase()
                    ),
                );
            }
        }
    }
}

/// BHF-409: Unchecked_Conversion whose target is an access type, or an
/// Address_To_Access_Conversions instance — pointers forged from raw values.
fn unchecked_conversion_to_access(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    let mut access_types = BTreeSet::new();
    let mut other_types = BTreeSet::new();
    for stmt in &m.stmts {
        let t = m.stmt_toks(stmt);
        if t.len() > 3 && (t[0].is("type") || t[0].is("subtype")) && t[2].is("is") {
            let rest = &t[3..];
            if rest.first().is_some_and(|x| x.is("access"))
                || rest.windows(2).any(|w| w[0].is("not") && w[1].is("null"))
                    && rest.iter().any(|x| x.is("access"))
            {
                access_types.insert(t[1].text.clone());
            } else {
                other_types.insert(t[1].text.clone());
            }
        }
    }
    for stmt in &m.stmts {
        let t = m.stmt_toks(stmt);
        let Some(new_at) = t.iter().position(|x| x.is("new")) else {
            continue;
        };
        if !(t[0].is("function") || t[0].is("package")) || new_at < 2 || !t[new_at - 1].is("is") {
            continue;
        }
        let generic = &t[new_at + 1..];
        let ends_with = |w: &str| {
            generic
                .iter()
                .take_while(|x| !x.sym("("))
                .last()
                .is_some_and(|x| x.is(w))
        };
        if ends_with("address_to_access_conversions") {
            hit(
                out,
                stmt.lo,
                "BHF-409",
                "ada-unchecked-conversion",
                "Access values forged from System.Address",
                "pointer_conversion",
                "Address_To_Access_Conversions.To_Pointer turns any address into an access value with no type or lifetime check.".to_owned(),
            );
            continue;
        }
        if !ends_with("unchecked_conversion") {
            continue;
        }
        let Some(open) = (stmt.lo + new_at..stmt.hi).find(|&k| m.toks[k].sym("(")) else {
            continue;
        };
        let args = call_args(&m.toks, open);
        let (Some((sa, sb)), Some((ta, tb))) =
            (arg_by(&args, &["source"], 0), arg_by(&args, &["target"], 1))
        else {
            continue;
        };
        let target = m.toks[tb - 1].text.clone();
        let source = m.text(sa, sb);
        let access_like = access_types.contains(&target)
            || !other_types.contains(&target)
                && (target.ends_with("_access")
                    || target.ends_with("_ptr")
                    || target.ends_with("_pointer")
                    || target == "chars_ptr"
                    || (target.ends_with("access") && target != "access")
                    || target.ends_with("ptr"));
        if !access_like || tb - ta == 0 {
            continue;
        }
        hit(
            out,
            stmt.lo,
            "BHF-409",
            "ada-unchecked-conversion",
            "Unchecked_Conversion produces an access value",
            "pointer_conversion",
            format!(
                "Unchecked_Conversion from {source} to the access type {target} forges a pointer; nothing checks that it designates a live object of that type."
            ),
        );
    }
}

/// BHF-410 / BHF-437 (Ada): an access value copied into a local alias, the
/// original deallocated, then the alias freed again or dereferenced.
fn free_through_alias(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    let mut freers: BTreeSet<String> = ["free", "deallocate", "unchecked_free"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for stmt in &m.stmts {
        let t = m.stmt_toks(stmt);
        if t.len() > 4
            && t[0].is("procedure")
            && t[2].is("is")
            && t[3].is("new")
            && t.iter().any(|x| x.is("unchecked_deallocation"))
        {
            freers.insert(t[1].text.clone());
        }
    }
    let free_arg = |s: &Stmt| -> Option<String> {
        let t = m.stmt_toks(s);
        (t.len() == 4
            && t[0].kind == Kind::Ident
            && freers.contains(&t[0].text)
            && t[1].sym("(")
            && t[2].kind == Kind::Ident
            && t[3].sym(")"))
        .then(|| t[2].text.clone())
    };
    for (ri, frame) in m.frames.iter().enumerate() {
        if !matches!(frame.kind, FrameKind::Subprogram | FrameKind::Task) {
            continue;
        }
        let body: Vec<usize> = m
            .stmts_in(ri)
            .filter(|(_, s)| m.routine_of(s.frame) == Some(ri))
            .map(|(i, _)| i)
            .collect();
        // alias -> original, valid from the statement that created it.
        let mut aliases: BTreeMap<String, String> = BTreeMap::new();
        let mut freed: BTreeMap<String, String> = BTreeMap::new();
        for &si in &body {
            let s = &m.stmts[si];
            if let Some(arg) = free_arg(s) {
                if let Some(original) = freed.get(&arg) {
                    hit(
                        out,
                        s.lo + 2,
                        "BHF-410",
                        "ada-unchecked-deallocation",
                        "Access value deallocated twice through an alias",
                        "double_free",
                        format!(
                            "{arg} aliases {original}, which was already deallocated; Free sets only {original} to null, so this frees the same object again."
                        ),
                    );
                    freed.remove(&arg);
                    continue;
                }
                let dangling: Vec<String> = aliases
                    .iter()
                    .filter(|(alias, orig)| *orig == &arg && **alias != arg)
                    .map(|(alias, _)| alias.clone())
                    .collect();
                for alias in dangling {
                    freed.insert(alias, arg.clone());
                }
                aliases.retain(|_, orig| *orig != arg);
                continue;
            }
            let assigned = if let Some(d) = m.decl_at(si) {
                Some((d.names[0].clone(), d.init))
            } else {
                assignment(&m.toks, s)
                    .filter(|(lhs, eq)| eq - lhs == 1)
                    .map(|(lhs, eq)| (m.toks[lhs].text.clone(), Some((eq + 1, s.hi))))
            };
            // Uses of a freed alias (before any reassignment) are dangling.
            for (alias, original) in freed.clone() {
                let lhs_only = assigned.as_ref().is_some_and(|(n, _)| *n == alias);
                let used = plain_idents(&m.toks, s.lo, s.hi)
                    .any(|k| m.toks[k].text == alias && !(lhs_only && k == s.lo));
                if used {
                    let at = plain_idents(&m.toks, s.lo, s.hi)
                        .find(|&k| m.toks[k].text == alias && !(lhs_only && k == s.lo))
                        .unwrap_or(s.lo);
                    hit(
                        out,
                        at,
                        "BHF-437",
                        "use-after-free",
                        "Access value used after its object was deallocated",
                        "use_after_free",
                        format!(
                            "{alias} aliases {original}, which was deallocated; Free nulls only {original}, so {alias} now dangles."
                        ),
                    );
                    freed.remove(&alias);
                } else if lhs_only {
                    freed.remove(&alias);
                }
            }
            if let Some((name, init)) = assigned {
                aliases.remove(&name);
                // A reassigned original no longer designates what its aliases do.
                aliases.retain(|_, orig| *orig != name);
                if let Some((a, b)) = init {
                    if b - a == 1 && m.toks[a].kind == Kind::Ident && m.toks[a].text != name {
                        aliases.insert(name, m.toks[a].text.clone());
                    }
                }
            }
        }
    }
}

/// BHF-411: a task body assigns a package-level variable that is neither
/// protected nor Atomic/Volatile and is also used outside that task.
fn unprotected_task_write(ctx: &Ctx, out: &mut Vec<Hit>) {
    let m = ctx.model;
    let mut synchronized = BTreeSet::new();
    for stmt in &m.stmts {
        let t = m.stmt_toks(stmt);
        if t.len() >= 4
            && t[0].is("pragma")
            && matches!(
                t[1].text.as_str(),
                "atomic" | "volatile" | "atomic_components" | "volatile_components" | "independent"
            )
            && t[2].sym("(")
        {
            synchronized.insert(t[3].text.clone());
        }
    }
    let mut synchronized_types = BTreeSet::new();
    for stmt in &m.stmts {
        let t = m.stmt_toks(stmt);
        if t.len() > 2
            && (t[0].is("protected") || t[0].is("task"))
            && (t[1].is("type") || t[1].kind == Kind::Ident)
        {
            let name = if t[1].is("type") {
                t.get(2)
            } else {
                Some(&t[1])
            };
            if let Some(n) = name {
                synchronized_types.insert(n.text.clone());
            }
        }
    }
    for (ti, frame) in m.frames.iter().enumerate() {
        if frame.kind != FrameKind::Task {
            continue;
        }
        let mut reported = BTreeSet::new();
        let loop_params: BTreeSet<String> = m
            .stmts_in(ti)
            .map(|(_, s)| s)
            .filter(|s| s.kind == StmtKind::Scheme)
            .filter_map(|s| {
                let mut t = m.stmt_toks(s);
                if t.len() > 2 && t[1].sym(":") {
                    t = &t[2..]; // `Label : for X in ...`
                }
                (t.len() > 2 && t[0].is("for") && (t[2].is("in") || t[2].is("of")))
                    .then(|| t[1].text.clone())
            })
            .collect();
        for stmt in m
            .stmts_in(ti)
            .map(|(_, s)| s)
            .filter(|s| s.phase != Phase::Decl)
        {
            let Some((lhs, eq)) = assignment(&m.toks, stmt) else {
                continue;
            };
            let var = m.toks[lhs].text.clone();
            let Binding::Library(d) = m.resolve(stmt.frame, &var) else {
                continue;
            };
            // `Shared (Node) := ...` indexed by a task-local or loop variable:
            // each task writes its own element.
            let partitioned = plain_idents(&m.toks, lhs + 1, eq).any(|k| {
                let name = &m.toks[k].text;
                matches!(
                    m.resolve(stmt.frame, name),
                    Binding::Local(_) | Binding::Param
                ) || loop_params.contains(name)
            });
            if partitioned {
                continue;
            }
            let decl = &m.decls[d];
            if decl.constant || synchronized.contains(&var) || reported.contains(&var) {
                continue;
            }
            let aspects = decl.aspects.map(|(a, b)| m.text(a, b)).unwrap_or_default();
            if ["atomic", "volatile", "independent"]
                .iter()
                .any(|w| aspects.split_whitespace().any(|x| x == *w))
            {
                continue;
            }
            let (ta, tb) = decl.ty;
            if m.toks[ta..tb]
                .iter()
                .any(|t| synchronized_types.contains(&t.text) || t.text.contains("atomic"))
            {
                continue;
            }
            let shared = m.stmts.iter().enumerate().any(|(si, s)| {
                si != decl.stmt
                    && !m.within(s.frame, ti)
                    && plain_idents(&m.toks, s.lo, s.hi).any(|k| m.toks[k].text == var)
            });
            if !shared {
                continue;
            }
            reported.insert(var.clone());
            hit(
                out,
                lhs,
                "BHF-411",
                "ada-tasking-hazard",
                "Task writes a shared variable without protection",
                "ada_tasking",
                format!(
                    "Task {} assigns {var}, a package-level variable that is also used outside the task and is not protected, Atomic or Volatile.",
                    frame.name
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn findings(src: &str) -> Vec<crate::StaticFinding> {
        let mut out = Vec::new();
        crate::scan_ada(
            Path::new("/r"),
            Path::new("/r/t.adb"),
            &crate::strip_ada_comments(src),
            &mut out,
        );
        out
    }

    /// Lines (1-based) carrying an `EXPECT <rule>` marker comment.
    fn expected_lines(src: &str, rule: &str) -> Vec<u32> {
        let marker = format!("EXPECT {rule}");
        src.lines()
            .enumerate()
            .filter(|(_, line)| {
                line.split("--").skip(1).any(|c| {
                    c.split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .contains(&marker)
                })
            })
            .map(|(i, _)| i as u32 + 1)
            .collect()
    }

    /// The rule fires on exactly the `EXPECT`-marked lines of the fixture: every
    /// positive is found and every unmarked look-alike stays clean.
    fn assert_rule(src: &str, rule: &str) {
        let mut got: Vec<u32> = findings(src)
            .iter()
            .filter(|f| f.rule_id == rule)
            .map(|f| f.location.line)
            .collect();
        got.sort_unstable();
        got.dedup();
        let want = expected_lines(src, rule);
        assert!(!want.is_empty(), "fixture for {rule} has no positives");
        assert_eq!(got, want, "{rule}: fired lines vs EXPECT lines");
    }

    #[test]
    fn suppressed_index_and_range_checks() {
        let src = r#"
package body P is
   pragma Suppress (Index_Check);            -- EXPECT BHF-564
   pragma Suppress (All_Checks);             -- EXPECT BHF-564
   pragma Suppress                           -- EXPECT BHF-564
     (Range_Check, On => Buffer);
   pragma Suppress (Length_Check);           -- EXPECT BHF-564
   pragma Unsuppress (Index_Check);
   pragma Suppress (Elaboration_Check);
   pragma Suppress (Accessibility_Check);
   -- pragma Suppress (All_Checks);
   procedure Show is
   begin
      Put_Line ("pragma Suppress (All_Checks);");
   end Show;
   pragma Suppress (Overflow_Check);
   function Element (Item : Utf16_String; Position : Index) return Code_Point is
      pragma Assert (Position in Item'Range);
      pragma Suppress (Index_Check);
   begin
      return Item (Position);
   end Element;
   function Get (Item : Vector; Position : Index) return Code_Point
     with Pre => Position <= Item.Last
   is
      pragma Suppress (Index_Check);
   begin
      return Item.Data (Position);
   end Get;
   procedure Fill (Item : out Buffer; Count : Natural) is
      pragma Suppress (All_Checks);                -- EXPECT BHF-564
   begin
      Item (1 .. Count) := (others => 0);
   end Fill;
end P;
"#;
        assert_rule(src, "BHF-564");
    }

    #[test]
    fn suppressed_overflow_check() {
        let src = r#"
package body Hash is
   pragma Suppress (Overflow_Check);         -- EXPECT BHF-565
   pragma Suppress (Overflow_Check, Mix);    -- EXPECT BHF-565
   pragma Unsuppress (Overflow_Check);
   pragma Suppress (Index_Check);
   Name : constant String := "pragma Suppress (Overflow_Check)";
end Hash;
"#;
        assert_rule(src, "BHF-565");
    }

    #[test]
    fn local_object_access_escapes_its_frame() {
        let src = r#"
package body Lifetimes is
   Global_Obj : aliased Buffer;
   Global_Ptr : Buffer_Access;

   function Get return Int_Access is
      Local : aliased Integer := 0;
   begin
      return Local'Unchecked_Access;           -- EXPECT BHF-566
   end Get;

   procedure Store is
      Buf : aliased Buffer;
   begin
      Global_Ptr := Buf'Unrestricted_Access;   -- EXPECT BHF-566
   end Store;

   procedure Store_Field (Into : in out Holder) is
      Tmp : aliased Buffer;
   begin
      Into.Ptr :=
        Tmp'Unchecked_Access;                  -- EXPECT BHF-566
   end Store_Field;

   procedure Use_Local is
      Buf : aliased Buffer;
      P   : Buffer_Access;
   begin
      P := Buf'Unchecked_Access;
      Process (P);
   end Use_Local;

   procedure Register is
   begin
      Global_Ptr := Global_Obj'Unchecked_Access;
   end Register;

   procedure From_Param (X : aliased in out Buffer) is
   begin
      Global_Ptr := X'Unchecked_Access;
   end From_Param;

   function Name return String is
   begin
      return "Local'Unchecked_Access";
   end Name;

   procedure Call_Arg (Out_H : out Handle) is
      Sec : aliased Security_Attributes;
   begin
      Out_H := Create_File (Path, Sec'Unchecked_Access, Mode);
   end Call_Arg;

   function Clone (Handler : Mapper) return Mapper_Access is
      Result : constant Mapper_Access := new Mapper;
   begin
      return Result.all'Unchecked_Access;
   end Clone;
end Lifetimes;
"#;
        assert_rule(src, "BHF-566");
    }

    #[test]
    fn address_overlay_onto_another_object() {
        let src = r#"
package body Codec is
   Reg : Unsigned_32 with Address => System'To_Address (16#4000_0000#);
   Port : Unsigned_8;
   for Port'Address use System.Storage_Elements.To_Address (16#3F8#);

   procedure Decode (Data : Stream_Element_Array) is
      Header : Header_Record
        with Import, Address => Data'Address;  -- EXPECT BHF-567
      Value : Unsigned_64 := 0;
      Raw   : Header_Record;
      for Raw'Address use Value'Address;       -- EXPECT BHF-567
      Copy  : Unsigned_64;
      for Copy'Address use Value'Address;
      pragma Import (Ada, Copy);
      Bytes : Stream_Element_Array (1 .. Data'Length);
      for Bytes'Address use Data'Address;
      View  : constant Stream_Element_Array (1 .. Item'Size / 8)
        with Import, Address => Item'Address;
      Text  : String (1 .. Natural (Info.Size));
      Blob  : Stream_Element_Array (1 .. Stream_Element_Offset (Info.Size));
      for Blob'Address use Text'Address;
      Words : Word_Array (0 .. 99);
      for Words'Address use Value'Address;
      Octet : Unsigned_8 with Address => Params (1)'Address;
      Pair  : array (Natural range 0 .. 1) of Interfaces.Unsigned_64;
      for Pair'Address use Result.Value'Address;
      Uuid  : Ada.Streams.Stream_Element_Array (1 .. 16);
      for Uuid'Address use Into'Address;
      Mode  : T_Sleep_Mode with Address => Params (2)'Address;   -- EXPECT BHF-567
      Wide  : Unsigned_64_Unrestricted_Array;
      for Wide'Address use Item.Value'Address;                   -- EXPECT BHF-567
      pragma Compile_Time_Error (Words'Size /= Value'Size, "bad overlay");
   begin
      Put_Line ("with Address => X'Address");
   end Decode;
end Codec;
"#;
        assert_rule(src, "BHF-567");
    }

    #[test]
    fn imported_unsafe_c_functions() {
        let src = r#"
package C_Binding is
   procedure C_Strcpy (D, S : chars_ptr);
   pragma Import (C, C_Strcpy, "strcpy");      -- EXPECT BHF-568
   function Sys (Cmd : char_array) return int
     with Import, Convention => C,
          External_Name => "system";           -- EXPECT BHF-568
   function Popen (C, M : chars_ptr) return File_Ptr;
   pragma Import (C, Popen);                   -- EXPECT BHF-568
   procedure Gets (S : chars_ptr)
     with Import, Convention => C, Link_Name => "gets"; -- EXPECT BHF-568
   function C_Strlen (S : chars_ptr) return size_t;
   pragma Import (C, C_Strlen, "strlen");
   function C_Snprintf (S : chars_ptr; N : size_t; F : chars_ptr) return int;
   pragma Import (C, C_Snprintf, "snprintf");
   procedure Strcpy_Wrapper (D, S : String);
   pragma Import (Ada, Strcpy_Wrapper, "strcpy_wrapper");
   Doc : constant String := "pragma Import (C, X, ""strcpy"")";
end C_Binding;
"#;
        assert_rule(src, "BHF-568");
    }

    #[test]
    fn new_string_without_free_leaks() {
        let src = r#"
package body Titles is
   procedure Set_Title (Title : String) is
      C_Title : chars_ptr := New_String (Title);  -- EXPECT BHF-550
   begin
      C_Set_Title (C_Title);
   end Set_Title;

   procedure Inline (Title : String) is
   begin
      C_Set_Title (New_String (Title));           -- EXPECT BHF-550
   end Inline;

   procedure Freed (Title : String) is
      C_Title : chars_ptr := New_String (Title);
   begin
      C_Set_Title (C_Title);
      Free (C_Title);
   end Freed;

   function Returned (Title : String) return chars_ptr is
      C_Title : constant chars_ptr := New_String (Title);
   begin
      return C_Title;
   end Returned;

   procedure Stored (Obj : in out Widget; Title : String) is
      C_Title : chars_ptr;
   begin
      C_Title := New_String (Title);
      Obj.Name := C_Title;
   end Stored;

   function Returned_Inline (S : String) return chars_ptr is
   begin
      return New_String (S);
   end Returned_Inline;

   procedure Insert (Into : in out Map; Key, Value : String) is
   begin
      Hash_Table_Insert (Into.Opaque, New_String (Key), New_String (Value));
   end Insert;

   procedure Keep (Into : in out Map; Key : String) is
      K : chars_ptr := New_String (Key);
   begin
      List_Append (Into.Keys, K);
   end Keep;
end Titles;
"#;
        assert_rule(src, "BHF-550");
    }

    #[test]
    fn spawn_with_non_constant_program_or_shell_command() {
        let src = r#"
with GNAT.OS_Lib; use GNAT.OS_Lib;
package body Runner is
   procedure Run_Program (Prog : String; Args : Argument_List) is
      Ok : Boolean;
   begin
      Spawn (Program_Name => Prog, Args => Args, Success => Ok);
   end Run_Program;

   procedure Run_Configured (Cfg : Settings) is
      Ok : Boolean;
   begin
      Spawn (Program_Name => Cfg.Tool.all, Args => No_Args, Success => Ok); -- EXPECT BHF-412
   end Run_Configured;

   procedure Edit (File : String) is
      Proc   : Util.Processes.Process;
      Editor : constant String := Ada.Environment_Variables.Value ("EDITOR");
   begin
      Util.Processes.Spawn (Proc, Editor & " " & File);   -- EXPECT BHF-412
      Util.Processes.Spawn (Proc, "env | grep ENV_VAR");
      Util.Processes.Spawn (Proc, Util.Processes.READ);
   end Edit;

   overriding
   procedure Spawn (Sys  : in out System_Process;
                    Proc : in out Process'Class;
                    Mode : in Pipe_Mode := NONE);

   procedure Spawn (Proc : in out Process; Mode : in Pipe_Mode := NONE) is
   begin
      Proc.Sys.Spawn (Proc, Mode);
   end Spawn;

   procedure Run_Shell (Cmd : String) is
      Ok : Boolean;
   begin
      GNAT.OS_Lib.Spawn                                    -- EXPECT BHF-412
        ("/bin/sh",
         (1 => new String'("-c"), 2 => new String'(Cmd)),
         Ok);
   end Run_Shell;

   procedure Run_Git (Args : Argument_List) is
      Ok  : Boolean;
      Git : String_Access := Locate_Exec_On_Path ("git");
   begin
      Spawn ("/usr/bin/git", Args, Ok);
      Spawn (Git.all, Args, Ok);
   end Run_Git;

   procedure Launch is
      Fixed : constant String := "/bin/ls";
      Ok    : Boolean;
   begin
      Put_Line ("Spawning: " & Fixed);
      Spawn (Fixed, (1 => new String'("-l")), Ok);
   end Launch;

   procedure Expect_It (Desc : in out Process_Descriptor; Command : String) is
   begin
      Non_Blocking_Spawn (Desc, Command, (1 .. 0 => null));
      Non_Blocking_Spawn (Desc, Desc_Command (Desc), (1 .. 0 => null)); -- EXPECT BHF-412
   end Expect_It;

   procedure Spawn (Program : String);
end Runner;
"#;
        assert_rule(src, "BHF-412");
    }

    #[test]
    fn sql_built_by_concatenation() {
        let src = r#"
package body Users is
   procedure Find (Conn : Database_Connection; Name : String) is
      C : Forward_Cursor;
   begin
      C.Fetch (Conn, "SELECT * FROM users WHERE name = '" & Name & "'"); -- EXPECT BHF-419
      Execute                                                           -- EXPECT BHF-419
        (Conn,
         "DELETE FROM sessions WHERE user_id = "
         & Name);
      Execute (Conn, "SELECT * FROM users WHERE id = $1", Params => (1 => +Name));
      Execute (Conn, "SELECT count(*) FROM users WHERE age > " & Integer'Image (Age));
      Put_Line ("SELECT " & Name);
   end Find;

   procedure Two_Step (S : Session; Id : String) is
      Query : constant String := "UPDATE accounts SET locked = 1 WHERE id = " & Id;
      Fixed : constant String := "SELECT a FROM b";
      Stmt  : Query_Statement;
   begin
      Stmt := S.Create_Statement (Query);                               -- EXPECT BHF-419
      Stmt := S.Create_Statement (Fixed);
   end Two_Step;
end Users;
"#;
        assert_rule(src, "BHF-419");
    }

    #[test]
    fn secrets_written_to_logs() {
        let src = r#"
package body Auth is
   procedure Login (User : String; Password : String; Api_Key : String) is
   begin
      Put_Line ("Password is: " & Password);                   -- EXPECT BHF-569
      Log.Debug ("Login {0} with {1}", User, Password);        -- EXPECT BHF-569
      Ada.Text_IO.Put_Line                                     -- EXPECT BHF-569
        (Standard_Error, "key=" & Api_Key);
      Put_Line ("Password length:" & Natural'Image (Password'Length));
      Put_Line ("Enter password:");
      Put_Line ("Unexpected token: " & Token);
      Log.Info ("Password_File {0}", Password_File);
      Put_Line (Config_File, Password);
      Log.Info ("Hash {0}", Hash (Password));
   end Login;
end Auth;
"#;
        assert_rule(src, "BHF-569");
    }

    #[test]
    fn exception_can_escape_an_exported_subprogram() {
        let src = r#"
package body Callbacks is
   procedure On_Event (X : int)
     with Export, Convention => C, External_Name => "on_event";
   procedure On_Safe (X : int)
     with Export, Convention => C, External_Name => "on_safe";
   procedure On_Null (X : int);
   pragma Export (C, On_Null, "on_null");
   function Compute (X : int) return int;
   pragma Export (C, Compute, "compute");

   procedure On_Event (X : int) is                -- EXPECT BHF-570
   begin
      Process (Integer (X));
   end On_Event;

   procedure On_Safe (X : int) is
   begin
      Process (Integer (X));
   exception
      when E : others =>
         Log (E);
   end On_Safe;

   procedure On_Null (X : int) is
   begin
      null;
   end On_Null;

   function Compute (X : int) return int is       -- EXPECT BHF-570
   begin
      return X * 2;
   end Compute;

   procedure Internal (X : Integer) is
   begin
      Process (X);
   end Internal;
end Callbacks;
"#;
        assert_rule(src, "BHF-570");
    }

    #[test]
    fn raise_out_of_finalize() {
        let src = r#"
package body Handles is
   overriding procedure Finalize (Obj : in out Handle) is
   begin
      if Obj.Fd < 0 then
         raise Program_Error with "double close";  -- EXPECT BHF-571
      end if;
      begin
         Close (Obj.Fd);
         raise Use_Error;
      exception
         when others => null;
      end;
   end Finalize;

   procedure Finalize (Obj : in out Other) is
   begin
      Close (Obj.Fd);
   exception
      when E : Use_Error =>
         Log (E);
         raise;                                    -- EXPECT BHF-571
   end Finalize;

   procedure Close_All (Obj : in out Handle) is
   begin
      raise Program_Error;
   end Close_All;

   procedure Finalize is
   begin
      if Errors > 0 then
         raise Command_Line_Error;
      end if;
   end Finalize;
end Handles;
"#;
        assert_rule(src, "BHF-571");
    }

    #[test]
    fn unbounded_string_input_from_socket_stream() {
        let src = r#"
with GNAT.Sockets; use GNAT.Sockets;
package body Server is
   procedure Serve (Sock : Socket_Type) is
      Channel : constant Stream_Access := Stream (Sock);
      Request : constant String := String'Input (Channel);   -- EXPECT BHF-436
      Header  : constant Header_Rec := Header_Rec'Input (Channel);
      Buf     : String (1 .. 64);
   begin
      String'Read (Channel, Buf);
      Process (Request, Header, Buf);
   end Serve;
end Server;
"#;
        assert_rule(src, "BHF-436");
    }

    #[test]
    fn string_input_without_a_network_stream_is_clean() {
        let src = r#"
with Ada.Streams.Stream_IO;
package body Store is
   procedure Load (S : Stream_Access) is
      Name : constant String := String'Input (S);
   begin
      Process (Name);
   end Load;
end Store;
"#;
        assert!(findings(src).iter().all(|f| f.rule_id != "BHF-436"));
    }

    #[test]
    fn predictable_random_in_a_security_context() {
        let src = r#"
with Ada.Numerics.Discrete_Random;
package body Sessions is
   package Rand is new Ada.Numerics.Discrete_Random (Character_Range);
   Gen : Rand.Generator;

   function New_Session_Token return String is
      Result : String (1 .. 32);
   begin
      for I in Result'Range loop
         Result (I) := Rand.Random (Gen);           -- EXPECT BHF-428
      end loop;
      return Result;
   end New_Session_Token;

   procedure Make_Salt (Salt : out Bytes) is
   begin
      Salt (1) := Byte (Rand.Random (Gen));         -- EXPECT BHF-428
   end Make_Salt;

   procedure Shuffle (Deck : in out Cards) is
      J : Positive;
   begin
      J := Positive (Rand.Random (Gen));
      Swap (Deck, 1, J);
   end Shuffle;

   function Next_Token (L : in out Lexer) return Token is
   begin
      return Scan (L);
   end Next_Token;
end Sessions;
"#;
        assert_rule(src, "BHF-428");
    }

    #[test]
    fn weak_hash_of_a_password() {
        let src = r#"
with GNAT.MD5; with GNAT.SHA1;
package body Accounts is
   function Hash_Password (Password : String) return String is
   begin
      return GNAT.MD5.Digest (Password);              -- EXPECT BHF-422
   end Hash_Password;

   procedure Check (User : User_Rec; Pass : String) is
   begin
      if GNAT.SHA1.Digest (Pass & User.Salt) = User.Hash then  -- EXPECT BHF-422
         Grant (User);
      end if;
   end Check;

   function Cache_Key (Path : String) return String is
   begin
      return GNAT.MD5.Digest (Path);
   end Cache_Key;

   function Accept_Key (Key : String) return String is
   begin
      return Base64 (GNAT.SHA1.Digest (Key & Websocket_GUID));
   end Accept_Key;
end Accounts;
"#;
        assert_rule(src, "BHF-422");
    }

    #[test]
    fn unchecked_conversion_to_an_access_type() {
        let src = r#"
with Ada.Unchecked_Conversion;
with System.Address_To_Access_Conversions;
package body Nodes is
   type Node_Access is access all Node;
   function To_Node is new Ada.Unchecked_Conversion (System.Address, Node_Access); -- EXPECT BHF-409
   function From_Int is new Ada.Unchecked_Conversion                               -- EXPECT BHF-409
     (Source => Integer_Address, Target => Node_Access);
   function To_Ptr is new Ada.Unchecked_Conversion (Root_Ptr, Leaf_Ptr);            -- EXPECT BHF-409
   package Conv is new System.Address_To_Access_Conversions (Node);                 -- EXPECT BHF-409
   function To_Bits is new Ada.Unchecked_Conversion (Float, Unsigned_32);
   function To_Addr is new Ada.Unchecked_Conversion (Node_Access, System.Address);
   function To_Byte is new Ada.Unchecked_Conversion (Character, Byte);
   type U32_For_Access is mod 2 ** 32;
   function To_U32 is new Ada.Unchecked_Conversion (Node_Access, U32_For_Access);
end Nodes;
"#;
        assert_rule(src, "BHF-409");
    }

    #[test]
    fn deallocated_through_an_alias_then_reused() {
        let src = r#"
package body Lists is
   procedure Free is new Ada.Unchecked_Deallocation (Node, Node_Access);

   procedure Drop (Head : in out Node_Access) is
      Saved : Node_Access := Head;
   begin
      Free (Head);
      Free (Saved);                      -- EXPECT BHF-410
   end Drop;

   procedure Peek (Head : in out Node_Access) is
      Cur : Node_Access;
   begin
      Cur := Head;
      Free (Head);
      Put_Line (Cur.Name);               -- EXPECT BHF-437
   end Peek;

   procedure Reset (Head : in out Node_Access) is
      Cur : Node_Access;
   begin
      Cur := Head;
      Free (Head);
      Cur := Allocate;
      Put_Line (Cur.Name);
   end Reset;

   procedure Single (Head : in out Node_Access) is
   begin
      Free (Head);
      Free (Head);
   end Single;
end Lists;
"#;
        assert_rule(src, "BHF-410");
        assert_rule(src, "BHF-437");
    }

    #[test]
    fn task_writes_an_unprotected_package_variable() {
        let src = r#"
package body Counter is
   Count  : Natural := 0;
   Hits   : Natural := 0 with Atomic;
   Ticks  : Natural := 0;
   pragma Volatile (Ticks);
   Limit  : constant Natural := 10;
   Owned  : Natural := 0;
   Desired : Vector (1 .. 10);

   task body Worker is
      Local : Natural := 0;
   begin
      loop
         Count := Count + 1;              -- EXPECT BHF-411
         Hits := Hits + 1;
         Ticks := Ticks + 1;
         Local := Local + 1;
         Owned := Owned + 1;
      end loop;
   end Worker;

   task body Agent is
   begin
      for Node in Start .. Stop loop
         Desired (Node) := Compute (Node);
      end loop;
      Outputs : for Slot in Start .. Stop loop
         Desired (Slot) := Compute (Slot);
      end loop Outputs;
   end Agent;

   function Get return Natural is
   begin
      return Count + Hits + Ticks + Limit + Desired (1);
   end Get;

   protected body Lock is
      procedure Bump is
      begin
         Count := Count + 1;
      end Bump;
   end Lock;
end Counter;
"#;
        assert_rule(src, "BHF-411");
    }

    #[test]
    fn tasking_constructs_alone_are_not_findings() {
        let src = r#"
package body Pool is
   task type Worker is
      entry Start;
   end Worker;
   task body Worker is
   begin
      accept Start;
      select
         delay 1.0;
      or
         terminate;
      end select;
   end Worker;
   protected type Queue is
      procedure Put (X : Integer);
   end Queue;
end Pool;
"#;
        assert!(findings(src).iter().all(|f| f.rule_id != "BHF-411"));
    }

    #[test]
    fn hardcoded_password_constant_is_reported() {
        // The generic BHF-429 assignment detector runs on Ada `:=`; this pins it.
        let root = std::env::temp_dir().join(format!("bhf-ada-secret-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("cfg.adb"),
            "package body Cfg is\n   Db_Password : constant String := \"Tr0ub4dor&3x\";\n   Password_Env : constant String := \"APP_DB_PASSWORD\";\nend Cfg;\n",
        )
        .unwrap();
        let report = crate::scan(&crate::StaticScanOptions {
            root: root.clone(),
            out_dir: root.join("out"),
            suppressions_path: None,
            baseline_path: None,
            policy_path: None,
            enabled_rules: std::collections::BTreeSet::from(["BHF-429".to_owned()]),
            disabled_rules: std::collections::BTreeSet::new(),
            emit_sarif: false,
        })
        .unwrap();
        let lines: Vec<u32> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "BHF-429")
            .map(|f| f.location.line)
            .collect();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(lines, vec![2]);
    }

    #[test]
    fn broad_handler_that_only_discards() {
        let src = r#"
package body Cleanup is
   procedure Parse_Quietly (F : in out File_Type) is
   begin
      Parse (F);
   exception
      when others => null;                   -- EXPECT BHF-402
   end Parse_Quietly;

   procedure Logged (F : in out File_Type) is
   begin
      Close (F);
   exception
      when E : others =>
         Log (E);
   end Logged;

   procedure Narrow (F : in out File_Type) is
   begin
      Load (F);
   exception
      when Status_Error => null;
      when others =>                         -- EXPECT BHF-402
         null;
   end Narrow;

   procedure Dispatch (K : Kind) is
   begin
      case K is
         when A => Run_A;
         when others => null;
      end case;
   end Dispatch;

   Template : constant String := "when others => null;";

   overriding procedure Finalize (Obj : in out Handle) is
   begin
      Release (Obj.Lock);
   exception
      when others => null;
   end Finalize;

   procedure Log_Start (Name : String) is
   begin
      if Log_Enabled then
         Ada.Text_IO.Put (Log_File, Name);
         Ada.Text_IO.Put_Line (Log_File, " ...");
      end if;
   exception
      when others => null;
   end Log_Start;

   procedure Drop (S : Socket_Type) is
   begin
      begin
         GNAT.Sockets.Shutdown_Socket (S);
      exception
         when others => null;
      end;
   end Drop;

   procedure Notify_All (L : Listener_List) is
   begin
      for X of L loop
         begin
            X.Notify;
         exception
            when others => null;                -- EXPECT BHF-402
         end;
      end loop;
   end Notify_All;
end Cleanup;
"#;
        assert_rule(src, "BHF-402");
    }

    #[test]
    fn gnat_binder_output_is_not_scanned() {
        let src = "pragma Suppress (Overflow_Check);\npackage body ada_main is\nend ada_main;\n";
        for rel in ["obj/b__main.adb", "b~main.adb"] {
            let mut out = Vec::new();
            crate::scan_ada(Path::new("/r"), &Path::new("/r").join(rel), src, &mut out);
            assert!(out.is_empty(), "{rel}");
        }
    }

    #[test]
    fn structural_rules_skip_test_trees() {
        let src = "package body T is\n   pragma Suppress (Index_Check);\n   procedure P is\n   begin\n      Parse (F);\n   exception\n      when others => null;\n   end P;\nend T;\n";
        for rel in [
            "regtests/src/t.adb",
            "tests/t.adb",
            "testsuite/xml/t.adb",
            "src/t-tests.adb",
        ] {
            let mut out = Vec::new();
            crate::scan_ada(
                Path::new("/r"),
                &Path::new("/r").join(rel),
                &crate::strip_ada_comments(src),
                &mut out,
            );
            assert!(
                out.is_empty(),
                "{rel}: {:?}",
                out.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
            );
        }
        let mut out = Vec::new();
        crate::scan_ada(
            Path::new("/home/me/tests"),
            Path::new("/home/me/tests/src/t.adb"),
            &crate::strip_ada_comments(src),
            &mut out,
        );
        let mut rules: Vec<&str> = out.iter().map(|f| f.rule_id.as_str()).collect();
        rules.sort_unstable();
        assert_eq!(
            rules,
            vec!["BHF-402", "BHF-564"],
            "the scan root's own name is not a test tree"
        );
    }

    #[test]
    fn language_runtime_units_are_not_scanned() {
        // An implementation of the predefined hierarchy (a runtime such as drake
        // or GNAT's own) must suppress checks and forge pointers to implement them.
        for unit in [
            "System.Formatting.Fixed",
            "Ada.Numerics.SFMT",
            "Interfaces.C.Pointers",
            "GNAT.Sockets.Thin",
        ] {
            let src = format!(
                "package body {unit} is\n   pragma Suppress (All_Checks);\n   function Cast is new Ada.Unchecked_Conversion (System.Address, Node_Access);\nend {unit};\n"
            );
            assert!(findings(&src).is_empty(), "{unit}");
        }
        let src = "separate (System.Unwind.Raising)\npackage body Separated is\n   pragma Suppress (All_Checks);\nend Separated;\n";
        assert!(findings(src).is_empty(), "runtime subunit");
        let src = "package body Matreshka.Internals.Strings is\n   pragma Suppress (All_Checks); -- EXPECT BHF-564\nend Matreshka.Internals.Strings;\n";
        assert_rule(src, "BHF-564");
        let src = "with Ada.Text_IO;\nprocedure Run_Tool is\n   pragma Suppress (Index_Check); -- EXPECT BHF-564\nbegin\n   null;\nend Run_Tool;\n";
        assert_rule(src, "BHF-564");
    }

    #[test]
    fn malformed_source_never_panics() {
        // Scanned trees are untrusted: unbalanced parens, stray `end`s, a lone
        // quote or tick, and truncated constructs must all scan without a panic.
        for src in [
            ")))",
            "end; end; end Foo;",
            "procedure P is begin X := (1 => (2 => ; end",
            "type T is array ) of Unsigned_8; X : T with Address => Y'Address;",
            "X : array ) of Byte; for X'Address use Y'Address;",
            "pragma Import (",
            "pragma Suppress",
            "'",
            "\"unterminated",
            "procedure Finalize (O : in out T) is begin raise",
            "task body T is begin X := 1; end T; X : Integer;",
            "function F is new Ada.Unchecked_Conversion (",
            "Spawn (",
            "Execute (C, \"SELECT a FROM b\" &",
            "C : chars_ptr := New_String (",
            "when others => null; exception when others => null;",
        ] {
            let _ = findings(src);
        }
    }

    #[test]
    fn lexer_keeps_character_literals_and_ticks_apart() {
        // A `'"'` character literal must not open a string that swallows the
        // following `pragma Suppress`, and `Character'('-')` must not start a comment.
        let src = "package body Q is\n   Quote : constant Character := '\"';\n   Dash : constant Character := Character'('-');\n   pragma Suppress (Index_Check); -- EXPECT BHF-564\nend Q;\n";
        assert_rule(src, "BHF-564");
    }
}
