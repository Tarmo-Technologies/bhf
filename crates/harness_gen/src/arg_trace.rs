// SPDX-License-Identifier: Apache-2.0

//! Per-parameter argument trace for generated C and C++ harnesses.
//!
//! A generated harness decodes each target parameter from the fuzz input with
//! one `decl` statement per parameter. This module turns a call's parameter
//! emissions into the statement list the templates render in their place:
//! the decls themselves, a cursor-position capture around each one (so a
//! parameter's byte span in the testcase is known), and one
//! `if (bhf_trace_on()) { ... }` statement per parameter that prints a
//! `BHF_ARG {json}` line to stderr when the harness runs with
//! `BHF_TRACE_ARGS=1` (see `c_runtime/bhf_trace.h`). Output and in-out
//! parameters also get an after-call statement printing their new value.
//!
//! With tracing off the harness pays one cached branch per call.

use crate::c_decoders::CParamEmission;
use serde::Serialize;
use type_model::{ScalarKind, TypeRegistry, TypeShape};

/// Longest parameter name and type spelling copied into a trace line.
const MAX_NAME: usize = 80;
const MAX_TYPE: usize = 160;
const MAX_DECODER: usize = 96;

/// The generated harness's language: C traces by the parameter's resolved
/// type, C++ by template dispatch in `bhf_trace.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lang {
    C,
    Cpp,
}

/// Whose arguments a group decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// Arguments of the called function.
    Param,
    /// Arguments that construct the receiver object of a C++ method.
    Receiver,
}

/// One call's parameter list, as the template decodes it.
pub(crate) struct Group<'a> {
    pub lang: Lang,
    /// Identifier fragment unique within the harness function (`p`, `c`,
    /// `s3`), naming the position captures `_bhf_at_<prefix><k>`.
    pub prefix: &'a str,
    /// `target`, `receiver`, or the name of the function called.
    pub call: &'a str,
    pub role: Role,
    /// Index of the first emission in the call's parameter list.
    pub index_base: usize,
    /// The C type registry, to classify typedef'd parameter types.
    pub registry: Option<&'a TypeRegistry>,
}

/// A parameter as declared: its sanitized name and spelled type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declared {
    pub name: String,
    pub ty: String,
}

impl Declared {
    pub(crate) fn new(name: impl Into<String>, ty: impl Into<String>) -> Self {
        Declared {
            name: name.into(),
            ty: ty.into(),
        }
    }
}

/// The statements a template renders for one call's parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct DecodePlan {
    /// In order: decls, position captures and before-call trace statements.
    /// Each is rendered as `<statement>;` on its own line.
    pub decode: Vec<String>,
    /// After-call trace statements for output and in-out parameters.
    pub after: Vec<String>,
}

/// Where a decl takes its bytes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Reads the cursor: its span is the cursor movement around the decl.
    Cursor,
    /// Uses the whole input (`Data`/`Size`) without the cursor.
    Input,
    /// Takes no input bytes (a constant, a scratch object).
    None,
}

/// Plan the decode and trace statements for one call's parameters.
pub(crate) fn plan(
    group: &Group<'_>,
    emissions: &[CParamEmission],
    declared: &[Declared],
) -> DecodePlan {
    if emissions.is_empty() {
        return DecodePlan::default();
    }
    let at = |k: usize| format!("_bhf_at_{}{k}", group.prefix);
    let sources: Vec<Source> = emissions
        .iter()
        .map(|emission| source_of(&format!("{} {}", emission.decl, emission.arg)))
        .collect();
    // A cursor position is captured only where a span uses it: an unused
    // local would fail a project build that adds `-Werror -Wunused`.
    let mut captured = vec![false; emissions.len() + 1];
    for (index, source) in sources.iter().enumerate() {
        if *source == Source::Cursor {
            captured[index] = true;
            captured[index + 1] = true;
        }
    }
    let mut plan = DecodePlan::default();
    for (index, emission) in emissions.iter().enumerate() {
        if captured[index] {
            plan.decode.push(format!("size_t {} = Cur.pos", at(index)));
        }
        if !emission.decl.trim().is_empty() {
            plan.decode.push(emission.decl.clone());
        }
    }
    if captured[emissions.len()] {
        plan.decode
            .push(format!("size_t {} = Cur.pos", at(emissions.len())));
    }
    for (index, emission) in emissions.iter().enumerate() {
        let declared = (declared.len() == emissions.len()).then(|| &declared[index]);
        let span = match sources[index] {
            Source::Cursor => Some((at(index), at(index + 1))),
            Source::Input => Some(("0".to_owned(), "Size".to_owned())),
            Source::None => None,
        };
        let traced = trace_param(group, index, emission, declared, span);
        plan.decode.push(traced.before);
        if let Some(after) = traced.after {
            plan.after.push(after);
        }
    }
    plan
}

/// The statements tracing one parameter.
struct Traced {
    before: String,
    after: Option<String>,
}

fn trace_param(
    group: &Group<'_>,
    index: usize,
    emission: &CParamEmission,
    declared: Option<&Declared>,
    span: Option<(String, String)>,
) -> Traced {
    let name = declared
        .map(|d| d.name.clone())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| fallback_name(&emission.arg, index));
    let ty = declared
        .map(|d| d.ty.trim().to_owned())
        .filter(|ty| !ty.is_empty())
        .unwrap_or_else(|| emission.c_type.trim().to_owned());
    let value = match group.lang {
        Lang::C => c_value(emission, &ty, group.registry),
        Lang::Cpp => cpp_value(emission, &ty),
    };
    let role = match (group.role, value.out) {
        (Role::Receiver, _) => "receiver",
        (Role::Param, true) => "out",
        (Role::Param, false) => "param",
    };
    let head = json_head(&[
        ("call", group.call),
        ("i", &(group.index_base + index).to_string()),
        ("role", role),
        ("name", &name),
        ("type", &ty),
        ("decoder", &decoder_label(&emission.decl)),
    ]);
    let span_stmt = span
        .map(|(lo, hi)| format!(" bhf_tl_span((size_t)({lo}), (size_t)({hi}));"))
        .unwrap_or_default();
    let before = format!(
        "if (bhf_trace_on()) {{ bhf_tl_begin({});{span_stmt} {} bhf_tl_end(); }}",
        c_string_literal(&head),
        value.before
    );
    let after = value.after.map(|after| {
        let head = format!("{head},\"phase\":\"after\"");
        format!(
            "if (bhf_trace_on()) {{ bhf_tl_begin({}); {after} bhf_tl_end(); }}",
            c_string_literal(&head)
        )
    });
    Traced { before, after }
}

/// The trace calls for one value: before the call, after it (for an output
/// parameter), and whether it is an output.
struct ValueTrace {
    before: String,
    after: Option<String>,
    out: bool,
}

fn c_value(emission: &CParamEmission, ty: &str, registry: Option<&TypeRegistry>) -> ValueTrace {
    let arg = emission.arg.trim();
    let shape = registry
        .map(|registry| registry.resolve(&emission.c_type))
        .unwrap_or_else(|| spelled_shape(&emission.c_type));
    let len = known_len(&emission.decl, arg);
    let nul = nul_flag(&emission.decl);
    let plain = |before: String| ValueTrace {
        before,
        after: None,
        out: false,
    };
    match &shape {
        TypeShape::Scalar(kind) => plain(scalar_call(*kind, arg)),
        TypeShape::Enum { .. } => plain(format!("bhf_tr_i64((int64_t)({arg}));")),
        TypeShape::CString => {
            let call = format!("bhf_tr_str((const char *)({arg}), Data, Size, {len}, {nul});");
            if pointee_is_const(ty) || pointee_is_const(&emission.c_type) {
                plain(call)
            } else {
                // A writable `char *` is an output buffer the callee may fill.
                ValueTrace {
                    before: call.clone(),
                    after: Some(call),
                    out: true,
                }
            }
        }
        TypeShape::Pointer(inner) => {
            let ptr = format!("bhf_tr_ptr((const void *)({arg}), Data, Size, {len}, 0);");
            let storage = is_storage_backed(&emission.decl, arg);
            let writable = !pointee_is_const(ty) && !pointee_is_const(&emission.c_type);
            match inner.as_ref() {
                TypeShape::Scalar(ScalarKind::U8 | ScalarKind::I8) => plain(ptr),
                TypeShape::Scalar(kind) if storage => {
                    let deref = guarded(arg, &scalar_call(*kind, &format!("*({arg})")));
                    output(ptr, deref, writable)
                }
                TypeShape::Enum { .. } if storage => {
                    let deref = guarded(arg, &format!("bhf_tr_i64((int64_t)*({arg}));"));
                    output(ptr, deref, writable)
                }
                TypeShape::Pointer(_) if storage => {
                    let slot = guarded(arg, &format!("bhf_tr_addr_value((const void *)*({arg}));"));
                    ValueTrace {
                        before: format!("{ptr} {slot}"),
                        after: writable.then_some(slot),
                        out: writable,
                    }
                }
                TypeShape::Struct { .. } | TypeShape::Union { .. } if storage && writable => {
                    ValueTrace {
                        before: ptr.clone(),
                        after: Some(ptr),
                        out: true,
                    }
                }
                _ => plain(ptr),
            }
        }
        // Only a variable is compared with NULL: comparing a function's own
        // name is a constant clang warns about.
        TypeShape::FuncPtr if is_identifier(arg) => plain(format!("bhf_tr_fnptr(({arg}) != 0);")),
        TypeShape::Struct { .. } | TypeShape::Union { .. } | TypeShape::Array { .. }
            if is_identifier(arg) =>
        {
            plain(format!(
                "bhf_tr_obj((const void *)&({arg}), sizeof({arg}));"
            ))
        }
        TypeShape::Opaque(_) if emission.c_type.trim_end().ends_with('*') => plain(format!(
            "bhf_tr_ptr((const void *)({arg}), Data, Size, {len}, 0);"
        )),
        _ => plain("bhf_tr_untraced();".to_owned()),
    }
}

/// `call` under a NULL check of `arg`, unless `arg` takes an address (`&x`),
/// which is never NULL (and testing it is a warning).
fn guarded(arg: &str, call: &str) -> String {
    if arg.starts_with('&') {
        call.to_owned()
    } else {
        format!("if ({arg}) {{ {call} }}")
    }
}

/// A pointer to scalar storage: its address and value, and when the callee may
/// write through it, the value after the call.
fn output(ptr: String, deref: String, writable: bool) -> ValueTrace {
    ValueTrace {
        before: format!("{ptr} {deref}"),
        after: writable.then_some(deref),
        out: writable,
    }
}

fn scalar_call(kind: ScalarKind, expr: &str) -> String {
    match kind {
        ScalarKind::Bool => format!("bhf_tr_bool(({expr}) ? 1 : 0);"),
        ScalarKind::I8 | ScalarKind::I16 | ScalarKind::I32 | ScalarKind::I64 => {
            format!("bhf_tr_i64((int64_t)({expr}));")
        }
        ScalarKind::U8 | ScalarKind::U16 | ScalarKind::U32 | ScalarKind::U64 => {
            format!("bhf_tr_u64((uint64_t)({expr}));")
        }
        ScalarKind::F32 | ScalarKind::F64 => format!("bhf_tr_f64((double)({expr}));"),
    }
}

fn cpp_value(emission: &CParamEmission, ty: &str) -> ValueTrace {
    let arg = emission.arg.trim();
    // `std::move(x)` would leave `x` moved-from after the call: trace `x`
    // before it and never after.
    let moved = arg
        .strip_prefix("std::move(")
        .and_then(|rest| rest.strip_suffix(')'))
        .map(str::trim);
    let traced = moved.unwrap_or(arg);
    let len = known_len(&emission.decl, traced);
    let storage = is_storage_backed(&emission.decl, traced);
    let mut flags = Vec::new();
    if storage {
        flags.push("BHF_TRACE_DEREF");
    }
    if nul_flag(&emission.decl) != "0" {
        flags.push("BHF_TRACE_NUL");
    }
    let flags = if flags.is_empty() {
        "0".to_owned()
    } else {
        flags.join(" | ")
    };
    let call = format!("bhf_trace_value(({traced}), Data, Size, {len}, {flags});");
    let out = moved.is_none()
        && (is_cpp_nonconst_lvalue_ref(ty)
            || (storage && is_cpp_writable_pointer(ty))
            || emission.decl.contains("bhf_c_string_out("));
    ValueTrace {
        before: call.clone(),
        after: out.then_some(call),
        out,
    }
}

/// Where a decl takes its bytes from, by the identifiers it uses: the cursor
/// `Cur`, or the harness's raw `Data`/`Size`.
fn source_of(decl: &str) -> Source {
    let mut cursor = false;
    let mut input = false;
    for token in identifiers(decl) {
        match token {
            "Cur" => cursor = true,
            "Data" | "Size" => input = true,
            _ => {}
        }
    }
    if input {
        Source::Input
    } else if cursor {
        Source::Cursor
    } else {
        Source::None
    }
}

/// The identifiers in a C/C++ fragment, skipping string and character literals.
fn identifiers(code: &str) -> Vec<&str> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            let quote = c;
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            out.push(&code[start..i]);
            continue;
        }
        if c.is_ascii_digit() {
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    out
}

/// A short, stable description of how a decl decodes its parameter: the first
/// runtime decoder it calls (without the cursor argument), or how it uses the
/// whole input.
fn decoder_label(decl: &str) -> String {
    let label = match first_runtime_call(decl) {
        Some((name, _)) if name == "bhf_make_tempfile" => "input file".to_owned(),
        Some((name, args)) => {
            let args: Vec<&str> = args
                .iter()
                .map(|a| a.as_str())
                .filter(|a| *a != "&Cur")
                .collect();
            let more = decl.matches("bhf_").count() > 1;
            format!(
                "{name}({}){}",
                args.join(", "),
                if more { " ..." } else { "" }
            )
        }
        None => match source_of(decl) {
            Source::Input if decl.contains("fmemopen") => "input stream".to_owned(),
            Source::Input
                if ["malloc", "calloc", "memcpy", "std::vector", "std::string"]
                    .iter()
                    .any(|w| decl.contains(w)) =>
            {
                "input copy".to_owned()
            }
            Source::Input => "input view".to_owned(),
            _ if decl.trim().is_empty() || decl.trim_start().starts_with("/*") => {
                "declared with the neighbouring parameter".to_owned()
            }
            _ => "fixed".to_owned(),
        },
    };
    truncate(&label, MAX_DECODER)
}

/// The first `bhf_*` runtime call in a decl and its top-level arguments.
fn first_runtime_call(decl: &str) -> Option<(String, Vec<String>)> {
    let bytes = decl.as_bytes();
    let mut search = 0;
    while let Some(found) = decl[search..].find("bhf_") {
        let start = search + found;
        search = start + 4;
        if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            continue;
        }
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if bytes.get(end) != Some(&b'(') {
            continue;
        }
        let name = decl[start..end].to_owned();
        let args = call_args(&decl[end..])?;
        return Some((name, args));
    }
    None
}

/// The top-level, whitespace-normalized arguments of the call starting at the
/// `(` that begins `text`.
fn call_args(text: &str) -> Option<Vec<String>> {
    let mut depth = 0usize;
    let mut args = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        match c {
            '(' => {
                depth += 1;
                if depth == 1 {
                    continue;
                }
            }
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let arg = normalize_space(&current);
                    if !arg.is_empty() {
                        args.push(arg);
                    }
                    return Some(args);
                }
            }
            ',' if depth == 1 => {
                args.push(normalize_space(&current));
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    None
}

fn normalize_space(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The decoder's own content length for a pointer parameter, as a C
/// expression in scope after the decl, or `BHF_TRACE_NO_LEN`.
///
/// Only the harness's `Size` and the helper variables the decoders declare at
/// the decl's top level (`_bhf_cap_<name>`, `_bhf_copy_<name>`,
/// `_bhf_ntlen_<name>`, `_bhf_n_<name>`) are used, so the expression always
/// names something declared where the trace runs.
fn known_len(decl: &str, arg: &str) -> String {
    let none = "BHF_TRACE_NO_LEN".to_owned();
    let name = arg.trim_start_matches('&').trim();
    if !is_identifier(name) {
        return none;
    }
    let declared_helper = |candidate: &str| {
        let helpers = [
            format!("_bhf_cap_{name}"),
            format!("_bhf_copy_{name}"),
            format!("_bhf_ntlen_{name}"),
            format!("_bhf_n_{name}"),
        ];
        helpers.iter().any(|helper| {
            helper == candidate
                && (decl.starts_with(&format!("size_t {helper} ="))
                    || decl.contains(&format!("; size_t {helper} ="))
                    || decl.contains(&format!(" size_t {helper} =")))
        })
    };
    if let Some(at) = decl.find("memcpy(") {
        if let Some(args) = call_args(&decl[at + "memcpy".len()..]) {
            if let Some(count) = args.get(2) {
                if count == "Size" || declared_helper(count) {
                    return format!("(size_t)({count})");
                }
            }
        }
        return none;
    }
    if decl.contains(")Data") || decl.contains("= Data") {
        return "(size_t)(Size)".to_owned();
    }
    let count = format!("_bhf_n_{name}");
    if declared_helper(&count) {
        return format!("(size_t)({count})");
    }
    none
}

/// `BHF_TRACE_NUL` when the decl builds a NUL-terminated string.
fn nul_flag(decl: &str) -> &'static str {
    if [
        "bhf_c_string(",
        "bhf_c_string_out(",
        "bhf_c_format_string(",
        "bhf_make_tempfile(",
    ]
    .iter()
    .any(|decoder| decl.contains(decoder))
    {
        "BHF_TRACE_NUL"
    } else {
        "0"
    }
}

/// A pointer the decl points at storage the harness declared (`= &_bhf_x`),
/// so its pointee is always valid to read.
fn is_storage_backed(decl: &str, arg: &str) -> bool {
    arg.starts_with("&_bhf_") || (is_identifier(arg) && decl.contains(&format!("{arg} = &_bhf_")))
}

/// A `const` qualifies what the outermost pointer points at.
fn pointee_is_const(ty: &str) -> bool {
    let spaced = ty.replace('*', " * ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let Some(last_star) = tokens.iter().rposition(|t| *t == "*") else {
        return tokens.contains(&"const");
    };
    tokens[..last_star].contains(&"const")
}

/// `T &` with a non-const `T`: the callee may write the argument.
fn is_cpp_nonconst_lvalue_ref(ty: &str) -> bool {
    let ty = ty.trim();
    let Some(base) = ty.strip_suffix('&') else {
        return false;
    };
    if base.trim_end().ends_with('&') {
        return false;
    }
    let spaced = base.replace('*', " * ").replace(['<', '>', ','], " ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    match tokens.iter().rposition(|t| *t == "*") {
        // A reference to a pointer: the pointer itself may be reseated unless
        // it is `T *const &`.
        Some(star) => !tokens[star + 1..].contains(&"const"),
        None => !tokens.contains(&"const"),
    }
}

fn is_cpp_writable_pointer(ty: &str) -> bool {
    ty.trim_end().ends_with('*') && !pointee_is_const(ty)
}

/// The shape of a C type by its spelling alone, when no registry is at hand.
fn spelled_shape(c_type: &str) -> TypeShape {
    let canonical = c_type
        .replace('*', " * ")
        .split_whitespace()
        .filter(|t| !matches!(*t, "const" | "volatile" | "restrict" | "struct" | "enum"))
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(base) = canonical.strip_suffix(" *") {
        return match base.trim() {
            "char" => TypeShape::CString,
            other => TypeShape::Pointer(Box::new(spelled_shape(other))),
        };
    }
    let kind = match canonical.as_str() {
        "_Bool" | "bool" => ScalarKind::Bool,
        "char" | "signed char" | "int8_t" => ScalarKind::I8,
        "unsigned char" | "uint8_t" => ScalarKind::U8,
        "short" | "short int" | "signed short" | "int16_t" => ScalarKind::I16,
        "unsigned short" | "unsigned short int" | "uint16_t" => ScalarKind::U16,
        "int" | "signed" | "signed int" | "int32_t" => ScalarKind::I32,
        "unsigned" | "unsigned int" | "uint32_t" => ScalarKind::U32,
        "long" | "long int" | "long long" | "int64_t" | "ssize_t" | "ptrdiff_t" => ScalarKind::I64,
        "unsigned long" | "unsigned long long" | "uint64_t" | "size_t" | "uintptr_t" => {
            ScalarKind::U64
        }
        "float" => ScalarKind::F32,
        "double" | "long double" => ScalarKind::F64,
        _ => return TypeShape::Opaque(canonical),
    };
    TypeShape::Scalar(kind)
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn fallback_name(arg: &str, index: usize) -> String {
    let bare = arg.trim().trim_start_matches('&').trim();
    if is_identifier(bare) {
        bare.to_owned()
    } else {
        format!("arg{index}")
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

/// `{"k":"v",...` without the closing brace: the head of a trace line. `i` is
/// written as a number, every other value as a string.
fn json_head(fields: &[(&str, &str)]) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(key);
        out.push_str("\":");
        if *key == "i" {
            out.push_str(value);
            continue;
        }
        let limit = match *key {
            "name" => MAX_NAME,
            "type" => MAX_TYPE,
            _ => MAX_DECODER,
        };
        out.push('"');
        out.push_str(&json_escape(&truncate(value, limit)));
        out.push('"');
    }
    out
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || !c.is_ascii() => {
                out.push_str(&format!("\\u{:04x}", c as u32 & 0xffff));
            }
            c => out.push(c),
        }
    }
    out
}

/// A C string literal holding `text` (ASCII, as `json_head` produces), with
/// `?` escaped so no trigraph forms in a C89 harness.
pub(crate) fn c_string_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '?' => out.push_str("\\?"),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => out.push_str(&format!("\\{:03o}", (c as u32) & 0xff)),
        }
    }
    out.push('"');
    out
}

/// The trace statement for a C++ method's receiver object `_bhf_receiver`:
/// its class and how it was built (`how`), and its address or object bytes.
pub(crate) fn receiver_statement(class: &str, how: &str) -> String {
    let head = json_head(&[
        ("call", "receiver"),
        ("i", "-1"),
        ("role", "receiver"),
        ("name", "this"),
        ("type", class),
        ("decoder", how),
    ]);
    format!(
        "if (bhf_trace_on()) {{ bhf_tl_begin({}); \
         bhf_trace_value((_bhf_receiver), Data, Size, BHF_TRACE_NO_LEN, 0); bhf_tl_end(); }}",
        c_string_literal(&head)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emission(decl: &str, arg: &str, c_type: &str) -> CParamEmission {
        CParamEmission {
            support: None,
            decl: decl.to_owned(),
            arg: arg.to_owned(),
            c_type: c_type.to_owned(),
            free: None,
        }
    }

    fn c_group<'a>(registry: &'a TypeRegistry) -> Group<'a> {
        Group {
            lang: Lang::C,
            prefix: "p",
            call: "target",
            role: Role::Param,
            index_base: 0,
            registry: Some(registry),
        }
    }

    #[test]
    fn cursor_decls_are_bracketed_by_position_captures_and_traced_after_all_of_them() {
        let registry = TypeRegistry::default();
        let emissions = [
            emission("int32_t a = bhf_i32(&Cur)", "a", "int32_t"),
            emission(
                "uint16_t b = (uint16_t)bhf_bounded_i32(&Cur, 0, 0xffff)",
                "b",
                "uint16_t",
            ),
        ];
        let plan = plan(
            &c_group(&registry),
            &emissions,
            &[
                Declared::new("a", "int32_t"),
                Declared::new("b", "uint16_t"),
            ],
        );
        assert_eq!(
            plan.decode[..5],
            [
                "size_t _bhf_at_p0 = Cur.pos".to_owned(),
                "int32_t a = bhf_i32(&Cur)".to_owned(),
                "size_t _bhf_at_p1 = Cur.pos".to_owned(),
                "uint16_t b = (uint16_t)bhf_bounded_i32(&Cur, 0, 0xffff)".to_owned(),
                "size_t _bhf_at_p2 = Cur.pos".to_owned(),
            ]
        );
        assert!(plan.decode[5].contains("bhf_tl_span((size_t)(_bhf_at_p0), (size_t)(_bhf_at_p1));"));
        assert!(plan.decode[5].contains("bhf_tr_i64((int64_t)(a));"));
        assert!(plan.decode[5].contains(r#"\"decoder\":\"bhf_i32()\""#));
        assert!(plan.decode[6].contains("bhf_tl_span((size_t)(_bhf_at_p1), (size_t)(_bhf_at_p2));"));
        assert!(plan.decode[6].contains("bhf_tr_u64((uint64_t)(b));"));
        assert!(plan.decode[6].contains(r#"\"decoder\":\"bhf_bounded_i32(0, 0xffff)\""#));
        assert!(plan.after.is_empty());
    }

    #[test]
    fn whole_input_buffers_span_the_input_and_report_their_copied_length() {
        let registry = TypeRegistry::default();
        let decl = "size_t _bhf_cap_data = (size_t)Size + 1; if (_bhf_cap_data < 8) \
                    _bhf_cap_data = 8; const uint8_t * data = (const uint8_t *)malloc(_bhf_cap_data); \
                    if (data) { memset((void *)data, 0, _bhf_cap_data); if (Size) memcpy((void *)data, Data, Size); \
                    ((char *)data)[Size] = '\\0'; }";
        let plan = plan(
            &c_group(&registry),
            &[emission(decl, "data", "const uint8_t *")],
            &[Declared::new("data", "const byte_t *")],
        );
        let trace = plan.decode.last().unwrap();
        assert!(
            trace.contains("bhf_tl_span((size_t)(0), (size_t)(Size));"),
            "{trace}"
        );
        assert!(
            trace.contains("bhf_tr_ptr((const void *)(data), Data, Size, (size_t)(Size), 0);"),
            "{trace}"
        );
        assert!(trace.contains(r#"\"type\":\"const byte_t *\""#), "{trace}");
        assert!(trace.contains(r#"\"decoder\":\"input copy\""#), "{trace}");
    }

    #[test]
    fn a_pair_length_bound_to_the_buffer_size_names_its_capacity_variable() {
        let decl = "size_t _bhf_cap_buf = Size <= (1024 * 1024) ? (size_t)Size : (1024 * 1024); \
                    unsigned char * buf = (unsigned char *)malloc(_bhf_cap_buf ? _bhf_cap_buf : 1); \
                    if (buf && _bhf_cap_buf) memcpy(buf, Data, _bhf_cap_buf)";
        assert_eq!(known_len(decl, "buf"), "(size_t)(_bhf_cap_buf)");
        assert_eq!(
            known_len("const char * s = (const char *)Data", "s"),
            "(size_t)(Size)"
        );
        // A count expression that is not a top-level helper is never used.
        assert_eq!(
            known_len("for (size_t i = 0; i < n; ++i) memcpy(x, Data, i)", "x"),
            "BHF_TRACE_NO_LEN"
        );
    }

    #[test]
    fn length_prefixed_strings_are_nul_flagged_and_writable_ones_are_outputs() {
        let registry = TypeRegistry::default();
        let plan = plan(
            &c_group(&registry),
            &[
                emission(
                    "char *name = bhf_c_string(&Cur, 4096)",
                    "name",
                    "const char *",
                ),
                emission("char *out = bhf_c_string_out(&Cur, 4096)", "out", "char *"),
            ],
            &[
                Declared::new("name", "const char *"),
                Declared::new("out", "char *"),
            ],
        );
        let name = &plan.decode[plan.decode.len() - 2];
        assert!(name.contains(
            "bhf_tr_str((const char *)(name), Data, Size, BHF_TRACE_NO_LEN, BHF_TRACE_NUL);"
        ));
        assert!(name.contains(r#"\"role\":\"param\""#));
        let out = plan.decode.last().unwrap();
        assert!(out.contains(r#"\"role\":\"out\""#), "{out}");
        assert_eq!(plan.after.len(), 1);
        assert!(plan.after[0].contains(r#"\"phase\":\"after\""#));
    }

    #[test]
    fn a_pointer_to_scalar_storage_prints_its_value_before_and_after_the_call() {
        let registry = TypeRegistry::default();
        let plan = plan(
            &c_group(&registry),
            &[emission(
                "int _bhf_out_count = bhf_i32(&Cur); int * count = &_bhf_out_count",
                "count",
                "int *",
            )],
            &[Declared::new("count", "int *")],
        );
        let before = plan.decode.last().unwrap();
        assert!(
            before.contains("if (count) { bhf_tr_i64((int64_t)(*(count))); }"),
            "{before}"
        );
        assert!(before.contains(r#"\"role\":\"out\""#));
        assert_eq!(plan.after.len(), 1);
        assert!(plan.after[0].contains("bhf_tr_i64((int64_t)(*(count)));"));
    }

    #[test]
    fn typedefs_are_classified_through_the_registry() {
        let defs = c_parser::parse_c_type_defs("typedef unsigned int word_t;").unwrap();
        let registry = TypeRegistry::from_defs([&defs]);
        let plan = plan(
            &c_group(&registry),
            &[emission(
                "word_t width = (word_t)(uint32_t)bhf_i32(&Cur)",
                "width",
                "word_t",
            )],
            &[Declared::new("width", "word_t")],
        );
        assert!(plan
            .decode
            .last()
            .unwrap()
            .contains("bhf_tr_u64((uint64_t)(width));"));
    }

    #[test]
    fn cpp_references_are_in_out_and_moved_arguments_are_traced_before_the_move() {
        let group = Group {
            lang: Lang::Cpp,
            prefix: "p",
            call: "target",
            role: Role::Param,
            index_base: 0,
            registry: None,
        };
        let plan = plan(
            &group,
            &[
                emission(
                    "unsigned short offset = (unsigned short)bhf_bounded_i32(&Cur, 0, 0xffff)",
                    "offset",
                    "unsigned short &",
                ),
                emission(
                    "std::string s = bhf_cpp_string(&Cur)",
                    "std::move(s)",
                    "std::string",
                ),
                emission("int k = bhf_i32(&Cur)", "k", "const int &"),
            ],
            &[
                Declared::new("offset", "unsigned short&"),
                Declared::new("s", "std::string"),
                Declared::new("k", "const int &"),
            ],
        );
        let n = plan.decode.len();
        assert!(plan.decode[n - 3].contains(r#"\"role\":\"out\""#));
        assert!(plan.decode[n - 3]
            .contains("bhf_trace_value((offset), Data, Size, BHF_TRACE_NO_LEN, 0);"));
        assert!(plan.decode[n - 2].contains("bhf_trace_value((s), Data, Size"));
        assert!(plan.decode[n - 2].contains(r#"\"role\":\"param\""#));
        assert!(plan.decode[n - 1].contains(r#"\"role\":\"param\""#));
        assert_eq!(plan.after.len(), 1);
        assert!(plan.after[0].contains("bhf_trace_value((offset)"));
    }

    #[test]
    fn receiver_groups_mark_every_argument_as_a_receiver_argument() {
        let group = Group {
            lang: Lang::Cpp,
            prefix: "c",
            call: "receiver",
            role: Role::Receiver,
            index_base: 0,
            registry: None,
        };
        let plan = plan(
            &group,
            &[emission("int mode = bhf_i32(&Cur)", "mode", "int")],
            &[Declared::new("mode", "int")],
        );
        let trace = plan.decode.last().unwrap();
        assert!(trace.contains(r#"\"call\":\"receiver\""#));
        assert!(trace.contains(r#"\"role\":\"receiver\""#));
        assert!(plan.decode[0].starts_with("size_t _bhf_at_c0"));
    }

    #[test]
    fn heads_are_valid_json_and_safe_c_literals() {
        let head = json_head(&[
            ("call", "target"),
            ("i", "3"),
            ("name", "x"),
            ("type", "std::map<int, \"q\"??=>"),
        ]);
        let json: serde_json::Value = serde_json::from_str(&format!("{head}}}")).unwrap();
        assert_eq!(json["i"], 3);
        assert_eq!(json["type"], "std::map<int, \"q\"??=>");
        let literal = c_string_literal(&head);
        assert!(literal.contains(r"\?\?="), "{literal}");
        assert!(!literal[1..literal.len() - 1].contains("\"\""));
    }

    #[test]
    fn decoder_labels_name_the_runtime_call_or_the_input_use() {
        assert_eq!(
            decoder_label("char *s = bhf_c_string(&Cur, 4096)"),
            "bhf_c_string(4096)"
        );
        assert_eq!(
            decoder_label("const void * p = (const void *)Data"),
            "input view"
        );
        assert_eq!(
            decoder_label(
                "char p_path[bhf_tempfile_path_len]; const char *p_made = bhf_make_tempfile(Data, Size, p_path); const char * p = p_made ? p_path : \"\""
            ),
            "input file"
        );
        assert_eq!(decoder_label("void * h = NULL"), "fixed");
        assert_eq!(
            decoder_label("/* backing array declared with its preceding count */"),
            "declared with the neighbouring parameter"
        );
    }

    #[test]
    fn positions_are_captured_only_where_a_span_uses_them() {
        let registry = TypeRegistry::default();
        let plan = plan(
            &c_group(&registry),
            &[
                emission(
                    "const unsigned char * buf = (const unsigned char *)Data",
                    "buf",
                    "const unsigned char *",
                ),
                emission("size_t len = (size_t)Size", "len", "size_t"),
            ],
            &[],
        );
        assert!(
            plan.decode
                .iter()
                .all(|statement| !statement.contains("Cur.pos")),
            "{plan:#?}"
        );
    }

    #[test]
    fn an_address_argument_is_dereferenced_without_a_null_test() {
        let registry = TypeRegistry::default();
        let plan = plan(
            &c_group(&registry),
            &[emission(
                "int _bhf_out_n = bhf_i32(&Cur)",
                "&_bhf_out_n",
                "int *",
            )],
            &[Declared::new("n", "int *")],
        );
        let trace = plan.decode.last().unwrap();
        assert!(
            trace.contains("bhf_tr_i64((int64_t)(*(&_bhf_out_n)));"),
            "{trace}"
        );
        assert!(!trace.contains("if (&"), "{trace}");
    }

    #[test]
    fn no_parameters_plan_no_statements() {
        let registry = TypeRegistry::default();
        assert_eq!(plan(&c_group(&registry), &[], &[]), DecodePlan::default());
    }
}
