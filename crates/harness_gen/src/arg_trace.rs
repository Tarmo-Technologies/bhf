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
//!
//! The plan also fixes the call's input layout (harness format 3 and 4): the
//! parameters decoded from the cursor take the leading bytes, in parameter
//! order, and the parameters decoded from the whole input (`Data`/`Size`: a
//! lone byte buffer, a `(buffer, length)` pair, a `FILE *`, ...) take the bytes
//! the cursor left, so no input byte feeds two parameters. When a call has
//! several such buffers, every one but the last takes a sized slice of the
//! cursor instead (see [`slice_input_units`]).

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
    /// Put the whole-input parameters in [`DecodePlan::late`], for a template
    /// that decodes other calls' arguments (a C++ receiver's constructor, a
    /// lifecycle loop) between this call's decode and the call itself.
    pub defer_input: bool,
    /// Nothing has read the cursor before this call's parameters, and the
    /// cursor covers the whole input (`Data`/`Size`): the first call of a
    /// direct harness. A call with no cursor parameter then keeps its
    /// whole-input decls as written. Every other call (a C++ receiver's
    /// constructor or factory, a protocol or lifecycle step, a sequence
    /// operation) gives its whole-input parameters the bytes the cursor left.
    pub fresh_cursor: bool,
    /// Give a buffer with no length parameter an explicit length: 4 more
    /// cursor bytes, then that many bytes (see `bhf_take_sized`). Off by
    /// default; see [`crate::buffer_len_dimension_enabled`].
    pub sized_buffers: bool,
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
    /// With [`Group::defer_input`]: the whole-input parameters' statements,
    /// rendered right before the call.
    pub late: Vec<String>,
    /// After-call trace statements for output and in-out parameters.
    pub after: Vec<String>,
    /// The static decode layout of [`DecodePlan::decode`]'s parameters, in
    /// decode order (see [`crate::arg_layout`]).
    pub layout: Vec<crate::arg_layout::LayoutStep>,
    /// The layout of [`DecodePlan::late`]'s parameters.
    pub late_layout: Vec<crate::arg_layout::LayoutStep>,
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
    /// Takes the bytes of a sized slice of the cursor (see
    /// [`slice_input_units`]).
    Slice,
}

/// Prefixes of the locals holding the bytes of a call's sliced buffer (see
/// [`slice_input_units`]): the heap copy, its length and its offset in the
/// input. None is a prefix of another.
const SLICE: &str = "_bhf_slice_";
const SLICE_LEN: &str = "_bhf_slicelen_";
const SLICE_AT: &str = "_bhf_sliceat_";

/// The locals of the slice `id`: the copy, its length and its offset.
fn slice_locals(id: &str) -> (String, String, String) {
    (
        format!("{SLICE}{id}"),
        format!("{SLICE_LEN}{id}"),
        format!("{SLICE_AT}{id}"),
    )
}

/// The statements that take slice `id` from the cursor.
fn slice_prefix(id: &str) -> String {
    let (data, len, at) = slice_locals(id);
    format!(
        "size_t {len} = 0; size_t {at} = 0; \
         uint8_t *{data} = bhf_take_sized_copy(&Cur, &{len}, &{at})"
    )
}

/// The slice whose locals `code` names, if any.
fn slice_named(code: &str) -> Option<String> {
    identifiers(code).into_iter().find_map(|id| {
        [SLICE_LEN, SLICE_AT, SLICE]
            .iter()
            .find_map(|prefix| id.strip_prefix(prefix))
            .map(str::to_owned)
    })
}

/// Give each buffer of one call its own bytes when the call takes several
/// (format 4).
///
/// `units` partitions `emissions` into the parameters decoded together: a
/// `(buffer, length)` pair, a lone buffer, a scalar. A unit that reads the
/// input bytes (`Data`) without the cursor would otherwise share the bytes
/// the cursor left with every other such unit of the call, so two buffers got
/// the same bytes, and a second pair's length was decoded on its own and
/// could exceed its buffer. Every such unit but the last now takes a sized
/// slice of the cursor instead (`bhf_take_sized_copy`: a 4-byte length, then
/// that many bytes, in a heap copy of exactly that size), its `Data`/`Size`
/// become the slice and its length, and the copy is freed with the unit's
/// first parameter. The last keeps the bytes the cursor leaves. A unit that
/// only uses the input size (an output buffer's capacity) reads no bytes and
/// is left alone.
pub(crate) fn slice_input_units(
    emissions: &mut [CParamEmission],
    units: &[std::ops::Range<usize>],
) {
    let reads_input = |unit: &std::ops::Range<usize>| {
        let unit = &emissions[unit.clone()];
        unit.iter().any(|emission| {
            identifiers(&format!("{} {}", emission.decl, emission.arg)).contains(&"Data")
        }) && unit
            .iter()
            .all(|emission| source_of(&emission.decl) != Source::Cursor)
    };
    let input_units: Vec<std::ops::Range<usize>> = units
        .iter()
        .filter(|unit| reads_input(unit))
        .cloned()
        .collect();
    let Some((_, sliced)) = input_units.split_last() else {
        return;
    };
    let mut taken: Vec<String> = Vec::new();
    for unit in sliced {
        let first = &emissions[unit.start];
        let base = first.arg.trim().trim_start_matches('&').trim();
        let base = if is_identifier(base) {
            base.to_owned()
        } else {
            declared_names(first)
                .last()
                .map(|name| (*name).to_owned())
                .unwrap_or_else(|| format!("u{}", unit.start))
        };
        let mut id = base.clone();
        let mut n = 1;
        while taken.contains(&id) {
            id = format!("{base}_{n}");
            n += 1;
        }
        taken.push(id.clone());
        let (data, len, _) = slice_locals(&id);
        for emission in &mut emissions[unit.clone()] {
            emission.decl = rewrite_input(&emission.decl, &data, &len);
            emission.arg = rewrite_input(&emission.arg, &data, &len);
            emission.free = emission
                .free
                .as_deref()
                .map(|free| rewrite_input(free, &data, &len));
        }
        let first = &mut emissions[unit.start];
        first.decl = if first.decl.trim().is_empty() {
            slice_prefix(&id)
        } else {
            format!("{}; {}", slice_prefix(&id), first.decl)
        };
        let release = format!("free({data})");
        first.free = Some(match first.free.take() {
            Some(free) => format!("{free}; {release}"),
            None => release,
        });
    }
}

/// A sliced emission as the decoder emitted it before
/// [`slice_input_units`]: its decl and argument with the slice locals back to
/// `Data`/`Size` and the slice statements removed, so it can be classified
/// and traced like any whole-input parameter.
fn unsliced(emission: &CParamEmission, id: &str) -> CParamEmission {
    let (data, len, _) = slice_locals(id);
    let back = |code: &str| {
        let renamed: String = {
            let mut out = String::with_capacity(code.len());
            let mut last = 0;
            for (at, word) in identifier_spans(code) {
                let replacement = if word == data {
                    Some("Data")
                } else if word == len {
                    Some("Size")
                } else {
                    None
                };
                if let Some(replacement) = replacement {
                    out.push_str(&code[last..at]);
                    out.push_str(replacement);
                    last = at + word.len();
                }
            }
            out.push_str(&code[last..]);
            out
        };
        renamed
    };
    let prefix = format!("{}; ", slice_prefix(id));
    let decl = emission
        .decl
        .strip_prefix(&prefix)
        .or_else(|| (emission.decl == slice_prefix(id)).then_some(""))
        .unwrap_or(&emission.decl);
    CParamEmission {
        support: emission.support.clone(),
        decl: back(decl),
        arg: back(&emission.arg),
        c_type: emission.c_type.clone(),
        free: emission.free.clone(),
    }
}

/// Names a generated harness function declares or calls itself: the input
/// (`Data`, `Size`), its cursor (`Cur`), the result (`R`), every helper local
/// (`_bhf_*`), the runtime (`bhf_*`) and the C library functions the decoders
/// call. A target parameter of one of these names would shadow or redefine
/// it.
const RESERVED_NAMES: &[&str] = &[
    "Data", "Size", "Cur", "R", "malloc", "calloc", "realloc", "free", "memcpy", "memset",
    "fmemopen", "fclose", "fwrite", "rewind", "tmpfile", "unlink", "strlen",
];

/// The local a generated harness declares for a target parameter named
/// `name`: the name itself, or `bhf_arg_<name>` when the harness already
/// uses that name ([`RESERVED_NAMES`], `_bhf_*`, `bhf_*`). Arguments are
/// passed by position, so the call means the same; the trace and the layout
/// keep the declared name.
pub(crate) fn harness_local_name(name: &str) -> String {
    if RESERVED_NAMES.contains(&name) || name.starts_with("_bhf_") || name.starts_with("bhf_") {
        format!("bhf_arg_{name}")
    } else {
        name.to_owned()
    }
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
    let rest = format!("_bhf_rest_{}", group.prefix);
    let rest_size = format!("_bhf_rest_size_{}", group.prefix);
    let rest_at = format!("_bhf_rest_at_{}", group.prefix);
    let slices = slice_ids(emissions);
    let sources: Vec<Source> = emissions
        .iter()
        .zip(&slices)
        .map(|(emission, slice)| match slice {
            Some(_) => Source::Slice,
            None => source_of(&format!("{} {}", emission.decl, emission.arg)),
        })
        .collect();
    let mut order = decode_order(emissions);
    let mut tail_start = order
        .iter()
        .position(|&(_, deferred)| deferred)
        .unwrap_or(order.len());
    let sized = group.sized_buffers
        && order[tail_start..]
            .iter()
            .any(|&(index, _)| is_lone_input_buffer(emissions, index));
    // With no cursor parameter in this call, nothing decoded before it and
    // nothing decoded between the call's decode and the call, the bytes the
    // cursor left are the whole input: keep the decls as written, in
    // parameter order.
    let head_reads_cursor = order[..tail_start]
        .iter()
        .any(|&(index, _)| matches!(sources[index], Source::Cursor | Source::Slice));
    if !head_reads_cursor && group.fresh_cursor && !group.defer_input && !sized {
        order = (0..emissions.len()).map(|index| (index, false)).collect();
        tail_start = order.len();
    }
    // A cursor position is captured only where a span uses it: an unused
    // local would fail a project build that adds `-Werror -Wunused`.
    let mut captured = vec![false; order.len() + 1];
    for (position, &(index, _)) in order.iter().enumerate() {
        if sources[index] == Source::Cursor {
            captured[position] = true;
            captured[position + 1] = true;
        }
    }
    let mut plan = DecodePlan::default();
    let mut head = Vec::new();
    let mut tail = Vec::new();
    let mut spans: Vec<Option<(String, String)>> = vec![None; emissions.len()];
    for (position, &(index, deferred)) in order.iter().enumerate() {
        // A capture sits between two decode items; the one where the tail
        // starts closes the head (it precedes the remaining-input setup).
        if captured[position] {
            let list = if position <= tail_start {
                &mut head
            } else {
                &mut tail
            };
            list.push(format!("size_t {} = Cur.pos", at(position)));
        }
        let statements = if deferred { &mut tail } else { &mut head };
        if deferred && position == tail_start {
            // The bytes the cursor has not read: what every whole-input
            // parameter of this call takes.
            if sized {
                statements.push(format!("size_t {rest_size} = 0"));
                statements.push(format!(
                    "const uint8_t *{rest} = bhf_take_sized(&Cur, &{rest_size})"
                ));
                statements.push(format!("size_t {rest_at} = (size_t)({rest} - Cur.data)"));
            } else {
                statements.push(format!("size_t {rest_at} = Cur.pos"));
                statements.push(format!("const uint8_t *{rest} = Cur.data + Cur.pos"));
                statements.push(format!("size_t {rest_size} = bhf_remaining(&Cur)"));
            }
            statements.push(format!("(void){rest}"));
            statements.push(format!("(void){rest_size}"));
        }
        let decl = if deferred {
            rewrite_input(&emissions[index].decl, &rest, &rest_size)
        } else {
            emissions[index].decl.clone()
        };
        if !decl.trim().is_empty() {
            statements.push(decl);
        }
        spans[index] = match sources[index] {
            Source::Cursor => Some((at(position), at(position + 1))),
            Source::Slice => {
                let (_, len, at) = slice_locals(slices[index].as_deref().unwrap_or_default());
                Some((at.clone(), format!("{at} + {len}")))
            }
            Source::Input if deferred => {
                Some((rest_at.clone(), format!("{rest_at} + {rest_size}")))
            }
            Source::Input => Some(("0".to_owned(), "Size".to_owned())),
            Source::None => None,
        };
    }
    let last = if tail.is_empty() {
        &mut head
    } else {
        &mut tail
    };
    if captured[order.len()] {
        last.push(format!("size_t {} = Cur.pos", at(order.len())));
    }
    for &(index, deferred) in &order {
        let declared = (declared.len() == emissions.len()).then(|| &declared[index]);
        if let Some(id) = &slices[index] {
            // Traced as the whole-input parameter it was, over its slice.
            let (data, len, _) = slice_locals(id);
            let traced = trace_param(
                group,
                index,
                &unsliced(&emissions[index], id),
                declared,
                spans[index].clone(),
            );
            head.push(rewrite_input(&traced.before, &data, &len));
            if let Some(after) = traced.after {
                plan.after.push(rewrite_input(&after, &data, &len));
            }
            continue;
        }
        let traced = trace_param(
            group,
            index,
            &emissions[index],
            declared,
            spans[index].clone(),
        );
        let (before, after) = if deferred {
            (
                rewrite_input(&traced.before, &rest, &rest_size),
                traced
                    .after
                    .map(|after| rewrite_input(&after, &rest, &rest_size)),
            )
        } else {
            (traced.before, traced.after)
        };
        if deferred {
            tail.push(before);
        } else {
            head.push(before);
        }
        if let Some(after) = after {
            plan.after.push(after);
        }
    }
    let (head_layout, tail_layout) = layout_steps(
        group, emissions, declared, &order, &sources, &slices, tail_start, sized,
    );
    plan.decode = head;
    plan.layout = head_layout;
    if group.defer_input {
        plan.late = tail;
        plan.late_layout = tail_layout;
    } else {
        plan.decode.extend(tail);
        plan.layout.extend(tail_layout);
    }
    plan
}

/// The layout steps of one call's parameters, in decode order, split where
/// its whole-input parameters start (the head, then the tail that takes the
/// bytes the cursor left). A sliced buffer is described as the whole-input
/// parameter it was, taking a sized remainder of its own.
#[allow(clippy::too_many_arguments)]
fn layout_steps(
    group: &Group<'_>,
    emissions: &[CParamEmission],
    declared: &[Declared],
    order: &[(usize, bool)],
    sources: &[Source],
    slices: &[Option<String>],
    tail_start: usize,
    sized: bool,
) -> (
    Vec<crate::arg_layout::LayoutStep>,
    Vec<crate::arg_layout::LayoutStep>,
) {
    use crate::arg_layout::{InputSource, LayoutStep};
    let role = match group.role {
        Role::Param => "param",
        Role::Receiver => "receiver",
    };
    let mut params = Vec::with_capacity(order.len());
    for (position, &(index, deferred)) in order.iter().enumerate() {
        let unsliced_emission = slices[index]
            .as_deref()
            .map(|id| unsliced(&emissions[index], id));
        let emission = unsliced_emission.as_ref().unwrap_or(&emissions[index]);
        let declared = (declared.len() == emissions.len()).then(|| &declared[index]);
        let name = declared
            .map(|d| d.name.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| fallback_name(&emission.arg, index));
        let ty = declared
            .map(|d| d.ty.trim().to_owned())
            .filter(|ty| !ty.is_empty())
            .unwrap_or_else(|| emission.c_type.trim().to_owned());
        let shape = group
            .registry
            .map(|registry| registry.resolve(&emission.c_type))
            .unwrap_or_else(|| spelled_shape(&emission.c_type));
        let source = match (sources[index], deferred) {
            (Source::Cursor, _) => InputSource::Cursor,
            (Source::Input, true) | (Source::None, true) | (Source::Slice, _) => {
                InputSource::Remainder
            }
            (Source::Input, false) => InputSource::WholeInput,
            (Source::None, false) => InputSource::None,
        };
        let mut param = crate::arg_layout::describe(&crate::arg_layout::Described {
            call: group.call,
            role,
            index: group.index_base + index,
            name: &name,
            ty: &ty,
            order: position,
            decl: &emission.decl,
            arg: &emission.arg,
            source,
            shape: &shape,
        });
        // A slice's bytes are a heap copy of their own.
        if slices[index].is_some() && param.decoder == "input_buffer" {
            param.copied = Some(true);
        }
        params.push(param);
    }
    // Pairs are neighbours in parameter order, taking the same bytes.
    let mut by_index: Vec<usize> = (0..params.len()).collect();
    by_index.sort_by_key(|&at| params[at].index);
    let mut sorted: Vec<_> = by_index.iter().map(|&at| params[at].clone()).collect();
    let groups: Vec<Option<&str>> = by_index
        .iter()
        .map(|&at| slices[order[at].0].as_deref())
        .collect();
    crate::arg_layout::pair_input_params(&mut sorted, &groups);
    for (&at, param) in by_index.iter().zip(sorted) {
        params[at] = param;
    }
    let mut head = Vec::new();
    let mut tail = Vec::new();
    let mut sliced: Vec<&str> = Vec::new();
    for (position, (param, &(index, deferred))) in params.into_iter().zip(order).enumerate() {
        if deferred && position == tail_start {
            tail.push(LayoutStep::Remainder {
                call: group.call.to_owned(),
                sized,
            });
        }
        if let Some(id) = slices[index].as_deref() {
            if !sliced.contains(&id) {
                sliced.push(id);
                head.push(LayoutStep::Remainder {
                    call: group.call.to_owned(),
                    sized: true,
                });
            }
        }
        if deferred {
            tail.push(LayoutStep::Param(param));
        } else {
            head.push(LayoutStep::Param(param));
        }
    }
    (head, tail)
}

/// The slice (see [`slice_input_units`]) each emission takes its bytes from:
/// the one whose locals it names, or the one of a neighbour whose names it
/// uses (a length decoded from its buffer's copy).
fn slice_ids(emissions: &[CParamEmission]) -> Vec<Option<String>> {
    let mut slices: Vec<Option<String>> = emissions
        .iter()
        .map(|emission| slice_named(&format!("{} {}", emission.decl, emission.arg)))
        .collect();
    if slices.iter().all(Option::is_none) {
        return slices;
    }
    loop {
        let mut changed = false;
        for index in 0..emissions.len() {
            if slices[index].is_some() {
                continue;
            }
            let code = format!("{} {}", emissions[index].decl, emissions[index].arg);
            let used = identifiers(&code);
            let linked = (0..emissions.len()).find_map(|other| {
                let slice = slices[other].as_ref()?;
                declared_names(&emissions[other])
                    .iter()
                    .any(|name| used.contains(name))
                    .then(|| slice.clone())
            });
            if linked.is_some() {
                slices[index] = linked;
                changed = true;
            }
        }
        if !changed {
            return slices;
        }
    }
}

/// Whether any of a call's decls reads the input cursor.
pub(crate) fn reads_cursor(emissions: &[CParamEmission]) -> bool {
    emissions
        .iter()
        .any(|emission| source_of(&emission.decl) == Source::Cursor)
}

/// The order a call's parameters are decoded in, as `(index, deferred)`:
/// first every parameter that reads the cursor (or nothing), in parameter
/// order, then the deferred ones, in parameter order. A parameter is deferred
/// when its decl uses the whole input (`Data`/`Size`) without reading the
/// cursor, or when its decl or argument names something a deferred decl
/// declares (the other half of a pair, whose decl may be empty).
fn decode_order(emissions: &[CParamEmission]) -> Vec<(usize, bool)> {
    let used: Vec<Vec<&str>> = emissions
        .iter()
        .map(|emission| {
            let mut used = identifiers(&emission.decl);
            used.extend(identifiers(&emission.arg));
            used
        })
        .collect();
    let declares: Vec<Vec<&str>> = emissions.iter().map(declared_names).collect();
    let mut deferred: Vec<bool> = emissions
        .iter()
        .map(|emission| source_of(&emission.decl) == Source::Input)
        .collect();
    loop {
        let mut changed = false;
        for index in 0..emissions.len() {
            if deferred[index] {
                continue;
            }
            let bound = (0..emissions.len()).any(|other| {
                other != index
                    && deferred[other]
                    && used[index].iter().any(|id| declares[other].contains(id))
            });
            if bound {
                deferred[index] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let head = (0..emissions.len())
        .filter(|&i| !deferred[i])
        .map(|i| (i, false));
    let tail = (0..emissions.len())
        .filter(|&i| deferred[i])
        .map(|i| (i, true));
    head.chain(tail).collect()
}

/// The names a decl declares where later decls and the call can see them:
/// the declarator of each top-level statement (`T x = ...`, `T x[n]`,
/// `T x(...)`, `T x{...}`, `T (*x)(...)`). A name declared inside a block
/// (`if (p) { size_t n = 0; }`) is out of scope after the decl.
fn declared_names(emission: &CParamEmission) -> Vec<&str> {
    top_level_statements(&emission.decl)
        .into_iter()
        .filter_map(declarator)
        .collect()
}

/// The top-level statements of a decl: split at `;` and after a `}` that
/// closes a top-level block, outside brackets and literals.
fn top_level_statements(code: &str) -> Vec<&str> {
    let bytes = code.as_bytes();
    let mut statements = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            quote @ (b'"' | b'\'') => {
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    statements.push(&code[start..=i]);
                    start = i + 1;
                }
            }
            b';' if depth == 0 => {
                statements.push(&code[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    statements.push(&code[start.min(code.len())..]);
    statements
        .into_iter()
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .collect()
}

/// Statement keywords: a statement starting with one declares nothing.
const STATEMENT_KEYWORDS: &[&str] = &[
    "if", "else", "for", "while", "do", "switch", "case", "default", "return", "goto", "break",
    "continue", "delete", "throw", "sizeof", "new", "using", "typedef",
];

/// The name one statement declares, if it is a declaration.
fn declarator(statement: &str) -> Option<&str> {
    let bytes = statement.as_bytes();
    if !bytes
        .first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_' || *c == b':')
    {
        return None;
    }
    let first = identifiers(statement).into_iter().next()?;
    if STATEMENT_KEYWORDS.contains(&first) {
        return None;
    }
    // The text before the initializer, array bound or argument list.
    let mut angle = 0usize;
    let mut stop = bytes.len();
    for (at, &c) in bytes.iter().enumerate() {
        match c {
            b'<' => angle += 1,
            b'>' if angle > 0 => angle -= 1,
            b'=' | b'(' | b'[' | b'{' if angle == 0 => {
                stop = at;
                break;
            }
            _ => {}
        }
    }
    let head = statement[..stop].trim_end();
    let names: Vec<(usize, &str)> = identifier_spans(head);
    if names.len() >= 2 {
        let &(at, name) = names.last().expect("two names");
        let before = head[..at].trim_end();
        let declares = before
            .ends_with(|c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '*' | '&' | '>'))
            && !before.ends_with("->");
        return declares.then_some(name);
    }
    // `T (*name)(...)`: a function pointer.
    if names.len() == 1 && bytes.get(stop) == Some(&b'(') {
        let rest = statement[stop + 1..]
            .trim_start()
            .strip_prefix('*')?
            .trim_start();
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let params = rest[end..].trim_start().strip_prefix(')')?.trim_start();
        if is_identifier(name) && params.starts_with(['(', '[']) {
            return Some(name);
        }
    }
    None
}

/// A whole-input parameter no neighbour is bound to: a buffer without a
/// length parameter. A pair's other half sits next to it and uses the input
/// size or the buffer's own names.
fn is_lone_input_buffer(emissions: &[CParamEmission], index: usize) -> bool {
    let emission = &emissions[index];
    if !emission.c_type.contains('*') && !emission.c_type.contains('[') {
        return false;
    }
    let names = declared_names(emission);
    let neighbours = [index.checked_sub(1), Some(index + 1)];
    !neighbours.into_iter().flatten().any(|other| {
        emissions.get(other).is_some_and(|other| {
            identifiers(&format!("{} {}", other.decl, other.arg))
                .iter()
                .any(|id| matches!(*id, "Data" | "Size") || names.contains(id))
        })
    })
}

/// `code` with the harness's `Data`/`Size` identifiers renamed to the call's
/// remaining-input pointer and size (outside string and character literals,
/// and never a member of that name).
fn rewrite_input(code: &str, data: &str, size: &str) -> String {
    let bytes = code.as_bytes();
    let mut out = String::with_capacity(code.len() + 32);
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != c {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(bytes.len());
            out.push_str(&code[start..i]);
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            match &code[start..i] {
                "Data" if !is_member_name(code, start) => out.push_str(data),
                "Size" if !is_member_name(code, start) => out.push_str(size),
                word => out.push_str(word),
            }
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            out.push_str(&code[start..i]);
            continue;
        }
        let ch = code[i..].chars().next().expect("in bounds");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
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
/// `Cur`, or the harness's raw `Data`/`Size` (never a member of that name,
/// such as a struct field `hdr.Size`).
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
    // A decl that reads the cursor is decoded with the cursor even when it
    // also names the input: deferring it would read cursor bytes after the
    // remaining input was handed out.
    if cursor {
        Source::Cursor
    } else if input {
        Source::Input
    } else {
        Source::None
    }
}

/// The identifiers in a C/C++ fragment, skipping string and character
/// literals and member names (`x.name`, `p->name`, `ns::name`).
fn identifiers(code: &str) -> Vec<&str> {
    identifier_spans(code)
        .into_iter()
        .filter(|&(at, _)| !is_member_name(code, at))
        .map(|(_, id)| id)
        .collect()
}

/// Every identifier in a C/C++ fragment with its byte offset, skipping
/// comments, string and character literals and number suffixes.
fn identifier_spans(code: &str) -> Vec<(usize, &str)> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if bytes[i..].starts_with(b"/*") {
            i = bytes[i + 2..]
                .windows(2)
                .position(|pair| pair == b"*/")
                .map_or(bytes.len(), |end| i + 2 + end + 2);
            continue;
        }
        if bytes[i..].starts_with(b"//") {
            i = bytes[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(bytes.len(), |end| i + end);
            continue;
        }
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
            out.push((start, &code[start..i]));
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

/// The identifier at `at` in `code` names a member or a qualified name: it
/// follows `.`, `->` or `::`.
fn is_member_name(code: &str, at: usize) -> bool {
    let before = code[..at].trim_end();
    before.ends_with('.') || before.ends_with("->") || before.ends_with("::")
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
    // The end of a `[begin, end)` pair points past the input's bytes.
    if crate::arg_layout::points_past_input(decl) {
        return "(size_t)(0)".to_owned();
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
            defer_input: false,
            fresh_cursor: true,
            sized_buffers: false,
        }
    }

    /// Of a call's buffers, every one but the last takes a sized slice of
    /// the cursor, freed after the call, and the last the bytes left; a
    /// length the input size gives only (an output capacity) is left alone.
    #[test]
    fn every_buffer_but_the_last_takes_a_slice_of_its_own() {
        let mut emissions = vec![
            emission("const uint8_t * a = (const uint8_t *)Data", "a", "const uint8_t *"),
            emission("size_t alen = (size_t)Size", "alen", "size_t"),
            emission(
                "size_t _bhf_cap_out = Size + 65536; uint8_t * out = (uint8_t *)malloc(_bhf_cap_out)",
                "out",
                "uint8_t *",
            ),
            emission("size_t cap = (size_t)_bhf_cap_out", "cap", "size_t"),
            emission("int x = bhf_i32(&Cur)", "x", "int"),
            emission("const uint8_t * b = (const uint8_t *)Data", "b", "const uint8_t *"),
            emission("size_t blen = (size_t)Size", "blen", "size_t"),
        ];
        slice_input_units(&mut emissions, &[0..2, 2..4, 4..5, 5..7]);
        assert_eq!(
            emissions[0].decl,
            "size_t _bhf_slicelen_a = 0; size_t _bhf_sliceat_a = 0; \
             uint8_t *_bhf_slice_a = bhf_take_sized_copy(&Cur, &_bhf_slicelen_a, &_bhf_sliceat_a); \
             const uint8_t * a = (const uint8_t *)_bhf_slice_a"
        );
        assert_eq!(emissions[0].free.as_deref(), Some("free(_bhf_slice_a)"));
        assert_eq!(emissions[1].decl, "size_t alen = (size_t)_bhf_slicelen_a");
        assert!(
            emissions[2].decl.contains("Size + 65536"),
            "{:?}",
            emissions[2]
        );
        assert_eq!(
            emissions[5].decl,
            "const uint8_t * b = (const uint8_t *)Data"
        );

        let registry = TypeRegistry::default();
        let declared: Vec<Declared> = ["a", "alen", "out", "cap", "x", "b", "blen"]
            .iter()
            .zip(&emissions)
            .map(|(name, emission)| Declared::new(*name, emission.c_type.clone()))
            .collect();
        let plan = plan(&c_group(&registry), &emissions, &declared);
        let steps: Vec<String> = plan
            .layout
            .iter()
            .map(|step| match step {
                crate::arg_layout::LayoutStep::Param(p) => format!("{}:{}", p.name, p.input),
                crate::arg_layout::LayoutStep::Remainder { sized, .. } => {
                    format!("rest:{sized}")
                }
                crate::arg_layout::LayoutStep::Opaque { .. } => "opaque".to_owned(),
            })
            .collect();
        assert_eq!(
            steps,
            [
                "rest:true",
                "a:remainder",
                "alen:remainder",
                "x:cursor",
                "rest:false",
                "out:remainder",
                "cap:remainder",
                "b:remainder",
                "blen:remainder",
            ]
        );
        let param = |name: &str| {
            plan.layout
                .iter()
                .find_map(|step| match step {
                    crate::arg_layout::LayoutStep::Param(p) if p.name == name => Some(p.clone()),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(param("a").paired_with.as_deref(), Some("alen"));
        assert_eq!(param("a").copied, Some(true));
        assert_eq!(param("b").paired_with.as_deref(), Some("blen"));
        assert_eq!(param("alen").paired_with.as_deref(), Some("a"));
        // The slice's span is its bytes after the 4-byte length.
        assert!(
            plan.decode.iter().any(|statement| statement.contains(
                "bhf_tl_span((size_t)(_bhf_sliceat_a), (size_t)(_bhf_sliceat_a + _bhf_slicelen_a))"
            )),
            "{:#?}",
            plan.decode
        );
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
    fn whole_input_buffers_take_the_remaining_input_and_report_their_copied_length() {
        let registry = TypeRegistry::default();
        let decl = "size_t _bhf_cap_data = (size_t)Size + 1; if (_bhf_cap_data < 8) \
                    _bhf_cap_data = 8; const uint8_t * data = (const uint8_t *)malloc(_bhf_cap_data); \
                    if (data) { memset((void *)data, 0, _bhf_cap_data); if (Size) memcpy((void *)data, Data, Size); \
                    ((char *)data)[Size] = '\\0'; }";
        let emissions = [
            emission(decl, "data", "const uint8_t *"),
            emission("int k = bhf_i32(&Cur)", "k", "int"),
        ];
        let declared = [
            Declared::new("data", "const byte_t *"),
            Declared::new("k", "int"),
        ];
        let plan = plan(&c_group(&registry), &emissions, &declared);
        let at = |needle: &str| {
            plan.decode
                .iter()
                .position(|statement| statement.starts_with(needle))
                .unwrap_or_else(|| panic!("no {needle} in {plan:#?}"))
        };
        assert!(at("int k = bhf_i32(&Cur)") < at("size_t _bhf_rest_at_p = Cur.pos"));
        assert!(at("const uint8_t *_bhf_rest_p = Cur.data + Cur.pos") < at("size_t _bhf_cap_data"));
        assert!(at("size_t _bhf_rest_size_p = bhf_remaining(&Cur)") < at("size_t _bhf_cap_data"));
        let copy = &plan.decode[at("size_t _bhf_cap_data")];
        assert!(
            copy.contains("memcpy((void *)data, _bhf_rest_p, _bhf_rest_size_p)"),
            "{copy}"
        );
        assert!(!copy.contains("Size)"), "{copy}");
        let trace = plan
            .decode
            .iter()
            .find(|statement| statement.contains("\\\"name\\\":\\\"data\\\""))
            .unwrap();
        assert!(
            trace.contains(
                "bhf_tl_span((size_t)(_bhf_rest_at_p), (size_t)(_bhf_rest_at_p + _bhf_rest_size_p));"
            ),
            "{trace}"
        );
        assert!(
            trace.contains(
                "bhf_tr_ptr((const void *)(data), _bhf_rest_p, _bhf_rest_size_p, \
                 (size_t)(_bhf_rest_size_p), 0);"
            ),
            "{trace}"
        );
        assert!(trace.contains(r#"\"type\":\"const byte_t *\""#), "{trace}");
        assert!(trace.contains(r#"\"decoder\":\"input copy\""#), "{trace}");

        // Alone in its call, it is the whole input, decoded as written.
        let alone = super::plan(&c_group(&registry), &emissions[..1], &declared[..1]);
        assert_eq!(alone.decode[0], decl);
        assert!(alone.decode[1].contains("bhf_tl_span((size_t)(0), (size_t)(Size));"));
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
            defer_input: false,
            fresh_cursor: true,
            sized_buffers: false,
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
            defer_input: false,
            fresh_cursor: true,
            sized_buffers: false,
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
                .all(|statement| !statement.contains("_bhf_at_")),
            "{plan:#?}"
        );
    }

    #[test]
    fn cursor_parameters_are_decoded_before_the_whole_input_ones_they_follow() {
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
                emission("int bias = bhf_i32(&Cur)", "bias", "int"),
            ],
            &[],
        );
        let at = |needle: &str| {
            plan.decode
                .iter()
                .position(|statement| statement.starts_with(needle))
                .unwrap_or_else(|| panic!("no {needle} in {plan:#?}"))
        };
        assert!(at("int bias = bhf_i32(&Cur)") < at("size_t _bhf_rest_at_p = Cur.pos"));
        assert!(
            at("size_t _bhf_rest_at_p")
                < at("const unsigned char * buf = (const unsigned char *)_bhf_rest_p")
        );
        assert!(at("const unsigned char * buf") < at("size_t len = (size_t)_bhf_rest_size_p"));
        // The pair's length depends on nothing else, but uses the input size.
        assert!(plan
            .decode
            .iter()
            .all(|statement| !statement.contains("(size_t)Size")));
    }

    #[test]
    fn a_length_that_names_its_buffer_moves_with_it() {
        let registry = TypeRegistry::default();
        let order = decode_order(&[
            emission(
                "size_t _bhf_ntlen_s = Size; char *_bhf_ntbuf_s = (char *)malloc(_bhf_ntlen_s + 1); const char * s = _bhf_ntbuf_s",
                "s",
                "const char *",
            ),
            emission("int n = (int)(_bhf_ntbuf_s ? _bhf_ntlen_s : 0)", "n", "int"),
            emission("int k = bhf_i32(&Cur)", "k", "int"),
        ]);
        assert_eq!(order, vec![(2, false), (0, true), (1, true)]);
        let _ = registry;
    }

    #[test]
    fn the_explicit_length_applies_only_to_a_buffer_without_a_length_partner() {
        let registry = TypeRegistry::default();
        let mut group = c_group(&registry);
        group.sized_buffers = true;
        let lone = plan(
            &group,
            &[
                emission(
                    "const uint8_t * p = (const uint8_t *)Data",
                    "p",
                    "const uint8_t *",
                ),
                emission("int k = bhf_i32(&Cur)", "k", "int"),
            ],
            &[],
        );
        assert!(
            lone.decode
                .iter()
                .any(|statement| statement.contains("bhf_take_sized(&Cur, &_bhf_rest_size_p)")),
            "{lone:#?}"
        );
        let paired = plan(
            &group,
            &[
                emission(
                    "const uint8_t * p = (const uint8_t *)Data",
                    "p",
                    "const uint8_t *",
                ),
                emission("size_t n = (size_t)Size", "n", "size_t"),
            ],
            &[],
        );
        assert!(
            paired
                .decode
                .iter()
                .all(|statement| !statement.contains("bhf_take_sized")),
            "{paired:#?}"
        );
    }

    #[test]
    fn deferred_input_parameters_move_to_the_late_list() {
        let registry = TypeRegistry::default();
        let mut group = c_group(&registry);
        group.defer_input = true;
        let plan = plan(
            &group,
            &[
                emission(
                    "const uint8_t * p = (const uint8_t *)Data",
                    "p",
                    "const uint8_t *",
                ),
                emission("int k = bhf_i32(&Cur)", "k", "int"),
            ],
            &[],
        );
        assert!(plan
            .decode
            .iter()
            .any(|statement| statement == "int k = bhf_i32(&Cur)"));
        assert!(plan
            .decode
            .iter()
            .all(|statement| !statement.contains("_bhf_rest_")));
        assert!(plan
            .late
            .iter()
            .any(|statement| statement == "const uint8_t * p = (const uint8_t *)_bhf_rest_p"));
    }

    #[test]
    fn input_renaming_skips_literals_and_longer_identifiers() {
        assert_eq!(
            rewrite_input(
                r#"f(Data, Size, DataLen, "Data Size", 'S', my_Size); g(Data[Size - 1])"#,
                "_r",
                "_n"
            ),
            r#"f(_r, _n, DataLen, "Data Size", 'S', my_Size); g(_r[_n - 1])"#
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
    fn a_decl_declares_only_its_declarators() {
        let buffer = emission(
            "size_t _bhf_cap_s = (size_t)Size + 1; if (_bhf_cap_s < 8) _bhf_cap_s = 8; \
             const uint8_t * s = (const uint8_t *)malloc(_bhf_cap_s); \
             if (s) { memset((void *)s, 0, _bhf_cap_s); size_t inner = 0; (void)inner; }",
            "s",
            "const uint8_t *",
        );
        assert_eq!(declared_names(&buffer), vec!["_bhf_cap_s", "s"]);
        let order = decode_order(&[
            buffer,
            emission("size_t stride = (size_t)bhf_i64(&Cur)", "stride", "size_t"),
        ]);
        assert_eq!(order, vec![(1, false), (0, true)]);
        assert_eq!(
            declared_names(&emission(
                "char p_path[bhf_tempfile_path_len]; std::vector<uint8_t> v(Data, Data + Size); \
                 int (*cb)(int) = 0; x = 1; s.len = 2; Widget::reset(); return",
                "v",
                "std::vector<uint8_t>",
            )),
            vec!["p_path", "v", "cb"]
        );
        // Comments name nothing, and text outside ASCII is skipped.
        assert_eq!(
            identifiers("/* count of Data */ int n = 0; // Size\n m"),
            vec!["int", "n", "m"]
        );
        assert_eq!(identifiers("x \u{e9} y"), vec!["x", "y"]);
        assert!(declared_names(&emission("free(*p); f(x)", "p", "int *")).is_empty());
    }

    #[test]
    fn a_buffer_declared_by_its_length_moves_with_the_length() {
        let order = decode_order(&[
            emission("int level = bhf_i32(&Cur)", "level", "int"),
            emission(
                "size_t _bhf_cap_out = Size < (1024 * 1024) ? Size + 65536 : (1024 * 1024 + 65536); \
                 unsigned char * out = (unsigned char *)malloc(_bhf_cap_out ? _bhf_cap_out : 1); \
                 size_t _bhf_out_out_len = (size_t)(out ? _bhf_cap_out : 0); \
                 size_t *out_len = &_bhf_out_out_len",
                "out_len",
                "size_t *",
            ),
            emission("", "out", "unsigned char *"),
        ]);
        assert_eq!(order, vec![(0, false), (1, true), (2, true)]);
    }

    #[test]
    fn member_names_are_not_the_input() {
        let decl = "widget_hdr _bhf_value_hdr; _bhf_value_hdr.Size = (unsigned int)bhf_i32(&Cur); \
                    _bhf_value_hdr.Data = (unsigned int)bhf_i32(&Cur); const widget_hdr * hdr = &_bhf_value_hdr";
        assert_eq!(source_of(decl), Source::Cursor);
        assert_eq!(
            rewrite_input("w.Size = Size; p->Data = Data[0]; n::Size = 1", "_r", "_n"),
            "w.Size = _n; p->Data = _r[0]; n::Size = 1"
        );
        let registry = TypeRegistry::default();
        let plan = plan(
            &c_group(&registry),
            &[
                emission(decl, "hdr", "const widget_hdr *"),
                emission("int level = bhf_i32(&Cur)", "level", "int"),
            ],
            &[],
        );
        assert_eq!(plan.decode[1], decl, "{plan:#?}");
        assert!(plan
            .decode
            .iter()
            .all(|statement| !statement.contains("_bhf_rest_")));
        // A decl that reads the cursor stays with the cursor even when it also
        // names the input.
        assert_eq!(
            source_of("size_t n = bhf_bounded_length(&Cur, 0, Size)"),
            Source::Cursor
        );
    }

    #[test]
    fn a_group_after_other_decoding_takes_the_input_the_cursor_left() {
        let registry = TypeRegistry::default();
        let emissions = [emission(
            "std::vector<std::uint8_t> _bhf_ctor_blob(Data, Data + Size)",
            "_bhf_ctor_blob",
            "std::vector<std::uint8_t>",
        )];
        let fresh = plan(&c_group(&registry), &emissions, &[]);
        assert_eq!(fresh.decode[0], emissions[0].decl);
        let mut group = c_group(&registry);
        group.fresh_cursor = false;
        let later = plan(&group, &emissions, &[]);
        assert!(later.decode.iter().any(|statement| statement
            == "std::vector<std::uint8_t> _bhf_ctor_blob(_bhf_rest_p, _bhf_rest_p + _bhf_rest_size_p)"),
            "{later:#?}");
    }

    #[test]
    fn no_parameters_plan_no_statements() {
        let registry = TypeRegistry::default();
        assert_eq!(plan(&c_group(&registry), &[], &[]), DecodePlan::default());
    }
}
