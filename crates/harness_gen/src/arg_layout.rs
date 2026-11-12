// SPDX-License-Identifier: Apache-2.0

//! `arg-layout.json`: a static description of how a generated C/C++ harness
//! decodes its input into arguments.
//!
//! Generation writes one per C/C++ harness, beside `main.c` / `main.cpp`. It
//! lists the harness's decode steps in the order the harness runs them: each
//! parameter's decode (its order, input source, decoder kind, width,
//! endianness, bounds, length prefix and pairing), the points where a call's
//! whole-input parameters take the bytes the cursor left, and any step whose
//! input use is known only at run time (a lifecycle loop).
//!
//! [`ArgLayout::decode`] replays that description over a testcase for the
//! decoder kinds whose semantics are fixed by `c_runtime/bhf_decode.h`
//! (scalars, bounded integers, length-prefixed strings, whole-input,
//! remainder and paired buffers), so a testcase can be mapped to argument
//! values when the harness binary cannot be run. Anything else is reported
//! as not decoded, with the reason; the harness's own argument trace
//! (`BHF_TRACE_ARGS=1`) stays the authority.

use serde::{Deserialize, Serialize};
use std::path::Path;
use type_model::{ScalarKind, TypeShape};

/// The file name, beside the harness's `main.c` / `main.cpp`.
pub const ARG_LAYOUT_FILE: &str = "arg-layout.json";
/// `schema_version` of [`ArgLayout`].
pub const ARG_LAYOUT_SCHEMA: &str = "bhf.arg-layout.v1";

/// Leading bytes of a buffer shown in a decoded value's preview.
const PREVIEW_BYTES: usize = 32;
/// Longest C string the harness trace measures (`BHF_TRACE_STRING_MAX`).
const TRACE_STRING_MAX: usize = 1 << 16;

/// A harness's decode layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgLayout {
    pub schema_version: String,
    /// The harness input format the layout describes
    /// ([`crate::harness_format_version_for`]).
    pub harness_format_version: u32,
    /// The explicit buffer-length dimension was on
    /// ([`crate::buffer_len_dimension_enabled`]).
    #[serde(default)]
    pub buffer_len_dimension: bool,
    /// `c` or `cpp`.
    pub language: String,
    /// `direct`, `byte_stream` (the target is called once per input byte,
    /// which is not a listed parameter), `sequence` or `custom`.
    pub harness: String,
    /// Whether the steps can be replayed over a testcase at all.
    pub static_decode: bool,
    /// Why not, when they cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_decode_note: Option<String>,
    /// The decode steps, in the order the harness runs them.
    pub steps: Vec<LayoutStep>,
}

/// One decode step.
// A layout holds one step per parameter, a handful per harness: the size
// difference between the variants costs nothing worth an indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum LayoutStep {
    /// A parameter's decode.
    Param(ParamLayout),
    /// The bytes the cursor has not read are taken for `call`'s whole-input
    /// (`remainder`) parameters. `sized`: first a 4-byte little-endian length
    /// L, then the next `min(L, remaining)` bytes, which the cursor moves past
    /// (the explicit buffer-length dimension); otherwise every remaining byte,
    /// and the cursor does not move.
    Remainder { call: String, sized: bool },
    /// Harness code between decodes whose input use is known only at run
    /// time; static decoding stops here.
    Opaque { what: String },
}

/// How one parameter is decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamLayout {
    /// `target`, `receiver`, or the function the harness calls.
    pub call: String,
    /// `param` or `receiver` (a receiver's constructor or factory argument).
    pub role: String,
    /// Position in the call's parameter list.
    pub index: usize,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// Position among the call's parameters in decode order.
    pub order: usize,
    /// Where its bytes come from: `cursor` (read in order from the input),
    /// `remainder` (the bytes the cursor left, taken at the call's
    /// [`LayoutStep::Remainder`]), `whole_input` (the whole testcase, without
    /// the cursor) or `none` (the harness supplies it).
    pub input: String,
    /// `scalar`, `bounded_int`, `enum_member`, `length_prefixed_string`,
    /// `capacity_string`, `rest_view`, `input_buffer`, `input_length`,
    /// `input_end` (a pointer one past the bytes, a `[begin, end)` pair's
    /// end), `input_stream`, `input_file`, `fixed` or `other`.
    pub decoder: String,
    /// The `bhf_decode.h` function that reads it, when one does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primitive: Option<String>,
    /// Bytes read for a fixed-width value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// `little` for every multi-byte value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<String>,
    /// The scalar kind the value lands in (`u32`, `i16`, `bool`, `f64`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_kind: Option<String>,
    /// Converted through `uint32_t` (zero-extended) on the way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub via_uint32: bool,
    /// Only the low bit is kept (`(bhf_u8(&Cur) & 1)`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub low_bit: bool,
    /// A bounded integer's inclusive range: `lo + raw % (hi - lo + 1)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lo: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hi: Option<i64>,
    /// An enum's members in selector order (`enum_member`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// Bytes of a string's little-endian length prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_prefix_bytes: Option<u32>,
    /// A string's largest payload, or a capacity string's capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<u64>,
    /// `%` is replaced by a space (a format string).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub format_neutralized: bool,
    /// The value is a NUL-terminated string: the target reads it, and the
    /// harness trace measures it, up to the first NUL among its bytes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub nul_terminated: bool,
    /// The integer constant a `fixed` parameter is given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_value: Option<i64>,
    /// A buffer is a heap copy (`true`) or a view of the input (`false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copied: Option<bool>,
    /// The other half of a `(buffer, length)` pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_with: Option<String>,
    /// Cursor bytes consumed, when known statically, for a decode whose value
    /// is not (a struct decoded field by field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_bytes: Option<u64>,
    /// Whether [`ArgLayout::decode`] can compute this parameter's value.
    pub static_decode: bool,
    /// Why not, when it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A parameter's value as [`ArgLayout::decode`] computed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticArg {
    pub call: String,
    pub index: usize,
    pub role: String,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub decoder: String,
    /// `[start, end)` testcase bytes it was decoded from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<[u64; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// A buffer's length in bytes; a NUL-terminated string's up to its first
    /// NUL, as the harness trace measures it (its decoded bytes are the span).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
    /// Leading bytes (at most 32), as hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_hex: Option<String>,
    /// A length-prefixed string's prefix as read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_prefix: Option<u64>,
    /// Whether the value above was computed.
    pub decoded: bool,
    /// Why it was not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ArgLayout {
    /// A layout of `steps` for a `language` (`c`, `cpp`) harness of kind
    /// `harness`, stamped with the current input format.
    pub fn new(language: &str, harness: &str, steps: Vec<LayoutStep>) -> Self {
        ArgLayout {
            schema_version: ARG_LAYOUT_SCHEMA.to_owned(),
            harness_format_version: crate::harness_format_version_for(language),
            buffer_len_dimension: crate::buffer_len_dimension_enabled(),
            language: language.to_owned(),
            harness: harness.to_owned(),
            static_decode: true,
            static_decode_note: None,
            steps,
        }
    }

    /// The same layout, marked as not replayable over a testcase.
    pub fn without_static_decode(mut self, note: impl Into<String>) -> Self {
        self.static_decode = false;
        self.static_decode_note = Some(note.into());
        self
    }

    /// Write `<dir>/arg-layout.json`.
    pub fn write(&self, dir: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(dir.join(ARG_LAYOUT_FILE), bytes)
    }

    /// Read `<dir>/arg-layout.json`: `None` when there is none, an error when
    /// it does not parse or has another schema.
    pub fn read(dir: &Path) -> Option<Result<ArgLayout, String>> {
        let path = dir.join(ARG_LAYOUT_FILE);
        let bytes = std::fs::read(&path).ok()?;
        Some(
            serde_json::from_slice::<ArgLayout>(&bytes)
                .map_err(|error| format!("{}: {error}", path.display()))
                .and_then(|layout| {
                    if layout.schema_version == ARG_LAYOUT_SCHEMA {
                        Ok(layout)
                    } else {
                        Err(format!(
                            "{}: schema {} is not {ARG_LAYOUT_SCHEMA}",
                            path.display(),
                            layout.schema_version
                        ))
                    }
                }),
        )
    }

    /// The parameters, in decode order.
    pub fn params(&self) -> impl Iterator<Item = &ParamLayout> {
        self.steps.iter().filter_map(|step| match step {
            LayoutStep::Param(param) => Some(param),
            _ => None,
        })
    }

    /// Replay the layout over `input`: every parameter, in decode order, with
    /// its value and byte span when [`ParamLayout::static_decode`] allows and
    /// everything before it could be replayed, else with the reason it could
    /// not.
    pub fn decode(&self, input: &[u8]) -> Vec<StaticArg> {
        let mut cursor = Cursor { input, pos: 0 };
        // Why replaying stopped: every later cursor or remainder read is
        // unknown from there on.
        let mut stopped: Option<String> = (!self.static_decode).then(|| {
            self.static_decode_note
                .clone()
                .unwrap_or_else(|| "this harness's layout cannot be replayed".to_owned())
        });
        let mut remainders: Vec<(String, std::ops::Range<usize>)> = Vec::new();
        let mut out = Vec::new();
        for step in &self.steps {
            match step {
                LayoutStep::Opaque { what } => {
                    stopped.get_or_insert_with(|| {
                        format!(
                            "it is decoded after {what}, whose input use is known only at run time"
                        )
                    });
                }
                LayoutStep::Remainder { call, sized } => {
                    if stopped.is_some() {
                        continue;
                    }
                    let range = if *sized {
                        let want = cursor.read_le(4) as usize;
                        let start = cursor.pos;
                        let take = want.min(cursor.remaining());
                        cursor.pos += take;
                        start..start + take
                    } else {
                        cursor.pos..input.len()
                    };
                    remainders.retain(|(other, _)| other != call);
                    remainders.push((call.clone(), range));
                }
                LayoutStep::Param(param) => {
                    let mut arg = StaticArg {
                        call: param.call.clone(),
                        index: param.index,
                        role: param.role.clone(),
                        name: param.name.clone(),
                        ty: param.ty.clone(),
                        decoder: param.decoder.clone(),
                        span: None,
                        value: None,
                        len: None,
                        preview_hex: None,
                        length_prefix: None,
                        decoded: false,
                        reason: None,
                    };
                    match param.input.as_str() {
                        "cursor" => match &stopped {
                            Some(reason) => arg.reason = Some(reason.clone()),
                            None => {
                                if let Err(reason) = decode_cursor(param, &mut cursor, &mut arg) {
                                    arg.reason = Some(reason.clone());
                                    if param.cursor_bytes.is_none() {
                                        stopped = Some(format!(
                                            "it is decoded after `{}`, whose byte count is known \
                                             only at run time",
                                            param.name
                                        ));
                                    }
                                }
                            }
                        },
                        "remainder" | "whole_input" => {
                            let range = if param.input == "whole_input" {
                                Some(0..input.len())
                            } else {
                                remainders
                                    .iter()
                                    .find(|(call, _)| *call == param.call)
                                    .map(|(_, range)| range.clone())
                            };
                            // The whole input needs no cursor; the remainder
                            // is known only while the cursor is.
                            let blocked = stopped.as_ref().filter(|_| param.input != "whole_input");
                            match (range, blocked) {
                                (_, Some(reason)) => arg.reason = Some(reason.clone()),
                                (Some(range), None) => {
                                    decode_input(param, &input[range.clone()], range, &mut arg)
                                }
                                (None, None) => {
                                    arg.reason = Some(
                                        "the layout takes no remaining input for its call"
                                            .to_owned(),
                                    )
                                }
                            }
                        }
                        _ => match param.fixed_value {
                            Some(constant) if param.decoder == "fixed" => {
                                arg.value = Some(
                                    Value::Signed(constant).convert(param.value_kind.as_deref()),
                                );
                                arg.decoded = true;
                            }
                            _ => {
                                arg.reason = Some(
                                    param
                                        .note
                                        .clone()
                                        .unwrap_or_else(|| "the harness supplies it".to_owned()),
                                )
                            }
                        },
                    }
                    out.push(arg);
                }
            }
        }
        out
    }
}

/// The testcase bytes, read the way `bhf_cursor` reads them.
struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// Up to `width` bytes, little-endian, the missing ones zero (`bhf_i32`,
    /// `bhf_i64`, `bhf_u8`).
    fn read_le(&mut self, width: usize) -> u64 {
        let mut value = 0u64;
        for shift in 0..width {
            if self.remaining() == 0 {
                break;
            }
            value |= u64::from(self.input[self.pos]) << (shift * 8);
            self.pos += 1;
        }
        value
    }
}

/// Decode a cursor parameter, recording its span and value in `arg`.
fn decode_cursor(
    param: &ParamLayout,
    cursor: &mut Cursor<'_>,
    arg: &mut StaticArg,
) -> Result<(), String> {
    let start = cursor.pos;
    let finish = |cursor: &Cursor<'_>, arg: &mut StaticArg| {
        arg.span = Some([start as u64, cursor.pos as u64]);
    };
    if !param.static_decode {
        if let Some(bytes) = param.cursor_bytes {
            cursor.pos = (cursor.pos + bytes as usize).min(cursor.input.len());
            finish(cursor, arg);
        }
        return Err(param
            .note
            .clone()
            .unwrap_or_else(|| "its decoder has no static form".to_owned()));
    }
    let primitive = param.primitive.as_deref().unwrap_or_default();
    match param.decoder.as_str() {
        "scalar" | "bounded_int" | "enum_member" => {
            let width = param.width.unwrap_or(0) as usize;
            let raw = cursor.read_le(width);
            finish(cursor, arg);
            let value = match primitive {
                "bhf_u8" => Value::Unsigned(raw & 0xff),
                "bhf_i32" => Value::Signed(i64::from(raw as u32 as i32)),
                "bhf_i64" => Value::Signed(raw as i64),
                "bhf_bounded_i32" => {
                    let lo = param.lo.unwrap_or(0) as i32;
                    let hi = param.hi.unwrap_or(0) as i32;
                    let range = (hi.wrapping_sub(lo) as u32).wrapping_add(1);
                    let raw = raw as u32;
                    let picked = if hi <= lo {
                        lo
                    } else if range == 0 {
                        raw as i32
                    } else {
                        lo.wrapping_add((raw % range) as i32)
                    };
                    Value::Signed(i64::from(picked))
                }
                "bhf_bounded_length" => {
                    let lo = param.lo.unwrap_or(0) as u64;
                    let hi = param.hi.unwrap_or(0) as u64;
                    let range = hi.wrapping_sub(lo).wrapping_add(1);
                    let picked = if hi <= lo {
                        lo
                    } else if range == 0 {
                        raw
                    } else {
                        lo.wrapping_add(raw % range)
                    };
                    Value::Unsigned(picked)
                }
                other => return Err(format!("`{other}` has no static form")),
            };
            if param.decoder == "enum_member" {
                let Value::Signed(selector) = value else {
                    return Err("an enum selector is a signed integer".to_owned());
                };
                let member = usize::try_from(selector - param.lo.unwrap_or(0))
                    .ok()
                    .and_then(|at| param.members.get(at));
                arg.value = Some(match member {
                    Some(member) => member.clone(),
                    None => param.members.first().cloned().unwrap_or_default(),
                });
            } else {
                let value = if param.low_bit {
                    value.low_bit()
                } else {
                    value
                };
                let value = if param.via_uint32 {
                    value.via_uint32()
                } else {
                    value
                };
                arg.value = Some(value.convert(param.value_kind.as_deref()));
            }
            arg.decoded = true;
            Ok(())
        }
        "length_prefixed_string" => {
            let prefix_bytes = param.length_prefix_bytes.unwrap_or(2) as usize;
            let prefix = cursor.read_le(prefix_bytes);
            let want = (prefix as usize)
                .min(param.max_len.unwrap_or(u64::MAX) as usize)
                .min(cursor.remaining());
            let payload = &cursor.input[cursor.pos..cursor.pos + want];
            cursor.pos += want;
            finish(cursor, arg);
            arg.length_prefix = Some(prefix);
            fill_buffer(arg, payload, param);
            Ok(())
        }
        "capacity_string" => {
            let want = cursor.remaining().min(param.max_len.unwrap_or(0) as usize);
            let payload = &cursor.input[cursor.pos..cursor.pos + want];
            cursor.pos += want;
            finish(cursor, arg);
            fill_buffer(arg, payload, param);
            Ok(())
        }
        "rest_view" => {
            let payload = &cursor.input[cursor.pos..];
            cursor.pos = cursor.input.len();
            finish(cursor, arg);
            fill_buffer(arg, payload, param);
            Ok(())
        }
        other => Err(format!("a `{other}` decode has no static form")),
    }
}

/// Decode a whole-input or remainder parameter from its bytes.
fn decode_input(
    param: &ParamLayout,
    bytes: &[u8],
    range: std::ops::Range<usize>,
    arg: &mut StaticArg,
) {
    arg.span = Some([range.start as u64, range.end as u64]);
    match param.decoder.as_str() {
        "input_length" => {
            arg.value =
                Some(Value::Unsigned(bytes.len() as u64).convert(param.value_kind.as_deref()));
            arg.decoded = true;
        }
        "input_buffer" | "input_stream" | "input_file" => fill_buffer(arg, bytes, param),
        // One past the bytes: none of them.
        "input_end" => fill_buffer(arg, &[], param),
        _ => {
            arg.reason = Some(
                param
                    .note
                    .clone()
                    .unwrap_or_else(|| "its decoder has no static form".to_owned()),
            )
        }
    }
}

/// A buffer's length and preview; for a NUL-terminated string, those of the
/// bytes before its first NUL (at most the trace's string bound), which is
/// what the target reads and the harness trace prints.
fn fill_buffer(arg: &mut StaticArg, bytes: &[u8], param: &ParamLayout) {
    let bytes = if param.nul_terminated {
        let bounded = &bytes[..bytes.len().min(TRACE_STRING_MAX)];
        let end = bounded
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(bounded.len());
        &bounded[..end]
    } else {
        bytes
    };
    arg.len = Some(bytes.len() as u64);
    arg.preview_hex = Some(
        bytes
            .iter()
            .take(PREVIEW_BYTES)
            .map(|&b| {
                if param.format_neutralized && b == b'%' {
                    b' '
                } else {
                    b
                }
            })
            .map(|b| format!("{b:02x}"))
            .collect(),
    );
    arg.decoded = true;
}

/// A decoded integer before it is converted to the parameter's type.
#[derive(Debug, Clone, Copy)]
enum Value {
    Signed(i64),
    Unsigned(u64),
}

impl Value {
    fn bits(self) -> u64 {
        match self {
            Value::Signed(v) => v as u64,
            Value::Unsigned(v) => v,
        }
    }

    fn low_bit(self) -> Value {
        Value::Unsigned(self.bits() & 1)
    }

    /// `(uint32_t)value`.
    fn via_uint32(self) -> Value {
        Value::Unsigned(self.bits() & 0xffff_ffff)
    }

    /// The value as C converts it to `kind` and the harness's trace prints it.
    fn convert(self, kind: Option<&str>) -> String {
        let signed = match self {
            Value::Signed(v) => v,
            Value::Unsigned(v) => v as i64,
        };
        match kind {
            Some("bool") => (self.bits() != 0).to_string(),
            Some("i8") => (self.bits() as u8 as i8).to_string(),
            Some("u8") => (self.bits() as u8).to_string(),
            Some("i16") => (self.bits() as u16 as i16).to_string(),
            Some("u16") => (self.bits() as u16).to_string(),
            Some("i32") => (self.bits() as u32 as i32).to_string(),
            Some("u32") => (self.bits() as u32).to_string(),
            Some("i64") => signed.to_string(),
            Some("u64") => match self {
                Value::Signed(v) => (v as u64).to_string(),
                Value::Unsigned(v) => v.to_string(),
            },
            Some("f32") => c_float_text(f64::from(signed as f32)),
            Some("f64") => c_float_text(match self {
                Value::Signed(v) => v as f64,
                Value::Unsigned(v) => v as f64,
            }),
            _ => match self {
                Value::Signed(v) => v.to_string(),
                Value::Unsigned(v) => v.to_string(),
            },
        }
    }
}

/// `printf("%.17g")` for the integral values an integer-to-float conversion
/// yields.
fn c_float_text(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e17 {
        return format!("{value:.0}");
    }
    let text = format!("{value:.16e}");
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let sign = if exponent < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exponent.abs())
}

/// Where a parameter's bytes come from, as [`crate::arg_trace`] classified
/// its decl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputSource {
    Cursor,
    Remainder,
    WholeInput,
    None,
}

impl InputSource {
    fn label(self) -> &'static str {
        match self {
            InputSource::Cursor => "cursor",
            InputSource::Remainder => "remainder",
            InputSource::WholeInput => "whole_input",
            InputSource::None => "none",
        }
    }
}

/// What [`describe`] needs to know about one parameter.
pub(crate) struct Described<'a> {
    pub call: &'a str,
    pub role: &'a str,
    pub index: usize,
    pub name: &'a str,
    pub ty: &'a str,
    pub order: usize,
    pub decl: &'a str,
    pub arg: &'a str,
    pub source: InputSource,
    /// The parameter's resolved shape (through the registry, when there is one).
    pub shape: &'a TypeShape,
}

/// The layout of one parameter, read from its decl.
pub(crate) fn describe(param: &Described<'_>) -> ParamLayout {
    let mut layout = ParamLayout {
        call: param.call.to_owned(),
        role: param.role.to_owned(),
        index: param.index,
        name: param.name.to_owned(),
        ty: param.ty.to_owned(),
        order: param.order,
        input: param.source.label().to_owned(),
        decoder: "other".to_owned(),
        primitive: None,
        width: None,
        endianness: None,
        value_kind: scalar_kind_label(param.shape).map(str::to_owned),
        via_uint32: false,
        low_bit: false,
        lo: None,
        hi: None,
        members: Vec::new(),
        length_prefix_bytes: None,
        max_len: None,
        format_neutralized: false,
        nul_terminated: false,
        fixed_value: None,
        copied: None,
        paired_with: None,
        cursor_bytes: None,
        static_decode: false,
        note: None,
    };
    match param.source {
        InputSource::Cursor => describe_cursor(param, &mut layout),
        InputSource::Remainder | InputSource::WholeInput => describe_input(param, &mut layout),
        InputSource::None => {
            layout.decoder = "fixed".to_owned();
            layout.fixed_value = fixed_integer(param);
            layout.static_decode = layout.fixed_value.is_some() && layout.value_kind.is_some();
            if !layout.static_decode {
                layout.fixed_value = None;
                layout.note = Some("the harness supplies it; it takes no input bytes".to_owned());
            }
        }
    }
    layout
}

/// The integer constant a parameter that takes no input is given: its
/// argument is the literal (`0`, `(unsigned)4`), or a variable the decl sets
/// to one (`unsigned int flags = 0`).
fn fixed_integer(param: &Described<'_>) -> Option<i64> {
    let literal = |text: &str| {
        let mut text = text.trim();
        // Leading `(type)` casts.
        while let Some(inner) = text.strip_prefix('(') {
            let close = inner.find(')')?;
            let cast = &inner[..close];
            if cast.contains('(') {
                return None;
            }
            text = inner[close + 1..].trim_start();
        }
        parse_c_integer(text)
    };
    let arg = param.arg.trim();
    if let Some(value) = literal(arg) {
        return Some(value);
    }
    let decl = param.decl.trim().trim_end_matches(';').trim();
    if !is_c_identifier(arg) || decl.contains(';') {
        return None;
    }
    let (head, value) = decl.split_once('=')?;
    let head = head.trim_end();
    let declares = head
        .strip_suffix(arg)
        .is_some_and(|ty| ty.ends_with(|c: char| c.is_whitespace() || c == '*'));
    declares.then(|| literal(value)).flatten()
}

fn is_c_identifier(text: &str) -> bool {
    text.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn scalar_kind_label(shape: &TypeShape) -> Option<&'static str> {
    match shape {
        TypeShape::Scalar(kind) => Some(match kind {
            ScalarKind::Bool => "bool",
            ScalarKind::I8 => "i8",
            ScalarKind::U8 => "u8",
            ScalarKind::I16 => "i16",
            ScalarKind::U16 => "u16",
            ScalarKind::I32 => "i32",
            ScalarKind::U32 => "u32",
            ScalarKind::I64 => "i64",
            ScalarKind::U64 => "u64",
            ScalarKind::F32 => "f32",
            ScalarKind::F64 => "f64",
        }),
        _ => None,
    }
}

/// Bytes a fixed-width cursor primitive reads.
fn primitive_width(name: &str) -> Option<u32> {
    match name {
        "bhf_u8" => Some(1),
        "bhf_i32" | "bhf_bounded_i32" => Some(4),
        "bhf_i64" | "bhf_bounded_length" => Some(8),
        _ => None,
    }
}

fn describe_cursor(param: &Described<'_>, layout: &mut ParamLayout) {
    let calls = cursor_calls(param.decl);
    let looped = has_loop(param.decl);
    let fixed: Option<u32> = calls
        .iter()
        .map(|(name, _)| primitive_width(name))
        .sum::<Option<u32>>();
    if let [(primitive, args)] = calls.as_slice() {
        layout.primitive = Some(primitive.clone());
        match primitive.as_str() {
            "bhf_u8" | "bhf_i32" | "bhf_i64" | "bhf_bounded_i32" | "bhf_bounded_length" => {
                layout.width = primitive_width(primitive);
                if layout.width != Some(1) {
                    layout.endianness = Some("little".to_owned());
                }
                let bounded = primitive.starts_with("bhf_bounded_");
                if bounded {
                    layout.decoder = "bounded_int".to_owned();
                    layout.lo = args.first().and_then(|a| parse_c_integer(a));
                    layout.hi = args.get(1).and_then(|a| parse_c_integer(a));
                } else {
                    layout.decoder = "scalar".to_owned();
                }
                if let Some(members) = enum_members(param.decl, param.name, primitive) {
                    layout.decoder = "enum_member".to_owned();
                    layout.members = members;
                    layout.value_kind = None;
                    layout.static_decode = layout.lo.is_some() && layout.hi.is_some();
                } else if let Some(form) = simple_form(param.decl, param.name, primitive) {
                    layout.via_uint32 = form.via_uint32;
                    layout.low_bit = form.low_bit;
                    layout.static_decode = !looped
                        && (!bounded || (layout.lo.is_some() && layout.hi.is_some()))
                        && (layout.value_kind.is_some() || form.plain_int);
                    if layout.value_kind.is_none() && form.plain_int {
                        layout.value_kind = Some(
                            match primitive.as_str() {
                                "bhf_u8" => "u8",
                                "bhf_i64" => "i64",
                                "bhf_bounded_length" => "u64",
                                _ => "i32",
                            }
                            .to_owned(),
                        );
                    }
                }
                if !layout.static_decode {
                    layout.cursor_bytes = (!looped).then_some(()).and(layout.width.map(u64::from));
                    layout.note = Some(
                        "its value is computed from the decoded bytes in a way the layout does \
                         not describe"
                            .to_owned(),
                    );
                }
                return;
            }
            "bhf_c_string" | "bhf_c_format_string" => {
                // A C++ string type is built from the C string, so it ends at
                // the first NUL too.
                layout.nul_terminated = true;
                layout.decoder = "length_prefixed_string".to_owned();
                layout.length_prefix_bytes = Some(2);
                layout.endianness = Some("little".to_owned());
                layout.max_len = args
                    .first()
                    .and_then(|a| parse_c_integer(a))
                    .map(|v| v as u64);
                layout.format_neutralized = primitive == "bhf_c_format_string";
                layout.static_decode = layout.max_len.is_some() && !looped;
            }
            "bhf_c_string_out" => {
                layout.nul_terminated = true;
                layout.decoder = "capacity_string".to_owned();
                layout.max_len = args
                    .first()
                    .and_then(|a| parse_c_integer(a))
                    .map(|v| v as u64);
                layout.static_decode = layout.max_len.is_some() && !looped;
            }
            "bhf_data_slice" => {
                layout.decoder = "rest_view".to_owned();
                layout.nul_terminated = matches!(param.shape, TypeShape::CString);
                layout.copied = Some(!param.decl.contains("string_view"));
                layout.static_decode = !looped;
            }
            "bhf_wc_string" => {
                layout.decoder = "length_prefixed_string".to_owned();
                layout.length_prefix_bytes = Some(2);
                layout.note = Some(
                    "a wide string's payload is counted in wchar_t units, whose size is the \
                     target platform's"
                        .to_owned(),
                );
                return;
            }
            _ => {}
        }
        if !layout.static_decode && layout.note.is_none() {
            layout.note = Some("its decoder has no static form".to_owned());
        }
        return;
    }
    layout.cursor_bytes = if looped { None } else { fixed.map(u64::from) };
    layout.note = Some(if calls.is_empty() {
        "its decode reads the cursor in a way the layout does not describe".to_owned()
    } else if layout.cursor_bytes.is_some() {
        "it is decoded field by field".to_owned()
    } else {
        "it reads a number of bytes known only at run time".to_owned()
    });
}

/// Whether a whole-input decl points one past the input's bytes (`T end =
/// (T)Data + Size`): the end of a `[begin, end)` pair, which points at none
/// of them.
pub(crate) fn points_past_input(decl: &str) -> bool {
    let decl = decl.trim_end();
    decl.ends_with(")Data + Size") || decl.ends_with("= Data + Size")
}

fn describe_input(param: &Described<'_>, layout: &mut ParamLayout) {
    let code = format!("{} {}", param.decl, param.arg);
    let pointer = param.ty.contains('*')
        || param.ty.contains('[')
        || matches!(param.shape, TypeShape::Pointer(_) | TypeShape::CString);
    let integer = matches!(param.shape, TypeShape::Scalar(kind) if !matches!(kind, ScalarKind::F32 | ScalarKind::F64));
    if pointer && points_past_input(param.decl) {
        layout.decoder = "input_end".to_owned();
    } else if code.contains("fmemopen") {
        layout.decoder = "input_stream".to_owned();
    } else if code.contains("bhf_make_tempfile") {
        layout.decoder = "input_file".to_owned();
    } else if pointer || is_byte_container(param.ty) {
        layout.decoder = "input_buffer".to_owned();
        // A `char *` view or copy of the input is read as a C string.
        layout.nul_terminated = matches!(param.shape, TypeShape::CString);
        layout.copied = Some(
            ["malloc", "calloc", "memcpy", "std::vector", "std::string"]
                .iter()
                .any(|copy| code.contains(copy))
                && !param.ty.contains("string_view")
                && !param.ty.contains("span<"),
        );
    } else if integer {
        layout.decoder = "input_length".to_owned();
    } else {
        layout.note =
            Some("its decode uses the input in a way the layout does not describe".to_owned());
        return;
    }
    layout.static_decode = true;
}

fn is_byte_container(ty: &str) -> bool {
    [
        "std::string",
        "std::vector",
        "string_view",
        "span<",
        "std::basic_string",
    ]
    .iter()
    .any(|container| ty.contains(container))
}

/// Mark the `(buffer, length)` pairs among one call's whole-input
/// parameters: a buffer and a length next to each other that take the same
/// bytes (`groups` names the slice each takes, `None` for the bytes the
/// cursor left), neither already paired.
pub(crate) fn pair_input_params(params: &mut [ParamLayout], groups: &[Option<&str>]) {
    for at in 0..params.len().saturating_sub(1) {
        if groups.get(at) != groups.get(at + 1) {
            continue;
        }
        let (left, right) = params.split_at_mut(at + 1);
        let (a, b) = (&mut left[at], &mut right[0]);
        if a.input != b.input || !matches!(a.input.as_str(), "remainder" | "whole_input") {
            continue;
        }
        if a.paired_with.is_some() || b.paired_with.is_some() {
            continue;
        }
        let kinds = (a.decoder.as_str(), b.decoder.as_str());
        if matches!(
            kinds,
            ("input_buffer", "input_length") | ("input_length", "input_buffer")
        ) {
            a.paired_with = Some(b.name.clone());
            b.paired_with = Some(a.name.clone());
        }
    }
}

/// The `bhf_*(&Cur, ...)` calls in a decl, with their arguments after `&Cur`.
fn cursor_calls(decl: &str) -> Vec<(String, Vec<String>)> {
    let bytes = decl.as_bytes();
    let mut calls = Vec::new();
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
        let Some(args) = top_level_args(&decl[end..]) else {
            continue;
        };
        if args.first().map(String::as_str) != Some("&Cur") {
            continue;
        }
        calls.push((decl[start..end].to_owned(), args[1..].to_vec()));
    }
    calls
}

/// The top-level, whitespace-normalized arguments of the call whose `(`
/// starts `text`.
fn top_level_args(text: &str) -> Option<Vec<String>> {
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
                    let arg = current.split_whitespace().collect::<Vec<_>>().join(" ");
                    if !arg.is_empty() {
                        args.push(arg);
                    }
                    return Some(args);
                }
            }
            ',' if depth == 1 => {
                args.push(current.split_whitespace().collect::<Vec<_>>().join(" "));
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    None
}

fn has_loop(decl: &str) -> bool {
    let words: Vec<&str> = decl
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .collect();
    words
        .iter()
        .any(|w| matches!(*w, "for" | "while" | "do" | "goto"))
}

/// How a one-primitive decl converts what it read.
struct SimpleForm {
    via_uint32: bool,
    low_bit: bool,
    /// No cast: the declared type is the primitive's own.
    plain_int: bool,
}

/// `T name = [(T)][(uint32_t)]prim(&Cur[, lo, hi])` or
/// `T name = (T)(bhf_u8(&Cur) & 1)`: the decls whose value the layout can
/// compute. Anything else (a selector, arithmetic, a second statement) is not.
fn simple_form(decl: &str, name: &str, primitive: &str) -> Option<SimpleForm> {
    let decl = decl.trim().trim_end_matches(';').trim();
    if decl.contains(';') {
        return None;
    }
    let (head, rhs) = decl.split_once('=')?;
    let head = head.trim_end();
    if !head.ends_with(name) || head[..head.len() - name.len()].trim().is_empty() {
        return None;
    }
    let mut rest = rhs.trim();
    let mut casts = 0;
    let mut via_uint32 = false;
    // Strip leading `(type)` casts.
    while let Some(inner) = rest.strip_prefix('(') {
        let Some(close) = inner.find(')') else {
            break;
        };
        let cast = inner[..close].trim();
        if cast.contains('(') || cast.contains("Cur") || cast.contains('&') {
            break;
        }
        if cast == "uint32_t" {
            via_uint32 = true;
        }
        casts += 1;
        rest = inner[close + 1..].trim_start();
    }
    let mut low_bit = false;
    if let Some(inner) = rest.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        let inner = inner.trim();
        if let Some(value) = inner.strip_suffix('1').map(str::trim_end) {
            let value = value.strip_suffix('&')?;
            low_bit = true;
            rest = value.trim();
        } else {
            rest = inner;
        }
    }
    let after = rest.strip_prefix(primitive)?.trim_start();
    let close = matching_paren(after)?;
    if !after[close + 1..].trim().is_empty() {
        return None;
    }
    Some(SimpleForm {
        via_uint32,
        low_bit,
        plain_int: casts == 0 && !low_bit,
    })
}

/// The index of the `)` closing the `(` that starts `text`.
fn matching_paren(text: &str) -> Option<usize> {
    if !text.starts_with('(') {
        return None;
    }
    let mut depth = 0usize;
    for (at, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// An enum decoded by selector: `int _bhf_sel_x = bhf_bounded_i32(&Cur, 0, N);
/// ... switch (_bhf_sel_x) { case 0: x = (T)A; break; ... }`. The members in
/// selector order.
fn enum_members(decl: &str, name: &str, primitive: &str) -> Option<Vec<String>> {
    if primitive != "bhf_bounded_i32" || !decl.contains(&format!("_bhf_sel_{name}")) {
        return None;
    }
    let switch = decl.find("switch")?;
    let mut members = Vec::new();
    for (expected, case) in decl[switch..].split("case ").skip(1).enumerate() {
        let (label, body) = case.split_once(':')?;
        if label.trim().parse::<usize>().ok()? != expected {
            return None;
        }
        let value = body.split_once('=')?.1.split(';').next()?.trim();
        let member = value.rsplit(')').next()?.trim();
        if member.is_empty() {
            return None;
        }
        members.push(member.to_owned());
    }
    (!members.is_empty()).then_some(members)
}

/// A C integer literal (decimal, hex or octal, with `u`/`l` suffixes and a
/// leading `-`), or `None` for any other expression.
fn parse_c_integer(text: &str) -> Option<i64> {
    let text = text.trim();
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.trim()),
        None => (false, text),
    };
    let digits = digits.trim_end_matches(['u', 'U', 'l', 'L']);
    let magnitude = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else if digits.len() > 1 && digits.starts_with('0') {
        u64::from_str_radix(&digits[1..], 8).ok()?
    } else {
        digits.parse::<u64>().ok()?
    };
    let value = i64::try_from(magnitude).ok()?;
    Some(if negative { -value } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(input: &str, decoder: &str) -> ParamLayout {
        ParamLayout {
            call: "target".to_owned(),
            role: "param".to_owned(),
            index: 0,
            name: "p".to_owned(),
            ty: "int".to_owned(),
            order: 0,
            input: input.to_owned(),
            decoder: decoder.to_owned(),
            primitive: None,
            width: None,
            endianness: None,
            value_kind: None,
            via_uint32: false,
            low_bit: false,
            lo: None,
            hi: None,
            members: Vec::new(),
            length_prefix_bytes: None,
            max_len: None,
            format_neutralized: false,
            nul_terminated: false,
            fixed_value: None,
            copied: None,
            paired_with: None,
            cursor_bytes: None,
            static_decode: true,
            note: None,
        }
    }

    fn described(decl: &str, name: &str, ty: &str, shape: &TypeShape) -> ParamLayout {
        describe(&Described {
            call: "target",
            role: "param",
            index: 0,
            name,
            ty,
            order: 0,
            decl,
            arg: name,
            source: InputSource::Cursor,
            shape,
        })
    }

    #[test]
    fn cursor_decls_are_described_by_kind_width_and_bounds() {
        let u32 = TypeShape::Scalar(ScalarKind::U32);
        let index = described(
            "u32_t bit_index = (u32_t)(uint32_t)bhf_i32(&Cur)",
            "bit_index",
            "u32_t",
            &u32,
        );
        assert_eq!(index.decoder, "scalar");
        assert_eq!(index.primitive.as_deref(), Some("bhf_i32"));
        assert_eq!(index.width, Some(4));
        assert_eq!(index.endianness.as_deref(), Some("little"));
        assert_eq!(index.value_kind.as_deref(), Some("u32"));
        assert!(index.via_uint32 && index.static_decode);

        let offset = described(
            "unsigned short offset = (unsigned short)bhf_bounded_i32(&Cur, 0, 0xffff)",
            "offset",
            "unsigned short",
            &TypeShape::Scalar(ScalarKind::U16),
        );
        assert_eq!(offset.decoder, "bounded_int");
        assert_eq!((offset.lo, offset.hi), (Some(0), Some(0xffff)));

        let flag = described(
            "bool flag = (bool)(bhf_u8(&Cur) & 1)",
            "flag",
            "bool",
            &TypeShape::Scalar(ScalarKind::Bool),
        );
        assert!(flag.low_bit && flag.static_decode && flag.width == Some(1));

        let name = described(
            "char *name = bhf_c_string(&Cur, 4096)",
            "name",
            "const char *",
            &TypeShape::CString,
        );
        assert_eq!(name.decoder, "length_prefixed_string");
        assert_eq!(
            (name.length_prefix_bytes, name.max_len),
            (Some(2), Some(4096))
        );

        let mode = described(
            "int _bhf_sel_m = bhf_bounded_i32(&Cur, 0, 2); enum mode m = (enum mode)M_A; switch \
             (_bhf_sel_m) { case 0: m = (enum mode)M_A; break; case 1: m = (enum mode)M_B; break; \
             case 2: m = (enum mode)M_C; break; default: break; }",
            "m",
            "enum mode",
            &TypeShape::Opaque("enum mode".to_owned()),
        );
        assert_eq!(mode.decoder, "enum_member");
        assert_eq!(mode.members, ["M_A", "M_B", "M_C"]);

        let point = described(
            "struct pt p; memset(&p, 0, sizeof p); p.x = bhf_i32(&Cur); p.y = (short)bhf_i32(&Cur)",
            "p",
            "struct pt",
            &TypeShape::Opaque("struct pt".to_owned()),
        );
        assert_eq!(point.decoder, "other");
        assert!(!point.static_decode);
        assert_eq!(point.cursor_bytes, Some(8));

        let looped = described(
            "int a[4]; for (size_t _i = 0; _i < 4; ++_i) a[_i] = bhf_i32(&Cur)",
            "a",
            "int[4]",
            &TypeShape::Opaque("int[4]".to_owned()),
        );
        assert_eq!(looped.cursor_bytes, None);
    }

    /// The layout replays the decoders of bhf_decode.h: little-endian,
    /// zero-filled when the input runs out, bounds by modulo, a 16-bit length
    /// prefix clamped to the bytes left, and the remainder after the cursor.
    #[test]
    fn decode_replays_cursor_scalars_strings_and_the_remainder() {
        let mut index = param("cursor", "scalar");
        index.name = "bit_index".to_owned();
        index.primitive = Some("bhf_i32".to_owned());
        index.width = Some(4);
        index.value_kind = Some("u32".to_owned());
        index.via_uint32 = true;
        let mut width = index.clone();
        width.name = "width".to_owned();
        width.index = 1;
        let mut offset = param("cursor", "bounded_int");
        offset.name = "offset".to_owned();
        offset.primitive = Some("bhf_bounded_i32".to_owned());
        offset.width = Some(4);
        offset.lo = Some(0);
        offset.hi = Some(0xffff);
        offset.value_kind = Some("u16".to_owned());
        let mut name = param("cursor", "length_prefixed_string");
        name.name = "name".to_owned();
        name.length_prefix_bytes = Some(2);
        name.max_len = Some(4096);
        let mut data = param("remainder", "input_buffer");
        data.name = "data".to_owned();
        let mut len = param("remainder", "input_length");
        len.name = "len".to_owned();
        len.value_kind = Some("u64".to_owned());
        let layout = ArgLayout::new(
            "c",
            "direct",
            vec![
                LayoutStep::Param(index),
                LayoutStep::Param(width),
                LayoutStep::Param(offset),
                LayoutStep::Param(name),
                LayoutStep::Remainder {
                    call: "target".to_owned(),
                    sized: false,
                },
                LayoutStep::Param(data),
                LayoutStep::Param(len),
            ],
        );
        let input = [
            0x68, 0xba, 0xa7, 0xfe, // bit_index
            0x0f, 0x00, 0x00, 0x80, // width
            0x01, 0x00, 0x01, 0x00, // offset = 0x00010001 % 0x10000
            0x03, 0x00, b'a', b'b', b'c', // name
            0xde, 0xad,
        ];
        let args = layout.decode(&input);
        let by = |name: &str| args.iter().find(|a| a.name == name).unwrap();
        assert_eq!(by("bit_index").value.as_deref(), Some("4272405096"));
        assert_eq!(by("bit_index").span, Some([0, 4]));
        assert_eq!(by("width").value.as_deref(), Some("2147483663"));
        assert_eq!(by("offset").value.as_deref(), Some("1"));
        let name = by("name");
        assert_eq!((name.length_prefix, name.len), (Some(3), Some(3)));
        assert_eq!(name.preview_hex.as_deref(), Some("616263"));
        assert_eq!(name.span, Some([12, 17]));
        let data = by("data");
        assert_eq!((data.span, data.len), (Some([17, 19]), Some(2)));
        assert_eq!(by("len").value.as_deref(), Some("2"));
        assert!(args.iter().all(|a| a.decoded), "{args:?}");

        // A short input zero-fills the scalars and leaves an empty remainder.
        let short = layout.decode(&[0x05]);
        assert_eq!(short[0].value.as_deref(), Some("5"));
        assert_eq!(short[1].value.as_deref(), Some("0"));
        assert_eq!(short[3].length_prefix, Some(0));
        assert_eq!(short[4].len, Some(0));
    }

    /// After a step whose input use is known only at run time, nothing that
    /// reads the cursor or the remainder is decoded, and the reason says why.
    #[test]
    fn decode_stops_at_an_opaque_step_and_names_undecodable_parameters() {
        let mut first = param("cursor", "scalar");
        first.primitive = Some("bhf_u8".to_owned());
        first.width = Some(1);
        first.value_kind = Some("u8".to_owned());
        let mut wide = param("cursor", "length_prefixed_string");
        wide.name = "path".to_owned();
        wide.static_decode = false;
        wide.note = Some("a wide string".to_owned());
        let mut after = first.clone();
        after.name = "after".to_owned();
        let whole = {
            let mut p = param("whole_input", "input_buffer");
            p.name = "all".to_owned();
            p
        };
        let layout = ArgLayout::new(
            "cpp",
            "direct",
            vec![
                LayoutStep::Param(first.clone()),
                LayoutStep::Param(wide),
                LayoutStep::Param(after),
                LayoutStep::Param(whole),
                LayoutStep::Opaque {
                    what: "a lifecycle loop".to_owned(),
                },
                LayoutStep::Param(first),
            ],
        );
        let args = layout.decode(b"\x07\x01\x00Z");
        assert!(args[0].decoded);
        assert!(!args[1].decoded);
        assert_eq!(args[1].reason.as_deref(), Some("a wide string"));
        assert!(!args[2].decoded);
        assert!(
            args[2].reason.as_deref().unwrap().contains("`path`"),
            "{args:?}"
        );
        assert!(args[3].decoded, "the whole input needs no cursor");
        assert!(
            args[4].reason.as_deref().unwrap().contains("`path`"),
            "the first step that stopped the replay is named: {args:?}"
        );

        let mut late = param("cursor", "scalar");
        late.primitive = Some("bhf_u8".to_owned());
        late.width = Some(1);
        let looped = ArgLayout::new(
            "cpp",
            "direct",
            vec![
                LayoutStep::Opaque {
                    what: "a lifecycle loop".to_owned(),
                },
                LayoutStep::Param(late),
            ],
        );
        let args = looped.decode(b"\x01");
        assert!(!args[0].decoded);
        assert!(args[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("a lifecycle loop"));
    }

    /// A C string's length and preview stop at its first NUL, the way the
    /// target reads it and the harness trace prints it; a byte buffer keeps
    /// every byte.
    #[test]
    fn a_c_string_is_measured_up_to_its_first_nul() {
        let fmt = described(
            "char *fmt = bhf_c_format_string(&Cur, 4096)",
            "fmt",
            "const char *",
            &TypeShape::CString,
        );
        assert!(fmt.nul_terminated && fmt.format_neutralized, "{fmt:?}");
        let view = |ty: &str, shape: &TypeShape| {
            describe(&Described {
                call: "target",
                role: "param",
                index: 1,
                name: "path",
                ty,
                order: 1,
                decl: "const char * path = (const char *)_bhf_rest_p",
                arg: "path",
                source: InputSource::Remainder,
                shape,
            })
        };
        let path = view("const char *", &TypeShape::CString);
        assert_eq!(path.decoder, "input_buffer");
        assert!(path.nul_terminated);
        let bytes = view(
            "const unsigned char *",
            &TypeShape::Pointer(Box::new(TypeShape::Scalar(ScalarKind::U8))),
        );
        assert!(!bytes.nul_terminated);
        let mut raw = bytes.clone();
        raw.name = "raw".to_owned();
        let layout = ArgLayout::new(
            "c",
            "direct",
            vec![
                LayoutStep::Param(fmt),
                LayoutStep::Remainder {
                    call: "target".to_owned(),
                    sized: false,
                },
                LayoutStep::Param(path),
                LayoutStep::Param(raw),
            ],
        );
        let args = layout.decode(b"\x05\x00%b\x00cdxyz\x00!");
        let by = |name: &str| args.iter().find(|a| a.name == name).unwrap();
        let fmt = by("fmt");
        assert_eq!((fmt.span, fmt.len), (Some([0, 7]), Some(2)));
        assert_eq!(fmt.preview_hex.as_deref(), Some("2062"));
        let path = by("path");
        assert_eq!((path.span, path.len), (Some([7, 12]), Some(3)));
        assert_eq!(path.preview_hex.as_deref(), Some("78797a"));
        let raw = by("raw");
        assert_eq!(raw.len, Some(5));
        assert_eq!(raw.preview_hex.as_deref(), Some("78797a0021"));
    }

    /// A parameter the harness sets to a constant decodes to it without
    /// reading the input; one set otherwise stays undecoded with the reason.
    #[test]
    fn a_fixed_constant_is_recorded_and_decoded() {
        let fixed = |decl: &str, arg: &str, shape: &TypeShape| {
            describe(&Described {
                call: "target",
                role: "param",
                index: 0,
                name: "flags",
                ty: "unsigned int",
                order: 0,
                decl,
                arg,
                source: InputSource::None,
                shape,
            })
        };
        let u32 = TypeShape::Scalar(ScalarKind::U32);
        let zero = fixed("unsigned int flags = 0", "flags", &u32);
        assert_eq!(
            (zero.decoder.as_str(), zero.fixed_value),
            ("fixed", Some(0))
        );
        assert!(zero.static_decode && zero.note.is_none(), "{zero:?}");
        assert_eq!(fixed("", "(unsigned int)0x10u", &u32).fixed_value, Some(16));
        let scratch = fixed("unsigned int flags = compute()", "flags", &u32);
        assert_eq!(scratch.fixed_value, None);
        assert!(!scratch.static_decode && scratch.note.is_some());
        let pointer = fixed(
            "",
            "0",
            &TypeShape::Pointer(Box::new(TypeShape::Scalar(ScalarKind::U8))),
        );
        assert!(!pointer.static_decode, "{pointer:?}");

        let mut negative = fixed(
            "int flags = -2",
            "flags",
            &TypeShape::Scalar(ScalarKind::I32),
        );
        negative.name = "bias".to_owned();
        let layout = ArgLayout::new(
            "c",
            "direct",
            vec![LayoutStep::Param(zero), LayoutStep::Param(negative)],
        );
        let args = layout.decode(b"\xff");
        assert_eq!(args[0].value.as_deref(), Some("0"));
        assert_eq!(args[1].value.as_deref(), Some("-2"));
        assert!(
            args.iter().all(|a| a.decoded && a.span.is_none()),
            "{args:?}"
        );
    }

    #[test]
    fn float_text_matches_the_harness_trace() {
        assert_eq!(c_float_text(1094795585.0), "1094795585");
        assert_eq!(c_float_text(-2.0), "-2");
        assert_eq!(
            c_float_text(9.223_372_036_854_776e18),
            "9.2233720368547758e+18"
        );
    }

    #[test]
    fn layout_round_trips_through_json() {
        let mut p = param("cursor", "scalar");
        p.primitive = Some("bhf_i64".to_owned());
        let layout = ArgLayout::new("c", "direct", vec![LayoutStep::Param(p)]);
        let text = serde_json::to_string(&layout).unwrap();
        assert!(text.contains("\"step\":\"param\""), "{text}");
        let back: ArgLayout = serde_json::from_str(&text).unwrap();
        assert_eq!(back, layout);
    }
}
