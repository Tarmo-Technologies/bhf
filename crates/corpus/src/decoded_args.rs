// SPDX-License-Identifier: Apache-2.0

//! The decoded harness arguments of a C/C++ finding.
//!
//! A generated C/C++ harness run with `BHF_TRACE_ARGS=1` prints one
//! `BHF_ARG {json}` line to stderr per decoded parameter, after decoding and
//! before the call, and one more (`"phase":"after"`) per output or in-out
//! parameter after the call (see `c_runtime/bhf_trace.h`). This module parses
//! those lines and records them in a finding's `decoded.json` (every traced
//! value) and `finding.json` (`decoded_args`, the target call's arguments).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

/// The environment variable that turns a generated harness's argument trace on.
pub const TRACE_ARGS_ENV: &str = "BHF_TRACE_ARGS";

/// The schema of `decoded.json`.
pub const DECODED_SCHEMA_VERSION: &str = "bhf.decoded.v1";

/// Most trace lines kept from one run (a lifecycle loop can call a step many
/// times).
pub const MAX_TRACED_ARGS: usize = 512;

/// The longest trace line parsed; longer lines are ignored.
const MAX_LINE: usize = 8192;

/// The marker that starts a trace line.
const MARKER: &str = "BHF_ARG {";

/// One traced argument value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracedArg {
    /// `target`, `receiver` (a C++ receiver's constructor or factory), or the
    /// name of another function the harness calls.
    pub call: String,
    /// Index in the call's parameter list; -1 for the receiver object itself.
    #[serde(rename = "i")]
    pub index: i64,
    /// `param`, `receiver` or `out` (an output or in-out parameter).
    pub role: String,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// How the harness decoded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoder: Option<String>,
    /// `[start, end)` byte offsets in the testcase it was decoded from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<[u64; 2]>,
    /// A scalar's value, or the pointee of a pointer to scalar storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// A pointer's address as the harness printed it (`0x...`, `NULL`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
    /// The heap allocation behind `ptr`, as the address sanitizer reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alloc_size: Option<u64>,
    /// A buffer's or string's content length, or an aggregate's size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
    /// Leading content bytes (at most 32), as hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_hex: Option<String>,
    /// `false` when the harness could not print the value of this type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traced: Option<bool>,
    /// An output's value after the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_call_value: Option<String>,
    /// An output buffer's leading bytes after the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_call_preview_hex: Option<String>,
    /// A length-prefixed string's 16-bit prefix as read from the testcase
    /// (the payload is `len` bytes: the prefix, clamped to the bytes left and
    /// to the decoder's maximum). See [`annotate_length_prefixes`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_prefix: Option<u64>,
}

impl TracedArg {
    /// The span as a `start..end` range.
    pub fn byte_range(&self) -> Option<std::ops::Range<u64>> {
        self.span.map(|[start, end]| start..end.max(start))
    }

    /// The traced pointer as a number.
    pub fn address(&self) -> Option<u64> {
        parse_address(self.ptr.as_deref()?)
    }

    /// The name shown to a reader: the parameter name, prefixed by its call
    /// unless that is the target call.
    pub fn display_name(&self) -> String {
        match self.call.as_str() {
            "target" => self.name.clone(),
            "receiver" if self.index < 0 => "receiver".to_owned(),
            "receiver" => format!("receiver({})", self.name),
            call => format!("{call}.{}", self.name),
        }
    }

    /// The value column: the value, else a buffer's length and allocation, else
    /// its address.
    pub fn summary(&self) -> String {
        if let Some(value) = &self.value {
            return value.clone();
        }
        let mut parts = Vec::new();
        if let Some(len) = self.len {
            match self.length_prefix {
                Some(prefix) if prefix != len => parts.push(format!("len {len} (prefix {prefix})")),
                _ => parts.push(format!("len {len}")),
            }
        }
        if let Some(alloc) = self.alloc_size {
            parts.push(format!("alloc {alloc}"));
        }
        if parts.is_empty() {
            if let Some(ptr) = &self.ptr {
                parts.push(ptr.clone());
            }
        }
        if parts.is_empty() && self.traced == Some(false) {
            parts.push("(not printable)".to_owned());
        }
        parts.join(", ")
    }
}

/// Parse an address printed as `0x...` (or decimal).
pub fn parse_address(text: &str) -> Option<u64> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The `BHF_ARG` lines of a harness run's stderr, in order, with each
/// after-call line folded into the argument it follows up.
pub fn parse_arg_trace(stderr: &str) -> Vec<TracedArg> {
    let mut args: Vec<TracedArg> = Vec::new();
    for line in stderr.lines() {
        if line.len() > MAX_LINE {
            continue;
        }
        let Some(at) = line.find(MARKER) else {
            continue;
        };
        let Ok(raw) = serde_json::from_str::<Value>(&line[at + MARKER.len() - 1..]) else {
            continue;
        };
        let after = raw.get("phase").and_then(Value::as_str) == Some("after");
        let Ok(arg) = serde_json::from_value::<TracedArg>(raw.clone()) else {
            continue;
        };
        if after {
            if let Some(before) = args.iter_mut().rev().find(|before| {
                before.call == arg.call && before.index == arg.index && before.name == arg.name
            }) {
                before.after_call_value = arg.value.or(arg.ptr);
                before.after_call_preview_hex = arg.preview_hex;
            }
            continue;
        }
        if args.len() >= MAX_TRACED_ARGS {
            break;
        }
        args.push(arg);
    }
    args
}

/// Decoders whose input bytes start with a 16-bit little-endian length prefix.
const LENGTH_PREFIXED: &[&str] = &["bhf_c_string(", "bhf_c_format_string(", "bhf_wc_string("];

/// Record each length-prefixed string's prefix, read from `input` at the start
/// of its span, so a reader sees both the prefix the bytes ask for and the
/// payload length the harness took.
pub fn annotate_length_prefixes(args: &mut [TracedArg], input: &[u8]) {
    for arg in args {
        let prefixed = arg
            .decoder
            .as_deref()
            .is_some_and(|decoder| LENGTH_PREFIXED.iter().any(|d| decoder.starts_with(d)));
        let Some(range) = arg.byte_range().filter(|_| prefixed) else {
            continue;
        };
        let start = usize::try_from(range.start).unwrap_or(usize::MAX);
        let low = input.get(start).copied();
        let high = input.get(start.saturating_add(1)).copied();
        arg.length_prefix = match (low, high) {
            (Some(low), Some(high)) => Some(u64::from(u16::from_le_bytes([low, high]))),
            (Some(low), None) => Some(u64::from(low)),
            _ => Some(0),
        };
    }
}

/// The arguments `finding.json` summarises: the target call's and the
/// receiver's. A harness with no single target call (a sequence harness)
/// reports every call's, named `<call>.<parameter>`.
pub fn summary_args(args: &[TracedArg]) -> Vec<&TracedArg> {
    let target: Vec<&TracedArg> = args
        .iter()
        .filter(|arg| matches!(arg.call.as_str(), "target" | "receiver"))
        .collect();
    if target.is_empty() {
        args.iter().collect()
    } else {
        target
    }
}

/// `finding.json`'s `decoded_args`: per argument its name, type, role, value
/// or length, span, preview and after-call value; the receiver object's entry
/// also says how the harness built it (`decoder`: `default constructor`,
/// `factory Widget::make()`, ...).
pub fn decoded_args_json(args: &[TracedArg]) -> Value {
    Value::Array(
        summary_args(args)
            .into_iter()
            .map(|arg| {
                let mut entry = json!({
                    "name": arg.display_name(),
                    "type": arg.ty,
                    "role": arg.role,
                });
                let object = entry.as_object_mut().expect("object literal");
                if let Some(how) = arg
                    .decoder
                    .as_ref()
                    .filter(|_| arg.call == "receiver" && arg.index < 0)
                {
                    object.insert("decoder".to_owned(), json!(how));
                }
                if let Some(value) = &arg.value {
                    object.insert("value".to_owned(), json!(value));
                }
                if let Some(len) = arg.len {
                    object.insert("len".to_owned(), json!(len));
                }
                if let Some([start, end]) = arg.span {
                    object.insert("span".to_owned(), json!([start, end]));
                }
                if let Some(preview) = &arg.preview_hex {
                    object.insert("preview_hex".to_owned(), json!(preview));
                }
                if let Some(after) = &arg.after_call_value {
                    object.insert("after_call_value".to_owned(), json!(after));
                }
                entry
            })
            .collect(),
    )
}

/// How the trace that fills `decoded.json` went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceOutcome {
    /// The harness printed these arguments.
    Traced(Vec<TracedArg>),
    /// The harness has no argument trace, or could not be re-run.
    Unavailable(String),
}

/// `decoded.json` for `input`: the input's size and preview, and either the
/// traced arguments with their byte provenance or why there are none.
pub fn decoded_document(input: &[u8], outcome: &TraceOutcome) -> Value {
    let mut provenance = vec![json!({
        "kind": "raw_bytes",
        "source": "testcase.bin",
        "byte_range": { "start": 0, "end": input.len() }
    })];
    let mut document = json!({
        "schema_version": DECODED_SCHEMA_VERSION,
        "input_size": input.len(),
        "preview_hex": preview_hex(input),
    });
    match outcome {
        TraceOutcome::Traced(args) => {
            for arg in args {
                if let Some(range) = arg.byte_range() {
                    provenance.push(json!({
                        "kind": "argument",
                        "call": arg.call,
                        "name": arg.name,
                        "source": "testcase.bin",
                        "byte_range": { "start": range.start, "end": range.end }
                    }));
                }
            }
            document["arguments_source"] = json!("harness_trace");
            document["arguments"] = serde_json::to_value(args).unwrap_or(Value::Null);
        }
        TraceOutcome::Unavailable(reason) => {
            document["arguments_source"] = json!("none");
            document["arguments_unavailable"] = json!(reason);
        }
    }
    document["provenance"] = Value::Array(provenance);
    document
}

/// Lowercase hex of at most the first 32 bytes.
pub fn preview_hex(input: &[u8]) -> String {
    input
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The parameter whose buffer a recorded memory access hit: the traced
/// pointer equal to the start of the accessed region (`address - offset`,
/// basis `region_start`); else the traced pointer into that region closest
/// below the access (basis `region_interior`, offset from that pointer: a view
/// that starts inside the allocation, such as a buffer taking the input bytes
/// after the scalars); or, for an access with no region, the closest traced
/// pointer below the faulting address within 4 GiB (basis `nearest_pointer`).
pub fn accessed_parameter(access: &Value, args: &[TracedArg]) -> Option<Value> {
    let address = parse_address(access.get("address")?.as_str()?)?;
    let pointers: Vec<(&TracedArg, u64)> = summary_args(args)
        .into_iter()
        .filter_map(|arg| Some((arg, arg.address().filter(|a| *a != 0)?)))
        .collect();
    if let Some(offset) = access.pointer("/region/offset").and_then(Value::as_i64) {
        let start = address.checked_add_signed(offset.checked_neg()?)?;
        if let Some((arg, _)) = pointers.iter().find(|(_, ptr)| *ptr == start) {
            return Some(json!({
                "name": arg.display_name(),
                "offset": offset,
                "basis": "region_start",
            }));
        }
        let end = access
            .pointer("/region/size")
            .and_then(Value::as_u64)
            .and_then(|size| start.checked_add(size));
        let (arg, ptr) = pointers
            .iter()
            .filter(|(_, ptr)| *ptr > start && *ptr <= address && end.is_none_or(|end| *ptr <= end))
            .max_by_key(|(_, ptr)| *ptr)?;
        return Some(json!({
            "name": arg.display_name(),
            "offset": address - ptr,
            "basis": "region_interior",
        }));
    }
    if access.get("region").is_some() {
        return None;
    }
    let (arg, ptr) = pointers
        .iter()
        .filter(|(_, ptr)| *ptr <= address && address - *ptr < (1 << 32))
        .max_by_key(|(_, ptr)| *ptr)?;
    Some(json!({
        "name": arg.display_name(),
        "offset": address - ptr,
        "basis": "nearest_pointer",
    }))
}

/// Record a trace in a finding: rewrite `decoded.json` from `input` and the
/// outcome and, when arguments were traced, set `finding.json`'s
/// `decoded_args` and name the parameter its memory access hit.
pub fn record_trace(
    finding_dir: &Path,
    input: &[u8],
    outcome: &TraceOutcome,
) -> std::io::Result<()> {
    let annotated;
    let outcome = match outcome {
        TraceOutcome::Traced(args) => {
            let mut args = args.clone();
            annotate_length_prefixes(&mut args, input);
            annotated = TraceOutcome::Traced(args);
            &annotated
        }
        other => other,
    };
    let document = decoded_document(input, outcome);
    std::fs::write(
        finding_dir.join("decoded.json"),
        serde_json::to_vec_pretty(&document)?,
    )?;
    let TraceOutcome::Traced(args) = outcome else {
        return Ok(());
    };
    let finding_path = finding_dir.join("finding.json");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&finding_path)?)?;
    let Some(object) = record.as_object_mut() else {
        return Ok(());
    };
    object.insert("decoded_args".to_owned(), decoded_args_json(args));
    if let Some(access) = record.pointer_mut("/exception/access") {
        if let Some(parameter) = accessed_parameter(access, args) {
            access["parameter"] = parameter;
        }
    }
    std::fs::write(&finding_path, serde_json::to_vec_pretty(&record)?)
}

/// Longest type and value shown in a table cell.
const TABLE_TYPE: usize = 28;
const TABLE_VALUE: usize = 36;
/// Preview bytes shown in a table row.
const TABLE_PREVIEW_BYTES: usize = 16;

/// The arguments as a text table, one row per traced value: name, type, the
/// testcase bytes it came from, its value (with the after-call value of an
/// output) and a preview of a buffer's leading bytes.
pub fn render_table(args: &[TracedArg]) -> Vec<String> {
    let rows: Vec<[String; 5]> = args
        .iter()
        .map(|arg| {
            let bytes = match arg.byte_range() {
                Some(range) if range.is_empty() => format!("{}..{} (none)", range.start, range.end),
                Some(range) => format!("{}..{}", range.start, range.end),
                None => "-".to_owned(),
            };
            let mut value = arg.summary();
            if let Some(after) = &arg.after_call_value {
                value = format!("{value} -> {after} after the call");
            }
            let preview = arg
                .preview_hex
                .as_deref()
                .filter(|hex| !hex.is_empty())
                .map(|hex| {
                    let shown: String = hex.chars().take(TABLE_PREVIEW_BYTES * 2).collect();
                    if shown.len() < hex.len() {
                        format!("{shown}...")
                    } else {
                        shown
                    }
                })
                .unwrap_or_default();
            [
                arg.display_name(),
                cell(&arg.ty, TABLE_TYPE),
                bytes,
                cell(&value, TABLE_VALUE),
                preview,
            ]
        })
        .collect();
    let header = ["name", "type", "bytes", "value", "preview (hex)"];
    let mut widths = header.map(str::len);
    for row in &rows {
        for (width, text) in widths.iter_mut().zip(row) {
            *width = (*width).max(text.chars().count());
        }
    }
    let line = |cells: [&str; 5]| {
        let mut out = String::new();
        for (index, (text, width)) in cells.iter().zip(widths).enumerate() {
            if index + 1 == cells.len() {
                out.push_str(text);
            } else {
                out.push_str(&format!("{text:<width$}  "));
            }
        }
        out.trim_end().to_owned()
    };
    let mut lines = vec![line(header)];
    for row in &rows {
        lines.push(line([&row[0], &row[1], &row[2], &row[3], &row[4]]));
    }
    lines
}

fn cell(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str = "\
noise before\n\
BHF_ARG {\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"buffer\",\"type\":\"const char *\",\"decoder\":\"bhf_c_string(4096)\",\"span\":[0,2],\"ptr\":\"0x502000000030\",\"alloc_size\":1,\"len\":0,\"preview_hex\":\"\"}\n\
BHF_ARG {\"call\":\"target\",\"i\":1,\"role\":\"out\",\"name\":\"offset\",\"type\":\"unsigned short &\",\"span\":[2,6],\"value\":\"5\"}\n\
BHF_ARG {\"call\":\"receiver\",\"i\":0,\"role\":\"receiver\",\"name\":\"mode\",\"type\":\"int\",\"span\":[6,10],\"value\":\"2\"}\n\
BHF_ARG {\"call\":\"target\",\"i\":1,\"role\":\"out\",\"name\":\"offset\",\"type\":\"unsigned short &\",\"phase\":\"after\",\"value\":\"6\"}\n\
BHF_ARG {not json\n\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000031\n";

    #[test]
    fn trace_lines_parse_in_order_with_after_call_values_folded_in() {
        let args = parse_arg_trace(TRACE);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0].name, "buffer");
        assert_eq!(args[0].span, Some([0, 2]));
        assert_eq!(args[0].alloc_size, Some(1));
        assert_eq!(args[0].address(), Some(0x5020_0000_0030));
        assert_eq!(args[1].value.as_deref(), Some("5"));
        assert_eq!(args[1].after_call_value.as_deref(), Some("6"));
        assert_eq!(args[2].display_name(), "receiver(mode)");
    }

    #[test]
    fn finding_summary_carries_the_contract_fields_only() {
        let args = parse_arg_trace(TRACE);
        let summary = decoded_args_json(&args);
        assert_eq!(
            summary[1],
            json!({"name": "offset", "type": "unsigned short &", "role": "out",
                   "value": "5", "span": [2, 6], "after_call_value": "6"})
        );
        assert_eq!(
            summary[0],
            json!({"name": "buffer", "type": "const char *", "role": "param",
                   "len": 0, "span": [0, 2], "preview_hex": ""})
        );
    }

    /// The receiver object's entry says how the harness built it, so a report
    /// can say the method ran on an object the harness constructed.
    #[test]
    fn the_receiver_entry_says_how_the_harness_built_it() {
        let args = parse_arg_trace(
            "BHF_ARG {\"call\":\"receiver\",\"i\":-1,\"role\":\"receiver\",\"name\":\"this\",\"type\":\"Widget\",\"decoder\":\"default constructor\",\"ptr\":\"0x7ffd0010\"}\n\
             BHF_ARG {\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"n\",\"type\":\"int\",\"decoder\":\"bhf_i32()\",\"span\":[0,4],\"value\":\"3\"}\n",
        );
        let summary = decoded_args_json(&args);
        assert_eq!(summary[0]["name"], "receiver");
        assert_eq!(summary[0]["decoder"], "default constructor");
        assert!(summary[1].get("decoder").is_none(), "{}", summary[1]);
    }

    #[test]
    fn a_heap_access_names_the_parameter_whose_buffer_starts_the_region() {
        let args = parse_arg_trace(TRACE);
        let access = json!({"direction": "read", "size": 4, "address": "0x502000000031",
                            "region": {"kind": "heap", "size": 1, "offset": 1}});
        assert_eq!(
            accessed_parameter(&access, &args),
            Some(json!({"name": "buffer", "offset": 1, "basis": "region_start"}))
        );
        let elsewhere = json!({"address": "0x602000000031",
                               "region": {"kind": "heap", "size": 1, "offset": 1}});
        assert_eq!(accessed_parameter(&elsewhere, &args), None);
        let wild = json!({"address": "0x502000a10040"});
        assert_eq!(
            accessed_parameter(&wild, &args),
            Some(json!({"name": "buffer", "offset": 0xa10010_u64, "basis": "nearest_pointer"}))
        );
    }

    #[test]
    fn a_view_into_the_middle_of_an_allocation_is_named_by_its_own_pointer() {
        // `level` took the first four input bytes, so `buf` points four bytes
        // into the 9-byte input allocation; the read lands one past its end.
        let args = parse_arg_trace(
            "BHF_ARG {\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"level\",\"type\":\"int\",\"span\":[0,4],\"value\":\"1\"}\n\
             BHF_ARG {\"call\":\"target\",\"i\":1,\"role\":\"param\",\"name\":\"buf\",\"type\":\"const uint8_t *\",\"span\":[4,8],\"ptr\":\"0x502000000014\",\"len\":4,\"preview_hex\":\"41424344\"}\n\
             BHF_ARG {\"call\":\"target\",\"i\":2,\"role\":\"param\",\"name\":\"len\",\"type\":\"size_t\",\"span\":[4,8],\"value\":\"4\"}\n",
        );
        let access = json!({"direction": "read", "size": 1, "address": "0x502000000019",
                            "region": {"kind": "heap", "size": 9, "offset": 9,
                                       "relation": "after", "distance": 0}});
        assert_eq!(
            accessed_parameter(&access, &args),
            Some(json!({"name": "buf", "offset": 5, "basis": "region_interior"}))
        );
        // A pointer past the region's end, or past the access, is not it.
        let before = json!({"address": "0x502000000012",
                            "region": {"kind": "heap", "size": 9, "offset": 2}});
        assert_eq!(accessed_parameter(&before, &args), None);
        let short = json!({"address": "0x502000000019",
                           "region": {"kind": "heap", "size": 2, "offset": 9}});
        assert_eq!(accessed_parameter(&short, &args), None);
    }

    #[test]
    fn decoded_document_lists_argument_provenance_or_why_there_is_none() {
        let input = [3u8, 0, b'A', b'B', b'C', 5, 0, 0, 0, 2];
        let traced = decoded_document(&input, &TraceOutcome::Traced(parse_arg_trace(TRACE)));
        assert_eq!(traced["schema_version"], DECODED_SCHEMA_VERSION);
        assert_eq!(traced["arguments_source"], "harness_trace");
        assert_eq!(traced["arguments"][0]["ptr"], "0x502000000030");
        assert_eq!(traced["provenance"][0]["kind"], "raw_bytes");
        assert_eq!(traced["provenance"][2]["name"], "offset");
        assert_eq!(
            traced["provenance"][2]["byte_range"],
            json!({"start": 2, "end": 6})
        );
        let none = decoded_document(&input, &TraceOutcome::Unavailable("no trace".to_owned()));
        assert_eq!(none["arguments_source"], "none");
        assert_eq!(none["arguments_unavailable"], "no trace");
        assert_eq!(none["provenance"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn the_table_shows_bytes_values_after_call_values_and_previews() {
        let table = render_table(&parse_arg_trace(TRACE));
        assert_eq!(table[0].split_whitespace().next(), Some("name"));
        assert!(table[1].starts_with("buffer"), "{table:#?}");
        assert!(table[1].contains("0..2"), "{table:#?}");
        assert!(table[1].contains("len 0, alloc 1"), "{table:#?}");
        assert!(table[2].contains("5 -> 6 after the call"), "{table:#?}");
        assert!(table[3].starts_with("receiver(mode)"), "{table:#?}");
    }

    #[test]
    fn length_prefixes_are_read_from_the_testcase_at_the_span_start() {
        let mut args = parse_arg_trace(
            "BHF_ARG {\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"s\",\"type\":\"const char *\",\"decoder\":\"bhf_c_string(4096)\",\"span\":[1,6],\"len\":3}\n\
             BHF_ARG {\"call\":\"target\",\"i\":1,\"role\":\"param\",\"name\":\"n\",\"type\":\"int\",\"decoder\":\"bhf_i32()\",\"span\":[6,10],\"value\":\"0\"}\n",
        );
        annotate_length_prefixes(&mut args, &[9, 0x10, 0x01, b'A', b'B', b'C']);
        assert_eq!(args[0].length_prefix, Some(0x0110));
        assert_eq!(args[0].summary(), "len 3 (prefix 272)");
        assert_eq!(args[1].length_prefix, None);
    }

    #[test]
    fn trace_parsing_is_bounded() {
        let line = "BHF_ARG {\"call\":\"step\",\"i\":0,\"role\":\"param\",\"name\":\"x\",\"type\":\"int\"}\n";
        let many = line.repeat(MAX_TRACED_ARGS + 10);
        assert_eq!(parse_arg_trace(&many).len(), MAX_TRACED_ARGS);
        let long = format!(
            "BHF_ARG {{\"call\":\"t\",\"i\":0,\"role\":\"param\",\"name\":\"{}\",\"type\":\"int\"}}\n",
            "x".repeat(MAX_LINE)
        );
        assert!(parse_arg_trace(&long).is_empty());
    }
}
