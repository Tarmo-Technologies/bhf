// SPDX-License-Identifier: Apache-2.0

//! The typed spans a fuzz input's decoded arguments occupy (#299). A
//! generated C/C++ harness reads its arguments from the input with
//! `bhf_decode.h`, and `arg-layout.json` beside it says how: replayed over an
//! input ([`ArgLayout::decode`]), it gives each scalar argument's byte span.
//! The built-in mutator then writes typed boundary values into those spans,
//! little-endian at the span's width as the decoder reads them on every
//! target ([`fuzz_engine_builtin::decoded_arg_candidates`]).

use std::path::Path;

use fuzz_engine_builtin::{TypedSpan, TypedValueKind};
use harness_gen::arg_layout::{ArgLayout, ParamLayout};

/// The harness's `arg-layout.json`: beside its executable, else in its
/// generated or build dir. A layout that cannot be read is left out.
pub(crate) fn find_arg_layout(
    work_dir: &Path,
    harness_id: &str,
    harness_path: Option<&Path>,
) -> Option<ArgLayout> {
    harness_path
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .into_iter()
        .chain(crate::auto::layout::harness_dir_candidates(
            work_dir, harness_id,
        ))
        .chain([work_dir.join("build").join(harness_id)])
        .find_map(|dir| ArgLayout::read(&dir)?.ok())
}

/// The spans of `input`'s decoded scalar arguments, with the kind of value
/// each takes. A value cut short by the end of the input is left out: its
/// bytes are not a field of its width.
pub(crate) fn arg_layout_typed_spans(layout: &ArgLayout, input: &[u8]) -> Vec<TypedSpan> {
    let params: Vec<&ParamLayout> = layout.params().collect();
    layout
        .decode(input)
        .into_iter()
        .filter_map(|arg| {
            let [start, end] = arg.span?;
            let param = params.iter().find(|param| {
                param.call == arg.call && param.index == arg.index && param.name == arg.name
            })?;
            let kind = scalar_kind(param)?;
            let range = usize::try_from(start).ok()?..usize::try_from(end).ok()?;
            (range.len() == param.width? as usize).then(|| TypedSpan::new(range, kind))
        })
        .collect()
}

/// The kind of raw value a scalar decoder reads: a flag, or a signed or
/// unsigned integer by the `bhf_decode.h` read behind it. An integer that
/// lands in a float is read as one too.
fn scalar_kind(param: &ParamLayout) -> Option<TypedValueKind> {
    if !matches!(
        param.decoder.as_str(),
        "scalar" | "bounded_int" | "enum_member"
    ) {
        return None;
    }
    if param.low_bit || param.value_kind.as_deref() == Some("bool") {
        return Some(TypedValueKind::Boolean);
    }
    match param.primitive.as_deref()? {
        "bhf_i32" | "bhf_i64" | "bhf_bounded_i32" => Some(TypedValueKind::SignedInteger),
        "bhf_u8" | "bhf_bounded_length" => Some(TypedValueKind::UnsignedInteger),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use harness_gen::arg_layout::LayoutStep;

    fn scalar(name: &str, index: usize, primitive: &str, width: u32, kind: &str) -> ParamLayout {
        serde_json::from_value(serde_json::json!({
            "call": "parse_packet",
            "role": "arg",
            "index": index,
            "name": name,
            "type": kind,
            "order": index,
            "input": "cursor",
            "decoder": "scalar",
            "primitive": primitive,
            "width": width,
            "endianness": "little",
            "value_kind": kind,
            "static_decode": true,
        }))
        .unwrap()
    }

    /// An `int32_t` then an `int64_t` then a `bool` take the input's first
    /// 4, 8 and 1 bytes, as the decoder reads them.
    pub(crate) fn packet_layout() -> ArgLayout {
        let mut flag = scalar("verbose", 2, "bhf_u8", 1, "bool");
        flag.low_bit = true;
        ArgLayout::new(
            "c",
            "direct",
            vec![
                LayoutStep::Param(scalar("kind", 0, "bhf_i32", 4, "i32")),
                LayoutStep::Param(scalar("offset", 1, "bhf_i64", 8, "i64")),
                LayoutStep::Param(flag),
            ],
        )
    }

    #[test]
    fn scalar_arguments_become_typed_spans_at_their_offsets() {
        let spans = arg_layout_typed_spans(&packet_layout(), &[7u8; 20]);
        assert_eq!(
            spans,
            [
                TypedSpan::new(0..4, TypedValueKind::SignedInteger),
                TypedSpan::new(4..12, TypedValueKind::SignedInteger),
                TypedSpan::new(12..13, TypedValueKind::Boolean),
            ]
        );
        // An input that ends inside the second argument has one whole span.
        assert_eq!(
            arg_layout_typed_spans(&packet_layout(), &[7u8; 6]),
            [TypedSpan::new(0..4, TypedValueKind::SignedInteger)]
        );
    }
}
