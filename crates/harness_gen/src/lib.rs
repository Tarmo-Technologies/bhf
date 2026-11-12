// SPDX-License-Identifier: Apache-2.0

pub use error::HarnessGenError;
pub use generate::{
    generate_direct_harness, generate_sequence_harness, generate_servant_direct_harness,
    GenerateDirectArgs, GenerateSequenceArgs, GenerateServantDirectArgs, GeneratedFiles,
};

/// Version of the input format that generated C and C++ harnesses decode.
///
/// A harness turns each fuzz input into the target's arguments. When the same
/// input bytes start decoding to different arguments, corpora, testcases and
/// findings recorded against an older harness no longer mean what they did, so
/// this is bumped whenever that happens. It is recorded in each harness's
/// `generation-metadata.json` (`harness_format_version`) and at the top of the
/// generated source. Harnesses that carry no version predate it (format 1).
/// `bhf generate-harness` warns when it regenerates a harness directory of
/// another format, and `bhf replay` when it replays against one.
///
/// - 2: unsigned scalars, `size_t` included, decode across their full range
///   (only length-, size- and count-named values stay bounded), and a byte
///   buffer pairs with the following integer, as `(Data, Size)` or as an output
///   buffer and its capacity, only when that integer is named like a length.
pub const HARNESS_FORMAT_VERSION: u32 = 2;

pub(crate) mod arg_trace;
pub mod build_safety;
pub mod c_decoders;
pub mod c_generate;
pub mod cpp_decoders;
pub mod cpp_generate;
pub mod decoders;
pub mod error;
pub mod generate;
pub mod generic_instance;
pub mod java_generate;
pub mod portability;
pub mod registry;
pub mod rust_decoders;
pub mod rust_generate;
pub mod stream_init;
pub mod templates;

#[cfg(test)]
mod tests {
    use super::HarnessGenError;

    #[test]
    fn error_display_for_target_not_found_includes_name() {
        let error = HarnessGenError::TargetNotFound("Parse".to_owned());

        assert!(error.to_string().contains("Parse"));
    }

    #[test]
    fn error_display_for_unsupported_param_type_includes_type_name() {
        let error = HarnessGenError::UnsupportedParamType("Root_Record".to_owned());

        assert!(error.to_string().contains("Root_Record"));
    }

    #[test]
    fn error_io_wraps_std_io_error() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "missing harness");
        let error = HarnessGenError::from(source);

        assert!(error.to_string().contains("missing harness"));
    }
}
