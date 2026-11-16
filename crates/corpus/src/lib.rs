// SPDX-License-Identifier: Apache-2.0

pub mod bridge;
pub mod classify;
pub mod cluster;
pub mod decoded_args;
pub mod finding;
pub mod layout;
pub mod line_remap;
pub mod lineage;
pub mod manager;
pub mod sanitizer;
pub mod sanitizer_options;
pub mod signature;

pub use classify::{
    classify, finding_tier, is_predefined_exception, resolve_handler, Classification, FindingTier,
    UNHANDLED_HANDLER_INDEX,
};
pub use finding::{ExtensionFinding, FindingEmitter, FindingId};
pub use line_remap::{ResolvedLocation, SourceLineMaps};
pub use manager::{CorpusError, CorpusManager, SignatureClass, SignatureRecord};
pub use sanitizer::{parse_sanitizer_report, Sanitizer, SanitizerReport};
pub use signature::{compute_signature, Signature};

/// `bytes` as lowercase hex, two digits a byte: how bhf spells a digest in
/// ids, file names and reports.
pub fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
