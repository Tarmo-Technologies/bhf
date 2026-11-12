// SPDX-License-Identifier: Apache-2.0
//! `bhf.findings.v1`, the results contract. The normative definition is
//! `schemas/bhf.findings.v1.schema.json`; keep the two in lockstep. Every
//! field serializes, including `null`s (no `skip_serializing_if`), because
//! consumers rely on keys being present.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const FINDINGS_SCHEMA_VERSION: &str = "bhf.findings.v1";
pub const FINDING_SCHEMA_VERSION: &str = "bhf.finding.v1";
pub const MANIFEST_SCHEMA_VERSION: &str = "bhf.results-manifest.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingsDocument {
    pub schema_version: String,
    pub generated_at: String,
    pub tool: ToolInfo,
    pub source: SourceInfo,
    /// The most recent producers, oldest first (manifest.json keeps more).
    pub producers: Vec<ProducerRecord>,
    pub counts: Counts,
    pub findings: Vec<Finding>,
    pub groups: Vec<Group>,
    pub errors: Vec<LoadError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub build: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SourceInfo {
    pub root: Option<String>,
    pub vcs: Option<Vcs>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vcs {
    pub kind: String,
    pub commit: String,
    pub branch: Option<String>,
    /// Never computed today: it would need `git status`, which can run
    /// repository-controlled config in an untrusted tree.
    pub dirty: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerRecord {
    pub command: String,
    pub argv: Vec<String>,
    pub started_at: String,
    pub finished_at: String,
    pub status: ProducerStatus,
    /// The command's real exit code. Exit codes mean different things per
    /// command (`static-scan` uses 1 for both errors and `--fail-on` trips), so
    /// bhf records the number instead of guessing "failed".
    pub exit_code: i32,
    /// Findings in results/ after this producer finished (all kinds).
    pub findings_total: usize,
}

/// `partial` only when the producer itself says so (`auto/run.json` `partial`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProducerStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub total: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<String, usize>,
    pub by_confirmation: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub key: String,
    pub representative: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadError {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Fuzz,
    Runtime,
    Static,
    Binary,
    Differential,
    Sca,
}

impl Kind {
    pub const ALL: [Kind; 6] = [
        Kind::Fuzz,
        Kind::Runtime,
        Kind::Static,
        Kind::Binary,
        Kind::Differential,
        Kind::Sca,
    ];

    pub fn as_str(self) -> &'static str {
        use corpus::finding::finding_kind;
        match self {
            Kind::Fuzz => finding_kind::FUZZ,
            Kind::Runtime => finding_kind::RUNTIME,
            Kind::Static => finding_kind::STATIC,
            Kind::Binary => finding_kind::BINARY,
            Kind::Differential => finding_kind::DIFFERENTIAL,
            Kind::Sca => finding_kind::SCA,
        }
    }

    pub fn parse(value: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

/// Ordered least to most severe so `Ord` reads naturally (`Critical > High`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// 0 = most severe; for sorting lists most-severe-first.
    pub fn rank(self) -> u8 {
        4 - self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationLevel {
    SanitizerCrash,
    RuntimeOracle,
    Capability,
    CrashLead,
    IntendedRejection,
    StaticConfirmed,
    Static,
    Advisory,
}

impl ConfirmationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfirmationLevel::SanitizerCrash => "sanitizer_crash",
            ConfirmationLevel::RuntimeOracle => "runtime_oracle",
            ConfirmationLevel::Capability => "capability",
            ConfirmationLevel::CrashLead => "crash_lead",
            ConfirmationLevel::IntendedRejection => "intended_rejection",
            ConfirmationLevel::StaticConfirmed => "static_confirmed",
            ConfirmationLevel::Static => "static",
            ConfirmationLevel::Advisory => "advisory",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub kind: Kind,
    pub producer: String,
    pub rule: RuleRef,
    pub title: String,
    pub message: String,
    pub explanation: Option<String>,
    pub severity: Severity,
    pub impact: Option<String>,
    pub confidence: Confidence,
    pub cwe: Vec<u32>,
    pub confirmation: Confirmation,
    pub verdict: Option<String>,
    pub location: Option<Location>,
    pub fix_location: Option<Location>,
    pub stack: Vec<Frame>,
    pub trace: Vec<TraceStep>,
    pub fingerprint: Fingerprint,
    pub group: Option<String>,
    pub occurrences: usize,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub reachability: Option<Value>,
    pub fidelity: Fidelity,
    pub remediation: Option<String>,
    pub patch_hints: Vec<PatchHint>,
    pub reproduce: Option<Reproduce>,
    pub evidence: Option<Evidence>,
    pub fuzz: Option<FuzzBlock>,
    #[serde(rename = "static")]
    pub static_: Option<StaticBlock>,
    pub sca: Option<ScaBlock>,
    pub binary: Option<BinaryBlock>,
    pub raw_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleRef {
    pub id: Option<String>,
    pub slug: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confidence {
    pub level: String,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub level: ConfirmationLevel,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub file: String,
    pub line: Option<u64>,
    pub column: Option<u64>,
    pub function: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceStep {
    pub file: String,
    pub line: Option<u64>,
    pub function: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub primary: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Fidelity {
    pub stubs_used: bool,
    pub forced: bool,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchHint {
    pub title: String,
    pub guidance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reproduce {
    pub harness_id: Option<String>,
    pub command: Option<String>,
    pub build: BuildInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BuildInfo {
    pub sanitizers: Vec<String>,
    pub binary_sha256: Option<String>,
    pub build_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub dir: String,
    pub files: Vec<EvidenceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFile {
    pub role: String,
    pub path: String,
    pub sha256: Option<String>,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzBlock {
    pub exception: ExceptionInfo,
    pub classification: Option<String>,
    pub harness_id: Option<String>,
    pub dialect: Option<String>,
    pub oracle: Option<Value>,
    /// The memory access the sanitizer reported (`exception.access` in
    /// `finding.json`), without the raw address. `null` when the report named
    /// none. Added after the first v1 release: `#[serde(default)]` keeps
    /// documents written before it readable.
    #[serde(default)]
    pub access: Option<MemoryAccess>,
    /// Comparison evidence recorded while this finding's input ran: which
    /// input bytes reached which comparison. `null` when no capture ran or it
    /// could not run, `[]` when one ran and found no input bytes feeding a
    /// comparison.
    #[serde(default)]
    pub input_to_state: Option<Vec<InputToState>>,
    /// The finding file the `input_to_state` offsets index
    /// (`min_testcase.bin` or `testcase.bin`), when the capture named it.
    /// Added after the first v1 release, like `input_to_state`.
    #[serde(default)]
    pub input_to_state_input: Option<String>,
    /// The values the harness decoded from the input and passed to the target
    /// (`decoded_args` in `finding.json`). `null` when they were not traced.
    #[serde(default)]
    pub arguments: Option<Vec<Argument>>,
}

/// A sanitizer-reported memory access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryAccess {
    /// `read`, `write` or `unknown`.
    pub direction: String,
    pub size: Option<u64>,
    /// `zero-page` or `high-value-address`, from the report's `Hint:`.
    pub address_hint: Option<String>,
    pub region: Option<AccessRegion>,
    /// Where the region was allocated (or, for a stack object, its frame),
    /// runtime and allocator frames dropped.
    pub alloc_stack: Vec<Frame>,
    pub free_stack: Vec<Frame>,
}

/// The object a memory access hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRegion {
    /// `heap`, `stack` or `global`.
    pub kind: String,
    pub size: Option<u64>,
    /// Access offset from the start of the object: negative before it,
    /// `>= size` past its end.
    pub offset: Option<i64>,
    /// `after`, `before` or `inside`.
    pub relation: Option<String>,
    pub distance: Option<u64>,
    pub variable: Option<String>,
    pub frame_offset: Option<u64>,
}

/// One comparison operand that came from the input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputToState {
    /// First input byte offset of the span.
    pub offset: u64,
    pub len: u64,
    /// The operand as the comparison saw it.
    pub operand_hex: String,
    /// The other operand.
    pub compared_with_hex: String,
    /// `cmp` (integer), `switch`, `float_cmp`, `double_cmp`, `memcmp`,
    /// `strcmp`, `strncmp`, `strcasecmp` or `strncasecmp`.
    pub cmp_kind: String,
    /// The comparison's offset in the harness executable (`0x...`).
    pub site: String,
    /// The comparison's source position, when it could be symbolized.
    pub site_location: Option<Location>,
    /// `equal`: the operand bytes are the input bytes; `byte_swapped`: the
    /// same in reverse order (a big-endian read); `derived`: the operand is
    /// computed from these bytes and changed when they did.
    pub relation: String,
    /// Whether the two operands were equal when compared.
    pub operands_equal: bool,
}

/// A decoded harness argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Argument {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub value: Option<String>,
    pub len: Option<u64>,
    /// `[start, end)` byte offsets of the testcase the argument came from.
    pub span: Option<[u64; 2]>,
    pub preview_hex: Option<String>,
    /// `param`, `receiver` or `out`.
    pub role: String,
    pub after_call_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExceptionInfo {
    pub name: Option<String>,
    pub message: Option<String>,
    pub sanitizer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticBlock {
    pub engine: Option<String>,
    pub precision: Option<Value>,
    pub snippet: Option<String>,
    pub baseline_status: Option<String>,
    pub triage_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScaBlock {
    pub vuln_id: String,
    pub aliases: Vec<String>,
    pub component: Component,
    pub fixed_versions: Vec<String>,
    pub cvss: Option<Value>,
    pub kev: Option<Value>,
    pub references: Vec<Value>,
    pub match_confidence: Option<String>,
    pub matching_method: Option<String>,
    pub vex: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryBlock {
    pub sha256: Option<String>,
    pub build_id: Option<String>,
    pub arch: Option<String>,
    pub crash: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub source: SourceInfo,
    /// Producer history, oldest first, bounded; the oldest records drop first.
    pub producers: Vec<ProducerRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../schemas/examples/findings.v1.example.json");

    #[test]
    fn example_round_trips_through_the_model() {
        let doc: FindingsDocument = serde_json::from_str(EXAMPLE).expect("example parses");
        assert_eq!(doc.schema_version, FINDINGS_SCHEMA_VERSION);
        assert_eq!(doc.findings[0].kind, Kind::Fuzz);
        assert_eq!(
            doc.findings[1].sca.as_ref().unwrap().vuln_id,
            "CVE-2026-0001"
        );
        let back = serde_json::to_value(&doc).unwrap();
        let original: serde_json::Value = serde_json::from_str(EXAMPLE).unwrap();
        assert_eq!(
            back, original,
            "model must serialize every key, including nulls"
        );
    }

    #[test]
    fn severity_orders_from_info_to_critical() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low > Severity::Info);
        assert_eq!(Severity::Critical.rank(), 0);
        assert_eq!(Severity::Info.rank(), 4);
    }

    #[test]
    fn kind_strings_match_corpus_constants() {
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
            // serde serialization must match as_str() so on-disk `finding_kind`
            // and the model stay one vocabulary.
            assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
        }
        assert_eq!(Kind::parse("binary_crash"), None);
    }
}
