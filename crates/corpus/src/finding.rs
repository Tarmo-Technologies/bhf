// SPDX-License-Identifier: Apache-2.0

use crate::{
    classify, compute_signature, finding_tier, resolve_handler, Classification, CorpusError,
    UNHANDLED_HANDLER_INDEX,
};
use event_log::{HandlerEvent, Testcase};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub struct FindingEmitter {
    root: PathBuf,
    metadata: FindingMetadata,
    line_maps: crate::line_remap::SourceLineMaps,
}

/// `finding_kind` values of the `bhf.finding.v1` envelope. `results::model::Kind`
/// serializes to exactly these strings.
pub mod finding_kind {
    pub const FUZZ: &str = "fuzz";
    pub const RUNTIME: &str = "runtime";
    pub const STATIC: &str = "static";
    pub const BINARY: &str = "binary";
    pub const DIFFERENTIAL: &str = "differential";
    pub const SCA: &str = "sca";
}

pub const FINDING_SCHEMA_VERSION: &str = "bhf.finding.v1";

/// Current UTC time as an RFC 3339 string with millisecond precision and a `Z`
/// suffix. Every finding timestamp uses this one format, so they also order
/// correctly as plain strings; compare against other formats only after parsing.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Stamp a new per-finding record with the `bhf.finding.v1` envelope. Keeps an
/// existing `created_at` so re-writes never move a finding's birth time.
pub fn stamp_v1(record: &mut serde_json::Value, kind: &str) {
    if let Some(obj) = record.as_object_mut() {
        obj.insert("schema_version".to_owned(), json!(FINDING_SCHEMA_VERSION));
        obj.insert("finding_kind".to_owned(), json!(kind));
        obj.entry("created_at")
            .or_insert_with(|| json!(now_rfc3339()));
    }
}

/// Cap for `sanitizer.log`; the first MiB holds the report and stacks, the rest is noise.
pub const SANITIZER_LOG_MAX: u64 = 1024 * 1024;

/// Write the captured stderr of the crashing execution, truncated to
/// [`SANITIZER_LOG_MAX`] with a trailing marker naming the dropped byte count.
pub fn write_sanitizer_log(finding_dir: &std::path::Path, log: &[u8]) -> std::io::Result<()> {
    let max = SANITIZER_LOG_MAX as usize;
    if log.len() <= max {
        return fs::write(finding_dir.join("sanitizer.log"), log);
    }
    let mut bytes = log[..max].to_vec();
    bytes.extend_from_slice(format!("\n[truncated {} bytes]\n", log.len() - max).as_bytes());
    fs::write(finding_dir.join("sanitizer.log"), bytes)
}

/// Record that `command` rewrote `fields` of this record. Enrichment steps edit
/// `finding.json` in place; this keeps the edits traceable.
pub fn append_history(record: &mut serde_json::Value, command: &str, fields: &[&str]) {
    let Some(obj) = record.as_object_mut() else {
        return;
    };
    let entry = json!({ "at": now_rfc3339(), "command": command, "fields": fields });
    match obj
        .get_mut("history")
        .and_then(serde_json::Value::as_array_mut)
    {
        Some(history) => history.push(entry),
        // No `history` yet, or a malformed non-array one: start a fresh array
        // (a non-array value is replaced rather than preserved).
        None => {
            obj.insert("history".to_owned(), json!([entry]));
        }
    }
}

/// The stable finding signature for an out-of-process extension oracle: the
/// sha256 of the extension's ORDERED `signature_inputs`, each prefixed by a `0x1f`
/// separator (a byte that cannot appear in the textual inputs, so distinct input
/// lists never collide by concatenation) and `"extension"`-tagged.
///
/// Hashing in the order the extension gave makes the signature reproduce
/// byte-for-byte on replay/minimize/re-evaluate regardless of host-side iteration
/// order — the single source of truth shared by [`FindingEmitter::emit_extension_finding`]
/// and `bhf extension minimize` so the two can never drift.
pub fn extension_signature(signature_inputs: &[String]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"extension");
    for part in signature_inputs {
        hasher.update(b"\x1f");
        hasher.update(part.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// The key a fuzz run dedupes an emitted finding on, by the set it lives in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunDedupeKey {
    /// `rule_id|oracle.name|oracle.api`: one finding per defect, not per input.
    Oracle(String),
    /// `cluster_key_full`: the root-cause key, or the finding signature when
    /// the crash had neither an informative frame nor a reported site
    /// ([`sanitizer_dedupe_key`]).
    Cluster(String),
}

/// The fuzz run's dedupe key for a written `finding.json`, rebuilt from the
/// record: what the run computed when it emitted the finding. Oracle keys are
/// kept verbatim, empty parts included, as the run builds them; an empty
/// cluster key yields nothing, since no run computes one and a shared empty
/// key would make unrelated records one crash.
pub fn run_dedupe_key(record: &serde_json::Value) -> Option<RunDedupeKey> {
    let rule_id = record.get("rule_id").and_then(serde_json::Value::as_str);
    if let (Some(rule_id), Some(oracle)) = (rule_id, record.get("oracle")) {
        if let (Some(name), Some(api)) = (
            oracle.get("name").and_then(serde_json::Value::as_str),
            oracle.get("api").and_then(serde_json::Value::as_str),
        ) {
            return Some(RunDedupeKey::Oracle(format!("{rule_id}|{name}|{api}")));
        }
    }
    // A fallback record's `cluster_key_full` is its signature, which is what
    // the run keys such a crash on (`sanitizer_dedupe_key`). Older runs keyed
    // every fallback crash of a rule as one `rule:<id>`, which hid later,
    // different crashes of that rule for the rest of the run.
    record
        .get("cluster_key_full")
        .and_then(serde_json::Value::as_str)
        .filter(|full| !full.is_empty())
        .map(|full| RunDedupeKey::Cluster(full.to_owned()))
}

/// The signature of a sanitizer crash: sha256 over the rule, the crash kind,
/// the sanitizer's check name, the reported site (for a UBSan report, or any
/// report without a crash stack; for a crash with no sanitizer report, the
/// faulting pc offset bhf's driver printed) and the crash-stack function
/// names. The allocation and free stacks describe the object, not the crash,
/// and are not hashed. Its first 8 hex digits are the finding ID suffix.
pub fn sanitizer_signature(report: &crate::sanitizer::SanitizerReport) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(report.rule_id.as_bytes());
    hasher.update(b"|");
    hasher.update(report.kind.as_bytes());
    if let Some(check) = &report.check {
        hasher.update(b"|check=");
        hasher.update(check.as_bytes());
    }
    let ubsan = report.sanitizer == Some(crate::sanitizer::Sanitizer::UndefinedBehaviorSanitizer);
    if let Some(site) = report
        .fault_site()
        .filter(|_| ubsan || report.stack.is_empty())
    {
        hasher.update(b"|site=");
        hasher.update(site.as_bytes());
    }
    for frame in &report.stack {
        hasher.update(b"|");
        hasher.update(frame.function.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// The key a fuzz run dedupes a sanitizer crash on: its root-cause cluster key,
/// or its signature when the crash has neither an informative frame nor a
/// reported site. The same key is written as the finding's
/// `cluster_key_full`, so [`run_dedupe_key`] rebuilds it from disk. Every site
/// that dedupes sanitizer crashes (the builtin loop, AFL++ crash ingestion,
/// the pre-seed from earlier passes) uses this one function.
pub fn sanitizer_dedupe_key(report: &crate::sanitizer::SanitizerReport) -> String {
    sanitizer_dedupe_key_scoped(report, "")
}

/// [`sanitizer_dedupe_key`] for a crash found in `scope`
/// ([`crate::cluster::crash_scope`]): a crash with neither an informative
/// frame nor a reported site keys on its scoped root-cause key
/// ([`crate::cluster::cluster_for_sanitizer_scoped`]), which is what the
/// emitter of that scope writes as `cluster_key_full`.
pub fn sanitizer_dedupe_key_scoped(
    report: &crate::sanitizer::SanitizerReport,
    scope: &str,
) -> String {
    let cluster = crate::cluster::cluster_for_sanitizer_scoped(report, scope);
    if cluster.is_placeholder() {
        sanitizer_signature(report)
    } else {
        cluster.full
    }
}

/// Every key that names `record`'s crash: its [`run_dedupe_key`] and its
/// `signature` (as `signature:<hex>`). Two findings of one harness that share
/// any key are the same crash; a record with no key matches nothing.
pub fn dedupe_keys(record: &serde_json::Value) -> Vec<String> {
    let run = run_dedupe_key(record).map(|key| match key {
        RunDedupeKey::Oracle(key) | RunDedupeKey::Cluster(key) => key,
    });
    let signature = record
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .filter(|signature| !signature.is_empty())
        .map(|signature| format!("signature:{signature}"));
    run.into_iter().chain(signature).collect()
}

/// A stable, replayable semantic finding produced by an explicitly-trusted,
/// out-of-process extension oracle (`oracle.evaluate`). The host passes plain
/// fields so `corpus` needs no dependency on the extension host crate.
#[derive(Debug, Clone)]
pub struct ExtensionFinding {
    /// The rule identifier the extension's oracle fired.
    pub rule: String,
    /// The finding classification (e.g. `extension_oracle`).
    pub classification: String,
    /// The ordered signature inputs. Hashed **in order** so the signature
    /// reproduces byte-for-byte on replay/minimize/re-evaluate regardless of
    /// host-side iteration order — this is what makes the finding identity
    /// stable across runs.
    pub signature_inputs: Vec<String>,
    /// Supporting evidence as ordered `(key, value)` pairs.
    pub evidence: Vec<(String, String)>,
    /// An optional minimization-predicate identifier the extension exposes.
    pub min_predicate: Option<String>,
    /// The provenance block stamped under `record["extension"]`: the extension
    /// executable/config sha256, protocol version, and negotiated capabilities
    /// (built by the host from `ExtensionProvenance::finding_block`).
    pub provenance: serde_json::Value,
}

impl FindingEmitter {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            metadata: FindingMetadata::default(),
            line_maps: crate::line_remap::SourceLineMaps::default(),
        }
    }

    /// Load instrumented→original line-map sidecars from `dir` (the
    /// `src_instrumented` directory) so emitted findings report the developer's
    /// original source lines instead of the instrumented copy's shifted lines.
    pub fn with_line_maps_dir(mut self, dir: &std::path::Path) -> Self {
        self.line_maps = crate::line_remap::SourceLineMaps::load(dir);
        self
    }

    pub fn with_metadata(
        root: PathBuf,
        harness_id: String,
        dialect: String,
        fixture_path: String,
    ) -> Self {
        Self {
            root,
            metadata: FindingMetadata {
                harness_id,
                dialect,
                fixture_path,
                sandbox: None,
                mode: actionability::RunMode::Reporting,
                build_binary: None,
                harness_format_version: None,
                buffer_len_dimension: false,
                crash_scope: None,
            },
            line_maps: crate::line_remap::SourceLineMaps::default(),
        }
    }

    pub fn with_metadata_and_sandbox(
        root: PathBuf,
        harness_id: String,
        dialect: String,
        fixture_path: String,
        sandbox: serde_json::Value,
    ) -> Self {
        Self {
            root,
            metadata: FindingMetadata {
                harness_id,
                dialect,
                fixture_path,
                sandbox: Some(sandbox),
                mode: actionability::RunMode::Reporting,
                build_binary: None,
                harness_format_version: None,
                buffer_len_dimension: false,
                crash_scope: None,
            },
            line_maps: crate::line_remap::SourceLineMaps::default(),
        }
    }

    pub fn with_mode(mut self, mode: actionability::RunMode) -> Self {
        self.metadata.mode = mode;
        self
    }

    /// Attach the harness/target binary's identity (sha256 + GNU build-id),
    /// serialized as JSON. Merged into `record["build"]["binary"]` by every
    /// emitter so a finding pins to the exact binary bytes that produced it.
    pub fn with_build_binary(mut self, identity: serde_json::Value) -> Self {
        self.metadata.build_binary = Some(identity);
        self
    }

    /// Record the generated harness's input format version in every finding
    /// this emitter writes (`harness_format_version`). `None` (a harness with
    /// no generation metadata) records nothing.
    pub fn with_harness_format_version(mut self, version: Option<u32>) -> Self {
        self.metadata.harness_format_version = version;
        self
    }

    /// Record that the generated harness was built with the explicit
    /// buffer-length dimension (`buffer_len_dimension: true` in every finding
    /// this emitter writes): it is part of the harness input format.
    pub fn with_buffer_len_dimension(mut self, enabled: bool) -> Self {
        self.metadata.buffer_len_dimension = enabled;
        self
    }

    /// Group the frame-less crashes this emitter writes by `scope` (see
    /// [`crate::cluster::crash_scope`]) instead of by the harness id alone.
    pub fn with_crash_scope(mut self, scope: impl Into<String>) -> Self {
        self.metadata.crash_scope = Some(scope.into());
        self
    }

    /// Emit a finding for a libFuzzer/AFL++ C/C++ crash captured via stderr.
    /// Unlike `emit`, there's no event log and no Ada Testcase; the sanitizer
    /// report already carries everything we need.
    pub fn emit_sanitizer_crash(
        &self,
        input: &[u8],
        report: &crate::sanitizer::SanitizerReport,
    ) -> Result<FindingId, CorpusError> {
        self.emit_sanitizer_crash_with_log(input, report, None)
    }

    /// Like [`Self::emit_sanitizer_crash`], additionally writing the raw
    /// captured stderr of the crashing execution as `sanitizer.log` next to
    /// the finding, when `log` is non-empty.
    pub fn emit_sanitizer_crash_with_log(
        &self,
        input: &[u8],
        report: &crate::sanitizer::SanitizerReport,
        log: Option<&[u8]>,
    ) -> Result<FindingId, CorpusError> {
        let signature_hex = sanitizer_signature(report);
        let cluster =
            crate::cluster::cluster_for_sanitizer_scoped(report, &self.metadata.crash_scope());
        let (cluster_short, cluster_full, cluster_fallback) = if cluster.is_placeholder() {
            (
                signature_hex.chars().take(16).collect::<String>(),
                signature_hex.clone(),
                true,
            )
        } else {
            (
                cluster.short.clone(),
                cluster.full.clone(),
                cluster.fallback,
            )
        };
        let (id, finding_dir) = self.allocate_finding(&signature_hex)?;

        fs::write(finding_dir.join("testcase.bin"), input)?;
        fs::write(
            finding_dir.join("decoded.json"),
            serde_json::to_vec_pretty(&decoded_placeholder(input))?,
        )?;
        let log_written = log.filter(|l| !l.is_empty());
        if let Some(log) = log_written {
            write_sanitizer_log(&finding_dir, log)?;
        }

        // The exception name and the `sanitizer` provenance follow what actually
        // occurred: with a sanitizer, `ASAN_HEAP_BUFFER_OVERFLOW` and a
        // `sanitizer` tag; without one (a host fatal signal or an on-target
        // transport fault), the kind alone (`TARGET_CPU_EXCEPTION`) and NO
        // `sanitizer` key — never a synthesized `asan` value that did not occur.
        let kind_token = report.kind.to_uppercase().replace('-', "_");
        let exception_name = match report.sanitizer {
            Some(sanitizer) => format!("{}_{}", sanitizer.as_str().to_uppercase(), kind_token),
            None => kind_token,
        };
        let mut record = json!({
            "id": id.0,
            "signature": signature_hex,
            "cluster_key": cluster_short,
            "cluster_key_full": cluster_full,
            "cluster_normalized_frames": cluster.frames,
            "cluster_fallback": cluster_fallback,
            "rule_id": report.rule_id,
            "classification": "unhandled",
            "harness_id": self.metadata.harness_id,
            "dialect": self.metadata.dialect,
            "fixture_path": stored_fixture_path(&self.root, &self.metadata.fixture_path),
            "exception": {
                "name": exception_name,
                "message": report.message,
                "stack": report.stack,
            },
            "paths": {
                "testcase": "testcase.bin",
                "decoded": "decoded.json",
                "finding": "finding.json",
            },
        });
        // Record the sanitizer provenance only when a sanitizer actually ran, so
        // an unsanitized host signal / on-target fault carries no `sanitizer`
        // field rather than a false `asan`. Older records that always wrote the
        // tag still read back: the normalized model's `sanitizer` is optional, so
        // a missing field and a present one both deserialize (a compatible,
        // additive change — no schema-version bump).
        if let Some(sanitizer) = report.sanitizer {
            record["exception"]["sanitizer"] = json!(sanitizer.as_str());
        }
        // Additive structured evidence: the reported site, the sanitizer's own
        // check name, and the memory access (direction, size, region, and the
        // allocation / free stacks kept apart from the crash stack).
        if let Some(location) = &report.location {
            record["exception"]["location"] = json!(location);
        }
        if let Some(check) = &report.check {
            record["exception"]["check"] = json!(check);
        }
        if let Some(access) = &report.access {
            record["exception"]["access"] = json!(access);
        }
        // A fatal signal with no sanitizer report names its signal as its
        // check; it is recorded as such too.
        if report.sanitizer.is_none() && report.kind == "fatal-signal" {
            if let Some(signal) = report.check.as_deref().filter(|c| c.starts_with("SIG")) {
                record["exception"]["signal"] = json!(signal);
            }
        }
        // A crash with no sanitizer report: where the driver saw it fault.
        if let Some(offset) = report.pc_offset {
            record["exception"]["pc_offset"] = json!(format!("{offset:#x}"));
        }
        if log_written.is_some() {
            record["paths"]["sanitizer_log"] = json!("sanitizer.log");
        }
        if let Some(sandbox) = &self.metadata.sandbox {
            record["sandbox"] = sandbox.clone();
            record["build"] = json!({ "sandbox": sandbox });
        }
        merge_build_binary(&mut record, &self.metadata);
        record["actionability"] = actionability::value_for_finding(
            self.metadata.mode,
            &record,
            Some(&finding_dir.join("finding.json")),
        );

        stamp_v1(&mut record, finding_kind::FUZZ);
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&record)?,
        )?;

        Ok(id)
    }

    /// Emit a finding for an executable oracle hit captured from
    /// runtime instrumentation, such as a path traversal signal from
    /// the runtrace shim. These findings are not crashes; the oracle
    /// evidence is the behavioral signal.
    pub fn emit_oracle_hit(
        &self,
        input: &[u8],
        hit: &finding_rules::oracle_sdk::OracleHit,
    ) -> Result<FindingId, CorpusError> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(hit.rule_id.as_bytes());
        hasher.update(b"|");
        hasher.update(hit.oracle_name.as_bytes());
        hasher.update(b"|");
        hasher.update(hit.api.as_bytes());
        for evidence in &hit.evidence {
            hasher.update(b"|");
            hasher.update(evidence.key.as_bytes());
            hasher.update(b"=");
            hasher.update(evidence.value.as_bytes());
        }
        let signature_hex = format!("{:x}", hasher.finalize());
        // The cluster key is DEFECT-level (rule | oracle | dangerous API) and
        // EXCLUDES per-input evidence (the opened path/fd, injected command, ...).
        // The `signature` above keeps the evidence so each finding ID stays unique,
        // but clustering must collapse repeated hits of the SAME defect — a
        // resource-leak oracle re-triggered every pass otherwise produced a new
        // cluster per finding (mpack), defeating report dedup.
        let mut cluster_hasher = sha2::Sha256::new();
        cluster_hasher.update(hit.rule_id.as_bytes());
        cluster_hasher.update(b"|");
        cluster_hasher.update(hit.oracle_name.as_bytes());
        cluster_hasher.update(b"|");
        cluster_hasher.update(hit.api.as_bytes());
        // Site-stable discriminators (oracle-declared) so two distinct sites of
        // the same defect — e.g. two native-assertion sites that share the
        // `__assert_fail` API — do not over-merge into one cluster with an empty
        // sink. Per-input evidence stays excluded (the allowlist names only
        // site-stable keys like the assertion source location/expression).
        let mut cluster_frames = vec![hit.oracle_name.clone(), hit.api.clone()];
        for key in finding_rules::oracle_manifest::site_keys_for(&hit.oracle_name) {
            if let Some(value) = hit.evidence_value(key) {
                cluster_hasher.update(b"|");
                cluster_hasher.update(key.as_bytes());
                cluster_hasher.update(b"=");
                cluster_hasher.update(value.as_bytes());
                cluster_frames.push(format!("{key}={value}"));
            }
        }
        let cluster_full = format!("{:x}", cluster_hasher.finalize());
        let cluster_short = cluster_full.chars().take(16).collect::<String>();
        let (id, finding_dir) = self.allocate_finding(&signature_hex)?;

        fs::write(finding_dir.join("testcase.bin"), input)?;
        fs::write(
            finding_dir.join("decoded.json"),
            serde_json::to_vec_pretty(&decoded_placeholder(input))?,
        )?;

        let mut record = json!({
            "id": id.0,
            "signature": signature_hex,
            "cluster_key": cluster_short,
            "cluster_key_full": cluster_full,
            "cluster_normalized_frames": cluster_frames,
            "cluster_fallback": false,
            "rule_id": hit.rule_id,
            "classification": "oracle_hit",
            // #422: an oracle hit is dynamic, runtime-confirmed evidence — the
            // graduation of a static candidate (e.g. BHF-405/BHF-408) from
            // "candidate" to runtime-confirmed. Static-scan findings carry no
            // such marker, so consumers can distinguish the two.
            "confirmation": "runtime",
            "harness_id": self.metadata.harness_id,
            "dialect": self.metadata.dialect,
            "fixture_path": stored_fixture_path(&self.root, &self.metadata.fixture_path),
            "oracle": {
                "name": hit.oracle_name,
                "category": hit.category,
                "api": hit.api,
                "message": hit.message,
                "evidence": hit.evidence,
            },
            "exception": {
                "name": oracle_exception_name(&hit.oracle_name),
                "message": hit.message,
            },
            "paths": {
                "testcase": "testcase.bin",
                "decoded": "decoded.json",
                "finding": "finding.json",
            },
        });
        if let Some(sandbox) = &self.metadata.sandbox {
            record["sandbox"] = sandbox.clone();
            record["build"] = json!({ "sandbox": sandbox });
        }
        merge_build_binary(&mut record, &self.metadata);
        record["actionability"] = actionability::value_for_finding(
            self.metadata.mode,
            &record,
            Some(&finding_dir.join("finding.json")),
        );

        stamp_v1(&mut record, finding_kind::FUZZ);
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&record)?,
        )?;

        Ok(id)
    }

    /// Emit a finding for a semantic violation reported by an out-of-process
    /// extension oracle (`oracle.evaluate`). These are not crashes: the oracle
    /// judged a clean-exiting input to violate a private semantic contract.
    ///
    /// The `signature` is the sha256 of the extension's ordered
    /// `signature_inputs`, so an identical violation reproduces the identical
    /// signature on replay/minimize/re-evaluate. The `cluster_key` is
    /// DEFECT-level (`rule | classification`) and EXCLUDES the per-input
    /// signature inputs/evidence, so repeated hits of one defect collapse into a
    /// single cluster for report dedup (mirroring [`Self::emit_oracle_hit`]). The
    /// record carries `confirmation: "extension"` and an `extension` provenance
    /// block so a consumer can audit which explicitly-trusted extension produced
    /// it.
    pub fn emit_extension_finding(
        &self,
        input: &[u8],
        finding: &ExtensionFinding,
    ) -> Result<FindingId, CorpusError> {
        use sha2::Digest;
        // Signature: the extension's ORDERED signature inputs (see
        // [`extension_signature`] — the shared source of truth with `minimize`).
        let signature_hex = extension_signature(&finding.signature_inputs);
        // Cluster key: DEFECT-level (rule | classification), excluding per-input
        // evidence so one defect re-triggered on many inputs stays one cluster.
        let mut cluster_hasher = sha2::Sha256::new();
        cluster_hasher.update(finding.rule.as_bytes());
        cluster_hasher.update(b"|");
        cluster_hasher.update(finding.classification.as_bytes());
        let cluster_full = format!("{:x}", cluster_hasher.finalize());
        let cluster_short = cluster_full.chars().take(16).collect::<String>();
        let cluster_frames = vec![finding.rule.clone(), finding.classification.clone()];

        let (id, finding_dir) = self.allocate_finding(&signature_hex)?;
        fs::write(finding_dir.join("testcase.bin"), input)?;
        fs::write(
            finding_dir.join("decoded.json"),
            serde_json::to_vec_pretty(&decoded_placeholder(input))?,
        )?;

        let evidence: Vec<serde_json::Value> = finding
            .evidence
            .iter()
            .map(|(key, value)| json!({ "key": key, "value": value }))
            .collect();
        let message = finding
            .evidence
            .iter()
            .find(|(key, _)| key == "reason" || key == "message")
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| format!("extension oracle rule {} fired", finding.rule));

        let mut record = json!({
            "id": id.0,
            "signature": signature_hex,
            "cluster_key": cluster_short,
            "cluster_key_full": cluster_full,
            "cluster_normalized_frames": cluster_frames,
            "cluster_fallback": false,
            "rule_id": finding.rule,
            "classification": finding.classification,
            // A semantic violation confirmed by an out-of-process extension
            // oracle — distinct from `static`, `runtime`, and `fuzz_confirmed`.
            "confirmation": "extension",
            "harness_id": self.metadata.harness_id,
            "dialect": self.metadata.dialect,
            "fixture_path": stored_fixture_path(&self.root, &self.metadata.fixture_path),
            "extension": finding.provenance,
            "evidence": evidence,
            "exception": {
                "name": oracle_exception_name(&finding.rule),
                "message": message,
            },
            "paths": {
                "testcase": "testcase.bin",
                "decoded": "decoded.json",
                "finding": "finding.json",
            },
        });
        if let Some(predicate) = &finding.min_predicate {
            record["min_predicate"] = json!(predicate);
        }
        if let Some(sandbox) = &self.metadata.sandbox {
            record["sandbox"] = sandbox.clone();
            record["build"] = json!({ "sandbox": sandbox });
        }
        merge_build_binary(&mut record, &self.metadata);
        record["actionability"] = actionability::value_for_finding(
            self.metadata.mode,
            &record,
            Some(&finding_dir.join("finding.json")),
        );

        stamp_v1(&mut record, finding_kind::FUZZ);
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&record)?,
        )?;

        Ok(id)
    }

    pub fn emit(
        &self,
        input: &[u8],
        testcase: &Testcase,
        handler_idx: usize,
    ) -> Result<FindingId, CorpusError> {
        let handler = resolve_handler(testcase, handler_idx)
            .ok_or(CorpusError::InvalidHandlerIndex { index: handler_idx })?;
        let handler = handler.as_ref();
        let classification = if handler_idx == UNHANDLED_HANDLER_INDEX {
            Classification::Unhandled
        } else {
            classify(testcase)
                .into_iter()
                .find_map(|(index, classification)| {
                    if index == handler_idx {
                        Some(classification)
                    } else {
                        None
                    }
                })
                .ok_or(CorpusError::InvalidHandlerIndex { index: handler_idx })?
        };
        let signature = compute_signature(testcase, handler);
        let signature_hex = signature.hex();
        let cluster = crate::cluster::cluster_for_ada(testcase, handler);
        let (cluster_short, cluster_full, cluster_fallback) = if cluster.fallback {
            (
                signature_hex.chars().take(16).collect::<String>(),
                signature_hex.clone(),
                true,
            )
        } else {
            (cluster.short.clone(), cluster.full.clone(), false)
        };
        let cluster_frames = cluster.frames.clone();
        let (id, finding_dir) = self.allocate_finding(&signature_hex)?;

        fs::write(finding_dir.join("testcase.bin"), input)?;
        fs::write(
            finding_dir.join("decoded.json"),
            serde_json::to_vec_pretty(&decoded_placeholder(input))?,
        )?;
        let fixture_path = stored_fixture_path(&self.root, &self.metadata.fixture_path);
        let mut record = finding_record(
            &id.0,
            &fixture_path,
            &signature_hex,
            classification,
            testcase,
            handler,
            &self.metadata,
            &cluster_short,
            &cluster_full,
            &cluster_frames,
            cluster_fallback,
        );
        self.remap_exception_lines(&mut record);
        record["actionability"] = actionability::value_for_finding(
            self.metadata.mode,
            &record,
            Some(&finding_dir.join("finding.json")),
        );
        stamp_v1(&mut record, finding_kind::FUZZ);
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&record)?,
        )?;

        Ok(id)
    }

    /// Rewrite instrumented-copy `<file>:<line>` references in the finding's
    /// exception message to the developer's original source lines, and record
    /// the resolved original location under `exception.source_file` /
    /// `exception.source_line`. No-op when no line maps were loaded.
    fn remap_exception_lines(&self, record: &mut serde_json::Value) {
        if self.line_maps.is_empty() {
            return;
        }
        let Some(message) = record
            .get("exception")
            .and_then(|exc| exc.get("message"))
            .and_then(|msg| msg.as_str())
        else {
            return;
        };
        let (rewritten, resolved) = self.line_maps.remap_message(message);
        if let Some(exc) = record.get_mut("exception") {
            exc["message"] = json!(rewritten);
            if let Some(location) = resolved {
                exc["source_file"] = json!(location.source_path);
                exc["source_line"] = json!(location.original_line);
            }
        }
    }

    /// Atomically reserve a fresh `F-NNNN-<sig8>` finding directory, retrying
    /// on an ordinal a concurrent writer already took. Replaces the old
    /// scan-then-`create_dir_all`, which could hand two writers sharing a work
    /// dir (multiple processes, or the daemon's concurrent jobs) the same id.
    fn allocate_finding(
        &self,
        signature_hex: &str,
    ) -> Result<(FindingId, std::path::PathBuf), CorpusError> {
        let findings_root = crate::layout::findings_dir(&self.root);
        let short: String = signature_hex.chars().take(8).collect();
        let mut allocator = crate::layout::FamilyAllocator::new(&findings_root, "F-")?;
        let (id, dir) = allocator.create_with_suffix(&short)?;
        self.record_corpus_format();
        Ok((FindingId(id), dir))
    }

    /// Record the harness's input format in its corpus's metadata
    /// (`corpus/<harness_id>/metadata.json`), so inputs kept from a harness
    /// of another format are recognised. Written with each finding and at
    /// the end of each fuzz pass, whether or not it found anything.
    /// Best-effort: a corpus dir that cannot be written never fails the
    /// finding or the pass.
    pub fn record_corpus_format(&self) {
        self.write_corpus_format(true);
    }

    /// [`Self::record_corpus_format`] for a corpus this pass is about to
    /// create: written only when `corpus/<harness_id>/` does not exist yet,
    /// so the corpus carries its format from its first input on, while an
    /// existing corpus keeps the format it was recorded with until the pass
    /// has added to it.
    pub fn start_corpus_format(&self) {
        self.write_corpus_format(false);
    }

    fn write_corpus_format(&self, existing: bool) {
        let Some(version) = self.metadata.harness_format_version else {
            return;
        };
        let harness_id = self.metadata.harness_id.as_str();
        if harness_id.is_empty()
            || harness_id.contains(['/', '\\'])
            || harness_id == "."
            || harness_id == ".."
        {
            return;
        }
        let dir = self.root.join("corpus").join(harness_id);
        if !existing && dir.exists() {
            return;
        }
        let metadata = json!({
            "schema_version": CORPUS_METADATA_SCHEMA,
            "harness_id": harness_id,
            "harness": {
                "format_version": version,
                "buffer_len_dimension": self.metadata.buffer_len_dimension,
            },
            "updated_at": now_rfc3339(),
        });
        if fs::create_dir_all(&dir).is_ok() {
            if let Ok(bytes) = serde_json::to_vec_pretty(&metadata) {
                let _ = fs::write(dir.join(CORPUS_METADATA_FILE), bytes);
            }
        }
    }
}

/// The metadata file of a harness's corpus, `corpus/<harness_id>/metadata.json`.
pub const CORPUS_METADATA_FILE: &str = "metadata.json";
/// `schema_version` of the corpus metadata.
pub const CORPUS_METADATA_SCHEMA: &str = "bhf.corpus-metadata.v1";

/// A generated harness's input format: its version, and whether the explicit
/// buffer-length dimension was on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HarnessFormat {
    pub version: u32,
    pub buffer_len_dimension: bool,
}

/// The input format a finding records: `harness.format_version` (and
/// `harness.buffer_len_dimension`) first, else the top-level
/// `harness_format_version` / `buffer_len_dimension` findings written before
/// `harness` existed carry. `None` when the finding records none.
pub fn finding_harness_format(record: &serde_json::Value) -> Option<HarnessFormat> {
    let version = |value: Option<&serde_json::Value>| {
        value
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u32::try_from(version).ok())
    };
    if let Some(version) = version(record.pointer("/harness/format_version")) {
        return Some(HarnessFormat {
            version,
            buffer_len_dimension: record
                .pointer("/harness/buffer_len_dimension")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        });
    }
    Some(HarnessFormat {
        version: version(record.get("harness_format_version"))?,
        buffer_len_dimension: record
            .get("buffer_len_dimension")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

/// The input format recorded for the corpus of `harness_id` under
/// `work_dir` (`corpus/<harness_id>/metadata.json`), when one is.
pub fn recorded_corpus_format(work_dir: &Path, harness_id: &str) -> Option<HarnessFormat> {
    let bytes = fs::read(
        work_dir
            .join("corpus")
            .join(harness_id)
            .join(CORPUS_METADATA_FILE),
    )
    .ok()?;
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    finding_harness_format(&metadata)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindingMetadata {
    harness_id: String,
    dialect: String,
    fixture_path: String,
    sandbox: Option<serde_json::Value>,
    mode: actionability::RunMode,
    /// The harness/target binary's identity (sha256 + GNU build-id), as JSON
    /// (`corpus` does not depend on `binary_analysis`): merged into
    /// `record["build"]["binary"]` by every emitter.
    build_binary: Option<serde_json::Value>,
    /// The input format of the generated harness that produced the finding
    /// (its `generation-metadata.json` `harness_format_version`), so a later
    /// replay can tell when the harness has since been regenerated with a
    /// format that decodes the testcase differently.
    harness_format_version: Option<u32>,
    /// The harness had the explicit buffer-length dimension on.
    buffer_len_dimension: bool,
    /// What frame-less crashes are grouped by ([`crate::cluster::crash_scope`]);
    /// `None` groups them by the harness id.
    crash_scope: Option<String>,
}

impl FindingMetadata {
    fn crash_scope(&self) -> String {
        self.crash_scope
            .clone()
            .unwrap_or_else(|| self.harness_id.clone())
    }
}

impl Default for FindingMetadata {
    fn default() -> Self {
        Self {
            harness_id: String::new(),
            dialect: String::new(),
            fixture_path: String::new(),
            sandbox: None,
            mode: actionability::RunMode::Reporting,
            build_binary: None,
            harness_format_version: None,
            buffer_len_dimension: false,
            crash_scope: None,
        }
    }
}

/// The directories under a work dir that hold harness `<id>/` directories.
const HARNESS_ROOTS: [&str; 4] = ["build", "harnesses", "auto", "generated_harnesses"];

/// The `fixture_path` recorded for a harness at `fixture`: relative to the work
/// dir (with `/` separators) when the harness is inside it, so a copied or
/// moved work dir resolves its own harness; unchanged otherwise.
pub fn stored_fixture_path(work_dir: &std::path::Path, fixture: &str) -> String {
    use std::path::{Component, Path};
    if fixture.is_empty() {
        return String::new();
    }
    let path = Path::new(fixture);
    let relative = path
        .strip_prefix(work_dir)
        .ok()
        .map(Path::to_path_buf)
        .or_else(|| {
            let canonical = fs::canonicalize(path).ok()?;
            let work = fs::canonicalize(work_dir).ok()?;
            canonical.strip_prefix(&work).ok().map(Path::to_path_buf)
        });
    let Some(relative) = relative else {
        return fixture.to_owned();
    };
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => return fixture.to_owned(),
        }
    }
    if parts.is_empty() {
        return fixture.to_owned();
    }
    parts.join("/")
}

/// Where a finding's recorded `fixture_path` may be found, most likely first,
/// resolved against the work dir that holds `finding_dir`:
///
/// - a relative value (what bhf records now) is taken relative to that work
///   dir, then by its `build|harnesses|auto|generated_harnesses/<id>/...`
///   tail in it — never relative to the current directory, which would run
///   whatever harness sits there;
/// - an absolute value inside that work dir, or one with no harness-root tail
///   (a harness outside any work dir), is taken as given;
/// - an absolute value recorded in another work dir (by an earlier release,
///   or in the original of a copied work dir) is mapped into this one by its
///   tail. The path as recorded is that other work dir's harness: it is
///   offered by [`fixture_path_fallback`], to try only after the harness dirs
///   of this work dir.
///
/// A finding outside a work-dir layout takes the value as given.
pub fn fixture_path_candidates(
    finding_dir: &std::path::Path,
    fixture: &str,
) -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    if fixture.is_empty() {
        return Vec::new();
    }
    let path = PathBuf::from(fixture);
    let Some(work) = crate::layout::work_dir_for_finding(finding_dir) else {
        return vec![path];
    };
    let mut candidates = Vec::new();
    let mut push = |candidate: PathBuf| {
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    };
    if path.is_relative() {
        push(work.join(&path));
        if let Some(tail) = harness_tail(&path) {
            push(work.join(tail));
        }
    } else if path.starts_with(&work) {
        push(path);
    } else if let Some(tail) = harness_tail(&path) {
        push(work.join(tail));
    } else {
        push(path);
    }
    candidates
}

/// The recorded `fixture_path` as given, when [`fixture_path_candidates`]
/// held it back: an absolute path into another work dir's harness dirs. A
/// caller tries it only once this work dir's own harness dirs hold nothing
/// for the finding's `harness_id`.
pub fn fixture_path_fallback(
    finding_dir: &std::path::Path,
    fixture: &str,
) -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(fixture);
    let work = crate::layout::work_dir_for_finding(finding_dir)?;
    (path.is_absolute() && !path.starts_with(&work) && harness_tail(&path).is_some())
        .then_some(path)
}

/// The `<root>/<id>/<leaf...>` tail of a harness path, from the last
/// component naming a harness root (`build`, `harnesses`, `auto`,
/// `generated_harnesses`) that is followed by at least an id and a file name.
fn harness_tail(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let parts: Vec<_> = path.components().collect();
    let index = (0..parts.len().saturating_sub(2)).rev().find(|&i| {
        matches!(parts[i], std::path::Component::Normal(name)
            if HARNESS_ROOTS.iter().any(|root| name == std::ffi::OsStr::new(root)))
    })?;
    Some(parts[index..].iter().collect())
}

/// A later run reproduced this finding: stamp `last_seen` (and history).
/// A caller replaying against a possibly read-only evidence tree should
/// `let _ =` the result rather than fail the replay on it.
///
/// Idempotent across repeated reproductions: `last_seen` is updated every
/// call, but a finding replayed N times keeps a single trailing
/// `command`/`[last_seen]` history entry (its timestamp refreshed) rather than
/// growing `history` by one entry per replay.
pub fn touch_last_seen(finding_dir: &std::path::Path, command: &str) -> std::io::Result<()> {
    let path = finding_dir.join("finding.json");
    let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if !raw.is_object() {
        return Ok(());
    }
    raw["last_seen"] = json!(now_rfc3339());
    let refreshed = raw
        .get_mut("history")
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|history| history.last_mut())
        .filter(|last| {
            last.get("command").and_then(serde_json::Value::as_str) == Some(command)
                && last.get("fields") == Some(&json!(["last_seen"]))
        })
        .map(|last| {
            last["at"] = json!(now_rfc3339());
        });
    if refreshed.is_none() {
        append_history(&mut raw, command, &["last_seen"]);
    }
    fs::write(&path, serde_json::to_vec_pretty(&raw)?)
}

/// Merge the harness/target binary's identity into `record["build"]["binary"]`,
/// creating `build` as an object first if no sandbox metadata already put one
/// there. No-op when `metadata` carries no build identity.
fn merge_build_binary(record: &mut serde_json::Value, metadata: &FindingMetadata) {
    if let Some(version) = metadata.harness_format_version {
        // `harness` is where readers look first; the top-level keys stay for
        // readers that predate it.
        record["harness"] = json!({
            "format_version": version,
            "buffer_len_dimension": metadata.buffer_len_dimension,
        });
        record["harness_format_version"] = json!(version);
    }
    if metadata.buffer_len_dimension {
        record["buffer_len_dimension"] = json!(true);
    }
    if let Some(binary) = &metadata.build_binary {
        let build = record
            .as_object_mut()
            .expect("record is an object")
            .entry("build")
            .or_insert_with(|| json!({}));
        if let Some(build) = build.as_object_mut() {
            build.insert("binary".to_owned(), binary.clone());
        }
    }
}

/// `decoded.json` before any argument trace: the input's size, preview and raw
/// byte provenance. A C/C++ finding's trace rewrites it (see
/// [`crate::decoded_args::record_trace`]).
fn decoded_placeholder(input: &[u8]) -> serde_json::Value {
    crate::decoded_args::decoded_document(
        input,
        &crate::decoded_args::TraceOutcome::Unavailable(
            "no argument trace was recorded for this finding".to_owned(),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn finding_record(
    id: &str,
    fixture_path: &str,
    signature_hex: &str,
    classification: Classification,
    testcase: &Testcase,
    handler: &HandlerEvent,
    metadata: &FindingMetadata,
    cluster_short: &str,
    cluster_full: &str,
    cluster_frames: &[String],
    cluster_fallback: bool,
) -> serde_json::Value {
    let classification_str = classification_label(classification);
    let rule_id = finding_rules::derive_rule_id(
        Some(classification_str),
        Some(handler.exception_name.as_str()),
    );
    let mut record = json!({
        "id": id,
        "signature": signature_hex,
        "cluster_key": cluster_short,
        "cluster_key_full": cluster_full,
        "cluster_normalized_frames": cluster_frames,
        "cluster_fallback": cluster_fallback,
        "classification": classification,
        "tier": finding_tier(classification, &handler.exception_name).as_str(),
        "handler": handler,
        "last_breadcrumb": handler.last_breadcrumb,
        "raises": testcase.raises,
        "mocks": testcase.mocks,
        "harness_id": metadata.harness_id,
        "dialect": metadata.dialect,
        "fixture_path": fixture_path,
        "exception": {
            "name": handler.exception_name,
            "message": handler.exception_message,
        },
        "paths": {
            "testcase": "testcase.bin",
            "decoded": "decoded.json",
            "finding": "finding.json",
        },
    });
    if let Some(rule_id) = rule_id {
        record["rule_id"] = json!(rule_id);
    }
    if let Some(sandbox) = &metadata.sandbox {
        record["sandbox"] = sandbox.clone();
        record["build"] = json!({ "sandbox": sandbox });
    }
    merge_build_binary(&mut record, metadata);
    record
}

fn classification_label(classification: Classification) -> &'static str {
    match classification {
        Classification::Unhandled => "unhandled",
        Classification::SwallowedPredefined => "swallowed_predefined",
        Classification::SwallowedUser => "swallowed_user",
        Classification::ExplicitRaise => "explicit_raise",
    }
}

fn oracle_exception_name(name: &str) -> String {
    let mut out = String::from("ORACLE_");
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::FindingEmitter;
    use super::{append_history, finding_kind, stamp_v1};
    use super::{
        finding_harness_format, recorded_corpus_format, HarnessFormat, CORPUS_METADATA_FILE,
        CORPUS_METADATA_SCHEMA,
    };
    use crate::compute_signature;
    use event_log::{HandlerEvent, Testcase};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn emit_creates_finding_directory() {
        let root = temp_dir("directory");
        let emitter = FindingEmitter::new(root.clone());

        let id = emitter.emit(b"input", &testcase(), 0).unwrap();

        assert!(crate::layout::findings_dir(&root).join(id.0).is_dir());
    }

    #[test]
    fn emit_writes_testcase_bin_with_exact_input_bytes() {
        let root = temp_dir("testcase-bin");
        let emitter = FindingEmitter::new(root.clone());

        let id = emitter.emit(b"\x00\x01bad", &testcase(), 0).unwrap();

        assert_eq!(
            fs::read(
                crate::layout::findings_dir(&root)
                    .join(id.0)
                    .join("testcase.bin")
            )
            .unwrap(),
            b"\x00\x01bad"
        );
    }

    #[test]
    fn findings_record_the_harness_format_they_were_found_with() {
        let root = temp_dir("format-version");
        let emitter = FindingEmitter::new(root.clone()).with_harness_format_version(Some(3));
        let id = emitter.emit(b"abc", &testcase(), 0).unwrap();
        let record: serde_json::Value = serde_json::from_slice(
            &fs::read(
                crate::layout::findings_dir(&root)
                    .join(&id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(record["harness_format_version"], 3);
        assert!(record.get("buffer_len_dimension").is_none());
        assert_eq!(
            record["harness"],
            serde_json::json!({"format_version": 3, "buffer_len_dimension": false}),
            "the format is also recorded under `harness`"
        );

        let sized = FindingEmitter::new(root.clone())
            .with_harness_format_version(Some(3))
            .with_buffer_len_dimension(true);
        let id = sized.emit(b"abe", &testcase(), 0).unwrap();
        let record: serde_json::Value = serde_json::from_slice(
            &fs::read(
                crate::layout::findings_dir(&root)
                    .join(&id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(record["buffer_len_dimension"], true);
        assert_eq!(record["harness"]["buffer_len_dimension"], true);

        let unversioned = FindingEmitter::new(root.clone());
        let id = unversioned.emit(b"abd", &testcase(), 0).unwrap();
        let record: serde_json::Value = serde_json::from_slice(
            &fs::read(
                crate::layout::findings_dir(&root)
                    .join(&id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(record.get("harness_format_version").is_none());
        assert!(record.get("harness").is_none());
    }

    /// The corpus of the harness that found something records the harness's
    /// input format, so inputs kept from another format are recognised.
    #[test]
    fn a_finding_records_the_harness_format_in_the_corpus_metadata() {
        let root = temp_dir("corpus-format");
        let emitter = FindingEmitter::with_metadata(
            root.clone(),
            "H-C0001".to_owned(),
            "c".to_owned(),
            "harnesses/H-C0001/main".to_owned(),
        )
        .with_harness_format_version(Some(3));
        emitter.emit(b"abc", &testcase(), 0).unwrap();
        let metadata: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join("corpus/H-C0001").join(CORPUS_METADATA_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(metadata["schema_version"], CORPUS_METADATA_SCHEMA);
        assert_eq!(metadata["harness_id"], "H-C0001");
        assert_eq!(metadata["harness"]["format_version"], 3);
        assert_eq!(
            recorded_corpus_format(&root, "H-C0001"),
            Some(HarnessFormat {
                version: 3,
                buffer_len_dimension: false
            })
        );
        // An emitter that knows no format leaves the corpus metadata alone.
        let unknown = FindingEmitter::with_metadata(
            root.clone(),
            "H-C0002".to_owned(),
            "c".to_owned(),
            String::new(),
        );
        unknown.emit(b"abd", &testcase(), 0).unwrap();
        assert!(!root
            .join("corpus/H-C0002")
            .join(CORPUS_METADATA_FILE)
            .exists());
        assert_eq!(recorded_corpus_format(&root, "H-C0002"), None);
    }

    /// A fuzz pass stamps a corpus it creates when it starts, leaves an
    /// existing corpus's stamp alone until it ends, and then stamps it with
    /// its own format.
    #[test]
    fn a_pass_stamps_a_new_corpus_at_its_start_and_every_corpus_at_its_end() {
        let root = temp_dir("corpus-pass-format");
        let emitter = |version: u32| {
            FindingEmitter::with_metadata(
                root.clone(),
                "H-C0003".to_owned(),
                "c".to_owned(),
                String::new(),
            )
            .with_harness_format_version(Some(version))
        };
        emitter(4).start_corpus_format();
        assert_eq!(
            recorded_corpus_format(&root, "H-C0003").map(|format| format.version),
            Some(4)
        );
        emitter(5).start_corpus_format();
        assert_eq!(
            recorded_corpus_format(&root, "H-C0003").map(|format| format.version),
            Some(4),
            "an existing corpus keeps its stamp when a pass starts"
        );
        emitter(5).record_corpus_format();
        assert_eq!(
            recorded_corpus_format(&root, "H-C0003").map(|format| format.version),
            Some(5)
        );
        // A corpus from before the stamp keeps having none until a pass ends.
        let queue = root.join("corpus/H-C0004/queue");
        fs::create_dir_all(&queue).unwrap();
        let unstamped = FindingEmitter::with_metadata(
            root.clone(),
            "H-C0004".to_owned(),
            "c".to_owned(),
            String::new(),
        )
        .with_harness_format_version(Some(4));
        unstamped.start_corpus_format();
        assert_eq!(recorded_corpus_format(&root, "H-C0004"), None);
    }

    #[test]
    fn the_recorded_format_is_read_from_harness_first_then_the_legacy_key() {
        let both = serde_json::json!({
            "harness": {"format_version": 3, "buffer_len_dimension": true},
            "harness_format_version": 2
        });
        assert_eq!(
            finding_harness_format(&both),
            Some(HarnessFormat {
                version: 3,
                buffer_len_dimension: true
            })
        );
        let legacy = serde_json::json!({"harness_format_version": 2, "buffer_len_dimension": true});
        assert_eq!(
            finding_harness_format(&legacy),
            Some(HarnessFormat {
                version: 2,
                buffer_len_dimension: true
            })
        );
        assert_eq!(finding_harness_format(&serde_json::json!({})), None);
    }

    #[test]
    fn emit_writes_decoded_json_with_input_size() {
        let root = temp_dir("decoded");
        let emitter = FindingEmitter::new(root.clone());

        let id = emitter.emit(b"abcdef", &testcase(), 0).unwrap();
        let decoded = fs::read_to_string(
            crate::layout::findings_dir(&root)
                .join(id.0)
                .join("decoded.json"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&decoded).unwrap();

        assert_eq!(value["input_size"], 6);
        assert_eq!(value["preview_hex"], "616263646566");
    }

    #[test]
    fn emit_writes_lightweight_input_provenance() {
        let root = temp_dir("decoded-provenance");
        let emitter = FindingEmitter::new(root.clone());
        let input = b"\x00\x01bad";

        let id = emitter.emit(input, &testcase(), 0).unwrap();
        let decoded = fs::read_to_string(
            crate::layout::findings_dir(&root)
                .join(id.0)
                .join("decoded.json"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&decoded).unwrap();

        assert_eq!(value["provenance"][0]["kind"], "raw_bytes");
        assert_eq!(value["provenance"][0]["source"], "testcase.bin");
        assert_eq!(value["provenance"][0]["byte_range"]["end"], input.len());
    }

    #[test]
    fn emit_writes_finding_json_with_signature_hex() {
        let root = temp_dir("finding-json");
        let emitter = FindingEmitter::new(root.clone());
        let testcase = testcase();
        let expected = compute_signature(&testcase, &testcase.handlers[0]).hex();

        let id = emitter.emit(b"input", &testcase, 0).unwrap();
        let finding = fs::read_to_string(
            crate::layout::findings_dir(&root)
                .join(id.0)
                .join("finding.json"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["signature"], expected);
        assert_eq!(value["classification"], "swallowed_predefined");
        assert_eq!(value["finding_kind"], "fuzz");
        assert_eq!(value["handler"]["handler_line"], 9);
    }

    #[test]
    fn emit_populates_rule_id_and_exception_block_from_classification() {
        let root = temp_dir("rule-id-and-exception");
        let emitter = FindingEmitter::new(root.clone());
        let testcase = testcase();

        let id = emitter.emit(b"input", &testcase, 0).unwrap();
        let finding = fs::read_to_string(
            crate::layout::findings_dir(&root)
                .join(id.0)
                .join("finding.json"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["rule_id"], "BHF-102");
        assert_eq!(value["exception"]["name"], "CONSTRAINT_ERROR");
        assert_eq!(value["exception"]["message"], "bad input");
    }

    #[test]
    fn emit_marks_mock_based_ada_finding_lab_only() {
        let root = temp_dir("ada-mock-actionability");
        let emitter =
            FindingEmitter::new(root.clone()).with_mode(actionability::RunMode::Attacking);
        let mut testcase = testcase();
        testcase.mocks = vec![event_log::MockEvent {
            symbol: "Missing_Service".to_owned(),
        }];

        let id = emitter.emit(b"input", &testcase, 0).unwrap();
        let finding = fs::read_to_string(
            crate::layout::findings_dir(&root)
                .join(id.0)
                .join("finding.json"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["mocks"][0]["symbol"], "Missing_Service");
        assert_eq!(value["actionability"]["verdict"], "lab_only");
        assert_eq!(value["actionability"]["prosthetics"]["used"], true);
    }

    #[test]
    fn emit_tags_swallowed_predefined_with_swallowed_check_tier() {
        let root = temp_dir("tier-swallowed-check");
        let emitter = FindingEmitter::new(root.clone());
        let id = emitter.emit(b"input", &testcase(), 0).unwrap();
        let value: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(&root)
                    .join(id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(value["tier"], "swallowed_check");
    }

    #[test]
    fn emit_records_unhandled_top_level_as_real_fault() {
        let root = temp_dir("tier-real-fault");
        let emitter = FindingEmitter::new(root.clone());
        let mut testcase = testcase();
        // An exception that escaped the target unhandled to the harness top
        // level, with no in-target handler that caught it.
        testcase.handlers.clear();
        testcase.top_level = Some(event_log::TopLevelEvent {
            exception_name: "PROGRAM_ERROR".to_owned(),
            exception_message: "escaped to harness".to_owned(),
        });

        let id = emitter
            .emit(b"input", &testcase, crate::UNHANDLED_HANDLER_INDEX)
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(&root)
                    .join(id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(value["tier"], "real_fault");
        assert_eq!(value["classification"], "unhandled");
        assert_eq!(value["exception"]["name"], "PROGRAM_ERROR");
        assert_eq!(value["rule_id"], "BHF-101");
    }

    #[test]
    fn emit_returns_finding_id_with_short_sig_prefix() {
        let root = temp_dir("id");
        let emitter = FindingEmitter::new(root);
        let testcase = testcase();
        let signature = compute_signature(&testcase, &testcase.handlers[0]).hex();

        let id = emitter.emit(b"input", &testcase, 0).unwrap();

        assert_eq!(id.0, format!("F-0000-{}", &signature[..8]));
    }

    #[test]
    fn emit_allocates_exclusively_and_never_overwrites_a_taken_ordinal() {
        let root = temp_dir("alloc");
        let emitter = FindingEmitter::new(root.clone());
        let testcase = testcase();
        let signature = compute_signature(&testcase, &testcase.handlers[0]).hex();

        // A concurrent writer sharing the work dir already holds F-0000 with
        // its own data; the emit must skip it, not scan-then-overwrite it.
        let taken = crate::layout::findings_dir(&root).join(format!("F-0000-{}", &signature[..8]));
        std::fs::create_dir_all(&taken).unwrap();
        std::fs::write(taken.join("sentinel"), b"keep").unwrap();

        let id = emitter.emit(b"input", &testcase, 0).unwrap();

        assert!(id.0.starts_with("F-0001-"), "got {}", id.0);
        assert_eq!(
            std::fs::read(taken.join("sentinel")).unwrap(),
            b"keep",
            "the already-taken finding dir must be left intact"
        );
    }

    fn testcase() -> Testcase {
        let handler = HandlerEvent {
            sequence_index: 3,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            exception_message: "bad input".to_owned(),
            handler_file: "pkg.adb".to_owned(),
            handler_line: 9,
            last_breadcrumb: 1,
            target_id: 0x42,
            testcase_id: 1,
        };

        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            target_entered: false,
            crumbs: vec![1],
            handlers: vec![handler],
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bhf-finding-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn testcase_with_message(message: &str) -> Testcase {
        let mut tc = testcase();
        tc.handlers[0].exception_message = message.to_owned();
        tc
    }

    #[test]
    fn emit_remaps_exception_line_to_original_source() {
        let root = temp_dir("remap");
        let instr = root.join("src_instrumented");
        fs::create_dir_all(&instr).unwrap();
        // Anchor (62 -> 56): an instrumented line 646 maps to 56 + (646-62) = 640.
        fs::write(
            instr.join("bzip2-decoding.adb.bhf-lines.json"),
            r#"{"source_path":"/src/bzip2-decoding.adb","anchors":[[1,1],[62,56]]}"#,
        )
        .unwrap();
        let emitter = FindingEmitter::new(root.clone()).with_line_maps_dir(&instr);

        let id = emitter
            .emit(
                b"crash",
                &testcase_with_message("bzip2-decoding.adb:646 index check failed"),
                0,
            )
            .unwrap();
        let finding: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(&root)
                    .join(&id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            finding["exception"]["message"],
            "bzip2-decoding.adb:640 index check failed"
        );
        assert_eq!(
            finding["exception"]["source_file"],
            "/src/bzip2-decoding.adb"
        );
        assert_eq!(finding["exception"]["source_line"], 640);
    }

    #[test]
    fn emit_without_line_maps_leaves_message_unchanged() {
        let root = temp_dir("no-remap");
        let emitter = FindingEmitter::new(root.clone());
        let id = emitter
            .emit(
                b"crash",
                &testcase_with_message("bzip2-decoding.adb:646 boom"),
                0,
            )
            .unwrap();
        let finding: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(&root)
                    .join(&id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            finding["exception"]["message"],
            "bzip2-decoding.adb:646 boom"
        );
        assert!(finding["exception"].get("source_line").is_none());
    }

    #[test]
    fn emit_sanitizer_crash_writes_cluster_fields() {
        use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
        let root = temp_dir("cluster-sanitizer");
        let emitter = super::FindingEmitter::new(root.clone());
        let report = SanitizerReport {
            sanitizer: Some(Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            stack: vec![
                StackFrame {
                    function: "__asan_memcpy".to_owned(),
                    file: None,
                    line: None,
                },
                StackFrame {
                    function: "real_parse".to_owned(),
                    file: Some("/src/p.c".to_owned()),
                    line: Some(9),
                },
                StackFrame {
                    function: "LLVMFuzzerTestOneInput".to_owned(),
                    file: None,
                    line: None,
                },
            ],
            message: "ERROR: ASan: heap-buffer-overflow".to_owned(),
            ..Default::default()
        };
        let id = emitter.emit_sanitizer_crash(b"in", &report).unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(&root)
                    .join(id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(v["cluster_normalized_frames"][0], "real_parse");
        let short = v["cluster_key"].as_str().unwrap();
        assert_eq!(short.len(), 16);
        assert_eq!(v["cluster_fallback"], false);
        assert_eq!(v["cluster_key_full"].as_str().unwrap().len(), 64);
        // A genuine sanitizer keeps its provenance and an ASAN_* exception name.
        assert_eq!(v["exception"]["sanitizer"], "asan");
        assert_eq!(v["exception"]["name"], "ASAN_HEAP_BUFFER_OVERFLOW");
    }

    #[test]
    fn no_sanitizer_report_omits_the_sanitizer_field_and_names_by_kind() {
        use crate::sanitizer::SanitizerReport;
        // An on-target CPU fault ran no sanitizer: the finding must NOT claim one
        // (#78) — no `sanitizer` key, and the exception name is built from the
        // kind, not a synthesized `asan` tag.
        let root = temp_dir("no-sanitizer");
        let emitter = super::FindingEmitter::new(root.clone());
        let report = SanitizerReport {
            sanitizer: None,
            kind: "target-cpu-exception".to_owned(),
            rule_id: "BHF-210",
            stack: Vec::new(),
            message: "target transport reported a target CPU exception with no sanitizer report"
                .to_owned(),
            ..Default::default()
        };
        let id = emitter.emit_sanitizer_crash(b"in", &report).unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(&root)
                    .join(id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            v["exception"].get("sanitizer").is_none(),
            "a non-sanitizer fault must carry no sanitizer field: {v}"
        );
        assert_eq!(v["exception"]["name"], "TARGET_CPU_EXCEPTION");
    }

    #[test]
    fn sanitizer_crash_lands_under_results_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let emitter = FindingEmitter::new(root.clone());
        let report = crate::sanitizer::SanitizerReport {
            sanitizer: Some(crate::sanitizer::Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            stack: Vec::new(),
            message: "heap-buffer-overflow".to_owned(),
            ..Default::default()
        };
        let id = emitter.emit_sanitizer_crash(b"in", &report).unwrap();
        let dir = crate::layout::finding_dir(&root, &id.0);
        assert!(
            dir.join("finding.json").is_file(),
            "missing {}",
            dir.display()
        );
        assert!(
            !root.join("findings").exists(),
            "legacy dir must not be created"
        );
    }

    #[test]
    fn emit_sanitizer_crash_writes_actionability_object() {
        use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
        let root = temp_dir("sanitizer-actionability");
        let emitter =
            super::FindingEmitter::new(root.clone()).with_mode(actionability::RunMode::Attacking);
        let report = SanitizerReport {
            sanitizer: Some(Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            stack: vec![StackFrame {
                function: "parse_packet".to_owned(),
                file: Some("src/packet.c".to_owned()),
                line: Some(27),
            }],
            message: "ERROR: ASan: heap-buffer-overflow".to_owned(),
            ..Default::default()
        };

        let id = emitter.emit_sanitizer_crash(b"in", &report).unwrap();
        let finding = fs::read_to_string(
            crate::layout::findings_dir(&root)
                .join(id.0)
                .join("finding.json"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["actionability"]["mode"], "attacking");
        assert_eq!(
            value["actionability"]["fix_location"]["path"],
            "src/packet.c"
        );
        assert_eq!(value["actionability"]["impact"], "critical");
    }

    fn fixture_recorded_for(root: &std::path::Path, fixture: &str) -> serde_json::Value {
        let report = crate::sanitizer::SanitizerReport {
            sanitizer: Some(crate::sanitizer::Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            message: "ERROR: AddressSanitizer: heap-buffer-overflow".to_owned(),
            ..Default::default()
        };
        let emitter = super::FindingEmitter::with_metadata(
            root.to_path_buf(),
            "H-1".to_owned(),
            "c".to_owned(),
            fixture.to_owned(),
        );
        let id = emitter.emit_sanitizer_crash(b"x", &report).unwrap();
        serde_json::from_slice(
            &fs::read(
                crate::layout::findings_dir(root)
                    .join(id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// A copied or moved work dir must run its own harness, so a harness
    /// inside the work dir is recorded relative to it.
    #[test]
    fn a_harness_inside_the_work_dir_is_recorded_relative_to_it() {
        let root = temp_dir("fixture-relative");
        let harness = root.join("harnesses").join("H-1").join("main");
        let value = fixture_recorded_for(&root, &harness.display().to_string());
        assert_eq!(value["fixture_path"], "harnesses/H-1/main");
    }

    #[test]
    fn a_harness_outside_the_work_dir_keeps_its_path() {
        let root = temp_dir("fixture-outside");
        let value = fixture_recorded_for(&root, "/opt/prebuilt/harness/main");
        assert_eq!(value["fixture_path"], "/opt/prebuilt/harness/main");
        let value = fixture_recorded_for(&root, "examples/widget/pkg.adb");
        assert_eq!(value["fixture_path"], "examples/widget/pkg.adb");
    }

    /// A relative value resolves in the work dir holding the finding, never
    /// relative to the current directory.
    #[test]
    fn a_relative_fixture_resolves_in_the_containing_work_dir_only() {
        let finding = std::path::Path::new("/copy/results/findings/F-0001-aa");
        assert_eq!(
            super::fixture_path_candidates(finding, "harnesses/H-1/main"),
            vec![PathBuf::from("/copy/harnesses/H-1/main")]
        );
        assert_eq!(
            super::fixture_path_fallback(finding, "harnesses/H-1/main"),
            None
        );
        // A value an earlier release recorded relative to its current
        // directory is mapped by its harness-root tail.
        assert_eq!(
            super::fixture_path_candidates(finding, "old/work/build/H-1/main"),
            vec![
                PathBuf::from("/copy/old/work/build/H-1/main"),
                PathBuf::from("/copy/build/H-1/main"),
            ]
        );
        // Outside a work-dir layout there is nothing else to resolve against.
        assert_eq!(
            super::fixture_path_candidates(
                std::path::Path::new("/loose/F-1"),
                "harnesses/H-1/main"
            ),
            vec![PathBuf::from("harnesses/H-1/main")]
        );
    }

    /// An absolute path recorded in another work dir is mapped into the work
    /// dir holding the finding; the path as recorded is only a fallback.
    #[test]
    fn an_absolute_fixture_is_mapped_into_the_containing_work_dir() {
        // An absolute path carries a drive on Windows.
        let abs = |path: &str| {
            if cfg!(windows) {
                format!("C:{path}")
            } else {
                path.to_owned()
            }
        };
        let finding_dir = abs("/copy/results/findings/F-0001-aa");
        let finding = std::path::Path::new(&finding_dir);
        assert_eq!(
            super::fixture_path_candidates(finding, &abs("/orig/work/harnesses/H-1/main")),
            vec![PathBuf::from(abs("/copy/harnesses/H-1/main"))]
        );
        assert_eq!(
            super::fixture_path_fallback(finding, &abs("/orig/work/harnesses/H-1/main")),
            Some(PathBuf::from(abs("/orig/work/harnesses/H-1/main")))
        );
        assert_eq!(
            super::fixture_path_candidates(finding, &abs("/copy/build/H-1/obj/main")),
            vec![PathBuf::from(abs("/copy/build/H-1/obj/main"))]
        );
        assert_eq!(
            super::fixture_path_fallback(finding, &abs("/copy/build/H-1/obj/main")),
            None
        );
        // A path with no harness-root tail is used as given.
        assert_eq!(
            super::fixture_path_candidates(finding, &abs("/opt/prebuilt/main")),
            vec![PathBuf::from(abs("/opt/prebuilt/main"))]
        );
        assert_eq!(
            super::fixture_path_fallback(finding, &abs("/opt/prebuilt/main")),
            None
        );
        assert!(super::fixture_path_candidates(finding, "").is_empty());
    }

    #[test]
    fn a_resource_leak_finding_is_named_for_the_oracle_of_its_harness() {
        use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

        let root = temp_dir("oracle-leak-names");
        let leak = |oracle: &str| OracleHit {
            oracle_name: oracle.to_owned(),
            rule_id: "BHF-306".to_owned(),
            category: "logic-bug".to_owned(),
            api: "fopen".to_owned(),
            message: "resource opened during fuzz execution was not released".to_owned(),
            evidence: vec![OracleEvidence {
                key: "resource".to_owned(),
                value: "fd:4 path:/srv/widget.cfg".to_owned(),
            }],
        };
        let exception_name = |harness: &str, language: &str, oracle: &str| {
            let emitter = super::FindingEmitter::with_metadata(
                root.clone(),
                harness.to_owned(),
                language.to_owned(),
                format!("/tmp/{harness}/main"),
            );
            let id = emitter.emit_oracle_hit(b"widget", &leak(oracle)).unwrap();
            let finding: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(
                    crate::layout::findings_dir(&root)
                        .join(id.0)
                        .join("finding.json"),
                )
                .unwrap(),
            )
            .unwrap();
            finding["exception"]["name"].as_str().unwrap().to_owned()
        };
        assert_eq!(
            exception_name("H-C0001", "c", "resource-leak"),
            "ORACLE_RESOURCE_LEAK"
        );
        assert_eq!(
            exception_name("H-A0001", "ada", "resource-leak-ada"),
            "ORACLE_RESOURCE_LEAK_ADA"
        );
    }

    #[test]
    fn emit_oracle_hit_writes_runtime_evidence() {
        use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

        let root = temp_dir("oracle-hit");
        let emitter = super::FindingEmitter::with_metadata(
            root.clone(),
            "H-path".to_owned(),
            "c".to_owned(),
            "/tmp/harness/main.c".to_owned(),
        );
        let hit = OracleHit {
            oracle_name: "path-traversal-ada".to_owned(),
            rule_id: "BHF-101".to_owned(),
            category: "logic-bug".to_owned(),
            api: "open".to_owned(),
            message: "filesystem path contains a parent-directory component".to_owned(),
            evidence: vec![OracleEvidence {
                key: "path".to_owned(),
                value: "../../etc/passwd".to_owned(),
            }],
        };

        let id = emitter.emit_oracle_hit(b"../../etc/passwd", &hit).unwrap();
        let finding = fs::read_to_string(
            crate::layout::findings_dir(&root)
                .join(id.0)
                .join("finding.json"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["rule_id"], "BHF-101");
        assert_eq!(value["classification"], "oracle_hit");
        assert_eq!(value["finding_kind"], "fuzz");
        assert_eq!(value["harness_id"], "H-path");
        assert_eq!(value["oracle"]["name"], "path-traversal-ada");
        assert_eq!(value["oracle"]["category"], "logic-bug");
        assert_eq!(value["oracle"]["evidence"][0]["key"], "path");
        assert_eq!(value["oracle"]["evidence"][0]["value"], "../../etc/passwd");
        assert_eq!(
            fs::read(
                crate::layout::findings_dir(&root)
                    .join(value["id"].as_str().unwrap())
                    .join("testcase.bin")
            )
            .unwrap(),
            b"../../etc/passwd"
        );
    }

    #[test]
    fn emit_oracle_hit_distinct_assert_sites_cluster_separately_and_populate_sink() {
        use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

        let root = temp_dir("oracle-assert-sites");
        let emitter = super::FindingEmitter::with_metadata(
            root.clone(),
            "H-assert".to_owned(),
            "c".to_owned(),
            "/tmp/harness/main.c".to_owned(),
        );
        let hit_at = |source: &str, expr: &str| OracleHit {
            oracle_name: "native-assertion-contract".to_owned(),
            rule_id: "BHF-415".to_owned(),
            category: "logic-bug".to_owned(),
            api: "__assert_fail".to_owned(),
            message: "native assertion contract failed during fuzz execution".to_owned(),
            evidence: vec![
                OracleEvidence::new("exception", "AssertionFailure"),
                OracleEvidence::new("check", "assertion"),
                OracleEvidence::new("expression", expr),
                OracleEvidence::new("source", source),
            ],
        };

        let id_a = emitter
            .emit_oracle_hit(b"a", &hit_at("parser.c:42:parse_frame", "len < cap"))
            .unwrap();
        let id_b = emitter
            .emit_oracle_hit(b"b", &hit_at("writer.c:99:flush_buf", "n > 0"))
            .unwrap();

        let read = |id: &super::FindingId| -> serde_json::Value {
            serde_json::from_str(
                &fs::read_to_string(
                    crate::layout::findings_dir(&root)
                        .join(&id.0)
                        .join("finding.json"),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let a = read(&id_a);
        let b = read(&id_b);

        // Two distinct assert sites → two distinct clusters (no over-merge).
        assert_ne!(a["cluster_key"], b["cluster_key"]);
        assert_ne!(a["cluster_key_full"], b["cluster_key_full"]);

        // The source location populates the actionability sink (report CSV cols).
        assert_eq!(a["actionability"]["sink"]["function"], "parse_frame");
        assert_eq!(a["actionability"]["sink"]["file"], "parser.c");
        assert_eq!(a["actionability"]["sink"]["line"], 42);
    }

    #[test]
    fn emit_oracle_hit_same_assert_site_clusters_together() {
        use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

        let root = temp_dir("oracle-assert-same");
        let emitter = super::FindingEmitter::new(root.clone());
        let hit = OracleHit {
            oracle_name: "native-assertion-contract".to_owned(),
            rule_id: "BHF-415".to_owned(),
            category: "logic-bug".to_owned(),
            api: "__assert_fail".to_owned(),
            message: "native assertion contract failed during fuzz execution".to_owned(),
            evidence: vec![
                OracleEvidence::new("expression", "len < cap"),
                OracleEvidence::new("source", "parser.c:42:parse_frame"),
            ],
        };
        // Same site, two different inputs → same cluster (the per-input bytes are
        // not part of the cluster key).
        let id_a = emitter.emit_oracle_hit(b"input-one", &hit).unwrap();
        let id_b = emitter
            .emit_oracle_hit(b"input-two-different", &hit)
            .unwrap();
        let read = |id: &super::FindingId| -> serde_json::Value {
            serde_json::from_str(
                &fs::read_to_string(
                    crate::layout::findings_dir(&root)
                        .join(&id.0)
                        .join("finding.json"),
                )
                .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(read(&id_a)["cluster_key"], read(&id_b)["cluster_key"]);
    }

    fn extension_finding(rule: &str, path: &str) -> super::ExtensionFinding {
        super::ExtensionFinding {
            rule: rule.to_owned(),
            classification: "extension_oracle".to_owned(),
            signature_inputs: vec![rule.to_owned(), path.to_owned()],
            evidence: vec![
                ("path".to_owned(), path.to_owned()),
                ("reason".to_owned(), "escapes sandbox root".to_owned()),
            ],
            min_predicate: Some("path-contains-dotdot".to_owned()),
            provenance: serde_json::json!({
                "executable_sha256": "a".repeat(64),
                "config_sha256": "b".repeat(64),
                "protocol_version": "bhf.extension.v1",
                "negotiated_caps": ["oracle.evaluate"],
            }),
        }
    }

    fn read_finding(root: &std::path::Path, id: &super::FindingId) -> serde_json::Value {
        serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(root)
                    .join(&id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn emit_extension_finding_writes_confirmation_extension() {
        let root = temp_dir("ext-confirmation");
        let emitter = super::FindingEmitter::with_metadata(
            root.clone(),
            "H-ext".to_owned(),
            "c".to_owned(),
            "/tmp/harness/main.c".to_owned(),
        );
        let id = emitter
            .emit_extension_finding(
                b"../etc/passwd",
                &extension_finding("oracle.path-escape", "../etc/passwd"),
            )
            .unwrap();
        let v = read_finding(&root, &id);
        assert_eq!(v["confirmation"], "extension");
        assert_eq!(v["classification"], "extension_oracle");
        assert_eq!(v["rule_id"], "oracle.path-escape");
        assert_eq!(v["finding_kind"], "fuzz");
        assert_eq!(v["evidence"][0]["key"], "path");
        assert_eq!(v["evidence"][0]["value"], "../etc/passwd");
        assert_eq!(v["min_predicate"], "path-contains-dotdot");
        assert_eq!(
            fs::read(
                crate::layout::findings_dir(&root)
                    .join(&id.0)
                    .join("testcase.bin")
            )
            .unwrap(),
            b"../etc/passwd"
        );
    }

    #[test]
    fn emit_extension_finding_signature_is_stable_across_identical_violations() {
        let root = temp_dir("ext-stable-sig");
        let emitter = super::FindingEmitter::new(root.clone());
        let finding = extension_finding("oracle.path-escape", "../etc/passwd");
        let id_a = emitter
            .emit_extension_finding(b"../etc/passwd", &finding)
            .unwrap();
        let id_b = emitter
            .emit_extension_finding(b"../etc/passwd", &finding)
            .unwrap();
        let a = read_finding(&root, &id_a);
        let b = read_finding(&root, &id_b);
        // Identical violation content → identical signature AND cluster key, so a
        // replay/minimize reproduces the same stable identity.
        assert_eq!(a["signature"], b["signature"]);
        assert_eq!(a["cluster_key"], b["cluster_key"]);
        assert_eq!(a["cluster_key_full"], b["cluster_key_full"]);
    }

    #[test]
    fn emit_extension_finding_stamps_executable_config_hashes_and_caps() {
        let root = temp_dir("ext-provenance");
        let emitter = super::FindingEmitter::new(root.clone());
        let id = emitter
            .emit_extension_finding(
                b"../etc/passwd",
                &extension_finding("oracle.path-escape", "../etc/passwd"),
            )
            .unwrap();
        let v = read_finding(&root, &id);
        assert_eq!(v["extension"]["executable_sha256"], "a".repeat(64));
        assert_eq!(v["extension"]["config_sha256"], "b".repeat(64));
        assert_eq!(v["extension"]["protocol_version"], "bhf.extension.v1");
        assert_eq!(v["extension"]["negotiated_caps"][0], "oracle.evaluate");
    }

    #[test]
    fn emit_extension_finding_distinct_sites_cluster_separately() {
        let root = temp_dir("ext-distinct-sites");
        let emitter = super::FindingEmitter::new(root.clone());
        let id_a = emitter
            .emit_extension_finding(b"a", &extension_finding("oracle.path-escape", "../a"))
            .unwrap();
        let id_b = emitter
            .emit_extension_finding(
                b"b",
                &extension_finding("oracle.secret-exfil", "/etc/shadow"),
            )
            .unwrap();
        let a = read_finding(&root, &id_a);
        let b = read_finding(&root, &id_b);
        // Two different rules → two distinct clusters (no over-merge) and distinct
        // signatures.
        assert_ne!(a["cluster_key"], b["cluster_key"]);
        assert_ne!(a["cluster_key_full"], b["cluster_key_full"]);
        assert_ne!(a["signature"], b["signature"]);
    }

    #[test]
    fn emit_writes_cluster_fields_for_ada_path() {
        let root = temp_dir("cluster-ada");
        let emitter = super::FindingEmitter::new(root.clone());
        let id = emitter.emit(b"input", &testcase(), 0).unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(&root)
                    .join(id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(v["cluster_normalized_frames"][0], "CONSTRAINT_ERROR");
        assert_eq!(v["cluster_normalized_frames"][1], "pkg.adb:9");
        assert_eq!(v["cluster_fallback"], false);
        assert_eq!(v["cluster_key"].as_str().unwrap().len(), 16);
    }

    #[test]
    fn emit_sanitizer_crash_falls_back_when_only_noise() {
        use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
        let root = temp_dir("cluster-fallback");
        let emitter = super::FindingEmitter::new(root.clone());
        let report = SanitizerReport {
            sanitizer: Some(Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            stack: vec![StackFrame {
                function: "__asan_memcpy".to_owned(),
                file: None,
                line: None,
            }],
            message: "ERROR: ASan: heap-buffer-overflow".to_owned(),
            ..Default::default()
        };
        let id = emitter.emit_sanitizer_crash(b"x", &report).unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                crate::layout::findings_dir(&root)
                    .join(id.0)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(v["cluster_fallback"], true);
        let signature = v["signature"].as_str().unwrap();
        assert_eq!(v["cluster_key"], signature[..16]);
    }

    #[test]
    fn new_records_carry_the_v1_envelope() {
        let root = temp_dir("v1-envelope");
        let emitter = FindingEmitter::new(root.clone());
        let report = crate::sanitizer::SanitizerReport {
            sanitizer: Some(crate::sanitizer::Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            stack: Vec::new(),
            message: "heap-buffer-overflow".to_owned(),
            ..Default::default()
        };
        let id = emitter.emit_sanitizer_crash(b"in", &report).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(
            &fs::read(crate::layout::finding_dir(&root, &id.0).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(raw["schema_version"], "bhf.finding.v1");
        assert_eq!(raw["finding_kind"], "fuzz");
        let created = raw["created_at"].as_str().unwrap();
        assert!(
            chrono::DateTime::parse_from_rfc3339(created).is_ok(),
            "{created}"
        );
    }

    #[test]
    fn stamp_keeps_an_existing_created_at() {
        let mut v = serde_json::json!({"id": "x", "created_at": "2020-01-01T00:00:00Z"});
        stamp_v1(&mut v, finding_kind::STATIC);
        assert_eq!(v["created_at"], "2020-01-01T00:00:00Z");
        assert_eq!(v["finding_kind"], "static");
    }

    #[test]
    fn append_history_records_command_and_fields() {
        let mut v = serde_json::json!({"id": "x"});
        append_history(&mut v, "minimize", &["minimal_reproducer"]);
        append_history(&mut v, "cartography", &["primitive"]);
        let history = v["history"].as_array().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0]["command"], "minimize");
        assert_eq!(history[1]["fields"][0], "primitive");
        assert!(chrono::DateTime::parse_from_rfc3339(history[0]["at"].as_str().unwrap()).is_ok());
    }

    #[test]
    fn run_dedupe_key_mirrors_the_fuzz_run_keys() {
        use super::{run_dedupe_key, RunDedupeKey};
        use serde_json::json;
        let oracle = json!({
            "rule_id": "BHF-405",
            "oracle": {"name": "path-traversal", "api": "open"},
            "cluster_key_full": "c0ffee",
        });
        assert_eq!(
            run_dedupe_key(&oracle),
            Some(RunDedupeKey::Oracle(
                "BHF-405|path-traversal|open".to_owned()
            ))
        );
        // A fallback record keys on its own `cluster_key_full` (its signature),
        // not on one shared `rule:<id>` per rule.
        let fallback =
            json!({"rule_id": "BHF-210", "cluster_fallback": true, "cluster_key_full": "x"});
        assert_eq!(
            run_dedupe_key(&fallback),
            Some(RunDedupeKey::Cluster("x".to_owned()))
        );
        let clustered = json!({"rule_id": "BHF-201", "cluster_fallback": false, "cluster_key_full": "deadbeef"});
        assert_eq!(
            run_dedupe_key(&clustered),
            Some(RunDedupeKey::Cluster("deadbeef".to_owned()))
        );
        // An oracle block without an api falls back to the cluster key.
        let partial_oracle =
            json!({"rule_id": "BHF-405", "oracle": {"name": "n"}, "cluster_key_full": "beef"});
        assert_eq!(
            run_dedupe_key(&partial_oracle),
            Some(RunDedupeKey::Cluster("beef".to_owned()))
        );
        // The run keys an oracle hit with an empty api exactly so.
        let empty_api = json!({"rule_id": "BHF-405", "oracle": {"name": "n", "api": ""}});
        assert_eq!(
            run_dedupe_key(&empty_api),
            Some(RunDedupeKey::Oracle("BHF-405|n|".to_owned()))
        );
        assert_eq!(run_dedupe_key(&json!({"cluster_key_full": ""})), None);
        assert_eq!(
            run_dedupe_key(&json!({"rule_id": "", "cluster_fallback": true})),
            None
        );
        assert_eq!(run_dedupe_key(&json!({"signature": "abc"})), None);
    }

    #[test]
    fn sanitizer_log_is_written_and_capped() {
        use super::{write_sanitizer_log, SANITIZER_LOG_MAX};
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_sanitizer_log(dir, b"==1==ERROR: AddressSanitizer\n").unwrap();
        assert_eq!(
            fs::read(dir.join("sanitizer.log")).unwrap(),
            b"==1==ERROR: AddressSanitizer\n"
        );
        let big = vec![b'a'; (SANITIZER_LOG_MAX + 10) as usize];
        write_sanitizer_log(dir, &big).unwrap();
        let written = fs::read_to_string(dir.join("sanitizer.log")).unwrap();
        assert!(
            written.ends_with("\n[truncated 10 bytes]\n"),
            "{}",
            &written[written.len() - 40..]
        );
        assert!(written.len() < big.len() + 40);
    }

    #[test]
    fn emit_with_log_writes_sanitizer_log_next_to_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let emitter = FindingEmitter::new(root.clone());
        let report = crate::sanitizer::SanitizerReport {
            sanitizer: Some(crate::sanitizer::Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            stack: Vec::new(),
            message: "heap-buffer-overflow".to_owned(),
            ..Default::default()
        };
        let id = emitter
            .emit_sanitizer_crash_with_log(b"in", &report, Some(b"full log"))
            .unwrap();
        let dir = crate::layout::finding_dir(&root, &id.0);
        assert_eq!(fs::read(dir.join("sanitizer.log")).unwrap(), b"full log");
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(raw["paths"]["sanitizer_log"], "sanitizer.log");
    }

    #[test]
    fn build_binary_identity_lands_in_record() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let emitter = FindingEmitter::new(root.clone())
            .with_build_binary(serde_json::json!({"sha256": "ab", "build_id": "cd"}));
        let report = crate::sanitizer::SanitizerReport {
            sanitizer: Some(crate::sanitizer::Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            stack: Vec::new(),
            message: "m".to_owned(),
            ..Default::default()
        };
        let id = emitter.emit_sanitizer_crash(b"in", &report).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(
            &std::fs::read(crate::layout::finding_dir(&root, &id.0).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(raw["build"]["binary"]["build_id"], "cd");
    }

    #[test]
    fn touch_last_seen_updates_and_records_history() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("finding.json"),
            r#"{"id":"F-1","created_at":"2020-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        super::touch_last_seen(tmp.path(), "replay").unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.path().join("finding.json")).unwrap())
                .unwrap();
        assert!(raw["last_seen"].as_str().unwrap() > "2020-01-01T00:00:00Z");
        assert_eq!(raw["history"][0]["fields"][0], "last_seen");
        assert_eq!(raw["created_at"], "2020-01-01T00:00:00Z");
    }

    #[test]
    fn touch_last_seen_does_not_grow_history_across_replays() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("finding.json");
        std::fs::write(&path, r#"{"id":"F-1"}"#).unwrap();
        super::touch_last_seen(tmp.path(), "replay").unwrap();
        super::touch_last_seen(tmp.path(), "replay").unwrap();
        super::touch_last_seen(tmp.path(), "replay").unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        // Three replays leave one trailing last_seen entry, not three.
        assert_eq!(
            raw["history"].as_array().unwrap().len(),
            1,
            "repeated replays must not grow history: {}",
            raw["history"]
        );
        assert_eq!(raw["history"][0]["command"], "replay");
        assert!(raw["last_seen"].as_str().is_some());
    }

    #[test]
    fn dedupe_keys_lists_the_run_key_and_the_signature() {
        use super::dedupe_keys;
        use serde_json::json;
        assert_eq!(
            dedupe_keys(&json!({"cluster_key_full": "deadbeef", "signature": "abc123"})),
            ["deadbeef", "signature:abc123"]
        );
        assert_eq!(
            dedupe_keys(&json!({"rule_id": "R", "oracle": {"name": "n", "api": "a"}})),
            ["R|n|a"]
        );
        assert_eq!(
            dedupe_keys(&json!({"signature": "abc123"})),
            ["signature:abc123"]
        );
        assert!(dedupe_keys(&json!({"id": "F-0000-x", "signature": ""})).is_empty());
        assert!(dedupe_keys(&json!("not an object")).is_empty());
    }

    fn emit_parsed(root: &std::path::Path, stderr: &str) -> serde_json::Value {
        let report = crate::sanitizer::parse_sanitizer_report(stderr).expect("a report");
        let emitter = super::FindingEmitter::with_metadata(
            root.to_path_buf(),
            "H-C0001".to_owned(),
            "c".to_owned(),
            String::new(),
        );
        let id = emitter
            .emit_sanitizer_crash_with_log(b"in", &report, Some(stderr.as_bytes()))
            .unwrap();
        serde_json::from_slice(
            &fs::read(crate::layout::finding_dir(root, &id.0).join("finding.json")).unwrap(),
        )
        .unwrap()
    }

    fn frameless_missing_return(file: &str, line: u32) -> String {
        format!(
            "{file}:{line}:5: runtime error: execution reached the end of a value-returning function without returning a value\n\
             SUMMARY: UndefinedBehaviorSanitizer: missing-return {file}:{line}:5 \n"
        )
    }

    /// A UBSan report printed without a stack used to hash only `rule|kind`, so
    /// every such finding in every project shared one ID suffix, one root-cause
    /// group and one per-run dedupe key.
    #[test]
    fn frameless_ubsan_findings_at_distinct_sites_get_distinct_ids_and_keys() {
        let root = temp_dir("frameless-sites");
        let a = emit_parsed(&root, &frameless_missing_return("/src/widget/a.c", 3));
        let b = emit_parsed(&root, &frameless_missing_return("/src/widget/a.c", 9));
        let c = emit_parsed(&root, &frameless_missing_return("/src/widget/b.c", 3));
        let suffix = |v: &serde_json::Value| v["id"].as_str().unwrap()[7..].to_owned();
        for (x, y) in [(&a, &b), (&a, &c), (&b, &c)] {
            assert_ne!(x["signature"], y["signature"]);
            assert_ne!(
                suffix(x),
                suffix(y),
                "distinct UB sites get distinct ID suffixes"
            );
            assert_ne!(x["cluster_key_full"], y["cluster_key_full"]);
            assert_ne!(super::run_dedupe_key(x), super::run_dedupe_key(y));
        }
        assert_eq!(
            a["cluster_fallback"], false,
            "a reported site is an identity"
        );
        assert!(!format!("{:?}", super::run_dedupe_key(&a)).contains("rule:"));
    }

    /// Two files that share a name in different directories are different
    /// sites, while the same file stays one site wherever the tree is checked
    /// out and whether the compiler got a relative or an absolute path.
    #[test]
    fn same_named_files_in_different_directories_are_different_sites() {
        let root = temp_dir("same-basename-sites");
        let a = emit_parsed(&root, &frameless_missing_return("/src/a/util.c", 3));
        let b = emit_parsed(&root, &frameless_missing_return("/src/b/util.c", 3));
        assert_ne!(a["signature"], b["signature"]);
        assert_ne!(a["cluster_key_full"], b["cluster_key_full"]);
        assert_ne!(super::run_dedupe_key(&a), super::run_dedupe_key(&b));

        for elsewhere in [
            "/home/dev/checkout/src/a/util.c",
            "src/a/util.c",
            "./a/util.c",
        ] {
            let moved = emit_parsed(&root, &frameless_missing_return(elsewhere, 3));
            assert_eq!(moved["signature"], a["signature"], "{elsewhere}");
            assert_eq!(
                moved["cluster_key_full"], a["cluster_key_full"],
                "{elsewhere}"
            );
        }

        // A bare file name (the compiler ran in the file's directory) takes the
        // directory from the crash frame that names the same file.
        let with_frame = |reported: &str, frame_file: &str| {
            let stderr = format!(
                "{reported}:3:5: runtime error: shift exponent 40 is too large for 32-bit type 'int'\n    \
                 #0 0x1 in copy_at {frame_file}:3:5\n\n\
                 SUMMARY: UndefinedBehaviorSanitizer: invalid-shift-exponent {reported}:3:5 \n"
            );
            let report = crate::sanitizer::parse_sanitizer_report(&stderr).unwrap();
            (
                super::sanitizer_signature(&report),
                super::sanitizer_dedupe_key(&report),
            )
        };
        let bare_a = with_frame("util.c", "/w/src/a/util.c");
        let bare_b = with_frame("util.c", "/w/src/b/util.c");
        assert_ne!(bare_a.0, bare_b.0);
        assert_ne!(bare_a.1, bare_b.1);
        assert_eq!(bare_a, with_frame("/w/src/a/util.c", "/w/src/a/util.c"));
    }

    /// The per-run dedupe key rebuilt from a written finding is exactly the key
    /// the fuzz loop computes for the report, so a later pass that re-seeds its
    /// dedup set from disk recognizes the same crash and only that crash.
    #[test]
    fn run_dedupe_key_of_the_record_matches_the_reports_runtime_key() {
        let root = temp_dir("dedupe-roundtrip");
        for stderr in [
            frameless_missing_return("/src/widget/a.c", 3),
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n\
             READ of size 1 at 0x1 thread T0\n    #0 0x1 in copy_at /src/widget/copy.c:9:41\n"
                .to_owned(),
            "==1==ERROR: AddressSanitizer: SEGV on unknown address (pc 0x1 bp 0x2 sp 0x3 T0)\n"
                .to_owned(),
        ] {
            let report = crate::sanitizer::parse_sanitizer_report(&stderr).unwrap();
            let record = emit_parsed(&root, &stderr);
            // The fuzz loop keys a crash in the scope of the harness that
            // found it, as the emitter does.
            assert_eq!(
                super::run_dedupe_key(&record),
                Some(super::RunDedupeKey::Cluster(
                    super::sanitizer_dedupe_key_scoped(&report, "H-C0001")
                )),
                "{stderr}"
            );
        }
    }

    /// A crash with no frames and no source position (a fatal signal without a
    /// sanitizer report) is grouped per harness: two harnesses' crashes are two
    /// root-cause groups, and a later pass of the same harness keys it the way
    /// the fuzz loop does. The faulting pc offset the driver printed is
    /// recorded and separates two crash sites of one harness.
    #[test]
    fn frameless_crashes_are_grouped_per_harness_and_per_pc() {
        let root = temp_dir("frameless-scope");
        let signal = |pc_offset: Option<u64>| crate::sanitizer::SanitizerReport {
            sanitizer: None,
            kind: "fatal-signal".to_owned(),
            rule_id: "BHF-210",
            message: "harness crashed with SIGSEGV and no sanitizer report".to_owned(),
            pc_offset,
            ..Default::default()
        };
        let emit = |harness_id: &str, report: &crate::sanitizer::SanitizerReport| {
            let emitter = FindingEmitter::with_metadata(
                root.clone(),
                harness_id.to_owned(),
                "c".to_owned(),
                format!("harnesses/{harness_id}/main"),
            );
            let id = emitter.emit_sanitizer_crash(b"x", report).unwrap();
            let raw: serde_json::Value = serde_json::from_slice(
                &fs::read(crate::layout::finding_dir(&root, &id.0).join("finding.json")).unwrap(),
            )
            .unwrap();
            raw
        };
        let parse = emit("H-PARSE", &signal(None));
        let copy = emit("H-COPY", &signal(None));
        assert_ne!(parse["cluster_key_full"], copy["cluster_key_full"]);
        assert_eq!(parse["cluster_fallback"], true);
        assert_eq!(
            super::run_dedupe_key(&parse),
            Some(super::RunDedupeKey::Cluster(
                super::sanitizer_dedupe_key_scoped(&signal(None), "H-PARSE")
            ))
        );
        let mut abort = signal(None);
        abort.check = Some("SIGABRT".to_owned());
        assert_eq!(emit("H-PARSE", &abort)["exception"]["signal"], "SIGABRT");
        assert!(parse["exception"].get("signal").is_none());
        let at = |pc| emit("H-PARSE", &signal(Some(pc)));
        let (a, b) = (at(0x1b3c), at(0x2a10));
        assert_eq!(a["exception"]["pc_offset"], "0x1b3c");
        assert_ne!(a["cluster_key_full"], b["cluster_key_full"]);
        assert_ne!(a["signature"], b["signature"]);
        assert_ne!(a["cluster_key_full"], parse["cluster_key_full"]);
    }

    /// Only the crash stack identifies a crash: the allocation and free stacks
    /// are evidence about the object, recorded separately and not hashed.
    #[test]
    fn allocation_and_free_frames_do_not_change_the_signature() {
        let root = temp_dir("alloc-not-hashed");
        let uaf = |freer: &str| {
            format!(
                "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x504000000054\n\
                 READ of size 4 at 0x504000000054 thread T0\n    \
                 #0 0x1 in Widget::parse_record() /src/widget/parser.cc:11:50\n\n\
                 0x504000000054 is located 4 bytes inside of 40-byte region [0x504000000050,0x504000000078)\n\
                 freed by thread T0 here:\n    #0 0x2 in free (/bin/h+0x2)\n    \
                 #1 0x3 in {freer} /src/widget/parser.cc:30:3\n\n\
                 previously allocated by thread T0 here:\n    #0 0x4 in malloc (/bin/h+0x4)\n    \
                 #1 0x5 in Widget::Widget() /src/widget/parser.cc:22:14\n"
            )
        };
        let a = emit_parsed(&root, &uaf("Widget::reset()"));
        let b = emit_parsed(&root, &uaf("Widget::clear()"));
        assert_eq!(a["signature"], b["signature"]);
        let names = |v: &serde_json::Value, path: &str| -> Vec<String> {
            v.pointer(path)
                .and_then(serde_json::Value::as_array)
                .unwrap()
                .iter()
                .map(|f| f["function"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(
            names(&a, "/exception/stack"),
            vec!["Widget::parse_record()"]
        );
        assert_eq!(
            names(&a, "/exception/access/free_stack"),
            vec!["free", "Widget::reset()"]
        );
        assert_eq!(
            names(&a, "/exception/access/alloc_stack"),
            vec!["malloc", "Widget::Widget()"]
        );
    }

    #[test]
    fn finding_record_carries_structured_access_location_and_check() {
        let root = temp_dir("structured-access");
        let heap = emit_parsed(
            &root,
            "==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000015 at pc 0x5 bp 0x6 sp 0x7\n\
             READ of size 4 at 0x502000000015 thread T0\n    \
             #0 0x1 in copy_at /src/widget/copy.c:9:41\n\n\
             0x502000000015 is located 0 bytes after 1-byte region [0x502000000014,0x502000000015)\n\
             allocated by thread T0 here:\n    #0 0x2 in malloc (/bin/h+0x2)\n    \
             #1 0x3 in bhf_c_string /work/harnesses/H-1/bhf_decode.h:195:23\n\n\
             SUMMARY: AddressSanitizer: heap-buffer-overflow /src/widget/copy.c:9:41 in copy_at\n",
        );
        let access = &heap["exception"]["access"];
        assert_eq!(access["direction"], "read");
        assert_eq!(access["size"], 4);
        assert_eq!(access["region"]["kind"], "heap");
        assert_eq!(access["region"]["size"], 1);
        assert_eq!(access["region"]["offset"], 1);
        assert_eq!(access["region"]["relation"], "after");
        assert_eq!(access["alloc_stack"][1]["function"], "bhf_c_string");
        assert_eq!(heap["exception"]["location"]["line"], 9);

        let ub = emit_parsed(&root, &frameless_missing_return("/src/widget/a.c", 3));
        assert_eq!(ub["exception"]["check"], "missing-return");
        assert_eq!(ub["exception"]["location"]["file"], "/src/widget/a.c");
        assert_eq!(ub["exception"]["location"]["column"], 5);
        assert!(ub["exception"].get("access").is_none());
    }
}
