// SPDX-License-Identifier: Apache-2.0
//! Producer records -> `bhf.findings.v1` findings. One function per source:
//! `finding.json` (via `report::FindingReport`), static-scan JSON, SBOM matches.

use crate::confirmation::{self, ConfirmationInput};
use crate::model::{
    BinaryBlock, BuildInfo, Component, Confidence, Confirmation, ConfirmationLevel, Evidence,
    EvidenceFile, ExceptionInfo, Fidelity, Finding, Fingerprint, Frame, FuzzBlock, Kind, Location,
    PatchHint, Reproduce, RuleRef, ScaBlock, StaticBlock, TraceStep,
};
use crate::severity;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

pub struct NormalizeContext<'a> {
    /// Absolute scanned source root, for repo-relative paths.
    pub source_root: Option<&'a Path>,
    /// `<work>/results`, to locate evidence files.
    pub results_dir: &'a Path,
}

const MAX_STACK: usize = 32;
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
const TITLE_MAX: usize = 160;

/// Evidence files we surface, in display order: (role, file name).
const EVIDENCE_FILES: [(&str, &str); 8] = [
    ("finding", "finding.json"),
    ("testcase", "testcase.bin"),
    ("testcase_minimized", "min_testcase.bin"),
    ("sanitizer_log", "sanitizer.log"),
    ("decoded", "decoded.json"),
    ("replay_script", "replay.py"),
    ("repro_ada", "repro.adb"),
    ("byte_control", "byte-control.json"),
];

pub fn kind_for(id: &str, raw: &Value) -> Kind {
    if let Some(kind) = raw
        .get("finding_kind")
        .and_then(Value::as_str)
        .and_then(Kind::parse)
    {
        return kind;
    }
    const RUNTIME: [&str; 5] = ["F-MSAN-", "F-TSAN-", "F-MEM-", "F-JSINK-", "F-CAP-"];
    const STATIC: [&str; 3] = ["F-STATIC-", "F-RO-", "F-EXT-"];
    if id.starts_with("F-DIFF-") {
        Kind::Differential
    } else if id.starts_with("F-SCA-") {
        Kind::Sca
    } else if id.starts_with("BF-") {
        Kind::Binary
    } else if id.starts_with("S-") || STATIC.iter().any(|p| id.starts_with(p)) {
        Kind::Static
    } else if RUNTIME.iter().any(|p| id.starts_with(p)) {
        Kind::Runtime
    } else {
        Kind::Fuzz
    }
}

pub fn producer_for(kind: Kind, id: &str) -> &'static str {
    match kind {
        Kind::Fuzz => "fuzz",
        Kind::Runtime => "auto",
        Kind::Static if id.starts_with("S-") => "static-scan",
        Kind::Static => "auto",
        Kind::Binary => "binary fuzz",
        Kind::Differential => "differential",
        Kind::Sca => "sbom",
    }
}

/// One loaded `finding.json`. Errors (as a reason for the index's
/// `errors[]`) when the record cannot be a finding directory: an invalid id,
/// or an SCA kind, since SCA findings exist only as SBOM matches.
pub fn from_finding_report(
    f: &report::FindingReport,
    ctx: &NormalizeContext<'_>,
) -> Result<Finding, String> {
    let raw = &f.raw;
    if !corpus::layout::is_valid_finding_id(&f.id) {
        return Err(format!("{:?} is not a valid finding id", f.id));
    }
    let kind = kind_for(&f.id, raw);
    if kind == Kind::Sca {
        return Err(format!(
            "{}: sca findings come only from sbom/vulnerabilities.json",
            f.id
        ));
    }
    let a = &f.actionability;
    let forced = raw.get("forced").and_then(Value::as_bool).unwrap_or(false);
    let rule = rule_ref(f.rule_id.as_deref());

    let exception = ExceptionInfo {
        name: str_at(&f.exception, &["name"])
            .or_else(|| str_at(&f.exception, &["exception_name"]))
            .or_else(|| str_at(&f.exception, &["handler", "exception_name"])),
        message: str_at(&f.exception, &["message"]).map(|m| strip_addresses(&m)),
        sanitizer: str_at(&f.exception, &["sanitizer"]),
    };
    let message = exception
        .message
        .clone()
        .or_else(|| str_at(raw, &["oracle", "message"]).map(|m| strip_addresses(&m)))
        .or_else(|| str_at(raw, &["message"]).map(|m| strip_addresses(&m)))
        .or_else(|| a.explanation.clone())
        .unwrap_or_default();

    let location =
        sink_location(a, ctx.source_root).or_else(|| record_location(raw, ctx.source_root));
    let fix_location = a
        .fix_location
        .as_ref()
        .filter(|fix| !fix.path.trim().is_empty())
        .map(|fix| Location {
            file: relativize(&fix.path, ctx.source_root),
            line: fix.line.filter(|l| *l > 0),
            column: fix.col.filter(|c| *c > 0),
            function: None,
        });

    let level = confirmation::level(&ConfirmationInput {
        kind,
        classification: f.classification.as_deref(),
        confirmation: str_at(raw, &["confirmation"]).as_deref(),
        sanitizer: exception.sanitizer.as_deref(),
        stubs_used: a.prosthetics.used || forced,
        confidence: Some(a.confidence.as_str()),
    });

    let mut caveats = Vec::new();
    for key in ["fidelity_caveat", "forced_note"] {
        if let Some(text) = str_at(raw, &[key]) {
            caveats.push(text);
        }
    }
    if str_at(raw, &["minimization_skipped"]).as_deref() == Some("time_budget") {
        caveats.push(crate::UNMINIMIZED_CAVEAT.to_owned());
    }

    // A binary crash keeps its signature under `crash` (exit/signal + stderr
    // digest); it is the only per-crash identity such a record has.
    let signature = f
        .signature
        .clone()
        .or_else(|| str_at(raw, &["crash", "signature"]));
    let created_at = timestamp_at(raw, "created_at");
    let primary = stable_primary(
        kind,
        f,
        signature.as_deref(),
        location.as_ref(),
        exception.name.as_deref(),
    );
    let title = title_for(
        &message,
        a.cwe_name.as_deref().or(rule.name.as_deref()),
        exception.name.as_deref(),
        location.as_ref(),
        &f.id,
    );
    // The key persisted at emit first (see `persisted_cluster_key_full`),
    // then the loader's. The confirm pass also writes a crash's cluster key
    // onto the static rows it confirms, without frames. Never the run-local
    // id: a finding with no cluster is its own group.
    let group = persisted_cluster_key_full(f)
        .or_else(|| str_at(raw, &["cluster_key"]))
        .or_else(|| f.cluster_key.clone())
        .unwrap_or_else(|| primary.clone());
    let finding_dir = ctx.results_dir.join("findings").join(&f.id);
    let evidence = evidence_for(&finding_dir, &f.id);
    let has_replay = evidence
        .as_ref()
        .is_some_and(|e| e.files.iter().any(|file| file.role == "replay_script"));
    let dynamic = matches!(
        kind,
        Kind::Fuzz | Kind::Runtime | Kind::Differential | Kind::Binary
    );
    let binary_sha256 = sha256_at(raw, &["build", "binary", "sha256"])
        .or_else(|| sha256_at(raw, &["binary", "sha256"]));
    let build_id = str_at(raw, &["build", "binary", "build_id"]).filter(|id| is_lower_hex(id));

    let mut finding = Finding {
        id: f.id.clone(),
        kind,
        producer: producer_for(kind, &f.id).to_owned(),
        severity: severity::resolve(
            Some(a.impact.as_str()),
            raw.get("severity").and_then(Value::as_str),
            f.rule_id.as_deref(),
            forced,
        ),
        rule,
        title,
        message,
        explanation: a.explanation.clone(),
        impact: Some(a.impact.as_str().to_owned()),
        confidence: Confidence {
            level: if forced {
                "low".to_owned()
            } else {
                a.confidence.as_str().to_owned()
            },
            score: confidence_score(&f.confidence),
        },
        cwe: parse_cwes(a.cwe.iter().map(String::as_str)),
        confirmation: Confirmation {
            level,
            detail: str_at(raw, &["confirmation"]),
        },
        verdict: Some(a.verdict.as_str().to_owned()),
        location,
        fix_location,
        stack: project_frames(&f.exception, ctx.source_root),
        trace: Vec::new(),
        fingerprint: Fingerprint { primary, signature },
        group: Some(group),
        occurrences: 1,
        first_seen: created_at.clone(),
        last_seen: timestamp_at(raw, "last_seen").or(created_at),
        reachability: a
            .entry_path
            .as_ref()
            .and_then(|entry| serde_json::to_value(entry).ok()),
        fidelity: Fidelity {
            stubs_used: a.prosthetics.used,
            forced,
            caveats,
        },
        remediation: str_at(raw, &["remediation"])
            .or_else(|| a.patch_hints.first().map(|hint| hint.guidance.clone())),
        patch_hints: a
            .patch_hints
            .iter()
            .map(|hint| PatchHint {
                title: hint.title.clone(),
                guidance: hint.guidance.clone(),
            })
            .collect(),
        reproduce: dynamic.then(|| Reproduce {
            harness_id: str_at(raw, &["harness_id"]),
            // Only commands bhf builds: record text (`triage.replay`) may come
            // from an imported directory.
            command: has_replay.then(|| format!("python3 findings/{}/replay.py", f.id)),
            build: BuildInfo {
                sanitizers: sanitizers(raw, exception.sanitizer.as_deref()),
                binary_sha256: binary_sha256.clone(),
                build_id: build_id.clone(),
            },
        }),
        evidence,
        fuzz: matches!(kind, Kind::Fuzz | Kind::Runtime | Kind::Differential).then(|| FuzzBlock {
            exception: exception.clone(),
            classification: f.classification.clone(),
            harness_id: str_at(raw, &["harness_id"]),
            dialect: str_at(raw, &["dialect"]),
            oracle: raw.get("oracle").filter(|v| v.is_object()).cloned(),
        }),
        static_: (kind == Kind::Static).then(|| StaticBlock {
            engine: str_at(raw, &["analysis", "engine"]).or_else(|| Some("bhf-static".to_owned())),
            precision: None,
            snippet: None,
            baseline_status: None,
            triage_state: None,
        }),
        sca: None,
        binary: (kind == Kind::Binary).then(|| BinaryBlock {
            sha256: binary_sha256,
            build_id,
            arch: None,
            crash: raw.get("crash").filter(|v| v.is_object()).cloned(),
        }),
        raw_ref: Some(format!("findings/{}/finding.json", f.id)),
    };
    strip_root_in_text(&mut finding, ctx.source_root);
    debug_assert_kind_block(&finding);
    Ok(finding)
}

fn sink_location(a: &actionability::ActionabilityRecord, root: Option<&Path>) -> Option<Location> {
    let sink = a.sink.as_ref()?;
    let file = sink.file.as_deref().filter(|f| !f.trim().is_empty())?;
    Some(Location {
        file: relativize(file, root),
        line: sink.line.filter(|l| *l > 0),
        column: None,
        function: non_empty(&sink.function),
    })
}

/// Location for records without a sink (auto static rows, some oracle and
/// capability records): the `source` oracle evidence (`file:line:function`),
/// then `target.location`, then `target.source_path`/`target.line`, then the
/// exception's `source_file`/`source_line`.
fn record_location(raw: &Value, root: Option<&Path>) -> Option<Location> {
    let line_of = |v: Option<&Value>| -> Option<u64> {
        let v = v?;
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            .filter(|l| *l > 0)
    };
    let evidence = raw
        .pointer("/oracle/evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|e| e.get("key").and_then(Value::as_str) == Some("source"))
        .and_then(|e| e.get("value").and_then(Value::as_str));
    if let Some((file, line, function)) = evidence.and_then(split_source_evidence) {
        return Some(Location {
            file: relativize(file, root),
            line: Some(line).filter(|l| *l > 0),
            column: None,
            function,
        });
    }
    if let Some(path) = str_at(raw, &["target", "location", "path"])
        .or_else(|| str_at(raw, &["target", "source_path"]))
    {
        return Some(Location {
            file: relativize(&path, root),
            line: line_of(raw.pointer("/target/location/line"))
                .or_else(|| line_of(raw.pointer("/target/line"))),
            column: None,
            function: None,
        });
    }
    let file = str_at(raw, &["exception", "source_file"])?;
    Some(Location {
        file: relativize(&file, root),
        line: line_of(raw.pointer("/exception/source_line")),
        column: None,
        function: None,
    })
}

/// `file:line[:function]`, split the way the actionability layer splits it:
/// the first all-digit segment is the line, so a `C:` drive prefix stays in
/// the file and a `ns::fn` function keeps its `::`.
fn split_source_evidence(text: &str) -> Option<(&str, u64, Option<String>)> {
    let mut offset = 0;
    for part in text.split(':') {
        if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) {
            let file = text[..offset].strip_suffix(':')?.trim();
            let line = part.parse().ok()?;
            let rest = text[offset + part.len()..].strip_prefix(':').unwrap_or("");
            return (!file.is_empty()).then(|| (file, line, non_empty(rest)));
        }
        offset += part.len() + 1;
    }
    None
}

/// The record's own `cluster_key_full`, else the loader's. The persisted value
/// is what the emitter wrote and what importers already key on; the loader
/// recomputes from the stack when `cluster_normalized_frames` is absent, and
/// that recompute drifts whenever the clustering algorithm changes.
fn persisted_cluster_key_full(f: &report::FindingReport) -> Option<String> {
    str_at(&f.raw, &["cluster_key_full"]).or_else(|| f.cluster_key_full.clone())
}

/// Cross-run identity. Static: the static fingerprint, else `rule:file:line`.
/// Binary: `rule:<binary file name>:<crash signature>`. Other dynamic kinds:
/// `cluster_key_full` (persisted, then recomputed), else `signature`, else the
/// `rule:exception:file:line:function` composite. The run-local id only when
/// there is no rule or no file.
fn stable_primary(
    kind: Kind,
    f: &report::FindingReport,
    signature: Option<&str>,
    location: Option<&Location>,
    exception_name: Option<&str>,
) -> String {
    let file = location.map(|l| l.file.clone());
    let line = location.and_then(|l| l.line).map(|l| l.to_string());
    let composite = |parts: Vec<Option<String>>| -> Option<String> {
        (f.rule_id.is_some() && file.is_some())
            .then(|| parts.into_iter().flatten().collect::<Vec<_>>().join(":"))
    };
    let found = if kind == Kind::Static {
        str_at(&f.raw, &["static_fingerprint"])
            .or_else(|| composite(vec![f.rule_id.clone(), file.clone(), line.clone()]))
    } else if let Some(crash) = (kind == Kind::Binary)
        .then(|| str_at(&f.raw, &["crash", "signature"]))
        .flatten()
    {
        // A crash signature only means something for the binary that
        // produced it.
        let binary = str_at(&f.raw, &["binary", "path"])
            .and_then(|path| {
                path.rsplit(['/', '\\'])
                    .next()
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "binary".to_owned());
        Some(
            [f.rule_id.clone(), Some(binary), Some(crash)]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(":"),
        )
    } else {
        persisted_cluster_key_full(f)
            .or_else(|| signature.map(str::to_owned))
            .or_else(|| {
                composite(vec![
                    f.rule_id.clone(),
                    exception_name.map(str::to_owned),
                    file.clone(),
                    line.clone(),
                    location.and_then(|l| l.function.clone()),
                ])
            })
    };
    found.unwrap_or_else(|| f.id.clone())
}

/// The schema ties each `kind` to its block: `fuzz` for fuzz/runtime/
/// differential, `static`, `sca` and `binary` for theirs.
fn kind_block_present(finding: &Finding) -> bool {
    match finding.kind {
        Kind::Fuzz | Kind::Runtime | Kind::Differential => finding.fuzz.is_some(),
        Kind::Static => finding.static_.is_some(),
        Kind::Sca => finding.sca.is_some(),
        Kind::Binary => finding.binary.is_some(),
    }
}

fn debug_assert_kind_block(finding: &Finding) {
    debug_assert!(
        kind_block_present(finding),
        "{} ({:?}) lacks its kind block",
        finding.id,
        finding.kind
    );
}

pub(crate) fn rule_ref(rule_id: Option<&str>) -> RuleRef {
    let rule = rule_id.and_then(finding_rules::by_id);
    RuleRef {
        id: rule_id.map(str::to_owned),
        slug: rule.map(|r| r.slug.to_owned()),
        name: rule.map(|r| r.name.to_owned()),
    }
}

pub(crate) fn str_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut cur = value;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// An RFC 3339 timestamp at `key`, as written; anything else is dropped.
fn timestamp_at(raw: &Value, key: &str) -> Option<String> {
    str_at(raw, &[key]).filter(|ts| chrono::DateTime::parse_from_rfc3339(ts).is_ok())
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A lowercase hex SHA-256 at `path`; anything else is dropped, never
/// passed through as a digest.
fn sha256_at(value: &Value, path: &[&str]) -> Option<String> {
    str_at(value, path).filter(|digest| digest.len() == 64 && is_lower_hex(digest))
}

/// Repo-relative POSIX path when `path` is under `root`; unchanged otherwise.
pub(crate) fn relativize(path: &str, root: Option<&Path>) -> String {
    let normalized = path.replace('\\', "/");
    if let Some(root) = root {
        let root = root.to_string_lossy().replace('\\', "/");
        let root = root.trim_end_matches('/');
        if let Some(rest) = normalized.strip_prefix(root) {
            // `rest` must start at a separator (`/src/demo2` is not under
            // `/src/demo`), and the root itself is not a relative path.
            let rel = rest.trim_start_matches('/');
            if rest.starts_with('/') && !rel.is_empty() {
                return rel.to_owned();
            }
        }
    }
    normalized
}

/// Drop every `<root>/` (or `<root>\\`) that starts a path in free text, so
/// prose names repo-relative paths only. A match must begin at a path
/// boundary (`/opt/src/demo/a.c` is not under `/src/demo`) and must be
/// followed by a separator (`/src/demo2` is not either). Both separator
/// spellings of the root are matched; an empty or `/` root strips nothing.
pub(crate) fn strip_root(text: &str, root: Option<&Path>) -> String {
    let Some(root) = root else {
        return text.to_owned();
    };
    let root = root.to_string_lossy();
    let root = root.trim_end_matches(['/', '\\']);
    if root.is_empty() {
        return text.to_owned();
    }
    let mut needles: Vec<String> = Vec::new();
    for spelling in [
        root.to_owned(),
        root.replace('\\', "/"),
        root.replace('/', "\\"),
    ] {
        for separator in ['/', '\\'] {
            let needle = format!("{spelling}{separator}");
            if !needles.contains(&needle) {
                needles.push(needle);
            }
        }
    }
    let in_path = |c: char| c.is_alphanumeric() || matches!(c, '/' | '\\' | '.' | '_' | '-' | '~');
    let mut out = String::with_capacity(text.len());
    let mut prev: Option<char> = None;
    let mut at = 0;
    while let Some(c) = text[at..].chars().next() {
        if !prev.is_some_and(in_path) {
            if let Some(needle) = needles.iter().find(|n| text[at..].starts_with(n.as_str())) {
                at += needle.len();
                prev = needle.chars().next_back();
                continue;
            }
        }
        out.push(c);
        prev = Some(c);
        at += c.len_utf8();
    }
    out
}

/// [`strip_root`] over every string in `value`, recursively; object keys are
/// left alone.
pub(crate) fn strip_root_in_value(value: &mut Value, root: Option<&Path>) {
    if root.is_none() {
        return;
    }
    match value {
        Value::String(text) => *text = strip_root(text, root),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| strip_root_in_value(item, root)),
        Value::Object(map) => map
            .values_mut()
            .for_each(|item| strip_root_in_value(item, root)),
        _ => {}
    }
}

/// [`strip_root`] over a finding's free text: title, message, explanation,
/// remediation, patch-hint guidance and the exception message.
fn strip_root_in_text(finding: &mut Finding, root: Option<&Path>) {
    if root.is_none() {
        return;
    }
    let strip = |text: &mut String| *text = strip_root(text, root);
    strip(&mut finding.title);
    strip(&mut finding.message);
    for text in [&mut finding.explanation, &mut finding.remediation]
        .into_iter()
        .flatten()
    {
        strip(text);
    }
    for hint in &mut finding.patch_hints {
        strip(&mut hint.guidance);
    }
    if let Some(message) = finding
        .fuzz
        .as_mut()
        .and_then(|fuzz| fuzz.exception.message.as_mut())
    {
        strip(message);
    }
}

/// `C:/…`: absolute on Windows even though it has no leading `/`.
fn is_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

/// Frames from code under the source root (or, with no root, frames that are
/// not toolchain/runtime/harness code), capped at [`MAX_STACK`].
fn project_frames(exception: &Value, root: Option<&Path>) -> Vec<Frame> {
    const NOISE: [&str; 6] = [
        "compiler-rt",
        "sanitizer_common",
        "libfuzzer",
        "/harnesses/",
        "generated_harnesses/",
        "/usr/",
    ];
    exception
        .get("stack")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|frame| {
            let file = frame.get("file").and_then(Value::as_str)?;
            let rel = relativize(file, root);
            let lower = rel.to_ascii_lowercase();
            if NOISE.iter().any(|n| lower.contains(n)) {
                return None;
            }
            if root.is_some()
                && (rel.starts_with('/') || rel.starts_with("..") || is_drive_path(&rel))
            {
                return None;
            }
            Some(Frame {
                function: frame
                    .get("function")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                file: Some(rel),
                line: frame.get("line").and_then(Value::as_u64).filter(|l| *l > 0),
            })
        })
        .take(MAX_STACK)
        .collect()
}

/// Replace hex literals of 6+ digits (heap/stack addresses) with `0x…`.
pub(crate) fn strip_addresses(text: &str) -> String {
    strip_hex_literals(text, false)
}

/// Replace hex literals of 6+ digits (absolute pc/heap/stack addresses) with
/// `0x…`, but keep one written right after `+`: a module offset such as
/// `(/bin/target+0x1a2b3c)` is stable across runs, and in a stripped binary
/// it is the only crash-site identity.
pub fn strip_addresses_keep_offsets(text: &str) -> String {
    strip_hex_literals(text, true)
}

fn strip_hex_literals(text: &str, keep_offsets: bool) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let is_offset = keep_offsets && i > 0 && bytes[i - 1] == b'+';
        if !is_offset && bytes[i] == b'0' && i + 1 < bytes.len() && (bytes[i + 1] | 0x20) == b'x' {
            let digits = bytes[i + 2..]
                .iter()
                .take_while(|b| b.is_ascii_hexdigit())
                .count();
            if digits >= 6 {
                out.push_str("0x…");
                i += 2 + digits;
                continue;
            }
        }
        let ch = text[i..].chars().next().expect("in bounds");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// `CWE-120` / `120` strings -> integers; CWE-20 only if nothing parses
/// (the report layer already guarantees a CWE, and the schema requires one).
pub(crate) fn parse_cwes<'a>(values: impl Iterator<Item = &'a str>) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    for value in values {
        let digits = value
            .trim()
            .trim_start_matches("CWE-")
            .trim_start_matches("cwe-");
        if let Ok(id) = digits.parse::<u32>() {
            if id > 0 && !out.contains(&id) {
                out.push(id);
            }
        }
    }
    if out.is_empty() {
        out.push(20);
    }
    out
}

fn confidence_score(confidence: &Value) -> Option<f64> {
    confidence
        .get("blend")
        .or_else(|| confidence.get("calibrated"))
        .and_then(Value::as_f64)
        .filter(|s| (0.0..=1.0).contains(s))
}

fn sanitizers(raw: &Value, exception_sanitizer: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = raw
        .pointer("/build/sanitizers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    if let Some(s) = exception_sanitizer {
        if !out.iter().any(|x| x == s) {
            out.push(s.to_owned());
        }
    }
    out
}

/// Readable list title: the weakness name (CWE name or catalog rule name),
/// else the humanized exception (`ASAN_HEAP_BUFFER_OVERFLOW` -> `Heap Buffer
/// Overflow`), plus ` in <function>` (` (<function>)` when the name already
/// says " in "); only then the first message line.
fn title_for(
    message: &str,
    weakness_name: Option<&str>,
    exception_name: Option<&str>,
    location: Option<&Location>,
    id: &str,
) -> String {
    let base = weakness_name
        .map(str::to_owned)
        .or_else(|| exception_name.map(humanize_exception))
        .filter(|b| !b.is_empty());
    let function = location.and_then(|l| l.function.as_deref());
    if let Some(base) = base {
        return match function {
            Some(function) if contains_identifier(&base, function) => base,
            Some(function) if base.contains(" in ") => format!("{base} ({function})"),
            Some(function) => format!("{base} in {function}"),
            None => base,
        };
    }
    let first_line = message.lines().next().unwrap_or("").trim();
    if !first_line.is_empty() {
        truncate(first_line, TITLE_MAX)
    } else {
        id.to_owned()
    }
}

/// `ident` appears in `text` as a whole identifier, not inside a longer one.
fn contains_identifier(text: &str, ident: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    !ident.is_empty()
        && text.match_indices(ident).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let after = text[at + ident.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
}

fn humanize_exception(name: &str) -> String {
    const PREFIXES: [&str; 5] = ["ASAN_", "UBSAN_", "MSAN_", "TSAN_", "LSAN_"];
    let trimmed = PREFIXES
        .iter()
        .find_map(|p| name.strip_prefix(p))
        .unwrap_or(name);
    trimmed
        .split('_')
        .filter(|w| !w.is_empty())
        .map(|w| {
            if w.starts_with("SIG") {
                w.to_owned()
            } else {
                let lower = w.to_ascii_lowercase();
                let mut chars = lower.chars();
                chars
                    .next()
                    .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                    .unwrap_or_default()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

fn evidence_for(finding_dir: &Path, id: &str) -> Option<Evidence> {
    let files: Vec<EvidenceFile> = EVIDENCE_FILES
        .iter()
        .filter_map(|(role, name)| {
            let (file, size) = open_regular(&finding_dir.join(name))?;
            Some(EvidenceFile {
                role: (*role).to_owned(),
                path: format!("findings/{id}/{name}"),
                sha256: (size <= MAX_HASH_BYTES)
                    .then(|| sha256_bounded(file))
                    .flatten(),
                size,
            })
        })
        .collect();
    (!files.is_empty()).then(|| Evidence {
        dir: format!("findings/{id}"),
        files,
    })
}

/// A regular file and its size, opened once without following a symlink
/// (on unix, `O_NOFOLLOW`; a FIFO does not block the open). `None` for
/// anything else.
fn open_regular(path: &Path) -> Option<(std::fs::File, u64)> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .ok()?
    };
    #[cfg(not(unix))]
    let file = {
        if std::fs::symlink_metadata(path)
            .ok()?
            .file_type()
            .is_symlink()
        {
            return None;
        }
        std::fs::File::open(path).ok()?
    };
    let meta = file.metadata().ok()?;
    meta.is_file().then_some((file, meta.len()))
}

/// SHA-256 of a regular file at `path` (never through a symlink), or `None`
/// when it is missing, not regular, or larger than 64 MiB.
pub fn sha256_file(path: &Path) -> Option<String> {
    let (file, size) = open_regular(path)?;
    (size <= MAX_HASH_BYTES)
        .then(|| sha256_bounded(file))
        .flatten()
}

/// SHA-256 of a regular file at `path` (never through a symlink), whatever
/// its size, or `None` when it is missing or not regular. For attestation,
/// which must cover every file.
pub fn sha256_file_uncapped(path: &Path) -> Option<String> {
    let (file, _) = open_regular(path)?;
    sha256_reader(file).map(|(digest, _)| digest)
}

/// Hash at most [`MAX_HASH_BYTES`]; a file that grew past it is `None`.
fn sha256_bounded(file: std::fs::File) -> Option<String> {
    let (digest, total) = sha256_reader(file.take(MAX_HASH_BYTES + 1))?;
    (total <= MAX_HASH_BYTES).then_some(digest)
}

/// Stream `reader` to its end: the hex digest and the bytes read.
fn sha256_reader(mut reader: impl Read) -> Option<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buf[..n]);
    }
    Some((format!("{:x}", hasher.finalize()), total))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// `issue_key` per static finding id, from static-report.json `issues[]`.
pub fn static_issue_keys(report: &Value) -> HashMap<String, String> {
    let mut keys = HashMap::new();
    for issue in report
        .get("issues")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(key) = issue.get("issue_key").and_then(Value::as_str) else {
            continue;
        };
        for id in issue
            .get("finding_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = id.as_str() {
                keys.insert(id.to_owned(), key.to_owned());
            }
        }
    }
    keys
}

/// One `static-report.json` `findings[]` entry. `None` when it has no usable
/// id or location.
pub fn from_static_value(
    v: &Value,
    issue_key: Option<&str>,
    ctx: &NormalizeContext<'_>,
) -> Option<Finding> {
    let id = str_at(v, &["id"]).filter(|id| corpus::layout::is_valid_finding_id(id))?;
    let path = str_at(v, &["location", "path"])?;
    let rule_id = str_at(v, &["rule_id"]);
    let mut rule = rule_ref(rule_id.as_deref());
    rule.slug = rule.slug.or_else(|| str_at(v, &["rule_slug"]));
    let message = str_at(v, &["message"]).unwrap_or_default();
    let location = Location {
        file: relativize(&path, ctx.source_root),
        line: v
            .pointer("/location/line")
            .and_then(Value::as_u64)
            .filter(|l| *l > 0),
        column: v
            .pointer("/location/column")
            .and_then(Value::as_u64)
            .filter(|c| *c > 0),
        function: str_at(v, &["analysis", "enclosing_function"]),
    };
    let trace = v
        .pointer("/analysis/trace")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|step| {
            Some(TraceStep {
                file: relativize(step.get("path")?.as_str()?, ctx.source_root),
                line: step.get("line").and_then(Value::as_u64).filter(|l| *l > 0),
                function: str_at(step, &["callee"]).or_else(|| str_at(step, &["caller"])),
                note: str_at(step, &["kind"]),
            })
        })
        .collect();
    let primary = str_at(v, &["fingerprint"]).unwrap_or_else(|| id.clone());
    let snippet = v
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|e| str_at(e, &["snippet"]));
    // static-report.json writes the reachability tier as a bare string; the
    // contract field is an object.
    let reachability = match v.pointer("/analysis/reachability") {
        Some(Value::String(tier)) if !tier.trim().is_empty() => {
            Some(serde_json::json!({ "tier": tier.trim() }))
        }
        Some(object @ Value::Object(_)) => Some(object.clone()),
        _ => None,
    };
    let title = title_for(&message, rule.name.as_deref(), None, Some(&location), &id);
    let mut finding = Finding {
        producer: producer_for(Kind::Static, &id).to_owned(),
        kind: Kind::Static,
        severity: severity::resolve(
            None,
            str_at(v, &["severity"]).as_deref(),
            rule_id.as_deref(),
            false,
        ),
        rule,
        title,
        message,
        explanation: None,
        impact: None,
        confidence: Confidence {
            level: level_word(str_at(v, &["confidence"]).as_deref()),
            score: None,
        },
        cwe: parse_cwes(str_at(v, &["cwe"]).as_deref().into_iter()),
        confirmation: Confirmation {
            level: ConfirmationLevel::Static,
            detail: None,
        },
        verdict: None,
        location: Some(location),
        fix_location: None,
        stack: Vec::new(),
        trace,
        group: Some(issue_key.map_or_else(|| primary.clone(), str::to_owned)),
        fingerprint: Fingerprint {
            primary,
            signature: str_at(v, &["identity"]),
        },
        occurrences: 1,
        first_seen: None,
        last_seen: None,
        reachability,
        fidelity: Fidelity::default(),
        remediation: str_at(v, &["remediation"]),
        patch_hints: Vec::new(),
        reproduce: None,
        evidence: None,
        fuzz: None,
        static_: Some(StaticBlock {
            engine: str_at(v, &["analysis", "engine"]),
            precision: v.pointer("/analysis/precision").cloned(),
            snippet,
            baseline_status: str_at(v, &["baseline_status"]),
            triage_state: str_at(v, &["triage", "state"]),
        }),
        sca: None,
        binary: None,
        raw_ref: Some("static/static-report.json".to_owned()),
        id,
    };
    strip_root_in_text(&mut finding, ctx.source_root);
    debug_assert_kind_block(&finding);
    Some(finding)
}

/// One `sbom/vulnerabilities.json` match. Its id is derived from the
/// versionless identity, so a version bump keeps it. `None` when the match
/// names no advisory or component.
pub fn from_sca_value(m: &Value) -> Option<Finding> {
    let vuln_id = str_at(m, &["id"])?;
    let name = str_at(m, &["component", "name"])?;
    let version = str_at(m, &["component", "version"]);
    let ecosystem = str_at(m, &["component", "ecosystem"]);
    let purl = str_at(m, &["component", "purl"]);
    let package_key = purl
        .as_deref()
        .map(purl_without_version)
        .unwrap_or_else(|| format!("{}:{}", ecosystem.as_deref().unwrap_or("unknown"), name));
    let primary = format!("{vuln_id}|{package_key}");
    let id = format!("F-SCA-{}", &sha256_hex(primary.as_bytes())[..16]);
    let fixed_versions: Vec<String> = m
        .pointer("/vex/advisory_fixed_versions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let remediation = fixed_versions
        .first()
        .map(|fixed| format!("Upgrade {name} to {fixed} or later."));
    let title = match &version {
        Some(version) => format!("{vuln_id} in {name} {version}"),
        None => format!("{vuln_id} in {name}"),
    };
    // The SBOM layer backfills CWE-1395 (dependency on a vulnerable
    // component) when an advisory has none; mirror it for older records.
    let cwe = m
        .get("cwe")
        .and_then(Value::as_array)
        .map(|list| parse_cwes(list.iter().filter_map(Value::as_str)))
        .unwrap_or_else(|| vec![1395]);
    let finding = Finding {
        id,
        kind: Kind::Sca,
        producer: producer_for(Kind::Sca, "").to_owned(),
        rule: RuleRef {
            id: Some(vuln_id.clone()),
            slug: None,
            name: None,
        },
        title,
        message: str_at(m, &["summary"]).unwrap_or_else(|| vuln_id.clone()),
        explanation: None,
        severity: severity::resolve(None, str_at(m, &["severity"]).as_deref(), None, false),
        impact: None,
        confidence: Confidence {
            level: level_word(str_at(m, &["match_confidence"]).as_deref()),
            score: None,
        },
        cwe,
        confirmation: Confirmation {
            level: ConfirmationLevel::Advisory,
            detail: None,
        },
        verdict: None,
        location: None,
        fix_location: None,
        stack: Vec::new(),
        trace: Vec::new(),
        group: Some(primary.clone()),
        fingerprint: Fingerprint {
            primary,
            signature: None,
        },
        occurrences: 1,
        first_seen: None,
        last_seen: None,
        reachability: m.get("reachability").filter(|r| r.is_object()).cloned(),
        fidelity: Fidelity::default(),
        remediation,
        patch_hints: Vec::new(),
        reproduce: None,
        evidence: None,
        fuzz: None,
        static_: None,
        sca: Some(ScaBlock {
            vuln_id,
            aliases: m
                .get("aliases")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            component: Component {
                name,
                version,
                ecosystem,
                purl,
                cpe: str_at(m, &["component", "cpe"]),
            },
            fixed_versions,
            cvss: m.get("cvss").filter(|v| v.is_object()).cloned(),
            kev: m.get("kev").filter(|v| !v.is_null()).cloned(),
            references: m
                .get("references")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            match_confidence: str_at(m, &["match_confidence"]),
            matching_method: str_at(m, &["matching_method"]),
            vex: m.get("vex").filter(|v| v.is_object()).cloned(),
        }),
        binary: None,
        raw_ref: Some("sbom/vulnerabilities.json".to_owned()),
    };
    debug_assert_kind_block(&finding);
    Some(finding)
}

/// Canonical versionless identity of a purl, used for the SCA fingerprint so
/// the same component fingerprints identically no matter how a scanner spelled
/// it: the `@version` segment is dropped and the qualifiers are sorted by key
/// (purl qualifier order is not significant). The subpath is preserved. Keeps
/// qualifiers' values, so a genuinely distinct artifact (e.g. a different
/// `?type=`) still fingerprints apart.
pub(crate) fn purl_without_version(purl: &str) -> String {
    // Peel off subpath (`#...`) then qualifiers (`?...`) from the coordinate.
    let (before_subpath, subpath) = match purl.split_once('#') {
        Some((head, sub)) => (head, Some(sub)),
        None => (purl, None),
    };
    let (coord, qualifiers) = match before_subpath.split_once('?') {
        Some((head, qual)) => (head, Some(qual)),
        None => (before_subpath, None),
    };
    // Drop `@version`: only an `@` after the last path separator is a version.
    let coord = match coord.rfind('@') {
        Some(at) if at > coord.rfind('/').unwrap_or(0) => &coord[..at],
        _ => coord,
    };
    let mut out = coord.to_owned();
    if let Some(qualifiers) = qualifiers {
        let mut pairs: Vec<&str> = qualifiers.split('&').filter(|p| !p.is_empty()).collect();
        pairs.sort_unstable();
        if !pairs.is_empty() {
            out.push('?');
            out.push_str(&pairs.join("&"));
        }
    }
    if let Some(subpath) = subpath {
        out.push('#');
        out.push_str(subpath);
    }
    out
}

fn level_word(value: Option<&str>) -> String {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("high") => "high",
        Some("medium") | Some("moderate") => "medium",
        Some("low") => "low",
        _ => "unknown",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConfirmationLevel, Kind, Severity};
    use serde_json::json;

    fn load_one(
        raw: serde_json::Value,
        files: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, report::FindingReport) {
        let tmp = tempfile::tempdir().unwrap();
        let id = raw["id"].as_str().unwrap().to_owned();
        let dir = tmp.path().join("results/findings").join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("finding.json"), serde_json::to_vec(&raw).unwrap()).unwrap();
        for (name, bytes) in files {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let (mut found, failed) =
            report::load_findings_tolerant(&tmp.path().join("results/findings"), None, false)
                .unwrap();
        assert!(failed.is_empty(), "{failed:?}");
        (tmp, found.remove(0))
    }

    fn normalize(raw: serde_json::Value, root: Option<&str>) -> Finding {
        normalize_dir(raw, root, |_| {}).1
    }

    /// Normalize `raw` after `setup` has populated its finding directory.
    fn normalize_dir(
        raw: serde_json::Value,
        root: Option<&str>,
        setup: impl FnOnce(&std::path::Path),
    ) -> (tempfile::TempDir, Finding) {
        let tmp = tempfile::tempdir().unwrap();
        let id = raw["id"].as_str().unwrap().to_owned();
        let dir = tmp.path().join("results/findings").join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("finding.json"), serde_json::to_vec(&raw).unwrap()).unwrap();
        setup(&dir);
        let (mut found, failed) =
            report::load_findings_tolerant(&tmp.path().join("results/findings"), None, false)
                .unwrap();
        assert!(failed.is_empty(), "{failed:?}");
        let results = tmp.path().join("results");
        let ctx = NormalizeContext {
            source_root: root.map(std::path::Path::new),
            results_dir: &results,
        };
        let finding = from_finding_report(&found.remove(0), &ctx).unwrap();
        (tmp, finding)
    }

    /// A complete on-disk actionability record, so explanation and patch
    /// hints are fixed instead of backfilled.
    fn actionability_with_hint() -> serde_json::Value {
        json!({
            "mode": "reporting", "verdict": "unknown", "impact": "medium", "confidence": "medium",
            "prosthetics": {"used": false}, "explanation": "plain words",
            "patch_hints": [{"rule_id": "BHF-201", "title": "Bound the copy", "guidance": "Check the length first."}]
        })
    }

    /// A fuzz crash as the emitter writes it: the cluster key travels with
    /// its normalized frames, so the loader keeps the record's own key.
    fn asan_record() -> serde_json::Value {
        json!({
            "id": "F-0000-1a2b3c4d",
            "signature": "aa11",
            "cluster_key": "c0ffee",
            "cluster_key_full": "c0ffee00c0ffee00",
            "cluster_normalized_frames": ["parse_header"],
            "rule_id": "BHF-201",
            "classification": "unhandled",
            "harness_id": "H-C-parse",
            "dialect": "c11",
            "created_at": "2026-10-01T11:20:00Z",
            "exception": {
                "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                "message": "heap-buffer-overflow on address 0x602000000010 READ of size 4",
                "sanitizer": "asan",
                "stack": [
                    {"function": "__asan_report_load4", "file": "/llvm/compiler-rt/lib/asan/asan_rtl.cpp", "line": 1},
                    {"function": "parse_header", "file": "/src/demo/src/parse.c", "line": 42},
                    {"function": "LLVMFuzzerTestOneInput", "file": "/w/harnesses/H-C-parse/harness.c", "line": 9}
                ]
            }
        })
    }

    #[test]
    fn asan_crash_normalizes_to_a_fuzz_finding() {
        let mut raw = asan_record();
        // A target location must not outrank the crash's own sink frame.
        raw["target"] = json!({"location": {"path": "/src/demo/src/other.c", "line": 7}});
        let (tmp, report) = load_one(raw, &[("testcase.bin", b"AAAA")]);
        let root = std::path::Path::new("/src/demo");
        let results = tmp.path().join("results");
        let ctx = NormalizeContext {
            source_root: Some(root),
            results_dir: &results,
        };
        let f = from_finding_report(&report, &ctx).unwrap();

        assert_eq!(f.kind, Kind::Fuzz);
        let loc = f.location.as_ref().expect("sink location");
        assert_eq!(
            (loc.file.as_str(), loc.line, loc.function.as_deref()),
            ("src/parse.c", Some(42), Some("parse_header"))
        );
        assert_eq!(f.producer, "fuzz");
        assert_eq!(f.rule.id.as_deref(), Some("BHF-201"));
        assert_eq!(f.confirmation.level, ConfirmationLevel::SanitizerCrash);
        assert_eq!(f.fingerprint.primary, "c0ffee00c0ffee00");
        assert_eq!(f.fingerprint.signature.as_deref(), Some("aa11"));
        assert_eq!(f.group.as_deref(), Some("c0ffee00c0ffee00"));
        assert!(
            f.message.contains("0x…"),
            "addresses stripped: {}",
            f.message
        );
        assert!(!f.message.contains("0x602000000010"));
        assert_eq!(f.stack.len(), 1, "only project frames: {:?}", f.stack);
        assert_eq!(f.stack[0].file.as_deref(), Some("src/parse.c"));
        assert_eq!(f.stack[0].function.as_deref(), Some("parse_header"));
        assert_eq!(f.stack[0].line, Some(42));
        assert!(!f.cwe.is_empty());
        assert_ne!(f.severity, Severity::Info);
        assert_eq!(f.first_seen.as_deref(), Some("2026-10-01T11:20:00Z"));
        assert_eq!(f.last_seen.as_deref(), Some("2026-10-01T11:20:00Z"));
        let evidence = f.evidence.as_ref().unwrap();
        assert_eq!(evidence.dir, "findings/F-0000-1a2b3c4d");
        let roles: Vec<_> = evidence.files.iter().map(|e| e.role.as_str()).collect();
        assert_eq!(roles, ["finding", "testcase"]);
        assert_eq!(
            evidence.files[1].path,
            "findings/F-0000-1a2b3c4d/testcase.bin"
        );
        assert_eq!(evidence.files[1].size, 4);
        assert_eq!(
            evidence.files[1].sha256.as_deref(),
            Some("63c1dd951ffedf6f7fd968ad4efa39b8ed584f162f46e715114ee184f8de9201")
        );
        let fuzz = f.fuzz.as_ref().unwrap();
        assert_eq!(fuzz.harness_id.as_deref(), Some("H-C-parse"));
        assert_eq!(fuzz.dialect.as_deref(), Some("c11"));
        assert_eq!(fuzz.exception.sanitizer.as_deref(), Some("asan"));
        let reproduce = f.reproduce.as_ref().unwrap();
        assert_eq!(reproduce.harness_id.as_deref(), Some("H-C-parse"));
        assert_eq!(reproduce.build.sanitizers, ["asan"]);
        assert!(reproduce.command.is_none(), "no replay.py, no command");
        assert_eq!(
            f.raw_ref.as_deref(),
            Some("findings/F-0000-1a2b3c4d/finding.json")
        );
        assert!(
            !f.title.contains("0x"),
            "title is a weakness name, not a raw sanitizer line: {}",
            f.title
        );
        assert!(f.static_.is_none() && f.sca.is_none() && f.binary.is_none());
    }

    #[test]
    fn auto_static_row_without_sink_takes_its_location_from_the_record() {
        let raw = json!({
            "id": "F-STATIC-0000", "rule_id": "BHF-401", "classification": "static_scan",
            "confirmation": "static", "finding_kind": "static",
            "exception": {"message": "Unbounded string copy", "source_file": "", "source_line": ""},
            "oracle": {"evidence": [{"key": "source", "value": "/work/proj/lib/parse.c:6:copy_name"}]},
            "target": {"line": 6, "location": {"line": 6, "path": "/work/proj/lib/parse.c"}, "source_path": "/work/proj/lib/parse.c"}
        });
        let f = normalize(raw, Some("/work/proj"));
        let loc = f.location.as_ref().expect("location");
        assert_eq!((loc.file.as_str(), loc.line), ("lib/parse.c", Some(6)));
        assert_eq!(
            f.fingerprint.primary, "BHF-401:lib/parse.c:6",
            "stable rule:file:line, not the run-local id"
        );
        assert_eq!(f.kind, Kind::Static);
        assert_eq!(f.producer, "auto");
        assert_eq!(f.confirmation.level, ConfirmationLevel::Static);
        assert!(f.reproduce.is_none(), "static findings have no reproducer");
        assert!(f.static_.is_some() && f.fuzz.is_none());
    }

    #[test]
    fn auto_static_row_prefers_its_static_fingerprint() {
        let raw = json!({
            "id": "F-RO-BHF-401-0000AAAA", "rule_id": "BHF-401", "classification": "static_scan",
            "finding_kind": "static", "static_fingerprint": "fp-parse-6",
            "target": {"location": {"line": 6, "path": "/work/proj/lib/parse.c"}}
        });
        let f = normalize(raw, Some("/work/proj"));
        assert_eq!(f.fingerprint.primary, "fp-parse-6");
    }

    #[test]
    fn record_location_falls_back_through_target_then_exception() {
        let target_only = json!({
            "target": {"source_path": "/work/proj/a.c", "line": "12"},
            "exception": {"source_file": "/work/proj/b.c", "source_line": 3}
        });
        let loc = record_location(&target_only, Some(std::path::Path::new("/work/proj"))).unwrap();
        assert_eq!((loc.file.as_str(), loc.line), ("a.c", Some(12)));

        let exception_only =
            json!({"exception": {"source_file": "/work/proj/b.c", "source_line": "3"}});
        let loc =
            record_location(&exception_only, Some(std::path::Path::new("/work/proj"))).unwrap();
        assert_eq!((loc.file.as_str(), loc.line), ("b.c", Some(3)));

        let file_line =
            json!({"oracle": {"evidence": [{"key": "source", "value": "/work/proj/c.c:7"}]}});
        let loc = record_location(&file_line, Some(std::path::Path::new("/work/proj"))).unwrap();
        assert_eq!(
            (loc.file.as_str(), loc.line, loc.function.as_deref()),
            ("c.c", Some(7), None)
        );

        assert!(record_location(&json!({"exception": {"source_file": ""}}), None).is_none());
    }

    #[test]
    fn source_evidence_splits_like_the_actionability_layer() {
        assert_eq!(
            split_source_evidence("/w/a.cpp:10:ns::parse"),
            Some(("/w/a.cpp", 10, Some("ns::parse".to_owned())))
        );
        assert_eq!(
            split_source_evidence("C:\\w\\a.c:7"),
            Some(("C:\\w\\a.c", 7, None))
        );
        assert_eq!(
            split_source_evidence("/w/a.c:7:"),
            Some(("/w/a.c", 7, None))
        );
        assert_eq!(
            split_source_evidence("12:fn"),
            None,
            "no file before the line"
        );
        assert_eq!(split_source_evidence("parse_header"), None);
    }

    #[test]
    fn dynamic_record_without_cluster_or_signature_gets_a_composite_primary() {
        let mut raw = asan_record();
        for key in [
            "signature",
            "cluster_key",
            "cluster_key_full",
            "cluster_normalized_frames",
        ] {
            raw.as_object_mut().unwrap().remove(key);
        }
        // With frames, the loader synthesizes a cluster key from them; drop
        // them so this pins the final fallback.
        raw["exception"]["stack"] = json!([]);
        raw["exception"]["source_file"] = json!("/src/demo/src/parse.c");
        raw["exception"]["source_line"] = json!(42);
        let f = normalize(raw, Some("/src/demo"));
        assert_ne!(f.fingerprint.primary, f.id);
        assert!(
            f.fingerprint
                .primary
                .starts_with("BHF-201:ASAN_HEAP_BUFFER_OVERFLOW:src/parse.c:42"),
            "{}",
            f.fingerprint.primary
        );
    }

    #[test]
    fn dynamic_record_with_frames_but_no_cluster_key_uses_the_synthesized_key() {
        let mut raw = asan_record();
        for key in [
            "cluster_key",
            "cluster_key_full",
            "cluster_normalized_frames",
        ] {
            raw.as_object_mut().unwrap().remove(key);
        }
        let (_tmp, report) = load_one(raw.clone(), &[]);
        let synthesized = report.cluster_key_full.clone().expect("frames give a key");
        let f = normalize(raw, Some("/src/demo"));
        assert_eq!(f.fingerprint.primary, synthesized);
    }

    #[test]
    fn persisted_cluster_key_outranks_the_loaders_recompute() {
        // A stack without `cluster_normalized_frames`: the loader recomputes
        // a key from the frames, but identity stays the one written at emit.
        let mut raw = asan_record();
        raw.as_object_mut()
            .unwrap()
            .remove("cluster_normalized_frames");
        let (_tmp, report) = load_one(raw.clone(), &[]);
        assert_ne!(
            report.cluster_key_full.as_deref(),
            Some("c0ffee00c0ffee00"),
            "precondition: the loader recomputed the key"
        );
        let f = normalize(raw, Some("/src/demo"));
        assert_eq!(f.fingerprint.primary, "c0ffee00c0ffee00");
        assert_eq!(f.group.as_deref(), Some("c0ffee00c0ffee00"));
    }

    #[test]
    fn binary_crash_uses_its_crash_signature_and_fills_the_binary_block() {
        let sha = "ab".repeat(32);
        let raw = json!({
            "id": "BF-0001", "kind": "binary_crash", "rule_id": "BHF-501", "severity": "high",
            "message": "Binary crashed under BHF binary-fuzz",
            "binary": {"path": "/bin/target", "sha256": sha},
            "crash": {"exit_code": null, "timeout": false, "signature": "signal:11:abcd"},
            "triage": {"replay": "bhf replay --harness /bin/target BF-0001"},
            "finding_kind": "binary"
        });
        let f = normalize(raw, None);
        assert_eq!(f.kind, Kind::Binary);
        assert_eq!(f.producer, "binary fuzz");
        assert_eq!(f.fingerprint.primary, "BHF-501:target:signal:11:abcd");
        assert_eq!(f.fingerprint.signature.as_deref(), Some("signal:11:abcd"));
        assert_eq!(f.group.as_deref(), Some("BHF-501:target:signal:11:abcd"));
        let binary = f.binary.as_ref().unwrap();
        assert_eq!(binary.sha256.as_deref(), Some(sha.as_str()));
        assert!(binary.crash.is_some());
        let reproduce = f.reproduce.as_ref().unwrap();
        assert!(
            reproduce.command.is_none(),
            "record text is not a bhf-built command: {:?}",
            reproduce.command
        );
        assert_eq!(reproduce.build.binary_sha256.as_deref(), Some(sha.as_str()));
        assert!(f.fuzz.is_none());
    }

    #[test]
    fn hashes_that_are_not_lowercase_hex_are_dropped() {
        let raw = json!({
            "id": "BF-0002", "rule_id": "BHF-501", "finding_kind": "binary",
            "binary": {"sha256": "not-a-digest"},
            "build": {"binary": {"sha256": "AB".repeat(32), "build_id": "zz"}}
        });
        let f = normalize(raw, None);
        assert!(f.binary.as_ref().unwrap().sha256.is_none());
        let build = &f.reproduce.as_ref().unwrap().build;
        assert!(build.binary_sha256.is_none());
        assert!(build.build_id.is_none());
    }

    #[test]
    fn humanizes_sanitizer_exception_names() {
        assert_eq!(
            humanize_exception("ASAN_HEAP_BUFFER_OVERFLOW"),
            "Heap Buffer Overflow"
        );
        assert_eq!(humanize_exception("SIGSEGV"), "SIGSEGV");
    }

    #[test]
    fn title_prefers_the_weakness_name_then_the_message() {
        let loc = Location {
            file: "a.c".to_owned(),
            line: Some(1),
            column: None,
            function: Some("parse".to_owned()),
        };
        assert_eq!(
            title_for("msg", Some("Use After Free"), None, Some(&loc), "F-1"),
            "Use After Free in parse"
        );
        assert_eq!(
            title_for("msg", None, Some("ASAN_DOUBLE_FREE"), None, "F-1"),
            "Double Free"
        );
        let free = Location {
            function: Some("free".to_owned()),
            ..loc.clone()
        };
        assert_eq!(
            title_for("msg", Some("Use of freed memory"), None, Some(&free), "F-1"),
            "Use of freed memory in free",
            "a substring is not the function"
        );
        let parse = Location {
            function: Some("parse".to_owned()),
            ..loc.clone()
        };
        assert_eq!(
            title_for("msg", Some("Overflow in parse"), None, Some(&parse), "F-1"),
            "Overflow in parse"
        );
        let copy = Location {
            function: Some("copy_name".to_owned()),
            ..loc.clone()
        };
        assert_eq!(
            title_for(
                "msg",
                Some("Unsafe string copy call in source"),
                None,
                Some(&copy),
                "F-1"
            ),
            "Unsafe string copy call in source (copy_name)",
            "a name that already says \"in\" takes the function in parentheses"
        );
        assert_eq!(
            title_for("msg", Some("Unsafe string copy"), None, Some(&copy), "F-1"),
            "Unsafe string copy in copy_name"
        );
        assert_eq!(title_for("first\nsecond", None, None, None, "F-1"), "first");
        assert_eq!(title_for("", None, None, None, "F-1"), "F-1");
        let long = "x".repeat(400);
        assert_eq!(
            title_for(&long, None, None, None, "F-1").chars().count(),
            TITLE_MAX
        );
    }

    #[test]
    fn forced_findings_are_floored_and_flagged() {
        let mut raw = asan_record();
        raw["forced"] = json!(true);
        raw["forced_note"] = json!("forced stub build");
        let f = normalize(raw, None);
        assert!(f.severity <= Severity::Low);
        assert_eq!(f.confidence.level, "low");
        assert!(f.fidelity.forced);
        assert_eq!(f.confirmation.level, ConfirmationLevel::CrashLead);
        assert!(f.fidelity.caveats.iter().any(|c| c == "forced stub build"));
    }

    #[test]
    fn time_budget_skip_becomes_a_caveat() {
        let mut raw = asan_record();
        raw["minimization_skipped"] = json!("time_budget");
        let (tmp, report) = load_one(raw, &[]);
        let results = tmp.path().join("results");
        let f = from_finding_report(
            &report,
            &NormalizeContext {
                source_root: None,
                results_dir: &results,
            },
        )
        .unwrap();
        assert!(f
            .fidelity
            .caveats
            .iter()
            .any(|c| c == crate::UNMINIMIZED_CAVEAT));
    }

    #[test]
    fn without_a_root_toolchain_and_harness_frames_are_still_dropped() {
        let f = normalize(asan_record(), None);
        assert_eq!(f.stack.len(), 1, "{:?}", f.stack);
        assert_eq!(f.stack[0].file.as_deref(), Some("/src/demo/src/parse.c"));
    }

    #[test]
    fn kind_inference_by_envelope_then_id_family() {
        assert_eq!(kind_for("F-TSAN-0000", &json!({})), Kind::Runtime);
        assert_eq!(kind_for("F-RO-BHF-1-0000AAAA", &json!({})), Kind::Static);
        assert_eq!(kind_for("F-EXT-0001", &json!({})), Kind::Static);
        assert_eq!(
            kind_for("BF-0001", &json!({"kind": "binary_crash"})),
            Kind::Binary
        );
        assert_eq!(kind_for("F-DIFF-0000", &json!({})), Kind::Differential);
        assert_eq!(kind_for("F-0003-abcd", &json!({})), Kind::Fuzz);
        assert_eq!(
            kind_for("F-0003-abcd", &json!({"finding_kind": "runtime"})),
            Kind::Runtime
        );
    }

    #[test]
    fn strip_addresses_only_touches_long_hex() {
        assert_eq!(
            strip_addresses("at 0x602000000010 size 0x4"),
            "at 0x… size 0x4"
        );
        assert_eq!(strip_addresses("ünï 0xdeadbeef"), "ünï 0x…");
    }

    fn static_scan_value() -> serde_json::Value {
        json!({
            "id": "S-0001", "rule_id": "BHF-S-120", "rule_slug": "strcpy-overflow", "cwe": "CWE-120",
            "remediation": "Use strlcpy.", "language": "c", "severity": "high", "confidence": "medium",
            "baseline_status": "new", "message": "strcpy into fixed buffer",
            "location": {"path": "/src/demo/weak.c", "line": 9, "column": 5},
            "fingerprint": "fp-weak-9", "identity": "id-weak",
            "evidence": [{"kind": "sink", "detail": "strcpy", "snippet": "strcpy(buf, name);"}],
            "analysis": {
                "engine": "taint", "precision": {"interprocedural_depth": 1, "complete_trace": true},
                "enclosing_function": "greet",
                "trace": [{"kind": "source", "path": "/src/demo/weak.c", "line": 3, "caller": "main", "callee": "greet", "snippet": "greet(argv[1])"}],
                "reachability": "source_reachable"
            },
            "triage": {"state": "open"}
        })
    }

    fn sca_match() -> serde_json::Value {
        json!({
            "id": "CVE-2026-TEST", "severity": "high", "summary": "test advisory",
            "component": {"name": "example", "version": "2.4.2", "ecosystem": "npm",
                          "purl": "pkg:npm/example@2.4.2?arch=x86", "cpe": null},
            "match_confidence": "high", "matching_method": "purl", "cwe": ["CWE-1395"],
            "reachability": {"status": "not_observed", "source": "auto_run"},
            "vex": {"advisory_fixed_versions": ["2.4.3"]}
        })
    }

    #[test]
    fn static_scan_finding_carries_trace_and_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = NormalizeContext {
            source_root: Some(std::path::Path::new("/src/demo")),
            results_dir: tmp.path(),
        };
        let f = from_static_value(&static_scan_value(), Some("issue-1"), &ctx).unwrap();
        assert_eq!(f.kind, Kind::Static);
        assert_eq!(f.producer, "static-scan");
        assert_eq!(f.cwe, vec![120]);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence.level, "medium");
        assert_eq!(f.confirmation.level, ConfirmationLevel::Static);
        assert_eq!(f.rule.slug.as_deref(), Some("strcpy-overflow"));
        let loc = f.location.as_ref().unwrap();
        assert_eq!(loc.file, "weak.c");
        assert_eq!((loc.line, loc.column), (Some(9), Some(5)));
        assert_eq!(loc.function.as_deref(), Some("greet"));
        assert_eq!(f.trace.len(), 1);
        assert_eq!(f.trace[0].file, "weak.c");
        assert_eq!(f.trace[0].function.as_deref(), Some("greet"));
        assert_eq!(f.trace[0].note.as_deref(), Some("source"));
        assert_eq!(f.fingerprint.primary, "fp-weak-9");
        assert_eq!(f.fingerprint.signature.as_deref(), Some("id-weak"));
        assert_eq!(f.group.as_deref(), Some("issue-1"));
        assert_eq!(f.remediation.as_deref(), Some("Use strlcpy."));
        assert_eq!(f.reachability, Some(json!({"tier": "source_reachable"})));
        let block = f.static_.as_ref().unwrap();
        assert_eq!(block.snippet.as_deref(), Some("strcpy(buf, name);"));
        assert_eq!(block.engine.as_deref(), Some("taint"));
        assert_eq!(block.baseline_status.as_deref(), Some("new"));
        assert_eq!(block.triage_state.as_deref(), Some("open"));
        assert!(block.precision.as_ref().is_some_and(|p| p.is_object()));
        assert!(f.evidence.is_none());
        assert!(f.reproduce.is_none());
        assert_eq!(f.raw_ref.as_deref(), Some("static/static-report.json"));
    }

    #[test]
    fn static_scan_finding_without_an_issue_groups_by_its_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = NormalizeContext {
            source_root: None,
            results_dir: tmp.path(),
        };
        let mut v = static_scan_value();
        v["analysis"]["reachability"] = json!({"tier": "isolated"});
        let f = from_static_value(&v, None, &ctx).unwrap();
        assert_eq!(f.group.as_deref(), Some("fp-weak-9"));
        assert_eq!(f.location.as_ref().unwrap().file, "/src/demo/weak.c");
        assert_eq!(f.reachability, Some(json!({"tier": "isolated"})));
        v.as_object_mut().unwrap().remove("location");
        assert!(
            from_static_value(&v, None, &ctx).is_none(),
            "no location, no finding"
        );
    }

    #[test]
    fn static_issue_keys_map_every_member() {
        let report = json!({"issues": [
            {"issue_key": "k1", "finding_ids": ["S-0001", "S-0002"]},
            {"issue_key": "k2", "finding_ids": ["S-0003"]},
            {"finding_ids": ["S-0004"]}
        ]});
        let keys = static_issue_keys(&report);
        assert_eq!(keys.len(), 3);
        assert_eq!(keys["S-0002"], "k1");
        assert_eq!(keys["S-0003"], "k2");
        assert!(static_issue_keys(&json!({})).is_empty());
    }

    #[test]
    fn sca_match_becomes_a_versionless_identity() {
        let m = sca_match();
        let f = from_sca_value(&m).unwrap();
        assert_eq!(f.kind, Kind::Sca);
        assert_eq!(f.producer, "sbom");
        assert_eq!(
            f.fingerprint.primary,
            "CVE-2026-TEST|pkg:npm/example?arch=x86"
        );
        assert!(f.id.starts_with("F-SCA-") && f.id.len() == "F-SCA-".len() + 16);
        assert_eq!(
            f.id,
            format!(
                "F-SCA-{}",
                &sha256_hex(b"CVE-2026-TEST|pkg:npm/example?arch=x86")[..16]
            )
        );
        assert_eq!(f.title, "CVE-2026-TEST in example 2.4.2");
        assert_eq!(f.message, "test advisory");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence.level, "high");
        let sca = f.sca.as_ref().unwrap();
        assert_eq!(sca.vuln_id, "CVE-2026-TEST");
        assert_eq!(sca.fixed_versions, ["2.4.3"]);
        assert_eq!(sca.component.version.as_deref(), Some("2.4.2"));
        assert!(sca.component.cpe.is_none());
        assert_eq!(
            f.remediation.as_deref(),
            Some("Upgrade example to 2.4.3 or later.")
        );
        assert_eq!(f.confirmation.level, ConfirmationLevel::Advisory);
        assert_eq!(f.cwe, vec![1395]);
        assert_eq!(f.raw_ref.as_deref(), Some("sbom/vulnerabilities.json"));
        // a version bump keeps the identity
        let mut bumped = m.clone();
        bumped["component"]["purl"] = json!("pkg:npm/example@2.4.9?arch=x86");
        bumped["component"]["version"] = json!("2.4.9");
        assert_eq!(from_sca_value(&bumped).unwrap().id, f.id);
    }

    #[test]
    fn sca_match_without_purl_or_cwe_still_has_an_identity_and_a_cwe() {
        let mut m = sca_match();
        m["component"]["purl"] = json!(null);
        m.as_object_mut().unwrap().remove("cwe");
        m["summary"] = json!(null);
        let f = from_sca_value(&m).unwrap();
        assert_eq!(f.fingerprint.primary, "CVE-2026-TEST|npm:example");
        assert_eq!(f.cwe, vec![1395]);
        assert_eq!(f.message, "CVE-2026-TEST");
        m["component"]["name"] = json!("");
        assert!(from_sca_value(&m).is_none(), "a match names its component");
    }

    #[test]
    fn purl_without_version_handles_qualifiers_and_subpaths() {
        assert_eq!(
            purl_without_version("pkg:npm/%40scope/x@1.0"),
            "pkg:npm/%40scope/x"
        );
        assert_eq!(
            purl_without_version("pkg:golang/a/b@v1#sub"),
            "pkg:golang/a/b#sub"
        );
        assert_eq!(purl_without_version("pkg:cargo/serde"), "pkg:cargo/serde");
        // Qualifier order is not significant: the same component fingerprints
        // identically no matter how a scanner ordered its qualifiers, and a
        // version bump does not change identity.
        assert_eq!(
            purl_without_version("pkg:npm/x@2.0?b=2&a=1"),
            "pkg:npm/x?a=1&b=2"
        );
        assert_eq!(
            purl_without_version("pkg:npm/x@2.1?a=1&b=2"),
            purl_without_version("pkg:npm/x@2.0?b=2&a=1"),
        );
        assert_eq!(
            purl_without_version("pkg:deb/debian/curl@7.0?distro=buster&arch=amd64#usr/bin"),
            "pkg:deb/debian/curl?arch=amd64&distro=buster#usr/bin"
        );
    }

    #[test]
    fn sca_identity_is_stable_across_qualifier_order() {
        let a = from_sca_value(&json!({
            "id": "CVE-2026-1", "summary": "x",
            "component": {"name": "x", "version": "2.0", "ecosystem": "npm",
                          "purl": "pkg:npm/x@2.0?b=2&a=1"},
        }))
        .unwrap();
        let b = from_sca_value(&json!({
            "id": "CVE-2026-1", "summary": "x",
            "component": {"name": "x", "version": "2.1", "ecosystem": "npm",
                          "purl": "pkg:npm/x@2.1?a=1&b=2"},
        }))
        .unwrap();
        assert_eq!(a.id, b.id, "same component, reordered qualifiers → one id");
        assert_eq!(a.fingerprint.primary, b.fingerprint.primary);
    }

    /// The schema requires each kind's block; nothing in the types enforces it.
    #[test]
    fn every_kind_carries_its_block() {
        let mut findings = vec![normalize(asan_record(), None)];
        for (id, kind) in [
            ("F-TSAN-0000", "runtime"),
            ("F-DIFF-0000", "differential"),
            ("BF-0001", "binary"),
            ("F-STATIC-0000", "static"),
        ] {
            findings.push(normalize(
                json!({"id": id, "rule_id": "BHF-201", "finding_kind": kind}),
                None,
            ));
        }
        let tmp = tempfile::tempdir().unwrap();
        let ctx = NormalizeContext {
            source_root: None,
            results_dir: tmp.path(),
        };
        findings.push(from_static_value(&static_scan_value(), None, &ctx).unwrap());
        findings.push(from_sca_value(&sca_match()).unwrap());

        let mut kinds: Vec<Kind> = findings.iter().map(|f| f.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds, Kind::ALL.to_vec(), "every kind is exercised");
        for f in &findings {
            assert!(
                kind_block_present(f),
                "{} ({:?}) lacks its block",
                f.id,
                f.kind
            );
            assert!(!f.cwe.is_empty(), "{} has no CWE", f.id);
            assert!(!f.title.is_empty() && !f.fingerprint.primary.is_empty());
        }
    }

    #[test]
    fn confirmed_static_row_groups_under_its_crash_cluster() {
        // The confirm pass writes the crash's cluster key onto the static row
        // without frames, so the loader computes no cluster for it.
        let raw = json!({
            "id": "F-STATIC-0000", "rule_id": "BHF-401", "classification": "static_scan",
            "confirmation": "fuzz_confirmed", "finding_kind": "static",
            "cluster_key_full": "crash-cluster",
            "target": {"location": {"line": 6, "path": "/work/proj/lib/parse.c"}}
        });
        let f = normalize(raw, Some("/work/proj"));
        assert_eq!(f.group.as_deref(), Some("crash-cluster"));
        assert_eq!(f.fingerprint.primary, "BHF-401:lib/parse.c:6");
        assert_eq!(f.confirmation.level, ConfirmationLevel::StaticConfirmed);
    }

    #[test]
    fn group_never_falls_back_to_the_run_local_id() {
        let raw = json!({
            "id": "BF-0003", "rule_id": "BHF-501", "finding_kind": "binary",
            "binary": {"path": "C:\\tools\\demo.exe"},
            "crash": {"signature": "exit:1:ff"}
        });
        let f = normalize(raw, None);
        assert_eq!(f.fingerprint.primary, "BHF-501:demo.exe:exit:1:ff");
        assert_eq!(f.group.as_deref(), Some(f.fingerprint.primary.as_str()));

        let raw = json!({
            "id": "BF-0004", "rule_id": "BHF-501", "finding_kind": "binary",
            "crash": {"signature": "timeout"}
        });
        assert_eq!(
            normalize(raw, None).fingerprint.primary,
            "BHF-501:binary:timeout"
        );
    }

    #[test]
    fn sca_findings_never_come_from_a_finding_record() {
        for raw in [
            json!({"id": "F-SCA-0123456789abcdef"}),
            json!({"id": "F-0000-aaaaaaaa", "finding_kind": "sca"}),
        ] {
            let (tmp, report) = load_one(raw, &[]);
            let results = tmp.path().join("results");
            let ctx = NormalizeContext {
                source_root: None,
                results_dir: &results,
            };
            let error = from_finding_report(&report, &ctx).unwrap_err();
            assert!(
                error.contains("sca findings come only from sbom/vulnerabilities.json"),
                "{error}"
            );
        }
    }

    #[test]
    fn relativize_table() {
        let cases = [
            ("/src/demo2/x.c", Some("/src/demo"), "/src/demo2/x.c"),
            ("/src/demo/x.c", Some("/src/demo/"), "x.c"),
            ("C:\\src\\demo\\x.c", Some("C:\\src\\demo"), "x.c"),
            ("/src/demo//x.c", Some("/src/demo"), "x.c"),
            ("/src/demo/", Some("/src/demo"), "/src/demo/"),
            ("/src/demo", Some("/src/demo"), "/src/demo"),
            ("lib/x.c", Some("/src/demo"), "lib/x.c"),
            ("C:\\a\\b.c", None, "C:/a/b.c"),
        ];
        for (path, root, want) in cases {
            assert_eq!(
                relativize(path, root.map(std::path::Path::new)),
                want,
                "{path} under {root:?}"
            );
        }
    }

    #[test]
    fn dynamic_primary_uses_the_signature_without_a_cluster_key() {
        let mut raw = asan_record();
        for key in [
            "cluster_key",
            "cluster_key_full",
            "cluster_normalized_frames",
        ] {
            raw.as_object_mut().unwrap().remove(key);
        }
        raw["exception"]["stack"] = json!([]);
        let f = normalize(raw, Some("/src/demo"));
        assert_eq!(f.fingerprint.primary, "aa11");
        assert_eq!(f.group.as_deref(), Some("aa11"));
    }

    #[test]
    fn a_rule_without_a_file_keeps_the_run_local_id() {
        let raw =
            json!({"id": "F-0009-abcdabcd", "rule_id": "BHF-201", "exception": {"name": "X"}});
        let f = normalize(raw, None);
        assert!(f.location.is_none(), "{:?}", f.location);
        assert_eq!(f.fingerprint.primary, "F-0009-abcdabcd");
    }

    #[test]
    fn message_falls_back_through_oracle_record_and_explanation() {
        let oracle = json!({
            "id": "F-0001-aaaaaaaa", "exception": {"name": "X"},
            "oracle": {"message": "write past end at 0x7ffd5e8c1234"},
            "message": "not this one"
        });
        assert_eq!(normalize(oracle, None).message, "write past end at 0x…");

        let record = json!({
            "id": "F-0002-aaaaaaaa", "exception": {"name": "X"},
            "message": "fault at 0x602000000010"
        });
        assert_eq!(normalize(record, None).message, "fault at 0x…");

        let explained = json!({
            "id": "F-0003-aaaaaaaa", "exception": {"name": "X"},
            "actionability": actionability_with_hint()
        });
        assert_eq!(normalize(explained, None).message, "plain words");
    }

    #[test]
    fn remediation_falls_back_to_the_first_patch_hint() {
        let raw = json!({"id": "F-0001-aaaaaaaa", "actionability": actionability_with_hint()});
        let f = normalize(raw.clone(), None);
        assert_eq!(f.remediation.as_deref(), Some("Check the length first."));
        assert_eq!(f.patch_hints.len(), 1);
        assert_eq!(f.patch_hints[0].title, "Bound the copy");

        let mut explicit = raw;
        explicit["remediation"] = json!("Use the bounded API.");
        assert_eq!(
            normalize(explicit, None).remediation.as_deref(),
            Some("Use the bounded API.")
        );
    }

    #[test]
    fn strip_root_only_touches_whole_root_prefixes() {
        let root = Some(std::path::Path::new("/src/demo"));
        assert_eq!(
            strip_root("at `/src/demo/src/parse.c:42` and /src/demo/lib/a.c", root),
            "at `src/parse.c:42` and lib/a.c"
        );
        for untouched in [
            "/opt/src/demo/a.c",
            "/src/demo2/a.c",
            "/src/demo",
            "x/src/demo/a.c",
        ] {
            assert_eq!(strip_root(untouched, root), untouched);
        }
        assert_eq!(
            strip_root("/src/demo/a.c", Some(std::path::Path::new("/src/demo/"))),
            "a.c"
        );
        assert_eq!(
            strip_root(
                r"see C:\src\demo\lib\a.c or C:/src/demo/b.c",
                Some(std::path::Path::new(r"C:\src\demo"))
            ),
            r"see lib\a.c or b.c"
        );
        assert_eq!(strip_root("/a.c", Some(std::path::Path::new("/"))), "/a.c");
        assert_eq!(strip_root("/src/demo/a.c", None), "/src/demo/a.c");
    }

    #[test]
    fn free_text_never_carries_the_absolute_source_root() {
        let mut raw = asan_record();
        raw["actionability"] = json!({
            "mode": "reporting", "verdict": "unknown", "impact": "high", "confidence": "medium",
            "prosthetics": {"used": false},
            "explanation": "Overflow at /src/demo/src/parse.c:42.",
            "patch_hints": [{"rule_id": "BHF-201", "title": "Bound the access",
                             "guidance": "Bounds-check the index/length before the access at `/src/demo/src/parse.c:42` (`parse_header`)."}]
        });
        raw["exception"]["message"] = json!("overflow in /src/demo/src/parse.c:42");
        let f = normalize(raw, Some("/src/demo"));
        assert_eq!(f.message, "overflow in src/parse.c:42");
        assert_eq!(
            f.fuzz.as_ref().unwrap().exception.message.as_deref(),
            Some("overflow in src/parse.c:42")
        );
        assert_eq!(
            f.explanation.as_deref(),
            Some("Overflow at src/parse.c:42.")
        );
        let fixed =
            "Bounds-check the index/length before the access at `src/parse.c:42` (`parse_header`).";
        assert_eq!(f.remediation.as_deref(), Some(fixed));
        assert_eq!(f.patch_hints[0].guidance, fixed);

        let mut value = static_scan_value();
        value["message"] = json!("strcpy into buf at /src/demo/weak.c:9");
        value["remediation"] = json!("Bound /src/demo/weak.c:9.");
        let ctx_dir = tempfile::tempdir().unwrap();
        let ctx = NormalizeContext {
            source_root: Some(std::path::Path::new("/src/demo")),
            results_dir: ctx_dir.path(),
        };
        let s = from_static_value(&value, None, &ctx).unwrap();
        assert_eq!(s.message, "strcpy into buf at weak.c:9");
        assert_eq!(s.remediation.as_deref(), Some("Bound weak.c:9."));
    }

    #[test]
    fn title_drops_the_source_root_from_a_message_title() {
        let raw = json!({
            "id": "F-0001-aaaaaaaa",
            "message": "assertion failed in /src/demo/src/a.c:3"
        });
        let f = normalize(raw, Some("/src/demo"));
        assert_eq!(f.title, "assertion failed in src/a.c:3");
    }

    #[test]
    fn confidence_score_reads_blend_then_calibrated_in_range() {
        assert_eq!(
            confidence_score(&json!({"blend": 0.7, "calibrated": 0.2})),
            Some(0.7)
        );
        assert_eq!(confidence_score(&json!({"calibrated": 0.4})), Some(0.4));
        assert_eq!(confidence_score(&json!({"blend": 1.5})), None);
        assert_eq!(confidence_score(&json!({"blend": "high"})), None);
        assert_eq!(confidence_score(&json!("high")), None);
    }

    #[test]
    fn timestamps_that_are_not_rfc3339_are_dropped() {
        let mut raw = asan_record();
        raw["created_at"] = json!("yesterday");
        let f = normalize(raw.clone(), None);
        assert!(f.first_seen.is_none() && f.last_seen.is_none());

        raw["last_seen"] = json!("2026-10-02T08:00:00.123Z");
        let f = normalize(raw, None);
        assert!(f.first_seen.is_none());
        assert_eq!(f.last_seen.as_deref(), Some("2026-10-02T08:00:00.123Z"));
    }

    #[cfg(unix)]
    #[test]
    fn evidence_skips_symlinks_and_caps_hashing() {
        let tmp_outside = tempfile::tempdir().unwrap();
        let secret = tmp_outside.path().join("secret");
        std::fs::write(&secret, b"secret").unwrap();
        let (_tmp, f) = normalize_dir(asan_record(), None, |dir| {
            std::os::unix::fs::symlink(&secret, dir.join("testcase.bin")).unwrap();
            std::fs::write(dir.join("sanitizer.log"), b"log").unwrap();
            let big = std::fs::File::create(dir.join("min_testcase.bin")).unwrap();
            big.set_len(MAX_HASH_BYTES + 1).unwrap();
        });
        let evidence = f.evidence.as_ref().unwrap();
        let roles: Vec<_> = evidence.files.iter().map(|e| e.role.as_str()).collect();
        assert_eq!(roles, ["finding", "testcase_minimized", "sanitizer_log"]);
        let big = &evidence.files[1];
        assert_eq!(big.size, MAX_HASH_BYTES + 1);
        assert!(big.sha256.is_none(), "over the cap: size only");
        assert_eq!(
            evidence.files[2].sha256.as_deref(),
            Some(sha256_hex(b"log").as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn sha256_file_hashes_regular_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("a");
        std::fs::write(&file, b"AAAA").unwrap();
        std::os::unix::fs::symlink(&file, tmp.path().join("link")).unwrap();
        assert_eq!(sha256_file(&file), Some(sha256_hex(b"AAAA")));
        assert_eq!(sha256_file(&tmp.path().join("link")), None);
        assert_eq!(sha256_file(tmp.path()), None, "a directory");
        assert_eq!(sha256_file(&tmp.path().join("missing")), None);
    }

    #[cfg(unix)]
    #[test]
    fn uncapped_hash_covers_files_past_the_evidence_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let big = tmp.path().join("big");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(MAX_HASH_BYTES + 1)
            .unwrap();
        std::os::unix::fs::symlink(&big, tmp.path().join("link")).unwrap();
        assert_eq!(
            sha256_file_uncapped(&big).as_deref(),
            // sha256 of 64 MiB + 1 zero bytes
            Some("91990977345985aaf03af1358f4f989d7eaf985b58529efb72f613c588f6599a")
        );
        assert_eq!(sha256_file(&big), None);
        assert_eq!(sha256_file_uncapped(&tmp.path().join("link")), None);
        assert_eq!(sha256_file(&tmp.path().join("link")), None);
        assert_eq!(sha256_file_uncapped(tmp.path()), None, "a directory");
    }

    #[test]
    fn replay_script_evidence_sets_the_reproduce_command() {
        let (_tmp, f) = normalize_dir(asan_record(), None, |dir| {
            std::fs::write(dir.join("replay.py"), b"print()").unwrap();
        });
        assert_eq!(
            f.reproduce.as_ref().unwrap().command.as_deref(),
            Some("python3 findings/F-0000-1a2b3c4d/replay.py")
        );
    }

    #[test]
    fn drive_paths_outside_the_root_are_not_project_frames() {
        let exception = json!({"stack": [
            {"function": "f", "file": "C:\\lib\\x.c", "line": 3},
            {"function": "g", "file": "D:\\w\\src\\y.c", "line": 4}
        ]});
        let frames = project_frames(&exception, Some(std::path::Path::new("D:/w")));
        assert_eq!(frames.len(), 1, "{frames:?}");
        assert_eq!(frames[0].file.as_deref(), Some("src/y.c"));
    }

    #[test]
    fn keep_offsets_variant_spares_only_module_offsets() {
        let frame = "#0 0x55d4c3a1b2c3 (/bin/t+0x1a2b3c)";
        assert_eq!(strip_addresses(frame), "#0 0x… (/bin/t+0x…)");
        assert_eq!(
            strip_addresses_keep_offsets(frame),
            "#0 0x… (/bin/t+0x1a2b3c)"
        );
        assert_eq!(strip_addresses_keep_offsets("size 0x4"), "size 0x4");
    }

    #[test]
    fn parse_cwes_never_returns_empty() {
        assert_eq!(
            parse_cwes(["CWE-120", "cwe-787", "120"].into_iter()),
            [120, 787]
        );
        assert_eq!(parse_cwes(["CWE-noinfo"].into_iter()), [20]);
        assert_eq!(parse_cwes(std::iter::empty()), [20]);
    }
}
