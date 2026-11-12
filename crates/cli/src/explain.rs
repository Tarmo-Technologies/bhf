// SPDX-License-Identifier: Apache-2.0

//! `bhf explain` — a deterministic, offline "why did it crash?" for a finding.
//!
//! Every other tool's answer to "explain this crash" is either a raw sanitizer
//! dump or an LLM round-trip. bhf already holds every fact needed to answer it
//! precisely and reproducibly, with NO model: the minimized input
//! (`min_testcase.bin`, else `testcase.bin`, named in the output), the
//! comparisons that input reached, recorded by the harness's driver while it
//! ran and confirmed byte by byte ([`crate::gate_evidence`]), the byte-origin
//! taint the shim recorded at each resource call (#422), the environment the
//! runtrace shim observed, the sink site + call frames, and the
//! build-recovery provenance verdict. This joins them through a FIXED
//! narrative grammar into a triage-ready explanation. Each claim names its
//! evidence, or says it has none.
//!
//! `dictionary.txt` is mined from the target's source when the harness is
//! generated; it is not runtime evidence. A dictionary token found in the
//! input is listed only as a labelled substring match.
//!
//! Deterministic for a recorded finding: the same finding always yields the
//! same text. A finding with no recorded comparison evidence is replayed once
//! to record it (nothing is written back). Best-effort per section — a
//! missing artifact drops that section, never the whole explanation.

use crate::auto::runtrace::{self, RuntraceEvent};
use crate::gate_evidence::{self, Capture, Gate};
use serde_json::Value;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// `bhf explain` — explain, offline, why a crash fired.
///
/// The input shown is the finding's `min_testcase.bin`, else its
/// `testcase.bin`, named in the output. Comparison evidence is what the
/// harness recorded while that input ran; a finding without it is replayed
/// once against its harness to record it (nothing is written). The
/// environment comes from that replay when the runtrace shim was loaded, else
/// from the harness's last fuzz pass, and says so; without the shim it reads
/// "not observed".
#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// Work directory of a prior `auto` run.
    #[arg(long = "work-dir", default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Explain only this finding id (default: every reproducible runtime crash,
    /// one per root-cause group).
    #[arg(long = "finding-id", value_name = "ID")]
    pub finding_id: Option<String>,

    /// Explain every finding of a root-cause group. By default a group (the
    /// findings that share a `cluster_key_full`, such as one site reached
    /// through several harnesses) is explained once, by its first finding,
    /// which lists the others and their harnesses.
    #[arg(long = "all-members")]
    pub all_members: bool,
}

pub fn run(args: ExplainArgs) -> i32 {
    if let Err(error) = crate::workdir::prepare(&args.work_dir) {
        bhfeprintln!("error: {error:#}");
        return 1;
    }
    let blocks = match render(&args.work_dir, args.finding_id.as_deref(), args.all_members) {
        Ok(blocks) => blocks,
        Err(e) => {
            bhfeprintln!("error: {e}");
            return 1;
        }
    };
    if blocks.is_empty() {
        bhfeprintln!(
            "bhf explain: no runtime crash findings in {} to explain",
            args.work_dir.display()
        );
        return 0;
    }
    let mut first = true;
    for block in &blocks {
        if !first {
            println!();
        }
        first = false;
        print!("{block}");
    }
    0
}

/// The explanation blocks to print: `only` alone when given, else one per
/// root-cause group (its first finding by ID), or every finding with
/// `all_members`. Each block names the other findings of its group.
fn render(work_dir: &Path, only: Option<&str>, all_members: bool) -> anyhow::Result<Vec<String>> {
    let findings = collect(work_dir)?;
    let mut groups: std::collections::BTreeMap<&str, Vec<&Finding>> = Default::default();
    for f in &findings {
        groups.entry(group_key(f)).or_default().push(f);
    }
    let collapse = only.is_none() && !all_members;
    let mut blocks = Vec::new();
    for f in &findings {
        if only.is_some_and(|want| f.id != want) {
            continue;
        }
        let members = &groups[group_key(f)];
        if collapse && members.first().is_some_and(|first| first.id != f.id) {
            continue;
        }
        let others: Vec<String> = members
            .iter()
            .filter(|member| member.id != f.id)
            .map(|member| match str_at(&member.raw, "/harness_id") {
                Some(harness_id) if !harness_id.is_empty() => {
                    format!("{} ({})", member.id, harness_label(work_dir, harness_id))
                }
                _ => member.id.clone(),
            })
            .collect();
        blocks.push(explain_one(work_dir, f, &others, collapse));
    }
    Ok(blocks)
}

/// The root-cause group a finding belongs to: its `cluster_key_full`, the key
/// the results reports group on, else the finding alone.
fn group_key(f: &Finding) -> &str {
    str_at(&f.raw, "/cluster_key_full")
        .filter(|key| !key.is_empty())
        .unwrap_or(&f.id)
}

/// ``H-C0001 (`target`)``, or `H-C0001` when the harness's target is unknown.
fn harness_label_paren(work_dir: &Path, harness_id: &str) -> String {
    match harness_target_name(work_dir, harness_id) {
        Some(target) => format!("{harness_id} (`{target}`)"),
        None => harness_id.to_owned(),
    }
}

/// `H-C0001`, or `` H-C0001, `target` `` when the harness's target is known.
fn harness_label(work_dir: &Path, harness_id: &str) -> String {
    match harness_target_name(work_dir, harness_id) {
        Some(target) => format!("{harness_id}, `{target}`"),
        None => harness_id.to_owned(),
    }
}

/// A finding to explain.
struct Finding {
    id: String,
    dir: PathBuf,
    raw: Value,
}

fn collect(work_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let dir = corpus::layout::findings_dir(work_dir);
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let fdir = entry.path();
        let Some(raw) = read_json(&fdir.join("finding.json")) else {
            continue;
        };
        // Runtime crashes / oracle hits — the things that "crashed". Static rows are
        // explained by their own report text, not this crash narrative.
        let class = raw.get("classification").and_then(Value::as_str);
        if !matches!(class, Some("unhandled") | Some("oracle")) {
            continue;
        }
        let id = raw
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        out.push(Finding { id, dir: fdir, raw });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Other members of a root-cause group listed by name in one block.
const MAX_LISTED_MEMBERS: usize = 10;

/// Render the full fixed-grammar narrative for one finding. `others` are the
/// other findings of its root-cause group, as `ID (harness)`; `collapsed` says
/// they are not explained separately.
fn explain_one(work_dir: &Path, f: &Finding, others: &[String], collapsed: bool) -> String {
    let mut s = String::new();
    let rule = str_at(&f.raw, "/rule_id").unwrap_or("");
    let cwe = f
        .raw
        .pointer("/actionability/cwe/0")
        .and_then(Value::as_str)
        .unwrap_or("");
    let cwe_name = str_at(&f.raw, "/actionability/cwe_name").unwrap_or("crash");
    let _ = writeln!(s, "━━━ {} — {cwe_name} ({cwe}, {rule}) ━━━", f.id);
    let harness_id = str_at(&f.raw, "/harness_id").unwrap_or("").to_owned();
    if !harness_id.is_empty() {
        let _ = writeln!(
            s,
            "  Harness: {}",
            harness_label_paren(work_dir, &harness_id)
        );
    }
    if let Some(fidelity) = f
        .raw
        .pointer("/build/fidelity")
        .and_then(|value| {
            serde_json::from_value::<results::model::BuildFidelity>(value.clone()).ok()
        })
        .filter(|fidelity| !fidelity.fabricated.is_empty())
    {
        let _ = writeln!(s, "  ⚠ BUILD FIDELITY (low confidence)");
        for line in wrap(&fidelity.caveat(), 74) {
            let _ = writeln!(s, "    {line}");
        }
    }
    if !others.is_empty() {
        let hint = if collapsed {
            " (pass --all-members to explain each)"
        } else {
            ""
        };
        let _ = writeln!(
            s,
            "  Root cause shared with {} other finding(s){hint}:",
            others.len()
        );
        for other in others.iter().take(MAX_LISTED_MEMBERS) {
            let _ = writeln!(s, "    {other}");
        }
        if others.len() > MAX_LISTED_MEMBERS {
            let _ = writeln!(s, "    ... and {} more", others.len() - MAX_LISTED_MEMBERS);
        }
    }

    // WHAT HAPPENED
    let exc = str_at(&f.raw, "/exception/name").unwrap_or("");
    let sink_file = str_at(&f.raw, "/actionability/sink/file").unwrap_or("");
    let sink_fn = str_at(&f.raw, "/actionability/sink/function").unwrap_or("");
    let sink_line = f
        .raw
        .pointer("/actionability/sink/line")
        .and_then(Value::as_u64);
    let _ = writeln!(s, "\nWHAT HAPPENED");
    if let Some(expl) = str_at(&f.raw, "/actionability/explanation") {
        for line in wrap(expl, 76) {
            let _ = writeln!(s, "  {line}");
        }
    }
    if !sink_file.is_empty() {
        let where_ = match sink_line {
            Some(l) => format!("{}:{l}", basename(sink_file)),
            None => basename(sink_file).to_owned(),
        };
        // A report that named only a source position has no sink function:
        // never print an empty `()`. Name the harness target the fault was
        // reached through (the defect may be in a callee), else the location.
        let sink = if !sink_fn.trim().is_empty() {
            format!("{sink_fn}() at {where_}")
        } else if let Some(target) = harness_target_name(work_dir, &harness_id) {
            format!("reached via `{target}` at {where_}")
        } else {
            where_
        };
        let _ = writeln!(s, "  Sink: {sink}");
    }
    if let Some(frames) = f
        .raw
        .get("cluster_normalized_frames")
        .and_then(Value::as_array)
    {
        let names: Vec<&str> = frames.iter().filter_map(Value::as_str).collect();
        if !names.is_empty() {
            let _ = writeln!(s, "  Call frames: {}", dedup_chain(&names).join(" → "));
        }
    }
    if !exc.is_empty() {
        let _ = writeln!(s, "  Sanitizer verdict: {exc}");
    }
    // The sanitizer's own report line: the exact check and site it names.
    if let Some(message) = str_at(&f.raw, "/exception/message")
        .and_then(|m| m.lines().next())
        .filter(|m| !m.trim().is_empty())
    {
        let _ = writeln!(s, "  Sanitizer report: {}", message.trim());
    }
    if let Some(access) = f.raw.pointer("/exception/access") {
        for line in access_lines(access) {
            let _ = writeln!(s, "{line}");
        }
    }

    // THE INPUT THAT TRIGGERS IT: the minimized input when there is one.
    let input = gate_evidence::preferred_input(&f.dir);
    if let Some((name, bytes)) = &input {
        let _ = writeln!(
            s,
            "\nTHE INPUT THAT TRIGGERS IT  ({})",
            input_label(&f.dir, name, bytes.len())
        );
        for line in hexdump(bytes, 6) {
            let _ = writeln!(s, "  {line}");
        }
        for note in input_origin(work_dir, bytes) {
            for (index, line) in wrap(&note, 74).into_iter().enumerate() {
                let indent = if index == 0 { "  " } else { "    " };
                let _ = writeln!(s, "{indent}{line}");
            }
        }
    }

    // Comparison evidence: operands recorded while this input ran.
    let evidence = comparison_evidence(work_dir, f, input.as_ref());
    if let Some((name, bytes)) = &input {
        for line in evidence_lines(&evidence, name) {
            let _ = writeln!(s, "{line}");
        }
        let dict = load_dictionary(work_dir, &harness_id);
        let present = dictionary_tokens_present(bytes, &dict);
        if !present.is_empty() {
            let _ = writeln!(
                s,
                "  Dictionary tokens present in the input (substring matches, not evidence \
                 that a comparison used them):"
            );
            for (token, first, count) in present {
                let more = if count > 1 {
                    format!(" (and {} more)", count - 1)
                } else {
                    String::new()
                };
                let _ = writeln!(s, "    {token} at byte {first}{more}");
            }
        }
    }

    // HARNESS ARGUMENTS: what each parameter was decoded to
    for line in argument_lines(work_dir, f, &evidence) {
        let _ = writeln!(s, "{line}");
    }

    // FAKED ENVIRONMENT + byte-origin taint: this input's own replay when it
    // was recorded, else the harness's last fuzz pass, else not observed.
    let (env_source, env) = environment(work_dir, f, &harness_id, &evidence);
    match env_source {
        Some(source) => {
            let _ = writeln!(s, "\nFAKED ENVIRONMENT  ({source})");
        }
        None => {
            let _ = writeln!(s, "\nFAKED ENVIRONMENT");
        }
    }
    for line in env {
        let _ = writeln!(s, "  {line}");
    }

    // REACHABILITY & PROVENANCE
    let _ = writeln!(s, "\nREACHABILITY & PROVENANCE");
    let statement = actionability::reachability_statement(
        &f.raw,
        harness_target_name(work_dir, &harness_id).as_deref(),
    );
    for (index, line) in wrap(&format!("Verdict: {statement}"), 76)
        .into_iter()
        .enumerate()
    {
        let indent = if index == 0 { "  " } else { "    " };
        let _ = writeln!(s, "{indent}{line}");
    }
    if let Some(prov) = str_at(&f.raw, "/provenance") {
        let note = str_at(&f.raw, "/stub_provenance/note").unwrap_or("");
        let _ = writeln!(s, "  Build-recovery provenance: {}", humanize_prov(prov));
        for line in wrap(note, 74) {
            let _ = writeln!(s, "    {line}");
        }
    }

    // HOW TO FIX
    if let Some(hints) = f
        .raw
        .pointer("/actionability/patch_hints")
        .and_then(Value::as_array)
    {
        if !hints.is_empty() {
            let _ = writeln!(s, "\nHOW TO FIX");
            for h in hints {
                if let Some(g) = h.get("guidance").and_then(Value::as_str) {
                    for line in wrap(g, 76) {
                        let _ = writeln!(s, "  {line}");
                    }
                }
            }
        }
    }

    // REPRODUCE
    let _ = writeln!(s, "\nREPRODUCE OFFLINE");
    for line in reproduce_lines(work_dir, f) {
        let _ = writeln!(s, "  {line}");
    }
    s
}

/// The REPRODUCE OFFLINE commands that apply to `f`: `bhf capsule` and
/// `bhf verify-poc` when the finding's lane takes it and its harness is laid
/// out to be packaged (the check capsule runs before it plans; what planning
/// checks, such as dependencies in the local cache, it says when it refuses),
/// otherwise why not and a command that does reproduce it; plus the finding's
/// `replay.py` and, for an AddressSanitizer crash cartography can map,
/// `bhf cartography`.
fn reproduce_lines(work_dir: &Path, f: &Finding) -> Vec<String> {
    use crate::repro_lane::{self, FindingRecord, Tool};
    let record = FindingRecord {
        id: f.id.clone(),
        dir: f.dir.clone(),
        raw: f.raw.clone(),
    };
    let work = work_dir.display();
    let replay = f.dir.join("replay.py");
    let mut lines = Vec::new();
    match repro_lane::assess(work_dir, &record, Tool::Capsule) {
        Ok(_) => {
            lines.push(format!(
                "bhf capsule --work-dir {work} --finding-id {}",
                f.id
            ));
            lines.push(format!("bhf verify-poc {work}/capsules/capsule_{}", f.id));
            lines.push(
                "  (the capsule records whether its offline rebuild reproduced the crash;"
                    .to_owned(),
            );
            lines.push(
                "  capsule can still refuse a dependency missing from the local cache or a"
                    .to_owned(),
            );
            lines.push("  tree too large to ship, and says which)".to_owned());
            if replay.is_file() {
                // Windows' Python installer provides `python`, not `python3`.
                let python = if cfg!(windows) { "python" } else { "python3" };
                lines.push(format!(
                    "{python} {}",
                    repro_lane::sh_word(&replay.to_string_lossy())
                ));
            }
        }
        Err(refusal) => {
            let reason = format!(
                "bhf capsule is not available for this finding: {}",
                refusal.reason(Tool::Capsule)
            );
            for (index, line) in wrap(&reason, 74).into_iter().enumerate() {
                lines.push(if index == 0 {
                    line
                } else {
                    format!("  {line}")
                });
            }
            match repro_lane::alternative(work_dir, &record, &refusal) {
                Some(command) => {
                    lines.push("Reproduce it with:".to_owned());
                    lines.push(format!("  {command}"));
                }
                None => lines.push("No offline reproducer is available.".to_owned()),
            }
        }
    }
    // A Windows harness needs its sanitizer runtime DLL directory on PATH;
    // replay.py adds it, a direct run of the binary has to as well.
    let harness_id = str_at(&f.raw, "/harness_id").unwrap_or_default();
    if !harness_id.is_empty() {
        let sidecar = crate::auto::layout::harness_dir(work_dir, harness_id)
            .join(crate::build::RUNTIME_PATH_FILE);
        if let Ok(text) = std::fs::read_to_string(&sidecar) {
            let dirs: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            if !dirs.is_empty() {
                lines.push(
                    "To run the harness binary directly, first put its sanitizer runtime on PATH:"
                        .to_owned(),
                );
                lines.push(format!("  $env:Path = \"{};$env:Path\"", dirs.join(";")));
            }
        }
    }
    let asan = str_at(&f.raw, "/exception/sanitizer") == Some("asan");
    if asan && repro_lane::assess(work_dir, &record, Tool::Cartography).is_ok() {
        lines.push(format!(
            "bhf cartography --work-dir {work} --finding-id {}   # which input bytes steer the access",
            f.id
        ));
    }
    lines
}

/// The HARNESS ARGUMENTS section: the value the harness decoded for each
/// parameter, from the argument trace recorded in `decoded.json`, or why there
/// is none and how to get it. A parameter whose input bytes a recorded
/// comparison read is tagged `[compared at <site>]`.
fn argument_lines(work_dir: &Path, f: &Finding, evidence: &Evidence) -> Vec<String> {
    let Some(decoded) = read_json(&f.dir.join("decoded.json")) else {
        return Vec::new();
    };
    let args: Vec<corpus::decoded_args::TracedArg> = decoded
        .get("arguments")
        .cloned()
        .and_then(|args| serde_json::from_value(args).ok())
        .unwrap_or_default();
    let mut lines = vec!["\nHARNESS ARGUMENTS  (what each parameter was decoded to)".to_owned()];
    if args.is_empty() {
        let reason = decoded
            .get("arguments_unavailable")
            .and_then(Value::as_str)
            .unwrap_or("no argument trace was recorded for this finding");
        for line in wrap(&format!("not recorded: {reason}."), 76) {
            lines.push(format!("  {line}"));
        }
        if f.raw
            .get("exception")
            .and_then(|e| e.get("sanitizer"))
            .is_some()
        {
            lines.push(format!(
                "  bhf replay --show-args {}   # re-run the harness with the trace",
                crate::repro_lane::sh_word(&f.dir.to_string_lossy())
            ));
        }
        return lines;
    }
    let (tags, tag_note) = comparison_tags(work_dir, f, evidence, &args);
    lines.extend(
        corpus::decoded_args::render_table(&args)
            .into_iter()
            .enumerate()
            .map(|(row, line)| {
                // Row 0 is the header; row k + 1 is argument k.
                match row
                    .checked_sub(1)
                    .and_then(|k| tags.get(k))
                    .and_then(Option::as_ref)
                {
                    Some(tag) => format!("  {line}  {tag}"),
                    None => format!("  {line}"),
                }
            }),
    );
    lines.push(
        "  (bytes are [start..end) offsets in testcase.bin; parameters whose ranges overlap \
         were decoded from the same bytes)"
            .to_owned(),
    );
    if let Some(note) = tag_note {
        for (index, line) in wrap(&note, 74).into_iter().enumerate() {
            lines.push(format!("{}{line}", if index == 0 { "  " } else { "    " }));
        }
    }
    lines
}

/// Most comparison sites a `[compared at ...]` tag names.
const MAX_TAG_SITES: usize = 3;

/// Per traced argument, the `[compared at <site>, ...]` tag when one of the
/// recorded comparisons read its input bytes, and a note on how the
/// comparisons' offsets were related to the arguments. The trace's spans
/// index testcase.bin; evidence recorded on another file (min_testcase.bin)
/// is related through the harness's `arg-layout.json` decoded over that file,
/// or not at all without one.
fn comparison_tags(
    work_dir: &Path,
    f: &Finding,
    evidence: &Evidence,
    args: &[corpus::decoded_args::TracedArg],
) -> (Vec<Option<String>>, Option<String>) {
    let none = vec![None; args.len()];
    let Some(capture) = evidence.capture.as_ref().filter(|c| !c.gates.is_empty()) else {
        return (none, None);
    };
    let input = capture.summary.input.as_str();
    let same_bytes = input == "testcase.bin"
        || std::fs::read(f.dir.join(input)).ok() == std::fs::read(f.dir.join("testcase.bin")).ok();
    let (spans, note): (Vec<Option<std::ops::Range<u64>>>, Option<String>) = if same_bytes {
        (args.iter().map(|arg| arg.byte_range()).collect(), None)
    } else {
        let layout = str_at(&f.raw, "/harness_id").and_then(|id| {
            crate::auto::layout::harness_dir_candidates(work_dir, id)
                .into_iter()
                .find_map(|dir| harness_gen::arg_layout::ArgLayout::read(&dir)?.ok())
        });
        let bytes = std::fs::read(f.dir.join(input)).ok();
        match (layout, bytes) {
            (Some(layout), Some(bytes)) => {
                let decoded = layout.decode(&bytes);
                let spans = args
                    .iter()
                    .map(|arg| {
                        decoded
                            .iter()
                            .find(|d| {
                                d.name == arg.name
                                    && d.call == arg.call
                                    && i64::try_from(d.index).ok() == Some(arg.index)
                            })
                            .and_then(|d| d.span)
                            .map(|[start, end]| start..end)
                    })
                    .collect();
                (
                    spans,
                    Some(format!(
                        "(comparison tags use each parameter's bytes in {input}, decoded with the \
                         harness's arg-layout.json)"
                    )),
                )
            }
            _ => {
                return (
                    none,
                    Some(format!(
                        "(the comparison evidence indexes {input} and these spans index \
                         testcase.bin; without the harness's arg-layout.json the comparisons are \
                         not related to the parameters)"
                    )),
                )
            }
        }
    };
    let tags = spans
        .iter()
        .map(|span| {
            let span = span.as_ref().filter(|span| span.start < span.end)?;
            let mut sites: Vec<String> = Vec::new();
            for gate in &capture.gates {
                let (start, end) = (gate.offset as u64, (gate.offset + gate.len) as u64);
                if start < span.end && span.start < end {
                    let site = match &gate.location {
                        Some(location) => match location.line {
                            Some(line) => format!("{}:{line}", basename(&location.file)),
                            None => basename(&location.file).to_owned(),
                        },
                        None => gate.site.clone(),
                    };
                    if !sites.contains(&site) {
                        sites.push(site);
                    }
                }
            }
            if sites.is_empty() {
                return None;
            }
            let more = sites.len().saturating_sub(MAX_TAG_SITES);
            sites.truncate(MAX_TAG_SITES);
            let more = if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            };
            Some(format!("[compared at {}{more}]", sites.join(", ")))
        })
        .collect();
    (tags, note)
}

/// The sanitizer's structured memory access (`exception.access`) as text: the
/// direction and width, the region it hit, and where that region was
/// allocated and freed (runtime and allocator frames skipped).
fn access_lines(access: &Value) -> Vec<String> {
    let text = |key: &str| access.get(key).and_then(Value::as_str);
    let mut head = match text("direction") {
        Some(direction @ ("read" | "write")) => direction.to_owned(),
        _ => "unknown-direction access".to_owned(),
    };
    if let Some(size) = access.get("size").and_then(Value::as_u64) {
        let _ = write!(head, " of {size} byte(s)");
    }
    match access.get("region") {
        Some(region) => head.push_str(&region_phrase(region)),
        None => {
            if let Some(address) = text("address") {
                let _ = write!(head, " at {address}");
            }
            if let Some(hint) = text("address_hint") {
                let _ = write!(head, " ({hint})");
            }
        }
    }
    let mut lines = vec![format!("  Access: {head}")];
    // The traced parameter whose buffer the access hit (see `decoded_args`).
    if let Some(parameter) = access.get("parameter") {
        let name = parameter.get("name").and_then(Value::as_str).unwrap_or("?");
        let offset = parameter
            .get("offset")
            .map(Value::to_string)
            .unwrap_or_default();
        lines.push(match parameter.get("basis").and_then(Value::as_str) {
            Some("region_start") => {
                format!("    the region is parameter `{name}`'s buffer (access at offset {offset})")
            }
            Some("region_interior") => format!(
                "    parameter `{name}`'s buffer starts inside the region (access at offset \
                 {offset} from it)"
            ),
            _ => format!(
                "    {offset} byte(s) past parameter `{name}` (the nearest traced pointer below \
                 the faulting address)"
            ),
        });
    }
    let stack_object = access.pointer("/region/kind").and_then(Value::as_str) == Some("stack");
    let alloc_verb = if stack_object {
        "in the frame of"
    } else {
        "allocated at"
    };
    for (verb, key) in [(alloc_verb, "alloc_stack"), ("freed at", "free_stack")] {
        let chain = project_chain(access.get(key));
        if !chain.is_empty() {
            lines.push(format!("    {verb} {chain}"));
        }
    }
    lines
}

/// `, 0 byte(s) after a 5-byte heap region (offset 5)`.
fn region_phrase(region: &Value) -> String {
    let text = |key: &str| region.get(key).and_then(Value::as_str);
    let kind = text("kind").unwrap_or("memory");
    let sized = match region.get("size").and_then(Value::as_u64) {
        Some(size) => format!("{size}-byte {kind}"),
        None => kind.to_owned(),
    };
    let object = match text("variable") {
        Some(variable) => format!("the {sized} variable `{variable}`"),
        None if kind == "heap" => format!("a {sized} region"),
        None => format!("a {sized} object"),
    };
    let mut phrase = match (
        region.get("distance").and_then(Value::as_u64),
        text("relation"),
    ) {
        (Some(distance), Some(relation)) => format!(", {distance} byte(s) {relation} {object}"),
        _ => format!(", in {object}"),
    };
    if let Some(offset) = region.get("offset").and_then(Value::as_i64) {
        let _ = write!(phrase, " (offset {offset})");
    }
    phrase
}

/// Up to three frames of an allocation or free stack, `f (file:line) <- g`,
/// skipping allocator, libc and sanitizer-runtime frames.
fn project_chain(stack: Option<&Value>) -> String {
    stack
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|frame| {
            let function = frame.get("function").and_then(Value::as_str)?.trim();
            let file = frame.get("file").and_then(Value::as_str);
            if function.is_empty() || actionability::is_runtime_noise_frame(function, file) {
                return None;
            }
            Some(match (file, frame.get("line").and_then(Value::as_u64)) {
                (Some(file), Some(line)) => format!("{function} ({}:{line})", basename(file)),
                (Some(file), None) => format!("{function} ({})", basename(file)),
                _ => function.to_owned(),
            })
        })
        .take(3)
        .collect::<Vec<_>>()
        .join(" <- ")
}

/// The target function a harness was generated for (`name` in its
/// `result.json`), or `None`.
fn harness_target_name(work_dir: &Path, harness_id: &str) -> Option<String> {
    if harness_id.is_empty() {
        return None;
    }
    crate::auto::layout::harness_dir_candidates(work_dir, harness_id)
        .into_iter()
        .find_map(|dir| read_json(&dir.join("result.json")))
        .and_then(|result| {
            result
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
        })
}

/// Distinct env/resource interactions the shim virtualized, as narrative lines.
/// Byte-origin taint (#422) is surfaced where present — it is the machine-checked
/// link from an input byte to a sink operand.
fn summarize_env(events: &[RuntraceEvent]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for ev in events {
        let line = match ev {
            RuntraceEvent::EnvVarAccess { name, .. } => {
                format!("getenv {name} → served (value withheld)")
            }
            RuntraceEvent::EnvVarMissing { name, .. } => format!("getenv {name} → served empty"),
            RuntraceEvent::FileOpened {
                path, taint_offset, ..
            } => taint_note("opened file", path, *taint_offset),
            RuntraceEvent::FileMissing {
                path, taint_offset, ..
            } => taint_note("probed missing file", path, *taint_offset),
            RuntraceEvent::PathChecked { path, .. } => format!("access-checked {path}"),
            RuntraceEvent::NetworkUnreachable { address, .. } => {
                format!("connect {address} → refused (offline)")
            }
            RuntraceEvent::DlopenFailed { library } => format!("dlopen {library} → NULL"),
            RuntraceEvent::CommandExecuted { command, .. } => {
                format!("executed command: {command}")
            }
            RuntraceEvent::FormatString {
                format, controlled, ..
            } => {
                let tag = if *controlled {
                    " (INPUT-CONTROLLED)"
                } else {
                    ""
                };
                format!("format string{tag}: {format}")
            }
            _ => continue,
        };
        if seen.insert(line.clone()) {
            lines.push(line);
        }
        if lines.len() >= 20 {
            break;
        }
    }
    lines
}

/// A resource-interaction line, annotated with byte-origin taint when the path was
/// derived from the fuzz input.
fn taint_note(verb: &str, path: &str, taint: Option<u32>) -> String {
    match taint {
        Some(off) => format!("{verb} {path}  ← input byte {off} controls this path"),
        None => format!("{verb} {path}"),
    }
}

/// The harness's fuzz dictionary (`dictionary.txt`), parsed by the engine's
/// own AFL dictionary parser. Empty when the harness has none.
fn load_dictionary(work_dir: &Path, harness_id: &str) -> Vec<Vec<u8>> {
    if harness_id.is_empty() {
        return Vec::new();
    }
    let path = crate::auto::layout::harness_dir(work_dir, harness_id).join("dictionary.txt");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| crate::fuzz::parse_afl_dictionary_line(line).ok().flatten())
        .filter(|token| !token.is_empty())
        .collect()
}

/// Dictionary tokens shorter than this match almost any input by chance.
const MIN_TOKEN_LEN: usize = 3;
/// A token found more often than this is too common to say anything.
const MAX_TOKEN_HITS: usize = 3;
/// Dictionary tokens listed at most.
const MAX_TOKENS_SHOWN: usize = 8;

/// Dictionary tokens that occur in the input, as `(printable token, first
/// offset, occurrences)`, in input order. A plain substring search, so it is
/// labelled as such: short tokens and tokens found more than
/// [`MAX_TOKEN_HITS`] times are left out.
fn dictionary_tokens_present(input: &[u8], dict: &[Vec<u8>]) -> Vec<(String, usize, usize)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for token in dict {
        if token.len() < MIN_TOKEN_LEN || token.len() > input.len() || !seen.insert(token) {
            continue;
        }
        let hits: Vec<usize> = input
            .windows(token.len())
            .enumerate()
            .filter(|(_, window)| window == token)
            .map(|(offset, _)| offset)
            .collect();
        if let Some(&first) = hits.first() {
            if hits.len() <= MAX_TOKEN_HITS {
                out.push((render_token(token), first, hits.len()));
            }
        }
    }
    out.sort_by_key(|(_, first, _)| *first);
    out.truncate(MAX_TOKENS_SHOWN);
    out
}

/// `min_testcase.bin, 5 byte(s), minimized from 4194` or `testcase.bin, 12
/// byte(s), not minimized`.
fn input_label(finding_dir: &Path, name: &str, len: usize) -> String {
    if name == "min_testcase.bin" {
        match std::fs::metadata(finding_dir.join("testcase.bin")) {
            Ok(original) => format!(
                "{name}, {len} byte(s), minimized from {} byte(s)",
                original.len()
            ),
            Err(_) => format!("{name}, {len} byte(s), minimized"),
        }
    } else {
        format!("{name}, {len} byte(s), not minimized")
    }
}

/// What is known about where the input came from: one of bhf's built-in
/// starting inputs, or a byte-identical copy of a seed the run listed in
/// `auto/seeds.json`.
fn input_origin(work_dir: &Path, bytes: &[u8]) -> Vec<String> {
    let mut notes = Vec::new();
    if matches!(bytes, b"" | b"A" | b"AAAAAAAA") {
        notes.push(
            "This is one of bhf's built-in starting inputs (empty, \"A\" or \"AAAAAAAA\"): \
             the crash needed no mutation."
                .to_owned(),
        );
    }
    if bytes.is_empty() {
        notes.push(
            "The input is empty: every scalar parameter decodes to 0 and every buffer is empty."
                .to_owned(),
        );
        return notes;
    }
    let digest = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let manifest = crate::auto::seed_manifest::manifest_path(work_dir);
    if let Some(seed) = read_json(&manifest)
        .as_ref()
        .and_then(|m| m.get("seeds"))
        .and_then(Value::as_array)
        .and_then(|seeds| {
            seeds
                .iter()
                .find(|seed| seed.get("sha256").and_then(Value::as_str) == Some(digest.as_str()))
                .cloned()
        })
    {
        let source = match seed.get("source").and_then(Value::as_str) {
            Some("user") => "your seed",
            _ => "the seed mined from",
        };
        let path = seed.get("path").and_then(Value::as_str).unwrap_or("?");
        notes.push(format!(
            "This input is byte-identical to {source} {path}: the crash needed no mutation of it."
        ));
    }
    notes
}

/// Comparison evidence for a finding's input, and the environment the
/// replay that recorded it touched.
struct Evidence {
    capture: Option<Capture>,
    /// The capture was recorded just now, by explain, rather than stored.
    recorded_now: bool,
    /// Why there is no capture.
    missing: Option<String>,
    /// The runtrace events of the capture's own replay, when the shim ran.
    own_events: Option<Vec<RuntraceEvent>>,
}

/// Time one explain run spends replaying findings that have no recorded
/// comparison evidence.
const LAZY_CAPTURE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// The finding's stored capture when it covers the input shown, else one
/// recorded now by replaying that input against its harness.
fn comparison_evidence(work_dir: &Path, f: &Finding, input: Option<&(&str, Vec<u8>)>) -> Evidence {
    let Some((name, bytes)) = input else {
        return Evidence {
            capture: None,
            recorded_now: false,
            missing: Some("the finding has no input file".to_owned()),
            own_events: None,
        };
    };
    if let Some(capture) = gate_evidence::recorded(&f.raw)
        .filter(|c| c.summary.input == *name && c.summary.input_len == bytes.len())
    {
        let log = f.dir.join(gate_evidence::FINDING_RUNTRACE);
        let own_events = (capture.summary.shim_armed && log.is_file()).then(|| parsed_events(&log));
        return Evidence {
            capture: Some(capture),
            recorded_now: false,
            missing: None,
            own_events,
        };
    }
    let Some(harness) = gate_evidence::harness_for_finding(work_dir, &f.dir, &f.raw) else {
        return Evidence {
            capture: None,
            recorded_now: false,
            missing: Some(
                "none was recorded for this finding, and its harness binary was not found to \
                 record it now"
                    .to_owned(),
            ),
            own_events: None,
        };
    };
    // One explain run replays for at most LAZY_CAPTURE_BUDGET in all.
    static STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let started = *STARTED.get_or_init(std::time::Instant::now);
    let budget_end = started + LAZY_CAPTURE_BUDGET;
    if std::time::Instant::now() >= budget_end {
        return Evidence {
            capture: None,
            recorded_now: false,
            missing: Some(
                "none was recorded for this finding, and this explain run spent its replay \
                 budget on earlier findings; `bhf report --backfill` records it"
                    .to_owned(),
            ),
            own_events: None,
        };
    }
    let Ok(scratch) = tempfile::tempdir() else {
        return Evidence {
            capture: None,
            recorded_now: false,
            missing: Some("no scratch directory to replay the input in".to_owned()),
            own_events: None,
        };
    };
    let log = scratch.path().join("runtrace.jsonl");
    let replay = gate_evidence::Replay {
        harness: &harness,
        raw: &f.raw,
        scratch: scratch.path().join("replay"),
        runtrace_log: Some(log.clone()),
        deadline: (std::time::Instant::now() + gate_evidence::PER_FINDING).min(budget_end),
    };
    let capture = gate_evidence::capture(&replay, bytes, name);
    let own_events = (capture.summary.shim_armed && log.is_file()).then(|| parsed_events(&log));
    Evidence {
        capture: Some(capture),
        recorded_now: true,
        missing: None,
        own_events,
    }
}

/// The comparison-evidence lines under THE INPUT THAT TRIGGERS IT.
fn evidence_lines(evidence: &Evidence, input_name: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let push_wrapped = |lines: &mut Vec<String>, text: &str, first: &str, rest: &str| {
        for (index, line) in wrap(text, 74).into_iter().enumerate() {
            lines.push(format!("{}{line}", if index == 0 { first } else { rest }));
        }
    };
    let Some(capture) = &evidence.capture else {
        let reason = evidence.missing.as_deref().unwrap_or("none was recorded");
        push_wrapped(
            &mut lines,
            &format!("No comparison evidence recorded: {reason}."),
            "  ",
            "    ",
        );
        return lines;
    };
    if capture.gates.is_empty() {
        let reason = capture
            .summary
            .reason
            .as_deref()
            .unwrap_or("no comparison operand came from the input");
        push_wrapped(
            &mut lines,
            &format!("No comparison evidence recorded for {input_name}: {reason}."),
            "  ",
            "    ",
        );
    } else {
        let how = if evidence.recorded_now {
            "recorded now by replaying it"
        } else {
            "recorded when the finding was saved"
        };
        lines.push(format!(
            "  Comparison evidence for this input ({input_name}, {how}):"
        ));
        for gate in &capture.gates {
            push_wrapped(&mut lines, &gate_line(gate), "    ", "      ");
        }
    }
    if capture.summary.unconfirmed > 0 {
        push_wrapped(
            &mut lines,
            &format!(
                "({} more operand(s) occur in the input but did not change when those input \
                 bytes did, or were not checked within the replay budget; they are not \
                 evidence.)",
                capture.summary.unconfirmed
            ),
            "  ",
            "   ",
        );
    }
    if capture.summary.truncated {
        lines.push(
            "  (More comparisons were made than the driver keeps (8192); later ones are missing.)"
                .to_owned(),
        );
    }
    lines
}

/// `bytes 0..5 "WIDGET" reach strcmp at parse.c:12 in parse_record, compared
/// with "WIDGET" (equal)`.
fn gate_line(gate: &Gate) -> String {
    let (span, reach, feed) = if gate.len == 1 {
        (format!("byte {}", gate.offset), "reaches", "feeds")
    } else {
        (
            format!("bytes {}..{}", gate.offset, gate.offset + gate.len),
            "reach",
            "feed",
        )
    };
    let site = match &gate.location {
        Some(location) => {
            let at = match location.line {
                Some(line) => format!("{}:{line}", basename(&location.file)),
                None => basename(&location.file).to_owned(),
            };
            match location.function.as_deref() {
                Some(function) => format!(" at {at} in {function}"),
                None => format!(" at {at}"),
            }
        }
        None => format!(" at {}", gate.site),
    };
    let token = |hex: &str| render_token(&decode_hex(hex));
    let outcome = if gate.operands_equal {
        "equal"
    } else {
        "not equal"
    };
    match gate.relation.as_str() {
        "derived" => format!(
            "{span} {feed} {}{site}: operand {} compared with {} ({outcome}; the operand is \
             computed from these bytes and changed when they did)",
            gate.cmp_kind,
            token(&gate.operand_hex),
            token(&gate.compared_with_hex)
        ),
        relation => format!(
            "{span} {} {reach} {}{site}, compared with {} ({outcome}{})",
            token(&gate.operand_hex),
            gate.cmp_kind,
            token(&gate.compared_with_hex),
            if relation == "byte_swapped" {
                "; read big-endian"
            } else {
                ""
            }
        ),
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

/// The FAKED ENVIRONMENT section: where its events come from (`None` when
/// none were observed) and its lines.
fn environment(
    work_dir: &Path,
    f: &Finding,
    harness_id: &str,
    evidence: &Evidence,
) -> (Option<String>, Vec<String>) {
    if let (Some(events), Some(capture)) = (&evidence.own_events, &evidence.capture) {
        let lines = summarize_env(events);
        let source = format!(
            "observed while replaying {} with the runtrace shim",
            capture.summary.input
        );
        if lines.is_empty() {
            return (
                Some(source),
                vec![
                    "the replay touched no external resource the runtrace shim watches".to_owned(),
                ],
            );
        }
        return (Some(source), lines);
    }
    let shim_armed = f
        .raw
        .pointer("/runtime_mode/shim_armed")
        .and_then(Value::as_bool);
    if shim_armed == Some(false) {
        return (
            None,
            vec!["environment not observed (runtrace shim not loaded)".to_owned()],
        );
    }
    let events = if harness_id.is_empty() {
        Vec::new()
    } else {
        load_events(work_dir, harness_id)
    };
    let lines = summarize_env(&events);
    let campaign = "runtrace events of the harness's last fuzz pass, across all of its inputs, \
                    not only this one"
        .to_owned();
    if !lines.is_empty() {
        return (Some(campaign), lines);
    }
    match shim_armed {
        Some(true) => (
            Some(campaign),
            vec![
                "the last fuzz pass touched no external resource the runtrace shim watches"
                    .to_owned(),
            ],
        ),
        _ => (
            None,
            vec![
                "environment not observed (no runtrace events were recorded; the runtrace shim \
                 may not have been loaded)"
                    .to_owned(),
            ],
        ),
    }
}

fn parsed_events(log: &Path) -> Vec<RuntraceEvent> {
    let mut events = runtrace::parse_log(log).unwrap_or_default();
    runtrace::dedupe_in_place(&mut events);
    events
}

/// Render a token as `"printable"` or `\xNN` bytes.
fn render_token(tok: &[u8]) -> String {
    if tok.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        format!("\"{}\"", String::from_utf8_lossy(tok))
    } else {
        let hex: Vec<String> = tok.iter().map(|b| format!("\\x{b:02x}")).collect();
        hex.join("")
    }
}

fn load_events(work_dir: &Path, harness_id: &str) -> Vec<RuntraceEvent> {
    parsed_events(&crate::auto::layout::harness_dir(work_dir, harness_id).join("runtrace.jsonl"))
}

/// Collapse consecutive duplicate frames (`handle → handle` → `handle`).
fn dedup_chain<'a>(frames: &[&'a str]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for f in frames {
        if out.last() != Some(f) {
            out.push(f);
        }
    }
    out
}

fn humanize_prov(p: &str) -> &str {
    match p {
        "real_defect" => "real_defect (independent of every injected build-recovery stub)",
        "stub_artifact" => "stub_artifact (the crash needed a value a recovery stub fabricated)",
        other => other,
    }
}

/// Wrap text to `width` columns on whitespace.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// A compact hex+ascii dump, capped to `max_rows` rows of 16 bytes.
fn hexdump(bytes: &[u8], max_rows: usize) -> Vec<String> {
    let mut rows = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        if i >= max_rows {
            rows.push(format!("... ({} more byte(s))", bytes.len() - i * 16));
            break;
        }
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        rows.push(format!("{:04x}  {:<47}  {ascii}", i * 16, hex.join(" ")));
    }
    rows
}

fn basename(p: &str) -> &str {
    Path::new(p)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(p)
}

fn str_at<'a>(v: &'a Value, ptr: &str) -> Option<&'a str> {
    v.pointer(ptr).and_then(Value::as_str)
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frameless_finding(dir: &Path) -> Finding {
        Finding {
            id: "F-0001-0a0b0c0d".to_owned(),
            dir: dir.to_path_buf(),
            raw: serde_json::json!({
                "id": "F-0001-0a0b0c0d",
                "rule_id": "BHF-210",
                "harness_id": "H-C0001",
                "classification": "unhandled",
                "exception": {
                    "name": "UBSAN_UNDEFINED_BEHAVIOR",
                    "sanitizer": "ubsan",
                    "message": "/src/widget/classify.c:3:5: runtime error: execution reached the end of a value-returning function without returning a value",
                    "stack": []
                },
                "actionability": {
                    "sink": { "file": "/src/widget/classify.c", "line": 3, "function": "" }
                }
            }),
        }
    }

    /// A report with no stack names a source position but no function: the
    /// Sink line must not render an empty `()`. It names the harness target the
    /// fault was reached through, else the location alone, and the sanitizer's
    /// own report line says what happened.
    #[test]
    fn a_sink_without_a_function_name_never_renders_empty_parens() {
        let work = tempfile::tempdir().unwrap();
        let finding_dir = work.path().join("results/findings/F-0001-0a0b0c0d");
        std::fs::create_dir_all(&finding_dir).unwrap();
        let finding = frameless_finding(&finding_dir);

        let out = explain_one(work.path(), &finding, &[], false);
        assert!(!out.contains("()"), "{out}");
        assert!(out.contains("  Sink: classify.c:3\n"), "{out}");
        assert!(out.contains("  Harness: H-C0001\n"), "{out}");
        assert!(
            out.contains("execution reached the end of a value-returning function"),
            "the exact report line is shown: {out}"
        );

        let harness = crate::auto::layout::harness_dir(work.path(), "H-C0001");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(
            harness.join("result.json"),
            br#"{"harness_id":"H-C0001","name":"classify_pair"}"#,
        )
        .unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains("  Sink: reached via `classify_pair` at classify.c:3\n"),
            "{out}"
        );
        assert!(!out.contains("()"), "{out}");
    }

    fn write_finding(work: &Path, id: &str, harness_id: &str, group: &str) {
        let dir = corpus::layout::findings_dir(work).join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let raw = serde_json::json!({
            "id": id,
            "rule_id": "BHF-214",
            "harness_id": harness_id,
            "classification": "unhandled",
            "cluster_key_full": group,
            "exception": {"name": "UBSAN_MISSING_RETURN", "sanitizer": "ubsan"},
            "actionability": {
                "sink": {"file": "/src/widget/classify.c", "line": 3, "function": "classify"}
            }
        });
        std::fs::write(dir.join("finding.json"), raw.to_string()).unwrap();
    }

    /// Findings of one root cause reached through different harnesses are one
    /// block by default, naming every member and its harness; distinct root
    /// causes stay separate, and `--all-members` explains each finding.
    #[test]
    fn findings_of_one_root_cause_are_explained_once_with_their_harnesses() {
        let work = tempfile::tempdir().unwrap();
        write_finding(work.path(), "F-0001-aaaaaaaa", "H-C0001", "site-a");
        write_finding(work.path(), "F-0002-bbbbbbbb", "H-C0002", "site-a");
        write_finding(work.path(), "F-0003-cccccccc", "H-C0003", "site-b");
        let harness = crate::auto::layout::harness_dir(work.path(), "H-C0002");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(
            harness.join("result.json"),
            br#"{"harness_id":"H-C0002","name":"classify_with_bias"}"#,
        )
        .unwrap();

        let blocks = render(work.path(), None, false).unwrap();
        assert_eq!(blocks.len(), 2, "{blocks:#?}");
        assert!(
            blocks[0].starts_with("━━━ F-0001-aaaaaaaa"),
            "{}",
            blocks[0]
        );
        assert!(blocks[0].contains("  Harness: H-C0001\n"), "{}", blocks[0]);
        assert!(
            blocks[0].contains("F-0002-bbbbbbbb (H-C0002, `classify_with_bias`)"),
            "{}",
            blocks[0]
        );
        assert!(blocks[0].contains("--all-members"), "{}", blocks[0]);
        assert!(
            blocks[1].starts_with("━━━ F-0003-cccccccc"),
            "{}",
            blocks[1]
        );
        assert!(!blocks[1].contains("Root cause shared"), "{}", blocks[1]);

        let every = render(work.path(), None, true).unwrap();
        assert_eq!(every.len(), 3);
        assert!(
            every[1].contains("  Harness: H-C0002 (`classify_with_bias`)\n"),
            "{}",
            every[1]
        );
        assert!(
            every[1].contains("F-0001-aaaaaaaa (H-C0001)"),
            "{}",
            every[1]
        );
        assert!(!every[1].contains("--all-members"), "{}", every[1]);

        // Asking for one member explains that member, with its group.
        let one = render(work.path(), Some("F-0002-bbbbbbbb"), false).unwrap();
        assert_eq!(one.len(), 1);
        assert!(one[0].starts_with("━━━ F-0002-bbbbbbbb"), "{}", one[0]);
        assert!(one[0].contains("F-0001-aaaaaaaa (H-C0001)"), "{}", one[0]);
    }

    /// The decoded arguments recorded in decoded.json are tabulated, and the
    /// access names the parameter whose buffer it hit.
    #[test]
    fn the_harness_arguments_are_tabulated_and_the_accessed_parameter_named() {
        let work = tempfile::tempdir().unwrap();
        let mut finding = frameless_finding(work.path());
        let args = corpus::decoded_args::parse_arg_trace(
            "BHF_ARG {\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"data\",\"type\":\"const unsigned char *\",\"span\":[4,9],\"ptr\":\"0x502000000030\",\"alloc_size\":8,\"len\":5,\"preview_hex\":\"5a3c99012e\"}\n\
             BHF_ARG {\"call\":\"target\",\"i\":1,\"role\":\"param\",\"name\":\"bit_index\",\"type\":\"unsigned int\",\"span\":[0,4],\"value\":\"305419896\"}\n",
        );
        corpus::decoded_args::record_trace(
            work.path(),
            &[0x78, 0x56, 0x34, 0x12, 0x5a, 0x3c, 0x99, 0x01, 0x2e],
            &corpus::decoded_args::TraceOutcome::Traced(args),
        )
        .expect_err("no finding.json yet: decoded.json is still written");
        finding.raw["exception"]["access"] = serde_json::json!({
            "direction": "read",
            "size": 1,
            "address": "0x502000000038",
            "region": {"kind": "heap", "size": 8, "offset": 8, "relation": "after", "distance": 0},
            "parameter": {"name": "data", "offset": 8, "basis": "region_start"}
        });
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(out.contains("\nHARNESS ARGUMENTS"), "{out}");
        let data = out
            .lines()
            .find(|line| line.trim_start().starts_with("data "))
            .unwrap_or_else(|| panic!("no data row in:\n{out}"));
        assert!(data.contains("const unsigned char *"), "{data}");
        assert!(data.contains("4..9"), "{data}");
        assert!(data.contains("len 5, alloc 8"), "{data}");
        assert!(data.contains("5a3c99012e"), "{data}");
        assert!(out.contains("305419896"), "{out}");
        assert!(
            out.contains("    the region is parameter `data`'s buffer (access at offset 8)\n"),
            "{out}"
        );
        finding.raw["exception"]["access"]["parameter"] =
            serde_json::json!({"name": "data", "offset": 5, "basis": "region_interior"});
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains(
                "    parameter `data`'s buffer starts inside the region (access at offset 5 from it)\n"
            ),
            "{out}"
        );
    }

    /// A harness argument whose input bytes a recorded comparison read is
    /// tagged with the comparison's site, in the file the evidence indexes.
    #[test]
    fn arguments_compared_by_the_target_are_tagged_with_the_site() {
        let work = tempfile::tempdir().unwrap();
        let gate = |offset: u64, len: u64, location: Option<(&str, u64)>| {
            let mut gate = serde_json::json!({"offset": offset, "len": len,
                "operand_hex": "41", "compared_with_hex": "41", "cmp_kind": "cmp",
                "site": "0x1a2b", "relation": "equal", "operands_equal": true});
            if let Some((file, line)) = location {
                gate["location"] = serde_json::json!({"file": file, "line": line,
                    "function": "read_bits"});
            }
            gate
        };
        let mut raw = recorded_capture(
            serde_json::json!([gate(1, 2, Some(("/src/demo/bits.c", 12))), gate(9, 1, None)]),
            None,
        );
        raw["gate_capture"]["input_len"] = serde_json::json!(10);
        let finding = finding_in(work.path(), raw);
        let input = [0x78, 0x56, 0x34, 0x12, 0x5a, 0x3c, 0x99, 0x01, 0x2e, 0x00];
        std::fs::write(finding.dir.join("testcase.bin"), input).unwrap();
        let args = corpus::decoded_args::parse_arg_trace(
            "BHF_ARG {\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"bit_index\",\"type\":\"unsigned int\",\"span\":[0,4],\"value\":\"305419896\"}\n\
             BHF_ARG {\"call\":\"target\",\"i\":1,\"role\":\"param\",\"name\":\"width\",\"type\":\"unsigned int\",\"span\":[4,8],\"value\":\"7\"}\n\
             BHF_ARG {\"call\":\"target\",\"i\":2,\"role\":\"param\",\"name\":\"data\",\"type\":\"const unsigned char *\",\"span\":[8,10],\"len\":2,\"preview_hex\":\"2e00\"}\n",
        );
        corpus::decoded_args::record_trace(
            &finding.dir,
            &input,
            &corpus::decoded_args::TraceOutcome::Traced(args),
        )
        .expect_err("no finding.json: decoded.json is still written");
        let out = explain_one(work.path(), &finding, &[], false);
        let row = |name: &str| {
            out.lines()
                .find(|line| line.trim_start().starts_with(&format!("{name} ")))
                .unwrap_or_else(|| panic!("no {name} row in:\n{out}"))
                .to_owned()
        };
        assert!(
            row("bit_index").ends_with("[compared at bits.c:12]"),
            "{out}"
        );
        assert!(!row("width").contains("compared at"), "{out}");
        assert!(row("data").ends_with("[compared at 0x1a2b]"), "{out}");

        // Evidence recorded on the minimized input is related to the
        // parameters through the harness's layout of that file.
        let mut raw = finding.raw.clone();
        raw["gate_capture"]["input"] = serde_json::json!("min_testcase.bin");
        raw["gate_capture"]["input_len"] = serde_json::json!(6);
        raw["gates"] = serde_json::json!([gate(5, 1, Some(("/src/demo/bits.c", 20)))]);
        let finding = Finding { raw, ..finding };
        std::fs::write(finding.dir.join("min_testcase.bin"), [0u8; 6]).unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains("min_testcase.bin") && !out.contains("[compared at bits.c:20]"),
            "without a layout nothing is tagged: {out}"
        );
        let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("comparisons are not related to the parameters"),
            "{out}"
        );
        let harness = crate::auto::layout::harness_dir(work.path(), "H-C0001");
        std::fs::create_dir_all(&harness).unwrap();
        let scalar = |name: &str, index: usize| {
            serde_json::json!({"step": "param", "call": "target", "role": "param", "index": index,
                "name": name, "type": "unsigned int", "order": index, "input": "cursor",
                "decoder": "scalar", "primitive": "bhf_i32", "width": 4,
                "value_kind": "u32", "static_decode": true})
        };
        std::fs::write(
            harness.join("arg-layout.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": "bhf.arg-layout.v1", "harness_format_version": 3,
                "language": "c", "harness": "direct", "static_decode": true,
                "steps": [scalar("bit_index", 0), scalar("width", 1),
                    {"step": "remainder", "call": "target", "sized": false},
                    {"step": "param", "call": "target", "role": "param", "index": 2,
                     "name": "data", "type": "const unsigned char *", "order": 2,
                     "input": "remainder", "decoder": "input_buffer", "static_decode": true}]
            }))
            .unwrap(),
        )
        .unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let width = out
            .lines()
            .find(|line| line.trim_start().starts_with("width "))
            .unwrap()
            .to_owned();
        assert!(width.ends_with("[compared at bits.c:20]"), "{out}");
        let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains(
                "(comparison tags use each parameter's bytes in min_testcase.bin, decoded with \
                 the harness's arg-layout.json)"
            ),
            "{out}"
        );
    }

    /// Without a recorded trace the section says why and how to get one.
    #[test]
    fn missing_harness_arguments_say_how_to_trace_them() {
        let work = tempfile::tempdir().unwrap();
        let finding = frameless_finding(work.path());
        corpus::decoded_args::record_trace(
            work.path(),
            b"x",
            &corpus::decoded_args::TraceOutcome::Unavailable(
                "the harness was built without the argument trace".to_owned(),
            ),
        )
        .unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains("  not recorded: the harness was built without the argument trace."),
            "{out}"
        );
        assert!(out.contains("bhf replay --show-args"), "{out}");
    }

    /// The structured access a sanitizer recorded (direction, size, the region
    /// it hit and where that region was allocated) is spelled out.
    #[test]
    fn a_recorded_memory_access_is_described() {
        let work = tempfile::tempdir().unwrap();
        let mut finding = frameless_finding(work.path());
        finding.raw["exception"]["access"] = serde_json::json!({
            "direction": "read",
            "size": 4,
            "address": "0x502000000015",
            "region": {"kind": "heap", "size": 5, "offset": 5, "relation": "after", "distance": 0},
            "alloc_stack": [
                {"function": "malloc", "file": "/llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp", "line": 68},
                {"function": "bhf_c_string", "file": "/w/harnesses/H-C0001/bhf_decode.h", "line": 195},
                {"function": "bhf_run_one", "file": "/w/harnesses/H-C0001/main.c", "line": 106}
            ]
        });
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains(
                "  Access: read of 4 byte(s), 0 byte(s) after a 5-byte heap region (offset 5)\n"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "    allocated at bhf_c_string (bhf_decode.h:195) <- bhf_run_one (main.c:106)\n"
            ),
            "{out}"
        );

        finding.raw["exception"]["access"] = serde_json::json!({
            "direction": "write",
            "size": 1,
            "region": {"kind": "stack", "size": 4, "offset": 4, "relation": "after",
                       "distance": 0, "variable": "buf", "frame_offset": 36},
            "alloc_stack": [{"function": "parse_record", "file": "/src/widget/rec.c", "line": 5}]
        });
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains("  Access: write of 1 byte(s), 0 byte(s) after the 4-byte stack variable `buf` (offset 4)\n"),
            "{out}"
        );
        assert!(
            out.contains("    in the frame of parse_record (rec.c:5)\n"),
            "{out}"
        );

        finding.raw["exception"]["access"] = serde_json::json!({
            "direction": "unknown",
            "address": "0x4141414141414141",
            "address_hint": "high-value-address"
        });
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains(
                "  Access: unknown-direction access at 0x4141414141414141 (high-value-address)\n"
            ),
            "{out}"
        );
    }

    /// REPRODUCE OFFLINE offers capsule + verify-poc only for a finding capsule
    /// takes; otherwise it says why and gives a command that works.
    #[test]
    fn reproduce_offline_suggests_only_commands_that_apply() {
        let work = tempfile::tempdir().unwrap();
        let finding_dir = work.path().join("results/findings/F-0001-0a0b0c0d");
        std::fs::create_dir_all(&finding_dir).unwrap();
        std::fs::write(finding_dir.join("testcase.bin"), b"AAAA").unwrap();
        let finding = frameless_finding(&finding_dir);

        // No harness dir: refused, and there is nothing to run instead yet.
        let out = explain_one(work.path(), &finding, &[], false);
        let reproduce = out.split("REPRODUCE OFFLINE").nth(1).unwrap();
        let words = reproduce.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(!reproduce.contains("bhf verify-poc"), "{reproduce}");
        assert!(
            words.contains("harness H-C0001 was not found"),
            "{reproduce}"
        );

        // A built harness with no capsule-able Makefile: the direct command.
        let harness = crate::auto::layout::harness_dir(work.path(), "H-C0001");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(harness.join("main"), b"\x7fELF").unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let reproduce = out.split("REPRODUCE OFFLINE").nth(1).unwrap();
        assert!(!reproduce.contains("bhf capsule --work-dir"), "{reproduce}");
        assert!(
            reproduce.contains("UBSAN_OPTIONS=print_stacktrace=1")
                && reproduce.contains(&harness.join("main").display().to_string()),
            "{reproduce}"
        );

        // A Windows build recorded where its sanitizer runtime lives: the
        // direct run is told to put it on PATH.
        std::fs::write(
            harness.join(crate::build::RUNTIME_PATH_FILE),
            "C:/Program Files/LLVM/lib/clang/23/lib/windows\n",
        )
        .unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let reproduce = out.split("REPRODUCE OFFLINE").nth(1).unwrap();
        assert!(
            reproduce.contains(
                "$env:Path = \"C:/Program Files/LLVM/lib/clang/23/lib/windows;$env:Path\""
            ),
            "{reproduce}"
        );
        std::fs::remove_file(harness.join(crate::build::RUNTIME_PATH_FILE)).unwrap();

        // A packageable C harness: capsule and verify-poc.
        std::fs::write(harness.join("main.c"), b"int main(void) { return 0; }\n").unwrap();
        std::fs::write(
            harness.join("Makefile"),
            b"main: main.c\n\t$(CC) $(CFLAGS) -o $@ main.c $(AUTO_EXTRA_SOURCES)\n",
        )
        .unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let reproduce = out.split("REPRODUCE OFFLINE").nth(1).unwrap();
        assert!(
            reproduce.contains(&format!(
                "bhf capsule --work-dir {} --finding-id F-0001-0a0b0c0d",
                work.path().display()
            )),
            "{reproduce}"
        );
        assert!(reproduce.contains("bhf verify-poc"), "{reproduce}");
        // cartography maps AddressSanitizer reports only: not this UBSan one.
        assert!(!reproduce.contains("bhf cartography"), "{reproduce}");

        // The same built harness with an AddressSanitizer crash: cartography too.
        let mut asan = frameless_finding(&finding_dir);
        asan.raw["exception"] = serde_json::json!({
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "message": "AddressSanitizer: heap-buffer-overflow",
            "stack": []
        });
        let out = explain_one(work.path(), &asan, &[], false);
        let reproduce = out.split("REPRODUCE OFFLINE").nth(1).unwrap();
        assert!(
            reproduce.contains(&format!(
                "bhf cartography --work-dir {} --finding-id F-0001-0a0b0c0d",
                work.path().display()
            )),
            "{reproduce}"
        );

        // An oracle hit is not a sanitizer crash: no capsule.
        let mut oracle = frameless_finding(&finding_dir);
        oracle.raw["classification"] = serde_json::json!("oracle");
        let out = explain_one(work.path(), &oracle, &[], false);
        let reproduce = out.split("REPRODUCE OFFLINE").nth(1).unwrap();
        assert!(!reproduce.contains("bhf verify-poc"), "{reproduce}");
        assert!(reproduce.contains("oracle finding"), "{reproduce}");
    }

    /// REPRODUCE OFFLINE offers capsule and verify-poc for a finding of every
    /// harness language capsule packages (a Python one here), and cartography
    /// only for the C and C++ AddressSanitizer crashes it maps.
    #[test]
    fn reproduce_offline_offers_capsule_for_an_interpreted_harness_but_not_cartography() {
        let work = tempfile::tempdir().unwrap();
        let tree = work.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(
            tree.join("record_parser.py"),
            "def parse_record(d):\n    pass\n",
        )
        .unwrap();
        std::fs::create_dir_all(work.path().join("auto")).unwrap();
        std::fs::write(
            work.path().join("auto/run.json"),
            serde_json::json!({"source_root": tree}).to_string(),
        )
        .unwrap();
        let harness = crate::auto::layout::harness_dir(work.path(), "H-P0001-0000ABCD");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(
            harness.join("main"),
            "#!/bin/sh\n# BHF_FRAMED BHF_PY_LAUNCHER\nexec \"/usr/bin/python3\" -B d.py \"$@\"\n",
        )
        .unwrap();
        let finding_dir = work.path().join("results/findings/F-0001-0a0b0c0d");
        std::fs::create_dir_all(&finding_dir).unwrap();
        std::fs::write(finding_dir.join("testcase.bin"), b"A").unwrap();
        let mut finding = frameless_finding(&finding_dir);
        finding.raw["harness_id"] = serde_json::json!("H-P0001-0000ABCD");
        finding.raw["exception"] = serde_json::json!({
            "name": "ASAN_PYTHON_UNCONTROLLED_RECURSION",
            "sanitizer": "asan",
            "message": "Python finding: RecursionError: maximum recursion depth exceeded",
            "stack": []
        });
        let out = explain_one(work.path(), &finding, &[], false);
        let reproduce = out.split("REPRODUCE OFFLINE").nth(1).unwrap();
        assert!(
            reproduce.contains(&format!(
                "bhf capsule --work-dir {} --finding-id F-0001-0a0b0c0d",
                work.path().display()
            )) && reproduce.contains("bhf verify-poc"),
            "{reproduce}"
        );
        assert!(!reproduce.contains("bhf cartography"), "{reproduce}");

        // A Python harness without its launcher is refused with that reason.
        std::fs::remove_file(harness.join("main")).unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let reproduce = out.split("REPRODUCE OFFLINE").nth(1).unwrap();
        let words = reproduce.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(!reproduce.contains("bhf verify-poc"), "{reproduce}");
        assert!(
            words.contains("Python harness H-P0001-0000ABCD")
                && words.contains("no `main` launcher"),
            "{reproduce}"
        );
    }

    /// The dictionary is read with the engine's own AFL parser: a token may
    /// contain `=`, `\r` is a carriage return, and a `name=` prefix and
    /// comments are skipped.
    #[test]
    fn dictionary_loader_shares_the_engine_parser() {
        let work = tempfile::tempdir().unwrap();
        let harness = crate::auto::layout::harness_dir(work.path(), "H-C0001");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(
            harness.join("dictionary.txt"),
            "# mined from widget.c\n\"encoding=utf8\"\n\"\\r\\nBODY\"\nhdr=\"HDR\"\n",
        )
        .unwrap();
        assert_eq!(
            load_dictionary(work.path(), "H-C0001"),
            vec![
                b"encoding=utf8".to_vec(),
                b"\r\nBODY".to_vec(),
                b"HDR".to_vec()
            ]
        );
        assert!(load_dictionary(work.path(), "H-C0002").is_empty());
    }

    /// Dictionary tokens are a labelled substring match: short tokens and
    /// tokens found too often are dropped, so a large input's coincidental
    /// single bytes never show up.
    #[test]
    fn dictionary_tokens_present_drop_short_and_common_tokens() {
        let mut input = b"WIDGET".to_vec();
        for i in 0..40_000u32 {
            input.push(match i % 7 {
                0 => 0,
                1 => b'0',
                2 => b'1',
                3 => b'z',
                _ => (i % 251) as u8,
            });
        }
        input.extend_from_slice(b"zzzzzz");
        let dict = vec![
            b"WIDGET".to_vec(),
            vec![0],
            b"0".to_vec(),
            b"01".to_vec(),
            b"zzz".to_vec(),
        ];
        assert_eq!(
            dictionary_tokens_present(&input, &dict),
            vec![("\"WIDGET\"".to_owned(), 0, 1)]
        );
    }

    fn finding_in(work: &Path, raw: serde_json::Value) -> Finding {
        let dir = corpus::layout::findings_dir(work).join("F-0001-0a0b0c0d");
        std::fs::create_dir_all(&dir).unwrap();
        Finding {
            id: "F-0001-0a0b0c0d".to_owned(),
            dir,
            raw,
        }
    }

    fn base_raw() -> serde_json::Value {
        serde_json::json!({
            "id": "F-0001-0a0b0c0d", "rule_id": "BHF-201", "harness_id": "H-C0001",
            "classification": "unhandled",
            "exception": {"name": "ASAN_HEAP_BUFFER_OVERFLOW", "sanitizer": "asan", "stack": []}
        })
    }

    /// A finding whose harness compiled only with fabricated headers or macro
    /// values says so right under its title, naming what was fabricated.
    #[test]
    fn a_fabricated_build_context_is_called_out() {
        let work = tempfile::tempdir().unwrap();
        let mut raw = base_raw();
        raw["build"] = serde_json::json!({"fidelity": {
            "level": "reduced",
            "context": "none",
            "fabricated": [
                {"kind": "macro", "name": "WIDGET_SLOTS", "value": "0"},
                {"kind": "header", "name": "tables.h"}
            ]
        }});
        let out = explain_one(work.path(), &finding_in(work.path(), raw), &[], false);
        let caveat = out
            .lines()
            .position(|line| line.contains("BUILD FIDELITY"))
            .unwrap_or_else(|| panic!("no build fidelity caveat:\n{out}"));
        let text = out
            .lines()
            .skip(caveat)
            .take(5)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("macro WIDGET_SLOTS=0"), "{out}");
        assert!(text.contains("header tables.h"), "{out}");
        assert!(text.contains("low confidence"), "{out}");
        let plain = explain_one(
            work.path(),
            &finding_in(work.path(), base_raw()),
            &[],
            false,
        );
        assert!(!plain.contains("BUILD FIDELITY"), "{plain}");
    }

    /// explain shows the minimized input when there is one, and says which
    /// file it shows.
    #[test]
    fn the_minimized_input_is_preferred_and_named() {
        let work = tempfile::tempdir().unwrap();
        let finding = finding_in(work.path(), base_raw());
        std::fs::write(finding.dir.join("testcase.bin"), vec![b'Q'; 4096]).unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains("THE INPUT THAT TRIGGERS IT  (testcase.bin, 4096 byte(s), not minimized)"),
            "{out}"
        );
        std::fs::write(finding.dir.join("min_testcase.bin"), b"WIDGE").unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains(
                "THE INPUT THAT TRIGGERS IT  (min_testcase.bin, 5 byte(s), minimized from 4096 byte(s))"
            ),
            "{out}"
        );
        assert!(
            out.contains("57 49 44 47 45"),
            "the minimized bytes are dumped: {out}"
        );
        assert!(!out.contains("51 51 51"), "{out}");
    }

    fn recorded_capture(gates: serde_json::Value, reason: Option<&str>) -> serde_json::Value {
        let mut raw = base_raw();
        raw["gates"] = gates;
        raw["gate_capture"] = serde_json::json!({
            "input": "testcase.bin", "input_len": 8,
            "status": if reason.is_some() { "no_input_comparisons" } else { "recorded" },
            "reason": reason, "comparisons": 4, "truncated": false, "unconfirmed": 2,
            "runs": 3, "shim_armed": false
        });
        raw
    }

    /// Recorded comparison evidence is shown with its offsets, operands and
    /// site, titled as evidence for this input; nothing is ever presented as
    /// solved gates without it.
    #[test]
    fn recorded_comparison_evidence_is_shown_and_its_absence_is_explained() {
        let work = tempfile::tempdir().unwrap();
        let raw = recorded_capture(
            serde_json::json!([{
                "offset": 2, "len": 6, "operand_hex": "574944474554", "compared_with_hex": "574944474554",
                "cmp_kind": "strcmp", "site": "0x1a2b", "relation": "equal", "operands_equal": true,
                "location": {"file": "/src/widget/parse.c", "line": 12, "function": "parse_record"}
            }, {
                "offset": 0, "len": 2, "operand_hex": "e0ffffff", "compared_with_hex": "1f000000",
                "cmp_kind": "cmp", "site": "0x1a40", "relation": "derived", "operands_equal": false,
                "location": null
            }]),
            None,
        );
        let finding = finding_in(work.path(), raw);
        std::fs::write(finding.dir.join("testcase.bin"), b"\x21\x00WIDGET").unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let words = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains(
                "Comparison evidence for this input (testcase.bin, recorded when the finding was saved):"
            ),
            "{out}"
        );
        assert!(
            words.contains(
                "bytes 2..8 \"WIDGET\" reach strcmp at parse.c:12 in parse_record, compared with \"WIDGET\" (equal)"
            ),
            "{out}"
        );
        assert!(words.contains("bytes 0..2 feed cmp at 0x1a40"), "{out}");
        assert!(
            words.contains("2 more operand(s) occur in the input"),
            "{out}"
        );
        assert!(
            !out.contains("solved") && !out.contains("not gated"),
            "{out}"
        );

        let none = finding_in(
            work.path(),
            recorded_capture(
                serde_json::json!([]),
                Some("4 comparison(s) recorded; no operand followed a change of the input bytes"),
            ),
        );
        let out = explain_one(work.path(), &none, &[], false);
        let words = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains("No comparison evidence recorded for testcase.bin: 4 comparison(s) recorded; no operand followed a change of the input bytes."),
            "{out}"
        );

        let unrecorded = finding_in(work.path(), base_raw());
        let out = explain_one(work.path(), &unrecorded, &[], false);
        let words = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains("No comparison evidence recorded: none was recorded for this finding, and its harness binary was not found to record it now."),
            "{out}"
        );
        assert!(
            !out.contains("Input-to-state") && !out.contains("recovered constant"),
            "{out}"
        );
    }

    /// An empty input, one of the built-in starting inputs, or a copy of a
    /// listed seed says so.
    #[test]
    fn the_input_says_where_it_came_from() {
        let work = tempfile::tempdir().unwrap();
        let finding = finding_in(work.path(), base_raw());
        std::fs::write(finding.dir.join("testcase.bin"), b"").unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let words = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains("one of bhf's built-in starting inputs"),
            "{out}"
        );
        assert!(
            words.contains("The input is empty: every scalar parameter decodes to 0 and every buffer is empty."),
            "{out}"
        );

        let seed = b"<Project><ClInclude Include=\"widget.h\"/></Project>";
        std::fs::write(finding.dir.join("testcase.bin"), seed).unwrap();
        let digest = {
            use sha2::Digest;
            sha2::Sha256::digest(seed)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let manifest = crate::auto::seed_manifest::manifest_path(work.path());
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest,
            serde_json::json!({"schema_version": 1, "mining": "ran", "seeds": [{
                "path": "tests/widget.vcxproj", "source": "mined", "sha256": digest,
                "size": seed.len(), "bytes_used": seed.len()
            }]})
            .to_string(),
        )
        .unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let words = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains("byte-identical to the seed mined from tests/widget.vcxproj"),
            "{out}"
        );
        assert!(!words.contains("built-in starting inputs"), "{out}");
    }

    /// The environment section names where its events come from, and says
    /// when nothing was observed instead of claiming no resources were used.
    #[test]
    fn the_environment_section_states_its_evidence() {
        let work = tempfile::tempdir().unwrap();
        let mut raw = base_raw();
        raw["runtime_mode"] =
            serde_json::json!({"pass": "empty", "env_injected": {}, "shim_armed": false});
        let finding = finding_in(work.path(), raw);
        std::fs::write(finding.dir.join("testcase.bin"), b"AB").unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        assert!(
            out.contains(
                "FAKED ENVIRONMENT\n  environment not observed (runtrace shim not loaded)\n"
            ),
            "{out}"
        );
        assert!(!out.contains("touched no external resources"), "{out}");

        let unknown = finding_in(work.path(), base_raw());
        let out = explain_one(work.path(), &unknown, &[], false);
        assert!(
            out.contains("environment not observed (no runtrace events"),
            "{out}"
        );

        let harness = crate::auto::layout::harness_dir(work.path(), "H-C0001");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(
            harness.join("runtrace.jsonl"),
            "{\"e\":\"getenv\",\"n\":\"WIDGET_MODE\",\"r\":1}\n",
        )
        .unwrap();
        let mut raw = base_raw();
        raw["runtime_mode"] =
            serde_json::json!({"pass": "empty", "env_injected": {}, "shim_armed": true});
        let campaign = finding_in(work.path(), raw);
        let out = explain_one(work.path(), &campaign, &[], false);
        assert!(
            out.contains("FAKED ENVIRONMENT  (runtrace events of the harness's last fuzz pass, across all of its inputs, not only this one)\n  getenv WIDGET_MODE"),
            "{out}"
        );

        let mut raw = recorded_capture(serde_json::json!([]), Some("no comparisons"));
        raw["gate_capture"]["shim_armed"] = serde_json::json!(true);
        let own = finding_in(work.path(), raw);
        std::fs::write(own.dir.join("testcase.bin"), b"ABCDEFGH").unwrap();
        std::fs::write(
            own.dir.join("runtrace.jsonl"),
            "{\"e\":\"getenv\",\"n\":\"WIDGET_HOME\",\"r\":1}\n",
        )
        .unwrap();
        let out = explain_one(work.path(), &own, &[], false);
        assert!(
            out.contains("FAKED ENVIRONMENT  (observed while replaying testcase.bin with the runtrace shim)\n  getenv WIDGET_HOME"),
            "{out}"
        );
        assert!(
            !out.contains("WIDGET_MODE"),
            "the finding's own replay wins: {out}"
        );
    }

    /// A finding with no recorded comparison evidence is replayed once to
    /// record it, and nothing is written back.
    #[cfg(target_os = "linux")]
    #[test]
    fn missing_comparison_evidence_is_recorded_by_replaying_the_input() {
        let Some((_build, main)) = crate::gate_evidence::harness_tests::harness() else {
            return;
        };
        let work = tempfile::tempdir().unwrap();
        let harness = crate::auto::layout::harness_dir(work.path(), "H-C0001");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::copy(&main, harness.join("main")).unwrap();
        let finding = finding_in(work.path(), base_raw());
        std::fs::write(finding.dir.join("testcase.bin"), b"\x05\x00WIDGET").unwrap();
        let record = finding.dir.join("finding.json");
        std::fs::write(&record, finding.raw.to_string()).unwrap();
        let out = explain_one(work.path(), &finding, &[], false);
        let words = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains(
                "Comparison evidence for this input (testcase.bin, recorded now by replaying it):"
            ),
            "{out}"
        );
        assert!(
            words.contains("bytes 2..8 \"WIDGET\" reach strcmp"),
            "{out}"
        );
        let after: Value = serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        assert!(after.get("gates").is_none(), "explain writes nothing back");
    }

    /// The reachability line names its basis: a signature inference says so,
    /// and an unassessed entry is not called reachable.
    #[test]
    fn the_reachability_line_names_its_basis() {
        let work = tempfile::tempdir().unwrap();
        let mut raw = base_raw();
        raw["actionability"] = serde_json::json!({"verdict": "likely_reachable"});
        raw["input_reachability"] = serde_json::json!("attacker_reachable");
        let finding = finding_in(work.path(), raw);
        let out = explain_one(work.path(), &finding, &[], false);
        let words = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains(
                "matches an input-taking shape, so likely reachable from input; not proven"
            ),
            "{out}"
        );
        assert!(!out.contains("attacker-reachable"), "{out}");
        let mut raw = base_raw();
        raw["actionability"] = serde_json::json!({"verdict": "likely_reachable"});
        let unassessed = finding_in(work.path(), raw);
        let out = explain_one(work.path(), &unassessed, &[], false);
        assert!(out.contains("Verdict: reachability not assessed"), "{out}");
    }

    #[test]
    fn renders_binary_token_as_hex() {
        assert_eq!(render_token(&[0xfe, 0x00]), "\\xfe\\x00");
        assert_eq!(render_token(b"GET"), "\"GET\"");
    }

    #[test]
    fn dedups_consecutive_frames() {
        assert_eq!(dedup_chain(&["a", "a", "b", "a"]), vec!["a", "b", "a"]);
    }

    #[test]
    fn summarize_env_surfaces_taint_and_env() {
        let events = vec![
            RuntraceEvent::EnvVarAccess {
                api: "getenv".into(),
                name: "APP_MODE".into(),
            },
            RuntraceEvent::FileOpened {
                syscall: "open".into(),
                fd: 3,
                path: "/etc/passwd".into(),
                taint_offset: Some(5),
            },
        ];
        let lines = summarize_env(&events);
        assert!(lines.iter().any(|l| l.contains("getenv APP_MODE")));
        assert!(lines
            .iter()
            .any(|l| l.contains("/etc/passwd") && l.contains("input byte 5")));
    }

    #[test]
    fn wrap_breaks_on_width() {
        let out = wrap("aaaa bbbb cccc", 9);
        assert_eq!(out, vec!["aaaa bbbb".to_owned(), "cccc".to_owned()]);
    }

    #[test]
    fn hexdump_caps_rows() {
        let bytes = vec![0u8; 200];
        let rows = hexdump(&bytes, 2);
        assert_eq!(rows.len(), 3); // 2 rows + a "... more" line
        assert!(rows.last().unwrap().contains("more byte"));
    }
}
