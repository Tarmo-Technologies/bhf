// SPDX-License-Identifier: Apache-2.0

//! `bhf explain` — a deterministic, offline "why did it crash?" for a finding.
//!
//! Every other tool's answer to "explain this crash" is either a raw sanitizer
//! dump or an LLM round-trip. bhf already holds every fact needed to answer it
//! precisely and reproducibly, with NO model: the minimized input, the comparison
//! constants the engine mined to get past the target's gates (cmplog / value
//! profile → `dictionary.txt`), the byte-origin taint the shim recorded at each
//! resource call (#422), the virtualized environment the sandbox served, the sink
//! site + call frames, and the build-recovery provenance verdict. This joins them
//! through a FIXED narrative grammar into a triage-ready explanation.
//!
//! Deterministic by construction: the same finding always yields the same text.
//! Best-effort per section — a missing artifact drops that section, never the
//! whole explanation.

use crate::auto::runtrace::{self, RuntraceEvent};
use serde_json::Value;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// `bhf explain` — explain, offline and deterministically, why a crash fired.
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

    // THE INPUT THAT TRIGGERS IT
    let input = f.dir.join("testcase.bin");
    if let Ok(bytes) = std::fs::read(&input) {
        let _ = writeln!(s, "\nTHE INPUT THAT TRIGGERS IT  ({} byte(s))", bytes.len());
        for line in hexdump(&bytes, 6) {
            let _ = writeln!(s, "  {line}");
        }
        // Input-to-state: which recovered comparison constants the input satisfies.
        let dict = load_dictionary(work_dir, &harness_id);
        let gates = matched_gates(&bytes, &dict);
        if gates.is_empty() {
            let _ = writeln!(
                s,
                "  (no recovered gate constants matched — the crash is not gated \
                 behind a magic value)"
            );
        } else {
            let _ = writeln!(
                s,
                "  Input-to-state — the engine solved these gates to reach the sink:"
            );
            for (off, tok) in gates {
                let _ = writeln!(s, "    byte {off}: matched recovered constant {tok}");
            }
        }
    }

    // FAKED ENVIRONMENT + byte-origin taint
    let events = harness_id
        .is_empty()
        .then(Vec::new)
        .unwrap_or_else(|| load_events(work_dir, &harness_id));
    let env = summarize_env(&events);
    let _ = writeln!(s, "\nFAKED ENVIRONMENT  (served by the bhf sandbox)");
    if env.is_empty() {
        let _ = writeln!(
            s,
            "  the target touched no external resources before the crash"
        );
    } else {
        for line in env {
            let _ = writeln!(s, "  {line}");
        }
    }

    // REACHABILITY & PROVENANCE
    let _ = writeln!(s, "\nREACHABILITY & PROVENANCE");
    let verdict = str_at(&f.raw, "/actionability/verdict").unwrap_or("");
    let _ = writeln!(s, "  Verdict: {}", humanize_verdict(verdict));
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
/// `bhf verify-poc` when capsule can package it (the same check capsule runs),
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
                "  (the capsule records whether its offline rebuild reproduced the crash)"
                    .to_owned(),
            );
            if replay.is_file() {
                lines.push(format!(
                    "python3 {}",
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
    let asan = str_at(&f.raw, "/exception/sanitizer") == Some("asan");
    if asan && repro_lane::assess(work_dir, &record, Tool::Cartography).is_ok() {
        lines.push(format!(
            "bhf cartography --work-dir {work} --finding-id {}   # which input bytes steer the access",
            f.id
        ));
    }
    lines
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

/// Parse the fuzz dictionary (`dictionary.txt`, one `"..."`-quoted token per line)
/// into raw byte tokens.
fn load_dictionary(work_dir: &Path, harness_id: &str) -> Vec<Vec<u8>> {
    if harness_id.is_empty() {
        return Vec::new();
    }
    let path = crate::auto::layout::harness_dir(work_dir, harness_id).join("dictionary.txt");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Drop an optional `name=` prefix, then the surrounding quotes.
        let quoted = line.split_once('=').map(|(_, v)| v).unwrap_or(line).trim();
        if let Some(tok) = unquote_dict_token(quoted) {
            if !tok.is_empty() {
                out.push(tok);
            }
        }
    }
    out
}

/// Unescape an AFL/libFuzzer dictionary token `"...\xNN..."` into raw bytes.
fn unquote_dict_token(quoted: &str) -> Option<Vec<u8>> {
    let inner = quoted.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let h: String = (0..2).filter_map(|_| chars.next()).collect();
                    if let Ok(b) = u8::from_str_radix(&h, 16) {
                        out.push(b);
                    }
                }
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some('n') => out.push(b'\n'),
                Some('t') => out.push(b'\t'),
                Some(other) => out.push(other as u8),
                None => {}
            }
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    Some(out)
}

/// Find dictionary tokens present in the input, returning `(offset, printable
/// token)` for the notable matches (longest first, deduped by token). A token that
/// appears in the input is a comparison constant the engine had to place there.
fn matched_gates(input: &[u8], dict: &[Vec<u8>]) -> Vec<(usize, String)> {
    let mut tokens: Vec<&Vec<u8>> = dict.iter().filter(|t| !t.is_empty()).collect();
    // Longest tokens are the most informative gates; report those first.
    tokens.sort_by_key(|t| std::cmp::Reverse(t.len()));
    let mut out = Vec::new();
    let mut used = std::collections::BTreeSet::new();
    for tok in tokens {
        if let Some(off) = find_sub(input, tok) {
            let rendered = render_token(tok);
            if used.insert(rendered.clone()) {
                out.push((off, rendered));
            }
        }
        if out.len() >= 8 {
            break;
        }
    }
    out.sort_by_key(|(off, _)| *off);
    out
}

/// First offset of `needle` in `haystack`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
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
    let log = crate::auto::layout::harness_dir(work_dir, harness_id).join("runtrace.jsonl");
    let mut events = runtrace::parse_log(&log).unwrap_or_default();
    runtrace::dedupe_in_place(&mut events);
    events
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

fn humanize_verdict(v: &str) -> &str {
    match v {
        "likely_reachable" => "attacker-reachable via the fuzzed input channel",
        "lab_only" => "reproducible in the lab; attacker-reachability unproven",
        "reachability_unproven" => "reachability from attacker input unproven",
        _ if v.is_empty() => "unassessed",
        other => other,
    }
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

    #[test]
    fn unquotes_dictionary_tokens() {
        assert_eq!(unquote_dict_token("\"BOOM\""), Some(b"BOOM".to_vec()));
        assert_eq!(unquote_dict_token("\"\\x04\""), Some(vec![0x04]));
        assert_eq!(unquote_dict_token("\"A\\x00B\""), Some(vec![b'A', 0, b'B']));
        assert_eq!(unquote_dict_token("notquoted"), None);
    }

    #[test]
    fn matches_gate_constants_in_input() {
        let input = b"BOOM\xfe\x4d";
        let dict = vec![b"BOOM".to_vec(), b"XY".to_vec(), b"B".to_vec()];
        let gates = matched_gates(input, &dict);
        // "BOOM" (longest) matches at 0; "XY" is absent. "B" is deduped-in by offset
        // order but distinct token, so it also appears — both at offset 0.
        assert!(gates.iter().any(|(o, t)| *o == 0 && t == "\"BOOM\""));
        assert!(!gates.iter().any(|(_, t)| t == "\"XY\""));
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
