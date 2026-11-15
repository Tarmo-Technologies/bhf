// SPDX-License-Identifier: Apache-2.0

//! `bhf capsule` / `bhf verify-poc` — a portable, self-verifying exploit
//! capsule for a crash bhf found on an un-buildable tree.
//!
//! bhf's whole point is that it fuzzes source with no working build by
//! stitching one together. The flip side: the crash it finds lives inside a
//! throwaway `bhf_work/` full of absolute paths and generated stubs. A capsule
//! makes that crash *hand-offable*: it copies the minimal set that reproduces it —
//! the harness driver, the target sources and the headers they include (in their
//! original layout), the recovered stubs, bhf's runtime for the language, any
//! dependencies vendored for an offline rebuild, and the crash input (the
//! minimized one when it reproduces) — rewrites every path to be relative, and
//! ships a `build.sh` plus a `manifest.json` recording the toolchain it needs
//! and the exact crash signature to expect. `bhf verify-poc` rebuilds it
//! offline (only the lane's toolchain + a shell needed — no bhf) and asserts
//! the same crash reproduces.
//!
//! What gets copied and how it rebuilds is the finding's lane
//! ([`crate::repro_lane`]): every harness language bhf generates has one. The
//! rebuilt PoC is replayed with the input protocol the shared detector
//! ([`crate::protocol_detect`]) reads off it — the input file as `argv[1]`, or
//! the Ada runtime's stdin with its event log — and the lane's crash oracle
//! names what fired. A harness its lane cannot rebuild offline is refused with
//! the specific reason.
//!
//! The capsule is self-verifying BY CONSTRUCTION: `capsule` builds and replays it in
//! a scratch dir before moving it into place, records the observed sanitizer
//! signature, and marks `reproduced: false` (never silently) when the
//! reconstruction doesn't fire. A refused or failed finding leaves nothing behind.

use crate::protocol_detect::{self, HarnessProtocol};
use crate::repro_lane::{self, HarnessContext, Lane, PlanRefusal, Requirement, Tool};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Wall clock for rebuilding a capsule.
const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Wall clock for one replay of the rebuilt PoC.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(60);
/// Where a capsule's crash input ships, whichever of the finding's inputs it is.
const SHIPPED_INPUT: &str = "input/testcase.bin";
/// The Windows build script a C or C++ capsule ships beside `build.sh`.
const WINDOWS_BUILD_SCRIPT: &str = "build.ps1";
/// How the manifest and the README say to run it.
const WINDOWS_BUILD_COMMAND: &str = "powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1";

// ── `bhf capsule` ───────────────────────────────────────────────────────

/// `bhf capsule` — package reproducible crashes into portable PoC capsules.
///
/// A capsule is checked when it is packaged: it reproduces only when its
/// rebuilt PoC shows the finding's crash (the minimized input ships only
/// then), and it is portable only when no file it ships, and no manifest
/// field, names the work dir or the scanned tree; otherwise the summary says
/// `⚠ not portable: <file> names <path>`.
#[derive(Debug, clap::Args)]
pub struct CapsuleArgs {
    /// Work directory of a prior `auto` run to read findings + harnesses from.
    #[arg(long = "work-dir", default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Package only this finding id (default: every runtime crash finding).
    /// Exits non-zero, with the reason, when it cannot be packaged or its
    /// capsule does not reproduce.
    #[arg(long = "finding-id", value_name = "ID")]
    pub finding_id: Option<String>,

    /// Directory to write capsules under. Default `<work-dir>/capsules`.
    #[arg(long, short = 'o', value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Also emit a `.tar.gz` next to each capsule dir (via the system `tar`).
    #[arg(long)]
    pub tar: bool,

    /// Print per-capsule detail.
    #[arg(short, long)]
    pub verbose: bool,
}

/// `bhf verify-poc` — rebuild a capsule offline and assert the crash reproduces.
///
/// A C or C++ capsule's replay is compared with the finding's crash field by
/// field, as `bhf replay` compares it (rule, kind, then sink or site): another
/// crash of the same sanitizer class is a MISMATCH naming the field that
/// differs. A capsule packaged before it recorded the finding's identity is
/// compared by sanitizer class, and says so.
///
/// It needs the programs the capsule's manifest lists under `requires` (the
/// lane's compiler or interpreter, each overridable by its variable, such as
/// `CC`, `GPRBUILD`, `PYTHON` or `DOTNET`) and says which are missing. On
/// Windows a C or C++ capsule rebuilds with its `build.ps1` instead of
/// `build.sh`, which needs no POSIX shell, with the compiler the harness was
/// built with (cl, clang-cl or clang; `CC`/`CXX` names another), as
/// `requires_windows` lists it.
#[derive(Debug, clap::Args)]
pub struct VerifyPocArgs {
    /// Capsule directory or `.tar.gz` produced by `bhf capsule` (absolute, or
    /// relative to the current dir).
    pub capsule: PathBuf,
}

pub fn run(args: CapsuleArgs) -> i32 {
    if let Err(error) = crate::workdir::prepare(&args.work_dir) {
        bhfeprintln!("error: {error:#}");
        return 1;
    }
    let requested = args.finding_id.is_some();
    let selection =
        match repro_lane::select(&args.work_dir, args.finding_id.as_deref(), Tool::Capsule) {
            Ok(selection) => selection,
            Err(error) => {
                bhfeprintln!("error: {error}");
                return 1;
            }
        };
    if selection.considered == 0 {
        bhfeprintln!(
            "bhf capsule: no runtime crash findings in {}",
            args.work_dir.display()
        );
        return 0;
    }
    repro_lane::print_refusals(Tool::Capsule, &selection.refused, requested, 10);
    let selection_refused = selection.refused.len();
    if selection.eligible.is_empty() {
        if !requested {
            bhfeprintln!(
                "bhf capsule: nothing packaged: none of the {} runtime finding(s) in {} can be \
                 packaged",
                selection.considered,
                args.work_dir.display()
            );
        }
        return 1;
    }
    let out_root = args
        .out
        .clone()
        .unwrap_or_else(|| args.work_dir.join("capsules"));
    let out_root_existed = out_root.exists();
    let mut made = 0usize;
    let mut reproduced = 0usize;
    let mut failed = 0usize;
    let mut refused_at_plan = 0usize;
    for (record, eligible) in selection.eligible {
        let Some(harness_dir) = eligible.harness_dir else {
            failed += 1;
            continue;
        };
        let finding = FindingRef {
            finding_id: record.id,
            finding_dir: record.dir,
            harness_id: eligible.harness_id,
            harness_dir,
            work_dir: args.work_dir.clone(),
            lane: eligible.lane,
            inputs: eligible.inputs,
            raw: record.raw,
        };
        match build_capsule(&finding, &out_root, args.tar) {
            Ok(report) => {
                made += 1;
                if report.reproduced {
                    reproduced += 1;
                }
                let mark = match (report.reproduced, report.portability.first()) {
                    (true, None) => "✓".to_owned(),
                    // It reproduces here, but a rebuild elsewhere needs what
                    // the named file points at.
                    (true, Some(first)) => format!(
                        "⚠ not portable: {first}{}",
                        match report.portability.len() {
                            1 => String::new(),
                            n => format!(" (and {} more)", n - 1),
                        }
                    ),
                    (false, _) => format!("⚠ not reproduced: {}", report.not_reproduced_reason),
                };
                println!(
                    "  {} {}  ({})",
                    report.finding_id,
                    report.capsule_path.display(),
                    mark
                );
                println!("      input: {}", report.input_note);
                if args.verbose {
                    println!("      signature: {}", report.signature);
                    if let Some(compared) = &report.compared {
                        println!("      compared: {compared}");
                    }
                }
                for warning in &report.warnings {
                    bhfeprintln!("  {} warning: {warning}", report.finding_id);
                }
            }
            Err(e) => match e.downcast_ref::<PlanRefusal>() {
                // The lane decided while planning that it cannot package this
                // harness (a dependency not vendorable offline, a project file
                // outside the tree): a refusal with its reason, like the ones
                // the selection makes.
                Some(refusal) => {
                    refused_at_plan += 1;
                    let reason = format!(
                        "{} harness {} cannot be packaged: {refusal}",
                        finding.lane.name(),
                        finding.harness_id,
                    );
                    if requested {
                        bhfeprintln!(
                            "bhf capsule: cannot package {}: {reason}",
                            finding.finding_id
                        );
                    } else {
                        bhfeprintln!("bhf capsule: {} skipped: {reason}", finding.finding_id);
                    }
                    let record = repro_lane::FindingRecord {
                        id: finding.finding_id.clone(),
                        dir: finding.finding_dir.clone(),
                        raw: finding.raw.clone(),
                    };
                    let refusal = repro_lane::Refusal::IncompleteHarness {
                        harness_id: finding.harness_id.clone(),
                        language: finding.lane.tag().to_owned(),
                        harness_dir: finding.harness_dir.clone(),
                        problem: refusal.to_string(),
                    };
                    if let Some(alternative) =
                        repro_lane::alternative(&finding.work_dir, &record, &refusal)
                    {
                        bhfeprintln!("  reproduce it with: {alternative}");
                    }
                }
                None => {
                    failed += 1;
                    bhfeprintln!("  {} failed: {e:#}", finding.finding_id);
                }
            },
        }
    }
    if !out_root_existed {
        // Only removes an empty dir: nothing was packaged into it.
        let _ = std::fs::remove_dir(&out_root);
    }
    let skipped = match selection_refused + refused_at_plan {
        0 => String::new(),
        n => format!("; {n} finding(s) skipped"),
    };
    println!(
        "bhf capsule: {made} capsule(s) written to {} ({reproduced} verified to reproduce{skipped})",
        out_root.display()
    );
    repro_lane::exit_code(&repro_lane::RunTally {
        requested,
        made,
        verified: reproduced,
        failed,
    })
}

/// A finding selected for packaging.
struct FindingRef {
    finding_id: String,
    finding_dir: PathBuf,
    harness_id: String,
    harness_dir: PathBuf,
    work_dir: PathBuf,
    lane: &'static dyn Lane,
    /// Crash inputs, minimized first.
    inputs: Vec<PathBuf>,
    raw: Value,
}

/// A written capsule's summary.
struct CapsuleReport {
    finding_id: String,
    capsule_path: PathBuf,
    reproduced: bool,
    signature: String,
    /// How the reproduced crash compared with the finding's identity.
    compared: Option<String>,
    /// Which input shipped, e.g. `min_testcase.bin (minimized, 5 bytes)`.
    input_note: String,
    not_reproduced_reason: String,
    /// `<file> names <path>`: what keeps the capsule from rebuilding elsewhere.
    portability: Vec<String>,
    warnings: Vec<String>,
}

/// What building and replaying a capsule showed.
#[derive(Debug, Default)]
struct Verification {
    built: bool,
    /// The last line the failed rebuild printed.
    build_error: Option<String>,
    /// The capsule-relative input that reproduced the crash.
    reproduced_with: Option<String>,
    signature: String,
    /// The input protocol the rebuilt PoC was replayed with, and why.
    protocol: Option<(HarnessProtocol, String)>,
    /// How the reproducing crash compared with the finding's identity, when
    /// the capsule records one.
    identity: Option<IdentityCheck>,
    /// The first replay that crashed, but not with the finding's crash.
    mismatch: Option<Mismatch>,
    /// The rebuilt PoC could not be started at all (permission denied).
    unrunnable: bool,
    /// The rebuild failed because it was denied running a program
    /// (`Permission denied`, as on a mount without exec permission).
    exec_denied: bool,
}

/// How a reproduced crash compared with the finding's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityCheck {
    /// `match`, or `unverified` when where the crash happened could not be
    /// compared.
    verdict: &'static str,
    /// The compared fields (`rule BHF-201; kind heap-buffer-overflow; ...`),
    /// or what was not compared.
    line: String,
}

/// A replay that crashed with another crash than the finding's.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mismatch {
    input: String,
    signature: String,
    /// The differing fields, comma-separated (`kind,site`).
    fields: String,
    /// One line per differing field (`kind: recorded ..., replayed ...`).
    differences: Vec<String>,
}

fn build_capsule(f: &FindingRef, out_root: &Path, tar: bool) -> anyhow::Result<CapsuleReport> {
    validate_capsule_id(&f.finding_id, "finding")?;
    validate_capsule_id(&f.harness_id, "harness")?;
    let plan = f.lane.plan_capsule(&HarnessContext::new(
        &f.work_dir,
        &f.harness_id,
        &f.harness_dir,
    ))?;
    std::fs::create_dir_all(out_root).map_err(|error| {
        anyhow::anyhow!("cannot create output dir {}: {error}", out_root.display())
    })?;
    // Build in a scratch dir beside the final one and move it into place only
    // when complete: a failure removes the scratch dir, never leaving a
    // half-written capsule for verify-poc to trip over.
    let staging = tempfile::Builder::new()
        .prefix(&format!(".capsule_{}.", f.finding_id))
        .tempdir_in(out_root)?;
    let cap = staging.path();
    for file in &plan.files {
        copy(&file.from, &cap.join(&file.to))?;
    }
    for file in &plan.generated {
        let dest = cap.join(&file.to);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &file.bytes)?;
        if file.executable {
            set_executable(&dest);
        }
    }
    let mut inputs = Vec::new();
    for input in &f.inputs {
        let name = basename(input);
        copy(input, &cap.join("input").join(&name))?;
        inputs.push(format!("input/{name}"));
    }
    let build_path = cap.join("build.sh");
    std::fs::write(&build_path, &plan.build_script)?;
    set_executable(&build_path);
    if let Some(windows) = &plan.windows {
        std::fs::write(cap.join(WINDOWS_BUILD_SCRIPT), &windows.script)?;
    }

    // The crash the finding recorded, in the capsule's own paths: a replay
    // reproduces the finding only when it shows that crash, at that place.
    let paths = PathMap::new(&plan, &f.work_dir);
    let identity = f
        .lane
        .finding_identity(&f.raw, &|path: &str| paths.shipped(path));
    // Verify by construction: build + replay, capture the signature. The
    // minimized input ships when it reproduces; otherwise the recorded one.
    let verification = verify_packaged(cap, f, &inputs, identity.as_ref());
    // Leave the capsule pristine (no compiled binary with a machine-specific path).
    remove_build_outputs(cap, &plan.build_outputs);
    let chosen = verification
        .reproduced_with
        .clone()
        .or_else(|| {
            inputs
                .iter()
                .find(|input| input.ends_with("/testcase.bin"))
                .cloned()
        })
        .or_else(|| inputs.first().cloned());
    // The chosen input always ships as `input/testcase.bin`, the path older
    // capsules and scripts use; the manifest records which one it is.
    let source = chosen
        .as_deref()
        .map(|input| basename(Path::new(input)))
        .unwrap_or_else(|| "testcase.bin".to_owned());
    for input in inputs
        .iter()
        .filter(|input| Some(*input) != chosen.as_ref())
    {
        let _ = std::fs::remove_file(cap.join(input));
    }
    if let Some(chosen) = chosen.as_deref().filter(|input| *input != SHIPPED_INPUT) {
        std::fs::rename(cap.join(chosen), cap.join(SHIPPED_INPUT))?;
    }
    let minimized = source == "min_testcase.bin";
    // The crash the finding recorded, when the lane can name it: a replay
    // that shows another one reproduces a crash, but not this finding's.
    let finding_signature = f.lane.finding_signature(&f.raw);
    // Compared field by field when the capsule records the finding's
    // identity; else by the signature class.
    let other = match &identity {
        Some(_) => None,
        None => other_crash(
            finding_signature.as_deref(),
            verification.reproduced_with.is_some(),
            &verification.signature,
        ),
    };
    let reproduced = verification.reproduced_with.is_some() && other.is_none();
    let format_note = crate::generate_harness::finding_format_note(&f.raw, &f.harness_dir);
    std::fs::write(
        cap.join("README.md"),
        readme(
            f,
            &plan,
            &source,
            &verification,
            finding_signature.as_deref(),
        ),
    )?;
    let mut manifest = manifest_value(
        f,
        &plan,
        &verification,
        &source,
        format_note.as_deref(),
        finding_signature.as_deref(),
        identity.as_ref(),
        &paths,
    );
    // Portable means a rebuild elsewhere reaches nothing on this host: no
    // shipped file and no manifest field names the work dir or the tree.
    let mut portability = plan.portability.problems.clone();
    if !plan.portability.protected.is_empty() {
        portability.extend(files_naming(cap, &plan.portability.protected));
    }
    let host: Vec<PathBuf> = plan
        .portability
        .protected
        .iter()
        .cloned()
        .chain(paths.host_dirs())
        .collect();
    if let Some(named) = value_naming(&manifest, &host) {
        portability.push(format!("manifest.json names {named}"));
    }
    portability.dedup();
    manifest["portable"] = json!(portability.is_empty());
    if !portability.is_empty() {
        manifest["portability"] = json!(portability);
    }
    std::fs::write(
        cap.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    let final_dir = out_root.join(format!("capsule_{}", f.finding_id));
    if final_dir.exists() {
        std::fs::remove_dir_all(&final_dir)?;
    }
    let staged = staging.keep();
    if let Err(error) = std::fs::rename(&staged, &final_dir) {
        let _ = std::fs::remove_dir_all(&staged);
        anyhow::bail!(
            "cannot move the capsule into {}: {error}",
            final_dir.display()
        );
    }
    if tar {
        make_tarball(out_root, &final_dir)?;
    }
    let size = std::fs::metadata(final_dir.join(SHIPPED_INPUT))
        .map(|meta| meta.len())
        .unwrap_or(0);
    let not_reproduced_reason = match &verification.build_error {
        Some(error) if !verification.built => format!("the rebuild failed: {error}"),
        _ if !verification.built => "the rebuild failed".to_owned(),
        _ => match (&verification.mismatch, &identity) {
            (Some(mismatch), Some(identity)) if verification.reproduced_with.is_none() => {
                format!(
                    "the rebuilt PoC shows {}, the finding recorded {}",
                    describe_mismatch(mismatch),
                    describe_identity(identity, finding_signature.as_deref())
                )
            }
            _ => other.unwrap_or_else(|| {
                "the rebuilt PoC did not crash on the finding's input".to_owned()
            }),
        },
    };
    Ok(CapsuleReport {
        finding_id: f.finding_id.clone(),
        capsule_path: final_dir,
        reproduced,
        signature: verification.signature,
        compared: verification.identity.map(|check| check.line),
        input_note: format!(
            "{source} ({}, {size} bytes) as {SHIPPED_INPUT}",
            if minimized {
                "minimized"
            } else {
                "as recorded"
            }
        ),
        not_reproduced_reason,
        portability,
        warnings: plan.warnings.into_iter().chain(format_note).collect(),
    })
}

/// Where the files a capsule ships came from, so a path the finding records
/// is written as the capsule ships it.
struct PathMap {
    /// Original (normalized) path and capsule path of every shipped file.
    shipped: Vec<(PathBuf, String)>,
    work_dir: PathBuf,
    source_root: Option<PathBuf>,
}

impl PathMap {
    fn new(plan: &repro_lane::CapsulePlan, work_dir: &Path) -> Self {
        let absolute = |path: &Path| {
            repro_lane::normalize(&std::path::absolute(path).unwrap_or_else(|_| path.into()))
        };
        let shipped = plan
            .files
            .iter()
            .map(|file| (absolute(&file.from), file.to.clone()))
            .chain(
                plan.portability
                    .shipped_paths
                    .iter()
                    .map(|(from, to)| (absolute(from), to.clone())),
            )
            .collect();
        let work_dir = absolute(work_dir);
        Self {
            shipped,
            source_root: repro_lane::recorded_source_root(&work_dir),
            work_dir,
        }
    }

    /// The capsule path of the file the capsule ships for `path`.
    fn shipped(&self, path: &str) -> Option<String> {
        let path = Path::new(path);
        if !path.is_absolute() {
            return None;
        }
        let path = repro_lane::normalize(path);
        self.shipped
            .iter()
            .find(|(from, _)| *from == path)
            .map(|(_, to)| to.clone())
    }

    /// `path` as a manifest records it: the capsule path of the file it
    /// ships, else relative to the scanned tree, else to the work dir. A
    /// recorded value that only embeds a path gets the same treatment for each
    /// path in it.
    fn portable(&self, path: &str) -> String {
        if let Some(shipped) = self.shipped(path) {
            return shipped;
        }
        let normalized = repro_lane::normalize(Path::new(path));
        if let Some(rel) = self
            .source_root
            .iter()
            .chain(std::iter::once(&self.work_dir))
            .find_map(|root| normalized.strip_prefix(root).ok())
            .filter(|_| Path::new(path).is_absolute())
        {
            return rel.to_string_lossy().replace('\\', "/");
        }
        // A recorded value that only embeds a path (`Lua finding: /tree/x.lua`).
        let mut text = path.to_owned();
        for (from, to) in &self.shipped {
            text = text.replace(&*from.to_string_lossy(), to);
        }
        for root in self
            .source_root
            .iter()
            .chain(std::iter::once(&self.work_dir))
        {
            let root = root.to_string_lossy();
            for separator in ['/', '\\'] {
                text = text.replace(&format!("{root}{separator}"), "");
            }
        }
        text
    }

    /// The host dirs a manifest must not name: the work dir and the tree.
    fn host_dirs(&self) -> impl Iterator<Item = PathBuf> + '_ {
        std::iter::once(self.work_dir.clone()).chain(self.source_root.iter().cloned())
    }
}

/// `<file> names <path>` for each text file under `cap` (but its inputs and
/// manifest) that names one of `protected`.
fn files_naming(cap: &Path, protected: &[PathBuf]) -> Vec<String> {
    const MAX_SCANNED: u64 = 1024 * 1024;
    let mut out = Vec::new();
    let mut stack = vec![cap.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                if path != cap.join("input") {
                    stack.push(path);
                }
                continue;
            }
            if path == cap.join("manifest.json")
                || std::fs::metadata(&path).map_or(true, |meta| meta.len() > MAX_SCANNED)
            {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.contains(&0) {
                continue;
            }
            let Ok(text) = std::str::from_utf8(&bytes) else {
                continue;
            };
            if let Some(named) = repro_lane::relocate::named_protected_path(text, protected) {
                let rel = path
                    .strip_prefix(cap)
                    .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                out.push(format!("{rel} names {named}"));
            }
        }
    }
    out.sort();
    out
}

/// The first string in `value` that names one of `protected`, as
/// `<field> names <path>` would say it (`sink.file`).
fn value_naming(value: &Value, protected: &[PathBuf]) -> Option<String> {
    fn walk(value: &Value, at: &str, protected: &[PathBuf]) -> Option<String> {
        match value {
            Value::String(text) => repro_lane::relocate::named_protected_path(text, protected)
                .map(|named| format!("{named} (in {at})")),
            Value::Array(items) => items
                .iter()
                .enumerate()
                .find_map(|(index, item)| walk(item, &format!("{at}[{index}]"), protected)),
            Value::Object(map) => map.iter().find_map(|(key, item)| {
                let at = if at.is_empty() {
                    key.clone()
                } else {
                    format!("{at}.{key}")
                };
                walk(item, &at, protected)
            }),
            _ => None,
        }
    }
    walk(value, "", protected)
}

/// The finding's identity as one phrase: its signature, kind and where.
fn describe_identity(identity: &Value, signature: Option<&str>) -> String {
    let text = |key: &str| identity.get(key).and_then(Value::as_str);
    let mut parts = Vec::new();
    if let Some(kind) = text("check").or_else(|| text("kind")) {
        parts.push(kind.to_owned());
    }
    match (text("sink_function"), text("site")) {
        (Some(sink), Some(site)) => parts.push(format!("in {sink} at {site}")),
        (Some(sink), None) => parts.push(format!("in {sink}")),
        (None, Some(site)) => parts.push(format!("at {site}")),
        (None, None) => {}
    }
    match (signature, parts.is_empty()) {
        (Some(signature), true) => signature.to_owned(),
        (Some(signature), false) => format!("{signature} ({})", parts.join(" ")),
        (None, false) => parts.join(" "),
        (None, true) => text("rule_id").unwrap_or("its crash").to_owned(),
    }
}

/// A mismatching replay as one phrase: its signature and what differs.
fn describe_mismatch(mismatch: &Mismatch) -> String {
    if mismatch.differences.is_empty() {
        mismatch.signature.clone()
    } else {
        format!(
            "{} ({})",
            mismatch.signature,
            mismatch.differences.join("; ")
        )
    }
}

/// Why a replay that crashed does not reproduce the finding, when the lane
/// names the crash the finding recorded (`finding_signature`) and the replay
/// showed another one.
fn other_crash(finding_signature: Option<&str>, crashed: bool, observed: &str) -> Option<String> {
    let expected = finding_signature.filter(|_| crashed)?;
    (!signature_matches(expected, observed))
        .then(|| format!("the rebuilt PoC shows {observed}, but the finding recorded {expected}"))
}

fn validate_capsule_id(value: &str, label: &str) -> anyhow::Result<()> {
    // Defence in depth lives in corpus::layout::is_valid_finding_id (shared with
    // resolve_finding_id): single safe path segment, no traversal.
    if !corpus::layout::is_valid_finding_id(value) {
        anyhow::bail!("invalid {label} ID: {value:?}");
    }
    Ok(())
}

/// Build the capsule in place, then replay each input in turn; the first that
/// crashes with the finding's crash is the one the capsule reproduces with.
/// With the finding's `identity` (its rule, kind and sink or site, in capsule
/// paths) a crash is compared field by field, as `bhf replay` compares it, and
/// one that differs is not the finding's; without it, any crash is. The
/// rebuilt PoC is replayed with the protocol the shared detector reads off it
/// (the lane's own when the detector finds nothing that says).
fn verify_capsule(
    cap: &Path,
    lane: &dyn Lane,
    inputs: &[String],
    identity: Option<&Value>,
) -> Verification {
    let (mut build, script, poc) = build_command(cap);
    let built = |cap: &Path| cap.join(poc).is_file();
    match crate::command_output::output_with_timeout(&mut build, BUILD_TIMEOUT) {
        Ok(out) if out.status.success() && built(cap) => {}
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            return Verification {
                build_error: build_failure_line(&stderr)
                    .or_else(|| build_failure_line(&stdout))
                    .or_else(|| {
                        (!out.status.success() || !built(cap))
                            .then(|| format!("{script} produced no {poc}"))
                    }),
                exec_denied: [&stderr, &stdout].iter().any(|text| denied_execution(text)),
                ..Verification::default()
            };
        }
        Err(error) => {
            return Verification {
                build_error: Some(format!("cannot run {script}: {error}")),
                ..Verification::default()
            };
        }
    }
    let (protocol, basis) = replay_protocol(cap, lane);
    let record = identity.and_then(|identity| identity.get("record"));
    let mut mismatch = None;
    let mut unrunnable = false;
    for input in inputs {
        // A replay that ran out its wall clock did not show the crash.
        let replay = match repro_lane::replay_poc(cap, input, protocol, REPLAY_TIMEOUT) {
            Ok(replay) if !replay.timed_out => replay,
            Ok(_) => continue,
            Err(error) => {
                unrunnable |= error.kind() == std::io::ErrorKind::PermissionDenied;
                continue;
            }
        };
        let Some(signature) = lane.crash_signature(&replay) else {
            continue;
        };
        let check = match record {
            None => None,
            Some(record) => match identity_check(record, &replay.stderr) {
                Ok(check) => Some(check),
                Err((fields, differences)) => {
                    mismatch.get_or_insert(Mismatch {
                        input: input.clone(),
                        signature,
                        fields,
                        differences,
                    });
                    continue;
                }
            },
        };
        return Verification {
            built: true,
            build_error: None,
            reproduced_with: Some(input.clone()),
            signature,
            protocol: Some((protocol, basis)),
            identity: check,
            mismatch,
            unrunnable: false,
            exec_denied: false,
        };
    }
    Verification {
        built: true,
        protocol: Some((protocol, basis)),
        mismatch,
        unrunnable,
        ..Verification::default()
    }
}

/// Why a capsule of a lane that compares identities has none to compare
/// (manifest `identity_comparison.reason`).
const NO_IDENTITY_REASON: &str = "the finding recorded no sanitizer report to compare field by \
     field, so only the crash class was compared";

/// The packaging-time verification of the staged capsule `cap`. The build
/// runs in a copy outside the work dir, so it reaches nothing beside the
/// capsule that it does not ship; where that copy cannot run what was built
/// in it (a temp dir mounted noexec: the PoC, or a build script or
/// proc-macro the build runs), it runs in place.
fn verify_packaged(
    cap: &Path,
    f: &FindingRef,
    inputs: &[String],
    identity: Option<&Value>,
) -> Verification {
    match verify_elsewhere(cap, f, inputs, identity) {
        Some(verification) if !verification.unrunnable && !verification.exec_denied => verification,
        _ => verify_capsule(cap, f.lane, inputs, identity),
    }
}

/// Whether a build's output says it was denied running a program: the
/// shell's `Permission denied` or a toolchain's `os error 13` (EACCES).
fn denied_execution(output: &str) -> bool {
    output.contains("Permission denied") || output.contains("os error 13")
}

/// [`verify_capsule`] on a copy of the staged capsule in a scratch dir
/// outside the work dir and the scanned tree; `None` when the copy cannot be
/// made.
fn verify_elsewhere(
    cap: &Path,
    f: &FindingRef,
    inputs: &[String],
    identity: Option<&Value>,
) -> Option<Verification> {
    let scratch = tempfile::Builder::new()
        .prefix("bhf-capsule-verify-")
        .tempdir()
        .ok()?;
    let copy = scratch.path().join(format!("capsule_{}", f.finding_id));
    copy_tree(cap, &copy).ok()?;
    Some(verify_capsule(&copy, f.lane, inputs, identity))
}

/// Copy the tree under `from` to `to`, file modes included.
fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// How a replay's crash compares with the finding's identity `record`: how
/// it matched, or the differing fields and one line per difference. A replay
/// that printed no sanitizer report (a bare fatal signal) is taken for the
/// finding's crash, with where it happened not compared.
fn identity_check(record: &Value, stderr: &str) -> Result<IdentityCheck, (String, Vec<String>)> {
    let Some(report) = corpus::sanitizer::parse_sanitizer_report(stderr) else {
        return Ok(IdentityCheck {
            verdict: "unverified",
            line: "site not compared: the rebuilt PoC printed no sanitizer report".to_owned(),
        });
    };
    let comparison = crate::crash_identity::compare(record, &report);
    match comparison.verdict() {
        crate::crash_identity::Verdict::Match => Ok(IdentityCheck {
            verdict: "match",
            line: comparison.compared_line(),
        }),
        crate::crash_identity::Verdict::Unverified => Ok(IdentityCheck {
            verdict: "unverified",
            line: format!(
                "{} not compared ({})",
                comparison.not_compared_fields(),
                comparison.compared_line()
            ),
        }),
        crate::crash_identity::Verdict::Mismatch => {
            Err((comparison.differing_fields(), comparison.difference_lines()))
        }
    }
}

/// Whether the capsule rebuilds here with its Windows build: on Windows, when
/// it ships one.
fn uses_windows_build(cap: &Path) -> bool {
    cfg!(windows) && cap.join(WINDOWS_BUILD_SCRIPT).is_file()
}

/// How a capsule rebuilds here: `build.ps1` through Windows PowerShell on
/// Windows when the capsule ships one (it needs no POSIX shell), else
/// `build.sh` through `sh`; with the script's name and the PoC it writes.
fn build_command(cap: &Path) -> (Command, &'static str, &'static str) {
    if uses_windows_build(cap) {
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            WINDOWS_BUILD_SCRIPT,
        ]);
        command.current_dir(cap);
        return (command, WINDOWS_BUILD_SCRIPT, "poc.exe");
    }
    let mut command = Command::new("sh");
    command.arg("build.sh").current_dir(cap);
    (command, "build.sh", "poc")
}

/// How the rebuilt `<cap>/poc` takes its input: what the shared protocol
/// detector reads off it, else the lane's own protocol.
fn replay_protocol(cap: &Path, lane: &dyn Lane) -> (HarnessProtocol, String) {
    let detection = protocol_detect::detect(&repro_lane::poc_path(cap), &[]);
    if detection.basis == protocol_detect::ProtocolBasis::Default {
        let protocol = lane.protocol();
        return (
            protocol,
            format!(
                "the {} lane's protocol (nothing in ./poc says otherwise)",
                lane.name()
            ),
        );
    }
    (detection.protocol, detection.basis.describe())
}

/// The command line that replays `input` on the rebuilt PoC.
fn run_line(protocol: HarnessProtocol, input: &str) -> String {
    match protocol {
        HarnessProtocol::StdinEventLog => {
            format!("cat {input} | BHF_EVENTS_PATH=events.bin ./poc")
        }
        HarnessProtocol::BhfFramed | HarnessProtocol::LibFuzzerSingleInput => {
            format!("./poc {input}")
        }
    }
}

/// The Windows command line that replays `input` on the PoC build.ps1 wrote.
fn run_line_windows(protocol: HarnessProtocol, input: &str) -> String {
    match protocol {
        // Piped, not redirected: the Ada runtime re-reads its stdin.
        HarnessProtocol::StdinEventLog => format!(
            "cmd /c \"set BHF_EVENTS_PATH=events.bin&& type {} | .\\poc.exe\"",
            input.replace('/', "\\")
        ),
        HarnessProtocol::BhfFramed | HarnessProtocol::LibFuzzerSingleInput => {
            format!(".\\poc.exe {input}")
        }
    }
}

/// The line that says why a rebuild failed: the first compiler diagnostic
/// (`error:`, or MSVC's `error C2065:` and `error LNK2019:`; for a failed
/// link, the linker's own line before clang's summary), else the last line
/// naming an error, else the last line.
fn build_failure_line(stderr: &str) -> Option<String> {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let diagnostic = |line: &str| {
        line.contains("error:")
            || [" error C", " error LNK", "fatal error C", "fatal error LNK"]
                .iter()
                .any(|marker| line.contains(marker))
    };
    if let Some(at) = lines.iter().position(|line| diagnostic(line)) {
        let line = match at.checked_sub(1) {
            Some(before) if lines[at].contains("linker command failed") => lines[before],
            _ => lines[at],
        };
        return Some(line.to_owned());
    }
    lines
        .iter()
        .rev()
        .find(|line| line.contains("error"))
        .or(lines.last())
        .map(|line| (*line).to_owned())
}

fn remove_build_outputs(cap: &Path, outputs: &[&str]) {
    for output in outputs {
        let path = cap.join(output);
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
    // The sanitizer runtime DLLs build.ps1 copies next to poc.exe.
    for entry in std::fs::read_dir(cap).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if name.starts_with("clang_rt.") && name.ends_with(".dll") && entry.path().is_file() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn manifest_value(
    f: &FindingRef,
    plan: &repro_lane::CapsulePlan,
    verification: &Verification,
    input_source: &str,
    format_note: Option<&str>,
    finding_signature: Option<&str>,
    identity: Option<&Value>,
    paths: &PathMap,
) -> Value {
    // The sink names the file in the capsule's terms, not this host's.
    let mut sink = f.raw.pointer("/actionability/sink").cloned();
    if let Some(file) = sink
        .as_mut()
        .and_then(|sink| sink.get_mut("file"))
        .filter(|file| file.is_string())
    {
        let portable = paths.portable(file.as_str().unwrap_or_default());
        *file = json!(portable);
    }
    let cwe = f.raw.pointer("/actionability/cwe").cloned();
    // The main program the rebuild needs, as older capsules recorded it.
    let main_tool = plan.requires.first();
    let protocol = verification
        .protocol
        .as_ref()
        .map(|(protocol, _)| *protocol)
        .unwrap_or_else(|| f.lane.protocol());
    let mut manifest = json!({
        "schema": "bhf.capsule/v1",
        "bhf_version": env!("BHF_VERSION_FULL"),
        "finding_id": f.finding_id,
        "harness_id": f.harness_id,
        "lang": f.lane.tag(),
        "language": f.lane.name(),
        "toolchain": {
            "env": main_tool.map(|tool| tool.env_var.clone()),
            "default": main_tool.map(|tool| tool.program.clone()),
        },
        "requires": plan.requires.iter().map(Requirement::to_json).collect::<Vec<_>>(),
        "rule_id": f.raw.get("rule_id"),
        "cwe": cwe,
        "exception": f.raw.pointer("/exception/name"),
        "sink": sink,
        "input": SHIPPED_INPUT,
        "input_source": input_source,
        "input_minimized": input_source == "min_testcase.bin",
        "build": "sh build.sh",
        "build_recipe": plan.build_facts,
        "protocol": protocol.label(),
        "protocol_basis": verification.protocol.as_ref().map(|(_, basis)| basis),
        "run": run_line(protocol, SHIPPED_INPUT),
        "rebuilt": verification.built,
        // Why the rebuild failed when it was packaged, so verify-poc says so
        // instead of guessing at the crash.
        "build_error": verification.build_error,
        "expected_signature": verification.signature,
        "reproduced": verification.reproduced_with.is_some(),
    });
    // The Windows build: no POSIX shell, its own compilers.
    if let Some(windows) = &plan.windows {
        manifest["build_windows"] = json!(WINDOWS_BUILD_COMMAND);
        manifest["run_windows"] = json!(run_line_windows(protocol, SHIPPED_INPUT));
        manifest["requires_windows"] = json!(windows
            .requires
            .iter()
            .map(Requirement::to_json)
            .collect::<Vec<_>>());
    }
    // The input formats of the harness packaged and of the finding's testcase,
    // when they are recorded, and the note when they differ.
    if let Some(version) = crate::generate_harness::recorded_harness_format_version(&f.harness_dir)
    {
        manifest["harness_format_version"] = json!(version);
    }
    if let Some(format) = corpus::finding::finding_harness_format(&f.raw) {
        manifest["finding_harness_format_version"] = json!(format.version);
    }
    if let Some(note) = format_note {
        manifest["harness_format_note"] = json!(note);
    }
    if let Some(recorded) = finding_signature {
        manifest["finding_signature"] = json!(recorded);
    }
    // The finding's crash as verify-poc compares it: rule, kind, check, sink
    // and site, in the capsule's paths.
    if let Some(identity) = identity {
        manifest["finding_identity"] = identity.clone();
        if let Some(check) = &verification.identity {
            manifest["identity_comparison"] = json!({
                "verdict": check.verdict,
                "compared": check.line,
            });
        }
    } else if f.lane.compares_identity() {
        // A lane that compares identities, on a finding that has none to
        // compare: say so, so verify-poc does not take the capsule for one
        // packaged before identities were recorded.
        manifest["identity_comparison"] = json!({
            "verdict": "none",
            "reason": NO_IDENTITY_REASON,
        });
    }
    // The rebuilt PoC crashed, but not with the finding's crash: it does not
    // reproduce this finding.
    let other_class = identity.is_none()
        && other_crash(
            finding_signature,
            verification.reproduced_with.is_some(),
            &verification.signature,
        )
        .is_some();
    if other_class {
        manifest["reproduced"] = json!(false);
        manifest["reproduced_other_crash"] = json!(true);
    }
    if let (Some(mismatch), None) = (&verification.mismatch, &verification.reproduced_with) {
        manifest["reproduced_other_crash"] = json!(true);
        manifest["other_crash"] = json!({
            "input": mismatch.input,
            "signature": mismatch.signature,
            "differs": mismatch.fields,
            "differences": mismatch.differences,
        });
    }
    manifest
}

fn readme(
    f: &FindingRef,
    plan: &repro_lane::CapsulePlan,
    input_source: &str,
    verification: &Verification,
    finding_signature: Option<&str>,
) -> String {
    use std::fmt::Write as _;
    let which_input = if input_source == "min_testcase.bin" {
        "the minimized crashing input"
    } else {
        "the crashing input"
    };
    let protocol = verification
        .protocol
        .as_ref()
        .map(|(protocol, _)| *protocol)
        .unwrap_or_else(|| f.lane.protocol());
    let mut layout = String::new();
    for (path, what) in &plan.layout {
        let _ = writeln!(layout, "- `{path}` — {what}");
    }
    let _ = writeln!(
        layout,
        "- `{SHIPPED_INPUT}` — {which_input} (the finding's `{input_source}`)"
    );
    let _ = writeln!(
        layout,
        "- `manifest.json` — finding metadata, the toolchain it needs + expected signature"
    );
    let list = |requirements: &[Requirement]| {
        let mut out = String::new();
        for requirement in requirements {
            let _ = writeln!(
                out,
                "- `{}` (or `${}`){}{}{}",
                requirement.program,
                requirement.env_var,
                if requirement.purpose.is_empty() {
                    String::new()
                } else {
                    format!(": {}", requirement.purpose)
                },
                if requirement.alternatives.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; else {}",
                        requirement
                            .alternatives
                            .iter()
                            .map(|name| format!("`{name}`"))
                            .collect::<Vec<_>>()
                            .join(" or ")
                    )
                },
                requirement
                    .version
                    .as_deref()
                    .map(|version| format!(" — packaged with `{version}`"))
                    .unwrap_or_default(),
            );
        }
        out
    };
    let requires = list(&plan.requires);
    let windows = match &plan.windows {
        Some(windows) => format!(
            "\nOn Windows, `build.ps1` rebuilds it with no POSIX shell. It needs:\n\n\
             {}\n\
             ```powershell\n\
             {WINDOWS_BUILD_COMMAND}   # compile .\\poc.exe\n\
             {}    # replay {which_input}\n\
             ```\n\n\
             It compiles with the compiler the harness was built with (cl gets\n\
             `/fsanitize=address` and cl's coverage flags; clang and clang-cl their own),\n\
             or with the one `$env:{}` names. Outside a Developer shell it takes the\n\
             environment cl and clang-cl read from the newest Visual Studio install.\n",
            list(&windows.requires),
            run_line_windows(protocol, SHIPPED_INPUT),
            windows
                .requires
                .first()
                .map(|requirement| requirement.env_var.as_str())
                .unwrap_or("CC"),
        ),
        None => String::new(),
    };
    let run = run_line(protocol, SHIPPED_INPUT);
    let stdin_note = if protocol == HarnessProtocol::StdinEventLog {
        "\nThe harness reads its input from stdin and records what it raised in the\n\
         event log `$BHF_EVENTS_PATH`; pipe the input in (`cat ... |`), as a file\n\
         redirect is read again and again.\n"
    } else {
        ""
    };
    format!(
        "# BHF PoC capsule — {id}\n\n\
         Self-contained reproducer for a crash bhf found in a {language} target on a tree\n\
         with no working build. Rebuilds offline with only these programs and a shell:\n\n\
         {requires}\n\
         ## Reproduce\n\n\
         ```sh\n\
         sh build.sh                 # {summary}\n\
         {run}    # replay {which_input}\n\
         ```\n\
         {stdin_note}{windows}\n\
         Or verify with bhf:\n\n\
         ```sh\n\
         bhf verify-poc .\n\
         ```\n\n\
         Expected signature: {signature}.\n\n\
         ## Layout\n\n\
         {layout}",
        id = f.finding_id,
        language = f.lane.name(),
        summary = plan.build_summary,
        signature = match (
            finding_signature,
            &verification.mismatch,
            &verification.reproduced_with,
        ) {
            (Some(recorded), Some(mismatch), None) => format!(
                "`{recorded}` (what the finding recorded; the rebuilt PoC showed `{}` when \
                 it was packaged)",
                describe_mismatch(mismatch)
            ),
            _ => match finding_signature.filter(|recorded| {
                other_crash(
                    Some(recorded),
                    verification.reproduced_with.is_some(),
                    &verification.signature,
                )
                .is_some()
            }) {
                Some(recorded) => format!(
                    "`{recorded}` (what the finding recorded; the rebuilt PoC showed `{}` \
                     when it was packaged)",
                    verification.signature
                ),
                None => format!("`{}`", verification.signature),
            },
        },
    )
}

// ── `bhf verify-poc` ─────────────────────────────────────────────────────

pub fn run_verify(args: VerifyPocArgs) -> i32 {
    // Accept a directory or a .tar.gz/.tar (extract to a scratch dir via system tar).
    let (root, _scratch) = match resolve_capsule(&args.capsule) {
        Ok(v) => v,
        Err(e) => {
            bhfeprintln!("error: {e}");
            return 1;
        }
    };
    let manifest = match read_json(&root.join("manifest.json")) {
        Some(m) => m,
        None => {
            bhfeprintln!(
                "error: not a bhf capsule (missing manifest.json): {}. `bhf capsule` writes \
                 the manifest last, so a dir without one was never finished; package the \
                 finding again",
                root.display()
            );
            return 1;
        }
    };
    // The crash the finding recorded, when its lane names it, else the one
    // the capsule showed when it was packaged.
    let expected = ["finding_signature", "expected_signature"]
        .iter()
        .find_map(|key| {
            manifest
                .get(*key)
                .and_then(Value::as_str)
                .filter(|signature| !signature.is_empty())
        })
        .unwrap_or("")
        .to_owned();
    // Capsules written before lanes existed are C capsules.
    let tag = manifest.get("lang").and_then(Value::as_str).unwrap_or("c");
    let Some(lane) = repro_lane::lane_for(tag) else {
        bhfeprintln!(
            "error: this capsule is for the `{tag}` lane, which this bhf cannot verify \
             (it verifies {} capsules); rebuild it by hand with `sh build.sh`",
            repro_lane::supported_language_names()
        );
        return 1;
    };
    // The programs the capsule recorded it needs (older capsules: the lane's);
    // on Windows, those of the Windows build when the capsule ships one.
    let requires_key = if uses_windows_build(&root) {
        "requires_windows"
    } else {
        "requires"
    };
    let requires: Vec<Requirement> = match manifest.get(requires_key).and_then(Value::as_array) {
        Some(recorded) => recorded.iter().filter_map(Requirement::from_json).collect(),
        None => lane.tools().iter().map(|tool| tool.requirement()).collect(),
    };
    let missing: Vec<String> = requires.iter().filter_map(Requirement::missing).collect();
    if !missing.is_empty() {
        println!(
            "verify-poc: FAIL — cannot rebuild the {} capsule here; it needs {}:",
            lane.name(),
            repro_lane::describe_requirements(&requires)
        );
        for line in missing {
            println!("  - {line}");
        }
        return 1;
    }
    let input = manifest
        .get("input")
        .and_then(Value::as_str)
        .unwrap_or("input/testcase.bin")
        .to_owned();

    // The finding's crash as the capsule recorded it, compared field by field;
    // a capsule packaged before it was recorded is compared by class.
    let identity = manifest
        .get("finding_identity")
        .filter(|identity| identity.get("record").is_some());
    // Rebuild in place (or a temp copy — for a tar it's already scratch).
    let verification = verify_capsule(&root, lane, std::slice::from_ref(&input), identity);
    remove_build_outputs(
        &root,
        &[
            &["poc", "obj", "build"][..],
            repro_lane::WINDOWS_BUILD_OUTPUTS,
        ]
        .concat(),
    );
    let reproduced = verification.reproduced_with.is_some();
    let finding = manifest
        .get("finding_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    if let (false, Some(mismatch), Some(identity)) = (reproduced, &verification.mismatch, identity)
    {
        // It crashed, but not with the finding's crash.
        println!(
            "verify-poc: MISMATCH — {} (finding {finding}): {} differs",
            mismatch.signature, mismatch.fields
        );
        println!(
            "  expected: {}",
            describe_identity(
                identity,
                (!expected.is_empty()).then_some(expected.as_str())
            )
        );
        for difference in &mismatch.differences {
            println!("  differs:  {difference}");
        }
        return 1;
    }
    let observed = verification.signature;

    if !reproduced {
        // A capsule records whether the crash fired when it was PACKAGED. If it
        // did not, this run is not a regression — the capsule never demonstrated
        // the crash — and saying "did not rebuild+crash as expected" sends the
        // reader hunting for an environment difference that does not exist.
        let packaged_reproducing = manifest
            .get("reproduced")
            .and_then(Value::as_bool)
            .unwrap_or(true)
            || manifest
                .get("reproduced_other_crash")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        if packaged_reproducing {
            println!("verify-poc: FAIL — the capsule did not rebuild+crash as expected");
            println!("  finding:  {finding}");
            println!("  expected: {expected}");
            match &verification.build_error {
                Some(error) if !verification.built => {
                    println!("  observed: the rebuild failed: {error}");
                }
                _ => println!("  observed: <no crash>"),
            }
        } else if manifest.get("rebuilt").and_then(Value::as_bool) == Some(false) {
            // The capsule never ran: its own rebuild failed when it was
            // packaged, so the crash was never replayed. Whether the build is
            // still what fails is this run's to say.
            let packaged_error = manifest
                .get("build_error")
                .and_then(Value::as_str)
                .filter(|error| !error.is_empty())
                .map(|error| format!(": {error}"))
                .unwrap_or_default();
            if verification.built {
                println!(
                    "verify-poc: NOT REPRODUCIBLE — the capsule rebuilds here, but its input \
                     did not crash"
                );
                println!("  finding:  {finding}");
                println!(
                    "  packaged: the crash was never replayed; the rebuild failed \
                     then{packaged_error}"
                );
                println!(
                    "  note:     package the finding again where its harness builds to \
                     record whether its capsule reproduces it; `bhf explain --finding-id \
                     {finding}` shows what the fuzzing run depended on"
                );
            } else {
                println!(
                    "verify-poc: NOT REPRODUCIBLE — the capsule's rebuild failed when it was \
                     packaged{packaged_error}"
                );
                println!("  finding:  {finding}");
                if let Some(error) = &verification.build_error {
                    println!("  observed: the rebuild fails here too: {error}");
                }
                println!(
                    "  fix:      the build, not the crash: run `{}` here to see the error, \
                     fix what the harness build needs (for example the flags its build \
                     recipe records), then package the finding again",
                    if uses_windows_build(&root) {
                        WINDOWS_BUILD_COMMAND
                    } else {
                        "sh build.sh"
                    }
                );
            }
        } else {
            println!(
                "verify-poc: NOT REPRODUCIBLE — this capsule was recorded as \
                 non-reproducing when it was packaged, so there is nothing for it \
                 to verify"
            );
            println!("  finding:  {finding}");
            println!(
                "  note:     the finding fired during fuzzing but not on a standalone \
                 replay (a warm fork-server state, an environment the shim faked, or \
                 a timing-dependent crash). `bhf explain --finding-id {finding}` \
                 shows what the run depended on."
            );
        }
        return 1;
    }
    // With the finding's identity the replay was compared field by field;
    // otherwise, when the manifest recorded a signature, its class must agree
    // (any sanitizer crash counts when it recorded none).
    let matched =
        identity.is_some() || expected.is_empty() || signature_matches(&expected, &observed);
    println!(
        "verify-poc: {} — {} (finding {finding})",
        if matched { "PASS" } else { "MISMATCH" },
        observed,
    );
    match &verification.identity {
        Some(check) if check.verdict == "match" => println!("  compared: {}", check.line),
        Some(check) => println!("  note:     {}", check.line),
        None if lane.compares_identity() && matched => {
            let comparison = manifest.get("identity_comparison");
            let verdict = comparison
                .and_then(|comparison| comparison.get("verdict"))
                .and_then(Value::as_str);
            if verdict == Some("none") {
                let reason = comparison
                    .and_then(|comparison| comparison.get("reason"))
                    .and_then(Value::as_str)
                    .unwrap_or(NO_IDENTITY_REASON);
                println!("  note:     {reason}");
            } else {
                println!(
                    "  note:     this capsule records no finding identity (packaged by an \
                     older bhf), so only the sanitizer class was compared"
                );
            }
        }
        None => {}
    }
    if let Some(problems) = manifest.get("portability").and_then(Value::as_array) {
        if let Some(first) = problems.first().and_then(Value::as_str) {
            println!("  note:     not portable when packaged: {first}");
        }
    }
    if !matched {
        println!("  expected: {expected}");
        let packaged = manifest
            .get("expected_signature")
            .and_then(Value::as_str)
            .filter(|packaged| *packaged != expected && !packaged.is_empty());
        if let Some(packaged) = packaged {
            println!("  packaged: {packaged} (what the rebuilt PoC showed when it was packaged)");
        }
        return 1;
    }
    0
}

/// Whether an observed signature matches the expected one. Exact, but a bare
/// `signal:crash` fallback is accepted against any sanitizer class (a coverage-less
/// rebuild can surface a raw SEGV where the instrumented run named the class).
fn signature_matches(expected: &str, observed: &str) -> bool {
    // Exact class agreement, or either side is the coverage-less `signal:crash`
    // fallback (a raw SEGV where the instrumented run named the ASan class).
    expected == observed || observed == "signal:crash" || expected == "signal:crash"
}

/// Resolve a capsule argument to a usable directory root, absolute (the
/// rebuild and the replay run inside it). A directory is used in place; an
/// archive is extracted to a scratch dir (returned so the caller keeps it
/// alive). The scratch guard is `Some` only for the archive case.
fn resolve_capsule(arg: &Path) -> anyhow::Result<(PathBuf, Option<tempfile::TempDir>)> {
    if arg.is_dir() {
        return Ok((std::path::absolute(arg)?, None));
    }
    if !arg.exists() {
        anyhow::bail!("{}", missing_capsule_message(arg));
    }
    let name = arg.to_string_lossy();
    if !(name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".tar")) {
        anyhow::bail!(
            "capsule must be a directory or a .tar.gz produced by `bhf capsule`: {}",
            arg.display()
        );
    }
    let scratch = tempfile::Builder::new()
        .prefix("bhf-verify-poc-")
        .tempdir()?;
    let status = Command::new("tar")
        .arg("xf")
        .arg(arg)
        .arg("-C")
        .arg(scratch.path())
        .status()
        .map_err(|e| anyhow::anyhow!("cannot run tar to extract capsule: {e}"))?;
    if !status.success() {
        anyhow::bail!("tar failed to extract {}", arg.display());
    }
    // The tarball holds a single `capsule_*` dir; descend into it if present.
    let root = single_subdir(scratch.path()).unwrap_or_else(|| scratch.path().to_path_buf());
    Ok((root, Some(scratch)))
}

/// `no capsule at <path>`, and the `bhf capsule` command that writes one there
/// when the path has the `<work>/capsules/capsule_<id>` shape.
fn missing_capsule_message(arg: &Path) -> String {
    let mut message = format!("no capsule at {}", arg.display());
    let name = arg
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let id = name.strip_prefix("capsule_").map(|rest| {
        [".tar.gz", ".tgz", ".tar"]
            .iter()
            .find_map(|ext| rest.strip_suffix(ext))
            .unwrap_or(rest)
            .to_owned()
    });
    match id.filter(|id| !id.is_empty()) {
        Some(id) => {
            let work_dir = arg
                .parent()
                .filter(|parent| parent.file_name().is_some_and(|n| n == "capsules"))
                .and_then(Path::parent)
                .map(|work| work.display().to_string())
                .unwrap_or_else(|| "<work-dir>".to_owned());
            message.push_str(&format!(
                ": package it first with `bhf capsule --work-dir {work_dir} --finding-id {id}`, \
                 which says why when it cannot package a finding"
            ));
        }
        None => message.push_str(": pass a capsule dir or .tar.gz written by `bhf capsule`"),
    }
    message
}

/// If `dir` holds exactly one subdirectory (and nothing else of substance), return it.
fn single_subdir(dir: &Path) -> Option<PathBuf> {
    let mut subdirs = Vec::new();
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if e.path().is_dir() {
            subdirs.push(e.path());
        }
    }
    if subdirs.len() == 1 {
        subdirs.pop()
    } else {
        None
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_tarball(out_root: &Path, cap: &Path) -> anyhow::Result<()> {
    let name = basename(cap);
    let status = Command::new("tar")
        .arg("czf")
        .arg(out_root.join(format!("{name}.tar.gz")))
        .arg("-C")
        .arg(out_root)
        .arg(&name)
        .status()
        .map_err(|error| anyhow::anyhow!("cannot run tar for capsule {name}: {error}"))?;
    if !status.success() {
        anyhow::bail!("tar failed for capsule {name}: {status}");
    }
    Ok(())
}

fn copy(src: &Path, dest: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dest)
        .map_err(|e| anyhow::anyhow!("copy {} -> {}: {e}", src.display(), dest.display()))?;
    Ok(())
}

fn basename(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn set_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    // Windows has no executable bit.
    #[cfg(not(unix))]
    let _ = path;
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed rebuild is reported by the compiler's diagnostic, not by its
    /// closing `N error(s) generated.` tally.
    #[test]
    fn a_failed_rebuild_reports_the_diagnostic_line() {
        let stderr = "\
In file included from harness/main.cpp:15:
sources/widget.h:2:10: fatal error: 'cstddef' file not found
    2 | #include <cstddef>
      |          ^~~~~~~~~
1 error generated.
";
        assert_eq!(
            build_failure_line(stderr).as_deref(),
            Some("sources/widget.h:2:10: fatal error: 'cstddef' file not found")
        );
        let link = "/usr/bin/ld: cannot find -lwidget\nclang: error: linker command failed with exit code 1 (use -v to see invocation)\n";
        assert_eq!(
            build_failure_line(link).as_deref(),
            Some("/usr/bin/ld: cannot find -lwidget")
        );
        assert_eq!(
            build_failure_line("build.sh: 7: clang: not found\n").as_deref(),
            Some("build.sh: 7: clang: not found")
        );
        assert_eq!(build_failure_line("\n  \n"), None);
        // cl's and link.exe's diagnostics, which build.ps1 passes to stderr.
        let cl = "\
main.c
sources/rec ord.c(3): error C2065: 'CAP': undeclared identifier
build.ps1: C:\\VS\\cl.exe exited with 2 at step link_1
";
        assert_eq!(
            build_failure_line(cl).as_deref(),
            Some("sources/rec ord.c(3): error C2065: 'CAP': undeclared identifier")
        );
        let link = "rec ord.obj : error LNK2019: unresolved external symbol lookup referenced in function record\n\
                    poc.exe : fatal error LNK1120: 1 unresolved externals\n";
        assert_eq!(
            build_failure_line(link).as_deref(),
            Some("rec ord.obj : error LNK2019: unresolved external symbol lookup referenced in function record")
        );
    }

    /// What a Windows build leaves beside the shipped files is removed: the
    /// PoC, its debug info, export library and the sanitizer runtime DLLs.
    #[test]
    fn the_outputs_of_a_windows_build_are_removed() {
        let temp = tempfile::tempdir().unwrap();
        let cap = temp.path();
        for file in [
            "poc.exe",
            "poc.pdb",
            "poc.lib",
            "poc.exp",
            "clang_rt.asan_dynamic-x86_64.dll",
            "clang_rt.asan_dbg_dynamic-x86_64.dll",
            "build.ps1",
            "manifest.json",
        ] {
            std::fs::write(cap.join(file), b"x").unwrap();
        }
        std::fs::create_dir_all(cap.join("obj")).unwrap();
        std::fs::write(cap.join("obj/link.rsp"), b"x").unwrap();
        remove_build_outputs(
            cap,
            &[
                &["poc", "obj", "build"][..],
                repro_lane::WINDOWS_BUILD_OUTPUTS,
            ]
            .concat(),
        );
        let mut left: Vec<String> = std::fs::read_dir(cap)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["build.ps1", "manifest.json"]);
    }

    /// The Windows replay line runs poc.exe from PowerShell or cmd.
    #[test]
    fn the_windows_replay_line_names_poc_exe() {
        assert_eq!(
            run_line_windows(HarnessProtocol::BhfFramed, SHIPPED_INPUT),
            ".\\poc.exe input/testcase.bin"
        );
        assert_eq!(
            run_line_windows(HarnessProtocol::StdinEventLog, SHIPPED_INPUT),
            "cmd /c \"set BHF_EVENTS_PATH=events.bin&& type input\\testcase.bin | .\\poc.exe\""
        );
    }

    /// A replay that crashes with another crash than the one the finding
    /// recorded does not reproduce the finding; one with no recorded crash to
    /// compare, or the same one, does.
    #[test]
    fn a_replay_showing_another_crash_does_not_reproduce_the_finding() {
        let reason = other_crash(Some("ada:PROGRAM_ERROR"), true, "ada:CONSTRAINT_ERROR").unwrap();
        assert_eq!(
            reason,
            "the rebuilt PoC shows ada:CONSTRAINT_ERROR, but the finding recorded \
             ada:PROGRAM_ERROR"
        );
        assert_eq!(
            other_crash(Some("ada:PROGRAM_ERROR"), true, "ada:PROGRAM_ERROR"),
            None
        );
        assert_eq!(
            other_crash(Some("ada:PROGRAM_ERROR"), true, "signal:crash"),
            None
        );
        assert_eq!(other_crash(None, true, "ada:CONSTRAINT_ERROR"), None);
        assert_eq!(other_crash(Some("ada:PROGRAM_ERROR"), false, ""), None);
    }

    fn plan_shipping(files: &[(&str, &str)]) -> repro_lane::CapsulePlan {
        repro_lane::CapsulePlan {
            files: files
                .iter()
                .map(|(from, to)| repro_lane::CapsuleFile {
                    from: PathBuf::from(from),
                    to: (*to).to_owned(),
                })
                .collect(),
            generated: Vec::new(),
            build_script: String::new(),
            build_summary: String::new(),
            build_facts: json!({}),
            requires: Vec::new(),
            layout: Vec::new(),
            build_outputs: Vec::new(),
            warnings: Vec::new(),
            windows: None,
            portability: repro_lane::PlanPortability {
                shipped_paths: vec![(
                    PathBuf::from("/w/harnesses/H-X1/repairs/auto_stubs.cpp"),
                    "stubs/auto_stubs.cpp".to_owned(),
                )],
                ..Default::default()
            },
        }
    }

    /// A path the finding records is written in the manifest as the capsule
    /// ships the file, else relative to the scanned tree or the work dir; a
    /// path neither holds stays as it is.
    #[test]
    fn a_manifest_names_recorded_paths_in_capsule_terms() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("w");
        let tree = temp.path().join("tree");
        let text = |path: &Path| path.to_string_lossy().into_owned();
        std::fs::create_dir_all(work.join("auto")).unwrap();
        std::fs::write(
            work.join("auto/run.json"),
            json!({ "source_root": tree }).to_string(),
        )
        .unwrap();
        let reader = tree.join("src").join("reader.cpp");
        let mut plan = plan_shipping(&[(&text(&reader), "sources/src/reader.cpp")]);
        let stub = work.join("harnesses/H-X1/repairs/auto_stubs.cpp");
        plan.portability.shipped_paths = vec![(stub.clone(), "stubs/auto_stubs.cpp".to_owned())];
        let paths = PathMap::new(&plan, &work);
        assert_eq!(
            paths.portable(&text(&tree.join("src").join(".").join("reader.cpp"))),
            "sources/src/reader.cpp"
        );
        assert_eq!(paths.portable(&text(&stub)), "stubs/auto_stubs.cpp");
        assert_eq!(
            paths.portable(&text(&tree.join("lib").join("other.c"))),
            "lib/other.c"
        );
        assert_eq!(
            paths.portable(&text(&work.join("harnesses").join("H-X1").join("main.cpp"))),
            "harnesses/H-X1/main.cpp"
        );
        assert_eq!(
            paths.portable("/usr/include/string.h"),
            "/usr/include/string.h"
        );
        assert_eq!(paths.portable("reader.cpp"), "reader.cpp");
        // A recorded value that embeds a path, as a runtime's report line does.
        assert_eq!(
            paths.portable(&format!(
                "Lua finding: {}/lib/record_parser.lua",
                tree.display()
            )),
            "Lua finding: lib/record_parser.lua"
        );
        assert_eq!(
            paths.portable(&format!("finding at {}:3", reader.display())),
            "finding at sources/src/reader.cpp:3"
        );

        // A manifest field that still names the work dir or the tree is found.
        let host: Vec<PathBuf> = paths.host_dirs().collect();
        let manifest = json!({
            "finding_id": "F-0001-0000aaaa",
            "sink": {"file": "sources/src/reader.cpp"},
            "requires": [{"program": "/usr/bin/clang++"}],
        });
        assert_eq!(value_naming(&manifest, &host), None);
        let leaky = json!({ "sink": { "file": reader } });
        assert_eq!(
            value_naming(&leaky, &host),
            Some(format!("{} (in sink.file)", reader.display()))
        );
    }

    /// Every shipped text file is checked for the dirs a rebuild elsewhere
    /// cannot reach; the inputs and the manifest are not shipped text.
    #[test]
    fn shipped_files_naming_a_host_dir_are_reported() {
        let temp = tempfile::tempdir().unwrap();
        let cap = temp.path();
        std::fs::create_dir_all(cap.join("stubs")).unwrap();
        std::fs::create_dir_all(cap.join("input")).unwrap();
        std::fs::write(
            cap.join("stubs/auto_stubs.c"),
            "#include \"/tree/inc/vendor.h\"\n",
        )
        .unwrap();
        std::fs::write(
            cap.join("stubs/ok.c"),
            "#include \"../sources/inc/vendor.h\"\n",
        )
        .unwrap();
        std::fs::write(cap.join("input/testcase.bin"), "/tree/inc").unwrap();
        std::fs::write(cap.join("manifest.json"), "\"/tree\"").unwrap();
        assert_eq!(
            files_naming(cap, &[PathBuf::from("/tree")]),
            ["stubs/auto_stubs.c names /tree/inc/vendor.h"]
        );
        // A path that only starts with the dir's name is another dir.
        std::fs::write(cap.join("stubs/auto_stubs.c"), "/treehouse/x.h\n").unwrap();
        assert!(files_naming(cap, &[PathBuf::from("/tree")]).is_empty());
    }

    /// A replay's crash compared with the finding's identity: the same crash
    /// matches; another check differs, naming the field; a replay without a
    /// sanitizer report is taken, its site not compared.
    #[test]
    fn a_replay_is_compared_with_the_finding_identity() {
        let record = json!({
            "rule_id": "BHF-201",
            "exception": {
                "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                "sanitizer": "asan",
                "stack": [{"function": "parse_record", "file": "sources/parse.c", "line": 7}]
            }
        });
        let asan = |kind: &str, line: u32| {
            format!(
                "==1==ERROR: AddressSanitizer: {kind} on address 0x602000000014 at pc 0x1 bp 0x2 sp 0x3\n\
                 WRITE of size 8 at 0x602000000014 thread T0\n\
                 \x20   #0 0x1 in __asan_memcpy\n\
                 \x20   #1 0x2 in parse_record /c/sources/parse.c:{line}:5\n\
                 \x20   #2 0x3 in main /c/harness/main.c:90:3\n\
                 SUMMARY: AddressSanitizer: {kind} /c/sources/parse.c:{line}:5 in parse_record\n"
            )
        };
        let same = identity_check(&record, &asan("heap-buffer-overflow", 7)).unwrap();
        assert_eq!(same.verdict, "match");
        assert!(same.line.contains("sink parse_record"), "{}", same.line);
        let (fields, differences) = identity_check(&record, &asan("SEGV", 3)).unwrap_err();
        assert!(fields.contains("kind"), "{fields}");
        assert!(
            differences
                .iter()
                .any(|line| line.starts_with("kind: recorded heap-buffer-overflow")),
            "{differences:?}"
        );
        let bare = identity_check(&record, "Segmentation fault\n").unwrap();
        assert_eq!(bare.verdict, "unverified");
        assert!(bare.line.contains("site not compared"), "{}", bare.line);
    }

    /// The capsule-time verification runs in a copy away from where the
    /// capsule is staged: a build that reaches a file beside the capsule
    /// (here, one next to its dir) does not verify.
    #[cfg(unix)]
    #[test]
    fn a_capsule_is_verified_away_from_where_it_is_staged() {
        let temp = tempfile::tempdir().unwrap();
        let out = temp.path().join("work/capsules");
        let cap = out.join(".capsule_F-1.stage");
        std::fs::create_dir_all(cap.join("input")).unwrap();
        std::fs::write(cap.join("input/testcase.bin"), b"x").unwrap();
        std::fs::write(out.join("beside.txt"), b"x").unwrap();
        // A PoC that reports a sanitizer crash, written only when the file
        // beside the capsule is reachable.
        std::fs::write(
            cap.join("build.sh"),
            "#!/bin/sh\nset -e\ncd \"$(dirname \"$0\")\"\ntest -f ../beside.txt\n\
             printf '#!/bin/sh\\necho \"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\" >&2\\nexit 1\\n' > poc\n\
             chmod +x poc\n",
        )
        .unwrap();
        let finding = FindingRef {
            finding_id: "F-1".to_owned(),
            finding_dir: temp.path().join("work/results/findings/F-1"),
            harness_id: "H-C0001".to_owned(),
            harness_dir: temp.path().join("work/harnesses/H-C0001"),
            work_dir: temp.path().join("work"),
            lane: &repro_lane::C_LANE,
            inputs: Vec::new(),
            raw: json!({}),
        };
        let inputs = vec!["input/testcase.bin".to_owned()];
        let elsewhere = verify_elsewhere(&cap, &finding, &inputs, None).unwrap();
        assert!(!elsewhere.built, "{elsewhere:?}");
        assert!(
            !cap.join("poc").exists(),
            "the copy's build leaves the staged capsule as packaged"
        );
        // In place, the same build reaches the file and the PoC reproduces.
        let in_place = verify_capsule(&cap, &repro_lane::C_LANE, &inputs, None);
        assert!(in_place.reproduced_with.is_some(), "{in_place:?}");
    }

    /// A build that cannot run a program it built in the scratch copy (a
    /// temp dir mounted noexec: `Permission denied`) says nothing about the
    /// capsule, so packaging verifies it in place instead.
    #[cfg(unix)]
    #[test]
    fn a_build_denied_execution_in_the_scratch_copy_is_verified_in_place() {
        let temp = tempfile::tempdir().unwrap();
        let out = temp.path().join("work/capsules");
        let cap = out.join(".capsule_F-1.stage");
        std::fs::create_dir_all(cap.join("input")).unwrap();
        std::fs::write(cap.join("input/testcase.bin"), b"x").unwrap();
        std::fs::write(out.join("beside.txt"), b"x").unwrap();
        // Away from the staged capsule the build fails the way a build
        // script or proc-macro does on a noexec mount; in place it builds a
        // PoC that reports a sanitizer crash.
        std::fs::write(
            cap.join("build.sh"),
            "#!/bin/sh\ncd \"$(dirname \"$0\")\"\n\
             if ! test -f ../beside.txt; then\n\
             echo 'error: could not execute process `build/tool` (never executed)' >&2\n\
             echo 'Caused by: Permission denied (os error 13)' >&2\n\
             exit 101\nfi\n\
             printf '#!/bin/sh\\necho \"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\" >&2\\nexit 1\\n' > poc\n\
             chmod +x poc\n",
        )
        .unwrap();
        let finding = FindingRef {
            finding_id: "F-1".to_owned(),
            finding_dir: temp.path().join("work/results/findings/F-1"),
            harness_id: "H-C0001".to_owned(),
            harness_dir: temp.path().join("work/harnesses/H-C0001"),
            work_dir: temp.path().join("work"),
            lane: &repro_lane::C_LANE,
            inputs: Vec::new(),
            raw: json!({}),
        };
        let inputs = vec!["input/testcase.bin".to_owned()];
        let elsewhere = verify_elsewhere(&cap, &finding, &inputs, None).unwrap();
        assert!(!elsewhere.built, "{elsewhere:?}");
        let verified = verify_packaged(&cap, &finding, &inputs, None);
        assert!(verified.reproduced_with.is_some(), "{verified:?}");

        // A build that fails for any other reason fails where it was copied
        // to, and is reported as it failed there.
        std::fs::write(
            cap.join("build.sh"),
            "#!/bin/sh\ncd \"$(dirname \"$0\")\"\n\
             test -f ../beside.txt || { echo 'cc: error: no input files' >&2; exit 1; }\n\
             printf '#!/bin/sh\\nexit 1\\n' > poc\nchmod +x poc\n",
        )
        .unwrap();
        let verified = verify_packaged(&cap, &finding, &inputs, None);
        assert!(!verified.built, "{verified:?}");
        assert_eq!(
            verified.build_error.as_deref(),
            Some("cc: error: no input files")
        );
    }

    #[test]
    fn signature_match_rules() {
        assert!(signature_matches(
            "AddressSanitizer:stack-buffer-overflow",
            "AddressSanitizer:stack-buffer-overflow"
        ));
        assert!(signature_matches("AddressSanitizer:SEGV", "signal:crash"));
        assert!(!signature_matches(
            "AddressSanitizer:heap-use-after-free",
            "AddressSanitizer:stack-buffer-overflow"
        ));
    }

    #[test]
    fn capsule_rejects_hostile_ids_before_touching_output() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let out = temp.path().join("out");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let harness = crate::auto::layout::harness_dir(&work, "H-C-1");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(harness.join("Makefile"), b"").unwrap();
        std::fs::create_dir(out.join("capsule_x")).unwrap();
        let sentinel = temp.path().join("sentinel");
        std::fs::create_dir(&sentinel).unwrap();
        std::fs::write(sentinel.join("keep"), b"keep").unwrap();
        let finding = FindingRef {
            finding_id: "x/../../sentinel".to_owned(),
            finding_dir: work.join("results/findings/x"),
            harness_id: "H-C-1".to_owned(),
            harness_dir: harness,
            work_dir: work.clone(),
            lane: &repro_lane::C_LANE,
            inputs: Vec::new(),
            raw: json!({}),
        };
        assert!(build_capsule(&finding, &out, false).is_err());
        assert_eq!(std::fs::read(sentinel.join("keep")).unwrap(), b"keep");
        assert!(validate_capsule_id("H-C\\..\\outside", "harness").is_err());
        assert!(validate_capsule_id("C:outside", "harness").is_err());
    }

    #[test]
    fn capsule_reports_requested_packaging_failure() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let finding_dir = work.join("results/findings/F-1");
        std::fs::create_dir_all(&finding_dir).unwrap();
        std::fs::write(finding_dir.join("testcase.bin"), b"input").unwrap();
        std::fs::write(
            finding_dir.join("finding.json"),
            br#"{"id":"F-1","classification":"unhandled","harness_id":"H-C-1"}"#,
        )
        .unwrap();
        let code = run(CapsuleArgs {
            work_dir: work,
            finding_id: Some("F-1".to_owned()),
            out: Some(temp.path().join("out")),
            tar: false,
            verbose: false,
        });
        assert_eq!(code, 1, "missing harness Makefile must fail packaging");
        assert!(
            !temp.path().join("out").exists(),
            "a refused finding leaves no output dir"
        );
    }

    /// A packaging step that fails part-way leaves neither a skeleton capsule
    /// nor scratch dirs behind.
    #[cfg(unix)]
    #[test]
    fn a_failed_capsule_build_leaves_nothing_behind() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: root reads unreadable files");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("proj");
        let harness = temp.path().join("work/harnesses/H-C0001-00000001");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(harness.join("main.c"), "int main(void) { return 0; }\n").unwrap();
        // The target source exists but cannot be read, so copying it fails
        // after the scratch dir exists.
        let target = src.join("locked.c");
        std::fs::write(&target, "int locked;\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::write(
            harness.join("Makefile"),
            format!(
                "main: main.c\n\t$(CC) $(CFLAGS) -o $@ main.c {} $(AUTO_EXTRA_SOURCES)\n",
                target.display()
            ),
        )
        .unwrap();
        let out = temp.path().join("out");
        let finding = FindingRef {
            finding_id: "F-0001-00000001".to_owned(),
            finding_dir: temp.path().join("work/results/findings/F-0001-00000001"),
            harness_id: "H-C0001-00000001".to_owned(),
            harness_dir: harness,
            work_dir: temp.path().join("work"),
            lane: &repro_lane::C_LANE,
            inputs: Vec::new(),
            raw: json!({}),
        };
        let Err(error) = build_capsule(&finding, &out, false) else {
            panic!("an unreadable target source must fail packaging");
        };
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(format!("{error:#}").contains("locked.c"), "{error:#}");
        let left: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(
            left.is_empty(),
            "nothing may be left in {}: {left:?}",
            out.display()
        );
    }

    /// verify-poc on a path that does not exist reports that, with the
    /// `bhf capsule` command that writes a capsule there.
    #[test]
    fn a_missing_capsule_path_names_the_command_that_makes_it() {
        let message =
            missing_capsule_message(Path::new("/w/bhf_work/capsules/capsule_F-0001-0000aaaa"));
        assert!(
            message.starts_with("no capsule at /w/bhf_work/capsules/capsule_F-0001-0000aaaa"),
            "{message}"
        );
        assert!(
            message.contains("bhf capsule --work-dir /w/bhf_work --finding-id F-0001-0000aaaa"),
            "{message}"
        );
        let tarball = missing_capsule_message(Path::new("/x/capsule_F-2.tar.gz"));
        assert!(
            tarball.contains("--work-dir <work-dir> --finding-id F-2`"),
            "{tarball}"
        );
        let other = missing_capsule_message(Path::new("/x/somewhere"));
        assert!(other.contains("written by `bhf capsule`"), "{other}");
        let error = resolve_capsule(Path::new("/nonexistent/capsule_F-3")).unwrap_err();
        assert!(format!("{error}").starts_with("no capsule at"), "{error}");
    }

    #[test]
    fn tarball_command_failure_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        assert!(make_tarball(temp.path(), &temp.path().join("missing-capsule")).is_err());
    }

    #[test]
    fn a_capsule_packaged_as_non_reproducing_verifies_as_such_not_as_a_failure() {
        // `capsule` writes a package even when the reconstruction did not fire,
        // marking `reproduced: false`. Running verify-poc on one then printed
        // "did not rebuild+crash as expected", which reads as a regression and
        // sends the reader looking for an environment difference that never
        // existed. The manifest already knows better.
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = serde_json::json!({
            "schema": "bhf.capsule/v1",
            "finding_id": "F-0000-a3531355",
            "expected_signature": "",
            "reproduced": false,
        });
        std::fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("serialize"),
        )
        .expect("write manifest");

        let parsed = read_json(&dir.path().join("manifest.json")).expect("read back");
        assert_eq!(
            parsed.get("reproduced").and_then(Value::as_bool),
            Some(false),
            "the packaged verdict is what verify-poc must report"
        );
        // A capsule that WAS reproducing when packaged keeps the strict reading.
        let strict = serde_json::json!({"finding_id": "F-1", "reproduced": true});
        assert_eq!(
            strict.get("reproduced").and_then(Value::as_bool),
            Some(true)
        );
        // An older capsule without the field is treated as reproducing, so its
        // failure is still reported as a failure.
        let legacy = serde_json::json!({"finding_id": "F-2"});
        assert!(legacy
            .get("reproduced")
            .and_then(Value::as_bool)
            .unwrap_or(true),);
    }
}
