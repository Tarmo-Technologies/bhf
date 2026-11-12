// SPDX-License-Identifier: Apache-2.0

//! `bhf capsule` / `bhf verify-poc` — a portable, self-verifying exploit
//! capsule for a crash bhf found on an un-buildable tree.
//!
//! bhf's whole point is that it fuzzes source with no working build by
//! stitching one together. The flip side: the crash it finds lives inside a
//! throwaway `bhf_work/` full of absolute paths and generated stubs. A capsule
//! makes that crash *hand-offable*: it copies the minimal set that reproduces it —
//! the harness driver, the target sources and the headers they include (in their
//! original layout), the recovered stubs, the C runtime headers, and the crash
//! input (the minimized one when it reproduces) — rewrites every path to be
//! relative, and ships a `build.sh` plus a `manifest.json` recording the exact
//! sanitizer signature to expect. `bhf verify-poc` rebuilds it offline (only the
//! lane's compiler + a shell needed — no bhf) and asserts the same crash
//! reproduces.
//!
//! What gets copied and how it rebuilds is the finding's lane
//! ([`crate::repro_lane`]): C and C++ harnesses today. Any other finding is
//! refused with a reason that names its harness and language.
//!
//! The capsule is self-verifying BY CONSTRUCTION: `capsule` builds and replays it in
//! a scratch dir before moving it into place, records the observed sanitizer
//! signature, and marks `reproduced: false` (never silently) when the
//! reconstruction doesn't fire. A refused or failed finding leaves nothing behind.

use crate::repro_lane::{self, Lane, PlanRequest, Tool};
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

// ── `bhf capsule` ───────────────────────────────────────────────────────

/// `bhf capsule` — package reproducible crashes into portable PoC capsules.
#[derive(Debug, clap::Args)]
pub struct CapsuleArgs {
    /// Work directory of a prior `auto` run to read findings + harnesses from.
    #[arg(long = "work-dir", default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Package only this finding id (default: every runtime crash finding of a
    /// C or C++ harness). Exits non-zero, with the reason, when it cannot be
    /// packaged.
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
#[derive(Debug, clap::Args)]
pub struct VerifyPocArgs {
    /// Capsule directory or `.tar.gz` produced by `bhf capsule`.
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
    for (record, eligible) in selection.eligible {
        let Some(harness_dir) = eligible.harness_dir else {
            failed += 1;
            continue;
        };
        let finding = FindingRef {
            finding_id: record.id,
            harness_id: eligible.harness_id,
            harness_dir,
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
                let mark = if report.reproduced {
                    "✓".to_owned()
                } else {
                    format!("⚠ not reproduced: {}", report.not_reproduced_reason)
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
                }
                for warning in &report.warnings {
                    bhfeprintln!("  {} warning: {warning}", report.finding_id);
                }
            }
            Err(e) => {
                failed += 1;
                bhfeprintln!("  {} failed: {e:#}", finding.finding_id);
            }
        }
    }
    if !out_root_existed {
        // Only removes an empty dir: nothing was packaged into it.
        let _ = std::fs::remove_dir(&out_root);
    }
    let skipped = match selection_refused {
        0 => String::new(),
        n => format!("; {n} finding(s) skipped"),
    };
    println!(
        "bhf capsule: {made} capsule(s) written to {} ({reproduced} verified to reproduce{skipped})",
        out_root.display()
    );
    let requested_unverified = requested && reproduced < made;
    if failed > 0 || made == 0 || requested_unverified {
        1
    } else {
        0
    }
}

/// A finding selected for packaging.
struct FindingRef {
    finding_id: String,
    harness_id: String,
    harness_dir: PathBuf,
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
    /// Which input shipped, e.g. `min_testcase.bin (minimized, 5 bytes)`.
    input_note: String,
    not_reproduced_reason: String,
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
}

fn build_capsule(f: &FindingRef, out_root: &Path, tar: bool) -> anyhow::Result<CapsuleReport> {
    validate_capsule_id(&f.finding_id, "finding")?;
    validate_capsule_id(&f.harness_id, "harness")?;
    let plan = f.lane.plan_capsule(&PlanRequest {
        harness_dir: &f.harness_dir,
    })?;
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
    let mut inputs = Vec::new();
    for input in &f.inputs {
        let name = basename(input);
        copy(input, &cap.join("input").join(&name))?;
        inputs.push(format!("input/{name}"));
    }
    let build_path = cap.join("build.sh");
    std::fs::write(&build_path, &plan.build_script)?;
    set_executable(&build_path);

    // Verify by construction: build + replay in place, capture the signature.
    // The minimized input ships when it reproduces; otherwise the recorded one.
    let verification = verify_capsule(cap, f.lane, &inputs);
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
    let reproduced = verification.reproduced_with.is_some();
    write_manifest(cap, f, &plan, &verification, &source)?;
    std::fs::write(
        cap.join("README.md"),
        readme(f, &plan, &source, &verification.signature),
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
        _ => "the rebuilt PoC did not crash on the finding's input".to_owned(),
    };
    Ok(CapsuleReport {
        finding_id: f.finding_id.clone(),
        capsule_path: final_dir,
        reproduced,
        signature: verification.signature,
        input_note: format!(
            "{source} ({}, {size} bytes) as {SHIPPED_INPUT}",
            if minimized {
                "minimized"
            } else {
                "as recorded"
            }
        ),
        not_reproduced_reason,
        warnings: plan.warnings,
    })
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
/// crashes is the one the capsule reproduces with.
fn verify_capsule(cap: &Path, lane: &dyn Lane, inputs: &[String]) -> Verification {
    let mut build = Command::new("sh");
    build.arg("build.sh").current_dir(cap);
    match crate::command_output::output_with_timeout(&mut build, BUILD_TIMEOUT) {
        Ok(out) if out.status.success() && cap.join("poc").is_file() => {}
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Verification {
                build_error: build_failure_line(&stderr),
                ..Verification::default()
            };
        }
        Err(error) => {
            return Verification {
                build_error: Some(format!("cannot run build.sh: {error}")),
                ..Verification::default()
            };
        }
    }
    for input in inputs {
        let mut replay = lane.replay_command(cap, input);
        let Ok(out) = crate::command_output::output_with_timeout(&mut replay, REPLAY_TIMEOUT)
        else {
            continue;
        };
        let stderr = String::from_utf8_lossy(&out.stderr);
        if let Some(signature) = lane.crash_signature(&stderr, &out.status) {
            return Verification {
                built: true,
                build_error: None,
                reproduced_with: Some(input.clone()),
                signature,
            };
        }
    }
    Verification {
        built: true,
        ..Verification::default()
    }
}

/// The line that says why a rebuild failed: the first compiler diagnostic
/// (`error:`; for a failed link, the linker's own line before it), else the
/// last line naming an error, else the last line.
fn build_failure_line(stderr: &str) -> Option<String> {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if let Some(at) = lines.iter().position(|line| line.contains("error:")) {
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
}

fn write_manifest(
    cap: &Path,
    f: &FindingRef,
    plan: &repro_lane::CapsulePlan,
    verification: &Verification,
    input_source: &str,
) -> anyhow::Result<()> {
    let sink = f.raw.pointer("/actionability/sink").cloned();
    let cwe = f.raw.pointer("/actionability/cwe").cloned();
    let toolchain = f.lane.toolchain();
    let manifest = json!({
        "schema": "bhf.capsule/v1",
        "bhf_version": env!("BHF_VERSION_FULL"),
        "finding_id": f.finding_id,
        "harness_id": f.harness_id,
        "lang": f.lane.tag(),
        "language": f.lane.name(),
        "toolchain": {"env": toolchain.env_var, "default": toolchain.default},
        "rule_id": f.raw.get("rule_id"),
        "cwe": cwe,
        "exception": f.raw.pointer("/exception/name"),
        "sink": sink,
        "input": SHIPPED_INPUT,
        "input_source": input_source,
        "input_minimized": input_source == "min_testcase.bin",
        "build": "sh build.sh",
        "build_recipe": plan.build_facts,
        "run": format!("./poc {SHIPPED_INPUT}"),
        "rebuilt": verification.built,
        "expected_signature": verification.signature,
        "reproduced": verification.reproduced_with.is_some(),
    });
    std::fs::write(
        cap.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

fn readme(
    f: &FindingRef,
    plan: &repro_lane::CapsulePlan,
    input_source: &str,
    signature: &str,
) -> String {
    use std::fmt::Write as _;
    let toolchain = f.lane.toolchain();
    let which_input = if input_source == "min_testcase.bin" {
        "the minimized crashing input"
    } else {
        "the crashing input"
    };
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
        "- `manifest.json` — finding metadata + expected signature"
    );
    format!(
        "# BHF PoC capsule — {id}\n\n\
         Self-contained reproducer for a crash bhf found in a {language} target on a tree\n\
         with no working build. Rebuilds offline with only `{compiler}` (or `${env}`) and a\n\
         shell.\n\n\
         ## Reproduce\n\n\
         ```sh\n\
         sh build.sh                 # compile ./poc (ASan+UBSan)\n\
         ./poc {SHIPPED_INPUT}    # replay {which_input}\n\
         ```\n\n\
         Or verify with bhf:\n\n\
         ```sh\n\
         bhf verify-poc .\n\
         ```\n\n\
         Expected sanitizer signature: `{signature}`.\n\n\
         ## Layout\n\n\
         {layout}",
        id = f.finding_id,
        language = f.lane.name(),
        compiler = toolchain.default,
        env = toolchain.env_var,
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
    let expected = manifest
        .get("expected_signature")
        .and_then(Value::as_str)
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
    if let Some(missing) = lane.toolchain().missing() {
        println!("verify-poc: FAIL — cannot rebuild the capsule: {missing}");
        return 1;
    }
    let input = manifest
        .get("input")
        .and_then(Value::as_str)
        .unwrap_or("input/testcase.bin")
        .to_owned();

    // Rebuild in place (or a temp copy — for a tar it's already scratch).
    let verification = verify_capsule(&root, lane, std::slice::from_ref(&input));
    remove_build_outputs(&root, &["poc", "obj"]);
    let reproduced = verification.reproduced_with.is_some();
    let observed = verification.signature;

    if !reproduced {
        // A capsule records whether the crash fired when it was PACKAGED. If it
        // did not, this run is not a regression — the capsule never demonstrated
        // the crash — and saying "did not rebuild+crash as expected" sends the
        // reader hunting for an environment difference that does not exist.
        let packaged_reproducing = manifest
            .get("reproduced")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let finding = manifest
            .get("finding_id")
            .and_then(Value::as_str)
            .unwrap_or("?");
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
    // Signature match is best-effort: if the manifest recorded one, require the class
    // to agree; otherwise any sanitizer crash counts.
    let matched = expected.is_empty() || signature_matches(&expected, &observed);
    println!(
        "verify-poc: {} — {} (finding {})",
        if matched { "PASS" } else { "MISMATCH" },
        observed,
        manifest
            .get("finding_id")
            .and_then(Value::as_str)
            .unwrap_or("?"),
    );
    if !matched {
        println!("  expected: {expected}");
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

/// Resolve a capsule argument to a usable directory root. A directory is used
/// in place; an archive is extracted to a scratch dir (returned so the caller keeps
/// it alive). The scratch guard is `Some` only for the archive case.
fn resolve_capsule(arg: &Path) -> anyhow::Result<(PathBuf, Option<tempfile::TempDir>)> {
    if arg.is_dir() {
        return Ok((arg.to_path_buf(), None));
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
            harness_id: "H-C-1".to_owned(),
            harness_dir: harness,
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
            harness_id: "H-C0001-00000001".to_owned(),
            harness_dir: harness,
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
