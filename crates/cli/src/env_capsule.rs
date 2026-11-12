// SPDX-License-Identifier: Apache-2.0

//! `bhf env-capsule` — record + replay the shim-served virtualized world for a
//! crash that depends on the ENVIRONMENT, not (only) the fuzz input.
//!
//! bhf fuzzes the content of "trusted" external resources — a config file, a
//! socket peer, a shared-memory partition — by faking them and serving fuzz-driven
//! bytes on reads (environment-response fuzzing, #7). A crash found that way is
//! driven by the SERVED bytes, so the minimized primary input is often empty and
//! replaying it alone does not reproduce: the reproducer lives in the faked world,
//! which a plain corpus file cannot carry.
//!
//! This subcommand captures that world. It replays a crashing input under the shim
//! with `BHF_ENVCAP_RECORD`, so the shim logs the exact bytes it served each
//! faked resource, and bundles the log (`env-world.jsonl`) with the harness binary,
//! the shim, the input, and a `replay.sh`. On replay the shim serves those exact
//! bytes back (`BHF_ENVCAP_REPLAY`), so the crash reproduces DETERMINISTICALLY
//! — even from an empty input — because the environment is pinned. Each capsule is
//! verified to reproduce before it is finalized.
//!
//! It works on the built harness of every native lane ([`crate::repro_lane`]):
//! C, C++, Ada, Rust, COBOL and Fortran. A harness that runs inside a
//! language runtime (Python, Java, ...), or a statically linked one (a Go
//! harness), cannot have the shim preloaded and is refused with that reason,
//! before the shim is looked up. The harness is replayed with the input
//! protocol the shared detector ([`crate::protocol_detect`]) reads off it: the
//! input file as `argv[1]`, or for an Ada harness the input piped to stdin
//! with the runtime's event log, whose unhandled exception is the crash. A
//! capsule is assembled in a scratch dir and moved into place only when
//! complete, so a failure leaves nothing behind.

use crate::protocol_detect::{self, HarnessProtocol};
use crate::repro_lane::{self, Lane, ReplayOutput, Tool};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_CANDIDATES: usize = 64;
/// Wall clock for one replay under the shim.
const REPLAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `bhf env-capsule` — bundle a replayable faked-environment reproducer.
#[derive(Debug, clap::Args)]
pub struct EnvCapsuleArgs {
    /// Work directory of a prior `auto` run.
    #[arg(long = "work-dir", default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Capture only this finding id (default: every runtime crash finding of
    /// a built native harness: C, C++, Ada, Rust, COBOL or Fortran). Exits
    /// non-zero, with the reason, when it cannot be captured.
    #[arg(long = "finding-id", value_name = "ID")]
    pub finding_id: Option<String>,

    /// Directory to write capsules under. Default `<work-dir>/env-capsules`.
    #[arg(long, short = 'o', value_name = "DIR")]
    pub out: Option<PathBuf>,
}

pub fn run(args: EnvCapsuleArgs) -> i32 {
    if let Err(error) = crate::workdir::prepare(&args.work_dir) {
        bhfeprintln!("error: {error:#}");
        return 1;
    }
    let requested = args.finding_id.is_some();
    let selection =
        match repro_lane::select(&args.work_dir, args.finding_id.as_deref(), Tool::EnvCapsule) {
            Ok(selection) => selection,
            Err(e) => {
                bhfeprintln!("error: {e}");
                return 1;
            }
        };
    if selection.considered == 0 {
        bhfeprintln!(
            "bhf env-capsule: no runtime crash findings in {}",
            args.work_dir.display()
        );
        return 0;
    }
    repro_lane::print_refusals(Tool::EnvCapsule, &selection.refused, requested, 10);
    let selection_refused = selection.refused.len();
    if selection.eligible.is_empty() {
        if !requested {
            bhfeprintln!(
                "bhf env-capsule: nothing captured: none of the {} runtime finding(s) in {} \
                 can be captured",
                selection.considered,
                args.work_dir.display()
            );
        }
        return 1;
    }
    let Some(shim) = crate::auto::shim_path::locate() else {
        bhfeprintln!(
            "bhf env-capsule: {}; it is required to record/replay the faked environment",
            crate::auto::shim_path::unavailable_reason()
        );
        return 1;
    };
    // LD_PRELOAD is read in the harness's dir, so a relative shim path breaks.
    let shim = std::path::absolute(&shim).unwrap_or(shim);
    let ld_preload = crate::auto::shim_path::ld_preload_value_with(&shim, None);
    let out_root = args
        .out
        .clone()
        .unwrap_or_else(|| args.work_dir.join("env-capsules"));
    let out_root_existed = out_root.exists();
    let mut made = 0usize;
    let mut reproduced = 0usize;
    let mut failed = 0usize;
    let mut no_world = 0usize;
    let taken = selection.eligible.len();
    for (record, eligible) in selection.eligible {
        let Some(binary) = eligible.binary else {
            failed += 1;
            bhfeprintln!(
                "  {} failed: its harness executable was not located",
                record.id
            );
            continue;
        };
        let protocol = protocol_detect::detect(&binary, &[&args.work_dir]).protocol;
        let (mode, env) = recorded_world(&record.raw);
        let f = FindingRef {
            id: record.id,
            harness_id: eligible.harness_id,
            lane: eligible.lane,
            binary,
            protocol,
            mode,
            env,
            inputs: eligible.inputs,
        };
        match build_env_capsule(&args.work_dir, &f, &out_root, &shim, &ld_preload) {
            Ok(Some(rep)) => {
                made += 1;
                if rep.reproduced {
                    reproduced += 1;
                }
                println!(
                    "  {} {}  ({})",
                    f.id,
                    rep.path.display(),
                    if rep.reproduced {
                        "✓ replays"
                    } else {
                        "⚠ not reproduced"
                    }
                );
            }
            Ok(None) => {
                no_world += 1;
                println!(
                    "  {} skipped (no faked-environment crash to capture): no input crashed it \
                     while the shim recorded bytes it served; `bhf capsule` packages crashes \
                     that need no faked resource",
                    f.id
                );
            }
            Err(error) => {
                failed += 1;
                bhfeprintln!("  {} failed: {error:#}", f.id);
            }
        }
    }
    if !out_root_existed {
        // Only removes an empty dir: nothing was captured into it.
        let _ = std::fs::remove_dir(&out_root);
    }
    let skipped = match selection_refused + no_world {
        0 => String::new(),
        n => format!("; {n} finding(s) skipped"),
    };
    println!(
        "bhf env-capsule: {made} capsule(s) in {} ({reproduced} verified to replay{skipped})",
        out_root.display()
    );
    if made == 0 && failed == 0 && !requested {
        bhfeprintln!(
            "bhf env-capsule: nothing captured: none of the {taken} finding(s) it can take \
             crashed while the shim served a faked resource"
        );
    }
    repro_lane::exit_code(&repro_lane::RunTally {
        requested,
        made,
        verified: reproduced,
        failed,
    })
}

struct FindingRef {
    id: String,
    harness_id: String,
    lane: &'static dyn Lane,
    /// The built harness executable.
    binary: PathBuf,
    /// How it takes its input.
    protocol: HarnessProtocol,
    /// The shim's faking mode the finding fired under (`fuzz_driven`, `rng`).
    mode: String,
    /// The environment variables the fuzz loop injected for it.
    env: Vec<(String, String)>,
    /// The finding's crash inputs, minimized first.
    inputs: Vec<PathBuf>,
}

struct EnvReport {
    path: PathBuf,
    reproduced: bool,
}

fn build_env_capsule(
    work_dir: &Path,
    f: &FindingRef,
    out_root: &Path,
    shim: &Path,
    ld_preload: &str,
) -> anyhow::Result<Option<EnvReport>> {
    if !corpus::layout::is_valid_finding_id(&f.id) {
        anyhow::bail!("invalid finding ID: {:?}", f.id);
    }
    let bin = &f.binary;
    // Find an input that crashes under a faking pass AND records a non-empty served
    // world (the finding's min input is often empty — the crash lives in the faked
    // environment, so we drive it with the corpus inputs that still carry bytes).
    // The recording lives in a scratch dir, outside the output dir.
    let recording = tempfile::Builder::new()
        .prefix("bhf-env-capsule-")
        .tempdir()?;
    let world_tmp = recording.path().join("world.jsonl");
    let mut candidates: Vec<PathBuf> = f.inputs.clone();
    candidates.extend(corpus_inputs(work_dir, &f.harness_id));
    let mut recorded: Option<PathBuf> = None;
    for cand in candidates.iter().take(MAX_CANDIDATES) {
        let _ = std::fs::remove_file(&world_tmp);
        if replay_crashes(f, bin, cand, ld_preload, Some(&world_tmp), None)
            && world_tmp.is_file()
            && std::fs::metadata(&world_tmp)
                .map(|m| m.len() > 0)
                .unwrap_or(false)
        {
            recorded = Some(cand.clone());
            break;
        }
    }
    let Some(crashing_input) = recorded else {
        return Ok(None);
    };

    // Assemble the capsule in a scratch dir beside its final place.
    std::fs::create_dir_all(out_root)
        .map_err(|error| anyhow::anyhow!("cannot create {}: {error}", out_root.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(&format!(".env_capsule_{}.", f.id))
        .tempdir_in(out_root)?;
    let cap = staging.path();
    std::fs::copy(&world_tmp, cap.join("env-world.jsonl"))?;
    std::fs::copy(bin, cap.join("main"))?;
    set_executable(&cap.join("main"));
    std::fs::copy(shim, cap.join("libbhf_runtrace.so"))?;

    // Verify: replay the recorded world with each input in turn — the finding's
    // own (minimized first: it proves the world alone reproduces), then the one
    // that crashed while recording — and ship the first that crashes. When none
    // does, ship the recorded one.
    let world_path = cap.join("env-world.jsonl");
    let mut tries: Vec<&PathBuf> = f.inputs.iter().collect();
    if !tries.contains(&&crashing_input) {
        tries.push(&crashing_input);
    }
    let mut shipped = None;
    for input in tries {
        std::fs::copy(input, cap.join("input.bin"))?;
        if replay_crashes(
            f,
            &cap.join("main"),
            &cap.join("input.bin"),
            "./libbhf_runtrace.so",
            None,
            Some(&world_path),
        ) {
            shipped = Some(input);
            break;
        }
    }
    let reproduced = shipped.is_some();
    let input_for_capsule = match shipped {
        Some(input) => input,
        None => {
            std::fs::copy(&crashing_input, cap.join("input.bin"))?;
            &crashing_input
        }
    };

    std::fs::write(cap.join("replay.sh"), replay_script(f))?;
    set_executable(&cap.join("replay.sh"));
    let name = input_for_capsule
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let input_source = if f.inputs.contains(input_for_capsule) {
        name
    } else {
        format!("corpus/{}/queue/{name}", f.harness_id)
    };
    write_manifest(cap, f, &input_source, reproduced)?;
    std::fs::write(cap.join("README.md"), readme(&f.id, f.protocol))?;

    let final_dir = out_root.join(format!("env_capsule_{}", f.id));
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
    Ok(Some(EnvReport {
        path: final_dir,
        reproduced,
    }))
}

/// Replay `input` through `bin` under the shim in a faking pass. `record` pins a
/// `BHF_ENVCAP_RECORD` log; `replay` pins a `BHF_ENVCAP_REPLAY` world.
/// Returns whether the lane's crash oracle saw a crash: a sanitizer report,
/// or for an Ada harness an unhandled exception in its event log.
///
/// The harness runs in its own dir, so every path handed to it is made
/// absolute first: a relative `--work-dir` would otherwise resolve against the
/// binary's dir and nothing would run.
fn replay_crashes(
    f: &FindingRef,
    bin: &Path,
    input: &Path,
    ld_preload: &str,
    record: Option<&Path>,
    replay: Option<&Path>,
) -> bool {
    let absolute = |path: &Path| std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let bin = absolute(bin);
    let dir = bin.parent().unwrap_or(Path::new("."));
    let mut cmd = Command::new(&bin);
    cmd.current_dir(dir)
        .env("LD_PRELOAD", ld_preload)
        .env("BHF_RUNTRACE_MODE", &f.mode)
        .envs(f.env.iter().map(|(key, value)| (key, value)))
        .env(
            "ASAN_OPTIONS",
            "abort_on_error=1:symbolize=0:detect_leaks=0",
        )
        .env_remove("BHF_FRAMED");
    if let Some(rec) = record {
        cmd.env("BHF_ENVCAP_RECORD", absolute(rec));
    }
    if let Some(rep) = replay {
        cmd.env("BHF_ENVCAP_REPLAY", absolute(rep));
    }
    let outcome = match f.protocol {
        HarnessProtocol::StdinEventLog => {
            let Ok(scratch) = tempfile::Builder::new()
                .prefix("bhf-envcap-events-")
                .tempdir()
            else {
                return false;
            };
            let events = scratch.path().join("events.bin");
            cmd.env("BHF_EVENTS_PATH", &events);
            let Ok(bytes) = std::fs::read(input) else {
                return false;
            };
            repro_lane::run_with_stdin(cmd, bytes, REPLAY_TIMEOUT)
                .ok()
                .map(|(out, timed_out)| ReplayOutput {
                    stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                    status: out.status,
                    events: std::fs::read(&events).ok(),
                    timed_out,
                })
        }
        HarnessProtocol::BhfFramed | HarnessProtocol::LibFuzzerSingleInput => {
            cmd.arg(absolute(input));
            crate::command_output::output_with_timeout_flagged(&mut cmd, REPLAY_TIMEOUT)
                .ok()
                .map(|(out, timed_out)| ReplayOutput {
                    stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                    status: out.status,
                    events: None,
                    timed_out,
                })
        }
    };
    let Some(outcome) = outcome else {
        return false;
    };
    // A fatal signal alone is not evidence of the faked-environment crash.
    f.lane
        .crash_signature(&outcome)
        .is_some_and(|signature| signature != "signal:crash")
}

/// The corpus queue inputs for a harness (bounded).
fn corpus_inputs(work_dir: &Path, harness_id: &str) -> Vec<PathBuf> {
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(entries) = std::fs::read_dir(&queue) else {
        return Vec::new();
    };
    let mut inputs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    // Larger inputs are likelier to carry the bytes the faked resource consumes.
    inputs.sort_by_key(|p| std::cmp::Reverse(std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)));
    inputs
}

fn write_manifest(
    cap: &Path,
    f: &FindingRef,
    input_source: &str,
    reproduced: bool,
) -> anyhow::Result<()> {
    let world_resources = count_world_resources(&cap.join("env-world.jsonl"));
    let manifest = json!({
        "schema": "bhf.env-capsule/v1",
        "bhf_version": env!("BHF_VERSION_FULL"),
        "finding_id": f.id,
        "harness_id": f.harness_id,
        "lang": f.lane.tag(),
        "language": f.lane.name(),
        "protocol": f.protocol.label(),
        "world": "env-world.jsonl",
        "recorded_resources": world_resources,
        "input": "input.bin",
        "input_source": input_source,
        "replay": "sh replay.sh",
        "runtime_mode": f.mode,
        "env_injected": f.env.iter().map(|(key, _)| key).collect::<Vec<_>>(),
        "reproduced": reproduced,
        "note": "the shim serves the recorded bytes for each faked resource, so the crash \
                 reproduces deterministically from the pinned environment even when the primary \
                 input is empty",
    });
    std::fs::write(
        cap.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

fn count_world_resources(world: &Path) -> usize {
    std::fs::read_to_string(world)
        .map(|t| t.lines().filter(|l| l.contains(':')).count())
        .unwrap_or(0)
}

/// The shim mode and injected environment the finding fired under
/// (`finding.json` `runtime_mode`): the env-capsule records and replays the
/// world the same way. A finding from bhf's RNG pass was served pseudo-random
/// bytes, which a harness that does not hand its input to the shim (an Ada
/// harness) needs to see again.
fn recorded_world(raw: &serde_json::Value) -> (String, Vec<(String, String)>) {
    let mode = raw
        .pointer("/runtime_mode/pass")
        .and_then(serde_json::Value::as_str)
        .filter(|pass| matches!(*pass, "rng" | "fuzz_driven"))
        .unwrap_or("fuzz_driven")
        .to_owned();
    let env = raw
        .pointer("/runtime_mode/env_injected")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(key, _)| {
            !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
        .collect();
    (mode, env)
}

fn replay_script(f: &FindingRef) -> String {
    // The Ada runtime reads its input from stdin (a pipe: it re-opens
    // /dev/stdin, so a redirected file is read again and again) and reports
    // what it raised in its event log.
    let (feed, events, argument) = match f.protocol {
        HarnessProtocol::StdinEventLog => (
            "cat input.bin | ",
            "\x20 BHF_EVENTS_PATH=events.bin \\\n".to_owned(),
            "",
        ),
        HarnessProtocol::BhfFramed | HarnessProtocol::LibFuzzerSingleInput => {
            ("", String::new(), " input.bin")
        }
    };
    let env: String = f
        .env
        .iter()
        .map(|(key, value)| format!("\x20 {key}={} \\\n", repro_lane::sh_word(value)))
        .collect();
    format!(
        "#!/bin/sh\n\
         # Reproduce the crash by replaying the recorded faked environment.\n\
         cd \"$(dirname \"$0\")\"\n\
         {feed}LD_PRELOAD=./libbhf_runtrace.so \\\n\
         \x20 BHF_RUNTRACE_MODE={mode} \\\n\
         \x20 BHF_ENVCAP_REPLAY=env-world.jsonl \\\n\
         {events}\
         {env}\
         \x20 ASAN_OPTIONS=abort_on_error=1:symbolize=0 \\\n\
         \x20 ./main{argument}\n",
        mode = f.mode,
    )
}

fn readme(id: &str, protocol: HarnessProtocol) -> String {
    let crash = match protocol {
        HarnessProtocol::StdinEventLog => {
            "The harness is an Ada harness: it reads `input.bin` from stdin and records the\n\
             exception it raised in `events.bin` (an unhandled one is the crash).\n\n"
        }
        HarnessProtocol::BhfFramed | HarnessProtocol::LibFuzzerSingleInput => "",
    };
    format!(
        "# BHF environment capsule — {id}\n\n\
         Reproduces a crash driven by the shim-served (fuzzed) content of a \"trusted\"\n\
         external resource. The reproducer is the recorded ENVIRONMENT, not the input.\n\n\
         ## Reproduce\n\n\
         ```sh\n\
         sh replay.sh\n\
         ```\n\n\
         The shim (`libbhf_runtrace.so`) serves each faked resource the exact bytes\n\
         in `env-world.jsonl`, so the crash fires even though `input.bin` may be empty.\n\n\
         {crash}\
         ## Layout\n\n\
         - `main` — the fuzz harness binary\n\
         - `libbhf_runtrace.so` — the resource-virtualization shim\n\
         - `env-world.jsonl` — the recorded served bytes, per faked resource\n\
         - `input.bin` — the primary fuzz input (often empty for env-driven crashes)\n\
         - `manifest.json` — finding metadata\n"
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_world_resources() {
        let dir = std::env::temp_dir().join(format!("bhf-envcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let w = dir.join("w.jsonl");
        std::fs::write(&w, "6161:4142\n6262:4344\ngarbage\n").unwrap();
        assert_eq!(count_world_resources(&w), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stand-in harness: it records a served world when asked and "crashes"
    /// (prints a sanitizer report) only on an input that starts with `X`.
    #[cfg(unix)]
    fn fake_harness(dir: &Path) -> PathBuf {
        let bin = dir.join("main");
        std::fs::write(
            &bin,
            "#!/bin/sh\n\
             if [ -n \"$BHF_ENVCAP_RECORD\" ]; then printf '6161:4142\\n' >> \"$BHF_ENVCAP_RECORD\"; fi\n\
             case \"$(head -c 1 \"$1\")\" in X) echo 'ERROR: AddressSanitizer: stack-buffer-overflow' >&2; exit 1;; esac\n\
             exit 0\n",
        )
        .unwrap();
        set_executable(&bin);
        bin
    }

    /// The minimized input does not crash under the recorded world but the
    /// recorded one does: the capsule ships the one that replays and says so.
    #[cfg(unix)]
    #[test]
    fn the_shipped_input_is_the_first_that_replays_under_the_recorded_world() {
        if which::which("head").is_err() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("work");
        let harness = work.join("harnesses/H-C0001-0000ABCD");
        let finding = work.join("results/findings/F-0001-0000aaaa");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::create_dir_all(&finding).unwrap();
        let binary = fake_harness(&harness);
        std::fs::write(finding.join("min_testcase.bin"), b"A").unwrap();
        std::fs::write(finding.join("testcase.bin"), b"XYZ").unwrap();
        let shim = root.path().join("libshim.so");
        std::fs::write(&shim, b"not a library").unwrap();
        let f = FindingRef {
            id: "F-0001-0000aaaa".to_owned(),
            harness_id: "H-C0001-0000ABCD".to_owned(),
            lane: &repro_lane::C_LANE,
            binary,
            protocol: HarnessProtocol::BhfFramed,
            mode: "fuzz_driven".to_owned(),
            env: Vec::new(),
            inputs: repro_lane::crash_inputs(&finding),
        };
        let out_root = work.join("env-capsules");
        let report = build_env_capsule(&work, &f, &out_root, &shim, &shim.to_string_lossy())
            .unwrap()
            .expect("the recorded input crashes, so a capsule is written");
        assert!(report.reproduced, "testcase.bin replays under the world");
        assert_eq!(
            std::fs::read(report.path.join("input.bin")).unwrap(),
            b"XYZ"
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report.path.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["input_source"], "testcase.bin", "{manifest}");
        assert_eq!(manifest["reproduced"], true, "{manifest}");
    }

    /// The env-capsule records under the shim mode the finding fired in and
    /// with the environment the fuzz loop injected for it.
    #[test]
    fn the_world_is_recorded_the_way_the_finding_fired() {
        let raw = serde_json::json!({"runtime_mode": {
            "pass": "rng",
            "env_injected": {"WIDGET_HOME": "/tmp/bhf/fake_env/WIDGET_HOME", "bad key": "x"},
        }});
        let (mode, env) = recorded_world(&raw);
        assert_eq!(mode, "rng");
        assert_eq!(
            env,
            vec![(
                "WIDGET_HOME".to_owned(),
                "/tmp/bhf/fake_env/WIDGET_HOME".to_owned()
            )]
        );
        let (mode, env) = recorded_world(&serde_json::json!({"runtime_mode": {"pass": "empty"}}));
        assert_eq!(
            mode, "fuzz_driven",
            "an empty pass serves no bytes to record"
        );
        assert!(env.is_empty());
    }

    #[test]
    fn replay_script_pins_replay_env() {
        let finding = |protocol| FindingRef {
            id: "F-0001-0000aaaa".to_owned(),
            harness_id: "H-C0001-0000ABCD".to_owned(),
            lane: &repro_lane::C_LANE,
            binary: PathBuf::from("main"),
            protocol,
            mode: "fuzz_driven".to_owned(),
            env: vec![("WIDGET_HOME".to_owned(), "/tmp/bhf/fake env".to_owned())],
            inputs: Vec::new(),
        };
        let s = replay_script(&finding(HarnessProtocol::BhfFramed));
        assert!(s.contains("BHF_RUNTRACE_MODE=fuzz_driven"), "{s}");
        assert!(s.contains("WIDGET_HOME='/tmp/bhf/fake env'"), "{s}");
        assert!(s.contains("BHF_ENVCAP_REPLAY=env-world.jsonl"));
        assert!(s.contains("LD_PRELOAD=./libbhf_runtrace.so"));
        assert!(s.contains("./main input.bin"), "{s}");
        // An Ada harness reads stdin from a pipe and writes its event log.
        let ada = replay_script(&finding(HarnessProtocol::StdinEventLog));
        assert!(
            ada.contains("cat input.bin | LD_PRELOAD=./libbhf_runtrace.so"),
            "{ada}"
        );
        assert!(ada.contains("BHF_EVENTS_PATH=events.bin"), "{ada}");
        assert!(!ada.contains("./main input.bin"), "{ada}");
    }
}
