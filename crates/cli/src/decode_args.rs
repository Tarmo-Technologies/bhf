// SPDX-License-Identifier: Apache-2.0

//! `bhf decode-args`: map a testcase to the value each harness parameter
//! receives.
//!
//! With a runnable generated C/C++ harness, the harness itself is the
//! decoder: it runs once on the testcase with `BHF_TRACE_ARGS=1` and its
//! `BHF_ARG` lines are shown. Without one (a work dir copied without its
//! binaries, a cross-compiled harness, or `--static`), the harness's
//! `arg-layout.json` is replayed over the testcase for the decoder kinds it
//! describes statically, and every parameter it cannot decode is named with
//! the reason.

use crate::finding_arg::resolve_finding_arg_in;
use crate::replay::{CInput, REPLAY_TIMEOUT};
use crate::runner::{engine_for, harness_runner_for, HarnessEngine, SandboxModeArg};
use corpus::decoded_args::TracedArg;
use harness_gen::arg_layout::{ArgLayout, StaticArg};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// `schema_version` of the `--json` document.
pub(crate) const DECODE_ARGS_SCHEMA: &str = "bhf.decode-args.v1";

#[derive(Debug, clap::Args)]
pub struct DecodeArgsArgs {
    /// The testcase to decode. Default with --finding: its testcase.bin.
    #[arg(value_name = "TESTCASE", required_unless_present = "finding")]
    pub testcase: Option<PathBuf>,

    /// A finding (directory, or id under --work-dir): its harness and, unless
    /// TESTCASE is given, its testcase.bin.
    #[arg(long, value_name = "ID_OR_DIR", visible_alias = "finding-id")]
    pub finding: Option<PathBuf>,

    /// The harness: its binary, its directory (with `arg-layout.json` and,
    /// when built, `main`), or its id under --work-dir. Default with
    /// --finding: the harness the finding records.
    #[arg(long, value_name = "PATH", required_unless_present = "finding")]
    pub harness: Option<PathBuf>,

    /// Work directory a bare finding id is looked up in.
    #[arg(long = "work-dir", default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Decode from `arg-layout.json` even when the harness binary could run.
    #[arg(long = "static")]
    pub static_only: bool,

    /// Print one `bhf.decode-args.v1` JSON document instead of the table.
    #[arg(long)]
    pub json: bool,

    /// qemu-user executable to run a cross-built harness under. Default: the
    /// emulator recorded beside the harness (`bhf_runner.json`).
    #[arg(long, value_name = "QEMU")]
    pub qemu_user: Option<PathBuf>,

    /// Extra argument passed to qemu-user before the harness path.
    #[arg(
        long = "qemu-arg",
        value_name = "ARG",
        allow_hyphen_values = true,
        requires = "qemu_user"
    )]
    pub qemu_args: Vec<String>,
}

/// Where the values came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    /// The harness ran with its argument trace on.
    HarnessTrace,
    /// `arg-layout.json` was replayed over the testcase.
    ArgLayout,
}

#[derive(Debug, Serialize)]
struct NotDecoded {
    call: String,
    index: usize,
    name: String,
    #[serde(rename = "type")]
    ty: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: &'static str,
    testcase: TestcaseRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    finding: Option<String>,
    harness: Option<String>,
    layout: Option<String>,
    source: Source,
    arguments: Vec<TracedArg>,
    not_decoded: Vec<NotDecoded>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TestcaseRef {
    path: String,
    size: usize,
}

pub fn run(args: DecodeArgsArgs) -> i32 {
    match decode(&args) {
        Ok(report) => {
            if args.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(text) => println!("{text}"),
                    Err(error) => {
                        bhfeprintln!("error: serialize the decoded arguments: {error}");
                        return 1;
                    }
                }
            } else {
                for line in render(&report) {
                    println!("{line}");
                }
            }
            0
        }
        Err(error) => {
            bhfeprintln!("error: {error}");
            1
        }
    }
}

/// What decode-args works from.
struct Inputs {
    finding_dir: Option<PathBuf>,
    finding: Value,
    testcase: PathBuf,
    /// The harness binary, when one exists.
    binary: Option<PathBuf>,
    /// The directory holding `arg-layout.json`, when one was found.
    layout_dir: Option<PathBuf>,
    /// The directories searched for the binary and `arg-layout.json`.
    searched_dirs: Vec<PathBuf>,
    qemu_user: Option<PathBuf>,
    qemu_args: Vec<String>,
}

fn inputs(args: &DecodeArgsArgs) -> Result<Inputs, String> {
    let finding_dir = args
        .finding
        .clone()
        .map(|finding| resolve_finding_arg_in(&args.work_dir, None, Some(finding)));
    let finding = match &finding_dir {
        Some(dir) => {
            let path = dir.join("finding.json");
            serde_json::from_slice(
                &std::fs::read(&path)
                    .map_err(|error| format!("read {}: {error}", path.display()))?,
            )
            .map_err(|error| format!("read {}: {error}", path.display()))?
        }
        None => Value::Null,
    };
    let testcase = match (&args.testcase, &finding_dir) {
        (Some(testcase), _) => testcase.clone(),
        (None, Some(dir)) => dir.join("testcase.bin"),
        (None, None) => return Err("pass a TESTCASE or --finding".to_owned()),
    };
    let (binary, mut layout_dirs) = match &args.harness {
        Some(path) if path.is_dir() => (
            harness_binary_in(std::slice::from_ref(path)),
            vec![path.clone()],
        ),
        // A bare relative file name is made absolute, so running it never
        // searches PATH for a program of that name.
        Some(path) if path.is_file() => (
            Some(std::path::absolute(path).unwrap_or_else(|_| Path::new(".").join(path))),
            path.parent().map(Path::to_path_buf).into_iter().collect(),
        ),
        // One plain path component naming no file or dir: a harness id under
        // the work dir.
        Some(path) if is_harness_id(path) => {
            let id = path.to_string_lossy();
            let mut dirs = vec![
                crate::auto::layout::harness_dir(&args.work_dir, &id),
                args.work_dir.join("build").join(&*id),
            ];
            for dir in crate::auto::layout::harness_dir_candidates(&args.work_dir, &id) {
                if !dirs.contains(&dir) {
                    dirs.push(dir);
                }
            }
            let found: Vec<PathBuf> = dirs.iter().filter(|dir| dir.is_dir()).cloned().collect();
            if found.is_empty() {
                return Err(no_such_harness(path, &args.work_dir, &dirs));
            }
            (harness_binary_in(&found), found)
        }
        // A binary path that is not built (a work dir copied without its
        // binaries) still decodes from the layout beside it.
        Some(path)
            if path.parent().is_some_and(|dir| {
                dir.join(harness_gen::arg_layout::ARG_LAYOUT_FILE).is_file()
            }) =>
        {
            (
                None,
                path.parent().map(Path::to_path_buf).into_iter().collect(),
            )
        }
        Some(path) => return Err(no_such_harness(path, &args.work_dir, &[])),
        None => {
            let dir = finding_dir
                .as_ref()
                .expect("clap requires --harness or --finding");
            let binary = crate::replay::recorded_harness(dir).ok();
            let dirs = binary
                .as_ref()
                .and_then(|binary| binary.parent().map(Path::to_path_buf))
                .into_iter()
                .collect();
            (binary, dirs)
        }
    };
    // A binary staged alone (`build/<id>/main`) has its layout in the harness
    // dir it was generated in.
    if let (Some(dir), Some(harness_id)) = (
        finding_dir
            .as_deref()
            .and_then(corpus::layout::work_dir_for_finding),
        finding.get("harness_id").and_then(Value::as_str),
    ) {
        layout_dirs.extend(crate::auto::layout::harness_dir_candidates(
            &dir, harness_id,
        ));
    }
    let layout_dir = layout_dirs
        .iter()
        .find(|dir| dir.join(harness_gen::arg_layout::ARG_LAYOUT_FILE).is_file())
        .cloned();
    Ok(Inputs {
        finding_dir,
        finding,
        testcase,
        binary,
        layout_dir,
        searched_dirs: layout_dirs,
        qemu_user: args.qemu_user.clone(),
        qemu_args: args.qemu_args.clone(),
    })
}

/// The first built harness binary in `dirs`: `main` under the platform's
/// spelling (`crate::auto::layout::harness_exe`), then `main.exe`.
fn harness_binary_in(dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter()
        .flat_map(|dir| {
            [
                crate::auto::layout::harness_exe(dir, "main"),
                dir.join("main.exe"),
            ]
        })
        .find(|candidate| candidate.is_file())
}

/// Whether `--harness <path>` reads as a harness id: one plain path
/// component, no separator.
fn is_harness_id(path: &Path) -> bool {
    let mut components = path.components();
    matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    ) && !path.to_string_lossy().contains(['/', '\\'])
}

/// The error for a `--harness` that names nothing: no file, no dir, and no
/// harness of that id under the work dir.
fn no_such_harness(path: &Path, work_dir: &Path, looked_in: &[PathBuf]) -> String {
    let id = if looked_in.is_empty() {
        String::new()
    } else {
        format!(
            ", and no harness `{}` under {} (looked in {})",
            path.display(),
            work_dir.display(),
            looked_in
                .iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!(
        "--harness {}: no such file or directory{id}",
        path.display()
    )
}

fn decode(args: &DecodeArgsArgs) -> Result<Report, String> {
    let inputs = inputs(args)?;
    let bytes = std::fs::read(&inputs.testcase)
        .map_err(|error| format!("read {}: {error}", inputs.testcase.display()))?;
    let mut notes = Vec::new();
    let layout = match inputs.layout_dir.as_deref().and_then(ArgLayout::read) {
        Some(Ok(layout)) => Some(layout),
        Some(Err(error)) => {
            notes.push(format!("the layout could not be read: {error}"));
            None
        }
        None => None,
    };
    // The finding's recorded format first, else the harness dir's.
    if let (Some(layout), Some(recorded)) = (&layout, recorded_format(&inputs)) {
        if layout.harness_format_version != recorded.version
            || layout.buffer_len_dimension != recorded.buffer_len_dimension
        {
            notes.push(format!(
                "the finding was recorded with harness input format {}{} and the layout \
                 describes format {}{}: the same bytes decode to other values there",
                recorded.version,
                dimension_text(recorded.buffer_len_dimension),
                layout.harness_format_version,
                dimension_text(layout.buffer_len_dimension),
            ));
        }
    }
    let mut report = Report {
        schema_version: DECODE_ARGS_SCHEMA,
        testcase: TestcaseRef {
            path: inputs.testcase.display().to_string(),
            size: bytes.len(),
        },
        finding: inputs
            .finding_dir
            .as_ref()
            .map(|dir| dir.display().to_string()),
        harness: inputs
            .binary
            .as_ref()
            .map(|path| path.display().to_string()),
        layout: inputs.layout_dir.as_ref().map(|dir| {
            dir.join(harness_gen::arg_layout::ARG_LAYOUT_FILE)
                .display()
                .to_string()
        }),
        source: Source::ArgLayout,
        arguments: Vec::new(),
        not_decoded: Vec::new(),
        notes,
    };
    // A passthrough harness decodes no parameters: there is nothing to trace,
    // and its layout (if any) describes none.
    if is_passthrough(&inputs) {
        report
            .notes
            .push(crate::replay::PASSTHROUGH_NO_ARGUMENTS.to_owned());
        if layout.is_none() {
            return Err(crate::replay::PASSTHROUGH_NO_ARGUMENTS.to_owned());
        }
    } else if !args.static_only {
        match inputs.binary.as_deref() {
            Some(binary) => match trace(binary, &inputs, &bytes) {
                Ok(traced) => {
                    report.source = Source::HarnessTrace;
                    report.arguments = traced;
                    return Ok(report);
                }
                Err(reason) => report.notes.push(if layout.is_some() {
                    format!(
                        "the harness was not traced ({reason}); decoded from the layout instead"
                    )
                } else {
                    format!("the harness was not traced ({reason})")
                }),
            },
            None if layout.is_some() => report
                .notes
                .push("no built harness binary was found; decoded from the layout".to_owned()),
            None => {}
        }
    }
    let Some(layout) = layout else {
        let searched = || {
            inputs
                .searched_dirs
                .iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(match &inputs.binary {
            Some(_) if args.static_only => {
                "--static needs the harness's arg-layout.json, and none was found; regenerate the \
                 harness with this bhf"
                    .to_owned()
            }
            Some(_) => format!(
                "cannot decode {}: no traceable harness binary and no arg-layout.json in {}{}",
                inputs.testcase.display(),
                searched(),
                report
                    .notes
                    .first()
                    .map(|note| format!(" ({note})"))
                    .unwrap_or_default()
            ),
            None => format!(
                "cannot decode {}: no harness binary in {} and no arg-layout.json in {}",
                inputs.testcase.display(),
                inputs
                    .searched_dirs
                    .first()
                    .map(|dir| dir.display().to_string())
                    .unwrap_or_else(|| "the harness dir".to_owned()),
                searched()
            ),
        });
    };
    if let Some(note) = &layout.static_decode_note {
        report.notes.push(note.clone());
    }
    for arg in layout.decode(&bytes) {
        if arg.decoded {
            report.arguments.push(traced_arg(&arg));
        } else {
            report.not_decoded.push(NotDecoded {
                call: arg.call,
                index: arg.index,
                name: arg.name,
                ty: arg.ty,
                reason: arg
                    .reason
                    .unwrap_or_else(|| "its decoder has no static form".to_owned()),
            });
        }
    }
    Ok(report)
}

/// The harness input format the testcase was recorded with: the finding's
/// own record (`harness.format_version`, else its top-level key), else the
/// format the harness dir's generation metadata records. A finding from a
/// bhf that recorded no format at all predates format 3 when its C/C++
/// harness is format 3 or later.
fn recorded_format(inputs: &Inputs) -> Option<corpus::finding::HarnessFormat> {
    if let Some(format) = corpus::finding::finding_harness_format(&inputs.finding) {
        return Some(format);
    }
    let harness = crate::generate_harness::recorded_harness_format(inputs.layout_dir.as_deref()?)?;
    let predates = inputs.finding_dir.is_some() && harness.version >= 3;
    Some(corpus::finding::HarnessFormat {
        version: if predates { 2 } else { harness.version },
        buffer_len_dimension: !predates && harness.buffer_len_dimension,
    })
}

fn dimension_text(on: bool) -> &'static str {
    if on {
        " with the explicit buffer-length dimension"
    } else {
        ""
    }
}

/// Whether the harness passes the input straight to the project's own
/// `LLVMFuzzerTestOneInput` (see [`crate::replay::is_passthrough_harness`]).
fn is_passthrough(inputs: &Inputs) -> bool {
    let mut dirs = inputs
        .binary
        .as_deref()
        .map(|binary| {
            crate::replay::harness_source_dirs(
                inputs.finding_dir.as_deref(),
                &inputs.finding,
                binary,
                None,
            )
        })
        .unwrap_or_default();
    dirs.extend(inputs.layout_dir.clone());
    crate::replay::is_passthrough_harness(&dirs)
}

/// Run the harness once on the testcase with its argument trace on.
fn trace(binary: &Path, inputs: &Inputs, bytes: &[u8]) -> Result<Vec<TracedArg>, String> {
    // A foreign harness with no emulator given or recorded is never run.
    if inputs.qemu_user.is_none() && crate::runner::recorded_runner_for(binary).is_none() {
        crate::runner::refuse_foreign_harness(binary)?;
    }
    if !crate::fuzz::harness_has_arg_trace(binary) {
        return Err(format!(
            "{} was built without the argument trace",
            binary.display()
        ));
    }
    let work = inputs
        .finding_dir
        .as_deref()
        .and_then(corpus::layout::work_dir_for_finding);
    let work_dirs: Vec<&Path> = work.iter().map(PathBuf::as_path).collect();
    let input = match binary.file_name().and_then(|name| name.to_str()) {
        Some("main_afl" | "main_afl.exe") => CInput::Stdin,
        _ => match engine_for(crate::protocol_detect::detect(binary, &work_dirs).protocol) {
            HarnessEngine::CLibFuzzer => CInput::ArgvFile,
            HarnessEngine::CAfl => CInput::Stdin,
            HarnessEngine::AdaStdin => {
                return Err("an Ada harness has no argument trace".to_owned());
            }
        },
    };
    // `--qemu-user`, else the emulator recorded beside a cross-built harness;
    // a foreign harness with neither is not run.
    let runner = harness_runner_for(
        binary.to_path_buf(),
        inputs.qemu_user.clone(),
        inputs.qemu_args.clone(),
        SandboxModeArg::Auto,
        None,
        false,
    )?;
    let run = crate::replay::run_c_testcase_with_env(
        &inputs.finding,
        &runner,
        input,
        &inputs.testcase,
        REPLAY_TIMEOUT,
        &[(
            corpus::decoded_args::TRACE_ARGS_ENV.to_owned(),
            "1".to_owned(),
        )],
    )?;
    let mut traced = corpus::decoded_args::parse_arg_trace(&String::from_utf8_lossy(&run.stderr));
    if traced.is_empty() {
        return Err(if run.timed_out {
            "it timed out before decoding".to_owned()
        } else {
            "it printed no BHF_ARG lines".to_owned()
        });
    }
    corpus::decoded_args::annotate_length_prefixes(&mut traced, bytes);
    Ok(traced)
}

/// A statically decoded value in the trace's shape, for one table.
fn traced_arg(arg: &StaticArg) -> TracedArg {
    TracedArg {
        call: arg.call.clone(),
        index: i64::try_from(arg.index).unwrap_or(i64::MAX),
        role: arg.role.clone(),
        name: arg.name.clone(),
        ty: arg.ty.clone(),
        decoder: Some(arg.decoder.clone()),
        span: arg.span,
        value: arg.value.clone(),
        len: arg.len,
        preview_hex: arg.preview_hex.clone(),
        length_prefix: arg.length_prefix,
        ..TracedArg::default()
    }
}

fn render(report: &Report) -> Vec<String> {
    let source = match report.source {
        Source::HarnessTrace => "the harness's argument trace (BHF_TRACE_ARGS=1)".to_owned(),
        Source::ArgLayout => format!(
            "{} (static decode; the harness did not run)",
            report.layout.as_deref().unwrap_or("arg-layout.json")
        ),
    };
    let mut lines = vec![format!(
        "decoded arguments of {} ({} byte(s)), from {source}",
        report.testcase.path, report.testcase.size
    )];
    if report.arguments.is_empty() {
        lines.push("  (no parameter could be decoded)".to_owned());
    } else {
        lines.extend(
            corpus::decoded_args::render_table(&report.arguments)
                .into_iter()
                .map(|line| format!("  {line}")),
        );
        lines.push(
            "  (bytes are [start..end) offsets in the testcase; a string's or buffer's value \
             column is its length)"
                .to_owned(),
        );
    }
    if !report.not_decoded.is_empty() {
        lines.push("not decoded statically:".to_owned());
        for param in &report.not_decoded {
            let call = if param.call == "target" {
                String::new()
            } else {
                format!("{}.", param.call)
            };
            lines.push(format!(
                "  {call}{} ({}): {}",
                param.name, param.ty, param.reason
            ));
        }
        lines.push(
            "  run the built harness on the testcase with BHF_TRACE_ARGS=1 (bhf decode-args \
             without --static) to see them"
                .to_owned(),
        );
    }
    for note in &report.notes {
        lines.push(format!("note: {note}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_gen::arg_layout::{LayoutStep, ParamLayout};

    fn layout_param(name: &str, input: &str, decoder: &str) -> ParamLayout {
        serde_json::from_value(serde_json::json!({
            "call": "target", "role": "param", "index": 0, "name": name, "type": "unsigned int",
            "order": 0, "input": input, "decoder": decoder, "static_decode": true
        }))
        .unwrap()
    }

    /// Without a harness binary, the layout is replayed and a parameter it
    /// cannot decode is named with its reason; the text says the harness did
    /// not run.
    #[test]
    fn decodes_statically_from_the_layout_and_names_what_it_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = layout_param("bit_index", "cursor", "scalar");
        index.primitive = Some("bhf_i32".to_owned());
        index.width = Some(4);
        index.value_kind = Some("u32".to_owned());
        let mut point = layout_param("origin", "cursor", "other");
        point.static_decode = false;
        point.cursor_bytes = Some(8);
        point.note = Some("it is decoded field by field".to_owned());
        let mut data = layout_param("data", "remainder", "input_buffer");
        data.index = 2;
        let layout = ArgLayout::new(
            "c",
            "direct",
            vec![
                LayoutStep::Param(index),
                LayoutStep::Param(point),
                LayoutStep::Remainder {
                    call: "target".to_owned(),
                    sized: false,
                },
                LayoutStep::Param(data),
            ],
        );
        layout.write(dir.path()).unwrap();
        let testcase = dir.path().join("t.bin");
        std::fs::write(&testcase, b"\x2a\x00\x00\x00ABCDEFGHxyz").unwrap();
        let args = DecodeArgsArgs {
            testcase: Some(testcase),
            finding: None,
            harness: Some(dir.path().to_path_buf()),
            work_dir: dir.path().to_path_buf(),
            static_only: false,
            json: false,
            qemu_user: None,
            qemu_args: Vec::new(),
        };
        let report = decode(&args).unwrap();
        assert_eq!(report.source, Source::ArgLayout);
        let names: Vec<&str> = report.arguments.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["bit_index", "data"]);
        assert_eq!(report.arguments[0].value.as_deref(), Some("42"));
        assert_eq!(report.arguments[1].span, Some([12, 15]));
        assert_eq!(report.not_decoded.len(), 1);
        assert_eq!(report.not_decoded[0].name, "origin");
        let text = render(&report).join("\n");
        assert!(
            text.contains("static decode; the harness did not run"),
            "{text}"
        );
        assert!(text.contains("not decoded statically:"), "{text}");
        assert!(
            text.contains("origin (unsigned int): it is decoded field by field"),
            "{text}"
        );
        assert!(text.contains("no built harness binary was found"), "{text}");
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], DECODE_ARGS_SCHEMA);
        assert_eq!(json["source"], "arg_layout");
        assert_eq!(
            json["not_decoded"][0]["reason"],
            "it is decoded field by field"
        );
    }

    #[test]
    fn without_a_layout_or_binary_it_says_what_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let testcase = dir.path().join("t.bin");
        std::fs::write(&testcase, b"x").unwrap();
        let error = decode(&DecodeArgsArgs {
            testcase: Some(testcase),
            finding: None,
            harness: Some(dir.path().to_path_buf()),
            work_dir: dir.path().to_path_buf(),
            static_only: true,
            json: false,
            qemu_user: None,
            qemu_args: Vec::new(),
        })
        .err()
        .unwrap();
        assert!(
            error.contains(&format!(
                "no harness binary in {} and no arg-layout.json in",
                dir.path().display()
            )),
            "{error}"
        );
        assert!(!error.contains("decoded from the layout"), "{error}");
    }

    /// The flag every other finding command spells `--finding-id` is
    /// accepted here too.
    #[test]
    fn finding_id_is_an_alias_of_finding() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            args: DecodeArgsArgs,
        }
        let cli = Cli::try_parse_from(["x", "--finding-id", "F-1"]).unwrap();
        assert_eq!(cli.args.finding.as_deref(), Some(Path::new("F-1")));
    }

    fn write_static_layout(dir: &Path) {
        let mut index = layout_param("bit_index", "cursor", "scalar");
        index.primitive = Some("bhf_i32".to_owned());
        index.width = Some(4);
        index.value_kind = Some("u32".to_owned());
        ArgLayout::new("c", "direct", vec![LayoutStep::Param(index)])
            .write(dir)
            .unwrap();
    }

    fn decode_with_harness(
        work: &Path,
        harness: &str,
        testcase: PathBuf,
    ) -> Result<Report, String> {
        decode(&DecodeArgsArgs {
            testcase: Some(testcase),
            finding: None,
            harness: Some(PathBuf::from(harness)),
            work_dir: work.to_path_buf(),
            static_only: false,
            json: false,
            qemu_user: None,
            qemu_args: Vec::new(),
        })
    }

    /// A `--harness` that names no file or dir but a harness id is looked up
    /// under the work dir.
    #[test]
    fn a_harness_id_resolves_under_the_work_dir() {
        let work = tempfile::tempdir().unwrap();
        let harness = work.path().join("harnesses/H-X");
        std::fs::create_dir_all(&harness).unwrap();
        write_static_layout(&harness);
        let testcase = work.path().join("t.bin");
        std::fs::write(&testcase, b"\x2a\x00\x00\x00").unwrap();
        let report = decode_with_harness(work.path(), "H-X", testcase).unwrap();
        assert_eq!(report.source, Source::ArgLayout);
        let names: Vec<&str> = report.arguments.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["bit_index"]);
        assert_eq!(report.arguments[0].value.as_deref(), Some("42"));
    }

    /// A `--harness` that names nothing says so, instead of saying it decoded
    /// from a layout it never found.
    #[test]
    fn an_unknown_harness_says_it_does_not_exist() {
        let work = tempfile::tempdir().unwrap();
        let testcase = work.path().join("t.bin");
        std::fs::write(&testcase, b"x").unwrap();
        let error = decode_with_harness(work.path(), "H-NOPE", testcase)
            .err()
            .unwrap();
        assert!(error.contains("no such file or directory"), "{error}");
        assert!(
            error.contains(&work.path().display().to_string()),
            "{error}"
        );
        assert!(!error.contains("decoded from the layout"), "{error}");
    }

    /// A bare file name given as `--harness` is the file in the current
    /// directory, never a program of that name on `PATH`.
    #[cfg(unix)]
    #[test]
    fn a_bare_harness_file_name_runs_the_file_in_the_current_directory() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("cwd");
        let bin = temp.path().join("bin");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let marker = temp.path().join("path-tracer-ran");
        let script = |name: &str, extra: &str| {
            format!(
                "#!/bin/sh\n# {} BHF_FRAMED\n{extra}echo 'BHF_ARG {{\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"{name}\",\"type\":\"int\",\"span\":[0,1],\"value\":\"7\"}}' >&2\n",
                corpus::decoded_args::TRACE_ARGS_ENV
            )
        };
        for (path, body) in [
            (cwd.join("tracer"), script("local", "")),
            (
                bin.join("tracer"),
                script("from_path", &format!("touch '{}'\n", marker.display())),
            ),
        ] {
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let testcase = temp.path().join("t.bin");
        std::fs::write(&testcase, b"x").unwrap();
        let saved_dir = std::env::current_dir().unwrap();
        let saved_path = std::env::var_os("PATH");
        let mut path = vec![bin.clone()];
        path.extend(std::env::split_paths(
            &saved_path.clone().unwrap_or_default(),
        ));
        std::env::set_var("PATH", std::env::join_paths(path).unwrap());
        std::env::set_current_dir(&cwd).unwrap();
        let report = decode_with_harness(temp.path(), "tracer", testcase);
        std::env::set_current_dir(saved_dir).unwrap();
        match saved_path {
            Some(path) => std::env::set_var("PATH", path),
            None => std::env::remove_var("PATH"),
        }
        let report = report.unwrap();
        assert!(!marker.exists(), "the PATH program ran: {:?}", report.notes);
        assert_eq!(report.source, Source::HarnessTrace, "{:?}", report.notes);
        assert_eq!(report.arguments[0].name, "local");
    }

    /// A finding recorded against another input format than the layout gets
    /// a note: the values are what this layout decodes, not that run.
    #[test]
    fn a_format_mismatch_is_noted() {
        let work = tempfile::tempdir().unwrap();
        let finding = work.path().join("results/findings/F-0001-aa");
        std::fs::create_dir_all(&finding).unwrap();
        std::fs::write(finding.join("testcase.bin"), b"\x01\x00\x00\x00").unwrap();
        std::fs::write(
            finding.join("finding.json"),
            r#"{"id":"F-0001-aa","harness_id":"H-1","harness":{"format_version":2},
                "harness_format_version":3}"#,
        )
        .unwrap();
        let harness = work.path().join("harnesses/H-1");
        std::fs::create_dir_all(&harness).unwrap();
        let mut p = layout_param("n", "cursor", "scalar");
        p.primitive = Some("bhf_i32".to_owned());
        p.width = Some(4);
        ArgLayout::new("c", "direct", vec![LayoutStep::Param(p)])
            .write(&harness)
            .unwrap();
        let report = decode(&DecodeArgsArgs {
            testcase: None,
            finding: Some(finding.clone()),
            harness: None,
            work_dir: work.path().to_path_buf(),
            static_only: true,
            json: false,
            qemu_user: None,
            qemu_args: Vec::new(),
        })
        .unwrap();
        assert_eq!(report.arguments[0].value.as_deref(), Some("1"));
        assert!(
            report.notes.iter().any(|n| n.contains("input format 2")),
            "{:?}",
            report.notes
        );
    }
}
