// SPDX-License-Identifier: Apache-2.0

//! `bhf differential` subcommand: replay each input through
//! two harnesses, compare stdout + exit code, emit BHF-301 findings
//! on divergence. No mutation or coverage feedback — pure replay.
//!
//! Metamorphic mode replays each input and its variants under the
//! transforms of [`TRANSFORMS`] through one harness. Each transform
//! declares the [`Relation`] its variant must keep with the input (the same
//! output, or the same exit status), as metamorphic testing pairs a
//! follow-up input with an expected relation; a broken relation is a BHF-307
//! finding.

use finding_rules::oracle_registry::ORACLE_REGISTRY;
use finding_rules::oracle_sdk::{OracleHit, OracleRuntimeEvent};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Error, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, clap::Args)]
pub struct DifferentialArgs {
    /// First harness binary. Receives the input path as argv[1].
    #[arg(long = "harness-a", value_name = "PATH")]
    pub harness_a: Option<PathBuf>,

    /// Second harness binary. Receives the input path as argv[1].
    #[arg(long = "harness-b", value_name = "PATH")]
    pub harness_b: Option<PathBuf>,

    /// Single harness binary for metamorphic mode. Receives the input path as argv[1].
    #[arg(long = "harness", value_name = "PATH")]
    pub harness: Option<PathBuf>,

    /// Metamorphic transform to apply to each input before replaying the same
    /// harness; several, comma-separated or the flag repeated, are each applied
    /// to every input. `append-newline` (a `\n` after the input) and
    /// `trailing-whitespace` (a space and a tab at the end of every line) must
    /// keep the output; `reorder-json-keys` (every JSON object's members in
    /// reverse order, every other byte kept) must keep the output;
    /// `utf8-bom` (a UTF-8 byte order mark before the input) must keep the
    /// exit status. An input a transform does not apply to (no JSON text,
    /// one with a BOM already) is left out for it.
    #[arg(
        long = "metamorphic-transform",
        value_enum,
        value_name = "NAME",
        value_delimiter = ','
    )]
    pub metamorphic_transforms: Vec<MetamorphicTransform>,

    /// Directory of input files to replay through both harnesses.
    #[arg(long, value_name = "DIR")]
    pub inputs: PathBuf,

    /// Work directory; findings go to <work-dir>/results/findings/F-DIFF-*.
    #[arg(long = "work-dir", value_name = "DIR", default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Deprecated spelling of --work-dir.
    #[arg(
        long = "out",
        value_name = "DIR",
        hide = true,
        conflicts_with = "work_dir"
    )]
    pub out: Option<PathBuf>,

    /// Per-side timeout in seconds.
    #[arg(long, default_value_t = 5)]
    pub timeout_secs: u64,
}

impl DifferentialArgs {
    /// Fold the deprecated `--out` into `work_dir`, saying where findings land now.
    pub fn resolve_deprecated_out(mut self) -> Self {
        if let Some(out) = self.out.take() {
            bhfeprintln!(
                "note: --out is deprecated for differential; treated as --work-dir; findings are in {}",
                corpus::layout::findings_dir(&out).display()
            );
            self.work_dir = out;
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MetamorphicTransform {
    #[value(name = "append-newline")]
    AppendNewline,
    #[value(name = "trailing-whitespace")]
    TrailingWhitespace,
    #[value(name = "reorder-json-keys")]
    ReorderJsonKeys,
    #[value(name = "utf8-bom")]
    Utf8Bom,
}

/// What must hold between the run of an input and the run of its
/// transformed variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Relation {
    /// The same stdout bytes and the same exit status: the transform must not
    /// change what the harness computes.
    SameOutput,
    /// The same exit status (and neither or both timed out); stdout may
    /// differ: the harness must accept or reject the variant as it does the
    /// input, though it may echo the change.
    SameExit,
}

impl Relation {
    fn as_str(self) -> &'static str {
        match self {
            Relation::SameOutput => "same-output",
            Relation::SameExit => "same-exit",
        }
    }

    /// Whether the runs that diverged as `div` break the relation.
    fn broken_by(self, div: &Divergence) -> bool {
        match self {
            Relation::SameOutput => !div.stdout_equal || !div.exit_equal,
            Relation::SameExit => !div.exit_equal,
        }
    }
}

/// One registered metamorphic transform: its name, what it does to an input,
/// and the relation its variant must keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransformSpec {
    pub(crate) transform: MetamorphicTransform,
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) relation: Relation,
}

/// The transform registry.
pub(crate) const TRANSFORMS: [TransformSpec; 4] = [
    TransformSpec {
        transform: MetamorphicTransform::AppendNewline,
        name: "append-newline",
        description: "a `\\n` after the input",
        relation: Relation::SameOutput,
    },
    TransformSpec {
        transform: MetamorphicTransform::TrailingWhitespace,
        name: "trailing-whitespace",
        description: "a space and a tab at the end of every line",
        relation: Relation::SameOutput,
    },
    TransformSpec {
        transform: MetamorphicTransform::ReorderJsonKeys,
        name: "reorder-json-keys",
        description: "every JSON object's members in reverse order, every other byte kept",
        relation: Relation::SameOutput,
    },
    TransformSpec {
        transform: MetamorphicTransform::Utf8Bom,
        name: "utf8-bom",
        description: "a UTF-8 byte order mark (EF BB BF) before the input",
        relation: Relation::SameExit,
    },
];

impl MetamorphicTransform {
    fn spec(self) -> &'static TransformSpec {
        TRANSFORMS
            .iter()
            .find(|spec| spec.transform == self)
            .expect("every transform is registered")
    }

    fn as_str(self) -> &'static str {
        self.spec().name
    }

    fn relation(self) -> Relation {
        self.spec().relation
    }

    /// `input`'s variant under the transform; `None` when the transform does
    /// not apply to it or leaves it as it is (no JSON object with two
    /// members, a BOM already there), so there is no relation to check.
    fn apply(self, input: &[u8]) -> Option<Vec<u8>> {
        let transformed = match self {
            MetamorphicTransform::AppendNewline => {
                let mut transformed = input.to_vec();
                transformed.push(b'\n');
                transformed
            }
            MetamorphicTransform::TrailingWhitespace => trailing_whitespace(input),
            MetamorphicTransform::ReorderJsonKeys => reverse_json_members(input)?,
            MetamorphicTransform::Utf8Bom => {
                if input.starts_with(UTF8_BOM) {
                    return None;
                }
                [UTF8_BOM, input].concat()
            }
        };
        (transformed != input).then_some(transformed)
    }
}

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// `input` with a space and a tab at the end of every line, before its
/// `\r\n` or `\n`, the last one too when it has no line end.
fn trailing_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 8 + 2);
    let mut line_start = 0;
    for (at, &byte) in input.iter().enumerate() {
        if byte == b'\n' {
            let end = if at > line_start && input[at - 1] == b'\r' {
                at - 1
            } else {
                at
            };
            out.extend_from_slice(&input[line_start..end]);
            out.extend_from_slice(b" \t");
            out.extend_from_slice(&input[end..=at]);
            line_start = at + 1;
        }
    }
    if line_start < input.len() {
        out.extend_from_slice(&input[line_start..]);
        out.extend_from_slice(b" \t");
    }
    out
}

/// The deepest JSON nesting [`reverse_json_members`] reads.
const MAX_JSON_DEPTH: usize = 512;

/// `input` with the members of every JSON object in reverse order and every
/// other byte (whitespace, separators, numbers' and strings' own spelling)
/// where it was: an order-independent consumer gives the same output for
/// both. `None` when `input` is no JSON text (RFC 8259).
fn reverse_json_members(input: &[u8]) -> Option<Vec<u8>> {
    let mut scan = JsonScan { s: input, at: 0 };
    let lead = scan.whitespace();
    let value = scan.value(0)?;
    let trail = scan.whitespace();
    (scan.at == input.len()).then(|| [lead, &value[..], trail].concat())
}

struct JsonScan<'a> {
    s: &'a [u8],
    at: usize,
}

impl<'a> JsonScan<'a> {
    fn whitespace(&mut self) -> &'a [u8] {
        let start = self.at;
        while matches!(self.s.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
        &self.s[start..self.at]
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        (self.s.get(self.at) == Some(&byte)).then(|| self.at += 1)
    }

    /// One value, with the members of its objects reversed.
    fn value(&mut self, depth: usize) -> Option<Vec<u8>> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        match *self.s.get(self.at)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(<[u8]>::to_vec),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, word: &[u8]) -> Option<Vec<u8>> {
        let end = self.at + word.len();
        (self.s.get(self.at..end) == Some(word)).then(|| {
            self.at = end;
            word.to_vec()
        })
    }

    fn number(&mut self) -> Option<Vec<u8>> {
        let start = self.at;
        let digits = |scan: &mut Self| {
            let from = scan.at;
            while scan.s.get(scan.at).is_some_and(u8::is_ascii_digit) {
                scan.at += 1;
            }
            scan.at > from
        };
        let _ = self.eat(b'-');
        if self.eat(b'0').is_none() && !digits(self) {
            return None;
        }
        if self.eat(b'.').is_some() && !digits(self) {
            return None;
        }
        if matches!(self.s.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.s.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !digits(self) {
                return None;
            }
        }
        Some(self.s[start..self.at].to_vec())
    }

    /// A string, as it is spelled.
    fn string(&mut self) -> Option<&'a [u8]> {
        let start = self.at;
        self.eat(b'"')?;
        loop {
            match *self.s.get(self.at)? {
                b'"' => {
                    self.at += 1;
                    return Some(&self.s[start..self.at]);
                }
                b'\\' => {
                    let escape = *self.s.get(self.at + 1)?;
                    match escape {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => self.at += 2,
                        b'u' => {
                            let hex = self.s.get(self.at + 2..self.at + 6)?;
                            if !hex.iter().all(u8::is_ascii_hexdigit) {
                                return None;
                            }
                            self.at += 6;
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1F => return None,
                _ => self.at += 1,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Vec<u8>> {
        let start = self.at;
        self.eat(b'[')?;
        let mut out = vec![b'['];
        out.extend_from_slice(self.whitespace());
        if self.eat(b']').is_some() {
            out.push(b']');
            return Some(out);
        }
        loop {
            out.extend_from_slice(&self.value(depth + 1)?);
            out.extend_from_slice(self.whitespace());
            match *self.s.get(self.at)? {
                b',' => {
                    self.at += 1;
                    out.push(b',');
                    out.extend_from_slice(self.whitespace());
                }
                b']' => {
                    self.at += 1;
                    out.push(b']');
                    debug_assert_eq!(out.len(), self.at - start);
                    return Some(out);
                }
                _ => return None,
            }
        }
    }

    /// An object: `{` and the whitespace after it, the members (each its
    /// key, `:`, its value and the whitespace between), the separators
    /// between them as they were, and the whitespace before `}`; the members
    /// are written back in reverse order between the same separators.
    fn object(&mut self, depth: usize) -> Option<Vec<u8>> {
        self.eat(b'{')?;
        let mut out = vec![b'{'];
        out.extend_from_slice(self.whitespace());
        if self.eat(b'}').is_some() {
            out.push(b'}');
            return Some(out);
        }
        let mut members: Vec<Vec<u8>> = Vec::new();
        let mut separators: Vec<Vec<u8>> = Vec::new();
        let closing;
        loop {
            let mut member = self.string()?.to_vec();
            member.extend_from_slice(self.whitespace());
            self.eat(b':')?;
            member.push(b':');
            member.extend_from_slice(self.whitespace());
            member.extend_from_slice(&self.value(depth + 1)?);
            members.push(member);
            let gap = self.whitespace().to_vec();
            match *self.s.get(self.at)? {
                b',' => {
                    self.at += 1;
                    let mut separator = gap;
                    separator.push(b',');
                    separator.extend_from_slice(self.whitespace());
                    separators.push(separator);
                }
                b'}' => {
                    self.at += 1;
                    closing = gap;
                    break;
                }
                _ => return None,
            }
        }
        for (index, member) in members.iter().rev().enumerate() {
            if index > 0 {
                out.extend_from_slice(&separators[index - 1]);
            }
            out.extend_from_slice(member);
        }
        out.extend_from_slice(&closing);
        out.push(b'}');
        Some(out)
    }
}

#[derive(Debug, Clone)]
enum RunMode {
    Differential {
        harness_a: PathBuf,
        harness_b: PathBuf,
    },
    Metamorphic {
        harness: PathBuf,
        transforms: Vec<MetamorphicTransform>,
    },
}

impl RunMode {
    fn from_args(args: &DifferentialArgs) -> Result<Self, std::io::Error> {
        match args.metamorphic_transforms.first() {
            Some(_) => {
                if args.harness_a.is_some() || args.harness_b.is_some() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "--metamorphic-transform uses --harness, not --harness-a/--harness-b",
                    ));
                }
                let harness = args.harness.clone().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "--metamorphic-transform requires --harness",
                    )
                })?;
                // Each transform once, in the order given.
                let mut transforms: Vec<MetamorphicTransform> = Vec::new();
                for transform in &args.metamorphic_transforms {
                    if !transforms.contains(transform) {
                        transforms.push(*transform);
                    }
                }
                Ok(RunMode::Metamorphic {
                    harness,
                    transforms,
                })
            }
            None => {
                if args.harness.is_some() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "--harness requires --metamorphic-transform",
                    ));
                }
                let harness_a = args.harness_a.clone().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidInput, "missing required --harness-a")
                })?;
                let harness_b = args.harness_b.clone().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidInput, "missing required --harness-b")
                })?;
                Ok(RunMode::Differential {
                    harness_a,
                    harness_b,
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HarnessOutput {
    stdout: Vec<u8>,
    #[allow(dead_code)]
    // captured for future inclusion in findings; v0.1 keeps stderr out of the divergence predicate
    stderr: Vec<u8>,
    exit_code: i32,
    timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Divergence {
    pub stdout_equal: bool,
    pub exit_equal: bool,
    pub stdout_a_preview: String,
    pub stdout_b_preview: String,
    pub exit_a: i32,
    pub exit_b: i32,
    pub timed_out_a: bool,
    pub timed_out_b: bool,
}

pub fn run(args: DifferentialArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) => {
            bhfeprintln!("error: {error}");
            1
        }
    }
}

fn run_inner(args: DifferentialArgs) -> Result<i32, std::io::Error> {
    let mode = RunMode::from_args(&args)?;
    let mut inputs: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&args.inputs)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            inputs.push(entry.path());
        }
    }
    inputs.sort();

    // Only a validated run touches the work dir.
    let findings_root = corpus::layout::findings_dir(&args.work_dir);
    fs::create_dir_all(&findings_root)?;
    let mut ids = corpus::layout::FamilyAllocator::new(&findings_root, "F-DIFF-")?;
    let transformed_root = args
        .work_dir
        .join("differential")
        .join("metamorphic_inputs");
    if matches!(mode, RunMode::Metamorphic { .. }) {
        fs::create_dir_all(&transformed_root)?;
    }

    let timeout = Duration::from_secs(args.timeout_secs);
    let mut divergences = 0usize;
    let mut not_applicable = 0usize;

    for (input_index, input_path) in inputs.iter().enumerate() {
        let input_bytes = fs::read(input_path)?;
        match &mode {
            RunMode::Differential {
                harness_a,
                harness_b,
            } => {
                let out_a = run_harness(harness_a, input_path, timeout);
                let out_b = run_harness(harness_b, input_path, timeout);
                if let Some(div) = compare_outputs(&out_a, &out_b) {
                    divergences += 1;
                    write_finding(
                        &mut ids,
                        &input_bytes,
                        input_path,
                        harness_a,
                        harness_b,
                        &div,
                    )?;
                }
            }
            RunMode::Metamorphic {
                harness,
                transforms,
            } => {
                let mut original = None;
                for transform in transforms {
                    let Some(transformed_bytes) = transform.apply(&input_bytes) else {
                        not_applicable += 1;
                        continue;
                    };
                    let transformed_path = transformed_root
                        .join(format!("{input_index:04}-{}.bin", transform.as_str()));
                    fs::write(&transformed_path, &transformed_bytes)?;
                    let original =
                        original.get_or_insert_with(|| run_harness(harness, input_path, timeout));
                    let transformed = run_harness(harness, &transformed_path, timeout);
                    let Some(div) = compare_outputs(original, &transformed) else {
                        continue;
                    };
                    if transform.relation().broken_by(&div) {
                        divergences += 1;
                        write_metamorphic_finding(
                            &mut ids,
                            &input_bytes,
                            input_path,
                            &transformed_bytes,
                            harness,
                            *transform,
                            &div,
                        )?;
                    }
                }
            }
        }
    }

    if not_applicable > 0 {
        println!(
            "{} inputs, {} divergences, {} transformed inputs left out (the transform does not \
             apply to the input)",
            inputs.len(),
            divergences,
            not_applicable
        );
    } else {
        println!("{} inputs, {} divergences", inputs.len(), divergences);
    }
    Ok(if divergences > 0 { 1 } else { 0 })
}

fn run_harness(bin: &Path, input: &Path, timeout: Duration) -> HarnessOutput {
    let mut command = Command::new(bin);
    command
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    crate::command_output::run_target_beside_binary(&mut command, bin);
    let child = command.spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(error) => {
            return HarnessOutput {
                stdout: Vec::new(),
                stderr: format!("spawn failed: {error}").into_bytes(),
                exit_code: -1,
                timed_out: false,
            };
        }
    };
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    timed_out = true;
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return HarnessOutput {
                    stdout: Vec::new(),
                    stderr: format!("wait failed: {error}").into_bytes(),
                    exit_code: -1,
                    timed_out: false,
                };
            }
        }
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_end(&mut stdout);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_end(&mut stderr);
    }
    let exit_code = if timed_out {
        -1
    } else {
        child.wait().ok().and_then(|s| s.code()).unwrap_or(-1)
    };
    HarnessOutput {
        stdout,
        stderr,
        exit_code,
        timed_out,
    }
}

pub(crate) fn compare_outputs(a: &HarnessOutput, b: &HarnessOutput) -> Option<Divergence> {
    let stdout_equal = a.stdout == b.stdout;
    let exit_equal = a.exit_code == b.exit_code && a.timed_out == b.timed_out;
    if stdout_equal && exit_equal {
        None
    } else {
        Some(Divergence {
            stdout_equal,
            exit_equal,
            stdout_a_preview: truncate_preview(&a.stdout, 4096),
            stdout_b_preview: truncate_preview(&b.stdout, 4096),
            exit_a: a.exit_code,
            exit_b: b.exit_code,
            timed_out_a: a.timed_out,
            timed_out_b: b.timed_out,
        })
    }
}

pub(crate) fn truncate_preview(bytes: &[u8], max: usize) -> String {
    let slice = if bytes.len() > max {
        &bytes[..max]
    } else {
        bytes
    };
    String::from_utf8_lossy(slice).into_owned()
}

fn write_finding(
    ids: &mut corpus::layout::FamilyAllocator,
    input_bytes: &[u8],
    input_path: &Path,
    harness_a: &Path,
    harness_b: &Path,
    div: &Divergence,
) -> std::io::Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(input_bytes);
    let signature_hex = corpus::hex_lower(&hasher.finalize());
    let oracle_hit = differential_oracle_hit(&signature_hex, div).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "differential oracle did not match a divergent output pair",
        )
    })?;
    let (id, finding_dir) = ids.create()?;
    fs::write(finding_dir.join("testcase.bin"), input_bytes)?;
    let mut record = json!({
        "id": id,
        "signature": signature_hex,
        "rule_id": "BHF-301",
        "classification": "divergence",
        "exception": {
            "name": "OUTPUT_DIVERGENCE",
            "message": if div.stdout_equal {
                "exit codes differ"
            } else {
                "stdout bytes differ"
            },
        },
        "differential": {
            "harness_a": harness_a.display().to_string(),
            "harness_b": harness_b.display().to_string(),
            "stdout_equal": div.stdout_equal,
            "exit_equal": div.exit_equal,
            "stdout_a_preview": div.stdout_a_preview,
            "stdout_b_preview": div.stdout_b_preview,
            "exit_a": div.exit_a,
            "exit_b": div.exit_b,
            "timed_out_a": div.timed_out_a,
            "timed_out_b": div.timed_out_b,
        },
        "oracle": oracle_hit_json(&oracle_hit),
        "paths": {
            "testcase": "testcase.bin",
            "finding": "finding.json",
        },
    });
    // The operator's input file, run as it is.
    crate::fuzz_lineage::insert(
        &mut record,
        &crate::fuzz_lineage::of_operator_input(input_bytes, Some(input_path)),
    );
    corpus::finding::stamp_v1(&mut record, corpus::finding::finding_kind::DIFFERENTIAL);
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    Ok(())
}

fn write_metamorphic_finding(
    ids: &mut corpus::layout::FamilyAllocator,
    input_bytes: &[u8],
    input_path: &Path,
    transformed_bytes: &[u8],
    harness: &Path,
    transform: MetamorphicTransform,
    div: &Divergence,
) -> std::io::Result<()> {
    let input_sha256 = sha256_hex(input_bytes);
    let transformed_sha256 = sha256_hex(transformed_bytes);
    let signature_hex = metamorphic_signature(transform, input_bytes, transformed_bytes);
    let oracle_hit = metamorphic_oracle_hit(&input_sha256, &transformed_sha256, transform, div)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "metamorphic oracle did not match a relation violation",
            )
        })?;
    let (id, finding_dir) = ids.create()?;
    fs::write(finding_dir.join("testcase.bin"), input_bytes)?;
    fs::write(
        finding_dir.join("testcase_transformed.bin"),
        transformed_bytes,
    )?;
    let mut record = json!({
        "id": id,
        "signature": signature_hex,
        "rule_id": "BHF-307",
        "classification": "metamorphic_violation",
        "exception": {
            "name": "METAMORPHIC_RELATION_VIOLATION",
            "message": if div.stdout_equal || transform.relation() == Relation::SameExit {
                "exit codes differ after metamorphic transform"
            } else {
                "stdout bytes differ after metamorphic transform"
            },
        },
        "metamorphic": {
            "harness": harness.display().to_string(),
            "transform": transform.as_str(),
            "relation": transform.relation().as_str(),
            "stdout_equal": div.stdout_equal,
            "exit_equal": div.exit_equal,
            "original_stdout_preview": div.stdout_a_preview,
            "transformed_stdout_preview": div.stdout_b_preview,
            "original_exit": div.exit_a,
            "transformed_exit": div.exit_b,
            "timed_out_original": div.timed_out_a,
            "timed_out_transformed": div.timed_out_b,
        },
        "oracle": oracle_hit_json(&oracle_hit),
        "paths": {
            "testcase": "testcase.bin",
            "transformed_testcase": "testcase_transformed.bin",
            "finding": "finding.json",
        },
    });
    // `testcase.bin` is the operator's input file, run as it is.
    crate::fuzz_lineage::insert(
        &mut record,
        &crate::fuzz_lineage::of_operator_input(input_bytes, Some(input_path)),
    );
    corpus::finding::stamp_v1(&mut record, corpus::finding::finding_kind::DIFFERENTIAL);
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    corpus::hex_lower(&hasher.finalize())
}

fn metamorphic_signature(
    transform: MetamorphicTransform,
    input_bytes: &[u8],
    transformed_bytes: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"metamorphic\0");
    hasher.update(transform.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(input_bytes);
    hasher.update(b"\0");
    hasher.update(transformed_bytes);
    corpus::hex_lower(&hasher.finalize())
}

fn differential_oracle_hit(input_sha256: &str, div: &Divergence) -> Option<OracleHit> {
    let event = OracleRuntimeEvent::Differential {
        api: "bhf differential".to_owned(),
        stdout_equal: div.stdout_equal,
        exit_equal: div.exit_equal,
        timed_out_a: div.timed_out_a,
        timed_out_b: div.timed_out_b,
        evidence: vec![("input_sha256".to_owned(), input_sha256.to_owned())],
    };
    ORACLE_REGISTRY
        .iter()
        .find_map(|oracle| oracle.evaluate(&event))
}

fn metamorphic_oracle_hit(
    input_sha256: &str,
    transformed_sha256: &str,
    transform: MetamorphicTransform,
    div: &Divergence,
) -> Option<OracleHit> {
    let event = OracleRuntimeEvent::Metamorphic {
        api: "bhf differential metamorphic".to_owned(),
        relation: transform.as_str().to_owned(),
        stdout_equal: div.stdout_equal,
        exit_equal: div.exit_equal,
        timed_out_original: div.timed_out_a,
        timed_out_transformed: div.timed_out_b,
        evidence: vec![
            ("input_sha256".to_owned(), input_sha256.to_owned()),
            (
                "transformed_input_sha256".to_owned(),
                transformed_sha256.to_owned(),
            ),
            (
                "expected_relation".to_owned(),
                transform.relation().as_str().to_owned(),
            ),
        ],
    };
    ORACLE_REGISTRY
        .iter()
        .find_map(|oracle| oracle.evaluate(&event))
}

fn oracle_hit_json(hit: &OracleHit) -> serde_json::Value {
    json!({
        "name": hit.oracle_name,
        "rule_id": hit.rule_id,
        "category": hit.category,
        "api": hit.api,
        "message": hit.message,
        "evidence": hit.evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        compare_outputs, reverse_json_members, trailing_whitespace, truncate_preview,
        HarnessOutput, MetamorphicTransform, Relation, TRANSFORMS,
    };
    #[cfg(unix)]
    use super::{fs, run_inner, sha256_hex, DifferentialArgs, Path, PathBuf};

    fn harness_output(stdout: &[u8], exit_code: i32) -> HarnessOutput {
        HarnessOutput {
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            exit_code,
            timed_out: false,
        }
    }

    #[test]
    fn compare_outputs_returns_none_when_identical() {
        let a = harness_output(b"hello", 0);
        let b = harness_output(b"hello", 0);
        assert!(compare_outputs(&a, &b).is_none());
    }

    #[test]
    fn compare_outputs_flags_stdout_difference() {
        let a = harness_output(b"hello", 0);
        let b = harness_output(b"world", 0);
        let div = compare_outputs(&a, &b).expect("divergent");
        assert!(!div.stdout_equal);
        assert!(div.exit_equal);
    }

    #[test]
    fn compare_outputs_flags_exit_code_difference() {
        let a = harness_output(b"same", 0);
        let b = harness_output(b"same", 1);
        let div = compare_outputs(&a, &b).expect("divergent");
        assert!(div.stdout_equal);
        assert!(!div.exit_equal);
    }

    #[test]
    fn truncate_preview_keeps_first_4096_bytes() {
        let bytes = vec![b'a'; 5000];
        let preview = truncate_preview(&bytes, 4096);
        assert_eq!(preview.len(), 4096);
    }

    #[test]
    fn truncate_preview_produces_lossy_for_binary_input() {
        let preview = truncate_preview(&[0xFF, 0xFE, b'a'], 4096);
        assert!(preview.contains('a'));
    }

    /// `bhf differential` runs the operator's input files as they are: a
    /// divergence's testcase is a user seed, 0 generations down, named by the
    /// file it was read from, in both modes.
    #[test]
    #[cfg(unix)]
    fn a_divergence_names_the_input_file_it_replayed_as_a_user_seed() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let inputs = root.join("inputs");
        fs::create_dir_all(&inputs).unwrap();
        let input = inputs.join("one.bin");
        fs::write(&input, b"hello").unwrap();
        let script = |name: &str, body: &str| {
            let path = root.join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let same = script("same", "#!/bin/sh\ncat \"$1\"\n");
        let other = script("other", "#!/bin/sh\necho other\n");
        let lines = script("lines", "#!/bin/sh\nwc -l < \"$1\"\n");
        let lineage = |work: &Path| -> serde_json::Value {
            let findings = corpus::layout::findings_dir(work);
            let dir = fs::read_dir(&findings)
                .unwrap()
                .flatten()
                .next()
                .unwrap()
                .path();
            let record: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
            record["lineage"].clone()
        };
        let args = |work: PathBuf| DifferentialArgs {
            harness_a: None,
            harness_b: None,
            harness: None,
            metamorphic_transforms: Vec::new(),
            inputs: inputs.clone(),
            work_dir: work,
            out: None,
            timeout_secs: 5,
        };
        let named = std::path::absolute(&input).unwrap().display().to_string();

        let work = root.join("work-diff");
        let mut differential = args(work.clone());
        differential.harness_a = Some(same.clone());
        differential.harness_b = Some(other);
        assert_eq!(run_inner(differential).unwrap(), 1);
        let found = lineage(&work);
        assert_eq!(found["origin"], "user_seed", "{found}");
        assert_eq!(found["root_path"], named.as_str());
        assert_eq!(found["root_sha256"], sha256_hex(b"hello"));
        assert_eq!(found["depth"], 0);

        let work = root.join("work-meta");
        let mut metamorphic = args(work.clone());
        metamorphic.harness = Some(lines);
        metamorphic.metamorphic_transforms = vec![MetamorphicTransform::AppendNewline];
        assert_eq!(run_inner(metamorphic).unwrap(), 1);
        let found = lineage(&work);
        assert_eq!(found["origin"], "user_seed", "{found}");
        assert_eq!(found["root_path"], named.as_str());
        assert_eq!(found["depth"], 0);
    }
    /// Every transform `--metamorphic-transform` takes is registered once,
    /// under its command-line name, with what it does and the relation its
    /// variant must keep; the relation decides which divergence breaks it.
    #[test]
    fn each_transform_declares_a_relation() {
        use clap::ValueEnum;
        for transform in MetamorphicTransform::value_variants() {
            let specs: Vec<_> = TRANSFORMS
                .iter()
                .filter(|spec| spec.transform == *transform)
                .collect();
            assert_eq!(specs.len(), 1, "{transform:?} is registered once");
            let spec = specs[0];
            let flag = transform.to_possible_value().unwrap();
            assert_eq!(spec.name, flag.get_name(), "{transform:?}");
            assert!(!spec.description.is_empty(), "{transform:?}");
            assert_eq!(transform.relation(), spec.relation);
        }
        assert_eq!(
            TRANSFORMS.len(),
            MetamorphicTransform::value_variants().len()
        );
        let relation = |transform: MetamorphicTransform| transform.relation();
        assert_eq!(
            relation(MetamorphicTransform::AppendNewline),
            Relation::SameOutput
        );
        assert_eq!(
            relation(MetamorphicTransform::TrailingWhitespace),
            Relation::SameOutput
        );
        assert_eq!(
            relation(MetamorphicTransform::ReorderJsonKeys),
            Relation::SameOutput
        );
        assert_eq!(relation(MetamorphicTransform::Utf8Bom), Relation::SameExit);

        // Other stdout alone breaks only the same-output relation; another
        // exit status breaks both.
        let stdout_only =
            compare_outputs(&harness_output(b"a", 0), &harness_output(b"b", 0)).expect("divergent");
        assert!(Relation::SameOutput.broken_by(&stdout_only));
        assert!(!Relation::SameExit.broken_by(&stdout_only));
        let exit =
            compare_outputs(&harness_output(b"a", 0), &harness_output(b"a", 1)).expect("divergent");
        assert!(Relation::SameOutput.broken_by(&exit));
        assert!(Relation::SameExit.broken_by(&exit));
    }

    #[test]
    fn the_transforms_rewrite_only_what_they_name() {
        assert_eq!(trailing_whitespace(b"a\nb\r\nc"), b"a \t\nb \t\r\nc \t");
        assert_eq!(trailing_whitespace(b"a\n"), b"a \t\n");
        assert_eq!(
            reverse_json_members(b" {\"a\": 1,\n \"b\" :[{\"x\":1,\"y\":\"}\"}], \"c\":{}} ")
                .unwrap(),
            b" {\"c\":{},\n \"b\" :[{\"y\":\"}\",\"x\":1}], \"a\": 1} "
        );
        // No JSON text, or nothing to reorder: no variant.
        assert_eq!(reverse_json_members(b"{\"a\":1,}"), None);
        assert_eq!(reverse_json_members(b"key=value"), None);
        assert_eq!(
            MetamorphicTransform::ReorderJsonKeys.apply(b"[1, {\"a\": 2}]"),
            None
        );
        let bom = MetamorphicTransform::Utf8Bom.apply(b"{}").unwrap();
        assert_eq!(bom, b"\xEF\xBB\xBF{}");
        assert_eq!(MetamorphicTransform::Utf8Bom.apply(&bom), None);
    }

    #[cfg(unix)]
    fn script(root: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    fn metamorphic_args(
        inputs: &Path,
        work: &Path,
        harness: &Path,
        transforms: &[MetamorphicTransform],
    ) -> DifferentialArgs {
        DifferentialArgs {
            harness_a: None,
            harness_b: None,
            harness: Some(harness.to_path_buf()),
            metamorphic_transforms: transforms.to_vec(),
            inputs: inputs.to_path_buf(),
            work_dir: work.to_path_buf(),
            out: None,
            timeout_secs: 5,
        }
    }

    /// Each finding under `work`: its record and its transformed testcase.
    #[cfg(unix)]
    fn metamorphic_findings(work: &Path) -> Vec<(serde_json::Value, Vec<u8>)> {
        let Ok(entries) = fs::read_dir(corpus::layout::findings_dir(work)) else {
            return Vec::new();
        };
        let mut found: Vec<_> = entries
            .flatten()
            .map(|entry| {
                let dir = entry.path();
                let record: serde_json::Value =
                    serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
                (
                    record,
                    fs::read(dir.join("testcase_transformed.bin")).unwrap(),
                )
            })
            .collect();
        found.sort_by_key(|(record, _)| record["id"].as_str().unwrap_or_default().to_owned());
        found
    }

    /// A harness whose output follows the order of a JSON object's keys
    /// breaks the relation `reorder-json-keys` keeps; one whose output does
    /// not, does not. An input that is no JSON is left out.
    #[test]
    #[cfg(unix)]
    fn reorder_json_keys_detects_order_dependent_output() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let inputs = root.join("inputs");
        fs::create_dir_all(&inputs).unwrap();
        let json = b"{\"user\": \"ada\", \"role\": [\"admin\", {\"x\": 1, \"y\": 2}]}\n";
        fs::write(inputs.join("a.json"), json).unwrap();
        fs::write(inputs.join("b.txt"), b"user=ada\n").unwrap();
        // The first key the object names, as a parser that keeps the first
        // of a duplicated or order-sensitive field might use it.
        let first_key = script(
            root,
            "first-key",
            "#!/bin/sh\nsed -n 's/^{\"\\([a-z]*\\)\".*/\\1/p' \"$1\"\n",
        );
        // The bytes it was given, counted: the same for any key order.
        let length = script(root, "length", "#!/bin/sh\nwc -c < \"$1\"\n");
        let reorder = [MetamorphicTransform::ReorderJsonKeys];

        let work = root.join("work-dependent");
        assert_eq!(
            run_inner(metamorphic_args(&inputs, &work, &first_key, &reorder)).unwrap(),
            1
        );
        let found = metamorphic_findings(&work);
        assert_eq!(found.len(), 1, "only the JSON input has a variant");
        let (record, transformed) = &found[0];
        assert_eq!(record["metamorphic"]["transform"], "reorder-json-keys");
        assert_eq!(record["metamorphic"]["relation"], "same-output");
        assert_eq!(record["metamorphic"]["original_stdout_preview"], "user\n");
        assert_eq!(
            record["metamorphic"]["transformed_stdout_preview"],
            "role\n"
        );
        assert_eq!(
            transformed.as_slice(),
            b"{\"role\": [\"admin\", {\"y\": 2, \"x\": 1}], \"user\": \"ada\"}\n"
        );
        assert_eq!(record["rule_id"], "BHF-307");

        let work = root.join("work-independent");
        assert_eq!(
            run_inner(metamorphic_args(&inputs, &work, &length, &reorder)).unwrap(),
            0
        );
        assert!(metamorphic_findings(&work).is_empty());
    }

    /// A parser that refuses a byte order mark breaks the relation
    /// `utf8-bom` keeps (the same exit status); one that accepts it and
    /// echoes it does not, though its output differs.
    #[test]
    #[cfg(unix)]
    fn utf8_bom_detects_bom_sensitive_parser() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let inputs = root.join("inputs");
        fs::create_dir_all(&inputs).unwrap();
        fs::write(inputs.join("doc.json"), b"{\"k\": 1}").unwrap();
        let sensitive = script(
            root,
            "sensitive",
            "#!/bin/sh\n[ \"$(head -c 3 \"$1\")\" = \"$(printf '\\357\\273\\277')\" ] && \
             { echo 'unexpected byte 0xEF' >&2; exit 2; }\ncat \"$1\"\n",
        );
        let tolerant = script(root, "tolerant", "#!/bin/sh\ncat \"$1\"\n");
        let bom = [MetamorphicTransform::Utf8Bom];

        let work = root.join("work-sensitive");
        assert_eq!(
            run_inner(metamorphic_args(&inputs, &work, &sensitive, &bom)).unwrap(),
            1
        );
        let found = metamorphic_findings(&work);
        assert_eq!(found.len(), 1);
        let (record, transformed) = &found[0];
        assert_eq!(record["metamorphic"]["transform"], "utf8-bom");
        assert_eq!(record["metamorphic"]["relation"], "same-exit");
        assert_eq!(record["metamorphic"]["original_exit"], 0);
        assert_eq!(record["metamorphic"]["transformed_exit"], 2);
        assert_eq!(
            record["exception"]["message"],
            "exit codes differ after metamorphic transform"
        );
        assert_eq!(transformed.as_slice(), b"\xEF\xBB\xBF{\"k\": 1}");
        let evidence = record["oracle"]["evidence"].to_string();
        assert!(evidence.contains("same-exit"), "{evidence}");

        let work = root.join("work-tolerant");
        assert_eq!(
            run_inner(metamorphic_args(&inputs, &work, &tolerant, &bom)).unwrap(),
            0,
            "an echoed BOM keeps the exit status"
        );
        assert!(metamorphic_findings(&work).is_empty());
    }

    /// Several `--metamorphic-transform` values, comma-separated or the flag
    /// repeated, are each applied to every input, each checked against its
    /// own relation, and named in the findings they make.
    #[test]
    #[cfg(unix)]
    fn multiple_values_per_transform_are_applied() {
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            args: DifferentialArgs,
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let inputs = root.join("inputs");
        fs::create_dir_all(&inputs).unwrap();
        fs::write(inputs.join("one.txt"), b"alpha\nbeta").unwrap();
        fs::write(inputs.join("two.txt"), b"gamma\n").unwrap();
        let echo = script(root, "echo", "#!/bin/sh\ncat \"$1\"\n");
        let work = root.join("work");
        let cli = Cli::try_parse_from([
            "differential".as_ref(),
            "--harness".as_ref(),
            echo.as_os_str(),
            "--metamorphic-transform".as_ref(),
            "append-newline,utf8-bom".as_ref(),
            "--metamorphic-transform".as_ref(),
            "trailing-whitespace".as_ref(),
            "--metamorphic-transform".as_ref(),
            "append-newline".as_ref(),
            "--inputs".as_ref(),
            inputs.as_os_str(),
            "--work-dir".as_ref(),
            work.as_os_str(),
        ])
        .unwrap();
        assert_eq!(
            cli.args.metamorphic_transforms,
            [
                MetamorphicTransform::AppendNewline,
                MetamorphicTransform::Utf8Bom,
                MetamorphicTransform::TrailingWhitespace,
                MetamorphicTransform::AppendNewline,
            ]
        );

        assert_eq!(run_inner(cli.args).unwrap(), 1);
        // Two inputs, three transforms (the repeat runs once): six variants.
        let mut variants: Vec<String> = fs::read_dir(work.join("differential/metamorphic_inputs"))
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        variants.sort();
        assert_eq!(
            variants,
            [
                "0000-append-newline.bin",
                "0000-trailing-whitespace.bin",
                "0000-utf8-bom.bin",
                "0001-append-newline.bin",
                "0001-trailing-whitespace.bin",
                "0001-utf8-bom.bin",
            ]
        );
        // The echo changes its output for both same-output transforms of
        // both inputs, and keeps its exit status under the BOM.
        let mut made: Vec<(String, Vec<u8>)> = metamorphic_findings(&work)
            .into_iter()
            .map(|(record, transformed)| {
                (
                    record["metamorphic"]["transform"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                    transformed,
                )
            })
            .collect();
        made.sort();
        assert_eq!(
            made,
            [
                ("append-newline".to_owned(), b"alpha\nbeta\n".to_vec()),
                ("append-newline".to_owned(), b"gamma\n\n".to_vec()),
                (
                    "trailing-whitespace".to_owned(),
                    b"alpha \t\nbeta \t".to_vec()
                ),
                ("trailing-whitespace".to_owned(), b"gamma \t\n".to_vec()),
            ]
        );
    }
}
