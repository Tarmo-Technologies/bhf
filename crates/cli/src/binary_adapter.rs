// SPDX-License-Identifier: Apache-2.0

//! `bhf binary adapter`: the functions, call edges, strings and xrefs of a
//! binary, from an external analyzer run as a subprocess (Rizin; the Ghidra and angr adapters find their tool but run no
//! analysis yet) or
//! from a mock fixture, written as
//! `binary-adapter-report.json`.
//!
//! Each analyzer runs a fixed command or a bundled script under a wall-clock
//! timeout and an output cap, and what it prints is mapped into the report's
//! four arrays, each capped. Addresses are the binary's link-time virtual
//! addresses (a PIE's are offsets from 0), whatever base the tool loaded it
//! at.

mod rizin;

use config::Profile;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const ADAPTER_SCHEMA_VERSION: &str = "bhf.binary.adapter.v1";
/// The report an adapter writes into its `--out` dir.
pub(crate) const REPORT_FILE: &str = "binary-adapter-report.json";

#[derive(Debug, clap::Args)]
pub struct BinaryAdapterArgs {
    /// Binary artifact to analyze.
    pub target: PathBuf,

    /// Adapter kind to run.
    #[arg(long, value_enum)]
    pub adapter: AdapterKind,

    /// Output directory for binary-adapter-report.json.
    #[arg(long)]
    pub out: PathBuf,

    /// Mock adapter JSON output for deterministic contract tests.
    #[arg(long)]
    pub mock_output: Option<PathBuf>,

    /// Local adapter executable (`rizin`, `analyzeHeadless`, or the Python
    /// that imports angr). A missing tool is reported as skipped (exit 1).
    #[arg(long)]
    pub tool: Option<PathBuf>,

    /// Wall-clock limit of the analysis, in seconds.
    #[arg(long, default_value_t = 900)]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AdapterKind {
    Mock,
    Rizin,
    Ghidra,
    Angr,
}

impl AdapterKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Rizin => "rizin",
            Self::Ghidra => "ghidra",
            Self::Angr => "angr",
        }
    }

    fn default_tool(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Rizin => "rizin",
            Self::Ghidra => "analyzeHeadless",
            Self::Angr => "python3",
        }
    }

    fn is_external(self) -> bool {
        !matches!(self, Self::Mock)
    }
}

pub fn run(args: BinaryAdapterArgs, profile: Profile) -> i32 {
    if !adapter_allowed(profile, args.adapter) {
        bhfeprintln!(
            "binary adapter '{}' is not allowed for profile '{}'",
            args.adapter.as_str(),
            profile.as_str()
        );
        return 2;
    }

    let result = match args.adapter {
        AdapterKind::Mock => run_mock(&args),
        AdapterKind::Rizin | AdapterKind::Ghidra | AdapterKind::Angr => run_real_adapter(&args),
    };
    match result {
        Ok(exit_code) => exit_code,
        Err(error) => {
            bhfeprintln!("{error}");
            1
        }
    }
}

fn adapter_allowed(profile: Profile, adapter: AdapterKind) -> bool {
    if !adapter.is_external() {
        return true;
    }
    let allowed = profile.allowed_subprocesses();
    allowed.contains(&"*") || allowed.contains(&adapter.as_str())
}

fn run_mock(args: &BinaryAdapterArgs) -> Result<i32, String> {
    let Some(mock_output) = args.mock_output.as_deref() else {
        return Err("--mock-output is required for the mock adapter".to_owned());
    };
    let value: Value = serde_json::from_slice(
        &fs::read(mock_output)
            .map_err(|error| format!("read {}: {error}", mock_output.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", mock_output.display()))?;
    let status = value.get("status").and_then(Value::as_str).unwrap_or("ok");
    let report = if status == "error" {
        base_report(args, "error", "mock_fixture")
            .with_arrays(&value)
            .with_error(
                "adapter_error",
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("mock adapter error"),
            )
            .finish()
    } else {
        base_report(args, "ok", "mock_fixture")
            .with_arrays(&value)
            .finish()
    };
    write_report(&args.out, &report)?;
    Ok(if status == "error" { 1 } else { 0 })
}

/// How long finding a tool and its version may take: angr's import takes
/// seconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

/// A tool that was found, and its version.
struct FoundTool {
    path: PathBuf,
    version: String,
}

/// Why a tool was not found or did not answer its probe.
enum ProbeFailure {
    /// No tool at the path, or on `PATH`; `skipped`, exit 1.
    NotFound(String),
    /// The tool ran and failed: `error`, exit 1.
    Failed(String),
}

/// Find the adapter's tool and its version, without analyzing anything.
/// `rizin -v` prints its version (`rizin --version` opens a file named
/// `--version` and waits in the shell); `analyzeHeadless` has no version
/// option; for angr the tool is a Python that must import angr.
fn probe_tool(kind: AdapterKind, tool: &Path) -> Result<FoundTool, ProbeFailure> {
    let Ok(path) = which::which(tool) else {
        return Err(ProbeFailure::NotFound(format!(
            "{} was not found",
            tool.display()
        )));
    };
    if kind == AdapterKind::Ghidra {
        return Ok(FoundTool {
            version: String::new(),
            path,
        });
    }
    let mut probe = Command::new(&path);
    probe.stdin(Stdio::null());
    match kind {
        AdapterKind::Angr => probe.args(["-c", "import angr; print(angr.__version__)"]),
        _ => probe.arg("-v"),
    };
    let output = crate::command_output::output_with_timeout(&mut probe, PROBE_TIMEOUT)
        .map_err(|error| ProbeFailure::Failed(format!("run {}: {error}", path.display())))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if kind == AdapterKind::Angr {
            ProbeFailure::NotFound(format!("{} cannot import angr: {stderr}", path.display()))
        } else {
            ProbeFailure::Failed(stderr)
        });
    }
    let version = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    Ok(FoundTool { path, version })
}

/// Run the analysis of the target and write its report:
/// `ok` and exit 0 with the analysis, `error` and exit 1 when the analysis
/// failed, `skipped` and exit 1 when the tool (or angr) is not there.
fn run_real_adapter(args: &BinaryAdapterArgs) -> Result<i32, String> {
    let kind = args.adapter;
    let tool = args
        .tool
        .clone()
        .unwrap_or_else(|| PathBuf::from(kind.default_tool()));
    let found = match probe_tool(kind, &tool) {
        Ok(found) => found,
        Err(ProbeFailure::NotFound(message)) => {
            let mut report = base_report(args, "skipped", "external_subprocess")
                .with_error("tool_not_found", &message)
                .finish();
            report["tool"] = json!({ "path": tool.to_string_lossy() });
            write_report(&args.out, &report)?;
            bhfeprintln!("binary adapter '{}': {message}", kind.as_str());
            return Ok(1);
        }
        Err(ProbeFailure::Failed(message)) => {
            let mut report = base_report(args, "error", "external_subprocess")
                .with_error("tool_error", &message)
                .finish();
            report["tool"] = json!({ "path": tool.to_string_lossy() });
            write_report(&args.out, &report)?;
            bhfeprintln!(
                "binary adapter '{}': {} failed: {message}",
                kind.as_str(),
                tool.display()
            );
            return Ok(1);
        }
    };
    let tool_info = json!({
        "path": found.path.to_string_lossy(),
        "version": found.version
    });
    if matches!(kind, AdapterKind::Ghidra | AdapterKind::Angr) {
        return not_implemented(args, tool_info);
    }
    let target = std::path::absolute(&args.target)
        .map_err(|error| format!("resolve {}: {error}", args.target.display()))?;
    let analyzed = if target.is_file() {
        let timeout = Duration::from_secs(args.timeout_secs.max(1));
        match kind {
            AdapterKind::Rizin => rizin::analyze(&found.path, &target, timeout),
            AdapterKind::Ghidra | AdapterKind::Angr | AdapterKind::Mock => {
                unreachable!("no analysis runs")
            }
        }
    } else {
        Err(AdapterError::new(
            "target_not_found",
            format!("{} is not a file", target.display()),
        ))
    };
    let report_path = args.out.join(REPORT_FILE);
    match analyzed {
        Ok(analysis) => {
            let summary = analysis.summary();
            let mut report = base_report(args, "ok", "external_subprocess")
                .with_analysis(analysis)
                .finish();
            report["tool"] = tool_info;
            write_report(&args.out, &report)?;
            bhfeprintln!(
                "binary adapter '{}': {summary} (report: {})",
                kind.as_str(),
                report_path.display()
            );
            Ok(0)
        }
        Err(error) => {
            let mut report = base_report(args, "error", "external_subprocess")
                .with_error(error.reason, &error.message)
                .finish();
            report["tool"] = tool_info;
            write_report(&args.out, &report)?;
            bhfeprintln!(
                "binary adapter '{}': {} (report: {})",
                kind.as_str(),
                error.message,
                report_path.display()
            );
            Ok(1)
        }
    }
}

/// The exit code of an adapter whose analysis bhf does not run yet.
const NOT_IMPLEMENTED_EXIT: i32 = 3;

/// An adapter whose analysis bhf does not run yet: its tool was found, and
/// the report says no analysis ran (`status: not_implemented`, exit 3).
fn not_implemented(args: &BinaryAdapterArgs, tool_info: Value) -> Result<i32, String> {
    let mut report = base_report(args, "not_implemented", "external_subprocess")
        .with_error(
            "not_implemented",
            &format!(
                "bhf runs no {} analysis yet: the tool was found, but no functions, call \
                 graph, strings or xrefs are extracted from the binary",
                args.adapter.as_str()
            ),
        )
        .finish();
    report["tool"] = tool_info;
    write_report(&args.out, &report)?;
    bhfeprintln!(
        "binary adapter '{}': not implemented; bhf ran no analysis (report: {})",
        args.adapter.as_str(),
        args.out.join(REPORT_FILE).display()
    );
    Ok(NOT_IMPLEMENTED_EXIT)
}

/// The most entries each report array keeps; `truncated` in the report names
/// an array that was cut there.
const MAX_FUNCTIONS: usize = 50_000;
const MAX_CALL_EDGES: usize = 200_000;
const MAX_STRINGS: usize = 50_000;
const MAX_XREFS: usize = 200_000;
/// The longest string value kept, in characters.
const MAX_STRING_CHARS: usize = 1024;
/// The most bytes of an analyzer's output (or export file) read.
const MAX_OUTPUT_BYTES: usize = 128 * crate::resource_limits::MIB;

/// String sections that hold symbol names, not program data.
const SYMBOL_STRING_SECTIONS: &[&str] = &[".dynstr", ".strtab", ".shstrtab"];

/// Why an analysis produced no arrays.
#[derive(Debug)]
struct AdapterError {
    /// `timeout`, `tool_error`, `output_too_large`, `bad_output`, ...
    reason: &'static str,
    message: String,
}

impl AdapterError {
    fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

/// What an analyzer found, in the report's shapes.
#[derive(Debug, Default)]
struct Analysis {
    functions: Vec<Value>,
    call_graph: Vec<Value>,
    strings: Vec<Value>,
    xrefs: Vec<Value>,
    calls_seen: HashSet<(String, String)>,
}

impl Analysis {
    /// A function named `name` at `address`; `imported` marks an import
    /// stub (a PLT thunk, an extern).
    fn function(
        &mut self,
        name: &str,
        address: u64,
        size: Option<u64>,
        signature: Option<&str>,
        imported: bool,
    ) {
        self.functions.push(json!({
            "name": name,
            "address": hex(address),
            "size": size,
            "signature": signature,
            "imported": imported
        }));
    }

    /// A call from `caller` to `callee`, each by name, once.
    fn call(&mut self, caller: &str, callee: &str) {
        if self
            .calls_seen
            .insert((caller.to_owned(), callee.to_owned()))
        {
            self.call_graph
                .push(json!({ "caller": caller, "callee": callee }));
        }
    }

    /// A string at `address` in `section`; empty ones and those in symbol
    /// tables are left out, long ones cut.
    fn string(&mut self, address: u64, value: &str, section: Option<&str>) {
        if value.is_empty() || section.is_some_and(|name| SYMBOL_STRING_SECTIONS.contains(&name)) {
            return;
        }
        let value: String = value.chars().take(MAX_STRING_CHARS).collect();
        self.strings.push(json!({
            "address": hex(address),
            "value": value,
            "section": section
        }));
    }

    /// A reference from `from` to `to`: `call`, `code` (a jump), `data` or
    /// `string`.
    fn xref(&mut self, from: u64, to: u64, kind: &str) {
        self.xrefs.push(json!({
            "from": hex(from),
            "to": hex(to),
            "kind": kind
        }));
    }

    fn summary(&self) -> String {
        format!(
            "{} functions, {} call edges, {} strings, {} xrefs",
            self.functions.len().min(MAX_FUNCTIONS),
            self.call_graph.len().min(MAX_CALL_EDGES),
            self.strings.len().min(MAX_STRINGS),
            self.xrefs.len().min(MAX_XREFS)
        )
    }
}

fn hex(address: u64) -> String {
    format!("{address:#x}")
}

/// An integer field of a tool's JSON: a number, or a `0x` hex string.
fn int_at(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => {
            let text = text.trim();
            match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                Some(digits) => u64::from_str_radix(digits, 16).ok(),
                None => text.parse().ok(),
            }
        }
        _ => None,
    }
}

/// Run an analyzer, bounded by `timeout` and [`MAX_OUTPUT_BYTES`]; its
/// stdout, or why it failed.
fn run_analyzer(command: &mut Command, timeout: Duration) -> Result<String, AdapterError> {
    command.stdin(Stdio::null());
    let captured = crate::command_output::capture_with_timeout(command, timeout, MAX_OUTPUT_BYTES)
        .map_err(|error| AdapterError::new("tool_error", format!("run the analyzer: {error}")))?;
    if captured.timed_out {
        return Err(AdapterError::new(
            "timeout",
            format!(
                "the analysis did not finish within {}s (--timeout-secs)",
                timeout.as_secs()
            ),
        ));
    }
    if captured.stdout_truncated {
        return Err(AdapterError::new(
            "output_too_large",
            format!(
                "the analyzer printed more than {} MiB",
                MAX_OUTPUT_BYTES / crate::resource_limits::MIB
            ),
        ));
    }
    let output = captured.output;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        return Err(AdapterError::new(
            "tool_error",
            format!(
                "the analyzer exited with {}: {}",
                output.status,
                tail.join("\n")
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

struct ReportBuilder {
    value: Value,
}

fn base_report(args: &BinaryAdapterArgs, status: &str, trust_boundary: &str) -> ReportBuilder {
    ReportBuilder {
        value: json!({
            "schema_version": ADAPTER_SCHEMA_VERSION,
            "target": args.target.to_string_lossy(),
            "status": status,
            "evidence_kind": "adapter_derived",
            "adapter": {
                "kind": args.adapter.as_str(),
                "trust_boundary": trust_boundary,
                "linked_into_bhf": false
            },
            "functions": [],
            "call_graph": [],
            "strings": [],
            "xrefs": [],
            "truncated": [],
            "errors": []
        }),
    }
}

impl ReportBuilder {
    fn with_arrays(mut self, value: &Value) -> Self {
        for key in ["functions", "call_graph", "strings", "xrefs"] {
            if let Some(items) = value.get(key).and_then(Value::as_array) {
                self.value[key] = Value::Array(items.clone());
            }
        }
        self
    }

    /// The analysis's arrays, each cut at its cap; `truncated` names each
    /// array that was cut and how many entries it kept.
    fn with_analysis(mut self, analysis: Analysis) -> Self {
        let mut truncated = Vec::new();
        for (key, mut items, cap) in [
            ("functions", analysis.functions, MAX_FUNCTIONS),
            ("call_graph", analysis.call_graph, MAX_CALL_EDGES),
            ("strings", analysis.strings, MAX_STRINGS),
            ("xrefs", analysis.xrefs, MAX_XREFS),
        ] {
            if items.len() > cap {
                items.truncate(cap);
                truncated.push(json!({ "array": key, "kept": cap }));
            }
            self.value[key] = Value::Array(items);
        }
        self.value["truncated"] = Value::Array(truncated);
        self
    }

    fn with_error(mut self, reason: &str, message: &str) -> Self {
        self.value["errors"] = json!([{
            "reason": reason,
            "message": message
        }]);
        self
    }

    fn finish(self) -> Value {
        self.value
    }
}

fn write_report(out_dir: &Path, report: &Value) -> Result<(), String> {
    fs::create_dir_all(out_dir)
        .map_err(|error| format!("create {}: {error}", out_dir.display()))?;
    let path = out_dir.join(REPORT_FILE);
    fs::write(
        &path,
        serde_json::to_vec_pretty(report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> BinaryAdapterArgs {
        BinaryAdapterArgs {
            target: PathBuf::from("legacy"),
            adapter: AdapterKind::Rizin,
            out: PathBuf::from("out"),
            mock_output: None,
            tool: None,
            timeout_secs: 900,
        }
    }

    /// Each array is cut at its cap, and the report says which.
    #[test]
    fn an_array_past_its_cap_is_cut_and_named() {
        let mut analysis = Analysis::default();
        for address in 0..(MAX_STRINGS as u64 + 5) {
            analysis.string(address, "s", Some(".rodata"));
        }
        analysis.function("main", 0x1000, Some(4), None, false);
        let report = base_report(&args(), "ok", "external_subprocess")
            .with_analysis(analysis)
            .finish();
        assert_eq!(report["strings"].as_array().unwrap().len(), MAX_STRINGS);
        assert_eq!(report["functions"].as_array().unwrap().len(), 1);
        assert_eq!(
            report["truncated"],
            json!([{ "array": "strings", "kept": MAX_STRINGS }])
        );
    }

    /// Symbol-table strings, empty strings and repeated call edges are left
    /// out; a long string is cut.
    #[test]
    fn strings_and_calls_are_filtered_as_they_are_added() {
        let mut analysis = Analysis::default();
        analysis.string(0x499, "puts", Some(".dynstr"));
        analysis.string(0x2000, "", Some(".rodata"));
        analysis.string(0x2004, &"x".repeat(MAX_STRING_CHARS + 10), Some(".rodata"));
        analysis.call("main", "handle");
        analysis.call("main", "handle");
        assert_eq!(analysis.strings.len(), 1);
        assert_eq!(
            analysis.strings[0]["value"].as_str().unwrap().len(),
            MAX_STRING_CHARS
        );
        assert_eq!(analysis.strings[0]["address"], "0x2004");
        assert_eq!(analysis.call_graph.len(), 1);
    }

    #[test]
    fn integers_are_read_from_numbers_and_hex_strings() {
        let value = json!({ "a": 4198400, "b": "0x401000", "c": "17", "d": null });
        assert_eq!(int_at(&value, "a"), Some(0x401000));
        assert_eq!(int_at(&value, "b"), Some(0x401000));
        assert_eq!(int_at(&value, "c"), Some(17));
        assert_eq!(int_at(&value, "d"), None);
    }
}
