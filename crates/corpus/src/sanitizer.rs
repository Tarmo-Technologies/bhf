// SPDX-License-Identifier: Apache-2.0
//
// Parse AddressSanitizer / UndefinedBehaviorSanitizer / LeakSanitizer crash
// reports out of a harness's stderr and map them to BHF rule ids.
//
// Used by the C/C++ fuzz path: when the libFuzzer harness exits non-zero,
// `parse_sanitizer_report` examines stderr, picks the most specific match
// from the existing rule catalog (BHF-201..BHF-208), and returns the top-5
// frames so the caller can attach them to the finding.

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SanitizerReport {
    /// The sanitizer that produced this report, or `None` when the crash was
    /// observed WITHOUT a sanitizer (a host fatal signal, or an on-target /
    /// transport CPU fault). An absent sanitizer is never serialized as a false
    /// `asan` tag — the provenance states only what actually occurred.
    pub sanitizer: Option<Sanitizer>,
    /// Short crash class string (e.g. `heap-buffer-overflow`,
    /// `signed-integer-overflow`).
    pub kind: String,
    pub rule_id: &'static str,
    /// The crash stack the sanitizer printed, in order (at most
    /// [`MAX_SANITIZER_FRAMES`]). For ASan this is only the stack of the
    /// faulting access: the allocation and free stacks are in
    /// [`SanitizerReport::access`]. Each frame is a `function` plus optional
    /// `file`:`line` from the sanitizer output - file/line are present when the
    /// binary was built with debug info (`-g`) so the SARIF emitter can attach a
    /// real `physicalLocation`.
    pub stack: Vec<StackFrame>,
    /// First line of the sanitizer error, useful as a `message`.
    pub message: String,
    /// The source position the sanitizer localized the report to: UBSan's
    /// `file:line:col: runtime error:` prefix, or the location on an ASan
    /// `SUMMARY:` line. `None` when the report names none.
    pub location: Option<SourceLocation>,
    /// The sanitizer's machine-readable check name, when it printed one: UBSan's
    /// `SUMMARY: UndefinedBehaviorSanitizer: <check>` under
    /// `report_error_type=1` (e.g. `missing-return`, `invalid-shift-exponent`).
    pub check: Option<String>,
    /// The memory access an ASan report describes: direction, size, the region
    /// it hit, and the allocation and free stacks. Boxed: most reports carry
    /// none, and the report travels inside every harness-run result.
    pub access: Option<Box<MemoryAccess>>,
}

/// A `file:line[:col]` source position.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub column: Option<u32>,
}

impl SourceLocation {
    /// `<dir>/<basename>:<line>[:<col>]`: the site identity used in finding
    /// signatures and cluster keys. The path is cut to its last two components
    /// ([`site_path`]): enough to tell `a/util.c` from `b/util.c`, while the
    /// identity does not depend on where the source tree was checked out or on
    /// whether the compiler was given a relative or an absolute path.
    pub fn site(&self) -> String {
        self.site_at(&site_path(&self.file))
    }

    fn site_at(&self, path: &str) -> String {
        match self.column {
            Some(column) => format!("{path}:{}:{column}", self.line),
            None => format!("{path}:{}", self.line),
        }
    }
}

/// The last two components of `file` (`src/a/util.c` -> `a/util.c`), with
/// `\\` read as `/`, and `.` and `dir/..` resolved first.
pub fn site_path(file: &str) -> String {
    let normalized = file.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let tail = &parts[parts.len().saturating_sub(2)..];
    tail.join("/")
}

impl SanitizerReport {
    /// The site identity of the reported location ([`SourceLocation::site`]).
    /// A bare file name, which the compiler prints when it ran in the file's
    /// own directory, takes that directory from the top crash frame when the
    /// frame names the same file, so it reads as it would with a longer path.
    pub fn site(&self) -> Option<String> {
        let location = self.location.as_ref()?;
        let path = site_path(&location.file);
        if path.contains('/') {
            return Some(location.site_at(&path));
        }
        let from_frame = self
            .stack
            .first()
            .and_then(|frame| frame.file.as_deref())
            .map(site_path)
            .filter(|frame_path| frame_path.rsplit('/').next() == Some(path.as_str()));
        Some(location.site_at(from_frame.as_deref().unwrap_or(&path)))
    }
}

/// The direction of a faulting memory access, read as a token from the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessDirection {
    Read,
    Write,
    /// No direction was reported, or the report said `UNKNOWN`.
    #[default]
    Unknown,
}

impl AccessDirection {
    fn from_token(token: &str) -> Self {
        match token {
            "READ" => Self::Read,
            "WRITE" => Self::Write,
            _ => Self::Unknown,
        }
    }
}

/// The memory access an ASan report describes. Serialized as
/// `exception.access` in `finding.json`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct MemoryAccess {
    /// `READ of size N` / `The signal is caused by a READ memory access.`
    pub direction: AccessDirection,
    /// Access width in bytes, when the report states it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size: Option<u64>,
    /// The faulting address as printed (`on address 0x...` /
    /// `SEGV on unknown address 0x...`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub address: Option<String>,
    /// ASan's `Hint:` about the address: `zero-page` or `high-value-address`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub address_hint: Option<String>,
    /// The object the access hit (`is located N bytes after M-byte region`, a
    /// stack variable, or a global).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub region: Option<MemoryRegion>,
    /// Where the region was allocated (`allocated by thread T0 here:`), or for a
    /// stack object the frame that holds it.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alloc_stack: Vec<StackFrame>,
    /// Where the region was freed (`freed by thread T0 here:`).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub free_stack: Vec<StackFrame>,
}

/// The object a faulting access hit, from ASan's address description.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct MemoryRegion {
    /// `heap`, `stack` or `global`.
    pub kind: String,
    /// The object's size in bytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size: Option<u64>,
    /// Byte offset of the access from the start of the object; negative before
    /// it, `>= size` past its end.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<i64>,
    /// `after`, `before` or `inside` the object.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub relation: Option<String>,
    /// Bytes from the object's edge named by `relation` (from its start for
    /// `inside`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub distance: Option<u64>,
    /// The stack or global variable's name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub variable: Option<String>,
    /// For a stack object, the access offset within its frame.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub frame_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StackFrame {
    pub function: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sanitizer {
    AddressSanitizer,
    UndefinedBehaviorSanitizer,
    LeakSanitizer,
}

impl Sanitizer {
    pub fn as_str(self) -> &'static str {
        match self {
            Sanitizer::AddressSanitizer => "asan",
            Sanitizer::UndefinedBehaviorSanitizer => "ubsan",
            Sanitizer::LeakSanitizer => "lsan",
        }
    }
}

pub fn parse_sanitizer_report(stderr: &str) -> Option<SanitizerReport> {
    parse_asan(stderr)
        .or_else(|| parse_ubsan(stderr))
        .or_else(|| parse_lsan(stderr))
        // A Rust panic is the PRIMARY bug signal for the native Rust lane: a
        // bounds-check / unwrap / overflow / explicit panic aborts via SIGABRT,
        // which the C-oriented `is_input_rejection` would otherwise dismiss as an
        // assert/abort "rejection". Recognising the panic message here turns it
        // into a finding (like cargo-fuzz/Jazzer treat a panic). Only fires when
        // stderr actually contains a Rust panic, so the C/Ada lanes are unaffected.
        .or_else(|| parse_rust_panic(stderr))
        // A JVM finding is the PRIMARY bug signal for the native Java lane: the
        // bhf JVM driver prints a marker + the Java stack trace and hard-halts
        // with a non-zero EXIT (not a fatal signal), which the signal-oriented
        // `is_input_rejection` would otherwise dismiss. Recognising the marker here
        // turns an uncaught exception/Error into a finding (like Jazzer). Only
        // fires on the bhf marker, so the other lanes are unaffected.
        .or_else(|| parse_jvm_finding(stderr))
        // A Python finding is the PRIMARY bug signal for the native Python lane: the
        // bhf CPython driver prints `== bhf python finding: <Type>: <msg>` +
        // a traceback and hard-halts with a non-zero EXIT (not a fatal signal).
        // Recognising the marker here maps the exception type to a BHF rule + CWE.
        // Only fires on the bhf marker, so the other lanes are unaffected.
        .or_else(|| parse_python_finding(stderr))
        // A Perl finding: the bhf Perl driver prints `== bhf perl finding:
        // <CWE>: <die message>` and hard-halts. The CWE token (computed driver-side
        // from the die message) selects the BHF rule.
        .or_else(|| parse_perl_finding(stderr))
        // A Ruby finding: the bhf Ruby driver prints `== bhf ruby finding:
        // <CWE>: <class>: <message>` and hard-halts. The CWE token (computed
        // driver-side from the exception class) selects the BHF rule.
        .or_else(|| parse_ruby_finding(stderr))
        // A Lua finding: the bhf Lua driver prints `== bhf lua finding:
        // <CWE>: <error>` and hard-halts. The CWE token (computed driver-side from the
        // Lua error message) selects the BHF rule.
        .or_else(|| parse_lua_finding(stderr))
        // A PHP finding: the bhf PHP driver prints `== bhf php finding:
        // <CWE>: <error>` and hard-halts. The CWE token selects the BHF rule.
        .or_else(|| parse_php_finding(stderr))
        // A Go finding: the bhf Go harness recovers a panic and prints
        // `== bhf go finding: <msg>` (or the runtime prints `panic:`/`fatal
        // error:` for an unrecoverable crash). The message selects the BHF rule.
        .or_else(|| parse_go_panic(stderr))
        // A C# finding: the bhf .NET driver prints `== bhf csharp finding:
        // <exception type>: <msg>` and hard-halts (exit 86). The exception type
        // selects the BHF rule + CWE, mirroring the JVM lane.
        .or_else(|| parse_csharp_finding(stderr))
        // A JS finding: the bhf Node driver prints `== bhf js finding:
        // <BHF-rule>: <error name>: <msg>` and hard-halts (exit 86). The BHF rule is
        // pre-resolved driver-side (the exception class → rule mapping is cleaner in
        // the driver where the Error object is live), so the parser reads it directly.
        .or_else(|| parse_js_finding(stderr))
}

/// Parse a bhf JavaScript finding out of stderr. The Node driver prints
/// `== bhf js finding: <BHF-NNN>: <Error name>: <message>` followed by the V8
/// stack (`    at fn (file:line:col)`). The BHF rule token is pre-resolved by the
/// driver (stack-exhaustion RangeError → BHF-207, resource RangeError → BHF-209, a
/// property-of-undefined TypeError → BHF-206, else BHF-210).
fn parse_js_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== bhf js finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    // `after` is `<BHF-NNN>: <rest>`.
    let (rule_tok, rest) = match after.split_once(':') {
        Some((r, m)) => (r.trim(), m.trim()),
        None => (after, ""),
    };
    let rule_id = match rule_tok {
        "BHF-201" => "BHF-201",
        "BHF-205" => "BHF-205",
        "BHF-206" => "BHF-206",
        "BHF-207" => "BHF-207",
        "BHF-209" => "BHF-209",
        // BHF-431: taint-confirmed command injection (CWE-78) from the JS driver's
        // sink guard — the fuzz input controlled shell syntax in a `child_process`
        // command, which the driver detected and refused to run.
        "BHF-431" => "BHF-431",
        // BHF-509: prototype pollution (CWE-1321) — a fuzz input carrying a
        // `__proto__`/`constructor`/`prototype` vector added a new own-property to
        // Object.prototype / Array.prototype (observed by the driver).
        "BHF-509" => "BHF-509",
        _ => "BHF-210",
    };
    let kind = match rule_id {
        "BHF-206" => "js-null-dereference",
        "BHF-207" => "js-stack-overflow",
        "BHF-209" => "js-out-of-memory",
        "BHF-205" => "js-arithmetic",
        "BHF-201" => "js-index-out-of-bounds",
        "BHF-431" => "js-command-injection",
        "BHF-509" => "js-prototype-pollution",
        _ => "js-uncaught-exception",
    }
    .to_owned();

    let mut stack = parse_js_stack_frames(stderr);
    stack.truncate(5);

    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack,
        message: format!("JS finding: {rest}"),
        ..Default::default()
    })
}

/// Parse V8 stack frames: `    at fn (path:line:col)` or `    at path:line:col`.
/// The bhf driver frames are skipped so the top frame is the target's code.
fn parse_js_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for raw in stderr.lines() {
        let t = raw.trim_start();
        let Some(rest) = t.strip_prefix("at ") else {
            continue;
        };
        if rest.contains("bhf_driver") {
            continue;
        }
        // Extract `name (loc)` or bare `loc`.
        let (func, loc) = if let Some(open) = rest.rfind('(') {
            let close = rest.rfind(')').unwrap_or(rest.len());
            (
                rest[..open].trim().to_owned(),
                rest.get(open + 1..close).unwrap_or("").to_owned(),
            )
        } else {
            ("<anonymous>".to_owned(), rest.trim().to_owned())
        };
        // loc = path:line:col — split the trailing :line:col.
        let (file, line) = split_loc(&loc);
        frames.push(StackFrame {
            function: if func.is_empty() {
                "<anonymous>".to_owned()
            } else {
                func
            },
            file,
            line,
        });
    }
    frames
}

/// Split a V8 `path:line:col` location into `(file, line)`.
fn split_loc(loc: &str) -> (Option<String>, Option<u32>) {
    let bytes: Vec<&str> = loc.rsplitn(3, ':').collect();
    // rsplitn yields [col, line, path] reversed.
    if bytes.len() == 3 {
        let line = bytes[1].parse::<u32>().ok();
        let file = bytes[2].to_owned();
        (Some(file), line)
    } else if loc.is_empty() {
        (None, None)
    } else {
        (Some(loc.to_owned()), None)
    }
}

/// Parse a bhf C# finding out of stderr. The .NET driver prints
/// `== bhf csharp finding: <System.ExceptionType>: <message>` followed by the
/// managed stack trace (`   at Ns.Type.Method(...) in File.cs:line N`). The
/// exception type drives the rule id: an index OOB is the CWE-125/787 class
/// (BHF-201); a divide-by-zero / overflow `DivideByZeroException` / `OverflowException`
/// / `ArithmeticException` maps to BHF-205; `OutOfMemoryException` to BHF-209;
/// `StackOverflowException` to the uncontrolled-recursion BHF-207; a
/// `NullReferenceException` to the null-deref BHF-206; everything else — a custom
/// exception, `InvalidOperationException`, an assertion — is a reachable-crash BHF-210.
fn parse_csharp_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== bhf csharp finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (exc, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    // Leaf type name (drop the `System.` / target namespace prefix).
    let leaf = exc.rsplit('.').next().unwrap_or(exc);

    let (kind, rule_id) = if leaf.contains("IndexOutOfRange") || leaf.contains("IndexOutOfBounds") {
        ("csharp-index-out-of-bounds".to_owned(), "BHF-201")
    } else if leaf == "DivideByZeroException"
        || leaf == "OverflowException"
        || leaf == "ArithmeticException"
        || leaf == "NotFiniteNumberException"
    {
        ("csharp-arithmetic".to_owned(), "BHF-205")
    } else if leaf == "OutOfMemoryException" {
        ("csharp-out-of-memory".to_owned(), "BHF-209")
    } else if leaf == "StackOverflowException" || leaf == "InsufficientExecutionStackException" {
        ("csharp-stack-overflow".to_owned(), "BHF-207")
    } else if leaf == "NullReferenceException" {
        ("csharp-null-dereference".to_owned(), "BHF-206")
    } else {
        // InvalidOperationException, custom exceptions, an explicit throw, ...
        ("csharp-uncaught-exception".to_owned(), "BHF-210")
    };

    let mut stack = parse_csharp_stack_frames(stderr);
    stack.truncate(5);

    let message = if msg.is_empty() {
        format!("C# finding: {exc}")
    } else {
        format!("C# finding: {exc}: {msg}")
    };
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack,
        message,
        ..Default::default()
    })
}

/// Parse managed stack frames from a .NET stack trace: `   at Ns.Type.Method(args)`
/// or `   at Ns.Type.Method(args) in /path/File.cs:line 42`. The `bhf`
/// driver/entry frames are skipped so the top frame is the target's own code.
fn parse_csharp_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for raw in stderr.lines() {
        let t = raw.trim_start();
        let Some(rest) = t.strip_prefix("at ") else {
            continue;
        };
        // Skip our own driver / entry shim frames.
        if rest.starts_with("Driver.") || rest.starts_with("Bhfgen.") {
            continue;
        }
        // Function = everything up to the first `(`.
        let func = rest.split('(').next().unwrap_or(rest).trim().to_owned();
        // Optional `in <file>:line N`.
        let (file, line) = if let Some(pos) = rest.find(" in ") {
            let loc = &rest[pos + 4..];
            if let Some(lpos) = loc.rfind(":line ") {
                let file = loc[..lpos].trim().to_owned();
                let line = loc[lpos + 6..].trim().parse::<u32>().ok();
                (Some(file), line)
            } else {
                (Some(loc.trim().to_owned()), None)
            }
        } else {
            (None, None)
        };
        if func.is_empty() {
            continue;
        }
        frames.push(StackFrame {
            function: func,
            file,
            line,
        });
    }
    frames
}

/// Parse a Go panic / fatal runtime error out of stderr. The bhf Go harness
/// recovers and prints `== bhf go finding: <msg>`; an unrecoverable crash leaves
/// the runtime's own `panic: <msg>` / `fatal error: <msg>`. The message drives the
/// rule id: index/slice OOB -> CWE-125 (BHF-201); nil dereference -> CWE-476 (BHF-204
/// — null-pointer class); integer divide-by-zero -> CWE-369 (BHF-205); stack
/// exhaustion -> CWE-674 (BHF-207); out-of-memory -> CWE-789 (BHF-209); everything
/// else (an explicit panic / type assertion / map misuse) -> reachable-crash BHF-210.
fn parse_go_panic(stderr: &str) -> Option<SanitizerReport> {
    let msg = stderr
        .lines()
        .find_map(|l| l.trim().strip_prefix("== bhf go finding:").map(str::trim))
        .or_else(|| {
            stderr
                .lines()
                .find_map(|l| l.trim().strip_prefix("panic:").map(str::trim))
        })
        .or_else(|| {
            stderr
                .lines()
                .find_map(|l| l.trim().strip_prefix("fatal error:").map(str::trim))
        })?;
    let lower = msg.to_ascii_lowercase();
    // An "interface conversion" panic is a failed type assertion. When the bhf
    // Go harness synthesizes an `interface{}` parameter (an unmarshal out-target) as
    // a generic `*interface{}`, a target that type-asserts it to a concrete type
    // panics — our synthesized value's fault, not a target defect (mirrors the
    // untyped lanes' suppression of wrong-type exceptions). Not a finding.
    if lower.contains("interface conversion") {
        return None;
    }
    let (kind, rule_id) = if lower.contains("index out of range")
        || lower.contains("slice bounds out of range")
    {
        ("go-index-out-of-bounds".to_owned(), "BHF-201")
    } else if lower.contains("nil pointer dereference") || lower.contains("invalid memory address")
    {
        ("go-nil-dereference".to_owned(), "BHF-206")
    } else if lower.contains("integer divide by zero") {
        ("go-arithmetic".to_owned(), "BHF-205")
    } else if lower.contains("stack overflow") || lower.contains("goroutine stack exceeds") {
        ("go-stack-overflow".to_owned(), "BHF-207")
    } else if lower.contains("out of memory") || lower.contains("makeslice: len out of range") {
        ("go-out-of-memory".to_owned(), "BHF-209")
    } else {
        ("go-panic".to_owned(), "BHF-210")
    };
    let mut stack = parse_go_stack_frames(stderr);
    stack.truncate(5);
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack,
        message: format!("Go panic: {msg}"),
        ..Default::default()
    })
}

/// Parse Go goroutine-stack frames from `debug.Stack()` output. Each frame is two
/// lines: `pkg/path.Func(args)` then `\t<file>:<line> +0xNN`. Skip the runtime,
/// the bhf harness, and debug.Stack itself so the top frame is the target's
/// own code — that frame drives the cluster key (one row per crash site).
fn parse_go_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let lines: Vec<&str> = stderr.lines().collect();
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 1 < lines.len() {
        let func_line = lines[i].trim_end();
        let loc_line = lines[i + 1];
        // A location line is indented and looks like `\t<file>:<line> +0x...`.
        let loc = loc_line.trim();
        let is_loc = loc_line.starts_with('\t') && loc.contains(':') && loc.contains(".go:");
        let is_func =
            func_line.contains('(') && !func_line.starts_with('\t') && !func_line.is_empty();
        if is_func && is_loc {
            let function = go_frame_function(func_line).to_owned();
            // `<file>:<line> +0xNN`
            let loc_no_off = loc.split(" +").next().unwrap_or(loc);
            let (file, line) = match loc_no_off.rsplit_once(':') {
                Some((f, l)) => (Some(f.to_owned()), l.trim().parse::<u32>().ok()),
                None => (None, None),
            };
            let skip = function.starts_with("runtime")
                || function == "panic"
                || function.starts_with("runtime/debug")
                || function.contains("main.runOne")
                || function == "main.main"
                || function.contains("bhf_harness");
            if !skip {
                frames.push(StackFrame {
                    function,
                    file,
                    line,
                });
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    frames
}

/// The function name in a Go runtime frame `qualified(args)`. A method frame's
/// `qualified` already contains a parenthesized receiver group, e.g.
/// `bhf.example/forcelib/forcelib.(*Decoder).Feed`, so the name is everything
/// before the *trailing* argument list — found by balancing parens from the
/// right. Splitting on the first `(` (the receiver) would truncate the method
/// name away, leaving a dangling `…forcelib.`.
fn go_frame_function(func_line: &str) -> &str {
    let s = func_line.trim();
    let bytes = s.as_bytes();
    if bytes.last() != Some(&b')') {
        return s; // no trailing arg list; take the whole frame
    }
    let mut depth: i32 = 0;
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    // `i` is the arg-list opener; the receiver group (if any)
                    // sits to its left and is kept.
                    return s[..i].trim_end();
                }
            }
            _ => {}
        }
    }
    s // unbalanced parens; fall back to the whole frame
}

/// Parse a bhf Perl finding out of stderr. The driver prints
/// `== bhf perl finding: <CWE-NNN>: <die message>` (the CWE pre-resolved from
/// the message: deep-recursion -> CWE-674/BHF-207, out-of-memory -> CWE-789/BHF-209,
/// division-by-zero -> CWE-369/BHF-205, else an uncaught die -> CWE-248/BHF-210).
fn parse_perl_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== bhf perl finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (cwe, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    let (kind, rule_id) = match cwe {
        "CWE-674" => ("perl-uncontrolled-recursion".to_owned(), "BHF-207"),
        "CWE-789" => ("perl-out-of-memory".to_owned(), "BHF-209"),
        "CWE-369" => ("perl-arithmetic".to_owned(), "BHF-205"),
        _ => ("perl-uncaught-die".to_owned(), "BHF-210"),
    };
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack: Vec::new(),
        message: if msg.is_empty() {
            "Perl finding".to_owned()
        } else {
            format!("Perl finding: {msg}")
        },
        ..Default::default()
    })
}

/// Parse a bhf Ruby finding out of stderr. The driver prints
/// `== bhf ruby finding: <CWE-NNN>: <class>: <message>` (the CWE pre-resolved
/// from the exception class: SystemStackError -> CWE-674/BHF-207, NoMemoryError ->
/// CWE-789/BHF-209, ZeroDivisionError -> CWE-369/BHF-205, an explicit assert/BUG
/// RuntimeError -> CWE-617/BHF-210).
fn parse_ruby_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== bhf ruby finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (cwe, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    let (kind, rule_id) = match cwe {
        "CWE-674" => ("ruby-uncontrolled-recursion".to_owned(), "BHF-207"),
        "CWE-789" => ("ruby-out-of-memory".to_owned(), "BHF-209"),
        "CWE-369" => ("ruby-arithmetic".to_owned(), "BHF-205"),
        _ => ("ruby-reachable-assertion".to_owned(), "BHF-210"),
    };
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack: Vec::new(),
        message: if msg.is_empty() {
            "Ruby finding".to_owned()
        } else {
            format!("Ruby finding: {msg}")
        },
        ..Default::default()
    })
}

/// Parse a bhf Lua finding out of stderr. The driver prints
/// `== bhf lua finding: <CWE-NNN>: <error>` (the CWE pre-resolved from the Lua
/// error message: stack overflow -> CWE-674/BHF-207, out-of-memory -> CWE-789/BHF-209,
/// integer divide-by-zero -> CWE-369/BHF-205, an explicit assert -> CWE-617/BHF-210).
fn parse_lua_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== bhf lua finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (cwe, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    let (kind, rule_id) = match cwe {
        "CWE-674" => ("lua-uncontrolled-recursion".to_owned(), "BHF-207"),
        "CWE-789" => ("lua-out-of-memory".to_owned(), "BHF-209"),
        "CWE-369" => ("lua-arithmetic".to_owned(), "BHF-205"),
        _ => ("lua-reachable-assertion".to_owned(), "BHF-210"),
    };
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack: Vec::new(),
        message: if msg.is_empty() {
            "Lua finding".to_owned()
        } else {
            format!("Lua finding: {msg}")
        },
        ..Default::default()
    })
}

/// Parse a bhf PHP finding out of stderr. The driver prints
/// `== bhf php finding: <CWE-NNN>: <class>: <message>` (the CWE pre-resolved from
/// the Throwable class/message: divide-by-zero -> CWE-369/BHF-205, assertion ->
/// CWE-617/BHF-210, out-of-memory -> CWE-789/BHF-209, deep recursion -> CWE-674/BHF-207).
fn parse_php_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== bhf php finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (cwe, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    let (kind, rule_id) = match cwe {
        "CWE-674" => ("php-uncontrolled-recursion".to_owned(), "BHF-207"),
        "CWE-789" => ("php-out-of-memory".to_owned(), "BHF-209"),
        "CWE-369" => ("php-arithmetic".to_owned(), "BHF-205"),
        _ => ("php-reachable-assertion".to_owned(), "BHF-210"),
    };
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack: Vec::new(),
        message: if msg.is_empty() {
            "PHP finding".to_owned()
        } else {
            format!("PHP finding: {msg}")
        },
        ..Default::default()
    })
}

/// Parse a bhf JVM finding out of stderr. The driver prints
/// `== bhf JVM finding: <exception class>: <message>` followed by the Java
/// stack trace (`\tat pkg.Class.method(File.java:line)`). The exception class
/// drives the rule id: an index/bounds exception is the CWE-125/787 OOB class
/// (BHF-201); an `ArithmeticException` (divide by zero) maps to BHF-205; an
/// `OutOfMemoryError` to BHF-209; everything else — NPE, ClassCast, AssertionError,
/// StackOverflow, … — is a reachable-crash BHF-210.
fn parse_jvm_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== bhf JVM finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    // `after` is `<class>: <message>` or just `<class>`.
    let (class, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    let class_leaf = class.rsplit('.').next().unwrap_or(class);

    // JVM class-loading / bytecode-verification / linkage errors are ENVIRONMENT
    // or INSTRUMENTATION artifacts, not target logic bugs: a coverage-instrumented
    // class whose stack-map frames weren't recomputed throws `ClassFormatError`
    // ("bad offset for Uninitialized" — snakeyaml emitted 15 identical ones), a
    // missing classpath entry throws `NoClassDefFoundError`, a version mismatch
    // `UnsupportedClassVersionError`. Raising a BHF-210 finding for them manufactures
    // phantom crashes that have nothing to do with the code under test, so report
    // no finding (the underlying instrumentation/classpath issue is handled out of
    // band, not as a fuzzing result).
    if matches!(
        class_leaf,
        "ClassFormatError"
            | "VerifyError"
            | "UnsupportedClassVersionError"
            | "NoClassDefFoundError"
            | "ClassNotFoundException"
            | "LinkageError"
            | "BootstrapMethodError"
            | "IncompatibleClassChangeError"
    ) {
        return None;
    }

    let (kind, rule_id) = if class_leaf.contains("IndexOutOfBounds")
        || class_leaf.contains("ArrayIndexOutOfBounds")
        || class_leaf.contains("StringIndexOutOfBounds")
    {
        ("jvm-index-out-of-bounds".to_owned(), "BHF-201")
    } else if class_leaf == "ArithmeticException" {
        ("jvm-arithmetic".to_owned(), "BHF-205")
    } else if class_leaf == "OutOfMemoryError" {
        ("jvm-out-of-memory".to_owned(), "BHF-209")
    } else {
        // NullPointerException, ClassCastException, NegativeArraySizeException,
        // AssertionError, StackOverflowError, an explicit throw, …
        ("jvm-uncaught-throwable".to_owned(), "BHF-210")
    };

    let mut stack = parse_java_stack_frames(stderr);
    stack.truncate(5);

    let message = if msg.is_empty() {
        format!("JVM finding: {class}")
    } else {
        format!("JVM finding: {class}: {msg}")
    };
    Some(SanitizerReport {
        // The crash-channel tag; AddressSanitizer keeps a memory-safety exception
        // (OOB) in the right bucket. `kind`/`rule_id` carry the JVM classification.
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack,
        message,
        ..Default::default()
    })
}

/// Parse a bhf Python finding out of stderr. The CPython driver prints
/// `== bhf python finding: <ExcType>: <message>` followed by the standard
/// traceback (`  File "x.py", line N, in func`). The exception type drives the
/// rule id: `IndexError` is the CWE-125/787 OOB class (BHF-201); a divide-by-zero /
/// overflow `ZeroDivisionError`/`OverflowError`/`FloatingPointError` maps to BHF-205;
/// `MemoryError` to BHF-209; `RecursionError` to the uncontrolled-recursion BHF-207;
/// everything else — KeyError, AttributeError, AssertionError, SystemError, a custom
/// exception — is a reachable-crash BHF-210. CWE flows from the rule catalog.
fn parse_python_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== bhf python finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (exc, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };

    let (kind, rule_id) = match exc {
        "IndexError" => ("python-index-out-of-bounds".to_owned(), "BHF-201"),
        "ZeroDivisionError" | "OverflowError" | "FloatingPointError" => {
            ("python-arithmetic".to_owned(), "BHF-205")
        }
        "MemoryError" => ("python-out-of-memory".to_owned(), "BHF-209"),
        "RecursionError" => ("python-uncontrolled-recursion".to_owned(), "BHF-207"),
        // KeyError, AttributeError, AssertionError, SystemError, custom errors, ...
        _ => ("python-uncaught-exception".to_owned(), "BHF-210"),
    };

    let mut stack = parse_python_stack_frames(stderr);
    stack.truncate(5);

    let message = if msg.is_empty() {
        format!("Python finding: {exc}")
    } else {
        format!("Python finding: {exc}: {msg}")
    };
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack,
        message,
        ..Default::default()
    })
}

/// Parse CPython traceback frames (`  File "x.py", line N, in func`), skipping the
/// bhf driver/harness/coverage frames so the top frame is the target's code.
fn parse_python_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for raw in stderr.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("File \"") else {
            continue;
        };
        let Some(end_quote) = rest.find('"') else {
            continue;
        };
        let file = &rest[..end_quote];
        // `, line N, in func`
        let tail = &rest[end_quote + 1..];
        let line_no = tail
            .split("line ")
            .nth(1)
            .and_then(|s| s.split([',', ' ']).next())
            .and_then(|s| s.trim().parse::<u32>().ok());
        let function = tail
            .split(" in ")
            .nth(1)
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        if file.ends_with("bhf_driver.py")
            || file.ends_with("bhf_cov.py")
            || file.ends_with("harness.py")
        {
            continue;
        }
        frames.push(StackFrame {
            function,
            file: Some(file.to_owned()),
            line: line_no,
        });
    }
    frames
}

/// Parse Java stack frames (`\tat pkg.Class.method(File.java:line)`).
fn parse_java_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for raw in stderr.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("at ") else {
            continue;
        };
        // rest = `pkg.Class.method(File.java:line)` (or `(Native Method)`).
        let Some(paren) = rest.find('(') else {
            continue;
        };
        let function = rest[..paren].trim().to_owned();
        let loc = &rest[paren + 1..];
        let loc = loc.trim_end_matches(')');
        let (file, line_no) = match loc.rsplit_once(':') {
            Some((f, l)) => (Some(f.to_owned()), l.parse::<u32>().ok()),
            None => (None, None),
        };
        // Skip the JDK reflection + bhf driver frames so the top frame is the
        // target's own code.
        if function.starts_with("java.")
            || function.starts_with("jdk.")
            || function.starts_with("com.bhf.")
        {
            continue;
        }
        frames.push(StackFrame {
            function,
            file,
            line: line_no,
        });
    }
    frames
}

/// Parse a Rust panic out of stderr. A panic line looks like
/// `thread '<unnamed>' (12345) panicked at <file>:<line>:<col>:` followed by the
/// panic message on the next line. The message drives the rule id (an OOB index
/// or slice-range panic is the same CWE-125/787 class as an ASan OOB; an
/// arithmetic-overflow panic maps to BHF-205; everything else — `unwrap` on
/// `None`/`Err`, an explicit `panic!`, `assert!` — is a reachable-crash BHF-210).
fn parse_rust_panic(stderr: &str) -> Option<SanitizerReport> {
    let lines: Vec<&str> = stderr.lines().collect();
    let idx = lines
        .iter()
        .position(|l| l.contains("panicked at") && l.contains("thread '"))
        // Also accept a bare `panicked at` (some panic hooks omit the thread).
        .or_else(|| {
            lines
                .iter()
                .position(|l| l.trim_start().starts_with("panicked at"))
        })?;
    let panic_line = lines[idx];
    // The human message is usually the next non-empty line.
    let msg = lines
        .get(idx + 1)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    let lower = msg.to_ascii_lowercase();
    let (kind, rule_id) = if lower.contains("index out of bounds")
        || lower.contains("range end index")
        || lower.contains("range start index")
        || lower.contains("slice index")
        || lower.contains("out of range for slice")
    {
        ("rust-panic-index-out-of-bounds".to_owned(), "BHF-201")
    } else if lower.contains("overflow")
        || lower.contains("divide by zero")
        || lower.contains("remainder with a divisor of zero")
    {
        ("rust-panic-arithmetic".to_owned(), "BHF-205")
    } else {
        // unwrap/expect on None/Err, explicit panic!, assert!, unreachable!, etc.
        ("rust-panic".to_owned(), "BHF-210")
    };

    // Capture the panic site (`<file>:<line>:<col>`) as the top frame so the
    // finding gets a real physicalLocation.
    let site = panic_line.split("panicked at").nth(1).map(str::trim);
    let mut stack = Vec::new();
    if let Some(site) = site {
        let loc = site.trim_end_matches(':');
        let (file, line) = parse_file_line(loc);
        if file.is_some() {
            stack.push(StackFrame {
                function: "<rust panic>".to_owned(),
                file,
                line,
            });
        }
    }
    // Append any backtrace frames the runtime printed.
    stack.extend(parse_stack_frames(stderr));
    stack.truncate(5);

    let message = if msg.is_empty() {
        panic_line.trim().to_owned()
    } else {
        format!("Rust panic: {msg}")
    };
    Some(SanitizerReport {
        // A Rust panic is not literally an ASan finding, but the corpus model's
        // `Sanitizer` enum is the crash-channel tag; AddressSanitizer is the
        // closest existing variant and keeps the finding in the memory-safety
        // bucket. The `kind`/`rule_id` carry the real Rust classification.
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack,
        message,
        ..Default::default()
    })
}

fn parse_asan(stderr: &str) -> Option<SanitizerReport> {
    let needle = "ERROR: AddressSanitizer:";
    let pos = stderr.find(needle)?;
    let rest = &stderr[pos..];
    let line = rest.lines().next()?;
    let after_marker = line[needle.len()..].trim_start();
    // Real ASan double-free output is "attempting double-free on 0x... in thread
    // T0:" (and "attempting free on address which was not malloc()-ed"): strip the
    // leading "attempting " so the kind token is the real class (`double-free` /
    // `free`), not `attempting`. The hyphenated `attempting-double-free` arm below
    // never matched — ASan emits a space, not a hyphen (#37).
    let after_marker = after_marker
        .strip_prefix("attempting ")
        .unwrap_or(after_marker);
    let kind = after_marker.split_whitespace().next()?.to_owned();
    let rule_id = match kind.as_str() {
        "heap-buffer-overflow" => "BHF-201",
        "heap-use-after-free" | "use-after-free" => "BHF-202",
        // Spatial stack errors (a fixed on-stack buffer overrun) — CWE-121.
        "stack-buffer-overflow" | "stack-buffer-underflow" | "dynamic-stack-buffer-overflow" => {
            "BHF-203"
        }
        // Temporal stack errors (a stale/expired stack pointer) are a DISTINCT
        // weakness — CWE-825/562, not the spatial CWE-121 — so route them to their
        // own rule instead of lumping them into BHF-203 (#29).
        "stack-use-after-return" | "stack-use-after-scope" => "BHF-211",
        // "double-free" (was "attempting double-free") and "free on address which
        // was not malloc()-ed" (kind token "free") are both the free-of-invalid-
        // pointer class — CWE-415 (#37).
        "double-free" | "free" => "BHF-204",
        // A SEGV is a NULL dereference (BHF-206) only when it faults in the
        // first page; anything else is a wild pointer (BHF-223). Decided below,
        // once the address and ASan's hint about it are parsed.
        "SEGV" => "BHF-223",
        // Global / static buffers and intra-object are all "OOB writes/reads"
        // at the rule-catalog level - one heuristic, same CWE-787.
        "global-buffer-overflow"
        | "container-overflow"
        | "intra-object-overflow"
        | "negative-size-param" => "BHF-201",
        // Mismatched allocator/deallocator (new/delete vs malloc/free) - same
        // exploitability class as double-free for the rule catalog.
        "alloc-dealloc-mismatch" | "new-delete-type-mismatch" | "bad-free" => "BHF-204",
        _ => "BHF-201",
    };
    // Enrich the message with the access kind — an OOB READ (info disclosure /
    // DoS) vs WRITE (memory corruption / potential RCE) drives severity and is on
    // a SEPARATE line of the report ("READ of size 4 at 0x...", "WRITE of size 8
    // at 0x..."). For a SEGV the direction is instead on the "The signal is caused
    // by a READ/WRITE memory access." line, which carries the `==NN==` PID prefix
    // so it can't be anchored with `starts_with` (#30). Keep just the kind, drop
    // the noisy address.
    let access = rest.lines().take(12).find_map(|l| {
        let t = l.trim_start();
        if t.starts_with("READ of size") || t.starts_with("WRITE of size") {
            return Some(t.split(" at ").next().unwrap_or(t).trim().to_owned());
        }
        if let Some(pos) = l.find("The signal is caused by a ") {
            let word = l[pos + "The signal is caused by a ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("");
            if word == "READ" || word == "WRITE" {
                return Some(format!("{word} memory access"));
            }
        }
        None
    });
    // For a non-canonical address ASan's direction is not one (see
    // `memory_access`); say so next to it.
    let high_value = rest
        .lines()
        .take(12)
        .any(|l| l.contains("Hint:") && l.contains("high value address"));
    let message = match access {
        Some(a) if high_value => format!("{line} ({a}; high value address)"),
        Some(a) => format!("{line} ({a})"),
        None => line.to_owned(),
    };
    let stacks = split_asan_stacks(rest);
    let access = memory_access(rest, line, stacks.alloc, stacks.free);
    let rule_id = if kind == "SEGV" && access.as_deref().is_some_and(faults_in_null_page) {
        "BHF-206"
    } else {
        rule_id
    };
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::AddressSanitizer),
        kind,
        rule_id,
        stack: stacks.crash,
        message,
        location: summary_location(rest, "AddressSanitizer:"),
        check: None,
        access,
    })
}

/// Whether a `runtime error:` line really came from UBSan, as opposed to another
/// runtime that happens to use the same words (a Go panic).
///
/// UBSan localizes every report to a source position, so its line begins
/// `<file>:<line>:<col>: runtime error:`, and it names itself in the trailing
/// `SUMMARY: UndefinedBehaviorSanitizer:`. Either signal is conclusive; a Go
/// panic has neither.
fn is_ubsan_output(line: &str, stderr: &str) -> bool {
    if stderr.contains("UndefinedBehaviorSanitizer") {
        return true;
    }
    let prefix = match line.split("runtime error:").next() {
        Some(prefix) => prefix.trim_end(),
        None => return false,
    };
    // `...:<line>:<col>:` — the last two colon-separated fields before the message
    // are numbers. Checking both avoids matching a bare `foo: runtime error:`.
    let mut fields = prefix.trim_end_matches(':').rsplit(':');
    let column = fields.next().unwrap_or("");
    let line_no = fields.next().unwrap_or("");
    let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    numeric(column) && numeric(line_no)
}

fn parse_ubsan(stderr: &str) -> Option<SanitizerReport> {
    // UBSan prints a single line per error in the form:
    // `<file>:<line>:<col>: runtime error: <message>`
    let line = stderr
        .lines()
        .find(|line| line.contains("runtime error:"))?;
    let after = line.split("runtime error:").nth(1)?.trim();

    // The report's own stack is the frames printed after its `runtime error:`
    // line (`print_stacktrace=1`), up to the blank line or `SUMMARY:` that ends
    // it — not every `#N` line anywhere in the log.
    let after_line = stderr
        .find(line)
        .map(|pos| &stderr[pos + line.len()..])
        .unwrap_or("");
    let check = ubsan_check_name(after_line);
    // Each UBSan check is its own kind and rule. UBSan's own check name
    // (`report_error_type=1`) decides when it is present; otherwise the report
    // text after `runtime error:` does — never the source path before it.
    let kind = check
        .as_deref()
        .and_then(finding_rules::ubsan::kind_for_check_name)
        .unwrap_or_else(|| finding_rules::ubsan::kind_for_message(after));
    if kind == "undefined-behavior" && !is_ubsan_output(line, stderr) {
        // `runtime error:` is not UBSan's alone — a Go panic reads `panic: runtime
        // error: index out of range [5] with length 1`, and this parser runs BEFORE
        // the Go one. Without this guard the generic arm would hijack every Go
        // panic and report it as C undefined behaviour.
        return None;
    }
    // An unrecognised check is still UNDEFINED BEHAVIOUR that UBSan localized to
    // a file and line: it is reported generically (the message carries the exact
    // check), never dropped as an input rejection.
    let rule_id = finding_rules::ubsan::rule_for_kind(kind);
    let kind = kind.to_owned();
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::UndefinedBehaviorSanitizer),
        kind,
        rule_id,
        stack: report_stack(after_line),
        message: line.to_owned(),
        location: ubsan_location(line),
        check,
        access: None,
    })
}

/// The `file:line:col` prefix of a UBSan `<file>:<line>:<col>: runtime error:`
/// line.
fn ubsan_location(line: &str) -> Option<SourceLocation> {
    let prefix = line.split("runtime error:").next()?;
    parse_location_token(prefix.trim().trim_end_matches(':'))
}

/// UBSan's check name from its `SUMMARY:` line. With `report_error_type=1`
/// the line reads `SUMMARY: UndefinedBehaviorSanitizer: missing-return
/// a.c:3:5`; without it every check reads `undefined-behavior`, which names
/// nothing and so yields `None`.
fn ubsan_check_name(report: &str) -> Option<String> {
    const MARKER: &str = "SUMMARY: UndefinedBehaviorSanitizer:";
    let line = report.lines().find(|line| line.contains(MARKER))?;
    let after = line.split(MARKER).nth(1)?.trim();
    let check = after.split_whitespace().next()?;
    (check != "undefined-behavior" && !check.is_empty()).then(|| check.to_owned())
}

/// The location on a `SUMMARY: <Sanitizer>: <kind> <file>:<line>:<col> in fn`
/// line, when the frame it names was symbolized.
fn summary_location(report: &str, sanitizer_marker: &str) -> Option<SourceLocation> {
    let line = report.lines().find(|line| {
        line.trim_start().starts_with("SUMMARY:") && line.contains(sanitizer_marker)
    })?;
    let after = line.split(sanitizer_marker).nth(1)?;
    let token = after.split_whitespace().nth(1)?;
    parse_location_token(token)
}

/// Parse `path:line[:col]` (a Windows drive prefix is kept in `path`). `None`
/// when the trailing fields are not numbers.
fn parse_location_token(token: &str) -> Option<SourceLocation> {
    if token.is_empty() || token.starts_with('(') {
        return None;
    }
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let mut fields = token.rsplitn(3, ':');
    let last = fields.next()?;
    let middle = fields.next()?;
    let head = fields.next();
    let (file, line, column) = match head {
        Some(head) if numeric(middle) && numeric(last) => {
            (head.to_owned(), middle.parse().ok()?, last.parse().ok())
        }
        _ if numeric(last) => {
            let file = match head {
                Some(head) => format!("{head}:{middle}"),
                None => middle.to_owned(),
            };
            (file, last.parse().ok()?, None)
        }
        _ => return None,
    };
    if file.trim().is_empty() {
        return None;
    }
    Some(SourceLocation { file, line, column })
}

fn parse_lsan(stderr: &str) -> Option<SanitizerReport> {
    let line = stderr.lines().find(|line| {
        line.contains("ERROR: LeakSanitizer:")
            || line.contains("LeakSanitizer: detected memory leaks")
    })?;
    Some(SanitizerReport {
        sanitizer: Some(Sanitizer::LeakSanitizer),
        kind: "memory-leak".to_owned(),
        rule_id: "BHF-208",
        stack: parse_stack_frames(stderr),
        message: line.to_owned(),
        ..Default::default()
    })
}

/// Most frames kept per stack (crash, allocation, free), each capped on its own
/// so a deep crash stack cannot push the allocation site out.
pub const MAX_SANITIZER_FRAMES: usize = 16;

/// One `#N 0x... in <symbol> [location]` sanitizer stack line, or `None`.
///
/// ASan/UBSan format:
///   "    #0 0x... in <symbol> /path/file.c:LINE[:COL]"
///   "    #0 0x... in <demangled C++ name with spaces> /path/file.c:LINE"
///   "    #0 0x... in <symbol> (module+0xab)"   (unresolved)
fn parse_frame_line(line: &str) -> Option<StackFrame> {
    let rest = line.trim_start().strip_prefix('#')?;
    let in_pos = rest.find(" in ")?;
    let after = &rest[in_pos + 4..].trim_end();
    let (function, file, line) = split_function_and_location(after);
    if function.is_empty() {
        return None;
    }
    Some(StackFrame {
        function: function.to_owned(),
        file,
        line,
    })
}

/// Add `frame` unless it is a repeat or the stack is full.
fn push_frame(frames: &mut Vec<StackFrame>, frame: StackFrame) {
    if !frames.contains(&frame) && frames.len() < MAX_SANITIZER_FRAMES {
        frames.push(frame);
    }
}

/// Every frame line in `stderr`, deduplicated and capped. Used for reports that
/// print a single stack (LSan, panics).
fn parse_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames: Vec<StackFrame> = Vec::new();
    for frame in stderr.lines().filter_map(parse_frame_line) {
        push_frame(&mut frames, frame);
    }
    frames
}

/// The frames of one report's stack: frame lines from the start of `report`
/// until the blank line after them, a `SUMMARY:` line, or the next report.
fn report_stack(report: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for line in report.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("SUMMARY:")
            || line.contains("runtime error:")
            || line.contains("ERROR: ")
            || (trimmed.is_empty() && !frames.is_empty())
        {
            break;
        }
        if let Some(frame) = parse_frame_line(line) {
            push_frame(&mut frames, frame);
        }
    }
    frames
}

/// The stacks of an ASan report, each from its own section.
#[derive(Default)]
struct AsanStacks {
    /// The faulting access's stack: the frames after the `ERROR:` line.
    crash: Vec<StackFrame>,
    /// `allocated by` / `previously allocated by`, or the frame holding a stack
    /// object.
    alloc: Vec<StackFrame>,
    /// `freed by`.
    free: Vec<StackFrame>,
}

/// Split an ASan report into its crash, allocation and free stacks. The crash
/// stack ends at the first blank line after it or at the address description;
/// every later stack belongs to the section header above it.
fn split_asan_stacks(report: &str) -> AsanStacks {
    #[derive(Clone, Copy, PartialEq)]
    enum Section {
        Crash,
        Alloc,
        Free,
        Other,
    }
    let mut stacks = AsanStacks::default();
    let mut section = Section::Crash;
    for line in report.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("SUMMARY:") {
            break;
        }
        if trimmed.contains("freed by thread") {
            section = Section::Free;
            continue;
        }
        if trimmed.contains("allocated by thread") || is_stack_object_header(trimmed) {
            section = Section::Alloc;
            continue;
        }
        if trimmed.contains(" is located ")
            || trimmed.starts_with("This frame has")
            || (trimmed.starts_with("Thread T") && trimmed.contains("created by"))
        {
            section = Section::Other;
            continue;
        }
        if trimmed.is_empty() {
            let started = match section {
                Section::Crash => !stacks.crash.is_empty(),
                _ => true,
            };
            if started {
                section = Section::Other;
            }
            continue;
        }
        let Some(frame) = parse_frame_line(line) else {
            continue;
        };
        match section {
            Section::Crash => push_frame(&mut stacks.crash, frame),
            Section::Alloc => push_frame(&mut stacks.alloc, frame),
            Section::Free => push_frame(&mut stacks.free, frame),
            Section::Other => {}
        }
    }
    stacks
}

/// `Address 0x... is located in stack of thread T0 at offset 36 in frame`: the
/// header of the stack-object description, followed by the frame that owns it.
fn is_stack_object_header(trimmed: &str) -> bool {
    trimmed.starts_with("Address ")
        && trimmed.contains(" at offset ")
        && trimmed.contains(" in frame")
}

/// The structured access of an ASan report: direction and size, the faulting
/// address and ASan's hint about it, the region the address falls in, and the
/// allocation and free stacks. `None` when the report states none of these.
fn memory_access(
    report: &str,
    error_line: &str,
    alloc_stack: Vec<StackFrame>,
    free_stack: Vec<StackFrame>,
) -> Option<Box<MemoryAccess>> {
    let mut direction = AccessDirection::Unknown;
    let mut size = None;
    let mut address_hint = None;
    for line in report
        .lines()
        .take_while(|l| !l.trim_start().starts_with("SUMMARY:"))
    {
        let trimmed = line.trim_start();
        if direction == AccessDirection::Unknown && size.is_none() {
            // `READ of size 4 at 0x... thread T0`
            if let Some((token, tail)) = trimmed.split_once(" of size ") {
                if matches!(token, "READ" | "WRITE") {
                    direction = AccessDirection::from_token(token);
                    size = tail
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u64>().ok());
                    continue;
                }
            }
        }
        // `==NN==The signal is caused by a READ memory access.` (SEGV): the PID
        // prefix means the line cannot be anchored with `starts_with`.
        if let Some(pos) = line.find("The signal is caused by a ") {
            let token = line[pos + "The signal is caused by a ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("");
            direction = AccessDirection::from_token(token);
        }
        if line.contains("Hint: address points to the zero page") {
            address_hint = Some("zero-page".to_owned());
        } else if line.contains("Hint:") && line.contains("high value address") {
            address_hint = Some("high-value-address".to_owned());
        }
    }
    // A non-canonical ("high value") address faults before the CPU reports a
    // direction, and ASan then prints READ whatever the instruction did.
    if address_hint.as_deref() == Some("high-value-address") {
        direction = AccessDirection::Unknown;
    }
    let access = MemoryAccess {
        direction,
        size,
        address: faulting_address(error_line),
        address_hint,
        region: memory_region(report),
        alloc_stack,
        free_stack,
    };
    (access != MemoryAccess::default()).then(|| Box::new(access))
}

/// Addresses below this are in the first memory page: a NULL base plus a small
/// field or element offset.
const NULL_PAGE_LIMIT: u64 = 0x1000;

/// Whether a SEGV faulted in the first memory page (a NULL dereference), by
/// ASan's `zero page` hint or by the faulting address itself.
fn faults_in_null_page(access: &MemoryAccess) -> bool {
    access.address_hint.as_deref() == Some("zero-page")
        || access
            .address
            .as_deref()
            .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
            .is_some_and(|address| address < NULL_PAGE_LIMIT)
}

/// The rule an earlier bhf release recorded for this report, where it differs
/// from today's. Earlier releases classified a UBSan report by five shapes of
/// the text after `runtime error:` ([`earlier_ubsan_rule`]) and gave every
/// ASan SEGV BHF-206. `None` when the rule did not change.
pub fn legacy_rule_id(report: &SanitizerReport) -> Option<&'static str> {
    let legacy = match report.sanitizer {
        Some(Sanitizer::UndefinedBehaviorSanitizer) => {
            let after = report
                .message
                .split_once("runtime error:")
                .map_or("", |(_, text)| text.trim());
            earlier_ubsan_rule(after)
        }
        Some(Sanitizer::AddressSanitizer) if report.kind == "SEGV" => "BHF-206",
        _ => return None,
    };
    (legacy != report.rule_id).then_some(legacy)
}

/// The rule earlier releases gave a UBSan report, from the text after
/// `runtime error:`: integer overflow, any "cannot be represented in type"
/// text and division by zero were BHF-205, the NULL shapes below BHF-206, an
/// array index BHF-201, and every other check BHF-210.
fn earlier_ubsan_rule(after: &str) -> &'static str {
    const NULL_PREFIXES: &[&str] = &[
        "load of null pointer",
        "store to null pointer",
        "member access within null pointer",
        "reference binding to null pointer",
        "null pointer passed as argument",
        "null pointer returned from function",
    ];
    if after.starts_with("signed integer overflow")
        || after.starts_with("unsigned integer overflow")
        || after.contains("cannot be represented in type")
    {
        "BHF-205"
    } else if NULL_PREFIXES.iter().any(|prefix| after.starts_with(prefix))
        || (after.starts_with("applying") && after.contains("to null pointer"))
    {
        "BHF-206"
    } else if after.starts_with("index ") && after.contains("out of bounds") {
        "BHF-201"
    } else if after.starts_with("division by zero") {
        "BHF-205"
    } else {
        "BHF-210"
    }
}

/// Whether `report` is the crash a finding recorded with `recorded_rule`: the
/// same rule, or the rule an earlier release gave the same report
/// ([`legacy_rule_id`]), so replaying an older finding still matches.
pub fn rule_matches(recorded_rule: &str, report: &SanitizerReport) -> bool {
    report.rule_id == recorded_rule || legacy_rule_id(report) == Some(recorded_rule)
}

/// The address on the `ERROR:` line: `on address 0x...`, `on unknown address
/// 0x...` (SEGV), or `double-free on 0x...`. `None` when ASan could not name
/// one (`SEGV on unknown address (pc ...)`).
fn faulting_address(error_line: &str) -> Option<String> {
    let after = error_line
        .split_once("address 0x")
        .map(|(_, tail)| tail)
        .or_else(|| error_line.split_once(" on 0x").map(|(_, tail)| tail))?;
    let hex: String = after.chars().take_while(char::is_ascii_hexdigit).collect();
    (!hex.is_empty()).then(|| format!("0x{hex}"))
}

/// The region an ASan report's address description names:
/// - heap: `0x... is located 0 bytes after 5-byte region [a,b)` (older
///   runtimes: `to the right of` / `to the left of`), or `N bytes inside of`;
/// - global: `... is located 0 bytes after global variable 'g' defined in
///   'x.c:4' (0x...) of size 40`;
/// - stack: `Address 0x... is located in stack of thread T0 at offset 36 in
///   frame`, then the frame's object list where the overflowed variable is
///   marked `<== Memory access at offset 36 overflows this variable`.
fn memory_region(report: &str) -> Option<MemoryRegion> {
    let lines: Vec<&str> = report.lines().collect();
    if let Some(idx) = lines.iter().position(|l| is_stack_object_header(l.trim())) {
        let frame_offset = number_after(lines[idx], " at offset ");
        let mut region = MemoryRegion {
            kind: "stack".to_owned(),
            frame_offset,
            ..MemoryRegion::default()
        };
        // `    [32, 36) 'buf' (line 13) <== Memory access at offset 36 overflows this variable`
        if let Some(object) = lines[idx..]
            .iter()
            .take_while(|l| !l.trim_start().starts_with("SUMMARY:"))
            .find(|l| l.contains("<== Memory access"))
        {
            let bounds = object
                .trim_start()
                .strip_prefix('[')
                .and_then(|rest| rest.split_once(')'));
            if let Some((range, tail)) = bounds {
                let mut ends = range.split(',').map(|n| n.trim().parse::<u64>().ok());
                if let (Some(Some(start)), Some(Some(end))) = (ends.next(), ends.next()) {
                    region.size = end.checked_sub(start);
                    if let Some(offset) = frame_offset.and_then(|at| signed_difference(at, start)) {
                        region.offset = Some(offset);
                        place_relative(&mut region, offset);
                    }
                }
                region.variable = quoted(tail);
            }
        }
        return Some(region);
    }
    let line = lines.iter().find(|l| l.contains(" is located "))?;
    let after = line.split(" is located ").nth(1)?;
    let distance = after
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok());
    let relation = if after.contains(" bytes after ") || after.contains(" bytes to the right of ") {
        "after"
    } else if after.contains(" bytes before ") || after.contains(" bytes to the left of ") {
        "before"
    } else if after.contains(" bytes inside of ") {
        "inside"
    } else {
        return None;
    };
    let (kind, size, variable) = if after.contains("global variable") {
        ("global", number_after(after, " of size "), quoted(after))
    } else {
        // `... 5-byte region [a,b)`
        let size = after
            .split_whitespace()
            .find_map(|word| word.strip_suffix("-byte"))
            .and_then(|n| n.parse::<u64>().ok());
        ("heap", size, None)
    };
    // The numbers come from the target's output: an offset that does not fit
    // stays unset rather than wrapping.
    let offset = match (relation, distance) {
        ("after", Some(d)) => size
            .and_then(|size| size.checked_add(d))
            .and_then(|end| i64::try_from(end).ok()),
        ("before", Some(d)) => 0_i64.checked_sub_unsigned(d),
        ("inside", Some(d)) => i64::try_from(d).ok(),
        _ => None,
    };
    Some(MemoryRegion {
        kind: kind.to_owned(),
        size,
        offset,
        relation: Some(relation.to_owned()),
        distance,
        variable,
        frame_offset: None,
    })
}

/// `at - start` as a signed offset, `None` when it does not fit in an `i64`.
fn signed_difference(at: u64, start: u64) -> Option<i64> {
    if at >= start {
        i64::try_from(at - start).ok()
    } else {
        0_i64.checked_sub_unsigned(start - at)
    }
}

/// Fill `relation`/`distance` from an object-relative `offset`.
fn place_relative(region: &mut MemoryRegion, offset: i64) {
    let (relation, distance) = match region.size {
        _ if offset < 0 => ("before", offset.unsigned_abs()),
        Some(size) if offset as u64 >= size => ("after", offset as u64 - size),
        _ => ("inside", offset as u64),
    };
    region.relation = Some(relation.to_owned());
    region.distance = Some(distance);
}

/// The first `'quoted'` word in `text`.
fn quoted(text: &str) -> Option<String> {
    let (_, rest) = text.split_once('\'')?;
    let (name, _) = rest.split_once('\'')?;
    (!name.is_empty()).then(|| name.to_owned())
}

/// The integer right after `needle` in `text`.
fn number_after(text: &str, needle: &str) -> Option<u64> {
    let (_, rest) = text.split_once(needle)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Signed offset of the faulting access from the object it hit, as ASan's
/// address description states it: `+N` for `N bytes after` (or inside), `-N`
/// for `N bytes before`, and the frame offset for a stack object (`at offset
/// N in frame`).
pub fn relative_offset(stderr: &str) -> Option<i64> {
    let region = memory_region(stderr)?;
    if region.kind == "stack" {
        return region
            .frame_offset
            .and_then(|offset| i64::try_from(offset).ok());
    }
    let distance = region.distance?;
    match region.relation.as_deref()? {
        "before" => 0_i64.checked_sub_unsigned(distance),
        _ => i64::try_from(distance).ok(),
    }
}

/// Pull a `(function, file, line)` triple out of the substring that
/// follows `" in "` on a sanitizer stack line. C++ demangled names
/// contain spaces (`std::vector<int>::push_back(int const&)`), so we
/// can't simply tokenize on whitespace. Instead, scan the trailing
/// token: if it looks like `path:LINE` (or `path:LINE:COL`), it's a
/// source location; if it's wrapped in `(...)` it's an unresolved
/// `(module+0xoffset)` and we drop it; otherwise the entire string
/// is the function name.
fn split_function_and_location(after: &str) -> (&str, Option<String>, Option<u32>) {
    // First check whether the last whitespace-separated token is a
    // source location (`path:LINE[:COL]`); if so, peel it off. Then
    // strip any number of trailing `(...)` annotations (module+offset,
    // `(BuildId: ...)`, etc.) so the function name doesn't get
    // contaminated with toolchain decoration.
    let mut cursor = after.trim();
    let mut file_opt: Option<String> = None;
    let mut line_opt: Option<u32> = None;
    if let Some(last_ws) = cursor.rfind(char::is_whitespace) {
        let tail = cursor[last_ws..].trim_start();
        if !tail.starts_with('(') {
            let (file, line) = parse_file_line(tail);
            if file.is_some() {
                cursor = cursor[..last_ws].trim_end();
                file_opt = file;
                line_opt = line;
            }
        }
    }
    // Strip trailing `(...)` chunks. Each chunk may itself contain
    // whitespace (BuildId blobs do), so we scan from the end matching
    // balanced parens.
    loop {
        let trimmed = cursor.trim_end();
        if !trimmed.ends_with(')') {
            cursor = trimmed;
            break;
        }
        // Find matching opening paren by scanning backwards.
        let bytes = trimmed.as_bytes();
        let mut depth = 0_i32;
        let mut open_idx: Option<usize> = None;
        for (i, b) in bytes.iter().enumerate().rev() {
            match b {
                b')' => depth += 1,
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        open_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(open) = open_idx else {
            cursor = trimmed;
            break;
        };
        // Only strip if the chunk is preceded by whitespace - otherwise
        // it's part of a C++ name like `foo(int)` and we keep it.
        let preceding = &trimmed[..open];
        if !preceding.ends_with(char::is_whitespace) {
            cursor = trimmed;
            break;
        }
        cursor = preceding.trim_end();
    }
    (cursor, file_opt, line_opt)
}

/// Parse the trailing `/path/file.c:42[:7]` token from a sanitizer frame.
/// Returns `(None, None)` when the symbol was unresolved (eg. stripped
/// binary printed `function+0xab` instead of a file:line tuple).
/// Examples handled:
///   /src/a.c:42       -> (Some(a.c), Some(42))
///   /src/a.c:42:7     -> (Some(a.c), Some(42))  // column dropped
///   stripped+0xab     -> (None, None)
fn parse_file_line(token: &str) -> (Option<String>, Option<u32>) {
    if token.is_empty() || token.starts_with('+') || token.starts_with('(') {
        return (None, None);
    }
    let Some(last_colon) = token.rfind(':') else {
        return (None, None);
    };
    let (head, tail) = token.split_at(last_colon);
    let tail_value = &tail[1..];
    let Ok(last_num) = tail_value.parse::<u32>() else {
        return (None, None);
    };
    if head.is_empty() {
        return (None, None);
    }
    // The trailing number is either the line (`file.c:42`) or the column
    // when there are two colons (`file.c:42:7`). Probe the segment before
    // the last colon: if that's also numeric, the trailing value was the
    // column and the real line is the inner number.
    if let Some(mid_colon) = head.rfind(':') {
        let (head_inner, mid) = head.split_at(mid_colon);
        if let Ok(line) = mid[1..].parse::<u32>() {
            return (Some(head_inner.to_owned()), Some(line));
        }
    }
    (Some(head.to_owned()), Some(last_num))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_asan_heap_buffer_overflow_maps_to_bhf201_and_captures_frames() {
        let stderr = "\
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead
    #0 0x4ff in target_parse /src/parse.c:42
    #1 0x500 in LLVMFuzzerTestOneInput /tmp/main.c:9
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-201");
        assert_eq!(r.kind, "heap-buffer-overflow");
        assert_eq!(r.sanitizer, Some(Sanitizer::AddressSanitizer));
        assert_eq!(r.stack.len(), 2);
        assert_eq!(r.stack[0].function, "target_parse");
        assert_eq!(r.stack[0].file.as_deref(), Some("/src/parse.c"));
        assert_eq!(r.stack[0].line, Some(42));
        assert!(r.message.contains("heap-buffer-overflow"));
    }

    #[test]
    fn parse_lsan_keeps_deep_rust_harness_frames() {
        let stderr = "\
==1234==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 6 byte(s) in 1 object(s) allocated from:
    #0 0x100 in malloc (/tmp/h/main+0x100)
    #1 0x101 in <alloc::raw_vec::RawVecInner>::try_allocate_in (/tmp/h/main+0x101)
    #2 0x102 in <alloc::raw_vec::RawVecInner>::with_capacity_in /rust/library/alloc/src/raw_vec/mod.rs:434:15
    #3 0x103 in <alloc::raw_vec::RawVec<u8>>::with_capacity_in /rust/library/alloc/src/raw_vec/mod.rs:177:20
    #4 0x104 in <alloc::vec::Vec<u8>>::with_capacity_in /rust/library/alloc/src/vec/mod.rs:977:20
    #5 0x105 in <u8 as <[_]>::to_vec_in::ConvertVec>::to_vec::<alloc::alloc::Global> /rust/library/alloc/src/slice.rs:448:29
    #6 0x106 in <[u8]>::to_vec /rust/library/alloc/src/slice.rs:376:14
    #7 0x107 in <str as alloc::borrow::ToOwned>::to_owned /rust/library/alloc/src/str.rs:251:62
    #8 0x108 in <alloc::borrow::Cow<str>>::into_owned /rust/library/alloc/src/borrow.rs:333:44
    #9 0x109 in <rust_runtime::Cursor>::string /workspace/crates/rust_runtime/src/lib.rs:171:39
    #10 0x10a in bhf_run_one /tmp/h/rust_harness/src/lib.rs:17:30
    #11 0x10b in bhf_run_one_bytes /tmp/h/main.c:406:5
    #12 0x10c in main /tmp/h/main.c:481:5
SUMMARY: AddressSanitizer: 6 byte(s) leaked in 1 allocation(s).
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-208");
        assert!(
            r.stack.iter().any(|frame| frame.function == "bhf_run_one"),
            "deep harness frame must be retained: {:?}",
            r.stack
        );
    }

    #[test]
    fn jvm_finding_aioobe_maps_to_bhf201_and_skips_driver_frames() {
        let stderr = "\
== bhf JVM finding: java.lang.ArrayIndexOutOfBoundsException: Index 8 out of bounds for length 1
java.lang.ArrayIndexOutOfBoundsException: Index 8 out of bounds for length 1
\tat com.acme.Magic.parse(Magic.java:30)
\tat bhfgen.Harness.bhfRunOne(Harness.java:10)
\tat java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)
\tat com.bhf.Driver.runInput(Driver.java:93)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-201");
        assert_eq!(r.kind, "jvm-index-out-of-bounds");
        // The target's own frame is the top frame; JDK/bhf frames are skipped.
        assert_eq!(r.stack[0].function, "com.acme.Magic.parse");
        assert_eq!(r.stack[0].file.as_deref(), Some("Magic.java"));
        assert_eq!(r.stack[0].line, Some(30));
        assert!(r.message.contains("ArrayIndexOutOfBoundsException"));
    }

    #[test]
    fn jvm_finding_npe_maps_to_bhf210() {
        let stderr = "== bhf JVM finding: java.lang.NullPointerException\n\
                      \tat com.acme.P.parse(P.java:5)\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-210");
        assert_eq!(r.kind, "jvm-uncaught-throwable");
    }

    #[test]
    fn non_jvm_stderr_is_not_a_jvm_finding() {
        assert!(parse_sanitizer_report("just some normal output\n").is_none());
    }

    #[test]
    fn python_finding_recursion_maps_to_bhf207_and_skips_driver_frames() {
        let stderr = "== bhf python finding: RecursionError: maximum recursion depth exceeded\n\
                      Traceback (most recent call last):\n\
                      \x20 File \"/w/bhf_driver.py\", line 99, in _run_input\n\
                      \x20 File \"/w/bhfgen/harness.py\", line 11, in bhf_run_one\n\
                      \x20 File \"/proj/recordparser.py\", line 18, in parse_record\n\
                      \x20 File \"/proj/recordparser.py\", line 22, in _walk\n";
        let r = parse_sanitizer_report(stderr).expect("python finding");
        assert_eq!(r.rule_id, "BHF-207");
        assert_eq!(r.kind, "python-uncontrolled-recursion");
        // Driver + harness frames are skipped; the top frame is the target's code.
        assert_eq!(r.stack[0].function, "parse_record");
        assert_eq!(r.stack[0].file.as_deref(), Some("/proj/recordparser.py"));
        assert_eq!(r.stack[0].line, Some(18));
    }

    #[test]
    fn python_finding_index_and_arithmetic_and_generic_map_correctly() {
        let idx = "== bhf python finding: IndexError: list index out of range\n";
        assert_eq!(parse_sanitizer_report(idx).unwrap().rule_id, "BHF-201");
        let zde = "== bhf python finding: ZeroDivisionError: division by zero\n";
        assert_eq!(parse_sanitizer_report(zde).unwrap().rule_id, "BHF-205");
        let oom = "== bhf python finding: MemoryError: \n";
        assert_eq!(parse_sanitizer_report(oom).unwrap().rule_id, "BHF-209");
        let key = "== bhf python finding: KeyError: 'x'\n";
        assert_eq!(parse_sanitizer_report(key).unwrap().rule_id, "BHF-210");
    }

    #[test]
    fn csharp_finding_maps_types_and_parses_stack() {
        let stderr = "== bhf csharp finding: System.IndexOutOfRangeException: Index was outside the bounds of the array.\n\
                      \x20  at Bhfgen.BhfEntry.Run(Byte[] data)\n\
                      \x20  at Acme.Parsing.JsonReader.Parse(Byte[] data) in /proj/JsonReader.cs:line 42\n\
                      \x20  at Acme.Parsing.JsonReader.Scan(Byte[] data) in /proj/JsonReader.cs:line 51\n";
        let r = parse_sanitizer_report(stderr).expect("csharp finding");
        assert_eq!(r.rule_id, "BHF-201");
        assert_eq!(r.kind, "csharp-index-out-of-bounds");
        // The Bhfgen entry frame is skipped; the top frame is the target's code.
        assert_eq!(r.stack[0].function, "Acme.Parsing.JsonReader.Parse");
        assert_eq!(r.stack[0].file.as_deref(), Some("/proj/JsonReader.cs"));
        assert_eq!(r.stack[0].line, Some(42));
    }

    #[test]
    fn csharp_finding_type_rule_mapping() {
        let nre = "== bhf csharp finding: System.NullReferenceException: \n";
        assert_eq!(parse_sanitizer_report(nre).unwrap().rule_id, "BHF-206");
        let dz = "== bhf csharp finding: System.DivideByZeroException: div by zero\n";
        assert_eq!(parse_sanitizer_report(dz).unwrap().rule_id, "BHF-205");
        let oom = "== bhf csharp finding: System.OutOfMemoryException: \n";
        assert_eq!(parse_sanitizer_report(oom).unwrap().rule_id, "BHF-209");
        let custom = "== bhf csharp finding: Acme.ParseException: bad token\n";
        assert_eq!(parse_sanitizer_report(custom).unwrap().rule_id, "BHF-210");
    }

    #[test]
    fn js_finding_reads_rule_and_stack() {
        let stderr = "== bhf js finding: BHF-206: TypeError: Cannot read properties of undefined (reading 'x')\n\
                      \x20   at parse (/proj/parser.js:42:13)\n\
                      \x20   at Object.<anonymous> (/w/bhf_driver.js:99:5)\n\
                      \x20   at walk (/proj/parser.js:51:7)\n";
        let r = parse_sanitizer_report(stderr).expect("js finding");
        assert_eq!(r.rule_id, "BHF-206");
        assert_eq!(r.kind, "js-null-dereference");
        // The driver frame is skipped; the top frame is the target's code.
        assert_eq!(r.stack[0].function, "parse");
        assert_eq!(r.stack[0].file.as_deref(), Some("/proj/parser.js"));
        assert_eq!(r.stack[0].line, Some(42));
    }

    #[test]
    fn js_finding_rule_mapping() {
        let so = "== bhf js finding: BHF-207: RangeError: Maximum call stack size exceeded\n";
        assert_eq!(parse_sanitizer_report(so).unwrap().rule_id, "BHF-207");
        let oom = "== bhf js finding: BHF-209: RangeError: Invalid array length\n";
        assert_eq!(parse_sanitizer_report(oom).unwrap().rule_id, "BHF-209");
        let gen = "== bhf js finding: BHF-210: Error: boom\n";
        assert_eq!(parse_sanitizer_report(gen).unwrap().rule_id, "BHF-210");
    }

    #[test]
    fn js_command_injection_sink_maps_to_bhf431() {
        let ci =
            "== bhf js finding: BHF-431: CommandInjection: execSync: convert x; rm -rf / out.png\n";
        let r = parse_sanitizer_report(ci).expect("js sink finding");
        assert_eq!(r.rule_id, "BHF-431");
        assert_eq!(r.kind, "js-command-injection");
    }

    #[test]
    fn js_prototype_pollution_maps_to_bhf509() {
        let pp =
            "== bhf js finding: BHF-509: PrototypePollution: Object.prototype: polluted key 'polluted'\n";
        let r = parse_sanitizer_report(pp).expect("js pollution finding");
        assert_eq!(r.rule_id, "BHF-509");
        assert_eq!(r.kind, "js-prototype-pollution");
    }

    #[test]
    fn non_python_stderr_is_not_a_python_finding() {
        assert!(parse_python_finding("regular traceback-free output\n").is_none());
    }

    #[test]
    fn go_panic_maps_message_to_rule_and_skips_runtime_frames() {
        let stderr = "== bhf go finding: runtime error: index out of range [5] with length 1\n\
                      goroutine 1 [running]:\n\
                      runtime/debug.Stack()\n\
                      \t/usr/local/go/src/runtime/debug/stack.go:24 +0x5e\n\
                      main.runOne.func1()\n\
                      \t/w/bhf_harness.go:40 +0x4c\n\
                      panic({0x4a0,0xc1})\n\
                      \t/usr/local/go/src/runtime/panic.go:770 +0x132\n\
                      example/recordparser.ParseRecord({0x0,0x1,0x1})\n\
                      \t/proj/recordparser/parser.go:17 +0x1d0\n";
        let r = parse_sanitizer_report(stderr).expect("go finding");
        assert_eq!(r.rule_id, "BHF-201");
        assert_eq!(r.kind, "go-index-out-of-bounds");
        assert_eq!(r.stack[0].function, "example/recordparser.ParseRecord");
        assert_eq!(
            r.stack[0].file.as_deref(),
            Some("/proj/recordparser/parser.go")
        );
        assert_eq!(r.stack[0].line, Some(17));
    }

    #[test]
    fn go_method_frame_keeps_the_receiver_and_method_name() {
        // Regression: a Go method frame's first `(` is its receiver group, not
        // the argument list. Splitting on the first `(` truncated the method
        // name, leaving `bhf.example/forcelib/forcelib.`. The whole qualified
        // method name must survive into the frame.
        let stderr = "== bhf go finding: runtime error: index out of range [4] with length 1\n\
                      goroutine 1 [running]:\n\
                      panic({0x4a0,0xc1})\n\
                      \t/usr/local/go/src/runtime/panic.go:770 +0x132\n\
                      bhf.example/forcelib/forcelib.(*Decoder).Feed(0xc00001c030, {0x5a1b40, 0x5, 0x5})\n\
                      \t/proj/forcelib/forcelib.go:27 +0x1d0\n";
        let r = parse_sanitizer_report(stderr).expect("go finding");
        assert_eq!(
            r.stack[0].function,
            "bhf.example/forcelib/forcelib.(*Decoder).Feed"
        );
        assert_eq!(
            r.stack[0].file.as_deref(),
            Some("/proj/forcelib/forcelib.go")
        );
        assert_eq!(r.stack[0].line, Some(27));
    }

    #[test]
    fn go_interface_conversion_panic_is_suppressed() {
        // Our-fault: a synthesized *interface{} passed to a target that type-asserts
        // it panics with "interface conversion" — not a finding.
        let stderr =
            "== bhf go finding: interface conversion: interface {} is *interface {}, not string\n\
                      goroutine 1 [running]:\n\
                      main.target(...)\n";
        assert!(parse_sanitizer_report(stderr).is_none());
        // A real OOB is still a finding.
        let oob = "panic: runtime error: index out of range [5] with length 1\n";
        assert_eq!(parse_sanitizer_report(oob).unwrap().rule_id, "BHF-201");
    }

    #[test]
    fn go_panic_classes() {
        let nil = "panic: runtime error: invalid memory address or nil pointer dereference\n";
        assert_eq!(parse_sanitizer_report(nil).unwrap().rule_id, "BHF-206");
        let div = "panic: runtime error: integer divide by zero\n";
        assert_eq!(parse_sanitizer_report(div).unwrap().rule_id, "BHF-205");
        let other = "panic: assertion failed\n";
        assert_eq!(parse_sanitizer_report(other).unwrap().rule_id, "BHF-210");
        assert!(parse_go_panic("ordinary program output\n").is_none());
    }

    #[test]
    fn perl_finding_maps_cwe_token_to_rule() {
        let div = "== bhf perl finding: CWE-369: Illegal division by zero\n";
        assert_eq!(parse_sanitizer_report(div).unwrap().rule_id, "BHF-205");
        let rec = "== bhf perl finding: CWE-674: Deep recursion\n";
        assert_eq!(parse_sanitizer_report(rec).unwrap().rule_id, "BHF-207");
        let oom = "== bhf perl finding: CWE-789: Out of memory\n";
        assert_eq!(parse_sanitizer_report(oom).unwrap().rule_id, "BHF-209");
        let assert_die = "== bhf perl finding: CWE-617: panic: invariant\n";
        assert_eq!(
            parse_sanitizer_report(assert_die).unwrap().rule_id,
            "BHF-210"
        );
        assert!(parse_perl_finding("Use of uninitialized value\n").is_none());
    }

    #[test]
    fn jvm_class_loading_errors_are_not_findings() {
        // ClassFormatError / VerifyError / NoClassDefFoundError are instrumentation
        // or classpath artifacts, not target bugs (snakeyaml emitted 15 identical
        // ClassFormatError "bad offset for Uninitialized" from coverage-instrumented
        // bytecode). They must NOT raise a BHF-210 finding.
        for class in [
            "java.lang.ClassFormatError",
            "java.lang.VerifyError",
            "java.lang.NoClassDefFoundError",
            "java.lang.UnsupportedClassVersionError",
            "java.lang.LinkageError",
        ] {
            let stderr = format!(
                "== bhf JVM finding: {class}: StackMapTable format error\n\
                 \tat org.yaml.snakeyaml.Yaml.load(Yaml.java:437)\n"
            );
            assert!(
                parse_sanitizer_report(&stderr).is_none(),
                "{class} must not be a finding"
            );
        }
        // A real target exception still IS a finding (regression guard).
        let real = "== bhf JVM finding: java.lang.NullPointerException\n\
                    \tat com.acme.P.parse(P.java:5)\n";
        assert!(parse_sanitizer_report(real).is_some());
    }

    #[test]
    fn rust_panic_index_oob_maps_to_bhf201_with_site() {
        let stderr = "\
thread '<unnamed>' (3064726) panicked at /src/lib.rs:37:50:
index out of bounds: the len is 6 but the index is 6
note: run with `RUST_BACKTRACE=1` to display a backtrace
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-201");
        assert_eq!(r.kind, "rust-panic-index-out-of-bounds");
        assert!(r.message.contains("index out of bounds"), "{}", r.message);
        // The panic site is the top frame.
        assert_eq!(r.stack[0].file.as_deref(), Some("/src/lib.rs"));
        assert_eq!(r.stack[0].line, Some(37));
    }

    #[test]
    fn rust_panic_arithmetic_overflow_maps_to_bhf205() {
        let stderr = "\
thread 'main' panicked at src/math.rs:9:5:
attempt to add with overflow
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-205");
        assert_eq!(r.kind, "rust-panic-arithmetic");
    }

    #[test]
    fn rust_panic_unwrap_is_generic_bhf210() {
        let stderr = "\
thread '<unnamed>' panicked at src/lib.rs:3:14:
called `Option::unwrap()` on a `None` value
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-210");
        assert_eq!(r.kind, "rust-panic");
        assert!(r.message.contains("unwrap"));
    }

    #[test]
    fn non_rust_stderr_is_not_a_rust_panic() {
        // A plain C assert/abort must NOT be misread as a Rust panic.
        assert!(parse_sanitizer_report("Assertion failed: x > 0\n").is_none());
        assert!(parse_sanitizer_report("some unrelated output\n").is_none());
    }

    /// Most of libc is declared `__attribute__((nonnull))`, so passing NULL to
    /// `memcpy` is reported by UBSan's nonnull check — not as a load/store of a
    /// null pointer. That shape was unmatched, so the report fell through to
    /// `None`, the SIGABRT read as the target rejecting the input, and the crash
    /// was discarded: a NULL returned by a stubbed external and handed to memcpy
    /// produced no finding at all, which left both the capsule and the
    /// stub-provenance features with no crash to work on.
    #[test]
    fn ubsan_nonnull_argument_is_a_null_dereference_finding() {
        for message in [
            "null pointer passed as argument 1, which is declared to never be null",
            "null pointer returned from function declared to never return null",
            "applying non-zero offset 8 to null pointer",
        ] {
            let stderr = format!(
                "/src/snippet.c:5:12: runtime error: {message}\n\
                 SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/snippet.c:5:12\n"
            );
            let report = parse_sanitizer_report(&stderr)
                .unwrap_or_else(|| panic!("must be a finding: {message}"));
            assert_eq!(report.rule_id, "BHF-206", "{message}");
            assert_eq!(report.kind, "null-pointer-dereference", "{message}");
        }
    }

    /// UBSan has ~20 checks. Failing closed on the ones this parser does not name
    /// individually meant discarding them, so an unrecognised check is reported
    /// generically rather than dropped.
    #[test]
    fn an_unrecognised_ubsan_check_is_reported_generically_not_dropped() {
        let stderr = "/src/t.c:9:3: runtime error: \
                      a check this parser has never seen\n\
                      SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/t.c:9:3\n";
        let report = parse_sanitizer_report(stderr).expect("must not be dropped");
        assert_eq!(report.rule_id, "BHF-213");
        assert_eq!(report.kind, "undefined-behavior");
        assert!(
            report
                .message
                .contains("a check this parser has never seen"),
            "the exact check must survive in the message: {}",
            report.message
        );
    }

    /// `runtime error:` is not UBSan's alone: a Go panic uses the same words and
    /// this parser runs BEFORE the Go one, so the generic fallback must not hijack
    /// it. Each of these must still classify as its own lane's finding.
    #[test]
    fn a_go_panic_is_not_mistaken_for_c_undefined_behavior() {
        for stderr in [
            "panic: runtime error: index out of range [5] with length 1\n",
            "panic: runtime error: invalid memory address or nil pointer dereference\n",
            "panic: runtime error: integer divide by zero\n",
        ] {
            let report = parse_sanitizer_report(stderr).expect("still a finding");
            assert_ne!(
                report.sanitizer,
                Some(Sanitizer::UndefinedBehaviorSanitizer),
                "a Go panic must not be reported as C UBSan: {stderr}"
            );
        }
        // And a bare `foo: runtime error: ...` with no source position and no
        // UBSan banner is not claimed either.
        assert!(!is_ubsan_output(
            "thing: runtime error: something",
            "thing: runtime error: something"
        ));
    }

    #[test]
    fn parse_ubsan_frame_with_column_suffix_keeps_line() {
        let stderr = "\
t.c:1:1: runtime error: signed integer overflow: 2 + 2147483647
    #0 0x123 in overflow_caller /tmp/t.c:7:9
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(r.stack[0].function, "overflow_caller");
        assert_eq!(r.stack[0].file.as_deref(), Some("/tmp/t.c"));
        assert_eq!(r.stack[0].line, Some(7));
    }

    #[test]
    fn parse_stack_frame_with_no_debug_info_keeps_function_only() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-use-after-free on 0xdead
    #0 0x456 in stripped_symbol+0xab
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(r.stack[0].function, "stripped_symbol+0xab");
        assert!(r.stack[0].file.is_none());
        assert!(r.stack[0].line.is_none());
    }

    #[test]
    fn parse_stack_frame_module_offset_token_is_not_a_file() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x4ff in __asan_memcpy (/tmp/build/main+0xfec85)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(r.stack[0].function, "__asan_memcpy");
        assert!(r.stack[0].file.is_none(), "module+offset is not a file");
        assert!(r.stack[0].line.is_none());
    }

    #[test]
    fn parse_stack_frame_strips_trailing_buildid_blob() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x4ff in __asan_memcpy (/tmp/main+0xfec85) (BuildId: b103ed1874b0142af3dadc0fd902cf79b6af9fa8)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(r.stack[0].function, "__asan_memcpy");
    }

    #[test]
    fn parse_stack_frame_preserves_cpp_paren_arglist_in_function() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x4ff in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/usr/bin/main+0x4cca4)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        // Trailing (module+offset) is dropped; the C++ arg list, which
        // is part of the function name with no preceding whitespace,
        // stays attached.
        assert_eq!(
            r.stack[0].function,
            "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)"
        );
    }

    #[test]
    fn parse_stack_frame_handles_demangled_cpp_name_with_spaces() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x4ff in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/usr/bin/main+0x4cca4)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(
            r.stack[0].function,
            "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)"
        );
        assert!(r.stack[0].file.is_none());
    }

    #[test]
    fn parse_asan_uaf_maps_to_bhf202() {
        let stderr = "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x...";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "BHF-202");
    }

    #[test]
    fn parse_asan_double_free_maps_to_bhf204() {
        // Real ASan emits "attempting double-free on 0x... in thread T0:" (a
        // SPACE, not a hyphen); the leading "attempting " must be stripped so the
        // kind is "double-free" -> BHF-204, not "attempting" -> BHF-201 (#37).
        let stderr = "==1==ERROR: AddressSanitizer: attempting double-free on 0x602000000010 in thread T0:\n    #0 0x4ff in free /a.c:1\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-204");
        assert_eq!(r.kind, "double-free");
    }

    #[test]
    fn parse_asan_attempting_free_on_non_malloc_maps_to_bhf204() {
        // "attempting free on address which was not malloc()-ed" — the kind token
        // after stripping "attempting " is "free"; classify as the invalid-free
        // class BHF-204, not the BHF-201 OOB fallback (#37).
        let stderr = "==1==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x7ff in thread T0\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-204");
        assert_eq!(r.kind, "free");
    }

    #[test]
    fn parse_asan_stack_overflow_maps_to_bhf203() {
        let stderr = "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xbad";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "BHF-203");
    }

    #[test]
    fn parse_ubsan_signed_overflow_maps_to_bhf205() {
        let stderr = "source.c:10:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-205");
        assert_eq!(r.kind, "signed-integer-overflow");
    }

    #[test]
    fn parse_ubsan_oob_index_maps_to_the_array_index_rule() {
        let stderr = "t.c:7:9: runtime error: index 88 out of bounds for type 'char[4]'";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-220");
        assert_eq!(r.kind, "out-of-bounds-access");
    }

    #[test]
    fn parse_ubsan_null_deref_maps_to_bhf206() {
        let stderr = "t.c:5:1: runtime error: load of null pointer of type 'int'";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "BHF-206");
    }

    #[test]
    fn parse_lsan_memory_leak_maps_to_bhf208() {
        let stderr =
            "=================================================================\n==1==ERROR: LeakSanitizer: detected memory leaks\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-208");
        assert_eq!(r.sanitizer, Some(Sanitizer::LeakSanitizer));
    }

    #[test]
    fn parse_asan_stack_use_after_return_maps_to_bhf211_temporal() {
        // A temporal stack error (stale stack pointer) is the CWE-825/562 class,
        // NOT the spatial stack-buffer-overflow BHF-203/CWE-121 (#29).
        let stderr = "==1==ERROR: AddressSanitizer: stack-use-after-return on address 0x7ff...";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-211");
        assert_eq!(r.kind, "stack-use-after-return");
    }

    #[test]
    fn parse_asan_stack_use_after_scope_maps_to_bhf211_temporal() {
        let stderr = "==1==ERROR: AddressSanitizer: stack-use-after-scope on address 0x7ff...";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "BHF-211");
        assert_eq!(r.kind, "stack-use-after-scope");
    }

    #[test]
    fn parse_asan_spatial_stack_overflow_stays_bhf203() {
        // A genuine spatial stack-buffer-overflow must NOT be reclassified to the
        // temporal rule — its signal stays loud as BHF-203/CWE-121 (#29 guard).
        let stderr = "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xbad";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "BHF-203");
    }

    #[test]
    fn parse_asan_segv_captures_read_write_direction_line() {
        // A SEGV states its access direction on a separate "==NN==The signal is
        // caused by a READ/WRITE memory access." line; it must be folded into the
        // message so the CWE layer can tell an OOB read from a write (#30).
        let read = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010 (pc 0x55 bp 0x0 sp 0x0 T0)\n\
                    ==1==The signal is caused by a READ memory access.\n    #0 0x55 in deref /a.c:7\n";
        let m = parse_sanitizer_report(read).unwrap().message;
        assert!(m.contains("READ memory access"), "got: {m}");
        let write = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000001234 (pc 0x55 bp 0x0 sp 0x0 T0)\n\
                     ==1==The signal is caused by a WRITE memory access.\n";
        assert!(parse_sanitizer_report(write)
            .unwrap()
            .message
            .contains("WRITE memory access"));
    }

    #[test]
    fn parse_asan_global_buffer_overflow_maps_to_bhf201() {
        let stderr = "==1==ERROR: AddressSanitizer: global-buffer-overflow on address 0xdead";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "BHF-201");
    }

    #[test]
    fn parse_asan_negative_size_param_maps_to_bhf201() {
        let stderr = "==1==ERROR: AddressSanitizer: negative-size-param: (size=-1)";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "BHF-201");
    }

    #[test]
    fn parse_asan_alloc_dealloc_mismatch_maps_to_bhf204() {
        let stderr = "==1==ERROR: AddressSanitizer: alloc-dealloc-mismatch (operator new vs free)";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "BHF-204");
    }

    #[test]
    fn parse_asan_captures_access_kind_read_vs_write_in_message() {
        // READ vs WRITE drives severity (info-disclosure vs memory corruption) and
        // is on a separate line; it must be folded into the report message.
        let write =
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50 at pc 0x6\n\
                     WRITE of size 8 at 0x50 thread T0\n    #0 0x6 in f /a.c:1\n";
        let m = parse_sanitizer_report(write).unwrap().message;
        assert!(m.contains("WRITE of size 8"), "got: {m}");
        assert!(
            !m.contains(" at 0x"),
            "noisy address dropped from access, got: {m}"
        );
        let read = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50 at pc 0x6\n\
                    READ of size 4 at 0x50 thread T0\n";
        assert!(parse_sanitizer_report(read)
            .unwrap()
            .message
            .contains("READ of size 4"));
        // No access line -> message is just the error line (unchanged behavior).
        let none = "==1==ERROR: AddressSanitizer: stack-use-after-return on address 0x7f";
        assert!(!parse_sanitizer_report(none)
            .unwrap()
            .message
            .contains("of size"));
    }

    #[test]
    fn parse_returns_none_for_clean_output() {
        assert!(parse_sanitizer_report("clean run, no errors").is_none());
    }

    #[test]
    fn parse_stack_frames_deduplicates_repeats_and_keeps_deeper_frames() {
        let stderr = "\
ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x1 in a /a.c:1
    #1 0x2 in b /a.c:2
    #2 0x3 in c /a.c:3
    #3 0x4 in d /a.c:4
    #4 0x5 in e /a.c:5
    #5 0x6 in f /a.c:6
    #6 0x7 in a /a.c:1
";
        let r = parse_sanitizer_report(stderr).unwrap();
        let names: Vec<&str> = r.stack.iter().map(|f| f.function.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d", "e", "f"]);
    }

    /// A heap-use-after-free report as clang 18 prints it: the crash stack, then
    /// the address description, then the `freed by` and `previously allocated
    /// by` stacks, each its own section.
    const ASAN_USE_AFTER_FREE: &str = "\
=================================================================
==7==ERROR: AddressSanitizer: heap-use-after-free on address 0x504000000054 at pc 0x63955aad1eb2 bp 0x7ffc90b151b0 sp 0x7ffc90b151a8
READ of size 4 at 0x504000000054 thread T0
    #0 0x63955aad1eb1 in Widget::parse_record(unsigned char const*) /src/widget/parser.cc:11:50
    #1 0x63955aad1f00 in bhf_run_one /work/harnesses/H-1/main.cpp:40:5
    #2 0x70481002a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #3 0x70481002a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #4 0x63955a9f8344 in _start (/work/harnesses/H-1/main+0x2c344) (BuildId: 77f846b4e182f35c0b68b778e8e92e529f5310a3)

0x504000000054 is located 4 bytes inside of 40-byte region [0x504000000050,0x504000000078)
freed by thread T0 here:
    #0 0x63955aa92efa in free (/work/harnesses/H-1/main+0xc6efa) (BuildId: 77f846b4e182f35c0b68b778e8e92e529f5310a3)
    #1 0x63955aad1d69 in Widget::reset() /src/widget/parser.cc:30:3

previously allocated by thread T0 here:
    #0 0x63955aa93193 in malloc (/work/harnesses/H-1/main+0xc7193) (BuildId: 77f846b4e182f35c0b68b778e8e92e529f5310a3)
    #1 0x63955aad1d56 in Widget::Widget() /src/widget/parser.cc:22:14

SUMMARY: AddressSanitizer: heap-use-after-free /src/widget/parser.cc:11:50 in Widget::parse_record(unsigned char const*)
Shadow bytes around the buggy address:
  0x503ffffffd80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
==7==ABORTING
";

    const ASAN_HEAP_OVERFLOW: &str = "\
==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000015 at pc 0x560cbeb6ebc9 bp 0x7ffe5987e150 sp 0x7ffe5987e148
READ of size 4 at 0x502000000015 thread T0
    #0 0x560cbeb6ebc8 in copy_at /src/widget/copy.c:9:41
    #1 0x560cbeb6ec00 in bhf_run_one /work/harnesses/H-2/main.c:12:3

0x502000000015 is located 0 bytes after 5-byte region [0x502000000010,0x502000000015)
allocated by thread T0 here:
    #0 0x560cbeb30193 in malloc (/work/harnesses/H-2/main+0xc7193) (BuildId: 77f846b4e182f35c0b68b778e8e92e529f5310a3)
    #1 0x560cbeb6ea90 in bhf_c_string /work/harnesses/H-2/bhf_decode.h:195:23
    #2 0x560cbeb6eb00 in bhf_run_one /work/harnesses/H-2/main.c:10:3

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/widget/copy.c:9:41 in copy_at
";

    #[test]
    fn asan_crash_stack_excludes_the_free_and_allocation_stacks() {
        let r = parse_sanitizer_report(ASAN_USE_AFTER_FREE).unwrap();
        let names: Vec<&str> = r.stack.iter().map(|f| f.function.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Widget::parse_record(unsigned char const*)",
                "bhf_run_one",
                "__libc_start_call_main",
                "__libc_start_main",
                "_start",
            ],
            "the crash stack is only the frames before the address description"
        );
    }

    #[test]
    fn asan_free_and_allocation_stacks_are_kept_apart() {
        let r = parse_sanitizer_report(ASAN_USE_AFTER_FREE).unwrap();
        let access = r.access.expect("a use-after-free records the access");
        let free: Vec<&str> = access
            .free_stack
            .iter()
            .map(|f| f.function.as_str())
            .collect();
        let alloc: Vec<&str> = access
            .alloc_stack
            .iter()
            .map(|f| f.function.as_str())
            .collect();
        assert_eq!(free, vec!["free", "Widget::reset()"]);
        assert_eq!(alloc, vec!["malloc", "Widget::Widget()"]);
        assert_eq!(access.direction, AccessDirection::Read);
        assert_eq!(access.size, Some(4));
        let region = access.region.expect("region");
        assert_eq!(region.kind, "heap");
        assert_eq!(region.size, Some(40));
        assert_eq!(region.relation.as_deref(), Some("inside"));
        assert_eq!(region.offset, Some(4));
    }

    #[test]
    fn a_deep_crash_stack_cannot_push_out_the_allocation_site() {
        let mut stderr = String::from(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n\
             WRITE of size 1 at 0x1 thread T0\n",
        );
        for i in 0..40 {
            stderr.push_str(&format!(
                "    #{i} 0x{i:x} in level_{i} /src/deep.c:{}\n",
                i + 1
            ));
        }
        stderr.push_str(
            "\n0x1 is located 0 bytes after 8-byte region [0x0,0x1)\n\
             allocated by thread T0 here:\n    #0 0x9 in malloc (/bin/h+0x9)\n    \
             #1 0xa in make_buffer /src/deep.c:99:3\n",
        );
        let r = parse_sanitizer_report(&stderr).unwrap();
        assert!(r.stack.iter().all(|f| f.function.starts_with("level_")));
        let access = r.access.unwrap();
        assert_eq!(access.direction, AccessDirection::Write);
        assert_eq!(access.alloc_stack[1].function, "make_buffer");
        assert_eq!(access.alloc_stack[1].line, Some(99));
    }

    #[test]
    fn asan_heap_overflow_records_region_size_offset_and_allocation_site() {
        let r = parse_sanitizer_report(ASAN_HEAP_OVERFLOW).unwrap();
        assert_eq!(r.stack.len(), 2);
        let access = r.access.expect("access");
        assert_eq!(access.direction, AccessDirection::Read);
        assert_eq!(access.size, Some(4));
        let region = access.region.expect("region");
        assert_eq!(region.kind, "heap");
        assert_eq!(region.size, Some(5));
        assert_eq!(region.relation.as_deref(), Some("after"));
        assert_eq!(region.distance, Some(0));
        // 0 bytes past the end of a 5-byte buffer is offset 5 from its start.
        assert_eq!(region.offset, Some(5));
        assert_eq!(access.alloc_stack[1].function, "bhf_c_string");
        assert_eq!(access.alloc_stack[2].line, Some(10));
        assert_eq!(
            r.location,
            Some(SourceLocation {
                file: "/src/widget/copy.c".to_owned(),
                line: 9,
                column: Some(41),
            }),
            "the SUMMARY names the crash site"
        );
    }

    #[test]
    fn asan_region_before_the_buffer_has_a_negative_offset() {
        let stderr = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000000f\n\
                      READ of size 1 at 0x50200000000f thread T0\n    #0 0x1 in f /a.c:1\n\n\
                      0x50200000000f is located 1 bytes before 16-byte region [0x502000000010,0x502000000020)\n";
        let region = parse_sanitizer_report(stderr)
            .unwrap()
            .access
            .unwrap()
            .region
            .unwrap();
        assert_eq!(region.relation.as_deref(), Some("before"));
        assert_eq!(region.distance, Some(1));
        assert_eq!(region.offset, Some(-1));
        assert_eq!(region.size, Some(16));
        // Older runtimes say "to the right of" instead of "after".
        let older = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n\
                     WRITE of size 2 at 0x1 thread T0\n\n\
                     0x1 is located 3 bytes to the right of 8-byte region [0x0,0x8)\n";
        let region = parse_sanitizer_report(older)
            .unwrap()
            .access
            .unwrap()
            .region
            .unwrap();
        assert_eq!(region.relation.as_deref(), Some("after"));
        assert_eq!(region.offset, Some(11));
    }

    /// Distances, sizes and frame offsets come from the target's stderr; values
    /// that do not fit a signed offset leave it unset instead of overflowing.
    #[test]
    fn region_numbers_too_large_for_an_offset_leave_it_unset() {
        let region_of = |stderr: &str| {
            parse_sanitizer_report(stderr)
                .unwrap()
                .access
                .unwrap()
                .region
                .unwrap()
        };
        let heap = |description: &str| {
            format!(
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n\
                 READ of size 1 at 0x1 thread T0\n    #0 0x1 in f /a.c:1\n\n\
                 0x1 is located {description} region [0x0,0x1)\n"
            )
        };
        let before = heap("9223372036854775809 bytes before 1-byte");
        let region = region_of(&before);
        assert_eq!(region.relation.as_deref(), Some("before"));
        assert_eq!(region.distance, Some(9_223_372_036_854_775_809));
        assert_eq!(region.offset, None);
        assert_eq!(relative_offset(&before), None);

        let after = heap("1 bytes after 9223372036854775807-byte");
        let region = region_of(&after);
        assert_eq!(region.size, Some(9_223_372_036_854_775_807));
        assert_eq!(region.offset, None);
        assert_eq!(relative_offset(&after), Some(1));

        let inside = heap("9223372036854775808 bytes inside of 1-byte");
        assert_eq!(region_of(&inside).offset, None);
        assert_eq!(relative_offset(&inside), None);

        // The largest distance before an object that still fits.
        let edge = heap("9223372036854775808 bytes before 1-byte");
        assert_eq!(region_of(&edge).offset, Some(i64::MIN));
        assert_eq!(relative_offset(&edge), Some(i64::MIN));

        let stack = "\
==3==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1 at pc 0x1 bp 0x1 sp 0x1
WRITE of size 1 at 0x1 thread T0
    #0 0x1 in parse_record /src/rec.c:13:37

Address 0x1 is located in stack of thread T0 at offset 18446744073709551615 in frame
    #0 0x1 in parse_record /src/rec.c:5

  This frame has 1 object(s):
    [1, 2) 'buf' (line 13) <== Memory access at offset 18446744073709551615 overflows this variable
";
        let region = region_of(stack);
        assert_eq!(region.frame_offset, Some(u64::MAX));
        assert_eq!(region.size, Some(1));
        assert_eq!(region.offset, None);
        assert_eq!(region.relation, None);
        assert_eq!(region.distance, None);
        assert_eq!(region.variable.as_deref(), Some("buf"));
        assert_eq!(relative_offset(stack), None);
    }

    #[test]
    fn asan_stack_overflow_records_the_overflowed_variable() {
        let stderr = "\
==3==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x71b444a00024 at pc 0x5b82 bp 0x7ffe sp 0x7ffe
WRITE of size 1 at 0x71b444a00024 thread T0
    #0 0x5b8237b350e0 in parse_record /src/widget/rec.c:13:37
    #1 0x5b8237b35100 in bhf_run_one /work/harnesses/H-3/main.c:20:3

Address 0x71b444a00024 is located in stack of thread T0 at offset 36 in frame
    #0 0x5b8237b34747 in parse_record /src/widget/rec.c:5

  This frame has 2 object(s):
    [32, 36) 'buf' (line 13) <== Memory access at offset 36 overflows this variable
    [48, 56) 'b' (line 19)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
SUMMARY: AddressSanitizer: stack-buffer-overflow /src/widget/rec.c:13:37 in parse_record
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(
            r.stack.len(),
            2,
            "the frame holding the object is not a crash frame"
        );
        let access = r.access.unwrap();
        assert_eq!(access.direction, AccessDirection::Write);
        let region = access.region.unwrap();
        assert_eq!(region.kind, "stack");
        assert_eq!(region.variable.as_deref(), Some("buf"));
        assert_eq!(region.size, Some(4));
        assert_eq!(region.offset, Some(4));
        assert_eq!(region.relation.as_deref(), Some("after"));
        assert_eq!(region.distance, Some(0));
        assert_eq!(region.frame_offset, Some(36));
        assert_eq!(access.alloc_stack[0].function, "parse_record");
        assert_eq!(relative_offset(stderr), Some(36));
    }

    #[test]
    fn asan_global_overflow_records_the_global_variable() {
        let stderr = "\
==4==ERROR: AddressSanitizer: global-buffer-overflow on address 0x5b2ba4b65f88 at pc 0x5b2b bp 0x7ffe sp 0x7ffe
READ of size 4 at 0x5b2ba4b65f88 thread T0
    #0 0x5b2ba41d62d3 in lookup /src/widget/table.c:14:20

0x5b2ba4b65f88 is located 0 bytes after global variable 'table' defined in '/src/widget/table.c:4' (0x5b2ba4b65f60) of size 40
SUMMARY: AddressSanitizer: global-buffer-overflow /src/widget/table.c:14:20 in lookup
";
        let region = parse_sanitizer_report(stderr)
            .unwrap()
            .access
            .unwrap()
            .region
            .unwrap();
        assert_eq!(region.kind, "global");
        assert_eq!(region.variable.as_deref(), Some("table"));
        assert_eq!(region.size, Some(40));
        assert_eq!(region.offset, Some(40));
        assert_eq!(region.relation.as_deref(), Some("after"));
    }

    #[test]
    fn asan_segv_records_direction_address_and_hint_tokens() {
        let stderr = "\
AddressSanitizer:DEADLYSIGNAL
==5==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010 (pc 0x5e04 bp 0x7ffd sp 0x7ffd T0)
==5==The signal is caused by a WRITE memory access.
==5==Hint: address points to the zero page.
    #0 0x5e0421df53ca in set_field /src/widget/obj.c:15:54
";
        let access = parse_sanitizer_report(stderr).unwrap().access.unwrap();
        assert_eq!(access.direction, AccessDirection::Write);
        assert_eq!(access.address.as_deref(), Some("0x000000000010"));
        assert_eq!(access.address_hint.as_deref(), Some("zero-page"));
        let high = "\
==6==ERROR: AddressSanitizer: SEGV on unknown address (pc 0x64e1 bp 0x7fff sp 0x7fff T0)
==6==The signal is caused by a READ memory access.
==6==Hint: this fault was caused by a dereference of a high value address (see register values below).  Disassemble the provided pc to learn which register was used.
    #0 0x64e1a60d65d0 in store_word /src/widget/obj.c:18:73
";
        let access = parse_sanitizer_report(high).unwrap().access.unwrap();
        assert_eq!(access.address, None);
        assert_eq!(access.address_hint.as_deref(), Some("high-value-address"));
        // The direction is a token: a "thread" in the message is not a READ.
        let unknown = "==7==ERROR: AddressSanitizer: SEGV on unknown address 0x7f0000001000 (pc 0x1 bp 0x2 sp 0x3 T0)\n\
                       ==7==The signal is caused by a UNKNOWN memory access.\n";
        let access = parse_sanitizer_report(unknown).unwrap().access.unwrap();
        assert_eq!(access.direction, AccessDirection::Unknown);
    }

    /// UBSan with `print_stacktrace=1` and `report_error_type=1`, as clang 18
    /// prints it.
    const UBSAN_SHIFT: &str = "\
src/widget/bits.c:5:15: runtime error: shift exponent 40 is too large for 32-bit type 'int'
    #0 0x5c2a0657bbab in shift_by(int, int) /work/src/widget/bits.c:5:15
    #1 0x5c2a0657c2c3 in bhf_run_one /work/harnesses/H-4/main.cpp:15:18
    #2 0x7b0cfbc2a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

SUMMARY: UndefinedBehaviorSanitizer: invalid-shift-exponent src/widget/bits.c:5:15 
";

    #[test]
    fn ubsan_report_records_its_location_and_check_name() {
        let r = parse_sanitizer_report(UBSAN_SHIFT).unwrap();
        assert_eq!(
            r.location,
            Some(SourceLocation {
                file: "src/widget/bits.c".to_owned(),
                line: 5,
                column: Some(15),
            })
        );
        assert_eq!(r.check.as_deref(), Some("invalid-shift-exponent"));
        assert_eq!(r.stack.len(), 3);
        assert_eq!(r.stack[0].function, "shift_by(int, int)");
        // Without report_error_type=1 the SUMMARY names no check.
        let generic = "/src/a.c:3:5: runtime error: execution reached the end of a value-returning function without returning a value\n\
                       SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/a.c:3:5 in \n";
        let r = parse_sanitizer_report(generic).unwrap();
        assert_eq!(r.check, None);
        assert_eq!(r.location.as_ref().map(|l| l.line), Some(3));
        assert!(r.stack.is_empty());
    }

    #[test]
    fn ubsan_stack_stops_at_the_end_of_its_report() {
        // A second, unrelated stack later in the log is not this report's stack.
        let stderr = format!(
            "{UBSAN_SHIFT}\n==1==ERROR: LeakSanitizer: detected memory leaks\n\n\
             Direct leak of 4 byte(s) in 1 object(s) allocated from:\n    \
             #0 0x1 in malloc (/bin/h+0x1)\n    #1 0x2 in leaky /src/l.c:3\n"
        );
        let r = parse_sanitizer_report(&stderr).unwrap();
        assert_eq!(r.sanitizer, Some(Sanitizer::UndefinedBehaviorSanitizer));
        assert!(
            r.stack.iter().all(|f| f.function != "leaky"),
            "{:?}",
            r.stack
        );
    }

    fn ubsan_report(message: &str, check: Option<&str>) -> String {
        let summary = check.unwrap_or("undefined-behavior");
        format!(
            "/src/widget/w.cc:7:9: runtime error: {message}\n    \
             #0 0x1 in parse_record /src/widget/w.cc:7:9\n\n\
             SUMMARY: UndefinedBehaviorSanitizer: {summary} /src/widget/w.cc:7:9 \n"
        )
    }

    /// Each UBSan check is its own kind and rule, whether the kind comes from
    /// UBSan's check name (report_error_type=1) or from the report text.
    #[test]
    fn every_ubsan_check_parses_to_its_own_kind_and_rule() {
        for (message, check, kind, rule) in [
            ("shift exponent 40 is too large for 32-bit type 'int'", "invalid-shift-exponent", "invalid-shift", "BHF-215"),
            ("left shift of negative value -5", "invalid-shift-base", "invalid-shift", "BHF-215"),
            ("execution reached the end of a value-returning function without returning a value", "missing-return", "missing-return", "BHF-214"),
            ("load of null pointer of type 'int'", "null-pointer-use", "null-pointer-dereference", "BHF-206"),
            ("index 10 out of bounds for type 'int[4]'", "out-of-bounds-index", "out-of-bounds-access", "BHF-220"),
            ("signed integer overflow: 2147483647 + 5 cannot be represented in type 'int'", "signed-integer-overflow", "signed-integer-overflow", "BHF-205"),
            ("division by zero", "integer-divide-by-zero", "division-by-zero", "BHF-222"),
            ("1e+20 is outside the range of representable values of type 'int'", "float-cast-overflow", "float-cast-overflow", "BHF-218"),
            ("load of value 7, which is not a valid value for type 'bool'", "invalid-bool-load", "invalid-value-load", "BHF-217"),
            ("load of value 9, which is not a valid value for type 'Color'", "invalid-enum-load", "invalid-value-load", "BHF-217"),
            ("execution reached an unreachable program point", "unreachable-call", "unreachable", "BHF-216"),
            ("variable length array bound evaluates to non-positive value -1", "non-positive-vla-index", "invalid-vla-bound", "BHF-224"),
            ("implicit conversion from type 'long long' of value 1099511627776 (64-bit, signed) to type 'int' changed the value to 0 (32-bit, signed)", "implicit-signed-integer-truncation", "implicit-conversion", "BHF-225"),
            ("load of misaligned address 0x7c3938b00021 for type 'int', which requires 4 byte alignment", "misaligned-pointer-use", "misaligned-access", "BHF-226"),
            ("load of address 0x7ffc8f3e2c10 with insufficient space for an object of type 'int'", "insufficient-object-size", "insufficient-object-size", "BHF-227"),
            ("passing zero to __builtin_clz(), which is not a valid argument", "invalid-builtin-use", "invalid-builtin-use", "BHF-228"),
            ("null pointer passed as argument 1, which is declared to never be null", "invalid-null-argument", "null-pointer-dereference", "BHF-206"),
            ("pointer index expression with base 0x7fffffffffff overflowed to 0x80000000fffe", "pointer-overflow", "pointer-overflow", "BHF-219"),
            ("call to function parse_record through pointer to incorrect function type 'int (*)(void)'", "function-type-mismatch", "type-mismatch", "BHF-221"),
        ] {
            for summary in [Some(check), None] {
                let r = parse_sanitizer_report(&ubsan_report(message, summary)).unwrap();
                assert_eq!(r.kind, kind, "{message} ({summary:?})");
                assert_eq!(r.rule_id, rule, "{message} ({summary:?})");
                assert_ne!(r.rule_id, "BHF-210");
            }
        }
    }

    #[test]
    fn the_ubsan_check_name_wins_over_unfamiliar_report_text() {
        let r = parse_sanitizer_report(&ubsan_report(
            "a phrasing a future runtime might print",
            Some("missing-return"),
        ))
        .unwrap();
        assert_eq!((r.kind.as_str(), r.rule_id), ("missing-return", "BHF-214"));
    }

    /// Classification reads the text after `runtime error:`, never the source
    /// path before it.
    #[test]
    fn a_source_path_never_classifies_a_ubsan_report() {
        let stderr = "/src/division_by_zero/index_out_of_bounds/zoom_timeout.c:3:5: runtime error: \
                      execution reached the end of a value-returning function without returning a value\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.kind, "missing-return");
    }

    fn segv(address: &str, direction: &str, hint: &str) -> SanitizerReport {
        parse_sanitizer_report(&format!(
            "==1==ERROR: AddressSanitizer: SEGV on unknown address {address}(pc 0x55 bp 0x1 sp 0x2 T0)\n\
             ==1==The signal is caused by a {direction} memory access.\n{hint}    \
             #0 0x55 in store_word /src/widget/obj.c:18:73\n"
        ))
        .unwrap()
    }

    /// A NULL dereference faults in the first page; every other SEGV is a wild
    /// or corrupted pointer, a different defect with its own rule.
    #[test]
    fn segv_null_page_and_wild_address_have_different_rules() {
        let zero_page = "==1==Hint: address points to the zero page.\n";
        assert_eq!(
            segv("0x000000000000 ", "READ", zero_page).rule_id,
            "BHF-206"
        );
        assert_eq!(
            segv("0x000000000010 ", "WRITE", zero_page).rule_id,
            "BHF-206"
        );
        assert_eq!(segv("0x000000000ff8 ", "READ", "").rule_id, "BHF-206");
        let wild = segv("0x7f0000001000 ", "WRITE", "");
        assert_eq!(wild.rule_id, "BHF-223");
        assert_eq!(wild.access.unwrap().direction, AccessDirection::Write);
        // A non-canonical address faults before the access direction is
        // known; ASan's READ is then not a direction.
        let high = segv(
            "",
            "READ",
            "==1==Hint: this fault was caused by a dereference of a high value address (see register values below).\n",
        );
        assert_eq!(high.rule_id, "BHF-223");
        assert!(
            high.message
                .ends_with("(READ memory access; high value address)"),
            "{}",
            high.message
        );
        let access = high.access.unwrap();
        assert_eq!(access.direction, AccessDirection::Unknown);
        assert_eq!(access.address_hint.as_deref(), Some("high-value-address"));
    }

    /// The rule an earlier release recorded for the same report, so a replay
    /// of an older finding still matches.
    #[test]
    fn legacy_rule_ids_cover_reports_whose_rule_changed() {
        let ub = |message: &str| parse_sanitizer_report(&ubsan_report(message, None)).unwrap();
        for (report, legacy) in [
            (ub("execution reached the end of a value-returning function without returning a value"), Some("BHF-210")),
            (ub("shift exponent 40 is too large for 32-bit type 'int'"), Some("BHF-210")),
            (ub("index 10 out of bounds for type 'int[4]'"), Some("BHF-201")),
            (ub("division by zero"), Some("BHF-205")),
            (ub("load of null pointer of type 'int'"), None),
            // Earlier releases sent any "cannot be represented in type" text to
            // the overflow rule, a shift report included.
            (
                ub("left shift of 1 by 31 places cannot be represented in type 'int'"),
                Some("BHF-205"),
            ),
            (
                ub("left shift of negative value -5"),
                Some("BHF-210"),
            ),
            // ...and had no NULL arm for a member call.
            (
                ub("member call on null pointer of type 'Widget'"),
                Some("BHF-210"),
            ),
            (ub("applying non-zero offset 8 to null pointer"), None),
            (segv("0x7f0000001000 ", "WRITE", ""), Some("BHF-206")),
        ] {
            assert_eq!(legacy_rule_id(&report), legacy, "{}", report.message);
        }
        let heap = parse_sanitizer_report(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n",
        )
        .unwrap();
        assert_eq!(
            legacy_rule_id(&heap),
            None,
            "unchanged rules have no legacy id"
        );
        assert!(rule_matches(
            "BHF-210",
            &ub("execution reached an unreachable program point")
        ));
        assert!(rule_matches(
            "BHF-216",
            &ub("execution reached an unreachable program point")
        ));
        assert!(!rule_matches(
            "BHF-202",
            &ub("execution reached an unreachable program point")
        ));
    }
}
