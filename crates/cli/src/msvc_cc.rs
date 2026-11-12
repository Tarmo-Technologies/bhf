// SPDX-License-Identifier: Apache-2.0

//! `bhf-cl`: bhf's front end for MSVC `cl.exe` (and `clang-cl`).
//!
//! Every generated harness Makefile, per-translation-unit fragment and repair
//! step speaks the GCC command-line dialect (`-I`, `-iquote`, `-include`,
//! `-o`, `-c -o x.o`, `-fsanitize-coverage=...`, `-Wl,--gc-sections`).
//! Rather than a second spelling of each, the MSVC lane points `CC`/`CXX` at
//! this front end: a hard link (or copy) of the `bhf` executable named
//! `bhf-cl`, which reads those command lines, runs the real `cl.exe` with the
//! equivalent options, and rewrites cl's diagnostics into the clang shapes
//! the repair loop reads (`'x.h' file not found`, `use of undeclared
//! identifier`, `undefined reference to`).
//!
//! The coverage flags become MSVC's SanitizerCoverage subset
//! (`/fsanitize-coverage=inline-8bit-counters`, `edge`, `trace-cmp`,
//! `trace-div`); the link adds `libsancov.lib`, whose start-up code hands the
//! counters to the driver's exported `__sanitizer_cov_8bit_counters_init`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The file stem the `bhf` executable answers to as the cl front end.
pub(crate) const FRONT_END_STEM: &str = "bhf-cl";
/// The real compiler the front end runs: `cl.exe` (default) or `clang-cl`.
pub(crate) const REAL_COMPILER_ENV: &str = "BHF_MSVC_CL";

/// What one GCC-style command line becomes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClCommand {
    /// The compiler arguments, without the program.
    pub args: Vec<String>,
    /// For a compile-and-link line: the options before the inputs, the
    /// translation units, and everything from `/link` on — so sources whose
    /// object names would collide can be compiled one at a time.
    pub split: Option<SplitLink>,
    /// `-idirafter` dirs: searched after the system headers, so they are
    /// appended to the child's `INCLUDE` rather than passed as `/I`.
    pub include_after: Vec<String>,
    /// Sources given as `-` (stdin), to be written to a file first.
    pub stdin_source: Option<&'static str>,
    /// The macro list a `-dM -E` probe asks for, answered without running cl.
    pub predefined_macros_probe: bool,
}

/// A compile-and-link line in parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SplitLink {
    pub compile_args: Vec<String>,
    pub sources: Vec<String>,
    pub other_inputs: Vec<String>,
    pub output: Option<String>,
    pub link_tail: Vec<String>,
}

impl SplitLink {
    /// Whether two translation units share a file stem: cl names each object
    /// after its source, so one would overwrite the other.
    pub fn has_colliding_objects(&self) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        self.sources.iter().any(|source| {
            let stem = Path::new(source)
                .file_stem()
                .map(|stem| stem.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            !seen.insert(stem)
        })
    }
}

/// The real compiler's dialect: cl itself, or clang-cl (which runs clang's own
/// coverage instrumentation and needs no `libsancov.lib`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Cl,
    ClangCl,
}

impl Backend {
    pub(crate) fn for_compiler(compiler: &str) -> Self {
        match harness_gen::compiler_family::driver_base_name(compiler) {
            Some("clang-cl") => Self::ClangCl,
            _ => Self::Cl,
        }
    }
}

fn is_source(arg: &str) -> bool {
    matches!(
        Path::new(arg).extension().and_then(|e| e.to_str()),
        Some("c" | "cc" | "cpp" | "cxx" | "c++" | "C")
    )
}

fn is_cpp_source(arg: &str) -> bool {
    matches!(
        Path::new(arg).extension().and_then(|e| e.to_str()),
        Some("cc" | "cpp" | "cxx" | "c++" | "C")
    )
}

/// The cl `/std:` for a GCC `-std=` value; `None` for a standard cl reads by
/// default (C89/C99 are MSVC's default C) or does not have.
fn cl_standard(standard: &str) -> Option<&'static str> {
    let standard = standard.trim();
    if let Some(cxx) = standard
        .strip_prefix("c++")
        .or_else(|| standard.strip_prefix("gnu++"))
    {
        return Some(match cxx {
            "98" | "03" | "0x" | "11" | "1y" | "14" => "/std:c++14",
            "1z" | "17" => "/std:c++17",
            "2a" | "20" => "/std:c++20",
            _ => "/std:c++latest",
        });
    }
    let c = standard
        .strip_prefix("gnu")
        .or_else(|| standard.strip_prefix("iso9899:"))
        .or_else(|| standard.strip_prefix('c'))
        .unwrap_or(standard);
    match c {
        "11" | "1x" | "2011" => Some("/std:c11"),
        "17" | "18" | "2017" | "2018" => Some("/std:c17"),
        "2x" | "23" | "2y" => Some("/std:clatest"),
        _ => None,
    }
}

/// The `foo.lib` a `-lfoo` names, or `None` for a POSIX runtime library the
/// MSVC CRT already provides.
fn import_library(name: &str) -> Option<String> {
    match name {
        "m" | "c" | "pthread" | "dl" | "rt" | "stdc++" | "c++" | "gcc" | "gcc_s" | "util" => None,
        name if name.to_ascii_lowercase().ends_with(".lib") => Some(name.to_owned()),
        name => Some(format!("{name}.lib")),
    }
}

/// Translate one GCC-style command line into cl's.
pub(crate) fn translate(gnu: &[String], backend: Backend) -> Result<ClCommand, String> {
    let mut out = ClCommand::default();
    let mut compile_args: Vec<String> = vec!["/nologo".to_owned(), "/utf-8".to_owned()];
    let mut inputs: Vec<String> = Vec::new();
    let mut link_args: Vec<String> = Vec::new();
    let mut output: Option<String> = None;
    let mut compile_only = false;
    let mut syntax_only = false;
    let mut preprocess = false;
    let mut defines_probe = false;
    let mut debug = false;
    let mut coverage = false;
    let mut cpp_mode: Option<bool> = None;
    let mut exceptions = true;
    let mut index = 0;
    let operand = |index: &mut usize, attached: &str| -> Result<String, String> {
        if !attached.is_empty() {
            return Ok(attached.to_owned());
        }
        *index += 1;
        gnu.get(*index)
            .cloned()
            .ok_or_else(|| format!("option {} needs a value", gnu[*index - 1]))
    };
    while index < gnu.len() {
        let arg = gnu[index].as_str();
        match arg {
            "-c" => compile_only = true,
            "-E" => preprocess = true,
            "-dM" => defines_probe = true,
            "-fsyntax-only" => syntax_only = true,
            "-" => inputs.push("-".to_owned()),
            "-o" => output = Some(operand(&mut index, "")?),
            "-O0" | "-Og" => compile_args.push("/Od".to_owned()),
            "-O" | "-O1" | "-Os" | "-Oz" => compile_args.push("/O1".to_owned()),
            "-O2" | "-O3" | "-O4" | "-Ofast" => compile_args.push("/O2".to_owned()),
            "-g0" => debug = false,
            "-x" => match operand(&mut index, "")?.as_str() {
                "c" => cpp_mode = Some(false),
                "c++" => cpp_mode = Some(true),
                _ => cpp_mode = None,
            },
            "-ffunction-sections" => compile_args.push("/Gy".to_owned()),
            "-fdata-sections" => compile_args.push("/Gw".to_owned()),
            "-fno-omit-frame-pointer" => compile_args.push("/Oy-".to_owned()),
            "-fexceptions" => exceptions = true,
            "-fno-exceptions" => exceptions = false,
            "-fno-rtti" => compile_args.push("/GR-".to_owned()),
            "-frtti" => compile_args.push("/GR".to_owned()),
            "-funsigned-char" => compile_args.push("/J".to_owned()),
            "-fno-wchar" => compile_args.push("/Zc:wchar_t-".to_owned()),
            "-w" => compile_args.push("/w".to_owned()),
            "-mavx" => compile_args.push("/arch:AVX".to_owned()),
            "-mavx2" => compile_args.push("/arch:AVX2".to_owned()),
            "-mavx512f" => compile_args.push("/arch:AVX512".to_owned()),
            // Options with a separate operand that cl has no use for.
            "-MF" | "-MT" | "-MQ" | "-target" | "-isysroot" | "-Xclang" | "-arch"
            | "-dependency-file" => {
                index += 1;
            }
            "-Xlinker" => {
                let value = operand(&mut index, "")?;
                link_args.extend(linker_option(&value));
            }
            "-L" => link_args.push(format!("/LIBPATH:{}", operand(&mut index, "")?)),
            "-l" => {
                if let Some(lib) = import_library(&operand(&mut index, "")?) {
                    inputs.push(lib);
                }
            }
            "-I" | "-iquote" | "-isystem" => {
                compile_args.push("/I".to_owned());
                compile_args.push(operand(&mut index, "")?);
            }
            "-idirafter" => out.include_after.push(operand(&mut index, "")?),
            "-include" | "-imacros" => {
                compile_args.push("/FI".to_owned());
                compile_args.push(operand(&mut index, "")?);
            }
            "-D" => compile_args.push(format!("/D{}", operand(&mut index, "")?)),
            "-U" => compile_args.push(format!("/U{}", operand(&mut index, "")?)),
            _ if arg.starts_with("-g") => debug = true,
            _ if arg.starts_with("-iquote") => {
                compile_args.push("/I".to_owned());
                compile_args.push(arg["-iquote".len()..].to_owned());
            }
            _ if arg.starts_with("-isystem") => {
                compile_args.push("/I".to_owned());
                compile_args.push(arg["-isystem".len()..].to_owned());
            }
            _ if arg.starts_with("-idirafter") => {
                out.include_after.push(arg["-idirafter".len()..].to_owned());
            }
            _ if arg.starts_with("-I") => {
                compile_args.push("/I".to_owned());
                compile_args.push(arg[2..].to_owned());
            }
            _ if arg.starts_with("-D") => compile_args.push(format!("/D{}", &arg[2..])),
            _ if arg.starts_with("-U") => compile_args.push(format!("/U{}", &arg[2..])),
            _ if arg.starts_with("-o") => output = Some(arg[2..].to_owned()),
            _ if arg.starts_with("-std=") => {
                if let Some(standard) = cl_standard(&arg["-std=".len()..]) {
                    compile_args.push(standard.to_owned());
                }
            }
            _ if arg.starts_with("-fpack-struct=") => {
                compile_args.push(format!("/Zp{}", &arg["-fpack-struct=".len()..]));
            }
            _ if arg.starts_with("-fsanitize=") => {
                for sanitizer in arg["-fsanitize=".len()..].split(',') {
                    match sanitizer {
                        "address" => compile_args.push("/fsanitize=address".to_owned()),
                        "fuzzer" => compile_args.push("/fsanitize=fuzzer".to_owned()),
                        // cl has no UBSan, MSan, TSan or LSan.
                        _ => {}
                    }
                }
            }
            _ if arg.starts_with("-fsanitize-coverage=") => {
                for kind in arg["-fsanitize-coverage=".len()..].split(',') {
                    match kind {
                        "inline-8bit-counters"
                        | "trace-pc-guard"
                        | "inline-bool-flag"
                        | "edge"
                        | "trace-cmp"
                        | "trace-div" => {
                            coverage = true;
                            compile_args.push(format!("/fsanitize-coverage={kind}"));
                        }
                        // GCC's `trace-pc` has no cl spelling; the counters
                        // give the same edge map.
                        "trace-pc" => {
                            coverage = true;
                            compile_args
                                .push("/fsanitize-coverage=inline-8bit-counters".to_owned());
                        }
                        _ => {}
                    }
                }
            }
            _ if arg.starts_with("-Wl,") => {
                for value in arg["-Wl,".len()..].split(',') {
                    link_args.extend(linker_option(value));
                }
            }
            _ if arg.starts_with("-L") => link_args.push(format!("/LIBPATH:{}", &arg[2..])),
            _ if arg.starts_with("-l") => {
                if let Some(lib) = import_library(&arg[2..]) {
                    inputs.push(lib);
                }
            }
            _ if arg.starts_with("-x") => {
                cpp_mode = match &arg[2..] {
                    "c" => Some(false),
                    "c++" => Some(true),
                    _ => None,
                };
            }
            // cl-spelled options (from an operator's flags) pass through.
            _ if arg.starts_with('/') && arg.len() > 1 && !Path::new(arg).exists() => {
                compile_args.push(arg.to_owned());
            }
            // Everything else GCC-specific has no cl meaning here: warnings
            // (`-W...`, `-pedantic`), code generation (`-f...`, `-m...`),
            // `-pthread`, `-static-lib...`, `--target=`, `--sysroot=`,
            // dependency output (`-MD`), `-fPIC`.
            _ if arg.starts_with('-') => {}
            _ => inputs.push(arg.to_owned()),
        }
        index += 1;
    }

    if defines_probe && preprocess {
        out.predefined_macros_probe = true;
        return Ok(out);
    }
    if debug {
        compile_args.push("/Z7".to_owned());
    }
    let any_cpp = cpp_mode == Some(true) || inputs.iter().any(|input| is_cpp_source(input));
    if any_cpp && exceptions {
        compile_args.push("/EHsc".to_owned());
    }
    match cpp_mode {
        Some(true) => compile_args.push("/TP".to_owned()),
        Some(false) => compile_args.push("/TC".to_owned()),
        None => {}
    }
    if inputs.iter().any(|input| input == "-") {
        out.stdin_source = Some(if cpp_mode == Some(true) { "cpp" } else { "c" });
    }
    let links = !(compile_only || syntax_only || preprocess);
    if syntax_only {
        compile_args.push("/Zs".to_owned());
    } else if preprocess {
        compile_args.push("/E".to_owned());
    } else if compile_only {
        compile_args.push("/c".to_owned());
        if let Some(output) = &output {
            compile_args.push(format!("/Fo:{output}"));
        }
    } else if let Some(output) = &output {
        compile_args.push(format!("/Fe:{output}"));
    }
    out.args = compile_args.clone();
    let mut sources = Vec::new();
    let mut other_inputs = Vec::new();
    for input in inputs {
        // cl reads `.c`/`.cpp`/`.cxx`/`.cc` by extension; other C++
        // spellings need `/Tp`.
        let word = if input.ends_with(".c++") || input.ends_with(".C") {
            format!("/Tp{input}")
        } else {
            input.clone()
        };
        if is_source(&input) {
            sources.push(word.clone());
        } else {
            other_inputs.push(word.clone());
        }
        out.args.push(word);
    }
    if links {
        let mut tail = vec![
            "/link".to_owned(),
            "/DEBUG".to_owned(),
            "/INCREMENTAL:NO".to_owned(),
        ];
        if coverage && backend == Backend::Cl {
            // Its start-up code finds the driver's exported
            // `__sanitizer_cov_8bit_counters_init` and hands it the counters.
            tail.push("libsancov.lib".to_owned());
        }
        tail.extend(link_args);
        out.args.extend(tail.iter().cloned());
        out.split = Some(SplitLink {
            compile_args: compile_args
                .into_iter()
                .filter(|arg| !arg.starts_with("/Fe:"))
                .collect(),
            sources,
            other_inputs,
            output,
            link_tail: tail,
        });
    }
    Ok(out)
}

/// The cl runs for a compile-and-link line whose sources would overwrite each
/// other's objects: each source compiled to its own numbered object in
/// `object_dir`, then one link of those objects.
pub(crate) fn split_commands(split: &SplitLink, object_dir: &Path) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut objects = Vec::new();
    for (index, source) in split.sources.iter().enumerate() {
        let stem = Path::new(source.trim_start_matches("/Tp"))
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "source".to_owned());
        // `/` on every host: cl reads it, and the name is the same everywhere.
        let object = format!("{}/{index}_{stem}.obj", object_dir.display());
        let mut command = split.compile_args.clone();
        command.push("/c".to_owned());
        command.push(format!("/Fo:{object}"));
        command.push(source.clone());
        commands.push(command);
        objects.push(object);
    }
    let mut link = split
        .compile_args
        .iter()
        .filter(|arg| arg.starts_with("/fsanitize") || *arg == "/nologo" || arg.starts_with("/Z7"))
        .cloned()
        .collect::<Vec<_>>();
    if let Some(output) = &split.output {
        link.push(format!("/Fe:{output}"));
    }
    link.extend(objects);
    link.extend(split.other_inputs.iter().cloned());
    link.extend(split.link_tail.iter().cloned());
    commands.push(link);
    commands
}

/// One `-Wl,` value as link.exe options.
fn linker_option(value: &str) -> Vec<String> {
    match value {
        "--gc-sections" | "-dead_strip" => vec!["/OPT:REF".to_owned()],
        value if value.starts_with('/') => vec![value.to_owned()],
        value if value.starts_with("-L") => vec![format!("/LIBPATH:{}", &value[2..])],
        // `--as-needed`, `--start-group`, `-rpath`, `-z`, ... have no link.exe
        // meaning.
        _ => Vec::new(),
    }
}

/// Rewrite one line of cl/link output into the clang shape bhf's build-error
/// classifier and repair loop read, or `None` to keep it as it is. The
/// original line is kept beside it, so a reader sees cl's own words too.
pub(crate) fn clang_style_diagnostic(line: &str) -> Option<String> {
    // `path(12): error C2065: 'NAME': undeclared identifier`
    // `path(12,5): fatal error C1083: Cannot open include file: 'x.h': No such file or directory`
    let (location, rest) = split_location(line)?;
    let (severity, code, message) = split_code(rest)?;
    let quoted = |text: &str| -> Option<String> {
        let start = text.find('\'')? + 1;
        let end = start + text[start..].find('\'')?;
        Some(text[start..end].to_owned())
    };
    let clang = match code {
        "C1083" => format!("fatal error: '{}' file not found", quoted(message)?),
        "C2065" | "C3861" => format!("error: use of undeclared identifier '{}'", quoted(message)?),
        "C2061" => format!(
            "error: unknown type name '{}'",
            message.rsplit_once(' ').map(|(_, name)| name).unwrap_or(message).trim_matches('\'')
        ),
        "C4013" => format!(
            "error: call to undeclared function '{}'; ISO C99 and later do not support implicit function declarations",
            quoted(message)?
        ),
        "C1189" => format!(
            "error: {}",
            message.trim_start_matches("#error:").trim()
        ),
        _ => return None,
    };
    let _ = severity;
    Some(format!("{location}: {clang}"))
}

/// `path(12)` / `path(12,5)` at the start of a cl diagnostic, as `path:12:5`,
/// and the remainder after `: `.
fn split_location(line: &str) -> Option<(String, &str)> {
    let open = line
        .find("): ")
        .and_then(|close| line[..close].rfind('(').map(|open| (open, close)))?;
    let (open, close) = open;
    let path = &line[..open];
    let position = &line[open + 1..close];
    let (row, column) = match position.split_once(',') {
        Some((row, column)) => (row, column),
        None => (position, "1"),
    };
    if path.is_empty()
        || !row.chars().all(|c| c.is_ascii_digit())
        || !column.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((
        format!("{}:{row}:{column}", path.replace('\\', "/")),
        &line[close + 3..],
    ))
}

/// `error C2065: message` -> (`error`, `C2065`, `message`).
fn split_code(rest: &str) -> Option<(&str, &str, &str)> {
    let (head, message) = rest.split_once(": ")?;
    let mut words = head.split_whitespace();
    let code = words.next_back()?;
    let severity = words.collect::<Vec<_>>().join(" ");
    if !(code.len() == 5 && code.starts_with('C') && code[1..].chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let severity = match severity.as_str() {
        "error" | "fatal error" => "error",
        "warning" => "warning",
        _ => return None,
    };
    Some((severity, code, message.trim()))
}

/// cl has no weak symbols. bhf's repair stubs are weak (`__attribute__((weak))`)
/// so a real definition, if one turns up, wins; MSVC's equivalent is an
/// alternate name: the stub is defined under a private name, and the linker
/// uses it for the real name only when nothing else defines that. A weak
/// declaration (`extern T f(...) __attribute__((weak));`, tested for null
/// before a call) gets a default that returns zero, which is what the null
/// branch produces. A weak C++ definition (a mangled name) is made a plain
/// definition. `underscore` is the x86 C name decoration.
pub(crate) fn msvc_weak_symbols(source: &str, cpp: bool, underscore: bool) -> String {
    const WEAK: &str = "__attribute__((weak))";
    let decorate = |name: &str| {
        if underscore {
            format!("_{name}")
        } else {
            name.to_owned()
        }
    };
    let is_identifier = |name: &str| {
        !name.is_empty()
            && name
                .bytes()
                .enumerate()
                .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
    };
    let mut out = String::with_capacity(source.len() + 256);
    for line in source.split_inclusive('\n') {
        if !line.contains(WEAK) {
            out.push_str(line);
            continue;
        }
        let body = line.trim_end_matches(['\r', '\n']);
        let newline = &line[body.len()..];
        let plain = body.replace(WEAK, "").replace("  ", " ").replace(" ;", ";");
        let plain = plain.trim();
        if cpp {
            out.push_str(plain);
            out.push_str(newline);
            continue;
        }
        let renamed = |text: &str, name: &str, private: &str| -> String {
            // Replace the declarator name only: the identifier before `(`,
            // `[` or ` =`.
            let at = text
                .find(&format!("{name}("))
                .or_else(|| text.find(&format!("{name}[")))
                .or_else(|| text.find(&format!("{name} =")));
            match at {
                Some(at) => format!("{}{private}{}", &text[..at], &text[at + name.len()..]),
                None => text.to_owned(),
            }
        };
        let alternate = |name: &str, private: &str| {
            format!(
                "#pragma comment(linker, \"/alternatename:{}={}\")\n",
                decorate(name),
                decorate(private)
            )
        };
        if plain.starts_with("extern") && plain.ends_with(';') && plain.contains('(') {
            // A weak declaration: give it a zero-returning default.
            let head = &plain[..plain.find('(').unwrap_or(0)];
            let name = head.rsplit([' ', '*']).next().unwrap_or("").trim();
            if is_identifier(name) {
                let private = format!("bhf_absent_{name}");
                let signature = plain
                    .trim_start_matches("extern")
                    .trim()
                    .trim_end_matches(';')
                    .trim();
                let returns_void =
                    signature.starts_with("void ") && !signature.starts_with("void *");
                let default = renamed(signature, name, &private);
                out.push_str(&format!("{plain}{newline}"));
                out.push_str(&format!(
                    "{default} {{ {} }}\n",
                    if returns_void { "" } else { "return 0;" }
                ));
                out.push_str(&alternate(name, &private));
                continue;
            }
        }
        let declarator_end = plain
            .find('(')
            .into_iter()
            .chain(plain.find('['))
            .chain(plain.find(" ="))
            .min();
        let name = declarator_end
            .map(|end| plain[..end].trim_end())
            .and_then(|head| head.rsplit([' ', '*']).next())
            .unwrap_or("")
            .trim();
        if is_identifier(name) && !plain.contains("::") {
            let private = format!("bhf_weak_{name}");
            out.push_str(&alternate(name, &private));
            out.push_str(&renamed(plain, name, &private));
        } else {
            out.push_str(plain);
        }
        out.push_str(newline);
    }
    out
}

/// The `#define`s a `-dM -E` probe gets: enough for bhf's family detection/// The `#define`s a `-dM -E` probe gets: enough for bhf's family detection
/// to read the MSVC dialect.
pub(crate) fn predefined_macros() -> &'static str {
    "#define _MSC_VER 1900\n#define _WIN32 1\n"
}

/// Entry point of the `bhf-cl` front end. Returns the real compiler's exit
/// status.
pub(crate) fn run(args: &[OsString]) -> i32 {
    let args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let args = expand_response_files(&args);
    let compiler = std::env::var(REAL_COMPILER_ENV).unwrap_or_else(|_| "cl.exe".to_owned());
    let backend = Backend::for_compiler(&compiler);
    let mut command = match translate(&args, backend) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("bhf-cl: {error}");
            return 2;
        }
    };
    if command.predefined_macros_probe {
        print!("{}", predefined_macros());
        return 0;
    }
    let _stdin_dir;
    if let Some(extension) = command.stdin_source {
        use std::io::Read;
        let mut source = Vec::new();
        if std::io::stdin().read_to_end(&mut source).is_err() {
            return 2;
        }
        let Ok(dir) = tempfile::tempdir() else {
            return 2;
        };
        let file = dir.path().join(format!("stdin.{extension}"));
        if std::fs::write(&file, source).is_err() {
            return 2;
        }
        for arg in &mut command.args {
            if arg == "-" {
                *arg = file.display().to_string();
            }
        }
        _stdin_dir = dir;
    }
    // bhf's own repair stubs are weak; cl spells that as an alternate name.
    let _weak_dir = match rewrite_weak_stub_sources(&mut command) {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("bhf-cl: {error}");
            return 2;
        }
    };
    let include = (!command.include_after.is_empty()).then(|| {
        let mut include: Vec<PathBuf> = std::env::var_os("INCLUDE")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        include.extend(command.include_after.iter().map(PathBuf::from));
        std::env::join_paths(include).ok()
    });
    let run_one = |args: &[String]| -> i32 {
        let mut child = std::process::Command::new(&compiler);
        child.args(args);
        if let Some(Some(include)) = &include {
            child.env("INCLUDE", include);
        }
        let output = match child.output() {
            Ok(output) => output,
            Err(error) => {
                eprintln!("bhf-cl: could not run {compiler}: {error}");
                return 127;
            }
        };
        // cl writes its diagnostics to stdout. Everything goes to stderr,
        // where a compiler's diagnostics belong, each recognised one followed
        // by its clang spelling.
        use std::io::Write;
        let mut stderr = std::io::stderr().lock();
        for stream in [&output.stdout, &output.stderr] {
            for line in String::from_utf8_lossy(stream).lines() {
                if is_noise(line) {
                    continue;
                }
                let _ = writeln!(stderr, "{line}");
                if let Some(clang) = clang_style_diagnostic(line) {
                    let _ = writeln!(stderr, "{clang}");
                }
            }
        }
        output.status.code().unwrap_or(1)
    };
    match &command.split {
        Some(split) if split.has_colliding_objects() => {
            let object_dir = PathBuf::from(format!(
                "{}.objs",
                split.output.as_deref().unwrap_or("a.out")
            ));
            if let Err(error) = std::fs::create_dir_all(&object_dir) {
                eprintln!("bhf-cl: create {}: {error}", object_dir.display());
                return 2;
            }
            for args in split_commands(split, &object_dir) {
                let status = run_one(&args);
                if status != 0 {
                    return status;
                }
            }
            0
        }
        _ => run_one(&command.args),
    }
}

/// Compile bhf-generated sources (under a `repairs` directory) that carry
/// weak definitions from an MSVC-spelled copy in a temporary directory: same
/// file name (so the object name is the same), and the original directory on
/// the include path so its relative includes still resolve.
fn rewrite_weak_stub_sources(command: &mut ClCommand) -> Result<Option<tempfile::TempDir>, String> {
    let underscore =
        std::env::var("VSCMD_ARG_TGT_ARCH").is_ok_and(|arch| arch.eq_ignore_ascii_case("x86"));
    let mut dir: Option<tempfile::TempDir> = None;
    let mut replacements: Vec<(String, String, String)> = Vec::new();
    for arg in command.args.iter().filter(|arg| is_source(arg)) {
        let path = Path::new(arg);
        let in_repairs = path
            .ancestors()
            .skip(1)
            .take(3)
            .any(|dir| dir.file_name().is_some_and(|name| name == "repairs"));
        if !in_repairs {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if !text.contains("__attribute__((weak))") {
            continue;
        }
        if dir.is_none() {
            dir =
                Some(tempfile::tempdir().map_err(|error| format!("temporary directory: {error}"))?);
        }
        let copy = dir
            .as_ref()
            .map(|dir| dir.path().join(path.file_name().unwrap_or_default()))
            .unwrap_or_default();
        std::fs::write(
            &copy,
            msvc_weak_symbols(&text, is_cpp_source(arg), underscore),
        )
        .map_err(|error| format!("write {}: {error}", copy.display()))?;
        let original_dir = path
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        replacements.push((arg.clone(), copy.display().to_string(), original_dir));
    }
    for (original, copy, include) in &replacements {
        let replace = |args: &mut Vec<String>| {
            for arg in args.iter_mut() {
                if arg == original {
                    *arg = copy.clone();
                }
            }
        };
        replace(&mut command.args);
        let first_input = command
            .args
            .iter()
            .position(|arg| arg == copy)
            .unwrap_or(command.args.len());
        command.args.insert(first_input, include.clone());
        command.args.insert(first_input, "/I".to_owned());
        if let Some(split) = command.split.as_mut() {
            replace(&mut split.sources);
            split.compile_args.push("/I".to_owned());
            split.compile_args.push(include.clone());
        }
    }
    Ok(dir)
}

/// cl lines that say nothing about the build: the source-name echo and the
/// warnings about GCC options bhf left for it to ignore.
fn is_noise(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.contains("warning D9024")
        || trimmed.contains("warning D9025")
        || trimmed.contains("warning D9002")
        || (!trimmed.contains(' ') && is_source(trimmed))
}

/// Expand `@file` response files (GCC quoting) in place.
fn expand_response_files(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for arg in args {
        match arg.strip_prefix('@').map(std::fs::read_to_string) {
            Some(Ok(text)) => out.extend(crate::generate_harness::split_compile_command(&text)),
            _ => out.push(arg.clone()),
        }
    }
    out
}

/// The `bhf-cl` front end for this `bhf` executable: a hard link (or a copy
/// when the link fails) named `bhf-cl` in a per-build directory of the
/// user's own cache (never a shared temporary directory, where another user
/// could plant a program under that name).
pub(crate) fn front_end_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|error| format!("locate bhf: {error}"))?;
    let size = std::fs::metadata(&exe)
        .map(|meta| meta.len())
        .map_err(|error| format!("read {}: {error}", exe.display()))?;
    let base =
        per_user_cache_dir(cfg!(windows), &|name| std::env::var(name).ok()).ok_or_else(|| {
            "no per-user cache directory for the bhf-cl front end (set LOCALAPPDATA on \
             Windows, XDG_CACHE_HOME or HOME elsewhere)"
                .to_owned()
        })?;
    let commit: String = crate::BUILD_COMMIT.chars().take(12).collect();
    let dir = base
        .join("bhf")
        .join("multicall")
        .join(format!("{commit}-{size}"));
    install_multicall(&dir, FRONT_END_STEM)
}

/// The user's own cache directory: `%LOCALAPPDATA%` on Windows,
/// `$XDG_CACHE_HOME` (when absolute) or `$HOME/.cache` elsewhere.
pub(crate) fn per_user_cache_dir(
    windows: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    if windows {
        return env("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
    }
    let absolute = |value: String| {
        let path = PathBuf::from(value);
        path.is_absolute().then_some(path)
    };
    env("XDG_CACHE_HOME").and_then(absolute).or_else(|| {
        env("HOME")
            .and_then(absolute)
            .map(|home| home.join(".cache"))
    })
}

/// Put this `bhf` executable in `dir` under the name `stem` (plus the
/// platform's executable suffix): a hard link, or a copy when the link fails
/// (another volume). The `bhf` executable dispatches on the name it was
/// started under.
pub(crate) fn install_multicall(dir: &Path, stem: &str) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|error| format!("locate bhf: {error}"))?;
    install_copy_of(&exe, dir, stem)
}

/// Install `program` as `dir/stem`. An existing file there is reused only when
/// its bytes are the program's (a hard link of it, or an earlier copy);
/// anything else is replaced.
pub(crate) fn install_copy_of(program: &Path, dir: &Path, stem: &str) -> Result<PathBuf, String> {
    let name = format!("{stem}{}", std::env::consts::EXE_SUFFIX);
    let target = dir.join(&name);
    if same_contents(program, &target) {
        return Ok(target);
    }
    std::fs::create_dir_all(dir).map_err(|error| format!("create {}: {error}", dir.display()))?;
    let staging = dir.join(format!("{name}.{}", std::process::id()));
    let _ = std::fs::remove_file(&staging);
    if std::fs::hard_link(program, &staging).is_err() {
        std::fs::copy(program, &staging).map_err(|error| {
            format!(
                "copy {} to {}: {error}",
                program.display(),
                staging.display()
            )
        })?;
    }
    match std::fs::rename(&staging, &target) {
        Ok(()) => Ok(target),
        // Another bhf process put the same program in place first (Windows
        // cannot replace a file that is running).
        Err(_) if same_contents(program, &target) => {
            let _ = std::fs::remove_file(&staging);
            Ok(target)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&staging);
            Err(format!("install {}: {error}", target.display()))
        }
    }
}

/// Whether `a` and `b` are files with the same bytes.
fn same_contents(a: &Path, b: &Path) -> bool {
    use std::io::Read;
    let (Ok(meta_a), Ok(meta_b)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    if !meta_a.is_file() || !meta_b.is_file() || meta_a.len() != meta_b.len() {
        return false;
    }
    let (Ok(mut file_a), Ok(mut file_b)) = (std::fs::File::open(a), std::fs::File::open(b)) else {
        return false;
    };
    let mut chunk_a = vec![0u8; 1 << 16];
    let mut chunk_b = vec![0u8; 1 << 16];
    loop {
        let Ok(read) = file_a.read(&mut chunk_a) else {
            return false;
        };
        if read == 0 {
            return true;
        }
        if file_b.read_exact(&mut chunk_b[..read]).is_err() || chunk_a[..read] != chunk_b[..read] {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_harness_link_line_becomes_a_cl_compile_and_link() {
        let gnu = words(
            "-O1 -g -fsanitize=address,undefined -fno-sanitize=function,vptr,alignment \
             -fsanitize-coverage=inline-8bit-counters,edge,trace-cmp,trace-div \
             -ffunction-sections -fdata-sections -D_GNU_SOURCE -DWIDGET_MODE=1 \
             -I . -I C:/bhf/c_runtime -iquote C:/proj/include -idirafter C:/proj/include \
             -include C:/w/repairs/auto_defines.h -std=gnu11 -Wall -Wno-error -pthread \
             -DBHF_EXTERNAL_DRIVER -o main main.c C:/proj/widget.c bhf_driver.o \
             -Wl,--gc-sections -lm -lws2_32",
        );
        let cl = translate(&gnu, Backend::Cl).unwrap();
        let args = cl.args.join(" ");
        for expected in [
            "/nologo",
            "/O1",
            "/fsanitize=address",
            "/fsanitize-coverage=inline-8bit-counters",
            "/fsanitize-coverage=edge",
            "/fsanitize-coverage=trace-cmp",
            "/fsanitize-coverage=trace-div",
            "/Gy",
            "/Gw",
            "/D_GNU_SOURCE",
            "/DWIDGET_MODE=1",
            "/I .",
            "/I C:/bhf/c_runtime",
            "/I C:/proj/include",
            "/FI C:/w/repairs/auto_defines.h",
            "/std:c11",
            "/Z7",
            "/Fe:main",
            "main.c C:/proj/widget.c bhf_driver.o",
            "/link /DEBUG /INCREMENTAL:NO libsancov.lib",
            "/OPT:REF",
            "ws2_32.lib",
        ] {
            assert!(args.contains(expected), "missing {expected:?} in {args}");
        }
        for absent in ["undefined", "-W", "-pthread", "m.lib", "/EHsc", "-o"] {
            assert!(!args.contains(absent), "{absent:?} leaked into {args}");
        }
        assert_eq!(cl.include_after, vec!["C:/proj/include"]);
        let link_at = cl.args.iter().position(|a| a == "/link").unwrap();
        assert!(
            cl.args[..link_at].iter().any(|a| a == "bhf_driver.o")
                && cl.args[link_at..].iter().any(|a| a == "/OPT:REF"),
            "inputs before /link, linker options after: {args}"
        );
    }

    /// Two translation units named alike would compile to the same object, so
    /// they are compiled one at a time to numbered objects, then linked.
    #[test]
    fn colliding_object_names_compile_separately() {
        let cl = translate(
            &words("-O1 -g -fsanitize=address -fsanitize-coverage=inline-8bit-counters -I inc -o main main.c a/util.c b/util.c bhf_driver.o -lws2_32"),
            Backend::Cl,
        )
        .unwrap();
        let split = cl.split.as_ref().expect("a link line");
        assert!(split.has_colliding_objects());
        let commands = split_commands(split, Path::new("main.objs"));
        assert_eq!(commands.len(), 4);
        for (command, source) in commands.iter().zip(["main.c", "a/util.c", "b/util.c"]) {
            assert!(command.contains(&"/c".to_owned()), "{command:?}");
            assert_eq!(command.last().map(String::as_str), Some(source));
            assert!(command.contains(&"/I".to_owned()));
        }
        let objects: Vec<&String> = commands[..3].iter().map(|c| &c[c.len() - 2]).collect();
        assert_eq!(objects[1].as_str(), "/Fo:main.objs/1_util.obj");
        assert_eq!(objects[2].as_str(), "/Fo:main.objs/2_util.obj");
        let link = commands.last().unwrap().join(" ");
        assert!(
            link.contains("/Fe:main main.objs/0_main.obj main.objs/1_util.obj main.objs/2_util.obj bhf_driver.o ws2_32.lib /link"),
            "{link}"
        );
        assert!(
            link.contains("/fsanitize=address") && link.contains("libsancov.lib"),
            "{link}"
        );
        let unique = translate(&words("-o main main.c widget.c"), Backend::Cl).unwrap();
        assert!(!unique.split.unwrap().has_colliding_objects());
    }

    #[test]
    fn compile_only_syntax_only_and_cxx_lines() {
        let object = translate(
            &words("-O1 -g -D_GNU_SOURCE -c -o bhf_driver.o C:/bhf/c_runtime/bhf_driver.c"),
            Backend::Cl,
        )
        .unwrap();
        assert!(object.args.ends_with(&[
            "/c".to_owned(),
            "/Fo:bhf_driver.o".to_owned(),
            "C:/bhf/c_runtime/bhf_driver.c".to_owned()
        ]));
        assert!(!object.args.contains(&"/link".to_owned()));

        let syntax = translate(&words("-fsyntax-only -I inc main.c a.c"), Backend::Cl).unwrap();
        assert!(syntax.args.contains(&"/Zs".to_owned()));
        assert!(!syntax.args.contains(&"/link".to_owned()));

        let cxx = translate(
            &words("-O1 -g -std=gnu++17 -fsanitize=address -fsanitize-coverage=inline-8bit-counters -o main main.cpp w.cpp"),
            Backend::Cl,
        )
        .unwrap();
        for expected in ["/std:c++17", "/EHsc", "/Fe:main"] {
            assert!(cxx.args.contains(&expected.to_owned()), "{:?}", cxx.args);
        }
        let no_exceptions =
            translate(&words("-fno-exceptions -c -o a.o a.cpp"), Backend::Cl).unwrap();
        assert!(!no_exceptions.args.contains(&"/EHsc".to_owned()));
        let clang_cl = translate(
            &words("-fsanitize-coverage=inline-8bit-counters -o main main.c"),
            Backend::ClangCl,
        )
        .unwrap();
        assert!(
            !clang_cl.args.contains(&"libsancov.lib".to_owned()),
            "clang-cl calls the counters callback itself"
        );
    }

    #[test]
    fn probes_and_stdin_sources() {
        let probe = translate(&words("-dM -E -x c -"), Backend::Cl).unwrap();
        assert!(probe.predefined_macros_probe);
        assert_eq!(
            harness_gen::compiler_family::family_from_predefined_macros(predefined_macros()),
            Some(harness_gen::compiler_family::CompilerFamily::Msvc)
        );
        let stdin = translate(&words("-fsanitize=address -x c - -o probe"), Backend::Cl).unwrap();
        assert_eq!(stdin.stdin_source, Some("c"));
        assert!(stdin.args.contains(&"/TC".to_owned()));
    }

    #[test]
    fn language_standards_map_to_what_cl_has() {
        for (gnu, cl) in [
            ("c89", None),
            ("gnu99", None),
            ("c11", Some("/std:c11")),
            ("gnu17", Some("/std:c17")),
            ("c2x", Some("/std:clatest")),
            ("c++11", Some("/std:c++14")),
            ("gnu++17", Some("/std:c++17")),
            ("c++20", Some("/std:c++20")),
            ("c++2b", Some("/std:c++latest")),
        ] {
            assert_eq!(cl_standard(gnu), cl, "{gnu}");
        }
    }

    /// Weak stubs become MSVC alternate names: the stub is defined under a
    /// private name and stands in for the real one only when nothing else
    /// defines it.
    #[test]
    fn weak_repair_stubs_become_msvc_alternate_names() {
        let stubs = "#include \"auto_types.h\"\n\
                     __attribute__((weak)) int widget_lookup(int _bhf_p0) {\n    return 0;\n}\n\
                     __attribute__((weak)) char * widget_name(void) {\n    return NULL;\n}\n\
                     __attribute__((weak)) int widget_table[4] = {0};\n\
                     __attribute__((weak)) unsigned long widget_count = 0;\n\
                     extern unsigned long long bhf_shim_fuzz_stub_value(const char *bhf_symbol) __attribute__((weak));\n";
        let msvc = msvc_weak_symbols(stubs, false, false);
        assert!(!msvc.contains("__attribute__"), "{msvc}");
        for expected in [
            "#pragma comment(linker, \"/alternatename:widget_lookup=bhf_weak_widget_lookup\")\nint bhf_weak_widget_lookup(int _bhf_p0) {",
            "char * bhf_weak_widget_name(void) {",
            "int bhf_weak_widget_table[4] = {0};",
            "unsigned long bhf_weak_widget_count = 0;",
            "extern unsigned long long bhf_shim_fuzz_stub_value(const char *bhf_symbol);\n\
             unsigned long long bhf_absent_bhf_shim_fuzz_stub_value(const char *bhf_symbol) { return 0; }\n\
             #pragma comment(linker, \"/alternatename:bhf_shim_fuzz_stub_value=bhf_absent_bhf_shim_fuzz_stub_value\")",
        ] {
            assert!(msvc.contains(expected), "missing {expected:?} in\n{msvc}");
        }
        assert!(
            msvc.contains("#include \"auto_types.h\"\n"),
            "other lines are kept"
        );
        let x86 = msvc_weak_symbols(stubs, false, true);
        assert!(
            x86.contains("/alternatename:_widget_lookup=_bhf_weak_widget_lookup"),
            "{x86}"
        );
        let cpp = msvc_weak_symbols(
            "__attribute__((weak)) int ns::Widget::size() const {\n    return 0;\n}\n",
            true,
            false,
        );
        assert_eq!(cpp, "int ns::Widget::size() const {\n    return 0;\n}\n");
    }

    #[test]
    fn cl_diagnostics_gain_their_clang_spelling() {
        for (cl, clang) in [
            (
                r"C:\proj\widget.c(4): fatal error C1083: Cannot open include file: 'tables.h': No such file or directory",
                "C:/proj/widget.c:4:1: fatal error: 'tables.h' file not found",
            ),
            (
                r"C:\proj\widget.c(13,22): error C2065: 'WIDGET_SLOTS': undeclared identifier",
                "C:/proj/widget.c:13:22: error: use of undeclared identifier 'WIDGET_SLOTS'",
            ),
            (
                "main.c(30): warning C4013: 'widget_log' undefined; assuming extern returning int",
                "main.c:30:1: error: call to undeclared function 'widget_log'; ISO C99 and later do not support implicit function declarations",
            ),
            (
                r#"C:\proj\widget.h(7): fatal error C1189: #error:  "WIDGET_MODE must be set""#,
                r#"C:/proj/widget.h:7:1: error: "WIDGET_MODE must be set""#,
            ),
            (
                "main.c(9): error C2061: syntax error: identifier 'widget_ctx'",
                "main.c:9:1: error: unknown type name 'widget_ctx'",
            ),
        ] {
            assert_eq!(clang_style_diagnostic(cl).as_deref(), Some(clang), "{cl}");
        }
        assert_eq!(clang_style_diagnostic("main.c"), None);
        assert_eq!(
            clang_style_diagnostic("Microsoft (R) Incremental Linker"),
            None
        );
        assert!(is_noise("widget.c"));
        assert!(is_noise(
            "cl : Command line warning D9002 : ignoring unknown option '-fPIC'"
        ));
        assert!(!is_noise(
            "main.c(1): error C2065: 'x': undeclared identifier"
        ));
    }

    #[test]
    fn the_front_end_lives_in_a_per_user_directory() {
        // Absolute on the host running the test.
        let home = std::env::temp_dir().join("someone");
        let cache = std::env::temp_dir().join("cache-of-someone");
        let home_text = home.display().to_string();
        let cache_text = cache.display().to_string();
        let env = |name: &str| match name {
            "HOME" => Some(home_text.clone()),
            "LOCALAPPDATA" => Some("C:/Users/someone/AppData/Local".to_owned()),
            _ => None,
        };
        assert_eq!(per_user_cache_dir(false, &env), Some(home.join(".cache")));
        let xdg = |name: &str| match name {
            "XDG_CACHE_HOME" => Some(cache_text.clone()),
            "HOME" => Some(home_text.clone()),
            _ => None,
        };
        assert_eq!(per_user_cache_dir(false, &xdg), Some(cache.clone()));
        let relative = |name: &str| (name == "XDG_CACHE_HOME").then(|| "cache".to_owned());
        assert_eq!(
            per_user_cache_dir(false, &relative),
            None,
            "a relative XDG_CACHE_HOME is ignored, and there is no shared fallback"
        );
        assert_eq!(
            per_user_cache_dir(true, &env),
            Some(PathBuf::from("C:/Users/someone/AppData/Local"))
        );
        assert_eq!(per_user_cache_dir(true, &|_: &str| None), None);
    }

    #[test]
    fn an_existing_front_end_is_reused_only_when_it_is_the_same_program() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let program = temp.path().join("program");
        fs::write(&program, b"the real program").unwrap();
        let dir = temp.path().join("multicall");
        fs::create_dir_all(&dir).unwrap();
        let name = format!("bhf-cl{}", std::env::consts::EXE_SUFFIX);
        // Same size, other content: planted by someone else.
        fs::write(dir.join(&name), b"planted program!").unwrap();
        let installed = install_copy_of(&program, &dir, "bhf-cl").unwrap();
        assert_eq!(fs::read(&installed).unwrap(), b"the real program");
        let again = install_copy_of(&program, &dir, "bhf-cl").unwrap();
        assert_eq!(again, installed);
        assert_eq!(fs::read(&again).unwrap(), b"the real program");
    }
}
