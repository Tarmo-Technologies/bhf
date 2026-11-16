// SPDX-License-Identifier: Apache-2.0

//! Classify gcc/clang/ld/gprbuild error output into structured
//! BuildErrorKind variants so the auto attempt loop can decide which
//! repair to synthesise.

use serde::{Deserialize, Serialize};

pub mod cargo;
pub mod gcc_clang;
pub mod gnat;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BuildErrorKind {
    MissingHeader {
        path: String,
    },
    /// A package the build restores is not in any package source it may use:
    /// NuGet's NU1101 ("Unable to find package") or NU1102 (none with the
    /// version asked for). `version` is the one NU1102 names.
    MissingPackage {
        name: String,
        version: Option<String>,
    },
    MissingType {
        name: String,
    },
    /// A type that IS declared (a forward `class X;`/`struct X;`) but never
    /// *defined* in the compiled sources — the pimpl idiom (`class Foo { class
    /// FooImpl *impl; };` where `FooImpl`'s body lives in a .cpp the harness
    /// doesn't compile). clang says "incomplete type 'X'"/"variable has
    /// incomplete type"/"... with incomplete return type", NOT "unknown type
    /// name". It must NOT be `void *`-typedef-repaired (that redefines the
    /// forward declaration) — it signals an external/private definition the
    /// offline harness can never complete, so the target degrades to report-only.
    IncompleteType {
        name: String,
    },
    /// An ALL-CAPS identifier used but never defined — almost always a
    /// build-config preprocessor macro the project's build system injects
    /// (generated `config.h`, `-D` flags), e.g. libyaml's `YAML_VERSION_STRING`.
    /// `as_value` is true when used in value position (define to `0`); false
    /// when used in type/specifier position — an inline/export/api qualifier
    /// like jansson's `JSON_INLINE` — which must define to *nothing*.
    MissingMacro {
        name: String,
        as_value: bool,
    },
    UndefinedSymbol {
        name: String,
    },
    /// A C frontend rejected a call because no declaration was visible. This is
    /// distinct from a linker undefined reference: adding a standalone weak
    /// definition cannot make the calling translation unit compile. The source
    /// location lets repair inspect missing function-like/declaration macros.
    UndeclaredFunction {
        name: String,
        file: String,
        line: u32,
    },
    MissingSharedLib {
        name: String,
    },
    MissingAdaWith {
        unit: String,
    },
    MissingAdaSymbol {
        unit: String,
        symbol: String,
    },
    MissingAdaPackageBody {
        unit: String,
    },
    /// An Ada body source the assembler/compiler can't translate on this host —
    /// most often target-specific inline machine code (bb-runtimes' ARM `mcr
    /// p15` / AArch64 `mrs` intrinsics built on x86). Repaired by overriding the
    /// body with a synthesised stub so a *dependent* target still builds and
    /// fuzzes — bhf's "fuzz code that doesn't cleanly build" thesis.
    UncompilableAdaBody {
        source: String,
    },
    MissingGprImport {
        path: String,
    },
    /// A C/C++ translation unit where a macro/IDL-codegen line expands to a
    /// body-less function declarator clang rejects with "expected function body
    /// after function declarator". The function name is absent from the error
    /// text (clang points its caret at the macro invocation), so only the
    /// source `file:line` is captured; the repair rewrites that line in place
    /// (append `{}`) since the malformed declaration is in an in-tree TU, not a
    /// link-time stub.
    MalformedFunctionDecl {
        file: String,
        line: u32,
    },
    /// A `#error` directive a build-configuration guard reached — the header's own
    /// way of saying "your build system was supposed to define something"
    /// (libssh's `#error "no strtoull function found"`, ImageMagick's `#error "you
    /// should set MAGICKCORE_QUANTUM_DEPTH"`). Nothing is missing from the tree, so
    /// no header/type/symbol repair can apply; the fix is to define the macro the
    /// surrounding conditional tests, which needs the `file:line` to read the guard.
    ConfigGuardError {
        file: String,
        line: u32,
        message: String,
    },
    /// A member declared inside its class with the class name repeated
    /// (`int Widget::name();` within `class Widget`), which only MSVC accepts.
    /// clang accepts it under `-fms-extensions` and g++ under `-fpermissive`; no
    /// `-std=` accepts it, so the dialect ladder cannot help. `file:line` is the
    /// declaration, `member` the member's name.
    ExtraQualification {
        file: String,
        line: u32,
        member: String,
    },
    Other {
        tail: String,
    },
}

/// The C++ standard header that declares a stream object, manipulator or stream
/// class: `cerr`/`std::cerr`/`endl`/`std::istream` -> `iostream`, `ifstream` ->
/// `fstream`, `stringstream` -> `sstream`. The manipulators `ends`, `flush` and
/// `ws` count only when written `std::`-qualified, since the bare names are
/// common project identifiers.
///
/// Pre-standard C++ often reached these through a transitive include that a
/// modern standard library no longer provides, so a missing `#include
/// <iostream>` surfaces as "undeclared identifier 'cerr'" or an implicit
/// instantiation of `std::basic_istream<char>`. `None` for any other name.
pub fn std_stream_header(name: &str) -> Option<&'static str> {
    let name = name.trim();
    let qualified = name.starts_with("std::");
    let bare = name.strip_prefix("std::").unwrap_or(name);
    Some(match bare {
        "cin" | "cout" | "cerr" | "clog" | "wcin" | "wcout" | "wcerr" | "wclog" | "endl"
        | "istream" | "ostream" | "iostream" | "wistream" | "wostream" | "wiostream"
        | "streambuf" | "wstreambuf" => "iostream",
        "ends" | "flush" | "ws" if qualified => "iostream",
        "ifstream" | "ofstream" | "fstream" | "wifstream" | "wofstream" | "wfstream"
        | "filebuf" | "wfilebuf" => "fstream",
        "istringstream" | "ostringstream" | "stringstream" | "wistringstream"
        | "wostringstream" | "wstringstream" | "stringbuf" | "wstringbuf" => "sstream",
        _ => return None,
    })
}

/// The C++ standard header that declares a library name pre-standard code
/// often writes without `std::`, relying on a `using namespace std;`:
/// `string` -> `string`, `map`/`multimap` -> `map`, `list` -> `list`, `vector`
/// -> `vector`, `pair`/`make_pair` -> `utility`, the other containers, smart
/// pointers, standard exceptions, `numeric_limits`, the `<ios>` types, and
/// every stream name [`std_stream_header`] knows. Accepts the bare or the
/// `std::`-qualified spelling; `None` for any other name.
pub fn std_library_header(name: &str) -> Option<&'static str> {
    if let Some(header) = std_stream_header(name) {
        return Some(header);
    }
    let name = name.trim();
    let bare = name.strip_prefix("std::").unwrap_or(name);
    Some(match bare {
        "string" | "wstring" | "u16string" | "u32string" | "basic_string" => "string",
        "vector" => "vector",
        "map" | "multimap" => "map",
        "set" | "multiset" => "set",
        "list" => "list",
        "deque" => "deque",
        "queue" | "priority_queue" => "queue",
        "stack" => "stack",
        "pair" | "make_pair" => "utility",
        "bitset" => "bitset",
        "unordered_map" | "unordered_multimap" => "unordered_map",
        "unordered_set" | "unordered_multiset" => "unordered_set",
        "unique_ptr" | "shared_ptr" | "weak_ptr" | "make_unique" | "make_shared" => "memory",
        "exception" => "exception",
        "runtime_error" | "logic_error" | "invalid_argument" | "out_of_range" | "length_error"
        | "domain_error" | "range_error" | "overflow_error" | "underflow_error" => "stdexcept",
        "numeric_limits" => "limits",
        "ios" | "ios_base" | "streamsize" | "streamoff" | "streampos" => "ios",
        _ => return None,
    })
}

/// A standard-library name that C++ compiler output shows a source using
/// without `std::` (see [`unqualified_std_names`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnqualifiedStdName {
    /// The name as the source writes it: `string`, `map`, `cerr`.
    pub name: String,
    /// The standard header that declares it ([`std_library_header`]).
    pub header: &'static str,
    /// The compiler named the `std::` declaration (clang's and gcc's "did you
    /// mean 'std::string'?", or a note pointing at it): the header is already
    /// included, so including it again cannot help; the name needs a `using`
    /// declaration (or the `std::` qualification).
    pub declared: bool,
    /// The source writes it as a template (`map<string, int>`, clang's "no
    /// template named 'map'"), which only a template of that name can
    /// satisfy: a project's own non-template `list` (a C struct, say) is no
    /// substitute for `std::list` there.
    pub as_template: bool,
}

/// Every C++ standard-library name the g++/clang++ output `stderr` shows a
/// source using without `std::`, in first-seen order, each once. Pre-standard
/// headers write `string`, `map<string, int>` or `list<T>` and rely on a
/// `using namespace std;` the project's own sources put before including
/// them; a translation unit without it (a generated harness) fails with
/// "unknown type name 'string'", "no template named 'map'", "'list' does not
/// name a type" or "'string' has not been declared". `-include <string>`
/// alone does not fix that: the names stay unqualified.
///
/// Type-position diagnostics count for every name [`std_library_header`]
/// knows. An undeclared identifier counts when the name cannot be an ordinary
/// variable or function (`string`, `vector`, `cerr`, `runtime_error`), or when
/// the compiler pointed at the `std::` declaration, or the source shows it as
/// a template (`set<int>`) or a scope (`ios::binary`). The source line clang
/// and gcc print under such a diagnostic is read too, because clang reports
/// only the first unknown name of `map<string, int>`.
///
/// Diagnostics in C code (a `.c` file, or a header whose include chain above
/// the diagnostic passes through one) do not count: a C source's `list` is its
/// own type, which a C compile never takes from a C++ prelude and which a
/// C++ compile of the `.c` file would wrongly take as `std::list`.
pub fn unqualified_std_names(stderr: &str) -> Vec<UnqualifiedStdName> {
    gcc_clang::unqualified_std_names(stderr)
}

/// Classify a captured stderr against both toolchain regex packs.
/// Returns one event per distinct error in source order. `Other` is
/// emitted only when no known pattern matched any line - so a
/// successful classifier still surfaces the unknown tail for the
/// report.
pub fn classify(stderr: &str) -> Vec<BuildErrorKind> {
    let mut hits = Vec::new();
    nuget_into(stderr, &mut hits);
    gcc_clang::classify_into(stderr, &mut hits);
    gnat::classify_into(stderr, &mut hits);
    // gprbuild frequently repeats the same underlying GNAT diagnostic while
    // compiling a dependency and again while summarizing the failed main. Counts
    // and repair rounds must represent distinct causes, not repeated lines.
    let mut distinct = Vec::new();
    for hit in hits.drain(..) {
        if !distinct.contains(&hit) {
            distinct.push(hit);
        }
    }
    hits = distinct;
    if hits.is_empty() {
        // Prefer the lines that actually name an error. A multi-unit gprbuild
        // run prints a long compile listing ("[Ada] foo.adb ...") and ends with
        // "compilation phase failed"; the real diagnostic is mid-stream, so the
        // last few lines are a useless listing. Surface the error lines when
        // present, falling back to the trailing lines only when none are found.
        let error_lines: Vec<&str> = stderr
            .lines()
            .filter(|line| {
                let l = line.to_ascii_lowercase();
                l.contains("error:")
                    // rustc codes are `error[E0425]:` — `error:` is not a substring,
                    // so without this the codegen diagnostic was dropped and the tail
                    // fell back to a lossy summary that read as a missing dep (#40).
                    || l.contains("error[")
                    || l.contains("fatal error")
                    || l.contains("undefined reference")
            })
            .collect();
        let tail: String = if error_lines.is_empty() {
            stderr
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            error_lines
                .into_iter()
                .take(8)
                .collect::<Vec<_>>()
                .join("\n")
        };
        hits.push(BuildErrorKind::Other { tail });
    }
    hits
}

/// True when a diagnostic is a bhf HARNESS / CODEGEN build error — a
/// malformed generated harness or a parser recovery artifact — rather than a
/// genuine missing external dependency. The report must NOT frame these to the
/// user as "bring this dependency / acquire ..." (yaml-cpp's "no member named …
/// did you mean", ada-url's recovery-artifact bare `type`, a clang `use of
/// undeclared identifier` on a generated symbol): the fix is in bhf's
/// codegen / the project's own build config, not an upstream package.
///
/// Conservative: only fires on the `MissingType { name }` recovery-artifact
/// shape and on `Other` tails that carry an unmistakable codegen/identifier
/// marker. Recognized missing-header / missing-symbol / missing-lib / Ada
/// diagnostics are untouched and still route to the dependency manifest.
pub fn is_codegen_error(kind: &BuildErrorKind) -> bool {
    match kind {
        BuildErrorKind::MissingType { name } => is_recovery_artifact(name),
        BuildErrorKind::Other { tail } => tail_is_codegen(tail),
        _ => false,
    }
}

/// NuGet restore errors: `error NU1101: Unable to find package SharpFuzz.`
/// and `error NU1102: Unable to find package SharpFuzz with version (>= 2.3.0)`.
fn nuget_into(stderr: &str, hits: &mut Vec<BuildErrorKind>) {
    for line in stderr.lines() {
        let Some(at) = line
            .find("NU1101: Unable to find package ")
            .or_else(|| line.find("NU1102: Unable to find package "))
        else {
            continue;
        };
        let rest = &line[at + "NU1101: Unable to find package ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .collect::<String>()
            .trim_end_matches('.')
            .to_owned();
        if name.is_empty() {
            continue;
        }
        let version = rest
            .split_once("with version (")
            .and_then(|(_, tail)| tail.split_once(')'))
            .map(|(range, _)| {
                range
                    .trim_start_matches(['>', '=', '<', ' '])
                    .trim()
                    .to_owned()
            })
            .filter(|version| !version.is_empty());
        let hit = BuildErrorKind::MissingPackage { name, version };
        if !hits.contains(&hit) {
            hits.push(hit);
        }
    }
}

/// A clang/gcc parser RECOVERY ARTIFACT rather than a real type the tree is
/// missing: the bare placeholder token (`type`) the frontend substitutes while
/// recovering from a malformed declaration. Stubbing it as a `void *` C type (or
/// reporting it as a missing dependency) is noise.
pub fn is_recovery_artifact(name: &str) -> bool {
    matches!(name.trim(), "type" | "expression" | "<recovery-expr>")
}

/// Whether an `Other` diagnostic tail names a codegen / identifier error: a
/// member/type lookup failure, a typo-suggestion, or an undeclared identifier
/// the project's build config / bhf codegen would have provided — none of
/// which is a "bring this dependency" situation.
fn tail_is_codegen(tail: &str) -> bool {
    let lower = tail.to_ascii_lowercase();
    // A lookup failure in the project's own source is the project's error, not
    // the generated code's: only one located in the generated harness, or one
    // with no location, is bhf's.
    let in_generated_code =
        diagnostic_location(tail).is_none_or(|(file, _)| is_generated_harness_file(&file));
    (in_generated_code
        && (lower.contains("no member named")
            || lower.contains("no type named")
            || lower.contains("did you mean")
            || lower.contains("use of undeclared identifier")))
        // Compiler-driver FLAG / OPTION errors are a bhf build-recipe problem
        // (e.g. a recovered `-std=c2x` applied to a C++ TU: "invalid argument
        // '-std=c2x' not allowed with 'C++'"), never an external dependency to
        // acquire (#41).
        || lower.contains("not allowed with")
        || lower.contains("unknown argument")
        || lower.contains("unsupported option")
        || lower.contains("unknown option")
        || lower.contains("unrecognized command-line option")
        || lower.contains("unrecognized command line option")
        // Rust harness-codegen failures: the generated call path doesn't resolve
        // (E0425) or the method/item doesn't exist (E0599). These are bhf
        // codegen bugs surfaced through the lossy Rust build summary, not missing
        // external deps (#40).
        || lower.contains("error[e0425]")
        || lower.contains("error[e0599]")
        || lower.contains("cannot find function")
        || lower.contains("cannot find value")
        || lower.contains("no method named")
        || lower.contains("no function or associated item named")
        // #105: a SYNTAX error located in the GENERATED driver (main.c / main.cpp)
        // — a malformed extracted declaration or a bad constructor selection bhf
        // emitted — is a bhf codegen defect, not a missing dependency and not a
        // generic target-build failure. Gate the broad syntax phrasings on the
        // generated file name so a genuine syntax error in the project's own source
        // stays a distinct target error.
        || (tail_mentions_generated_harness_file(&lower) && tail_names_generated_syntax_error(&lower))
}

/// The file and line of the first `file:line:col: error:` (or `file:line:
/// error:`) a diagnostic tail names.
pub fn diagnostic_location(tail: &str) -> Option<(String, u32)> {
    tail.lines().find_map(|line| {
        let at = line
            .find(": error:")
            .or_else(|| line.find(": fatal error:"))?;
        let mut parts = line[..at].rsplitn(3, ':');
        let (last, middle) = (parts.next()?, parts.next()?);
        let (file, line_no) = match parts.next() {
            // `file:line:col`
            Some(file) if last.parse::<u32>().is_ok() => (file, middle.parse::<u32>().ok()?),
            // `file:line`
            _ => (line[..at].rsplit_once(':')?.0, last.parse::<u32>().ok()?),
        };
        let file = file.trim();
        (!file.is_empty()).then(|| (file.to_owned(), line_no))
    })
}

/// Whether `file` is code bhf generated for a harness: the driver it writes
/// (`main.c`, `main.cpp`) or a repair under the harness's `repairs/`.
pub fn is_generated_harness_file(file: &str) -> bool {
    let name = file.rsplit(['/', '\\']).next().unwrap_or(file);
    matches!(name, "main.c" | "main.cpp" | "main.cc")
        || file.contains("/repairs/")
        || file.contains("\\repairs\\")
        || name.starts_with("auto_stubs")
        || name.starts_with("auto_types")
}

/// #105: whether a diagnostic tail is located in the GENERATED harness driver.
/// bhf always names it `main.c` / `main.cpp`, so an error whose location is
/// that file is bhf's own emitted code, not the project's source.
fn tail_mentions_generated_harness_file(lower: &str) -> bool {
    lower.contains("main.c:") || lower.contains("main.cpp:")
}

/// #105: C/C++ front-end phrasings for a malformed DECLARATION or a bad
/// constructor selection — the shapes bhf's harness emitter can produce when
/// it reproduces an extracted parameter declaration or picks a constructor. Only
/// meaningful when the location is the generated driver (see caller).
fn tail_names_generated_syntax_error(lower: &str) -> bool {
    lower.contains("expected parameter declarator")
        || lower.contains("expected member name")
        || lower.contains("expected function body")
        || lower.contains("expected ')'")
        || lower.contains("expected ';'")
        || lower.contains("expected expression")
        || lower.contains("expected unqualified-id")
        || lower.contains("no matching constructor")
        || lower.contains("no matching function for call")
        || lower.contains("too few arguments")
        || lower.contains("too many arguments")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An undeclared identifier in the project's own file is the project's
    /// error; in the generated driver, or with no location, it is bhf's.
    #[test]
    fn nuget_restore_errors_name_the_missing_package() {
        let log = "/w/H-S1/bhf_harness.csproj : error NU1101: Unable to find package \
                   SharpFuzz. No packages exist with this id in source(s): offline-feed\n\
                   /w/H-S1/bhf_harness.csproj : error NU1102: Unable to find package \
                   Newtonsoft.Json with version (>= 13.0.3)\n";
        assert_eq!(
            classify(log),
            vec![
                BuildErrorKind::MissingPackage {
                    name: "SharpFuzz".to_owned(),
                    version: None,
                },
                BuildErrorKind::MissingPackage {
                    name: "Newtonsoft.Json".to_owned(),
                    version: Some("13.0.3".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn a_lookup_error_is_codegen_only_in_the_generated_harness() {
        let in_tree = "/p/src/bad.c:3:25: error: use of undeclared identifier 'counter'";
        assert!(!is_codegen_error(&BuildErrorKind::Other {
            tail: in_tree.to_owned()
        }));
        assert_eq!(
            diagnostic_location(in_tree),
            Some(("/p/src/bad.c".to_owned(), 3))
        );
        for generated in [
            "/w/harnesses/H-C1/main.c:40:9: error: use of undeclared identifier 'ctx'",
            "/w/harnesses/H-C1/repairs/auto_stubs.c:2:1: error: no member named 'x' in 'struct s'",
            "error: use of undeclared identifier 'ctx'",
        ] {
            assert!(
                is_codegen_error(&BuildErrorKind::Other {
                    tail: generated.to_owned()
                }),
                "{generated}"
            );
        }
        assert_eq!(
            diagnostic_location("lib.c:12: error: expected ';'"),
            Some(("lib.c".to_owned(), 12))
        );
    }

    #[test]
    fn config_guard_hash_error_is_classified_with_its_location() {
        // Both compiler spellings of a `#error` directive, from real headers in the
        // sweep. The location is the payload: the repair has to read the guard.
        for line in [
            r#"/p/libssh/include/libssh/priv.h:45:4: error: "no strtoull function found""#,
            r#"/p/libssh/include/libssh/priv.h:45:4: error: #error "no strtoull function found""#,
        ] {
            let hits = classify(line);
            assert_eq!(
                hits,
                vec![BuildErrorKind::ConfigGuardError {
                    file: "/p/libssh/include/libssh/priv.h".to_owned(),
                    line: 45,
                    message: "no strtoull function found".to_owned(),
                }],
                "{line}"
            );
        }
    }

    #[test]
    fn an_ordinary_diagnostic_is_never_read_as_a_hash_error() {
        // The clang form is recognized by its operand being a QUOTED string, so an
        // ordinary diagnostic — which starts with a bare word or a single-quoted
        // identifier — must keep its own classification.
        for line in [
            "/p/src/a.c:9:1: error: unknown type name 'bignum'",
            "/p/src/a.c:9:1: fatal error: 'zlib.h' file not found",
            "/p/src/a.c:9:1: error: expected expression",
        ] {
            let hits = classify(line);
            assert!(
                !hits
                    .iter()
                    .any(|h| matches!(h, BuildErrorKind::ConfigGuardError { .. })),
                "{line} -> {hits:?}"
            );
        }
    }

    #[test]
    fn no_member_named_is_a_codegen_error_not_a_missing_dep() {
        // yaml-cpp: a member/typo lookup failure in the generated driver is a
        // codegen/version mismatch, never an external dependency to acquire.
        let other = BuildErrorKind::Other {
            tail: "main.cpp:9:7: error: no member named 'as' in 'YAML::Node'; did you mean 'at'?"
                .to_owned(),
        };
        assert!(is_codegen_error(&other));
        // In the project's own file it is the project's error.
        let in_tree = BuildErrorKind::Other {
            tail: "node.cpp:9:7: error: no member named 'as' in 'YAML::Node'; did you mean 'at'?"
                .to_owned(),
        };
        assert!(!is_codegen_error(&in_tree));

        // A genuine missing-header Other-shaped tail is NOT a codegen error.
        let dep = BuildErrorKind::Other {
            tail: "internal compiler error: out of memory".to_owned(),
        };
        assert!(!is_codegen_error(&dep));
    }

    #[test]
    fn generated_harness_syntax_error_is_a_codegen_error_not_a_target_failure() {
        // #105: a malformed extracted declaration or a bad constructor selection in
        // the GENERATED driver (main.c / main.cpp) is a bhf codegen defect —
        // categorized distinctly, never a missing dependency or a generic target
        // build failure.
        for tail in [
            "main.c:42:18: error: expected parameter declarator",
            "main.cpp:70:5: error: expected member name or ';' after declaration specifiers",
            "main.cpp:88:3: error: no matching constructor for initialization of 'Foo'",
            "main.c:12:9: error: expected ')'",
        ] {
            assert!(
                is_codegen_error(&BuildErrorKind::Other {
                    tail: tail.to_owned()
                }),
                "generated-driver syntax error must be a codegen error: {tail}"
            );
        }
        // The SAME phrasing in the PROJECT's own source is a distinct TARGET error,
        // not a bhf codegen defect — the generated-file gate keeps them apart.
        assert!(
            !is_codegen_error(&BuildErrorKind::Other {
                tail: "src/parser.c:42:18: error: expected parameter declarator".to_owned()
            }),
            "a syntax error in the project's own source must stay a distinct target error"
        );
    }

    #[test]
    fn rust_codegen_e0425_e0599_are_not_missing_deps() {
        // #40: a Rust harness-codegen failure round-trips through this classifier as
        // a lossy summary string. The error[E0425]/[E0599] diagnostic must route to
        // codegen, not the dependency manifest.
        for tail in [
            "cargo build failed: error[E0425]: cannot find function `decode_to_vec` in this scope",
            "cargo build failed: error[E0599]: no method named `parse_str` found for struct `Doc`",
            "in-crate cargo build failed: cannot find value `STANDARD` in this scope",
        ] {
            let kinds = classify(tail);
            assert!(
                kinds.iter().any(is_codegen_error),
                "rust codegen tail must be a codegen error, not a dep: {tail:?} -> {kinds:?}"
            );
        }
        // A genuine missing crate is still a dependency (must NOT be swept up).
        let dep = BuildErrorKind::Other {
            tail: "error[E0463]: can't find crate for `serde`".to_owned(),
        };
        assert!(!is_codegen_error(&dep));
    }

    #[test]
    fn compiler_flag_diagnostics_are_codegen_not_missing_deps() {
        // #41: cmark's recovered `-std=c2x` applied to a C++ TU is a build-recipe
        // problem, not an external dependency to acquire.
        for tail in [
            "clang: error: invalid argument '-std=c2x' not allowed with 'C++'",
            "clang: error: unknown argument: '-fmodules-ts'",
            "cc1plus: error: unrecognized command-line option '-Wfoo'",
        ] {
            let other = BuildErrorKind::Other {
                tail: tail.to_owned(),
            };
            assert!(
                is_codegen_error(&other),
                "flag/option diagnostic must be codegen: {tail:?}"
            );
        }
    }

    #[test]
    fn use_of_undeclared_identifier_tail_is_codegen() {
        let other = BuildErrorKind::Other {
            tail: "main.c:4:5: error: use of undeclared identifier 'helper_fn'".to_owned(),
        };
        assert!(is_codegen_error(&other));
        let in_tree = BuildErrorKind::Other {
            tail: "h.c:4:5: error: use of undeclared identifier 'helper_fn'".to_owned(),
        };
        assert!(!is_codegen_error(&in_tree));
    }

    #[test]
    fn recovery_artifact_type_is_codegen_not_a_ctype_dep() {
        // ada-url: clang recovering from a malformed declaration emits a bare
        // `type` placeholder — never a real missing C type.
        assert!(is_codegen_error(&BuildErrorKind::MissingType {
            name: "type".to_owned()
        }));
        // A real missing type stays a dependency.
        assert!(!is_codegen_error(&BuildErrorKind::MissingType {
            name: "widget_t".to_owned()
        }));
        // And missing headers/symbols/libs are never codegen errors.
        assert!(!is_codegen_error(&BuildErrorKind::MissingHeader {
            path: "foo.h".to_owned()
        }));
        assert!(!is_codegen_error(&BuildErrorKind::MissingSharedLib {
            name: "hiredis".to_owned()
        }));
    }

    #[test]
    fn classifies_expected_function_body_as_malformed_function_decl() {
        // A macro that expands to a body-less declarator: clang's caret points
        // at the macro invocation, so the function name is absent — only the
        // source file:line is recoverable.
        let stderr = "t.c:2:9: error: expected function body after function declarator\n    \
                      2 | PROTO(y)\n      |         ^\n";
        let kinds = classify(stderr);
        assert_eq!(
            kinds,
            vec![BuildErrorKind::MalformedFunctionDecl {
                file: "t.c".to_owned(),
                line: 2,
            }]
        );
        // A normal semantic error is unaffected (no false positive).
        let other = classify("t.c:9:6: error: unknown type name 'Frobnicator'\n");
        assert!(other
            .iter()
            .all(|k| !matches!(k, BuildErrorKind::MalformedFunctionDecl { .. })));
    }

    #[test]
    fn classifies_missing_parameter_wrapper_macro() {
        let stderr = "api.c:97:57: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]\n\
            \x20  97 |         yaml_char_t **b_start, yaml_char_t **b_pointer, SHIM(yaml_char_t **b_end))\n\
            \x20     |                                                   ^\n";
        let kinds = classify(stderr);
        assert_eq!(
            kinds,
            vec![BuildErrorKind::MissingMacro {
                name: "SHIM".to_owned(),
                as_value: false,
            }]
        );
    }

    #[test]
    fn other_surfaces_error_line_not_compile_listing() {
        // A multi-unit gprbuild run: the real error is mid-stream, followed by
        // a long listing and the generic failure summary. The Other tail must
        // surface the error, not the trailing listing.
        let stderr = "Compile\n   [Ada] main.adb\n\
            main.adb:9:06: error: unrecognised gnat diagnostic about pkg\n\
            \x20  [Ada] adafuzz-probe.adb\n   [Ada] adafuzz-decode.adb\n\
            \x20  [Ada] toml.adb\ngprbuild: *** compilation phase failed\n";
        let kinds = classify(stderr);
        match kinds.as_slice() {
            [BuildErrorKind::Other { tail }] => assert!(
                tail.contains("unrecognised gnat diagnostic"),
                "Other tail must surface the error line, got: {tail:?}"
            ),
            other => panic!("expected a single Other, got {other:?}"),
        }
    }

    #[test]
    fn missing_header_clang_form() {
        let stderr = "main.c:3:10: fatal error: 'internal/log.h' file not found\n    #include \"internal/log.h\"\n         ^~~~~~~~~~~~~~~~\n1 error generated.\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingHeader { path } if path == "internal/log.h"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_header_gcc_form() {
        let stderr = "mfc_command.cpp:6:10: fatal error: afxwin.h: No such file or directory\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                BuildErrorKind::MissingHeader { path } if path == "afxwin.h"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_parent_header_clang_suggestion_form() {
        let stderr = "internal/stack.h:18:10: error: '../allocators.h' file not found, did you mean 'allocators.h'?\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                BuildErrorKind::MissingHeader { path } if path == "../allocators.h"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn explicit_no_config_error_is_a_missing_generated_header() {
        let stderr = "archive_platform.h:50:2: error: Oops: No config.h and no pre-built configuration in archive_platform.h.\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                BuildErrorKind::MissingHeader { path } if path == "config.h"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn undefined_symbol_ld_form() {
        let stderr = "/usr/bin/ld: /tmp/foo.o: in function `main':\n/tmp/foo.c:9: undefined reference to `decoder_create'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::UndefinedSymbol { name } if name == "decoder_create"
            )),
            "got {kinds:?}"
        );
    }

    /// The MSVC linker (link.exe, used by clang and cl on Windows) and
    /// lld-link name an unresolved symbol their own way; each is the same
    /// undefined symbol the repair loop stubs. A C++ symbol is named by its
    /// qualified function and parameter list.
    #[test]
    fn undefined_symbol_msvc_linker_forms() {
        let stderr = "\
main.obj : error LNK2019: unresolved external symbol widget_lookup referenced in function parse_record\r\n\
widget.obj : error LNK2001: unresolved external symbol widget_table\r\n\
main.obj : error LNK2019: unresolved external symbol \"public: int __cdecl ns::Widget::size(void)const \" (?size@Widget@ns@@QEBAHXZ) referenced in function main\r\n\
main.obj : error LNK2019: unresolved external symbol \"int __cdecl widget_count(int,char const *)\" (?widget_count@@YAHHPEBD@Z) referenced in function main\r\n\
lld-link: error: undefined symbol: widget_reset\n\
>>> referenced by main.c:12\n\
lld-link: error: undefined symbol: int __cdecl widget_total(int)\n\
>>> referenced by main.cpp:7\n\
lld-link: error: undefined symbol: public: void __cdecl ns::Widget::clear(void)\n\
lld-link: error: undefined symbol: __declspec(dllimport) widget_open\n\
main.exe : fatal error LNK1120: 4 unresolved externals\r\n";
        let names: Vec<String> = classify(stderr)
            .into_iter()
            .filter_map(|kind| match kind {
                BuildErrorKind::UndefinedSymbol { name } => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "widget_lookup",
                "widget_table",
                "ns::Widget::size()",
                "widget_count(int,char const *)",
                "widget_reset",
                "widget_total(int)",
                "ns::Widget::clear()",
                "widget_open",
            ]
        );
        let kinds = classify(
            "x.obj : error LNK2019: unresolved external symbol sqrt referenced in function f\n",
        );
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::MissingSharedLib { .. })),
            "a math-library symbol is a missing library, not a stub: {kinds:?}"
        );
    }

    #[test]
    fn missing_macro_all_caps_undeclared_identifier() {
        let stderr = "api.c:11:12: error: use of undeclared identifier 'YAML_VERSION_STRING'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingMacro { name, as_value: true } if name == "YAML_VERSION_STRING"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn all_caps_unknown_type_is_a_specifier_macro_not_a_type() {
        // jansson's `static JSON_INLINE json_t *json_incref(...)` — JSON_INLINE
        // is an inline/qualifier macro in type position, not a real type.
        let stderr = "jansson.h:120:8: error: unknown type name 'JSON_INLINE'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingMacro { name, as_value: false } if name == "JSON_INLINE"
            )),
            "ALL-CAPS unknown type should be a specifier macro: {kinds:?}"
        );
        // A real lower/mixed-case unknown type stays a MissingType.
        let kinds = classify("x.c:1:1: error: unknown type name 'widget_t'\n");
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::MissingType { name } if name == "widget_t")),
            "got {kinds:?}"
        );
    }

    #[test]
    fn leading_underscore_all_caps_is_a_specifier_macro() {
        // PX4 / NuttX / HAL visibility + linkage macros: `__EXPORT int param_get(
        // ...)`, `__BEGIN_DECLS`. The leading underscore must not demote them to a
        // (void*) MissingType, which corrupts every declaration; define-empty.
        for name in ["__EXPORT", "__BEGIN_DECLS", "__WEAK"] {
            let stderr = format!("p.h:1:1: error: unknown type name '{name}'\n");
            let kinds = classify(&stderr);
            assert!(
                kinds.iter().any(|k| matches!(
                    k,
                    BuildErrorKind::MissingMacro { name: n, as_value: false } if n == name
                )),
                "{name} should be a specifier macro: {kinds:?}"
            );
        }
        // A leading-underscore but mixed-case name is not a macro (`_MyType`).
        let kinds = classify("x.c:1:1: error: unknown type name '_MyType'\n");
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::MissingType { name } if name == "_MyType")),
            "got {kinds:?}"
        );
    }

    #[test]
    fn all_caps_typedef_in_type_position_is_a_type_not_a_macro() {
        // #96: legacy C libraries use ALL_CAPS TYPEDEF names. Expat's `SCANNER` is a
        // typedef in a project header; "unknown type name 'SCANNER'" must produce a
        // type/header repair, NOT a define-empty macro (which corrupts the decl).
        // Covers Clang + GCC phrasings (identical text), C and C++.
        for stderr in [
            "xmlparse.c:120:5: error: unknown type name 'SCANNER'\n",
            "expat.cpp:9:1: error: unknown type name 'BUFFER'\n",
            "s.c:1:1: error: unknown type name 'HASHTABLE'\n",
        ] {
            let kinds = classify(stderr);
            assert!(
                kinds
                    .iter()
                    .any(|k| matches!(k, BuildErrorKind::MissingType { .. })),
                "uppercase typedef in type position must be MissingType: {stderr:?} -> {kinds:?}"
            );
            assert!(
                !kinds
                    .iter()
                    .any(|k| matches!(k, BuildErrorKind::MissingMacro { .. })),
                "must NOT be a macro: {stderr:?} -> {kinds:?}"
            );
        }
        // Declaration DECORATOR macros stay macros (a decl-spec word or leading _).
        for name in ["JSON_INLINE", "WINAPI", "MYLIB_EXPORT", "__EXPORT"] {
            let kinds = classify(&format!("h.h:1:1: error: unknown type name '{name}'\n"));
            assert!(
                kinds.iter().any(|k| matches!(
                    k,
                    BuildErrorKind::MissingMacro { name: n, .. } if n == name
                )),
                "decorator {name} must stay a macro: {kinds:?}"
            );
        }
    }

    #[test]
    fn type_position_classification_is_stable_across_rounds() {
        // #96 oscillation guard: the SAME diagnostic always yields the SAME kind, so
        // a successful type-header repair cannot be undone by a later round
        // reclassifying the same symbol as a macro.
        let stderr = "p.c:1:1: error: unknown type name 'SCANNER'\n";
        let first = classify(stderr);
        let second = classify(stderr);
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
        assert!(first
            .iter()
            .any(|k| matches!(k, BuildErrorKind::MissingType { name } if name == "SCANNER")));
    }

    #[test]
    fn lowercase_undeclared_identifier_is_not_a_macro() {
        // A real undeclared symbol must not be faked as a macro #define.
        let stderr = "x.c:4:5: error: use of undeclared identifier 'helper_fn'\n";
        let kinds = classify(stderr);
        assert!(
            !kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::MissingMacro { .. })),
            "got {kinds:?}"
        );
    }

    #[test]
    fn mixed_case_project_constants_and_aliases_are_repairable() {
        for name in ["True", "UChar", "cJSON_IsReference"] {
            let kinds = classify(&format!(
                "x.c:4:5: error: use of undeclared identifier '{name}'\n"
            ));
            assert!(
                matches!(
                    kinds.as_slice(),
                    [BuildErrorKind::MissingMacro { name: found, as_value: true }]
                        if found == name
                ),
                "{name}: {kinds:?}"
            );
        }
    }

    #[test]
    fn undeclared_identifier_in_cpp_call_context_is_repairable() {
        let stderr = "coding.h:42:10: error: use of undeclared identifier 'DecodeFixed32'\n\
                      return DecodeFixed32(data);\n\
                             ^\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                BuildErrorKind::MissingMacro { name, as_value: true }
                    if name == "DecodeFixed32"
            )),
            "got {kinds:?}"
        );

        let variable = classify(
            "coding.h:42:10: error: use of undeclared identifier 'decode_state'\n\
             return decode_state;\n\
                    ^\n",
        );
        assert!(matches!(
            variable.as_slice(),
            [BuildErrorKind::Other { .. }]
        ));
    }

    #[test]
    fn known_posix_cpp_undeclared_identifier_is_repairable_symbol() {
        let kinds = classify("TProtocol.h:658:50: error: use of undeclared identifier 'htons'\n");
        assert!(kinds.iter().any(|kind| matches!(
            kind,
            BuildErrorKind::UndefinedSymbol { name } if name == "htons"
        )));

        // A lowercase variable is deliberately not promoted to a function.
        let kinds = classify("x.cpp:4:5: error: use of undeclared identifier 'state'\n");
        assert!(matches!(kinds.as_slice(), [BuildErrorKind::Other { .. }]));
    }

    #[test]
    fn undeclared_std_qualifier_preserves_the_qualified_standard_type() {
        let stderr = "x.cpp:4:7: error: use of undeclared identifier 'std'\n\
                      using std::string;\n\
                            ^\n";
        let kinds = classify(stderr);
        assert!(kinds.iter().any(|kind| matches!(
            kind,
            BuildErrorKind::MissingType { name } if name == "std::string"
        )));
    }

    #[test]
    fn known_wide_string_function_is_not_classified_as_a_macro() {
        let kinds = classify("archive.c:10:9: error: use of undeclared identifier 'wcslen'\n");
        assert!(matches!(
            kinds.as_slice(),
            [BuildErrorKind::UndefinedSymbol { name }] if name == "wcslen"
        ));
    }

    #[test]
    fn undeclared_c_boolean_literal_is_repairable_via_stdbool() {
        let kinds = classify("data.c:9:4: error: use of undeclared identifier 'false'\n");
        assert!(matches!(
            kinds.as_slice(),
            [BuildErrorKind::UndefinedSymbol { name }] if name == "false"
        ));
    }

    #[test]
    fn call_to_undeclared_clang_frontend_form() {
        // clang's compile-time error when a function is referenced
        // without a prior declaration. Prior to this regex the auto
        // pipeline saw it as `Other` and never planned a call-site repair.
        let stderr = "harness.c:77:11: error: call to undeclared function 'vendor_helper'; \
                      ISO C99 and later do not support implicit function declarations \
                      [-Wimplicit-function-declaration]\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::UndeclaredFunction { name, file, line }
                    if name == "vendor_helper" && file == "harness.c" && *line == 77
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn call_to_undeclared_library_function_is_repairable() {
        let kinds = classify(
            "mpc.c:105:20: error: call to undeclared library function 'malloc' with type 'void *(unsigned long)'\n",
        );
        assert!(matches!(
            kinds.as_slice(),
            [BuildErrorKind::UndeclaredFunction { name, file, line }]
                if name == "malloc" && file == "mpc.c" && *line == 105
        ));
    }

    #[test]
    fn math_symbol_reclassifies_as_missing_libm() {
        let stderr = "/usr/bin/ld: /tmp/foo.o: in function `f':\n\
                      /tmp/foo.c:9: undefined reference to `sqrt'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "m"
            )),
            "sqrt should reclassify to MissingSharedLib(m), got {kinds:?}"
        );
        assert!(
            !kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::UndefinedSymbol { name } if name == "sqrt"
            )),
            "sqrt should NOT also be reported as UndefinedSymbol"
        );
    }

    #[test]
    fn pthread_symbol_reclassifies_as_missing_pthread() {
        let stderr = "ld: undefined reference to `pthread_mutex_lock'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "pthread"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn dl_symbol_reclassifies_as_missing_libdl() {
        let stderr = "ld: undefined reference to `dlopen'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "dl"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn rt_symbol_reclassifies_as_missing_librt() {
        let stderr = "ld: undefined reference to `clock_gettime'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "rt"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn unknown_symbol_stays_undefined_symbol() {
        // Project-local symbols don't match the system-lib table and
        // should still flow through the existing UndefinedSymbol →
        // StubDeclared / StubBlind path.
        let stderr = "ld: undefined reference to `vendor_decode'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::UndefinedSymbol { name } if name == "vendor_decode"
            )),
            "got {kinds:?}"
        );
    }

    /// gcc's driver names a spec file it cannot read (a sanitizer's, when the
    /// runtime is not installed: MinGW's gcc has none) in the words of a
    /// missing header. It is not one, and placeholder headers cannot repair it.
    #[test]
    fn an_unreadable_spec_file_is_not_a_missing_header() {
        let stderr = "gcc: fatal error: cannot read spec file 'libsanitizer.spec': No such \
                      file or directory\ncompilation terminated.\n\
                      make: *** [Makefile:258: main] Error 1\n";
        let kinds = classify(stderr);
        assert_eq!(
            kinds,
            vec![BuildErrorKind::Other {
                tail: "gcc: fatal error: cannot read spec file 'libsanitizer.spec': No such \
                       file or directory"
                    .to_owned()
            }]
        );
        // A real one still is.
        assert_eq!(
            classify("x.c:1:10: fatal error: widget.h: No such file or directory\n"),
            vec![BuildErrorKind::MissingHeader {
                path: "widget.h".to_owned()
            }]
        );
    }

    #[test]
    fn missing_shared_lib_ld_form() {
        let stderr = "/usr/bin/ld: cannot find -lhiredis: No such file or directory\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "hiredis"
            )),
            "got {kinds:?}"
        );
    }

    /// The MSVC-style linkers name a library `-l<name>` asked for as the
    /// `<name>.lib` they could not open: lld-link (`could not open
    /// 'x.lib': no such file or directory`) and link.exe (LNK1181).
    #[test]
    fn missing_shared_lib_msvc_linker_forms() {
        for stderr in [
            "lld-link: error: could not open 'hiredis.lib': no such file or directory\n",
            "LINK : fatal error LNK1181: cannot open input file 'hiredis.lib'\r\n",
            "lld-link: error: could not open 'C:/vendor/lib/hiredis.lib': no such file or directory\n",
        ] {
            let kinds = classify(stderr);
            assert!(
                kinds.iter().any(|k| matches!(
                    k,
                    BuildErrorKind::MissingSharedLib { name } if name == "hiredis"
                )),
                "{stderr:?}: got {kinds:?}"
            );
        }
        // An object file that cannot be opened is no library.
        let kinds =
            classify("lld-link: error: could not open 'main.obj': no such file or directory\n");
        assert!(
            !kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::MissingSharedLib { .. })),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_type_clang_form() {
        let stderr = "main.c:5:1: error: unknown type name 'Widget'\nWidget x;\n^\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingType { name } if name == "Widget"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn target_specific_inline_asm_is_an_uncompilable_body() {
        // bb-runtimes ARM/AArch64 machine intrinsics built on an x86 host.
        for stderr in [
            "/w/i-arm_v7ar.adb:273: Error: no such instruction: `mcr p15,'\n",
            "/w/i-aarch64.adb:9: Error: junk `el1' after expression\n",
            "i-aarch64.adb:9:4: error: missing \"return\" statement in function body\n",
        ] {
            let kinds = classify(stderr);
            assert!(
                kinds.iter().any(|k| matches!(
                    k,
                    BuildErrorKind::UncompilableAdaBody { source } if source.ends_with(".adb")
                )),
                "asm error should be an uncompilable Ada body: {kinds:?}"
            );
        }
        // A normal Ada semantic error is NOT an uncompilable body.
        let kinds = classify("x.adb:1:1: error: \"Foo\" is undefined\n");
        assert!(
            !kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::UncompilableAdaBody { .. })),
            "got {kinds:?}"
        );
    }

    #[test]
    fn other_for_unknown_tail() {
        let stderr = "internal compiler error: oh no\nflux capacitor exploded\n";
        let kinds = classify(stderr);
        assert!(matches!(kinds[0], BuildErrorKind::Other { .. }));
    }

    #[test]
    fn incomplete_type_is_distinct_from_unknown_type() {
        // A forward-declared-but-undefined type (pimpl) is IncompleteType, NOT
        // MissingType — so it is never `void *`-repaired (that redefines the
        // forward decl) and instead degrades the target to report-only.
        for line in [
            "main.cpp:81:47: error: calling 'parse' with incomplete return type 'EncryptionParametersImpl'",
            "main.cpp:5:24: error: variable has incomplete type 'FooImpl'",
            "main.cpp:9:5: error: field has incomplete type 'class BarImpl'",
        ] {
            let kinds = classify(line);
            assert!(
                matches!(&kinds[0], BuildErrorKind::IncompleteType { .. }),
                "expected IncompleteType for {line:?}, got {kinds:?}"
            );
        }
        // The captured name strips a leading class/struct keyword.
        let kinds = classify("main.cpp:9:5: error: field has incomplete type 'class BarImpl'");
        assert!(
            matches!(&kinds[0], BuildErrorKind::IncompleteType { name } if name == "BarImpl"),
            "got {kinds:?}"
        );
        // A genuinely unknown type stays MissingType (gets the void* repair).
        let unknown = classify("x.c:1:1: error: unknown type name 'CString'");
        assert!(
            matches!(&unknown[0], BuildErrorKind::MissingType { name } if name == "CString"),
            "got {unknown:?}"
        );
    }

    #[test]
    fn missing_with_ada() {
        let stderr = "src/app.adb:3:06: file \"foo.ads\" not found\ngprbuild: \"src/app.adb\" compilation failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaWith { unit } if unit == "foo"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_ada_symbol() {
        let stderr = "src/app.adb:42:10: \"Parse_Error\" is undefined (more references follow)\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaSymbol { symbol, .. } if symbol == "Parse_Error"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_ada_symbol_not_declared_in_package() {
        let stderr = "src/app.adb:42:10: \"Score\" not declared in \"Aux_Pkg\"\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaSymbol { unit, symbol }
                    if unit == "Aux_Pkg" && symbol == "Score"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn ada_reserved_words_and_literals_are_never_missing_symbols() {
        // #100: GNAT reporting a reserved word / boolean-null literal as undefined
        // (or "not declared in P") is a visibility/syntax error, not a missing
        // callable — never propose a stub, which cannot recover a valid program and
        // only buries the real diagnostic.
        for sym in [
            "False", "True", "null", "Null", "return", "package", "TYPE", "Range",
        ] {
            let undefined = format!("main.adb:9:12: error: \"{sym}\" is undefined\n");
            let kinds = classify(&undefined);
            assert!(
                !kinds
                    .iter()
                    .any(|k| matches!(k, BuildErrorKind::MissingAdaSymbol { .. })),
                "{sym} must not be a MissingAdaSymbol (undefined): {kinds:?}"
            );
            let not_decl = format!("main.adb:9:12: error: \"{sym}\" not declared in \"Pkg\"\n");
            let kinds = classify(&not_decl);
            assert!(
                !kinds
                    .iter()
                    .any(|k| matches!(k, BuildErrorKind::MissingAdaSymbol { .. })),
                "{sym} must not be a MissingAdaSymbol (not declared in): {kinds:?}"
            );
        }
        // A real user symbol still classifies as a MissingAdaSymbol.
        let kinds = classify("main.adb:9:12: error: \"To_String\" is undefined\n");
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaSymbol { symbol, .. } if symbol == "To_String"
            )),
            "a real undefined symbol must still classify: {kinds:?}"
        );
    }

    #[test]
    fn repeated_gnat_diagnostics_are_counted_once() {
        let stderr = "x.adb:1:2: error: \"To_String\" not declared in \"Legacy\"\n\
                      x.adb:1:2: error: \"To_String\" not declared in \"Legacy\"\n";
        let errors = classify(stderr);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(matches!(
            &errors[0],
            BuildErrorKind::MissingAdaSymbol { unit, symbol }
                if unit == "Legacy" && symbol == "To_String"
        ));
    }

    #[test]
    fn missing_ada_package_body() {
        let stderr = "missing body for unit \"Demo.Parser\"\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaPackageBody { unit } if unit == "Demo.Parser"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_body_cannot_generate_code_form() {
        // gprbuild's way of saying "you have a spec but no body".
        let stderr = "Compile\n   [Ada]          aux_pkg.ads\n\
                      cannot generate code for file aux_pkg.ads (package spec)\n\
                      gprbuild: *** compilation phase failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaPackageBody { unit } if unit == "aux_pkg"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_gpr_import_imported_project_form() {
        // gprbuild's "imported project file" flavour, which is what
        // we see in practice when an `<x>.gpr` `with`s a missing
        // `<y>.gpr`.
        let stderr = "bhf_build.gpr:3:06: imported project file \"missing.gpr\" not found\n\
                      gprbuild: \"bhf_build.gpr\" processing failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingGprImport { path } if path == "missing.gpr"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn std_stream_identifiers_classify_as_missing_iostream_names() {
        // clang and gcc spellings (ASCII and UTF-8 quotes) of a source that uses
        // the standard streams without including <iostream>.
        let cases = [
            ("parser.cpp:331:2: error: use of undeclared identifier 'cerr'", "cerr"),
            (
                "parser.cpp:3:27: error: use of undeclared identifier 'endl'; did you mean 'end'?",
                "endl",
            ),
            ("parser.cpp:9:3: error: \u{2018}cout\u{2019} was not declared in this scope", "cout"),
            ("parser.cpp:9:3: error: 'clog' was not declared in this scope", "clog"),
            ("parser.cpp:9:3: error: use of undeclared identifier 'cin'", "cin"),
            (
                "parser.cpp:4:17: error: no member named 'cout' in namespace 'std'",
                "std::cout",
            ),
            (
                "parser.cpp:4:17: error: \u{2018}cerr\u{2019} is not a member of \u{2018}std\u{2019}",
                "std::cerr",
            ),
            (
                "lexer.cpp:52:19: error: implicit instantiation of undefined template 'std::basic_istream<char>'",
                "std::istream",
            ),
            (
                "lexer.cpp:52:19: error: implicit instantiation of undefined template 'std::basic_ifstream<wchar_t>'",
                "std::wifstream",
            ),
        ];
        for (line, expected) in cases {
            let kinds = classify(line);
            assert_eq!(
                kinds,
                vec![BuildErrorKind::MissingType {
                    name: expected.to_owned()
                }],
                "{line}"
            );
        }
        // Other undeclared lowercase identifiers keep their old classification.
        assert!(matches!(
            classify("x.cpp:4:5: error: 'state' was not declared in this scope").as_slice(),
            [BuildErrorKind::Other { .. }]
        ));
        assert!(matches!(
            classify("x.cpp:4:5: error: no member named 'widget' in namespace 'std'").as_slice(),
            [BuildErrorKind::Other { .. }]
        ));
    }

    #[test]
    fn extra_member_qualification_is_classified_with_its_location() {
        let expected = |file: &str, member: &str| BuildErrorKind::ExtraQualification {
            file: file.to_owned(),
            line: 136,
            member: member.to_owned(),
        };
        for (line, file, member) in [
            (
                "src/widget.h:136:18: error: extra qualification on member 'name'",
                "src/widget.h",
                "name",
            ),
            (
                "src/widget.h:136:12: error: extra qualification 'Widget::' on member 'name' [-fpermissive]",
                "src/widget.h",
                "name",
            ),
            (
                "inc/w.h:136:12: error: extra qualification \u{2018}ns::Widget::\u{2019} on member \u{2018}set\u{2019} [-fpermissive]",
                "inc/w.h",
                "set",
            ),
        ] {
            assert_eq!(classify(line), vec![expected(file, member)], "{line}");
        }
        // The same header included by two translation units is one cause.
        let twice = "src/widget.h:136:18: error: extra qualification on member 'name'\n\
                     src/widget.h:136:18: error: extra qualification on member 'name'\n";
        assert_eq!(classify(twice).len(), 1);
        // Accepted under -fpermissive it is only a warning, not a build error.
        assert!(matches!(
            classify("src/widget.h:136:12: warning: extra qualification 'Widget::' on member 'name' [-fpermissive]")
                .as_slice(),
            [BuildErrorKind::Other { .. }]
        ));
    }

    #[test]
    fn std_stream_header_names_the_declaring_header() {
        for (name, header) in [
            ("cerr", "iostream"),
            ("std::cout", "iostream"),
            ("wclog", "iostream"),
            ("endl", "iostream"),
            ("std::istream", "iostream"),
            ("ofstream", "fstream"),
            ("std::stringstream", "sstream"),
        ] {
            assert_eq!(std_stream_header(name), Some(header), "{name}");
        }
        assert_eq!(std_stream_header("state"), None);
        assert_eq!(std_stream_header("std::vector"), None);
        // Bare manipulator names are common project identifiers.
        for bare in ["ws", "flush", "ends"] {
            assert_eq!(std_stream_header(bare), None, "{bare}");
            assert_eq!(
                std_stream_header(&format!("std::{bare}")),
                Some("iostream"),
                "{bare}"
            );
        }
    }

    #[test]
    fn std_library_header_names_the_declaring_header() {
        for (name, header) in [
            ("string", "string"),
            ("std::wstring", "string"),
            ("map", "map"),
            ("multimap", "map"),
            ("vector", "vector"),
            ("list", "list"),
            ("pair", "utility"),
            ("make_pair", "utility"),
            ("set", "set"),
            ("deque", "deque"),
            ("priority_queue", "queue"),
            ("stack", "stack"),
            ("unordered_map", "unordered_map"),
            ("shared_ptr", "memory"),
            ("runtime_error", "stdexcept"),
            ("numeric_limits", "limits"),
            ("ios_base", "ios"),
            // The stream names keep their headers.
            ("cerr", "iostream"),
            ("ostream", "iostream"),
            ("ifstream", "fstream"),
        ] {
            assert_eq!(std_library_header(name), Some(header), "{name}");
        }
        for other in ["Widget", "state", "flush", "copy_at", "std::copy_at"] {
            assert_eq!(std_library_header(other), None, "{other}");
        }
    }

    /// `(name, declared)` for each unqualified standard name in `output`.
    fn unqualified(output: &str) -> Vec<(String, &'static str, bool)> {
        unqualified_std_names(output)
            .into_iter()
            .map(|name| (name.name, name.header, name.declared))
            .collect()
    }

    /// The header the generated harness includes, with the project's own
    /// sources providing `using namespace std;` before including it:
    ///
    /// ```cpp
    /// class Widget {
    /// public:
    ///     int parse_record(const unsigned char *data, size_t size);
    ///     map<string, int> fields;
    ///     vector<int> sizes;
    ///     list<string> names;
    ///     pair<int, int> span;
    /// };
    /// ```
    #[test]
    fn clang_unqualified_std_types_are_named_with_their_headers() {
        // Nothing included the standard headers: clang reports `string` for
        // `map<string, int>` and `list<string>`, and the source lines name the
        // templates.
        let missing = "In file included from main.cpp:1:\n\
./widget.h:6:9: error: use of undeclared identifier 'string'\n\
    6 |     map<string, int> fields;\n\
      |         ^\n\
./widget.h:7:5: error: no template named 'vector'\n\
    7 |     vector<int> sizes;\n\
      |     ^\n\
./widget.h:8:10: error: use of undeclared identifier 'string'\n\
    8 |     list<string> names;\n\
      |          ^\n\
./widget.h:9:5: error: no template named 'pair'\n\
    9 |     pair<int, int> span;\n\
      |     ^\n\
4 errors generated.\n";
        assert_eq!(
            unqualified(missing),
            vec![
                ("string".to_owned(), "string", false),
                ("map".to_owned(), "map", false),
                ("vector".to_owned(), "vector", false),
                ("list".to_owned(), "list", false),
                ("pair".to_owned(), "utility", false),
            ]
        );
        // The headers are included but the names unqualified: clang points at
        // each `std::` declaration.
        let declared = "In file included from main.cpp:6:\n\
./widget.h:6:9: error: unknown type name 'string'; did you mean 'std::string'?\n\
    6 |     map<string, int> fields;\n\
      |         ^~~~~~\n\
      |         std::string\n\
/usr/lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/stringfwd.h:77:33: note: 'std::string' declared here\n\
   77 |   typedef basic_string<char>    string;\n\
      |                                 ^\n\
./widget.h:6:5: error: no template named 'map'; did you mean 'std::map'?\n\
    6 |     map<string, int> fields;\n\
      |     ^~~\n\
      |     std::map\n\
./widget.h:7:5: error: no template named 'vector'; did you mean 'std::vector'?\n\
./widget.h:8:5: error: no template named 'list'; did you mean 'std::list'?\n\
./widget.h:9:5: error: no template named 'pair'; did you mean 'std::pair'?\n\
6 errors generated.\n";
        assert_eq!(
            unqualified(declared),
            vec![
                ("string".to_owned(), "string", true),
                ("map".to_owned(), "map", true),
                ("vector".to_owned(), "vector", true),
                ("list".to_owned(), "list", true),
                ("pair".to_owned(), "utility", true),
            ]
        );
        // More names in type position, and the stream objects.
        let more = "./doc.h:4:15: error: unknown type name 'ostream'\n\
./doc.h:6:5: error: no template named 'shared_ptr'\n\
./doc.h:8:5: error: no template named 'unordered_map'\n\
./doc.h:9:25: error: use of undeclared identifier 'runtime_error'\n\
    9 |     void fail() { throw runtime_error(\"bad list\"); }\n\
./doc.h:10:24: error: no template named 'numeric_limits'\n\
./doc.h:11:18: error: use of undeclared identifier 'cerr'\n\
   11 |     void say() { cerr << \"x\" << endl; }\n\
./doc.h:12:49: error: use of undeclared identifier 'make_pair'\n";
        let names: Vec<(String, &str, bool)> = unqualified(more);
        assert_eq!(
            names,
            vec![
                ("ostream".to_owned(), "iostream", false),
                ("shared_ptr".to_owned(), "memory", false),
                ("unordered_map".to_owned(), "unordered_map", false),
                ("runtime_error".to_owned(), "stdexcept", false),
                ("numeric_limits".to_owned(), "limits", false),
                ("cerr".to_owned(), "iostream", false),
                ("endl".to_owned(), "iostream", false),
                ("make_pair".to_owned(), "utility", false),
            ],
            "the literal's `list` is not a use"
        );
    }

    #[test]
    fn gcc_unqualified_std_types_are_named_with_their_headers() {
        // gcc reports the template of `map<string, int>`; `string` is on the
        // source line. UTF-8 quotes, as in a UTF-8 locale.
        let missing = "In file included from main.cpp:1:\n\
widget.h:6:5: error: \u{2018}map\u{2019} does not name a type\n\
    6 |     map<string, int> fields;\n\
      |     ^~~\n\
widget.h:7:5: error: \u{2018}vector\u{2019} does not name a type\n\
    7 |     vector<int> sizes;\n\
      |     ^~~~~~\n\
widget.h:8:5: error: \u{2018}list\u{2019} does not name a type\n\
    8 |     list<string> names;\n\
      |     ^~~~\n\
widget.h:9:5: error: \u{2018}pair\u{2019} does not name a type\n\
    9 |     pair<int, int> span;\n\
      |     ^~~~\n";
        let expected = vec![
            ("map".to_owned(), "map", false),
            ("string".to_owned(), "string", false),
            ("vector".to_owned(), "vector", false),
            ("list".to_owned(), "list", false),
            ("pair".to_owned(), "utility", false),
        ];
        assert_eq!(unqualified(missing), expected);
        // The C locale's ASCII quotes.
        let ascii = missing.replace(['\u{2018}', '\u{2019}'], "'");
        assert_eq!(unqualified(&ascii), expected);

        // Parameter and local-variable positions. gcc names the `std::`
        // declaration in "did you mean" or a "suggested alternatives" note when
        // the header is included; `does not name a type` never does.
        let contexts = "ctx.h:2:17: error: \u{2018}string\u{2019} was not declared in this scope\n\
ctx.h:2:17: note: suggested alternatives:\n\
/usr/include/c++/13/bits/stringfwd.h:77:33: note:   \u{2018}std::string\u{2019}\n\
/usr/include/c++/13/string:66:11: note:   \u{2018}std::pmr::string\u{2019}\n\
ctx.h:3:22: error: \u{2018}vector\u{2019} does not name a type\n\
ctx.h:4:31: error: \u{2018}list\u{2019} was not declared in this scope\n\
ctx.h:4:31: note: suggested alternatives:\n\
/usr/include/c++/13/bits/stl_list.h:632:11: note:   \u{2018}std::__cxx11::list\u{2019}\n\
ctx.h:5:8: error: \u{2018}pair\u{2019} does not name a type\n\
doc.h:4:15: error: \u{2018}ostream\u{2019} has not been declared\n\
doc.h:9:25: error: \u{2018}runtime_error\u{2019} was not declared in this scope; did you mean \u{2018}std::runtime_error\u{2019}?\n\
doc.h:11:18: error: \u{2018}cerr\u{2019} was not declared in this scope\n\
doc.h:11:18: note: \u{2018}std::cerr\u{2019} is defined in header \u{2018}<iostream>\u{2019}; this is probably fixable by adding \u{2018}#include <iostream>\u{2019}\n";
        assert_eq!(
            unqualified(contexts),
            vec![
                ("string".to_owned(), "string", true),
                ("vector".to_owned(), "vector", false),
                ("list".to_owned(), "list", true),
                ("pair".to_owned(), "utility", false),
                ("ostream".to_owned(), "iostream", false),
                ("runtime_error".to_owned(), "stdexcept", true),
                ("cerr".to_owned(), "iostream", false),
            ]
        );
    }

    /// A name the source writes as a template (`list<string>`, clang's "no
    /// template named 'list'") is marked, so only a template of the
    /// project's own can stand for it; `string` in `map<string, int>` is a
    /// plain type use.
    #[test]
    fn template_uses_of_unqualified_std_names_are_marked() {
        let as_template = |output: &str| -> Vec<(String, bool)> {
            unqualified_std_names(output)
                .into_iter()
                .map(|name| (name.name, name.as_template))
                .collect()
        };
        let clang = "./widget.h:6:9: error: unknown type name 'string'\n\
    6 |     map<string, int> fields;\n\
      |         ^\n\
./widget.h:8:5: error: no template named 'list'\n\
./widget.h:9:20: error: use of undeclared identifier 'cerr'\n\
    9 |     void say() { cerr << 1; }\n";
        assert_eq!(
            as_template(clang),
            vec![
                ("string".to_owned(), false),
                ("map".to_owned(), true),
                ("list".to_owned(), true),
                ("cerr".to_owned(), false),
            ]
        );
        let gcc = "widget.h:6:5: error: \u{2018}map\u{2019} does not name a type\n\
    6 |     map<string, int> fields;\n\
      |     ^~~\n\
widget.h:7:5: error: \u{2018}string\u{2019} does not name a type\n\
    7 |     string title;\n\
      |     ^~~~~~\n";
        assert_eq!(
            as_template(gcc),
            vec![("map".to_owned(), true), ("string".to_owned(), false),]
        );
    }

    #[test]
    fn project_names_and_qualified_uses_are_not_unqualified_std_names() {
        for output in [
            // A project type, and names qualified with a namespace.
            "w.h:3:5: error: unknown type name 'Widget'\n",
            "w.h:3:5: error: no template named 'vector' in namespace 'std'\n",
            "w.h:3:5: error: no template named 'map' in namespace 'widgets'\n",
            "w.h:3:5: error: \u{2018}string\u{2019} in namespace \u{2018}std\u{2019} does not name a type\n",
            "w.h:3:5: error: \u{2018}map\u{2019} is not a member of \u{2018}std\u{2019}\n",
            // A manipulator name is a project identifier unless qualified.
            "w.cpp:3:5: error: use of undeclared identifier 'flush'\n",
            // An everyday word as an undeclared variable or call (clang's C and
            // C++ wording, gcc's C++ wording) is not the standard name.
            "w.c:3:5: error: use of undeclared identifier 'list'\n    3 |     list = list->next;\n      |     ^\n",
            "w.cpp:3:5: error: \u{2018}set\u{2019} was not declared in this scope\n    3 |     set(value);\n      |     ^~~\n",
            "w.cpp:3:5: error: use of undeclared identifier 'pair'\n",
            // A warning is not a build error.
            "w.h:3:5: warning: unknown type name 'string'\n",
        ] {
            assert_eq!(unqualified_std_names(output), Vec::new(), "{output}");
        }
        // With evidence an everyday word counts: written as a template or a
        // scope, or the compiler named the `std::` declaration.
        for (output, name) in [
            (
                "w.cpp:3:5: error: \u{2018}set\u{2019} was not declared in this scope\n    3 |     set<int> seen;\n      |     ^~~\n",
                "set",
            ),
            (
                "w.cpp:3:5: error: use of undeclared identifier 'ios'\n    3 |     open(path, ios::binary);\n      |                ^\n",
                "ios",
            ),
            (
                "w.cpp:3:5: error: use of undeclared identifier 'pair'; did you mean 'std::pair'?\n",
                "pair",
            ),
        ] {
            assert_eq!(
                unqualified_std_names(output)
                    .into_iter()
                    .map(|found| found.name)
                    .collect::<Vec<_>>(),
                vec![name.to_owned()],
                "{output}"
            );
        }
        // Old compilers print the source line without a gutter, then a caret.
        let old = "w.h:6:9: error: use of undeclared identifier 'string'\n\
                   \x20   map<string, int> fields;\n\
                   \x20       ^\n";
        assert_eq!(
            unqualified(old),
            vec![
                ("string".to_owned(), "string", false),
                ("map".to_owned(), "map", false),
            ]
        );
    }

    /// C code of a C++ harness (a `.c` extra source, or a header it includes)
    /// may name its own `list` or `stack` type. A C++ prelude cannot reach a C
    /// compile, and where the harness Makefile compiles the `.c` file with the
    /// C++ compiler it would bind the name to the standard template, so those
    /// diagnostics are not unqualified standard names.
    #[test]
    fn c_code_diagnostics_are_not_unqualified_std_names() {
        for output in [
            // The C source itself: clang, gcc with a function context line, and
            // the parenthesised location of clang-cl.
            "lib/src/node.c:2:18: error: unknown type name 'list'\n    2 | int walk(void) { list *head = 0; return 0; }\n      |                  ^\n",
            "lib/src/node.c: In function \u{2018}walk\u{2019}:\n\
             lib/src/node.c:2:18: error: unknown type name \u{2018}list\u{2019}\n",
            "lib\\src\\node.c(2,18): error: unknown type name 'list'\n",
            // The same source compiled by g++ (the harness compiles extra
            // sources with $(CXX)), in C++ wording.
            "lib/src/node.c:1:1: error: \u{2018}list\u{2019} does not name a type\n\
             \x20   1 | list *roots;\n\
             \x20     | ^~~~\n",
            // A header a C source includes: clang prints the chain once and not
            // again for the next diagnostic from the same place; gcc prints a
            // nested chain innermost first, on continuation lines.
            "In file included from lib/src/node.c:1:\n\
             lib/include/node.h:3:5: error: unknown type name 'list'\n\
             lib/include/node.h:4:5: error: unknown type name 'stack'\n",
            "In file included from lib/include/node.h:2,\n\
             \x20                from lib/src/node.c:1:\n\
             lib/include/queue.h: At top level:\n\
             lib/include/queue.h:3:5: error: unknown type name \u{2018}queue\u{2019}\n",
            "In file included from C:\\w\\lib\\src\\node.c:1:\n\
             C:\\w\\lib\\include\\node.h:3:5: error: unknown type name 'list'\n",
            // clang prints a nested chain outermost first.
            "In file included from lib/src/node.c:1:\n\
             In file included from lib/include/node.h:2:\n\
             lib/include/queue.h:3:5: error: unknown type name 'queue'\n",
            // A `.c` file a C++ source includes is C code too, and so are the
            // headers it includes. gcc prints no chain when it returns to that
            // file from one of them.
            "In file included from main.cpp:2:\n\
             lib/legacy.c:3:5: error: unknown type name 'list'\n\
             lib/legacy.c:4:5: error: unknown type name 'stack'\n",
            "In file included from main.cpp:2:\n\
             In file included from lib/legacy.c:1:\n\
             lib/legacy.h:3:5: error: unknown type name 'list'\n",
            "In file included from lib/legacy.h:1,\n\
             \x20                from lib/legacy.c:1,\n\
             \x20                from main.cpp:2:\n\
             lib/types.h:3:1: error: \u{2018}list\u{2019} does not name a type\n\
             lib/legacy.c: In function \u{2018}int walk()\u{2019}:\n\
             lib/legacy.c:4:5: error: \u{2018}stack\u{2019} does not name a type\n",
        ] {
            assert_eq!(unqualified(output), Vec::new(), "{output}");
        }

        // The C++ code's names still count, before or after the C code's.
        let cpp_then_c = "In file included from main.cpp:3:\n\
                          ./widget.h:6:5: error: unknown type name 'string'\n\
                          lib/src/node.c:2:18: error: unknown type name 'list'\n\
                          In file included from lib/src/node.c:1:\n\
                          lib/include/node.h:3:5: error: unknown type name 'stack'\n";
        let c_then_cpp = "lib/src/node.c:2:18: error: unknown type name 'list'\n\
                          In file included from main.cpp:3:\n\
                          ./widget.h:6:5: error: unknown type name 'string'\n\
                          ./widget.h:7:5: error: no template named 'deque'\n\
                          src/log.cpp:9:5: error: unknown type name 'stack'\n";
        assert_eq!(
            unqualified(cpp_then_c),
            vec![("string".to_owned(), "string", false)]
        );
        assert_eq!(
            unqualified(c_then_cpp),
            vec![
                ("string".to_owned(), "string", false),
                ("deque".to_owned(), "deque", false),
                ("stack".to_owned(), "stack", false),
            ]
        );
        // A header error with no include chain at all stays a C++ one, as is
        // a force-included header's under its `<command-line>` chain.
        let forced = "In file included from <command-line>:\n\
                      ./std_prelude.h:9:5: error: unknown type name 'string'\n";
        assert_eq!(
            unqualified(forced),
            vec![("string".to_owned(), "string", false)]
        );
    }

    #[test]
    fn missing_gpr_import() {
        let stderr = "demo.gpr:5:09: cannot find \"gnatcoll.gpr\"\ngprbuild: project file \"demo.gpr\" loading failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingGprImport { path } if path == "gnatcoll.gpr"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_gpr_import_without_extension() {
        // GNAT reports a missing `with "gnatcoll";` (no `.gpr` in the clause) as
        // `imported project file "gnatcoll" not found` — the name carries no
        // extension. Must still classify as MissingGprImport (not Other).
        let stderr = "spat.gpr:1:06: imported project file \"gnatcoll\" not found\n\
                      gprbuild: \"bhf_build.gpr\" processing failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingGprImport { path } if path == "gnatcoll"
            )),
            "extension-less missing GPR import must classify: got {kinds:?}"
        );
    }
}
