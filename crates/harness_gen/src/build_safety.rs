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
/// On Unix the recipe is parsed by `/bin/sh`. On Windows GNU make runs it
/// through `sh` when one is on `PATH` (w64devkit, MSYS2) and through `cmd.exe`
/// otherwise, so the Windows set holds what either shell acts on inside a
/// word: the shell operators, parentheses and quotes, and `cmd`'s `^` and `%`.
/// A parenthesis or apostrophe is syntax to `sh`, so a flag carrying one is
/// quoted ([`quoted_build_input`]) and a path carrying one
/// (`C:/Program Files (x86)/...`) is double-quoted ([`recipe_path`]). The set
/// leaves out the backslash, the Windows path separator (the paths bhf writes
/// into a recipe are rendered with forward slashes by [`make_path`]), and the
/// glob, brace, tilde and history characters: a Windows path cannot hold `*`
/// or `?`, and an 8.3 short name such as `C:/Users/ADMINI~1` carries a `~`.
/// (`make`'s own `$`/`#` are forbidden on both.)
#[cfg(not(windows))]
const FORBIDDEN: &[char] = &[
    '$', '`', ';', '|', '&', '(', ')', '<', '>', '*', '?', '{', '}', '[', ']', '~', '!', '#', '\'',
    '"', '\\', ' ', '\t', '\n', '\r',
];
#[cfg(windows)]
const FORBIDDEN: &[char] = &[
    '$', '`', ';', '|', '&', '(', ')', '<', '>', '^', '%', '\'', '"', '#', ' ', '\t', '\n', '\r',
];

/// What double quotes do not hold literally in a Windows recipe, which may run
/// through `sh` or `cmd`: `$` (expanded by `make`), a backtick (expanded by
/// `sh` inside double quotes), a double quote (it ends the quoting) and `%`
/// (`cmd` expands variables inside double quotes).
const WINDOWS_UNQUOTABLE: &[char] = &['$', '`', '"', '%'];

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

/// A token that is not safe BARE but is safe once quoted, rendered with those
/// quotes. `None` when it is unsafe either way, or when it needs no quoting at
/// all (the caller then emits it unchanged).
///
/// `sh` treats every character inside single quotes literally, so the only shell
/// hazard is a single quote itself. `make` expands `$` BEFORE the shell ever sees
/// the line, so that stays forbidden, as do newlines and control characters,
/// which no quoting can contain. A flag with an apostrophe in it (an include dir
/// under `/home/Dana's tree/`) is double-quoted instead, when every character
/// that needs quoting is one a path may carry ([`QUOTABLE_IN_PATH`]); see
/// [`first_unquotable_flag_char`].
///
/// On Windows every such flag is double-quoted ([`windows_double_quoted`]):
/// the recipe may run through `cmd`, which does not honour single quotes, and
/// double quotes hold the shell operators and parentheses literally in both
/// `sh` and `cmd`.
///
/// This is what lets a legitimate CMake define through. `-DLLAMA_VERSIONS=>=3`
/// (gpt4all) and `-D_LIBCPP_HARDENING_MODE=..._DEBUG>` (btop) are ordinary
/// version-comparison defines whose `>` would redirect if emitted bare — refusing
/// them cost every target in those projects, and quoting them is both correct and
/// safe.
pub fn quoted_build_input(value: &str) -> Option<String> {
    if value.is_empty() || is_build_input_safe(value) || first_unquotable_flag_char(value).is_some()
    {
        return None;
    }
    if cfg!(windows) {
        Some(windows_double_quoted(value))
    } else if value.contains('\'') {
        Some(format!("\"{value}\""))
    } else {
        Some(format!("'{value}'"))
    }
}

/// `value` in double quotes for a Windows recipe. A run of backslashes at the
/// end is doubled: `sh` and the Windows argument parser both read `\"` as a
/// literal quote, and both read `\\"` back as one backslash and the closing
/// quote. Callers have refused what double quotes cannot hold
/// ([`WINDOWS_UNQUOTABLE`]).
fn windows_double_quoted(value: &str) -> String {
    let trailing = value.len() - value.trim_end_matches('\\').len();
    format!("\"{value}{}\"", "\\".repeat(trailing))
}

/// The first character of a compile flag that no quoting can make safe, or
/// `None` when the flag can be emitted bare or quoted by
/// [`quoted_build_input`].
///
/// A control character or `$` is never safe. Single quotes contain anything
/// else except a single quote. A flag with an apostrophe is double-quoted, and
/// inside double quotes `sh` still acts on `$`, a backtick, a backslash and a
/// double quote, so such a flag may only carry the characters a path may
/// ([`QUOTABLE_IN_PATH`]) beyond those safe bare. On Windows every flag that
/// needs quoting is double-quoted, so it may carry anything but
/// [`WINDOWS_UNQUOTABLE`]; a backslash stays, as the path separator.
fn first_unquotable_flag_char(value: &str) -> Option<char> {
    if is_build_input_safe(value) {
        return None;
    }
    if let Some(c) = value.chars().find(|c| c.is_control() || *c == '$') {
        return Some(c);
    }
    if cfg!(windows) {
        return value.chars().find(|c| WINDOWS_UNQUOTABLE.contains(c));
    }
    if !value.contains('\'') {
        return None;
    }
    value
        .chars()
        .find(|c| *c == '\\' || (FORBIDDEN.contains(c) && !QUOTABLE_IN_PATH.contains(c)))
}

/// Whether a COMPILE FLAG may be interpolated into a recipe — bare or quoted.
///
/// Deliberately narrower than it looks: this relaxation is for flags ONLY. A
/// compile flag appears only inside a recipe command line, where single quotes
/// contain it completely. Filesystem paths get their own, narrower relaxation
/// ([`is_build_path_usable`]): they also land in `#include "..."` lines and in
/// make variable assignments, so a `;` or `|` in one stays refused.
pub fn is_compile_flag_usable(value: &str) -> bool {
    first_unquotable_flag_char(value).is_none()
}

/// Render a compile flag for a recipe: unchanged when it is safe bare,
/// quoted when it needs it ([`quoted_build_input`]). Callers must have
/// validated it first.
pub fn recipe_token(value: &str) -> String {
    quoted_build_input(value).unwrap_or_else(|| value.to_owned())
}

/// Characters a filesystem path may contain once it is double-quoted, beyond
/// those already safe bare: a space, the parentheses and apostrophe found in
/// `C:/Program Files (x86)/...` and personal directory names, and the glob,
/// brace, tilde and history characters (`* ? [ ] { } ~ !`). Inside double
/// quotes `sh` treats each of them literally, and `make` only acts on them in
/// rule targets and prerequisites, where a quoted path never appears. Even if a
/// path were ever emitted unquoted they could only split, expand or break the
/// command line, never start another command, which is why shell control
/// operators (`;`, `|`, `&`, `<`, `>`) are not on this list although quoting
/// would contain them too.
const QUOTABLE_IN_PATH: &[char] = &[' ', '(', ')', '\'', '*', '?', '[', ']', '{', '}', '~', '!'];

/// The first character of `value` that no quoting makes safe in a recipe path:
/// a control character, or a metacharacter outside [`QUOTABLE_IN_PATH`]. That
/// covers `$` (expanded by `make`), `#` (a `make` comment), a backtick or a
/// double quote (which would break out of the quotes), and the shell operators.
fn first_unquotable_path_char(value: &str) -> Option<char> {
    value
        .chars()
        .find(|c| c.is_control() || (FORBIDDEN.contains(c) && !QUOTABLE_IN_PATH.contains(c)))
}

/// Whether a filesystem PATH (source file, include dir, extra source, runtime
/// dir, compiler) can be emitted into a generated Makefile: bare when it is
/// plain, double-quoted by [`recipe_path`] when it carries a space, parenthesis
/// or apostrophe. Paths reach recipes and make variables only, never a make
/// target or prerequisite while they need quoting.
pub fn is_build_path_usable(value: &str) -> bool {
    first_unquotable_path_char(value).is_none()
}

/// Validate one filesystem path for a generated Makefile, naming the offending
/// character and the remedy when it cannot be quoted safely.
pub fn ensure_build_path_safe(kind: &str, value: &str) -> Result<(), HarnessGenError> {
    match first_unquotable_path_char(value) {
        None => Ok(()),
        Some(c) => Err(HarnessGenError::UnsafeBuildInput(format!(
            "refusing to generate harness: {kind} {value:?} contains {c:?}, which cannot be \
             quoted safely in a build recipe (a shell/make metacharacter that could inject \
             commands); rename or move it to a path without that character (spaces, \
             parentheses and apostrophes are supported)"
        ))),
    }
}

/// Validate every path in an iterator, naming the offending one.
pub fn ensure_all_build_paths_safe<'a, I>(kind: &str, values: I) -> Result<(), HarnessGenError>
where
    I: IntoIterator<Item = &'a str>,
{
    for value in values {
        ensure_build_path_safe(kind, value)?;
    }
    Ok(())
}

/// A character that needs no quoting in a recipe word.
fn is_plain_path_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | ',' | '=' | ':' | '@' | '%')
}

/// Render a validated path for a recipe or a make variable that a recipe
/// expands: unchanged when every character is plain, otherwise wrapped in
/// double quotes, which `sh` and the Windows argument parser both honour.
/// Callers validate with [`ensure_build_path_safe`] first; `$`, `#`, a backtick
/// and a double quote can never appear here.
pub fn recipe_path(value: &str) -> String {
    debug_assert!(
        is_build_path_usable(value),
        "unvalidated recipe path {value:?}"
    );
    if value.chars().all(is_plain_path_char) {
        value.to_owned()
    } else {
        format!("\"{value}\"")
    }
}

/// [`make_path`], validated and quoted for a recipe in one step.
pub fn checked_recipe_path(kind: &str, path: &std::path::Path) -> Result<String, HarnessGenError> {
    let rendered = make_path(path);
    ensure_build_path_safe(kind, &rendered)?;
    Ok(recipe_path(&rendered))
}

/// Validate every compile flag, permitting one that is safe once quoted.
pub fn ensure_all_compile_flags_safe<'a, I>(values: I) -> Result<(), HarnessGenError>
where
    I: IntoIterator<Item = &'a str>,
{
    for value in values {
        if let Some(c) = first_unquotable_flag_char(value) {
            return Err(HarnessGenError::UnsafeBuildInput(format!(
                "refusing to generate harness: compile flag {value:?} contains {c:?}, a \
                 shell/make metacharacter that quoting cannot contain and could inject \
                 commands into the build recipe; rename or move the path it names to one \
                 without that character"
            )));
        }
    }
    Ok(())
}

/// Whether a failure reason is a build-input refusal from this module (an
/// unsafe path, include name or compile flag), as opposed to a parameter the
/// decoders could not drive. Every refusal message starts this way.
pub fn is_unsafe_build_input_reason(reason: &str) -> bool {
    reason.contains("refusing to generate harness: ")
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
/// three shell commands. Hold it to the path rule — a compiler path never
/// legitimately needs a shell operator. The single-quote relaxation for compile
/// FLAGS does not apply. A compiler under a directory with spaces
/// (`C:/Program Files/LLVM/bin/clang.exe`) is accepted, and the Makefile names
/// it through [`recipe_path`], double-quoted, so it stays one word at the head of
/// each recipe line.
pub fn is_compiler_token(value: &str) -> bool {
    !value.trim().is_empty() && is_build_path_usable(value) && !value.starts_with('-')
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
                "refusing to generate harness: {kind} {value:?} contains a quote or newline \
                 that would terminate its GPR string literal and inject project syntax"
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
    let s = s
        .strip_prefix(r"\\?\UNC\")
        .map(|rest| format!(r"\\{rest}"))
        .or_else(|| s.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or(s)
        .replace('\\', "/");
    s
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
    /// btop; quoting it is correct AND safe: `sh` treats everything inside
    /// single quotes literally, and on Windows, where the recipe may run
    /// through `cmd`, it is double-quoted, which `sh` and `cmd` both honour.
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
            let quoted = if cfg!(windows) {
                format!("\"{flag}\"")
            } else {
                format!("'{flag}'")
            };
            assert_eq!(recipe_token(flag), quoted);
            assert!(ensure_all_compile_flags_safe([flag]).is_ok());
        }

        // What quoting CANNOT contain is still refused: `make` expands `$`
        // before the shell sees the line, and a newline starts a new recipe
        // line.
        for flag in ["-DX=y$(shell id)", "-DX=${HOME}", "-DX=y\nrun: ; id"] {
            assert!(quoted_build_input(flag).is_none(), "{flag:?}");
            assert!(!is_compile_flag_usable(flag), "{flag:?}");
            assert!(ensure_all_compile_flags_safe([flag]).is_err(), "{flag:?}");
        }

        // On Unix a single quote ends the single quoting, so a flag carrying
        // one and an operator is refused (Windows double-quotes it).
        if !cfg!(windows) {
            assert!(!is_compile_flag_usable("-DX='; id; '"));
            assert!(ensure_all_compile_flags_safe(["-DX='; id; '"]).is_err());
        }

        // A safe-bare flag is emitted unchanged — no gratuitous quoting.
        assert_eq!(recipe_token("-DNDEBUG"), "-DNDEBUG");
        assert_eq!(recipe_token("-I/usr/include"), "-I/usr/include");

        // A shell control operator in a source path stays refused even though
        // quoting would contain it (paths have their own, narrower relaxation).
        assert!(ensure_build_input_safe("source path", "src/a;curl evil|sh.c").is_err());
        assert!(ensure_build_path_safe("source path", "src/a;curl evil|sh.c").is_err());
    }

    /// Source trees, work directories and SDK include dirs routinely contain
    /// spaces (`/home/Dana Smith/...`, `C:/Program Files (x86)/Windows Kits/...`).
    /// They are accepted and double-quoted wherever they reach a recipe.
    #[test]
    fn paths_with_spaces_are_accepted_and_quoted_for_recipes() {
        for (path, rendered) in [
            (
                "/home/Dana Smith/My Proj/src/a.c",
                "\"/home/Dana Smith/My Proj/src/a.c\"",
            ),
            (
                "C:/Program Files (x86)/Windows Kits/10/Include",
                "\"C:/Program Files (x86)/Windows Kits/10/Include\"",
            ),
            ("/srv/o'neil/include", "\"/srv/o'neil/include\""),
            ("/home/Dana Smith/work dir", "\"/home/Dana Smith/work dir\""),
        ] {
            assert!(is_build_path_usable(path), "{path:?} must be usable");
            assert!(
                ensure_build_path_safe("source path", path).is_ok(),
                "{path:?}"
            );
            assert_eq!(recipe_path(path), rendered);
        }
        // An ordinary path is emitted exactly as before.
        for plain in [
            "/usr/include",
            "src/miniz.c",
            "C:/tools/llvm/bin/clang.exe",
            "-",
        ] {
            assert_eq!(recipe_path(plain), plain);
        }
    }

    /// What quoting cannot make safe is still refused: `make` expands `$` and
    /// starts a comment at `#` before the shell sees the line, a backtick or an
    /// inner double quote breaks out of the quotes, a newline ends the recipe
    /// line, and shell control operators are refused even though quoting would
    /// contain them, so a path never carries an operator into a recipe.
    #[test]
    fn paths_with_unquotable_metacharacters_stay_refused() {
        for hostile in [
            "/tmp/$(id)/a.c",
            "/tmp/${HOME}/a.c",
            "/tmp/`id`/a.c",
            "/tmp/a\"b/a.c",
            "/tmp/a#b/a.c",
            "/tmp/a\nrun: ; id/a.c",
            "/tmp/a\tb/a.c",
            "src/a;curl evil|sh.c",
            "/tmp/a&b/a.c",
            "/tmp/a>b/a.c",
        ] {
            assert!(
                !is_build_path_usable(hostile),
                "{hostile:?} must be refused"
            );
            let error = ensure_build_path_safe("source path", hostile).unwrap_err();
            assert!(
                error.to_string().contains("source path"),
                "the refusal names what was refused: {error}"
            );
        }
    }

    #[test]
    fn a_refused_path_names_the_character_and_the_remedy() {
        let error = ensure_build_path_safe("include dir", "/srv/build$tmp/include")
            .unwrap_err()
            .to_string();
        assert!(error.contains("'$'"), "{error}");
        assert!(error.contains("rename or move"), "{error}");
        assert!(error.contains("spaces"), "{error}");
    }

    #[test]
    fn every_refusal_is_recognised_as_a_build_input_refusal() {
        let refusals = [
            ensure_build_path_safe("include dir", "/a$b").unwrap_err(),
            ensure_build_input_safe("include name", "a;b.h").unwrap_err(),
            ensure_all_compile_flags_safe(["-DX=$(id)"]).unwrap_err(),
            ensure_all_gpr_strings_safe("source dir", ["a\"b"]).unwrap_err(),
        ];
        for refusal in refusals {
            assert!(
                is_unsafe_build_input_reason(&refusal.to_string()),
                "{refusal}"
            );
        }
        assert!(!is_unsafe_build_input_reason(
            "C++ parameter 'cb' of type 'callback_t' has no byte-buffer decoder"
        ));
    }

    /// On Windows the native path is first rendered with forward slashes (and
    /// without the `\\?\` verbatim prefix), then quoted like any other.
    #[cfg(windows)]
    #[test]
    fn windows_paths_with_spaces_are_rendered_and_quoted() {
        let rendered = checked_recipe_path(
            "include dir",
            std::path::Path::new(r"\\?\C:\Program Files (x86)\Windows Kits\10\Include"),
        )
        .unwrap();
        assert_eq!(
            rendered,
            "\"C:/Program Files (x86)/Windows Kits/10/Include\""
        );
        assert_eq!(
            checked_recipe_path("source path", std::path::Path::new(r"C:\src\a.c")).unwrap(),
            "C:/src/a.c"
        );
        assert!(
            checked_recipe_path("source path", std::path::Path::new(r"C:\a%PATH%\b.c")).is_err()
        );
    }

    /// A compile-database flag under a directory with an apostrophe
    /// (`-I/home/Dana's tree/include`) cannot be single-quoted, so it is
    /// double-quoted, which holds a space, parenthesis or apostrophe literally.
    #[cfg(not(windows))]
    #[test]
    fn a_flag_with_an_apostrophe_is_double_quoted() {
        for flag in [
            "-I/home/Dana's tree/proj/include",
            "-I/srv/o'neil/include",
            "-DOWNER=o'neil",
            "-iquote/opt/Kit's (x86)/inc",
            "-I/data/proj [old]/inc's",
        ] {
            assert!(is_compile_flag_usable(flag), "{flag:?} must be usable");
            assert_eq!(recipe_token(flag), format!("\"{flag}\""), "{flag:?}");
            assert!(ensure_all_compile_flags_safe([flag]).is_ok(), "{flag:?}");
        }
        // With an apostrophe, anything double quotes do not hold literally stays
        // refused: an operator, an expansion, a backtick, a quote or a backslash.
        for flag in [
            "-DX='; id; '",
            "-I/a'b/$(id)",
            "-I/a'b/`id`",
            "-DX='a\"b'",
            "-I/a'b\\c",
            "-DX='a|b'",
        ] {
            assert!(!is_compile_flag_usable(flag), "{flag:?} must be refused");
        }
    }

    /// On Windows GNU make runs a recipe through `sh` when one is on `PATH`
    /// (w64devkit) and through `cmd` otherwise. `sh` reads a bare parenthesis
    /// or apostrophe as syntax and `cmd` does not honour single quotes, so a
    /// flag that needs quoting is double-quoted, and what double quotes do not
    /// hold literally in one of the two shells is refused.
    #[cfg(windows)]
    #[test]
    fn windows_flags_are_double_quoted_for_sh_and_cmd() {
        for (flag, rendered) in [
            ("-DBAR=(x)", "\"-DBAR=(x)\""),
            ("-DOWNER=o'neil", "\"-DOWNER=o'neil\""),
            ("-DX='; id; '", "\"-DX='; id; '\""),
            ("-DPOW=2^8", "\"-DPOW=2^8\""),
            (
                "-IC:/Program Files (x86)/Kit/include",
                "\"-IC:/Program Files (x86)/Kit/include\"",
            ),
            (r"-IC:\Program Files\Kit\", r#""-IC:\Program Files\Kit\\""#),
        ] {
            assert!(is_compile_flag_usable(flag), "{flag:?} must be usable");
            assert_eq!(recipe_token(flag), rendered, "{flag:?}");
        }
        for flag in ["-DX=%PATH%", "-DX=a\"b c", "-DX=`id`", "-DX=$(id)"] {
            assert!(!is_compile_flag_usable(flag), "{flag:?} must be refused");
            assert!(ensure_all_compile_flags_safe([flag]).is_err(), "{flag:?}");
        }
        // A flag or path that is safe bare, backslashes and the `~` of an 8.3
        // short name included, is unchanged.
        assert_eq!(recipe_token(r"-IC:\src\include"), r"-IC:\src\include");
        assert_eq!(recipe_token("-DNDEBUG"), "-DNDEBUG");
        assert!(is_build_input_safe(r"C:\Users\ADMINI~1\AppData\Local\Temp"));
    }

    /// Inside double quotes `sh` reads `\"` as a literal quote and the Windows
    /// argument parser does the same, so a trailing backslash would swallow the
    /// closing quote. Doubled, both read back the original value.
    #[test]
    fn a_windows_double_quoted_flag_keeps_its_trailing_backslashes() {
        assert_eq!(windows_double_quoted("-DBAR=(x)"), "\"-DBAR=(x)\"");
        assert_eq!(
            windows_double_quoted(r"-IC:\Kit (x86)\"),
            r#""-IC:\Kit (x86)\\""#
        );
        assert_eq!(
            windows_double_quoted(r"-IC:\Kit (x86)\\"),
            r#""-IC:\Kit (x86)\\\\""#
        );
    }

    #[test]
    fn a_refused_compile_flag_names_the_character() {
        let error = ensure_all_compile_flags_safe(["-DX=$(id)"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("'$'"), "{error}");
        let error = ensure_all_compile_flags_safe(["-DX=a\nb"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("'\\n'"), "{error}");
    }

    /// Glob, brace, tilde and history characters are inert inside the double
    /// quotes a path gets in a recipe, so a path may carry them.
    #[cfg(not(windows))]
    #[test]
    fn paths_with_glob_and_brace_characters_are_quoted_not_refused() {
        for path in [
            "/data/proj [old]/src/a.c",
            "/data/proj~backup/include",
            "/data/wow!/src",
            "/data/{tmp}/a*b?.c",
        ] {
            assert!(is_build_path_usable(path), "{path:?} must be usable");
            assert_eq!(recipe_path(path), format!("\"{path}\""));
        }
    }

    #[test]
    fn a_compiler_path_with_spaces_is_accepted_and_quoted() {
        let clang = "C:/Program Files/LLVM/bin/clang.exe";
        assert!(is_compiler_token(clang));
        assert_eq!(recipe_path(clang), format!("\"{clang}\""));
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
