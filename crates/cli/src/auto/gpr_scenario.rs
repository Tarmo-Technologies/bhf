// SPDX-License-Identifier: Apache-2.0

//! Evaluate a GNAT project file's scenario `case` statements with their default
//! `external (...)` values, to find `Source_Dirs` that the *default* build
//! configuration excludes.
//!
//! GNAT projects routinely gate source directories on a scenario variable
//! (libkeccak's `LIBKECCAK_SIMD` selects `src/x86_64/AVX2`; a bare-metal crate's
//! config selects an RP2040 critical-section body). `gprbuild` compiles only the
//! directories active under the chosen scenario, but bhf walks the whole
//! tree — so it tries to compile scenario-excluded sources (host can't assemble
//! `-mavx2` intrinsics; a bare-metal body references hardware addresses) and the
//! whole harness fails to build.
//!
//! This is a focused evaluator, not a full GPR interpreter: it tracks the
//! default value of each `external`-initialised scenario variable, walks the
//! `case`/`when`/`others` structure, and classifies every directory-string
//! literal as referenced by an *active* (default) region or only by an
//! *inactive* one. A directory referenced only by inactive branches — and which
//! actually exists on disk — is reported as excluded. The existence check and
//! the "never exclude a dir also seen active" rule keep it safe: a parse the
//! evaluator doesn't understand can at worst fail to exclude something (falling
//! back to today's whole-tree behaviour), never wrongly drop an active dir.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Find the project file governing `root` — the first `*.gpr` in `root` itself,
/// else walking up to 8 parents. Returns `None` when there is no project file.
pub fn find_project_gpr(root: &Path) -> Option<PathBuf> {
    let mut dir = Some(root.to_path_buf());
    for _ in 0..8 {
        let current = dir?;
        if let Ok(entries) = std::fs::read_dir(&current) {
            let mut gprs: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("gpr")))
                .collect();
            if !gprs.is_empty() {
                gprs.sort();
                // #7: prefer a concrete, buildable project. An aggregate cannot be
                // extended and has no Source_Dirs of its own (so the instrumented
                // overlay would find no sources), and an abstract project has no
                // sources — so if a real component GPR sits alongside them, pick it.
                // Fall back to the alphabetically-first GPR only when every
                // candidate is aggregate/abstract.
                if let Some(concrete) = gprs.iter().find(|gpr| {
                    std::fs::read_to_string(gpr)
                        .map(|text| !gpr_declares_aggregate(&text) && !gpr_declares_abstract(&text))
                        .unwrap_or(false)
                }) {
                    return Some(concrete.clone());
                }
                return gprs.into_iter().next();
            }
        }
        dir = current.parent().map(Path::to_path_buf);
    }
    None
}

/// #91: select the GPR that GOVERNS `candidate_source` — the non-aggregate
/// component project whose active `Source_Dirs` actually contain the candidate —
/// rather than the alphabetically-first `.gpr` near the root. Multi-project Ada
/// repos routinely mix library, test, tool, aggregate, and abstract-umbrella
/// projects; picking the wrong one gives the harness the wrong source closure or
/// a project GNAT cannot extend (an aggregate). Aggregates are never selected;
/// abstract and Main/test/tool projects are ranked last. Selection is fully
/// deterministic (sorted enumeration + a total-order tie-break). Falls back to the
/// legacy [`find_project_gpr`] when no project owns the candidate (a gprless source
/// tree, or a project the evaluator cannot read).
pub fn select_governing_gpr(candidate_source: &Path, search_root: &Path) -> Option<PathBuf> {
    let canon_src = candidate_source.canonicalize().ok();
    // (is_abstract, is_main_or_test, path) for every project that OWNS the source.
    let mut owners: Vec<(bool, bool, PathBuf)> = Vec::new();
    for gpr in enumerate_gprs(search_root) {
        let Ok(text) = std::fs::read_to_string(&gpr) else {
            continue;
        };
        let stripped = strip_comments(&text);
        if gpr_declares_aggregate(&stripped) {
            // An aggregate bundles sub-projects and cannot be a build/extension
            // base — never own the candidate through it.
            continue;
        }
        // #287: `Source_Dirs` spelled `"src/" & project'Name` names no
        // literal directory; read it as gprbuild does too.
        let owns = match &canon_src {
            Some(src) => {
                active_source_dirs(&gpr)
                    .iter()
                    .any(|dir| src.starts_with(dir))
                    || in_source_dirs(&project_source_dirs(&gpr), src)
            }
            None => false,
        };
        if !owns {
            continue;
        }
        owners.push((
            gpr_declares_abstract(&stripped),
            gpr_is_main_or_test(&stripped, &gpr),
            gpr,
        ));
    }
    // Prefer a concrete library component: non-abstract, non-Main/test, then the
    // deepest (most specific) project path, then lexicographic — all deterministic
    // so repeated runs select byte-identically.
    owners.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.cmp(&b.1))
            .then(b.2.components().count().cmp(&a.2.components().count()))
            .then(a.2.cmp(&b.2))
    });
    owners
        .into_iter()
        .next()
        .map(|(_, _, path)| path)
        .or_else(|| find_project_gpr(search_root))
}

/// #91: enumerate every `*.gpr` under `root` and up to 8 parents, deduplicated
/// and sorted, so governing-project selection is deterministic.
fn enumerate_gprs(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut dir = Some(root.to_path_buf());
    for _ in 0..8 {
        let Some(current) = dir else { break };
        if let Ok(entries) = std::fs::read_dir(&current) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("gpr"))
                    && !out.contains(&path)
                {
                    out.push(path);
                }
            }
        }
        dir = current.parent().map(Path::to_path_buf);
    }
    out.sort();
    out
}

/// Whitespace-normalized, lower-cased view of comment-stripped GPR text, for the
/// project-qualifier checks below (GPR keywords are case-insensitive and the
/// whitespace between them varies).
fn gpr_normalized(text: &str) -> String {
    text.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// #91: whether the GPR declares an AGGREGATE project (`aggregate project Foo is`,
/// or `aggregate library project`). An aggregate cannot be a build/extension base.
fn gpr_declares_aggregate(text: &str) -> bool {
    let n = gpr_normalized(text);
    n.contains("aggregate project") || n.contains("aggregate library project")
}

/// #91: whether the GPR declares an ABSTRACT project — an umbrella with no
/// sources of its own that should not be extended to build the harness.
fn gpr_declares_abstract(text: &str) -> bool {
    let n = gpr_normalized(text);
    n.contains("abstract project") || n.contains("abstract library project")
}

/// Offline-legacy audit #1: whether the GPR declares a LIBRARY project. GNAT
/// rejects `project X extends "lib.gpr"` on a library project unless X declares
/// `Library_Dir` — and a library project can't carry the harness `Main` anyway —
/// so a library project is not a valid base for the synthesized extending build.
fn gpr_declares_library(text: &str) -> bool {
    let n = gpr_normalized(text);
    // `library project Foo is`. (`aggregate library project` is handled by
    // gpr_declares_aggregate; matching "library project" here too is harmless —
    // both mean "not extendable".) The `for library_dir` / `for library_name`
    // attributes are the ones GNAT's diagnostic keys on, so honor them as a
    // fallback for oddly-formatted headers.
    n.contains("library project") || n.contains("for library_dir") || n.contains("for library_name")
}

/// Whether `gpr_path` declares a library project (#287).
pub(crate) fn gpr_is_library_project(gpr_path: &Path) -> bool {
    std::fs::read_to_string(gpr_path).is_ok_and(|text| gpr_declares_library(&text))
}

/// Offline-legacy audit #1/#7: whether `gpr_path` can be safely EXTENDED to build
/// the harness. Library, aggregate, and abstract projects cannot be: extending a
/// library project requires the child to declare `Library_Dir` (and it still
/// can't hold the harness `Main`); an aggregate project cannot be extended at
/// all; an abstract project has no sources. For any of these the harness is built
/// as a STANDALONE project over the instrumented source overlay — which already
/// carries the governing project's `Source_Dirs`
/// ([`ensure_ada_src_instrumented`]) — instead of extending. An unreadable GPR is
/// treated as non-extendable (conservative: the standalone path still builds).
pub(crate) fn gpr_is_extendable_base(gpr_path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(gpr_path) else {
        return false;
    };
    !gpr_declares_library(&text) && !gpr_declares_aggregate(&text) && !gpr_declares_abstract(&text)
}

/// #91: whether the GPR builds an executable / test / tool — it has a `for Main
/// use (...)` (an executable, typically a test runner or CLI driver) or a project
/// file name that reads as a test/tool/example. Such a project imports its library
/// rather than owning it, so it is ranked below a real library component.
fn gpr_is_main_or_test(text: &str, gpr_path: &Path) -> bool {
    if gpr_normalized(text).contains("for main use") {
        return true;
    }
    let stem = gpr_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    [
        "test", "tests", "tool", "tools", "example", "examples", "demo",
    ]
    .iter()
    .any(|k| stem.contains(k))
}

/// Directories referenced only by non-default scenario branches of `gpr_path`
/// (canonicalised, absolute). A dir also referenced by the default configuration
/// is never excluded. Returns empty when the file can't be read or has no
/// scenario-gated directories.
pub fn scenario_excluded_dirs(gpr_path: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(gpr_path) else {
        return Vec::new();
    };
    let base = gpr_path.parent().unwrap_or_else(|| Path::new("."));
    let stripped = strip_comments(&text);
    let scenario = scenario_defaults(&stripped);
    let (active, inactive) = classify_dir_literals(&stripped, &scenario);

    let mut out = Vec::new();
    for dir in inactive.difference(&active) {
        let candidate = base.join(dir);
        if candidate.is_dir() {
            if let Ok(canon) = candidate.canonicalize() {
                if !out.contains(&canon) {
                    out.push(canon);
                }
            }
        }
    }
    out
}

/// The source directories the DEFAULT build configuration of `gpr_path` includes
/// (#450): every directory-string literal referenced by an ACTIVE (default-
/// scenario) region of the project file, resolved relative to the `.gpr`,
/// existing on disk AND containing Ada sources (so an `Object_Dir`/library dir
/// string isn't mistaken for a source dir), canonicalised. Used to feed a
/// multi-directory Ada library's full source-dir closure into the harness build
/// (ada-util's `src/sys/encoders` pulling `src/core` + `src/sys`) instead of the
/// harness seeing only the scanned subdir and failing `missing_ada_symbol`.
pub fn active_source_dirs(gpr_path: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(gpr_path) else {
        return Vec::new();
    };
    let base = gpr_path.parent().unwrap_or_else(|| Path::new("."));
    let stripped = strip_comments(&text);
    let scenario = scenario_defaults(&stripped);
    let (active, _inactive) = classify_dir_literals(&stripped, &scenario);

    let mut out = Vec::new();
    for dir in &active {
        let candidate = base.join(dir);
        if candidate.is_dir() && dir_has_ada_sources(&candidate) {
            if let Ok(canon) = candidate.canonicalize() {
                if !out.contains(&canon) {
                    out.push(canon);
                }
            }
        }
    }
    out.sort();
    out
}

/// The projects `gpr_path` names in its `with` clauses (`limited with` too),
/// resolved beside it; ones that are not files there (a `GPR_PROJECT_PATH`
/// lookup) are left out.
pub fn project_with_clauses(gpr_path: &Path) -> Vec<PathBuf> {
    project_path_clauses(gpr_path, r#"(?i)\bwith\s+((?:"[^"]+"\s*,\s*)*"[^"]+")\s*;"#)
}

/// The projects `gpr_path` `extends` (`extends "base.gpr"`, `extends all`).
fn project_extends_clauses(gpr_path: &Path) -> Vec<PathBuf> {
    project_path_clauses(gpr_path, r#"(?i)\bextends\s+(?:all\s+)?("[^"]+")"#)
}

fn project_path_clauses(gpr_path: &Path, pattern: &str) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(gpr_path) else {
        return Vec::new();
    };
    let base = gpr_path.parent().unwrap_or_else(|| Path::new("."));
    let clause = regex::Regex::new(pattern).expect("regex");
    let quoted = regex::Regex::new(r#""([^"]+)""#).expect("regex");
    let mut out = Vec::new();
    for caps in clause.captures_iter(&strip_comments(&text)) {
        for name in quoted.captures_iter(&caps[1]) {
            let mut name = name[1].to_owned();
            if !name.to_ascii_lowercase().ends_with(".gpr") {
                name.push_str(".gpr");
            }
            if let Ok(path) = base.join(&name).canonicalize() {
                if path.is_file() && !out.contains(&path) {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Every project `gpr_path` depends on through `with` (#287): the projects it
/// `with`s, the ones those `with` or `extend`, and so on. Not `gpr_path`, and
/// not a project it `extends`, whose units an extension may override.
pub fn withed_project_closure(gpr_path: &Path) -> Vec<PathBuf> {
    const MAX_PROJECTS: usize = 64;
    let own = gpr_path
        .canonicalize()
        .unwrap_or_else(|_| gpr_path.to_path_buf());
    let mut excluded = project_extends_clauses(gpr_path);
    excluded.push(own);
    let mut out: Vec<PathBuf> = Vec::new();
    let mut queue = project_with_clauses(gpr_path);
    while let Some(project) = queue.pop() {
        if out.len() >= MAX_PROJECTS || excluded.contains(&project) || out.contains(&project) {
            continue;
        }
        queue.extend(project_with_clauses(&project));
        queue.extend(project_extends_clauses(&project));
        out.push(project);
    }
    out.sort();
    out
}

/// The directories `gpr_path`'s sources are in, as gprbuild reads its
/// `Source_Dirs` (#287), each with whether it takes the directories below it
/// (`"src/**"`): an element of string literals and `project'Name`, joined by
/// `&` (whitakers-words' `"src/" & project'Name`), relative to the project's
/// directory. A project that declares no `Source_Dirs` has its own directory
/// (an abstract one, none); `()` none. An element of another form (a variable, `external`) is left out,
/// and every `Source_Dirs` of every scenario counts.
pub fn project_source_dirs(gpr_path: &Path) -> Vec<(PathBuf, bool)> {
    let Ok(text) = std::fs::read_to_string(gpr_path) else {
        return Vec::new();
    };
    let base = gpr_path.parent().unwrap_or_else(|| Path::new("."));
    let text = strip_comments(&text);
    let name = regex::Regex::new(
        r"(?i)\bproject\s+([A-Za-z][A-Za-z0-9_.]*)\s+(?:extends\b[^;]*?\s+)?is\b",
    )
    .expect("regex")
    .captures(&text)
    .map(|caps| caps[1].to_ascii_lowercase());
    let attribute =
        regex::Regex::new(r"(?is)\bfor\s+source_dirs\s+use\s*\((.*?)\)\s*;").expect("regex");
    let mut lists = attribute.captures_iter(&text).peekable();
    if lists.peek().is_none() {
        // An abstract project has no sources unless it names some.
        if gpr_declares_abstract(&text) {
            return Vec::new();
        }
        return base
            .canonicalize()
            .map(|dir| vec![(dir, false)])
            .unwrap_or_default();
    }
    let literal = regex::Regex::new(r#"^"([^"]*)"$"#).expect("regex");
    let mut out = Vec::new();
    for list in lists {
        for element in list[1].split(',') {
            let element = element.trim();
            if element.is_empty() {
                continue;
            }
            let mut value = String::new();
            let evaluated = element.split('&').all(|part| {
                let part = part.trim();
                if let Some(caps) = literal.captures(part) {
                    value.push_str(&caps[1]);
                    true
                } else if part.eq_ignore_ascii_case("project'name") {
                    name.as_deref().map(|name| value.push_str(name)).is_some()
                } else {
                    false
                }
            });
            if !evaluated {
                continue;
            }
            let (dir, recursive) = match value.strip_suffix("**") {
                Some(prefix) => (prefix.trim_end_matches('/').to_owned(), true),
                None => (value, false),
            };
            let dir = if dir.is_empty() { ".".to_owned() } else { dir };
            if let Ok(dir) = base.join(dir).canonicalize() {
                if !out.iter().any(|(existing, _)| existing == &dir) {
                    out.push((dir, recursive));
                }
            }
        }
    }
    out
}

/// The source directories of the projects `gpr_path` depends on through
/// `with` ([`withed_project_closure`]), less its own: a unit there is that
/// project's, and the build compiles it there (#287).
pub fn withed_project_source_dirs(gpr_path: &Path) -> Vec<(PathBuf, bool)> {
    let own = project_source_dirs(gpr_path);
    let mut out: Vec<(PathBuf, bool)> = Vec::new();
    for project in withed_project_closure(gpr_path) {
        for (dir, recursive) in project_source_dirs(&project) {
            let is_own = own.iter().any(|(own_dir, _)| own_dir == &dir);
            if !is_own && !out.iter().any(|(existing, _)| existing == &dir) {
                out.push((dir, recursive));
            }
        }
    }
    out
}

/// Whether `path` is in one of `dirs` ([`project_source_dirs`]).
pub fn in_source_dirs(dirs: &[(PathBuf, bool)], path: &Path) -> bool {
    let Some(parent) = path.parent().and_then(|dir| dir.canonicalize().ok()) else {
        return false;
    };
    dirs.iter()
        .any(|(dir, recursive)| &parent == dir || (*recursive && parent.starts_with(dir)))
}

/// Whether `dir` directly contains an Ada source file (`.ads`/`.adb`).
fn dir_has_ada_sources(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries.flatten().any(|e| {
                e.path().extension().is_some_and(|x| {
                    let x = x.to_ascii_lowercase();
                    x == "ads" || x == "adb"
                })
            })
        })
        .unwrap_or(false)
}

/// Strip `--` line comments (GPR has no block comments).
fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("--") {
            Some(pos) => &line[..pos],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Map each `external`-initialised scenario variable to its default value (the
/// innermost default of a possibly-nested `external(...)` chain, i.e. the last
/// quoted string in the initializer). Only `external`-driven variables are
/// recorded — plain list variables are not scenario selectors.
fn scenario_defaults(text: &str) -> HashMap<String, String> {
    let mut defaults = HashMap::new();
    for stmt in text.split(';') {
        let Some(assign) = stmt.find(":=") else {
            continue;
        };
        let lhs = stmt[..assign].trim();
        let rhs = &stmt[assign + 2..];
        // The variable name is the last identifier before the type colon
        // (`Arch` from `Arch : Arch_Kind`), or the last word of the LHS when
        // there is no type annotation. Splitting on the first ':' would keep
        // leading tokens like `project P is` when no `;` precedes the decl.
        let before_colon = match lhs.find(':') {
            Some(colon) => &lhs[..colon],
            None => lhs,
        };
        let Some(var) = before_colon.split_whitespace().last() else {
            continue;
        };
        if !is_identifier(var) {
            continue;
        }
        // An `external (...)`-driven scenario variable's default is the innermost
        // quoted string of the initializer. A plainly-assigned selector
        // (`OS : OS_Kind := "linux"`, the common OS-variant idiom that gates
        // `for Source_Dirs use` per branch) defaults to that single string
        // literal. A list assignment (`Dirs := (...)`) or a non-string value
        // yields no default and is not a scenario selector.
        let default = if rhs.contains("external") || rhs.contains("External") {
            last_quoted(rhs)
        } else {
            single_string_literal(rhs)
        };
        if let Some(default) = default {
            defaults.insert(var.to_ascii_lowercase(), default);
        }
    }
    defaults
}

/// The single `"..."` string literal `s` consists of, ignoring surrounding
/// whitespace. `None` when `s` is not exactly one literal (a `(...)` list, an
/// `external(...)` call, a `"a" & "b"` concatenation, or a non-string value) — so
/// only a plain scalar string default is captured as a scenario value.
fn single_string_literal(s: &str) -> Option<String> {
    let trimmed = s.trim();
    let inner = trimmed.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('"') {
        return None;
    }
    Some(inner.to_owned())
}

/// The last `"..."` string literal in `s`.
fn last_quoted(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut last = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(end) = s[i + 1..].find('"') {
                last = Some(s[i + 1..i + 1 + end].to_owned());
                i = i + 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    last
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Arrow,
    Sym(char),
}

fn tokenize(text: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '"' {
            if let Some(end) = text[i + 1..].find('"') {
                toks.push(Tok::Str(text[i + 1..i + 1 + end].to_owned()));
                i = i + 1 + end + 1;
                continue;
            }
            i += 1;
        } else if c == '=' && i + 1 < bytes.len() && bytes[i + 1] == b'>' {
            toks.push(Tok::Arrow);
            i += 2;
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < bytes.len()
                && ((bytes[i] as char).is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            toks.push(Tok::Word(text[start..i].to_owned()));
        } else if c.is_whitespace() {
            i += 1;
        } else {
            toks.push(Tok::Sym(c));
            i += 1;
        }
    }
    toks
}

struct CaseFrame {
    /// Ordinal of the `when` branch this case selects (precomputed at the `case`
    /// keyword), and the running count of `when`s seen so far.
    selected: usize,
    when_index: usize,
    branch_active: bool,
}

/// Walk the `case`/`when`/`others` structure, returning (active, inactive) sets
/// of directory-string literals. A literal is "active" when every enclosing case
/// branch is the one its scenario variable's default value selects. Exactly one
/// branch per case is selected ([`case_branch_selection`]): the value-matching
/// branch, else `others`, else the first — so the same unit defined under several
/// OS variants contributes one coherent variant's dirs, never all (conflicting)
/// nor none (under-included).
fn classify_dir_literals(
    text: &str,
    scenario: &HashMap<String, String>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let toks = tokenize(text);
    let mut stack: Vec<CaseFrame> = Vec::new();
    let mut active = BTreeSet::new();
    let mut inactive = BTreeSet::new();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            Tok::Word(w) if w.eq_ignore_ascii_case("case") => {
                // `case <Var> is`
                let var = match toks.get(i + 1) {
                    Some(Tok::Word(v)) => v.to_ascii_lowercase(),
                    _ => String::new(),
                };
                let value = scenario.get(&var).cloned().unwrap_or_default();
                let selected = case_branch_selection(&toks, i, &value);
                stack.push(CaseFrame {
                    selected,
                    when_index: 0,
                    branch_active: false,
                });
                i += 1;
            }
            Tok::Word(w) if w.eq_ignore_ascii_case("when") => {
                // Advance past the when-values to the `=>`; the active branch was
                // chosen up front, so only the ordinal matters here.
                let mut j = i + 1;
                while j < toks.len() && !matches!(toks[j], Tok::Arrow) {
                    j += 1;
                }
                if let Some(frame) = stack.last_mut() {
                    frame.branch_active = frame.when_index == frame.selected;
                    frame.when_index += 1;
                }
                i = j;
            }
            Tok::Word(w) if w.eq_ignore_ascii_case("end") => {
                if matches!(toks.get(i + 1), Some(Tok::Word(c)) if c.eq_ignore_ascii_case("case")) {
                    stack.pop();
                    i += 1;
                }
            }
            Tok::Str(s) => {
                let region_active = stack.iter().all(|f| f.branch_active);
                if region_active {
                    active.insert(s.clone());
                } else {
                    inactive.insert(s.clone());
                }
            }
            _ => {}
        }
        i += 1;
    }
    (active, inactive)
}

/// The ordinal of the `when` branch a case selects, given its scenario variable's
/// resolved `value`. Scans the case's own `when` branches (skipping any nested
/// case) and picks, in order of preference: the branch whose values include
/// `value`; else the `others` branch; else the first branch — a single coherent
/// variant. `case_pos` is the index of the opening `case` keyword.
fn case_branch_selection(toks: &[Tok], case_pos: usize, value: &str) -> usize {
    let mut branches: Vec<(Vec<String>, bool)> = Vec::new();
    let mut depth = 0i32;
    let mut i = case_pos;
    while i < toks.len() {
        match &toks[i] {
            Tok::Word(w) if w.eq_ignore_ascii_case("case") => {
                depth += 1;
                i += 1;
            }
            Tok::Word(w)
                if w.eq_ignore_ascii_case("end")
                    && matches!(toks.get(i + 1), Some(Tok::Word(c)) if c.eq_ignore_ascii_case("case")) =>
            {
                depth -= 1;
                i += 2; // skip `end case`
                if depth == 0 {
                    break;
                }
            }
            Tok::Word(w) if depth == 1 && w.eq_ignore_ascii_case("when") => {
                let mut values = Vec::new();
                let mut others = false;
                let mut j = i + 1;
                while j < toks.len() && !matches!(toks[j], Tok::Arrow) {
                    match &toks[j] {
                        Tok::Str(s) => values.push(s.clone()),
                        Tok::Word(ow) if ow.eq_ignore_ascii_case("others") => others = true,
                        _ => {}
                    }
                    j += 1;
                }
                branches.push((values, others));
                i = j;
            }
            _ => i += 1,
        }
    }
    branches
        .iter()
        .position(|(values, _)| values.iter().any(|v| v == value))
        .or_else(|| branches.iter().position(|(_, others)| *others))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> crate::test_support::TestDir {
        crate::test_support::TestDir::new(&format!("gpr-{name}"))
    }

    /// #287: whitakers-words' layout. `Source_Dirs` is `"src/" &
    /// project'Name`; `commands.gpr` `with`s `words_engine.gpr`, which `with`s
    /// `support_utils.gpr`; `shared.gpr` is abstract.
    #[test]
    fn a_withed_project_closure_and_its_source_dirs_are_read_as_gprbuild_reads_them() {
        let root = tmp("withed-closure");
        let project = |name: &str, kind: &str, withs: &[&str]| {
            let clauses: String = withs
                .iter()
                .map(|w| format!("with \"{w}.gpr\";\n"))
                .collect();
            std::fs::write(
                root.join(format!("{name}.gpr")),
                format!(
                    "{clauses}{kind}project {name} is\n   for Source_Dirs use (\"src/\" & \
                     project'Name);  -- one directory per project\nend {name};\n"
                ),
            )
            .unwrap();
            std::fs::create_dir_all(root.join("src").join(name.to_ascii_lowercase())).unwrap();
        };
        project("Commands", "", &["shared", "words_engine"]);
        project("Words_Engine", "library ", &["shared", "support_utils"]);
        project("Support_Utils", "library ", &["shared"]);
        std::fs::write(
            root.join("shared.gpr"),
            "abstract project Shared is\nend Shared;\n",
        )
        .unwrap();
        std::fs::write(root.join("tools.gpr"), "project Tools is\nend Tools;\n").unwrap();
        let canon = |rel: &str| root.join(rel).canonicalize().unwrap();
        // `with` clauses name `commands`'s file as `Commands.gpr`; on a
        // case-sensitive file system they resolve as written.
        std::fs::rename(root.join("Commands.gpr"), root.join("commands.gpr")).unwrap();
        std::fs::rename(root.join("Words_Engine.gpr"), root.join("words_engine.gpr")).unwrap();
        std::fs::rename(
            root.join("Support_Utils.gpr"),
            root.join("support_utils.gpr"),
        )
        .unwrap();

        let commands = root.join("commands.gpr");
        assert_eq!(
            withed_project_closure(&commands),
            [
                canon("shared.gpr"),
                canon("support_utils.gpr"),
                canon("words_engine.gpr")
            ]
        );
        assert_eq!(
            project_source_dirs(&commands),
            [(canon("src/commands"), false)]
        );
        assert!(project_source_dirs(&root.join("shared.gpr")).is_empty());
        assert_eq!(
            project_source_dirs(&root.join("tools.gpr")),
            [(canon("."), false)]
        );
        let elsewhere = withed_project_source_dirs(&commands);
        assert_eq!(
            elsewhere,
            [
                (canon("src/support_utils"), false),
                (canon("src/words_engine"), false)
            ]
        );
        std::fs::write(root.join("src/support_utils/x.adb"), "").unwrap();
        std::fs::write(root.join("src/commands/y.adb"), "").unwrap();
        assert!(in_source_dirs(
            &elsewhere,
            &root.join("src/support_utils/x.adb")
        ));
        assert!(!in_source_dirs(
            &elsewhere,
            &root.join("src/commands/y.adb")
        ));
        // The governing project of a `src/support_utils` source is the one whose
        // `Source_Dirs` name it.
        assert_eq!(
            select_governing_gpr(&root.join("src/support_utils/x.adb"), &root),
            Some(root.join("support_utils.gpr"))
        );
    }

    #[test]
    fn recursive_and_multi_project_clauses_are_read() {
        let root = tmp("recursive-dirs");
        std::fs::create_dir_all(root.join("src/a/deep")).unwrap();
        std::fs::write(
            root.join("p.gpr"),
            "with \"q\", \"r.gpr\";\nproject P is\n   for Source_Dirs use (\"src/**\", \"gen\", Extra);\nend P;\n",
        )
        .unwrap();
        std::fs::write(root.join("q.gpr"), "project Q is\nend Q;\n").unwrap();
        std::fs::write(root.join("r.gpr"), "project R is\nend R;\n").unwrap();
        let dirs = project_source_dirs(&root.join("p.gpr"));
        assert_eq!(dirs, [(root.join("src").canonicalize().unwrap(), true)]);
        std::fs::write(root.join("src/a/deep/z.adb"), "").unwrap();
        assert!(in_source_dirs(&dirs, &root.join("src/a/deep/z.adb")));
        assert_eq!(project_with_clauses(&root.join("p.gpr")).len(), 2);
    }

    #[test]
    fn active_source_dirs_returns_default_scenario_ada_source_dirs() {
        // #450: a multi-directory library lists several Source_Dirs; active_source_dirs
        // returns the Ada-source ones, dropping a non-source (object) dir.
        let root = tmp("ada-util");
        for d in ["src/core", "src/sys/encoders", "obj"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(
            root.join("src/core/util.ads"),
            "package Util is end Util;\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/sys/encoders/enc.ads"),
            "package Enc is end Enc;\n",
        )
        .unwrap();
        let gpr = root.join("utilada.gpr");
        std::fs::write(
            &gpr,
            "project Utilada is\n   for Source_Dirs use (\"src/core\", \"src/sys/encoders\", \"obj\");\n   for Object_Dir use \"obj\";\nend Utilada;\n",
        )
        .unwrap();

        let dirs = active_source_dirs(&gpr);
        assert!(dirs.iter().any(|p| p.ends_with("src/core")), "{dirs:?}");
        assert!(dirs.iter().any(|p| p.ends_with("encoders")), "{dirs:?}");
        assert!(
            !dirs.iter().any(|p| p.ends_with("obj")),
            "object dir (no Ada sources) must be excluded: {dirs:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn active_source_dirs_excludes_inactive_scenario_branch() {
        // A scenario-gated dir active only under a non-default value is NOT returned.
        let root = tmp("ada-scenario");
        for d in ["src/common", "src/avx2"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("src/common/c.ads"), "package C is end C;\n").unwrap();
        std::fs::write(root.join("src/avx2/a.ads"), "package A is end A;\n").unwrap();
        let gpr = root.join("lib.gpr");
        std::fs::write(
            &gpr,
            "project Lib is\n   type Simd_Kind is (\"none\", \"avx2\");\n   Simd : Simd_Kind := external (\"SIMD\", \"none\");\n   Dirs := (\"src/common\");\n   case Simd is\n      when \"avx2\" => Dirs := Dirs & (\"src/avx2\");\n      when others => null;\n   end case;\n   for Source_Dirs use Dirs;\nend Lib;\n",
        )
        .unwrap();

        let dirs = active_source_dirs(&gpr);
        assert!(dirs.iter().any(|p| p.ends_with("common")), "{dirs:?}");
        assert!(
            !dirs.iter().any(|p| p.ends_with("avx2")),
            "non-default SIMD dir must be excluded: {dirs:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn excludes_simd_dirs_active_under_non_default_scenario() {
        // libkeccak's pattern: SIMD dirs added only under non-default Arch/SIMD.
        let root = tmp("libkeccak");
        for d in [
            "src/common",
            "src/generic",
            "src/x86_64/SSE2_defs",
            "src/x86_64/SSE2",
            "src/x86_64/AVX2_defs",
            "src/x86_64/AVX2",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let gpr = root.join("libkeccak.gpr");
        std::fs::write(
            &gpr,
            r#"
            project Libkeccak is
               type Arch_Kind is ("generic", "x86_64");
               type SIMD_Kind is ("none", "SSE2", "AVX2");
               Arch : Arch_Kind := external ("LIBKECCAK_ARCH", "generic");
               SIMD : SIMD_Kind := external ("LIBKECCAK_SIMD", "none");
               Arch_Dirs := ();
               case Arch is
                  when "generic" =>
                     Arch_Dirs := Arch_Dirs & ("src/generic");
                  when "x86_64" =>
                     case SIMD is
                        when "none" => Arch_Dirs := Arch_Dirs & ("src/generic");
                        when "SSE2" => Arch_Dirs := Arch_Dirs & ("src/x86_64/SSE2_defs", "src/x86_64/SSE2");
                        when "AVX2" => Arch_Dirs := Arch_Dirs & ("src/x86_64/SSE2_defs", "src/x86_64/AVX2_defs", "src/x86_64/AVX2");
                     end case;
               end case;
               for Source_Dirs use ("src/common") & Arch_Dirs;
            end Libkeccak;
            "#,
        )
        .unwrap();

        let excluded = scenario_excluded_dirs(&gpr);
        let names: BTreeSet<String> = excluded
            .iter()
            .map(|p| {
                p.strip_prefix(root.canonicalize().unwrap())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        assert!(
            names.contains("src/x86_64/AVX2") && names.contains("src/x86_64/SSE2"),
            "SIMD dirs must be excluded: {names:?}"
        );
        assert!(
            !names.contains("src/common") && !names.contains("src/generic"),
            "default-active dirs must NOT be excluded (src/generic is also active): {names:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn active_source_dirs_picks_default_os_variant_for_source_dirs_in_case() {
        // The OS-variant idiom: a literal-default scenario selector gates
        // `for Source_Dirs use (...)` per branch. The default variant's dirs are
        // taken; the other OS's dir (which redefines the SAME unit) is dropped so
        // the build doesn't see two `OS` bodies.
        let root = tmp("os-variant");
        for d in ["src/common", "src/linux", "src/windows"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("src/common/c.ads"), "package C is end C;\n").unwrap();
        std::fs::write(
            root.join("src/linux/os.adb"),
            "package body OS is end OS;\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/windows/os.adb"),
            "package body OS is end OS;\n",
        )
        .unwrap();
        let gpr = root.join("app.gpr");
        std::fs::write(
            &gpr,
            "project App is\n   type OS_Kind is (\"linux\", \"windows\");\n   OS_Var : OS_Kind := \"linux\";\n   case OS_Var is\n      when \"linux\" => for Source_Dirs use (\"src/common\", \"src/linux\");\n      when \"windows\" => for Source_Dirs use (\"src/common\", \"src/windows\");\n   end case;\nend App;\n",
        )
        .unwrap();
        let dirs = active_source_dirs(&gpr);
        assert!(dirs.iter().any(|p| p.ends_with("src/common")), "{dirs:?}");
        assert!(dirs.iter().any(|p| p.ends_with("src/linux")), "{dirs:?}");
        assert!(
            !dirs.iter().any(|p| p.ends_with("src/windows")),
            "non-default OS dir (redefining the same unit) must be excluded: {dirs:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn active_source_dirs_picks_first_variant_when_default_unresolvable() {
        // No external/literal default the parser can resolve: rather than drop ALL
        // variant dirs (under-include -> missing unit) or take them all (two `OS`
        // bodies), pick the first branch — one coherent variant.
        let root = tmp("os-no-default");
        for d in ["src/posix", "src/win32"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(
            root.join("src/posix/os.adb"),
            "package body OS is end OS;\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/win32/os.adb"),
            "package body OS is end OS;\n",
        )
        .unwrap();
        let gpr = root.join("app.gpr");
        std::fs::write(
            &gpr,
            "project App is\n   case OS_Var is\n      when \"posix\" => for Source_Dirs use (\"src/posix\");\n      when \"win32\" => for Source_Dirs use (\"src/win32\");\n   end case;\nend App;\n",
        )
        .unwrap();
        let dirs = active_source_dirs(&gpr);
        assert!(dirs.iter().any(|p| p.ends_with("src/posix")), "{dirs:?}");
        assert!(
            !dirs.iter().any(|p| p.ends_with("src/win32")),
            "only one coherent variant must be taken: {dirs:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn no_scenario_gating_excludes_nothing() {
        let root = tmp("plain");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let gpr = root.join("p.gpr");
        std::fs::write(
            &gpr,
            "project P is\n   for Source_Dirs use (\"src\");\nend P;\n",
        )
        .unwrap();
        assert!(scenario_excluded_dirs(&gpr).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dir_referenced_in_both_active_and_inactive_is_not_excluded() {
        // `src/generic` appears under both the default branch and (nested) the
        // non-default one; it must stay (seen active wins).
        let root = tmp("shared");
        std::fs::create_dir_all(root.join("src/generic")).unwrap();
        std::fs::create_dir_all(root.join("src/avx")).unwrap();
        let gpr = root.join("p.gpr");
        std::fs::write(
            &gpr,
            r#"
            project P is
               Arch : T := external ("ARCH", "generic");
               case Arch is
                  when "generic" => D := ("src/generic");
                  when "x86" => D := ("src/generic", "src/avx");
               end case;
            end P;
            "#,
        )
        .unwrap();
        let excluded: BTreeSet<String> = scenario_excluded_dirs(&gpr)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(excluded.contains("avx"), "{excluded:?}");
        assert!(
            !excluded.contains("generic"),
            "shared dir kept: {excluded:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // #91 -------------------------------------------------------------------
    #[test]
    fn owning_library_is_selected_over_an_alphabetically_earlier_test_gpr() {
        let root = tmp("owner-vs-test");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("tests")).unwrap();
        let target = root.join("src/parser.adb");
        std::fs::write(&target, "package body Parser is end Parser;\n").unwrap();
        std::fs::write(
            root.join("tests/run_tests.adb"),
            "procedure Run_Tests is begin null; end;\n",
        )
        .unwrap();
        // `a_tests.gpr` sorts BEFORE `lib.gpr` and is a test executable; it does not
        // own src/. `lib.gpr` owns the candidate. The owner must win.
        std::fs::write(
            root.join("a_tests.gpr"),
            "project A_Tests is\n  for Source_Dirs use (\"tests\");\n  for Main use (\"run_tests.adb\");\nend A_Tests;\n",
        )
        .unwrap();
        std::fs::write(
            root.join("lib.gpr"),
            "library project Lib is\n  for Source_Dirs use (\"src\");\nend Lib;\n",
        )
        .unwrap();
        let selected = select_governing_gpr(&target, &root).expect("a governing gpr");
        assert_eq!(
            selected.file_name().unwrap().to_string_lossy(),
            "lib.gpr",
            "the owning library, not the alphabetically-earlier test project"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn component_is_selected_and_the_aggregate_is_never_chosen() {
        let root = tmp("aggregate-vs-component");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let target = root.join("src/engine.adb");
        std::fs::write(&target, "package body Engine is end Engine;\n").unwrap();
        // An aggregate umbrella (sorts first) plus the real component that owns src/.
        std::fs::write(
            root.join("all.gpr"),
            "aggregate project All is\n  for Project_Files use (\"component.gpr\");\nend All;\n",
        )
        .unwrap();
        std::fs::write(
            root.join("component.gpr"),
            "library project Component is\n  for Source_Dirs use (\"src\");\nend Component;\n",
        )
        .unwrap();
        let selected = select_governing_gpr(&target, &root).expect("a governing gpr");
        assert_eq!(
            selected.file_name().unwrap().to_string_lossy(),
            "component.gpr",
            "the component that owns the source, never the aggregate"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn falls_back_to_find_project_gpr_when_no_project_owns_the_source() {
        let root = tmp("no-owner-fallback");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let target = root.join("src/orphan.adb");
        std::fs::write(&target, "package body Orphan is end Orphan;\n").unwrap();
        // A project whose Source_Dirs do NOT include src/ — nothing owns the target.
        std::fs::write(
            root.join("other.gpr"),
            "project Other is\n  for Source_Dirs use (\"elsewhere\");\nend Other;\n",
        )
        .unwrap();
        // No owner -> deterministic fallback to the legacy first-gpr selection.
        assert_eq!(
            select_governing_gpr(&target, &root),
            find_project_gpr(&root),
            "with no owning project, fall back to the legacy selection"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // Offline-legacy audit #1/#7 -------------------------------------------
    #[test]
    fn library_aggregate_abstract_projects_are_not_extendable_bases() {
        let root = tmp("extendable-base");
        std::fs::create_dir_all(&root).unwrap();
        let cases = [
            (
                "lib.gpr",
                "library project Lib is\n  for Library_Name use \"x\";\nend Lib;\n",
                false,
            ),
            (
                "agg.gpr",
                "aggregate project Agg is\n  for Project_Files use ();\nend Agg;\n",
                false,
            ),
            ("abs.gpr", "abstract project Abs is\nend Abs;\n", false),
            (
                "app.gpr",
                "project App is\n  for Source_Dirs use (\"src\");\nend App;\n",
                true,
            ),
        ];
        for (name, text, extendable) in cases {
            let path = root.join(name);
            std::fs::write(&path, text).unwrap();
            assert_eq!(
                gpr_is_extendable_base(&path),
                extendable,
                "{name} extendable should be {extendable}"
            );
        }
        // An unreadable path is conservatively non-extendable.
        assert!(!gpr_is_extendable_base(&root.join("does-not-exist.gpr")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn find_project_gpr_prefers_a_concrete_project_over_an_aggregate() {
        let root = tmp("find-concrete");
        std::fs::create_dir_all(&root).unwrap();
        // `all.gpr` sorts before `zcomponent.gpr` but is an aggregate.
        std::fs::write(
            root.join("all.gpr"),
            "aggregate project All is\n  for Project_Files use (\"zcomponent.gpr\");\nend All;\n",
        )
        .unwrap();
        std::fs::write(
            root.join("zcomponent.gpr"),
            "project Zcomponent is\n  for Source_Dirs use (\"src\");\nend Zcomponent;\n",
        )
        .unwrap();
        assert_eq!(
            find_project_gpr(&root)
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy(),
            "zcomponent.gpr",
            "a concrete project must be chosen over the alphabetically-first aggregate"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
