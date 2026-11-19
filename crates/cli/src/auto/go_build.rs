// SPDX-License-Identifier: Apache-2.0

//! Native Go fuzzing lane (M3.3): generate a harness `main` package that imports
//! the target package via a module `replace`, `go build -cover -covermode=atomic`
//! it to `harnesses/<id>/main`, and let the builtin engine drive it over the
//! `BHF_FRAMED` fork-server protocol — the SAME execution path as the C/Rust
//! lanes, no third-party fuzzer.
//!
//! Coverage is REAL edge coverage (not black-box): per input the harness clears
//! Go's `-cover` atomic counters, runs the target, then folds the SET of executed
//! blocks (via `runtime/coverage.WriteCounters`, ignoring the count VALUE so a
//! loop's trip count is never false novelty) into bhf's shared `BHF_COV_SHM`
//! edge map — the same coverage-guided feedback the other lanes get. Parsing Go's
//! internal covcounters format is version-guarded: a mismatch folds nothing
//! (graceful black-box fallback), never a wrong signal.
//!
//! Go is compiled + statically typed, so the harness decodes by the parameter's
//! declared type. A Go panic (nil deref, index OOB, divide-by-zero, ...) is
//! `recover`ed and reported as a finding; an unrecoverable `fatal error` crashes
//! the process and the engine catches the death. A missing `go` toolchain, a
//! method (needs a receiver), or an unsupported parameter type skips cleanly
//! (the GNAT-less rule). A target outside every module is copied into a module
//! of its own ([`loose_package_module`]).

use crate::auto::candidate::Candidate;
use go_parser::{parse_go_data_types, parse_go_functions, parse_go_package, GoDataType, GoFunc};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

pub enum GoBuildResult {
    Built {
        /// Under `--force`: what the generator had to synthesize to make the call
        /// compile (an undrivable parameter's zero value, a zero-valued receiver).
        /// `None` for every normal build. The attempt loop records it as
        /// [`crate::auto::repair::Repair::ForcedSyntheticParams`] so the report
        /// floors the target's findings — a nil map or zero receiver can panic on
        /// its own account, and that must never read as a confirmed defect.
        forced: Option<String>,
    },
    Failed {
        reason: String,
        skip: bool,
    },
}

fn probe_go() -> Option<PathBuf> {
    which::which("go").ok()
}

pub fn build_go_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    _source_root: &Path,
    force: bool,
) -> GoBuildResult {
    let Some(go) = probe_go() else {
        return GoBuildResult::Failed {
            reason: "no `go` toolchain found; install Go to fuzz Go (the lane skips \
                     cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };

    // A native fuzz test is the project's own harness: build it, not one of ours.
    if crate::auto::provided::is_go_fuzz_test(candidate) {
        return build_go_fuzz_test(&go, candidate, work_dir, harness_id);
    }

    let (func, siblings, data_types) = match resolve_target(candidate) {
        Ok(pair) => pair,
        Err(reason) => return GoBuildResult::Failed { reason, skip: true },
    };
    // A method needs a receiver value. Prefer a REAL one from a sibling no-arg
    // constructor; failing that, and only under `--force`, synthesize the zero
    // value — it exists for every Go type, and taking its address satisfies a
    // pointer receiver without passing nil (which would panic on first field
    // access — our fault, not the target's).
    let state_feeder = target_rank::go_rank::find_stateful_byte_feeder(&func, &siblings);
    let receiver = match receiver_synthesis(&func, &siblings, force) {
        Ok(r) => r,
        Err(reason) => return GoBuildResult::Failed { reason, skip: true },
    };

    let target_abs = candidate
        .source_path
        .canonicalize()
        .unwrap_or_else(|_| candidate.source_path.clone());

    // Build the decode/call body; an unsupported required param type skips cleanly
    // (unforced) or is synthesized as its zero value (forced).
    let call = match generate_call_with_data_types(
        &func,
        receiver.as_ref(),
        state_feeder,
        &data_types,
        &siblings,
        force,
    ) {
        Ok(c) => c,
        Err(reason) => return GoBuildResult::Failed { reason, skip: true },
    };
    let body = call.body;
    let forced = call.forced_detail;

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&auto_dir) {
        return GoBuildResult::Failed {
            reason: format!("create {}: {e}", auto_dir.display()),
            skip: false,
        };
    }

    // The enclosing Go module (go.mod), so the harness can import the target
    // package by its module import path. A package outside every module (a
    // GOPATH-era tree, a loose directory of `.go` files) is copied into a module
    // of its own.
    let (mod_root, module_path, import_path) = match find_go_module(&target_abs) {
        Some((mod_root, module_path)) => {
            let import_path = compute_import_path(&module_path, &mod_root, &target_abs);
            (mod_root, module_path, import_path)
        }
        None => match loose_package_module(&target_abs, &auto_dir, &func.package) {
            Ok((mod_root, module_path)) => (mod_root, module_path.clone(), module_path),
            Err(reason) => {
                return GoBuildResult::Failed {
                    reason,
                    skip: false,
                }
            }
        },
    };

    let main_go = generate_main_go(&import_path, &body);
    let harness_files = std::iter::once(("bhf_harness.go", main_go.as_str())).chain(GO_OS_FILES);
    for (name, text) in harness_files {
        if let Err(e) = std::fs::write(auto_dir.join(name), text) {
            return GoBuildResult::Failed {
                reason: format!("write harness {name}: {e}"),
                skip: false,
            };
        }
    }
    if let Err(error) = append_json_seed_dictionary(&auto_dir, &call.json_seed_tokens) {
        return GoBuildResult::Failed {
            reason: format!("write structured Go seed dictionary: {error}"),
            skip: false,
        };
    }
    if let Err(error) = write_structured_seed_inputs(&auto_dir, &call.structured_seed_inputs) {
        return GoBuildResult::Failed {
            reason: format!("write structured Go starting inputs: {error}"),
            skip: false,
        };
    }
    let go_mod = format!(
        "module {harness_module}\n\ngo 1.21\n\nrequire {module_path} {version}\n\nreplace {module_path} => {root}\n",
        harness_module = harness_module_path(&module_path),
        module_path = module_path,
        version = placeholder_module_version(&module_path),
        // go.mod uses Go string-literal quoting, not shell quoting. A bare
        // local replacement path breaks when the source directory has spaces.
        // The copy of a package outside every module is named relative to the
        // go.mod: it moves with the harness dir (a capsule ships both), and
        // no spelling of the dir (a Windows 8.3 short name) has to match.
        root = serde_json::to_string(&match mod_root.strip_prefix(&auto_dir) {
            Ok(relative) => format!("./{}", relative.to_string_lossy().replace('\\', "/")),
            Err(_) => mod_root.to_string_lossy().into_owned(),
        })
        .expect("serializing a path string cannot fail"),
    );
    if let Err(e) = std::fs::write(auto_dir.join("go.mod"), &go_mod) {
        return GoBuildResult::Failed {
            reason: format!("write go.mod: {e}"),
            skip: false,
        };
    }

    // Resolve the dependency graph (offline-tolerant) then build the binary.
    // GOTOOLCHAIN=local: use the INSTALLED Go, never auto-download a newer toolchain
    // a target's `go 1.x` directive asks for (that needs network + is an env limit,
    // not a bhf failure). The version-compatible majority then still builds.
    // `main.exe` on Windows, so the harness runs from cmd and PowerShell too.
    let bin = auto_dir.join(crate::auto::layout::harness_exe_name("main"));
    // `go mod tidy` reaches the module graph and can sit indefinitely on a wedged
    // proxy or a huge closure, so it is bounded like every other spawn.
    let mut tidy = Command::new(&go);
    tidy.args(["mod", "tidy"])
        .current_dir(&auto_dir)
        .env("GOFLAGS", "-mod=mod")
        .env("GOTOOLCHAIN", "local");
    let _ =
        crate::command_output::output_with_timeout(&mut tidy, std::time::Duration::from_secs(300));
    // Real edge coverage (was black-box): build with `-cover -covermode=atomic` so
    // the harness can read per-input executed-block sets via `runtime/coverage` and
    // fold them into bhf's shared edge map — the same coverage-guided feedback
    // the C/Rust/Python/Perl lanes get. `atomic` is required by `WriteCounters`.
    let coverage_patterns = coverage_package_patterns(&module_path, &import_path);
    let run_build = |overlay: Option<&Path>, cover_pattern: Option<&str>| {
        let mut cmd = Command::new(&go);
        cmd.args(["build", "-o"]).arg(&bin);
        // Flags MUST precede the `.` package argument — `go build` stops parsing
        // flags at the first non-flag, so an `-overlay` placed after `.` is
        // silently treated as a package pattern and ignored.
        if let Some(pattern) = cover_pattern {
            cmd.args(["-cover", "-covermode=atomic"]);
            // `-cover` alone instruments only the packages being BUILT, which
            // here is just the generated harness `main` — the target library
            // arrives as a dependency through the module `replace` and would be
            // left uninstrumented, so the lane's "real edge coverage" would
            // measure the harness fuzzing itself. `-coverpkg` includes both
            // the target scope and generated main package; Go's coverage API
            // needs the latter to initialize its counter mode.
            cmd.arg(format!("-coverpkg={pattern}"));
        }
        if let Some(overlay) = overlay {
            cmd.arg(format!("-overlay={}", overlay.display()));
        }
        cmd.arg(".")
            .current_dir(&auto_dir)
            .env("GOFLAGS", "-mod=mod")
            .env("GOTOOLCHAIN", "local");
        crate::command_output::output_with_timeout(
            &mut cmd,
            std::time::Duration::from_secs(30 * 60),
        )
    };
    let build_failed = |build: &Result<std::process::Output, std::io::Error>| {
        build
            .as_ref()
            .map_or(true, |out| !out.status.success() || !bin.is_file())
    };
    // Module-wide coverage is deepest, but real modules often contain unrelated
    // platform-only commands/packages (`windows`, `iter`, generated tools). A
    // `{module}/...` instrumentation failure used to jump directly to a blind
    // build even though the selected package itself was perfectly coverable.
    // Retry the exact imported package first: that is the scope an expert harness
    // needs to prove and guide execution of the selected target body.
    let build_with_coverage_fallback = |overlay: Option<&Path>| {
        let mut patterns = coverage_patterns.iter();
        let mut build = run_build(
            overlay,
            Some(patterns.next().expect("module coverage pattern")),
        );
        for pattern in patterns {
            if !build_failed(&build) {
                break;
            }
            build = run_build(overlay, Some(pattern));
        }
        if build_failed(&build) {
            run_build(overlay, None)
        } else {
            build
        }
    };
    let mut build = build_with_coverage_fallback(None);
    // Many modern modules DECLARE a newer `go` directive than the installed
    // toolchain but never use its features. Under GOTOOLCHAIN=local that
    // directive HARD-fails the build ("module … requires go >= 1.2x"), which
    // previously blocked every such module wholesale. Retry once with a
    // `-overlay` that lowers the TARGET module's go.mod directive to the local
    // toolchain — non-mutating (the scanned tree is never edited). A module
    // whose code is actually version-compatible now builds; one that genuinely
    // uses newer features still fails on the real symbol and skips cleanly below.
    let version_gated = build.as_ref().is_ok_and(|out| {
        !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("requires go >=")
    });
    if version_gated {
        if let Some(overlay) = write_lowered_go_overlay(&auto_dir, &mod_root, &go) {
            build = build_with_coverage_fallback(Some(&overlay));
        }
    }
    match build {
        Ok(out) if out.status.success() && bin.is_file() => GoBuildResult::Built { forced },
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // A target needing external modules we can't fetch offline, or a newer Go
            // toolchain than installed, is an ENVIRONMENT limit, not a bhf failure
            // — skip cleanly.
            let skip = stderr.contains("cannot find module")
                || stderr.contains("missing go.sum")
                || stderr.contains("dial tcp")
                || stderr.contains("no required module")
                || stderr.contains("toolchain not available")
                || stderr.contains("download go1")
                || stderr.contains("requires go >=");
            GoBuildResult::Failed {
                reason: format!("go build failed: {}", stderr.lines().last().unwrap_or("")),
                skip,
            }
        }
        Err(e) => GoBuildResult::Failed {
            reason: format!("could not run go build: {e}"),
            skip: false,
        },
    }
}

/// The target plus every function parsed from its file — the siblings a receiver
/// constructor is looked for among.
fn resolve_target(candidate: &Candidate) -> Result<(GoFunc, Vec<GoFunc>, Vec<GoDataType>), String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let target_functions =
        parse_go_functions(&source).map_err(|_| "failed to parse Go target source".to_owned())?;
    let target = target_functions
        .iter()
        .find(|func| func.name == candidate.name && func.line == candidate.line)
        .cloned()
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))?;
    let mut functions = Vec::new();
    let mut data_types = Vec::new();
    let package_dir = candidate
        .source_path
        .parent()
        .ok_or_else(|| "Go target source has no package directory".to_owned())?;
    let entries = std::fs::read_dir(package_dir)
        .map_err(|error| format!("read Go package '{}': {error}", package_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read Go package entry: {error}"))?;
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "go")
            || path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with("_test.go"))
        {
            continue;
        }
        let package_source = if path == candidate.source_path {
            source.clone()
        } else {
            crate::source_text::read_source_text(&path)
                .map_err(|error| format!("read Go package '{}': {error}", path.display()))?
        };
        let package = parse_go_package(&package_source)
            .map_err(|_| format!("parse Go package clause '{}': invalid", path.display()))?;
        if package != target.package {
            continue;
        }
        let file_functions = parse_go_functions(&package_source)
            .map_err(|_| format!("parse Go package '{}': functions", path.display()))?;
        functions.extend(file_functions);
        data_types.extend(
            parse_go_data_types(&package_source)
                .map_err(|_| format!("parse Go package '{}': types", path.display()))?,
        );
    }
    if functions.is_empty() {
        functions = target_functions;
    }
    Ok((target, functions, data_types))
}

/// Local Go toolchain language version as `MAJOR.MINOR` ("1.22"), from
/// `go env GOVERSION` ("go1.22.2"). None if it can't be parsed.
fn local_go_minor(go: &Path) -> Option<String> {
    let mut version_probe = Command::new(go);
    version_probe
        .args(["env", "GOVERSION"])
        .env("GOTOOLCHAIN", "local");
    let out = crate::command_output::output_with_timeout(
        &mut version_probe,
        std::time::Duration::from_secs(30),
    )
    .ok()?;
    parse_go_minor(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `go1.22.2` / `go1.24` into `1.22` / `1.24`. None if not a `goX.Y…`
/// string (a `devel …` toolchain, empty output, ...).
fn parse_go_minor(goversion: &str) -> Option<String> {
    let version = goversion.trim().strip_prefix("go")?;
    let mut parts = version.split('.');
    let major = parts.next()?;
    let minor: String = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if !major.is_empty() && major.chars().all(|c| c.is_ascii_digit()) && !minor.is_empty() {
        Some(format!("{major}.{minor}"))
    } else {
        None
    }
}

/// Write a `go build -overlay` JSON that maps the target module's go.mod to a
/// copy whose `go` directive is lowered to the local toolchain (and any pinned
/// `toolchain` line dropped), so a build gated only by a declared-too-new
/// directive can proceed WITHOUT mutating the scanned tree. Returns the overlay
/// file path, or None if the local version is unknown or any file op fails.
fn write_lowered_go_overlay(auto_dir: &Path, mod_root: &Path, go: &Path) -> Option<PathBuf> {
    let local = local_go_minor(go)?;
    let gomod = mod_root.join("go.mod");
    let src = std::fs::read_to_string(&gomod).ok()?;
    let lowered = lower_go_mod_directive(&src, &local);
    let lowered_path = auto_dir.join("bhf_lowered_go.mod");
    std::fs::write(&lowered_path, lowered).ok()?;
    let mut replace = serde_json::Map::new();
    replace.insert(
        gomod.to_string_lossy().into_owned(),
        serde_json::Value::String(lowered_path.to_string_lossy().into_owned()),
    );
    let overlay = serde_json::json!({ "Replace": serde_json::Value::Object(replace) });
    let overlay_path = auto_dir.join("bhf_overlay.json");
    std::fs::write(&overlay_path, serde_json::to_vec(&overlay).ok()?).ok()?;
    Some(overlay_path)
}

/// Lower a go.mod's language requirement so it won't gate the local toolchain:
/// rewrite the `go MAJOR.MINOR…` directive to `go <local>` and drop any pinned
/// `toolchain …` line. Every other line is preserved verbatim.
fn lower_go_mod_directive(src: &str, local_minor: &str) -> String {
    let mut out = String::with_capacity(src.len() + 8);
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("toolchain ") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("go ") {
            if rest.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
                out.push_str("go ");
                out.push_str(local_minor);
                out.push('\n');
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Walk up from the target file to the nearest `go.mod`; return (module root dir,
/// module path).
fn find_go_module(target_abs: &Path) -> Option<(PathBuf, String)> {
    let mut dir = target_abs.parent()?;
    loop {
        let gomod = dir.join("go.mod");
        if gomod.is_file() {
            let text = std::fs::read_to_string(&gomod).ok()?;
            let module = text.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("module ")
                    .map(|m| m.trim().to_owned())
            })?;
            return Some((dir.to_path_buf(), module));
        }
        dir = dir.parent()?;
    }
}

/// Where in the harness dir a package outside every Go module is copied.
pub(crate) const LOOSE_PACKAGE_DIR: &str = "bhf_target";

/// What a copied `package main` is renamed to, so the harness can import it.
const LOOSE_MAIN_PACKAGE: &str = "bhftarget";

/// The module a target outside every Go module is built from: a copy of its
/// package dir in the harness dir, with a synthesized `go.mod`. The `replace`
/// that points the harness at a target module needs a dir holding a `go.mod`,
/// and the scanned tree is never edited. Returns (module root, module path).
///
/// A copy rather than a `-overlay`: `-cover` instruments the files on disk and
/// ignores an overlay's replacement `.go` files, and a `package main` has to be
/// renamed to be imported at all. Each copied `.go` file opens with a `//line`
/// directive naming the original, so a panic's frames and the coverage map
/// name the project's file and line, not the copy's.
fn loose_package_module(
    target_abs: &Path,
    auto_dir: &Path,
    package: &str,
) -> Result<(PathBuf, String), String> {
    // Plain (no Windows `\\?\` prefix), as the `//line` directives name it.
    let package_dir = crate::workdir::plain_canonical(
        target_abs
            .parent()
            .ok_or_else(|| "Go target source has no package directory".to_owned())?,
    );
    let package_dir = package_dir.as_path();
    let copy = auto_dir.join(LOOSE_PACKAGE_DIR);
    let _ = std::fs::remove_dir_all(&copy);
    std::fs::create_dir_all(&copy)
        .map_err(|error| format!("create {}: {error}", copy.display()))?;
    let entries = std::fs::read_dir(package_dir)
        .map_err(|error| format!("read Go package '{}': {error}", package_dir.display()))?;
    let mut files: Vec<(PathBuf, Option<String>)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !path.is_file() || name.ends_with("_test.go") {
            continue;
        }
        let text = name
            .ends_with(".go")
            .then(|| std::fs::read_to_string(&path).ok())
            .flatten();
        files.push((path, text));
    }
    // A dir of `go run file.go` scripts: each file is a program with its own
    // `main`, and together they are no package at all. Only the target's
    // file is the target's program.
    let mains = files
        .iter()
        .filter(|(_, text)| text.as_deref().is_some_and(declares_main))
        .count();
    let target_file = target_abs.file_name();
    for (path, text) in &files {
        let dest = copy.join(path.file_name().unwrap_or_default());
        let copied = match text {
            Some(_) if package == "main" && mains > 1 && path.file_name() != target_file => {
                continue;
            }
            Some(text) => std::fs::write(&dest, loose_go_source(path, text, package == "main")),
            None => std::fs::copy(path, &dest).map(|_| ()),
        };
        copied
            .map_err(|error| format!("copy {} to {}: {error}", path.display(), dest.display()))?;
    }
    let module_path = format!("bhf.local/{}", module_path_element(package_dir));
    std::fs::write(
        copy.join("go.mod"),
        format!("module {module_path}\n\ngo 1.21\n"),
    )
    .map_err(|error| format!("write the target's go.mod: {error}"))?;
    Ok((copy, module_path))
}

/// A copied Go source: a `//line` directive naming `original`, then the
/// source, with `package main` and its `func main` renamed when `rename_main`
/// so the package can be imported. Every line keeps its number.
fn loose_go_source(original: &Path, text: &str, rename_main: bool) -> String {
    let mut out = format!("//line {}:1\n", original.display());
    let mut in_block_comment = false;
    let mut renamed_package = !rename_main;
    for line in text.split_inclusive('\n') {
        let rewritten = if in_block_comment || !rename_main {
            None
        } else if !renamed_package {
            renamed_package_clause(line).inspect(|_| renamed_package = true)
        } else {
            line.strip_prefix("func main(")
                .map(|rest| format!("func bhfProgramMain({rest}"))
        };
        if let Some((_, after)) = line.rsplit_once("/*") {
            in_block_comment = !after.contains("*/");
        } else if in_block_comment && line.contains("*/") {
            in_block_comment = false;
        }
        out.push_str(rewritten.as_deref().unwrap_or(line));
    }
    out
}

/// Whether a Go source declares a top-level `func main`.
fn declares_main(text: &str) -> bool {
    text.lines().any(|line| line.starts_with("func main("))
}

/// `line` with a `package main` clause renamed to [`LOOSE_MAIN_PACKAGE`],
/// or `None` when it is not the package clause.
fn renamed_package_clause(line: &str) -> Option<String> {
    let rest = line.strip_prefix("package")?;
    let name = rest.trim_start_matches([' ', '\t']);
    let after = name.strip_prefix("main")?;
    if after.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let indent = &rest[..rest.len() - name.len()];
    Some(format!("package{indent}{LOOSE_MAIN_PACKAGE}{after}"))
}

/// A module path element from a package dir's name: its ASCII letters,
/// digits, `-`, `_` and `~`, every other character a `-`.
fn module_path_element(package_dir: &Path) -> String {
    let name = package_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let element: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '~') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let element = element.trim_matches('-');
    if element.is_empty() {
        "pkg".to_owned()
    } else {
        element.to_owned()
    }
}

/// The module path the harness declares for ITSELF.
///
/// Go forbids importing `<M>/…/internal/x` from outside the tree rooted at that
/// `internal`'s parent, and it decides "outside" from the IMPORT PATH. A harness
/// module called `bhfharness` is therefore outside every project, so any
/// target whose package lives under an `internal/` was unreachable —
/// `use of internal package … not allowed`, 8 targets in three of the sweep's Go
/// repos, and `internal/` is where a great deal of real Go code lives.
///
/// Declaring the harness a child of the module under test satisfies the rule by
/// the same mechanism the project's own packages do. It changes nothing else:
/// the module is still built in its own directory with its own `replace` at the
/// real tree, and the name never resolves as a real import path.
fn harness_module_path(module_path: &str) -> String {
    let base = module_path.trim_end_matches('/');
    if base.is_empty() {
        return "bhfharness".to_owned();
    }
    format!("{base}/bhfharness")
}

/// Coverage scopes in preference order. The generated main package must be in
/// `-coverpkg` too: without it Go may link target coverage metadata but leave
/// runtime/coverage's counter mode invalid, so WriteCounters reports no edges.
/// The module-wide target pattern captures sibling calls; the exact package is
/// the fallback when unrelated packages make `{module}/...` unbuildable.
fn coverage_package_patterns(module_path: &str, import_path: &str) -> Vec<String> {
    let module = format!("{}/...", module_path.trim_end_matches('/'));
    let harness = harness_module_path(module_path);
    let mut patterns = vec![format!("{module},{harness}")];
    if module != import_path {
        patterns.push(format!("{import_path},{harness}"));
    }
    patterns
}

/// The placeholder version the harness `require`s the module under test at.
///
/// The `replace` beside it points at the real tree, so this version is never
/// resolved — but it must still SATISFY Go's rules, and semantic import
/// versioning makes one of them path-dependent: a module path ending `/vN`
/// (N >= 2) may only be required at a version starting `vN`. A hardcoded
/// `v0.0.0-incompatible` on such a path is not a bad guess, it is a `go.mod`
/// that does not parse — `go: errors parsing go.mod` before any build — and it
/// took EVERY target in the project with it. In the 500-project sweep that was
/// 51 targets across 9 of 40 Go projects: caddy, cli/cli, alist, etcd, moby,
/// traefik, bubbletea, 3x-ui and CLIProxyAPI.
///
/// `/v1` and an unsuffixed path keep the v0 pre-release spelling, which is what
/// Go wants for a module that has not adopted the suffix.
fn placeholder_module_version(module_path: &str) -> String {
    match module_path.rsplit_once("/v") {
        Some((_, major)) if major.parse::<u32>().is_ok_and(|n| n >= 2) => format!("v{major}.0.0"),
        _ => "v0.0.0-incompatible".to_owned(),
    }
}

/// Import path of the target package = module path + the target dir relative to the
/// module root.
fn compute_import_path(module_path: &str, mod_root: &Path, target_abs: &Path) -> String {
    let Some(parent) = target_abs.parent() else {
        return module_path.to_owned();
    };
    match parent.strip_prefix(mod_root) {
        Ok(rel) if rel.as_os_str().is_empty() => module_path.to_owned(),
        Ok(rel) => format!(
            "{}/{}",
            module_path,
            rel.to_string_lossy().replace('\\', "/")
        ),
        Err(_) => module_path.to_owned(),
    }
}

/// A generated call body plus, under `--force`, what had to be synthesized for it.
struct GoCall {
    body: String,
    /// `Some(detail)` when at least one parameter or the receiver is a forced zero
    /// value rather than a decode of the fuzz bytes.
    forced_detail: Option<String>,
    /// Complete JSON values usable by the builtin mutation dictionary to seed
    /// structurally valid input for data-only parameter types.
    json_seed_tokens: Vec<String>,
    /// Complete starting inputs, including the length-prefixed byte argument
    /// when a data-only JSON argument follows it.
    structured_seed_inputs: Vec<String>,
}

/// How the harness obtains the receiver for a method target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoReceiver {
    /// The line that binds `recv`.
    setup: String,
    /// How the call names it: `recv` when it is already a pointer, `(&recv)`
    /// otherwise — the addressable form is valid for BOTH a value and a pointer
    /// receiver.
    callee: String,
    /// `Some(detail)` only when the value was FABRICATED rather than constructed,
    /// so the report can floor a finding on it. A real constructor is not forced.
    forced: Option<String>,
}

/// The receiver for a method target, or `None` for a plain function.
///
/// Preferred: a sibling no-arg constructor (`func NewT() *T`), which is what a
/// human would write and is a REAL value, so a finding on it stands on its own.
/// That was previously impossible to spot — `go_parser::GoFunc` carried no result
/// type, so a constructor could not be told from any other no-arg function — and
/// every method target demanded `--force` instead. It was among the largest Go
/// blockers in the 500-project sweep.
///
/// Failing that, and only under force: the receiver's zero value, taken by
/// address. `(&r).M()` is valid for both a value and a pointer receiver when `r`
/// is addressable, and unlike a nil `*T` it does not panic the moment the method
/// touches a field.
///
/// Refused either way when the receiver type is not nameable from the harness
/// package: unexported (`*decoder` — inaccessible by Go's visibility rules, so the
/// method is uncallable from anywhere outside its package) or generic (`Tree[T]`
/// needs a type argument bhf cannot choose).
fn receiver_synthesis(
    func: &GoFunc,
    siblings: &[GoFunc],
    force: bool,
) -> Result<Option<GoReceiver>, String> {
    if !func.is_method {
        return Ok(None);
    }
    let raw = func.receiver_type.as_deref().unwrap_or("").trim();
    let bare = raw.trim_start_matches('*').trim();
    let nameable = !bare.is_empty()
        && !bare.contains('[')
        && !bare.contains('.')
        && bare.starts_with(|c: char| c.is_ascii_uppercase());
    if !nameable {
        return Err(format!(
            "Go receiver type `{raw}` of method `{}` is not nameable from the \
             harness package (unexported or generic); skipped cleanly",
            func.name
        ));
    }

    if let Some(ctor) = find_go_constructor(bare, siblings) {
        // A `*T` constructor already yields a pointer; a `T` one needs its
        // address so a pointer-receiver method is still callable.
        let returns_pointer = ctor
            .returns
            .as_deref()
            .is_some_and(|r| r.trim().starts_with('*'));
        return Ok(Some(GoReceiver {
            setup: format!("\trecv := tgt.{}()\n", ctor.name),
            callee: if returns_pointer {
                "recv".to_owned()
            } else {
                "(&recv)".to_owned()
            },
            forced: None,
        }));
    }

    // A public feeder followed by a zero-argument terminal is a real stateful
    // construction path. The addressable zero value is initialized through the
    // type's own API before the target call, so unlike an arbitrary `--force`
    // receiver it is not labeled synthetic. Cobra's `Command.SetArgs -> Execute`
    // is the canonical example and matches an expert harness's sequence.
    if target_rank::go_rank::find_stateful_byte_feeder(func, siblings).is_some() {
        return Ok(Some(GoReceiver {
            setup: format!("\tvar recv tgt.{bare}\n"),
            callee: "(&recv)".to_owned(),
            forced: None,
        }));
    }

    if !force {
        return Err(format!(
            "Go method `{}` needs a receiver value and its type `{bare}` has no no-arg \
             constructor; pass --force to call it on a zero-valued receiver (skipped cleanly)",
            func.name
        ));
    }
    Ok(Some(GoReceiver {
        setup: format!("\tvar recv tgt.{bare}\n"),
        callee: "(&recv)".to_owned(),
        forced: Some(format!("receiver tgt.{bare}")),
    }))
}

/// A sibling no-arg constructor for `bare` — `func NewT() T` or `func NewT() *T`.
///
/// Restricted to the `New…` naming convention on purpose. Any exported no-arg
/// function returning the type would compile, but only the convention says it is
/// meant to CONSTRUCT one; `Open…`/`Connect…` shapes touch the world, and calling
/// those per harness build is not something to do on a guess.
fn find_go_constructor<'a>(bare: &str, siblings: &'a [GoFunc]) -> Option<&'a GoFunc> {
    siblings
        .iter()
        .filter(|f| {
            !f.is_method && f.is_exported && f.params.is_empty() && f.name.starts_with("New")
        })
        .find(|f| {
            f.returns
                .as_deref()
                .map(|r| r.trim().trim_start_matches('*').trim())
                .is_some_and(|returned| returned == bare)
        })
}

/// Build the decode lines + the call statement for the target's params. Returns an
/// error (clean skip) if a required parameter type can't be synthesized.
#[cfg(test)]
fn generate_call(
    func: &GoFunc,
    receiver: Option<&GoReceiver>,
    state_feeder: Option<&GoFunc>,
    force: bool,
) -> Result<GoCall, String> {
    generate_call_with_data_types(func, receiver, state_feeder, &[], &[], force)
}

fn generate_call_with_data_types(
    func: &GoFunc,
    receiver: Option<&GoReceiver>,
    state_feeder: Option<&GoFunc>,
    data_types: &[GoDataType],
    methods: &[GoFunc],
    force: bool,
) -> Result<GoCall, String> {
    let n = func.params.len();
    let mut lines = String::new();
    let mut args = Vec::new();
    let mut forced: Vec<String> = Vec::new();
    let mut json_seed_tokens = Vec::new();
    let mut structured_seed_inputs = Vec::new();
    if let Some(receiver) = receiver {
        lines.push_str(&receiver.setup);
        if let Some(detail) = &receiver.forced {
            forced.push(detail.clone());
        }
    }
    if let Some(feeder) = state_feeder {
        let receiver = receiver.ok_or_else(|| {
            format!(
                "Go state feeder `{}` requires a receiver for `{}`",
                feeder.name, func.name
            )
        })?;
        let input = decode_for_param(feeder, 0, true).ok_or_else(|| {
            format!(
                "unsupported Go state-feeder parameter type `{}` (skipped)",
                feeder.params[0].ty
            )
        })?;
        lines.push_str(&format!("\tstateInput := {input}\n"));
        lines.push_str(&format!(
            "\t{}.{}(stateInput)\n",
            receiver.callee, feeder.name
        ));
    }
    for (i, p) in func.params.iter().enumerate() {
        let last = i + 1 == n;
        let expr = match decode_for_param(func, i, last) {
            Some(expr) => expr,
            None if !force
                && harness_visible_go_type(&p.ty).is_some()
                && is_plain_json_parameter(&p.ty, data_types, methods, &mut Vec::new()) =>
            {
                let visible_type = harness_visible_go_type(&p.ty).expect("checked above");
                let json_example = go_json_example(&p.ty, data_types, &mut Vec::new())
                    .ok_or_else(|| format!("cannot construct JSON seed for Go type `{}`", p.ty))?;
                lines.push_str(&format!("\tvar a{i} {visible_type}\n"));
                let paired_bytes = n == 2 && i == 1 && func.params[0].ty.trim() == "[]byte";
                let json_source = if paired_bytes { "c.rest()" } else { "data" };
                lines.push_str(&format!(
                    "\tif err := json.Unmarshal({json_source}, &a{i}); err != nil {{ return }}\n"
                ));
                args.push(format!("a{i}"));
                let example = json_example.to_string();
                if paired_bytes {
                    // The first byte sizes c.bytesField(), then the remaining
                    // bytes form an independent JSON document. A seed that
                    // repeats a short JSON example in both slots lets parser
                    // targets exercise their raw bytes and option fields.
                    if example.len() <= 127 {
                        structured_seed_inputs.push(format!(
                            "{}{}{}",
                            char::from(example.len() as u8),
                            example,
                            example
                        ));
                    }
                    structured_seed_inputs.push(format!("\x01A{example}"));
                } else {
                    structured_seed_inputs.push(example.clone());
                }
                json_seed_tokens.push(example);
                continue;
            }
            None if force => {
                // No decoder for this type. The Go zero value exists for EVERY type,
                // so declaring one always compiles as long as the type is nameable
                // from the harness package — which is the only thing that can fail.
                let ty = harness_visible_go_type(&p.ty).ok_or_else(|| {
                    format!(
                        "forced: Go parameter type `{}` is not nameable from the harness \
                         package (unexported, generic, variadic or an inline literal); \
                         skipped cleanly",
                        p.ty
                    )
                })?;
                lines.push_str(&format!("\tvar z{i} {ty}\n"));
                forced.push(format!("{} {}", p.name, p.ty));
                format!("z{i}")
            }
            None => {
                return Err(format!(
                    "unsupported Go parameter type `{}` (skipped)",
                    p.ty
                ))
            }
        };
        lines.push_str(&format!("\ta{i} := {expr}\n"));
        args.push(format!("a{i}"));
    }
    let callee = match receiver {
        Some(receiver) => format!("{}.{}", receiver.callee, func.name),
        None => format!("tgt.{}", func.name),
    };
    lines.push_str("\tbhfMarkTargetEntry()\n");
    lines.push_str(&format!("\t{callee}({})\n", args.join(", ")));
    Ok(GoCall {
        body: lines,
        forced_detail: (!forced.is_empty())
            .then(|| format!("go: synthesized zero value for {}", forced.join(", "))),
        json_seed_tokens,
        structured_seed_inputs,
    })
}

fn append_json_seed_dictionary(output_dir: &Path, tokens: &[String]) -> std::io::Result<()> {
    if tokens.is_empty() {
        return Ok(());
    }
    let path = output_dir.join("dictionary.txt");
    let mut contents = std::fs::read_to_string(&path).unwrap_or_default();
    for token in tokens {
        let escaped = escape_afl_dictionary_token(token.as_bytes());
        let entry = format!("\"{escaped}\"\n");
        if !contents.lines().any(|line| line.trim() == entry.trim()) {
            if !contents.is_empty() && !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(&entry);
        }
    }
    std::fs::write(path, contents)
}

const STRUCTURED_SEEDS_FILE: &str = "structured-seeds.json";
const MAX_STRUCTURED_SEEDS_BYTES: u64 = 64 * 1024;
const MAX_STRUCTURED_SEEDS: usize = 16;

fn write_structured_seed_inputs(output_dir: &Path, tokens: &[String]) -> std::io::Result<()> {
    let path = output_dir.join(STRUCTURED_SEEDS_FILE);
    if tokens.is_empty() {
        if let Err(error) = std::fs::remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error);
            }
        }
        return Ok(());
    }
    let bytes = serde_json::to_vec(tokens).map_err(std::io::Error::other)?;
    if tokens.len() > MAX_STRUCTURED_SEEDS || bytes.len() as u64 > MAX_STRUCTURED_SEEDS_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "generated structured seeds exceed the input budget",
        ));
    }
    std::fs::write(path, bytes)
}

/// Start from complete JSON documents. Dictionary tokens alone are only used
/// during mutation, so they cannot establish reachability for a Go data type.
pub(crate) fn load_structured_seed_inputs(output_dir: &Path) -> Result<Vec<Vec<u8>>, String> {
    let path = output_dir.join(STRUCTURED_SEEDS_FILE);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("read '{}': {error}", path.display())),
    };
    if !metadata.is_file() || metadata.len() > MAX_STRUCTURED_SEEDS_BYTES {
        return Err(format!(
            "structured seed file '{}' exceeds its budget",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|error| format!("read '{}': {error}", path.display()))?
        .take(MAX_STRUCTURED_SEEDS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read '{}': {error}", path.display()))?;
    if bytes.len() as u64 > MAX_STRUCTURED_SEEDS_BYTES {
        return Err(format!(
            "structured seed file '{}' exceeds its budget",
            path.display()
        ));
    }
    let tokens: Vec<String> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse '{}': {error}", path.display()))?;
    if tokens.len() > MAX_STRUCTURED_SEEDS {
        return Err(format!(
            "structured seed file '{}' has too many inputs",
            path.display()
        ));
    }
    Ok(tokens.into_iter().map(String::into_bytes).collect())
}

fn escape_afl_dictionary_token(token: &[u8]) -> String {
    crate::generate_harness::escape_afl_dictionary_token(token)
}

fn is_plain_json_parameter(
    ty: &str,
    types: &[GoDataType],
    methods: &[GoFunc],
    visiting: &mut Vec<String>,
) -> bool {
    let ty = ty.trim();
    if matches!(
        ty,
        "bool"
            | "string"
            | "byte"
            | "uint8"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "rune"
            | "uint"
            | "uint16"
            | "uint32"
            | "uint64"
            | "float32"
            | "float64"
    ) {
        return true;
    }
    if let Some(inner) = ty.strip_prefix('*') {
        return is_plain_json_parameter(inner, types, methods, visiting);
    }
    if let Some(inner) = ty.strip_prefix("[]") {
        return is_plain_json_parameter(inner, types, methods, visiting);
    }
    if ty.starts_with('[') {
        let Some(close) = ty.find(']') else {
            return false;
        };
        let size = &ty[1..close];
        if size.is_empty()
            || !size.chars().all(|c| c.is_ascii_digit())
            || size.parse::<usize>().ok().is_none_or(|count| count > 1024)
        {
            return false;
        }
        return is_plain_json_parameter(ty[close + 1..].trim(), types, methods, visiting);
    }
    if let Some(rest) = ty.strip_prefix("map[") {
        let Some(close) = rest.find(']') else {
            return false;
        };
        let key = rest[..close].trim();
        return key == "string"
            && is_plain_json_parameter(rest[close + 1..].trim(), types, methods, visiting);
    }
    if ty.contains('.') || ty.contains('[') || ty.contains(']') {
        return false;
    }
    let matches: Vec<_> = types
        .iter()
        .filter(|candidate| candidate.name == ty)
        .collect();
    if matches.len() != 1 {
        return false;
    }
    let definition = matches[0];
    if visiting.iter().any(|seen| seen == ty) {
        return true;
    }
    // A method-bearing type can carry custom decoding or lifecycle invariants
    // that syntax alone cannot establish as safe. Keep this first slice to
    // passive data records, including nested records.
    if methods.iter().any(|method| {
        method.is_method
            && method
                .receiver_type
                .as_deref()
                .unwrap_or_default()
                .trim_start_matches('*')
                == ty
    }) {
        return false;
    }
    let Some(fields) = definition.fields.as_ref() else {
        return false;
    };
    if fields.is_empty() || fields.iter().any(|field| !field.is_exported) {
        return false;
    }
    visiting.push(ty.to_owned());
    let safe = fields
        .iter()
        .all(|field| is_plain_json_parameter(&field.ty, types, methods, visiting));
    visiting.pop();
    safe
}

fn go_json_example(
    ty: &str,
    types: &[GoDataType],
    visiting: &mut Vec<String>,
) -> Option<serde_json::Value> {
    let ty = ty.trim();
    Some(match ty {
        "bool" => serde_json::Value::Bool(true),
        "string" => serde_json::Value::String("A".to_owned()),
        "byte" | "uint8" => serde_json::Value::from(65),
        "int" | "int8" | "int16" | "int32" | "int64" | "rune" | "uint" | "uint16" | "uint32"
        | "uint64" => serde_json::Value::from(1),
        "float32" | "float64" => serde_json::json!(1.0),
        _ if ty.starts_with("*") => go_json_example(&ty[1..], types, visiting)?,
        _ if ty.starts_with("[]") => {
            let inner = &ty[2..];
            if matches!(inner, "byte" | "uint8") {
                serde_json::Value::String("QQ==".to_owned())
            } else {
                serde_json::Value::Array(vec![go_json_example(inner, types, visiting)?])
            }
        }
        _ if ty.starts_with('[') => {
            let close = ty.find(']')?;
            let inner = ty[close + 1..].trim();
            serde_json::Value::Array(vec![go_json_example(inner, types, visiting)?])
        }
        _ if ty.starts_with("map[") => {
            let close = ty.find(']')?;
            let inner = ty[close + 1..].trim();
            let mut object = serde_json::Map::new();
            object.insert("k".to_owned(), go_json_example(inner, types, visiting)?);
            serde_json::Value::Object(object)
        }
        _ => {
            let matching: Vec<_> = types
                .iter()
                .filter(|candidate| candidate.name == ty)
                .collect();
            if matching.len() != 1 || visiting.iter().any(|seen| seen == ty) {
                return Some(serde_json::Value::Null);
            }
            let fields = matching[0].fields.as_ref()?;
            visiting.push(ty.to_owned());
            let mut object = serde_json::Map::new();
            for field in fields {
                object.insert(
                    field.json_name.clone(),
                    go_json_example(&field.ty, types, visiting)?,
                );
            }
            visiting.pop();
            serde_json::Value::Object(object)
        }
    })
}

/// Go's predeclared type names — usable in the harness package unqualified.
const GO_PREDECLARED_TYPES: &[&str] = &[
    "any",
    "bool",
    "byte",
    "complex64",
    "complex128",
    "error",
    "float32",
    "float64",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "rune",
    "string",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uintptr",
];

/// Type-syntax keywords that carry no package scope.
const GO_TYPE_KEYWORDS: &[&str] = &["chan", "map", "struct", "interface", "func"];

/// The packages the generated harness already imports, so a qualified type naming
/// one of them resolves without touching the import block.
const GO_HARNESS_IMPORTS: &[&str] = &["bytes", "fmt", "io", "math", "os", "syscall"];

/// Rewrite a Go type spelling from the TARGET package into one valid in the
/// harness package, where the target is imported as `tgt`. `None` when the
/// spelling names something the harness cannot reach.
///
/// A bare exported name is the target's own type, so it gains the `tgt.` qualifier
/// (`[]Record` -> `[]tgt.Record`); a predeclared name and a qualifier naming a
/// package the harness already imports are kept. Everything else is refused rather
/// than guessed: an unexported name is inaccessible by Go's visibility rules, a
/// foreign qualifier would need an import path only the type-checker knows, a
/// generic instantiation needs a type argument, and an inline `struct{...}` /
/// `func(...)` literal contains FIELD and PARAMETER names this identifier walk
/// would happily mistake for types.
fn harness_visible_go_type(ty: &str) -> Option<String> {
    let t = ty.trim();
    if t.is_empty()
        || t.starts_with("...")
        || t.contains("struct{")
        || t.contains("struct {")
        || t.contains("func(")
        || t.contains("func (")
    {
        return None;
    }
    // `interface{}` is the only interface literal with no method names in it.
    let scan = t.replace("interface{}", "any");
    if scan.contains("interface{") {
        return None;
    }
    let bytes = scan.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if !(ch.is_ascii_alphabetic() || ch == '_') {
            out.push(ch);
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                i += 1;
            } else {
                break;
            }
        }
        let word = &scan[start..i];
        if GO_PREDECLARED_TYPES.contains(&word) || GO_TYPE_KEYWORDS.contains(&word) {
            // `map[K]V` / `chan T` keep their brackets; only a NAMED type followed by
            // `[` is a generic instantiation.
            out.push_str(word);
            continue;
        }
        // A generic instantiation (`Tree[T]`) needs a type argument we cannot choose.
        if scan[i..].starts_with('[') {
            return None;
        }
        if let Some((pkg, name)) = word.split_once('.') {
            if !GO_HARNESS_IMPORTS.contains(&pkg)
                || !name.starts_with(|c: char| c.is_ascii_uppercase())
            {
                return None;
            }
            out.push_str(word);
            continue;
        }
        if !word.starts_with(|c: char| c.is_ascii_uppercase()) {
            return None;
        }
        out.push_str("tgt.");
        out.push_str(word);
    }
    Some(out)
}

/// Map a Go parameter type to a decode expression over the cursor `c`. `None` for
/// an unsupported type (struct/map/pointer/interface/slice-of-other).
fn decode_for_type(ty: &str, last: bool) -> Option<String> {
    let t = ty.trim();
    Some(match t {
        "[]byte" => {
            if last {
                "c.rest()".to_owned()
            } else {
                "c.bytesField()".to_owned()
            }
        }
        "string" => {
            if last {
                "string(c.rest())".to_owned()
            } else {
                "string(c.bytesField())".to_owned()
            }
        }
        "[]rune" => "[]rune(string(c.rest()))".to_owned(),
        // Command/state-machine argument vectors use NUL as an unambiguous
        // separator, matching the expert Cobra harness and preserving arbitrary
        // spaces inside individual arguments.
        "[]string" => "c.args()".to_owned(),
        "io.Reader" | "io.ReadCloser" => "bytes.NewReader(c.rest())".to_owned(),
        "bool" => "(c.u8()&1 == 1)".to_owned(),
        "byte" | "uint8" => "c.u8()".to_owned(),
        "rune" | "int32" => "int32(c.i64())".to_owned(),
        "int" => "int(c.i64())".to_owned(),
        "int8" => "int8(c.i64())".to_owned(),
        "int16" => "int16(c.i64())".to_owned(),
        "int64" => "c.i64()".to_owned(),
        "uint" => "uint(c.i64())".to_owned(),
        "uint16" => "uint16(c.i64())".to_owned(),
        "uint32" => "uint32(c.i64())".to_owned(),
        "uint64" => "uint64(c.i64())".to_owned(),
        "uintptr" => "uintptr(c.i64())".to_owned(),
        "float32" => "float32(c.f64())".to_owned(),
        "float64" => "c.f64()".to_owned(),
        // An `interface{}`/`any` parameter is the canonical unmarshal out-target
        // (`Unmarshal(data []byte, v interface{})`, `Decode(v interface{})`): pass a
        // fresh `*interface{}` so the decoder populates it and the parser is fuzzed
        // deeply. A value-input `interface{}` accepts it too (interface{} holds any
        // value); an unchecked type assertion on our synthesized value panics with
        // "interface conversion", which the finding classifier treats as our-fault.
        "interface{}" | "any" => "new(interface{})".to_owned(),
        // Call context, not fuzz input. `context.Background()` is what every
        // real caller passes; a nil context panics the moment the callee touches
        // Done()/Err(), which would be bhf's fault rather than a finding.
        "context.Context" => "c.ctx()".to_owned(),
        _ => return None,
    })
}

/// Decode with enough call-site context to distinguish parser output slots from
/// arbitrary `interface{}` values. An expert passes a pointer for
/// `Unmarshal(data, out)` but attacker-controlled bytes for registry/value APIs;
/// treating every interface as an output pointer made shallow setters look more
/// harnessable than they really were.
fn decode_for_param(func: &GoFunc, index: usize, last: bool) -> Option<String> {
    let param = func.params.get(index)?;
    let ty = param.ty.trim();
    if ty != "interface{}" && ty != "any" {
        return decode_for_type(ty, last);
    }
    let name = func.name.to_ascii_lowercase();
    let param_name = param.name.to_ascii_lowercase();
    let parser_output =
        (name.contains("unmarshal") || name.contains("decode") || name.contains("deserialize"))
            && (index > 0
                || matches!(
                    param_name.as_str(),
                    "out" | "dst" | "result" | "value" | "v"
                ));
    Some(if parser_output {
        "new(interface{})".to_owned()
    } else {
        "append([]byte(nil), c.rest()...)".to_owned()
    })
}

/// The platform half of the harness runtime, beside `bhf_harness.go`: mapping
/// the engine's shared coverage file and taking over stdout. Go picks the file
/// for the platform it builds on, so a harness (and the capsule that ships it)
/// builds on Linux and on Windows alike. Both files define
/// `bhfMapShared(path, size) []byte` (nil when the file cannot be mapped) and
/// `bhfControlPipe() *os.File` (the engine's control pipe, after stdout is
/// pointed at the null device).
pub(crate) const GO_OS_FILES: [(&str, &str); 2] = [
    ("bhf_os_unix.go", GO_OS_UNIX),
    ("bhf_os_windows.go", GO_OS_WINDOWS),
];

const GO_OS_UNIX: &str = r#"// SPDX-License-Identifier: Apache-2.0
// Generated by bhf (native Go lane): the harness runtime's POSIX half. Do not edit.

//go:build !windows

package main

import (
	"os"
	"syscall"
)

// bhfMapShared maps size bytes of the file at path, shared with the engine
// (open, ftruncate, mmap MAP_SHARED), or nil.
func bhfMapShared(path string, size int) []byte {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o600)
	if err != nil {
		return nil
	}
	_ = syscall.Ftruncate(fd, int64(size))
	m, err := syscall.Mmap(fd, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	_ = syscall.Close(fd)
	if err != nil {
		return nil
	}
	return m
}

// bhfControlPipe saves the control pipe (fd 1), then points fd 1 and os.Stdout
// at /dev/null.
func bhfControlPipe() *os.File {
	ctlFd, _ := syscall.Dup(1)
	control := os.NewFile(uintptr(ctlFd), "ctl")
	if dn, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		_ = syscall.Dup2(int(dn.Fd()), 1)
		os.Stdout = dn
	}
	return control
}
"#;

const GO_OS_WINDOWS: &str = r#"// SPDX-License-Identifier: Apache-2.0
// Generated by bhf (native Go lane): the harness runtime's Windows half. Do not edit.

//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// bhfMapShared maps size bytes of the file at path, shared with the engine
// (CreateFileMapping + MapViewOfFile, which write through to the file), or nil.
func bhfMapShared(path string, size int) []byte {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	file, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil
	}
	// The mapping keeps the file open; it and the view last as long as the process.
	mapping, err := syscall.CreateFileMapping(file, nil, syscall.PAGE_READWRITE, 0, uint32(size), nil)
	_ = syscall.CloseHandle(file)
	if err != nil {
		return nil
	}
	view, err := syscall.MapViewOfFile(mapping, syscall.FILE_MAP_WRITE, 0, 0, uintptr(size))
	if err != nil {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(view)), size)
}

// bhfControlPipe keeps the control pipe (the stdout handle bhf gave the
// process), then points os.Stdout and the process's standard output handle
// at NUL.
func bhfControlPipe() *os.File {
	control := os.Stdout
	if null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stdout = null
		stdout := syscall.STD_OUTPUT_HANDLE
		setStdHandle := syscall.NewLazyDLL("kernel32.dll").NewProc("SetStdHandle")
		_, _, _ = setStdHandle.Call(uintptr(stdout), null.Fd())
	}
	return control
}
"#;

/// The full harness `main.go`. All imports are referenced inside cursor methods so
/// none is "unused" regardless of which decode paths a given target uses.
fn generate_main_go(import_path: &str, body: &str) -> String {
    format!(
        r#"// SPDX-License-Identifier: Apache-2.0
// Generated by bhf (native Go lane). Decodes fuzz bytes into typed args and
// calls the target; a recovered panic is a finding. Do not edit. BHF_FRAMED
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"runtime/coverage"
	"runtime/debug"
	"strings"
	"syscall"

	tgt "{import_path}"
)

{coverage}type cur struct {{
	d []byte
	p int
}}

func (c *cur) rest() []byte {{ r := c.d[c.p:]; c.p = len(c.d); return r }}
func (c *cur) u8() byte {{
	if c.p < len(c.d) {{
		v := c.d[c.p]
		c.p++
		return v
	}}
	return 0
}}
func (c *cur) i64() int64 {{
	var v uint64
	for i := 0; i < 8 && c.p < len(c.d); i++ {{
		v |= uint64(c.d[c.p]) << (8 * uint(i))
		c.p++
	}}
	return int64(v)
}}

// bytesField reads a 1-byte length then that many bytes (bounded by what remains),
// so multiple []byte/string params each get a chunk.
func (c *cur) bytesField() []byte {{
	n := int(c.u8())
	if rem := len(c.d) - c.p; n > rem {{
		n = rem
	}}
	r := c.d[c.p : c.p+n]
	c.p += n
	return r
}}

// args maps one byte stream to a command/state-machine argument vector. NUL is
// not accepted inside command-line arguments, so it is a lossless field boundary.
func (c *cur) args() []string {{ return strings.Split(string(c.rest()), "\\x00") }}

// f64 decodes a float (and keeps the math import referenced even when no float
// param is decoded by a given target).
func (c *cur) f64() float64 {{ return math.Float64frombits(uint64(c.i64())) }}

// ctx supplies the canonical non-nil, non-cancelled context every real caller
// passes. A `context.Context` parameter carries no fuzz input — it is call
// context — and refusing it made the whole target undrivable. It must NOT be
// nil: a nil context panics the moment the callee touches Done()/Err(), and that
// panic would be bhf's fault, not a finding. This also keeps the context
// import referenced when no target decodes one.
func (c *cur) ctx() context.Context {{ return context.Background() }}

// reader keeps the io import referenced even when no io.Reader param is decoded.
var _ = io.EOF
var _ = json.Unmarshal

// A target parameter's type may name syscall (it is among the imports a type
// can be qualified with); every platform has Getpid.
var _ = syscall.Getpid

{entry}func runOne(data []byte) {{
	defer func() {{
		if r := recover(); r != nil {{
			os.Stderr.WriteString("== bhf go finding: " + fmt.Sprint(r) + "\n")
			os.Stderr.Write(debug.Stack()) // stack frames so findings cluster by site
			_ = os.Stderr.Sync()
			os.Exit(86)
		}}
	}}()
	c := &cur{{d: data}}
	_ = c // JSON-only data arguments do not consume the byte cursor.
	_ = bytes.MinRead
{body}}}

func readU32(f *os.File) (int, bool) {{
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(f, hdr); err != nil {{
		return 0, false
	}}
	return int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16 | int(hdr[3])<<24, true
}}

func main() {{
	// Keep the control pipe (stdout) and point stdout at the null device, so
	// the target's prints can't corrupt the sync stream (#427).
	control := bhfControlPipe()
	in := os.Stdin
	if os.Getenv("BHF_FRAMED") != "" {{
		bhfCovInit()
		_, _ = control.Write([]byte{{1}}) // ready
		for {{
			n, ok := readU32(in)
			if !ok {{
				break
			}}
			buf := make([]byte, n)
			if _, err := io.ReadFull(in, buf); err != nil && n > 0 {{
				break
			}}
			bhfCovClear()
			runOne(buf)
			bhfCovRecord()
			_, _ = control.Write([]byte{{1}}) // sync
		}}
		return
	}}
	// Per-spawn replay: argv[1] file else stdin.
	var data []byte
	if len(os.Args) > 1 {{
		if b, err := os.ReadFile(os.Args[1]); err == nil {{
			data = b
		}}
	}} else {{
		data, _ = io.ReadAll(in)
	}}
	runOne(data)
}}
"#,
        import_path = import_path,
        body = body,
        coverage = GO_COVERAGE_RUNTIME,
        entry = GO_TARGET_ENTRY_RUNTIME,
    )
}

/// The harness runtime's edge coverage: per input, the set of Go `-cover`
/// blocks the input executed, folded into the engine's `BHF_COV_SHM` map.
/// Shared by every Go harness `main` bhf generates.
const GO_COVERAGE_RUNTIME: &str = r#"// --- bhf real edge coverage (Go -cover atomic counters -> shared edge map) ---
// The builtin engine reads BHF_COV_SHM as a cumulative 64KB AFL edge bitmap.
// Per input we clear Go's coverage counters, run the target, then fold the SET of
// executed blocks (counter != 0 — the count VALUE is ignored, so a loop's trip
// count is never false novelty) into the map. Parsing Go's internal covcounters
// format is version-guarded: any mismatch folds nothing (black-box fallback), so a
// future format change degrades gracefully rather than emitting a wrong signal.
const bhfCovBits = 1 << 16

var bhfCovMap []byte
var bhfCovBuf bytes.Buffer

func bhfCovInit() {
	path := os.Getenv("BHF_COV_SHM")
	if path == "" {
		return
	}
	bhfCovMap = bhfMapShared(path, bhfCovBits)
	_ = coverage.ClearCounters()
}

func bhfCovClear() {
	if bhfCovMap != nil {
		_ = coverage.ClearCounters()
	}
}

func bhfCovRecord() {
	if bhfCovMap == nil {
		return
	}
	bhfCovBuf.Reset()
	if coverage.WriteCounters(&bhfCovBuf) != nil {
		_ = coverage.ClearCounters()
		return
	}
	b := bhfCovBuf.Bytes()
	_ = coverage.ClearCounters()
	if len(b) < 32 || b[1] != 'c' || b[2] != 'w' || b[3] != 'm' {
		return
	}
	flavor := b[24]
	p := 32 // magic[4] version[4] metaHash[16] flavor[1] bigEndian[1] pad[6]
	le := func(n int) uint64 {
		var v uint64
		for i := 0; i < n; i++ {
			v |= uint64(b[p+i]) << (8 * uint(i))
		}
		p += n
		return v
	}
	uleb := func() (uint64, bool) {
		var v uint64
		var s uint
		for {
			if p >= len(b) {
				return 0, false
			}
			c := b[p]
			p++
			v |= uint64(c&0x7f) << s
			if c&0x80 == 0 {
				break
			}
			s += 7
		}
		return v, true
	}
	rd := func() (uint64, bool) {
		if flavor == 1 { // CtrRaw: fixed uint32
			if p+4 > len(b) {
				return 0, false
			}
			return le(4), true
		}
		return uleb() // CtrULeb128
	}
	if p+16 > len(b) {
		return
	}
	fcn := le(8)
	strtab := le(4)
	args := le(4)
	p += int(strtab) + int(args)
	if p > len(b) {
		return
	}
	for f := uint64(0); f < fcn; f++ {
		nc, ok := rd()
		if !ok {
			return
		}
		pkg, ok2 := rd()
		if !ok2 {
			return
		}
		fnc, ok3 := rd()
		if !ok3 {
			return
		}
		for c := uint64(0); c < nc; c++ {
			v, ok4 := rd()
			if !ok4 {
				return
			}
			if v != 0 {
				idx := ((uint32(pkg) * 2654435761) ^ (uint32(fnc) * 40503) ^ uint32(c)) & (bhfCovBits - 1)
				if bhfCovMap[idx] != 0xff {
					bhfCovMap[idx]++
				}
			}
		}
	}
}

"#;

/// The harness runtime's target-entry proof: one byte in `BHF_TARGET_ENTRY_SHM`
/// once an input reached the target.
const GO_TARGET_ENTRY_RUNTIME: &str = r#"var bhfTargetEntered bool

func bhfMarkTargetEntry() {
	if bhfTargetEntered {
		return
	}
	path := os.Getenv("BHF_TARGET_ENTRY_SHM")
	if path == "" {
		return
	}
	if os.WriteFile(path, []byte{1}, 0o600) == nil {
		bhfTargetEntered = true
	}
}

"#;

/// Where in a fuzz test's harness dir the closure of the target module is
/// copied ([`stage_module_closure`]).
pub(crate) const FUZZ_MODULE_DIR: &str = "bhf_module";

/// The harness package the stand-in for `testing` is written to.
const FUZZ_SHIM_DIR: &str = "bhftesting";

/// The harness package an external (`package x_test`) fuzz test is copied to.
const FUZZ_EXTERNAL_PACKAGE: &str = "bhffuzz";

/// Most bytes, and files, one copy of a target module's closure may hold.
const MAX_MODULE_COPY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MODULE_COPY_FILES: usize = 50_000;

/// Most source-literal tokens a fuzz test's package adds to its dictionary.
const MAX_FUZZ_PACKAGE_TOKENS: usize = 256;

/// Build a Go native fuzz test (`func FuzzXxx(f *testing.F)` in a `_test.go`
/// file) as a harness the builtin engine drives.
///
/// `go test -fuzz` runs a fuzz test with its own engine, which bhf's cannot
/// drive, and a `_test.go` file is not part of any package `go build` builds.
/// So, as OSS-Fuzz builds native Go fuzzers: the test file is copied into its
/// package as an ordinary source file, with its `testing` import pointed at a
/// stand-in ([`GO_TESTING_SHIM`]) whose `F.Fuzz` hands bhf's inputs to the
/// fuzz target, and a generated `main` runs the fuzz test. The package and
/// what it imports from its module are COPIED into the harness dir
/// ([`stage_module_closure`]), each file with a `//line` directive naming the
/// original, because `go build -cover` reads the files it instruments from
/// disk and ignores a `-overlay`, and the scanned tree is never edited.
///
/// An input is decoded into the fuzz target's arguments in the layout bhf's
/// generated Go harnesses use; the fuzz test's `f.Add` seeds and its
/// `testdata/fuzz/<Name>` corpus are written in that layout to
/// [`crate::auto::provided::SEEDS_DIR`] by running the built harness once with
/// `BHF_GO_FUZZ_SEEDS` set. A recovered panic, or a failure the fuzz target
/// reports with `t.Error`/`t.Fatal`, is a finding, as it is to `go test`.
fn build_go_fuzz_test(
    go: &Path,
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
) -> GoBuildResult {
    match build_go_fuzz_test_inner(go, candidate, work_dir, harness_id) {
        Ok(()) => GoBuildResult::Built { forced: None },
        Err((reason, skip)) => GoBuildResult::Failed { reason, skip },
    }
}

/// A test file of the fuzz test's package, as read.
struct GoTestFile {
    path: PathBuf,
    text: String,
}

fn build_go_fuzz_test_inner(
    go: &Path,
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
) -> Result<(), (String, bool)> {
    let source = crate::source_text::read_source_text(&candidate.source_path).map_err(|e| {
        (
            format!("read {}: {e}", candidate.source_path.display()),
            false,
        )
    })?;
    let tests = go_parser::parse_go_fuzz_tests(&source)
        .map_err(|_| ("failed to parse the Go fuzz test's file".to_owned(), true))?;
    let test = tests
        .iter()
        .find(|t| t.name == candidate.name && t.line == candidate.line)
        .or_else(|| tests.iter().find(|t| t.name == candidate.name))
        .cloned()
        .ok_or_else(|| {
            (
                format!("fuzz test `{}` no longer present in source", candidate.name),
                true,
            )
        })?;
    let target_abs = crate::workdir::plain_canonical(&candidate.source_path);
    let pkg_dir = target_abs
        .parent()
        .ok_or_else(|| ("Go fuzz test has no package directory".to_owned(), false))?
        .to_path_buf();
    let (internal_package, external) = match test.package.strip_suffix("_test") {
        Some(package) => (package.to_owned(), true),
        None => (test.package.clone(), false),
    };
    if external && internal_package == "main" {
        return Err((
            "an external test of a `main` package cannot import it".to_owned(),
            true,
        ));
    }

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    std::fs::create_dir_all(&auto_dir)
        .map_err(|e| (format!("create {}: {e}", auto_dir.display()), false))?;
    crate::auto::provided::clear(&auto_dir)
        .map_err(|e| (format!("clear {}: {e}", auto_dir.display()), false))?;

    // The fuzz test's file, then the package's other test files, which a
    // second build adds when the first could not resolve a helper they
    // define. An external test's package also sees the package's internal
    // test files, which `go test` compiles into the package under test (an
    // `export_test.go` exporting what the external test calls): a third
    // build adds those to the package's copy.
    let fuzz_file = GoTestFile {
        path: target_abs.clone(),
        text: source,
    };
    let siblings = sibling_test_files(&pkg_dir, &target_abs, &test.package);
    let internal_tests = if external {
        sibling_test_files(&pkg_dir, &target_abs, &internal_package)
    } else {
        Vec::new()
    };
    let mut last = None;
    for (with_siblings, with_internal) in [(false, false), (true, false), (true, true)] {
        let adds = if with_internal {
            !internal_tests.is_empty()
        } else {
            !with_siblings || !siblings.is_empty()
        };
        if !adds {
            continue;
        }
        let mut files = vec![&fuzz_file];
        if with_siblings {
            files.extend(siblings.iter());
        }
        let internal: Vec<&GoTestFile> = if with_internal {
            internal_tests.iter().collect()
        } else {
            Vec::new()
        };
        match stage_and_build_fuzz_test(
            go,
            &test,
            &files,
            &internal,
            &pkg_dir,
            &internal_package,
            external,
            &auto_dir,
            work_dir,
        ) {
            Ok(()) => {
                last = None;
                break;
            }
            Err(error) => {
                let retry = error.0.contains("undefined:");
                last = Some(error);
                if !retry {
                    break;
                }
            }
        }
    }
    if let Some(error) = last {
        return Err(error);
    }
    probe_fuzz_test(&auto_dir, candidate, &test, &pkg_dir)
}

/// The other `_test.go` files of `pkg_dir` in `package`.
fn sibling_test_files(pkg_dir: &Path, fuzz_file: &Path, package: &str) -> Vec<GoTestFile> {
    let Ok(entries) = std::fs::read_dir(pkg_dir) else {
        return Vec::new();
    };
    let mut files: Vec<GoTestFile> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path != fuzz_file
                && path.is_file()
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with("_test.go"))
        })
        .filter_map(|path| {
            let text = crate::source_text::read_source_text(&path).ok()?;
            (parse_go_package(&text).ok()? == package).then_some(GoTestFile { path, text })
        })
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

/// The harness file name a test file is copied to: `parse_test.go` becomes
/// `bhf_fuzztest_parse.go`, an ordinary source file.
fn fuzz_test_copy_name(path: &Path) -> String {
    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix("_test.go"))
        .unwrap_or("fuzz");
    format!("bhf_fuzztest_{stem}.go")
}

/// Stage the fuzz test's `files` (the fuzz test's first) and, for an
/// external test, the package's `internal` test files, and build them.
#[allow(clippy::too_many_arguments)]
fn stage_and_build_fuzz_test(
    go: &Path,
    test: &go_parser::GoFuzzTest,
    files: &[&GoTestFile],
    internal: &[&GoTestFile],
    pkg_dir: &Path,
    internal_package: &str,
    external: bool,
    auto_dir: &Path,
    work_dir: &Path,
) -> Result<(), (String, bool)> {
    let io = |what: &str, error: std::io::Error| (format!("{what}: {error}"), false);
    for stale in [
        FUZZ_MODULE_DIR,
        FUZZ_SHIM_DIR,
        FUZZ_EXTERNAL_PACKAGE,
        LOOSE_PACKAGE_DIR,
    ] {
        let _ = std::fs::remove_dir_all(auto_dir.join(stale));
    }
    let rename_main = internal_package == "main";
    // The copy of the target's module, its module path, the target package's
    // import path and its directory in the copy.
    let (copy_root, module_path, import_path, copy_pkg_dir, gated_go_mod) =
        match find_go_module(&files[0].path) {
            Some((mod_root, module_path)) => {
                let copy_root = auto_dir.join(FUZZ_MODULE_DIR);
                let harness = harness_module_path(&module_path);
                let shim = format!("{harness}/{FUZZ_SHIM_DIR}");
                let imports: Vec<String> = files
                    .iter()
                    .chain(internal)
                    .flat_map(|file| go_parser::parse_go_imports(&file.text).unwrap_or_default())
                    .filter(|path| path != "testing" && *path != shim)
                    .collect();
                stage_module_closure(
                    &mod_root,
                    &module_path,
                    pkg_dir,
                    &imports,
                    rename_main,
                    &copy_root,
                    work_dir,
                )
                .map_err(|reason| (reason, true))?;
                let import_path = compute_import_path(&module_path, &mod_root, &files[0].path);
                let relative = pkg_dir.strip_prefix(&mod_root).unwrap_or(Path::new(""));
                let copy_pkg_dir = copy_root.join(relative);
                let gated = copy_root.join("go.mod");
                (
                    copy_root,
                    module_path,
                    import_path,
                    copy_pkg_dir,
                    Some(gated),
                )
            }
            None => {
                let (copy_root, module_path) =
                    loose_package_module(&files[0].path, auto_dir, internal_package)
                        .map_err(|reason| (reason, false))?;
                (
                    copy_root.clone(),
                    module_path.clone(),
                    module_path,
                    copy_root,
                    None,
                )
            }
        };
    let harness = harness_module_path(&module_path);
    let shim = format!("{harness}/{FUZZ_SHIM_DIR}");

    // The test files, as ordinary sources: an internal test's in its package
    // (in the copy), an external test's in a harness package of its own.
    let external_dir = auto_dir.join(FUZZ_EXTERNAL_PACKAGE);
    for file in files {
        let text = go_parser::rewrite_testing_import(&file.text, &shim)
            .unwrap_or_else(|| file.text.clone());
        let name = fuzz_test_copy_name(&file.path);
        if external {
            std::fs::create_dir_all(&external_dir)
                .map_err(|e| io("create the external test's package", e))?;
            let copied = external_test_source(&file.path, &text, &test.package);
            std::fs::write(external_dir.join(&name), copied)
                .map_err(|e| io("write the fuzz test", e))?;
        } else {
            std::fs::create_dir_all(&copy_pkg_dir)
                .map_err(|e| io("create the fuzz test's package", e))?;
            std::fs::write(
                copy_pkg_dir.join(&name),
                loose_go_source(&file.path, &text, rename_main),
            )
            .map_err(|e| io("write the fuzz test", e))?;
        }
    }
    for file in internal {
        let text = go_parser::rewrite_testing_import(&file.text, &shim)
            .unwrap_or_else(|| file.text.clone());
        std::fs::create_dir_all(&copy_pkg_dir)
            .map_err(|e| io("create the fuzz test's package", e))?;
        std::fs::write(
            copy_pkg_dir.join(fuzz_test_copy_name(&file.path)),
            loose_go_source(&file.path, &text, false),
        )
        .map_err(|e| io("write the package's test file", e))?;
    }
    let shim_dir = auto_dir.join(FUZZ_SHIM_DIR);
    std::fs::create_dir_all(&shim_dir).map_err(|e| io("create the testing stand-in", e))?;
    std::fs::write(shim_dir.join("testing.go"), GO_TESTING_SHIM)
        .map_err(|e| io("write the testing stand-in", e))?;

    let entry_import = if external {
        format!("{harness}/{FUZZ_EXTERNAL_PACKAGE}")
    } else {
        import_path.clone()
    };
    let corpus = pkg_dir.join("testdata").join("fuzz").join(&test.name);
    let main_go = generate_fuzz_test_main_go(&entry_import, &shim, &test.name, pkg_dir, &corpus);
    for (name, text) in std::iter::once(("bhf_harness.go", main_go.as_str())).chain(GO_OS_FILES) {
        std::fs::write(auto_dir.join(name), text).map_err(|e| io("write the harness", e))?;
    }
    let tokens = fuzz_package_tokens(pkg_dir);
    append_json_seed_dictionary(auto_dir, &tokens)
        .map_err(|e| io("write the fuzz test's dictionary", e))?;
    let relative_copy = format!(
        "./{}",
        copy_root
            .strip_prefix(auto_dir)
            .unwrap_or(&copy_root)
            .to_string_lossy()
            .replace('\\', "/")
    );
    let go_mod = format!(
        "module {harness}\n\ngo 1.21\n\nrequire {module_path} {version}\n\nreplace {module_path} => {root}\n",
        version = placeholder_module_version(&module_path),
        root = serde_json::to_string(&relative_copy).expect("serializing a path string cannot fail"),
    );
    std::fs::write(auto_dir.join("go.mod"), go_mod).map_err(|e| io("write go.mod", e))?;

    let bin = auto_dir.join(crate::auto::layout::harness_exe_name("main"));
    let _ = std::fs::remove_file(&bin);
    let mut tidy = Command::new(go);
    tidy.args(["mod", "tidy"])
        .current_dir(auto_dir)
        .env("GOFLAGS", "-mod=mod")
        .env("GOTOOLCHAIN", "local");
    let _ =
        crate::command_output::output_with_timeout(&mut tidy, std::time::Duration::from_secs(300));
    let patterns = coverage_package_patterns(&module_path, &import_path);
    let mut build = go_build_with_coverage(go, auto_dir, &bin, &patterns);
    let version_gated = build.as_ref().is_ok_and(|out| {
        !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("requires go >=")
    });
    if let (true, Some(go_mod), Some(local)) = (version_gated, gated_go_mod, local_go_minor(go)) {
        // The copy is bhf's own, so its `go` directive is lowered in place.
        if let Ok(text) = std::fs::read_to_string(&go_mod) {
            if std::fs::write(&go_mod, lower_go_mod_directive(&text, &local)).is_ok() {
                build = go_build_with_coverage(go, auto_dir, &bin, &patterns);
            }
        }
    }
    match build {
        Ok(out) if out.status.success() && bin.is_file() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let skip = stderr.contains("cannot find module")
                || stderr.contains("missing go.sum")
                || stderr.contains("dial tcp")
                || stderr.contains("no required module")
                || stderr.contains("toolchain not available")
                || stderr.contains("requires go >=");
            let first = stderr
                .lines()
                .find(|line| line.contains(".go:") || line.contains("undefined"))
                .or_else(|| stderr.lines().last())
                .unwrap_or("");
            Err((format!("go build of fuzz test failed: {first}"), skip))
        }
        Err(e) => Err((format!("could not run go build: {e}"), false)),
    }
}

/// `go build` the harness in `auto_dir` with coverage of the first of
/// `patterns` that builds, else without coverage.
fn go_build_with_coverage(
    go: &Path,
    auto_dir: &Path,
    bin: &Path,
    patterns: &[String],
) -> std::io::Result<std::process::Output> {
    let run = |cover: Option<&str>| {
        let mut cmd = Command::new(go);
        cmd.args(["build", "-o"]).arg(bin);
        if let Some(pattern) = cover {
            cmd.args(["-cover", "-covermode=atomic"])
                .arg(format!("-coverpkg={pattern}"));
        }
        cmd.arg(".")
            .current_dir(auto_dir)
            .env("GOFLAGS", "-mod=mod")
            .env("GOTOOLCHAIN", "local");
        crate::command_output::output_with_timeout(
            &mut cmd,
            std::time::Duration::from_secs(30 * 60),
        )
    };
    let built = |build: &std::io::Result<std::process::Output>| {
        build
            .as_ref()
            .is_ok_and(|out| out.status.success() && bin.is_file())
    };
    for pattern in patterns {
        let build = run(Some(pattern));
        if built(&build) {
            return build;
        }
    }
    run(None)
}

/// Copy the package at `pkg_dir` of the module at `mod_root`, and every package
/// of the module it imports (directly, through `imports`, or through another
/// copied package), into `dest`, with the module's `go.mod` and `go.sum`.
///
/// Each `.go` file (but a test file) is copied with a `//line` directive naming
/// the original, so panics and coverage name the project's files; every other
/// regular file of a copied package (assembly, cgo sources, embedded files) is
/// copied as it is, and so is each subdirectory a `//go:embed` names. Hidden
/// and `testdata` directories, nested modules, the work dir and symlinks are
/// not copied. The copy is refused past [`MAX_MODULE_COPY_BYTES`] or
/// [`MAX_MODULE_COPY_FILES`].
fn stage_module_closure(
    mod_root: &Path,
    module_path: &str,
    pkg_dir: &Path,
    imports: &[String],
    rename_main: bool,
    dest: &Path,
    work_dir: &Path,
) -> Result<(), String> {
    let mut budget = CopyBudget::default();
    std::fs::create_dir_all(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    for name in ["go.mod", "go.sum"] {
        let from = mod_root.join(name);
        if from.is_file() {
            budget.copy(&from, &dest.join(name))?;
        }
    }
    let package_dir = |import: &str| -> Option<PathBuf> {
        let rest = if import == module_path {
            ""
        } else {
            import.strip_prefix(module_path)?.strip_prefix('/')?
        };
        let dir = mod_root.join(rest);
        dir.is_dir().then_some(dir)
    };
    let work_dir = crate::workdir::plain_canonical(work_dir);
    let mut queue: std::collections::VecDeque<PathBuf> =
        std::iter::once(pkg_dir.to_path_buf()).collect();
    queue.extend(imports.iter().filter_map(|import| package_dir(import)));
    let mut seen = std::collections::BTreeSet::new();
    while let Some(dir) = queue.pop_front() {
        if !seen.insert(dir.clone()) || crate::workdir::plain_canonical(&dir).starts_with(&work_dir)
        {
            continue;
        }
        let relative = dir.strip_prefix(mod_root).unwrap_or(Path::new(""));
        let copy = dest.join(relative);
        std::fs::create_dir_all(&copy).map_err(|e| format!("create {}: {e}", copy.display()))?;
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut embedded = std::collections::BTreeSet::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with("_test.go") {
                continue;
            }
            if !name.ends_with(".go") {
                budget.copy(&path, &copy.join(&name))?;
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                budget.copy(&path, &copy.join(&name))?;
                continue;
            };
            for import in go_parser::parse_go_imports(&text).unwrap_or_default() {
                if let Some(imported) = package_dir(&import) {
                    queue.push_back(imported);
                }
            }
            embedded.extend(embed_dirs(&text));
            let renamed = rename_main && dir == pkg_dir;
            budget.charge(text.len() as u64)?;
            std::fs::write(copy.join(&name), loose_go_source(&path, &text, renamed))
                .map_err(|e| format!("copy {}: {e}", path.display()))?;
        }
        for sub in embedded {
            let from = dir.join(&sub);
            if from.is_dir() {
                budget.copy_tree(&from, &copy.join(&sub))?;
            }
        }
    }
    Ok(())
}

/// The first path element of each pattern a `//go:embed` line names: a
/// directory to copy with the package.
fn embed_dirs(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("//go:embed "))
        .flat_map(|patterns| patterns.split_whitespace())
        .map(|pattern| {
            pattern
                .trim_matches(['"', '`'])
                .trim_start_matches("all:")
                .split('/')
                .next()
                .unwrap_or("")
                .to_owned()
        })
        .filter(|first| {
            !first.is_empty()
                && !first.starts_with('.')
                && *first != "testdata"
                && !first.contains(['*', '?', '['])
        })
        .collect()
}

/// What a module copy has taken so far.
#[derive(Default)]
struct CopyBudget {
    bytes: u64,
    files: usize,
}

impl CopyBudget {
    fn charge(&mut self, bytes: u64) -> Result<(), String> {
        self.bytes += bytes;
        self.files += 1;
        if self.bytes > MAX_MODULE_COPY_BYTES || self.files > MAX_MODULE_COPY_FILES {
            return Err(format!(
                "the fuzz test's packages hold more than {} MiB or {MAX_MODULE_COPY_FILES} \
                 files; too many to stage a copy of",
                MAX_MODULE_COPY_BYTES / (1024 * 1024)
            ));
        }
        Ok(())
    }

    fn copy(&mut self, from: &Path, to: &Path) -> Result<(), String> {
        let len = std::fs::symlink_metadata(from)
            .map_err(|e| format!("read {}: {e}", from.display()))?
            .len();
        self.charge(len)?;
        std::fs::copy(from, to)
            .map(|_| ())
            .map_err(|e| format!("copy {}: {e}", from.display()))
    }

    /// Copy the regular files under `from`, but hidden directories, nested
    /// modules and symlinks.
    fn copy_tree(&mut self, from: &Path, to: &Path) -> Result<(), String> {
        if from.join("go.mod").exists() {
            return Ok(());
        }
        std::fs::create_dir_all(to).map_err(|e| format!("create {}: {e}", to.display()))?;
        let entries =
            std::fs::read_dir(from).map_err(|e| format!("read {}: {e}", from.display()))?;
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            if kind.is_dir() {
                self.copy_tree(&entry.path(), &to.join(&name))?;
            } else if kind.is_file() {
                self.copy(&entry.path(), &to.join(&name))?;
            }
        }
        Ok(())
    }
}

/// A copied external test file (`package x_test`): a `//line` directive
/// naming `original`, then the source, its package clause renamed to
/// [`FUZZ_EXTERNAL_PACKAGE`]. Every line keeps its number.
fn external_test_source(original: &Path, text: &str, package: &str) -> String {
    let mut out = format!("//line {}:1\n", original.display());
    let mut renamed = false;
    let mut in_block_comment = false;
    for line in text.split_inclusive('\n') {
        if !renamed && !in_block_comment {
            let clause = line
                .strip_prefix("package")
                .map(|rest| rest.trim_start_matches([' ', '\t']))
                .and_then(|name| name.strip_prefix(package))
                .filter(|after| !after.starts_with(|c: char| c.is_alphanumeric() || c == '_'));
            if let Some(after) = clause {
                out.push_str(&format!("package {FUZZ_EXTERNAL_PACKAGE}{after}"));
                renamed = true;
                continue;
            }
        }
        if let Some((_, after)) = line.rsplit_once("/*") {
            in_block_comment = !after.contains("*/");
        } else if in_block_comment && line.contains("*/") {
            in_block_comment = false;
        }
        out.push_str(line);
    }
    out
}

/// Source-literal tokens of the fuzz test's package (its ordinary files), for
/// its dictionary: the magic values its code compares input against.
fn fuzz_package_tokens(pkg_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(pkg_dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "go")
                && !path.to_string_lossy().ends_with("_test.go")
        })
        .collect();
    files.sort();
    let mut tokens = Vec::new();
    for file in files {
        let Ok(text) = crate::source_text::read_source_text(&file) else {
            continue;
        };
        for token in go_parser::extract_go_dictionary_tokens(&text).unwrap_or_default() {
            if tokens.len() >= MAX_FUZZ_PACKAGE_TOKENS {
                return tokens;
            }
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
    }
    tokens
}

/// Run the built fuzz test once with `BHF_GO_FUZZ_SEEDS`: it sets the test up
/// (which must reach `f.Fuzz`) and writes its starting inputs, then record it
/// as a provided harness.
fn probe_fuzz_test(
    auto_dir: &Path,
    candidate: &Candidate,
    test: &go_parser::GoFuzzTest,
    pkg_dir: &Path,
) -> Result<(), (String, bool)> {
    let bin = auto_dir.join(crate::auto::layout::harness_exe_name("main"));
    let seeds = auto_dir.join(crate::auto::provided::SEEDS_DIR);
    let summary = auto_dir.join(format!("{}.txt", crate::auto::provided::SEEDS_DIR));
    let _ = std::fs::remove_file(&summary);
    let mut probe = Command::new(&bin);
    probe
        .env("BHF_GO_FUZZ_SEEDS", &seeds)
        .env_remove("BHF_FRAMED")
        .current_dir(auto_dir)
        .stdin(std::process::Stdio::null());
    let out =
        crate::command_output::output_with_timeout(&mut probe, std::time::Duration::from_secs(60))
            .map_err(|e| (format!("could not run the fuzz test harness: {e}"), false))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        if let Some(why) = stderr
            .lines()
            .find_map(|line| line.strip_prefix("== bhf go fuzz test setup: "))
        {
            return Err((format!("fuzz test could not be set up: {why}"), true));
        }
        return Err((
            format!(
                "the fuzz test harness failed to start ({}): {}",
                out.status,
                stderr.lines().last().unwrap_or("")
            ),
            false,
        ));
    }
    let counts = std::fs::read_to_string(&summary).unwrap_or_default();
    let _ = std::fs::remove_file(&summary);
    let mut numbers = counts
        .split_whitespace()
        .map(|n| n.parse::<usize>().unwrap_or(0));
    let written = numbers.next().unwrap_or(0);
    let skipped = numbers.next().unwrap_or(0);
    let corpus = pkg_dir.join("testdata").join("fuzz").join(&test.name);
    let mut notes = Vec::new();
    if skipped > 0 {
        notes.push(format!(
            "{skipped} seed(s) could not be used: not in the `go test fuzz v1` encoding, or not \
             of the fuzz target's argument types"
        ));
    }
    crate::auto::provided::write_record(
        auto_dir,
        &crate::auto::provided::ProvidedRecord {
            origin: crate::auto::provided::Origin::GoFuzzTest,
            entry: test.name.clone(),
            source: candidate.source_path.clone(),
            seeds: written,
            seed_sources: corpus.is_dir().then_some(corpus).into_iter().collect(),
            notes,
        },
    )
    .map_err(|e| (format!("record the provided harness: {e}"), false))
}

/// The harness `main` of a native fuzz test: it runs the fuzz test `name`
/// (from `entry_import`) through the stand-in `testing` package at
/// `shim_import`, whose `f.Fuzz` hands it the framed input loop.
fn generate_fuzz_test_main_go(
    entry_import: &str,
    shim_import: &str,
    name: &str,
    package_dir: &Path,
    corpus: &Path,
) -> String {
    let quote = |path: &Path| {
        serde_json::to_string(&path.to_string_lossy()).expect("serializing a string cannot fail")
    };
    format!(
        r#"// SPDX-License-Identifier: Apache-2.0
// Generated by bhf (native Go lane): runs the project's native fuzz test {name}
// on bhf's engine. A recovered panic, or a failure the fuzz target reports
// through its *testing.T, is a finding. Do not edit. BHF_FRAMED
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/coverage"
	"runtime/debug"

	testing "{shim_import}"
	tgt "{entry_import}"
)

{coverage}{entry}func runOne(run func([]byte), data []byte) {{
	defer func() {{
		if r := recover(); r != nil {{
			os.Stderr.WriteString("== bhf go finding: " + fmt.Sprint(r) + "\n")
			os.Stderr.Write(debug.Stack()) // stack frames so findings cluster by site
			_ = os.Stderr.Sync()
			os.Exit(86)
		}}
	}}()
	bhfMarkTargetEntry()
	run(data)
}}

func readU32(f *os.File) (int, bool) {{
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(f, hdr); err != nil {{
		return 0, false
	}}
	return int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16 | int(hdr[3])<<24, true
}}

func main() {{
	// The fuzz test runs in its package's directory, as under go test, so a
	// replayed input named relative to where bhf started the harness is
	// resolved first.
	if len(os.Args) > 1 {{
		if abs, err := filepath.Abs(os.Args[1]); err == nil {{
			os.Args[1] = abs
		}}
	}}
	// Keep the control pipe (stdout) and point stdout at the null device, so
	// the fuzz test's prints can't corrupt the sync stream.
	control := bhfControlPipe()
	loop := func(run func([]byte)) {{
		in := os.Stdin
		if os.Getenv("BHF_FRAMED") != "" {{
			bhfCovInit()
			_, _ = control.Write([]byte{{1}}) // ready
			for {{
				n, ok := readU32(in)
				if !ok {{
					break
				}}
				buf := make([]byte, n)
				if _, err := io.ReadFull(in, buf); err != nil && n > 0 {{
					break
				}}
				bhfCovClear()
				runOne(run, buf)
				bhfCovRecord()
				_, _ = control.Write([]byte{{1}}) // sync
			}}
			return
		}}
		// Per-spawn replay: argv[1] file else stdin.
		var data []byte
		if len(os.Args) > 1 {{
			if b, err := os.ReadFile(os.Args[1]); err == nil {{
				data = b
			}}
		}} else {{
			data, _ = io.ReadAll(in)
		}}
		runOne(run, data)
	}}
	testing.BhfMain("{name}", tgt.{name}, {dir}, {corpus}, os.Getenv("BHF_GO_FUZZ_SEEDS"), loop)
}}
"#,
        coverage = GO_COVERAGE_RUNTIME,
        entry = GO_TARGET_ENTRY_RUNTIME,
        dir = quote(package_dir),
        corpus = quote(corpus),
    )
}

/// The stand-in for the standard `testing` package a native fuzz test is
/// built against (package `testing` at `<harness>/bhftesting`). Its `F`
/// collects the `f.Add` seeds and runs bhf's inputs through the `f.Fuzz`
/// target; `T`, `B`, `M` and the package functions are there so the rest of a
/// test file compiles.
const GO_TESTING_SHIM: &str = r#"// SPDX-License-Identifier: Apache-2.0
// Generated by bhf (native Go lane): the stand-in for the standard `testing`
// package a project's native fuzz test is built against, so bhf's engine
// drives the test's f.Fuzz target. Do not edit.

package testing

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TB is the interface common to T, B and F.
type TB interface {
	Cleanup(func())
	Error(args ...any)
	Errorf(format string, args ...any)
	Fail()
	FailNow()
	Failed() bool
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Helper()
	Log(args ...any)
	Logf(format string, args ...any)
	Name() string
	Setenv(key, value string)
	Skip(args ...any)
	SkipNow()
	Skipf(format string, args ...any)
	Skipped() bool
	TempDir() string
}

type stopNow struct{}

type common struct {
	mu       sync.Mutex
	name     string
	failed   bool
	skipped  bool
	stopping bool
	messages []string
	stack    []byte
	cleanups []func()
	parent   *common
}

// stop ends the running test function, as runtime.Goexit ends a test's
// goroutine under go test: runGuarded recovers this panic, and only it.
func (c *common) stop() {
	c.mu.Lock()
	c.stopping = true
	c.mu.Unlock()
	panic(stopNow{})
}

func (c *common) record(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.messages) < 16 {
		c.messages = append(c.messages, msg)
	}
}

func (c *common) markFailed() {
	c.mu.Lock()
	c.failed = true
	if c.stack == nil {
		c.stack = callerStack()
	}
	c.mu.Unlock()
	if c.parent != nil {
		c.parent.inherit(c)
	}
}

func (c *common) inherit(child *common) {
	c.mu.Lock()
	c.failed = true
	if c.stack == nil {
		c.stack = child.stack
	}
	c.messages = append(c.messages, child.messages...)
	c.mu.Unlock()
}

func (c *common) Cleanup(f func()) {
	c.mu.Lock()
	c.cleanups = append(c.cleanups, f)
	c.mu.Unlock()
}

func (c *common) runCleanups() {
	for {
		c.mu.Lock()
		n := len(c.cleanups)
		if n == 0 {
			c.mu.Unlock()
			return
		}
		f := c.cleanups[n-1]
		c.cleanups = c.cleanups[:n-1]
		c.mu.Unlock()
		f()
	}
}

func (c *common) Error(args ...any) { c.record(fmt.Sprintln(args...)); c.markFailed() }
func (c *common) Errorf(format string, args ...any) {
	c.record(fmt.Sprintf(format, args...))
	c.markFailed()
}
func (c *common) Fail()                             { c.markFailed() }
func (c *common) FailNow()                          { c.markFailed(); c.stop() }
func (c *common) Failed() bool                      { c.mu.Lock(); defer c.mu.Unlock(); return c.failed }
func (c *common) Fatal(args ...any)                 { c.Error(args...); c.stop() }
func (c *common) Fatalf(format string, args ...any) { c.Errorf(format, args...); c.stop() }
func (c *common) Helper()                           {}
func (c *common) Log(args ...any)                   {}
func (c *common) Logf(format string, args ...any)   {}
func (c *common) Name() string                      { return c.name }
func (c *common) Skip(args ...any)                  { c.SkipNow() }
func (c *common) Skipf(format string, args ...any)  { c.SkipNow() }
func (c *common) SkipNow() {
	c.mu.Lock()
	c.skipped = true
	c.mu.Unlock()
	c.stop()
}
func (c *common) Skipped() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.skipped }
func (c *common) Setenv(key, value string) {
	prev, had := os.LookupEnv(key)
	_ = os.Setenv(key, value)
	c.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}
func (c *common) TempDir() string {
	dir, err := os.MkdirTemp("", "bhf-go-fuzz-")
	if err != nil {
		c.Fatalf("TempDir: %v", err)
	}
	c.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
func (c *common) Chdir(dir string) {
	prev, err := os.Getwd()
	if err != nil || os.Chdir(dir) != nil {
		c.Fatalf("Chdir %s failed", dir)
	}
	c.Cleanup(func() { _ = os.Chdir(prev) })
}
func (c *common) Context() context.Context { return context.Background() }
func (c *common) Output() *os.File         { return os.Stderr }
func (c *common) Attr(key, value string)   {}

// T is the fuzz target's per-input test value.
type T struct{ common }

func (t *T) Parallel()                   {}
func (t *T) Deadline() (time.Time, bool) { return time.Time{}, false }
func (t *T) Run(name string, f func(t *T)) bool {
	sub := &T{common{name: t.name + "/" + name, parent: &t.common}}
	runGuarded(&sub.common, func() { f(sub) })
	return !sub.Failed()
}

// B is the benchmark value; a benchmark in a fuzz test's file only has to compile.
type B struct {
	common
	N int
}

func (b *B) ResetTimer()                         {}
func (b *B) StartTimer()                         {}
func (b *B) StopTimer()                          {}
func (b *B) ReportAllocs()                       {}
func (b *B) SetBytes(n int64)                    {}
func (b *B) SetParallelism(p int)                {}
func (b *B) ReportMetric(n float64, unit string) {}
func (b *B) Elapsed() time.Duration              { return 0 }
func (b *B) Loop() bool                          { return false }
func (b *B) Run(name string, f func(b *B)) bool  { return true }
func (b *B) RunParallel(body func(*PB))          {}

// PB iterates a parallel benchmark.
type PB struct{}

func (pb *PB) Next() bool { return false }

// M is a TestMain's argument; bhf never runs a TestMain.
type M struct{}

func (m *M) Run() int { return 0 }

// BenchmarkResult is what Benchmark returns.
type BenchmarkResult struct {
	N int
	T time.Duration
}

func Benchmark(f func(b *B)) BenchmarkResult { return BenchmarkResult{} }
func AllocsPerRun(runs int, f func()) float64 {
	for i := 0; i < runs; i++ {
		f()
	}
	return 0
}
func Short() bool       { return true }
func Verbose() bool     { return false }
func Testing() bool     { return true }
func CoverMode() string { return "" }
func Coverage() float64 { return 0 }
func Init()             {}

// F is the fuzz test's value: it collects the f.Add seeds, and its f.Fuzz
// runs bhf's inputs through the fuzz target.
type F struct {
	common
	seeds  [][]any
	target reflect.Value
	args   []reflect.Type
	loop   func(run func([]byte))
	ran    bool
}

func (f *F) Add(args ...any) {
	f.mu.Lock()
	f.seeds = append(f.seeds, args)
	f.mu.Unlock()
}

// Fuzz takes the fuzz target, a func(*T, ...) whose other arguments are of
// the types go test fuzzes ([]byte, string, bool, the integer types, float32
// and float64), and runs bhf's inputs through it, as go test -fuzz runs its
// own: the fuzz test's body resumes, and its deferred calls run, only after
// the last input.
func (f *F) Fuzz(ff any) {
	v := reflect.ValueOf(ff)
	ty := v.Type()
	if ty.Kind() != reflect.Func || ty.NumIn() < 1 || ty.In(0) != reflect.TypeOf((*T)(nil)) {
		f.Fatalf("f.Fuzz takes a func(*testing.T, ...), not %v", ty)
	}
	var args []reflect.Type
	for i := 1; i < ty.NumIn(); i++ {
		if !supported(ty.In(i)) {
			f.Fatalf("f.Fuzz argument %d has a type go test does not fuzz: %v", i, ty.In(i))
		}
		args = append(args, ty.In(i))
	}
	f.target, f.args = v, args
	if f.loop != nil && !f.ran {
		f.ran = true
		f.loop(f.runInput)
	}
}

func supported(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Slice:
		return t.Elem().Kind() == reflect.Uint8
	case reflect.String, reflect.Bool, reflect.Float32, reflect.Float64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	}
	return false
}

// runGuarded runs body, absorbing the panic FailNow and SkipNow stop it
// with, then the cleanups. Any other panic is left alone, never recovered
// and raised again, so it reaches the harness with the target's frames on
// top of its stack: it is a finding.
func runGuarded(c *common, body func()) {
	defer c.runCleanups()
	defer func() {
		c.mu.Lock()
		stopping := c.stopping
		c.mu.Unlock()
		if stopping {
			recover()
		}
	}()
	body()
}

// shimPackage is this package's import path, whose frames callerStack drops.
var shimPackage = reflect.TypeOf(common{}).PkgPath()

// callerStack is the goroutine's stack without this package's frames (and
// runtime/debug.Stack's), so a failure reported through *T is placed at the
// target's code that reported it.
func callerStack() []byte {
	lines := strings.Split(string(debug.Stack()), "\n")
	out := lines[:1]
	for i := 1; i+1 < len(lines); i += 2 {
		fn := lines[i]
		if strings.HasPrefix(fn, shimPackage+".") || strings.HasPrefix(fn, "runtime/debug.") {
			continue
		}
		out = append(out, fn, lines[i+1])
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

// runInput decodes one input into the fuzz target's arguments and calls it.
// A failure the target reports through its *T (t.Error, t.Fatal) is a
// finding, as it is to go test.
func (f *F) runInput(data []byte) {
	t := &T{common{name: f.name}}
	in := []reflect.Value{reflect.ValueOf(t)}
	c := &cursor{d: data}
	for i, ty := range f.args {
		in = append(in, c.decode(ty, i == len(f.args)-1))
	}
	runGuarded(&t.common, func() { f.target.Call(in) })
	if t.Failed() {
		os.Stderr.WriteString("== bhf go finding: fuzz target " + f.name + " failed: " +
			strings.TrimSpace(strings.Join(t.messages, " ")) + "\n")
		os.Stderr.Write(t.stack)
		_ = os.Stderr.Sync()
		os.Exit(86)
	}
}

// BhfMain runs the fuzz test fn in dir, the directory go test runs it in.
// Its f.Fuzz hands loop the function that runs one input. With seedDir set it
// runs no input: it writes the fuzz test's starting inputs there
// ([F.writeSeeds]) and exits. A fuzz test that fails, skips or never reaches
// f.Fuzz stops the harness with exit status 3.
func BhfMain(name string, fn func(*F), dir, corpus, seedDir string, loop func(run func([]byte))) {
	f := &F{common: common{name: name}}
	if seedDir == "" {
		f.loop = loop
	}
	if dir != "" {
		_ = os.Chdir(dir)
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(stopNow); !ok {
					setupFailed(name, fmt.Sprintf("panicked: %v", r))
				}
			}
		}()
		fn(f)
	}()
	switch {
	case f.ran:
		return
	case f.failed:
		setupFailed(name, "failed: "+strings.TrimSpace(strings.Join(f.messages, " ")))
	case f.skipped:
		setupFailed(name, "skipped itself")
	case !f.target.IsValid():
		setupFailed(name, "never called f.Fuzz")
	}
	if err := f.writeSeeds(seedDir, corpus); err != nil {
		setupFailed(name, "could not write its seeds: "+err.Error())
	}
	os.Exit(0)
}

func setupFailed(name, why string) {
	os.Stderr.WriteString("== bhf go fuzz test setup: " + name + " " + why + "\n")
	os.Exit(3)
}

// The input layout, the same as bhf's generated Go harnesses decode: a
// []byte or string takes the rest of the input when it is the last argument,
// else one length byte and that many bytes; a bool or byte one byte; every
// other integer 8 bytes and a float the 8 bytes of a float64, little-endian;
// zero when the input runs out.
type cursor struct {
	d []byte
	p int
}

func (c *cursor) u8() byte {
	if c.p < len(c.d) {
		v := c.d[c.p]
		c.p++
		return v
	}
	return 0
}

func (c *cursor) u64() uint64 {
	var v uint64
	for i := 0; i < 8 && c.p < len(c.d); i++ {
		v |= uint64(c.d[c.p]) << (8 * uint(i))
		c.p++
	}
	return v
}

func (c *cursor) bytes(last bool) []byte {
	n := len(c.d) - c.p
	if !last {
		n = int(c.u8())
		if rem := len(c.d) - c.p; n > rem {
			n = rem
		}
	}
	r := append([]byte(nil), c.d[c.p:c.p+n]...)
	c.p += n
	return r
}

func (c *cursor) decode(ty reflect.Type, last bool) reflect.Value {
	v := reflect.New(ty).Elem()
	switch ty.Kind() {
	case reflect.Slice:
		v.SetBytes(c.bytes(last))
	case reflect.String:
		v.SetString(string(c.bytes(last)))
	case reflect.Bool:
		v.SetBool(c.u8()&1 == 1)
	case reflect.Uint8:
		v.SetUint(uint64(c.u8()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(c.u64()))
	case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v.SetUint(c.u64())
	case reflect.Float32, reflect.Float64:
		v.SetFloat(math.Float64frombits(c.u64()))
	}
	return v
}

func encode(args []reflect.Type, values []any) ([]byte, bool) {
	if len(values) != len(args) {
		return nil, false
	}
	var out []byte
	put := func(v uint64) {
		for i := 0; i < 8; i++ {
			out = append(out, byte(v>>(8*uint(i))))
		}
	}
	for i, ty := range args {
		rv := reflect.ValueOf(values[i])
		if !rv.IsValid() || rv.Type() != ty && !rv.Type().ConvertibleTo(ty) {
			return nil, false
		}
		rv = rv.Convert(ty)
		last := i == len(args)-1
		switch ty.Kind() {
		case reflect.Slice, reflect.String:
			var b []byte
			if ty.Kind() == reflect.String {
				b = []byte(rv.String())
			} else {
				b = rv.Bytes()
			}
			if !last {
				if len(b) > 255 {
					b = b[:255]
				}
				out = append(out, byte(len(b)))
			}
			out = append(out, b...)
		case reflect.Bool:
			if rv.Bool() {
				out = append(out, 1)
			} else {
				out = append(out, 0)
			}
		case reflect.Uint8:
			out = append(out, byte(rv.Uint()))
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			put(uint64(rv.Int()))
		case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			put(rv.Uint())
		case reflect.Float32, reflect.Float64:
			put(math.Float64bits(rv.Float()))
		default:
			return nil, false
		}
	}
	return out, true
}

// writeSeeds writes the fuzz test's starting inputs to dir in the input
// layout: each f.Add, then each file of its seed corpus (testdata/fuzz/<Name>,
// in the `go test fuzz v1` encoding), and how many it wrote and could not
// use to dir.txt.
func (f *F) writeSeeds(dir, corpus string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	written, skipped := 0, 0
	for i, seed := range f.seeds {
		b, ok := encode(f.args, seed)
		if !ok {
			skipped++
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("add-%04d", i)), b, 0o644); err != nil {
			return err
		}
		written++
	}
	if corpus != "" {
		entries, _ := os.ReadDir(corpus)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.Type().IsRegular() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			raw, err := os.ReadFile(filepath.Join(corpus, name))
			if err != nil {
				skipped++
				continue
			}
			values, err := parseCorpusFile(raw)
			var b []byte
			ok := err == nil
			if ok {
				b, ok = encode(f.args, values)
			}
			if !ok {
				skipped++
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, "corpus-"+name), b, 0o644); err != nil {
				return err
			}
			written++
		}
	}
	return os.WriteFile(dir+".txt", []byte(fmt.Sprintf("%d %d\n", written, skipped)), 0o644)
}

// parseCorpusFile reads a seed corpus file in the encoding go test writes:
// a `go test fuzz v1` line, then one Go expression per value.
func parseCorpusFile(raw []byte) ([]any, error) {
	lines := strings.Split(string(raw), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "go test fuzz v1" {
		return nil, fmt.Errorf("not a go test fuzz v1 file")
	}
	var values []any
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		v, err := parseCorpusValue(line)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, nil
}

func parseCorpusValue(line string) (any, error) {
	expr, err := parser.ParseExpr(line)
	if err != nil {
		return nil, err
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil, fmt.Errorf("expected a call: %s", line)
	}
	arg := call.Args[0]
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		pkg, _ := sel.X.(*ast.Ident)
		lit, ok := arg.(*ast.BasicLit)
		if pkg == nil || pkg.Name != "math" || !ok || lit.Kind != token.INT {
			return nil, fmt.Errorf("unsupported value: %s", line)
		}
		bits, err := strconv.ParseUint(lit.Value, 0, 64)
		if err != nil {
			return nil, err
		}
		switch sel.Sel.Name {
		case "Float64frombits":
			return math.Float64frombits(bits), nil
		case "Float32frombits":
			return math.Float32frombits(uint32(bits)), nil
		}
		return nil, fmt.Errorf("unsupported value: %s", line)
	}
	var typ string
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		typ = fun.Name
	case *ast.ArrayType:
		if id, ok := fun.Elt.(*ast.Ident); ok && fun.Len == nil && (id.Name == "byte" || id.Name == "uint8") {
			typ = "[]byte"
		}
	}
	if id, ok := arg.(*ast.Ident); ok && typ == "bool" && (id.Name == "true" || id.Name == "false") {
		return id.Name == "true", nil
	}
	negative := false
	if u, ok := arg.(*ast.UnaryExpr); ok && u.Op == token.SUB {
		negative = true
		arg = u.X
	}
	lit, ok := arg.(*ast.BasicLit)
	if !ok {
		return nil, fmt.Errorf("unsupported value: %s", line)
	}
	text := lit.Value
	if negative {
		text = "-" + text
	}
	switch typ {
	case "[]byte", "string":
		if lit.Kind != token.STRING {
			return nil, fmt.Errorf("expected a string: %s", line)
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return nil, err
		}
		if typ == "string" {
			return s, nil
		}
		return []byte(s), nil
	case "byte", "uint8", "rune", "int32":
		if lit.Kind == token.CHAR {
			r, _, _, err := strconv.UnquoteChar(lit.Value[1:len(lit.Value)-1], '\'')
			if err != nil {
				return nil, err
			}
			if typ == "byte" || typ == "uint8" {
				return byte(r), nil
			}
			return r, nil
		}
	}
	switch typ {
	case "int", "int8", "int16", "int32", "int64", "rune":
		n, err := strconv.ParseInt(text, 0, 64)
		if err != nil {
			return nil, err
		}
		return convertInt(typ, n), nil
	case "uint", "uint8", "byte", "uint16", "uint32", "uint64", "uintptr":
		n, err := strconv.ParseUint(text, 0, 64)
		if err != nil {
			return nil, err
		}
		return convertUint(typ, n), nil
	case "float32", "float64":
		x, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, err
		}
		if typ == "float32" {
			return float32(x), nil
		}
		return x, nil
	}
	return nil, fmt.Errorf("unsupported value: %s", line)
}

func convertInt(typ string, n int64) any {
	switch typ {
	case "int8":
		return int8(n)
	case "int16":
		return int16(n)
	case "int32", "rune":
		return int32(n)
	case "int64":
		return n
	}
	return int(n)
}

func convertUint(typ string, n uint64) any {
	switch typ {
	case "uint8", "byte":
		return uint8(n)
	case "uint16":
		return uint16(n)
	case "uint32":
		return uint32(n)
	case "uint64":
		return n
	case "uintptr":
		return uintptr(n)
	}
	return uint(n)
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn func(name: &str, params: &[(&str, &str)], method: bool) -> GoFunc {
        GoFunc {
            name: name.to_owned(),
            line: 1,
            package: "p".to_owned(),
            is_exported: true,
            is_method: method,
            receiver_type: None,
            params: params
                .iter()
                .map(|(n, t)| go_parser::GoParam {
                    name: (*n).to_owned(),
                    ty: (*t).to_owned(),
                })
                .collect(),
            returns: None,
        }
    }

    fn plain(f: &GoFunc) -> Result<GoCall, String> {
        generate_call(f, None, None, false)
    }

    #[test]
    fn generates_typed_call_for_bytes() {
        let call = plain(&func("ParseRecord", &[("data", "[]byte")], false)).unwrap();
        assert!(call.body.contains("a0 := c.rest()"));
        assert!(call
            .body
            .contains("bhfMarkTargetEntry()\n\ttgt.ParseRecord(a0)"));
        assert!(call.body.contains("tgt.ParseRecord(a0)"));
        assert!(call.forced_detail.is_none(), "nothing synthesized");
    }

    #[test]
    fn typed_params_decode_by_type() {
        let call = plain(&func("Decode", &[("s", "string"), ("n", "int")], false)).unwrap();
        assert!(call.body.contains("a0 := string(c.bytesField())"));
        assert!(call.body.contains("a1 := int(c.i64())"));
        assert!(call.body.contains("tgt.Decode(a0, a1)"));
    }

    #[test]
    fn plain_map_parameter_is_json_driven() {
        let call = plain(&func("F", &[("m", "map[string]int")], false)).unwrap();
        assert!(call.body.contains("json.Unmarshal(data, &a0)"));
        assert_eq!(call.json_seed_tokens, vec![r#"{"k":1}"#]);
        assert_eq!(call.structured_seed_inputs, vec![r#"{"k":1}"#]);
    }

    #[test]
    fn raw_bytes_and_json_map_get_independent_seed_fields() {
        let call = plain(&func(
            "Render",
            &[("data", "[]byte"), ("opts", "map[string]int")],
            false,
        ))
        .unwrap();
        assert!(call.body.contains("a0 := c.bytesField()"));
        assert!(call.body.contains("json.Unmarshal(c.rest(), &a1)"));
        for seed in &call.structured_seed_inputs {
            let bytes = seed.as_bytes();
            let raw_len = bytes[0] as usize;
            let json = &bytes[1 + raw_len..];
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(json).unwrap(),
                serde_json::json!({"k": 1})
            );
        }
        assert!(call
            .structured_seed_inputs
            .iter()
            .any(|seed| seed.as_bytes()[1] == b'{'));
    }

    #[test]
    fn plain_exported_struct_is_json_driven_with_a_valid_dictionary_seed() {
        let source = r#"
package parser
type Child struct { Name string }
type Request struct {
    Magic string
    Count int
    Child *Child
    Values []int
    Labels map[string]string
}
func ParseRequest(req *Request) {}
"#;
        let types = parse_go_data_types(source).unwrap();
        let methods = parse_go_functions(source).unwrap();
        let target = methods
            .iter()
            .find(|method| method.name == "ParseRequest")
            .unwrap();
        let call = generate_call_with_data_types(target, None, None, &types, &methods, false)
            .expect("simple data structs have a safe JSON decoder");
        assert!(call.body.contains("var a0 *tgt.Request"), "{}", call.body);
        assert!(
            call.body
                .contains("json.Unmarshal(data, &a0); err != nil { return }"),
            "malformed JSON must return before calling the target: {}",
            call.body
        );
        assert!(
            call.body.find("json.Unmarshal").unwrap() < call.body.find("tgt.ParseRequest").unwrap()
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&call.json_seed_tokens[0]).unwrap(),
            serde_json::json!({
                "magic": "A", "count": 1, "child": {"name": "A"},
                "values": [1], "labels": {"k": "A"}
            })
        );
        assert!(call.forced_detail.is_none());
    }

    #[test]
    fn structured_go_examples_are_loaded_as_starting_inputs() {
        let output = tempfile::tempdir().unwrap();
        let examples = vec![r#"{"wire_code":1}"#.to_owned()];
        write_structured_seed_inputs(output.path(), &examples).unwrap();
        assert_eq!(
            load_structured_seed_inputs(output.path()).unwrap(),
            vec![br#"{"wire_code":1}"#.to_vec()]
        );
        write_structured_seed_inputs(output.path(), &[]).unwrap();
        assert!(load_structured_seed_inputs(output.path())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn data_struct_decoder_rejects_private_state_custom_json_and_unknown_handles() {
        let private_source = "package p\ntype Request struct { Name string; hidden int }\n";
        let private_types = parse_go_data_types(private_source).unwrap();
        let target = func("Parse", &[("request", "*Request")], false);
        assert!(
            generate_call_with_data_types(&target, None, None, &private_types, &[], false).is_err()
        );

        let custom_source = "package p\ntype Request struct { Name string }\nfunc (r *Request) UnmarshalJSON([]byte) error { return nil }\n";
        let custom_types = parse_go_data_types(custom_source).unwrap();
        let custom_methods = parse_go_functions(custom_source).unwrap();
        assert!(generate_call_with_data_types(
            &target,
            None,
            None,
            &custom_types,
            &custom_methods,
            false,
        )
        .is_err());

        let logger = func("Parse", &[("logger", "*zap.Logger")], false);
        assert!(generate_call_with_data_types(&logger, None, None, &[], &[], false).is_err());

        let text_source = "package p\ntype Request struct { Name string }\nfunc (r *Request) UnmarshalText([]byte) error { return nil }\n";
        let text_types = parse_go_data_types(text_source).unwrap();
        let text_methods = parse_go_functions(text_source).unwrap();
        assert!(generate_call_with_data_types(
            &target,
            None,
            None,
            &text_types,
            &text_methods,
            false,
        )
        .is_err());
    }

    #[test]
    fn data_decoder_allows_only_plain_recursively_proven_field_types() {
        let safe = parse_go_data_types(
            "package p\ntype Child struct { Name string }\ntype Request struct { Child *Child; Labels map[string][]int }\n",
        )
        .unwrap();
        assert!(is_plain_json_parameter(
            "*Request",
            &safe,
            &[],
            &mut Vec::new()
        ));

        for unsafe_type in [
            "type Request struct { Value interface{} }",
            "type Request struct { Value chan int }",
            "type Request struct { Value func() }",
            "type Request struct { Value map[int]string }",
            "type Request struct { Child }",
        ] {
            let source = format!("package p\n{unsafe_type}\n");
            let types = parse_go_data_types(&source).unwrap();
            assert!(
                !is_plain_json_parameter("Request", &types, &[], &mut Vec::new()),
                "unsafe shape unexpectedly accepted: {unsafe_type}"
            );
        }
    }

    #[test]
    fn interface_param_synthesized_as_unmarshal_target() {
        // `Unmarshal(in []byte, out interface{})` — the canonical Go parser API — is
        // now fuzzable: the interface{} out-param becomes a fresh *interface{}.
        let call = plain(&func(
            "Unmarshal",
            &[("in", "[]byte"), ("out", "interface{}")],
            false,
        ))
        .unwrap();
        assert!(call.body.contains("a0 := c.bytesField()"));
        assert!(call.body.contains("a1 := new(interface{})"));
        assert!(call.body.contains("tgt.Unmarshal(a0, a1)"));
        // `any` (the Go 1.18 alias) works too.
        let anycall = plain(&func("Decode", &[("data", "[]byte"), ("v", "any")], false)).unwrap();
        assert!(anycall.body.contains("a1 := new(interface{})"));
    }

    #[test]
    fn forced_undrivable_param_becomes_its_zero_value() {
        // The largest residual Go blocker: a parameter no decoder covers. Unforced it
        // is still a clean skip (asserted above); forced it is the type's zero value,
        // qualified into the harness package.
        let target = func(
            "Render",
            &[("data", "[]byte"), ("opts", "map[string]Option")],
            false,
        );
        let call = generate_call(&target, None, None, true).unwrap();
        assert!(
            call.body.contains("var z1 map[string]tgt.Option"),
            "{}",
            call.body
        );
        assert!(call.body.contains("a1 := z1"), "{}", call.body);
        assert!(call.body.contains("tgt.Render(a0, a1)"), "{}", call.body);
        let detail = call.forced_detail.expect("forced params are recorded");
        assert!(detail.contains("opts"), "{detail}");
    }

    #[test]
    fn forced_method_is_called_on_an_addressable_zero_receiver() {
        // 23 of the residual Go targets are methods. A nil `*T` would panic the moment
        // the method touched a field — our fault — so the receiver is a zero VALUE
        // whose address satisfies both a pointer and a value receiver.
        let mut method = func("Feed", &[("data", "[]byte")], true);
        method.receiver_type = Some("*Decoder".to_owned());
        assert!(
            receiver_synthesis(&method, &[], false).is_err(),
            "with no constructor to find, unforced is still a clean skip"
        );
        let receiver = receiver_synthesis(&method, &[], true).unwrap().unwrap();
        let call = generate_call(&method, Some(&receiver), None, true).unwrap();
        assert!(call.body.contains("var recv tgt.Decoder"), "{}", call.body);
        assert!(call.body.contains("(&recv).Feed(a0)"), "{}", call.body);
        assert!(
            call.forced_detail.is_some(),
            "receiver is recorded as forced"
        );
    }

    /// A sibling `func NewT() *T` is what a human would call, and the value is
    /// REAL — so the target needs no `--force` and its findings are not floored.
    /// `GoFunc` carried no result type until now, so a constructor could not be
    /// told from any other no-arg function and every method target demanded force.
    #[test]
    fn a_sibling_constructor_gives_a_real_receiver_without_force() {
        let mut method = func("Feed", &[("data", "[]byte")], true);
        method.receiver_type = Some("*Decoder".to_owned());

        let mut ctor = func("NewDecoder", &[], false);
        ctor.returns = Some("*Decoder".to_owned());
        let receiver = receiver_synthesis(&method, std::slice::from_ref(&ctor), false)
            .expect("a constructor makes this drivable unforced")
            .expect("a method has a receiver");
        assert!(receiver.forced.is_none(), "a real value is not forced");
        let call = generate_call(&method, Some(&receiver), None, false).unwrap();
        assert!(
            call.body.contains("recv := tgt.NewDecoder()"),
            "{}",
            call.body
        );
        // Already a pointer: no extra address-of.
        assert!(call.body.contains("recv.Feed(a0)"), "{}", call.body);
        assert!(call.forced_detail.is_none(), "{:?}", call.forced_detail);

        // A VALUE-returning constructor needs its address so a pointer-receiver
        // method is still callable.
        let mut by_value = func("NewDecoder", &[], false);
        by_value.returns = Some("Decoder".to_owned());
        let receiver = receiver_synthesis(&method, std::slice::from_ref(&by_value), false)
            .unwrap()
            .unwrap();
        let call = generate_call(&method, Some(&receiver), None, false).unwrap();
        assert!(call.body.contains("(&recv).Feed(a0)"), "{}", call.body);

        // Only the `New…` convention counts, and only for the right type: an
        // arbitrary no-arg function returning it may touch the world.
        let mut opener = func("OpenDecoder", &[], false);
        opener.returns = Some("*Decoder".to_owned());
        let mut wrong_type = func("NewEncoder", &[], false);
        wrong_type.returns = Some("*Encoder".to_owned());
        for sibling in [opener, wrong_type] {
            assert!(
                receiver_synthesis(&method, std::slice::from_ref(&sibling), false).is_err(),
                "must not be treated as a constructor for Decoder"
            );
        }
    }

    #[test]
    fn stateful_argument_feeder_initializes_receiver_before_terminal_call() {
        let mut execute = func("Execute", &[], true);
        execute.receiver_type = Some("*Command".to_owned());
        let mut set_args = func("SetArgs", &[("args", "[]string")], true);
        set_args.receiver_type = Some("*Command".to_owned());
        let siblings = vec![set_args.clone(), execute.clone()];

        let receiver = receiver_synthesis(&execute, &siblings, false)
            .expect("public state feeder makes the receiver constructible")
            .expect("method receiver");
        assert!(receiver.forced.is_none());
        let call = generate_call(&execute, Some(&receiver), Some(&set_args), false).unwrap();
        assert!(call.body.contains("var recv tgt.Command"), "{}", call.body);
        assert!(
            call.body.contains("stateInput := c.args()"),
            "{}",
            call.body
        );
        assert!(
            call.body.contains("(&recv).SetArgs(stateInput)"),
            "{}",
            call.body
        );
        assert!(call
            .body
            .contains("bhfMarkTargetEntry()\n\t(&recv).Execute()"));
        assert!(call.forced_detail.is_none());
    }

    #[test]
    fn forced_receiver_refuses_what_the_harness_cannot_name() {
        for receiver_type in ["*decoder", "Tree[T]", "other.Decoder", ""] {
            let mut method = func("Feed", &[("data", "[]byte")], true);
            method.receiver_type = Some(receiver_type.to_owned());
            assert!(
                receiver_synthesis(&method, &[], true).is_err(),
                "`{receiver_type}` is not nameable from the harness package"
            );
        }
    }

    #[test]
    fn harness_visible_type_qualifies_only_what_it_can_reach() {
        assert_eq!(
            harness_visible_go_type("[]Record").as_deref(),
            Some("[]tgt.Record")
        );
        assert_eq!(
            harness_visible_go_type("map[string]int").as_deref(),
            Some("map[string]int")
        );
        assert_eq!(
            harness_visible_go_type("*Node").as_deref(),
            Some("*tgt.Node")
        );
        assert_eq!(
            harness_visible_go_type("io.Writer").as_deref(),
            Some("io.Writer")
        );
        assert_eq!(
            harness_visible_go_type("chan int").as_deref(),
            Some("chan int")
        );
        for unreachable in [
            "config",          // unexported: inaccessible from any other package
            "[]config",        // ... including inside a composite
            "net.Conn",        // a package the harness does not import
            "Tree[string]",    // generic instantiation
            "...string",       // variadic
            "struct{a int}",   // inline literal: `a` is a field, not a type
            "func(r int) int", // inline literal: `r` is a parameter, not a type
            "interface{ Read() }",
        ] {
            assert_eq!(harness_visible_go_type(unreachable), None, "{unreachable}");
        }
    }

    #[test]
    fn import_path_computation() {
        let root = Path::new("/proj");
        let f = Path::new("/proj/internal/parser/p.go");
        assert_eq!(
            compute_import_path("github.com/x/proj", root, f),
            "github.com/x/proj/internal/parser"
        );
        let rootf = Path::new("/proj/p.go");
        assert_eq!(
            compute_import_path("github.com/x/proj", root, rootf),
            "github.com/x/proj"
        );
    }

    #[test]
    fn coverage_falls_back_from_module_graph_to_exact_target_package() {
        assert_eq!(
            coverage_package_patterns(
                "github.com/example/project",
                "github.com/example/project/internal/parser"
            ),
            vec![
                "github.com/example/project/...,github.com/example/project/bhfharness".to_owned(),
                "github.com/example/project/internal/parser,github.com/example/project/bhfharness"
                    .to_owned(),
            ]
        );
        assert_eq!(
            coverage_package_patterns("github.com/example/project", "github.com/example/project"),
            vec![
                "github.com/example/project/...,github.com/example/project/bhfharness".to_owned(),
                "github.com/example/project,github.com/example/project/bhfharness".to_owned(),
            ]
        );
    }

    #[test]
    fn parse_go_minor_extracts_major_minor() {
        assert_eq!(parse_go_minor("go1.22.2").as_deref(), Some("1.22"));
        assert_eq!(parse_go_minor("go1.24\n").as_deref(), Some("1.24"));
        assert_eq!(parse_go_minor("  go1.21  ").as_deref(), Some("1.21"));
        // Toolchains with a pre-release minor keep the numeric prefix.
        assert_eq!(parse_go_minor("go1.25rc1").as_deref(), Some("1.25"));
        assert_eq!(parse_go_minor("devel go1.99"), None);
        assert_eq!(parse_go_minor(""), None);
    }

    #[test]
    fn lower_go_mod_directive_lowers_go_and_drops_toolchain() {
        // A module declaring a too-new directive (+ a toolchain pin) is rewritten
        // to the local version so the build isn't gated; everything else is kept.
        let src = "module github.com/x/y\n\ngo 1.24\n\ntoolchain go1.24.0\n\nrequire github.com/z/w v1.2.3\n";
        let out = lower_go_mod_directive(src, "1.22");
        assert!(out.contains("go 1.22\n"), "go directive lowered: {out}");
        assert!(
            !out.contains("1.24"),
            "no 1.24 directive/toolchain remains: {out}"
        );
        assert!(!out.contains("toolchain "), "toolchain pin dropped: {out}");
        assert!(out.contains("module github.com/x/y"), "module line kept");
        assert!(
            out.contains("require github.com/z/w v1.2.3"),
            "require kept"
        );
    }

    #[test]
    fn lower_go_mod_directive_leaves_non_version_go_lines() {
        // `go` appearing as a require path segment or comment must not be touched;
        // only a `go <digit>` directive is rewritten.
        let src = "module m\ngo 1.23\nrequire golang.org/x/text v0.3.0\n";
        let out = lower_go_mod_directive(src, "1.22");
        assert!(out.contains("go 1.22\n"));
        assert!(out.contains("require golang.org/x/text v0.3.0"));
    }

    #[test]
    fn main_go_carries_framed_marker() {
        let m = generate_main_go("x/y", "\ttgt.F()\n");
        assert!(m.contains("BHF_FRAMED"));
        assert!(m.contains("tgt \"x/y\""));
    }

    #[test]
    fn main_go_carries_real_edge_coverage() {
        // The Go lane is no longer black-box: the harness reads Go's -cover atomic
        // counters and folds executed blocks into the shared BHF_COV_SHM map,
        // clearing+recording around each framed input.
        let m = generate_main_go("x/y", "\ttgt.F()\n");
        assert!(m.contains("runtime/coverage"), "imports runtime/coverage");
        assert!(m.contains("BHF_COV_SHM"), "maps the shared edge map");
        assert!(m.contains("WriteCounters"), "reads per-input counters");
        // The framed loop hooks coverage around runOne: clear before, record after.
        // Match the call SEQUENCE directly (whitespace-normalized) so the function
        // DEFINITIONS earlier in the file can't satisfy an index-ordering check.
        let calls: String = m.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            calls.contains("bhfCovClear() runOne(buf) bhfCovRecord()"),
            "framed loop must clear -> runOne -> record in order"
        );
    }

    /// `context.Context` is call context, not fuzz input, and refusing it made
    /// the whole target undrivable — it was among the most common undrivable Go
    /// parameter types in the 500-project sweep. It must never be nil: a nil
    /// context panics the moment the callee touches Done()/Err(), and that panic
    /// would be bhf's fault rather than a finding.
    #[test]
    fn a_context_parameter_is_the_background_context_not_a_refusal() {
        assert_eq!(
            decode_for_type("context.Context", false).as_deref(),
            Some("c.ctx()")
        );
        assert_eq!(
            decode_for_type("context.Context", true).as_deref(),
            Some("c.ctx()")
        );
        // The helper it calls exists, returns the non-nil background context,
        // and keeps the import referenced so an unrelated harness still compiles.
        let main_go = generate_main_go("x/y", "\ttgt.F()\n");
        assert!(
            main_go.contains("func (c *cur) ctx() context.Context"),
            "{main_go}"
        );
        assert!(main_go.contains("context.Background()"), "{main_go}");
        assert!(
            main_go.contains("\"context\""),
            "the import must be present: {main_go}"
        );
    }

    /// Go decides "outside the internal tree" from the import path, so a harness
    /// module named `bhfharness` is outside every project and could never
    /// reach a target under an `internal/` — which is where a great deal of real
    /// Go code lives. Declaring it a child of the module under test satisfies the
    /// rule the same way the project's own packages do.
    #[test]
    fn the_harness_module_is_a_child_of_the_module_under_test() {
        assert_eq!(
            harness_module_path("github.com/santifer/career-ops/dashboard"),
            "github.com/santifer/career-ops/dashboard/bhfharness"
        );
        // A major-version suffix is part of the path and stays put.
        assert_eq!(
            harness_module_path("github.com/caddyserver/caddy/v2"),
            "github.com/caddyserver/caddy/v2/bhfharness"
        );
        // A trailing slash or an empty module path must still yield a legal name.
        assert_eq!(
            harness_module_path("example.com/x/"),
            "example.com/x/bhfharness"
        );
        assert_eq!(harness_module_path(""), "bhfharness");
    }

    /// Semantic import versioning: a `/vN` module path may only be required at a
    /// version starting `vN`. The hardcoded `v0.0.0-incompatible` made the
    /// harness `go.mod` fail to PARSE, which failed every target in the project —
    /// 51 of them across 9 of the 500-project sweep's 40 Go repos.
    #[test]
    fn a_major_version_suffixed_module_is_required_at_that_major() {
        assert_eq!(
            placeholder_module_version("github.com/caddyserver/caddy/v2"),
            "v2.0.0"
        );
        assert_eq!(
            placeholder_module_version("go.etcd.io/etcd/server/v3"),
            "v3.0.0"
        );
        assert_eq!(placeholder_module_version("example.com/x/v10"), "v10.0.0");
        // No suffix, `/v1`, and a path whose last segment merely STARTS with `v`
        // keep the v0 spelling — Go wants exactly that for an unsuffixed module,
        // and `v2beta`/`vendor` are not major-version suffixes.
        for path in [
            "github.com/mhsanaei/3x-ui",
            "example.com/x/v1",
            "example.com/x/v2beta",
            "example.com/x/vendor",
            "singleword",
        ] {
            assert_eq!(
                placeholder_module_version(path),
                "v0.0.0-incompatible",
                "{path}"
            );
        }
    }

    /// A copied `package main` is renamed, with its `main`, and keeps every
    /// line where it was: the `//line` directive maps line 1 of the copy's
    /// second line to line 1 of the original.
    #[test]
    fn a_copied_main_package_is_renamed_and_keeps_its_line_numbers() {
        let source = "// Command tool.\n\
                      /*\n\
                      package main is what this is\n\
                      */\n\
                      package main // the tool\n\
                      \n\
                      func Parse(s string) int { return len(s) }\n\
                      \n\
                      func main() {\n\
                      \tfunc main() {}\n\
                      }\n\
                      \n\
                      func mainly() {}\n";
        let copied = loose_go_source(Path::new("/src/tool/tool.go"), source, true);
        let (directive, body) = copied.split_once('\n').unwrap();
        assert_eq!(directive, "//line /src/tool/tool.go:1");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), source.lines().count());
        assert_eq!(lines[2], "package main is what this is");
        assert_eq!(lines[4], "package bhftarget // the tool");
        assert_eq!(lines[8], "func bhfProgramMain() {");
        assert_eq!(lines[9], "\tfunc main() {}");
        assert_eq!(lines[12], "func mainly() {}");

        // Any other package is copied as it is, under the directive.
        let library = "package parser\n\nfunc main() {}\n";
        assert_eq!(
            loose_go_source(Path::new("/src/p.go"), library, false),
            format!("//line /src/p.go:1\n{library}")
        );
        // `package mainframe` is not `package main`.
        assert_eq!(renamed_package_clause("package mainframe\n"), None);
    }

    #[test]
    fn a_package_dir_name_becomes_a_module_path_element() {
        for (dir, element) in [
            ("/r/zh-tw", "zh-tw"),
            ("/r/my tool", "my-tool"),
            ("/r/v1.2", "v1-2"),
            ("/r/日本", "pkg"),
        ] {
            assert_eq!(module_path_element(Path::new(dir)), element, "{dir}");
        }
    }

    /// A package outside every module is copied with a `go.mod` of its own;
    /// its tests are left behind and the scanned tree is not written to.
    #[test]
    fn a_loose_package_is_copied_into_a_module_of_its_own() {
        let root = tempfile::tempdir().unwrap();
        let package_dir = root.path().join("legacy tool");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(
            package_dir.join("tool.go"),
            "package main\n\nfunc main() {}\n",
        )
        .unwrap();
        std::fs::write(package_dir.join("tool_test.go"), "package main\n").unwrap();
        std::fs::write(package_dir.join("words.txt"), "embedded\n").unwrap();
        let auto_dir = root.path().join("harness");
        std::fs::create_dir_all(&auto_dir).unwrap();

        let (mod_root, module_path) =
            loose_package_module(&package_dir.join("tool.go"), &auto_dir, "main").unwrap();
        assert_eq!(mod_root, auto_dir.join(LOOSE_PACKAGE_DIR));
        assert_eq!(module_path, "bhf.local/legacy-tool");
        assert_eq!(
            std::fs::read_to_string(mod_root.join("go.mod")).unwrap(),
            "module bhf.local/legacy-tool\n\ngo 1.21\n"
        );
        let copied = std::fs::read_to_string(mod_root.join("tool.go")).unwrap();
        assert!(copied.contains("package bhftarget\n"), "{copied}");
        assert!(copied.contains("func bhfProgramMain() {}"), "{copied}");
        assert!(mod_root.join("words.txt").is_file());
        assert!(!mod_root.join("tool_test.go").exists());
        let mut left: Vec<_> = std::fs::read_dir(&package_dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["tool.go", "tool_test.go", "words.txt"]);
    }

    /// Two files that each declare `main` are two `go run` programs: the
    /// copy holds only the target's.
    #[test]
    fn a_dir_of_standalone_programs_copies_only_the_targets_file() {
        let root = tempfile::tempdir().unwrap();
        let scripts = root.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        for name in ["build.go", "build_new.go"] {
            std::fs::write(
                scripts.join(name),
                "package main\n\nfunc FixHeader(s string) string { return s }\n\nfunc main() {}\n",
            )
            .unwrap();
        }
        std::fs::write(scripts.join("notes.md"), "notes\n").unwrap();
        let auto_dir = root.path().join("harness");
        std::fs::create_dir_all(&auto_dir).unwrap();
        let (mod_root, _) =
            loose_package_module(&scripts.join("build_new.go"), &auto_dir, "main").unwrap();
        let mut copied: Vec<_> = std::fs::read_dir(&mod_root)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        copied.sort();
        assert_eq!(copied, ["build_new.go", "go.mod", "notes.md"]);
    }

    #[test]
    fn a_fuzz_tests_package_is_copied_with_what_it_imports_from_its_module() {
        let root = tempfile::tempdir().unwrap();
        let module = root.path().join("widget");
        let write = |relative: &str, text: &str| {
            let path = module.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("go.mod", "module example.com/widget\n\ngo 1.21\n");
        write("go.sum", "");
        write(
            "parser/parse.go",
            "package parser\n\nimport (\n\t\"embed\"\n\t\"example.com/widget/codec\"\n)\n\n\
             //go:embed tables\nvar tables embed.FS\n\nfunc parse(b []byte) int { return codec.Len(b) }\n",
        );
        write("parser/parse_test.go", "package parser\n");
        write("parser/tables/kinds.txt", "kinds\n");
        write("parser/testdata/fuzz/FuzzParse/seed", "go test fuzz v1\n");
        write("parser/asm_amd64.s", "// assembly\n");
        write(
            "codec/codec.go",
            "package codec\n\nfunc Len(b []byte) int { return len(b) }\n",
        );
        // Not imported by the fuzz test's package: not copied.
        write("unrelated/unrelated.go", "package unrelated\n");
        // Imported only by the fuzz test's file.
        write("helpers/helpers.go", "package helpers\n");
        let dest = root.path().join("copy");
        let work = root.path().join("work");
        stage_module_closure(
            &module,
            "example.com/widget",
            &module.join("parser"),
            &["example.com/widget/helpers".to_owned(), "os".to_owned()],
            false,
            &dest,
            &work,
        )
        .unwrap();
        let mut copied = Vec::new();
        let mut stack = vec![dest.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    copied.push(
                        path.strip_prefix(&dest)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        copied.sort();
        assert_eq!(
            copied,
            [
                "codec/codec.go",
                "go.mod",
                "go.sum",
                "helpers/helpers.go",
                "parser/asm_amd64.s",
                "parser/parse.go",
                "parser/tables/kinds.txt",
            ]
        );
        // Each copied Go file names its original, line for line.
        let parse = std::fs::read_to_string(dest.join("parser/parse.go")).unwrap();
        assert!(parse.starts_with(&format!(
            "//line {}:1\npackage parser\n",
            module.join("parser/parse.go").display()
        )));
    }

    #[test]
    fn an_external_fuzz_tests_package_clause_is_renamed_line_for_line() {
        let copied = external_test_source(
            Path::new("/src/codec/codec_test.go"),
            "// Package codec_test is the external test.\npackage codec_test\n\nimport \"testing\"\n",
            "codec_test",
        );
        assert_eq!(
            copied,
            "//line /src/codec/codec_test.go:1\n// Package codec_test is the external test.\n\
             package bhffuzz\n\nimport \"testing\"\n"
        );
        assert_eq!(
            fuzz_test_copy_name(Path::new("/src/codec/codec_test.go")),
            "bhf_fuzztest_codec.go"
        );
    }

    #[test]
    fn embed_patterns_name_the_directories_to_copy() {
        let dirs = embed_dirs(
            "//go:embed tables/*.txt static\n//go:embed \"all:assets\" *.json .hidden testdata/x\n",
        );
        assert_eq!(dirs, ["tables", "static", "assets"]);
    }

    #[test]
    fn the_fuzz_test_main_runs_the_fuzz_test_through_the_testing_stand_in() {
        let main = generate_fuzz_test_main_go(
            "example.com/widget/parser",
            "example.com/widget/bhfharness/bhftesting",
            "FuzzParse",
            Path::new("/src/parser"),
            Path::new("/src/parser/testdata/fuzz/FuzzParse"),
        );
        assert!(main.contains("\ttesting \"example.com/widget/bhfharness/bhftesting\"\n"));
        assert!(main.contains("\ttgt \"example.com/widget/parser\"\n"));
        assert!(main.contains(
            "testing.BhfMain(\"FuzzParse\", tgt.FuzzParse, \"/src/parser\", \
             \"/src/parser/testdata/fuzz/FuzzParse\", os.Getenv(\"BHF_GO_FUZZ_SEEDS\"), loop)"
        ));
        // The same coverage and target-entry runtime as every Go harness.
        assert!(main.contains(GO_COVERAGE_RUNTIME));
        assert!(main.contains(GO_TARGET_ENTRY_RUNTIME));
        assert!(main.contains("bhfMarkTargetEntry()\n\trun(data)"));
        // The stand-in is the package `testing`, and names its own entry point
        // apart from the real package's.
        assert!(GO_TESTING_SHIM.contains("\npackage testing\n"));
        assert!(GO_TESTING_SHIM.contains("func BhfMain("));
    }
}
