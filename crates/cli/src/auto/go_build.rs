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
//! target outside a module, a method (needs a receiver), or an unsupported
//! parameter type skips cleanly (the GNAT-less rule).

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

    // Locate the enclosing Go module (go.mod) so the harness can import the target
    // package by its module import path.
    let target_abs = candidate
        .source_path
        .canonicalize()
        .unwrap_or_else(|_| candidate.source_path.clone());
    let Some((mod_root, module_path)) = find_go_module(&target_abs) else {
        return GoBuildResult::Failed {
            reason: "target is not inside a Go module (no go.mod found); only \
                     module-based Go targets are supported (skipped cleanly)"
                .to_owned(),
            skip: true,
        };
    };
    let import_path = compute_import_path(&module_path, &mod_root, &target_abs);

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

    let main_go = generate_main_go(&import_path, &body);
    if let Err(e) = std::fs::write(auto_dir.join("bhf_harness.go"), &main_go) {
        return GoBuildResult::Failed {
            reason: format!("write harness: {e}"),
            skip: false,
        };
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
        root = mod_root.display(),
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
    let bin = auto_dir.join("main");
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
    let mut out = String::new();
    for byte in token {
        match *byte {
            b'\\' => out.push_str("\\\\"),
            b'\"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b' '..=b'~' => out.push(*byte as char),
            other => out.push_str(&format!("\\x{other:02x}")),
        }
    }
    out
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

// --- bhf real edge coverage (Go -cover atomic counters -> shared edge map) ---
// The builtin engine reads BHF_COV_SHM as a cumulative 64KB AFL edge bitmap.
// Per input we clear Go's coverage counters, run the target, then fold the SET of
// executed blocks (counter != 0 — the count VALUE is ignored, so a loop's trip
// count is never false novelty) into the map. Parsing Go's internal covcounters
// format is version-guarded: any mismatch folds nothing (black-box fallback), so a
// future format change degrades gracefully rather than emitting a wrong signal.
const bhfCovBits = 1 << 16

var bhfCovMap []byte
var bhfCovBuf bytes.Buffer

func bhfCovInit() {{
	path := os.Getenv("BHF_COV_SHM")
	if path == "" {{
		return
	}}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o600)
	if err != nil {{
		return
	}}
	_ = syscall.Ftruncate(fd, bhfCovBits)
	m, err := syscall.Mmap(fd, 0, bhfCovBits, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	_ = syscall.Close(fd)
	if err == nil {{
		bhfCovMap = m
	}}
	_ = coverage.ClearCounters()
}}

func bhfCovClear() {{
	if bhfCovMap != nil {{
		_ = coverage.ClearCounters()
	}}
}}

func bhfCovRecord() {{
	if bhfCovMap == nil {{
		return
	}}
	bhfCovBuf.Reset()
	if coverage.WriteCounters(&bhfCovBuf) != nil {{
		_ = coverage.ClearCounters()
		return
	}}
	b := bhfCovBuf.Bytes()
	_ = coverage.ClearCounters()
	if len(b) < 32 || b[1] != 'c' || b[2] != 'w' || b[3] != 'm' {{
		return
	}}
	flavor := b[24]
	p := 32 // magic[4] version[4] metaHash[16] flavor[1] bigEndian[1] pad[6]
	le := func(n int) uint64 {{
		var v uint64
		for i := 0; i < n; i++ {{
			v |= uint64(b[p+i]) << (8 * uint(i))
		}}
		p += n
		return v
	}}
	uleb := func() (uint64, bool) {{
		var v uint64
		var s uint
		for {{
			if p >= len(b) {{
				return 0, false
			}}
			c := b[p]
			p++
			v |= uint64(c&0x7f) << s
			if c&0x80 == 0 {{
				break
			}}
			s += 7
		}}
		return v, true
	}}
	rd := func() (uint64, bool) {{
		if flavor == 1 {{ // CtrRaw: fixed uint32
			if p+4 > len(b) {{
				return 0, false
			}}
			return le(4), true
		}}
		return uleb() // CtrULeb128
	}}
	if p+16 > len(b) {{
		return
	}}
	fcn := le(8)
	strtab := le(4)
	args := le(4)
	p += int(strtab) + int(args)
	if p > len(b) {{
		return
	}}
	for f := uint64(0); f < fcn; f++ {{
		nc, ok := rd()
		if !ok {{
			return
		}}
		pkg, ok2 := rd()
		if !ok2 {{
			return
		}}
		fnc, ok3 := rd()
		if !ok3 {{
			return
		}}
		for c := uint64(0); c < nc; c++ {{
			v, ok4 := rd()
			if !ok4 {{
				return
			}}
			if v != 0 {{
				idx := ((uint32(pkg) * 2654435761) ^ (uint32(fnc) * 40503) ^ uint32(c)) & (bhfCovBits - 1)
				if bhfCovMap[idx] != 0xff {{
					bhfCovMap[idx]++
				}}
			}}
		}}
	}}
}}

type cur struct {{
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

var bhfTargetEntered bool

func bhfMarkTargetEntry() {{
	if bhfTargetEntered {{
		return
	}}
	path := os.Getenv("BHF_TARGET_ENTRY_SHM")
	if path == "" {{
		return
	}}
	if os.WriteFile(path, []byte{{1}}, 0o600) == nil {{
		bhfTargetEntered = true
	}}
}}

func runOne(data []byte) {{
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
	// Save the control pipe (fd 1), then redirect fd 1 + os.Stdout to /dev/null so
	// the target's prints can't corrupt the sync stream (#427).
	ctlFd, _ := syscall.Dup(1)
	control := os.NewFile(uintptr(ctlFd), "ctl")
	if dn, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {{
		_ = syscall.Dup2(int(dn.Fd()), 1)
		os.Stdout = dn
	}}
	in := os.NewFile(0, "in")
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
    )
}

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
}
