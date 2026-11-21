// SPDX-License-Identifier: Apache-2.0

//! JavaScript / Node.js harness build (M3.7) — see [`crate::auto::js`] for strategy.
//!
//! Step 0 of the attempt loop for a `Lang::Js` candidate: resolve the target
//! module, syntax-check it with `node -c`, copy the bundled framed driver next to
//! the harness, and emit a launcher `main` that execs
//! `node js_runtime/bhf_driver.js` with the target module + export path + arg
//! kind in the environment. The engine sets `BHF_FRAMED` + `BHF_COV_SHM`
//! across the exec and drives the warm Node process over the framed fork-server
//! protocol — same path as Python/Perl. Interpreted: there is no native binary.

use crate::auto::candidate::Candidate;
use crate::auto::js::{parse_js, JsFunction};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// A `--version`-style toolchain probe should answer instantly; this only exists
/// so a wedged or half-installed toolchain cannot hang the whole run.
const TOOL_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The browser globals the JS driver stands in for when a target needs them
/// (#288); `js_runtime/bhf_driver.js` keeps the same list.
const BROWSER_GLOBALS: &[&str] = &[
    "window",
    "self",
    "document",
    "navigator",
    "location",
    "localStorage",
    "sessionStorage",
    "history",
    "screen",
    "customElements",
    "HTMLElement",
    "Element",
    "Node",
];

/// The browser global a Node error says is missing
/// (`ReferenceError: window is not defined`), if `stderr` holds one.
fn missing_browser_global(stderr: &str) -> Option<&'static str> {
    stderr.lines().find_map(|line| {
        let name = line
            .trim()
            .strip_prefix("ReferenceError: ")?
            .strip_suffix(" is not defined")?;
        let class = (name.starts_with("HTML") || name.starts_with("SVG"))
            && name.ends_with("Element")
            || name.ends_with("Observer");
        (BROWSER_GLOBALS.contains(&name) || class).then(|| {
            BROWSER_GLOBALS
                .iter()
                .copied()
                .find(|known| *known == name)
                .unwrap_or("a browser class")
        })
    })
}

/// The file beside a JS harness's launcher where its driver records the
/// browser globals it stood in for (#288), comma-separated; absent when the
/// target needed none.
pub(crate) const BROWSER_GLOBALS_RECORD: &str = "browser-globals.txt";

pub enum JsBuildResult {
    Built,
    /// Not fuzzable here (target no longer present, will not transpile or
    /// load) — skip cleanly.
    Skip(String),
    /// The lane's toolchain (`node`, or esbuild for TypeScript) is not
    /// installed: nothing about the target could be tried.
    MissingToolchain(String),
    /// A genuine failure (missing runtime, unwritable work dir).
    Failed(String),
    /// Built, but every input the build's probe ran stopped at the same
    /// undefined global, from the same frame: the target's environment, not a
    /// finding. Carries why, naming the global.
    NotEntered(String),
}

fn have_node() -> bool {
    let mut command = Command::new("node");
    command.arg("--version");
    crate::command_output::output_with_timeout(&mut command, TOOL_PROBE_TIMEOUT)
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Locate the bundled `js_runtime/bhf_driver.js`, relative to the source tree
/// (dev) or the installed binary (release) — mirrors `locate_python_runtime`.
fn locate_js_runtime() -> Option<PathBuf> {
    crate::runtime_assets::locate("js_runtime", "bhf_driver.js")
}

/// Re-parse the source and find the discovered function by (name, line).
fn resolve_target(candidate: &Candidate) -> Result<JsFunction, String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let fns = parse_js(&source);
    fns.iter()
        .find(|f| f.name == candidate.name && f.line == candidate.line)
        .or_else(|| fns.iter().find(|f| f.name == candidate.name))
        .cloned()
        .ok_or_else(|| format!("JS target `{}` no longer present in source", candidate.name))
}

/// The single public entry point of the lane. `starting_inputs`: the run's
/// seed inputs (`--seed-file`/`--seed-dir`, or the seeds mined from the
/// tree), which build gate 4 also runs.
pub fn build_js_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    starting_inputs: &[Vec<u8>],
) -> JsBuildResult {
    if !have_node() {
        return JsBuildResult::MissingToolchain(
            "no `node` runtime found; install Node.js to fuzz JavaScript (the lane \
             skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
        );
    }
    let Some(runtime) = locate_js_runtime() else {
        return JsBuildResult::Failed(
            "could not locate the bundled js_runtime/bhf_driver.js".to_owned(),
        );
    };
    let func = match resolve_target(candidate) {
        Ok(f) => f,
        Err(reason) => return JsBuildResult::Skip(reason),
    };

    // Without Windows' verbatim `\\?\` prefix: a capsule relocates the
    // launcher's paths onto its copy, and `\\?\` with the `/` that brings
    // names no file.
    let module_abs = crate::workdir::plain_canonical(&candidate.source_path);
    let load_cwd = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(error) = std::fs::create_dir_all(&load_cwd) {
        return JsBuildResult::Failed(format!("create {}: {error}", load_cwd.display()));
    }

    // Syntax + load smoke-test: the module must parse AND `require` at runtime.
    // `node -c` only checks syntax; a module whose `require('...')` cannot resolve
    // (an npm dependency not installed — `side-channel`, etc.) parses fine but dies
    // at startup, which would silently fuzz 0 inputs. Skip it cleanly with the
    // reason (mirrors the Python lane's import check).
    if let Some(reason) = js_module_load_error(&module_abs, &load_cwd) {
        return JsBuildResult::Skip(reason);
    }

    emit_js_harness(
        work_dir,
        harness_id,
        &runtime,
        &module_abs,
        &func,
        false,
        starting_inputs,
    )
}

/// `None` if the module parses and `require`s cleanly, else a skip reason. Catches
/// both syntax errors and unresolved runtime `require`s (missing npm dependencies).
fn js_module_load_error(module_abs: &Path, load_cwd: &Path) -> Option<String> {
    // `node -c` first (cheap, no side effects) for a precise syntax message.
    let mut syntax_check = Command::new("node");
    syntax_check.arg("-c").arg(module_abs).current_dir(load_cwd);
    // A syntax check reads USER JavaScript, so it gets a real budget rather than
    // the probe timeout — but a budget all the same.
    if let Ok(out) = crate::command_output::output_with_timeout(
        &mut syntax_check,
        std::time::Duration::from_secs(120),
    ) {
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            return Some(format!(
                "`node -c` rejected {}: {}",
                module_abs.display(),
                msg.lines().next().unwrap_or("").trim()
            ));
        }
    }
    // Then require it in a throwaway process to confirm the dependency graph resolves.
    let out = crate::command_output::output_with_timeout(
        Command::new("node")
            .arg("-e")
            .arg("require(process.argv[1])")
            .arg(module_abs)
            .current_dir(load_cwd),
        Duration::from_secs(30),
    )
    .ok()?;
    if out.status.success() {
        return None;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // #288: a browser module that needs `window` as it loads is the driver's
    // to stand in for; its load-only gate (build gate 3) decides.
    if missing_browser_global(&stderr).is_some() {
        return None;
    }
    // Shared wording so the uninstalled npm package is recorded as a named
    // requirement: the prose form said `npm install` but carried no marker, so
    // the run reported "no dependencies were missing" for a tree where every
    // target skipped on one.
    Some(crate::auto::script_load_roots::unloadable_reason(
        &module_abs.display().to_string(),
        &stderr,
    ))
}

/// Copy the driver and emit the `node` launcher pointing at `module_abs` (the target
/// module for JS, or the transpiled `.js` for TS). Shared by both lanes.
/// `source_maps`: run node with `--enable-source-maps`, so the stacks of a
/// module transpiled with a source map (the TypeScript lane's `target.js`)
/// name the original source's file and line. Off for plain JavaScript, whose
/// frames already name its own files. `starting_inputs`: the run's seed
/// inputs, for build gate 4.
fn emit_js_harness(
    work_dir: &Path,
    harness_id: &str,
    runtime: &Path,
    module_abs: &Path,
    func: &JsFunction,
    source_maps: bool,
    starting_inputs: &[Vec<u8>],
) -> JsBuildResult {
    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&hdir) {
        return JsBuildResult::Failed(format!("create {}: {e}", hdir.display()));
    }
    let driver = hdir.join("bhf_driver.js");
    if let Err(e) = std::fs::copy(runtime.join("bhf_driver.js"), &driver) {
        return JsBuildResult::Failed(format!("copy driver: {e}"));
    }

    // Emit the launcher `main`. Carries the BHF_FRAMED marker the engine greps
    // for; node inherits BHF_FRAMED + BHF_COV_SHM across the exec.
    let main_path = hdir.join("main");
    let script = format!(
        "#!/bin/sh\n\
         # BHF_FRAMED BHF_JS_LAUNCHER bhf Node.js driver launcher.\n\
         # The engine sets BHF_FRAMED + BHF_COV_SHM in the environment; node\n\
         # inherits them across this exec. The driver records V8 precise block coverage\n\
         # into the file-backed BHF_COV_SHM map and speaks the framed protocol.\n\
         # BHF_JS_MODULE = the target module; BHF_JS_EXPORT = the export path;\n\
         # BHF_JS_ARG = buffer|string|path (how fuzz bytes reach the first param).\n\
         # BHF_JS_SHIM_RECORD = where the driver records the browser globals it\n\
         # stood in for, when the target needed them (#288).\n\
         BHF_JS_MODULE=\"{module}\" \\\n\
         BHF_JS_EXPORT=\"{export_path}\" \\\n\
         BHF_JS_ARG=\"{arg}\" \\\n\
         BHF_JS_SHIM_RECORD=\"{shim_record}\" \\\n\
         exec node {node_flags}\"{driver}\" \"$@\"\n",
        shim_record = hdir.join(BROWSER_GLOBALS_RECORD).display(),
        module = module_abs.display(),
        export_path = func.export_path,
        arg = func.arg_kind.as_env(),
        node_flags = if source_maps {
            "--enable-source-maps "
        } else {
            ""
        },
        driver = driver.display(),
    );
    // An earlier build's record is not this one's: the driver writes it again
    // when this target needs the browser stand-ins.
    let _ = std::fs::remove_file(hdir.join(BROWSER_GLOBALS_RECORD));
    if let Err(e) = std::fs::write(&main_path, script) {
        return JsBuildResult::Failed(format!("write launcher {}: {e}", main_path.display()));
    }
    if let Err(e) = make_executable(&main_path) {
        return JsBuildResult::Failed(format!("chmod +x {}: {e}", main_path.display()));
    }
    // The same launch where the shell script cannot run (#307).
    let mut args = Vec::new();
    if source_maps {
        args.push("--enable-source-maps".to_owned());
    }
    args.push(driver.display().to_string());
    let launch = replay_min::Launch {
        program: "node".into(),
        args,
        env: vec![
            ("BHF_JS_MODULE".to_owned(), module_abs.display().to_string()),
            ("BHF_JS_EXPORT".to_owned(), func.export_path.clone()),
            ("BHF_JS_ARG".to_owned(), func.arg_kind.as_env().to_owned()),
            (
                "BHF_JS_SHIM_RECORD".to_owned(),
                hdir.join(BROWSER_GLOBALS_RECORD).display().to_string(),
            ),
        ],
    };
    if let Err(e) = crate::launch_spec::write(&main_path, &launch) {
        return JsBuildResult::Failed(format!(
            "write the launch spec of {}: {e}",
            main_path.display()
        ));
    }
    // Build gate 3: the driver must be able to PREPARE the target — resolve the
    // export, and construct a receiver for a `Class#method` — before the engine
    // spends a budget on it. A class whose constructor needs an environment that
    // is not here (gstack's `BrowseClient` wants a live daemon port and token)
    // builds perfectly and then dies in the driver's load path, so the engine
    // recorded a harness that ran ZERO inputs and the run reported `built, no
    // fuzz pass ran` — a row naming nothing, on 58 targets across the
    // 500-project sweep. Now it says what could not be prepared, and skips.
    if let Some(reason) = js_export_load_error(&main_path, &func.export_path) {
        return JsBuildResult::Skip(reason);
    }
    // Build gate 4 (#398): a global that neither Node nor the driver's
    // browser stand-ins define (`FileReader`, a host's `app`) that every
    // input bhf can try stops at. Fuzzing it would report the environment as
    // a finding.
    if let Some(stop) = undefined_global_gate(&main_path, starting_inputs) {
        return JsBuildResult::NotEntered(stop.reason());
    }
    JsBuildResult::Built
}

/// Every input build gate 4's probe ran threw `ReferenceError: {name} is
/// not defined` from `frame` (V8's `fn (file:line:column)`).
#[derive(Debug, PartialEq)]
struct UndefinedGlobalStop {
    inputs: usize,
    name: String,
    frame: String,
}

impl UndefinedGlobalStop {
    fn reason(&self) -> String {
        let UndefinedGlobalStop {
            inputs,
            name,
            frame,
        } = self;
        format!(
            "all {inputs} inputs bhf ran before fuzzing (the fuzz passes' starting inputs, and \
             inputs built from the target's own literals) stop at `ReferenceError: {name} is \
             not defined`, thrown at `{frame}`. Node does not define `{name}` here, so this is \
             the target's environment, not a finding. Fuzz the target where `{name}` exists, \
             fuzz a function that does not need it, or pass an input that gets past that \
             point with `--seed-file`"
        )
    }
}

/// How many of the target's dictionary tokens build gate 4 turns into probe
/// inputs, at most (two inputs each).
const MAX_LITERAL_PROBES: usize = 2048;

/// Build gate 4 (#398): `Some` when every input the probe runs stops at the
/// same undefined global from the same frame. The bootstrap seeds
/// ([`crate::auto::attempt::BOOTSTRAP_SEEDS`]) run first, alone: most targets
/// get past the first of them, and the gate ends there. Only when all of them
/// stop does the probe run [`undefined_global_probes`]. `None` as soon as one
/// input does anything else (runs cleanly, is rejected, raises another error),
/// and when the probe cannot run or runs out of time: then the gate has
/// learned nothing and the target is fuzzed.
fn undefined_global_gate(
    main_path: &Path,
    starting_inputs: &[Vec<u8>],
) -> Option<UndefinedGlobalStop> {
    let bootstrap: Vec<Vec<u8>> = crate::auto::attempt::BOOTSTRAP_SEEDS
        .iter()
        .map(|seed| seed.to_vec())
        .collect();
    run_undefined_global_probe(main_path, &bootstrap, Duration::from_secs(10))?;
    let dir = main_path.parent().unwrap_or_else(|| Path::new("."));
    let probes = undefined_global_probes(dir, starting_inputs);
    run_undefined_global_probe(main_path, &probes, Duration::from_secs(60))
}

/// The inputs build gate 4 runs when every bootstrap seed stopped: the fuzz
/// passes' starting inputs (the bootstrap seeds, the run's seed inputs and a
/// provided harness's seeds), each token of the harness's dictionary (the
/// target's own string and number literals) alone and followed by 64 `A`s,
/// and three longer shapes. Duplicates are dropped; the order is kept.
fn undefined_global_probes(harness_dir: &Path, starting_inputs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut probes: Vec<Vec<u8>> = crate::auto::attempt::BOOTSTRAP_SEEDS
        .iter()
        .map(|seed| seed.to_vec())
        .collect();
    probes.extend(starting_inputs.iter().cloned());
    probes.extend(crate::auto::provided::load_seeds(harness_dir));
    let dictionary =
        std::fs::read_to_string(harness_dir.join("dictionary.txt")).unwrap_or_default();
    let tokens = dictionary
        .lines()
        .filter_map(|line| crate::fuzz::parse_afl_dictionary_line(line).ok().flatten())
        .filter(|token| !token.is_empty())
        .take(MAX_LITERAL_PROBES);
    for token in tokens {
        let mut padded = token.clone();
        padded.extend_from_slice(&[b'A'; 64]);
        probes.push(token);
        probes.push(padded);
    }
    probes.extend([vec![b'A'; 4096], vec![0; 64], vec![0xff; 64]]);
    let mut seen = std::collections::HashSet::new();
    probes.retain(|probe| seen.insert(probe.clone()));
    probes
}

/// Run `inputs` through the emitted launcher in the driver's probe mode
/// (`BHF_JS_PROBE`, one process for all of them) and read its verdict.
fn run_undefined_global_probe(
    main_path: &Path,
    inputs: &[Vec<u8>],
    timeout: Duration,
) -> Option<UndefinedGlobalStop> {
    let dir = main_path.parent().unwrap_or_else(|| Path::new("."));
    let file = dir.join("bhf-probe-inputs.bin");
    let mut framed = Vec::new();
    for input in inputs {
        framed.extend_from_slice(&u32::try_from(input.len()).ok()?.to_le_bytes());
        framed.extend_from_slice(input);
    }
    std::fs::write(&file, framed).ok()?;
    let mut command = match crate::launch_spec::launch_for(main_path) {
        Some(launch) => {
            let mut command = Command::new(&launch.program);
            command.args(&launch.args).envs(launch.env.iter().cloned());
            command
        }
        None => Command::new(main_path),
    };
    command
        .env("BHF_JS_PROBE", &file)
        .env_remove("BHF_FRAMED")
        .env_remove("BHF_JS_LOAD_ONLY")
        .current_dir(dir)
        .stdin(std::process::Stdio::null());
    let run = crate::command_output::output_with_timeout_flagged(&mut command, timeout);
    let _ = std::fs::remove_file(&file);
    let (out, timed_out) = run.ok()?;
    if timed_out {
        return None;
    }
    undefined_global_verdict(&String::from_utf8_lossy(&out.stderr))
        .filter(|stop| stop.inputs == inputs.len())
}

/// The probe's verdict when every input stopped at one undefined global
/// (`== bhf js probe: every input stopped: 3: hostApp: readUpload (/x/a.js:9:17)`).
fn undefined_global_verdict(stderr: &str) -> Option<UndefinedGlobalStop> {
    let verdict = stderr
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("== bhf js probe: "))?;
    let rest = verdict.strip_prefix("every input stopped: ")?;
    let (inputs, rest) = rest.split_once(": ")?;
    let (name, frame) = rest.split_once(": ")?;
    let identifier = !name.is_empty()
        && name
            .chars()
            .all(|c| c == '_' || c == '$' || c.is_alphanumeric());
    if !identifier {
        return None;
    }
    Some(UndefinedGlobalStop {
        inputs: inputs.parse().ok()?,
        name: name.to_owned(),
        frame: frame.trim_end().to_owned(),
    })
}

/// Run the emitted launcher in LOAD-ONLY mode: the driver resolves the export,
/// constructs any receiver, and exits without running an input. A nonzero exit
/// therefore means the target could not be prepared, and stderr carries why.
///
/// Load-only rather than "run it once with no input" because a finding halts the
/// driver with a nonzero code — so a target that legitimately crashes on the
/// empty input would be indistinguishable from one that could never load, and
/// gating on that would skip exactly the most interesting targets.
///
/// A TIMEOUT is deliberately not a failure. A module that blocks on load (a
/// server, a watch loop) is a different problem, and refusing it here would turn
/// a hang into a false skip.
fn js_export_load_error(main_path: &Path, export_path: &str) -> Option<String> {
    let dir = main_path.parent().unwrap_or_else(|| Path::new("."));
    let record = dir.join(BROWSER_GLOBALS_RECORD);
    let read_record = || std::fs::read_to_string(&record).unwrap_or_default();
    // #288: a load that stood in for another browser global is tried again,
    // with the recorded stand-ins from the start (an ES module that threw as
    // it loaded loads again only in a new process).
    let mut attempts = 0;
    let out = loop {
        let before = read_record();
        // The launcher, or its launch spec where it cannot run (#307).
        let mut command = match crate::launch_spec::launch_for(main_path) {
            Some(launch) => {
                let mut command = Command::new(&launch.program);
                command.args(&launch.args).envs(launch.env.iter().cloned());
                command
            }
            None => Command::new(main_path),
        };
        let out = crate::command_output::output_with_timeout(
            command
                .env("BHF_JS_LOAD_ONLY", "1")
                .current_dir(dir)
                .stdin(std::process::Stdio::null()),
            Duration::from_secs(30),
        )
        .ok()?;
        attempts += 1;
        if out.status.success() || read_record() == before || attempts >= 8 {
            break out;
        }
    };
    if out.status.success() {
        return None;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Some(crate::auto::script_load_roots::unloadable_reason(
        export_path,
        &stderr,
    ))
}

/// Loaders for the non-code assets a real TypeScript module imports.
///
/// A front-end module routinely does `import logo from "./logo.png"` or
/// `import cfg from "./config.yaml"`. esbuild has no built-in loader for those
/// and fails the WHOLE bundle with `No loader is configured for ".png" files`,
/// which skipped the target. Measured in the 500-project sweep: `.png` 5, `.svg`
/// 5, `.yaml` 5, `.vue` 3, across NextChat, mermaid and matomo.
///
/// The asset is irrelevant to fuzzing the module's FUNCTIONS, so it loads as
/// inert text (or a data URL for binaries) and the code goes through. This never
/// changes how the code itself is transpiled.
///
/// `.vue` is deliberately included even though a Single File Component is not
/// really text: esbuild cannot compile one at all, and loading it inertly at
/// least lets a sibling function be reached. If the module then breaks at load,
/// the load-only build gate skips it with the real error rather than fuzzing
/// something malformed — which is why this is safe to be liberal about.
const NON_CODE_IMPORT_LOADERS: &[&str] = &[
    "--loader:.css=text",
    "--loader:.scss=text",
    "--loader:.sass=text",
    "--loader:.less=text",
    "--loader:.styl=text",
    "--loader:.svg=text",
    "--loader:.html=text",
    "--loader:.vue=text",
    "--loader:.md=text",
    "--loader:.txt=text",
    "--loader:.yaml=text",
    "--loader:.yml=text",
    "--loader:.toml=text",
    "--loader:.graphql=text",
    "--loader:.gql=text",
    "--loader:.png=dataurl",
    "--loader:.jpg=dataurl",
    "--loader:.jpeg=dataurl",
    "--loader:.gif=dataurl",
    "--loader:.ico=dataurl",
    "--loader:.webp=dataurl",
    "--loader:.avif=dataurl",
    "--loader:.mp3=dataurl",
    "--loader:.wav=dataurl",
    "--loader:.woff=dataurl",
    "--loader:.woff2=dataurl",
    "--loader:.ttf=dataurl",
    "--loader:.otf=dataurl",
    "--loader:.eot=dataurl",
];

/// The file names an installed esbuild has.
const ESBUILD_NAMES: &[&str] = if cfg!(windows) {
    &["esbuild.exe", "esbuild.cmd"]
} else {
    &["esbuild"]
};

/// Resolve the TypeScript transpiler: `esbuild` on `path` (a single fast binary
/// that strips types), else the project's own `node_modules/.bin/esbuild` in a
/// directory from the source's own up to and including `scan_root`, the
/// nearest first.
///
/// Never above `scan_root`: a `node_modules` there is not the scanned
/// project's, and in a directory any user can write (`/tmp`, a shared home)
/// anyone could plant the esbuild bhf would run for every tree scanned below
/// it. Without a scan root, or with a single file as the scan root, only
/// `path` is searched.
///
/// Never `npx`: since npm 7 `npx --no-install esbuild` looks the package up in
/// the registry and refuses to install it (or, at a terminal, asks to), so it
/// reaches the network and fails where esbuild is missing, and adds nothing
/// where the project has its own esbuild, which this finds directly.
fn locate_esbuild_in(
    path: Option<&std::ffi::OsStr>,
    source: &Path,
    scan_root: Option<&Path>,
) -> Option<PathBuf> {
    let on_path = path
        .into_iter()
        .flat_map(std::env::split_paths)
        .flat_map(|dir| ESBUILD_NAMES.iter().map(move |name| dir.join(name)));
    let in_project = project_dirs(source, scan_root).into_iter().flat_map(|dir| {
        ESBUILD_NAMES
            .iter()
            .map(move |name| dir.join("node_modules").join(".bin").join(name))
    });
    on_path
        .chain(in_project)
        .find(|candidate| candidate.is_file())
}

/// [`locate_esbuild_in`] on this process's `PATH`: the esbuild the TypeScript
/// lane runs for `source`, which the run-start toolchain check also asks for.
pub(crate) fn locate_esbuild(source: &Path, scan_root: Option<&Path>) -> Option<PathBuf> {
    locate_esbuild_in(std::env::var_os("PATH").as_deref(), source, scan_root)
}

/// The directories from `source`'s own up to and including the scan root
/// directory, nearest first. Empty without a scan root, when it is not a
/// directory, or when `source` is not inside it.
fn project_dirs(source: &Path, scan_root: Option<&Path>) -> Vec<PathBuf> {
    let Some(root) = scan_root
        .and_then(|root| root.canonicalize().ok())
        .filter(|root| root.is_dir())
    else {
        return Vec::new();
    };
    let Ok(source) = source.canonicalize() else {
        return Vec::new();
    };
    source
        .ancestors()
        .skip(1)
        .take_while(|dir| dir.starts_with(&root))
        .map(Path::to_path_buf)
        .collect()
}

/// The TypeScript lane's build (M3.8). Transpile the `.ts` target to CommonJS `.js`
/// with esbuild (bundling local imports, leaving `node_modules` external), then
/// reuse the JS driver on the transpiled module. A missing node/esbuild, or a
/// transpile/load failure, skips cleanly.
pub fn build_ts_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    scan_root: Option<&Path>,
    starting_inputs: &[Vec<u8>],
) -> JsBuildResult {
    if !have_node() {
        return JsBuildResult::MissingToolchain(
            "no `node` runtime found; install Node.js to fuzz TypeScript (skips cleanly)"
                .to_owned(),
        );
    }
    let Some(runtime) = locate_js_runtime() else {
        return JsBuildResult::Failed(
            "could not locate the bundled js_runtime/bhf_driver.js".to_owned(),
        );
    };
    let func = match resolve_target(candidate) {
        Ok(f) => f,
        Err(reason) => return JsBuildResult::Skip(reason),
    };
    let Some(esbuild) = locate_esbuild(&candidate.source_path, scan_root) else {
        return JsBuildResult::MissingToolchain(
            "no TypeScript transpiler found (install esbuild: `npm i -g esbuild`, or add it \
             to the scanned project's node_modules); the TS lane skips cleanly"
                .to_owned(),
        );
    };
    let src_abs = candidate
        .source_path
        .canonicalize()
        .unwrap_or_else(|_| candidate.source_path.clone());

    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&hdir) {
        return JsBuildResult::Failed(format!("create {}: {e}", hdir.display()));
    }
    let out_js = hdir.join("target.js");

    // Transpile: bundle local TS imports + strip types, keep node_modules external.
    // The source map (`target.js.map`) lets node's stacks, and so the finding,
    // name the `.ts` file and line rather than the transpiled module's.
    let mut cmd = Command::new(&esbuild);
    cmd.arg(&src_abs)
        .arg("--bundle")
        .arg("--packages=external")
        .arg("--format=cjs")
        .arg("--platform=node")
        .arg("--sourcemap")
        .arg(format!("--outfile={}", out_js.display()));
    for loader in NON_CODE_IMPORT_LOADERS {
        cmd.arg(loader);
    }
    match crate::command_output::output_with_timeout(
        &mut cmd,
        std::time::Duration::from_secs(30 * 60),
    ) {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr);
            return JsBuildResult::Skip(format!(
                "esbuild could not transpile {}: {}",
                src_abs.display(),
                msg.lines().next().unwrap_or("").trim()
            ));
        }
        Err(e) => return JsBuildResult::Skip(format!("spawn esbuild: {e}")),
    }
    // Smoke-test the transpiled module parses AND loads (external node_modules
    // requires resolvable) — else it would fuzz 0 inputs. Skip cleanly otherwise.
    if let Some(reason) = js_module_load_error(&out_js, &hdir) {
        return JsBuildResult::Skip(reason);
    }
    emit_js_harness(
        work_dir,
        harness_id,
        &runtime,
        &out_js,
        &func,
        true,
        starting_inputs,
    )
}

#[cfg(unix)]
fn make_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    /// #288: a missing browser global is told from another load error.
    #[test]
    fn a_missing_browser_global_is_named_and_other_errors_are_not() {
        let window = "/x/index.js:3\n  const w = window.innerWidth;\n\nReferenceError: window is not defined\n    at Object.<anonymous>";
        assert_eq!(super::missing_browser_global(window), Some("window"));
        assert_eq!(
            super::missing_browser_global("ReferenceError: navigator is not defined"),
            Some("navigator")
        );
        assert_eq!(
            super::missing_browser_global("ReferenceError: HTMLFormElement is not defined"),
            Some("a browser class")
        );
        assert_eq!(
            super::missing_browser_global("ReferenceError: foo is not defined"),
            None
        );
        assert_eq!(
            super::missing_browser_global("Error: Cannot find module 'side-channel'"),
            None
        );
    }

    use super::*;

    /// esbuild is found on PATH, else in a `node_modules/.bin` between the
    /// source and the scan root, the nearest first, and nowhere else: never
    /// above the scan root (a directory another user may write, such as
    /// `/tmp`), never without a scan root, and never through `npx`.
    #[cfg(unix)]
    #[test]
    fn esbuild_comes_from_path_or_the_scanned_tree_and_never_from_above_it() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp = tmp.path().canonicalize().unwrap();
        let bin = tmp.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("npx"), "#!/bin/sh\nexit 0\n").unwrap();
        let root = tmp.join("shared/project");
        let source = root.join("src/lib/parser.ts");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, "export function f() {}\n").unwrap();
        let path = std::env::join_paths([&bin]).unwrap();
        let plant = |dir: &Path| {
            let esbuild = dir.join("node_modules/.bin/esbuild");
            std::fs::create_dir_all(esbuild.parent().unwrap()).unwrap();
            std::fs::write(&esbuild, "").unwrap();
            esbuild
        };
        let found = |root: Option<&Path>| locate_esbuild_in(Some(&path), &source, root);
        assert_eq!(found(Some(&root)), None);

        // Above the scan root: one level up and at the top of the tree.
        plant(&tmp.join("shared"));
        plant(&tmp);
        assert_eq!(found(Some(&root)), None, "nothing above the scan root");
        assert_eq!(found(None), None, "nothing without a scan root");
        assert_eq!(found(Some(&source)), None, "a file root has no project dir");
        assert_eq!(found(Some(&root.join("other"))), None, "not under the root");

        // In the scanned tree: the scan root itself, then a nearer directory.
        let at_root = plant(&root);
        assert_eq!(found(Some(&root)), Some(at_root.clone()));
        assert_eq!(locate_esbuild_in(None, &source, Some(&root)), Some(at_root));
        let nearer = plant(&root.join("src"));
        assert_eq!(found(Some(&root)), Some(nearer));

        // PATH wins over the project.
        std::fs::write(bin.join("esbuild"), "").unwrap();
        assert_eq!(found(Some(&root)), Some(bin.join("esbuild")));
    }

    #[test]
    fn bundled_driver_checkpoints_immediately_before_the_selected_export() {
        let runtime = locate_js_runtime().expect("js_runtime locatable in-tree");
        let driver = std::fs::read_to_string(runtime.join("bhf_driver.js")).unwrap();
        assert!(
            driver.contains("markTargetEntry();\n      return bound(arg);"),
            "string export call lacks an entry checkpoint"
        );
        assert!(
            driver.contains("markTargetEntry();\n    return bound(buf);"),
            "buffer export call lacks an entry checkpoint"
        );
        let write = driver.find("fs.writeFileSync(inputPath, buf);").unwrap();
        let path_call = driver.find("return await bound(inputPath);").unwrap();
        let checkpoint = driver[write..path_call]
            .find("markTargetEntry();")
            .map(|offset| write + offset)
            .unwrap();
        assert!(write < checkpoint && checkpoint < path_call);
        assert!(driver.contains("fs.rmSync(dir, { recursive: true, force: true })"));
        assert!(
            driver.contains("await runOne(buf);"),
            "promise rejections must pass through finding classification"
        );
    }

    /// #398: the probe's verdict line, and nothing for any other line.
    #[test]
    fn the_probe_verdict_names_the_global_its_frame_and_the_input_count() {
        let stderr = "ReferenceError: hostApp is not defined\n\
                      == bhf js probe: every input stopped: 3: hostApp: readUpload (/x/upload.js:9:17)\n";
        assert_eq!(
            undefined_global_verdict(stderr),
            Some(UndefinedGlobalStop {
                inputs: 3,
                name: "hostApp".to_owned(),
                frame: "readUpload (/x/upload.js:9:17)".to_owned(),
            })
        );
        for other in [
            "== bhf js probe: got past: 0",
            "== bhf js probe: every input stopped: x: hostApp: f (/x/a.js:1:1)",
            "== bhf js probe: every input stopped: 2: host app: f (/x/a.js:1:1)",
            "== bhf js finding: BHF-210: ReferenceError: hostApp is not defined",
            "",
        ] {
            assert_eq!(undefined_global_verdict(other), None, "{other}");
        }
    }

    /// #398: the probe runs the fuzz passes' starting inputs, then each
    /// dictionary token alone and padded, then the longer shapes, once each.
    #[test]
    fn the_probe_inputs_are_the_starting_inputs_and_the_targets_literals() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("dictionary.txt"),
            "# from frame.js:10\n\"BHF1\"\n\"A\"\n",
        )
        .unwrap();
        let seeds = crate::auto::provided::SEEDS_DIR;
        std::fs::create_dir_all(dir.path().join(seeds)).unwrap();
        std::fs::write(dir.path().join(seeds).join("one"), b"REC1").unwrap();
        let probes = undefined_global_probes(dir.path(), &[b"12-34".to_vec(), b"A".to_vec()]);
        let padded = |token: &[u8]| [token, &[b'A'; 64][..]].concat();
        assert_eq!(
            probes,
            [
                b"".to_vec(),
                b"A".to_vec(),
                b"AAAAAAAA".to_vec(),
                b"12-34".to_vec(),
                b"REC1".to_vec(),
                b"BHF1".to_vec(),
                padded(b"BHF1"),
                padded(b"A"),
                vec![b'A'; 4096],
                vec![0; 64],
                vec![0xff; 64],
            ]
        );
    }

    /// #398: build gate 4 against real targets. A global read on every call
    /// stops every input. One that a literal, a seed or a longer input gets
    /// past, or that two frames throw, is not the target's environment.
    #[cfg(unix)]
    #[test]
    fn the_gate_reports_only_a_global_no_input_gets_past() {
        if which::which("node").is_err() {
            return;
        }
        let runtime = locate_js_runtime().expect("js_runtime locatable in-tree");
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("widget.js");
        std::fs::write(
            &module,
            "'use strict';\n\
             const text = (data) => Buffer.from(data).toString('latin1');\n\
             exports.readUpload = (data) => hostApp.uploads.save(data);\n\
             exports.parseFrame = (data) =>\n\
               text(data).startsWith('BHF1') ? 1 : legacyFrames.decode(data);\n\
             exports.parseRange = (data) =>\n\
               /^[0-9]+-[0-9]+$/.test(text(data)) ? 1 : rangeTable.lookup(data);\n\
             exports.parseBlock = (data) => (data.length > 8 ? 0 : shortBlocks.decode(data));\n\
             function short(data) { return ghost.short(data); }\n\
             function long(data) { return ghost.long(data); }\n\
             exports.copyAt = (data) => (data.length === 1 ? short(data) : long(data));\n",
        )
        .unwrap();
        let gate = |export: &str, dictionary: &str, seeds: &[Vec<u8>]| {
            let harness = dir.path().join(export);
            std::fs::create_dir_all(&harness).unwrap();
            std::fs::write(harness.join("dictionary.txt"), dictionary).unwrap();
            let main = harness.join("main");
            std::fs::write(
                &main,
                format!(
                    "#!/bin/sh\nBHF_JS_MODULE=\"{}\" BHF_JS_EXPORT=\"{export}\" \
                     BHF_JS_ARG=buffer exec node \"{}\" \"$@\"\n",
                    module.display(),
                    runtime.join("bhf_driver.js").display()
                ),
            )
            .unwrap();
            make_executable(&main).unwrap();
            undefined_global_gate(&main, seeds)
        };
        let upload = gate("readUpload", "\"BHF1\"\n", &[b"12-34".to_vec()])
            .expect("hostApp stops every input");
        assert_eq!(upload.name, "hostApp");
        assert!(upload.frame.contains("widget.js:3:"), "{upload:?}");
        assert!(upload.reason().contains("`hostApp`"), "{}", upload.reason());
        assert!(
            upload.reason().contains(&upload.frame),
            "{}",
            upload.reason()
        );
        assert_eq!(
            gate("parseFrame", "", &[]).map(|stop| stop.name),
            Some("legacyFrames".to_owned())
        );
        assert_eq!(gate("parseFrame", "\"BHF1\"\n", &[]), None);
        assert_eq!(
            gate("parseRange", "\"-\"\n", &[]).map(|stop| stop.name),
            Some("rangeTable".to_owned())
        );
        assert_eq!(gate("parseRange", "\"-\"\n", &[b"12-34".to_vec()]), None);
        assert_eq!(gate("parseBlock", "", &[]), None);
        assert_eq!(gate("copyAt", "", &[]), None);
        assert!(!dir.path().join("readUpload/bhf-probe-inputs.bin").exists());
    }

    #[test]
    fn async_path_target_keeps_materialized_input_until_promise_settles() {
        let Some(node) = which::which("node").ok() else {
            return;
        };
        let runtime = locate_js_runtime().expect("js_runtime locatable in-tree");
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.js");
        let input = temp.path().join("input.bin");
        std::fs::write(
            &target,
            "const fs = require('fs');\n\
             exports.readLater = async function(filePath) {\n\
               await new Promise((resolve) => setTimeout(resolve, 20));\n\
               const data = fs.readFileSync(filePath);\n\
               if (data.toString('utf8') !== 'kept alive') throw new Error('wrong data');\n\
             };\n",
        )
        .unwrap();
        std::fs::write(&input, b"kept alive").unwrap();
        let output = Command::new(node)
            .arg(runtime.join("bhf_driver.js"))
            .arg(&input)
            .env("BHF_JS_MODULE", &target)
            .env("BHF_JS_EXPORT", "readLater")
            .env("BHF_JS_ARG", "path")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "async file target failed after cleanup: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
