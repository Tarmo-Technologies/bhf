// SPDX-License-Identifier: Apache-2.0

//! Native Python fuzzing lane (M3.1): generate a bhf harness module, copy the
//! `python_runtime` (decode/cov/driver), and emit a `harnesses/<id>/main` launcher that
//! runs the target under a persistent CPython speaking the `BHF_FRAMED`
//! fork-server protocol with `sys.monitoring`/`sys.settrace` edge coverage into the
//! shared map — the SAME builtin-engine execution path as C/C++/Rust/Java, no
//! Atheris, no libFuzzer.
//!
//! Python is interpreted, so there is no native binary: the launcher execs the
//! interpreter on the generated driver. "Build" is a `py_compile` syntax gate; the
//! repair loop is a pass-through (the launcher already exists). A missing `python3`
//! or an un-harnessable target (currently: an instance method needing a constructed
//! receiver) skips cleanly — the GNAT-less rule.
//!
//! A Python 2 source runs under a `python2` interpreter with the same runtime,
//! which is written for both (#285); without one it is report-only.

use crate::auto::candidate::Candidate;
use python_parser::{parse_python_functions, PyFunction};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Outcome of the native Python build lane (parallels `JavaBuildResult`).
pub enum PythonBuildResult {
    /// `<work>/harnesses/<id>/main` was produced and is ready to fuzz.
    Built,
    /// The lane could not run / the harness could not build. `skip` is true for a
    /// missing toolchain or an un-harnessable target (skip cleanly), false for a
    /// genuine build error worth surfacing.
    Failed { reason: String, skip: bool },
}

/// `name` on `path` (`PATH` when `None`).
fn find_on(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    match path {
        Some(path) => which::which_in(name, Some(path), "/").ok(),
        None => which::which(name).ok(),
    }
}

/// The interpreter a candidate of `dialect` runs under (#285), found on `path`
/// (`PATH` when `None`): a Python 2 source under `python2`, `python2.7` or a
/// `python` that is 2.x, any other under `python3` or a `python` that is 3.x.
/// The error is the reason the target is skipped.
pub(crate) fn select_interpreter(
    dialect: Option<lang_profile::Dialect>,
    path: Option<&OsStr>,
) -> Result<PathBuf, String> {
    if dialect == Some(lang_profile::Dialect::Python2) {
        return ["python2", "python2.7", "python"]
            .into_iter()
            .filter_map(|name| find_on(name, path))
            .find(|python| python_version(python).is_some_and(|(major, _)| major == 2))
            .ok_or_else(|| {
                "Python 2: no `python2` interpreter found; install Python 2.7 as `python2` \
                 to fuzz this target"
                    .to_owned()
            });
    }
    let Some(python) = find_on("python3", path).or_else(|| find_on("python", path)) else {
        return Err(
            "no `python3` interpreter found; install Python 3 to fuzz Python \
                    (the lane skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
        );
    };
    // A Python 2 interpreter (the only `python` on some legacy hosts) cannot
    // import a Python 3 source. Say so up front rather than letting the import
    // smoke-test fail with an opaque SyntaxError.
    if let Some((major, minor)) = python_version(&python) {
        if major < 3 {
            return Err(format!(
                "interpreter at {} is Python {major}.{minor} and this is a Python 3 \
                 source; install python3 to fuzz this target",
                python.display()
            ));
        }
    }
    Ok(python)
}

/// M22: detected `(major, minor)` of a Python interpreter, or `None` if it could
/// not be run/parsed. Used to detect a Python 2 interpreter up front so the lane
/// skips with an actionable reason instead of letting the Python 3 driver fail
/// later with an opaque import-time `SyntaxError`.
fn python_version(python: &Path) -> Option<(u32, u32)> {
    let out = std::process::Command::new(python)
        .arg("-c")
        .arg("import sys; sys.stdout.write('%d.%d' % sys.version_info[:2])")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let mut it = s.trim().split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

/// Locate the bundled `python_runtime/` directory (decode/cov/driver), relative to
/// the source tree (dev) or the installed binary (release) — mirrors
/// `locate_build_agent_script` for the Java agent.
fn locate_python_runtime() -> Option<PathBuf> {
    crate::runtime_assets::locate("python_runtime", "bhf_driver.py")
}

/// The single public entry point of the lane.
pub fn build_python_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> PythonBuildResult {
    // A project's own Atheris harness runs as it is written, not through a
    // generated call.
    if let Some(entry) = crate::auto::provided::atheris_entry(candidate) {
        return match build_atheris_harness(candidate, &entry, work_dir, harness_id, source_root) {
            Ok(()) => PythonBuildResult::Built,
            Err((reason, skip)) => PythonBuildResult::Failed { reason, skip },
        };
    }
    let python = match select_interpreter(candidate.dialect, None) {
        Ok(python) => python,
        Err(reason) => return PythonBuildResult::Failed { reason, skip: true },
    };
    let Some(runtime) = locate_python_runtime() else {
        return PythonBuildResult::Failed {
            reason: "could not locate the bundled python_runtime/ (decode/cov/driver)".to_owned(),
            skip: false,
        };
    };

    // Resolve the target function by re-parsing the source and matching (name, line).
    let resolved = match resolve_target(candidate) {
        Ok(r) => r,
        Err(reason) => return PythonBuildResult::Failed { reason, skip: true },
    };
    let func = &resolved.func;

    // Compute the importable module path + the directory to put on PYTHONPATH.
    let (import_root, module) = resolve_module(&candidate.source_path, source_root);

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let gen_pkg = auto_dir.join("bhfgen");
    if let Err(e) = std::fs::create_dir_all(&gen_pkg) {
        return PythonBuildResult::Failed {
            reason: format!("create {}: {e}", gen_pkg.display()),
            skip: false,
        };
    }

    // Copy the runtime modules next to the harness so they are importable.
    for f in ["bhf_decode.py", "bhf_cov.py", "bhf_driver.py"] {
        if let Err(e) = std::fs::copy(runtime.join(f), auto_dir.join(f)) {
            return PythonBuildResult::Failed {
                reason: format!("copy runtime {f}: {e}", f = f),
                skip: false,
            };
        }
    }
    let _ = std::fs::write(
        gen_pkg.join("__init__.py"),
        "# SPDX-License-Identifier: Apache-2.0\n",
    );

    // Generate the harness module.
    let harness_src = generate_harness(&module, func, resolved.receiver.as_ref());
    let harness_path = gen_pkg.join("harness.py");
    if let Err(e) = std::fs::write(&harness_path, &harness_src) {
        return PythonBuildResult::Failed {
            reason: format!("write harness {}: {e}", harness_path.display()),
            skip: false,
        };
    }

    // Build gate: py_compile the generated harness (syntax only; no target execution).
    let compile = Command::new(&python)
        .arg("-m")
        .arg("py_compile")
        .arg(&harness_path)
        .output();
    match compile {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return PythonBuildResult::Failed {
                reason: format!(
                    "py_compile of generated harness failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
                skip: false,
            };
        }
        Err(e) => {
            return PythonBuildResult::Failed {
                reason: format!("could not run py_compile: {e}"),
                skip: false,
            };
        }
    }

    let pythonpath = crate::launch_spec::search_path(&[&auto_dir, &import_root]);

    // Import smoke-test: actually import the harness (which imports the target
    // module) so a target that isn't importable under this interpreter — a missing
    // third-party dependency, a newer-Python syntax, an import-time error — is a
    // CLEAN SKIP instead of a silent "built, 0 executions" run. This executes the
    // module's import-time code, the same exposure as the fuzz step (which runs the
    // target); bounded by a timeout. Run without the shim so import-time mkdir of
    // caches can't trip a behavioral oracle.
    let smoke = crate::command_output::output_with_timeout(
        Command::new(&python)
            .arg("-B")
            .arg("-c")
            .arg("import bhfgen.harness")
            .env("PYTHONPATH", &pythonpath)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .current_dir(&auto_dir),
        Duration::from_secs(30),
    );
    match smoke {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            // Name the distribution when CPython named it: an uninstalled PyPI
            // package is a REQUIREMENT the operator can satisfy, whereas the raw
            // traceback tail reads as an unsupported signature and sent every
            // such target to the "try --force" advice, which cannot install it.
            return PythonBuildResult::Failed {
                reason: crate::auto::script_load_roots::unloadable_reason(
                    &module,
                    &String::from_utf8_lossy(&out.stderr),
                ),
                skip: true,
            };
        }
        Err(e) => {
            return PythonBuildResult::Failed {
                reason: format!("could not run import smoke-test: {e}"),
                skip: false,
            };
        }
    }

    if let Err(reason) = write_launcher(
        &auto_dir,
        &python,
        &import_root,
        module.split('.').next().unwrap_or(&module),
        &pythonpath,
        &[],
    ) {
        return PythonBuildResult::Failed {
            reason,
            skip: false,
        };
    }
    PythonBuildResult::Built
}

/// Build a project's Atheris harness, the function its file registers with
/// `atheris.Setup` (`entry`), as a harness of this lane.
///
/// Atheris runs a harness under libFuzzer, which bhf's engine does not
/// drive, so the harness runs as it is under bhf's driver instead: the
/// harness dir holds a stand-in for the `atheris` module
/// ([`ATHERIS_STAND_IN`]), ahead of an installed one on the module path,
/// whose `Setup` and `Fuzz` only record and return when the harness file is
/// imported, whose instrumentation calls leave coverage to bhf's tracer, and
/// whose `FuzzedDataProvider` decodes values from the input; the generated
/// harness module imports the harness file and calls the registered function
/// with each input. As under Atheris, every exception the function lets
/// escape is a finding (`BHF_PY_EVERY_EXCEPTION`), located past the harness
/// file's own frames (`BHF_PY_GLUE_FILES`). Coverage is traced over
/// the whole tree, since the code a harness drives is the project's, and
/// the tree (and its `src/`) is on the module path, as an installed project
/// would be.
///
/// The `<stem>.dict` beside the harness joins its dictionary, and the files
/// of its seed corpus ([`atheris_seed_dirs`]) start the fuzz passes.
fn build_atheris_harness(
    candidate: &Candidate,
    entry: &python_parser::AtherisEntry,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> Result<(), (String, bool)> {
    use crate::auto::provided;
    // Atheris is Python 3 only.
    let python = select_interpreter(None, None).map_err(|reason| (reason, true))?;
    let runtime = locate_python_runtime().ok_or_else(|| {
        (
            "could not locate the bundled python_runtime/ (decode/cov/driver)".to_owned(),
            false,
        )
    })?;
    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let gen_pkg = auto_dir.join("bhfgen");
    let stand_in = auto_dir.join("atheris");
    for dir in [&gen_pkg, &stand_in] {
        std::fs::create_dir_all(dir)
            .map_err(|e| (format!("create {}: {e}", dir.display()), false))?;
    }
    provided::clear(&auto_dir)
        .map_err(|e| (format!("clear {}: {e}", auto_dir.display()), false))?;
    for f in ["bhf_decode.py", "bhf_cov.py", "bhf_driver.py"] {
        std::fs::copy(runtime.join(f), auto_dir.join(f))
            .map_err(|e| (format!("copy runtime {f}: {e}"), false))?;
    }
    let harness_file = crate::workdir::plain_canonical(&candidate.source_path);
    let tree = crate::workdir::plain_canonical(source_root);
    let (import_root, module) = resolve_module(&harness_file, &tree);
    let harness_path = gen_pkg.join("harness.py");
    for (path, text) in [
        (
            gen_pkg.join("__init__.py"),
            "# SPDX-License-Identifier: Apache-2.0\n".to_owned(),
        ),
        (stand_in.join("__init__.py"), ATHERIS_STAND_IN.to_owned()),
        (
            harness_path.clone(),
            generate_atheris_harness(&module, &entry.callback),
        ),
    ] {
        std::fs::write(&path, text)
            .map_err(|e| (format!("write {}: {e}", path.display()), false))?;
    }

    // The module path: the stand-in and the generated harness, the harness
    // file's own import root, then the tree and its `src/`.
    let mut path_dirs: Vec<PathBuf> = vec![auto_dir.clone(), import_root];
    for dir in [tree.clone(), tree.join("src")] {
        if dir.is_dir() && !path_dirs.contains(&dir) {
            path_dirs.push(dir);
        }
    }
    let path_refs: Vec<&Path> = path_dirs.iter().map(PathBuf::as_path).collect();
    let pythonpath = crate::launch_spec::search_path(&path_refs);

    // Import the harness file (its module-level code runs, its `Setup` and
    // `Fuzz` included) so one that cannot load here is a clean skip naming
    // why, not a run of zero executions.
    let smoke = crate::command_output::output_with_timeout(
        Command::new(&python)
            .arg("-B")
            .arg("-c")
            .arg("import bhfgen.harness")
            .env("PYTHONPATH", &pythonpath)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .current_dir(&auto_dir)
            .stdin(std::process::Stdio::null()),
        Duration::from_secs(30),
    )
    .map_err(|e| (format!("could not run import smoke-test: {e}"), false))?;
    if !smoke.status.success() {
        return Err((
            crate::auto::script_load_roots::unloadable_reason(
                &module,
                &String::from_utf8_lossy(&smoke.stderr),
            ),
            true,
        ));
    }

    let mut record =
        provided::ProvidedRecord::new(provided::Origin::Atheris, &entry.callback, &harness_file);
    let seed_dirs = atheris_seed_dirs(&harness_file);
    let (seeds, skipped) = provided::copy_seed_files(&auto_dir, &seed_dirs)
        .map_err(|e| (format!("copy the harness's seeds: {e}"), false))?;
    record.seeds = seeds;
    record.seed_sources = seed_dirs;
    if skipped > 0 {
        record.notes.push(format!(
            "{skipped} seed file(s) were left out: a symlink, or past the seed count or size limits"
        ));
    }
    let dictionary = harness_file.with_extension("dict");
    if dictionary.is_file() {
        match provided::append_dictionaries(&auto_dir, std::slice::from_ref(&dictionary)) {
            Ok(tokens) => {
                record.dictionaries.push(dictionary);
                record.dictionary_tokens = tokens;
            }
            Err(error) => record
                .notes
                .push(format!("{error}; the dictionary is left out")),
        }
    }

    // The harness file only hands the input on: a finding is the code's it
    // calls, unless the harness raised it itself.
    let glue = harness_file.to_string_lossy();
    write_launcher(
        &auto_dir,
        &python,
        &tree,
        "",
        &pythonpath,
        &[
            ("BHF_PY_EVERY_EXCEPTION", "1"),
            ("BHF_PY_GLUE_FILES", &glue),
        ],
    )
    .map_err(|reason| (reason, false))?;
    provided::write_record(&auto_dir, &record)
        .map_err(|e| (format!("record the provided harness: {e}"), false))
}

/// The seed corpora an Atheris harness keeps beside it, by the names
/// projects give them: `<stem>_seed_corpus/`, `<stem>_corpus/`,
/// `corpus/<stem>/` and `seeds/<stem>/`.
fn atheris_seed_dirs(harness_file: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(stem)) = (
        harness_file.parent(),
        harness_file.file_stem().and_then(|stem| stem.to_str()),
    ) else {
        return Vec::new();
    };
    [
        dir.join(format!("{stem}_seed_corpus")),
        dir.join(format!("{stem}_corpus")),
        dir.join("corpus").join(stem),
        dir.join("seeds").join(stem),
    ]
    .into_iter()
    .filter(|dir| dir.is_dir())
    .collect()
}

/// The `bhfgen/harness.py` of an Atheris harness: it imports the harness
/// file as `module` and hands each input to its registered `callback`.
fn generate_atheris_harness(module: &str, callback: &str) -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         # Generated by bhf (native Python lane) for the project's Atheris harness:\n\
         # each input goes to the function it registers with atheris.Setup. Do not edit.\n\
         import importlib\n\
         import os\n\
         \n\
         _t = importlib.import_module(\"{module}\")\n\
         _bhf_entry = getattr(_t, \"{callback}\")\n\
         {probe}\
         \n\
         def bhf_run_one(data):\n\
         \x20   _bhf_mark_target_entry()\n\
         \x20   _bhf_entry(data)\n",
        probe = TARGET_ENTRY_PROBE,
    )
}

/// What every generated harness module defines ahead of `bhf_run_one`: the
/// probe that marks the first entry into the target.
const TARGET_ENTRY_PROBE: &str = "\n\
     _bhf_target_entered = False\n\
     \n\
     def _bhf_mark_target_entry():\n\
     \x20   global _bhf_target_entered\n\
     \x20   if _bhf_target_entered:\n\
     \x20       return\n\
     \x20   path = os.environ.get(\"BHF_TARGET_ENTRY_SHM\")\n\
     \x20   if not path:\n\
     \x20       return\n\
     \x20   try:\n\
     \x20       with open(path, \"wb\") as entry:\n\
     \x20           entry.write(b\"\\x01\")\n\
     \x20       _bhf_target_entered = True\n\
     \x20   except (IOError, OSError):\n\
     \x20       pass\n\
     \n";

/// bhf's stand-in for the `atheris` module, which an Atheris harness imports.
/// It covers the module's harness-facing API; an attribute it lacks fails the
/// import smoke test, so such a harness skips with the reason.
const ATHERIS_STAND_IN: &str = r#"# SPDX-License-Identifier: Apache-2.0
"""bhf's stand-in for the `atheris` module, written beside a project's Atheris
harness so the harness runs under bhf's driver. bhf's engine hands each input
to the function the harness registers, and bhf's tracer measures coverage, so
Setup and Fuzz only record and return, and the instrumentation calls change
nothing. FuzzedDataProvider decodes values from the front of the input: text
as Atheris does (a first byte choosing ASCII, UTF-16 or UTF-32), integers as
little-endian two's complement."""
import contextlib
import math
import sys

ALL_REMAINING = sys.maxsize

registered = []


def Setup(args, test_one_input, **kwargs):
    registered.append(test_one_input)
    return list(args)


def Fuzz():
    return None


def instrument_func(func):
    return func


def instrument_all():
    return None


@contextlib.contextmanager
def instrument_imports(*args, **kwargs):
    yield


enabled_hooks = set()


def Mutate(data, max_size):
    return bytes(data)[:max_size]


class FuzzedDataProvider(object):
    def __init__(self, data):
        self._data = bytes(data)
        self._pos = 0

    def remaining_bytes(self):
        return len(self._data) - self._pos

    def buffer(self):
        return self._data[self._pos:]

    def _take(self, count):
        count = max(0, min(int(count), self.remaining_bytes()))
        out = self._data[self._pos:self._pos + count]
        self._pos += count
        return out

    def ConsumeBytes(self, count):
        return self._take(count)

    def _text(self, count, surrogates):
        if count <= 0 or self.remaining_bytes() == 0:
            return ""
        spec = self._take(1)[0]
        if spec & 1 == 0:
            return "".join(chr(b & 0x7F) for b in self._take(count))
        if spec & 2 == 0:
            raw = self._take(count * 2)
            points = [int.from_bytes(raw[i:i + 2], "little") for i in range(0, len(raw) - 1, 2)]
        else:
            raw = self._take(count * 4)
            points = [int.from_bytes(raw[i:i + 4], "little") & 0x1FFFFF
                      for i in range(0, len(raw) - 3, 4)]
            points = [p if p <= 0x10FFFF else p & 0xFFFF for p in points]
        if not surrogates:
            points = [0xFFFD if 0xD800 <= p <= 0xDFFF else p for p in points]
        return "".join(chr(p) for p in points)

    def ConsumeUnicode(self, count):
        return self._text(count, True)

    def ConsumeUnicodeNoSurrogates(self, count):
        return self._text(count, False)

    def ConsumeString(self, count):
        return self._text(count, True)

    def ConsumeInt(self, size):
        return int.from_bytes(self._take(size), "little", signed=True)

    def ConsumeUInt(self, size):
        return int.from_bytes(self._take(size), "little")

    def ConsumeIntInRange(self, low, high):
        if low > high:
            raise ValueError("ConsumeIntInRange: min must not exceed max")
        span = high - low
        if span == 0:
            return low
        raw = self._take((span.bit_length() + 7) // 8)
        return low + int.from_bytes(raw, "little") % (span + 1)

    def ConsumeIntList(self, count, size):
        return [self.ConsumeInt(size) for _ in range(count)]

    def ConsumeIntListInRange(self, count, low, high):
        return [self.ConsumeIntInRange(low, high) for _ in range(count)]

    def ConsumeBool(self):
        return bool(self.ConsumeUInt(1) & 1)

    def ConsumeProbability(self):
        return self.ConsumeUInt(8) / float(0xFFFFFFFFFFFFFFFF)

    def ConsumeFloatInRange(self, low, high):
        if low > high:
            raise ValueError("ConsumeFloatInRange: min must not exceed max")
        base, span = low, high - low
        if math.isinf(span):
            span = high / 2.0 - low / 2.0
            if self.ConsumeBool():
                base += span
        return base + span * self.ConsumeProbability()

    def ConsumeRegularFloat(self):
        return self.ConsumeFloatInRange(-sys.float_info.max, sys.float_info.max)

    def ConsumeFloat(self):
        special = (0.0, -0.0, float("inf"), float("-inf"), float("nan"),
                   sys.float_info.max, -sys.float_info.max, sys.float_info.min)
        pick = self.ConsumeUInt(1)
        if pick < len(special):
            return special[pick]
        return self.ConsumeRegularFloat()

    def ConsumeFloatList(self, count):
        return [self.ConsumeFloat() for _ in range(count)]

    def ConsumeRegularFloatList(self, count):
        return [self.ConsumeRegularFloat() for _ in range(count)]

    def ConsumeProbabilityList(self, count):
        return [self.ConsumeProbability() for _ in range(count)]

    def ConsumeFloatListInRange(self, count, low, high):
        return [self.ConsumeFloatInRange(low, high) for _ in range(count)]

    def PickValueInList(self, values):
        if not values:
            raise ValueError("PickValueInList: the list is empty")
        return values[self.ConsumeIntInRange(0, len(values) - 1)]
"#;

/// Write the launcher `harnesses/<id>/main` and its launch spec: the
/// interpreter on bhf's driver, with the harness module, the coverage trace
/// prefix, the target package and `pythonpath`, and `extra_env` after them.
fn write_launcher(
    auto_dir: &Path,
    python: &Path,
    trace_prefix: &Path,
    package: &str,
    pythonpath: &str,
    extra_env: &[(&str, &str)],
) -> Result<(), String> {
    // Emit the launcher `main`. Carries the BHF_FRAMED marker the engine greps
    // for; the interpreter inherits BHF_FRAMED + BHF_COV_SHM across the exec.
    let main_path = auto_dir.join("main");
    let driver = auto_dir.join("bhf_driver.py");
    let extra: String = extra_env
        .iter()
        .map(|(key, value)| format!("{key}=\"{value}\" \\\n"))
        .collect();
    let script = format!(
        "#!/bin/sh\n\
         # BHF_FRAMED BHF_PY_LAUNCHER bhf CPython driver launcher (native Python lane).\n\
         # The engine sets BHF_FRAMED + BHF_COV_SHM in the environment; the\n\
         # interpreter inherits them across this exec. bhf_cov joins the file-backed\n\
         # BHF_COV_SHM map; bhf_driver speaks the framed fork-server protocol.\n\
         # PYTHONDONTWRITEBYTECODE: don't write __pycache__ at import time — its mkdir\n\
         # would otherwise trip the insecure-permissions behavioral oracle (BHF-416) on\n\
         # the interpreter's own bytecode cache, a false positive unrelated to the target.\n\
         BHF_HARNESS_MODULE=\"bhfgen.harness\" \\\n\
         BHF_TRACE_PREFIX=\"{trace}\" \\\n\
         BHF_TARGET_PACKAGE=\"{pkg}\" \\\n\
         BHF_COVERED_LINES=\"{covered}\" \\\n\
         {extra}\
         PYTHONDONTWRITEBYTECODE=1 \\\n\
         PYTHONPATH=\"{pythonpath}{separator}${{PYTHONPATH}}\" \\\n\
         exec \"{python}\" -B \"{driver}\" \"$@\"\n",
        trace = trace_prefix.display(),
        pkg = package,
        covered = auto_dir.join("covered-lines.txt").display(),
        pythonpath = pythonpath,
        // The host's separator: on Windows a `:` would join the inherited
        // path onto the last entry, which then names no directory.
        separator = if cfg!(windows) { ';' } else { ':' },
        python = python.display(),
        driver = driver.display(),
    );
    std::fs::write(&main_path, script)
        .map_err(|e| format!("write launcher {}: {e}", main_path.display()))?;
    make_executable(&main_path).map_err(|e| format!("chmod +x {}: {e}", main_path.display()))?;
    // The same launch where the shell script cannot run (#305): a native
    // Windows host execs the interpreter on the driver with this
    // environment.
    let inherited = std::env::var("PYTHONPATH").unwrap_or_default();
    let mut env = vec![
        ("BHF_HARNESS_MODULE".to_owned(), "bhfgen.harness".to_owned()),
        (
            "BHF_TRACE_PREFIX".to_owned(),
            trace_prefix.display().to_string(),
        ),
        ("BHF_TARGET_PACKAGE".to_owned(), package.to_owned()),
        (
            "BHF_COVERED_LINES".to_owned(),
            auto_dir.join("covered-lines.txt").display().to_string(),
        ),
    ];
    env.extend(
        extra_env
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    );
    env.push(("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned()));
    env.push((
        "PYTHONPATH".to_owned(),
        if inherited.is_empty() {
            pythonpath.to_owned()
        } else {
            format!(
                "{pythonpath}{}{inherited}",
                if cfg!(windows) { ';' } else { ':' }
            )
        },
    ));
    let launch = replay_min::Launch {
        program: python.to_path_buf(),
        args: vec!["-B".to_owned(), driver.display().to_string()],
        env,
    };
    crate::launch_spec::write(&main_path, &launch)
        .map_err(|e| format!("write launch spec in {}: {e}", auto_dir.display()))
}

/// A resolved target: the matched function plus, for an instance method, the
/// receiver-construction expression (`_t.Class()`).
struct ResolvedTarget {
    func: PyFunction,
    /// How an instance method's receiver is built, or `None` for a
    /// module-level function / `@staticmethod` / `@classmethod`.
    receiver: Option<Receiver>,
}

/// Re-parse the candidate source, find the function by (qualified name, line), and
/// resolve the receiver for an instance method ([`resolve_receiver`]).
fn resolve_target(candidate: &Candidate) -> Result<ResolvedTarget, String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    // A Python 2 source fails the Python 3 grammar; discovery read it with the
    // tolerant extractor, and so does this.
    let functions = if candidate.dialect == Some(lang_profile::Dialect::Python2) {
        python_parser::parse_python2_functions(&source)
    } else {
        parse_python_functions(&source).map_err(|_| "failed to parse Python source".to_owned())?
    };
    let func = functions
        .iter()
        .find(|f| f.qualified() == candidate.name && f.line == candidate.line)
        .or_else(|| functions.iter().find(|f| f.qualified() == candidate.name))
        .cloned()
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))?;

    let receiver = resolve_receiver(&func, &functions)?;
    Ok(ResolvedTarget { func, receiver })
}

/// How an instance method's receiver is built: `_t.<class>(r0, r1, ...)`, one
/// argument per required `__init__` parameter, decoded from the input ahead of
/// the method's own arguments (#286).
struct Receiver {
    class: String,
    params: Vec<python_parser::PyParam>,
}

/// Resolve an instance method's receiver. `None` for module fns / static / class
/// methods. An instance method's receiver is its class built from the required
/// parameters of its `__init__` (none when this file defines no `__init__`),
/// each decoded as a method parameter of its annotation or name is. An
/// annotated parameter of a type the decoder cannot build (a class, a union)
/// is an `Err`, so the target skips cleanly.
fn resolve_receiver(func: &PyFunction, all: &[PyFunction]) -> Result<Option<Receiver>, String> {
    if !func.is_method || func.is_staticmethod || func.is_classmethod {
        return Ok(None);
    }
    let Some(class) = func.class_name.as_deref() else {
        return Ok(None);
    };
    // The parser already drops the implicit `self`, so a non-default, non-varargs
    // param of `__init__` is a REQUIRED constructor argument.
    let params: Vec<python_parser::PyParam> = all
        .iter()
        .find(|f| f.class_name.as_deref() == Some(class) && f.name == "__init__")
        .map(|init| {
            init.params
                .iter()
                .filter(|p| !p.is_varargs && !p.has_default)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(param) = params.iter().find(|p| {
        p.annotation
            .as_deref()
            .is_some_and(|ann| !decodable_annotation(ann))
    }) {
        return Err(format!(
            "instance method `{}` needs a receiver, but `{class}.__init__` parameter \
             `{}: {}` is not a scalar, str, bytes, container or stream bhf can decode \
             (skipped cleanly)",
            func.qualified(),
            param.name,
            param.annotation.as_deref().unwrap_or_default()
        ));
    }
    Ok(Some(Receiver {
        class: class.to_owned(),
        params,
    }))
}

/// Whether [`decode_expr`] builds a value of annotation `ann` (rather than
/// handing raw bytes to a parameter of some other type): a union counts when
/// one of its members does ([`effective_annotation`]).
fn decodable_annotation(ann: &str) -> bool {
    single_decodable(&effective_annotation(ann))
}

/// Whether [`decode_expr`] builds a value of the one (non-union) annotation `ann`.
fn single_decodable(ann: &str) -> bool {
    let inner = ann.trim();
    matches!(inner, "int" | "float" | "bool" | "boolean" | "IO")
        || is_path_annotation(inner)
        || [
            "str",
            "bytes",
            "bytearray",
            "memoryview",
            "dict",
            "Dict",
            "Mapping",
            "list",
            "List",
            "Sequence",
            "Iterable",
            "set",
            "Set",
            "frozenset",
        ]
        .iter()
        .any(|family| {
            inner == *family
                || inner
                    .strip_prefix(family)
                    .is_some_and(|rest| rest.starts_with('['))
        })
        || [
            "TextIO",
            "StringIO",
            "BinaryIO",
            "BytesIO",
            "IO[",
            "BufferedReader",
            "BufferedIOBase",
        ]
        .iter()
        .any(|stream| inner.contains(stream))
}

/// A filesystem-path annotation: `Path`, `pathlib.Path`, `PurePath`,
/// `os.PathLike[str]`.
fn is_path_annotation(ann: &str) -> bool {
    let base = ann.split('[').next().unwrap_or(ann).trim();
    matches!(
        base.rsplit('.').next().unwrap_or(base),
        "Path" | "PurePath" | "PurePosixPath" | "PathLike"
    )
}

/// The annotation [`decode_expr`] decodes `ann` as (#286): `ann` itself, or,
/// for a union (`A | B`, `Union[A, B]`, `Optional[A]`), its first member that
/// [`decode_expr`] can build (`str` of `str | os.PathLike[str]`). A union with
/// no such member is returned as written.
fn effective_annotation(ann: &str) -> String {
    let ann = ann.trim();
    let members: Vec<String> = if let Some(inner) = ann
        .strip_prefix("Optional[")
        .and_then(|rest| rest.strip_suffix(']'))
    {
        vec![inner.trim().to_owned()]
    } else if let Some(inner) = ann
        .strip_prefix("Union[")
        .and_then(|rest| rest.strip_suffix(']'))
    {
        split_top_level(inner, ',')
    } else if split_top_level(ann, '|').len() > 1 {
        split_top_level(ann, '|')
    } else {
        return ann.to_owned();
    };
    members
        .into_iter()
        .filter(|member| member != "None")
        .find(|member| single_decodable(member))
        .unwrap_or_else(|| ann.to_owned())
}

/// `text` split at each `separator` outside brackets, each part trimmed.
fn split_top_level(text: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in text.chars() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            _ => {}
        }
        if c == separator && depth == 0 {
            parts.push(current.trim().to_owned());
            current.clear();
        } else {
            current.push(c);
        }
    }
    parts.push(current.trim().to_owned());
    parts
}

/// Map a source file to `(import_root_dir, dotted_module)`. Walks up through
/// directories that contain `__init__.py` to find the package root; the directory
/// ABOVE the top package goes on PYTHONPATH and the module is the dotted path from
/// there. A file with no package ancestry imports as its bare stem from its own dir.
fn resolve_module(source_path: &Path, source_root: &Path) -> (PathBuf, String) {
    let stem = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("module")
        .to_owned();
    let Some(mut dir) = source_path.parent().map(Path::to_path_buf) else {
        return (source_root.to_path_buf(), stem);
    };
    let mut parts = vec![stem];
    // Walk up while the directory is a package (has __init__.py).
    while dir.join("__init__.py").is_file() {
        let pkg = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        if pkg.is_empty() {
            break;
        }
        parts.push(pkg);
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => break,
        }
    }
    parts.reverse();
    (dir, parts.join("."))
}

/// Decide how to decode one parameter from the fuzz cursor, by annotation then
/// name heuristic. `last` controls whether a byte/str param drains the rest.
fn decode_expr(p: &python_parser::PyParam, last: bool) -> String {
    let effective = effective_annotation(p.annotation.as_deref().unwrap_or(""));
    let ann = effective.as_str();
    let name = p.name.to_ascii_lowercase();
    // A path annotation gets a `pathlib.Path` of decoded text.
    if is_path_annotation(ann) {
        let text = if last {
            "_c.rest().decode('utf-8', 'replace')"
        } else {
            "_c.text()"
        };
        return format!("__import__('pathlib').Path({text})");
    }
    // A file-like param (`fp`/`file`/`stream` or an IO annotation) must NOT get raw
    // bytes — `bytes` has no `.read()`, which would manufacture an AttributeError
    // false positive (plistlib.load(fp)). Wrap the fuzz bytes in a real stream.
    let is_text_file = ann.contains("TextIO") || ann.contains("StringIO");
    let is_file = is_text_file
        || ann.contains("BinaryIO")
        || ann.contains("BytesIO")
        || ann.contains("IO[")
        || ann == "IO"
        || ann.contains("BufferedReader")
        || ann.contains("BufferedIOBase")
        || matches!(
            name.as_str(),
            "fp" | "file" | "fileobj" | "fobj" | "infile" | "stream" | "f" | "readable"
        );
    if is_file {
        let bytes_expr = if last {
            "_c.rest()"
        } else {
            "_c.take_bytes(_c.bounded_length(0, _c.remaining()))"
        };
        return if is_text_file {
            format!("io.StringIO({bytes_expr}.decode('utf-8', 'replace'))")
        } else {
            format!("io.BytesIO({bytes_expr})")
        };
    }
    // Container params: synthesize an empty container rather than raw bytes, so an
    // internal function with an output `kwds: dict` / `out: list` (e.g.
    // email DateHeader.parse(value, kwds)) is fuzzed sensibly instead of raising a
    // wrong-type error on `bytes['key']=...`. Keyword-ish names map to dict too.
    let is_dict = ann.starts_with("dict")
        || ann.starts_with("Dict")
        || ann.contains("Mapping")
        || matches!(
            name.as_str(),
            "kwds" | "kw" | "kwargs" | "options" | "opts" | "params" | "attrs" | "headers"
        );
    let is_list = ann.starts_with("list")
        || ann.starts_with("List")
        || ann.starts_with("Sequence")
        || ann.starts_with("Iterable")
        || matches!(name.as_str(), "items" | "elements" | "rows" | "args");
    let is_set = ann.starts_with("set") || ann.starts_with("Set") || ann.starts_with("frozenset");
    if is_dict {
        return "{}".to_owned();
    }
    if is_list {
        return "[]".to_owned();
    }
    if is_set {
        return "set()".to_owned();
    }
    let is_bytes = ann.starts_with("bytes")
        || ann.starts_with("bytearray")
        || ann.starts_with("memoryview")
        || matches!(
            name.as_str(),
            "data" | "buf" | "buffer" | "payload" | "raw" | "blob" | "b" | "bytes_" | "chunk"
        );
    let is_str = ann.starts_with("str")
        || matches!(
            name.as_str(),
            "text" | "s" | "string" | "content" | "src" | "source" | "line" | "msg" | "message"
        );
    let is_int = ann == "int" || matches!(name.as_str(), "n" | "size" | "length" | "count" | "i");
    let is_float = ann == "float";
    let is_bool = ann == "bool" || ann == "boolean";
    if is_int {
        "_c.i32()".to_owned()
    } else if is_float {
        "_c.f64()".to_owned()
    } else if is_bool {
        "_c.boolean()".to_owned()
    } else if is_str {
        if last {
            "_c.rest().decode('utf-8', 'replace')".to_owned()
        } else {
            "_c.text()".to_owned()
        }
    } else if is_bytes {
        if last {
            "_c.rest()".to_owned()
        } else {
            "_c.take_bytes(_c.bounded_length(0, _c.remaining()))".to_owned()
        }
    } else {
        // Unknown/unannotated -> hand it raw bytes (the most fuzzable default).
        if last {
            "_c.rest()".to_owned()
        } else {
            "_c.take_bytes(_c.bounded_length(0, _c.remaining()))".to_owned()
        }
    }
}

/// Emit `bhfgen/harness.py` exposing `bhf_run_one(data: bytes)`. Decodes
/// only the REQUIRED parameters (skip defaulted + `*args`/`**kwargs`) so we never
/// pass a keyword-only-with-default param positionally (e.g. `loads(s, *,
/// parse_float=...)` -> `loads(a0)`). For an instance method, construct a fresh
/// receiver per input so each input starts from clean state.
fn generate_harness(module: &str, func: &PyFunction, receiver: Option<&Receiver>) -> String {
    let decodable: Vec<&python_parser::PyParam> = func
        .params
        .iter()
        .filter(|p| !p.is_varargs && !p.has_default)
        .collect();
    let n = decodable.len();
    let mut lines = String::new();
    // The receiver's constructor arguments come first: the method's last
    // argument takes the rest of the input.
    let mut receiver_args = Vec::new();
    for (i, p) in receiver
        .map(|r| r.params.as_slice())
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        lines.push_str(&format!("    r{i} = {}\n", decode_expr(p, false)));
        receiver_args.push(format!("r{i}"));
    }
    let mut args = Vec::new();
    for (i, p) in decodable.iter().enumerate() {
        let last = i + 1 == n;
        lines.push_str(&format!("    a{i} = {}\n", decode_expr(p, last)));
        args.push(format!("a{i}"));
    }
    let arglist = args.join(", ");
    let call = match receiver {
        // Instance method: fresh receiver per input, then call the bare method name.
        Some(recv) => format!(
            "    _recv = _t.{class}({ctor})\n    _recv.{method}({arglist})\n",
            class = recv.class,
            ctor = receiver_args.join(", "),
            method = func.name,
            arglist = arglist,
        ),
        // Module fn / @staticmethod / @classmethod: an attribute path on the module.
        None => format!(
            "    _t.{}({arglist})\n",
            func.qualified(),
            arglist = arglist
        ),
    };
    // A module whose name is not a Python identifier cannot be reached by an
    // `import` statement — git ships `git-p4.py`, and `import git-p4 as _t` is a
    // syntax error that failed every target in the file. importlib takes the
    // name as a string and loads it happily.
    let import = if is_importable_identifier(module) {
        format!("import {module} as _t\n")
    } else {
        format!("import importlib\n_t = importlib.import_module(\"{module}\")\n")
    };
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         # Generated by bhf (native Python lane). Decodes fuzz bytes into typed\n\
         # arguments and calls the target. Do not edit.\n\
         import io\n\
         import os\n\
         import bhf_decode\n\
         {import}\
         {probe}\
         \n\
         def bhf_run_one(data):\n\
         \x20   _c = bhf_decode.open_cursor(data)\n\
         {lines}    _bhf_mark_target_entry()\n\
         {call}",
        import = import,
        probe = TARGET_ENTRY_PROBE,
        lines = lines,
        call = call,
    )
}

/// Whether every dotted segment of `module` is a Python identifier, so an
/// `import` statement can name it. Real trees are full of module files that are
/// not: `git-p4.py`, `2to3.py`, `pre-commit.py`.
fn is_importable_identifier(module: &str) -> bool {
    !module.is_empty()
        && module.split('.').all(|segment| {
            !segment.is_empty()
                && !segment.starts_with(|c: char| c.is_ascii_digit())
                && segment.chars().all(|c| c.is_alphanumeric() || c == '_')
        })
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
    use super::*;

    fn func(name: &str, params: &[(&str, Option<&str>)], method: bool) -> PyFunction {
        PyFunction {
            name: name.to_owned(),
            line: 1,
            params: params
                .iter()
                .map(|(n, a)| python_parser::PyParam {
                    name: (*n).to_owned(),
                    annotation: a.map(|s| s.to_owned()),
                    is_varargs: false,
                    has_default: false,
                })
                .collect(),
            decorators: Vec::new(),
            return_annotation: None,
            is_method: method,
            class_name: if method { Some("C".to_owned()) } else { None },
            is_staticmethod: false,
            is_classmethod: false,
            is_property: false,
            is_async: false,
            is_private: false,
            is_dunder: false,
        }
    }

    #[test]
    fn a_module_name_that_is_not_an_identifier_is_imported_by_string() {
        // git ships `git-p4.py`. `import git-p4 as _t` is a syntax error, so
        // every target in the file failed to build with "SyntaxError: invalid
        // syntax" — a bhf bug reported as if the project's code were broken.
        assert!(is_importable_identifier("pkg.mod"));
        assert!(is_importable_identifier("_private"));
        assert!(!is_importable_identifier("git-p4"));
        assert!(!is_importable_identifier("2to3"));
        assert!(!is_importable_identifier("pkg.git-p4"));
        assert!(!is_importable_identifier(""));

        let h = generate_harness(
            "git-p4",
            &func("decode_text_stream", &[("s", None)], false),
            None,
        );
        assert!(
            h.contains("importlib.import_module(\"git-p4\")"),
            "a hyphenated module must load by string: {h}"
        );
        assert!(!h.contains("import git-p4 as"), "{h}");
        // An ordinary module keeps the plain import.
        let plain = generate_harness("pkg.mod", &func("parse", &[("s", None)], false), None);
        assert!(plain.contains("import pkg.mod as _t"), "{plain}");
    }

    #[test]
    fn single_bytes_param_gets_whole_input() {
        let h = generate_harness(
            "pkg.mod",
            &func("parse", &[("data", Some("bytes"))], false),
            None,
        );
        assert!(h.contains("import pkg.mod as _t"));
        assert!(h.contains("a0 = _c.rest()"));
        assert!(h.contains("_t.parse(a0)"));
        assert!(h.contains("def bhf_run_one(data):"));
        assert!(
            h.contains("    _bhf_mark_target_entry()\n    _t.parse(a0)"),
            "entry checkpoint must immediately precede the selected call: {h}"
        );
    }

    #[test]
    fn typed_params_decode_by_annotation() {
        let h = generate_harness(
            "m",
            &func(
                "f",
                &[("s", Some("str")), ("n", Some("int")), ("b", Some("bytes"))],
                false,
            ),
            None,
        );
        assert!(h.contains("a0 = _c.text()")); // str, not last
        assert!(h.contains("a1 = _c.i32()"));
        assert!(h.contains("a2 = _c.rest()")); // bytes, last
        assert!(h.contains("_t.f(a0, a1, a2)"));
    }

    #[test]
    fn staticmethod_call_uses_qualified_path() {
        let mut m = func("decode", &[("data", Some("bytes"))], true);
        m.is_staticmethod = true;
        let h = generate_harness("m", &m, None);
        assert!(h.contains("_t.C.decode(a0)"));
    }

    #[test]
    fn instance_method_constructs_receiver_and_skips_defaulted_params() {
        let mut m = func("feed", &[("chunk", Some("bytes"))], true);
        // Add a defaulted param that must NOT be decoded/passed.
        m.params.push(python_parser::PyParam {
            name: "strict".to_owned(),
            annotation: Some("bool".to_owned()),
            is_varargs: false,
            has_default: true,
        });
        let recv = Receiver {
            class: "C".to_owned(),
            params: Vec::new(),
        };
        let h = generate_harness("m", &m, Some(&recv));
        assert!(h.contains("_recv = _t.C()"), "constructs receiver:\n{h}");
        assert!(
            h.contains("_recv.feed(a0)"),
            "calls bare method on receiver:\n{h}"
        );
        assert!(!h.contains("a1"), "defaulted param must be skipped:\n{h}");
    }

    /// #286: a receiver whose `__init__` takes arguments is built from them,
    /// decoded ahead of the method's own, so the method's last parameter
    /// still takes the rest of the input.
    #[test]
    fn a_receiver_is_built_from_its_init_arguments() {
        let source = "class Parser:\n\
                      \x20   def __init__(self, limit: int, name, strict=True):\n\
                      \x20       self.limit = limit\n\
                      \x20   def feed(self, data: bytes):\n\
                      \x20       return data[: self.limit]\n";
        let all = parse_python_functions(source).unwrap();
        let feed = all.iter().find(|f| f.name == "feed").unwrap();
        let recv = resolve_receiver(feed, &all).unwrap().unwrap();
        assert_eq!(recv.class, "Parser");
        let names: Vec<&str> = recv.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["limit", "name"],
            "the defaulted `strict` is left out"
        );
        let h = generate_harness("m", feed, Some(&recv));
        let r0 = h.find("    r0 = _c.i32()").expect(&h);
        let r1 = h.find("    r1 = _c.take_bytes(").expect(&h);
        let a0 = h.find("    a0 = _c.rest()").expect(&h);
        assert!(r0 < r1 && r1 < a0, "constructor arguments first:\n{h}");
        assert!(
            h.contains("_recv = _t.Parser(r0, r1)\n    _recv.feed(a0)"),
            "{h}"
        );
    }

    /// An `__init__` parameter annotated with a type the decoder cannot build
    /// still skips cleanly, and names the parameter.
    #[test]
    fn an_init_parameter_of_an_undecodable_type_skips_the_target() {
        let source = "class Session:\n\
                      \x20   def __init__(self, config: Config):\n\
                      \x20       self.config = config\n\
                      \x20   def handle(self, data: bytes):\n\
                      \x20       return data\n";
        let all = parse_python_functions(source).unwrap();
        let handle = all.iter().find(|f| f.name == "handle").unwrap();
        let error = resolve_receiver(handle, &all).err().unwrap();
        assert!(error.contains("parameter `config: Config`"), "{error}");
        for ann in [
            "int",
            "Optional[str]",
            "bytes",
            "Dict[str, int]",
            "List[bytes]",
            "BinaryIO",
            "Union[int, str]",
            "str | Path",
            "Path",
            "os.PathLike[str]",
        ] {
            assert!(decodable_annotation(ann), "{ann}");
        }
        for ann in [
            "Config",
            "Union[Config, Listener]",
            "App | None",
            "strategy",
        ] {
            assert!(!decodable_annotation(ann), "{ann}");
        }
    }

    /// A union decodes as its first member the decoder builds, and a path
    /// annotation as a `pathlib.Path` of decoded text.
    #[test]
    fn a_union_decodes_as_its_first_buildable_member_and_a_path_as_path() {
        assert_eq!(effective_annotation("str | os.PathLike[str]"), "str");
        assert_eq!(effective_annotation("Optional[bytes]"), "bytes");
        assert_eq!(effective_annotation("Union[Config, int]"), "int");
        assert_eq!(
            effective_annotation("None | Dict[str, int]"),
            "Dict[str, int]"
        );
        assert_eq!(effective_annotation("Config | None"), "Config | None");
        assert_eq!(
            decode_expr(&param("root", Some("str | os.PathLike[str]")), false),
            "_c.text()"
        );
        assert_eq!(
            decode_expr(&param("workspace", Some("Path")), false),
            "__import__('pathlib').Path(_c.text())"
        );
        assert_eq!(
            decode_expr(&param("limit", Some("Optional[int]")), false),
            "_c.i32()"
        );
    }

    fn param(name: &str, ann: Option<&str>) -> python_parser::PyParam {
        python_parser::PyParam {
            name: name.to_owned(),
            annotation: ann.map(|s| s.to_owned()),
            is_varargs: false,
            has_default: false,
        }
    }

    #[test]
    fn file_param_wrapped_in_stream_not_raw_bytes() {
        // `fp` by name -> BytesIO (binary); avoids the `bytes has no .read()` FP.
        assert!(decode_expr(&param("fp", None), true).contains("io.BytesIO"));
        // An IO annotation -> BytesIO.
        assert!(decode_expr(&param("x", Some("BinaryIO")), true).contains("io.BytesIO"));
        // A text IO annotation -> StringIO.
        assert!(decode_expr(&param("x", Some("TextIO")), true).contains("io.StringIO"));
    }

    #[test]
    fn container_params_synthesize_empty_containers() {
        assert_eq!(decode_expr(&param("kwds", None), true), "{}");
        assert_eq!(decode_expr(&param("x", Some("dict")), true), "{}");
        assert_eq!(decode_expr(&param("items", None), true), "[]");
        assert_eq!(decode_expr(&param("x", Some("set")), true), "set()");
    }

    #[test]
    fn harness_imports_io_for_file_params() {
        let mut f = func("load", &[("fp", None)], false);
        f.params = vec![param("fp", None)];
        let h = generate_harness("plistlib", &f, None);
        assert!(h.contains("import io"));
        assert!(h.contains("io.BytesIO"));
        assert!(h.contains("_t.load(a0)"));
    }

    #[test]
    fn resolve_module_walks_packages() {
        // Build a temp tree: root/pkg/sub/mod.py with __init__.py in pkg and sub.
        let tmp = crate::test_support::TestDir::new("gfpytest");
        let sub = tmp.join("pkg").join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(tmp.join("pkg").join("__init__.py"), "").unwrap();
        std::fs::write(sub.join("__init__.py"), "").unwrap();
        let modf = sub.join("mod.py");
        std::fs::write(&modf, "def f(): pass\n").unwrap();
        let (root, module) = resolve_module(&modf, &tmp);
        assert_eq!(root, tmp.path());
        assert_eq!(module, "pkg.sub.mod");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// True if `code` contains an f-string prefix at a token boundary (so we do
    /// not misflag `stuff"` as an f-string).
    fn has_fstring(code: &str) -> bool {
        let b = code.as_bytes();
        for i in 0..b.len() {
            if b[i] == b'f' && i + 1 < b.len() && (b[i + 1] == b'"' || b[i + 1] == b'\'') {
                let boundary = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
                if boundary {
                    return true;
                }
            }
        }
        false
    }

    #[test]
    fn bundled_driver_imports_on_python_3_0_no_fstrings() {
        // M22 Phase 1b: the driver must import on Python 3.0-3.5 (legacy gov/mil
        // interpreters), so it must contain no f-strings (a SyntaxError <3.6).
        let runtime = locate_python_runtime().expect("python_runtime locatable in-tree");
        let driver = std::fs::read_to_string(runtime.join("bhf_driver.py")).unwrap();
        for (i, line) in driver.lines().enumerate() {
            let code = line.split('#').next().unwrap_or("");
            assert!(
                !has_fstring(code),
                "f-string at line {} breaks Python <3.6 import: {line}",
                i + 1
            );
        }
    }

    /// #285: a Python 2 source runs under a `python2`, `python2.7` or 2.x
    /// `python` interpreter, and a Python 3 source never does. Stub
    /// interpreters answer the version probe.
    #[cfg(unix)]
    #[test]
    fn the_interpreter_follows_the_source_dialect() {
        use lang_profile::Dialect;
        use std::os::unix::fs::PermissionsExt;
        let stub = |dir: &Path, name: &str, version: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\nprintf '{version}'\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let both = crate::test_support::TestDir::new("py-interp-both");
        let python2 = stub(both.path(), "python2", "2.7");
        let python3 = stub(both.path(), "python3", "3.12");
        let path = Some(both.path().as_os_str());
        assert_eq!(
            select_interpreter(Some(Dialect::Python2), path),
            Ok(python2)
        );
        assert_eq!(select_interpreter(None, path), Ok(python3.clone()));
        assert_eq!(
            select_interpreter(Some(Dialect::Python3), path),
            Ok(python3)
        );

        // A legacy host's only `python` is 2.x: the Python 2 source takes it,
        // a Python 3 source is told why it cannot.
        let legacy = crate::test_support::TestDir::new("py-interp-legacy");
        let python = stub(legacy.path(), "python", "2.7");
        let path = Some(legacy.path().as_os_str());
        assert_eq!(select_interpreter(Some(Dialect::Python2), path), Ok(python));
        let error = select_interpreter(None, path).unwrap_err();
        assert!(
            error.contains("is Python 2.7 and this is a Python 3 source"),
            "{error}"
        );

        // `python2.7` alone serves; a 3.x `python` does not.
        let versioned = crate::test_support::TestDir::new("py-interp-27");
        stub(versioned.path(), "python", "3.11");
        let python27 = stub(versioned.path(), "python2.7", "2.7");
        let path = Some(versioned.path().as_os_str());
        assert_eq!(
            select_interpreter(Some(Dialect::Python2), path),
            Ok(python27)
        );

        let none = crate::test_support::TestDir::new("py-interp-none");
        stub(none.path(), "python3", "3.12");
        let error =
            select_interpreter(Some(Dialect::Python2), Some(none.path().as_os_str())).unwrap_err();
        assert!(error.contains("no `python2` interpreter found"), "{error}");
    }

    #[test]
    fn an_atheris_harness_module_calls_the_registered_function_after_the_entry_probe() {
        let h = generate_atheris_harness("fuzz_records", "TestOneInput");
        assert!(
            h.contains("_t = importlib.import_module(\"fuzz_records\")\n"),
            "{h}"
        );
        assert!(
            h.contains("_bhf_entry = getattr(_t, \"TestOneInput\")\n"),
            "{h}"
        );
        assert!(
            h.ends_with(
                "\ndef bhf_run_one(data):\n    _bhf_mark_target_entry()\n    _bhf_entry(data)\n"
            ),
            "{h}"
        );
        // The same entry probe as a generated harness's.
        let generated = generate_harness("m", &func("f", &[("data", None)], false), None);
        assert!(h.contains(TARGET_ENTRY_PROBE) && generated.contains(TARGET_ENTRY_PROBE));
        assert!(
            generated.contains("        pass\n\n\ndef bhf_run_one(data):\n"),
            "{generated}"
        );
    }

    /// The stand-in `atheris` decodes a FuzzedDataProvider's values from the
    /// input, and its Setup and Fuzz return at once.
    #[test]
    fn the_atheris_stand_in_decodes_values_from_the_input() {
        let Ok(python) = select_interpreter(None, None) else {
            return; // no interpreter installed
        };
        let dir = crate::test_support::TestDir::new("py-atheris-stand-in");
        std::fs::create_dir_all(dir.join("atheris")).unwrap();
        std::fs::write(dir.join("atheris/__init__.py"), ATHERIS_STAND_IN).unwrap();
        let script = "import sys, atheris\n\
            assert atheris.Setup(['prog', '-runs=1'], len) == ['prog', '-runs=1']\n\
            assert atheris.registered == [len] and atheris.Fuzz() is None\n\
            with atheris.instrument_imports():\n    import json\n\
            assert atheris.instrument_func(len) is len\n\
            fdp = atheris.FuzzedDataProvider(b'\\x06\\xff\\x02AB\\x01\\x07\\x00XYZ')\n\
            print(fdp.ConsumeIntInRange(0, 3), fdp.ConsumeInt(1), fdp.ConsumeUnicode(2),\n\
            \x20     fdp.ConsumeBool(), fdp.ConsumeUInt(2), fdp.remaining_bytes(),\n\
            \x20     fdp.ConsumeBytes(atheris.ALL_REMAINING), fdp.ConsumeInt(4),\n\
            \x20     fdp.PickValueInList(['only']))\n";
        let out = Command::new(&python)
            .args(["-B", "-c", script])
            .env("PYTHONPATH", dir.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // 6 % 4; 0xff as a signed byte; an ASCII spec byte, then "AB"; 1 & 1;
        // 0x0007 little-endian; what is left; nothing left reads as 0.
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"),
            "2 -1 AB True 7 3 b'XYZ' 0 only\n"
        );
    }

    /// An Atheris harness builds into a launcher that runs its registered
    /// function on each input, with its seed corpus and dictionary, and
    /// reports every exception it lets escape, a ValueError included.
    #[cfg(unix)]
    #[test]
    fn an_atheris_harness_builds_and_every_exception_it_lets_escape_is_a_finding() {
        if select_interpreter(None, None).is_err() || locate_python_runtime().is_none() {
            return;
        }
        let root = crate::test_support::TestDir::new("py-atheris-build");
        let tree = root.join("tree");
        let write = |path: &Path, text: &[u8]| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write(
            &tree.join("widget/__init__.py"),
            b"def parse_record(data):\n    if data.startswith(b'BAD'):\n        \
              raise ValueError('planted')\n    return len(data)\n",
        );
        let harness = tree.join("fuzz/fuzz_widget.py");
        write(
            &harness,
            b"import sys\nimport atheris\n\nwith atheris.instrument_imports():\n    \
              import widget\n\n\ndef TestOneInput(data):\n    widget.parse_record(data)\n\n\n\
              def main():\n    atheris.Setup(sys.argv, TestOneInput)\n    atheris.Fuzz()\n\n\n\
              if __name__ == '__main__':\n    main()\n",
        );
        write(&tree.join("fuzz/fuzz_widget.dict"), b"bad=\"BAD\"\n");
        write(&tree.join("fuzz/corpus/fuzz_widget/one"), b"GOOD");
        let found =
            crate::auto::provided::discover(&tree, &crate::auto::discovery::DirFilter::default());
        assert_eq!(found.len(), 1, "{found:?}");
        let work = root.join("work");
        let result = build_python_harness(&found[0], &work, "H-P1", &tree);
        if let PythonBuildResult::Failed { reason, .. } = &result {
            panic!("the Atheris harness did not build: {reason}");
        }
        let dir = crate::auto::layout::harness_dir(&work, "H-P1");
        let record = crate::auto::provided::read_record(&dir).expect("a provided record");
        assert_eq!(record.origin, crate::auto::provided::Origin::Atheris);
        assert_eq!(record.entry, "TestOneInput");
        assert_eq!(record.seeds, 1);
        assert_eq!(record.dictionary_tokens, 1);
        assert_eq!(
            record.dictionaries,
            [crate::workdir::plain_canonical(
                &tree.join("fuzz/fuzz_widget.dict")
            )]
        );
        assert_eq!(crate::auto::provided::load_seeds(&dir), [b"GOOD".to_vec()]);
        assert!(std::fs::read_to_string(dir.join("dictionary.txt"))
            .unwrap()
            .contains("\"BAD\""));
        let launcher = std::fs::read_to_string(dir.join("main")).unwrap();
        assert!(
            launcher.contains("BHF_PY_EVERY_EXCEPTION=\"1\""),
            "{launcher}"
        );

        let replay = |input: &[u8]| {
            let file = root.join("input");
            std::fs::write(&file, input).unwrap();
            Command::new(dir.join("main"))
                .arg(&file)
                .env_remove("BHF_FRAMED")
                .output()
                .unwrap()
        };
        let ok = replay(b"GOOD");
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        let bad = replay(b"BAD!");
        let stderr = String::from_utf8_lossy(&bad.stderr);
        assert_eq!(bad.status.code(), Some(86), "{stderr}");
        assert!(
            stderr.contains("== bhf python finding: ValueError: planted"),
            "{stderr}"
        );
        assert!(stderr.contains("in parse_record"), "{stderr}");
        // The finding is the library's: the harness's own frame only handed
        // the input on.
        let report = corpus::sanitizer::parse_sanitizer_report(&stderr).expect("a Python finding");
        let widget = crate::workdir::plain_canonical(&tree.join("widget/__init__.py"));
        assert_eq!(
            (
                report.stack[0].function.as_str(),
                report.stack[0].file.as_deref(),
                report.stack[0].line
            ),
            ("parse_record", widget.to_str(), Some(3)),
            "{stderr}"
        );
    }

    #[test]
    fn python_version_parses_installed_interpreter() {
        let Ok(py) = select_interpreter(None, None) else {
            return; // no interpreter installed -> skip, like a GNAT-less Ada skip
        };
        let v = python_version(&py).expect("python_version should parse a real interpreter");
        assert!(v.0 >= 2, "major version is sane: {v:?}");
    }
}
