// SPDX-License-Identifier: Apache-2.0

//! COBOL harness build (M3.4) — see [`crate::auto::cobol`] for the strategy.
//!
//! Step 0 of the attempt loop for a `Lang::Cobol` candidate: translate the COBOL
//! subprogram to C with `cobc -C -debug -fec=all` (free/fixed format detected,
//! copybook dirs added as `-I`), generate a `LLVMFuzzerTestOneInput` glue that
//! drives the `PROCEDURE DIVISION USING` operands from the fuzz bytes, reuse the
//! passthrough C fork-server driver + coverage/cmplog runtime, and build with
//! `libcob` linked. The result at `harnesses/<id>/main` is a normal bhf C
//! harness the built-in engine drives unchanged.
//!
//! On native Windows (#430) GnuCOBOL is a MinGW build: its libcob uses
//! MinGW's ABI and C runtime, so the driver, the glue and the translated
//! program build with the MinGW gcc in GnuCOBOL's `bin`, which has no
//! AddressSanitizer. libcob's runtime checks stay the crash oracle: the glue
//! turns a runtime error during the target call into a crash through an
//! error procedure registered with libcob, since a DLL's `exit` cannot be
//! interposed. The DLLs the harness loads from GnuCOBOL's `bin` are placed
//! beside `main.exe`, and the harness records [`WINDOWS_SANITIZER_LIMIT`] for
//! its findings' fidelity.

use crate::auto::candidate::Candidate;
use crate::auto::cobol::{CobolParam, CobolParamKind};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub enum CobolBuildResult {
    Built,
    /// Not fuzzable here (no `cobc`, no byte-buffer LINKAGE operand) — skip cleanly.
    Skip(String),
    /// A genuine build failure.
    Failed(String),
}

/// `cob-config --cflags` / `--libs`, or conservative defaults when the helper is
/// absent. libcob is LGPLv3 and links into the user's harness (like the GNAT
/// runtime), never into bhf.
fn cob_config(flag: &str) -> Vec<String> {
    if let Ok(o) = Command::new("cob-config").arg(flag).output() {
        if o.status.success() {
            let toks: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect();
            if !toks.is_empty() {
                return toks;
            }
        }
    }
    match flag {
        "--libs" => vec!["-lcob".to_owned(), "-lm".to_owned()],
        _ => Vec::new(),
    }
}

fn have_cobc() -> bool {
    Command::new("cobc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether the source is free-format (code from column 1, `*>` comments) vs the
/// fixed 80-column format. An explicit `>>SOURCE FORMAT` directive wins.
fn is_free_format(source: &str) -> bool {
    for line in source.lines() {
        let u = line.to_ascii_uppercase();
        if u.contains(">>SOURCE FORMAT") || u.contains(">> SOURCE FORMAT") {
            if u.contains("FREE") {
                return true;
            }
            if u.contains("FIXED") {
                return false;
            }
        }
    }
    source.lines().any(|l| {
        l.contains("*>")
            || (l.starts_with(|c: char| c.is_ascii_alphabetic()) && {
                let u = l.trim_end().to_ascii_uppercase();
                u.starts_with("IDENTIFICATION DIVISION")
                    || u.starts_with("PROGRAM-ID")
                    || u.starts_with("DATA DIVISION")
                    || u.starts_with("PROCEDURE DIVISION")
                    || u.starts_with("ENVIRONMENT DIVISION")
                    || u.starts_with("WORKING-STORAGE")
            })
    })
}

/// How deep below its search root the copybook search reads directories.
const COPYBOOK_SEARCH_DEPTH: usize = 6;
/// Most directory entries the copybook search visits.
const COPYBOOK_SEARCH_ENTRIES: usize = 20_000;
/// Most copybook directories passed to `cobc`.
const COPYBOOK_SEARCH_DIRS: usize = 200;

/// Directories to pass to `cobc` as copybook search paths (`-I`): the source
/// file's own directory plus every directory under the search root that holds
/// a `.cpy` copybook. The search root is the project holding the source (the
/// nearest directory with `.git`) inside `scan_root`, the tree `bhf auto`
/// scans, else `scan_root` itself: the search never goes above `scan_root`, so
/// a tree that is not a git checkout does not reach a shared directory such
/// as `/tmp`, or another project's copybooks. A source outside `scan_root`
/// gets its own directory only. The walk is bounded by depth, by the entries
/// it visits and by the directories it returns, and does not follow
/// symlinked directories.
fn copybook_includes(source_path: &Path, scan_root: &Path) -> Vec<PathBuf> {
    let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let Some(source_dir) = source_path.parent() else {
        return Vec::new();
    };
    dirs.insert(source_dir.to_path_buf());
    if let Some(root) = copybook_search_root(source_dir, scan_root) {
        collect_cpy_dirs(&root, COPYBOOK_SEARCH_ENTRIES, &mut dirs);
    }
    dirs.into_iter().collect()
}

/// The root of the copybook search for a source in `source_dir`: the nearest
/// directory with `.git` from `source_dir` up to `scan_root` (a file's
/// directory when `bhf auto` was given one file), else `scan_root`; `None`
/// when `source_dir` is not inside `scan_root`.
fn copybook_search_root(source_dir: &Path, scan_root: &Path) -> Option<PathBuf> {
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let source_dir = canonical(source_dir);
    let mut scan_root = canonical(scan_root);
    if scan_root.is_file() {
        scan_root.pop();
    }
    if !source_dir.starts_with(&scan_root) {
        return None;
    }
    source_dir
        .ancestors()
        .take_while(|dir| dir.starts_with(&scan_root))
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
        .or(Some(scan_root))
}

/// Add every directory under `root` that holds a `.cpy` file to `out`,
/// reading at most [`COPYBOOK_SEARCH_DEPTH`] levels and `max_entries`
/// entries. Returns the number of entries visited.
fn collect_cpy_dirs(root: &Path, max_entries: usize, out: &mut BTreeSet<PathBuf>) -> usize {
    let mut visited = 0;
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if visited >= max_entries || out.len() > COPYBOOK_SEARCH_DIRS {
                return visited;
            }
            visited += 1;
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if depth < COPYBOOK_SEARCH_DEPTH
                    && !matches!(name, ".git" | "target" | "node_modules" | ".svn")
                {
                    pending.push((path, depth + 1));
                }
            } else if path
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("cpy"))
            {
                out.insert(dir.clone());
            }
        }
    }
    visited
}

/// Recover the C entry symbol GnuCOBOL emitted: `int   PROGID (cob_u8_t *...)`
/// (whitespace/tab-separated; the PROGRAM-ID may be mixed-case with `_` for `-`).
/// Recover the C entry symbol for the TARGET program `program_id` from cobc's
/// generated C. `cobc -C` emits a C function per `PROGRAM-ID` in the source, so a
/// multi-program file yields several `int Name(cob_u8_t *…)` entries; picking the
/// FIRST one drives the wrong program (e.g. targeting CobolCraft `Facing-FromString`
/// but calling `Facing-GetRelative` — whose numeric-first operand fuzzed to garbage
/// then indexed a stack array out of bounds: a false positive). Match the entry
/// whose de-mangled name equals `program_id` (cobc mangles `-` to `__`; normalize by
/// dropping every non-alphanumeric char and upper-casing both sides). Fall back to
/// the first entry when nothing matches (single-program files / unusual mangling).
/// On Windows cobc writes the entry's declaration after its export macro,
/// `COB_EXT_EXPORT int NAME (...)`.
fn recover_entry_symbol(generated_c: &str, program_id: &str) -> Option<String> {
    let normalize = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect()
    };
    let want = normalize(program_id);
    let mut first: Option<String> = None;
    for line in generated_c.lines() {
        let t = line.trim_start();
        let t = t
            .strip_prefix("COB_EXT_EXPORT")
            .filter(|rest| rest.starts_with(|c: char| c.is_whitespace()))
            .map_or(t, str::trim_start);
        let Some(rest) = t.strip_prefix("int") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let rest = rest.trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let after = rest[name.len()..].trim_start();
        if !after.starts_with("(cob_u8_t") {
            continue;
        }
        if normalize(&name) == want {
            return Some(name);
        }
        first.get_or_insert(name);
    }
    first
}

/// Whether `program_id` was compiled by cobc as a NESTED program — a `static int`
/// C function whose name (de-mangled: cobc appends a `_0_`/`_0__` nesting suffix)
/// begins with the target's normalized name. Such a function has internal linkage and
/// cannot be reached from the generated harness, so the target is skipped rather than
/// reported as a failed build.
fn is_nested_static_program(generated_c: &str, program_id: &str) -> bool {
    let normalize = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect()
    };
    let want = normalize(program_id);
    if want.is_empty() {
        return false;
    }
    for line in generated_c.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("static int") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let rest = rest.trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = rest[name.len()..].trim_start();
        if !after.starts_with("(cob_u8_t") {
            continue;
        }
        // cobc mangles a nested program `getquery` to `getquery_0__`; normalized that is
        // `GETQUERY0`, which starts with the wanted `GETQUERY`.
        if normalize(&name).starts_with(&want) {
            return true;
        }
    }
    false
}

/// Pick the operand to set to the fuzz byte count: a numeric operand named
/// `*LEN*`/`*LENGTH*`/`*SIZE*`/`*COUNT*`, else the numeric operand immediately
/// after the primary buffer.
fn length_param_index(params: &[CobolParam], primary: usize) -> Option<usize> {
    let named = params.iter().position(|p| {
        matches!(p.kind, CobolParamKind::Numeric { .. }) && {
            let u = p.name.to_ascii_uppercase();
            u.contains("LEN") || u.contains("SIZE") || u.contains("COUNT")
        }
    });
    if named.is_some() {
        return named;
    }
    let next = primary + 1;
    if params
        .get(next)
        .is_some_and(|p| matches!(p.kind, CobolParamKind::Numeric { .. }))
    {
        Some(next)
    } else {
        None
    }
}

fn materialized_path_param_index(params: &[CobolParam]) -> Option<usize> {
    let path = params.iter().position(|param| {
        matches!(param.kind, CobolParamKind::Bytes { .. }) && {
            let name = param.name.to_ascii_uppercase();
            name.contains("PATH") || name.contains("FILE-NAME") || name.contains("FILENAME")
        }
    })?;
    let has_output_buffer = params.iter().enumerate().any(|(index, param)| {
        index != path && matches!(param.kind, CobolParamKind::Bytes { .. }) && {
            let name = param.name.to_ascii_uppercase();
            name.contains("BUFFER") || name.contains("CONTENT") || name.contains("OUTPUT")
        }
    });
    has_output_buffer.then_some(path)
}

/// The `LLVMFuzzerTestOneInput` glue that drives every `USING` operand.
pub(crate) fn multi_param_glue(entry: &str, params: &[CobolParam]) -> String {
    // A path plus a separate output buffer is a read-file protocol, not a path
    // parser. An expert harness materializes the fuzz bytes as a real file and
    // passes its stable path; feeding arbitrary bytes as the filename exercises
    // almost nothing beyond OPEN's error branch.
    let materialized_path = materialized_path_param_index(params);
    let primary = params
        .iter()
        .position(|p| matches!(p.kind, CobolParamKind::Bytes { .. }))
        .unwrap_or(0);
    let len_idx = materialized_path
        .is_none()
        .then(|| length_param_index(params, primary))
        .flatten();

    let mut decls = String::new();
    let mut fills = String::new();
    let mut cleanup = String::new();
    let mut args: Vec<String> = Vec::new();
    for (i, p) in params.iter().enumerate() {
        let var = format!("bhf_b{i}");
        let is_primary = i == primary;
        match p.kind {
            CobolParamKind::Bytes { len: Some(n) } if Some(i) == materialized_path => {
                let n = n.max(1);
                decls.push_str(&format!(
                    "    static unsigned char {var}[{n}];\n\
                     #ifdef _WIN32\n    char bhf_temp_path[MAX_PATH] = \"\";\n\
                     #else\n    char bhf_temp_path[] = \"/tmp/bhf-cobol-XXXXXX\";\n#endif\n\
                     \x20   int bhf_temp_created = 0;\n"
                ));
                fills.push_str(&format!(
                    "    memset({var}, ' ', {n});\n\
                     #ifdef _WIN32\n\
                     \x20   {{ char _dir[MAX_PATH]; DWORD _dn = GetTempPathA(MAX_PATH, _dir); if (_dn > 0 && _dn < MAX_PATH && GetTempFileNameA(_dir, \"bhf\", 0, bhf_temp_path)) {{ FILE *_f = fopen(bhf_temp_path, \"wb\"); bhf_temp_created = 1; if (_f) {{ if (Size) fwrite(Data, 1, Size, _f); fclose(_f); size_t _pn = strlen(bhf_temp_path); if (_pn > {n}) _pn = {n}; memcpy({var}, bhf_temp_path, _pn); bhf_primary_len = Size; }} }} }}\n\
                     #else\n\
                     \x20   {{ int _fd = mkstemp(bhf_temp_path); if (_fd >= 0) {{ size_t _off = 0; while (_off < Size) {{ ssize_t _w = write(_fd, Data + _off, Size - _off); if (_w <= 0) break; _off += (size_t)_w; }} close(_fd); bhf_temp_created = 1; size_t _pn = strlen(bhf_temp_path); if (_pn > {n}) _pn = {n}; memcpy({var}, bhf_temp_path, _pn); bhf_primary_len = Size; }} }}\n\
                     #endif\n"
                ));
                cleanup.push_str("    if (bhf_temp_created) remove(bhf_temp_path);\n");
            }
            CobolParamKind::Bytes { len: Some(n) } if is_primary => {
                let n = n.max(1);
                decls.push_str(&format!("    static unsigned char {var}[{n}];\n"));
                fills.push_str(&format!(
                    "    memset({var}, ' ', {n});\n    {{ size_t _n = Size < {n} ? Size : (size_t){n}; if (_n) memcpy({var}, Data, _n); bhf_primary_len = _n; }}\n"
                ));
            }
            CobolParamKind::Bytes { len: None } if is_primary => {
                decls.push_str(&format!("    static unsigned char {var}[65536];\n"));
                fills.push_str(&format!(
                    "    memset({var}, 0, sizeof {var});\n    {{ size_t _n = Size < sizeof {var} ? Size : sizeof {var}; if (_n) memcpy({var}, Data, _n); bhf_primary_len = _n; }}\n"
                ));
            }
            CobolParamKind::Bytes { len: Some(n) } => {
                let n = n.max(1);
                decls.push_str(&format!("    static unsigned char {var}[{n}];\n"));
                fills.push_str(&format!("    memset({var}, ' ', {n});\n"));
            }
            CobolParamKind::Numeric { width } if Some(i) == len_idx => {
                let w = width.clamp(1, 8);
                decls.push_str(&format!("    unsigned char {var}[8];\n"));
                fills.push_str(&format!(
                    "    memset({var}, 0, sizeof {var});\n    {{ size_t _v = bhf_primary_len; for (int _k = 0; _k < {w}; _k++) {var}[{w}-1-_k] = (unsigned char)((_v >> (8*_k)) & 0xff); }}\n"
                ));
            }
            _ => {
                // Secondary ANY-LENGTH buffers, other numerics, groups: a generous
                // zeroed scratch so the program's reads/writes stay in bounds.
                decls.push_str(&format!("    static unsigned char {var}[256];\n"));
                fills.push_str(&format!("    memset({var}, 0, sizeof {var});\n"));
            }
        }
        args.push(format!("(cob_u8_t *){var}"));
    }

    let extern_sig = if params.is_empty() {
        "void".to_owned()
    } else {
        vec!["cob_u8_t *"; params.len()].join(", ")
    };
    let call_args = args.join(", ");

    format!(
        "/* SPDX-License-Identifier: Apache-2.0 */\n\
         /* bhf COBOL glue: drives {entry}({n} operand(s)) from fuzzer bytes. */\n\
         /* {marker}: LLVMFuzzerTestOneInput below is bhf's, not the project's. */\n\
         #include <stdint.h>\n\
         #include <stdio.h>\n\
         #include <stdlib.h>\n\
         #include <string.h>\n\
         #ifdef _WIN32\n\
         #define WIN32_LEAN_AND_MEAN\n\
         #include <windows.h>\n\
         #else\n\
         #include <unistd.h>\n\
         #endif\n\
         #include <libcob.h>\n\
         extern int {entry}({extern_sig});\n\
         extern void bhf_target_enter(void);\n\
         static volatile int bhf_in_target = 0;\n\
         #ifdef _WIN32\n\
         /* Native Windows: libcob is a DLL whose exit() is the C runtime's, which\n\
         \x20* the harness cannot interpose. A libcob runtime check (EC-BOUND-*,\n\
         \x20* EC-SIZE-*, zero divide, ...) calls the error procedure registered with\n\
         \x20* libcob (CBL_ERROR_PROC), prints its message and exits nonzero, which bhf\n\
         \x20* would classify as an input REJECTION not a crash. When that exit comes\n\
         \x20* during a target call, the atexit handler ends the process as bhf's\n\
         \x20* driver ends a faulting one: a BHF_CRASH line and the exit code\n\
         \x20* BHF_WIN_CRASH_EXIT (0x39). A STOP RUN, or an error outside a target\n\
         \x20* call, exits as it would. */\n\
         static volatile int bhf_cob_error = 0;\n\
         static int bhf_cob_error_proc(char *message) {{\n\
         \x20   (void)message;\n\
         \x20   if (bhf_in_target) bhf_cob_error = 1;\n\
         \x20   return 1;\n\
         }}\n\
         static void bhf_cob_atexit(void) {{\n\
         \x20   if (!bhf_in_target || !bhf_cob_error) return;\n\
         \x20   fprintf(stderr, \"BHF_CRASH libcob runtime error\\n\");\n\
         \x20   fflush(stderr);\n\
         \x20   TerminateProcess(GetCurrentProcess(), 0x39);\n\
         }}\n\
         static void bhf_cob_hooks(void) {{\n\
         \x20   unsigned char bhf_install = 0;\n\
         \x20   int (*bhf_proc)(char *) = bhf_cob_error_proc;\n\
         \x20   cob_get_global_ptr()->cob_call_params = 2;\n\
         \x20   cob_sys_error_proc(&bhf_install, (void *)&bhf_proc);\n\
         \x20   atexit(bhf_cob_atexit);\n\
         }}\n\
         #else\n\
         /* Interpose exit(): a libcob runtime check (EC-BOUND-*, EC-SIZE-*, zero\n\
         \x20* divide, ...) reports a COBOL-semantic defect via a nonzero exit, which\n\
         \x20* bhf would classify as an input REJECTION not a crash. ONLY while a\n\
         \x20* target call is in flight, force a genuine crash signal (SIGSEGV) so the\n\
         \x20* fuzzer records it, with the libcob + COBOL frames on the stack. A\n\
         \x20* nonzero exit outside a target call (ASan leak check on libcob's\n\
         \x20* by-design retained memory, teardown) passes through as a clean exit. */\n\
         __attribute__((noreturn)) void exit(int code) {{\n\
         \x20   if (code != 0 && bhf_in_target) {{ *(volatile int *)0 = 0; }}\n\
         \x20   _exit(0);\n\
         }}\n\
         static void bhf_cob_hooks(void) {{}}\n\
         #endif\n\
         static int bhf_cob_ready = 0;\n\
         int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{\n\
         \x20   if (!bhf_cob_ready) {{ cob_init(0, (char **)0); bhf_cob_hooks(); bhf_cob_ready = 1; }}\n\
         \x20   size_t bhf_primary_len = 0; (void)bhf_primary_len; (void)Data;\n\
         {decls}\
         {fills}\
         \x20   bhf_target_enter();\n\
         \x20   bhf_in_target = 1;\n\
         \x20   int bhf_rc = {entry}({call_args});\n\
         \x20   bhf_in_target = 0;\n\
         {cleanup}\
         \x20   return bhf_rc;\n\
         }}\n",
        n = params.len(),
        cleanup = cleanup,
        marker = crate::replay::GENERATED_ENTRY_MARKER,
    )
}

/// The harness binary a COBOL build writes into `hdir`, if it is there:
/// `main`, or `main.exe` on Windows, where the harness Makefile names it so.
pub(crate) fn harness_binary(hdir: &Path) -> Option<PathBuf> {
    let main_bin = crate::auto::layout::harness_exe(hdir, "main");
    main_bin.is_file().then_some(main_bin)
}

/// What a native Windows COBOL harness records in
/// [`SANITIZER_LIMIT_RECORD`](crate::auto::fortran_build::SANITIZER_LIMIT_RECORD).
pub(crate) const WINDOWS_SANITIZER_LIMIT: &str =
    "none (toolchain limit): GnuCOBOL for Windows is a MinGW build, whose libcob links only \
     with MinGW's gcc, and MinGW's GCC ships no AddressSanitizer; libcob's runtime checks \
     (cobc -fec=all) stood in for it";

/// GnuCOBOL's `bin` directory on native Windows: the one that holds
/// `cobc.exe` and the MinGW gcc GnuCOBOL was built with (its libcob uses
/// that gcc's ABI and C runtime). A `PATH` entry holding both, else the
/// `bin` beside `COB_MAIN_DIR` (set by GnuCOBOL's `set_env.cmd`) or beside
/// `COB_CONFIG_DIR` (set by its Chocolatey package, whose `cobc` on `PATH` is
/// a shim).
fn gnucobol_bin(
    path: &[PathBuf],
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let is_toolchain = |dir: &Path| dir.join("cobc.exe").is_file() && dir.join("gcc.exe").is_file();
    let from_env = |key: &str, up: usize| {
        let mut dir = PathBuf::from(env(key).filter(|value| !value.is_empty())?);
        for _ in 0..up {
            dir = dir.parent()?.to_path_buf();
        }
        Some(dir.join("bin"))
    };
    path.iter()
        .find(|dir| is_toolchain(dir))
        .cloned()
        .or_else(|| from_env("COB_MAIN_DIR", 0).filter(|dir| is_toolchain(dir)))
        .or_else(|| from_env("COB_CONFIG_DIR", 1).filter(|dir| is_toolchain(dir)))
}

/// The DLLs in GnuCOBOL's `bin` that `harness` loads, directly or through
/// one another (libcob and what it loads: GMP, Berkeley DB, the GCC
/// runtime, ...), as `imports` names each file's imported DLLs. Windows
/// matches DLL names without regard to case.
fn runtime_dlls(
    harness: &Path,
    bin: &Path,
    imports: &dyn Fn(&Path) -> Vec<String>,
) -> Vec<PathBuf> {
    let in_bin: std::collections::HashMap<String, PathBuf> = std::fs::read_dir(bin)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().to_lowercase(),
                entry.path(),
            )
        })
        .filter(|(name, _)| name.ends_with(".dll"))
        .collect();
    let mut found: BTreeSet<PathBuf> = BTreeSet::new();
    let mut pending = vec![harness.to_path_buf()];
    while let Some(file) = pending.pop() {
        for name in imports(&file) {
            if let Some(dll) = in_bin.get(&name.to_lowercase()) {
                if found.insert(dll.clone()) {
                    pending.push(dll.clone());
                }
            }
        }
    }
    found.into_iter().collect()
}

/// Put `files` in `dir` under their own names, hard-linked where the volume
/// allows it and copied otherwise, replacing what a previous build left.
fn place_beside(dir: &Path, files: &[PathBuf]) -> std::io::Result<()> {
    for file in files {
        let Some(name) = file.file_name() else {
            continue;
        };
        let placed = dir.join(name);
        let _ = std::fs::remove_file(&placed);
        if std::fs::hard_link(file, &placed).is_err() {
            std::fs::copy(file, &placed)?;
        }
    }
    Ok(())
}

/// The DLLs a PE file imports.
fn pe_imports(file: &Path) -> Vec<String> {
    std::fs::read(file)
        .map(|bytes| binary_analysis::pe_import_libraries(&bytes))
        .unwrap_or_default()
}

/// How a native Windows COBOL harness is built: with the MinGW gcc in
/// GnuCOBOL's `bin`, against the libcob headers and import library beside
/// it, without sanitizers.
struct MingwCobol {
    bin: PathBuf,
}

impl MingwCobol {
    fn root(&self) -> PathBuf {
        self.bin
            .parent()
            .map_or_else(|| self.bin.clone(), Path::to_path_buf)
    }

    /// `cobc` with GnuCOBOL's `bin` first on `PATH`, and its `config` as
    /// `COB_CONFIG_DIR` unless one is set: a `bin` added to `PATH` by hand
    /// has no `set_env.cmd` behind it, and its cobc looks for its
    /// configuration where GnuCOBOL was built.
    fn cobc(&self) -> Command {
        let mut cobc = Command::new(self.bin.join("cobc.exe"));
        cobc.env("PATH", self.path());
        let config = self.root().join("config");
        if std::env::var_os("COB_CONFIG_DIR").is_none() && config.join("default.conf").is_file() {
            cobc.env("COB_CONFIG_DIR", config);
        }
        cobc
    }

    /// `PATH` with GnuCOBOL's `bin` first, so its gcc runs its own assembler
    /// and linker, not those of another MinGW earlier on `PATH`.
    fn path(&self) -> std::ffi::OsString {
        let rest = std::env::var_os("PATH").unwrap_or_default();
        std::env::join_paths(std::iter::once(self.bin.clone()).chain(std::env::split_paths(&rest)))
            .unwrap_or(rest)
    }

    /// The C flags that find `libcob.h`.
    fn cflags(&self) -> Vec<String> {
        vec![format!(
            "-I{}",
            crate::auto::fortran_build::make_command_path(&self.root().join("include"))
        )]
    }

    /// The link flags of libcob's import library.
    fn libs(&self) -> String {
        let lib = crate::auto::fortran_build::make_command_path(&self.root().join("lib"));
        if lib.contains(' ') {
            format!("\"-L{lib}\" -lcob")
        } else {
            format!("-L{lib} -lcob")
        }
    }

    /// Have `make` build with GnuCOBOL's gcc and the flags it supports.
    fn configure_make(&self, make: &mut Command) {
        make.env("PATH", self.path())
            .env(
                "CC",
                crate::auto::fortran_build::make_command_path(&self.bin.join("gcc.exe")),
            )
            .env("BHF_CC_FAMILY", "gcc")
            .env(
                crate::build::MAKE_BHF_CFLAGS,
                crate::auto::fortran_build::WINDOWS_C_FLAGS,
            );
    }
}

/// Build the COBOL harness for `candidate` into `harnesses/<harness_id>/`.
///
/// `source_root` is the tree `bhf auto` scans: the copybook search never
/// leaves it.
pub fn build_cobol_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> CobolBuildResult {
    if !have_cobc() {
        return CobolBuildResult::Skip(
            "no `cobc` (GnuCOBOL) toolchain found; install gnucobol to fuzz COBOL".to_owned(),
        );
    }
    // Native Windows: GnuCOBOL is a MinGW build, so the harness builds with
    // the MinGW gcc in its `bin`, without sanitizers.
    let mingw = if cfg!(windows) {
        let path: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        match gnucobol_bin(&path, &|key| std::env::var_os(key)) {
            Some(bin) => Some(MingwCobol { bin }),
            None => {
                return CobolBuildResult::Skip(
                    "GnuCOBOL's bin directory, with cobc.exe and the MinGW gcc.exe GnuCOBOL was \
                     built with, is not on PATH (and neither COB_MAIN_DIR nor COB_CONFIG_DIR \
                     names it): put it on PATH, or run GnuCOBOL's set_env.cmd, to fuzz COBOL \
                     on Windows"
                        .to_owned(),
                );
            }
        }
    } else {
        None
    };
    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&hdir) {
        return CobolBuildResult::Failed(format!("create {}: {e}", hdir.display()));
    }

    let source = match crate::source_text::read_source_text(&candidate.source_path) {
        Ok(s) => s,
        Err(e) => return CobolBuildResult::Failed(format!("read COBOL source: {e}")),
    };
    let programs = crate::auto::cobol::parse_cobol(&source);
    let program = programs
        .iter()
        .find(|p| p.program_id == candidate.name)
        .or_else(|| programs.first());
    let Some(program) = program.filter(|p| p.is_fuzzable()) else {
        return CobolBuildResult::Skip(format!(
            "{}: no fuzzable LINKAGE byte-buffer operand (no USING PIC X input surface)",
            candidate.name
        ));
    };

    // Translate COBOL -> C with runtime bound checks (`-fec=all`); detect
    // free-format and add copybook search dirs so real projects translate.
    let target_c = hdir.join("cobol_target.c");
    let mut cmd = mingw
        .as_ref()
        .map_or_else(|| Command::new("cobc"), MingwCobol::cobc);
    cmd.arg("-C").arg("-debug").arg("-fec=all");
    if is_free_format(&source) {
        cmd.arg("-free");
    }
    for inc in copybook_includes(&candidate.source_path, source_root) {
        cmd.arg("-I").arg(inc);
    }
    cmd.arg("-o").arg(&target_c).arg(&candidate.source_path);
    match crate::command_output::output_with_timeout(
        &mut cmd,
        std::time::Duration::from_secs(30 * 60),
    ) {
        Ok(o) if o.status.success() && target_c.is_file() => {}
        Ok(o) => {
            return CobolBuildResult::Failed(format!(
                "cobc -C failed: {}",
                String::from_utf8_lossy(&o.stderr)
                    .lines()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        Err(e) => return CobolBuildResult::Failed(format!("spawn cobc: {e}")),
    }

    let generated = std::fs::read_to_string(&target_c).unwrap_or_default();
    let Some(entry) = recover_entry_symbol(&generated, &program.program_id) else {
        // A NESTED (contained) COBOL program — one whose `END PROGRAM` precedes its
        // enclosing program's — is compiled by cobc as a `static` C function (mangled
        // `name_0_`, internal linkage), only callable from its parent via `CALL`. It has
        // no external entry the harness can link, so skip it cleanly (the COBOL analog of
        // a Fortran private module procedure / a C# internal-class method) rather than
        // reporting a confusing failed_build.
        if is_nested_static_program(&generated, &program.program_id) {
            return CobolBuildResult::Skip(format!(
                "{}: nested COBOL program (cobc compiles it as a static C function, not \
                 externally callable)",
                program.program_id
            ));
        }
        return CobolBuildResult::Failed(
            "could not recover the C entry symbol from cobc output".to_owned(),
        );
    };

    let glue_c = hdir.join("cobol_glue.c");
    if let Err(e) = std::fs::write(&glue_c, multi_param_glue(&entry, &program.params)) {
        return CobolBuildResult::Failed(format!("write glue: {e}"));
    }

    // Passthrough C driver (main.c) + Makefile; the COBOL C + glue are extra
    // sources, cob-config cflags (GnuCOBOL's include dir on Windows) let the
    // driver see libcob headers.
    let gen_result = harness_gen::c_generate::generate_c_direct_harness(
        harness_gen::c_generate::GenerateCDirectArgs {
            environment: None,
            harness_id: harness_id.to_owned(),
            output_dir: hdir.clone(),
            source_path: candidate.source_path.clone(),
            target: c_parser::CFunction {
                name: "LLVMFuzzerTestOneInput".to_owned(),
                line: 0,
                return_type: "int".to_owned(),
                params: Vec::new(),
                is_static: false,
                foreign_guard: None,
                variadic: false,
            },
            params: Vec::new(),
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![target_c.clone(), glue_c.clone()],
            compile_flags: mingw
                .as_ref()
                .map_or_else(|| cob_config("--cflags"), MingwCobol::cflags),
            target_declared_in_header: false,
            c_runtime_include: crate::generate_harness::locate_c_runtime(),
            type_defs: Vec::new(),
            result_cleanup: None,
            lifecycle: Vec::new(),
            drive_plan: None,
            decoder_limits: harness_gen::c_decoders::DecoderLimits::default(),
            force: false,
        },
    );
    if let Err(e) = gen_result {
        return CobolBuildResult::Failed(format!("generate C driver: {e}"));
    }

    let libs = mingw
        .as_ref()
        .map_or_else(|| cob_config("--libs").join(" "), MingwCobol::libs);
    let mut make = Command::new("make");
    make.current_dir(&hdir).env("AUTO_EXTRA_LDFLAGS", &libs);
    if let Some(mingw) = &mingw {
        mingw.configure_make(&mut make);
    }
    let built = crate::command_output::output_with_timeout(
        &mut make,
        std::time::Duration::from_secs(30 * 60),
    );
    match built {
        Ok(o) if o.status.success() && harness_binary(&hdir).is_some() => {
            crate::build::record_lane_ldflags(&hdir, &libs);
            if let (Some(mingw), Some(main_bin)) = (&mingw, harness_binary(&hdir)) {
                // libcob and the DLLs it loads go beside the harness, which then
                // starts without GnuCOBOL's `bin` on PATH (a `bhf replay` from
                // another shell).
                let dlls = runtime_dlls(&main_bin, &mingw.bin, &pe_imports);
                if let Err(e) = place_beside(&hdir, &dlls) {
                    return CobolBuildResult::Failed(format!(
                        "put GnuCOBOL's DLLs beside the harness: {e}"
                    ));
                }
                let _ = std::fs::write(
                    hdir.join(crate::auto::fortran_build::SANITIZER_LIMIT_RECORD),
                    WINDOWS_SANITIZER_LIMIT,
                );
            }
            CobolBuildResult::Built
        }
        Ok(o) => CobolBuildResult::Failed(format!(
            "COBOL harness build failed: {}",
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .filter(|l| l.contains("error"))
                .take(3)
                .collect::<Vec<_>>()
                .join("; ")
        )),
        Err(e) => CobolBuildResult::Failed(format!("spawn make: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"       01 REC PIC X(8).\n").unwrap();
    }

    /// A COBOL source in a tree that is not a git checkout, inside a shared
    /// directory full of unrelated projects: the copybook search covers the
    /// tree being scanned and nothing above it, so another project's
    /// copybook is never put on the include path.
    #[test]
    fn the_copybook_search_stays_inside_the_scanned_tree() {
        let outer = tempfile::tempdir().unwrap();
        for i in 0..400 {
            std::fs::create_dir_all(outer.path().join(format!("other-{i}/src"))).unwrap();
        }
        touch(&outer.path().join("unrelated/copy/DECOY.cpy"));
        let tree = outer.path().join("ws/team/project");
        let source = tree.join("src/prog.cob");
        touch(&source);
        touch(&tree.join("copy/REC.cpy"));
        touch(&tree.join("lib/shared/copybooks/HDR.cpy"));

        let started = std::time::Instant::now();
        let dirs = copybook_includes(&source, &tree);
        let elapsed = started.elapsed();
        let canonical = |p: PathBuf| std::fs::canonicalize(&p).unwrap_or(p);
        let dirs: Vec<PathBuf> = dirs.into_iter().map(canonical).collect();
        for wanted in ["src", "copy", "lib/shared/copybooks"] {
            assert!(
                dirs.contains(&canonical(tree.join(wanted))),
                "{wanted} missing: {dirs:?}"
            );
        }
        let tree = canonical(tree);
        assert!(
            dirs.iter().all(|dir| dir.starts_with(&tree)),
            "the search left the scanned tree: {dirs:?}"
        );
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
    }

    /// Within the scanned tree, a git checkout holding the source is its
    /// project: copybooks are searched there, as before.
    #[test]
    fn the_copybook_search_uses_the_project_inside_the_scanned_tree() {
        let tree = tempfile::tempdir().unwrap();
        let project = tree.path().join("vendor/lib");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        let source = project.join("src/prog.cob");
        touch(&source);
        touch(&project.join("copy/LIB.cpy"));
        touch(&tree.path().join("other/copy/OTHER.cpy"));
        let canonical = |p: PathBuf| std::fs::canonicalize(&p).unwrap_or(p);
        let dirs: Vec<PathBuf> = copybook_includes(&source, tree.path())
            .into_iter()
            .map(canonical)
            .collect();
        assert!(dirs.contains(&canonical(project.join("copy"))), "{dirs:?}");
        assert!(
            !dirs.contains(&canonical(tree.path().join("other/copy"))),
            "{dirs:?}"
        );
    }

    /// `bhf auto` given one COBOL file scans that file's directory.
    #[test]
    fn a_single_scanned_file_searches_its_own_directory() {
        let tree = tempfile::tempdir().unwrap();
        let source = tree.path().join("prog.cob");
        touch(&source);
        touch(&tree.path().join("copy/REC.cpy"));
        let canonical = |p: PathBuf| std::fs::canonicalize(&p).unwrap_or(p);
        let dirs: Vec<PathBuf> = copybook_includes(&source, &source)
            .into_iter()
            .map(canonical)
            .collect();
        assert!(
            dirs.contains(&canonical(tree.path().join("copy"))),
            "{dirs:?}"
        );
    }

    /// The walk visits at most `max_entries` entries, however large the tree.
    #[test]
    fn the_copybook_walk_stops_after_its_entry_budget() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..150 {
            touch(&root.path().join(format!("d{i}/x.txt")));
        }
        let mut dirs = BTreeSet::new();
        let visited = collect_cpy_dirs(root.path(), 50, &mut dirs);
        assert!(visited <= 50, "{visited} entries visited");
    }

    fn param(name: &str, kind: CobolParamKind) -> CobolParam {
        CobolParam {
            name: name.to_owned(),
            kind,
        }
    }

    #[test]
    fn recovers_mixed_case_tab_separated_entry() {
        let c = "int\t\tBlocks__Parse (cob_u8_t *, cob_u8_t *, cob_u8_t *);\n";
        assert_eq!(
            recover_entry_symbol(c, "Blocks-Parse").as_deref(),
            Some("Blocks__Parse")
        );
    }

    /// cobc on Windows writes each program's entry as `COB_EXT_EXPORT int
    /// NAME (cob_u8_t *...)`, the export macro first.
    #[test]
    fn recovers_an_entry_cobc_exports_as_it_does_on_windows() {
        let c = "COB_EXT_EXPORT int\t\tPARSEIT (cob_u8_t *);\n\
                 static int\t\tPARSEIT_ (const int, cob_u8_t *);\n";
        assert_eq!(
            recover_entry_symbol(c, "PARSEIT").as_deref(),
            Some("PARSEIT")
        );
        assert!(!is_nested_static_program(c, "PARSEIT"));
    }

    /// The COBOL build's binary is `main`, or `main.exe` where the harness
    /// Makefile names it so (Windows); the build and the attempt's
    /// pass-through both find it.
    #[test]
    fn the_built_harness_is_found_under_the_name_the_makefile_gives_it() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(harness_binary(dir.path()), None);
        let name = crate::auto::layout::harness_exe_name("main");
        std::fs::write(dir.path().join(&name), b"MZ").unwrap();
        assert_eq!(harness_binary(dir.path()), Some(dir.path().join(&name)));
        if cfg!(windows) {
            assert_eq!(name, "main.exe");
        }
    }

    fn files(dir: &Path, names: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        for name in names {
            std::fs::write(dir.join(name), b"MZ").unwrap();
        }
    }

    /// The toolchain a Windows COBOL harness builds with is GnuCOBOL's `bin`
    /// directory, the one holding `cobc.exe` and the gcc it was built with:
    /// a PATH entry with both, else the one `COB_MAIN_DIR` (GnuCOBOL's
    /// `set_env.cmd`) or `COB_CONFIG_DIR` (its Chocolatey package) sits
    /// beside. A `cobc` shim alone, or another MinGW's gcc, is not it.
    #[test]
    fn the_windows_toolchain_is_the_gnucobol_bin_with_its_own_gcc() {
        let root = tempfile::tempdir().unwrap();
        let shim = root.path().join("chocolatey/bin");
        let other_gcc = root.path().join("strawberry/c/bin");
        let gnucobol = root.path().join("gnucobol");
        let bin = gnucobol.join("bin");
        files(&shim, &["cobc.exe", "make.exe"]);
        files(&other_gcc, &["gcc.exe", "gfortran.exe"]);
        files(&bin, &["cobc.exe", "gcc.exe", "libcob-4.dll"]);
        files(&gnucobol.join("config"), &["default.conf"]);
        let unset = |_: &str| None;

        let path = [shim.clone(), other_gcc.clone(), bin.clone()];
        assert_eq!(gnucobol_bin(&path, &unset), Some(bin.clone()));
        let path = [shim.clone(), other_gcc.clone()];
        assert_eq!(gnucobol_bin(&path, &unset), None);
        let config = gnucobol.join("config").into_os_string();
        let chocolatey = |key: &str| (key == "COB_CONFIG_DIR").then(|| config.clone());
        assert_eq!(gnucobol_bin(&path, &chocolatey), Some(bin.clone()));
        // set_env.cmd's COB_MAIN_DIR ends in a separator.
        let main_dir = format!("{}{}", gnucobol.display(), std::path::MAIN_SEPARATOR);
        let set_env = |key: &str| (key == "COB_MAIN_DIR").then(|| main_dir.clone().into());
        assert_eq!(gnucobol_bin(&path, &set_env), Some(bin));
    }

    /// A Windows harness runs with the GnuCOBOL DLLs it loads beside it, so
    /// it starts without GnuCOBOL's `bin` on PATH: libcob and what libcob
    /// loads from there, and none of the toolchain's other DLLs.
    #[test]
    fn the_harness_gets_the_gnucobol_dlls_it_loads_beside_it() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        files(
            &bin,
            &[
                "libcob-4.dll",
                "libgmp-10.dll",
                "libgcc_s_dw2-1.dll",
                "libstdc++-6.dll",
            ],
        );
        let harness = root.path().join("harness");
        files(&harness, &["main.exe"]);
        let imports = |path: &Path| -> Vec<String> {
            let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
            let names: &[&str] = match name.as_str() {
                "main.exe" => &["libcob-4.dll", "KERNEL32.dll", "msvcrt.dll"],
                "libcob-4.dll" => &["LIBGMP-10.DLL", "libgcc_s_dw2-1.dll", "msvcrt.dll"],
                "libgmp-10.dll" => &["libgcc_s_dw2-1.dll", "KERNEL32.dll"],
                _ => &["KERNEL32.dll"],
            };
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        let dlls = runtime_dlls(&harness.join("main.exe"), &bin, &imports);
        assert_eq!(
            dlls,
            ["libcob-4.dll", "libgcc_s_dw2-1.dll", "libgmp-10.dll"].map(|name| bin.join(name))
        );
        place_beside(&harness, &dlls).unwrap();
        // A rebuild in the same directory places them again.
        place_beside(&harness, &dlls).unwrap();
        for name in ["libcob-4.dll", "libgcc_s_dw2-1.dll", "libgmp-10.dll"] {
            assert!(harness.join(name).is_file(), "{name}");
        }
        assert!(!harness.join("libstdc++-6.dll").exists());
    }

    /// On native Windows libcob is a DLL whose `exit` the glue cannot
    /// interpose: the glue registers an error procedure with libcob and,
    /// when libcob exits after a runtime error during the target call, ends
    /// the process as bhf's driver ends a faulting one. Elsewhere it still
    /// interposes `exit`.
    #[test]
    fn the_glue_turns_a_libcob_runtime_error_into_a_crash_on_windows() {
        let glue = multi_param_glue(
            "PARSEIT",
            &[param("BUF", CobolParamKind::Bytes { len: Some(8) })],
        );
        let windows = glue.find("#ifdef _WIN32\n/* Native Windows").expect(&glue);
        let elsewhere = glue[windows..].find("#else\n").unwrap() + windows;
        let end = glue[elsewhere..].find("#endif\n").unwrap() + elsewhere;
        let (windows, elsewhere) = (&glue[windows..elsewhere], &glue[elsewhere..end]);
        assert!(
            windows.contains("cob_sys_error_proc(&bhf_install"),
            "{glue}"
        );
        assert!(windows.contains("atexit(bhf_cob_atexit)"), "{glue}");
        assert!(
            windows.contains("TerminateProcess(GetCurrentProcess(), 0x39)"),
            "{glue}"
        );
        assert!(!windows.contains("void exit(int code)"), "{glue}");
        assert!(elsewhere.contains("void exit(int code)"), "{glue}");
        assert!(
            glue.contains("cob_init(0, (char **)0); bhf_cob_hooks();"),
            "{glue}"
        );
    }

    /// The read-file protocol's temporary file is made with the host's own
    /// calls: `mkstemp` under `/tmp`, or `GetTempFileNameA` in the Windows
    /// temporary directory.
    #[test]
    fn the_materialized_input_file_is_made_on_either_host() {
        let params = vec![
            param("LS-FILE-PATH", CobolParamKind::Bytes { len: Some(512) }),
            param("LS-FILE-BUFFER", CobolParamKind::Bytes { len: Some(4096) }),
        ];
        let glue = multi_param_glue("FILE__OPS", &params);
        let windows = glue.find("GetTempFileNameA(").expect(&glue);
        let posix = glue.find("mkstemp(bhf_temp_path)").expect(&glue);
        let split = glue[..posix].rfind("#else\n").expect(&glue);
        assert!(windows < split, "{glue}");
        assert!(glue.contains("char bhf_temp_path[MAX_PATH]"), "{glue}");
    }

    #[test]
    fn ignores_non_cobol_int_decls() {
        assert_eq!(
            recover_entry_symbol("int main(int argc, char **argv)", "Anything"),
            None
        );
    }

    #[test]
    fn recovers_the_targeted_entry_in_a_multi_program_file() {
        // cobc emits a C function per PROGRAM-ID; the harness must drive the TARGET,
        // not whichever appears first. Regression for CobolCraft `Facing-FromString`
        // being driven as `Facing-GetRelative` (first in the file) -> stack OOB FP.
        let c = "\
int\t\tFacing__GetRelative (cob_u8_t *, cob_u8_t *);
int\t\tFacing__ToString (cob_u8_t *, cob_u8_t *);
int\t\tFacing__FromString (cob_u8_t *, cob_u8_t *);
";
        assert_eq!(
            recover_entry_symbol(c, "Facing-FromString").as_deref(),
            Some("Facing__FromString"),
            "must match the targeted program, not the first in the file"
        );
        assert_eq!(
            recover_entry_symbol(c, "Facing-GetRelative").as_deref(),
            Some("Facing__GetRelative")
        );
        // Unknown target falls back to the first entry (single-program / odd mangling).
        assert_eq!(
            recover_entry_symbol(c, "Nonexistent").as_deref(),
            Some("Facing__GetRelative")
        );
    }

    #[test]
    fn nested_program_is_static_and_detected() {
        // cobol-on-wheelchair: `getquery`/`checkquery` are NESTED programs inside `cow`,
        // which cobc compiles as `static int getquery_0__(...)` (internal linkage) — no
        // external entry the harness can link. recover_entry_symbol finds none (the only
        // non-static entry is the parameterless main `cow`), and the target is detected
        // as nested so the build skips instead of failing.
        let c = "\
int\t\tcow (void);
static int\t\tcow_ (const int);
static int\t\tgetquery_0__ (cob_u8_t *);
static int\t\tgetquery_0_ (const int, cob_u8_t *);
static int\t\tcheckquery_0__ (cob_u8_t *, cob_u8_t *, cob_u8_t *, cob_u8_t *);
";
        // No linkable entry for the nested program.
        assert_eq!(recover_entry_symbol(c, "getquery"), None);
        // It is recognized as a nested (static) program.
        assert!(is_nested_static_program(c, "getquery"));
        assert!(is_nested_static_program(c, "checkquery"));
        // A genuinely-absent program is NOT flagged nested.
        assert!(!is_nested_static_program(c, "nonexistent"));
        // A top-level program with a real external entry is not "nested".
        let top = "int\t\tParseit (cob_u8_t *);\n";
        assert!(!is_nested_static_program(top, "Parseit"));
        assert_eq!(
            recover_entry_symbol(top, "Parseit").as_deref(),
            Some("Parseit")
        );
    }

    #[test]
    fn detects_free_vs_fixed_format() {
        assert!(is_free_format("*> a free-format comment\nPROGRAM-ID. P.\n"));
        assert!(is_free_format("IDENTIFICATION DIVISION.\nPROGRAM-ID. P.\n"));
        assert!(is_free_format(">>SOURCE FORMAT FREE\n 01 X.\n"));
        assert!(!is_free_format(
            ">>SOURCE FORMAT FIXED\n       PROGRAM-ID. P.\n"
        ));
        assert!(!is_free_format("000100 PROGRAM-ID. P.\n"));
    }

    #[test]
    fn length_param_by_name_then_position() {
        let by_name = vec![
            param("BUF", CobolParamKind::Bytes { len: None }),
            param("STATUS-X", CobolParamKind::Numeric { width: 1 }),
            param("BUF-LENGTH", CobolParamKind::Numeric { width: 4 }),
        ];
        assert_eq!(length_param_index(&by_name, 0), Some(2));
        let by_pos = vec![
            param("BUF", CobolParamKind::Bytes { len: None }),
            param("N", CobolParamKind::Numeric { width: 4 }),
        ];
        assert_eq!(length_param_index(&by_pos, 0), Some(1));
    }

    #[test]
    fn multi_param_glue_drives_all_operands() {
        let params = vec![
            param("LK-JSON", CobolParamKind::Bytes { len: None }),
            param("LK-JSON-LEN", CobolParamKind::Numeric { width: 4 }),
            param("LK-FAILURE", CobolParamKind::Numeric { width: 1 }),
        ];
        let g = multi_param_glue("JSON__PARSE", &params);
        // One extern operand per USING param; the call passes all three.
        assert!(g.contains("extern int JSON__PARSE(cob_u8_t *, cob_u8_t *, cob_u8_t *);"));
        assert!(g.contains(
            "int bhf_rc = JSON__PARSE((cob_u8_t *)bhf_b0, (cob_u8_t *)bhf_b1, (cob_u8_t *)bhf_b2);"
        ));
        // Primary ANY-LENGTH buffer filled from the input; length operand set.
        assert!(g.contains("bhf_primary_len = _n;"));
        assert!(g.contains("bhf_b1[4-1-_k]"));
        // in-target guard so the end-of-run leak check is not a phantom crash.
        assert!(g.contains("bhf_in_target = 1;"));
        assert!(
            g.contains("bhf_target_enter();\n    bhf_in_target = 1;\n    int bhf_rc = JSON__PARSE")
        );
    }

    #[test]
    fn read_file_protocol_materializes_fuzz_bytes() {
        let params = vec![
            param("LS-FILE-PATH", CobolParamKind::Bytes { len: Some(512) }),
            param(
                "LS-FILE-BUFFER",
                CobolParamKind::Bytes { len: Some(65_536) },
            ),
            param("LS-FILE-SIZE", CobolParamKind::Numeric { width: 4 }),
            param("LS-RETURN-CODE", CobolParamKind::Numeric { width: 1 }),
        ];
        assert_eq!(materialized_path_param_index(&params), Some(0));
        let glue = multi_param_glue("FILE__OPS", &params);
        assert!(glue.contains("mkstemp(bhf_temp_path)"), "{glue}");
        assert!(glue.contains("write(_fd, Data + _off"), "{glue}");
        assert!(
            glue.contains("memcpy(bhf_b0, bhf_temp_path, _pn)"),
            "{glue}"
        );
        assert!(glue.contains("if (bhf_temp_created) remove(bhf_temp_path);"));
        assert!(
            !glue.contains("bhf_b2[4-1-_k]"),
            "FILE-SIZE is an output, not the input-path length"
        );
    }

    #[test]
    fn single_fixed_buffer_glue() {
        let params = vec![param("BUF", CobolParamKind::Bytes { len: Some(8) })];
        let g = multi_param_glue("PARSEIT", &params);
        assert!(g.contains("extern int PARSEIT(cob_u8_t *);"));
        assert!(g.contains("static unsigned char bhf_b0[8];"));
        assert!(g.contains("memset(bhf_b0, ' ', 8);"));
        assert!(g.contains("int bhf_rc = PARSEIT((cob_u8_t *)bhf_b0);"));
    }
}
