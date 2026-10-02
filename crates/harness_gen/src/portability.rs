// SPDX-License-Identifier: Apache-2.0
//! Portable-harness export artifacts.
//!
//! `bhf auto` generates self-contained native harnesses (C, C++, Rust, Ada)
//! whose default binary already reads a single input and runs the target once —
//! the black-box contract an external fuzzer expects. This module emits, next to
//! each such harness, the small artifacts that make that portability
//! *discoverable* and *drivable*:
//!
//! - a `Mayhemfile` wired to the right input delivery (a `@@` file argument, or
//!   stdin), so `mayhem run .` works against the harness dir;
//! - a `PORTABILITY.md` with the exact build/run commands for Mayhem, libFuzzer,
//!   AFL++, and honggfuzz;
//! - a `bhf_libfuzzer.c` shim (for the lanes that gain a libFuzzer binary) that
//!   adapts bhf's stable `bhf_run_one(data, size)` entry to libFuzzer's
//!   `LLVMFuzzerTestOneInput`.
//!
//! The artifacts are inert: they change nothing about how bhf's own engine
//! drives the harness. They only let a *different* fuzzer consume the same
//! generated code.

use std::fs;
use std::io;
use std::path::Path;

/// Filename of the generated Mayhem configuration.
pub const MAYHEMFILE_NAME: &str = "Mayhemfile";
/// Filename of the generated portability guide.
pub const PORTABILITY_DOC_NAME: &str = "PORTABILITY.md";
/// Filename of the generated libFuzzer adapter shim.
pub const LIBFUZZER_SHIM_NAME: &str = "bhf_libfuzzer.c";

/// The C-ABI libFuzzer adapter, shared verbatim by every lane that produces a
/// libFuzzer binary (C, C++, Rust). It provides the two symbols a
/// `-fsanitize=fuzzer` link needs that the bhf harness does not define on its
/// own once the native fork-server driver is left out:
///
/// - `LLVMFuzzerTestOneInput` — libFuzzer's per-input entry, forwarded to bhf's
///   stable `bhf_run_one(data, size)`;
/// - a no-op `bhf_target_enter` — the harness calls this boundary hook when it is
///   compiled for an external driver (`-DBHF_EXTERNAL_DRIVER`); the real counting
///   definition lives in `bhf_driver.c`, which a libFuzzer build does not link.
///
/// `bhf_run_one` has C linkage in every lane (the C/C++ harness declares it
/// `extern "C"`; the Rust staticlib exports it `#[no_mangle] extern "C"`), so a
/// single C translation unit adapts all three.
pub const LIBFUZZER_SHIM_C: &str = r#"/* SPDX-License-Identifier: Apache-2.0 */
/* bhf libFuzzer adapter (generated).
 *
 * Links the bhf harness (which exposes `bhf_run_one`) against libFuzzer's own
 * `main`/coverage runtime via `-fsanitize=fuzzer`. Build it with the harness's
 * `make libfuzzer` target (C/C++) or the sibling build script (Rust); see
 * PORTABILITY.md. */
#include <stddef.h>
#include <stdint.h>

/* Defined by the bhf harness (C/C++ `extern "C"`, Rust `#[no_mangle]`). */
extern int bhf_run_one(const uint8_t *data, size_t size);

/* The harness calls this boundary hook under -DBHF_EXTERNAL_DRIVER; the counting
 * definition is in bhf_driver.c, which a libFuzzer build intentionally omits. */
void bhf_target_enter(void) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return bhf_run_one(data, size);
}
"#;

/// Which language lane a harness belongs to. Drives the lane-specific sections
/// of `PORTABILITY.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    C,
    Cpp,
    Rust,
    Ada,
}

impl Lane {
    fn label(self) -> &'static str {
        match self {
            Lane::C => "C",
            Lane::Cpp => "C++",
            Lane::Rust => "Rust",
            Lane::Ada => "Ada",
        }
    }
}

/// How the harness binary receives one input per run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputDelivery {
    /// The input is a file path passed as the first argument — Mayhem's `@@`
    /// token, AFL file mode. Used by C/C++/Rust (bhf's native driver reads
    /// `argv[1]`).
    File,
    /// The whole of standard input is one input. Used by Ada (the AdaFuzz runtime
    /// reads `/dev/stdin`); Mayhem feeds `/dev/stdin` when `@@` is absent.
    Stdin,
}

/// Everything the Mayhemfile/doc generators need about one harness.
#[derive(Clone, Debug)]
pub struct PortabilitySpec {
    /// The harness id (e.g. `H-0001`); used as the Mayhem `target`.
    pub harness_id: String,
    /// Language lane.
    pub lane: Lane,
    /// Default base-executable binary name (relative to the harness dir), e.g.
    /// `main`.
    pub binary: String,
    /// How the base executable takes its input.
    pub input: InputDelivery,
    /// Whether the base executable is built with a sanitizer (ASan/UBSan). When
    /// true the Mayhemfile marks the command `sanitizer: true`.
    pub sanitizer: bool,
    /// Name of the libFuzzer binary a user can build, if this lane offers one
    /// (`main_libfuzzer`). `None` suppresses the libFuzzer sections.
    pub libfuzzer_binary: Option<String>,
    /// Name of the AFL++ persistent binary a user can build, if any
    /// (`main_afl`). `None` suppresses the AFL sections.
    pub afl_binary: Option<String>,
    /// When true, the generated `cmd` is prefixed with
    /// `env BHF_CRASH_ON_FINDING=1` so a reported finding aborts the process and
    /// an external crash-keying engine detects it (Ada caught-exception case).
    pub crash_on_finding_env: bool,
}

impl PortabilitySpec {
    /// The Mayhem `cmd` string: the base executable, an optional
    /// `BHF_CRASH_ON_FINDING` env prefix, and a trailing `@@` for file input.
    fn mayhem_cmd(&self) -> String {
        let mut cmd = String::new();
        if self.crash_on_finding_env {
            cmd.push_str("env BHF_CRASH_ON_FINDING=1 ");
        }
        cmd.push_str("./");
        cmd.push_str(&self.binary);
        if self.input == InputDelivery::File {
            cmd.push_str(" @@");
        }
        cmd
    }
}

/// Render the `Mayhemfile` for a harness.
pub fn mayhemfile(spec: &PortabilitySpec) -> String {
    let mut s = String::new();
    s.push_str("# Mayhemfile — generated by bhf.\n");
    s.push_str("# Run Mayhem against this harness directory:  mayhem run .\n");
    s.push_str("# Build/run details and other engines (libFuzzer, AFL++, honggfuzz):\n");
    s.push_str("#   see PORTABILITY.md next to this file.\n");
    s.push_str("project: bhf\n");
    s.push_str(&format!("target: {}\n", spec.harness_id));
    s.push_str("cmds:\n");
    match spec.input {
        InputDelivery::File => {
            s.push_str(&format!(
                "  - cmd: {}   # '@@' is the input file\n",
                spec.mayhem_cmd()
            ));
        }
        InputDelivery::Stdin => {
            s.push_str(&format!(
                "  - cmd: {}   # input is read from stdin\n",
                spec.mayhem_cmd()
            ));
        }
    }
    if spec.sanitizer {
        s.push_str("    sanitizer: true\n");
    }
    if let Some(bin) = &spec.libfuzzer_binary {
        s.push_str("# Coverage-guided alternative — build it first (see PORTABILITY.md),\n");
        s.push_str("# then replace the command above with:\n");
        s.push_str(&format!("#  - cmd: ./{bin}\n"));
        s.push_str("#    libfuzzer: true\n");
    }
    s
}

/// Render the `PORTABILITY.md` guide for a harness.
pub fn portability_md(spec: &PortabilitySpec) -> String {
    let lane = spec.lane.label();
    let bin = &spec.binary;
    let mut s = String::new();
    s.push_str(&format!(
        "# Running this {lane} harness under another fuzzer\n\n"
    ));
    s.push_str(&format!(
        "`bhf` generated this harness (`{}`). The files here are self-contained: \
the default binary reads one input per run and executes the target once, so an \
external fuzzer can drive it directly.\n\n",
        spec.harness_id
    ));

    // Black-box / Mayhem base-executable.
    s.push_str("## Mayhem (base-executable)\n\n");
    match spec.input {
        InputDelivery::File => {
            s.push_str(&format!(
                "The default build reads the input from a file path in `argv[1]`, which matches \
Mayhem's `@@` token and AFL file mode.\n\n```sh\nmake            # builds ./{bin}\n./{bin} <input-file>   # replay one input\nmayhem run .    # uses the generated Mayhemfile\n```\n\n"
            ));
        }
        InputDelivery::Stdin => {
            s.push_str(&format!(
                "The default build reads the whole of standard input as one input (Mayhem feeds \
`/dev/stdin` when the command has no `@@`).\n\n```sh\ngprbuild        # builds ./{bin}\n./{bin} < input-file   # replay one input\nmayhem run .    # uses the generated Mayhemfile\n```\n\n"
            ));
        }
    }
    if spec.crash_on_finding_env {
        s.push_str(
            "> **Important for Ada:** a caught top-level exception is reported as a finding but \
does **not** crash the process, so a crash-keying engine would miss it. Set \
`BHF_CRASH_ON_FINDING=1` (the generated Mayhemfile already does) to abort the \
process when a finding is reported:\n\n",
        );
        s.push_str(&format!(
            "```sh\nBHF_CRASH_ON_FINDING=1 ./{bin} < input-file\n```\n\n"
        ));
    }

    // libFuzzer.
    if let Some(lf) = &spec.libfuzzer_binary {
        s.push_str("## libFuzzer (and Mayhem coverage-guided)\n\n");
        s.push_str(&format!(
            "`LLVMFuzzerTestOneInput` is provided by the generated `{LIBFUZZER_SHIM_NAME}` shim \
(it forwards to bhf's `bhf_run_one`).\n\n"
        ));
        match spec.lane {
            Lane::C | Lane::Cpp => {
                s.push_str(&format!(
                    "```sh\nmake libfuzzer          # builds ./{lf} with -fsanitize=fuzzer\n./{lf} corpus/          # coverage-guided run\n```\n\n"
                ));
            }
            Lane::Rust => {
                s.push_str(&format!(
                    "```sh\n./build-libfuzzer.sh    # links the staticlib into ./{lf} with -fsanitize=fuzzer\n./{lf} corpus/          # coverage-guided run\n```\n\n"
                ));
            }
            Lane::Ada => {}
        }
        s.push_str(&format!(
            "For Mayhem, point the command at `./{lf}` and set `libfuzzer: true` \
(the Mayhemfile shows this as a commented alternative).\n\n"
        ));
    }

    // AFL++.
    if let Some(afl) = &spec.afl_binary {
        s.push_str("## AFL++\n\n");
        s.push_str(&format!(
            "```sh\nmake afl                # builds ./{afl} (afl-clang-fast persistent mode)\nafl-fuzz -i seeds -o out -- ./{afl}\n```\n\n"
        ));
        s.push_str("For Mayhem, set `afl: true` on the command.\n\n");
    }

    // honggfuzz (only where a libFuzzer-style entry exists).
    if spec.libfuzzer_binary.is_some() && matches!(spec.lane, Lane::C | Lane::Cpp) {
        s.push_str("## honggfuzz\n\n");
        s.push_str(&format!(
            "honggfuzz consumes the same `LLVMFuzzerTestOneInput` entry via `hfuzz-cc`:\n\n```sh\nhfuzz-cc -fsanitize=address,undefined {LIBFUZZER_SHIM_NAME} main.c <target-sources> -o {bin}.hfuzz\nhonggfuzz -i seeds -- ./{bin}.hfuzz\n```\n\n"
        ));
    }

    s.push_str("---\n");
    s.push_str(
        "All commands run from this directory. The default binary is also safe to run by hand \
for triage — it executes the target exactly once per input.\n",
    );
    s
}

/// Write the Mayhemfile and PORTABILITY.md (and, when the lane has a libFuzzer
/// binary, the `bhf_libfuzzer.c` shim) into `dir`. Existing files are
/// overwritten; the harness dir is regenerated per attempt.
pub fn write_artifacts(dir: &Path, spec: &PortabilitySpec) -> io::Result<()> {
    fs::write(dir.join(MAYHEMFILE_NAME), mayhemfile(spec))?;
    fs::write(dir.join(PORTABILITY_DOC_NAME), portability_md(spec))?;
    if spec.libfuzzer_binary.is_some() {
        fs::write(dir.join(LIBFUZZER_SHIM_NAME), LIBFUZZER_SHIM_C)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c_spec() -> PortabilitySpec {
        PortabilitySpec {
            harness_id: "H-0001".to_owned(),
            lane: Lane::C,
            binary: "main".to_owned(),
            input: InputDelivery::File,
            sanitizer: true,
            libfuzzer_binary: Some("main_libfuzzer".to_owned()),
            afl_binary: Some("main_afl".to_owned()),
            crash_on_finding_env: false,
        }
    }

    fn ada_spec() -> PortabilitySpec {
        PortabilitySpec {
            harness_id: "H-0007".to_owned(),
            lane: Lane::Ada,
            binary: "main".to_owned(),
            input: InputDelivery::Stdin,
            sanitizer: false,
            libfuzzer_binary: None,
            afl_binary: None,
            crash_on_finding_env: true,
        }
    }

    #[test]
    fn mayhemfile_file_input_uses_the_at_token_and_marks_sanitizer() {
        let m = mayhemfile(&c_spec());
        assert!(m.contains("project: bhf\n"), "{m}");
        assert!(m.contains("target: H-0001\n"), "{m}");
        assert!(m.contains("- cmd: ./main @@"), "{m}");
        assert!(m.contains("sanitizer: true"), "{m}");
        // The libFuzzer alternative is offered but commented out (binary not built yet).
        assert!(m.contains("#  - cmd: ./main_libfuzzer"), "{m}");
        assert!(m.contains("#    libfuzzer: true"), "{m}");
    }

    #[test]
    fn mayhemfile_stdin_input_omits_the_at_token() {
        let m = mayhemfile(&ada_spec());
        assert!(m.contains("target: H-0007\n"), "{m}");
        // Stdin: no '@@'.
        assert!(!m.contains("@@"), "{m}");
        // Ada crash-on-finding env prefix so a finding is a detectable crash.
        assert!(
            m.contains("- cmd: env BHF_CRASH_ON_FINDING=1 ./main"),
            "{m}"
        );
        // No sanitizer flag for the plain GNAT build.
        assert!(!m.contains("sanitizer: true"), "{m}");
        // No libFuzzer alternative for Ada.
        assert!(!m.contains("libfuzzer: true"), "{m}");
    }

    #[test]
    fn portability_doc_c_covers_every_external_engine() {
        let d = portability_md(&c_spec());
        assert!(
            d.contains("# Running this C harness under another fuzzer"),
            "{d}"
        );
        assert!(d.contains("## Mayhem (base-executable)"), "{d}");
        assert!(d.contains("make libfuzzer"), "{d}");
        assert!(d.contains("## AFL++"), "{d}");
        assert!(d.contains("make afl"), "{d}");
        assert!(d.contains("## honggfuzz"), "{d}");
        assert!(d.contains("./main <input-file>"), "{d}");
    }

    #[test]
    fn portability_doc_ada_warns_about_caught_exceptions_and_has_no_libfuzzer() {
        let d = portability_md(&ada_spec());
        assert!(
            d.contains("# Running this Ada harness under another fuzzer"),
            "{d}"
        );
        assert!(d.contains("BHF_CRASH_ON_FINDING=1"), "{d}");
        assert!(d.contains("does **not** crash the process"), "{d}");
        // Ada has no libFuzzer / AFL sections.
        assert!(!d.contains("## libFuzzer"), "{d}");
        assert!(!d.contains("## AFL++"), "{d}");
        // stdin replay form.
        assert!(d.contains("./main < input-file"), "{d}");
    }

    #[test]
    fn rust_doc_uses_the_build_script_not_make() {
        let spec = PortabilitySpec {
            harness_id: "H-0003".to_owned(),
            lane: Lane::Rust,
            binary: "main".to_owned(),
            input: InputDelivery::File,
            sanitizer: true,
            libfuzzer_binary: Some("main_libfuzzer".to_owned()),
            afl_binary: None,
            crash_on_finding_env: false,
        };
        let d = portability_md(&spec);
        assert!(d.contains("./build-libfuzzer.sh"), "{d}");
        assert!(!d.contains("make libfuzzer"), "{d}");
        // No AFL section when the lane offers no AFL binary.
        assert!(!d.contains("## AFL++"), "{d}");
    }

    #[test]
    fn libfuzzer_shim_defines_the_entry_and_the_boundary_hook() {
        assert!(LIBFUZZER_SHIM_C.contains("int LLVMFuzzerTestOneInput("));
        assert!(LIBFUZZER_SHIM_C.contains("bhf_run_one(data, size)"));
        assert!(LIBFUZZER_SHIM_C.contains("void bhf_target_enter(void) {}"));
    }

    #[test]
    fn write_artifacts_emits_shim_only_when_a_libfuzzer_binary_exists() {
        let tmp = std::env::temp_dir().join(format!("bhf-portability-{}", std::process::id()));
        let c_dir = tmp.join("c");
        let ada_dir = tmp.join("ada");
        fs::create_dir_all(&c_dir).unwrap();
        fs::create_dir_all(&ada_dir).unwrap();

        write_artifacts(&c_dir, &c_spec()).unwrap();
        assert!(c_dir.join(MAYHEMFILE_NAME).is_file());
        assert!(c_dir.join(PORTABILITY_DOC_NAME).is_file());
        assert!(c_dir.join(LIBFUZZER_SHIM_NAME).is_file());

        write_artifacts(&ada_dir, &ada_spec()).unwrap();
        assert!(ada_dir.join(MAYHEMFILE_NAME).is_file());
        assert!(ada_dir.join(PORTABILITY_DOC_NAME).is_file());
        assert!(!ada_dir.join(LIBFUZZER_SHIM_NAME).exists());

        fs::remove_dir_all(&tmp).ok();
    }
}
