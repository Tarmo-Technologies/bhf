// SPDX-License-Identifier: Apache-2.0

pub use error::HarnessGenError;
pub use generate::{
    generate_direct_harness, generate_sequence_harness, generate_servant_direct_harness,
    GenerateDirectArgs, GenerateSequenceArgs, GenerateServantDirectArgs, GeneratedFiles,
};

/// Version of the input format that generated C and C++ harnesses decode
/// (see [`harness_format_version_for`] for Ada).
///
/// A harness turns each fuzz input into the target's arguments. When the same
/// input bytes start decoding to different arguments, corpora, testcases and
/// findings recorded against an older harness no longer mean what they did, so
/// this is bumped whenever that happens. It is recorded in each harness's
/// `generation-metadata.json` (`harness_format_version`) and at the top of the
/// generated source. Harnesses that carry no version predate it (format 1).
/// `bhf generate-harness` warns when it regenerates a harness directory of
/// another format, and `bhf replay` when it replays against one.
///
/// - 2: unsigned scalars, `size_t` included, decode across their full range
///   (only length-, size- and count-named values stay bounded), and a byte
///   buffer pairs with the following integer, as `(Data, Size)` or as an output
///   buffer and its capacity, only when that integer is named like a length.
/// - 3: within each call, the parameters decoded from the input cursor take
///   the leading bytes and the whole-input parameters (lone byte buffers,
///   `(buffer, length)` pairs, `FILE *`, temp-file paths) take the bytes the
///   cursor left, instead of the whole input again; a C++ method's
///   whole-input target parameters come after its receiver's arguments.
/// - 4: a call with several buffers gives each its own bytes: every one but
///   the last takes a sized slice of the cursor (a 4-byte length, then that
///   many bytes), and the last the bytes the cursor left, instead of all of
///   them sharing those bytes (and a second `(buffer, length)` pair's length
///   being decoded on its own). Counts named `nElem`, `numberOfItems` or a
///   bare Win32 `cb`/`cch`, and buffers spelled through a pointer typedef
///   (`LPCBYTE`), now pair, a lone writable byte pointer whose element type
///   is a typedef or `std::uint8_t` (`u8_t *`, `BYTE *`) is a copy of the
///   input with headroom and one whose element type is a `char` typedef
///   (`CHAR *`) a writable string, instead of one decoded byte, and a
///   parameter named like a harness local (`Data`, `Size`, `Cur`) gets a
///   local of its own. It also resolves the
///   scalar typedefs a C target declares in its own `.c`, in C++ sizes a
///   typed array to its element count as the C lane does, and in both lanes
///   decodes each element of such an array from the input.
pub const HARNESS_FORMAT_VERSION: u32 = 4;

/// The input format generated Ada harnesses decode. Formats 3 and 4 changed
/// only the C and C++ layout, so Ada harnesses stay at format 2.
pub const ADA_HARNESS_FORMAT_VERSION: u32 = 2;

/// The input format a harness generated for `language` (`"c"`, `"cpp"` or
/// `"ada"`, as `generation-metadata.json` records it) decodes.
pub fn harness_format_version_for(language: &str) -> u32 {
    if language == "ada" {
        ADA_HARNESS_FORMAT_VERSION
    } else {
        HARNESS_FORMAT_VERSION
    }
}

/// The environment variable that turns on the explicit buffer-length
/// dimension when a harness is generated (see
/// [`buffer_len_dimension_enabled`]).
pub const BUFFER_LEN_DIMENSION_ENV: &str = "BHF_BUFFER_LEN_DIMENSION";

thread_local! {
    static BUFFER_LEN_DIMENSION: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
}

/// Whether generated harnesses give a byte buffer that has no length
/// parameter an explicit length: four more input bytes (a little-endian
/// length, clamped to the bytes left), then that many bytes, instead of every
/// byte the other parameters left. Off unless `BHF_BUFFER_LEN_DIMENSION=1` is
/// set when the harness is generated (or a [`scoped_buffer_len_dimension`]
/// guard is live): sizing such a buffer below the input can make a function
/// with an implicit length contract overflow it, a crash the harness made.
pub fn buffer_len_dimension_enabled() -> bool {
    BUFFER_LEN_DIMENSION
        .with(|cell| cell.get())
        .unwrap_or_else(|| {
            std::env::var(BUFFER_LEN_DIMENSION_ENV)
                .is_ok_and(|value| !value.is_empty() && value != "0")
        })
}

/// Override [`buffer_len_dimension_enabled`] on this thread until the guard
/// drops.
#[must_use]
pub fn scoped_buffer_len_dimension(enabled: bool) -> BufferLenDimensionGuard {
    let previous = BUFFER_LEN_DIMENSION.with(|cell| cell.replace(Some(enabled)));
    BufferLenDimensionGuard { previous }
}

/// Restores the previous [`scoped_buffer_len_dimension`] state on drop.
pub struct BufferLenDimensionGuard {
    previous: Option<bool>,
}

impl Drop for BufferLenDimensionGuard {
    fn drop(&mut self) {
        BUFFER_LEN_DIMENSION.with(|cell| cell.set(self.previous));
    }
}

pub mod arg_layout;
pub(crate) mod arg_trace;
pub mod build_safety;
pub mod c_decoders;
pub mod c_generate;
pub mod compiler_family;
pub mod cpp_decoders;
pub mod cpp_generate;
pub mod decoders;
pub mod error;
pub mod fuzzing_build_mode;
pub mod generate;
pub mod generic_instance;
pub mod java_generate;
pub mod portability;
pub mod registry;
pub mod rust_decoders;
pub mod rust_generate;
pub mod stream_init;
pub mod templates;

/// A command running a harness a test built with `make`. On Windows the
/// harness needs clang's AddressSanitizer runtime DLL, which `bhf build`
/// stages next to the binary, so its directory goes first on the child's
/// PATH.
#[cfg(test)]
pub(crate) fn harness_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    #[allow(unused_mut)]
    let mut command = std::process::Command::new(program);
    #[cfg(windows)]
    if let Some(runtime) = clang_sanitizer_runtime_dir() {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let dirs = std::iter::once(runtime.clone()).chain(std::env::split_paths(&path));
        command.env(
            "PATH",
            std::env::join_paths(dirs).expect("PATH entries join"),
        );
    }
    command
}

/// `<clang resource dir>/lib/windows`, where clang keeps its sanitizer DLLs.
#[cfg(all(test, windows))]
fn clang_sanitizer_runtime_dir() -> Option<&'static std::path::PathBuf> {
    static DIR: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let output = std::process::Command::new("clang")
            .arg("-print-resource-dir")
            .output()
            .ok()?;
        let resource = String::from_utf8_lossy(&output.stdout);
        let dir = std::path::Path::new(resource.trim())
            .join("lib")
            .join("windows");
        dir.is_dir().then_some(dir)
    })
    .as_ref()
}

/// Test helpers for a harness's framed fuzz loop, and for a harness built
/// with its own standalone driver: the copy of bhf's driver in its
/// `main.c`/`main.cpp`, compiled without `-DBHF_EXTERNAL_DRIVER`, as a
/// capsule replays it.
#[cfg(test)]
pub(crate) mod standalone_driver {
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};

    /// Compile `out/<main>` and `sources` with `compiler` and
    /// AddressSanitizer, using the harness's own driver, into
    /// `out/standalone`. `None` (the test skips) when `compiler` is missing.
    /// At `-O0`, which inlines nothing: the driver's runtime callbacks
    /// (`bhf_cmp_buf`) are then real calls, as in a debug build of a harness,
    /// and must not be address-checked before ASan's shadow is set up.
    pub(crate) fn build(
        out: &Path,
        compiler: &str,
        main: &str,
        sources: &[PathBuf],
    ) -> Option<PathBuf> {
        let present = Command::new(compiler)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        if !present {
            eprintln!("skipping the standalone build: {compiler} unavailable");
            return None;
        }
        let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime");
        let program = out.join(format!("standalone{}", std::env::consts::EXE_SUFFIX));
        let mut command = Command::new(compiler);
        command.args([
            "-g",
            "-O0",
            "-fsanitize=address",
            "-D_GNU_SOURCE",
            "-D_DEFAULT_SOURCE",
        ]);
        if cfg!(windows) {
            command.arg("-D_CRT_SECURE_NO_WARNINGS");
        }
        let build = command
            .arg("-I")
            .arg(&runtime)
            .arg("-I")
            .arg(out)
            .arg("-o")
            .arg(&program)
            .arg(out.join(main))
            .args(sources)
            .output()
            .expect("run the compiler");
        assert!(
            build.status.success(),
            "standalone build of {} failed:\n{}",
            out.join(main).display(),
            String::from_utf8_lossy(&build.stderr)
        );
        Some(program)
    }

    /// Run `program`'s framed loop (`BHF_FRAMED=1`) over `frames`, one `{u32
    /// LE length, bytes}` frame each: how many sync bytes came back before
    /// the loop ended, then its exit status and stderr once stdin is closed.
    pub(crate) fn run_framed(program: &Path, frames: &[&[u8]]) -> (usize, ExitStatus, String) {
        use std::io::{Read, Write};
        let mut child = crate::harness_command(program)
            .env("BHF_FRAMED", "1")
            .env_remove("BHF_TRACE_ARGS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the framed harness");
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut byte = [0u8; 1];
        stdout.read_exact(&mut byte).expect("ready byte");
        assert_eq!(byte[0], 1, "ready byte");
        let mut synced = 0;
        for frame in frames {
            let mut bytes = (frame.len() as u32).to_le_bytes().to_vec();
            bytes.extend_from_slice(frame);
            if stdin.write_all(&bytes).is_err() {
                break;
            }
            match stdout.read(&mut byte) {
                Ok(1) => synced += 1,
                _ => break,
            }
        }
        drop(stdin);
        drop(stdout);
        let output = child.wait_with_output().expect("framed harness exits");
        (
            synced,
            output.status,
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// `program` runs a target that reads `buf[0..=len]` of a buffer viewing
    /// the whole input, one byte past it. Its driver passes each input in a
    /// heap allocation of exactly its size, so the read is a heap overflow
    /// AddressSanitizer reports on file replay and in the framed loop alike,
    /// and an empty input (one addressable byte) runs clean.
    pub(crate) fn assert_reports_a_read_one_past_the_input(program: &Path) {
        let dir = program.parent().expect("the program's dir");
        let replay = |input: &[u8]| {
            let path = dir.join("one-past.bin");
            std::fs::write(&path, input).unwrap();
            crate::harness_command(program)
                .arg(&path)
                .env_remove("BHF_TRACE_ARGS")
                .output()
                .unwrap()
        };
        let run = replay(b"ABCD");
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            !run.status.success()
                && stderr.contains("heap-buffer-overflow")
                && stderr.contains("4-byte region"),
            "{}: file replay: {}: {stderr}",
            program.display(),
            run.status
        );
        let run = replay(b"");
        assert!(
            run.status.success(),
            "{}: empty replay: {}",
            program.display(),
            String::from_utf8_lossy(&run.stderr)
        );
        let (synced, status, stderr) = run_framed(program, &[b"", b"ABCD"]);
        assert_eq!(synced, 1, "{}: framed: {stderr}", program.display());
        assert!(
            !status.success()
                && stderr.contains("heap-buffer-overflow")
                && stderr.contains("4-byte region"),
            "{}: framed: {status}: {stderr}",
            program.display()
        );
    }

    /// The target the AFL++ lane tests drive: it reports each run's length
    /// on stderr, reads `buf[0..len)`, and reads one byte past the input when
    /// it starts with `X`.
    pub(crate) const AFL_PROBE_BODY: &str =
        "\x20   fprintf(stderr, \"BHF_TEST_RUN %u\\n\", (unsigned)len);\n\
         \x20   int s = 0;\n\
         \x20   for (size_t i = 0; i < len; i++) s += buf[i];\n\
         \x20   if (len && buf[0] == 'X') s += buf[len];\n\
         \x20   return s;\n";

    /// Build the AFL++ lane of the harness in `out` (`make main_afl`) with
    /// `compiler` as its AFL++ compiler (`var` is `AFLPP_CC` or `AFLPP_CXX`).
    /// `None` (the test skips) off Unix, where the lane does not exist, or
    /// without `make` or `compiler`.
    pub(crate) fn build_afl(out: &Path, var: &str, compiler: &str) -> Option<PathBuf> {
        let present = |tool: &str| {
            Command::new(tool)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        };
        if cfg!(windows) || !present("make") || !present(compiler) {
            eprintln!("skipping the AFL++ lane build with {compiler}");
            return None;
        }
        // Another compiler's build of the lane would look up to date.
        std::fs::remove_file(out.join("main_afl")).ok();
        let build = Command::new("make")
            .arg("-C")
            .arg(out)
            .arg("main_afl")
            .arg(format!("{var}={compiler}"))
            .env("AFL_QUIET", "1")
            .output()
            .expect("run make");
        assert!(
            build.status.success(),
            "make main_afl with {compiler} failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );
        Some(out.join("main_afl"))
    }

    /// Compile `out/<main>` and `sources` with `compiler` as the AFL++ lane
    /// (`-DBHF_AFL`) at `-O1`, with its persistent loop driven over `inputs`: each
    /// iteration writes the next input into the testcase buffer, as afl-fuzz
    /// does, after the harness has made the buffer addressable again.
    pub(crate) fn build_afl_loop(
        out: &Path,
        compiler: &str,
        main: &str,
        sources: &[PathBuf],
        inputs: &[&[u8]],
    ) -> Option<PathBuf> {
        let present = Command::new(compiler)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        if cfg!(windows) || !present {
            eprintln!("skipping the AFL++ loop build with {compiler}");
            return None;
        }
        let array = |input: &[u8]| {
            let bytes: Vec<String> = input.iter().map(|b| format!("0x{b:02x}")).collect();
            if bytes.is_empty() {
                "0".to_owned()
            } else {
                bytes.join(", ")
            }
        };
        let mut shim =
            String::from("#include <stddef.h>\n#include <string.h>\n#include \"afl_loop.h\"\n");
        for (at, input) in inputs.iter().enumerate() {
            shim.push_str(&format!(
                "static const unsigned char bhf_test_in{at}[] = {{ {} }};\n",
                array(input)
            ));
        }
        shim.push_str(&format!(
            "static const unsigned char *const bhf_test_in[] = {{ {} }};\n\
             static const size_t bhf_test_len[] = {{ {} }};\n\
             static size_t bhf_test_at = 0;\n\
             int bhf_test_loop(void) {{ return bhf_test_at < {}; }}\n\
             size_t bhf_test_next(unsigned char *buf) {{\n\
             \x20   size_t n = bhf_test_len[bhf_test_at];\n\
             \x20   memcpy(buf, bhf_test_in[bhf_test_at], n);\n\
             \x20   bhf_test_at++;\n\
             \x20   return n;\n\
             }}\n",
            (0..inputs.len())
                .map(|at| format!("bhf_test_in{at}"))
                .collect::<Vec<_>>()
                .join(", "),
            inputs
                .iter()
                .map(|input| input.len().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            inputs.len()
        ));
        std::fs::write(
            out.join("afl_loop.h"),
            "#include <stddef.h>\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\
             int bhf_test_loop(void);\nsize_t bhf_test_next(unsigned char *buf);\n\
             #ifdef __cplusplus\n}\n#endif\n",
        )
        .unwrap();
        // Compiled as the main source's language, so its linkage matches.
        let shim_path = out.join(if main.ends_with(".cpp") {
            "afl_loop.cpp"
        } else {
            "afl_loop.c"
        });
        std::fs::write(&shim_path, shim).unwrap();
        let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime");
        let program = out.join("afl_loop");
        let build = Command::new(compiler)
            .args([
                "-g",
                "-O1",
                "-fsanitize=address",
                "-DBHF_AFL",
                "-D_GNU_SOURCE",
            ])
            .arg("-include")
            .arg(out.join("afl_loop.h"))
            .arg("-D__AFL_LOOP(_n)=bhf_test_loop()")
            .arg("-D__AFL_FUZZ_TESTCASE_LEN=bhf_test_next(buf)")
            .arg("-I")
            .arg(&runtime)
            .arg("-I")
            .arg(out)
            .arg("-o")
            .arg(&program)
            .arg(out.join(main))
            .args(sources)
            .arg(&shim_path)
            .output()
            .expect("run the compiler");
        assert!(
            build.status.success(),
            "AFL++ loop build of {} failed:\n{}",
            out.join(main).display(),
            String::from_utf8_lossy(&build.stderr)
        );
        Some(program)
    }

    /// Run an AFL++ lane binary once outside afl-fuzz, with `input` on stdin,
    /// as a crash is replayed.
    pub(crate) fn run_afl(program: &Path, input: &[u8]) -> std::process::Output {
        use std::io::Write;
        let mut child = Command::new(program)
            .env_remove("BHF_TRACE_ARGS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the AFL++ lane");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input)
            .expect("write the input");
        child.wait_with_output().expect("AFL++ lane exits")
    }

    /// `program` is an AFL++ lane of a target with [`AFL_PROBE_BODY`]: a
    /// read one past the input is the heap-buffer-overflow the builtin lane
    /// reports, though AFL++'s testcase buffer is larger than any input, and
    /// a correct read of an input of any size is not reported.
    pub(crate) fn assert_afl_reports_a_read_one_past_the_input(program: &Path) {
        for input in [&b"ABCD"[..], b""] {
            let run = run_afl(program, input);
            assert!(
                run.status.success(),
                "{} on {input:02x?}: {}",
                program.display(),
                String::from_utf8_lossy(&run.stderr)
            );
        }
        let run = run_afl(program, b"XBCD");
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            !run.status.success()
                && stderr.contains("ERROR: AddressSanitizer: heap-buffer-overflow"),
            "{}: the read one past the input: {}: {stderr}",
            program.display(),
            run.status
        );
    }

    /// `program` was built with [`build_afl_loop`] over
    /// [`AFL_LOOP_INPUTS`] for a target with [`AFL_PROBE_BODY`]: every input
    /// runs clean however its length compares to the last one's, until the
    /// last input's read one past it is reported as a heap-buffer-overflow.
    pub(crate) fn assert_afl_loop_reports_only_past_each_input(program: &Path) {
        let run = Command::new(program)
            .env_remove("BHF_TRACE_ARGS")
            .output()
            .expect("run the AFL++ loop");
        let stderr = String::from_utf8_lossy(&run.stderr);
        let runs: Vec<&str> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("BHF_TEST_RUN "))
            .collect();
        assert_eq!(runs, ["4", "8", "0", "8", "4"], "{stderr}");
        assert!(
            !run.status.success()
                && stderr.contains("ERROR: AddressSanitizer: heap-buffer-overflow"),
            "{}: {stderr}",
            run.status
        );
    }

    /// The inputs [`assert_afl_loop_reports_only_past_each_input`] expects:
    /// a shorter, a longer, an empty and a longer input, then one that reads
    /// one past itself.
    pub(crate) const AFL_LOOP_INPUTS: &[&[u8]] = &[b"ABCD", b"ABCDEFGH", b"", b"ABCDEFGH", b"XBCD"];
}

#[cfg(test)]
mod tests {
    use super::HarnessGenError;

    #[test]
    fn error_display_for_target_not_found_includes_name() {
        let error = HarnessGenError::TargetNotFound("Parse".to_owned());

        assert!(error.to_string().contains("Parse"));
    }

    #[test]
    fn error_display_for_unsupported_param_type_includes_type_name() {
        let error = HarnessGenError::UnsupportedParamType("Root_Record".to_owned());

        assert!(error.to_string().contains("Root_Record"));
    }

    #[test]
    fn error_io_wraps_std_io_error() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "missing harness");
        let error = HarnessGenError::from(source);

        assert!(error.to_string().contains("missing harness"));
    }
}
