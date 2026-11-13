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
///   (`LPCBYTE`), now pair, and a parameter named like a harness local
///   (`Data`, `Size`, `Cur`) gets a local of its own.
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
