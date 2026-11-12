// SPDX-License-Identifier: Apache-2.0

//! How a harness binary consumes its input, decided in one place for `bhf fuzz`,
//! `bhf replay` and `bhf minimize`.
//!
//! The evidence, strongest first:
//!
//! 1. a declared input mode in a `harness-protocol.json` sidecar next to the
//!    binary (written by `bhf project run` from a `bhf.project.v1` target);
//! 2. the `BHF_FRAMED` marker in a launcher script that is the harness itself;
//! 3. a bhf `main.c` / `main.cpp` beside the binary or in any harness directory
//!    of the work dir (`generated_harnesses/`, `harnesses/`, `auto/`, `build/`
//!    `<id>/`);
//! 4. strings compiled into the binary: bhf's C/C++ driver reads `BHF_FRAMED`;
//!    so does the Ada runtime, which a GNAT-bound main identifies (the binder
//!    always embeds `GNAT Version: `, and the host-file probe also reads
//!    `BHF_EVENTS_PATH`); the libFuzzer runtime carries its own messages. The
//!    whole file is scanned, not just a prefix, so a binary staged alone into
//!    `build/<id>/main` is still recognised;
//! 5. a C/C++ source without the marker (a plain libFuzzer target);
//! 6. otherwise the Ada stdin/event-log protocol.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

/// The input protocol a harness speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HarnessProtocol {
    /// bhf's C/C++ (or Go/Rust/launcher) driver: framed fork-server loop, plus
    /// one input by file name (`argv[1]`) outside the loop.
    BhfFramed,
    /// A libFuzzer-style binary run on one input file per process.
    LibFuzzerSingleInput,
    /// The Ada runtime: input on stdin, results in an event log.
    StdinEventLog,
}

impl HarnessProtocol {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::BhfFramed => "bhf framed",
            Self::LibFuzzerSingleInput => "libFuzzer single input",
            Self::StdinEventLog => "stdin event log",
        }
    }
}

/// What decided the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolBasis {
    /// `input_mode` declared in [`PROTOCOL_SIDECAR`] next to the binary.
    Declared(String),
    /// `BHF_FRAMED` in the harness launcher script itself.
    LauncherMarker,
    /// `BHF_FRAMED` in this harness source.
    SourceMarker(PathBuf),
    /// bhf's framed driver strings compiled into the binary.
    EmbeddedDriver,
    /// The Ada runtime's strings compiled into the binary.
    EmbeddedAdaRuntime,
    /// A C/C++ source without bhf's marker.
    PlainSource(PathBuf),
    /// The libFuzzer runtime compiled into a binary with no bhf source.
    LibFuzzerBinary,
    /// Nothing identified the harness.
    Default,
}

impl ProtocolBasis {
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Declared(mode) => {
                format!("input mode '{mode}' declared in {PROTOCOL_SIDECAR}")
            }
            Self::LauncherMarker => "BHF_FRAMED marker in the launcher".to_owned(),
            Self::SourceMarker(path) => format!("BHF_FRAMED marker in {}", path.display()),
            Self::EmbeddedDriver => "bhf driver strings in the binary".to_owned(),
            Self::EmbeddedAdaRuntime => "Ada runtime strings in the binary".to_owned(),
            Self::PlainSource(path) => format!("libFuzzer source {}", path.display()),
            Self::LibFuzzerBinary => "libFuzzer runtime in the binary".to_owned(),
            Self::Default => "no marker found; Ada stdin harness assumed".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Detection {
    pub(crate) protocol: HarnessProtocol,
    pub(crate) basis: ProtocolBasis,
}

/// Sidecar declaring a harness's input mode, written next to the binary.
pub(crate) const PROTOCOL_SIDECAR: &str = "harness-protocol.json";

/// Harness directory roots under a work dir that can hold a harness `<id>/`.
pub(crate) const HARNESS_ROOTS: [&str; 4] = ["build", "harnesses", "auto", "generated_harnesses"];

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
/// Binaries larger than this are not scanned for markers.
const MAX_SCAN_BYTES: u64 = 1024 * 1024 * 1024;

/// Write [`PROTOCOL_SIDECAR`] into `dir` declaring `input_mode`.
pub(crate) fn write_declared_input_mode(
    dir: &Path,
    input_mode: &str,
    source: &str,
) -> std::io::Result<()> {
    let body = serde_json::json!({
        "schema_version": 1,
        "input_mode": input_mode,
        "source": source,
    });
    std::fs::write(
        dir.join(PROTOCOL_SIDECAR),
        serde_json::to_vec_pretty(&body).map_err(std::io::Error::other)?,
    )
}

fn declared_input_mode(harness: &Path) -> Option<String> {
    let dir = harness.parent()?;
    let candidates = [
        Some(dir.join(PROTOCOL_SIDECAR)),
        // An Ada harness lives in `<id>/obj/main`.
        (dir.file_name().is_some_and(|name| name == "obj"))
            .then(|| dir.parent().map(|parent| parent.join(PROTOCOL_SIDECAR)))
            .flatten(),
    ];
    candidates.into_iter().flatten().find_map(|path| {
        let bytes = std::fs::read(path).ok()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        value
            .get("input_mode")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    })
}

/// The harness id directory of `harness` (`<root>/<id>/main` or
/// `<root>/<id>/obj/main`).
fn harness_id_dir(harness: &Path) -> Option<&Path> {
    let parent = harness.parent()?;
    if parent.file_name().is_some_and(|name| name == "obj") {
        parent.parent()
    } else {
        Some(parent)
    }
}

/// The work dir a harness binary sits in, when its path has the
/// `<work>/<root>/<id>/main` shape of a harness root in [`HARNESS_ROOTS`].
pub(crate) fn work_dir_for_harness(harness: &Path) -> Option<PathBuf> {
    let id_dir = harness_id_dir(harness)?;
    let root = id_dir.parent()?;
    let name = root.file_name()?.to_str()?;
    HARNESS_ROOTS
        .contains(&name)
        .then(|| root.parent().map(Path::to_path_buf))
        .flatten()
}

/// Detect the protocol of `harness`, searching the harness directories of each
/// work dir in `work_dirs` (and of the work dir the harness path names) for its
/// sources.
pub(crate) fn detect(harness: &Path, work_dirs: &[&Path]) -> Detection {
    let embedded = || {
        let mut markers = embedded_markers(harness);
        // An Ada harness is built as `<id>/obj/main`; with the framed marker
        // and no other runtime string, that layout decides it.
        markers.ada_layout = harness
            .parent()
            .is_some_and(|dir| dir.file_name().is_some_and(|name| name == "obj"));
        markers
    };
    if let Some(mode) = declared_input_mode(harness) {
        if mode == "framed" {
            let protocol = if embedded().ada_runtime() {
                HarnessProtocol::StdinEventLog
            } else {
                HarnessProtocol::BhfFramed
            };
            return Detection {
                protocol,
                basis: ProtocolBasis::Declared(mode),
            };
        }
    }
    if read_text(harness, MAX_SOURCE_BYTES, true).is_some_and(|text| text.contains("BHF_FRAMED")) {
        return Detection {
            protocol: HarnessProtocol::BhfFramed,
            basis: ProtocolBasis::LauncherMarker,
        };
    }
    let mut plain_source = None;
    for dir in source_dirs(harness, work_dirs) {
        for name in ["main.c", "main.cpp"] {
            let path = dir.join(name);
            if let Some(text) = read_text(&path, MAX_SOURCE_BYTES, false) {
                if text.contains("BHF_FRAMED") {
                    return Detection {
                        protocol: HarnessProtocol::BhfFramed,
                        basis: ProtocolBasis::SourceMarker(path),
                    };
                }
                plain_source.get_or_insert(path);
            }
        }
    }
    let markers = embedded();
    if markers.bhf_driver() {
        return Detection {
            protocol: HarnessProtocol::BhfFramed,
            basis: ProtocolBasis::EmbeddedDriver,
        };
    }
    if let Some(path) = plain_source {
        return Detection {
            protocol: HarnessProtocol::LibFuzzerSingleInput,
            basis: ProtocolBasis::PlainSource(path),
        };
    }
    if markers.libfuzzer {
        return Detection {
            protocol: HarnessProtocol::LibFuzzerSingleInput,
            basis: ProtocolBasis::LibFuzzerBinary,
        };
    }
    Detection {
        protocol: HarnessProtocol::StdinEventLog,
        basis: if markers.ada_runtime() {
            ProtocolBasis::EmbeddedAdaRuntime
        } else {
            ProtocolBasis::Default
        },
    }
}

/// Directories that can hold the harness's `main.c` / `main.cpp`: its own
/// directory, then `<work>/<root>/<id>/` for every harness root of every work
/// dir (the given ones first, then the one the harness path names).
fn source_dirs(harness: &Path, work_dirs: &[&Path]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut push = |dir: PathBuf| {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    };
    if let Some(parent) = harness.parent() {
        push(parent.to_path_buf());
    }
    let Some(id) = harness_id_dir(harness).and_then(Path::file_name) else {
        return dirs;
    };
    let own = work_dir_for_harness(harness);
    let works = work_dirs
        .iter()
        .map(|work| work.to_path_buf())
        .chain(own)
        .collect::<Vec<_>>();
    for work in works {
        // `build/` last: a stale libFuzzer source there must not outrank a
        // generated driver source elsewhere (the marker wins either way).
        for root in ["generated_harnesses", "harnesses", "auto", "build"] {
            push(work.join(root).join(id));
        }
    }
    dirs
}

/// Read `path` as UTF-8 text of at most `max` bytes. With `executable`, a file
/// whose first 4 KiB hold a NUL byte or invalid UTF-8 (a binary) is skipped
/// before it is read whole.
fn read_text(path: &Path, max: u64, executable: bool) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > max {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    if executable {
        let mut prefix = [0u8; 4096];
        let read = file.read(&mut prefix).ok()?;
        if prefix[..read].contains(&0) || std::str::from_utf8(&prefix[..read]).is_err() {
            return None;
        }
        bytes.extend_from_slice(&prefix[..read]);
    }
    file.take(max + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > max {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Strings found in a harness binary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EmbeddedMarkers {
    /// `BHF_FRAMED`: read by bhf's drivers and by the Ada runtime.
    framed: bool,
    /// `BHF_EVENTS_PATH`: read by the Ada runtime's host-file probe only.
    events_path: bool,
    /// The version string GNAT's binder puts in every Ada main, whichever
    /// probe backend the Ada runtime was built with.
    gnat: bool,
    /// A message only the libFuzzer runtime prints.
    libfuzzer: bool,
    /// Not a string: the binary sits at `<id>/obj/main`, where Ada harnesses
    /// are built.
    ada_layout: bool,
}

impl EmbeddedMarkers {
    fn bhf_driver(self) -> bool {
        self.framed && !self.ada_runtime()
    }

    fn ada_runtime(self) -> bool {
        self.events_path || self.gnat || (self.framed && self.ada_layout && !self.libfuzzer)
    }
}

const FRAMED_MARKER: &[u8] = b"BHF_FRAMED";
const EVENTS_MARKER: &[u8] = b"BHF_EVENTS_PATH";
const GNAT_MARKER: &[u8] = b"GNAT Version: ";
const LIBFUZZER_MARKER: &[u8] = b"libFuzzer ignores flags";

type MarkerCache = Mutex<HashMap<PathBuf, (u64, Option<SystemTime>, EmbeddedMarkers)>>;

/// Scan `path` for [`EmbeddedMarkers`], cached per path, size and mtime so a
/// fuzz loop resolving the protocol again does not re-read the binary.
fn embedded_markers(path: &Path) -> EmbeddedMarkers {
    static CACHE: OnceLock<MarkerCache> = OnceLock::new();
    let Ok(metadata) = std::fs::metadata(path) else {
        return EmbeddedMarkers::default();
    };
    if !metadata.is_file() || metadata.len() > MAX_SCAN_BYTES {
        return EmbeddedMarkers::default();
    }
    let key = (metadata.len(), metadata.modified().ok());
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = cache.lock() {
        if let Some((len, modified, markers)) = cache.get(path) {
            if (*len, *modified) == key {
                return *markers;
            }
        }
    }
    let markers = scan_markers(path).unwrap_or_default();
    if let Ok(mut cache) = cache.lock() {
        cache.insert(path.to_path_buf(), (key.0, key.1, markers));
    }
    markers
}

fn scan_markers(path: &Path) -> std::io::Result<EmbeddedMarkers> {
    const CHUNK: usize = 1024 * 1024;
    let overlap = [FRAMED_MARKER, EVENTS_MARKER, GNAT_MARKER, LIBFUZZER_MARKER]
        .iter()
        .map(|marker| marker.len())
        .max()
        .unwrap_or(1)
        - 1;
    let mut file = std::fs::File::open(path)?;
    let mut markers = EmbeddedMarkers::default();
    let mut buffer: Vec<u8> = Vec::with_capacity(CHUNK + overlap);
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        markers.framed |= contains(&buffer, FRAMED_MARKER);
        markers.events_path |= contains(&buffer, EVENTS_MARKER);
        markers.gnat |= contains(&buffer, GNAT_MARKER);
        markers.libfuzzer |= contains(&buffer, LIBFUZZER_MARKER);
        if markers.framed && markers.events_path && markers.gnat && markers.libfuzzer {
            break;
        }
        let keep = buffer.len().min(overlap);
        buffer.drain(..buffer.len() - keep);
    }
    Ok(markers)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return true;
    };
    let mut offset = 0;
    while let Some(pos) = haystack[offset..].iter().position(|&b| b == first) {
        let start = offset + pos + 1;
        if haystack.len() >= start + rest.len() && &haystack[start..start + rest.len()] == rest {
            return true;
        }
        offset = start;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn binary(dir: &Path, contents: &[u8]) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join("main");
        fs::write(&path, contents).unwrap();
        path
    }

    /// An ELF-looking file whose marker sits past the first 4 KiB and across a
    /// scan-chunk boundary.
    fn padded(marker: &[u8], at: usize) -> Vec<u8> {
        let mut bytes = b"\x7fELF\x02\x01\x01\0".to_vec();
        bytes.resize(at, 0);
        bytes.extend_from_slice(marker);
        bytes.extend_from_slice(&[0u8; 64]);
        bytes
    }

    #[test]
    fn a_staged_framed_binary_without_sources_is_framed() {
        let work = tempfile::tempdir().unwrap();
        let harness = binary(
            &work.path().join("build/H-STAGED"),
            &padded(b"BHF_FRAMED\0BHF_COV_SHM\0", 1024 * 1024 - 4),
        );
        let detection = detect(&harness, &[work.path()]);
        assert_eq!(detection.protocol, HarnessProtocol::BhfFramed);
        assert_eq!(detection.basis, ProtocolBasis::EmbeddedDriver);
    }

    #[test]
    fn an_ada_binary_that_also_reads_the_framed_variable_stays_on_the_event_log() {
        let work = tempfile::tempdir().unwrap();
        let harness = binary(
            &work.path().join("build/H-ADA/obj"),
            &padded(b"BHF_FRAMED\0BHF_EVENTS_PATH\0", 8192),
        );
        let detection = detect(&harness, &[work.path()]);
        assert_eq!(detection.protocol, HarnessProtocol::StdinEventLog);
        assert_eq!(detection.basis, ProtocolBasis::EmbeddedAdaRuntime);
    }

    /// An Ada harness built with a probe backend other than the host file
    /// one reads `BHF_FRAMED` but never `BHF_EVENTS_PATH`; GNAT's binder
    /// string still identifies it.
    #[test]
    fn an_ada_binary_without_the_events_variable_stays_on_the_event_log() {
        let work = tempfile::tempdir().unwrap();
        let mut bytes = padded(b"BHF_FRAMED\0", 8192);
        bytes.extend_from_slice(b"GNAT Version: 13.3.0\0");
        let harness = binary(&work.path().join("build/H-ADA/obj"), &bytes);
        let detection = detect(&harness, &[work.path()]);
        assert_eq!(detection.protocol, HarnessProtocol::StdinEventLog);
        assert_eq!(detection.basis, ProtocolBasis::EmbeddedAdaRuntime);
        // The same strings outside the Ada layout are still an Ada main.
        let staged = binary(&work.path().join("build/H-ADA2"), &bytes);
        assert_eq!(
            detect(&staged, &[work.path()]).protocol,
            HarnessProtocol::StdinEventLog
        );
        // Without the binder string, the `<id>/obj/main` layout decides it.
        let layout = binary(
            &work.path().join("build/H-ADA3/obj"),
            &padded(b"BHF_FRAMED\0", 8192),
        );
        assert_eq!(
            detect(&layout, &[work.path()]).protocol,
            HarnessProtocol::StdinEventLog
        );
        // A C/C++ driver with the framed marker alone is framed.
        let driver = binary(
            &work.path().join("build/H-C"),
            &padded(b"BHF_FRAMED\0", 8192),
        );
        assert_eq!(
            detect(&driver, &[work.path()]).protocol,
            HarnessProtocol::BhfFramed
        );
    }

    #[test]
    fn a_libfuzzer_binary_runs_one_input_per_process() {
        let work = tempfile::tempdir().unwrap();
        let harness = binary(
            &work.path().join("build/H-LF"),
            &padded(
                b"INFO: libFuzzer ignores flags that start with '--'\0",
                9000,
            ),
        );
        let detection = detect(&harness, &[work.path()]);
        assert_eq!(detection.protocol, HarnessProtocol::LibFuzzerSingleInput);
        assert_eq!(detection.basis, ProtocolBasis::LibFuzzerBinary);
    }

    #[test]
    fn a_staged_binary_finds_its_source_in_another_harness_root() {
        let work = tempfile::tempdir().unwrap();
        let harness = binary(&work.path().join("build/H-GEN"), b"\x7fELF\0");
        let generated = work.path().join("generated_harnesses/H-GEN");
        fs::create_dir_all(&generated).unwrap();
        fs::write(generated.join("main.cpp"), "// BHF_FRAMED driver\n").unwrap();
        // Found through the work dir the harness path names, with none given.
        let detection = detect(&harness, &[]);
        assert_eq!(detection.protocol, HarnessProtocol::BhfFramed);
        assert_eq!(
            detection.basis,
            ProtocolBasis::SourceMarker(generated.join("main.cpp"))
        );
    }

    #[test]
    fn a_declared_framed_input_mode_wins_over_missing_markers() {
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("build/attrs");
        let harness = binary(&dir, b"\x7fELF\0stripped");
        assert_eq!(
            detect(&harness, &[work.path()]).protocol,
            HarnessProtocol::StdinEventLog
        );
        write_declared_input_mode(&dir, "framed", "bhf.project.v1 manifest").unwrap();
        let detection = detect(&harness, &[work.path()]);
        assert_eq!(detection.protocol, HarnessProtocol::BhfFramed);
        assert_eq!(
            detection.basis,
            ProtocolBasis::Declared("framed".to_owned())
        );
    }

    #[test]
    fn a_plain_libfuzzer_source_and_an_unmarked_binary_keep_their_protocols() {
        let work = tempfile::tempdir().unwrap();
        let lib = binary(&work.path().join("build/H-LIB"), b"\x7fELF\0");
        fs::write(
            work.path().join("build/H-LIB/main.c"),
            "int LLVMFuzzerTestOneInput(const unsigned char *, unsigned long);\n",
        )
        .unwrap();
        assert_eq!(
            detect(&lib, &[work.path()]).protocol,
            HarnessProtocol::LibFuzzerSingleInput
        );
        let plain = binary(&work.path().join("build/H-PLAIN"), b"\x7fELF\0plain");
        let detection = detect(&plain, &[work.path()]);
        assert_eq!(detection.protocol, HarnessProtocol::StdinEventLog);
        assert_eq!(detection.basis, ProtocolBasis::Default);
    }

    #[test]
    fn a_rebuilt_binary_is_scanned_again() {
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("build/H-RE");
        let harness = binary(&dir, b"\x7fELF\0old");
        assert_eq!(
            detect(&harness, &[work.path()]).protocol,
            HarnessProtocol::StdinEventLog
        );
        fs::write(&harness, padded(b"BHF_FRAMED", 5000)).unwrap();
        assert_eq!(
            detect(&harness, &[work.path()]).protocol,
            HarnessProtocol::BhfFramed
        );
    }

    #[test]
    fn work_dir_is_recovered_from_every_harness_root() {
        for root in HARNESS_ROOTS {
            let harness = Path::new("/w").join(root).join("H-1/main");
            assert_eq!(work_dir_for_harness(&harness), Some(PathBuf::from("/w")));
        }
        assert_eq!(
            work_dir_for_harness(Path::new("/w/build/H-1/obj/main")),
            Some(PathBuf::from("/w"))
        );
        assert_eq!(work_dir_for_harness(Path::new("/tmp/x/main")), None);
    }

    #[test]
    fn marker_search_handles_boundaries() {
        assert!(contains(b"xxBHF_FRAMED", b"BHF_FRAMED"));
        assert!(!contains(b"BHF_FRAME", b"BHF_FRAMED"));
        assert!(contains(b"BBHF_FRAMED", b"BHF_FRAMED"));
    }
}
