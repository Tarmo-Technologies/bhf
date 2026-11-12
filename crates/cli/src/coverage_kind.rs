// SPDX-License-Identifier: Apache-2.0

//! Which edge-coverage instrumentation a harness binary carries, read from the
//! binary itself.
//!
//! Every lane that feeds bhf's shared edge map (`BHF_COV_SHM`) fills the same
//! bitmap, but not with the same instrumentation: clang's
//! `-fsanitize-coverage=trace-pc-guard` numbers each edge through a guard
//! array, GCC's `trace-pc` has no guards and calls the driver's guard-less
//! `__sanitizer_cov_trace_pc` hook, and the Go lane folds its `-cover` counters
//! into the map. The kind is told from what the linked binary was compiled
//! with, so a label never names an instrumentation the build did not use:
//!
//! * a `__sancov_guards` section (ELF, Mach-O) or a `.SCOVP` section (COFF)
//!   holds clang's guards: `trace-pc-guard`;
//! * a Go binary (`.gopclntab` / `.go.buildinfo`) uses Go's counters;
//! * otherwise a translation unit whose recorded compiler command line (GCC's
//!   `DW_AT_producer`, `GNU C17 13.3.0 ... -fsanitize-coverage=trace-pc,...`,
//!   in `.debug_str` or inline in `.debug_info`) selects `trace-pc` was built
//!   with it. bhf's driver defines the hook in every build, so the hook's
//!   symbol alone says nothing.
//!
//! Anything else (a launcher script, a stripped binary, compressed debug
//! sections, a build without coverage) is not identified.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// The instrumentation that fills a harness's edge map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverageInstrumentation {
    /// clang's `-fsanitize-coverage=trace-pc-guard`.
    TracePcGuard,
    /// GCC's (or clang's) guard-less `-fsanitize-coverage=trace-pc`.
    TracePc,
    /// Go's `-cover` counters, folded into the map by the Go harness.
    GoCover,
}

impl CoverageInstrumentation {
    /// The label `run.json`, `finding.json` and the reports use.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::TracePcGuard => "sancov-trace-pc-guard",
            Self::TracePc => "sancov-trace-pc",
            Self::GoCover => "go-cover",
        }
    }
}

/// Label for an edge map whose writer the harness binary does not identify.
pub(crate) const UNIDENTIFIED_EDGE_MAP: &str = "edge-bitmap";

/// The most of one section read.
const MAX_SECTION: u64 = 256 * 1024 * 1024;
/// The most section headers read.
const MAX_SECTIONS: usize = 65_535;
/// ELF `SHF_COMPRESSED`: the section holds compressed data.
const SHF_COMPRESSED: u64 = 0x800;
/// ELF `SHT_NOBITS`: the section has no bytes in the file.
const SHT_NOBITS: u32 = 8;

/// The coverage instrumentation of the binary at `path`, or `None` when it is
/// not a binary or carries none this recognises.
pub(crate) fn of_binary(path: &Path) -> Option<CoverageInstrumentation> {
    let mut file = File::open(path).ok()?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).ok()?;
    match &magic {
        b"\x7fELF" => elf(&mut file),
        [b'M', b'Z', _, _] => pe(&mut file),
        [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] => macho(&mut file, false),
        [0xfe, 0xed, 0xfa, 0xcf] | [0xfe, 0xed, 0xfa, 0xce] => macho(&mut file, true),
        _ => None,
    }
}

fn read_at(file: &mut File, offset: u64, len: usize) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

#[derive(Clone, Copy)]
struct Endian {
    big: bool,
}

impl Endian {
    fn u16(self, bytes: &[u8], at: usize) -> Option<u16> {
        let raw: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
        Some(if self.big {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    }

    fn u32(self, bytes: &[u8], at: usize) -> Option<u32> {
        let raw: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
        Some(if self.big {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    }

    fn u64(self, bytes: &[u8], at: usize) -> Option<u64> {
        let raw: [u8; 8] = bytes.get(at..at + 8)?.try_into().ok()?;
        Some(if self.big {
            u64::from_be_bytes(raw)
        } else {
            u64::from_le_bytes(raw)
        })
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Whether `section` (a debug-information section's bytes) holds a recorded
/// compiler command line whose `-fsanitize-coverage=` list selects
/// `trace-pc`: a NUL-terminated producer string naming GCC (`GNU ...`) or
/// clang, with the option as one of its words.
fn records_trace_pc(section: &[u8]) -> bool {
    const OPTION: &[u8] = b"-fsanitize-coverage=";
    let mut from = 0;
    while let Some(found) = find(&section[from..], OPTION) {
        let at = from + found;
        let string_start = section[..at]
            .iter()
            .rposition(|byte| *byte == 0)
            .map_or(0, |nul| nul + 1);
        let value_start = at + OPTION.len();
        let value_end = section[value_start..]
            .iter()
            .position(|byte| matches!(byte, 0 | b' ' | b'\t' | b'\n'))
            .map_or(section.len(), |end| value_start + end);
        let producer = &section[string_start..at];
        let word = at > 0 && section[at - 1] == b' ';
        if word
            && (contains(producer, b"GNU ") || contains(producer, b"clang version"))
            && section[value_start..value_end]
                .split(|byte| *byte == b',')
                .any(|kind| kind == b"trace-pc")
        {
            return true;
        }
        from = value_end.max(at + 1);
    }
    false
}

fn elf(file: &mut File) -> Option<CoverageInstrumentation> {
    let header = read_at(file, 0, 64)?;
    let wide = match header[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let endian = Endian {
        big: match header[5] {
            1 => false,
            2 => true,
            _ => return None,
        },
    };
    let (shoff, shentsize, shnum, shstrndx) = if wide {
        (
            endian.u64(&header, 0x28)?,
            endian.u16(&header, 0x3a)?,
            endian.u16(&header, 0x3c)?,
            endian.u16(&header, 0x3e)?,
        )
    } else {
        (
            u64::from(endian.u32(&header, 0x20)?),
            endian.u16(&header, 0x2e)?,
            endian.u16(&header, 0x30)?,
            endian.u16(&header, 0x32)?,
        )
    };
    let entry = usize::from(shentsize);
    let count = usize::from(shnum).min(MAX_SECTIONS);
    if shoff == 0 || count == 0 || entry < if wide { 64 } else { 40 } {
        return None;
    }
    let table = read_at(file, shoff, count.checked_mul(entry)?)?;
    // (name offset, type, flags, file offset, size) of each section.
    let sections: Vec<(u32, u32, u64, u64, u64)> = (0..count)
        .filter_map(|index| {
            let at = index * entry;
            let name = endian.u32(&table, at)?;
            let kind = endian.u32(&table, at + 4)?;
            let (flags, offset, size) = if wide {
                (
                    endian.u64(&table, at + 0x08)?,
                    endian.u64(&table, at + 0x18)?,
                    endian.u64(&table, at + 0x20)?,
                )
            } else {
                (
                    u64::from(endian.u32(&table, at + 0x08)?),
                    u64::from(endian.u32(&table, at + 0x10)?),
                    u64::from(endian.u32(&table, at + 0x14)?),
                )
            };
            Some((name, kind, flags, offset, size))
        })
        .collect();
    let (_, _, _, names_offset, names_size) = *sections.get(usize::from(shstrndx))?;
    let names = read_at(
        file,
        names_offset,
        usize::try_from(names_size.min(MAX_SECTION)).ok()?,
    )?;
    let name_of = |offset: u32| -> &[u8] {
        let start = offset as usize;
        let rest = names.get(start..).unwrap_or_default();
        &rest[..rest.iter().position(|b| *b == 0).unwrap_or(rest.len())]
    };
    let mut go = false;
    let (mut strings, mut info) = (Vec::new(), Vec::new());
    for (name, kind, flags, offset, size) in &sections {
        let readable = *kind != SHT_NOBITS && flags & SHF_COMPRESSED == 0;
        match name_of(*name) {
            b"__sancov_guards" => return Some(CoverageInstrumentation::TracePcGuard),
            b".gopclntab" | b".go.buildinfo" => go = true,
            b".debug_str" if readable => strings.push((*offset, *size)),
            b".debug_info" if readable => info.push((*offset, *size)),
            _ => {}
        }
    }
    if go {
        return Some(CoverageInstrumentation::GoCover);
    }
    // GCC keeps an ELF producer in the merged string section; only without
    // one is it inline in `.debug_info`, the larger section.
    traced_debug_sections(file, if strings.is_empty() { &info } else { &strings })
}

/// `TracePc` when one of the debug sections at (file offset, size) records a
/// `trace-pc` compile ([`records_trace_pc`]).
fn traced_debug_sections(
    file: &mut File,
    sections: &[(u64, u64)],
) -> Option<CoverageInstrumentation> {
    sections
        .iter()
        .any(|&(offset, size)| {
            usize::try_from(size.min(MAX_SECTION))
                .ok()
                .and_then(|size| read_at(file, offset, size))
                .is_some_and(|bytes| records_trace_pc(&bytes))
        })
        .then_some(CoverageInstrumentation::TracePc)
}

fn pe(file: &mut File) -> Option<CoverageInstrumentation> {
    let endian = Endian { big: false };
    let dos = read_at(file, 0, 64)?;
    let pe_offset = u64::from(endian.u32(&dos, 0x3c)?);
    let coff = read_at(file, pe_offset, 24)?;
    if &coff[..4] != b"PE\0\0" {
        return None;
    }
    let sections = usize::from(endian.u16(&coff, 6)?);
    let symbol_table = u64::from(endian.u32(&coff, 12)?);
    let symbols = u64::from(endian.u32(&coff, 16)?);
    let optional = u64::from(endian.u16(&coff, 20)?);
    let table = read_at(file, pe_offset + 24 + optional, sections.checked_mul(40)?)?;
    // MinGW's long section names (`.debug_str`) are `/<offset>` into the
    // COFF string table that follows the symbol table.
    let strings = (symbol_table != 0)
        .then(|| {
            let at = symbol_table.checked_add(symbols.checked_mul(18)?)?;
            let size = u64::from(endian.u32(&read_at(file, at, 4)?, 0)?);
            read_at(file, at, usize::try_from(size.min(MAX_SECTION)).ok()?)
        })
        .flatten()
        .unwrap_or_default();
    let mut debug = Vec::new();
    for index in 0..sections {
        let header = &table[index * 40..index * 40 + 40];
        let short = &header[..8];
        let short = &short[..short.iter().position(|b| *b == 0).unwrap_or(8)];
        let name = match short.strip_prefix(b"/") {
            Some(digits) => {
                let offset: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
                let rest = strings.get(offset..).unwrap_or_default();
                &rest[..rest.iter().position(|b| *b == 0).unwrap_or(rest.len())]
            }
            None => short,
        };
        if name.starts_with(b".SCOVP") {
            return Some(CoverageInstrumentation::TracePcGuard);
        }
        // A PE has no mergeable strings, so GCC writes a producer inline in
        // `.debug_info`: both sections are read.
        if matches!(name, b".debug_str" | b".debug_info") {
            let size = u64::from(endian.u32(header, 16)?);
            let offset = u64::from(endian.u32(header, 20)?);
            debug.push((offset, size));
        }
    }
    traced_debug_sections(file, &debug)
}

fn macho(file: &mut File, big: bool) -> Option<CoverageInstrumentation> {
    let endian = Endian { big };
    let header = read_at(file, 0, 32)?;
    let wide = matches!(endian.u32(&header, 0)?, 0xfeed_facf | 0xcffa_edfe);
    let commands = endian.u32(&header, 16)? as usize;
    let commands_size = endian.u32(&header, 20)? as usize;
    let start = if wide { 32 } else { 28 };
    let bytes = read_at(file, start, commands_size.min(16 * 1024 * 1024))?;
    let mut at = 0usize;
    for _ in 0..commands.min(4096) {
        let command = endian.u32(&bytes, at)?;
        let size = endian.u32(&bytes, at + 4)? as usize;
        if size < 8 {
            return None;
        }
        // LC_SEGMENT_64 (0x19) / LC_SEGMENT (0x1) list their sections.
        let (first, section_size, count_at) = match command {
            0x19 => (72, 80, 64),
            0x1 => (56, 68, 48),
            _ => {
                at += size;
                continue;
            }
        };
        let count = endian.u32(&bytes, at + count_at)? as usize;
        for index in 0..count.min(4096) {
            let section = at + first + index * section_size;
            let name = bytes.get(section..section + 16)?;
            let name = &name[..name.iter().position(|b| *b == 0).unwrap_or(16)];
            if name == b"__sancov_guards" {
                return Some(CoverageInstrumentation::TracePcGuard);
            }
        }
        at += size;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn have(program: &str) -> bool {
        which::which(program).is_ok()
    }

    /// Build `source` with `compiler` and `flags` into `dir`, returning the
    /// binary.
    fn build(dir: &Path, compiler: &str, flags: &[&str], source: &str) -> std::path::PathBuf {
        let src = dir.join(format!("{}.c", compiler.replace('/', "_")));
        let out = dir.join(format!("{}.bin", compiler.replace('/', "_")));
        std::fs::write(&src, source).unwrap();
        let status = Command::new(compiler)
            .args(flags)
            .arg(&src)
            .arg("-o")
            .arg(&out)
            .status()
            .unwrap();
        assert!(status.success(), "{compiler} {flags:?} failed");
        out
    }

    const TRACE_PC_PROGRAM: &str = "void __sanitizer_cov_trace_pc(void) {}\n\
         int parse_record(int v) { return v > 3 ? v * 2 : v; }\n\
         int main(int argc, char **argv) { (void)argv; return parse_record(argc); }\n";

    const GUARD_PROGRAM: &str = "#include <stdint.h>\n\
         void __sanitizer_cov_trace_pc_guard_init(uint32_t *a, uint32_t *b) { (void)a; (void)b; }\n\
         void __sanitizer_cov_trace_pc_guard(uint32_t *g) { (void)g; }\n\
         void __sanitizer_cov_trace_pc(void) {}\n\
         int parse_record(int v) { return v > 3 ? v * 2 : v; }\n\
         int main(int argc, char **argv) { (void)argv; return parse_record(argc); }\n";

    #[test]
    fn a_gcc_trace_pc_binary_is_told_from_a_clang_guard_binary() {
        let dir = tempfile::tempdir().unwrap();
        if have("gcc") {
            let binary = build(
                dir.path(),
                "gcc",
                &["-O1", "-g", "-fsanitize-coverage=trace-pc"],
                TRACE_PC_PROGRAM,
            );
            assert_eq!(of_binary(&binary), Some(CoverageInstrumentation::TracePc));
        } else {
            eprintln!("skip: gcc unavailable");
        }
        if have("clang") {
            let binary = build(
                dir.path(),
                "clang",
                &["-O1", "-fsanitize-coverage=trace-pc-guard"],
                GUARD_PROGRAM,
            );
            assert_eq!(
                of_binary(&binary),
                Some(CoverageInstrumentation::TracePcGuard)
            );
        } else {
            eprintln!("skip: clang unavailable");
        }
    }

    /// Foreign binaries are read too: a 64-bit and a 32-bit cross build.
    #[test]
    fn cross_built_trace_pc_binaries_are_recognised() {
        let dir = tempfile::tempdir().unwrap();
        for compiler in ["aarch64-linux-gnu-gcc", "arm-linux-gnueabihf-gcc"] {
            if !have(compiler) {
                eprintln!("skip: {compiler} unavailable");
                continue;
            }
            let binary = build(
                dir.path(),
                compiler,
                &["-O1", "-g", "-fsanitize-coverage=trace-pc"],
                TRACE_PC_PROGRAM,
            );
            assert_eq!(
                of_binary(&binary),
                Some(CoverageInstrumentation::TracePc),
                "{compiler}"
            );
        }
    }

    #[test]
    fn a_binary_without_coverage_hooks_and_a_script_are_not_identified() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("launcher");
        std::fs::write(&script, "#!/bin/sh\nexec python3 harness.py \"$@\"\n").unwrap();
        assert_eq!(of_binary(&script), None);
        assert_eq!(of_binary(&dir.path().join("missing")), None);
        if have("gcc") {
            let binary = build(
                dir.path(),
                "gcc",
                &["-O1"],
                "int main(void) { return 0; }\n",
            );
            assert_eq!(of_binary(&binary), None);
        }
    }

    /// bhf's driver defines the guard-less hook whatever the build, so a
    /// harness linked with it is labelled `trace-pc` only when its own code
    /// was compiled with that coverage, natively and for another target.
    #[test]
    fn a_driver_linked_harness_is_labelled_by_its_compile_not_the_hook() {
        let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.c");
        std::fs::write(
            &target,
            "#include <stddef.h>\n#include <stdint.h>\n\
             int bhf_run_one(const uint8_t *data, size_t size) {\n\
                 return size > 3 && data[0] == 'A' ? data[1] : 0;\n\
             }\n",
        )
        .unwrap();
        for compiler in ["gcc", "aarch64-linux-gnu-gcc"] {
            if !have(compiler) {
                eprintln!("skip: {compiler} unavailable");
                continue;
            }
            let link = |name: &str, coverage: &[&str]| {
                let object = dir.path().join(format!("{compiler}-{name}-driver.o"));
                let status = Command::new(compiler)
                    .args(["-O1", "-g", "-D_GNU_SOURCE", "-c", "-o"])
                    .arg(&object)
                    .arg(&driver)
                    .status()
                    .unwrap();
                assert!(status.success(), "{compiler}: the driver compiles");
                let binary = dir.path().join(format!("{compiler}-{name}"));
                let status = Command::new(compiler)
                    .args(["-O1", "-g"])
                    .args(coverage)
                    .arg(&target)
                    .arg(&object)
                    .arg("-o")
                    .arg(&binary)
                    .status()
                    .unwrap();
                assert!(
                    status.success(),
                    "{compiler} {coverage:?}: the harness links"
                );
                binary
            };
            let plain = link("plain", &[]);
            assert_eq!(
                of_binary(&plain),
                None,
                "{compiler}: no coverage was compiled in"
            );
            let covered = link("covered", &["-fsanitize-coverage=trace-pc,trace-cmp"]);
            assert_eq!(
                of_binary(&covered),
                Some(CoverageInstrumentation::TracePc),
                "{compiler}"
            );
        }
    }

    #[test]
    fn only_a_recorded_compile_with_trace_pc_counts() {
        let section = |strings: &[&str]| -> Vec<u8> {
            strings
                .iter()
                .flat_map(|s| [s.as_bytes(), b"\0"].concat())
                .collect()
        };
        assert!(records_trace_pc(&section(&[
            "parse.c",
            "GNU C17 13.3.0 -mtune=generic -g -O1 -fsanitize-coverage=trace-pc,trace-cmp -fPIE",
        ])));
        assert!(records_trace_pc(&section(&[
            "GNU C17 12.4.0 -meb -g -fsanitize-coverage=trace-cmp,trace-pc"
        ])));
        // Inline in `.debug_info`, after binary attribute bytes.
        let mut info = vec![0x01, 0x11, 0x25];
        info.extend_from_slice(b"GNU C11 13.3.0 -g -fsanitize-coverage=trace-pc\0\x0c");
        assert!(records_trace_pc(&info));
        for unrelated in [
            // The driver itself, and any other object, compiled without it.
            "GNU C17 13.3.0 -mtune=generic -g -O1",
            // Another coverage kind, or the option's text outside a producer.
            "GNU C17 13.3.0 -g -fsanitize-coverage=trace-cmp",
            "GNU C17 13.3.0 -g -fsanitize-coverage=trace-pc-guard",
            "#define COVERAGE -fsanitize-coverage=trace-pc",
            "GNU C17 13.3.0 -g -Xfsanitize-coverage=trace-pc",
        ] {
            assert!(!records_trace_pc(&section(&[unrelated])), "{unrelated}");
        }
    }

    /// A MinGW PE names its debug sections through the COFF string table; a
    /// `trace-pc` producer there labels it, a `.SCOVP` section is clang's.
    #[test]
    fn a_pe_binary_is_read_through_its_long_section_names() {
        fn pe(section_name: &[u8; 8], strings: &[u8], data: &[u8]) -> Vec<u8> {
            let mut image = vec![0u8; 0x40];
            image[0..2].copy_from_slice(b"MZ");
            image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
            let data_at = 0x40 + 24 + 40;
            let symbols_at = data_at + data.len();
            image.extend_from_slice(b"PE\0\0");
            image.extend_from_slice(&0x8664u16.to_le_bytes());
            image.extend_from_slice(&1u16.to_le_bytes());
            image.extend_from_slice(&0u32.to_le_bytes());
            image.extend_from_slice(&(symbols_at as u32).to_le_bytes());
            image.extend_from_slice(&0u32.to_le_bytes());
            image.extend_from_slice(&0u16.to_le_bytes());
            image.extend_from_slice(&0u16.to_le_bytes());
            let mut header = [0u8; 40];
            header[..8].copy_from_slice(section_name);
            header[16..20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            header[20..24].copy_from_slice(&(data_at as u32).to_le_bytes());
            image.extend_from_slice(&header);
            image.extend_from_slice(data);
            image.extend_from_slice(&((strings.len() + 4) as u32).to_le_bytes());
            image.extend_from_slice(strings);
            image
        }
        let dir = tempfile::tempdir().unwrap();
        let read = |name: &str, image: Vec<u8>| {
            let path = dir.path().join(name);
            std::fs::write(&path, image).unwrap();
            of_binary(&path)
        };
        let producer = b"GNU C17 13.2.0 -g -O1 -fsanitize-coverage=trace-pc,trace-cmp\0";
        assert_eq!(
            read(
                "traced.exe",
                pe(b"/4\0\0\0\0\0\0", b".debug_str\0", producer)
            ),
            Some(CoverageInstrumentation::TracePc)
        );
        assert_eq!(
            read(
                "plain.exe",
                pe(b"/4\0\0\0\0\0\0", b".debug_str\0", b"GNU C17 13.2.0 -g\0")
            ),
            None
        );
        // The producer counts only in a debug section.
        assert_eq!(read("data.exe", pe(b".rdata\0\0", b"", producer)), None);
        assert_eq!(
            read("guard.exe", pe(b".SCOVP$G", b"", b"\0\0\0\0")),
            Some(CoverageInstrumentation::TracePcGuard)
        );
    }
}
