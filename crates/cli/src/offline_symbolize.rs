// SPDX-License-Identifier: Apache-2.0

//! Symbolize a sanitizer report after the fact. A report printed without a
//! symbolizer names each frame only as `(<module>+0x<offset>)`; when the
//! replayed binary is the build a finding was recorded with, those offsets are
//! resolved with `llvm-symbolizer` (or `addr2line`) and the report is
//! rewritten the way a symbolized run prints it, so its crash location can be
//! compared.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// How long one symbolizer run may take.
const SYMBOLIZER_TIMEOUT: Duration = Duration::from_secs(20);
/// Most frames a report has resolved.
const MAX_FRAMES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Llvm,
    Addr2line,
}

/// A symbolizer found on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Symbolizer {
    kind: Kind,
    program: PathBuf,
}

impl Symbolizer {
    /// The symbolizer's file name, for the note that says it was used.
    pub(crate) fn name(&self) -> String {
        self.program
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.program.display().to_string())
    }
}

/// The first symbolizer found: `ASAN_SYMBOLIZER_PATH`, `llvm-symbolizer` on
/// `PATH`, the newest versioned `llvm-symbolizer-<N>` on `PATH`, then
/// `addr2line`.
pub(crate) fn find() -> Option<Symbolizer> {
    find_in(
        std::env::var_os("ASAN_SYMBOLIZER_PATH").map(PathBuf::from),
        std::env::var_os("PATH").as_deref(),
    )
}

fn find_in(explicit: Option<PathBuf>, path: Option<&std::ffi::OsStr>) -> Option<Symbolizer> {
    let llvm = |program: PathBuf| Symbolizer {
        kind: Kind::Llvm,
        program,
    };
    if let Some(program) = explicit.filter(|program| program.is_file()) {
        let kind = if program
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains("addr2line"))
        {
            Kind::Addr2line
        } else {
            Kind::Llvm
        };
        return Some(Symbolizer { kind, program });
    }
    let dirs: Vec<PathBuf> = path
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect();
    if let Some(program) = dirs
        .iter()
        .map(|dir| dir.join("llvm-symbolizer"))
        .find(|candidate| candidate.is_file())
    {
        return Some(llvm(program));
    }
    let versioned = dirs
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let version: u32 = name.strip_prefix("llvm-symbolizer-")?.parse().ok()?;
            Some((version, entry.path()))
        })
        .max_by_key(|(version, _)| *version);
    if let Some((_, program)) = versioned {
        return Some(llvm(program));
    }
    dirs.iter()
        .map(|dir| dir.join("addr2line"))
        .find(|candidate| candidate.is_file())
        .map(|program| Symbolizer {
            kind: Kind::Addr2line,
            program,
        })
}

/// One `(<module>+0x<offset>)` reference in a report line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reference {
    module: String,
    offset: u64,
}

/// A resolved address: its function and, when known, `file:line[:col]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolved {
    function: String,
    position: Option<String>,
}

/// The `(<module>+0x<offset>)` an unsymbolized frame or `SUMMARY:` line ends
/// with (before any `(BuildId: ...)`), and where that group starts.
fn reference(line: &str) -> Option<(usize, Reference)> {
    let mut search = line;
    while let Some(open) = search.rfind('(') {
        let close = search[open..].find(')')? + open;
        let inner = &search[open + 1..close];
        if let Some((module, offset)) = inner.rsplit_once("+0x") {
            if !module.is_empty() && !module.contains(' ') {
                if let Ok(offset) = u64::from_str_radix(offset, 16) {
                    return Some((
                        open,
                        Reference {
                            module: module.to_owned(),
                            offset,
                        },
                    ));
                }
            }
        }
        search = &search[..open];
    }
    None
}

/// An unsymbolized crash-stack frame: `#N 0x<pc>  (<module>+0x<offset>)`.
fn frame_reference(line: &str) -> Option<(String, Reference)> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix('#')?;
    let (index, rest) = rest.split_once(' ')?;
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pc = rest.split_whitespace().next()?;
    if !pc.starts_with("0x") || rest.contains(" in ") {
        return None;
    }
    let (_, reference) = reference(rest)?;
    Some((format!("    #{index} {pc}"), reference))
}

/// An unsymbolized `SUMMARY: <Sanitizer>: <kind> (<module>+0x<offset>)` line.
fn summary_reference(line: &str) -> Option<(String, Reference)> {
    if !line.trim_start().starts_with("SUMMARY:") || line.contains(" in ") {
        return None;
    }
    let (start, reference) = reference(line)?;
    Some((line[..start].trim_end().to_owned(), reference))
}

/// `stderr` with every unsymbolized frame and `SUMMARY:` location resolved by
/// `symbolizer`, or `None` when nothing could be resolved.
pub(crate) fn symbolize_report(stderr: &str, symbolizer: &Symbolizer) -> Option<String> {
    let mut wanted: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut lines = 0usize;
    for line in stderr.lines() {
        let found = frame_reference(line)
            .map(|(_, reference)| reference)
            .or_else(|| summary_reference(line).map(|(_, reference)| reference));
        if let Some(reference) = found {
            lines += 1;
            if lines > MAX_FRAMES {
                break;
            }
            let offsets = wanted.entry(reference.module).or_default();
            if !offsets.contains(&reference.offset) {
                offsets.push(reference.offset);
            }
        }
    }
    let mut resolved: BTreeMap<(String, u64), Resolved> = BTreeMap::new();
    for (module, offsets) in &wanted {
        if !Path::new(module).is_file() {
            continue;
        }
        for (offset, result) in offsets.iter().zip(resolve(symbolizer, module, offsets)?) {
            if let Some(result) = result {
                resolved.insert((module.clone(), *offset), result);
            }
        }
    }
    if resolved.is_empty() {
        return None;
    }
    let lookup =
        |reference: &Reference| resolved.get(&(reference.module.clone(), reference.offset));
    let mut out = String::with_capacity(stderr.len());
    for line in stderr.lines() {
        if let Some((head, reference)) = frame_reference(line) {
            if let Some(found) = lookup(&reference) {
                out.push_str(&format!("{head} in {}", found.function));
                if let Some(position) = &found.position {
                    out.push(' ');
                    out.push_str(position);
                }
                out.push('\n');
                continue;
            }
        }
        if let Some((head, reference)) = summary_reference(line) {
            if let Some(found) = lookup(&reference) {
                match &found.position {
                    Some(position) => {
                        out.push_str(&format!("{head} {position} in {}\n", found.function))
                    }
                    None => out.push_str(&format!("{head} in {}\n", found.function)),
                }
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

/// Resolve `offsets` of `module`, one result per offset (`None` for one the
/// symbolizer could not name), or `None` when the symbolizer did not run.
fn resolve(
    symbolizer: &Symbolizer,
    module: &str,
    offsets: &[u64],
) -> Option<Vec<Option<Resolved>>> {
    let mut command = Command::new(&symbolizer.program);
    match symbolizer.kind {
        Kind::Llvm => {
            command.arg(format!("--obj={module}")).args([
                "--functions=linkage",
                "--demangle",
                "--no-inlines",
            ]);
        }
        Kind::Addr2line => {
            command.args(["-f", "-C", "-e", module]);
        }
    }
    command
        .args(offsets.iter().map(|offset| format!("{offset:#x}")))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    replay_min::process::isolate_process_group(&mut command);
    let mut child = command.spawn().ok()?;
    let stdout = child
        .stdout
        .take()
        .map(|pipe| replay_min::process::drain(pipe, 4 * 1024 * 1024));
    let (status, timed_out) =
        replay_min::process::wait_with_timeout(&mut child, SYMBOLIZER_TIMEOUT).ok()?;
    let output = stdout
        .and_then(|handle| {
            replay_min::process::join_bounded(handle, replay_min::process::DRAIN_GRACE)
        })
        .unwrap_or_default();
    if timed_out || !status.is_some_and(|status| status.success()) {
        return None;
    }
    let text = String::from_utf8_lossy(&output);
    let mut lines = text.lines().filter(|line| {
        // llvm-symbolizer separates addresses with an empty line.
        symbolizer.kind == Kind::Addr2line || !line.trim().is_empty()
    });
    let mut results = Vec::with_capacity(offsets.len());
    for _ in offsets {
        let function = lines.next()?.trim().to_owned();
        let position = lines.next()?.trim().to_owned();
        let position = position
            .split(" (discriminator")
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        let known_position = !position.starts_with("??") && !position.ends_with(":0");
        results.push(
            (function != "??" && !function.is_empty()).then(|| Resolved {
                function,
                position: known_position.then_some(position),
            }),
        );
    }
    Some(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNSYMBOLIZED: &str = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2 bp 0x3 sp 0x4\n\
        WRITE of size 1 at 0x1 thread T0\n\
        \x20   #0 0x5c350e08e77e  (/w/harnesses/H-1/main+0x10477e) (BuildId: 4f3a)\n\
        \x20   #1 0x5c350e08e7c2  (/w/harnesses/H-1/main+0x1047c2)\n\
        \x20   #2 0x702e9ca2a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16\n\
        \n\
        SUMMARY: AddressSanitizer: heap-buffer-overflow (/w/harnesses/H-1/main+0x10477e) (BuildId: 4f3a) in\n";

    #[test]
    fn unsymbolized_frames_and_the_summary_are_recognised() {
        let lines: Vec<&str> = UNSYMBOLIZED.lines().collect();
        let (head, reference) = frame_reference(lines[2]).expect("frame #0");
        assert_eq!(head, "    #0 0x5c350e08e77e");
        assert_eq!(
            reference,
            Reference {
                module: "/w/harnesses/H-1/main".to_owned(),
                offset: 0x10477e
            }
        );
        assert!(frame_reference(lines[4]).is_none(), "a symbolized frame");
        assert!(
            summary_reference("SUMMARY: AddressSanitizer: heap-buffer-overflow (/w/m+0x1a)")
                .is_some()
        );
        assert!(summary_reference(
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/a.c:3:5 in f"
        )
        .is_none());
    }

    #[test]
    fn the_symbolizer_search_order() {
        let dir = tempfile::tempdir().unwrap();
        let touch = |name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, b"").unwrap();
            path
        };
        let path = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find_in(None, Some(&path)), None);
        let addr2line = touch("addr2line");
        assert_eq!(find_in(None, Some(&path)).unwrap().kind, Kind::Addr2line);
        touch("llvm-symbolizer-17");
        let newest = touch("llvm-symbolizer-18");
        assert_eq!(find_in(None, Some(&path)).unwrap().program, newest);
        let plain = touch("llvm-symbolizer");
        assert_eq!(find_in(None, Some(&path)).unwrap().program, plain);
        let explicit = find_in(Some(addr2line.clone()), Some(&path)).unwrap();
        assert_eq!(
            (explicit.kind, explicit.program),
            (Kind::Addr2line, addr2line)
        );
    }

    /// A real binary's offsets resolve with addr2line, and the rewritten
    /// report parses with its function and position.
    #[cfg(unix)]
    #[test]
    fn a_report_of_a_real_binary_is_rewritten_symbolized() {
        let Ok(addr2line) = which::which("addr2line") else {
            eprintln!("skipping: addr2line unavailable");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("copy.c"),
            "__attribute__((noinline)) void copy_at(char *p) { p[4] = 1; }\nint main(void) { return 0; }\n",
        )
        .unwrap();
        let built = Command::new("cc")
            .current_dir(dir.path())
            .args(["-g", "-O0", "-no-pie", "-o", "copy", "copy.c"])
            .status();
        if !built.is_ok_and(|status| status.success()) {
            eprintln!("skipping: no C compiler");
            return;
        }
        let binary = dir.path().join("copy");
        let nm = Command::new("nm").arg(&binary).output();
        let Some(address) = nm.ok().and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find(|line| line.ends_with(" copy_at"))
                .and_then(|line| u64::from_str_radix(line.split_whitespace().next()?, 16).ok())
        }) else {
            eprintln!("skipping: nm unavailable");
            return;
        };
        let report = format!(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2 bp 0x3 sp 0x4\n\
             WRITE of size 1 at 0x1 thread T0\n\
             \x20   #0 {address:#x}  ({module}+{address:#x})\n\n\
             SUMMARY: AddressSanitizer: heap-buffer-overflow ({module}+{address:#x})\n",
            module = binary.display()
        );
        let symbolizer = Symbolizer {
            kind: Kind::Addr2line,
            program: addr2line,
        };
        let symbolized = symbolize_report(&report, &symbolizer).expect("resolved");
        let parsed = corpus::parse_sanitizer_report(&symbolized).expect("parses");
        assert_eq!(parsed.stack[0].function, "copy_at", "{symbolized}");
        assert!(
            parsed.stack[0]
                .file
                .as_deref()
                .is_some_and(|file| file.ends_with("copy.c")),
            "{symbolized}"
        );
        assert!(
            symbolized.contains("SUMMARY: AddressSanitizer: heap-buffer-overflow "),
            "{symbolized}"
        );
        assert!(symbolized.contains(" in copy_at\n"), "{symbolized}");
    }
}
