// SPDX-License-Identifier: Apache-2.0

//! Relocating a harness whose build and launch files name absolute paths.
//!
//! Every lane but C and C++ writes its harness with absolute paths baked in: a
//! launcher `exec`s `/usr/bin/python3` on `<work>/harnesses/<id>/bhf_driver.py`
//! with the scanned tree on `PYTHONPATH`; a `go.mod` replaces the target module
//! with `<tree>`; a `Cargo.toml` path-depends on the target crate; a GPR
//! project names its source dirs. A capsule copies each of those dirs (a
//! [`Mount`]) to its own place and rewrites every path into it as
//! [`CAPSULE_ROOT`]-relative. `build.sh` renders the rewritten files into
//! `build/` with the capsule's real location, then builds there, so the shipped
//! files stay as packaged and a rebuild in a clean copy works anywhere.
//!
//! A rewritten file that still names the work dir or the scanned tree after
//! the rewrite would only rebuild where the capsule was made, so relocation
//! refuses it, naming the path. A text file that ships as is (a target source)
//! and names them is reported in a warning.

use super::{refuse, CapsuleFile, GeneratedFile, Toolchain};
use std::path::{Path, PathBuf};

/// The placeholder build.sh replaces with the capsule's absolute path.
pub(crate) const CAPSULE_ROOT: &str = "@BHF_CAPSULE@";

/// Most files and bytes one capsule copies from a tree.
const MAX_FILES: usize = 20_000;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
/// The largest file shipped as is that is checked for paths it should not name.
const MAX_SCANNED_TEXT: u64 = 1024 * 1024;

/// What a mount ships.
pub(crate) enum Contents {
    /// Every file under the dir, except what `skip` rejects (`(relative path,
    /// is a dir)`).
    Tree { skip: fn(&Path, bool) -> bool },
    /// These files (relative to the dir).
    Files(Vec<PathBuf>),
    /// Nothing: an output dir the build writes (an object dir).
    Nothing,
}

/// One original directory and where it lives in the capsule.
pub(crate) struct Mount {
    /// The original absolute directory.
    pub(crate) from: PathBuf,
    /// The capsule-relative dir its paths are rewritten to.
    pub(crate) target: String,
    /// Where its files ship (capsule-relative), when it ships any.
    pub(crate) ship_to: Option<String>,
    /// Whether its text files are templates build.sh renders into `target`.
    pub(crate) rendered: bool,
    pub(crate) contents: Contents,
}

impl Mount {
    /// Ships to `to`, rendered by build.sh into `build/<to>` (the harness).
    pub(crate) fn rendered(from: impl Into<PathBuf>, to: &str, contents: Contents) -> Self {
        Self {
            from: from.into(),
            target: format!("build/{to}"),
            ship_to: Some(to.to_owned()),
            rendered: true,
            contents,
        }
    }

    /// Ships to `to` and is used there as shipped (the target sources).
    pub(crate) fn in_place(from: impl Into<PathBuf>, to: &str, contents: Contents) -> Self {
        Self {
            from: from.into(),
            target: to.to_owned(),
            ship_to: Some(to.to_owned()),
            rendered: false,
            contents,
        }
    }

    /// Ships nothing; its paths become `target` (a build output dir).
    pub(crate) fn output(from: impl Into<PathBuf>, target: &str) -> Self {
        Self {
            from: from.into(),
            target: target.to_owned(),
            ship_to: None,
            rendered: false,
            contents: Contents::Nothing,
        }
    }
}

/// An absolute program a launcher `exec`s, replaced by the program build.sh
/// finds on the host that runs it.
pub(crate) struct ToolSlot {
    /// The program as the launcher names it, quoted (`"/usr/bin/python3"`).
    pub(crate) original: String,
    /// The toolchain that resolves it.
    pub(crate) toolchain: Toolchain,
    /// The build.sh variable holding the resolved program (`TOOL_0`).
    pub(crate) var: String,
}

impl ToolSlot {
    fn placeholder(&self) -> String {
        format!("@BHF_{}@", self.var)
    }
}

/// The relocation of one harness.
#[derive(Default)]
pub(crate) struct Relocator {
    pub(crate) mounts: Vec<Mount>,
    pub(crate) tools: Vec<ToolSlot>,
    /// Dirs no rewritten file may still name (the work dir, the scanned tree).
    pub(crate) protected: Vec<PathBuf>,
    /// Dirs no mount copies (a work dir inside the scanned tree).
    pub(crate) exclude: Vec<PathBuf>,
}

/// The files a relocation ships.
#[derive(Default)]
pub(crate) struct Relocated {
    pub(crate) files: Vec<CapsuleFile>,
    pub(crate) generated: Vec<GeneratedFile>,
    /// Shipped files build.sh renders (capsule-relative).
    pub(crate) templates: Vec<String>,
    pub(crate) warnings: Vec<String>,
}

#[cfg(all(test, unix))]
impl Relocated {
    /// Whether the capsule ships `to` (capsule-relative), copied or written.
    pub(crate) fn ships(&self, to: &str) -> bool {
        self.files.iter().any(|file| file.to == to)
            || self.generated.iter().any(|file| file.to == to)
    }
}

impl Relocator {
    /// Add the slot for the program a launcher `exec`s, when it names one by
    /// absolute path: `exec "/usr/bin/python3" ...`.
    pub(crate) fn exec_tool(&mut self, launcher: &str, toolchain: Toolchain) {
        let Some(program) = exec_program(launcher) else {
            return;
        };
        if !program.starts_with('/') {
            return;
        }
        let var = format!("TOOL_{}", self.tools.len());
        self.tools.push(ToolSlot {
            original: format!("\"{program}\""),
            toolchain,
            var,
        });
    }

    /// The capsule-relative path build.sh uses for an original path.
    pub(crate) fn build_path(&self, path: &Path) -> Option<String> {
        self.mount_of(path).map(|(mount, rel)| {
            if rel.is_empty() {
                mount.target.clone()
            } else {
                format!("{}/{rel}", mount.target)
            }
        })
    }

    /// The deepest mount holding `path`, and `path` relative to it.
    fn mount_of(&self, path: &Path) -> Option<(&Mount, String)> {
        self.mounts
            .iter()
            .filter(|mount| path.starts_with(&mount.from))
            .max_by_key(|mount| mount.from.components().count())
            .map(|mount| {
                let rel = path
                    .strip_prefix(&mount.from)
                    .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                (mount, rel)
            })
    }

    /// `text` with every path into a mount rewritten to its capsule path, or
    /// the protected path a part of it still names.
    pub(crate) fn rewrite(&self, text: &str) -> Result<String, String> {
        let mut text = text.to_owned();
        for slot in &self.tools {
            text = text.replace(&slot.original, &format!("\"{}\"", slot.placeholder()));
        }
        let mut mounts: Vec<&Mount> = self.mounts.iter().collect();
        mounts.sort_by_key(|mount| std::cmp::Reverse(mount.from.as_os_str().len()));
        for mount in mounts {
            // A protected dir inside this mount (a work dir inside the scanned
            // tree) must already be rewritten away: this mount would swallow
            // it into a copy that does not hold it.
            for protected in &self.protected {
                if protected != &mount.from && protected.starts_with(&mount.from) {
                    if let Some(at) = find_path(&text, &protected.to_string_lossy()) {
                        return Err(path_at(&text, at));
                    }
                }
            }
            let from = mount.from.to_string_lossy();
            let to = format!("{CAPSULE_ROOT}/{}", mount.target);
            text = replace_path(&text, &from, &to);
        }
        for protected in &self.protected {
            if let Some(at) = find_path(&text, &protected.to_string_lossy()) {
                return Err(path_at(&text, at));
            }
        }
        Ok(text)
    }

    /// Copy every mount's files and rewrite the rendered ones. A file that
    /// ships as is but names the work dir or the scanned tree is reported in a
    /// warning: a rebuild elsewhere cannot reach what it names.
    pub(crate) fn relocate(&self) -> anyhow::Result<Relocated> {
        let mut out = Relocated::default();
        let mut budget = (MAX_FILES, MAX_BYTES);
        let mut naming_protected = Vec::new();
        for mount in &self.mounts {
            let Some(ship_to) = &mount.ship_to else {
                continue;
            };
            let rels = match &mount.contents {
                Contents::Nothing => continue,
                Contents::Files(files) => files.clone(),
                Contents::Tree { skip } => walk(&mount.from, *skip, &self.exclude, &mut budget)?,
            };
            for rel in rels {
                let from = mount.from.join(&rel);
                if !from.is_file() {
                    continue;
                }
                let rel = rel.to_string_lossy().replace('\\', "/");
                let to = format!("{ship_to}/{rel}");
                if !mount.rendered {
                    if let Some(path) = self.protected_path_in(&from) {
                        naming_protected.push(format!("{to} names {path}"));
                    }
                    out.files.push(CapsuleFile { from, to });
                    continue;
                }
                let bytes = std::fs::read(&from)
                    .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", from.display()))?;
                let Some(text) = text_of(&bytes) else {
                    out.files.push(CapsuleFile { from, to });
                    continue;
                };
                let rewritten = self.rewrite(text).map_err(|path| {
                    refuse(format!(
                        "{} names {path}, which a capsule cannot relocate (it is not under \
                         any dir the capsule ships)",
                        from.display()
                    ))
                })?;
                if rewritten == text {
                    out.files.push(CapsuleFile { from, to });
                } else {
                    out.generated.push(GeneratedFile {
                        to: to.clone(),
                        bytes: rewritten.into_bytes(),
                        executable: is_executable(&from),
                    });
                    out.templates.push(to);
                }
            }
        }
        if let Some(first) = naming_protected.first() {
            out.warnings.push(format!(
                "{} shipped file(s) still name the work dir or the scanned tree, which a \
                 rebuild elsewhere cannot reach ({first}{})",
                naming_protected.len(),
                if naming_protected.len() > 1 {
                    ", ..."
                } else {
                    ""
                }
            ));
        }
        Ok(out)
    }

    /// The protected path a text file that ships as is names, if it names one
    /// (files over [`MAX_SCANNED_TEXT`] are not read).
    fn protected_path_in(&self, file: &Path) -> Option<String> {
        if std::fs::metadata(file).map_or(true, |meta| meta.len() > MAX_SCANNED_TEXT) {
            return None;
        }
        let bytes = std::fs::read(file).ok()?;
        let text = text_of(&bytes)?;
        self.protected.iter().find_map(|protected| {
            find_path(text, &protected.to_string_lossy()).map(|at| path_at(text, at))
        })
    }

    /// The build.sh lines that find each program, copy the rendered mounts
    /// into `build/` and render their templates there.
    pub(crate) fn render_script(&self, relocated: &Relocated) -> String {
        let mut script = String::new();
        for slot in &self.tools {
            script.push_str(&resolve_tool(&slot.var, &slot.toolchain));
        }
        script.push_str(
            "here=$(pwd -P)\n\
             sed_escape() { printf '%s\\n' \"$1\" | sed -e 's/[\\\\|&]/\\\\&/g'; }\n\
             SED_HERE=$(sed_escape \"$here\")\n",
        );
        for slot in &self.tools {
            script.push_str(&format!(
                "SED_{var}=$(sed_escape \"${var}\")\n",
                var = slot.var
            ));
        }
        script.push_str("rm -rf build\nmkdir -p build\n");
        let rendered: Vec<&String> = self
            .mounts
            .iter()
            .filter(|mount| mount.rendered)
            .filter_map(|mount| mount.ship_to.as_ref())
            .collect();
        for mount in self.mounts.iter().filter(|mount| mount.rendered) {
            let Some(ship_to) = &mount.ship_to else {
                continue;
            };
            // A dir shipped inside another rendered one is copied with it.
            if rendered
                .iter()
                .any(|outer| *outer != ship_to && Path::new(ship_to).starts_with(outer.as_str()))
            {
                continue;
            }
            let target = super::sh_word(&mount.target);
            if let Some(parent) = Path::new(&mount.target)
                .parent()
                .filter(|parent| parent != &Path::new("build"))
            {
                script.push_str(&format!(
                    "mkdir -p {}\n",
                    super::sh_word(&parent.to_string_lossy())
                ));
            }
            script.push_str(&format!(
                "if [ -d {from} ]; then cp -R {from} {target}; else mkdir -p {target}; fi\n",
                from = super::sh_word(ship_to),
            ));
        }
        for mount in &self.mounts {
            // An output dir, or a dir that shipped empty (a source dir with no
            // files yet), must still exist for the build to name it.
            if mount.ship_to.is_none() || !mount.rendered {
                script.push_str(&format!("mkdir -p {}\n", super::sh_word(&mount.target)));
            }
        }
        if !relocated.templates.is_empty() {
            let mut substitutions = format!("-e \"s|{CAPSULE_ROOT}|$SED_HERE|g\"");
            for slot in &self.tools {
                substitutions.push_str(&format!(
                    " -e \"s|{}|$SED_{}|g\"",
                    slot.placeholder(),
                    slot.var
                ));
            }
            script.push_str(&format!(
                "render() {{ sed {substitutions} \"$1\" > \"$2\"; }}\n"
            ));
            for template in &relocated.templates {
                let rendered = self.rendered_path(template);
                script.push_str(&format!(
                    "render {} {}\n",
                    super::sh_word(template),
                    super::sh_word(&rendered)
                ));
            }
        }
        script
    }

    /// Where build.sh renders a shipped template.
    fn rendered_path(&self, shipped: &str) -> String {
        self.mounts
            .iter()
            .filter(|mount| mount.rendered)
            .find_map(|mount| {
                let ship_to = mount.ship_to.as_deref()?;
                let rest = shipped.strip_prefix(ship_to)?.strip_prefix('/')?;
                Some(format!("{}/{rest}", mount.target))
            })
            .unwrap_or_else(|| format!("build/{shipped}"))
    }
}

/// The build.sh line setting `$<var>` to the program `toolchain` names on the
/// host that runs it, or stopping with what is missing.
pub(crate) fn resolve_tool(var: &str, toolchain: &Toolchain) -> String {
    let env = toolchain.env_var;
    let mut lookups = vec![format!("command -v \"${{{env}:-{}}}\"", toolchain.default)];
    lookups.extend(
        toolchain
            .fallbacks
            .iter()
            .map(|name| format!("command -v {name}")),
    );
    format!(
        "{var}=$({{ {}; }} 2>/dev/null | head -n 1)\n\
         if [ -z \"${var}\" ]; then echo \"build.sh: needs {} (or \\${env}): it {}\" >&2; exit 127; fi\n",
        lookups.join(" || "),
        toolchain.default,
        toolchain.purpose,
    )
}

/// The program a launcher script's `exec` line runs, unquoted.
pub(crate) fn exec_program(launcher: &str) -> Option<String> {
    let line = launcher
        .lines()
        .map(str::trim_start)
        .find(|line| line.starts_with("exec "))?;
    let rest = line["exec ".len()..].trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        quoted.find('"').map(|end| quoted[..end].to_owned())
    } else {
        rest.split_whitespace().next().map(str::to_owned)
    }
}

/// UTF-8 text without NUL bytes, else `None` (a binary file ships as is).
fn text_of(bytes: &[u8]) -> Option<&str> {
    if bytes.contains(&0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Characters that continue a path name: a match followed by one of them is a
/// longer, different name (`/src` in `/src2`).
fn continues_name(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '@' | '~')
}

/// The first occurrence of `path` in `text` that is a whole path or a prefix
/// ending at a `/` (or the end of the name).
fn find_path(text: &str, path: &str) -> Option<usize> {
    if path.is_empty() {
        return None;
    }
    let mut from = 0;
    while let Some(found) = text[from..].find(path) {
        let at = from + found;
        let end = at + path.len();
        let before_ok = text[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(continues_name(c) || c == '/'));
        let after_ok = text[end..]
            .chars()
            .next()
            .is_none_or(|c| !continues_name(c));
        if before_ok && after_ok {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// `text` with each whole-path occurrence of `from` replaced by `to`.
fn replace_path(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        match find_path(rest, from) {
            Some(at) => {
                out.push_str(&rest[..at]);
                out.push_str(to);
                rest = &rest[at + from.len()..];
            }
            None => {
                out.push_str(rest);
                return out;
            }
        }
    }
}

/// The path-like token at `at` in `text`, for a message.
fn path_at(text: &str, at: usize) -> String {
    text[at..]
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | ':' | ';' | ',' | ')'))
        .take(200)
        .collect()
}

/// The files under `root` (relative), skipping what `skip` rejects, within the
/// copy budget.
fn walk(
    root: &Path,
    skip: fn(&Path, bool) -> bool,
    exclude: &[PathBuf],
    budget: &mut (usize, u64),
) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let dir = root.join(&rel);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child = rel.join(entry.file_name());
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            // A symlinked dir is not followed: it may loop or leave the tree.
            let is_dir = kind.is_dir();
            if skip(&child, is_dir) || (is_dir && exclude.contains(&root.join(&child))) {
                continue;
            }
            if is_dir {
                stack.push(child);
                continue;
            }
            let path = root.join(&child);
            if kind.is_symlink() && !path.is_file() {
                continue;
            }
            let size = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
            if budget.0 == 0 || budget.1 < size {
                return Err(refuse(format!(
                    "{} holds more than a capsule ships ({MAX_FILES} files / {} MiB in all)",
                    root.display(),
                    MAX_BYTES / (1024 * 1024)
                )));
            }
            budget.0 -= 1;
            budget.1 -= size;
            out.push(child);
        }
    }
    out.sort();
    Ok(out)
}

/// Dirs no capsule copies from a scanned tree: version control, build
/// outputs, caches, and bhf's own work dirs.
pub(crate) fn is_tree_noise(rel: &Path, is_dir: bool) -> bool {
    let Some(name) = rel.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if is_dir {
        return matches!(
            name,
            ".git"
                | ".hg"
                | ".svn"
                | "bhf_work"
                | "__pycache__"
                | ".mypy_cache"
                | ".pytest_cache"
                | ".tox"
                | ".venv"
                | "venv"
                | ".gradle"
                | ".idea"
                | ".vs"
                | "target"
                | "obj"
                | "bin"
        );
    }
    name.ends_with(".pyc")
}

/// What a harness dir holds that is run state, not part of the harness: the
/// fuzz loop's shared maps and logs.
pub(crate) fn is_harness_state(rel: &Path, is_dir: bool) -> bool {
    let Some(name) = rel.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if is_dir {
        return matches!(name, "__pycache__" | "corpus" | "seeds" | "crashes");
    }
    name.ends_with(".shm")
        || name.ends_with(".log")
        || matches!(
            name,
            "runtrace.jsonl"
                | "result.json"
                | "covered-lines.txt"
                | "coverage-summary.json"
                | "cmplog.jsonl"
                | "sink_report.txt"
                | "dictionary.txt"
                | "learned_dictionary.txt"
                | "Mayhemfile"
                | "PORTABILITY.md"
                | "coverage-replay-diagnostic.txt"
                | "expert-oracle.json"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn relocator(work: &Path, tree: &Path) -> Relocator {
        Relocator {
            mounts: vec![
                Mount::rendered(
                    work.join("harnesses/H-P0001"),
                    "harness",
                    Contents::Tree {
                        skip: is_harness_state,
                    },
                ),
                Mount::in_place(
                    tree,
                    "sources",
                    Contents::Tree {
                        skip: is_tree_noise,
                    },
                ),
            ],
            tools: Vec::new(),
            protected: vec![work.to_path_buf(), tree.to_path_buf()],
            exclude: vec![work.to_path_buf()],
        }
    }

    /// A path is rewritten only as a whole name: `/t/src` does not touch
    /// `/t/src2`, and the deepest mount wins.
    // Unix only: the fixture's paths are POSIX absolute paths.
    #[cfg(unix)]
    #[test]
    fn paths_are_rewritten_as_whole_names_deepest_mount_first() {
        let r = relocator(Path::new("/t/src/bhf_work"), Path::new("/t/src"));
        let out = r
            .rewrite("PYTHONPATH=\"/t/src/bhf_work/harnesses/H-P0001:/t/src\" x=/t/src2/y")
            .unwrap();
        assert_eq!(
            out,
            "PYTHONPATH=\"@BHF_CAPSULE@/build/harness:@BHF_CAPSULE@/sources\" x=/t/src2/y"
        );
        // A work-dir path no mount holds would be swallowed by the tree's
        // mount (which leaves the work dir out): refused, named.
        let left = r.rewrite("obj=/t/src/bhf_work/ada_obj/x.o").unwrap_err();
        assert_eq!(left, "/t/src/bhf_work/ada_obj/x.o");
    }

    #[test]
    fn the_exec_program_of_a_launcher_is_found_quoted_or_bare() {
        assert_eq!(
            exec_program("#!/bin/sh\nA=1 \\\nexec \"/usr/bin/python3\" -B x.py \"$@\"\n")
                .as_deref(),
            Some("/usr/bin/python3")
        );
        assert_eq!(
            exec_program("exec node \"/w/d.js\" \"$@\"\n").as_deref(),
            Some("node")
        );
        assert_eq!(exec_program("echo hi\n"), None);
    }

    /// Relocation copies the harness without its run state, rewrites the
    /// launcher into a template, and build.sh renders it with the capsule's
    /// own path and the interpreter it finds.
    #[cfg(unix)]
    #[test]
    fn a_relocated_launcher_renders_with_the_capsule_path() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let tree = temp.path().join("tree");
        let harness = work.join("harnesses/H-P0001");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("parse_record.py"), "def f(d):\n    pass\n").unwrap();
        let launcher = format!(
            "#!/bin/sh\nPYTHONPATH=\"{}:{}\" \\\nexec \"/usr/bin/env\" python3 \"{}/driver.py\" \"$@\"\n",
            harness.display(),
            tree.display(),
            harness.display()
        );
        std::fs::write(harness.join("main"), &launcher).unwrap();
        std::fs::write(harness.join("driver.py"), "print('d')\n").unwrap();
        std::fs::write(harness.join("coverage.shm"), b"\0\0").unwrap();
        let mut r = relocator(&work, &tree);
        r.exec_tool(
            &launcher,
            Toolchain::new("BHF_TEST_ENV_PROGRAM", "env", "runs the harness"),
        );
        let relocated = r.relocate().unwrap();
        assert_eq!(relocated.templates, vec!["harness/main"]);
        assert!(relocated.ships("harness/driver.py"));
        assert!(relocated.ships("sources/parse_record.py"));
        assert!(
            !relocated.ships("harness/coverage.shm"),
            "run state stays out"
        );
        let template = String::from_utf8(relocated.generated[0].bytes.clone()).unwrap();
        assert!(
            template.contains(
                "exec \"@BHF_TOOL_0@\" python3 \"@BHF_CAPSULE@/build/harness/driver.py\""
            ),
            "{template}"
        );

        // Render it as build.sh would, in a copy at another path.
        let cap = temp.path().join("cap with space");
        std::fs::create_dir_all(cap.join("harness")).unwrap();
        std::fs::write(cap.join("harness/main"), &template).unwrap();
        let script = r.render_script(&relocated);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("set -e\n{script}"))
            .current_dir(&cap)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let rendered = std::fs::read_to_string(cap.join("build/harness/main")).unwrap();
        let here = cap.canonicalize().unwrap();
        assert!(
            rendered.contains(&format!("{}/build/harness/driver.py", here.display())),
            "{rendered}"
        );
        assert!(rendered.contains("exec \"/usr/bin/env\""), "{rendered}");
        assert!(!rendered.contains("@BHF_"), "{rendered}");
    }

    /// A text file that ships as is but names the work dir or the scanned
    /// tree is reported, as a rebuild elsewhere cannot reach what it names; a
    /// binary file is not read for it.
    // Unix only: the POSIX capsule names paths with `/`.
    #[cfg(unix)]
    #[test]
    fn a_file_shipped_as_is_naming_the_work_dir_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let tree = temp.path().join("tree");
        std::fs::create_dir_all(work.join("harnesses/H-P0001")).unwrap();
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("parse_record.py"), "def f(d):\n    pass\n").unwrap();
        let r = relocator(&work, &tree);
        assert!(r.relocate().unwrap().warnings.is_empty());

        std::fs::write(
            tree.join("widget.cfg"),
            format!("cache = {}/cache/widget.db\n", work.display()),
        )
        .unwrap();
        std::fs::write(
            tree.join("widget.bin"),
            [b"\0".as_slice(), work.to_string_lossy().as_bytes()].concat(),
        )
        .unwrap();
        let relocated = r.relocate().unwrap();
        assert!(relocated.ships("sources/widget.cfg"));
        assert_eq!(relocated.warnings.len(), 1, "{:?}", relocated.warnings);
        let warning = &relocated.warnings[0];
        assert!(
            warning.starts_with("1 shipped file(s)")
                && warning.contains(&format!(
                    "sources/widget.cfg names {}/cache/widget.db",
                    work.display()
                )),
            "{warning}"
        );
    }
}
