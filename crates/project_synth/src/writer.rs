// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::AdaStandard;
use std::path::Path;

use crate::{ProjectSpec, ProjectSynthError};

pub fn render_project(spec: &ProjectSpec) -> Result<String, ProjectSynthError> {
    spec.validate()?;

    let mut out = String::new();
    out.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
    for with_clause in &spec.with_clauses {
        out.push_str(&format!("with \"{}\";\n", with_clause.to_string_lossy()));
    }
    out.push('\n');
    if let Some(parent) = &spec.extends_project {
        out.push_str(&format!(
            "project {} extends \"{}\" is\n\n",
            spec.project_name,
            parent.to_string_lossy()
        ));
    } else {
        out.push_str(&format!("project {} is\n\n", spec.project_name));
    }

    // Distinct source-dir paths: a dir may appear under more than one language
    // (an Ada dependency tree that also ships C glue), but GPR wants each dir once.
    let mut seen_dirs = std::collections::BTreeSet::new();
    let dirs = spec
        .source_roots
        .iter()
        .map(|root| root.path.to_string_lossy().into_owned())
        .filter(|dir| seen_dirs.insert(dir.clone()))
        .map(|dir| format!("\"{dir}\""))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("   for Source_Dirs use ({dirs});\n"));
    // Languages: Ada always; add C when the source dirs carry C glue a real Ada
    // library binds to (else the Ada link fails on the bound C symbols). Omitted
    // for pure-Ada trees so the project stays byte-for-byte the historical one.
    if spec.compile_c {
        out.push_str("   for Languages use (\"Ada\", \"C\");\n");
    }
    // Drop C sources that would collide on object-file name with a same-stem Ada
    // unit (`sxxx.adb` + `sxxx.c` -> `sxxx.o`), which gprbuild rejects outright.
    // Base names only, which is what `Excluded_Source_Files` wants.
    if !spec.excluded_source_files.is_empty() {
        let files = spec
            .excluded_source_files
            .iter()
            .map(|f| format!("\"{f}\""))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("   for Excluded_Source_Files use ({files});\n"));
    }
    out.push_str(&format!(
        "   for Object_Dir use \"{}\";\n",
        spec.object_dir.to_string_lossy()
    ));
    if let Some(exec_dir) = &spec.exec_dir {
        out.push_str(&format!(
            "   for Exec_Dir use \"{}\";\n",
            exec_dir.to_string_lossy()
        ));
    }
    if let Some(main_adb) = &spec.main_adb {
        out.push_str(&format!("   for Main use (\"{main_adb}\");\n"));
    }
    // `toolchain` is either a gprconfig compiler name (`GNAT`, `GNAT_LLVM`),
    // written as Toolchain_Name, or a tool prefix (`aarch64-linux-gnu`). A
    // prefix only locates `<prefix>-gprbuild`/`<prefix>-gnat`; as a
    // Toolchain_Name it matches no compiler in gprconfig's knowledge base and
    // the project has no Ada compiler at all. A prefix is the target triple, so
    // it becomes `for Target use` when no target was given.
    let toolchain_name = spec
        .toolchain
        .as_deref()
        .and_then(crate::gpr_toolchain_name);
    let target = spec.target.clone().or_else(|| {
        spec.toolchain
            .as_deref()
            .filter(|toolchain| crate::gpr_toolchain_name(toolchain).is_none())
            .map(|prefix| prefix.trim_end_matches('-').to_owned())
            .filter(|prefix| !prefix.is_empty())
    });
    if let Some(target) = &target {
        out.push_str(&format!("   for Target use \"{target}\";\n"));
    }
    if let Some(runtime) = &spec.runtime {
        out.push_str(&format!("   for Runtime (\"Ada\") use \"{runtime}\";\n"));
    }
    if let Some(toolchain) = toolchain_name {
        out.push_str(&format!(
            "   for Toolchain_Name (\"Ada\") use \"{toolchain}\";\n"
        ));
    }

    out.push('\n');
    let switches = spec
        .switches
        .default
        .iter()
        .map(|switch| format!("\"{switch}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let own_switches = format!("({switches}, \"{}\")", dialect_switch(spec.ada_standard));
    match (&spec.extends_project, &spec.parent_compiler) {
        // Extend the parent's package rather than replace it, so its per-file
        // `Switches` and its `Default_Switches` (a `-gnateD` the sources need,
        // `-O1`) still apply; bhf's own come after them and win a conflict.
        (Some(_), Some(parent)) => {
            out.push_str(&format!(
                "   package Compiler extends {}.Compiler is\n",
                parent.project_name
            ));
            out.push_str(&format!(
                "      for Default_Switches (\"Ada\") use {}.Compiler'Default_Switches \
                 (\"Ada\") & {own_switches};\n",
                parent.project_name
            ));
        }
        _ => {
            out.push_str("   package Compiler is\n");
            out.push_str(&format!(
                "      for Default_Switches (\"Ada\") use {own_switches};\n"
            ));
        }
    }
    if spec.compile_c {
        // Glue C is third-party binding code — compile it for debug only, never
        // instrument it (coverage is for the Ada target, not the libc shims).
        out.push_str("      for Default_Switches (\"C\") use (\"-g\");\n");
    }
    out.push_str("   end Compiler;\n\n");
    if let (Some(main_adb), Some(exe)) = (&spec.main_adb, &spec.executable_name) {
        out.push_str("   package Builder is\n");
        out.push_str(&format!(
            "      for Executable (\"{main_adb}\") use \"{exe}\";\n"
        ));
        out.push_str("   end Builder;\n\n");
    }
    out.push_str(&format!("end {};\n", spec.project_name));

    Ok(out)
}

pub fn write_project(spec: &ProjectSpec, dest_path: &Path) -> Result<(), ProjectSynthError> {
    let rendered = render_project(spec)?;
    std::fs::write(dest_path, rendered)?;
    Ok(())
}

/// The `package Compiler` of the project file at `gpr`, when it declares one
/// (see [`parent_compiler_from_text`]); `None` when the file cannot be read.
pub fn parent_compiler_package(gpr: &Path) -> Option<crate::ParentCompiler> {
    parent_compiler_from_text(&std::fs::read_to_string(gpr).ok()?)
}

/// The project name and `package Compiler` of a project file's text: `None`
/// when it declares no Compiler package (one it renames counts), or when its
/// name is not one GPR can reference. The switches are the string literals of
/// its `Default_Switches ("Ada")`, if any.
pub fn parent_compiler_from_text(text: &str) -> Option<crate::ParentCompiler> {
    let tokens = gpr_tokens(text);
    let is = |token: &GprToken, word: &str| matches!(token, GprToken::Word(w) if w.eq_ignore_ascii_case(word));
    let project_name = tokens.windows(2).find_map(|pair| match pair {
        [first, GprToken::Word(name)] if is(first, "project") => Some(name.clone()),
        _ => None,
    })?;
    let valid_name = project_name.split('.').all(|part| {
        let mut chars = part.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    if !valid_name {
        return None;
    }
    let start = tokens.windows(3).position(|triple| {
        is(&triple[0], "package")
            && is(&triple[1], "compiler")
            && ["is", "extends", "renames"]
                .iter()
                .any(|word| is(&triple[2], word))
    })?;
    let body = &tokens[start..];
    let end = body
        .windows(2)
        .position(|pair| is(&pair[0], "end") && is(&pair[1], "compiler"))
        .unwrap_or(body.len());
    let body = &body[..end];
    let ada_switches = body
        .windows(4)
        .position(|window| {
            is(&window[0], "for")
                && is(&window[1], "default_switches")
                && window[2] == GprToken::Punct('(')
                && matches!(&window[3], GprToken::Str(lang) if lang.eq_ignore_ascii_case("ada"))
        })
        .map(|at| {
            body[at..]
                .iter()
                .skip_while(|token| !is(token, "use"))
                .take_while(|token| **token != GprToken::Punct(';'))
                .filter_map(|token| match token {
                    GprToken::Str(value) => Some(value.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Some(crate::ParentCompiler {
        project_name,
        ada_switches,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GprToken {
    Word(String),
    Str(String),
    Punct(char),
}

/// A project file's words (identifiers, dotted names), string literals and
/// punctuation, with `--` comments dropped.
fn gpr_tokens(text: &str) -> Vec<GprToken> {
    let mut tokens = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '-' if chars.peek() == Some(&'-') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            '"' => {
                let mut value = String::new();
                while let Some(next) = chars.next() {
                    if next == '"' {
                        // `""` is an escaped quote inside a GPR string.
                        if chars.peek() == Some(&'"') {
                            chars.next();
                            value.push('"');
                            continue;
                        }
                        break;
                    }
                    value.push(next);
                }
                tokens.push(GprToken::Str(value));
            }
            c if c.is_ascii_alphanumeric() || c == '_' => {
                let mut word = String::from(c);
                while let Some(&next) = chars.peek() {
                    if next.is_ascii_alphanumeric() || next == '_' || next == '.' {
                        word.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(GprToken::Word(word));
            }
            c if c.is_whitespace() => {}
            other => tokens.push(GprToken::Punct(other)),
        }
    }
    tokens
}

fn dialect_switch(standard: AdaStandard) -> &'static str {
    match standard {
        AdaStandard::Ada83 => "-gnat83",
        AdaStandard::Ada95 => "-gnat95",
        AdaStandard::Ada2005 => "-gnat05",
        AdaStandard::Ada2012 => "-gnat12",
        AdaStandard::Ada2022 => "-gnat2022",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ParentCompiler, SourceRoot, Switches};

    fn extending_spec() -> ProjectSpec {
        ProjectSpec {
            project_name: "Bhf_Build".to_owned(),
            extends_project: Some("/proj/board.gpr".into()),
            parent_compiler: None,
            source_roots: vec![SourceRoot {
                path: "src_instrumented".into(),
                language: "Ada".to_owned(),
            }],
            object_dir: "obj".into(),
            exec_dir: None,
            main_adb: Some("main.adb".to_owned()),
            ada_standard: AdaStandard::Ada2022,
            target: None,
            runtime: None,
            toolchain: None,
            switches: Switches {
                default: vec!["-g".to_owned(), "-gnatwa".to_owned(), "-gnata".to_owned()],
                debug: true,
                warnings_as_errors: false,
            },
            with_clauses: Vec::new(),
            executable_name: None,
            compile_c: false,
            excluded_source_files: Vec::new(),
        }
    }

    /// A parent project's `package Compiler` is extended, not replaced: its
    /// per-file `Switches` still apply, and bhf's switches follow the
    /// parent's `Default_Switches ("Ada")` (so a `-gnateD` the sources need
    /// stays, and bhf's `-g`/assertions/dialect come after it).
    #[test]
    fn an_extending_project_merges_the_parents_compiler_switches() {
        let mut spec = extending_spec();
        spec.parent_compiler = Some(ParentCompiler {
            project_name: "Board".to_owned(),
            ada_switches: vec!["-O1".to_owned(), "-gnateDBOARD_REV=7".to_owned()],
        });
        let rendered = render_project(&spec).unwrap();
        assert!(
            rendered.contains(
                "   package Compiler extends Board.Compiler is\n      for Default_Switches \
                 (\"Ada\") use Board.Compiler'Default_Switches (\"Ada\") & (\"-g\", \
                 \"-gnatwa\", \"-gnata\", \"-gnat2022\");\n   end Compiler;\n"
            ),
            "{rendered}"
        );
        // Without a parent Compiler package the output is as before.
        let plain = render_project(&extending_spec()).unwrap();
        assert!(
            plain.contains(
                "   package Compiler is\n      for Default_Switches (\"Ada\") use (\"-g\", \
                 \"-gnatwa\", \"-gnata\", \"-gnat2022\");\n"
            ),
            "{plain}"
        );
    }

    #[test]
    fn a_parent_projects_compiler_package_is_read_from_its_text() {
        let parent = parent_compiler_from_text(
            "-- board support\n\
             with \"shared.gpr\";\n\
             library project Board.Core extends \"base.gpr\" is\n\
             \x20  for Source_Dirs use (\"src\");\n\
             \x20  package Compiler is  -- the build's own switches\n\
             \x20     for Default_Switches (\"ada\") use (\"-O1\", \"-gnatwa\",\n\
             \x20        \"-gnateDBOARD_REV=7\");\n\
             \x20     for Switches (\"board.adb\") use (\"-O0\");\n\
             \x20  end Compiler;\n\
             end Board.Core;\n",
        )
        .expect("a Compiler package");
        assert_eq!(parent.project_name, "Board.Core");
        assert_eq!(
            parent.ada_switches,
            ["-O1", "-gnatwa", "-gnateDBOARD_REV=7"]
        );
        // A package that only renames another's still has its attributes.
        let renamed = parent_compiler_from_text(
            "project App is\n   package Compiler renames Shared.Compiler;\nend App;\n",
        )
        .expect("a renamed Compiler package");
        assert_eq!(renamed.project_name, "App");
        assert!(renamed.ada_switches.is_empty());
        // No Compiler package, or a name GPR could not reference: nothing.
        assert_eq!(
            parent_compiler_from_text(
                "project App is\n   package Binder is\n   end Binder;\nend App;\n"
            ),
            None
        );
        assert_eq!(
            parent_compiler_from_text("project \"App\" is\n package Compiler is\n end Compiler;\n"),
            None
        );
    }
}
