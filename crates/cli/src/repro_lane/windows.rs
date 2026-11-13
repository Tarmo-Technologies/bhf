// SPDX-License-Identifier: Apache-2.0

//! The Windows build script of a C or C++ capsule (`build.ps1`).
//!
//! `build.sh` needs a POSIX shell, and its compile lines speak the GCC
//! dialect, so a capsule could not be rebuilt natively on Windows, and with
//! `CC=cl` it handed cl clang's `-fsanitize` flags. A C or C++ capsule
//! therefore also ships `build.ps1`, which rebuilds `poc.exe` the way the
//! harness Makefile built the harness on Windows, in one of three dialects:
//!
//! * **clang** (`clang`/`clang++` targeting MSVC): the Makefile's GCC-style
//!   command lines, with clang's AddressSanitizer, UBSan and coverage flags;
//! * **cl** (MSVC `cl.exe`): the same command lines as the bhf-cl front end
//!   spells them for cl ([`crate::msvc_cc::translate`]): `/fsanitize=address`
//!   and cl's SanitizerCoverage flags, linking `libsancov.lib`, with bhf's
//!   weak repair stubs rewritten as MSVC alternate names;
//! * **clang-cl**: as cl, without `libsancov.lib` (clang has its own coverage
//!   runtime).
//!
//! The dialect is the one the harness was built with (the family in its
//! `bhf_toolchain.stamp`, and for the MSVC lane the compiler the front end
//! ran, from `coverage-build-recipe.json`), unless `$CC`/`$CXX` names another
//! compiler when the script runs. Like the Makefile, every dialect links bhf's
//! driver (`runtime/bhf_driver.c`): the generated driver's own `main` uses GNU
//! builtins cl does not have. The compiler runs from response files written
//! with the Windows command-line rules, so arguments keep their spaces and
//! quotes under Windows PowerShell 5.1, and outside a Developer shell the
//! script takes the environment cl and clang-cl read (`INCLUDE`, `LIB`,
//! `PATH`) from the newest Visual Studio instance with the C++ toolset, as bhf
//! itself does. The
//! sanitizer runtime DLL of the compiler that ran is copied next to
//! `poc.exe`, where Windows looks first.

use super::relocate::CAPSULE_ROOT;
use crate::msvc_cc::{self, Backend};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// The command-line dialect of a Windows rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    /// `clang`/`clang++` targeting MSVC: GCC-style command lines.
    Clang,
    /// MSVC `cl.exe`.
    Cl,
    /// LLVM's cl-compatible driver.
    ClangCl,
}

impl Dialect {
    /// All dialects, in the order build.ps1 lists them.
    pub(crate) const ALL: [Dialect; 3] = [Dialect::Cl, Dialect::ClangCl, Dialect::Clang];

    /// The name build.ps1 and the manifest use for it.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Dialect::Clang => "clang",
            Dialect::Cl => "cl",
            Dialect::ClangCl => "clang-cl",
        }
    }

    /// The dialect a compiler name or path speaks (`cl.exe`,
    /// `C:/LLVM/bin/clang-cl.exe`, `clang++-18`), by name; `None` for a name
    /// that is none of them (gcc has no Windows AddressSanitizer).
    pub(crate) fn of_compiler(compiler: &str) -> Option<Self> {
        match harness_gen::compiler_family::driver_base_name(compiler)? {
            "cl" => Some(Dialect::Cl),
            "clang-cl" => Some(Dialect::ClangCl),
            "clang" | "clang++" => Some(Dialect::Clang),
            _ => None,
        }
    }

    /// The front end's backend for a cl dialect.
    pub(crate) fn backend(self) -> Option<Backend> {
        match self {
            Dialect::Clang => None,
            Dialect::Cl => Some(Backend::Cl),
            Dialect::ClangCl => Some(Backend::ClangCl),
        }
    }

    /// The program build.ps1 runs for this dialect when `$CC`/`$CXX` is unset.
    pub(crate) fn program(self, cxx: bool) -> &'static str {
        match self {
            Dialect::Clang if cxx => "clang++",
            Dialect::Clang => "clang",
            Dialect::Cl => "cl",
            Dialect::ClangCl => "clang-cl",
        }
    }
}

/// The compiler a Windows rebuild runs by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsCompiler {
    pub(crate) dialect: Dialect,
    /// The program build.ps1 runs when `$CC`/`$CXX` is unset.
    pub(crate) program: String,
    /// Where the choice came from: `environment`, `recorded build`, `default`.
    pub(crate) source: &'static str,
}

/// One compiler run of build.ps1: the name of its response file and its
/// arguments, in the dialect's own spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) name: String,
    pub(crate) args: Vec<String>,
}

/// The compiler runs of one dialect, and the capsule dirs it appends to
/// `INCLUDE` (cl's `-idirafter`: searched after the system headers).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DialectBuild {
    pub(crate) steps: Vec<Step>,
    pub(crate) include_after: Vec<String>,
}

/// The cl runs of GNU-style compiler command lines (`backend`'s spelling,
/// through the bhf-cl front end's translation). A compile line becomes one
/// run; the compile-and-link line becomes one compile per source into `obj/`
/// and a link, as the front end runs a line whose objects would collide, so
/// every intermediate file stays in `obj/`. `weak` maps a source to its MSVC
/// spelling and the dir its own includes resolve from (a repair stub whose
/// weak definitions became alternate names). cl looks a forced include
/// (`/FI`) up from the source's dir, not the working dir as clang does, so a
/// relative one the capsule ships (`shipped`) is anchored at the capsule
/// ([`CAPSULE_ROOT`], which build.ps1 replaces with its own dir); any other
/// (`iostream`) is a header cl finds on its include path and stays as written.
pub(crate) fn cl_build(
    commands: &[(String, Vec<String>)],
    backend: Backend,
    weak: &BTreeMap<String, (String, String)>,
    shipped: &dyn Fn(&str) -> bool,
) -> Result<DialectBuild, String> {
    let mut build = DialectBuild::default();
    let anchor_forced_includes = |args: &mut Vec<String>| {
        let mut forced = false;
        for arg in args.iter_mut() {
            if forced && !Path::new(arg.as_str()).is_absolute() && shipped(arg) {
                *arg = format!("{CAPSULE_ROOT}/{arg}");
            }
            forced = arg == "/FI";
        }
    };
    for (name, gnu) in commands {
        let mut command = msvc_cc::translate(gnu, backend)?;
        anchor_forced_includes(&mut command.args);
        if let Some(split) = command.split.as_mut() {
            anchor_forced_includes(&mut split.compile_args);
        }
        for dir in &command.include_after {
            if !build.include_after.contains(dir) {
                build.include_after.push(dir.clone());
            }
        }
        match command.split {
            Some(mut split) => {
                let mut include_dirs = Vec::new();
                for source in &mut split.sources {
                    if let Some((copy, dir)) = weak.get(source.as_str()) {
                        *source = copy.clone();
                        include_dirs.push(dir.clone());
                    }
                }
                for dir in include_dirs {
                    split.compile_args.push("/I".to_owned());
                    split.compile_args.push(dir);
                }
                let runs = msvc_cc::split_commands(&split, Path::new("obj"));
                let last = runs.len().saturating_sub(1);
                for (index, args) in runs.into_iter().enumerate() {
                    build.steps.push(Step {
                        name: if index == last {
                            name.clone()
                        } else {
                            format!("{name}_{index}")
                        },
                        args,
                    });
                }
            }
            None => {
                let mut args = Vec::with_capacity(command.args.len() + 2);
                for arg in command.args {
                    match weak.get(arg.as_str()) {
                        Some((copy, dir)) => {
                            args.push("/I".to_owned());
                            args.push(dir.clone());
                            args.push(copy.clone());
                        }
                        None => args.push(arg),
                    }
                }
                build.steps.push(Step {
                    name: name.clone(),
                    args,
                });
            }
        }
    }
    Ok(build)
}

/// What build.ps1 is rendered from.
pub(crate) struct ScriptInputs<'a> {
    /// `CC` or `CXX`.
    pub(crate) compiler_var: &'static str,
    /// Whether this is the C++ lane (`clang++` is its clang).
    pub(crate) cxx: bool,
    /// The compiler the harness was built with (the default).
    pub(crate) recorded: &'a WindowsCompiler,
    /// The Visual Studio target architecture for cl (`x64`).
    pub(crate) arch: &'a str,
    pub(crate) builds: &'a [(Dialect, DialectBuild)],
}

/// The program names build.ps1 tries, in order, when `$CC`/`$CXX` is unset:
/// the recorded one first.
pub(crate) fn candidates(recorded: &WindowsCompiler, cxx: bool) -> Vec<String> {
    let mut names = vec![recorded.program.clone()];
    for dialect in Dialect::ALL {
        let name = dialect.program(cxx).to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// The `build.ps1` text, with a UTF-8 byte-order mark (Windows PowerShell 5.1
/// reads a script without one in the ANSI code page).
pub(crate) fn render(inputs: &ScriptInputs) -> String {
    let var = inputs.compiler_var;
    let recorded = inputs.recorded;
    let names = candidates(recorded, inputs.cxx);
    let mut script = String::from("\u{feff}");
    let _ = write!(
        script,
        "# Rebuild this bhf PoC offline on Windows; writes .\\poc.exe.\r\n\
         #   powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1\r\n\
         # The harness was built with {built_with}; set $env:{var} to rebuild with\r\n\
         # another compiler: {others}.\r\n\
         $ErrorActionPreference = 'Stop'\r\n\
         Set-Location -LiteralPath $PSScriptRoot\r\n\
         $Recorded = {recorded_dialect}\r\n\
         $Arch = {arch}\r\n\
         $HostArch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {{ 'arm64' }} else {{ 'x64' }}\r\n\
         \r\n\
         function Import-VsEnvironment {{\r\n\
         \x20 # cl and clang-cl need the Visual Studio build environment (INCLUDE, LIB, PATH). Outside a\r\n\
         \x20 # Developer shell, take it from the newest instance with the C++ toolset.\r\n\
         \x20 if ($env:INCLUDE -and $env:LIB) {{ return }}\r\n\
         \x20 $vswhere = Join-Path ${{env:ProgramFiles(x86)}} 'Microsoft Visual Studio\\Installer\\vswhere.exe'\r\n\
         \x20 if (-not (Test-Path -LiteralPath $vswhere)) {{ return }}\r\n\
         \x20 $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1\r\n\
         \x20 if (-not $install) {{ return }}\r\n\
         \x20 $devcmd = Join-Path $install 'Common7\\Tools\\VsDevCmd.bat'\r\n\
         \x20 if (-not (Test-Path -LiteralPath $devcmd)) {{ return }}\r\n\
         \x20 $batch = Join-Path ([IO.Path]::GetTempPath()) ('bhf-vsdevcmd-{{0}}.cmd' -f $PID)\r\n\
         \x20 Set-Content -LiteralPath $batch -Encoding Ascii -Value \"@call `\"$devcmd`\" -arch=$Arch -host_arch=$HostArch -no_logo >nul`r`n@set\"\r\n\
         \x20 try {{ $lines = & cmd.exe /d /c $batch }} finally {{ Remove-Item -LiteralPath $batch -ErrorAction SilentlyContinue }}\r\n\
         \x20 foreach ($line in $lines) {{\r\n\
         \x20   $at = $line.IndexOf('=')\r\n\
         \x20   if ($at -gt 0) {{ [Environment]::SetEnvironmentVariable($line.Substring(0, $at), $line.Substring($at + 1), 'Process') }}\r\n\
         \x20 }}\r\n\
         }}\r\n\
         \r\n\
         function Get-Dialect([string]$Compiler) {{\r\n\
         \x20 $leaf = [IO.Path]::GetFileName($Compiler.Trim().Trim('\"')).ToLowerInvariant()\r\n\
         \x20 if ($leaf.EndsWith('.exe')) {{ $leaf = $leaf.Substring(0, $leaf.Length - 4) }}\r\n\
         \x20 $leaf = $leaf -replace '-[0-9][0-9.]*$', ''\r\n\
         \x20 if ($leaf -eq 'clang-cl' -or $leaf.EndsWith('-clang-cl')) {{ return 'clang-cl' }}\r\n\
         \x20 if ($leaf -eq 'cl') {{ return 'cl' }}\r\n\
         \x20 if ($leaf -eq 'clang' -or $leaf -eq 'clang++' -or $leaf.EndsWith('-clang') -or $leaf.EndsWith('-clang++')) {{ return 'clang' }}\r\n\
         \x20 return $null\r\n\
         }}\r\n\
         \r\n\
         function Fail([string]$Message) {{\r\n\
         \x20 [Console]::Error.WriteLine(\"build.ps1: $Message\")\r\n\
         \x20 exit 1\r\n\
         }}\r\n\
         \r\n\
         # The compiler: $env:{var}, else the recorded one, else the first other one installed.\r\n\
         $Compiler = $env:{var}\r\n\
         if ($Compiler) {{ $Compiler = $Compiler.Trim().Trim('\"') }}\r\n\
         if (-not $Compiler) {{\r\n\
         \x20 foreach ($candidate in @({names})) {{\r\n\
         \x20   if ((Get-Dialect $candidate) -eq 'cl') {{ Import-VsEnvironment }}\r\n\
         \x20   if (Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue) {{ $Compiler = $candidate; break }}\r\n\
         \x20 }}\r\n\
         \x20 if (-not $Compiler) {{ Fail \"no compiler found: install {program} or set `$env:{var}\" }}\r\n\
         }}\r\n\
         $Dialect = Get-Dialect $Compiler\r\n\
         if (-not $Dialect) {{ $Dialect = $Recorded }}\r\n\
         # cl and clang-cl read the system headers and libraries from INCLUDE and LIB.\r\n\
         if ($Dialect -ne 'clang') {{ Import-VsEnvironment }}\r\n\
         $Program = Get-Command $Compiler -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1\r\n\
         if (-not $Program) {{ Fail \"$Compiler is not installed (set `$env:{var} to a {language} compiler)\" }}\r\n\
         $Program = $Program.Source\r\n\
         New-Item -ItemType Directory -Force -Path obj | Out-Null\r\n\
         \r\n\
         # One compiler run from a one-line response file (cl takes an option's\r\n\
         # argument from the same line; the Windows command-line rules keep each\r\n\
         # argument whole); its output goes to stderr with the compiler's own.\r\n\
         function Invoke-Step([string]$Name, [string[]]$Words) {{\r\n\
         \x20 $line = ($Words -join ' ').Replace({root}, $PSScriptRoot)\r\n\
         \x20 Set-Content -LiteralPath (Join-Path $PSScriptRoot \"obj\\$Name.rsp\") -Value $line -Encoding Unicode\r\n\
         \x20 $output = & $Program \"@obj\\$Name.rsp\"\r\n\
         \x20 $code = $LASTEXITCODE\r\n\
         \x20 foreach ($line in @($output)) {{ [Console]::Error.WriteLine($line) }}\r\n\
         \x20 if ($code -ne 0) {{ Fail \"$Compiler exited with $code at step $Name\" }}\r\n\
         }}\r\n\
         \r\n",
        program = recorded.program,
        built_with = if recorded.program == recorded.dialect.program(inputs.cxx) {
            recorded.program.clone()
        } else {
            format!("{} ({})", recorded.program, recorded.dialect.label())
        },
        others = Dialect::ALL
            .iter()
            .filter(|dialect| **dialect != recorded.dialect)
            .map(|dialect| dialect.program(inputs.cxx))
            .collect::<Vec<_>>()
            .join(" or "),
        recorded_dialect = ps_literal(recorded.dialect.label()),
        arch = ps_literal(inputs.arch),
        names = names
            .iter()
            .map(|name| ps_literal(name))
            .collect::<Vec<_>>()
            .join(", "),
        language = if inputs.cxx { "C++" } else { "C" },
        root = ps_literal(CAPSULE_ROOT),
    );
    script.push_str("switch ($Dialect) {\r\n");
    for (dialect, build) in inputs.builds {
        let _ = write!(script, "  {} {{\r\n", ps_literal(dialect.label()));
        if !build.include_after.is_empty() {
            let dirs = build
                .include_after
                .iter()
                .map(|dir| format!("(Join-Path $PSScriptRoot {})", ps_literal(dir)))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                script,
                "    $env:INCLUDE = (@($env:INCLUDE, {dirs}) | Where-Object {{ $_ }}) -join ';'\r\n"
            );
        }
        for step in &build.steps {
            let words = step
                .args
                .iter()
                .map(|arg| ps_literal(&rsp_word(arg)))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                script,
                "    Invoke-Step {} @({words})\r\n",
                ps_literal(&step.name)
            );
        }
        script.push_str("  }\r\n");
    }
    script.push_str(
        "  default { Fail \"no $Dialect build in this capsule\" }\r\n\
         }\r\n\
         if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'poc.exe'))) { Fail 'the link wrote no poc.exe' }\r\n\
         \r\n\
         # The AddressSanitizer runtime DLL of the compiler that ran goes next to\r\n\
         # poc.exe, where Windows looks first: cl's beside cl.exe, clang's in its\r\n\
         # resource dir.\r\n\
         $runtime = @()\r\n\
         if ($Dialect -eq 'cl') {\r\n\
         \x20 $runtime += Split-Path -Parent $Program\r\n\
         } else {\r\n\
         \x20 $resource = & $Program -print-resource-dir | Select-Object -First 1\r\n\
         \x20 if ($resource) { $runtime += Join-Path $resource.Trim() 'lib\\windows' }\r\n\
         }\r\n\
         $copied = $false\r\n\
         foreach ($dir in $runtime) {\r\n\
         \x20 $dlls = @(Get-ChildItem -LiteralPath $dir -Filter 'clang_rt.asan*dynamic*.dll' -ErrorAction SilentlyContinue)\r\n\
         \x20 if ($dlls.Count -gt 0) { $dlls | Copy-Item -Destination $PSScriptRoot -Force; $copied = $true; break }\r\n\
         }\r\n\
         if (-not $copied) { [Console]::Error.WriteLine('build.ps1: warning: no AddressSanitizer runtime DLL found; put its directory on PATH to run poc.exe') }\r\n\
         exit 0\r\n",
    );
    script
}

/// One argument as a response-file word cl and clang read: unchanged when it
/// holds no whitespace or `"`, otherwise double-quoted with the Windows
/// command-line rules (a `"` and the backslashes before it, or before the
/// closing quote, are escaped). A word anchored at the capsule is always
/// quoted: the capsule's own path, which replaces [`CAPSULE_ROOT`], may hold
/// spaces.
pub(crate) fn rsp_word(word: &str) -> String {
    let plain = !word.is_empty()
        && !word.contains(CAPSULE_ROOT)
        && !word
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '"'));
    if plain {
        return word.to_owned();
    }
    let mut out = String::with_capacity(word.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in word.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// A PowerShell single-quoted string literal of `text`: every quote character
/// PowerShell takes for a single quote is doubled.
pub(crate) fn ps_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_file_words_follow_the_windows_command_line_rules() {
        assert_eq!(rsp_word("/O1"), "/O1");
        assert_eq!(rsp_word("sources/rec ord.c"), "\"sources/rec ord.c\"");
        assert_eq!(rsp_word(""), "\"\"");
        assert_eq!(rsp_word("/DNAME=\"v 1\""), "\"/DNAME=\\\"v 1\\\"\"");
        // Backslashes are literal unless a quote follows them.
        assert_eq!(rsp_word("a\\b c"), "\"a\\b c\"");
        assert_eq!(rsp_word("dir with space\\"), "\"dir with space\\\\\"");
        assert_eq!(rsp_word("a\\\"b"), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn powershell_literals_double_every_single_quote() {
        assert_eq!(
            ps_literal("-fsanitize=address,undefined"),
            "'-fsanitize=address,undefined'"
        );
        assert_eq!(ps_literal("it's"), "'it''s'");
        assert_eq!(ps_literal("a\u{2019}b"), "'a\u{2019}\u{2019}b'");
        assert_eq!(ps_literal("$env:X"), "'$env:X'");
    }

    #[test]
    fn compilers_are_told_apart_by_name() {
        for (name, dialect) in [
            ("cl", Some(Dialect::Cl)),
            ("C:/VS/bin/HostX64/x64/cl.exe", Some(Dialect::Cl)),
            ("clang-cl", Some(Dialect::ClangCl)),
            (
                "C:\\Program Files\\LLVM\\bin\\clang-cl.exe",
                Some(Dialect::ClangCl),
            ),
            ("clang++-18", Some(Dialect::Clang)),
            ("clang", Some(Dialect::Clang)),
            ("gcc", None),
        ] {
            assert_eq!(Dialect::of_compiler(name), dialect, "{name}");
        }
    }

    /// The compile-and-link line becomes a compile per source into obj/ and a
    /// link; a weak stub compiles from its MSVC copy with its own dir on the
    /// include path; -idirafter dirs go to INCLUDE.
    #[test]
    fn cl_build_spells_the_command_lines_for_cl() {
        let words = |text: &str| -> Vec<String> { text.split(' ').map(str::to_owned).collect() };
        let weak = BTreeMap::from([(
            "stubs/stub.c".to_owned(),
            ("stubs_msvc/stub.c".to_owned(), "stubs".to_owned()),
        )]);
        let build = cl_build(
            &[
                (
                    "unit_0".to_owned(),
                    words("-O1 -g -fsanitize=address -c stubs/stub.c -o obj/unit_0.obj"),
                ),
                (
                    "link".to_owned(),
                    words(
                        "-O1 -g -fsanitize=address -fsanitize-coverage=inline-8bit-counters,edge \
                         -I harness -idirafter sources -include stubs/defs.h -include iostream \
                         -DBHF_EXTERNAL_DRIVER -o poc.exe \
                         harness/main.c sources/main.c obj/unit_0.obj -Wl,/OPT:REF",
                    ),
                ),
            ],
            Backend::Cl,
            &weak,
            &|path: &str| path == "stubs/defs.h",
        )
        .unwrap();
        assert_eq!(build.include_after, ["sources"]);
        let names: Vec<&str> = build.steps.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["unit_0", "link_0", "link_1", "link"]);
        let unit = &build.steps[0].args;
        assert!(unit.contains(&"/fsanitize=address".to_owned()), "{unit:?}");
        let copy = unit.iter().position(|a| a == "stubs_msvc/stub.c").unwrap();
        assert_eq!(&unit[copy - 2..copy], ["/I", "stubs"], "{unit:?}");
        // Both mains compile to their own objects: no collision.
        assert!(build.steps[1]
            .args
            .contains(&"/Fo:obj/0_main.obj".to_owned()));
        assert!(build.steps[2]
            .args
            .contains(&"/Fo:obj/1_main.obj".to_owned()));
        assert!(build.steps[1]
            .args
            .contains(&"/fsanitize-coverage=inline-8bit-counters".to_owned()));
        // cl reads a forced include from the source's dir: it is anchored at
        // the capsule, and its word is quoted for the capsule's path.
        let forced = build.steps[1].args.iter().position(|a| a == "/FI").unwrap();
        assert_eq!(
            build.steps[1].args[forced + 1],
            "@BHF_CAPSULE@/stubs/defs.h"
        );
        assert_eq!(
            rsp_word("@BHF_CAPSULE@/stubs/defs.h"),
            "\"@BHF_CAPSULE@/stubs/defs.h\""
        );
        // A forced include the capsule does not ship is a header cl finds on
        // its own include path: it stays as written.
        let system = build.steps[1]
            .args
            .iter()
            .enumerate()
            .filter(|(_, arg)| *arg == "/FI")
            .map(|(at, _)| build.steps[1].args[at + 1].as_str())
            .collect::<Vec<_>>();
        assert_eq!(system, ["@BHF_CAPSULE@/stubs/defs.h", "iostream"]);
        let link = &build.steps[3].args;
        for expected in [
            "/Fe:poc.exe",
            "obj/0_main.obj",
            "obj/unit_0.obj",
            "libsancov.lib",
            "/OPT:REF",
        ] {
            assert!(link.contains(&expected.to_owned()), "{expected}: {link:?}");
        }
        let clang_cl = cl_build(
            &[(
                "link".to_owned(),
                words("-fsanitize=address -fsanitize-coverage=edge -o poc.exe harness/main.c"),
            )],
            Backend::ClangCl,
            &BTreeMap::new(),
            &|_: &str| true,
        )
        .unwrap();
        assert!(clang_cl
            .steps
            .iter()
            .all(|step| !step.args.contains(&"libsancov.lib".to_owned())));
    }

    #[test]
    fn the_script_tries_the_recorded_compiler_first() {
        let recorded = WindowsCompiler {
            dialect: Dialect::ClangCl,
            program: "clang-cl".to_owned(),
            source: "recorded build",
        };
        assert_eq!(candidates(&recorded, true), ["clang-cl", "cl", "clang++"]);
        let script = render(&ScriptInputs {
            compiler_var: "CXX",
            cxx: true,
            recorded: &recorded,
            arch: "x64",
            builds: &[(
                Dialect::ClangCl,
                DialectBuild {
                    steps: vec![Step {
                        name: "link".to_owned(),
                        args: vec!["/Fe:poc.exe".to_owned(), "sources/rec ord.cpp".to_owned()],
                    }],
                    include_after: vec!["sources".to_owned()],
                },
            )],
        });
        assert!(script.starts_with('\u{feff}'), "a BOM for PowerShell 5.1");
        assert!(script.contains("$Recorded = 'clang-cl'"), "{script}");
        assert!(
            script.contains("foreach ($candidate in @('clang-cl', 'cl', 'clang++'))"),
            "{script}"
        );
        assert!(
            script.contains("Invoke-Step 'link' @('/Fe:poc.exe', '\"sources/rec ord.cpp\"')"),
            "{script}"
        );
        assert!(
            script.contains("$env:INCLUDE = (@($env:INCLUDE, (Join-Path $PSScriptRoot 'sources'))"),
            "{script}"
        );
        assert!(script.contains("$Compiler = $env:CXX"), "{script}");
    }
}
