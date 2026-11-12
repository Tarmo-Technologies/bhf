// SPDX-License-Identifier: Apache-2.0

//! Recognise a C/C++ compiler driver from its name.
//!
//! A compile database, a captured build, or an operator setting names a
//! compiler in many spellings: `gcc`, `g++-12`, `/usr/bin/aarch64-linux-gnu-gcc`,
//! `x86_64-w64-mingw32-g++.exe`, `clang-18`, `C:/LLVM/bin/clang.exe`,
//! `cl.exe`, `clang-cl`. Every
//! place that needs to know which driver it is uses this one normalisation —
//! lowercase the file name, drop a `.exe` suffix, drop a trailing numeric
//! version (`-12`, `-18.1`), then drop a target-triple prefix — so a check that
//! accepts a name and a check that picks flags for it can never disagree.
//!
//! The name is only a fallback. The generated Makefile asks the compiler itself
//! (`$(CC) -dM -E`) which family it belongs to, since a renamed or wrapped
//! compiler says nothing about itself in its name.

use std::path::Path;

/// The flag dialect a compiler speaks, as far as bhf's instrumentation cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompilerFamily {
    /// Clang (and clang-based drivers): `trace-pc-guard` coverage, the
    /// `function`/`vptr` UBSan checks, libFuzzer.
    Clang,
    /// GCC (native or cross): `trace-pc` coverage and no `function` check.
    Gcc,
    /// The MSVC command-line dialect: `cl.exe`, and `clang-cl` when it is the
    /// harness compiler. Coverage is SanitizerCoverage's inline 8-bit counters
    /// (the form MSVC implements), there is no UBSan, and the harness build goes
    /// through bhf's `bhf-cl` front end, which spells the generated Makefile's
    /// GCC-style command lines the way `cl` reads them.
    Msvc,
}

impl CompilerFamily {
    /// The value the generated Makefiles test (`BHF_CC_FAMILY`/`BHF_CXX_FAMILY`).
    pub fn make_value(self) -> &'static str {
        match self {
            Self::Clang => "clang",
            Self::Gcc => "gcc",
            Self::Msvc => "msvc",
        }
    }

    /// Parse a [`Self::make_value`] spelling.
    pub fn from_make_value(value: &str) -> Option<Self> {
        match value.trim() {
            "clang" => Some(Self::Clang),
            "gcc" => Some(Self::Gcc),
            "msvc" => Some(Self::Msvc),
            _ => None,
        }
    }

    /// The SanitizerCoverage flag this family's compilers accept, with the
    /// comparison hooks bhf's driver consumes. GCC has no `trace-pc-guard`;
    /// MSVC implements the inline 8-bit counters, which the driver folds into
    /// the same edge map after every input.
    pub fn coverage_flag(self) -> &'static str {
        match self {
            Self::Clang => "-fsanitize-coverage=trace-pc-guard,trace-cmp",
            Self::Gcc => "-fsanitize-coverage=trace-pc,trace-cmp",
            Self::Msvc => "-fsanitize-coverage=inline-8bit-counters,edge,trace-cmp,trace-div",
        }
    }

    /// The UBSan checks bhf subtracts from `-fsanitize=undefined`. GCC has no
    /// `function` check and rejects its name; MSVC has no UBSan at all.
    pub fn ubsan_subtraction(self) -> &'static str {
        match self {
            Self::Clang => "-fno-sanitize=function,vptr,alignment",
            Self::Gcc => "-fno-sanitize=alignment",
            Self::Msvc => "",
        }
    }

    /// Whether this family has UndefinedBehaviorSanitizer.
    pub fn supports_ubsan(self) -> bool {
        !matches!(self, Self::Msvc)
    }
}

/// A recognised compiler driver: its family and whether it is the C++ driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilerDriver {
    pub family: CompilerFamily,
    pub cxx: bool,
}

/// The driver base name of `compiler` (a name or a path): `clang`, `clang++`,
/// `gcc`, `g++`, `cl` or `clang-cl` after the normalisation described in the
/// module docs, or `None` when the name is none of them.
pub fn driver_base_name(compiler: &str) -> Option<&'static str> {
    let trimmed = compiler.trim().trim_matches('"');
    let leaf = Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(trimmed);
    let leaf = leaf.rsplit(['/', '\\']).next().unwrap_or(leaf);
    let mut lower = leaf.to_ascii_lowercase();
    if let Some(stem) = lower.strip_suffix(".exe") {
        lower = stem.to_owned();
    }
    // `gcc-12`, `clang-18.1` -> drop a trailing all-numeric version component.
    let stem = match lower.rsplit_once('-') {
        Some((base, suffix))
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit() || c == '.') =>
        {
            base
        }
        _ => lower.as_str(),
    };
    // `clang-cl` is one driver name, not a `clang` triple prefix on `cl`.
    if stem == "clang-cl" || stem.ends_with("-clang-cl") {
        return Some("clang-cl");
    }
    // `aarch64-linux-gnu-gcc` -> the driver name is the last component.
    let base = stem.rsplit('-').next().unwrap_or(stem);
    match base {
        "clang" => Some("clang"),
        "clang++" => Some("clang++"),
        "gcc" => Some("gcc"),
        "g++" => Some("g++"),
        "cl" => Some("cl"),
        _ => None,
    }
}

/// The driver `compiler` names, by name alone.
pub fn driver_from_name(compiler: &str) -> Option<CompilerDriver> {
    Some(match driver_base_name(compiler)? {
        "clang" => CompilerDriver {
            family: CompilerFamily::Clang,
            cxx: false,
        },
        "clang++" => CompilerDriver {
            family: CompilerFamily::Clang,
            cxx: true,
        },
        "gcc" => CompilerDriver {
            family: CompilerFamily::Gcc,
            cxx: false,
        },
        // One driver for both languages; it picks C or C++ from the file name.
        "cl" | "clang-cl" => CompilerDriver {
            family: CompilerFamily::Msvc,
            cxx: false,
        },
        _ => CompilerDriver {
            family: CompilerFamily::Gcc,
            cxx: true,
        },
    })
}

/// The family `compiler` names, by name alone (`None` for an unrecognised name).
pub fn family_from_name(compiler: &str) -> Option<CompilerFamily> {
    driver_from_name(compiler).map(|driver| driver.family)
}

/// The C driver that pairs with a C++ driver: `clang++` -> `clang`,
/// `/opt/x/bin/aarch64-linux-gnu-g++-12` -> `/opt/x/bin/aarch64-linux-gnu-gcc-12`.
/// A name that is not a recognised C++ driver is returned unchanged when it is
/// a C driver, and as `cc` otherwise.
pub fn c_driver_for(cxx: &str) -> String {
    match driver_from_name(cxx) {
        Some(CompilerDriver { cxx: false, .. }) => cxx.to_owned(),
        Some(CompilerDriver { family, cxx: true }) => {
            let (from, to) = match family {
                CompilerFamily::Clang => ("clang++", "clang"),
                CompilerFamily::Gcc => ("g++", "gcc"),
                CompilerFamily::Msvc => return cxx.to_owned(),
            };
            // Replace the LAST occurrence: that is the driver component, after
            // any directory and triple prefix and before a version suffix.
            match cxx.rfind(from) {
                Some(at) => format!("{}{}{}", &cxx[..at], to, &cxx[at + from.len()..]),
                None => cxx.to_owned(),
            }
        }
        None => "cc".to_owned(),
    }
}

/// The C++ driver that pairs with a C driver: `clang` -> `clang++`,
/// `aarch64-linux-gnu-gcc` -> `aarch64-linux-gnu-g++`. A C++ driver is returned
/// unchanged, and an unrecognised name as `c++`.
pub fn cxx_driver_for(cc: &str) -> String {
    match driver_from_name(cc) {
        Some(CompilerDriver { cxx: true, .. }) => cc.to_owned(),
        Some(CompilerDriver { family, cxx: false }) => {
            let (from, to) = match family {
                CompilerFamily::Clang => ("clang", "clang++"),
                CompilerFamily::Gcc => ("gcc", "g++"),
                CompilerFamily::Msvc => return cc.to_owned(),
            };
            match cc.rfind(from) {
                Some(at) => format!("{}{}{}", &cc[..at], to, &cc[at + from.len()..]),
                None => cc.to_owned(),
            }
        }
        None => "c++".to_owned(),
    }
}

/// Parse the output of `<compiler> -dM -E -x c -` (the predefined macros) into
/// a family: `__clang__` means Clang (which also defines `__GNUC__`), a bare
/// `__GNUC__` means GCC, and a bare `_MSC_VER` means MSVC. `None` for anything
/// else, such as a compiler that could not run.
pub fn family_from_predefined_macros(macros: &str) -> Option<CompilerFamily> {
    let defines = |name: &str| {
        macros.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("#define") && words.next() == Some(name)
        })
    };
    if defines("__clang__") {
        Some(CompilerFamily::Clang)
    } else if defines("__GNUC__") {
        Some(CompilerFamily::Gcc)
    } else if defines("_MSC_VER") {
        Some(CompilerFamily::Msvc)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_versions_triples_paths_and_exe_suffixes() {
        for (name, base) in [
            ("gcc", "gcc"),
            ("g++-12", "g++"),
            ("/usr/bin/aarch64-linux-gnu-gcc", "gcc"),
            ("/usr/bin/aarch64-linux-gnu-g++-13", "g++"),
            ("arm-linux-gnueabihf-gcc", "gcc"),
            ("x86_64-w64-mingw32-g++.exe", "g++"),
            ("clang-18", "clang"),
            ("clang++-18.1", "clang++"),
            ("C:\\LLVM\\bin\\clang.exe", "clang"),
            ("\"C:/Program Files/LLVM/bin/clang++.exe\"", "clang++"),
            ("GCC.EXE", "gcc"),
        ] {
            assert_eq!(driver_base_name(name), Some(base), "{name}");
        }
    }

    #[test]
    fn rejects_names_that_only_embed_a_driver_name() {
        for name in [
            "evilclang",
            "gccwrap",
            "cc",
            "c++",
            "tcc",
            "icx",
            "evilcl",
            "",
        ] {
            assert_eq!(driver_base_name(name), None, "{name}");
        }
    }

    #[test]
    fn a_cross_prefixed_gcc_is_the_gcc_family() {
        assert_eq!(
            family_from_name("/usr/bin/aarch64-linux-gnu-gcc"),
            Some(CompilerFamily::Gcc)
        );
        assert_eq!(
            driver_from_name("x86_64-w64-mingw32-g++.exe"),
            Some(CompilerDriver {
                family: CompilerFamily::Gcc,
                cxx: true
            })
        );
        assert_eq!(family_from_name("clang.exe"), Some(CompilerFamily::Clang));
    }

    #[test]
    fn pairs_a_cxx_driver_with_its_c_driver() {
        assert_eq!(c_driver_for("clang++"), "clang");
        assert_eq!(c_driver_for("g++"), "gcc");
        assert_eq!(
            c_driver_for("/opt/x/bin/aarch64-linux-gnu-g++-12"),
            "/opt/x/bin/aarch64-linux-gnu-gcc-12"
        );
        assert_eq!(c_driver_for("clang"), "clang");
        assert_eq!(c_driver_for("c++"), "cc");
        assert_eq!(cxx_driver_for("clang-18"), "clang++-18");
        assert_eq!(
            cxx_driver_for("/usr/bin/aarch64-linux-gnu-gcc"),
            "/usr/bin/aarch64-linux-gnu-g++"
        );
        assert_eq!(cxx_driver_for("g++"), "g++");
        assert_eq!(cxx_driver_for("cc"), "c++");
    }

    #[test]
    fn reads_the_family_from_predefined_macros() {
        let clang = "#define __GNUC__ 4\n#define __clang__ 1\n#define __x86_64__ 1\n";
        let gcc = "#define __GNUC__ 13\n#define __GNUC_MINOR__ 3\n";
        assert_eq!(
            family_from_predefined_macros(clang),
            Some(CompilerFamily::Clang)
        );
        assert_eq!(
            family_from_predefined_macros(gcc),
            Some(CompilerFamily::Gcc)
        );
        assert_eq!(family_from_predefined_macros(""), None);
        assert_eq!(
            family_from_predefined_macros("#define __clang_major__ 18\n"),
            None,
            "a prefix of the macro name is not the macro"
        );
    }

    #[test]
    fn flag_spellings_differ_by_family() {
        assert!(CompilerFamily::Gcc
            .coverage_flag()
            .contains("trace-pc,trace-cmp"));
        assert!(CompilerFamily::Clang
            .coverage_flag()
            .contains("trace-pc-guard,trace-cmp"));
        assert!(!CompilerFamily::Gcc.ubsan_subtraction().contains("function"));
        assert_eq!(
            CompilerFamily::from_make_value(CompilerFamily::Gcc.make_value()),
            Some(CompilerFamily::Gcc)
        );
    }

    #[test]
    fn msvc_drivers_are_recognised_with_or_without_exe_and_path() {
        for (name, base) in [
            ("cl", "cl"),
            ("cl.exe", "cl"),
            ("CL.EXE", "cl"),
            (
                "C:\\Program Files\\VS\\VC\\Tools\\MSVC\\14.44\\bin\\HostX64\\x64\\cl.exe",
                "cl",
            ),
            ("clang-cl", "clang-cl"),
            ("clang-cl.exe", "clang-cl"),
            ("C:/LLVM/bin/clang-cl.exe", "clang-cl"),
            ("clang-cl-19", "clang-cl"),
            ("bhf-cl.exe", "cl"),
        ] {
            assert_eq!(driver_base_name(name), Some(base), "{name}");
            assert_eq!(family_from_name(name), Some(CompilerFamily::Msvc), "{name}");
        }
        // One cl-style driver compiles both languages, so its C and C++ pair is
        // itself.
        assert_eq!(c_driver_for("cl.exe"), "cl.exe");
        assert_eq!(cxx_driver_for("cl"), "cl");
        assert_eq!(cxx_driver_for("clang-cl.exe"), "clang-cl.exe");
        assert_eq!(c_driver_for("clang-cl"), "clang-cl");
    }

    #[test]
    fn msvc_flags_use_inline_counters_and_never_name_ubsan_checks() {
        let coverage = CompilerFamily::Msvc.coverage_flag();
        for kind in ["inline-8bit-counters", "edge", "trace-cmp", "trace-div"] {
            assert!(coverage.contains(kind), "{coverage}");
        }
        assert!(!coverage.contains("trace-pc-guard"), "{coverage}");
        assert_eq!(CompilerFamily::Msvc.ubsan_subtraction(), "");
        assert!(!CompilerFamily::Msvc.supports_ubsan());
        assert!(CompilerFamily::Clang.supports_ubsan());
        assert_eq!(CompilerFamily::Msvc.make_value(), "msvc");
        assert_eq!(
            CompilerFamily::from_make_value("msvc"),
            Some(CompilerFamily::Msvc)
        );
    }

    #[test]
    fn msvc_is_read_from_predefined_macros_without_clang_or_gcc() {
        assert_eq!(
            family_from_predefined_macros("#define _MSC_VER 1944\n#define _WIN64 1\n"),
            Some(CompilerFamily::Msvc)
        );
        // clang-cl defines _MSC_VER too, and speaks the cl dialect.
        assert_eq!(
            family_from_predefined_macros("#define _MSC_VER 1944\n#define __clang__ 1\n"),
            Some(CompilerFamily::Clang)
        );
    }
}
