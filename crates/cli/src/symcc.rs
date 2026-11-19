// SPDX-License-Identifier: Apache-2.0

//! SymCC, the concolic engine `bhf auto --symcc` runs beside the fuzzer
//! (#324). SymCC is a compiler pass: a harness compiled with its `symcc` (C)
//! or `sym++` (C++) wrapper solves, on every run, the conditions of the
//! branches the input reached and writes an input for each branch it can
//! flip. That reaches what input-to-state and comparison progress cannot: a
//! comparison against a value the input holds only after hashing, modular
//! arithmetic or decoding.
//!
//! SymCC is GPL-3.0. bhf never links it: `make symcc`, which drives SymCC's
//! compiler, and the `main_symcc` binary it builds run as subprocesses, and
//! only under a license profile that allows the `symcc` subprocess
//! (`external-tools`, `research-lab`). An explicit `BHF_PROFILE` wins;
//! without one, asking for SymCC opts into `external-tools`, as
//! `--external-tools` does for the external static analyzers.

use std::path::{Path, PathBuf};

use crate::auto::lanes::LaneStatus;

/// The lane's name in a harness's `lanes.json` and run.json's
/// `targets[].lanes`.
pub(crate) const LANE: &str = "symcc";
/// The Makefile goal that builds the lane.
pub(crate) const MAKE_GOAL: &str = "symcc";
/// The binary the lane builds, beside the harness's `main`.
pub(crate) const BINARY: &str = "main_symcc";
/// The subprocess id a license profile allows SymCC by.
pub(crate) const SUBPROCESS_ID: &str = "symcc";
/// `1` asks for SymCC: `bhf auto --symcc` sets it for its run once the
/// license profile and the tools allow it.
pub(crate) const ENABLE_ENV: &str = "BHF_SYMCC";
/// The Makefile's variables naming SymCC's C and C++ compiler wrappers.
pub(crate) const CC_ENV: &str = "SYMCC_CC";
pub(crate) const CXX_ENV: &str = "SYMCC_CXX";

/// Whether the run asked for SymCC (`BHF_SYMCC=1`).
pub(crate) fn requested() -> bool {
    std::env::var(ENABLE_ENV).is_ok_and(|value| value.trim() == "1")
}

/// The license profile SymCC runs under: the one `BHF_PROFILE` names, else
/// `external-tools`, which asking for SymCC opts into.
pub(crate) fn license_profile() -> config::Profile {
    profile_from(std::env::var("BHF_PROFILE").ok().as_deref())
}

fn profile_from(value: Option<&str>) -> config::Profile {
    value
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(config::Profile::ExternalTools)
}

/// Whether `profile` lets bhf run SymCC.
pub(crate) fn profile_allows(profile: config::Profile) -> bool {
    let allowed = profile.allowed_subprocesses();
    allowed.contains(&"*") || allowed.contains(&SUBPROCESS_ID)
}

/// SymCC's compiler wrappers, where they were found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Compilers {
    /// `symcc`, for C harnesses.
    pub(crate) cc: Option<PathBuf>,
    /// `sym++`, for C++ harnesses.
    pub(crate) cxx: Option<PathBuf>,
}

/// SymCC's compiler wrappers: the ones `SYMCC_CC` and `SYMCC_CXX` name (a
/// path, or a program on PATH), else `symcc` and `sym++` on PATH.
pub(crate) fn find_compilers() -> Compilers {
    Compilers {
        cc: find_compiler(CC_ENV, "symcc"),
        cxx: find_compiler(CXX_ENV, "sym++"),
    }
}

fn find_compiler(var: &str, default: &str) -> Option<PathBuf> {
    let named = std::env::var_os(var)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.into());
    which::which(named).ok()
}

/// Whether a run that asked for SymCC gets it: `Ok` with what the lane
/// builds with, `Err` with why the run goes without it.
pub(crate) fn run_gate(profile: config::Profile, compilers: &Compilers) -> Result<String, String> {
    if !profile_allows(profile) {
        return Err(format!(
            "the `{}` license profile does not allow SymCC (GPL-3.0) to run; set \
             BHF_PROFILE=external-tools or research-lab to allow it",
            profile.as_str()
        ));
    }
    let show = |compiler: &Option<PathBuf>, name: &str| match compiler {
        Some(path) => path.display().to_string(),
        None => format!("none (no `{name}` on PATH, so their SymCC lane is not built)"),
    };
    if compilers.cc.is_none() && compilers.cxx.is_none() {
        return Err(
            "SymCC's compilers are not installed: no `symcc` or `sym++` on PATH, and \
             SYMCC_CC/SYMCC_CXX name none"
                .to_owned(),
        );
    }
    Ok(format!(
        "SymCC lane on (license profile `{}`): C harnesses build main_symcc with {}, C++ \
         harnesses with {}",
        profile.as_str(),
        show(&compilers.cc, "symcc"),
        show(&compilers.cxx, "sym++"),
    ))
}

/// Turn SymCC on for this run, or off, as `bhf auto --symcc` (or
/// `BHF_SYMCC=1`) asks and the license profile and the tools allow. When it
/// is on, `BHF_SYMCC=1` tells the harness builds and the fuzz passes, and
/// `SYMCC_CC`/`SYMCC_CXX` give `make symcc` the compilers found. Returns the
/// line to print.
pub(crate) fn configure_run(asked: bool) -> Option<String> {
    if !asked {
        return None;
    }
    let compilers = find_compilers();
    match run_gate(license_profile(), &compilers) {
        Ok(note) => {
            // Set before any build or worker starts (edition 2021: safe).
            std::env::set_var(ENABLE_ENV, "1");
            if let Some(cc) = &compilers.cc {
                std::env::set_var(CC_ENV, cc);
            }
            if let Some(cxx) = &compilers.cxx {
                std::env::set_var(CXX_ENV, cxx);
            }
            Some(note)
        }
        Err(reason) => {
            std::env::remove_var(ENABLE_ENV);
            Some(format!("--symcc: {reason}; this run fuzzes without SymCC"))
        }
    }
}

/// Build the SymCC lane (`make symcc`, `main_symcc`) of a native C/C++
/// harness that built, when the run asked for SymCC, and record in the
/// harness's `lanes.json` whether it built. `standard` is the language
/// standard the harness's `main` built with (`CXX_STD` for C++, `C_STD` for
/// C, such as a `gnu89` rung of the C dialect ladder), which the lane
/// builds with too. `None` when the run did not ask.
pub(crate) fn build_lane(
    work_dir: &Path,
    harness_id: &str,
    harness_dir: &Path,
    cpp: bool,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    standard: Option<&str>,
) -> Option<LaneStatus> {
    if !requested() {
        return None;
    }
    let status = build_lane_in(
        license_profile(),
        &find_compilers(),
        &LaneBuild {
            work_dir,
            harness_id,
            harness_dir,
            cpp,
            extra_sources,
            extra_includes,
            standard,
        },
    );
    if let Some(reason) = status.reason.as_deref().filter(|_| !status.built) {
        bhfeprintln!("bhf auto: note: {harness_id}: {reason}; it fuzzes without SymCC");
    }
    Some(status)
}

/// The harness whose SymCC lane [`build_lane_in`] builds, and what its
/// `main` built with.
struct LaneBuild<'a> {
    work_dir: &'a Path,
    harness_id: &'a str,
    harness_dir: &'a Path,
    cpp: bool,
    extra_sources: &'a [PathBuf],
    extra_includes: &'a [PathBuf],
    standard: Option<&'a str>,
}

/// [`build_lane`] once the run asked for SymCC: `make symcc` in the
/// harness's dir, with the sources, includes and language standard its
/// `main` built with.
fn build_lane_in(profile: config::Profile, compilers: &Compilers, lane: &LaneBuild) -> LaneStatus {
    build_lane_with(profile, compilers, lane.cpp, lane.harness_dir, || {
        crate::build::try_run_c_make_build_with_target(
            lane.work_dir,
            lane.harness_id,
            lane.extra_sources,
            lane.extra_includes,
            None,
            Some(MAKE_GOAL),
            lane.standard,
        )
    })
}

/// [`build_lane`] once the run asked for SymCC: `make` runs the build only
/// when `profile` allows SymCC and `compilers` has the harness language's.
fn build_lane_with(
    profile: config::Profile,
    compilers: &Compilers,
    cpp: bool,
    harness_dir: &Path,
    make: impl FnOnce() -> std::process::Output,
) -> LaneStatus {
    let (compiler, name, var) = if cpp {
        (&compilers.cxx, "sym++", CXX_ENV)
    } else {
        (&compilers.cc, "symcc", CC_ENV)
    };
    let status = if !profile_allows(profile) {
        not_built(format!(
            "the `{}` license profile does not allow SymCC",
            profile.as_str()
        ))
    } else if compiler.is_none() {
        not_built(format!(
            "SymCC's `{name}` is not on PATH and {var} names none"
        ))
    } else {
        let output = make();
        let binary = crate::auto::layout::harness_exe(harness_dir, BINARY);
        if output.status.success() && binary.is_file() {
            LaneStatus::built()
        } else {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            LaneStatus::failed(BINARY, &text)
        }
    };
    crate::auto::lanes::record(harness_dir, LANE, status.clone());
    status
}

fn not_built(reason: String) -> LaneStatus {
    LaneStatus {
        built: false,
        reason: Some(reason),
        recorded_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(code: i32) -> std::process::ExitStatus {
        #[cfg(unix)]
        {
            std::os::unix::process::ExitStatusExt::from_raw(code << 8)
        }
        #[cfg(windows)]
        {
            std::os::windows::process::ExitStatusExt::from_raw(code as u32)
        }
    }

    fn output(code: i32, stderr: &str) -> std::process::Output {
        std::process::Output {
            status: exit(code),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn found() -> Compilers {
        Compilers {
            cc: Some(PathBuf::from("/opt/symcc/symcc")),
            cxx: Some(PathBuf::from("/opt/symcc/sym++")),
        }
    }

    #[test]
    fn an_explicit_profile_wins_and_none_opts_into_external_tools() {
        use config::Profile;
        assert_eq!(profile_from(None), Profile::ExternalTools);
        assert_eq!(
            profile_from(Some("strict-permissive")),
            Profile::StrictPermissive
        );
        assert_eq!(profile_from(Some("research-lab")), Profile::ResearchLab);
        assert_eq!(profile_from(Some("widget")), Profile::ExternalTools);
        assert!(!profile_allows(Profile::StrictPermissive));
        assert!(profile_allows(Profile::ExternalTools));
        assert!(profile_allows(Profile::ResearchLab));
    }

    #[test]
    fn the_gate_refuses_a_strict_profile_and_missing_compilers() {
        use config::Profile;
        let strict = run_gate(Profile::StrictPermissive, &found()).unwrap_err();
        assert!(strict.contains("`strict-permissive`"), "{strict}");
        assert!(strict.contains("BHF_PROFILE=external-tools"), "{strict}");
        let none = run_gate(Profile::ExternalTools, &Compilers::default()).unwrap_err();
        assert!(none.contains("no `symcc` or `sym++` on PATH"), "{none}");
        let c_only = Compilers {
            cc: Some(PathBuf::from("/opt/symcc/symcc")),
            cxx: None,
        };
        let note = run_gate(Profile::ResearchLab, &c_only).unwrap();
        assert!(note.contains("C harnesses build main_symcc with /opt/symcc/symcc"));
        assert!(note.contains("C++ harnesses with none (no `sym++` on PATH"));
    }

    /// The lane is recorded in the harness's lanes.json, built or not; make
    /// runs only when the profile allows SymCC and its compiler was found.
    #[test]
    fn the_lane_is_built_only_when_allowed_and_recorded_either_way() {
        use config::Profile;
        let dir = tempfile::tempdir().unwrap();
        let harness = dir.path();
        let mut ran = 0;
        let status = build_lane_with(Profile::StrictPermissive, &found(), false, harness, || {
            ran += 1;
            output(0, "")
        });
        assert!(!status.built);
        assert_eq!(ran, 0, "make ran under strict-permissive");
        assert_eq!(
            crate::auto::lanes::read(harness)[LANE].reason.as_deref(),
            Some("the `strict-permissive` license profile does not allow SymCC")
        );

        let c_only = Compilers {
            cc: Some(PathBuf::from("/opt/symcc/symcc")),
            cxx: None,
        };
        let status = build_lane_with(Profile::ExternalTools, &c_only, true, harness, || {
            ran += 1;
            output(0, "")
        });
        assert_eq!(ran, 0, "make ran without sym++");
        assert_eq!(
            status.reason.as_deref(),
            Some("SymCC's `sym++` is not on PATH and SYMCC_CXX names none")
        );

        let status = build_lane_with(Profile::ExternalTools, &found(), false, harness, || {
            ran += 1;
            output(
                2,
                "main.c:3:10: error: unknown type name 'widget_t'\n\
                 make: *** [Makefile:481: main_symcc] Error 1\n",
            )
        });
        assert_eq!(ran, 1);
        assert_eq!(
            status.reason.as_deref(),
            Some("make main_symcc failed: main.c:3:10: error: unknown type name 'widget_t'")
        );
        assert!(!crate::auto::lanes::read(harness)[LANE].built);

        // make succeeding without leaving the binary is no lane either.
        let status = build_lane_with(Profile::ExternalTools, &found(), false, harness, || {
            output(0, "")
        });
        assert!(!status.built);
        std::fs::write(
            crate::auto::layout::harness_exe(harness, BINARY),
            b"#!/bin/sh\n",
        )
        .unwrap();
        let status = build_lane_with(Profile::ExternalTools, &found(), false, harness, || {
            output(0, "")
        });
        assert!(status.built, "{status:?}");
        let recorded = &crate::auto::lanes::read(harness)[LANE];
        assert!(recorded.built && recorded.recorded_at.is_some());
    }

    /// The lane builds at the language standard the harness's `main` built
    /// with: a C harness that needed a `gnu89` rung of the dialect ladder
    /// gets `C_STD=gnu89`, a C++ one its `CXX_STD`. The stand-in Makefiles
    /// build `main_symcc` only at that standard.
    #[cfg(unix)]
    #[test]
    fn the_lane_builds_at_the_standard_main_built_with() {
        use config::Profile;
        if which::which("make").is_err() {
            eprintln!("skip: make unavailable");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        for (id, cpp, var, standard) in [
            ("H-LEGACY", false, "C_STD", "gnu89"),
            ("H-WIDGET", true, "CXX_STD", "gnu++14"),
        ] {
            let harness = crate::auto::layout::harness_dir(work.path(), id);
            std::fs::create_dir_all(&harness).unwrap();
            if cpp {
                std::fs::write(harness.join("main.cpp"), "").unwrap();
            }
            std::fs::write(
                harness.join("Makefile"),
                format!(
                    "{var} ?=\nsymcc:\n\
                     \t@test \"$({var})\" = {standard} || {{ echo \"{var}='$({var})'\" >&2; exit 1; }}\n\
                     \t@touch main_symcc\n"
                ),
            )
            .unwrap();
            let status = build_lane_in(
                Profile::ExternalTools,
                &found(),
                &LaneBuild {
                    work_dir: work.path(),
                    harness_id: id,
                    harness_dir: &harness,
                    cpp,
                    extra_sources: &[],
                    extra_includes: &[],
                    standard: Some(standard),
                },
            );
            assert!(status.built, "{id}: {status:?}");
        }
    }
}
