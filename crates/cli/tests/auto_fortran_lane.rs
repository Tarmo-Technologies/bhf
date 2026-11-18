// SPDX-License-Identifier: Apache-2.0

//! The Fortran lane finds an out-of-bounds write on every host it runs on.
//! On Linux AddressSanitizer reports it. On native Windows (#327) MinGW-w64's
//! gfortran ships no sanitizer, so the lane builds with gfortran's bounds
//! checks, turns a failed check into a crash, and labels the finding's
//! sanitizer fidelity `none (toolchain limit)`.

use serde_json::Value;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn runs(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// What the lane needs here: gfortran, and the C compiler its harness links
/// with (MinGW's gcc on Windows, clang elsewhere).
fn have_toolchain() -> bool {
    let cc = if cfg!(windows) { "gcc" } else { "clang" };
    support::require_tool(runs("gfortran") && runs(cc), &format!("gfortran and {cc}"))
}

const PARSE_F90: &str = "subroutine parse_record(data)\n  implicit none\n  \
    character(len=*), intent(in) :: data\n  integer, allocatable :: slots(:)\n  \
    integer :: i\n  allocate(slots(4))\n  slots = 0\n  if (len(data) > 0) then\n    \
    if (data(1:1) == 'A') then\n      i = len(data) + 4\n      slots(i) = 7\n      \
    print *, slots(i)\n    end if\n  end if\n  deallocate(slots)\nend subroutine parse_record\n";

#[test]
fn a_crashing_fortran_input_is_found_with_its_sanitizer_fidelity() {
    if !have_toolchain() {
        eprintln!("skipping: the Fortran toolchain is not installed");
        return;
    }
    let root = TestDir::new("auto-fortran-lane");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("parse.f90"), PARSE_F90).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--languages", "fortran", "--jobs", "1"])
        .args(["--per-target-time", "20", "--no-discovery-cache"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("built+fuzzed"), "{stderr}");

    let findings: Vec<Value> = std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .filter(|finding: &Value| finding["classification"] == "unhandled")
        .collect();
    let finding = findings
        .first()
        .unwrap_or_else(|| panic!("no runtime crash found: {findings:#?}\n{stderr}"));
    let sanitizers = &finding["fidelity"]["sanitizers"];
    if cfg!(windows) {
        assert_eq!(sanitizers["status"], "not_exercised", "{finding:#}");
        let reason = sanitizers["reason"].as_str().unwrap_or_default();
        assert!(
            reason.starts_with("none (toolchain limit): "),
            "the finding says why no sanitizer ran: {finding:#}"
        );
    } else {
        assert_eq!(sanitizers["status"], "exercised", "{finding:#}");
    }
}
