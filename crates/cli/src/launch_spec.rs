// SPDX-License-Identifier: Apache-2.0

//! How an interpreted lane's harness runs without its POSIX launcher (#305).
//!
//! Each interpreted lane writes `harnesses/<id>/main`, a shell script that
//! sets the driver's environment and execs the interpreter on it. A native
//! Windows host cannot run that script, so the lane also writes
//! `main.launch.json` beside it (`<harness>.launch.json` for each launcher
//! it writes): the interpreter, the driver arguments and the environment
//! the script sets. On Windows the harness runner execs that
//! program directly, with the input after its arguments as it follows
//! `main` (a direct exec, so a timeout's kill reaches the interpreter).
//! `BHF_LAUNCH_SPEC=1` makes any host run a harness this way, which is how
//! the tests check it on Linux.

use replay_min::Launch;
use std::path::Path;

/// The launch spec of the harness file `harness_name`, beside it.
pub(crate) fn spec_file_name(harness_name: &str) -> String {
    format!("{harness_name}.launch.json")
}

/// Whether this host runs a harness from its launch spec: native Windows,
/// or `BHF_LAUNCH_SPEC=1`.
pub(crate) fn launch_specs_apply() -> bool {
    cfg!(windows) || std::env::var("BHF_LAUNCH_SPEC").is_ok_and(|value| value == "1")
}

/// Write `launch` as the launch spec of the harness file `harness`.
pub(crate) fn write(harness: &Path, launch: &Launch) -> std::io::Result<()> {
    let name = harness
        .file_name()
        .ok_or_else(|| std::io::Error::other("a harness path names a file"))?
        .to_string_lossy();
    let bytes = serde_json::to_vec_pretty(launch).map_err(std::io::Error::other)?;
    std::fs::write(harness.with_file_name(spec_file_name(&name)), bytes)
}

/// The launch spec beside `harness`, if this host runs from it and there is
/// one.
pub(crate) fn launch_for(harness: &Path) -> Option<Launch> {
    if !launch_specs_apply() {
        return None;
    }
    let name = harness.file_name()?.to_string_lossy();
    let bytes = std::fs::read(harness.with_file_name(spec_file_name(&name))).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// `dirs` joined as this host's search path (`PYTHONPATH`, a classpath):
/// `:` on Unix, `;` on Windows.
pub(crate) fn search_path(dirs: &[&Path]) -> String {
    let separator = if cfg!(windows) { ";" } else { ":" };
    dirs.iter()
        .map(|dir| dir.display().to_string())
        .collect::<Vec<_>>()
        .join(separator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_launch_spec_round_trips_beside_its_harness() {
        let dir = tempfile::tempdir().unwrap();
        let launch = Launch {
            program: "/usr/bin/python3".into(),
            args: vec!["-B".to_owned(), "driver.py".to_owned()],
            env: vec![("PYTHONPATH".to_owned(), "/w".to_owned())],
        };
        let harness = dir.path().join("main");
        write(&harness, &launch).unwrap();
        assert!(dir.path().join("main.launch.json").is_file());
        std::env::set_var("BHF_LAUNCH_SPEC", "1");
        assert_eq!(launch_for(&harness), Some(launch));
        // Each launcher has its own: `main_symbols` has none here.
        assert_eq!(launch_for(&dir.path().join("main_symbols")), None);
        std::env::remove_var("BHF_LAUNCH_SPEC");
        if !cfg!(windows) {
            assert_eq!(launch_for(&harness), None, "only where specs apply");
        }
    }
}
