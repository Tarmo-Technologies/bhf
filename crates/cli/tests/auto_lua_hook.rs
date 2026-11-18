// SPDX-License-Identifier: Apache-2.0

//! The Lua driver's coverage hook runs only for the target's own chunks and
//! costs little there, and a stack overflow is located in the target. The
//! hook ran for every line event of every chunk, hashing the source path each
//! time (100–600x per line event), so deep recursion timed out unreported, and
//! an overflow was reported at `bhf_driver.lua:26`, inside the hook.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn lua() -> Option<&'static str> {
    ["lua5.4", "lua"].into_iter().find(|lua| {
        Command::new(lua)
            .args(["-e", "assert(_VERSION == 'Lua 5.4')"])
            .output()
            .is_ok_and(|out| out.status.success())
    })
}

fn driver() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../lua_runtime/bhf_driver.lua")
}

/// Run the driver on one input for `harness`, tracing chunks under `prefix`.
fn run_driver(lua: &str, harness: &Path, prefix: &Path, covered: &Path) -> std::process::Output {
    let input = harness.with_file_name("input.bin");
    std::fs::write(&input, b"x").unwrap();
    Command::new(lua)
        .arg(driver())
        .arg(&input)
        .env("BHF_HARNESS", harness)
        .env("BHF_TRACE_PREFIX", prefix)
        .env("BHF_COVERED_LINES", covered)
        .output()
        .expect("run the Lua driver")
}

#[test]
fn the_coverage_hook_runs_only_for_the_target_chunk() {
    let Some(lua) = lua() else {
        eprintln!("skipping: no Lua 5.4 on PATH");
        return;
    };
    let root = TestDir::new("lua-hook-target-only");
    let target_dir = root.join("target");
    let vendor = root.join("vendor");
    std::fs::create_dir_all(&target_dir).unwrap();
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(
        vendor.join("helper.lua"),
        "local H = {}\nfunction H.twice(n)\n  local r = n * 2\n  return r\nend\nreturn H\n",
    )
    .unwrap();
    std::fs::write(
        target_dir.join("calc.lua"),
        format!(
            "local helper = dofile('{}')\nlocal M = {{}}\nfunction M.run(data)\n  \
             local n = #data\n  return helper.twice(n)\nend\nreturn M\n",
            vendor.join("helper.lua").display()
        ),
    )
    .unwrap();
    let harness = root.join("bhfgen.lua");
    std::fs::write(
        &harness,
        format!(
            "local mod = dofile('{}')\nreturn function(data)\n  return mod.run(data)\nend\n",
            target_dir.join("calc.lua").display()
        ),
    )
    .unwrap();
    let covered = root.join("covered-lines.txt");
    let out = run_driver(lua, &harness, &target_dir, &covered);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = std::fs::read_to_string(&covered).unwrap();
    let calc = target_dir.join("calc.lua").display().to_string();
    assert!(
        lines.contains(&format!("{calc}:4")),
        "the target's lines: {lines}"
    );
    for line in lines.lines() {
        assert!(
            line.starts_with(&calc),
            "only the target chunk is traced: {line}"
        );
    }
}

/// `walk` recurses without end on an input that starts with `[`.
const WALK: &str = "local M = {}\n\nlocal function walk(node, depth)\n  \
                    return walk(node, depth + 1) + 1\nend\n\n\
                    function M.walk_tree(data)\n  if data:sub(1, 1) == '[' then\n    \
                    return walk({}, 0)\n  end\n  return 0\nend\n\nreturn M\n";

#[test]
fn a_stack_overflow_is_located_in_the_target() {
    if lua().is_none() {
        eprintln!("skipping: no Lua 5.4 on PATH");
        return;
    }
    let root = TestDir::new("lua-walk-overflow");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("walk.lua"), WALK).unwrap();
    // The test is where the overflow is located, not whether mutation finds
    // the `[`: a seed takes the path, so a loaded runner cannot miss it. The
    // line hook makes the overflow take half a second here and seconds on a
    // loaded runner, and a run is cut short where its pass ends: one pass
    // with the whole budget, and a timeout past it, let the seed finish.
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"[x").unwrap();
    let work = root.join("work");
    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .arg("--seed-file")
        .arg(&seed)
        .args([
            "--languages",
            "lua",
            "--jobs",
            "1",
            "--per-target-time",
            "10",
            "--timeout",
            "30s",
            "--single-pass",
        ])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    let overflow = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["cwe"][0] == 674)
        .unwrap_or_else(|| panic!("no CWE-674 finding:\n{doc:#}\n{stderr}"));
    assert_eq!(overflow["location"]["file"], "walk.lua", "{overflow:#}");
    assert_eq!(overflow["location"]["line"], 4, "{overflow:#}");
    eprintln!("bhf auto took {:?}", started.elapsed());
}

/// The driver's cost on a function of ~20000 line events, run 200 times in
/// one process, against the same loop under plain Lua. Timing-sensitive, so
/// the nightly runs it (`--run-ignored`).
#[test]
#[ignore = "timing benchmark: the nightly runs it"]
fn the_line_hook_costs_under_ten_times_plain_lua() {
    let Some(lua) = lua() else {
        eprintln!("skipping: no Lua 5.4 on PATH");
        return;
    };
    let root = TestDir::new("lua-hook-benchmark");
    let target = root.join("spin.lua");
    std::fs::write(
        &target,
        "local M = {}\nfunction M.spin(data)\n  local acc = 0\n  for i = 1, 10000 do\n    \
         acc = acc + i\n  end\n  return acc\nend\nreturn M\n",
    )
    .unwrap();
    // Enough rounds that the work, not the process start, is what is timed
    // (200 rounds ran 11 ms plain), and the best of three runs on each side,
    // so a busy CI runner's stall in one run does not decide the ratio.
    let rounds = 2000;
    let best_of_three =
        |run: &mut dyn FnMut() -> std::time::Duration| (0..3).map(|_| run()).min().unwrap();
    let plain_time = best_of_three(&mut || {
        let started = Instant::now();
        let plain = Command::new(lua)
            .arg("-e")
            .arg(format!(
                "local M = dofile('{}') for _ = 1, {rounds} do M.spin('') end",
                target.display()
            ))
            .output()
            .unwrap();
        assert!(plain.status.success());
        started.elapsed()
    });

    let harness = root.join("bhfgen.lua");
    std::fs::write(
        &harness,
        format!(
            "local mod = dofile('{}')\nreturn function(data)\n  for _ = 1, {rounds} do mod.spin(data) end\nend\n",
            target.display()
        ),
    )
    .unwrap();
    let hooked_time = best_of_three(&mut || {
        let started = Instant::now();
        let hooked = run_driver(lua, &harness, &root, &root.join("covered.txt"));
        let elapsed = started.elapsed();
        assert!(
            hooked.status.success(),
            "{}",
            String::from_utf8_lossy(&hooked.stderr)
        );
        elapsed
    });
    let ratio = hooked_time.as_secs_f64() / plain_time.as_secs_f64();
    eprintln!("plain {plain_time:?}, harnessed {hooked_time:?}, ratio {ratio:.1}x");
    assert!(ratio < 10.0, "harnessed/plain is {ratio:.1}x");
}
