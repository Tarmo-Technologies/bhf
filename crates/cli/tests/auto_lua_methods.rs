// SPDX-License-Identifier: Apache-2.0

//! A Lua colon method runs on an instance of its class. The harness called
//! `mod['f'](mod, data)`, handing the class table in as `self`, so a method
//! that reads its instance's fields died on a nil error the driver suppresses
//! and object-oriented Lua reported clean. A target whose inputs nearly all
//! end in a nil-value error is now flagged `stub_executed`.

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have_lua() -> bool {
    ["lua", "lua5.4"].iter().any(|lua| {
        Command::new(lua)
            .args(["-e", "return 1"])
            .output()
            .is_ok_and(|out| out.status.success())
    })
}

/// `average` divides the bytes' total by its instance's count, which `new`
/// sets: an empty input divides by zero.
const READER: &str = "local Reader = {}\nReader.__index = Reader\n\n\
                      function Reader.new()\n  return setmetatable({ total = 0, count = 0 }, Reader)\nend\n\n\
                      function Reader:average(data)\n  for i = 1, #data do\n    \
                      self.total = self.total + data:byte(i)\n    self.count = self.count + 1\n  end\n  \
                      return self.total // self.count\nend\n\nreturn Reader\n";

/// `limit` reads a config that is never set, so every input ends in a nil
/// error; `header` errors on nil only for inputs that start with `A`.
const CONFIG: &str = "local M = {}\n\n\
                      function M.limit(data)\n  local cfg = M.config\n  return cfg.max + #data\nend\n\n\
                      function M.header(data)\n  if data:byte(1) == 65 then\n    local field = nil\n    \
                      return field.size\n  end\n  return #data\nend\n\nreturn M\n";

fn auto(root: &TestDir, file: &str, source: &str) -> (std::path::PathBuf, String) {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join(file), source).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args([
            "--languages",
            "lua",
            "--jobs",
            "1",
            "--per-target-time",
            "5",
        ])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    (work, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn read(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn a_colon_method_runs_on_an_instance_and_its_divide_by_zero_is_found() {
    if !have_lua() {
        eprintln!("skipping: no lua on PATH");
        return;
    }
    let root = TestDir::new("lua-colon-method");
    let (work, stderr) = auto(&root, "reader.lua", READER);
    let doc = read(&work.join("results/findings.json"));
    assert!(
        doc["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["cwe"][0] == 369),
        "Reader:average divides by zero:\n{doc:#}\n{stderr}"
    );
}

#[test]
fn a_target_whose_inputs_nearly_all_hit_nil_is_flagged_stub_executed() {
    if !have_lua() {
        eprintln!("skipping: no lua on PATH");
        return;
    }
    let root = TestDir::new("lua-stub-executed");
    let (work, stderr) = auto(&root, "config.lua", CONFIG);
    let run = read(&work.join("auto/run.json"));
    let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
    let target = |name: &str| {
        run["targets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"].as_str().is_some_and(|n| n.ends_with(name)))
            .unwrap_or_else(|| panic!("no {name} target:\n{run:#}\n{stderr}"))
            .clone()
    };

    let limit = target("limit");
    let stub = &limit["stub_executed"];
    assert!(
        stub["nil_errors"].as_u64().unwrap() * 100 >= stub["executions"].as_u64().unwrap() * 95,
        "{limit:#}"
    );
    let id = limit["harness_id"].as_str().unwrap();
    let row = md.lines().find(|line| line.contains(id)).unwrap();
    assert!(row.contains("stub executed:"), "{row}");

    let header = target("header");
    assert!(header.get("stub_executed").is_none(), "{header:#}");
}
