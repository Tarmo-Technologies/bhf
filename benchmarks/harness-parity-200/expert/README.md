<!-- SPDX-License-Identifier: Apache-2.0 -->
# Independently designed expert harnesses

Each driver here was written for its project, independently of bhf's generated output. It targets the revision pinned in `../expert-projects.tsv` and uses the call shape an experienced fuzzing engineer would choose after reading the code. Comparing against a project-level driver shows the target-selection and protocol gaps that a same-function comparison would hide: resource materialization, object construction, stateful entry points, dependency setup, compiler descriptors and expected rejection.

| Language | Driver |
|---|---|
| Ada | `ada/adl_basename.adb` |
| C | `c/stb_image.c` |
| C++ | `cpp/nlohmann_json.cc` |
| COBOL | `cobol/webbol_file_ops.c` |
| C# | `csharp/CleanArchitectureColour.cs` |
| Fortran | `fortran/functional_arrstr.f90` |
| Go | `go/cobra_execute_test.go` |
| Java | `java/TheAlgorithmsPostfix.java` |
| JavaScript | `js/ecc_read_json.mjs` |
| Lua | `lua/lazyvim_snippet.lua` |
| Perl | `perl/flamegraph_parse_integer.pl` |
| PHP | `php/monolog_chrome.php` |
| Python | `python/public_apis_links.py` |
| Ruby | `ruby/tmuxinator_project.rb` |
| Rust | `rust/zoxide_db.rs` |
| TypeScript | `ts/vue_parse_filters.ts` |

Copy a driver into the named checkout and run it with that ecosystem's usual fuzzer: libFuzzer, Jazzer, Go fuzzing, SharpFuzz, or a framed stdin adapter. For C and C++, the 30-project blind line-coverage comparison in [`../../harness-parity-20/`](../../harness-parity-20/README.md) goes further.
